# /home/admin/ids_project/redis_client.py

import redis
import logging
from typing import Optional, Set, Union
import time
from redis.exceptions import RedisError, ConnectionError, TimeoutError, AuthenticationError

logger = logging.getLogger(__name__)

class RedisConfig:
    """Classe para armazenar configurações do Redis."""
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0,
                 password: Optional[str] = None, block_list_key: str = 'ids:blocked_ips',
                 block_ttl_seconds: int = 3600):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.block_list_key = block_list_key
        self.block_ttl_seconds = block_ttl_seconds

class RedisClient:
    """Cliente Redis para gerenciar bloqueios e métricas de tráfego."""
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0,
                 password: Optional[str] = None, block_list_key: str = 'ids:blocked_ips',
                 block_ttl_seconds: int = 3600):
        """Inicializa o cliente com configuração e tenta conectar."""
        self.config = RedisConfig(host, port, db, password, block_list_key, block_ttl_seconds)
        self.connection: Optional[redis.Redis] = None
        self._connect()  # Conecta na inicialização

    def _connect(self) -> None:
        """Estabelece conexão com o Redis com retry e backoff."""
        max_retries = 3
        retry_delay = 1  # segundos
        for attempt in range(max_retries):
            try:
                if self.connection:
                    self.connection.close()
                self.connection = redis.Redis(
                    host=self.config.host,
                    port=self.config.port,
                    db=self.config.db,
                    password=self.config.password,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                self.connection.ping()
                logger.info(f"Conectado ao Redis: {self.config.host}:{self.config.port}, DB: {self.config.db}")
                return
            except (ConnectionError, TimeoutError) as e:
                logger.warning(f"Tentativa {attempt+1}/{max_retries} falhou: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))  # Backoff exponencial
            except AuthenticationError as e:
                logger.error(f"Erro de autenticação: {e}")
                self.connection = None
                raise
            except Exception as e:
                logger.error(f"Erro inesperado na conexão: {e}", exc_info=True)
                self.connection = None
                raise
        logger.error("Falha ao conectar ao Redis após retries.")
        self.connection = None

    def get_connection(self) -> Optional[redis.Redis]:
        """Retorna a conexão ativa, reconectando se necessário."""
        if self.connection:
            try:
                self.connection.ping()
                return self.connection
            except (ConnectionError, TimeoutError):
                logger.warning("Conexão perdida. Reconectando...")
                self._connect()
                return self.connection if self.connection else None
        self._connect()
        return self.connection

    def is_blocked(self, ip_address: str) -> bool:
        """Verifica se um IP está bloqueado."""
        conn = self.get_connection()
        if not conn:
            logger.warning(f"is_blocked: Sem conexão. Assumindo {ip_address} não bloqueado.")
            return False
        try:
            return conn.sismember(self.config.block_list_key, ip_address)
        except RedisError as e:
            logger.error(f"Erro ao verificar {ip_address}: {e}")
            return False

    def add_block(self, ip_address: str, ttl: Optional[int] = -1) -> bool:
        """Adiciona um IP à lista de bloqueio com TTL configurável."""
        conn = self.get_connection()
        if not conn:
            logger.error(f"add_block: Sem conexão para {ip_address}.")
            return False
        try:
            added = conn.sadd(self.config.block_list_key, ip_address)
            effective_ttl = self.config.block_ttl_seconds if ttl == -1 else ttl
            if effective_ttl > 0:
                conn.expire(self.config.block_list_key, effective_ttl)
                logger.debug(f"TTL de {effective_ttl}s definido para {self.config.block_list_key}")
            elif effective_ttl == 0:
                conn.persist(self.config.block_list_key)
                logger.debug(f"{self.config.block_list_key} tornado persistente")
            logger.info(f"IP {ip_address} {'adicionado' if added else 'já existia'} em {self.config.block_list_key}")
            return True
        except RedisError as e:
            logger.error(f"Erro ao adicionar {ip_address}: {e}")
            return False

    def remove_block(self, ip_address: str) -> bool:
        """Remove um IP da lista de bloqueio."""
        conn = self.get_connection()
        if not conn:
            logger.error(f"remove_block: Sem conexão para {ip_address}.")
            return False
        try:
            removed = conn.srem(self.config.block_list_key, ip_address)
            if removed:
                logger.info(f"IP {ip_address} removido de {self.config.block_list_key}")
                return True
            logger.warning(f"IP {ip_address} não encontrado em {self.config.block_list_key}")
            return False
        except RedisError as e:
            logger.error(f"Erro ao remover {ip_address}: {e}")
            return False

    def get_blocked_ips(self) -> Optional[Set[str]]:
        """Retorna todos os IPs bloqueados usando SSCAN para escalabilidade."""
        conn = self.get_connection()
        if not conn:
            logger.error("get_blocked_ips: Sem conexão.")
            return None
        try:
            blocked_ips = set()
            cursor = '0'
            while cursor != 0:
                cursor, ips = conn.sscan(self.config.block_list_key, cursor=cursor, count=100)
                blocked_ips.update(ips)
            return blocked_ips
        except RedisError as e:
            logger.error(f"Erro ao listar IPs bloqueados: {e}")
            return None

    def increment_packet_count(self, ip_address: str, ttl: int = 5) -> int:
        """Incrementa e retorna a contagem de pacotes por IP em uma janela de tempo."""
        conn = self.get_connection()
        if not conn:
            logger.warning(f"increment_packet_count: Sem conexão para {ip_address}. Retornando 0.")
            return 0
        key = f"rate:{ip_address}"
        try:
            count = conn.incr(key)
            conn.expire(key, ttl)
            return count
        except RedisError as e:
            logger.error(f"Erro ao contar pacotes para {ip_address}: {e}")
            return 0

    def get_packet_rate(self, ip_address: str) -> int:
        """Retorna a taxa de pacotes atual para um IP."""
        conn = self.get_connection()
        if not conn:
            logger.warning(f"get_packet_rate: Sem conexão para {ip_address}.")
            return 0
        key = f"rate:{ip_address}"
        try:
            count = conn.get(key)
            return int(count) if count else 0
        except RedisError as e:
            logger.error(f"Erro ao obter taxa para {ip_address}: {e}")
            return 0

    def close(self) -> None:
        """Fecha a conexão com o Redis."""
        if self.connection:
            try:
                self.connection.close()
                logger.info("Conexão Redis fechada.")
            except Exception as e:
                logger.error(f"Erro ao fechar conexão: {e}")
            finally:
                self.connection = None

    def __del__(self):
        """Fecha a conexão ao destruir o objeto."""
        self.close()

# Teste standalone
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    client = RedisClient(host='localhost', port=6379, block_ttl_seconds=60)

    # Limpar chave de teste
    conn = client.get_connection()
    if conn:
        conn.delete('ids:blocked_ips')

    # Testes
    print("Adicionando IPs...")
    client.add_block("192.168.1.1")
    client.add_block("10.0.0.1", ttl=10)
    print(f"192.168.1.1 bloqueado? {client.is_blocked('192.168.1.1')}")
    print(f"Lista de bloqueados: {client.get_blocked_ips()}")

    print("Contando pacotes...")
    for _ in range(5):
        print(f"Taxa para 192.168.1.1: {client.increment_packet_count('192.168.1.1')}")
    
    client.remove_block("192.168.1.1")
    print(f"Após remoção: {client.get_blocked_ips()}")
    client.close()