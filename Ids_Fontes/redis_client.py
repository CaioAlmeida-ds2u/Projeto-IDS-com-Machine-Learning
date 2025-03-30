import redis
import logging
from typing import Optional, Set

# Configura um logger específico para este módulo
logger = logging.getLogger(__name__)

class RedisClient:
    """
    Classe utilitária para gerenciar a conexão e operações com o Redis
    específicas para o sistema IDS (lista de bloqueio).
    """
    def __init__(self, host='localhost', port=6379, db=0, password=None,
                 block_list_key='ids:blocked_ips', block_ttl_seconds=3600):
        """
        Inicializa o cliente Redis.

        Args:
            host (str): Endereço do servidor Redis.
            port (int): Porta do servidor Redis.
            db (int): Número do banco de dados Redis a ser usado.
            password (Optional[str]): Senha para autenticação no Redis (se houver).
            block_list_key (str): Nome da chave Redis (tipo Set) para armazenar IPs bloqueados.
            block_ttl_seconds (int): Tempo de vida padrão (em segundos) para um bloqueio.
                                     Usado ao adicionar um IP se nenhum TTL específico for fornecido.
                                     Se 0, o bloqueio não expira automaticamente pelo TTL padrão.
        """
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.block_list_key = block_list_key
        self.block_ttl_seconds = block_ttl_seconds
        self.connection: Optional[redis.Redis] = None # Define o tipo da conexão
        # Tenta conectar na inicialização
        try:
            self._connect()
        except Exception as e:
            # Loga o erro, mas não impede a instanciação. A conexão será None.
            logger.error(f"Falha inicial ao conectar ao Redis em {self.host}:{self.port} - {e}")
            self.connection = None

    def _connect(self):
        """Estabelece (ou restabelece) a conexão com o Redis."""
        # Fecha conexão anterior se existir
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                 pass # Ignora erros ao fechar conexão antiga
            finally:
                 self.connection = None

        logger.debug(f"Tentando conectar ao Redis: {self.host}:{self.port}, DB: {self.db}")
        try:
            # decode_responses=True: retorna strings em vez de bytes. Facilita o uso.
            # socket_connect_timeout: tempo máximo para estabelecer a conexão.
            # socket_timeout: tempo máximo para operações individuais (get, set, etc.).
            self.connection = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            # Verifica a conexão imediatamente
            self.connection.ping()
            logger.info(f"Conectado com sucesso ao Redis em {self.host}:{self.port}, DB: {self.db}")
        except redis.exceptions.TimeoutError:
            logger.error(f"Timeout ao conectar ao Redis ({self.host}:{self.port}).")
            self.connection = None
            raise # Re-lança para indicar falha na conexão
        except redis.exceptions.AuthenticationError:
             logger.error(f"Erro de autenticação ao conectar ao Redis ({self.host}:{self.port}). Verifique a senha.")
             self.connection = None
             raise
        except redis.exceptions.ConnectionError as e:
            logger.error(f"Erro de conexão ao Redis ({self.host}:{self.port}): {e}")
            self.connection = None
            raise
        except Exception as e:
             logger.error(f"Erro inesperado ao conectar ao Redis ({self.host}:{self.port}): {e}", exc_info=True)
             self.connection = None
             raise

    def get_connection(self) -> Optional[redis.Redis]:
         """
         Retorna a instância de conexão Redis ativa, tentando reconectar se necessário.
         Retorna None se a conexão falhar.
         """
         if self.connection:
              try:
                   # Verifica se a conexão ainda é válida
                   if self.connection.ping():
                        return self.connection
                   else:
                        logger.warning("Conexão Redis perdida (ping falhou). Tentando reconectar...")
                        self._connect() # Tenta reconectar
                        return self.connection # Retorna a nova conexão (ou None se falhar)
              except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
                   logger.warning("Erro ao verificar/reconectar ao Redis. Tentando reconectar na próxima chamada.")
                   self.connection = None # Marca como desconectado
                   return None
              except Exception as e:
                   logger.error(f"Erro inesperado ao obter/verificar conexão Redis: {e}", exc_info=True)
                   self.connection = None
                   return None
         else:
              # Se self.connection é None, tenta conectar pela primeira vez (ou novamente após falha anterior)
              logger.info("Conexão Redis não existente. Tentando conectar...")
              try:
                   self._connect()
                   return self.connection
              except Exception:
                   # _connect já loga o erro
                   return None # Falha ao conectar

    def is_blocked(self, ip_address: str) -> bool:
        """
        Verifica se um IP está na lista de bloqueio (Set).

        Args:
            ip_address (str): O endereço IP a ser verificado.

        Returns:
            bool: True se o IP estiver bloqueado, False caso contrário ou em caso de erro.
        """
        conn = self.get_connection()
        if not conn:
            logger.warning("is_blocked: Conexão Redis indisponível. Assumindo IP não bloqueado.")
            return False # Assumir não bloqueado se Redis estiver fora é uma decisão de segurança.
                         # Poderia ser True dependendo da política desejada.
        try:
            # SISMEMBER: Verifica se um membro existe no Set. O(1).
            return conn.sismember(self.block_list_key, ip_address)
        except redis.exceptions.RedisError as e:
            logger.error(f"Erro ao verificar IP {ip_address} na lista '{self.block_list_key}' no Redis: {e}")
            return False # Assumir não bloqueado em caso de erro Redis

    def add_block(self, ip_address: str, ttl: Optional[int] = -1) -> bool:
        """
        Adiciona um IP à lista de bloqueio (Set).
        Gerencia o TTL da *chave principal* (o Set) para expirar bloqueios antigos,
        se um TTL > 0 for especificado ou configurado por padrão.

        Args:
            ip_address (str): O endereço IP a ser bloqueado.
            ttl (Optional[int]): Tempo de vida específico para este bloqueio (em segundos).
                                 Se -1 (padrão), usa o TTL padrão da classe (self.block_ttl_seconds).
                                 Se 0, o bloqueio não expira por TTL (usa o TTL padrão 0 se configurado).
                                 Se None, não tenta definir/atualizar o TTL da chave.

        Returns:
            bool: True se o IP foi adicionado com sucesso (ou já existia), False em caso de erro.
        """
        conn = self.get_connection()
        if not conn:
            logger.error(f"add_block: Conexão Redis indisponível. Falha ao adicionar IP {ip_address}.")
            return False

        try:
            # SADD: Adiciona o membro ao Set. Retorna 1 se adicionado, 0 se já existia. O(1).
            added = conn.sadd(self.block_list_key, ip_address)

            # Determina o TTL a ser aplicado à *chave do Set*
            effective_ttl = self.block_ttl_seconds if ttl == -1 else ttl if ttl is not None else None

            if effective_ttl is not None:
                if effective_ttl > 0:
                    # EXPIRE: Define um TTL na chave. Se a chave já tiver TTL, ele é atualizado.
                    conn.expire(self.block_list_key, effective_ttl)
                    logger.debug(f"TTL da chave '{self.block_list_key}' definido/atualizado para {effective_ttl} segundos.")
                elif effective_ttl == 0:
                    # PERSIST: Remove o TTL da chave, tornando-a permanente (até ser deletada).
                    conn.persist(self.block_list_key)
                    logger.debug(f"TTL da chave '{self.block_list_key}' removido (persistente).")

            if added:
                logger.info(f"IP {ip_address} ADICIONADO à lista de bloqueio '{self.block_list_key}'.")
            else:
                logger.info(f"IP {ip_address} JÁ EXISTIA na lista de bloqueio '{self.block_list_key}'.")

            return True # Sucesso mesmo se já existia

        except redis.exceptions.RedisError as e:
            logger.error(f"Erro ao adicionar/atualizar IP {ip_address} na lista '{self.block_list_key}' no Redis: {e}")
            return False

    def remove_block(self, ip_address: str) -> bool:
        """
        Remove um IP da lista de bloqueio (Set).

        Args:
            ip_address (str): O endereço IP a ser desbloqueado.

        Returns:
            bool: True se o IP foi removido com sucesso, False se não existia ou em caso de erro.
        """
        conn = self.get_connection()
        if not conn:
            logger.error(f"remove_block: Conexão Redis indisponível. Falha ao remover IP {ip_address}.")
            return False
        try:
            # SREM: Remove o membro do Set. Retorna 1 se removido, 0 se não existia. O(1).
            removed = conn.srem(self.block_list_key, ip_address)
            if removed:
                 logger.info(f"IP {ip_address} REMOVIDO da lista de bloqueio '{self.block_list_key}'.")
                 return True
            else:
                 # Logar como warning, pois pode ser uma tentativa válida de remover algo que já expirou
                 logger.warning(f"Tentativa de remover IP {ip_address}, mas ele não foi encontrado na lista '{self.block_list_key}'.")
                 return False # Retorna False indicando que não estava lá
        except redis.exceptions.RedisError as e:
            logger.error(f"Erro ao remover IP {ip_address} da lista '{self.block_list_key}' no Redis: {e}")
            return False

    def get_blocked_ips(self) -> Optional[Set[str]]:
        """
        Retorna o conjunto (Set) de todos os IPs atualmente na lista de bloqueio.

        Returns:
            Optional[Set[str]]: Um conjunto contendo os IPs bloqueados,
                                ou None em caso de erro de conexão/Redis.
        """
        conn = self.get_connection()
        if not conn:
            logger.error("get_blocked_ips: Conexão Redis indisponível.")
            return None # Retorna None para indicar erro
        try:
            # SMEMBERS: Retorna todos os membros do Set. O(N), onde N é o tamanho do Set.
            # Pode ser custoso para listas muito grandes. Considere SSCAN para iteração.
            return conn.smembers(self.block_list_key)
        except redis.exceptions.RedisError as e:
            logger.error(f"Erro ao obter membros da lista '{self.block_list_key}' no Redis: {e}")
            return None # Retorna None para indicar erro

    def close(self):
        """Fecha a conexão com o Redis, se estiver aberta."""
        if self.connection:
            try:
                self.connection.close()
                logger.info("Conexão com Redis fechada.")
            except Exception as e:
                 logger.error(f"Erro ao fechar conexão Redis: {e}")
            finally:
                 self.connection = None

    def __del__(self):
        """Garante que a conexão seja fechada quando o objeto for destruído."""
        self.close()

# Exemplo de uso (opcional, para teste direto do arquivo)
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Simula configurações (poderia carregar do ConfigManager)
    redis_host = 'localhost'
    redis_port = 6379
    key = 'ids:test_blocked_ips'

    print(f"--- Testando RedisClient (Conectando a {redis_host}:{redis_port}) ---")
    try:
        client = RedisClient(host=redis_host, port=redis_port, block_list_key=key, block_ttl_seconds=60)

        # Limpa a chave de teste antes de começar
        conn = client.get_connection()
        if conn:
            conn.delete(key)
            print(f"Chave de teste '{key}' limpa.")

        # Teste 1: Adicionar IPs
        print("\n--- Teste 1: Adicionando IPs ---")
        ip1 = "192.168.1.100"
        ip2 = "10.0.0.5"
        ip3 = "172.16.30.40"
        print(f"Adicionando {ip1}: {client.add_block(ip1)}")
        print(f"Adicionando {ip2} (sem TTL específico): {client.add_block(ip2, ttl=None)}") # Não afeta TTL da chave
        print(f"Adicionando {ip3} (com TTL 0): {client.add_block(ip3, ttl=0)}") # Tenta persistir a chave
        print(f"Adicionando {ip1} novamente: {client.add_block(ip1)}") # Deve retornar True, mas logar 'JÁ EXISTIA'

        # Teste 2: Verificar IPs
        print("\n--- Teste 2: Verificando IPs ---")
        print(f"Verificando {ip1}: {client.is_blocked(ip1)}")
        print(f"Verificando {ip2}: {client.is_blocked(ip2)}")
        print(f"Verificando 1.1.1.1: {client.is_blocked('1.1.1.1')}")

        # Teste 3: Listar IPs
        print("\n--- Teste 3: Listando IPs ---")
        blocked_list = client.get_blocked_ips()
        if blocked_list is not None:
             print(f"IPs bloqueados ({len(blocked_list)}): {sorted(list(blocked_list))}")
             # Verificar TTL da chave (se aplicável)
             if conn:
                  ttl_key = conn.ttl(key)
                  print(f"TTL da chave '{key}': {ttl_key} segundos (-1 = sem TTL, -2 = chave não existe)")
        else:
             print("Erro ao obter lista de IPs bloqueados.")


        # Teste 4: Remover IPs
        print("\n--- Teste 4: Removendo IPs ---")
        print(f"Removendo {ip2}: {client.remove_block(ip2)}")
        print(f"Removendo 1.1.1.1 (não existe): {client.remove_block('1.1.1.1')}")
        print(f"Verificando {ip2} após remoção: {client.is_blocked(ip2)}")

        # Listar novamente
        blocked_list_after_remove = client.get_blocked_ips()
        if blocked_list_after_remove is not None:
            print(f"IPs bloqueados após remoção ({len(blocked_list_after_remove)}): {sorted(list(blocked_list_after_remove))}")

        # Fechar conexão
        print("\n--- Fechando conexão ---")
        client.close()

    except Exception as main_e:
        print(f"\nERRO DURANTE O TESTE: {main_e}")

    print("\n--- Teste Concluído ---")