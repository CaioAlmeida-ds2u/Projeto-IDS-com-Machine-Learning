# /home/admin/ids_project/blocker_worker.py

import os
import logging
import time
import signal
import subprocess
import threading
import redis
from typing import Set, Optional, List
from ipaddress import ip_address, IPv4Address, IPv6Address
from concurrent.futures import ThreadPoolExecutor
from config import ConfigManager
from redis_client import RedisClient

logger = logging.getLogger("BlockerWorker")

class BlockerWorker:
    """Worker que sincroniza IPs bloqueados do Redis com o firewall."""
    def __init__(self):
        logger.info("Inicializando BlockerWorker...")
        self.config_manager = ConfigManager()
        self.running = True
        self.redis_client: Optional[RedisClient] = None
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.lock = threading.Lock()

        # Configurações
        self.firewall_type = 'iptables'
        self.check_interval = 5
        self.block_list_key = 'ids:blocked_ips'
        self.chain_name = 'IDS_BLOCK'  # Chain customizada para iptables
        self.currently_blocked_in_firewall: Set[str] = set()

        try:
            self._load_configuration()
            self._configure_logging()
            self._initialize_redis_client()
            self._setup_firewall()
            logger.info("BlockerWorker inicializado.")
        except Exception as e:
            logger.critical(f"Falha na inicialização: {e}", exc_info=True)
            self.running = False
            self._cleanup()
            raise RuntimeError("Falha na inicialização") from e

    def _load_configuration(self):
        """Carrega as configurações."""
        settings = self.config_manager.get_config().get('settings', {})
        log_level = settings.get('log_level', 'INFO').upper()
        self.log_level = getattr(logging, log_level, logging.INFO)

        worker_config = self.config_manager.get_blocker_worker_config()
        self.firewall_type = worker_config.get('firewall_type', 'iptables').lower()
        self.check_interval = int(worker_config.get('check_interval_seconds', 5))
        if self.check_interval <= 0:
            raise ValueError("check_interval_seconds deve ser positivo")
        if self.firewall_type not in ['iptables', 'ufw']:
            logger.warning(f"Firewall '{self.firewall_type}' não suportado. Usando iptables.")
            self.firewall_type = 'iptables'

        redis_config = self.config_manager.get_redis_config()
        self.block_list_key = redis_config.get('block_list_key', 'ids:blocked_ips')
        logger.info(f"Config: Firewall={self.firewall_type}, Interval={self.check_interval}s, Key={self.block_list_key}")

    def _configure_logging(self):
        """Configura o logging."""
        logging.basicConfig(level=self.log_level, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
        logger.info(f"Logging configurado: {logging.getLevelName(self.log_level)}")

    def _initialize_redis_client(self):
        """Inicializa o cliente Redis com retry."""
        redis_config = self.config_manager.get_redis_config()
        retries = 3
        for attempt in range(retries):
            try:
                self.redis_client = RedisClient(
                    host=redis_config.get('host', 'localhost'),
                    port=int(redis_config.get('port', 6379)),
                    db=int(redis_config.get('db', 0)),
                    password=redis_config.get('password'),
                    block_list_key=self.block_list_key,
                    block_ttl_seconds=int(redis_config.get('block_ttl_seconds', 3600))
                )
                if self.redis_client.get_connection():
                    logger.info("Redis inicializado.")
                    return
            except Exception as e:
                logger.error(f"Tentativa {attempt+1}/{retries} falhou: {e}")
                time.sleep(2 ** attempt)
        raise RuntimeError("Falha ao conectar ao Redis após retries")

    def _setup_firewall(self):
        """Configura o firewall inicial (ex.: cria chain no iptables)."""
        if self.firewall_type == 'iptables':
            commands = [
                ["iptables", "-w", "5", "-N", self.chain_name],  # Cria chain
                ["iptables", "-w", "5", "-A", "INPUT", "-j", self.chain_name]  # Liga à INPUT
            ]
            for cmd in commands:
                if not self._run_command(cmd):
                    logger.warning(f"Falha ao configurar chain {self.chain_name}. Tentando continuar.")
            self._sync_initial_firewall_state()

    def _sync_initial_firewall_state(self):
        """Sincroniza o estado inicial do firewall com o interno."""
        if self.firewall_type == 'iptables':
            try:
                output = subprocess.check_output(
                    ["iptables", "-L", self.chain_name, "-n", "--line-numbers"],
                    text=True
                )
                for line in output.splitlines()[2:]:  # Pula cabeçalhos
                    parts = line.split()
                    if len(parts) > 4 and parts[1] == "DROP" and parts[3]:
                        ip = parts[3]
                        self.currently_blocked_in_firewall.add(ip)
                logger.info(f"Estado inicial do firewall: {self.currently_blocked_in_firewall}")
            except Exception as e:
                logger.error(f"Erro ao sincronizar estado inicial: {e}")

    def _run_command(self, command: List[str]) -> bool:
        """Executa um comando de firewall."""
        try:
            cmd_str = ' '.join(command)
            logger.debug(f"Executando: {cmd_str}")
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=15)
            if result.stdout:
                logger.debug(f"Stdout: {result.stdout.strip()}")
            if result.stderr:
                logger.warning(f"Stderr: {result.stderr.strip()}")
            return True
        except Exception as e:
            logger.error(f"Erro ao executar '{command[0]}': {e}")
            return False

    def _validate_ip(self, ip: str) -> bool:
        """Valida o IP antes de bloquear."""
        try:
            ip_obj = ip_address(ip)
            if isinstance(ip_obj, IPv4Address) and ip_obj.is_private:
                logger.warning(f"IP privado {ip} não será bloqueado por segurança.")
                return False
            if ip in ['127.0.0.1', '::1']:
                logger.warning(f"Loopback {ip} não será bloqueado.")
                return False
            return True
        except ValueError:
            logger.error(f"IP inválido: {ip}")
            return False

    def _apply_block(self, ip: str) -> bool:
        """Aplica uma regra de bloqueio."""
        if not self._validate_ip(ip):
            return False
        if self.firewall_type == 'iptables':
            cmd = ["iptables", "-w", "5", "-A", self.chain_name, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "IDS_BLOCK"]
        else:  # ufw
            cmd = ["ufw", "deny", "from", ip, "comment", "IDS_BLOCK"]
        return self._run_command(cmd)

    def _remove_block(self, ip: str) -> bool:
        """Remove uma regra de bloqueio."""
        if self.firewall_type == 'iptables':
            cmd = ["iptables", "-w", "5", "-D", self.chain_name, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "IDS_BLOCK"]
        else:  # ufw
            cmd = ["ufw", "delete", "deny", "from", ip, "comment", "IDS_BLOCK"]
        return self._run_command(cmd)

    def synchronize_blocks(self):
        """Sincroniza os IPs bloqueados do Redis com o firewall."""
        with self.lock:
            if not self.redis_client:
                logger.error("Redis não disponível.")
                return
            try:
                desired_blocks = self.redis_client.get_blocked_ips() or set()
                current_blocks = self.currently_blocked_in_firewall

                # IPs a adicionar
                to_add = desired_blocks - current_blocks
                if to_add:
                    futures = [self.executor.submit(self._apply_block, ip) for ip in to_add]
                    for ip, future in zip(to_add, futures):
                        if future.result():
                            self.currently_blocked_in_firewall.add(ip)

                # IPs a remover
                to_remove = current_blocks - desired_blocks
                if to_remove:
                    futures = [self.executor.submit(self._remove_block, ip) for ip in to_remove]
                    for ip, future in zip(to_remove, futures):
                        if future.result():
                            self.currently_blocked_in_firewall.discard(ip)

                logger.debug(f"Sincronização concluída: Adicionados={len(to_add)}, Removidos={len(to_remove)}")
            except Exception as e:
                logger.error(f"Erro na sincronização: {e}", exc_info=True)

    def run(self):
        """Loop principal do worker."""
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        logger.info("BlockerWorker iniciado.")
        while self.running:
            try:
                start_time = time.monotonic()
                self.synchronize_blocks()
                elapsed = time.monotonic() - start_time
                time.sleep(max(0, self.check_interval - elapsed))
            except Exception as e:
                logger.error(f"Erro no loop: {e}", exc_info=True)
                time.sleep(self.check_interval)
        self._cleanup()

    def stop(self, signum=None, frame=None):
        """Para o worker."""
        logger.warning(f"Parando BlockerWorker (sinal {signum})...")
        self.running = False

    def _cleanup(self):
        """Limpa recursos ao encerrar."""
        logger.info("Limpando BlockerWorker...")
        self.executor.shutdown(wait=True)
        if self.redis_client:
            self.redis_client.close()
        # Não remove regras por padrão para persistência
        logger.info("BlockerWorker finalizado.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.critical("Este script requer privilégios de root.")
        exit(1)
    worker = None
    try:
        worker = BlockerWorker()
        worker.run()
    except Exception as e:
        logger.critical(f"Erro fatal: {e}", exc_info=True)
        exit(1)
    finally:
        if worker:
            worker._cleanup()
        time.sleep(0.5)
        exit(0)