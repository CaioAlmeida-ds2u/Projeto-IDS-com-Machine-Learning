#!/usr/bin/env python3
import time
import json
import argparse
import logging
import threading
import queue
from logging.handlers import RotatingFileHandler
from filelock import Timeout, FileLock
from typing import Optional

# --- Configurações ---
CONFIG_FILE = "config.json"
LOCK_TIMEOUT = 5  # segundos
CHECK_INTERVAL = 3  # Tempo entre leituras
MAX_LOG_SIZE = 2 * 1024 * 1024  # 2MB
LOG_BACKUP_COUNT = 3

COMMAND_QUEUE = queue.Queue()  # Fila de comandos

class ControlService:
    def __init__(self):
        self._configure_logging()
        self.config_lock = FileLock(f"{CONFIG_FILE}.lock", timeout=LOCK_TIMEOUT)
        self.valid_commands = ['start', 'stop', 'restart', 'status']
        
        # Inicia a thread do worker para processar a fila de comandos
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()

    def _configure_logging(self):
        """Configura o sistema de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler('logs/control.log', maxBytes=MAX_LOG_SIZE, backupCount=LOG_BACKUP_COUNT),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _read_config(self) -> Optional[dict]:
        """Lê o arquivo de configuração"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Erro ao ler configuração: {e}")
            return None

    def _write_config(self, config: dict) -> bool:
        """Escreve no arquivo de configuração"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            self.logger.error(f"Erro ao escrever configuração: {e}")
            return False

    def update_service_status(self, command: str):
        """Adiciona o comando na fila para processamento"""
        COMMAND_QUEUE.put(command)
        self.logger.info(f"Comando '{command}' adicionado à fila")

    def _process_queue(self):
        """Thread que processa os comandos da fila"""
        while True:
            try:
                command = COMMAND_QUEUE.get()
                self._execute_command(command)
                COMMAND_QUEUE.task_done()
            except Exception as e:
                self.logger.error(f"Erro ao processar fila: {e}")
            time.sleep(CHECK_INTERVAL)

    def _execute_command(self, command: str):
        if command not in self.valid_commands:
            self.logger.error(f"Comando inválido: {command}")
            return
    
        try:
            with self.config_lock:
                config = self._read_config()
                if not config:
                    self.logger.error("Falha ao ler a configuração.")
                    return
    
                config.setdefault('service', {})  # Garante que a chave 'service' existe
                config['service']['requested_command'] = command
                config['service']['status'] = 'pending'  # Define status intermediário
                
                if not self._write_config(config):
                    self.logger.error("Falha ao escrever a configuração.")
                    return
    
                self.logger.info(f"Comando '{command}' processado com sucesso.")
        except Exception as e:
            self.logger.exception(f"Erro ao executar comando '{command}': {e}")


    def get_status(self) -> Optional[str]:
        """Obtém o status do serviço"""
        try:
            with self.config_lock:
                config = self._read_config()
                return config['service'].get('status', 'unknown') if config else 'unconfigured'
        except Timeout:
            self.logger.error("Timeout ao verificar status")
            return None

    def run_command(self, command: str):
        """Envia um comando para ser executado"""
        start_time = time.time()

        if command == 'status':
            if status := self.get_status():
                print(f"Status do IDS: {status.upper()}")
                self.logger.info(f"Status verificado: {status}")
            return

        self.update_service_status(command)
        elapsed = time.time() - start_time
        self.logger.debug(f"Comando '{command}' enviado para fila em {elapsed:.2f}s")

def main():
    parser = argparse.ArgumentParser(
        description="Controlador do IDS - Gerencia a operação do sistema",
        epilog="Exemplos:\n  sudo ./control.py start\n  sudo ./control.py status"
    )
    
    parser.add_argument(
        'command',
        choices=['start', 'stop', 'restart', 'status'],
        help="Comando para executar"
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Habilita modo verboso"
    )
    
    args = parser.parse_args()
    
    controller = ControlService()
    if args.verbose:
        controller.logger.setLevel(logging.DEBUG)
    
    controller.run_command(args.command)

if __name__ == "__main__":
    main()
