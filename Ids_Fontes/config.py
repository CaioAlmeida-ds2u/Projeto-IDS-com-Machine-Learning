import json
import logging
from typing import Dict, Any
from filelock import FileLock

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, config_file: str = "/home/admin/ids_project/config.json"):
        self.config_file = config_file
        self.lock = FileLock(f"{self.config_file}.lock", timeout=5)
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Carrega e valida o arquivo de configuração com lock"""
        defaults = {
                'service': {
                    'status': 'stopped',
                    'requested_command': '',
                    'start_command': 'systemctl start ids_service',  # Adicione
                    'stop_command': 'systemctl stop ids_service'     # Adicione
                },
                'database': {
                    'host': 'localhost',
                    'port': 3306,
                    'user': 'ids_user',
                    'password': '',  # Campo obrigatório adicionado
                    'database': 'ids_db',
                    'ssl': False,
                    'connect_timeout': 10,  # Campos extras do seu JSON
                    'pool_size': 5
                },
                'settings': {
                    'interface': 'enp0s3',
                    'buffer_size': 100,
                    'write_interval': 5,
                    'packet_timeout': 30,  # Campo do seu JSON
                    'log_level': 'INFO'
                }
            }
        try:
            with self.lock:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("Arquivo de configuração não encontrado ou corrompido. Usando valores padrão.")
            config = {}
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            raise

        # Mescla a configuração existente com os padrões
        for section, values in defaults.items():
            config.setdefault(section, {})
            for key, value in values.items():
                config[section].setdefault(key, value)

        if not config['database'].get('password'):
            logger.critical("Senha do banco de dados não configurada!")
            raise ValueError("Database password not configured")

        return config

    def reload_config(self):
        """Recarrega o arquivo de configuração"""
        self.config = self._load_config()

    def update_service_status(self, new_status: str):
        """Atualiza o status do serviço de forma atômica"""
        try:
            with self.lock:
                with open(self.config_file, 'r+') as f:
                    config = json.load(f)
                    config['service']['status'] = new_status
                    f.seek(0)
                    json.dump(config, f, indent=4)
                    f.truncate()
                self.config['service']['status'] = new_status  # Atualiza cache interno
        except Exception as e:
            logger.error(f"Erro ao atualizar status: {e}")
            raise

    def get_service_status(self) -> str:
        """Obtém o status atual do serviço"""
        return self.config['service'].get('status', 'unknown')

    def get_database_config(self) -> Dict[str, Any]:
        """Obtém a configuração do banco de dados"""
        return self.config['database']

    def get_settings(self) -> Dict[str, Any]:
        """Obtém as configurações gerais"""
        return self.config['settings']

    def get_service_commands(self) -> Dict[str, str]:
        """Obtém os comandos do serviço"""
        return self.config['service']
