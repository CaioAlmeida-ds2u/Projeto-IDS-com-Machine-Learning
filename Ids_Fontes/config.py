import logging
import json
import copy
from typing import Dict, Any
import os

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self):
        self._current_config = self._load_config()
        logger.info("Configuração carregada com sucesso.")

    def _load_config(self) -> Dict[str, Any]:
        """Carrega a configuração de um arquivo JSON (se existir) ou usa padrões."""
        config_file_path = os.environ.get('IDS_CONFIG_PATH', 'config.json')

        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Erro ao decodificar JSON em {config_file_path}: {e}. Usando configuração padrão.")
            except Exception as e:
                logger.error(f"Erro ao carregar {config_file_path}: {e}. Usando configuração padrão.")
        else:
            logger.info(f"Arquivo {config_file_path} não encontrado. Usando configuração padrão.")

        return self._get_default_config()

    def _save_config(self):
        """Salva a configuração atual no arquivo JSON."""
        config_file_path = os.environ.get('IDS_CONFIG_PATH', 'config.json')
        try:
            with open(config_file_path, 'w') as f:
                json.dump(self._current_config, f, indent=4)
            logger.info("Configuração salva com sucesso.")
        except IOError as e:
            logger.error(f"Erro ao salvar configuração em {config_file_path}: {e}")

    def _get_default_config(self) -> Dict[str, Any]:
        """Retorna a configuração padrão."""
        return {
            'service': {
                'status': 'stopped',
                'requested_command': '',
                'allowed_actions': ['start', 'stop', 'status', 'get_config']
            },
            'settings': {
                'interface': 'enp0s3',
                'filter': 'ip',
                'buffer_size': 100,
                'ml_endpoint': 'http://localhost:8000/predict',
                'log_level': 'INFO',
                'ml_flush_interval': 2,
                'service_host': 'localhost',
                'service_port': 65432,
                'udp_flood_threshold': 1000,
                'udp_ports_to_monitor': [53, 123, 161]
            },
            'rabbitmq': {
                'host': 'localhost',
                'port': 5672,
                'queue': 'pacotes_ids'
            }
        }

    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """Atualiza configurações dinamicamente via API."""
        try:
            if 'settings' in new_config:
                self._validate_settings(new_config['settings'])
                self._current_config['settings'].update(new_config['settings'])
            self._save_config()
            logger.info("Configurações atualizadas com sucesso.")
            return True
        except ValueError as e:
            logger.error(f"Erro de validação ao atualizar configuração: {e}")
            return False
        except Exception as e:
            logger.error(f"Erro inesperado ao atualizar configuração: {e}")
            return False

    def _validate_settings(self, settings: Dict[str, Any]):
        """Valida as configurações antes de atualizá-las."""
        if 'buffer_size' in settings and not isinstance(settings['buffer_size'], int):
            raise ValueError("buffer_size deve ser um inteiro.")
        if 'log_level' in settings and settings['log_level'].upper() not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError("log_level inválido. Use: DEBUG, INFO, WARNING, ERROR ou CRITICAL.")
        if 'udp_ports_to_monitor' in settings and not all(isinstance(port, int) for port in settings['udp_ports_to_monitor']):
            raise ValueError("udp_ports_to_monitor deve ser uma lista de inteiros.")
        if 'service_port' in settings and not (1 <= settings['service_port'] <= 65535):
            raise ValueError("service_port deve estar entre 1 e 65535.")

    def get_config(self) -> Dict[str, Any]:
        """Retorna a configuração atual."""
        # return {
        #     'service': self._current_config['service'].copy(),
        #     'settings': self._current_config['settings'].copy()
        # }      
        if self._current_config:
             return copy.deepcopy(self._current_config)
        else:
             # Retorna um dicionário vazio ou lança um erro se _current_config for None
             logger.warning("Tentativa de obter configuração antes de ser carregada ou após falha.")
             return {}

    def get_service_status(self) -> str:
        """Retorna o status atual do serviço."""
        return self._current_config['service']['status']

    def set_service_status(self, new_status: str):
        """Define o status do serviço."""
        valid_statuses = ['stopped', 'running', 'error']
        if new_status in valid_statuses:
            self._current_config['service']['status'] = new_status
            self._save_config()
            logger.info(f"Status do serviço atualizado para: {new_status}")
        else:
            logger.warning(f"Status inválido: {new_status}")

    def get_ml_endpoint(self) -> str:
        """Retorna o endpoint de Machine Learning."""
        return self._current_config['settings']['ml_endpoint']

    def get_capture_settings(self) -> Dict[str, Any]:
        """Retorna as configurações de captura."""
        return self._current_config['settings'].copy()

    def set_log_level(self, level: str):
        """Configura o nível de log e aplica imediatamente."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level.upper() in valid_levels:
            self._current_config['settings']['log_level'] = level.upper()
            logging.basicConfig(level=level.upper())
            self._save_config()
            logger.info(f"Nível de log alterado para {level.upper()}")
        else:
            logger.warning(f"Nível de log inválido: {level}")