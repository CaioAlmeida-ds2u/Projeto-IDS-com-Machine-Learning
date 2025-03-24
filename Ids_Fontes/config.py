import logging
import json
from typing import Dict, Any
import os

logger = logging.getLogger(__name__)
CONFIG_FILE_PATH = 'config.json'  # Nome do arquivo de configuração

class ConfigManager:
    def __init__(self):
        self._current_config = self._load_config()
        logger.info("Configuração carregada")

    def _load_config(self) -> Dict[str, Any]:
        """Carrega a configuração do arquivo JSON ou inicializa com valores padrão."""
        if os.path.exists(CONFIG_FILE_PATH):
            try:
                with open(CONFIG_FILE_PATH, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Erro ao carregar configuração do arquivo: {str(e)}")
                return self._get_default_config()
        else:
            logger.info("Arquivo de configuração não encontrado, usando configuração padrão.")
            return self._get_default_config()

    def _save_config(self):
        """Salva a configuração atual no arquivo JSON."""
        try:
            with open(CONFIG_FILE_PATH, 'w') as f:
                json.dump(self._current_config, f, indent=4)
        except Exception as e:
            logger.error(f"Erro ao salvar configuração no arquivo: {str(e)}")

    def _get_default_config(self) -> Dict[str, Any]:
        """Retorna a configuração padrão."""
        return {
            'service': {
                'status': 'stopped',
                'requested_command': '',
                'allowed_actions': ['start', 'stop', 'status']
            },
            'settings': {
                'interface': 'enp0s3',
                'buffer_size': 100,
                'ml_endpoint': 'http://localhost:8000/predict',
                'log_level': 'INFO',
                'ml_flush_interval': 2
            }
        }

    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """Atualiza configurações dinamicamente via API"""
        try:
            if 'service' in new_config:
                self._current_config['service'].update(new_config['service'])
            if 'settings' in new_config:
                self._current_config['settings'].update(new_config['settings'])
            self._save_config()
            logger.debug("Configurações atualizadas com sucesso")
            return True
        except Exception as e:
            logger.error(f"Falha na atualização: {str(e)}")
            return False

    def get_config(self) -> Dict[str, Any]:
        """Retorna cópia segura da configuração atual"""
        return {
            'service': self._current_config['service'].copy(),
            'settings': self._current_config['settings'].copy()
        }

    def get_service_status(self) -> str:
        """Retorna o status atual do serviço"""
        return self._current_config['service']['status']

    def set_service_status(self, new_status: str):
        """Atualiza o status do serviço"""
        valid_statuses = ['stopped', 'running', 'error']
        if new_status in valid_statuses:
            self._current_config['service']['status'] = new_status
            self._save_config()
        else:
            logger.warning(f"Status inválido: {new_status}")

    def get_ml_endpoint(self) -> str:
        """Retorna o endpoint do modelo de ML"""
        return self._current_config['settings']['ml_endpoint']

    def get_capture_settings(self) -> Dict[str, Any]:
        """Retorna as configurações de captura de pacotes"""
        return {
            'interface': self._current_config['settings']['interface'],
            'buffer_size': self._current_config['settings']['buffer_size']
        }

    def set_log_level(self, level: str):
        """Configura o nível de log"""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level in valid_levels:
            self._current_config['settings']['log_level'] = level
            logging.basicConfig(level=level)
            self._save_config()
        else:
            logger.warning(f"Nível de log inválido: {level}")