import logging
import json
from typing import Dict, Any
import os

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self):
        self._current_config = self._load_config()
        logger.info("Configuração carregada")

    def _load_config(self) -> Dict[str, Any]:
        """Carrega a configuração de um arquivo JSON (se existir) ou usa padrões."""
        config_file_path = os.environ.get('IDS_CONFIG_PATH', 'config.json') # Melhora: Variável de ambiente

        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Erro ao carregar {config_file_path}: {e}. Usando configuração padrão.")
                return self._get_default_config()  # Retorna padrão em caso de erro
        else:
            logger.info(f"Arquivo {config_file_path} não encontrado. Usando configuração padrão.")
            return self._get_default_config()

    def _save_config(self):
        """Salva a configuração atual no arquivo JSON."""
        config_file_path = os.environ.get('IDS_CONFIG_PATH', 'config.json')
        try:
            with open(config_file_path, 'w') as f:
                json.dump(self._current_config, f, indent=4)
        except Exception as e:
            logger.error(f"Erro ao salvar configuração: {e}")

    def _get_default_config(self) -> Dict[str, Any]:
        """Retorna a configuração padrão."""
        return {
            'service': {  # Separando 'service' e 'settings'
                'status': 'stopped',
                'requested_command': '',
                'allowed_actions': ['start', 'stop', 'status', 'get_config']
            },
            'settings': { # Todas as configurações *do IDS* ficam aqui
                'interface': 'enp0s3',
                'filter': 'ip',  # Filtro padrão
                'buffer_size': 100,
                'ml_endpoint': 'http://localhost:8000/predict',
                'log_level': 'INFO',
                'ml_flush_interval': 2,
                'service_host': 'localhost',  # Adicionado para consistência
                'service_port': 65432        # Adicionado para consistência

            }
        }

    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """Atualiza configurações dinamicamente via API."""
        try:
            # Atualiza apenas a seção 'settings', não 'service'
            if 'settings' in new_config:
                self._current_config['settings'].update(new_config['settings'])
            self._save_config()
            logger.info("Configurações atualizadas com sucesso")
            return True
        except Exception as e:
            logger.error(f"Falha na atualização da configuração: {e}")
            return False

    def get_config(self) -> Dict[str, Any]:
        """Retorna uma cópia da configuração atual."""
        return {  # Retorna cópias para evitar modificações externas
            'service': self._current_config['service'].copy(),
            'settings': self._current_config['settings'].copy()
        }
    # Métodos para obter partes específicas (opcional, mas útil)
    def get_service_status(self) -> str:
        return self._current_config['service']['status']

    def set_service_status(self, new_status: str):
        valid_statuses = ['stopped', 'running', 'error']
        if new_status in valid_statuses:
            self._current_config['service']['status'] = new_status
            self._save_config()  # Salva a mudança de status
        else:
            logger.warning(f"Status inválido: {new_status}")

    def get_ml_endpoint(self) -> str:
        return self._current_config['settings']['ml_endpoint']

    def get_capture_settings(self) -> Dict[str, Any]:
        return self._current_config['settings'].copy()  # Retorna uma cópia


    def set_log_level(self, level: str):
        """Configura o nível de log (e aplica imediatamente)."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level.upper() in valid_levels:
            self._current_config['settings']['log_level'] = level.upper()
            logging.basicConfig(level=level.upper())  # Aplica o novo nível
            self._save_config()
            logger.info(f"Nível de log alterado para {level.upper()}")
        else:
            logger.warning(f"Nível de log inválido: {level}")