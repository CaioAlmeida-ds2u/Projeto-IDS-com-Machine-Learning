# /home/admin/ids_project/config.py

import logging
import json
import copy
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ConfigManager:
    """Gerencia a configuração do IDS."""
    def __init__(self, config_path: str = None):
        self.config_path = config_path or os.environ.get('IDS_CONFIG_PATH', '/home/admin/ids_project/config.json')
        self._current_config = self._load_config()
        self._validate_config_values(self._current_config)
        self._apply_log_level()
        logger.info("ConfigManager inicializado.")

    def _load_config(self) -> Dict[str, Any]:
        """Carrega a configuração de um arquivo JSON ou usa padrões."""
        default_config = self._get_default_config()

        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                    merged_config = copy.deepcopy(default_config)
                    self._update_recursive(merged_config, loaded_config)
                    logger.info(f"Configuração carregada de {self.config_path}")
                    return merged_config
            except Exception as e:
                logger.error(f"Erro ao carregar {self.config_path}: {e}. Usando padrão.", exc_info=True)
        else:
            logger.warning(f"{self.config_path} não encontrado. Usando configuração padrão.")
        return copy.deepcopy(default_config)

    def _save_config(self):
        """Salva a configuração atual no arquivo JSON."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self._current_config, f, indent=4)
            logger.info(f"Configuração salva em {self.config_path}")
        except Exception as e:
            logger.error(f"Erro ao salvar configuração: {e}", exc_info=True)

    def _get_default_config(self) -> Dict[str, Any]:
        """Retorna a configuração padrão alinhada com todos os serviços."""
        return {
            'service': {
                'status': 'stopped',
                'allowed_actions': ['start', 'stop', 'status', 'get_config', 'shutdown']
            },
            'settings': {
                'interface': 'enp0s3',  # Alinhado com config.json revisado
                'filter': 'ip or ip6',
                'log_level': 'INFO',
                'service_host': 'localhost',
                'service_port': 65432,
                'health_api_port': 5005  # Não usado atualmente, mas mantido
            },
            'rabbitmq': {
                'host': os.environ.get('RABBITMQ_HOST', 'localhost'),
                'port': int(os.environ.get('RABBITMQ_PORT', 5672)),
                'packet_queue': 'ids_packet_analysis_queue',
                'alert_queue': 'ids_alert_notification_queue'  # Corrigido para o nome do config.json
            },
            'redis': {
                'host': os.environ.get('REDIS_HOST', 'localhost'),
                'port': int(os.environ.get('REDIS_PORT', 6379)),
                'db': int(os.environ.get('REDIS_DB', 0)),
                'password': os.environ.get('REDIS_PASSWORD'),
                'block_list_key': 'ids:blocked_ips',
                'block_ttl_seconds': 3600
            },
            'database': {
                'host': os.environ.get('DB_HOST', 'localhost'),
                'port': int(os.environ.get('DB_PORT', 3306)),
                'user': os.environ.get('DB_USER', 'ids_user'),
                'password': os.environ.get('DB_PASSWORD', 'fatec123'),
                'database': os.environ.get('DB_NAME', 'ids_db')
            },
            'ml_service': {
                'model_path': os.environ.get('ML_MODEL_PATH', '/home/admin/ids_project/models/modelo_ml.joblib'),
                'anomaly_threshold': -0.15,
                'feature_order': [
                    'payload_size', 'src_port', 'dst_port', 'ttl', 'udp_length', 'is_tcp', 'is_udp', 'is_icmp',
                    'flag_syn', 'flag_ack', 'flag_fin', 'flag_rst', 'flag_psh', 'flag_urg', 'flag_ece', 'flag_cwr',
                    'port_src_well_known', 'port_dst_well_known', 'port_dst_is_dns', 'port_dst_is_ntp',
                    'port_dst_is_http', 'port_dst_is_https', 'same_network', 'is_private'
                ]
            },
            'blocker_worker': {  # Adicionado para suportar blocker_worker.py
                'check_interval_seconds': 5,
                'firewall_type': 'iptables'
            }
        }

    def _update_recursive(self, target: Dict, source: Dict):
        """Atualiza um dicionário recursivamente."""
        for key, value in source.items():
            if isinstance(value, dict) and key in target and isinstance(target[key], dict):
                self._update_recursive(target[key], value)
            elif key in target:
                target[key] = value

    def _validate_config_values(self, config: Dict[str, Any]):
        """Valida os valores da configuração."""
        settings = config.get('settings', {})
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if settings.get('log_level', 'INFO').upper() not in valid_log_levels:
            raise ValueError(f"settings.log_level inválido. Esperado: {valid_log_levels}")
        if not (1 <= settings.get('service_port', 65432) <= 65535):
            raise ValueError("settings.service_port deve estar entre 1 e 65535")

        rabbitmq = config.get('rabbitmq', {})
        if not rabbitmq.get('host') or not (1 <= rabbitmq.get('port', 5672) <= 65535):
            raise ValueError("rabbitmq.host ou rabbitmq.port inválidos")

        redis = config.get('redis', {})
        if not redis.get('host') or not (1 <= redis.get('port', 6379) <= 65535) or redis.get('db', 0) < 0:
            raise ValueError("redis.host, redis.port ou redis.db inválidos")

        ml = config.get('ml_service', {})
        if not ml.get('model_path') or not isinstance(ml.get('anomaly_threshold'), (int, float)):
            raise ValueError("ml_service.model_path ou ml_service.anomaly_threshold inválidos")

        blocker = config.get('blocker_worker', {})
        if not isinstance(blocker.get('check_interval_seconds', 5), (int, float)) or blocker.get('check_interval_seconds', 5) <= 0:
            raise ValueError("blocker_worker.check_interval_seconds deve ser um número positivo")
        if blocker.get('firewall_type') not in ['iptables', 'ufw', None]:
            raise ValueError("blocker_worker.firewall_type inválido. Esperado: 'iptables' ou 'ufw'")

    def _apply_log_level(self):
        """Aplica o nível de log carregado ao logger global."""
        log_level = self._current_config.get('settings', {}).get('log_level', 'INFO').upper()
        logging.getLogger().setLevel(getattr(logging, log_level, logging.INFO))

    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """Atualiza a configuração."""
        config_backup = copy.deepcopy(self._current_config)
        try:
            self._update_recursive(self._current_config, new_config)
            self._validate_config_values(self._current_config)
            self._save_config()
            self._apply_log_level()
            return True
        except Exception as e:
            logger.error(f"Erro ao atualizar config: {e}", exc_info=True)
            self._current_config = config_backup
            return False

    def get_config(self) -> Dict[str, Any]:
        """Retorna uma cópia da configuração completa."""
        return copy.deepcopy(self._current_config)

    def get_service_config(self) -> Dict[str, Any]:
        """Retorna a config do serviço principal."""
        return self._current_config.get('service', {}).copy()

    def get_service_status(self) -> str:
        """Retorna o status do serviço."""
        return self._current_config.get('service', {}).get('status', 'unknown')

    def set_service_status(self, new_status: str):
        """Define o status do serviço."""
        valid_statuses = ['stopped', 'starting', 'running', 'stopping', 'error', 'initializing']
        if new_status in valid_statuses:
            self._current_config.setdefault('service', {})['status'] = new_status
            self._save_config()
            logger.info(f"Status atualizado: {new_status}")

    def get_rabbitmq_config(self) -> Dict[str, Any]:
        """Retorna a config do RabbitMQ."""
        return self._current_config.get('rabbitmq', {}).copy()

    def get_redis_config(self) -> Dict[str, Any]:
        """Retorna a config do Redis."""
        return self._current_config.get('redis', {}).copy()

    def get_ml_service_config(self) -> Dict[str, Any]:
        """Retorna a config do ML Service."""
        return self._current_config.get('ml_service', {}).copy()

    def get_database_config(self) -> Dict[str, Any]:
        """Retorna a config do banco de dados."""
        return self._current_config.get('database', {}).copy()

    def get_blocker_worker_config(self) -> Dict[str, Any]:
        """Retorna a config do Blocker Worker."""
        return self._current_config.get('blocker_worker', {}).copy()

    def get_settings_config(self) -> Dict[str, Any]:
        """Retorna a config das configurações gerais."""
        return self._current_config.get('settings', {}).copy()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    config = ConfigManager()
    print(json.dumps(config.get_config(), indent=2))