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
                    # Usar um deepcopy garante que a configuração padrão não seja alterada
                    # se o arquivo carregado for incompleto e depois mesclado.
                    loaded_config = json.load(f)
                    default_config = self._get_default_config()
                    # Mescla o carregado com o padrão (padrão como base)
                    # Isso garante que novas chaves padrão existam se o arquivo for antigo
                    merged_config = copy.deepcopy(default_config)
                    # Atualiza recursivamente para mesclar sub-dicionários
                    def update_recursive(target, source):
                        for key, value in source.items():
                            if isinstance(value, dict) and key in target and isinstance(target[key], dict):
                                update_recursive(target[key], value)
                            else:
                                target[key] = value
                    update_recursive(merged_config, loaded_config)
                    return merged_config
            except json.JSONDecodeError as e:
                logger.error(f"Erro ao decodificar JSON em {config_file_path}: {e}. Usando configuração padrão.")
            except Exception as e:
                logger.error(f"Erro ao carregar {config_file_path}: {e}. Usando configuração padrão.")
        else:
            logger.info(f"Arquivo {config_file_path} não encontrado. Usando configuração padrão.")

        # Retorna a configuração padrão se o arquivo não existir ou falhar ao carregar/mesclar
        return self._get_default_config()

    def _save_config(self):
        """Salva a configuração atual no arquivo JSON."""
        config_file_path = os.environ.get('IDS_CONFIG_PATH', 'config.json')
        try:
            with open(config_file_path, 'w') as f:
                json.dump(self._current_config, f, indent=4, sort_keys=True) # sort_keys para consistência
            logger.info(f"Configuração salva com sucesso em {config_file_path}.")
        except IOError as e:
            logger.error(f"Erro ao salvar configuração em {config_file_path}: {e}")
        except Exception as e:
             logger.error(f"Erro inesperado ao salvar configuração: {e}")

    def _get_default_config(self) -> Dict[str, Any]:
        """Retorna a configuração padrão completa para a nova arquitetura."""
        return {
            'service': {
                'status': 'stopped',
                'requested_command': '',
                # Adicionado 'shutdown' se você for usar esse comando via API de controle
                'allowed_actions': ['start', 'stop', 'status', 'get_config', 'shutdown']
            },
            'settings': {
                # Manter interface, filter, log_level, service_host, service_port
                'interface': 'eth0', # Ajuste conforme sua interface principal
                'filter': 'ip or ip6', # Filtro geral para capturar tráfego IP
                'log_level': 'INFO',
                'service_host': 'localhost', # Host para o socket de controle do main.py
                'service_port': 65432,      # Porta para o socket de controle do main.py
            },
            'rabbitmq': {
                'host': 'localhost',
                'port': 5672,
                # Filas específicas para cada propósito
                'packet_queue': 'ids_packet_analysis_queue', # Fila para pacotes suspeitos (IDS -> ML)
                'alert_queue': 'ids_alert_notification_queue'   # Fila para alertas/notificações (ML -> API/Dashboard)
            },
            'redis': { # <<< NOVA SEÇÃO >>>
                'host': 'localhost',
                'port': 6379,
                'db': 0,
                'block_list_key': 'ids:blocked_ips', # Nome da chave (Set) no Redis
                'block_ttl_seconds': 3600           # Tempo (em seg) que um IP fica bloqueado (0 = para sempre)
            },
            'blocker_worker': { # <<< NOVA SEÇÃO >>>
                 'firewall_type': 'iptables', # Ou 'ufw' - o tipo de firewall a ser usado
                 'check_interval_seconds': 5  # Intervalo (em seg) para verificar o Redis por mudanças
            },
            'ml_service': { # <<< NOVA SEÇÃO >>>
                'model_path': 'modelo_ml.joblib', # Caminho para o modelo treinado
                'anomaly_threshold': -0.15        # Limiar de score para considerar anomalia (ajustar)
            }
            # Manter 'database' se o db.py ainda for usado para logar pacotes/anomalias
            # 'database': {
            #     'host': 'localhost',
            #     'port': 3306,
            #     'user': 'ids_user',
            #     'password': 'your_db_password', # Use variáveis de ambiente em produção!
            #     'database': 'ids_db'
            # }
        }

    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """Atualiza configurações dinamicamente. Valida e salva."""
        # Faz uma cópia profunda para não alterar o original em caso de erro
        config_backup = copy.deepcopy(self._current_config)
        try:
            # Atualiza recursivamente para preservar sub-chaves não alteradas
            def update_recursive(target, source):
                for key, value in source.items():
                    if key in target: # Só atualiza chaves que existem no padrão
                        if isinstance(value, dict) and isinstance(target[key], dict):
                            # Se for um dicionário e a chave existe e também é dicionário, atualiza recursivamente
                            update_recursive(target[key], value)
                        elif not isinstance(value, dict) and not isinstance(target[key], dict):
                             # Atualiza apenas se ambos não forem dicionários (evita substituir dict por valor)
                             # Adicionar validações de tipo aqui se necessário
                             target[key] = value
                        # else: Ignora se os tipos não correspondem (ex: tentar substituir dict por int)
                    # else: Ignora chaves que não existem na configuração padrão/atual

            update_recursive(self._current_config, new_config)

            # --- VALIDAÇÃO APÓS ATUALIZAÇÃO ---
            # É importante validar *depois* de tentar mesclar, usando a config atualizada
            self._validate_config_values(self._current_config)

            # Se passou na validação, salva
            self._save_config()
            logger.info("Configurações atualizadas e validadas com sucesso.")
            return True

        except ValueError as e: # Erro de validação
            logger.error(f"Erro de validação ao atualizar configuração: {e}")
            self._current_config = config_backup # Restaura backup em caso de erro
            return False
        except Exception as e: # Outros erros
            logger.error(f"Erro inesperado ao atualizar configuração: {e}", exc_info=True)
            self._current_config = config_backup # Restaura backup
            return False

    def _validate_config_values(self, config_to_check: Dict[str, Any]):
        """Valida os valores nas configurações após uma tentativa de atualização."""
        # Validações da seção 'settings'
        settings = config_to_check.get('settings', {})
        if not isinstance(settings.get('log_level', 'INFO'), str) or \
           settings.get('log_level', 'INFO').upper() not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError("settings.log_level inválido.")
        if not isinstance(settings.get('service_port', 65432), int) or \
           not (1 <= settings.get('service_port', 65432) <= 65535):
            raise ValueError("settings.service_port deve ser um inteiro entre 1 e 65535.")
        # Adicione validação para 'interface', 'filter', 'service_host' se necessário

        # Validações da seção 'rabbitmq'
        rabbitmq = config_to_check.get('rabbitmq', {})
        if not isinstance(rabbitmq.get('host'), str) or not rabbitmq.get('host'):
             raise ValueError("rabbitmq.host deve ser uma string não vazia.")
        if not isinstance(rabbitmq.get('port'), int) or not (1 <= rabbitmq.get('port') <= 65535):
             raise ValueError("rabbitmq.port deve ser um inteiro entre 1 e 65535.")
        if not isinstance(rabbitmq.get('packet_queue'), str) or not rabbitmq.get('packet_queue'):
             raise ValueError("rabbitmq.packet_queue deve ser uma string não vazia.")
        if not isinstance(rabbitmq.get('alert_queue'), str) or not rabbitmq.get('alert_queue'):
             raise ValueError("rabbitmq.alert_queue deve ser uma string não vazia.")

        # Validações da seção 'redis'
        redis_cfg = config_to_check.get('redis', {})
        if not isinstance(redis_cfg.get('host'), str) or not redis_cfg.get('host'):
             raise ValueError("redis.host deve ser uma string não vazia.")
        if not isinstance(redis_cfg.get('port'), int) or not (1 <= redis_cfg.get('port') <= 65535):
             raise ValueError("redis.port deve ser um inteiro entre 1 e 65535.")
        if not isinstance(redis_cfg.get('db'), int) or redis_cfg.get('db') < 0:
             raise ValueError("redis.db deve ser um inteiro não negativo.")
        if not isinstance(redis_cfg.get('block_list_key'), str) or not redis_cfg.get('block_list_key'):
             raise ValueError("redis.block_list_key deve ser uma string não vazia.")
        if not isinstance(redis_cfg.get('block_ttl_seconds'), int) or redis_cfg.get('block_ttl_seconds') < 0:
             raise ValueError("redis.block_ttl_seconds deve ser um inteiro não negativo (0 para sem TTL).")

        # Validações da seção 'blocker_worker'
        blocker = config_to_check.get('blocker_worker', {})
        if not isinstance(blocker.get('firewall_type'), str) or blocker.get('firewall_type').lower() not in ['iptables', 'ufw']:
             raise ValueError("blocker_worker.firewall_type deve ser 'iptables' ou 'ufw'.")
        if not isinstance(blocker.get('check_interval_seconds'), int) or blocker.get('check_interval_seconds') <= 0:
             raise ValueError("blocker_worker.check_interval_seconds deve ser um inteiro positivo.")

        # Validações da seção 'ml_service'
        ml = config_to_check.get('ml_service', {})
        if not isinstance(ml.get('model_path'), str) or not ml.get('model_path'):
             raise ValueError("ml_service.model_path deve ser uma string não vazia.")
        # Validar se o path existe? Talvez não aqui, mas no serviço ML.
        if not isinstance(ml.get('anomaly_threshold'), (int, float)):
             raise ValueError("ml_service.anomaly_threshold deve ser um número (int ou float).")

        # Adicione validações para 'database' se estiver usando
        # ...

        logger.debug("Valores de configuração verificados com sucesso.")

    def get_config(self) -> Dict[str, Any]:
        """Retorna uma cópia profunda da configuração atual."""
        if self._current_config:
             # Retorna cópia profunda para evitar modificações externas acidentais
             return copy.deepcopy(self._current_config)
        else:
             logger.warning("Tentativa de obter configuração antes de ser carregada ou após falha.")
             # Retornar padrão ou vazio? Retornar padrão é mais seguro.
             return copy.deepcopy(self._get_default_config())


    def get_service_status(self) -> str:
        """Retorna o status atual do serviço (do nó 'service')."""
        # Adiciona verificação caso _current_config seja None inesperadamente
        if self._current_config and 'service' in self._current_config:
            return self._current_config['service'].get('status', 'unknown')
        return 'unknown'

    def set_service_status(self, new_status: str):
        """Define o status do serviço (no nó 'service') e salva."""
        valid_statuses = ['stopped', 'starting', 'running', 'stopping', 'error', 'initializing']
        if new_status in valid_statuses:
            # Garante que a estrutura existe antes de tentar definir
            if not self._current_config: self._current_config = self._get_default_config()
            if 'service' not in self._current_config: self._current_config['service'] = {}

            if self._current_config['service'].get('status') != new_status:
                 self._current_config['service']['status'] = new_status
                 self._save_config() # Salva a mudança de status
                 logger.info(f"Status do serviço ('service.status') atualizado para: {new_status}")
            # else: logger.debug(f"Status do serviço já é {new_status}, sem alterações.")
        else:
            logger.warning(f"Tentativa de definir status inválido: {new_status}")

    # --- Remover get_ml_endpoint ---
    # def get_ml_endpoint(self) -> str: ...


    def get_capture_settings(self) -> Dict[str, Any]:
        """Retorna as configurações relevantes para a captura (do nó 'settings')."""
        # Retorna apenas as chaves relevantes para captura, se necessário, ou a seção inteira
        if self._current_config and 'settings' in self._current_config:
            # Exemplo: retornar apenas interface e filtro
            # return {
            #     'interface': self._current_config['settings'].get('interface'),
            #     'filter': self._current_config['settings'].get('filter')
            # }
            # Ou retornar a cópia da seção inteira
            return self._current_config['settings'].copy()
        return {}

    # --- Getters para as novas seções ---
    def get_rabbitmq_config(self) -> Dict[str, Any]:
        """Retorna uma cópia da configuração RabbitMQ."""
        if self._current_config and 'rabbitmq' in self._current_config:
            return self._current_config['rabbitmq'].copy()
        return {}

    def get_redis_config(self) -> Dict[str, Any]:
        """Retorna uma cópia da configuração Redis."""
        if self._current_config and 'redis' in self._current_config:
            return self._current_config['redis'].copy()
        return {}

    def get_blocker_worker_config(self) -> Dict[str, Any]:
        """Retorna uma cópia da configuração Blocker Worker."""
        if self._current_config and 'blocker_worker' in self._current_config:
            return self._current_config['blocker_worker'].copy()
        return {}

    def get_ml_service_config(self) -> Dict[str, Any]:
        """Retorna uma cópia da configuração ML Service."""
        if self._current_config and 'ml_service' in self._current_config:
            return self._current_config['ml_service'].copy()
        return {}

    # Manter set_log_level, mas garantir que ele atualize o logger raiz
    def set_log_level(self, level: str):
         """Configura o nível de log, aplica imediatamente e salva."""
         valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
         level_upper = level.upper()
         if level_upper in valid_levels:
             try:
                 # Garante que a estrutura existe
                 if not self._current_config: self._current_config = self._get_default_config()
                 if 'settings' not in self._current_config: self._current_config['settings'] = {}

                 # Atualiza a configuração interna
                 self._current_config['settings']['log_level'] = level_upper

                 # Aplica ao logger raiz imediatamente
                 # NOTA: Isso reconfigura o logging globalmente.
                 # Considere uma abordagem mais granular se tiver múltiplos handlers.
                 logging.getLogger().setLevel(level_upper)
                 # Log com o NOVO nível para confirmar
                 logger.warning(f"Nível de log alterado para {level_upper}") # Usar warning para garantir visibilidade

                 # Salva a configuração
                 self._save_config()
             except Exception as e:
                  logger.error(f"Erro ao definir nível de log para {level_upper}: {e}")
         else:
             logger.warning(f"Nível de log inválido: {level}. Níveis válidos: {valid_levels}")