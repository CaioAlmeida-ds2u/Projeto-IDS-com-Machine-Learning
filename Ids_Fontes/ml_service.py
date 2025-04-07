import logging
import json
import signal
import pika
import joblib
import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional # Adicionado Optional
import pandas as pd

try:
    from config import ConfigManager
    from redis_client import RedisClient
except ImportError as e:
    print(f"Erro ao importar módulos locais: {e}")
    exit(1)

# Configuração básica de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s'
)
logger = logging.getLogger("MLService")

# Mapeamento de números de protocolo para nomes
PROTOCOL_MAP = {
    6: "tcp",
    17: "udp",
    1: "icmp"
}

class MLService:
    def __init__(self):
        """Inicializa o MLService com configurações e dependências."""
        logger.info("Inicializando MLService...")
        self.running = True
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None
        self.consumer_tag = None

        # Carregar configurações
        self.config_manager = ConfigManager()
        self._load_configuration()
        self.redis_client = self._initialize_redis_client()
        self.model = self._load_model()

        # Limites de detecção (Carregados da config agora)
        # self.ssh_brute_force_threshold = 3  # Movido para _load_configuration
        # self.dns_abuse_threshold = 50       # Movido para _load_configuration
        # self.icmp_ddos_threshold = 20       # Movido para _load_configuration
        # self.udp_ddos_threshold = 100       # Movido para _load_configuration
        # self.ml_anomaly_threshold = -0.4    # Adicionado para ML (configurável)

    def _load_configuration(self):
        """Carrega as configurações do ConfigManager."""
        settings = self.config_manager.get_config().get('settings', {})
        self.rabbitmq_host = self.config_manager.get_rabbitmq_config().get('host', 'localhost')
        self.rabbitmq_port = int(self.config_manager.get_rabbitmq_config().get('port', 5672))
        self.rabbitmq_packet_queue = self.config_manager.get_rabbitmq_config().get('queue', 'pacotes')
        self.rabbitmq_alert_queue = self.config_manager.get_rabbitmq_config().get('alert_queue', 'ids_alert_notification_queue')

        ml_config = self.config_manager.get_ml_service_config()
        self.model_path = ml_config.get('model_path')
        if not self.model_path or not os.path.exists(self.model_path):
            # logger.critical(f"Caminho do modelo não encontrado ou inválido: {self.model_path}. Verifique 'ml_service.model_path' no config.yml")
            # raise ValueError(f"Modelo não encontrado em: {self.model_path}")
            # Decidi logar como erro e continuar sem modelo, ou usar apenas regras
            logger.error(f"Modelo não encontrado em: {self.model_path}. MLService operará apenas com regras baseadas em contagem.")
            self.model = None # Definir modelo como None
        
        self.feature_order = ml_config.get('feature_order', [
            'payload_size', 'src_port', 'dst_port', 'ttl', 'udp_length', 'is_tcp', 'is_udp', 'is_icmp',
            'flag_syn', 'flag_ack', 'flag_fin', 'flag_rst', 'flag_psh', 'flag_urg', 'flag_ece', 'flag_cwr',
            'port_src_well_known', 'port_dst_well_known', 'port_dst_is_dns', 'port_dst_is_ntp',
            'port_dst_is_http', 'port_dst_is_https', 'same_network', 'is_private'
        ])

        # Carregar thresholds da configuração, com defaults
        detection_config = ml_config.get('detection_thresholds', {})
        self.ssh_brute_force_threshold = int(detection_config.get('ssh_attempts', 3))
        self.ssh_brute_force_window = int(detection_config.get('ssh_window_seconds', 5))
        self.dns_abuse_threshold = int(detection_config.get('dns_attempts', 50))
        self.dns_abuse_window = int(detection_config.get('dns_window_seconds', 5))
        self.icmp_ddos_threshold = int(detection_config.get('icmp_packets', 20))
        self.icmp_ddos_window = int(detection_config.get('icmp_window_seconds', 5))
        self.udp_ddos_threshold = int(detection_config.get('udp_packets', 100))
        self.udp_ddos_window = int(detection_config.get('udp_window_seconds', 5))
        self.ml_anomaly_threshold = float(detection_config.get('ml_anomaly_score', -0.4)) # Threshold para considerar ML como anômalo

        logger.info("Configurações carregadas com sucesso.")
        logger.info(f"Thresholds: SSH={self.ssh_brute_force_threshold}/{self.ssh_brute_force_window}s, "
                    f"DNS={self.dns_abuse_threshold}/{self.dns_abuse_window}s, "
                    f"ICMP={self.icmp_ddos_threshold}/{self.icmp_ddos_window}s, "
                    f"UDP={self.udp_ddos_threshold}/{self.udp_ddos_window}s, "
                    f"ML Score={self.ml_anomaly_threshold}")


    def _initialize_redis_client(self) -> RedisClient:
        """Inicializa o cliente Redis."""
        redis_config = self.config_manager.get_redis_config()
        block_ttl = int(self.config_manager.get_ml_service_config().get('block_ttl_seconds', 3600))
        return RedisClient(
            host=redis_config.get('host', 'localhost'),
            port=int(redis_config.get('port', 6379)),
            db=int(redis_config.get('db', 0)),
            password=redis_config.get('password'),
            block_list_key='ids:blocked_ips',
            block_ttl_seconds=block_ttl # Usar TTL da config
        )

    def _load_model(self):
        """Carrega o modelo de IsolationForest (se o caminho foi definido)."""
        if not self.model_path: # Se o caminho não foi definido em _load_configuration
             logger.warning("Nenhum caminho de modelo definido. Operando sem ML.")
             return None
        try:
            model = joblib.load(self.model_path)
            logger.info(f"Modelo carregado de: {self.model_path}")
            return model
        except FileNotFoundError:
            logger.error(f"Arquivo do modelo não encontrado em: {self.model_path}. Operando sem ML.")
            return None
        except Exception as e:
            logger.error(f"Erro ao carregar modelo de {self.model_path}: {e}. Operando sem ML.")
            return None # Retorna None se não puder carregar

    def _connect_to_rabbitmq(self):
        """Estabelece conexão com o RabbitMQ com retentativas."""
        max_retries = 5
        wait_time = 5 # Tempo inicial de espera
        for attempt in range(max_retries):
            try:
                # Considerar buscar credenciais do config manager também
                credentials = pika.PlainCredentials('guest', 'guest')
                params = pika.ConnectionParameters(
                    host=self.rabbitmq_host,
                    port=self.rabbitmq_port,
                    credentials=credentials,
                    heartbeat=600,
                    blocked_connection_timeout=300
                )
                self.rabbitmq_connection = pika.BlockingConnection(params)
                self.rabbitmq_channel = self.rabbitmq_connection.channel()
                self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_packet_queue, durable=True)
                self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_alert_queue, durable=True)
                logger.info(f"Conectado ao RabbitMQ em {self.rabbitmq_host}:{self.rabbitmq_port}")
                return True
            except pika.exceptions.AMQPConnectionError as e:
                logger.error(f"Conexão RabbitMQ falhou (tentativa {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    logger.info(f"Aguardando {wait_time}s para tentar novamente...")
                    time.sleep(wait_time)
                    wait_time *= 2 # Backoff exponencial simples para conexão inicial
                else:
                    logger.critical("Não foi possível conectar ao RabbitMQ após várias tentativas.")
                    return False
        return False # Caso saia do loop sem sucesso

    def _prepare_features(self, data: Dict[str, any]) -> Optional[pd.DataFrame]:
        """Prepara as features como DataFrame para o modelo."""
        try:
            # Garante que todas as features esperadas existam, preenchendo com 0.0 se faltar
            features = {feature: float(data.get(feature, 0.0)) for feature in self.feature_order}
            return pd.DataFrame([features])
        except Exception as e:
            logger.error(f"Erro ao preparar features para {data.get('src_ip')}->{data.get('dst_ip')}: {e}. Dados: {data}")
            return None

    def _track_attempts(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str, data: Dict[str, any]) -> Optional[Dict[str, str]]:
        """
        Rastreia tentativas de acesso por IP de origem e retorna ação se exceder limite.
        Retorna um dicionário de ação ou None se nenhum limite for atingido.
        """
        action_details = None # Guarda os detalhes da ação se um limite for atingido

        # Rastreio para SSH brute force (TCP, porta 22)
        # Condições mais específicas podem ser adicionadas se necessário (ex: flags)
        if protocol == "tcp" and dst_port == 22:
             # Opcional: refinar condição para contar apenas SYNs iniciais, se necessário
             # if data.get('flag_syn', 0) == 1 and data.get('flag_ack', 0) == 0:
                key = f"ssh_attempts:{src_ip}_to_{dst_ip}:{dst_port}" # Chave mais específica
                count = self.redis_client.incr_with_expiry(key, expiry=self.ssh_brute_force_window)
                if count is not None and count >= self.ssh_brute_force_threshold:
                    action_details = {
                        "action": "block_ip",
                        "target": src_ip,
                        "reason": f"Brute force SSH detectado: {count} tentativas para {dst_ip}:{dst_port} em {self.ssh_brute_force_window}s"
                    }

        # Rastreio para abuso DNS (UDP, porta 53)
        elif protocol == "udp" and dst_port == 53:
            key = f"dns_attempts:{src_ip}"
            count = self.redis_client.incr_with_expiry(key, expiry=self.dns_abuse_window)
            if count is not None and count >= self.dns_abuse_threshold:
                action_details = {
                    "action": "block_ip",
                    "target": src_ip,
                    "reason": f"Abuso DNS detectado: {count} pacotes UDP/53 em {self.dns_abuse_window}s"
                }

        # Rastreio para possíveis ataques DDoS via ICMP
        elif protocol == "icmp":
            key = f"icmp_packets:{src_ip}"
            count = self.redis_client.incr_with_expiry(key, expiry=self.icmp_ddos_window)
            if count is not None and count >= self.icmp_ddos_threshold:
                action_details = {
                    "action": "block_ip",
                    "target": src_ip,
                    "reason": f"Possível DDoS ICMP detectado: {count} pacotes ICMP em {self.icmp_ddos_window}s"
                }

        # Rastreio para possíveis ataques DDoS via UDP (genérico, excluindo DNS)
        elif protocol == "udp" and dst_port != 53:
            key = f"udp_packets:{src_ip}" # Chave genérica para UDP não-DNS
            count = self.redis_client.incr_with_expiry(key, expiry=self.udp_ddos_window)
            if count is not None and count >= self.udp_ddos_threshold:
                action_details = {
                    "action": "block_ip",
                    "target": src_ip,
                    "reason": f"Possível DDoS UDP detectado: {count} pacotes UDP (não-DNS) em {self.udp_ddos_window}s"
                }

        # Log se uma ação for determinada pelo tracking
        if action_details:
             logger.warning(f"Tracking detectou: IP {src_ip} | Razão: {action_details['reason']}")
             return action_details

        return None # Nenhum limite de tracking atingido

    def _decide_action(self, data: Dict[str, any], anomaly_score: Optional[float]) -> Dict[str, Optional[str]]:
        """
        Decide a ação a ser tomada com base nas regras de tracking e/ou score do ML.
        Prioriza o bloqueio por tracking. Usa ML para gerar alertas adicionais.
        Retorna: {"action": "block_ip" | "alert_anomaly" | "none", "target": ip | None, "reason": str | None}
        """
        src_ip = data.get('src_ip')
        dst_ip = data.get('dst_ip') # Adicionado para logs/alertas
        dst_port = data.get('dst_port', 0)
        protocol_num = data.get('protocol', 0)
        protocol = PROTOCOL_MAP.get(protocol_num, "unknown").lower()

        # === Passo 1: Verificar regras de tracking (baseadas em contagem) ===
        # Estas regras têm prioridade para bloqueio imediato se atingidas.
        tracking_action = self._track_attempts(src_ip, dst_ip, dst_port, protocol, data)
        if tracking_action:
            # Se o tracking detectou algo (SSH, DNS, ICMP, UDP Flood), retorna essa ação.
            return tracking_action # Já contém action, target, reason

        # === Passo 2: Avaliar score do ML (se o modelo estiver carregado) ===
        # Se o tracking não disparou, verifica o ML.
        # Usamos o ML para gerar um ALERTA, não necessariamente um bloqueio imediato,
        # para reduzir falsos positivos causados apenas pelo ML.
        if self.model is not None and anomaly_score is not None:
             if anomaly_score < self.ml_anomaly_threshold:
                 # O score do ML indica uma anomalia, mas não bloqueamos automaticamente.
                 # Geramos um alerta para análise.
                 reason = (f"Anomalia detectada por ML (Score: {anomaly_score:.4f} < {self.ml_anomaly_threshold}). "
                           f"Protocolo: {protocol}, Porta Dest: {dst_port}")
                 logger.info(f"Alerta ML: {src_ip} -> {dst_ip} | Razão: {reason}")
                 return {
                     "action": "alert_anomaly", # Ação específica para alerta ML
                     "target": src_ip, # Pode ser útil no alerta
                     "reason": reason
                 }

        # === Passo 3: Nenhuma ação necessária ===
        # Se nem o tracking nem o ML (acima do threshold) indicaram problema.
        return {"action": "none", "target": None, "reason": "Tráfego considerado normal"}

    def process_message(self, ch, method, properties, body):
        """Processa mensagens recebidas da fila pacotes."""
        try:
            data = json.loads(body.decode('utf-8'))
            src_ip = data.get('src_ip', 'N/A')
            dst_ip = data.get('dst_ip', 'N/A')
            protocol_num = data.get('protocol', 0)
            protocol = PROTOCOL_MAP.get(protocol_num, "unknown").lower()

            # Log específico para ICMP para ajudar na depuração
            if protocol == 'icmp':
                logger.debug(f"Processando pacote ICMP: {src_ip} -> {dst_ip}")

            features_df = self._prepare_features(data)
            anomaly_score = None
            if self.model is not None and features_df is not None:
                try:
                    # Use predict para obter -1 (anomalia) ou 1 (normal) se preferir
                    # prediction = self.model.predict(features_df)[0] # -1 for outliers, 1 for inliers
                    # Ou continue usando score_samples para ter o score bruto
                    anomaly_score = self.model.score_samples(features_df)[0]
                except Exception as e:
                    logger.error(f"Erro ao calcular score ML para {src_ip}->{dst_ip}: {e}")
                    # Continuar sem score se o cálculo falhar

            action_info = self._decide_action(data, anomaly_score)
            action_type = action_info.get("action", "none")

            if action_type == "block_ip":
                logger.warning(f"BLOQUEIO: {src_ip} | Razão: {action_info.get('reason')} | Score ML: {anomaly_score if anomaly_score else 'N/A'}")
                self._handle_action(data, action_info, anomaly_score) # Lida com bloqueio e alerta
            elif action_type == "alert_anomaly":
                logger.info(f"ALERTA ML: {src_ip} -> {dst_ip} | Razão: {action_info.get('reason')}")
                # Apenas envia alerta, sem bloquear
                self._send_alert(data, action_info, anomaly_score)
            else:
                # Tráfego normal, log apenas em DEBUG
                logger.debug(f"Tráfego normal: {src_ip} -> {dst_ip} | Score ML: {anomaly_score if anomaly_score else 'N/A'}")

            # Confirma o recebimento da mensagem ao RabbitMQ
            ch.basic_ack(delivery_tag=method.delivery_tag)
            # logger.debug(f"Mensagem confirmada (acked): delivery_tag={method.delivery_tag}")

        except json.JSONDecodeError as e:
            logger.error(f"Erro ao decodificar mensagem JSON: {e}. Body: {body[:200]}...") # Logar parte do body ajuda
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Não re-enfileirar msg mal formada
        except Exception as e:
            logger.exception(f"Erro inesperado ao processar mensagem (delivery_tag={method.delivery_tag}): {e}") # Usar logger.exception para incluir traceback
            # Rejeitar a mensagem, mas talvez re-enfileirar dependendo do erro?
            # Por segurança, não vamos re-enfileirar para evitar loops de erro.
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            # logger.debug(f"Mensagem rejeitada (nacked): delivery_tag={method.delivery_tag}")

    def _handle_action(self, data: Dict[str, any], action_info: Dict[str, str], anomaly_score: Optional[float]):
        """Executa ações (atualmente só bloqueio) E envia alerta."""
        action_type = action_info.get("action")
        target = action_info.get("target")
        reason = action_info.get("reason")

        if action_type == "block_ip" and target:
            try:
                # Usar o TTL definido na configuração via RedisClient
                self.redis_client.add_block(target) # TTL já configurado no cliente
                logger.info(f"IP {target} bloqueado via Redis. Razão: {reason}")
            except Exception as e:
                logger.error(f"Falha ao bloquear IP {target} no Redis: {e}")
        # Adicionar outras ações aqui se necessário (ex: block_port)

        # Sempre enviar um alerta quando uma ação de bloqueio é tomada
        self._send_alert(data, action_info, anomaly_score)

    def _send_alert(self, data: Dict[str, any], action_info: Dict[str, str], anomaly_score: Optional[float]):
        """Constrói e envia um alerta para a fila RabbitMQ."""
        alert = {
            'timestamp_utc': datetime.now(timezone.utc).isoformat(timespec='seconds') + 'Z', # Formato comum
            'alert_type': action_info.get("action", "unknown_action"), # 'block_ip' ou 'alert_anomaly'
            'source_ip': data.get('src_ip'),
            'destination_ip': data.get('dst_ip'),
            'destination_port': data.get('dst_port'),
            'protocol': PROTOCOL_MAP.get(data.get('protocol', 0), "unknown"),
            'anomaly_score': f"{anomaly_score:.4f}" if anomaly_score is not None else None, # Formata score se existir
            'action_taken': action_info.get("action"), # O que o MLService decidiu
            'target': action_info.get("target"), # IP alvo (ou outro, se aplicável)
            'reason': action_info.get("reason"), # Motivo da decisão
            'raw_packet_sample': data.get('raw_packet_sample', None) # Opcional: incluir amostra se Data_Processing enviar
        }
        try:
            if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
                self.rabbitmq_channel.basic_publish(
                    exchange='',
                    routing_key=self.rabbitmq_alert_queue,
                    body=json.dumps(alert, ensure_ascii=False), # ensure_ascii=False se tiver caracteres não-ASCII
                    properties=pika.BasicProperties(
                        delivery_mode=2, # Make message persistent
                        content_type='application/json'
                        )
                )
                logger.info(f"Alerta tipo '{alert['alert_type']}' enviado para {self.rabbitmq_alert_queue} sobre IP {alert['source_ip']}")
            else:
                 logger.error("Não foi possível enviar alerta: Canal RabbitMQ não está aberto.")

        except pika.exceptions.AMQPChannelError as ce:
             logger.error(f"Erro de canal ao enviar alerta: {ce}. Tentando reconectar ou aguardar.")
             # Aqui pode ser necessário implementar lógica de reconexão ou buffer de alertas
        except Exception as e:
            logger.error(f"Erro desconhecido ao enviar alerta para {self.rabbitmq_alert_queue}: {e}")


    def start(self):
        """Inicia o consumo de mensagens."""
        if not self._connect_to_rabbitmq():
            logger.critical("Falha na inicialização do RabbitMQ. Encerrando...")
            return

        # Tentar configurar QoS para evitar sobrecarga do consumidor
        try:
            self.rabbitmq_channel.basic_qos(prefetch_count=10) # Processar no máximo 10 msgs por vez antes de ack
            logger.info("QoS (prefetch_count=10) configurado para o canal.")
        except Exception as e:
            logger.warning(f"Não foi possível configurar QoS: {e}")


        self.consumer_tag = self.rabbitmq_channel.basic_consume(
            queue=self.rabbitmq_packet_queue,
            on_message_callback=self.process_message,
            auto_ack=False # Manual acknowledgement é essencial (já estava assim)
        )
        logger.info(f"Consumidor iniciado na fila '{self.rabbitmq_packet_queue}' com consumer_tag: {self.consumer_tag}")

        # last_message_time = time.time() # Removido, pois o loop principal já verifica
        # timeout = 300  # 5 minutos sem mensagens (Removido, lógica similar abaixo)
        error_backoff = 0  # Controle de backoff para erros de CONSUMO (não de processamento de msg)
        max_backoff = 60  # Máximo de 60 segundos de espera
        consecutive_connection_errors = 0 # Contador para erros de conexão

        while self.running:
            try:
                # Verifica conexão antes de processar eventos
                if not self.rabbitmq_connection or self.rabbitmq_connection.is_closed:
                    logger.warning("Conexão RabbitMQ perdida. Tentando reconectar...")
                    consecutive_connection_errors += 1
                    if consecutive_connection_errors > 3: # Limite de tentativas rápidas
                         wait_before_reconnect = min(10 * consecutive_connection_errors, 120) # Espera mais longa
                         logger.warning(f"Muitos erros de conexão, aguardando {wait_before_reconnect}s...")
                         time.sleep(wait_before_reconnect)

                    if not self._connect_to_rabbitmq():
                        logger.error("Falha ao reconectar. Aguardando antes de nova tentativa.")
                        # Espera um tempo fixo ou aumenta o backoff aqui também antes de `continue`
                        time.sleep(max_backoff) # Espera o máximo antes de tentar o loop de novo
                        continue # Volta ao início do while para tentar reconectar
                    else:
                         # Reconectado com sucesso, resetar contagem de erros e registrar consumidor de novo
                         consecutive_connection_errors = 0
                         self.consumer_tag = self.rabbitmq_channel.basic_consume(
                             queue=self.rabbitmq_packet_queue,
                             on_message_callback=self.process_message,
                             auto_ack=False
                         )
                         logger.info(f"Reconectado e consumidor registrado novamente: {self.consumer_tag}")

                # Processa eventos de I/O por 1 segundo. Se houver mensagens, o callback process_message será chamado.
                self.rabbitmq_connection.process_data_events(time_limit=1.0)

                # Resetar backoff de erro de CONSUMO se chegamos aqui sem exceção no try
                if error_backoff > 0:
                    logger.info("Ciclo de consumo bem-sucedido, resetando backoff de erro.")
                    error_backoff = 0
                # Resetar contador de erros de conexão também
                consecutive_connection_errors = 0

                # Log de status da fila (opcional, pode ser verboso)
                # try:
                #     queue_info = self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_packet_queue, passive=True)
                #     message_count = queue_info.method.message_count
                #     # Obter unacked pode ser complexo/impreciso dependendo do cliente/estado
                #     logger.debug(f"Fila '{self.rabbitmq_packet_queue}' status: Prontas={message_count}")
                # except Exception as qe:
                #     logger.warning(f"Não foi possível obter status da fila: {qe}")


            # --- Tratamento de Erros Específicos ---
            except pika.exceptions.StreamLostError as sle:
                 logger.error(f"Stream de conexão perdida com RabbitMQ: {sle}. Tentando reconectar...")
                 consecutive_connection_errors += 1
                 # Forçar fechamento da conexão antiga se ainda existir objeto
                 if self.rabbitmq_connection and not self.rabbitmq_connection.is_closed:
                     try: self.rabbitmq_connection.close()
                     except: pass
                 self.rabbitmq_connection = None # Garantir que a reconexão seja tentada
                 time.sleep(5) # Pequena pausa antes de tentar o loop de novo

            except pika.exceptions.ConnectionClosedByBroker:
                 logger.error("Conexão fechada pelo Broker RabbitMQ. Verifique logs do Broker. Tentando reconectar...")
                 consecutive_connection_errors += 1
                 self.rabbitmq_connection = None
                 time.sleep(10)

            except pika.exceptions.AMQPConnectionError as ace:
                 logger.error(f"Erro geral de conexão AMQP: {ace}. Tentando reconectar...")
                 consecutive_connection_errors += 1
                 self.rabbitmq_connection = None
                 time.sleep(10)

            # --- Tratamento Genérico (Deve vir depois dos específicos) ---
            except Exception as e:
                # Erro durante o process_data_events ou outra operação no loop principal
                logger.exception(f"Erro inesperado no loop principal de consumo: {e}") # logger.exception inclui traceback
                error_backoff = min(error_backoff + 5, max_backoff)  # Aumenta backoff para erros GERAIS do loop
                logger.info(f"Aguardando {error_backoff}s antes da próxima tentativa devido a erro no loop.")
                time.sleep(error_backoff)
                # Não reseta consecutive_connection_errors aqui, pois pode não ser erro de conexão
                continue # Tenta a próxima iteração do loop

            # Pequena pausa para não consumir 100% CPU se a fila estiver vazia
            # time.sleep(0.1) # Ajuste conforme necessário

    def stop(self, signum=None, frame=None):
        """Para o serviço de forma segura."""
        if not self.running: # Evitar múltiplas chamadas
             return
        logger.info(f"Parando MLService (recebido sinal {signum})...")
        self.running = False # Sinaliza para o loop while terminar

        # Cancela o consumidor primeiro
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open and self.consumer_tag:
            try:
                logger.info(f"Cancelando consumidor {self.consumer_tag}...")
                self.rabbitmq_channel.basic_cancel(self.consumer_tag)
            except pika.exceptions.ChannelClosed:
                 logger.warning("Canal já estava fechado ao tentar cancelar consumidor.")
            except Exception as e:
                logger.error(f"Erro ao cancelar consumidor RabbitMQ: {e}")

        # Fecha o canal
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
             try:
                 logger.info("Fechando canal RabbitMQ...")
                 self.rabbitmq_channel.close()
             except Exception as e:
                  logger.error(f"Erro ao fechar canal RabbitMQ: {e}")


        # Fecha a conexão
        if self.rabbitmq_connection and not self.rabbitmq_connection.is_closed:
            try:
                logger.info("Fechando conexão RabbitMQ...")
                self.rabbitmq_connection.close()
            except Exception as e:
                logger.error(f"Erro ao fechar conexão RabbitMQ: {e}")

        # Fecha conexão Redis
        if self.redis_client:
            try:
                self.redis_client.close()
                logger.info("Conexão Redis fechada.")
            except Exception as e:
                logger.error(f"Erro ao fechar conexão Redis: {e}")

        logger.info("MLService parado.")

    def run(self):
        """Executa o serviço com tratamento de sinais."""
        # Registrar handlers de sinal ANTES de iniciar o loop principal
        signal.signal(signal.SIGINT, self.stop)  # Ctrl+C
        signal.signal(signal.SIGTERM, self.stop) # kill/systemd stop
        logger.info("Handlers de sinal SIGINT e SIGTERM registrados.")

        try:
            self.start() # Inicia o loop de consumo
        except Exception as e:
             logger.critical(f"Erro fatal não capturado durante a execução: {e}", exc_info=True)
             self.stop() # Tenta parar graciosamente mesmo em erro fatal
             exit(1)
        finally:
             logger.info("Processo MLService encerrado.")


if __name__ == "__main__":
    service = MLService()
    service.run()