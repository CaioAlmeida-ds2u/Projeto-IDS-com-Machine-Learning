# /home/admin/ids_project/ml_service.py

import logging
import json
import signal
import pika
import joblib
import os
import time
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

try:
    from config import ConfigManager
    from redis_client import RedisClient
except ImportError as e:
    print(f"ERRO: Falha ao importar módulos locais: {e}")
    exit(1)

logger = logging.getLogger("MLService")

class HealthMonitor:
    """Monitora a saúde das dependências em uma thread separada."""
    def __init__(self, service: 'MLService'):
        self.service = service
        self.running = True
        self.thread = threading.Thread(target=self._monitor, name="MLHealthMonitor", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.running = False
        self.thread.join(timeout=5)

    def _monitor(self):
        while self.running:
            try:
                if not self.service.redis_client.get_connection():
                    logger.warning("Redis desconectado no MLService. Tentando reconectar...")
                if not self.service.rabbitmq_channel or not self.service.rabbitmq_channel.is_open:
                    logger.warning("RabbitMQ desconectado no MLService. Tentando reconectar...")
                    self.service._connect_to_rabbitmq(is_reconnect=True)
                time.sleep(10)
            except Exception as e:
                logger.error(f"Erro no monitoramento de saúde do MLService: {e}")
                time.sleep(10)

class MLService:
    """Serviço de Machine Learning para detecção de anomalias."""
    def __init__(self):
        logger.info("Inicializando MLService...")
        self.config_manager: Optional[ConfigManager] = None
        self.redis_client: Optional[RedisClient] = None
        self.model = None
        self.rabbitmq_connection: Optional[pika.BlockingConnection] = None
        self.rabbitmq_channel: Optional[pika.channel.Channel] = None
        self.health_monitor: Optional[HealthMonitor] = None
        self.running = True
        self.message_queue = Queue(maxsize=1000)
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.lock = threading.Lock()

        self.log_level = logging.INFO
        self.rabbitmq_host: Optional[str] = None
        self.rabbitmq_port: Optional[int] = None
        self.rabbitmq_packet_queue: Optional[str] = None
        self.rabbitmq_alert_queue: Optional[str] = None
        self.model_path: Optional[str] = None
        self.anomaly_threshold: Optional[float] = None
        self.feature_order: Optional[List[str]] = None

        try:
            self.config_manager = ConfigManager()
            self._load_configuration()
            self._configure_logging()
            self._initialize_redis_client()
            logger.info("MLService inicializado.")
        except Exception as e:
            logger.critical(f"Falha na inicialização: {e}", exc_info=True)
            self.running = False
            self._cleanup()
            raise RuntimeError("Falha na inicialização") from e

    def _load_configuration(self):
        """Carrega configurações do ConfigManager."""
        settings = self.config_manager.get_config().get('settings', {})
        self.log_level = getattr(logging, settings.get('log_level', 'INFO').upper(), logging.INFO)

        rabbitmq_config = self.config_manager.get_rabbitmq_config()
        self.rabbitmq_host = rabbitmq_config.get('host', 'localhost')
        self.rabbitmq_port = int(rabbitmq_config.get('port', 5672))
        self.rabbitmq_packet_queue = rabbitmq_config.get('packet_queue', 'ids_packet_analysis_queue')
        self.rabbitmq_alert_queue = rabbitmq_config.get('alert_queue', 'ids_alert_queue')

        ml_config = self.config_manager.get_ml_service_config()
        self.model_path = ml_config.get('model_path')
        self.anomaly_threshold = float(ml_config.get('anomaly_threshold', 0.5))
        self.feature_order = ml_config.get('feature_order', [
            'payload_size', 'src_port', 'dst_port', 'ttl', 'udp_length', 'is_tcp', 'is_udp', 'is_icmp',
            'flag_syn', 'flag_ack', 'flag_fin', 'flag_rst', 'flag_psh', 'flag_urg', 'flag_ece', 'flag_cwr',
            'port_src_well_known', 'port_dst_well_known', 'port_dst_is_dns', 'port_dst_is_ntp',
            'port_dst_is_http', 'port_dst_is_https', 'same_network', 'is_private'
        ])
        if not self.model_path:
            raise ValueError("model_path não configurado.")
        logger.info(f"Config: Model={self.model_path}, Threshold={self.anomaly_threshold}")

    def _configure_logging(self):
        """Configura o logging."""
        logging.basicConfig(level=self.log_level, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
        logger.info(f"Logging configurado: {logging.getLevelName(self.log_level)}")

    def _initialize_redis_client(self):
        """Inicializa o cliente Redis."""
        redis_config = self.config_manager.get_redis_config()
        self.redis_client = RedisClient(
            host=redis_config.get('host', 'localhost'),
            port=int(redis_config.get('port', 6379)),
            db=int(redis_config.get('db', 0)),
            password=redis_config.get('password'),
            block_list_key=redis_config.get('block_list_key', 'ids:blocked_ips'),
            block_ttl_seconds=int(redis_config.get('block_ttl_seconds', 3600))
        )
        if not self.redis_client.get_connection():
            raise ConnectionError("Falha ao conectar ao Redis.")

    def load_model(self):
        """Carrega o modelo ML."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Modelo não encontrado: {self.model_path}")
        self.model = joblib.load(self.model_path)
        logger.info(f"Modelo carregado: {self.model_path}")

    def _connect_to_rabbitmq(self, is_reconnect=False) -> bool:
        """Conecta ao RabbitMQ."""
        with self.lock:
            if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
                return True
            self._close_rabbitmq_connection()
            try:
                params = pika.ConnectionParameters(host=self.rabbitmq_host, port=self.rabbitmq_port, heartbeat=600)
                self.rabbitmq_connection = pika.BlockingConnection(params)
                self.rabbitmq_channel = self.rabbitmq_connection.channel()
                self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_packet_queue, durable=True)
                self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_alert_queue, durable=True)
                logger.info(f"Conectado ao RabbitMQ: {self.rabbitmq_packet_queue}, {self.rabbitmq_alert_queue}")
                return True
            except Exception as e:
                logger.error(f"Falha ao conectar ao RabbitMQ: {e}")
                return False

    def _close_rabbitmq_connection(self):
        """Fecha a conexão RabbitMQ."""
        with self.lock:
            if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
                self.rabbitmq_channel.close()
            if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
                self.rabbitmq_connection.close()
            self.rabbitmq_channel = None
            self.rabbitmq_connection = None
            logger.info("Conexão RabbitMQ fechada.")

    def validate_data(self, data: Dict[str, Any]):
        """Valida os dados recebidos."""
        required = set(self.feature_order)
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Features faltando: {missing}")

    def prepare_features(self, data: Dict[str, Any]) -> List[float]:
        """Prepara as features para o modelo."""
        return [float(data.get(f, 0)) for f in self.feature_order]

    def process_message(self, ch, method, properties, body):
        """Processa mensagens do RabbitMQ."""
        if not self.running:
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            return
        self.message_queue.put((ch, method, properties, body))
        self.executor.submit(self._process_message_worker, ch, method, properties, body)

    def _process_message_worker(self, ch, method, properties, body):
        """Worker para processar mensagens em paralelo."""
        try:
            data = json.loads(body.decode('utf-8'))
            self.validate_data(data)
            features = self.prepare_features(data)
            prediction = self.model.predict([features])[0]
            score = self.model.decision_function([features])[0]

            if score < self.anomaly_threshold:
                logger.warning(f"Anomalia detectada: {data['src_ip']} -> {data['dst_ip']}, Score={score}")
                self.handle_anomaly(data, score, prediction)
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as e:
            logger.error(f"Erro ao processar mensagem: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    def handle_anomaly(self, data: Dict[str, Any], score: float, prediction: Any):
        """Trata anomalias detectadas."""
        src_ip = data.get('src_ip')
        packet_rate = self.redis_client.increment_packet_count(src_ip)

        if packet_rate > 100:  # Exemplo de limite para DDoS/SSH brute force
            self.redis_client.add_block(src_ip, ttl=3600)
            logger.info(f"IP {src_ip} bloqueado por alta taxa: {packet_rate}/5s")

        alert = {
            'timestamp_utc': datetime.now(timezone.utc).isoformat() + 'Z',
            'alert_type': 'anomaly_detected',
            'source_ip': src_ip,
            'destination_ip': data.get('dst_ip'),
            'score': score,
            'prediction': str(prediction),
            'packet_rate': packet_rate
        }
        with self.lock:
            if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                self._connect_to_rabbitmq(is_reconnect=True)
            self.rabbitmq_channel.basic_publish(
                exchange='', routing_key=self.rabbitmq_alert_queue,
                body=json.dumps(alert, default=str),
                properties=pika.BasicProperties(delivery_mode=2)
            )

    def start_consuming(self):
        """Inicia o consumo de mensagens."""
        if not self._connect_to_rabbitmq():
            self.running = False
            return
        self.rabbitmq_channel.basic_qos(prefetch_count=1)
        self.rabbitmq_channel.basic_consume(queue=self.rabbitmq_packet_queue, on_message_callback=self.process_message, auto_ack=False)
        logger.info(f"Consumindo de {self.rabbitmq_packet_queue}")
        while self.running:
            try:
                self.rabbitmq_connection.process_data_events(time_limit=1.0)
            except Exception as e:
                logger.error(f"Erro no consumo: {e}")
                self._connect_to_rabbitmq(is_reconnect=True)
                time.sleep(5)

    def stop(self, signum=None, frame=None):
        """Para o serviço."""
        logger.warning(f"Parando MLService (sinal {signum})...")
        self.running = False

    def _cleanup(self):
        """Realiza a limpeza."""
        logger.info("Limpando MLService...")
        self._close_rabbitmq_connection()
        if self.redis_client:
            self.redis_client.close()
        self.executor.shutdown(wait=True)
        if self.health_monitor:
            self.health_monitor.stop()
        logger.info("MLService limpo.")

    def run(self):
        """Executa o serviço."""
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        try:
            self.load_model()
            self.health_monitor = HealthMonitor(self)
            self.health_monitor.start()
            self.start_consuming()
        except Exception as e:
            logger.critical(f"Erro no run: {e}", exc_info=True)
            self.running = False
        finally:
            self._cleanup()

if __name__ == "__main__":
    service = None
    try:
        service = MLService()
        service.run()
    except Exception as e:
        logger.critical(f"Erro fatal: {e}", exc_info=True)
        exit(1)
    finally:
        if service:
            service._cleanup()
        time.sleep(1)
        exit(0)