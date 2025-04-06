# /home/admin/ids_project/main.py

import logging
import time
import threading
import signal
import socket
import netifaces
import json
import pika
import os
from typing import Optional, Dict, Any

# Flask para API de health (opcional)
try:
    from flask import Flask, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Scapy
try:
    from scapy.packet import Packet
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    import scapy.all as scapy
except ImportError as e:
    print(f"ERRO: Falha ao importar Scapy: {e}")
    exit(1)

# Módulos locais
try:
    from config import ConfigManager
    from packet_processor import PacketCapturer  # Assumido existente
    from data_processing import PacketNormalizer
    from redis_client import RedisClient
except ImportError as e:
    print(f"ERRO: Falha ao importar módulos locais: {e}")
    exit(1)

logger = logging.getLogger(__name__)

class HealthMonitor:
    """Monitora a saúde das dependências em uma thread separada."""
    def __init__(self, controller: 'IDSController'):
        self.controller = controller
        self.running = True
        self.thread = threading.Thread(target=self._monitor, name="HealthMonitor", daemon=True)

    def start(self):
        """Inicia o monitoramento."""
        self.thread.start()

    def stop(self):
        """Para o monitoramento."""
        self.running = False
        self.thread.join(timeout=5)

    def _monitor(self):
        """Verifica periodicamente Redis e RabbitMQ."""
        while self.running:
            try:
                if not self.controller.redis_client.get_connection():
                    logger.warning("Redis desconectado. Tentando reconectar...")
                if not self.controller.rabbitmq_channel or not self.controller.rabbitmq_channel.is_open:
                    logger.warning("RabbitMQ desconectado. Tentando reconectar...")
                    self.controller._connect_to_rabbitmq(retries=1)
                time.sleep(10)  # Verifica a cada 10s
            except Exception as e:
                logger.error(f"Erro no monitoramento de saúde: {e}", exc_info=True)
                time.sleep(10)

class IDSController:
    """Controlador principal do IDS."""
    def __init__(self):
        logger.info("Inicializando IDSController...")
        self.config_manager: Optional[ConfigManager] = None
        self.capturer: Optional[PacketCapturer] = None
        self.redis_client: Optional[RedisClient] = None
        self.rabbitmq_connection: Optional[pika.BlockingConnection] = None
        self.rabbitmq_channel: Optional[pika.channel.Channel] = None
        self.health_monitor: Optional[HealthMonitor] = None

        self.running = True
        self.service_status = 'initializing'
        self.control_lock = threading.Lock()  # Para operações críticas

        # Configurações padrão
        self.host = 'localhost'
        self.port = 65432
        self.interface: Optional[str] = None
        self.filter_rules = 'ip or ip6'
        self.log_level = logging.INFO
        self.health_api_port = 5005
        self.rabbitmq_host = 'localhost'
        self.rabbitmq_port = 5672
        self.rabbitmq_packet_queue = 'ids_packet_analysis_queue'

        try:
            self.config_manager = ConfigManager()
            self._load_configuration()
            self._configure_logging()
            self._configure_rabbitmq_params()
            self._initialize_redis_client()
            self.service_status = 'stopped'
            self.config_manager.set_service_status(self.service_status)
            logger.info("IDSController inicializado.")
        except Exception as e:
            logger.critical(f"Falha na inicialização: {e}", exc_info=True)
            self.service_status = 'error'
            self.running = False
            self._cleanup()
            raise RuntimeError("Falha na inicialização") from e

    def _load_configuration(self):
        """Carrega configurações gerais."""
        config_data = self.config_manager.get_config()
        settings = config_data.get('settings', {})
        self.host = settings.get('service_host', self.host)
        self.port = int(settings.get('service_port', self.port))
        self.interface = settings.get('interface')
        self.filter_rules = settings.get('filter', self.filter_rules)
        self.log_level = getattr(logging, settings.get('log_level', 'INFO').upper(), logging.INFO)
        self.health_api_port = int(settings.get('health_api_port', self.health_api_port))

        if not self.interface:
            non_loopback = [i for i in netifaces.interfaces() if i != 'lo']
            self.interface = non_loopback[0] if non_loopback else 'lo'
            logger.info(f"Interface detectada: {self.interface}")
        elif self.interface not in netifaces.interfaces():
            raise ValueError(f"Interface {self.interface} não existe.")
        logger.info(f"Config: Interface={self.interface}, Filter={self.filter_rules}")

    def _configure_logging(self):
        """Configura o logging global."""
        logging.basicConfig(level=self.log_level, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
        logger.info(f"Logging configurado: {logging.getLevelName(self.log_level)}")

    def _configure_rabbitmq_params(self):
        """Carrega configurações do RabbitMQ."""
        rabbitmq_config = self.config_manager.get_rabbitmq_config()
        self.rabbitmq_host = rabbitmq_config.get('host', self.rabbitmq_host)
        self.rabbitmq_port = int(rabbitmq_config.get('port', self.rabbitmq_port))
        self.rabbitmq_packet_queue = rabbitmq_config.get('packet_queue', self.rabbitmq_packet_queue)
        logger.info(f"RabbitMQ: {self.rabbitmq_host}:{self.rabbitmq_port}, Queue={self.rabbitmq_packet_queue}")

    def _initialize_redis_client(self):
        """Inicializa o cliente Redis."""
        redis_config = self.config_manager.get_redis_config()
        self.redis_client = RedisClient(
            host=redis_config.get('host', 'localhost'),
            port=int(redis_config.get('port', 6379)),
            db=int(redis_config.get('db', 0)),
            password=redis_config.get('password'),
            block_list_key=redis_config.get('block_list_key', 'ids:blocked_ips')
        )
        if not self.redis_client.get_connection():
            raise ConnectionError("Falha ao conectar ao Redis.")

    def _connect_to_rabbitmq(self, retries=5, delay=5) -> bool:
        """Conecta ao RabbitMQ com retries."""
        with self.control_lock:
            if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
                return True
            self._close_rabbitmq_connection()
            for attempt in range(retries):
                try:
                    params = pika.ConnectionParameters(
                        host=self.rabbitmq_host, port=self.rabbitmq_port,
                        heartbeat=600, blocked_connection_timeout=300
                    )
                    self.rabbitmq_connection = pika.BlockingConnection(params)
                    self.rabbitmq_channel = self.rabbitmq_connection.channel()
                    self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_packet_queue, durable=True)
                    logger.info(f"Conectado ao RabbitMQ: {self.rabbitmq_packet_queue}")
                    return True
                except Exception as e:
                    logger.warning(f"Falha na conexão RabbitMQ ({attempt+1}/{retries}): {e}")
                    if attempt < retries - 1:
                        time.sleep(delay)
            logger.critical("Falha ao conectar ao RabbitMQ após retries.")
            return False

    def _close_rabbitmq_connection(self):
        """Fecha a conexão RabbitMQ."""
        with self.control_lock:
            if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
                self.rabbitmq_channel.close()
            if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
                self.rabbitmq_connection.close()
            self.rabbitmq_channel = None
            self.rabbitmq_connection = None
            logger.info("Conexão RabbitMQ fechada.")

    def _start_health_api(self):
        """Inicia API de health opcional com Flask."""
        if not FLASK_AVAILABLE:
            logger.warning("Flask não disponível. Health API não iniciada.")
            return

        app = Flask(__name__)
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

        @app.route('/health', methods=['GET'])
        def health():
            status = {
                "service_status": self.service_status,
                "capture": "running" if self.capturer and self.capturer.is_alive() else "stopped",
                "rabbitmq": "connected" if self.rabbitmq_channel and self.rabbitmq_channel.is_open else "disconnected",
                "redis": "connected" if self.redis_client and self.redis_client.get_connection() else "disconnected",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            return jsonify(status), 200 if self.running else 503

        def run_flask():
            try:
                app.run(host='0.0.0.0', port=self.health_api_port, debug=False, use_reloader=False)
            except Exception as e:
                logger.critical(f"Falha ao iniciar health API na porta {self.health_api_port}: {e}")

        threading.Thread(target=run_flask, name="HealthApi", daemon=True).start()

    def start(self):
        """Inicia o serviço IDS."""
        logger.info("Iniciando IDSController...")
        self.service_status = 'starting'
        self.config_manager.set_service_status(self.service_status)

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        if not self._connect_to_rabbitmq() or not self.redis_client.get_connection():
            self._handle_critical_error("Dependências indisponíveis")
            return

        self.control_thread = threading.Thread(target=self._start_control_server, name="ControlServer", daemon=True)
        self.control_thread.start()
        self.health_monitor = HealthMonitor(self)
        self.health_monitor.start()
        self._start_health_api()

        self.service_status = 'stopped'
        self.config_manager.set_service_status(self.service_status)
        logger.info("IDSController pronto.")

        # Aguarda sinais ou parada manual
        while self.running:
            time.sleep(1)
        logger.info("Iniciando processo de parada...")
        self._cleanup()

    def _handle_critical_error(self, reason: str):
        """Trata erros críticos."""
        logger.critical(f"Erro crítico: {reason}")
        self.service_status = 'error'
        self.config_manager.set_service_status(self.service_status)
        self.running = False

    def _start_control_server(self):
        """Inicia o servidor de controle via socket."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(5)
            server.settimeout(2.0)
            logger.info(f"Controlador ouvindo em {self.host}:{self.port}")

            while self.running:
                try:
                    conn, addr = server.accept()
                    conn.settimeout(60.0)
                    threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        name=f"Handler-{addr}",
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Erro no servidor de controle: {e}")
                        self._handle_critical_error(f"Control server error: {e}")
                    break

    def _handle_connection(self, conn: socket.socket, addr):
        """Processa comandos recebidos."""
        try:
            data = conn.recv(1024).decode('utf-8', errors='ignore').strip().lower()
            logger.info(f"Comando de {addr}: {data}")
            allowed = self.config_manager.get_config().get('service', {}).get('allowed_actions', [])
            if data not in allowed:
                conn.sendall(b"Erro: Comando nao permitido")
                return

            responses = {
                'start': self._start_capture,
                'stop': self._stop_capture,
                'status': lambda: json.dumps({
                    "service_status": self.service_status,
                    "capture": "running" if self.capturer and self.capturer.is_alive() else "stopped",
                    "rabbitmq": "connected" if self.rabbitmq_channel and self.rabbitmq_channel.is_open else "disconnected",
                    "redis": "connected" if self.redis_client.get_connection() else "disconnected"
                }, separators=(',', ':')).encode('utf-8'),
                'get_config': lambda: json.dumps({**self.config_manager.get_config(), "interface": self.interface}, indent=2).encode('utf-8'),
                'shutdown': lambda: (self.stop(), b"Shutting down...")[1]
            }
            response = responses.get(data, lambda: b"Erro: Comando desconhecido")()
            conn.sendall(response)
        except Exception as e:
            logger.error(f"Erro ao processar comando de {addr}: {e}")
            conn.sendall(b"Erro interno")
        finally:
            conn.close()

    def _start_capture(self) -> bytes:
        """Inicia a captura de pacotes."""
        with self.control_lock:
            if self.capturer and self.capturer.is_alive():
                return b'{"status": "warning", "message": "Capture already running"}'
            if not self._connect_to_rabbitmq(retries=1) or not self.redis_client.get_connection():
                self.service_status = 'error'
                self.config_manager.set_service_status(self.service_status)
                return b'{"status": "error", "message": "Dependencies unavailable"}'
            try:
                self.capturer = PacketCapturer(self.interface, self._process_packet, self.filter_rules)
                self.capturer.start()
                time.sleep(0.5)
                if self.capturer.is_alive():
                    self.service_status = 'running'
                    self.config_manager.set_service_status(self.service_status)
                    return b'{"status": "success", "message": "Capture started"}'
                return b'{"status": "error", "message": "Capture failed to start"}'
            except Exception as e:
                logger.error(f"Erro ao iniciar captura: {e}")
                self._handle_critical_error(f"Capture error: {e}")
                return b'{"status": "error", "message": "Capture failed"}'

    def _stop_capture(self) -> bytes:
        """Para a captura de pacotes."""
        with self.control_lock:
            if not self.capturer or not self.capturer.is_alive():
                self.service_status = 'stopped'
                self.config_manager.set_service_status(self.service_status)
                return b'{"status": "info", "message": "Capture not running"}'
            self.capturer.stop()
            self.capturer.capture_thread.join(timeout=3.0)
            self.capturer = None
            self.service_status = 'stopped'
            self.config_manager.set_service_status(self.service_status)
            return b'{"status": "success", "message": "Capture stopped"}'

    def _process_packet(self, packet: Packet):
        """Processa pacotes capturados."""
        if not self.running:
            return
        normalized = PacketNormalizer(redis_client=self.redis_client).normalize(packet)
        if not normalized:
            return
        src_ip = normalized.get('src_ip')
        if self.redis_client.is_blocked(src_ip):
            logger.debug(f"IP {src_ip} bloqueado. Pacote descartado.")
            return
        self._send_to_rabbitmq(normalized)

    def _send_to_rabbitmq(self, data: Dict[str, Any]):
        """Envia pacotes normalizados ao RabbitMQ."""
        with self.control_lock:
            if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                if not self._connect_to_rabbitmq(retries=1):
                    logger.error("Falha ao reconectar ao RabbitMQ. Pacote perdido.")
                    return
            try:
                self.rabbitmq_channel.basic_publish(
                    exchange='',
                    routing_key=self.rabbitmq_packet_queue,
                    body=json.dumps(data, default=str, separators=(',', ':')).encode('utf-8'),
                    properties=pika.BasicProperties(delivery_mode=2)
                )
            except Exception as e:
                logger.error(f"Erro ao enviar ao RabbitMQ: {e}")
                self._close_rabbitmq_connection()

    def _signal_handler(self, signum, frame):
        """Handler para sinais de parada."""
        logger.warning(f"Sinal {signal.Signals(signum).name} recebido. Parando...")
        self.stop()

    def stop(self):
        """Inicia a parada do serviço."""
        logger.info("Recebido comando de parada.")
        self.running = False
        self.config_manager.set_service_status('stopping')


    def _cleanup(self):
        """Realiza a limpeza final."""
        logger.info("Limpando recursos...")
        with self.control_lock:
            if self.capturer and self.capturer.is_alive():
                logger.info("Parando captura...")
                self._stop_capture()
            if self.health_monitor:
                logger.info("Parando health monitor...")
                self.health_monitor.stop()
            if self.rabbitmq_channel or self.rabbitmq_connection:
                logger.info("Fechando RabbitMQ...")
                self._close_rabbitmq_connection()
            if self.redis_client:
                logger.info("Fechando Redis...")
                self.redis_client.close()
        self.service_status = 'stopped' if self.service_status != 'error' else 'error'
        self.config_manager.set_service_status(self.service_status)
        logger.info("IDSController parado.")

if __name__ == "__main__":
    controller = None
    try:
        controller = IDSController()
        controller.start()
    except Exception as e:
        logger.critical(f"Erro fatal: {e}", exc_info=True)
        if controller:
            controller.stop()
        exit(1)
    finally:
        if controller:
            controller._cleanup()
        logger.info("Aplicação finalizada.")
        time.sleep(0.5)
        exit(0)