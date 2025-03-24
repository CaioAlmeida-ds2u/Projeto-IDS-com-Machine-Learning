import logging
import time
import threading
import signal
import socket
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from config import ConfigManager
from packet_processor import PacketCapturer
from data_processing import PacketNormalizer
import json
import pika  # Importa pika


logger = logging.getLogger(__name__)

class IDSController:
    def __init__(self):
        self.config = ConfigManager()
        self.capturer = None
        self.running = True
        self.service_status = 'stopped'
        self.buffer = []
        self.buffer_lock = threading.Lock()
        self._load_configuration()
        logging.basicConfig(level=self.log_level)

        # Configurações do RabbitMQ
        self.rabbitmq_host = 'localhost'  # Altere se o RabbitMQ estiver em outra máquina
        self.rabbitmq_port = 5672         # Porta padrão do RabbitMQ
        self.rabbitmq_queue = 'pacotes'   # Nome da fila
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None

    def _load_configuration(self):
        """Carrega configurações de rede."""
        config_data = self.config.get_config()
        self.host = config_data['settings'].get('service_host', 'localhost')
        self.port = int(config_data['settings'].get('service_port', 65432))
        self.interface = config_data['settings'].get('interface', 'enp0s3')
        self.filter_rules = config_data['settings'].get('filter', 'ip')
        self.log_level = logging.INFO  # Valor padrão

        log_level_str = config_data['settings'].get('log_level', 'INFO').upper()
        self.log_level = getattr(logging, log_level_str, logging.INFO)

    def _connect_to_rabbitmq(self):
        """Estabelece conexão com o RabbitMQ."""
        try:
            self.rabbitmq_connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=self.rabbitmq_host, port=self.rabbitmq_port)
            )
            self.rabbitmq_channel = self.rabbitmq_connection.channel()
            self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_queue, durable=True)  # Fila durável
            logger.info(f"Conectado ao RabbitMQ em {self.rabbitmq_host}:{self.rabbitmq_port}, fila: {self.rabbitmq_queue}")
        except Exception as e:
            logger.error(f"Erro ao conectar ao RabbitMQ: {e}", exc_info=True)
            # Trate o erro aqui (por exemplo, tente reconectar, ou pare o serviço)

    def _close_rabbitmq_connection(self):
        """Fecha a conexão com o RabbitMQ."""
        try:
            if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
                self.rabbitmq_channel.close()
            if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
                self.rabbitmq_connection.close()
            logger.info("Conexão com o RabbitMQ fechada.")
        except Exception as e:
            logger.error(f"Erro ao fechar a conexão com o RabbitMQ: {e}", exc_info=True)


    def start(self):
        """Inicia o serviço principal."""
        logger.info("Iniciando IDS...")
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Conecta ao RabbitMQ ao iniciar
        self._connect_to_rabbitmq()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(5)
                logger.info(f"Serviço ouvindo em {self.host}:{self.port}")

                while self.running:
                    conn, addr = s.accept()
                    threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True
                    ).start()
        except Exception as e:
            logger.error(f"Erro no servidor: {e}")
            self.stop()

    def _handle_connection(self, conn, addr):
        """Processa conexões de controle."""
        with conn:
            try:
                data = conn.recv(1024).decode().strip().lower()
                logger.info(f"Comando recebido: {data}")

                if data == 'start' or data == 'iniciar':
                    self._start_capture()
                    conn.sendall(b"Capture started")
                elif data == 'stop' or data == 'parar':
                    self._stop_capture()
                    conn.sendall(b"Capture stopped")
                elif data == 'status':
                    conn.sendall(self.service_status.encode())
                elif data == 'get_config':
                    config_data = self.config.get_config()
                    config_data['settings']['interface'] = self.interface
                    config_data['settings']['filter'] = self.filter_rules
                    conn.sendall(json.dumps(config_data).encode())

                else:
                    conn.sendall(b"Invalid command")
            except Exception as e:
                logger.error(f"Erro na conexão: {e}")

    def _start_capture(self):
        """Inicia a captura de pacotes."""
        if not self.capturer or not self.capturer.is_alive():
            logger.info(f"Iniciando captura na interface: {self.interface} com filtro: {self.filter_rules}")
            self.capturer = PacketCapturer(
                interface=self.interface,
                packet_handler=self._process_packet,
                filter_rules=self.filter_rules
            )
            self.capturer.start()
            self.service_status = 'running'
            logger.info("Captura iniciada")

    def _stop_capture(self):
        """Para a captura de pacotes."""
        if self.capturer and self.capturer.is_alive():
            self.capturer.stop()
            self.service_status = 'stopped'
            logger.info("Captura encerrada")

    def _process_packet(self, packet):
        """Processa cada pacote capturado e envia para o RabbitMQ."""
        try:
            processed = PacketNormalizer.normalize(packet)
            if processed:
                with self.buffer_lock:  # Ainda mantém o buffer local (opcional)
                    self.buffer.append(processed)

                # Envia para o RabbitMQ
                try:
                    message = json.dumps(processed)  # Converte o dicionário para JSON
                    self.rabbitmq_channel.basic_publish(
                        exchange='',
                        routing_key=self.rabbitmq_queue,
                        body=message,
                        properties=pika.BasicProperties(
                            delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE  # Mensagens persistentes
                        ))
                    logger.debug(f"Mensagem publicada no RabbitMQ: {message[:100]}...") # Log (truncado)
                except Exception as e:
                    logger.error(f"Erro ao publicar no RabbitMQ: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Erro no processamento: {e}")


    def _log_packet(self, packet_info):  # Opcional: Mantenha se quiser logs detalhados
        """Registra informações do pacote (Opcional)."""
        logger.info("***** Pacote Capturado *****")

        if 'src_mac' in packet_info:
            logger.info("[L2] Ethernet:")
            logger.info(f"  Origem: {packet_info['src_mac']}")
            logger.info(f"  Destino: {packet_info['dst_mac']}")

        if 'src_ip' in packet_info:
            logger.info("[L3] IP:")
            logger.info(f"  Versão: {packet_info.get('ip_version', 'N/A')}")
            logger.info(f"  Origem: {packet_info['src_ip']}")
            logger.info(f"  Destino: {packet_info['dst_ip']}")

        if 'protocol' in packet_info:
            protocol = packet_info['protocol']
            logger.info(f"[L4] {protocol}:")
            logger.info(f"  Porta Origem: {packet_info.get('src_port', 'N/A')}")
            logger.info(f"  Porta Destino: {packet_info.get('dst_port', 'N/A')}")

        logger.info("***** Fim do Pacote *****\n")


    def _signal_handler(self, signum, frame):
        """Manipula sinais de desligamento."""
        logger.info(f"Recebido sinal {signum}, encerrando...")
        self.stop()

    def stop(self):
        """Para todos os componentes."""
        self.running = False
        self._stop_capture()
        self._close_rabbitmq_connection() # Fecha a conexão com RabbitMQ
        logger.info("Serviço encerrado")

if __name__ == "__main__":
    ids = IDSController()
    ids.start()