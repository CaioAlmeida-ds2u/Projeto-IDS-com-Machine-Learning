import logging
import time
import threading
import signal
import socket
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from config import ConfigManager  # Corrigido: Importar a classe
from packet_processor import PacketCapturer
from data_processing import PacketNormalizer
import json  # Import para lidar com a configuração


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
        logging.basicConfig(level=self.log_level)  # Configura o logging

    def _load_configuration(self):
        """Carrega configurações de rede."""
        config_data = self.config.get_config()
        self.host = config_data['settings'].get('service_host', 'localhost') # Corrigi a leitura
        self.port = int(config_data['settings'].get('service_port', 65432)) # Corrigi a leitura
        self.interface = config_data['settings'].get('interface', 'enp0s3')
        self.filter_rules = config_data['settings'].get('filter', 'ip') # Carrega o filtro
        self.log_level = logging.INFO  # Valor padrão

        log_level_str = config_data['settings'].get('log_level', 'INFO').upper()
        self.log_level = getattr(logging, log_level_str, logging.INFO)


    def start(self):
        """Inicia o serviço principal."""
        logger.info("Iniciando IDS...")
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

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

                if data == 'start':
                    self._start_capture()
                    conn.sendall(b"Capture started")
                elif data == 'stop':
                    self._stop_capture()
                    conn.sendall(b"Capture stopped")
                elif data == 'status':
                    conn.sendall(self.service_status.encode())
                elif data == 'get_config': # Comando para obter a configuração
                    config_data = self.config.get_config()
                    # Adiciona a interface e o filtro *explicitamente*
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
            logger.info(f"Iniciando captura na interface: {self.interface} com filtro: {self.filter_rules}") # Log crucial
            self.capturer = PacketCapturer(
                interface=self.interface,
                packet_handler=self._process_packet,
                filter_rules=self.filter_rules  # Usa o filtro carregado
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
        """Processa cada pacote capturado."""
        try:
            processed = PacketNormalizer.normalize(packet)  # Simplificado
            # logger.debug(f"Valor de 'processed': {processed}") # Debug, pode ser removido depois
            if processed:
                with self.buffer_lock:
                    self.buffer.append(processed)
                self._log_packet(processed)  # Log detalhado, opcional
        except Exception as e:
            logger.error(f"Erro no processamento: {e}")

    def _parse_packet(self, packet):
        """Analisa as camadas do pacote (agora usando PacketNormalizer)."""
        return PacketNormalizer.normalize(packet) # Usa o PacketNormalizer


    def _log_packet(self, packet_info):
        """Registra informações do pacote (Opcional - Para Debug)."""
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
        logger.info("Serviço encerrado")

if __name__ == "__main__":
    ids = IDSController()
    ids.start()