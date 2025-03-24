import logging
import time
import threading
import signal
import socket
from config import ConfigManager  # Ainda usando para obter configurações
from packet_processor import PacketCapturer
from data_processing import PacketNormalizer

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

HOST = 'localhost'
PORT = 65432

class IDSController:
    def __init__(self):
        self.config = ConfigManager()
        self.capturer = None
        self.running = True
        self.service_status = 'stopped' # Status local do serviço IDS
        self.buffer = []# Inicializa o buffer
        self.buffer_lock = threading.Lock()  # Inicializa o lock do buffer
        logger.info("IDS: Sistema IDS inicializado")

    def start(self):
        logger.info("IDS: Iniciando serviço IDS...")
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            logger.info(f"IDS: ids.service ouvindo em {HOST}:{PORT}")
            while self.running:
                conn, addr = s.accept()
                threading.Thread(target=self._handle_connection, args=(conn, addr)).start()

    def _handle_connection(self, conn, addr):
            with conn:
                logger.info(f"IDS: Conexão estabelecida com {addr}")
                command = conn.recv(1024).decode().lower()
                logger.info(f"IDS: Comando recebido: {command}")

                if command == 'iniciar':  # Alterado para 'iniciar'
                    self._start_capture()
                    self.service_status = 'running'
                    logger.info("IDS: Serviço iniciado.")
                elif command == 'parar':  # Alterado para 'parar'
                    self._stop_capture()
                    self.service_status = 'stopped'
                    logger.info("IDS: Serviço parado.")
                elif command == 'status':
                    conn.sendall(self.service_status.encode())
                    logger.info(f"IDS: Status reportado: {self.service_status}")
                else:
                    logger.warning(f"IDS: Comando desconhecido: {command}")

    def _start_capture(self):
        if not self._is_capturer_active():
            settings = self.config.get_capture_settings()
            self.capturer = PacketCapturer(
                interface=settings['interface'],
                packet_handler=self._process_packet
            )
            self.capturer.start()
            logger.info(f"IDS: Captura iniciada na interface {settings['interface']}")

    def _stop_capture(self):
        if self._is_capturer_active():
            self.capturer.stop()
            logger.info("IDS: Captura interrompida")

    def _process_packet(self, packet):
            """Processa cada pacote capturado"""
            try:
                normalized = PacketNormalizer.normalize(packet)
                if normalized:
                    # Log dos dados capturados e processados (agora um dicionário)
                    logger.info(f"IDS: Pacote capturado e processado: {normalized}")
                    with self.buffer_lock:
                        self.buffer.append(normalized)
                        # self._check_ml_flush()
            except Exception as e:
                logger.error(f"Erro no processamento: {str(e)}")

    def _is_capturer_active(self) -> bool:
        return self.capturer is not None and self.capturer.is_alive()

    def _signal_handler(self, signum, frame):
        logger.info(f"IDS: Recebido sinal {signum}, encerrando...")
        self.running = False
        self._stop_capture()

if __name__ == "__main__":
    ids = IDSController()
    ids.start()