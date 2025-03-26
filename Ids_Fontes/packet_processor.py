import scapy.all as scapy
import threading
import logging
import time
from typing import Callable, Optional, Dict, Any
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

logger = logging.getLogger(__name__)

class PacketCapturer:
    """Classe para captura de pacotes de rede."""

    def __init__(self, interface: str, packet_handler: Callable, filter_rules: str = "ip or ip6"):
        self.interface = interface
        self.packet_handler = packet_handler
        self.filter_rules = filter_rules
        self.running = False
        self.running_lock = threading.Lock()  # Adicionado lock
        self.capture_thread = None
    
    def start(self) -> None:
        """Inicia a captura em thread separada."""
        with self.running_lock:
            if self.running:
                logger.warning("Captura já está em execução")
                return

        # Valida se a interface existe
        if not scapy.get_if_list() or self.interface not in scapy.get_if_list():
            logger.error(f"Interface inválida ou não encontrada: {self.interface}")
            return

        self.running = True
        try:
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                name=f"PacketCapturer-{self.interface}",
                daemon=True
            )
            self.capture_thread.start()
            logger.info(f"Captura iniciada na interface {self.interface} com filtro: {self.filter_rules}")
        except Exception as e:
            logger.error(f"Falha ao iniciar captura: {e}")
            self.running = False

    def _capture_loop(self) -> None:
        """Loop principal de captura."""
        logger.debug("Entrando no _capture_loop")
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self.running,
                filter=self.filter_rules,
                timeout=60  # Timeout de 60 segundos
            )
        except scapy.Scapy_Exception as e:
            logger.error(f"Erro do Scapy: {e}")
        except PermissionError:
            logger.error("Permissão insuficiente. Execute com sudo.")
        except Exception as e:
            logger.error(f"Erro na captura: {e}")
        finally:
            self.running = False
            logger.info("Captura encerrada")

    def _handle_packet(self, packet: scapy.packet.Packet) -> None:
        """Processa cada pacote capturado."""
        try:
            if UDP in packet:
                logger.debug(f"Pacote UDP capturado: {packet.summary()} | Origem: {packet[IP].src} -> Destino: {packet[IP].dst}")
            elif TCP in packet:
                logger.debug(f"Pacote TCP capturado: {packet.summary()} | Origem: {packet[IP].src} -> Destino: {packet[IP].dst}")
            elif ICMP in packet:
                logger.debug(f"Pacote ICMP capturado: {packet.summary()} | Origem: {packet[IP].src} -> Destino: {packet[IP].dst}")
            elif IPv6 in packet:
                logger.debug(f"Pacote IPv6 capturado: {packet.summary()} | Origem: {packet[IPv6].src} -> Destino: {packet[IPv6].dst}")
            else:
                logger.debug(f"Pacote IP capturado: {packet.summary()}")
            self.packet_handler(packet)
        except Exception as e:
            logger.error(f"Erro no processamento do pacote: {e}", exc_info=True)


    def stop(self) -> None:
        """Para a captura."""
        if self.running:
            self.running = False
            if self.capture_thread:
                self.capture_thread.join(timeout=5)
                if self.capture_thread.is_alive():
                    logger.warning("A thread de captura não foi encerrada dentro do tempo limite")
                else:
                    logger.info("Captura finalizada com sucesso")

    def is_alive(self) -> bool:
        """Verifica se a thread de captura está ativa."""
        return self.capture_thread.is_alive() if self.capture_thread else False