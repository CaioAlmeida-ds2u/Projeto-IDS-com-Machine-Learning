# packet_processor.py
import scapy.all as scapy
import threading
import logging
from typing import Callable

logger = logging.getLogger(__name__)

class PacketCapturer:
    """Classe para captura de pacotes de rede"""
    
    def __init__(self, interface: str, packet_handler: Callable):
        self.interface = interface
        self.packet_handler = packet_handler
        self.running = False
        self.capture_thread = None
        self.default_filter = "ip"

    def start(self):
        """Inicia a captura em thread separada"""
        if self.running:
            logger.warning("Captura já está em execução")
            return

        self.running = True
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            name=f"PacketCapturer-{self.interface}"
        )
        self.capture_thread.start()
        logger.info(f"Thread de captura iniciada (ID: {self.capture_thread.native_id})")

    def _capture_loop(self):
        """Loop principal de captura"""
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self.running,
                filter=self.default_filter,
                timeout=30  # Adicione timeout para evitar bloqueios
            )
        except scapy.Scapy_Exception as e:
            logger.error(f"Erro do Scapy: {e}")
        except Exception as e:
            logger.error(f"Erro geral na captura: {e}")
        finally:
            self.running = False
            logger.debug("Thread de captura encerrada")

    def _handle_packet(self, packet):
        """Processa cada pacote capturado"""
        try:
            parsed = self._parse_packet(packet)
            if parsed:
                self.packet_handler(parsed)
        except Exception as e:
            logger.error(f"Erro no processamento do pacote: {e}")

    def _parse_packet(self, packet) -> dict:
        """Extrai informações básicas do pacote"""
        if not packet.haslayer(scapy.IP):
            return None

        parsed = {
            'timestamp': packet.time,
            'src_ip': packet[scapy.IP].src,
            'dest_ip': packet[scapy.IP].dst,
            'protocol': packet[scapy.IP].proto,
            'length': len(packet)
        }

        # Processar camadas específicas
        if packet.haslayer(scapy.TCP):
            parsed.update({
                'port_src': packet[scapy.TCP].sport,
                'port_dest': packet[scapy.TCP].dport,
                'flags': self._parse_tcp_flags(packet[scapy.TCP].flags)
            })
        elif packet.haslayer(scapy.UDP):
            parsed.update({
                'port_src': packet[scapy.UDP].sport,
                'port_dest': packet[scapy.UDP].dport
            })

        return parsed

    def _parse_tcp_flags(self, flags: int) -> str:
        """Decodifica flags TCP para string"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return '-'.join(flag_names)

    def stop(self):
        """Para a captura de pacotes de forma mais assertiva"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=1)  # Tempo máximo de espera
            if self.capture_thread.is_alive():
                logger.warning("Thread de captura não respondeu, finalizando forçadamente")
        logger.info("Captura interrompida com sucesso")

    def is_alive(self) -> bool:
        """Verifica se a captura está ativa"""
        return self.capture_thread.is_alive() if self.capture_thread else False

    def is_capturing(self) -> bool:
        """Alias para compatibilidade com código existente"""
        return self.running