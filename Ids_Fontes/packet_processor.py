# /home/admin/ids_project/packet_processor.py

import scapy.all as scapy
import threading
import logging
import time
import os
from typing import Callable, Optional, List
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from queue import Queue

logger = logging.getLogger(__name__)

class PacketCapturer:
    """Classe para captura de pacotes de rede em uma ou mais interfaces."""

    def __init__(self, interfaces: List[str], packet_handler: Callable[[Packet], None], filter_rules: str = "ip or ip6", buffer_size: int = 1000):
        """
        Inicializa o capturador.

        Args:
            interfaces: Lista de interfaces de rede para captura.
            packet_handler: Função para processar cada pacote capturado.
            filter_rules: Regras de filtro para o Scapy (ex.: 'ip or ip6').
            buffer_size: Tamanho máximo do buffer de pacotes.
        """
        self.interfaces = interfaces
        self.packet_handler = packet_handler
        self.filter_rules = filter_rules
        self.buffer_size = buffer_size
        self.running = False
        self.running_lock = threading.Lock()
        self.capture_threads: List[threading.Thread] = []
        self.packet_queue = Queue(maxsize=buffer_size)
        self.processor_thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Inicia a captura em todas as interfaces especificadas."""
        with self.running_lock:
            if self.running:
                logger.warning("Captura já está em execução.")
                return False

        # Valida interfaces e permissões
        available_interfaces = scapy.get_if_list()
        for iface in self.interfaces:
            if iface not in available_interfaces:
                logger.error(f"Interface inválida ou não encontrada: {iface}")
                return False
            if not self._check_permissions(iface):
                logger.error(f"Permissões insuficientes para capturar em {iface}. Execute com privilégios.")
                return False

        self.running = True
        try:
            # Inicia threads de captura para cada interface
            for iface in self.interfaces:
                thread = threading.Thread(
                    target=self._capture_loop,
                    args=(iface,),
                    name=f"PacketCapturer-{iface}",
                    daemon=True
                )
                self.capture_threads.append(thread)
                thread.start()

            # Inicia thread de processamento do buffer
            self.processor_thread = threading.Thread(
                target=self._process_buffer,
                name="PacketProcessor",
                daemon=True
            )
            self.processor_thread.start()

            logger.info(f"Captura iniciada em interfaces {self.interfaces} com filtro: {self.filter_rules}")
            return True
        except Exception as e:
            logger.error(f"Falha ao iniciar captura: {e}", exc_info=True)
            self.running = False
            return False

    def _check_permissions(self, interface: str) -> bool:
        """Verifica se há permissões para capturar na interface."""
        try:
            # Testa captura mínima para verificar permissões
            scapy.sniff(iface=interface, count=1, timeout=1, store=False)
            return True
        except PermissionError:
            return False
        except Exception:
            return True  # Assume OK se não for PermissionError

    def _capture_loop(self, interface: str) -> None:
        """Loop de captura para uma interface específica."""
        logger.debug(f"Iniciando captura em {interface}")
        retry_count = 0
        max_retries = 3
        while self.running and retry_count < max_retries:
            try:
                scapy.sniff(
                    iface=interface,
                    prn=lambda pkt: self.packet_queue.put(pkt),
                    store=False,
                    stop_filter=lambda _: not self.running,
                    filter=self.filter_rules,
                    timeout=60  # Reinicia após 60s se não houver pacotes
                )
                retry_count = 0  # Reseta retries após sucesso
            except PermissionError:
                logger.error(f"Permissão insuficiente em {interface}. Encerrando captura.")
                break
            except scapy.Scapy_Exception as e:
                logger.error(f"Erro do Scapy em {interface}: {e}")
                retry_count += 1
                time.sleep(5 * retry_count)  # Backoff
            except Exception as e:
                logger.error(f"Erro inesperado em {interface}: {e}", exc_info=True)
                retry_count += 1
                time.sleep(5 * retry_count)
        self.running = False
        logger.info(f"Captura em {interface} encerrada.")

    def _process_buffer(self) -> None:
        """Processa pacotes do buffer em uma thread separada."""
        while self.running or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self._handle_packet(packet)
                self.packet_queue.task_done()
            except Queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Erro ao processar pacote do buffer: {e}", exc_info=True)

    def _handle_packet(self, packet: Packet) -> None:
        """Processa cada pacote capturado."""
        try:
            # Logging reduzido para performance; habilitar apenas em debug
            if logger.isEnabledFor(logging.DEBUG):
                if UDP in packet:
                    logger.debug(f"UDP: {packet.summary()} | {packet[IP].src} -> {packet[IP].dst}")
                elif TCP in packet:
                    logger.debug(f"TCP: {packet.summary()} | {packet[IP].src} -> {packet[IP].dst}")
                elif ICMP in packet:
                    logger.debug(f"ICMP: {packet.summary()} | {packet[IP].src} -> {packet[IP].dst}")
                elif IPv6 in packet:
                    logger.debug(f"IPv6: {packet.summary()} | {packet[IPv6].src} -> {packet[IPv6].dst}")
                else:
                    logger.debug(f"Outro: {packet.summary()}")
            self.packet_handler(packet)
        except Exception as e:
            logger.error(f"Erro ao processar pacote: {e}", exc_info=True)

    def stop(self) -> None:
        """Para a captura em todas as interfaces."""
        with self.running_lock:
            if not self.running:
                logger.info("Captura já estava parada.")
                return
            self.running = False

        for thread in self.capture_threads:
            if thread.is_alive():
                thread.join(timeout=5)
                if thread.is_alive():
                    logger.warning(f"Thread de captura {thread.name} não encerrou a tempo.")
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=5)
            if self.processor_thread.is_alive():
                logger.warning("Thread de processamento não encerrou a tempo.")
        self.capture_threads.clear()
        self.processor_thread = None
        logger.info("Captura finalizada.")

    def is_alive(self) -> bool:
        """Verifica se alguma thread de captura está ativa."""
        return any(t.is_alive() for t in self.capture_threads) if self.capture_threads else False

# Teste standalone
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
    def dummy_handler(pkt):
        print(f"Pacote capturado: {pkt.summary()}")

    capturer = PacketCapturer(interfaces=["lo"], packet_handler=dummy_handler)
    capturer.start()
    time.sleep(10)
    capturer.stop()