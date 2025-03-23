# data_processing.py
import logging
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)

class PacketNormalizer:
    """Classe para normalização e preparação de dados para ML"""
    
    @staticmethod
    def normalize(raw_packet: dict) -> dict:
        """Normaliza os dados do pacote para formato estruturado"""
        try:
            normalized = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': raw_packet.get('src_ip', '0.0.0.0'),
                'dest_ip': raw_packet.get('dest_ip', '0.0.0.0'),
                'protocol': raw_packet.get('protocol', 'unknown'),
                'length': raw_packet.get('length', 0),
                'flags': raw_packet.get('flags', ''),
                'port_src': raw_packet.get('port_src', 0),
                'port_dest': raw_packet.get('port_dest', 0)
            }
            
            # Adicionar features básicas para ML
            normalized.update(PacketNormalizer._extract_basic_features(raw_packet))
            return normalized
        except Exception as e:
            logger.error(f"Erro na normalização: {e}")
            return None

    @staticmethod
    def _extract_basic_features(packet: dict) -> dict:
        """Extrai features básicas para análise"""
        features = {
            'is_tcp': 1 if packet.get('protocol') == 'TCP' else 0,
            'is_udp': 1 if packet.get('protocol') == 'UDP' else 0,
            'flag_syn': 1 if 'S' in packet.get('flags', '') else 0,
            'flag_ack': 1 if 'A' in packet.get('flags', '') else 0,
            'flag_fin': 1 if 'F' in packet.get('flags', '') else 0,
            'payload_size': packet.get('length', 0)
        }
        return features

class DataProcessor:
    """Classe para gerenciamento do pipeline de dados"""
    
    def __init__(self, db):
        self.db = db
        self.buffer = []
        self.buffer_lock = threading.Lock()
        self.last_write = time.time()
        self.write_interval = 5  # Segundos
        self.buffer_size = 100   # Itens

    def process_packet(self, packet_data: dict):
        """Adiciona pacote normalizado ao buffer"""
        normalized = PacketNormalizer.normalize(packet_data)
        if not normalized:
            return

        with self.buffer_lock:
            self.buffer.append(normalized)
            if self._should_flush():
                self._flush_buffer()

    def _should_flush(self) -> bool:
        """Verifica condições para descarregar o buffer"""
        return (len(self.buffer) >= self.buffer_size or
                (time.time() - self.last_write) > self.write_interval)

    def _flush_buffer(self):
        """Descarrega o buffer no banco de dados"""
        try:
            with self.buffer_lock:
                if not self.buffer:
                    return
                
                packets = self.buffer.copy()
                self.db.bulk_insert_packets(packets)
                self.buffer.clear()
                self.last_write = time.time()
                logger.debug(f"Buffer descarregado: {len(packets)} pacotes")
        except Exception as e:
            logger.error(f"Erro ao escrever no banco: {e}")
            # Re-inserir pacotes no buffer em caso de erro
            with self.buffer_lock:
                self.buffer.extend(packets)

    def flush(self):
        """Força a escrita dos dados remanescentes"""
        self._flush_buffer()