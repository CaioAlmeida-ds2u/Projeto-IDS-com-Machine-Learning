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

# Remoção da classe DataProcessor conforme solicitado