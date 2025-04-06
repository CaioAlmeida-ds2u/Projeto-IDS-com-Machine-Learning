# /home/admin/ids_project/data_processing.py

import logging
import time
from datetime import datetime
import ipaddress
from typing import Optional, Dict, Any, List, Set
from abc import ABC, abstractmethod

# Importações essenciais
try:
    from config import ConfigManager
    from redis_client import RedisClient  # Para features dinâmicas
except ImportError as e:
    logging.critical(f"ERRO CRÍTICO: Falha ao importar módulos locais: {e}")
    exit(1)

# Importações do Scapy
try:
    from scapy.packet import Packet
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    import socket  # Para nomes de protocolos
except ImportError as e:
    logging.critical(f"ERRO CRÍTICO: Falha ao importar Scapy ou socket: {e}")
    exit(1)

logger = logging.getLogger(__name__)

# Configuração global de noisy_ports
_DEFAULT_NOISY_PORTS: List[int] = [53, 137, 138, 139, 1900, 5353, 15672]  # Exemplo de portas ruidosas
_MODULE_NOISY_PORTS: Set[int] = set(_DEFAULT_NOISY_PORTS)

try:
    config_manager = ConfigManager()
    settings_config = config_manager.get_config().get('settings', {})
    noisy_ports = settings_config.get('noisy_ports')
    if isinstance(noisy_ports, list) and all(isinstance(p, int) for p in noisy_ports):
        _MODULE_NOISY_PORTS = set(noisy_ports)
        logger.info(f"noisy_ports carregado da config: {_MODULE_NOISY_PORTS}")
    else:
        logger.warning("noisy_ports inválido na config. Usando padrão.")
except Exception as e:
    logger.error(f"Erro ao carregar noisy_ports: {e}. Usando padrão.", exc_info=True)

# Interface para filtros
class PacketFilter(ABC):
    @abstractmethod
    def apply(self, packet_data: Dict[str, Any]) -> bool:
        """Retorna True se o pacote deve ser mantido, False se descartado."""
        pass

class NoisyPortFilter(PacketFilter):
    """Filtro para portas ruidosas configuráveis."""
    def __init__(self, noisy_ports: Set[int]):
        self.noisy_ports = noisy_ports

    def apply(self, packet_data: Dict[str, Any]) -> bool:
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        if src_port in self.noisy_ports or dst_port in self.noisy_ports:
            logger.debug(f"Pacote descartado por porta ruidosa: SRC={src_port}, DST={dst_port}")
            return False
        return True

class BroadcastFilter(PacketFilter):
    """Filtro para pacotes broadcast."""
    def apply(self, packet_data: Dict[str, Any]) -> bool:
        if packet_data.get('dst_ip') == "255.255.255.255":
            logger.debug(f"Pacote broadcast geral descartado: {packet_data.get('src_ip')}")
            return False
        return True

class MulticastFilter(PacketFilter):
    """Filtro para pacotes multicast."""
    def apply(self, packet_data: Dict[str, Any]) -> bool:
        dst_ip = packet_data.get('dst_ip')
        try:
            if dst_ip and ipaddress.ip_address(dst_ip).is_multicast:
                logger.debug(f"Pacote multicast descartado: {dst_ip}")
                return False
        except ValueError:
            pass
        return True

class LoopbackFilter(PacketFilter):
    """Filtro para pacotes loopback e link-local."""
    def apply(self, packet_data: Dict[str, Any]) -> bool:
        src_ip, dst_ip = packet_data.get('src_ip'), packet_data.get('dst_ip')
        try:
            src_ip_obj = ipaddress.ip_address(src_ip) if src_ip else None
            dst_ip_obj = ipaddress.ip_address(dst_ip) if dst_ip else None
            
            # Verifica loopback (127.0.0.0/8 ou ::1)
            src_loop = src_ip_obj and src_ip_obj.is_loopback
            dst_loop = dst_ip_obj and dst_ip_obj.is_loopback
            
            # Verifica link-local (169.254.0.0/16 ou fe80::/10)
            src_link_local = src_ip_obj and src_ip_obj.is_link_local
            dst_link_local = dst_ip_obj and dst_ip_obj.is_link_local
            
            if src_loop or dst_loop or src_link_local or dst_link_local:
                logger.debug(f"Pacote loopback ou link-local descartado: {src_ip} -> {dst_ip}")
                return False
        except ValueError:
            pass
        return True

class PacketProcessor:
    """Classe base para processar camadas de pacotes."""
    @staticmethod
    def process_ethernet(packet: Packet, result: Dict[str, Any]) -> None:
        """Extrai dados da camada Ethernet."""
        if Ether in packet:
            eth = packet[Ether]
            result.update({'src_mac': eth.src, 'dst_mac': eth.dst, 'ether_type': eth.type})
            result['layers'].append('Ethernet')

    @staticmethod
    def process_ip(packet: Packet, result: Dict[str, Any]) -> bool:
        """Extrai dados da camada IP (IPv4/IPv6). Retorna True se processado."""
        if IP in packet:
            ip = packet[IP]
            result.update({'src_ip': ip.src, 'dst_ip': ip.dst, 'ip_version': 4, 'ttl': ip.ttl, 'protocol': ip.proto})
            result['layers'].append('IPv4')
            return True
        elif IPv6 in packet:
            ipv6 = packet[IPv6]
            result.update({'src_ip': ipv6.src, 'dst_ip': ipv6.dst, 'ip_version': 6, 'hop_limit': ipv6.hlim, 'protocol': ipv6.nh})
            result['layers'].append('IPv6')
            return True
        return False

    @staticmethod
    def process_transport(packet: Packet, result: Dict[str, Any]) -> bool:
        """Extrai dados da camada de transporte (TCP/UDP/ICMP)."""
        processed = False
        payload = b''
        if TCP in packet:
            tcp = packet[TCP]
            payload = bytes(tcp.payload)
            result.update({'src_port': tcp.sport, 'dst_port': tcp.dport, 'flags': PacketProcessor.parse_tcp_flags(tcp.flags)})
            result['protocol_name'] = 'TCP'
            processed = True
        elif UDP in packet:
            udp = packet[UDP]
            payload = bytes(udp.payload)
            result.update({'src_port': udp.sport, 'dst_port': udp.dport, 'udp_length': udp.len})
            result['protocol_name'] = 'UDP'
            processed = True
        elif ICMP in packet:
            icmp = packet[ICMP]
            payload = bytes(icmp.payload)
            result.update({'icmp_type': icmp.type, 'icmp_code': icmp.code})
            result['protocol_name'] = 'ICMP'
            processed = True
        else:
            proto = result.get('protocol')
            if proto:
                try:
                    result['protocol_name'] = socket.getprotobynumber(proto).upper()
                except (AttributeError, OSError):
                    # Fallback manual se getprotobynumber não existir ou falhar
                    common_protos = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP'}
                    result['protocol_name'] = common_protos.get(proto, f'Proto{proto}')
                ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
                if ip_layer and hasattr(ip_layer, 'payload'):
                    payload = bytes(ip_layer.payload)
                processed = True

        if processed:
            result['payload_size'] = len(payload)
            result['layers'].append(result['protocol_name'])
        return processed

    @staticmethod
    def parse_tcp_flags(flags: Any) -> Dict[str, int]:
        """Converte flags TCP em dicionário."""
        flag_keys = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        parsed = {key: 0 for key in flag_keys}
        if isinstance(flags, int):
            parsed['FIN'] = 1 if flags & 0x01 else 0
            parsed['SYN'] = 1 if flags & 0x02 else 0
            parsed['RST'] = 1 if flags & 0x04 else 0
            parsed['PSH'] = 1 if flags & 0x08 else 0
            parsed['ACK'] = 1 if flags & 0x10 else 0
            parsed['URG'] = 1 if flags & 0x20 else 0
            parsed['ECE'] = 1 if flags & 0x40 else 0
            parsed['CWR'] = 1 if flags & 0x80 else 0
        return parsed

class FeatureExtractor:
    """Classe para extrair features para ML."""
    def __init__(self, redis_client: Optional[RedisClient] = None):
        self.redis_client = redis_client

    def extract(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extrai features para análise de ML."""
        features = {}
        proto = packet_data.get('protocol_name', '')
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        tcp_flags = packet_data.get('tcp_flags', {})

        # Indicadores de protocolo
        features['is_tcp'] = 1 if proto == 'TCP' else 0
        features['is_udp'] = 1 if proto == 'UDP' else 0
        features['is_icmp'] = 1 if proto == 'ICMP' else 0

        # Flags TCP
        features.update({f'flag_{k.lower()}': v for k, v in tcp_flags.items()})

        # Portas conhecidas
        features['port_src_well_known'] = 1 if 0 < src_port < 1024 else 0
        features['port_dst_well_known'] = 1 if 0 < dst_port < 1024 else 0
        features['port_dst_is_dns'] = 1 if dst_port == 53 else 0
        features['port_dst_is_ntp'] = 1 if dst_port == 123 else 0
        features['port_dst_is_http'] = 1 if dst_port == 80 else 0
        features['port_dst_is_https'] = 1 if dst_port == 443 else 0
        features['port_dst_is_ssh'] = 1 if dst_port == 22 else 0  # Novo: SSH

        # Tamanhos
        features['udp_length'] = packet_data.get('udp_length', 0)
        features['payload_size'] = packet_data.get('payload_size', 0)

        # Rede
        features['same_network'] = self._check_same_network(packet_data.get('src_ip'), packet_data.get('dst_ip'))
        features['is_private'] = 1 if self._is_private(packet_data.get('src_ip')) or self._is_private(packet_data.get('dst_ip')) else 0

        # Features dinâmicas (com Redis)
        if self.redis_client:
            src_ip = packet_data.get('src_ip')
            key = f"rate:{src_ip}"
            features['packet_rate'] = self.redis_client.increment_packet_count(key, ttl=5)  # Taxa em 5s

        return features

    @staticmethod
    def _check_same_network(ip1: str, ip2: str) -> int:
        """Verifica se IPs estão na mesma sub-rede."""
        if not ip1 or not ip2:
            return 0
        try:
            ip1_addr = ipaddress.ip_address(ip1)
            ip2_addr = ipaddress.ip_address(ip2)
            if ip1_addr.version != ip2_addr.version:
                return 0
            prefix = 24 if ip1_addr.version == 4 else 64
            net1 = ipaddress.ip_network(f"{ip1}/{prefix}", strict=False)
            return 1 if ip2_addr in net1 else 0
        except ValueError:
            return 0

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Verifica se o IP é privado, loopback ou link-local."""
        if not ip:
            return False
        try:
            return not ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

class PacketNormalizer:
    """Classe principal para normalizar pacotes."""
    def __init__(self, filters: List[PacketFilter] = None, redis_client: Optional[RedisClient] = None, rabbitmq_host: str = 'localhost'):
        self.processor = PacketProcessor()
        self.feature_extractor = FeatureExtractor(redis_client)
        self.rabbitmq_host = rabbitmq_host  # Host do RabbitMQ, passado pelo IDSController
        self.filters = filters or [
            BroadcastFilter(),
            MulticastFilter(),
            LoopbackFilter(),
            NoisyPortFilter(_MODULE_NOISY_PORTS)
        ]

    def normalize(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Normaliza um pacote Scapy e aplica filtros."""
        try:
            # Dados brutos iniciais
            raw_result = {
                'timestamp': time.time(), 'layers': [],
                'src_mac': None, 'dst_mac': None, 'ether_type': None,
                'src_ip': None, 'dst_ip': None, 'ip_version': 0,
                'ttl': 0, 'hop_limit': 0, 'protocol': 0, 'protocol_name': None,
                'src_port': 0, 'dst_port': 0, 'flags': {}, 'udp_length': 0,
                'payload_size': 0, 'icmp_type': -1, 'icmp_code': -1
            }

            # Processamento de camadas
            self.processor.process_ethernet(packet, raw_result)
            if not self.processor.process_ip(packet, raw_result):
                logger.debug("Pacote sem IP descartado.")
                return None
            self.processor.process_transport(packet, raw_result)

            # Normalização básica
            normalized = {
                'timestamp': datetime.fromtimestamp(raw_result['timestamp']).isoformat(),
                'src_mac': raw_result['src_mac'],
                'dst_mac': raw_result['dst_mac'],
                'src_ip': self._validate_ip(raw_result['src_ip']),
                'dst_ip': self._validate_ip(raw_result['dst_ip']),
                'ip_version': raw_result['ip_version'],
                'ttl': raw_result['hop_limit'] if raw_result['ip_version'] == 6 else raw_result['ttl'],
                'protocol': raw_result['protocol'],
                'protocol_name': raw_result.get('protocol_name', 'UNKNOWN'),
                'src_port': raw_result['src_port'],
                'dst_port': raw_result['dst_port'],
                'tcp_flags': raw_result['flags'],
                'udp_length': raw_result['udp_length'],
                'payload_size': raw_result['payload_size'],
                'icmp_type': raw_result['icmp_type'],
                'icmp_code': raw_result['icmp_code']
            }

            if not normalized['src_ip'] or not normalized['dst_ip']:
                logger.warning(f"Pacote descartado por IP inválido: SRC={raw_result['src_ip']} DST={raw_result['dst_ip']}")
                return None

            # Ignorar pacotes envolvendo o host do RabbitMQ
            src_ip = normalized.get('src_ip')
            dst_ip = normalized.get('dst_ip')
            if src_ip == self.rabbitmq_host or dst_ip == self.rabbitmq_host:
                logger.debug(f"Pacote do/para RabbitMQ ignorado: {src_ip} -> {dst_ip}")
                return None
            
            if normalized["protocol"] == 6 and all(flag == 0 for flag in normalized["tcp_flags"].values()):
                logger.debug(f"Pacote TCP com flags zeradas descartado: {normalized['src_ip']} -> {normalized['dst_ip']}")
                return None
            
            if normalized["payload_size"] == 0:
                logger.debug(f"Pacote sem payload descartado: {normalized['src_ip']} -> {normalized['dst_ip']}")
                return None

            # Aplicar filtros
            for filt in self.filters:
                if not filt.apply(normalized):
                    return None

            # Extrair features
            features = self.feature_extractor.extract(normalized)
            return {**normalized, **features}

        except Exception as e:
            logger.error(f"Erro na normalização: {e}", exc_info=True)
            return None

    @staticmethod
    def _validate_ip(ip: Optional[str]) -> Optional[str]:
        """Valida e normaliza IPs."""
        if not ip or not isinstance(ip, str):
            return None
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return None

# Teste standalone
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
    logger.info("Testando PacketNormalizer...")

    redis_client = RedisClient(host='localhost', port=6379, db=0)  # Ajuste conforme config
    normalizer = PacketNormalizer(redis_client=redis_client)

    # Pacotes de teste
    from scapy.all import *
    packets = [
        Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=12345, dport=53)/"udp test",
        Ether()/IP(src="10.0.0.5", dst="1.1.1.1")/TCP(sport=54321, dport=80, flags="S"),
        Ether()/IP(src="192.168.3.37", dst="192.168.3.4")/TCP(sport=22, dport=56426, flags="PA")/"ssh data"*100,
        Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/TCP(dport=8080),
        Ether()/IP(src="172.16.0.1", dst="255.255.255.255")/UDP(sport=138, dport=138)
    ]

    for i, pkt in enumerate(packets):
        print(f"\nPacote {i+1}: {pkt.summary()}")
        result = normalizer.normalize(pkt)
        if result:
            import pprint
            pprint.pprint(result)
        else:
            print("Descartado.")