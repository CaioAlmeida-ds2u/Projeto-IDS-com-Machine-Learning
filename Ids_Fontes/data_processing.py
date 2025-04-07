import logging
import time
from datetime import datetime
import ipaddress
from typing import Optional, Dict, Any, List, Set
from abc import ABC, abstractmethod

try:
    from config import ConfigManager
    from redis_client import RedisClient
except ImportError as e:
    logging.critical(f"ERRO CRÍTICO: Falha ao importar módulos locais: {e}")
    exit(1)

try:
    from scapy.packet import Packet
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    import socket
except ImportError as e:
    logging.critical(f"ERRO CRÍTICO: Falha ao importar Scapy ou socket: {e}")
    exit(1)

logger = logging.getLogger(__name__)

_DEFAULT_NOISY_PORTS: List[int] = [53, 123, 80, 443, 137, 138, 139, 1900, 5353, 15672]  # Portas ruidosas
_DEFAULT_ALLOWED_PORTS: List[int] = [22]  # Apenas SSH por padrão
_DEFAULT_NOISY_PROTOCOLS: List[int] = [17]  # UDP e ICMP
_DEFAULT_ALLOWED_PROTOCOLS: List[int] = [6,1]  # Apenas TCP

try:
    config_manager = ConfigManager()
    settings_config = config_manager.get_config().get('settings', {})
    
    noisy_ports = settings_config.get('noisy_ports', _DEFAULT_NOISY_PORTS)
    allowed_ports = settings_config.get('allowed_ports', _DEFAULT_ALLOWED_PORTS)
    noisy_protocols = settings_config.get('noisy_protocols', _DEFAULT_NOISY_PROTOCOLS)
    allowed_protocols = settings_config.get('allowed_protocols', _DEFAULT_ALLOWED_PROTOCOLS)

    _MODULE_NOISY_PORTS = set(noisy_ports) if isinstance(noisy_ports, list) and all(isinstance(p, int) for p in noisy_ports) else set(_DEFAULT_NOISY_PORTS)
    _MODULE_ALLOWED_PORTS = set(allowed_ports) if isinstance(allowed_ports, list) and all(isinstance(p, int) for p in allowed_ports) else set(_DEFAULT_ALLOWED_PORTS)
    _MODULE_NOISY_PROTOCOLS = set(noisy_protocols) if isinstance(noisy_protocols, list) and all(isinstance(p, int) for p in noisy_protocols) else set(_DEFAULT_NOISY_PROTOCOLS)
    _MODULE_ALLOWED_PROTOCOLS = set(allowed_protocols) if isinstance(allowed_protocols, list) and all(isinstance(p, int) for p in allowed_protocols) else set(_DEFAULT_ALLOWED_PROTOCOLS)

    logger.info(f"Configuração carregada - noisy_ports: {_MODULE_NOISY_PORTS}, allowed_ports: {_MODULE_ALLOWED_PORTS}, noisy_protocols: {_MODULE_NOISY_PROTOCOLS}, allowed_protocols: {_MODULE_ALLOWED_PROTOCOLS}")
except Exception as e:
    logger.error(f"Erro ao carregar configurações: {e}. Usando padrões.", exc_info=True)
    _MODULE_NOISY_PORTS = set(_DEFAULT_NOISY_PORTS)
    _MODULE_ALLOWED_PORTS = set(_DEFAULT_ALLOWED_PORTS)
    _MODULE_NOISY_PROTOCOLS = set(_DEFAULT_NOISY_PROTOCOLS)
    _MODULE_ALLOWED_PROTOCOLS = set(_DEFAULT_ALLOWED_PROTOCOLS)

class PacketFilter(ABC):
    @abstractmethod
    def apply(self, packet_data: Dict[str, Any]) -> bool:
        pass

class AllowedPortFilter(PacketFilter):
    def __init__(self, allowed_ports: Set[int]):
        self.allowed_ports = allowed_ports

    def apply(self, packet_data: Dict[str, Any]) -> bool:
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        if src_port not in self.allowed_ports and dst_port not in self.allowed_ports:
            logger.debug(f"Pacote descartado por porta não permitida: SRC={src_port}, DST={dst_port}")
            return False
        return True

class AllowedProtocolFilter(PacketFilter):
    def __init__(self, allowed_protocols: Set[int]):
        self.allowed_protocols = allowed_protocols

    def apply(self, packet_data: Dict[str, Any]) -> bool:
        protocol = packet_data.get('protocol', 0)
        if protocol not in self.allowed_protocols:
            logger.debug(f"Pacote descartado por protocolo não permitido: Protocol={protocol} ({packet_data.get('protocol_name')})")
            return False
        return True

class BroadcastFilter(PacketFilter):
    def apply(self, packet_data: Dict[str, Any]) -> bool:
        if packet_data.get('dst_ip') == "255.255.255.255":
            logger.debug(f"Pacote broadcast geral descartado: {packet_data.get('src_ip')}")
            return False
        return True

class MulticastFilter(PacketFilter):
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
    def apply(self, packet_data: Dict[str, Any]) -> bool:
        src_ip, dst_ip = packet_data.get('src_ip'), packet_data.get('dst_ip')
        try:
            src_ip_obj = ipaddress.ip_address(src_ip) if src_ip else None
            dst_ip_obj = ipaddress.ip_address(dst_ip) if dst_ip else None
            src_loop = src_ip_obj and src_ip_obj.is_loopback
            dst_loop = dst_ip_obj and dst_ip_obj.is_loopback
            src_link_local = src_ip_obj and src_ip_obj.is_link_local
            dst_link_local = dst_ip_obj and dst_ip_obj.is_link_local
            if src_loop or dst_loop or src_link_local or dst_link_local:
                logger.debug(f"Pacote loopback ou link-local descartado: {src_ip} -> {dst_ip}")
                return False
        except ValueError:
            pass
        return True

class PayloadFilter(PacketFilter):
    def apply(self, packet_data: Dict[str, Any]) -> bool:
        payload_size = packet_data.get('payload_size', 0)
        if payload_size == 0:
            logger.debug(f"Pacote sem payload descartado: {packet_data.get('src_ip')} -> {packet_data.get('dst_ip')}")
            return False
        return True

class SameNetworkFilter(PacketFilter):
    def __init__(self, allowed_ports: Set[int]):
        self.allowed_ports = allowed_ports

    def apply(self, packet_data: Dict[str, Any]) -> bool:
        src_ip, dst_ip = packet_data.get('src_ip'), packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port', 0)
        try:
            src_ip_obj = ipaddress.ip_address(src_ip)
            dst_ip_obj = ipaddress.ip_address(dst_ip)
            if src_ip_obj.version == dst_ip_obj.version:
                prefix = 24 if src_ip_obj.version == 4 else 64
                net1 = ipaddress.ip_network(f"{src_ip}/{prefix}", strict=False)
                if dst_ip_obj in net1 and dst_port not in self.allowed_ports:
                    logger.debug(f"Pacote de mesma rede sem porta de interesse descartado: {src_ip} -> {dst_ip}, DST_PORT={dst_port}")
                    return False
        except ValueError:
            pass
        return True

class PacketProcessor:
    @staticmethod
    def process_ethernet(packet: Packet, result: Dict[str, Any]) -> None:
        if Ether in packet:
            eth = packet[Ether]
            result.update({'src_mac': eth.src, 'dst_mac': eth.dst, 'ether_type': eth.type})
            result['layers'].append('Ethernet')

    @staticmethod
    def process_ip(packet: Packet, result: Dict[str, Any]) -> bool:
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
        processed = False
        payload = b''
        if TCP in packet:
            tcp = packet[TCP]
            payload = bytes(tcp.payload)
            flags = PacketProcessor.parse_tcp_flags(tcp.flags)
            result.update({'src_port': tcp.sport, 'dst_port': tcp.dport, 'flags': flags})
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
        flag_keys = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        parsed = {key: 0 for key in flag_keys}
        if hasattr(flags, 'value'):
            flags_value = flags.value
        else:
            flags_value = int(flags) if flags is not None else 0
        if isinstance(flags_value, int):
            parsed['FIN'] = 1 if flags_value & 0x01 else 0
            parsed['SYN'] = 1 if flags_value & 0x02 else 0
            parsed['RST'] = 1 if flags_value & 0x04 else 0
            parsed['PSH'] = 1 if flags_value & 0x08 else 0
            parsed['ACK'] = 1 if flags_value & 0x10 else 0
            parsed['URG'] = 1 if flags_value & 0x20 else 0
            parsed['ECE'] = 1 if flags_value & 0x40 else 0
            parsed['CWR'] = 1 if flags_value & 0x80 else 0
        return parsed

class FeatureExtractor:
    def __init__(self, redis_client: Optional[RedisClient] = None):
        self.redis_client = redis_client

    def extract(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        features = {}
        proto = packet_data.get('protocol_name', '')
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        tcp_flags = packet_data.get('tcp_flags', {})
        features['is_tcp'] = 1 if proto == 'TCP' else 0
        features['is_udp'] = 1 if proto == 'UDP' else 0
        features['is_icmp'] = 1 if proto == 'ICMP' else 0
        features.update({f'flag_{k.lower()}': v for k, v in tcp_flags.items()})
        features['port_src_well_known'] = 1 if 0 < src_port < 1024 else 0
        features['port_dst_well_known'] = 1 if 0 < dst_port < 1024 else 0
        features['port_dst_is_dns'] = 1 if dst_port == 53 else 0
        features['port_dst_is_ntp'] = 1 if dst_port == 123 else 0
        features['port_dst_is_http'] = 1 if dst_port == 80 else 0
        features['port_dst_is_https'] = 1 if dst_port == 443 else 0
        features['port_dst_is_ssh'] = 1 if dst_port == 22 else 0
        features['udp_length'] = packet_data.get('udp_length', 0)
        features['payload_size'] = packet_data.get('payload_size', 0)
        features['same_network'] = self._check_same_network(packet_data.get('src_ip'), packet_data.get('dst_ip'))
        features['is_private'] = 1 if self._is_private(packet_data.get('src_ip')) or self._is_private(packet_data.get('dst_ip')) else 0
        if self.redis_client:
            src_ip = packet_data.get('src_ip')
            key = f"rate:{src_ip}"
            features['packet_rate'] = self.redis_client.increment_packet_count(key, ttl=5)
        return features

    @staticmethod
    def _check_same_network(ip1: str, ip2: str) -> int:
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
        if not ip:
            return False
        try:
            return not ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

class PacketNormalizer:
    def __init__(self, filters: List[PacketFilter] = None, redis_client: Optional[RedisClient] = None, rabbitmq_host: str = 'localhost', disable_filters: bool = False):
        self.processor = PacketProcessor()
        self.feature_extractor = FeatureExtractor(redis_client)
        self.rabbitmq_host = rabbitmq_host
        self.disable_filters = disable_filters
        self.filters = filters or [
            BroadcastFilter(),
            MulticastFilter(),
            LoopbackFilter(),
            AllowedPortFilter(_MODULE_ALLOWED_PORTS),
            AllowedProtocolFilter(_MODULE_ALLOWED_PROTOCOLS),
            PayloadFilter(),
            SameNetworkFilter(_MODULE_ALLOWED_PORTS)
        ]

    def normalize(self, packet: Packet) -> Optional[Dict[str, Any]]:
        try:
            logger.debug(f"Normalizando pacote: {packet.summary()}")
            raw_result = {
                'timestamp': time.time(), 'layers': [],
                'src_mac': None, 'dst_mac': None, 'ether_type': None,
                'src_ip': None, 'dst_ip': None, 'ip_version': 0,
                'ttl': 0, 'hop_limit': 0, 'protocol': 0, 'protocol_name': None,
                'src_port': 0, 'dst_port': 0, 'flags': {}, 'udp_length': 0,
                'payload_size': 0, 'icmp_type': -1, 'icmp_code': -1
            }

            self.processor.process_ethernet(packet, raw_result)
            logger.debug(f"Após Ethernet: {raw_result.get('src_mac')} -> {raw_result.get('dst_mac')}")
            if not self.processor.process_ip(packet, raw_result):
                logger.debug("Pacote sem IP descartado.")
                return None
            logger.debug(f"Após IP: {raw_result.get('src_ip')} -> {raw_result.get('dst_ip')}, Protocol={raw_result.get('protocol')}")

            self.processor.process_transport(packet, raw_result)
            logger.debug(f"Após Transporte: SRC_PORT={raw_result['src_port']}, DST_PORT={raw_result['dst_port']}, Payload={raw_result['payload_size']}, Flags={raw_result['flags']}")

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

            src_ip = normalized.get('src_ip')
            dst_ip = normalized.get('dst_ip')
            logger.debug(f"IPs validados: {src_ip} -> {dst_ip}")

            if src_ip == self.rabbitmq_host or dst_ip == self.rabbitmq_host:
                logger.debug(f"Pacote do/para RabbitMQ ignorado: {src_ip} -> {dst_ip}")
                return None
            
            tcp_flags = normalized["tcp_flags"]
            logger.debug(f"Flags TCP antes de verificação: {tcp_flags}")
            if normalized["protocol"] == 6 and all(flag == 0 for flag in tcp_flags.values()):
                logger.debug(f"Pacote TCP com flags zeradas descartado: {src_ip} -> {dst_ip}")
                return None

            if not self.disable_filters:
                for filt in self.filters:
                    if not filt.apply(normalized):
                        logger.debug(f"Pacote descartado por filtro {filt.__class__.__name__}: {src_ip} -> {dst_ip}, Protocol={normalized['protocol_name']}, Port={normalized['dst_port']}")
                        return None
            else:
                logger.debug("Filtros desativados, prosseguindo com normalização.")

            features = self.feature_extractor.extract(normalized)
            logger.debug(f"Features extraídas: {src_ip} -> {dst_ip}, Port={normalized['dst_port']}")
            return {**normalized, **features}

        except Exception as e:
            logger.error(f"Erro na normalização: {e}", exc_info=True)
            return None

    @staticmethod
    def _validate_ip(ip: Optional[str]) -> Optional[str]:
        if not ip or not isinstance(ip, str):
            return None
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s [%levelname]s] - %(message)s')
    logger.info("Testando PacketNormalizer...")

    redis_client = RedisClient(host='localhost', port=6379, db=0)
    normalizer = PacketNormalizer(redis_client=redis_client, disable_filters=False)

    from scapy.all import *
    packets = [
        Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=12345, dport=53)/"udp test",  # UDP DNS
        Ether()/IP(src="10.0.0.5", dst="1.1.1.1")/TCP(sport=54321, dport=80, flags="S"),  # TCP HTTP SYN
        Ether()/IP(src="192.168.3.37", dst="192.168.3.4")/TCP(sport=56426, dport=22, flags="S"),  # SSH SYN
        Ether()/IP(src="192.168.3.37", dst="192.168.3.4")/TCP(sport=22, dport=56426, flags="PA")/"ssh data"*100,  # SSH PSH+ACK
        Ether()/IP(src="127.0.0.1", dst="127.0.0.1")/TCP(dport=8080),  # Loopback
        Ether()/IP(src="172.16.0.1", dst="255.255.255.255")/UDP(sport=138, dport=138)  # Broadcast
    ]

    for i, pkt in enumerate(packets):
        print(f"\nPacote {i+1}: {pkt.summary()}")
        result = normalizer.normalize(pkt)
        if result:
            import pprint
            pprint.pprint(result)
        else:
            print("Descartado.")