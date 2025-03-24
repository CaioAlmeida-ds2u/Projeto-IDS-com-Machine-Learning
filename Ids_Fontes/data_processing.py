import logging
import time
from datetime import datetime
import ipaddress
from typing import Optional, Dict, Any
from scapy.packet import Packet  # Importante: Recebe um objeto Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

logger = logging.getLogger(__name__)

class PacketNormalizer:
    """Classe para normalização e enriquecimento de dados de pacotes"""

    @staticmethod
    def normalize(packet: Packet) -> Optional[dict]:  # Recebe um objeto Packet
        """Normaliza e valida os dados do pacote para análise."""
        try:
            result = {
                'timestamp': time.time(),
                'layers': [],
                'protocols': []
            }

            # --- Ethernet ---
            if Ether in packet:
                eth = packet[Ether]
                result.update({
                    'src_mac': eth.src,
                    'dst_mac': eth.dst,
                    'ether_type': eth.type
                })
                result['layers'].append('Ethernet')

            # --- IP ---
            if IP in packet:
                ip = packet[IP]
                result.update({
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'ip_version': 4,
                    'ttl': ip.ttl,
                    'protocol': ip.proto  # Protocolo da camada de transporte
                })
                result['layers'].append('IPv4')
                result['protocols'].append('IP')
            elif IPv6 in packet:
                ipv6 = packet[IPv6]
                result.update({
                    'src_ip': ipv6.src,
                    'dst_ip': ipv6.dst,
                    'ip_version': 6,
                    'hop_limit': ipv6.hlim,
                    'protocol': ipv6.nh  # Next Header (similar a ip.proto)
                })
                result['layers'].append('IPv6')
                result['protocols'].append('IP')


            # --- Transporte ---
            if TCP in packet:
                tcp = packet[TCP]
                result.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'flags': PacketNormalizer._parse_tcp_flags(tcp.flags),
                    'protocol': 'TCP'  # Sobrescreve o protocolo IP
                })
                result['layers'].append('TCP')
            elif UDP in packet:
                udp = packet[UDP]
                result.update({
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'protocol': 'UDP'  # Sobrescreve o protocolo IP
                })
                result['layers'].append('UDP')
            elif ICMP in packet:
                # ICMP não tem portas
                result.update({
                    'protocol': 'ICMP'  # Sobrescreve o protocolo IP
                })
                result['layers'].append('ICMP')

            if 'protocol' not in result:
                return None  # Não processa se não houver protocolo
            
            normalized_result =  {
                'timestamp': datetime.fromtimestamp(result['timestamp']).isoformat(),
                'src_ip': PacketNormalizer._validate_ip(result.get('src_ip')),
                'dst_ip': PacketNormalizer._validate_ip(result.get('dst_ip')),
                'protocol': result['protocol'],
                'src_port': result.get('src_port', 0),
                'dst_port': result.get('dst_port', 0),
                'ip_version': result.get('ip_version', 0),
                'ttl': result.get('ttl', 0),
                'tcp_flags': result.get('flags', {}),  # Flags TCP
                # 'payload_size': len(packet.payload) if hasattr(packet, 'payload') else 0, # Adicionado
                'src_mac': result.get('src_mac'),
                'dst_mac': result.get('dst_mac')
            }
            if not normalized_result['src_ip'] or not normalized_result['dst_ip']:
                return None

            return {**normalized_result, **PacketNormalizer._extract_features(normalized_result)}

        except Exception as e:
            logger.error(f"Erro na normalização: {e}", exc_info=True)
            return None

    @staticmethod
    def _validate_ip(ip: Optional[str]) -> Optional[str]:
        """Valida e normaliza endereços IP."""
        if not ip:
            return None
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return None

    @staticmethod
    def _is_private_network(src_ip: Optional[str], dst_ip: Optional[str]) -> bool:
        """Verifica se pelo menos um IP está em rede privada."""
        def check_private(ip):
            if not ip: return False
            try:
                return ipaddress.ip_address(ip).is_private
            except ValueError:
                return False
        return check_private(src_ip) or check_private(dst_ip)

    @staticmethod
    def _parse_tcp_flags(flags: int) -> Dict[str, bool]:
        """Decodifica flags TCP para dicionário booleano."""
        return {
            'FIN': bool(flags & 0x01),
            'SYN': bool(flags & 0x02),
            'RST': bool(flags & 0x04),
            'PSH': bool(flags & 0x08),
            'ACK': bool(flags & 0x10),
            'URG': bool(flags & 0x20)
        }
    @staticmethod
    def _extract_features(packet: dict) -> dict:
        """Extrai features para análise de ML."""
        return {
            'is_tcp': int(packet['protocol'] == 'TCP'),
            'is_udp': int(packet['protocol'] == 'UDP'),
            'is_icmp': int(packet['protocol'] == 'ICMP'),
            'flag_syn': int(packet.get('tcp_flags', {}).get('SYN', False)),  # Acesso seguro
            'flag_ack': int(packet.get('tcp_flags', {}).get('ACK', False)),  # Acesso seguro
            'flag_fin': int(packet.get('tcp_flags', {}).get('FIN', False)),  # Acesso seguro
            'port_src_well_known': int(packet.get('src_port', 0) < 1024),  # Acesso seguro
            'port_dst_well_known': int(packet.get('dst_port', 0) < 1024),   # Acesso seguro
            'same_network': int(
                PacketNormalizer._safe_ip_network(packet.get('src_ip'), packet.get('dst_ip'))
            )
        }
    
    @staticmethod
    def _safe_ip_network(ip1: Optional[str], ip2: Optional[str]) -> bool:
        """Verifica se dois IPs estão na mesma sub-rede /24, lidando com possíveis erros."""
        if not ip1 or not ip2:
            return False
        try:
            return ipaddress.ip_network(ip1 + '/24', strict=False) == ipaddress.ip_network(ip2 + '/24', strict=False)
        except ValueError:
            return False