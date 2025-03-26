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
    def normalize(packet: Packet) -> Optional[dict]:
        """Normaliza e valida os dados do pacote para análise."""
        try:
            result = {
                'timestamp': time.time(),
                'layers': [],
                'protocols': []
            }

            PacketNormalizer._process_ethernet(packet, result)
            PacketNormalizer._process_ip(packet, result)
            PacketNormalizer._process_transport(packet, result)

            if 'protocol' not in result:
                return None

            normalized_result = {
                'timestamp': datetime.fromtimestamp(result['timestamp']).isoformat(),
                'src_ip': PacketNormalizer._validate_ip(result.get('src_ip')),
                'dst_ip': PacketNormalizer._validate_ip(result.get('dst_ip')),
                'protocol': result['protocol'],
                'src_port': result.get('src_port', 0),
                'dst_port': result.get('dst_port', 0),
                'ip_version': result.get('ip_version', 0),
                'ttl': result.get('ttl', 0),
                'tcp_flags': result.get('flags', {}),
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
    def _process_transport(packet: Packet, result: dict) -> None:
        """Processa a camada de transporte (TCP, UDP, ICMP)."""
        if TCP in packet:
            tcp = packet[TCP]
            result.update({
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'flags': PacketNormalizer._parse_tcp_flags(tcp.flags)
            })
            result['layers'].append('TCP')
            result['protocols'].append('TCP')   

        elif UDP in packet:
            udp = packet[UDP]
            result.update({
                'src_port': udp.sport,
                'dst_port': udp.dport,
                'udp_length': len(udp)
            })
            result['layers'].append('UDP')
            result['protocols'].append('UDP')   

        elif ICMP in packet:
            icmp = packet[ICMP]
            result.update({
                'icmp_type': icmp.type,
                'icmp_code': icmp.code
            })
            result['layers'].append('ICMP')
            result['protocols'].append('ICMP')  

        else:
            # Caso nenhum protocolo de transporte seja identificado
            result['protocol'] = 'Unknown'
            logger.debug("Protocolo de transporte desconhecido no pacote.")

    @staticmethod
    def _validate_ip(ip: Optional[str]) -> Optional[str]:
        """Valida e normaliza endereços IP."""
        if not ip:
            return None
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            logger.warning(f"IP inválido: {ip}")
            return None

    @staticmethod
    def _is_private_network(src_ip: Optional[str], dst_ip: Optional[str]) -> bool:
        """Verifica se pelo menos um IP está em rede privada."""
        try:
            return any(ipaddress.ip_address(ip).is_private for ip in (src_ip, dst_ip) if ip)
        except ValueError:
            return False

    @staticmethod
    def _parse_tcp_flags(flags: int) -> Dict[str, bool]:
        """
        Decodifica flags TCP para um dicionário booleano.

        Args:
            flags (int): Valor inteiro representando as flags TCP.

        Returns:
            Dict[str, bool]: Dicionário com as flags TCP como chaves e valores booleanos.
        """
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
        """
        Extrai features para análise de Machine Learning.

        Args:
            packet (dict): Dicionário contendo os dados normalizados do pacote.

        Returns:
            dict: Dicionário com as features extraídas.
        """
        return {
            'is_tcp': int(packet.get('protocol') == 'TCP'),
            'is_udp': int(packet.get('protocol') == 'UDP'),
            'is_icmp': int(packet.get('protocol') == 'ICMP'),
            'flag_syn': int(packet.get('tcp_flags', {}).get('SYN', False)),
            'flag_ack': int(packet.get('tcp_flags', {}).get('ACK', False)),
            'flag_fin': int(packet.get('tcp_flags', {}).get('FIN', False)),
            'port_src_well_known': int(packet.get('src_port', 0) < 1024),
            'port_dst_well_known': int(packet.get('dst_port', 0) < 1024),
            'udp_length': packet.get('udp_length', 0),
            'payload_size': packet.get('payload_size', 0),
            'port_dst_is_dns': int(packet.get('dst_port') == 53),
            'port_dst_is_ntp': int(packet.get('dst_port') == 123),
            'same_network': int(
                PacketNormalizer._safe_ip_network(packet.get('src_ip'), packet.get('dst_ip'))
            )
        }
    
    @staticmethod
    def _safe_ip_network(ip1: Optional[str], ip2: Optional[str]) -> bool:
        """Verifica se dois IPs estão na mesma sub-rede /24, lidando com possíveis erros."""
        try:
            if ip1 and ip2:
                net1 = ipaddress.ip_network(f"{ip1}/24", strict=False)
                net2 = ipaddress.ip_network(f"{ip2}/24", strict=False)
                return net1 == net2
        except ValueError:
            pass
        return False
    
    @staticmethod
    def _process_ethernet(packet: Packet, result: dict) -> None:
        """Processa a camada Ethernet."""
        if Ether in packet:
            eth = packet[Ether]
            result.update({
                'src_mac': eth.src,
                'dst_mac': eth.dst,
                'ether_type': eth.type
            })
            result['layers'].append('Ethernet')

    @staticmethod
    def _process_ip(packet: Packet, result: dict) -> None:
        """Processa a camada IP."""
        if IP in packet:
            ip = packet[IP]
            result.update({
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'ip_version': 4,
                'ttl': ip.ttl,
                'protocol': ip.proto
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
                'protocol': ipv6.nh
            })
            result['layers'].append('IPv6')
            result['protocols'].append('IP')