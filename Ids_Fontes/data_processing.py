# /home/admin/ids_project/data_processing.py

import logging
import time
from datetime import datetime
import ipaddress
from typing import Optional, Dict, Any, List, Set # Import Set
import copy # Importar para deepcopy

# Importações do Scapy
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
# Importar getprotobyname para o fallback (opcional, mas útil)
try:
     from scapy.utils import PcapReader # Exemplo, importar o necessário
     from scapy.all import getprotobyname # Tenta importar
except ImportError:
     # Fallback se getprotobyname não estiver disponível facilmente
     def getprotobyname(name):
         import socket
         try:
             return socket.getprotobyname(name)
         except OSError:
             # Mapeamento manual para protocolos comuns que Scapy usa
             proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
             return proto_map.get(name.lower())

logger = logging.getLogger(__name__)

class PacketNormalizer:
    """
    Classe para normalização, validação, ENRIQUECIMENTO e FILTRAGEM SIMPLES
    de dados de pacotes capturados pelo Scapy.
    (Versão CORRIGIDA e com FILTROS)
    """

    # Conjunto de portas conhecidas por gerar "ruído" em muitas redes. AJUSTE conforme necessário.
    NOISY_PORTS: Set[int] = {137, 138, 139, 1900, 5353} # NetBIOS, SSDP, mDNS

    @staticmethod
    def normalize(packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Normaliza, valida, enriquece e aplica filtros simples ao pacote Scapy.

        Args:
            packet (Packet): O pacote Scapy capturado.

        Returns:
            Optional[Dict[str, Any]]: Um dicionário com os dados normalizados e
                                     features extraídas se o pacote for considerado
                                     relevante, ou None se for descartado pelos filtros.
        """
        try:
            # Dicionário temporário para coletar dados brutos durante o processamento
            raw_result: Dict[str, Any] = {
                'timestamp': time.time(),       # Timestamp da captura/processamento inicial
                'layers': [],                   # Lista de nomes de camadas detectadas
                'protocols': [],                # Lista de nomes de protocolos detectados
                'src_mac': None, 'dst_mac': None, 'ether_type': None,
                'src_ip': None, 'dst_ip': None, 'ip_version': 0,
                'ttl': 0, 'hop_limit': 0, 'protocol': 0, 'protocol_name': None,
                'src_port': 0, 'dst_port': 0, 'flags': {}, 'udp_length': 0,
                'payload_size': 0, 'icmp_type': -1, 'icmp_code': -1
            }

            # 1. Processa Camada Ethernet (L2)
            PacketNormalizer._process_ethernet(packet, raw_result)

            # 2. Processa Camada IP (L3)
            ip_processed = PacketNormalizer._process_ip(packet, raw_result)
            if not ip_processed:
                logger.debug("Pacote sem camada IP reconhecida descartado.")
                return None

            # 3. Processa Camada de Transporte (L4)
            PacketNormalizer._process_transport(packet, raw_result)

            # --- INÍCIO: FILTROS SIMPLES DE "RUÍDO" ---
            # Obtem dados relevantes para os filtros do dicionário temporário
            # Usar .get() é mais seguro caso alguma chave não tenha sido preenchida
            dst_ip_str = raw_result.get('dst_ip')
            src_ip_str = raw_result.get('src_ip')
            dst_port = raw_result.get('dst_port', 0)
            src_port = raw_result.get('src_port', 0)

            # Filtro 1: Descartar broadcast geral IPv4
            if dst_ip_str == "255.255.255.255":
                logger.debug(f"Pacote broadcast geral (255.255.255.255) de {src_ip_str} descartado.")
                return None

            # Filtro 2: Descartar multicast se não for relevante
            try:
                if dst_ip_str and ipaddress.ip_address(dst_ip_str).is_multicast:
                     # Você pode adicionar exceções: ex, não descartar IGMP (proto 2) ou PIM se precisar
                     # proto_num = raw_result.get('protocol')
                     # if proto_num == 2: # Exemplo: manter IGMP
                     #     pass
                     # else:
                     logger.debug(f"Pacote multicast ({dst_ip_str}) de {src_ip_str} descartado.")
                     return None
            except ValueError: pass # Ignora se IP for inválido (será pego depois)

            # Filtro 3: Descartar loopback (tráfego para si mesmo) se não interessar
            try:
                # Verifica se origem OU destino é loopback
                if (src_ip_str and ipaddress.ip_address(src_ip_str).is_loopback) or \
                   (dst_ip_str and ipaddress.ip_address(dst_ip_str).is_loopback):
                     logger.debug(f"Pacote loopback ({src_ip_str} -> {dst_ip_str}) descartado.")
                     return None
            except ValueError: pass

            # Filtro 4: Descartar portas específicas conhecidas por ruído
            if dst_port in PacketNormalizer.NOISY_PORTS or src_port in PacketNormalizer.NOISY_PORTS:
                logger.debug(f"Pacote em porta 'ruidosa' (SRC:{src_port} DST:{dst_port}) descartado.")
                return None
            # --- FIM: FILTROS SIMPLES DE "RUÍDO" ---


            # --- Montagem do Resultado Final Normalizado (Só se passou pelos filtros) ---
            normalized_base = {
                'timestamp': datetime.fromtimestamp(raw_result['timestamp']).isoformat(),
                'src_mac': raw_result['src_mac'],
                'dst_mac': raw_result['dst_mac'],
                'src_ip': PacketNormalizer._validate_ip(raw_result['src_ip']),
                'dst_ip': PacketNormalizer._validate_ip(raw_result['dst_ip']),
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

            # Validação Crítica: IPs devem ser válidos após normalização
            if not normalized_base['src_ip'] or not normalized_base['dst_ip']:
                # O _validate_ip já pode ter retornado None, este log é uma segurança extra
                logger.warning(f"Pacote descartado por IP inválido na validação final: SRC={raw_result['src_ip']} DST={raw_result['dst_ip']}")
                return None

            # 4. Extrai Features Adicionais (para ML)
            ml_features = PacketNormalizer._extract_features(normalized_base)

            # 5. Mescla o dicionário base com as features de ML
            final_result = {**normalized_base, **ml_features}

            return final_result

        except Exception as e:
            logger.error(f"Erro inesperado durante normalização: {e}", exc_info=True)
            try:
                 if packet: logger.error(f"Pacote com erro (sumário): {packet.summary()[:250]}")
            except: pass
            return None


    @staticmethod
    def _process_ethernet(packet: Packet, result: dict) -> None:
        """Processa a camada Ethernet (L2), se presente."""
        if Ether in packet:
            eth = packet[Ether]
            result.update({
                'src_mac': eth.src,
                'dst_mac': eth.dst,
                'ether_type': eth.type
            })
            result['layers'].append('Ethernet')

    @staticmethod
    def _process_ip(packet: Packet, result: dict) -> bool:
        """Processa a camada IP (L3 - IPv4 ou IPv6), se presente. Retorna True se processado."""
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
            return True
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
            return True
        return False

    @staticmethod
    def _process_transport(packet: Packet, result: dict) -> bool:
        """Processa a camada de Transporte (L4 - TCP, UDP, ICMP), se presente. Retorna True se processado."""
        layer4_processed = False
        payload = b''

        if TCP in packet:
            tcp = packet[TCP]
            payload = bytes(tcp.payload)
            result.update({
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'flags': PacketNormalizer._parse_tcp_flags(tcp.flags),
                'protocol_name': 'TCP'
            })
            result['layers'].append('TCP')
            result['protocols'].append('TCP')
            layer4_processed = True

        elif UDP in packet:
            udp = packet[UDP]
            payload = bytes(udp.payload)
            result.update({
                'src_port': udp.sport,
                'dst_port': udp.dport,
                'udp_length': udp.len,
                'protocol_name': 'UDP'
            })
            result['layers'].append('UDP')
            result['protocols'].append('UDP')
            layer4_processed = True

        elif ICMP in packet:
            icmp = packet[ICMP]
            payload = bytes(icmp.payload)
            result.update({
                'icmp_type': icmp.type,
                'icmp_code': icmp.code,
                'protocol_name': 'ICMP'
            })
            result['layers'].append('ICMP')
            result['protocols'].append('ICMP')
            layer4_processed = True

        if layer4_processed:
            result['payload_size'] = len(payload)
        elif result.get('protocol'):
            proto_num = result['protocol']
            try:
                import socket
                result['protocol_name'] = socket.getprotobynumber(proto_num).upper()
            except OSError:
                common_protos = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF', 132: 'SCTP'}
                result['protocol_name'] = common_protos.get(proto_num, f'Proto{proto_num}')

            try:
                if IP in packet: result['payload_size'] = len(packet[IP].payload)
                elif IPv6 in packet: result['payload_size'] = len(packet[IPv6].payload)
                logger.debug(f"Protocolo L4 não dissecado ({result['protocol_name']}). Payload size calculado a partir da camada IP.")
            except Exception as e:
                logger.warning(f"Não foi possível calcular payload size para protocolo {result['protocol_name']}: {e}")
                result['payload_size'] = 0
            layer4_processed = True # Considera processado se tinha IP

        return layer4_processed


    @staticmethod
    def _validate_ip(ip_str: Optional[str]) -> Optional[str]:
        """Valida se a string é um IP válido (v4 ou v6) e retorna a forma canônica."""
        if not ip_str or not isinstance(ip_str, str):
            return None
        try:
            return str(ipaddress.ip_address(ip_str))
        except ValueError:
            return None


    @staticmethod
    def _parse_tcp_flags(flags: Any) -> Dict[str, int]:
        """
        Decodifica flags TCP (pode ser int ou objeto Flags do Scapy)
        para um dicionário com nomes padrão e valores 0 ou 1.
        """
        flag_keys = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        parsed_flags = {key: 0 for key in flag_keys}

        if isinstance(flags, int):
            if flags & 0x01: parsed_flags['FIN'] = 1
            if flags & 0x02: parsed_flags['SYN'] = 1
            if flags & 0x04: parsed_flags['RST'] = 1
            if flags & 0x08: parsed_flags['PSH'] = 1
            if flags & 0x10: parsed_flags['ACK'] = 1
            if flags & 0x20: parsed_flags['URG'] = 1
            if flags & 0x40: parsed_flags['ECE'] = 1
            if flags & 0x80: parsed_flags['CWR'] = 1
        elif hasattr(flags, 'flagrepr'):
            scapy_flag_map = {
                'F': 'FIN', 'S': 'SYN', 'R': 'RST',
                'P': 'PSH', 'A': 'ACK', 'U': 'URG',
                'E': 'ECE', 'C': 'CWR'
            }
            flag_str = flags.flagrepr()
            for scapy_flag_char in flag_str:
                flag_name = scapy_flag_map.get(scapy_flag_char)
                if flag_name:
                    parsed_flags[flag_name] = 1
        return parsed_flags


    @staticmethod
    def _extract_features(packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extrai features adicionais do dicionário normalizado, prontas para ML.
        Retorna um dicionário contendo apenas as features extras.
        """
        features = {}
        protocol_name = packet_data.get('protocol_name')
        dst_port = packet_data.get('dst_port', 0)
        src_port = packet_data.get('src_port', 0)

        features['is_tcp'] = 1 if protocol_name == 'TCP' else 0
        features['is_udp'] = 1 if protocol_name == 'UDP' else 0
        features['is_icmp'] = 1 if protocol_name == 'ICMP' else 0

        tcp_flags = packet_data.get('tcp_flags', {})
        features['flag_syn'] = tcp_flags.get('SYN', 0)
        features['flag_ack'] = tcp_flags.get('ACK', 0)
        features['flag_fin'] = tcp_flags.get('FIN', 0)
        features['flag_rst'] = tcp_flags.get('RST', 0)
        features['flag_psh'] = tcp_flags.get('PSH', 0)
        features['flag_urg'] = tcp_flags.get('URG', 0)
        features['flag_ece'] = tcp_flags.get('ECE', 0)
        features['flag_cwr'] = tcp_flags.get('CWR', 0)

        features['port_src_well_known'] = 1 if 0 < src_port < 1024 else 0
        features['port_dst_well_known'] = 1 if 0 < dst_port < 1024 else 0
        features['port_dst_is_dns'] = 1 if dst_port == 53 else 0
        features['port_dst_is_ntp'] = 1 if dst_port == 123 else 0
        features['port_dst_is_http'] = 1 if dst_port == 80 else 0
        features['port_dst_is_https'] = 1 if dst_port == 443 else 0

        features['udp_length'] = packet_data.get('udp_length', 0)
        features['payload_size'] = packet_data.get('payload_size', 0)

        features['same_network'] = PacketNormalizer._safe_ip_network(
            packet_data.get('src_ip'), packet_data.get('dst_ip')
        )

        features['is_private'] = 1 if PacketNormalizer._is_private_check(packet_data.get('src_ip')) or \
                                       PacketNormalizer._is_private_check(packet_data.get('dst_ip')) else 0
        return features

    @staticmethod
    def _safe_ip_network(ip1_str: Optional[str], ip2_str: Optional[str]) -> int:
        """Verifica se dois IPs (strings) estão na mesma sub-rede (IPv4:/24, IPv6:/64)."""
        if not ip1_str or not ip2_str: return 0
        try:
            ip1 = ipaddress.ip_address(ip1_str)
            ip2 = ipaddress.ip_address(ip2_str)
            if ip1.version != ip2.version: return 0
            if ip1.version == 4:
                net1 = ipaddress.ip_network(f"{ip1_str}/24", strict=False)
                return 1 if ip2 in net1 else 0
            elif ip1.version == 6:
                 net1 = ipaddress.ip_network(f"{ip1_str}/64", strict=False)
                 return 1 if ip2 in net1 else 0
            else: return 0
        except ValueError: return 0
        except Exception as e:
            logger.warning(f"Erro inesperado em _safe_ip_network: {e}")
            return 0

    @staticmethod
    def _is_private_check(ip_str: Optional[str]) -> bool:
         """Verifica se um IP (string) pertence a um range privado, loopback ou link-local."""
         if not ip_str: return False
         try:
             ip = ipaddress.ip_address(ip_str)
             return ip.is_private or ip.is_loopback or ip.is_link_local
         except ValueError: return False

# Bloco de teste mantido para verificações rápidas e isoladas
if __name__ == '__main__':
    # Configuração de logging básica para teste direto do script
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.info("Executando teste direto do PacketNormalizer...")

    # Criar pacotes de teste Scapy
    udp_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF")/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=12345, dport=53)/("test payload udp")
    tcp_packet = Ether()/IP(src="10.0.0.5", dst="1.1.1.1")/TCP(sport=54321, dport=80, flags="S") # SYN
    tcp_data_packet = Ether()/IP(src="192.168.3.37", dst="192.168.3.4")/TCP(sport=22, dport=56426, flags="PA")/("ssh data"*100) # PSH+ACK
    icmp_packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.100")/ICMP(type=8, code=0)
    ipv6_udp_packet = Ether()/IPv6(src="fe80::1", dst="ff02::1")/UDP(dport=5353)/("ipv6 mdns test") # Link-local, Multicast, mDNS
    gre_packet = Ether()/IP(src="172.16.0.1", dst="172.16.0.2", proto=47)/("gre data") # Protocolo 47 (GRE)
    broadcast_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="192.168.1.50", dst="255.255.255.255")/UDP(sport=138, dport=138)/("netbios broadcast") # NetBIOS broadcast
    ssdp_packet = Ether()/IP(src="192.168.1.60", dst="239.255.255.250")/UDP(sport=1900, dport=1900)/("ssdp discover") # SSDP Multicast

    packets_to_test = [
        udp_packet, tcp_packet, tcp_data_packet, icmp_packet,
        ipv6_udp_packet, gre_packet, broadcast_packet, ssdp_packet
    ]

    print("\n--- Testando Normalizador com Filtros ---")
    results = []
    for i, pkt in enumerate(packets_to_test):
        print(f"\n--- Processando Pacote {i+1}: {pkt.summary()} ---")
        normalized_data = PacketNormalizer.normalize(pkt)
        if normalized_data:
            print("   Pacote NORMALIZADO e NÃO FILTRADO:")
            import pprint
            pprint.pprint(normalized_data)
            results.append(normalized_data)
        else:
            print("   Pacote DESCARTADO pela normalização ou filtros.")
    print(f"\n--- Fim dos Testes: {len(results)} pacotes passaram ---")