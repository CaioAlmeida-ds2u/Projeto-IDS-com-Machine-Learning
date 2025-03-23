#!/usr/bin/env python3
# --- Imports ---
import scapy.all as scapy
import time
import signal
import os
import json
import threading
import mariadb
import ipaddress
from datetime import datetime
from filelock import FileLock, Timeout
from logging.handlers import RotatingFileHandler
import logging
from typing import Optional, Dict, Any

# --- Configuração de Log ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            'logs/ids.log',
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Constantes ---
CONFIG_FILE = "config.json"
PID_FILE = "ids_pid.txt"
LOCK_TIMEOUT = 5  # segundos

class IDSController:
    def __init__(self):
        self._load_config()
        self.running = True
        self.capturing = False
        self.buffer = []
        self.buffer_lock = threading.Lock()
        self.last_write = time.time()
        self.db_conn = self._connect_to_db()
        self._init_db()
        self.capture_thread = None

    def _load_config(self):
        """Carrega e valida o arquivo de configuração"""
        try:
            with open(CONFIG_FILE) as f:
                self.config = json.load(f)

            # Configurações padrão
            self.config.setdefault('database', {})
            self.config.setdefault('settings', {})
            self.config.setdefault('rules', {})

            # Database - Valores padrão e VERIFICAÇÃO DE SENHA
            db_config = self.config['database']
            db_config.setdefault('host', 'localhost')
            db_config.setdefault('port', 3306)
            db_config.setdefault('user', 'ids_user')
            db_config.setdefault('ssl', False)
            db_config.setdefault('database', 'ids_db')
            if 'password' not in db_config:
                logger.error("Erro: A senha do banco de dados não está definida em config.json!")
                exit(1)  # Encerra se não tiver senha

            # Settings - Valores padrão
            self.config['settings'].setdefault('interface', 'enp0s3')
            self.config['settings'].setdefault('buffer_size', 100)
            self.config['settings'].setdefault('write_interval', 5)
            self.config['settings'].setdefault('packet_timeout', 10)
            self.config['settings'].setdefault('log_level', 'INFO')

            # Rules
            self.config['rules'].setdefault('detect_port_scan', True)
            self.config['rules'].setdefault('detect_ddos', False)  # Sugestão
            self.config['rules'].setdefault('whitelist', [])

        except Exception as e:
            logger.error(f"Erro fatal ao carregar configurações: {e}")
            exit(1)

    def _connect_to_db(self):
        """Conecta ao MariaDB usando as configurações"""
        try:
            conn = mariadb.connect(
                host=self.config['database']['host'],
                port=self.config['database']['port'],
                user=self.config['database']['user'],
                password=self.config['database']['password'],
                database=self.config['database']['database'],
                ssl=self.config['database']['ssl'],
                autocommit=False
            )
            return conn
        except mariadb.Error as e:
            logger.error(f"Erro ao conectar ao MariaDB: {e}")
            exit(1)

    def _init_db(self):
        """Cria as tabelas se não existirem"""
        try:
            with self.db_conn.cursor() as cursor:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        timestamp DATETIME,
                        source_ip VARCHAR(255),
                        dest_ip VARCHAR(255),
                        protocol VARCHAR(255),
                        description TEXT
                    ) ENGINE=InnoDB
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS packets (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        timestamp DATETIME,
                        protocol VARCHAR(10),
                        src_ip VARCHAR(45),
                        src_port INT,
                        dest_ip VARCHAR(45),
                        dest_port INT,
                        tcp_flags VARCHAR(10),
                        ip_version INT,
                        ip_ihl INT,
                        ip_ttl INT,
                        packet_size INT,
                        payload_length INT,
                        feature_1 REAL,
                        feature_2 REAL
                    ) ENGINE=InnoDB
                ''')
            self.db_conn.commit()
        except mariadb.Error as e:
            logger.error(f"Erro ao criar tabelas: {e}")
            exit(1)


    def _process_packet(self, packet):
        """Processa cada pacote capturado, extraindo informações relevantes."""
        try:
            # --- Decodificação ---
            dest_mac, src_mac, eth_type = self.unpack_ethernet_header(packet)
    
            if eth_type == 0x0800:  # IPv4
                #Verifica se é IP
                if scapy.IP not in packet:
                    logger.debug("Pacote não IP recebido: %s", packet.summary())
                    return # Não processa
                version, ihl, tos, total_length, identification, flags_fragoffset, ttl, protocol, checksum, src_ip, dest_ip = self.unpack_ip_header(packet)
    
                if protocol == 6:  # TCP
                    if scapy.TCP not in packet:
                        logger.debug("Pacote TCP inválido recebido: %s", packet.summary())
                        return
                    src_port, dest_port, seq_number, ack_number, data_offset, tcp_flags, window_size, checksum, urgent_pointer = self.unpack_tcp_header(packet)
                    protocol_str = "TCP"
                elif protocol == 17:  # UDP
                    if scapy.UDP not in packet:
                      logger.debug("Pacote UDP inválido recebido: %s", packet.summary())
                      return
                    src_port, dest_port, length, checksum = self.unpack_udp_header(packet)
                    protocol_str = "UDP"
                    tcp_flags = ""  # UDP não tem flags
                elif protocol == 1:  # ICMP
                    #Verifica se é ICMP
                    if scapy.ICMP not in packet:
                      logger.debug("Pacote ICMP inválido recebido: %s", packet.summary())
                      return
                    src_port = 0  # ICMP não tem portas
                    dest_port = 0
                    protocol_str = "ICMP"
                    tcp_flags = ""
                else:
                    # Outro protocolo (não tratamos agora)
                    logger.debug(f"Pacote de protocolo desconhecido ({protocol}) recebido: {packet.summary()}")
                    return
    
                packet_size = len(packet)
                payload_length = total_length - (ihl * 4)
    
                # --- Cria um dicionário com os dados extraídos ---
                packet_data = {
                    'timestamp': datetime.now().isoformat(),
                    'protocol': protocol_str,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'tcp_flags': tcp_flags,
                    'ip_version': version,
                    'ip_ihl': ihl,
                    'ip_ttl': ttl,
                    'packet_size' : packet_size,
                    'payload_length': payload_length,
                    # Adicione outras features aqui
                }
    
                # --- Verificação de Assinaturas (após a decodificação) ---
                self._check_signatures(packet_data)  # Passa o dicionário, não o pacote IP
    
                # --- Adicionar ao Buffer ---
                with self.buffer_lock:
                    # self.buffer.append(packet_data) #Adiciona o dicionario
                    #Transforma em tupla
                    self.buffer.append(tuple(packet_data.values()))
    
                    if (len(self.buffer) >= self.config['settings']['buffer_size'] or
                            (time.time() - self.last_write) > self.config['settings']['write_interval']):
                        self._write_to_db()
                        self.last_write = time.time()
    
            else: #Caso não seja IPv4
              logger.debug(f"Pacote não IPv4 ({hex(eth_type)}) recebido: {packet.summary()}")
              return #Ignora
    
        except Exception as e:
            logger.error(f"Erro ao processar pacote: {e}")

    def _check_signatures(self, packet_data):
        """Verifica assinaturas de ataques básicos"""
        # Exemplo: Detecção de port scan
        if packet_data['protocol'] == "TCP":
            if packet_data['tcp_flags'] == 'SYN' and self.config['rules']['detect_port_scan']:
                self._log_alert(
                    source_ip=packet_data['src_ip'],
                    dest_ip=packet_data['dest_ip'],
                    protocol="TCP",
                    description="Possível port scan detectado"
                )

    def _log_alert(self, **kwargs):
        """Registra alerta no banco de dados"""
        try:
            with self.db_conn:  # Garante commit/rollback
                with self.db_conn.cursor() as cursor:
                    cursor.execute('''
                        INSERT INTO alerts (timestamp, source_ip, dest_ip, protocol, description)
                        VALUES (%s, %s, %s, %s, %s)
                    ''', (
                        datetime.now().isoformat(),
                        kwargs.get('source_ip'),
                        kwargs.get('dest_ip'),
                        kwargs.get('protocol'),
                        kwargs.get('description')
                    ))
            logger.warning(f"Alerta: {kwargs.get('description')}")
        except mariadb.Error as e:
            logger.error(f"Erro ao registrar alerta: {e}")

    def _write_to_db(self):
        """Escreve os dados dos pacotes no banco de dados (MariaDB)."""
        if not self.buffer:
            return

        with self.buffer_lock:
            buffer_copy = self.buffer[:]
            self.buffer.clear()

        try:
            with self.db_conn:  # Garante commit/rollback
                with self.db_conn.cursor() as cursor:
                    stmt = '''
                        INSERT INTO packets (timestamp, protocol, src_ip, src_port, dest_ip, dest_port, tcp_flags, ip_version, ip_ihl, ip_ttl, packet_size, payload_length)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    '''  # Todas as colunas
                    cursor.executemany(stmt, buffer_copy)
            logger.debug(f"Escritos {len(buffer_copy)} pacotes no banco")

        except mariadb.Error as e:
            logger.error(f"Erro ao escrever no banco: {e}")
            self.db_conn.rollback()
            with self.buffer_lock:
                self.buffer.extend(buffer_copy) #Reinsere

    def unpack_ethernet_header(self, packet):
        eth_header = packet[:14]
        eth_data = struct.unpack("!6s6sH", eth_header)  # ! para network byte order
        dest_mac = ':'.join('%02x' % b for b in eth_data[0])
        src_mac = ':'.join('%02x' % b for b in eth_data[1])
        eth_type = socket.ntohs(eth_data[2])  # Converter para ordem do host
        return dest_mac, src_mac, eth_type

    def unpack_ip_header(self, packet):
        ip_header = packet[14:34]  # IPv4 (minimo 20 bytes)
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4  # Versão (4 bits)
        ihl = version_ihl & 0xF  # IHL (4 bits)
        tos = iph[1]
        total_length = iph[2]
        identification = iph[3]
        flags_fragoffset = iph[4]
        ttl = iph[5]
        protocol = iph[6]
        checksum = iph[7]
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])
        return version, ihl, tos, total_length, identification, flags_fragoffset, ttl, protocol, checksum, src_ip, dest_ip

    def unpack_tcp_header(self, packet):
        tcp_header = packet[34:54]  # Tamanho mínimo do cabeçalho TCP (20 bytes)
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)
        src_port = tcph[0]
        dest_port = tcph[1]
        seq_number = tcph[2]
        ack_number = tcph[3]
        data_offset_reserved = tcph[4]
        data_offset = (data_offset_reserved >> 4) * 4  # Tamanho do cabeçalho em palavras de 4 bytes
        flags = tcph[5]
        fin = (flags & 1) != 0
        syn = (flags & 2) != 0
        rst = (flags & 4) != 0
        psh = (flags & 8) != 0
        ack = (flags & 16) != 0
        urg = (flags & 32) != 0
        window_size = tcph[6]
        checksum = tcph[7]
        urgent_pointer = tcph[8]

        # Cria uma string representando as flags
        flag_str = ""
        if fin:
            flag_str += "FIN "
        if syn:
            flag_str += "SYN "
        if rst:
            flag_str += "RST "
        if psh:
            flag_str += "PSH "
        if ack:
            flag_str += "ACK "
        if urg:
            flag_str += "URG "

        return src_port, dest_port, seq_number, ack_number, data_offset, flag_str.strip(), window_size, checksum, urgent_pointer

    def unpack_udp_header(self, packet):
        udp_header = packet[34:42]  # Tamanho do cabeçalho UDP (8 bytes)
        udph = struct.unpack("!HHHH", udp_header)
        src_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]
        return src_port, dest_port, length, checksum

    def _get_current_command(self):
        """Obtém o comando atual do arquivo de configuração"""
        try:
            with FileLock(f"{CONFIG_FILE}.lock", timeout=LOCK_TIMEOUT):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                return config.get('command', '')  # Retorna '' se não houver comando
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Erro ao ler comando do config.json: {e}")
            return ''  # Retorna vazio em caso de erro
        except Timeout:
            logger.warning(f"Timeout ao obter lock do config.json. Tentando novamente...")
            return ''
        except Exception as e:
            logger.exception(f"Erro inesperado ao obter comando: {e}")  # Usa logger.exception
            return ''

    def _clear_command(self):
        """Limpa o comando no arquivo de configuração"""
        try:
            with FileLock(f"{CONFIG_FILE}.lock", timeout=LOCK_TIMEOUT):
                with open(CONFIG_FILE, 'r+') as f:  # Abre para leitura E escrita
                    config = json.load(f)
                    config['command'] = ''  # Limpa o comando
                    f.seek(0)  # Volta para o início do arquivo
                    json.dump(config, f, indent=4)  # Sobrescreve o arquivo
                    f.truncate()  # Remove qualquer conteúdo antigo que possa sobrar

        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Erro ao limpar comando do config.json: {e}")
        except Timeout:
            logger.warning(f"Timeout ao obter lock do config.json para limpeza.")
        except Exception as e:
            logger.exception(f"Erro inesperado ao limpar o comando: {e}")

    def _start_capture(self):
        """Inicia a captura de pacotes em thread separada"""
        self.running = True
        self.capturing = True

        def capture_thread():
            try:
                scapy.sniff(
                    prn=self._process_packet,
                    store=False,
                    iface=self.config['settings']['interface'],
                    stop_filter=lambda x: not self.running,
                    # timeout=self.config['settings']['packet_timeout'],  # Removido o timeout do sniff()
                    filter="ip"  # Filtro BPF para capturar apenas pacotes IP (otimização)
                )
            except Exception as e:
                logger.error(f"Erro na captura: {e}")
            finally:
                self.capturing = False
                self._write_to_db()  # Garante que os dados pendentes sejam gravados

        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()



    def _handle_command(self, command):
        """Processa os comandos recebidos"""
        if command == "start" and not self.capturing:
            logger.info("Iniciando captura de pacotes")
            self._start_capture()
            self._clear_command()
        elif command == "stop" and self.capturing:
            logger.info("Parando captura de pacotes")
            self.running = False  # Isso fará com que a thread de captura pare
            self.capturing = False
            self._clear_command()
        elif command == "status":
            logger.info(f"Status: {'Capturando' if self.capturing else 'Inativo'}")



    def run(self):
        """Loop principal de execução"""
        logger.info("Iniciando IDS, insira o comando start para iniciar a captura")

        # Registrar o PID
        try:
            with open(PID_FILE, 'w') as f:
                f.write(str(os.getpid()))
        except IOError as e:
            logger.error(f"Erro ao registrar PID: {e}")
            return

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        try:
            while True:  # Loop infinito (executa como um serviço)
                command = self._get_current_command()
                self._handle_command(command)
                time.sleep(1)  # Pequena pausa

        finally:
            self._cleanup()


    def _signal_handler(self, signum, frame):
        """Trata sinais de desligamento"""
        logger.info(f"Recebido sinal {signum}, encerrando...")
        self.running = False  # Isso sinaliza para a thread de captura parar


    def _cleanup(self):
        """Limpeza final"""
        try:
            os.remove(PID_FILE)
        except FileNotFoundError:
            pass
        finally:
            if self.db_conn:
                self.db_conn.close()
            logger.info("IDS encerrado corretamente")

if __name__ == "__main__":
    ids = IDSController()
    ids.run()