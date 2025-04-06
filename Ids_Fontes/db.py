# /home/admin/ids_project/db.py

import mariadb
import logging
import time
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from config import ConfigManager

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Gerencia o banco de dados para logging de pacotes e ações de firewall."""
    def __init__(self):
        """Inicializa o DatabaseManager com configurações dinâmicas."""
        self.config_manager = ConfigManager()
        self.connection: Optional[mariadb.connection] = None
        self.cursor: Optional[mariadb.cursor] = None
        self._load_config()
        self._connect_with_retry()

    def _load_config(self):
        """Carrega configurações do ConfigManager."""
        db_config = self.config_manager.get_config().get('database', {})
        self.host = db_config.get('host', 'localhost')
        self.port = int(db_config.get('port', 3306))
        self.user = db_config.get('user', 'ids_user')
        self.password = db_config.get('password', 'fatec123')  # Use env var em prod
        self.database = db_config.get('database', 'ids_db')
        logger.info(f"Configuração DB carregada: {self.host}:{self.port}/{self.database}")

    def _connect_with_retry(self, retries: int = 3, backoff: float = 2.0):
        """Conecta ao banco com retry."""
        for attempt in range(retries):
            try:
                self.connection = mariadb.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                    database=self.database,
                    autocommit=False
                )
                self.cursor = self.connection.cursor()
                logger.info(f"Conectado ao MariaDB: {self.host}:{self.port}/{self.database}")
                self.initialize_schema()
                return
            except mariadb.Error as e:
                logger.error(f"Tentativa {attempt+1}/{retries} falhou: {e}")
                if attempt < retries - 1:
                    time.sleep(backoff * (2 ** attempt))
        raise RuntimeError("Falha ao conectar ao MariaDB após retries")

    def _reconnect(self):
        """Reconecta ao banco em caso de falha."""
        logger.warning("Reconectando ao banco de dados...")
        self.close()
        self._connect_with_retry()

    def initialize_schema(self):
        """Cria as tabelas necessárias."""
        try:
            # Tabela de pacotes
            packets_sql = '''
                CREATE TABLE IF NOT EXISTS packets (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    packet_date DATE NOT NULL,
                    packet_time TIME NOT NULL,
                    src_ip VARCHAR(45) NOT NULL,
                    dst_ip VARCHAR(45) NOT NULL,
                    src_mac VARCHAR(17),
                    dst_mac VARCHAR(17),
                    protocol VARCHAR(10) NOT NULL,
                    src_port INT,
                    dst_port INT,
                    ip_version INT,
                    ttl INT,
                    is_tcp BOOLEAN,
                    is_udp BOOLEAN,
                    is_icmp BOOLEAN,
                    flag_syn BOOLEAN,
                    flag_ack BOOLEAN,
                    flag_fin BOOLEAN,
                    same_network BOOLEAN,
                    score FLOAT,
                    raw_packet JSON,
                    INDEX idx_src_ip (src_ip),
                    INDEX idx_dst_ip (dst_ip),
                    INDEX idx_packet_date (packet_date)
                ) ENGINE=InnoDB;
            '''
            # Tabela de ações de firewall
            firewall_sql = '''
                CREATE TABLE IF NOT EXISTS firewall_logs (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    action VARCHAR(20) NOT NULL,
                    ip_address VARCHAR(45) NOT NULL,
                    worker_id VARCHAR(50),
                    INDEX idx_ip_address (ip_address),
                    INDEX idx_timestamp (timestamp)
                ) ENGINE=InnoDB;
            '''
            for sql in [packets_sql, firewall_sql]:
                self.cursor.execute(sql)
            self.connection.commit()
            logger.info("Schemas verificados/criados: packets, firewall_logs")
        except mariadb.Error as e:
            logger.error(f"Erro ao inicializar schema: {e}", exc_info=True)
            self.connection.rollback()
            raise

    def insert_packet(self, packet_data: Dict[str, Any]):
        """Insere um único pacote no banco."""
        try:
            packet_datetime = datetime.fromisoformat(packet_data.get('timestamp', datetime.now().isoformat()))
            values = (
                packet_datetime.date(),
                packet_datetime.time(),
                packet_data.get('src_ip'),
                packet_data.get('dst_ip'),
                packet_data.get('src_mac'),
                packet_data.get('dst_mac'),
                packet_data.get('protocol', 'unknown'),
                packet_data.get('src_port', 0),
                packet_data.get('dst_port', 0),
                packet_data.get('ip_version', 4),
                packet_data.get('ttl', 0),
                bool(packet_data.get('is_tcp', 0)),
                bool(packet_data.get('is_udp', 0)),
                bool(packet_data.get('is_icmp', 0)),
                bool(packet_data.get('flag_syn', 0)),
                bool(packet_data.get('flag_ack', 0)),
                bool(packet_data.get('flag_fin', 0)),
                bool(packet_data.get('same_network', 0)),
                float(packet_data.get('score', 0.0)),
                json.dumps(packet_data)
            )
            sql = '''
                INSERT INTO packets (packet_date, packet_time, src_ip, dst_ip, src_mac, dst_mac, 
                    protocol, src_port, dst_port, ip_version, ttl, is_tcp, is_udp, is_icmp, 
                    flag_syn, flag_ack, flag_fin, same_network, score, raw_packet)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            '''
            self.cursor.execute(sql, values)
            self.connection.commit()
            logger.debug(f"Pacote inserido: {packet_data.get('src_ip')} -> {packet_data.get('dst_ip')}")
        except mariadb.Error as e:
            logger.error(f"Erro ao inserir pacote: {e}", exc_info=True)
            self.connection.rollback()
            self._reconnect()

    def insert_packets_batch(self, packets: List[Dict[str, Any]]):
        """Insere múltiplos pacotes em batch."""
        if not packets:
            return
        try:
            values_list = []
            for packet_data in packets:
                packet_datetime = datetime.fromisoformat(packet_data.get('timestamp', datetime.now().isoformat()))
                values = (
                    packet_datetime.date(),
                    packet_datetime.time(),
                    packet_data.get('src_ip'),
                    packet_data.get('dst_ip'),
                    packet_data.get('src_mac'),
                    packet_data.get('dst_mac'),
                    packet_data.get('protocol', 'unknown'),
                    packet_data.get('src_port', 0),
                    packet_data.get('dst_port', 0),
                    packet_data.get('ip_version', 4),
                    packet_data.get('ttl', 0),
                    bool(packet_data.get('is_tcp', 0)),
                    bool(packet_data.get('is_udp', 0)),
                    bool(packet_data.get('is_icmp', 0)),
                    bool(packet_data.get('flag_syn', 0)),
                    bool(packet_data.get('flag_ack', 0)),
                    bool(packet_data.get('flag_fin', 0)),
                    bool(packet_data.get('same_network', 0)),
                    float(packet_data.get('score', 0.0)),
                    json.dumps(packet_data)
                )
                values_list.append(values)
            sql = '''
                INSERT INTO packets (packet_date, packet_time, src_ip, dst_ip, src_mac, dst_mac, 
                    protocol, src_port, dst_port, ip_version, ttl, is_tcp, is_udp, is_icmp, 
                    flag_syn, flag_ack, flag_fin, same_network, score, raw_packet)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            '''
            self.cursor.executemany(sql, values_list)
            self.connection.commit()
            logger.debug(f"{len(packets)} pacotes inseridos em batch")
        except mariadb.Error as e:
            logger.error(f"Erro ao inserir batch: {e}", exc_info=True)
            self.connection.rollback()
            self._reconnect()

    def log_firewall_action(self, action: str, ip_address: str, worker_id: str = None):
        """Registra uma ação de firewall."""
        try:
            sql = '''
                INSERT INTO firewall_logs (timestamp, action, ip_address, worker_id)
                VALUES (%s, %s, %s, %s)
            '''
            values = (datetime.now(), action, ip_address, worker_id)
            self.cursor.execute(sql, values)
            self.connection.commit()
            logger.debug(f"Ação de firewall registrada: {action} para {ip_address}")
        except mariadb.Error as e:
            logger.error(f"Erro ao logar ação de firewall: {e}", exc_info=True)
            self.connection.rollback()
            self._reconnect()

    def get_recent_anomalies(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retorna os pacotes recentes com score de anomalia baixo."""
        try:
            sql = '''
                SELECT src_ip, dst_ip, protocol, src_port, dst_port, score, packet_date, packet_time
                FROM packets
                WHERE score < %s
                ORDER BY packet_date DESC, packet_time DESC
                LIMIT %s
            '''
            threshold = self.config_manager.get_ml_service_config().get('anomaly_threshold', -0.15)
            self.cursor.execute(sql, (threshold, limit))
            rows = self.cursor.fetchall()
            columns = ['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'score', 'packet_date', 'packet_time']
            return [dict(zip(columns, row)) for row in rows]
        except mariadb.Error as e:
            logger.error(f"Erro ao consultar anomalias: {e}", exc_info=True)
            self._reconnect()
            return []

    def close(self):
        """Fecha a conexão com o banco."""
        try:
            if self.cursor:
                self.cursor.close()
            if self.connection and self.connection.is_connected():
                self.connection.close()
            logger.info("Conexão com MariaDB fechada.")
        except Exception as e:
            logger.error(f"Erro ao fechar conexão: {e}", exc_info=True)
        finally:
            self.connection = None
            self.cursor = None

    def __del__(self):
        """Garante o fechamento da conexão."""
        self.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    db = DatabaseManager()
    try:
        # Exemplo de uso
        packet = {
            'timestamp': '2025-04-05T10:00:00',
            'src_ip': '192.168.1.1',
            'dst_ip': '10.0.0.1',
            'protocol': 'TCP',
            'src_port': 12345,
            'dst_port': 80,
            'score': -0.5
        }
        db.insert_packet(packet)
        db.log_firewall_action('block_applied', '192.168.1.1', 'worker_1')
        anomalies = db.get_recent_anomalies(5)
        print("Anomalias recentes:", anomalies)
    finally:
        db.close()