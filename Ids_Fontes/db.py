import mariadb
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class DatabaseManager:

    def get_database_manager():
        from main import IDSController  # Importar aqui, dentro de uma função, evita o ciclo
        return DatabaseManager()

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.connection = None
        self._connect()
        
    def _connect(self) -> None:
        """Estabelece conexão com o banco de dados"""
        try:
            # Verifique as configurações antes de tentar a conexão
            logger.debug(f"Tentando conectar ao banco de dados {self.config['database']} na host {self.config['host']}:{self.config['port']}")

            # Conectar ao banco de dados sem a configuração ssl (removido por simplicidade)
            self.connection = mariadb.connect(
                host=self.config['host'],
                port=self.config['port'],
                user=self.config['user'],
                password=self.config['password'],
                database=self.config['database'],
                autocommit=True  # Removido autocommit=False para simplificar
            )
            logger.info("Conexão com o banco estabelecida com sucesso!")
        except mariadb.Error as e:
            logger.error(f"Erro ao conectar ao banco de dados: {e}")
            raise

    def initialize_schema(self) -> None:
        """Cria a tabela de pacotes"""
        create_table_sql = '''
            CREATE TABLE IF NOT EXISTS packets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                src_ip VARCHAR(45) NOT NULL,
                dest_ip VARCHAR(45) NOT NULL,
                protocol VARCHAR(10) NOT NULL,
                length INT NOT NULL,
                flags VARCHAR(20),
                port_src INT,
                port_dest INT,
                is_tcp BOOLEAN,
                is_udp BOOLEAN,
                flag_syn BOOLEAN,
                flag_ack BOOLEAN,
                flag_fin BOOLEAN,
                payload_size INT
            ) ENGINE=InnoDB
        '''
        
        try:
            if not self.connection:
                logger.error("Não há conexão com o banco de dados.")
                return
            
            with self.connection.cursor() as cursor:
                cursor.execute(create_table_sql)
                logger.info("Tabela 'packets' verificada/criada com sucesso.")
        except mariadb.Error as e:
            logger.error(f"Erro ao criar/verificar a tabela: {e}")
            self.connection.rollback()
            raise

    def bulk_insert_packets(self, packets: List[Dict[str, Any]]) -> None:
        """Insere múltiplos pacotes de forma otimizada"""
        columns = [
            'timestamp', 'src_ip', 'dest_ip', 'protocol',
            'length', 'flags', 'port_src', 'port_dest',
            'is_tcp', 'is_udp', 'flag_syn', 'flag_ack',
            'flag_fin', 'payload_size'
        ]
        
        placeholders = ', '.join(['%s'] * len(columns))
        stmt = f"""
            INSERT INTO packets (
                {', '.join(columns)}
            ) VALUES ({placeholders})
        """

        try:
            if not self.connection:
                logger.error("Não há conexão com o banco de dados.")
                return
            
            with self.connection.cursor() as cursor:
                # Converter dicionários para lista ordenada de valores
                values = [
                    [packet.get(col) for col in columns]
                    for packet in packets
                ]
                
                cursor.executemany(stmt, values)
                logger.info(f"{len(packets)} pacotes inseridos com sucesso.")
        except mariadb.Error as e:
            logger.error(f"Erro ao inserir pacotes: {e}")
            self.connection.rollback()
            raise

    def __del__(self):
        """Fecha a conexão de maneira segura"""
        try:
            # Verifica se a conexão existe e se está válida
            if hasattr(self, 'connection') and self.connection:
                if self.connection._socket:  # Verifica se o socket ainda está ativo
                    self.connection.close()
                    logger.info("Conexão com o banco fechada com sucesso.")
                else:
                    logger.warning("Conexão com o banco já está fechada.")
        except mariadb.ProgrammingError as e:
            logger.warning(f"Erro ao fechar conexão: {str(e)}")
        except Exception as e:
            logger.warning(f"Erro inesperado ao tentar fechar conexão: {str(e)}")
