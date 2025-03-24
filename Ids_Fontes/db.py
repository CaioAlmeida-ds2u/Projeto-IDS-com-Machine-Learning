import mariadb
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class DatabaseManager:

    def __init__(self, host="localhost", port=3306, user="ids_user", password="fatec123", database="ids_db"):
        """
        Inicializa o DatabaseManager com as credenciais do banco de dados.

        Args:
            host (str): Endereço do servidor do banco de dados.
            port (int): Porta do banco de dados.
            user (str): Nome de usuário do banco de dados.
            password (str): Senha do usuário do banco de dados.
            database (str): Nome do banco de dados.
        """
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.connection = None
        self.cursor = None  # Adicionado cursor como atributo
        self._connect()

    def _connect(self) -> None:
        """Estabelece conexão com o banco de dados."""
        try:
            self.connection = mariadb.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                autocommit=False  # Melhor controle de transações
            )
            self.cursor = self.connection.cursor()  # Cria o cursor
            logger.info(f"Conectado ao MariaDB em {self.host}:{self.port}, banco de dados: {self.database}")
        except mariadb.Error as e:
            logger.error(f"Erro ao conectar ao MariaDB: {e}", exc_info=True)
            raise  # Importante: re-lança a exceção para que o serviço não inicie se a conexão falhar


    def initialize_schema(self) -> None:
        """Cria a tabela de pacotes (se ela não existir)."""

        # Adicionei src_mac e dst_mac, e separei os campos de data e hora.
        create_table_sql = '''
            CREATE TABLE IF NOT EXISTS packets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                packet_date DATE NOT NULL,
                packet_time TIME NOT NULL,
                src_ip VARCHAR(45) NOT NULL,
                dst_ip VARCHAR(45) NOT NULL,
                src_mac VARCHAR(17) NULL,  -- Adicionado
                dst_mac VARCHAR(17) NULL,  -- Adicionado
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
                score FLOAT,  -- Adicionado:  Score de anomalia
                raw_packet JSON NULL  -- Adicionado: Armazena o pacote bruto em JSON (opcional)
            ) ENGINE=InnoDB;
        '''

        try:
            if not self.connection or not self.cursor: #Verifica se a conexão e o cursor foram criados.
                raise mariadb.Error("Conexão com o banco de dados não estabelecida.")
            self.cursor.execute(create_table_sql)
            self.connection.commit()  # Commit para DDL (CREATE TABLE)
            logger.info("Tabela 'packets' verificada/criada com sucesso.")
        except mariadb.Error as e:
            logger.error(f"Erro ao criar/verificar a tabela: {e}", exc_info=True)
            if self.connection: # Faz o rollback somente se a conexão existir.
                self.connection.rollback()
            raise

    def insert_packet(self, packet_data: Dict[str, Any]) -> None:
        """Insere um único pacote no banco de dados.

        Args:
            packet_data (Dict[str, Any]): Um dicionário contendo os dados do pacote.
        """

        # Adaptação para o novo formato e a nova tabela:
        columns = [
            'packet_date', 'packet_time', 'src_ip', 'dst_ip', 'src_mac', 'dst_mac',
            'protocol', 'src_port', 'dst_port', 'ip_version', 'ttl',
            'is_tcp', 'is_udp', 'is_icmp', 'flag_syn', 'flag_ack', 'flag_fin',
            'same_network', 'score', 'raw_packet'  # Inclui o score e o raw_packet
        ]
        placeholders = ', '.join(['%s'] * len(columns))
        sql = f"INSERT INTO packets ({', '.join(columns)}) VALUES ({placeholders})"

        # Extrai a data e hora do timestamp
        try:
            packet_datetime = datetime.fromisoformat(packet_data['timestamp'])
            packet_date = packet_datetime.date()
            packet_time = packet_datetime.time()
        except (ValueError, KeyError) as e:
            logger.error(f"Erro ao extrair data/hora: {e}, Dados: {packet_data}. Usando data/hora atual.")
            now = datetime.now()
            packet_date = now.date()
            packet_time = now.time()

        # Prepara os valores para inserção
        values = [
            packet_date,
            packet_time,
            packet_data.get('src_ip'),
            packet_data.get('dst_ip'),
            packet_data.get('src_mac'),
            packet_data.get('dst_mac'),
            packet_data.get('protocol'),
            packet_data.get('src_port', 0),  # Valor padrão 0 se a porta não estiver presente
            packet_data.get('dst_port', 0),  # Valor padrão 0 se a porta não estiver presente
            packet_data.get('ip_version', 4),  # Valor padrão 4
            packet_data.get('ttl', 0),          # Valor padrão 0
            packet_data.get('is_tcp', 0),      # Valor padrão 0
            packet_data.get('is_udp', 0),      # Valor padrão 0
            packet_data.get('is_icmp', 0),    # Valor padrão 0
            packet_data.get('flag_syn', 0),     # Valor padrão 0
            packet_data.get('flag_ack', 0),     # Valor padrão 0
            packet_data.get('flag_fin', 0),     # Valor padrão 0
            packet_data.get('same_network', 0),# Valor padrão 0
            packet_data.get('score', 0.0),      # Valor padrão 0.0, você deve passar o score real
            json.dumps(packet_data)  # Armazena o pacote bruto como JSON (opcional, mas recomendado)

        ]

        try:
            if not self.connection or not self.cursor:
                raise mariadb.Error("Conexão com o banco de dados não estabelecida.")
            self.cursor.execute(sql, values)
            self.connection.commit() # Commit para DML (INSERT)
            logger.debug(f"Pacote inserido no banco de dados: {packet_data.get('src_ip')} -> {packet_data.get('dst_ip')}")

        except mariadb.Error as e:
            logger.error(f"Erro ao inserir pacote no banco de dados: {e}", exc_info=True)
            if self.connection:
                self.connection.rollback()
            # Não re-lança a exceção aqui, pois queremos continuar processando outras mensagens.
            # Mas você *deve* tratar o erro de alguma forma (registrar, alerta, etc.)


    def close(self):
        """Fecha a conexão com o banco de dados."""
        try:
            if self.cursor:
                self.cursor.close()
            if self.connection and self.connection.is_connected():
                self.connection.close()
            logger.info("Conexão com o MariaDB fechada.")
        except Exception as e:
            logger.error(f"Erro ao fechar conexão com MariaDB: {e}", exc_info=True)


    def __del__(self):
        """Garante que a conexão seja fechada quando o objeto for destruído."""
        self.close()