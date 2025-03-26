import logging
import json
import signal
import pika
import joblib
import mysql.connector  # Biblioteca para conexão com MariaDB
import subprocess  # Para executar comandos do sistema (iptables)
from sklearn.ensemble import IsolationForest  # Exemplo de modelo
import os

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurações do RabbitMQ e do modelo
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
RABBITMQ_PORT = int(os.getenv('RABBITMQ_PORT', 5672))
RABBITMQ_QUEUE = os.getenv('RABBITMQ_QUEUE', 'pacotes')
ALERT_QUEUE = os.getenv('ALERT_QUEUE', 'alertas')
MODEL_PATH = os.getenv('MODEL_PATH', 'modelo_ml.joblib')
ANOMALY_THRESHOLD = float(os.getenv('ANOMALY_THRESHOLD', -0.1))

# Configurações do MariaDB
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = int(os.getenv('DB_PORT', 3306))
DB_NAME = os.getenv('DB_NAME', 'ids_db')
DB_USER = os.getenv('DB_USER', 'ids_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'password')


class MLService:
    def __init__(self):
        self.model = None
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None
        self.db_connection = None
        self.running = True

    def load_model(self):
        """Carrega o modelo de ML treinado a partir do arquivo."""
        try:
            self.model = joblib.load(MODEL_PATH)
            logger.info(f"Modelo carregado com sucesso de {MODEL_PATH}")
        except Exception as e:
            logger.error(f"Erro ao carregar modelo: {e}", exc_info=True)
            raise

    def connect_to_rabbitmq(self):
        """Conecta ao RabbitMQ."""
        try:
            self.rabbitmq_connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
            )
            self.rabbitmq_channel = self.rabbitmq_connection.channel()
            self.rabbitmq_channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
            self.rabbitmq_channel.queue_declare(queue=ALERT_QUEUE, durable=True)
            logger.info(f"Conectado ao RabbitMQ em {RABBITMQ_HOST}:{RABBITMQ_PORT}")
        except Exception as e:
            logger.error(f"Erro ao conectar ao RabbitMQ: {e}", exc_info=True)
            raise

    def connect_to_database(self):
        """Conecta ao banco de dados MariaDB."""
        try:
            self.db_connection = mysql.connector.connect(
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD
            )
            logger.info("Conectado ao banco de dados MariaDB com sucesso.")
        except mysql.connector.Error as e:
            logger.error(f"Erro ao conectar ao banco de dados MariaDB: {e}", exc_info=True)
            raise

    def validate_data(self, data):
        """Valida se os dados recebidos possuem todas as features necessárias."""
        required_features = [
            'is_tcp', 'is_udp', 'is_icmp', 'flag_syn', 'flag_ack', 'flag_fin',
            'port_src_well_known', 'port_dst_well_known', 'same_network', 'src_ip'
        ]
        for feature in required_features:
            if feature not in data:
                raise ValueError(f"Feature ausente nos dados recebidos: {feature}")

    def process_message(self, ch, method, properties, body):
        """Processa uma mensagem recebida do RabbitMQ."""
        try:
            data = json.loads(body)
            logger.debug(f"Mensagem recebida: {data}")

            # Validação dos dados
            self.validate_data(data)

            # Preparar os dados para o modelo
            features = [
                data['is_tcp'], data['is_udp'], data['is_icmp'], data['flag_syn'],
                data['flag_ack'], data['flag_fin'], data['port_src_well_known'],
                data['port_dst_well_known'], data['same_network']
            ]

            # Fazer a predição
            prediction = self.model.predict([features])[0]
            score = self.model.decision_function([features])[0]

            logger.info(f"Predição: {prediction}, Score: {score}")

            # Ações com base na predição
            if score < ANOMALY_THRESHOLD:
                logger.warning(f"Anomalia detectada! Score: {score}, Dados: {data}")
                self.handle_anomaly(data, score)

            ch.basic_ack(delivery_tag=method.delivery_tag)

        except json.JSONDecodeError:
            logger.error(f"Erro ao decodificar JSON: {body}", exc_info=True)
            ch.basic_nack(delivery_tag=method.delivery_tag)
        except ValueError as e:
            logger.error(f"Erro de validação dos dados: {e}", exc_info=True)
            ch.basic_nack(delivery_tag=method.delivery_tag)
        except Exception as e:
            logger.error(f"Erro ao processar mensagem: {e}", exc_info=True)
            ch.basic_nack(delivery_tag=method.delivery_tag)

    def handle_anomaly(self, data, score):
        """Lida com anomalias detectadas."""
        ip_address = data.get('src_ip')  # Supondo que o IP de origem esteja nos dados
        reason = f"Anomalia detectada com score {score}"

        # Salvar no banco de dados
        try:
            cursor = self.db_connection.cursor()
            cursor.execute(
                "INSERT INTO anomalies (score, data, timestamp) VALUES (%s, %s, NOW())",
                (score, json.dumps(data))
            )
            self.db_connection.commit()
            cursor.close()
            logger.info("Anomalia salva no banco de dados.")
        except mysql.connector.Error as e:
            logger.error(f"Erro ao salvar anomalia no banco de dados: {e}", exc_info=True)

        # Enviar alerta em tempo real
        try:
            self.rabbitmq_channel.basic_publish(
                exchange='',
                routing_key=ALERT_QUEUE,
                body=json.dumps({'score': score, 'data': data}),
                properties=pika.BasicProperties(delivery_mode=2)  # Persistente
            )
            logger.info("Alerta enviado para a fila de mensagens.")
        except Exception as e:
            logger.error(f"Erro ao enviar alerta para a fila de mensagens: {e}", exc_info=True)

        # Bloquear o IP se necessário
        if ip_address:
            try:
                self.block_ip(ip_address)
                self.log_blocked_ip(ip_address, reason)
            except Exception as e:
                logger.error(f"Erro ao bloquear o IP {ip_address}: {e}", exc_info=True)

    def block_ip(self, ip_address):
        """Bloqueia um endereço IP usando iptables."""
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            logger.info(f"Endereço IP {ip_address} bloqueado com sucesso.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Erro ao bloquear o IP {ip_address}: {e}")

    def log_blocked_ip(self, ip_address, reason):
        """Registra o bloqueio de um IP no banco de dados."""
        try:
            cursor = self.db_connection.cursor()
            cursor.execute(
                "INSERT INTO blocked_ips (ip_address, reason, timestamp) VALUES (%s, %s, NOW())",
                (ip_address, reason)
            )
            self.db_connection.commit()
            cursor.close()
            logger.info(f"Endereço IP {ip_address} registrado como bloqueado no banco de dados.")
        except mysql.connector.Error as e:
            logger.error(f"Erro ao registrar IP bloqueado no banco de dados: {e}", exc_info=True)

    def start_consuming(self):
        """Inicia o consumo de mensagens do RabbitMQ."""
        self.rabbitmq_channel.basic_qos(prefetch_count=1)
        self.rabbitmq_channel.basic_consume(queue=RABBITMQ_QUEUE, on_message_callback=self.process_message)

        logger.info("Aguardando mensagens...")
        while self.running:
            try:
                self.rabbitmq_channel.start_consuming()
            except Exception as e:
                logger.error(f"Erro no consumo de mensagens: {e}", exc_info=True)
                self.running = False

    def stop(self, signum, frame):
        """Encerra o serviço de forma limpa."""
        logger.info("Sinal de encerramento recebido. Encerrando...")
        self.running = False
        if self.rabbitmq_channel:
            self.rabbitmq_channel.stop_consuming()
        if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
            self.rabbitmq_connection.close()
        if self.db_connection:
            self.db_connection.close()

    def run(self):
        """Método principal para executar o serviço."""
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        self.load_model()
        self.connect_to_rabbitmq()
        self.connect_to_database()
        self.start_consuming()


if __name__ == "__main__":
    ml_service = MLService()
    ml_service.run()