import logging
import json
import time
import pika  # Para comunicação com o RabbitMQ
import joblib  # Para carregar o modelo treinado (você pode usar pickle, se preferir)
# Importe outras bibliotecas necessárias (ex: para o banco de dados)
from sklearn.ensemble import IsolationForest  # Exemplo (se você usar Isolation Forest)


# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurações do RabbitMQ
RABBITMQ_HOST = 'localhost'  # Ou o IP do servidor RabbitMQ
RABBITMQ_PORT = 5672
RABBITMQ_QUEUE = 'pacotes'

# Caminho para o arquivo do modelo treinado
MODEL_PATH = 'modelo_ml.joblib'  # Altere para o caminho correto

# Limiar (threshold) para detecção de anomalias (ajuste conforme necessário)
ANOMALY_THRESHOLD = -0.1  # Exemplo (valores negativos indicam anomalia no Isolation Forest)

class MLService:
    def __init__(self):
        self.model = None  # O modelo de ML será carregado aqui
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None

    def load_model(self):
        """Carrega o modelo de ML treinado a partir do arquivo."""
        try:
            self.model = joblib.load(MODEL_PATH)
            logger.info(f"Modelo carregado com sucesso de {MODEL_PATH}")
        except Exception as e:
            logger.error(f"Erro ao carregar modelo: {e}", exc_info=True)
            # Trate o erro (pare o serviço, use um modelo padrão, etc.)
            raise  # Re-lança a exceção para parar o serviço se o modelo não carregar

    def connect_to_rabbitmq(self):
        """Conecta ao RabbitMQ."""
        try:
            self.rabbitmq_connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
            )
            self.rabbitmq_channel = self.rabbitmq_connection.channel()
            self.rabbitmq_channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
            logger.info(f"Conectado ao RabbitMQ em {RABBITMQ_HOST}:{RABBITMQ_PORT}, fila: {RABBITMQ_QUEUE}")
        except Exception as e:
            logger.error(f"Erro ao conectar ao RabbitMQ: {e}", exc_info=True)
            raise

    def process_message(self, ch, method, properties, body):
        """Processa uma mensagem recebida do RabbitMQ."""
        try:
            data = json.loads(body)  # Deserializa o JSON
            logger.debug(f"Mensagem recebida: {data}")

            # --- Lógica de Predição ---
            if self.model:
                # 1. Preparar os dados para o modelo.  O formato exato
                #    depende do seu modelo e dos recursos que você extraiu.
                #    Exemplo (se você estiver usando um IsolationForest e as features
                #    extraídas em _extract_features no data_processing.py):
                features = [
                    data['is_tcp'],
                    data['is_udp'],
                    data['is_icmp'],
                    data['flag_syn'],
                    data['flag_ack'],
                    data['flag_fin'],
                    data['port_src_well_known'],
                    data['port_dst_well_known'],
                    data['same_network']
                ]

                # 2. Fazer a predição
                prediction = self.model.predict([features])[0]  # Predição (1: normal, -1: anomalia)
                score = self.model.decision_function([features])[0] # Score de anomalia

                logger.info(f"Predição: {prediction}, Score: {score}")

                # 3. Tomar ações com base na predição
                if score < ANOMALY_THRESHOLD:
                    logger.warning(f"Anomalia detectada! Score: {score}, Dados: {data}")
                    # Enviar alerta (log, e-mail, etc.)
                    # Armazenar no banco de dados (se necessário)
            else:
                logger.error("Modelo de ML não carregado. Impossível fazer predição.")

            # --- Fim da Lógica de Predição ---

            ch.basic_ack(delivery_tag=method.delivery_tag)  # Confirma o recebimento da mensagem

        except json.JSONDecodeError:
            logger.error(f"Erro ao decodificar JSON: {body}", exc_info=True)
            ch.basic_nack(delivery_tag=method.delivery_tag)  # Rejeita a mensagem (não re-enfileira)
        except Exception as e:
            logger.error(f"Erro ao processar mensagem: {e}", exc_info=True)
            ch.basic_nack(delivery_tag=method.delivery_tag)  # Rejeita a mensagem

    def start_consuming(self):
        """Inicia o consumo de mensagens do RabbitMQ."""
        self.rabbitmq_channel.basic_qos(prefetch_count=1)  # Processa uma mensagem por vez
        self.rabbitmq_channel.basic_consume(queue=RABBITMQ_QUEUE, on_message_callback=self.process_message)

        logger.info("Aguardando mensagens. Para sair, pressione CTRL+C")
        try:
            self.rabbitmq_channel.start_consuming()
        except KeyboardInterrupt:
            logger.info("Interrupção recebida. Encerrando...")
            self.rabbitmq_channel.stop_consuming()
            if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
                self.rabbitmq_connection.close()

    def run(self):
        """Método principal para executar o serviço."""
        self.load_model()  # Carrega o modeloa
        self.connect_to_rabbitmq()  # Conecta ao RabbitMQ
        self.start_consuming()  # Começa a consumir mensagens


if __name__ == "__main__":
    ml_service = MLService()
    ml_service.run()