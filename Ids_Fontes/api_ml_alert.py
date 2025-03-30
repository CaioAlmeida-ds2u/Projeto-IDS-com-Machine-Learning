import logging
import json
import pika
from flask import Flask, jsonify, Response

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurações do RabbitMQ
RABBITMQ_HOST = 'localhost'
RABBITMQ_PORT = 5672
ALERT_QUEUE = 'alertas'

# Inicialização do Flask
app = Flask(__name__)

class AlertAPI:
    def __init__(self):
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None

    def connect_to_rabbitmq(self):
        """Conecta ao RabbitMQ."""
        try:
            self.rabbitmq_connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=RABBITMQ_HOST, port=RABBITMQ_PORT)
            )
            self.rabbitmq_channel = self.rabbitmq_connection.channel()
            self.rabbitmq_channel.queue_declare(queue=ALERT_QUEUE, durable=True)
            logger.info(f"Conectado ao RabbitMQ em {RABBITMQ_HOST}:{RABBITMQ_PORT}")
        except Exception as e:
            logger.error(f"Erro ao conectar ao RabbitMQ: {e}", exc_info=True)
            raise

    def consume_alerts(self):
        """Consome mensagens da fila ALERT_QUEUE."""
        try:
            method_frame, properties, body = self.rabbitmq_channel.basic_get(queue=ALERT_QUEUE, auto_ack=True)
            if method_frame:
                logger.info(f"Alerta consumido: {body}")
                return json.loads(body)
            else:
                logger.info("Nenhum alerta disponível na fila.")
                return None
        except Exception as e:
            logger.error(f"Erro ao consumir mensagens da fila: {e}", exc_info=True)
            return None

    def close_connection(self):
        """Fecha a conexão com o RabbitMQ."""
        if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
            self.rabbitmq_connection.close()
            logger.info("Conexão com RabbitMQ encerrada.")

# Instância da classe AlertAPI
alert_api = AlertAPI()
alert_api.connect_to_rabbitmq()

@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint para verificar o status da API e conexão RabbitMQ."""
    status_data = {"status": "ok", "component": "api_ml_alert"}
    mq_status = "unknown"
    try:
        # Verifica se a conexão e o canal existem e estão abertos
        if (alert_api.rabbitmq_connection and alert_api.rabbitmq_connection.is_open and
                alert_api.rabbitmq_channel and alert_api.rabbitmq_channel.is_open):
            # Tenta um comando leve, como declarar a fila novamente (idempotente)
            alert_api.rabbitmq_channel.queue_declare(queue=ALERT_QUEUE, durable=True, passive=True) # passive=True não cria, só verifica
            mq_status = "connected"
        else:
            mq_status = "disconnected"
        status_code = 200
    except (pika.exceptions.AMQPConnectionError, pika.exceptions.ChannelClosed, AttributeError) as e:
         logger.warning(f"Health check: Falha na verificação RabbitMQ: {e}")
         mq_status = "error"
         status_data["error"] = f"RabbitMQ connection error: {e}"
         status_code = 503 # Service unavailable (dependência falhou)
    except Exception as e:
         logger.error(f"Health check: Erro inesperado: {e}", exc_info=True)
         status_data["status"] = "error"
         status_data["error"] = f"Unexpected error: {e}"
         mq_status = "error"
         status_code = 500

    status_data["dependencies"] = {"rabbitmq": mq_status}
    return jsonify(status_data), status_code

@app.route('/alerts', methods=['GET'])
def get_alerts():
    """
    Endpoint para consumir alertas da fila ALERT_QUEUE.
    """
    try:
        alert = alert_api.consume_alerts()
        if alert:
            return jsonify({"status": "sucesso", "alert": alert}), 200
        else:
            return jsonify({"status": "sucesso", "mensagem": "Nenhum alerta disponível."}), 200
    except Exception as e:
        logger.error(f"Erro ao processar requisição de alertas: {e}", exc_info=True)
        return jsonify({"status": "erro", "mensagem": "Erro ao processar requisição."}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """
    Endpoint para verificar o status da API.
    """
    return jsonify({"status": "sucesso", "mensagem": "API está funcionando."}), 200

@app.teardown_appcontext
def close_rabbitmq_connection(exception=None):
    """Fecha a conexão com o RabbitMQ ao encerrar a aplicação."""
    alert_api.close_connection()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)