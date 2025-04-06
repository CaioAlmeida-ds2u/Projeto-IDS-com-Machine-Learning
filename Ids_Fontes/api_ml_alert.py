# api_ml_alert.py - Refatorado para bom funcionamento

import logging
import json
import pika
import os
from typing import Optional, Dict
from flask import Flask, jsonify

# --- Integração com ConfigManager ---
try:
    from config import ConfigManager
except ImportError:
    # Log inicial básico, pois o logger principal ainda não está configurado
    print("ERRO CRÍTICO: Não foi possível importar ConfigManager de 'config.py'.")
    logging.error("Falha ao importar ConfigManager.")
    exit(1) # Aborta se a config não pode ser lida

# Configuração inicial do Logger (será reconfigurado)
# Define um nível inicial, mas será sobrescrito pela config
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AlertAPI") # Logger específico

# --- Variáveis Globais para Config e Instância da API ---
config_manager: Optional[ConfigManager] = None
alert_api_instance: Optional['AlertAPI'] = None # Forward declaration

# Inicialização do Flask
app = Flask(__name__)

# --- Classe AlertAPI Aprimorada ---
class AlertAPI:
    """Gerencia a conexão e consumo de alertas do RabbitMQ de forma mais robusta."""

    def __init__(self, mq_config: dict):
        """
        Inicializa com a configuração do RabbitMQ.

        Args:
            mq_config (dict): Dicionário contendo 'host', 'port', 'alert_queue'.
        """
        self.host = mq_config.get('host', 'localhost')
        self.port = int(mq_config.get('port', 5672))
        self.alert_queue_name = mq_config.get('alert_queue')
        if not self.alert_queue_name:
            logger.critical("Nome da fila de alertas ('alert_queue') não fornecido na configuração!")
            # Considerar levantar um erro aqui é mais seguro
            raise ValueError("Nome da fila de alertas ('alert_queue') é obrigatório na configuração.")

        self.rabbitmq_connection: Optional[pika.BlockingConnection] = None
        self.rabbitmq_channel: Optional[pika.channel.Channel] = None
        # Não conecta no __init__, conexão será gerenciada sob demanda ou na inicialização da app

    def _ensure_connection(self) -> bool:
        """Garante que a conexão e o canal estejam ativos, tenta conectar/reconectar se necessário."""
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
            return True
        logger.info("Conexão/Canal RabbitMQ não está aberto. Tentando conectar/reconectar...")
        return self.connect_to_rabbitmq()

    def connect_to_rabbitmq(self) -> bool:
        """Tenta estabelecer conexão com RabbitMQ e declarar a fila."""
        logger.info(f"Tentando conectar AlertAPI a {self.host}:{self.port}...")
        try:
            self._close_connection() # Garante limpeza antes de nova tentativa
            # Parâmetros com timeouts e heartbeat
            params = pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                heartbeat=60,
                blocked_connection_timeout=30 # Timeout mais curto para conexão bloqueada
                # Adicionar credenciais se necessário:
                # credentials=pika.PlainCredentials('user', 'password')
            )
            self.rabbitmq_connection = pika.BlockingConnection(params)
            self.rabbitmq_channel = self.rabbitmq_connection.channel()

            # Declara a fila usando o nome correto, garantindo durabilidade
            self.rabbitmq_channel.queue_declare(queue=self.alert_queue_name, durable=True, passive=False)
            logger.info(f"AlertAPI conectada ao RabbitMQ. Fila '{self.alert_queue_name}' OK.")
            return True
        except pika.exceptions.AMQPConnectionError as e:
             logger.error(f"Erro de conexão AMQP ao conectar AlertAPI ao RabbitMQ: {e}")
        except Exception as e:
            logger.error(f"Erro inesperado ao conectar AlertAPI ao RabbitMQ: {e}", exc_info=True)

        # Se chegou aqui, houve erro
        self._close_connection() # Limpa em caso de erro
        return False # Indica falha na conexão

    def consume_alerts(self) -> Optional[Dict]:
        """
        Consome UMA mensagem da fila de alertas usando basic_get.
        Usa ack manual para maior segurança contra perda de mensagens.
        Retorna o dicionário do alerta ou None se fila vazia ou erro.
        """
        if not self._ensure_connection():
            logger.error("Falha ao garantir conexão MQ. Não foi possível consumir alerta.")
            return None

        method_frame = None # Define fora do try para uso no finally/except
        try:
            # --- Correção: auto_ack=False ---
            method_frame, properties, body = self.rabbitmq_channel.basic_get(
                queue=self.alert_queue_name,
                auto_ack=False # Confirmação será manual
            )

            if method_frame:
                # Mensagem recebida, processa o JSON
                logger.info(f"Mensagem recebida de '{self.alert_queue_name}' (tag={method_frame.delivery_tag}). Processando...")
                try:
                    alert_data = json.loads(body.decode('utf-8'))
                    # --- Correção: Confirma (ACK) APÓS processar com sucesso ---
                    try:
                        self.rabbitmq_channel.basic_ack(delivery_tag=method_frame.delivery_tag)
                        logger.debug(f"Mensagem {method_frame.delivery_tag} processada e confirmada (ACK).")
                        return alert_data
                    except Exception as ack_err:
                         # Erro raro, mas pode acontecer se conexão cair entre get e ack
                         logger.error(f"Erro ao confirmar (ACK) mensagem {method_frame.delivery_tag}: {ack_err}. Mensagem pode ser reprocessada.")
                         # Neste caso, não retornar os dados, pois não foi confirmado
                         return None

                except json.JSONDecodeError:
                    logger.error(f"Erro ao decodificar JSON do alerta: {body[:200]}... Rejeitando mensagem.")
                    # --- Correção: Rejeita (NACK) mensagem inválida ---
                    self.rabbitmq_channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False) # False=não recolocar na fila
                    return None
                except Exception as dec_err:
                    logger.error(f"Erro inesperado ao processar corpo da mensagem: {dec_err}. Rejeitando.", exc_info=True)
                    self.rabbitmq_channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)
                    return None
            else:
                # Nenhuma mensagem disponível na fila
                logger.debug(f"Nenhum alerta disponível na fila '{self.alert_queue_name}'.")
                return None

        except pika.exceptions.StreamLostError as stream_err:
            logger.error(f"Conexão RabbitMQ perdida durante basic_get: {stream_err}.")
            self._close_connection()
            # Não precisa rejeitar msg aqui, pois não chegou a pegá-la
            return None
        except Exception as e:
            logger.error(f"Erro inesperado ao tentar consumir da fila '{self.alert_queue_name}': {e}", exc_info=True)
            self._close_connection() # Força reconexão na próxima tentativa
            # Se houve um method_frame, a mensagem foi pega mas não processada/confirmada
            # O broker deve reenviar após timeout (se não foi feito ack/nack)
            return None

    def check_connection(self) -> tuple[bool, Optional[str]]:
         """Verifica conexão e existência da fila. Retorna (status_bool, error_msg_or_none)."""
         if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
             # Tenta reconectar uma vez para o health check
             if not self.connect_to_rabbitmq():
                  return False, "Disconnected - Failed to reconnect"
             # Se reconectou, continua a verificação abaixo

         # Canal está aberto, verifica se a fila existe
         try:
             # passive=True apenas verifica, não cria. durable=True deve corresponder à declaração original.
             self.rabbitmq_channel.queue_declare(queue=self.alert_queue_name, durable=True, passive=True)
             return True, None # Conectado e fila existe
         except pika.exceptions.ChannelClosedByBroker as queue_err:
             # Código 404 normalmente indica que a fila não foi encontrada
             if queue_err.reply_code == 404:
                 error_msg = f"Connected but queue '{self.alert_queue_name}' not found"
                 logger.warning(f"Health Check: {error_msg}")
                 return False, error_msg
             else:
                 error_msg = f"Connected but queue check failed (reply={queue_err.reply_code} {queue_err.reply_text})"
                 logger.warning(f"Health Check: {error_msg}")
                 return False, error_msg
         except (pika.exceptions.AMQPConnectionError, pika.exceptions.StreamLostError) as conn_err:
             error_msg = f"Connection error during queue check: {conn_err}"
             logger.warning(f"Health Check: {error_msg}")
             self._close_connection() # Fecha se erro ocorreu durante verificação
             return False, error_msg
         except Exception as e:
              error_msg = f"Unexpected error during queue check: {e}"
              logger.error(f"Health Check: {error_msg}", exc_info=True)
              return False, error_msg

    def _close_connection(self):
        """Fecha a conexão com o RabbitMQ de forma segura."""
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
            try: self.rabbitmq_channel.close(); logger.debug("Canal MQ fechado (AlertAPI).")
            except Exception: pass
        if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
            try: self.rabbitmq_connection.close(); logger.debug("Conexão MQ fechada (AlertAPI).")
            except Exception: pass
        # Zera as variáveis para indicar estado fechado
        self.rabbitmq_channel = None
        self.rabbitmq_connection = None
        logger.debug("Recursos RabbitMQ (canal/conexão) zerados (AlertAPI).")


# --- Inicialização da Aplicação e Configuração ---
def initialize_app():
    """Inicializa o ConfigManager, o AlertAPI e configura o logging."""
    global config_manager, alert_api_instance, app

    if alert_api_instance: # Evita inicialização dupla
        return True

    logger.info("Inicializando Alert API Application...")
    try:
        # 1. Carrega ConfigManager
        config_manager = ConfigManager()

        # 2. Configura Logging (com base na config)
        settings_config = config_manager.get_config().get('settings', {})
        log_level_str = settings_config.get('log_level', 'INFO').upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        logging.getLogger().setLevel(log_level) # Aplica ao logger raiz
        logger.info(f"Logging da AlertAPI reconfigurado para nível: {log_level_str}")

        # 3. Obtem config do RabbitMQ
        rabbitmq_config = config_manager.get_rabbitmq_config()
        if not rabbitmq_config or not rabbitmq_config.get('alert_queue'):
             logger.critical("Configuração 'rabbitmq' ou 'rabbitmq.alert_queue' ausente no config.json!")
             raise ValueError("Configuração essencial do RabbitMQ ausente.")

        # 4. Inicializa AlertAPI (mas não conecta ainda)
        alert_api_instance = AlertAPI(rabbitmq_config)
        # Tenta a conexão inicial aqui, mas não impede a API de iniciar se falhar
        if not alert_api_instance.connect_to_rabbitmq():
            logger.warning("Falha na conexão inicial com RabbitMQ ao iniciar API. Tentará reconectar sob demanda.")

        logger.info("Alert API Application inicializada.")
        return True

    except Exception as e:
        logger.critical(f"Erro fatal ao inicializar Alert API Application: {e}", exc_info=True)
        config_manager = None
        alert_api_instance = None
        return False

# --- Endpoints Flask ---

@app.before_first_request
def ensure_initialization():
    """Garante que a inicialização seja feita antes da primeira requisição."""
    # Chama a função de inicialização. Se já foi chamada, retorna True rapidamente.
    if not initialize_app() and alert_api_instance is None:
         # Se a inicialização falhou criticamente, podemos tentar logar de novo
         logger.critical("Falha na inicialização impediu a criação da instância da API.")
         # Poderia retornar um erro aqui, mas é complicado em before_first_request
         # A verificação 'if alert_api_instance is None:' nos endpoints tratará isso

@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Endpoint para consumir um alerta da fila configurada."""
    # Verifica se a instância foi criada com sucesso
    if alert_api_instance is None:
        logger.error("GET /alerts: Chamado mas a API não foi inicializada corretamente.")
        return jsonify({"status": "erro", "mensagem": "Serviço indisponível (falha na inicialização)."}), 503

    logger.debug("Requisição GET /alerts recebida.")
    try:
        alert_data = alert_api_instance.consume_alerts() # Tenta consumir
        if alert_data is not None:
            # Alerta consumido e processado com sucesso
            return jsonify({"status": "sucesso", "alert": alert_data}), 200
        else:
            # Retornou None: pode ser fila vazia ou erro de conexão/processamento
            # Verifica a conexão para dar uma resposta mais precisa
            is_connected, _ = alert_api_instance.check_connection()
            if not is_connected:
                logger.warning("GET /alerts: Nenhum alerta retornado, problema de conexão MQ detectado.")
                return jsonify({"status": "erro", "mensagem": "Erro ao comunicar com o serviço de mensagens."}), 503
            else:
                # Conectado, mas fila estava vazia ou houve erro na decodificação (já logado)
                logger.info("GET /alerts: Nenhum alerta disponível na fila ou mensagem inválida descartada.")
                return jsonify({"status": "sucesso", "mensagem": "Nenhum alerta disponível no momento."}), 200
    except Exception as e:
        # Erro inesperado no próprio endpoint Flask
        logger.error(f"Erro inesperado ao processar requisição GET /alerts: {e}", exc_info=True)
        return jsonify({"status": "erro", "mensagem": "Erro interno do servidor ao processar requisição de alertas."}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Verifica a saúde da API e sua conexão/fila com RabbitMQ."""
    if alert_api_instance is None:
        return jsonify({
            "status": "error",
            "component": "api_ml_alert",
            "message": "API service instance not initialized"
        }), 503 # Indica que o serviço está indisponível

    status_data = {"status": "ok", "component": "api_ml_alert"}
    mq_status = "unknown"
    status_code = 200 # Assume OK inicialmente

    try:
        is_connected, error_msg = alert_api_instance.check_connection()
        if is_connected:
            mq_status = "connected"
        else:
            mq_status = f"error ({error_msg or 'check failed'})"
            status_code = 503 # Dependência crítica indisponível
            if error_msg: status_data["error_details"] = error_msg

    except Exception as e:
        logger.error(f"Health check: Erro inesperado: {e}", exc_info=True)
        status_data["status"] = "error"
        status_data["error_details"] = f"Unexpected health check error: {e}"
        mq_status = "error (check failed)"
        status_code = 500 # Erro interno no health check

    status_data["dependencies"] = {"rabbitmq": mq_status}
    return jsonify(status_data), status_code

@app.teardown_appcontext
def close_rabbitmq_connection(exception=None):
    """Fecha a conexão com o RabbitMQ ao encerrar o contexto da aplicação Flask."""
    if alert_api_instance:
        logger.debug("Teardown: Fechando conexão RabbitMQ da AlertAPI...")
        alert_api_instance._close_connection()

# --- Ponto de Entrada ---
if __name__ == '__main__':
    # Chama a inicialização aqui para garantir que ocorra mesmo sem requisições
    # e para pegar erros críticos antes de tentar rodar o app.run
    if not initialize_app():
         logger.critical("Finalizando devido a erro fatal na inicialização.")
         exit(1)

    # Obtem host e porta (poderia vir da config ou env vars)
    api_host = os.environ.get('ALERT_API_HOST', '0.0.0.0')
    api_port = int(os.environ.get('ALERT_API_PORT', 5001))

    logger.info(f"Iniciando Alert API Flask em http://{api_host}:{api_port}")

    # Em produção, use Gunicorn ou uWSGI
    # Ex: gunicorn --bind 0.0.0.0:5001 api_ml_alert:app --log-level info
    try:
        # debug=False é essencial para produção
        # use_reloader=False também é importante se rodar com Gunicorn/uWSGI
        app.run(host=api_host, port=api_port, debug=False, use_reloader=False)
    except Exception as run_err:
        logger.critical(f"Falha ao iniciar servidor Flask: {run_err}", exc_info=True)
        exit(1) # Sai se o servidor não puder iniciar

    logger.info("Servidor Flask da AlertAPI encerrado.")