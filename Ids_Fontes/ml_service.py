import logging
import json
import signal
import pika
import joblib
import os
import time
from typing import Optional, List, Any, Dict # Tipos adicionados

# Componentes locais
from config import ConfigManager
from redis_client import RedisClient

# Configuração inicial do Logger (será reconfigurado)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
logger = logging.getLogger("MLService") # Logger específico

class MLService:
    def __init__(self):
        """Inicializa o Serviço de Machine Learning."""
        logger.info("Inicializando MLService...")
        self.config_manager = ConfigManager()
        self.model = None
        self.running = True # Controle do loop principal

        # Atributos de configuração (serão preenchidos por _load_configuration)
        self.log_level = logging.INFO
        self.rabbitmq_host: Optional[str] = None
        self.rabbitmq_port: Optional[int] = None
        self.rabbitmq_packet_queue: Optional[str] = None # Fila de onde consome pacotes
        self.rabbitmq_alert_queue: Optional[str] = None  # Fila para onde envia alertas
        self.model_path: Optional[str] = None
        self.anomaly_threshold: Optional[float] = None

        # Conexões
        self.rabbitmq_connection: Optional[pika.BlockingConnection] = None
        self.rabbitmq_channel: Optional[pika.channel.Channel] = None
        self.redis_client: Optional[RedisClient] = None

        # Flag para evitar múltiplas tentativas de reconexão simultâneas
        self._is_reconnecting_mq = False

        try:
            self._load_configuration()
            self._configure_logging() # Configura logger com base no nível carregado
            self._initialize_redis_client()
            # A conexão RabbitMQ e o carregamento do modelo serão feitos no run()
            logger.info("MLService pré-inicializado com sucesso (configurações carregadas).")
        except Exception as e:
             logger.critical(f"Falha crítica na pré-inicialização do MLService: {e}", exc_info=True)
             self.running = False
             self._cleanup() # Tenta limpar o que foi inicializado
             raise RuntimeError("Falha na inicialização do MLService") from e

    def _load_configuration(self):
        """Carrega todas as configurações necessárias do ConfigManager."""
        logger.info("Carregando configurações do MLService...")
        try:
            # Config Geral (para log level)
            settings_config = self.config_manager.get_config().get('settings', {})
            log_level_str = settings_config.get('log_level', 'INFO').upper()
            self.log_level = getattr(logging, log_level_str, logging.INFO)

            # Config RabbitMQ
            rabbitmq_config = self.config_manager.get_rabbitmq_config()
            if not rabbitmq_config: raise ValueError("Seção 'rabbitmq' ausente na config.")
            self.rabbitmq_host = rabbitmq_config.get('host')
            self.rabbitmq_port = int(rabbitmq_config.get('port'))
            self.rabbitmq_packet_queue = rabbitmq_config.get('packet_queue') # Consome daqui
            self.rabbitmq_alert_queue = rabbitmq_config.get('alert_queue')   # Publica aqui
            if not all([self.rabbitmq_host, self.rabbitmq_port, self.rabbitmq_packet_queue, self.rabbitmq_alert_queue]):
                 raise ValueError("Configuração RabbitMQ incompleta (host, port, packet_queue, alert_queue).")
            logger.info(f"Config RabbitMQ: {self.rabbitmq_host}:{self.rabbitmq_port}, Consume='{self.rabbitmq_packet_queue}', Alert='{self.rabbitmq_alert_queue}'")

            # Config ML Service
            ml_config = self.config_manager.get_ml_service_config()
            if not ml_config: raise ValueError("Seção 'ml_service' ausente na config.")
            self.model_path = ml_config.get('model_path')
            self.anomaly_threshold = float(ml_config.get('anomaly_threshold'))
            if not self.model_path or self.anomaly_threshold is None:
                 raise ValueError("Configuração MLService incompleta (model_path, anomaly_threshold).")
            logger.info(f"Config ML: Model='{self.model_path}', Threshold={self.anomaly_threshold}")

            # Config Redis (necessária para inicializar o cliente)
            redis_config = self.config_manager.get_redis_config()
            if not redis_config: raise ValueError("Seção 'redis' ausente na config.")
            # Validações básicas Redis (host, port, etc.) são feitas no _initialize_redis_client

        except (ValueError, TypeError, KeyError) as e:
             logger.critical(f"Erro ao carregar ou validar configurações do MLService: {e}")
             raise RuntimeError("Configuração inválida para MLService.") from e
        except Exception as e:
            logger.critical(f"Erro inesperado ao carregar configurações do MLService: {e}", exc_info=True)
            raise RuntimeError("Erro ao carregar configurações do MLService.") from e

    def _configure_logging(self):
        """Reconfigura o sistema de logging globalmente com o nível carregado."""
        # (Mesma lógica de _configure_logging do main.py)
        try:
            root_logger = logging.getLogger()
            for handler in root_logger.handlers[:]: root_logger.removeHandler(handler)
            formatter = logging.Formatter('%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            root_logger.addHandler(stream_handler)
            root_logger.setLevel(self.log_level)
            logger.info(f"Logging do MLService configurado para nível: {logging.getLevelName(root_logger.getEffectiveLevel())}")
        except Exception as e:
            print(f"CRITICAL: Falha ao configurar o logging do MLService: {e}")
            logger.critical(f"Falha ao configurar o logging do MLService: {e}", exc_info=True)

    def _initialize_redis_client(self):
        """Inicializa o cliente Redis com base na configuração."""
        # (Mesma lógica de _initialize_redis_client do main.py)
        logger.info("Inicializando cliente Redis para MLService...")
        try:
            redis_config = self.config_manager.get_redis_config()
            if not redis_config: raise ValueError("Seção 'redis' ausente.")

            self.redis_client = RedisClient(
                host=redis_config.get('host'),
                port=int(redis_config.get('port')),
                db=int(redis_config.get('db')),
                password=redis_config.get('password'),
                block_list_key=redis_config.get('block_list_key'),
                block_ttl_seconds=int(redis_config.get('block_ttl_seconds')) # Usa TTL ao adicionar
            )
            if not self.redis_client.get_connection():
                 raise redis.exceptions.ConnectionError("Falha ao conectar ao Redis na inicialização.")
            logger.info("Cliente Redis do MLService inicializado e conectado.")
        except (ValueError, TypeError, KeyError) as e:
            logger.critical(f"Erro na configuração Redis para MLService: {e}")
            self.redis_client = None
            raise RuntimeError("Configuração inválida para Redis no MLService.") from e
        except redis.exceptions.ConnectionError as e:
             logger.critical(f"Falha ao conectar Redis no MLService: {e}")
             self.redis_client = None
             raise RuntimeError("Falha na conexão inicial Redis no MLService.") from e
        except Exception as e:
            logger.critical(f"Erro inesperado inicializando Redis no MLService: {e}", exc_info=True)
            self.redis_client = None
            raise RuntimeError("Erro ao inicializar Redis no MLService.") from e

    def load_model(self):
        """Carrega o modelo de ML treinado a partir do arquivo."""
        logger.info(f"Carregando modelo ML de: {self.model_path}")
        if not self.model_path or not os.path.exists(self.model_path):
             logger.critical(f"Arquivo do modelo não encontrado: {self.model_path}")
             raise FileNotFoundError(f"Modelo ML não encontrado em {self.model_path}")
        try:
            self.model = joblib.load(self.model_path)
            logger.info(f"Modelo ML carregado com sucesso de {self.model_path}")
            # Validação básica de interface do modelo
            if not (hasattr(self.model, 'predict') and hasattr(self.model, 'decision_function')):
                 logger.warning(f"Modelo {self.model_path} pode não ter os métodos 'predict' e 'decision_function' esperados.")
                 # Dependendo do modelo, pode ser necessário ajustar essa verificação
        except Exception as e:
            logger.critical(f"Erro ao carregar modelo ML de {self.model_path}: {e}", exc_info=True)
            raise RuntimeError(f"Falha ao carregar modelo ML de {self.model_path}") from e

    def _connect_to_rabbitmq(self, is_reconnect=False) -> bool:
        """Conecta ao RabbitMQ, declarando as filas necessárias."""
        if self._is_reconnecting_mq and not is_reconnect:
             logger.warning("Tentativa de conexão MQ ignorada, já em processo de reconexão.")
             return False
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
            logger.debug("Já conectado ao RabbitMQ.")
            return True

        if is_reconnect:
             logger.info(f"Tentando RECONECTAR MLService ao RabbitMQ em {self.rabbitmq_host}:{self.rabbitmq_port}...")
             self._is_reconnecting_mq = True # Sinaliza início da reconexão
        else:
             logger.info(f"Tentando conectar MLService ao RabbitMQ em {self.rabbitmq_host}:{self.rabbitmq_port}...")

        try:
            self._close_rabbitmq_connection() # Garante limpeza antes de tentar

            self.rabbitmq_connection = pika.BlockingConnection(
                 pika.ConnectionParameters(
                      host=self.rabbitmq_host,
                      port=self.rabbitmq_port,
                      heartbeat=600,
                      blocked_connection_timeout=300
                 )
            )
            self.rabbitmq_channel = self.rabbitmq_connection.channel()

            # Declara a fila de onde VAI CONSUMIR pacotes
            self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_packet_queue, durable=True)
            logger.debug(f"Fila de consumo '{self.rabbitmq_packet_queue}' declarada.")

            # Declara a fila para onde VAI PUBLICAR alertas
            self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_alert_queue, durable=True)
            logger.debug(f"Fila de alerta '{self.rabbitmq_alert_queue}' declarada.")

            logger.info(f"MLService {'RECONECTADO' if is_reconnect else 'CONECTADO'} ao RabbitMQ com sucesso.")
            self._is_reconnecting_mq = False # Sinaliza fim da reconexão bem-sucedida
            return True
        except Exception as e:
            logger.error(f"Erro ao {'reconectar' if is_reconnect else 'conectar'} MLService ao RabbitMQ: {e.__class__.__name__}")
            self._close_rabbitmq_connection() # Limpa em caso de falha
            self._is_reconnecting_mq = False # Sinaliza fim da tentativa de reconexão (falha)
            # Não re-lança exceção aqui, o chamador tratará o retorno False
            return False

    # <<< REMOVER: connect_to_database() se não for logar anomalias no DB >>>
    # def connect_to_database(self): ...

    def validate_data(self, data: Dict[str, Any]):
        """
        Valida se os dados recebidos contêm as features mínimas esperadas.
        NOTA: Esta é uma validação de *existência*, não de tipo ou valor.
        A ordem correta das features é crucial em `prepare_features`.
        """
        # Ajuste esta lista com base nas features REAIS usadas no seu modelo treinado!
        # É crucial que todas as features usadas em `prepare_features` estejam aqui.
        required_features = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'payload_size',
            'is_tcp', 'is_udp', 'is_icmp', 'flag_syn', 'flag_ack', 'flag_fin', 'flag_rst',
            'port_src_well_known', 'port_dst_well_known', 'same_network',
            # Adicione MAIS features se o seu modelo usar
        ]
        missing = [f for f in required_features if f not in data]
        if missing:
            # Logar em warning pois é um problema com os dados recebidos
            logger.warning(f"Features ausentes nos dados recebidos: {', '.join(missing)}. Pacote descartado.")
            raise ValueError(f"Features ausentes: {', '.join(missing)}")
        # logger.debug("Validação básica de features recebidas OK.")
        return True

    def prepare_features(self, data: Dict[str, Any]) -> List[float]:
         """
         Extrai e ordena as features na ordem EXATA esperada pelo modelo.
         Converte para float. Retorna a lista de features prontas para `model.predict`.

         !!!! IMPORTANTE: A ordem aqui DEVE ser idêntica à usada no TREINAMENTO !!!!
         """
         try:
            # Exemplo (SUBSTITUA PELA ORDEM REAL DO SEU MODELO):
            features_ordered = [
                 data.get('payload_size', 0.0),
                 data.get('src_port', 0.0),
                 data.get('dst_port', 0.0),
                 data.get('ttl', 0.0), # Exemplo: adicionando TTL
                 data.get('is_tcp', 0.0),
                 data.get('is_udp', 0.0),
                 data.get('is_icmp', 0.0),
                 data.get('flag_syn', 0.0),
                 data.get('flag_ack', 0.0),
                 data.get('flag_fin', 0.0),
                 data.get('flag_rst', 0.0),
                 data.get('flag_psh', 0.0), # Exemplo: adicionando PSH
                 data.get('flag_urg', 0.0), # Exemplo: adicionando URG
                 data.get('port_src_well_known', 0.0),
                 data.get('port_dst_well_known', 0.0),
                 data.get('same_network', 0.0),
                 # ... adicione TODAS as outras features na ordem correta ...
            ]
            # Converte tudo para float, tratando possíveis erros de conversão
            return [float(f) for f in features_ordered]
         except (TypeError, ValueError) as e:
              logger.error(f"Erro ao converter features para float: {e}. Dados: {data}")
              raise ValueError("Erro na preparação/conversão de features.") from e


    def process_message(self, ch: pika.channel.Channel, method: pika.spec.Basic.Deliver,
                        properties: pika.spec.BasicProperties, body: bytes):
        """Processa uma mensagem (pacote normalizado) recebida do RabbitMQ."""
        if not self.running:
            # Se o serviço está parando, rejeita a mensagem e pede para re-enfileirar
            logger.warning("Serviço parando, rejeitando mensagem para re-enfileirar.")
            try: ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            except Exception as e: logger.error(f"Erro ao dar NACK na parada: {e}")
            return
        try:
            # Decodifica o corpo da mensagem (JSON)
            data = json.loads(body.decode('utf-8'))
            # logger.debug(f"Mensagem recebida para análise: SRC={data.get('src_ip')} -> DST={data.get('dst_ip')}")

            # 1. Validação dos dados (verifica se chaves existem)
            self.validate_data(data)

            # 2. Preparar features na ordem correta para o modelo
            features = self.prepare_features(data)

            # 3. Fazer a predição e obter o score
            # Garante que o modelo foi carregado
            if not self.model:
                 logger.error("Modelo ML não carregado! Descartando mensagem.")
                 ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Descarta
                 return

            prediction = self.model.predict([features])[0]
            score = self.model.decision_function([features])[0]

            logger.debug(f"Análise ML: SRC={data.get('src_ip')} -> DST={data.get('dst_ip')} | Proto={data.get('protocol_name','N/A')} | DPort={data.get('dst_port','N/A')} | Score={score:.4f} | Pred={prediction}")

            # 4. Ação baseada no score e limiar
            if score < self.anomaly_threshold:
                logger.warning(f"ANOMALIA DETECTADA! Score: {score:.4f} < {self.anomaly_threshold}. SRC={data.get('src_ip')}, DST={data.get('dst_ip')}, DPort={data.get('dst_port')}")
                # Lida com a anomalia (adiciona ao Redis, envia alerta)
                self.handle_anomaly(data, score, prediction)

            # Confirma o processamento da mensagem para RabbitMQ
            ch.basic_ack(delivery_tag=method.delivery_tag)

        except json.JSONDecodeError:
            logger.error(f"Erro ao decodificar JSON: {body[:500]}...", exc_info=False) # Log limitado
            # Descarta mensagem mal formatada permanentemente
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except ValueError as e: # Erro de validação ou preparação
            logger.error(f"Erro de validação/preparação dos dados: {e}. Descartando msg.")
            # Logar os dados em debug pode ser útil
            # logger.debug(f"Dados com erro de validação/preparação: {body.decode('utf-8', 'ignore')}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Descarta
        except Exception as e:
            logger.error(f"Erro inesperado ao processar mensagem: {e}", exc_info=True)
            # Descarta a mensagem para evitar loops de erro com mensagens problemáticas
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    # <<< MÉTODO CHAVE MODIFICADO >>>
    def handle_anomaly(self, data: Dict[str, Any], score: float, prediction: Any):
        """
        Lida com anomalias detectadas:
        1. Adiciona o IP de origem à lista de bloqueio no Redis.
        2. Envia um alerta para a fila de notificações RabbitMQ.
        """
        ip_to_block = data.get('src_ip')
        reason = f"ML Anomaly Detection: Score={score:.4f} (Threshold={self.anomaly_threshold}), Prediction={prediction}"

        if not ip_to_block:
             logger.error("Não foi possível determinar o IP para bloquear a partir dos dados da anomalia.")
             return

        # 1. Adicionar ao Redis para Bloqueio
        if self.redis_client:
            # Tenta adicionar ao Redis, usando o TTL padrão configurado
            success = self.redis_client.add_block(ip_to_block)
            if success:
                logger.info(f"Solicitação de bloqueio para IP {ip_to_block} enviada ao Redis.")
            else:
                # Erro já logado pelo RedisClient, mas podemos logar aqui também
                logger.error(f"Falha ao enviar solicitação de bloqueio para IP {ip_to_block} ao Redis (verificar logs do RedisClient).")
        else:
            # Isso não deveria acontecer se a inicialização foi bem-sucedida
            logger.error("Cliente Redis não inicializado! Não é possível solicitar bloqueio para {ip_to_block}.")

        # 2. Enviar Alerta para Fila de Notificação (RabbitMQ)
        alert_message = {
            'timestamp': time.time(),
            'type': 'anomaly_detected',
            'decision': 'block_requested', # Indica a ação tomada (solicitar bloqueio)
            'ip_address': ip_to_block,
            'score': round(score, 4), # Arredonda para clareza
            'threshold': self.anomaly_threshold,
            'prediction': str(prediction), # Converte para string por segurança
            'reason': reason,
            'packet_sample': { # Inclui amostra dos dados do pacote para contexto
                 'src_ip': data.get('src_ip'),
                 'dst_ip': data.get('dst_ip'),
                 'src_port': data.get('src_port'),
                 'dst_port': data.get('dst_port'),
                 'protocol': data.get('protocol_name', data.get('protocol')),
                 'payload_size': data.get('payload_size')
            }
        }
        try:
             # Garante que o canal MQ está aberto antes de publicar
             if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                  logger.warning("Canal RabbitMQ para alertas fechado. Tentando reconectar...")
                  if not self._connect_to_rabbitmq(is_reconnect=True):
                       logger.error(f"Falha ao reconectar MQ. Alerta para {ip_to_block} NÃO enviado.")
                       return # Não envia se não reconectar

             # Publica na fila de ALERTAS
             self.rabbitmq_channel.basic_publish(
                  exchange='',
                  routing_key=self.rabbitmq_alert_queue, # <<< Fila de ALERTAS >>>
                  body=json.dumps(alert_message, default=str),
                  properties=pika.BasicProperties(delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE)
             )
             logger.info(f"Alerta de anomalia para IP {ip_to_block} publicado na fila '{self.rabbitmq_alert_queue}'.")

        except Exception as e:
            # Pode ser erro de publicação ou reconexão
            logger.error(f"Erro ao enviar alerta para RabbitMQ (IP: {ip_to_block}): {e}", exc_info=True)
            # Forçar fechamento pode ajudar na próxima tentativa
            self._close_rabbitmq_connection()


        # 3. <<< REMOVIDO: Log de BLOQUEIO no Banco de Dados >>>
        # A ação de bloqueio efetiva e seu log são responsabilidade do BlockerWorker

        # 4. <<< OPCIONAL: Log da ANOMALIA no Banco de Dados >>>
        # Se você ainda quiser logar *todas* as anomalias detectadas (independente do bloqueio):
        # self._log_anomaly_to_db(data, score, prediction, ip_to_block, reason)

    # <<< MÉTODO DE CONSUMO MODIFICADO >>>
    def start_consuming(self):
        """Inicia o consumo de mensagens da fila de pacotes RabbitMQ."""
        if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
             logger.error("Canal RabbitMQ não está disponível. Não é possível iniciar consumo.")
             # Tentar reconectar antes de desistir?
             if not self._connect_to_rabbitmq(is_reconnect=True):
                  logger.critical("Falha ao conectar ao RabbitMQ para iniciar consumo. Serviço encerrando.")
                  self.running = False
                  return
             # Se reconectou, continua abaixo

        try:
            # Define Quality of Service: processa uma mensagem por vez antes de receber a próxima
            self.rabbitmq_channel.basic_qos(prefetch_count=1)
            # Inicia o consumidor
            consumer_tag = self.rabbitmq_channel.basic_consume(
                queue=self.rabbitmq_packet_queue, # <<< Consome da fila de PACOTES >>>
                on_message_callback=self.process_message
                # auto_ack=False é o padrão, confirmação manual em process_message
            )
            logger.info(f"Consumidor iniciado na fila '{self.rabbitmq_packet_queue}' (Tag: {consumer_tag}). Aguardando mensagens...")
        except Exception as e:
             logger.critical(f"Erro ao iniciar consumidor RabbitMQ: {e}", exc_info=True)
             self.running = False # Para o serviço se não conseguir iniciar o consumo
             return

        # Loop principal de processamento de eventos RabbitMQ
        while self.running:
            try:
                 # Processa eventos de I/O por um curto período (não bloqueante)
                 # Permite que o loop verifique self.running e trate sinais
                 self.rabbitmq_connection.process_data_events(time_limit=1) # Timeout de 1 segundo

                 # Verificação de saúde periódica (opcional)
                 # if time.time() % 30 < 1: # A cada ~30 segundos
                 #      if not self.redis_client or not self.redis_client.get_connection():
                 #           logger.warning("Perda de conexão Redis detectada no loop de consumo.")
                 #      if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                 #           logger.warning("Perda de conexão RabbitMQ detectada no loop. Tentando reconectar...")
                 #           self._try_reconnect_mq()

            except pika.exceptions.StreamLostError:
                 logger.error("Conexão RabbitMQ perdida (StreamLostError)! Tentando reconectar...")
                 self._try_reconnect_mq() # Tenta reconectar e reiniciar consumo
                 if not self.running: break # Sai se a reconexão falhar e setar running=False

            except KeyboardInterrupt:
                 logger.info("KeyboardInterrupt recebido no loop de consumo. Encerrando...")
                 self.running = False # Sinaliza para sair do loop
                 break # Sai imediatamente
            except Exception as e:
                # Erro inesperado no process_data_events ou na lógica do loop
                logger.error(f"Erro inesperado no loop de consumo do MLService: {e}", exc_info=True)
                # Pausa para evitar loop de erro muito rápido antes de continuar/tentar reconectar
                logger.info("Pausando por 5 segundos antes de continuar...")
                time.sleep(5)
                # Tentar reconectar pode ser uma boa ideia aqui também
                self._try_reconnect_mq()
                if not self.running: break # Sai se a reconexão falhar

        logger.info("Loop de consumo do MLService terminado.")
        # Tenta cancelar o consumidor explicitamente ao sair do loop
        if self.rabbitmq_channel and self.rabbitmq_channel.is_consuming:
             try:
                  logger.info(f"Cancelando consumidor (Tag: {consumer_tag})...")
                  self.rabbitmq_channel.basic_cancel(consumer_tag)
             except Exception as e:
                  logger.warning(f"Erro ao cancelar consumidor RabbitMQ: {e}")

    def _try_reconnect_mq(self):
        """Tenta reconectar ao RabbitMQ e reiniciar o consumo."""
        if not self.running or self._is_reconnecting_mq: return # Sai se já parando ou reconectando

        logger.info("Iniciando tentativa de reconexão MQ...")
        if self._connect_to_rabbitmq(is_reconnect=True):
             # Se reconectou, reinicia o consumo
             try:
                  logger.info("Reiniciando consumo RabbitMQ após reconexão...")
                  self.rabbitmq_channel.basic_qos(prefetch_count=1)
                  consumer_tag = self.rabbitmq_channel.basic_consume(
                       queue=self.rabbitmq_packet_queue,
                       on_message_callback=self.process_message
                  )
                  logger.info(f"Consumo reiniciado com sucesso (Tag: {consumer_tag}).")
             except Exception as recon_consume_err:
                  logger.critical(f"Falha ao reiniciar consumo após reconexão MQ: {recon_consume_err}. Encerrando.")
                  self.running = False # Erro crítico, para o serviço
        else:
             logger.error("Falha na reconexão MQ. Tentará novamente mais tarde se o loop continuar.")
             # Não para o serviço aqui, o loop principal pode tentar novamente

    # <<< MÉTODO STOP MODIFICADO >>>
    def stop(self, signum=None, frame=None):
        """Sinaliza para o serviço parar de forma graciosa."""
        if not self.running: return # Já parando/parado
        signal_name = f"Sinal {signal.Signals(signum).name}" if signum else "Chamada programática"
        logger.warning(f"{signal_name} recebido. Solicitando parada do MLService...")
        self.running = False
        # A limpeza real acontece no _cleanup() chamado ao final do run() ou erro

    # <<< NOVO MÉTODO CLEANUP >>>
    def _cleanup(self):
        """Libera recursos (conexões MQ, Redis)."""
        logger.info("Executando limpeza dos recursos do MLService...")
        # Fecha RabbitMQ
        logger.debug("Fechando conexão RabbitMQ...")
        self._close_rabbitmq_connection()
        # Fecha Redis
        logger.debug("Fechando conexão Redis...")
        if self.redis_client:
            self.redis_client.close()
        # Fecha DB (se usado)
        # if self.db_connection and self.db_connection.is_connected():
        #     try:
        #         self.db_connection.close()
        #         logger.info("Conexão DB fechada.")
        #     except Exception as e: logger.error(f"Erro ao fechar DB: {e}")
        logger.info("Recursos do MLService liberados.")

    # <<< NOVO MÉTODO AUXILIAR >>>
    def _close_rabbitmq_connection(self):
        """Fecha conexão RabbitMQ de forma segura."""
        # (Mesma lógica de _close_rabbitmq_connection do main.py)
        closed = False
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
            try: self.rabbitmq_channel.close(); logger.debug("Canal MQ fechado."); closed=True
            except Exception as e: logger.error(f"Erro ao fechar canal MQ: {e}", exc_info=False)
        if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
             try: self.rabbitmq_connection.close(); logger.info("Conexão MQ fechada."); closed=True
             except Exception as e: logger.error(f"Erro ao fechar conexão MQ: {e}", exc_info=False)
        self.rabbitmq_channel = None
        self.rabbitmq_connection = None
        # if closed: logger.debug("Recursos MQ liberados.")

    # <<< MÉTODO RUN MODIFICADO >>>
    def run(self):
        """Método principal para configurar, conectar e iniciar o consumo."""
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)

        if not self.running: # Verifica se a pré-inicialização falhou
             logger.critical("MLService não pode iniciar devido a erro na pré-inicialização.")
             return # Sai imediatamente

        try:
             # Carrega o modelo ML
             self.load_model()

             # Conecta ao RabbitMQ (já tenta reconectar internamente se necessário)
             if not self._connect_to_rabbitmq():
                  raise RuntimeError("Falha ao conectar ao RabbitMQ na inicialização do run().")

             # Verifica cliente Redis (já inicializado e conectado no __init__)
             if not self.redis_client or not self.redis_client.get_connection():
                 raise RuntimeError("Conexão Redis não disponível na inicialização do run().")

             # Inicia o loop de consumo
             self.start_consuming()

        except Exception as e:
             logger.critical(f"Erro fatal durante a execução do MLService (run): {e}", exc_info=True)
             self.running = False # Garante que pare se ocorrer erro aqui
        finally:
             logger.info("MLService run() finalizando.")
             self._cleanup() # Garante que a limpeza seja chamada ao sair


# --- Ponto de Entrada Principal ---
if __name__ == "__main__":
    service = None
    exit_code = 0
    try:
        logger.info("Iniciando aplicação MLService...")
        service = MLService()
        # O run() agora bloqueia até self.running ser False
        service.run()
        logger.info("MLService run() concluído.")
    except RuntimeError as e:
        # Erros fatais da inicialização já logados
        logger.critical(f"Encerrando MLService devido a erro fatal na inicialização: {e}")
        exit_code = 1
    except KeyboardInterrupt:
         logger.warning("Interrupção pelo teclado (Ctrl+C) detectada.")
         # O signal handler ou o loop de consumo devem ter setado running=False
         exit_code = 0
    except Exception as e:
         logger.critical(f"Erro não tratado no nível principal do MLService: {e}", exc_info=True)
         exit_code = 1
    finally:
        logger.info("Aplicação MLService encerrando...")
        # Cleanup já é chamado no finally do run()
        logger.info(f"Aplicação MLService finalizada com código de saída: {exit_code}")
        time.sleep(0.5) # Pausa para logs
        exit(exit_code)