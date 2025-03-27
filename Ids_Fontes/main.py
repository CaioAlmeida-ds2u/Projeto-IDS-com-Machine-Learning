import logging
# Use o handler específico do systemd se estiver disponível e for necessário
# Se não, o logging padrão para stdout/stderr já é capturado pelo journald
# from systemd.journal import JournalHandler
import time
import threading
import signal
import socket
import ipaddress
import netifaces
import json
import pika  # Importa pika
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

# Assumindo que essas classes existem nos arquivos correspondentes
from config import ConfigManager
from packet_processor import PacketCapturer
from data_processing import PacketNormalizer

# --- Configuração Inicial do Logger (antes da configuração via arquivo) ---
# Este logger inicial pega erros MUITO cedo (antes de ler config.json)
# Ele será reconfigurado depois em _configure_logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
# ---------------------------------------------------------------------

class IDSController:
    def __init__(self):
        """Inicializa o controlador do IDS."""
        logger.info("Inicializando IDSController...")
        self.config_manager = ConfigManager() # Renomeado para clareza
        self.capturer = None
        self.running = True # Controla os loops principais
        self.service_status = 'initializing'
        # Removido buffer interno, confiando no RabbitMQ
        # self.buffer = []
        # self.buffer_lock = threading.Lock()

        self.host = 'localhost'
        self.port = 65432
        self.interface = None
        self.filter_rules = 'ip'
        self.log_level = logging.INFO

        self.rabbitmq_host = 'localhost'
        self.rabbitmq_port = 5672
        self.rabbitmq_queue = 'pacotes_ids' # Nome da fila atualizado
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None

        try:
            # 1. Carrega configurações primeiro
            self._load_configuration()
            # 2. Configura o logging com base nas configurações carregadas
            self._configure_logging()
            # 3. Configura parâmetros do RabbitMQ
            self._configure_rabbitmq_params() # Renomeado para clareza

            self.service_status = 'stopped' # Pronto para iniciar
            logger.info("IDSController inicializado com sucesso.")

        except Exception as e:
            logger.critical(f"Falha crítica durante a inicialização do IDSController: {e}", exc_info=True)
            self.service_status = 'error'
            self.running = False # Impede a execução de start()
            raise RuntimeError("Falha na inicialização do IDSController") from e

    def _load_configuration(self):
        """Carrega configurações do arquivo usando ConfigManager."""
        logger.info("Carregando configurações do arquivo...")
        try:
            config_data = self.config_manager.get_config()
            if not config_data:
                 raise ValueError("Arquivo de configuração vazio ou inválido.")

            settings = config_data.get('settings', {})
            self.host = settings.get('service_host', self.host)
            self.port = int(settings.get('service_port', self.port))
            self.interface = settings.get('interface', None) # Pode ser None inicialmente
            self.filter_rules = settings.get('filter', self.filter_rules)

            log_level_str = settings.get('log_level', 'INFO').upper()
            self.log_level = getattr(logging, log_level_str, logging.INFO)

            # Tenta detectar interface se não estiver definida
            if not self.interface:
                logger.warning("Interface de rede não especificada. Tentando detectar automaticamente...")
                try:
                    # Tenta obter o gateway padrão para AF_INET
                    gateways = netifaces.gateways()
                    default_gw_info = gateways.get('default', {}).get(netifaces.AF_INET)
                    if default_gw_info:
                        self.interface = default_gw_info[1]
                        logger.info(f"Interface detectada automaticamente: {self.interface}")
                    else:
                        # Fallback: Tenta pegar a primeira interface não-loopback (mais arriscado)
                        interfaces = netifaces.interfaces()
                        for iface in interfaces:
                            if iface != 'lo':
                                addrs = netifaces.ifaddresses(iface)
                                if netifaces.AF_INET in addrs:
                                     self.interface = iface
                                     logger.warning(f"Gateway padrão não encontrado, usando interface fallback: {self.interface}")
                                     break
                        if not self.interface:
                             raise ValueError("Não foi possível detectar interface padrão e nenhuma interface fallback encontrada.")

                except Exception as e:
                    logger.error(f"Falha ao detectar interface padrão: {e}. Defina 'interface' no config.json.")
                    # Erro fatal se a interface for essencial e não puder ser determinada
                    raise ValueError("Interface de rede não configurada e não pôde ser detectada.") from e

            # Verifica se a interface final é válida (existe no sistema)
            if self.interface not in netifaces.interfaces():
                 raise ValueError(f"Interface de rede '{self.interface}' configurada não existe no sistema.")

            logger.info("Configurações carregadas e validadas com sucesso.")
            logger.info(f"Interface ativa: {self.interface}")
            logger.info(f"Filtro de captura: {self.filter_rules}")
            logger.info(f"Nível de log: {logging.getLevelName(self.log_level)}")

        except Exception as e:
            logger.critical(f"Erro crítico ao carregar ou validar configuração: {e}", exc_info=True)
            raise RuntimeError("Falha ao carregar/validar configuração inicial.") from e

    def _configure_logging(self):
        """Configura o sistema de logging para usar o nível definido (Abordagem Simplificada)."""
        try:
            root_logger = logging.getLogger() # Obtem o logger raiz

            # Remove QUALQUER handler existente do logger raiz (limpeza inicial)
            # Isso garante que handlers do basicConfig ou de chamadas anteriores sejam removidos.
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)

            # Configura o formato da mensagem
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

            # Cria UM handler para escrever em stderr (capturado pelo journald)
            stream_handler = logging.StreamHandler() # Por padrão, usa sys.stderr
            stream_handler.setFormatter(formatter)

            # Adiciona o handler APENAS ao logger raiz
            root_logger.addHandler(stream_handler)

            # Define o nível desejado APENAS no logger raiz
            root_logger.setLevel(self.log_level)

            # Loggers específicos (como o 'logger' = getLogger(__name__)) herdarão
            # o nível e usarão o handler do root automaticamente via propagação.
            # Não precisamos configurar 'logger' diretamente nem mexer em 'propagate'.

            # Usar 'logger' (que é getLogger(__name__)) para a mensagem de confirmação
            logger.info(f"Sistema de logging (simplificado) configurado para nível: {logging.getLevelName(root_logger.getEffectiveLevel())}")
            logger.debug("Mensagem de debug de teste do logging (simplificado).")

        except Exception as e:
            # Se o logging falhar, loga no stderr e continua
            print(f"CRITICAL: Falha ao configurar o logging : {e}")
            logger.critical(f"Falha ao configurar o logging : {e}", exc_info=True) # Tenta logar mesmo assim

    def _configure_rabbitmq_params(self):
        """Carrega os parâmetros do RabbitMQ da configuração."""
        logger.info("Carregando configuração do RabbitMQ...")
        try:
            config_data = self.config_manager.get_config()
            rabbitmq_config = config_data.get('rabbitmq') # Não precisa de default {}, verifica abaixo

            if not rabbitmq_config or not isinstance(rabbitmq_config, dict):
                raise ValueError("Seção 'rabbitmq' não encontrada ou inválida no config.json.")

            self.rabbitmq_host = rabbitmq_config.get('host', self.rabbitmq_host)
            self.rabbitmq_port = int(rabbitmq_config.get('port', self.rabbitmq_port))
            self.rabbitmq_queue = rabbitmq_config.get('queue', self.rabbitmq_queue)

            if not self.rabbitmq_queue:
                 raise ValueError("Nome da fila ('queue') do RabbitMQ não pode ser vazio.")

            logger.info(f"Configuração do RabbitMQ carregada: host={self.rabbitmq_host}, port={self.rabbitmq_port}, queue={self.rabbitmq_queue}")

        except ValueError as e:
             logger.critical(f"Erro na configuração do RabbitMQ: {e}", exc_info=True)
             raise RuntimeError("Configuração inválida para RabbitMQ.") from e
        except Exception as e:
            logger.critical(f"Erro inesperado ao carregar configuração RabbitMQ: {e}", exc_info=True)
            raise RuntimeError("Erro ao carregar configuração RabbitMQ.") from e

    def _connect_to_rabbitmq(self, retries=5, delay=5):
        """Estabelece conexão com o RabbitMQ com tentativas de reconexão."""
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
             logger.debug("Já conectado ao RabbitMQ.")
             return True

        logger.info(f"Tentando conectar ao RabbitMQ em {self.rabbitmq_host}:{self.rabbitmq_port}...")
        for attempt in range(retries):
            try:
                # Fecha conexão anterior se existir e estiver fechada/quebrada
                self._close_rabbitmq_connection()

                self.rabbitmq_connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=self.rabbitmq_host,
                        port=self.rabbitmq_port,
                        heartbeat=600, # Timeout maior para evitar desconexões
                        blocked_connection_timeout=300
                    )
                )
                self.rabbitmq_channel = self.rabbitmq_connection.channel()
                # Declara a fila como durável para persistência
                self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_queue, durable=True)
                logger.info(f"Conectado ao RabbitMQ. Fila '{self.rabbitmq_queue}' declarada/verificada.")
                return True # Conectado com sucesso

            except pika.exceptions.AMQPConnectionError as e:
                logger.error(f"Erro de conexão AMQP com RabbitMQ (tentativa {attempt + 1}/{retries}): {e}")
            except Exception as e:
                logger.error(f"Erro inesperado ao conectar/declarar fila no RabbitMQ (tentativa {attempt + 1}/{retries}): {e}", exc_info=False) # exc_info=False para não poluir

            if attempt < retries - 1:
                logger.info(f"Tentando novamente em {delay} segundos...")
                time.sleep(delay)
            else:
                logger.critical("Falha ao conectar ao RabbitMQ após várias tentativas.")
                # Decide se deve parar o serviço ou apenas continuar sem RabbitMQ
                # self.stop() # Descomente se RabbitMQ for absolutamente essencial
                return False # Falha ao conectar

    def _close_rabbitmq_connection(self):
        """Fecha a conexão com o RabbitMQ de forma segura."""
        # logger.debug("Tentando fechar conexão com o RabbitMQ...") # Log muito verboso
        closed = False
        try:
            if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
                self.rabbitmq_channel.close()
                logger.info("Canal RabbitMQ fechado.")
                closed = True
            if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
                self.rabbitmq_connection.close()
                logger.info("Conexão RabbitMQ fechada.")
                closed = True
        except Exception as e:
            logger.error(f"Erro ao fechar a conexão com o RabbitMQ: {e}", exc_info=True)
        finally:
             self.rabbitmq_channel = None
             self.rabbitmq_connection = None
             # if closed: logger.debug("Recursos RabbitMQ liberados.")


    def start(self):
        """Inicia o serviço principal do IDS e o servidor de controle."""
        if not self.running:
             logger.error("Não é possível iniciar, o controlador já foi parado ou falhou na inicialização.")
             return

        logger.info("Iniciando Controlador IDS...")
        self.service_status = 'starting'
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Tenta conectar ao RabbitMQ ao iniciar
        if not self._connect_to_rabbitmq():
            logger.critical("Não foi possível conectar ao RabbitMQ no início. Verifique a configuração e o servidor RabbitMQ.")
            # Decide se o serviço pode rodar sem RabbitMQ
            # Se não puder, descomente a linha abaixo:
            # self.stop()
            # return # Retorna se RabbitMQ for essencial

        # Inicia o servidor de controle em uma thread separada
        # É importante que a thread de controle possa parar graciosamente
        control_thread = threading.Thread(target=self._start_control_server, name="ControlServerThread", daemon=True)
        control_thread.start()

        # Mantem a thread principal ativa e verificando o status
        logger.info("Controlador IDS pronto. Servidor de controle iniciado.")
        # O status só vai para 'running' quando a captura iniciar
        if self.service_status != 'error': # Se não houve erro até aqui
            self.service_status = 'stopped' # Status inicial é parado (sem captura ativa)

        while self.running:
            try:
                # Verifica se a thread de controle ainda está viva (opcional)
                # if not control_thread.is_alive():
                #     logger.error("Thread do servidor de controle terminou inesperadamente.")
                #     self.stop()
                #     break
                time.sleep(1) # Loop principal pode fazer verificações periódicas
            except Exception as e:
                 logger.error(f"Erro no loop principal do controlador: {e}", exc_info=True)
                 self.stop() # Parar em caso de erro inesperado no loop

        logger.info("Loop principal do controlador encerrado.")
        # Garante que a limpeza final ocorra se sair do loop por outras razões
        self._cleanup()


    def _start_control_server(self):
        """Inicia o servidor socket para receber comandos."""
        server_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            # Define um timeout para o listen/accept não bloquear indefinidamente
            server_socket.settimeout(2.0)
            logger.info(f"Servidor de controle ouvindo em {self.host}:{self.port}")

            while self.running:
                conn = None
                addr = None
                try:
                    try:
                        conn, addr = server_socket.accept()
                        # logger.debug(f"Conexão de controle recebida de {addr}")
                        # Define timeout para a comunicação com o cliente
                        conn.settimeout(60.0)
                        # Cria uma nova thread para cada conexão de controle
                        handler_thread = threading.Thread(
                            target=self._handle_connection,
                            args=(conn, addr),
                            name=f"ControlHandler-{addr}",
                            daemon=True # Permite que o programa saia mesmo se essas threads estiverem ativas
                        )
                        handler_thread.start()
                    except socket.timeout:
                        # Timeout é esperado para verificar self.running
                        continue
                    except OSError as e:
                         # Pode ocorrer se o socket for fechado enquanto em accept()
                         if self.running:
                              logger.error(f"Erro de socket no accept(): {e}")
                         break # Sai do loop se o socket tiver problemas sérios

                except Exception as e:
                    # Erros ao iniciar a thread ou outros problemas
                    if self.running:
                        logger.error(f"Erro ao lidar com nova conexão de controle de {addr}: {e}", exc_info=True)
                    if conn:
                         try:
                              conn.close()
                         except: pass # Ignora erros ao fechar conexão com erro

        except OSError as e:
            logger.critical(f"Erro CRÍTICO ao iniciar servidor de controle em {self.host}:{self.port} - {e}. Verifique se a porta está em uso.", exc_info=True)
            self.service_status = 'error'
            self.running = False # Sinaliza para parar tudo
        except Exception as e:
            logger.critical(f"Erro CRÍTICO inesperado no servidor de controle: {e}", exc_info=True)
            self.service_status = 'error'
            self.running = False
        finally:
            if server_socket:
                try:
                    server_socket.close()
                except Exception as e:
                     logger.error(f"Erro ao fechar socket do servidor de controle: {e}")
            logger.info("Servidor de controle encerrado.")


    def _handle_connection(self, conn, addr):
        """Processa uma conexão de controle."""
        command = "N/A"
        response = b"Internal server error" # Default
        try:
            with conn: # Garante que conn.close() seja chamado
                data_bytes = conn.recv(1024)
                if not data_bytes:
                    logger.warning(f"Conexão de {addr} fechada sem enviar dados.")
                    return

                command = data_bytes.decode('utf-8', errors='ignore').strip().lower()
                logger.info(f"Comando '{command}' recebido de {addr}")

                if command == 'start' or command == 'iniciar':
                    response = self._start_capture()
                elif command == 'stop' or command == 'parar':
                    response = self._stop_capture()
                elif command == 'status':
                    # Inclui status da captura e talvez conectividade RabbitMQ
                    capture_status = 'running' if self.capturer and self.capturer.is_alive() else 'stopped'
                    mq_status = 'connected' if self.rabbitmq_channel and self.rabbitmq_channel.is_open else 'disconnected'
                    response_str = f"Service: {self.service_status}, Capture: {capture_status}, RabbitMQ: {mq_status}"
                    response = response_str.encode('utf-8')
                elif command == 'get_config':
                    try:
                        config_data = self.config_manager.get_config()
                        # Adiciona informações de estado atuais à resposta
                        runtime_info = {
                            'active_interface': self.interface,
                            'active_filter': self.filter_rules,
                            'active_log_level': logging.getLevelName(logger.getEffectiveLevel()),
                            'service_status': self.service_status,
                            'capture_running': bool(self.capturer and self.capturer.is_alive()),
                            'rabbitmq_connected': bool(self.rabbitmq_channel and self.rabbitmq_channel.is_open)
                        }
                        # Merge runtime info into a copy of config_data to avoid modifying the original
                        response_data = {**config_data, 'runtime_info': runtime_info}

                        response = json.dumps(response_data, indent=2, default=str).encode('utf-8') # default=str para lidar com tipos não serializáveis
                    except Exception as e:
                        logger.error(f"Erro ao obter/serializar configuração para {addr}: {e}", exc_info=True)
                        response = b"Error getting or formatting config"
                elif command == 'shutdown': # Comando para parar o serviço inteiro
                     response = b"Shutdown initiated"
                     self.stop() # Inicia o processo de parada total
                else:
                    response = b"Invalid command"

                conn.sendall(response)
                # Log limitado da resposta para evitar poluição com config grande
                response_log = response if len(response) < 200 else response[:197] + b'...'
                logger.debug(f"Resposta enviada para {addr} para comando '{command}': {response_log.decode('utf-8', errors='ignore')}")

        except socket.timeout:
            logger.warning(f"Conexão de controle com {addr} expirou (timeout) ao receber/enviar.")
        except (socket.error, ConnectionResetError) as e:
            logger.warning(f"Erro de socket na conexão de controle com {addr}: {e}")
        except Exception as e:
            logger.error(f"Erro ao processar comando '{command}' de {addr}: {e}", exc_info=True)
            # Tenta enviar uma mensagem de erro genérica se possível
            try:
                conn.sendall(b"Error processing command on server")
            except:
                pass # Ignora se não conseguir enviar
        finally:
             logger.debug(f"Conexão de controle com {addr} fechada.")


    def _start_capture(self):
        """Inicia a captura de pacotes em uma thread separada."""
        if self.capturer and self.capturer.is_alive():
            logger.warning("Tentativa de iniciar captura que já está rodando.")
            return b"Capture already running"

        if not self.interface:
            logger.error("Não é possível iniciar a captura: interface de rede não definida.")
            self.service_status = 'error'
            return b"Error: Network interface not set"

        logger.info(f"Iniciando captura na interface: {self.interface} com filtro: '{self.filter_rules}'")
        try:
            # Garante que estamos conectados ao RabbitMQ antes de iniciar a captura
            if not self._connect_to_rabbitmq():
                 logger.error("Falha ao conectar/reconectar ao RabbitMQ. Não é possível iniciar a captura.")
                 self.service_status = 'error'
                 return b"Error: Cannot connect to RabbitMQ"

            # Cria e inicia o capturador
            self.capturer = PacketCapturer(
                interface=self.interface,
                packet_handler=self._process_packet,
                filter_rules=self.filter_rules,
                #stop_event=threading.Event() Passa um evento para parada limpa
            )
            self.capturer.start() # Inicia a thread de captura (deve ser Thread)
            time.sleep(0.5) # Pequena pausa para a thread iniciar

            if self.capturer.is_alive():
                 self.service_status = 'running'
                 logger.info("Captura de pacotes iniciada com sucesso.")
                 return b"Capture started"
            else:
                 logger.error("Thread de captura não iniciou corretamente.")
                 self.service_status = 'error'
                 self.capturer = None
                 return b"Error: Capture thread failed to start"

        except Exception as e:
            logger.error(f"Falha CRÍTICA ao iniciar a thread de captura: {e}", exc_info=True)
            self.service_status = 'error'
            self.capturer = None # Garante que não fique em estado inconsistente
            return b"Error starting capture thread"


    def _stop_capture(self):
        """Para a thread de captura de pacotes."""
        if self.capturer and self.capturer.is_alive():
            logger.info("Parando a captura de pacotes...")
            try:
                self.capturer.stop() # Sinaliza para a thread parar (via stop_event)
                #self.capturer.join(timeout=10.0) # Espera a thread terminar

                if self.capturer.is_alive():
                    logger.warning("Timeout ao esperar a thread de captura terminar. Pode haver pacotes sendo processados.")
                    # Considerar medidas mais drásticas se necessário
                else:
                    logger.info("Thread de captura terminada com sucesso.")

            except Exception as e:
                logger.error(f"Erro ao parar/juntar a thread de captura: {e}", exc_info=True)
                # Mesmo com erro, consideramos parado para fins de status
            finally:
                 self.capturer = None # Libera a referência
                 self.service_status = 'stopped'
                 logger.info("Captura de pacotes finalizada.")
                 return b"Capture stopped"
        else:
            logger.info("Captura de pacotes já estava parada.")
            self.service_status = 'stopped' # Garante que o status está correto
            return b"Capture not running"


    def _process_packet(self, packet):
        """Normaliza o pacote, loga no Journal e envia para o RabbitMQ."""
        if not self.running: # Verifica se o serviço está parando
            return
        try:
            processed = PacketNormalizer.normalize(packet)

            if processed:
                # Validação de IP (essencial)
                src_ip = processed.get('src_ip')
                dst_ip = processed.get('dst_ip')
                if not self._validate_ip(src_ip) or not self._validate_ip(dst_ip):
                    logger.warning(f"IP inválido detectado no pacote: SRC='{src_ip}', DST='{dst_ip}'. Pacote descartado.")
                    # Log extra opcional com mais detalhes:
                    # logger.debug("Detalhes do pacote com IP inválido:", extra={'PACKET_DETAILS': str(processed)})
                    return

                # ---- Log Estruturado para Systemd Journal ----
                # Converte todos os valores para string para segurança no Journal
                extra_data = {
                    'NETWORK_PROTOCOL': str(processed.get('protocol', 'UNKNOWN')).upper(),
                    'SOURCE_IP': str(src_ip),
                    'DESTINATION_IP': str(dst_ip),
                    'SOURCE_PORT': str(processed.get('src_port', 'N/A')),
                    'DESTINATION_PORT': str(processed.get('dst_port', 'N/A')),
                    'SOURCE_MAC': str(processed.get('src_mac', 'N/A')),
                    'DESTINATION_MAC': str(processed.get('dst_mac', 'N/A')),
                    'PACKET_SIZE': str(processed.get('packet_size', -1)),
                    'IP_VERSION': str(processed.get('ip_version', 'N/A')),
                    'TCP_FLAGS': str(processed.get('tcp_flags', 'N/A')),
                    # Adicionar mais campos normalizados aqui, sempre como string
                    'TIMESTAMP_PROCESS': time.strftime('%Y-%m-%dT%H:%M:%S%z') # Timestamp do processamento
                }
                # Logar em nível DEBUG para não poluir o log principal
                logger.debug("Packet processed", extra=extra_data)
                # ---- Fim do Log Estruturado ----


                # ---- Envia para o RabbitMQ ----
                try:
                    # Verifica conexão antes de publicar
                    if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                         logger.warning("Canal RabbitMQ fechado/indisponível. Tentando reconectar antes de publicar...")
                         if not self._connect_to_rabbitmq(retries=1, delay=1): # Tenta reconectar rapidamente
                              logger.error("Falha ao reconectar ao RabbitMQ. Mensagem perdida.")
                              # Considerar fila de espera local ou descarte
                              return # Perde a mensagem atual

                    message_body = json.dumps(processed, default=str) # default=str para segurança
                    self.rabbitmq_channel.basic_publish(
                        exchange='',
                        routing_key=self.rabbitmq_queue,
                        body=message_body,
                        properties=pika.BasicProperties(
                            delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE # Mensagens persistentes
                        )
                    )
                    # logger.debug(f"Pacote publicado na fila '{self.rabbitmq_queue}'") # Log muito verboso

                except (pika.exceptions.AMQPConnectionError, pika.exceptions.ChannelClosedByBroker, pika.exceptions.StreamLostError) as e:
                     logger.error(f"Erro de conexão/canal com RabbitMQ ao publicar: {e}. Tentará reconectar na próxima vez.")
                     self._close_rabbitmq_connection() # Força fechamento para tentar reconexão
                except Exception as e:
                    logger.error(f"Erro inesperado ao publicar mensagem no RabbitMQ: {e}", exc_info=True)
                    # Considerar estratégia de retry ou dead-letter queue

        except Exception as e:
            logger.error(f"Erro durante o processamento/normalização do pacote: {e}", exc_info=True)
            # Tentar logar informações básicas do pacote original se possível
            try:
                if packet:
                     summary = packet.summary() if hasattr(packet, 'summary') else 'No summary'
                     logger.error(f"Detalhes do pacote bruto (resumo): {summary[:200]}") # Limita tamanho
            except:
                pass # Evita erros no tratamento de erro

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Valida se uma string é um endereço IP válido (IPv4 ou IPv6)."""
        if not ip or not isinstance(ip, str):
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    # Removido _log_packet por redundância com log estruturado

    def _signal_handler(self, signum, frame):
        """Manipula sinais de desligamento (SIGINT, SIGTERM)."""
        signal_name = signal.Signals(signum).name
        logger.warning(f"Sinal {signal_name} ({signum}) recebido. Iniciando encerramento gracioso...")
        # Inicia a parada em uma nova thread para não bloquear o handler
        # Embora 'stop' tente ser rápido, é mais seguro não fazer trabalho pesado no handler
        if self.running: # Evita múltiplas chamadas se o sinal for repetido
             # Não inicia thread aqui, apenas seta a flag. O loop principal ou join() cuida.
             self.running = False
             logger.info("Flag 'running' definida como False. Serviço irá parar.")
             # A chamada self.stop() será feita no _cleanup() ou ao sair do loop principal
        else:
             logger.warning("Sinal recebido, mas o serviço já estava em processo de parada.")


    def stop(self):
        """Inicia o processo de parada graciosa do serviço."""
        if not self.running:
            # logger.info("Processo de parada já iniciado.")
            return # Evita múltiplas chamadas concorrentes

        logger.info("Iniciando procedimento de parada do serviço...")
        self.running = False # Sinaliza para todos os loops pararem
        # Chama a limpeza real. Isso pode ser chamado pelo signal handler indiretamente
        # ou pelo comando 'shutdown' ou no final do loop principal
        self._cleanup()


    def _cleanup(self):
         """Realiza a parada efetiva dos componentes."""
         logger.info("Executando limpeza dos recursos...")

         # 1. Para a captura de pacotes primeiro
         try:
             self._stop_capture()
         except Exception as e:
             logger.error(f"Erro durante _stop_capture na limpeza: {e}", exc_info=True)

         # 2. Fecha a conexão com RabbitMQ
         try:
             self._close_rabbitmq_connection()
         except Exception as e:
             logger.error(f"Erro durante _close_rabbitmq_connection na limpeza: {e}", exc_info=True)

         # 3. Outras limpezas se necessário (ex: fechar socket de controle já é feito no finally da thread)

         self.service_status = 'stopped'
         logger.info("Controlador IDS e seus componentes foram parados.")
         # Não chamar exit() aqui, deixa o fluxo principal terminar


# --- Ponto de Entrada Principal ---
if __name__ == "__main__":
    controller = None
    exit_code = 0
    try:
        logger.info("Iniciando aplicação IDS...")
        controller = IDSController()
        controller.start() # Bloqueia ou executa até self.running ser False
    except RuntimeError as e:
        # Erros fatais durante a inicialização já logados no __init__
        logger.critical(f"Encerrando devido a erro fatal na inicialização: {e}")
        exit_code = 1
    except KeyboardInterrupt:
        logger.warning("Interrupção pelo teclado (Ctrl+C) detectada no nível principal.")
        exit_code = 0 # Saída normal após Ctrl+C
    except Exception as e:
        logger.critical(f"Erro não tratado no nível principal ('__main__'): {e}", exc_info=True)
        exit_code = 1 # Erro inesperado
    finally:
        logger.info("Aplicação IDS encerrando...")
        if controller and controller.running: # Se ainda estiver rodando (ex: KeyboardInterrupt)
            logger.info("Chamando controller.stop() na saída final.")
            controller.stop() # Tenta parada graciosa
        logger.info(f"Aplicação IDS finalizada com código de saída: {exit_code}")
        # Opcional: Esperar um pouco para garantir que os logs sejam escritos
        # time.sleep(1)
        exit(exit_code) # Encerra o processo