import logging
from systemd.journal import JournalHandler # <-- Adicionado
import time
import threading
import signal
import socket
import ipaddress
import netifaces
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from config import ConfigManager # Presume que este arquivo existe e funciona
from packet_processor import PacketCapturer # Presume que este arquivo existe e funciona
from data_processing import PacketNormalizer # Presume que este arquivo existe e funciona
import json
import pika # Importa pika

# Define o logger globalmente para que possa ser configurado no __init__
logger = logging.getLogger(__name__)

class IDSController:
    def __init__(self):
        """Inicializa o controlador do IDS."""
        self.config = ConfigManager()
        self.capturer = None
        self.running = True
        self.service_status = 'stopped'
        self.buffer = [] # Buffer interno (considerar se ainda é necessário com RabbitMQ)
        self.buffer_lock = threading.Lock()
        
        # Carrega configurações ANTES de configurar o logging
        self._load_configuration()

        # ---- Configuração do Logging para Systemd Journal ----
        # Remove handlers pré-existentes para evitar duplicação
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # Define o nível de log no logger principal
        logger.setLevel(self.log_level) # Nível definido em _load_configuration

        # Cria e adiciona o Journal Handler
        journal_handler = JournalHandler()
        # Opcional: Definir um formatador para o campo MESSAGE=
        # formatter = logging.Formatter('%(levelname)s - %(message)s')
        # journal_handler.setFormatter(formatter)
        logger.addHandler(journal_handler)

        # Opcional: Handler para console (útil para debug) - Comente/Remova em produção se não necessário
        # stream_handler = logging.StreamHandler()
        # stream_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        # stream_handler.setFormatter(stream_formatter)
        # logger.addHandler(stream_handler)
        # ---- Fim da Configuração do Logging ----

        logger.info(f"Nível de log configurado para: {logging.getLevelName(self.log_level)}")

        # Configurações do RabbitMQ
        self.rabbitmq_host = self.config.get_config()['rabbitmq'].get('host', 'localhost')
        self.rabbitmq_port = int(self.config.get_config()['rabbitmq'].get('port', 5672))
        self.rabbitmq_queue = self.config.get_config()['rabbitmq'].get('queue', 'pacotes')
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None

    def _load_configuration(self):
        """Carrega configurações de arquivos."""
        logger.info("Carregando configurações...") # Log inicial pode ir para stderr se journald não estiver pronto
        try:
            config_data = self.config.get_config()
            settings = config_data.get('settings', {})
            self.host = settings.get('service_host', 'localhost')
            self.port = int(settings.get('service_port', 65432))
            self.interface = settings.get('interface', None) # Use None se não especificado
            if not self.interface:
                logger.warning("Interface de rede não especificada nas configurações. Tentando detectar automaticamente ou usar padrão.")
                # Adicione lógica para detectar interface padrão se necessário, ou use um valor fixo como fallback.
                # Exemplo simples (pode não funcionar em todos os sistemas):
                try:
                    default_gateway = netifaces.gateways()['default']
                    if netifaces.AF_INET in default_gateway:
                        self.interface = default_gateway[netifaces.AF_INET][1]
                        logger.info(f"Interface detectada automaticamente: {self.interface}")
                    else:
                        raise Exception("Não foi possível detectar interface padrão.")
                except Exception as e:
                    logger.error(f"Falha ao detectar interface padrão: {e}. Defina 'interface' no config.json.")
                    # Defina um padrão se a detecção falhar ou gere um erro fatal
                    # self.interface = 'eth0' # Exemplo de fallback
                    raise ValueError("Interface de rede não configurada e não pôde ser detectada.")

            self.filter_rules = settings.get('filter', 'ip') # Filtro padrão 'ip'

            log_level_str = settings.get('log_level', 'INFO').upper()
            self.log_level = getattr(logging, log_level_str, logging.INFO)
            # IMPORTANTE: REMOVIDO -> logging.basicConfig(level=self.log_level)
            logger.info("Configurações carregadas com sucesso.")

        except Exception as e:
            logger.critical(f"Erro crítico ao carregar configuração: {e}", exc_info=True)
            # Encerrar ou usar valores padrão seguros se a configuração falhar
            raise RuntimeError("Falha ao carregar configuração inicial.") from e


    def _connect_to_rabbitmq(self, retries=3, delay=5):
        """Estabelece conexão com o RabbitMQ com tentativas de reconexão."""
        logger.info(f"Tentando conectar ao RabbitMQ em {self.rabbitmq_host}:{self.rabbitmq_port}...")
        for attempt in range(retries):
            try:
                self.rabbitmq_connection = pika.BlockingConnection(
                    pika.ConnectionParameters(host=self.rabbitmq_host, port=self.rabbitmq_port)
                )
                self.rabbitmq_channel = self.rabbitmq_connection.channel()
                # Declara a fila como durável
                self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_queue, durable=True)
                logger.info(f"Conectado ao RabbitMQ. Fila declarada: '{self.rabbitmq_queue}'")
                return # Conectado com sucesso
            except Exception as e:
                logger.error(f"Erro ao conectar ao RabbitMQ (tentativa {attempt + 1}/{retries}): {e}", exc_info=False) # exc_info=False para não poluir tanto em tentativas
                if attempt < retries - 1:
                    time.sleep(delay)
                else:
                    logger.critical("Falha ao conectar ao RabbitMQ após várias tentativas.")
                    # Considerar se deve parar o serviço ou tentar reconectar mais tarde
                    self.stop() # Parar o serviço se RabbitMQ for essencial

    def _close_rabbitmq_connection(self):
        """Fecha a conexão com o RabbitMQ de forma segura."""
        logger.info("Tentando fechar conexão com o RabbitMQ...")
        try:
            if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
                self.rabbitmq_channel.close()
                logger.info("Canal RabbitMQ fechado.")
            if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
                self.rabbitmq_connection.close()
                logger.info("Conexão RabbitMQ fechada.")
        except Exception as e:
            logger.error(f"Erro ao fechar a conexão com o RabbitMQ: {e}", exc_info=True)

    def start(self):
        """Inicia o serviço principal do IDS e o servidor de controle."""
        logger.info("Iniciando Controlador IDS...")
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Conecta ao RabbitMQ ao iniciar
        self._connect_to_rabbitmq()
        if not self.running: # Se a conexão com RabbitMQ falhou e chamou stop()
             logger.critical("Não foi possível iniciar o serviço devido à falha na conexão com RabbitMQ.")
             return

        # Inicia o servidor de controle em uma thread separada
        control_thread = threading.Thread(target=self._start_control_server, daemon=True)
        control_thread.start()
        
        # Mantem a thread principal ativa (ou pode iniciar a captura aqui se preferir)
        logger.info("Controlador IDS iniciado. Use um cliente para enviar comandos (start, stop, status, get_config).")
        while self.running:
             time.sleep(1) # Loop principal pode esperar ou fazer outras tarefas de monitoramento

        logger.info("Loop principal do controlador encerrado.")


    def _start_control_server(self):
        """Inicia o servidor socket para receber comandos."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(5)
                logger.info(f"Servidor de controle ouvindo em {self.host}:{self.port}")

                while self.running:
                    try:
                        # Define um timeout pequeno para o accept para verificar self.running periodicamente
                        s.settimeout(1.0)
                        conn, addr = s.accept()
                        s.settimeout(None) # Remove timeout para a conexão ativa
                        logger.info(f"Conexão de controle recebida de {addr}")
                        # Cria uma nova thread para cada conexão de controle
                        threading.Thread(
                            target=self._handle_connection,
                            args=(conn, addr),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        continue # Timeout é esperado, volta para verificar self.running
                    except Exception as e:
                         if self.running: # Loga erro apenas se não estivermos parando
                              logger.error(f"Erro no accept do servidor de controle: {e}", exc_info=True)
                         time.sleep(0.5) # Evita loop de erro muito rápido

        except OSError as e:
             logger.critical(f"Erro ao iniciar servidor de controle em {self.host}:{self.port} - {e}. Verifique se a porta está em uso.", exc_info=True)
             self.stop() # Para o serviço se o servidor de controle não puder iniciar
        except Exception as e:
            logger.critical(f"Erro inesperado no servidor de controle: {e}", exc_info=True)
            self.stop()
        finally:
             logger.info("Servidor de controle encerrado.")


    def _handle_connection(self, conn, addr):
        """Processa conexões de controle para iniciar/parar captura, etc."""
        conn.settimeout(30) # Timeout mais longo para interação
        command = "N/A" # Inicializa
        try:
            with conn:
                data_bytes = conn.recv(1024)
                if not data_bytes:
                    logger.warning(f"Conexão de {addr} fechada sem enviar dados.")
                    return

                command = data_bytes.decode().strip().lower()
                logger.info(f"Comando '{command}' recebido de {addr}")
                response = b"Invalid command" # Resposta padrão

                if command == 'start' or command == 'iniciar':
                    response = self._start_capture()
                elif command == 'stop' or command == 'parar':
                    response = self._stop_capture()
                elif command == 'status':
                    response = self.service_status.encode()
                elif command == 'get_config':
                    try:
                        config_data = self.config.get_config()
                        # Inclui configurações ativas que podem ter sido detectadas
                        config_data['settings']['active_interface'] = self.interface
                        config_data['settings']['active_filter'] = self.filter_rules
                        config_data['settings']['active_log_level'] = logging.getLevelName(logger.getEffectiveLevel())
                        response = json.dumps(config_data, indent=2).encode()
                    except Exception as e:
                         logger.error(f"Erro ao obter configuração para {addr}: {e}", exc_info=True)
                         response = b"Error getting config"
                # Adicione mais comandos aqui se necessário

                conn.sendall(response)
                logger.info(f"Resposta enviada para {addr} para o comando '{command}': {response.decode(errors='ignore')[:100]}...")

        except socket.timeout:
            logger.warning(f"Conexão de controle com {addr} expirou (timeout).")
        except socket.error as e:
             logger.error(f"Erro de socket na conexão de controle com {addr}: {e}")
        except Exception as e:
            logger.error(f"Erro ao processar comando '{command}' de {addr}: {e}", exc_info=True)
        finally:
             logger.info(f"Conexão de controle com {addr} fechada.")

    def _start_capture(self):
        """Inicia a captura de pacotes em uma thread separada."""
        if self.capturer and self.capturer.is_alive():
            logger.warning("Tentativa de iniciar captura que já está rodando.")
            return b"Capture already running"

        if not self.interface:
             logger.error("Não é possível iniciar a captura: interface de rede não definida.")
             return b"Error: Network interface not set"

        logger.info(f"Iniciando captura na interface: {self.interface} com filtro: '{self.filter_rules}'")
        try:
            # Garante que estamos conectados ao RabbitMQ antes de iniciar a captura
            if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                logger.warning("Conexão com RabbitMQ perdida ou não estabelecida. Tentando reconectar...")
                self._connect_to_rabbitmq()
                if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                     logger.error("Falha ao reconectar ao RabbitMQ. Não é possível iniciar a captura.")
                     return b"Error: Cannot connect to RabbitMQ"

            self.capturer = PacketCapturer(
                interface=self.interface,
                packet_handler=self._process_packet,
                filter_rules=self.filter_rules
            )
            self.capturer.start() # Inicia a thread de captura
            self.service_status = 'running'
            logger.info("Captura de pacotes iniciada.")
            return b"Capture started"
        except Exception as e:
             logger.error(f"Falha ao iniciar a thread de captura: {e}", exc_info=True)
             self.service_status = 'error'
             return b"Error starting capture thread"


    def _stop_capture(self):
        """Para a thread de captura de pacotes."""
        if self.capturer and self.capturer.is_alive():
            logger.info("Parando a captura de pacotes...")
            try:
                self.capturer.stop() # Sinaliza para a thread parar
                self.capturer.join(timeout=5.0) # Espera a thread terminar com timeout
                if self.capturer.is_alive():
                     logger.warning("Timeout ao esperar a thread de captura terminar. Pode haver pacotes pendentes.")
                else:
                     logger.info("Thread de captura terminada com sucesso.")
                self.service_status = 'stopped'
                self.capturer = None
                return b"Capture stopped"
            except Exception as e:
                 logger.error(f"Erro ao parar a captura: {e}", exc_info=True)
                 self.service_status = 'error'
                 return b"Error stopping capture"
        else:
            logger.warning("Tentativa de parar captura que não está rodando.")
            self.service_status = 'stopped' # Garante que o status está correto
            return b"Capture not running"

    def _process_packet(self, packet):
        """Normaliza o pacote, loga no Journal e envia para o RabbitMQ."""
        try:
            # Normaliza o pacote usando a classe externa
            processed = PacketNormalizer.normalize(packet)

            if processed: # Se a normalização retornou dados válidos
                # Validação básica de IP (pode ser expandida)
                if not self._validate_ip(processed.get('src_ip')) or not self._validate_ip(processed.get('dst_ip')):
                    logger.warning(
                        "Invalid IP address detected in processed packet",
                        extra={
                            'SOURCE_IP': processed.get('src_ip', 'N/A'),
                            'DESTINATION_IP': processed.get('dst_ip', 'N/A'),
                            'SOURCE_MAC': processed.get('src_mac', 'N/A'),
                            'DESTINATION_MAC': processed.get('dst_mac', 'N/A'),
                            # Adicione outros campos se úteis para depurar IP inválido
                        }
                    )
                    return # Não processa pacote com IP inválido

                # ---- Log Estruturado para Systemd Journal ----
                log_level = logging.DEBUG # Use DEBUG para info detalhada, INFO para menos verboso
                logger.log(
                    log_level,
                    "Packet processed", # Mensagem curta e genérica
                    extra={
                        # Campos derivados do pacote normalizado
                        # Garantir que as chaves existem e são strings
                        'NETWORK_PROTOCOL': str(processed.get('protocol', 'UNKNOWN')).upper(),
                        'SOURCE_IP': str(processed.get('src_ip', 'N/A')),
                        'DESTINATION_IP': str(processed.get('dst_ip', 'N/A')),
                        'SOURCE_PORT': str(processed.get('src_port', 'N/A')),
                        'DESTINATION_PORT': str(processed.get('dst_port', 'N/A')),
                        'SOURCE_MAC': str(processed.get('src_mac', 'N/A')),
                        'DESTINATION_MAC': str(processed.get('dst_mac', 'N/A')),
                        'PACKET_SIZE': str(processed.get('packet_size', -1)),
                        'IP_VERSION': str(processed.get('ip_version', 'N/A')),
                        'TCP_FLAGS': str(processed.get('tcp_flags', 'N/A')), # Exemplo adicional
                        # Adicione mais campos relevantes que PacketNormalizer possa extrair
                    }
                )
                # ---- Fim do Log Estruturado ----

                # Lógica do buffer - Opcional, pode ser removida se RabbitMQ for confiável
                # with self.buffer_lock:
                #     if len(self.buffer) >= 1000:
                #         logger.warning("Internal buffer full, discarding oldest packets.")
                #         self.buffer.pop(0)
                #     self.buffer.append(processed)

                # Envia para o RabbitMQ
                try:
                    # Garante que o canal está aberto antes de publicar
                    if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                         logger.warning("Canal RabbitMQ fechado. Tentando reconectar antes de publicar...")
                         self._connect_to_rabbitmq() # Tenta reconectar
                         if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                              logger.error("Falha ao reconectar ao RabbitMQ. Mensagem perdida.")
                              return # Perde a mensagem atual

                    message_body = json.dumps(processed)
                    self.rabbitmq_channel.basic_publish(
                        exchange='',
                        routing_key=self.rabbitmq_queue,
                        body=message_body,
                        properties=pika.BasicProperties(
                            delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE # Mensagens persistentes
                        )
                    )
                    # Log de debug para publicação no RabbitMQ (pode ser removido se muito verboso)
                    # logger.debug(f"Packet data published to RabbitMQ queue '{self.rabbitmq_queue}'")

                except Exception as e:
                    logger.error(f"Error publishing message to RabbitMQ: {e}", exc_info=True)
                    # Considerar uma estratégia de retry ou fila morta aqui

        except Exception as e:
            # Loga erros durante a normalização ou processamento geral
            logger.error(f"Error processing packet data: {e}", exc_info=True)
            # Tentar logar informações básicas do pacote original se possível e seguro
            try:
                 if packet and packet.haslayer(IP):
                      logger.error("Packet details (if available): SRC=%s DST=%s", packet[IP].src, packet[IP].dst)
            except:
                 pass # Evita erros dentro do tratamento de erro

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Valida se uma string é um endereço IP válido (IPv4 ou IPv6)."""
        if not ip or not isinstance(ip, str):
             return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            # Não loga aqui, o chamador (_process_packet) decide se loga
            return False

    def _log_packet(self, packet_info):
        """Registra informações detalhadas do pacote (Opcional/Redundante).
        Esta função pode ser removida se o log estruturado em _process_packet for suficiente.
        """
        logger.info("***** Pacote Capturado Detalhado (Função _log_packet) *****")
        for key, value in packet_info.items():
             logger.info(f"  {key}: {value}")
        logger.info("***** Fim do Pacote Detalhado *****\n")


    def _signal_handler(self, signum, frame):
        """Manipula sinais de desligamento como SIGINT (Ctrl+C) e SIGTERM."""
        signal_name = signal.Signals(signum).name
        logger.warning(f"Recebido sinal {signal_name} ({signum}). Iniciando encerramento gracioso...")
        self.stop()
        # Dê um tempo extra para logs finais serem escritos, se necessário
        time.sleep(0.5)
        # Sair explicitamente após tentar parar tudo
        exit(0)

    def stop(self):
        """Para todos os componentes do serviço de forma graciosa."""
        if not self.running:
             logger.info("O serviço já está parado ou em processo de parada.")
             return

        logger.info("Iniciando procedimento de parada do serviço...")
        self.running = False # Sinaliza para todos os loops pararem

        # Para a captura primeiro
        try:
            self._stop_capture()
        except Exception as e:
            logger.error(f"Erro durante _stop_capture: {e}", exc_info=True)

        # Fecha a conexão com RabbitMQ
        try:
            self._close_rabbitmq_connection()
        except Exception as e:
            logger.error(f"Erro durante _close_rabbitmq_connection: {e}", exc_info=True)

        # Outras limpezas se necessário (ex: fechar socket de controle explicitamente se não usar 'with')

        self.service_status = 'stopped'
        logger.info("Controlador IDS e seus componentes foram parados.")


if __name__ == "__main__":
    # Configuração inicial de logging (vai para stderr até o JournalHandler ser configurado no __init__)
    # Isso é útil para ver erros que ocorrem ANTES do __init__ do IDSController terminar.
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    try:
        ids_controller = IDSController()
        ids_controller.start() # Inicia o controlador (que inicia o servidor de controle)
    except RuntimeError as e:
         # Erros fatais durante a inicialização (ex: falha ao carregar config)
         logger.critical(f"Falha na inicialização do IDSController: {e}", exc_info=True)
         exit(1) # Termina com código de erro
    except KeyboardInterrupt:
         logger.warning("Interrupção pelo teclado detectada (Ctrl+C fora do signal handler?). Encerrando.")
         # Tenta chamar stop se o objeto foi criado
         if 'ids_controller' in locals() and ids_controller:
              ids_controller.stop()
    except Exception as e:
         logger.critical(f"Erro não tratado no nível principal: {e}", exc_info=True)
         exit(1) # Termina com código de erro