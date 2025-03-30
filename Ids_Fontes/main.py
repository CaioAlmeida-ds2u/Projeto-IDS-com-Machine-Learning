# main.py - Aprimorado com Status JSON e Health API Opcional

import logging
import time
import threading
import signal
import socket
import ipaddress
import netifaces
import json
import pika
import copy
import os # << Adicionado
from typing import Optional, Dict, Any # << Ajustado

# Import Flask apenas se a Health API for usada
try:
    from flask import Flask, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Scapy imports (assumindo que estão corretos)
# (Pode ser necessário ajustar dependendo da sua instalação Scapy)
try:
    from scapy.packet import Packet
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    import scapy.all as scapy # Para get_if_list
except ImportError as e:
    print(f"ERRO: Falha ao importar Scapy. Verifique a instalação: {e}")
    # Saída ou tratamento alternativo se Scapy for essencial
    exit(1)

# Importações locais do projeto
try:
    from config import ConfigManager
    from packet_processor import PacketCapturer
    from data_processing import PacketNormalizer
    from redis_client import RedisClient
except ImportError as e:
    print(f"ERRO: Falha ao importar módulos locais (config, packet_processor, etc.): {e}")
    print("Certifique-se que os arquivos .py estão no mesmo diretório ou no PYTHONPATH.")
    exit(1)

# Configuração inicial do Logger (será reconfigurado)
# Usar INFO como padrão inicial pode ser menos verboso antes da config carregar
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__) # Logger específico para este módulo

class IDSController:
    def __init__(self):
        """Inicializa o controlador do IDS."""
        logger.info("Inicializando IDSController...")
        self.config_manager: Optional[ConfigManager] = None
        self.capturer: Optional[PacketCapturer] = None
        self.redis_client: Optional[RedisClient] = None
        self.rabbitmq_connection: Optional[pika.BlockingConnection] = None
        self.rabbitmq_channel: Optional[pika.channel.Channel] = None

        self.running = True
        self.service_status = 'initializing'
        self.control_server_thread: Optional[threading.Thread] = None
        self.health_api_thread: Optional[threading.Thread] = None # Para a API de health opcional

        # Configurações de rede e serviço (serão carregadas)
        self.host = 'localhost'
        self.port = 65432
        self.interface: Optional[str] = None
        self.filter_rules = 'ip or ip6' # Filtro padrão mais abrangente
        self.log_level = logging.INFO
        self.health_api_port = 5005 # Porta padrão para health API opcional

        # Configurações RabbitMQ (serão carregadas)
        self.rabbitmq_host = 'localhost'
        self.rabbitmq_port = 5672
        self.rabbitmq_packet_queue = 'ids_packet_analysis_queue' # Padrão

        try:
            # 1. Carrega ConfigManager
            self.config_manager = ConfigManager()
            # 2. Carrega configurações gerais
            self._load_configuration()
            # 3. Configura o logging com base no nível carregado
            self._configure_logging()
            # 4. Carrega parâmetros específicos do RabbitMQ
            self._configure_rabbitmq_params()
            # 5. Inicializa o cliente Redis
            self._initialize_redis_client()

            self.service_status = 'stopped' # Pronto para receber comandos
            self.config_manager.set_service_status(self.service_status) # Salva estado inicial
            logger.info("IDSController inicializado com sucesso.")

        except Exception as e:
            logger.critical(f"Falha crítica durante a inicialização do IDSController: {e}", exc_info=True)
            self.service_status = 'error'
            self.running = False
            # Tenta salvar o status de erro se o config manager foi carregado
            if self.config_manager:
                try: self.config_manager.set_service_status(self.service_status)
                except: pass # Ignora erro ao salvar status de erro
            self._cleanup() # Tenta limpar recursos mesmo em falha de inicialização
            raise RuntimeError("Falha na inicialização do IDSController") from e

    def _load_configuration(self):
        """Carrega configurações GERAIS do arquivo usando ConfigManager."""
        if not self.config_manager: raise RuntimeError("ConfigManager não inicializado.")
        logger.info("Carregando configurações gerais...")
        try:
            config_data = self.config_manager.get_config()
            if not config_data or 'settings' not in config_data:
                raise ValueError("Configuração inválida ou seção 'settings' ausente.")

            settings = config_data['settings']
            self.host = settings.get('service_host', self.host)
            self.port = int(settings.get('service_port', self.port))
            self.interface = settings.get('interface', None)
            self.filter_rules = settings.get('filter', self.filter_rules)
            log_level_str = settings.get('log_level', 'INFO').upper()
            self.log_level = getattr(logging, log_level_str, logging.INFO)
            # Porta para API de Health (opcional, pode não estar no config)
            self.health_api_port = int(settings.get('health_api_port', self.health_api_port))

            # Lógica de detecção/validação de interface
            available_interfaces = netifaces.interfaces()
            if not self.interface:
                logger.warning("Interface de rede não especificada na config. Tentando detectar...")
                # Lógica simples: pegar a primeira interface não-loopback
                non_loopback = [iface for iface in available_interfaces if iface != 'lo']
                if non_loopback:
                    self.interface = non_loopback[0]
                    logger.info(f"Interface detectada automaticamente: {self.interface}")
                else:
                     # Tenta usar 'lo' como último recurso se SÓ ela existir
                     if 'lo' in available_interfaces:
                         self.interface = 'lo'
                         logger.warning("Nenhuma interface não-loopback encontrada. Usando 'lo'.")
                     else:
                         raise ValueError("Nenhuma interface de rede encontrada no sistema.")
            elif self.interface not in available_interfaces:
                raise ValueError(f"Interface de rede '{self.interface}' configurada não existe no sistema. Disponíveis: {available_interfaces}")

            logger.info(f"Configurações carregadas: Interface='{self.interface}', Filtro='{self.filter_rules}', LogLevel='{log_level_str}', SocketControle='{self.host}:{self.port}', HealthPort='{self.health_api_port}'")

        except (ValueError, KeyError, TypeError) as e:
            logger.critical(f"Erro ao carregar/validar config 'settings': {e}", exc_info=True)
            raise RuntimeError("Falha ao carregar/validar configurações 'settings'.") from e
        except Exception as e:
             logger.critical(f"Erro inesperado ao carregar config 'settings': {e}", exc_info=True)
             raise RuntimeError("Erro inesperado ao carregar 'settings'.") from e

    def _configure_logging(self):
        """Configura o sistema de logging globalmente com o nível definido."""
        try:
            root_logger = logging.getLogger()
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)
            formatter = logging.Formatter('%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            root_logger.addHandler(stream_handler)
            root_logger.setLevel(self.log_level)
            # Log inicial com o nível configurado
            logger.log(self.log_level, f"Sistema de logging configurado para nível: {logging.getLevelName(root_logger.getEffectiveLevel())}")
        except Exception as e:
            print(f"CRITICAL: Falha ao configurar o logging: {e}")
            logger.critical(f"Falha ao configurar o logging: {e}", exc_info=True)

    def _configure_rabbitmq_params(self):
        """Carrega os parâmetros específicos do RabbitMQ da configuração."""
        if not self.config_manager: raise RuntimeError("ConfigManager não inicializado.")
        logger.info("Carregando configuração do RabbitMQ...")
        try:
            rabbitmq_config = self.config_manager.get_rabbitmq_config()
            if not rabbitmq_config:
                raise ValueError("Seção 'rabbitmq' não encontrada ou inválida na configuração.")

            self.rabbitmq_host = rabbitmq_config.get('host', self.rabbitmq_host)
            self.rabbitmq_port = int(rabbitmq_config.get('port', self.rabbitmq_port))
            self.rabbitmq_packet_queue = rabbitmq_config.get('packet_queue', self.rabbitmq_packet_queue)

            if not self.rabbitmq_packet_queue:
                raise ValueError("Nome da fila de pacotes ('packet_queue') do RabbitMQ não pode ser vazio.")

            logger.info(f"Config RabbitMQ: {self.rabbitmq_host}:{self.rabbitmq_port}, Packet Queue='{self.rabbitmq_packet_queue}'")

        except (ValueError, KeyError, TypeError) as e:
            logger.critical(f"Erro na configuração do RabbitMQ: {e}")
            raise RuntimeError("Configuração inválida para RabbitMQ.") from e
        except Exception as e:
            logger.critical(f"Erro inesperado ao carregar config RabbitMQ: {e}", exc_info=True)
            raise RuntimeError("Erro ao carregar configuração RabbitMQ.") from e

    def _initialize_redis_client(self):
        """Inicializa o cliente Redis com base na configuração."""
        if not self.config_manager: raise RuntimeError("ConfigManager não inicializado.")
        logger.info("Inicializando cliente Redis...")
        try:
            redis_config = self.config_manager.get_redis_config()
            if not redis_config:
                raise ValueError("Seção 'redis' não encontrada na configuração.")

            self.redis_client = RedisClient(
                host=redis_config.get('host', 'localhost'),
                port=int(redis_config.get('port', 6379)),
                db=int(redis_config.get('db', 0)),
                password=redis_config.get('password'),
                block_list_key=redis_config.get('block_list_key', 'ids:blocked_ips'),
                # Não passamos block_ttl_seconds aqui, pois este módulo só consulta
            )
            # Tentativa de conexão inicial e verificação
            if not self.redis_client.get_connection():
                # O RedisClient já loga o erro, apenas levantamos exceção aqui
                raise ConnectionError("Falha ao conectar ao Redis na inicialização.")

            logger.info("Cliente Redis inicializado e conectado com sucesso.")
        except (ValueError, KeyError, TypeError) as e:
            logger.critical(f"Erro na configuração do Redis: {e}")
            self.redis_client = None
            raise RuntimeError("Configuração inválida para Redis.") from e
        except (ConnectionError, redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
            logger.critical(f"Falha ao conectar ao Redis na inicialização: {e}")
            self.redis_client = None
            raise RuntimeError("Falha na conexão inicial com Redis.") from e
        except Exception as e:
            logger.critical(f"Erro inesperado ao inicializar cliente Redis: {e}", exc_info=True)
            self.redis_client = None
            raise RuntimeError("Erro ao inicializar Redis.") from e

    def _connect_to_rabbitmq(self, retries=5, delay=5) -> bool:
        """Estabelece conexão com o RabbitMQ com tentativas."""
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
            return True

        logger.info(f"Tentando conectar ao RabbitMQ em {self.rabbitmq_host}:{self.rabbitmq_port}...")
        for attempt in range(retries):
            try:
                self._close_rabbitmq_connection() # Garante limpeza antes de tentar

                # Define parâmetros de conexão
                params = pika.ConnectionParameters(
                    host=self.rabbitmq_host,
                    port=self.rabbitmq_port,
                    heartbeat=600,
                    blocked_connection_timeout=300
                    # Adicionar credenciais se necessário:
                    # credentials=pika.PlainCredentials('user', 'password')
                )
                self.rabbitmq_connection = pika.BlockingConnection(params)
                self.rabbitmq_channel = self.rabbitmq_connection.channel()

                # Declara a fila de PACOTES que este módulo PUBLICA
                # durable=True garante que a fila sobreviva a reinícios do broker
                self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_packet_queue, durable=True)
                logger.info(f"Conectado ao RabbitMQ. Fila '{self.rabbitmq_packet_queue}' declarada/verificada.")
                return True # Sucesso

            except pika.exceptions.AMQPConnectionError as e:
                error_msg = f"Falha na conexão RabbitMQ (tentativa {attempt + 1}/{retries}): {e}"
                # Log mais severo na última tentativa
                if attempt == retries - 1: logger.critical(error_msg)
                else: logger.warning(error_msg)
            except Exception as e:
                error_msg = f"Erro inesperado ao conectar RabbitMQ (tentativa {attempt + 1}/{retries}): {e.__class__.__name__} - {e}"
                if attempt == retries - 1: logger.critical(error_msg, exc_info=True)
                else: logger.warning(error_msg)

            if attempt < retries - 1:
                logger.info(f"Nova tentativa de conexão RabbitMQ em {delay} segundos...")
                time.sleep(delay)

        logger.critical("Falha ao conectar ao RabbitMQ após várias tentativas.")
        return False # Falha definitiva

    def _close_rabbitmq_connection(self):
        """Fecha a conexão RabbitMQ de forma segura."""
        # Fecha o canal primeiro
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
            try:
                self.rabbitmq_channel.close()
                logger.debug("Canal RabbitMQ fechado.")
            except Exception as e:
                # Não crítico, apenas log
                logger.warning(f"Erro (ignorado) ao fechar canal RabbitMQ: {e}", exc_info=False)
        # Fecha a conexão
        if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
            try:
                self.rabbitmq_connection.close()
                logger.info("Conexão RabbitMQ fechada.")
            except Exception as e:
                logger.warning(f"Erro (ignorado) ao fechar conexão RabbitMQ: {e}", exc_info=False)
        # Zera as variáveis
        self.rabbitmq_channel = None
        self.rabbitmq_connection = None

    # --- API de Health Opcional ---
    def _start_health_api(self):
        """(OPCIONAL) Inicia uma API Flask mínima para health check em uma thread."""
        if not FLASK_AVAILABLE:
            logger.warning("Flask não está instalado. API de Health não será iniciada.")
            return

        health_app = Flask(f"{__name__}_health")

        # Desabilita logs padrão do Flask/Werkzeug para evitar poluição
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        health_app.logger.disabled = True

        @health_app.route('/health', methods=['GET'])
        def main_health():
            # Verifica apenas se o loop principal do controlador está ativo
            if self.running:
                # Poderia adicionar mais verificações aqui se necessário (ex: capturer.is_alive())
                return jsonify({"status": "ok", "component": "IDSController", "main_loop": "running"}), 200
            else:
                return jsonify({"status": "error", "component": "IDSController", "main_loop": "stopped"}), 503

        def run_flask():
            try:
                logger.info(f"Iniciando health API para IDSController em 0.0.0.0:{self.health_api_port}")
                health_app.run(host='0.0.0.0', port=self.health_api_port, debug=False, use_reloader=False)
            except OSError as e:
                 logger.critical(f"Falha ao iniciar health API na porta {self.health_api_port}: {e}. Verifique se a porta está em uso.", exc_info=True)
                 # Não para o serviço principal por causa disso, mas loga criticamente
            except Exception as e:
                logger.error(f"Erro inesperado na thread da health API: {e}", exc_info=True)

        self.health_api_thread = threading.Thread(target=run_flask, name="HealthApiThread", daemon=True)
        self.health_api_thread.start()

    def start(self):
        """Inicia o serviço principal do IDS e os servidores auxiliares."""
        if not self.running:
            logger.error("Não é possível iniciar, o controlador já foi parado ou falhou na inicialização.")
            return

        logger.info("Iniciando Controlador IDS...")
        self.service_status = 'starting'
        self.config_manager.set_service_status(self.service_status)

        # Configura handlers de sinal
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except ValueError as e: # Pode acontecer no Windows ou em threads não principais
            logger.warning(f"Não foi possível configurar signal handlers: {e}. Desligamento gracioso por sinal pode não funcionar.")

        # Verifica conexões essenciais ANTES de iniciar threads
        if not self._connect_to_rabbitmq():
            logger.critical("Falha ao conectar ao RabbitMQ no início. Serviço não pode continuar.")
            self._handle_critical_error("RabbitMQ connection failed")
            return # Impede a continuação

        if not self.redis_client or not self.redis_client.get_connection():
            logger.critical("Falha ao conectar ao Redis no início. Serviço não pode continuar.")
            self._handle_critical_error("Redis connection failed")
            return # Impede a continuação

        # Inicia o servidor de controle em uma thread separada
        self.control_server_thread = threading.Thread(target=self._start_control_server, name="ControlServerThread", daemon=True)
        self.control_server_thread.start()

        # Inicia a API de health opcional
        self._start_health_api()

        logger.info("Controlador IDS pronto. Servidores auxiliares iniciados.")
        # Define como parado, esperando comando 'start' da API de controle para iniciar captura
        self.service_status = 'stopped'
        self.config_manager.set_service_status(self.service_status)

        # Loop principal aguardando sinal de parada
        while self.running:
            try:
                # Verifica se a thread de controle ainda está ativa
                if self.control_server_thread and not self.control_server_thread.is_alive():
                    logger.error("Thread do servidor de controle terminou inesperadamente! Parando o serviço.")
                    self._handle_critical_error("Control server thread died")
                    break # Sai do loop

                # Outras verificações periódicas podem ser adicionadas aqui
                # Ex: if time.monotonic() % 60 < 1: self._check_dependencies()

                time.sleep(1) # Pausa principal do loop

            except Exception as e:
                logger.error(f"Erro inesperado no loop principal do controlador: {e}", exc_info=True)
                self._handle_critical_error(f"Unexpected main loop error: {e}")
                break # Sai do loop em erro grave

        logger.info("Loop principal do controlador encerrado.")
        self._cleanup() # Garante limpeza ao sair do loop

    def _handle_critical_error(self, reason: str):
        """Centraliza o tratamento de erros que devem parar o serviço."""
        logger.critical(f"Erro crítico detectado: {reason}. Solicitando parada do serviço.")
        self.service_status = 'error'
        if self.config_manager:
            try: self.config_manager.set_service_status(self.service_status)
            except: pass
        self.running = False # Sinaliza para parar tudo

    def _start_control_server(self):
        """Inicia o servidor socket para receber comandos."""
        server_socket: Optional[socket.socket] = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if not (1 <= self.port <= 65535):
                raise ValueError(f"Porta de controle inválida: {self.port}")

            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            # Define um timeout para accept() para que o loop possa verificar self.running
            server_socket.settimeout(2.0)
            logger.info(f"Servidor de controle ouvindo em {self.host}:{self.port}")

            while self.running:
                conn = None
                addr = None
                try:
                    conn, addr = server_socket.accept()
                    # Define timeout para a comunicação com o cliente
                    conn.settimeout(60.0)
                    logger.debug(f"Nova conexão de controle recebida de {addr}")
                    # Trata cada conexão em sua própria thread para não bloquear accept
                    handler_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        name=f"ControlHandler-{addr}",
                        daemon=True # Permite que o programa saia mesmo se estas threads estiverem rodando
                    )
                    handler_thread.start()
                except socket.timeout:
                    # Timeout em accept() é esperado, apenas continua verificando self.running
                    continue
                except OSError as e:
                    # Erro no socket principal (ex: se for fechado externamente)
                    if self.running: # Só loga erro se não estivermos parando intencionalmente
                        logger.error(f"Erro de socket no accept(): {e}. Encerrando servidor de controle.")
                        self._handle_critical_error(f"Control server accept error: {e}")
                    break # Sai do loop while self.running

        except (OSError, ValueError) as e:
            logger.critical(f"Erro CRÍTICO ao iniciar/bind servidor de controle em {self.host}:{self.port} - {e}. Verifique permissões e se a porta está em uso.", exc_info=True)
            self._handle_critical_error(f"Control server bind/init error: {e}")
        except Exception as e:
            logger.critical(f"Erro CRÍTICO inesperado no servidor de controle: {e}", exc_info=True)
            self._handle_critical_error(f"Unexpected control server error: {e}")
        finally:
            if server_socket:
                try: server_socket.close()
                except: pass
            logger.info("Servidor de controle encerrado.")

    def _handle_connection(self, conn: socket.socket, addr):
        """Processa uma conexão de controle (start, stop, status, get_config, shutdown)."""
        command = "N/A"
        response = b"Erro: Comando nao processado." # Mensagem de erro padrão
        try:
            with conn: # Garante fechamento da conexão no final ou em erro
                data_bytes = conn.recv(1024)
                if not data_bytes:
                    logger.warning(f"Conexão de controle {addr} fechada sem enviar dados.")
                    return

                # Decodifica o comando (assume UTF-8)
                command = data_bytes.decode('utf-8', errors='ignore').strip().lower()
                logger.info(f"Comando '{command}' recebido de {addr}")

                # Valida ações permitidas (lidas da config)
                allowed_actions = self.config_manager.get_config().get('service', {}).get('allowed_actions', [])
                if command not in allowed_actions:
                     logger.warning(f"Comando '{command}' de {addr} não está na lista de ações permitidas: {allowed_actions}")
                     response = b"Erro: Comando nao permitido"
                # Processa comandos válidos
                elif command == 'start':
                    response = self._start_capture()
                elif command == 'stop':
                    response = self._stop_capture()
                elif command == 'status':
                    # --- Status Aprimorado JSON ---
                    capture_status = 'running' if self.capturer and self.capturer.is_alive() else 'stopped'
                    # Verifica conexões de forma mais segura
                    mq_status = 'connected' if self.rabbitmq_channel and self.rabbitmq_channel.is_open else 'disconnected'
                    redis_status = 'connected' if self.redis_client and self.redis_client.get_connection() else 'disconnected' # get_connection pode tentar reconectar
                    current_service_status = self.config_manager.get_service_status()

                    status_dict = {
                        "service_status": current_service_status,
                        "capture": {
                            "status": capture_status,
                            "interface": self.interface,
                            "filter": self.filter_rules
                        },
                        "dependencies": {
                            "rabbitmq": mq_status,
                            "redis": redis_status
                        },
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) # Adiciona timestamp UTC
                    }
                    try:
                         # Converte para JSON (sem indentação para economizar bytes)
                         response = json.dumps(status_dict, separators=(',', ':')).encode('utf-8')
                    except Exception as json_e:
                         logger.error(f"Erro ao serializar status para JSON: {json_e}")
                         response = b'{"error": "Failed to serialize status to JSON"}'

                elif command == 'get_config':
                    try:
                        config_data = self.config_manager.get_config()
                        # Adiciona informações de runtime que não estão na config salva
                        runtime_info = {
                            'active_interface': self.interface,
                            'active_filter': self.filter_rules,
                            'active_log_level': logging.getLevelName(logger.getEffectiveLevel()),
                            'service_status': self.config_manager.get_service_status(),
                            'capture_running': bool(self.capturer and self.capturer.is_alive()),
                            'rabbitmq_connected': bool(self.rabbitmq_channel and self.rabbitmq_channel.is_open),
                            'redis_connected': bool(self.redis_client and self.redis_client.get_connection())
                        }
                        # Usa deepcopy para não modificar a config original ao adicionar runtime_info
                        response_data = {**copy.deepcopy(config_data), 'runtime_info': runtime_info}
                        # Serializa com indentação para leitura humana
                        response = json.dumps(response_data, indent=2, default=str).encode('utf-8')
                    except Exception as e:
                        logger.error(f"Erro ao obter/serializar config para {addr}: {e}", exc_info=True)
                        response = b'{"error": "Failed to get or format configuration"}'

                elif command == 'shutdown':
                    response = b"Comando 'shutdown' recebido. Iniciando parada..."
                    logger.warning(f"Comando 'shutdown' recebido de {addr}. Solicitando parada do serviço.")
                    # Chama self.stop() em uma nova thread para não bloquear a resposta
                    # Usamos a flag 'running' que será verificada pelo loop principal
                    self.stop() # Apenas seta a flag self.running = False

                else:
                    # Comando estava em allowed_actions mas não foi tratado acima? Log erro.
                    logger.error(f"Comando permitido '{command}' não foi tratado em _handle_connection!")
                    response = b"Erro: Comando permitido mas nao implementado no handler"

                # Envia a resposta
                conn.sendall(response)
                # Log limitado da resposta
                response_log = response if len(response) < 250 else response[:247] + b'...'
                logger.debug(f"Resposta enviada para {addr} (Cmd: '{command}'): {response_log.decode('utf-8', 'ignore')}")

        except socket.timeout:
            logger.warning(f"Timeout (>60s) na comunicação com cliente de controle {addr}. Fechando.")
        except (socket.error, ConnectionResetError, BrokenPipeError) as e:
            logger.warning(f"Erro de socket ou conexão perdida com cliente de controle {addr}: {e}")
        except Exception as e:
            # Erro genérico no processamento do comando
            logger.error(f"Erro ao processar comando '{command}' de {addr}: {e}", exc_info=True)
            try:
                # Tenta enviar uma mensagem de erro genérica
                conn.sendall(b'{"error": "Internal server error processing command"}')
            except:
                pass # Ignora erro ao enviar mensagem de erro
        # finally: O 'with conn:' garante o fechamento.

    def _start_capture(self) -> bytes:
        """Inicia a captura de pacotes (se não estiver rodando). Retorna bytes da resposta."""
        if self.capturer and self.capturer.is_alive():
            logger.warning("Tentativa de iniciar captura que já está rodando.")
            return b'{"status": "warning", "message": "Capture already running"}'

        # Verifica dependências essenciais ANTES de criar a thread
        if not self.interface:
            logger.error("Não é possível iniciar captura: interface não definida.")
            self._handle_critical_error("Capture failed: interface not defined")
            return b'{"status": "error", "message": "Capture interface not defined"}'

        # Verifica conexões novamente
        if not self._connect_to_rabbitmq(retries=1): # Tenta rápido
            logger.error("Falha ao conectar/reconectar ao RabbitMQ. Captura não iniciada.")
            # Não consideramos erro fatal para o serviço todo, mas a captura falha
            self.config_manager.set_service_status('error') # Status do serviço vira erro
            return b'{"status": "error", "message": "Failed to connect to RabbitMQ"}'
        if not self.redis_client or not self.redis_client.get_connection(): # Tenta rápido
            logger.error("Falha ao conectar/reconectar ao Redis. Captura não iniciada.")
            self.config_manager.set_service_status('error')
            return b'{"status": "error", "message": "Failed to connect to Redis"}'

        logger.info(f"Iniciando captura na interface: {self.interface} com filtro: '{self.filter_rules}'")
        try:
            self.capturer = PacketCapturer(
                interface=self.interface,
                packet_handler=self._process_packet,
                filter_rules=self.filter_rules,
            )
            self.capturer.start() # Inicia a thread de captura
            time.sleep(0.5) # Pausa para dar tempo da thread iniciar/falhar

            if self.capturer.is_alive():
                self.service_status = 'running'
                self.config_manager.set_service_status(self.service_status)
                logger.info("Captura de pacotes iniciada com sucesso.")
                return b'{"status": "success", "message": "Capture started"}'
            else:
                logger.error("Thread de captura não iniciou corretamente (ver logs do PacketCapturer).")
                self.service_status = 'error'
                self.config_manager.set_service_status(self.service_status)
                self.capturer = None
                return b'{"status": "error", "message": "Failed to start capture thread"}'

        except PermissionError:
             logger.critical("Erro de permissão ao iniciar captura (Scapy). Execute com privilégios.", exc_info=True)
             self._handle_critical_error("Capture failed: Permission denied")
             return b'{"status": "error", "message": "Permission denied to start capture"}'
        except Exception as e:
            logger.error(f"Falha CRÍTICA ao criar/iniciar a thread de captura: {e}", exc_info=True)
            self._handle_critical_error(f"Capture failed: {e}")
            return b'{"status": "error", "message": "Critical error starting capture"}'

    def _stop_capture(self) -> bytes:
        """Para a thread de captura de pacotes. Retorna bytes da resposta."""
        if self.capturer and self.capturer.is_alive():
            logger.info("Parando a captura de pacotes...")
            stopped_cleanly = False
            try:
                self.capturer.stop() # Sinaliza para parar
                # Espera um pouco pela thread terminar (join opcional)
                self.capturer.capture_thread.join(timeout=3.0) # Espera até 3s
                if not self.capturer.is_alive():
                     stopped_cleanly = True
                     logger.info("Thread de captura encerrada graciosamente.")
                else:
                     logger.warning("Thread de captura não encerrou no tempo esperado após stop().")
            except Exception as e:
                logger.error(f"Erro ao sinalizar/aguardar parada da thread de captura: {e}", exc_info=True)
            finally:
                self.capturer = None # Libera referência de qualquer forma
                self.service_status = 'stopped'
                self.config_manager.set_service_status(self.service_status)
                logger.info("Sinal de parada enviado e referência ao capturador liberada.")
                if stopped_cleanly:
                    return b'{"status": "success", "message": "Capture stopped"}'
                else:
                     return b'{"status": "warning", "message": "Capture stop requested, thread termination uncertain"}'
        else:
            logger.info("Comando 'stop' recebido, mas captura já estava parada.")
            # Garante que o status está correto
            if self.config_manager.get_service_status() != 'stopped':
                self.service_status = 'stopped'
                self.config_manager.set_service_status(self.service_status)
            return b'{"status": "info", "message": "Capture was not running"}'

    def _process_packet(self, packet: Packet):
        """
        Processa um pacote: normaliza, verifica bloqueio no Redis,
        e envia para RabbitMQ se não estiver bloqueado.
        """
        # Verificações rápidas para evitar processamento desnecessário
        if not self.running: return
        if not self.redis_client or not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
            # Log esporádico para não floodar
            if time.monotonic() % 10 < 1: # A cada ~10 segundos
                logger.warning("_process_packet: Serviço parando ou Redis/RabbitMQ indisponível. Descartando pacote.")
            return

        try:
            # 1. Normaliza o pacote
            # Passamos o pacote Scapy diretamente
            normalized_data = PacketNormalizer.normalize(packet)

            # 2. Verifica se a normalização foi bem sucedida e obtém IPs
            if normalized_data:
                src_ip = normalized_data.get('src_ip')
                dst_ip = normalized_data.get('dst_ip')

                # Validação mínima (IPs devem existir após normalização)
                if not src_ip or not dst_ip:
                     # PacketNormalizer já deve ter validado, mas verificamos aqui por segurança
                    logger.debug(f"IP inválido/ausente no pacote normalizado: SRC='{src_ip}', DST='{dst_ip}'. Descartado.")
                    return

                # 3. Verifica bloqueio no Redis (IP de ORIGEM)
                try:
                    is_blocked = self.redis_client.is_blocked(src_ip)
                except Exception as redis_err:
                    # Loga o erro e assume não bloqueado para não parar o fluxo por erro no Redis
                    logger.error(f"Erro ao verificar bloqueio Redis para {src_ip}: {redis_err}. Assumindo não bloqueado.")
                    is_blocked = False

                if is_blocked:
                    # Log em nível DEBUG para não poluir
                    logger.debug(f"IP {src_ip} está bloqueado (Redis). Pacote descartado.")
                    # Contadores podem ser mais úteis que logs aqui para produção
                    return # <<< NÃO ENVIA PARA ANÁLISE >>>

                # 4. Se não bloqueado, envia para análise via RabbitMQ
                self._send_to_rabbitmq(normalized_data)

                # 5. Log Opcional (removido por padrão para performance)
                # logger.debug(f"Pacote [{src_ip}:{normalized_data.get('src_port')} -> {dst_ip}:{normalized_data.get('dst_port')}] enviado para analise.")

            # else: O PacketNormalizer descartou o pacote (ruído, broadcast, etc.) ou falhou. Logs devem vir dele.

        except Exception as e:
            # Erro genérico no processamento deste pacote específico
            logger.error(f"Erro durante _process_packet para {packet.summary()[:150]}: {e}", exc_info=True)

    def _send_to_rabbitmq(self, data: Dict[str, Any]):
        """Envia dados normalizados para a fila de pacotes do RabbitMQ."""
        # Verifica se o canal está pronto
        if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
            logger.warning("Tentativa de envio MQ, mas canal fechado. Tentando reconectar...")
            # Tenta reconectar rapidamente. Se falhar, a mensagem é perdida.
            if not self._connect_to_rabbitmq(retries=1, delay=0):
                logger.error("Falha ao reconectar MQ rapidamente. Mensagem perdida.")
                return
            # Se reconectou, o canal deve estar pronto agora

        try:
            # Serializa os dados para JSON
            message_body = json.dumps(data, default=str, separators=(',', ':')) # Compacto

            # Publica a mensagem
            self.rabbitmq_channel.basic_publish(
                exchange='', # Usa exchange default
                routing_key=self.rabbitmq_packet_queue, # Fila de destino
                body=message_body,
                properties=pika.BasicProperties(
                    delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE # Marca como persistente
                )
            )
            # Log muito verboso para produção
            # logger.debug(f"Dados enviados para fila '{self.rabbitmq_packet_queue}'")

        except (pika.exceptions.AMQPConnectionError,
                pika.exceptions.ChannelClosedByBroker,
                pika.exceptions.StreamLostError,
                pika.exceptions.ChannelWrongStateError, # Adicionado
                AttributeError) as conn_err: # AttributeError se channel for None
            # Erros que indicam problema na conexão/canal
            logger.error(f"Erro de conexão/canal RabbitMQ ao publicar: {conn_err.__class__.__name__}. Tentará reconectar.")
            # Força fechamento para limpar estado e tentar reconectar na próxima vez
            self._close_rabbitmq_connection()
        except Exception as e:
            # Outros erros (ex: serialização JSON, erro inesperado do Pika)
            logger.error(f"Erro inesperado ao publicar no RabbitMQ: {e}", exc_info=True)
            # Considerar estratégia de retry ou dead-letter queue aqui pode ser útil
            # Dependendo do erro, forçar reconexão pode ou não ajudar
            # self._close_rabbitmq_connection() # Opcional

    # @staticmethod # Não precisa ser staticmethod se não usa 'self'
    # def _validate_ip(ip: str) -> bool:
    #     """Valida se uma string é um endereço IP válido (IPv4 ou IPv6)."""
    #     # Simplificado, pois PacketNormalizer e RedisClient já validam
    #     return isinstance(ip, str) and ip is not None

    def _signal_handler(self, signum, frame):
        """Manipula sinais de desligamento (SIGINT, SIGTERM)."""
        signal_name = signal.Signals(signum).name
        if self.running:
            logger.warning(f"Sinal {signal_name} ({signum}) recebido. Iniciando parada...")
            self.stop() # Chama o método stop que seta self.running = False
        else:
            logger.warning(f"Sinal {signal_name} ({signum}) recebido, mas serviço já estava parando.")

    def stop(self):
        """Inicia o processo de parada graciosa do serviço (chamado pelo handler ou API)."""
        if not self.running:
            # logger.debug("Processo de parada já iniciado.")
            return # Evita chamadas múltiplas

        logger.info("Solicitando parada do serviço IDSController...")
        self.running = False # Sinaliza para todos os loops pararem

        # Atualiza status na config (se possível)
        current_status = self.config_manager.get_service_status() if self.config_manager else 'unknown'
        if current_status not in ['stopped', 'stopping', 'error']:
             if self.config_manager:
                  try: self.config_manager.set_service_status('stopping')
                  except: pass # Ignora erro ao salvar status

        # NÃO chamar cleanup aqui. O loop principal chamará ao sair.

    def _cleanup(self):
        """Realiza a parada efetiva dos componentes e fecha conexões."""
        logger.info("Executando limpeza dos recursos do IDSController...")
        final_status = 'stopped' # Assume parada normal, a menos que já esteja em erro

        # 1. Para a captura de pacotes (garante que pare se ainda estiver ativa)
        if self.capturer and self.capturer.is_alive():
            logger.info("Garantindo parada da captura na limpeza...")
            self._stop_capture() # Tenta parar e aguardar um pouco

        # 2. Fecha a conexão com RabbitMQ
        logger.debug("Fechando conexão RabbitMQ na limpeza...")
        self._close_rabbitmq_connection()

        # 3. Fecha a conexão com Redis
        logger.debug("Fechando conexão Redis na limpeza...")
        if self.redis_client:
            self.redis_client.close()

        # 4. Fecha socket de controle (a thread deve terminar ao self.running=False)
        # Apenas logamos que estamos parando
        logger.debug("Sinalizando para threads auxiliares terminarem...")

        # 5. Define o status final (a menos que já esteja 'error')
        if self.config_manager:
            if self.config_manager.get_service_status() != 'error':
                try: self.config_manager.set_service_status(final_status)
                except: pass # Ignora erro ao salvar status final

        logger.info(f"Limpeza do Controlador IDS concluída. Status final: {self.config_manager.get_service_status() if self.config_manager else 'unknown'}.")


# --- Ponto de Entrada Principal ---
if __name__ == "__main__":
    controller: Optional[IDSController] = None
    exit_code = 0
    try:
        logger.info("Iniciando aplicação IDSController...")
        controller = IDSController()
        # O start() agora bloqueia até que 'running' seja False
        controller.start()
        logger.info("Aplicação IDSController: controller.start() retornou.")
    except RuntimeError as e:
        # Erros fatais durante a inicialização já logados
        logger.critical(f"Encerrando devido a erro fatal na inicialização: {e}")
        exit_code = 1
    except KeyboardInterrupt:
        logger.warning("Interrupção pelo teclado (Ctrl+C) detectada.")
        # O signal handler (se configurado) ou a exceção devem ter chamado stop()
        # O fluxo normal levará ao _cleanup() após sair do start()
        exit_code = 0 # Saída normal
    except Exception as e:
        logger.critical(f"Erro não tratado no nível principal: {e}", exc_info=True)
        exit_code = 1
        # Tenta garantir que a flag de parada seja setada em caso de erro inesperado
        if controller and controller.running:
             controller.running = False
             # O cleanup será chamado no finally
    finally:
        logger.info("Aplicação IDSController no bloco finally...")
        # O cleanup é chamado ao final normal ou com erro do controller.start()
        # Não precisamos chamar explicitamente aqui, a menos que a instanciação falhe
        if controller is None and exit_code == 0: # Caso raro: falha antes mesmo de instanciar
             exit_code = 1 # Indica erro se não conseguiu nem instanciar

        logger.info(f"Aplicação IDSController finalizada com código de saída: {exit_code}")
        # Pequena pausa para garantir que logs sejam escritos antes de sair
        time.sleep(0.5)
        exit(exit_code)