import logging
import time
import threading
import signal
import socket
import ipaddress
import netifaces
import json
import pika
import scapy.all as scapy

# Importando Classes dos fontes config.py, packet_processor.py e data_processing.py
from config import ConfigManager
from packet_processor import PacketCapturer
from data_processing import PacketNormalizer
from systemd.journal import JournalHandler

logger = logging.getLogger(__name__)

class IDSController:
    def __init__(self):
        self.config = ConfigManager()
        self.capturer = None
        self.running = True
        self.service_status = 'stopped'
        self.connection_threads = []
        # Configurações do RabbitMQ
        self.rabbitmq_host = self.config.get_config()['rabbitmq'].get('host', 'localhost')
        self.rabbitmq_port = int(self.config.get_config()['rabbitmq'].get('port', 5672))
        self.rabbitmq_queue = self.config.get_config()['rabbitmq'].get('queue', 'pacotes')
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None
        self.normalizer = PacketNormalizer(rabbitmq_host=self.rabbitmq_host)  # Passa o host do RabbitMQ
        self._load_configuration()

        # Configuração do Logging para Systemd Journal
        for handler in logger.handlers[:]: # Remove todos os manipuladores existentes
            logger.removeHandler(handler)
        logger.setLevel(self.log_level) # Define o nível de log
        journal_handler = JournalHandler() # Manipulador para o Systemd Journal
        logger.addHandler(journal_handler) # Adiciona o manipulador
        logger.info(f"Nível de log configurado para: {logging.getLevelName(self.log_level)}") 

        # Configurações do RabbitMQ
        self.rabbitmq_host = self.config.get_config()['rabbitmq'].get('host', 'localhost') 
        self.rabbitmq_port = int(self.config.get_config()['rabbitmq'].get('port', 5672)) 
        self.rabbitmq_queue = self.config.get_config()['rabbitmq'].get('queue', 'pacotes') 
        self.rabbitmq_connection = None # Conexão RabbitMQ
        self.rabbitmq_channel = None # Canal RabbitMQ

    def _load_configuration(self):
        logger.info("Carregando configurações...")
        try:
            config_data = self.config.get_config() # Carrega a configuração do gerenciador
            settings = config_data.get('settings', {})
            self.host = settings.get('service_host', 'localhost')
            self.port = int(settings.get('service_port', 65432))
            self.interface = settings.get('interface', None)
            if not self.interface:
                logger.warning("Interface não especificada. Tentando detectar automaticamente.")
                try:
                    default_gateway = netifaces.gateways()['default']
                    if netifaces.AF_INET in default_gateway:
                        self.interface = default_gateway[netifaces.AF_INET][1]
                        logger.info(f"Interface detectada: {self.interface}")
                    else:
                        raise Exception("Não foi possível detectar interface padrão.")
                except Exception as e:
                    logger.error(f"Falha ao detectar interface: {e}. Use 'interface' no config.json.")
                    raise ValueError("Interface de rede não configurada.")
            # Validação adicional
            if not isinstance(self.interface, str) or len(self.interface.strip()) < 2:
                raise ValueError(f"Interface inválida no config: '{self.interface}'")
            self.filter_rules = settings.get('filter', 'ip')
            log_level_str = settings.get('log_level', 'INFO').upper()
            self.log_level = getattr(logging, log_level_str, logging.INFO)
            logger.info("Configurações carregadas com sucesso.")
        except Exception as e:
            logger.critical(f"Erro ao carregar configuração: {e}", exc_info=True)
            raise RuntimeError("Falha ao carregar configuração.") from e

    def _connect_to_rabbitmq(self, retries=3, delay=5):
        """Estabelece conexão com o RabbitMQ com tentativas de reconexão."""
        logger.info(f"Tentando conectar ao RabbitMQ em {self.rabbitmq_host}:{self.rabbitmq_port}...")
        for attempt in range(retries):
            try:
                self.rabbitmq_connection = pika.BlockingConnection(
                    pika.ConnectionParameters(host=self.rabbitmq_host, port=self.rabbitmq_port)
                )
                self.rabbitmq_channel = self.rabbitmq_connection.channel()
                self.rabbitmq_channel.queue_declare(queue=self.rabbitmq_queue, durable=True)
                logger.info(f"Conectado ao RabbitMQ. Fila '{self.rabbitmq_queue}' declarada.")
                return
            except Exception as e:
                logger.error(f"Erro ao conectar ao RabbitMQ (tentativa {attempt + 1}/{retries}): {e}")
                if attempt < retries - 1:
                    time.sleep(delay)
        logger.critical("Falha ao conectar ao RabbitMQ após várias tentativas.")
        self.stop()

    def _close_rabbitmq_connection(self):
        """Fecha a conexão com o RabbitMQ de forma segura."""
        logger.info("Fechando conexão com o RabbitMQ...")
        try:
            if self.rabbitmq_channel and self.rabbitmq_channel.is_open:
                self.rabbitmq_channel.close() # Fecha o canal RabbitMQ
            if self.rabbitmq_connection and self.rabbitmq_connection.is_open:
                self.rabbitmq_connection.close() # Fecha a conexão RabbitMQ
            self.rabbitmq_channel = None # Limpa a referência ao canal
            logger.info("Conexão RabbitMQ fechada.") 
        except Exception as e:
            logger.error(f"Erro ao fechar conexão RabbitMQ: {e}")

    def start(self):
        """Inicia o serviço principal do IDS e o servidor de controle."""
        logger.info("Iniciando Controlador IDS...")
        self.is_manual_stop = False # Reseta a flag de parada manual
        signal.signal(signal.SIGINT, self._signal_handler) # Manipulador para Ctrl+C
        signal.signal(signal.SIGTERM, self._signal_handler) # Manipulador para SIGTERM
        logger.info("Aguardando conexão com o RabbitMQ...")

        self._connect_to_rabbitmq() # Tenta conectar ao RabbitMQ
        if not self.rabbitmq_connection or not self.rabbitmq_connection.is_open: # Verifica se a conexão RabbitMQ está aberta
            logger.critical("Falha ao conectar ao RabbitMQ. Encerrando...")
            self.stop()
            return
        logger.info("Conexão com RabbitMQ estabelecida. Iniciando servidor de controle...")
        if not self.running:
            logger.critical("Não foi possível iniciar devido à falha na conexão com RabbitMQ.")
            return

        control_thread = threading.Thread(target=self._start_control_server, daemon=True)
        control_thread.start()

        while self.running:
            time.sleep(1) # Mantém o loop principal ativo
            if self.capturer and not self.capturer.is_alive(): # Verifica se a captura está ativa
                if not self.is_manual_stop:
                    logger.warning("Captura não está ativa. Tentando reiniciar...")
                    self._start_capture()
            if self.rabbitmq_channel and not self.rabbitmq_channel.is_open: # Verifica se o canal RabbitMQ está aberto
                logger.warning("Canal RabbitMQ não está aberto. Tentando reconectar...")
                self._connect_to_rabbitmq()
            if not self.rabbitmq_connection or not self.rabbitmq_connection.is_open: # Verifica se a conexão RabbitMQ está aberta
                logger.warning("Conexão RabbitMQ não está aberta. Tentando reconectar...")
                self._connect_to_rabbitmq()
        if self.capturer and self.capturer.is_alive(): # Verifica se a captura está ativa
            logger.info("Parando captura antes de encerrar...")
            self._stop_capture()
        if self.rabbitmq_channel and self.rabbitmq_channel.is_open: # Verifica se o canal RabbitMQ está aberto
            logger.info("Fechando canal RabbitMQ...")
            self.rabbitmq_channel.close()
        if self.rabbitmq_connection and self.rabbitmq_connection.is_open: # Verifica se a conexão RabbitMQ está aberta
            logger.info("Fechando conexão RabbitMQ...")
            self.rabbitmq_connection.close()
        for thread in self.connection_threads[:]: # Copia para evitar modificação durante iteração
            if thread.is_alive():
                thread.join(timeout=5.0)
                if thread.is_alive():
                    logger.warning(f"Thread {thread.name} não parou.")
            self.connection_threads.remove(thread)
        self.service_status = 'stopped'
        logger.info("Loop principal encerrado.")

    def _start_control_server(self):
        """Inicia o servidor socket para receber comandos."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Permite reutilizar o endereço
                s.bind((self.host, self.port)) # Associa o socket ao host e porta
                s.listen(5) # Escuta até 5 conexões simultâneas
                s.settimeout(1.0) # Timeout para evitar bloqueio
                logger.info("Servidor de controle iniciado.")
                logger.info(f"Servidor de controle ouvindo em {self.host}:{self.port}")
                while self.running:
                    try:
                        conn, addr = s.accept()
                        conn.settimeout(30)
                        handler_thread = threading.Thread(
                            target=self._handle_connection,
                            args=(conn, addr),
                            daemon=True
                        )
                        handler_thread.start()
                        self.connection_threads.append(handler_thread)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            logger.error(f"Erro no accept: {e}")
        except OSError as e:
            logger.critical(f"Erro ao iniciar servidor em {self.host}:{self.port} - {e}.", exc_info=True) 
            self.stop() 
        finally:
            logger.info("Servidor de controle encerrado.")

    def _handle_connection(self, conn, addr):
        try:
            with conn:
                data = conn.recv(1024).decode().strip().lower() # Recebe e normaliza o comando
                if not data:
                    logger.warning(f"Comando vazio recebido de {addr}.")
                    return
                if not isinstance(data, str): # Verifica se o comando é uma string
                    logger.warning(f"Comando inválido recebido de {addr}: {data}")
                logger.info(f"Comando '{data}' recebido de {addr}") 
                response = json.dumps({"status": "error", "message": "Comando invalido"}).encode() 
                if data in ('start', 'iniciar'): # Comandos para iniciar a captura
                    response = self._start_capture() 
                elif data in ('stop', 'parar'): # Comandos para parar a captura
                    self.is_manual_stop = True # Marca que a parada foi manual
                    response = self._stop_capture()
                elif data == 'status': # Comando para verificar o status do serviço
                    if self.capturer and self.capturer.is_alive():
                        self.service_status = 'running'
                    else:
                        self.service_status = 'stopped'
                    response = json.dumps({"status": "success", "service_status": self.service_status}).encode() 
                elif data == 'get_config': # Comando para obter a configuração atual
                    logger.info("Solicitação de configuração recebida.")
                    config_data = self.config.get_config() # Obtém a configuração atual
                    config_data['settings']['service_status'] = self.service_status
                    config_data['settings']['active_interface'] = self.interface
                    config_data['settings']['active_filter'] = self.filter_rules
                    config_data['settings']['active_log_level'] = logging.getLevelName(logger.getEffectiveLevel())
                    response = json.dumps({"status": "success", "data": config_data}).encode()
                conn.sendall(response)
        except Exception as e:
            logger.error(f"Erro ao processar comando de {addr}: {e}")

    def _start_capture(self):
        if self.capturer is not None and hasattr(self.capturer, 'is_alive') and self.capturer.is_alive():
            self.service_status = 'running'
            logger.warning("Captura já está em execução.")
            return json.dumps({"status": "warning", "message": "Captura ja em execucao"}).encode()

        if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
            logger.info("Tentando reconectar ao RabbitMQ...")
            self._connect_to_rabbitmq()
            if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                logger.error("Falha ao reconectar ao RabbitMQ.")
                return json.dumps({"status": "error", "message": "Nao e possível conectar ao RabbitMQ"}).encode()

        available_interfaces = scapy.get_if_list()
        if not self.interface or not isinstance(self.interface, str) or self.interface not in available_interfaces:
            logger.error(f"Interface inválida ou não encontrada: '{self.interface}'")
            self.service_status = 'error'
            return json.dumps({"status": "error", "message": f"Interface de rede invalida ou indisponivel: '{self.interface}'"}).encode()

        try:
            self.capturer = PacketCapturer(self.interface, self._process_packet, self.filter_rules)
            self.capturer.start()  # start() normalmente não retorna nada

            time.sleep(0.5)  # Dá tempo da thread iniciar

            if self.capturer is not None and self.capturer.is_alive():
                self.service_status = 'running'
                logger.info("Captura iniciada.")
                return json.dumps({"status": "success", "message": "Iniciando Captura"}).encode()
            else:
                logger.error("Thread de captura não está ativa após início.")
                self.capturer = None
                self.service_status = 'error'
                return json.dumps({"status": "error", "message": "Falha ao iniciar a thread de captura"}).encode()
        except Exception as e:
            logger.error(f"Falha ao iniciar captura: {e}", exc_info=True)
            self.service_status = 'error'
            return json.dumps({"status": "error", "message": f"Error starting capture: {str(e)}"}).encode()

    def _stop_capture(self):
        if self.capturer and self.capturer.is_alive():
            logger.info("Parando captura...")
            self.is_manual_stop = True # Marca que a parada foi manual
            self.capturer.stop()  # Chama o método stop do PacketCapturer
            time.sleep(1)  # Aguarda um curto período para garantir que as threads internas parem
            if self.capturer.is_alive(): # Verifica se a captura ainda está ativa
                logger.warning("Captura não parou completamente.")
            logger.info("Captura parada.")
            self.capturer = None
            self.service_status = 'stopped'
            return json.dumps({"status": "success", "message": "Captura parou"}).encode()
        self.service_status = 'stopped'
        logger.info("Captura não estava ativa.")
        return json.dumps({"status": "info", "message": "Captura nao esta em execucao"}).encode()

    def _process_packet(self, packet): 
        """Normaliza o pacote e envia para o RabbitMQ."""
        try:
            processed = self.normalizer.normalize(packet)  # Usa a instância
            if processed:  # Verifica se o pacote foi processado corretamente
                # Adiciona validação de IPs
                if not self._validate_ip(processed.get('src_ip')) or not self._validate_ip(processed.get('dst_ip')):
                    logger.warning("IP inválido detectado.", extra=processed) 
                    return
                logger.debug("Pacote processado", extra=processed)  # Adiciona log de depuração
                if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                    logger.warning("Canal RabbitMQ não está aberto. Tentando reconectar...")
                    self._connect_to_rabbitmq()
                    if not self.rabbitmq_channel or not self.rabbitmq_channel.is_open:
                        logger.error("Falha ao reconectar ao RabbitMQ. Mensagem perdida.")
                        return
                message_body = json.dumps(processed)  # Serializa o pacote processado
                self.rabbitmq_channel.basic_publish(
                    exchange='',
                    routing_key=self.rabbitmq_queue,
                    body=message_body,
                    properties=pika.BasicProperties(delivery_mode=2)  # Mensagem persistente
                )
                logger.debug(f"Mensagem enviada para a fila '{self.rabbitmq_queue}': {message_body}")
        except Exception as e:
            logger.error(f"Erro ao processar pacote: {e}", exc_info=True)

    @staticmethod
    def _validate_ip(ip): 
        """Valida se uma string é um endereço IP válido (IPv4 ou IPv6)."""
        if not ip or not isinstance(ip, str): # Verifica se é uma string não vazia
            logger.warning("IP inválido ou não é uma string.")
            return False
        try:
            ipaddress.ip_address(ip) # Tenta criar um objeto IP a partir da string
            return True
        except ValueError:
            return False

    def _signal_handler(self, signum, frame):
        """Manipula sinais de desligamento."""
        logger.warning(f"Sinal {signal.Signals(signum).name} recebido.")
        self.stop()

    def stop(self):
        """Para todos os componentes do serviço de forma graciosa."""
        if not self.running:
            logger.info("Serviço já está parado.")
            return
        logger.info("Iniciando parada do serviço...")
        self.running = False
        self._stop_capture() # Para a captura de pacotes
        self._close_rabbitmq_connection() # Fecha a conexão com o RabbitMQ
        for thread in self.connection_threads[:]: # Copia para evitar modificação durante iteração
            if thread.is_alive():
                thread.join(timeout=5.0)
                if thread.is_alive():
                    logger.warning(f"Thread {thread.name} não parou.")
            self.connection_threads.remove(thread)
        self.service_status = 'stopped'
        logger.info("Serviço parado com sucesso.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    try:
        ids_controller = IDSController()
        ids_controller.start()
    except RuntimeError as e:
        logger.critical(f"Falha na inicialização: {e}", exc_info=True)
        exit(1)
    except Exception as e:
        logger.critical(f"Erro inesperado: {e}", exc_info=True)
        if 'ids_controller' in locals():
            ids_controller.stop()
        exit(1)
    logger.info("Aplicação finalizada.")