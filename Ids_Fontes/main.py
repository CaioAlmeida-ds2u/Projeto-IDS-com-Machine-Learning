import signal
import time
import logging
import threading
import json
from config import ConfigManager
from db import DatabaseManager
from packet_processor import PacketCapturer
from filelock import FileLock, Timeout
from data_processing import PacketNormalizer

logger = logging.getLogger(__name__)

class IDSController:
    def __init__(self):
        self.config = ConfigManager()
        self.service_config = self.config.get_service_commands()
        self.db = DatabaseManager(self.config.get_database_config())
        self.capturer = None
        self.running = True
        self.buffer = []
        self.buffer_lock = threading.Lock()
        self.last_write = time.time()
        logging.basicConfig(level=self.config.get_settings().get('log_level', 'INFO'))
        logger.info("Sistema IDS inicializado")
        self._init_system()

    def _init_system(self):
        """Inicializa componentes do sistema"""
        self.db.initialize_schema()

    def start(self):
        """Inicia o loop principal de serviço"""
        logger.info("Iniciando serviço IDS...")
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            while self.running:
                self._service_loop()
                time.sleep(0.5)
        except Exception as e:
            logger.error(f"Erro inesperado durante a execução do serviço: {str(e)}")
        finally:
            self._cleanup()

    def _service_loop(self):
        """Loop principal de operação do serviço"""
        while self.running:
            self._check_control_commands()  # Verifica comandos periodicamente
            self._process_buffer()
            self._monitor_components()
            time.sleep(1)  # Ajuste o intervalo conforme necessário

    def _check_control_commands(self):
        try:
            with FileLock("config.json.lock", timeout=10):
                self.config.reload_config()  # Recarrega as configurações do arquivo
                current_config = self.config.config
                service_section = current_config.get('service', {})
                command = service_section.get('requested_command', '').lower()

                if command:
                    logger.debug(f"Processando comando: {command}")
                    self._execute_service_command(command)
                    self._clear_service_command(current_config)

        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Erro de configuração: {str(e)}")
        except Timeout:
            logger.warning("Timeout no acesso ao arquivo de configuração")
        except Exception as e:
            logger.error(f"Erro no processamento de comandos: {str(e)}")

    def _execute_service_command(self, command: str):
        """Executa comandos do serviço"""
        command_handlers = {
            'start': self._start_capture,
            'stop': self._stop_capture,
            'restart': self._restart_capture,
            'status': self._report_status
        }
        
        if command in command_handlers:
            command_handlers[command]()
        else:
            logger.warning(f"Comando não implementado: {command}")

    def _start_capture(self):
        """Inicia a captura de pacotes"""
        if not self._is_capturer_active():
            interface = self.config.get_settings().get('interface', 'enp0s3')
            self.capturer = PacketCapturer(
                interface=interface,
                packet_handler=self._process_packet
            )
            self.capturer.start()
            self._update_service_status('running')
            logger.info(f"Captura iniciada na interface {interface}")

    def _stop_capture(self):
        """Para a captura de pacotes"""
        if self._is_capturer_active():
            self.capturer.stop()
            self._update_service_status('stopped')
            logger.info("Captura de pacotes interrompida")

    def _restart_capture(self):
        """Reinicia a captura de pacotes"""
        self._stop_capture()
        time.sleep(1)
        self._start_capture()

    def _report_status(self):
        """Reporta o status atual do serviço"""
        status = 'running' if self._is_capturer_active() else 'stopped'
        logger.info(f"Status do serviço: {status.upper()}")
        self._update_service_status(status)

    def _clear_service_command(self, config: dict):
        """Limpa o comando processado"""
        try:
            config['service']['requested_command'] = ''
            with open('config.json', 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logger.error(f"Erro ao limpar comando: {str(e)}")

    def _process_packet(self, packet):
        """Processa cada pacote capturado"""
        try:
            normalized = PacketNormalizer.normalize(packet)
            if normalized:
                # Espaço para integração do Machine Learning
                ml_analysis = self._analyze_with_ml(normalized)  # <--- Integração ML aqui
                
                with self.buffer_lock:
                    self.buffer.append(normalized)
                    self._check_buffer_flush()
        except Exception as e:
            logger.error(f"Erro no processamento do pacote: {str(e)}")

    def _analyze_with_ml(self, packet_data):
        """Método para integração do Machine Learning"""
        # TODO: Implementar análise com modelo de ML
        # Retornar resultados da análise
        return {}  # Placeholder
    
    def _process_buffer(self):
        """Processa os pacotes no buffer para inserção no banco"""
        try:
            with self.buffer_lock:
                if len(self.buffer) > 0:
                    self.db.bulk_insert_packets(self.buffer)
                    self.buffer.clear()
                    logger.info(f"Buffer descarregado - {len(self.buffer)} pacotes restantes")
        except Exception as e:
            logger.error(f"Erro crítico ao processar buffer: {str(e)}")

    def _check_buffer_flush(self):
        """Gerencia o descarregamento do buffer"""
        buffer_size = len(self.buffer)
        settings = self.config.get_settings()
        
        if buffer_size >= settings.get('buffer_size', 100) or \
           (time.time() - self.last_write) > settings.get('write_interval', 5):
            
            self._flush_buffer()

    def _flush_buffer(self):
        """Descarrega o buffer no banco de dados"""
        with self.buffer_lock:
            if self.buffer:
                try:
                    self.db.bulk_insert_packets(self.buffer)
                    self.last_write = time.time()
                    self.buffer.clear()
                    logger.debug(f"Buffer descarregado - {len(self.buffer)} pacotes")
                except Exception as e:
                    logger.error(f"Erro ao escrever no banco: {str(e)}")

    def _update_service_status(self, status: str):
        """Atualiza o status do serviço"""
        try:
            self.config.update_service_status(status)
            logger.debug(f"Status atualizado para: {status}")
        except Exception as e:
            logger.error(f"Falha ao atualizar status: {str(e)}")

    def _is_capturer_active(self) -> bool:
        """Verifica se a captura está ativa"""
        return self.capturer and self.capturer.is_alive()

    def _monitor_components(self):
        """Monitora o estado dos componentes"""
        if self._is_capturer_active() and not self.capturer.is_capturing():
            logger.warning("Capturador parado inesperadamente!")
            self._update_service_status('error')

    def _signal_handler(self, signum, frame):
        """Trata sinais de desligamento"""
        logger.info(f"Recebido sinal {signum}, encerrando...")
        self.running = False
        self._stop_capture()

    def _cleanup(self):
        """Executa procedimentos de encerramento"""
        self._flush_buffer()
        self.db.connection.close()
        logger.info("Serviço IDS encerrado corretamente")

    def _is_capturer_active(self) -> bool:
        """Verifica se a captura está ativa"""
        return self.capturer.is_alive() if self.capturer else False

    def _monitor_components(self):
        """Monitora o estado dos componentes"""
        if self._is_capturer_active() and not self.capturer.is_capturing():
            logger.warning("Capturador parado inesperadamente!")
            self._update_service_status('error')

if __name__ == "__main__":
    try:
        ids = IDSController()
        ids.start()
    except Exception as e:
        logger.error(f"Falha crítica no sistema: {str(e)}")
        raise


