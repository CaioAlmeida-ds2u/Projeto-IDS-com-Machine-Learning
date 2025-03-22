#!/usr/bin/env python3
# --- Imports ---
import scapy.all as scapy
import time
import signal
import os
import json
import threading
from filelock import Timeout, FileLock

# --- Variáveis Globais ---
running = True  # Controla a captura, nao o serviço em si
config_file = "config.json"
pid_file = "ids_pid.txt"  # Ainda usado para o systemd saber o PID
database_file = "ids.db"
buffer = []
buffer_lock = threading.Lock()
last_write_time = time.time()
config_lock = FileLock(f"{config_file}.lock")

# --- Configurações ---
DATABASE_FILE = "ids.db"
BUFFER_SIZE_LIMIT = 100
WRITE_INTERVAL = 5
INTERFACE = "enp0s3"
LOG_FILE = "logs/ids.log"  # Usado pelo systemd também

# --- Função para lidar com sinais (SIGTERM, SIGINT) ---
#agora o sinal é usado para finalizar todo o serviço
def signal_handler(signum, frame):
    """Lida com sinais (SIGINT, SIGTERM) para encerrar o IDS."""
    global running
    log_event(f"Sinal {signum} recebido. Encerrando o IDS...")
    running = False #encerra tudo
    exit(0)


# --- Funções de Decodificação (placeholders) ---
def unpack_ethernet_header(packet):
    pass

def unpack_ip_header(packet):
    pass

def unpack_tcp_header(packet):
    pass

def unpack_udp_header(packet):
    pass

# --- Função para ler a configuração ---
def read_config():
    """Lê o arquivo de configuração (config.json) e retorna um dicionário."""
    with config_lock:
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                return config
        except FileNotFoundError:
            log_event("Arquivo de configuração não encontrado. Criando um novo com valores padrão.")
            default_config = {"command": ""}  # Começa sem nenhum comando
            try:
                with open(config_file, "w") as f:
                    json.dump(default_config, f, indent=4)
                return default_config
            except:
                log_event(f"Erro ao salvar config")
                exit(1)
        except json.JSONDecodeError:
            log_event("Erro ao decodificar o arquivo de configuração. Usando configuração padrão.")
            return {"command": ""}
        except Exception as e:
            log_event(f"Erro ao ler configurações: {e}")
            return {"command": ""}
# --- Função para limpar o comando no config.json (NOVO) ---
def clear_command():
    """Limpa o campo 'command' no arquivo config.json."""
    with config_lock:
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
            config["command"] = ""  # Limpa o comando
            with open(config_file, "w") as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            log_event(f"Erro ao limpar o comando: {e}")

# --- Funções para Machine Learning (placeholders) ---
def load_model():
    pass

def detect_anomaly(features):
    pass

# --- Função de thread (placeholder)
def write_to_db(data):
  pass

# --- Função de Logging ---
def log_event(message):
    """Registra uma mensagem no arquivo de log com timestamp."""
    try:
        with open(LOG_FILE, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Erro ao registrar log: {e}")

# --- Função de Processamento de Pacotes ---
def process_packet(packet):
    """Processa cada pacote capturado (placeholder)."""
    log_event(packet.summary())

# --- Função para verificar se devemos parar (usada pelo stop_filter) ---
def should_stop_sniffing(packet):
    """Verifica se a variável 'running' é False."""
    global running
    return not running  # Agora, só verifica 'running'

# --- Função para iniciar a captura (Modificada) ---
def start_capture():
    """Inicia a captura de pacotes."""
    global running
    log_event("Iniciando captura de pacotes...")
    try:
        while running: #mantem a captura
            try:
                scapy.sniff(prn=process_packet, store=False, iface=INTERFACE,
                            stop_filter=should_stop_sniffing)
            except scapy.Scapy_Exception as e:
                log_event(f"Erro do Scapy: {e}")
                break
            except Exception as e:
                log_event(f"Erro inesperado: {e}")
                break
    except Exception as e:
        log_event(f"Erro no loop de captura: {e}")

    finally:
        log_event("Captura finalizada.")

# --- Loop Principal ---
def main():
    global running

    # Registrar o PID
    try:
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
    except Exception as e:
        log_event(f"Erro ao registrar o PID: {e}")
        return

    # Registrar os tratadores de sinais
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    log_event("IDS iniciado, aguardando comando.")

    capturing = False  # Variável para controlar se a captura está ativa
    while True:  # Loop infinito (o serviço roda continuamente)
        try:
            config = read_config()
            command = config.get("command", "")

            if command == "start" and not capturing:
                start_capture()  # Inicia a captura
                capturing = True
                clear_command()  # Limpa o comando
            elif command == "stop" and capturing:
                running = False # Para a captura
                capturing = False
                clear_command()
            elif command == "stop" and not capturing: #caso ja tiver parado
                clear_command()
            #Verifica se chegou novo comando ou se o processo não está rodando
            time.sleep(1)

        except Exception as e:
            log_event(f"Erro no loop principal: {e}")

# --- Execução do Script ---
if __name__ == "__main__":
    main()