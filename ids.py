#!/usr/bin/env python3
# --- Imports ---
import scapy.all as scapy
import time
import signal
import os
import json
import threading

# --- Variáveis Globais ---
running = True
config_file = "config.json"
pid_file = "ids_pid.txt"
database_file = "ids.db"
buffer = []
buffer_lock = threading.Lock()
last_write_time = time.time()
config_lock = threading.Lock()  # Lock para acesso ao config.json

# --- Configurações ---
DATABASE_FILE = "ids.db"
BUFFER_SIZE_LIMIT = 100
WRITE_INTERVAL = 5
INTERFACE = "enp0s3"
LOG_FILE = "logs/ids.log"

# --- Função para lidar com sinais (SIGTERM, SIGINT) ---
def signal_handler(signum, frame):
    """Lida com sinais (SIGINT, SIGTERM) para encerrar o IDS."""
    global running
    log_event(f"Sinal {signum} recebido. Encerrando o IDS...")
    running = False

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
    with config_lock:  # Adiciona lock para evitar condições de corrida
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                return config
        except FileNotFoundError:
            log_event("Arquivo de configuração não encontrado. Criando um novo com valores padrão.")
            default_config = {"start": False, "blocked_protocols": []}
            try:
                with open(config_file, "w") as f:
                    json.dump(default_config, f, indent=4)
                return default_config
            except Exception as e:
                log_event(f"Erro ao salvar config: {e}")
                exit(1)

        except json.JSONDecodeError:
            log_event("Erro ao decodificar o arquivo de configuração. Usando configuração padrão.")
            return {"start": False, "blocked_protocols": []}
        except Exception as e:
            log_event(f"Erro ao ler configurações: {e}")
            return {"start": False, "blocked_protocols": []}

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
    """Processa cada pacote capturado."""
    if hasattr(packet, "haslayer") and (packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP)):  # Verifica se é TCP ou UDP
        log_event(f"Pacote recebido: {packet.summary()}")

# --- Função para verificar se devemos parar (usada pelo stop_filter) ---
def should_stop_sniffing(packet):
    """Verifica se a variável 'running' é False (usada como stop_filter)."""
    global running
    return not running

# --- Função para iniciar a captura (NOVO) ---
def start_capture():
    """Inicia a captura de pacotes (precisa ser executada com sudo)."""
    global running
    log_event("Iniciando captura de pacotes...")
    try:
        while running:
            try:
                scapy.sniff(prn=process_packet, store=False, iface=INTERFACE,
                            stop_filter=should_stop_sniffing, timeout=10)  # Adicionado timeout
            except scapy.Scapy_Exception as e:
                log_event(f"Erro do Scapy: {e}")
                break  # Sai do loop interno em caso de erro
            except Exception as e:
                log_event(f"Erro inesperado: {e}")
                break  # Sai do loop interno em caso de erro

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

    try:
        while running:
            time.sleep(1)
    except Exception as e:
        log_event(f"Erro na espera: {e}")
    finally:
        log_event("Encerrando o IDS...")
        try:
            os.remove(pid_file)
        except FileNotFoundError:
            pass
        log_event("IDS encerrado.")

# --- Execução do Script ---
if __name__ == "__main__":
    config = read_config()
    if config.get("start", False):  # Usa .get() com valor padrão
        start_capture()
    else:
        main()