#!/usr/bin/env python3
import subprocess
import time
import signal
import os
import json
import threading  # Importa threading

# --- Configurações ---
IDS_SCRIPT = "ids.py"
LOG_FILE = "logs/control.log"
PID_FILE = "ids_pid.txt"
WAIT_TIME = 10
CONFIG_FILE = "config.json"
config_lock = threading.Lock() #Cria o lock

# --- Função para registrar eventos no log ---
def log_event(message):
    with open(LOG_FILE, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

# --- Função para iniciar o IDS ---
def start_ids():
    log_event("Iniciando o IDS...")
    try:
        # Modificar a configuração para iniciar a captura
        with config_lock:  # Adquire o lock
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            config["start"] = True
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)

        # Iniciar o ids.py (sem sudo aqui!)
        process = subprocess.Popen(["python3", IDS_SCRIPT])
        log_event(f"IDS iniciado com PID: {process.pid}")
        return process

    except Exception as e:
        log_event(f"Erro ao iniciar o IDS: {e}")
        return None

# --- Função para parar o IDS ---
def stop_ids(process):
    log_event("Parando o IDS...")
    try:
        # Modificar a configuração para parar a captura
        with config_lock:  # Adquire o lock
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            config["start"] = False
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)

        # Ler o PID do arquivo
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())

        # Verificar se o processo ainda está rodando antes de matar
        if os.path.exists(f"/proc/{pid}"):  # Apenas para sistemas Unix/Linux
            os.kill(pid, signal.SIGTERM)
            log_event("Sinal SIGTERM enviado ao IDS.")
            process.wait(timeout=10) #Espera o processo
        else:
            log_event("O processo do IDS já foi encerrado.")

    except FileNotFoundError:
        log_event("Arquivo PID ou config não encontrado.")
    except ProcessLookupError:
        log_event("O processo IDS já foi encerrado.")
    except Exception as e:
        log_event(f"Erro ao parar o IDS: {e}")

# --- Main ---
if __name__ == "__main__":
    ids_process = start_ids()

    if ids_process:
        time.sleep(WAIT_TIME)
        stop_ids(ids_process)