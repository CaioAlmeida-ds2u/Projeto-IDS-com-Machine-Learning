#!/usr/bin/env python3
import time
import json
from filelock import Timeout, FileLock

# --- Configurações ---
LOG_FILE = "logs/control.log"
CONFIG_FILE = "config.json"
config_lock = FileLock(f"{CONFIG_FILE}.lock")

# --- Função para registrar eventos no log ---
def log_event(message):
    with open(LOG_FILE, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

# --- Função para iniciar o IDS ---
def start_ids():
    log_event("Enviando comando 'start' para o IDS...")
    try:
        with config_lock:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            config["command"] = "start"
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)
        log_event("Comando 'start' enviado com sucesso.")
    except Exception as e:
        log_event(f"Erro ao enviar comando 'start': {e}")

# --- Função para parar o IDS ---
def stop_ids():
    log_event("Enviando comando 'stop' para o IDS...")
    try:
        with config_lock:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            config["command"] = "stop"
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)
        log_event("Comando 'stop' enviado com sucesso.")
    except Exception as e:
        log_event(f"Erro ao enviar comando 'stop': {e}")

# --- Main ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "start":
            start_ids()
        elif command == "stop":
            stop_ids()
        else:
            print("Uso: python3 control.py [start|stop]")
    else:
        print("Uso: python3 control.py [start|stop]")