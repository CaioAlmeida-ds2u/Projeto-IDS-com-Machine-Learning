# /home/admin/ids_project/api_control.py

import json
import logging
import socket
import threading
import os
from flask import Flask, jsonify, request, abort
from typing import Dict, Any
from config import ConfigManager

app = Flask(__name__)
logger = logging.getLogger(__name__)

IDS_HOST = 'localhost'
IDS_PORT = 65432
API_KEY = os.environ.get('IDS_API_KEY', 'secret_key')  # Defina via variável de ambiente

def configure_logging():
    """Configura o logging com base no ConfigManager."""
    config_manager = ConfigManager()
    log_level = config_manager.get_config().get('settings', {}).get('log_level', 'INFO')
    logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO),
                        format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
    logger.info("Logging configurado para api_control.")

def send_command(command: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Envia um comando ao IDS via socket e retorna a resposta."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((IDS_HOST, IDS_PORT))
            s.sendall(command.encode('utf-8'))
            response = s.recv(4096).decode('utf-8')
            return json.loads(response)  # Agora tudo é JSON
    except socket.timeout:
        return {"status": "error", "message": "Timeout ao conectar ao IDS"}
    except ConnectionRefusedError:
        return {"status": "error", "message": "Conexão com IDS recusada"}
    except Exception as e:
        logger.error(f"Erro ao enviar comando '{command}': {e}", exc_info=True)
        return {"status": "error", "message": str(e)}

def check_auth():
    """Verifica a autenticação via API key."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != f"Bearer {API_KEY}":
        abort(401, description="Autenticação necessária ou inválida")

@app.route('/health', methods=['GET'])
def health_check():
    check_auth()
    config_manager = ConfigManager()
    api_status = {"status": "ok", "component": "api_control"}
    dependencies = {}

    try:
        result = send_command('status', timeout=3.0)  # Aumentado de 1.0 para 3.0
        logger.info(f"Resposta do IDS para 'status': {result}")
        if result["status"] == "success":
            dependencies["ids_service"] = result
        else:
            dependencies["ids_service"] = {"status": "unreachable", "error": result["message"]}
        api_status["dependencies"] = dependencies
        return jsonify(api_status), 200
    except Exception as e:
        logger.error(f"Erro no health check: {e}", exc_info=True)
        api_status["status"] = "error"
        api_status["error"] = str(e)
        return jsonify(api_status), 500

@app.route('/ids/command', methods=['POST'])
def receive_command():
    """Envia comandos ao IDS."""
    check_auth()
    data = request.get_json()
    if not data or 'action' not in data:
        return jsonify({"status": "error", "message": "Comando inválido"}), 400

    action = data['action']
    allowed_actions = ConfigManager().get_config().get('service', {}).get('allowed_actions', [])
    if action not in allowed_actions:
        return jsonify({"status": "error", "message": f"Ação '{action}' não permitida"}), 403

    logger.info(f"Recebido comando: {action}")
    result = send_command(action)
    return jsonify(result), 200 if result["status"] == "success" else 500

@app.route('/ids/config', methods=['GET', 'POST'])
def handle_config():
    """Gerencia a configuração do IDS."""
    check_auth()
    config_manager = ConfigManager()

    if request.method == 'GET':
        return jsonify(config_manager.get_config()), 200

    elif request.method == 'POST':
        new_config = request.get_json()
        if not new_config:
            return jsonify({"status": "error", "message": "Configuração inválida"}), 400
        if config_manager.update_config(new_config):
            return jsonify({"status": "success", "message": "Configuração atualizada"}), 200
        return jsonify({"status": "error", "message": "Falha ao atualizar configuração"}), 500

if __name__ == "__main__":
    configure_logging()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)