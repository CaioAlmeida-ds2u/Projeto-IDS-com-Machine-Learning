import logging
from flask import Flask, jsonify, request
import socket

app = Flask(__name__)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

IDS_HOST = 'localhost'  # Assumindo que ids.service roda na mesma máquina
IDS_PORT = 65432

@app.route('/ids/comando', methods=['POST'])
def receber_comando():
    """
    Endpoint para receber comandos e enviá-los ao serviço IDS.
    """
    comando_json = request.get_json()
    if not comando_json or 'acao' not in comando_json:
        logger.warning("Comando inválido recebido.")
        return jsonify({"status": "erro", "mensagem": "Comando inválido."}), 400

    acao = comando_json['acao']
    logger.info(f"API recebeu requisição para: {acao}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)  # Timeout para evitar bloqueios indefinidos
            s.connect((IDS_HOST, IDS_PORT))
            s.sendall(acao.encode())
            logger.info(f"API enviou comando '{acao}' para ids.service")

            if acao == 'status':
                status_data = s.recv(1024).decode()
                logger.info(f"API recebeu status de ids.service: {status_data}")
                return jsonify({"status": "sucesso", "data": {"service_status": status_data}}), 200
            else:
                return jsonify({"status": "sucesso", "mensagem": f"Comando '{acao}' enviado."}), 200

    except socket.timeout:
        error_message = "API Erro: Tempo limite ao tentar se conectar ao ids.service."
        logger.error(error_message)
        return jsonify({"status": "erro", "mensagem": error_message}), 504
    except ConnectionRefusedError:
        error_message = "API Erro: Conexão com ids.service recusada."
        logger.error(error_message)
        return jsonify({"status": "erro", "mensagem": error_message}), 500
    except Exception as e:
        error_message = f"API Erro ao comunicar com ids.service: {e}"
        logger.error(error_message, exc_info=True)
        return jsonify({"status": "erro", "mensagem": error_message}), 500

@app.route('/ids/config', methods=['GET'])
def handle_config():
    """
    Endpoint para lidar com configurações (não implementado nesta versão).
    """
    logger.warning("Tentativa de acesso ao endpoint de configuração não suportado.")
    return jsonify({"status": "erro", "mensagem": "Acesso à configuração não suportado nesta versão."}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)