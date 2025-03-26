from flask import Flask, jsonify, request
import subprocess
import mysql.connector
import logging

# Configuração do Flask
app = Flask(__name__)

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurações do Banco de Dados MariaDB
DB_HOST = 'localhost'
DB_PORT = 3306
DB_NAME = 'ids_db'
DB_USER = 'ids_user'
DB_PASSWORD = 'password'

def connect_to_database():
    """Conecta ao banco de dados MariaDB."""
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        return connection
    except mysql.connector.Error as e:
        logger.error(f"Erro ao conectar ao banco de dados: {e}", exc_info=True)
        raise

def unblock_ip(ip_address):
    """Desbloqueia um endereço IP usando iptables."""
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        logger.info(f"Endereço IP {ip_address} desbloqueado com sucesso.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao desbloquear o IP {ip_address}: {e}")
        raise

@app.route('/blocked_ips', methods=['GET'])
def get_blocked_ips():
    """Endpoint para listar todos os IPs bloqueados."""
    try:
        connection = connect_to_database()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT ip_address, reason, timestamp FROM blocked_ips")
        blocked_ips = cursor.fetchall()
        cursor.close()
        connection.close()
        return jsonify({"status": "sucesso", "blocked_ips": blocked_ips}), 200
    except Exception as e:
        logger.error(f"Erro ao obter lista de IPs bloqueados: {e}", exc_info=True)
        return jsonify({"status": "erro", "mensagem": "Erro ao obter lista de IPs bloqueados."}), 500

@app.route('/unblock_ip', methods=['POST'])
def api_unblock_ip():
    """Endpoint para desbloquear um IP."""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')

        if not ip_address:
            return jsonify({"status": "erro", "mensagem": "IP não fornecido."}), 400

        # Desbloquear o IP no firewall
        unblock_ip(ip_address)

        # Remover o IP do banco de dados
        connection = connect_to_database()
        cursor = connection.cursor()
        cursor.execute("DELETE FROM blocked_ips WHERE ip_address = %s", (ip_address,))
        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({"status": "sucesso", "mensagem": f"IP {ip_address} desbloqueado com sucesso."}), 200
    except Exception as e:
        logger.error(f"Erro ao desbloquear IP: {e}", exc_info=True)
        return jsonify({"status": "erro", "mensagem": "Erro ao desbloquear IP."}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)

#curl -X POST -H "Content-Type: application/json" -d '{"ip_address": "192.168.1.100"}' http://localhost:5002/unblock_ip
#curl http://localhost:5002/blocked_ips
