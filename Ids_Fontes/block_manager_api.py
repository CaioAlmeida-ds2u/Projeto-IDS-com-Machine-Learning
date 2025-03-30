import logging
import signal
import ipaddress # Para validar IPs
import os
from typing import Optional
from flask import Flask, jsonify, request, Response
from config import ConfigManager
from redis_client import RedisClient

# Configuração inicial do logger (será reconfigurado)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
logger = logging.getLogger("BlockManagerAPI") # Logger específico

# Instância do Flask
app = Flask(__name__)

# Variáveis globais para manter instâncias (alternativa a injeção de dependência)
config_manager: Optional[ConfigManager] = None
redis_client: Optional[RedisClient] = None

# --- Inicialização e Configuração ---

def initialize_api():
    """
    Inicializa o ConfigManager, o RedisClient e configura o logging da API.
    Retorna True em sucesso, False em falha.
    """
    global config_manager, redis_client
    logger.info("Inicializando BlockManagerAPI...")
    try:
        # 1. Carrega ConfigManager
        config_manager = ConfigManager()

        # 2. Configura Logging (com base na config carregada)
        settings_config = config_manager.get_config().get('settings', {})
        log_level_str = settings_config.get('log_level', 'INFO').upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        # Reconfigura o logger raiz para o nível desejado
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]: root_logger.removeHandler(handler)
        formatter = logging.Formatter('%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        root_logger.addHandler(stream_handler)
        root_logger.setLevel(log_level)
        logger.info(f"Logging da BlockManagerAPI configurado para nível: {logging.getLevelName(log_level)}")

        # 3. Inicializa RedisClient
        redis_config = config_manager.get_redis_config()
        if not redis_config: raise ValueError("Seção 'redis' ausente na config.")
        redis_client = RedisClient(
            host=redis_config.get('host'),
            port=int(redis_config.get('port')),
            db=int(redis_config.get('db')),
            password=redis_config.get('password'),
            block_list_key=redis_config.get('block_list_key')
            # TTL não é gerenciado por esta API
        )
        # Verifica conexão inicial
        if not redis_client.get_connection():
             raise redis.exceptions.ConnectionError("Falha ao conectar ao Redis na inicialização da API.")

        logger.info("BlockManagerAPI inicializada com sucesso.")
        return True

    except Exception as e:
        logger.critical(f"Erro fatal ao inicializar BlockManagerAPI: {e}", exc_info=True)
        # Garante que as variáveis globais fiquem None em caso de falha
        config_manager = None
        redis_client = None
        return False

# Hook do Flask para verificar a conexão Redis antes de cada requisição
@app.before_request
def check_redis_connection():
    """Verifica a conexão Redis. Retorna erro 503 se indisponível."""
    global redis_client
    # Tenta obter conexão (que pode tentar reconectar)
    if not redis_client or not redis_client.get_connection():
        logger.error("API não pode processar requisição: Conexão Redis indisponível.")
        # 503 Service Unavailable é apropriado aqui
        return jsonify({
            "status": "erro",
            "mensagem": "Erro interno do servidor: Backend de dados indisponível."
        }), 503
    # Se a conexão está OK, a requisição continua normalmente (retorna None)

# --- Endpoints da API ---

@app.route('/health', methods=['GET'])
def health_check():
    """Verifica a saúde da API e a conexão Redis."""
    status_data = {"status": "ok", "component": "block_manager_api"}
    redis_status = "unknown"
    try:
        # before_request já tenta conectar, aqui verificamos explicitamente
        conn = redis_client.get_connection() # Tenta obter/validar conexão
        if conn and conn.ping(): # Ping é um comando leve para verificar
            redis_status = "connected"
        else:
            redis_status = "disconnected"
        status_code = 200
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, AttributeError) as e:
         logger.warning(f"Health check: Falha na verificação Redis: {e}")
         redis_status = "error"
         status_data["error"] = f"Redis connection error: {e}"
         status_code = 503 # Service unavailable (dependência falhou)
    except Exception as e:
         logger.error(f"Health check: Erro inesperado: {e}", exc_info=True)
         status_data["status"] = "error"
         status_data["error"] = f"Unexpected error: {e}"
         redis_status = "error"
         status_code = 500

    status_data["dependencies"] = {"redis": redis_status}
    return jsonify(status_data), status_code

@app.route('/blocked', methods=['GET'])
def list_blocked_ips():
    """
    Endpoint GET para listar todos os IPs atualmente na lista de bloqueio do Redis.
    Retorna uma lista ordenada de IPs.
    """
    global redis_client
    logger.info("Recebida requisição GET /blocked")
    try:
        # get_blocked_ips retorna um Set ou None
        blocked_ips_set = redis_client.get_blocked_ips()

        if blocked_ips_set is None:
             # Erro já logado pelo redis_client ou before_request
             return jsonify({"status": "erro", "mensagem": "Erro ao buscar dados da lista de bloqueio."}), 500

        # Converte o Set para lista e ordena para uma resposta consistente
        blocked_ips_list = sorted(list(blocked_ips_set))

        return jsonify({
            "status": "sucesso",
            "count": len(blocked_ips_list),
            "blocked_ips": blocked_ips_list
        }), 200

    except Exception as e:
        # Captura outros erros inesperados
        logger.error(f"Erro inesperado em GET /blocked: {e}", exc_info=True)
        return jsonify({"status": "erro", "mensagem": "Erro interno do servidor ao processar a requisição."}), 500

@app.route('/blocked/<string:ip_address>', methods=['DELETE'])
def unblock_ip(ip_address: str):
    """
    Endpoint DELETE para remover (desbloquear) um IP específico da lista no Redis.
    O Blocker Worker detectará essa remoção e removerá a regra do firewall.
    """
    global redis_client
    logger.info(f"Recebida requisição DELETE /blocked/{ip_address}")

    # 1. Validar o formato do IP recebido na URL
    try:
        # Tenta converter para um objeto IP (v4 ou v6)
        ip_obj = ipaddress.ip_address(ip_address)
        # Usa a forma canônica/normalizada do IP
        ip_to_remove = str(ip_obj)
        logger.debug(f"IP validado para remoção: {ip_to_remove}")
    except ValueError:
        logger.warning(f"Formato de IP inválido recebido para desbloqueio: {ip_address}")
        return jsonify({
            "status": "erro",
            "mensagem": f"Formato de endereço IP inválido fornecido: '{ip_address}'."
        }), 400 # 400 Bad Request

    # 2. Tentar remover o IP do Redis
    try:
        # remove_block retorna True se removeu, False se não existia ou erro
        removed = redis_client.remove_block(ip_to_remove)

        if removed:
            logger.info(f"IP {ip_to_remove} removido da lista de bloqueio Redis via API.")
            return jsonify({
                "status": "sucesso",
                "mensagem": f"IP {ip_to_remove} removido da lista de bloqueio com sucesso. O Blocker Worker removerá a regra do firewall."
            }), 200 # 200 OK
        else:
            # Log warning já é feito pelo redis_client se não encontrou
            return jsonify({
                "status": "nao_encontrado",
                "mensagem": f"IP {ip_to_remove} não encontrado na lista de bloqueio ativa."
            }), 404 # 404 Not Found

    except Exception as e:
        # Captura erros inesperados na comunicação com Redis ou outros
        logger.error(f"Erro inesperado em DELETE /blocked/{ip_to_remove}: {e}", exc_info=True)
        return jsonify({"status": "erro", "mensagem": "Erro interno do servidor ao tentar remover o IP."}), 500


# Opcional: Endpoint para adicionar bloqueio manual via API
@app.route('/blocked', methods=['POST'])
def add_manual_block():
    """
    Endpoint POST para adicionar manualmente um IP à lista de bloqueio.
    Espera um JSON no corpo da requisição: {"ip_address": "x.x.x.x", "ttl": 3600 (opcional)}
    """
    global redis_client
    logger.info("Recebida requisição POST /blocked")

    # 1. Verifica se o corpo é JSON
    if not request.is_json:
        logger.warning("Requisição POST /blocked recebida sem corpo JSON.")
        return jsonify({"status": "erro", "mensagem": "Corpo da requisição deve ser JSON."}), 400

    # 2. Extrai dados do JSON
    data = request.get_json()
    ip_to_block = data.get("ip_address")
    ttl_str = data.get("ttl") # TTL é opcional

    # 3. Valida IP
    if not ip_to_block:
        return jsonify({"status": "erro", "mensagem": "Campo 'ip_address' é obrigatório no JSON."}), 400
    try:
        ip_obj = ipaddress.ip_address(ip_to_block)
        ip_to_block = str(ip_obj) # Forma canônica
    except ValueError:
        return jsonify({"status": "erro", "mensagem": f"Formato de 'ip_address' inválido: '{ip_to_block}'."}), 400

    # 4. Valida TTL (se fornecido)
    ttl: Optional[int] = -1 # Usa TTL padrão do RedisClient se não fornecido ou inválido
    if ttl_str is not None:
        try:
            ttl_val = int(ttl_str)
            if ttl_val >= 0: # Permite 0 para sem expiração
                ttl = ttl_val
            else:
                 logger.warning(f"TTL inválido fornecido ({ttl_str}), usando TTL padrão.")
                 # Mantém ttl = -1 para usar o padrão do RedisClient
        except (ValueError, TypeError):
             logger.warning(f"TTL inválido fornecido ({ttl_str}), usando TTL padrão.")
             # Mantém ttl = -1 para usar o padrão do RedisClient

    # 5. Adiciona ao Redis
    try:
        # add_block usa TTL padrão se ttl=-1
        success = redis_client.add_block(ip_to_block, ttl=ttl if ttl != -1 else None)
        if success:
            logger.info(f"IP {ip_to_block} adicionado manualmente à lista de bloqueio via API (TTL Solicitado: {ttl if ttl != -1 else 'padrão'}).")
            return jsonify({
                "status": "sucesso",
                "mensagem": f"IP {ip_to_block} adicionado à lista de bloqueio. O Blocker Worker aplicará a regra."
            }), 201 # 201 Created (ou 200 OK se já existia)
        else:
            # Erro já logado pelo redis_client
             return jsonify({"status": "erro", "mensagem": "Falha ao adicionar IP à lista de bloqueio (verificar logs)."}), 500
    except Exception as e:
         logger.error(f"Erro inesperado em POST /blocked para {ip_to_block}: {e}", exc_info=True)
         return jsonify({"status": "erro", "mensagem": "Erro interno do servidor ao adicionar o bloqueio."}), 500


# --- Gerenciamento do Servidor ---

def shutdown_server(signum=None, frame=None):
    """Função chamada ao receber SIGHUP ou SIGTERM para tentar parar graciosamente."""
    signal_name = f"Sinal {signal.Signals(signum).name}" if signum else "Chamada programática"
    logger.warning(f"{signal_name} recebido. Desligando a BlockManagerAPI...")
    # Não há um método direto para parar o servidor de dev do Flask de forma limpa.
    # Em produção, o Gunicorn/uWSGI receberia o sinal e gerenciaria as workers.
    # Apenas fechamos o cliente Redis aqui.
    if redis_client:
        redis_client.close()
    # O processo será encerrado pelo systemd ou manualmente.
    # exit(0) # Evitar exit() explícito se possível

# --- Ponto de Entrada ---
if __name__ == '__main__':
    # Inicializa as dependências globais (Config, Redis)
    if initialize_api():
        # Configura handlers de sinal para desligamento
        # SIGINT (Ctrl+C) geralmente já causa a parada, mas podemos adicionar handler se quisermos log extra.
        signal.signal(signal.SIGTERM, shutdown_server)
        signal.signal(signal.SIGHUP, shutdown_server) # SIGHUP também pode ser usado para reload/shutdown

        # Define host e porta para a API (diferente dos outros serviços)
        # Usar 0.0.0.0 para ser acessível externamente (se necessário)
        # ou 127.0.0.1 para acesso apenas local.
        api_host = os.environ.get('BLOCK_API_HOST', '0.0.0.0')
        api_port = int(os.environ.get('BLOCK_API_PORT', 5002)) # Ex: Porta 5002

        logger.info(f"Iniciando Block Manager API em http://{api_host}:{api_port}")

        # --- Execução ---
        # Em desenvolvimento: app.run()
        # Em produção: use um servidor WSGI como Gunicorn ou uWSGI!
        # Exemplo com Gunicorn (instalar com pip install gunicorn):
        # gunicorn --bind 0.0.0.0:5002 block_manager_api:app --workers 2 --log-level info
        # Para desenvolvimento:
        app.run(host=api_host, port=api_port, debug=False) # debug=False é mais seguro

        logger.info("Servidor Flask da BlockManagerAPI encerrado.")

    else:
        logger.critical("Não foi possível iniciar a Block Manager API devido a erro na inicialização.")
        exit(1)