# /home/admin/ids_project/train_service.py

import logging
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from flask import Flask, request, jsonify
import os
from typing import List, Dict, Any

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

# Caminho para salvar o modelo
MODEL_PATH = "/home/admin/ids_project/models/modelo_ml.joblib"

# Features esperadas
FEATURES = [
    "payload_size", "src_port", "dst_port", "ttl", "udp_length", "is_tcp", "is_udp", "is_icmp",
    "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg", "flag_ece", "flag_cwr",
    "port_src_well_known", "port_dst_well_known", "port_dst_is_dns", "port_dst_is_ntp",
    "port_dst_is_http", "port_dst_is_https", "same_network", "is_private"
]

app = Flask(__name__)

def train_model(data: pd.DataFrame) -> IsolationForest:
    """Treina o modelo de detecção de anomalias."""
    model = IsolationForest(
        contamination=0.2,  # 20% de anomalias esperadas
        random_state=42,
        n_estimators=100
    )
    model.fit(data)
    logger.info("Modelo treinado com sucesso.")
    return model

def save_model(model: IsolationForest, path: str = MODEL_PATH):
    """Salva o modelo em um arquivo .joblib."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    logger.info(f"Modelo salvo em: {path}")

@app.route('/train', methods=['POST'])
def train_from_payload():
    """Treina o modelo a partir de um payload CSV ou JSON."""
    content_type = request.headers.get('Content-Type')

    try:
        # Suporte a CSV
        if content_type == 'text/csv' or 'file' in request.files:
            if 'file' in request.files:
                file = request.files['file']
                if not file.filename.endswith('.csv'):
                    return jsonify({"error": "Arquivo deve ser CSV"}), 400
                data = pd.read_csv(file)
            else:
                data = pd.read_csv(request.stream)
            
            if not all(f in data.columns for f in FEATURES):
                return jsonify({"error": f"O CSV deve conter todas as colunas: {FEATURES}"}), 400

        # Suporte a JSON
        elif content_type == 'application/json':
            json_data = request.get_json()
            if not json_data or 'data' not in json_data:
                return jsonify({"error": "JSON deve conter chave 'data' com lista de pacotes"}), 400
            data = pd.DataFrame(json_data['data'])
            if not all(f in data.columns for f in FEATURES):
                return jsonify({"error": f"O JSON deve conter todas as colunas: {FEATURES}"}), 400

        else:
            return jsonify({"error": "Content-Type deve ser 'text/csv' ou 'application/json'"}), 400

        # Treina e salva o modelo
        model = train_model(data)
        save_model(model)
        return jsonify({"message": f"Modelo treinado e salvo em {MODEL_PATH}"}), 200

    except Exception as e:
        logger.error(f"Erro ao treinar via API: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = 5002  # Porta diferente para evitar conflito com api_control.py (5000)
    logger.info(f"Iniciando serviço de treinamento na porta {port}...")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)