# ids_project/utils.py
import logging
from typing import Generator
from filelock import FileLock, Timeout

def configure_logging(log_level: str = 'INFO', log_file: str = 'ids.log'):
    """Configuração centralizada de logging"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def safe_file_access(file_path: str, timeout: int = 5, mode: str = 'r') -> Generator:
    """
    Context manager para acesso seguro a arquivos.

    Args:
        file_path (str): Caminho do arquivo a ser acessado.
        timeout (int): Tempo máximo para adquirir o bloqueio (em segundos).
        mode (str): Modo de abertura do arquivo ('r', 'w', 'a', etc.).

    Yields:
        file object: Objeto de arquivo aberto no modo especificado.

    Raises:
        Timeout: Se o bloqueio não puder ser adquirido dentro do tempo limite.
    """
    lock = FileLock(f"{file_path}.lock", timeout=timeout)
    try:
        with lock:
            with open(file_path, mode) as f:
                yield f
    except Timeout:
        logging.error(f"Timeout ao acessar arquivo {file_path}")
        raise