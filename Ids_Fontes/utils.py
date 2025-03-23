# ids_project/utils.py
import logging
from filelock import FileLock, Timeout

def configure_logging():
    """Configuração centralizada de logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ids.log'),
            logging.StreamHandler()
        ]
    )

def safe_file_access(file_path: str, timeout: int = 5, mode: str = 'r'):
    """Context manager para acesso seguro a arquivos"""
    lock = FileLock(f"{file_path}.lock", timeout=timeout)
    try:
        with lock:
            with open(file_path, mode) as f:
                yield f
    except Timeout:
        logging.error(f"Timeout ao acessar arquivo {file_path}")
        raise