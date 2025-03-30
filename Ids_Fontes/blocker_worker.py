import logging
import time
import signal
import subprocess
import redis # Import direto do redis pode ser necessário para erros específicos
from typing import Set, Optional, List # List adicionado para o comando subprocess

# Componentes locais
from config import ConfigManager
from redis_client import RedisClient

# Configuração inicial (será reconfigurada)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
logger = logging.getLogger("BlockerWorker") # Logger específico

class BlockerWorker:
    """
    Serviço Worker que monitora o Redis por IPs a serem bloqueados/desbloqueados
    e aplica/remove as regras correspondentes no firewall do sistema (iptables/UFW).

    Requer permissões elevadas (root ou CAP_NET_ADMIN) para modificar o firewall.
    """
    def __init__(self):
        """Inicializa o Blocker Worker."""
        logger.info("Inicializando BlockerWorker...")
        self.config_manager = ConfigManager()
        self.running = True # Controle do loop principal
        self.redis_client: Optional[RedisClient] = None

        # Configurações (serão carregadas)
        self.log_level = logging.INFO
        self.firewall_type = 'iptables' # Padrão
        self.check_interval = 5 # Segundos (padrão)
        self.block_list_key = 'ids:blocked_ips' # Padrão

        # Estado interno: IPs que este worker *acredita* ter bloqueado no firewall.
        # Usado para comparar com o Redis e evitar comandos redundantes.
        self.currently_blocked_in_firewall: Set[str] = set()

        try:
            self._load_configuration()
            self._configure_logging()
            self._initialize_redis_client()
            # Opcional: Tentar detectar regras existentes no início? É complexo e frágil.
            # self._detect_initial_firewall_blocks()
            logger.info("BlockerWorker inicializado com sucesso (configurações carregadas).")
        except Exception as e:
             logger.critical(f"Falha crítica na inicialização do BlockerWorker: {e}", exc_info=True)
             self.running = False
             self._cleanup()
             raise RuntimeError("Falha na inicialização do BlockerWorker") from e

    def _load_configuration(self):
        """Carrega as configurações relevantes para o worker."""
        logger.info("Carregando configurações do BlockerWorker...")
        try:
             # Log Level (da seção settings)
             settings_config = self.config_manager.get_config().get('settings', {})
             log_level_str = settings_config.get('log_level', 'INFO').upper()
             self.log_level = getattr(logging, log_level_str, logging.INFO)

             # Config Blocker Worker
             worker_config = self.config_manager.get_blocker_worker_config()
             if not worker_config: raise ValueError("Seção 'blocker_worker' ausente na config.")
             self.firewall_type = worker_config.get('firewall_type', self.firewall_type).lower()
             self.check_interval = int(worker_config.get('check_interval_seconds', self.check_interval))
             if self.check_interval <= 0: raise ValueError("check_interval_seconds deve ser positivo.")
             if self.firewall_type not in ['iptables', 'ufw']:
                  logger.warning(f"Tipo de firewall '{self.firewall_type}' não suportado. Usando 'iptables'.")
                  self.firewall_type = 'iptables'

             # Config Redis (apenas a chave é essencial aqui)
             redis_config = self.config_manager.get_redis_config()
             if not redis_config: raise ValueError("Seção 'redis' ausente na config.")
             self.block_list_key = redis_config.get('block_list_key', self.block_list_key)
             if not self.block_list_key: raise ValueError("redis.block_list_key não pode ser vazio.")

             logger.info(f"Config BlockerWorker: Firewall={self.firewall_type}, Interval={self.check_interval}s, RedisKey={self.block_list_key}")

        except (ValueError, TypeError, KeyError) as e:
             logger.critical(f"Erro ao carregar ou validar configurações do BlockerWorker: {e}")
             raise RuntimeError("Configuração inválida para BlockerWorker.") from e
        except Exception as e:
            logger.critical(f"Erro inesperado ao carregar config BlockerWorker: {e}", exc_info=True)
            raise RuntimeError("Erro ao carregar config BlockerWorker.") from e

    def _configure_logging(self):
        """Reconfigura o logging globalmente com o nível carregado."""
        # (Mesma lógica de _configure_logging dos outros módulos)
        try:
            root_logger = logging.getLogger()
            for handler in root_logger.handlers[:]: root_logger.removeHandler(handler)
            formatter = logging.Formatter('%(asctime)s - %(name)s [%(levelname)s] - %(message)s')
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            root_logger.addHandler(stream_handler)
            root_logger.setLevel(self.log_level)
            logger.info(f"Logging do BlockerWorker configurado para nível: {logging.getLevelName(root_logger.getEffectiveLevel())}")
        except Exception as e:
            print(f"CRITICAL: Falha ao configurar logging do BlockerWorker: {e}")
            logger.critical(f"Falha ao configurar logging do BlockerWorker: {e}", exc_info=True)

    def _initialize_redis_client(self):
        """Inicializa o cliente Redis."""
        # (Mesma lógica de _initialize_redis_client dos outros módulos)
        logger.info("Inicializando cliente Redis para BlockerWorker...")
        try:
            redis_config = self.config_manager.get_redis_config()
            if not redis_config: raise ValueError("Seção 'redis' ausente.")
            self.redis_client = RedisClient(
                host=redis_config.get('host'),
                port=int(redis_config.get('port')),
                db=int(redis_config.get('db')),
                password=redis_config.get('password'),
                block_list_key=self.block_list_key
                # TTL não é usado para leitura
            )
            if not self.redis_client.get_connection():
                 raise redis.exceptions.ConnectionError("Falha ao conectar ao Redis na inicialização.")
            logger.info("Cliente Redis do BlockerWorker inicializado e conectado.")
        except Exception as e: # Captura erros de config ou conexão
            logger.critical(f"Erro ao inicializar RedisClient no BlockerWorker: {e}")
            self.redis_client = None
            raise RuntimeError("Falha ao inicializar Redis para BlockerWorker.") from e


    def _run_command(self, command: List[str]) -> bool:
        """
        Executa um comando de sistema (firewall) de forma segura.

        Args:
            command (List[str]): O comando e seus argumentos como uma lista.

        Returns:
            bool: True se o comando foi executado com sucesso (código de saída 0),
                  False caso contrário.
        """
        command_str = ' '.join(command) # Para logs
        try:
            logger.debug(f"Executando comando firewall: {command_str}")
            # check=True: levanta CalledProcessError se o código de saída não for 0.
            # capture_output=True: captura stdout/stderr.
            # text=True: decodifica stdout/stderr como texto.
            # timeout: evita que o processo fique preso indefinidamente.
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=15)
            # Mesmo com check=True, logar saídas pode ser útil para debug
            if result.stdout: logger.debug(f"Comando '{command_str}' stdout: {result.stdout.strip()}")
            # UFW costuma usar stderr para status, então logar como warning é razoável
            if result.stderr: logger.warning(f"Comando '{command_str}' stderr: {result.stderr.strip()}")
            logger.info(f"Comando firewall bem-sucedido: {command_str}")
            return True
        except FileNotFoundError:
             # Erro comum se iptables/ufw não estiver instalado ou no PATH
             logger.error(f"Erro: Comando '{command[0]}' não encontrado. Verifique instalação e PATH.")
             return False
        except subprocess.CalledProcessError as e:
            # Erro quando o comando retorna um código de saída diferente de 0
            logger.error(f"Erro ao executar comando firewall: {command_str}")
            logger.error(f"Código de Retorno: {e.returncode}")
            # Stderr geralmente contém a mensagem de erro do comando
            if e.stderr: logger.error(f"Stderr: {e.stderr.strip()}")
            if e.stdout: logger.error(f"Stdout: {e.stdout.strip()}")
            return False
        except subprocess.TimeoutExpired:
             logger.error(f"Timeout (15s) ao executar comando firewall: {command_str}")
             return False
        except PermissionError:
             # Erro crítico, o worker não pode funcionar sem permissão
             logger.critical(f"Erro de permissão ao executar: {command_str}. Execute como root ou com privilégios necessários (e.g., CAP_NET_ADMIN).")
             # Considerar parar o worker se não tiver permissão?
             # self.running = False
             return False
        except Exception as e:
            # Captura outros erros inesperados
            logger.error(f"Erro inesperado ao executar comando {command_str}: {e}", exc_info=True)
            return False

    def _apply_block(self, ip_address: str) -> bool:
        """
        Aplica a regra de bloqueio para o IP fornecido usando o firewall configurado.
        Tenta ser idempotente (evitar adicionar regras duplicadas).

        Args:
            ip_address (str): O IP a ser bloqueado.

        Returns:
            bool: True se o bloqueio foi aplicado com sucesso ou já existia, False se falhou.
        """
        logger.info(f"Tentando aplicar bloqueio de firewall para IP: {ip_address} (Tipo: {self.firewall_type})")
        success = False
        if self.firewall_type == 'iptables':
            # Abordagem IPTables: Inserir (-I) na primeira posição da chain INPUT.
            # Isso garante que a regra DROP seja avaliada antes de outras regras ACCEPT.
            # Presume que a chain INPUT é o local apropriado.
            # O ideal seria ter uma chain dedicada para o IDS.

            # Comando para inserir a regra DROP na primeira posição
            # Usar -w (wait) pode ajudar a evitar conflitos se outras ferramentas mexerem no iptables
            insert_command = ["iptables", "-w", "5", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP", "-m", "comment", "--comment", "IDS_BLOCK"]
            # Comando para verificar se a regra *exata* já existe (útil para idempotência)
            check_command = ["iptables", "-w", "5", "-C", "INPUT", "-s", ip_address, "-j", "DROP", "-m", "comment", "--comment", "IDS_BLOCK"]

            # 1. Verifica se a regra já existe
            # A opção -C retorna 0 se existe, 1 se não existe. run() com check=True levanta erro se for 1.
            rule_exists = False
            try:
                 # Executa check sem check=True para não levantar erro se não existir
                 check_result = subprocess.run(check_command, capture_output=True, text=True, timeout=10)
                 if check_result.returncode == 0:
                      rule_exists = True
                      logger.debug(f"[IPTABLES] Regra de bloqueio para {ip_address} já existe.")
                 # Ignora outros códigos de retorno (significa que não existe)
            except Exception as e:
                 logger.warning(f"[IPTABLES] Erro ao verificar regra existente para {ip_address} (continuando): {e}")

            # 2. Se não existe, tenta inserir
            if not rule_exists:
                if self._run_command(insert_command):
                    logger.info(f"[IPTABLES] Bloqueio APLICADO com sucesso para IP: {ip_address}")
                    success = True
                else:
                    logger.error(f"[IPTABLES] FALHA ao aplicar bloqueio para IP: {ip_address}")
                    success = False
            else:
                 success = True # Considera sucesso se a regra já existia

        elif self.firewall_type == 'ufw':
            # Abordagem UFW: Mais simples, geralmente gerencia duplicatas.
            # 'deny from <ip>' bloqueia todas as conexões de entrada do IP.
            command = ["ufw", "deny", "from", ip_address, "comment", "IDS_BLOCK"]
            # UFW não tem um comando de checagem simples como iptables -C.
            # Apenas executa o comando 'deny'. Se já existir, geralmente não dá erro (ou dá um aviso).
            if self._run_command(command):
                 logger.info(f"[UFW] Comando 'deny from {ip_address}' executado.")
                 # UFW pode exigir 'reload' para aplicar algumas regras, mas 'deny' geralmente é imediato.
                 # self._run_command(["ufw", "reload"]) # Descomentar se necessário
                 success = True
            else:
                 # Pode falhar por sintaxe, permissão, ou outros motivos.
                 logger.error(f"[UFW] FALHA ao aplicar bloqueio para IP: {ip_address}")
                 success = False
        else:
             logger.error(f"Tipo de firewall desconhecido: {self.firewall_type}")
             success = False

        return success

    def _remove_block(self, ip_address: str) -> bool:
        """
        Remove a regra de bloqueio para o IP fornecido usando o firewall configurado.

        Args:
            ip_address (str): O IP a ser desbloqueado.

        Returns:
            bool: True se o bloqueio foi removido com sucesso, False se falhou ou não foi encontrado.
        """
        logger.info(f"Tentando remover bloqueio de firewall para IP: {ip_address} (Tipo: {self.firewall_type})")
        success = False
        if self.firewall_type == 'iptables':
            # Comando para deletar a regra específica que adicionamos (com comentário)
            # Usar -D (delete)
            # É importante que a regra para deletar seja idêntica à regra adicionada.
            delete_command = ["iptables", "-w", "5", "-D", "INPUT", "-s", ip_address, "-j", "DROP", "-m", "comment", "--comment", "IDS_BLOCK"]

            # Tenta remover. Se _run_command retornar True, a regra existia e foi removida.
            # Se retornar False, pode ser porque a regra não existia ou houve outro erro.
            if self._run_command(delete_command):
                 logger.info(f"[IPTABLES] Bloqueio REMOVIDO com sucesso para IP: {ip_address}")
                 success = True
            else:
                 # O erro já foi logado por _run_command. Logar um aviso aqui.
                 logger.warning(f"[IPTABLES] Falha ao remover bloqueio para {ip_address} (pode não existir mais ou erro).")
                 success = False # Indica que a remoção falhou ou não era necessária

        elif self.firewall_type == 'ufw':
            # UFW: Usar 'ufw delete' com a regra exata.
            # IMPORTANTE: Se a regra foi adicionada sem comentário, remova o 'comment' daqui.
            command = ["ufw", "delete", "deny", "from", ip_address, "comment", "IDS_BLOCK"]
            if self._run_command(command):
                  logger.info(f"[UFW] Bloqueio REMOVIDO com sucesso para IP: {ip_address}")
                  success = True
            else:
                  logger.warning(f"[UFW] Falha ao remover bloqueio para {ip_address} (pode não existir mais ou erro).")
                  success = False
        else:
             logger.error(f"Tipo de firewall desconhecido: {self.firewall_type}")
             success = False

        return success

    # --- Lógica de Sincronização ---
    def synchronize_blocks(self):
        """
        Compara a lista de bloqueio do Redis com o estado interno rastreado
        pelo worker (IPs bloqueados no firewall) e aplica/remove as diferenças.
        """
        if not self.redis_client:
             logger.error("Cliente Redis não disponível. Sincronização abortada.")
             return

        logger.debug("Iniciando ciclo de sincronização de bloqueios...")
        try:
            # 1. Obtem o estado DESEJADO (do Redis)
            # Usar um valor padrão (set vazio) se a conexão falhar ou a chave não existir
            redis_blocks_or_none = self.redis_client.get_blocked_ips()
            if redis_blocks_or_none is None:
                 # Erro ao comunicar com Redis, não fazer nada para evitar desbloqueios indevidos
                 logger.error("Não foi possível obter lista de bloqueio do Redis. Nenhuma ação de firewall será tomada.")
                 return
            # Se a chave não existe no Redis, smembers retorna set vazio, o que é correto.
            desired_blocks: Set[str] = redis_blocks_or_none
            logger.debug(f"Estado desejado (Redis - '{self.block_list_key}'): {len(desired_blocks)} IPs {list(desired_blocks)[:10]}...") # Log limitado

            # 2. Obtem o estado ATUAL (rastreado pelo worker)
            current_blocks_in_fw = self.currently_blocked_in_firewall
            logger.debug(f"Estado atual (Firewall - rastreado): {len(current_blocks_in_fw)} IPs {list(current_blocks_in_fw)[:10]}...")

            # 3. IPs a ADICIONAR ao firewall (no Redis, mas não no FW rastreado)
            ips_to_add = desired_blocks - current_blocks_in_fw
            if ips_to_add:
                logger.info(f"IPs para ADICIONAR ao firewall: {ips_to_add}")
                for ip in ips_to_add:
                    if self._apply_block(ip):
                        # Se o bloqueio foi aplicado com sucesso, atualiza estado interno
                        self.currently_blocked_in_firewall.add(ip)
                        # Opcional: Logar ação no banco de dados
                        # self._log_firewall_action('block_applied', ip)
                    else:
                        # Se falhar, *não* adiciona ao estado interno, tentará novamente
                        logger.error(f"Falha ao aplicar bloqueio para {ip}, será tentado na próxima sincronização.")

            # 4. IPs a REMOVER do firewall (não está mais no Redis, mas está no FW rastreado)
            ips_to_remove = current_blocks_in_fw - desired_blocks
            if ips_to_remove:
                logger.info(f"IPs para REMOVER do firewall: {ips_to_remove}")
                for ip in ips_to_remove:
                    if self._remove_block(ip):
                        # Se removido com sucesso, atualiza estado interno
                        self.currently_blocked_in_firewall.discard(ip)
                        # Opcional: Logar ação no banco de dados
                        # self._log_firewall_action('block_removed', ip)
                    else:
                        # Falha ao remover. Pode ser que já foi removido manualmente.
                        # Por segurança, remove do estado interno para não tentar remover de novo.
                        logger.warning(f"Falha ao remover bloqueio para {ip}. Removendo do rastreamento interno.")
                        self.currently_blocked_in_firewall.discard(ip)

            logger.debug("Ciclo de sincronização de bloqueios concluído.")

        except redis.exceptions.RedisError as e:
            logger.error(f"Erro de comunicação com Redis durante sincronização: {e}. Nenhuma ação de firewall tomada.")
            # Importante não fazer nada no firewall se não puder ler o estado desejado
        except Exception as e:
             logger.error(f"Erro inesperado durante sincronização de bloqueios: {e}", exc_info=True)

    # def _log_firewall_action(self, action: str, ip_address: str): # Opcional
    #      """Registra a ação de firewall no banco de dados."""
    #      # Necessitaria de um DatabaseManager (db.py) adaptado
    #      try:
    #          # db_manager.insert_firewall_log(timestamp=time.time(), action=action, ip_address=ip_address, worker_id="...")
    #          logger.debug(f"Ação de firewall '{action}' para IP {ip_address} registrada no DB.")
    #      except Exception as e:
    #          logger.error(f"Falha ao registrar ação '{action}' para {ip_address} no DB: {e}")

    # --- Controle do Serviço ---
    def run(self):
        """Loop principal do worker: verifica Redis e sincroniza o firewall periodicamente."""
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)

        if not self.running:
             logger.critical("BlockerWorker não pode iniciar devido a erro na inicialização.")
             return

        logger.info("BlockerWorker iniciado. Monitorando Redis e gerenciando firewall...")
        while self.running:
            start_time = time.monotonic()
            try:
                # Executa a lógica principal de sincronização
                self.synchronize_blocks()

            except Exception as e:
                 # Captura erros inesperados na lógica principal para não parar o worker
                 logger.error(f"Erro inesperado no loop principal do BlockerWorker: {e}", exc_info=True)
                 # Pausa um pouco mais longa em caso de erro para evitar spam
                 time.sleep(self.check_interval * 2)

            # Calcula tempo para dormir até o próximo ciclo
            elapsed_time = time.monotonic() - start_time
            sleep_time = max(0, self.check_interval - elapsed_time)
            logger.debug(f"Ciclo levou {elapsed_time:.2f}s. Dormindo por {sleep_time:.2f}s.")

            # Dorme de forma interruptível (verifica self.running a cada segundo)
            for _ in range(int(sleep_time)):
                 if not self.running: break
                 time.sleep(1)
            if self.running: # Dorme o restante fracionário
                 time.sleep(sleep_time % 1.0)

        logger.info("BlockerWorker encerrando...")
        self._cleanup()

    def stop(self, signum=None, frame=None):
        """Sinaliza para o worker parar na próxima iteração do loop."""
        if not self.running: return
        signal_name = f"Sinal {signal.Signals(signum).name}" if signum else "Chamada programática"
        logger.warning(f"{signal_name} recebido. Solicitando parada do BlockerWorker...")
        self.running = False # O loop principal verificará esta flag

    def _cleanup(self):
        """Limpeza ao encerrar o worker."""
        logger.info("Executando limpeza dos recursos do BlockerWorker...")

        # --- Decisão Importante: Remover regras ao parar? ---
        # Por padrão, NÃO removemos as regras ao parar o worker.
        # Isso evita que um reinício rápido do worker ou uma parada acidental
        # desbloqueie IPs que deveriam continuar bloqueados.
        # A sincronização na próxima inicialização cuidará do estado correto.
        # Se *realmente* quiser limpar as regras GGERENCIADAS POR ESTE WORKER ao parar:
        # ----------------------------------------------------
        # logger.warning("Removendo regras de firewall gerenciadas por este worker...")
        # for ip in list(self.currently_blocked_in_firewall): # Itera sobre cópia
        #     if self._remove_block(ip):
        #          self.currently_blocked_in_firewall.discard(ip)
        # logger.info(f"Tentativa de remoção de {len(self.currently_blocked_in_firewall)} regras restantes concluída.")
        # ----------------------------------------------------

        # Fecha conexão Redis
        if self.redis_client:
            self.redis_client.close()

        logger.info("BlockerWorker finalizado.")


# --- Ponto de Entrada Principal ---
if __name__ == "__main__":
    # Verificar permissões é crucial para este worker
    effective_uid = os.geteuid() if hasattr(os, 'geteuid') else -1
    if effective_uid != 0:
         # Tenta verificar capabilities se não for root (mais complexo, depende de libs externas)
         # try:
         #      import sys
         #      # Exemplo rudimentar, pode precisar de lib 'python-prctl' ou similar
         #      # Esta verificação é apenas um indicativo, pode não ser 100% precisa
         #      if 'cap_net_admin' not in str(subprocess.check_output(['capsh', '--print'], text=True)):
         #           raise PermissionError("CAP_NET_ADMIN não encontrada.")
         #      logger.warning("Rodando como não-root, mas CAP_NET_ADMIN parece presente (verificação básica).")
         # except (ImportError, FileNotFoundError, PermissionError, Exception) as cap_err:
              logger.critical(f"Este script precisa ser executado como root (UID 0) ou com privilégios equivalentes (ex: CAP_NET_ADMIN) para modificar o firewall. UID atual: {effective_uid}")
              exit(1)
    else:
         logger.info(f"Executando como root (UID {effective_uid}).")


    worker = None
    exit_code = 0
    try:
        logger.info("Iniciando aplicação BlockerWorker...")
        worker = BlockerWorker()
        worker.run() # Bloqueia até self.running ser False
        logger.info("BlockerWorker run() concluído.")
    except RuntimeError as e:
        logger.critical(f"Encerrando BlockerWorker devido a erro fatal na inicialização: {e}")
        exit_code = 1
    except KeyboardInterrupt:
        logger.warning("Interrupção pelo teclado (Ctrl+C) detectada.")
        # O signal handler deve ter sido chamado. O run() terminará e chamará cleanup.
        exit_code = 0
    except Exception as e:
        logger.critical(f"Erro não tratado no nível principal do BlockerWorker: {e}", exc_info=True)
        exit_code = 1
    finally:
        logger.info("Aplicação BlockerWorker encerrando...")
        # Cleanup é chamado no finally do run()
        logger.info(f"Aplicação BlockerWorker finalizada com código de saída: {exit_code}")
        time.sleep(0.5) # Pausa para logs
        exit(exit_code)