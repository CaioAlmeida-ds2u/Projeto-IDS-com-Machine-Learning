# Projeto-IDS-com-Machine-Learning
Projeto de Estudo
Documentação do Projeto IDS com Machine Learning

1. Introdução

Este documento apresenta o desenvolvimento de um Sistema de Detecção de Intrusão (IDS) baseado em machine learning, criado como parte de um projeto acadêmico. O objetivo é monitorar o tráfego de rede, identificar atividades suspeitas e gerar alertas. O sistema conta com uma interface web desenvolvida em PHP para visualização de logs, controle do IDS (iniciar/parar), gerenciamento de bloqueios e acompanhamento do treinamento do modelo de machine learning.

2. Objetivos

Detecção de anomalias: Identificar padrões incomuns no tráfego de rede que possam indicar tentativas de intrusão.

Uso de machine learning: Aplicar algoritmos de aprendizado de máquina para aprimorar a precisão da detecção.

Interface web intuitiva: Disponibilizar uma plataforma para monitoramento em tempo real dos eventos de rede.

Gerenciamento de bloqueios: Permitir a configuração dinâmica de bloqueios de protocolos (TCP, UDP, ICMP).

Treinamento do modelo: Prover opção para iniciar e monitorar o treinamento do modelo diretamente pela interface.

Projeto educacional: Focar no aprendizado e na compreensão dos princípios de um IDS baseado em machine learning.

3. Arquitetura do Sistema

O IDS é composto por três principais módulos:

Núcleo do IDS (Python): Responsável pela captura e análise de pacotes de rede, detecção de ameaças e armazenamento de logs.

Interface Web (PHP): Fornece uma interface para visualizar logs, controlar o IDS e configurar bloqueios.

Banco de Dados (SQLite): Armazena logs de eventos, status do treinamento e regras de bloqueio.

Fluxo de funcionamento do IDS

Captura de pacotes com Scapy e filtragem com BPF.

Extração de informações relevantes e armazenamento temporário em buffer.

Avaliação dos pacotes pelo modelo de machine learning.

Geração de alertas e aplicação de bloqueios, conforme configurações.

Registro das atividades no banco de dados.

4. Componentes

4.1. IDS (Python)

Principais tecnologias:

scapy: Captura e manipulação de pacotes.

sqlite3: Armazena logs e eventos.

threading: Implementa gravação assíncrona.

scikit-learn: Treina e aplica o modelo de detecção.

signal: Controle do funcionamento do IDS.

json: Leitura e escrita da configuração de bloqueios.

Funcionalidades:

Captura e filtragem de pacotes de rede.

Extração de features relevantes para análise.

Uso de machine learning para identificar ameaças.

Geração de alertas em tempo real.

Aplicar bloqueios com base em regras configuradas.

Registra logs no banco de dados SQLite.

4.2. Interface Web (PHP)

Principais tecnologias:

PHP + SQLite3: Gerenciamento dos dados capturados pelo IDS.

JavaScript (AJAX + Chart.js): Exibição dinâmica dos eventos e gráficos.

Funcionalidades:

Monitoramento de logs: Exibição em tempo real dos eventos capturados.

Controle do IDS: Permite iniciar e parar o IDS remotamente.

Gerenciamento de bloqueios: Interface para configurar regras de bloqueio/desbloqueio de protocolos.

Treinamento do modelo: Iniciar e acompanhar o treinamento do modelo diretamente pela interface.

Segurança: Controle de acesso e validação de entradas para evitar ataques de injeção de código.

4.3. Banco de Dados (SQLite)

Tabelas principais:

logs: Armazena pacotes analisados e eventos de alerta.

training_status: Registra o progresso do treinamento do modelo de machine learning.

blocked_ips (opcional): Lista de endereços IP bloqueados.

5. Fluxo de Trabalho

Configuração Inicial:

Instalação das dependências.

Criação do banco de dados e tabelas.

Ajuste do arquivo config.json.

Treinamento do Modelo:

O modelo de machine learning é treinado com dados históricos.

O modelo treinado é salvo e preparado para uso.

Execução do IDS:

Captura pacotes e analisa com o modelo treinado.

Identifica e registra ameaças no banco de dados.

Aplica bloqueios, conforme configurações.

Interação via Interface Web:

Exibição de logs em tempo real.

Controle do IDS (iniciar/parar).

Configuração de bloqueios.

Iniciação do treinamento do modelo.

6. Considerações Finais

O sistema foi projetado para proporcionar um ambiente de aprendizado sobre IDS e machine learning, com uma implementação funcional que pode ser expandida conforme necessário. Algumas melhorias futuras incluem:

Melhor otimização do modelo de machine learning.

Suporte a diferentes bancos de dados.

Aprimoramento da interface web.

Implementação de autenticação para acesso seguro.
