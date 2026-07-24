# 📖 Manual de Uso - Sistema de Prevenção de Intrusão Baseado em Host (SPIH)

Este documento descreve como subir o ambiente em containers Docker, como funcionam o **Suricata** e os **coletores de logs (PySpark)** no *Host Final*, como orquestrar as regras de segurança e como **simular os ataques** utilizando a botnet via **Command & Control (CNC)**.

---

## 🏗️ 1. Visão Geral da Arquitetura

O ambiente é composto por uma rede privada Docker (`seguranca_net` na sub-rede `172.28.0.0/16`) contendo os seguintes componentes:

| Container | Endereço IP | Função |
| :--- | :--- | :--- |
| **`host_final_1`** | `172.28.0.10` | Servidor-alvo (vítima) que roda o **Suricata IDS**, gera logs em `eve.json` e faz ingestão no PostgreSQL via **PySpark**. |
| **`cnc`** | `172.28.0.100` | Servidor de Comando e Controle (C&C) que executa playbooks Ansible para orquestrar os bots de ataque. |
| **`bot_1` a `bot_5`** | `172.28.0.20` - `172.28.0.60` | Nós da botnet que disparam os ataques (Nmap, Hydra) contra o `host_final_1`. |
| **`orquestrador`** | `172.28.0.5` | Nó centralizador de segurança que baixa regras da API (LLM) e as envia aos hosts finais. |

---

## 🚀 2. Como Subir o Ambiente Docker

### Pré-requisitos
- Docker & Docker Compose instalados.

### Passos para Inicialização

1. **Navegue até a raiz do projeto** (onde está o arquivo `docker-compose.yml`):
   ```bash
   cd /caminho/para/ansible-security
   ```

2. **Construa as imagens e suba os containers**:
   ```bash
   docker compose up -d --build
   ```

3. **Verifique se todos os containers estão em execução (`running`)**:
   ```bash
   docker compose ps
   ```

---

## 🛡️ 3. Suricata e Coletores de Logs (`host_final_1`)

Ao subir o container `host_final_1`, o script de inicialização (`entrypoint.sh`) é executado automaticamente, realizando o setup do sensor e do coletor:

### 3.1. Suricata IDS
- **Script de Inicialização**: `/opt/scripts/suricata_start.sh` (executado em background na subida do container).
- **Interface Monitorada**: `eth0`.
- **Logs de Saída**: Os logs de alerta e eventos são gravados em formato JSON em `/var/log/suricata/eve.json` (também mapeado localmente na pasta `./logs_suricata`).
- **Verificar logs do Suricata**:
  ```bash
  docker exec -it host_final_1 tail -f /var/log/suricata/eve.json
  ```

### 3.2. Coletor de Logs PySpark (Ingestão no DB)
- **Script PySpark**: `/opt/scripts/process_suricata_logs.py`.
- **Funcionamento**: O script lê o arquivo `/var/log/suricata/eve.json`, normaliza os campos do esquema (IDs de fluxo, IP de origem/destino, severidade, estatísticas de pacotes/bytes, etc.) e envia os dados via JDBC para o banco PostgreSQL (`nids_db`).
- **Agendamento Automático**: O script `/opt/spark_log_ingest/setup_ingest_timer.sh` configura um timer via **Systemd** (`log_ingest.timer`) ou um job no **Cron** executado a **cada 1 minuto**.
- **Execução manual (caso deseje testar a ingestão explicitamente)**:
  ```bash
  docker exec -it host_final_1 python3 /opt/scripts/process_suricata_logs.py
  ```

---

## ⚔️ 4. Como Simular os Ataques

Os ataques são simulados a partir do nó **CNC** (`cnc`), que utiliza o **Ansible** para comandar os nós da botnet (`bot_1` a `bot_5`) contra o `host_final_1` (`172.28.0.10`).

### Passo 1: Acessar o container CNC
```bash
docker exec -it cnc bash
```

### Passo 2: Navegar para o diretório dos bots
```bash
cd /home/bot
```

### Passo 3: Executar os Ataques

#### 🎯 4.1. Ataque de Varredura de Portas (Port Scan via Nmap)
Executa varreduras `Nmap` de forma distribuída a partir dos bots contra o IP alvo (`172.28.0.10`).

```bash
ansible-playbook -i inventory/bots.yml playbooks/ataque_portscan.yml
```

#### 🔑 4.2. Ataque de Força Bruta em SSH (Brute-Force via Hydra)
Envia dicionários de senha (`wordlist`) e tenta autenticação SSH simultânea a partir de cada bot contra o IP alvo.

```bash
ansible-playbook -i inventory/bots.yml playbooks/ataque_bruteforce.yml
```

---

## 📊 5. Validando a Detecção e Ingestão de Ataques

Depois de disparar um ataque no CNC:

1. **Verificar os Alertas do Suricata (`host_final_1`)**:
   ```bash
   docker exec -it host_final_1 grep "alert" /var/log/suricata/eve.json
   ```
2. **Verificar o Log da Ingestão de Dados (PySpark -> PostgreSQL)**:
   ```bash
   docker exec -it host_final_1 cat /var/log/suricata_ingest.log
   ```

---

## ⚙️ 6. Orquestrador de Segurança

O container `orquestrador` gerencia o download de novas regras de segurança geradas via API e a aplicação das mesmas nos alvos:

- **Baixar novas regras**: Executa `/usr/local/bin/baixar_regras.sh` a cada 5 minutos.
- **Enviar regras para o Host Final**: Executa `/usr/local/bin/enviar_regras.sh` para aplicar as novas regras e atualizar o firewall (`nftables`).
- **Acessar o Orquestrador**:
  ```bash
  docker exec -it orquestrador bash
  ```

---

## 📝 Resumo Rápido de Comandos (Cheat Sheet)

```bash
# 1. Subir o ambiente
docker compose up -d --build

# 2. Simular Portscan (no container CNC)
docker exec -it cnc ansible-playbook -i /home/bot/inventory/bots.yml /home/bot/playbooks/ataque_portscan.yml

# 3. Simular Brute-Force SSH (no container CNC)
docker exec -it cnc ansible-playbook -i /home/bot/inventory/bots.yml /home/bot/playbooks/ataque_bruteforce.yml

# 4. Ver alertas gerados em tempo real no Host Final
docker exec -it host_final_1 tail -f /var/log/suricata/eve.json

# 5. Parar o ambiente
docker compose down
```
