import utils
import json
from passlib.context import CryptContext
import aiohttp
import asyncio

def gerar_regras_prompt(ataques, IPS_CONFIAVEIS):
    """Gera um prompt dinâmico baseado nos ataques detectados, priorizando os mais críticos."""

    lista_de_ataques = "\n".join(
        f"- Tipo: {tipo}, Descrição: {descricao}, Detalhes: {detalhes}" for tipo, descricao, detalhes in ataques
    )

    lista_ips_confiaveis = "\n".join(f"- {ip}" for ip in IPS_CONFIAVEIS)

    prompt = (
        "Você é um sistema especializado em defesa de redes cibernéticas.\n\n"
        f"Com base nos seguintes ataques detectados:\n{lista_de_ataques}\n\n"
        f"### IPs confiáveis (NUNCA devem ser bloqueados ou prejudicados):\n{lista_ips_confiaveis}\n\n"
        "Sua tarefa é gerar regras de mitigação para esses ataques.\n\n"
        "### Orientações para a geração de regras:\n"
        "- Priorize ameaças mais graves primeiro. Considere como graves:\n"
        "  - Ataques de negação de serviço (DoS, DDoS)\n"
        "  - Injeções de SQL ou comandos (SQLi, Command Injection)\n"
        "  - Execução remota de código (RCE)\n"
        "  - Escalonamento de privilégios\n"
        "- Toda regra de bloqueio com `iptables` deve ser precedida por uma regra de log correspondente (`-j LOG`).\n"
        "  Use `--log-prefix` para indicar o motivo do bloqueio (ex: 'ATAQUE BLOQUEADO: ').\n"
        "- Se não souber como mitigar um ataque, ignore-o (não crie regras inválidas).\n"
        "- Nunca bloqueie IPs da lista confiável.\n"
        "- Nunca crie regras que vão travar o sistema ou causar perda de conectividade.\n"
        "- Se possível, use estratégias de mitigação eficientes para ataques como portscan:\n"
        "  - Prefira usar o módulo `recent` do iptables para detectar múltiplas tentativas em curto tempo e bloquear o IP automaticamente.\n"
        "  - Evite criar uma regra para cada porta individualmente.\n"
        "  - Considere também o uso de `connlimit` (para limitar conexões simultâneas por IP) ou `hashlimit` (para limitar a taxa de pacotes).\n"
        "  - Um bom padrão para portscan é: log e bloqueie IPs que tentarem mais de 10 conexões TCP SYN em menos de 60 segundos.\n"
        "- Se nenhuma regra puder ser gerada, simplesmente retorne [].\n\n"
        "### Formato obrigatório da resposta:\n"
        "- Um JSON puro (sem comentários ou explicações externas).\n"
        "- Uma lista de objetos, cada um com três campos obrigatórios:\n"
        "  - \"tipo\": firewall, ids ou ips\n"
        "  - \"descricao\": breve descrição da ação\n"
        "  - \"comando\": comando CLI correspondente (pode conter múltiplos comandos separados por ponto e vírgula)\n\n"
        "### Exemplo de resposta correta:\n"
        "[\n"
        "  {\"tipo\": \"firewall\", \"descricao\": \"Bloqueia tentativas de força bruta SSH\", \"comando\": \"iptables -A INPUT -p tcp --dport 22 -m recent --name sshbrute --set; iptables -A INPUT -p tcp --dport 22 -m recent --name sshbrute --update --seconds 60 --hitcount 5 -j LOG --log-prefix \\\"BRUTEFORCE SSH DETECTADO: \\\"; iptables -A INPUT -p tcp --dport 22 -m recent --name sshbrute --update --seconds 60 --hitcount 5 -j DROP\"}\n"
        "  {\"tipo\": \"firewall\", \"descricao\": \"Detecta e bloqueia portscan com iptables\", \"comando\": \"iptables -A INPUT -p tcp --syn -m recent --name portscan --set; iptables -A INPUT -p tcp --syn -m recent --name portscan --update --seconds 60 --hitcount 10 -j LOG --log-prefix \\\"PORTSCAN DETECTADO: \\\"; iptables -A INPUT -p tcp --syn -m recent --name portscan --update --seconds 60 --hitcount 10 -j DROP\"}\n"
        "  {\"tipo\": \"firewall\", \"descricao\": \"Limita taxa de conexões para mitigar DoS\", \"comando\": \"iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/second --limit-burst 100 -j ACCEPT; iptables -A INPUT -p tcp --dport 80 -j LOG --log-prefix \\\"DOS BLOQUEADO: \\\"; iptables -A INPUT -p tcp --dport 80 -j DROP\"}\n"
        "  {\"tipo\": \"ids\", \"descricao\": \"Aplica fail2ban para proteger contra tentativas de login repetidas\", \"comando\": \"fail2ban-client reload sshd\"}\n"        
        "  {\"tipo\": \"firewall\", \"descricao\": \"Loga e bloqueia IP malicioso na porta 80\", \"comando\": \"iptables -A INPUT -p tcp --dport 80 -s 10.0.0.5 -j LOG --log-prefix \\\"ATAQUE BLOQUEADO: \\\"; iptables -A INPUT -p tcp --dport 80 -s 10.0.0.5 -j DROP\"}\n"
        "  {\"tipo\": \"ips\", \"descricao\": \"Finaliza processo suspeito de mineração\", \"comando\": \"pkill -f miner_script\"}\n"
        "  {\"tipo\": \"firewall\", \"descricao\": \"Loga e bloqueia Lista de IPs maliciosos na porta 22\", \"comando\": \"iptables -A INPUT -p tcp --dport 22 -s 172.28.0.50,172.28.0.60,172.28.0.20 -j LOG --log-prefix \\\"ATAQUE BLOQUEADO: \\\"; iptables -A INPUT -p tcp --dport 22 -s 172.28.0.50,172.28.0.60,172.28.0.20 -j DROP"
        "  {\"tipo\": \"firewall\", \"descricao\": \"Detecta e bloqueia portscan com iptables\", \"comando\": \"iptables -A INPUT -p tcp --syn -m recent --name portscan --set; iptables -A INPUT -p tcp --syn -m recent --name portscan --update --seconds 60 --hitcount 10 -j LOG --log-prefix \\\"PORTSCAN DETECTADO: \\\"; iptables -A INPUT -p tcp --syn -m recent --name portscan --update --seconds 60 --hitcount 10 -j DROP\"},\n"
        "  {\"tipo\": \"ids\", \"descricao\": \"Aplica fail2ban para proteger contra tentativas de login repetidas\", \"comando\": \"fail2ban-client reload sshd\"}\n"
        "  {\"tipo\": \"firewall\", \"descricao\": \"Loga e bloqueia o IP 172.28.0.50 devido a ataques DoS em múltiplas portas.\", \"comando\": \"iptables -A INPUT -p tcp -m multiport --dports 49157,49167,49175,49999,50001 -s 172.28.0.50 -j LOG --log-prefix \\\"ATAQUE BLOQUEADO: DoS - 172.28.0.50\\\"; iptables -A INPUT -p tcp -m multiport --dports 49157,49167,49175,49999,50001 -s 172.28.0.50 -j DROP\"}\n"
        "]\n\n"
        "Repita: retorne apenas o JSON solicitado, sem explicações fora dele. E gere a menor quantidade de regras possível.\n"
    )

    return prompt


async def gerar_regras(model, token):
    """Gera regras de segurança com base nos ataques registrados."""

    if not utils.verificar_token_jwt(token):
        raise utils.HTTPException(status_code=401, detail="Token inválido")

    # Consulta ataques
    query = "SELECT tipo, descricao, detalhes FROM ataques ORDER BY id DESC"
    ataques = utils.executar_query(query, fetchall=True)
    query = "SELECT ip_protegido FROM protegidos"
    ips_confiaveis = utils.executar_query(query, fetchall=True)

    if not ataques:
        raise utils.HTTPException(status_code=404, detail="Nenhum ataque registrado")

    # Gera o prompt dinâmico
    prompt = gerar_regras_prompt(ataques, ips_confiaveis)

    # Prepara requisição
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }
    headers = {
        "Authorization": f"Bearer {token}"
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                f"{utils.OLLAMA_URL}/api/generate",
                json=payload,
                headers=headers,
                timeout=3600
            ) as resp:
                if resp.status != 200:
                    texto = await resp.text()
                    raise utils.HTTPException(status_code=resp.status, detail=f"Erro da LLM: {texto}")

                texto = await resp.text()
                resultado = json.loads(texto)

                # Se a LLM respondeu uma lista vazia ou não enviou nada útil
                if not resultado:
                    return {"mensagem": "Nenhuma regra foi gerada pelos dados enviados.", "regras": []}

                return resultado

        except asyncio.TimeoutError:
            raise utils.HTTPException(status_code=504, detail="Timeout da LLM")
        except json.JSONDecodeError:
            raise utils.HTTPException(status_code=500, detail="Erro ao processar resposta da LLM")


def registrar_regra(tipo: str, descricao: str, comando: str, ataques, token: str = None):
    """Adiciona uma regra criada ao banco de dados"""
    if not utils.verificar_token_jwt(token):
        raise utils.HTTPException(status_code=401, detail="Token inválido")
    ataque_id_str = json.dumps(ataques)
    query = "INSERT INTO regras (tipo, descricao, comando, ataque_id) VALUES (?, ?, ?, ?)"
    utils.executar_query(query, (tipo, descricao, comando, ataque_id_str))
    return {"mensagem": "Regra registrada com sucesso!"}
