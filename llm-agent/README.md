# Agente LLM para o Sistema de Prevenção de Intrusão Baseado em Host
Construido em Docker, Python (FastAPI) e Ollama

# Como construir:
No diretório onde foi feito o clone do repositório do github
```sh
cd ./SPIH/llm-agent
docker-compose build
docker-compose up -d
```

# Para interromper a execução
```sh
docker-compose down
```

# Informações de Rede
A API fica exposta na porta 8000 no localhost
http://localhost:8000

O servidor Ollama fica exposto, fora do Docker, na porta 11444 no localhost
http://localhost:11444

# Para usar o bash de cada Container
```sh
docker exec -it api_llm bash
docker exec -it ollama bash
```

Ou

```sh
docker exec -it api_llm sh
docker exec -it ollama sh
```

📌 Endpoints
1. Registrar Ataque

Adiciona um ataque detectado ao banco de dados.

    Endpoint

```http
POST /registrar_ataque
```
```json
Parâmetros (JSON)

{
  "tipo": "DoS",
  "descricao": "Ataque de negação de serviço",
  "detalhes": "Vários pacotes ICMP"
}
```
```http

```
```json

```
```json
Resposta

    {
      "mensagem": "Ataque registrado com sucesso!"
    }
```


2. Listar Ataques

Lista todos os ataques registrados no banco de dados.

    Endpoint

```http
GET /listar_ataques
```

```json
Resposta

    [
      {
        "id": 1,
        "tipo": "DoS",
        "descricao": "Ataque de negação de serviço",
        "detalhes": "Vários pacotes ICMP"
      },
      {
        "id": 2,
        "tipo": "Botnet",
        "descricao": "Ataque distribuído com múltiplos bots",
        "detalhes": "Uso de Mirai botnet"
      }
    ]
```


3. Baixar Modelo

Solicita ao Ollama o download de um modelo específico.

    Endpoint

```http
POST /download_model/
```

```json
Parâmetros (JSON)

{
  "model_name": "llama3.2:3b"
}

Resposta

    {
      "message": "Modelo llama3.2:3b baixado com sucesso"
    }
```


4. Gerar Regras de Segurança

Gera regras de segurança baseadas nos ataques registrados no banco de dados.

    Endpoint

GET /gerar_regras

Parâmetros (Query)
Nome	Tipo	Obrigatório	Descrição
model	string	Não	Nome do modelo a ser usado (padrão: llama3.2:3b)

Resposta

    {
      "firewall": [
        "iptables -A INPUT -s 192.168.0.0/24 -j DROP"
      ],
      "ids": [
        "alert tcp any any -> any 80 (msg:\"Suspicious HTTP request\"; sid:1000001;)"
      ],
      "ips": [
        "fail2ban action: ban IP 192.168.1.1"
      ]
    }

5. Listar Modelos Disponíveis

Lista todos os modelos disponíveis no servidor Ollama.

    Endpoint

GET /models

Resposta

    [
      {
        "name": "llama3.2:3b",
        "tags": ["llama", "3b"]
      },
      {
        "name": "gpt4:large",
        "tags": ["gpt", "large"]
      }
    ]

6. Gerar Resposta

Gera uma resposta do modelo especificado com base no prompt fornecido.

    Endpoint

POST /generate/

Parâmetros (JSON)

{
  "model": "llama3.2:3b",
  "prompt": "Como mitigar ataques DoS?"
}

Resposta

    {
      "regras": "Para mitigar ataques DoS, recomenda-se utilizar técnicas de rate-limiting e bloquear IPs suspeitos."
    }

🛑 Erros Comuns e Soluções
❌ Erro ao Registrar Ataque

    Descrição: A requisição falhou ao tentar registrar um ataque.

    Solução: Verifique se os parâmetros tipo, descricao e detalhes estão sendo enviados corretamente.

❌ Erro ao Baixar Modelo

    Descrição: Não foi possível baixar o modelo do Ollama.

    Solução: Certifique-se de que o servidor Ollama está rodando e que o nome do modelo está correto.

❌ Erro ao Gerar Regras

    Descrição: O processamento das regras falhou ao tentar gerar as regras com base nos ataques registrados.

    Solução: Verifique se há ataques registrados e se o servidor Ollama está operacional.
