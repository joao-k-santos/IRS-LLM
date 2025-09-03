# utils.py (ou no mesmo arquivo, se preferir)
import sqlite3
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
import os
import requests
import json
import re

DB_FILE = "/app/databases/ataques.db"
OLLAMA_URL = "http://localhost:11434"

# Configuração do JWT
SECRET_KEY = "seu_segredo_super_secreto"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1448 # 24 horas

#oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
oauth2_scheme = HTTPBearer()

# Configuração para criptografar senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

CAMPOS_ATAQUE = [
    "flow_id", "src_ip", "dest_ip", "src_port", "dest_port", "proto",
    "hour", "minute", "seconds", "severity",
    "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
    "class", "processado"
]


def parse_ataques(dados_brutos):
    """Converte listas de ataques em dicionários com nomes de campos"""
    return [dict(zip(CAMPOS_ATAQUE, ataque)) for ataque in dados_brutos]

# Executar query no banco
def executar_query(query, params=(), fetchall=False, fetchone=False, db_file=DB_FILE):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    cursor.execute(query, params)
    conn.commit()

    if fetchall:
        resultado = cursor.fetchall()
    elif fetchone:
        resultado = cursor.fetchone()
    else:
        resultado = None

    conn.close()
    return resultado

# Criar token JWT
def criar_token_jwt(dados: dict, expira_em: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    dados_copia = dados.copy()
    expira = datetime.now(timezone.utc) + timedelta(minutes=expira_em)
    dados_copia.update({"exp": expira})
    return jwt.encode(dados_copia, SECRET_KEY, algorithm=ALGORITHM)

# Verificar token JWT
#def verificar_token_jwt(token: str = Security(oauth2_scheme)):
def verificar_token_jwt(credentials):
    if isinstance(credentials, str):
        token = credentials
    elif isinstance(credentials, HTTPAuthorizationCredentials):
        token = credentials.credentials
    else:
        raise ValueError("Formato de token inválido")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


def extrair_json_de_response(response_str: str):
    # Remove blocos markdown (```json ... ```)
    match = re.search(r'```json\s*(\{.*?\})\s*```', response_str, re.DOTALL)
    if match:
        json_str = match.group(1)
        return json.loads(json_str)
    else:
        raise ValueError("JSON não encontrado na resposta da LLM")
    
def extrair_json_de_resposta(response_dict):
    response_text = response_dict.get("response", "")

    # 1. Tenta extrair blocos de JSON dentro de markdown: ```json ... ``` ou ``` ... ```
    markdown_match = re.search(r"```(?:json)?\s*([\[\{].*?[\]\}])\s*```", response_text, re.DOTALL)
    if markdown_match:
        json_str = markdown_match.group(1)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            print("[Watcher] Erro ao decodificar JSON dentro do bloco markdown:", e)

    # 2. Tenta encontrar JSON completo fora de markdown, com balanceamento de delimitadores
    def extrair_json_balanceado(texto):
        delimitadores = [('(', ')'), ('[', ']'), ('{', '}')]
        aberturas = {a: b for a, b in delimitadores}

        for i, char in enumerate(texto):
            if char in aberturas:
                stack = [char]
                for j in range(i + 1, len(texto)):
                    if texto[j] in aberturas:
                        stack.append(texto[j])
                    elif texto[j] == aberturas[stack[-1]]:
                        stack.pop()
                        if not stack:
                            trecho = texto[i:j + 1]
                            try:
                                return json.loads(trecho)
                            except json.JSONDecodeError:
                                break  # Tenta o próximo trecho
                # Se não encontrar fechamento, continua procurando
        return None

    resultado_fallback = extrair_json_balanceado(response_text)
    if resultado_fallback:
        return resultado_fallback
    
def carregar_prompt_template(caminho: str, dados_ataques: str) -> str:
    with open(caminho, "r", encoding="utf-8") as f:
        template = f.read()
    return template.replace("{dados_ataques}", dados_ataques)

def truncar_ataques_por_tokens(ataques, limite_tokens=4000):
    ataques_final = []
    tokens_total = 0
    for ataque in ataques:
        texto = json.dumps(ataque)
        tokens = len(texto.split())  # estimativa simples
        if tokens_total + tokens > limite_tokens:
            break
        ataques_final.append(ataque)
        tokens_total += tokens
    return ataques_final

def dividir_em_lotes(lista, tamanho_lote):
    """Divide uma lista em sublistas de tamanho especificado."""
    return [lista[i:i + tamanho_lote] for i in range(0, len(lista), tamanho_lote)]

def validar_saida_llm(contexto):
    """
    Garante que o contexto gerado contenha campos válidos.
    - flow_id: str
    - tipo: str
    - descricao: str
    - detalhes: str (não pode ser dict ou list)
    """
    campos_obrigatorios = ["flow_id", "tipo", "descricao", "detalhes"]

    if not all(campo in contexto for campo in campos_obrigatorios):
        raise ValueError(f"Contexto incompleto: campos ausentes em {contexto}")

    if not isinstance(contexto["detalhes"], str):
        raise ValueError(f"O campo 'detalhes' deve ser uma string, mas veio: {type(contexto['detalhes'])}")


import json

def validar_ataques_para_llm(response: str):
    """Faz o parsing do response da LLM e valida se cada 'detalhes' é uma string não nula."""
    try:
        dados = json.loads(response)
    except json.JSONDecodeError as e:
        raise ValueError(f"Resposta da LLM não é JSON válido: {e}")

    if isinstance(dados, dict):
        dados = [dados]

    for i, item in enumerate(dados):
        detalhes = item.get("detalhes", None)
        if detalhes is None:
            raise ValueError(f"[Item {i}] O campo 'detalhes' está ausente ou é None")
        if not isinstance(detalhes, str):
            raise ValueError(f"[Item {i}] O campo 'detalhes' deve ser uma string, mas é {type(detalhes).__name__}")
        if detalhes.strip() == "":
            raise ValueError(f"[Item {i}] O campo 'detalhes' está vazio")

    return dados

