import utils
import sqlite3
import requests
import json
from datetime import datetime, timedelta
from passlib.context import CryptContext
import os
import aiohttp
import asyncio


NIDS_URL = "http://172.16.9.105:5050" # API FastAPI NIDS API
LLM_URL = "http://localhost:8000"  # API FastAPI LLM API
OLLAMA_URL = "http://localhost:11434"


CREDENCIAIS = {
    "api_nids": {"username": "joao", "password": "UIOT"},
    "api_llm": {"username": "joao", "password": "admin"}
}

def obter_token(api_name, url):
    """Obtém e retorna um token JWT para uma API específica"""
    try:
        response = requests.post(f"{url}/token", data=CREDENCIAIS[api_name])
        response.raise_for_status()
        return response.json()["access_token"]
    except requests.RequestException as e:
        raise utils.HTTPException(status_code=500, detail=f"Erro ao obter token para {api_name}: {e}")
        

def buscar_classificados(api_name=CREDENCIAIS["api_nids"], url=NIDS_URL, token=None):
    """Busca dados da API correspondente usando o token e aplica parsing"""
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(f"{url}/dados/ataques/novos", headers=headers)
        response.raise_for_status()
        dados_brutos = response.json()["dados"]
        return utils.parse_ataques(dados_brutos)
    except requests.RequestException as e:
        raise utils.HTTPException(
            status_code=500,
            detail=f"Erro ao buscar dados de {api_name}: {e}"
        )


def atualizar_classificado(flow_id,  api_name=CREDENCIAIS["api_nids"], url=NIDS_URL, token=None):
    """Atualiza o status do classificado na API correspondente usando o token"""
    headers = {"Authorization": f"Bearer {token}"}
    data = {"flow_id": flow_id}
    
    try:
        response = requests.put(f"{url}/dados/ataques/processar/{flow_id}", json=data, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise utils.HTTPException(status_code=500, detail=f"Erro ao atualizar classificado de {api_name}: {e}")


async def gerar_contexto_para_lote(lote, model, token):
    if not utils.verificar_token_jwt(token):
        raise utils.HTTPException(status_code=401, detail="Token inválido")

    ataques = utils.truncar_ataques_por_tokens(lote)
    if not ataques:
        raise utils.HTTPException(status_code=404, detail="Lote vazio ou muito grande")

    dados_str = json.dumps(ataques, indent=2, ensure_ascii=False)
    prompt = utils.carregar_prompt_template("/app/prompt_template.txt", dados_str)

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                headers={"Authorization": f"Bearer {token}"},
                timeout=3600
            ) as resp:
                if resp.status != 200:
                    raise utils.HTTPException(status_code=resp.status, detail=f"Erro da LLM: {await resp.text()}")
                texto = await resp.text()
                return json.loads(texto)
        except asyncio.TimeoutError:
            raise utils.HTTPException(status_code=504, detail="Timeout da LLM")
        except json.JSONDecodeError as e:
            raise utils.HTTPException(status_code=500, detail=f"Erro ao processar resposta JSON: {str(e)}")
        except ValueError as e:
            raise utils.HTTPException(status_code=422, detail=f"Erro de validação do contexto: {str(e)}")



async def gerar_contexto(model, token):
    if not utils.verificar_token_jwt(token):
        raise utils.HTTPException(status_code=401, detail="Token inválido")

    token_nids = obter_token("api_nids", NIDS_URL)
    classificados = buscar_classificados(token=token_nids)

    if not classificados:
        raise utils.HTTPException(status_code=404, detail="Nenhum dado classificado encontrado")

    ataques = [dado for dado in classificados if dado['processado'] == 0]
    ataques = utils.truncar_ataques_por_tokens(ataques)

    if not ataques:
        raise utils.HTTPException(status_code=404, detail="Nenhum ataque disponível para gerar contexto")

    dados_str = json.dumps(ataques, indent=2, ensure_ascii=False)
    prompt = utils.carregar_prompt_template("/app/prompt_template.txt", dados_str)

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False, "keep_alive": "0"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=3600
            ) as resp:
                if resp.status != 200:
                    raise utils.HTTPException(status_code=resp.status, detail=f"Erro da LLM: {await resp.text()}")
                texto = await resp.text()
                return json.loads(texto)
        except asyncio.TimeoutError:
            raise utils.HTTPException(status_code=504, detail="Timeout da LLM")
        except json.JSONDecodeError as e:
            raise utils.HTTPException(status_code=500, detail=f"Erro ao processar resposta JSON: {str(e)}")
        except ValueError as e:
            raise utils.HTTPException(status_code=422, detail=f"Erro de validação do contexto: {str(e)}")



def salvar_contexto(contexto: dict, db_file="/app/databases/ataques.db"):
    """Salva um contexto gerado pela LLM como ataque"""
    tipo = contexto.get("tipo", "Contextualizado")
    descricao = contexto.get("descricao", "Contexto gerado automaticamente")
    detalhes = contexto.get("detalhes", str(contexto))

    query = "INSERT INTO ataques (tipo, descricao, detalhes) VALUES (?, ?, ?)"
    utils.executar_query(query, (tipo, descricao, detalhes), db_file=db_file)
    return {"mensagem": "Contexto salvo com sucesso!"}


async def registrar_ataque(contextos, token: str):
    url = f"{LLM_URL}/registrar_ataque"
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    
    async with aiohttp.ClientSession() as session:
        if isinstance(contextos, list):
            for contexto in contextos:
                async with session.post(url, headers=headers, json=contexto) as resp:
                    if resp.status != 200:
                        erro = await resp.text()
                        raise Exception(f"Erro ao registrar ataque: {erro}")
        else:
            async with session.post(url, headers=headers, json=contextos) as resp:
                if resp.status != 200:
                    erro = await resp.text()
                    raise Exception(f"Erro ao registrar ataque: {erro}")
        print("[Watcher] Ataque registrado com sucesso!")
    
