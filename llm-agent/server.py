from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import sqlite3
import requests
import uvicorn
import json
import jwt
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
import utils
from contextualizer import gerar_contexto
from rule_generator import gerar_regras
from pydantic import BaseModel
from contextualizer import salvar_contexto
from fastapi import Body
from fastapi import Query
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse
import tempfile

class ModelRequest(BaseModel):
    model: str

class AtaqueInput(BaseModel):
    tipo: str
    descricao: str
    detalhes: str


app = FastAPI()
OLLAMA_URL = "http://localhost:11434"
DB_FILE = "/app/databases/ataques.db"


# def gerar_token_watcher(dados: dict):
#     return criar_token_jwt(dados, expira_em=ACCESS_TOKEN_EXPIRE_MINUTES)
    

# def verificar_token_watcher(token: str):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         return True
#     except JWTError:
#         return False


@app.get("/healthcheck")
async def healthcheck():
    """Verifica se o servidor está ativo"""
    return {"status": "ok"}

@app.post("/registrar_usuario")
def registrar_usuario(username: str, password: str):
    """Registra um novo usuário com senha criptografada"""
    senha_criptografada = utils.pwd_context.hash(password)

    try:
        utils.executar_query("INSERT INTO usuarios (username, password) VALUES (?, ?)", (username, senha_criptografada))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Usuário já existe")

    return {"mensagem": "Usuário registrado com sucesso!"}

@app.post("/token")
async def gerar_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Gera um token JWT para um usuário autenticado"""
    usuario = form_data.username
    senha = form_data.password

    # Buscar usuário no banco
    resultado = utils.executar_query("SELECT password FROM usuarios WHERE username = ?", (usuario,), fetchone=True)

    if not resultado or not utils.pwd_context.verify(senha, resultado[0]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = utils.criar_token_jwt({"sub": usuario})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/listar_ataques")
def listar_ataques(token: dict = Security(utils.verificar_token_jwt), db_file=DB_FILE):
    """Lista todos os ataques registrados"""
    query = "SELECT id, tipo, descricao, detalhes FROM ataques"
    ataques = utils.executar_query(query, fetchall=True, db_file=db_file)
    return [{"id": a[0], "tipo": a[1], "descricao": a[2], "detalhes": a[3]} for a in ataques]

@app.get("/listar_usuarios")
def listar_usuarios(db_file=DB_FILE):
    """Lista todos os ataques registrados"""
    query = "SELECT username FROM usuarios"
    usuarios = utils.executar_query(query, fetchall=True, db_file=db_file)
    return [{"username": a[0]} for a in usuarios]

@app.post("/download_model/")
def download_model(model_name: str, token: dict = Depends(utils.verificar_token_jwt)):
    """Solicita ao Ollama para baixar um modelo"""
    response = requests.post(f"{OLLAMA_URL}/api/pull", json={"name": model_name})
    
    if response.status_code == 200:
        return {"message": f"Modelo {model_name} baixado com sucesso"}
    else:
        return {"error": f"Erro ao baixar modelo {model_name}", "details": response.json()}

@app.get("/models")
def listar_modelos(token: dict = Depends(utils.verificar_token_jwt)):
    """Lista os modelos disponíveis no Ollama"""
    response = requests.get(f"{OLLAMA_URL}/api/tags")
    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=500, detail="Erro ao obter modelos disponíveis")


@app.post("/gerar_contexto")
async def gerar_contexto_endpoint(
    payload: ModelRequest,
    token: dict = Security(utils.verificar_token_jwt)
):
    if not utils.verificar_token_jwt(token):
        raise HTTPException(status_code=401, detail="Token inválido")

    ataques = utils.executar_query("SELECT * FROM ataques WHERE processado = 0", fetchall=True)
    if not ataques:
        raise HTTPException(status_code=404, detail="Nenhum ataque não processado")

    try:
        resultado = await gerar_contexto(ataques, payload.model, OLLAMA_URL)
        return resultado
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gerar_regras")
async def gerar_regras_endpoint(
    payload: ModelRequest,
    token: dict = Security(utils.verificar_token_jwt)
):
    #token = credentials.credentials
    if not utils.verificar_token_jwt(token):
        raise HTTPException(status_code=401, detail="Token inválido")

    try:
        resultado = await gerar_regras(payload.model, OLLAMA_URL)
        return resultado
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/registrar_ataque")
def registrar_ataque(
    ataque: AtaqueInput,
    credentials: HTTPAuthorizationCredentials = Security(utils.oauth2_scheme),
    db_file=DB_FILE
):
    token = credentials.credentials
    if not utils.verificar_token_jwt(token):
        raise HTTPException(status_code=401, detail="Token inválido")

    query = "INSERT INTO ataques (tipo, descricao, detalhes) VALUES (?, ?, ?)"
    utils.executar_query(query, (ataque.tipo, ataque.descricao, ataque.detalhes), db_file=db_file)
    return {"mensagem": "Ataque registrado com sucesso!"}

@app.get("/listar_regras")
def listar_ataques(token: dict = Security(utils.verificar_token_jwt), db_file=DB_FILE):
    """Lista todos os ataques registrados"""
    query = "SELECT id, tipo, descricao, comando, ataque_id FROM regras"
    regras = utils.executar_query(query, fetchall=True, db_file=db_file)
    return [{"id": a[0], "tipo": a[1], "descricao": a[2], "comando": a[3], "ataque_id": a[4]} for a in regras]


@app.post("/registrar_dispositivo")
def registrar_dispositivo(
    dispositivo: str,
    credentials: HTTPAuthorizationCredentials = Security(utils.oauth2_scheme),
    db_file=DB_FILE
):
    token = credentials.credentials
    if not utils.verificar_token_jwt(token):
        raise HTTPException(status_code=401, detail="Token inválido")

    query = "INSERT INTO protegidos (ip_protegido) VALUES (?)"
    utils.executar_query(query, (dispositivo,), db_file=db_file)
    return {"mensagem": "Dispositivo protegido registrado com sucesso!"}


@app.get("/listar_dispositivos")
def listar_dispositivos(token: dict = Security(utils.verificar_token_jwt), db_file=DB_FILE):
    """Lista todos os dispositivos registrados"""
    query = "SELECT ip_protegido FROM protegidos"
    dispositivos = utils.executar_query(query, fetchall=True, db_file=db_file)
    return [{"ip-dispositivo":dispositivo} for dispositivo in dispositivos]


@app.get("/download_regras")
def download_regras(
    formato: str = Query("json", enum=["json", "arquivo_json", "arquivo_txt"]),
    credentials: HTTPAuthorizationCredentials = Security(HTTPBearer()),
    db_file: str = DB_FILE
):
    token = utils.verificar_token_jwt(credentials.credentials)
    if not token:
        raise HTTPException(status_code=401, detail="Token inválido")

    query = "SELECT id, tipo, descricao, comando, ataque_id FROM regras"
    regras = utils.executar_query(query, fetchall=True, db_file=db_file)

    if not regras:
        raise HTTPException(status_code=404, detail="Nenhuma regra encontrada")

    regras_formatadas = [
        {
            "id": r[0],
            "tipo": r[1],
            "descricao": r[2],
            "comando": r[3],
        }
        for r in regras
    ]

    if formato == "json":
        return JSONResponse(content=regras_formatadas)

    elif formato == "arquivo_json":
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json") as tmp_file:
            json.dump(regras_formatadas, tmp_file, indent=2)
            file_path = tmp_file.name
        return FileResponse(file_path, media_type="application/json", filename="regras.json")

    elif formato == "arquivo_txt":
        regras_txt = "\n".join(
            f"ID: {r['id']}\nTipo: {r['tipo']}\nDescrição: {r['descricao']}\nComando: {r['comando']}\nAtaque ID: {r['ataque_id']}\n"
            for r in regras_formatadas
        )
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as tmp_file:
            tmp_file.write(regras_txt)
            file_path = tmp_file.name
        return FileResponse(file_path, media_type="text/plain", filename="regras.txt")


def run_api(host="0.0.0.0", port=8000):
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_api()

