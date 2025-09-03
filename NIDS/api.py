from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import psycopg2
import requests
import uvicorn
import json
import jwt
import os
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext

app = FastAPI()
#NIDS_URL = "http://nids:5050"
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "nids_db")
DB_USER = os.getenv("DB_USER", "user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")

# Configuração do JWT
SECRET_KEY = "seu_segredo_super_secreto"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
oauth2_scheme = HTTPBearer()

# Configuração para criptografar senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def conectar():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

# Criar token JWT
def criar_token_jwt(dados: dict, expira_em: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    dados_copia = dados.copy()
    expira = datetime.now(timezone.utc) + timedelta(minutes=expira_em)
    dados_copia.update({"exp": expira})
    return jwt.encode(dados_copia, SECRET_KEY, algorithm=ALGORITHM)

# Verificar token JWT
#def verificar_token_jwt(token: str = Security(oauth2_scheme)):
def verificar_token_jwt(credentials: HTTPAuthorizationCredentials = Security(oauth2_scheme)):
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Token não fornecido")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

# Executar query no banco
def executar_query(query, params=(), fetchall=False, fetchone=False):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute(query, params)
    conn.commit()

    if fetchall:
        resultado = cursor.fetchall()
    elif fetchone:
        resultado = cursor.fetchone()
    else:
        resultado = None

    cursor.close()
    conn.close()
    return resultado


@app.post("/registrar_usuario")
def registrar_usuario(username: str, password: str):
    """Registra um novo usuário com senha criptografada"""
    senha_criptografada = pwd_context.hash(password)

    try:
        executar_query("INSERT INTO usuarios (username, password) VALUES (%s, %s)", (username, senha_criptografada))
    except psycopg2.IntegrityError:
        raise HTTPException(status_code=400, detail="Usuário já existe")

    return {"mensagem": "Usuário registrado com sucesso!"}

@app.post("/token")
async def gerar_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Gera um token JWT para um usuário autenticado"""
    usuario = form_data.username
    senha = form_data.password

    # Buscar usuário no banco
    resultado = executar_query("SELECT password FROM usuarios WHERE username = %s", (usuario,), fetchone=True)

    if not resultado or not pwd_context.verify(senha, resultado[0]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = criar_token_jwt({"sub": usuario})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/dados")
def obter_dados(tabela, token: dict = Depends(verificar_token_jwt)):
    try:
        dados = executar_query(query=f"SELECT * FROM {tabela}")
        return {"dados": dados}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao obter dados: {str(e)}")

@app.get("/dados/ataques")
def obter_dados_ataques(token: dict = Depends(verificar_token_jwt)):
    dados = executar_query(query = "SELECT * FROM classificados WHERE class NOT IN ('normal', 'Benign')")
    return {"dados": dados}

@app.get("/dados/trafego/insert")
def inserir_dados(flow_id: str, src_ip: str, dest_ip: str, src_port: int, dest_port: int, proto: str, hour: int, 
            minute: int, seconds: int, severity: int, pkts_toserver: int, pkts_toclient: int, bytes_toserver: int,
            bytes_toclient: int, token: dict = Depends(verificar_token_jwt)):
    query = "INSERT INTO trafego (flow_id, src_ip, dest_ip, src_port, dest_port, proto, hour, minute, seconds, severity, pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    if executar_query(query, (flow_id, src_ip, dest_ip, src_port, dest_port, proto, hour, minute, seconds, severity, pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient)):
        return {"mensagem": "Dados inseridos com sucesso!"}

@app.get("/dados/ataques/insert")
def inserir_dados(flow_id: str, src_ip: str, dest_ip: str, src_port: int, dest_port: int, proto: str, hour: int, 
            minute: int, seconds: int, severity: int, pkts_toserver: int, pkts_toclient: int, bytes_toserver: int,
            bytes_toclient: int, classe: str, processado: int, token: dict = Depends(verificar_token_jwt)):
    query = "INSERT INTO classificados (flow_id, src_ip, dest_ip, src_port, dest_port, proto, hour, minute, seconds, severity, pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, class, processado) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    if executar_query(query, (flow_id, src_ip, dest_ip, src_port, dest_port, proto, hour, minute, seconds, severity, pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, classe, processado)):
        return {"mensagem": "Dados inseridos com sucesso!"}

@app.get("/dados/ataques/novos")
def obter_dados_ataques(token: dict = Depends(verificar_token_jwt)):
    dados = executar_query(query = "SELECT flow_id, src_ip, dest_ip, src_port, dest_port, proto, hour, minute, seconds, severity, pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, class, processado FROM classificados WHERE class NOT IN ('normal', 'Benign') AND processado = 0", fetchall=True)
    return {"dados": dados}

@app.put("/dados/ataques/processar/{flow_id}")
def atualizar_ataque_processado(flow_id: str, token: dict = Depends(verificar_token_jwt)):
    """
    Atualiza um ataque específico para processado, baseado no flow_id.
    """
    query = "UPDATE classificados SET processado = 1 WHERE flow_id = %s AND processado = 0"
    executar_query(query, (flow_id,))

    return {"mensagem": f"Ataque {flow_id} marcado como processado!"}

def run_api(host="0.0.0.0", port=5050):
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_api()

