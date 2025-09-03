import sqlite3
import os
import requests
import time

DB_DIR = "/app/databases"  # Caminho do diretório onde o banco será salvo
DB_FILE = os.path.join(DB_DIR, "ataques.db")  # Caminho completo do banco

# Garante que o diretório do banco exista
os.makedirs(DB_DIR, exist_ok=True)


OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "gemma3:12b-it-qat"

def ensure_default_model():
    """Verifica se o modelo padrão está disponível e baixa se necessário"""
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags")
        if response.status_code == 200 and DEFAULT_MODEL in [m["name"] for m in response.json().get("models", [])]:
            print(f"Modelo {DEFAULT_MODEL} já está disponível.")
            return
    except Exception as e:
        print(f"Erro ao verificar modelos: {e}")

    print(f"Baixando modelo padrão {DEFAULT_MODEL}...")
    response = requests.post(f"{OLLAMA_URL}/api/pull", json={"name": DEFAULT_MODEL})
    
    if response.status_code == 200:
        print(f"Modelo {DEFAULT_MODEL} baixado com sucesso.")
    else:
        print(f"Erro ao baixar modelo {DEFAULT_MODEL}: {response.json()}")

def inicializar_banco():
    """Cria o banco de dados e as tabelas se ainda não existirem"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ataques (
            id TEXT PRIMARY KEY,
            tipo TEXT NOT NULL,
            descricao TEXT NOT NULL,
            detalhes TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS regras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo TEXT NOT NULL,
            descricao TEXT NOT NULL,
            comando TEXT NOT NULL,
            ataque_id TEXT NOT NULL,
            FOREIGN KEY (ataque_id) REFERENCES ataques(id)
        )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS protegidos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_protegido TEXT UNIQUE NOT NULL
    )
    """)

    conn.commit()
    conn.close()
    print("Banco de dados inicializado!")

if __name__ == "__main__":
    inicializar_banco()
    time.sleep(10)  # Aguarda o Ollama inicializar
    ensure_default_model()
    
