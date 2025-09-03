# Usa a imagem oficial do Python
FROM python:3.12

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia os arquivos necessários
COPY requirements.txt ./
COPY server.py ./
COPY rule_generator.py ./
COPY contextualizer.py ./
COPY llm_client.py ./
COPY utils.py ./
COPY watcher.py ./
COPY init_db.py ./
COPY prompt_template.txt ./prompt_template.txt

RUN apt-get update && apt-get install -y sqlite3

# Instala as dependências
RUN pip install --no-cache-dir -r requirements.txt

# Expõe a porta da API (opcional, já que estamos em modo host)
EXPOSE 8000

# Não definimos CMD aqui — cada container define seu command no docker-compose
