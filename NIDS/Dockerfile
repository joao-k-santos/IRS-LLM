# Usa a imagem oficial do Python
FROM python:3.12

# Define o diretório de trabalho dentro do container
WORKDIR /

RUN mkdir -p /certificates
RUN mkdir -p /Folds
RUN mkdir -p /models
RUN mkdir -p /var/log/


# Copia os arquivos necessários para dentro do container
COPY certificates/ ./certificates
COPY Folds ./Folds
COPY models ./models
COPY trainmodel.zip ./
COPY requirements.txt ./
COPY server.py ./
COPY client.py ./
COPY classifier.py ./
COPY run.sh ./
COPY startclient.sh ./
COPY entrypoint.sh ./
COPY init_db.py ./
COPY api.py ./
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Instala as dependências do sistema
RUN apt-get update && apt-get install -y \
    git \
    sshpass \
    openssh-server \
    openssh-client \
    libhdf5-dev \
    pkg-config \
    openssl \
    zip \
    supervisor \
    && rm -rf /var/lib/apt/lists/*  # Limpa o cache do apt para reduzir a imagem

# Instala as dependências do Python
RUN pip install -r requirements.txt

RUN unzip trainmodel.zip -d ./Folds
# Dá permissão de execução para os scripts
RUN chmod +x entrypoint.sh run.sh startclient.sh

# Expõe a porta do Flower
EXPOSE 8080
EXPOSE 5050

# Define o ponto de entrada do container
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
