#!/bin/bash
set -e

# Inicia o servidor do Ollama em segundo plano
ollama serve &
sleep 5

# Verifica se o modelo personalizado já existe
if ! ollama list | grep -q "$CUSTOM_MODEL_NAME"; then
    echo "Modelo '$CUSTOM_MODEL_NAME' não encontrado. Criando..."
    ollama create "$CUSTOM_MODEL_NAME" -f "/root/.ollama/models/$CUSTOM_MODEL_NAME"
else
    echo "Modelo '$CUSTOM_MODEL_NAME' já existe. Pulando criação."
fi

# Mantém o container rodando
tail -f /dev/null
