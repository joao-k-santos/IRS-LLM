#!/bin/bash

PARTITION=$1
SERVER_ADDRESS=$2
IP_CLIENT=$3
PASS=$4

# Verifica o IP e executa o código correspondente em segundo plano
sshpass -p $PASS ssh -o StrictHostKeyChecking=no nodeflower@$IP_CLIENT << EOF &
    cd ~/client
    source venv/bin/activate
    python3 client.py --partition $PARTITION --address $SERVER_ADDRESS
EOF
# Para esperar que todos os processos em background terminem (opcional)
wait
