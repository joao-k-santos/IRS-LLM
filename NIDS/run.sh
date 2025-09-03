#!/bin/bash

# Parâmetros de entrada
SERVER_ADDRESS=$1
CLIENTS_STRING=$2
NUM_CLIENTS=$3
NUM_ROUNDS=$4

# Transformar a string em array
IFS=',' read -ra CLIENT_IPS <<< "$CLIENTS_STRING"

# Iniciar o servidor com o número de clientes e rounds passados como parâmetros
echo "Starting server with $NUM_CLIENTS clients and $NUM_ROUNDS rounds"
python3 server.py --address $SERVER_ADDRESS --clients $NUM_CLIENTS --rounds $NUM_ROUNDS &

# Dar tempo suficiente para o servidor iniciar
sleep 10  

# Iniciar os clientes com os IPs fornecidos
for (( i=0; i<$NUM_CLIENTS; i++ )); do
    IP=${CLIENT_IPS[$i]}
    SENHA="@flower$((14 + i))"
    echo "Starting client $i with IP $IP and password $SENHA"
    bash startclient.sh $i $SERVER_ADDRESS "$IP" "$SENHA" &
done

# Permitir parar todos os processos com CTRL+C
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM

# Espera por todos os processos em segundo plano
wait
