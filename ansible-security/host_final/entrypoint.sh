#!/bin/bash
set -e

echo "Registrando timer do cron para ingestão de logs de rede..."
bash /opt/spark_log_ingest/setup_ingest_timer.sh

echo "Iniciando o cron em segundo plano..."
service cron start

echo "Iniciando a captura do suricata..."
bash /opt/scripts/suricata_start.sh &

echo "Iniciando o SSH daemon em primeiro plano..."
exec /usr/sbin/sshd -D
