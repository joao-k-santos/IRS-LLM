#!/bin/sh
# Habilita saída imediata em caso de erro
set -e

echo "Executando Ansible playbook na inicialização..."
# Execute seu playbook Ansible
# Certifique-se que os caminhos 'inventory' e 'playbook' estão corretos dentro do container
ansible-playbook -i /home/ansible_user/orquestrador/inventory/hosts.yml /home/ansible_user/orquestrador/playbooks/setup_orquestrador.yml

echo "Playbook Ansible concluído."

echo "Aplicando regras de firewall nft..."
nft -f /home/ansible_user/orquestrador/scripts/firewall_config.nft
# Use 'exec' para substituir este script pelo processo do cron.
# Isso faz o 'cron -f' se tornar o PID 1 (ou o processo principal monitorado pelo Docker).
echo "Iniciando cron em primeiro plano..."
exec cron -f