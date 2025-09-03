#!/bin/bash
if [ ! -d "/flower/.cache" ]; then
    echo "Gerando novos certificados SSL..."
    bash certificates/generate_certificates.sh
else
    echo "Certificados SSL já existem. Pulando geração..."
fi
echo "Iniciando o servidor flower..."
exec bash ./run.sh "$@"