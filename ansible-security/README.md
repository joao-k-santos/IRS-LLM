# Sistema de Prevenção de Intrusão Baseado em Host (SPIH)

## Autor

**João Kleber Magalhães dos Santos**

## Sobre o Projeto

Este projeto foi desenvolvido durante a realização do **Projeto de Graduação do Curso de Engenharia de Redes de Comunicação** na **Universidade de Brasília**.

O objetivo é implementar um **Sistema de Prevenção de Intrusão Baseado em Host (SPIH)**, utilizando **Ansible** para orquestração e automação da aplicação de regras de segurança.

---

## Estrutura do Diretório do Projeto

```
/ansible_security/
│
├── inventory/                           # Inventário de hosts (arquivo ou diretórios)
│   └── hosts.yml                        # Lista de hosts para o Ansible
│
├── playbooks/                           # Diretório para os playbooks do Ansible
│   └── aplicar_regras.yml               # Playbook para baixar e aplicar regras
│
├── scripts/                             # Diretório para os scripts de automação
│   └── aplicar_regras.sh                # Script que baixa e aplica as regras
│
├── systemd/                             # Diretório para os arquivos de serviço systemd
│   ├── aplicar_regras.service           # Arquivo de serviço systemd para rodar o script
│   └── aplicar_regras.timer             # Arquivo de timer systemd para rodar periodicamente
│
├── vars/                                # Diretório para variáveis, como URLs do orquestrador
│   └── vars.yml                         # Arquivo com variáveis globais, como API_URL
│
└── README.md                            # Documentação do projeto
```

---

## Como Utilizar

### 1️⃣ Configurar o Inventário de Hosts

Defina os hosts que serão gerenciados pelo **Ansible** no arquivo `inventory/hosts.yml`.

### 2️⃣ Executar o Playbook

Para baixar e aplicar as regras de segurança, execute:

```sh
ansible-playbook -i inventory/hosts.yml playbooks/aplicar_regras.yml
```

### 3️⃣ Configurar a Automação via Systemd

Ative o serviço para executar o script periodicamente:

```sh
sudo systemctl enable aplicar_regras.timer
sudo systemctl start aplicar_regras.timer
```

---

## 📌 Contato

Caso tenha dúvidas ou sugestões, entre em contato!

---

**Universidade de Brasília - Engenharia de Redes de Comunicação**

Como ficaria o código para exibi-lo assim no Github?

