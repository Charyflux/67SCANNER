#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
#  SOC Scanner PRO v5.0 — Script de Instalação Automática
# ══════════════════════════════════════════════════════════════
set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}"
echo "  ██████╗  ██████╗  ██████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗███╗  ██╗███████╗██████╗"
echo "  ██╔═══╝ ██╔═══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗"
echo "  ╚█████╗ ██║   ██║██║         ███████╗██║     ███████║██╔██╗██║██╔██╗██║█████╗  ██████╔╝"
echo "   ╚══██╗██║   ██║██║         ╚════██║██║     ██╔══██║██║╚████║██║╚████║██╔══╝  ██╔══██╗"
echo "  ██████╔╝╚██████╔╝╚██████╗   ███████║╚██████╗██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║"
echo "  ╚═════╝  ╚═════╝  ╚═════╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${YELLOW}  PRO v5.0 — Advanced Pentest · Nuclei · Katana · JWT · Supabase · OWASP Top 10${NC}"
echo ""

# ── 1. Python ──────────────────────────────────────────────────
echo -e "${CYAN}[1/5] Verificando Python 3...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Python3 nao encontrado. Instale: sudo apt install python3 python3-pip${NC}"
    exit 1
fi
echo -e "${GREEN}✔ Python $(python3 --version)${NC}"

# ── 2. pip dependencies ───────────────────────────────────────
echo -e "${CYAN}[2/5] Instalando dependencias Python...${NC}"
pip3 install -r requirements.txt --quiet
echo -e "${GREEN}✔ Dependencias instaladas${NC}"

# ── 3. Go + Ferramentas ───────────────────────────────────────
echo -e "${CYAN}[3/5] Verificando Go...${NC}"
if ! command -v go &>/dev/null; then
    echo -e "${YELLOW}Go nao encontrado. Instalando...${NC}"
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
fi
echo -e "${GREEN}✔ Go instalado${NC}"

# ── 4. Nuclei, Katana, Subfinder ──────────────────────────────
echo -e "${CYAN}[4/5] Instalando Nuclei, Katana e Subfinder...${NC}"
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

if ! command -v nuclei &>/dev/null && [ ! -f "$HOME/go/bin/nuclei" ]; then
    echo -e "  → Instalando Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
fi

if ! command -v katana &>/dev/null && [ ! -f "$HOME/go/bin/katana" ]; then
    echo -e "  → Instalando Katana..."
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
fi

if ! command -v subfinder &>/dev/null && [ ! -f "$HOME/go/bin/subfinder" ]; then
    echo -e "  → Instalando Subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
fi

echo -e "${GREEN}✔ Ferramentas Go instaladas${NC}"

# ── 5. Nuclei templates ───────────────────────────────────────
echo -e "${CYAN}[5/5] Actualizando templates Nuclei...${NC}"
if [ -f "$HOME/go/bin/nuclei" ]; then
    $HOME/go/bin/nuclei -update-templates -silent 2>/dev/null || true
fi
echo -e "${GREEN}✔ Templates actualizados${NC}"

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✔ INSTALAÇÃO COMPLETA!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Inicia o scanner com: ${CYAN}python3 soc.py${NC}"
echo -e "  Abre no browser:      ${CYAN}http://localhost:7331${NC}"
echo ""
