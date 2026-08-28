#!/usr/bin/env bash
# ============================================================
# PATRICT-OSINT Automated Universal Installer
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${BLUE}===================================================================${RESET}"
echo -e "         ${YELLOW}PATRICT-OSINT Framework - Installer${RESET}"
echo -e "${BLUE}===================================================================${RESET}"

# 1. Periksa ketersediaan Python 3 & Git
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Error: Python 3 belum terinstal. Silakan instal python3 terlebih dahulu.${RESET}"
    exit 1
fi

if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    echo -e "${RED}[!] Error: pip belum terinstal. Silakan instal python3-pip.${RESET}"
    exit 1
fi

PIP_CMD="pip3"
if ! command -v pip3 &> /dev/null; then
    PIP_CMD="pip"
fi

INSTALL_DIR="$HOME/.patrict-osint"

echo -e "${YELLOW}[*] Mengunduh repository PATRICT-OSINT...${RESET}"
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[*] Memperbarui instalasi yang sudah ada di $INSTALL_DIR...${RESET}"
    cd "$INSTALL_DIR"
    git pull origin dev || git pull origin main
else
    git clone -b dev https://github.com/tb245950-wq/PATRICT-OSINT.git "$INSTALL_DIR" || \
    git clone https://github.com/tb245950-wq/PATRICT-OSINT.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo -e "${YELLOW}[*] Menginstal dependensi & mendaftarkan command binary 'osint'...${RESET}"
$PIP_CMD install -e . --break-system-packages 2>/dev/null || $PIP_CMD install -e .

echo ""
echo -e "${GREEN}[+] INSTALASI BERHASIL!${RESET}"
echo -e "${GREEN}[+] Anda sekarang dapat menjalankan perintah:${RESET}"
echo -e "    ${YELLOW}osint${RESET}          (Mode Interaktif)"
echo -e "    ${YELLOW}osint --help${RESET}   (Panduan Lengkap)"
echo -e "${BLUE}===================================================================${RESET}"
