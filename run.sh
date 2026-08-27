#!/usr/bin/env bash
# ============================================================
# PATRICT-OSINT EXECUTION SCRIPT & CLI INSTALLER
# ============================================================

set -e

# Warna Terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Direktori Project
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Fungsi Menampilkan Banner
show_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << "BANNER"
  ____       _  _____ ____  ___ ____ _____        ___  ____ ___ _   _ _____ 
 |  _ \     / \|_   _|  _ \|_ _/ ___|_   _|      / _ \/ ___|_ _| \ | |_   _|
 | |_) |   / _ \ | | | |_) || | |     | |  ____ | | | \___ \| ||  \| | | |  
 |  __/   / ___ \| | |  _ < | | |___  | | |____|| |_| |___) | || |\  | | |  
 |_|     /_/   \_\_| |_| \_\___\____| |_|        \___/|____/___|_| \_| |_|  
BANNER
    echo -e "              ${PURPLE}PATRICT-OSINT RUNNER & CLI ENGINE v2.0${NC}"
    echo -e "${CYAN}===================================================================${NC}\n"
}

# Fungsi Aktivasi Virtual Environment
check_environment() {
    if [ -d "venv" ]; then
        if [ -f "venv/bin/activate" ]; then
            source venv/bin/activate
        elif [ -f "venv/Scripts/activate" ]; then
            source venv/Scripts/activate
        fi
    fi

    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
        echo -e "${RED}[!] Error: Python3 tidak ditemukan di sistem Anda.${NC}"
        exit 1
    fi
}

# Fungsi Menampilkan Bantuan
show_help() {
    show_banner
    echo -e "${YELLOW}Penggunaan:${NC}"
    echo -e "  ./run.sh [perintah] [opsi]\n"
    echo -e "${YELLOW}Daftar Perintah:${NC}"
    echo -e "  ${GREEN}scan <target>${NC}        Jalankan pemindaian intelijen pada nomor telepon"
    echo -e "                       Contoh: ${CYAN}./run.sh scan +6281234567890${NC}"
    echo -e "  ${GREEN}install / setup${NC}      Install dependensi & daftarkan perintah '${BOLD}osint${NC}${GREEN}' ke terminal"
    echo -e "  ${GREEN}clean${NC}                Hapus hasil scan lama di folder output/"
    echo -e "  ${GREEN}help / --help${NC}        Tampilkan panduan ini\n"
    echo -e "${YELLOW}Jalan Pintas Global:${NC}"
    echo -e "  Setelah menjalankan ${CYAN}./run.sh install${NC}, Anda bisa langsung mengetik:"
    echo -e "  ${GREEN}osint${NC}                (untuk membuka mode interaktif dari mana saja)"
    echo -e "  ${GREEN}osint +6281234567890${NC} (untuk langsung scan nomor target)\n"
}

# Fungsi Setup Dependensi & Registrasi Global CLI
setup_dependencies() {
    show_banner
    echo -e "${BLUE}[*] Memeriksa dan menginstall dependensi...${NC}"
    
    if [ ! -d "venv" ]; then
        echo -e "${YELLOW}[*] Membuat virtual environment baru (venv)...${NC}"
        python3 -m venv venv
    fi
    source venv/bin/activate

    if [ ! -f ".env" ] && [ -f ".env.example" ]; then
        echo -e "${YELLOW}[*] Membuat file .env dari template...${NC}"
        cp .env.example .env
    fi

    echo -e "${BLUE}[*] Menginstall paket dari requirements.txt...${NC}"
    pip install --upgrade pip
    pip install -e .

    # Registrasi wrapper global ke ~/.local/bin
    mkdir -p "$HOME/.local/bin"
    cat << WRAPPER > "$HOME/.local/bin/osint"
#!/usr/bin/env bash
exec "$SCRIPT_DIR/venv/bin/python3" "$SCRIPT_DIR/main.py" "\$@"
WRAPPER
    chmod +x "$HOME/.local/bin/osint"

    # Buat juga alias patrict
    cp "$HOME/.local/bin/osint" "$HOME/.local/bin/patrict"

    echo -e "\n${GREEN}[✔] Setup Berhasil!${NC}"
    echo -e "${GREEN}[✔] Perintah global '${BOLD}osint${NC}${GREEN}' dan '${BOLD}patrict${NC}${GREEN}' telah aktif di terminal Anda.${NC}"
    echo -e "\n${YELLOW}Coba sekarang:${NC}"
    echo -e "  Ketik: ${CYAN}osint${NC} atau ${CYAN}osint +6281234567890${NC}\n"
}

# Fungsi Bersihkan Output
clean_output() {
    echo -e "${YELLOW}[*] Membersihkan isi folder output/...${NC}"
    rm -rf output/*
    echo -e "${GREEN}[✔] Folder output/ telah dibersihkan.${NC}"
}

# Inisialisasi Environment
check_environment

# Router Argumen Perintah
case "$1" in
    scan)
        if [ -z "$2" ]; then
            echo -e "${RED}[!] Error: Masukkan nomor telepon target.${NC}"
            echo -e "${YELLOW}Contoh:${NC} ./run.sh scan +6281234567890"
            exit 1
        fi
        python3 main.py "$2"
        ;;
    setup|install)
        setup_dependencies
        ;;
    clean)
        clean_output
        ;;
    help|--help|-h)
        show_help
        ;;
    "")
        python3 main.py
        ;;
    *)
        # Jika argumen pertama langsung berupa nomor (misal ./run.sh +628123456)
        python3 main.py "$@"
        ;;
esac
