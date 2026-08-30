#!/bin/bash
# ufw-antiscan/install.sh — точка входа
#
# Использование:
#   sudo bash install.sh             # интерактивное меню
#   sudo bash install.sh protect     # установить защиту
#   sudo bash install.sh rollback    # откатить
#   sudo bash install.sh status      # проверить статус
#   sudo bash install.sh --help      # справка

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

err() { echo -e "${RED}[✘]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && err "Нужен root: sudo bash $0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_help() {
    cat << 'HELP'
ufw-antiscan — защита от сканеров и флуда поверх UFW

Использование:
  sudo bash install.sh [команда]

Команды:
  protect    Установить защиту (iptables-правила + fail2ban + CrowdSec)
  rollback   Откатить все изменения
  status     Показать текущий статус защиты
  --help     Показать эту справку

ENV для команды protect:
  SSH_PORT              Порт SSH (авто-детект если не задан)
  TCP_PORTS             Сервисные TCP-порты через запятую (по умолч.: 443,2087)
  UDP_PORTS             Сервисные UDP-порты через запятую (по умолч.: 443)
  WHITELIST             IP/CIDR через запятую — никогда не блокируются
  SYN_RATE              Per-IP лимит новых TCP-соед/сек (по умолч.: 100)
  CONN_LIMIT            Макс одновременных соединений с одного IP (по умолч.: 600)
  ENABLE_CROWDSEC       1/0 — установить CrowdSec (по умолч.: 1)
  CROWDSEC_ENROLL_KEY   Ключ из app.crowdsec.net (опционально)
  DRY_RUN               1 — показать правила без применения

ENV для команды rollback:
  PURGE_CROWDSEC        1 — удалить CrowdSec полностью (по умолч.: 0)

Примеры:
  # Remnawave-нода
  sudo SSH_PORT=22 TCP_PORTS=443,2087 UDP_PORTS=443 \
       WHITELIST="1.2.3.4" bash install.sh protect

  # Посмотреть что будет без применения
  sudo DRY_RUN=1 bash install.sh protect

  # Без CrowdSec
  sudo ENABLE_CROWDSEC=0 bash install.sh protect

  # Откатить всё включая CrowdSec
  sudo PURGE_CROWDSEC=1 bash install.sh rollback
HELP
}

show_banner() {
    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "  ╦ ╦╔═╗╦ ╦   ╔═╗╔╗╔╔╦╗╦╔═╗╔═╗╔═╗╔╗╔"
    echo "  ║ ║╠╣ ║║║───╠═╣║║║ ║ ║╚═╗║  ╠═╣║║║"
    echo "  ╚═╝╚  ╚╩╝   ╩ ╩╝╚╝ ╩ ╩╚═╝╚═╝╩ ╩╝╚╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}AntiScan + flag-drop + rate-limit + CrowdSec поверх UFW${NC}"
    echo -e "  Для Remnawave-нод и любых VPS с UFW"
    echo ""
}

show_menu() {
    show_banner
    echo -e "  Выбери действие:\n"
    echo -e "  ${BOLD}1)${NC} 🛡  Установить защиту"
    echo -e "  ${BOLD}2)${NC} 🩺  Статус"
    echo -e "  ${BOLD}3)${NC} ↩   Откат"
    echo -e "  ${BOLD}q)${NC}     Выход"
    echo ""
    echo -n "  Выбор: "
    read -r CHOICE

    case "$CHOICE" in
        1) bash "${SCRIPT_DIR}/scripts/protect.sh" ;;
        2) bash "${SCRIPT_DIR}/scripts/status.sh"  ;;
        3) bash "${SCRIPT_DIR}/scripts/rollback.sh" ;;
        q|Q) exit 0 ;;
        *) echo "Неверный выбор"; show_menu ;;
    esac
}

CMD="${1:-}"

case "$CMD" in
    protect)  bash "${SCRIPT_DIR}/scripts/protect.sh"  ;;
    rollback) bash "${SCRIPT_DIR}/scripts/rollback.sh" ;;
    status)   bash "${SCRIPT_DIR}/scripts/status.sh"   ;;
    --help|-h) show_help ;;
    "")       show_menu ;;
    *)
        echo -e "${RED}Неизвестная команда: ${CMD}${NC}"
        echo "Используй: sudo bash install.sh --help"
        exit 1
        ;;
esac
