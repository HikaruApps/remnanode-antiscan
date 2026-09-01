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

err()    { echo -e "${RED}[✘]${NC} $*" >&2; exit 1; }
info()   { echo -e "${CYAN}[*]${NC} $*"; }
prompt() { echo -e "${BOLD}$*${NC}"; }

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
  ENABLE_BLOCKLISTS     1/0 — загрузить IP-blocklists в ipset (по умолч.: 1)
  DRY_RUN               1 — показать правила без применения

ENV для команды rollback:
  PURGE_CROWDSEC        1 — удалить CrowdSec полностью (по умолч.: 0)

Примеры:
  sudo SSH_PORT=22 TCP_PORTS=443,2087 UDP_PORTS=443 \
       WHITELIST="1.2.3.4" bash install.sh protect

  sudo DRY_RUN=1 bash install.sh protect
  sudo ENABLE_CROWDSEC=0 bash install.sh protect
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

# Читает ввод с дефолтом: ask "Вопрос" "дефолт" → результат в $REPLY
ask() {
    local question="$1"
    local default="$2"
    echo -ne "  ${BOLD}${question}${NC} [${CYAN}${default}${NC}]: "
    read -r REPLY
    REPLY="${REPLY:-$default}"
}

# Да/нет: yn "Вопрос" "y" → 1 или 0 в $YN
yn() {
    local question="$1"
    local default="${2:-y}"
    local hint; [[ "$default" == "y" ]] && hint="Y/n" || hint="y/N"
    echo -ne "  ${BOLD}${question}${NC} [${CYAN}${hint}${NC}]: "
    read -r REPLY
    REPLY="${REPLY:-$default}"
    [[ "${REPLY,,}" == "y" ]] && YN=1 || YN=0
}

ask_protect_params() {
    echo ""
    echo -e "  ${BOLD}Настройка параметров защиты${NC}"
    echo -e "  ${YELLOW}Enter — оставить значение по умолчанию${NC}"
    echo ""

    # Авто-детект SSH
    local ssh_detected
    ssh_detected=$(ss -tlnp 2>/dev/null \
        | awk '/sshd/{match($4,/[0-9]+$/); p=substr($4,RSTART,RLENGTH); if(p) print p}' \
        | head -1)
    ssh_detected="${ssh_detected:-22}"

    ask "SSH-порт" "$ssh_detected"
    PARAM_SSH_PORT="$REPLY"

    ask "TCP-порты сервиса (через запятую)" "443,2087"
    PARAM_TCP_PORTS="$REPLY"

    ask "UDP-порты сервиса (через запятую)" "443"
    PARAM_UDP_PORTS="$REPLY"

    ask "Whitelist IP/CIDR (через запятую, или оставь пустым)" ""
    PARAM_WHITELIST="$REPLY"

    echo ""
    echo -e "  ${BOLD}Дополнительные компоненты:${NC}"

    yn "Установить CrowdSec (community blocklist + IPS)?" "y"
    PARAM_CROWDSEC="$YN"

    yn "Загрузить IP-blocklists в ipset (antiscanner + gov)?" "y"
    PARAM_BLOCKLISTS="$YN"

    if [[ "$PARAM_CROWDSEC" == "1" ]]; then
        ask "CrowdSec enroll key (из app.crowdsec.net, или Enter чтобы пропустить)" ""
        PARAM_ENROLL_KEY="$REPLY"
    else
        PARAM_ENROLL_KEY=""
    fi

    yn "DRY RUN — только показать правила, не применять?" "n"
    PARAM_DRY_RUN="$YN"

    # Итоговый summary
    echo ""
    echo -e "  ┌─ ${BOLD}Итоговые параметры${NC} ─────────────────────────"
    echo -e "  │  SSH-порт:    ${CYAN}${PARAM_SSH_PORT}${NC}"
    echo -e "  │  TCP-порты:   ${CYAN}${PARAM_TCP_PORTS}${NC}"
    echo -e "  │  UDP-порты:   ${CYAN}${PARAM_UDP_PORTS}${NC}"
    echo -e "  │  Whitelist:   ${CYAN}${PARAM_WHITELIST:-не задан}${NC}"
    echo -e "  │  CrowdSec:    ${CYAN}${PARAM_CROWDSEC}${NC}"
    echo -e "  │  Blocklists:  ${CYAN}${PARAM_BLOCKLISTS}${NC}"
    echo -e "  │  DRY RUN:     ${CYAN}${PARAM_DRY_RUN}${NC}"
    echo -e "  └──────────────────────────────────────────"
    echo ""

    yn "Всё верно, продолжить?" "y"
    if [[ "$YN" == "0" ]]; then
        info "Отменено. Запускай заново."
        exit 0
    fi
}

run_protect() {
    ask_protect_params

    SSH_PORT="$PARAM_SSH_PORT" \
    TCP_PORTS="$PARAM_TCP_PORTS" \
    UDP_PORTS="$PARAM_UDP_PORTS" \
    WHITELIST="$PARAM_WHITELIST" \
    ENABLE_CROWDSEC="$PARAM_CROWDSEC" \
    ENABLE_BLOCKLISTS="$PARAM_BLOCKLISTS" \
    CROWDSEC_ENROLL_KEY="$PARAM_ENROLL_KEY" \
    DRY_RUN="$PARAM_DRY_RUN" \
    bash "${SCRIPT_DIR}/scripts/protect.sh"
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
        1) run_protect ;;
        2) bash "${SCRIPT_DIR}/scripts/status.sh" ;;
        3) bash "${SCRIPT_DIR}/scripts/rollback.sh" ;;
        q|Q) exit 0 ;;
        *) echo "Неверный выбор"; show_menu ;;
    esac
}

CMD="${1:-}"

case "$CMD" in
    protect)   run_protect ;;
    rollback)  bash "${SCRIPT_DIR}/scripts/rollback.sh" ;;
    status)    bash "${SCRIPT_DIR}/scripts/status.sh" ;;
    --help|-h) show_help ;;
    "")        show_menu ;;
    *)
        echo -e "${RED}Неизвестная команда: ${CMD}${NC}"
        echo "Используй: sudo bash install.sh --help"
        exit 1
        ;;
esac
