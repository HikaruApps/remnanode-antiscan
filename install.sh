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
if [[ ! -t 1 || -n ${NO_COLOR:-} ]]; then
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''
fi

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
  confirm    Подтвердить применение из нового SSH-подключения
  rollback   Удалить защиту и восстановить прежние настройки
  status     Показать текущий статус защиты
  update     Обновить файлы проекта из GitHub
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

  SAFETY_TIMER          Время на подтверждение (по умолч.: 180 секунд)

Примеры:
  sudo SSH_PORT=22 TCP_PORTS=443,2087 UDP_PORTS=443 \
       WHITELIST="1.2.3.4" bash install.sh protect

  sudo DRY_RUN=1 bash install.sh protect
  sudo ENABLE_CROWDSEC=0 bash install.sh protect
  sudo --preserve-env=SSH_CONNECTION bash install.sh confirm
HELP
}

show_banner() {
    printf '\n  %bRemnaNode AntiScan%b\n' "$BOLD$CYAN" "$NC"
    printf '  Защита ноды · UFW · Управление\n'
    if [[ -f /var/lib/ufw-antiscan/pending ]]; then
        printf '  %bОжидается подтверждение — автооткат включён%b\n' "$YELLOW" "$NC"
    fi
    printf '\n'
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

    ask "SSH-порт" "${SSH_PORT:-$ssh_detected}"
    PARAM_SSH_PORT="$REPLY"

    ask "TCP-порты сервиса (через запятую)" "${TCP_PORTS:-443,2087}"
    PARAM_TCP_PORTS="$REPLY"

    ask "UDP-порты сервиса (через запятую)" "${UDP_PORTS-443}"
    PARAM_UDP_PORTS="$REPLY"

    ask "Whitelist IP/CIDR (через запятую, или оставь пустым)" "${WHITELIST:-}"
    PARAM_WHITELIST="$REPLY"

    echo ""
    echo -e "  ${BOLD}Дополнительные компоненты:${NC}"

    yn "Установить CrowdSec (community blocklist + IPS)?" "$([[ ${ENABLE_CROWDSEC:-1} == 1 ]] && echo y || echo n)"
    PARAM_CROWDSEC="$YN"

    yn "Загрузить IP-blocklists в ipset (antiscanner + gov)?" "$([[ ${ENABLE_BLOCKLISTS:-1} == 1 ]] && echo y || echo n)"
    PARAM_BLOCKLISTS="$YN"

    if [[ "$PARAM_CROWDSEC" == "1" ]]; then
        ask "CrowdSec enroll key (из app.crowdsec.net, или Enter чтобы пропустить)" ""
        PARAM_ENROLL_KEY="$REPLY"
    else
        PARAM_ENROLL_KEY=""
    fi

    yn "DRY RUN — только показать правила, не применять?" "$([[ ${DRY_RUN:-0} == 1 ]] && echo y || echo n)"
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
        return 1
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
    local choice
    while true; do
        show_banner
        printf '  %b1%b  Настроить защиту\n' "$BOLD" "$NC"
        printf '  %b2%b  Проверить статус\n' "$BOLD" "$NC"
        printf '  %b3%b  Удалить защиту\n' "$BOLD" "$NC"
        printf '  %b4%b  Обновить скрипт\n' "$BOLD" "$NC"
        printf '  %b5%b  Подтвердить применение\n' "$BOLD" "$NC"
        printf '\n  %b0%b  Выйти\n\n' "$BOLD" "$NC"
        printf '  Выберите действие: '
        read -r choice || return 0
        case "$choice" in
            1) bash "$SCRIPT_DIR/install.sh" --configure || info "Настройка не завершена." ;;
            2) bash "$SCRIPT_DIR/scripts/status.sh" || info "Не удалось получить полный статус." ;;
            3)
                printf '  Удалить защиту? [y/N]: '
                read -r choice || return 0
                if [[ "${choice,,}" == y ]]; then
                    bash "$SCRIPT_DIR/scripts/rollback.sh" || info "Удаление не завершено."
                fi
                ;;
            4)
                if bash "$SCRIPT_DIR/scripts/update.sh"; then
                    cd "$SCRIPT_DIR"
                    exec bash "$SCRIPT_DIR/install.sh"
                else
                    info "Обновление не выполнено."
                fi
                ;;
            5) bash "$SCRIPT_DIR/scripts/confirm.sh" || info "Применение не подтверждено." ;;
            0|q|Q) printf '\n  До встречи :3\n'; return 0 ;;
            *) info "Введите номер от 0 до 5."; continue ;;
        esac
        printf '\n  Enter — вернуться в меню…'
        read -r choice || return 0
    done
}

CMD="${1:-}"

case "$CMD" in
    --configure) run_protect ;;
    update)    bash "$SCRIPT_DIR/scripts/update.sh" ;;
    protect)   bash "${SCRIPT_DIR}/scripts/protect.sh" "${@:2}" ;;
    confirm)   bash "${SCRIPT_DIR}/scripts/confirm.sh" ;;
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
