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
ok()     { echo -e "${GREEN}[✔]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
prompt() { echo -e "${BOLD}$*${NC}"; }

[[ $EUID -ne 0 ]] && err "Нужен root: sudo bash $0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_help() {
    cat << 'HELP'
ufw-antiscan — защита от сканеров и флуда поверх UFW

Использование:
  sudo bash install.sh [команда]

Команды:
  basic      Basic: SSH-ключ, безопасное отключение пароля, Fail2Ban/CrowdSec
  protect    Experimental: настраиваемые firewall-правила + Fail2Ban/CrowdSec
  confirm    Подтвердить применение из нового SSH-подключения
  rollback   Удалить защиту и восстановить прежние настройки
  status     Показать текущий статус защиты
  update     Обновить файлы проекта из GitHub
  --help     Показать эту справку

ENV для команды basic apply:
  TARGET_USER           Пользователь SSH
  DISABLE_SSH_PASSWORD  1/0 — отключить парольный вход
  KEY_TEST_CONFIRMED    1 — подтверждён вход ключом без пароля
  ENABLE_FAIL2BAN       1/0 — установить Fail2Ban
  ENABLE_CROWDSEC       1/0 — установить CrowdSec

ENV для команды protect (Experimental):
  SSH_PORT              Порт SSH (авто-детект если не задан)
  TCP_PORTS             Сервисные TCP-порты через запятую (по умолч.: 443,2087)
  UDP_PORTS             Сервисные UDP-порты через запятую (по умолч.: 443)
  WHITELIST             IP/CIDR через запятую — никогда не блокируются
  ENABLE_BAD_TCP_FLAGS  1/0 — фильтровать некорректные TCP-флаги
  ENABLE_ANTISPOOFING   1/0 — IPv4 anti-spoofing на WAN
  ENABLE_SYN_RATE_LIMIT 1/0 — per-IP SYN rate-limit
  SYN_RATE              Per-IP лимит новых TCP-соед/сек (по умолч.: 100)
  ENABLE_CONN_LIMIT     1/0 — ограничить одновременные соединения
  CONN_LIMIT            Макс одновременных соединений с одного IP (по умолч.: 600)
  ENABLE_SSH_RATE_LIMIT 1/0 — отдельный SSH SYN rate-limit
  ENABLE_PORTSCAN_BAN   1/0 — эвристический автобан сканирования
  ENABLE_ICMP_RATE_LIMIT 1/0 — ICMP echo rate-limit
  ENABLE_FAIL2BAN       1/0 — установить Fail2Ban
  ENABLE_CROWDSEC       1/0 — установить CrowdSec (по умолч.: 0)
  CROWDSEC_ENROLL_KEY   Ключ из app.crowdsec.net (опционально)
  DRY_RUN               1 — показать правила без применения

  SAFETY_TIMER          Время на подтверждение (по умолч.: 180 секунд)

Примеры:
  sudo SSH_PORT=22 TCP_PORTS=443,2087 UDP_PORTS=443 \
       ENABLE_BAD_TCP_FLAGS=1 ENABLE_SYN_RATE_LIMIT=1 \
       WHITELIST="1.2.3.4" bash install.sh protect

  sudo DRY_RUN=1 ENABLE_BAD_TCP_FLAGS=1 bash install.sh protect
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

ask_experimental_params() {
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
    echo -e "  ${BOLD}Функции Experimental — каждая включается вручную:${NC}"

    yn "Отбрасывать некорректные TCP-флаги?" "$([[ ${ENABLE_BAD_TCP_FLAGS:-0} == 1 ]] && echo y || echo n)"
    PARAM_BAD_TCP_FLAGS="$YN"

    yn "Включить IPv4 anti-spoofing на WAN?" "$([[ ${ENABLE_ANTISPOOFING:-0} == 1 ]] && echo y || echo n)"
    PARAM_ANTISPOOFING="$YN"

    yn "Включить per-IP SYN rate-limit?" "$([[ ${ENABLE_SYN_RATE_LIMIT:-0} == 1 ]] && echo y || echo n)"
    PARAM_SYN_LIMIT="$YN"
    PARAM_SYN_RATE="${SYN_RATE:-100}"
    PARAM_SYN_BURST="${SYN_BURST:-200}"
    if [[ "$PARAM_SYN_LIMIT" == 1 ]]; then
        ask "SYN в секунду с одного IP, на порт" "$PARAM_SYN_RATE"; PARAM_SYN_RATE="$REPLY"
        ask "Допустимый SYN burst" "$PARAM_SYN_BURST"; PARAM_SYN_BURST="$REPLY"
    fi

    yn "Включить лимит одновременных TCP-соединений?" "$([[ ${ENABLE_CONN_LIMIT:-0} == 1 ]] && echo y || echo n)"
    PARAM_CONN_LIMIT_ENABLED="$YN"
    PARAM_CONN_LIMIT="${CONN_LIMIT:-600}"
    if [[ "$PARAM_CONN_LIMIT_ENABLED" == 1 ]]; then
        ask "Соединений с одного IP, на порт" "$PARAM_CONN_LIMIT"; PARAM_CONN_LIMIT="$REPLY"
    fi

    yn "Включить отдельный SSH rate-limit?" "$([[ ${ENABLE_SSH_RATE_LIMIT:-0} == 1 ]] && echo y || echo n)"
    PARAM_SSH_LIMIT="$YN"
    PARAM_SSH_RATE="${SSH_RATE:-6}"
    PARAM_SSH_BURST="${SSH_BURST:-4}"
    if [[ "$PARAM_SSH_LIMIT" == 1 ]]; then
        ask "SSH SYN с одного IP в минуту" "$PARAM_SSH_RATE"; PARAM_SSH_RATE="$REPLY"
        ask "Допустимый SSH burst" "$PARAM_SSH_BURST"; PARAM_SSH_BURST="$REPLY"
    fi

    yn "Включить эвристический portscan autoban?" "$([[ ${ENABLE_PORTSCAN_BAN:-0} == 1 ]] && echo y || echo n)"
    PARAM_PORTSCAN="$YN"
    PARAM_PORTSCAN_HITS="${PORTSCAN_HITS:-10}"
    PARAM_PORTSCAN_WINDOW="${PORTSCAN_WINDOW:-60}"
    PARAM_PORTSCAN_BAN_SECONDS="${PORTSCAN_BAN_SECONDS:-3600}"
    if [[ "$PARAM_PORTSCAN" == 1 ]]; then
        ask "Событий до бана" "$PARAM_PORTSCAN_HITS"; PARAM_PORTSCAN_HITS="$REPLY"
        ask "Окно подсчёта, секунд" "$PARAM_PORTSCAN_WINDOW"; PARAM_PORTSCAN_WINDOW="$REPLY"
        ask "Длительность бана, секунд" "$PARAM_PORTSCAN_BAN_SECONDS"; PARAM_PORTSCAN_BAN_SECONDS="$REPLY"
    fi

    yn "Ограничивать ICMP echo-request?" "$([[ ${ENABLE_ICMP_RATE_LIMIT:-0} == 1 ]] && echo y || echo n)"
    PARAM_ICMP_LIMIT="$YN"
    PARAM_ICMP_RATE="${ICMP_RATE:-5}"
    PARAM_ICMP_BURST="${ICMP_BURST:-10}"
    if [[ "$PARAM_ICMP_LIMIT" == 1 ]]; then
        ask "ICMP echo-request с одного IP в секунду" "$PARAM_ICMP_RATE"; PARAM_ICMP_RATE="$REPLY"
        ask "Допустимый ICMP burst" "$PARAM_ICMP_BURST"; PARAM_ICMP_BURST="$REPLY"
    fi

    yn "Установить Fail2Ban для SSH?" "$([[ ${ENABLE_FAIL2BAN:-0} == 1 ]] && echo y || echo n)"
    PARAM_FAIL2BAN="$YN"
    PARAM_F2B_MAXRETRY="${F2B_MAXRETRY:-5}"
    PARAM_F2B_FINDTIME="${F2B_FINDTIME:-300}"
    PARAM_F2B_BANTIME="${F2B_BANTIME:-86400}"
    if [[ "$PARAM_FAIL2BAN" == 1 ]]; then
        ask "Fail2Ban: попыток до бана" "$PARAM_F2B_MAXRETRY"; PARAM_F2B_MAXRETRY="$REPLY"
        ask "Fail2Ban: окно попыток, секунд" "$PARAM_F2B_FINDTIME"; PARAM_F2B_FINDTIME="$REPLY"
        ask "Fail2Ban: длительность бана, секунд" "$PARAM_F2B_BANTIME"; PARAM_F2B_BANTIME="$REPLY"
    fi

    yn "Установить CrowdSec (community blocklist + IPS)?" "$([[ ${ENABLE_CROWDSEC:-0} == 1 ]] && echo y || echo n)"
    PARAM_CROWDSEC="$YN"

    if [[ "$PARAM_CROWDSEC" == "1" ]]; then
        ask "CrowdSec enroll key (из app.crowdsec.net, или Enter чтобы пропустить)" ""
        PARAM_ENROLL_KEY="$REPLY"
    else
        PARAM_ENROLL_KEY=""
    fi

    if [[ "$PARAM_BAD_TCP_FLAGS$PARAM_ANTISPOOFING$PARAM_SYN_LIMIT$PARAM_CONN_LIMIT_ENABLED$PARAM_SSH_LIMIT$PARAM_PORTSCAN$PARAM_ICMP_LIMIT$PARAM_FAIL2BAN$PARAM_CROWDSEC" == 000000000 ]]; then
        warn "Experimental не применён: выберите хотя бы одну функцию."
        return 1
    fi

    ask "Время safety-таймера после применения, секунд" "${SAFETY_TIMER:-180}"
    PARAM_SAFETY_TIMER="$REPLY"

    yn "DRY RUN — только показать правила, не применять?" "$([[ ${DRY_RUN:-0} == 1 ]] && echo y || echo n)"
    PARAM_DRY_RUN="$YN"

    # Итоговый summary
    echo ""
    echo -e "  ┌─ ${BOLD}Итоговые параметры${NC} ─────────────────────────"
    echo -e "  │  SSH-порт:    ${CYAN}${PARAM_SSH_PORT}${NC}"
    echo -e "  │  TCP-порты:   ${CYAN}${PARAM_TCP_PORTS}${NC}"
    echo -e "  │  UDP-порты:   ${CYAN}${PARAM_UDP_PORTS}${NC}"
    echo -e "  │  Whitelist:   ${CYAN}${PARAM_WHITELIST:-не задан}${NC}"
    echo -e "  │  Bad flags:   ${CYAN}${PARAM_BAD_TCP_FLAGS}${NC}"
    echo -e "  │  Anti-spoof:  ${CYAN}${PARAM_ANTISPOOFING}${NC}"
    echo -e "  │  SYN limit:   ${CYAN}${PARAM_SYN_LIMIT}${NC} (${PARAM_SYN_RATE}/s, burst ${PARAM_SYN_BURST})"
    echo -e "  │  Connlimit:   ${CYAN}${PARAM_CONN_LIMIT_ENABLED}${NC} (${PARAM_CONN_LIMIT})"
    echo -e "  │  SSH limit:   ${CYAN}${PARAM_SSH_LIMIT}${NC} (${PARAM_SSH_RATE}/min, burst ${PARAM_SSH_BURST})"
    echo -e "  │  Portscan:    ${CYAN}${PARAM_PORTSCAN}${NC}"
    echo -e "  │  ICMP limit:  ${CYAN}${PARAM_ICMP_LIMIT}${NC} (${PARAM_ICMP_RATE}/s, burst ${PARAM_ICMP_BURST})"
    echo -e "  │  Fail2Ban:    ${CYAN}${PARAM_FAIL2BAN}${NC} (${PARAM_F2B_MAXRETRY}/${PARAM_F2B_FINDTIME}s/${PARAM_F2B_BANTIME}s)"
    echo -e "  │  CrowdSec:    ${CYAN}${PARAM_CROWDSEC}${NC}"
    echo -e "  │  Safety:      ${CYAN}${PARAM_SAFETY_TIMER}s${NC}"
    echo -e "  │  DRY RUN:     ${CYAN}${PARAM_DRY_RUN}${NC}"
    echo -e "  └──────────────────────────────────────────"
    echo ""

    yn "Всё верно, продолжить?" "y"
    if [[ "$YN" == "0" ]]; then
        info "Отменено. Запускай заново."
        return 1
    fi
}

run_experimental() {
    ask_experimental_params || return $?

    SSH_PORT="$PARAM_SSH_PORT" \
    TCP_PORTS="$PARAM_TCP_PORTS" \
    UDP_PORTS="$PARAM_UDP_PORTS" \
    WHITELIST="$PARAM_WHITELIST" \
    ENABLE_BAD_TCP_FLAGS="$PARAM_BAD_TCP_FLAGS" \
    ENABLE_ANTISPOOFING="$PARAM_ANTISPOOFING" \
    ENABLE_SYN_RATE_LIMIT="$PARAM_SYN_LIMIT" \
    SYN_RATE="$PARAM_SYN_RATE" SYN_BURST="$PARAM_SYN_BURST" \
    ENABLE_CONN_LIMIT="$PARAM_CONN_LIMIT_ENABLED" CONN_LIMIT="$PARAM_CONN_LIMIT" \
    ENABLE_SSH_RATE_LIMIT="$PARAM_SSH_LIMIT" \
    SSH_RATE="$PARAM_SSH_RATE" SSH_BURST="$PARAM_SSH_BURST" \
    ENABLE_PORTSCAN_BAN="$PARAM_PORTSCAN" \
    PORTSCAN_HITS="$PARAM_PORTSCAN_HITS" PORTSCAN_WINDOW="$PARAM_PORTSCAN_WINDOW" \
    PORTSCAN_BAN_SECONDS="$PARAM_PORTSCAN_BAN_SECONDS" \
    ENABLE_ICMP_RATE_LIMIT="$PARAM_ICMP_LIMIT" \
    ICMP_RATE="$PARAM_ICMP_RATE" ICMP_BURST="$PARAM_ICMP_BURST" \
    ENABLE_FAIL2BAN="$PARAM_FAIL2BAN" \
    F2B_MAXRETRY="$PARAM_F2B_MAXRETRY" F2B_FINDTIME="$PARAM_F2B_FINDTIME" F2B_BANTIME="$PARAM_F2B_BANTIME" \
    ENABLE_CROWDSEC="$PARAM_CROWDSEC" \
    CROWDSEC_ENROLL_KEY="$PARAM_ENROLL_KEY" \
    SAFETY_TIMER="$PARAM_SAFETY_TIMER" \
    DRY_RUN="$PARAM_DRY_RUN" \
    bash "${SCRIPT_DIR}/scripts/protect.sh"
}

run_basic() {
    local default_user server_address ssh_detected key_verified=0
    default_user="${SUDO_USER:-root}"
    ssh_detected=$(ss -tlnp 2>/dev/null \
        | awk '/sshd/{match($4,/[0-9]+$/); p=substr($4,RSTART,RLENGTH); if(p) print p}' \
        | head -1 || true)
    ssh_detected=${ssh_detected:-22}
    ask "SSH-пользователь" "${TARGET_USER:-$default_user}"
    PARAM_TARGET_USER="$REPLY"
    ask "SSH-порт" "${SSH_PORT:-$ssh_detected}"
    PARAM_SSH_PORT="$REPLY"

    yn "Добавить публичный SSH-ключ для ${PARAM_TARGET_USER}?" "n"
    if [[ "$YN" == 1 ]]; then
        echo -e "  ${BOLD}Вставьте публичный ключ одной строкой:${NC}"
        IFS= read -r PARAM_SSH_KEY
        if ! printf '%s\n' "$PARAM_SSH_KEY" | TARGET_USER="$PARAM_TARGET_USER" SSH_PORT="$PARAM_SSH_PORT" \
            bash "$SCRIPT_DIR/scripts/basic.sh" add-key; then
            err "SSH-ключ не добавлен; Basic остановлен."
        fi
        server_address=$(awk '{print $3}' <<< "${SSH_CONNECTION:-}")
        server_address="${server_address:-адрес-сервера}"
        [[ "$server_address" != *:* ]] || server_address="[$server_address]"
        echo ""
        warn "Молодой человек, пожалуйста, откройте ВТОРУЮ сессию строго через ключ:"
        echo "  ssh -o ControlMaster=no -o ControlPath=none \\"
        echo "      -o PreferredAuthentications=publickey -o PasswordAuthentication=no \\"
        echo "      -o KbdInteractiveAuthentication=no -p ${PARAM_SSH_PORT} ${PARAM_TARGET_USER}@${server_address}"
        echo ""
        yn "Вторая сессия успешно открылась без запроса пароля?" "n"
        key_verified="$YN"
    else
        yn "Вы уже проверили вход существующим ключом с PasswordAuthentication=no?" "n"
        key_verified="$YN"
    fi

    PARAM_DISABLE_PASSWORD=0
    if [[ "$key_verified" == 1 ]]; then
        warn "Это отключит парольную аутентификацию SSH для ВСЕХ пользователей."
        yn "Отключить парольный и keyboard-interactive вход SSH глобально?" "n"
        PARAM_DISABLE_PASSWORD="$YN"
    else
        warn "Парольный вход не будет отключён без подтверждённой проверки ключа."
    fi

    yn "Установить и настроить Fail2Ban?" "n"
    PARAM_FAIL2BAN="$YN"
    yn "Установить и настроить CrowdSec?" "n"
    PARAM_CROWDSEC="$YN"
    PARAM_ENROLL_KEY=""
    if [[ "$PARAM_CROWDSEC" == 1 ]]; then
        ask "CrowdSec enroll key (необязательно)" ""
        PARAM_ENROLL_KEY="$REPLY"
    fi

    if [[ "$PARAM_DISABLE_PASSWORD$PARAM_FAIL2BAN$PARAM_CROWDSEC" == 000 ]]; then
        ok "Basic завершён: дополнительных изменений не выбрано."
        return 0
    fi
    ask "Время safety-таймера, секунд" "${SAFETY_TIMER:-180}"
    PARAM_SAFETY_TIMER="$REPLY"
    echo ""
    warn "После применения потребуется ещё одна новая SSH-сессия и команда confirm."
    yn "Применить выбранные функции Basic?" "n"
    [[ "$YN" == 1 ]] || { info "Применение отменено; уже добавленный ключ сохранён."; return 0; }

    TARGET_USER="$PARAM_TARGET_USER" SSH_PORT="$PARAM_SSH_PORT" \
    DISABLE_SSH_PASSWORD="$PARAM_DISABLE_PASSWORD" \
    KEY_TEST_CONFIRMED="$key_verified" \
    ENABLE_FAIL2BAN="$PARAM_FAIL2BAN" ENABLE_CROWDSEC="$PARAM_CROWDSEC" \
    CROWDSEC_ENROLL_KEY="$PARAM_ENROLL_KEY" SAFETY_TIMER="$PARAM_SAFETY_TIMER" \
        bash "$SCRIPT_DIR/scripts/basic.sh" apply
}

show_protect_menu() {
    local choice
    echo ""
    echo -e "  ${BOLD}Режим Protect${NC}"
    echo "  1  Basic — SSH-ключ, пароль, Fail2Ban/CrowdSec"
    echo "  2  Experimental — ручная настройка сетевых фильтров"
    echo "  0  Назад"
    echo ""
    printf '  Выберите режим: '
    read -r choice
    case "$choice" in
        1) run_basic ;;
        2) run_experimental ;;
        0) return 0 ;;
        *) info "Неизвестный режим."; return 1 ;;
    esac
}

show_menu() {
    local choice
    while true; do
        show_banner
        printf '  %b1%b  Protect — Basic / Experimental\n' "$BOLD" "$NC"
        printf '  %b2%b  Проверить статус\n' "$BOLD" "$NC"
        printf '  %b3%b  Удалить защиту\n' "$BOLD" "$NC"
        printf '  %b4%b  Обновить скрипт\n' "$BOLD" "$NC"
        printf '  %b5%b  Подтвердить применение\n' "$BOLD" "$NC"
        printf '\n  %b0%b  Выйти\n\n' "$BOLD" "$NC"
        printf '  Выберите действие: '
        read -r choice || return 0
        case "$choice" in
            1) show_protect_menu || info "Настройка не завершена." ;;
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
    --configure) run_experimental ;;
    basic)
        if [[ -z ${2:-} ]]; then run_basic; else bash "${SCRIPT_DIR}/scripts/basic.sh" "${@:2}"; fi
        ;;
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
