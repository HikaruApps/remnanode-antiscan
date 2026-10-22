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
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
if [[ ! -t 1 || -n ${NO_COLOR:-} ]]; then
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' DIM='' NC=''
fi

err()    { echo -e "${RED}[✘]${NC} $*" >&2; exit 1; }
info()   { echo -e "${CYAN}[*]${NC} $*"; }
ok()     { echo -e "${GREEN}[✔]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
prompt() { echo -e "${BOLD}$*${NC}"; }

[[ $EUID -ne 0 ]] && err "Нужен root: sudo bash $0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Paths of managed files and recover_ssh_connection (sudo may drop SSH_CONNECTION).
source "$SCRIPT_DIR/scripts/state.sh"
recover_ssh_connection

show_help() {
    cat << 'HELP'
RemnaNode AntiScan — защита ноды поверх UFW

Использование:
  sudo bash install.sh [команда]

Команды:
  basic      Basic: SSH-ключ, безопасное отключение пароля, Fail2Ban/CrowdSec
  protect    Experimental: настраиваемые firewall-правила + Fail2Ban/CrowdSec
  tuning     Дополнительные настройки: BBR + CAKE и состояние IPv6
  rkn        Блокировка подсетей РКН: rkn [apply|update|disable|status]
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
  F2B_MAXRETRY/FINDTIME/BANTIME  Параметры SSH jail (5/300/86400 секунд)

ENV для команды protect (Experimental):
  SSH_PORT              Порт SSH (авто-детект если не задан)
  TCP_PORTS             Сервисные TCP-порты через запятую (в меню — из UFW, иначе 443)
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
  PORTSCAN_SKIP_PORT_CHECK 1 — не сверять разрешённые порты UFW со списками
  ENABLE_ICMP_RATE_LIMIT 1/0 — ICMP echo rate-limit
  ENABLE_FAIL2BAN       1/0 — установить Fail2Ban
  ENABLE_CROWDSEC       1/0 — установить CrowdSec (по умолч.: 0)
  CROWDSEC_ENROLL_KEY   Ключ из app.crowdsec.net (опционально)
  DRY_RUN               1 — показать правила без применения

ENV для команды rkn apply:
  RKN_URLS              HTTPS-списки подсетей через пробел (по умолч.: notacircle/greatlists gn + sn)
  WHITELIST             IP/CIDR через запятую — никогда не блокируются
  RKN_BLOCK_SSH         1 — блокировать и SSH-порт (по умолч.: 0, SSH исключён)
  RKN_INTERVAL          Период обновления: 30min, 6h, 1d (по умолч.: 6h)

ENV для команды tuning apply:
  ENABLE_BBR_CAKE       1 — включить BBR + CAKE; 0 — не менять
  IPV6_MODE             keep/enable/disable — не менять, включить или отключить IPv6

  SAFETY_TIMER          Время на подтверждение (по умолч.: 180 секунд)

Примеры:
  sudo SSH_PORT=22 TCP_PORTS=443 UDP_PORTS=443 \
       ENABLE_BAD_TCP_FLAGS=1 ENABLE_SYN_RATE_LIMIT=1 \
       WHITELIST="1.2.3.4" bash install.sh protect

  sudo DRY_RUN=1 ENABLE_BAD_TCP_FLAGS=1 bash install.sh protect
  sudo ENABLE_BBR_CAKE=1 IPV6_MODE=keep bash install.sh tuning apply
  sudo bash install.sh confirm
HELP
}

# "✔ name" when enabled, dimmed "– name" otherwise.
feature_mark() {
    if [[ "$2" == 1 ]]; then
        printf '%b✔%b %s' "$GREEN" "$NC" "$1"
    else
        printf '%b– %s%b' "$DIM" "$1" "$NC"
    fi
}

show_banner() {
    local basic=0 experimental=0 rkn=0 bbr=0 left
    printf '\n  %bRemnaNode AntiScan%b\n' "$BOLD$CYAN" "$NC"
    [[ ! -f "$SSH_DROPIN" ]] || basic=1
    ! grep -q 'UFW-ANTISCAN START' /etc/ufw/before.rules 2>/dev/null || experimental=1
    [[ ! -f "$RKN_CONF" ]] || rkn=1
    [[ ! -f "$TUNING_BBR_SYSCTL" ]] || bbr=1
    printf '  %s · %s · %s · %s\n' "$(feature_mark Basic "$basic")" \
        "$(feature_mark Experimental "$experimental")" "$(feature_mark РКН "$rkn")" \
        "$(feature_mark BBR "$bbr")"
    if [[ -f "$PENDING" ]]; then
        left=$(( $(cat "$SAFETY_DEADLINE" 2>/dev/null || echo 0) - $(date +%s) ))
        if (( left > 0 )); then
            printf '  %bОжидается подтверждение: автооткат через %d:%02d — пункт 6 из НОВОЙ сессии%b\n' \
                "$YELLOW" $((left / 60)) $((left % 60)) "$NC"
        else
            printf '  %bОжидается подтверждение — автооткат включён%b\n' "$YELLOW" "$NC"
        fi
    fi
    printf '\n'
}

# Читает ввод с дефолтом: ask "Вопрос" "дефолт" → результат в $REPLY
ask() {
    local question="$1"
    local default="$2"
    echo -ne "  ${BOLD}${question}${NC} [${CYAN}${default}${NC}]: "
    read -r REPLY || input_closed
    REPLY="${REPLY:-$default}"
}

# Ctrl+D or a closed pipe: stop instead of silently taking the default answer.
input_closed() {
    echo ""
    info "Ввод закрыт — выход без изменений."
    exit 1
}

yes_no() { [[ "$1" == 1 ]] && echo "вкл" || echo "выкл"; }

# Ports UFW allows for one protocol, without SSH: "tcp" or "udp", SSH port.
ufw_service_ports() {
    LC_ALL=C ufw status 2>/dev/null | python3 -c '
import re
import sys

proto, ssh = sys.argv[1:3]
spec = re.compile(r"^(\d+(?:,\d+)*)(?:/(tcp|udp))?$")
ports = []
for line in sys.stdin:
    match = re.match(r"^(.*?)\s+(ALLOW|LIMIT)(\s+(?:IN|OUT|FWD))?\s+", line)
    if not match or (match.group(3) or "").strip() in ("OUT", "FWD"):
        continue
    for token in re.sub(r"\(v6\)|\bon \S+", " ", match.group(1)).split():
        found = spec.match(token)
        if found and found.group(2) in (None, proto):
            ports += [p for p in found.group(1).split(",") if p != ssh and p not in ports]
print(",".join(ports))
' "$1" "$2" 2>/dev/null || true
}

# Да/нет: yn "Вопрос" "y" → 1 или 0 в $YN
yn() {
    local question="$1"
    local default="${2:-y}"
    local hint; [[ "$default" == "y" ]] && hint="Y/n" || hint="y/N"
    echo -ne "  ${BOLD}${question}${NC} [${CYAN}${hint}${NC}]: "
    read -r REPLY || input_closed
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

    # Suggest the ports UFW already allows; fall back to 443 without rules.
    local ufw_tcp ufw_udp
    ufw_tcp=$(ufw_service_ports tcp "$PARAM_SSH_PORT")
    ufw_udp=$(ufw_service_ports udp "$PARAM_SSH_PORT")
    if [[ -z "$ufw_tcp$ufw_udp" ]]; then
        ufw_tcp=443 ufw_udp=443
    else
        echo -e "  ${CYAN}Порты ниже взяты из правил UFW.${NC}"
    fi
    ask "TCP-порты сервиса (через запятую)" "${TCP_PORTS:-$ufw_tcp}"
    PARAM_TCP_PORTS="$REPLY"

    ask "UDP-порты сервиса (через запятую, - без UDP)" "${UDP_PORTS-$ufw_udp}"
    PARAM_UDP_PORTS="$REPLY"
    [[ "$PARAM_UDP_PORTS" != - ]] || PARAM_UDP_PORTS=""

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
    # Labels carry their own padding: printf widths count bytes, not Cyrillic letters.
    summary_row() { echo -e "  │  $1 ${CYAN}$2${NC}${3:+ ($3)}"; }
    # Feature row: parameters are shown only when the feature is enabled.
    feature_row() { summary_row "$1" "$(yes_no "$2")" "$([[ "$2" == 1 ]] && echo "${3:-}")"; }
    summary_row "SSH-порт:   " "$PARAM_SSH_PORT"
    summary_row "TCP-порты:  " "${PARAM_TCP_PORTS:-нет}"
    summary_row "UDP-порты:  " "${PARAM_UDP_PORTS:-нет}"
    summary_row "Whitelist:  " "${PARAM_WHITELIST:-не задан}"
    feature_row "Bad flags:  " "$PARAM_BAD_TCP_FLAGS"
    feature_row "Anti-spoof: " "$PARAM_ANTISPOOFING"
    feature_row "SYN limit:  " "$PARAM_SYN_LIMIT" "${PARAM_SYN_RATE}/с, burst ${PARAM_SYN_BURST}"
    feature_row "Connlimit:  " "$PARAM_CONN_LIMIT_ENABLED" "${PARAM_CONN_LIMIT} соединений"
    feature_row "SSH limit:  " "$PARAM_SSH_LIMIT" "${PARAM_SSH_RATE}/мин, burst ${PARAM_SSH_BURST}"
    feature_row "Portscan:   " "$PARAM_PORTSCAN" \
        "${PARAM_PORTSCAN_HITS} событий за ${PARAM_PORTSCAN_WINDOW}с, бан ${PARAM_PORTSCAN_BAN_SECONDS}с"
    feature_row "ICMP limit: " "$PARAM_ICMP_LIMIT" "${PARAM_ICMP_RATE}/с, burst ${PARAM_ICMP_BURST}"
    feature_row "Fail2Ban:   " "$PARAM_FAIL2BAN" \
        "${PARAM_F2B_MAXRETRY} попыток за ${PARAM_F2B_FINDTIME}с, бан ${PARAM_F2B_BANTIME}с"
    feature_row "CrowdSec:   " "$PARAM_CROWDSEC"
    summary_row "Safety:     " "${PARAM_SAFETY_TIMER}с"
    summary_row "DRY RUN:    " "$(yes_no "$PARAM_DRY_RUN")"
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
    local default_user server_address ssh_detected key_verified=0 key_added=0
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
            warn "SSH-ключ не добавлен; Basic остановлен."
            return 1
        fi
        key_added=1
        server_address=$(awk '{print $3}' <<< "${SSH_CONNECTION:-}")
        server_address="${server_address:-адрес-сервера}"
        [[ "$server_address" != *:* ]] || server_address="[$server_address]"
        echo ""
        warn "Не закрывая эту сессию, откройте ВТОРУЮ — строго по ключу:"
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
    echo -e "  ┌─ ${BOLD}Итоговые параметры${NC} ─────────────────────────"
    echo -e "  │  Пользователь:   ${CYAN}${PARAM_TARGET_USER}${NC}, SSH-порт ${CYAN}${PARAM_SSH_PORT}${NC}"
    echo -e "  │  Пароль SSH:     ${CYAN}$([[ $PARAM_DISABLE_PASSWORD == 1 ]] && echo "отключить для всех" || echo "не менять")${NC}"
    echo -e "  │  Fail2Ban:       ${CYAN}$(yes_no "$PARAM_FAIL2BAN")${NC}"
    echo -e "  │  CrowdSec:       ${CYAN}$(yes_no "$PARAM_CROWDSEC")${NC}"
    echo -e "  │  Safety:         ${CYAN}${PARAM_SAFETY_TIMER}с${NC}"
    echo -e "  └──────────────────────────────────────────"
    echo ""
    warn "После применения потребуется ещё одна новая SSH-сессия и команда confirm."
    yn "Применить выбранные функции Basic?" "n"
    if [[ "$YN" != 1 ]]; then
        info "Применение отменено.$([[ $key_added == 1 ]] && echo ' Добавленный ключ остаётся в authorized_keys.')"
        return 0
    fi

    TARGET_USER="$PARAM_TARGET_USER" SSH_PORT="$PARAM_SSH_PORT" \
    DISABLE_SSH_PASSWORD="$PARAM_DISABLE_PASSWORD" \
    KEY_TEST_CONFIRMED="$key_verified" \
    ENABLE_FAIL2BAN="$PARAM_FAIL2BAN" ENABLE_CROWDSEC="$PARAM_CROWDSEC" \
    CROWDSEC_ENROLL_KEY="$PARAM_ENROLL_KEY" SAFETY_TIMER="$PARAM_SAFETY_TIMER" \
        bash "$SCRIPT_DIR/scripts/basic.sh" apply
}

run_tuning() {
    local ipv6_default ipv6_choice current_cc current_qdisc current_ipv6
    echo ""
    echo -e "  ${BOLD}Дополнительные настройки${NC}"
    echo -e "  ${YELLOW}Каждая функция применяется только после явного выбора.${NC}"
    echo ""

    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')
    current_ipv6=$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo '?')
    [[ "$current_ipv6" != 0 ]] || current_ipv6="включён"
    [[ "$current_ipv6" != 1 ]] || current_ipv6="отключён"
    echo "  Сейчас: TCP=${current_cc}, default qdisc=${current_qdisc}, IPv6=${current_ipv6}"
    echo ""

    yn "Включить BBR + CAKE?" "$([[ ${ENABLE_BBR_CAKE:-0} == 1 ]] && echo y || echo n)"
    PARAM_BBR_CAKE="$YN"
    if [[ "$PARAM_BBR_CAKE" == 1 ]]; then
        warn "CAKE станет default qdisc; активный интерфейс подхватит его после reboot или пересоздания."
    fi

    case "${IPV6_MODE:-keep}" in
        enable) ipv6_default=1 ;;
        disable) ipv6_default=2 ;;
        *) ipv6_default=0 ;;
    esac
    echo ""
    echo "  IPv6: 0 — не менять, 1 — включить, 2 — отключить"
    ask "Действие с IPv6" "$ipv6_default"
    ipv6_choice="$REPLY"
    case "$ipv6_choice" in
        0) PARAM_IPV6_MODE=keep ;;
        1) PARAM_IPV6_MODE=enable ;;
        2) PARAM_IPV6_MODE=disable ;;
        *) warn "Введите 0, 1 или 2."; return 1 ;;
    esac
    if [[ "$PARAM_IPV6_MODE" == disable ]]; then
        warn "Отключение IPv6 удалит IPv6-адреса и маршруты со всех интерфейсов."
        warn "Из текущей SSH-сессии по IPv6 это действие будет запрещено."
    fi

    if [[ "$PARAM_BBR_CAKE" == 0 && "$PARAM_IPV6_MODE" == keep ]]; then
        ok "Дополнительные настройки не изменены."
        return 0
    fi

    ask "Время safety-таймера, секунд" "${SAFETY_TIMER:-180}"
    PARAM_SAFETY_TIMER="$REPLY"
    echo ""
    echo -e "  ┌─ ${BOLD}Итоговые параметры${NC} ─────────────────────────"
    echo -e "  │  BBR + CAKE: ${CYAN}${PARAM_BBR_CAKE}${NC}"
    echo -e "  │  IPv6:       ${CYAN}${PARAM_IPV6_MODE}${NC}"
    echo -e "  │  Safety:     ${CYAN}${PARAM_SAFETY_TIMER}s${NC}"
    echo -e "  └──────────────────────────────────────────"
    echo ""
    yn "Применить дополнительные настройки?" "n"
    [[ "$YN" == 1 ]] || { info "Применение отменено."; return 0; }

    ENABLE_BBR_CAKE="$PARAM_BBR_CAKE" IPV6_MODE="$PARAM_IPV6_MODE" \
    SAFETY_TIMER="$PARAM_SAFETY_TIMER" bash "$SCRIPT_DIR/scripts/tuning.sh" apply
}

run_rkn() {
    local choice
    echo ""
    echo -e "  ${BOLD}Блокировка подсетей РКН${NC}"
    bash "$SCRIPT_DIR/scripts/rkn.sh" status
    echo ""
    echo "  1  Включить / перенастроить"
    echo "  2  Обновить списки сейчас"
    echo "  3  Отключить"
    echo "  0  Назад"
    echo ""
    printf '  Выберите действие: '
    read -r choice
    case "$choice" in
        1) ;;
        2) bash "$SCRIPT_DIR/scripts/rkn.sh" update; return ;;
        3)
            yn "Отключить блокировку подсетей РКН?" "n"
            [[ "$YN" == 1 ]] || return 0
            bash "$SCRIPT_DIR/scripts/rkn.sh" disable
            return
            ;;
        0) return 0 ;;
        *) info "Неизвестное действие."; return 1 ;;
    esac

    # Current settings (or defaults) so that Enter keeps what is configured.
    local key value cur_urls="" cur_whitelist="" cur_ssh_port="" cur_block_ssh=0 cur_interval=""
    while IFS='=' read -r key value; do
        case "$key" in
            URLS) cur_urls=$value ;;
            WHITELIST) cur_whitelist=$value ;;
            SSH_PORT) cur_ssh_port=$value ;;
            BLOCK_SSH) cur_block_ssh=$value ;;
            INTERVAL) cur_interval=$value ;;
        esac
    done < <(bash "$SCRIPT_DIR/scripts/rkn.sh" config 2>/dev/null || true)
    echo ""
    echo -e "  ${YELLOW}Входящие соединения из подсетей списка будут отбрасываться на всех портах.${NC}"
    echo -e "  ${YELLOW}Ответы на исходящие соединения ноды и уже открытые сессии не затрагиваются.${NC}"
    echo -e "  ${YELLOW}Enter — оставить текущее значение.${NC}"
    echo ""
    ask "URL списков (через пробел)" "$cur_urls"
    PARAM_RKN_URLS="$REPLY"
    ask "Whitelist IP/CIDR через запятую (- очистить)" "$cur_whitelist"
    PARAM_WHITELIST="$REPLY"
    [[ "$PARAM_WHITELIST" != - ]] || PARAM_WHITELIST=""
    ask "SSH-порт" "${cur_ssh_port:-22}"
    PARAM_SSH_PORT="$REPLY"
    yn "Блокировать подсети и на SSH-порту? (риск потерять доступ)" "$([[ $cur_block_ssh == 1 ]] && echo y || echo n)"
    PARAM_RKN_BLOCK_SSH="$YN"
    ask "Период обновления (30min / 6h / 1d)" "${cur_interval:-6h}"
    PARAM_RKN_INTERVAL="$REPLY"
    ask "Время safety-таймера, секунд" "${SAFETY_TIMER:-180}"
    PARAM_SAFETY_TIMER="$REPLY"
    echo ""
    yn "Применить блокировку подсетей РКН?" "n"
    [[ "$YN" == 1 ]] || { info "Применение отменено."; return 0; }

    RKN_URLS="$PARAM_RKN_URLS" WHITELIST="$PARAM_WHITELIST" SSH_PORT="$PARAM_SSH_PORT" \
    RKN_BLOCK_SSH="$PARAM_RKN_BLOCK_SSH" RKN_INTERVAL="$PARAM_RKN_INTERVAL" \
    SAFETY_TIMER="$PARAM_SAFETY_TIMER" bash "$SCRIPT_DIR/scripts/rkn.sh" apply
}

show_protect_menu() {
    local choice
    echo ""
    echo -e "  ${BOLD}Режим Protect${NC}"
    echo "  1  Basic — SSH-ключ, пароль, Fail2Ban/CrowdSec"
    echo "  2  Experimental — ручная настройка сетевых фильтров"
    echo "  3  Блокировка РКН — авто-обновляемые подсети"
    echo "  0  Назад"
    echo ""
    printf '  Выберите режим: '
    read -r choice
    case "$choice" in
        1) run_basic ;;
        2) run_experimental ;;
        3) run_rkn ;;
        0) return 0 ;;
        *) info "Неизвестный режим."; return 1 ;;
    esac
}

show_menu() {
    local choice
    while true; do
        show_banner
        printf '  %b1%b  Protect — Basic / Experimental\n' "$BOLD" "$NC"
        printf '  %b2%b  Доп. настройки — BBR + CAKE / IPv6\n' "$BOLD" "$NC"
        printf '  %b3%b  Проверить статус\n' "$BOLD" "$NC"
        printf '  %b4%b  Удалить защиту\n' "$BOLD" "$NC"
        printf '  %b5%b  Обновить скрипт\n' "$BOLD" "$NC"
        printf '  %b6%b  Подтвердить применение\n' "$BOLD" "$NC"
        printf '\n  %b0%b  Выйти\n\n' "$BOLD" "$NC"
        printf '  Выберите действие: '
        read -r choice || return 0
        case "$choice" in
            1) show_protect_menu || info "Настройка не завершена." ;;
            2) run_tuning || info "Дополнительные настройки не завершены." ;;
            3) bash "$SCRIPT_DIR/scripts/status.sh" || info "Не удалось получить полный статус." ;;
            4)
                printf '  Удалить защиту? [y/N]: '
                read -r choice || return 0
                if [[ "${choice,,}" == y ]]; then
                    bash "$SCRIPT_DIR/scripts/rollback.sh" || info "Удаление не завершено."
                fi
                ;;
            5)
                if bash "$SCRIPT_DIR/scripts/update.sh"; then
                    cd "$SCRIPT_DIR"
                    exec bash "$SCRIPT_DIR/install.sh"
                else
                    info "Обновление не выполнено."
                fi
                ;;
            6) bash "$SCRIPT_DIR/scripts/confirm.sh" || info "Применение не подтверждено." ;;
            0|q|Q) printf '\n  До встречи :3\n'; return 0 ;;
            *) info "Введите номер от 0 до 6."; continue ;;
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
    tuning)
        if [[ -z ${2:-} ]]; then run_tuning; else bash "${SCRIPT_DIR}/scripts/tuning.sh" "${@:2}"; fi
        ;;
    rkn)
        if [[ -z ${2:-} ]]; then run_rkn; else bash "${SCRIPT_DIR}/scripts/rkn.sh" "${@:2}"; fi
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
