#!/bin/bash
# ufw-antiscan/scripts/protect.sh
# AntiScan + flag-drop + rate-limit + CrowdSec поверх UFW
#
# Совместим с Docker (network_mode: host) и Remnawave-нодами
# Поддержка: Debian 11/12/13, Ubuntu 20.04–24.04
#
# Использование:
#   sudo bash scripts/protect.sh
#   sudo DRY_RUN=1 bash scripts/protect.sh          # посмотреть без применения
#   sudo ENABLE_BAD_TCP_FLAGS=1 bash scripts/protect.sh
#
# ENV-переменные: см. README.md

set -Eeuo pipefail
export LC_ALL=C
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/state.sh"

# ── Цвета ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[✔]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✘]${NC} $*" >&2; return 1; }
dry()     { echo -e "${YELLOW}[DRY]${NC} $*"; }
section() { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

# ── Help ──────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << 'HELP'
ufw-antiscan — защита от сканеров и флуда поверх UFW

Использование:
  sudo bash scripts/protect.sh [опции]

Опции:
  --help, -h     Показать эту справку
  --dry-run      Сгенерировать правила и показать, не применяя (то же что DRY_RUN=1)

ENV-переменные:
  SSH_PORT                  Порт SSH (по умолчанию: авто-детект)
  TCP_PORTS                 Сервисные TCP-порты через запятую (по умолчанию: 443,2087)
  UDP_PORTS                 Сервисные UDP-порты через запятую (по умолчанию: 443)
  WHITELIST                 IP/CIDR через запятую — никогда не блокируются
  ENABLE_BAD_TCP_FLAGS      1/0 — отбрасывать некорректные TCP-флаги (0)
  ENABLE_ANTISPOOFING       1/0 — IPv4 bogon-фильтр на WAN (0)
  ENABLE_SYN_RATE_LIMIT     1/0 — включить SYN rate-limit (0)
  SYN_RATE / SYN_BURST      Per-IP лимит новых TCP-соед/сек (по умолчанию: 100/200)
  ENABLE_CONN_LIMIT         1/0 — включить connlimit (0)
  CONN_LIMIT                Макс одновременных соединений с одного IP (по умолчанию: 600)
  ENABLE_SSH_RATE_LIMIT     1/0 — включить отдельный SSH rate-limit (0)
  SSH_RATE / SSH_BURST      Лимит новых SSH-соед/мин до бана (по умолчанию: 6/4)
  PORTSCAN_BAN_SECONDS      Время бана за сканирование в секундах (по умолчанию: 3600)
  ENABLE_PORTSCAN_BAN       1/0 — включить portscan autoban (по умолчанию: 0)
  PORTSCAN_HITS/WINDOW      Порог событий / окно в секундах (10 / 60)
  ENABLE_ICMP_RATE_LIMIT    1/0 — ограничивать ICMP echo-request (0)
  ICMP_RATE / ICMP_BURST    Лимит echo-request с IP в секунду (5/10)
  SAFETY_TIMER             Время на подтверждение из нового SSH (180 секунд)
  ENABLE_CROWDSEC           1/0 — установить CrowdSec (по умолчанию: 0)
  CROWDSEC_ENROLL_KEY       Ключ из app.crowdsec.net (опционально)
  ENABLE_FAIL2BAN           1/0 — установить/настроить Fail2Ban (по умолчанию: 0)
  F2B_MAXRETRY/FINDTIME/BANTIME Параметры SSH jail (5/300/86400 секунд)
  DRY_RUN                   1/0 — только показать правила, не применять

Примеры:
  # Remnawave-нода
  sudo SSH_PORT=22 TCP_PORTS=443,2087 UDP_PORTS=443 \
       ENABLE_BAD_TCP_FLAGS=1 ENABLE_SYN_RATE_LIMIT=1 \
       WHITELIST="1.2.3.4" bash scripts/protect.sh

  # Посмотреть что будет без применения
  sudo DRY_RUN=1 ENABLE_BAD_TCP_FLAGS=1 bash scripts/protect.sh

HELP
    exit 0
fi

# ── Параметры ─────────────────────────────────────────────────────────────────
case "${1:-}" in
    "") ;;
    --dry-run) export DRY_RUN=1 ;;
    *) err "Unknown argument: $1" ;;
esac
[[ $# -le 1 ]] || err "Too many arguments"

DRY_RUN="${DRY_RUN:-0}"

SSH_PORT="${SSH_PORT:-$(ss -tlnp 2>/dev/null \
    | awk '/sshd/{match($4,/[0-9]+$/); p=substr($4,RSTART,RLENGTH); if(p) print p}' \
    | head -1 || true)}"
SSH_PORT="${SSH_PORT:-22}"

TCP_PORTS="${TCP_PORTS:-443,2087}"
UDP_PORTS="${UDP_PORTS-443}"

SYN_RATE="${SYN_RATE:-100}"
SYN_BURST="${SYN_BURST:-200}"
CONN_LIMIT="${CONN_LIMIT:-600}"
ENABLE_BAD_TCP_FLAGS="${ENABLE_BAD_TCP_FLAGS:-0}"
ENABLE_SYN_RATE_LIMIT="${ENABLE_SYN_RATE_LIMIT:-0}"
ENABLE_CONN_LIMIT="${ENABLE_CONN_LIMIT:-0}"

SSH_RATE="${SSH_RATE:-6}"
SSH_BURST="${SSH_BURST:-4}"
ENABLE_SSH_RATE_LIMIT="${ENABLE_SSH_RATE_LIMIT:-0}"

PORTSCAN_BAN_SECONDS="${PORTSCAN_BAN_SECONDS:-3600}"
ENABLE_PORTSCAN_BAN="${ENABLE_PORTSCAN_BAN:-0}"
PORTSCAN_HITS="${PORTSCAN_HITS:-10}"
PORTSCAN_WINDOW="${PORTSCAN_WINDOW:-60}"
ENABLE_ICMP_RATE_LIMIT="${ENABLE_ICMP_RATE_LIMIT:-0}"
ICMP_RATE="${ICMP_RATE:-5}"
ICMP_BURST="${ICMP_BURST:-10}"

WHITELIST="${WHITELIST:-}"

# Safety timer: автоматический откат если что-то пошло не так (секунд)
SAFETY_TIMER="${SAFETY_TIMER:-180}"

ENABLE_CROWDSEC="${ENABLE_CROWDSEC:-0}"
CROWDSEC_ENROLL_KEY="${CROWDSEC_ENROLL_KEY:-}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-0}"
F2B_MAXRETRY="${F2B_MAXRETRY:-5}"
F2B_FINDTIME="${F2B_FINDTIME:-300}"
F2B_BANTIME="${F2B_BANTIME:-86400}"

MARKER_START="# === UFW-ANTISCAN START ==="
MARKER_END="# === UFW-ANTISCAN END ==="

BACKUP_DIR=""

# ── Проверки ──────────────────────────────────────────────────────────────────
section "Проверка окружения"

[[ $EUID -ne 0 ]] && err "Нужен root: sudo bash $0"
command -v ufw      &>/dev/null || err "ufw не установлен. Установи: apt install ufw"
command -v iptables &>/dev/null || err "iptables не найден"
command -v iptables-restore &>/dev/null || err "iptables-restore не найден"
command -v python3  &>/dev/null || err "python3 не найден. Установи: apt install python3"
if [[ "$ENABLE_CROWDSEC" == 1 ]]; then
    command -v curl >/dev/null || err "curl is required: apt install curl"
fi

# Проверка поддерживаемой ОС
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in
        debian)
            [[ "${VERSION_ID:-0}" -lt 11 ]] && \
                warn "Debian ${VERSION_ID} не тестировался, рекомендуется 11+"
            ;;
        ubuntu)
            # Поддерживаем 20.04+
            VER_MAJOR=$(echo "${VERSION_ID:-0}" | cut -d. -f1)
            [[ "$VER_MAJOR" -lt 20 ]] && \
                warn "Ubuntu ${VERSION_ID} не тестировалась, рекомендуется 20.04+"
            ;;
        *)
            warn "ОС '${ID:-unknown}' не тестировалась. Продолжаю, но возможны проблемы."
            ;;
    esac
fi

UFW_STATUS=$(ufw status 2>/dev/null | head -1 || true)
[[ "$UFW_STATUS" != "Status: active" ]] && \
    warn "UFW сейчас неактивен — правила применятся после: sudo ufw enable"

WAN_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1 || true)
[[ -z "$WAN_IFACE" ]] && warn "WAN-интерфейс не определён — anti-spoofing будет отключён"

# Авто-детект: если у сервера приватный IP (VPS за NAT) — anti-spoofing опасен
MY_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1 || true)
ENABLE_ANTISPOOFING="${ENABLE_ANTISPOOFING:-0}"
[[ -n "$WAN_IFACE" ]] || ENABLE_ANTISPOOFING=0
if [[ "${ENABLE_ANTISPOOFING}" == "1" && -n "$MY_IP" ]]; then
    if [[ "$MY_IP" =~ ^10\. ||           "$MY_IP" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ||           "$MY_IP" =~ ^192\.168\. ||           "$MY_IP" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]]; then
        warn "Обнаружен приватный IP сервера (${MY_IP}) — anti-spoofing ОТКЛЮЧЁН"
        warn "Сервер за NAT: RFC1918-правила заблокируют легитимный трафик"
        ENABLE_ANTISPOOFING=0
    fi
fi

# Проверка hashlimit только когда он действительно выбран.
if [[ "$ENABLE_SYN_RATE_LIMIT" == 1 || "$ENABLE_SSH_RATE_LIMIT" == 1 || "$ENABLE_ICMP_RATE_LIMIT" == 1 ]] \
    && ! iptables -m hashlimit --help &>/dev/null 2>&1; then
    err "Модуль iptables hashlimit недоступен"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    warn "Режим DRY RUN — правила будут показаны, но НЕ применены"
fi

info "SSH-порт:  ${SSH_PORT}"
info "WAN:       ${WAN_IFACE:-любой интерфейс}"
info "TCP-порты: ${TCP_PORTS}"
info "UDP-порты: ${UDP_PORTS}"
info "Whitelist: ${WHITELIST:-не задан}"
info "Bad flags: ${ENABLE_BAD_TCP_FLAGS}"
info "Anti-spoof: ${ENABLE_ANTISPOOFING} (IP сервера: ${MY_IP:-неизвестен})"
info "SYN limit: ${ENABLE_SYN_RATE_LIMIT}"
info "Connlimit: ${ENABLE_CONN_LIMIT}"
info "SSH limit: ${ENABLE_SSH_RATE_LIMIT}"
info "Portscan: ${ENABLE_PORTSCAN_BAN}"
info "ICMP limit: ${ENABLE_ICMP_RATE_LIMIT}"
info "Fail2Ban: ${ENABLE_FAIL2BAN}"
info "CrowdSec:  ${ENABLE_CROWDSEC}"
info "DRY RUN:   ${DRY_RUN}"

# Validate input before any filesystem or service changes.
python3 - "$SSH_PORT" "$TCP_PORTS" "$UDP_PORTS" "$WHITELIST" \
    "$SYN_RATE" "$SYN_BURST" "$CONN_LIMIT" "$SSH_RATE" "$SSH_BURST" \
    "$PORTSCAN_BAN_SECONDS" "$PORTSCAN_HITS" "$PORTSCAN_WINDOW" "$SAFETY_TIMER" \
    "$ICMP_RATE" "$ICMP_BURST" "$F2B_MAXRETRY" "$F2B_FINDTIME" "$F2B_BANTIME" \
    "$DRY_RUN" "$ENABLE_CROWDSEC" "$ENABLE_PORTSCAN_BAN" "$ENABLE_ANTISPOOFING" \
    "$ENABLE_BAD_TCP_FLAGS" "$ENABLE_SYN_RATE_LIMIT" "$ENABLE_CONN_LIMIT" \
    "$ENABLE_SSH_RATE_LIMIT" "$ENABLE_ICMP_RATE_LIMIT" "$ENABLE_FAIL2BAN" <<'VALIDATE'
import ipaddress
import sys
ssh, tcp, udp, whitelist = sys.argv[1:5]
for ports in (ssh, tcp, udp):
    if ports:
        for port in ports.split(','):
            if not port.strip().isascii() or not port.strip().isdigit() or not 1 <= int(port) <= 65535:
                raise SystemExit('Invalid port: ' + repr(port))
if ',' in ssh or not ssh:
    raise SystemExit('SSH_PORT must be one port')
for entry in filter(None, whitelist.split(',')):
    ipaddress.ip_network(entry.strip(), strict=False)
for value in sys.argv[5:19]:
    if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 2147483647:
        raise SystemExit('Limits and SAFETY_TIMER must be positive integers')
for value in sys.argv[19:]:
    if value not in ('0', '1'):
        raise SystemExit('Feature flags must be 0 or 1')
VALIDATE
if (( 10#$SAFETY_TIMER < 60 || 10#$SAFETY_TIMER > 3600 )); then
    err "SAFETY_TIMER должен быть от 60 до 3600 секунд"
fi
if [[ "$ENABLE_BAD_TCP_FLAGS$ENABLE_ANTISPOOFING$ENABLE_SYN_RATE_LIMIT$ENABLE_CONN_LIMIT$ENABLE_SSH_RATE_LIMIT$ENABLE_PORTSCAN_BAN$ENABLE_ICMP_RATE_LIMIT$ENABLE_FAIL2BAN$ENABLE_CROWDSEC" == 000000000 ]]; then
    err "Experimental: не выбрано ни одной функции защиты"
fi
if [[ -z "$TCP_PORTS" && ( "$ENABLE_SYN_RATE_LIMIT" == 1 || "$ENABLE_CONN_LIMIT" == 1 ) ]]; then
    err "TCP_PORTS обязателен для SYN rate-limit и connlimit"
fi
# ── Генерация правил ──────────────────────────────────────────────────────────
build_rules() {
    local FAMILY="$1"
    local CHAIN
    [[ "$FAMILY" == "6" ]] && CHAIN="ufw6-antiscan" || CHAIN="ufw-antiscan"

    echo ""
    echo "$MARKER_START"
    echo "# Установлено ufw-antiscan $(date)"
    echo ":${CHAIN} - [0:0]"
    if [[ "$FAMILY" == "6" ]]; then
        echo "-A ufw6-before-input -j ${CHAIN}"
    else
        echo "-A ufw-before-input -j ${CHAIN}"
    fi
    echo "-A ${CHAIN} -i lo -j RETURN"
    echo ""

    # Whitelist должен идти раньше всех DROP-правил.
    # RETURN выводит пакет из отдельной цепочки обратно в ufw-before-input,
    # не обходя пользовательские ALLOW/DENY-правила.
    if [[ -n "$WHITELIST" ]]; then
        echo "# ── Whitelist ──────────────────────────────────────────────────────"
        IFS=',' read -ra WL <<< "$WHITELIST"
        for ip in "${WL[@]}"; do
            ip="${ip// /}"
            [[ -z "$ip" ]] && continue
            if [[ "$FAMILY" == "4" && "$ip" == *:* ]]; then continue; fi
            if [[ "$FAMILY" == "6" && "$ip" != *:* ]]; then continue; fi
            echo "-A ${CHAIN} -s ${ip} -j RETURN"
        done
        echo ""
    fi

    if [[ "$ENABLE_BAD_TCP_FLAGS" == 1 ]]; then
        echo "# ── Bad TCP flags (flag-drop) ──────────────────────────────────────"
        echo "# XMAS"
        echo "-A ${CHAIN} -p tcp --tcp-flags ALL ALL -j DROP"
        echo "# NULL"
        echo "-A ${CHAIN} -p tcp --tcp-flags ALL NONE -j DROP"
        echo "-A ${CHAIN} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP"
        echo "-A ${CHAIN} -p tcp --tcp-flags SYN,RST SYN,RST -j DROP"
        echo "-A ${CHAIN} -p tcp --tcp-flags FIN,RST FIN,RST -j DROP"
        echo "# FIN/PSH/URG без ACK"
        echo "-A ${CHAIN} -p tcp --tcp-flags ACK,FIN FIN -j DROP"
        echo "-A ${CHAIN} -p tcp --tcp-flags ACK,PSH PSH -j DROP"
        echo "-A ${CHAIN} -p tcp --tcp-flags ACK,URG URG -j DROP"
        echo ""
    fi

    # Preserve replies and related ICMP (including PMTU errors from private routers).
    echo "-A ${CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
    # Let normal UFW policy handle DHCP replies; they are not scan attempts.
    if [[ "$FAMILY" == "4" ]]; then
        echo "-A ${CHAIN} -p udp --sport 67 --dport 68 -j RETURN"
    else
        echo "-A ${CHAIN} -p udp --sport 547 --dport 546 -j RETURN"
    fi

    # Anti-spoofing только IPv4 и только если сервер имеет публичный IP
    if [[ "$FAMILY" == "4" && "$ENABLE_ANTISPOOFING" == "1" ]]; then
        local SIFACE=""
        [[ -n "$WAN_IFACE" ]] && SIFACE="-i ${WAN_IFACE}"
        echo "# ── Anti-spoofing (RFC1918/bogon на WAN) ───────────────────────────"
        for NET in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 \
                   100.64.0.0/10 169.254.0.0/16 192.0.0.0/24 \
                   198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 \
                   224.0.0.0/3 0.0.0.0/8; do
            echo "-A ${CHAIN} ${SIFACE} -s ${NET} -j DROP"
        done
        echo ""
    fi

    # Do not let source bans interfere with IPv6 neighbour discovery.
    if [[ "$FAMILY" == "6" ]]; then
        for kind in 133 134 135 136; do
            echo "-A ${CHAIN} -p ipv6-icmp --icmpv6-type ${kind} -j RETURN"
        done
    fi

    # AntiScan: забаненные — сразу дроп (должно быть первым)
    if [[ "$ENABLE_PORTSCAN_BAN" == "1" ]]; then
        echo "# ── AntiScan: забаненные IP → сразу дроп ───────────────────────────"
        echo "-A ${CHAIN} -m recent --name PORTSCANNERS --rcheck --seconds ${PORTSCAN_BAN_SECONDS} -j DROP"
        echo ""
    fi

    if [[ "$ENABLE_SYN_RATE_LIMIT" == 1 ]]; then
        echo "# ── Per-IP SYN-flood rate-limit ────────────────────────────────────"
        IFS=',' read -ra TPORTS <<< "$TCP_PORTS"
        for p in "${TPORTS[@]}"; do
            p="${p// /}"
            echo "-A ${CHAIN} -p tcp --dport ${p} --syn -m hashlimit --hashlimit-above ${SYN_RATE}/sec --hashlimit-burst ${SYN_BURST} --hashlimit-mode srcip --hashlimit-name syn_${p} --hashlimit-htable-expire 10000 -j DROP"
        done
        echo ""
    fi

    if [[ "$ENABLE_CONN_LIMIT" == 1 ]]; then
        echo "# ── Per-IP connlimit ────────────────────────────────────────────────"
        IFS=',' read -ra TPORTS <<< "$TCP_PORTS"
        for p in "${TPORTS[@]}"; do
            p="${p// /}"
            if [[ "$FAMILY" == "4" ]]; then
                echo "-A ${CHAIN} -p tcp --dport ${p} --syn -m connlimit --connlimit-above ${CONN_LIMIT} --connlimit-mask 32 -j DROP"
            else
                echo "-A ${CHAIN} -p tcp --dport ${p} --syn -m connlimit --connlimit-above ${CONN_LIMIT} --connlimit-mask 128 -j DROP"
            fi
        done
        echo ""
    fi

    if [[ "$ENABLE_SSH_RATE_LIMIT" == 1 ]]; then
        echo "# ── SSH per-IP rate-limit ───────────────────────────────────────────"
        echo "-A ${CHAIN} -p tcp --dport ${SSH_PORT} --syn -m hashlimit --hashlimit-above ${SSH_RATE}/minute --hashlimit-burst ${SSH_BURST} --hashlimit-mode srcip --hashlimit-name ssh_rate --hashlimit-htable-expire 60000 -j DROP"
    fi

    # AntiScan: сервисные порты возвращаем в обычную обработку UFW.
    # Важно: --remove без target не завершает цепочку и раньше пропускал даже
    # разрешённые SYN до общего DROP ниже.
    if [[ "$ENABLE_PORTSCAN_BAN" == "1" ]]; then
        echo ""
        echo "# ── AntiScan: сервисные порты → обратно в обычные правила UFW ─────"
        echo "-A ${CHAIN} -p tcp --dport ${SSH_PORT} -j RETURN"
        IFS=',' read -ra TPORTS <<< "$TCP_PORTS"
        for p in "${TPORTS[@]}"; do
            echo "-A ${CHAIN} -p tcp --dport ${p// /} -j RETURN"
        done
        IFS=',' read -ra UPORTS <<< "$UDP_PORTS"
        for p in "${UPORTS[@]}"; do
            echo "-A ${CHAIN} -p udp --dport ${p// /} -j RETURN"
        done
        echo ""
        echo "# SYN/UDP на нессервисный порт → в список сканеров + DROP"
        for proto in tcp udp; do
            local flags=""
            [[ "$proto" == tcp ]] && flags="--syn"
            echo "-A ${CHAIN} -p ${proto} ${flags} -m conntrack --ctstate NEW -m recent --name SCANHITS --set"
            echo "-A ${CHAIN} -p ${proto} ${flags} -m conntrack --ctstate NEW -m recent --name SCANHITS --rcheck --seconds ${PORTSCAN_WINDOW} --hitcount ${PORTSCAN_HITS} -m recent --name PORTSCANNERS --set -j DROP"
            echo "-A ${CHAIN} -p ${proto} ${flags} -m conntrack --ctstate NEW -j DROP"
        done
    fi
    echo ""

    if [[ "$ENABLE_ICMP_RATE_LIMIT" == 1 ]]; then
        echo "# ── ICMP rate-limit ─────────────────────────────────────────────────"
        if [[ "$FAMILY" == "4" ]]; then
            echo "-A ${CHAIN} -p icmp --icmp-type echo-request -m hashlimit --hashlimit-above ${ICMP_RATE}/sec --hashlimit-burst ${ICMP_BURST} --hashlimit-mode srcip --hashlimit-name icmp_rate -j DROP"
        else
            echo "-A ${CHAIN} -p ipv6-icmp --icmpv6-type echo-request -m hashlimit --hashlimit-above ${ICMP_RATE}/sec --hashlimit-burst ${ICMP_BURST} --hashlimit-mode srcip --hashlimit-name icmp6_rate -j DROP"
        fi
    fi

    echo ""
    echo "$MARKER_END"
    echo ""
}

# ── DRY RUN или применение ────────────────────────────────────────────────────
section "Правила iptables"

RULES_V4=$(build_rules 4)
RULES_V6=$(build_rules 6)

if [[ "$DRY_RUN" == "1" ]]; then
    dry "Правила IPv4 (before.rules):"
    echo "$RULES_V4"
    dry "Правила IPv6 (before6.rules):"
    echo "$RULES_V6"
    echo ""
    warn "DRY RUN завершён. Для применения запусти без DRY_RUN=1"
    exit 0
fi

# Serialize changes and preserve the pre-install state for uninstall.
command -v flock >/dev/null || err "flock is required"
[[ "$UFW_STATUS" == "Status: active" ]] || err "Enable and configure UFW before applying AntiScan"
iptables -S >/dev/null || err "Cannot read netfilter rules: CAP_NET_ADMIN is required"
systemctl show-environment >/dev/null || err "A running systemd manager is required"
exec 9>/run/lock/ufw-antiscan.lock
flock -n 9 || err "Another AntiScan operation is running"
mkdir -p "$STATE" /var/backups/ufw-antiscan
chmod 700 "$STATE"
[[ ! -f "$PENDING" ]] || err "Confirm or roll back the pending application first"
BACKUP_DIR=$(mktemp -d /var/backups/ufw-antiscan/apply.XXXXXXXX)
snapshot "$BACKUP_DIR"
if [[ ! -d "$STATE/original" ]]; then
    ORIGINAL_STAGE=$(mktemp -d "$STATE/original.XXXXXXXX")
    cp -a "$BACKUP_DIR/." "$ORIGINAL_STAGE/"
    mv -T "$ORIGINAL_STAGE" "$STATE/original"
fi
printf '%s' "${SSH_CONNECTION:-}" > "$BACKUP_DIR/ssh-connection"
rollback_on_error() {
    local code=$?
    trap - ERR INT TERM HUP
    echo "Application failed; restoring $BACKUP_DIR" >&2
    if restore_snapshot "$BACKUP_DIR"; then
        rm -f "$PENDING"
        disarm_safety || true
    else
        echo "RESTORE FAILED. Backup: $BACKUP_DIR" >&2
    fi
    exit "$code"
}
trap rollback_on_error ERR
trap 'false' INT TERM HUP
# Keep recovery code installed even when restoring the first application fails.
mkdir -p /usr/local/lib/ufw-antiscan
install -m 644 "$SCRIPT_DIR/state.sh" /usr/local/lib/ufw-antiscan/state.sh
install -m 755 "$SCRIPT_DIR/restore.sh" /usr/local/lib/ufw-antiscan/restore.sh
# Arm before modifying optional services, not just before UFW.
arm_safety "$BACKUP_DIR" 3600
# Stop blocklist services left by older releases. Their files and sets are
# removed only after UFW no longer references them.
systemctl stop ufw-antiscan-blocklists.timer ufw-antiscan-blocklists.service 2>/dev/null || true
# Stage UFW files: no live firewall file is changed until validation succeeds.
STAGE="$BACKUP_DIR/stage"
mkdir -p "$STAGE"
printf '%s\n' "$RULES_V4" > "$STAGE/rules4"
printf '%s\n' "$RULES_V6" > "$STAGE/rules6"
cp -a /etc/ufw/before.rules "$STAGE/before.rules"
python3 "$SCRIPT_DIR/rules.py" inject "$STAGE/before.rules" "$STAGE/rules4" 4
if [[ -f /etc/ufw/before6.rules ]]; then
    cp -a /etc/ufw/before6.rules "$STAGE/before6.rules"
    python3 "$SCRIPT_DIR/rules.py" inject "$STAGE/before6.rules" "$STAGE/rules6" 6
fi

# ── fail2ban ──────────────────────────────────────────────────────────────────
if [[ "$ENABLE_FAIL2BAN" == 1 ]]; then
    section "fail2ban (SSH brute-force)"
    if ! command -v fail2ban-client &>/dev/null; then
        info "Устанавливаю fail2ban..."
        apt-get install -y -q fail2ban
    fi
    cat > /etc/fail2ban/jail.d/ufw-antiscan-ssh.conf << F2BEOF
[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
backend  = systemd
maxretry = ${F2B_MAXRETRY}
findtime = ${F2B_FINDTIME}
bantime  = ${F2B_BANTIME}
action   = ufw
F2BEOF
    fail2ban-client -t
    ok "fail2ban SSH настроен (${F2B_MAXRETRY} попыток/${F2B_FINDTIME}с, бан ${F2B_BANTIME}с)"
fi

# ── CrowdSec ──────────────────────────────────────────────────────────────────
if [[ "$ENABLE_CROWDSEC" == "1" ]]; then
    section "CrowdSec"

    if ! command -v cscli &>/dev/null; then
        if ! command -v gpg &>/dev/null; then
            info "Устанавливаю gnupg для импорта ключа репозитория CrowdSec..."
            apt-get update -q
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q gnupg
            ok "gnupg установлен"
        fi

        info "Добавляю репозиторий CrowdSec..."
        curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
            | gpg --batch --yes --dearmor \
                -o /usr/share/keyrings/crowdsec-archive-keyring.gpg

        . /etc/os-release
        echo "deb [signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] \
https://packagecloud.io/crowdsec/crowdsec/${ID} ${VERSION_CODENAME} main" \
            > /etc/apt/sources.list.d/crowdsec.list

        apt-get update -q
        info "Устанавливаю crowdsec..."
        apt-get install -y -q crowdsec
        ok "CrowdSec агент установлен"
    else
        ok "CrowdSec уже установлен"
    fi

    # Bouncer через iptables; фактический backend может быть legacy или nft.
    if [[ "$(dpkg-query -W -f='${Status}' crowdsec-firewall-bouncer-iptables 2>/dev/null || true)" != "install ok installed" ]]; then
        info "Устанавливаю crowdsec-firewall-bouncer-iptables..."
        apt-get install -y -q crowdsec-firewall-bouncer-iptables
        ok "iptables-bouncer установлен"
    else
        ok "iptables-bouncer уже установлен"
    fi

    # Базовые коллекции
    info "Устанавливаю коллекции..."
    cscli collections install crowdsecurity/linux -q || warn "Коллекция linux не установлена"
    cscli collections install crowdsecurity/sshd -q || warn "Коллекция sshd не установлена"
    cscli collections install crowdsecurity/iptables -q || warn "Коллекция iptables не установлена"
    cscli collections install crowdsecurity/http-cve -q || warn "Коллекция http-cve не установлена"
    info "Проверь acquisition и метрики CrowdSec для нужных источников логов"

    # Enroll в Console (опционально)
    if [[ -n "$CROWDSEC_ENROLL_KEY" ]]; then
        info "Enrolling в CrowdSec Console..."
        cscli console enroll "$CROWDSEC_ENROLL_KEY" \
            && ok "Console enrollment выполнен" \
            || warn "Enrollment не удался — проверь ключ"
    else
        warn "CROWDSEC_ENROLL_KEY не задан — веб-консоль недоступна (опционально)"
        info "Зарегистрируйся на https://app.crowdsec.net, потом:"
        info "  cscli console enroll <твой-ключ>"
    fi

    systemctl enable --now crowdsec 2>/dev/null || true
    systemctl enable --now crowdsec-firewall-bouncer 2>/dev/null || true
    systemctl restart crowdsec
    systemctl restart crowdsec-firewall-bouncer
    ok "CrowdSec запущен"
fi

# ── Проверка сгенерированных UFW-файлов ──────────────────────────────────────
validate_ufw_rules() {
    local failed=0

    info "Проверяю синтаксис /etc/ufw/before.rules..."
    if ! iptables-restore --test < "$STAGE/before.rules"; then
        warn "Ошибка синтаксиса IPv4 ruleset"
        failed=1
    fi

    if [[ -f /etc/ufw/before6.rules ]]; then
        if ! command -v ip6tables-restore &>/dev/null; then
            warn "ip6tables-restore не найден, IPv6 ruleset проверить невозможно"
            failed=1
        else
            info "Проверяю синтаксис /etc/ufw/before6.rules..."
            if ! ip6tables-restore --test < "$STAGE/before6.rules"; then
                warn "Ошибка синтаксиса IPv6 ruleset"
                failed=1
            fi
        fi
    fi

    [[ "$failed" == 0 ]] || return 1

    ok "Синтаксис IPv4/IPv6 правил корректен"
}

# ── Применяем всё ─────────────────────────────────────────────────────────────
section "Применение"

validate_ufw_rules

# Reset the deadline after dependency preparation, before applying UFW.
arm_safety "$BACKUP_DIR" "$SAFETY_TIMER"
# Atomic rename within /etc/ufw, retaining the original permissions.
cp -a "$STAGE/before.rules" /etc/ufw/before.rules.antiscan-new
mv -f /etc/ufw/before.rules.antiscan-new /etc/ufw/before.rules
if [[ -f "$STAGE/before6.rules" ]]; then
    cp -a "$STAGE/before6.rules" /etc/ufw/before6.rules.antiscan-new
    mv -f /etc/ufw/before6.rules.antiscan-new /etc/ufw/before6.rules
fi
if [[ "$ENABLE_FAIL2BAN" == 1 ]]; then
    systemctl enable --now fail2ban
    systemctl restart fail2ban
fi
ufw reload

# Releases before this one installed static IP blocklists. Remove their legacy
# services and sets only after the new ruleset is active and has no ipset jumps.
section "Очистка устаревших IP-списков"
systemctl disable --now ufw-antiscan-blocklists.timer 2>/dev/null || true
systemctl disable --now ufw-antiscan-blocklists.service 2>/dev/null || true
systemctl disable --now ufw-antiscan-ipsets.service 2>/dev/null || true
rm -f /usr/local/bin/ufw-antiscan-update-blocklists.sh \
      /usr/local/bin/ufw-antiscan-ensure-ipsets.sh \
      /etc/systemd/system/ufw-antiscan-ipsets.service \
      /etc/systemd/system/ufw.service.d/ufw-antiscan-ipsets.conf \
      /etc/systemd/system/ufw-antiscan-blocklists.service \
      /etc/systemd/system/ufw-antiscan-blocklists.timer \
      /etc/ufw-antiscan/blocklists.conf \
      "$STATE/current.restore"
rmdir /etc/systemd/system/ufw.service.d /etc/ufw-antiscan 2>/dev/null || true
systemctl daemon-reload
if command -v ipset >/dev/null; then
    (
        exec 8>/run/lock/ufw-antiscan-blocklists.lock
        flock -x 8
        for name in ANTISCAN-V4 ANTISCAN-V6 ANTISCAN-V4-TMP ANTISCAN-V6-TMP; do
            ipset destroy "$name" 2>/dev/null || true
        done
    )
fi
ok "Устаревшие статические IP-списки удалены"

mark_confirmation_boundary "$BACKUP_DIR"
warn "Проверь новое SSH-подключение и VPN. Автооткат через ${SAFETY_TIMER} секунд."
warn "Из НОВОГО SSH-подключения: sudo --preserve-env=SSH_CONNECTION bash install.sh confirm"

ok "UFW перезагружен"
[[ "$ENABLE_FAIL2BAN" == 0 ]] || ok "Fail2Ban запущен"

# The timer stays armed until an explicit confirmation from a new connection.
trap - ERR INT TERM HUP
ok "Применено, ожидается подтверждение. Бэкап: $BACKUP_DIR"
