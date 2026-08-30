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
#   sudo ENABLE_CROWDSEC=0 bash scripts/protect.sh  # без CrowdSec
#
# ENV-переменные: см. README.md

set -euo pipefail

# ── Цвета ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[✔]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✘]${NC} $*" >&2; exit 1; }
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
  SYN_RATE / SYN_BURST      Per-IP лимит новых TCP-соед/сек (по умолчанию: 100/200)
  CONN_LIMIT                Макс одновременных соединений с одного IP (по умолчанию: 600)
  SSH_RATE / SSH_BURST      Лимит новых SSH-соед/мин до бана (по умолчанию: 6/4)
  PORTSCAN_BAN_SECONDS      Время бана за сканирование в секундах (по умолчанию: 3600)
  ENABLE_PORTSCAN_BAN       1/0 — включить portscan autoban (по умолчанию: 1)
  ENABLE_CROWDSEC           1/0 — установить CrowdSec (по умолчанию: 1)
  CROWDSEC_ENROLL_KEY       Ключ из app.crowdsec.net (опционально)
  DRY_RUN                   1/0 — только показать правила, не применять

Примеры:
  # Remnawave-нода
  sudo SSH_PORT=22 TCP_PORTS=443,2087 UDP_PORTS=443 \
       WHITELIST="1.2.3.4" bash scripts/protect.sh

  # Посмотреть что будет без применения
  sudo DRY_RUN=1 bash scripts/protect.sh

  # Без CrowdSec
  sudo ENABLE_CROWDSEC=0 bash scripts/protect.sh
HELP
    exit 0
fi

# ── Параметры ─────────────────────────────────────────────────────────────────
[[ "${1:-}" == "--dry-run" ]] && export DRY_RUN=1

DRY_RUN="${DRY_RUN:-0}"

SSH_PORT="${SSH_PORT:-$(ss -tlnp 2>/dev/null \
    | awk '/sshd/{match($4,/[0-9]+$/); p=substr($4,RSTART,RLENGTH); if(p) print p}' \
    | head -1)}"
SSH_PORT="${SSH_PORT:-22}"

TCP_PORTS="${TCP_PORTS:-443,2087}"
UDP_PORTS="${UDP_PORTS:-443}"

SYN_RATE="${SYN_RATE:-100}"
SYN_BURST="${SYN_BURST:-200}"
CONN_LIMIT="${CONN_LIMIT:-600}"

SSH_RATE="${SSH_RATE:-6}"
SSH_BURST="${SSH_BURST:-4}"

PORTSCAN_BAN_SECONDS="${PORTSCAN_BAN_SECONDS:-3600}"
ENABLE_PORTSCAN_BAN="${ENABLE_PORTSCAN_BAN:-1}"

WHITELIST="${WHITELIST:-}"

ENABLE_CROWDSEC="${ENABLE_CROWDSEC:-1}"
CROWDSEC_ENROLL_KEY="${CROWDSEC_ENROLL_KEY:-}"

MARKER_START="# === UFW-ANTISCAN START ==="
MARKER_END="# === UFW-ANTISCAN END ==="

BACKUP_DIR="/var/backups/ufw-antiscan/$(date +%Y%m%d_%H%M%S)"

# ── Проверки ──────────────────────────────────────────────────────────────────
section "Проверка окружения"

[[ $EUID -ne 0 ]] && err "Нужен root: sudo bash $0"
command -v ufw      &>/dev/null || err "ufw не установлен. Установи: apt install ufw"
command -v iptables &>/dev/null || err "iptables не найден"
command -v python3  &>/dev/null || err "python3 не найден. Установи: apt install python3"

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
[[ "$UFW_STATUS" != *"active"* ]] && \
    warn "UFW сейчас неактивен — правила применятся после: sudo ufw enable"

WAN_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1 || true)
[[ -z "$WAN_IFACE" ]] && \
    warn "WAN-интерфейс не определён — anti-spoofing без привязки к интерфейсу"

# Проверка что hashlimit и recent доступны
if ! iptables -m hashlimit --help &>/dev/null 2>&1; then
    warn "Модуль iptables 'hashlimit' недоступен — rate-limiting будет пропущен"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    warn "Режим DRY RUN — правила будут показаны, но НЕ применены"
fi

info "SSH-порт:  ${SSH_PORT}"
info "WAN:       ${WAN_IFACE:-любой интерфейс}"
info "TCP-порты: ${TCP_PORTS}"
info "UDP-порты: ${UDP_PORTS}"
info "Whitelist: ${WHITELIST:-не задан}"
info "CrowdSec:  ${ENABLE_CROWDSEC}"
info "DRY RUN:   ${DRY_RUN}"

# ── Бэкап ─────────────────────────────────────────────────────────────────────
if [[ "$DRY_RUN" == "0" ]]; then
    section "Бэкап"
    mkdir -p "$BACKUP_DIR"
    cp /etc/ufw/before.rules "$BACKUP_DIR/before.rules.bak"
    [[ -f /etc/ufw/before6.rules ]] && \
        cp /etc/ufw/before6.rules "$BACKUP_DIR/before6.rules.bak"
    iptables-save > "$BACKUP_DIR/iptables.bak"
    ok "Бэкап → $BACKUP_DIR"
fi

# ── Генерация правил ──────────────────────────────────────────────────────────
build_rules() {
    local FAMILY="$1"
    local CHAIN
    [[ "$FAMILY" == "6" ]] && CHAIN="ufw6-before-input" || CHAIN="ufw-before-input"

    echo ""
    echo "$MARKER_START"
    echo "# Установлено ufw-antiscan $(date)"
    echo ""

    # Whitelist
    if [[ -n "$WHITELIST" ]]; then
        echo "# ── Whitelist ──────────────────────────────────────────────────────"
        IFS=',' read -ra WL <<< "$WHITELIST"
        for ip in "${WL[@]}"; do
            ip="${ip// /}"
            [[ -z "$ip" ]] && continue
            if [[ "$FAMILY" == "4" && "$ip" == *:* ]]; then continue; fi
            if [[ "$FAMILY" == "6" && "$ip" != *:* ]]; then continue; fi
            echo "-A ${CHAIN} -s ${ip} -j ACCEPT"
        done
        echo ""
    fi

    echo "# ── Bad TCP flags (flag-drop) ──────────────────────────────────────"
    echo "-A ${CHAIN} -p tcp --tcp-flags ALL ALL         -j DROP  # XMAS"
    echo "-A ${CHAIN} -p tcp --tcp-flags ALL NONE        -j DROP  # NULL"
    echo "-A ${CHAIN} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP"
    echo "-A ${CHAIN} -p tcp --tcp-flags SYN,RST SYN,RST -j DROP"
    echo "-A ${CHAIN} -p tcp --tcp-flags FIN,RST FIN,RST -j DROP"
    echo "-A ${CHAIN} -p tcp --tcp-flags ACK,FIN FIN     -j DROP  # FIN без ACK"
    echo "-A ${CHAIN} -p tcp --tcp-flags ACK,PSH PSH     -j DROP  # PSH без ACK"
    echo "-A ${CHAIN} -p tcp --tcp-flags ACK,URG URG     -j DROP  # URG без ACK"
    echo ""

    # Anti-spoofing только IPv4
    if [[ "$FAMILY" == "4" ]]; then
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

    # AntiScan: забаненные — сразу дроп (должно быть первым)
    if [[ "$ENABLE_PORTSCAN_BAN" == "1" ]]; then
        echo "# ── AntiScan: забаненные IP → сразу дроп ───────────────────────────"
        echo "-A ${CHAIN} -m recent --name PORTSCANNERS --rcheck --seconds ${PORTSCAN_BAN_SECONDS} -j DROP"
        echo ""
    fi

    echo "# ── Per-IP SYN-flood rate-limit ────────────────────────────────────"
    echo "# (применяется ДО снятия флага сканера — весь трафик проходит через лимиты)"
    IFS=',' read -ra TPORTS <<< "$TCP_PORTS"
    for p in "${TPORTS[@]}"; do
        p="${p// /}"
        echo "-A ${CHAIN} -p tcp --dport ${p} --syn \\"
        echo "   -m hashlimit --hashlimit-above ${SYN_RATE}/sec --hashlimit-burst ${SYN_BURST} \\"
        echo "   --hashlimit-mode srcip --hashlimit-name syn_${p} \\"
        echo "   --hashlimit-htable-expire 10000 -j DROP"
    done
    echo ""

    echo "# ── Per-IP connlimit ────────────────────────────────────────────────"
    IFS=',' read -ra TPORTS <<< "$TCP_PORTS"
    for p in "${TPORTS[@]}"; do
        p="${p// /}"
        echo "-A ${CHAIN} -p tcp --dport ${p} \\"
        echo "   -m connlimit --connlimit-above ${CONN_LIMIT} --connlimit-mask 32 -j DROP"
    done
    echo ""

    echo "# ── SSH per-IP rate-limit ───────────────────────────────────────────"
    echo "-A ${CHAIN} -p tcp --dport ${SSH_PORT} --syn \\"
    echo "   -m hashlimit --hashlimit-above ${SSH_RATE}/minute --hashlimit-burst ${SSH_BURST} \\"
    echo "   --hashlimit-mode srcip --hashlimit-name ssh_rate \\"
    echo "   --hashlimit-htable-expire 60000 -j DROP"

    # AntiScan: снятие флага для сервисных портов и бан нессервисных
    # Стоит ПОСЛЕ rate-limit — легитимный трафик всё равно проходит через лимиты
    if [[ "$ENABLE_PORTSCAN_BAN" == "1" ]]; then
        echo ""
        echo "# ── AntiScan: сервисные порты — снять флаг сканера, идти дальше ────"
        echo "# Используем --remove без -j RETURN, чтобы трафик продолжал"
        echo "# обрабатываться UFW-правилами (ACCEPT и т.д.)"
        echo "-A ${CHAIN} -p tcp --dport ${SSH_PORT} -m recent --name PORTSCANNERS --remove"
        IFS=',' read -ra TPORTS <<< "$TCP_PORTS"
        for p in "${TPORTS[@]}"; do
            echo "-A ${CHAIN} -p tcp --dport ${p// /} -m recent --name PORTSCANNERS --remove"
        done
        IFS=',' read -ra UPORTS <<< "$UDP_PORTS"
        for p in "${UPORTS[@]}"; do
            echo "-A ${CHAIN} -p udp --dport ${p// /} -m recent --name PORTSCANNERS --remove"
        done
        echo ""
        echo "# SYN/UDP на нессервисный порт → в список сканеров + DROP"
        echo "-A ${CHAIN} -p tcp --syn -m recent --name PORTSCANNERS --set -j DROP"
        echo "-A ${CHAIN} -p udp -m state --state NEW -m recent --name PORTSCANNERS --set -j DROP"
    fi
    echo ""

    echo "# ── ICMP rate-limit ─────────────────────────────────────────────────"
    if [[ "$FAMILY" == "4" ]]; then
        echo "-A ${CHAIN} -p icmp --icmp-type echo-request \\"
        echo "   -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 \\"
        echo "   --hashlimit-mode srcip --hashlimit-name icmp_rate -j DROP"
    else
        echo "-A ${CHAIN} -p ipv6-icmp --icmpv6-type echo-request \\"
        echo "   -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 \\"
        echo "   --hashlimit-mode srcip --hashlimit-name icmp6_rate -j DROP"
    fi

    echo ""
    echo "$MARKER_END"
    echo ""
}

# ── Вставка правил в файл ─────────────────────────────────────────────────────
inject_rules() {
    local FILE="$1"
    local RULES="$2"

    # Удаляем старый блок если есть
    if grep -q "UFW-ANTISCAN START" "$FILE" 2>/dev/null; then
        python3 -c "
import re
with open('${FILE}', 'r') as f:
    c = f.read()
c = re.sub(r'# === UFW-ANTISCAN START ===.*?# === UFW-ANTISCAN END ===\n?', '', c, flags=re.DOTALL)
with open('${FILE}', 'w') as f:
    f.write(c)
"
    fi

    python3 - "$FILE" "$RULES" << 'PYEOF'
import sys

filepath = sys.argv[1]
rules = sys.argv[2]

with open(filepath, 'r') as f:
    content = f.read()

anchor = "# ok icmp codes for INPUT"
if anchor in content:
    content = content.replace(anchor, rules + "\n" + anchor, 1)
else:
    idx = content.rfind('COMMIT')
    if idx != -1:
        content = content[:idx] + rules + "\n" + content[idx:]

with open(filepath, 'w') as f:
    f.write(content)
PYEOF
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

inject_rules /etc/ufw/before.rules "$RULES_V4"
ok "IPv4 → /etc/ufw/before.rules"

if [[ -f /etc/ufw/before6.rules ]]; then
    inject_rules /etc/ufw/before6.rules "$RULES_V6"
    ok "IPv6 → /etc/ufw/before6.rules"
fi

# ── fail2ban ──────────────────────────────────────────────────────────────────
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
maxretry = 5
findtime = 300
bantime  = 86400
action   = ufw
F2BEOF

ok "fail2ban SSH настроен (бан после 5 попыток за 5 мин, на 24ч)"

# ── CrowdSec ──────────────────────────────────────────────────────────────────
if [[ "$ENABLE_CROWDSEC" == "1" ]]; then
    section "CrowdSec"

    if ! command -v cscli &>/dev/null; then
        info "Добавляю репозиторий CrowdSec..."
        curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
            | gpg --dearmor -o /usr/share/keyrings/crowdsec-archive-keyring.gpg

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

    # Bouncer для iptables (UFW использует iptables, не nftables)
    if ! dpkg -l crowdsec-firewall-bouncer-iptables &>/dev/null 2>&1; then
        info "Устанавливаю crowdsec-firewall-bouncer-iptables..."
        apt-get install -y -q crowdsec-firewall-bouncer-iptables
        ok "iptables-bouncer установлен"
    else
        ok "iptables-bouncer уже установлен"
    fi

    # Базовые коллекции
    info "Устанавливаю коллекции..."
    cscli collections install crowdsecurity/linux    -q 2>/dev/null || true
    cscli collections install crowdsecurity/sshd     -q 2>/dev/null || true
    cscli collections install crowdsecurity/iptables -q 2>/dev/null || true
    cscli collections install crowdsecurity/http-cve -q 2>/dev/null || true
    ok "Коллекции установлены"

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

# ── Применяем всё ─────────────────────────────────────────────────────────────
section "Применение"

systemctl enable --now fail2ban 2>/dev/null || true
systemctl restart fail2ban
ufw reload

ok "UFW перезагружен, fail2ban запущен"

# ── Финальный статус ──────────────────────────────────────────────────────────
section "Статус"

echo ""
echo -e "${BOLD}Правила UFW:${NC}"
ufw status numbered 2>/dev/null | head -20

echo ""
echo -e "${BOLD}Portscan-баны:${NC}"
SCAN_COUNT=$(wc -l < /proc/net/ipt_recent/PORTSCANNERS 2>/dev/null || echo 0)
echo "  Заблокировано IP: ${SCAN_COUNT}"

echo ""
echo -e "${BOLD}fail2ban SSH:${NC}"
fail2ban-client status sshd 2>/dev/null || true

if [[ "$ENABLE_CROWDSEC" == "1" ]]; then
    echo ""
    echo -e "${BOLD}CrowdSec:${NC}"
    CSEC_COUNT=$(cscli decisions list 2>/dev/null | wc -l || echo '?')
    echo "  Активных блокировок: ${CSEC_COUNT}"
fi

echo ""
echo -e "${GREEN}${BOLD}✔ Готово!${NC}"
echo ""
echo -e "${BOLD}Полезные команды:${NC}"
echo "  Статус:                   sudo bash install.sh status"
echo "  Откат:                    sudo bash install.sh rollback"
echo "  Portscan-баны:            cat /proc/net/ipt_recent/PORTSCANNERS"
echo "  Разбанить всех сканеров:  echo / > /proc/net/ipt_recent/PORTSCANNERS"
echo "  SSH-баны:                 fail2ban-client status sshd"
echo "  CrowdSec-баны:            cscli decisions list"
echo ""
