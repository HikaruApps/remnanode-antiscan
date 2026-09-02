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
  ENABLE_BLOCKLISTS         1/0 — загрузить IP-blocklists в ipset (по умолчанию: 1)
  BLOCKLIST_URLS            URL списков через пробел (antiscanner + gov_networks)
  BLOCKLIST_UPDATE_INTERVAL Интервал авто-обновления systemd-таймером (по умолч.: 6h)
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

# Safety timer: автоматический откат если что-то пошло не так (секунд)
SAFETY_TIMER="${SAFETY_TIMER:-60}"

ENABLE_CROWDSEC="${ENABLE_CROWDSEC:-1}"
CROWDSEC_ENROLL_KEY="${CROWDSEC_ENROLL_KEY:-}"

ENABLE_BLOCKLISTS="${ENABLE_BLOCKLISTS:-1}"
# Списки через пробел; по умолчанию antiscanner + government_networks
BLOCKLIST_URLS="${BLOCKLIST_URLS:-https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list}"
BLOCKLIST_UPDATE_INTERVAL="${BLOCKLIST_UPDATE_INTERVAL:-6h}"

IPSET_NAME_V4="ANTISCAN-V4"
IPSET_NAME_V6="ANTISCAN-V6"
BLOCKLIST_UPDATE_SCRIPT="/usr/local/bin/ufw-antiscan-update-blocklists.sh"
IPSET_BOOTSTRAP_SCRIPT="/usr/local/bin/ufw-antiscan-ensure-ipsets.sh"

MARKER_START="# === UFW-ANTISCAN START ==="
MARKER_END="# === UFW-ANTISCAN END ==="

BACKUP_DIR="/var/backups/ufw-antiscan/$(date +%Y%m%d_%H%M%S)"

# ── Проверки ──────────────────────────────────────────────────────────────────
section "Проверка окружения"

[[ $EUID -ne 0 ]] && err "Нужен root: sudo bash $0"
command -v ufw      &>/dev/null || err "ufw не установлен. Установи: apt install ufw"
command -v iptables &>/dev/null || err "iptables не найден"
command -v iptables-restore &>/dev/null || err "iptables-restore не найден"
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
[[ -z "$WAN_IFACE" ]] &&     warn "WAN-интерфейс не определён — anti-spoofing без привязки к интерфейсу"

# Авто-детект: если у сервера приватный IP (VPS за NAT) — anti-spoofing опасен
MY_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1 || true)
ENABLE_ANTISPOOFING="${ENABLE_ANTISPOOFING:-1}"
if [[ "${ENABLE_ANTISPOOFING}" == "1" && -n "$MY_IP" ]]; then
    if [[ "$MY_IP" =~ ^10\. ||           "$MY_IP" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ||           "$MY_IP" =~ ^192\.168\. ||           "$MY_IP" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]]; then
        warn "Обнаружен приватный IP сервера (${MY_IP}) — anti-spoofing ОТКЛЮЧЁН"
        warn "Сервер за NAT: RFC1918-правила заблокируют легитимный трафик"
        ENABLE_ANTISPOOFING=0
    fi
fi

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
info "Anti-spoof: ${ENABLE_ANTISPOOFING} (IP сервера: ${MY_IP:-неизвестен})"
info "CrowdSec:  ${ENABLE_CROWDSEC}"
info "Blocklists: ${ENABLE_BLOCKLISTS}"
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

    # Whitelist должен идти раньше всех DROP-правил, включая blocklists.
    # RETURN выводит пакет из ufw-before-input обратно в основную UFW-цепочку,
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

    # ipset blocklists (O(1), после whitelist)
    if [[ "$ENABLE_BLOCKLISTS" == "1" ]]; then
        echo "# ── ipset blocklists (known scanners/gov networks) ──────────────────"
        echo "# ipset-сеты создаются отдельно; здесь только jump-правила"
        if [[ "$FAMILY" == "4" ]]; then
            echo "-A ${CHAIN} -m set --match-set ${IPSET_NAME_V4} src -j DROP"
        else
            echo "-A ${CHAIN} -m set --match-set ${IPSET_NAME_V6} src -j DROP"
        fi
        echo ""
    fi

    echo "# ── Bad TCP flags (flag-drop) ──────────────────────────────────────"
    echo "# XMAS"
    echo "-A ${CHAIN} -p tcp --tcp-flags ALL ALL -j DROP"
    echo "# NULL"
    echo "-A ${CHAIN} -p tcp --tcp-flags ALL NONE -j DROP"
    echo "-A ${CHAIN} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP"
    echo "-A ${CHAIN} -p tcp --tcp-flags SYN,RST SYN,RST -j DROP"
    echo "-A ${CHAIN} -p tcp --tcp-flags FIN,RST FIN,RST -j DROP"
    echo "# FIN без ACK"
    echo "-A ${CHAIN} -p tcp --tcp-flags ACK,FIN FIN -j DROP"
    echo "# PSH без ACK"
    echo "-A ${CHAIN} -p tcp --tcp-flags ACK,PSH PSH -j DROP"
    echo "# URG без ACK"
    echo "-A ${CHAIN} -p tcp --tcp-flags ACK,URG URG -j DROP"
    echo ""

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
        echo "-A ${CHAIN} -p tcp --dport ${p} --syn -m hashlimit --hashlimit-above ${SYN_RATE}/sec --hashlimit-burst ${SYN_BURST} --hashlimit-mode srcip --hashlimit-name syn_${p} --hashlimit-htable-expire 10000 -j DROP"
    done
    echo ""

    echo "# ── Per-IP connlimit ────────────────────────────────────────────────"
    IFS=',' read -ra TPORTS <<< "$TCP_PORTS"
    for p in "${TPORTS[@]}"; do
        p="${p// /}"
        if [[ "$FAMILY" == "4" ]]; then
            echo "-A ${CHAIN} -p tcp --dport ${p} -m connlimit --connlimit-above ${CONN_LIMIT} --connlimit-mask 32 -j DROP"
        else
            echo "-A ${CHAIN} -p tcp --dport ${p} -m connlimit --connlimit-above ${CONN_LIMIT} --connlimit-mask 128 -j DROP"
        fi
    done
    echo ""

    echo "# ── SSH per-IP rate-limit ───────────────────────────────────────────"
    echo "-A ${CHAIN} -p tcp --dport ${SSH_PORT} --syn -m hashlimit --hashlimit-above ${SSH_RATE}/minute --hashlimit-burst ${SSH_BURST} --hashlimit-mode srcip --hashlimit-name ssh_rate --hashlimit-htable-expire 60000 -j DROP"

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
        echo "-A ${CHAIN} -p tcp --syn -m recent --name PORTSCANNERS --set -j DROP"
        echo "-A ${CHAIN} -p udp -m state --state NEW -m recent --name PORTSCANNERS --set -j DROP"
    fi
    echo ""

    echo "# ── ICMP rate-limit ─────────────────────────────────────────────────"
    if [[ "$FAMILY" == "4" ]]; then
        echo "-A ${CHAIN} -p icmp --icmp-type echo-request -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name icmp_rate -j DROP"
    else
        echo "-A ${CHAIN} -p ipv6-icmp --icmpv6-type echo-request -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name icmp6_rate -j DROP"
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

# ── Blocklists (ipset) ───────────────────────────────────────────────────────
setup_blocklists() {
    section "Blocklists (ipset)"

    # Устанавливаем ipset если нет
    if ! command -v ipset &>/dev/null; then
        info "Устанавливаю ipset..."
        apt-get install -y -q ipset
    fi

    ok "ipset $(ipset --version | head -1)"

    # Создаём скрипт обновления
    info "Создаю скрипт обновления: ${BLOCKLIST_UPDATE_SCRIPT}"
    cat > "${BLOCKLIST_UPDATE_SCRIPT}" << 'UPDSCRIPT'
#!/bin/bash
# Авто-обновление ipset blocklists для ufw-antiscan
# Запускается systemd-таймером

set -euo pipefail

IPSET_NAME_V4="ANTISCAN-V4"
IPSET_NAME_V6="ANTISCAN-V6"
TMP_V4="ANTISCAN-V4-TMP"
TMP_V6="ANTISCAN-V6-TMP"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

log "Обновление blocklists..."

# Читаем URL из конфига
CONF="/etc/ufw-antiscan/blocklists.conf"
if [[ ! -f "$CONF" ]]; then
    log "ОШИБКА: конфиг не найден: $CONF"
    exit 1
fi
mapfile -t URLS < "$CONF"

# Создаём временные сеты
ipset create "$TMP_V4" hash:net family inet  hashsize 65536 maxelem 500000 2>/dev/null || ipset flush "$TMP_V4"
ipset create "$TMP_V6" hash:net family inet6 hashsize 65536 maxelem 500000 2>/dev/null || ipset flush "$TMP_V6"

TOTAL_V4=0
TOTAL_V6=0

for URL in "${URLS[@]}"; do
    [[ -z "$URL" || "$URL" == \#* ]] && continue
    log "Скачиваю: $URL"

    LINES=$(curl -fsSL --max-time 30 "$URL" 2>/dev/null || true)
    if [[ -z "$LINES" ]]; then
        log "WARN: не удалось скачать $URL — пропускаю"
        continue
    fi

    while IFS= read -r line; do
        line="${line%%#*}"   # убираем комментарии
        line="${line// /}"   # убираем пробелы
        [[ -z "$line" ]] && continue

        if [[ "$line" == *:* ]]; then
            ipset add "$TMP_V6" "$line" 2>/dev/null && ((TOTAL_V6++)) || true
        else
            ipset add "$TMP_V4" "$line" 2>/dev/null && ((TOTAL_V4++)) || true
        fi
    done <<< "$LINES"
done

# Атомарный swap (нет разрыва защиты во время обновления)
ipset create "$IPSET_NAME_V4" hash:net family inet  hashsize 65536 maxelem 500000 2>/dev/null || true
ipset create "$IPSET_NAME_V6" hash:net family inet6 hashsize 65536 maxelem 500000 2>/dev/null || true
ipset swap "$TMP_V4" "$IPSET_NAME_V4"
ipset swap "$TMP_V6" "$IPSET_NAME_V6"
ipset destroy "$TMP_V4" 2>/dev/null || true
ipset destroy "$TMP_V6" 2>/dev/null || true

log "Готово: IPv4=${TOTAL_V4} подсетей, IPv6=${TOTAL_V6} подсетей"
UPDSCRIPT

    chmod +x "${BLOCKLIST_UPDATE_SCRIPT}"

    # ipset-наборы не переживают перезагрузку. Создаём их до запуска UFW,
    # иначе iptables-restore не сможет загрузить before.rules при старте ОС.
    cat > "${IPSET_BOOTSTRAP_SCRIPT}" << 'BOOTSTRAP'
#!/bin/sh
set -eu

ipset create ANTISCAN-V4 hash:net family inet  hashsize 65536 maxelem 500000 2>/dev/null || true
ipset create ANTISCAN-V6 hash:net family inet6 hashsize 65536 maxelem 500000 2>/dev/null || true
BOOTSTRAP
    chmod +x "${IPSET_BOOTSTRAP_SCRIPT}"

    cat > /etc/systemd/system/ufw-antiscan-ipsets.service << BOOTEOF
[Unit]
Description=ufw-antiscan: создать ipset-наборы до запуска UFW
DefaultDependencies=no
After=local-fs.target
Before=ufw.service

[Service]
Type=oneshot
ExecStart=${IPSET_BOOTSTRAP_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
BOOTEOF

    mkdir -p /etc/systemd/system/ufw.service.d
    cat > /etc/systemd/system/ufw.service.d/ufw-antiscan-ipsets.conf << 'DROPINEOF'
[Unit]
Requires=ufw-antiscan-ipsets.service
After=ufw-antiscan-ipsets.service
DROPINEOF

    systemctl daemon-reload
    systemctl enable ufw-antiscan-ipsets.service 2>/dev/null
    systemctl restart ufw-antiscan-ipsets.service
    ok "ipset bootstrap настроен до запуска UFW"

    # Сохраняем URLs в конфиг
    mkdir -p /etc/ufw-antiscan
    : > /etc/ufw-antiscan/blocklists.conf
    for URL in $BLOCKLIST_URLS; do
        echo "$URL" >> /etc/ufw-antiscan/blocklists.conf
    done
    ok "Конфиг → /etc/ufw-antiscan/blocklists.conf"

    # Запускаем первое обновление сразу
    info "Первичная загрузка списков (может занять несколько секунд)..."
    bash "${BLOCKLIST_UPDATE_SCRIPT}" && ok "Blocklists загружены" || warn "Ошибка загрузки — проверь интернет-доступ"

    # Systemd-таймер для авто-обновления
    cat > /etc/systemd/system/ufw-antiscan-blocklists.service << SVCEOF
[Unit]
Description=ufw-antiscan: обновление IP-blocklists
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${BLOCKLIST_UPDATE_SCRIPT}
StandardOutput=journal
StandardError=journal
SVCEOF

    cat > /etc/systemd/system/ufw-antiscan-blocklists.timer << TMREOF
[Unit]
Description=ufw-antiscan: авто-обновление blocklists каждые ${BLOCKLIST_UPDATE_INTERVAL}
After=network-online.target

[Timer]
OnBootSec=2min
OnUnitActiveSec=${BLOCKLIST_UPDATE_INTERVAL}
Persistent=true

[Install]
WantedBy=timers.target
TMREOF

    systemctl daemon-reload
    systemctl enable --now ufw-antiscan-blocklists.timer 2>/dev/null
    ok "Systemd-таймер: обновление каждые ${BLOCKLIST_UPDATE_INTERVAL}"

    # Статистика
    V4_COUNT=$(ipset list "${IPSET_NAME_V4}" 2>/dev/null | awk '/^Number of entries:/ {print $4; found=1} END {if (!found) print 0}')
    V6_COUNT=$(ipset list "${IPSET_NAME_V6}" 2>/dev/null | awk '/^Number of entries:/ {print $4; found=1} END {if (!found) print 0}')
    ok "Загружено: IPv4=${V4_COUNT} подсетей, IPv6=${V6_COUNT} подсетей"
}

if [[ "$ENABLE_BLOCKLISTS" == "1" && "$DRY_RUN" == "0" ]]; then
    setup_blocklists
elif [[ "$ENABLE_BLOCKLISTS" == "1" && "$DRY_RUN" == "1" ]]; then
    dry "Blocklists: будут загружены из:"
    for URL in $BLOCKLIST_URLS; do
        dry "  $URL"
    done
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

# ── Проверка сгенерированных UFW-файлов ──────────────────────────────────────
validate_ufw_rules() {
    local failed=0

    info "Проверяю синтаксис /etc/ufw/before.rules..."
    if ! iptables-restore --test < /etc/ufw/before.rules; then
        warn "Ошибка синтаксиса IPv4 ruleset"
        failed=1
    fi

    if [[ -f /etc/ufw/before6.rules ]]; then
        if ! command -v ip6tables-restore &>/dev/null; then
            warn "ip6tables-restore не найден, IPv6 ruleset проверить невозможно"
            failed=1
        else
            info "Проверяю синтаксис /etc/ufw/before6.rules..."
            if ! ip6tables-restore --test < /etc/ufw/before6.rules; then
                warn "Ошибка синтаксиса IPv6 ruleset"
                failed=1
            fi
        fi
    fi

    if [[ "$failed" != "0" ]]; then
        warn "Возвращаю исходные UFW-файлы из бэкапа"
        cp "$BACKUP_DIR/before.rules.bak" /etc/ufw/before.rules
        if [[ -f "$BACKUP_DIR/before6.rules.bak" ]]; then
            cp "$BACKUP_DIR/before6.rules.bak" /etc/ufw/before6.rules
        fi
        err "Правила не применены. Исходные UFW-файлы восстановлены: $BACKUP_DIR"
    fi

    ok "Синтаксис IPv4/IPv6 правил корректен"
}

# ── Применяем всё ─────────────────────────────────────────────────────────────
section "Применение"

validate_ufw_rules

# Safety timer: если через SAFETY_TIMER секунд скрипт ещё не завершился нормально,
# автоматически восстанавливаем бэкап. Защита от потери SSH-доступа.
SAFETY_PID=""
if [[ "$SAFETY_TIMER" -gt 0 ]]; then
    (
        sleep "$SAFETY_TIMER"
        echo ""
        echo -e "\033[0;31m[!] SAFETY ROLLBACK: $SAFETY_TIMER сек прошло, что-то пошло не так!\033[0m"
        echo -e "\033[0;31m[!] Восстанавливаю исходные правила из бэкапа...\033[0m"
        cp "$BACKUP_DIR/before.rules.bak" /etc/ufw/before.rules 2>/dev/null || true
        [[ -f "$BACKUP_DIR/before6.rules.bak" ]] &&             cp "$BACKUP_DIR/before6.rules.bak" /etc/ufw/before6.rules 2>/dev/null || true
        ufw reload 2>/dev/null || true
        echo -e "\033[0;32m[✔] Исходные правила восстановлены\033[0m"
    ) &
    SAFETY_PID=$!
    info "Safety timer запущен (PID ${SAFETY_PID}): автооткат через ${SAFETY_TIMER} сек"
fi

systemctl enable --now fail2ban 2>/dev/null || true
systemctl restart fail2ban
ufw reload

# Проверяем что SSH-порт слушает после применения
sleep 2
if ss -tlnp 2>/dev/null | grep -q ":${SSH_PORT} "; then
    ok "SSH (порт ${SSH_PORT}) слушает — соединение не потеряно"
else
    warn "SSH-порт ${SSH_PORT} не обнаружен после reload!"
fi

# Отменяем safety timer — всё ок
if [[ -n "$SAFETY_PID" ]]; then
    kill "$SAFETY_PID" 2>/dev/null &&         ok "Safety timer отменён — правила применены успешно" || true
fi

ok "UFW перезагружен, fail2ban запущен"

# ── Финальный статус ──────────────────────────────────────────────────────────
section "Статус"

echo ""
echo -e "${BOLD}Правила UFW:${NC}"
ufw status numbered 2>/dev/null | head -20

echo ""
echo -e "${BOLD}Portscan-баны:${NC}"
RECENT_FILE=""
for candidate in \
    /proc/net/xt_recent/PORTSCANNERS \
    /proc/net/ipt_recent/PORTSCANNERS; do
    if [[ -r "$candidate" ]]; then
        RECENT_FILE="$candidate"
        break
    fi
done

if [[ -n "$RECENT_FILE" ]]; then
    SCAN_COUNT=$(wc -l < "$RECENT_FILE")
else
    SCAN_COUNT=0
fi
echo "  Заблокировано IP: ${SCAN_COUNT}"

echo ""
echo -e "${BOLD}fail2ban SSH:${NC}"
fail2ban-client status sshd 2>/dev/null || true

if [[ "$ENABLE_BLOCKLISTS" == "1" ]]; then
    echo ""
    echo -e "${BOLD}Blocklists (ipset):${NC}"
    V4_COUNT=$(ipset list "${IPSET_NAME_V4}" 2>/dev/null | awk '/^Number of entries:/ {print $4; found=1} END {if (!found) print 0}')
    V6_COUNT=$(ipset list "${IPSET_NAME_V6}" 2>/dev/null | awk '/^Number of entries:/ {print $4; found=1} END {if (!found) print 0}')
    echo "  Загружено подсетей: IPv4=${V4_COUNT}, IPv6=${V6_COUNT}"
    NEXT=$(systemctl status ufw-antiscan-blocklists.timer 2>/dev/null | awk '/Trigger:/{print $2,$3}' || echo 'нет таймера')
    echo "  Следующее обновление: ${NEXT}"
fi

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
RECENT_FILE_DISPLAY="${RECENT_FILE:-/proc/net/xt_recent/PORTSCANNERS}"
echo "  Portscan-баны:            cat ${RECENT_FILE_DISPLAY}"
echo "  Разбанить всех сканеров:  echo / > ${RECENT_FILE_DISPLAY}"
echo "  SSH-баны:                 fail2ban-client status sshd"
echo "  CrowdSec-баны:            cscli decisions list"
echo "  Blocklist-статистика:     ipset list ANTISCAN-V4 | tail -3"
echo "  Обновить blocklists:      systemctl start ufw-antiscan-blocklists"
echo ""
