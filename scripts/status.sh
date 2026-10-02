#!/bin/bash
# ufw-antiscan/scripts/status.sh
# Read-only отчёт о состоянии защиты

set -euo pipefail
export LC_ALL=C

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()      { echo -e "  ${GREEN}✔${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}▲${NC}  $*"; }
bad()     { echo -e "  ${RED}✘${NC}  $*"; }
section() { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

echo ""
echo -e "${BOLD}ufw-antiscan — статус защиты${NC}"
echo -e "$(date)"

# ── UFW ───────────────────────────────────────────────────────────────────────
section "UFW"
if [[ -f /var/lib/ufw-antiscan/pending ]]; then
    warn "Применение не подтверждено; ожидается автоматический откат"
fi

UFW_STATUS=$(ufw status 2>/dev/null | head -1 || true)
if [[ "$UFW_STATUS" == "Status: active" ]]; then
    ok "UFW активен"
elif grep -q "UFW-ANTISCAN START" /etc/ufw/before.rules 2>/dev/null; then
    bad "UFW неактивен при установленных Experimental-правилах"
else
    warn "UFW неактивен; для режима Basic он не обязателен"
fi

if grep -q "UFW-ANTISCAN START" /etc/ufw/before.rules 2>/dev/null; then
    ok "Правила ufw-antiscan записаны (before.rules)"
    if iptables -S ufw-antiscan >/dev/null 2>&1; then
        if iptables -C ufw-before-input -j ufw-antiscan >/dev/null 2>&1; then
            ok "Цепочка IPv4 подключена"
        else
            bad "Цепочка IPv4 есть, но переход к ней отсутствует"
        fi
    else
        bad "Цепочка IPv4 не загружена"
    fi
else
    warn "Experimental-правила не установлены"
fi

# ── SSH Basic ─────────────────────────────────────────────────────────────────
section "SSH Basic"
SSH_DROPIN=/etc/ssh/sshd_config.d/00-remnanode-antiscan.conf
if [[ -f "$SSH_DROPIN" ]]; then
    ok "Управляемая SSH-конфигурация установлена"
    SSHD=$(command -v sshd 2>/dev/null || true)
    [[ -n "$SSHD" ]] || [[ ! -x /usr/sbin/sshd ]] || SSHD=/usr/sbin/sshd
    if [[ -n "$SSHD" ]]; then
        EFFECTIVE=$("$SSHD" -T 2>/dev/null || true)
        PUBKEY=$(awk '$1=="pubkeyauthentication"{print $2}' <<< "$EFFECTIVE")
        PASSWORD=$(awk '$1=="passwordauthentication"{print $2}' <<< "$EFFECTIVE")
        KBD=$(awk '$1=="kbdinteractiveauthentication"{print $2}' <<< "$EFFECTIVE")
        echo "    PubkeyAuthentication:       ${PUBKEY:-?}"
        echo "    PasswordAuthentication:     ${PASSWORD:-?}"
        echo "    KbdInteractiveAuthentication: ${KBD:-?}"
        [[ "$PUBKEY" == yes && "$PASSWORD" == no && "$KBD" == no ]] \
            && ok "Вход по ключу включён, парольные методы отключены" \
            || warn "Эффективная конфигурация SSH отличается от ожидаемой"
    else
        bad "sshd не найден"
    fi
else
    warn "Basic не управляет парольной аутентификацией SSH"
fi

# ── Portscan-баны ─────────────────────────────────────────────────────────────
section "AntiScan (ipt_recent)"

RECENT_FILE=/proc/net/xt_recent/PORTSCANNERS
[[ -r "$RECENT_FILE" ]] || RECENT_FILE=/proc/net/ipt_recent/PORTSCANNERS
PORTSCAN_ENABLED=0
if iptables -S ufw-antiscan 2>/dev/null | grep -q PORTSCANNERS; then
    PORTSCAN_ENABLED=1
    if [[ ! -r "$RECENT_FILE" ]]; then
        warn "Portscan autoban включён, но таблица xt_recent недоступна"
    else
        SCAN_COUNT=$(wc -l < "$RECENT_FILE")
        if [[ "$SCAN_COUNT" -gt 0 ]]; then
            warn "Записей recent (включая истёкшие): ${SCAN_COUNT}"
            echo ""
            echo -e "  ${BOLD}Последние 10 забаненных IP:${NC}"
            awk '{
                for(i=1;i<=NF;i++){
                    if($i ~ /^src=/) { gsub("src=","",$i); printf "    %s\n",$i }
                }
            }' "$RECENT_FILE" 2>/dev/null | tail -10
        else
            ok "Активных portscan-банов нет"
        fi
    fi
else
    warn "Portscan autoban не включён"
fi

# ── fail2ban ──────────────────────────────────────────────────────────────────
section "fail2ban (SSH)"

if command -v fail2ban-client &>/dev/null; then
    if systemctl is-active fail2ban &>/dev/null; then
        ok "fail2ban запущен"
        F2B_OUT=$(fail2ban-client status sshd 2>/dev/null || true)
        if [[ -n "$F2B_OUT" ]]; then
            BANNED=$(echo "$F2B_OUT" | awk '/Currently banned:/{print $NF}')
            TOTAL=$(echo "$F2B_OUT"  | awk '/Total banned/{print $NF}')
            echo "    Сейчас забанено: ${BANNED:-0}"
            echo "    Всего за всё время: ${TOTAL:-0}"
        fi
    else
        bad "fail2ban не запущен"
    fi
else
    warn "Fail2Ban не установлен (опционально)"
fi

# ── CrowdSec ──────────────────────────────────────────────────────────────────
section "CrowdSec"

if command -v cscli &>/dev/null; then
    if systemctl is-active crowdsec &>/dev/null; then
        ok "CrowdSec агент запущен"
    else
        bad "CrowdSec агент не запущен"
    fi

    if systemctl is-active crowdsec-firewall-bouncer &>/dev/null; then
        ok "CrowdSec bouncer запущен"
    else
        bad "CrowdSec bouncer не запущен"
    fi

    DECISIONS=$(cscli decisions list -o json 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin) or []))' 2>/dev/null || echo '?')
    ok "Решений, возвращённых cscli: ${DECISIONS}"

    # Топ-5 активных банов
    TOP=$(cscli decisions list 2>/dev/null | grep "^|" | head -6 || true)
    if [[ -n "$TOP" ]]; then
        echo ""
        echo -e "  ${BOLD}Последние решения:${NC}"
        echo "$TOP" | while IFS= read -r line; do
            echo "    $line"
        done
    fi
else
    warn "CrowdSec не установлен (опционально)"
fi

# ── Активные правила ──────────────────────────────────────────────────────────
section "Правила UFW"
ufw status numbered 2>/dev/null | sed -n '/./{p;}' | sed -n '1,30p' || warn "Не удалось прочитать правила UFW"

echo ""
echo -e "${BOLD}Команды управления:${NC}"
if [[ "$PORTSCAN_ENABLED" == 1 ]]; then
    echo "  Разбанить portscan-IP:    echo -<IP> > ${RECENT_FILE}"
    echo "  Разбанить всех сканеров:  echo / > ${RECENT_FILE}"
fi
echo "  Разбанить SSH (Fail2Ban): fail2ban-client set sshd unbanip <IP>"
echo "  Разбанить (CrowdSec):     cscli decisions delete --ip <IP>"
echo "  Откат:                    sudo bash install.sh rollback"
echo ""
