#!/bin/bash
# ufw-antiscan/scripts/status.sh
# Read-only отчёт о состоянии защиты

set -euo pipefail

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

UFW_STATUS=$(ufw status 2>/dev/null | head -1 || true)
if [[ "$UFW_STATUS" == *"active"* ]]; then
    ok "UFW активен"
else
    bad "UFW неактивен! Включи: sudo ufw enable"
fi

if grep -q "UFW-ANTISCAN START" /etc/ufw/before.rules 2>/dev/null; then
    ok "Правила ufw-antiscan установлены (before.rules)"
else
    bad "Правила ufw-antiscan НЕ установлены"
fi

# ── Portscan-баны ─────────────────────────────────────────────────────────────
section "AntiScan (ipt_recent)"

if [[ -f /proc/net/ipt_recent/PORTSCANNERS ]]; then
    SCAN_COUNT=$(grep -c "^" /proc/net/ipt_recent/PORTSCANNERS 2>/dev/null || echo 0)
    if [[ "$SCAN_COUNT" -gt 0 ]]; then
        warn "Заблокировано сканеров: ${SCAN_COUNT}"
        echo ""
        echo -e "  ${BOLD}Последние 10 забаненных IP:${NC}"
        awk '{
            for(i=1;i<=NF;i++){
                if($i ~ /^src=/) { gsub("src=","",$i); printf "    %s\n",$i }
            }
        }' /proc/net/ipt_recent/PORTSCANNERS 2>/dev/null | tail -10
    else
        ok "Активных portscan-банов нет"
    fi
else
    warn "Модуль ipt_recent не активен (правила ещё не применялись?)"
fi

# ── fail2ban ──────────────────────────────────────────────────────────────────
section "fail2ban (SSH)"

if command -v fail2ban-client &>/dev/null; then
    if systemctl is-active fail2ban &>/dev/null; then
        ok "fail2ban запущен"
        F2B_OUT=$(fail2ban-client status sshd 2>/dev/null || true)
        if [[ -n "$F2B_OUT" ]]; then
            BANNED=$(echo "$F2B_OUT" | awk '/Banned IP/{print $NF}')
            TOTAL=$(echo "$F2B_OUT"  | awk '/Total banned/{print $NF}')
            echo "    Сейчас забанено: ${BANNED:-0}"
            echo "    Всего за всё время: ${TOTAL:-0}"
        fi
    else
        bad "fail2ban не запущен"
    fi
else
    bad "fail2ban не установлен"
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

    DECISIONS=$(cscli decisions list 2>/dev/null | grep -c "^|" || echo 0)
    ok "Активных блокировок (community + local): ${DECISIONS}"

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
ufw status numbered 2>/dev/null | grep -v "^$" | head -30

echo ""
echo -e "${BOLD}Команды управления:${NC}"
echo "  Разбанить portscan-IP:    echo -<IP> > /proc/net/ipt_recent/PORTSCANNERS"
echo "  Разбанить всех сканеров:  echo / > /proc/net/ipt_recent/PORTSCANNERS"
echo "  Разбанить SSH (fail2ban): fail2ban-client unban <IP>"
echo "  Разбанить (CrowdSec):     cscli decisions delete --ip <IP>"
echo "  Откат:                    sudo bash install.sh rollback"
echo ""
