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
else
    bad "UFW неактивен! Включи: sudo ufw enable"
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
    bad "Правила ufw-antiscan НЕ установлены"
fi

# ── Portscan-баны ─────────────────────────────────────────────────────────────
section "AntiScan (ipt_recent)"

RECENT_FILE=/proc/net/xt_recent/PORTSCANNERS
[[ -r "$RECENT_FILE" ]] || RECENT_FILE=/proc/net/ipt_recent/PORTSCANNERS
if [[ -r "$RECENT_FILE" ]]; then
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
else
    warn "Модуль ipt_recent не активен (правила ещё не применялись?)"
fi

# ── Blocklists (ipset) ───────────────────────────────────────────────────────
section "Blocklists (ipset)"

if command -v ipset &>/dev/null; then
    V4_COUNT=$(ipset list ANTISCAN-V4 2>/dev/null | awk '/^Number of entries:/ {n=$4} END {print n+0}' || true)
    V6_COUNT=$(ipset list ANTISCAN-V6 2>/dev/null | awk '/^Number of entries:/ {n=$4} END {print n+0}' || true)

    if [[ "$V4_COUNT" -gt 0 || "$V6_COUNT" -gt 0 ]]; then
        ok "ipset активен: IPv4=${V4_COUNT} подсетей, IPv6=${V6_COUNT} подсетей"
    else
        warn "ipset сеты пусты или не созданы"
    fi

    if systemctl is-active ufw-antiscan-blocklists.timer &>/dev/null; then
        NEXT=$(systemctl status ufw-antiscan-blocklists.timer 2>/dev/null             | awk '/Trigger:/{print $2,$3}' || echo '?')
        ok "Таймер обновления активен, следующий запуск: ${NEXT}"
    else
        warn "Таймер обновления не активен (sudo systemctl start ufw-antiscan-blocklists.timer)"
    fi

    # Последнее обновление
    LAST=$(journalctl -u ufw-antiscan-blocklists.service --no-pager -n 1 2>/dev/null         | awk '{print $1,$2,$3}' || echo '?')
    echo "  Последнее обновление: ${LAST}"
else
    warn "ipset не установлен (blocklists не активны)"
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
echo "  Разбанить portscan-IP:    echo -<IP> > ${RECENT_FILE}"
echo "  Разбанить всех сканеров:  echo / > ${RECENT_FILE}"
echo "  Разбанить SSH (fail2ban): fail2ban-client unban <IP>"
echo "  Разбанить (CrowdSec):     cscli decisions delete --ip <IP>"
echo "  Откат:                    sudo bash install.sh rollback"
echo "  Обновить blocklists:      systemctl start ufw-antiscan-blocklists"
echo "  Логи обновления:          journalctl -u ufw-antiscan-blocklists -f"
echo ""
