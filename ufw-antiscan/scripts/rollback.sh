#!/bin/bash
# ufw-antiscan/scripts/rollback.sh
# Откат всех изменений, внесённых protect.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[✔]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✘]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

[[ $EUID -ne 0 ]] && err "Нужен root: sudo bash $0"

MARKER_START="# === UFW-ANTISCAN START ==="
MARKER_END="# === UFW-ANTISCAN END ==="

section "Откат ufw-antiscan"

# ── Удаляем правила из before.rules ──────────────────────────────────────────
remove_block() {
    local FILE="$1"
    if [[ ! -f "$FILE" ]]; then return; fi

    if grep -q "UFW-ANTISCAN START" "$FILE" 2>/dev/null; then
        python3 -c "
import re
with open('${FILE}', 'r') as f:
    c = f.read()
c = re.sub(r'\n?# === UFW-ANTISCAN START ===.*?# === UFW-ANTISCAN END ===\n?', '\n', c, flags=re.DOTALL)
with open('${FILE}', 'w') as f:
    f.write(c)
"
        ok "Блок правил удалён из ${FILE}"
    else
        info "Блок не найден в ${FILE} — пропускаю"
    fi
}

remove_block /etc/ufw/before.rules
remove_block /etc/ufw/before6.rules

# ── Удаляем fail2ban jail ─────────────────────────────────────────────────────
section "fail2ban"

F2B_JAIL="/etc/fail2ban/jail.d/ufw-antiscan-ssh.conf"
if [[ -f "$F2B_JAIL" ]]; then
    rm -f "$F2B_JAIL"
    ok "fail2ban SSH jail удалён"
    systemctl restart fail2ban 2>/dev/null || true
else
    info "fail2ban jail не найден — пропускаю"
fi

# ── Сброс portscan-банов ──────────────────────────────────────────────────────
section "Portscan-баны"

if [[ -f /proc/net/ipt_recent/PORTSCANNERS ]]; then
    echo / > /proc/net/ipt_recent/PORTSCANNERS
    ok "Список PORTSCANNERS очищен"
else
    info "Список PORTSCANNERS не найден — пропускаю"
fi

# ── CrowdSec ──────────────────────────────────────────────────────────────────
section "CrowdSec"

PURGE_CROWDSEC="${PURGE_CROWDSEC:-0}"

if [[ "$PURGE_CROWDSEC" == "1" ]]; then
    warn "PURGE_CROWDSEC=1 — удаляю CrowdSec полностью"
    systemctl stop crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
    apt-get remove -y crowdsec crowdsec-firewall-bouncer-iptables 2>/dev/null || true
    rm -rf /etc/crowdsec /var/lib/crowdsec
    ok "CrowdSec удалён"
else
    info "CrowdSec оставлен (удалить: PURGE_CROWDSEC=1 bash scripts/rollback.sh)"
    if command -v cscli &>/dev/null; then
        systemctl stop crowdsec-firewall-bouncer 2>/dev/null || true
        ok "CrowdSec bouncer остановлен (агент продолжает работать)"
    fi
fi

# ── Восстановление из бэкапа ──────────────────────────────────────────────────
section "Бэкап"

LATEST_BACKUP=$(ls -dt /var/backups/ufw-antiscan/*/ 2>/dev/null | head -1 || true)
if [[ -n "$LATEST_BACKUP" ]]; then
    info "Найден бэкап: ${LATEST_BACKUP}"
    echo -n "Восстановить before.rules из бэкапа? [y/N] "
    read -r ANSWER
    if [[ "${ANSWER,,}" == "y" ]]; then
        cp "${LATEST_BACKUP}/before.rules.bak"  /etc/ufw/before.rules
        [[ -f "${LATEST_BACKUP}/before6.rules.bak" ]] && \
            cp "${LATEST_BACKUP}/before6.rules.bak" /etc/ufw/before6.rules
        ok "Файлы восстановлены из бэкапа"
    fi
else
    info "Бэкапы не найдены"
fi

# ── UFW reload ────────────────────────────────────────────────────────────────
ufw reload
ok "UFW перезагружен"

echo ""
echo -e "${GREEN}${BOLD}✔ Откат завершён${NC}"
echo ""
