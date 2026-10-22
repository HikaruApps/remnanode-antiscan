#!/bin/bash
# Block RKN/TSPU networks from auto-updated lists: ipsets + own INPUT chain.
#
# Commands:
#   apply    Install or reconfigure (safety timer + confirm, like other modes)
#   update   Download lists and swap them into the kernel sets (timer)
#   load     Create sets from the cache and install the chain (boot)
#   unload   Remove the chain and the sets
#   disable  Turn blocking off and remove its units and configuration
#   status   Short report
#   config   Print the effective settings (current config or defaults)
set -Eeuo pipefail
# Command substitutions must fail too (fetch_lists runs inside one).
shopt -s inherit_errexit
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/state.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
if [[ ! -t 1 || -n ${NO_COLOR:-} ]]; then RED='' GREEN='' YELLOW='' CYAN='' NC=''; fi
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[✔]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✘]${NC} $*" >&2; return 1; }

RKN_DEFAULT_URLS="https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/gn.lst https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/sn.lst"
RKN_MAXELEM=262144
# Global: EXIT traps run after function locals are gone.
RKN_WORK=""

[[ $EUID == 0 ]] || { echo 'Нужен root.' >&2; exit 1; }

# read_conf reuses the RKN_* names, so remember what the caller passed in.
# ${VAR+x} keeps "set but empty" distinct from "unset" (needed for WHITELIST).
[[ -z ${RKN_URLS+x} ]] || ENV_RKN_URLS=$RKN_URLS
[[ -z ${RKN_WHITELIST+x} ]] || ENV_RKN_WHITELIST=$RKN_WHITELIST
[[ -z ${WHITELIST+x} ]] || ENV_WHITELIST=$WHITELIST
[[ -z ${SSH_PORT+x} ]] || ENV_SSH_PORT=$SSH_PORT
[[ -z ${RKN_BLOCK_SSH+x} ]] || ENV_RKN_BLOCK_SSH=$RKN_BLOCK_SSH
[[ -z ${RKN_INTERVAL+x} ]] || ENV_RKN_INTERVAL=$RKN_INTERVAL

validate_settings() {
    python3 -I - "$RKN_URLS" "$RKN_WHITELIST" "$RKN_SSH_PORT" "$RKN_BLOCK_SSH" "$RKN_INTERVAL" <<'PY'
import ipaddress
import re
import sys

urls, whitelist, ssh_port, block_ssh, interval = sys.argv[1:]
items = urls.split()
if not items or len(items) > 10:
    raise SystemExit('Нужно от 1 до 10 URL списков')
for url in items:
    if not re.fullmatch(r"https://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+", url):
        raise SystemExit(f'Некорректный URL (нужен https): {url!r}')
for entry in filter(None, (e.strip() for e in whitelist.split(','))):
    try:
        ipaddress.ip_network(entry, strict=False)
    except ValueError:
        raise SystemExit(f'Некорректный адрес в whitelist: {entry!r}')
if not (ssh_port.isascii() and ssh_port.isdigit() and 1 <= int(ssh_port) <= 65535):
    raise SystemExit('Некорректный SSH-порт')
if block_ssh not in ('0', '1'):
    raise SystemExit('RKN_BLOCK_SSH должен быть 0 или 1')
if not re.fullmatch(r'[1-9][0-9]{0,3}(min|h|d)', interval):
    raise SystemExit('RKN_INTERVAL: например 30min, 6h или 1d')
PY
}

read_conf() {
    local key value
    [[ -f "$RKN_CONF" ]] || err "Блокировка РКН не настроена: $RKN_CONF не найден"
    RKN_URLS="" RKN_WHITELIST="" RKN_SSH_PORT=22 RKN_BLOCK_SSH=0 RKN_INTERVAL=6h
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        case "$key" in
            URLS) RKN_URLS=$value ;;
            WHITELIST) RKN_WHITELIST=$value ;;
            SSH_PORT) RKN_SSH_PORT=$value ;;
            BLOCK_SSH) RKN_BLOCK_SSH=$value ;;
            INTERVAL) RKN_INTERVAL=$value ;;
            ''|\#*) ;;
            *) err "Неизвестный параметр в $RKN_CONF: $key" ;;
        esac
    done < "$RKN_CONF"
    validate_settings
}

# Download every source into $1 and build $1/list. Any failed or malformed
# source aborts the update, so the previous list stays in force. $2 is the
# list to compare against for the shrink guard; empty disables the guard.
fetch_lists() {
    local work=$1 previous=${2-$RKN_CACHE} url index=0
    for url in $RKN_URLS; do
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --connect-timeout 10 --max-time 60 --max-filesize 16777216 --retry 2 \
            --output "$work/source-$index" "$url" \
            || { err "Не удалось скачать $url; остаётся предыдущий список"; return 1; }
        index=$((index + 1))
    done
    python3 -I - "$work" "$previous" "$RKN_MAXELEM" <<'PY'
import ipaddress
import sys
from pathlib import Path

work, maxelem = Path(sys.argv[1]), int(sys.argv[3])
previous = Path(sys.argv[2]) if sys.argv[2] else None
# Wider entries are skipped: a broken or hijacked list must not cut off
# whole providers (or the whole Internet) on every node at once.
MIN_PREFIX = {4: 16, 6: 32}
networks = {4: set(), 6: set()}
skipped = 0
for source in sorted(work.glob('source-*')):
    count = 0
    for number, raw in enumerate(source.read_text(encoding='ascii').splitlines(), 1):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            raise SystemExit(f'{source.name}:{number}: не подсеть ({line[:60]!r}); список отклонён')
        if net.prefixlen < MIN_PREFIX[net.version] or not net.is_global:
            skipped += 1
            continue
        networks[net.version].add(net)
        count += 1
    if not count:
        raise SystemExit(f'{source.name}: нет ни одной подсети; список отклонён')
collapsed = {v: sorted(ipaddress.collapse_addresses(n)) for v, n in networks.items()}
old = {4: 0, 6: 0}
if previous and previous.exists():
    for line in previous.read_text().splitlines():
        if line.strip():
            old[ipaddress.ip_network(line.strip()).version] += 1
for version in (4, 6):
    new = len(collapsed[version])
    if new > maxelem:
        raise SystemExit(f'IPv{version}: {new} подсетей, больше лимита {maxelem}')
    if old[version] and new < old[version] / 2:
        raise SystemExit(f'IPv{version}: список сократился с {old[version]} до {new}; оставлен предыдущий')
(work / 'list').write_text(''.join(f'{n}\n' for v in (4, 6) for n in collapsed[v]))
print(f'IPv4: {len(collapsed[4])}, IPv6: {len(collapsed[6])}, пропущено широких/служебных: {skipped}')
PY
}

# IPv6 sets are optional: a kernel booted with ipv6.disable=1 must still
# get IPv4 blocking.
RKN_HAVE_V6=0
create_sets() {
    ipset create "$RKN_SET4" hash:net family inet hashsize 4096 maxelem "$RKN_MAXELEM" -exist
    if ipset create "$RKN_SET6" hash:net family inet6 hashsize 4096 maxelem "$RKN_MAXELEM" -exist 2>/dev/null; then
        RKN_HAVE_V6=1
    fi
}

# Atomically replace one family's set with its networks from a list file.
swap_family() {
    local list=$1 set=$2 family=$3 pattern=':'
    [[ "$family" == inet6 ]] || pattern='^[^:]*$'
    ipset destroy "${set}-TMP" 2>/dev/null || true
    {
        printf 'create %s-TMP hash:net family %s hashsize 4096 maxelem %s\n' "$set" "$family" "$RKN_MAXELEM"
        { grep -E "$pattern" "$list" || true; } | awk -v s="${set}-TMP" 'NF { print "add " s " " $1 }'
    } | ipset restore
    ipset swap "${set}-TMP" "$set"
    ipset destroy "${set}-TMP"
}

swap_sets() {
    create_sets
    swap_family "$1" "$RKN_SET4" inet
    if [[ "$RKN_HAVE_V6" == 1 ]]; then
        swap_family "$1" "$RKN_SET6" inet6
    elif grep -q ':' "$1"; then
        warn "IPv6 недоступен: IPv6-подсети из списка пропущены"
    fi
}

load_family() {
    local family=$1 bin=iptables set=$RKN_SET4 entry
    if [[ "$family" == 6 ]]; then bin=ip6tables; set=$RKN_SET6; fi
    command -v "$bin" >/dev/null || return 0
    "$bin" -N "$RKN_CHAIN" 2>/dev/null || "$bin" -F "$RKN_CHAIN"
    "$bin" -A "$RKN_CHAIN" -i lo -j RETURN
    # Replies to the node's own connections and existing sessions stay intact.
    "$bin" -A "$RKN_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    IFS=',' read -ra entries <<< "$RKN_WHITELIST"
    for entry in "${entries[@]}"; do
        entry=${entry// /}
        [[ -n "$entry" ]] || continue
        if [[ "$family" == 4 && "$entry" == *:* ]] || [[ "$family" == 6 && "$entry" != *:* ]]; then
            continue
        fi
        "$bin" -A "$RKN_CHAIN" -s "$entry" -j RETURN
    done
    if [[ "$RKN_BLOCK_SSH" != 1 ]]; then
        "$bin" -A "$RKN_CHAIN" -p tcp --dport "$RKN_SSH_PORT" -j RETURN
    fi
    "$bin" -A "$RKN_CHAIN" -m set --match-set "$set" src -j DROP
    "$bin" -C INPUT -j "$RKN_CHAIN" 2>/dev/null || "$bin" -I INPUT 1 -j "$RKN_CHAIN"
}

load() {
    exec 8>"$RKN_LOCK"
    flock -x 8
    read_conf
    if [[ -s "$RKN_CACHE" ]]; then swap_sets "$RKN_CACHE"; else create_sets; fi
    load_family 4
    # IPv6 may be disabled in the kernel; IPv4 blocking must still work.
    if [[ "$RKN_HAVE_V6" == 1 ]]; then
        load_family 6 || warn "IPv6-цепочка РКН не загружена"
    fi
    ok "Блокировка подсетей РКН загружена"
}

unload() {
    local bin
    exec 8>"$RKN_LOCK"
    flock -x 8
    for bin in iptables ip6tables; do
        command -v "$bin" >/dev/null || continue
        while "$bin" -D INPUT -j "$RKN_CHAIN" 2>/dev/null; do :; done
        "$bin" -F "$RKN_CHAIN" 2>/dev/null || true
        "$bin" -X "$RKN_CHAIN" 2>/dev/null || true
    done
    if command -v ipset >/dev/null; then
        for set in "$RKN_SET4" "$RKN_SET6" "${RKN_SET4}-TMP" "${RKN_SET6}-TMP"; do
            ipset destroy "$set" 2>/dev/null || true
        done
    fi
}

update() {
    local summary
    exec 8>"$RKN_LOCK"
    flock -x 8
    read_conf
    RKN_WORK=$(mktemp -d "$STATE/rkn-update.XXXXXXXX")
    trap 'rm -rf -- "${RKN_WORK:-}"' EXIT
    summary=$(fetch_lists "$RKN_WORK")
    swap_sets "$RKN_WORK/list"
    install -m 600 "$RKN_WORK/list" "$RKN_CACHE.antiscan-new"
    mv -f "$RKN_CACHE.antiscan-new" "$RKN_CACHE"
    ok "Списки РКН обновлены: $summary"
}

# Report whether the SSH client address is inside the downloaded list.
admin_listed() {
    local source_ip
    source_ip=$(awk '{print $1}' <<< "${SSH_CONNECTION:-}")
    [[ -n "$source_ip" ]] || return 1
    python3 -I - "$1" "$source_ip" "$RKN_WHITELIST" <<'PY'
import ipaddress
import sys

path, source, whitelist = sys.argv[1:]
address = ipaddress.ip_address(source)
trusted = [ipaddress.ip_network(e.strip(), strict=False) for e in whitelist.split(',') if e.strip()]
if any(address in net for net in trusted):
    raise SystemExit(1)
for line in open(path):
    if line.strip() and address in ipaddress.ip_network(line.strip()):
        print(line.strip())
        raise SystemExit(0)
raise SystemExit(1)
PY
}

write_units() {
    cat > "/etc/systemd/system/$RKN_LOAD_UNIT" <<EOF
[Unit]
Description=remnanode-antiscan: block RKN networks
DefaultDependencies=no
After=local-fs.target ufw.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$RKN_LIB load
ExecStop=$RKN_LIB unload

[Install]
WantedBy=multi-user.target
EOF
    cat > "/etc/systemd/system/$RKN_UPDATE_UNIT" <<EOF
[Unit]
Description=remnanode-antiscan: update RKN network lists
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$RKN_LIB update
EOF
    cat > "/etc/systemd/system/$RKN_TIMER_UNIT" <<EOF
[Unit]
Description=remnanode-antiscan: update RKN network lists every $RKN_INTERVAL

[Timer]
OnBootSec=10min
OnUnitActiveSec=$RKN_INTERVAL
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
EOF
    chmod 644 "/etc/systemd/system/$RKN_LOAD_UNIT" "/etc/systemd/system/$RKN_UPDATE_UNIT" \
        "/etc/systemd/system/$RKN_TIMER_UNIT"
}

# Explicit ENV wins, then the current config, then defaults. Re-applying
# without arguments therefore keeps the existing whitelist and settings.
resolve_settings() {
    local cur_urls="" cur_whitelist="" cur_ssh_port="" cur_block_ssh="" cur_interval=""
    if [[ -f "$RKN_CONF" ]]; then
        read_conf
        cur_urls=$RKN_URLS cur_whitelist=$RKN_WHITELIST cur_ssh_port=$RKN_SSH_PORT
        cur_block_ssh=$RKN_BLOCK_SSH cur_interval=$RKN_INTERVAL
    fi
    RKN_URLS=${ENV_RKN_URLS:-${cur_urls:-$RKN_DEFAULT_URLS}}
    # Set-but-empty WHITELIST clears it; unset keeps the current one.
    RKN_WHITELIST=${ENV_RKN_WHITELIST-${ENV_WHITELIST-$cur_whitelist}}
    RKN_SSH_PORT=${ENV_SSH_PORT:-$cur_ssh_port}
    if [[ -z "$RKN_SSH_PORT" ]]; then
        RKN_SSH_PORT=$(ss -tlnp 2>/dev/null \
            | awk '/sshd/{match($4,/[0-9]+$/); p=substr($4,RSTART,RLENGTH); if(p) print p}' | head -1 || true)
    fi
    RKN_SSH_PORT=${RKN_SSH_PORT:-22}
    RKN_BLOCK_SSH=${ENV_RKN_BLOCK_SSH:-${cur_block_ssh:-0}}
    RKN_INTERVAL=${ENV_RKN_INTERVAL:-${cur_interval:-6h}}
    validate_settings
}

config() {
    resolve_settings
    printf 'URLS=%s\nWHITELIST=%s\nSSH_PORT=%s\nBLOCK_SSH=%s\nINTERVAL=%s\n' \
        "$RKN_URLS" "$RKN_WHITELIST" "$RKN_SSH_PORT" "$RKN_BLOCK_SSH" "$RKN_INTERVAL"
}

apply() {
    local backup original_stage code listed project_root summary
    resolve_settings
    SAFETY_TIMER=${SAFETY_TIMER:-180}
    [[ "$SAFETY_TIMER" =~ ^[0-9]{1,10}$ ]] && (( 10#$SAFETY_TIMER >= 60 && 10#$SAFETY_TIMER <= 3600 )) \
        || err "SAFETY_TIMER должен быть от 60 до 3600 секунд"
    SAFETY_TIMER=$((10#$SAFETY_TIMER))
    for command in iptables curl python3 flock awk; do
        command -v "$command" >/dev/null || err "Не найдена команда: $command"
    done
    systemctl show-environment >/dev/null || err "Нужен работающий systemd"
    iptables -S >/dev/null || err "Нет доступа к netfilter (нужен CAP_NET_ADMIN)"
    recover_ssh_connection

    exec 9>"$LOCK_FILE"
    flock -n 9 || err "Другая операция AntiScan уже выполняется"
    mkdir -p "$STATE" /var/backups/ufw-antiscan
    chmod 700 "$STATE"
    [[ ! -f "$PENDING" ]] || err "Сначала подтвердите или откатите предыдущее применение"

    # Download and validate before anything on the system changes.
    RKN_WORK=$(mktemp -d "$STATE/rkn-apply.XXXXXXXX")
    trap 'rm -rf -- "${RKN_WORK:-}"' EXIT
    info "Скачиваю списки…"
    # A deliberate reconfiguration may switch to a smaller list.
    summary=$(fetch_lists "$RKN_WORK" "")
    ok "$summary"
    if listed=$(admin_listed "$RKN_WORK/list"); then
        if [[ "$RKN_BLOCK_SSH" == 1 ]]; then
            err "Ваш IP входит в $listed: с блокировкой SSH вы потеряете доступ. Добавьте IP в whitelist."
        fi
        warn "Ваш IP входит в $listed: SSH останется доступен, но VPN с этого адреса будет заблокирован."
    fi

    backup=$(mktemp -d /var/backups/ufw-antiscan/rkn.XXXXXXXX)
    snapshot "$backup" rkn
    if [[ ! -d "$STATE/rkn-original" ]]; then
        original_stage=$(mktemp -d "$STATE/rkn-original.XXXXXXXX")
        cp -a "$backup/." "$original_stage/"
        mv -T "$original_stage" "$STATE/rkn-original"
    fi
    printf '%s' "${SSH_CONNECTION:-}" > "$backup/ssh-connection"

    rollback_on_error() {
        code=$?
        trap - ERR INT TERM HUP
        echo "Применение блокировки РКН не удалось; восстанавливаю $backup" >&2
        if restore_snapshot "$backup"; then
            rm -f "$PENDING"
            disarm_safety || true
        else
            echo "ВОССТАНОВЛЕНИЕ НЕ УДАЛОСЬ. Бэкап: $backup" >&2
        fi
        exit "$code"
    }
    trap rollback_on_error ERR
    trap 'false' INT TERM HUP

    mkdir -p /usr/local/lib/ufw-antiscan
    install -m 644 "$SCRIPT_DIR/state.sh" /usr/local/lib/ufw-antiscan/state.sh
    install -m 755 "$SCRIPT_DIR/restore.sh" /usr/local/lib/ufw-antiscan/restore.sh
    install -m 755 "$SCRIPT_DIR/rkn.sh" "$RKN_LIB"
    arm_safety "$backup" 3600

    if ! command -v ipset >/dev/null; then
        info "Устанавливаю ipset..."
        apt-get update -q
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q ipset
    fi
    mkdir -p "$(dirname "$RKN_CONF")"
    printf 'URLS=%s\nWHITELIST=%s\nSSH_PORT=%s\nBLOCK_SSH=%s\nINTERVAL=%s\n' \
        "$RKN_URLS" "$RKN_WHITELIST" "$RKN_SSH_PORT" "$RKN_BLOCK_SSH" "$RKN_INTERVAL" > "$RKN_CONF.antiscan-new"
    chmod 644 "$RKN_CONF.antiscan-new"
    mv -f "$RKN_CONF.antiscan-new" "$RKN_CONF"
    install -m 600 "$RKN_WORK/list" "$RKN_CACHE"
    write_units
    systemctl daemon-reload
    systemctl enable "$RKN_LOAD_UNIT"
    systemctl restart "$RKN_LOAD_UNIT"
    systemctl enable --now "$RKN_TIMER_UNIT"
    iptables -C INPUT -j "$RKN_CHAIN" || err "Цепочка $RKN_CHAIN не подключена к INPUT"

    arm_safety "$backup" "$SAFETY_TIMER"
    mark_confirmation_boundary "$backup"
    trap - ERR INT TERM HUP
    project_root=$(cd "$SCRIPT_DIR/.." && pwd)
    ok "Подсети РКН блокируются; списки обновляются каждые $RKN_INTERVAL"
    [[ "$RKN_BLOCK_SSH" == 1 ]] || info "SSH-порт $RKN_SSH_PORT исключён из блокировки"
    warn "Проверьте новое SSH-подключение и VPN. Автооткат через ${SAFETY_TIMER} секунд."
    printf '  Из новой сессии: sudo bash %q confirm\n' "$project_root/install.sh"
    ok "Применено, ожидается подтверждение. Бэкап: $backup"
}

disable() {
    exec 9>"$LOCK_FILE"
    flock -n 9 || err "Другая операция AntiScan уже выполняется"
    [[ ! -f "$PENDING" ]] || err "Сначала подтвердите или откатите предыдущее применение"
    systemctl disable --now "$RKN_TIMER_UNIT" 2>/dev/null || true
    systemctl disable --now "$RKN_LOAD_UNIT" 2>/dev/null || true
    unload
    rm -f "${RKN_MANAGED_FILES[@]}"
    rmdir "$(dirname "$RKN_CONF")" 2>/dev/null || true
    systemctl daemon-reload
    ok "Блокировка подсетей РКН отключена"
}

status() {
    local count4 count6 drops dim='\033[2m'
    [[ -n "$NC" ]] || dim=''
    # Same markers as status.sh, since this output is embedded there.
    if ! [[ -f "$RKN_CONF" ]]; then
        echo -e "  ${dim}–  Блокировка подсетей РКН не включена${NC}"
        return 0
    fi
    if systemctl is-active "$RKN_LOAD_UNIT" >/dev/null 2>&1 && iptables -C INPUT -j "$RKN_CHAIN" 2>/dev/null; then
        count4=$(ipset list -t "$RKN_SET4" 2>/dev/null | awk -F': ' '/Number of entries/{print $2}')
        count6=$(ipset list -t "$RKN_SET6" 2>/dev/null | awk -F': ' '/Number of entries/{print $2}')
        drops=$(iptables -nvxL "$RKN_CHAIN" 2>/dev/null | awk '/match-set/{print $1; exit}')
        echo -e "  ${GREEN}✔${NC}  Блокировка РКН активна: IPv4 ${count4:-?}, IPv6 ${count6:-?} подсетей"
        echo "    Отброшено пакетов: ${drops:-?}"
    else
        echo -e "  ${RED}✘${NC}  Блокировка РКН настроена, но не загружена (systemctl status $RKN_LOAD_UNIT)"
    fi
    if [[ -f "$RKN_CACHE" ]]; then
        echo "    Последнее успешное обновление: $(date -r "$RKN_CACHE" '+%F %T')"
    fi
    if systemctl is-failed "$RKN_UPDATE_UNIT" >/dev/null 2>&1; then
        echo -e "  ${YELLOW}▲${NC}  Последнее обновление не удалось: journalctl -u $RKN_UPDATE_UNIT"
    fi
}

case "${1:-}" in
    apply) apply ;;
    update) update ;;
    load) load ;;
    unload) unload ;;
    disable) disable ;;
    status) status ;;
    config) config ;;
    *) echo "Использование: rkn.sh apply|update|load|unload|disable|status|config" >&2; exit 2 ;;
esac
