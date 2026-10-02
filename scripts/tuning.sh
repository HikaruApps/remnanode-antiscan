#!/bin/bash
# Optional kernel/network tuning: BBR + CAKE defaults and explicit IPv6 state.
set -Eeuo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/state.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
if [[ ! -t 1 || -n ${NO_COLOR:-} ]]; then RED='' GREEN='' YELLOW='' NC=''; fi
err()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }
ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

recover_parent_ssh_connection() {
    python3 - "$$" <<'PY'
import os
import sys

pid = int(sys.argv[1])
seen = set()
while pid > 1 and pid not in seen:
    seen.add(pid)
    try:
        environment = open(f'/proc/{pid}/environ', 'rb').read().split(b'\0')
        for item in environment:
            if item.startswith(b'SSH_CONNECTION='):
                value = item.split(b'=', 1)[1].decode(errors='strict')
                if len(value.split()) == 4:
                    print(value)
                    raise SystemExit(0)
        raw = open(f'/proc/{pid}/stat').read()
        pid = int(raw.rsplit(')', 1)[1].split()[1])
    except (FileNotFoundError, PermissionError, UnicodeDecodeError, IndexError, ValueError):
        break
raise SystemExit(1)
PY
}

write_bbr_config() {
    local sysctl_stage modules_stage
    mkdir -p /etc/sysctl.d /etc/modules-load.d
    sysctl_stage=$(mktemp /etc/sysctl.d/.remnanode-bbr-cake.XXXXXXXX)
    modules_stage=$(mktemp /etc/modules-load.d/.remnanode-antiscan.XXXXXXXX)
    cat > "$sysctl_stage" <<'EOF'
# Managed by remnanode-antiscan. Applied to new TCP connections/interfaces.
net.core.default_qdisc = cake
net.ipv4.tcp_congestion_control = bbr
EOF
    cat > "$modules_stage" <<'EOF'
# Managed by remnanode-antiscan.
tcp_bbr
sch_cake
EOF
    chmod 644 "$sysctl_stage" "$modules_stage"
    chown root:root "$sysctl_stage" "$modules_stage"
    mv -f "$sysctl_stage" "$TUNING_BBR_SYSCTL"
    mv -f "$modules_stage" "$TUNING_MODULES"
}

write_ipv6_config() {
    local value=$1 stage
    mkdir -p /etc/sysctl.d
    stage=$(mktemp /etc/sysctl.d/.remnanode-ipv6.XXXXXXXX)
    cat > "$stage" <<EOF
# Managed by remnanode-antiscan.
net.ipv6.conf.default.disable_ipv6 = $value
net.ipv6.conf.all.disable_ipv6 = $value
EOF
    chmod 644 "$stage"
    chown root:root "$stage"
    mv -f "$stage" "$TUNING_IPV6_SYSCTL"
}

verify_ipv6_state() {
    local expected=$1 path iface
    for path in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
        [[ -f "$path" ]] || continue
        iface=${path%/disable_ipv6}
        iface=${iface##*/}
        [[ "$iface" != all ]] || continue
        [[ "$(cat "$path")" == "$expected" ]] || return 1
    done
}

apply_tuning() {
    local backup original_stage code ipv6_value="" available scope original
    local source_ip source_port local_ip local_port ssh_user server_address project_root
    ENABLE_BBR_CAKE=${ENABLE_BBR_CAKE:-0}
    IPV6_MODE=${IPV6_MODE:-keep}
    SAFETY_TIMER=${SAFETY_TIMER:-180}

    [[ "$ENABLE_BBR_CAKE" == 0 || "$ENABLE_BBR_CAKE" == 1 ]] \
        || err "ENABLE_BBR_CAKE должен быть 0 или 1"
    case "$IPV6_MODE" in
        keep) ;;
        enable) ipv6_value=0 ;;
        disable) ipv6_value=1 ;;
        *) err "IPV6_MODE должен быть keep, enable или disable" ;;
    esac
    [[ "$ENABLE_BBR_CAKE" == 1 || "$IPV6_MODE" != keep ]] || err "Не выбрано ни одного действия"
    [[ "$SAFETY_TIMER" =~ ^[0-9]{1,10}$ ]] || err "SAFETY_TIMER должен быть числом"
    (( 10#$SAFETY_TIMER >= 60 && 10#$SAFETY_TIMER <= 3600 )) \
        || err "SAFETY_TIMER должен быть от 60 до 3600 секунд"
    SAFETY_TIMER=$((10#$SAFETY_TIMER))

    [[ $EUID == 0 ]] || err "Запустите от root"
    for command in flock sysctl modprobe python3; do
        command -v "$command" >/dev/null || err "Не найдена команда: $command"
    done
    systemctl show-environment >/dev/null || err "Нужен работающий systemd"
    if [[ -z ${SSH_CONNECTION:-} ]]; then
        SSH_CONNECTION=$(recover_parent_ssh_connection || true)
        export SSH_CONNECTION
    fi

    if [[ "$ENABLE_BBR_CAKE" == 1 ]]; then
        [[ -e /proc/sys/net/core/default_qdisc ]] || err "Ядро не предоставляет net.core.default_qdisc"
        [[ -e /proc/sys/net/ipv4/tcp_congestion_control ]] || err "Ядро не поддерживает выбор TCP congestion control"
        modprobe -n tcp_bbr >/dev/null 2>&1 || err "Модуль tcp_bbr отсутствует для текущего ядра"
        modprobe -n sch_cake >/dev/null 2>&1 || err "Модуль sch_cake отсутствует для текущего ядра"
    fi

    if [[ "$IPV6_MODE" != keep ]]; then
        [[ -d /proc/sys/net/ipv6/conf ]] || err "IPv6 sysctl недоступен в текущем ядре"
        if [[ "$IPV6_MODE" == enable ]] && grep -Eq '(^| )ipv6\.(disable|disable_ipv6)=1( |$)' /proc/cmdline; then
            err "IPv6 отключён параметром ядра; удалите его из загрузчика и перезагрузите сервер"
        fi
        if [[ "$IPV6_MODE" == disable && -n ${SSH_CONNECTION:-} ]]; then
            read -r source_ip source_port local_ip local_port <<< "$SSH_CONNECTION"
            [[ "$local_ip" != *:* ]] || err "Нельзя отключить IPv6 из SSH-сессии, работающей по IPv6; используйте IPv4 или консоль хостера"
        fi
    fi

    exec 9>/run/lock/ufw-antiscan.lock
    flock -n 9 || err "Другая операция AntiScan уже выполняется"
    mkdir -p "$STATE" /var/backups/ufw-antiscan
    chmod 700 "$STATE"
    [[ ! -f "$PENDING" ]] || err "Сначала подтвердите или откатите предыдущее применение"

    backup=$(mktemp -d /var/backups/ufw-antiscan/tuning.XXXXXXXX)
    snapshot "$backup" tuning
    [[ "$ENABLE_BBR_CAKE" == 0 ]] || : > "$backup/restore-bbr"
    [[ "$IPV6_MODE" == keep ]] || : > "$backup/restore-ipv6"
    for scope in bbr ipv6; do
        [[ -f "$backup/restore-$scope" ]] || continue
        original="$STATE/tuning-$scope-original"
        [[ -d "$original" ]] && continue
        original_stage=$(mktemp -d "$STATE/tuning-$scope-original.XXXXXXXX")
        cp -a "$backup/." "$original_stage/"
        rm -f "$original_stage/restore-bbr" "$original_stage/restore-ipv6"
        : > "$original_stage/restore-$scope"
        mv -T "$original_stage" "$original"
    done
    printf '%s' "${SSH_CONNECTION:-}" > "$backup/ssh-connection"

    rollback_on_error() {
        code=$?
        trap - ERR INT TERM HUP
        echo "Tuning apply failed; restoring $backup" >&2
        if restore_snapshot "$backup"; then
            rm -f "$PENDING"
            disarm_safety || true
        else
            echo "RESTORE FAILED. Backup: $backup" >&2
        fi
        exit "$code"
    }
    trap rollback_on_error ERR
    trap 'false' INT TERM HUP

    mkdir -p /usr/local/lib/ufw-antiscan
    install -m 644 "$SCRIPT_DIR/state.sh" /usr/local/lib/ufw-antiscan/state.sh
    install -m 755 "$SCRIPT_DIR/restore.sh" /usr/local/lib/ufw-antiscan/restore.sh
    arm_safety "$backup" "$SAFETY_TIMER"

    if [[ "$ENABLE_BBR_CAKE" == 1 ]]; then
        modprobe tcp_bbr
        modprobe sch_cake
        available=$(sysctl -n net.ipv4.tcp_available_congestion_control)
        grep -qw bbr <<< "$available" || err "BBR не появился в списке доступных алгоритмов: $available"
        write_bbr_config
        sysctl -q -w net.core.default_qdisc=cake
        sysctl -q -w net.ipv4.tcp_congestion_control=bbr
        [[ "$(sysctl -n net.core.default_qdisc)" == cake ]] || err "Не удалось выбрать CAKE как default qdisc"
        [[ "$(sysctl -n net.ipv4.tcp_congestion_control)" == bbr ]] || err "Не удалось включить BBR"
        ok "BBR включён; CAKE выбран как default qdisc"
        warn "CAKE не заменяет qdisc активного интерфейса вслепую: он применится после reboot или пересоздания интерфейса."
        warn "Сначала подтвердите применение, и только затем перезагружайте сервер для активации CAKE на интерфейсе."
    fi

    if [[ "$IPV6_MODE" != keep ]]; then
        write_ipv6_config "$ipv6_value"
        sysctl -q -w "net.ipv6.conf.all.disable_ipv6=$ipv6_value"
        sysctl -q -w "net.ipv6.conf.default.disable_ipv6=$ipv6_value"
        verify_ipv6_state "$ipv6_value" || err "Не все интерфейсы приняли выбранное состояние IPv6"
        if [[ "$IPV6_MODE" == enable ]]; then
            ok "IPv6 включён; адреса могут появиться после DAD и настройки сети провайдером"
        else
            ok "IPv6 отключён на существующих и будущих интерфейсах"
        fi
    fi

    mark_confirmation_boundary "$backup"
    trap - ERR INT TERM HUP
    project_root=$(cd "$SCRIPT_DIR/.." && pwd)
    warn "Проверьте новое SSH-подключение и VPN. Автооткат через ${SAFETY_TIMER} секунд."
    if [[ -n ${SSH_CONNECTION:-} ]]; then
        read -r source_ip source_port local_ip local_port <<< "$SSH_CONNECTION"
        ssh_user=${SUDO_USER:-${USER:-root}}
        server_address=$local_ip
        [[ "$server_address" != *:* ]] || server_address="[$server_address]"
        printf '  ssh -o ControlMaster=no -o ControlPath=none -p %q %q@%q\n' \
            "$local_port" "$ssh_user" "$server_address"
    fi
    printf '  Из новой сессии: sudo --preserve-env=SSH_CONNECTION bash %q confirm\n' "$project_root/install.sh"
    ok "Дополнительные настройки применены и ожидают подтверждения. Бэкап: $backup"
}

case "${1:-}" in
    apply) apply_tuning ;;
    *) echo "Использование: tuning.sh apply" >&2; exit 2 ;;
esac
