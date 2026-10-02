#!/bin/bash
# Root-owned state; shared by apply, confirm, timed restore and uninstall.
STATE=/var/lib/ufw-antiscan
PENDING=$STATE/pending
SSH_DROPIN=/etc/ssh/sshd_config.d/00-remnanode-antiscan.conf
FIREWALL_MANAGED_FILES=(
 /etc/ufw/before.rules /etc/ufw/before6.rules
 /etc/fail2ban/jail.d/ufw-antiscan-ssh.conf
 # Legacy blocklist artifacts are retained here only so upgrades and rollback
 # can remove or restore installations made by older releases safely.
 /usr/local/bin/ufw-antiscan-update-blocklists.sh
 /usr/local/bin/ufw-antiscan-ensure-ipsets.sh
 /etc/systemd/system/ufw-antiscan-ipsets.service
 /etc/systemd/system/ufw.service.d/ufw-antiscan-ipsets.conf
 /etc/systemd/system/ufw-antiscan-blocklists.service
 /etc/systemd/system/ufw-antiscan-blocklists.timer
 /etc/ufw-antiscan/blocklists.conf
 /var/lib/ufw-antiscan/current.restore
)
BASIC_MANAGED_FILES=(
 "$SSH_DROPIN"
 /etc/fail2ban/jail.d/ufw-antiscan-ssh.conf
)
FIREWALL_MANAGED_SERVICES=(ufw-antiscan-blocklists.timer ufw-antiscan-ipsets.service fail2ban crowdsec crowdsec-firewall-bouncer)
BASIC_MANAGED_SERVICES=(fail2ban crowdsec crowdsec-firewall-bouncer)

snapshot_kind() {
    if [[ -f "$1/kind" ]]; then
        cat "$1/kind"
    else
        # Snapshots made by releases before Basic mode were firewall snapshots.
        printf 'firewall\n'
    fi
}

managed_items() {
    local kind=$1
    local -n files_ref=$2 services_ref=$3
    case "$kind" in
        firewall)
            files_ref=("${FIREWALL_MANAGED_FILES[@]}")
            services_ref=("${FIREWALL_MANAGED_SERVICES[@]}")
            ;;
        basic)
            files_ref=("${BASIC_MANAGED_FILES[@]}")
            services_ref=("${BASIC_MANAGED_SERVICES[@]}")
            ;;
        *) return 1 ;;
    esac
}

snapshot() {
    local dest=$1 kind=${2:-firewall} file unit
    local -a files services
    managed_items "$kind" files services || return 1
    mkdir -p "$dest/files" "$dest/services"
    chmod 700 "$dest"
    printf '%s\n' "$kind" > "$dest/kind"
    date +%s%N > "$dest/created"
    for file in "${files[@]}"; do
        if [[ -e "$file" || -L "$file" ]]; then
            mkdir -p "$dest/files$(dirname "$file")"
            cp -a "$file" "$dest/files$file"
        fi
    done
    for unit in "${services[@]}"; do
        systemctl is-active "$unit" > "$dest/services/$unit.active" 2>/dev/null || true
        systemctl is-enabled "$unit" > "$dest/services/$unit.enabled" 2>/dev/null || true
    done
}
restore_files() {
    local dest=$1 file tmp kind
    local -a files services
    kind=$(snapshot_kind "$dest")
    managed_items "$kind" files services || return 1
    for file in "${files[@]}"; do
        [[ "${2:-}" == uninstall && "$file" == /etc/ufw/before*.rules ]] && continue
        if [[ -e "$dest/files$file" || -L "$dest/files$file" ]]; then
            mkdir -p "$(dirname "$file")" || return 1
            tmp=$(mktemp "$(dirname "$file")/.antiscan-restore.XXXXXXXX") || return 1
            rm -f "$tmp" || return 1
            if ! cp -a "$dest/files$file" "$tmp" || ! mv -fT "$tmp" "$file"; then
                rm -f "$tmp"
                return 1
            fi
        else
            rm -f "$file" || return 1
        fi
    done
}

snapshot_file_differs() {
    local dest=$1 file=$2 saved="$1/files$2"
    if [[ -e "$saved" || -L "$saved" ]]; then
        [[ -e "$file" || -L "$file" ]] || return 0
        cmp -s "$saved" "$file" || return 0
    elif [[ -e "$file" || -L "$file" ]]; then
        return 0
    fi
    return 1
}

restore_services() {
    local dest=$1 unit enabled active failed=0 kind
    local -a files services
    kind=$(snapshot_kind "$dest")
    managed_items "$kind" files services || return 1
    systemctl daemon-reload || return 1
    for unit in "${services[@]}"; do
        enabled=$(cat "$dest/services/$unit.enabled")
        active=$(cat "$dest/services/$unit.active")
        if [[ "$enabled" == enabled ]]; then
            systemctl enable "$unit" || failed=1
        elif [[ "$enabled" == enabled-runtime ]]; then
            systemctl enable --runtime "$unit" || failed=1
        elif [[ "$enabled" != masked && "$enabled" != static ]]; then
            systemctl disable "$unit" 2>/dev/null || true
        fi
        if [[ "$active" == active ]]; then
            systemctl restart "$unit" || failed=1
        else
            systemctl stop "$unit" 2>/dev/null || true
        fi
    done
    return "$failed"
}

reload_ssh() {
    local unit daemon
    if command -v sshd >/dev/null 2>&1; then
        daemon=$(command -v sshd)
    elif [[ -x /usr/sbin/sshd ]]; then
        daemon=/usr/sbin/sshd
    else
        return 1
    fi
    "$daemon" -t || return 1
    for unit in ssh.service sshd.service; do
        if systemctl is-active "$unit" >/dev/null 2>&1; then
            systemctl reload "$unit"
            return
        fi
    done
    return 1
}
remove_private_chains() {
    local binary chain
    for binary in iptables ip6tables; do
        chain=ufw-antiscan
        [[ "$binary" == ip6tables ]] && chain=ufw6-antiscan
        if command -v "$binary" >/dev/null && "$binary" -S "$chain" >/dev/null 2>&1; then
            "$binary" -F "$chain" || return 1
            "$binary" -X "$chain" || return 1
        fi
    done
}
restore_snapshot() {
    local dest=$1 failed=0 kind
    [[ -d "$dest/files" && -d "$dest/services" ]] || return 1
    kind=$(snapshot_kind "$dest")
    case "$kind" in
        firewall)
            systemctl stop ufw-antiscan-blocklists.timer ufw-antiscan-blocklists.service 2>/dev/null || true
            restore_files "$dest" || return 1
            # An older snapshot may contain rules referencing legacy ipsets. Restore
            # those sets before UFW only when its bootstrap script was restored too.
            if [[ -x /usr/local/bin/ufw-antiscan-ensure-ipsets.sh ]]; then
                /usr/local/bin/ufw-antiscan-ensure-ipsets.sh || failed=1
            fi
            ufw reload || return 1
            if ! grep -q 'UFW-ANTISCAN START' /etc/ufw/before.rules; then
                remove_private_chains || failed=1
            fi
            restore_services "$dest" || failed=1
            ;;
        basic)
            local ssh_changed=0
            snapshot_file_differs "$dest" "$SSH_DROPIN" && ssh_changed=1
            restore_files "$dest" || return 1
            [[ "$ssh_changed" == 0 ]] || reload_ssh || failed=1
            restore_services "$dest" || failed=1
            ;;
        *) return 1 ;;
    esac
    return "$failed"
}

arm_safety() {
    local backup=$1 seconds=$2 deadline
    if systemctl is-active ufw-antiscan-safety.service >/dev/null 2>&1; then
        echo 'Safety restore has already started' >&2
        return 1
    fi
    printf '%s\n' "$backup" > "$PENDING"
    systemctl disable --now ufw-antiscan-safety.timer 2>/dev/null || true
    systemctl reset-failed ufw-antiscan-safety.service 2>/dev/null || true
    deadline=$(date -u -d "@$(($(date +%s) + seconds))" '+%Y-%m-%d %H:%M:%S UTC') || return 1
    cat > /etc/systemd/system/ufw-antiscan-safety.service.antiscan-new <<'EOF'
[Unit]
Description=ufw-antiscan: restore unconfirmed protection
ConditionPathExists=/var/lib/ufw-antiscan/pending

[Service]
Type=oneshot
ExecStart=/usr/local/lib/ufw-antiscan/restore.sh
Restart=on-failure
RestartSec=10s
EOF
    cat > /etc/systemd/system/ufw-antiscan-safety.timer.antiscan-new <<EOF
[Unit]
Description=ufw-antiscan: persistent safety rollback timer

[Timer]
OnActiveSec=${seconds}s
OnCalendar=${deadline}
Persistent=true
AccuracySec=1s
RandomizedDelaySec=0
Unit=ufw-antiscan-safety.service

[Install]
WantedBy=timers.target
EOF
    chmod 644 /etc/systemd/system/ufw-antiscan-safety.service.antiscan-new \
              /etc/systemd/system/ufw-antiscan-safety.timer.antiscan-new
    mv -f /etc/systemd/system/ufw-antiscan-safety.service.antiscan-new \
          /etc/systemd/system/ufw-antiscan-safety.service
    mv -f /etc/systemd/system/ufw-antiscan-safety.timer.antiscan-new \
          /etc/systemd/system/ufw-antiscan-safety.timer
    systemctl daemon-reload
    systemctl enable --now ufw-antiscan-safety.timer
}

disarm_safety() {
    systemctl disable --now ufw-antiscan-safety.timer 2>/dev/null || true
    rm -f /etc/systemd/system/ufw-antiscan-safety.timer \
          /etc/systemd/system/ufw-antiscan-safety.service \
          /etc/systemd/system/ufw-antiscan-safety.timer.antiscan-new \
          /etc/systemd/system/ufw-antiscan-safety.service.antiscan-new
    systemctl daemon-reload
}

mark_confirmation_boundary() {
    local backup=$1
    [[ -n "${SSH_CONNECTION:-}" ]] || return 0
    [[ -r /proc/sys/kernel/random/boot_id ]] || return 1
    {
        cat /proc/sys/kernel/random/boot_id
        python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_BOOTTIME))'
    } > "$backup/require-new-after"
}
