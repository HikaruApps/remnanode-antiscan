#!/bin/bash
# Root-owned state; shared by apply, confirm, timed restore and uninstall.
STATE=/var/lib/ufw-antiscan
PENDING=$STATE/pending
MANAGED_FILES=(
 /etc/ufw/before.rules /etc/ufw/before6.rules
 /etc/fail2ban/jail.d/ufw-antiscan-ssh.conf
 /usr/local/bin/ufw-antiscan-update-blocklists.sh
 /usr/local/bin/ufw-antiscan-ensure-ipsets.sh
 /etc/systemd/system/ufw-antiscan-ipsets.service
 /etc/systemd/system/ufw.service.d/ufw-antiscan-ipsets.conf
 /etc/systemd/system/ufw-antiscan-blocklists.service
 /etc/systemd/system/ufw-antiscan-blocklists.timer
 /etc/ufw-antiscan/blocklists.conf
 /var/lib/ufw-antiscan/current.restore
)
MANAGED_SERVICES=(ufw-antiscan-blocklists.timer ufw-antiscan-ipsets.service fail2ban crowdsec crowdsec-firewall-bouncer)
snapshot() {
    local dest=$1 file unit
    mkdir -p "$dest/files" "$dest/services"
    chmod 700 "$dest"
    for file in "${MANAGED_FILES[@]}"; do
        if [[ -e "$file" || -L "$file" ]]; then
            mkdir -p "$dest/files$(dirname "$file")"
            cp -a "$file" "$dest/files$file"
        fi
    done
    for unit in "${MANAGED_SERVICES[@]}"; do
        systemctl is-active "$unit" > "$dest/services/$unit.active" 2>/dev/null || true
        systemctl is-enabled "$unit" > "$dest/services/$unit.enabled" 2>/dev/null || true
    done
}
restore_files() {
    local dest=$1 file tmp
    for file in "${MANAGED_FILES[@]}"; do
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
restore_services() {
    local dest=$1 unit enabled active failed=0
    systemctl daemon-reload || return 1
    for unit in "${MANAGED_SERVICES[@]}"; do
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
    local dest=$1 failed=0
    [[ -d "$dest/files" && -d "$dest/services" ]] || return 1
    systemctl stop ufw-antiscan-blocklists.timer ufw-antiscan-blocklists.service 2>/dev/null || true
    restore_files "$dest" || return 1
    # Restore cached sets before reloading rules referencing them.
    if [[ -x /usr/local/bin/ufw-antiscan-ensure-ipsets.sh ]]; then
        /usr/local/bin/ufw-antiscan-ensure-ipsets.sh || failed=1
    fi
    ufw reload || return 1
    if ! grep -q 'UFW-ANTISCAN START' /etc/ufw/before.rules; then
        remove_private_chains || failed=1
    fi
    restore_services "$dest" || failed=1
    return "$failed"
}

arm_safety() {
    local backup=$1 seconds=$2
    printf '%s\n' "$backup" > "$PENDING"
    systemctl stop ufw-antiscan-safety.timer ufw-antiscan-safety.service 2>/dev/null || true
    systemctl reset-failed ufw-antiscan-safety.service 2>/dev/null || true
    systemd-run --collect --unit=ufw-antiscan-safety --on-active="${seconds}s" \
        --property=Restart=on-failure --property=RestartSec=10s \
        /usr/local/lib/ufw-antiscan/restore.sh
}
