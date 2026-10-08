#!/bin/bash
# Uninstall owned rules; preserve unrelated UFW edits and pre-existing services.
set -Eeuo pipefail
export LC_ALL=C
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/state.sh"
[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ "${PURGE_CROWDSEC:-0}" == 0 ]] || {
    echo 'Automatic CrowdSec purge is no longer supported. Remove it separately if needed.' >&2
    exit 1
}
exec 9>"$LOCK_FILE"
flock -n 9 || { echo 'Another AntiScan operation is running' >&2; exit 1; }
FIREWALL_ORIGINAL="$STATE/original"
BASIC_ORIGINAL="$STATE/basic-original"
TUNING_BBR_ORIGINAL="$STATE/tuning-bbr-original"
TUNING_IPV6_ORIGINAL="$STATE/tuning-ipv6-original"
[[ -d "$FIREWALL_ORIGINAL" || -d "$BASIC_ORIGINAL" || \
   -d "$TUNING_BBR_ORIGINAL" || -d "$TUNING_IPV6_ORIGINAL" ]] || {
    echo 'No installation snapshot. Legacy installations require manual rollback from their backup.' >&2
    exit 1
}
# Keep an emergency snapshot before stopping services.
BACKUP=$(mktemp -d /var/backups/ufw-antiscan/uninstall.XXXXXXXX)
if [[ -d "$FIREWALL_ORIGINAL" ]]; then snapshot "$BACKUP/firewall-current" firewall; fi
if [[ -d "$BASIC_ORIGINAL" ]]; then snapshot "$BACKUP/basic-current" basic; fi
if [[ -d "$TUNING_BBR_ORIGINAL" || -d "$TUNING_IPV6_ORIGINAL" ]]; then
    snapshot "$BACKUP/tuning-current" tuning
    [[ ! -d "$TUNING_BBR_ORIGINAL" ]] || : > "$BACKUP/tuning-current/restore-bbr"
    [[ ! -d "$TUNING_IPV6_ORIGINAL" ]] || : > "$BACKUP/tuning-current/restore-ipv6"
fi
rollback_error() {
    local code=$?
    trap - ERR
    flock -u 8 2>/dev/null || true
    if [[ -d "$BACKUP/firewall-current" ]]; then
        restore_snapshot "$BACKUP/firewall-current" || echo "Firewall restore failed: $BACKUP" >&2
    fi
    if [[ -d "$BACKUP/basic-current" ]]; then
        restore_snapshot "$BACKUP/basic-current" || echo "Basic restore failed: $BACKUP" >&2
    fi
    if [[ -d "$BACKUP/tuning-current" ]]; then
        restore_snapshot "$BACKUP/tuning-current" || echo "Tuning restore failed: $BACKUP" >&2
    fi
    if [[ -f "$PENDING" ]]; then
        arm_safety "$(cat "$PENDING")" 180 || echo 'Failed to rearm recovery timer' >&2
    fi
    exit "$code"
}
trap rollback_error ERR
systemctl disable --now ufw-antiscan-safety.timer 2>/dev/null || true
# Compatibility cleanup for installations made before static IP lists were removed.
systemctl stop ufw-antiscan-blocklists.timer ufw-antiscan-blocklists.service 2>/dev/null || true
if [[ -d "$FIREWALL_ORIGINAL" ]]; then
    for family in 4 6; do
        name=before.rules; restore=iptables-restore
        if [[ $family == 6 ]]; then name=before6.rules; restore=ip6tables-restore; fi
        [[ -f "/etc/ufw/$name" ]] || continue
        cp -a "/etc/ufw/$name" "$BACKUP/$name"
        python3 "$SCRIPT_DIR/rules.py" remove "$BACKUP/$name"
        "$restore" --test < "$BACKUP/$name"
    done
    for name in before.rules before6.rules; do
        [[ -f "$BACKUP/$name" ]] || continue
        cp -a "$BACKUP/$name" "/etc/ufw/$name.antiscan-new"
        mv -f "/etc/ufw/$name.antiscan-new" "/etc/ufw/$name"
    done
    ufw reload
    remove_private_chains
fi

# Restore overlapping Basic/firewall files and services newest snapshot first,
# so the oldest baseline wins when both modes were installed at different times.
restore_owned() {
    local snap=$1
    restore_files "$snap" uninstall
    restore_services "$snap"
}
firewall_created=0; basic_created=0
ssh_changed=0
if [[ -d "$BASIC_ORIGINAL" ]] && snapshot_file_differs "$BASIC_ORIGINAL" "$SSH_DROPIN"; then
    ssh_changed=1
fi
[[ -f "$FIREWALL_ORIGINAL/created" ]] && firewall_created=$(cat "$FIREWALL_ORIGINAL/created")
[[ -f "$BASIC_ORIGINAL/created" ]] && basic_created=$(cat "$BASIC_ORIGINAL/created")
if [[ -d "$FIREWALL_ORIGINAL" && -d "$BASIC_ORIGINAL" ]]; then
    if [[ "$firewall_created" -gt "$basic_created" ]]; then
        restore_owned "$FIREWALL_ORIGINAL"
        restore_owned "$BASIC_ORIGINAL"
    else
        restore_owned "$BASIC_ORIGINAL"
        restore_owned "$FIREWALL_ORIGINAL"
    fi
elif [[ -d "$FIREWALL_ORIGINAL" ]]; then
    restore_owned "$FIREWALL_ORIGINAL"
elif [[ -d "$BASIC_ORIGINAL" ]]; then
    restore_owned "$BASIC_ORIGINAL"
fi
[[ "$ssh_changed" == 0 ]] || reload_ssh
[[ ! -d "$TUNING_BBR_ORIGINAL" ]] || restore_snapshot "$TUNING_BBR_ORIGINAL"
[[ ! -d "$TUNING_IPV6_ORIGINAL" ]] || restore_snapshot "$TUNING_IPV6_ORIGINAL"

# Only now are there no active references to legacy sets.
if [[ -d "$FIREWALL_ORIGINAL" ]]; then
    exec 8>/run/lock/ufw-antiscan-blocklists.lock
    flock -x 8
    if command -v ipset >/dev/null; then
        for name in ANTISCAN-V4 ANTISCAN-V6 ANTISCAN-V4-TMP ANTISCAN-V6-TMP; do
            if ipset list "$name" >/dev/null 2>&1; then ipset destroy "$name"; fi
        done
    fi
fi
rm -f "$PENDING"
disarm_safety
[[ ! -d "$FIREWALL_ORIGINAL" ]] || mv "$FIREWALL_ORIGINAL" "$BACKUP/original"
[[ ! -d "$BASIC_ORIGINAL" ]] || mv "$BASIC_ORIGINAL" "$BACKUP/basic-original"
[[ ! -d "$TUNING_BBR_ORIGINAL" ]] || mv "$TUNING_BBR_ORIGINAL" "$BACKUP/tuning-bbr-original"
[[ ! -d "$TUNING_IPV6_ORIGINAL" ]] || mv "$TUNING_IPV6_ORIGINAL" "$BACKUP/tuning-ipv6-original"
trap - ERR
rm -rf /usr/local/lib/ufw-antiscan
echo "AntiScan removed. SSH, kernel/network settings and pre-existing services restored. Backup: $BACKUP"
echo 'Installed packages were retained; unrelated UFW rules were preserved.'
echo 'Public keys added to authorized_keys were retained.'
