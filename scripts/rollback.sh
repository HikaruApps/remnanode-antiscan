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
exec 9>/run/lock/ufw-antiscan.lock
flock -n 9 || { echo 'Another AntiScan operation is running' >&2; exit 1; }
[[ -d "$STATE/original" ]] || {
    echo 'No installation snapshot. Legacy installations require manual rollback from their backup.' >&2
    exit 1
}
# Keep an emergency snapshot before stopping services.
BACKUP=$(mktemp -d /var/backups/ufw-antiscan/uninstall.XXXXXXXX)
snapshot "$BACKUP"
rollback_error() {
    local code=$?
    trap - ERR
    flock -u 8 2>/dev/null || true
    restore_snapshot "$BACKUP" || echo "Restore failed: $BACKUP" >&2
    if [[ -f "$PENDING" ]]; then
        arm_safety "$(cat "$PENDING")" 180 || echo 'Failed to rearm recovery timer' >&2
    fi
    exit "$code"
}
trap rollback_error ERR
systemctl stop ufw-antiscan-safety.timer ufw-antiscan-safety.service 2>/dev/null || true
systemctl stop ufw-antiscan-blocklists.timer ufw-antiscan-blocklists.service 2>/dev/null || true
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
# Only now are there no active references to our sets.
restore_files "$STATE/original" uninstall
restore_services "$STATE/original"
exec 8>/run/lock/ufw-antiscan-blocklists.lock
flock -x 8
if command -v ipset >/dev/null; then
    for name in ANTISCAN-V4 ANTISCAN-V6 ANTISCAN-V4-TMP ANTISCAN-V6-TMP; do
        if ipset list "$name" >/dev/null 2>&1; then
            ipset destroy "$name"
        fi
    done
fi
rm -f "$PENDING"
mv "$STATE/original" "$BACKUP/original"
trap - ERR
rm -rf /usr/local/lib/ufw-antiscan
echo "AntiScan removed. Pre-existing services restored. Backup: $BACKUP"
echo 'Installed packages were retained; unrelated UFW rules were preserved.'
