#!/bin/bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/state.sh"
[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
exec 9>/run/lock/ufw-antiscan.lock
flock -x 9
[[ -f "$PENDING" ]] || { echo 'No pending application'; exit 0; }
BACKUP=$(cat "$PENDING")
# Require a different SSH connection when installation ran over SSH.
if [[ -s "$BACKUP/ssh-connection" ]]; then
    [[ -n "${SSH_CONNECTION:-}" && "$SSH_CONNECTION" != "$(cat "$BACKUP/ssh-connection")" ]] || {
        echo 'Confirm from a NEW SSH connection; preserve SSH_CONNECTION with sudo.' >&2
        exit 1
    }
fi
systemctl stop ufw-antiscan-safety.timer
rm -f "$PENDING"
echo 'Application confirmed; automatic rollback cancelled'
