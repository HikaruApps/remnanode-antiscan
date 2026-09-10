#!/bin/bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/state.sh"
[[ $EUID == 0 ]] || exit 1
exec 9>/run/lock/ufw-antiscan.lock
flock -x 9
[[ -f "$PENDING" ]] || exit 0
BACKUP=$(cat "$PENDING")
restore_snapshot "$BACKUP"
rm -f "$PENDING"
echo "AntiScan: unconfirmed changes restored from $BACKUP"
