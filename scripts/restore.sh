#!/bin/bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/state.sh"
[[ $EUID == 0 ]] || exit 1
exec 9>"$LOCK_FILE"
flock -x 9
[[ -f "$PENDING" ]] || exit 0
BACKUP=$(cat "$PENDING")
restore_snapshot "$BACKUP"
rm -f "$PENDING"
printf '%s %s\n' "$(date '+%F %T %Z')" "$BACKUP" > "$AUTO_RESTORED"
disarm_safety
echo "AntiScan: unconfirmed changes restored from $BACKUP"
