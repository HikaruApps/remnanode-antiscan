#!/bin/bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/state.sh"
[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
exec 9>"$LOCK_FILE"
flock -x 9
if [[ ! -f "$PENDING" ]]; then
    if [[ -f "$AUTO_RESTORED" ]]; then
        echo "Nothing to confirm: the unconfirmed changes were already rolled back ($(cat "$AUTO_RESTORED"))." >&2
        echo 'Apply the changes again if they are still needed.' >&2
        exit 1
    fi
    echo 'No pending application'
    exit 0
fi
BACKUP=$(cat "$PENDING")
recover_ssh_connection
# Require a different SSH connection when installation ran over SSH.
if [[ -s "$BACKUP/ssh-connection" ]]; then
    [[ -n "${SSH_CONNECTION:-}" && "$SSH_CONNECTION" != "$(cat "$BACKUP/ssh-connection")" ]] || {
        echo 'Confirm from a NEW SSH connection.' >&2
        exit 1
    }
fi
if [[ -s "$BACKUP/require-new-after" ]]; then
    command -v python3 >/dev/null || { echo 'python3 is required to verify the SSH session age.' >&2; exit 1; }
    mapfile -t boundary < "$BACKUP/require-new-after"
    [[ ${#boundary[@]} == 2 ]] || { echo 'Invalid SSH confirmation boundary.' >&2; exit 1; }
    python3 - "${boundary[0]}" "${boundary[1]}" <<'PY'
import os
import sys

required_boot_id = sys.argv[1]
required_ns = int(sys.argv[2])
current_boot_id = open('/proc/sys/kernel/random/boot_id').read().strip()
if current_boot_id != required_boot_id:
    raise SystemExit('The server rebooted after protection was applied; allow the pending safety rollback to run.')
pid = os.getppid()
found = False
while pid > 1:
    try:
        comm = open(f'/proc/{pid}/comm').read().strip()
        raw = open(f'/proc/{pid}/stat').read()
        fields = raw.rsplit(')', 1)[1].split()
        parent = int(fields[1])
        start_ticks = int(fields[19])
    except (FileNotFoundError, IndexError, ValueError):
        break
    if comm in {'sshd', 'sshd-session'}:
        started_ns = start_ticks * 1_000_000_000 // os.sysconf('SC_CLK_TCK')
        if started_ns <= required_ns:
            raise SystemExit('This SSH session existed before protection was applied; open a fresh connection.')
        found = True
        break
    pid = parent
if not found:
    raise SystemExit('Could not verify a fresh sshd session; run confirm directly in a new SSH login, not inside tmux/screen.')
PY
fi
rm -f "$PENDING"
disarm_safety
echo 'Application confirmed; automatic rollback cancelled'
