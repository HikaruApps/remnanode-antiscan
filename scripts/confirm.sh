#!/bin/bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/state.sh"
[[ $EUID == 0 ]] || { echo 'Нужен root.' >&2; exit 1; }
exec 9>"$LOCK_FILE"
flock -x 9
if [[ ! -f "$PENDING" ]]; then
    if [[ -f "$AUTO_RESTORED" ]]; then
        echo "Подтверждать нечего: изменения уже откатились ($(cat "$AUTO_RESTORED"))." >&2
        echo 'Если они нужны, примените их заново.' >&2
        exit 1
    fi
    echo 'Нет применения, ожидающего подтверждения.'
    exit 0
fi
BACKUP=$(cat "$PENDING")
recover_ssh_connection
# Require a different SSH connection when installation ran over SSH.
if [[ -s "$BACKUP/ssh-connection" ]]; then
    [[ -n "${SSH_CONNECTION:-}" && "$SSH_CONNECTION" != "$(cat "$BACKUP/ssh-connection")" ]] || {
        echo 'Подтвердите из НОВОГО SSH-подключения, а не из того, где запускалась установка.' >&2
        exit 1
    }
fi
if [[ -s "$BACKUP/require-new-after" ]]; then
    command -v python3 >/dev/null || { echo 'Для проверки SSH-сессии нужен python3.' >&2; exit 1; }
    mapfile -t boundary < "$BACKUP/require-new-after"
    [[ ${#boundary[@]} == 2 ]] || { echo 'Повреждена отметка времени применения.' >&2; exit 1; }
    python3 - "${boundary[0]}" "${boundary[1]}" <<'PY'
import os
import sys
import time

def wall(boot_ns):
    # Convert a CLOCK_BOOTTIME instant to local wall-clock time for messages.
    offset = (time.clock_gettime_ns(time.CLOCK_BOOTTIME) - boot_ns) / 1e9
    return time.strftime('%H:%M:%S', time.localtime(time.time() - offset))

required_boot_id = sys.argv[1]
required_ns = int(sys.argv[2])
current_boot_id = open('/proc/sys/kernel/random/boot_id').read().strip()
if current_boot_id != required_boot_id:
    raise SystemExit('Сервер перезагрузился после применения: подтверждение невозможно, дождитесь автоотката.')
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
            raise SystemExit(f'Эта SSH-сессия открыта в {wall(started_ns)}, а защита применена в {wall(required_ns)}.\n'
                             'Откройте новое подключение (новая вкладка/окно) и выполните confirm в нём.')
        found = True
        break
    pid = parent
if not found:
    raise SystemExit('Не удалось найти процесс sshd этой сессии; запустите confirm прямо в новом SSH-входе, не внутри tmux/screen.')
PY
fi
rm -f "$PENDING"
disarm_safety
echo 'Применение подтверждено, автооткат отменён.'
