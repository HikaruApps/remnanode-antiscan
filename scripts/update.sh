#!/bin/bash
# Update the project files, not the firewall or installed services.
set -euo pipefail
export LC_ALL=C
[[ $EUID == 0 ]] || { echo 'Нужен root.' >&2; exit 1; }
TARGET=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
PARENT=$(dirname "$TARGET")
[[ "$TARGET" != / ]] || exit 1
for command in git python3 flock; do
    command -v "$command" >/dev/null || { echo "Не найдена команда: $command" >&2; exit 1; }
done
exec 9>/run/lock/ufw-antiscan.lock
flock -n 9 || { echo 'Другая операция AntiScan уже выполняется.' >&2; exit 1; }
[[ ! -f /var/lib/ufw-antiscan/pending ]] || {
    echo 'Сначала подтвердите применение защиты или выполните откат.' >&2; exit 1;
}
if [[ -e "$TARGET/.git" ]]; then
    [[ -d "$TARGET/.git" && ! -L "$TARGET/.git" ]] || {
        echo 'Обновление linked worktree не поддерживается.' >&2; exit 1;
    }
    STATUS=$(git -c safe.directory="$TARGET" -C "$TARGET" status --porcelain --untracked-files=normal) || {
        echo 'Не удалось проверить Git-каталог; обновление отменено.' >&2; exit 1;
    }
    if [[ -n "$STATUS" ]]; then
        echo 'Есть локальные изменения. Сохраните их перед обновлением.' >&2; exit 1
    fi
fi
WORK=$(mktemp -d "$PARENT/.antiscan-update.XXXXXXXX")
BACKUP=""
MOVED=0
cleanup() {
    local code=$?
    if [[ "$MOVED" == 1 && ! -e "$TARGET" ]]; then
        mv -- "$BACKUP" "$TARGET" || echo "Восстановите каталог вручную: $BACKUP" >&2
    fi
    rm -rf -- "$WORK"
    return "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
printf '\n  Загрузка обновления из HikaruApps/remnanode-antiscan…\n'
git -c http.lowSpeedLimit=1 -c http.lowSpeedTime=30 clone --quiet --depth 1 --template='' \
    https://github.com/HikaruApps/remnanode-antiscan.git "$WORK/release"
# Never execute downloaded code during validation.
python3 - "$WORK/release" <<'PY'
import ast
import subprocess
import sys
from pathlib import Path
root = Path(sys.argv[1])
required = ['install.sh', 'scripts/update.sh', 'scripts/protect.sh', 'scripts/status.sh',
            'scripts/rollback.sh', 'scripts/confirm.sh', 'scripts/restore.sh',
            'scripts/state.sh', 'scripts/rules.py', 'scripts/update-blocklists.sh',
            'scripts/ensure-ipsets.sh']
for name in required:
    path = root / name
    if not path.is_file() or path.is_symlink() or root.resolve() not in path.resolve().parents:
        raise SystemExit('Неполная или несовместимая версия: ' + name)
for path in root.rglob('*'):
    if '.git' in path.relative_to(root).parts:
        continue
    if path.is_symlink():
        raise SystemExit('Символические ссылки в обновлении не поддерживаются')
    if path.suffix == '.sh':
        subprocess.run(['bash', '-n', str(path)], check=True)
    elif path.suffix == '.py':
        ast.parse(path.read_text(), filename=str(path))
PY
REVISION=$(git -C "$WORK/release" rev-parse --short=12 HEAD)
if [[ -d "$TARGET/.git" ]] && \
    [[ "$(git -c safe.directory="$TARGET" -C "$TARGET" rev-parse HEAD)" == "$(git -C "$WORK/release" rev-parse HEAD)" ]]; then
    echo "Уже установлена актуальная версия: $REVISION"
    exit 0
fi
# Keep the whole previous directory, including local files and Git history.
BACKUP=$(mktemp -d "$PARENT/remnanode-antiscan-backup.XXXXXXXX")
rmdir "$BACKUP"
MOVED=1
mv -- "$TARGET" "$BACKUP"
mv -- "$WORK/release" "$TARGET"
MOVED=0
printf '\n  Обновлено до %s\n  Предыдущая версия: %s\n' "$REVISION" "$BACKUP"
echo '  Обновлены файлы проекта. Для применения новой логики защиты выберите пункт 1.'
