#!/bin/bash
# Basic hardening: safely add an SSH key and optionally harden SSH/install IPS.
set -Eeuo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/state.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[✔]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✘]${NC} $*" >&2; return 1; }

[[ $EUID == 0 ]] || { echo 'Нужен root.' >&2; exit 1; }

sshd_bin() {
    if command -v sshd >/dev/null 2>&1; then
        command -v sshd
    elif [[ -x /usr/sbin/sshd ]]; then
        printf '/usr/sbin/sshd\n'
    else
        return 1
    fi
}

account_data() {
    local entry
    [[ -n "${TARGET_USER:-}" ]] || err "TARGET_USER не задан"
    [[ "$TARGET_USER" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ ]] || err "Некорректное имя пользователя"
    entry=$(getent passwd "$TARGET_USER") || err "Пользователь не найден: $TARGET_USER"
    IFS=: read -r _ _ TARGET_UID TARGET_GID _ TARGET_HOME TARGET_SHELL <<< "$entry"
    [[ "$TARGET_UID" =~ ^[0-9]+$ && "$TARGET_GID" =~ ^[0-9]+$ ]] || err "Некорректная учётная запись"
    [[ "$TARGET_HOME" == /* && -d "$TARGET_HOME" ]] || err "Домашний каталог недоступен: $TARGET_HOME"
    case "$TARGET_SHELL" in
        */nologin|*/false) err "У пользователя запрещён интерактивный вход: $TARGET_USER" ;;
    esac
}

ssh_context() {
    local source_ip source_port local_ip local_port
    read -r source_ip source_port local_ip local_port <<< "${SSH_CONNECTION:-}"
    source_ip=${source_ip:-127.0.0.1}
    local_ip=${local_ip:-127.0.0.1}
    local_port=${local_port:-${SSH_PORT:-22}}
    printf 'user=%s,host=%s,addr=%s,laddr=%s,lport=%s' \
        "$TARGET_USER" "$(hostname)" "$source_ip" "$local_ip" "$local_port"
}

check_authorized_keys_location() {
    local daemon=$1 effective
    effective=$("$daemon" -T -C "$(ssh_context)") || err "Не удалось прочитать эффективную конфигурацию sshd"
    if ! awk '$1 == "authorizedkeysfile" { for (i=2; i<=NF; i++) if ($i == ".ssh/authorized_keys" || $i == "%h/.ssh/authorized_keys") found=1 } END { exit !found }' <<< "$effective"; then
        err "sshd не использует ~/.ssh/authorized_keys для $TARGET_USER; автоматическое добавление остановлено"
    fi
}

add_key() {
    local daemon key key_type key_blob ssh_dir auth fingerprint result
    SSH_PORT=${SSH_PORT:-22}
    [[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535 )) \
        || err "Некорректный SSH_PORT"
    SSH_PORT=$((10#$SSH_PORT))
    command -v getent >/dev/null || err "getent не найден"
    command -v ssh-keygen >/dev/null || err "ssh-keygen не найден"
    command -v python3 >/dev/null || err "python3 не найден"
    daemon=$(sshd_bin) || err "sshd не найден"
    account_data
    recover_ssh_connection
    check_authorized_keys_location "$daemon"

    IFS= read -r key || err "SSH-ключ не получен"
    [[ -n "$key" && "$key" != *$'\r'* && "$key" != *$'\n'* ]] || err "Ключ должен занимать одну строку"
    [[ ! "$key" =~ [[:cntrl:]] ]] || err "Управляющие символы в ключе запрещены"
    [[ ${#key} -le 16384 ]] || err "Публичный ключ слишком длинный"
    read -r key_type key_blob _ <<< "$key"
    case "$key_type" in
        ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ;;
        *) err "Неподдерживаемый тип публичного ключа: ${key_type:-пусто}" ;;
    esac
    [[ "$key_blob" =~ ^[A-Za-z0-9+/]+={0,3}$ ]] || err "Некорректные данные публичного ключа"

    # Global: the EXIT trap runs after this function's locals are gone.
    KEY_TMP=$(mktemp)
    trap 'rm -f -- "${KEY_TMP:-}"' EXIT
    chmod 600 "$KEY_TMP"
    printf '%s\n' "$key" > "$KEY_TMP"
    fingerprint=$(ssh-keygen -lf "$KEY_TMP") || err "ssh-keygen отклонил ключ: вставьте публичный ключ целиком"
    if [[ "$key_type" == ssh-rsa && "${fingerprint%% *}" -lt 2048 ]]; then
        err "RSA-ключ короче 2048 бит не принимается"
    fi

    ssh_dir="$TARGET_HOME/.ssh"
    auth="$ssh_dir/authorized_keys"
    [[ ! -L "$ssh_dir" && ! -L "$auth" ]] || err "Символические ссылки в пути authorized_keys не поддерживаются"
    if [[ -e "$ssh_dir" ]]; then
        [[ -d "$ssh_dir" ]] || err "$ssh_dir не является каталогом"
        [[ $(stat -c '%u:%g' "$ssh_dir") == "$TARGET_UID:$TARGET_GID" ]] || err "$ssh_dir принадлежит другому пользователю"
        chmod 700 "$ssh_dir"
    else
        install -d -m 700 -o "$TARGET_UID" -g "$TARGET_GID" "$ssh_dir"
    fi

    result=$(python3 - "$ssh_dir" "$KEY_TMP" "$TARGET_UID" "$TARGET_GID" "$key_type" "$key_blob" <<'PY'
import fcntl
import os
import stat
import sys

directory, source, uid, gid, key_type, key_blob = sys.argv[1:]
flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
dir_fd = os.open(directory, dir_flags)
try:
    previous = os.stat("authorized_keys", dir_fd=dir_fd, follow_symlinks=False)
except FileNotFoundError:
    previous = None
fd = os.open("authorized_keys", flags, 0o600, dir_fd=dir_fd)
try:
    fcntl.flock(fd, fcntl.LOCK_EX)
    meta = os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode):
        raise SystemExit("authorized_keys is not a regular file")
    if meta.st_nlink != 1:
        raise SystemExit("authorized_keys hard links are not supported")
    if previous is not None and (previous.st_dev, previous.st_ino) != (meta.st_dev, meta.st_ino):
        raise SystemExit("authorized_keys changed while it was being opened")
    target_uid, target_gid = int(uid), int(gid)
    if previous is not None and meta.st_uid not in (0, target_uid):
        raise SystemExit("authorized_keys has an unexpected owner")
    os.fchmod(fd, 0o600)
    if previous is None or meta.st_uid != 0:
        os.fchown(fd, target_uid, target_gid)
    os.lseek(fd, 0, os.SEEK_SET)
    content = os.read(fd, meta.st_size)
    for line in content.splitlines():
        fields = line.split()
        pairs = zip(fields, fields[1:])
        if any(a.decode(errors="ignore") == key_type and b.decode(errors="ignore") == key_blob for a, b in pairs):
            print("SSH_KEY_ALREADY_PRESENT=1")
            break
    else:
        key = open(source, "rb").read().rstrip(b"\r\n")
        prefix = b"" if not content or content.endswith(b"\n") else b"\n"
        os.write(fd, prefix + key + b"\n")
        os.fsync(fd)
        print("SSH_KEY_ADDED=1")
finally:
    os.close(fd)
    os.close(dir_fd)
PY
)
    if [[ "$result" == SSH_KEY_ALREADY_PRESENT=1 ]]; then
        ok "Этот ключ уже есть у $TARGET_USER; authorized_keys не изменён"
    else
        ok "Публичный ключ проверен и безопасно добавлен для $TARGET_USER"
    fi
    printf '    %s\n' "$fingerprint"
}

setup_fail2ban() {
    if ! command -v fail2ban-client >/dev/null; then
        info "Устанавливаю Fail2Ban..."
        apt-get update -q
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q fail2ban
    fi
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/ufw-antiscan-ssh.conf <<EOF
[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
backend  = systemd
maxretry = ${F2B_MAXRETRY}
findtime = ${F2B_FINDTIME}
bantime  = ${F2B_BANTIME}
EOF
    fail2ban-client -t
    systemctl enable --now fail2ban
    systemctl restart fail2ban
    ok "Fail2Ban настроен для SSH-порта $SSH_PORT (${F2B_MAXRETRY} попыток/${F2B_FINDTIME}с, бан ${F2B_BANTIME}с)"
}

setup_crowdsec() {
    if ! command -v cscli >/dev/null; then
        if ! command -v gpg >/dev/null; then
            apt-get update -q
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q gnupg
        fi
        curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
            | gpg --batch --yes --dearmor -o /usr/share/keyrings/crowdsec-archive-keyring.gpg
        . /etc/os-release
        printf 'deb [signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/%s %s main\n' \
            "$ID" "$VERSION_CODENAME" > /etc/apt/sources.list.d/crowdsec.list
        apt-get update -q
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q crowdsec
    fi
    if [[ "$(dpkg-query -W -f='${Status}' crowdsec-firewall-bouncer-iptables 2>/dev/null || true)" != "install ok installed" ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q crowdsec-firewall-bouncer-iptables
    fi
    cscli collections install crowdsecurity/linux -q || warn "Коллекция linux не установлена"
    cscli collections install crowdsecurity/sshd -q || warn "Коллекция sshd не установлена"
    if [[ -n "${CROWDSEC_ENROLL_KEY:-}" ]]; then
        cscli console enroll "$CROWDSEC_ENROLL_KEY" || warn "CrowdSec enrollment не выполнен"
    fi
    systemctl enable --now crowdsec crowdsec-firewall-bouncer
    systemctl restart crowdsec crowdsec-firewall-bouncer
    ok "CrowdSec и firewall bouncer запущены"
}

# Without passwords, the effective config must still allow a key-only login;
# otherwise the reload would lock everyone out until the safety rollback.
check_key_login_possible() {
    local effective=$1 methods root_login
    methods=$(awk '$1 == "authenticationmethods" { $1 = ""; sub(/^ /, ""); print; exit }' <<< "$effective")
    if [[ -n "$methods" && "$methods" != any ]] && ! tr ' ' '\n' <<< "$methods" | grep -qx publickey; then
        err "AuthenticationMethods ($methods) требует не только ключ: без пароля вход станет невозможен"
    fi
    if [[ "$TARGET_UID" == 0 ]]; then
        root_login=$(awk '$1 == "permitrootlogin" { print $2; exit }' <<< "$effective")
        case "$root_login" in
            yes|prohibit-password|without-password) ;;
            *) err "PermitRootLogin ${root_login:-?}: root не сможет войти по ключу" ;;
        esac
    fi
}

apply_basic() {
    local daemon backup original_stage effective code project_root server_address ssh_stage=""
    DISABLE_SSH_PASSWORD=${DISABLE_SSH_PASSWORD:-0}
    KEY_TEST_CONFIRMED=${KEY_TEST_CONFIRMED:-0}
    ENABLE_FAIL2BAN=${ENABLE_FAIL2BAN:-0}
    ENABLE_CROWDSEC=${ENABLE_CROWDSEC:-0}
    SAFETY_TIMER=${SAFETY_TIMER:-180}
    SSH_PORT=${SSH_PORT:-22}
    F2B_MAXRETRY=${F2B_MAXRETRY:-5}
    F2B_FINDTIME=${F2B_FINDTIME:-300}
    F2B_BANTIME=${F2B_BANTIME:-86400}
    for value in "$DISABLE_SSH_PASSWORD" "$KEY_TEST_CONFIRMED" "$ENABLE_FAIL2BAN" "$ENABLE_CROWDSEC"; do
        [[ "$value" == 0 || "$value" == 1 ]] || err "Флаги Basic должны быть 0 или 1"
    done
    for value in "$F2B_MAXRETRY" "$F2B_FINDTIME" "$F2B_BANTIME"; do
        [[ "$value" =~ ^[0-9]{1,9}$ ]] && (( 10#$value >= 1 )) \
            || err "Параметры Fail2Ban должны быть положительными числами"
    done
    F2B_MAXRETRY=$((10#$F2B_MAXRETRY))
    F2B_FINDTIME=$((10#$F2B_FINDTIME))
    F2B_BANTIME=$((10#$F2B_BANTIME))
    [[ "$SAFETY_TIMER" =~ ^[0-9]{1,10}$ ]] || err "SAFETY_TIMER должен быть числом"
    (( 10#$SAFETY_TIMER >= 60 && 10#$SAFETY_TIMER <= 3600 )) \
        || err "SAFETY_TIMER должен быть от 60 до 3600 секунд"
    [[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] || err "Некорректный SSH_PORT"
    (( 10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535 )) || err "Некорректный SSH_PORT"
    SAFETY_TIMER=$((10#$SAFETY_TIMER))
    SSH_PORT=$((10#$SSH_PORT))
    [[ "$DISABLE_SSH_PASSWORD$ENABLE_FAIL2BAN$ENABLE_CROWDSEC" != 000 ]] || err "Не выбрано ни одного действия"

    daemon=$(sshd_bin) || err "sshd не найден"
    account_data
    recover_ssh_connection
    if [[ "$DISABLE_SSH_PASSWORD" == 1 ]]; then
        check_authorized_keys_location "$daemon"
        command -v ssh-keygen >/dev/null || err "ssh-keygen не найден"
        [[ "$KEY_TEST_CONFIRMED" == 1 ]] || err "Сначала подтвердите вход ключом с отключённой клиентской парольной аутентификацией"
        [[ -s "$TARGET_HOME/.ssh/authorized_keys" ]] || err "Сначала добавьте хотя бы один SSH-ключ для $TARGET_USER"
        ssh-keygen -l -f "$TARGET_HOME/.ssh/authorized_keys" >/dev/null || err "В authorized_keys нет валидного ключа"
    fi
    command -v flock >/dev/null || err "flock не найден"
    systemctl show-environment >/dev/null || err "Нужен работающий systemd"
    [[ "$ENABLE_CROWDSEC" == 0 ]] || command -v curl >/dev/null || err "Для CrowdSec нужен curl"

    exec 9>"$LOCK_FILE"
    flock -n 9 || err "Другая операция AntiScan уже выполняется"
    mkdir -p "$STATE" /var/backups/ufw-antiscan
    chmod 700 "$STATE"
    [[ ! -f "$PENDING" ]] || err "Сначала подтвердите или откатите предыдущее применение"
    backup=$(mktemp -d /var/backups/ufw-antiscan/basic.XXXXXXXX)
    snapshot "$backup" basic
    if [[ ! -d "$STATE/basic-original" ]]; then
        original_stage=$(mktemp -d "$STATE/basic-original.XXXXXXXX")
        cp -a "$backup/." "$original_stage/"
        mv -T "$original_stage" "$STATE/basic-original"
    fi
    printf '%s' "${SSH_CONNECTION:-}" > "$backup/ssh-connection"

    rollback_on_error() {
        code=$?
        trap - ERR INT TERM HUP
        [[ -z "$ssh_stage" ]] || rm -f "$ssh_stage"
        echo "Basic apply failed; restoring $backup" >&2
        if restore_snapshot "$backup"; then
            rm -f "$PENDING"
            disarm_safety || true
        fi
        exit "$code"
    }
    trap rollback_on_error ERR
    trap 'false' INT TERM HUP
    mkdir -p /usr/local/lib/ufw-antiscan
    install -m 644 "$SCRIPT_DIR/state.sh" /usr/local/lib/ufw-antiscan/state.sh
    install -m 755 "$SCRIPT_DIR/restore.sh" /usr/local/lib/ufw-antiscan/restore.sh
    # Package installation can be slow. A long preparation timer protects
    # partial service changes; the short verification timer starts afterwards.
    arm_safety "$backup" 3600

    [[ "$ENABLE_FAIL2BAN" == 0 ]] || setup_fail2ban
    [[ "$ENABLE_CROWDSEC" == 0 ]] || setup_crowdsec

    if [[ "$DISABLE_SSH_PASSWORD" == 1 ]]; then
        arm_safety "$backup" "$SAFETY_TIMER"
        mkdir -p /etc/ssh/sshd_config.d
        ssh_stage=$(mktemp /etc/ssh/sshd_config.d/.remnanode-antiscan.XXXXXXXX)
        cat > "$ssh_stage" <<'EOF'
# Managed by remnanode-antiscan Basic mode.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
EOF
        chmod 600 "$ssh_stage"
        chown root:root "$ssh_stage"
        mv -f "$ssh_stage" "$SSH_DROPIN"
        ssh_stage=""
        "$daemon" -t
        effective=$("$daemon" -T -C "$(ssh_context)")
        grep -qx 'pubkeyauthentication yes' <<< "$effective" || err "sshd не включил вход по ключу"
        grep -qx 'passwordauthentication no' <<< "$effective" || err "sshd не отключил вход по паролю"
        grep -qx 'kbdinteractiveauthentication no' <<< "$effective" || err "sshd не отключил keyboard-interactive"
        check_key_login_possible "$effective"
        reload_ssh
        ok "Парольный вход SSH отключён эффективной конфигурацией sshd"
    fi

    arm_safety "$backup" "$SAFETY_TIMER"
    mark_confirmation_boundary "$backup"
    trap - ERR INT TERM HUP
    project_root=$(cd "$SCRIPT_DIR/.." && pwd)
    warn "Откройте НОВУЮ SSH-сессию ключом. Автооткат через ${SAFETY_TIMER} секунд."
    server_address=$(awk '{print $3}' <<< "${SSH_CONNECTION:-}")
    server_address=${server_address:-адрес-сервера}
    [[ "$server_address" != *:* ]] || server_address="[$server_address]"
    printf '  ssh -o ControlMaster=no -o ControlPath=none -p %q %q@%q\n' \
        "$SSH_PORT" "$TARGET_USER" "$server_address"
    printf '  Из новой сессии: sudo --preserve-env=SSH_CONNECTION bash %q confirm\n' "$project_root/install.sh"
    ok "Basic применён и ожидает подтверждения. Бэкап: $backup"
}

case "${1:-}" in
    add-key) add_key ;;
    apply) apply_basic ;;
    *) echo "Использование: basic.sh add-key|apply" >&2; exit 2 ;;
esac
