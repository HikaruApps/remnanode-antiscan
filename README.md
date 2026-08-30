# 🛡 remnanode-antiscan

Защита от сканеров, флуда и брутфорса поверх существующего UFW.

Заточен под **Remnawave-ноды** (Xray / VLESS-Reality, xHTTP, Hysteria2/TUIC),
но подходит для любого VPS с UFW.

> **Поддержка:** Debian 11/12/13, Ubuntu 20.04–24.04.
> Совместим с Docker (`network_mode: host`) и CrowdSec.

---

## Что внутри

### 🔒 Правила iptables (before.rules)

Вставляются **перед** правилами UFW, не трогают Docker-NAT и не делают `flush ruleset`.

- **AntiScan** — SYN/UDP на нессервисный порт → автобан IP на 1 час (ядерный модуль `ipt_recent`, без доп. зависимостей)
- **Flag-drop** — XMAS, NULL, SYN+FIN, SYN+RST, FIN+RST и другие мусорные пакеты
- **Anti-spoofing** — RFC1918/bogon источники на WAN-интерфейсе
- **Per-IP SYN-flood** — `hashlimit` на каждый сервисный порт отдельно, масштабируется по клиентам
- **Per-IP connlimit** — ограничение одновременных соединений с одного IP
- **ICMP rate-limit** — ping живой, флуд режется
- **Whitelist** — IP из списка всегда пропускаются первыми

### 🚫 fail2ban

SSH brute-force: бан после 5 попыток за 5 минут, на 24 часа.

### 🌐 CrowdSec (опционально)

Community-driven threat intelligence: IP, уже атакующие других, блокируются **превентивно** — до того как постучатся к тебе.

- Устанавливает агент + iptables-bouncer (совместим с UFW)
- Подключается к community blocklist автоматически
- Опционально: регистрация в [веб-консоли](https://app.crowdsec.net)

---

## Установка

```bash
# Скачать
git clone https://github.com/<твой-ник>/ufw-antiscan.git
cd ufw-antiscan

# Интерактивное меню
sudo bash install.sh

# Или сразу с параметрами (рекомендуется для Remnawave-ноды)
sudo SSH_PORT=22 TCP_PORTS=443,2087 UDP_PORTS=443 \
     WHITELIST="IP_твоей_панели" \
     bash install.sh protect
```

> **Важно для Remnawave:** добавь IP панели в `WHITELIST` — иначе панель может попасть под portscan-бан при подключении к ноде.

### Посмотреть что будет без применения

```bash
sudo DRY_RUN=1 bash install.sh protect
```

### Без CrowdSec

```bash
sudo ENABLE_CROWDSEC=0 bash install.sh protect
```

---

## Параметры

| Переменная              | По умолчанию | Описание |
|-------------------------|--------------|----------|
| `SSH_PORT`              | авто-детект  | Порт SSH |
| `TCP_PORTS`             | `443,2087`   | Сервисные TCP-порты через запятую |
| `UDP_PORTS`             | `443`        | Сервисные UDP-порты через запятую |
| `WHITELIST`             | —            | IP/CIDR через запятую — никогда не блокируются |
| `SYN_RATE`/`SYN_BURST`  | `100`/`200`  | Per-IP новых TCP-соед/сек на сервисный порт |
| `CONN_LIMIT`            | `600`        | Макс одновременных соединений с одного IP |
| `SSH_RATE`/`SSH_BURST`  | `6`/`4`      | Новых SSH/мин до бана |
| `PORTSCAN_BAN_SECONDS`  | `3600`       | Время бана за сканирование (секунд) |
| `ENABLE_PORTSCAN_BAN`   | `1`          | Включить AntiScan |
| `ENABLE_CROWDSEC`       | `1`          | Установить CrowdSec |
| `CROWDSEC_ENROLL_KEY`   | —            | Ключ из [app.crowdsec.net](https://app.crowdsec.net) |
| `DRY_RUN`               | `0`          | `1` — показать правила без применения |
| `PURGE_CROWDSEC`        | `0`          | `1` — удалить CrowdSec при откате |

---

## Команды

```bash
# Меню
sudo bash install.sh

# По модулям
sudo bash install.sh protect     # 🛡 установить защиту
sudo bash install.sh status      # 🩺 текущий статус
sudo bash install.sh rollback    # ↩  откатить всё

# Справка
sudo bash install.sh --help
```

---

## Мониторинг

```bash
# Статус одной командой
sudo bash install.sh status

# Portscan-баны (ipt_recent)
cat /proc/net/ipt_recent/PORTSCANNERS

# SSH-баны (fail2ban)
fail2ban-client status sshd

# CrowdSec-баны
cscli decisions list
```

---

## Откат

```bash
# Откатить всё (CrowdSec останется, только остановится bouncer)
sudo bash install.sh rollback

# Откатить всё включая удаление CrowdSec
sudo PURGE_CROWDSEC=1 bash install.sh rollback
```

Бэкапы оригинальных файлов хранятся в `/var/backups/ufw-antiscan/<timestamp>/`.

---

## Разбанить вручную

```bash
# Конкретный IP из portscan-банов
echo -1.2.3.4 > /proc/net/ipt_recent/PORTSCANNERS

# Всех сканеров сразу
echo / > /proc/net/ipt_recent/PORTSCANNERS

# SSH (fail2ban)
fail2ban-client unban 1.2.3.4

# CrowdSec
cscli decisions delete --ip 1.2.3.4
```

---

## Как это работает

UFW — фронтенд к iptables. Все правила вставляются в `/etc/ufw/before.rules` в цепочку `ufw-before-input`, которая обрабатывается **до** пользовательских правил UFW.

При `ufw reload` файл перечитывается, правила сохраняются. Docker-NAT и CrowdSec-bouncer работают в своих отдельных цепочках и не затрагиваются.

---

MIT. Читай скрипты перед запуском на проде.
