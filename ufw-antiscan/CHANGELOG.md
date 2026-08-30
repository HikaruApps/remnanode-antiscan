# Changelog

## [1.0.0] — 2026

### Добавлено
- AntiScan: автобан IP за SYN/UDP на нессервисный порт (ipt_recent, без доп. зависимостей)
- Flag-drop: XMAS, NULL, SYN+FIN, SYN+RST, FIN+RST и другие мусорные пакеты
- Anti-spoofing: RFC1918/bogon на WAN-интерфейсе (IPv4)
- Per-IP SYN-flood rate-limit через hashlimit на каждый сервисный порт
- Per-IP connlimit: ограничение одновременных соединений
- SSH per-IP rate-limit + fail2ban (бан после 5 попыток, 24ч)
- ICMP rate-limit (ping живой, флуд режется)
- CrowdSec: community blocklist + поведенческий IPS
- Whitelist: IP из списка всегда пропускаются первыми
- DRY_RUN=1: посмотреть правила без применения
- Полный откат одной командой
- Бэкап before.rules перед каждым применением
- Интерактивное меню + прямые команды
- IPv4 и IPv6 паритет
