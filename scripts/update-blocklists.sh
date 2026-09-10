#!/bin/bash
# Keep the last complete list if any source fails. Run under a private lock.
set -euo pipefail
export LC_ALL=C
STATE=/var/lib/ufw-antiscan
CONF=/etc/ufw-antiscan/blocklists.conf
mkdir -p "$STATE"
exec 8>/run/lock/ufw-antiscan-blocklists.lock
flock -x 8
WORK=$(mktemp -d "$STATE/update.XXXXXXXX")
V4_SWAPPED=0
V6_SWAPPED=0
COMMITTED=0
cleanup() {
    local code=$? failed=0
    if [[ "$COMMITTED" == 0 ]]; then
        if [[ "$V6_SWAPPED" == 1 ]]; then
            ipset swap ANTISCAN-V6-TMP ANTISCAN-V6 || failed=1
        fi
        if [[ "$V4_SWAPPED" == 1 ]]; then
            ipset swap ANTISCAN-V4-TMP ANTISCAN-V4 || failed=1
        fi
    fi
    if [[ "$failed" == 0 ]]; then
        ipset destroy ANTISCAN-V4-TMP 2>/dev/null || true
        ipset destroy ANTISCAN-V6-TMP 2>/dev/null || true
    else
        echo 'Restore failed: temporary sets retained for manual recovery' >&2
        code=1
    fi
    rm -rf "$WORK"
    return "$code"
}
trap cleanup EXIT
trap 'exit 143' TERM HUP
trap 'exit 130' INT
[[ -s "$CONF" ]] || { echo 'Missing blocklist configuration' >&2; exit 1; }
# Abort on partial HTTP transfers too: never mask curl's return code.
index=0
while IFS= read -r url || [[ -n "$url" ]]; do
    [[ -z "$url" || "$url" == \#* ]] && continue
    [[ "$url" == https://* ]] || { echo 'Blocklists require HTTPS' >&2; exit 1; }
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 60 --max-filesize 16777216 \
        --output "$WORK/source-$index" "$url"
    index=$((index + 1))
done < "$CONF"
[[ "$index" -gt 0 ]] || { echo 'No blocklist sources' >&2; exit 1; }
python3 - "$WORK" "$STATE/current.restore" <<'PY'
import ipaddress
import sys
from pathlib import Path
work, previous = map(Path, sys.argv[1:])
networks = set()
for source in work.glob('source-*'):
    if source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Source exceeds 16 MiB")
    source_networks = set()
    for line in source.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        net = ipaddress.ip_network(line, strict=False)
        if net.prefixlen == 0:
            raise ValueError('Default routes are not accepted in blocklists')
        source_networks.add(net)
    if not source_networks:
        raise ValueError(f'Empty source: {source.name}; retaining previous lists')
    networks.update(source_networks)
# Reject suspicious loss independently for each address family.
old = {4: 0, 6: 0}
if previous.exists():
    for line in previous.read_text().splitlines():
        if line.startswith('add '):
            old[ipaddress.ip_network(line.split()[2]).version] += 1
for family in (4, 6):
    count = sum(n.version == family for n in networks)
    if old[family] and count < old[family] / 2:
        raise ValueError(f'IPv{family} list shrank by more than 50%; retaining previous lists')
rows = []
for family, name in ((4, 'inet'), (6, 'inet6')):
    rows.append(f'create ANTISCAN-V{family} hash:net family {name} hashsize 65536 maxelem 500000 -exist')
for net in sorted(networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen)):
    rows.append(f'add ANTISCAN-V{net.version} {net} -exist')
(work / 'current.restore').write_text('\n'.join(rows) + '\n')
PY
for family in 4 6; do
    ipset destroy "ANTISCAN-V${family}-TMP" 2>/dev/null || true
done
sed -e 's/ANTISCAN-V4 /ANTISCAN-V4-TMP /g' -e 's/ANTISCAN-V6 /ANTISCAN-V6-TMP /g' \
    "$WORK/current.restore" | ipset restore
ipset create ANTISCAN-V4 hash:net family inet hashsize 65536 maxelem 500000 -exist
ipset create ANTISCAN-V6 hash:net family inet6 hashsize 65536 maxelem 500000 -exist
ipset swap ANTISCAN-V4-TMP ANTISCAN-V4
V4_SWAPPED=1
ipset swap ANTISCAN-V6-TMP ANTISCAN-V6
V6_SWAPPED=1
# Commit the disk cache only after both kernel swaps succeeded.
mv "$WORK/current.restore" "$STATE/current.restore"
COMMITTED=1
echo 'Blocklists updated and cached successfully'
