#!/bin/bash
set -euo pipefail
mkdir -p /var/lib/ufw-antiscan
exec 8>/run/lock/ufw-antiscan-blocklists.lock
flock -x 8
ipset create ANTISCAN-V4 hash:net family inet hashsize 65536 maxelem 500000 -exist
ipset create ANTISCAN-V6 hash:net family inet6 hashsize 65536 maxelem 500000 -exist
if [[ -s /var/lib/ufw-antiscan/current.restore ]]; then
    cleanup() {
        ipset destroy ANTISCAN-V4-TMP 2>/dev/null || true
        ipset destroy ANTISCAN-V6-TMP 2>/dev/null || true
    }
    trap cleanup EXIT
    cleanup
    sed -e 's/ANTISCAN-V4 /ANTISCAN-V4-TMP /g' -e 's/ANTISCAN-V6 /ANTISCAN-V6-TMP /g' \
        /var/lib/ufw-antiscan/current.restore | ipset restore
    ipset swap ANTISCAN-V4-TMP ANTISCAN-V4
    if ! ipset swap ANTISCAN-V6-TMP ANTISCAN-V6; then
        ipset swap ANTISCAN-V4-TMP ANTISCAN-V4
        exit 1
    fi
fi
