# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

`ufw-antiscan` (repo `HikaruApps/remnanode-antiscan`) — Bash toolkit for hardening
Remnawave nodes and other VPS on Debian 11–13 / Ubuntu 20.04–24.04 with systemd and UFW.
User-facing text (menus, messages, README, CHANGELOG) is in **Russian**; keep it that way.
Code comments in newer scripts are short English one-liners.

Everything runs as root and touches SSH, netfilter, sysctl and systemd on a remote
server. A mistake can lock the operator out — preserve the safety mechanisms below.

## Layout

- `install.sh` — entry point: interactive menu and subcommands
  (`basic`, `protect`, `tuning`, `confirm`, `rollback`, `status`, `update`, `--help`).
  Interactive prompts live here; it then calls the scripts with ENV variables.
- `scripts/state.sh` — shared library sourced by the others. State lives in
  `/var/lib/ufw-antiscan`: snapshots of managed files/services/sysctl, restore,
  the persistent systemd safety timer (`arm_safety` / `disarm_safety`) and the
  confirmation boundary.
- `scripts/basic.sh` — Basic mode: SSH key validation and append, password-auth disable
  via an sshd drop-in (checked with `sshd -t` / `sshd -T`, applied with reload), Fail2Ban/CrowdSec.
- `scripts/protect.sh` — Experimental mode: opt-in iptables/ip6tables rules
  (bad TCP flags, anti-spoofing, SYN/conn/SSH/ICMP limits, portscan autoban) injected into UFW
  `before.rules` / `before6.rules`, plus Fail2Ban/CrowdSec. Supports `DRY_RUN=1`.
- `scripts/rules.py` — inserts/removes only the block between
  `# === UFW-ANTISCAN START/END ===` markers in the UFW filter table.
- `scripts/tuning.sh` — BBR + CAKE defaults and `IPV6_MODE=keep|enable|disable`.
- `scripts/confirm.sh` — confirms an apply; requires an SSH session created after the apply.
- `scripts/restore.sh` — invoked by the safety timer to roll back an unconfirmed apply.
- `scripts/rollback.sh` — full uninstall; preserves unrelated UFW edits and prior service states.
- `scripts/status.sh` — read-only status report.
- `scripts/update.sh` — self-update from the GitHub default branch, with a backup dir and syntax check.
- `README.md`, `CHANGELOG.md` (`[Unreleased]` section), `RELEASE_CHECK.md` (pre-release verification log).

## Invariants

- Every change to SSH/firewall/sysctl: snapshot first → arm the persistent safety timer →
  apply → the operator confirms from a **new** SSH connection. Without confirmation the
  timer restores the previous state, including after a reboot.
- All Experimental features default to off (`ENABLE_*=0`); nothing is enabled implicitly.
- Never overwrite user data: `authorized_keys` is appended to, unrelated UFW rules are kept,
  and pre-existing services are restored to their previous state.
- Validate inputs (ports, CIDRs, keys, unknown options) before making any change; fail early.
- Docker is supported only with `network_mode: host`.

## Checks

There is no automated test suite or CI in this checkout (see `RELEASE_CHECK.md`).
Before committing, at least run:

```bash
for f in install.sh scripts/*.sh; do bash -n "$f"; done
python3 -m py_compile scripts/rules.py
git diff --check
```

Run `shellcheck` too if it is installed. Real SSH/netfilter/systemd behavior cannot be tested
in this container (no `CAP_NET_ADMIN`); say so instead of claiming runtime verification.
When behavior changes, update `README.md`, `CHANGELOG.md` and, where relevant, `RELEASE_CHECK.md`.
