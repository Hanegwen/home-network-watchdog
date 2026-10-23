# Guide for AI coding agents

Home Network Watch: a stdlib-only Python service for a Linux box on a home LAN (often a Raspberry Pi). systemd
timers run short checks; each compares what it sees with a local SQLite file and emails only the changes.
User docs: [README.md](README.md), [docs/DEPLOY.md](docs/DEPLOY.md). How it works: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## This repo is public

- Never commit anything personal: real IPs, MACs, hostnames or mDNS names, tailnet names (`*.ts.net`),
  email addresses, public IPs, real port forwards, which apps or devices a real home runs, locations or
  time zones, account names, file paths with user names. Use placeholders: `192.168.1.x` / `10.0.0.x` for
  LAN, documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and `1.2.3.4` / `5.6.7.8` for
  public IPs, `02:00:00:..`-style MACs (see `PLACEHOLDER_MACS` in `tools/check_public.py`), `AS64500`.
- `python tools/check_public.py` must pass before every commit (CI runs it). It also reads the maintainer's
  private denylist when present; never print or copy that file.
- Real settings live only in `/etc/netwatch.env` on the box; `*.env` is git-ignored except `config.example.env`.

## Layout

- `netwatch/run.py`: entry point. Runs the checks in `FAST` (plus `exposure` with `--daily`), sends one email per run.
- One module per check (`devices`, `forwards`, `tailnet`, `visitors`, `vault`, `exposure`). Each has
  `check(conn, now, ...) -> (alerts, notes)`; alerts are `(title, body)` pairs.
- `netwatch/config.py`: every setting, read from the environment once at import, with defaults.
- `netwatch/db.py`: schema (created on connect; new columns get an `ALTER TABLE` there), `kv` helpers, `once`.
- `devices.py` and `visitors.py` also have a `main()` for `nw devices` / `nw visitors`.
- `deploy/`: `install.sh`, systemd units (`@SERVICE_USER@` is filled in by install.sh), the `nw` helper.

## Tests

```sh
python -m unittest            # or python3; no network, no root, no arp-scan needed
python tools/check_public.py
```

Checks take their inputs as optional arguments, and tests pass fakes instead of touching the network:
`devices.check(conn, now, found, tailnet_hosts, names)`, `forwards.check(conn, now, forwards)`,
`tailnet.check(conn, now, current)`, `visitors.check(conn, now, lines, fetch=...)`,
`exposure.check(conn, now, ip, data)`, `vault.check(conn, now, up=..., planned=...)`. Use
`db.connect(":memory:")`. To change a setting in a test, set it on `config` and restore it with `addCleanup`.
A new check or behavior gets a test in `tests/test_checks.py`.

## Conventions

- Python stdlib only, Python 3.9+. No new dependencies.
- Short functions, f-strings, lines up to about 120 characters. Docstrings say what and why, briefly.
- SQL always uses `?` parameters for values.
- Email text is plain, short sentences that tell a non-expert what happened and what to do.
- Every check has a quiet first run (baseline) and alerts only on changes; optional checks turn themselves
  off when their tool or file is missing.
- A new setting goes in `config.py`, `config.example.env` and the tables in `docs/DEPLOY.md`.
- Update `docs/ARCHITECTURE.md` (and its Mermaid diagrams) when a check, table or identity rule changes.
- Old setting names `NETWATCH_VAULT_URL` / `NETWATCH_VAULT_MAINT_DIR` still work as fallbacks for
  `SITE_URL` / `MAINT_DIR`; the `vault_*` kv keys keep their names so existing databases keep working.

## Deploying

Install is `git clone` to `/opt/netwatch` and `sudo ./deploy/install.sh`; update is `git pull` and install.sh
again. Runs as the user in the units; settings come from `/etc/netwatch.env` (`EnvironmentFile`).
`nw run --dry-run` on the box shows what would alert without saving or emailing.

## Gotchas

- When working on a real box over SSH, don't retry failed SSH connections quickly; space retries out
  (rapid attempts can trip fail2ban-style blocking).
- `nw` sources `/etc/netwatch.env` with `sh`, while systemd reads it with its own parser. Quote values with
  spaces and avoid `$` and backticks in values, or the two can disagree.
- The run commits the database only after emails are sent. A failing send means the same alerts next run.
- `devices` runs before `forwards` on purpose (forwards look up the client's MAC from the devices table).
- Device recognition (mDNS name, Tailscale LAN IP) is a noise filter, not a security boundary; keep the
  documented limitation accurate if you change it.
