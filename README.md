# Home Network Watch

A small Python (stdlib only) service for a Linux box on your home LAN, such as a Raspberry Pi. It emails you
when something new can reach, or has joined, your home network.

Many NAS boxes, media servers, game consoles and smart-home apps quietly open router ports through UPnP
("automatic router setup"), which puts their admin pages and databases on the internet without anyone
noticing. This watches for that, plus new devices on the Wi-Fi, new Tailscale machines and, optionally,
who uses a site you host at home through Tailscale Funnel.

New here? Follow **[docs/DEPLOY.md](docs/DEPLOY.md)** for a step-by-step setup.

## What it watches

| Check | How often | Emails when |
|---|---|---|
| Router port forwards (UPnP IGD, read-only) | 5 min | a device opens an internet port that isn't in `ALLOWED_FORWARDS` |
| Devices on the LAN/Wi-Fi (`arp-scan`) | 5 min | a MAC address never seen before shows up |
| Tailscale machines (optional) | 5 min | a new machine joins the tailnet (Funnel relay nodes are ignored) |
| Site visitors (optional: Caddy JSON access log behind Tailscale Funnel) | 5 min | someone is **signed in** from a country/network not seen signed in before, or one outside IP sends `HAMMER_REQUESTS` (600) requests in a run |
| Site down (optional: `SITE_URL`) | 5 min | the site hasn't answered for 5+ minutes, and again when it's back |
| Shodan InternetDB for your public IP | daily 8 AM | Shodan newly lists an open port |

The first run learns what is there now and sends one "set up" email listing it. New devices seen during the
first 24 hours are learned quietly (things that were asleep at the first scan). After that only changes alert.
Devices are known by their MAC, not their IP, so a router reset or new DHCP address is quiet. A new MAC that
announces the mDNS (Bonjour) name of a known device (e.g. `NAS-1234`, `iPhone-12`; generic names like `Android`
don't count) or sits on the LAN IP of one of your Tailscale machines is that device with a fresh private address.
Port forwards are known by device MAC + internal port + label: the same service coming back after a reset, on a new
IP or a new outside port, is only logged; a new service, or a known one on a different device, alerts.
`nw devices --watch MAC` emails every time that device comes back after 30+ minutes away.
Anonymous site visitors (bots that scan every public URL) never alert; they go into the **weekly summary**
(Mondays, with the daily run). If `PC_REPORT` is set (the Steam report file of isp-outage-monitor's
optional Windows helper), the weekly summary also says when that PC last checked in and flags **NOT CONNECTING**
after `PC_STALE_HOURS` (48) of silence.

Optional checks turn themselves off: no `tailscale` command means no Tailscale check, a missing `CADDY_LOG`
file means no visitor check, and an empty `SITE_URL` means no site-down check.

## What it can't see

- The box isn't in the traffic path, so it can't see connection attempts the router blocks, or traffic.
- Port forwards made by hand in the router's admin page only show up if the router lists them through UPnP
  (many don't). Shodan's daily check is a second opinion, but its data can be weeks old.
- Devices that never answer ARP, or sit on another VLAN / guest network, are invisible to `arp-scan`.
- Device recognition trusts what devices announce. A new device that copies the mDNS name of a known
  device (or the LAN IP of an absent Tailscale machine, with a randomized MAC) is taken for that device and
  doesn't alert. It cuts noise from phones changing their private Wi-Fi address; it doesn't stop someone
  who is already on your Wi-Fi. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#trust-and-security).

## Requirements

- A Linux box wired to the LAN, running systemd (Raspberry Pi OS Lite, Debian, Ubuntu). Python 3.9+.
- `arp-scan` (install.sh installs it with apt).
- Optional: `avahi-utils` (`sudo apt install avahi-utils`) for the mDNS names devices announce. Without
  `avahi-resolve` devices are only known by MAC, vendor and the names you give them.
- For the port-forward check: a router with UPnP IGD. The defaults (`UPNP_PORT=5000`,
  `UPNP_DESC_PATH=/Public_UPNP_gatedesc.xml`) match Netgear routers; other routers use other ports and paths
  (see [docs/DEPLOY.md](docs/DEPLOY.md#port-forward-check-on-other-routers)). If UPnP is off or unreachable,
  the check just reports that.
- A Gmail account with an [App Password](https://support.google.com/accounts/answer/185833) to send the email
  (any SMTP-over-SSL server works via `SMTP_HOST` / `SMTP_PORT`).
- Optional: [Tailscale](https://tailscale.com) on the box; a site served by Caddy behind Tailscale Funnel.

## Privacy: what leaves your network

| Service | What it gets | When |
|---|---|---|
| [ipify](https://www.ipify.org) (HTTPS) | a request from your public IP | daily |
| [Shodan InternetDB](https://internetdb.shodan.io) (HTTPS) | your public IP | daily |
| [ip-api.com](https://ip-api.com) (**plain HTTP**, free tier) | IPs of outside visitors to your site, in cleartext | when new visitors appear (cached) |
| Gmail SMTP (TLS) | the alert emails, which list device IPs/MACs, port forwards and visitor IPs | when something alerts |

Set `GEO_LOOKUP=off` to never send visitor IPs to ip-api.com; visitors then show country `?` and each new
outside IP that signs in counts as a new network. Everything else (devices, history) stays in a local SQLite file.

## Layout

```
netwatch/run.py        runs the checks, sends one email per run (setup / alerts / weekly)
netwatch/forwards.py   router UPnP port mappings
netwatch/devices.py    LAN ARP scan + mDNS names; `nw devices` lists/names/watches devices
netwatch/tailnet.py    tailscale status
netwatch/visitors.py   site access log (visitor IP from X-Forwarded-For)
netwatch/vault.py      site down / back up
netwatch/exposure.py   public IP + Shodan InternetDB
netwatch/geo.py        ip-api.com lookups (cached)
netwatch/config.py     every setting, with defaults
deploy/                systemd units, install.sh, `nw` helper
tests/test_checks.py   unit tests (no network, no root: every check takes fake inputs)
tools/check_public.py  fails if a tracked file holds real-looking MACs, public IPs, emails or tailnet names
```

How the pieces fit together, with diagrams: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

Data: SQLite at `/var/lib/netwatch/netwatch.db`. Settings: `/etc/netwatch.env` (template
`config.example.env`). If [isp-outage-monitor](https://github.com/Hanegwen/isp-outage-monitor) is
installed on the same box, install.sh copies its email settings.

## Handy commands

```sh
nw run --dry-run                          # what would alert right now (changes nothing)
nw run --weekly                           # send the weekly summary now
nw devices --watch MAC                    # email every time that device comes back (away 30+ min)
nw devices --unwatch MAC
nw devices                                # every device ever seen
nw devices --name aa:bb:cc:dd:ee:ff "Kitchen speaker"
nw visitors                               # this month's site visitors
nw visitors --name "US|AS64500" "Family laptop"   # name a network seen signed in
journalctl -u netwatch                    # run log
systemctl list-timers 'netwatch*'         # when it runs next
```

`nw` runs as the service user (through `sudo` if you are someone else).

To allow a port forward on purpose (e.g. Plex remote access), add its UPnP label prefix to `ALLOWED_FORWARDS`
in `/etc/netwatch.env`, e.g. `ALLOWED_FORWARDS="tailscale-portmap,Plex Media Server"`.

## Tests

```sh
python3 -m unittest
python3 tools/check_public.py     # CI runs this too: nothing personal in this public repo
```

Working on it with an AI coding agent: see [CLAUDE.md](CLAUDE.md).

## License

MIT, see [LICENSE](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
