# Deploying Home Network Watch

A step-by-step setup on a Raspberry Pi. Any always-on Debian/Ubuntu box with systemd works the same way.
It takes about 20 minutes, and then 24 hours of quiet learning.

## 1. Prepare the Pi

1. Flash **Raspberry Pi OS Lite (64-bit)** with Raspberry Pi Imager. In its settings, set a hostname,
   a user and password, and turn on SSH.
2. Plug the Pi into the router with an **Ethernet cable**. A wired connection is more reliable for the
   device scan; Wi-Fi works too if you set `LAN_IFACE=wlan0` later.
3. SSH in and update:

   ```sh
   sudo apt update && sudo apt full-upgrade -y
   sudo apt install -y git
   ```

4. Set your time zone. The daily check runs at 8 AM local time and emails show local times.

   ```sh
   timedatectl list-timezones | grep Europe      # find yours
   sudo timedatectl set-timezone Europe/London
   ```

5. Optional: install [Tailscale](https://tailscale.com/download/linux) and run `sudo tailscale up` if you
   want the Tailscale check or host a site through Funnel.

## 2. Install

```sh
sudo git clone https://github.com/Hanegwen/home-network-watchdog /opt/netwatch
cd /opt/netwatch
sudo ./deploy/install.sh
```

install.sh:

- creates a system user `netwatch` that the checks run as (to use an existing user instead:
  `sudo SERVICE_USER=pi ./deploy/install.sh`),
- installs `arp-scan` and lets it open raw sockets (`setcap cap_net_raw+ep`),
- creates `/etc/netwatch.env` from `config.example.env` (owner root, group `netwatch`, mode 640) if it
  doesn't exist yet. If [isp-outage-monitor](https://github.com/Hanegwen/isp-outage-monitor) is
  installed (`/etc/comcast-monitor.env`), its `REPORT_TO`, `SMTP_USER` and `SMTP_APP_PASSWORD` are copied in.
- installs the `nw` helper to `/usr/local/bin`, and the systemd units and timers, and starts the timers.

The timers start right away. Until the email settings are filled in, each run stops with
`REPORT_TO / SMTP_USER / SMTP_APP_PASSWORD not configured` in the log and nothing is saved, so that's harmless.

## 3. Fill in /etc/netwatch.env

```sh
sudo nano /etc/netwatch.env
```

Quote values that contain spaces (`NAME="two words"`). Lines starting with `#` are defaults; remove the `#`
to change one. Never commit or share this file: it holds your email password.

### Email (required)

| Setting | What to put |
|---|---|
| `REPORT_TO` | the address that receives alerts (several: comma-separated) |
| `SMTP_USER` | the Gmail address that sends them |
| `SMTP_APP_PASSWORD` | a Gmail **App Password** (not your normal password). It needs 2-Step Verification on the Google account; create one at https://support.google.com/accounts/answer/185833 |
| `SMTP_HOST`, `SMTP_PORT` | default `smtp.gmail.com` and `465` (SMTP over SSL). Change for another provider |

### Your network

| Setting | What to put |
|---|---|
| `LAN_IFACE` | the network interface on your LAN. List them with `ip -br link`: usually `eth0` (wired) or `wlan0` (Wi-Fi). Skip `lo` and `tailscale0` |
| `ROUTER_IP` | your router's LAN address, default `192.168.1.1`. Find it with `ip route` (the address after `default via`) |
| `ALLOWED_FORWARDS` | port forwards you expect, by the start of their UPnP label, comma-separated. Default `tailscale-portmap` (Tailscale opens one for direct connections). Example: `ALLOWED_FORWARDS="tailscale-portmap,Plex Media Server"` |
| `UPNP_PORT`, `UPNP_DESC_PATH` | where the router's UPnP description lives, default `5000` and `/Public_UPNP_gatedesc.xml` (Netgear). See [other routers](#port-forward-check-on-other-routers) |
| `OUI_FILE` | arp-scan's MAC vendor list, default `/usr/share/arp-scan/ieee-oui.txt` |
| `DB_PATH` | the SQLite file, default `/var/lib/netwatch/netwatch.db` |

For mDNS (Bonjour) device names, install `avahi-utils` (`sudo apt install -y avahi-utils`). It's optional:
without it, `nw devices` shows only MACs, vendors and your own names, and a phone that changes its private
Wi-Fi address is recognized only if it is one of your Tailscale machines.

### Optional: PC check-in line in the weekly summary

| Setting | What to put |
|---|---|
| `PC_REPORT` | a JSON file a PC rewrites regularly, with `generated` (Unix seconds) and optionally `pc` (its name), e.g. the Steam report of isp-outage-monitor's Windows helper. Unset = no line |
| `PC_STALE_HOURS` | hours of silence before the line says **NOT CONNECTING**, default `48` |

### Optional: a site you host through Tailscale Funnel

Leave these alone if you don't host a site. A missing log file or an empty `SITE_URL` turns those checks off.

| Setting | What to put |
|---|---|
| `CADDY_LOG` | Caddy's JSON access log for the site, default `/var/log/caddy/site-access.log`. See [the Caddy log](#the-caddy-access-log) |
| `SITE_ACCOUNTS_UNIT` | optional. The systemd unit of the site's backend, if its log has one line per request with `ip=<visitor ip>` and `email=<account>` (or `user=`), and ideally `ua="Chrome 155/Windows"`. Visitor emails then say which account signed in and whether it already uses that kind of device (see [the README](../README.md)). The service user must be able to read the journal (group `adm` or `systemd-journal`) |
| `SITE_NAME` | what emails call it, default `website` (e.g. `SITE_NAME="home wiki"`) |
| `SITE_URL` | an address on this box that answers `200 OK` when the site works, e.g. `http://127.0.0.1:8000/`. If it doesn't answer for 5+ minutes you get an email, and another when it's back |
| `MAINT_DIR` | optional. A directory where your own maintenance script writes `active.json` while the site is down on purpose; no alert then |
| `HAMMER_REQUESTS` | requests from one outside IP in one 5-minute run that count as hammering, default `600` |
| `GEO_LOOKUP` | `on` (default) looks up visitors' country and network at ip-api.com, over plain HTTP. `off` sends nothing: visitors show country `?`, and each new outside IP that signs in counts as a new network |

## 4. First run

See what it finds, without sending or saving anything:

```sh
nw run --dry-run
```

It prints `note:` lines (what it sees now), `ALERT` lines and `check failed:` lines. Fix any failed check
(see [Troubleshooting](#troubleshooting)), then run it for real, or wait up to 5 minutes for the timer:

```sh
sudo systemctl start netwatch.service
journalctl -u netwatch -n 30
```

You get one email, **"Home network watch is set up"**, listing what is watched and what it saw:

```
Home network watch now checks the network every 5 minutes and emails you when:
  - a device opens an internet port on the router (UPnP)
  - a device it has never seen joins the Wi-Fi/LAN
  ...
What it sees right now (all treated as normal from here on):

Shodan's last scan of 198.51.100.7 lists open ports: none
Router port forwards open right now (UPnP):
  UDP:41641 -> 192.168.1.20:41641  tailscale-portmap
Devices on the network right now (14) - these are now 'known':
  192.168.1.1     00:11:22:33:44:01  NETGEAR
  192.168.1.23    da:00:00:00:00:05  private Wi-Fi address (phone/tablet/laptop)
  ...
```

Read it once: anything open or present now is treated as normal from here on. An unexpected port forward
already open gets its own alert.

**The first 24 hours** are a learning period for devices: phones and gadgets that were asleep during the
first scan join quietly. After that, every new MAC address emails you.

Phones, tablets and laptops use a randomized "private Wi-Fi address" that can change. A new address is
recognized and named, without an alert, when it announces the mDNS name of a device already seen (generic
names like `Android` don't count), or when it is one of your own Tailscale machines on its LAN IP. Any device
can announce any name, so this is a noise filter, not a defense (see [ARCHITECTURE.md](ARCHITECTURE.md#trust-and-security)).

## 5. Day to day

Name devices so lists and alerts are easy to read:

```sh
nw devices                                         # every device ever seen
nw devices --name 00:11:22:33:44:01 "Kitchen speaker"
nw devices --watch 00:11:22:33:44:01             # email each time it comes back after 30+ min away
nw devices --unwatch 00:11:22:33:44:01
```

Name networks that signed in to your site (the alert prints the exact command):

```sh
nw visitors
nw visitors --name "US|AS64500" "Family laptop"
```

A weekly summary arrives on Mondays after 8 AM; `nw run --weekly` sends one now.

`nw` runs as the service user, through `sudo` if you are someone else, so it may ask for your password.

## The Caddy access log

The visitor check reads a Caddy v2 JSON access log for requests that came in through Tailscale Funnel (they
carry a `Tailscale-Funnel-Request` header). The visitor's IP comes from `X-Forwarded-For`; Funnel sets it,
and only its last entry is trusted. A visitor counts as **signed in** on a successful request to a path
starting with `/api/` that carries an `Authorization` header or a `?token=` parameter. A site that signs in
only with cookies is still counted, but as anonymous visitors.

Example Caddyfile, with Funnel forwarding to Caddy on port 8080 (`sudo tailscale funnel --bg 8080`) and your
app on port 8000:

```caddy
:8080 {
	bind 127.0.0.1
	log {
		output file /var/log/caddy/site-access.log {
			mode 0640
		}
		format filter {
			request>uri query {
				replace token REDACTED
			}
		}
	}
	reverse_proxy 127.0.0.1:8000
}
```

- Caddy already logs `Authorization` and `Cookie` headers as `REDACTED` (leave the `log_credentials` option
  off). Don't delete the `Authorization` header from the log: the sign-in check looks for it.
- `replace token REDACTED` hides sign-in tokens in URLs. Add more `replace <param> REDACTED` lines for other
  secret query parameters.
- `mode 0640` lets the `caddy` group read the file (Caddy's default is 0600). Let the service user read it:

  ```sh
  sudo usermod -aG caddy netwatch
  sudo -u netwatch head -c 200 /var/log/caddy/site-access.log    # should print, not "Permission denied"
  ```

Log rotation is handled: after Caddy rolls the file, the next run starts at the top of the new one.

## Port-forward check on other routers

The check asks the router for its UPnP port mappings (`GetGenericPortMappingEntry`, read-only). To find
your router's description URL, ask it on the LAN:

```sh
python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n", ("239.255.255.250", 1900)); print(s.recv(4096).decode())'
```

The `LOCATION:` line, e.g. `http://192.168.1.1:5000/Public_UPNP_gatedesc.xml`, gives `ROUTER_IP`,
`UPNP_PORT` and `UPNP_DESC_PATH`. No answer usually means UPnP is off in the router, which is the safest
setting; the setup email then says so. The router must offer the `WANIPConnection:1` service; if it doesn't,
the run log shows `check failed: port forwards: ... no WANIPConnection:1 service`.

## Updating

```sh
cd /opt/netwatch
sudo git pull
sudo ./deploy/install.sh         # keeps the user the checks already run as
```

install.sh never overwrites `/etc/netwatch.env`. Compare it with `config.example.env` for new settings.

## Uninstalling

```sh
sudo systemctl disable --now netwatch.timer netwatch-daily.timer
sudo rm /etc/systemd/system/netwatch.service /etc/systemd/system/netwatch.timer \
        /etc/systemd/system/netwatch-daily.service /etc/systemd/system/netwatch-daily.timer /usr/local/bin/nw
sudo systemctl daemon-reload
sudo rm -rf /opt/netwatch /var/lib/netwatch /etc/netwatch.env
sudo userdel netwatch
sudo setcap -r "$(command -v arp-scan)"     # optional: undo the raw-socket permission
```

## Troubleshooting

Start with the run log: `journalctl -u netwatch -n 50` (and `-u netwatch-daily` for the 8 AM run). A broken
check shows as `check failed: <check>: <error>` and the other checks keep running.

| Symptom | Fix |
|---|---|
| `REPORT_TO / SMTP_USER / SMTP_APP_PASSWORD not configured` | fill in the email settings in `/etc/netwatch.env` |
| `535` / `Username and Password not accepted` | use a Gmail App Password, not the account password; 2-Step Verification must be on |
| `check failed: devices: ...` | wrong `LAN_IFACE` (check `ip -br link`), or `arp-scan` missing: re-run install.sh |
| "Router UPnP is off or unreachable" but UPnP is on | wrong `ROUTER_IP`, `UPNP_PORT` or `UPNP_DESC_PATH`; see [other routers](#port-forward-check-on-other-routers) |
| no Tailscale check | `tailscale` isn't installed, or `sudo -u netwatch tailscale status` fails |
| no visitors ever | check `CADDY_LOG`, that it is JSON, that the service user can read it, and that requests come through Funnel |
| `sudo: a password is required` from `nw` | your user needs sudo rights, or run it as root: `sudo nw ...` |
| start over (re-learn everything, new setup email) | `sudo rm /var/lib/netwatch/netwatch.db*` |
