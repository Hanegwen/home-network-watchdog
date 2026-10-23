"""Settings come from environment variables (installed: /etc/netwatch.env, template config.example.env)."""
import os


def _get(name, default=None):
    value = os.environ.get(name)
    return value if value not in (None, "") else default


DB_PATH = _get("DB_PATH", "/var/lib/netwatch/netwatch.db")

# Router port forwards (UPnP)
ROUTER_IP = _get("ROUTER_IP", "192.168.1.1")
UPNP_PORT = int(_get("UPNP_PORT", "5000"))
UPNP_DESC_PATH = _get("UPNP_DESC_PATH", "/Public_UPNP_gatedesc.xml")  # Netgear's; other routers differ
# Forwards that are expected (matched against the UPnP description); everything else alerts
ALLOWED_FORWARDS = [s.strip() for s in _get("ALLOWED_FORWARDS", "tailscale-portmap").split(",") if s.strip()]

# New devices on the LAN
LAN_IFACE = _get("LAN_IFACE", "eth0")
OUI_FILE = _get("OUI_FILE", "/usr/share/arp-scan/ieee-oui.txt")

# Self-hosted site (optional): visitors from the Caddy access log behind Tailscale Funnel, and the site being down
CADDY_LOG = _get("CADDY_LOG", "/var/log/caddy/site-access.log")  # missing file = visitor check does nothing
SITE_NAME = _get("SITE_NAME", "website")
SITE_URL = _get("SITE_URL", _get("NETWATCH_VAULT_URL"))  # unset = no down check
MAINT_DIR = _get("MAINT_DIR", _get("NETWATCH_VAULT_MAINT_DIR"))  # active.json there = planned downtime
HAMMER_REQUESTS = int(_get("HAMMER_REQUESTS", "600"))  # one outside IP, one 5-minute run
# Country/network of outside visitors via ip-api.com (plain HTTP); "off" keeps visitor IPs at home
GEO_LOOKUP = _get("GEO_LOOKUP", "on").lower() not in ("off", "no", "false", "0")

# Optional PC check-in for the weekly summary: the Steam report file that isp-outage-monitor's Windows helper
# (pc/steam-report.ps1) rewrites every 5 minutes, e.g. /var/lib/comcast-monitor/steam.json. Unset = no line.
PC_REPORT = _get("PC_REPORT", "")
PC_STALE_HOURS = float(_get("PC_STALE_HOURS", "48"))

# Email (Gmail SMTP with an app password)
REPORT_TO = _get("REPORT_TO", "")
SMTP_HOST = _get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(_get("SMTP_PORT", "465"))
SMTP_USER = _get("SMTP_USER", "")
SMTP_APP_PASSWORD = _get("SMTP_APP_PASSWORD", "")
