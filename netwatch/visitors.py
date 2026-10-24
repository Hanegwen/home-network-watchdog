"""Who reaches the self-hosted site from the internet (Caddy JSON access log behind Tailscale Funnel).

Funnel sets X-Forwarded-For to the visitor's IP. Only the rightmost entry is trusted: anything to its left
came from the client and can be forged (e.g. our own home IP, to hide from these alerts).

Alerts when someone is *signed in* from a country/network not seen signed in before, and when one outside
IP hammers the site. Anonymous visitors (bots scanning the public URL) only go into the weekly summary.

With SITE_ACCOUNTS_UNIT set, the backend's own log says which account each visitor IP signed in as. Each account's
kinds of device ("iPhone app", "Chrome on Windows", from the User-Agent) are learned, at home too, so an alert can
say "this account's usual iPhone app on another network" or "a device this account has never used". A first
sign-in from an account's new kind of device alerts even on a known network.
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime

from . import config, db, geo


# "US|AS64500", or "??|<ip>" with GEO_LOOKUP=off. ip-api answers over plain HTTP, so anything else
# is not put into a command the reader might paste into a shell.
SAFE_KEY = re.compile(r"^[A-Z?]{2}\|[A-Za-z0-9.:]{1,45}$")


def _name_hint(key):
    if not SAFE_KEY.match(key):
        return "Name it with nw visitors --name (see nw visitors for the exact network key)."
    return f"Name it so the weekly summary says who it is:  nw visitors --name '{key}' \"Family laptop\""


def read_new_lines(conn, path=None):
    """Lines appended since the last run (handles log rotation)."""
    path = path or config.CADDY_LOG
    try:
        st = os.stat(path)
    except OSError:
        return []
    inode, offset = str(st.st_ino), int(db.get(conn, "log_offset", 0))
    if db.get(conn, "log_inode") != inode or offset > st.st_size:
        offset = 0
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    end = data.rfind(b"\n") + 1  # leave a half-written last line for next time
    db.put(conn, "log_inode", inode)
    db.put(conn, "log_offset", offset + end)
    return data[:end].replace(bytes(1), b"").decode("utf-8", "replace").splitlines()


def parse(line):
    """-> (ts, ip, signed_in, user_agent) for a Funnel request, else None."""
    try:
        d = json.loads(line)
        req = d["request"]
        h = req.get("headers", {})
    except (ValueError, KeyError, TypeError):
        return None
    if "Tailscale-Funnel-Request" not in h or not h.get("X-Forwarded-For"):
        return None
    ip = h["X-Forwarded-For"][-1].split(",")[-1].strip()  # rightmost: added by the proxy, not the client
    uri = req.get("uri", "")
    # signed in = a successful /api/ request with an Authorization header (Caddy logs it as REDACTED) or ?token=
    signed_in = (("Authorization" in h or "token=" in uri) and uri.startswith("/api/") and d.get("status", 500) < 400)
    return d.get("ts", 0), ip, signed_in, (h.get("User-Agent") or [""])[0]


# The same names the site backend may log ("Chrome 155/Windows"), so both logs name a device the same way
BROWSERS = (("Edge", r"Edg(?:e|A|iOS)?/"), ("Opera", r"OPR/"), ("Samsung", r"SamsungBrowser/"),
            ("Firefox", r"(?:Firefox|FxiOS)/"), ("Chrome", r"(?:Chrome|CriOS)/"), ("Safari", r"Version/[\d.]+ .*Safari/"),
            ("curl", r"curl/"), ("python", r"python-(?:httpx|requests)/"))
OSES = (("iPhone", "iOS"), ("iPad", "iPadOS"), ("Android", "Android"), ("Windows", "Windows"), ("CrOS", "ChromeOS"),
        ("Mac OS X", "macOS"), ("Macintosh", "macOS"), ("Linux", "Linux"))


def kind(browser, os_name):
    """A kind of device that survives updates: "Chrome on Windows", "iOS app" (an app's web view), "curl"."""
    if browser == "other":
        return f"{os_name} app" if os_name != "other" else "unknown device"
    return browser if os_name == "other" else f"{browser} on {os_name}"


def device(ua):
    browser = next((name for name, pattern in BROWSERS if re.search(pattern, ua)), "other")
    return kind(browser, next((label for token, label in OSES if token in ua), "other"))


BACKEND_IP = re.compile(r"\bip=(\S+)")
BACKEND_EMAIL = re.compile(r"\bemail=(\S+)")
BACKEND_USER = re.compile(r"\buser=(\S+)")
BACKEND_UA = re.compile(r'\bua="?([^"/]+)/([^"\s]+)')  # ua="Chrome 155/Windows", ua=other/iOS


def read_accounts(conn, now, lines=None):
    """-> {(ip, account, kind of device or None)} from the backend's log since the last run (empty when
    SITE_ACCOUNTS_UNIT is unset)."""
    if lines is None:
        if not config.SITE_ACCOUNTS_UNIT:
            return set()
        # the first run reads the last 30 days, so devices already in use don't alert; overlap is harmless
        since = int(db.get(conn, "accounts_since", int(now.timestamp()) - 30 * 86400)) - 60
        try:
            lines = subprocess.run(["journalctl", "-u", config.SITE_ACCOUNTS_UNIT, "--since", f"@{since}", "-o",
                                    "cat", "--no-pager", "-q"], capture_output=True, text=True, timeout=60).stdout
        except (OSError, subprocess.TimeoutExpired):
            return set()
        db.put(conn, "accounts_since", int(now.timestamp()))
        lines = lines.splitlines()
    out = set()
    for line in lines:
        ip, acct = BACKEND_IP.search(line), BACKEND_EMAIL.search(line) or BACKEND_USER.search(line)
        if ip and acct:
            ua = BACKEND_UA.search(line)
            dev = ua and kind(re.sub(r"\s+\d+$", "", ua.group(1)), ua.group(2))
            out.add((ip.group(1), acct.group(1).strip('"'), dev))
    return out


def _where(ip, home_ip):
    """Where a sign-in that isn't an outside visitor came from, or None for an outside IP."""
    if ip == home_ip:
        return "home"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr in TAILNET_V4 or addr in TAILNET_V6:
        return "Tailscale"
    return None if geo.is_public(ip) else "home network"


TAILNET_V4, TAILNET_V6 = ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48")


def _who(conn, pairs, where, ts, learning):
    """-> (lines saying which account signed in on what kind of device, a kind it never used before?).
    Remembers each (account, kind of device)."""
    lines, new = [], False
    for acct, dev in sorted(pairs):
        row = conn.execute("SELECT * FROM account_devices WHERE account = ? AND device = ?", (acct, dev)).fetchone()
        conn.execute("INSERT INTO account_devices VALUES (?,?,?,?,?) ON CONFLICT(account, device) DO UPDATE "
                     "SET last_seen = excluded.last_seen, last_where = excluded.last_where",
                     (acct, dev, int(ts), int(ts), where))
        if row:
            seen = datetime.fromtimestamp(row["last_seen"]).strftime("%Y-%m-%d")
            lines.append(f"  {acct} on {dev}: a kind of device this account uses (last {seen}, {row['last_where']})")
        else:
            new = new or not learning
            lines.append(f"  {acct} on {dev}: FIRST TIME this account used this kind of device")
    return lines, new


def check(conn, now, lines=None, fetch=None, accounts=None):
    lines = read_new_lines(conn) if lines is None else lines
    # after the access log: the backend logs a request before the proxy does, so every IP read is in here
    accounts = read_accounts(conn, now) if accounts is None else accounts
    learning = db.get(conn, "account_devices_from") is None  # first run with accounts: learn devices quietly
    if accounts and learning:
        db.put(conn, "account_devices_from", int(now.timestamp()))
    home_ip = db.get(conn, "home_ip")
    per_ip = defaultdict(lambda: [0, 0])  # ip -> [requests, signed_in requests]
    agents = defaultdict(set)              # outside ip -> kinds of device of its signed-in requests
    for line in lines:
        p = parse(line)
        if not p or p[1] == home_ip or not geo.is_public(p[1]):
            continue
        per_ip[p[1]][0] += 1
        per_ip[p[1]][1] += p[2]
        if p[2]:
            agents[p[1]].add(device(p[3]))
    signed_in = defaultdict(set)           # ip -> {(account, kind of device)}
    for ip, acct, dev in accounts:
        if dev or agents[ip]:
            signed_in[ip] |= {(acct, dev)} if dev else {(acct, d) for d in agents[ip]}
    ts = now.timestamp()
    for ip, pairs in signed_in.items():  # at home and over Tailscale (and everything on the first run): just learn
        where = _where(ip, home_ip) or (learning and "before alerts by account")
        if where and not (learning and ip in per_ip):
            _who(conn, pairs, where, ts, True)
    if not per_ip:
        return [], []
    day = now.strftime("%Y-%m-%d")
    for ip, (n, s) in per_ip.items():
        conn.execute("INSERT INTO visits (day, ip, requests, signed_in) VALUES (?,?,?,?) ON CONFLICT(day, ip) "
                     "DO UPDATE SET requests = requests + excluded.requests, signed_in = signed_in + excluded.signed_in",
                     (day, ip, n, s))
    info = geo.lookup(conn, per_ip, fetch=fetch)
    alerts = []
    for ip, (n, s) in sorted(per_ip.items()):
        row = info[ip]
        if s:
            key = f"{row['cc']}|{row['asn']}"
            new_network = conn.execute("INSERT OR IGNORE INTO networks (key, first_seen) VALUES (?, ?)",
                                       (key, int(ts))).rowcount
            name = conn.execute("SELECT name FROM networks WHERE key = ?", (key,)).fetchone()["name"]
            who, new_device = _who(conn, signed_in[ip], name or row["org"] or key, ts, learning)
            if new_network or new_device:
                alerts.append(_signed_in_alert(ip, row, s, key, who, new_network, new_device, bool(accounts)))
        if n >= config.HAMMER_REQUESTS and db.once(conn, f"hammer:{ip}:{day}", ts):
            alerts.append((f"{ip} is hammering the {config.SITE_NAME}",
                           f"{n} requests in the last few minutes from\n  {ip}  {geo.describe(row)}\n"
                           f"{'(signed in)' if s else '(not signed in - likely a bot)'}"))
    return alerts, []


def _signed_in_alert(ip, row, n, key, who, new_network, new_device, have_accounts):
    if new_device:
        verdict = ("A kind of device this account has NEVER used before signed in. If that person didn't just sign "
                   "in on a new phone, computer or browser, change that account's password and check the site's "
                   "list of users.")
    elif who:
        verdict = ("Each account here is on a kind of device it already uses, so this is most likely that person "
                   "on another network (phone carrier, work, travel). Nothing to do.")
    elif have_accounts:
        verdict = ("The site's log didn't say which account this was. If nobody was using it, change your "
                   "passwords and check the site's list of users.")
    else:
        verdict = ("Family on a new phone carrier, at work, or traveling is normal - ignore it and this network "
                   "won't alert again. If nobody was using it, change that account's password and check the "
                   "site's list of users.")
    body = (f"Someone signed in to the {config.SITE_NAME} from "
            f"{'a place/network not seen before' if new_network else 'a known network'}:\n"
            f"  {ip}  {geo.describe(row)}\n  {n} signed-in requests\n")
    if who:
        body += "\nWho (account and kind of device):\n" + "\n".join(who) + "\n"
    body += "\n" + verdict + ("\n" + _name_hint(key) if new_network else "")
    if new_device:
        subject = f"{config.SITE_NAME}: an account signed in from a new kind of device"
    else:
        usual = f" - {who[0].split(' on ')[0].strip()}'s usual device" if who and len(who) == 1 else ""
        subject = f"{config.SITE_NAME} used from a new place: {row['country']}{usual}"
    return subject, body


def summary(conn, since_day):
    """Text block for the weekly summary."""
    rows = conn.execute(
        "SELECT v.ip, SUM(v.requests) n, SUM(v.signed_in) s, i.country, i.city, i.org, w.name FROM visits v "
        "LEFT JOIN ipinfo i ON i.ip = v.ip LEFT JOIN networks w ON w.key = i.cc || '|' || i.asn "
        "WHERE v.day >= ? GROUP BY v.ip ORDER BY n DESC", (since_day,)).fetchall()
    if not rows:
        return f"No outside visitors to the {config.SITE_NAME}."
    users = [r for r in rows if r["s"]]
    bots = [r for r in rows if not r["s"]]
    by_country = defaultdict(int)
    for r in bots:
        by_country[r["country"] or "?"] += 1
    out = [f"Signed-in visitors ({len(users)} IPs):"]
    out += [f"  {r['ip']:<16} {r['n']:>6} req  {r['city'] or ''}, {r['country'] or '?'} - {r['org'] or '?'}"
            + (f"  [{r['name']}]" if r["name"] else "") for r in users] or ["  none"]
    out.append(f"\nAnonymous visitors / bots ({len(bots)} IPs): " +
               ", ".join(f"{c} {k}" for k, c in sorted(by_country.items(), key=lambda kv: -kv[1])))
    out += [f"  {r['ip']:<16} {r['n']:>6} req  {r['country'] or '?'} - {r['org'] or '?'}" for r in bots[:10]]
    since_ts = int(datetime.strptime(since_day, "%Y-%m-%d").timestamp())
    used = conn.execute("SELECT * FROM account_devices WHERE last_seen >= ? ORDER BY account, last_seen DESC",
                        (since_ts,)).fetchall()
    learned = int(db.get(conn, "account_devices_from", 0))  # devices learned at setup aren't "new"
    if used:
        out.append("\nAccounts and the kinds of device they used:")
        out += [f"  {r['account']} - {r['device']} (last {datetime.fromtimestamp(r['last_seen']):%m-%d}, "
                f"{r['last_where']})" + ("  NEW" if r["first_seen"] >= max(since_ts, learned + 1) else "")
                for r in used]
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", nargs=2, metavar=("NETWORK", "NAME"), help="e.g. 'US|AS64500' \"Family laptop\"")
    args = p.parse_args()
    conn = db.connect()
    if args.name:
        if conn.execute("UPDATE networks SET name = ? WHERE key = ?", (args.name[1], args.name[0])).rowcount == 0:
            raise SystemExit(f"no network {args.name[0]}")
        conn.commit()
    print("Networks seen signed in:")
    for r in conn.execute("SELECT * FROM networks ORDER BY first_seen"):
        seen = datetime.fromtimestamp(r["first_seen"]).strftime("%Y-%m-%d")
        print(f"  {r['key']:<16} first {seen}  {r['name'] or ''}")
    print()
    print(summary(conn, datetime.now().strftime("%Y-%m-01")))


if __name__ == "__main__":
    main()
