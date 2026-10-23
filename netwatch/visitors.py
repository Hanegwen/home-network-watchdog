"""Who reaches the self-hosted site from the internet (Caddy JSON access log behind Tailscale Funnel).

Funnel sets X-Forwarded-For to the visitor's IP. Only the rightmost entry is trusted: anything to its left
came from the client and can be forged (e.g. our own home IP, to hide from these alerts).

Alerts when someone is *signed in* from a country/network not seen signed in before, and when one outside
IP hammers the site. Anonymous visitors (bots scanning the public URL) only go into the weekly summary.
"""
import argparse
import json
import os
import re
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
    """-> (ts, ip, signed_in) for a Funnel request, else None."""
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
    return d.get("ts", 0), ip, signed_in


def check(conn, now, lines=None, fetch=None):
    lines = read_new_lines(conn) if lines is None else lines
    home_ip = db.get(conn, "home_ip")
    per_ip = defaultdict(lambda: [0, 0])  # ip -> [requests, signed_in requests]
    for line in lines:
        p = parse(line)
        if not p or p[1] == home_ip or not geo.is_public(p[1]):
            continue
        per_ip[p[1]][0] += 1
        per_ip[p[1]][1] += p[2]
    if not per_ip:
        return [], []
    day = now.strftime("%Y-%m-%d")
    for ip, (n, s) in per_ip.items():
        conn.execute("INSERT INTO visits (day, ip, requests, signed_in) VALUES (?,?,?,?) ON CONFLICT(day, ip) "
                     "DO UPDATE SET requests = requests + excluded.requests, signed_in = signed_in + excluded.signed_in",
                     (day, ip, n, s))
    info = geo.lookup(conn, per_ip, fetch=fetch)
    alerts, ts = [], now.timestamp()
    for ip, (n, s) in sorted(per_ip.items()):
        row = info[ip]
        if s:
            key = f"{row['cc']}|{row['asn']}"
            if conn.execute("INSERT OR IGNORE INTO networks (key, first_seen) VALUES (?, ?)",
                            (key, int(ts))).rowcount:
                alerts.append((f"{config.SITE_NAME} used from a new place: {row['country']}",
                               f"Someone signed in to the {config.SITE_NAME} from a place/network not seen before:\n"
                               f"  {ip}  {geo.describe(row)}\n  {s} signed-in requests\n\n"
                               "Family on a new phone carrier, at work, or traveling is normal - ignore it and this "
                               "network won't alert again. If nobody was using it, change that account's password "
                               "and check the site's list of users.\n" + _name_hint(key)))
        if n >= config.HAMMER_REQUESTS and db.once(conn, f"hammer:{ip}:{day}", ts):
            alerts.append((f"{ip} is hammering the {config.SITE_NAME}",
                           f"{n} requests in the last few minutes from\n  {ip}  {geo.describe(row)}\n"
                           f"{'(signed in)' if s else '(not signed in - likely a bot)'}"))
    return alerts, []


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
