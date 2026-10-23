"""Country / network lookups for outside IPs (ip-api.com free batch API), cached in the DB.

The free tier is HTTP only, so visitor IPs go to ip-api.com in cleartext; GEO_LOOKUP=off turns it off.
"""
import ipaddress
import json
import time
import urllib.request

from . import config

FIELDS = "status,query,country,countryCode,regionName,city,org,isp,as"


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup(conn, ips, fetch=None):
    """-> {ip: row} for every ip; unknown ones are fetched and cached."""
    ips = sorted(set(ips))
    if fetch is None and not config.GEO_LOOKUP:
        # nothing leaves the network; each IP counts as its own network (asn = the IP), not cached
        return {ip: {"ip": ip, "country": "?", "cc": "??", "region": "", "city": "", "org": "lookup off", "asn": ip}
                for ip in ips}
    have = {r["ip"]: r for r in conn.execute(
        "SELECT * FROM ipinfo WHERE ip IN (%s)" % ",".join("?" * len(ips)), ips)} if ips else {}
    missing = [ip for ip in ips if ip not in have]
    for i in range(0, len(missing), 100):
        for d in (fetch or _fetch)(missing[i:i + 100]):
            ok = d.get("status") == "success"
            conn.execute("INSERT OR REPLACE INTO ipinfo VALUES (?,?,?,?,?,?,?,?)",
                         (d["query"], d.get("country", "?") if ok else "?", d.get("countryCode", "??") if ok else "??",
                          d.get("regionName", ""), d.get("city", ""), d.get("org") or d.get("isp", ""),
                          (d.get("as", "") or "").split(" ")[0], int(time.time())))
    if missing:
        have.update({r["ip"]: r for r in conn.execute(
            "SELECT * FROM ipinfo WHERE ip IN (%s)" % ",".join("?" * len(missing)), missing)})
    return have


def _fetch(ips):
    req = urllib.request.Request(f"http://ip-api.com/batch?fields={FIELDS}", json.dumps(ips).encode(),
                                 {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=15))


def describe(row):
    place = ", ".join(p for p in (row["city"], row["region"], row["country"]) if p)
    return f"{place} - {row['org'] or 'unknown network'} ({row['asn'] or 'no ASN'})"
