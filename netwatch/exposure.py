"""What the internet can see on our public IP, from Shodan's free InternetDB (a second opinion on forwards).

Shodan rescans every few weeks, so its list lags reality: we alert only on ports it *newly* lists.
"""
import json
import urllib.request

from . import db


UA = {"User-Agent": "home-network-watchdog/1.0 (+curl compatible)"}  # Shodan 403s urllib's default UA


def _open(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20)


def public_ip():
    return _open("https://api.ipify.org").read().decode().strip()


def shodan(ip):
    try:
        return json.load(_open(f"https://internetdb.shodan.io/{ip}"))
    except urllib.error.HTTPError as e:
        if e.code == 404:  # nothing known about this IP
            return {"ports": []}
        raise


def check(conn, now, ip=None, data=None):
    ip = ip or public_ip()
    alerts, notes = [], []
    old_ip = db.get(conn, "home_ip")
    if old_ip and old_ip != ip:
        notes.append(f"Home public IP changed: {old_ip} -> {ip}")
    db.put(conn, "home_ip", ip)

    data = shodan(ip) if data is None else data
    ports = sorted(set(data.get("ports", [])))
    prev = db.get(conn, "shodan_ports")
    db.put(conn, "shodan_ports", json.dumps(ports))
    listed = ", ".join(map(str, ports)) or "none"
    if prev is None:
        notes.append(f"Shodan's last scan of {ip} lists open ports: {listed}\n"
                     "(Shodan rescans every few weeks, so ports closed recently can still show here.)")
    else:
        new = sorted(set(ports) - set(json.loads(prev)))
        if new:
            alerts.append((f"internet scanners now see port(s) {', '.join(map(str, new))} open",
                           f"Shodan's latest scan of our public IP {ip} lists new open ports: "
                           f"{', '.join(map(str, new))} (all listed: {listed}).\n"
                           f"Details: https://www.shodan.io/host/{ip}\n"
                           "Check the router's port forwarding / UPnP page for what is forwarding them."))
    return alerts, notes
