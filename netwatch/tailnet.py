"""New machines added to the Tailscale network (they can reach machines on your tailnet). Skipped without tailscale."""
import ipaddress
import json
import shutil
import subprocess

from . import db


def _status():
    out = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=30,
                         check=True).stdout
    return [p for p in (json.loads(out).get("Peer") or {}).values()
            if "funnel-ingress-node" not in p.get("HostName", "")]


def peers():
    """-> {id: (name, os)}, ignoring Funnel's public relay nodes."""
    return {p["ID"]: (p.get("HostName", "?"), p.get("OS", "")) for p in _status()}


def _lan_ip(peer):
    """The peer's home-LAN IP if Tailscale talks to it directly over the LAN, else None."""
    host = (peer.get("CurAddr") or "").rpartition(":")[0].strip("[]")
    try:
        return host if ipaddress.ip_address(host).is_private else None
    except ValueError:
        return None


def lan_hosts():
    """-> {lan_ip: tailscale hostname} for Tailscale machines on the home Wi-Fi/LAN right now.
    Tailscale only knows a peer's LAN address while a direct connection is up, so ping the
    online peers that don't have one yet first."""
    for p in _status():
        if p.get("Online") and not _lan_ip(p) and p.get("TailscaleIPs"):
            subprocess.run(["tailscale", "ping", "-c", "1", "--timeout", "3s", p["TailscaleIPs"][0]],
                           capture_output=True, timeout=10)
    return {ip: p.get("HostName", "?") for p in _status() if (ip := _lan_ip(p))}


def check(conn, now, current=None):
    if current is None:
        if not shutil.which("tailscale"):
            return [], []
        current = peers()
    known = {r["id"] for r in conn.execute("SELECT id FROM peers")}
    first_run = db.get(conn, "peers_baselined") is None
    new = [(i, n, o) for i, (n, o) in current.items() if i not in known]
    for i, n, o in new:
        conn.execute("INSERT INTO peers (id, name, os, first_seen) VALUES (?,?,?,?)", (i, n, o, int(now.timestamp())))
    lines = "\n".join(f"  {n} ({o or 'unknown OS'})" for _, n, o in new)
    if first_run:
        db.put(conn, "peers_baselined", int(now.timestamp()))
        return [], [f"Tailscale machines on your tailnet:\n{lines or '  none'}"]
    if not new:
        return [], []
    return [("new machine joined Tailscale",
             f"Added to your Tailscale network (it can reach machines on your tailnet):\n{lines}\n\n"
             "If you didn't add it, remove it at https://login.tailscale.com/admin/machines")], []
