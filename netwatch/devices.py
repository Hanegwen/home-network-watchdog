"""New devices on the home network (ARP scan of the LAN).

  python -m netwatch.devices                 list every device ever seen
  python -m netwatch.devices --name MAC TEXT give a device a friendly name
  python -m netwatch.devices --watch MAC     email every time it comes back (--unwatch MAC stops it)
"""
import argparse
import functools
import re
import subprocess
from datetime import datetime

from . import config, db, tailnet

LEARN_SECONDS = 24 * 3600  # devices asleep during the first scan show up over the first day
WATCH_AWAY_SECONDS = 30 * 60  # a watched device alerts when it comes back after at least this long away


def scan():
    """-> {mac: ip}. Needs CAP_NET_RAW (the systemd unit grants it)."""
    out = subprocess.run(["arp-scan", "-I", config.LAN_IFACE, "--localnet", "-q", "-x", "-r", "2"],
                         capture_output=True, text=True, timeout=60, check=True).stdout
    found = {}
    for line in out.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})", line)
        if m:
            found[m.group(2)] = m.group(1)
    return found


@functools.lru_cache(maxsize=1)
def _ouis():
    table = {}
    try:
        with open(config.OUI_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                prefix, _, vendor = line.rstrip("\n").partition("\t")
                if len(prefix) == 6:
                    table[prefix.upper()] = vendor
    except OSError:
        pass
    return table


def private_mac(mac):
    """Phones/tablets/laptops using a randomized 'private Wi-Fi address'."""
    return int(mac[1], 16) & 2 == 2


def vendor(mac):
    if private_mac(mac):
        return "private Wi-Fi address (phone/tablet/laptop)"
    return _ouis().get(mac.replace(":", "")[:6].upper(), "unknown maker")


# mDNS names many phones share; they don't prove which device it is
GENERIC_NAMES = {"android", "iphone", "ipad", "localhost", "macbook", "macbook-air", "macbook-pro", "raspberrypi"}


def hostnames(ips):
    """-> {ip: name} for devices that answer an mDNS (Bonjour) reverse lookup, e.g. "NAS-1234" or
    "iPhone-12". One batched avahi-resolve call; ~5 s since silent devices time out together."""
    if not ips:
        return {}
    try:
        out = subprocess.run(["avahi-resolve", "-a", *ips], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    names = {}
    for line in out.splitlines():
        ip, _, name = line.partition("\t")
        if name:
            names[ip.strip()] = name.strip().removesuffix(".local")
    return names


def identifying(name):
    return bool(name) and name.lower() not in GENERIC_NAMES


def same_name(conn, new, names):
    """A new MAC announcing the mDNS name of a device we already know is that device with a fresh
    private Wi-Fi address (or a new network card) - copy its friendly name over and don't alert."""
    unknown = []
    for mac, ip, v in new:
        name = names.get(ip)
        old = identifying(name) and conn.execute(
            "SELECT mac, name FROM devices WHERE hostname = ? COLLATE NOCASE AND mac != ? "
            "ORDER BY last_seen DESC", (name, mac)).fetchone()
        if old:
            conn.execute("UPDATE devices SET name = ? WHERE mac = ?", (old["name"] or name, mac))
            print(f"recognized {mac} at {ip} as {old['name'] or name} (announces mDNS name {name}, was {old['mac']})")
        else:
            unknown.append((mac, ip, v))
    return unknown


def recognize(conn, new, hosts):
    """Private Wi-Fi addresses change now and then; if a new one sits on the LAN IP of one of our
    own Tailscale machines, it's that machine with a fresh address - name it and don't alert."""
    try:
        hosts = hosts() if callable(hosts) else hosts
    except Exception as e:
        print("tailscale lookup failed:", e)
        return new
    unknown = []
    for mac, ip, v in new:
        if private_mac(mac) and ip in hosts:
            conn.execute("UPDATE devices SET name = ? WHERE mac = ?", (hosts[ip], mac))
            print(f"recognized {mac} at {ip} as {hosts[ip]} (Tailscale)")
        else:
            unknown.append((mac, ip, v))
    return unknown


def _back_alert(r, ip, mdns, now):
    away = (now.timestamp() - r["last_seen"]) / 3600
    away = f"{away:.0f} hours" if away < 48 else f"{away / 24:.0f} days"
    label = r["name"] or r["mac"]
    return (f"watched device is back on the network: {label} ({ip})",
            f"A device you asked to be told about just rejoined the home network:\n"
            f"  {ip:<15} {r['mac']}  {r['vendor']}\n"
            f"  announces itself as: {mdns or r['hostname'] or '(no mDNS name)'}\n"
            f"  away for about {away}; first seen {datetime.fromtimestamp(r['first_seen']):%Y-%m-%d %H:%M}\n"
            f"  back at {now:%a %Y-%m-%d %H:%M}\n\n"
            f"To see what it is while it's here: the router's device list (http://{config.ROUTER_IP}, e.g. Attached "
            "Devices) shows its name. If you don't recognize it, change the Wi-Fi password (router: Wireless).\n"
            f"Stop these emails:  nw devices --unwatch {r['mac']}")


def check(conn, now, found=None, tailnet_hosts=None, names=None):
    found = scan() if found is None else found
    names = hostnames(list(found.values())) if names is None else names
    known = {r["mac"] for r in conn.execute("SELECT mac FROM devices")}
    first_run = not known
    ts, new = int(now.timestamp()), []
    if first_run:
        db.put(conn, "devices_baselined", ts)
    learning = ts - int(db.get(conn, "devices_baselined", 0)) < LEARN_SECONDS
    watched = {r["mac"]: r for r in conn.execute("SELECT * FROM devices WHERE watch = 1")}
    back = []
    for mac, ip in sorted(found.items(), key=lambda kv: tuple(int(p) for p in kv[1].split("."))):
        if mac not in known:
            new.append((mac, ip, vendor(mac)))
            conn.execute("INSERT INTO devices (mac, ip, vendor, first_seen, last_seen) VALUES (?,?,?,?,?)",
                         (mac, ip, vendor(mac), ts, ts))
        else:
            if mac in watched and ts - watched[mac]["last_seen"] >= WATCH_AWAY_SECONDS:
                back.append((watched[mac], ip))
            conn.execute("UPDATE devices SET ip = ?, last_seen = ? WHERE mac = ?", (ip, ts, mac))
    alerts = [_back_alert(r, ip, names.get(ip), now) for r, ip in back]
    if not first_run and new:
        new = same_name(conn, new, names)
    for mac, ip in found.items():  # after same_name, so a new MAC doesn't match its own name
        if names.get(ip):
            conn.execute("UPDATE devices SET hostname = ? WHERE mac = ?", (names[ip], mac))
    if not first_run and any(private_mac(mac) for mac, _, _ in new):
        new = recognize(conn, new, tailnet.lan_hosts if tailnet_hosts is None else tailnet_hosts)
    lines = "\n".join(f"  {ip:<15} {mac}  {v}" + (f"  announces itself as \"{names[ip]}\"" if names.get(ip) else "")
                      for mac, ip, v in new)
    if first_run:
        return alerts, [f"Devices on the network right now ({len(new)}) - these are now 'known':\n{lines}"]
    if not new:
        return alerts, []
    if learning:
        print("learning (first 24 h), not alerting:\n" + lines)
        return alerts, []
    return alerts + [(f"new device on the network ({new[0][1]})" if len(new) == 1 else f"{len(new)} new devices on the network",
             f"Never seen before on the home network:\n{lines}\n\n"
             "If it's a guest or a new gadget, nothing to do. If you don't recognize it, change the Wi-Fi password "
             "(in the router's wireless settings) - that kicks everyone off and they rejoin with the new one.\n"
             "Name it so it's easy to spot later:  nw devices --name <mac> \"Kitchen speaker\"")], []


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", nargs=2, metavar=("MAC", "NAME"))
    p.add_argument("--watch", metavar="MAC", help="email every time this device comes back")
    p.add_argument("--unwatch", metavar="MAC")
    args = p.parse_args()
    conn = db.connect()
    if args.name:
        mac, name = args.name[0].lower(), args.name[1]
        if conn.execute("UPDATE devices SET name = ? WHERE mac = ?", (name, mac)).rowcount == 0:
            raise SystemExit(f"no device {mac}")
        conn.commit()
    for mac, flag in ((args.watch, 1), (args.unwatch, 0)):
        if mac:
            if conn.execute("UPDATE devices SET watch = ? WHERE mac = ?", (flag, mac.lower())).rowcount == 0:
                raise SystemExit(f"no device {mac}")
            conn.commit()
            print(("watching " if flag else "stopped watching ") + mac.lower())
    for r in conn.execute("SELECT * FROM devices ORDER BY last_seen DESC"):
        seen = datetime.fromtimestamp(r["last_seen"]).strftime("%Y-%m-%d %H:%M")
        print(f"{r['ip'] or '':<15} {r['mac']}  last {seen}  {r['name'] or ''}  [{r['vendor']}]"
              + (f"  mdns:{r['hostname']}" if r["hostname"] else "") + ("  WATCHED" if r["watch"] else ""))


if __name__ == "__main__":
    main()
