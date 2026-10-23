"""Router port forwards opened through UPnP (how NAS boxes and media apps quietly expose themselves)."""
import re
import urllib.request

from . import config, db

ST = "WANIPConnection:1"


class UpnpOff(Exception):
    pass


def list_forwards():
    """-> [{key, client, int_port, descr}] from the router's UPnP service. Read-only."""
    base = f"http://{config.ROUTER_IP}:{config.UPNP_PORT}"
    try:
        desc = urllib.request.urlopen(base + config.UPNP_DESC_PATH, timeout=5).read().decode()
    except OSError as e:
        raise UpnpOff(str(e))
    m = re.search(r"<serviceType>urn:schemas-upnp-org:service:%s</serviceType>.*?<controlURL>([^<]+)</controlURL>"
                  % ST, desc, re.S)
    if not m:
        raise RuntimeError(f"no {ST} service in {config.UPNP_DESC_PATH} (router not supported?)")  # not "off"
    url = base + m.group(1)
    out = []
    for i in range(500):
        body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:{ST}">'
                f'<NewPortMappingIndex>{i}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>')
        req = urllib.request.Request(url, body.encode(), {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"urn:schemas-upnp-org:service:{ST}#GetGenericPortMappingEntry"'})
        try:
            r = urllib.request.urlopen(req, timeout=5).read().decode()
        except urllib.error.HTTPError:  # 500 = past the last entry
            break
        g = lambda t: (re.search(f"<{t}>([^<]*)</{t}>", r) or [None, ""])[1]
        out.append({"key": f"{g('NewProtocol')}:{g('NewExternalPort')}", "client": g("NewInternalClient"),
                    "int_port": g("NewInternalPort"), "descr": g("NewPortMappingDescription")})
    return out


def allowed(f):
    return any(f["descr"] == a or f["descr"].startswith(a) for a in config.ALLOWED_FORWARDS)


def _service(conn, f):
    """(device, proto, int_port, descr): what the forward reaches. The device is its MAC, so the same
    service coming back after a router reset or on a new DHCP address is recognized."""
    who = conn.execute("SELECT mac FROM devices WHERE ip = ? ORDER BY last_seen DESC", (f["client"],)).fetchone()
    return (who["mac"] if who else "ip:" + f["client"], f["key"].partition(":")[0], f["int_port"], f["descr"])


def _seen_before(conn, svc):
    return conn.execute("SELECT 1 FROM forward_services WHERE device IN (?, '*') AND proto = ? AND int_port = ? "
                        "AND descr = ?", svc).fetchone() is not None


def check(conn, now, forwards=None):
    """-> (alerts, notes). New, unexpected forwards alert; the first run only learns. A forward for a
    service that device had before (router reset, new IP, new outside port) is only logged."""
    try:
        current = list_forwards() if forwards is None else forwards
    except UpnpOff:
        db.put(conn, "upnp", "off")
        return [], ["Router UPnP is off or unreachable - nothing can open ports automatically (good)."]
    db.put(conn, "upnp", "on")
    first_run = db.get(conn, "forwards_baselined") is None
    alerts, ts = [], int(now.timestamp())
    if db.get(conn, "services_seeded") is None:  # forwards seen before services were tracked count as known
        conn.execute("INSERT OR IGNORE INTO forward_services SELECT '*', substr(key, 1, instr(key, ':') - 1), "
                     "int_port, descr, first_seen FROM forwards")
        db.put(conn, "services_seeded", ts)
    active = {r["key"] for r in conn.execute("SELECT key FROM forwards WHERE active = 1")}
    for f in current:
        svc = _service(conn, f)
        known = _seen_before(conn, svc)
        conn.execute("INSERT OR IGNORE INTO forward_services VALUES (?,?,?,?,?)", svc + (ts,))
        if f["key"] in active or allowed(f) or first_run:
            pass
        elif known:
            print(f"known forward back: {f['key']} -> {f['client']}:{f['int_port']} ({f['descr']}), not alerting")
        else:
            who = conn.execute("SELECT vendor, name, hostname FROM devices WHERE ip = ? ORDER BY last_seen DESC",
                               (f["client"],)).fetchone()
            label = who and (who["name"] or who["hostname"] or who["vendor"])
            device = f" ({label})" if label else ""
            alerts.append((
                f"internet port {f['key']} opened to {f['client']}",
                f"A device asked the router to open a door from the internet:\n"
                f"  internet port {f['key']}  ->  {f['client']}:{f['int_port']}{device}\n"
                f"  label: {f['descr'] or '(none)'}\n\n"
                "Anyone on the internet can now reach that service.\n"
                "If you didn't set this up: turn off the device or app's automatic router setup / UPnP option, "
                "remove the mapping in the router's UPnP page, or turn UPnP off in the router."))
        conn.execute("INSERT INTO forwards (key, client, int_port, descr, first_seen, last_seen, active) "
                     "VALUES (?,?,?,?,?,?,1) ON CONFLICT(key) DO UPDATE SET client=excluded.client, "
                     "int_port=excluded.int_port, descr=excluded.descr, last_seen=excluded.last_seen, active=1",
                     (f["key"], f["client"], f["int_port"], f["descr"], ts, ts))
    keys = [f["key"] for f in current]
    conn.execute("UPDATE forwards SET active = 0 WHERE key NOT IN (%s)" % ",".join("?" * len(keys)), keys)
    notes = []
    if first_run:
        db.put(conn, "forwards_baselined", ts)
        listed = "\n".join(f"  {f['key']} -> {f['client']}:{f['int_port']}  {f['descr']}" for f in current)
        notes.append("Router port forwards open right now (UPnP):\n" + (listed or "  none"))
        bad = [f for f in current if not allowed(f)]
        if bad:
            alerts.append(("unexpected internet ports are open right now",
                           "These forwards are open and not on the expected list:\n" +
                           "\n".join(f"  {f['key']} -> {f['client']}:{f['int_port']}  {f['descr']}" for f in bad)))
    return alerts, notes
