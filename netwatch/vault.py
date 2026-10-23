"""The self-hosted site (SITE_URL, e.g. its backend on this machine) being down. Skipped when SITE_URL is unset.

Alerts once it has been down for 5+ minutes - two runs in a row, so a deploy's
restart never alerts - and again when it's back. Optional MAINT_DIR: while
MAINT_DIR/active.json exists the site is down on purpose (a maintenance page),
so it stays quiet; MAINT_DIR/status.json {"nas": {"ok": false, "since": ...}}
adds "its storage is down too" to the alert.
"""
import json
import os
import urllib.request
from datetime import datetime

from . import config, db

ALERT_AFTER = 5 * 60


def backend_ok():
    try:
        with urllib.request.urlopen(config.SITE_URL, timeout=10) as r:
            return r.status == 200
    except Exception:
        return False


def _maint(name):
    if not config.MAINT_DIR:
        return None
    try:
        with open(os.path.join(config.MAINT_DIR, name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _why():
    s = _maint("status.json") or {}
    if s.get("nas") and not s["nas"].get("ok"):
        return f"Its storage (NAS) isn't answering either, since {s['nas'].get('since', '?')}."
    return "Check the log of your site's service, e.g. journalctl -u <service> -n 100"


def check(conn, now, up=None, planned=None):
    if up is None and not config.SITE_URL:
        return [], []
    up = backend_ok() if up is None else up
    planned = (_maint("active.json") is not None) if planned is None else planned
    ts = int(now.timestamp())
    down_since = db.get(conn, "vault_down_since")
    alerted = db.get(conn, "vault_alerted")
    name = config.SITE_NAME
    if up:
        conn.execute("DELETE FROM kv WHERE key IN ('vault_down_since', 'vault_alerted')")
        if alerted:
            mins = (ts - int(down_since)) // 60 if down_since else "?"
            return [(f"{name} is back up", f"The {name} answers again (it was down about {mins} minutes).")], []
        return [], []
    if planned:
        return [], []
    if not down_since:
        db.put(conn, "vault_down_since", ts)
        return [], []
    if not alerted and ts - int(down_since) >= ALERT_AFTER:
        db.put(conn, "vault_alerted", ts)
        since = datetime.fromtimestamp(int(down_since)).strftime("%H:%M")
        return [(f"{name} is down",
                 f"The {name} ({config.SITE_URL}) hasn't answered since {since}.\n{_why()}")], []
    return [], []
