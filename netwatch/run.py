"""Every 5 minutes (netwatch.timer): port forwards, LAN devices, Tailscale machines, site visitors,
the site being down.

  python -m netwatch.run             normal run (emails alerts)
  python -m netwatch.run --dry-run   print what would be emailed, change nothing
  python -m netwatch.run --daily     also the daily outside scan; on Mondays the weekly summary
"""
import argparse
import json
import os
import shutil
import traceback
from datetime import datetime, timedelta

from . import config, db, devices, exposure, forwards, mail, tailnet, vault, visitors

FAST = (("devices", devices), ("port forwards", forwards), ("tailscale", tailnet), ("visitors", visitors),
        ("site down", vault))


def run_checks(conn, now, checks):
    alerts, notes, errors = [], [], []
    for name, mod in checks:
        try:
            a, n = mod.check(conn, now)
            alerts += a
            notes += n
        except Exception:
            errors.append(f"{name}: {traceback.format_exc(limit=2).strip().splitlines()[-1]}")
    return alerts, notes, errors


def weekly_summary(conn, now):
    since = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    devs = conn.execute("SELECT COUNT(*) n FROM devices WHERE last_seen >= ?",
                        (int((now - timedelta(days=7)).timestamp()),)).fetchone()["n"]
    fw = conn.execute("SELECT key, client, descr FROM forwards WHERE active = 1").fetchall()
    return (f"Weekly home network summary ({since} to {now:%Y-%m-%d})\n\n"
            f"Router UPnP: {db.get(conn, 'upnp', '?')}\n"
            "Open port forwards: " + (", ".join(f"{r['key']}->{r['client']} ({r['descr']})" for r in fw) or "none") +
            f"\nShodan last saw ports: {db.get(conn, 'shodan_ports', '?')}\n"
            f"Devices seen this week: {devs}\n" + (pc_checkin(now) + "\n" if config.PC_REPORT else "") + "\n" +
            visitors.summary(conn, since))


def pc_checkin(now):
    """One line: when the PC's Steam reporter last checked in (the data-usage monitor relies on it); "" if not set up."""
    if not config.PC_REPORT:
        return ""
    try:
        with open(config.PC_REPORT, encoding="utf-8-sig") as f:
            report = json.load(f)
        last, pc = datetime.fromtimestamp(report["generated"]), report.get("pc", "PC")
    except (OSError, ValueError, KeyError):
        return ("PC check-in: NOT CONNECTING - no Steam report from the PC yet. Run pc/install-task.ps1 "
                "(isp-outage-monitor) on the PC.")
    age_h = (now - last).total_seconds() / 3600
    when = f"{last:%a %Y-%m-%d %H:%M}"
    if age_h > config.PC_STALE_HOURS:
        return (f"PC check-in: NOT CONNECTING - {pc} last reported {when} ({age_h / 24:.0f} days ago). Data-usage "
                "alerts can't tell Steam updates apart until it's back: check the PC is on and the scheduled task "
                "\"Comcast monitor - Steam report\" is running.")
    return f"PC check-in: OK - {pc} last reported {when}"


def watching():
    """The setup email's list of what is checked, leaving out the optional checks that aren't set up."""
    items = ["a device opens an internet port on the router (UPnP)",
             "a device it has never seen joins the Wi-Fi/LAN"]
    if shutil.which("tailscale"):
        items.append("a new machine joins Tailscale")
    if os.path.exists(config.CADDY_LOG):
        items.append(f"someone signs in to the {config.SITE_NAME} from a new country/network, or an IP hammers it")
    if config.SITE_URL:
        items.append(f"the {config.SITE_NAME} is down for 5+ minutes, and when it's back")
    items.append("internet scanners (Shodan) newly see an open port on your public IP (checked daily)")
    return "".join(f"  - {i}\n" for i in items)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--daily", action="store_true")
    p.add_argument("--weekly", action="store_true", help="send the weekly summary now")
    args = p.parse_args()

    conn = db.connect()
    now = datetime.now()
    checks = (("outside scan", exposure),) + FAST if args.daily or db.get(conn, "home_ip") is None else FAST
    first_run = db.get(conn, "setup_sent") is None
    alerts, notes, errors = run_checks(conn, now, checks)

    for e in errors:
        print("check failed:", e)
    for t, b in alerts:
        print(f"ALERT {t}\n{b}\n")
    if args.dry_run:
        for n in notes:
            print("note:", n)
        conn.rollback()
        return

    if first_run:
        mail.send("Home network watch is set up",
                  "Home network watch now checks the network every 5 minutes and emails you when:\n" + watching() +
                  "Weekly summary on Mondays.\n\nWhat it sees right now (all treated as normal from here on):\n\n" +
                  "\n\n".join(notes) + ("\n\nChecks that failed: " + "; ".join(errors) if errors else ""))
        db.put(conn, "setup_sent", int(now.timestamp()))
    elif notes:
        print("\n".join(notes))
    mail.send_alerts(alerts)
    if args.weekly or (args.daily and now.weekday() == 0):
        mail.send("Home network weekly summary", weekly_summary(conn, now))
    conn.commit()


if __name__ == "__main__":
    main()
