import json
import unittest
from datetime import datetime, timedelta

from netwatch import config, db, devices, exposure, forwards, geo, tailnet, visitors

NOW = datetime(2026, 1, 5, 9, 0)
LATER = datetime(2026, 1, 5, 9, 5)


def fwd(port, client="10.0.0.104", descr="web-ui"):
    return {"key": f"TCP:{port}", "client": client, "int_port": str(port), "descr": descr}


class Forwards(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")

    def test_first_run_learns_and_flags_unexpected_open_ports(self):
        alerts, notes = forwards.check(self.conn, NOW, [fwd(41641, "10.0.0.110", "tailscale-portmap")])
        self.assertEqual(alerts, [])
        self.assertIn("tailscale-portmap", notes[0])
        conn = db.connect(":memory:")
        alerts, _ = forwards.check(conn, NOW, [fwd(3389, descr="remote-desktop")])
        self.assertEqual(len(alerts), 1)

    def test_new_forward_alerts_once(self):
        forwards.check(self.conn, NOW, [])
        alerts, _ = forwards.check(self.conn, LATER, [fwd(8000)])
        self.assertIn("TCP:8000", alerts[0][0])
        self.assertEqual(forwards.check(self.conn, LATER, [fwd(8000)])[0], [])

    def test_same_service_back_after_router_reset_on_new_ip_is_quiet(self):
        # a router reset clears the forwards; the server gets a new IP and its media app re-opens its forward
        server = "02:00:00:00:00:01"
        devices.check(self.conn, NOW, {server: "10.0.0.104"}, {}, {})
        media = {"key": "TCP:40000", "client": "10.0.0.104", "int_port": "32400", "descr": "media-server"}
        forwards.check(self.conn, NOW, [])
        self.assertEqual(len(forwards.check(self.conn, NOW, [media])[0]), 1)  # first time: alert
        forwards.check(self.conn, LATER, [])                                  # router reset clears it
        devices.check(self.conn, LATER, {server: "10.0.0.150"}, {}, {})
        back = dict(media, client="10.0.0.150", key="TCP:31000")
        self.assertEqual(forwards.check(self.conn, LATER, [back])[0], [])
        # a different service on that server, or the media app on another device, still alerts
        self.assertEqual(len(forwards.check(self.conn, LATER, [fwd(8000, "10.0.0.150")])[0]), 1)
        devices.check(self.conn, LATER, {server: "10.0.0.150", "02:00:00:00:00:02": "10.0.0.103"}, {}, {})
        other = dict(media, client="10.0.0.103", key="TCP:32400")
        self.assertEqual(len(forwards.check(self.conn, LATER, [other])[0]), 1)

    def test_forwards_from_before_service_tracking_count_as_known(self):
        self.conn.execute("INSERT INTO forwards VALUES ('TCP:40000', '10.0.0.104', '32400', 'media-server',"
                          " 1, 1, 0)")
        db.put(self.conn, "forwards_baselined", 1)
        media = {"key": "TCP:40000", "client": "10.0.0.150", "int_port": "32400", "descr": "media-server"}
        self.assertEqual(forwards.check(self.conn, LATER, [media])[0], [])

    def test_allowed_forward_is_quiet(self):
        forwards.check(self.conn, NOW, [])
        self.assertEqual(forwards.check(self.conn, LATER, [fwd(41641, descr="tailscale-portmap")])[0], [])


class Devices(unittest.TestCase):
    def test_baseline_then_new_device(self):
        conn = db.connect(":memory:")
        alerts, notes = devices.check(conn, NOW, {"00:11:22:33:44:01": "10.0.0.104"})
        self.assertEqual(alerts, [])
        self.assertIn("10.0.0.104", notes[0])
        self.assertEqual(devices.check(conn, LATER, {"00:11:22:33:44:01": "10.0.0.109"}), ([], []))
        # first 24 h: devices waking up are learned quietly
        self.assertEqual(devices.check(conn, LATER, {"00:11:22:33:44:02": "10.0.0.103"}), ([], []))
        alerts, _ = devices.check(conn, NOW + timedelta(days=1, minutes=1), {"00:11:22:33:44:01": "10.0.0.109", "ee:00:00:00:00:02": "10.0.0.140"}, {})
        self.assertIn("10.0.0.140", alerts[0][0])
        self.assertIn("private Wi-Fi address", alerts[0][1])

    def test_own_tailscale_machine_with_new_private_address_is_named_not_alerted(self):
        conn = db.connect(":memory:")
        devices.check(conn, NOW, {"00:11:22:33:44:01": "10.0.0.104"})
        day2 = NOW + timedelta(days=1, minutes=1)
        hosts = {"10.0.0.136": "laptop-1"}
        found = {"da:00:00:00:00:01": "10.0.0.136", "ee:00:00:00:00:02": "10.0.0.140"}
        alerts, _ = devices.check(conn, day2, found, hosts)
        self.assertNotIn("10.0.0.136", alerts[0][1])
        self.assertIn("10.0.0.140", alerts[0][1])
        name = conn.execute("SELECT name FROM devices WHERE mac = 'da:00:00:00:00:01'").fetchone()["name"]
        self.assertEqual(name, "laptop-1")
        # a fixed (non-private) MAC on that IP is not trusted just because of the IP
        alerts, _ = devices.check(conn, day2, {"00:11:22:33:44:02": "10.0.0.136"}, hosts)
        self.assertIn("10.0.0.136", alerts[0][1])
        # Tailscale down: still alerts
        def broken():
            raise RuntimeError("tailscaled not running")
        alerts, _ = devices.check(conn, day2, {"06:00:00:00:00:03": "10.0.0.136"}, broken)
        self.assertIn("10.0.0.136", alerts[0][1])

    def test_new_mac_announcing_a_known_mdns_name_is_the_same_device(self):
        conn = db.connect(":memory:")
        devices.check(conn, NOW, {"02:00:00:00:01:01": "10.0.0.122", "02:00:00:00:01:02": "10.0.0.120"}, {},
                      {"10.0.0.122": "iPhone-12", "10.0.0.120": "Android"})
        conn.execute("UPDATE devices SET name = 'Guest iPhone' WHERE mac = '02:00:00:00:01:01'")
        day2 = NOW + timedelta(days=1, minutes=1)
        found = {"06:00:00:00:01:03": "10.0.0.130", "06:00:00:00:01:04": "10.0.0.131",
                 "02:00:00:00:01:05": "10.0.0.132"}
        names = {"10.0.0.130": "iPhone-12", "10.0.0.131": "Android", "10.0.0.132": "LivingRoomTV"}
        alerts, _ = devices.check(conn, day2, found, {}, names)
        self.assertNotIn("10.0.0.130", alerts[0][1])          # known name: recognized
        self.assertIn("10.0.0.131", alerts[0][1])             # "Android" proves nothing
        self.assertIn('announces itself as "LivingRoomTV"', alerts[0][1])
        name = conn.execute("SELECT name FROM devices WHERE mac = '06:00:00:00:01:03'").fetchone()["name"]
        self.assertEqual(name, "Guest iPhone")

    def test_watched_device_alerts_each_time_it_comes_back(self):
        conn = db.connect(":memory:")
        mystery = "02:00:00:00:01:05"
        devices.check(conn, NOW, {mystery: "10.0.0.122"}, {}, {})
        conn.execute("UPDATE devices SET watch = 1 WHERE mac = ?", (mystery,))
        self.assertEqual(devices.check(conn, LATER, {mystery: "10.0.0.122"}, {}, {}), ([], []))  # still here
        gone = NOW + timedelta(hours=17)
        self.assertEqual(devices.check(conn, gone, {}, {}, {}), ([], []))
        alerts, _ = devices.check(conn, gone + timedelta(minutes=5), {mystery: "10.0.0.140"}, {},
                                  {"10.0.0.140": "LivingRoomTV"})
        self.assertIn("10.0.0.140", alerts[0][0])
        self.assertIn("LivingRoomTV", alerts[0][1])
        self.assertIn("17 hours", alerts[0][1])
        later = gone + timedelta(minutes=10)
        self.assertEqual(devices.check(conn, later, {mystery: "10.0.0.140"}, {}, {}), ([], []))  # once per visit

    def test_lan_ip_from_tailscale_peer(self):
        self.assertEqual(tailnet._lan_ip({"CurAddr": "10.0.0.104:58933"}), "10.0.0.104")
        self.assertIsNone(tailnet._lan_ip({"CurAddr": "1.2.3.4:41641"}))
        self.assertIsNone(tailnet._lan_ip({"CurAddr": ""}))


class Tailnet(unittest.TestCase):
    def test_baseline_then_new_peer(self):
        conn = db.connect(":memory:")
        self.assertEqual(tailnet.check(conn, NOW, {"n1": ("home-server", "linux")})[0], [])
        alerts, _ = tailnet.check(conn, LATER, {"n1": ("home-server", "linux"), "n2": ("evil-box", "windows")})
        self.assertIn("evil-box", alerts[0][1])


def logline(ip, signed_in=False, status=200, uri="/api/media", funnel=True, xff=None):
    h = {"X-Forwarded-For": xff or [ip]}
    if funnel:
        h["Tailscale-Funnel-Request"] = ["?1"]
    if signed_in:
        h["Authorization"] = ["REDACTED"]
    return json.dumps({"ts": 1, "status": status, "request": {"remote_ip": "127.0.0.1", "uri": uri, "headers": h}})


GEO = {"8.8.4.4": ("US", "AS15169", "Google"), "1.2.3.4": ("CN", "AS4134", "Chinanet"),
       "5.6.7.8": ("US", "AS64500", "Example ISP")}


def fake_fetch(ips):
    return [{"status": "success", "query": ip, "country": GEO[ip][0], "countryCode": GEO[ip][0],
             "city": "", "regionName": "", "org": GEO[ip][2], "as": GEO[ip][1] + " x"} for ip in ips]


class Visitors(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        db.put(self.conn, "home_ip", "5.6.7.8")

    def check(self, lines, now=NOW):
        return visitors.check(self.conn, now, lines, fetch=fake_fetch)[0]

    def test_signed_in_from_new_network_alerts_once(self):
        self.assertEqual(len(self.check([logline("1.2.3.4", signed_in=True)])), 1)
        self.assertEqual(self.check([logline("1.2.3.4", signed_in=True)], LATER), [])

    def test_anonymous_bots_home_ip_and_failed_requests_are_quiet(self):
        lines = [logline("1.2.3.4"), logline("5.6.7.8", signed_in=True),
                 logline("8.8.4.4", signed_in=True, status=401), logline("8.8.4.4", signed_in=True, funnel=False)]
        self.assertEqual(self.check(lines), [])
        self.assertIn("Anonymous visitors / bots (2 IPs)", visitors.summary(self.conn, "2026-01-01"))

    def test_named_network_shows_in_summary(self):
        self.check([logline("1.2.3.4", signed_in=True)])
        self.conn.execute("UPDATE networks SET name = 'Family laptop' WHERE key = 'CN|AS4134'")
        self.assertIn("[Family laptop]", visitors.summary(self.conn, "2026-01-01"))

    def test_token_in_url_counts_as_signed_in(self):
        self.assertEqual(len(self.check([logline("1.2.3.4", uri="/api/media/1/thumbnail?token=REDACTED")])), 1)

    def test_spoofed_forwarded_for_uses_rightmost_entry(self):
        # a client can send its own X-Forwarded-For (here: our home IP); only the last entry is from the proxy
        for xff in (["5.6.7.8, 1.2.3.4"], ["5.6.7.8", "1.2.3.4"]):
            self.assertEqual(visitors.parse(logline("", xff=xff))[1], "1.2.3.4")
        self.assertEqual(len(self.check([logline("", signed_in=True, xff=["5.6.7.8, 1.2.3.4"])])), 1)

    def test_geo_lookup_off_sends_nothing_and_counts_each_ip(self):
        self.addCleanup(setattr, config, "GEO_LOOKUP", config.GEO_LOOKUP)
        config.GEO_LOOKUP = False
        self.assertEqual(geo.lookup(self.conn, ["1.2.3.4"])["1.2.3.4"]["country"], "?")
        alerts, _ = visitors.check(self.conn, NOW, [logline("1.2.3.4", signed_in=True)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(visitors.check(self.conn, LATER, [logline("8.8.4.4", signed_in=True)])[0][0][0],
                         f"{config.SITE_NAME} used from a new place: ?")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) n FROM ipinfo").fetchone()["n"], 0)

    def test_hammering(self):
        alerts = self.check([logline("1.2.3.4")] * 700)
        self.assertEqual(len(alerts), 1)
        self.assertIn("hammering", alerts[0][0])
        self.assertEqual(self.check([logline("1.2.3.4")] * 700, LATER), [])  # once per day


class Exposure(unittest.TestCase):
    def test_baseline_then_only_newly_listed_ports(self):
        conn = db.connect(":memory:")
        alerts, notes = exposure.check(conn, NOW, "5.6.7.8", {"ports": [22, 443]})
        self.assertEqual(alerts, [])
        self.assertIn("443", notes[0])
        self.assertEqual(exposure.check(conn, LATER, "5.6.7.8", {"ports": []})[0], [])
        alerts, _ = exposure.check(conn, LATER, "5.6.7.8", {"ports": [8000]})
        self.assertIn("8000", alerts[0][0])


class Vault(unittest.TestCase):
    def test_alerts_after_five_minutes_once_then_back(self):
        from netwatch import vault
        conn = db.connect(":memory:")
        self.assertEqual(vault.check(conn, NOW, up=False, planned=False), ([], []))  # a restart blip
        self.assertEqual(vault.check(conn, NOW + timedelta(minutes=4), up=False, planned=False), ([], []))
        alerts, _ = vault.check(conn, NOW + timedelta(minutes=5), up=False, planned=False)
        self.assertEqual(alerts[0][0], f"{config.SITE_NAME} is down")
        self.assertIn("09:00", alerts[0][1])
        self.assertEqual(vault.check(conn, NOW + timedelta(minutes=10), up=False, planned=False), ([], []))
        alerts, _ = vault.check(conn, NOW + timedelta(minutes=12), up=True, planned=False)
        self.assertIn("about 12 minutes", alerts[0][1])
        self.assertEqual(vault.check(conn, NOW + timedelta(minutes=17), up=True, planned=False), ([], []))

    def test_short_blip_and_planned_maintenance_are_quiet(self):
        from netwatch import vault
        conn = db.connect(":memory:")
        vault.check(conn, NOW, up=False, planned=False)
        self.assertEqual(vault.check(conn, LATER, up=True, planned=False), ([], []))
        for m in (0, 10, 60):
            self.assertEqual(vault.check(conn, NOW + timedelta(minutes=m), up=False, planned=True), ([], []))


    def test_skipped_without_site_url(self):
        from netwatch import vault
        self.addCleanup(setattr, config, "SITE_URL", config.SITE_URL)
        config.SITE_URL = None
        self.assertEqual(vault.check(db.connect(":memory:"), NOW), ([], []))


class PcCheckin(unittest.TestCase):
    def test_ok_stale_and_missing(self):
        import os
        import tempfile
        from netwatch import config, run
        with tempfile.TemporaryDirectory() as d:
            self.addCleanup(setattr, config, "PC_REPORT", config.PC_REPORT)
            config.PC_REPORT = ""
            self.assertEqual(run.pc_checkin(NOW), "")  # not set up: no line at all
            config.PC_REPORT, config.PC_STALE_HOURS = os.path.join(d, "steam.json"), 48
            self.assertIn("no Steam report", run.pc_checkin(NOW))
            with open(config.PC_REPORT, "w") as f:
                json.dump({"generated": int(NOW.timestamp()) - 3600, "pc": "GAMING-PC"}, f)
            self.assertTrue(run.pc_checkin(NOW).startswith("PC check-in: OK - GAMING-PC"))
            self.assertIn("NOT CONNECTING", run.pc_checkin(NOW + timedelta(days=3)))


if __name__ == "__main__":
    unittest.main()


class Hardening(unittest.TestCase):
    def test_odd_network_key_is_not_put_in_a_shell_command(self):
        self.assertIn("--name 'US|AS64500'", visitors._name_hint("US|AS64500"))
        self.assertIn("--name '??|5.6.7.8'", visitors._name_hint("??|5.6.7.8"))
        self.assertNotIn("$(", visitors._name_hint("US|AS1'; $(reboot) #"))

    def test_control_characters_are_removed_from_subjects(self):
        from unittest import mock
        from netwatch import config, mail
        self.addCleanup(setattr, config, "REPORT_TO", config.REPORT_TO)
        config.REPORT_TO, config.SMTP_USER, config.SMTP_APP_PASSWORD = "a@example.com", "b@example.com", "x"
        with mock.patch("smtplib.SMTP_SSL") as smtp:
            mail.send("router said\r\nBcc: evil@example.com", "body")
        msg = smtp.return_value.__enter__.return_value.send_message.call_args[0][0]
        self.assertEqual(msg["Subject"], "router said Bcc: evil@example.com")
