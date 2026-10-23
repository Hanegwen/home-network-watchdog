import os
import sqlite3

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS forwards (          -- router UPnP port forwards
    key TEXT PRIMARY KEY,                      -- TCP:8000
    client TEXT, int_port TEXT, descr TEXT,
    first_seen INTEGER, last_seen INTEGER,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS forward_services ( -- what a forward reaches, so a reset/new IP isn't "new"
    device TEXT,                               -- MAC of the LAN client ('*' = learned before MACs were kept)
    proto TEXT, int_port TEXT, descr TEXT,
    first_seen INTEGER,
    PRIMARY KEY (device, proto, int_port, descr)
);

CREATE TABLE IF NOT EXISTS devices (           -- everything ever seen on the LAN
    mac TEXT PRIMARY KEY,
    ip TEXT, vendor TEXT, name TEXT,
    first_seen INTEGER, last_seen INTEGER,
    hostname TEXT,                             -- the name it announces over mDNS (Bonjour), if any
    watch INTEGER NOT NULL DEFAULT 0           -- 1 = email every time it comes back (nw devices --watch)
);

CREATE TABLE IF NOT EXISTS peers (             -- Tailscale machines
    id TEXT PRIMARY KEY, name TEXT, os TEXT, first_seen INTEGER
);

CREATE TABLE IF NOT EXISTS ipinfo (            -- GeoIP cache
    ip TEXT PRIMARY KEY,
    country TEXT, cc TEXT, region TEXT, city TEXT, org TEXT, asn TEXT, ts INTEGER
);

CREATE TABLE IF NOT EXISTS networks (          -- country|ASN pairs seen signed in to the site
    key TEXT PRIMARY KEY, first_seen INTEGER, name TEXT
);

CREATE TABLE IF NOT EXISTS visits (            -- per day, per outside IP
    day TEXT, ip TEXT,
    requests INTEGER NOT NULL DEFAULT 0,
    signed_in INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, ip)
);

CREATE TABLE IF NOT EXISTS sent (key TEXT PRIMARY KEY, ts INTEGER);  -- one-off alerts already emailed
"""


def connect(path=None):
    path = path or config.DB_PATH
    if path != ":memory:":
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    if "name" not in {r["name"] for r in conn.execute("PRAGMA table_info(networks)")}:  # DBs made before names
        conn.execute("ALTER TABLE networks ADD COLUMN name TEXT")
    if "hostname" not in {r["name"] for r in conn.execute("PRAGMA table_info(devices)")}:  # DBs made before mDNS
        conn.execute("ALTER TABLE devices ADD COLUMN hostname TEXT")
    if "watch" not in {r["name"] for r in conn.execute("PRAGMA table_info(devices)")}:
        conn.execute("ALTER TABLE devices ADD COLUMN watch INTEGER NOT NULL DEFAULT 0")
    return conn


def get(conn, key, default=None):
    row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def put(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", (key, str(value)))


def once(conn, key, ts):
    """True the first time a key is seen (then remembers it)."""
    cur = conn.execute("INSERT OR IGNORE INTO sent (key, ts) VALUES (?, ?)", (key, int(ts)))
    return cur.rowcount == 1
