"""Fail if tracked files contain details that shouldn't be in a public repo.

  python tools/check_public.py                 generic checks (CI runs this)
  python tools/check_public.py --staged        only the files staged for commit (the pre-commit hook)

Generic checks: MAC addresses outside the placeholder ranges, public IPv4 addresses that aren't well-known
examples, email addresses, Tailscale *.ts.net names. On the maintainer's machine it also reads a private
denylist (one literal string per line; never committed) from $PUBLIC_DENYLIST or ~/.config/public-denylist.txt.
A line ending in `public-ok` is skipped.
"""
import ipaddress
import os
import re
import subprocess
import sys

MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
PLACEHOLDER_MACS = ("00:11:22:", "02:00:00:", "06:00:00:", "aa:bb:cc:", "da:00:00:", "ee:00:00:")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
OK_IPS = {"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "1.2.3.4", "5.6.7.8"}  # public DNS + examples
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
OK_EMAIL = re.compile(r"noreply|no-reply|@example\.|@users\.noreply\.github\.com")
TAILNET = re.compile(r"\b[\w-]+\.ts\.net\b|\btail[0-9a-f]{6}\b")
SKIP = (".pyc", ".png", ".jpg", ".gif", ".ico", ".db")


def files(staged):
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"] if staged else ["git", "ls-files"]
    return [f for f in subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()
            if not f.endswith(SKIP) and f != "tools/check_public.py"]


def read(path, staged):
    if staged:
        return subprocess.run(["git", "show", f":{path}"], capture_output=True, text=True,
                              encoding="utf-8", errors="replace").stdout
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def denylist():
    path = os.environ.get("PUBLIC_DENYLIST") or os.path.expanduser("~/.config/public-denylist.txt")
    try:
        with open(path, encoding="utf-8") as f:
            return [s.strip() for s in f if s.strip() and not s.startswith("#")]
    except OSError:
        return []


def public_ip(s):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    docs = s.startswith(("192.0.2.", "198.51.100.", "203.0.113."))  # documentation ranges
    return ip.is_global and not ip.is_multicast and s not in OK_IPS and not docs


def problems(text, deny):
    for n, line in enumerate(text.splitlines(), 1):
        if line.rstrip().endswith("public-ok"):
            continue
        low = line.lower()
        for m in MAC.findall(line):
            if not m.lower().startswith(PLACEHOLDER_MACS):
                yield n, f"real-looking MAC address {m}"
        for m in IPV4.findall(line):
            if public_ip(m):
                yield n, f"public IP address {m}"
        for m in EMAIL.findall(line):
            if not OK_EMAIL.search(m):
                yield n, f"email address {m}"
        for m in TAILNET.findall(line):
            yield n, f"Tailscale name {m}"
        for d in deny:
            if d.lower() in low:
                yield n, "private denylist entry"  # don't echo the value itself


def main():
    staged = "--staged" in sys.argv
    deny, found = denylist(), 0
    for path in files(staged):
        for n, why in problems(read(path, staged), deny):
            print(f"{path}:{n}: {why}")
            found += 1
    if found:
        print(f"\n{found} problem(s): this repo is published. Use placeholders (see tools/check_public.py), "
              "or end the line with `public-ok` if it's really fine.")
        sys.exit(1)


if __name__ == "__main__":
    main()
