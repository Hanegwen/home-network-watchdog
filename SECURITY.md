# Security

## Keep your settings private

`/etc/netwatch.env` holds your email App Password. Never commit it, paste it in an issue, or share it
(`.gitignore` ignores `*.env` except `config.example.env`). Alert emails and the database
(`/var/lib/netwatch/netwatch.db`) list your devices, port forwards and visitor IPs; treat them as private too.

## What it does to your router

Nothing. The port-forward check is read-only: it only sends UPnP `GetGenericPortMappingEntry` requests to
list mappings. It never adds, removes or changes a mapping or any router setting, and needs no router password.
The device scan is a normal ARP scan of the local network.

## Reporting a vulnerability

Please report it privately through GitHub: **Security > Report a vulnerability** on this repository
(a private security advisory). Don't open a public issue for it.
