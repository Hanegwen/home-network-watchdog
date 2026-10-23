#!/bin/sh
# Run as root after cloning to /opt/netwatch:  sudo ./deploy/install.sh
# The checks run as SERVICE_USER (default: a system user "netwatch", created if missing), e.g.
#   sudo SERVICE_USER=pi ./deploy/install.sh
# Updating an existing install keeps the user its services already run as, unless SERVICE_USER is given.
set -e
cd /opt/netwatch
current=$(sed -n 's/^User=//p' /etc/systemd/system/netwatch.service 2>/dev/null | head -n 1)
SERVICE_USER="${SERVICE_USER:-${current:-netwatch}}"
echo "Checks will run as: $SERVICE_USER"
case "$SERVICE_USER" in
    *[!A-Za-z0-9._-]*|"") echo "bad SERVICE_USER: $SERVICE_USER" >&2; exit 1 ;;
esac

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    [ "$SERVICE_USER" = netwatch ] || { echo "no such user: $SERVICE_USER" >&2; exit 1; }
    useradd --system --no-create-home --shell /usr/sbin/nologin netwatch
fi

command -v arp-scan >/dev/null || { apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q arp-scan; }

if [ ! -f /etc/netwatch.env ]; then
    install -m 640 -o root -g "$SERVICE_USER" /dev/null /etc/netwatch.env
    EMAIL='^(REPORT_TO|SMTP_USER|SMTP_APP_PASSWORD)='
    if [ -f /etc/comcast-monitor.env ]; then
        # optional: reuse the email settings of isp-outage-monitor when it is installed
        { grep -vE "$EMAIL" config.example.env; grep -E "$EMAIL" /etc/comcast-monitor.env; } > /etc/netwatch.env
    else
        cat config.example.env > /etc/netwatch.env
    fi
    echo "Created /etc/netwatch.env - fill it in (see docs/DEPLOY.md)"
fi
chgrp "$SERVICE_USER" /etc/netwatch.env

# lets `nw run` do the device scan by hand (the units grant raw sockets via AmbientCapabilities)
setcap cap_net_raw+ep "$(command -v arp-scan)"

install -d /var/lib/netwatch
chown -R "$SERVICE_USER:" /var/lib/netwatch  # also after switching SERVICE_USER
sed "s/@SERVICE_USER@/$SERVICE_USER/g" deploy/nw > /usr/local/bin/nw
chmod 755 /usr/local/bin/nw
for f in deploy/*.service deploy/*.timer; do
    sed "s/@SERVICE_USER@/$SERVICE_USER/g" "$f" > "/etc/systemd/system/${f#deploy/}"
done
systemctl daemon-reload
systemctl enable --now netwatch.timer netwatch-daily.timer
systemctl --no-pager list-timers 'netwatch*'
