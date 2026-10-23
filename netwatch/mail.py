import re
import smtplib
from email.message import EmailMessage

from . import config


def send(subject, body):
    if not (config.REPORT_TO and config.SMTP_USER and config.SMTP_APP_PASSWORD):
        raise SystemExit("REPORT_TO / SMTP_USER / SMTP_APP_PASSWORD not configured")
    # subjects can hold text from the router or ip-api; a newline there would make the email fail
    subject = re.sub(r"[\x00-\x1f\x7f]+", " ", subject).strip()
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, config.SMTP_USER, config.REPORT_TO
    msg.set_content(body)
    with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as smtp:
        smtp.login(config.SMTP_USER, config.SMTP_APP_PASSWORD)
        smtp.send_message(msg)


def send_alerts(alerts):
    """alerts: [(title, body)] -> one email."""
    if not alerts:
        return
    subject = ("Home network alert: " + alerts[0][0]) if len(alerts) == 1 else \
        f"Home network alert: {len(alerts)} things to check"
    body = "\n\n".join(f"== {t} ==\n{b}" for t, b in alerts)
    send(subject, body + "\n\n-- home network watch")
