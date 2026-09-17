"""
notifications.py - Notification and Webhook Alert Engine for CertValid.
Provides non-blocking, background thread dispatch for Webhook POST HTTP alerts
and SMTP Email notifications on certificate issuance, revocation, and security events.
"""

import json
import logging
import smtplib
import threading
import urllib.request
import urllib.error
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

import db

logger = logging.getLogger('certvalid.notifications')


def _dispatch_webhook(webhook_url, event_type, payload):
    """Internal helper to execute outgoing POST Webhook request in background thread."""
    try:
        data = {
            'event': event_type,
            'timestamp': datetime.now().isoformat(),
            'payload': payload
        }
        json_bytes = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(
            webhook_url,
            data=json_bytes,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'CertValid-Webhook-Engine/1.0'
            },
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info(f"Webhook {event_type} delivered to {webhook_url}: HTTP {resp.status}")
    except Exception as e:
        logger.error(f"Failed to deliver Webhook {event_type} to {webhook_url}: {e}")


def _dispatch_email(smtp_host, smtp_port, smtp_user, smtp_pass, sender_email, target_email, subject, body_html):
    """Internal helper to send SMTP email alert in background thread."""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = sender_email or smtp_user or 'alerts@certvalid.io'
        msg['To']      = target_email

        html_part = MIMEText(body_html, 'html')
        msg.attach(html_part)

        port = int(smtp_port) if smtp_port else 587
        if port == 465:
            server = smtplib.SMTP_SSL(smtp_host, port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_host, port, timeout=10)
            server.starttls()

        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)

        server.sendmail(msg['From'], [target_email], msg.as_string())
        server.quit()
        logger.info(f"Email alert '{subject}' sent to {target_email}")
    except Exception as e:
        logger.error(f"Failed to send email alert '{subject}' to {target_email}: {e}")


def trigger_event(event_type, details):
    """
    Public entry point to trigger Webhook & Email alerts asynchronously.
    """
    # 1. Dispatch Webhook if enabled
    webhook_enabled = db.get_setting('webhook_enabled', 'false').lower() == 'true'
    webhook_url     = db.get_setting('webhook_url', '').strip()

    if webhook_enabled and webhook_url:
        t = threading.Thread(
            target=_dispatch_webhook,
            args=(webhook_url, event_type, details),
            daemon=True
        )
        t.start()

    # 2. Dispatch Email Alert if enabled
    email_enabled = db.get_setting('email_alerts_enabled', 'false').lower() == 'true'
    smtp_host     = db.get_setting('smtp_host', '').strip()
    target_email  = db.get_setting('alert_email', '').strip()

    if email_enabled and smtp_host and target_email:
        smtp_port    = db.get_setting('smtp_port', '587')
        smtp_user    = db.get_setting('smtp_user', '')
        smtp_pass    = db.get_setting('smtp_pass', '')
        sender_email = db.get_setting('sender_email', 'alerts@certvalid.io')

        subject = f"🛡️ CertValid Alert: {event_type.replace('_', ' ').title()}"
        body_html = f"""
        <html>
          <body style="font-family:sans-serif; background:#0f0f1d; color:#e2e8f0; padding:20px;">
            <div style="max-width:560px; margin:0 auto; background:#18182a; border:1px solid #d4af37; border-radius:8px; padding:24px;">
              <h2 style="color:#d4af37; margin-top:0;">🛡️ CertValid Notification</h2>
              <p><strong>Event:</strong> {event_type}</p>
              <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
              <hr style="border:none; border-top:1px solid #334155; margin:16px 0;">
              <h3>Event Details:</h3>
              <pre style="background:#0f172a; padding:12px; border-radius:6px; font-size:13px; color:#38bdf8; overflow-x:auto;">
{json.dumps(details, indent=2)}
              </pre>
              <p style="font-size:12px; color:#94a3b8; margin-top:20px;">This is an automated notification sent by your CertValid Enterprise System.</p>
            </div>
          </body>
        </html>
        """

        t_email = threading.Thread(
            target=_dispatch_email,
            args=(smtp_host, smtp_port, smtp_user, smtp_pass, sender_email, target_email, subject, body_html),
            daemon=True
        )
        t_email.start()
