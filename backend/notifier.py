import os
import requests
import smtplib
from email.message import EmailMessage
import json

class ScanNotifier:
    def __init__(self):
        # Use simple mock settings or env vars for SMTP
        self.smtp_server = os.getenv("SMTP_SERVER", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", 1025)) # Default to MailHog/local testing
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_pass = os.getenv("SMTP_PASS", "")

    def send_slack_webhook(self, webhook_url: str, scan_id: str, url: str, score: int, grade: str):
        if not webhook_url:
            return False
            
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 VulnScan Pro Report Ready: {url}",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Scan ID:*\n{scan_id}"},
                        {"type": "mrkdwn", "text": f"*Grade:*\n{grade}"},
                        {"type": "mrkdwn", "text": f"*Score:*\n{score}/100"}
                    ]
                }
            ]
        }
        
        try:
            res = requests.post(webhook_url, json=payload, timeout=5)
            return res.status_code == 200
        except Exception as e:
            print(f"Failed to send Slack webhook: {e}")
            return False

    def send_email_report(self, to_email: str, scan_id: str, url: str, score: int, grade: str, summary: str):
        if not to_email:
            return False
            
        msg = EmailMessage()
        msg.set_content(f"""
VulnScan Pro Report Complete for {url}

Scan ID: {scan_id}
Security Grade: {grade}
Security Score: {score}/100

Summary:
{summary}

Log in to the dashboard to view the full PDF report and interactive charts.
        """)

        msg['Subject'] = f'[VulnScan] Report Complete: {url} ({grade})'
        msg['From'] = "noreply@vulnscan.local"
        msg['To'] = to_email

        try:
            # Using basic SMTP without TLS for local testing (Mailhog/Mailtrap)
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.smtp_user:
                    server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"Failed to send Email notification to {to_email}: {e}")
            return False
