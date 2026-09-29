from __future__ import annotations
import logging, os, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
import httpx
logger = logging.getLogger("hermes.notifier")
SOC_EMAIL_ENABLED = os.getenv("SOC_EMAIL_ENABLED", "false").lower() == "true"
SOC_REPORT_RECIPIENTS = [r.strip() for r in os.getenv("SOC_REPORT_RECIPIENTS", "").split(",") if r.strip()]
SOC_SMTP_HOST = os.getenv("SOC_SMTP_HOST", "smtp.office365.com"); SOC_SMTP_PORT = int(os.getenv("SOC_SMTP_PORT", "587"))
SOC_SMTP_USER = os.getenv("SOC_SMTP_USER", ""); SOC_SMTP_PASSWORD = os.getenv("SOC_SMTP_PASSWORD", "")
SOC_SMTP_FROM = os.getenv("SOC_SMTP_FROM", SOC_SMTP_USER)
SOC_TEAMS_ENABLED = os.getenv("SOC_TEAMS_ENABLED", "false").lower() == "true"; SOC_TEAMS_WEBHOOK = os.getenv("SOC_TEAMS_WEBHOOK", "")
def send_email_report(subject, html_body) -> bool:
    if not SOC_EMAIL_ENABLED or not SOC_REPORT_RECIPIENTS: return False
    msg = MIMEMultipart("alternative"); msg["Subject"] = subject; msg["From"] = SOC_SMTP_FROM; msg["To"] = ", ".join(SOC_REPORT_RECIPIENTS)
    msg.attach(MIMEText(html_body, "html"))
    try:
        with smtplib.SMTP(SOC_SMTP_HOST, SOC_SMTP_PORT, timeout=20) as server:
            server.starttls(); server.login(SOC_SMTP_USER, SOC_SMTP_PASSWORD); server.sendmail(SOC_SMTP_FROM, SOC_REPORT_RECIPIENTS, msg.as_string())
        return True
    except Exception: return False
def send_teams_notification(title, text, facts: Optional[dict] = None) -> bool:
    if not SOC_TEAMS_ENABLED or not SOC_TEAMS_WEBHOOK: return False
    card = {"@type": "MessageCard", "@context": "http://schema.org/extensions", "summary": title, "themeColor": "D93025",
            "title": title, "text": text, "sections": [{"facts": [{"name": k, "value": str(v)} for k, v in (facts or {}).items()]}]}
    try:
        with httpx.Client(timeout=15) as client: client.post(SOC_TEAMS_WEBHOOK, json=card).raise_for_status()
        return True
    except Exception: return False
def build_daily_report_html(findings: list[dict]) -> str:
    rows = "".join(f"<tr><td>{f.get('threat_classification','-')}</td><td>{f.get('severity','-')}</td><td>{f.get('confidence','-')}</td><td>{f.get('recommendation','-')}</td></tr>" for f in findings)
    return f"<html><body><h2>SOC Daily Report</h2><p>{len(findings)} findings.</p><table border=1>{rows}</table></body></html>"
