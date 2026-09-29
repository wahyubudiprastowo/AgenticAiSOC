from __future__ import annotations
import logging, os, time
from . import db, notifier
logger = logging.getLogger("hermes.reporter")
SOC_DELIVERY_INTERVAL_SECONDS = int(os.getenv("SOC_DELIVERY_INTERVAL_SECONDS", "86400"))
def delivery_loop() -> None:
    if not (notifier.SOC_EMAIL_ENABLED or notifier.SOC_TEAMS_ENABLED): return
    while True:
        time.sleep(SOC_DELIVERY_INTERVAL_SECONDS)
        try:
            findings = db.list_findings(limit=200)
            if not findings: continue
            if notifier.SOC_EMAIL_ENABLED:
                notifier.send_email_report(subject=f"SOC Daily Report ({len(findings)})", html_body=notifier.build_daily_report_html(findings))
            if notifier.SOC_TEAMS_ENABLED:
                critical = [f for f in findings if f.get("severity") in ("high", "critical")]
                notifier.send_teams_notification("SOC Daily Summary", f"{len(findings)} findings, {len(critical)} high/critical.",
                    {"Total": len(findings), "High/Critical": len(critical)})
        except Exception: logger.exception("delivery_loop error")
