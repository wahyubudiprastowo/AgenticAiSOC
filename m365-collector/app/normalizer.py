from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone


# Security signals only. Routine mailbox/file access needs correlation or a
# Defender/Purview alert before it is treated as an attack.
OPERATION_PROFILES: dict[str, dict] = {
    "MalwareDetected": {"type": "malware", "severity": "high", "security_signal": True},
    "PhishNotAllowed": {"type": "phishing", "severity": "high", "security_signal": True},
    "DlpRuleMatch": {"type": "data_exfiltration", "severity": "high", "security_signal": True},
    "Copy to Removable Media": {"type": "data_exfiltration", "severity": "high", "security_signal": True},
    "New-InboxRule": {"type": "mailbox_rule_change", "severity": "medium", "security_signal": True},
    "Consent to application": {"type": "oauth_consent", "severity": "medium", "security_signal": True},
    "Add app role assignment to service principal": {"type": "privilege_change", "severity": "medium", "security_signal": True},
    "Add member to role": {"type": "privilege_change", "severity": "medium", "security_signal": True},
    "MemberAdded": {"type": "privilege_change", "severity": "medium", "security_signal": True},
    "AnonymousLinkCreated": {"type": "external_sharing", "severity": "medium", "security_signal": True},
}

DOWNLOAD_OPERATIONS = {"FileDownloaded", "FileSyncDownloadedFull", "FileDownloadedFromBrowser"}
M365_INCIDENT_WINDOW_SECONDS = max(300, int(os.getenv("M365_INCIDENT_WINDOW_SECONDS", "3600")))

# AAD codes caused by MFA/Conditional Access are not bad-password attempts.
EXPECTED_AUTH_INTERRUPTION_CODES = {
    "50074", "50076", "50079", "50097", "50125", "50140", "50158", "53003",
}
CREDENTIAL_FAILURE_CODES = {"50053", "50055", "50056", "50057", "50059", "50105", "50126"}


def _canonical_hash(record: dict) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def _stable_event_id(record: dict, raw_hash: str) -> str:
    record_id = str(record.get("Id") or record.get("IntraSystemId") or "").strip()
    identity = f"{record.get('_content_type', '')}:{record_id}" if record_id else raw_hash
    return f"evt-m365-{hashlib.sha256(identity.encode()).hexdigest()[:24]}"


def _text_values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_text_values(item))
        return result
    if isinstance(value, dict):
        for key in ("EmailAddress", "Address", "Recipient", "Value", "Name"):
            if value.get(key):
                return _text_values(value[key])
        return []
    text = str(value).strip()
    return [text] if text else []


def _incident_identity(record: dict, event_type: str) -> dict:
    """Build a privacy-safe incident key for actionable TIMailData records."""
    if str(record.get("Operation") or "") != "TIMailData" or event_type not in {"phishing", "malware"}:
        return {}
    campaign = str(record.get("CampaignId") or record.get("ThreatClusterId") or "").strip()
    network_message = str(record.get("NetworkMessageId") or "").strip()
    internet_message = str(record.get("InternetMessageId") or "").strip()
    if campaign:
        scope, anchor = "campaign", campaign
    elif network_message:
        scope, anchor = "network_message", network_message
    elif internet_message:
        scope, anchor = "internet_message", internet_message
    else:
        recipients = sorted(set(_text_values(record.get("Recipients")) +
                                _text_values(record.get("RecipientEmailAddress")) +
                                _text_values(record.get("UserId"))))
        scope = "message_fingerprint"
        anchor = "|".join([
            str(record.get("P2Sender") or record.get("P1Sender") or "").strip().lower(),
            ",".join(value.lower() for value in recipients),
            str(record.get("Subject") or "").strip().lower(),
        ])
    timestamp = record.get("MessageTime") or record.get("CreationTime")
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        parsed = datetime.now(timezone.utc)
    bucket = int(parsed.timestamp()) // M365_INCIDENT_WINDOW_SECONDS
    digest = hashlib.sha256(f"{event_type}|{scope}|{anchor}|{bucket}".encode()).hexdigest()
    return {
        "incident_key": f"m365-ti-{digest[:32]}",
        "incident_scope": scope,
        "incident_window_seconds": M365_INCIDENT_WINDOW_SECONDS,
        "incident_window_start": datetime.fromtimestamp(
            bucket * M365_INCIDENT_WINDOW_SECONDS, tz=timezone.utc
        ).isoformat(),
    }


def _profile_for(record: dict) -> dict:
    operation = str(record.get("Operation") or "unknown")
    if operation in OPERATION_PROFILES:
        return dict(OPERATION_PROFILES[operation])
    if operation == "TIMailData":
        threat_text = json.dumps({"verdict": record.get("Verdict"), "threats": record.get("ThreatsAndDetectionTech")},
                                 sort_keys=True).lower()
        if "phish" in threat_text:
            return {"type": "phishing", "severity": "high", "security_signal": True}
        if any(marker in threat_text for marker in ("malware", "trojan", "virus")):
            return {"type": "malware", "severity": "high", "security_signal": True}
    if operation == "UserLoginFailed":
        error_number = str(record.get("ErrorNumber") or "")
        if error_number in EXPECTED_AUTH_INTERRUPTION_CODES:
            return {"type": "auth_interruption", "severity": "low", "security_signal": False}
        return {
            "type": "auth_failure",
            "severity": "medium" if error_number in CREDENTIAL_FAILURE_CODES else "low",
            "security_signal": False,
            "correlate": error_number in CREDENTIAL_FAILURE_CODES,
        }
    if operation in DOWNLOAD_OPERATIONS:
        return {"type": "file_download", "severity": "low", "security_signal": False, "correlate": True}
    return {"type": "generic", "severity": "low", "security_signal": False}


def normalize_m365_record(record: dict) -> dict:
    operation = str(record.get("Operation") or "unknown")
    workload = str(record.get("Workload") or record.get("_content_type") or "m365")
    profile = _profile_for(record)
    raw_hash = _canonical_hash(record)
    creation_time = record.get("CreationTime") or datetime.now(timezone.utc).isoformat()
    record_id = record.get("Id") or record.get("IntraSystemId")
    recipients = _text_values(record.get("Recipients")) + _text_values(record.get("RecipientEmailAddress"))
    affected_user = recipients[0] if recipients else record.get("UserId")
    incident = _incident_identity(record, profile["type"])
    description = f"{workload}: {operation}"
    if operation == "TIMailData" and profile["type"] in {"phishing", "malware"}:
        description = f"{workload}: TIMailData {profile['type']} detection"
    return {
        "id": _stable_event_id(record, raw_hash),
        "source": "m365_audit",
        "type": profile["type"],
        "severity": profile["severity"],
        "src_ip": record.get("SenderIp") or record.get("ClientIP") or record.get("ActorIpAddress"),
        "destination": affected_user,
        "user_name": affected_user,
        "action": record.get("DeliveryAction") or record.get("PolicyAction"),
        "description": description,
        "mitre_technique": [],
        "time": creation_time,
        "raw": record,
        "raw_hash": raw_hash,
        "raw_kv": {
            "operation": operation,
            "workload": workload,
            "record_id": record_id,
            "security_signal": profile.get("security_signal", False),
            "correlate": profile.get("correlate", False),
            "error_number": str(record.get("ErrorNumber") or ""),
            "logon_error": record.get("LogonError"),
            "result_status": record.get("ResultStatus"),
            "object_id": record.get("ObjectId"),
            "verdict": record.get("Verdict"),
            "threats": record.get("ThreatsAndDetectionTech"),
            "detection_type": record.get("DetectionType"),
            "detection_method": record.get("DetectionMethod"),
            "network_message_id": record.get("NetworkMessageId"),
            "internet_message_id": record.get("InternetMessageId"),
            "sender": record.get("P2Sender") or record.get("P1Sender"),
            "sender_ip": record.get("SenderIp"),
            "recipients": recipients,
            "delivery_action": record.get("DeliveryAction"),
            "source_provenance": "m365_management_activity",
            **incident,
        },
    }
