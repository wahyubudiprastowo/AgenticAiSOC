from __future__ import annotations
import json, logging, os, re
from pathlib import Path
logger = logging.getLogger("jev-client.reasoning")
AI_PROVIDER_BASE_URL = os.getenv("AI_PROVIDER_BASE_URL", os.getenv("AI_BASE_URL", "http://jev:20128"))
AI_MODEL = os.getenv("AI_MODEL", "cgpt-web/gpt-5.6-sol-high"); AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "4096")); AI_TIMEOUT = int(os.getenv("AI_TIMEOUT_SECONDS", os.getenv("AI_TIMEOUT", "180")))
JEV_FALLBACK_MODE = os.getenv("JEV_FALLBACK_MODE", "auto")
_PROMPT_PATH = Path(os.getenv("JEV_SYSTEM_PROMPT_PATH", "/app/prompts/jev_system_prompt.txt"))
def _load_system_prompt():
    if _PROMPT_PATH.exists(): return _PROMPT_PATH.read_text(encoding="utf-8")
    return "You are a senior SOC analyst."
SYSTEM_PROMPT = _load_system_prompt()
_MITRE_BY_CATEGORY = {"credential_attack": ["T1110"], "malware": ["T1105", "T1204"], "phishing": ["T1566"],
    "ransomware": ["T1486"], "suspicious_network": ["T1046"], "reconnaissance": ["T1595"], "vulnerability_management": ["T1190"],
    "file_integrity": [], "supply_chain": ["T1195", "T1195.002"], "ddos": ["T1498", "T1499"], "sql_injection": ["T1190"],
    "insider_threat": ["T1078", "T1005"], "data_exfiltration": ["T1041", "T1567"], "apt_activity": ["T1071", "T1105"],
    "zero_day": ["T1190", "T1203"], "cloud_native": ["T1526", "T1580"], "container_kubernetes": ["T1610", "T1613"]}
_CLASSIFICATION_BY_CATEGORY = {"credential_attack": "Credential Attack", "malware": "Malware", "phishing": "Phishing",
    "ransomware": "Ransomware", "suspicious_network": "Suspicious Network Activity", "reconnaissance": "Reconnaissance",
    "vulnerability_management": "Vulnerability", "file_integrity": "File Integrity", "supply_chain": "Supply Chain Compromise",
    "ddos": "Denial of Service (DDoS)", "sql_injection": "SQL Injection", "insider_threat": "Insider Threat",
    "data_exfiltration": "Data Exfiltration", "apt_activity": "APT Activity", "zero_day": "Zero-Day Exploitation",
    "cloud_native": "Cloud-Native Attack", "container_kubernetes": "Container/Kubernetes Threat"}
REQUIRED_KEYS = {"threat_classification", "mitre_technique", "confidence", "investigation_recommendation", "severity", "based_on"}
def _mock_reasoning(evidence: dict) -> dict:
    finding_text = (evidence.get("finding") or "").lower(); all_text = finding_text + " " + " ".join(evidence.get("evidence", [])).lower()
    evidence_ids = [e.split(":")[0].strip() if ":" in e else e for e in evidence.get("evidence", [])]
    category_hint = evidence.get("category_hint")
    category = category_hint if category_hint in _CLASSIFICATION_BY_CATEGORY else None
    if "apt-attribution" in all_text or any(k in all_text for k in ("apt", "lazarus", "fancy bear", "cozy bear")): category = "apt_activity"
    elif category is None and any(k in finding_text for k in ("login", "password", "brute", "credential")): category = "credential_attack"
    elif category is None and "ransom" in finding_text: category = "ransomware"
    elif category is None and ("phish" in finding_text or "inbox rule" in finding_text): category = "phishing"
    elif category is None and ("zero-day" in finding_text or "unpatched" in finding_text): category = "zero_day"
    elif category is None and ("sql injection" in finding_text or "web attack" in finding_text): category = "sql_injection"
    elif category is None and ("ddos" in finding_text or "denial of service" in finding_text): category = "ddos"
    elif category is None and ("node_modules" in finding_text or "site-packages" in finding_text): category = "supply_chain"
    elif category is None and ("dlprulematch" in all_text or "exfiltrat" in finding_text): category = "data_exfiltration"
    elif category is None and any(k in finding_text for k in ("anonymouslinkcreated", "bulk download", "removable media")): category = "insider_threat"
    elif category is None and any(k in finding_text for k in ("malware", "virus", "trojan")): category = "malware"
    elif category is None and "scan" in finding_text: category = "reconnaissance"
    elif category is None and "cve" in finding_text: category = "vulnerability_management"
    elif category is None and "fim:" in finding_text: category = "file_integrity"
    malicious_ioc = "malicious" in all_text and "not flagged" not in all_text
    many_failures = any(re.search(r"\b(\d{2,})\b.*fail", e, re.IGNORECASE) for e in evidence.get("evidence", []))
    confidence = 0.55
    if malicious_ioc: confidence += 0.25
    if many_failures: confidence += 0.15
    if category == "apt_activity": confidence += 0.10
    confidence = min(confidence, 0.97)
    if not evidence.get("evidence"):
        return {"threat_classification": "Unknown", "mitre_technique": [], "confidence": 0.0, "investigation_recommendation": "No evidence provided.", "severity": "low", "based_on": []}
    severity = "critical" if confidence > 0.9 else "high" if confidence > 0.7 else "medium"
    if category in ("data_exfiltration", "supply_chain", "zero_day", "apt_activity"): severity = "critical" if confidence > 0.6 else severity
    return {"threat_classification": _CLASSIFICATION_BY_CATEGORY.get(category, "Unknown"), "mitre_technique": _MITRE_BY_CATEGORY.get(category, []),
            "confidence": round(confidence, 2), "investigation_recommendation": "Investigate account/asset for possible compromise.", "severity": severity, "based_on": evidence_ids}
def _extract_json_from_text(text: str):
    try: return json.loads(text)
    except json.JSONDecodeError: pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try: return json.loads(match.group(0))
        except json.JSONDecodeError: return None
    return None
def _validate_schema(result) -> bool: return isinstance(result, dict) and REQUIRED_KEYS.issubset(result.keys())
def _call_remote_jev(evidence: dict) -> dict:
    import httpx
    headers = {"Content-Type": "application/json"}
    if AI_API_KEY: headers["Authorization"] = f"Bearer {AI_API_KEY}"
    payload = {"model": AI_MODEL, "max_tokens": AI_MAX_TOKENS, "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": json.dumps(evidence)}]}
    base = AI_PROVIDER_BASE_URL.rstrip("/")
    for url in [f"{base}/chat/completions", base]:
        try:
            with httpx.Client(timeout=AI_TIMEOUT) as client:
                resp = client.post(url, json=payload, headers=headers); resp.raise_for_status(); data = resp.json()
            content = data["choices"][0]["message"]["content"] if isinstance(data, dict) and "choices" in data else \
                      data.get("content") if isinstance(data, dict) and "content" in data else \
                      data.get("response") if isinstance(data, dict) and "response" in data else json.dumps(data)
            parsed = _extract_json_from_text(content) if isinstance(content, str) else content
            if parsed and _validate_schema(parsed): return parsed
        except Exception: continue
    raise RuntimeError("All 9router endpoint candidates failed")
def analyze(evidence: dict) -> dict:
    if JEV_FALLBACK_MODE == "force_mock": return _mock_reasoning(evidence)
    if JEV_FALLBACK_MODE == "force_remote": return _call_remote_jev(evidence)
    try: return _call_remote_jev(evidence)
    except Exception: return _mock_reasoning(evidence)
