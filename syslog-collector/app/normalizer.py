from __future__ import annotations
import hashlib, re, uuid
from datetime import datetime, timezone
from typing import Optional
KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
AUTH_FAIL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in
    [r"failed password", r"authentication failur", r"invalid user", r"login attempt failed", r"userloginfailed"]]
SCAN_PATTERN = re.compile(r"port\s*scan|scan detected|network scan|nmap|port sweep", re.IGNORECASE)
WEB_ATTACK_PATTERN = re.compile(
    r"sql\s*injection|union\s+select|select\s+.*\s+from|'\s*or\s*1\s*=\s*1|xss|cross[\s-]?site|"
    r"path\s+traversal|directory\s+traversal|\.\./\.\.|command\s+injection|remote\s+file\s+inclusion", re.IGNORECASE)
DOS_PATTERN = re.compile(
    r"\bdos\b|ddos|denial[\s-]of[\s-]service|syn[\s_-]?flood|udp[\s_-]?flood|icmp[\s_-]?flood|http[\s_-]?flood", re.IGNORECASE)
SEVERITY_KEYWORDS = {
    "critical": ["ransomware", "critical", "emergency"],
    "high": ["virus", "malware", "attack", "blocked", "exploit", "bruteforce", "brute-force", "brute_force", "sql injection", "ddos", "denial of service"],
    "medium": ["denied", "warning", "suspicious", "anomaly"],
}
def _sha256(payload: str) -> str: return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()
def _parse_kv(payload: str) -> dict:
    out = {}
    for key, value in KV_RE.findall(payload): out[key] = value.strip('"')
    return out
def _infer_severity(payload: str, kv: dict) -> str:
    lowered = payload.lower()
    if kv.get("level") or kv.get("severity"):
        lvl = (kv.get("level") or kv.get("severity") or "").lower()
        if lvl in ("critical", "alert", "emergency"): return "critical"
        if lvl in ("error", "high"): return "high"
        if lvl in ("warning", "medium"): return "medium"
    for sev, keywords in SEVERITY_KEYWORDS.items():
        if any(k in lowered for k in keywords): return sev
    return "low"
def _infer_type(payload: str, kv: dict) -> str:
    lowered = payload.lower()
    subtype = (kv.get("subtype") or "").lower()
    event_type = (kv.get("eventtype") or "").lower()
    action = (kv.get("action") or "").lower()
    if subtype in ("virus", "av") or "virus" in lowered or "malware" in lowered: return "malware"
    if any(p.search(payload) for p in AUTH_FAIL_PATTERNS): return "auth_failure"
    if subtype in ("waf", "webfilter") and WEB_ATTACK_PATTERN.search(payload): return "web_attack"
    if WEB_ATTACK_PATTERN.search(payload): return "web_attack"
    if subtype in ("dos", "anomaly") and DOS_PATTERN.search(payload): return "dos_attack"
    if DOS_PATTERN.search(payload): return "dos_attack"
    if SCAN_PATTERN.search(payload): return "reconnaissance"
    if subtype in ("ips", "anomaly") or event_type in ("ips", "signature"):
        return "network_attack"
    if re.search(r"attack (detected|dropped|blocked)|intrusion|exploit", lowered): return "network_attack"
    if action in ("deny", "denied", "blocked", "dropped", "reset"):
        return "firewall_denied"
    return "generic"
def _infer_source(payload: str, kv: dict, hint: Optional[str] = None) -> str:
    if hint: return hint
    if kv.get("devname") or "fortigate" in payload.lower() or kv.get("type") == "utm": return "fortigate"
    if "sshd" in payload.lower() or "sudo" in payload.lower(): return "linux"
    if "eventid" in payload.lower(): return "windows"
    return "unknown"
def _build_description(kv: dict, raw: str, event_type: str) -> str:
    if kv.get("virus"): return f"Malware/virus detected: {kv['virus']}"
    if event_type == "web_attack": return f"SQL Injection / Web Attack detected: {kv.get('attack') or kv.get('msg') or 'web application attack'}"
    if event_type == "dos_attack": return f"DDoS / Denial of Service attack detected: {kv.get('attack') or kv.get('msg') or 'volumetric flood'}"
    if kv.get("msg"): return kv["msg"]
    return raw[:250]
def normalize_syslog_line(raw: str, source_hint: Optional[str] = None, source_ip: Optional[str] = None) -> dict:
    raw = raw.strip(); kv = _parse_kv(raw)
    if kv.get("date") and kv.get("time"):
        try: ts = datetime.fromisoformat(f"{kv['date']}T{kv['time']}").replace(tzinfo=timezone.utc)
        except ValueError: ts = datetime.now(timezone.utc)
    else: ts = datetime.now(timezone.utc)
    event_type = _infer_type(raw, kv)
    return {"id": f"evt-{uuid.uuid4().hex[:10]}", "source": _infer_source(raw, kv, source_hint), "type": event_type,
        "severity": _infer_severity(raw, kv), "src_ip": kv.get("srcip") or source_ip, "destination": kv.get("dstip"),
        "user_name": kv.get("user"), "action": kv.get("action"), "description": _build_description(kv, raw, event_type),
        "time": ts.isoformat(), "raw": raw, "raw_hash": _sha256(raw), "raw_kv": kv}
