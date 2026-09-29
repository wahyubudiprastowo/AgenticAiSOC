from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.IGNORECASE)

_IP_KEYS = {"src_ip", "source_ip", "srcip", "dst_ip", "destination_ip", "dstip", "client_ip", "clientip", "ip_address", "ipaddress"}
_URL_KEYS = {"url", "uri", "link", "request_url", "requesturl", "malicious_url"}
_DOMAIN_KEYS = {"domain", "fqdn", "hostname", "host", "sender_domain", "recipient_domain"}
_HASH_KEYS = {"hash", "file_hash", "filehash", "md5", "sha1", "sha256"}
_CVE_KEYS = {"cve", "cve_id", "vulnerability_id", "vulnerabilityid"}


def _normal_ip(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value.strip(" [](){}<>,;\"'"))
        return str(address) if address.is_global else None
    except ValueError:
        return None


def _normal_url(value: str) -> str | None:
    candidate = value.strip().rstrip(".,;:!?)\"]}'")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def _normal_domain(value: str) -> str | None:
    candidate = value.strip().strip(".[](){}<>,;:\"'").lower()
    if _normal_ip(candidate) or not _DOMAIN_RE.fullmatch(candidate):
        return None
    return candidate


def _normal_hash(value: str) -> str | None:
    candidate = value.strip().lower()
    return candidate if _HASH_RE.fullmatch(candidate) else None


def extract_iocs(event: dict, limit: int = 8) -> list[dict[str, str]]:
    """Extract bounded, externally enrichable indicators from normalized evidence.

    Private/reserved IP addresses and the platform's own ``raw_hash`` are not sent
    to external providers. The returned order is stable for reproducible findings.
    """
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc_type: str, value: str | None) -> None:
        if value is None or len(found) >= max(1, limit):
            return
        key = (ioc_type, value)
        if key not in seen:
            seen.add(key); found.append({"ioc": value, "ioc_type": ioc_type})

    def scan_text(value: str, key: str = "") -> None:
        for match in _CVE_RE.findall(value): add("cve", match.upper())
        for match in _URL_RE.findall(value):
            url = _normal_url(match); add("url", url)
            if url:
                try: add("domain", _normal_domain(urlsplit(url).hostname or ""))
                except ValueError: pass
        for match in _IP_RE.findall(value): add("ip", _normal_ip(match))
        if key in _IP_KEYS: add("ip", _normal_ip(value))
        elif key in _URL_KEYS:
            url = _normal_url(value); add("url", url)
            if url:
                try: add("domain", _normal_domain(urlsplit(url).hostname or ""))
                except ValueError: pass
        elif key in _DOMAIN_KEYS: add("domain", _normal_domain(value))
        elif key in _HASH_KEYS: add("hash", _normal_hash(value))
        elif key in _CVE_KEYS:
            for match in _CVE_RE.findall(value): add("cve", match.upper())

    def walk(value, key: str = "") -> None:
        if len(found) >= max(1, limit): return
        if isinstance(value, dict):
            for nested_key, nested in value.items():
                if str(nested_key).lower() == "raw_hash":
                    continue
                walk(nested, str(nested_key).lower())
        elif isinstance(value, (list, tuple, set)):
            for nested in value: walk(nested, key)
        elif value is not None:
            scan_text(str(value), key)

    scan_text(str(event.get("src_ip") or ""), "src_ip")
    scan_text(str(event.get("destination") or ""), "destination_ip")
    scan_text(str(event.get("description") or ""))
    walk(event.get("raw_kv") or {})
    walk(event.get("raw") or {})
    return found
