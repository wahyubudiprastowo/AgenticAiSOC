from __future__ import annotations
import logging, os, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from . import correlation, db, detections, filters, ioc_extractor, redis_client, wazuh_client, threat_intel_client
logger = logging.getLogger("soc-core.worker")
WAZUH_POLL_INTERVAL_SECONDS = int(os.getenv("WAZUH_POLL_INTERVAL_SECONDS", "30"))
WAZUH_FIM_POLL_INTERVAL_SECONDS = int(os.getenv("WAZUH_FIM_POLL_INTERVAL_SECONDS", "60"))
WAZUH_VULN_POLL_INTERVAL_SECONDS = int(os.getenv("WAZUH_VULN_POLL_INTERVAL_SECONDS", "900"))
SOC_MAX_IOCS_PER_EVENT = int(os.getenv("SOC_MAX_IOCS_PER_EVENT", "8"))
SOC_IOC_ENRICH_WORKERS = max(1, int(os.getenv("SOC_IOC_ENRICH_WORKERS", "4")))
_IOC_ENRICH_EXECUTOR = ThreadPoolExecutor(max_workers=SOC_IOC_ENRICH_WORKERS, thread_name_prefix="ioc-enrich")
_seen_ids: set[str] = set()
def _dedupe(doc_id: str) -> bool:
    if doc_id in _seen_ids: return False
    _seen_ids.add(doc_id)
    if len(_seen_ids) > 50000: _seen_ids.clear()
    return True
def _maybe_enrich(event: dict):
    ioc_hits = []
    enrichable_types = {"credential_attack", "malware", "ransomware", "network_attack", "reconnaissance",
                        "web_attack", "dos_attack", "phishing", "data_exfiltration", "insider_risk", "security_alert",
                        "vulnerability", "zero_day"}
    should_enrich = (event.get("type") in enrichable_types or event.get("severity") in ("high", "critical")
                     or bool((event.get("raw_kv") or {}).get("security_signal")))
    if should_enrich:
        indicators = ioc_extractor.extract_iocs(event, limit=SOC_MAX_IOCS_PER_EVENT)
        ordered: list[dict | None] = [None] * len(indicators)
        futures = {_IOC_ENRICH_EXECUTOR.submit(threat_intel_client.enrich_ioc,
                   indicator["ioc"], indicator["ioc_type"]): index for index, indicator in enumerate(indicators)}
        for future in as_completed(futures):
            index = futures[future]
            try: ordered[index] = future.result()
            except Exception: logger.exception("IOC enrichment worker failed")
        for indicator, result in zip(indicators, ordered):
            if not result: continue
            ioc_hits.append(result)
            for provider in result.get("providers", []):
                db.upsert_intelligence(ioc=indicator["ioc"], ioc_type=indicator["ioc_type"],
                    provider=provider.get("name", "unknown"), malicious=provider.get("malicious", False),
                    score=provider.get("score", 0.0), raw=provider)
    return ioc_hits, bool(event.get("mitre_technique"))
def process_event(event: dict) -> str:
    existing = db.find_duplicate_event(event)
    if existing: return existing
    event["is_filtered_in"] = False
    event_uuid, inserted = db.insert_event(event)
    if not inserted: return event_uuid
    correlation.apply(event)
    ioc_hits, mitre_matched = _maybe_enrich(event)
    event["ioc_hits"] = ioc_hits
    forward = filters.should_forward_to_ai(event, ioc_hits=ioc_hits, mitre_matched=mitre_matched)
    event["is_filtered_in"] = forward
    db.update_event_decision(event_uuid, event)
    if forward:
        enriched = dict(event); enriched["db_id"] = event_uuid; enriched["ioc_hits"] = ioc_hits
        detection = detections.classify(event)
        if detection:
            enriched["finding_id"] = db.insert_deterministic_finding(event_uuid, event, detection, ioc_hits)
            db.upsert_finding_indicators(enriched["finding_id"], event_uuid, ioc_hits)
        redis_client.push_filtered_event(enriched)
    return event_uuid
def _process_event(event: dict) -> None:
    try: process_event(event)
    except Exception: logger.exception("Failed to process event")
def raw_event_loop() -> None:
    while True:
        try:
            event = redis_client.blocking_pop_raw_event(timeout=5)
            if event is None: continue
            _process_event(event)
        except Exception: logger.exception("raw_event_loop error"); time.sleep(2)
def wazuh_alerts_loop() -> None:
    while True:
        try:
            for alert in wazuh_client.fetch_recent_alerts():
                doc_id = f"alert-{alert.get('_id', '')}"
                if not _dedupe(doc_id): continue
                _process_event(wazuh_client.wazuh_alert_to_normalized(alert))
        except Exception: logger.exception("wazuh_alerts_loop error")
        time.sleep(WAZUH_POLL_INTERVAL_SECONDS)
def wazuh_fim_loop() -> None:
    while True:
        try:
            for fim in wazuh_client.fetch_recent_fim_events():
                doc_id = f"fim-{fim.get('_id', '')}"
                if not _dedupe(doc_id): continue
                _process_event(wazuh_client.wazuh_fim_to_normalized(fim))
        except Exception: logger.exception("wazuh_fim_loop error")
        time.sleep(WAZUH_FIM_POLL_INTERVAL_SECONDS)
def wazuh_vuln_loop() -> None:
    while True:
        try:
            for vuln in wazuh_client.fetch_recent_vulnerabilities():
                doc_id = f"vuln-{vuln.get('_id', '')}"
                if not _dedupe(doc_id): continue
                _process_event(wazuh_client.wazuh_vulnerability_to_normalized(vuln))
        except Exception: logger.exception("wazuh_vuln_loop error")
        time.sleep(WAZUH_VULN_POLL_INTERVAL_SECONDS)
