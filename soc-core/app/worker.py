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
SOC_RAW_EVENT_WORKERS = max(1, int(os.getenv("SOC_RAW_EVENT_WORKERS", "4")))
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
    if existing and db.event_pipeline_status(existing) == "complete": return existing
    event["is_filtered_in"] = False
    if existing:
        event_uuid = existing
    else:
        event_uuid, inserted = db.insert_event(event)
        if not inserted and db.event_pipeline_status(event_uuid) == "complete": return event_uuid
    correlation.apply(event)
    incident_key = str((event.get("raw_kv") or {}).get("incident_key") or "")
    if incident_key:
        attached_finding = db.attach_event_to_correlated_finding(incident_key, event_uuid, event)
        if attached_finding:
            event["is_filtered_in"] = True
            event["raw_kv"]["incident_aggregated"] = True
            event["raw_kv"]["incident_finding_id"] = attached_finding
            db.update_event_decision(event_uuid, event)
            db.mark_event_complete(event_uuid)
            return event_uuid
    ioc_hits, mitre_matched = _maybe_enrich(event)
    event["ioc_hits"] = ioc_hits
    forward = filters.should_forward_to_ai(event, ioc_hits=ioc_hits, mitre_matched=mitre_matched)
    event["is_filtered_in"] = forward
    db.update_event_decision(event_uuid, event)
    if forward:
        enriched = dict(event); enriched["db_id"] = event_uuid; enriched["ioc_hits"] = ioc_hits
        detection = detections.classify(event, ioc_hits=ioc_hits)
        if detection:
            enriched["detection"] = detection
            enriched["finding_id"], finding_created = db.insert_deterministic_finding(
                event_uuid, event, detection, ioc_hits
            )
            db.upsert_finding_indicators(enriched["finding_id"], event_uuid, ioc_hits)
            if incident_key and not finding_created:
                event["raw_kv"]["incident_aggregated"] = True
                db.update_event_decision(event_uuid, event)
                db.mark_event_complete(event_uuid)
                return event_uuid
        redis_client.push_filtered_event(enriched)
    db.mark_event_complete(event_uuid)
    return event_uuid
def _process_event(event: dict) -> bool:
    try:
        process_event(event); return True
    except Exception:
        logger.exception("Failed to process event"); return False
def raw_event_loop() -> None:
    while True:
        try:
            claimed = redis_client.blocking_claim_raw_event(timeout=5)
            if claimed is None: continue
            event, payload = claimed
            if _process_event(event): redis_client.ack_raw_event(payload)
            else: logger.warning("Raw event queue outcome=%s", redis_client.retry_raw_event(payload))
        except Exception: logger.exception("raw_event_loop error"); time.sleep(2)


def _process_wazuh_batch(stream: str, documents: list[dict], normalizer, prefix: str,
                         timestamp_paths: tuple[str, ...]) -> None:
    completed_cursor = None
    for document in documents:
        doc_id = f"{prefix}-{document.get('_id', '')}"
        if _dedupe(doc_id):
            if not _process_event(normalizer(document)):
                _seen_ids.discard(doc_id)
                break
        cursor = wazuh_client.document_cursor(document, *timestamp_paths)
        if cursor: completed_cursor = cursor
    if completed_cursor:
        redis_client.set_source_cursor(stream, completed_cursor)


def wazuh_alerts_loop() -> None:
    while True:
        try:
            cursor = redis_client.get_source_cursor("wazuh:alerts")
            _process_wazuh_batch("wazuh:alerts", wazuh_client.fetch_recent_alerts(cursor=cursor),
                                 wazuh_client.wazuh_alert_to_normalized, "alert", ("@timestamp",))
        except Exception: logger.exception("wazuh_alerts_loop error")
        time.sleep(WAZUH_POLL_INTERVAL_SECONDS)
def wazuh_fim_loop() -> None:
    while True:
        try:
            cursor = redis_client.get_source_cursor("wazuh:fim")
            _process_wazuh_batch("wazuh:fim", wazuh_client.fetch_recent_fim_events(cursor=cursor),
                                 wazuh_client.wazuh_fim_to_normalized, "fim", ("@timestamp",))
        except Exception: logger.exception("wazuh_fim_loop error")
        time.sleep(WAZUH_FIM_POLL_INTERVAL_SECONDS)
def wazuh_vuln_loop() -> None:
    while True:
        try:
            cursor = redis_client.get_source_cursor("wazuh:vulnerabilities")
            _process_wazuh_batch("wazuh:vulnerabilities", wazuh_client.fetch_recent_vulnerabilities(cursor=cursor),
                                 wazuh_client.wazuh_vulnerability_to_normalized, "vuln",
                                 ("vulnerability.detected_at", "@timestamp"))
        except Exception: logger.exception("wazuh_vuln_loop error")
        time.sleep(WAZUH_VULN_POLL_INTERVAL_SECONDS)
