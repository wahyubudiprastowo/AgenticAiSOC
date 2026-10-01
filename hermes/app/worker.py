from __future__ import annotations

import logging
import re
import time

from shared.taxonomy import (
    category_family,
    normalize_subtype,
    subtype_display,
    subtype_mitre,
    taxonomy_version,
    valid_mitre,
)

from . import db, jev_client, memory, redis_client
from .agents import InvestigationAgent, ThreatAnalystAgent, TriageAgent
from .skill_loader import select_skill


logger = logging.getLogger("hermes.worker")
triage_agent = TriageAgent()
investigation_agent = InvestigationAgent()
threat_analyst_agent = ThreatAnalystAgent()

_ACTOR_PATTERNS = (
    re.compile(r"\bapt(?:28|29|41)?\b", re.IGNORECASE),
    *(re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE) for name in (
        "lazarus", "fancy bear", "cozy bear", "kimsuky", "turla", "sandworm",
        "volt typhoon", "mustang panda", "fin7", "carbanak", "equation group",
    )),
)


def _detect_attribution(ioc_hits: list[dict]) -> dict | None:
    matches: list[dict] = []
    for hit in ioc_hits:
        for candidate in [hit, *(hit.get("providers") or [])]:
            detail = str(candidate.get("detail") or "").strip()
            if detail and any(pattern.search(detail) for pattern in _ACTOR_PATTERNS):
                matches.append({
                    "ioc": hit.get("ioc"),
                    "provider": candidate.get("name") or hit.get("provider") or "unknown",
                    "detail": detail[:1000],
                })
    if not matches:
        return None
    providers = sorted({match["provider"] for match in matches})
    return {
        "status": "corroborated" if len(providers) >= 2 else "provider_reported",
        "providers": providers,
        "matches": matches[:8],
    }


def _build_evidence_object(event: dict, triage: dict, investigation: dict,
                           skill: dict, attribution: dict | None) -> dict:
    event_ref = str(event.get("db_id") or event.get("id") or "unknown")
    event_evidence_id = f"EVT-{event_ref}"
    description = str(event.get("description") or event.get("type") or "source event")
    evidence_lines = [f"{event_evidence_id}: {description}"]
    evidence_items = [{
        "id": event_evidence_id,
        "kind": "source_event",
        "summary": description[:2000],
        "attributes": {
            "source": event.get("source"), "type": event.get("type"),
            "severity": event.get("severity"), "action": event.get("action"),
        },
    }]
    indicators = investigation.get("ioc_hits", []) or []
    for index, hit in enumerate(indicators, start=1):
        evidence_id = f"IOC-{index}"
        verdict = "malicious" if hit.get("malicious") else "not flagged as malicious"
        providers = ",".join(
            provider.get("name", "unknown") for provider in hit.get("providers", [])
            if provider.get("mode") == "live"
        ) or "none-live"
        summary = (
            f"{hit.get('ioc', event.get('src_ip'))} ({hit.get('ioc_type', 'ip')}): {verdict}; "
            f"confidence={hit.get('confidence', hit.get('score', 0))}; "
            f"status={hit.get('enrichment_status', 'unknown')}; providers={providers}"
        )
        evidence_lines.append(f"{evidence_id}: {summary}")
        evidence_items.append({
            "id": evidence_id, "kind": "ioc", "summary": summary[:2000],
            "attributes": {
                "ioc": hit.get("ioc"), "ioc_type": hit.get("ioc_type"),
                "malicious": bool(hit.get("malicious")), "providers": providers.split(","),
            },
        })
    if investigation.get("attack_chain"):
        chain_summary = f"Observed steps: {investigation['attack_chain']}"
        evidence_lines.append(f"CHAIN-1: {chain_summary}")
        evidence_items.append({"id": "CHAIN-1", "kind": "correlation", "summary": chain_summary,
                               "attributes": {"steps": investigation["attack_chain"]}})
    raw_kv = event.get("raw_kv") or {}
    if raw_kv.get("incident_key"):
        correlation_summary = (
            f"M365 incident correlation scope={raw_kv.get('incident_scope') or 'message'}; "
            f"window={raw_kv.get('incident_window_seconds') or 'unknown'} seconds"
        )
        evidence_lines.append(f"CORR-1: {correlation_summary}")
        evidence_items.append({"id": "CORR-1", "kind": "correlation", "summary": correlation_summary,
                               "attributes": {"scope": raw_kv.get("incident_scope"),
                                              "window_seconds": raw_kv.get("incident_window_seconds")}})
    if attribution:
        summary = f"Threat-actor reporting from providers: {', '.join(attribution['providers'])}"
        evidence_lines.append(f"ATTRIBUTION-1: {summary}")
        evidence_items.append({"id": "ATTRIBUTION-1", "kind": "attribution", "summary": summary,
                               "attributes": attribution})
    deterministic = event.get("detection") or None
    return {
        "finding": description,
        "evidence": evidence_lines,
        "evidence_items": evidence_items,
        "context": event.get("destination") or event.get("source"),
        "category_hint": triage.get("category"),
        "subtype_hint": triage.get("attack_subtype"),
        "taxonomy_version": (deterministic or {}).get("taxonomy_version") or taxonomy_version(),
        "skill": skill.get("skill"),
        "indicators": indicators,
        "deterministic_detection": deterministic,
        "attribution": attribution,
        "correlation": ({"key": raw_kv.get("incident_key"), "scope": raw_kv.get("incident_scope"),
                         "event_count": raw_kv.get("correlation_count") or 1}
                        if raw_kv.get("incident_key") else None),
        "event": {
            "source": event.get("source"), "type": event.get("type"),
            "severity": event.get("severity"), "action": event.get("action"),
            "mitre_technique": event.get("mitre_technique") or [],
            "operation": raw_kv.get("operation"), "wazuh_rule_id": raw_kv.get("wazuh_rule_id"),
            "wazuh_rule_groups": raw_kv.get("wazuh_rule_groups") or [],
            "correlation_count": raw_kv.get("correlation_count"),
            "test_marker": raw_kv.get("test_marker"),
            "is_synthetic_test": bool(raw_kv.get("is_synthetic_test")),
        },
    }


def _canonical_result(event: dict, triage: dict, skill: dict,
                      attribution: dict | None, jev_result: dict) -> tuple[dict, dict]:
    deterministic = event.get("detection") or {}
    category = deterministic.get("category") or triage["category"]
    subtype = normalize_subtype(
        category,
        deterministic.get("attack_subtype") or triage.get("attack_subtype") or skill.get("attack_subtype"),
    )
    classification = deterministic.get("classification") or subtype_display(category, subtype)
    if deterministic:
        mitre = valid_mitre([*(deterministic.get("mitre_technique") or []),
                             *(event.get("mitre_technique") or [])])
    else:
        mitre = valid_mitre([*(event.get("mitre_technique") or []),
                             *(skill.get("mitre_technique") or []),
                             *subtype_mitre(category, subtype)])
    confidence = deterministic.get("confidence")
    if not isinstance(confidence, (int, float)):
        confidence = triage.get("confidence", 0.5)
    severity = str(event.get("severity") or "low").lower()
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "low"
    ai_supported = jev_result.get("reasoning_mode") == "remote" and jev_result.get("verdict") == "supported"
    recommendation = (
        jev_result.get("investigation_recommendation") if ai_supported
        else deterministic.get("recommendation") or
        "Review the cited source evidence and validate the affected account or asset."
    )
    attribution_status = deterministic.get("attribution_status") or "none"
    if attribution:
        attribution_status = attribution["status"]
    canonical = {
        "category": category,
        "threat_classification": classification,
        "mitre_technique": mitre,
        "confidence": float(confidence),
        "severity": severity,
        "recommendation": recommendation,
    }
    metadata = {
        "attack_family": deterministic.get("attack_family") or category_family(category),
        "attack_subtype": subtype,
        "taxonomy_version": deterministic.get("taxonomy_version") or taxonomy_version(),
        "classification_method": deterministic.get("classification_method") or "hermes_skill",
        "detection_rule_version": deterministic.get("rule_version"),
        "evidence_quality": deterministic.get("evidence_quality") or "moderate",
        "attribution_status": attribution_status,
        "ai_verdict": jev_result.get("verdict"),
        "ai_reasoning_mode": jev_result.get("reasoning_mode"),
    }
    return canonical, metadata


def _process_filtered_event(event: dict) -> None:
    start = time.time()
    skill = select_skill(event)
    preliminary_finding_id = event.get("finding_id")
    if skill is None:
        db.log_agent_run(
            "triage_no_match", preliminary_finding_id, event,
            {"need_analysis": False, "reason": "no evidence-backed detection skill"},
            int((time.time() - start) * 1000),
        )
        return
    triage = triage_agent.run(event, skill)
    db.log_agent_run("triage", preliminary_finding_id, event, triage, int((time.time() - start) * 1000))
    if not triage.get("need_analysis"):
        return
    t0 = time.time()
    investigation = investigation_agent.run(event, skill)
    db.log_agent_run("investigation", preliminary_finding_id, event, investigation, int((time.time() - t0) * 1000))
    attribution = _detect_attribution(investigation.get("ioc_hits", []) or [])
    t0 = time.time()
    threat_summary = threat_analyst_agent.run(triage, investigation, event)
    db.log_agent_run("threat_analyst", preliminary_finding_id, event, threat_summary,
                     int((time.time() - t0) * 1000))
    evidence_obj = _build_evidence_object(event, triage, investigation, skill, attribution)
    similar = memory.search_similar_incidents(evidence_obj["finding"], limit=2)
    for index, prior in enumerate(similar, start=1):
        if prior.get("score", 0) <= 0.85:
            continue
        evidence_id = f"PRIOR-{index}"
        summary = f"Similar prior finding: {prior.get('threat_classification') or 'Unknown'}"
        evidence_obj["evidence"].append(f"{evidence_id}: {summary}")
        evidence_obj["evidence_items"].append({
            "id": evidence_id, "kind": "prior_incident", "summary": summary,
            "attributes": {"score": prior.get("score"), "finding_id": prior.get("finding_id")},
        })
    t0 = time.time()
    jev_result = jev_client.analyze_evidence(evidence_obj)
    db.log_agent_run("jev", preliminary_finding_id, evidence_obj, jev_result, int((time.time() - t0) * 1000))
    canonical, metadata = _canonical_result(event, triage, skill, attribution, jev_result)
    ai_result = dict(jev_result)
    ai_result["threat_summary"] = threat_summary
    ai_result["canonical_classification"] = {
        "category": canonical["category"], "attack_subtype": metadata["attack_subtype"],
        "threat_classification": canonical["threat_classification"],
        "confidence": canonical["confidence"], "severity": canonical["severity"],
    }
    finding_values = {
        **canonical, "evidence": evidence_obj, "ai_result": ai_result, "metadata": metadata,
    }
    finding_id = preliminary_finding_id
    if finding_id and not db.enrich_finding(finding_id=finding_id, **finding_values):
        finding_id = None
    if not finding_id:
        finding_id = db.insert_finding(
            event_ids=[event.get("db_id") or event.get("id")], **finding_values,
        )
    memory.store_incident_memory(finding_id, evidence_obj, {
        **canonical, "ai_verdict": metadata["ai_verdict"],
        "ai_reasoning_mode": metadata["ai_reasoning_mode"],
    })
    redis_client.publish_finding({
        "finding_id": finding_id,
        "event": {"id": event.get("id"), "source": event.get("source"), "severity": event.get("severity")},
        "skill": skill.get("skill"), "triage": triage, "investigation": investigation,
        "threat_summary": threat_summary, "jev_result": jev_result,
        "canonical": canonical, "metadata": metadata,
    })


def orchestration_loop() -> None:
    while True:
        try:
            claimed = redis_client.blocking_claim_filtered_event(timeout=5)
            if claimed is None:
                continue
            event, payload = claimed
            try:
                _process_filtered_event(event)
            except Exception:
                logger.exception("Filtered event processing failed")
                logger.warning("Filtered event queue outcome=%s", redis_client.retry_filtered_event(payload))
            else:
                redis_client.ack_filtered_event(payload)
        except Exception:
            logger.exception("orchestration_loop error")
            time.sleep(2)
