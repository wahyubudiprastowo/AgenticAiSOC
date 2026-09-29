from __future__ import annotations
import logging, os, time
from . import db, jev_client, memory, redis_client
from .agents import InvestigationAgent, ThreatAnalystAgent, TriageAgent
from .skill_loader import load_skills, select_skill
logger = logging.getLogger("hermes.worker")
triage_agent = TriageAgent(); investigation_agent = InvestigationAgent(); threat_analyst_agent = ThreatAnalystAgent()
_APT_NAME_MARKERS = ("apt", "lazarus", "fancy bear", "cozy bear", "kimsuky", "turla", "sandworm", "volt typhoon",
    "mustang panda", "apt28", "apt29", "apt41", "conti", "fin7", "carbanak", "equation group")
def _detect_apt_indicator(ioc_hits: list[dict]) -> str | None:
    for hit in ioc_hits:
        detail = (hit.get("detail") or "").lower()
        for marker in _APT_NAME_MARKERS:
            if marker in detail: return hit.get("detail")
    return None
def _get_apt_skill() -> dict | None:
    return next((s for s in load_skills() if s.get("skill") == "apt_activity"), None)
def _build_evidence_object(event, triage, investigation, skill):
    evidence_lines = [f"EVT-{event.get('id')}: {event.get('description') or event.get('type')}"]
    for hit in investigation.get("ioc_hits", []) or []:
        verdict = "malicious" if hit.get("malicious") else "not flagged as malicious"
        line = f"IOC-{hit.get('ioc', event.get('src_ip'))}: reputation check returned {verdict} (confidence={hit.get('confidence', hit.get('score', 0))})"
        if hit.get("detail"): line += f" [{hit['detail']}]"
        evidence_lines.append(line)
    if investigation.get("attack_chain"): evidence_lines.append(f"CHAIN: observed steps {investigation['attack_chain']}")
    raw_kv = event.get("raw_kv") or {}
    return {"finding": event.get("description") or f"{event.get('type')} on {event.get('destination')}",
            "evidence": evidence_lines, "context": event.get("destination") or event.get("source"),
            "category_hint": triage.get("category"), "skill": (skill or {}).get("skill"),
            "event": {"source": event.get("source"), "type": event.get("type"), "severity": event.get("severity"),
                      "action": event.get("action"), "mitre_technique": event.get("mitre_technique") or [],
                      "operation": raw_kv.get("operation"), "wazuh_rule_id": raw_kv.get("wazuh_rule_id"),
                      "wazuh_rule_groups": raw_kv.get("wazuh_rule_groups") or [],
                      "correlation_count": raw_kv.get("correlation_count"),
                      "test_marker": raw_kv.get("test_marker"),
                      "is_synthetic_test": bool(raw_kv.get("is_synthetic_test"))}}
def _process_filtered_event(event: dict) -> None:
    start = time.time(); skill = select_skill(event); preliminary_finding_id = event.get("finding_id")
    if skill is None:
        db.log_agent_run("triage_no_match", preliminary_finding_id, event, {"need_analysis": False, "reason": "no evidence-backed detection skill"},
                         int((time.time() - start) * 1000))
        return
    triage = triage_agent.run(event, skill)
    db.log_agent_run("triage", preliminary_finding_id, event, triage, int((time.time() - start) * 1000))
    if not triage.get("need_analysis"): return
    t0 = time.time(); investigation = investigation_agent.run(event, skill)
    db.log_agent_run("investigation", preliminary_finding_id, event, investigation, int((time.time() - t0) * 1000))
    apt_evidence_detail = _detect_apt_indicator(investigation.get("ioc_hits", []) or [])
    if apt_evidence_detail:
        apt_skill = _get_apt_skill()
        if apt_skill is not None and skill is not apt_skill:
            skill = apt_skill; triage["category"] = apt_skill.get("category", "apt_activity")
            triage["confidence"] = min(round(triage.get("confidence", 0.6) + 0.15, 2), 0.99)
    t0 = time.time(); threat_summary = threat_analyst_agent.run(triage, investigation, event)
    db.log_agent_run("threat_analyst", preliminary_finding_id, event, threat_summary, int((time.time() - t0) * 1000))
    evidence_obj = _build_evidence_object(event, triage, investigation, skill)
    if apt_evidence_detail: evidence_obj["evidence"].append(f"APT-ATTRIBUTION: {apt_evidence_detail}")
    similar = memory.search_similar_incidents(evidence_obj.get("finding", ""), limit=2)
    for i, prior in enumerate(similar):
        if prior.get("score", 0) > 0.85:
            evidence_obj["evidence"].append(f"PRIOR-INCIDENT-{i}: similar past finding classified as '{prior.get('threat_classification')}'")
    t0 = time.time(); jev_result = jev_client.analyze_evidence(evidence_obj)
    db.log_agent_run("jev", preliminary_finding_id, evidence_obj, jev_result, int((time.time() - t0) * 1000))
    expected_classification = threat_summary.get("type", "Unknown")
    if expected_classification != "Unknown" and jev_result.get("threat_classification") != expected_classification:
        jev_result["model_threat_classification"] = jev_result.get("threat_classification", "Unknown")
        jev_result["threat_classification"] = expected_classification
        jev_result["classification_reconciled"] = True
    jev_result["mitre_technique"] = sorted(set((jev_result.get("mitre_technique") or []) +
                                                (skill.get("mitre_technique") or []) +
                                                (event.get("mitre_technique") or [])))
    ai_result_with_summary = dict(jev_result); ai_result_with_summary["threat_summary"] = threat_summary
    finding_values = {"category": triage.get("category"),
        "threat_classification": jev_result.get("threat_classification", "Unknown"),
        "mitre_technique": jev_result.get("mitre_technique", []), "confidence": jev_result.get("confidence", 0.0),
        "severity": jev_result.get("severity", event.get("severity", "low")), "evidence": evidence_obj,
        "ai_result": ai_result_with_summary, "recommendation": jev_result.get("investigation_recommendation", "")}
    finding_id = preliminary_finding_id
    if finding_id:
        updated = db.enrich_finding(finding_id=finding_id, **finding_values)
        if not updated: finding_id = None
    if not finding_id:
        finding_id = db.insert_finding(event_ids=[event.get("db_id") or event.get("id")], **finding_values)
    memory.store_incident_memory(finding_id, evidence_obj, jev_result)
    finding_payload = {"finding_id": finding_id, "event": {"id": event.get("id"), "source": event.get("source"), "severity": event.get("severity")},
        "skill": skill.get("skill") if skill else None, "triage": triage, "investigation": investigation,
        "threat_summary": threat_summary, "jev_result": jev_result}
    redis_client.publish_finding(finding_payload)
def orchestration_loop() -> None:
    while True:
        try:
            event = redis_client.blocking_pop_filtered_event(timeout=5)
            if event is None: continue
            _process_filtered_event(event)
        except Exception: logger.exception("orchestration_loop error"); time.sleep(2)
