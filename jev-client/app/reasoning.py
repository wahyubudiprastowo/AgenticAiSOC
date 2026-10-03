from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path

from pydantic import ValidationError

from shared.taxonomy import (
    category_ids,
    normalize_subtype,
    subtype_display,
    subtype_mitre,
    taxonomy_version,
    valid_mitre,
)
from .schemas import AIAnalysis, AnalyzeRequest
from .circuit import RemoteCircuitBreaker


logger = logging.getLogger("jev-client.reasoning")
AI_PROVIDER_BASE_URL = os.getenv("AI_PROVIDER_BASE_URL", os.getenv("AI_BASE_URL", "http://jev:20128"))
AI_MODEL = os.getenv("AI_MODEL", "cgpt-web/gpt-5.6-sol-high")
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "4096"))
AI_TIMEOUT_SECONDS = max(2.0, float(os.getenv("AI_TIMEOUT_SECONDS", "180")))
JEV_UPSTREAM_TIMEOUT = max(2.0, float(os.getenv("JEV_UPSTREAM_TIMEOUT_SECONDS", str(AI_TIMEOUT_SECONDS))))
JEV_FAILURE_BACKOFF = max(5.0, float(os.getenv("JEV_FAILURE_BACKOFF_SECONDS", "60")))
JEV_FALLBACK_MODE = os.getenv("JEV_FALLBACK_MODE", "auto")
_PROMPT_PATH = Path(os.getenv("JEV_SYSTEM_PROMPT_PATH", "/app/prompts/jev_system_prompt.txt"))
_RUNTIME_LOCK = threading.Lock()
_RUNTIME = {"mode": "untested", "last_checked": None, "last_error": None,
            "schema_version": 2, "taxonomy_version": taxonomy_version()}
_CIRCUIT = RemoteCircuitBreaker(JEV_FAILURE_BACKOFF)


def _load_system_prompt() -> str:
    if _PROMPT_PATH.exists(): return _PROMPT_PATH.read_text(encoding="utf-8")
    return "Analyze only cited evidence and return the required JSON schema."


SYSTEM_PROMPT = _load_system_prompt()


def runtime_status() -> dict:
    with _RUNTIME_LOCK:
        runtime = dict(_RUNTIME)
    runtime.update(_CIRCUIT.snapshot())
    return runtime


def _record_runtime(mode: str, error: str | None = None) -> None:
    with _RUNTIME_LOCK:
        _RUNTIME.update({"mode": mode, "last_checked": time.time(), "last_error": error})


def _fallback(request: AnalyzeRequest, reason: str) -> dict:
    _record_runtime("fallback", reason)
    result = _local_reasoning(request)
    result["verdict"] = "unavailable"
    result["confidence"] = 0.0
    result["reasoning_mode"] = "fallback"
    result["fallback_reason"] = reason
    return result


def _evidence_ids(request: AnalyzeRequest) -> set[str]:
    ids = {item.id for item in request.evidence_items}
    for line in request.evidence:
        prefix = line.split(":", 1)[0].strip()
        if prefix: ids.add(prefix)
    return ids


def _validate_analysis(value: object, request: AnalyzeRequest) -> dict:
    try:
        analysis = AIAnalysis.model_validate(value)
    except ValidationError as exc:
        raise ValueError(f"invalid AI response schema: {exc.errors(include_url=False)}") from exc
    if analysis.proposed_category and analysis.proposed_category not in category_ids():
        raise ValueError(f"unknown proposed_category: {analysis.proposed_category}")
    if analysis.proposed_category and analysis.proposed_subtype:
        normalized = normalize_subtype(analysis.proposed_category, analysis.proposed_subtype)
        if normalized != analysis.proposed_subtype:
            raise ValueError(f"unknown proposed_subtype: {analysis.proposed_category}.{analysis.proposed_subtype}")
    if valid_mitre(analysis.mitre_technique) != sorted(set(analysis.mitre_technique)):
        raise ValueError("mitre_technique contains an invalid or duplicate ATT&CK ID")
    unknown_refs = set(analysis.based_on) - _evidence_ids(request)
    if unknown_refs:
        raise ValueError(f"based_on references evidence that was not supplied: {sorted(unknown_refs)}")
    if analysis.verdict in {"supported", "contradicted"} and not analysis.based_on:
        raise ValueError(f"verdict {analysis.verdict} requires at least one evidence reference")
    return analysis.model_dump()


def _local_reasoning(request: AnalyzeRequest) -> dict:
    category = request.category_hint if request.category_hint in category_ids() else None
    subtype = normalize_subtype(category, request.subtype_hint) if category else None
    evidence_ids = sorted(_evidence_ids(request))
    if not category or not evidence_ids:
        return AIAnalysis(verdict="insufficient", threat_classification="Unknown",
            proposed_category=None, proposed_subtype=None, mitre_technique=[], confidence=0.0,
            investigation_recommendation="Review the source event because the deterministic evidence is incomplete.",
            severity="low", based_on=[], reasoning="No valid category hint or citable evidence was supplied.").model_dump()
    event = request.event
    severity = event.severity if event and event.severity in {"low", "medium", "high", "critical"} else "medium"
    mitre = valid_mitre([*(event.mitre_technique if event else []), *subtype_mitre(category, subtype)])
    return AIAnalysis(verdict="supported", threat_classification=subtype_display(category, subtype),
        proposed_category=category, proposed_subtype=subtype, mitre_technique=mitre, confidence=0.65,
        investigation_recommendation="Validate the affected identity or asset using the cited source evidence.",
        severity=severity, based_on=evidence_ids[:8],
        reasoning="Local deterministic fallback retained the supplied taxonomy classification; it did not infer new facts.").model_dump()


def _extract_json_from_text(text: str):
    try: return json.loads(text)
    except json.JSONDecodeError: pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try: return json.loads(match.group(0))
        except json.JSONDecodeError: return None
    return None


def _call_remote_jev(request: AnalyzeRequest) -> dict:
    import httpx

    headers = {"Content-Type": "application/json"}
    if AI_API_KEY: headers["Authorization"] = f"Bearer {AI_API_KEY}"
    evidence_payload = request.model_dump(mode="json")
    evidence_payload["contract"] = {"schema_version": 2, "taxonomy_version": taxonomy_version(),
        "allowed_categories": sorted(category_ids())}
    payload = {"model": AI_MODEL, "max_tokens": AI_MAX_TOKENS,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": json.dumps(evidence_payload)}]}
    url = f"{AI_PROVIDER_BASE_URL.rstrip('/')}/chat/completions"
    try:
        with httpx.Client(timeout=JEV_UPSTREAM_TIMEOUT) as client:
            response = client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
        content = (data["choices"][0]["message"]["content"] if isinstance(data, dict) and "choices" in data else
                   data.get("content") if isinstance(data, dict) and "content" in data else
                   data.get("response") if isinstance(data, dict) and "response" in data else json.dumps(data))
        parsed = _extract_json_from_text(content) if isinstance(content, str) else content
        if parsed is None:
            raise ValueError("response did not contain a JSON object")
        return _validate_analysis(parsed, request)
    except httpx.HTTPStatusError as exc:
        message = ""
        try:
            message = str((exc.response.json().get("error") or {}).get("message") or "")
        except Exception:
            pass
        raise RuntimeError(
            f"upstream HTTP {exc.response.status_code}" + (f": {message[:160]}" if message else "")
        ) from exc


def analyze(evidence: dict | AnalyzeRequest) -> dict:
    request = evidence if isinstance(evidence, AnalyzeRequest) else AnalyzeRequest.model_validate(evidence)
    if JEV_FALLBACK_MODE == "force_mock":
        result = _local_reasoning(request)
        result["reasoning_mode"] = "fallback"
        _record_runtime("fallback", "forced by JEV_FALLBACK_MODE")
        return result
    allowed, circuit_reason = _CIRCUIT.begin()
    if not allowed:
        if JEV_FALLBACK_MODE == "force_remote":
            _record_runtime("unavailable", circuit_reason)
            raise RuntimeError(circuit_reason)
        return _fallback(request, circuit_reason or "upstream circuit unavailable")
    try:
        result = _call_remote_jev(request)
        _CIRCUIT.finish(True)
        result["reasoning_mode"] = "remote"
        _record_runtime("remote")
        return result
    except Exception as exc:
        _CIRCUIT.finish(False)
        error = str(exc)[:300]
        _record_runtime("unavailable" if JEV_FALLBACK_MODE == "force_remote" else "fallback", error)
        if JEV_FALLBACK_MODE == "force_remote": raise
        return _fallback(request, error)
