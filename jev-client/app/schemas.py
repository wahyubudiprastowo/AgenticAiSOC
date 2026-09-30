from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=200)
    kind: Literal["source_event", "ioc", "correlation", "prior_incident", "attribution"]
    summary: str = Field(min_length=1, max_length=2000)
    attributes: dict[str, Any] = Field(default_factory=dict)


class EvidenceEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str | None = None
    type: str | None = None
    severity: str | None = None
    action: str | None = None
    mitre_technique: list[str] = Field(default_factory=list)
    operation: str | None = None
    wazuh_rule_id: str | None = None
    wazuh_rule_groups: list[str] = Field(default_factory=list)
    correlation_count: int | None = None
    test_marker: str | None = None
    is_synthetic_test: bool = False


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding: str
    evidence: list[str] = Field(default_factory=list)
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    context: str | None = None
    category_hint: str | None = None
    subtype_hint: str | None = None
    taxonomy_version: str | None = None
    skill: str | None = None
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    event: EvidenceEvent | None = None
    deterministic_detection: dict[str, Any] | None = None
    attribution: dict[str, Any] | None = None


class AIAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["supported", "insufficient", "contradicted", "unavailable"]
    threat_classification: str = Field(min_length=1, max_length=200)
    proposed_category: str | None = None
    proposed_subtype: str | None = None
    mitre_technique: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    investigation_recommendation: str = Field(min_length=1, max_length=4000)
    severity: Literal["low", "medium", "high", "critical"]
    based_on: list[str] = Field(default_factory=list)
    reasoning: str = Field(min_length=1, max_length=4000)

    @field_validator("based_on")
    @classmethod
    def unique_evidence_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))
