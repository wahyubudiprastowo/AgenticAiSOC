from __future__ import annotations
import logging, os
from pathlib import Path
from typing import Any, Optional
import yaml
from shared.taxonomy import category_ids, normalize_subtype, valid_mitre
logger = logging.getLogger("hermes.skill_loader")
SKILLS_DIR = Path(os.getenv("HERMES_SKILLS_DIR", str(Path(__file__).resolve().parent / "skills")))
_skills_cache: Optional[list[dict]] = None
def load_skills(force_reload: bool = False) -> list[dict]:
    global _skills_cache
    if _skills_cache is not None and not force_reload: return _skills_cache
    skills = []
    if not SKILLS_DIR.exists(): _skills_cache = []; return _skills_cache
    for path in sorted(SKILLS_DIR.glob("*.yaml")):
        try:
            with path.open("r", encoding="utf-8") as fh:
                skill = yaml.safe_load(fh)
                if not isinstance(skill, dict) or not skill.get("skill"):
                    raise ValueError("skill file requires a mapping and skill id")
                category = skill.get("category")
                if category not in category_ids():
                    raise ValueError(f"unknown taxonomy category: {category}")
                if skill.get("attack_subtype"):
                    normalized = normalize_subtype(category, skill["attack_subtype"])
                    if normalized != skill["attack_subtype"]:
                        raise ValueError(f"unknown taxonomy subtype: {category}.{skill['attack_subtype']}")
                mitre = skill.get("mitre_technique") or []
                if valid_mitre(mitre) != sorted(set(mitre)):
                    raise ValueError(f"invalid or duplicate MITRE technique in {path.name}")
                skill["_file"] = path.name; skill.setdefault("priority", 0); skills.append(skill)
        except Exception: logger.exception("Failed to load skill file %s", path)
    _skills_cache = skills
    logger.info("Loaded %d skills: %s", len(skills), [s.get("skill") for s in skills])
    return skills
def _values(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _values(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value: yield from _values(item)
    elif value is not None:
        yield str(value)

def _norm(value: Any) -> str: return str(value or "").strip().lower()
def _norm_set(values) -> set[str]: return {_norm(v) for v in (values or []) if _norm(v)}

def select_skill(event: dict) -> Optional[dict]:
    """Select a skill from structured evidence; unmatched events stay unmatched.

    Supported match keys are event_types, operations, sources, wazuh_groups,
    mitre_techniques, defender_categories, keywords, exclude_keywords and
    type_only. Exact structured matches outrank free-text keyword matches.
    """
    event_type = _norm(event.get("type")); source = _norm(event.get("source"))
    raw_kv = event.get("raw_kv") or {}
    operation = _norm(raw_kv.get("operation"))
    groups = _norm_set(raw_kv.get("wazuh_rule_groups"))
    mitre = _norm_set(event.get("mitre_technique"))
    defender_categories = _norm_set(raw_kv.get("alert_categories"))
    searchable = " ".join(_norm(v) for v in [event.get("description"), event_type, source,
                                               event.get("action"), *_values(raw_kv)])

    best_match: Optional[dict] = None; best_key: tuple[int, int, int] = (0, 0, 0)
    for skill in load_skills():
        cfg = skill.get("match") or {}
        excluded = [k for k in cfg.get("exclude_keywords", []) if _norm(k) in searchable]
        if excluded: continue

        score = 0; evidence_matches = 0
        configured_types = _norm_set(cfg.get("event_types"))
        type_match = event_type in configured_types
        if operation and operation in _norm_set(cfg.get("operations")):
            score += 120; evidence_matches += 1
        if mitre & _norm_set(cfg.get("mitre_techniques")):
            score += 100 + 5 * len(mitre & _norm_set(cfg.get("mitre_techniques"))); evidence_matches += 1
        if defender_categories & _norm_set(cfg.get("defender_categories")):
            score += 90; evidence_matches += 1
        if groups & _norm_set(cfg.get("wazuh_groups")):
            score += 70; evidence_matches += 1
        keyword_hits = sum(1 for keyword in cfg.get("keywords", []) if _norm(keyword) in searchable)
        if keyword_hits:
            score += 60 * keyword_hits; evidence_matches += keyword_hits
        if type_match and cfg.get("type_only"):
            score += 50; evidence_matches += 1
        elif type_match and evidence_matches:
            score += 15
        configured_sources = _norm_set(cfg.get("sources"))
        if source in configured_sources and evidence_matches:
            score += 10
        if configured_sources and cfg.get("require_source") and source not in configured_sources:
            continue
        if not evidence_matches: continue
        key = (score, int(skill.get("priority", 0)), keyword_hits)
        if key > best_key: best_key = key; best_match = skill
    return best_match
