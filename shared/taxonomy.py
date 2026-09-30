from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _taxonomy_path() -> Path:
    configured = os.getenv("DETECTION_TAXONOMY_PATH")
    candidates = [
        Path(configured) if configured else None,
        Path("/app/config/detection_taxonomy.yaml"),
        Path(__file__).resolve().parents[1] / "config" / "detection_taxonomy.yaml",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    raise RuntimeError("detection taxonomy file is unavailable")


def _validate(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict) or not data.get("version"):
        raise ValueError("taxonomy requires a version")
    categories = data.get("categories")
    if not isinstance(categories, dict) or not categories:
        raise ValueError("taxonomy requires categories")
    for category_id, category in categories.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", str(category_id)):
            raise ValueError(f"invalid category id: {category_id}")
        if not isinstance(category, dict) or not category.get("display_name") or not category.get("family"):
            raise ValueError(f"category {category_id} requires display_name and family")
        subtypes = category.get("subtypes") or {}
        default_subtype = category.get("default_subtype")
        if default_subtype not in subtypes:
            raise ValueError(f"category {category_id} has invalid default_subtype")
        for subtype_id, subtype in subtypes.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]*", str(subtype_id)):
                raise ValueError(f"invalid subtype id: {category_id}.{subtype_id}")
            if not isinstance(subtype, dict) or not subtype.get("display_name"):
                raise ValueError(f"subtype {category_id}.{subtype_id} requires display_name")
            invalid = [value for value in subtype.get("mitre", []) if not _MITRE_RE.fullmatch(str(value))]
            if invalid:
                raise ValueError(f"invalid MITRE IDs in {category_id}.{subtype_id}: {invalid}")
    return data


@lru_cache(maxsize=1)
def load_taxonomy() -> dict[str, Any]:
    with _taxonomy_path().open("r", encoding="utf-8") as handle:
        return _validate(yaml.safe_load(handle))


def taxonomy_version() -> str:
    return str(load_taxonomy()["version"])


def categories() -> dict[str, dict[str, Any]]:
    return load_taxonomy()["categories"]


def category_ids() -> set[str]:
    return set(categories())


def category_config(category_id: str) -> dict[str, Any]:
    return categories().get(category_id) or {}


def category_display(category_id: str) -> str:
    return str(category_config(category_id).get("display_name") or "Unknown")


def category_family(category_id: str) -> str:
    return str(category_config(category_id).get("family") or "unknown")


def default_subtype(category_id: str) -> str:
    return str(category_config(category_id).get("default_subtype") or "unknown")


def subtype_config(category_id: str, subtype_id: str | None) -> dict[str, Any]:
    category = category_config(category_id)
    subtype = subtype_id if subtype_id in (category.get("subtypes") or {}) else category.get("default_subtype")
    return (category.get("subtypes") or {}).get(subtype) or {}


def normalize_subtype(category_id: str, subtype_id: str | None) -> str:
    category = category_config(category_id)
    return str(subtype_id if subtype_id in (category.get("subtypes") or {}) else category.get("default_subtype") or "unknown")


def infer_subtype(category_id: str, classification: str | None = None,
                  subtype_id: str | None = None) -> tuple[str, str]:
    """Resolve stored subtype or conservatively infer one for legacy rows.

    Exact display-name matches are safe historical inferences. Everything else
    falls back to the category's generic/default subtype and is explicitly
    labelled so callers do not present it as source-observed evidence.
    """
    category = category_config(category_id)
    subtypes = category.get("subtypes") or {}
    if subtype_id in subtypes:
        return str(subtype_id), "stored"
    normalized = re.sub(r"[^a-z0-9]+", " ", str(classification or "").lower()).strip()
    if normalized:
        for candidate, config in subtypes.items():
            display = re.sub(r"[^a-z0-9]+", " ", str(config.get("display_name") or "").lower()).strip()
            if normalized == display:
                return str(candidate), "classification_display_match"
    return normalize_subtype(category_id, None), "category_default"


def subtype_display(category_id: str, subtype_id: str | None) -> str:
    return str(subtype_config(category_id, subtype_id).get("display_name") or category_display(category_id))


def subtype_mitre(category_id: str, subtype_id: str | None) -> list[str]:
    return [str(value) for value in subtype_config(category_id, subtype_id).get("mitre", [])]


def valid_mitre(values: list[str] | tuple[str, ...] | None) -> list[str]:
    return sorted({str(value) for value in (values or []) if _MITRE_RE.fullmatch(str(value))})


def public_registry() -> dict[str, Any]:
    data = load_taxonomy()
    return {"version": data["version"], "schema_version": data.get("schema_version", 1),
            "categories": data["categories"]}
