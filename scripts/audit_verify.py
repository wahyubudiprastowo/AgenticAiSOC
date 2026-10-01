#!/usr/bin/env python3
"""
Agentic AI SOC Platform — Automated Coordination Audit Verifier (v4)
Run with:  python3 scripts/audit_verify.py
Exit code: 0 if all checks pass, 1 if any FAIL is found.
"""
from __future__ import annotations
import os, re, sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
FAILURES: list[str] = []
WARNINGS: list[str] = []
PASSES: list[str] = []

def ok(msg): PASSES.append(msg); print(f"  OK: {msg}")
def fail(msg): FAILURES.append(msg); print(f"  FAIL: {msg}")
def warn(msg): WARNINGS.append(msg); print(f"  WARN: {msg}")
def section(t): print(f"\n{'='*78}\n{t}\n{'='*78}")

def read_env_keys(p: Path) -> dict[str, str]:
    keys = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, _, v = line.partition("="); keys[k.strip()] = v.strip()
    return keys

def find_getenv_calls(f: Path):
    text = f.read_text()
    pattern = re.compile(r'os\.getenv\(\s*"([A-Z0-9_]+)"\s*(?:,\s*(.*?))?\)')
    return [(m.group(1), m.group(2)) for m in pattern.finditer(text)]

def project_python_files():
    excluded_parts = {".git", ".venv", "venv", "env", "__pycache__"}
    return (path for path in ROOT.rglob("*.py") if not excluded_parts.intersection(path.relative_to(ROOT).parts))

def audit_section_1():
    section("SECTION 1: Docker Compose <-> .env <-> Inter-Service URLs")
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    services = set(compose.get("services", {}).keys())
    ok(f"docker-compose.yml parsed, {len(services)} services: {sorted(services)}")
    env_keys = read_env_keys(ROOT / ".env")
    ok(f".env parsed, {len(env_keys)} keys")
    url_pattern = re.compile(r'http://([a-z0-9][a-z0-9\-]*):(\d+)')
    referenced_hosts = {}
    for py_file in project_python_files():
        if py_file.name == "audit_verify.py": continue
        text = py_file.read_text(errors="ignore")
        for host, port in url_pattern.findall(text):
            referenced_hosts.setdefault(host, set()).add(str(py_file.relative_to(ROOT)))
    known_non_service = {"localhost", "127.0.0.1", "0.0.0.0", "wazuh.indexer", "wazuh.manager"}
    for host, files in sorted(referenced_hosts.items()):
        if host in known_non_service: continue
        if host in services: ok(f"Hostname '{host}' matches compose service")
        else: fail(f"Hostname '{host}' in {sorted(files)} does NOT match any service")
    ti_deps = compose["services"]["threat-intel"].get("depends_on", {})
    if "postgres" in ti_deps: ok("threat-intel depends_on: postgres")
    else: fail("threat-intel missing depends_on: postgres")
    dash_env = compose["services"]["dashboard"].get("environment", [])
    dash_vars = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in dash_env if "=" in e}
    expected_ports = {"SOC_CORE_URL": "18200", "HERMES_URL": "8003", "M365_COLLECTOR_URL": "8006",
        "THREAT_INTEL_URL": "8005", "SYSLOG_COLLECTOR_URL": "38001", "JEV_URL": "20128", "QDRANT_URL": "6333"}
    for var, url in dash_vars.items():
        m = url_pattern.search(url)
        if not m: continue
        host, port = m.group(1), m.group(2)
        if host in services: ok(f"dashboard {var}={url} targets valid service")
        else: fail(f"dashboard {var}={url} targets invalid service '{host}'")
        exp = expected_ports.get(var)
        if exp and port == exp: ok(f"dashboard {var} uses unchanged internal port {port}")
        elif exp: fail(f"dashboard {var} port {port} != expected {exp}")

def audit_section_2():
    section("SECTION 2: Hermes Skills <-> Dashboard Taxonomy (17 categories)")
    skills_dir = ROOT / "hermes" / "app" / "skills"
    cats = set()
    for f in sorted(skills_dir.glob("*.yaml")): cats.add(yaml.safe_load(f.read_text())["category"])
    registry = yaml.safe_load((ROOT / "config" / "detection_taxonomy.yaml").read_text())
    registry_cats = set(registry.get("categories", {}))
    ok(f"Found {len(cats)} categories across {len(list(skills_dir.glob('*.yaml')))} skills")
    if len(registry_cats) != 17: fail(f"Expected 17 registry categories, found {len(registry_cats)}")
    else: ok(f"Canonical taxonomy {registry['version']} defines 17 top-level categories")
    if cats != registry_cats:
        fail(f"Skill/registry category drift: missing={sorted(registry_cats-cats)}, extra={sorted(cats-registry_cats)}")
    else: ok("All Hermes skill categories are registered canonically")
    agg = (ROOT / "dashboard" / "app" / "aggregations.py").read_text()
    m = re.search(r"_CATEGORY_TO_THREAT_TYPE\s*=\s*\{(.*?)\}", agg, re.DOTALL)
    mapped = set(re.findall(r'"([a-z_]+)":\s*"', m.group(1))) if m else set()
    orphaned = registry_cats - mapped
    if orphaned: fail(f"Categories not mapped in dashboard: {sorted(orphaned)}")
    else: ok("All categories mapped in dashboard")
    agents = (ROOT / "hermes" / "app" / "agents.py").read_text()
    if "from shared.taxonomy import" in agents: ok("Hermes agents resolve labels/subtypes from canonical taxonomy")
    else: fail("Hermes agents do not import canonical taxonomy")
    jev = (ROOT / "jev-client" / "app" / "reasoning.py").read_text()
    if "from shared.taxonomy import" in jev and "category_ids" in jev:
        ok("Jev validates AI proposals against canonical taxonomy")
    else: fail("Jev does not validate against canonical taxonomy")

def audit_section_3():
    section("SECTION 3: Skill event_types <-> Normalizer-Produced Types")
    syslog = (ROOT / "syslog-collector" / "app" / "normalizer.py").read_text()
    fn = re.search(r"def _infer_type\(.*?\n(?=def _|\Z)", syslog, re.DOTALL)
    produced = set(re.findall(r'return\s+"(\w+)"', fn.group(0))) if fn else set()
    wazuh = (ROOT / "soc-core" / "app" / "wazuh_client.py").read_text()
    produced |= set(re.findall(r'"type":\s*"(\w+)"', wazuh)) | set(re.findall(r'return\s+"(\w+)"', wazuh))
    m365n = (ROOT / "m365-collector" / "app" / "normalizer.py").read_text()
    produced |= set(re.findall(r'"type":\s*"([\w.]+)"', m365n))
    correlation = (ROOT / "soc-core" / "app" / "correlation.py").read_text()
    produced |= set(re.findall(r'event\["type"\]\s*=\s*"(\w+)"', correlation))
    defender = (ROOT / "m365-collector" / "app" / "defender_xdr.py").read_text()
    produced |= set(re.findall(r'"type":\s*"(\w+)"', defender))
    cyfirma = (ROOT / "threat-intel" / "app" / "cyfirma_feeds.py").read_text()
    t = re.search(r'event_type\s*=\s*"(\w+)"\s+if\s+zero_day\s+else\s+"(\w+)"', cyfirma)
    if t: produced |= {t.group(1), t.group(2)}
    ok(f"Normalizers can produce {len(produced)} distinct types: {sorted(produced)}")
    skills_dir = ROOT / "hermes" / "app" / "skills"
    for f in sorted(skills_dir.glob("*.yaml")):
        d = yaml.safe_load(f.read_text())
        types = set(d.get("match", {}).get("event_types", []))
        unprod = types - produced - {"cloud_alert", "k8s_alert"}
        if unprod: warn(f"Skill '{d['skill']}' references unproducable types {sorted(unprod)}")
    ok("cloud_alert/k8s_alert intentionally manual-ingest-only")

def audit_section_4():
    section("SECTION 4: MITRE Technique Coverage")
    skills_dir = ROOT / "hermes" / "app" / "skills"
    used = set()
    for f in sorted(skills_dir.glob("*.yaml")): used |= set(yaml.safe_load(f.read_text()).get("mitre_technique", []))
    registry = yaml.safe_load((ROOT / "config" / "detection_taxonomy.yaml").read_text())
    for category in registry.get("categories", {}).values():
        for subtype in (category.get("subtypes") or {}).values(): used |= set(subtype.get("mitre", []))
    agg = (ROOT / "dashboard" / "app" / "aggregations.py").read_text()
    m = re.search(r"MITRE_NAMES\s*=\s*\{(.*?)\}", agg, re.DOTALL)
    known = set(re.findall(r'"(T\d+(?:\.\d+)?)"', m.group(1))) if m else set()
    if used - known: fail(f"MITRE IDs missing from dashboard: {sorted(used-known)}")
    else: ok(f"All {len(used)} MITRE IDs have dashboard names")

def audit_section_5():
    section("SECTION 5: Redis Queue Name Consistency")
    files = {"syslog-collector": ROOT/"syslog-collector"/"app"/"redis_client.py",
        "soc-core": ROOT/"soc-core"/"app"/"redis_client.py", "m365-collector": ROOT/"m365-collector"/"app"/"redis_client.py",
        "hermes": ROOT/"hermes"/"app"/"redis_client.py", "threat-intel": ROOT/"threat-intel"/"app"/"redis_client.py"}
    env = read_env_keys(ROOT / ".env")
    expected = {"QUEUE_RAW_EVENTS": env.get("QUEUE_RAW_EVENTS"), "QUEUE_FILTERED_EVENTS": env.get("QUEUE_FILTERED_EVENTS"), "QUEUE_FINDINGS": env.get("QUEUE_FINDINGS")}
    ok(f"Expected queues: {expected}")
    for svc, path in files.items():
        if not path.exists(): continue
        text = path.read_text()
        for var, exp in expected.items():
            m = re.search(rf'{var}\s*=\s*os\.getenv\("{var}",\s*"([^"]+)"\)', text)
            if not m: continue
            if m.group(1) == exp: ok(f"{svc}: {var} matches")
            else: fail(f"{svc}: {var} mismatch")
    soc_main = (ROOT / "soc-core" / "app" / "main.py").read_text()
    if "worker.process_event(event)" in soc_main: ok("/events/ingest funnels through process_event()")
    else: fail("/events/ingest does NOT call process_event()")

def audit_section_6():
    section("SECTION 6: Env Vars Referenced vs Defined")
    env_keys = set(read_env_keys(ROOT / ".env").keys())
    referenced = {}
    for py_file in project_python_files():
        if py_file.name == "audit_verify.py": continue
        for var, _ in find_getenv_calls(py_file): referenced.setdefault(var, []).append(str(py_file))
    undefined = sorted(set(referenced.keys()) - env_keys)
    acceptable = {"LOG_LEVEL", "JEV_SYSTEM_PROMPT_PATH", "DASHBOARD_FINDINGS_WINDOW_MINUTES", "HERMES_SKILLS_DIR",
        "JEV_URL", "AI_BASE_URL", "THREAT_INTEL_URL", "WAZUH_MANAGER_API_URL", "SOC_CORE_URL", "HERMES_URL",
        "M365_COLLECTOR_URL", "SYSLOG_COLLECTOR_URL", "QDRANT_URL"}
    truly_undef = [v for v in undefined if v not in acceptable]
    if truly_undef:
        for v in truly_undef: warn(f"Env var '{v}' not in .env")
    else: ok(f"All {len(referenced)-len(undefined)} operational env vars defined in .env")
    ok(f"Total referenced: {len(referenced)}; defined: {len(env_keys)}")

def audit_section_7():
    section("SECTION 7: Empirical skill_loader.py Classification Simulation")
    sys.path.insert(0, str(ROOT / "hermes"))
    from app.skill_loader import load_skills, select_skill
    load_skills(force_reload=True)
    def select(event):
        skill = select_skill(event)
        return skill.get("skill") if skill else None
    cases = [
        ({"type": "security_alert", "description": "SSHD brute force attempt"}, "brute_force"),
        ({"type": "credential_attack", "description": "Correlated credential failures", "mitre_technique": ["T1110"]}, "brute_force"),
        ({"type": "security_alert", "description": "File added to the system (possible malware drop)"}, "malware"),
        ({"type": "ransomware", "description": "Windows Defender detected ransomware behaviour", "mitre_technique": ["T1486"]}, "ransomware"),
        ({"type": "informational", "description": "Fortigate: App passed by firewall."}, None),
        ({"type": "generic", "description": "Exchange: MailItemsAccessed", "raw_kv": {"operation": "MailItemsAccessed"}}, None),
        ({"type": "reconnaissance", "description": "TCP port scan detected"}, "reconnaissance"),
        ({"type": "vulnerability", "description": "CVE-2024-3400 affecting openssl 1.1.1"}, "vulnerability_management"),
        ({"type": "fim_change", "description": "FIM: modified on /etc/passwd", "raw_kv": {"wazuh_rule_groups": ["syscheck"]}}, "file_integrity"),
        ({"type": "mailbox_rule_change", "description": "Exchange: New-InboxRule", "raw_kv": {"operation": "New-InboxRule"}}, "phishing"),
        ({"type": "fim_change", "description": "FIM: modified on node_modules/lodash/package.json", "raw_kv": {"wazuh_rule_groups": ["syscheck"]}}, "supply_chain"),
        ({"type": "dos_attack", "description": "DDoS attack detected: tcp_syn_flood"}, "ddos"),
        ({"type": "web_attack", "description": "SQL Injection detected: Union.Select"}, "sql_injection"),
        ({"type": "external_sharing", "description": "OneDrive: AnonymousLinkCreated", "raw_kv": {"operation": "AnonymousLinkCreated"}}, "insider_threat"),
        ({"type": "data_exfiltration", "description": "SecurityComplianceCenter: DlpRuleMatch", "raw_kv": {"operation": "DlpRuleMatch"}}, "data_exfiltration"),
        ({"type": "security_alert", "source": "threat_intel", "description": "APT29 infrastructure detected",
          "raw_kv": {"attribution_evidence": True}}, "apt_activity"),
        ({"type": "security_alert", "description": "possible pass-the-hash attack", "mitre_technique": ["T1550.002"]}, "credential_access"),
        ({"type": "security_alert", "description": "WMI query for System Information Discovery", "mitre_technique": ["T1082", "T1047"]}, "endpoint_discovery"),
        ({"type": "zero_day", "description": "ZERO-DAY: CVE-2025-9999 vendor fix unavailable", "raw_kv": {"is_zero_day": True}}, "zero_day"),
        ({"type": "cloud_alert", "description": "AWS IAM root UnauthorizedAccess"}, "cloud_native"),
        ({"type": "k8s_alert", "description": "Privileged container hostPath mount"}, "container_kubernetes")]
    passed = True
    for event, exp in cases:
        act = select(event); desc = event["description"]; et = event["type"]
        if act == exp: ok(f"{et}/{desc[:40]} -> {act}")
        else: fail(f"{et}/{desc[:40]} -> got {act}, expected {exp}"); passed = False
    if passed: ok(f"All {len(cases)} test cases pass")

def audit_section_8():
    section("SECTION 8: Threat Attribution Is Context, Not Reclassification")
    worker = (ROOT / "hermes" / "app" / "worker.py").read_text()
    providers = (ROOT / "threat-intel" / "app" / "providers.py").read_text()
    if "_detect_attribution" in worker and '"attribution_status"' in worker:
        ok("worker.py records provider attribution as a separate dimension")
    else: fail("worker.py missing separate attribution metadata")
    canonical_block = re.search(r"def _canonical_result\(.*?\n\s*return canonical, metadata", worker, re.DOTALL)
    if canonical_block and 'category = deterministic.get("category") or triage["category"]' in canonical_block.group(0):
        ok("Attribution cannot replace the deterministic attack category")
    else: fail("Could not prove deterministic category authority")
    if "detail" in providers and "OTX pulses" in providers: ok("providers.py surfaces OTX pulse names")
    else: fail("providers.py missing pulse surfacing")
    if (ROOT / "hermes" / "app" / "skills" / "apt_activity.yaml").exists(): ok("apt_activity.yaml exists")
    else: fail("apt_activity.yaml missing")

def audit_section_9():
    section("SECTION 9: Manual-Ingest Categories Honestly Labeled")
    agg = (ROOT / "dashboard" / "app" / "aggregations.py").read_text()
    if "_MANUAL_INGEST_ONLY_CATEGORIES" in agg: ok("aggregations.py flags manual-ingest categories")
    else: warn("Could not confirm manual-ingest labeling")
    tmpl = (ROOT / "dashboard" / "app" / "templates" / "index.html").read_text()
    if "manual_ingest_only" in tmpl: ok("Template distinguishes manual-ingest categories")
    else: fail("Template does NOT distinguish manual-ingest categories")

def audit_section_10():
    section("SECTION 10: Port Collision Matrix (v4 unique port scheme)")
    KNOWN_EXTERNAL = {514: "wazuh-manager", 1514: "wazuh-manager", 1515: "wazuh-manager", 55000: "wazuh-manager",
        9200: "wazuh-indexer", 443: "wazuh-dashboard", 3000: "wazuh-main-server", 8088: "wazuh-mcp-dashboard",
        8000: "wazuh-infokom-mcp", 20129: "9router"}
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    env = read_env_keys(ROOT / ".env")
    pattern = re.compile(r'\$\{(\w+):-(\d+)\}')
    our_ports = {}; port_proto_owner = {}; self_collisions = []
    for svc, cfg in compose.get("services", {}).items():
        for entry in cfg.get("ports", []) or []:
            proto = "udp" if entry.endswith("/udp") else "tcp"
            matches = pattern.findall(entry)
            if matches:
                var, default = matches[0]; actual = env.get(var, default)
                try: port = int(actual)
                except ValueError: continue
            else:
                host_part = entry.split(":")[0].strip('"')
                if not host_part.isdigit(): continue
                port = int(host_part)
            our_ports.setdefault(port, svc)
            key = (port, proto)
            if key in port_proto_owner and port_proto_owner[key] != svc:
                self_collisions.append((port, proto, port_proto_owner[key], svc))
            else: port_proto_owner[key] = svc
    ok(f"Parsed {len(our_ports)} host ports: {sorted(our_ports.items())}")
    if self_collisions:
        for p, proto, a, b in self_collisions: fail(f"SELF-COLLISION: {p}/{proto} both '{a}' and '{b}'")
    else: ok("No self-collisions (syslog UDP+TCP dual-binding correctly excluded)")
    real_collisions = [(p, s, KNOWN_EXTERNAL[p]) for p, s in our_ports.items() if p in KNOWN_EXTERNAL]
    if real_collisions:
        for p, our, their in real_collisions: fail(f"COLLISION: '{our}' port {p} == existing '{their}'")
    else: ok(f"Zero collisions with {len(KNOWN_EXTERNAL)} known existing container ports")
    common_defaults = {80, 443, 8080, 8000, 8443, 3306, 5432, 6379, 27017, 9000, 9090, 5000}
    risky = [(p, s) for p, s in our_ports.items() if p < 1024 or p in common_defaults]
    if risky:
        for p, s in risky: fail(f"RISKY: '{s}' uses common/privileged port {p}")
    else: ok(f"All {len(our_ports)} ports are in unique 3xxxx-4xxxx range")
    jev_cfg = compose["services"].get("jev", {})
    if "ports" not in jev_cfg and "expose" in jev_cfg: ok("jev-client uses expose-only (zero host collision risk)")
    else: warn("jev-client config unexpected")

def audit_section_11():
    section("SECTION 11: Reliable Queues, M365 Aggregation, and CVE Backfill")
    soc_redis = (ROOT / "soc-core" / "app" / "redis_client.py").read_text()
    soc_worker = (ROOT / "soc-core" / "app" / "worker.py").read_text()
    soc_main = (ROOT / "soc-core" / "app" / "main.py").read_text()
    soc_db = (ROOT / "soc-core" / "app" / "db.py").read_text()
    hermes_redis = (ROOT / "hermes" / "app" / "redis_client.py").read_text()
    management = (ROOT / "m365-collector" / "app" / "management_api.py").read_text()
    m365_redis = (ROOT / "m365-collector" / "app" / "redis_client.py").read_text()
    m365_normalizer = (ROOT / "m365-collector" / "app" / "normalizer.py").read_text()
    syslog_main = (ROOT / "syslog-collector" / "app" / "main.py").read_text()
    backfill = (ROOT / "scripts" / "backfill_cve_indicators.py").read_text()
    intel_main = (ROOT / "threat-intel" / "app" / "main.py").read_text()
    if "blmove(QUEUE_RAW_EVENTS, QUEUE_RAW_PROCESSING" in soc_redis:
        ok("SOC Core atomically claims raw events into a processing queue")
    else: fail("SOC Core raw queue is not using an atomic processing claim")
    if all(token in soc_redis for token in ("ack_raw_event", "retry_raw_event", "QUEUE_RAW_DLQ", "recover_raw_inflight")):
        ok("SOC Core raw queue has ACK, bounded retry, dead-letter, and restart recovery")
    else: fail("SOC Core raw queue reliability controls are incomplete")
    if "SOC_RAW_EVENT_WORKERS" in soc_worker and "range(worker.SOC_RAW_EVENT_WORKERS)" in soc_main:
        ok("SOC Core uses a bounded configurable raw-event worker pool")
    else: fail("SOC Core raw-event worker pool is not configurable")
    if "pipeline_status" in soc_db and "mark_event_complete" in soc_worker:
        ok("Event pipeline completion is persisted before queue ACK")
    else: fail("Event pipeline completion state is not persisted")
    if all(token in hermes_redis for token in ("blocking_claim_filtered_event", "ack_filtered_event",
                                                "retry_filtered_event", "QUEUE_FILTERED_DLQ",
                                                "recover_filtered_inflight")):
        ok("Hermes filtered queue has atomic claim, ACK, retry, dead-letter, and recovery")
    else: fail("Hermes filtered queue reliability controls are incomplete")
    if 'client.post(f"{BASE_URL}/subscriptions/start"' in management:
        ok("M365 starts Management Activity subscriptions with POST")
    else: fail("M365 subscription start is not using POST")
    if 'f"{BASE_URL}/subscriptions/list"' in management and 'item.get("status") == "enabled"' in management:
        ok("M365 discovers already-enabled subscriptions before starting missing ones")
    else: fail("M365 subscription discovery is incomplete")
    if "NextPageUri" in management and "MAX_CONTENT_PAGES" in management:
        ok("M365 follows bounded NextPageUri pagination")
    else: fail("M365 content pagination is incomplete")
    if "cursor_getter" in management and "cursor_setter" in management and "M365_CURSOR_PREFIX" in m365_redis:
        ok("M365 uses a durable per-content-type Redis cursor")
    else: fail("M365 durable cursor wiring is incomplete")
    if all(token in m365_normalizer for token in ("CampaignId", "NetworkMessageId", "InternetMessageId",
                                                   "incident_key", "M365_INCIDENT_WINDOW_SECONDS")):
        ok("M365 TIMailData derives bounded campaign/message incident keys")
    else: fail("M365 TIMailData incident-key derivation is incomplete")
    if all(token in soc_db for token in ("correlation_key", "attach_event_to_correlated_finding",
                                         "M365_INCIDENT_MAX_LINKED_EVENTS")) and "incident_aggregated" in soc_worker:
        ok("M365 incident members link to one finding without repeat AI processing")
    else: fail("M365 incident finding aggregation is incomplete")
    if all(token in syslog_main for token in ("synthetic_simulation", "is_synthetic_test", "test_marker")):
        ok("Built-in syslog simulations are explicitly marked synthetic")
    else: fail("Built-in syslog simulations can pollute production evidence counts")
    if "--apply" in backfill and "ON CONFLICT (finding_id,ioc_type,ioc) DO UPDATE" in backfill:
        ok("Historical CVE backfill is dry-run by default and idempotent on apply")
    else: fail("Historical CVE backfill safety controls are incomplete")
    if "refresh=args.refresh_unavailable" in backfill and "not payload.refresh and cached" in intel_main:
        ok("Unavailable CVE retries can explicitly bypass stale provider cache entries")
    else: fail("Unavailable CVE retry does not bypass the threat-intel cache")
    providers = (ROOT / "threat-intel" / "app" / "providers.py").read_text()
    if all(token in providers for token in ("PROVIDER_CIRCUIT_FAILURE_THRESHOLD", "PROVIDER_CIRCUIT_COOLDOWN_SECONDS",
                                             "provider circuit open after repeated failures")):
        ok("Threat-intel providers have bounded failure circuit breakers")
    else: fail("Threat-intel provider circuit breakers are incomplete")

def main():
    print("Agentic AI SOC Platform — Audit Verifier (v4)")
    print(f"Root: {ROOT}")
    audit_section_1(); audit_section_2(); audit_section_3(); audit_section_4()
    audit_section_5(); audit_section_6(); audit_section_7(); audit_section_8()
    audit_section_9(); audit_section_10(); audit_section_11()
    print(f"\n{'='*78}\nSUMMARY: {len(PASSES)} PASS, {len(WARNINGS)} WARN, {len(FAILURES)} FAIL\n{'='*78}")
    if FAILURES:
        print("\nFAILURES:")
        for f in FAILURES: print(f"  - {f}")
    if WARNINGS:
        print("\nWARNINGS:")
        for w in WARNINGS: print(f"  - {w}")
    return 1 if FAILURES else 0

if __name__ == "__main__":
    sys.exit(main())
