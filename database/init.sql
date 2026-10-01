CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), external_id TEXT, source TEXT NOT NULL,
    type TEXT, severity TEXT NOT NULL DEFAULT 'low', src_ip INET, dst_ip INET,
    user_name TEXT, description TEXT, mitre_technique TEXT[], raw_hash TEXT NOT NULL,
    raw_payload JSONB, normalized JSONB NOT NULL, is_filtered_in BOOLEAN NOT NULL DEFAULT FALSE,
    pipeline_status TEXT NOT NULL DEFAULT 'complete',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_source ON events (source);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (type);
CREATE INDEX IF NOT EXISTS idx_events_pipeline_status ON events (pipeline_status) WHERE pipeline_status <> 'complete';
CREATE UNIQUE INDEX IF NOT EXISTS uq_events_source_external_id ON events (source, external_id) WHERE external_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_events_m365_raw_hash ON events (source, raw_hash) WHERE source IN ('m365_audit', 'm365_defender_xdr');
CREATE TABLE IF NOT EXISTS intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), ioc TEXT NOT NULL, ioc_type TEXT NOT NULL,
    provider TEXT NOT NULL, malicious BOOLEAN NOT NULL DEFAULT FALSE, score NUMERIC(4,3) NOT NULL DEFAULT 0.0,
    raw_response JSONB, checked_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (ioc, provider)
);
CREATE INDEX IF NOT EXISTS idx_intel_ioc ON intelligence (ioc);
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), event_ids UUID[] NOT NULL, category TEXT,
    threat_classification TEXT, mitre_technique TEXT[], confidence NUMERIC(4,3) NOT NULL DEFAULT 0.0,
    severity TEXT, evidence JSONB NOT NULL, ai_result JSONB NOT NULL, recommendation TEXT,
    status TEXT NOT NULL DEFAULT 'open', created_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    primary_event_id UUID, analysis_status TEXT NOT NULL DEFAULT 'complete',
    detection_rule TEXT, detection_source TEXT, updated_time TIMESTAMPTZ,
    attack_family TEXT, attack_subtype TEXT, taxonomy_version TEXT,
    classification_method TEXT, detection_rule_version INTEGER,
    evidence_quality TEXT, attribution_status TEXT NOT NULL DEFAULT 'none',
    ai_verdict TEXT, ai_reasoning_mode TEXT,
    correlation_key TEXT, correlation_scope TEXT,
    correlation_count INTEGER NOT NULL DEFAULT 1,
    first_seen TIMESTAMPTZ, last_seen TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings (category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings (created_time DESC);
CREATE INDEX IF NOT EXISTS idx_findings_subtype ON findings (attack_subtype);
CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_primary_event ON findings (primary_event_id) WHERE primary_event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_correlation_key ON findings (correlation_key) WHERE correlation_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS finding_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    event_id UUID REFERENCES events(id) ON DELETE SET NULL, ioc TEXT NOT NULL, ioc_type TEXT NOT NULL,
    malicious BOOLEAN NOT NULL DEFAULT FALSE, confidence NUMERIC(4,3) NOT NULL DEFAULT 0.0,
    enrichment_status TEXT NOT NULL DEFAULT 'unknown', verdict_reason TEXT,
    provider_results JSONB NOT NULL DEFAULT '[]'::jsonb, checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (finding_id, ioc_type, ioc)
);
CREATE INDEX IF NOT EXISTS idx_finding_indicators_finding ON finding_indicators (finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_indicators_ioc ON finding_indicators (ioc_type, ioc);
CREATE TABLE IF NOT EXISTS agent_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), agent_name TEXT NOT NULL,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE, input_payload JSONB,
    output_payload JSONB, duration_ms INTEGER, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_finding ON agent_runs (finding_id);
CREATE TABLE IF NOT EXISTS threat_research (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), provider TEXT NOT NULL DEFAULT 'cyfirma',
    title TEXT NOT NULL, url TEXT, summary TEXT, published_at TIMESTAMPTZ,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(), raw_payload JSONB, UNIQUE (provider, url)
);
CREATE INDEX IF NOT EXISTS idx_threat_research_fetched ON threat_research (fetched_at DESC);
CREATE TABLE IF NOT EXISTS cyfirma_org_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), cve TEXT, severity TEXT, title TEXT,
    description TEXT, is_zero_day BOOLEAN NOT NULL DEFAULT FALSE, detected_at TIMESTAMPTZ,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(), raw_payload JSONB, UNIQUE (cve, title)
);
CREATE INDEX IF NOT EXISTS idx_cyfirma_vuln_fetched ON cyfirma_org_vulnerabilities (fetched_at DESC);
