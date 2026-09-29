-- Idempotently link historical IP intelligence to existing findings.
-- This adds relationship rows only; events and findings are not rewritten.
WITH grouped AS (
    SELECT f.id AS finding_id, e.id AS event_id, host(e.src_ip) AS ioc,
           (bool_or(i.malicious AND i.provider IN ('threatfox','cyfirma','crowdsec','virustotal','abuseipdb')
                    AND i.score >= 0.8)
            OR count(*) FILTER (WHERE i.malicious AND i.score >= 0.2) >= 2) AS malicious,
           max(i.score) FILTER (WHERE i.malicious) AS confidence,
           count(*) FILTER (WHERE i.raw_response->>'mode' = 'live') AS live_count,
           count(*) FILTER (WHERE i.raw_response->>'mode' = 'unavailable') AS unavailable_count,
           jsonb_agg(i.raw_response ORDER BY i.provider) AS provider_results
    FROM findings f
    CROSS JOIN LATERAL unnest(f.event_ids) AS linked(event_id)
    JOIN events e ON e.id = linked.event_id
    JOIN intelligence i ON i.ioc_type = 'ip' AND i.ioc = host(e.src_ip)
    WHERE e.src_ip IS NOT NULL
    GROUP BY f.id, e.id, e.src_ip
)
INSERT INTO finding_indicators
    (finding_id,event_id,ioc,ioc_type,malicious,confidence,enrichment_status,verdict_reason,provider_results)
SELECT finding_id,event_id,ioc,'ip',malicious,
       CASE WHEN malicious THEN coalesce(confidence,0) ELSE 0 END,
       CASE WHEN live_count > 0 AND unavailable_count = 0 THEN 'complete'
            WHEN live_count > 0 THEN 'partial' ELSE 'unavailable' END,
       'historical_provider_records',provider_results
FROM grouped
ON CONFLICT (finding_id,ioc_type,ioc) DO NOTHING;
