USE DATABASE SECURITY_OPS_DB;
USE SCHEMA TELEMETRY_INGESTION;

-- =====================================================================
-- ANALYTICAL QUERY 01: High-Confidence Threat Feed Correlations
-- Cross-references firewall egress drops with active threat intelligence
-- =====================================================================
SELECT 
    f.event_id,
    f.ingest_time,
    f.vlan_source,
    f.source_ip,
    f.destination_ip,
    f.target_port,
    t.threat_actor,
    t.confidence_score
FROM RAW_FIREWALL_LOGS f
INNER JOIN KNOWN_MALICIOUS_IPS t 
    ON f.destination_ip = t.indicator_ip
WHERE f.action_taken = 'ALERT_DROP'
  AND t.confidence_score >= 80
ORDER BY t.confidence_score DESC;

-- =====================================================================
-- ANALYTICAL QUERY 02: Exfiltration Outbound Volume Metrics
-- Aggregates data transfer spikes per internal host targeting external IPs
-- =====================================================================
SELECT 
    source_ip,
    destination_ip,
    COUNT(event_id) AS total_connection_attempts,
    SUM(payload_bytes) / (1024 * 1024) AS total_data_exchanged_mb
FROM RAW_FIREWALL_LOGS
WHERE action_taken = 'ALLOW'
  AND destination_ip NOT LIKE '10.%' -- Focus strictly on outbound internet traffic
GROUP BY source_ip, destination_ip
HAVING total_data_exchanged_mb > 500 -- Flag connections shifting massive payloads
ORDER BY total_data_exchanged_mb DESC;

-- =====================================================================
-- ANALYTICAL QUERY 03: NanoMesh Incident Severity Rollup
-- Summarizes incident counts by severity for report-ready dashboards.
-- =====================================================================
SELECT
    severity_level,
    COUNT(*) AS incident_count,
    MIN(ingest_time) AS first_seen,
    MAX(ingest_time) AS last_seen
FROM RAW_FIREWALL_LOGS
WHERE incident_id IS NOT NULL
GROUP BY severity_level
ORDER BY incident_count DESC;

-- =====================================================================
-- ANALYTICAL QUERY 04: Detection Coverage by Rule Name
-- Shows which detection rules are producing analyst-reviewed findings.
-- =====================================================================
SELECT
    detection_name,
    severity_level,
    COUNT(*) AS matched_events,
    MAX(matched_at) AS latest_match
FROM DETECTION_RESULTS
GROUP BY detection_name, severity_level
ORDER BY matched_events DESC;
