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