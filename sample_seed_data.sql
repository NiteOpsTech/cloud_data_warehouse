USE DATABASE SECURITY_OPS_DB;
USE SCHEMA TELEMETRY_INGESTION;

INSERT INTO RAW_FIREWALL_LOGS (
    device_hostname,
    vlan_source,
    source_ip,
    destination_ip,
    target_port,
    action_taken,
    payload_bytes,
    severity_level,
    incident_id
) VALUES
    ('core-fw-01', 30, '10.10.30.51', '185.220.101.5', 4444, 'ALERT_DROP', 2048, 'CRITICAL', 'INC-2026-003'),
    ('core-fw-01', 30, '10.10.30.52', '10.10.10.10', 22, 'ALERT_DROP', 512, 'HIGH', 'INC-2026-005'),
    ('core-fw-01', 20, '10.10.20.42', '142.250.190.46', 443, 'ALLOW', 1048576, NULL, NULL);

INSERT INTO KNOWN_MALICIOUS_IPS (
    indicator_ip,
    threat_actor,
    confidence_score,
    last_updated
) VALUES
    ('185.220.101.5', 'Synthetic C2 Lab Indicator', 95, CURRENT_TIMESTAMP());

INSERT INTO DETECTION_RESULTS (
    incident_id,
    detection_name,
    severity_level,
    analyst_summary
) VALUES
    (
        'INC-2026-003',
        'Potential Reverse Shell Callout',
        'CRITICAL',
        'Synthetic lab event matched blocked egress to a known C2-like destination.'
    ),
    (
        'INC-2026-005',
        'Potential SSH Lateral Movement',
        'HIGH',
        'Synthetic lab event matched blocked SSH pivot behavior from an IoT VLAN.'
    );
