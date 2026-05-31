-- 1. Establish the isolated Security Analytics Virtual Environment
CREATE DATABASE IF NOT EXISTS SECURITY_OPS_DB;
USE DATABASE SECURITY_OPS_DB;

CREATE SCHEMA IF NOT EXISTS TELEMETRY_INGESTION;
USE SCHEMA TELEMETRY_INGESTION;

-- 2. Construct the centralized raw security event logs table
CREATE TABLE IF NOT EXISTS RAW_FIREWALL_LOGS (
    event_id        VARCHAR(64) DEFAULT UUID_STRING(),
    ingest_time     TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    device_hostname VARCHAR(128),
    vlan_source     NUMBER,
    source_ip       VARCHAR(45),
    destination_ip  VARCHAR(45),
    target_port     NUMBER,
    action_taken    VARCHAR(32),
    payload_bytes   NUMBER
);

-- 3. Construct an optimized Threat Intelligence Reference table
CREATE TABLE IF NOT EXISTS KNOWN_MALICIOUS_IPS (
    indicator_ip    VARCHAR(45) PRIMARY KEY,
    threat_actor    VARCHAR(128),
    confidence_score NUMBER,
    last_updated    TIMESTAMP_NTZ
);
