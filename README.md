# Cloud Data Warehouse

Snowflake-style analytics layer for the NiteOpsTech / NanoMesh lab chain.

## Purpose

This repository models how normalized firewall and detection telemetry can be
stored for later threat-hunting queries, severity rollups, and portfolio-ready
analytics.

It is SQL-only and uses synthetic sample data. No Snowflake credentials or cloud
secrets belong in this repository.

## Files

- `snowflake_schema.sql`: database, schema, and table definitions
- `sample_seed_data.sql`: synthetic lab records for local review
- `threat_analytics.sql`: analytical queries for threat correlation and reporting

## NanoMesh Role

This is Level 8 in the NanoMesh support chain:

```text
ETL incident payloads
-> warehouse tables
-> threat analytics SQL
-> report/dashboard layer
-> autonomous defense matrix evidence
```

## Analytical Coverage

Current query examples:

- high-confidence malicious IP correlation
- outbound volume/exfiltration-style rollups
- incident severity summary
- detection coverage by rule name

## Safety Boundary

- Synthetic lab data only
- No credentials
- No production logs
- No automatic cloud provisioning
- No real threat-intelligence feed keys
