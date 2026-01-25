# SOC Security Dashboard - SQL-Based Threat Detection

A Security Operations Center (SOC) dashboard built entirely in PostgreSQL to analyze authentication logs and surface actionable security insights using advanced SQL.

This project simulates how raw security events are transformed into executive-ready metrics, incident detection, threat actor profiling, and response recommendations in a real SOC or SIEM environment.

---

## Project Overview

This dashboard processes authentication events stored in a dimensional data warehouse and produces a single, unified security summary using SQL only - no BI tools or dashboards.

It is designed to mirror real SOC workflows, including:
- Monitoring authentication security
- Detecting common attack patterns
- Prioritizing high-risk users, assets, and source IPs
- Supporting security response decisions

---

## Data Model

**Fact Table**
- `fact_auth_events`
  - `event_timestamp`
  - `user_id`
  - `source_ip`
  - `dest_host_id`
  - `success`
 
**Dimension Tables**
- `dim_users`
  - `user_id`
  - `username`
  - `department`
  - `is_privileged`
- `dim_hosts`
  - `host_id`
  - `hostname`
  - `asset_criticality`

---

## Detection Logic

The dashboard implements multiple SOC-style detections using SQL:

- **Brute Force Compromise**
  - For >= 3 failed login attempts from the same source IP followed by a successful login

- **Password Spraying**
  - A single source IP targeting >= 5 distinct users with failed login attempts
 
- **Privileged Account Exposure**
  - Authentication activity involving privileged users

- **Critical Asset Targeting**
  - Failed authentication attempts against hosts marked as `CRITICAL`

---

## Dashboard Secitons

The query outputs an executive-style security dashboard with the following sections:

- Overall Security Metrics
- Critical Incidents
- Top Threats (Users, Servers, IPs)
- Attack Timeline
- Threat Actor Summary
- Security Recommendations

---

## Technical Highlights

- PostgreSQL
- Dimensional data modeling (fact & dimension tables)
- Advanced SQL techniques:
  - `UNION ALL` for dashboard contruction
  - Nested subqueries and derived tables
  - Conditional logic with `CASE`
  - Aggregations (`COUNT`, `SUM`, `STRING_AGG`)
  - Detection thresholds using `HAVING`
- Executive-friendly output formatting

---

## How to Run

1. Create the tables using the provided schema
2. Load authentication log data into `fact_auth_events`
3. Run `soc_dashboard.sql` in PostgreSQL
4. Review the unifed dashboard output

---

## Repository Structure

```text
.
├── sql/
│   ├── schema.sql                         -- NOT TESTED, MAY HAVE ERRORS
│   ├── sample_data.sql                    -- NOT TESTED, MAY HAVE ERRORS
│   └── executive_security_dashboard.sql
├── diagrams/
│   └── data_model.png       -- NOT YET ADDED
├── README.md
├── LICENSE
└── .gitignore
