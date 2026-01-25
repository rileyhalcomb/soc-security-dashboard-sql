-- =========================================
-- SOC Dashboard Database Schema
-- =========================================

-- =========================================
-- Users Dimension
-- =========================================
CREATE TABLE dim_users (
    user_id       SERIAL PRIMARY KEY,
    username      VARCHAR(50) NOT NULL,
    department    VARCHAR(50),
    is_privileged BOOLEAN DEFAULT FALSE
);

-- =========================================
-- Hosts Dimension
-- =========================================
CREATE TABLE dim_hosts (
    host_id           SERIAL PRIMARY KEY,
    hostname          VARCHAR(100) NOT NULL,
    asset_criticality VARCHAR(20) -- e.g., CRITICAL, HIGH, MEDIUM, LOW
);

-- =========================================
-- Authentication Events Fact Table
-- =========================================
CREATE TABLE fact_auth_events (
    event_id     SERIAL PRIMARY KEY,
    event_timestamp TIMESTAMP NOT NULL,
    user_id      INT NOT NULL REFERENCES dim_users(user_id),
    source_ip    INET NOT NULL,                -- PostgreSQL supports INET type for IPs
    dest_host_id INT NOT NULL REFERENCES dim_hosts(host_id),
    success      BOOLEAN NOT NULL
);

-- =========================================
-- Optional: Indexes for performance
-- =========================================
CREATE INDEX idx_auth_events_timestamp ON fact_auth_events(event_timestamp);
CREATE INDEX idx_auth_events_user ON fact_auth_events(user_id);
CREATE INDEX idx_auth_events_source_ip ON fact_auth_events(source_ip);
CREATE INDEX idx_auth_events_host ON fact_auth_events(dest_host_id);
