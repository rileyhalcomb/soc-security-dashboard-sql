-- =====================================================
-- TEMPORAL ANALYSIS QUERIES USING DIM_TIME
-- =====================================================
-- Purpose: Demonstrate how to use dim_time for attack pattern detection
-- =====================================================

-- =====================================================
-- QUERY 1: ATTACKS BY TIME OF DAY
-- =====================================================
-- Shows which hours have the most attacks
-- Helps identify "danger hours" (usually nights/weekends)

SELECT 
    t.hour,
    COUNT(*) AS attack_count,
    t.is_business_hours,
    t.risk_period,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS percent_of_total
FROM fact_auth_events e
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE e.success = FALSE
    AND e.event_timestamp >= '2025-01-01'
GROUP BY t.hour, t.is_business_hours, t.risk_period
ORDER BY attack_count DESC;

-- =====================================================
-- QUERY 2: BUSINESS HOURS VS OFF-HOURS ATTACKS
-- =====================================================
-- Compares attack volume during business hours vs after-hours
-- Off-hours attacks are more suspicious

SELECT 
    t.is_business_hours,
    COUNT(*) AS total_attacks,
    COUNT(DISTINCT e.source_ip) AS unique_attackers,
    COUNT(DISTINCT e.user_id) AS unique_targets,
    ROUND(AVG(CASE WHEN e.success THEN 1 ELSE 0 END) * 100, 1) AS success_rate_percent
FROM fact_auth_events e
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE e.event_timestamp >= '2025-01-01'
GROUP BY t.is_business_hours
ORDER BY t.is_business_hours DESC;

-- =====================================================
-- QUERY 3: WEEKEND VS WEEKDAY ATTACK PATTERNS
-- =====================================================
-- Detects if attackers prefer weekends (less monitoring)

SELECT 
    t.day_name,
    t.is_weekend,
    COUNT(*) AS event_count,
    SUM(CASE WHEN e.success = FALSE THEN 1 ELSE 0 END) AS failed_attempts,
    SUM(CASE WHEN e.success = TRUE THEN 1 ELSE 0 END) AS successful_logins
FROM fact_auth_events e
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE e.event_timestamp >= '2025-01-01'
GROUP BY t.day_name, t.is_weekend, t.day_of_week
ORDER BY t.day_of_week;

-- =====================================================
-- QUERY 4: HIGH-RISK TIME PERIOD ATTACKS
-- =====================================================
-- Flags attacks during high-risk periods (nights, weekends)
-- These are most likely to be malicious

SELECT 
    e.source_ip,
    u.username,
    t.risk_period,
    COUNT(*) AS attack_count,
    STRING_AGG(DISTINCT TO_CHAR(e.event_timestamp, 'Mon DD HH24:MI'), ', ' ORDER BY TO_CHAR(e.event_timestamp, 'Mon DD HH24:MI')) AS attack_times
FROM fact_auth_events e
JOIN dim_users u ON e.user_id = u.user_id
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE e.success = FALSE
    AND e.event_timestamp >= '2025-01-01'
    AND t.risk_period = 'HIGH_RISK'  -- Only high-risk periods
GROUP BY e.source_ip, u.username, t.risk_period
ORDER BY attack_count DESC;

-- =====================================================
-- QUERY 5: NIGHT SHIFT ANOMALY DETECTION
-- =====================================================
-- Finds non-IT users logging in during night shift
-- IT may have legitimate night work, but Finance at 3 AM is suspicious

SELECT 
    u.username,
    u.department,
    u.is_privileged,
    COUNT(*) AS night_logins,
    MIN(e.event_timestamp) AS first_night_login,
    MAX(e.event_timestamp) AS last_night_login
FROM fact_auth_events e
JOIN dim_users u ON e.user_id = u.user_id
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE t.is_night_shift = TRUE
    AND e.success = TRUE
    AND e.event_timestamp >= '2025-01-01'
    AND u.department NOT IN ('IT Security', 'IT Ops', 'IT Support')  -- Exclude IT
GROUP BY u.username, u.department, u.is_privileged
ORDER BY night_logins DESC;

-- =====================================================
-- QUERY 6: HOURLY ATTACK HEATMAP DATA
-- =====================================================
-- Generates data for a heatmap visualization
-- Shows attack intensity by hour and day of week

SELECT 
    t.day_name,
    t.hour,
    COUNT(*) AS attack_count,
    CASE 
        WHEN COUNT(*) >= 5 THEN 'CRITICAL'
        WHEN COUNT(*) >= 3 THEN 'HIGH'
        WHEN COUNT(*) >= 1 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS severity
FROM fact_auth_events e
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE e.success = FALSE
    AND e.event_timestamp >= '2025-01-01'
GROUP BY t.day_name, t.hour, t.day_of_week
ORDER BY t.day_of_week, t.hour;

-- =====================================================
-- QUERY 7: PRIVILEGED ACCOUNT OFF-HOURS ACTIVITY
-- =====================================================
-- Critical: Admin accounts active outside business hours
-- Could indicate compromised account or insider threat

SELECT 
    u.username,
    u.department,
    h.hostname,
    e.event_timestamp,
    t.day_name,
    t.hour,
    t.risk_period,
    e.source_ip,
    e.success
FROM fact_auth_events e
JOIN dim_users u ON e.user_id = u.user_id
LEFT JOIN dim_hosts h ON e.dest_host_id = h.host_id
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE u.is_privileged = TRUE
    AND t.is_business_hours = FALSE  -- Outside business hours
    AND e.event_timestamp >= '2025-01-01'
ORDER BY e.event_timestamp DESC;

-- =====================================================
-- PLAIN ENGLISH EXPLANATIONS
-- =====================================================

/*
QUERY 1: "Show me which hours of the day have the most attacks"
- Useful for: Identifying if attackers prefer certain times (e.g., 3 AM when SOC is understaffed)

QUERY 2: "Compare attacks during work hours vs after-hours"
- Useful for: Seeing if off-hours attacks have higher success rates

QUERY 3: "Do attacks happen more on weekends or weekdays?"
- Useful for: Detecting if attackers wait for weekends (less security staff)

QUERY 4: "Show me all attacks during high-risk time periods"
- Useful for: Prioritizing investigation of late-night/weekend attacks

QUERY 5: "Which non-IT users are logging in at night?"
- Useful for: Finding anomalous behavior (Finance user at 2 AM = suspicious)

QUERY 6: "Create a heatmap of attacks by day and hour"
- Useful for: Visualizing attack patterns over the week

QUERY 7: "Show admin account activity outside business hours"
- Useful for: Catching compromised admin accounts being used off-hours
*/

-- =====================================================
-- SAMPLE OUTPUT (Query 2)
-- =====================================================
-- is_business_hours | total_attacks | unique_attackers | unique_targets | success_rate_percent
-- ------------------|---------------|------------------|----------------|---------------------
-- true              | 15            | 3                | 8              | 40.0
-- false             | 37            | 5                | 10             | 48.6
--
-- INTERPRETATION: More attacks happen off-hours (37 vs 15) with higher success rate (48.6% vs 40%)
-- This suggests attackers prefer nights/weekends when security monitoring is reduced

SELECT '✅ Temporal analysis queries created!' AS status;