-- =====================================================
-- CYSA+ THREAT HUNTING QUERIES
-- Security Data Warehouse - Authentication Analysis
--
-- Author: Riley Halcomb
-- Date: January 21, 2026
-- Purpose: Detect common attack patterns in authentication logs.
--
-- CySA+ Domains Covered:
-- - Domain 2: Security Operations and Monitoring
-- - Domain 3: Threat Intelligence and Incident Response
-- =====================================================

-- =====================================================
-- QUERY 1: BRUTE FORCE DETECTION
-- =====================================================
-- Description: Detects multiple failed login attempts
-- 				against a single account from same source IP
-- Attack Pattern: Attacker tries many passwords for one username
-- CySA+ Objective: 2.3 - Analyze data to identify security events
-- Threshold: 3+ failed attempts from same IP to same user
-- =====================================================

-- COMMENTED OUT IS PAST 24HRS
select 
	u.username,
	u.department,
	u.is_privileged,
	COUNT(*) as failed_attempts,
	e.source_ip,
	MIN(e.event_timestamp) as first_attempt,
	MAX(e.event_timestamp) as last_attempt
from fact_auth_events e
join dim_users u on e.user_id = u.user_id 
where
	e.success = false
--	and e.event_timestamp > CURRENT_TIMESTAMP - interval '24 hours'
	and e.event_timestamp >= '2025-01-01'
group by u.username, u.department, u.is_privileged, e.source_ip
having COUNT(*) >= 3
order by failed_attempts desc;

-- Expected Results:
-- Shows accounts under brute force attack
-- Prioritize: is_privileged = TRUE (admin accounts)
-- Action: Block source_ip, alert security team



-- =====================================================
-- QUERY 2: SUCCESSFULL LOGIN AFTER FAILED ATTEMPTS
-- =====================================================
-- Description: Finds successful logins that occurred after
--				multiple failures from the same IP
-- Attack Pattern: Brute force that succeeded
-- CySA+ Objective: 3.1 - Utilitze threat intelligence
-- Risk Level: CRITICAL - Potential account compromise
-- =====================================================

with failed_logins as (
	select 
		user_id,
		source_ip,
		COUNT(*) as failure_count,
		MAX(event_timestamp) as last_failure
	from fact_auth_events
	where success = false
	group by user_id, source_ip
	having COUNT(*) >= 3
)
select 
	u.username,
	u.department,
	u.is_privileged,
	fl.failure_count,
	fl.last_failure,
	e.event_timestamp as successful_login_time,
	e.source_ip,
	h.hostname as target_host,
	h.asset_criticality
from failed_logins fl
join fact_auth_events e on
	fl.user_id = e.user_id
	and e.event_timestamp > fl.last_failure
	and e.success = true
join dim_users u on e.user_id = u.user_id
join dim_hosts h on e.dest_host_id = h.host_id
order by e.event_timestamp desc;

-- Expected Results:
-- Empty = Good (no successful compromises)
-- Rows returned = CRITICAL INCIDENT
-- Action: Immediate investigation, force password reset, review access logs



-- =====================================================
-- QUERY 3: ATTACKS ON HIGH-VALUE TARGETS
-- =====================================================
-- Description: Failed logins to critical/high priority servers
-- Attack Pattern: Targeted attacks on valuable assets
-- CySA+ Objective: 2.2 - Implement security monitoring
-- Priority: Focus SOC resources on critical infrastructure
-- =====================================================

-- ============================================
-- QUERY 3A: ATTACKS ON HIGH-VALUE TARGETS (DETAILED)
-- Shows per-user targeting
-- ============================================

-- COMMENTED OUT IS PAST 7 DAYS
select 
	h.hostname,
	h.asset_criticality,
	h.location,
	u.username,
	u.is_privileged,
	COUNT(*) as attack_attempts,
	COUNT(distinct e.source_ip) as unique_attackers,
	STRING_AGG(distinct e.source_ip::text, ', ') as attacker_ips
from fact_auth_events e
join dim_users u on e.user_id = u.user_id 
join dim_hosts h on e.dest_host_id = h.host_id
where 
	e.success = false
	and h.asset_criticality in ('CRITICAL', 'HIGH')
	and e.event_timestamp >= '2025-01-01'
--	and e.event_timestamp > CURRENT_TIMESTAMP - interval '7 days'
group by h.hostname, h.asset_criticality, h.location, u.username, u.is_privileged
order by h.asset_criticality desc, attack_attempts desc;

-- ============================================
-- QUERY 3B: ATTACKS ON HIGH-VALUE TARGETS (SUMMARY)
-- Rolled up by server
-- ============================================
SELECT 
    h.hostname,
    h.asset_criticality,
    COUNT(*) as total_attacks,
    COUNT(DISTINCT u.user_id) as users_targeted,
    COUNT(DISTINCT e.source_ip) as unique_attackers,
    STRING_AGG(DISTINCT e.source_ip::text, ', ') as attacker_ips
FROM fact_auth_events e
JOIN dim_users u ON e.user_id = u.user_id
JOIN dim_hosts h ON e.dest_host_id = h.host_id
WHERE 
    e.success = FALSE
    AND h.asset_criticality IN ('CRITICAL', 'HIGH')
    AND e.event_timestamp >= '2025-01-01'
GROUP BY h.hostname, h.asset_criticality
ORDER BY h.asset_criticality, total_attacks DESC;

-- Expected Results:
-- Shows which critical servers are under attack
-- Prioritize CRITICAL over HIGH
-- Action: Increase monitoring, apply additional controls



-- =====================================================
-- QUERY 4: PRIVILEGED ACCOUNT MONITORING
-- =====================================================
-- Description: All activity by privileged accounts
-- Attack Pattern: Monitoring admin account usage
-- CySA+ Objective: 2.1 - Security monitoring activities
-- Purpose: Baseline normal admin behavior, detect anomalies
-- =====================================================

-- COMMENTED OUT IS PAST 24HRS
select
	u.username,
	u.department,
	h.hostname,
	h.asset_criticality,
	e.event_type,
	e.success,
	e.event_timestamp,
	e.source_ip
from fact_auth_events e
join dim_users u on e.user_id = u.user_id 
join dim_hosts h on e.dest_host_id = h.host_id
where
	u.is_privileged = true
	and e.event_timestamp >= '2025-01-01'
--	and e.event_timestamp > CURRENT_TIMESTAMP - interval '24 hours'
order by e.event_timestamp desc;

-- Expected Results:
-- Complete audit trail of admin activity
-- Review for: unusual times, unusual sources, unusual targets
-- Action: Verify all admin actions are authorized



-- =====================================================
-- QUERY 5: EXTERNAL IP ADDRESS SUMMARY
-- =====================================================
-- Description: Summarize login attempts from non-internal IPs
-- Attack Pattern: External threat actors
-- CySA+ Objective: 3.2 - Analyze threat intelligence data
-- Network Content: 10.x.x.x = internal, everything else = external
-- =====================================================

-- COMMENTED OUT IS PAST 30 DAYS
select 
	e.source_ip,
	COUNT(*) as total_attempts,
	SUM(case when e.success = false then 1 else 0 end) as failed_attempts,
	SUM(case when e.success = true then 1 else 0 end) as successful_logins,
	COUNT(distinct u.user_id) as unique_users_targeted,
	COUNT(distinct h.host_id) as unique_hosts_targeted,
	MIN(e.event_timestamp) as first_seen,
	MAX(e.event_timestamp) as last_seen
from fact_auth_events e
join dim_users u on e.user_id = u.user_id 
join dim_hosts h on e.dest_host_id = h.host_id
where
	e.source_ip not between '10.0.0.0' and '10.255.255.255'	-- Exclude internal IPs
	and e.event_timestamp >= '2025-01-01'
--	and e.event_timestamp > CURRENT_TIMESTAMP - interval '30 days'
group by e.source_ip
order by total_attempts desc;

-- Expected Results:
-- Shows external IPs attacking your infrastructure
-- High failed_attempts + 0 successful = unsuccessful attack
-- Any successful_logins from external IP = INVESTIGATE
-- Action: Block IPs with high failed attempts
	
	

-- =====================================================
-- QUERY 6: ACCOUNT ACTIVITY SUMMARY 
-- =====================================================
-- Description: Overview of all user account activity
-- Purpose: Baseline normal behavior, spot anomalies
-- CySA+ Objective: 2.3 - Analyze data for security events
-- Use Case: Daily security report for management
-- =====================================================

-- COMMENTED OUT IS PAST 7 DAYS
select
	u.username,
	u.department,
	u.is_privileged,
	COUNT(*) as total_events,
	SUM(case when e.success = true then 1 else 0 end) as successful_logins,
	SUM(case when e.success = false then 1 else 0 end) as failed_logins,
	COUNT(distinct e.source_ip) as unique_source_ips,
	COUNT(distinct h.host_id) as unique_hosts_accessed,
	MIN(e.event_timestamp) as first_activity,
	MAX(e.event_timestamp) as last_activity
from fact_auth_events e
join dim_users u on e.user_id = u.user_id 
left join dim_hosts h on e.dest_host_id = h.host_id 
where e.event_timestamp >= '2025-01-01'
--where e.event_timestamp > CURRENT_TIMESTAMP - interval '7 days'
group by u.username, u.department, u.is_privileged
order by total_events desc;

-- ============================================
-- QUERY 6B: PASSWORD SPRAYING DETECTION
-- ============================================
SELECT 
    e.source_ip,
    COUNT(DISTINCT e.user_id) as unique_users_targeted,
    COUNT(*) as total_attempts,
    MIN(e.event_timestamp) as attack_start,
    MAX(e.event_timestamp) as attack_end,
    STRING_AGG(DISTINCT u.username, ', ' ORDER BY u.username) as targeted_accounts
FROM fact_auth_events e
JOIN dim_users u ON e.user_id = u.user_id
WHERE 
    e.success = FALSE
    AND e.event_timestamp >= '2025-01-01'
GROUP BY e.source_ip
HAVING COUNT(DISTINCT e.user_id) >= 5
ORDER BY unique_users_targeted DESC;

-- Expected Results:
-- Shows which accounts are most active
-- Red flags: High failed_logins, many unique_source_ips
-- Action: Investigate accounts with unusual patterns




