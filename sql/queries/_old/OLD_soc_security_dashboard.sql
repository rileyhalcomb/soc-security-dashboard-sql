-- ============================================
-- SECURITY OPERATIONS CENTER (SOC) DASHBOARD
-- Executive Summary - Security Data Warehouse
-- ============================================
-- Purpose: Single-query overview of all security events
-- Audience: SOC analysts, security managers, executives
-- Refresh: Run daily or on-demand
-- ============================================

-- ============================================
-- SECTION 1: OVERALL SECURITY METRICS
-- ============================================

select *
from (
	select
		'📊 OVERALL METRICS' as category,
		'Total Security Events' as metric,
		COUNT(*)::text as value,
		'' as details,
		'' as severity
	from fact_auth_events
	where event_timestamp >= '2025-01-01'
) total_security_events

union all 

select *
from (
	select 
		'📊 OVERALL METRICS',
		'Failed Login Attempts',
		COUNT(*)::text,
		ROUND(100.0 * COUNT(*) / (select COUNT(*) from fact_auth_events where event_timestamp >= '2025-01-01'), 1)::text || '%',	-- CREATES % FROM (FAILED LOGIN ATTEMPTS) / (TOTAL EVENTS)
		case when COUNT(*) > 10 then '⚠️' else '✅' end																				-- GIVES AN EMOJI BASED ON # OF EVENTS
	from fact_auth_events
	where success = false and event_timestamp >= '2025-01-01'
) failed_login_attempts

union all 

select *
from (
	select
		'📊 OVERALL METRICS',
		'Successful Logins',
		COUNT(*)::text,
		ROUND(100.0 * COUNT(*) / (select COUNT(*) from fact_auth_events where event_timestamp >= '2025-01-01'), 1)::text || '%',	-- CREATES % FROM (SUCCESSFUL LOGIN ATTEMPTS) / (TOTAL EVENTS)
		'✅'
	from fact_auth_events
	where success = true and event_timestamp >= '2025-01-01'
) successful_logins

union all

select * 
from (
	select
		'📊 OVERALL METRICS',
		'External Attack Sources',
		COUNT(distinct source_ip)::text,
		'Non-internal IPs',
		case when COUNT(distinct source_ip) > 3 then '🔴' else '🟡' end
	from fact_auth_events
	where source_ip not between '10.0.0.0' and '10.255.255.255'
	and event_timestamp >= '2025-01-01'
) external_attack_sources

union all

select *
from (
	select
		'📊 OVERALL METRICS',
		'Privileged Accounts Active',
		COUNT(distinct u.user_id)::text,
		STRING_AGG(distinct u.username, ', '),																						-- COMBINES USERNAMES IN THE DETAILS COLUMN WITH ,
		'🔐'
	from fact_auth_events e
	join dim_users u on e.user_id = u.user_id
	where u.is_privileged = true
	and e.event_timestamp >= '2025-01-01'
) privileged_accounts_active


union all
-- ============================================
-- SECTION 2: CRITICAL INCIDENTS
-- ============================================
select *
from (
	select 
		'🚨 CRITICAL INCIDENTS',
		'Successful Brute',
		COUNT(distinct e.user_id)::text,
		STRING_AGG(distinct u.username || ' from ' || e.source_ip::text, '; '),														-- COMBINING IN A STRING: DISTINCT USERNAMES, "USERNAME FROM {SOURCE_IP};"
		'🔴'
	from (																															-- CREATING NEW TEMP TABLE "FAILURES" >3 FROM SUBQUERY
		select user_id, source_ip
		from fact_auth_events
		where success = false and event_timestamp >= '2025-01-01'
		group by user_id, source_ip
		having COUNT(*) >= 3
	) failures
	join fact_auth_events e on
		failures.user_id = e.user_id
		and failures.source_ip = e.source_ip
		and e.success = true																										-- SEEING IF THERE WERE BOTH FAILURES (FROM "FAILURES" TABLE) AND SUCCESSES, SHOWING BRUTE FORCE ENTRY
		and e.event_timestamp >= '2025-01-01'
	join dim_users u on e.user_id = u.user_id
) successful_brute_force_attacks

union all

select *
from (
	select 
		'🚨 CRITICAL INCIDENTS',
		'Password Spraying Attacks Detected',
		COUNT(*)::text,
		STRING_AGG(source_ip::text || ' (' || user_count::text || ' users)', ', '),
		'🔴'
	from (
		select
			source_ip,
			COUNT(distinct user_id) as user_count
		from fact_auth_events 
		where success = false and event_timestamp >= '2025-01-01'
		group by source_ip
		having COUNT(distinct user_id) >= 5																							-- SEEING >5 USERS BEING ATTACKED BY THE SAME IP
	) spraying
) password_spraying_attacks_detected

-- =========================
-- FINAL DASHBOARD ORDERING
-- =========================
ORDER BY
CASE section
    WHEN 'OVERALL STATISTICS' THEN 1
    WHEN 'Failed Logins' THEN 2
    WHEN 'Successful Logins' THEN 3
    WHEN 'External Attacks (non-10.x.x.x)' THEN 4
    WHEN 'TOP ATTACKED USERS' THEN 5
    WHEN 'TOP ATTACKED HOSTS' THEN 6
    WHEN 'CRITICAL INCIDENTS' THEN 7
    WHEN 'Total Events' THEN 8
    ELSE 99
END,
count DESC;