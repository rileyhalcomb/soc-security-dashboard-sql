-- =====================================================
-- QUERY 3: SUCCESSFULL LOGIN AFTER FAILED ATTEMPTS (SUCCESSFUL COMPROMISE DETECTION)
-- =====================================================
-- DESCRIPTION: Finds successful logins that occurred after
--				multiple failures from the same IP
-- ATTACK PATTERN: Multiple failures followed by successful login from same IP
-- MITRE ATT&CK: T1110 (Brute Force) + T1078 (Valid Accounts - compromised)
-- THRESHOLD: 3+ failures then 1 success
-- PRIORITY: CRITICAL (active breach in progress)
-- =====================================================

-- STEP 1: Find IPs w/ 3+ failed login attempts (potential brute force)
with failed_logins as (
	select 
		user_id,
		source_ip,
		COUNT(*) as failure_count,							-- How many failed attempts
		MAX(event_timestamp) as last_failure				-- When did they stop failing
	from fact_auth_events
	where success = false
	group by user_id, source_ip
	having COUNT(*) >= 3									-- Only 3+ attempts
)

-- STEP 2: Find successful logins from those same (user, IP) pairs AFTER the failure
select 
	u.username,												-- WHO was compromised
	u.department,											
	u.is_privileged,										-- Is this an admin account? (Critical!)
	fl.failure_count,										-- How many tries before success
	fl.last_failure,										-- When did attempts stop
	e.event_timestamp as successful_login_time,				-- When did they get in
	e.source_ip,											-- Attacker's IP
	h.hostname as target_host,								-- What system was accessed
	h.asset_criticality										-- How important is that system
from failed_logins fl
join fact_auth_events e on
	fl.user_id = e.user_id									-- Same user
	and fl.source_ip = e.source_ip							-- Same attacker IP
	and e.event_timestamp > fl.last_failure					-- Success came AFTER failures
	and e.success = true									-- And it was successful
join dim_users u on e.user_id = u.user_id
join dim_hosts h on e.dest_host_id = h.host_id
order by e.event_timestamp desc;

-- Expected Results:
-- Empty = Good (no successful compromises)
-- Rows returned = CRITICAL INCIDENT
-- Action: Immediate investigation, force password reset, review access logs

-- ============================================
-- PLAIN ENGLISH EXPLANATION
-- ============================================
-- "Find any IP that failed to login 3+ times, then successfully logged in
--  as that same user - this means the brute force attack worked and the
--  account is now compromised."

-- ============================================
-- WHY THIS MATTERS (Security Impact)
-- ============================================
-- This is the MOST CRITICAL query because it detects active breaches:
--   - Not just an attempt - the attacker is IN
--   - Immediate incident response required
--   - Could be ransomware staging, data exfiltration, or lateral movement prep
-- In a real SOC, this triggers:
--   1. Immediate password reset
--   2. Kill all sessions for that user
--   3. Review what the attacker accessed
--   4. Block the source IP at firewall

-- ============================================
-- SQL CONCEPTS USED
-- ============================================
-- CTE (Common Table Expression) - WITH clause creates temporary result set
-- Subquery logic                - Query builds on previous results
-- Multiple JOIN conditions      - Must match on user_id AND source_ip AND time
-- LEFT JOIN                     - Include events even if no host info (vs INNER JOIN)
-- Temporal logic                - e.event_timestamp > fl.last_failure

-- ============================================
-- INTERVIEW QUESTIONS YOU CAN ANSWER
-- ============================================
-- Q: "Why use a CTE instead of a subquery?"
-- A: "Readability and performance. The CTE makes it clear I'm doing this in two steps:
--     first find potential brute force attempts, then check if they succeeded. It's
--     also easier to debug - I can run just the CTE part to verify that logic works.
--     Some databases also optimize CTEs better than nested subqueries."
--
-- Q: "Why check e.event_timestamp > fl.last_failure?"
-- A: "Critical temporal logic. I only want successes that came AFTER the failures.
--     Without this check, I'd catch users who legitimately logged in yesterday, then
--     had a few typos today - that's not a compromise. The > ensures the success is
--     part of the same attack session."
--
-- Q: "What if the attacker logs in from a different IP after the brute force?"
-- A: "This query would miss that - it only catches same-IP compromises. In production,
--     I'd add a companion query: any successful login within 1 hour of 3+ failures
--     from ANY IP. Also cross-reference with geo-location - login from Russia then
--     USA 5 minutes later = impossible travel."
--
-- Q: "Why LEFT JOIN for hosts instead of INNER JOIN?"
-- A: "LEFT JOIN keeps the row even if dest_host_id is NULL (no host recorded). This
--     ensures I see ALL compromises. INNER JOIN would hide compromises where we
--     don't know which system they accessed - that's still critical data."

-- ============================================
-- IMPROVEMENTS FOR PRODUCTION
-- ============================================
-- 1. Alert severity: Auto-page security team if is_privileged = TRUE
-- 2. Session tracking: Show what the attacker did after getting in
-- 3. Impossible travel: Flag if login location changed drastically
-- 4. Auto-response: Trigger automated account lockout
-- 5. Forensics: Log all queries/commands run by compromised account

-- ============================================
-- SAMPLE OUTPUT
-- ============================================
-- username | department  | is_privileged | failure_count | last_failure        | successful_login_time | source_ip       | target_host       | asset_criticality
-- ---------|-------------|---------------|---------------|---------------------|----------------------|-----------------|-------------------|------------------
-- admin    | IT Security | true          | 4             | 2025-01-20 14:30:45 | 2025-01-20 14:31:00  | 185.220.101.47  | webserver-prod-01 | HIGH
-- dbaker   | Engineering | false         | 3             | 2025-01-20 16:32:00 | 2025-01-20 16:35:00  | 10.0.3.78       | laptop-schen      | LOW
