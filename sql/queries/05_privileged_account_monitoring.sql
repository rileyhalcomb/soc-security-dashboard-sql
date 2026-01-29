-- =====================================================
-- QUERY 5: PRIVILEGED ACCOUNT MONITORING
-- =====================================================
-- PURPOSE: Complete audit trail of ALL activity by admin/privileged accounts
-- ATTACK PATTERN: Not attack detection - this is baseline monitoring for high-risk accounts
-- MITRE ATT&CK: T1078.002 (Valid Accounts: Domain Accounts with elevated privileges)
-- THRESHOLD: ALL activity (no filtering - we want to see everything)
-- PRIORITY: CONTINOUS MONITORING (any anomaly in admin behavior is suspicious)
-- =====================================================

-- COMMENTED OUT IS PAST 24HRS
select
	u.username,																-- WHICH admin account
	u.department,															-- WHICH team (IT, Security, etc.)
	h.hostname,																-- WHAT system they accessed
	h.asset_criticality,													-- How IMPORTANT is that system
	e.event_type,															-- WHAT did they do (login, logout, etc.)
	e.success,																-- Did it work
	e.event_timestamp,														-- WHEN did this happen
	e.source_ip																-- WHERE did they connect FROM
from fact_auth_events e
join dim_users u on e.user_id = u.user_id 
left join dim_hosts h on e.dest_host_id = h.host_id							-- LEFT JOIN: keeps events with no host
where
	u.is_privileged = true													-- ONLY privileged accounts
	and e.event_timestamp >= '2025-01-01'
--	and e.event_timestamp > CURRENT_TIMESTAMP - interval '24 hours'
order by e.event_timestamp desc;											-- Most RECENT first

-- Expected Results:
-- Complete audit trail of admin activity
-- Review for: unusual times, unusual sources, unusual targets
-- Action: Verify all admin actions are authorized

-- ============================================
-- PLAIN ENGLISH EXPLANATION
-- ============================================
-- "Show me every single thing that admin accounts have done - successful logins,
--  failed logins, logouts, everything - so I can see if anything looks abnormal."

-- ============================================
-- WHY THIS MATTERS (Security Impact)
-- ============================================
-- Privileged accounts are the nuclear codes of IT infrastructure:
--   - Can create/delete users, change passwords, access any system
--   - If compromised, attacker has "keys to the kingdom"
--   - Should have minimal, well-documented activity
-- This query establishes baseline behavior so analysts can spot anomalies:
--   - Admin logging in at 3 AM? (Unusual)
--   - Admin accessing systems they normally don't touch? (Lateral movement)
--   - Admin failed login from external IP? (Compromise attempt)
--   - Admin activity on weekend? (Check if scheduled maintenance or suspicious)
-- Unlike other queries that find specific attacks, this finds "anything weird"

-- ============================================
-- SQL CONCEPTS USED
-- ============================================
-- LEFT JOIN                - Includes all events even if host_id is NULL
-- Simple filtering         - Just is_privileged = TRUE (no complex logic needed)
-- Complete audit trail     - No HAVING, no aggregation - shows individual events
-- Chronological ordering   - DESC = newest first (most recent activity matters most)

-- ============================================
-- WHY NO AGGREGATION?
-- ============================================
-- Unlike other queries that GROUP BY and COUNT, this shows RAW EVENTS because:
--   1. Need forensic detail: "Admin logged in at 2:34 AM" not "Admin logged in 3 times"
--   2. Sequence matters: Login → Access DB → Logout tells a story, aggregation loses it
--   3. Anomalies are specific: "Why did admin access server X?" not "How many logins?"
-- Think of this as "admin activity log" not "admin statistics"

-- ============================================
-- INTERVIEW QUESTIONS YOU CAN ANSWER
-- ============================================
-- Q: "Why LEFT JOIN for hosts instead of INNER JOIN?"
-- A: "LEFT JOIN keeps events even if dest_host_id is NULL. This matters for privileged
--     accounts because I want to see ALL their activity - even VPN logins where we
--     might not record the destination host. INNER JOIN would hide those events,
--     creating blind spots in my audit trail. For admin monitoring, completeness
--     trumps cleanliness."
--
-- Q: "This returns a lot of rows - isn't that inefficient?"
-- A: "For ad-hoc investigation, yes it's verbose. But for monitoring, this feeds into
--     a SIEM or log management system that can:
--     - Store it for compliance (SOX, PCI-DSS require admin activity logs)
--     - Alert on anomalies (ML baseline: 'admin usually logs in at 9 AM, not 3 AM')
--     - Forensics after breach ('What did the compromised admin account access?')
--     In production, I'd add LIMIT 1000 for manual review, but unlimited for automated
--     ingestion into security tools."
--
-- Q: "What patterns would you look for in this data?"
-- A: "Five key anomalies:
--     1. Off-hours activity (nights/weekends when IT staff isn't on duty)
--     2. Failed logins (admins shouldn't forget passwords - could be attacker)
--     3. External IPs (admins should use VPN, not public internet)
--     4. Unusual destinations (why is helpdesk admin accessing database server?)
--     5. Rapid succession (login → 50 systems in 5 minutes = automated attack tool)"
--
-- Q: "How does this help detect compromised admin accounts?"
-- A: "By establishing normal behavior baseline. Example: 'jdoe-admin' normally:
--     - Logs in Mon-Fri 8 AM - 5 PM
--     - Accesses 3-5 servers (Active Directory, Exchange, file server)
--     - From office IP 10.10.1.x
--     If suddenly jdoe-admin logs in at 2 AM Saturday from Russia and accesses
--     database server they've never touched, this query shows it immediately.
--     The 'unusual' only stands out against the 'usual' - that's the value."

-- ============================================
-- IMPROVEMENTS FOR PRODUCTION
-- ============================================
-- 1. Geo-location: Add country/city from source_ip for impossible travel detection
-- 2. Session duration: Calculate time between login and logout (unusually long = suspicious)
-- 3. Command logging: If available, show what commands admin ran (not just that they logged in)
-- 4. Risk scoring: Flag high-risk combinations (external IP + off-hours + CRITICAL asset = alert)
-- 5. Peer comparison: "jdoe-admin accessed 15 servers today, other admins average 3 - investigate"

-- ============================================
-- COMPLIANCE USE CASE
-- ============================================
-- Many regulations REQUIRE privileged account monitoring:
--   - PCI-DSS 10.2: Log all admin access to cardholder data
--   - HIPAA: Track who accessed patient records
--   - SOX: Audit financial system administrators
--   - NIST 800-53: Monitor privileged user activity
-- This query provides the audit trail auditors demand in security assessments.

-- ============================================
-- SAMPLE OUTPUT
-- ============================================
-- username    | department  | hostname          | asset_criticality | event_type   | success | event_timestamp     | source_ip
-- ------------|-------------|-------------------|-------------------|--------------|---------|---------------------|----------------
-- admin       | IT Security | webserver-prod-01 | HIGH              | login        | true    | 2025-01-20 14:31:00 | 185.220.101.47
-- admin       | IT Security | webserver-prod-01 | HIGH              | failed_login | false   | 2025-01-20 14:30:45 | 185.220.101.47
-- admin       | IT Security | webserver-prod-01 | HIGH              | failed_login | false   | 2025-01-20 14:30:30 | 185.220.101.47
-- admin       | IT Security | webserver-prod-01 | HIGH              | failed_login | false   | 2025-01-20 14:30:15 | 185.220.101.47
-- admin       | IT Security | webserver-prod-01 | HIGH              | failed_login | false   | 2025-01-20 14:30:00 | 185.220.101.47
-- jdoe-admin  | IT Security | database-prod-01  | CRITICAL          | logout       | true    | 2025-01-20 11:45:00 | 10.0.1.100
-- jdoe-admin  | IT Security | database-prod-01  | CRITICAL          | login        | true    | 2025-01-20 10:00:00 | 10.0.1.100
-- svc-backup  | IT Ops      | fileserver-corp   | MEDIUM            | logout       | true    | 2025-01-20 02:30:00 | 10.10.5.20
-- svc-backup  | IT Ops      | fileserver-corp   | MEDIUM            | login        | true    | 2025-01-20 02:05:00 | 10.10.5.20
-- svc-backup  | IT Ops      | database-prod-01  | CRITICAL          | login        | true    | 2025-01-20 02:00:00 | 10.10.5.20

-- ANOMALY SPOTTED: admin account has 4 failed logins then success from Russian IP!
-- NORMAL PATTERN: jdoe-admin doing scheduled maintenance (login → work → logout)
-- EXPECTED AUTOMATION: svc-backup nightly backup routine (consistent timing)
