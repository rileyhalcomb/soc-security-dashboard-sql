-- =====================================================
-- QUERY 7: ACCOUNT ACTIVITY SUMMARY 
-- =====================================================
-- PURPOSE: Profile all user accounts based on their authentication behavior
-- ATTACK PATTERN: User behavior analytics (UEBA) - identify anomalous accounts
-- MITRE ATT&CK: T1078 (Valid Accounts - understanding normal vs compromised usage)
-- THRESHOLD: All users (no filtering - we want complete behavioral profile)
-- PRIORITY: Varies - flags unusual patterns for investigation 
-- =====================================================

-- COMMENTED OUT IS PAST 7 DAYS
select
	u.username,																		-- WHO is this user
	u.department,																	-- WHICH team do they belong to
	u.is_privileged,																-- Are they an admin (higher scrutiny)
	COUNT(*) as total_events,														-- HOW ACTIVE is this account
	SUM(case when e.success = true then 1 else 0 end) as successful_logins,
		-- HOW MANY successful logins
	SUM(case when e.success = false then 1 else 0 end) as failed_logins,
		-- HOW MANY failed attempts (high number = suspicious)
	COUNT(distinct e.source_ip) as unique_source_ips,
		-- HOW MANY different locations (high = travel or VPN, very high = compromised)
	COUNT(distinct h.host_id) as unique_hosts_accessed,
		-- HOW MANY different systems accessed (cross-system activity)
	MIN(e.event_timestamp) as first_activity,										-- WHEN did we first see this user
	MAX(e.event_timestamp) as last_activity											-- WHEN was their most recent activity
from fact_auth_events e
join dim_users u on e.user_id = u.user_id 
left join dim_hosts h on e.dest_host_id = h.host_id 
where e.event_timestamp >= '2025-01-01'
--where e.event_timestamp > CURRENT_TIMESTAMP - interval '7 days'
group by u.username, u.department, u.is_privileged
order by total_events desc;															-- Most active users first

-- Expected Results:
-- Shows which accounts are most active
-- Red flags: High failed_logins, many unique_source_ips
-- Action: Investigate accounts with unusual patterns

-- ============================================
-- PLAIN ENGLISH EXPLANATION
-- ============================================
-- "Show me every user account and summarize their behavior: how many times they
--  logged in (success/fail), from how many different IPs, to how many different
--  systems, and when we first/last saw them active."

-- ============================================
-- WHY THIS MATTERS (Security Impact)
-- ============================================
-- This query establishes "normal behavior" baselines for each user:
--   - Normal user: 5-20 logins/day, 1-2 IPs, 1-3 systems, 0-2 failed logins
--   - Service account: predictable pattern (same time daily, same systems)
--   - Compromised account: unusual spikes, many IPs, accessing new systems
--
-- Red flags this query surfaces:
--   1. High failed_logins → Account under attack or user forgot password
--   2. Many unique_source_ips → Impossible travel or credential sharing
--   3. Many unique_hosts_accessed → Lateral movement or reconnaissance
--   4. Sudden activity spike → Account takeover
--   5. first_activity = last_activity → Dormant account activated (why?)
--
-- Use cases:
--   - Insider threat detection: Finance user suddenly accessing engineering servers
--   - Compromised accounts: Normal user now logging in from 10 countries
--   - Dormant account abuse: Old account that hasn't logged in for months suddenly active
--   - Shared credentials: One account logging in from 5 IPs simultaneously

-- ============================================
-- SQL CONCEPTS USED
-- ============================================
-- Multiple conditional aggregations - SUM(CASE) for success vs failure counts
-- Multiple COUNT(DISTINCT)           - Unique IPs and unique hosts
-- LEFT JOIN                           - Include users even if no host recorded
-- Comprehensive GROUP BY              - By user, department, privilege level
-- Simple ORDER BY                     - Most active users first

-- ============================================
-- INTERVIEW QUESTIONS YOU CAN ANSWER
-- ============================================
-- Q: "What's the difference between this query and the privileged account monitoring query?"
-- A: "Privileged account monitoring shows INDIVIDUAL EVENTS (raw log detail) for
--     admins. This shows AGGREGATE STATISTICS for ALL users. It's the difference
--     between 'admin logged in at 2:34 AM to server X' vs 'admin had 45 total logins,
--     from 3 IPs, to 5 systems'. Different use cases: privileged monitoring = forensic
--     detail, this = behavioral profiling."
--
-- Q: "Why count unique_source_ips?"
-- A: "Detects impossible travel and credential sharing. Example:
--     - User logs in from New York (IP 1.2.3.4) at 9 AM
--     - Same user logs in from Tokyo (IP 5.6.7.8) at 9:05 AM
--     That's physically impossible → account is compromised and being used by attacker.
--     Or if unique_source_ips = 10 for a regular employee, they're either traveling
--     constantly (rare) or sharing credentials (policy violation) or compromised."
--
-- Q: "What does unique_hosts_accessed tell you?"
-- A: "Normal users access predictable systems:
--     - Finance: login to laptop, access fileserver, occasionally VPN
--     - IT: access many servers (normal for their role)
--     If Finance user suddenly accesses database server, engineering systems, domain
--     controller → that's lateral movement after compromise. The 'unique' count shows
--     breadth of access, which should match job role."
--
-- Q: "How do you differentiate service accounts from human accounts?"
-- A: "Service accounts have predictable patterns:
--     - total_events: Multiple per day, exact same times (e.g., backup at 2 AM daily)
--     - unique_source_ips: Usually 1 (always from same server)
--     - unique_hosts_accessed: Same systems every time
--     - failed_logins: Should be 0 (automated, no typos)
--     Human accounts are irregular - different times, occasional failures, variable systems.
--     If service account shows failures or new IPs → investigate (service misconfigured or hijacked)."

-- ============================================
-- ANOMALY DETECTION PATTERNS
-- ============================================
-- Flag these combinations for investigation:
--
-- CRITICAL ANOMALIES:
--   - failed_logins > successful_logins AND failed_logins >= 5
--     → Account under active brute force attack
--   - unique_source_ips >= 5 AND time_range < 1 hour
--     → Impossible travel (account sharing or compromise)
--   - unique_hosts_accessed > 10 for non-IT user
--     → Lateral movement (attacker exploring network)
--
-- MODERATE ANOMALIES:
--   - failed_logins >= 3 AND is_privileged = TRUE
--     → Admin forgot password? Or attacker probing?
--   - first_activity = last_activity AND total_events = 1
--     → Dormant account used once (why?)
--   - total_events > 100 in one day for normally quiet account
--     → Activity spike (legitimate or automated attack tool?)
--
-- INFORMATIONAL:
--   - total_events = 0 (not in this query, but track separately)
--     → Unused accounts (should be disabled)
--   - unique_source_ips = 1 AND unique_hosts_accessed = 1
--     → Very predictable (good for baseline, low risk)

-- ============================================
-- BASELINE VS ANOMALY EXAMPLE
-- ============================================
-- Normal "jsmith" baseline (established over 30 days):
--   - total_events: 20-30/day (Mon-Fri)
--   - successful_logins: 18-25/day
--   - failed_logins: 0-2/day (occasional typos)
--   - unique_source_ips: 2 (home VPN + office)
--   - unique_hosts_accessed: 3 (laptop, fileserver, VPN gateway)
--   - Activity time: 8 AM - 6 PM weekdays
--
-- Anomaly detected Jan 20:
--   - total_events: 156 (700% increase)
--   - unique_source_ips: 8 (400% increase)
--   - unique_hosts_accessed: 12 (400% increase)
--   - Activity time: 2 AM - 4 AM (off hours)
--   
-- Conclusion: "jsmith" account likely compromised - investigate immediately

-- ============================================
-- IMPROVEMENTS FOR PRODUCTION
-- ============================================
-- 1. Time-based baselines: Compare today vs last 30-day average
-- 2. Peer group analysis: Compare user to department peers (is everyone in Finance behaving this way?)
-- 3. Velocity scoring: Logins per hour (100 logins/hour = automated tool)
-- 4. Dormant account flagging: No activity in 90+ days → disable account
-- 5. Role-based expectations: IT should access many systems, Finance shouldn't
-- 6. Machine learning: Train model on "normal" behavior, auto-flag outliers

-- ============================================
-- COMPLIANCE USE CASE
-- ============================================
-- Many regulations require user activity monitoring:
--   - SOX: Track who accessed financial systems
--   - HIPAA: Monitor who viewed patient records
--   - GDPR: Know who accessed personal data
-- This query provides summary for:
--   - Annual access reviews: "Does jsmith still need access to these 12 systems?"
--   - Least privilege audits: "Why does finance user access engineering servers?"
--   - Insider threat programs: "Who has unusually high access breadth?"

-- ============================================
-- SAMPLE OUTPUT
-- ============================================
-- username    | department  | is_privileged | total_events | successful_logins | failed_logins | unique_source_ips | unique_hosts_accessed | first_activity      | last_activity
-- ------------|-------------|---------------|--------------|-------------------|---------------|-------------------|----------------------|---------------------|--------------------
-- svc-backup  | IT Ops      | true          | 9            | 9                 | 0             | 1                 | 2                    | 2025-01-18 02:00:00 | 2025-01-20 02:30:00
-- kwilson     | Finance     | false         | 6            | 4                 | 2             | 2                 | 5                    | 2025-01-18 22:15:00 | 2025-01-20 09:15:00
-- admin       | IT Security | true          | 5            | 1                 | 4             | 1                 | 1                    | 2025-01-20 14:30:00 | 2025-01-20 14:31:00
-- dbaker      | Engineering | false         | 5            | 1                 | 4             | 2                 | 4                    | 2025-01-19 03:45:25 | 2025-01-20 16:35:00
-- lbrown      | IT Support  | false         | 5            | 3                 | 2             | 5                 | 5                    | 2025-01-19 03:46:55 | 2025-01-20 02:25:40
-- mjones      | Marketing   | false         | 3            | 2                 | 1             | 2                 | 2                    | 2025-01-19 03:45:55 | 2025-01-20 17:30:00
-- schen       | Engineering | false         | 3            | 2                 | 1             | 2                 | 2                    | 2025-01-19 03:46:10 | 2025-01-20 15:35:00
-- tgarcia     | Sales       | false         | 2            | 1                 | 1             | 2                 | 1                    | 2025-01-19 03:46:25 | 2025-01-20 08:30:00
-- jdoe-admin  | IT Security | true          | 2            | 2                 | 0             | 1                 | 1                    | 2025-01-20 10:00:00 | 2025-01-20 11:45:00
-- jsmith      | Finance     | false         | 2            | 1                 | 1             | 2                 | 2                    | 2025-01-19 03:45:10 | 2025-01-20 14:20:00
-- rjohnson    | Sales       | false         | 1            | 0                 | 1             | 1                 | 1                    | 2025-01-19 03:45:40 | 2025-01-19 03:45:40

-- ANALYSIS:
-- svc-backup: NORMAL - Service account, predictable pattern (9 events, 1 IP, 2 systems, 0 failures)
-- kwilson: SUSPICIOUS - Finance accessing 5 systems (cross-department), after-hours activity
-- admin: CRITICAL - 4 failures then success = successful brute force
-- dbaker: SUSPICIOUS - 4 failures, multiple systems = privilege escalation attempt
-- lbrown: SUSPICIOUS - 5 unique IPs and 5 systems = potential lateral movement
-- mjones/schen/tgarcia/jsmith: MEDIUM - Password spray victims (1 failure each from same attacker)
-- jdoe-admin: NORMAL - Legitimate admin maintenance (2 events, 1 IP, scheduled)
-- rjohnson: INFO - Single failed login (likely typo or password spray victim)
