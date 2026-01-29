-- =====================================================
-- QUERY 1: BRUTE FORCE DETECTION
-- =====================================================
-- PURPOSE: Identify multiple failed login attempts from the same source IP targeting the same user
-- ATTACK PATTERN: Attacker trying different passwords for one specific account
-- MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing)
-- THRESHOLD: 3+ failed attempts (tunable based on environment)
-- PRIORITY: HIGH if targeting privileged accounts
-- =====================================================

-- COMMENTED OUT IS PAST 24HRS
select 
	u.username,																-- WHO is being attacked
	u.department,															-- Helps prioritize (Finance vs IT?)
	u.is_privileged,														-- CRITICAL if true (admin account!)
	COUNT(*) as failed_attempts,											-- HOW MANY password guesses
	e.source_ip,															-- WHERE/WHAT IP is the attack coming from
	MIN(e.event_timestamp) as first_attempt,								-- WHEN did attack start
	MAX(e.event_timestamp) as last_attempt									-- WHEN did attack end
from fact_auth_events e														-- Start with all login events
join dim_users u on e.user_id = u.user_id 									-- Add user details to login events
where
	e.success = false														-- ONLY failed logins
--	and e.event_timestamp > CURRENT_TIMESTAMP - interval '24 hours'			-- From last 24 hrs (time range filter)
	and e.event_timestamp >= '2025-01-01'									-- From after Jan. 1, 2025 (time range filter)
group by u.username, u.department, u.is_privileged, e.source_ip				
	-- Grouping by: user + attacker IP combo
	-- This creates buckets: "IP 1.2.3.4 attacking user 'admin'"
having COUNT(*) >= 3														-- ONLY shows if 3+ attempts
	-- HAVING filters AFTER grouping
	-- WHERE filters BEFORE grouping
order by failed_attempts desc;												-- WORST attacks FIRST

-- Expected Results:
-- Shows accounts under brute force attack
-- Prioritize: is_privileged = TRUE (admin accounts)
-- Action: Block source_ip, alert security team

-- ============================================
-- PLAIN ENGLISH EXPLANATION
-- ============================================
-- "Show me any IP address that failed to login as the same user 3 or more times,
--  and tell me when the attack started/ended, prioritizing admin accounts."

-- ============================================
-- WHY THIS MATTERS (Security Impact)
-- ============================================
-- In a real SOC, this catches attackers trying to break into specific accounts.
-- The threshold of 3 balances:
--   - Catching real attacks (attackers rarely give up after 1-2 tries)
--   - Avoiding false positives (users legitimately mistype passwords 1-2 times)
-- Flagging privileged accounts separately lets analysts prioritize response.

-- ============================================
-- SQL CONCEPTS USED
-- ============================================
-- JOIN          - Connecting fact table to dimension for user context
-- WHERE         - Filtering rows BEFORE grouping
-- GROUP BY      - Creating buckets of (user, IP) combinations
-- HAVING        - Filtering groups AFTER aggregation
-- COUNT()       - Counting rows in each group
-- MIN()/MAX()   - Finding earliest/latest timestamp in each group
-- Aggregation   - Combining multiple rows into summary statistics

-- ============================================
-- INTERVIEW QUESTIONS YOU CAN ANSWER
-- ============================================
-- Q: "Why GROUP BY instead of just WHERE?"
-- A: "WHERE filters individual events, but I need to COUNT events per attacker/victim
--     pair. GROUP BY creates those pairs, then COUNT tells me how many in each pair."
--
-- Q: "Why 3 attempts as the threshold?"
-- A: "It's a balance. 1-2 could be legitimate typos, but 3+ indicates intentional
--     password guessing. In production, I'd make this configurable - maybe stricter
--     for admin accounts (2 attempts) vs regular users (5 attempts)."
--
-- Q: "What if an attacker uses multiple IPs?"
-- A: "This query catches single-IP attacks. For distributed attacks, I'd write a
--     companion query that groups by username only and looks for attacks from
--     multiple IPs in a short timeframe - that's password spraying."
--
-- Q: "How would you reduce false positives?"
-- A: "Add a time window - only count attempts in last 1 hour instead of all time.
--     Also correlate with successful logins - if user eventually logged in from
--     same IP, maybe they just forgot password. Finally, check if IP is internal
--     (10.x.x.x) vs external - internal might be locked-out employee."

-- ============================================
-- IMPROVEMENTS FOR PRODUCTION
-- ============================================
-- 1. Time window: Change to "WHERE e.event_timestamp > NOW() - INTERVAL '1 hour'"
-- 2. Differentiate thresholds: 2 for privileged, 5 for regular users
-- 3. Add IP reputation: Flag known malicious IPs immediately
-- 4. Correlate with success: Did the attack eventually succeed?
-- 5. Alert severity: Auto-escalate if targeting multiple admin accounts

-- ============================================
-- SAMPLE OUTPUT
-- ============================================
-- username | department  | is_privileged | failed_attempts | source_ip       | first_attempt       | last_attempt
-- ---------|-------------|---------------|-----------------|-----------------|---------------------|--------------------
-- admin    | IT Security | true          | 4               | 185.220.101.47  | 2025-01-20 14:30:00 | 2025-01-20 14:30:45
-- dbaker   | Engineering | false         | 3               | 10.0.3.78       | 2025-01-20 16:30:00 | 2025-01-20 16:32:00
