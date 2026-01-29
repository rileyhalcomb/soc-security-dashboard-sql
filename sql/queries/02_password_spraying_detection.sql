-- =====================================================
-- QUERY 2: PASSWORD SPRAYING DETECTION
-- =====================================================
-- PURPOSE: Identify single IP trying one password across multiple user accounts
-- ATTACK PATTERN: Attacker using common password (e.g., "Winter2024!") across many users
-- MITRE ATT&CK: T1110.003 (Brute Force: Password Spraying)
-- THRESHOLD: 5+ distinct users targeted from one IP
-- PRIORITY: CRITICAL (indicates coordinated, sophisticated attack)
-- =====================================================

select 
	e.source_ip,																		-- WHERE is the attack coming from
	count(distinct e.user_id) as users_targeted,										-- HOW MANY different accounts are bieng targeted
	count(*) as total_attempts,															-- TOTAL login attempts
	min(e.event_timestamp) as attack_start,												-- WHEN did attack BEGIN
	max(e.event_timestamp) as attack_end,												-- WHEN did attack END
	string_agg(distinct u.username, ', ' order by u.username) as targeted_accounts
		-- LIST of usernamed attacked (sorted alphabetically)
from fact_auth_events e
join dim_users u on e.user_id  = u.user_id 
where 
	e.success = false																	-- Only FAILED attempts
	and e.event_timestamp >= '2025-01-01'
group by e.source_ip																	-- Bucket by source IP ONLY
	-- Each bucket = ONE attacker IP's activity
having count(distinct e.user_id) >= 5													-- Only if 5+ different users targeted
	-- DISTINCT is key here - same user hit TWICE counts as 1
order by users_targeted desc;															-- WORST sprayers first

-- ============================================
-- PLAIN ENGLISH EXPLANATION
-- ============================================
-- "Show me any IP address that tried to login as 5 or more different users and failed,
--  with a list of which accounts they targeted and when the attack happened."

-- ============================================
-- WHY THIS MATTERS (Security Impact)
-- ============================================
-- Password spraying is MORE dangerous than brute force because:
--   1. Harder to detect (only 1 attempt per user = no lockouts triggered)
--   2. Often succeeds (attackers use common passwords like "Spring2024!")
--   3. Indicates sophisticated attacker (not just script kiddie)
-- Real example: Microsoft saw password spraying in 99% of cloud attacks in 2023.

-- ============================================
-- SQL CONCEPTS USED
-- ============================================
-- COUNT(DISTINCT)     - Counting unique values (not total rows)
-- STRING_AGG()        - PostgreSQL function to concatenate strings with delimiter
-- ORDER BY in STRING_AGG - Sorting within the aggregation
-- GROUP BY single column - Buckets by IP only (vs IP+user in brute force)

-- ============================================
-- INTERVIEW QUESTIONS YOU CAN ANSWER
-- ============================================
-- Q: "What's the difference between this and brute force detection?"
-- A: "Brute force = many attempts against ONE user. Password spraying = one attempt
--     against MANY users. I detect this by grouping only by source_ip, then counting
--     DISTINCT users. The DISTINCT is crucial - without it, I'd just count total
--     attempts, which doesn't tell me if they're spreading across accounts."
--
-- Q: "Why is 5 users the threshold?"
-- A: "Industry standard. Attacking 1-2 users could be coincidence, but 5+ indicates
--     systematic credential stuffing. Some orgs use 3, others 10 - depends on size.
--     For a 100-person company, 5 is significant. For enterprise with 10,000 users,
--     I might raise it to 20."
--
-- Q: "How do attackers get the username list?"
-- A: "LinkedIn, data breaches, email pattern guessing (firstname.lastname@company.com),
--     or directory harvesting. That's why this attack is so effective - usernames
--     are often public, only passwords are secret."
--
-- Q: "What if attack happens over days, not minutes?"
-- A: "Good catch. This query looks at all time. In production, I'd add:
--     WHERE e.event_timestamp > NOW() - INTERVAL '24 hours'
--     to catch attacks within a rolling 24-hour window. Slower attacks need
--     different detection - maybe 5+ users over 7 days from same IP."

-- ============================================
-- IMPROVEMENTS FOR PRODUCTION
-- ============================================
-- 1. Time-based detection: 5+ users in 1 hour = urgent, 5+ in 1 week = monitor
-- 2. Success correlation: Did ANY of these attempts succeed? (Critical alert)
-- 3. Department analysis: Targeting specific department? (Spear phishing follow-up)
-- 4. Credential stuffing vs spraying: Check if usernames are common (john, admin, etc.)
-- 5. IP reputation: Cross-reference with threat intel feeds

-- ============================================
-- SAMPLE OUTPUT
-- ============================================
-- source_ip       | users_targeted | total_attempts | attack_start        | attack_end          | targeted_accounts
-- ----------------|----------------|----------------|---------------------|---------------------|--------------------------------------------------
-- 198.51.100.42   | 8              | 8              | 2025-01-19 03:45:10 | 2025-01-19 03:46:55 | dbaker, jsmith, kwilson, lbrown, mjones, rjohnson, schen, tgarcia
