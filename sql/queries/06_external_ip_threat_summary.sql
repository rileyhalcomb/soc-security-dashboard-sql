-- =====================================================
-- QUERY 6: EXTERNAL IP THREAT SUMMARY
-- =====================================================
-- PURPOSE: Profile all external (non-internal) IP addresses attacking the network
-- ATTACK PATTERN: Threat actor intelligence - who's attacking us and how dangerous are they
-- MITRE ATT&CK: TA0001 (Initial Access - external threat actors attempting entry)
-- THRESHOLD: Any activity from non-10.x.x.x IP addresses
-- PRIORITY: Varies by success rate (successful attacks = CRITICAL)
-- =====================================================

-- COMMENTED OUT IS PAST 30 DAYS
select 
	e.source_ip,																	-- WHO is the threat actor (IP address)
	count(*) as total_attempts,														-- HOW ACTIVE are they (total activities)
	sum(case when e.success = false then 1 else 0 end) as failed_attempts,
		-- HOW MANY times did we block them
	sum(case when e.success = true then 1 else 0 end) as successful_logins,
		-- HOW MANY times did they get in (CRITICAL if > 0)
	count(distinct u.user_id) as unique_users_targeted,
		-- HOW MANY different accounts did they attack
	count(distinct h.host_id) as unique_hosts_targeted,
		-- HOW MANY different systems did they target
	min(e.event_timestamp) as first_seen,											-- WHEN did we first see this IP
	max(e.event_timestamp) as last_seen												-- WHEN was their most recent activity 
from fact_auth_events e
join dim_users u on e.user_id = u.user_id 
left join dim_hosts h on e.dest_host_id = h.host_id
where
	e.source_ip not between '10.0.0.0' and '10.255.255.255'
		-- EXCLUDE internal IPs (10.x.x.x = private network)
		-- Only show external/internet IPs
	and e.event_timestamp >= '2025-01-01'
--	and e.event_timestamp > CURRENT_TIMESTAMP - interval '30 days'
group by e.source_ip																-- Bucket by each unique IP address
order by 
	successful_logins desc,															-- Most dangerous first (got in)
	total_attempts desc;															-- Then by most active

-- Expected Results:
-- Shows external IPs attacking your infrastructure
-- High failed_attempts + 0 successful = unsuccessful attack
-- Any successful_logins from external IP = INVESTIGATE
-- Action: Block IPs with high failed attempts
	
-- ============================================
-- PLAIN ENGLISH EXPLANATION
-- ============================================
-- "Show me every external IP address that tried to access our systems, how many
--  times they tried, whether they succeeded, how many accounts/systems they targeted,
--  and when we first and last saw them. Prioritize IPs that successfully got in."

-- ============================================
-- WHY THIS MATTERS (Security Impact)
-- ============================================
-- This query creates a "threat actor database" - external IPs are potential attackers:
--   - Internal IPs (10.x.x.x) = employees, usually legitimate
--   - External IPs = internet, could be legitimate (VPN) or malicious (attackers)
-- 
-- Key intelligence this provides:
--   1. WHO is attacking: IP addresses (can geo-locate, check reputation)
--   2. PERSISTENCE: first_seen vs last_seen = ongoing campaign or one-time probe
--   3. SUCCESS RATE: failed vs successful = how effective are our defenses
--   4. SCOPE: How many targets = reconnaissance (1-2) vs attack (10+)
--   5. PRIORITIZATION: Successful logins demand immediate response
--
-- Real SOC workflow:
--   - successful_logins > 0 → Immediate incident response (active breach)
--   - unique_users_targeted >= 5 → Password spraying attack
--   - total_attempts > 100 → Persistent threat actor (add to watchlist)
--   - first_seen = last_seen → One-time probe (low priority)

-- ============================================
-- SQL CONCEPTS USED
-- ============================================
-- IP range filtering (NOT BETWEEN) - Excludes private IP range 10.0.0.0 to 10.255.255.255
-- CASE statements in aggregation   - Conditional counting (success vs failure)
-- Multiple COUNT(DISTINCT)          - Counting unique values across different columns
-- Multi-level ORDER BY              - Sort by success first, then attempts
-- SUM(CASE) pattern                 - Standard way to count conditionally in SQL

-- ============================================
-- UNDERSTANDING IP RANGES
-- ============================================
-- Private IP ranges (RFC 1918 - internal networks only):
--   - 10.0.0.0 to 10.255.255.255 (Class A - large enterprises)
--   - 172.16.0.0 to 172.31.255.255 (Class B - medium networks)
--   - 192.168.0.0 to 192.168.255.255 (Class C - home/small office)
-- This query only looks at 10.x.x.x because that's what this specific network uses.
-- In production, you'd exclude ALL private ranges:
--   WHERE e.source_ip NOT BETWEEN '10.0.0.0' AND '10.255.255.255'
--     AND e.source_ip NOT BETWEEN '172.16.0.0' AND '172.31.255.255'
--     AND e.source_ip NOT BETWEEN '192.168.0.0' AND '192.168.255.255'

-- ============================================
-- INTERVIEW QUESTIONS YOU CAN ANSWER
-- ============================================
-- Q: "Why use SUM(CASE...) instead of two separate COUNT queries?"
-- A: "Efficiency. SUM(CASE) lets me count successes and failures in one pass through
--     the data. Two queries would scan the table twice. The CASE returns 1 if condition
--     is true, 0 if false, then SUM adds them up. It's a common SQL pattern for
--     'conditional aggregation' - counting rows that meet specific criteria."
--
-- Q: "What's the difference between total_attempts and failed_attempts?"
-- A: "total_attempts = ALL activity (successes + failures). failed_attempts = only
--     failures. successful_logins = only successes. The math: 
--     total_attempts = failed_attempts + successful_logins.
--     This gives complete picture: '100 attempts, 95 failed, 5 succeeded' tells me
--     they're persistent (100 tries) but mostly blocked (95%) with some success (5)."
--
-- Q: "Why does ORDER BY have two columns?"
-- A: "Priority layering. First sort puts IPs with successful_logins at top (most
--     dangerous - they got in). Among those with same success count, secondary sort
--     by total_attempts shows who's most active. Result: 
--     Top of list = 'Got in AND very active' (worst case)
--     Bottom of list = 'Never got in AND low activity' (least concern)"
--
-- Q: "How would you enhance this for a real SOC?"
-- A: "Five additions:
--     1. Geo-location: Add country/city lookup from IP (MaxMind GeoIP database)
--     2. Reputation scoring: Cross-reference with threat intel feeds (AbuseIPDB, etc.)
--     3. ASN lookup: Identify if IP belongs to hosting provider (AWS, DigitalOcean = likely attacker)
--     4. Time-based analysis: Group by date to see 'active today' vs 'seen last month'
--     5. Threat classification: Auto-label as 'Brute Force' / 'Spraying' / 'Scanner' based on behavior"

-- ============================================
-- THREAT CLASSIFICATION LOGIC
-- ============================================
-- Based on the metrics, you can classify threats:
--
-- CRITICAL (Immediate Response):
--   - successful_logins > 0 AND failed_attempts >= 3 → Successful brute force
--   - successful_logins > 0 AND unique_users_targeted >= 5 → Successful password spray
--
-- HIGH (Urgent Investigation):
--   - unique_users_targeted >= 5 AND failed_attempts >= 5 → Active password spraying
--   - total_attempts > 100 → Persistent attacker (bot or determined human)
--
-- MEDIUM (Monitor):
--   - unique_users_targeted >= 2 AND failed_attempts >= 3 → Targeted attack attempt
--   - total_attempts between 10-100 → Moderate threat
--
-- LOW (Informational):
--   - total_attempts < 10 AND unique_users_targeted = 1 → Opportunistic scan
--   - first_seen = last_seen → One-time probe

-- ============================================
-- IMPROVEMENTS FOR PRODUCTION
-- ============================================
-- 1. Automated threat scoring: Calculate risk score (0-100) based on behavior
-- 2. IP reputation API integration: Pull reputation from AbuseIPDB, VirusTotal
-- 3. Geo-blocking recommendations: "75% of attacks from Russia, consider geo-fence"
-- 4. Time-series analysis: Show attack trends (increasing/decreasing activity)
-- 5. Auto-block integration: IPs with 50+ failures → auto-add to firewall deny list
-- 6. Correlation with other logs: Cross-reference with firewall, IDS, web server logs

-- ============================================
-- REAL-WORLD METRICS
-- ============================================
-- Typical SOC expectations:
--   - 90%+ of external IPs should have 0 successful logins (good defenses)
--   - 1-5% might be legitimate VPN users (verify against VPN logs)
--   - <1% are successful attackers (these become incidents)
--   - Average external IP attempts: 1-10 (random scanners)
--   - Persistent attackers: 50-1000+ attempts over days/weeks

-- ============================================
-- SAMPLE OUTPUT
-- ============================================
-- source_ip       | total_attempts | failed_attempts | successful_logins | unique_users_targeted | unique_hosts_targeted | first_seen          | last_seen
-- ----------------|----------------|-----------------|-------------------|----------------------|----------------------|---------------------|--------------------
-- 185.220.101.47  | 5              | 4               | 1                 | 1                    | 1                    | 2025-01-20 14:30:00 | 2025-01-20 14:31:00
-- 203.0.113.88    | 1              | 0               | 1                 | 1                    | 1                    | 2025-01-20 02:15:00 | 2025-01-20 02:15:00
-- 73.241.12.56    | 1              | 0               | 1                 | 1                    | 1                    | 2025-01-20 08:30:00 | 2025-01-20 08:30:00
-- 198.51.100.42   | 8              | 8               | 0                 | 8                    | 1                    | 2025-01-19 03:45:10 | 2025-01-19 03:46:55

-- THREAT ANALYSIS:
-- 185.220.101.47: CRITICAL - Brute force succeeded (4 failures → 1 success)
-- 203.0.113.88: MEDIUM - Suspicious lateral movement (successful but unusual)
-- 73.241.12.56: LOW - Likely legitimate VPN user (single successful login)
-- 198.51.100.42: HIGH - Password spraying attack (8 users, all blocked)
	