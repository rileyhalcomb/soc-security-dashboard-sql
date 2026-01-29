-- =====================================================
-- QUERY 4: ATTACKS ON CRITICAL ASSETS
-- =====================================================
-- PURPOSE: Identify failed login attempts targeting high-value infrastructure
-- ATTACK PATTERN: Attackers focusing on critical/high priority servers
-- MITRE ATT&CK: T1078 (Valid Accounts - attempting to gain access)
-- THRESHOLD: Any failed attempt against CRITICAL or HIGH assets
-- PRIORITY: HIGH (attacks on crown jewels deserve immediate attention)
-- =====================================================

-- COMMENTED OUT IS PAST 7 DAYS
select 
	h.hostname,																				-- WHICH server is under attack
	h.asset_criticality,																	-- HOW important is it (CRITICAL/HIGH)
	h.location,																				-- WHERE is it (data center, cloud, office)
	u.username,																				-- WHO is being targeted
	u.is_privileged,																		-- Is this an ADMIN account too? (More of a risk)
	COUNT(*) as attack_count,																-- HOW MANY failed attempts
	COUNT(distinct e.source_ip) as unique_attackers,										-- From how many DIFFERENT IPs
	STRING_AGG(distinct e.source_ip::text, ', ') as attacker_ips
		-- LIST of attacking IPs (cast to text for string_agg)
from fact_auth_events e
join dim_users u on e.user_id = u.user_id 
join dim_hosts h on e.dest_host_id = h.host_id
where 
	e.success = false																		-- Only FAILED attempts
	and h.asset_criticality in ('CRITICAL', 'HIGH')											-- Only HIGH-VALUE targets
	and e.event_timestamp >= '2025-01-01'
--	and e.event_timestamp > CURRENT_TIMESTAMP - interval '7 days'
group by h.hostname, h.asset_criticality, h.location, u.username, u.is_privileged
	-- Bucket by: (specific server + specific user being attacked)
order by 
	case h.asset_criticality 																-- Sort CRITICAL above HIGH
		when 'CRITICAL' then 1
		when 'HIGH' then 2
	end,
	attack_count desc;																		-- Then by most attacked
	
	-- ============================================
-- PLAIN ENGLISH EXPLANATION
-- ============================================
-- "Show me every failed login attempt against our most important servers
--  (CRITICAL and HIGH priority), grouped by which server and which user
--  account was targeted, and tell me how many different IPs are attacking."

-- ============================================
-- WHY THIS MATTERS (Security Impact)
-- ============================================
-- Not all servers are equal - protecting crown jewels is paramount:
--   - CRITICAL assets: Database servers, domain controllers, payment systems
--   - HIGH assets: Production web servers, VPN gateways, email servers
-- Even one failed attempt against these deserves investigation because:
--   1. Attack surface should be minimal (why can external IPs even reach these?)
--   2. Indicates reconnaissance or targeted attack (not random scanning)
--   3. Success could mean data breach, ransomware, or total network compromise
-- This query helps prioritize: 100 attacks on a test server < 1 attack on production DB

-- ============================================
-- SQL CONCEPTS USED
-- ============================================
-- Multiple JOINs           - Connecting 3 tables (events, users, hosts)
-- IN operator              - Filtering to multiple values ('CRITICAL', 'HIGH')
-- COUNT(DISTINCT)          - Counting unique IPs (not total attempts)
-- Type casting (::text)    - Converting INET to text for STRING_AGG
-- CASE in ORDER BY         - Custom sort order (not alphabetical)
-- Composite GROUP BY       - Grouping by multiple columns creates specific buckets

-- ============================================
-- INTERVIEW QUESTIONS YOU CAN ANSWER
-- ============================================
-- Q: "Why group by both hostname AND username?"
-- A: "I want granular visibility. If I only grouped by hostname, I'd see '10 attacks
--     on database-prod-01' but not know if all 10 targeted the same admin account
--     (coordinated) or 10 different accounts (spray). Grouping by both tells me
--     'database-prod-01 had 4 attacks against admin and 6 against dbuser'."
--
-- Q: "What's the difference between COUNT(*) and COUNT(DISTINCT e.source_ip)?"
-- A: "COUNT(*) counts total rows (total failed attempts). COUNT(DISTINCT e.source_ip)
--     counts unique IPs. Example: If IP 1.2.3.4 failed 5 times, that's:
--     attack_count = 5 (total attempts), unique_attackers = 1 (only one IP).
--     Multiple unique IPs indicates distributed attack or multiple threat actors."
--
-- Q: "Why use CASE in ORDER BY instead of just ORDER BY asset_criticality?"
-- A: "Alphabetically, 'CRITICAL' comes before 'HIGH' - but 'HIGH' comes before 'MEDIUM'.
--     That's not the priority order I want. The CASE statement assigns numbers:
--     CRITICAL=1, HIGH=2, so they sort in actual priority order. Without this,
--     results would be: CRITICAL, HIGH, MEDIUM (if it existed) - lucky coincidence
--     that works, but CASE makes the intent explicit and handles edge cases."
--
-- Q: "Why include location in the query?"
-- A: "Helps incident response planning. If attacks are on 'AWS us-east-1', I engage
--     cloud security team and check AWS GuardDuty. If on 'Office - New York', I
--     check physical security logs. Location also helps identify insider threats -
--     attack on office server from internal IP might be disgruntled employee."

-- ============================================
-- IMPROVEMENTS FOR PRODUCTION
-- ============================================
-- 1. Severity scoring: CRITICAL + is_privileged = immediate page to security team
-- 2. Time analysis: Are attacks during business hours (insider?) or off-hours (external?)
-- 3. Success correlation: Did any attempts against these assets succeed? (Code red)
-- 4. Network segmentation check: Should this IP have access at all? (Firewall gap)
-- 5. Asset inventory sync: Cross-reference with CMDB to ensure criticality ratings are current

-- ============================================
-- REAL-WORLD EXAMPLE
-- ============================================
-- In 2021, Colonial Pipeline ransomware started with ONE compromised VPN account
-- accessing a HIGH criticality server. If they'd had this query running, they would
-- have seen the unusual login pattern days before the attack escalated to full shutdown.

-- ============================================
-- SAMPLE OUTPUT
-- ============================================
-- hostname          | asset_criticality | location      | username | is_privileged | attack_count | unique_attackers | attacker_ips
-- ------------------|-------------------|---------------|----------|---------------|--------------|------------------|-------------------
-- dc-corp-01        | CRITICAL          | Office - NY   | dbaker   | false         | 2            | 1                | 10.0.3.78
-- dc-corp-01        | CRITICAL          | Office - NY   | lbrown   | false         | 1            | 1                | 10.50.2.10
-- database-prod-01  | CRITICAL          | AWS us-east-1 | dbaker   | false         | 1            | 1                | 10.0.3.78
-- vpn-gateway       | HIGH              | AWS us-east-1 | jsmith   | false         | 1            | 1                | 198.51.100.42
-- vpn-gateway       | HIGH              | AWS us-east-1 | dbaker   | false         | 1            | 1                | 198.51.100.42
-- webserver-prod-01 | HIGH              | AWS us-east-1 | admin    | true          | 4            | 1                | 185.220.101.47
-- webserver-prod-01 | HIGH              | AWS us-east-1 | kwilson  | false         | 1            | 1                | 10.0.1.50
	