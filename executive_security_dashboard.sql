-- ============================================
-- SECURITY OPERATIONS CENTER (SOC) DASHBOARD
-- Executive Summary - Security Data Warehouse
-- ============================================
-- Purpose: Single-query overview of all security events
-- Audience: SOC analysts, security managers, executives
-- Refresh: Run daily or on-demand
-- ============================================
--
-- USAGE:
-- Run this query daily to get executive security overview
-- Returns ~20 rows across 6 categories
-- 
-- INTERPRETATION:
-- 🔴 = Critical - Immediate action required
-- 🟠 = High - Urgent attention needed  
-- 🟡 = Medium - Monitor and investigate
-- 🟢 = Low - Informational
-- ✅ = Normal - No action needed
--
-- SECTIONS:
-- 1. Overall Metrics - Environment health
-- 2. Critical Incidents - Active compromises
-- 3. Top Threats - Highest priority targets
-- 4. Attack Timeline - Temporal analysis
-- 5. Threat Actors - Ranked by danger
-- 6. Recommendations - Actionable next steps
--
-- ============================================

select *
from (

-- ============================================
-- SECTION 1: OVERALL SECURITY METRICS
-- ============================================

	select *
	from (
		select
			'📊 OVERALL METRICS' as category,
			'Total Security Events' as metric,
			COUNT(*)::text || ' event(s)' as value,
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
			COUNT(*)::text || ' attempt(s)',
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
			COUNT(*)::text || ' login(s)',
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
			COUNT(distinct source_ip)::text || ' source(s)',
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
			COUNT(distinct u.user_id)::text || ' account(s)',
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
			COUNT(distinct e.user_id)::text || ' brute(s)',
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
			COUNT(*)::text || ' attack(s)',
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
	
	union all
	
	select *
	from (
		select
			'🚨 CRITICAL INCIDENTS',
			'Attacks on CRITICAL Assets',
			COUNT(*)::text || ' attack(s)',																								-- TOTAL COUNT
			COUNT(distinct h.hostname)::text || ' servers targeted',																	-- DISTINCT COUNT
			'🔴'
		from fact_auth_events e
		join dim_hosts h on e.dest_host_id = h.host_id
		where h.asset_criticality = 'CRITICAL'																							-- ONLY CRITICAL ASSETS
		and e.success = false
		and e.event_timestamp >= '2025-01-01'
	) attacks_on_critical_assets
	
	union all



-- ============================================
-- SECTION 3: TOP THREATS
-- ============================================

	select *
	from (
		select
			'🎯 TOP THREATS',
			'Most Attacked User: ' || u.username,
			COUNT(*)::text || ' attack(s)',
			u.department ||
			case when u.is_privileged then ' (PRIVILEGED)' else '' end,																	-- ADDS DEPARTMENT + IF USER IS PRIVILEGED AFTER 
			case when u.is_privileged then '🔴' else '🟡' end																			-- ADDITIONAL SEVERITY CHARACTER
		from fact_auth_events e
		join dim_users u on e.user_id = u.user_id 
		where e.success = false and e.event_timestamp >= '2025-01-01'
		group by u.user_id, u.username, u.department, u.is_privileged 
		order by COUNT(*) desc 
		limit 1
	) most_attacked_user
	
	union all
	
	select *
	from (
		select
			'🎯 TOP THREATS',
			'Most Attacked Server: ' || h.hostname,
			COUNT(*)::text || ' attack(s)',
			h.asset_criticality || ' criticality',
			case
				when h.asset_criticality = 'CRITICAL' then '🔴'
	        	when h.asset_criticality = 'HIGH' then '🟠'
	        	else '🟡' 
			end
		from fact_auth_events e
		join dim_hosts h on e.dest_host_id = h.host_id 
		where e.success = false and e.event_timestamp >= '2025-01-01'
		group by h.host_id, h.hostname, h.asset_criticality
		order by COUNT(*) desc
		limit 1
	) most_attacked_server
	
	union all
	
	select *
	from (
		select 
			'🎯 TOP THREATS',
			'Most Dangerous IP: ' || source_ip::text,
			total_attacks::text || ' attack(s) (' || successful::text || ' succeeded)',													-- # OF ATTACKS AND # SUCCEEDED IN ()
			users_targeted::text || ' user(s) targeted',
			'🔴'
		from (																															-- CREATES TEMP TABLE TO FIND TOTAL, SUCCESSFUL, AND USERS TARGETED
			select
				source_ip,
				COUNT(*) as total_attacks,
				SUM(case when success = true then 1 else 0 end) as successful,															-- SUMMING UP SUCCESSFUL ATTACKS 
				COUNT(distinct user_id) as users_targeted	
			from fact_auth_events
			where source_ip not between '10.0.0.0' and '10.255.255.255'
			and event_timestamp >= '2025-01-01'
			group by source_ip
			order by 
				SUM(case when success = true then 1 else 0 end) desc,
				COUNT(*) desc
			limit 1
		) top_ip
	) most_dangerous_ip
	
	union all



-- ============================================
-- SECTION 4: ATTACK TIMELINE
-- ============================================

	select *
	from (
		select
			'📅 ATTACK TIMELINE',
			'First Attack Recorded',
			TO_CHAR(MIN(event_timestamp), 'YYYY-MM-DD HH24:MI')::text,																	-- FINDING MINIMUM TIMESTAMP (EARLIEST DATE) 
			'Monitoring since',
			'📍'
		from fact_auth_events
		where success = false and event_timestamp >= '2025-01-01'
	) first_attack_recorded
	
	union all
	
	select *
	from (
		select
			'📅 ATTACK TIMELINE',
			'Most Recent Attack',
			TO_CHAR(MAX(event_timestamp), 'YYYY-MM-DD HH24:MI')::text,																	-- FINDING MAXIMUM TIMESTAMP (LATEST DATE/MOST RECENT)
			'Last failed login',
			'📍'
		from fact_auth_events
		where success = false and event_timestamp >= '2025-01-01'
	) most_recent_attack
	
	union all
	
	select *
	from (
		select 
		 	'📅 ATTACK TIMELINE',
		 	'Peak Attack Day',
		 	event_date::text,
		 	attack_count::text || ' attack(s)',
		 	'📊'
		from (
		 	select
		 		event_timestamp::date as event_date,
		 		COUNT(*) as attack_count																								-- COUNTING # OF ATTACKS, LIMITING TO ONLY TOP COUNT
		 	from fact_auth_events
		 	where success = false and event_timestamp >= '2025-01-01'
		 	group by event_timestamp::date
		 	order by COUNT(*) desc
		 	limit 1
		) peak
	) peak_attack_day
	
	union all



-- ============================================
-- SECTION 5: THREAT ACTOR SUMMARY
-- ============================================

	select *
	from (
		select 
			'👤 THREAT ACTORS',
			source_ip::text,
			total_attempts::text || ' attempt(s)',
			user_list,
			case 
				when successful > 0 and failed >= 3 then '🔴 Successful Brute Force'														-- IF THIS PRECONFIGURED CONDITION FOR (BRUTE FORCE) IS MET, OUTPUT
	        	when users_targeted >= 5 then '🔴 Password Spraying'																		-- IF THIS PRECONFIGURED CONDITION FOR (PASSWORD SPRAYING) IS MET, OUTPUT
	        	when successful > 0 then '🟡 Successful External Login'																	-- IF THIS PRECONFIGURED CONDITION FOR (SUCCESSFUL EXTERNAL LOGIN) IS MET, OUTPUT
	        	else '🟢 Blocked'
			end
		from (
			select
				e.source_ip,
				COUNT(*) as total_attempts,
				SUM(case when e.success = true then 1 else 0 end) as successful,
				SUM(case when e.success = false then 1 else 0 end) as failed,
				COUNT(distinct e.user_id) as users_targeted,
				STRING_AGG(distinct u.username, ', ' order by u.username) as user_list
			from fact_auth_events e
			join dim_users u on e.user_id = u.user_id
			where e.source_ip not between '10.0.0.0' and '10.255.255.255'
			and e.event_timestamp >= '2025-01-01'
			group by e.source_ip
		) threats
		order by
			case 
				when successful > 0 and failed >= 3 then 1																				-- CREATING DIFFERENT THREAT ACTOR ROWS, SORTING IN SAME ORDER AS CASE ABOVE
				when users_targeted >= 5 then 2
				when successful > 0 then 3
				else 4
			end,
			total_attempts desc
	) threat_actors
	
	union all



-- ============================================
-- SECTION 6: RECOMMENDATIONS
-- ============================================

	select *
	from (
		select																															-- COUNTING ACCOUNTS THAT HAD 3 FAILED LOGINS AND SUCCESSFUL LOGIN TOGETHER
			'✅ RECOMMENDATIONS',
			'Immediate Actions Required',
			COUNT(*)::text || ' action(s)',
			'Compromised accounts needing password reset',
			'🔴'
		from (
			select distinct e.user_id 
			from (
				select user_id, source_ip
				from fact_auth_events
				where success = false
				group by user_id, source_ip
				having COUNT(*) >= 3
			) failures
			join fact_auth_events e on
				failures.user_id = e.user_id
				and failures.source_ip = e.source_ip
				and e.success = TRUE
		) compromised
	) immediate_actions_required
	
	union all
	
	select *
	from (
		select 
			'✅ RECOMMENDATIONS',
	    	'IPs to Block',
	    	COUNT(*)::text || ' IP(s)',
	    	'External IPs with failed attacks',
	    	'🟠'
		from (
			select distinct source_ip 	
			from fact_auth_events
			where source_ip not between '10.0.0.0' and '10.255.255.255'
			and success = false
			and event_timestamp >= '2025-01-01'
		) malicious_ips
	) ips_to_block
	
	union all
	
	select *
	from (
		select 
			'✅ RECOMMENDATIONS',
	    	'Users Requiring Training',
	    	COUNT(*)::text || ' user(s)',
	    	'Users with suspicious activity patterns',
	    	'🟡'
		from (
			select user_id 
			from fact_auth_events
			where event_timestamp >= '2025-01-01'
			group by user_id
			having SUM(case when success = false then 1 else 0 end) >= 3
		) suspicious_users
	) users_requiring_training
) soc_dashboard

-- =========================
-- FINAL DASHBOARD ORDERING
-- =========================
ORDER BY 
    CASE category
        WHEN '📊 OVERALL METRICS' THEN 1
        WHEN '🚨 CRITICAL INCIDENTS' THEN 2
        WHEN '🎯 TOP THREATS' THEN 3
        WHEN '📅 ATTACK TIMELINE' THEN 4
        WHEN '👤 THREAT ACTORS' THEN 5
        WHEN '✅ RECOMMENDATIONS' THEN 6
    END,
    category,
    metric;