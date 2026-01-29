-- =====================================================
-- ADD TIME DIMENSION FOR TEMPORAL ANALYSIS
-- =====================================================
-- Purpose: Enable time-based attack pattern detection
-- Usage: Join fact_auth_events to dim_time on event_timestamp
-- Benefits: Pre-computed time attributes (business hours, weekends, shifts)
-- =====================================================

-- Create the time dimension table
create table dim_time (
	time_id				serial primary key,
	full_timestamp		timestamp unique not null,
	
	-- Date components
	date				date not null,
	year				integer not null,
	quarter				integer not null,
	month				integer not null,
	month_name			varchar(20) not null,
	week_of_year		integer not null,
	day_of_month		integer not null,
	day_of_week			integer not null,		-- 0= Sunday, 6=Saturday
	day_name			varchar(20) not null,
	
	-- Time components
	hour				integer not null,		-- 0-23
	minute				integer not null,		-- 0-59
	
	-- Business logic flags
	is_weekend			boolean not null,
	is_business_hours	boolean not null,		-- Mon-Fri 8 AM - 6 PM
	is_night_shift		boolean not null,		-- 10 PM - 6 AM
	
	-- Security risk classification
	risk_period			varchar(20) not null,	-- HIGH_RISK, MEDIUM_RISK, NORMAL
	
	-- Audit
	created_at			timestamp default current_timestamp
);

-- Add helpful comment
comment on table dim_time is 'Time dimension for temporal attack pattern analysis';
comment on column dim_time.is_business_hours is 'TRUE = Monday-Friday 8 AM - 6 PM';
comment on column dim_time.risk_period is 'HIGH RISK = nights/weekends, NORMAL = business hours';

-- =====================================================
-- POPULATE TIME DIMENSION
-- =====================================================
-- Generate one row per hour from Jan 1, 2025 to Dec 31, 2025
-- Adjust date range as needed for your data

insert into dim_time (
	full_timestamp,
    date,
    year,
    quarter,
    month,
    month_name,
    week_of_year,
    day_of_month,
    day_of_week,
    day_name,
    hour,
    minute,
    is_weekend,
    is_business_hours,
    is_night_shift,
    risk_period
)
select
	ts as full_timestamp,
	ts::date as date,
	extract(year from ts) as year,
	extract(quarter from ts) as quarter,
	extract(month from ts) as month,
	to_char(ts, 'Month') as month_name,
	extract(week from ts) as week_of_year,
	extract(day from ts) as day_of_month,
	extract(dow from ts) as day_of_week,	-- 0=Sunday, 6=Saturday
	to_char(ts, 'Day') as day_name,
	extract(hour from ts) as hour,
	0 as minute,							-- Starting with hourly granularity
	
	-- Weekend flag
	extract(dow from ts) in (0, 6) as is_weekend,
	
	-- Business hours flag (Mon-Fri 8 AM - 6 PM)
	(
		extract(dow from ts) between 1 and 5		-- Monday to Friday
		and extract(hour from ts) between 8 and 17	-- 8 AM to 5 PM (17 = 5 PM)
	) as is_business_hours,
	
	-- Night shift flag (10 PM - 6 AM)
	(
		extract(hour from ts) >= 22 or extract(hour from ts) < 6
	) as is_night_shift,
	
	-- Risk period classification
	case
		-- High risk: Weekends + nights (most suspicious)
		when extract(dow from ts) in (0, 6) then 'HIGH_RISK'
		when extract(hour from ts) >= 22 or extract(hour from ts) < 6 then 'HIGH_RISK'
		
		-- Medium risk: Early morning/late evening on weekdays
		when extract(hour from ts) between 6 and 7 then 'MEDIUM_RISK'
		when extract(hour from ts) between 18 and 21 then 'MEDIUM_RISK'
		
		-- Normal: Business hours
		else 'NORMAL'
	end as risk_period
	
from generate_series(
	'2025-01-01 00:00:00'::timestamp,
	'2025-12-31 23:00:00'::timestamp,
	'1 hour'::interval
) as ts;
	
-- =====================================================
-- CREATE INDEXES FOR FAST LOOKUPS
-- =====================================================

-- Index on timestamp for joining with fact_auth_events
CREATE INDEX idx_dim_time_timestamp ON dim_time(full_timestamp);

-- Index on date for daily aggregations
CREATE INDEX idx_dim_time_date ON dim_time(date);

-- Index on business hours flag for filtering
CREATE INDEX idx_dim_time_business_hours ON dim_time(is_business_hours);

-- Index on risk period for security queries
CREATE INDEX idx_dim_time_risk_period ON dim_time(risk_period);

-- =====================================================
-- VERIFICATION QUERY
-- =====================================================

-- Show sample of time dimension
select
	full_timestamp,
	day_name,
	hour,
	is_weekend,
	is_business_hours,
	is_night_shift,
	risk_period
from dim_time
where date = '2025-01-20'
order by hour
limit 10;

-- Count total rows
select
	count(*) as total_hours,
	min(full_timestamp) as earliest,
	max(full_timestamp) as latest
from dim_time;

select 'Time dimension created and populated successfully!' as status;