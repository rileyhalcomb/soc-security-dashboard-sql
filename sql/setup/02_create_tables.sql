-- =====================================================
-- SECURITY DATA WAREHOUSE - TABLE DEFINITIONS
-- =====================================================
-- File: 02_create_tables.sql
-- Purpose: Create fact and dimension tables (star schema)
-- Run after: 01_create_database.sql
-- =====================================================

-- =====================================================
-- DIMENSION TABLES (Master Data)
-- =====================================================

-- Dimension: Users (Employees, Service Accounts)
create table dim_users (
	user_id			serial primary key,
	username		varchar(100) unique not null,
	department		varchar(100),
	is_privileged	boolean default false,
	
	-- Audit fields
	created_at		timestamp default current_timestamp,
	updated_at		timestamp default current_timestamp
);

comment on table dim_users is 'User dimension - employee and service account master data';
comment on column dim_users.is_privileged is 'TRUE = admin/root/domain admin accounts';

-- Dimension: Hosts (Servers, Workstations, Network Devices)
create table dim_hosts (
	host_id				serial primary key,
	hostname			varchar(255) unique not null,
	asset_criticality	varchar(20) check (asset_criticality in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
	location			varchar(100),
	
	-- Audit fields
	created_at			timestamp default current_timestamp,
	updated_at			timestamp default current_timestamp
);

comment on table dim_hosts is 'Host dimension - servers and endpoints inventory';

-- =====================================================
-- FACT TABLE (Transaction/Event Data)
-- =====================================================

create table fact_auth_events (
	event_id		serial primary key,
	user_id			integer not null references dim_users(user_id),
	dest_host_id	integer references dim_hosts(host_id),
	source_ip		inet not null,
	event_type		varchar(50) default 'login',
	success			boolean not null,
	event_timestamp	timestamp not null,
	
	-- Audit
	ingested_at		timestamp default current_timestamp
);

comment on table fact_auth_events is 'Authentication events fact table';

-- =====================================================
-- INDEXES (Performance Optimization)
-- =====================================================

create index idx_event_timestamp on fact_auth_events(event_timestamp);
create index idx_success on fact_auth_events(success);
create index idx_source_ip on fact_auth_events(source_ip);
create index idx_user_id on fact_auth_events(user_id);
create index idx_dest_host on fact_auth_events(dest_host_id);
create index idx_user_time on fact_auth_events(user_id, event_timestamp);

select 'Tables and indexes created successfully!' as status;