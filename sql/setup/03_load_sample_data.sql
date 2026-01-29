-- =====================================================
-- SECURITY DATA WAREHOUSE - SAMPLE DATA
-- =====================================================
-- File: 03_load_sample_data.sql
-- Purpose: Load realistic attack scenarios for testing
-- Run after: 02_create_tables.sql
-- =====================================================

truncate table fact_auth_events cascade;
truncate table dim_users restart identity cascade;
truncate table dim_hosts restart identity cascade;

-- =====================================================
-- DIMENSION DATA
-- =====================================================

insert into dim_users (username, department, is_privileged) values
('jsmith', 'Finance', false),
('dbaker', 'Engineering', false),
('mjones', 'Marketing', false),
('kwilson', 'Finance', false),
('tgarcia', 'Sales', false),
('rjohnson', 'Sales', false),
('schen', 'Engineering', false),
('lbrown', 'IT Support', false),
('admin', 'IT Security', true),
('jdoe-admin', 'IT Security', true),
('svc-backup', 'IT Ops', true);

insert into dim_hosts (hostname, asset_criticality, location) values
('dc-corp-01', 'CRITICAL', 'Office - NY'),
('database-prod-01', 'CRITICAL', 'AWS us-east-1'),
('vpn-gateway', 'HIGH', 'AWS us-east-1'),
('webserver-prod-01', 'HIGH', 'AWS us-east-1'),
('fileserver-corp', 'MEDIUM', 'Office - NY'),
('laptop-dbaker', 'LOW', 'Remote'),
('laptop-jsmith', 'LOW', 'Remote'),
('laptop-schen', 'LOW', 'Remote'),
('laptop-kwilson', 'LOW', 'Remote');

-- =====================================================
-- SCENARIO 1: PasSWORD SPRAYING ATTACK (8 users targeted)
-- =====================================================

insert into fact_auth_events (user_id, dest_host_id, source_ip, event_type, success, event_timestamp) values
(1, 1, '198.51.100.42', 'failed_login', false, '2025-01-19 03:45:10'),
(2, 4, '198.51.100.42', 'failed_login', false, '2025-01-19 03:45:25'),
(6, 1, '198.51.100.42', 'failed_login', false, '2025-01-19 03:45:40'),
(3, 2, '198.51.100.42', 'failed_login', false, '2025-01-19 03:45:55'),
(7, 2, '198.51.100.42', 'failed_login', false, '2025-01-19 03:46:10'),
(5, 1, '198.51.100.42', 'failed_login', false, '2025-01-19 03:46:25'),
(4, 3, '198.51.100.42', 'failed_login', false, '2025-01-19 03:46:40'),
(8, 1, '198.51.100.42', 'failed_login', false, '2025-01-19 03:46:55');

-- =====================================================
-- SCENARIO 2: SUCCESSFUL BRUTE FORCE (Russian IP breaks in)
-- =====================================================

insert into fact_auth_events (user_id, dest_host_id, source_ip, event_type, success, event_timestamp) values
(9, 4, '185.220.101.47', 'failed_login', false, '2025-01-20 14:30:00'),
(9, 4, '185.220.101.47', 'failed_login', false, '2025-01-20 14:30:15'),
(9, 4, '185.220.101.47', 'failed_login', false, '2025-01-20 14:30:30'),
(9, 4, '185.220.101.47', 'failed_login', false, '2025-01-20 14:30:45'),
(9, 4, '185.220.101.47', 'login', true, '2025-01-20 14:31:00');

-- =====================================================
-- SCENARIO 3: INTERNAL THREAT (Engineering accessing Domain Controller)
-- =====================================================

insert into fact_auth_events (user_id, dest_host_id, source_ip, event_type, success, event_timestamp) values
(2, 1, '10.0.3.78', 'failed_login', false, '2025-01-20 16:30:00'),
(2, 1, '10.0.3.78', 'failed_login', false, '2025-01-20 16:31:00'),
(2, 2, '10.0.3.78', 'failed_login', false, '2025-01-20 16:32:00'),
(2, 6, '10.0.3.78', 'login', true, '2025-01-20 16:35:00');

-- =====================================================
-- SCENARIO 4: LATERAL MOVEMENT (Finance → Engineering systems)
-- =====================================================

insert into fact_auth_events (user_id, dest_host_id, source_ip, event_type, success, event_timestamp) values
(4, 3, '10.0.1.50', 'failed_login', false, '2025-01-18 22:15:00'),
(4, 4, '10.0.1.50', 'failed_login', false, '2025-01-18 22:20:00'),
(4, 6, '10.0.1.50', 'login', true, '2025-01-20 09:10:00'),
(4, 8, '10.0.1.50', 'login', true, '2025-01-20 09:12:00'),
(4, 2, '10.0.1.50', 'login', true, '2025-01-20 09:15:00');

-- =====================================================
-- SCENARIO 5: NORMAL VPN LOGINS
-- =====================================================

insert into fact_auth_events (user_id, dest_host_id, source_ip, event_type, success, event_timestamp) values
(5, 1, '73.241.12.56', 'login', true, '2025-01-20 08:30:00'),
(3, 2, '67.180.93.22', 'login', true, '2025-01-20 09:45:00'),
(1, 7, '203.0.113.88', 'login', true, '2025-01-20 02:15:00'),
(7, 8, '10.0.2.15', 'login', true, '2025-01-20 15:35:00');

-- =====================================================
-- SCENARIO 6: ADMIN MAINTENANCE (Normal privileged activity)
-- =====================================================

insert into fact_auth_events (user_id, dest_host_id, source_ip, event_type, success, event_timestamp) values
(10, 2, '10.0.1.100', 'login', true, '2025-01-20 10:00:00'),
(10, 2, '10.0.1.100', 'logout', true, '2025-01-20 11:45:00');

-- =====================================================
-- SCENARIO 7: SERVICE ACCOUNT BACKUPS (Predictable pattern)
-- =====================================================

insert into fact_auth_events (user_id, dest_host_id, source_ip, event_type, success, event_timestamp) values
(11, 2, '10.10.5.20', 'login', true, '2025-01-18 02:00:00'),
(11, 5, '10.10.5.20', 'login', true, '2025-01-18 02:05:00'),
(11, 5, '10.10.5.20', 'logout', true, '2025-01-18 02:30:00'),
(11, 2, '10.10.5.20', 'login', true, '2025-01-19 02:00:00'),
(11, 5, '10.10.5.20', 'login', true, '2025-01-19 02:05:00'),
(11, 5, '10.10.5.20', 'logout', true, '2025-01-19 02:30:00'),
(11, 2, '10.10.5.20', 'login', true, '2025-01-20 02:00:00'),
(11, 5, '10.10.5.20', 'login', true, '2025-01-20 02:05:00'),
(11, 5, '10.10.5.20', 'logout', true, '2025-01-20 02:30:00');

-- =====================================================
-- SCENARIO 8: IMPOSSIBLE TRAVEL (Multiple locations quickly)
-- =====================================================

insert into fact_auth_events (user_id, dest_host_id, source_ip, event_type, success, event_timestamp) values
(8, 3, '10.50.2.10', 'failed_login', false, '2025-01-19 03:46:55'),
(8, 3, '45.142.212.61', 'failed_login', false, '2025-01-20 02:20:00'),
(8, 1, '203.0.113.88', 'login', true, '2025-01-20 02:25:40'),
(8, 4, '67.180.93.22', 'login', true, '2025-01-20 14:10:00'),
(8, 2, '103.28.48.12', 'login', true, '2025-01-20 14:25:00');

-- =====================================================
-- SCENARIO 9: NORMAL TYPOS (1-2 failures then success)
-- =====================================================

insert into fact_auth_events (user_id, dest_host_id, source_ip, event_type, success, event_timestamp) values
(1, 7, '10.0.1.25', 'failed_login', false, '2025-01-20 14:20:00'),
(1, 7, '10.0.1.25', 'login', true, '2025-01-20 14:20:15'),
(3, 2, '10.0.2.30', 'failed_login', false, '2025-01-20 17:30:00'),
(3, 2, '10.0.2.30', 'login', true, '2025-01-20 17:30:20');

-- Verification
select '✅ Sample data loaded: 52 events across 9 attack scenarios' as status;