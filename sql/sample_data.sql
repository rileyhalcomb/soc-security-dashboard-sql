INSERT INTO dim_users (user_id, username, department, is_privileged)
VALUES
(1, 'alice', 'IT', true),
(2, 'bob', 'Finance', false),
(3, 'charlie', 'HR', false),
(4, 'david', 'IT', false),
(5, 'eve', 'Engineering', true),
(6, 'frank', 'Marketing', false),
(7, 'grace', 'IT', false),
(8, 'heidi', 'Finance', true);

INSERT INTO dim_hosts (host_id, hostname, asset_criticality)
VALUES
(1, 'webserver01', 'HIGH'),
(2, 'db01', 'CRITICAL'),
(3, 'file01', 'MEDIUM'),
(4, 'webserver02', 'CRITICAL'),
(5, 'devserver', 'LOW');

-- Sample normal logins
INSERT INTO fact_auth_events (event_timestamp, user_id, source_ip, dest_host_id, success)
VALUES
('2025-01-02 08:10', 1, '192.168.1.10', 1, true),
('2025-01-02 08:15', 2, '192.168.1.11', 3, true),
('2025-01-02 09:00', 3, '192.168.1.12', 3, true);

-- Failed login attempts (simulate attacks)
INSERT INTO fact_auth_events (event_timestamp, user_id, source_ip, dest_host_id, success)
VALUES
('2025-01-03 10:00', 2, '203.0.113.5', 3, false),
('2025-01-03 10:01', 2, '203.0.113.5', 3, false),
('2025-01-03 10:02', 2, '203.0.113.5', 3, false), -- triggers brute force
('2025-01-03 10:03', 2, '203.0.113.5', 3, true);  -- successful brute force

-- Password spraying example
INSERT INTO fact_auth_events (event_timestamp, user_id, source_ip, dest_host_id, success)
VALUES
('2025-01-04 11:00', 3, '198.51.100.7', 1, false),
('2025-01-04 11:01', 4, '198.51.100.7', 1, false),
('2025-01-04 11:02', 5, '198.51.100.7', 2, false),
('2025-01-04 11:03', 6, '198.51.100.7', 4, false),
('2025-01-04 11:04', 7, '198.51.100.7', 5, false); -- triggers password spraying

-- More attacks on critical assets
INSERT INTO fact_auth_events (event_timestamp, user_id, source_ip, dest_host_id, success)
VALUES
('2025-01-05 12:00', 1, '203.0.113.9', 2, false),
('2025-01-05 12:01', 2, '203.0.113.9', 4, false),
('2025-01-05 12:02', 5, '203.0.113.8', 2, false);
