-- =====================================================
-- SECURITY DATA WAREHOUSE - DATABASE INITIALIZATION
-- =====================================================
-- File: 01_create_database.sql
-- Purpose: Create the security data warehouse database
-- Run as: PostgreSQL superuser (postgres)
-- =====================================================

-- Drop existing database (CAUTION: This deletes all data!)
DROP DATABASE IF EXISTS security_dwh;

-- Create fresh database
CREATE DATABASE security_dwh
    WITH 
    OWNER = postgres
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    TEMPLATE = template0;

-- Connect to the new database
\c security_dwh

-- Enable UUID extension (for future use with unique identifiers)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Display confirmation
SELECT 'Security Data Warehouse database created successfully!' AS status;