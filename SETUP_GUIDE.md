# 🚀 Setup Guide - Security Data Warehouse

## Quick Start (5 minutes)

### Option A: Automated Setup (Recommended)
```bash
# 1. Run the automated setup script
./setup.sh

# 2. Open the dashboard
open output/index.html
```

### Option B: Manual Setup (Step-by-Step)

---

## Prerequisites

**Required Software:**
- PostgreSQL 12+ ([Download](https://www.postgresql.org/download/))
- Python 3.8+ ([Download](https://www.python.org/downloads/))
- pip (included with Python)

**Check your installations:**
```bash
# PostgreSQL
psql --version
# Should show: psql (PostgreSQL) 12.x or higher

# Python
python3 --version
# Should show: Python 3.8.x or higher

# pip
pip3 --version
# Should show: pip 20.x or higher
```

---

## Step 1: Install Python Dependencies

```bash
# Navigate to project directory
cd security-data-warehouse

# Install required packages
pip3 install -r requirements.txt

# Verify installation
python3 -c "import psycopg2, pandas, plotly; print('✅ All packages installed')"
```

**What this installs:**
- `psycopg2-binary` - PostgreSQL database connector
- `pandas` - Data manipulation library
- `plotly` - Interactive chart library
- `jinja2` - HTML template engine

---

## Step 2: Create the Database

### Connect to PostgreSQL
```bash
# Connect as superuser
psql -U postgres

# Or if using password:
psql -U postgres -W
```

### Run Setup Scripts
```sql
-- Script 1: Create database
\i sql/setup/01_create_database.sql
-- Output: "Security Data Warehouse database created successfully!"

-- Script 2: Create tables
\i sql/setup/02_create_tables.sql
-- Output: "Tables and indexes created successfully!"

-- Script 3: Load sample data
\i sql/setup/03_load_sample_data.sql
-- Output: "✅ Sample data loaded: 52 events across 9 attack scenarios"
```

**Verify tables exist:**
```sql
\dt
```
Should show:
```
 Schema |      Name        | Type  |  Owner   
--------+------------------+-------+----------
 public | dim_hosts        | table | postgres
 public | dim_users        | table | postgres
 public | fact_auth_events | table | postgres
```

---

## Step 3: Configure Database Connection

Edit `python/generate_dashboard.py`:

```python
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'security_dwh',
    'user': 'postgres',           # ← Change to your username
    'password': 'your_password'   # ← Change to your password
}
```

**Security Note:** Never commit passwords to version control!
- For production, use environment variables:
```python
import os
DB_CONFIG = {
    'password': os.getenv('DB_PASSWORD')
}
```

---

## Step 4: Generate the Dashboard

```bash
# Run the dashboard generator
python3 python/generate_dashboard.py
```

**Expected output:**
```
SOC Dashboard Generator Starting...
Output Directory: /path/to/output
Database connection established
Query executed - 4 rows returned
Query executed - 4 rows returned
Query executed - 7 rows returned
Query executed - 52 rows returned
Metrics generated: 52 events analyzed
Creating charts...
4 interactive charts created
JSON exported: output/soc_dashboard.json
Dashboard HTML created: output/index.html
SOC Dashboard Generation Complete
```

---

## Step 5: View the Dashboard

```bash
# Open in default browser
open output/index.html

# Or manually navigate to:
file:///path/to/security-data-warehouse/output/index.html
```

**What you'll see:**
- 📊 Overview Metrics (52 events, 27 failed, 25 successful)
- 🔴 Critical Incidents (brute force, password spraying)
- 🎯 Threat Actors (4 external IPs analyzed)
- 📈 Interactive charts (pie, bar, scatter, timeline)

---

## Step 6: Run Threat Detection Queries

### From psql:
```sql
-- Connect to database
\c security_dwh

-- Run brute force detection
\i sql/queries/01_brute_force_detection.sql

-- Run password spraying detection
\i sql/queries/02_password_spraying_detection.sql

-- Run all queries in sequence
\i sql/queries/01_brute_force_detection.sql
\i sql/queries/02_password_spraying_detection.sql
\i sql/queries/03_successful_compromise_detection.sql
\i sql/queries/04_attacks_on_critical_assets.sql
\i sql/queries/05_privileged_account_monitoring.sql
\i sql/queries/06_external_ip_threat_summary.sql
\i sql/queries/07_account_activity_summary.sql
```

### From DBeaver/pgAdmin:
1. Connect to `security_dwh` database
2. Open query file
3. Execute (F5 or Ctrl+Enter)

---

## Troubleshooting

### Issue: "psycopg2 installation failed"
**Solution:**
```bash
# macOS
brew install postgresql

# Ubuntu/Debian
sudo apt-get install libpq-dev python3-dev

# Then retry
pip3 install psycopg2-binary
```

### Issue: "Database connection refused"
**Check if PostgreSQL is running:**
```bash
# macOS
brew services list | grep postgresql

# Linux
sudo systemctl status postgresql

# Start if not running
brew services start postgresql  # macOS
sudo systemctl start postgresql # Linux
```

### Issue: "Permission denied for database"
**Grant permissions:**
```sql
-- Connect as superuser
psql -U postgres

-- Create user with proper permissions
CREATE USER your_username WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE security_dwh TO your_username;
```

### Issue: "No module named 'psycopg2'"
**Verify Python path:**
```bash
# Check which Python you're using
which python3

# Install to correct Python
python3 -m pip install -r requirements.txt
```

### Issue: "Dashboard shows no data"
**Verify sample data loaded:**
```sql
SELECT COUNT(*) FROM fact_auth_events;
-- Should return 52

SELECT COUNT(*) FROM dim_users;
-- Should return 11

SELECT COUNT(*) FROM dim_hosts;
-- Should return 9
```

---

## Next Steps

### Customize for Your Environment

**1. Adjust Detection Thresholds**
Edit SQL queries to tune sensitivity:
```sql
-- In 01_brute_force_detection.sql
HAVING COUNT(*) >= 3  -- Change to 5 for less sensitive
```

**2. Add Your Own Data**
```sql
-- Insert real users
INSERT INTO dim_users (username, department, is_privileged) 
VALUES ('real.user@company.com', 'Engineering', FALSE);

-- Insert real events
INSERT INTO fact_auth_events (user_id, dest_host_id, source_ip, success, event_timestamp)
VALUES (1, 1, '10.0.1.100', TRUE, NOW());
```

**3. Schedule Automated Reports**
```bash
# Add to crontab (daily at 9 AM)
0 9 * * * cd /path/to/project && python3 python/generate_dashboard.py
```

**4. Integrate with SIEM**
```bash
# Export JSON for Splunk/ELK
cat output/soc_dashboard.json | curl -X POST http://siem-server/api/ingest
```

---

## Learning Path

### Beginner (You are here!)
- ✅ Set up database
- ✅ Run pre-built queries
- ✅ Generate dashboard

### Intermediate (Week 2-3)
- [ ] Modify detection thresholds
- [ ] Add new queries
- [ ] Customize dashboard charts

### Advanced (Week 4+)
- [ ] Add `dim_time` table for temporal analysis
- [ ] Build CLI tool for ad-hoc queries
- [ ] Integrate machine learning anomaly detection

---

## Resources

### PostgreSQL Documentation
- [SQL Tutorial](https://www.postgresql.org/docs/current/tutorial.html)
- [psql Commands](https://www.postgresql.org/docs/current/app-psql.html)

### Python Libraries
- [pandas User Guide](https://pandas.pydata.org/docs/user_guide/index.html)
- [Plotly Documentation](https://plotly.com/python/)

### Security Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## Getting Help

**Questions?** Open an issue on GitHub:
```
https://github.com/yourusername/security-data-warehouse/issues
```

**Found a bug?** Submit a pull request!

**Want to contribute?** See [CONTRIBUTING.md](CONTRIBUTING.md)

---

**✅ Setup Complete! You're ready to start detecting threats.**
