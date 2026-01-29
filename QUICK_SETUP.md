# ⚡ Quick Setup Reference

## Files You Downloaded

### **Setup Files (Run in order):**
1. `01_create_database.sql` - Creates the database
2. `02_create_tables.sql` - Creates tables and indexes
3. `03_load_sample_data.sql` - Loads 52 sample events

### **Query Files (7 threat detection queries):**
- In the `queries/` folder
- Run individually in psql to detect attacks

### **Python & Config:**
- `generate_dashboard.py` - Dashboard generator
- `requirements.txt` - Python dependencies

### **Documentation:**
- `README.md` - Project overview
- `SETUP_GUIDE.md` - Detailed instructions

---

## 🚀 Fastest Setup (Copy & Paste)

### Step 1: Install Python Packages
```bash
pip install psycopg2-binary pandas plotly jinja2
```

### Step 2: Run SQL Setup (in psql)
```sql
-- Connect to PostgreSQL
psql -U postgres

-- Run each file
\i 01_create_database.sql
\i 02_create_tables.sql
\i 03_load_sample_data.sql
```

### Step 3: Configure Python
Open `generate_dashboard.py` and update:
```python
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'security_dwh',
    'user': 'postgres',        # ← Your username
    'password': 'your_password' # ← Your password
}
```

### Step 4: Generate Dashboard
```bash
python3 generate_dashboard.py
open output/index.html
```

---

## 📊 What Each SQL File Does

**01_create_database.sql:**
- Drops existing database (if any)
- Creates new `security_dwh` database
- Sets encoding to UTF-8

**02_create_tables.sql:**
- Creates `dim_users` (11 users)
- Creates `dim_hosts` (9 servers)
- Creates `fact_auth_events` (logs)
- Adds 6 indexes for performance

**03_load_sample_data.sql:**
- Loads 9 attack scenarios:
  1. Password spraying (8 users targeted)
  2. Successful brute force (Russian IP)
  3. Internal threat (insider attack)
  4. Lateral movement (Finance → Engineering)
  5. Normal VPN logins
  6. Admin maintenance
  7. Service account automation
  8. Impossible travel
  9. Normal typos

---

## 🔍 Running Queries

### From psql:
```sql
\c security_dwh

-- Run brute force detection
\i queries/01_brute_force_detection.sql

-- Run password spraying
\i queries/02_password_spraying_detection.sql

-- Run all queries
\i queries/01_brute_force_detection.sql
\i queries/02_password_spraying_detection.sql
\i queries/03_successful_compromise_detection.sql
\i queries/04_attacks_on_critical_assets.sql
\i queries/05_privileged_account_monitoring.sql
\i queries/06_external_ip_threat_summary.sql
\i queries/07_account_activity_summary.sql
```

### From DBeaver/pgAdmin:
1. Connect to `security_dwh` database
2. Open query file
3. Execute (F5)

---

## 📁 Project Structure

```
Downloaded Files:
├── 01_create_database.sql      # Database setup
├── 02_create_tables.sql        # Schema creation
├── 03_load_sample_data.sql     # Sample data
├── README.md                   # Overview
├── SETUP_GUIDE.md              # Detailed guide
├── requirements.txt            # Python deps
├── generate_dashboard.py       # Dashboard script
└── queries/                    # 7 SQL queries
    ├── 01_brute_force_detection.sql
    ├── 02_password_spraying_detection.sql
    ├── 03_successful_compromise_detection.sql
    ├── 04_attacks_on_critical_assets.sql
    ├── 05_privileged_account_monitoring.sql
    ├── 06_external_ip_threat_summary.sql
    └── 07_account_activity_summary.sql
```

---

## ✅ Verification Commands

### Check database exists:
```sql
\l security_dwh
```

### Check tables exist:
```sql
\c security_dwh
\dt
-- Should show: dim_users, dim_hosts, fact_auth_events
```

### Check data loaded:
```sql
SELECT COUNT(*) FROM fact_auth_events;
-- Should return: 52

SELECT COUNT(*) FROM dim_users;
-- Should return: 11

SELECT COUNT(*) FROM dim_hosts;
-- Should return: 9
```

---

## 🎯 Expected Results

### Sample Query Output (Brute Force Detection):
```
username | department  | is_privileged | failed_attempts | source_ip      
---------|-------------|---------------|-----------------|----------------
admin    | IT Security | true          | 4               | 185.220.101.47
dbaker   | Engineering | false         | 3               | 10.0.3.78
```

### Dashboard Metrics:
- Total Events: 52
- Failed Logins: 27 (51.9%)
- Successful Logins: 25 (48.1%)
- External Threats: 4 IPs

---

## 💡 Tips

**Database Connection Issues?**
```bash
# Check PostgreSQL is running
brew services list | grep postgresql  # macOS
sudo systemctl status postgresql      # Linux

# Start if needed
brew services start postgresql        # macOS
sudo systemctl start postgresql       # Linux
```

**Python Import Errors?**
```bash
# Verify installation
python3 -c "import psycopg2, pandas, plotly; print('OK')"

# Reinstall if needed
pip3 install --upgrade -r requirements.txt
```

**Need to Reset?**
```sql
-- Drop and recreate everything
DROP DATABASE IF EXISTS security_dwh;
\i 01_create_database.sql
\i 02_create_tables.sql
\i 03_load_sample_data.sql
```

---

## 📚 Next Steps

1. **Get it working** - Follow steps above
2. **Understand the queries** - Read comments in SQL files
3. **Run queries manually** - See what each detects
4. **Generate dashboard** - Run Python script
5. **Customize** - Adjust thresholds, add queries
6. **Portfolio** - Upload to GitHub, add to resume

---

**Questions?** Check SETUP_GUIDE.md for detailed instructions!
