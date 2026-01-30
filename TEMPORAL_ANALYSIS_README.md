# Temporal Analysis Feature - Implementation Guide

## Overview
This enhancement adds time-based attack pattern detection to the Security Data Warehouse. It helps identify:
- When attacks occur (hour of day, day of week)
- Business hours vs off-hours patterns
- High-risk time periods (nights, weekends)
- Anomalous user activity outside normal hours

## What Was Added

### 1. **dim_time Table** (Database Layer)
A dimension table with pre-computed time attributes for fast analysis.

**Key Columns:**
- `hour` - 0-23 (for hourly analysis)
- `day_of_week` - 0=Sunday, 6=Saturday
- `is_weekend` - Boolean flag
- `is_business_hours` - TRUE if Mon-Fri 8 AM - 6 PM
- `is_night_shift` - TRUE if 10 PM - 6 AM
- `risk_period` - HIGH_RISK, MEDIUM_RISK, or NORMAL

**Why This Design:**
- Pre-computing saves calculation time in queries
- One row per hour (8,760 rows for full year)
- Easy to join: `JOIN dim_time ON DATE_TRUNC('hour', event_timestamp) = full_timestamp`

### 2. **Temporal Analysis Queries** (Analytics Layer)
Seven new SQL queries that use dim_time:

| Query | Purpose | Use Case |
|-------|---------|----------|
| Attacks by Hour | Shows which hours have most attacks | Schedule SOC coverage |
| Business Hours Comparison | Off-hours vs work hours | Detect external attackers |
| Day of Week Patterns | Weekend vs weekday | Identify automated attacks |
| High-Risk Period Attacks | Nights/weekends only | Prioritize investigations |
| Night Shift Anomalies | Non-IT users at night | Insider threat detection |
| Hourly Heatmap | Visual attack intensity | Management reporting |
| Admin Off-Hours Activity | Privileged accounts at night | Compromised admin detection |

### 3. **Enhanced Dashboard** (Visualization Layer)
Three new interactive charts:

**Hourly Heatmap**
- Bar chart showing attacks per hour (0-23)
- Color-coded by attack count (darker = more attacks)
- Hover shows risk_period classification

**Business Hours Comparison**
- Side-by-side comparison: work hours vs off-hours
- Metrics: total attacks, unique attackers, success rate
- Helps identify if attackers prefer nights

**Day of Week Pattern**
- Bar chart with 7 bars (Sunday - Saturday)
- Weekends highlighted in red
- Shows if attacks spike on weekends

## Installation Steps

### Step 1: Create the Time Dimension
```bash
# Connect to your database
psql -U postgres -d security_dwh

# Run the time dimension script
\i 04_create_dim_time.sql
```

**What happens:**
1. Creates `dim_time` table
2. Populates with 8,760 rows (one per hour in 2025)
3. Adds indexes for fast lookups
4. Shows sample data for verification

**Expected output:**
```
✅ Time dimension created and populated successfully!
 total_hours |      earliest       |       latest        
-------------|---------------------|---------------------
        8760 | 2025-01-01 00:00:00 | 2025-12-31 23:00:00
```

### Step 2: Test the Temporal Queries
```bash
# Run example queries
\i 08_temporal_analysis_queries.sql
```

**What you'll see:**
- Attack distribution by hour (Query 1)
- Business hours vs off-hours comparison (Query 2)
- Weekend vs weekday patterns (Query 3)
- More specialized queries for specific use cases

### Step 3: Generate Enhanced Dashboard
```bash
# Copy the enhanced Python script
cp generate_dashboard_temporal.py generate_dashboard.py

# Copy the enhanced HTML template
cp dashboard_temporal.html templates/dashboard_temporal.html

# Run the dashboard generator
python generate_dashboard.py
```

**Output:**
- `output/index.html` - Interactive dashboard with temporal analysis
- `output/soc_dashboard.json` - Raw data including temporal metrics

### Step 4: View the Dashboard
```bash
# Open in browser (Mac)
open output/index.html

# Or (Linux)
xdg-open output/index.html

# Or (Windows)
start output/index.html
```

## How to Read the Temporal Charts

### Hourly Heatmap
```
High bars at 22:00-06:00 = Attackers prefer nights (less monitoring)
Peaks at 09:00, 13:00, 17:00 = Normal user activity (logins, lunch returns, end-of-day)
```

### Business Hours Comparison
```
Off-Hours > Business Hours = External attackers
Business Hours > Off-Hours = Insider threats or lateral movement
Success rate higher off-hours = Weaker monitoring at night
```

### Day of Week Pattern
```
Weekend spikes = Automated attacks (bots don't take weekends off)
Monday spike = Weekend attack aftermath being discovered
Flat pattern = Distributed attack campaign
```

## Example Use Cases

### Use Case 1: Detecting Compromised Admin Account
**Query:**
```sql
SELECT * FROM fact_auth_events e
JOIN dim_users u ON e.user_id = u.user_id
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE u.is_privileged = TRUE
  AND t.is_business_hours = FALSE;
```

**Interpretation:**
- Admin "jdoe-admin" logged in at 3 AM on Saturday
- Not in IT Ops (no scheduled maintenance)
- Source IP is external (not VPN)
- **Action:** Immediately lock account, force password reset

### Use Case 2: Password Spraying Campaign
**Query:**
```sql
SELECT 
    t.hour,
    COUNT(*) as attack_count,
    COUNT(DISTINCT e.user_id) as users_targeted
FROM fact_auth_events e
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE e.success = FALSE
GROUP BY t.hour
HAVING COUNT(DISTINCT e.user_id) >= 5;
```

**Interpretation:**
- Attacks concentrated at 3-4 AM
- 8+ different users targeted per hour
- All from same external IP
- **Action:** Block IP, alert users, check for any successes

### Use Case 3: Insider Threat - Finance User at Night
**Query:**
```sql
SELECT * FROM fact_auth_events e
JOIN dim_users u ON e.user_id = u.user_id
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE u.department = 'Finance'
  AND t.is_night_shift = TRUE
  AND e.success = TRUE;
```

**Interpretation:**
- Finance user "kwilson" logged in at 2 AM
- Accessed engineering systems
- No scheduled work, not on-call
- **Action:** Interview user, review accessed files, check for data exfiltration

## Performance Considerations

### Why Pre-compute Time Attributes?
**Without dim_time:**
```sql
-- Slow: Calculates for every row
WHERE EXTRACT(HOUR FROM event_timestamp) BETWEEN 8 AND 17
  AND EXTRACT(DOW FROM event_timestamp) BETWEEN 1 AND 5
```

**With dim_time:**
```sql
-- Fast: Simple boolean lookup
JOIN dim_time t ON ...
WHERE t.is_business_hours = TRUE
```

**Benefit:** 10-100x faster on large datasets (millions of events)

### Index Usage
```sql
-- These queries use indexes efficiently:
WHERE t.is_business_hours = TRUE  -- idx_dim_time_business_hours
WHERE t.risk_period = 'HIGH_RISK'  -- idx_dim_time_risk_period
WHERE t.date = '2025-01-20'         -- idx_dim_time_date
```

## Customization

### Adjust Business Hours
Edit `04_create_dim_time.sql`:
```sql
-- Change from 8 AM - 6 PM to 9 AM - 5 PM
AND EXTRACT(HOUR FROM ts) BETWEEN 9 AND 16  -- 9 AM to 4 PM
```

### Adjust Risk Classification
```sql
-- Make nights even more sensitive
WHEN EXTRACT(HOUR FROM ts) >= 20 OR EXTRACT(HOUR FROM ts) < 7 THEN 'HIGH_RISK'
-- Was: >= 22 OR < 6
```

### Add Shift-Based Analysis
```sql
-- Add columns for 24/7 operations
ALTER TABLE dim_time ADD COLUMN shift VARCHAR(20);

UPDATE dim_time SET shift = 
    CASE 
        WHEN hour BETWEEN 6 AND 13 THEN 'DAY_SHIFT'
        WHEN hour BETWEEN 14 AND 21 THEN 'EVENING_SHIFT'
        ELSE 'NIGHT_SHIFT'
    END;
```

## Troubleshooting

### Issue: No data in temporal queries
**Check:**
```sql
-- Verify dim_time is populated
SELECT COUNT(*) FROM dim_time;
-- Should return 8760

-- Verify join is working
SELECT COUNT(*) FROM fact_auth_events e
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp;
-- Should match your event count
```

### Issue: Dashboard not showing temporal charts
**Check:**
1. Template path: `templates/dashboard_temporal.html` exists
2. Python script: Using `generate_dashboard_temporal.py`
3. Console output: Look for "3 temporal analysis" message

### Issue: Performance is slow
**Solution:**
```sql
-- Verify indexes exist
SELECT indexname FROM pg_indexes WHERE tablename = 'dim_time';

-- If missing, create them
CREATE INDEX idx_dim_time_timestamp ON dim_time(full_timestamp);
```

## Next Steps

### Advanced Enhancements
1. **Machine Learning Baselines**
   - Train model on "normal" hourly patterns
   - Auto-detect anomalies (e.g., 3 AM spike on quiet system)

2. **Shift-Based Monitoring**
   - Different thresholds for 24/7 operations
   - Correlate with shift schedules

3. **Holiday Calendar**
   - Add `is_holiday` column
   - Activity on holidays = higher suspicion

4. **Real-Time Alerting**
   - Trigger alert when high-risk period attack detected
   - Send to Slack/email during off-hours

5. **Comparative Analysis**
   - "Today vs last Monday" comparison
   - Seasonal trend analysis (Q1 vs Q4)

## Interview Talking Points

**Question:** "How does temporal analysis improve threat detection?"

**Answer:** 
"Temporal analysis adds context that pure event detection misses. For example, 10 failed logins might be normal during business hours (users forgetting passwords), but suspicious at 3 AM. By classifying time periods as HIGH_RISK, MEDIUM_RISK, or NORMAL, we can:

1. **Prioritize alerts:** Off-hours admin activity = page SOC immediately
2. **Reduce false positives:** Don't alert on morning login spikes
3. **Detect insider threats:** Finance user at midnight = investigate
4. **Optimize resources:** Schedule extra SOC analysts during peak attack hours

The dim_time table makes this analysis fast by pre-computing time attributes, so queries don't recalculate 'is it business hours?' for every single event."

---

## Summary

**Time Investment:** ~3 hours
- 1 hour: Create dim_time table + indexes
- 1 hour: Write temporal queries
- 1 hour: Update dashboard + test

**Value Added:**
- ✅ Detect attacks by time-of-day patterns
- ✅ Identify off-hours anomalies
- ✅ Prioritize high-risk period incidents
- ✅ Three new interactive visualizations
- ✅ Foundation for advanced ML anomaly detection

**Files Created:**
- `04_create_dim_time.sql` - Table creation + population
- `08_temporal_analysis_queries.sql` - 7 example queries
- `generate_dashboard_temporal.py` - Enhanced dashboard
- `dashboard_temporal.html` - Updated template