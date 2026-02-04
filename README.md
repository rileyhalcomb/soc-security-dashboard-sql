# 🛡️ Security Data Warehouse & SOC Dashboard

**Enterprise Security Operations Center (SOC) Analytics Platform**

A production-ready security data warehouse with automated threat detection queries and interactive dashboard for monitoring authentication attacks and insider threats.

---

## 📋 Project Overview

This project implements a complete **security analytics pipeline** using PostgreSQL, Python, and Plotly for real-time threat detection and visualization. It demonstrates:

- ✅ **Data warehouse design** with star schema (fact + dimension tables)
- ✅ **7 advanced SQL threat detection queries** mapping to MITRE ATT&CK framework
- ✅ **Automated dashboard generation** with interactive charts
- ✅ **Real-world attack scenarios** (brute force, password spraying, lateral movement)

**Perfect for:** Cybersecurity analysts, SOC teams, data engineers, or security-focused developers building their portfolio.

---

## 🎯 Key Features

### Threat Detection Queries
| Query | Attack Type | MITRE ATT&CK | Priority |
|-------|-------------|--------------|----------|
| **01_brute_force_detection** | Multiple password guesses on single account | T1110.001 | HIGH |
| **02_password_spraying** | Single password across multiple accounts | T1110.003 | CRITICAL |
| **03_successful_compromise** | Brute force attack that succeeded | T1110 + T1078 | CRITICAL |
| **04_critical_assets** | Attacks on high-value infrastructure | T1078 | HIGH |
| **05_privileged_monitoring** | Admin account activity audit trail | T1078.002 | CONTINUOUS |
| **06_external_ip_summary** | Threat actor intelligence profiling | TA0001 | VARIES |
| **07_account_activity** | User behavior analytics (UEBA) | T1078 | VARIES |

### Dashboard Capabilities
- 📊 **4 interactive Plotly charts** (pie, bar, scatter, timeline)
- 🎯 **Threat actor severity classification** (Critical/High/Medium/Low)
- 🏢 **Critical asset monitoring** with attack counts
- 📈 **Attack timeline visualization** showing success/failure patterns
- 📄 **JSON export** for integration with SIEM/SOAR tools

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Data Warehouse Layer                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ dim_users    │  │ dim_hosts    │  │ dim_time     │       │
│  │ - user_id    │  │ - host_id    │  │ - date       │       │
│  │ - username   │  │ - hostname   │  │ - hour       │       │
│  │ - department │  │ - criticality│  │ - day_of_week│       │
│  │ - etc...     │  │ - etc...     │  │ - etc...     │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│           │               │                                 │
│           └───────┬───────┘                                 │
│                   ▼                                         │
│         ┌──────────────────────┐                            │
│         │ fact_auth_events     │                            │
│         │ - event_id           │                            │
│         │ - user_id (FK)       │                            │
│         │ - dest_host_id (FK)  │                            │
│         │ - source_ip          │                            │
│         │ - success (bool)     │                            │
│         │ - event_timestamp    │                            │
│         │ - etc...             │                            │
│         └──────────────────────┘                            │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Analytics Layer (SQL)                     │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │
│  │ Brute Force    │  │ Password Spray │  │ Compromised    │ │ 
│  │ Detection      │  │ Detection      │  │ Accounts       │ │
│  └────────────────┘  └────────────────┘  └────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              Visualization Layer (Python + Plotly)          │
│  generate_dashboard.py → Interactive HTML Dashboard         │
└─────────────────────────────────────────────────────────────┘
```

**Design Principles:**
- **Star Schema**: Optimized for analytical queries (fast JOINs)
- **Separation of Concerns**: Detection logic in SQL, presentation in Python
- **MITRE ATT&CK Mapping**: Industry-standard threat categorization
- **Tunable Thresholds**: Easy to adjust sensitivity (e.g., 3 vs 5 failed logins)

---

## 🚀 Quick Start

### Prerequisites
- PostgreSQL 12+ installed
- Python 3.8+ with pip
- Basic SQL knowledge

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/security-data-warehouse.git
cd security-data-warehouse
```

**2. Set up Python environment**
```bash
pip install -r requirements.txt
```

**3. Create the database**
```bash
# Connect to PostgreSQL
psql -U postgres

# Run the setup script
\i sql/setup/01_create_database.sql
\i sql/setup/02_create_tables.sql
\i sql/setup/03_load_sample_data.sql
```

**4. Generate the dashboard**
```bash
python generate_dashboard.py
```

**5. View the results**
```bash
# Dashboard opens in browser automatically, or open manually:
open output/index.html
```

---

## 📊 Sample Dashboard Output

The generated dashboard includes:

### Section 1: Overview Metrics
```
Total Events: 52
Failed Logins: 27 (51.9%)
Successful Logins: 25 (48.1%)
External Threats: 4 IPs
```

### Section 2: Critical Incidents
- ✅ **Successful Brute Force**: admin from 185.220.101.47
- ✅ **Password Spraying**: 198.51.100.42 targeting 8 users
- ✅ **Critical Assets**: dc-corp-01 (4 attacks), database-prod-01 (1 attack)

### Section 3: Threat Actors
| IP Address | Severity | Attempts | Success | Classification |
|------------|----------|----------|---------|----------------|
| 185.220.101.47 | 🔴 Critical | 5 | 1 | Successful Brute Force |
| 198.51.100.42 | 🔴 Critical | 8 | 0 | Password Spraying |
| 10.0.3.78 | 🟡 Medium | 3 | 1 | Internal Threat |

---

## 📁 Project Structure

```
security-data-warehouse/
│
├── README.md                          # This file
├── ARCHITECTURE.md                    # Detailed technical design
├── requirements.txt                   # Python dependencies
│
├── sql/
│   ├── setup/                        # Database initialization
│   │   ├── 01_create_database.sql
│   │   ├── 02_create_tables.sql
│   │   └── 03_load_sample_data.sql
│   │
│   ├── queries/                      # Threat detection queries
│   │   ├── 01_brute_force_detection.sql
│   │   ├── 02_password_spraying_detection.sql
│   │   ├── 03_successful_compromise_detection.sql
│   │   ├── 04_attacks_on_critical_assets.sql
│   │   ├── 05_privileged_account_monitoring.sql
│   │   ├── 06_external_ip_threat_summary.sql
│   │   └── 07_account_activity_summary.sql
│   │
│   └── dashboard/
│       └── executive_security_dashboard.sql
│
├── python/
│   └── generate_dashboard.py         # Dashboard generator
│
├── templates/
│   └── dashboard.html                # Jinja2 template
│
└── output/                           # Generated artifacts
    ├── index.html                    # Interactive dashboard
    └── soc_dashboard.json            # Raw metrics
```

---

## 🔍 Query Explanations

### Example: Brute Force Detection

**Business Logic:**
> "Show me any IP that failed to login as the same user 3+ times"

**SQL Implementation:**
```sql
SELECT 
    u.username,
    COUNT(*) as failed_attempts,
    e.source_ip,
    MIN(e.event_timestamp) as first_attempt,
    MAX(e.event_timestamp) as last_attempt
FROM fact_auth_events e
JOIN dim_users u ON e.user_id = u.user_id 
WHERE e.success = FALSE
GROUP BY u.username, e.source_ip
HAVING COUNT(*) >= 3
ORDER BY failed_attempts DESC;
```

**Why This Matters:**
- Detects targeted attacks on specific accounts
- Threshold of 3 balances false positives (typos) vs real attacks
- Prioritizes admin accounts (`is_privileged = TRUE`)

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed explanations of all 7 queries.

---

## 🛠️ Configuration

### Database Connection
Edit `generate_dashboard.py`:
```python
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'security_dwh',
    'user': 'your_username',
    'password': 'your_password'
}
```

### Detection Thresholds
Adjust sensitivity in SQL queries:
```sql
-- Brute force: 3 → 5 attempts for less sensitive environments
HAVING COUNT(*) >= 3  -- Change to 5

-- Password spraying: 5 → 10 users for larger organizations
HAVING COUNT(DISTINCT user_id) >= 5  -- Change to 10
```

---

## 📚 Learning Resources

### SQL Concepts Demonstrated
- ✅ JOINs (INNER, LEFT) for dimensional modeling
- ✅ GROUP BY and HAVING for aggregations
- ✅ CTEs (WITH clauses) for query readability
- ✅ Window functions for ranking
- ✅ CASE statements for conditional logic
- ✅ String aggregation (STRING_AGG)

### Security Concepts
- ✅ MITRE ATT&CK framework mapping
- ✅ User Behavior Analytics (UEBA)
- ✅ Threat actor profiling
- ✅ Baseline vs anomaly detection
- ✅ Insider threat indicators

### Interview Prep
Each query includes:
- Plain English explanation
- "Why this matters" security impact
- Common interview questions + answers
- Real-world examples

---

## 🎓 Use Cases

### For Security Analysts
- Run queries to investigate incidents
- Tune thresholds for your environment
- Export JSON to feed SIEM/SOAR tools

### For Data Engineers
- Learn star schema design
- Practice complex SQL JOINs and aggregations
- Understand analytics optimization

### For Hiring Managers
- **Demonstrates:** SQL proficiency, security knowledge, data visualization
- **Complexity Level:** Intermediate to advanced
- **Time Investment:** ~40 hours (design + queries + dashboard)

---

## 🔮 Future Enhancements

**Planned Improvements:**
- [ ] Add `dim_time` table for temporal analysis (hour-of-day patterns)
- [ ] Machine learning anomaly detection (scikit-learn)
- [ ] Geo-location lookup for external IPs (MaxMind GeoIP)
- [ ] Real-time alerting (email/Slack integration)
- [ ] Integration with cloud SIEM (Splunk, ELK, Sentinel)

**Advanced Projects:**
- [ ] CLI tool for parameterized threat hunting
- [ ] Attack path visualization (Neo4j graph database)
- [ ] Compliance reporting (SOX, HIPAA, PCI-DSS)

---

## 📝 Sample Data Scenarios

The project includes 8 pre-loaded attack scenarios:

1. **Brute Force Success**: Russian IP successfully breaks into admin account
2. **Password Spraying**: Single IP tries same password across 8 users
3. **Lateral Movement**: Finance user accessing engineering servers
4. **Insider Threat**: Employee accessing systems at 3 AM
5. **Service Account**: Automated backup process (baseline normal)
6. **Dormant Account**: Old account suddenly active
7. **Impossible Travel**: User logs in from 5 different countries in 1 hour
8. **Privilege Escalation**: Non-admin accessing domain controller

Each scenario is documented in `sql/setup/03_load_sample_data.sql`.

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-query`)
3. Document your changes (comments + README updates)
4. Submit a pull request

**Ideas for contributions:**
- Additional detection queries (credential stuffing, DDoS)
- Integration with threat intelligence feeds
- Dashboard UI improvements

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---[requirements.txt](../../../../Downloads/requirements.txt)

## 👤 Author

**Riley Halcomb**
- LinkedIn: [rileyhalcomb](https://linkedin.com/in/rileyhalcomb)
- Portfolio: [themiraiproject](https://themiraiproject.vercel.app/)
- Email: rileyhalcomb@proton.me

**Skills Demonstrated:**
- SQL (PostgreSQL)
- Python (pandas, plotly, jinja2)
- Security Analytics
- Data Visualization
- MITRE ATT&CK Framework

---

## 🙏 Acknowledgments

- MITRE ATT&CK for threat categorization framework
- Plotly for interactive visualization library
- PostgreSQL community for excellent documentation

---

## 📊 Project Stats

- **Lines of Code:** ~2,000 (SQL + Python)
- **Database:** 4 tables, 52 sample events
- **Queries:** 7 threat detection + 1 executive dashboard
- **Visualizations:** 4 interactive charts
- **Documentation:** 500+ lines of in-code comments

---

**⭐ If this project helped you, please star the repository!**
