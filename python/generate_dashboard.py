"""
SOC Security Dashboard Generator
Advanced automated reporting system for security data warehouse
"""
from csv import excel

import psycopg2
import pandas as pd
import json
from datetime import datetime
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
from jinja2 import Template
import sys

# Configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'security_dwh',
    'user': 'postgres',
    'password': 'Marissa2004*'
}

# Output paths
OUTPUT_DIR = Path(__file__).parent / 'output'
TEMPLATE_DIR = Path(__file__).parent / 'templates'
OUTPUT_DIR.mkdir(exist_ok=True)
TEMPLATE_DIR.mkdir(exist_ok=True)

print("SOC Dashboard Generator Starting...")
print(f"Output Directory: {OUTPUT_DIR}")

def connect_db():
    """Connect to PostgreSQL database"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        print("Database connection established")
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}")
        sys.exit(1)

def run_query(conn, query):
    """Execute SQL query and return pandas DataFrame"""
    try:
        df = pd.read_sql_query(query, conn)
        print(f"Query executed - {len(df)} rows returned")
        return df
    except Exception as e:
        print(f"Query failed: {e}")
        return None

# EDIT THIS TO CONFORM
DASHBOARD_QUERY = """
SELECT 
    CASE 
        -- Password Spraying: Multiple users from same IP
        WHEN source_ip IN (
            SELECT source_ip FROM fact_auth_events
            WHERE success = FALSE
            GROUP BY source_ip
            HAVING COUNT(DISTINCT user_id) >= 5
        ) THEN 'Password Spraying'

        -- Brute Force: Multiple failures then success from same IP
        WHEN user_id IN (
            SELECT e1.user_id 
            FROM fact_auth_events e1
            WHERE e1.success = FALSE
            GROUP BY e1.user_id, e1.source_ip
            HAVING COUNT(*) >= 3
        ) AND source_ip NOT BETWEEN '10.0.0.0' AND '10.255.255.255' 
        THEN 'Brute Force'

        -- Service Account: User ID 11
        WHEN user_id = 11 THEN 'Service Account'

        -- Normal Activity: Business hours, internal IPs
        WHEN EXTRACT(HOUR FROM event_timestamp) BETWEEN 8 AND 18
             AND EXTRACT(DOW FROM event_timestamp) BETWEEN 1 AND 5
             AND source_ip BETWEEN '10.0.0.0' AND '10.255.255.255'
        THEN 'Normal Activity'

        ELSE 'Other'
    END as scenario,
    COUNT(*) as event_count,
    SUM(CASE WHEN success = FALSE THEN 1 ELSE 0 END) as failed_count,
    SUM(CASE WHEN success = TRUE THEN 1 ELSE 0 END) as success_count
FROM fact_auth_events
WHERE event_timestamp >= '2025-01-01'
GROUP BY scenario
ORDER BY event_count DESC;
"""

THREAT_ACTORS_QUERY = """
SELECT 
    e.source_ip::text as ip_address,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN e.success = TRUE THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN e.success = FALSE THEN 1 ELSE 0 END) as failed,
    COUNT(DISTINCT u.user_id) as users_targeted,
    STRING_AGG(DISTINCT u.username, ', ') as usernames
FROM fact_auth_events e
JOIN dim_users u ON e.user_id = u.user_id
WHERE e.source_ip NOT BETWEEN '10.0.0.0' AND '10.255.255.255'
  AND e.event_timestamp >= '2025-01-01'
GROUP BY e.source_ip
ORDER BY successful DESC, total_attempts DESC;
"""

CRITICAL_ASSETS_QUERY = """
SELECT 
    h.hostname,
    h.asset_criticality,
    COUNT(*) as attack_count,
    COUNT(DISTINCT e.source_ip) as unique_attackers
FROM fact_auth_events e
JOIN dim_hosts h ON e.dest_host_id = h.host_id
WHERE e.success = FALSE
  AND h.asset_criticality IN ('CRITICAL', 'HIGH')
  AND e.event_timestamp >= '2025-01-01'
GROUP BY h.hostname, h.asset_criticality
ORDER BY attack_count DESC;
"""

TIMELINE_QUERY = """
SELECT
  event_timestamp,
  source_ip,
  user_id,
  success
FROM fact_auth_events
WHERE event_timestamp >= '2025-01-01'
ORDER BY event_timestamp;
"""

def classify_severity(row):
    if row['successful'] > 0 and row['failed'] >= 3:
        return 'Critical'
    if row['users_targeted'] >= 5:
        return 'High'
    if row['successful'] > 0:
        return 'Medium'
    return 'Low'

def generate_metrics(conn):
    """Generate all dashboard metrics"""
    print("\nGenerating metrics...")

    metrics = {}

    # Overall stats
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM fact_auth_events WHERE event_timestamp >= '2025-01-01'")
    metrics['total_events'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM fact_auth_events WHERE success = FALSE AND event_timestamp >= '2025-01-01'")
    metrics['failed_logins'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM fact_auth_events WHERE success = TRUE AND event_timestamp >= '2025-01-01'")
    metrics['successful_logins'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM fact_auth_events WHERE source_ip NOT BETWEEN '10.0.0.0' AND '10.255.255.255' AND event_timestamp >= '2025-01-01'")
    metrics['external_ips'] = cursor.fetchone()[0]

    # Get dataframes
    metrics['scenarios'] = run_query(conn, DASHBOARD_QUERY)
    metrics['threat_actors'] = run_query(conn, THREAT_ACTORS_QUERY)
    metrics['critical_assets'] = run_query(conn, CRITICAL_ASSETS_QUERY)
    metrics['timeline'] = run_query(conn, TIMELINE_QUERY)

    metrics['threat_actors']['severity'] = metrics['threat_actors'].apply(
        classify_severity, axis=1
    )

    cursor.close()

    print(f"Metrics generated: {metrics['total_events']} events analyzed")
    return metrics

def create_timeline_chart(df):
    """Create attack timeline chart with proper date handling"""
    df['event_timestamp'] = pd.to_datetime(df['event_timestamp'])
    df['date'] = df['event_timestamp'].dt.date

    # Convert success boolean to readable labels
    df['result'] = df['success'].map({True: 'Success âœ…', False: 'Failed âŒ'})

    fig = px.scatter(
        df,
        x='event_timestamp',
        y='source_ip',
        color='result',
        title='Attack Timeline - Chronological View',
        labels={
            'event_timestamp': 'Time',
            'source_ip': 'Source IP',
            'result': 'Login Result'
        },
        color_discrete_map={
            'Success âœ…': '#00FF00',
            'Failed âŒ': '#FF0000'
        },
        height=500,
        hover_data={'user_id': True}
    )

    fig.update_layout(
        plot_bgcolor='#161b22',
        paper_bgcolor='#0e1117',
        font_color='#e6edf3'
    )

    return fig.to_html(include_plotlyjs='cdn', div_id='timeline')

def create_charts(metrics):
    """Create interactive Plotly charts"""
    print("\n Creating charts...")

    charts = {}

    # Chart 1: Event Distribution Pie Chart
    df_scenarios = metrics['scenarios']
    fig1 = px.pie(
        df_scenarios,
        values='event_count',
        names='scenario',
        title='Security Events by Type',
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    charts['event_distribution'] = fig1.to_html(include_plotlyjs='cdn', div_id='chart1')

    # Chart 2: Attack vs Normal Activity Bar Chart
    fig2 = px.bar(
        df_scenarios,
        x='scenario',
        y='event_count',
        title='Event Count by Scenario',
        color='event_count',
        color_continuous_scale='Reds'
    )
    charts['scenario_bar'] = fig2.to_html(include_plotlyjs='cdn', div_id='chart2')

    # Chart 3: Threat Actor Severity
    df_threats = metrics['threat_actors']

    # Add small random offsets to separate overlapping points
    df_threats['x_jitter'] = df_threats['total_attempts'] + np.random.uniform(-0.1, 0.1, len(df_threats))
    df_threats['y_jitter'] = df_threats['users_targeted'] + np.random.uniform(-0.05, 0.05, len(df_threats))

    fig3 = px.scatter(
        df_threats,
        x='x_jitter',
        y='y_jitter',
        size='total_attempts',
        color='severity',
        hover_data={
            'ip_address': True,
            'usernames': True,
            'successful': True,
            'failed': True,
            'total_attempts': True,
            'users_targeted': True
        },
        title='Threat Actor Analysis',
        labels={
            'x_jitter': 'Total Attempts',
            'y_jitter': 'Users Targeted'
        },
        color_discrete_map={
            'Critical': '#FF0000',
            'High': '#FF6600',
            'Medium': '#FFCC00',
            'Low': '#00CC00'
        }
    )

    # Optional: customize hover template for cleaner display
    fig3.update_traces(
        hovertemplate='<b>%{customdata[0]}</b><br>' +
                      'Attempts: %{x}<br>' +
                      'Users Targeted: %{y}<br>' +
                      'Successful: %{customdata[2]}<br>' +
                      'Failed: %{customdata[3]}<br>' +
                      'Usernames: %{customdata[1]}<br>' +
                      '<extra></extra>'
    )
    charts['threat_scatter'] = fig3.to_html(include_plotlyjs='cdn', div_id='chart3')

    # Chart 4: Attack Timeline
    charts['attack_timeline'] = create_timeline_chart(metrics['timeline'])

    print("4 interactive charts created")
    return charts

def export_json(metrics, output_path):
    """Export metrics to JSON"""
    print("\n Exporting JSON...")

    json_data = {
        'generated_at': datetime.now().isoformat(),
        'summary': {
            'total_events': int(metrics['total_events']),
            'failed_logins': int(metrics['failed_logins']),
            'successful_logins': int(metrics['successful_logins']),
            'external_threats': int(metrics['external_ips'])
        },
        'scenarios': metrics['scenarios'].to_dict('records'),
        'threat_actors': metrics['threat_actors'].to_dict('records'),
        'critical_assets': metrics['critical_assets'].to_dict('records')
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2)

    print(f"JSON exported: {output_path}")
    return json_data

def create_default_template(template_path):
    """Create default HTML template if it doesn't exist"""
    print(f"Creating default template at: {template_path}")

    default_html = """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SOC Security Dashboard</title>
        <style>
            body {
                background-color: #0e1117;
                color: #e6edf3;
                font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
                margin: 0;
                padding: 20px;
                line-height: 1.6;
            }

            h1 {
                color: #f0f6fc;
                font-size: 2.5em;
                margin-bottom: 10px;
                text-align: center;
                border-bottom: 3px solid #58a6ff;
                padding-bottom: 15px;
            }

            h2 {
                color: #58a6ff;
                font-size: 1.8em;
                margin-top: 0;
            }

            .header {
                text-align: center;
                margin-bottom: 30px;
            }

            .timestamp {
                color: #8b949e;
                font-size: 0.9em;
            }

            .dashboard-section {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            }

            .metric-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }

            .metric-card {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 15px;
                text-align: center;
            }

            .metric-value {
                font-size: 2.5em;
                font-weight: bold;
                color: #58a6ff;
            }

            .metric-label {
                font-size: 0.9em;
                color: #8b949e;
                margin-top: 5px;
            }

            .metric {
                font-size: 1.1em;
                margin: 10px 0;
                padding: 8px;
                background: #0d1117;
                border-radius: 6px;
            }

            ul {
                list-style: none;
                padding: 0;
            }

            .badge {
                padding: 4px 12px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 0.85em;
                margin-left: 10px;
            }

            .badge-critical {
                background: #ff4d4d;
                color: #000;
            }

            .badge-high {
                background: #ff9933;
                color: #000;
            }

            .badge-medium {
                background: #ffcc00;
                color: #000;
            }

            .badge-low {
                background: #2ecc71;
                color: #000;
            }

            .chart-container {
                background: #0d1117;
                border-radius: 8px;
                padding: 10px;
                margin: 15px 0;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>SOC Security Dashboard</h1>
            <p class="timestamp">Generated: {{ summary.generated_at }}</p>
        </div>

        <div class="dashboard-section">
            <h2>Overview Metrics</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">{{ summary.total_events }}</div>
                    <div class="metric-label">Total Events</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{{ summary.failed_logins }}</div>
                    <div class="metric-label">Failed Logins</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{{ summary.successful_logins }}</div>
                    <div class="metric-label">Successful Logins</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{{ summary.external_threats }}</div>
                    <div class="metric-label">External Threats</div>
                </div>
            </div>
        </div>

        <div class="dashboard-section">
            <h2>Event Distribution</h2>
            <div class="chart-container">
                {{ charts.event_distribution | safe }}
            </div>
        </div>

        <div class="dashboard-section">
            <h2>Scenario Breakdown</h2>
            <div class="chart-container">
                {{ charts.scenario_bar | safe }}
            </div>
        </div>

        <div class="dashboard-section">
            <h2>Threat Actor Analysis</h2>
            <div class="chart-container">
                {{ charts.threat_scatter | safe }}
            </div>
        </div>

        <div class="dashboard-section">
            <h2>Attack Timeline</h2>
            <div class="chart-container">
                {{ charts.attack_timeline | safe }}
            </div>
        </div>

        <div class="dashboard-section">
            <h2>Critical Assets Under Attack</h2>
            <ul>
                {% for asset in critical_assets %}
                <li class="metric">
                    <strong>{{ asset.hostname }}</strong> ({{ asset.asset_criticality }})
                    &mdash; {{ asset.attack_count }} attacks from {{ asset.unique_attackers }} source(s)
                </li>
                {% endfor %}
            </ul>
        </div>

        <div class="dashboard-section">
            <h2>Threat Actors</h2>
            <ul>
                {% for actor in threat_actors %}
                <li class="metric">
                    <strong>{{ actor.ip_address }}</strong>
                    <span class="badge badge-{{ actor.severity|lower }}">{{ actor.severity }}</span>
                    &mdash; {{ actor.total_attempts }} attempts 
                    ({{ actor.successful }} successful, {{ actor.failed }} failed)
                    <br>
                    <small style="color: #8b949e;">Targeted: {{ actor.usernames }}</small>
                </li>
                {% endfor %}
            </ul>
        </div>

        <div class="dashboard-section">
            <h2>Security Recommendations</h2>
            <ul>
                <li class="metric"><strong>CRITICAL:</strong> Reset compromised account passwords immediately</li>
                <li class="metric"><strong>HIGH:</strong> Block malicious external IP addresses</li>
                <li class="metric"><strong>MEDIUM:</strong> Provide security awareness training to targeted users</li>
                <li class="metric"><strong>INFO:</strong> Review VPN access policies and implement MFA</li>
            </ul>
        </div>
    </body>
    </html>"""

    # Write the template file
    with open(template_path, 'w', encoding='utf-8') as f:
        f.write(default_html)

    print(f"Default template created successfully")


def render_dashboard(metrics, charts):
    """Render HTML dashboard with Jinja2 template"""
    template_path = TEMPLATE_DIR / 'dashboard.html'

    # Check if template exists, create if missing
    if not template_path.exists():
        print(f"Template not found: {template_path}")
        create_default_template(template_path)

    # Load template with UTF-8 encoding
    try:
        with open(template_path, encoding='utf-8') as f:
            template = Template(f.read())
    except Exception as e:
        print(f"Error reading template: {e}")
        return None

    # Render with data
    html = template.render(
        summary={
            'total_events': metrics['total_events'],
            'failed_logins': metrics['failed_logins'],
            'successful_logins': metrics['successful_logins'],
            'external_threats': metrics['external_ips'],
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        charts=charts,
        threat_actors=metrics['threat_actors'].to_dict('records'),
        critical_assets=metrics['critical_assets'].to_dict('records')
    )

    # Save output with UTF-8 encoding
    output_file = OUTPUT_DIR / 'index.html'
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"Dashboard HTML created: {output_file}")
        return output_file
    except UnicodeEncodeError as e:
        print(f"Unicode error: {e}")
        # Fallback: save without emojis
        print("Attempting to save without special characters...")
        html_clean = html.encode('ascii', 'ignore').decode('ascii')
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_clean)
        print(f"Dashboard saved (emojis removed): {output_file}")
        return output_file

def main():
    conn = connect_db()

    metrics = generate_metrics(conn)

    charts = create_charts(metrics)

    output_file = OUTPUT_DIR / 'soc_dashboard.json'
    export_json(metrics, output_file)

    render_dashboard(metrics, charts)

    conn.close()
    print("\nSOC Dashboard Generation Complete")

if __name__ == "__main__":
    main()