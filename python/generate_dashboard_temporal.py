"""
Enhanced SOC Security Dashboard Generator with Temporal Analysis
Adds time-based attack pattern detection and visualization
"""
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
OUTPUT_DIR = Path(__file__).parent.parent / 'output'
TEMPLATE_DIR = Path(__file__).parent.parent / 'templates'
OUTPUT_DIR.mkdir(exist_ok=True)
TEMPLATE_DIR.mkdir(exist_ok=True)

print("🛡️  Enhanced SOC Dashboard Generator Starting...")
print(f"Output Directory: {OUTPUT_DIR}")


def connect_db():
    """Connect to PostgreSQL database"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        print("✅ Database connection established")
        return conn
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        sys.exit(1)


def run_query(conn, query):
    """Execute SQL query and return pandas DataFrame"""
    try:
        df = pd.read_sql_query(query, conn)
        print(f"✅ Query executed - {len(df)} rows returned")
        return df
    except Exception as e:
        print(f"❌ Query failed: {e}")
        return None


# =====================================================
# NEW: TEMPORAL ANALYSIS QUERIES
# =====================================================

HOURLY_ATTACKS_QUERY = """
SELECT 
    t.hour,
    COUNT(*) AS attack_count,
    t.is_business_hours,
    t.risk_period
FROM fact_auth_events e
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE e.success = FALSE
    AND e.event_timestamp >= '2025-01-01'
GROUP BY t.hour, t.is_business_hours, t.risk_period
ORDER BY t.hour;
"""

BUSINESS_HOURS_COMPARISON_QUERY = """
SELECT 
    CASE WHEN t.is_business_hours THEN 'Business Hours' ELSE 'Off-Hours' END AS period,
    COUNT(*) AS total_attacks,
    COUNT(DISTINCT e.source_ip) AS unique_attackers,
    SUM(CASE WHEN e.success THEN 1 ELSE 0 END) AS successful_attempts
FROM fact_auth_events e
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE e.event_timestamp >= '2025-01-01'
GROUP BY t.is_business_hours;
"""

DAY_OF_WEEK_ATTACKS_QUERY = """
SELECT 
    t.day_name,
    t.is_weekend,
    COUNT(*) AS event_count,
    SUM(CASE WHEN e.success = FALSE THEN 1 ELSE 0 END) AS failed_attempts
FROM fact_auth_events e
JOIN dim_time t ON DATE_TRUNC('hour', e.event_timestamp) = t.full_timestamp
WHERE e.event_timestamp >= '2025-01-01'
GROUP BY t.day_name, t.is_weekend, t.day_of_week
ORDER BY t.day_of_week;
"""

# Original queries (keeping existing functionality)
DASHBOARD_QUERY = """
SELECT 
    CASE 
        WHEN source_ip IN (
            SELECT source_ip FROM fact_auth_events
            WHERE success = FALSE
            GROUP BY source_ip
            HAVING COUNT(DISTINCT user_id) >= 5
        ) THEN 'Password Spraying'

        WHEN user_id IN (
            SELECT e1.user_id 
            FROM fact_auth_events e1
            WHERE e1.success = FALSE
            GROUP BY e1.user_id, e1.source_ip
            HAVING COUNT(*) >= 3
        ) AND source_ip NOT BETWEEN '10.0.0.0' AND '10.255.255.255' 
        THEN 'Brute Force'

        WHEN user_id = 11 THEN 'Service Account'

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
    """Classify threat actor severity"""
    if row['successful'] > 0 and row['failed'] >= 3:
        return 'Critical'
    if row['users_targeted'] >= 5:
        return 'High'
    if row['successful'] > 0:
        return 'Medium'
    return 'Low'


def generate_metrics(conn):
    """Generate all dashboard metrics including temporal analysis"""
    print("\n📊 Generating metrics...")

    metrics = {}
    cursor = conn.cursor()

    # Overall stats
    cursor.execute("SELECT COUNT(*) FROM fact_auth_events WHERE event_timestamp >= '2025-01-01'")
    metrics['total_events'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM fact_auth_events WHERE success = FALSE AND event_timestamp >= '2025-01-01'")
    metrics['failed_logins'] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM fact_auth_events WHERE success = TRUE AND event_timestamp >= '2025-01-01'")
    metrics['successful_logins'] = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(DISTINCT source_ip) FROM fact_auth_events WHERE source_ip NOT BETWEEN '10.0.0.0' AND '10.255.255.255' AND event_timestamp >= '2025-01-01'")
    metrics['external_ips'] = cursor.fetchone()[0]

    # Original dataframes
    metrics['scenarios'] = run_query(conn, DASHBOARD_QUERY)
    metrics['threat_actors'] = run_query(conn, THREAT_ACTORS_QUERY)
    metrics['critical_assets'] = run_query(conn, CRITICAL_ASSETS_QUERY)
    metrics['timeline'] = run_query(conn, TIMELINE_QUERY)

    # NEW: Temporal analysis dataframes
    print("\n⏰ Loading temporal analysis data...")
    metrics['hourly_attacks'] = run_query(conn, HOURLY_ATTACKS_QUERY)
    metrics['business_hours'] = run_query(conn, BUSINESS_HOURS_COMPARISON_QUERY)
    metrics['day_of_week'] = run_query(conn, DAY_OF_WEEK_ATTACKS_QUERY)

    # Classify threat actors
    metrics['threat_actors']['severity'] = metrics['threat_actors'].apply(classify_severity, axis=1)

    cursor.close()
    print(f"✅ Metrics generated: {metrics['total_events']} events analyzed")
    return metrics


def create_timeline_chart(df):
    """Create attack timeline chart"""
    df['event_timestamp'] = pd.to_datetime(df['event_timestamp'])
    df['result'] = df['success'].map({True: 'Success ✅', False: 'Failed ❌'})

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
            'Success ✅': '#00FF00',
            'Failed ❌': '#FF0000'
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


def create_hourly_heatmap(df):
    """Create hourly attack heatmap showing risk periods"""
    fig = go.Figure(data=go.Bar(
        x=df['hour'],
        y=df['attack_count'],
        marker=dict(
            color=df['attack_count'],
            colorscale='Reds',
            showscale=True,
            colorbar=dict(title='Attacks')
        ),
        text=df['risk_period'],
        hovertemplate='<b>Hour %{x}:00</b><br>' +
                      'Attacks: %{y}<br>' +
                      'Risk: %{text}<br>' +
                      '<extra></extra>'
    ))

    fig.update_layout(
        title='Attack Distribution by Hour of Day',
        xaxis_title='Hour (24-hour format)',
        yaxis_title='Number of Attacks',
        plot_bgcolor='#161b22',
        paper_bgcolor='#0e1117',
        font_color='#e6edf3',
        height=400
    )

    return fig.to_html(include_plotlyjs='cdn', div_id='hourly_heatmap')


def create_business_hours_chart(df):
    """Create business hours vs off-hours comparison"""
    fig = px.bar(
        df,
        x='period',
        y='total_attacks',
        color='period',
        title='Business Hours vs Off-Hours Attack Comparison',
        labels={'total_attacks': 'Total Attacks', 'period': 'Time Period'},
        color_discrete_map={
            'Business Hours': '#3498db',
            'Off-Hours': '#e74c3c'
        },
        text='total_attacks'
    )

    fig.update_traces(textposition='outside')
    fig.update_layout(
        plot_bgcolor='#161b22',
        paper_bgcolor='#0e1117',
        font_color='#e6edf3',
        height=400,
        showlegend=False
    )

    return fig.to_html(include_plotlyjs='cdn', div_id='business_hours')


def create_day_of_week_chart(df):
    """Create day of week attack pattern"""
    fig = px.bar(
        df,
        x='day_name',
        y='event_count',
        color='is_weekend',
        title='Attack Patterns by Day of Week',
        labels={'event_count': 'Total Events', 'day_name': 'Day'},
        color_discrete_map={
            True: '#e74c3c',  # Weekend = red
            False: '#3498db'  # Weekday = blue
        },
        text='event_count'
    )

    fig.update_traces(textposition='outside')
    fig.update_layout(
        plot_bgcolor='#161b22',
        paper_bgcolor='#0e1117',
        font_color='#e6edf3',
        height=400
    )

    return fig.to_html(include_plotlyjs='cdn', div_id='day_of_week')


def create_charts(metrics):
    """Create all charts including temporal analysis"""
    print("\n📈 Creating charts...")

    charts = {}

    # Original charts
    df_scenarios = metrics['scenarios']
    fig1 = px.pie(
        df_scenarios,
        values='event_count',
        names='scenario',
        title='Security Events by Type',
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    fig1.update_layout(plot_bgcolor='#161b22', paper_bgcolor='#0e1117', font_color='#e6edf3')
    charts['event_distribution'] = fig1.to_html(include_plotlyjs='cdn', div_id='chart1')

    fig2 = px.bar(
        df_scenarios,
        x='scenario',
        y='event_count',
        title='Event Count by Scenario',
        color='event_count',
        color_continuous_scale='Reds'
    )
    fig2.update_layout(plot_bgcolor='#161b22', paper_bgcolor='#0e1117', font_color='#e6edf3')
    charts['scenario_bar'] = fig2.to_html(include_plotlyjs='cdn', div_id='chart2')

    # Threat actor scatter
    df_threats = metrics['threat_actors']
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
            'failed': True
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
    fig3.update_layout(plot_bgcolor='#161b22', paper_bgcolor='#0e1117', font_color='#e6edf3')
    charts['threat_scatter'] = fig3.to_html(include_plotlyjs='cdn', div_id='chart3')

    # Timeline
    charts['attack_timeline'] = create_timeline_chart(metrics['timeline'])

    # NEW: Temporal analysis charts
    charts['hourly_heatmap'] = create_hourly_heatmap(metrics['hourly_attacks'])
    charts['business_hours'] = create_business_hours_chart(metrics['business_hours'])
    charts['day_of_week'] = create_day_of_week_chart(metrics['day_of_week'])

    print("✅ 7 interactive charts created (including 3 temporal analysis)")
    return charts


def export_json(metrics, output_path):
    """Export metrics to JSON"""
    print("\n💾 Exporting JSON...")

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
        'critical_assets': metrics['critical_assets'].to_dict('records'),
        'temporal_analysis': {
            'hourly_attacks': metrics['hourly_attacks'].to_dict('records'),
            'business_hours': metrics['business_hours'].to_dict('records'),
            'day_of_week': metrics['day_of_week'].to_dict('records')
        }
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2)

    print(f"✅ JSON exported: {output_path}")
    return json_data


def render_dashboard(metrics, charts):
    """Render HTML dashboard"""
    template_path = TEMPLATE_DIR / 'dashboard_temporal.html'

    if not template_path.exists():
        print(f"⚠️  Template not found, using default")
        template_path = TEMPLATE_DIR / 'dashboard.html'

    try:
        with open(template_path, encoding='utf-8') as f:
            template = Template(f.read())
    except Exception as e:
        print(f"❌ Error reading template: {e}")
        return None

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

    output_file = OUTPUT_DIR / 'index.html'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"✅ Dashboard HTML created: {output_file}")
    return output_file


def main():
    conn = connect_db()
    metrics = generate_metrics(conn)
    charts = create_charts(metrics)

    output_file = OUTPUT_DIR / 'soc_dashboard.json'
    export_json(metrics, output_file)

    render_dashboard(metrics, charts)

    conn.close()
    print("\n🎉 Enhanced SOC Dashboard Generation Complete!")
    print("✅ New features: Hourly heatmap, Business hours comparison, Day-of-week analysis")


if __name__ == "__main__":
    main()