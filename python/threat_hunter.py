#!/usr/bin/env python3
"""
SOC Threat Hunting CLI Tool
Professional command-line interface for security analysts
"""

import psycopg2
import argparse
import sys
import json
import csv
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

# Color codes for terminal output (ANSI escape codes)
class Colors:
    """Terminal color codes for pretty output"""
    RED = '\033[91m'        # Critical threats
    YELLOW = '\033[93m'     # Warnings
    GREEN = '\033[92m'      # Success/Safe
    BLUE = '\033[94m'       # Info
    CYAN = '\033[96m'       # Headers
    BOLD = '\033[1m'        # Emphasis
    END = '\033[0m'         # Reset color

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'security_dwh',
    'user': 'postgres',
    'password': 'Marissa2004*'
}

class ThreatHunter:
    """Main threat hunting class - handles all database queries"""

    def __init__(self):
        """Initialize database connection"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            self.cursor = self.conn.cursor()
            print(f"{Colors.GREEN}Connected to security database{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Database connection failed: {e}{Colors.END}")
            sys.exit(1)

    def __del__(self):
        """Clean up database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()

    # =================================================================
    # HUNT 1: BRUTE FORCE ATTACKS
    # =================================================================
    def hunt_brute_force(self, username: Optional[str] = None,
                         threshold: int = 3,
                         days: int = 1) -> List[Dict]:
        """
        Find brute force attacks

        Args:
            username: Filter to specific user (optional)
            threshold: Minimum failed attempts (default 3)
            days: Look back this many days (default 1)
        """
        query = """
        SELECT 
            u.username,
            u.department,
            u.is_privileged,
            COUNT(*) as failed_attempts,
            e.source_ip::text,
            MIN(e.event_timestamp) as first_attempt,
            MAX(e.event_timestamp) as last_attempt
        FROM fact_auth_events e
        JOIN dim_users u ON e.user_id = u.user_id
        WHERE e.success = FALSE
            AND e.event_timestamp > CURRENT_TIMESTAMP - INTERVAL '%s days'
        """

        params = [days]

        # Add username filter if provided
        if username:
            query += " AND u.username = %s"
            params.append(username)

        query += """
        GROUP BY u.username, u.department, u.is_privileged, e.source_ip
        HAVING COUNT(*) >= %s
        ORDER BY failed_attempts DESC
        """
        params.append(threshold)

        self.cursor.execute(query, params)
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    # =================================================================
    # HUNT 2: PASSWORD SPRAYING
    # =================================================================
    def hunt_password_spraying(self, ip_address: Optional[str] = None,
                               threshold: int = 5,
                               days: int = 1) -> List[Dict]:
        """
        Find password spraying attacks (one password, many users)

        Args:
            ip_address: Filter to specific IP (optional)
            threshold: Minimum users targeted (default 5)
            days: Look back this many days (default 1)
        """
        query = """
        SELECT 
            e.source_ip::text,
            COUNT(DISTINCT e.user_id) as users_targeted,
            COUNT(*) as total_attempts,
            MIN(e.event_timestamp) as attack_start,
            MAX(e.event_timestamp) as attack_end,
            STRING_AGG(DISTINCT u.username, ', ' ORDER BY u.username) as targeted_accounts
        FROM fact_auth_events e
        JOIN dim_users u ON e.user_id = u.user_id
        WHERE e.success = FALSE
            AND e.event_timestamp > CURRENT_TIMESTAMP - INTERVAL '%s days'
        """

        params = [days]

        if ip_address:
            query += " AND e.source_ip = %s"
            params.append(ip_address)

        query += """
        GROUP BY e.source_ip
        HAVING COUNT(DISTINCT e.user_id) >= %s
        ORDER BY users_targeted DESC
        """
        params.append(threshold)

        self.cursor.execute(query, params)
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    # =================================================================
    # HUNT 3: SUCCESSFUL COMPROMISES
    # =================================================================
    def hunt_compromises(self, days: int = 7) -> List[Dict]:
        """
        Find successful logins after multiple failures (compromised accounts)

        Args:
            days: Look back this many days (default 7)
        """
        query = """
        WITH failed_logins AS (
            SELECT 
                user_id,
                source_ip,
                COUNT(*) as failure_count,
                MAX(event_timestamp) as last_failure
            FROM fact_auth_events
            WHERE success = FALSE
                AND event_timestamp > CURRENT_TIMESTAMP - INTERVAL '%s days'
            GROUP BY user_id, source_ip
            HAVING COUNT(*) >= 3
        )
        SELECT 
            u.username,
            u.department,
            u.is_privileged,
            fl.failure_count,
            fl.last_failure,
            e.event_timestamp as successful_login_time,
            e.source_ip::text,
            h.hostname as target_host,
            h.asset_criticality
        FROM failed_logins fl
        JOIN fact_auth_events e ON
            fl.user_id = e.user_id
            AND fl.source_ip = e.source_ip
            AND e.event_timestamp > fl.last_failure
            AND e.success = TRUE
        JOIN dim_users u ON e.user_id = u.user_id
        LEFT JOIN dim_hosts h ON e.dest_host_id = h.host_id
        ORDER BY e.event_timestamp DESC
        """

        self.cursor.execute(query, [days])
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    # =================================================================
    # HUNT 4: EXTERNAL THREAT ACTORS
    # =================================================================
    def hunt_external_threats(self, min_attempts: int = 1,
                              days: int = 30) -> List[Dict]:
        """
        Profile external IPs attacking the network

        Args:
             min_attempts: Minimum attempts to include (default 1)
             days: Look back this many days (default 30)
        """
        query = """
        SELECT 
            e.source_ip::text,
            COUNT(*) as total_attempts,
            SUM(CASE WHEN e.success = FALSE THEN 1 ELSE 0 END) as failed_attempts,
            SUM(CASE WHEN e.success = TRUE THEN 1 ELSE 0 END) as successful_logins,
            COUNT(DISTINCT u.user_id) as unique_users_targeted,
            MIN(e.event_timestamp) as first_seen,
            MAX(e.event_timestamp) as last_seen
        FROM fact_auth_events e
        JOIN dim_users u ON e.user_id = u.user_id
        WHERE e.source_ip NOT BETWEEN '10.0.0.0' AND '10.255.255.255'
            AND e.event_timestamp > CURRENT_TIMESTAMP - INTERVAL '%s days'
        GROUP BY e.source_ip
        HAVING COUNT(*) >= %s
        ORDER BY successful_logins DESC, total_attempts DESC
        """

        self.cursor.execute(query, [days, min_attempts])
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    # =================================================================
    # HUNT 5: PRIVILEGED ACCOUNT ACTIVITY
    # =================================================================
    def hunt_privileged_activity(self, username: Optional[str] = None,
                                 hours: int = 24) -> List[Dict]:
        """
        Monitor admin account activity

        Args:
            username: Filter to specific admin (optional)
            hours: Look back this many hours (default 24)
        """
        query = """
        SELECT
            u.username,
            u.department,
            h.hostname,
            h.asset_criticality,
            e.event_type,
            e.success,
            e.event_timestamp,
            e.source_ip::text
        FROM fact_auth_events e
        JOIN dim_users u ON e.user_id = u.user_id
        LEFT JOIN dim_hosts h ON e.dest_host_id = h.host_id
        WHERE u.is_privileged = TRUE
            AND e.event_timestamp > CURRENT_TIMESTAMP - INTERVAL '%s hours'
        """

        params = [hours]

        if username:
            query += " AND u.username = %s"
            params.append(username)

        query += " ORDER BY e.event_timestamp DESC"

        self.cursor.execute(query, params)
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    # =================================================================
    # HUNT 6: CRITICAL ASSET ATTACKS
    # =================================================================
    def hunt_critical_assets(self, days: int = 7) -> List[Dict]:
        """
        Find attacks on high-value infrastructure

        Args:
             days: Look back this many days (default 7)
        """
        query = """
        SELECT 
            h.hostname,
            h.asset_criticality,
            h.location,
            COUNT(*) as attack_count,
            COUNT(DISTINCT e.source_ip) as unique_attackers,
            STRING_AGG(DISTINCT e.source_ip::text, ', ') as attacker_ips
        FROM fact_auth_events e
        JOIN dim_hosts h ON e.dest_host_id = h.host_id
        WHERE e.success = FALSE
            AND h.asset_criticality IN ('CRITICAL', 'HIGH')
            AND e.event_timestamp > CURRENT_TIMESTAMP - INTERVAL '%s days'
        GROUP BY h.hostname, h.asset_criticality, h.location
        ORDER BY attack_count DESC
        """

        self.cursor.execute(query, [days])
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

# =================================================================
# OUTPUT FORMATTING FUNCTIONS
# =================================================================
def format_results(results: List[Dict], hunt_type: str):
    """
    Pretty-print results with colors

    Args:
         results: List of result dictionaries
         hunt_type: Type of hunt (for title)
    """
    if not results:
        print(f"\n{Colors.GREEN}No threats found - all clear!{Colors.END}\n")
        return

    print(f"\n{Colors.BOLD}{Colors.RED}THREATS DETECTED: {hunt_type}{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 80}{Colors.END}")

    for i, result in enumerate(results, 1):
        print(f"{Colors.BOLD}[{i}]{Colors.END}")

        for key, value in result.items():
            # Color-code important fields
            if key == 'is_privileged' and value:
                color = Colors.RED
                value = "YES (ADMIN ACCOUNT)"
            elif 'critical' in str(key).lower() or 'severity' in str(key).lower():
                color = Colors.RED
            elif 'success' in str(key).lower():
                color = Colors.RED if value else Colors.YELLOW
            else:
                color = Colors.END

            # Format field name nicely
            field_name = key.replace('_', ' ').title()
            print(f"  {Colors.CYAN}{field_name}:{Colors.END} {color}{value}{Colors.END}")

        print() # Blank line between results

def export_results(results: List[Dict], format: str, output_file: str):
    """
    Export results to file

    Args:
         results: Query results
         format: 'json' or 'csv'
         output_file: Destination file path
    """
    output_path = Path(output_file)

    try:
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)

        elif format == 'csv':
            if not results:
                print(f"{Colors.YELLOW}No results to export{Colors.END}")
                return

            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)

        print(f"{Colors.GREEN}Exported to {output_path}{Colors.END}")

    except Exception as e:
        print(f"{Colors.RED}Export failed: {e}{Colors.END}")

# =================================================================
# INTERACTIVE MENU
# =================================================================

def show_menu():
    """Display interactive hunt menu"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}")
    print(f"{Colors.BOLD}SOC THREAT HUNTING TOOL{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 80}{Colors.END}\n")

    print(f"{Colors.BOLD}Available Hunts:{Colors.END}")
    print(f"  1. {Colors.RED}Brute Force Attacks{Colors.END}       - Multiple password guesses")
    print(f"  2. {Colors.RED}Password Spraying{Colors.END}         - One password, many users")
    print(f"  3. {Colors.RED}Successful Compromises{Colors.END}    - Breached accounts")
    print(f"  4. {Colors.YELLOW}External Threats{Colors.END}          - Outside attackers")
    print(f"  5. {Colors.YELLOW}Privileged Activity{Colors.END}       - Admin account monitoring")
    print(f"  6. {Colors.YELLOW}Critical Asset Attacks{Colors.END}    - High-value targets")
    print(f"  7. {Colors.BLUE}Exit{Colors.END}\n")


def interactive_mode():
    """Run interactive threat hunting session"""
    hunter = ThreatHunter()

    while True:
        show_menu()
        choice = input(f"{Colors.BOLD}Select hunt [1-7]: {Colors.END}").strip()

        if choice == '1':
            days = input("  Days to look back [default 1]: ").strip() or '1'
            results = hunter.hunt_brute_force(days=int(days))
            format_results(results, "Brute Force Attacks")

        elif choice == '2':
            days = input("  Days to look back [default 1]: ").strip() or '1'
            results = hunter.hunt_password_spraying(days=int(days))
            format_results(results, "Password Spraying")

        elif choice == '3':
            days = input("  Days to look back [default 7]: ").strip() or '7'
            results = hunter.hunt_compromises(days=int(days))
            format_results(results, "Successful Compromises")

        elif choice == '4':
            days = input("  Days to look back [default 30]: ").strip() or '30'
            results = hunter.hunt_external_threats(days=int(days))
            format_results(results, "External Threat Actors")

        elif choice == '5':
            hours = input("  Hours to look back [default 24]: ").strip() or '24'
            results = hunter.hunt_privileged_activity(hours=int(hours))
            format_results(results, "Privileged Account Activity")

        elif choice == '6':
            days = input("  Days to look back [default 7]: ").strip() or '7'
            results = hunter.hunt_critical_assets(days=int(days))
            format_results(results, "Critical Asset Attacks")

        elif choice == '7':
            print(f"\n{Colors.GREEN}Stay vigilant! 🛡️{Colors.END}\n")
            break

        else:
            print(f"{Colors.RED}Invalid choice{Colors.END}")

        # Ask about export
        if choice in ['1', '2', '3', '4', '5', '6'] and results:
            export = input(f"\n{Colors.BOLD}Export results? [y/N]: {Colors.END}").strip().lower()
            if export == 'y':
                fmt = input("  Format [json/csv]: ").strip().lower() or 'json'
                filename = input("  Filename: ").strip()
                if filename:
                    export_results(results, fmt, filename)


# =================================================================
# COMMAND-LINE INTERFACE
# =================================================================

def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description='SOC Threat Hunting CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python threat_hunter.py

  # Quick brute force check
  python threat_hunter.py --brute-force --days 1

  # Find password spraying in last 24 hours
  python threat_hunter.py --password-spray --days 1

  # Export compromised accounts to JSON
  python threat_hunter.py --compromises --export compromises.json
        """
    )

    # Hunt selection arguments
    parser.add_argument('--brute-force', action='store_true',
                        help='Hunt for brute force attacks')
    parser.add_argument('--password-spray', action='store_true',
                        help='Hunt for password spraying')
    parser.add_argument('--compromises', action='store_true',
                        help='Find successful compromises')
    parser.add_argument('--external-threats', action='store_true',
                        help='Profile external attackers')
    parser.add_argument('--privileged', action='store_true',
                        help='Monitor admin activity')
    parser.add_argument('--critical-assets', action='store_true',
                        help='Find attacks on critical systems')

    # Filter arguments
    parser.add_argument('--days', type=int, default=1,
                        help='Days to look back (default: 1)')
    parser.add_argument('--hours', type=int, default=24,
                        help='Hours to look back for privileged (default: 24)')
    parser.add_argument('--username', type=str,
                        help='Filter to specific username')
    parser.add_argument('--ip', type=str,
                        help='Filter to specific IP address')

    # Output arguments
    parser.add_argument('--export', type=str,
                        help='Export results to file (json or csv)')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress colored output')

    args = parser.parse_args()

    # If no hunt specified, run interactive mode
    if not any([args.brute_force, args.password_spray, args.compromises,
                args.external_threats, args.privileged, args.critical_assets]):
        interactive_mode()
        return

    # Run specified hunt
    hunter = ThreatHunter()
    results = []
    hunt_type = ""

    if args.brute_force:
        results = hunter.hunt_brute_force(username=args.username, days=args.days)
        hunt_type = "Brute Force Attacks"

    elif args.password_spray:
        results = hunter.hunt_password_spraying(ip_address=args.ip, days=args.days)
        hunt_type = "Password Spraying"

    elif args.compromises:
        results = hunter.hunt_compromises(days=args.days)
        hunt_type = "Successful Compromises"

    elif args.external_threats:
        results = hunter.hunt_external_threats(days=args.days)
        hunt_type = "External Threat Actors"

    elif args.privileged:
        results = hunter.hunt_privileged_activity(username=args.username, hours=args.hours)
        hunt_type = "Privileged Account Activity"

    elif args.critical_assets:
        results = hunter.hunt_critical_assets(days=args.days)
        hunt_type = "Critical Asset Attacks"

    # Display results
    if not args.quiet:
        format_results(results, hunt_type)

    # Export if requested
    if args.export:
        fmt = 'json' if args.export.endswith('.json') else 'csv'
        export_results(results, fmt, args.export)

    # Exit code: 0 if no threats, 1 if threats found
    sys.exit(0 if not results else 1)


if __name__ == '__main__':
    main()