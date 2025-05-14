#!/usr/bin/env python3
"""
Network Discovery Tool

A tool for scanning networks, identifying online hosts, and gathering system information.
Updated to work with the new IP-centric database schema.
"""

import argparse
import concurrent.futures
import ipaddress
import os
import platform
import socket
import subprocess
import sys
import time
import re
import getpass
import tempfile
import sqlite3
import os
from datetime import datetime

# SQL to create the tables according to the new schema
CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    hostname TEXT,
    mac_address TEXT,
    vlan TEXT,
    vlan TEXT,
    os TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    service_name TEXT,
    last_updated TIMESTAMP NOT NULL,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    UNIQUE(ip, port)
);

CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    share_name TEXT NOT NULL,
    last_updated TIMESTAMP NOT NULL,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    UNIQUE(ip, share_name)
);

CREATE TABLE IF NOT EXISTS system_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    last_updated TIMESTAMP NOT NULL,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    UNIQUE(ip, key)
);

CREATE TABLE IF NOT EXISTS installed_software (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    path TEXT,
    last_updated TIMESTAMP NOT NULL,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    UNIQUE(ip, name, path)
);

CREATE TABLE IF NOT EXISTS running_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    name TEXT NOT NULL,
    display_name TEXT,
    status TEXT,
    last_updated TIMESTAMP NOT NULL,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    UNIQUE(ip, name)
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    target_range TEXT,
    hosts_total INTEGER,
    hosts_online INTEGER,
    scan_type TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    status TEXT NOT NULL,
    scan_time TIMESTAMP NOT NULL,
    session_id INTEGER,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
);
"""

# Sample queries updated for the new schema
SAMPLE_QUERIES = {
    # Get all online hosts
    "online_hosts": """
        SELECT ip, hostname, os, mac_address, vlan, last_seen 
        FROM hosts 
        WHERE status = 'online' 
        ORDER BY ip
    """,
    
    # Get hosts with specific open port
    "hosts_with_port": """
        SELECT h.ip, h.hostname, h.os, s.port, s.service_name
        FROM hosts h
        JOIN services s ON h.ip = s.ip
        WHERE s.port = ? AND h.status = 'online'
        ORDER BY h.ip
    """,
    
    # Get Windows hosts with specific software
    "hosts_with_software": """
        SELECT h.ip, h.hostname, h.os, i.name, i.version
        FROM hosts h
        JOIN installed_software i ON h.ip = i.ip
        WHERE i.name LIKE ? AND h.status = 'online'
        ORDER BY h.ip
    """,
    
    # Get all hosts with Foxit license key
    "hosts_with_foxit": """
        SELECT h.ip, h.hostname, s.value AS foxit_license_key
        FROM hosts h
        JOIN system_info s ON h.ip = s.ip
        WHERE s.key = 'foxit_license_key' AND h.status = 'online'
        ORDER BY h.ip
    """,
    
    # Get all scan sessions
    "scan_sessions": """
        SELECT id, start_time, end_time, target_range, hosts_total, hosts_online,
               (hosts_online * 100.0 / hosts_total) AS online_percentage,
               scan_type
        FROM scan_sessions
        ORDER BY start_time DESC
    """
}

def init_database(db_path):
    """
    Initialize the SQLite database with the required schema.
    
    Args:
        db_path (str): Path to the SQLite database file
        
    Returns:
        tuple: (connection, cursor) to the database
    """
    # Create directory if it doesn't exist
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Use dictionary-like rows
    cursor = conn.cursor()
    
    # Create tables
    for statement in CREATE_TABLES_SQL.split(';'):
        if statement.strip():
            cursor.execute(statement)
    
    conn.commit()
    return conn, cursor

def start_scan_session(cursor, target_range, total_hosts, scan_type):
    """
    Record the start of a new scan session.
    
    Args:
        cursor: Database cursor
        target_range (str): Description of the target range
        total_hosts (int): Total number of hosts to scan
        scan_type (str): Type of scan (e.g., "Basic", "Full")
        
    Returns:
        int: ID of the new scan session
    """
    cursor.execute(
        "INSERT INTO scan_sessions (start_time, target_range, hosts_total, scan_type) VALUES (?, ?, ?, ?)",
        (datetime.now().isoformat(), target_range, total_hosts, scan_type)
    )
    return cursor.lastrowid

def end_scan_session(cursor, session_id, online_hosts):
    """
    Record the end of a scan session.
    
    Args:
        cursor: Database cursor
        session_id (int): ID of the scan session
        online_hosts (int): Number of hosts found online
    """
    cursor.execute(
        "UPDATE scan_sessions SET end_time = ?, hosts_online = ? WHERE id = ?",
        (datetime.now().isoformat(), online_hosts, session_id)
    )

def insert_host_to_db(conn, cursor, host_info, session_id=None):
    """Insert host scan results into the database using the new schema."""
    current_time = datetime.now().isoformat()
    try:
        # Check if host exists in hosts table
        cursor.execute("SELECT * FROM hosts WHERE ip = ?", (host_info['ip'],))
        existing_host = cursor.fetchone()
        
        if existing_host:
            # Update existing host
            cursor.execute(
                "UPDATE hosts SET status = ?, hostname = ?, mac_address = ?, vlan = ?, os = ?, last_seen = ? WHERE ip = ?",
                (
                    host_info['status'],
                    host_info['hostname'],
                    host_info['mac_address'],
                    host_info.get('vlan', ''),
                    host_info.get('vlan', ''),
                    host_info.get('vlan', ''),
                    host_info.get('vlan', ''),
                    host_info.get('vlan', ''),
                    host_info.get('vlan', ''),
                    host_info['os'],
                    current_time,
                    host_info['ip']
                )
            )
        else:
            # Insert new host
            cursor.execute(
                "INSERT INTO hosts (ip, status, hostname, mac_address, vlan, os, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    host_info['ip'],
                    host_info['status'],
                    host_info['hostname'],
                    host_info['mac_address'],
                    host_info.get('vlan', ''),
                    host_info.get('vlan', ''),
                    host_info.get('vlan', ''),
                    host_info['os'],
                    current_time,
                    current_time
                )
            )
        
        # Add entry in scan_history
        if session_id:
            cursor.execute(
                "INSERT INTO scan_history (ip, status, scan_time, session_id) VALUES (?, ?, ?, ?)",
                (host_info['ip'], host_info['status'], current_time, session_id)
            )
        
        # Skip the rest if host is offline
        if host_info['status'] != 'online':
            conn.commit()
            return host_info['ip']
        
        # Insert services (ports)
        for port, service in host_info['services'].items():
            # Check if service exists
            cursor.execute(
                "SELECT * FROM services WHERE ip = ? AND port = ?",
                (host_info['ip'], port)
            )
            if cursor.fetchone():
                # Update existing service
                cursor.execute(
                    "UPDATE services SET service_name = ?, last_updated = ? WHERE ip = ? AND port = ?",
                    (service, current_time, host_info['ip'], port)
                )
            else:
                # Insert new service
                cursor.execute(
                    "INSERT INTO services (ip, port, service_name, last_updated) VALUES (?, ?, ?, ?)",
                    (host_info['ip'], port, service, current_time)
                )
        
        # Insert shares
        for share in host_info.get('shares', []):
            # Check if share exists
            cursor.execute(
                "SELECT * FROM shares WHERE ip = ? AND share_name = ?",
                (host_info['ip'], share)
            )
            if cursor.fetchone():
                # Update existing share
                cursor.execute(
                    "UPDATE shares SET last_updated = ? WHERE ip = ? AND share_name = ?",
                    (current_time, host_info['ip'], share)
                )
            else:
                # Insert new share
                cursor.execute(
                    "INSERT INTO shares (ip, share_name, last_updated) VALUES (?, ?, ?)",
                    (host_info['ip'], share, current_time)
                )
        
        # Insert Windows-specific information if available
        if host_info.get('windows_info'):
            win_info = host_info['windows_info']
            
            # System info
            if win_info.get('system_info'):
                for key, value in win_info['system_info'].items():
                    # Check if system info exists
                    cursor.execute(
                        "SELECT * FROM system_info WHERE ip = ? AND key = ?",
                        (host_info['ip'], key)
                    )
                    if cursor.fetchone():
                        # Update existing system info
                        cursor.execute(
                            "UPDATE system_info SET value = ?, last_updated = ? WHERE ip = ? AND key = ?",
                            (value, current_time, host_info['ip'], key)
                        )
                    else:
                        # Insert new system info
                        cursor.execute(
                            "INSERT INTO system_info (ip, key, value, last_updated) VALUES (?, ?, ?, ?)",
                            (host_info['ip'], key, value, current_time)
                        )
                    
                    # Debug output for Foxit license keys
                    if key == 'foxit_license_key':
                        print(f"Found Foxit license key for host {host_info['ip']}: {value}")
            
            # Installed software
            if win_info.get('installed_software'):
                for software in win_info['installed_software']:
                    name = software.get('name', 'Unknown')
                    version = software.get('version', '')
                    path = software.get('path', '')
                    
                    # Check if software exists
                    cursor.execute(
                        "SELECT * FROM installed_software WHERE ip = ? AND name = ? AND path = ?",
                        (host_info['ip'], name, path)
                    )
                    if cursor.fetchone():
                        # Update existing software
                        cursor.execute(
                            "UPDATE installed_software SET version = ?, last_updated = ? WHERE ip = ? AND name = ? AND path = ?",
                            (version, current_time, host_info['ip'], name, path)
                        )
                    else:
                        # Insert new software
                        cursor.execute(
                            "INSERT INTO installed_software (ip, name, version, path, last_updated) VALUES (?, ?, ?, ?, ?)",
                            (host_info['ip'], name, version, path, current_time)
                        )
            
            # Running services
            if win_info.get('running_services'):
                for service in win_info['running_services']:
                    name = service.get('name', 'Unknown')
                    display_name = service.get('display_name', '')
                    status = service.get('status', '')
                    
                    # Check if running service exists
                    cursor.execute(
                        "SELECT * FROM running_services WHERE ip = ? AND name = ?",
                        (host_info['ip'], name)
                    )
                    if cursor.fetchone():
                        # Update existing running service
                        cursor.execute(
                            "UPDATE running_services SET display_name = ?, status = ?, last_updated = ? WHERE ip = ? AND name = ?",
                            (display_name, status, current_time, host_info['ip'], name)
                        )
                    else:
                        # Insert new running service
                        cursor.execute(
                            "INSERT INTO running_services (ip, name, display_name, status, last_updated) VALUES (?, ?, ?, ?, ?)",
                            (host_info['ip'], name, display_name, status, current_time)
                        )
        
        conn.commit()
        return host_info['ip']
        
    except sqlite3.Error as e:
        # Log the error and roll back
        print(f"Database error: {str(e)}")
        conn.rollback()
        return None
    except Exception as e:
        print(f"Error: {e}")
        pass

def query_database(conn, query_name, params=()):
    """
    Execute a predefined query against the database.
    
    Args:
        conn: Database connection
        query_name (str): Name of the query in SAMPLE_QUERIES
        params (tuple): Parameters for the query
        
    Returns:
        list: Query results as a list of dictionaries
    """
    if query_name not in SAMPLE_QUERIES:
        print(f"{Colors.RED}Error: Unknown query '{query_name}'{Colors.ENDC}")
        return []
    
    cursor = conn.cursor()
    cursor.execute(SAMPLE_QUERIES[query_name], params)
    return cursor.fetchall()

def export_to_csv(conn, output_file):
    """
    Export database contents to a CSV file.
    
    Args:
        conn: Database connection
        output_file (str): Path to the output CSV file
    """
    cursor = conn.cursor()
    
    with open(output_file, 'w') as f:
        # Write header
        f.write("IP,Status,Hostname,MAC_Address,OS,Services,Shares,Installed_Software,Running_Services,Foxit_License_Key\n")
        
        # Get all online hosts
        cursor.execute("""
            SELECT ip, status, hostname, mac_address, os
            FROM hosts
            WHERE status = 'online'
            ORDER BY ip
        """)
        
        for host in cursor.fetchall():
            ip = host['ip']
            
            # Get services
            cursor.execute("SELECT port, service_name FROM services WHERE ip = ?", (ip,))
            services = cursor.fetchall()
            services_str = "|".join([f"{s['port']}:{s['service_name']}" for s in services])
            
            # Get shares
            cursor.execute("SELECT share_name FROM shares WHERE ip = ?", (ip,))
            shares = cursor.fetchall()
            shares_str = "|".join([s['share_name'] for s in shares])
            
            # Get installed software
            cursor.execute("SELECT name FROM installed_software WHERE ip = ?", (ip,))
            software = cursor.fetchall()
            software_str = "|".join([s['name'] for s in software])
            
            # Get running services
            cursor.execute("""
                SELECT COALESCE(display_name, name) as service_name 
                FROM running_services 
                WHERE ip = ?
            """, (ip,))
            running_services = cursor.fetchall()
            services_str = "|".join([s['service_name'] for s in running_services])
            
            # Get Foxit license key
            cursor.execute("""
                SELECT value FROM system_info 
                WHERE ip = ? AND key = 'foxit_license_key'
            """, (ip,))
            foxit_key = cursor.fetchone()
            foxit_key_str = foxit_key['value'] if foxit_key else ""
            
            # Write the CSV line
            f.write(f"{host['ip']},{host['status']},{host['hostname']},{host['mac_address']},{host['os']},{services_str},{shares_str},{software_str},{services_str},{foxit_key_str}\n")
    
    print(f"\nResults exported to {output_file}")

def get_db_stats(conn):
    """
    Get basic statistics from the database.
    
    Args:
        conn: Database connection
        
    Returns:
        dict: Statistics about the database
    """
    cursor = conn.cursor()
    stats = {}
    
    # Count total hosts
    cursor.execute("SELECT COUNT(*) as count FROM hosts")
    stats['total_hosts'] = cursor.fetchone()['count']
    
    # Count online hosts
    cursor.execute("SELECT COUNT(*) as count FROM hosts WHERE status = 'online'")
    stats['online_hosts'] = cursor.fetchone()['count']
    
    # Count hosts by OS
    cursor.execute("""
        SELECT os, COUNT(*) as count
        FROM hosts
        WHERE status = 'online' AND os != ''
        GROUP BY os
        ORDER BY count DESC
    """)
    stats['os_distribution'] = cursor.fetchall()
    
    # Count top open ports
    cursor.execute("""
        SELECT s.port, s.service_name, COUNT(*) as count
        FROM services s
        JOIN hosts h ON s.ip = h.ip
        WHERE h.status = 'online'
        GROUP BY s.port, s.service_name
        ORDER BY count DESC
        LIMIT 10
    """)
    stats['top_ports'] = cursor.fetchall()
    
    # Count hosts with Foxit license keys
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM system_info
        WHERE key = 'foxit_license_key'
    """)
    stats['foxit_license_count'] = cursor.fetchone()['count']
    
    return stats

# ... [rest of the original code - scanning functions, etc.] ...

def scan_host(ip, full_scan=False, username=None, password=None, switch_config=None):
    """
    Scan a host for information.
    
    Args:
        ip (str): The IP address
        full_scan (bool): Whether to do a full scan (including OS detection)
        username (str): Username for authentication (Windows scanning)
        password (str): Password for authentication (Windows scanning)
        
    Returns:
        dict: Host information
    """
    result = {
        'ip': str(ip),
        'status': 'offline',
        'hostname': '',
        'mac_address': '',
        'vlan': '',
        'vlan': '',
        'vlan': '',
        'os': '',
        'services': {},
        'shares': [],
        'windows_info': {},
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    if ping(ip):
        result['status'] = 'online'
        
        # Try to get MAC address
        print(f"\n{Colors.BOLD}Scanning host: {ip}{Colors.ENDC}")
        mac_address, vlan = get_mac_and_vlan(ip, switch_config)
        result['mac_address'] = mac_address
        result['vlan'] = vlan
        
        # Try to get hostname
        result['hostname'] = get_improved_hostname(ip, username, password)
        
        if full_scan:
            result['os'] = os_detection(ip)
            result['services'] = scan_services(ip)
            
            # If it appears to be a Windows machine based on ports or OS detection
            is_windows = False
            
            # Check port 445 (SMB) is open - strong indicator of Windows
            if 445 in result['services'] or 139 in result['services']:
                is_windows = True
            
            # Check OS detection results
            if result['os'] and ('windows' in result['os'].lower() or 'microsoft' in result['os'].lower()):
                is_windows = True
            
            # If credentials provided or it looks like Windows, try Windows-specific scans
            if is_windows or (username and password):
                # Try to enumerate shares
                result['shares'] = enumerate_windows_shares(ip, username, password)
                
                # If credentials provided, attempt to scan Windows system
                if username and password:
                    if platform.system() == "Windows":
                        result['windows_info'] = scan_windows_system(ip, username, password)
                    else:
                        result['windows_info'] = scan_windows_system_linux(ip, username, password)
    
    return result

def main():
    parser = argparse.ArgumentParser(description="Network Discovery Tool")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-r', '--range', help='IP range (e.g., 192.168.1.1-192.168.1.254)')
    target_group.add_argument('-s', '--subnet', help='Subnet in CIDR notation (e.g., 192.168.1.0/24)')
    target_group.add_argument('-t', '--target', help='Single IP target')
    target_group.add_argument('-l', '--local', action='store_true', help='Scan local networks')
    target_group.add_argument('-q', '--query', choices=['online_hosts', 'hosts_with_port', 'hosts_with_software', 'hosts_with_foxit', 'scan_sessions'], help='Query the database without scanning')
    
    parser.add_argument('-f', '--full', action='store_true', help='Perform full scan (OS detection, service discovery)')
    parser.add_argument('-w', '--workers', type=int, default=50, help='Number of parallel workers (default: 50)')
    parser.add_argument('-o', '--output', help='Export results to CSV file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show offline hosts')
    parser.add_argument('-u', '--username', help='Username for Windows authentication')
    parser.add_argument('-p', '--password', help='Password for Windows authentication')
    parser.add_argument('--ask-password', action='store_true', help='Prompt for password instead of using command line argument')
    parser.add_argument('--find-foxit-license', action='store_true', help='Search for Foxit PDF license key')
    parser.add_argument('--db-path', default='network_discovery.db', help='Path to SQLite database file (default: network_discovery.db)')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    parser.add_argument('--param', help='Parameter for database query (used with --query)')
    
    # Switch configuration arguments
    parser.add_argument('--switch-ip', help='IP address of managed switch for MAC/VLAN lookup')
    parser.add_argument('--switch-username', help='Username for switch authentication')
    parser.add_argument('--switch-password', help='Password for switch authentication')
    parser.add_argument('--switch-secret', help='Enable password for switch (if required)')
    
    args = parser.parse_args()
    
    # Connect to the database
    conn, cursor = init_database(args.db_path)    
    # Build switch configuration
    switch_config = None
    if args.switch_ip and args.switch_username and args.switch_password:
        switch_config = {
            'enabled': True,
            'ip': args.switch_ip,
            'username': args.switch_username,
            'password': args.switch_password,
            'secret': args.switch_secret
        }
        print(f"Switch MAC/VLAN lookup enabled for {args.switch_ip}")
    
    # Handle query mode
    if args.query:
        params = (args.param,) if args.param else ()
        results = query_database(conn, args.query, params)
        
        if not results:
            print(f"No results found for query: {args.query}")
        else:
            print(f"\nResults for query: {args.query}")
            print("=" * 80)
            
            # Print column names
            columns = list(results[0].keys())
            print(" | ".join(columns))
            print("-" * 80)
            
            # Print rows
            for row in results:
                values = [str(row[col]) for col in columns]
                print(" | ".join(values))
            
            print(f"\nTotal results: {len(results)}")
        
        # Export to CSV if requested
        if args.output:
            export_to_csv(conn, args.output)
        
        conn.close()
        return
    
    # Show database statistics if requested
    if args.stats:
        stats = get_db_stats(conn)
        
        print("\nDatabase Statistics")
        print("=" * 80)
        print(f"Total hosts: {stats['total_hosts']}")
        print(f"Online hosts: {stats['online_hosts']} ({stats['online_hosts']/stats['total_hosts']*100:.1f}% if stats['total_hosts'] > 0 else 0.0%)")
        
        print("\nOS Distribution:")
        for os_info in stats['os_distribution']:
            print(f"  {os_info['os']}: {os_info['count']}")
        
        print("\nTop 10 Open Ports:")
        for port_info in stats['top_ports']:
            print(f"  Port {port_info['port']}: {port_info['count']} hosts")
        
        print(f"\nHosts with Foxit license keys: {stats['foxit_license_count']}")
        
        # Export to CSV if requested
        if args.output:
            export_to_csv(conn, args.output)
        
        conn.close()
        return
    
    # Handle password input securely
    password = None
    if args.ask_password:
        import getpass
        if args.username:
            password = getpass.getpass(f"Enter password for {args.username}: ")
        else:
            password = getpass.getpass("Enter password: ")
    else:
        password = args.password
    
    # Check for missing dependencies
    check_dependencies()
    
    targets = []
    target_description = ""
    
    # Generate target list based on input method
    if args.target:
        try:
            ipaddress.ip_address(args.target)
            targets.append(args.target)
            target_description = f"IP: {args.target}"
        except ValueError:
            print(f"Error: Invalid IP address: {args.target}")
            sys.exit(1)
    
    elif args.range:
        try:
            start, end = args.range.split('-')
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
            
            if start_ip.version != end_ip.version:
                print("Error: IP range must be of the same version (IPv4 or IPv6)")
                sys.exit(1)
            
            # Convert to integers for easier iteration
            start_int = int(start_ip)
            end_int = int(end_ip)
            
            if start_int > end_int:
                print("Error: Start IP must be less than or equal to end IP")
                sys.exit(1)
            
            for ip_int in range(start_int, end_int + 1):
                targets.append(str(ipaddress.ip_address(ip_int)))
            
            target_description = f"Range: {start}-{end}"
            
        except ValueError as e:
            print(f"Error: Invalid IP range: {e}")
            sys.exit(1)
    
    elif args.subnet:
        try:
            network = ipaddress.ip_network(args.subnet, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            target_description = f"Subnet: {args.subnet}"
        except ValueError as e:
            print(f"Error: Invalid subnet: {e}")
            sys.exit(1)
    
    elif args.local:
        local_networks = get_local_networks()
        if not local_networks:
            print("Error: Could not determine local networks. Please install netifaces or specify targets manually.")
            sys.exit(1)
        
        print(f"Detected local networks: {', '.join(local_networks)}")
        target_description = f"Local Networks: {', '.join(local_networks)}"
        
        for net_cidr in local_networks:
            try:
                network = ipaddress.ip_network(net_cidr, strict=False)
                targets.extend([str(ip) for ip in network.hosts()])
            except ValueError as e:
                print(f"Error with network {net_cidr}: {e}")
    
    # Remove duplicates
    targets = list(set(targets))
    
    if not targets:
        print("Error: No valid targets specified")
        sys.exit(1)
    
    print(f"\nStarting scan of {len(targets)} hosts at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'Full scan' if args.full else 'Basic scan'} with {args.workers} parallel workers")
    print(f"Storing results in database: {args.db_path}\n")
    
    # Start a new scan session in the database
    scan_type = "Full" if args.full else "Basic"
    session_id = start_scan_session(cursor, target_description, len(targets), scan_type)
    conn.commit()
    
    start_time = time.time()
    
    # Initialize output file if CSV export is requested
    output_file = None
    if args.output:
        print(f"Results will also be exported to CSV: {args.output} after scan completion")
    
    # Track statistics
    online_count = 0
    
    # Use ThreadPoolExecutor for parallel scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_ip = {executor.submit(scan_host, ip, args.full, args.username, password, switch_config): ip for ip in targets}
        
        # Show progress indicator
        total = len(targets)
        completed = 0
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                host_info = future.result()
                
                # Insert into database
                insert_host_to_db(conn, cursor, host_info, session_id)
                
                if host_info['status'] == 'online':
                    online_count += 1
                    print(format_scan_result(host_info))
                elif args.verbose:
                    print(format_scan_result(host_info, args.verbose))
                
            except Exception as e:
                print(f"{ip} - Error: {e}")
            
            completed += 1
            if completed % 10 == 0 or completed == total:
                progress = (completed / total) * 100
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                remaining = (total - completed) / rate if rate > 0 else 0
                
                sys.stdout.write(f"\rProgress: {completed}/{total} ({progress:.1f}%) | "
                               f"Online: {online_count} | "
                               f"Elapsed: {elapsed:.1f}s | "
                               f"Remaining: {remaining:.1f}s")
                sys.stdout.flush()
    
    # Update scan session with results
    end_scan_session(cursor, session_id, online_count)
    conn.commit()
    
    # Export to CSV if requested
    if args.output:
        export_to_csv(conn, args.output)
        
# Close the database connection
    conn.close()
    
    # Final stats
    duration = time.time() - start_time
    
    print(f"\n\nScan completed in {duration:.2f} seconds")
    print(f"Hosts scanned: {len(targets)}")
    print(f"Hosts online: {online_count} ({(online_count/len(targets))*100:.1f}%)")
    print(f"Results stored in database: {args.db_path}")
    print(f"To query results: {sys.argv[0]} --query online_hosts --db-path {args.db_path}")

# ... Keeping the original supporting functions but updating as needed ...

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

# Windows-specific modules - will only work on Windows
try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

WIN32NET_AVAILABLE = False
if platform.system() == "Windows":
    try:
        import win32wnet
        import win32netcon
        WIN32NET_AVAILABLE = True
    except ImportError:
        pass

# Linux-specific modules for Windows scanning
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# ANSI colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def is_admin():
    """Check if the script is running with administrative privileges."""
    if platform.system() == "Windows":
        try:
            return subprocess.run(["net", "session"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
        except:
            return False
    else:
        return os.geteuid() == 0

def ping(ip, timeout=1):
    """
    Ping an IP address to check if it's online.
    
    Args:
        ip (str): The IP address to ping
        timeout (int): Timeout in seconds
        
    Returns:
        bool: True if host is online, False otherwise
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', str(timeout), str(ip)]
    
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def find_foxit_license(ip, username, password):
    """
    Search for Foxit license key file in Foxit installation directories.
    
    Args:
        ip (str): The IP address
        username (str): Username for authentication
        password (str): Password for authentication
        
    Returns:
        str: Extracted license key or None if not found
    """
    license_key = None
    
    # Create credentials file for authentication
    fd, creds_file = tempfile.mkstemp(prefix="smb_auth_")
    try:
        with os.fdopen(fd, 'w') as f:
            # Parse domain if present
            if '\\' in username:
                domain, user = username.split('\\')
                f.write(f"username={user}\n")
                f.write(f"password={password}\n")
                f.write(f"domain={domain}\n")
            else:
                f.write(f"username={username}\n")
                f.write(f"password={password}\n")
        
        # Check specific Foxit directories in Program Files and Program Files (x86)
        foxit_dirs = [
            "Program Files/Foxit Software",
            "Program Files/Foxit Software/Foxit PDF Editor",
            "Program Files/Foxit Software/Foxit PhantomPDF",
            "Program Files/Foxit Software/Foxit Reader",
            "Program Files (x86)/Foxit Software",
            "Program Files (x86)/Foxit Software/Foxit PDF Editor",
            "Program Files (x86)/Foxit Software/Foxit PhantomPDF",
            "Program Files (x86)/Foxit Software/Foxit Reader"
        ]
        
        # Search in each potential Foxit directory
        for foxit_dir in foxit_dirs:
            print(f"{Colors.BLUE}Checking for fpmkey.txt in {foxit_dir}{Colors.ENDC}")
            try:
                # First check if directory exists
                cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd \"{foxit_dir}\"; dir'"
                try:
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                    print(f"{Colors.GREEN}Found Foxit directory: {foxit_dir}{Colors.ENDC}")
                    
                    # Now look for fpmkey.txt in this directory
                    cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd \"{foxit_dir}\"; dir fpmkey.txt'"
                    try:
                        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                        if "fpmkey.txt" in output:
                            print(f"{Colors.GREEN}Found fpmkey.txt in {foxit_dir}{Colors.ENDC}")
                            
                            # Get the file content
                            cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd \"{foxit_dir}\"; get fpmkey.txt -'"
                            try:
                                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                                
                                # Look for the license key pattern in the 'Restrictions' field
                                import re
                                # Try to match Code:XXXXX-XXXXX-XXXXX pattern
                                key_match = re.search(r'Code:([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})', output)
                                if key_match:
                                    license_key = key_match.group(1)
                                    print(f"{Colors.GREEN}Found Foxit license key: {license_key}{Colors.ENDC}")
                                    return license_key
                                
                                # If that doesn't work, try looking for a slightly different format
                                key_match = re.search(r'Restrictions=.*?Code:([A-Z0-9\-]+)', output)
                                if key_match:
                                    license_key = key_match.group(1)
                                    print(f"{Colors.GREEN}Found Foxit license key: {license_key}{Colors.ENDC}")
                                    return license_key
                                
                                # If still no match, dump the entire content for debugging
                                print(f"{Colors.YELLOW}Found fpmkey.txt but couldn't extract license automatically.{Colors.ENDC}")
                                print(f"{Colors.YELLOW}File content: {output}{Colors.ENDC}")
                                
                                # Try one more pattern with no dashes
                                key_match = re.search(r'Code:([A-Z0-9]+)', output)
                                if key_match:
                                    raw_key = key_match.group(1)
                                    # Format it as XXXXX-XXXXX-XXXXX if needed
                                    if len(raw_key) == 15:  # If it's a 15-char key without dashes
                                        license_key = f"{raw_key[:5]}-{raw_key[5:10]}-{raw_key[10:15]}"
                                    else:
                                        license_key = raw_key
                                    print(f"{Colors.GREEN}Found Foxit license key: {license_key}{Colors.ENDC}")
                                    return license_key
                                
                            except subprocess.CalledProcessError as e:
                                print(f"{Colors.RED}Error getting file content: {e.output.strip()}{Colors.ENDC}")
                    except subprocess.CalledProcessError:
                        print(f"{Colors.YELLOW}No fpmkey.txt found in {foxit_dir}{Colors.ENDC}")
                
                except subprocess.CalledProcessError:
                    # No Foxit directory found
                    pass
            except Exception as e:
                pass
    
    finally:
        # Clean up credentials file
        try:
            os.remove(creds_file)
        except:
            pass
    
    if not license_key:
        print(f"{Colors.YELLOW}No Foxit license key found{Colors.ENDC}")
    
    return license_key

def get_hostname(ip):
    """
    Get hostname for an IP address.
    
    Args:
        ip (str): The IP address
        
    Returns:
        str: Hostname or empty string if not found
    """
    try:
        return socket.getfqdn(str(ip))
    except:
        return ""

def scan_ports(ip, ports):
    """
    Scan specific ports on an IP address.
    
    Args:
        ip (str): The IP address
        ports (list): List of ports to scan
        
    Returns:
        dict: Dictionary of open ports and their services
    """
    open_ports = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((str(ip), port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            open_ports[port] = service
        sock.close()
    return open_ports

def os_detection(ip):
    """
    Attempt to detect OS using nmap.
    Requires nmap library and root/admin privileges.
    
    Args:
        ip (str): The IP address
        
    Returns:
        str: Detected OS or "Unknown"
    """
    if not NMAP_AVAILABLE:
        return "Unknown (nmap library not available)"
    
    if not is_admin():
        return "Unknown (admin privileges required for OS detection)"
    
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=str(ip), arguments='-O')
        if str(ip) in nm.all_hosts() and 'osmatch' in nm[str(ip)]:
            if len(nm[str(ip)]['osmatch']) > 0:
                return nm[str(ip)]['osmatch'][0]['name']
    except:
        pass
    return "Unknown"

def scan_services(ip):
    """
    Scan common services using nmap.
    
    Args:
        ip (str): The IP address
        
    Returns:
        dict: Dictionary of discovered services
    """
    if not NMAP_AVAILABLE:
        return scan_ports(ip, [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 464, 587, 636, 3306, 3389, 5900, 8080])
    
    services = {}
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=str(ip), arguments='-sV -F')
        
        if str(ip) in nm.all_hosts():
            for proto in nm[str(ip)].all_protocols():
                for port in nm[str(ip)][proto]:
                    port_info = nm[str(ip)][proto][port]
                    service_name = port_info['name']
                    if port_info['product']:
                        service_name += f" ({port_info['product']})"
                        if port_info['version']:
                            service_name += f" {port_info['version']}"
                    services[port] = service_name
    except:
        # Fall back to basic port scanning
        services = scan_ports(ip, [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 464, 587, 636, 3306, 3389, 5900, 8080])
    
    return services

def enumerate_windows_shares(ip, username=None, password=None):
    """
    Enumerate available shares on a Windows machine.
    
    Args:
        ip (str): The IP address
        username (str): Username for authentication
        password (str): Password for authentication
        
    Returns:
        list: List of available shares
    """
    shares = []
    
    # If authentication credentials provided, try direct listing first
    if username and password:
        # Create a credentials file for safer auth
        fd, creds_file = tempfile.mkstemp(prefix="smb_auth_")
        try:
            with os.fdopen(fd, 'w') as f:
                # Parse domain if present
                if '\\' in username:
                    domain, user = username.split('\\')
                    f.write(f"username={user}\n")
                    f.write(f"password={password}\n")
                    f.write(f"domain={domain}\n")
                else:
                    f.write(f"username={username}\n")
                    f.write(f"password={password}\n")
            
            # Use credentials file for authentication
            cmd = f"smbclient -L //{ip} -A {creds_file}"
            try:
                print(f"{Colors.BLUE}Trying to list shares with credentials file{Colors.ENDC}")
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                
                # Parse the output to extract shares
                current_section = None
                for line in output.splitlines():
                    line = line.strip()
                    
                    # Look for the Sharename section header
                    if "Sharename" in line and "Type" in line and "Comment" in line:
                        current_section = "shares"
                        continue
                    
                    # Parse shares section
                    if current_section == "shares" and line and not line.startswith("-"):
                        parts = line.split()
                        if len(parts) >= 2 and not parts[0] in ["Sharename", "---------"]:
                            shares.append(parts[0])
                
                print(f"{Colors.GREEN}Successfully enumerated {len(shares)} shares{Colors.ENDC}")
                
            except subprocess.CalledProcessError as e:
                print(f"{Colors.RED}Error listing shares: {e.output.strip()}{Colors.ENDC}")
                
                # Try another method with direct username/password
                try:
                    cmd = f"smbclient -L //{ip} -U '{username}%{password}'"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                    
                    # Parse the output to extract shares
                    current_section = None
                    for line in output.splitlines():
                        line = line.strip()
                        
                        # Look for the Sharename section header
                        if "Sharename" in line and "Type" in line and "Comment" in line:
                            current_section = "shares"
                            continue
                        
                        # Parse shares section
                        if current_section == "shares" and line and not line.startswith("-"):
                            parts = line.split()
                            if len(parts) >= 2 and not parts[0] in ["Sharename", "---------"]:
                                shares.append(parts[0])
                    
                    print(f"{Colors.GREEN}Successfully enumerated {len(shares)} shares with direct auth{Colors.ENDC}")
                    
                except subprocess.CalledProcessError as e2:
                    print(f"{Colors.RED}Error with direct auth: {e2.output.strip()}{Colors.ENDC}")
        
        finally:
            # Clean up credentials file
            try:
                os.remove(creds_file)
            except:
                pass
    
    # If no shares found or no credentials provided, try anonymous listing
    if not shares:
        try:
            cmd = f"smbclient -L //{ip} -N"
            try:
                print(f"{Colors.BLUE}Trying anonymous share listing{Colors.ENDC}")
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                
                # Parse the output for share names
                current_section = None
                for line in output.splitlines():
                    line = line.strip()
                    
                    # Look for the Sharename section header
                    if "Sharename" in line and "Type" in line and "Comment" in line:
                        current_section = "shares"
                        continue
                    
                    # Parse shares section
                    if current_section == "shares" and line and not line.startswith("-"):
                        parts = line.split()
                        if len(parts) >= 2 and not parts[0] in ["Sharename", "---------"]:
                            shares.append(parts[0])
                            
                print(f"{Colors.GREEN}Successfully enumerated {len(shares)} shares anonymously{Colors.ENDC}")
                
            except subprocess.CalledProcessError as e:
                print(f"{Colors.RED}Error with anonymous listing: {e.output.strip()}{Colors.ENDC}")
                
                # Try nmblookup as a fallback
                try:
                    cmd = f"nmblookup -A {ip}"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                    
                    # Just returning the NetBIOS name here
                    for line in output.splitlines():
                        if "<00>" in line and not "<GROUP>" in line:
                            netbios_name = line.split()[0]
                            shares.append("NetBIOS Name: " + netbios_name)
                            print(f"{Colors.GREEN}Found NetBIOS name: {netbios_name}{Colors.ENDC}")
                except:
                    pass
        except Exception as e:
            print(f"{Colors.RED}General error in share enumeration: {str(e)}{Colors.ENDC}")
    
    # If no shares found but we know host is up, add default administrative shares
    if not shares and ping(ip):
        shares = ["C$", "ADMIN$", "IPC$"]
        print(f"{Colors.YELLOW}Using default administrative shares list{Colors.ENDC}")
    
    return shares

def detect_windows_version(ip, username, password):
    """
    Detect Windows version by examining system files instead of using nmap.
    
    Args:
        ip (str): The IP address
        username (str): Username for authentication
        password (str): Password for authentication
        
    Returns:
        str: Detected Windows version or "Unknown"
    """
    # Create credentials file for authentication
    fd, creds_file = tempfile.mkstemp(prefix="smb_auth_")
    try:
        with os.fdopen(fd, 'w') as f:
            # Parse domain if present
            if '\\' in username:
                domain, user = username.split('\\')
                f.write(f"username={user}\n")
                f.write(f"password={password}\n")
                f.write(f"domain={domain}\n")
            else:
                f.write(f"username={username}\n")
                f.write(f"password={password}\n")
        
        # Method 1: Check Windows directory structure for version info
        version_info = {}
        
        # Check for specific Windows version identifiers
        version_files = {
            "system32\\license.rtf": {
                "Windows 10": "Windows 10",
                "Windows Server 2016": "Windows Server 2016",
                "Windows Server 2019": "Windows Server 2019"
            },
            "system32\\ntoskrnl.exe": True,  # Just check existence
            "servicing\\Version": True,  # Directory containing version info
        }
        
        for file_path, version_check in version_files.items():
            try:
                cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd Windows; ls {file_path}'"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                
                if "NT_STATUS_OBJECT_NAME_NOT_FOUND" not in output and "NT_STATUS_NO_SUCH_FILE" not in output:
                    version_info[file_path] = "Found"
            except subprocess.CalledProcessError:
                pass
        
        # Method 2: Get ProductName from registry system file
        try:
            # Try to get a copy of the SOFTWARE registry hive
            cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd Windows\\System32\\config; get SOFTWARE -'"
            # This would output a binary file, so we'll just check if it exists
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            if "NT_STATUS_OBJECT_NAME_NOT_FOUND" not in output and "NT_STATUS_NO_SUCH_FILE" not in output:
                version_info["registry_software"] = "Found"
        except subprocess.CalledProcessError:
            pass
        
        # Method 3: Check for specific Windows version directories
        windows_versions = {
            "WinSxS": "Windows Vista or later",
            "SysWOW64": "64-bit Windows",
            "winsxs\\x86_microsoft-windows-serveros_31bf3856ad364e35": "Windows Server",
            "winsxs\\amd64_microsoft-windows-serveros": "Windows Server 64-bit"
        }
        
        for dir_path, version_name in windows_versions.items():
            try:
                cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd Windows; ls {dir_path}'"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                
                if "NT_STATUS_OBJECT_NAME_NOT_FOUND" not in output and "NT_STATUS_NO_SUCH_FILE" not in output:
                    version_info[dir_path] = version_name
            except subprocess.CalledProcessError:
                pass
        
        # Method 4: Check for version-specific files
        specific_files = {
            "explorer.exe": True,
            "notepad.exe": True,
            "system32\\kernel32.dll": True,
            "system32\\win32k.sys": True
        }
        
        for file_path in specific_files.keys():
            try:
                cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd Windows; ls {file_path}'"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                
                if "NT_STATUS_OBJECT_NAME_NOT_FOUND" not in output and "NT_STATUS_NO_SUCH_FILE" not in output:
                    version_info[file_path] = "Found"
            except subprocess.CalledProcessError:
                pass
                
        # Now determine version based on the files found
        windows_os = "Windows (details undetermined)"
        
        # Look for Server-specific indicators
        if any("Server" in value for value in version_info.values() if isinstance(value, str)):
            windows_os = "Windows Server"
            
            # Try to determine specific server version
            if "winsxs\\amd64_microsoft-windows-serveros" in version_info:
                windows_os = "Windows Server (64-bit)"
                
            # Look for specific server versions based on file combinations
            if "system32\\license.rtf" in version_info and "registry_software" in version_info:
                if "SysWOW64" in version_info:
                    windows_os = "Windows Server 2016/2019/2022 (64-bit)"
                else:
                    windows_os = "Windows Server 2016/2019/2022"
        else:
            # Client OS indicators
            if "WinSxS" in version_info:
                windows_os = "Windows 10/11"
                
                if "SysWOW64" in version_info:
                    windows_os = "Windows 10/11 (64-bit)"
        
        # Add detail on whether Exchange or SQL Server is present
        if version_info.get("registry_software") == "Found":
            for app_dir in ["Microsoft Exchange Server", "Microsoft SQL Server"]:
                try:
                    cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd \"Program Files\"; ls \"{app_dir}\"'"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                    
                    if "NT_STATUS_OBJECT_NAME_NOT_FOUND" not in output:
                        if "Exchange" in app_dir:
                            windows_os += " with Exchange Server"
                        else:
                            windows_os += " with SQL Server"
                except subprocess.CalledProcessError:
                    pass
        
        return windows_os
        
    finally:
        # Clean up credentials file
        try:
            os.remove(creds_file)
        except:
            pass
    
    return "Windows (version undetermined)"

def scan_windows_system_linux(ip, username=None, password=None):
    """
    Scan a Windows system from Linux using various tools like SSH, smbclient, etc.
    
    Args:
        ip (str): The IP address
        username (str): Username for authentication
        password (str): Password for authentication
        
    Returns:
        dict: Dictionary with installed software and services
    """
    result = {
        'installed_software': [],
        'running_services': [],
        'system_info': {}
    }
    
    # If we have credentials, try to access C$ share
    if username and password:
        print(f"{Colors.BLUE}Attempting to scan Windows system at {ip}{Colors.ENDC}")
        
        # First, try to detect Windows version
        try:
            windows_version = detect_windows_version(ip, username, password)
            if windows_version:
                result['system_info']['os'] = windows_version
                print(f"{Colors.GREEN}Detected OS: {windows_version}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}Error detecting Windows version: {str(e)}{Colors.ENDC}")
        
        # Create credentials file for authentication
        fd, creds_file = tempfile.mkstemp(prefix="smb_auth_")
        try:
            with os.fdopen(fd, 'w') as f:
                # Parse domain if present
                if '\\' in username:
                    domain, user = username.split('\\')
                    f.write(f"username={user}\n")
                    f.write(f"password={password}\n")
                    f.write(f"domain={domain}\n")
                else:
                    f.write(f"username={username}\n")
                    f.write(f"password={password}\n")
            
            # Test if we can access C$ share
            try:
                cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'dir'"
                print(f"{Colors.BLUE}Testing access to C$ with credentials file{Colors.ENDC}")
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                
                print(f"{Colors.GREEN}Successfully accessed C$ share!{Colors.ENDC}")
                result['system_info']['admin_share_access'] = "Available"
                
                # Save raw output for debugging
                with open("smb_output_debug.txt", "w") as f:
                    f.write("DEBUG - Raw SMB Output:\n")
                    f.write(output)
                
                # Now we know we have access, try to gather information
                
                # 1. Check for Program Files
                print(f"{Colors.BLUE}Checking Program Files directory{Colors.ENDC}")
                try:
                    # Use -D option to get more detailed directory format
                    cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd \"Program Files\"; dir'"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                    
                    # Save raw output for debugging
                    with open("program_files_output.txt", "w") as f:
                        f.write("DEBUG - Program Files Output:\n")
                        f.write(output)
                    
                    # Try direct extraction first - looking for directory pattern
                    directories = []
                    for line in output.splitlines():
                        if "D        0" in line:
                            # Format appears to be like:
                            #   7-Zip                               D        0  Fri Nov 22 14:42:30 2024
                            parts = line.split("D        0")
                            if len(parts) >= 2:
                                name = parts[0].strip()
                                if name and name not in [".", ".."]:
                                    directories.append(name)
                    
                    # If that didn't work, try another approach
                    if not directories:
                        # Try another pattern - directories have D attribute at beginning
                        for line in output.splitlines():
                            if line.strip() and line[0:10].strip() and "D" in line[0:10]:
                                # Get everything before the first date field
                                parts = line.split("  ")
                                if parts:
                                    name = parts[0].strip()
                                    if name and name not in [".", ".."]:
                                        directories.append(name)
                    
                    # If that still didn't work, try yet another approach
                    if not directories:
                        # Manual approach - print lines with 'D' in first 10 chars
                        print(f"{Colors.YELLOW}DEBUG - Trying manual parsing{Colors.ENDC}")
                        for line in output.splitlines():
                            if line.strip() and len(line) > 10 and "D" in line[0:10]:
                                print(f"DEBUG LINE: {line}")
                                # Attempt to extract name
                                name = line.split("D        0")[0].strip() if "D        0" in line else None
                                if name and name not in [".", ".."]:
                                    directories.append(name)
                                    print(f"EXTRACTED: {name}")
                    
                    for prog_name in directories:
                        result['installed_software'].append({
                            'name': prog_name,
                            'path': f"C:\\Program Files\\{prog_name}"
                        })
                    
                    print(f"{Colors.GREEN}Found {len(directories)} programs in Program Files{Colors.ENDC}")
                    
                except Exception as e:
                    print(f"{Colors.RED}Error accessing Program Files: {str(e)}{Colors.ENDC}")
                
                # 2. Check for Program Files (x86)
                print(f"{Colors.BLUE}Checking Program Files (x86) directory{Colors.ENDC}")
                try:
                    cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd \"Program Files (x86)\"; dir'"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                    
                    # Same approach as above
                    directories = []
                    for line in output.splitlines():
                        if "D        0" in line:
                            parts = line.split("D        0")
                            if len(parts) >= 2:
                                name = parts[0].strip()
                                if name and name not in [".", ".."]:
                                    directories.append(name)
                    
                    # Fallback approaches if needed
                    if not directories:
                        for line in output.splitlines():
                            if line.strip() and line[0:10].strip() and "D" in line[0:10]:
                                parts = line.split("  ")
                                if parts:
                                    name = parts[0].strip()
                                    if name and name not in [".", ".."]:
                                        directories.append(name)
                    
                    for prog_name in directories:
                        result['installed_software'].append({
                            'name': prog_name,
                            'path': f"C:\\Program Files (x86)\\{prog_name}"
                        })
                    
                    print(f"{Colors.GREEN}Found {len(directories)} programs in Program Files (x86){Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.RED}Error accessing Program Files (x86): {str(e)}{Colors.ENDC}")
                
                # 3. Check Windows directory for system info
                print(f"{Colors.BLUE}Checking Windows directory{Colors.ENDC}")
                try:
                    cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd Windows; dir'"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                    result['system_info']['windows_directory'] = "C:\\Windows"
                    
                    # Check for version info in Windows directory
                    for version_file in ["system.ini", "win.ini"]:
                        try:
                            cmd = f"smbclient //{ip}/C$ -A {creds_file} -c 'cd Windows; get {version_file} -'"
                            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                            # Add version info to system_info
                            result['system_info'][f'{version_file}'] = "Found"
                        except:
                            pass
                except Exception as e:
                    print(f"{Colors.RED}Error accessing Windows directory: {str(e)}{Colors.ENDC}")

                # 4. Look for Foxit license if requested
                if '--find-foxit-license' in sys.argv:
                    print(f"{Colors.BLUE}Looking for Foxit license key{Colors.ENDC}")
                    foxit_key = find_foxit_license(ip, username, password)
                    if foxit_key:
                        result['system_info']['foxit_license_key'] = foxit_key
        
            except subprocess.CalledProcessError as e:
                print(f"{Colors.RED}Cannot access C$ share: {e.output.strip()}{Colors.ENDC}")
                result['system_info']['admin_share_access'] = "Not Available"
                
                # Try with direct username/password format as fallback
                try:
                    cmd = f"smbclient //{ip}/C$ -U '{username}%{password}' -c 'dir'"
                    print(f"{Colors.BLUE}Trying direct auth format as fallback{Colors.ENDC}")
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                    
                    print(f"{Colors.GREEN}Direct auth worked!{Colors.ENDC}")
                    result['system_info']['admin_share_access'] = "Available with direct auth"
                    
                except subprocess.CalledProcessError as e2:
                    print(f"{Colors.RED}Both auth methods failed for C$ access: {e2.output.strip()}{Colors.ENDC}")
        
        finally:
            # Clean up credentials file
            try:
                os.remove(creds_file)
            except:
                pass
    
    # Try to use nmblookup to get system info as fallback
    if not result['system_info'] and ping(ip):
        try:
            cmd = f"nmblookup -A {ip}"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            
            for line in output.splitlines():
                if "<00>" in line and not "<GROUP>" in line:
                    netbios_name = line.split()[0]
                    result['system_info']['netbios_name'] = netbios_name
                if "<20>" in line:
                    result['system_info']['file_server'] = True
                    
            print(f"{Colors.GREEN}Retrieved NetBIOS information{Colors.ENDC}")
        except:
            pass
    
    return result

def get_improved_hostname(ip, username=None, password=None):
    """
    Get hostname for an IP address using faster, targeted methods.
    
    Args:
        ip (str): The IP address
        username (str): Username for authentication (optional)
        password (str): Password for authentication (optional)
        
    Returns:
        str: Hostname or empty string if not found
    """
    hostname = ""
    
    # Method 1: Use nmap's rdp-ntlm-info script - much faster than full -A scan
    try:
        print(f"{Colors.BLUE}Getting hostname for {ip} using targeted nmap RDP scan{Colors.ENDC}")
        # This focused scan typically takes just a few seconds instead of minutes
        cmd = f"sudo nmap -p 3389 --script rdp-ntlm-info --script-timeout 10s {ip}"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True, timeout=15)
        
        # Extract hostname information from nmap's output
        netbios_name_match = re.search(r'NetBIOS_Computer_Name: ([^\s]+)', output)
        dns_name_match = re.search(r'DNS_Computer_Name: ([^\s]+)', output)
        
        if dns_name_match:
            hostname = dns_name_match.group(1)
            print(f"{Colors.GREEN}Found FQDN via nmap: {hostname}{Colors.ENDC}")
            return hostname

# MAC and VLAN functions from macscans.py
    except Exception as e:
        print(f"Error: {e}")
        pass

def convert_mac_format(mac):
    """
    Convert MAC from xxxx.xxxx.xxxx to xx:xx:xx:xx:xx:xx format.
    """
    try:
        mac = mac.replace(".", "").lower()
        if len(mac) != 12:
            return mac
        return ":".join(mac[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return mac
    except Exception as e:
        print(f"Error: {e}")
        pass

def query_switch_for_mac_vlan(ip, switch_ip, username, password, secret=None):
    """
    Query a Cisco switch for MAC address and VLAN information for a specific IP.
    Returns tuple of (mac_address, vlan) or (None, None) if not found.
    """
    try:
        from netmiko import ConnectHandler
    except ImportError:
        print(f"{Colors.YELLOW}netmiko not available, skipping switch query{Colors.ENDC}")
        return None, None
    
    switch = {
        "device_type": "cisco_ios",
        "ip": switch_ip,
        "username": username,
        "password": password,
        "secret": secret or "",
    }
    
    try:
        connection = ConnectHandler(**switch)
        if switch.get("secret"):
            connection.enable()
        
        arp_output = connection.send_command(f"show ip arp {ip}")
        arp_match = re.search(r"Internet\s+{}\s+\d+\s+([0-9a-fA-F.]+)\s+ARPA\s+(\S+)".format(ip), arp_output)
        if not arp_match:
            connection.send_command(f"ping {ip}")
            arp_output = connection.send_command(f"show ip arp {ip}")
            arp_match = re.search(r"Internet\s+{}\s+\d+\s+([0-9a-fA-F.]+)\s+ARPA\s+(\S+)".format(ip), arp_output)
        
        if arp_match:
            arp_mac, arp_interface = arp_match.groups()
            arp_mac_converted = convert_mac_format(arp_mac)
            mac_lookup = connection.send_command(f"show mac address-table | include {arp_mac}")
            
            if mac_lookup:
                for line in mac_lookup.splitlines():
                    if arp_mac in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            vlan = parts[0]
                            if vlan.isdigit():
                                connection.disconnect()
                                return arp_mac_converted, vlan
            
            connection.disconnect()
            return arp_mac_converted, None
        
        connection.disconnect()
        return None, None
        
    except Exception as e:
        print(f"{Colors.RED}Error querying switch: {e}{Colors.ENDC}")
        return None, None
    except Exception as e:
        print(f"Error: {e}")
        pass

def get_mac_and_vlan(ip, switch_config=None):
    """
    Get MAC address and VLAN for an IP using multiple methods.
    First tries switch query if configured, then falls back to local methods.
    """
    mac_address = ""
    vlan = ""
    
    if switch_config and switch_config.get("enabled", False):
        switch_mac, switch_vlan = query_switch_for_mac_vlan(
            ip, 
            switch_config["ip"], 
            switch_config["username"], 
            switch_config["password"],
            switch_config.get("secret")
        )
        if switch_mac:
            mac_address = switch_mac
            vlan = switch_vlan or ""
            print(f"{Colors.GREEN}Found MAC via switch: {mac_address} (VLAN {vlan}){Colors.ENDC}")
            return mac_address, vlan
    
    mac_address = get_mac_address(ip)
    return mac_address, vlan

# MAC and VLAN functions from macscans.py
# MAC and VLAN functions from macscans.py
# MAC and VLAN functions from macscans.py
# MAC and VLAN functions from macscans.py
# MAC and VLAN functions from macscans.py
# MAC and VLAN functions from macscans.py
# MAC and VLAN functions from macscans.py
# MAC and VLAN functions from macscans.py
# MAC and VLAN functions from macscans.py
def get_mac_address(ip):
    """
    Get MAC address for an IP address using faster methods.
    
    Args:
        ip (str): The IP address
        
    Returns:
        str: MAC address or empty string if not found
    """
    mac = ""
    
    # Method 1: Try using arp command (fastest)
    try:
        print(f"{Colors.BLUE}Getting MAC address for {ip} using arp{Colors.ENDC}")
        cmd = f"arp -n {ip}"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, universal_newlines=True)
        
        # Parse the output line by line
        for line in output.splitlines():
            if ip in line:
                # Match MAC address pattern in the line
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                if mac_match:
                    mac = mac_match.group(0)
                    print(f"{Colors.GREEN}Found MAC: {mac}{Colors.ENDC}")
                    return mac
    except Exception as e:
        print(f"{Colors.RED}Error getting MAC with arp: {str(e)}{Colors.ENDC}")
    
    # Method 2: Targeted nmap scan (much faster than -A)
    if not mac:
        try:
            print(f"{Colors.BLUE}Getting MAC with targeted nmap scan{Colors.ENDC}")
            # This is much faster than a full -A scan
            cmd = f"sudo nmap -sS -p 445 --max-retries 1 -n {ip}"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True, timeout=10)
            
            # Look for MAC Address line in the output
            mac_match = re.search(r'MAC Address: ([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})', output)
            if mac_match:
                mac = mac_match.group(1)
                print(f"{Colors.GREEN}Found MAC via nmap: {mac}{Colors.ENDC}")
                return mac
        except Exception as e:
            print(f"{Colors.RED}Error with nmap scan: {str(e)}{Colors.ENDC}")
    
    return mac

def format_scan_result(host_info, verbose=False):
    """
    Format scan results for terminal output.
    
    Args:
        host_info (dict): Host information
        verbose (bool): Whether to show detailed information
        
    Returns:
        str: Formatted output
    """
    if host_info['status'] == 'offline' and not verbose:
        return f"{host_info['ip']} - {Colors.RED}Offline{Colors.ENDC}"
    
    output = [f"{Colors.BOLD}{host_info['ip']}{Colors.ENDC} - {Colors.GREEN if host_info['status'] == 'online' else Colors.RED}{host_info['status'].title()}{Colors.ENDC}"]
    
    if host_info['status'] == 'online':
        if host_info['hostname'] and host_info['hostname'] != host_info['ip']:
            output.append(f"  Hostname: {Colors.BLUE}{host_info['hostname']}{Colors.ENDC}")
        
        if host_info['mac_address']:
            mac_display = f"  MAC: {Colors.YELLOW}{host_info['mac_address']}{Colors.ENDC}"
            if host_info.get('vlan'):
                mac_display += f" (VLAN {host_info['vlan']})"
            output.append(mac_display)
        
        if host_info['os']:
            output.append(f"  OS: {Colors.YELLOW}{host_info['os']}{Colors.ENDC}")
        
        if host_info['services']:
            output.append(f"  Services:")
            for port, service in sorted(host_info['services'].items()):
                output.append(f"    {Colors.BLUE}Port {port}{Colors.ENDC}: {service}")
        
        # Display Windows shares if any
        if host_info.get('shares'):
            output.append(f"  Shares:")
            for share in host_info['shares']:
                output.append(f"    {Colors.BLUE}{share}{Colors.ENDC}")
        
        # Display Windows info if available
        if host_info.get('windows_info'):
            win_info = host_info['windows_info']
            
            if win_info.get('system_info'):
                output.append(f"  System Information:")
                for key, value in win_info['system_info'].items():
                    output.append(f"    {key}: {value}")
            
            if win_info.get('installed_software'):
                output.append(f"  Installed Software:")
                # Limit to first 10 for display, with a count of total
                software_count = len(win_info['installed_software'])
                for software in win_info['installed_software'][:10]:
                    name = software.get('name', 'Unknown')
                    version = software.get('version', '')
                    if version:
                        output.append(f"    {Colors.BLUE}{name}{Colors.ENDC} - {version}")
                    else:
                        output.append(f"    {Colors.BLUE}{name}{Colors.ENDC}")
                
                if software_count > 10:
                    output.append(f"    ... and {software_count - 10} more")
            
            if win_info.get('running_services'):
                output.append(f"  Running Services:")
                # Limit to first 10 for display, with a count of total
                service_count = len(win_info['running_services'])
                for service in win_info['running_services'][:10]:
                    name = service.get('display_name', service.get('name', 'Unknown'))
                    output.append(f"    {Colors.BLUE}{name}{Colors.ENDC}")
                
                if service_count > 10:
                    output.append(f"    ... and {service_count - 10} more")
    
    return "\n".join(output)

def get_local_networks():
    """
    Get local network subnets.
    
    Returns:
        list: List of local network CIDR strings
    """
    if not NETIFACES_AVAILABLE:
        return []
    
    networks = []
    
    try:
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and 'netmask' in addr:
                        ip = addr['addr']
                        # Skip loopback
                        if ip.startswith('127.'):
                            continue
                        
                        # Convert netmask to CIDR notation
                        netmask = addr['netmask']
                        prefix_len = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                        networks.append(f"{ip}/{prefix_len}")
    except:
        pass
    
    return networks

def check_dependencies():
    """Check and inform about missing dependencies."""
    missing = []
    
    if not NMAP_AVAILABLE:
        missing.append("python-nmap (enhanced scanning capabilities)")
    
    if not NETIFACES_AVAILABLE:
        missing.append("netifaces (network interface detection)")
    
    if not PARAMIKO_AVAILABLE:
        missing.append("paramiko (SSH-based Windows system scanning)")
    
    if platform.system() == "Windows":
        if not WMI_AVAILABLE:
            missing.append("wmi (Windows system information via WMI)")
        
        if not WIN32NET_AVAILABLE:
            missing.append("pywin32 (Windows share access)")
    
    if missing:
        print(f"{Colors.YELLOW}Notice: The following optional dependencies are missing:{Colors.ENDC}")
        for pkg in missing:
            print(f"  - {pkg}")
        
        # Different installation instructions based on platform
        if platform.system() == "Windows":
            print(f"\nInstall them with: pip install python-nmap netifaces wmi pywin32 paramiko\n")
        else:
            print(f"\nInstall them with: pip install python-nmap netifaces paramiko\n")
            print(f"Note: For Linux systems scanning Windows machines, also ensure smbclient and nmblookup")
            print(f"are installed (typically available in the 'samba-client' package):\n")
            print(f"  Debian/Ubuntu: sudo apt install samba-client")
            print(f"  RHEL/CentOS:   sudo yum install samba-client")
            print(f"  Arch Linux:    sudo pacman -S smbclient\n")
        
def is_scan_already_running(target):
    """Check if a scan with the same target is already running."""
    try:
        # Look for existing processes with the same target
        cmd = f"ps -aux | grep b-activedisc | grep '{target}' | grep -v grep"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # If we found matching processes
        if result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            if len(lines) > 0:  # More than one process found
                print(f"Found existing processes running for target {target}:")
                for line in lines:
                    print(f"  {line}")
                return True
        
        return False
    except Exception as e:
        print(f"Error checking for running scans: {str(e)}")
        return False

if __name__ == "__main__":
    # Import os here to avoid potential issues with is_admin function
    import os
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan canceled by user")
        print("Partial results have been saved to the database")
        sys.exit(0)
