#!/usr/bin/env python3
"""
Sidney Database Migration Script

This script migrates the Sidney database from the old schema (with host_id as primary key)
to the new schema (with IP as primary key). It creates a backup before migration.
"""

import sqlite3
import os
import sys
import shutil
from datetime import datetime

# Define the new schema
CREATE_TABLES_SQL = """
-- Main hosts table (one entry per unique IP)
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    hostname TEXT,
    mac_address TEXT,
    os TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL
);

-- Scan history table to track when hosts were scanned
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    status TEXT NOT NULL,
    scan_time TIMESTAMP NOT NULL,
    session_id INTEGER,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
);

-- Services table (ports/services found on hosts)
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    service_name TEXT,
    last_updated TIMESTAMP NOT NULL,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    UNIQUE(ip, port)
);

-- Shares table (SMB shares found on hosts)
CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    share_name TEXT NOT NULL,
    last_updated TIMESTAMP NOT NULL,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    UNIQUE(ip, share_name)
);

-- System info table (detailed Windows system information)
CREATE TABLE IF NOT EXISTS system_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    last_updated TIMESTAMP NOT NULL,
    FOREIGN KEY (ip) REFERENCES hosts (ip),
    UNIQUE(ip, key)
);

-- Installed software table
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

-- Running services table
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

-- Scan sessions table to group scans
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    target_range TEXT,
    hosts_total INTEGER,
    hosts_online INTEGER,
    scan_type TEXT
);
"""

def migrate_database(db_path):
    """
    Migrate the database from old schema to new schema.
    
    Args:
        db_path (str): Path to the database file
    """
    print(f"Starting migration of database: {db_path}")
    
    # Create backup
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    print(f"Creating backup at: {backup_path}")
    shutil.copy2(db_path, backup_path)
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if this is the right schema for migration
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'")
    has_hosts_table = cursor.fetchone() is not None
    
    if not has_hosts_table:
        print("Error: Database doesn't have a hosts table. Cannot migrate.")
        conn.close()
        return False
    
    # Check if the old schema has a scan_time column
    cursor.execute("PRAGMA table_info(hosts)")
    columns = cursor.fetchall()
    column_names = [col['name'] for col in columns]
    
    if 'scan_time' not in column_names:
        print("Error: The hosts table doesn't have a scan_time column. This doesn't appear to be the old schema.")
        conn.close()
        return False
    
    if 'last_seen' in column_names:
        print("The hosts table already has a last_seen column. Migration may have already been performed.")
        confirm = input("Continue with migration anyway? (y/n): ")
        if confirm.lower() != 'y':
            conn.close()
            return False
    
    print("Detected old schema. Proceeding with migration...")
    
    # Begin transaction
    cursor.execute("BEGIN TRANSACTION")
    
    try:
        # 1. Create backup tables to preserve the data
        print("Creating backup tables...")
        cursor.execute("ALTER TABLE hosts RENAME TO hosts_old")
        
        tables_to_backup = [
            "services", "shares", "system_info", 
            "installed_software", "running_services"
        ]
        
        for table in tables_to_backup:
            try:
                cursor.execute(f"ALTER TABLE {table} RENAME TO {table}_old")
                print(f"  Backed up table: {table}")
            except sqlite3.OperationalError:
                print(f"  Table {table} doesn't exist, skipping")
        
        # 2. Create the new tables
        print("Creating new tables...")
        for statement in CREATE_TABLES_SQL.split(';'):
            if statement.strip():
                cursor.execute(statement)
        
        # 3. Migrate hosts data
        print("Migrating hosts data...")
        cursor.execute("""
            INSERT INTO hosts (ip, status, hostname, mac_address, os, first_seen, last_seen)
            SELECT h1.ip, h1.status, h1.hostname, h1.mac_address, h1.os, 
                   MIN(h1.scan_time) as first_seen, 
                   MAX(h1.scan_time) as last_seen
            FROM hosts_old h1
            GROUP BY h1.ip
        """)
        print(f"  Migrated {cursor.rowcount} hosts")
        
        # 4. Migrate scan history
        print("Creating scan history records...")
        cursor.execute("""
            INSERT INTO scan_history (ip, status, scan_time, session_id)
            SELECT ip, status, scan_time, NULL
            FROM hosts_old
        """)
        print(f"  Created {cursor.rowcount} scan history records")
        
        # 5. Update scan history with session IDs if possible
        print("Updating scan history with session IDs...")
        cursor.execute("""
            UPDATE scan_history
            SET session_id = (
                SELECT id FROM scan_sessions
                WHERE scan_history.scan_time BETWEEN start_time AND 
                      COALESCE(end_time, datetime('now'))
                LIMIT 1
            )
            WHERE session_id IS NULL
        """)
        
        # 6. Migrate services data
        try:
            print("Migrating services data...")
            cursor.execute("""
                INSERT INTO services (ip, port, service_name, last_updated)
                SELECT h.ip, s.port, s.service_name, MAX(h.scan_time) as last_updated
                FROM services_old s
                JOIN hosts_old h ON s.host_id = h.id
                GROUP BY h.ip, s.port
            """)
            print(f"  Migrated {cursor.rowcount} services")
        except sqlite3.OperationalError:
            print("  No services table found or migration error, skipping")
        
        # 7. Migrate shares data
        try:
            print("Migrating shares data...")
            cursor.execute("""
                INSERT INTO shares (ip, share_name, last_updated)
                SELECT h.ip, s.share_name, MAX(h.scan_time) as last_updated
                FROM shares_old s
                JOIN hosts_old h ON s.host_id = h.id
                GROUP BY h.ip, s.share_name
            """)
            print(f"  Migrated {cursor.rowcount} shares")
        except sqlite3.OperationalError:
            print("  No shares table found or migration error, skipping")
        
        # 8. Migrate system info
        try:
            print("Migrating system info...")
            cursor.execute("""
                INSERT INTO system_info (ip, key, value, last_updated)
                SELECT h.ip, s.key, s.value, MAX(h.scan_time) as last_updated
                FROM system_info_old s
                JOIN hosts_old h ON s.host_id = h.id
                GROUP BY h.ip, s.key
            """)
            print(f"  Migrated {cursor.rowcount} system info records")
        except sqlite3.OperationalError:
            print("  No system_info table found or migration error, skipping")
        
        # 9. Migrate installed software
        try:
            print("Migrating installed software...")
            cursor.execute("""
                INSERT INTO installed_software (ip, name, version, path, last_updated)
                SELECT h.ip, s.name, s.version, s.path, MAX(h.scan_time) as last_updated
                FROM installed_software_old s
                JOIN hosts_old h ON s.host_id = h.id
                GROUP BY h.ip, s.name, s.path
            """)
            print(f"  Migrated {cursor.rowcount} software records")
        except sqlite3.OperationalError:
            print("  No installed_software table found or migration error, skipping")
        
        # 10. Migrate running services
        try:
            print("Migrating running services...")
            cursor.execute("""
                INSERT INTO running_services (ip, name, display_name, status, last_updated)
                SELECT h.ip, s.name, s.display_name, s.status, MAX(h.scan_time) as last_updated
                FROM running_services_old s
                JOIN hosts_old h ON s.host_id = h.id
                GROUP BY h.ip, s.name
            """)
            print(f"  Migrated {cursor.rowcount} running services")
        except sqlite3.OperationalError:
            print("  No running_services table found or migration error, skipping")
        
        # 11. Commit the transaction
        print("Committing transaction...")
        conn.commit()
        print("Migration completed successfully.")
        print(f"Original database backed up at: {backup_path}")
        
        return True
        
    except Exception as e:
        # Roll back on error
        conn.rollback()
        print(f"Error during migration: {str(e)}")
        print("Rolling back changes...")
        print(f"You can still use the backup at: {backup_path}")
        return False
    
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python migrate_sidney_db.py /path/to/database.db")
        sys.exit(1)
    
    db_path = sys.argv[1]
    
    if not os.path.exists(db_path):
        print(f"Error: Database file {db_path} does not exist")
        sys.exit(1)
    
    success = migrate_database(db_path)
    if success:
        print("Migration completed successfully!")
        sys.exit(0)
    else:
        print("Migration failed.")
        sys.exit(1)
