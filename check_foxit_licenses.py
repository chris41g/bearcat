#!/usr/bin/env python3
import sqlite3
import sys
import os

def main():
    """Check the system_info table for Foxit license keys and allow manual addition."""
    if len(sys.argv) < 2:
        print("Usage: check_foxit_licenses.py <database_path>")
        return
        
    db_path = sys.argv[1]
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if system_info table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_info'")
    if not cursor.fetchone():
        print("Error: system_info table does not exist in the database")
        conn.close()
        return
    
    # Check for existing Foxit license keys
    cursor.execute("""
        SELECT h.id, h.ip, h.hostname, si.value AS foxit_license_key
        FROM hosts h
        JOIN system_info si ON h.id = si.host_id
        WHERE si.key = 'foxit_license_key'
    """)
    
    existing_licenses = cursor.fetchall()
    if existing_licenses:
        print(f"Found {len(existing_licenses)} Foxit license keys in the database:")
        for license in existing_licenses:
            print(f"  Host ID: {license['id']}, IP: {license['ip']}, Key: {license['foxit_license_key']}")
    else:
        print("No Foxit license keys found in the database")
    
    # Option to manually add a license key
    add_manually = input("\nWould you like to manually add a Foxit license key? (y/n): ")
    if add_manually.lower() == 'y':
        # Get list of hosts to choose from
        cursor.execute("SELECT id, ip, hostname FROM hosts WHERE status = 'online' ORDER BY ip")
        hosts = cursor.fetchall()
        
        if not hosts:
            print("Error: No online hosts found in the database")
            conn.close()
            return
        
        print("\nAvailable hosts:")
        for i, host in enumerate(hosts):
            print(f"{i+1}. ID: {host['id']}, IP: {host['ip']}, Hostname: {host['hostname'] or 'unknown'}")
        
        host_idx = int(input("\nSelect host number: ")) - 1
        if host_idx < 0 or host_idx >= len(hosts):
            print("Invalid selection")
            conn.close()
            return
        
        selected_host = hosts[host_idx]
        license_key = input(f"Enter Foxit license key for {selected_host['ip']}: ")
        
        # Check if this host already has a license key
        cursor.execute("""
            SELECT id FROM system_info
            WHERE host_id = ? AND key = 'foxit_license_key'
        """, (selected_host['id'],))
        
        existing = cursor.fetchone()
        if existing:
            # Update existing record
            cursor.execute("""
                UPDATE system_info
                SET value = ?
                WHERE host_id = ? AND key = 'foxit_license_key'
            """, (license_key, selected_host['id']))
            print(f"Updated Foxit license key for host {selected_host['ip']}")
        else:
            # Insert new record
            cursor.execute("""
                INSERT INTO system_info (host_id, key, value)
                VALUES (?, 'foxit_license_key', ?)
            """, (selected_host['id'], license_key))
            print(f"Added Foxit license key for host {selected_host['ip']}")
        
        conn.commit()
    
    conn.close()
    print("Done")

if __name__ == "__main__":
    main()
