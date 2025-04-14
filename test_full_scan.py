#!/usr/bin/env python3
import subprocess
import sys
import os

def main():
    # Set the path to your scanner script
    scanner_path = '/opt/activediscovery/b-activedisc.py'
    db_path = '/opt/activediscovery/network_discovery.db'
    
    # Make sure the script is executable
    if not os.access(scanner_path, os.X_OK):
        os.chmod(scanner_path, 0o755)
        print(f"Made script executable: {scanner_path}")
    
    # Build a command to run a full scan of a single IP
    cmd = [sys.executable, scanner_path, '-t', '127.0.0.1', '--db-path', db_path, '-f']
    
    print(f"Running command: {' '.join(cmd)}")
    
    try:
        # Run the process with output displayed in real-time
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        # Monitor stdout in real-time
        print("=== STDOUT ===")
        for line in iter(process.stdout.readline, ''):
            print(line.strip())
        
        # Get any stderr output
        stderr = process.stderr.read()
        if stderr:
            print("=== STDERR ===")
            print(stderr)
        
        # Wait for process to complete
        exit_code = process.wait()
        print(f"Process exited with code: {exit_code}")
        
    except Exception as e:
        print(f"Error executing command: {e}")

if __name__ == "__main__":
    main()
