#!/usr/bin/env python3
import os
import sys
import subprocess
import time

def main():
    print("Testing scanner functionality")
    
    # Try to run the script directly
    script_path = '/opt/activediscovery/b-activedisc.py'
    if not os.path.exists(script_path):
        print(f"Error: Script not found at {script_path}")
        return
    
    cmd = [sys.executable, script_path, '-t', '127.0.0.1']
    print(f"Running command: {' '.join(cmd)}")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True
        )
        
        # Monitor output
        print("Monitoring output:")
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                print(f"OUTPUT: {line.strip()}")
        
        # Check for errors
        stderr = process.stderr.read()
        if stderr:
            print(f"STDERR: {stderr}")
        
        return_code = process.poll()
        print(f"Process exited with code: {return_code}")
        
    except Exception as e:
        print(f"Error running scanner: {str(e)}")

if __name__ == "__main__":
    main()
