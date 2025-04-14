#!/usr/bin/env python3
import subprocess
import sys

# Use the same command that your scanner would use
cmd = [sys.executable, '/opt/activediscovery/b-activedisc.py', '-t', '10.0.10.171']

try:
    print(f"Trying to execute: {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True
    )
    
    # Read and print output
    print("Command started, reading output:")
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
    
    # Print return code
    print(f"Process exited with code: {process.returncode}")
    
except Exception as e:
    print(f"ERROR: {str(e)}")
