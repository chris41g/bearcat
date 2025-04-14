#!/usr/bin/env python3
import sys
import time
import os

# Log to a file for debugging
with open('/tmp/scanner_test.log', 'a') as f:
    f.write(f"Script executed at {time.ctime()}\n")
    f.write(f"Arguments: {sys.argv}\n")
    f.write(f"Working directory: {os.getcwd()}\n")
    f.write(f"Environment: {os.environ}\n")
    f.write("-" * 50 + "\n")

# Simulate a successful scan
print("10.0.10.1 - Online")
print("Progress: 1/1 (100.0%) | Online: 1")
print("Scan completed in 1.23 seconds")
