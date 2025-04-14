#!/usr/bin/env python3
import os
import sys
import platform

print(f"Python version: {platform.python_version()}")
print(f"Executable: {sys.executable}")
print(f"Working directory: {os.getcwd()}")
print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', '')}")

for key, value in sorted(os.environ.items()):
    print(f"{key}={value}")
