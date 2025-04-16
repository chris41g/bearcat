#!/bin/bash
# Force sudo for all operations
echo "Starting network discovery with sudo" >&2
echo "Command: sudo python3 /opt/activediscovery/b-activedisc.py $@" >&2

# Execute with sudo - this will ensure elevated privileges
sudo python3 /opt/activediscovery/b-activedisc.py "$@"

# Capture and return the exit code
exit $?
