#!/bin/bash

# Sidney Scanner Sudo Wrapper
# This script runs sidney-scanner.py with sudo while preserving the virtual environment

# Get the current virtual environment path
if [[ "$VIRTUAL_ENV" != "" ]]; then
    VENV_PYTHON="$VIRTUAL_ENV/bin/python3"
    echo "Using virtual environment Python: $VENV_PYTHON"
else
    echo "Warning: No virtual environment detected"
    VENV_PYTHON="python3"
fi

# Run the scanner with sudo, preserving environment variables and using venv python
sudo -E env PATH="$PATH" "$VENV_PYTHON" sidney-scanner.py "$@"
