#!/usr/bin/env python3
import re

# Read the file
with open('sidney-scanner.py', 'r') as f:
    content = f.read()

# Find all function definitions
functions = {}
lines = content.split('\n')
output_lines = []
skip_until_next_def = False
current_function = None

i = 0
while i < len(lines):
    line = lines[i]
    
    # Check if this is a function definition
    func_match = re.match(r'^def\s+(\w+)\s*\(', line)
    if func_match:
        func_name = func_match.group(1)
        
        # If we've seen this function before, skip it
        if func_name in functions:
            print(f"Skipping duplicate function: {func_name}")
            # Skip until we find the next function or class definition
            i += 1
            while i < len(lines):
                if re.match(r'^(def|class|\S)', lines[i]):
                    i -= 1  # Back up one line to process this definition
                    break
                i += 1
        else:
            functions[func_name] = True
            output_lines.append(line)
        skip_until_next_def = False
    else:
        # Not a function definition, include the line
        output_lines.append(line)
    
    i += 1

# Write the cleaned content back
with open('sidney-scanner.py', 'w') as f:
    f.write('\n'.join(output_lines))

print("Fixed duplicate function definitions")
