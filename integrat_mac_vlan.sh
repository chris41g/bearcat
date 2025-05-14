#!/bin/bash

# Script to integrate MAC/VLAN functionality into sidney-scanner.py

echo "Backing up original file..."
cp sidney-scanner.py sidney-scanner.py.backup

echo "Applying MAC/VLAN integration..."

# 1. Add vlan field to CREATE_TABLES_SQL
sed -i '/mac_address TEXT,/a\    vlan TEXT,' sidney-scanner.py

# 2. Update SAMPLE_QUERIES
sed -i 's/SELECT ip, hostname, os, mac_address, last_seen/SELECT ip, hostname, os, mac_address, vlan, last_seen/' sidney-scanner.py

# 3. Add the new functions after get_improved_hostname
sed -i '/return hostname$/a\\n# MAC and VLAN functions from macscans.py\ndef convert_mac_format(mac):\n    """Convert MAC from xxxx.xxxx.xxxx to xx:xx:xx:xx:xx:xx format."""\n    try:\n        mac = mac.replace(".", "").lower()\n        if len(mac) != 12:\n            return mac\n        return ":".join(mac[i:i+2] for i in range(0, 12, 2))\n    except Exception:\n        return mac\n\ndef query_switch_for_mac_vlan(ip, switch_ip, username, password, secret=None):\n    """\n    Query a Cisco switch for MAC address and VLAN information for a specific IP.\n    Returns tuple of (mac_address, vlan) or (None, None) if not found.\n    """\n    try:\n        from netmiko import ConnectHandler\n    except ImportError:\n        print(f"{Colors.YELLOW}netmiko not available, skipping switch query{Colors.ENDC}")\n        return None, None\n    \n    switch = {\n        "device_type": "cisco_ios",\n        "ip": switch_ip,\n        "username": username,\n        "password": password,\n        "secret": secret or "",\n    }\n    \n    try:\n        connection = ConnectHandler(**switch)\n        if switch.get("secret"):\n            connection.enable()\n        \n        arp_output = connection.send_command(f"show ip arp {ip}")\n        arp_match = re.search(r"Internet\\s+{}\\s+\\d+\\s+([0-9a-fA-F.]+)\\s+ARPA\\s+(\\S+)".format(ip), arp_output)\n        if not arp_match:\n            connection.send_command(f"ping {ip}")\n            arp_output = connection.send_command(f"show ip arp {ip}")\n            arp_match = re.search(r"Internet\\s+{}\\s+\\d+\\s+([0-9a-fA-F.]+)\\s+ARPA\\s+(\\S+)".format(ip), arp_output)\n        \n        if arp_match:\n            arp_mac, arp_interface = arp_match.groups()\n            arp_mac_converted = convert_mac_format(arp_mac)\n            mac_lookup = connection.send_command(f"show mac address-table | include {arp_mac}")\n            \n            if mac_lookup:\n                for line in mac_lookup.splitlines():\n                    if arp_mac in line:\n                        parts = line.split()\n                        if len(parts) >= 4:\n                            vlan = parts[0]\n                            if vlan.isdigit():\n                                connection.disconnect()\n                                return arp_mac_converted, vlan\n            \n            connection.disconnect()\n            return arp_mac_converted, None\n        \n        connection.disconnect()\n        return None, None\n        \n    except Exception as e:\n        print(f"{Colors.RED}Error querying switch: {e}{Colors.ENDC}")\n        return None, None\n\ndef get_mac_and_vlan(ip, switch_config=None):\n    """\n    Get MAC address and VLAN for an IP using multiple methods.\n    First tries switch query if configured, then falls back to local methods.\n    """\n    mac_address = ""\n    vlan = ""\n    \n    if switch_config and switch_config.get("enabled", False):\n        switch_mac, switch_vlan = query_switch_for_mac_vlan(\n            ip, \n            switch_config["ip"], \n            switch_config["username"], \n            switch_config["password"],\n            switch_config.get("secret")\n        )\n        if switch_mac:\n            mac_address = switch_mac\n            vlan = switch_vlan or ""\n            print(f"{Colors.GREEN}Found MAC via switch: {mac_address} (VLAN {vlan}){Colors.ENDC}")\n            return mac_address, vlan\n    \n    mac_address = get_mac_address(ip)\n    return mac_address, vlan' sidney-scanner.py

echo "Creating a Python script to make the remaining changes..."

cat > apply_mac_vlan_changes.py << 'EOF'
#!/usr/bin/env python3

import re

# Read the file
with open('sidney-scanner.py', 'r') as f:
    content = f.read()

# 1. Update scan_host function signature
content = re.sub(
    r'def scan_host\(ip, full_scan=False, username=None, password=None\):',
    'def scan_host(ip, full_scan=False, username=None, password=None, switch_config=None):',
    content
)

# 2. Add vlan to result dictionary
content = re.sub(
    r"(\s+'mac_address': '',\n)",
    r"\1        'vlan': '',\n",
    content
)

# 3. Update MAC address retrieval
content = re.sub(
    r"(\s+# Try to get MAC address\n\s+print.*\n\s+)result\['mac_address'\] = get_mac_address\(ip\)",
    r"\1mac_address, vlan = get_mac_and_vlan(ip, switch_config)\n        result['mac_address'] = mac_address\n        result['vlan'] = vlan",
    content
)

# 4. Update database queries
content = re.sub(
    r'"UPDATE hosts SET status = \?, hostname = \?, mac_address = \?, os = \?, last_seen = \? WHERE ip = \?"',
    '"UPDATE hosts SET status = ?, hostname = ?, mac_address = ?, vlan = ?, os = ?, last_seen = ? WHERE ip = ?"',
    content
)

content = re.sub(
    r"(\s+host_info\['mac_address'\],\n)",
    r"\1                    host_info.get('vlan', ''),\n",
    content,
    count=1
)

content = re.sub(
    r'"INSERT INTO hosts \(ip, status, hostname, mac_address, os, first_seen, last_seen\) VALUES \(\?, \?, \?, \?, \?, \?, \?\)"',
    '"INSERT INTO hosts (ip, status, hostname, mac_address, vlan, os, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"',
    content
)

content = re.sub(
    r"(\s+host_info\['mac_address'\],\n)",
    r"\1                    host_info.get('vlan', ''),\n",
    content
)

# 5. Add switch arguments
switch_args = '''    
    # Switch configuration arguments
    parser.add_argument('--switch-ip', help='IP address of managed switch for MAC/VLAN lookup')
    parser.add_argument('--switch-username', help='Username for switch authentication')
    parser.add_argument('--switch-password', help='Password for switch authentication')
    parser.add_argument('--switch-secret', help='Enable password for switch (if required)')'''

content = re.sub(
    r"(\s+parser\.add_argument\('--param'.*\n)",
    r"\1" + switch_args + "\n",
    content
)

# 6. Add switch configuration logic
switch_config = '''    
    # Build switch configuration
    switch_config = None
    if args.switch_ip and args.switch_username and args.switch_password:
        switch_config = {
            'enabled': True,
            'ip': args.switch_ip,
            'username': args.switch_username,
            'password': args.switch_password,
            'secret': args.switch_secret
        }
        print(f"Switch MAC/VLAN lookup enabled for {args.switch_ip}")
    '''

content = re.sub(
    r"(\s+# Handle database-only operations\n)",
    switch_config + "\n\1",
    content
)

# 7. Update scan_host call in ThreadPoolExecutor
content = re.sub(
    r'future_to_ip = \{executor\.submit\(scan_host, ip, args\.full, args\.username, password\): ip for ip in targets\}',
    'future_to_ip = {executor.submit(scan_host, ip, args.full, args.username, password, switch_config): ip for ip in targets}',
    content
)

# 8. Update format_scan_result function
format_update = '''        if host_info['mac_address']:
            mac_display = f"  MAC: {Colors.YELLOW}{host_info['mac_address']}{Colors.ENDC}"
            if host_info.get('vlan'):
                mac_display += f" (VLAN {host_info['vlan']})"
            output.append(mac_display)
        '''

content = re.sub(
    r"(\s+if host_info\['hostname'\].*\n\s+output\.append.*\n\s+)",
    r"\1" + format_update + "\n",
    content
)

# Write the updated content
with open('sidney-scanner.py', 'w') as f:
    f.write(content)

print("Applied all MAC/VLAN integration changes!")
EOF

chmod +x apply_mac_vlan_changes.py
python3 apply_mac_vlan_changes.py

echo "MAC/VLAN integration complete!"
echo "You can now use sidney-scanner with switch configuration:"
echo "sudo python3 sidney-scanner.py -s 192.168.1.0/24 --switch-ip 192.168.1.1 --switch-username admin --switch-password mypass --switch-secret enablepass"
