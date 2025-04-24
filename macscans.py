import argparse
from netmiko import ConnectHandler
import json
import re

def convert_mac_format(mac):
    """Convert MAC from xxxx.xxxx.xxxx to xx:xx:xx:xx:xx:xx format."""
    try:
        mac = mac.replace('.', '').lower()
        if len(mac) != 12:
            return mac
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return mac

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Query Cisco switch for MAC and ARP information.")
    parser.add_argument('--ip', required=True, help="Switch IP address")
    parser.add_argument('--username', required=True, help="SSH username")
    parser.add_argument('--password', required=True, help="SSH password")
    parser.add_argument('--secret', help="Enable password (if required)")
    parser.add_argument('--find-ip', help="IP address to find MAC for")
    parser.add_argument('--show-mac-table', action='store_true', help="Show MAC address table for sub-switch ports")
    parser.add_argument('--max-entries', type=int, default=50, help="Max MAC table entries to show (default: 50)")

    args = parser.parse_args()

    # Define switch details
    switch = {
        'device_type': 'cisco_ios',
        'ip': args.ip,
        'username': args.username,
        'password': args.password,
        'secret': args.secret or '',
    }

    # Ports to sub-switches (only used if MAC table requested)
    sub_switch_ports = ["TenGigabitEthernet1/1/2", "TenGigabitEthernet1/1/4", "TenGigabitEthernet1/1/8"]

    try:
        # Connect
        print(f"Connecting to {switch['ip']}...")
        connection = ConnectHandler(**switch)
        if switch.get('secret'):
            connection.enable()

        # Handle IP-to-MAC lookup
        if args.find_ip:
            print(f"\nLooking up MAC for IP {args.find_ip}...")
            arp_output = connection.send_command(f"show ip arp {args.find_ip}")
            print("\nARP Raw Output:")
            print(arp_output if arp_output else "No ARP entry found.")

            # Parse ARP output (e.g., "Internet  192.168.1.100  10  c047.0ede.d0d1  ARPA  Vlan101")
            arp_match = re.search(r'Internet\s+{}\s+\d+\s+([0-9a-fA-F.]+)\s+ARPA\s+(\S+)'.format(args.find_ip), arp_output)
            if arp_match:
                arp_mac, arp_interface = arp_match.groups()
                arp_mac_converted = convert_mac_format(arp_mac)
                print(f"\nFound: IP {args.find_ip} -> MAC {arp_mac_converted} on {arp_interface}")

                # Look up MAC in MAC address table
                print(f"\nChecking MAC {arp_mac} in MAC address table...")
                mac_lookup = connection.send_command(f"show mac address-table | include {arp_mac}")
                print("\nMAC Table Lookup:")
                print(mac_lookup if mac_lookup else "MAC not found in table.")
            else:
                print(f"\nNo ARP entry for {args.find_ip}. Pinging to populate ARP...")
                ping_output = connection.send_command(f"ping {args.find_ip}")
                print("\nPing Output:")
                print(ping_output)
                # Retry ARP
                arp_output = connection.send_command(f"show ip arp {args.find_ip}")
                arp_match = re.search(r'Internet\s+{}\s+\d+\s+([0-9a-fA-F.]+)\s+ARPA\s+(\S+)'.format(args.find_ip), arp_output)
                if arp_match:
                    arp_mac, arp_interface = arp_match.groups()
                    arp_mac_converted = convert_mac_format(arp_mac)
                    print(f"\nAfter ping: IP {args.find_ip} -> MAC {arp_mac_converted} on {arp_interface}")
                    mac_lookup = connection.send_command(f"show mac address-table | include {arp_mac}")
                    print("\nMAC Table Lookup:")
                    print(mac_lookup)
                else:
                    print(f"\nStill no ARP entry for {args.find_ip}. Ensure IP is reachable.")

        # Collect MAC addresses for sub-switch ports (only if requested)
        if args.show_mac_table:
            all_entries = []
            for port in sub_switch_ports:
                print(f"\nRunning 'show mac address-table interface {port}'...")
                raw_output = connection.send_command(f"show mac address-table interface {port}")
                print("\nRaw Output:")
                print(raw_output if raw_output else "No output returned.")

                # Try TextFSM parsing
                print(f"\nAttempting TextFSM parsing for {port}...")
                output = connection.send_command(f"show mac address-table interface {port}", use_textfsm=True)

                # Debug parsed output
                print(f"\nOutput type: {type(output)}")
                print(f"Parsed output (first 5 entries): {json.dumps(output[:5], indent=2)}")

                if isinstance(output, list):
                    for entry in output:
                        if isinstance(entry, dict):
                            all_entries.append({
                                'vlan': entry.get('vlan', 'N/A'),
                                'mac': convert_mac_format(entry.get('destination_address', 'N/A')),
                                'type': entry.get('type', 'N/A'),
                                'port': entry.get('destination_port', port)
                            })
                        else:
                            print(f"Skipping invalid entry: {entry}")
                else:
                    print("TextFSM failed. Falling back to manual parsing...")
                    lines = raw_output.splitlines()
                    for line in lines:
                        match = re.match(r'^\s*(\d+|\*)\s+([0-9a-fA-F.]+)\s+(\S+)\s+(\S+)', line)
                        if match:
                            vlan, mac, mac_type, dest_port = match.groups()
                            all_entries.append({
                                'vlan': vlan if vlan != '*' else 'N/A',
                                'mac': convert_mac_format(mac),
                                'type': mac_type,
                                'port': dest_port
                            })

            # Print MAC table results
            if all_entries:
                print(f"\nMAC Address Table for Sub-Switch Ports (showing up to {args.max_entries} entries):")
                print(f"{'VLAN':<8} {'MAC Address':<18} {'Type':<8} {'Port':<20}")
                print("-" * 60)
                entries_to_show = all_entries[:args.max_entries]
                for entry in entries_to_show:
                    vlan = str(entry['vlan'])
                    mac = str(entry['mac'])
                    mac_type = str(entry['type'])
                    port = str(entry['port'])
                    print(f"{vlan:<8} {mac:<18} {mac_type:<8} {port:<20}")
            else:
                print("\nNo MAC addresses found.")

        # Disconnect
        connection.disconnect()

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
