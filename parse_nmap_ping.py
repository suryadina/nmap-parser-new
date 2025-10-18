#!/usr/bin/env python3
"""
Nmap Ping Scan Parser
Parses nmap ping scan output in normal format (.nmap) and extracts host information.
"""

import re
import argparse
import json
import csv
from typing import List, Dict, Optional
from pathlib import Path


class NmapPingParser:
    """Parser for nmap ping scan output."""

    def __init__(self, nmap_file: str):
        self.nmap_file = nmap_file
        self.hosts = []

    def parse(self) -> List[Dict[str, Optional[str]]]:
        """Parse the nmap file and extract host information."""
        with open(self.nmap_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Split into individual host reports
        # Pattern: "Nmap scan report for ..."
        host_blocks = re.split(r'(?=Nmap scan report for)', content)

        for block in host_blocks:
            if not block.strip() or 'Nmap scan report for' not in block:
                continue

            host_info = self._parse_host_block(block)
            if host_info:
                self.hosts.append(host_info)

        return self.hosts

    def _parse_host_block(self, block: str) -> Optional[Dict[str, Optional[str]]]:
        """Parse a single host block and extract information."""
        lines = block.strip().split('\n')

        if not lines:
            return None

        first_line = lines[0]

        # Initialize host info
        host_info = {
            'ip': None,
            'hostname': None,
            'status': 'down',
            'latency': None,
            'mac_address': None,
            'mac_vendor': None
        }

        # Parse the first line: "Nmap scan report for ..."
        # Format 1: "Nmap scan report for 10.247.254.4 [host down]"
        # Format 2: "Nmap scan report for 10.247.254.11"

        # Check if host is down (indicated in first line)
        if '[host down]' in first_line:
            host_info['status'] = 'down'
            # Extract IP
            ip_match = re.search(r'for\s+([\d.]+)\s+\[host down\]', first_line)
            if ip_match:
                host_info['ip'] = ip_match.group(1)
            return host_info

        # Extract hostname and IP if present
        # Format: "for hostname (IP)" or "for IP"
        hostname_ip_match = re.search(r'for\s+([^\s(]+)\s+\(([\d.]+)\)', first_line)
        if hostname_ip_match:
            host_info['hostname'] = hostname_ip_match.group(1)
            host_info['ip'] = hostname_ip_match.group(2)
        else:
            # Just IP
            ip_only_match = re.search(r'for\s+([\d.]+)', first_line)
            if ip_only_match:
                host_info['ip'] = ip_only_match.group(1)

        # Parse remaining lines for additional info
        for line in lines[1:]:
            line = line.strip()

            # Check if host is up
            if 'Host is up' in line:
                host_info['status'] = 'up'
                # Extract latency
                latency_match = re.search(r'\(([\d.]+)s latency\)', line)
                if latency_match:
                    host_info['latency'] = latency_match.group(1)

            # Extract MAC address
            if 'MAC Address:' in line:
                mac_match = re.search(r'MAC Address:\s+([0-9A-Fa-f:]+)(?:\s+\(([^)]+)\))?', line)
                if mac_match:
                    host_info['mac_address'] = mac_match.group(1)
                    if mac_match.group(2):
                        host_info['mac_vendor'] = mac_match.group(2)

        return host_info

    def to_csv(self, output_file: str):
        """Export parsed data to CSV."""
        if not self.hosts:
            print("No hosts to export. Run parse() first.")
            return

        fieldnames = ['ip', 'hostname', 'status', 'latency', 'mac_address', 'mac_vendor']

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.hosts)

        print(f"CSV output saved to: {output_file}")

    def to_json(self, output_file: str):
        """Export parsed data to JSON."""
        if not self.hosts:
            print("No hosts to export. Run parse() first.")
            return

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.hosts, f, indent=2)

        print(f"JSON output saved to: {output_file}")

    def to_ip_list(self, output_file_base: str):
        """Export live IPs to text files (both inline and list formats)."""
        if not self.hosts:
            print("No hosts to export. Run parse() first.")
            return

        live_ips = [host['ip'] for host in self.hosts if host['status'] == 'up' and host['ip']]

        # Remove known extensions if present (but preserve dots in filenames like IPs)
        base = output_file_base
        for ext in ['.csv', '.json', '.txt']:
            if base.endswith(ext):
                base = base[:-len(ext)]
                break

        # Create inline version (all IPs in one line)
        inline_file = f"{base}-inline.txt"
        with open(inline_file, 'w', encoding='utf-8') as f:
            f.write(' '.join(live_ips))
        print(f"IP list (inline) saved to: {inline_file} ({len(live_ips)} live hosts)")

        # Create list version (one IP per line)
        list_file = f"{base}-list.txt"
        with open(list_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(live_ips))
        print(f"IP list (per line) saved to: {list_file} ({len(live_ips)} live hosts)")

    def print_summary(self):
        """Print a summary of the parsed results."""
        if not self.hosts:
            print("No hosts found.")
            return

        total_hosts = len(self.hosts)
        hosts_up = sum(1 for h in self.hosts if h['status'] == 'up')
        hosts_down = total_hosts - hosts_up

        print(f"\n{'='*60}")
        print(f"Nmap Ping Scan Summary")
        print(f"{'='*60}")
        print(f"Total hosts scanned: {total_hosts}")
        print(f"Hosts up:            {hosts_up}")
        print(f"Hosts down:          {hosts_down}")
        print(f"{'='*60}\n")

        if hosts_up > 0:
            print("Live hosts:")
            print(f"{'IP Address':<18} {'Hostname':<30} {'Latency':<10} {'MAC Address':<20}")
            print('-' * 80)
            for host in self.hosts:
                if host['status'] == 'up':
                    ip = host['ip'] or 'N/A'
                    hostname = host['hostname'] or '-'
                    latency = f"{host['latency']}s" if host['latency'] else '-'
                    mac = host['mac_address'] or '-'
                    print(f"{ip:<18} {hostname:<30} {latency:<10} {mac:<20}")


def main():
    parser = argparse.ArgumentParser(
        description='Parse nmap ping scan output (.nmap format)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s scan.nmap                              # Creates scan-parsed.csv by default
  %(prog)s scan.nmap -o results.csv
  %(prog)s scan.nmap -o results.json --format json
  %(prog)s scan.nmap --format txt                 # Creates scan-parsed-inline.txt and scan-parsed-list.txt
  %(prog)s scan.nmap -o results --format all      # Creates all formats
        '''
    )

    parser.add_argument('input_file', help='Input nmap file (.nmap format)')
    parser.add_argument('-o', '--output', help='Output file name (without extension for "all" format). Default: <input>-parsed')
    parser.add_argument('-f', '--format', choices=['csv', 'json', 'txt', 'all'],
                       default='csv', help='Output format (default: csv). txt=2 files (inline & list), all=csv+json+txt')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress summary output')

    args = parser.parse_args()

    # Check if input file exists
    if not Path(args.input_file).exists():
        print(f"Error: Input file '{args.input_file}' not found.")
        return 1

    # Generate default output filename if not provided
    if not args.output:
        # Get input filename without extension
        input_path = Path(args.input_file)
        base_name = input_path.stem  # filename without extension
        args.output = f"{base_name}-parsed"

    # Parse the nmap file
    print(f"Parsing {args.input_file}...")
    nmap_parser = NmapPingParser(args.input_file)
    nmap_parser.parse()

    # Print summary unless quiet mode
    if not args.quiet:
        nmap_parser.print_summary()

    # Export to requested format(s)
    if args.format == 'csv':
        output_file = args.output if args.output.endswith('.csv') else f"{args.output}.csv"
        nmap_parser.to_csv(output_file)
    elif args.format == 'json':
        output_file = args.output if args.output.endswith('.json') else f"{args.output}.json"
        nmap_parser.to_json(output_file)
    elif args.format == 'txt':
        nmap_parser.to_ip_list(args.output)
    elif args.format == 'all':
        # Remove known extensions if provided (but preserve dots in filenames like IPs)
        base_name = args.output
        for ext in ['.csv', '.json', '.txt']:
            if base_name.endswith(ext):
                base_name = base_name[:-len(ext)]
                break
        nmap_parser.to_csv(f"{base_name}.csv")
        nmap_parser.to_json(f"{base_name}.json")
        nmap_parser.to_ip_list(base_name)

    return 0


if __name__ == '__main__':
    exit(main())
