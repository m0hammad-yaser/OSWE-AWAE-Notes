#!/usr/bin/env python3

"""
Usage:
python3 route_buster.py -a /usr/share/wordlists/dirb/small.txt -w endpoints_simple.txt -t http://apigateway:8000
"""

import argparse
import requests

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--actionlist', required=True, help='File with list of actions')
    parser.add_argument('-w', '--wordlist', required=True, help='File with list of endpoints')
    parser.add_argument('-t', '--target', required=True, help='Base target URL (e.g. http://host:port)')
    args = parser.parse_args()

    try:
        with open(args.actionlist, "r") as af:
            actions = [line.strip() for line in af if line.strip()]
    except Exception as e:
        print(f"Failed to read action list: {e}")
        return

    try:
        with open(args.wordlist, "r") as wf:
            words = [line.strip() for line in wf if line.strip()]
    except Exception as e:
        print(f"Failed to read word list: {e}")
        return

    print("Path                    - \tGET\tPOST")
    for word in words:
        for action in actions:
            path = f"/{word}/{action}"
            url = f"{args.target.rstrip('/')}{path}"
            try:
                r_get = requests.get(url, timeout=3)
                r_post = requests.post(url, timeout=3)
                if r_get.status_code not in [204, 401, 403, 404] or r_post.status_code not in [204, 401, 403, 404]:
                    print(f"{path:24} - \t{r_get.status_code}\t{r_post.status_code}")
            except requests.RequestException as e:
                print(f"{path:24} - \tERROR\tERROR ({e.__class__.__name__})")

    print("Wordlist complete. Goodbye.")

if __name__ == '__main__':
    main()
