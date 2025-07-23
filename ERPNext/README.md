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
frappe@ubuntu:~$ cd /home/frappe/frappe-bench/sites/
frappe@ubuntu:~/frappe-bench/sites$ ../env/bin/python ../apps/frappe/frappe/app.py --noreload --nothreading
```
