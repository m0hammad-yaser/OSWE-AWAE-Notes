# ERPNext Authentication Bypass and Server Side Template Injection
This module explores a methodology for discovering vulnerabilities in ERPNext, an open-source ERP system built on the Frappe Web Framework. We begin with an in-depth analysis of a SQL injection vulnerability, originally discovered in Frappe, which allows us to bypass authentication and gain administrator access.

With administrator access, we then examine a Server-Side Template Injection (SSTI) vulnerability. Although it uses character blacklisting to prevent exploitation (`.__`), we demonstrate a bypass technique to execute system commands and achieve remote code execution.
## Getting Started
### Configuring the SMTP Server
We’ll need to send emails as part of bypassing the password reset functionality. To achieve this, we’ll configure ERPNext to use our Kali machine as its SMTP server.
First, log in to the ERPNext server via SSH: `ssh frappe@<ERPNext_IP_Address>`

####Edit SMTP Settings
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
```
kali@kali:~$ sudo python2 -m smtpd -n -c DebuggingServer 0.0.0.0:25
```
This will start a simple SMTP server that accepts connections and prints messages to the terminal without storing them.
