# openCRX Authentication Bypass and Remote Code Execution
This module covers the analysis and exploitation of multiple vulnerabilities in openCRX, an open-source Java-based CRM application. Using white box techniques, we exploited **predictable password reset tokens** to gain authenticated access. From there, we combined white and black box approaches to exploit an XXE vulnerability, enumerate the server, extract **HSQLDB credentials**, and leverage Java routines to achieve limited **remote code execution** and deploy a web shell on the server.
## Vulnerability Discovery
In its default setup, openCRX runs on Apache TomEE, and like many Java web applications, it may be packaged as a JAR, WAR, or EAR file—essentially ZIP files with different purposes:

- **JAR:** Stand-alone apps or libraries
- **WAR:** Web apps with static content and JARs
- **EAR:** Bundles multiple WARs and JARs for enterprise apps

While packaging format doesn’t affect exploitability, understanding it helps locate target files.

To analyze openCRX’s structure, we use white box techniques, connecting via SSH and running:
```bash
tree -L 3
```
```bash
student@opencrx:~$ cd crx/apache-tomee-plus-7.0.5/

student@opencrx:~/crx/apache-tomee-plus-7.0.5$ tree -L 3
.
|-- airsyncdir
|-- apps
|   |-- opencrx-core-CRX
|   |   |-- APP-INF
|   |   |-- META-INF
|   |   |-- opencrx-bpi-CRX
|   |   |-- opencrx-bpi-CRX.war
|   |   |-- opencrx-caldav-CRX
|   |   |-- opencrx-caldav-CRX.war
|   |   |-- opencrx-calendar-CRX
|   |   |-- opencrx-calendar-CRX.war
|   |   |-- opencrx-carddav-CRX
|   |   |-- opencrx-carddav-CRX.war
|   |   |-- opencrx-contacts-CRX
|   |   |-- opencrx-contacts-CRX.war
|   |   |-- opencrx-core-CRX
|   |   |-- opencrx-core-CRX.war
|   |   |-- opencrx-documents-CRX
|   |   |-- opencrx-documents-CRX.war
|   |   |-- opencrx-ical-CRX
|   |   |-- opencrx-ical-CRX.war
|   |   |-- opencrx-imap-CRX
|   |   |-- opencrx-imap-CRX.war
|   |   |-- opencrx-ldap-CRX
|   |   |-- opencrx-ldap-CRX.war
|   |   |-- opencrx-rest-CRX
|   |   |-- opencrx-rest-CRX.war
|   |   |-- opencrx-spaces-CRX
|   |   |-- opencrx-spaces-CRX.war
|   |   |-- opencrx-vcard-CRX
|   |   |-- opencrx-vcard-CRX.war
|   |   |-- opencrx-webdav-CRX
|   |   |-- opencrx-webdav-CRX.war
|   |-- opencrx-core-CRX.ear
|-- bin
...

55 directories, 339 files
```
We confirmed that openCRX is packaged as an EAR file located at: `/home/student/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX.ear`

Inside, we found multiple WAR files, each representing a separate web application, eliminating the need to extract them individually.

use scp to copy opencrx-core-CRX.ear to our local Kali machine.
```bash
scp student@opencrx:~/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX.ear .
```
Next, we'll unzip it, passing in -d opencrx to extract the contents into a new directory.
```bash
unzip -q opencrx-core-CRX.ear -d opencrx
```
Once we have extracted the contents of the EAR file, we can examine them on our Kali machine.
```bash
kali@kali:~$ cd opencrx

kali@kali:~/opencrx$ ls -al
total 29184
drwxr-xr-x  4 kali kali     4096 Feb 27 14:19 .
drwxr-xr-x 51 kali kali     4096 Feb 27 14:19 ..
drwxr-xr-x  3 kali kali     4096 Jan  2  2019 APP-INF
drwxr-xr-x  2 kali kali     4096 Jan  2  2019 META-INF
-rw-r--r--  1 kali kali     2028 Jan  2  2019 opencrx-bpi-CRX.war
-rw-r--r--  1 kali kali     2027 Jan  2  2019 opencrx-caldav-CRX.war
-rw-r--r--  1 kali kali  3908343 Jan  2  2019 opencrx-calendar-CRX.war
-rw-r--r--  1 kali kali     2030 Jan  2  2019 opencrx-carddav-CRX.war
-rw-r--r--  1 kali kali  3675357 Jan  2  2019 opencrx-contacts-CRX.war
-rw-r--r--  1 kali kali 18285302 Jan  2  2019 opencrx-core-CRX.war
-rw-r--r--  1 kali kali  1099839 Jan  2  2019 opencrx-documents-CRX.war
-rw-r--r--  1 kali kali     2750 Jan  2  2019 opencrx-ical-CRX.war
-rw-r--r--  1 kali kali     1785 Jan  2  2019 opencrx-imap-CRX.war
-rw-r--r--  1 kali kali     1788 Jan  2  2019 opencrx-ldap-CRX.war
-rw-r--r--  1 kali kali  2778171 Jan  2  2019 opencrx-rest-CRX.war
-rw-r--r--  1 kali kali    70520 Jan  2  2019 opencrx-spaces-CRX.war
-rw-r--r--  1 kali kali     2036 Jan  2  2019 opencrx-vcard-CRX.war
-rw-r--r--  1 kali kali     2029 Jan  2  2019 opencrx-webdav-CRX.war
```
As we suspected earlier, the EAR file did contain the WAR files. Each WAR file is essentially a separate web application with its own static content. The common JAR files are in `/APP-INF/lib`.

We will come back to these JAR files. First, let's examine the main application, `opencrx-core-CRX.war`, in JD-GUI.

We start with JSP files rather than web.xml because openCRX embeds key logic and functionality directly within them. This approach allows for faster identification of dynamic behavior and potential vulnerabilities without tracing servlet mappings.
