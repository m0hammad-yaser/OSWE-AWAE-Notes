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
