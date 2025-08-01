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

