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
