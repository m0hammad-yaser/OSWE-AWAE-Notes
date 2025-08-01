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

