# Concord Authentication Bypass to RCE
This module focuses on the Concord workflow server, which contains three authentication bypass vulnerabilities. Initially using a greybox approach, the module explores a CORS misconfiguration leading to information disclosure, a CSRF vulnerability, and later, through a whitebox review, default user accounts accessible via undocumented API keys. These vulnerabilities are exploited to achieve remote code execution.
## Authentication Bypass: Round One - CSRF and CORS
### Same-Origin Policy (SOP)

Browsers enforce a same-origin policy to prevent one origin from accessing resources on a different origin. An origin is defined as a protocol, hostname, and port number. A resource can be an image, html, data, json, etc.

Without the same-origin policy, the web would be a much more dangerous place, allowing any website we visit to read our emails, check our bank balances, and view other information even from our logged-in sessions.

This table lists some of those resources, indicates whether or not they will load, and explains why:

| URL | Result | Reason |
|-----|--------|--------|
| https://a.com/myInfo | Allowed | Same Origin |
| http://a.com/users.json | Blocked | Different Scheme and Port |
| https://api.a.com/info | Blocked | Different Domain |
| https://a.com**:8443**/files | Blocked | Different Port |
| https://b.com/analytics | Blocked | Different Domain |

