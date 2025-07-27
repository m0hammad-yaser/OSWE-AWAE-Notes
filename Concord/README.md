# Concord Authentication Bypass to RCE
This module focuses on the Concord workflow server, which contains three authentication bypass vulnerabilities. Initially using a greybox approach, the module explores a CORS misconfiguration leading to information disclosure, a CSRF vulnerability, and later, through a whitebox review, default user accounts accessible via undocumented API keys. These vulnerabilities are exploited to achieve remote code execution.
## Authentication Bypass: Round One - CSRF and CORS


Here's the table in markdown format:

| URL | Result | Reason |
|-----|--------|--------|
| https://a.com/myInfo | Allowed | Same Origin |
| http://a.com/users.json | Blocked | Different Scheme and Port |
| https://api.a.com/info | Blocked | Different Domain |
| https://a.com**:8443**/files | Blocked | Different Port |
| https://b.com/analytics | Blocked | Different Domain |
