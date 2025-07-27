# Concord Authentication Bypass to RCE
This module focuses on the Concord workflow server, which contains three authentication bypass vulnerabilities. Initially using a greybox approach, the module explores a CORS misconfiguration leading to information disclosure, a CSRF vulnerability, and later, through a whitebox review, default user accounts accessible via undocumented API keys. These vulnerabilities are exploited to achieve remote code execution.
## Authentication Bypass: Round One - CSRF and CORS
