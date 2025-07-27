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

The purpose of SOP is not to prevent the request for a resource from being sent, but to prevent JavaScript from reading the response.
### Cross-Origin Resource Sharing (CORS)
CORS uses HTTP headers to tell browsers which origins can access resources from a server. It works alongside the Same-Origin Policy (SOP) to control cross-origin requests.

#### Key CORS Headers

- `Access-Control-Allow-Origin`: Specifies which origins can access the response
- `Access-Control-Allow-Credentials`: Indicates if cookies can be included in requests
- `Access-Control-Expose-Headers`: Lists headers that JavaScript can access

#### Request Types and Preflight
- Simple requests: (standard `GET`, `HEAD`, `POST` with basic `content-types`) are sent directly, but the response is blocked if CORS headers don't allow it.
- Complex requests: (custom headers, non-standard `content-types`, or non-standard methods) trigger a preflight `OPTIONS` request first. The browser checks if the actual request is allowed before sending it.

#### Security Implications

*Vulnerable Configurations:*

1. Dynamic Origin Reflection: Setting `Access-Control-Allow-Origin` to match the requesting origin allows any site to make authenticated requests
2. Null Origin: Allowing `"null"` origin can be exploited by certain documents/files
3. Wildcard with Credentials: Not possible - wildcard (`*`) requires credentials to be `false`

*Secure Configuration:*

Only set `Access-Control-Allow-Origin` to trusted, specific origins. Remove the header entirely if cross-origin access isn't needed.

The main security risk occurs when sites dynamically set the allowed origin to match any requesting origin while allowing credentials, enabling malicious sites to make authenticated requests on behalf of users.
### Discovering Unsafe CORS Headers

#### Initial Analysis

The `/api/service/console/whoami` endpoint initially shows:
- Without Origin header: Response contains Access-Control-Allow-Origin: *
- This wildcard setting means cookies won't be sent on cross-origin requests

#### Key Discovery
When an `Origin` header is added to the request:
1. Server reflects the origin into `Access-Control-Allow-Origin` header
2. Server adds `Access-Control-Allow-Credentials: true`

**This is a dangerous configuration** - it allows any origin to make authenticated requests.

#### Testing Different Methods

`OPTIONS` requests behave differently:

- The origin is not reflected in the response
- This limits the vulnerability scope

#### Vulnerability Scope

With this CORS misconfiguration, attackers can only:
- Read responses from `GET` requests
- Read responses from standard `POST` requests
- Cannot perform complex requests (those requiring preflight)

#### Next Consideration
The **`SameSite` cookie attribute** could provide additional protection against this CORS vulnerability, which needs to be investigated to understand the full attack surface.
Key Takeaway
The application has an unsafe CORS configuration that dynamically reflects any origin while allowing credentials, but the vulnerability is somewhat limited due to the `OPTIONS` method behavior.
