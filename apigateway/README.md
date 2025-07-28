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

Output:
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
