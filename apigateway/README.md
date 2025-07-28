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

