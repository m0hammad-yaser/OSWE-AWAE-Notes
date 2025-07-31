# RudderStack SQLi and Coraza WAF Bypass
In this module we analyzed the source code of RudderStack, a Go-based application, to identify unauthenticated API endpoints. After discovering one, we exploited a SQL injection vulnerability. We then tested the same exploit against a Web Application Firewall (WAF), adapting our payload to bypass its rules and highlighting the limitations of WAF protection.

## Getting Started 
The RudderStack VM uses Docker to run RudderStack and OWASP Coraza WAF in containers. We can access RudderStack through the Coraza WAF on port `80`. We can also access RudderStack directly on port `8080`. We'll be connecting on both ports as we examine how the WAF interacts with the vulnerability.

We can retrieve a list of the running Docker containers by running `docker` with the `ps` command.
```bash
student@rudderstack:~$ docker ps 
CONTAINER ID   IMAGE                                   COMMAND                  CREATED         STATUS                   PORTS                                                           NAMES
e79560abca80   student_caddy                           "/usr/bin/caddy run …"   3 minutes ago   Up 3 minutes             443/tcp, 0.0.0.0:80->80/tcp, :::80->80/tcp, 2019/tcp, 443/udp   student_caddy_1
9526a6198f87   rudderlabs/rudder-server:1.2.5          "sh -c '/wait-for db…"   3 minutes ago   Up 3 minutes             0.0.0.0:8080->8080/tcp, :::8080->8080/tcp                       student_backend_1
0a8d88671ac6   rudderstack/rudder-transformer:latest   "/sbin/tini -- npm s…"   3 minutes ago   Up 3 minutes (healthy)   127.0.0.1:9090->9090/tcp                                        student_d-transformer_1
5bb0f9d91064   postgres:15-alpine                      "docker-entrypoint.s…"   3 minutes ago   Up 3 minutes             0.0.0.0:6432->5432/tcp, :::6432->5432/tcp                       student_db_1
a945e7ac5d11   prom/statsd-exporter:v0.22.4            "/bin/statsd_exporter"   3 minutes ago   Up 3 minutes (healthy)   127.0.0.1:9102->9102/tcp, 9125/tcp, 9125/udp                    student_metrics-exporter_1
student@rudderstack:~$
```
While there are several containers running, we only need to be aware of `student_caddy_1`, `student_backend_1`, and `student_db_1` for this module.

If we want to inspect the contents of a container, we could run the following command:
```bash
student@rudderstack:~$ docker exec -it student_db_1 /bin/sh
/ #
```
## RudderStack SQL Injection Vulnerability
Our VM is running RudderStack `v1.2.5`, which contains a SQL injection vulnerability identified by the GitHub Security Lab and documented as `CVE-2023-30625`.

Rather than working off of the CVE write up, we'll perform our own source code analysis to enumerate the application's unauthenticated endpoints and discover the SQL injection vulnerability.

### Discovering the SQL Injection Vulnerability
