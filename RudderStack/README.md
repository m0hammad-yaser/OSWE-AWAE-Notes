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
We'll analyze the application as an **unauthenticated user**, starting by **enumerating API endpoints** and identifying which require authentication. RudderStack's **[official API documentation](https://www.rudderstack.com/docs/api/)**, found online, reveals that it uses **URL versioning** for its endpoints.

If we want to discover all the endpoints in the application's source code, we can search for variations of `"/v1"`, `"/v2"`, and so on.

We'll click on the *Search* icon in code-server, then click on the ellipsis to toggle additional search details.

We want to find strings that match the expected endpoint format, so we'll type `/v1` in the *Search* field. We'll limit our search to source files by typing `*.go` in the `"files to include"` field. We'll exclude any test files, since they will likely contain duplicate results, by typing `*_test.go` in the `"files to exclude"` field.

We have `40` results in `9` files. The first three results contain `Sprintf` calls that are constructing URL paths. After that, we'll notice multiple results in `gateway.go` containing strings that appear to be API paths passed to a `HandleFunc()` function. Let's analyze the start of the `StartWebHandler()` function, which contains most of the search results in `gateway.go`.

```go
1417  /*
1418  StartWebHandler starts all gateway web handlers, listening on gateway port.
1419  Supports CORS from all origins.
1420  This function will block.
1421  */
1422  func (gateway *HandleT) StartWebHandler(ctx context.Context) error {
1423  	gateway.logger.Infof("WebHandler waiting for BackendConfig before starting on %d", webPort)
1424  	gateway.backendConfig.WaitForConfig(ctx)
1425  	gateway.logger.Infof("WebHandler Starting on %d", webPort)
1426  
1427  	srvMux := mux.NewRouter()
1428  	srvMux.Use(
1429  		middleware.StatMiddleware(ctx, srvMux),
1430  		middleware.LimitConcurrentRequests(maxConcurrentRequests),
1431  	)
1432  	srvMux.HandleFunc("/v1/batch", gateway.webBatchHandler).Methods("POST")
1433  	srvMux.HandleFunc("/v1/identify", gateway.webIdentifyHandler).Methods("POST")
1434  	srvMux.HandleFunc("/v1/track", gateway.webTrackHandler).Methods("POST")
```
Source code excerpt of `StartWebHandler()` function

This code snippet explains how a web application sets up its HTTP endpoints. It uses the Gorilla Mux router (a popular Go library) to map specific URL paths to their corresponding handler functions. The `srvMux` object registers each route using `HandleFunc()`, so when a request comes in - like a `POST` to `"/v1/batch"` - the router automatically directs it to the appropriate handler function (`gateway.webBatchHandler` in this example). Essentially, it's the routing system that determines which code runs based on the incoming request's URL and HTTP method.

Identifying this function gives us URLs to test and shows which handlers to review. Instead of analyzing each one, we’ll use **Burp Suite** to quickly check which endpoints require authentication.

Let's get the list of potential URLs out of code-server by right-clicking on the search results and selecting `Copy All`. We'll then paste the results into a text file named `routes.txt` using our text editor of choice.

Unfortunately, the pasted results include line numbers and source files, so we don't have a clean list of URLs to pass to another tool or script.
```go
kali@kali:~$ head routes.txt
/home/student/rudder-server-1.2.5/cmd/devtool/commands/event.go
  60,24:        url := fmt.Sprintf("%s/v1/batch", c.String("endpoint"))

/home/student/rudder-server-1.2.5/config/backend-config/namespace_config.go
  84,35:        u.Path = fmt.Sprintf("/data-plane/v1/namespaces/%s/config", nc.Namespace)

/home/student/rudder-server-1.2.5/gateway/gateway.go
  989,24:       uri := fmt.Sprintf(`%s/v1/warehouse/pending-events?triggerUpload=true`, misc.GetWarehouseURL())
  1432,21:      srvMux.HandleFunc("/v1/batch", gateway.webBatchHandler).Methods("POST")
  1433,21:      srvMux.HandleFunc("/v1/identify", gateway.webIdentifyHandler).Methods("POST")
```
we can clean up most of the list using:
```bash
kali@kali:~$ grep -e "/v" routes.txt | cut -d "(" -f 2 | cut -d "," -f 1 | cut -d "\"" -f 2
%s/v1/batch
/data-plane/v1/namespaces/%s/config
`%s/v1/warehouse/pending-events?triggerUpload=true`
/v1/batch
/v1/identify
/v1/track
/v1/page
/v1/screen
/v1/alias
...
```
Let's redirect the results to a new file named routes_clean.txt. We'll also sort the results so we can check for duplicate URLs.
```bash
kali@kali:~$ grep -e "/v" routes.txt | cut -d "(" -f 2 | cut -d "," -f 1 | cut -d "\"" -f 2 | sort > routes_clean.txt
```
We’ll clean up the URLs by removing backticks (`` ` ``), format markers (`%s`), and `localhost` references to make them relative. For placeholders like `job_run_id`, we’ll replace them with `web300`.

Final version: [routes_clean.txt](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/RudderStack/routes_clean.txt)

Now that we have our list, we'll use Burp Suite to send requests to every endpoint. After opening Burp Suite, let's open the embedded browser and navigate to `http://rudderstack:8080/` so that we have a request that we can send to *Intruder*.

