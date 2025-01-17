# [cURL](https://curl.se/docs/)
`cURL` is a command-line tool for transferring data using various protocols (HTTP, HTTPS, FTP, etc.). It is commonly used for making web requests, downloading/uploading files, testing APIs, and automating network tasks.  
## **General & Help Flags**
-> Shows a short help summary with basic options  
- `curl -h`  
- `curl --help`

-> Shows **all** available options in a long list  
- `curl --help all`

-> Lists all available categories of options (e.g., authentication, connections, output, etc.)  
- `curl --help category`

-> Shows help for a specific category (e.g., HTTP-related options)  
- `curl --help http`

-> Displays the full manual page  
- `curl -M`  
- `curl --manual`

-> Shows the version of `curl`, the supported protocols, and features  
- `curl -V`  
- `curl --version`

---

## **Verbose Output Flags**
-> Provides detailed information about the request and response, including headers and connection details  
- `curl -v https://example.com`  
- `curl --verbose https://example.com`

-> Hides progress and error messages (useful to reduce clutter)  
- `curl -s https://example.com`  
- `curl --silent https://example.com`

-> Hides progress but still shows errors (recommended for scripts)  
- `curl -sS https://example.com`

---

## **Debugging Headers & Data**
-> Displays the response headers along with the body  
- `curl -i https://example.com`  
- `curl --include https://example.com`

-> Fetches only the headers (without the response body)  
- `curl -I https://example.com`  
- `curl --head https://example.com`

-> Logs detailed request/response data to a file  
- `curl --trace curl.log https://example.com`

-> Logs detailed request/response data, but only in ASCII (more readable)  
- `curl --trace-ascii curl.log https://example.com`

-> Allows custom output formatting (e.g., response time, status code)  
- `curl -w "Response Code: %{http_code}\n" -o /dev/null -s https://example.com`

---

## HTTP Methods & Request Manipulation**
-> Sends a custom HTTP request method (useful for testing PUT, DELETE, etc.)  
- `curl -X PUT https://example.com/resource`

-> Modifies or adds custom headers (e.g., testing WAF rules or bypassing security)  
- `curl -H "X-Forwarded-For: 127.0.0.1" https://example.com`

-> Sends data with a POST request (e.g., testing forms, injecting payloads)  
- `curl -X POST -d "username=admin&password=1234" https://example.com/login`

-> Reads request body from a file (useful for sending JSON, XML, etc.)  
- `curl -X POST -H "Content-Type: application/json" -d @data.json https://example.com/api`

---

## Authentication & Cookies**
-> Uses Basic Authentication (useful for brute force or testing credentials)  
- `curl -u admin:password https://example.com/protected`

-> Uses a session cookie (useful for maintaining authentication)  
- `curl -b "PHPSESSID=abcd1234" https://example.com/dashboard`

-> Stores cookies from a response into a file  
- `curl -c cookies.txt https://example.com`

-> Uses stored cookies for a new request  
- `curl -b cookies.txt https://example.com`

---

## Proxy & Evasion Techniques**
-> Sends requests through a proxy (useful for anonymity and testing)  
- `curl -x http://proxy.example.com:8080 https://target.com`

-> Uses a SOCKS5 proxy (e.g., routing through Tor)  
- `curl --socks5 127.0.0.1:9050 https://target.onion`

-> Changes the User-Agent string (useful for bypassing security filters)  
- `curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://example.com`

-> Spoofs the Referer header  
- `curl -e "https://google.com" https://example.com`

---

## Enumeration & Reconnaissance**
-> Checks for available HTTP methods (useful for discovering misconfigurations)  
- `curl -X OPTIONS -i https://example.com`

-> Follows redirects (useful for tracking authentication flows)  
- `curl -L https://example.com`

-> Measures response time (useful for identifying time-based attacks)  
- `curl -o /dev/null -s -w "Time: %{time_total}s\n" https://example.com`

-> Dumps response headers (useful for fingerprinting web technologies)  
- `curl -I https://example.com`

---

## File Transfers & Exploitation**
-> Uploads a file via POST (useful for testing file upload vulnerabilities)  
- `curl -F "file=@exploit.php" https://example.com/upload`

-> Uploads a file via PUT (useful for testing misconfigured web servers)  
- `curl -X PUT --data-binary @exploit.php https://example.com/exploit.php`

-> Downloads a file from a server (useful for exfiltration)  
- `curl -O https://example.com/file.txt`

-> Executes command injection through headers (useful for testing RCE)  
- `curl -H "User-Agent: () { :; }; /bin/bash -c 'id'" https://example.com`

---

## Examples
-> Get a single resource via URI:  
- `curl https://jsonplaceholder.typicode.com/posts/1`

-> Get a single resource via URI and show response header:  
- `curl -i https://jsonplaceholder.typicode.com/posts/1`

-> Show response header only:  
- `curl -I https://jsonplaceholder.typicode.com/posts/1`  
- `curl --head https://jsonplaceholder.typicode.com/posts/1`

-> Download response to file with a special name:  
- `curl -o filename.txt https://jsonplaceholder.typicode.com/posts/1`

-> Download response with limit size:  
- `curl -O https://jsonplaceholder.typicode.com/megafamous.png`

-> Download response with max size:  
- `curl -O --limit-rate 1000B https://jsonplaceholder.typicode.com/posts`

-> Send POST with data (-d or --data):  
- `curl -X PUT -d "title=Hello&body=Hello World" https://jsonplaceholder.typicode.com/posts`

-> Send request with method PUT to update data (-d or --data):  
- `curl -X PUT --data "title=Hello01&body=Hello World Update" https://jsonplaceholder.typicode.com/posts/2`

-> Send request with method DELETE to delete item:  
- `curl -X DELETE https://jsonplaceholder.typicode.com/posts/2`

-> Basic authentication email:password:  
- `curl -u moemengaballa@gmail.com:12345678 https://site.com/login`

-> Basic authentication using token with curl:  
- `curl --header "Authorization: Bearer xxxxxxxxx" https://host.com/`

-> Request if URL redirect (301 Moved) complete to redirect:  
- `curl -L https://google.com`

-> Upload file as FileZilla FTP to server:  
- `curl -u test@host.com:123456 -T hello.txt ftp://ftp.host.com`

-> Download file as FileZilla FTP:  
- `curl -u test@host.com:123456 -O hello.txt ftp://ftp.host.com/hello.txt`

-> To ignore SSL certificate issues:  
- `curl --insecure https://www.google.com.eg/`

-> Get SSL certificate information from a remote web server:  
- `curl --insecure -vvI https://www.google.com.eg/`


