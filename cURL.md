## [cURL](https://curl.se/docs/) Commands
`cURL` is a command-line tool for transferring data using various protocols (HTTP, HTTPS, FTP, etc.). It is commonly used for making web requests, downloading/uploading files, testing APIs, and automating network tasks. Use `| html2text` to make it more readable! for the love of god end URLs with a /

### **General & Help Flags**
- cURL help menu - `curl -h` / `curl --help-all` 
- Shows all available options in a long list - `curl --help all` 
- Lists all available categories of options - `curl --help category` 
- Shows help for a specific category (e.g., HTTP) - `curl --help http` 
- Displays the full manual page - `curl -M` / `curl --manual` 
- Shows the version of `curl`, supported protocols, and features - `curl -V` / `curl --version` 

### **Verbose Output Flags**
- Provides detailed request/response info - `curl -v https://example.com` / `curl --verbose https://example.com` 
- Hides progress and error messages - `curl -s https://example.com` / `curl --silent https://example.com` 
- Hides progress but still shows errors - `curl -sS https://example.com` 

### **Debugging Headers & Data**
- Displays response headers with body - `curl -i https://example.com` / `curl --include https://example.com` 
- Fetches only headers (no body) - `curl -I https://example.com` / `curl --head https://example.com` 
- Logs detailed request/response data to file - `curl --trace curl.log https://example.com` 
- Logs request/response data in ASCII format - `curl --trace-ascii curl.log https://example.com` 
- Custom output formatting (e.g., response time) - `curl -w "Response Code: %{http_code}\n" -o /dev/null -s https://example.com`

### **HTTP Methods & Request Manipulation**
- Basic GET request | `curl inlanefreight.com` |
- Sends a custom HTTP request method - `curl -X PUT https://example.com/resource` 
- Modifies or adds custom headers - `curl -H "X-Forwarded-For: 127.0.0.1" https://example.com` 
- Sends data via POST request - `curl -X POST -d "username=admin&password=admin" https://example.com/login` 
- Reads request body from a file - `curl -X POST -H "Content-Type: application/json" -d @data.json https://example.com/api` 

### **Authentication & Cookies**
- Uses Basic Authentication - `curl -u admin:password https://example.com/protected` 
- Uses a session cookie - `curl -b "PHPSESSID=abcd1234" https://example.com/dashboard` 
- Stores cookies from a response - `curl -c cookies.txt https://example.com` 
- Uses stored cookies for a new request - `curl -b cookies.txt https://example.com` 

### **Proxy & Evasion Techniques**
- Sends requests through a proxy - `curl -x http://proxy.example.com:8080 https://target.com` 
- Uses a SOCKS5 proxy (e.g., Tor) - `curl --socks5 127.0.0.1:9050 https://target.onion` 
- Changes the User-Agent string - `curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://example.com` 
- Spoofs the Referer header - `curl -e "https://google.com" https://example.com` 

### **Enumeration & Reconnaissance**
- Checks available HTTP methods - `curl -X OPTIONS -i https://example.com`
- Follows redirects - `curl -L https://example.com` 
- Measures response time - `curl -o /dev/null -s -w "Time: %{time_total}s\n" https://example.com` 
- Dumps response headers - `curl -I https://example.com` 

### **File Transfers & Exploitation**
- Uploads a file via POST - `curl -F "file=@exploit.php" https://example.com/upload` 
- Uploads a file via PUT - `curl -X PUT --data-binary @exploit.php https://example.com/exploit.php` 
- Downloads a file from a server - `curl -O https://example.com/file.txt` 
- Executes command injection through headers - `curl -H "User-Agent: () { :; }; /bin/bash -c 'id'" https://example.com` 

### **API Interactions & Security Tools**
- Read API entry - `curl http://<SERVER_IP>:<PORT>/api.php/city/london` 
- Read all API entries - `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq` 
- Create API entry - `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` 
- Update API entry - `curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` 
- Delete API entry - `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City` 
- Send a suspicious hash to VirusTotal - `curl -v --request POST --url 'https://www.virustotal.com/vtapi/v2/file/report' -d apikey=<VT API KEY> -d 'resource=<SUSPICIOUS FILE HASH>'` 
- Send a suspicious file to VirusTotal - `curl -v -F 'file=/<PATH TO FILE>/<SUSPICIOUS FILE NAME>' -F apikey=<VT API KEY> https://www.virustotal.com/vtapi/v2/file/scan` 
