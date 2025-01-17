# CTF & PenTesting Directory
A directory for every (most) Cyber Security / PenTest topics
 - [HackTricks](https://book.hacktricks.wiki/en/index.html)
 - [HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)
 - [OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/)
 - [HackTheBox Academy](https://academy.hackthebox.com)

## Browser DevTools Shortcuts

| Description | Shortcut |
|-------------|----------|
| Show DevTools | `[CTRL+SHIFT+I]` or `[F12]` |
| Show Network tab | `[CTRL+SHIFT+E]` |
| Show Console tab | `[CTRL+SHIFT+K]` |

---

# [cURL](https://curl.se/docs/) Commands
| Description | Command |
|-------------|---------|
| cURL help menu | `curl -h` or `curl --help-all` |
| Basic GET request | `curl inlanefreight.com` |
| Download file | `curl -s -O inlanefreight.com/index.html` |
| Skip HTTPS (SSL) certificate validation | `curl -k https://inlanefreight.com` |
| Print full HTTP request/response details | `curl inlanefreight.com -v` |
| Send HEAD request (only prints response headers) | `curl -I https://www.inlanefreight.com` |
| Print response headers and response body | `curl -i https://www.inlanefreight.com` |
| Set User-Agent header | `curl https://www.inlanefreight.com -A 'Mozilla/5.0'` |
| Set HTTP basic authorization credentials | `curl -u admin:admin http://<SERVER_IP>:<PORT>/` |
| Pass HTTP basic authorization credentials in the URL | `curl http://admin:admin@<SERVER_IP>:<PORT>/` |
| Set request header | `curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/` |
| Pass GET parameters | `curl 'http://<SERVER_IP>:<PORT>/search.php?search=le'` |
| Send POST request with POST data | `curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/` |
| Set request cookies | `curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/` |
| Send POST request with JSON data | `curl -X POST -d '{"search":"london"}' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php` |
| Monitor of a website or file is still accessible | `while :; do curl -sSr http://<URL> \| head -n 1; sleep 60; done` |
| Grab headers and spoof user agent | `curl -I -X HEAD -A "Mozilla/5.0 (compatible; MSIE 7.01; Windows NT 5.0)" <URL>` |
| Scrape site after login | `curl -u <USERNAME>:<PASSWORD> -o <OUTPUT_FILE> <URL>` | 
| FTP | `curl ftp://<USERNAME>:<PASSWORD>@<URL>/<DIRECTORY>` | 
| Sequential Lookup | `curl http://<URL>/<FILE_PATH>[1-10].txt` | 
| Read entry | `curl http://<SERVER_IP>:<PORT>/api.php/city/london` |
| Read all entries | `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ \| jq` |
| Create (add) entry | `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` |
| Update (modify) entry | `curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` |
| Delete entry | `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City` |
| Send a suspicious hash to VirusTotal | `curl -v --request POST --url 'https://www.virustotal.com/vtapi/v2/file/report' -d apikey=<VT API KEY> -d 'resource=<SUSPICIOUS FILE HASH>'` |
| Send a suspicious file to VirusTotal | `curl -v -F 'file=/<PATH TO FILE>/<SUSPICIOUS FILE NAME>' -F apikey=<VT API KEY> https://www.virustotal.com/vtapi/v2/file/scan` |


---


# HTTPie


---


# Wget Commands


---


# Netcat (nc) Commands


---


# Telnet Commands


---


# FFuf Commands


---


# Dirb


---


# Gobuster


---


# Wappalyzer


---


# Tcpdump


---


# Tshark


---


# SQLmap


---


# Nikto


---


# Hydra


---


# JWT-Tool


---


#
