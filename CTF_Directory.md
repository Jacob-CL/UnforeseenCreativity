# CTF & PenTesting Directory
A directory for every (most) CTF / Cyber Security topics
 - [HackTricks](https://book.hacktricks.wiki/en/index.html)
 - [HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)
 - [OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/)

# Web Requests / cURL / HTTP & HTTPS
- [HackTricks 80,443 - Pentesting Web Methodology]([url](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html))
- [HTB Web Requests Module](https://academy.hackthebox.com/module/35/section/219)
- [cURL](https://curl.se/docs/)

## cURL Commands

| Description | Command |
|-------------|---------|
| cURL help menu | `curl -h` |
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

---

## API Commands

| Description | Command |
|-------------|---------|
| Read entry | `curl http://<SERVER_IP>:<PORT>/api.php/city/london` |
| Read all entries | `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ \| jq` |
| Create (add) entry | `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` |
| Update (modify) entry | `curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` |
| Delete entry | `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City` |

---

## Browser DevTools Shortcuts

| Description | Shortcut |
|-------------|----------|
| Show DevTools | `[CTRL+SHIFT+I]` or `[F12]` |
| Show Network tab | `[CTRL+SHIFT+E]` |
| Show Console tab | `[CTRL+SHIFT+K]` |
