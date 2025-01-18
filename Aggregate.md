# CTF & PenTesting Directory  
A directory for every (most) Cyber Security / PenTest topics  
- [HackTricks](https://book.hacktricks.wiki/en/index.html)  
- [HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)  
- [OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/)  
- [HackTheBox Academy](https://academy.hackthebox.com)  

---

## **Recon Methodology:**  
Port Scanning, Network Mapping, and Service Enumeration - `nmap`  
OS Fingerprinting - `nmap`, `Wappalyzer`, `WhatWeb`, `wafw00f`  
Vulnerability Scanning - `Nessus`, `OpenVAS`, `Nikto`  
Banner Grabbing - `Netcat`, `curl`  
Web Spidering - `Burp Suite`, `OWASP ZAP Spider`, `Scrapy`  
Search Engines - `Google Dorking`, `DuckDuckGo`, `Shodan`, `Yandex`, `Baidu`  
WHOIS Lookups - `whois example.com`  
DNS Zone Transfers and Subdomain Bruteforcing - `dig`, `nslookup`, `dnsenum`, `dnsrecon`  
Virtual Host Discovery - `gobuster`, `ffuf`  
Web Archive Analysis - `Wayback Machine`  
Social Media Analysis - `LinkedIn`, `Twitter/X`, `Facebook`, `Instagram`  
Code Repositories - `GitHub`, `GitLab`  
Certificate Transparency - `crt.sh`, `Censys`  

---

## **Browser DevTools Shortcuts**  
Show DevTools - `[CTRL+SHIFT+I]` or `[F12]`  
Show Network Tab - `[CTRL+SHIFT+E]`  
Show Console Tab - `[CTRL+SHIFT+K]`  

---

## **Useful Linux Commands**  
Add an IP and Domain to `/etc/hosts` - `echo "192.168.1.100 example.com" | sudo tee -a /etc/hosts`  
Determine file type - `file -i file.txt`  
Extract/Unzip file - `unzip file.txt -d extractedfileoutput.txt`  

---

## **WHOIS Commands**  
Basic WHOIS Lookup - `whois example.com`  
Use grep for specifics - `whois google.com | grep "Name Server"`  
Malware Hash Lookup - `whois -h hash.cymru.com <SUSPICIOUS FILE HASH>`  

---

## **dig Commands (DNS Lookup)**  
Default A record lookup - `dig domain.com`  
Retrieve IPv4 address - `dig domain.com A`  
Retrieve IPv6 address - `dig domain.com AAAA`  
Find mail servers (MX records) - `dig domain.com MX`  
Identify authoritative name servers - `dig domain.com NS`  
Retrieve TXT records - `dig domain.com TXT`  
Retrieve canonical name (CNAME) record - `dig domain.com CNAME`  
Retrieve start of authority (SOA) record - `dig domain.com SOA`  
Query specific name server - `dig @1.1.1.1 domain.com`  
Show full path of DNS resolution - `dig +trace domain.com`  
Perform reverse lookup - `dig -x 192.168.1.1`  
Provide a short answer - `dig +short domain.com`  
Display only the answer section - `dig +noall +answer domain.com`  
Retrieve all available DNS records - `dig domain.com ANY`  
Reverse domain lookup - `dig -x <IP_ADDRESS>`  
DNS zone transfer - `dig axfr <DOMAIN_NAME_TO_TRANSFER> @<DNS_IP>`  
DNS reverse lookup scan - `for ip in {1..254}; do dig -x 1.1.1.$ip | grep $ip >> dns.txt; done;`  

---

## **cURL Commands**  
cURL help menu - `curl -h` / `curl --help-all`  
Verbose request info - `curl -v https://example.com`  
Fetch only headers - `curl -I https://example.com`  
Make a POST request - `curl -X POST -d "username=admin&password=admin" https://example.com/login`  
Use Basic Authentication - `curl -u admin:password https://example.com/protected`  
Send a request through a proxy - `curl -x http://proxy.example.com:8080 https://target.com`  
Download a file - `curl -O https://example.com/file.txt`  
Upload a file - `curl -F "file=@exploit.php" https://example.com/upload`  
Follow redirects - `curl -L https://example.com`  

---

## **LDAP Enumeration Commands**  
Check anonymous LDAP access - `ldapsearch -H ldap://10.129.1.207 -x -b "dc=inlanefreight,dc=local"`  
Authenticated search - `python3 windapsearch.py --dc-ip 10.129.1.207 -u inlanefreight\\james.cross --da`  
Find Kerberoastable accounts - `python3 ldapsearch-ad.py -l 10.129.85.28 -d sequel -u rose -p KxEPkKe6R8su -t all`  

---

## **MSSQL Authentication**  
Authenticate with `sqlcmd` - `sqlcmd -S SERVER_IP -U USERNAME -P PASSWORD`  
Run a query with `sqlcmd` - `sqlcmd -S 10.10.10.10 -U sa -P MyPass123 -Q "SELECT name FROM master.sys.databases;"`  
Authenticate with `mssqlclient.py` - `python3 mssqlclient.py DOMAIN/USERNAME:PASSWORD@IP -windows-auth`  

---

## **SMB Commands**  
Connect to SMB share - `smbclient //10.129.85.28/Accounting -U rose`  
List files in SMB - `ls`  
Download a file - `get filename.txt`  
