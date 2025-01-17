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

# 1. **Recon**
# [WHOIS](https://whoisrb.org/docs/) commands
The `whois` command queries **WHOIS databases** to retrieve information about domain registrations, IP addresses, and network ownership. It can help determine the following:
- **Registrar Name** – The company that registered the domain (e.g., GoDaddy, Namecheap).
- **Registrant Name & Contact Information** *(if not hidden by privacy protection)*.
- **Domain Creation & Expiry Dates** – When the domain was registered and when it will expire.
- **Domain Status** – Active, expired, on-hold, or locked to prevent transfer.

| Description | Command |
|-------------|---------|
| Basic WHOIS Lookup | `whois example.com` |
| Use grep for specifics | `whois google.com \| grep "Name Server"` |

## WHOIS Resources
| Resource | Organization |
|----------|-------------|
| [icann.org](https://www.icann.org/) | ICANN |
| [iana.com](https://www.iana.org/) | IANA |
| [nro.net](https://www.nro.net/) | NRO |
| [afrinic.net](https://www.afrinic.net/) | AFRINIC |
| [apnic.net](https://www.apnic.net/) | APNIC |
| [ws.arin.net](https://www.arin.net/) | ARIN |
| [lacnic.net](https://www.lacnic.net/) | LACNIC |
| [ripe.net](https://www.ripe.net/) | RIPE |
| [internic.net](https://www.internic.net/) | InterNIC |


## Network Resources
| Resource | Description |
|----------|-------------|
| [dnsstuff.com/tools](https://www.dnsstuff.com/tools) | DNSstuff Toolbox |
| [network-tools.com](https://network-tools.com/) | Network-Tools |
| [centralops.net](https://centralops.net/) | CentralOps |
| [lg.he.net](https://lg.he.net/) | Hurricane Electric Looking Glass |
| [bgp4.as/looking-glasses](https://www.bgp4.as/looking-glasses) | BGP Looking Glass |
| [shodan.io](https://www.shodan.io/) | Shodan (Internet-wide scanning) |
| [viz.greynoise.io](https://viz.greynoise.io/) | GreyNoise (Threat intelligence) |
| [mxtoolbox.com/NetworkTools.aspx](https://mxtoolbox.com/NetworkTools.aspx) | MxToolBox |
| [iana.org/numbers](https://www.iana.org/numbers) | IANA IP and ASN Lookup |

# Relationship and Recon Tools
| Resource | Description |
|----------|-------------|
| [github.com/ElevenPaths/FOCA](https://github.com/ElevenPaths/FOCA) | FOCA (Metadata Extraction) |
| [github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) | theHarvester (Email & Domain OSINT) |
| [maltego.com](https://www.maltego.com/) | Maltego (Graph-Based OSINT) |
| [github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) | Recon-ng Framework (Automated Recon) |

# People Search Resources
| Resource | Description |
|----------|-------------|
| [peekyou.com](https://www.peekyou.com/) | PeekYou |
| [spokeo.com](https://www.spokeo.com/) | Spokeo |
| [pipl.com](https://www.pipl.com/) | Pipl |
| [intelius.com](https://www.intelius.com/) | Intelius |
| [publicrecords.searchsystems.net](https://publicrecords.searchsystems.net/) | Search Systems |

# OSINT Websites
| Resource | Description |
|----------|-------------|
| [vulnerabilityassessment.co.uk/Penetration%20Test.html](https://www.vulnerabilityassessment.co.uk/Penetration%20Test.html) | Vulnerability Assessment & Penetration Testing |
| [securitysift.com/passive-reconnaissance/](https://www.securitysift.com/passive-reconnaissance/) | Passive Reconnaissance Techniques |
| [pentest-standard.org/index.php/Intelligence_Gathering](https://pentest-standard.org/index.php/Intelligence_Gathering) | Penetration Testing Standard - Intelligence Gathering |
| [onstrat.com/osint/](http://www.onstrat.com/osint/) | Open-Source Intelligence (OSINT) Guide |

---

## [cURL](https://curl.se/docs/) Commands
`cURL` is a command-line tool for transferring data using various protocols (HTTP, HTTPS, FTP, etc.). It is commonly used for making web requests, downloading/uploading files, testing APIs, and automating network tasks.

### **General & Help Flags**

| Description | Command |
|-------------|---------|
| cURL help menu | `curl -h` / `curl --help-all` |
| Shows all available options in a long list | `curl --help all` |
| Lists all available categories of options | `curl --help category` |
| Shows help for a specific category (e.g., HTTP) | `curl --help http` |
| Displays the full manual page | `curl -M` / `curl --manual` |
| Shows the version of `curl`, supported protocols, and features | `curl -V` / `curl --version` |

### **Verbose Output Flags**

| Description | Command |
|-------------|---------|
| Provides detailed request/response info | `curl -v https://example.com` / `curl --verbose https://example.com` |
| Hides progress and error messages | `curl -s https://example.com` / `curl --silent https://example.com` |
| Hides progress but still shows errors | `curl -sS https://example.com` |

### **Debugging Headers & Data**

| Description | Command |
|-------------|---------|
| Displays response headers with body | `curl -i https://example.com` / `curl --include https://example.com` |
| Fetches only headers (no body) | `curl -I https://example.com` / `curl --head https://example.com` |
| Logs detailed request/response data to file | `curl --trace curl.log https://example.com` |
| Logs request/response data in ASCII format | `curl --trace-ascii curl.log https://example.com` |
| Custom output formatting (e.g., response time) | `curl -w "Response Code: %{http_code}\n" -o /dev/null -s https://example.com` |


### **HTTP Methods & Request Manipulation**

| Description | Command |
|-------------|---------|
| Basic GET request | `curl inlanefreight.com` |
| Sends a custom HTTP request method | `curl -X PUT https://example.com/resource` |
| Modifies or adds custom headers | `curl -H "X-Forwarded-For: 127.0.0.1" https://example.com` |
| Sends data via POST request | `curl -X POST -d "username=admin&password=admin" https://example.com/login` |
| Reads request body from a file | `curl -X POST -H "Content-Type: application/json" -d @data.json https://example.com/api` |

### **Authentication & Cookies**

| Description | Command |
|-------------|---------|
| Uses Basic Authentication | `curl -u admin:password https://example.com/protected` |
| Uses a session cookie | `curl -b "PHPSESSID=abcd1234" https://example.com/dashboard` |
| Stores cookies from a response | `curl -c cookies.txt https://example.com` |
| Uses stored cookies for a new request | `curl -b cookies.txt https://example.com` |

### **Proxy & Evasion Techniques**

| Description | Command |
|-------------|---------|
| Sends requests through a proxy | `curl -x http://proxy.example.com:8080 https://target.com` |
| Uses a SOCKS5 proxy (e.g., Tor) | `curl --socks5 127.0.0.1:9050 https://target.onion` |
| Changes the User-Agent string | `curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://example.com` |
| Spoofs the Referer header | `curl -e "https://google.com" https://example.com` |

### **Enumeration & Reconnaissance**

| Description | Command |
|-------------|---------|
| Checks available HTTP methods | `curl -X OPTIONS -i https://example.com` |
| Follows redirects | `curl -L https://example.com` |
| Measures response time | `curl -o /dev/null -s -w "Time: %{time_total}s\n" https://example.com` |
| Dumps response headers | `curl -I https://example.com` |

### **File Transfers & Exploitation**

| Description | Command |
|-------------|---------|
| Uploads a file via POST | `curl -F "file=@exploit.php" https://example.com/upload` |
| Uploads a file via PUT | `curl -X PUT --data-binary @exploit.php https://example.com/exploit.php` |
| Downloads a file from a server | `curl -O https://example.com/file.txt` |
| Executes command injection through headers | `curl -H "User-Agent: () { :; }; /bin/bash -c 'id'" https://example.com` |

### **API Interactions & Security Tools**

| Description | Command |
|-------------|---------|
| Read API entry | `curl http://<SERVER_IP>:<PORT>/api.php/city/london` |
| Read all API entries | `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq` |
| Create API entry | `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` |
| Update API entry | `curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` |
| Delete API entry | `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City` |
| Send a suspicious hash to VirusTotal | `curl -v --request POST --url 'https://www.virustotal.com/vtapi/v2/file/report' -d apikey=<VT API KEY> -d 'resource=<SUSPICIOUS FILE HASH>'` |
| Send a suspicious file to VirusTotal | `curl -v -F 'file=/<PATH TO FILE>/<SUSPICIOUS FILE NAME>' -F apikey=<VT API KEY> https://www.virustotal.com/vtapi/v2/file/scan` |

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
