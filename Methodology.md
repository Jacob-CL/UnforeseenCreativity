# Web Application Penetration Testing Methodology

---

## **1. Reconnaissance & Information Gathering**
### **Objectives:**
- **Identifying Assets**: Uncovering all publicly accessible components of the target, such as web pages, subdomains, IP addresses, and technologies used. This step provides a comprehensive overview of the target's online presence.
-** Discovering Hidden Information**: Locating sensitive information that might be inadvertently exposed, including backup files, configuration files, or internal documentation. These findings can reveal valuable insights and potential entry points for attacks.
- **Analysing the Attack Surface**: Examining the target's attack surface to identify potential vulnerabilities and weaknesses. This involves assessing the technologies used, configurations, and possible entry points for exploitation.
- **Gathering Intelligence**: Collecting information that can be leveraged for further exploitation or social engineering attacks. This includes identifying key personnel, email addresses, or patterns of behaviour that could be exploited.

#### Active Reconnaissance
| Technique | Description | Example | Tools | Risk of Detection |
|-----------|-------------|---------|-------|------------------|
| **Port Scanning** | Identifying open ports and services running on the target. | Using Nmap to scan a web server for open ports like 80 (HTTP) and 443 (HTTPS). | `Nmap`, `Masscan`, `Unicornscan` | **High**: Direct interaction with the target can trigger intrusion detection systems (IDS) and firewalls. |
| **Vulnerability Scanning** | Probing the target for known vulnerabilities, such as outdated software or misconfigurations. | Running Nessus against a web application to check for SQL injection flaws or cross-site scripting (XSS) vulnerabilities. | `Nessus`, `OpenVAS`, `Nikto` | **High**: Vulnerability scanners send exploit payloads that security solutions can detect. |
| **Network Mapping** | Mapping the target's network topology, including connected devices and their relationships. | Using traceroute to determine the path packets take to reach the target server, revealing potential network hops and infrastructure. | `Traceroute`, `Nmap` | **Medium to High**: Excessive or unusual network traffic can raise suspicion. |
| **Banner Grabbing** | Retrieving information from banners displayed by services running on the target. | Connecting to a web server on port 80 and examining the HTTP banner to identify the web server software and version. | `Netcat`, `curl` | **Low**: Banner grabbing typically involves minimal interaction but can still be logged. |
| **OS Fingerprinting** | Identifying the operating system running on the target. | Using Nmap's OS detection capabilities (`-O`) to determine if the target is running Windows, Linux, or another OS. | `Nmap`, `Xprobe2` | **Low**: OS fingerprinting is usually passive, but some advanced techniques can be detected. |
| **Service Enumeration** | Determining the specific versions of services running on open ports. | Using Nmap's service version detection (`-sV`) to determine if a web server is running Apache 2.4.50 or Nginx 1.18.0. | `Nmap` | **Low**: Similar to banner grabbing, service enumeration can be logged but is less likely to trigger alerts. |
| **Web Spidering** | Crawling the target website to identify web pages, directories, and files. | Running a web crawler like Burp Suite Spider or OWASP ZAP Spider to map out the structure of a website and discover hidden resources. | `Burp Suite Spider`, `OWASP ZAP Spider`, `Scrapy` (customizable) | **Low to Medium**: Can be detected if the crawler's behavior is not carefully configured to mimic legitimate traffic. |


---

## **2. Enumeration & Mapping**
### **Objective:** Identify potential attack vectors, endpoints, and application structure.

| Task | Recommended Tools |
|------|------------------|
| Extract server headers & HTTP methods | `curl -I`, `curl -X OPTIONS`, `nmap --script http-methods` |
| Crawl & analyze the website structure | `hakrawler`, `gospider`, `waybackurls` |
| Extract JavaScript endpoints | `LinkFinder`, `JSParser`, `gf` |
| Identify API endpoints | `ffuf`, `gau`, `katana`, `burpsuite` |
| Identify input fields & parameters | `burpsuite`, `ZAP`, `arjun` |

---

## **3. Vulnerability Assessment**
### **Objective:** Detect security weaknesses and misconfigurations.

| Task | Recommended Tools |
|------|------------------|
| Scan for common vulnerabilities | `nikto`, `nmap --script http-vuln*`, `ZAP` |
| Check for outdated technologies | `whatweb`, `nuclei` |
| Test for misconfigured security headers | `curl -I`, `securityheaders.com` |
| Identify exposed sensitive files | `dirsearch`, `ffuf`, `gobuster` |
| Automated API vulnerability scanning | `nuclei -t http`, `dalfox` (XSS scanning), `gf` (sensitive parameters) |

---

## **4. Exploitation & Attack Simulation**
### **Objective:** Exploit identified vulnerabilities to verify their impact.

| Attack Type | Recommended Tools |
|------------|------------------|
| SQL Injection (SQLi) | `sqlmap`, `burpsuite`, `nmap --script=http-sql-injection` |
| Cross-Site Scripting (XSS) | `dalfox`, `XSStrike`, `kiterunner`, `burpsuite` |
| Cross-Site Request Forgery (CSRF) | `burpsuite`, `ZAP` |
| Open Redirects | `burpsuite`, `curl`, `qsreplace` |
| Server-Side Request Forgery (SSRF) | `ssrfmap`, `burpsuite`, `metasploit` |
| XML External Entity Injection (XXE) | `burpsuite`, `nmap --script=http-xxe` |
| Remote Code Execution (RCE) | `burpsuite`, `nmap --script=http-rfi`, `metasploit` |
| Broken Authentication & Authorization | `hydra`, `jwt_tool`, `burpsuite` |

---

## **5. Privilege Escalation & Post-Exploitation**
### **Objective:** Escalate access within the application to gain deeper control.

| Task | Recommended Tools |
|------|------------------|
| Test for privilege escalation flaws | `burpsuite`, `ffuf`, `jwt_tool` |
| Exploit weak session management | `jwt_tool`, `mitmproxy`, `burpsuite` |
| Test API authentication flaws | `restcli`, `Postman`, `burpsuite` |
| Exploit IDOR vulnerabilities | `burpsuite`, `ffuf`, `nuclei` |

---

## **6. Defensive Evasion & Bypasses**
### **Objective:** Evade security mechanisms like WAFs and detection systems.

| Task | Recommended Tools |
|------|------------------|
| Bypass Web Application Firewalls (WAFs) | `wafw00f`, `burpsuite`, `ffuf`, `nuclei` |
| Encode payloads to bypass filters | `base64`, `urlencode`, `cyberchef`, `burpsuite` |
| Use alternate request methods | `curl -X PUT`, `nmap --script http-methods` |
| Proxy & anonymize requests | `tor`, `proxychains`, `mitmproxy` |

---

## **7. Reporting & Documentation**
### **Objective:** Document findings with detailed explanations and remediation recommendations.

| Task | Recommended Tools |
|------|------------------|
| Generate a professional penetration test report | `Dradis`, `Serpico`, `LaTeX`, `Obsidian` |
| Organize findings & screenshots | `CherryTree`, `KeepNote`, `burpsuite` |
| Convert raw results into readable reports | `markdown`, `notion`, `Jupyter Notebooks` |

---

## **Additional Tools & Resources**
### **Essential CLI Utilities**
- `jq` – JSON processor for handling API responses
- `xargs` – Chain multiple commands for automation
- `awk` / `sed` – Parsing and manipulating output
- `nmap` – Port scanning and enumeration
- `Metasploit` – Exploitation framework

### **Online Resources**
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackerOne Reports](https://hackerone.com/reports)
- [Google Dorking Database](https://www.exploit-db.com/google-hacking-database)

---

This methodology ensures **structured** web penetration testing, covering **reconnaissance, enumeration, exploitation, and reporting**. Let me know if you need modifications or additional details! 🚀
