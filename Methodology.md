# Web Application Penetration Testing Methodology

This methodology provides a structured approach to **web application penetration testing**, ensuring thorough coverage of attack surfaces. Below are the key phases, along with **recommended tools** for each step.

---

## **1. Reconnaissance & Information Gathering**
### **Objective:** Gather as much information about the target as possible before active testing.

| Task | Recommended Tools |
|------|------------------|
| Passive reconnaissance (Google dorking, WHOIS, etc.) | `Google`, `WHOIS`, `Shodan`, `theHarvester` |
| Subdomain enumeration | `subfinder`, `amass`, `assetfinder`, `crt.sh` |
| DNS reconnaissance | `dnsrecon`, `dnsenum`, `dig`, `nslookup` |
| Website fingerprinting | `whatweb`, `wappalyzer`, `nmap -p 80,443 --script=http-title,http-server-header` |
| Find hidden files/directories | `gobuster`, `dirb`, `ffuf` |
| Gather web application metadata | `curl -I`, `wget --spider`, `httpie` |

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
