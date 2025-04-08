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
