# Web Requests
- Default port for HTTP communication is port 80, though this can be changed to any other port, depending on the web server configuration.
- We enter a Fully Qualified Domain Name (FQDN) as a Uniform Resource Locator (URL) to reach the desired website
- http://admin:password@inlanefreight.com:90/dashboard.php?login=true#status

| Component  | Example  | Description   |
|---|---|---|
| Scheme   | http:// https://   | This is used to identify the protocol being accessed by the client, and ends with a colon and a double slash (://)   |
| User Info   | admin:password@   | This is an optional component that contains the credentials (separated by a colon :) used to authenticate to the host, and is separated from the host with an at sign (@)   |
| Host   | inlanefreight.com   | The host signifies the resource location. This can be a hostname or an IP address   |
| Port   | :80   | The Port is separated from the Host by a colon (:). If no port is specified, http schemes default to port 80 and https default to port 443   |
| Path   | /dashboard.php   | This points to the resource being accessed, which can be a file or a folder. If there is no path specified, the server returns the default index (e.g. index.html).   |
| Query String   | ?login=true  |  	The query string starts with a question mark (?), and consists of a parameter (e.g. login) and a value (e.g. true). Multiple parameters can be separated by an ampersand (&).   |
| Fragments   | #status   | Fragments are processed by the browsers on the client-side to locate sections within the primary resource (e.g. a header or section on the page).  |
- Our browsers usually first look up records in the local '/etc/hosts' file, and if the requested domain does not exist within it, then they would contact other DNS servers. We can use the '/etc/hosts' to manually add records to for DNS resolution, by adding the IP followed by the domain name.
- By default, servers are configured to return an index file when a request for / is received.
- [cURL](https://curl.haxx.se)
- Use `--help all` or `man curl`
- Use `-v` flag to see both request and response. The `-vvv` flag shows an even more verbose output.
- Use cURL to download a page or file locally - use the -0 flag: `curl -O inlanefreight.com/index.html`
- Although data transferred through the HTTPS protocol may be encrypted, the request may still reveal the visited URL if it contacted a clear-text DNS server. For this reason, it is recommended to utilize encrypted DNS servers (e.g. 8.8.8.8 or 1.1.1.1), or utilize a VPN service to ensure all traffic is properly encrypted.
- If we type http:// instead of https:// to visit a website that enforces HTTPS, the browser attempts to resolve the domain and redirects the user to the webserver hosting the target website. A request is sent to port 80 first, which is the unencrypted HTTP protocol. The server detects this and redirects the client to secure HTTPS port 443 instead. This is done via the 301 Moved Permanently response code
- If we ever contact a website with an invalid SSL certificate or an outdated one, then cURL by default would not proceed with the communication to protect against the earlier mentioned MITM attacks `curl: (60) SSL certificate problem: Invalid certificate chain
More details here: https://curl.haxx.se/docs/sslcerts.html`
- Skip the certificate check with the `-k` flag
- HTTP REQUEST =
| Field   | Example   | Description   |
|---|---|---|
| Method   | GET   |  	The HTTP method or verb, which specifies the type of action to perform.   |
| Path   | /users/login.html   | The path to the resource being accessed. This field can also be suffixed with a query string (e.g. ?username=user).   | 
| Version   | HTTP/1.1   | The third and final field is used to denote the HTTP version.   |

- The next set of lines contain HTTP header value pairs, like Host, User-Agent, Cookie, and many other possible headers. These headers are used to specify various attributes of a request. The headers are terminated with a new line, which is necessary for the server to validate the request.
- HTTP version 1.X sends requests as clear-text, and uses a new-line character to separate different fields and different requests. HTTP version 2.X, on the other hand, sends requests as binary data in a dictionary form.

### General Headers
- General headers are used in both HTTP requests and responses. They are contextual and are used to describe the message rather than its contents.
| Header   | Example   | Description   |
|---|---|---|
| Date   | Date: Wed, 16 Feb 2022 10:38:44 GMT   | Holds the date and time at which the message originated. It's preferred to convert the time to the standard UTC time zone.   |
| Connection   | Connection: close   | Dictates if the current network connection should stay alive after the request finishes. Two commonly used values for this header are close and keep-alive. The close value from either the client or server means that they would like to terminate the connection, while the keep-alive header indicates that the connection should remain open to receive more data and input.   |

