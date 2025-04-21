# Server Side Attacks
Four classes of server-side vulnerabilities:
- Server-Side Request Forgery (SSRF): is a vulnerability where an attacker can manipulate a web application into sending unauthorized requests from the server. This vulnerability often occurs when an application makes HTTP requests to other servers based on user input. Successful exploitation of SSRF can enable an attacker to access internal systems, bypass firewalls, and retrieve sensitive information.
- Server-Side Template Injection (SSTI): Web applications can utilize templating engines and server-side templates to generate responses such as HTML content dynamically. This generation is often based on user input, enabling the web application to respond to user input dynamically. When an attacker can inject template code, a Server-Side Template Injection vulnerability can occur. 
- Server-Side Includes (SSI) Injection: Similar to server-side templates, server-side includes (SSI) can be used to generate HTML responses dynamically. SSI directives instruct the webserver to include additional content dynamically. These directives are embedded into HTML files. For instance, SSI can be used to include content that is present in all HTML pages, such as headers or footers. When an attacker can inject commands into the SSI directives, Server-Side Includes (SSI) Injection can occur. SSI injection can lead to data leakage or even remote code execution.
- eXtensible Stylesheet Language Transformations (XSLT) Server-Side Injection: XSLT (Extensible Stylesheet Language Transformations) server-side injection is a vulnerability that arises when an attacker can manipulate XSLT transformations performed on the server. XSLT is a language used to transform XML documents into other formats, such as HTML, and is commonly employed in web applications to generate content dynamically. In the context of XSLT server-side injection, attackers exploit weaknesses in how XSLT transformations are handled, allowing them to inject and execute arbitrary code on the server.

## Identifying SSRF
- If there is a variable name in the POST which contains a URL, this indicates that the web server fetches the availability information from a separate system determined by the URL passed in this POST parameter.
- To confirm an SSRF vulnerability, let us supply a URL pointing to our system to the web application in that variable.
  - `dateserver=http://your_ip:8000/ssrf` etc 
- Use NetCat: `nc -lnvp 8000`
- To determine whether the HTTP response reflects the SSRF response to us, let us point the web application to itself by providing the URL `http://127.0.0.1/index.php` and if the HTML response includes the file then youre in business.
- You can then use this SSRF to enumerate the ports e.g `dateserver:http://127.0.0.1:81`, assuming that it's closed we might get an error message back in the response. Do this for each port and youve essentially done an NMAP scan.
- Enumerate this with Burp and a wordlist of numbers and inspect the responses to see which ports are open.
- Quickly make a word list of numbers 1 -- > 10,000: `seq 1 10000 > ports.txt`
