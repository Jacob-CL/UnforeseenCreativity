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

# [Gopher Protocol](https://github.com/tarunkant/Gopherus)
- As we have seen previously, we can use SSRF to access restricted internal endpoints. However, we are restricted to GET requests as there is no way to send a POST request with the http:// URL scheme. 
- Use the gopher URL scheme to send arbitrary bytes to a TCP socket. This protocol enables us to create a POST request by building the HTTP request ourselves.
- We can use the gopher protocol to interact with many internal services, not just HTTP servers. Imagine a scenario where we identify, through an SSRF vulnerability, that TCP port 25 is open locally. This is the standard port for SMTP servers. We can use Gopher to interact with this internal SMTP server as well. However, constructing syntactically and semantically correct gopher URLs can take time and effort. Thus, we will utilize the tool Gopherus to generate gopher URLs for us. The following services are supported:
```
    MySQL
    PostgreSQL
    FastCGI
    Redis
    SMTP
    Zabbix
    pymemcache
    rbmemcache
    phpmemcache
    dmpmemcache
```
## Blind SSRF
In many real-world SSRF vulnerabilities, the response is not directly displayed to us. These instances are called blind SSRF vulnerabilities because we cannot see the response. As such, all of the exploitation vectors discussed in the previous sections are unavailable to us because they all rely on us being able to inspect the response. 
- Need a NetCat listener to see if an SSRF exists
- Depending on how the web application catches unexpected errors, we might be unable to identify running services that do not respond with valid HTTP responses. For whether we're testing for different ports or different services - enumerate the responses!

## Template Engines
A template engine is software that combines pre-defined templates with dynamically generated data and is often used by web applications to generate dynamic responses. An everyday use case for template engines is a website with shared headers and footers for all pages. A template can dynamically add content but keep the header and footer the same. This avoids duplicate instances of header and footer in different places, reducing complexity and thus enabling better code maintainability. 
- The process of identifying an SSTI vulnerability is similar to the process of identifying any other injection vulnerability, such as SQL injection. The most effective way is to inject special characters with semantic meaning in template engines and observe the web application's behavior. As such, the following test string is commonly used to provoke an error message in a web application vulnerable to SSTI, as it consists of all special characters that have a particular semantic purpose in popular template engines:

`${{<%[%'"}}%\.`

Since the above test string should almost certainly violate the template syntax, it should result in an error if the web application is vulnerable to SSTI.
To enable the successful exploitation of an SSTI vulnerability, we first need to determine the template engine used by the web application. We can utilize slight variations in the behavior of different template engines to achieve this. For instance, consider the following commonly used overview containing slight differences in popular template engines:
![image](https://github.com/user-attachments/assets/e6753a74-123c-4495-ae58-792a5b4ebc3f)
- The result will enable us to deduce the template engine used by the web application. In Jinja, the result will be 7777777, while in Twig, the result will be 49.
- If the mathematical functoin is not executed, then that's a fail and you should follow the red arrow.
- we can obtain the web application's configuration using the following SSTI payload: `{{ config.items() }}`
- Code to read the flag: `{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}`



