# Web Attacks
## HTTP Verb Tampering
- The HTTP protocol works by accepting various HTTP methods as verbs at the beginning of an HTTP request. Depending on the web server configuration, web applications may be scripted to accept certain HTTP methods for their various functionalities and perform a particular action based on the type of the request.
- Verbs include: GET, POST, HEAD, PUT, HEAD, PATCH, OPTIONS, DELETE
- Right click --> change request method in burp
- OPTIONS should send back all allowable verbs
- Some web apps only filter/allow list certain verbs, but HEAD acts very similar to GET but has no response in the body.

## IDOR
- Insecure Direct Object References (IDOR) vulnerabilities are among the most common web vulnerabilities and can significantly impact the vulnerable web application. IDOR vulnerabilities occur when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects. If any user can access any resource due to the lack of a solid access control system, the system is considered to be vulnerable.

- Reminder: Hashes are one way

## Bypassing encoded references
- We might not be able to update/post a users details but can we see them with a GET request?
