# File Upload Attacks
- The worst possible kind of file upload vulnerability is an unauthenticated arbitrary file upload vulnerability.
- a file upload vulnerability is not only caused by writing insecure functions but is also often caused by the use of outdated libraries that may be vulnerable to these attacks
- If we click on a form to select a file, the file selector dialog does not specify any file type, as it says `All Files` for the file type, which may also suggest that no type of restrictions or limitations are specified for the web application on the FRONT END, there may be some on the back end
-  A web shell has to be written in the same programming language that runs the web server, as it runs platform-specific functions and commands to execute system commands on the back-end server, making web shells non-cross-platform scripts. So, the first step would be to identify what language runs the web application.
-  One easy method to determine what language runs the web application is to visit the `/index.ext` page, where we would swap out `ext` with various common web extensions, like `php`, `asp`, `aspx`, among others, to see whether any of them exist.
-  Once you have identified the web framework running the web application and its programming language, test whether we can upload a file with the same extension.
-  test.php --> `<?php echo "Hello HTB";?>`
-  If we can then download the test.php and it prints the string, we have executed PHP code on the back-end server
-  In PHP, use `system()` to execute commands e.g this is a simple webshell in pho - `<?php system($_REQUEST['cmd']); ?>`
  - Save as a .php and upload to get a web shell in the URL. We can execute system commands with the ?cmd= GET parameter (e.g. ?cmd=id), as follows: `http://SERVER_IP:PORT/uploads/shell.php?cmd=id`
- For .NET Web apps we can use the eval() function: `<% eval request('cmd') %> `
-  [SecLists Webshells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells)
-  We can download any of these web shells for the language of our web application, then upload it through the vulnerable upload feature, and visit the uploaded file to interact with the web shell.
-  If we are using this custom web shell in a browser, it may be best to use source-view by clicking [CTRL+U], as the source-view shows the command output as it would be shown in the terminal, without any HTML rendering that may affect how the output is formatted.
- [phpbash](https://github.com/Arrexel/phpbash)
- It must be noted that in certain cases, web shells may not work. This may be due to the web server preventing the use of some functions utilized by the web shell (e.g. system()), or due to a Web Application Firewall, among other reasons. 
-  [php reverse shell](https://github.com/pentestmonkey/php-reverse-shell)
NetCat listener: `nc -lvnp OUR_PORT` (where OUR_PORT is any free port)
- While reverse shells are always preferred over web shells, as they provide the most interactive method for controlling the compromised server, they may not always work, and we may have to rely on web shells instead.
- Webshell is CLI in browser, where reverse shell is in terminal.

Upload Exploitation Commands - Get Webshell
- Make PHP file `<?php system($_REQUEST['cmd']); ?>`
- Then add `?cmd=cat /flag.txt` to the end of the URL to get flag

Any code that runs on the client-side is under our control. While the web server is responsible for sending the front-end code, the rendering and execution of the front-end code happen within our browser. If the web application does not apply any of these validations on the back-end, we should be able to upload any file type.

To bypass these protections, we can either modify the upload request to the back-end server, or we can manipulate the front-end code to disable these type validations.

- We may also modify the Content-Type of the uploaded file, though this should not play an important role at this stage, so we'll keep it unmodified.
- Reminder: if you upload with nothing in the network tab then it's all happening front end. All front end code you can just remove lol
- In DevTools, go to console and search for functions you see in the front end HTML/Javascript and remove them to remove the front end filtering. Hope that it doesn't break the 'upload' functionality of the site and just removes the filtering element.
- Keep in mind you might come across whitelisting or blacklisting
- Also keep in mind the filtering could be listening for file type or file extension. The weakest form of validation amongst these is testing the file extension against a blacklist of extension to determine whether the upload request should be blocked
- Reminder: Case manipulation (php == PhP etc)
- A whitelist is generally more secure than a blacklist.
- Is the whitelist using regex? if it's matching on file extension just double ext image.jpeg.exe
## Fuzzing Web Extensions
- [SecList Web Extentions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)
- Use 'Intruder' in BurpSuite to fuzz available extensions.
- Note: If using a payload, make sure you untick 'URL-encode these characters' since you don't want the full stop encoded.
- Then look at the 'Length' of each response to see which are allowed.
- Not all extensions will work with all web server configurations, so we may need to try several extensions to get one that successfully executes PHP code.
- Many different file extensions will run php e.g .phar worked for the exercise.

## Character Injection
The following are some of the characters we may try injecting:
```
    %20
    %0a
    %00
    %0d0a
    /
    .\
    .
    …
    :
```
Each character has a specific use case that may trick the web application to misinterpret the file extension. For example, (shell.php%00.jpg) works with PHP servers with version 5.X or earlier, as it causes the PHP web server to end the file name after the (%00), and store it as (shell.php), while still passing the whitelist. The same may be used with web applications hosted on a Windows server by injecting a colon (:) before the allowed file extension (e.g. shell.aspx:.jpg), which should also write the file as (shell.aspx). Similarly, each of the other characters has a use case that may allow us to upload a PHP script while bypassing the type validation test.

- 
### Type Filters
There are two common methods for validating the file content: Content-Type Header or File Content.
Our browsers automatically set the Content-Type header when selecting a file through the file selector dialog, usually derived from the file extension. However, since our browsers set this, this operation is a client-side operation, and we can manipulate it to change the perceived file type and potentially bypass the type filter.

- [Seclists]((https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)
```
Lumington@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
Lumington@htb[/htb]$ cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```

A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header (e.g. if the uploaded content was sent as POST data), in which case we will need to modify the main Content-Type header.

- The second and more common type of file content validation is testing the uploaded file's `MIME-Type`. `Multipurpose Internet Mail Extensions (MIME)` is an internet standard that determines the type of a file through its general format and bytes structure.
- `file` command uses this e.g
```
Lumington@htb[/htb]$ echo "this is a text file" > text.jpg 
Lumington@htb[/htb]$ file text.jpg 
text.jpg: ASCII text
```
However, 
```
Lumington@htb[/htb]$ echo "GIF8" > text.jpg 
Lumington@htb[/htb]$file text.jpg
text.jpg: GIF image data
```
- So god dam important to read the source code - the date was prepended to the filename which is why i couldnt find my uploaded file :(
