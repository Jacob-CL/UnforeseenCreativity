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
