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
- Base64 encoded file to get it's contents rather than have the code execute and get it rendered.
