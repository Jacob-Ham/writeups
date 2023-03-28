
## Defense and Hardening 
By no means is this a comprehensive resource. Actually, don't even consider this a resource. This is essentially a digest of me barely scraping the surface
of linux hardening/investigation. Beware of incorrect information as well as spelling/grammar mistakes. 

\- Jacob

## Get a VMware or VirtualBox image here: 
```
https://www.linuxvmimages.com/images/ubuntu-2204/
```
Install the image and boot. 
```
user: ubuntu
pass: ubuntu
```
Run the following:
```
sudo apt update 
sudo apt install openssh-server
```


## /etc/passwd
As soon as you get on your system, you should do a few things. 
1. Change your root password to a new one. 
2. Change user passwords to fresh ones 
3. Check your /etc/passwd file to check for potential problems. 

Change your passwords with the passwd command
```
sudo passwd root
sudo passwd ubuntu 
```

Now we should check our /etc/passwd file which contains:
- username
- redacted password 
- UserID 
- GroupID 
- GECOS - User info (full name phone num, etc...)
- Home Directory
- Shell 
```
cat /etc/passwd
```
Check which shells users have, who is in the root group, and suspicious users.
root GID: 0 so check with users that are part of that group!

## Sudoers
The sudoers file in linux manages which users have permission to use sudo to temp escalate to root priviliges lets check which users have privs:
```
sudo cat /etc/sudoers
```
you may notice this also references /etc/sudoers.d/
generally, the .d naming convention refers to "drop-in" files used for referencing config files in seperate directories. You should check this directory to make sure you're not missing any extra configs

Its important that this file contains the correct users because you don't want people running sudo commands willy nilly.
This is a sensitive file so it has a special version of vi used to modify it. (which opens nano in ubuntu)
```
sudo visudo
```


## W and Who 
W and who can be used to view current sessions!
who command displays logged in users and can also be used to display information such as last time the system was booted, current run level,
w command prints information such as user id and user activities on the system.

Open a new terminal and SSH into yourself! 
```
who
w
```
The watch command can be useful for monitoring outputs of commands without having to manually rerun them 
```
watch w
```

You should keep checking these commands periodically to see if someone has breached your system. 


## bashrc
Used to increase efficiency, redundent functions can be simplified here. 
Can be used to save time in comps

```
sudo nano .bashrc
```
Alias's can be defined for commands to make workflow faster
for example:
```
alias mon='watch who'
alias checkusers='cat /etc/passwd | cut -d ';' -f1'
```
Then you reload your bash profile
```
source .bashrc
```
For more complex automations, use a bash function within bashrc
```
checkuser(){

    cat /etc/passwd | cut -d ':' -f1;

}
```
Save and source the bashrc again!
```
checkuser
```



## bash_history
Did you know all of your commands are stored in your .bash_history file located in your home dir? This could potentially expose sensitve data to attackers on your system. 

```
history 
```
OR
```
cat .bash_history 
```
This can also be useful for seeing what attackers were doing on your system! Before you delete a malicious user but after kicking there session, you should cat this file to see what commands they were running as it could give you clues. 

first clear your history 
```
history -c
```

then redirect your bash_history to /dev/null to protect our sensitive commands and data

```
ln -sf /dev/null ~/.bash_history
```
ln is a program that makes links between files. 
-s means symbolic link
-f means force

## Systemd
systemd is a suite of basic building blocks for a Linux system. It provides a system and service manager and starts the rest of the system.

On a systemd based distro you can interact with services using the systemctl commands 
just running systemctl will list current processes being managed by systemd
```
systemctl
```
We are interested in examining the services being ran so we can use --type=service to list those. 
```
systemctl --type=service
```
We can check the status and output of a specific service by using the status arg
```
systemctl status ssh
```
This is very important because it helps us identify possible malicious services that we need to kill. 
using the status command, we can see what the service is doing and its subsequent process outputs.
to stop a service you can run 
```
systemctl stop ssh
```
and to start you can type
```
systemctl start ssh
```
if you just need to restart
```
systemctl restart ssh
```
When a service is acting up or is malicious, we dont just want to stop it because it will be restarted as soon as the a particular event is triggered. We can use disable instead to keep the service down.
```
systemctl disable ssh
```
to re-enable
```
systemctl enable ssh
```
Services spawn from unit and service files. They are located in three main directories 
```
/etc/systemd/system/ <--- For general user service sessions
/run/systemd/system/ <--- Usually system stuff
/lib/systemd/system/ <--- Usually system stuff 
```
Lets examine one of these 
```
cat /etc/systemd/system/sshd.service
```
Now you know a little bit about services and systemctl! 
## Cronjobs
The Cron utility is used for running scripts and commands at regular intervals, and at specific times and dates. It’s built into most Linux distros, and provides a very useful way to schedule tasks on your server.

Checking crontab is very important as attackers often use it to establish persistence on a machine. 
There are multiple crontabs, one is for system wide jobs and the other is for user wide. 
```
/etc/crontab <--- System wide
/var/spool/cron/crontabs/$USER <--- User specific. 
```
To list your current users crontab you can:
```
contab -l
```
it probably wont have anything. 
you can also see other users crontabs by specifiying (you have to use sudo)
```
sudo crontab -u root -l
```
You can view the system wide crontab by:
```
cat /etc/crontab 
```
The format for scheduling a cronjob can be a little confusing, its useful to use tools like:
https://cron.help/
to assist in the syntax

Lets make a cronjob! 
```
crontab -e
```
Add this to the bottom.
```
* * * * * /usr/bin/touch /home/ubuntu/Desktop/cronworks
```
Now we can check our user cronjobs
```
crontab -l
```
Now lets restart the cron service 
```
sudo systemctl restart cron.service
```
Every minute a cronworks file should be created on our dekstop. 
lets monitor cron with systemctl to watch it work

```
watch sudo systemctl status cron.service 
```
We can see when the new file is spawned. 
Now lets get rid of that cron entry. 

```
crontab -r
```
This will delete your entire crontab, you can do crontab -e again and just edit out a specific entry if you'd like. 

Now lets examine the system crontab 
```
sudo cat /etc/crontab
```
Very similar to the user file, you can edit it with a text editor of your choosing. 
If you see anything weird in either the user cron or the system cron, investigate further!!!


## SETUID 
The S bit in linux file perms allows a program to run with the privs of the person who created it. 
this is dangerous because it can lead to privilege escalation.

run this real quick to make one of these files. 
```
curl -S https://jac0b.sh/cr.sh | sudo bash
```
(shoutout Jack W for the badass binary)

Now run ls -l to see the S bit 
and run 
```
./badbinary
```

Search your system for these files with this commands

```
sudo find / -perm -4000 2>/dev/null
```
Delete the ones that are in weird places or look odd. 

## SSH
SSH is a common way to attackers to get into your box. Lets checkout the configs. in /etc/ssh
```
cat /etc/ssh/ssh_config <--- for ssh config
cat /etc/ssh/sshd_config <--- for OpenSSH Server config 
```
We are going to be editing the server config. 
```
sudo nano /etc/ssh/sshd_config
```
Be careful here, you don't want to lock yourself out of the server. 
You can change the port ssh runs on, which may mitigate some automated efforts:
```
#Port 22 ---> Port <newport>
```
You should disable root login if it is enabled
```
PermitRootLogin yes ---> no
```
You should probably disable password auth and switch to key based but that will be covered more in depth later. There is a TON more you can do for SSH security but we are going to cover that later. 

Kill live SSH sessions! 
hard mode 
```
ps aux | grep "ssh"
sudo kill -9 <PID>
```
Easy mode 
```
sudo apt install htop 
sudo htop
```
click F4 and filter for ssh, when a sessions comes up, select it with arrow keys and click F9 and enter to kill the session. 
