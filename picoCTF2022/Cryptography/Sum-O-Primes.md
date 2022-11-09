    

# PicoCTF 2022 – Sum-O-Primes
RSA Cryptography

### **Problem**
We have so much faith in RSA we give you not just the product of the primes, but their sum as well!

- gen.py
- output.txt

### **Summary of Solution**
If you are given the sum of P and Q you can do some basic math to derive P and Q given the sum and N. I wrote a python script that does this math, then inputed P, Q, C, and N into dcode.fr and captured the flag!

### **Research**
Not having much previous RSA expierence I started by reading the Wiki page to gain a general understanding of the system.

[https://en.wikipedia.org/wiki/RSA_(cryptosystem](https://en.wikipedia.org/wiki/RSA_(cryptosystem))

This was helpful, I knew I needed to find the two large primes (P & Q) that were used to generate N (p*q) and use P, Q, and N to uncipher C. Output.txt gives us N, X, and C with X being the sum of P and Q.

My breakthrough came from this question on stackexchange: [https://crypto.stackexchange.com/a/87309](https://crypto.stackexchange.com/a/87309)

My teammate  shared the post with the team and I couldn't have solved this without it.


### **Solution**

I implemented the solution to find P and Q in python then used dcode.fr to do the actual decryption.

We are given N, X, and C in Hex so I converted everything to decimal before starting.


**Step 1.  import decimal and set its precision**


``````python
import decimal as d

n = #<REPLACE WITH YOUR PUBLIC KEY>#
x = #<REPLACE WITH SUM OF PRIMES>#

d.getcontext().prec = 617
``````
  

**Step 2. We have to find the discriminant**
``````python
discriminant = sqrt((b^2)-4n), in python:
x1 = d.Decimal(x**2)
val = d.Decimal(x1 - (4 * n))
discriminant = d.Decimal(val).sqrt()
``````
  

**Step 3. Find P:**
``````python
p = x + discriminant/2
p = d.Decimal(x + discriminant)/2
``````
  

**Step 4. Find q**
``````python
q = x – discriminant/2
q = d.Decimal(x – discriminant)/2
``````

**Step 5. Print P and Q**
``````python
print(f'p = {p:f}')
print(f'q = {q:f}')
``````

**Entire Script:**
``````python
import decimal as d

n = #<REPLACE WITH YOUR PUBLIC KEY>#
x = #<REPLACE WITH SUM OF PRIMES>#

d.getcontext().prec = 617

def factor(n,x):

	x1 = d.Decimal(x**2)
	val = d.Decimal(x1 - (4 * n))
	discriminant = d.Decimal(val).sqrt()

	p = d.Decimal(x + discriminant)/2
	q = d.Decimal(x - discriminant)/2

	print(f'p = {p:f}')
	print(f'q = {q:f}')

factor(n,x)
``````

### Final step:

I used [https://www.dcode.fr/rsa-cipher](https://www.dcode.fr/rsa-cipher) to do the final decryption

![](file:///tmp/lu64249bjp2g.tmp/lu64249bjp2l_tmp_e9630230a2fa990d.png)  

### Flag

**picoCTF{ee326097}**