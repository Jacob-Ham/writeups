# Policy Violation Pt.1 #

1. Install ewf tools
```bash
sudo apt install ewf-tools
```

2. create folder to mount image and mount .e01 file
``````bash
mkdir image
ewfmount Image.E01 image 
``````

3. Extract files with tsk_recover
``````bash
mkdir imageExtract

cd image

tsk_recover -e ewf1 ../imageExtract
``````

4. Looking through the directories two PDFs in the $RECYCLE.BIN directory look interesting. I know you can embed exploits into pdfs, so i upload them to virustotal and it shows the CVE 

![[Virustotal.png.png]]

The flag format is crew{CVE-2008-2992_Date:MM.D.YY}

 google the CVE find this page: 
https://www.cvedetails.com/cve/CVE-2008-2992/

I first try the report date, it doesent work so i try the publish date and thats the flag!

## Flag ##
**crew{CVE-2008-2992_Date:11.04.08}**


