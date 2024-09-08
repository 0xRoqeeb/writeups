
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


