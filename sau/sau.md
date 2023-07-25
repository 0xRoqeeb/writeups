# Hack The Box - Sau Writeup
by Roqeeb

# Information Gathering
## Nmap
```
nmap -sC -sV 10.10.11.224 -vvv -T3 -oN nmap
```
After the scan was done we discovered two open ports opened ports 22 and 55555 ,due the speed of my scan i also got some false positives port 80 and 6003 with the ‘filtered’ state i will be ignoring because accessing them provides no response
