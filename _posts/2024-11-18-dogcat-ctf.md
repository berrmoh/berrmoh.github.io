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
root@ip-10-10-250-210:~# nmap -n -sC -sV -p- -v -T4 10.10.234.138

Starting Nmap 7.60 ( https://nmap.org ) at 2024-11-18 15:06 GMT
NSE: Loaded 146 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 15:06
Completed NSE at 15:06, 0.00s elapsed
Initiating NSE at 15:06
Completed NSE at 15:06, 0.00s elapsed
Initiating ARP Ping Scan at 15:06
Scanning 10.10.234.138 [1 port]
Completed ARP Ping Scan at 15:06, 0.22s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:06
Scanning 10.10.234.138 [65535 ports]
Discovered open port 22/tcp on 10.10.234.138
Discovered open port 80/tcp on 10.10.234.138
SYN Stealth Scan Timing: About 23.13% done; ETC: 15:08 (0:01:43 remaining)
SYN Stealth Scan Timing: About 27.80% done; ETC: 15:09 (0:02:38 remaining)
Increasing send delay for 10.10.234.138 from 0 to 5 due to 13885 out of 34712 dropped probes since last increase.
Increasing send delay for 10.10.234.138 from 5 to 10 due to 15 out of 36 dropped probes since last increase.
SYN Stealth Scan Timing: About 35.73% done; ETC: 15:10 (0:02:54 remaining)
SYN Stealth Scan Timing: About 37.84% done; ETC: 15:11 (0:03:29 remaining)
SYN Stealth Scan Timing: About 39.95% done; ETC: 15:12 (0:03:56 remaining)
SYN Stealth Scan Timing: About 42.07% done; ETC: 15:13 (0:04:18 remaining)
SYN Stealth Scan Timing: About 45.23% done; ETC: 15:14 (0:04:41 remaining)
SYN Stealth Scan Timing: About 65.55% done; ETC: 15:19 (0:04:30 remaining)
SYN Stealth Scan Timing: About 72.94% done; ETC: 15:20 (0:03:50 remaining)
SYN Stealth Scan Timing: About 79.07% done; ETC: 15:21 (0:03:07 remaining)
SYN Stealth Scan Timing: About 84.77% done; ETC: 15:21 (0:02:21 remaining)
SYN Stealth Scan Timing: About 90.26% done; ETC: 15:22 (0:01:33 remaining)
SYN Stealth Scan Timing: About 95.54% done; ETC: 15:22 (0:00:44 remaining)
Completed SYN Stealth Scan at 15:26, 1219.06s elapsed (65535 total ports)
Initiating Service scan at 15:26
Scanning 2 services on 10.10.234.138
Completed Service scan at 15:26, 6.01s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.234.138.
Initiating NSE at 15:26
Completed NSE at 15:26, 0.14s elapsed
Initiating NSE at 15:26
Completed NSE at 15:26, 0.00s elapsed
Nmap scan report for 10.10.234.138
Host is up (0.00037s latency).
Not shown: 65533 closed ports
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