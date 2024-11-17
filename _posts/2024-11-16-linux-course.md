---
title: "Linux Essentials (I)"
image: /linux-image.webp
categories: [Cyber Courses, Linux]
tags: [linux ,command Line ,file system]
media_subpath: /images/linux-course
author: <author_id>
---

----

## **What is Linux?**

**Linux** is an **open-source operating system**[like windows] widely used across a diverse range of devices, from personal computers to powerful servers. It is known for its stability, security, and customizability, making it a popular choice among developers and IT professionals. Based on the **Linux kernel**, it offers various interfaces and environments, allowing for numerous distributions such as **Ubuntu**, **Fedora**, and **Debian**, each tailored to specific needs. Due to its flexibility, Linux powers many server systems, smart devices, and even mobile operating systems like Android. 

>Linux like Foundation and Structure of the House.
{: .prompt-info}
 
![Desktop View](/structure-fondation-analogy.webp){: width="1200" height="450" }

### **The Linux Kernel(The Heart of Linux)**

The **Linux kernel** is the core component of the Linux operating system. It is responsible for managing the system's hardware and software resources, and acts as an intermediary between the hardware (like the CPU, memory, and devices) and the software (applications and processes).

>Linux Kernel (Core) is like the Electrical Wiring and Plumbing and Software Applications are like Appliances and Devices in the House.
{: .prompt-info}

![Desktop View](/kernel-layout.png){: w="400" h="200" .normal }


### **Linux Distributions (Distros)**

Linux **distros** (short for distributions) are customized versions of the Linux operating system. Each distro includes the **Linux kernel** (the core of the system) along with a selection of software packages, utilities, and tools chosen to serve specific purposes or user needs. In simple terms, a Linux distro is like a version of Linux that has been tailored to meet particular goals, such as *personal use*, *servers*, or *developer environments*

| Distro         | Description                                                                   | Usage                                                             |
| -------------- |
| **Ubuntu**     | Beginner-friendly with (GNOME) interface                                      | Personal, small business,education                                |
| **Fedora**     | Cutting-edge, community-driven                                                | Developers, IT professionals, server environments                 |
| **Debian**     | stability and long-term support. Forms the base for many other distros        | Servers, data centers, and environments needing system stability. |
| **Arch Linux** | A lightweight, minimalist distro focused on customization.                    | Advanced users, developers, and system administrators             |
| **Kali Linux** | distro focused on security testing, penetration testing, and ethical hacking. | Penetration testing, ethical hacking, security auditing           |
| ----           |

>Linux Distributions (Distros) are like different types  house designs for very design have specific purpose
{: .prompt-info}
----

## **Essential Linux Commands Line for Beginners**

The command line (also called the **terminal** or **shell**) in Linux is a text-based interface used to interact with the operating system. Instead of using graphical user interfaces (GUIs), users type commands to perform specific tasks, such as managing files, running programs, configuring system settings, and more.

We use the command line in Linux because it offers **greater control**, **speed**, and **flexibility** compared to graphical user interfaces (GUIs). It allows users to perform tasks quickly by typing simple commands, automate repetitive actions through scripts, and access powerful system tools that are not always available in GUIs. The command line is also more **resource-efficient**, making it ideal for *managing servers* and *performing* complex tasks in a precise and *customizable* way. For advanced users, it is an essential tool for **system administration**, **software development**, and **troubleshooting**.

>Troubleshooting is the process of identifying and fixing problems in a system or software.
{: .prompt-info}

### **Navigating the File System**

* **pwd** command in Linux shows the full path of the directory you are currently in.

```console
┌──(drcpap㉿dcpapnet)-[~]
└─$ pwd
/home/drcpap
```
>We are currently at the root directory (/), and within the root, we are located in the home directory. Inside the home directory, we are specifically in the drcpap directory.
{: .prompt-info}

* **ls** command in Linux lists all the files and directories in the current directory. 

```console
┌──(drcpap㉿drcpapnet)-[~]
└─$ ls
Desktop    Downloads     Music     Public     Videos      Documents    Pictures  Templates
```
* **cd** command in Linux is used to change the current directory to another directory.

```console
┌──(drcpap㉿drcpapnet)-[~]
└─$ cd Desktop/        

┌──(drcpap㉿drcpapnet)-[~/Desktop]
└─$ pwd
/home/drcpap/Desktop

```

### **Managing Files and Directories**

* **mkdir** create a new Directory 

```console
┌──(drcpap㉿drcpapnet)-[~/Desktop]
└─$ mkdir new_Directory

┌──(drcpap㉿drcpapnet)-[~/Desktop]
└─$ cd new_Directory/

┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ pwd
/home/drcpap/Desktop/new_Directory

```

* **touch** create a new empty file

```console
┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ touch new_file

┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ ls
new_file

```

* **cp** copy files from directory to another

```console
┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ cp /home/drcpap/Desktop/copy_file .

┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ ls
new_file    copy_file

```
* **mv** move(cut) file from Directory to another

```console

┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ mv /home/drcpap/Desktop/moved_file .

┌──(drcpap㉿drcpapnet)-[~/Desktop]
└─$ ls
(moved_file) // Doesn't exist
┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ ls
new_file    copy_file   moved_file

```

* **rm** remove a file

```console
┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ rm new_file copy_file moved_file

┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ ls
```

* **rmdir** remove a empty Direcorty

```console
┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ cd .. (mean we return to previous directory)

┌──(drcpap㉿drcpapnet)-[~/Desktop/]
└─$ rmdir new_Directory

```
### **Viewing and Editing Files**

#### Viewing

* **less** View the contents of a file, page by page

* **cat** command in Linux is used to display the contents of a file in the terminal.
`cat <filename>`

```console 
┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ cat myfile
hello im the new file

```

#### Editing

* **nano** command in Linux is a simple text editor used to create or edit files directly from the terminal. 

```console 
┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ nano edit_file
```

![Desktop View](/nano.png){: .normal }

* **vim** command in Linux is a powerful text editor used for creating and editing files in the terminal, offering advanced features for efficient text manipulation.


```console 
┌──(drcpap㉿drcpapnet)-[~/Desktop/new_Directory]
└─$ vim edit_file
```

![Desktop View](/vim.png){: .normal }

>to get exit from vim (ESC) and write (:wq) 
{: .prompt-tip} 

### **Getting Help in Linux**

* **man** its manual help for every command in the linux
`man <command>`

>you can even use `man man` to see the manual of the manual funny isn't!!
{: .prompt-tip}

----

## **User Guide to Navigating the Linux File System Structure**

### **Understanding the Linux Directory Structure**

The Linux directory structure is a **hierarchical file system** that organizes files and directories in a tree-like structure. At the top is the root directory (/), which is the starting point of the entire file system. Under the root, directories such as /home, /bin, /etc, and /var contain system files, user files, executable programs, configurations, and logs. Each directory serves a specific purpose, ensuring that the system is organized and files are easily accessible. This structure is consistent across most Linux distributions, providing a standardized environment for users and administrators to work with.

![Desktop View](/linux-directory-structure.png){: .normal }

```console
┌──(drcpap㉿drcpapnet)-[/]
└─$ ls
bin   dev  home     lib32    mnt  proc  run   srv  tmp  var      vmlinuz.old
boot  etc    lib      lib64  media       opt  root  sbin  sys  usr  vmlinuz

```

### **The Importance of /home and User Directories**

The /home directory in Linux is crucial because it contains **personal directories** for each user on the system. Each user has a dedicated folder within /home (e.g., /home/username), where they can store their *personal files*, *configurations*, and *application* data. This separation ensures that user data is kept distinct from system files, enhancing security and organization. The /home directory also allows users to maintain their own environment settings, ensuring a personalized experience, and is important for data backup and recovery. By storing user-specific information separately, Linux ensures that system configurations and user data are managed efficiently and securely.

### **Exploring System Files in /etc, /bin, and /usr**

In Linux, certain directories are essential for system operation and organization. The /etc directory contains system configuration files that control the behavior of the system and installed applications. Files in /bin hold essential binary executable programs that are required for basic system functionality, such as ls, cp, and mv. The /usr directory is used for user-related programs, libraries, and documentation, and contains software installed for general use. Understanding these directories is important for system administrators and advanced users, as they help maintain and manage the system’s functionality and configurations.


| **Directory** | **Description**                                                                                 |
| ------------- |
| **/etc**      | Contains system-wide configuration files (e.g., network settings, user configurations).         |
| **/bin**      | Houses essential binary executables required for system operations                              |
| **/usr**      | Contains user-related programs, libraries, and documentation, including software and utilities. |

## Finally

Its just the begin of the course so be patient ypu will learn advanced topics in the next courses.

----
