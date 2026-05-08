---
title: OSEP-02-Windows注册表
description: '02-操作系统与编程理论 | 06-Windows注册表'
pubDate: 2026-05-08T14:00:00+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Windows
  - Persistence
  - Privilege Escalation
---

# Windows 注册表

## 什么是注册表？

**注册表**（Registry）是 Windows 的核心数据库，存储系统和应用程序的配置信息。

**类比**：
- 程序有局部变量和全局变量
- 注册表就像操作系统的"全局变量"

---

## 注册表的结构

### 层级结构

```
注册表
├── HKEY_CLASSES_ROOT (HKCR)
├── HKEY_CURRENT_USER (HKCU)
├── HKEY_LOCAL_MACHINE (HKLM)
├── HKEY_USERS (HKU)
└── HKEY_CURRENT_CONFIG (HKCC)
```

### 根键（Hive）详解

| 根键 | 缩写 | 存储内容 |
|------|------|---------|
| HKEY_LOCAL_MACHINE | HKLM | 系统级配置（所有用户共享） |
| HKEY_CURRENT_USER | HKCU | 当前用户的配置 |
| HKEY_CLASSES_ROOT | HKCR | 文件关联和 COM 对象 |
| HKEY_USERS | HKU | 所有用户的配置 |
| HKEY_CURRENT_CONFIG | HKCC | 当前硬件配置 |

### 键、子键、值

```
HKEY_CURRENT_USER                    ← 根键（Hive）
└── Software                         ← 键（Key）
    └── Microsoft                    ← 子键（Subkey）
        └── Windows                  ← 子键
            └── CurrentVersion       ← 子键
                └── Run              ← 子键
                    └── MyApp = "C:\app.exe"  ← 值（Value）
```

---

## 渗透测试中的重要注册表位置

### 1. 自启动位置

**用户级别（HKCU）**：
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**系统级别（HKLM）**：
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**渗透测试用途**：添加持久化后门

### 2. 服务配置

```
HKLM\SYSTEM\CurrentControlSet\Services\<服务名>
```

**渗透测试用途**：创建恶意服务、修改服务路径

### 3. 安全策略

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
```

**渗透测试用途**：禁用安全功能

### 4. PowerShell 执行策略

```
HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell
```

**渗透测试用途**：绕过执行策略限制

---

## HKCU vs HKLM

| 特性 | HKCU | HKLM |
|------|------|------|
| 作用范围 | 当前用户 | 所有用户 |
| 写入权限 | 普通用户可写 | 需要管理员权限 |
| 持久化效果 | 仅当前用户登录时生效 | 任何用户登录都生效 |

**渗透测试提示**：
- 没有管理员权限时，使用 HKCU
- 有管理员权限时，优先使用 HKLM（更持久）

---

## 32 位程序的注册表重定向

### Wow6432Node

在 64 位系统上，32 位程序访问某些注册表键时会被重定向：

```
32位程序访问: HKLM\SOFTWARE\Microsoft
实际访问的是: HKLM\SOFTWARE\WOW6432Node\Microsoft
```

### 受影响的键

主要是 `HKLM\SOFTWARE` 和 `HKCU\SOFTWARE` 下的键。

---

## 注册表操作命令

### 命令行工具：reg

**查询值**：
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

**添加值**：
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MyBackdoor /t REG_SZ /d "C:\backdoor.exe" /f
```

**删除值**：
```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MyBackdoor /f
```

### PowerShell

**查询**：
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

**添加**：
```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyBackdoor" -Value "C:\backdoor.exe"
```

**删除**：
```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyBackdoor"
```

---

## C# 操作注册表

### 使用 Microsoft.Win32 命名空间

```csharp
using Microsoft.Win32;

class RegistryDemo
{
    static void Main()
    {
        // 读取值
        object value = Registry.GetValue(
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            "MyApp",
            null  // 默认值
        );
        Console.WriteLine("值: " + value);

        // 写入值
        Registry.SetValue(
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            "MyBackdoor",
            @"C:\backdoor.exe"
        );
    }
}
```

### 使用 RegistryKey 类（更灵活）

```csharp
using Microsoft.Win32;

class RegistryDemo2
{
    static void Main()
    {
        // 打开键
        RegistryKey key = Registry.CurrentUser.OpenSubKey(
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            true  // true = 可写
        );

        if (key != null)
        {
            // 写入值
            key.SetValue("MyBackdoor", @"C:\backdoor.exe");

            // 读取值
            string value = (string)key.GetValue("MyBackdoor");
            Console.WriteLine("值: " + value);

            // 删除值
            key.DeleteValue("MyBackdoor", false);

            key.Close();
        }
    }
}
```

---

## 注册表值类型

| 类型 | 说明 | 示例 |
|------|------|------|
| REG_SZ | 字符串 | "C:\app.exe" |
| REG_DWORD | 32位整数 | 0x00000001 |
| REG_QWORD | 64位整数 | 0x0000000000000001 |
| REG_BINARY | 二进制数据 | 01 02 03 04 |
| REG_MULTI_SZ | 多字符串 | "str1\0str2\0" |
| REG_EXPAND_SZ | 可扩展字符串 | "%SystemRoot%\app.exe" |

---

## 渗透测试实战示例

### 添加自启动后门

```csharp
using Microsoft.Win32;

class Persistence
{
    static void AddPersistence(string name, string path)
    {
        try
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                true
            );

            if (key != null)
            {
                key.SetValue(name, path);
                Console.WriteLine("[+] 持久化添加成功");
                key.Close();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] 错误: " + ex.Message);
        }
    }

    static void Main()
    {
        AddPersistence("WindowsUpdate", @"C:\Users\Public\update.exe");
    }
}
```

### 检查 PowerShell 执行策略

```csharp
using Microsoft.Win32;

class CheckPolicy
{
    static void Main()
    {
        string policy = (string)Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
            "ExecutionPolicy",
            "Unknown"
        );
        Console.WriteLine("执行策略: " + policy);
    }
}
```

---

## 本节要点总结

| 概念 | 要点 |
|------|------|
| 注册表 | Windows 的配置数据库 |
| HKLM | 系统级配置，需要管理员权限 |
| HKCU | 用户级配置，普通用户可写 |
| Run 键 | 自启动位置，用于持久化 |
| Wow6432Node | 32 位程序的注册表重定向 |
| reg 命令 | 命令行操作注册表 |

---

## 第三章总结

本章学习了以下基础知识：

1. **编程语言基础**：编译型/解释型、低级/高级语言
2. **托管代码与非托管代码**：.NET、CLR、IL、JIT
3. **面向对象编程**：类、对象、构造函数、访问修饰符
4. **WOW64**：64 位系统运行 32 位程序的机制
5. **Win32 API**：Windows 系统函数，P/Invoke 调用
6. **Windows 注册表**：系统配置数据库

这些是后续所有攻击技术的基础！

---

**下一章**：后续章节发布后，这里会补上可直接跳转的文章链接。
