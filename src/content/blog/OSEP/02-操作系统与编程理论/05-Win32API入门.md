---
title: OSEP-02-Win32API入门
description: '02-操作系统与编程理论 | 05-Win32API入门'
pubDate: 2026-01-30T00:00:05+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Exploit Development
  - Windows Learning
  - PowerShell
  - Privilege Escalation
---

# Win32 API 入门

## 什么是 Win32 API？

**Win32 API** 是 Windows 操作系统提供的编程接口，允许程序与操作系统交互。

**本质**：一组预先编写好的函数，存放在系统 DLL 中。

**为什么叫 Win32？**
- 最初为 32 位 Windows 设计
- 现在 64 位系统也使用这个名称
- 有时也叫 Windows API

---

## 为什么渗透测试要学 Win32 API？

| 用途 | 需要的 API |
|------|-----------|
| 进程注入 | OpenProcess, VirtualAllocEx, WriteProcessMemory |
| 执行 Shellcode | VirtualAlloc, CreateThread |
| 凭证获取 | OpenProcessToken, LookupPrivilegeValue |
| 键盘记录 | SetWindowsHookEx, GetAsyncKeyState |
| 屏幕截图 | GetDC, BitBlt |

**核心观点**：几乎所有高级攻击技术都依赖 Win32 API。

---

## API 存放在哪里？

Win32 API 存放在系统 DLL 中：

| DLL | 包含的 API 类型 |
|-----|----------------|
| kernel32.dll | 进程、线程、内存、文件操作 |
| user32.dll | 窗口、消息、用户界面 |
| advapi32.dll | 注册表、安全、服务 |
| ntdll.dll | 底层系统调用（Native API） |
| ws2_32.dll | 网络套接字 |

---

## 如何查找 API 文档？

### Microsoft 官方文档

网址：https://docs.microsoft.com/en-us/windows/win32/api/

### 文档结构

以 `VirtualAlloc` 为例：

```
VirtualAlloc function (memoryapi.h)

Reserves, commits, or changes the state of a region of pages...

Syntax:
LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

Parameters:
lpAddress - 起始地址
dwSize - 大小
...

Return value:
成功返回分配的地址，失败返回 NULL
```

---

## 函数原型详解

### 什么是函数原型？

**函数原型**描述了函数的：
- 返回类型
- 函数名
- 参数类型和数量

### 示例：GetUserNameA

```c
BOOL GetUserNameA(
  LPSTR   lpBuffer,    // 输出缓冲区
  LPDWORD pcbBuffer    // 缓冲区大小
);
```

**解读**：
| 部分 | 含义 |
|------|------|
| BOOL | 返回类型，布尔值（成功/失败） |
| GetUserNameA | 函数名 |
| LPSTR | 参数类型，字符串指针 |
| LPDWORD | 参数类型，DWORD 指针 |

---

## Windows 数据类型

Win32 API 使用特殊的数据类型名称：

### 基本类型

| Windows 类型 | C# 对应 | 说明 |
|-------------|---------|------|
| BOOL | bool/int | 布尔值 |
| BYTE | byte | 8 位无符号 |
| WORD | ushort | 16 位无符号 |
| DWORD | uint | 32 位无符号 |
| QWORD | ulong | 64 位无符号 |

### 指针类型

| Windows 类型 | C# 对应 | 说明 |
|-------------|---------|------|
| LPVOID | IntPtr | 通用指针 |
| LPSTR | string/StringBuilder | ASCII 字符串指针 |
| LPWSTR | string/StringBuilder | Unicode 字符串指针 |
| LPDWORD | ref uint | DWORD 指针 |
| HANDLE | IntPtr | 句柄 |

### 类型前缀含义

| 前缀 | 含义 |
|------|------|
| LP | Long Pointer（指针） |
| P | Pointer（指针） |
| H | Handle（句柄） |
| DW | DWORD |
| SZ | Zero-terminated String（以零结尾的字符串） |

---

## ASCII vs Unicode

### 两个版本的 API

很多 Win32 API 有两个版本：

| 后缀 | 字符编码 | 示例 |
|------|---------|------|
| A | ASCII（单字节） | GetUserName**A** |
| W | Unicode/Wide（双字节） | GetUserName**W** |

### 为什么有两个版本？

- ASCII：每个字符 1 字节，只支持英文
- Unicode：每个字符 2+ 字节，支持所有语言

### 选择哪个版本？

| 场景 | 推荐 |
|------|------|
| 现代程序 | W 版本（Unicode） |
| 兼容旧系统 | A 版本（ASCII） |
| 渗透测试 | 通常用 A 版本（更简单） |

---

## 在 C# 中调用 Win32 API

### P/Invoke 基本语法

```csharp
using System.Runtime.InteropServices;

class Program
{
    // 声明外部函数
    [DllImport("user32.dll", CharSet = CharSet.Ansi)]
    static extern int MessageBoxA(
        IntPtr hWnd,      // 父窗口句柄
        string lpText,    // 消息内容
        string lpCaption, // 标题
        uint uType        // 按钮类型
    );

    static void Main()
    {
        // 调用 API
        MessageBoxA(IntPtr.Zero, "Hello", "Title", 0);
    }
}
```

### DllImport 属性详解

```csharp
[DllImport("kernel32.dll",          // DLL 名称
           SetLastError = true,      // 保存错误码
           CharSet = CharSet.Ansi,   // 字符编码
           EntryPoint = "VirtualAlloc")] // 函数名（可选）
```

| 参数 | 作用 |
|------|------|
| DLL 名称 | 指定包含函数的 DLL |
| SetLastError | 是否保存 Windows 错误码 |
| CharSet | 字符串编码方式 |
| EntryPoint | 实际函数名（如果 C# 方法名不同） |

---

## 常用 API 速查

### 进程操作

| API | 作用 |
|-----|------|
| OpenProcess | 打开进程，获取句柄 |
| CreateProcess | 创建新进程 |
| TerminateProcess | 终止进程 |
| GetCurrentProcess | 获取当前进程句柄 |

### 内存操作

| API | 作用 |
|-----|------|
| VirtualAlloc | 在当前进程分配内存 |
| VirtualAllocEx | 在其他进程分配内存 |
| VirtualProtect | 修改内存保护属性 |
| VirtualFree | 释放内存 |

### 线程操作

| API | 作用 |
|-----|------|
| CreateThread | 在当前进程创建线程 |
| CreateRemoteThread | 在其他进程创建线程 |
| ResumeThread | 恢复挂起的线程 |
| SuspendThread | 挂起线程 |

### 内存读写

| API | 作用 |
|-----|------|
| ReadProcessMemory | 读取其他进程的内存 |
| WriteProcessMemory | 写入其他进程的内存 |

---

## 实战示例：调用 VirtualAlloc

```csharp
using System;
using System.Runtime.InteropServices;

class VirtualAllocDemo
{
    // 声明 API
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,       // 起始地址（NULL 让系统决定）
        uint dwSize,            // 分配大小
        uint flAllocationType,  // 分配类型
        uint flProtect          // 内存保护
    );

    // 常量定义
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    static void Main()
    {
        // 分配 1024 字节可执行内存
        IntPtr addr = VirtualAlloc(
            IntPtr.Zero,                    // 让系统选择地址
            1024,                           // 1024 字节
            MEM_COMMIT | MEM_RESERVE,       // 提交并保留
            PAGE_EXECUTE_READWRITE          // 可读可写可执行
        );

        if (addr == IntPtr.Zero)
        {
            Console.WriteLine("分配失败！错误码: " + Marshal.GetLastWin32Error());
            return;
        }

        Console.WriteLine("分配成功！地址: 0x" + addr.ToString("X"));
    }
}
```

---

## 本节要点总结

| 概念 | 要点 |
|------|------|
| Win32 API | Windows 提供的系统函数 |
| 存放位置 | kernel32.dll, user32.dll 等 |
| 函数原型 | 描述返回类型、参数类型 |
| A/W 后缀 | ASCII/Unicode 版本 |
| P/Invoke | C# 调用 Win32 API 的机制 |
| DllImport | 声明外部函数的属性 |

---

**下一节**：[06-Windows注册表](/blog/osep/02-操作系统与编程理论/06-windows注册表/)
