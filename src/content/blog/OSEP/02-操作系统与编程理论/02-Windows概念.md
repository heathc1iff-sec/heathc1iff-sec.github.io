---
title: OSEP-02-Windows概念
description: '02-操作系统与编程理论 | 02-Windows概念'
pubDate: 2026-01-30T00:00:02+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
  - Windows
  - PowerShell
---

# Windows 与代码执行模型完整指南

> 对应参考资料：`1：office钓鱼.html`、`4：反射式powershell.html`、`6：进程注入迁移挖空.html`、`8/9：Windows 防御机制绕过` 的共同前置知识。  
> 学习定位：用一篇文档把 Windows 进程、线程、内存、句柄、注册表、安全机制、WOW64、托管/非托管和 Win32 API 串起来。

## 这篇解决什么问题

你后面会反复看到这些句子：

```text
打开目标进程句柄
在目标进程分配内存
把 shellcode 写进去
创建远程线程执行
检查 32/64 位是否匹配
通过 P/Invoke 调用 kernel32.dll
读取注册表策略判断 AppLocker
AMSI 扫描 PowerShell 脚本内容
```

这些都不是孤立技巧，而是 Windows 的基本执行模型。你只要理解下面这张图，后面很多章节会突然变清晰：

```text
用户操作 / 文档 / 脚本
  -> 进程启动
  -> 线程执行代码
  -> 进程拥有虚拟内存
  -> 代码调用 Win32 API
  -> API 操作句柄、内存、文件、注册表、网络
  -> 安全机制在不同层面观察和拦截
```

---

## 一、Windows 中最重要的三个对象：进程、线程、内存

### 1.1 进程 Process

进程是正在运行的程序实例。

```text
notepad.exe 文件
  -> 双击运行
  -> 变成一个 notepad.exe 进程
```

一个进程通常包含：

| 组成 | 说明 |
|---|---|
| PID | 进程 ID |
| 私有虚拟内存空间 | 代码、堆、栈、模块、映射区域 |
| 一个或多个线程 | 真正执行代码的单位 |
| 句柄表 | 打开的文件、进程、线程、注册表键等 |
| 安全上下文 | 当前用户、令牌、完整性级别 |
| 已加载模块 | EXE、DLL、.NET 程序集等 |

渗透测试中为什么关心进程？

| 场景 | 进程相关问题 |
|---|---|
| Office 宏 | 宏运行在 `WINWORD.EXE` 或 `EXCEL.EXE` 里 |
| PowerShell Runner | payload 可能运行在 `powershell.exe` 里 |
| 进程注入 | 需要选择目标进程 |
| 凭证抓取 | 需要访问 `lsass.exe` |
| AppLocker | 规则可能限制某些进程或路径 |

### 1.2 线程 Thread

线程是 CPU 调度和执行代码的基本单位。一个进程可以有多个线程。

```text
进程 = 工厂
线程 = 工厂里的工人
内存 = 工厂仓库
句柄 = 工厂拿到的各种许可证/钥匙
```

线程共享同一个进程的内存空间，所以：

```text
CreateThread(addr)
  -> 在当前进程创建线程
  -> 从 addr 地址开始执行代码

CreateRemoteThread(hProcess, addr)
  -> 在目标进程创建线程
  -> 从目标进程的 addr 地址开始执行代码
```

### 1.3 虚拟内存

每个进程都有自己的虚拟地址空间。进程 A 里的 `0x10000000` 和进程 B 里的 `0x10000000` 不是同一块真实内存。

常见内存区域：

| 区域 | 用途 |
|---|---|
| 代码段 | 程序机器码 |
| 数据段 | 全局变量 |
| 堆 Heap | 动态分配对象 |
| 栈 Stack | 函数调用、局部变量 |
| 映射模块 | DLL、EXE、内存映射文件 |
| 手动分配区域 | `VirtualAlloc` / `VirtualAllocEx` |

执行 shellcode 的核心就是：

```text
申请一段内存
  -> 把字节写进去
  -> 让线程从这段内存开始执行
```

---

## 二、句柄 Handle：Windows 对象的引用

### 2.1 什么是句柄

句柄是 Windows 给程序的一种“引用”。程序不用直接拿内核对象本体，而是拿一个句柄来操作它。

常见句柄：

| 类型 | 例子 |
|---|---|
| 进程句柄 | `OpenProcess` 返回 |
| 线程句柄 | `CreateThread` 返回 |
| 文件句柄 | `CreateFile` 返回 |
| 注册表键句柄 | `RegOpenKeyEx` 返回 |
| 窗口句柄 | `HWND` |
| 模块句柄 | `HMODULE` |

### 2.2 为什么要关闭句柄

打开句柄会占用系统资源。用完应关闭：

```csharp
[DllImport("kernel32.dll")]
static extern bool CloseHandle(IntPtr hObject);
```

如果不关闭，可能造成：

| 问题 | 影响 |
|---|---|
| 句柄泄漏 | 程序长期运行后资源耗尽 |
| 文件被占用 | 文件无法删除或覆盖 |
| 行为特征异常 | EDR 可能观察到异常句柄操作 |

### 2.3 句柄和权限

拿到句柄不代表能做所有事。打开进程时要请求权限：

```csharp
OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, false, pid)
```

常见权限：

| 权限 | 用途 |
|---|---|
| `PROCESS_VM_READ` | 读取目标进程内存 |
| `PROCESS_VM_WRITE` | 写目标进程内存 |
| `PROCESS_VM_OPERATION` | 在目标进程分配/释放内存 |
| `PROCESS_CREATE_THREAD` | 创建远程线程 |
| `PROCESS_QUERY_INFORMATION` | 查询目标进程信息 |

---

## 三、Win32 API 是 Windows 技术的公共语言

### 3.1 API 分布在哪些 DLL

| DLL | 主要功能 |
|---|---|
| `kernel32.dll` | 进程、线程、内存、文件 |
| `advapi32.dll` | 注册表、安全、服务、令牌 |
| `user32.dll` | 窗口、消息、键鼠 |
| `ntdll.dll` | Native API，更接近系统调用 |
| `ws2_32.dll` | 网络 socket |
| `shell32.dll` | ShellExecute、Shell 对象 |

### 3.2 A/W 后缀

很多 API 有两个版本：

| 后缀 | 含义 | 例子 |
|---|---|---|
| `A` | ANSI 字符串 | `MessageBoxA` |
| `W` | Unicode/Wide 字符串 | `MessageBoxW` |

C# 中常用：

```csharp
[DllImport("user32.dll", CharSet = CharSet.Auto)]
```

VBA 中常用：

```vba
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (...)
```

### 3.3 OSEP 高频 API

| 目标 | API |
|---|---|
| 当前进程内存执行 | `VirtualAlloc`、`VirtualProtect`、`CreateThread` |
| 远程进程注入 | `OpenProcess`、`VirtualAllocEx`、`WriteProcessMemory`、`CreateRemoteThread` |
| DLL 加载 | `LoadLibrary`、`GetProcAddress`、`GetModuleHandle` |
| 进程创建 | `CreateProcess` |
| 句柄清理 | `CloseHandle` |
| 注册表操作 | `RegOpenKeyEx`、`RegQueryValueEx`、`RegSetValueEx` |

---

## 四、托管代码、非托管代码与 P/Invoke

### 4.1 为什么这部分放在 Windows 概念里

Windows API 大多是非托管函数，而 OSEP 大量示例使用 C# 和 PowerShell。于是你会一直看到这个桥：

```text
C# / PowerShell 托管世界
  -> P/Invoke / Add-Type / 反射
  -> kernel32.dll / advapi32.dll 非托管世界
```

### 4.2 非托管代码

```text
C/C++ 源码
  -> 编译成机器码
  -> 操作系统加载执行
```

特点：

| 特点 | 说明 |
|---|---|
| 直接操作内存 | 指针、地址、缓冲区 |
| 手动资源管理 | `malloc/free`、`CloseHandle` |
| 更接近系统 | 可直接使用 Win32 API |
| 更容易崩溃 | 参数、指针、越界错误更危险 |

### 4.3 托管代码

```text
C# 源码
  -> IL
  -> CLR
  -> JIT
  -> 机器码
```

特点：

| 特点 | 说明 |
|---|---|
| 自动内存管理 | GC 负责对象释放 |
| 类型和元数据丰富 | 便于反射 |
| 默认更安全 | 不能随意操作裸指针 |
| 需要桥接底层 API | 用 P/Invoke、Marshal、反射 |

### 4.4 P/Invoke 例子

```csharp
using System;
using System.Runtime.InteropServices;

class Win32
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );
}
```

关键类型：

| 类型 | 用途 |
|---|---|
| `IntPtr` | 指针、地址、句柄 |
| `uint` | DWORD、标志位 |
| `bool` | Win32 BOOL 有时也用 `bool` 或 `int` |
| `Marshal` | 托管/非托管数据转换 |

---

## 五、WOW64：32 位与 64 位共存

### 5.1 WOW64 是什么

WOW64 是 Windows 在 64 位系统上运行 32 位程序的兼容层。

```text
32 位程序
  -> 32 位 ntdll.dll
  -> WOW64 转换层
  -> 64 位 ntdll.dll
  -> 64 位内核
```

核心组件：

| 组件 | 作用 |
|---|---|
| `wow64.dll` | 核心转换层 |
| `wow64win.dll` | GUI/Win32k 相关转换 |
| `wow64cpu.dll` | CPU 模式切换 |
| 32 位 `ntdll.dll` | 32 位用户态系统调用接口 |

### 5.2 System32 和 SysWOW64 的反直觉命名

| 目录 | 实际内容 |
|---|---|
| `C:\Windows\System32` | 64 位系统文件 |
| `C:\Windows\SysWOW64` | 32 位系统文件 |

32 位进程访问 `System32` 时，通常会被重定向到 `SysWOW64`。

### 5.3 注册表重定向

32 位程序访问：

```text
HKLM\SOFTWARE
```

可能实际看到：

```text
HKLM\SOFTWARE\WOW6432Node
```

### 5.4 为什么对 OSEP 重要

| 场景 | 影响 |
|---|---|
| Office 宏 | 32 位 Office 需要 x86 payload |
| PowerShell | 32 位 PowerShell 和 64 位 PowerShell 路径不同 |
| 进程注入 | 注入器和目标进程架构要匹配 |
| Mimikatz | 工具位数要匹配系统/目标进程 |
| 文件路径 | 32 位进程访问 System32 可能被重定向 |

快速检查：

```powershell
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
[IntPtr]::Size
```

详细内容见 [04-WOW64详解](/blog/osep/02-操作系统与编程理论/04-wow64详解/)。

---

## 六、注册表 Registry

### 6.1 注册表是什么

注册表是 Windows 的配置数据库。

常见根键：

| 根键 | 说明 |
|---|---|
| `HKCU` | 当前用户配置 |
| `HKLM` | 本机配置 |
| `HKCR` | 文件关联和 COM |
| `HKU` | 所有用户配置 |
| `HKCC` | 当前硬件配置 |

### 6.2 OSEP 高频位置

| 位置 | 用途 |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | 当前用户登录自启动 |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | 本机级自启动 |
| `HKLM\SYSTEM\CurrentControlSet\Services` | 服务配置 |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2` | AppLocker 策略 |
| `HKLM\SOFTWARE\Microsoft\AMSI\Providers` | AMSI Provider |
| `HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell` | PowerShell 策略 |

### 6.3 PowerShell 读取注册表

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" |
  Select-Object PSChildName, ImagePath, Start
```

详细内容见 [06-Windows注册表](/blog/osep/02-操作系统与编程理论/06-windows注册表/)。

---

## 七、Windows 安全机制总览

### 7.1 UAC 和完整性级别

完整性级别从低到高：

```text
Untrusted
Low
Medium
High
System
```

常见对应：

| 级别 | 场景 |
|---|---|
| Low | 浏览器沙箱、受保护模式 |
| Medium | 普通用户进程 |
| High | 管理员提升后的进程 |
| System | 系统服务、LocalSystem |

### 7.2 Defender、AMSI、脚本检测

| 机制 | 关注点 |
|---|---|
| Defender 实时保护 | 文件、进程、行为 |
| AMSI | PowerShell、VBA、JScript 等脚本内容扫描 |
| Script Block Logging | PowerShell 脚本块记录 |
| ETW | 事件跟踪，很多安全产品会使用 |

### 7.3 AppLocker/WDAC

AppLocker 规则类型：

| 类型 | 管控 |
|---|---|
| 可执行规则 | `.exe`、`.com` |
| 脚本规则 | `.ps1`、`.vbs`、`.js`、`.bat`、`.cmd` |
| DLL 规则 | `.dll`、`.ocx` |
| MSI 规则 | `.msi`、`.msp` |
| 打包应用规则 | Store/UWP 应用 |

规则条件：

```text
发布者
路径
文件哈希
```

相关章节：

| 机制 | 后续章节 |
|---|---|
| AV/Defender | `07-杀软绕过` |
| AMSI/CLM | `08-AMSI绕过` |
| AppLocker | `09-应用白名单绕过` |

---

## 八、进程注入基础模型

### 8.1 当前进程内执行

Office VBA 或 PowerShell runner 常见流程：

```text
VirtualAlloc
  -> Marshal.Copy 或 RtlMoveMemory
  -> CreateThread
```

含义：

| 步骤 | 说明 |
|---|---|
| 分配内存 | 给 shellcode 找一块地方 |
| 写入字节 | 把 payload 放进内存 |
| 创建线程 | 从 payload 地址开始执行 |

### 8.2 远程进程注入

标准远程注入流程：

```text
OpenProcess
  -> VirtualAllocEx
  -> WriteProcessMemory
  -> CreateRemoteThread
```

对应 API：

| 步骤 | API | 说明 |
|---|---|---|
| 打开进程 | `OpenProcess` | 获取目标进程句柄 |
| 远程分配 | `VirtualAllocEx` | 在目标进程分配内存 |
| 写入内存 | `WriteProcessMemory` | 写入 shellcode/DLL 路径 |
| 远程执行 | `CreateRemoteThread` | 在目标进程启动线程 |

### 8.3 为什么容易失败

| 现象 | 可能原因 |
|---|---|
| `OpenProcess` 失败 | 权限不足、目标受保护、PID 错误 |
| `VirtualAllocEx` 失败 | 句柄权限不够、参数错误 |
| `WriteProcessMemory` 失败 | 内存地址无效、权限不足 |
| 目标崩溃 | 架构不匹配、payload 错误 |
| 无回连 | 网络、监听器、出站限制、payload 类型不一致 |

详细内容见 `06-进程注入`。

---

## 九、从基础概念映射到后续章节

| 本篇概念 | 直接对应章节 |
|---|---|
| 进程、线程、内存 | `03-Office宏攻击`、`06-进程注入` |
| Win32 API | `03-Office宏攻击`、`05-反射式PowerShell`、`06-进程注入` |
| 托管/非托管 | `05-反射式PowerShell` |
| WOW64 | `03-Office宏攻击`、`06-进程注入`、`13-Windows凭证` |
| 注册表 | `09-应用白名单绕过`、权限维持、枚举 |
| AMSI/CLM | `08-AMSI绕过` |
| AppLocker | `09-应用白名单绕过` |
| 远程线程 | `06-进程注入` |

---

## 十、初学者排错口诀

遇到 Windows 执行链失败时，不要直接换 payload，按层排：

```text
1. 当前代码运行在哪个进程？
2. 当前进程是 32 位还是 64 位？
3. 当前用户权限是什么？
4. API 返回值是否成功？
5. 句柄权限是否足够？
6. 内存是否可写/可执行？
7. 线程是否真的创建？
8. 防护机制是否拦截？
9. 网络是否允许回连？
```

这个顺序会贯穿 Office、PowerShell、注入、横向移动和凭证章节。

---

## 十一、练习任务

### 练习 1：观察进程

1. 打开 Process Explorer。
2. 找到 `notepad.exe`。
3. 查看它的线程、句柄、模块。
4. 记录：PID、用户、完整性级别、加载的 DLL。

### 练习 2：判断架构

```powershell
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
[IntPtr]::Size
```

再分别启动 32 位和 64 位 PowerShell，比较结果。

### 练习 3：调用一个 Win32 API

用 C# 或 PowerShell `Add-Type` 调用 `MessageBoxA`，确认 P/Invoke 工作。

### 练习 4：注册表枚举

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

记录哪些项是用户级，哪些项是机器级。

### 练习 5：画出注入流程

不用看资料，手写：

```text
OpenProcess
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
```

并解释每一步为什么需要。

---

## 十二、复习清单

```text
□ 能解释进程、线程、虚拟内存的关系
□ 能解释句柄是什么，为什么要关闭
□ 能说出 kernel32、advapi32、user32、ntdll 的大致用途
□ 能解释 A/W API 后缀
□ 能解释托管代码如何调用非托管 Win32 API
□ 能解释 WOW64、System32、SysWOW64 的关系
□ 能说出几个 OSEP 高频注册表位置
□ 能区分 UAC、AMSI、AppLocker、Defender 的作用层面
□ 能复述当前进程执行和远程进程注入的区别
□ 能按排错口诀定位执行链失败层级
```

---

**下一节**：[03-面向对象编程基础](/blog/osep/02-操作系统与编程理论/03-面向对象编程基础/)
