---
title: OSEP-08-AMSI基础原理
description: '08-AMSI绕过 | 01-AMSI基础原理'
pubDate: 2026-01-30T00:01:14+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# AMSI 基础原理

---

## 【Claude的学习建议】

> **AMSI绕过是OSEP考试的必考内容！**
>
> 这章非常重要，因为：
> 1. 现代Windows默认启用AMSI
> 2. 几乎所有PowerShell攻击都会被AMSI拦截
> 3. 不绕过AMSI，很多攻击技术都无法使用
>
> **学习目标**：
> - 理解AMSI是什么，为什么它能拦截你的攻击
> - 理解AMSI的工作流程
> - 为后面学习绕过技术打下基础
>
> **给零基础同学的话**：
> AMSI就像是Windows里的"安检员"，你执行的每一条PowerShell命令都要经过它检查。
> 我们的目标是让这个"安检员"失效。

---

## 什么是 AMSI

AMSI（Antimalware Scan Interface，反恶意软件扫描接口）是 Microsoft 在 Windows 10 中引入的一套 API，允许杀软产品在运行时检查 PowerShell 命令和脚本，即使它们从未写入磁盘。

> 【Claude的通俗解释】
>
> **AMSI是什么？用最简单的话说：**
>
> ```
> 以前的杀软：
> ├── 只检查硬盘上的文件
> ├── 你下载一个病毒.exe → 杀软扫描 → 发现病毒 → 删除
> └── 但如果代码直接在内存里运行，杀软看不到！
>
> 攻击者的对策：
> ├── 不把恶意代码存到硬盘
> ├── 直接用PowerShell下载并在内存中执行
> └── 杀软：？？？我什么都没看到啊
>
> 微软的解决方案 - AMSI：
> ├── 在PowerShell内部安装一个"监控器"
> ├── 你输入的每一条命令都会被发送给杀软检查
> ├── 即使代码不落地，也能被检测到
> └── 攻击者：我的PowerShell攻击全被拦截了！
> ```
>
> **一句话总结**：AMSI让杀软能够检查"内存中执行的代码"

### 引入背景

传统杀软主要扫描文件系统中的文件，但攻击者可以：
- 直接在内存中下载和执行代码
- 使用 PowerShell 等脚本语言执行恶意操作
- 避免将恶意代码写入磁盘

AMSI 解决了这个"内存执行"的检测盲区。

## AMSI 支持的组件

| 组件 | 支持版本 |
|------|----------|
| PowerShell | Windows 10 起 |
| JScript/VBScript | 后续添加 |
| VBA 宏 | Office 2019 起 |
| .NET | .NET Framework 4.8 起 |

## AMSI 架构概述

```
┌─────────────────────────────────────────────────────────────┐
│                    PowerShell 进程                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    AMSI.DLL                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │AmsiInitialize│  │AmsiScanBuffer│  │AmsiCloseSession│ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│                           │ RPC                              │
│                           ↓                                  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   Windows Defender                           │
│                   (或其他支持 AMSI 的杀软)                    │
└─────────────────────────────────────────────────────────────┘
```

## AMSI 工作流程

> 【Claude的深入解析】
>
> **理解AMSI的工作流程是绕过它的关键！**
>
> 当你在PowerShell中输入一条命令时，发生了什么？
>
> ```
> 你输入: IEX (New-Object Net.WebClient).DownloadString('http://...')
>
>     ↓ 1. PowerShell接收到命令
>
> PowerShell: "等等，我要先让AMSI检查一下"
>
>     ↓ 2. 调用AmsiScanBuffer()
>
> AMSI.DLL: "好的，我把这段代码发给杀软"
>
>     ↓ 3. 通过RPC发送给Windows Defender
>
> Windows Defender: "让我看看... 这是Invoke-Mimikatz！恶意代码！"
>
>     ↓ 4. 返回结果: AMSI_RESULT_DETECTED (32768)
>
> PowerShell: "杀软说这是恶意代码，我不执行了"
>
>     ↓ 5. 显示错误
>
> 你看到: "此脚本包含恶意内容，已被阻止"
> ```
>
> **绕过的思路**：
> - 让AmsiScanBuffer()不被调用
> - 或者让它返回"干净"的结果
> - 或者让AMSI.DLL根本不加载

### 1. 初始化阶段

当 PowerShell 启动时：

```
1. 加载 AMSI.DLL
   ↓
2. 调用 AmsiInitialize()
   ↓
3. 创建 AMSI 上下文结构
```

### 2. 扫描阶段

当执行命令时：

```
1. 调用 AmsiOpenSession()
   ↓
2. 调用 AmsiScanBuffer() 或 AmsiScanString()
   ↓
3. 通过 RPC 发送到 Windows Defender
   ↓
4. 接收扫描结果
   ↓
5. 调用 AmsiCloseSession()
```

## AMSI 核心 API

### AmsiInitialize

```c
HRESULT AmsiInitialize(
    LPCWSTR      appName,        // 应用程序名称
    HAMSICONTEXT *amsiContext    // 输出：上下文结构指针
);
```

**说明**：
- 在 PowerShell 启动时调用
- 在我们能执行任何命令之前完成
- 无法通过 PowerShell 命令影响

### AmsiOpenSession

```c
HRESULT AmsiOpenSession(
    HAMSICONTEXT amsiContext,    // 上下文结构
    HAMSISESSION *amsiSession    // 输出：会话结构指针
);
```

**说明**：
- 为每次扫描创建会话
- 会话结构用于后续 API 调用

### AmsiScanBuffer

```c
HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,    // 上下文结构
    PVOID        buffer,         // 要扫描的缓冲区
    ULONG        length,         // 缓冲区长度
    LPCWSTR      contentName,    // 内容标识符
    HAMSISESSION amsiSession,    // 会话结构
    AMSI_RESULT  *result         // 输出：扫描结果
);
```

**说明**：
- 核心扫描函数
- 将缓冲区内容发送给杀软分析
- 返回扫描结果

### AmsiScanString

```c
HRESULT AmsiScanString(
    HAMSICONTEXT amsiContext,
    LPCWSTR      string,         // 要扫描的字符串
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result
);
```

**说明**：
- 扫描字符串内容
- 已被 AmsiScanBuffer 取代（存在绕过漏洞）

### AmsiCloseSession

```c
HRESULT AmsiCloseSession(
    HAMSICONTEXT amsiContext,
    HAMSISESSION amsiSession
);
```

**说明**：
- 关闭扫描会话
- 在扫描结果返回后调用

## AMSI_RESULT 枚举

```c
typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN                  = 0,      // 干净
    AMSI_RESULT_NOT_DETECTED           = 1,      // 未检测到威胁
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,  // 被管理员阻止
    AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 20479,
    AMSI_RESULT_DETECTED               = 32768   // 检测到恶意软件
} AMSI_RESULT;
```

**关键值**：
- `1` = 扫描通过（干净）
- `32768` = 检测到恶意软件

## AMSI 支持的杀软

截至课程编写时，只有约 11 家杀软厂商支持 AMSI：

- Windows Defender（微软自带）
- Avira
- AVG
- Bitdefender
- ESET
- F-Secure
- Kaspersky
- Norton
- Sophos
- Trend Micro
- 等

**注意**：AMSI 于 2015 年随 Windows 10 发布，第三方采用率并不高。

## AMSI 的局限性

1. **仅限 Windows 10+** - 旧版 Windows 不支持
2. **需要杀软支持** - 未支持的杀软无法利用 AMSI
3. **可被绕过** - 存在多种绕过技术
4. **性能开销** - 每次命令都需要扫描

## 为什么需要绕过 AMSI

> 【Claude的实战说明】
>
> **没有AMSI绕过，你的攻击寸步难行！**
>
> 试试在PowerShell中执行这个：
> ```powershell
> 'Invoke-Mimikatz'
> ```
> 即使只是一个字符串，也会被AMSI拦截！
>
> **AMSI会拦截的东西**：
> - 任何包含已知恶意特征的字符串
> - 混淆后的代码（AMSI在解混淆后扫描）
> - 从网络下载的脚本
> - 反射加载的.NET程序集
>
> **绕过AMSI后你能做什么**：
> - 执行Mimikatz提取密码
> - 运行PowerShell Empire
> - 使用各种PowerShell攻击工具
> - 执行自定义的shellcode runner

在渗透测试中，AMSI 会阻止：

1. **PowerShell 攻击脚本**
   - Invoke-Mimikatz
   - PowerShell Empire
   - 自定义 shellcode runner

2. **内存执行技术**
   - 反射加载
   - 进程注入
   - 无文件攻击

3. **混淆后的代码**
   - AMSI 在解混淆后扫描
   - 传统混淆技术失效

## 下一步

了解 AMSI 原理后，继续学习 [02-Intel架构与汇编基础.md](/blog/osep/08-amsi绕过/02-intel架构与汇编基础/)，掌握分析 AMSI 所需的汇编知识。
