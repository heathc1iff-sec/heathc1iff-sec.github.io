---
title: OSEP-05-反射式PowerShell新手详解
description: '05-反射式PowerShell | 07-反射式PowerShell新手详解'
pubDate: 2026-01-30T00:00:46+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
  - PowerShell
---

# 反射式 PowerShell 新手详解

## 对应课程范围

本文件对应 `4：反射式powershell.html` 和 `5：客户端反射代码攻击.html` 的 PowerShell 反射部分。

反射式 PowerShell 是 OSEP 前半段的核心，因为它把 PowerShell、.NET、Win32 API 和内存执行连在一起。

---

## 一句话理解

反射式 PowerShell 的本质是：

```
不写 C# 源码
  -> 直接从已加载 .NET 程序集中找类型
  -> 解析 Win32 API 地址
  -> 动态创建委托
  -> 调用底层函数完成内存操作
```

它的目标不是“神奇免杀”，而是减少编译、减少落地、绕开某些语言或文件限制。

---

## 为什么要避免 Add-Type

`Add-Type` 很方便，但它常见问题很多：

| 问题 | 说明 |
|---|---|
| 需要编译 | 可能调用编译链路，留下临时文件和进程痕迹 |
| 受 CLM 影响 | Constrained Language Mode 下经常不可用 |
| 内容容易被扫 | C# 源码、API 名、关键字符串都可能被 AMSI 扫描 |
| 不够灵活 | 目标机器环境不同，编译和引用可能失败 |

反射路线就是尽量使用当前进程已经有的 .NET 能力完成调用。

---

## 核心概念

| 概念 | 说明 | 你要掌握 |
|---|---|---|
| Assembly | .NET 程序集 | PowerShell 本身就加载了很多程序集 |
| Type | .NET 类型 | 通过类型找到内部方法 |
| UnsafeNativeMethods | .NET 内部可用的 Native API 辅助类 | 可用于查找 Win32 API 地址 |
| GetModuleHandle | 获取已加载模块句柄 | 找到 `kernel32.dll` 等模块 |
| GetProcAddress | 获取函数地址 | 找到 `VirtualAlloc` 等函数入口 |
| Delegate | 委托 | 把函数地址包装成 PowerShell 可调用对象 |
| Marshal | .NET 互操作能力 | 把指针转换成委托 |

---

## 正序学习路线

| 顺序 | 文件 | 学习目标 |
|---|---|---|
| 1 | `01-PowerShell与Win32API.md` | 理解 PowerShell 如何接触 Win32 API |
| 2 | `02-下载摇篮技术.md` | 理解下载、执行和代理问题 |
| 3 | `03-反射技术进阶.md` | 掌握类型查找、委托、API 地址解析 |
| 4 | `04-完整反射实现.md` | 串起完整 shellcode runner |
| 5 | `06-客户端反射代码攻击联动.md` | 放回 Office/JScript 客户端场景 |
| 6 | `07-反射式PowerShell新手详解.md` | 用本页做初学者复盘 |

---

## 反射调用的步骤

| 步骤 | 目的 | 常见错误 |
|---|---|---|
| 找程序集 | 找到可复用的 .NET 类型 | 类型名写错，版本差异 |
| 找类型 | 定位内部辅助类 | 目标 PowerShell/.NET 版本不同 |
| 找方法 | 获取 `GetModuleHandle`、`GetProcAddress` | 方法签名不匹配 |
| 创建委托 | 让 PowerShell 能调用函数指针 | 参数类型、返回值类型错误 |
| 分配内存 | 给 payload 准备空间 | 权限错误、大小错误 |
| 写入并执行 | 复制字节并启动线程 | 架构不匹配、内存保护错误 |

---

## 常用环境判断

```powershell
$PSVersionTable
$ExecutionContext.SessionState.LanguageMode
[Environment]::Is64BitProcess
[Environment]::Is64BitOperatingSystem
[AppDomain]::CurrentDomain.GetAssemblies() | Select-Object -First 5
```

这些命令帮助你判断 PowerShell 版本、语言模式、进程位数和已加载程序集。

---

## 常见失败与排错

| 现象 | 排查 |
|---|---|
| 类型找不到 | .NET 版本、程序集是否加载、类型全名 |
| 委托创建失败 | 参数类型、返回类型、调用约定 |
| `AccessViolation` | 指针大小、API 声明、shellcode 架构 |
| AMSI 报恶意内容 | 字符串、下载内容、绕过是否当前进程生效 |
| CLM 下失败 | 语言能力限制，转 Custom Runspace 或非 PowerShell |
| 本地成功目标失败 | PowerShell 版本、AV、代理、位数 |

---

## OSEP 考试重点

| 重点 | 要求 |
|---|---|
| 能画出流程 | Assembly -> Type -> Method -> Delegate -> Win32 API |
| 能解释失败 | 不是看到红字就换 payload，要判断是类型、AMSI、CLM 还是位数 |
| 能和客户端结合 | Office/JScript 只是入口，反射是加载层 |
| 能降级测试 | 先测试类型查找，再测试内存分配，再测试完整执行 |

---

## 复习自测

1. `Add-Type` 为什么方便但危险？
2. `GetModuleHandle` 和 `GetProcAddress` 分别做什么？
3. 委托为什么能调用函数指针？
4. CLM 会影响哪些 PowerShell 能力？
5. x86 PowerShell 调 x64 shellcode 会发生什么？
6. 反射加载被 AMSI 拦时，下一步怎么判断？

---

## 交叉引用

| 主题 | 文件 |
|---|---|
| 客户端反射联动 | `06-客户端反射代码攻击联动.md` |
| Office 入口 | `03-Office宏攻击/16-Office宏攻击新手详解与考试闭环.md` |
| JScript 入口 | `04-JScript攻击/10-JScript新手详解与投递闭环.md` |
| AMSI/CLM | `08-AMSI绕过/11-AMSI-CLM联动排错.md` |
| 进程注入 | `06-进程注入/09-进程注入新手详解与排错.md` |
