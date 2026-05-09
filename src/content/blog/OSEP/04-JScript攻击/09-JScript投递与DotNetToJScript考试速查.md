---
title: OSEP-04-JScript投递与DotNetToJScript考试速查
description: '04-JScript攻击 | 09-JScript投递与DotNetToJScript考试速查'
pubDate: 2026-01-30T00:00:36+08:00
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

# JScript 投递与 DotNetToJScript 考试速查

## 对应课程范围

本文件对应 `3：wsh钓鱼.html` 中的 JScript Dropper、DotNetToJScript、C# Win32 API、C# Shellcode Runner、JScript Shellcode Runner、SharpShooter。

---

## JScript 的考试定位

JScript 是 Office/PowerShell 之外的客户端执行通道。它的价值在于：

| 价值 | 说明 |
|---|---|
| 换宿主 | 使用 `wscript.exe`、`cscript.exe`、`mshta.exe` 等脚本宿主 |
| 加载 .NET | 通过 DotNetToJScript 或 COM/反序列化思路触发 .NET 代码 |
| 绕开 PowerShell 入口 | PowerShell 被严控时的备选 |
| 组合 C# Loader | 把 C# Shellcode Runner 变成脚本投递 |

---

## 选择 JScript 的条件

| 条件 | 判断 |
|---|---|
| 脚本规则是否允许 | AppLocker 是否限制 `.js/.vbs/.hta` |
| WSH 是否启用 | `wscript/cscript` 是否可运行 |
| .NET 是否可用 | 目标 .NET 版本是否满足载荷 |
| AMSI 是否介入 | 现代脚本宿主可能触发内容扫描 |
| 代理是否需要 | 下载器是否使用系统代理 |

---

## DotNetToJScript 判断链

```
准备 C# 能力模块
  -> 编译成 .NET 程序集
  -> 转成 JScript 可触发形式
  -> 由脚本宿主执行
  -> .NET 代码在内存中运行
```

关键排查：

| 现象 | 排查 |
|---|---|
| 脚本双击无反应 | 默认宿主、脚本策略、错误窗口被隐藏 |
| 报 ActiveX/COM 错误 | 组件被禁、位数不匹配、系统策略 |
| .NET 入口不执行 | 构造函数/入口点、目标框架版本 |
| 本地成功目标失败 | AppLocker、AMSI、Defender、代理 |

---

## SharpShooter 使用思路

SharpShooter 的价值是快速生成脚本型投递器，但考试里要避免把它当黑盒：

| 你要理解 | 原因 |
|---|---|
| 生成的脚本宿主是什么 | 决定被 AppLocker 哪类规则限制 |
| 载荷是否 Staged | 决定网络和代理需求 |
| 是否依赖 PowerShell | 决定是否会撞 AMSI/CLM |
| 目标 .NET 版本 | 决定程序集能否运行 |
| 输出格式 | 决定投递方式和用户交互 |

---

## JScript 与 AppLocker 联动

| 限制 | 优先方向 |
|---|---|
| EXE 禁止但脚本允许 | JScript Dropper、HTA |
| 脚本也禁止 | 转向 DLL、MSI、InstallUtil、Workflow Compiler |
| PowerShell CLM | JScript + .NET Loader |
| MSHTA 可用 | HTA 包装 JScript |
| 第三方程序可运行 | 找脚本/插件/配置加载点 |

---

## 复习闭环

学完本主题后，至少能写出：

1. 一个 JScript Dropper 的执行流程。
2. DotNetToJScript 为什么能把 C# 能力放进脚本。
3. JScript 与 PowerShell 载体各自的检测面。
4. AppLocker 下什么时候选 JScript，什么时候不该选。
5. 失败时如何区分脚本宿主、.NET、AMSI、代理、位数问题。
