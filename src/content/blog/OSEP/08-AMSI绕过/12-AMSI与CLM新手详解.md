---
title: OSEP-08-AMSI与CLM新手详解
description: '08-AMSI绕过 | 12-AMSI与CLM新手详解'
pubDate: 2026-01-30T00:01:25+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# AMSI 与 CLM 新手详解

## 对应课程范围

本文件用于帮助初学者理解 AMSI、CLM、AppLocker/WDAC 的区别。源目录中 `8：windows防御机制绕过（amsi+clm）.html` 当前疑似重复导出 AV 内容，因此 AMSI/CLM 的复习以本目录为主。

---

## 一句话理解

```
AMSI 负责看内容
CLM 负责限制 PowerShell 能力
AppLocker/WDAC 负责限制什么能运行
```

这三者经常一起出现，但不是同一个问题。判断错了，就会在错误方向上浪费很多时间。

---

## 三者区别

| 机制 | 它管什么 | 常见现象 | 处理方向 |
|---|---|---|---|
| AMSI | 脚本内容、动态内容 | 报 malicious content | 混淆、绕过、换宿主、分段加载 |
| CLM | PowerShell 语言能力 | `Add-Type`、反射、COM 受限 | Custom Runspace、JScript、MSHTA、C# |
| AppLocker | 程序、脚本、DLL、MSI 是否能运行 | 策略阻止启动 | 枚举规则，找允许路径或可信加载点 |
| AV/EDR | 文件和行为 | 文件被删、进程被杀 | AV 决策树 |

---

## 正序学习路线

| 顺序 | 文件 | 学习目标 |
|---|---|---|
| 1 | `01-AMSI基础原理.md` | 理解 AMSI 在脚本执行链的位置 |
| 2 | `02-Intel架构与汇编基础.md` | 为二进制补丁做基础 |
| 3 | `03-WinDbg调试器使用指南.md`、`04-Frida动态追踪技术.md` | 学会观察和验证 |
| 4 | `05-AMSI绕过技术.md`、`06-AMSI二进制补丁绕过.md` | 理解不同绕过方式 |
| 5 | `07-AMSI绕过完整指南.md`、`08-JScript-AMSI绕过.md` | 扩展到完整链和脚本宿主 |
| 6 | `11-AMSI-CLM联动排错.md` | 处理 AMSI/CLM/AppLocker 联动 |
| 7 | `12-AMSI与CLM新手详解.md` | 用本页做初学者复盘 |

---

## 快速判断流程

1. 先运行 `$ExecutionContext.SessionState.LanguageMode`。
2. 如果是 `ConstrainedLanguage`，先按 CLM 处理。
3. 如果是 `FullLanguage`，再看是否出现 AMSI 报错。
4. 如果文件或脚本根本无法启动，检查 AppLocker/WDAC。
5. 如果执行后进程被杀，转 AV/EDR 排错。

---

## 常用状态检查

```powershell
$ExecutionContext.SessionState.LanguageMode
$PSVersionTable
Get-ExecutionPolicy -List
[Environment]::Is64BitProcess
```

```powershell
Get-AppLockerPolicy -Effective -Xml
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 5
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/MSI and Script" -MaxEvents 5
```

如果没有权限读取策略，也要记录错误本身。错误信息也是证据。

---

## AMSI 排错重点

| 问题 | 判断 |
|---|---|
| 绕过代码被拦 | 绕过字符串本身被签名 |
| 绕过后 payload 仍被拦 | 绕过未生效或只影响当前进程 |
| 下载时被拦 | 内容在进入执行前已经被扫描 |
| JScript 也被拦 | 脚本宿主也可能接入 AMSI |
| 只在目标失败 | 签名版本、PowerShell 版本、策略不同 |

---

## CLM 排错重点

| 受限内容 | 替代方向 |
|---|---|
| `Add-Type` | 纯反射、预编译 C#、JScript/.NET |
| 反射 | Custom Runspace、非 PowerShell 宿主 |
| COM | MSHTA、WMI、第三方程序 |
| 复杂 .NET 调用 | 可信 C# 加载点、InstallUtil、Workflow |
| 脚本块 | AppLocker 绕过路径 |

---

## OSEP 考试重点

| 重点 | 要求 |
|---|---|
| 先判断 | 不能把 AMSI、CLM、AppLocker 混为一谈 |
| 会取证 | 记录语言模式、报错、策略、绕过后结果 |
| 会切换 | CLM 下不要硬写 PowerShell，换宿主或加载点 |
| 会联动 | AMSI 解决内容，AppLocker 解决运行，AV 解决行为 |

---

## 复习自测

1. AMSI 和 AV 的区别是什么？
2. CLM 会让哪些 PowerShell 能力失效？
3. 为什么 AppLocker 可能导致 CLM？
4. FullLanguage 下报 malicious content 应该先处理什么？
5. CLM 下 `Add-Type` 失败时有哪些替代路径？
6. AMSI 绕过成功后仍无回连，下一步查什么？

---

## 交叉引用

| 主题 | 文件 |
|---|---|
| 联动排错 | `11-AMSI-CLM联动排错.md` |
| AV 排错 | `07-杀软绕过/12-AV绕过新手详解与实验闭环.md` |
| AppLocker | `09-应用白名单绕过/08-AppLocker新手详解与绕过地图.md` |
| 网络出站 | `10-网络过滤绕过/09-网络过滤新手详解与出网排错.md` |
