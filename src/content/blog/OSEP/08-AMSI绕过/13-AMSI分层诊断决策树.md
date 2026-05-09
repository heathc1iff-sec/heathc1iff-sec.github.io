---
title: OSEP-08-AMSI分层诊断决策树
description: '08-AMSI绕过 | 13-AMSI分层诊断决策树'
pubDate: 2026-01-30T00:01:26+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# AMSI 分层诊断决策树

## 先确认是不是 AMSI

不是所有 PowerShell 失败都是 AMSI。先按现象判断：

| 现象 | 更像 |
|---|---|
| `This script contains malicious content` | AMSI |
| `Cannot invoke method. Method invocation is supported only on core types` | CLM |
| 程序被策略阻止 | AppLocker/WDAC |
| 文件被删 | AV/Defender |
| 执行后无回连 | 网络或 payload 配置 |

---

## AMSI、Defender、日志、CLM 的区别

| 机制 | 作用 | 处理方式 |
|---|---|---|
| AMSI | 扫描脚本内容 | 内容绕过、补丁、换宿主 |
| Defender/AV | 文件和行为检测 | AV 绕过 |
| ScriptBlock Logging | 记录脚本内容 | 日志规避和 OPSEC |
| CLM | 限制语言能力 | 换执行能力 |
| AppLocker | 限制运行对象 | 白名单绕过 |

---

## PowerShell 字符串被拦时怎么判断

1. 先运行无害命令确认 PowerShell 正常。
2. 再逐段执行脚本。
3. 找出触发 AMSI 的字符串或逻辑。
4. 判断是 bypass 本身被拦，还是 payload 被拦。
5. 只在当前 PowerShell 进程内验证绕过是否生效。

---

## 反射加载失败时怎么判断

| 失败点 | 判断 |
|---|---|
| 类型找不到 | .NET/PowerShell 版本问题 |
| 委托创建失败 | 参数类型或调用约定问题 |
| 脚本内容被拦 | AMSI |
| `Add-Type` 不可用 | CLM |
| 执行后被杀 | AV/EDR |

---

## Patch 生效但仍失败的原因

| 原因 | 说明 |
|---|---|
| 补丁只在当前进程生效 | 新进程仍会触发 AMSI |
| payload 被 AV 行为检测 | AMSI 不是唯一防护 |
| 脚本在下载阶段被拦 | 内容进入执行前已被扫描 |
| 位数不匹配 | x86/x64 PowerShell 加载不同 |
| 补丁地址错误 | 版本差异或函数定位错误 |

---

## 32 位和 64 位 PowerShell 的影响

| 项目 | 影响 |
|---|---|
| `amsi.dll` | x86/x64 进程各自加载 |
| shellcode | 必须匹配进程架构 |
| 调试器 | WinDbg/Frida 要 attach 到正确进程 |
| Office | 32 位 Office 可能启动 32 位 PowerShell |

---

## JScript AMSI 与 PowerShell AMSI

| 项目 | PowerShell | JScript/WSH |
|---|---|---|
| 常见检测 | 脚本块、下载内容、IEX | 脚本内容、ActiveX、加载器 |
| 常见绕过 | 补丁、混淆、反射 | 换宿主、混淆、DotNetToJScript |
| 常见误区 | 以为绕过一次全局生效 | 以为 JScript 一定不走 AMSI |

---

## 和 AppLocker/CLM 的边界

如果语言模式是 `ConstrainedLanguage`，不要继续只处理 AMSI。CLM 下很多反射、COM、Add-Type 能力会直接受限，需要转到 AppLocker/CLM 绕过路线。

---

## 排错记录模板

| 项目 | 记录 |
|---|---|
| PowerShell 版本 |  |
| 位数 |  |
| LanguageMode |  |
| 报错文本 |  |
| 是否确认 AMSI |  |
| 绕过方式 |  |
| 绕过后测试命令 |  |
| 下一步 |  |
