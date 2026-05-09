---
title: OSEP-08-AMSI-CLM联动排错
description: '08-AMSI绕过 | 11-AMSI-CLM联动排错'
pubDate: 2026-01-30T00:01:24+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# AMSI 与 CLM 联动排错

## 为什么要放在一起看

AMSI 和 CLM 经常同时出现，但它们不是一回事：

| 机制 | 作用 |
|---|---|
| AMSI | 扫描脚本内容和动态执行内容 |
| CLM | 限制 PowerShell 语言能力 |
| AppLocker/WDAC | 决定程序、脚本、DLL 是否允许运行 |

AMSI 像内容审查，CLM 像语法能力阉割，AppLocker 像门禁。考试里要先判断是哪一层在拦你。

---

## 和源资料的关系

`web` 目录中第 8 个 HTML 的文件名标注 AMSI/CLM，但当前导出内容疑似与 AV 绕过章节重复。复习 AMSI/CLM 时，以本目录的 AMSI 原理、调试、补丁、JScript AMSI 和本页排错链为准；第 8 个 HTML 暂时只作为“待核对源资料”记录在课程映射表中。

---

## 快速判断

| 现象 | 更像 |
|---|---|
| 报 `This script contains malicious content` | AMSI |
| `$ExecutionContext.SessionState.LanguageMode` 是 `ConstrainedLanguage` | CLM |
| `Add-Type`、反射、COM 报受限 | CLM |
| 文件无法启动，提示策略阻止 | AppLocker/WDAC |
| JScript/HTA 也被拦内容 | AMSI 或脚本策略 |

---

## 先收集四个状态

| 状态 | 命令/证据 | 用途 |
|---|---|---|
| PowerShell 语言模式 | `$ExecutionContext.SessionState.LanguageMode` | 判断是否 CLM |
| PowerShell 版本 | `$PSVersionTable` | 判断绕过方式和日志能力差异 |
| AppLocker/WDAC 线索 | 策略提示、事件日志、可运行目录 | 判断是否策略导致 CLM |
| AMSI 报错文本 | 报错截图或完整错误 | 判断是内容扫描还是语法/权限问题 |

---

## 处理顺序

```
先检查语言模式
  -> 如果 CLM，别急着修 AMSI，先换执行能力
  -> 如果 FullLanguage，再处理 AMSI 内容
  -> 如果程序被策略阻止，转 AppLocker
  -> 如果都通过但行为被杀，转 AV 绕过
```

---

## 三层判别流程

| 第一问 | 如果是 | 下一步 |
|---|---|---|
| 内容是否被判恶意 | AMSI | 先做内容层处理：拆字符串、编码、换 bypass、换宿主 |
| 语言能力是否受限 | CLM | 不要继续堆 AMSI 绕过，优先换执行能力或 Custom Runspace |
| 程序/脚本是否被策略拦 | AppLocker/WDAC | 枚举规则，找 Trusted Folder、MSHTA/XSL、InstallUtil、Workflow、第三方加载点 |
| 以上都不是 | AV/EDR 或网络 | 转 AV 决策树或出网受限决策树 |

---

## AMSI 排错

| 问题 | 排查 |
|---|---|
| 绕过代码本身被拦 | 字符串拆分、编码、换绕过方式 |
| 绕过成功但后续脚本被拦 | 绕过只影响当前进程或未真正生效 |
| 远程加载失败 | 内容在下载/执行前被扫描 |
| JScript 路线也被拦 | AMSI 可能覆盖脚本宿主 |
| 只在目标失败 | 签名更新、PowerShell 版本、日志策略 |

---

## CLM 排错

| 受限能力 | 替代方向 |
|---|---|
| `Add-Type` 不可用 | 纯反射、换宿主、C# 预编译 |
| 反射不可用 | Custom Runspace、JScript/.NET、MSHTA |
| COM 不可用 | WMI、WinRM、第三方程序 |
| .NET 方法受限 | 转向非 PowerShell 路径 |
| 脚本块受限 | AppLocker 绕过或可信程序加载 |

---

## AppLocker 联动

CLM 很多时候是 AppLocker/WDAC 强制出来的。判断：

| 检查 | 目的 |
|---|---|
| AppLocker 事件日志 | 确认被哪个规则阻止 |
| 可运行目录 | 找 Trusted Folder |
| 脚本规则 | 判断 JScript/HTA 是否可用 |
| DLL 规则 | 判断 DLL 劫持是否可用 |
| MSI/InstallUtil | 找白名单执行器 |

---

## 常见组合场景

| 场景 | 判断 | 处理 |
|---|---|---|
| FullLanguage 但脚本报恶意内容 | 典型 AMSI | 先绕 AMSI 或换内容表达，再执行反射加载 |
| CLM 且 `Add-Type`/反射失败 | 语言能力受限 | 换 Custom Runspace、JScript/.NET、MSHTA、可信 C# 加载 |
| CLM 同时脚本文件无法运行 | 策略和语言双限制 | 进入 AppLocker，找 DLL/MSI/第三方程序加载点 |
| AMSI 绕过成功但 payload 仍被杀 | AMSI 不是唯一拦截层 | 转 `07-杀软绕过/11-AV绕过决策树.md` |
| 能执行但不能回连 | 不是 AMSI/CLM 主问题 | 转 `10-网络过滤绕过/08-出网受限决策树.md` |

---

## 考试决策表

| 当前状态 | 下一步 |
|---|---|
| PowerShell FullLanguage + AMSI 拦 | AMSI 绕过、混淆、反射加载 |
| PowerShell CLM | Custom Runspace、JScript、MSHTA、C# 可信加载 |
| PowerShell 不可用 | JScript/HTA/XSL/InstallUtil/Workflow |
| 脚本也不可用 | DLL、MSI、第三方程序加载点 |
| 执行都可用但回连失败 | 网络过滤绕过 |

---

## 和其他章节联动

| 如果卡在 | 跳转 |
|---|---|
| Office/JScript 初始入口不稳定 | `03-Office宏攻击/15-客户端初始访问考试速查.md` |
| 反射加载方式选择困难 | `05-反射式PowerShell/06-客户端反射代码攻击联动.md` |
| 文件或执行行为被杀 | `07-杀软绕过/11-AV绕过决策树.md` |
| 策略白名单限制 | `09-应用白名单绕过/07-MSHTA-XSL与第三方执行.md` |
| 网络出不去 | `10-网络过滤绕过/08-出网受限决策树.md` |

---

## 证据记录

| 证据 | 为什么 |
|---|---|
| 语言模式输出 | 证明 CLM 状态 |
| 拦截错误信息 | 区分 AMSI/策略/行为检测 |
| AppLocker 规则或事件 | 证明策略限制 |
| 绕过后执行结果 | 证明影响 |
