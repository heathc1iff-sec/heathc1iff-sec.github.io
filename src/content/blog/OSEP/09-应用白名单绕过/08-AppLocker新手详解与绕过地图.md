---
title: OSEP-09-AppLocker新手详解与绕过地图
description: '09-应用白名单绕过 | 08-AppLocker新手详解与绕过地图'
pubDate: 2026-01-30T00:01:35+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# AppLocker 新手详解与绕过地图

## 对应课程范围

本文件对应 `9：windows防御机制绕过（应用程序白名单：applocker).html`，用于把 AppLocker、CLM、MSHTA、XSL、第三方执行和 C# 加载点串成初学者地图。

---

## 一句话理解

AppLocker 的本质是：

```
规则决定什么能运行
  -> 你枚举规则
  -> 找到允许的文件类型、路径、签名或程序
  -> 让可信程序加载你可控的内容
```

它不是“记一个 LOLBin 命令”，而是规则枚举和加载点分析。

---

## AppLocker 管什么

| 类型 | 说明 | 常见绕过思路 |
|---|---|---|
| EXE | 可执行文件 | Trusted Folder、签名程序、第三方程序 |
| Script | `.ps1`、`.js`、`.vbs`、`.hta` 等 | MSHTA、JScript、XSL、换宿主 |
| DLL | 动态链接库 | DLL 搜索顺序、插件目录 |
| MSI | 安装包 | MSI/InstallUtil 相关路径 |
| Packaged app | 商店应用 | 一般不是 OSEP 主线 |

---

## 正序学习路线

| 顺序 | 文件 | 学习目标 |
|---|---|---|
| 1 | `01-AppLocker基础与绕过完整指南.md` | 理解规则类型、默认规则、可信路径、DLL、LOLBAS 和 CLM |
| 2 | `02-基础绕过技术.md` | 对主文档中的绕过思路做补充复习 |
| 3 | `02-基础绕过技术.md`、`03-InstallUtil绕过详解.md` | 掌握常见执行器 |
| 4 | `04-PowerShell绕过.md`、`05-Workflow-Compiler绕过详解.md` | 理解 CLM 和编译路径 |
| 5 | `07-MSHTA-XSL与第三方执行.md` | 学 MSHTA、XSL、第三方加载点 |
| 6 | `08-AppLocker新手详解与绕过地图.md` | 用本页做综合复盘 |

---

## 枚举顺序

| 顺序 | 要查什么 | 为什么 |
|---|---|---|
| 1 | 当前用户身份和组 | 规则可能按用户/组应用 |
| 2 | 哪些文件类型被限制 | 决定走 EXE、脚本、DLL 还是 MSI |
| 3 | 允许路径 | Trusted Folder 是最直接的机会 |
| 4 | 允许签名 | 找被信任的厂商程序 |
| 5 | 可写目录 | 判断能否放置脚本、DLL、配置 |
| 6 | PowerShell 语言模式 | 判断是否 CLM |
| 7 | 日志事件 | 确认到底被哪条规则拦 |

---

## 常用检查命令

```powershell
whoami
whoami /groups
$ExecutionContext.SessionState.LanguageMode
Get-AppLockerPolicy -Effective -Xml
```

```powershell
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 10
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/MSI and Script" -MaxEvents 10
```

```cmd
icacls C:\Windows\Tasks
icacls C:\Users\Public
where mshta
where installutil
```

---

## 绕过方向地图

| 发现 | 优先方向 |
|---|---|
| 某个允许路径可写 | Trusted Folder 放置载荷 |
| EXE 被禁但脚本允许 | JScript、HTA、MSHTA |
| 脚本被禁但 DLL 宽松 | DLL 搜索顺序、第三方 DLL 加载 |
| PowerShell CLM | Custom Runspace、JScript/.NET、MSHTA |
| MSI/InstallUtil 可用 | InstallUtil、MSI 执行链 |
| 第三方程序可运行 | 反编译找配置、插件、DLL、程序集加载点 |
| 只能出网不能落地 | 远程脚本、内存加载，但要考虑 AMSI |

---

## 常见失败与排错

| 现象 | 排查 |
|---|---|
| 文件无法启动 | 规则类型、路径、签名、事件日志 |
| PowerShell 变 CLM | AppLocker/WDAC 是否强制语言模式 |
| MSHTA 启动但脚本不执行 | 脚本规则、AMSI、HTA 格式 |
| DLL 放了但不加载 | 搜索顺序、位数、导出函数、权限 |
| 第三方程序没触发加载点 | 参数、配置路径、版本差异 |
| 绕过后被杀 | 转 AV/AMSI |

---

## OSEP 考试重点

| 重点 | 要求 |
|---|---|
| 能读规则 | 不要只凭感觉猜 |
| 能找允许面 | 路径、签名、文件类型、用户组 |
| 能找可控输入 | 配置、插件、DLL、XSL、脚本、参数 |
| 能解释 CLM | CLM 不是 AMSI，它是语言能力限制 |
| 能记录证据 | 规则、事件、可写路径、执行结果 |

---

## 复习自测

1. AppLocker 的 EXE、Script、DLL 规则有什么区别？
2. 为什么可写的允许路径很危险？
3. CLM 和 AppLocker 有什么关系？
4. MSHTA/XSL 属于什么类型的绕过思路？
5. 第三方程序加载点应该怎么找？
6. 事件日志能帮你确认什么？

---

## 交叉引用

| 主题 | 文件 |
|---|---|
| MSHTA/XSL | `07-MSHTA-XSL与第三方执行.md` |
| AMSI/CLM | `08-AMSI绕过/12-AMSI与CLM新手详解.md` |
| AV | `07-杀软绕过/12-AV绕过新手详解与实验闭环.md` |
| 反射加载 | `05-反射式PowerShell/07-反射式PowerShell新手详解.md` |
