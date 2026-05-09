---
title: OSEP-04-JScript新手详解与投递闭环
description: '04-JScript攻击 | 10-JScript新手详解与投递闭环'
pubDate: 2026-01-30T00:00:37+08:00
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

# JScript 新手详解与投递闭环

## 对应课程范围

本文件对应 `3：wsh钓鱼.html`，用于把 JScript、WSH、DotNetToJScript、C# Shellcode Runner 和 SharpShooter 串成一条可学习的投递链。

JScript 在 OSEP 里不是为了学习浏览器 JavaScript，而是学习 Windows Script Host 下的脚本执行能力。

---

## 一句话理解

JScript 攻击链的本质是：

```
脚本宿主运行 .js
  -> JScript 创建 COM 对象或调用系统能力
  -> 下载、解码或加载 .NET 能力模块
  -> 执行命令、加载程序集或启动下一阶段
```

它常常是 Office/PowerShell 受限时的替代入口。

---

## 核心概念

| 概念 | 说明 | 初学者要掌握 |
|---|---|---|
| WSH | Windows Script Host，脚本宿主 | `wscript.exe` 有图形弹窗，`cscript.exe` 输出到控制台 |
| JScript Dropper | 用脚本下载或启动下一阶段 | 先能下载小文件，再考虑完整载荷 |
| ActiveXObject | JScript 调用 COM 的入口 | 常见对象包括 `WScript.Shell`、`MSXML2.XMLHTTP` |
| DotNetToJScript | 把 .NET 程序集包装成 JScript 可触发形式 | 重点理解思路，不要当黑盒 |
| C# Shellcode Runner | 由 C# 完成 Win32 API 调用和内存执行 | 要能解释 API 调用顺序 |
| SharpShooter | 自动生成脚本型投递器 | 考试里要理解生成结果的宿主和依赖 |

---

## 正序学习路线

| 顺序 | 文件 | 学习目标 |
|---|---|---|
| 1 | `01-Jscript基础.md`、`02-JScript完整指南.md` | 先学脚本执行、命令执行、下载文件 |
| 2 | `03-Jscript-Dropper.md` | 学会最小投递器 |
| 3 | `04-DotNetToJscript.md` | 理解 JScript 如何触发 .NET 代码 |
| 4 | `08-CSharp-ShellcodeRunner.md` | 理解 C# 能力模块本身 |
| 5 | `05-反射式加载.md` | 学习内存加载和少落地思路 |
| 6 | `06-SharpShooter工具.md` | 学会读懂自动生成器的输出 |
| 7 | `09-JScript投递与DotNetToJScript考试速查.md` | 用考试视角选 JScript 路径 |

---

## 最小实验闭环

1. 用 `WScript.Echo` 确认脚本宿主正常。
2. 用 `WScript.Shell` 执行 `whoami`，确认命令执行。
3. 用 `MSXML2.XMLHTTP` 下载一个小文本，确认出网。
4. 用 `ADODB.Stream` 保存测试文件，确认写权限。
5. 再替换为 DotNetToJScript 或 C# 加载器。

每一步都要保存输出。失败时只回退一步，不要同时改宿主、代码和 payload。

---

## 常用安全检查命令

```cmd
where wscript
where cscript
assoc .js
ftype JSFile
whoami
```

```powershell
Get-Command wscript.exe
Get-Command cscript.exe
$ExecutionContext.SessionState.LanguageMode
```

这些检查可以帮助判断：脚本宿主是否存在、默认打开方式是什么、PowerShell 是否也受限。

---

## JScript 与 PowerShell 的取舍

| 场景 | 优先选择 |
|---|---|
| PowerShell FullLanguage 且 AMSI 可处理 | PowerShell 反射更直接 |
| PowerShell CLM | JScript、MSHTA、DotNetToJScript |
| 脚本规则允许 `.js` | JScript Dropper |
| `.js` 被拦但 HTA 可运行 | MSHTA |
| .NET 版本满足 | DotNetToJScript 或 C# 程序集 |
| AppLocker 脚本规则严格 | 转 DLL、MSI、第三方加载点 |

---

## 常见失败与排错

| 现象 | 排查 |
|---|---|
| 双击没有反应 | 默认宿主、文件关联、错误窗口是否被隐藏 |
| `ActiveXObject` 报错 | COM 被禁、对象名写错、策略限制 |
| 下载失败 | 代理、DNS、TLS、认证、URL 分类 |
| 写文件失败 | 路径权限、杀软删除、Mark-of-the-Web |
| DotNetToJScript 不执行 | .NET 版本、入口构造函数、位数、脚本被 AMSI |
| 本地成功目标失败 | AppLocker、Defender、语言环境、代理差异 |

---

## OSEP 考试重点

| 重点 | 你要能解释 |
|---|---|
| WSH | `wscript` 和 `cscript` 的差别 |
| DotNetToJScript | 为什么可以把 C# 能力包装成脚本 |
| 检测面 | JScript、PowerShell、HTA 各自容易被什么拦 |
| 替代路径 | PowerShell 被限制后，为什么考虑 JScript |
| 排错顺序 | 宿主、COM、.NET、网络、策略分别怎么排 |

---

## 复习自测

1. JScript 和浏览器 JavaScript 有什么区别？
2. `WScript.Shell` 能做什么？
3. `MSXML2.XMLHTTP` 和 `ADODB.Stream` 在 Dropper 里分别负责什么？
4. DotNetToJScript 依赖什么运行环境？
5. 为什么 SharpShooter 不能只当黑盒？
6. JScript 被 AppLocker 拦时，你会转向哪几个方向？

---

## 交叉引用

| 主题 | 文件 |
|---|---|
| JScript 考试速查 | `09-JScript投递与DotNetToJScript考试速查.md` |
| 客户端初始访问 | `03-Office宏攻击/15-客户端初始访问考试速查.md` |
| 客户端反射联动 | `05-反射式PowerShell/06-客户端反射代码攻击联动.md` |
| AMSI/CLM | `08-AMSI绕过/11-AMSI-CLM联动排错.md` |
| AppLocker | `09-应用白名单绕过/07-MSHTA-XSL与第三方执行.md` |
