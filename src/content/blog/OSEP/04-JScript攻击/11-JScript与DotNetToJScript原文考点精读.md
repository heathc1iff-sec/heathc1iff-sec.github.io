---
title: OSEP-04-JScript与DotNetToJScript原文考点精读
description: '04-JScript攻击 | 11-JScript与DotNetToJScript原文考点精读'
pubDate: 2026-01-30T00:00:38+08:00
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

# JScript 与 DotNetToJScript 原文考点精读

## 这篇文章解决什么问题

本文件对照参考资料：

`C:\Users\Administrator\Desktop\办公\OSEP\web\3：wsh钓鱼.html`

原文主题是 `5. Phishing with Jscript`，核心小节包括：

| 原文小节 | 你应该读懂什么 |
|---|---|
| `5.1 Creating a Basic Dropper in Jscript` | JScript 为什么可以作为 Windows 客户端投递入口 |
| `5.1.1 Execution of Jscript on Windows` | `wscript.exe`、`cscript.exe`、WSH 的执行模型 |
| `5.1.2 Jscript Meterpreter Dropper` | JScript 如何下载或启动下一阶段载荷 |
| `5.2 Jscript and C#` | 为什么要把 JScript 和 C# 组合起来 |
| `5.2.1 Introduction to Visual Studio` | C# Loader 为什么需要编译环境 |
| `5.2.2 DotNetToJscript` | 如何把 .NET 程序包装成 JScript 执行 |
| `5.2.3 Win32 API Calls From C#` | C# 如何通过 P/Invoke 调用 Windows API |
| `5.2.4 Shellcode Runner in C#` | C# Shellcode Runner 的内存执行模型 |
| `5.2.5 Jscript Shellcode Runner` | JScript 如何承载 C# Runner，实现不直接落地 EXE |
| `5.2.6 SharpShooter` | 自动化生成器解决什么问题，又带来什么风险 |

这篇文章的目标不是让你背工具，而是让你读懂：为什么 JScript 是入口、为什么 C# 是能力层、为什么 DotNetToJScript 是桥。

---

## 一句话总模型

JScript 章节的完整逻辑是：

```text
用户执行 .js
  -> Windows Script Host 解释 JScript
  -> JScript 做下载、执行或反序列化
  -> .NET/C# 能力被加载到内存
  -> C# 调 Win32 API 执行 shellcode
  -> 最终建立 foothold 或进入下一步枚举
```

你可以把它分成三层：

| 层 | 作用 | 常见技术 |
|---|---|---|
| 入口层 | 让代码第一次被 Windows 执行 | `.js`、WSH、`wscript.exe`、`cscript.exe` |
| 桥接层 | 把脚本世界接到 .NET 世界 | DotNetToJScript、COM、反序列化 |
| 能力层 | 真正调用系统能力 | C#、P/Invoke、Win32 API、Shellcode Runner |

考试里如果某一层失败，不要整条链重做。先判断是入口层、桥接层还是能力层坏了。

---

## 5.1 Creating a Basic Dropper in Jscript

原文这里想让你理解：JScript 本身就能做一个基础 Dropper。

Dropper 的意思不是“恶意软件本体”，而是“把下一阶段带进来的载体”。在 OSEP 里，Dropper 通常做这几类事：

| 动作 | 说明 | 成功信号 |
|---|---|---|
| 执行命令 | 调用 `WScript.Shell` 执行系统命令 | 能看到 `whoami`、`hostname` 等输出 |
| 下载文件 | 用 COM HTTP 对象请求远程资源 | 目标上出现测试文件或服务端收到请求 |
| 写文件 | 用 `ADODB.Stream` 保存响应内容 | 文件大小和内容正确 |
| 启动下一阶段 | 调用 PowerShell、EXE、脚本或注册组件 | 下一阶段有输出、回连或进程 |

初学者要先做最小验证：

```text
弹窗/输出 -> whoami -> HTTP 请求 -> 下载小文本 -> 下一阶段载荷
```

不要一开始就运行完整 payload。否则失败时你分不清是 WSH 被禁、网络不通、下载失败、AV 拦截，还是 payload 本身错。

---

## 5.1.1 Execution of Jscript on Windows

JScript 在 Windows 上通常由 Windows Script Host 运行。

| 宿主 | 人话解释 | 适合场景 |
|---|---|---|
| `wscript.exe` | 图形化脚本宿主，常弹窗口，不直接显示控制台输出 | 用户双击、弹窗测试 |
| `cscript.exe` | 控制台脚本宿主，输出在命令行里 | 调试、查看标准输出 |
| WSH | Windows 内置脚本运行环境 | 让 `.js`、`VBS` 具备系统操作能力 |

读懂标准：

```
我知道 JScript 不是浏览器里的 JavaScript，而是 Windows Script Host 里的脚本。
它可以通过 ActiveX/COM 调用系统对象，所以能读写文件、执行命令、发 HTTP 请求。
```

常见失败：

| 现象 | 优先排查 |
|---|---|
| 双击没反应 | WSH 是否禁用、文件关联、SmartScreen、AV |
| `WScript.Echo` 不显示 | 你是不是用 `cscript`/`wscript` 混了输出方式 |
| ActiveXObject 创建失败 | 组件被禁、位数不匹配、策略限制 |
| 脚本运行但下载失败 | DNS、代理、TLS、URL、User-Agent、出站过滤 |

读不懂时回退：

| 卡点 | 回退 |
|---|---|
| 不懂脚本宿主 | `04-JScript攻击/01-Jscript基础.md` |
| 不懂出网失败 | `10-网络过滤绕过/09-网络过滤新手详解与出网排错.md` |
| 不懂被策略拦截 | `09-应用白名单绕过/08-AppLocker新手详解与绕过地图.md` |

---

## 5.1.2 Jscript Meterpreter Dropper

原文这里的重点不是 Meterpreter 本身，而是“JScript 如何把下一阶段拉进来”。

拆成步骤：

| 步骤 | 你要理解什么 |
|---|---|
| 生成或准备 payload | 下一阶段是什么，架构和监听器是否匹配 |
| JScript 下载/写入/执行 | JScript 只是投递和启动机制 |
| 监听器等待连接 | 成功不是脚本结束，而是目标能连回来 |
| 验证上下文 | 当前用户、主机、权限、网络位置 |

常见误区：

| 误区 | 正确理解 |
|---|---|
| Dropper 运行完就算成功 | 要看下一阶段是否真正执行并回连 |
| 下载成功等于执行成功 | 下载、写入、执行是三件事 |
| 有回连就不用记录环境 | 报告需要主机、身份、入口、时间和影响 |

---

## 5.2 Jscript and C#

为什么原文要从 JScript 转到 C#？

因为 JScript 适合做入口，但不适合写复杂的底层能力。C# 更适合调用 Win32 API、管理字节数组、写 Shellcode Runner。

| 技术 | 适合做什么 | 不适合做什么 |
|---|---|---|
| JScript | 入口、下载、COM 调用、触发 .NET | 复杂内存操作 |
| C# | Win32 API、shellcode runner、反射、复杂逻辑 | 直接让用户双击可能更显眼 |
| DotNetToJScript | 把 C# 能力塞进 JScript 入口 | 不是万能免杀，也可能被检测 |

一句话：

```text
JScript 负责进门，C# 负责干活，DotNetToJScript 负责把两者接起来。
```

---

## 5.2.1 Introduction to Visual Studio

原文提 Visual Studio，是因为你需要能编译 C# 代码。

你要理解的不是 IDE 按钮，而是这几个概念：

| 概念 | 为什么重要 |
|---|---|
| 项目类型 | 控制生成 EXE、DLL、类库 |
| 目标框架 | 影响目标机器是否能加载 |
| 平台目标 | x86、x64、AnyCPU 影响 shellcode 和 API |
| 引用和命名空间 | 决定能否使用 `System.Runtime.InteropServices` 等能力 |
| 编译输出 | DotNetToJScript 通常需要可被包装的 .NET 程序集 |

失败排查：

| 现象 | 优先排查 |
|---|---|
| 编译失败 | 引用、命名空间、类可见性、语法 |
| 目标机器无法运行 | .NET 版本、架构、依赖 |
| DotNetToJScript 转换失败 | 类/方法要求、COM 可见性、入口设计 |

---

## 5.2.2 DotNetToJscript

DotNetToJScript 的核心价值是：让 JScript 承载 .NET 程序集。

理解链路：

```text
写 C# 类
  -> 编译成 .NET 程序集
  -> DotNetToJScript 把程序集包装进 JScript
  -> WSH 执行 JScript
  -> JScript 触发 .NET 对象
  -> C# 代码在内存中运行
```

它解决的问题：

| 问题 | DotNetToJScript 的意义 |
|---|---|
| 不想直接落地 EXE | 把 .NET 能力包装到脚本里 |
| JScript 能力有限 | 借 C# 实现复杂逻辑 |
| 需要客户端入口 | `.js` 更像脚本投递载体 |

它不解决的问题：

| 不解决 | 说明 |
|---|---|
| 不保证免杀 | 生成内容和行为仍可能被 AV/EDR/AMSI 检测 |
| 不保证能执行 | AppLocker/WSH 禁用/脚本策略仍可能阻止 |
| 不解决网络 | 回连失败仍要查代理、DNS、TLS、端口 |

---

## 5.2.3 Win32 API Calls From C#

C# 调 Win32 API 主要靠 P/Invoke。

| 术语 | 人话解释 |
|---|---|
| P/Invoke | .NET 调原生 DLL 函数的桥 |
| `DllImport` | 告诉 C#：这个函数在某个 DLL 里 |
| `IntPtr` | 表示指针、地址、句柄，适配 32/64 位 |
| `Marshal` | 在托管代码和非托管内存之间复制数据 |

读懂标准：

```
我知道 C# 不是天然会执行 shellcode，它是通过 P/Invoke 调 Windows API，
再把 shellcode 字节放进可执行内存并创建线程。
```

常见失败：

| 失败 | 原因 |
|---|---|
| API 返回 0 或空指针 | 参数、权限、内存保护、位数 |
| 程序崩溃 | API 声明错误、调用约定错误、payload 架构错误 |
| 编译成功但目标失败 | .NET 版本、位数、AV/EDR、缺依赖 |

---

## 5.2.4 Shellcode Runner in C#

C# Shellcode Runner 的结构和 VBA/PowerShell 类似：

| 动作 | 常见 API/方法 | 成功信号 |
|---|---|---|
| 申请内存 | `VirtualAlloc` | 返回非零地址 |
| 复制字节 | `Marshal.Copy` | 写入长度等于 shellcode 长度 |
| 创建线程 | `CreateThread` | 返回线程句柄 |
| 等待执行 | `WaitForSingleObject` | 进程不立刻退出，payload 有机会运行 |

关键理解：

```text
JScript、VBA、PowerShell、C# 的语法不同，但 Shellcode Runner 的内存模型相同。
```

所以你不需要把每种语言当成全新知识点。你要抓住底层模型：

```text
字节 -> 内存 -> 执行权限 -> 线程 -> 回连/效果
```

---

## 5.2.5 Jscript Shellcode Runner

这一节把前面内容合起来：

```text
JScript 入口
  -> 承载/触发 C# 代码
  -> C# 调 Win32 API
  -> shellcode 在内存中执行
```

排错时分层：

| 层 | 失败现象 | 排查 |
|---|---|---|
| JScript 入口 | `.js` 不运行 | WSH、AppLocker、SmartScreen、AV |
| .NET 桥接 | 脚本运行但 C# 不触发 | DotNetToJScript 输出、类入口、反序列化 |
| API 调用 | C# 触发但崩溃 | P/Invoke、位数、API 参数 |
| payload | 线程创建但无回连 | shellcode、监听器、网络、代理 |

这个表非常重要。它能防止你把所有失败都归因于“免杀不行”。

---

## 5.2.6 SharpShooter

SharpShooter 属于自动化生成器。它的价值是帮你快速生成投递载体，但学习时不能只会点工具。

| 你要理解 | 原因 |
|---|---|
| 它生成了什么类型的载体 | JS、HTA、VBA 等行为不同 |
| 它把 payload 放在哪里 | 内嵌、远程下载、编码、加密 |
| 它如何触发执行 | WSH、COM、PowerShell、.NET |
| 它产生什么特征 | 自动化模板容易被签名 |
| 失败如何拆分 | 入口、加载、执行、网络分层排查 |

考试建议：

```
自动化工具可以节省时间，但不能替代理解链路。
如果工具失败，你要能手工说出它本来想做哪几步。
```

---

## JScript 章节的考试决策

| 场景 | 优先方向 | 失败后切换 |
|---|---|---|
| Office 宏受限但脚本可运行 | JScript Dropper | HTA/XSL/AppLocker 绕过 |
| 需要复杂 Win32 API 能力 | JScript + C# | PowerShell 反射或原生 C# Loader |
| 不想直接落地 EXE | DotNetToJScript | 反射 PowerShell、MSHTA |
| WSH 被禁 | 换执行入口 | Office、HTA、XSL、InstallUtil |
| JScript 能跑但无回连 | 查网络 | `10-网络过滤绕过/08-出网受限决策树.md` |
| 内容被杀 | 查 AV/AMSI/AppLocker | `08`、`09`、`10` 相关章节 |

---

## 每段原文精读问题

读 `3：wsh钓鱼.html` 时，每个小节都问：

```text
这一节在讲入口、桥接还是能力？
它依赖 WSH、COM、.NET、Win32 API 还是网络？
成功信号是什么：脚本执行、文件下载、C# 触发、线程创建还是回连？
失败应该先查哪一层？
它和 Office 宏、反射 PowerShell、进程注入有什么共同底层模型？
```

---

## 报告证据清单

| 阶段 | 证据 |
|---|---|
| JScript 执行 | 文件名、执行方式、当前用户、主机名 |
| 下载/Dropper | 服务端访问记录、目标文件路径、大小 |
| DotNetToJScript | 生成载体、执行结果、C# 代码触发证明 |
| C# Runner | 位数、API 执行结果、回连证明 |
| 失败排查 | WSH/策略/AV/网络检查输出 |

---

## 闭卷自测

1. `wscript.exe` 和 `cscript.exe` 有什么区别？
2. 为什么 JScript 能调用系统对象？
3. Dropper 的成功信号有哪些层次？
4. 为什么课程要把 JScript 和 C# 组合起来？
5. DotNetToJScript 解决什么问题，又不解决什么问题？
6. C# 调 Win32 API 为什么需要 `DllImport` 和 `IntPtr`？
7. JScript Shellcode Runner 失败时，如何区分入口层、桥接层、能力层和网络层？
8. SharpShooter 自动化生成器为什么不能替代理解？

---

## 下一步阅读

| 如果你想继续 | 阅读 |
|---|---|
| JScript 基础 | `01-Jscript基础.md` |
| DotNetToJScript | `04-DotNetToJscript.md` |
| C# Shellcode Runner | `08-CSharp-ShellcodeRunner.md` |
| 考试速查 | `09-JScript投递与DotNetToJScript考试速查.md` |
| 新手闭环 | `10-JScript新手详解与投递闭环.md` |
| 反射 PowerShell | `../05-反射式PowerShell/00-章节指南.md` |
