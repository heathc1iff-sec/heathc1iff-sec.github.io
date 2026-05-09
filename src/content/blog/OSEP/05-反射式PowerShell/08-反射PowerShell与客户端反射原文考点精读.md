---
title: OSEP-05-反射PowerShell与客户端反射原文考点精读
description: '05-反射式PowerShell | 08-反射PowerShell与客户端反射原文考点精读'
pubDate: 2026-01-30T00:00:47+08:00
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

# 反射 PowerShell 与客户端反射原文考点精读

## 这篇文章解决什么问题

本文件对照两篇原文：

| 原文 HTML | 原文主题 | 本文处理方式 |
|---|---|---|
| `C:\Users\Administrator\Desktop\办公\OSEP\web\4：反射式powershell.html` | `6. Reflective PowerShell` | 拆解 PowerShell + .NET、UnsafeNativeMethods、DelegateType、反射式 Shellcode Runner |
| `C:\Users\Administrator\Desktop\办公\OSEP\web\5：客户端反射代码攻击.html` | `7. Reflective Code Execution in Client Side Attacks` | 解释如何把反射 PowerShell / 反射 C# 放回 Office、JScript 等客户端入口 |

你读这两章最容易卡在：

1. 反射到底是什么，不要把它当成“高级黑魔法”。
2. 为什么要绕开 `Add-Type`，改用 `UnsafeNativeMethods` 和 Delegate。
3. 客户端反射代码为什么是“入口层 + 加载层 + 能力层”的组合。

---

## 原文小节地图

### Reflective PowerShell

| 原文小节 | 你应该读懂什么 | 知识库对应 |
|---|---|---|
| `6.1 Classic PowerShell Tradecraft` | 传统 PowerShell 攻击链和它的检测面 | `01-PowerShell与Win32API.md`、`02-下载摇篮技术.md` |
| `6.1.1 PowerShell and .NET` | PowerShell 为什么能调用 .NET 类型和方法 | `01-PowerShell与Win32API.md` |
| `6.2 Keep That PowerShell in Memory` | 为什么要尽量减少落地和编译痕迹 | `03-反射技术进阶.md` |
| `6.2.1 Leveraging UnsafeNativeMethods` | 如何从已有 .NET 程序集中找 Win32 API 调用能力 | `03-反射技术进阶.md` |
| `6.2.2 DelegateType Reflection` | 如何用 Delegate 动态调用函数地址 | `04-完整反射实现.md` |
| `6.2.3 Reflection Shellcode Runner in PowerShell` | 用纯反射完成内存执行链路 | `04-完整反射实现.md` |

### Client Side Reflective Code Execution

| 原文小节 | 你应该读懂什么 | 知识库对应 |
|---|---|---|
| `7.1 Including Reflective Code` | 反射代码如何被塞进客户端载体 | `06-客户端反射代码攻击联动.md` |
| `7.1.1 Reflective PowerShell in Client-Side Attacks` | Office/JScript 如何触发反射 PowerShell | `06-客户端反射代码攻击联动.md` |
| `7.1.2 Reflective C# in Client-Side Attacks` | C# 能力如何通过客户端入口加载 | `06-客户端反射代码攻击联动.md` |

---

## 一句话总模型

反射 PowerShell 的核心不是“隐藏命令”，而是：

```text
在运行时查找 .NET 类型和方法
  -> 动态解析 Win32 API 地址
  -> 动态构造可调用的 Delegate
  -> 申请内存、复制 shellcode、创建线程
  -> 尽量减少磁盘编译和静态特征
```

客户端反射代码的核心是：

```text
Office/JScript/HTA 负责入口
  -> PowerShell/C# 负责加载和调用系统能力
  -> 反射负责减少落地和静态检测面
```

---

## 6.1 Classic PowerShell Tradecraft

原文从传统 PowerShell 技术讲起，是为了让你看到它的优点和问题。

| 优点 | 问题 |
|---|---|
| 系统自带，常见于管理场景 | 日志、AMSI、脚本块检测、命令行检测 |
| 能调用 .NET | `Add-Type` 可能产生编译痕迹 |
| 下载和内存加载方便 | 代理、TLS、CLM、AppLocker 可能限制 |

读懂标准：

```
我知道 PowerShell 强大，是因为它不是单纯 shell，而是 .NET 的交互入口。
```

常见误区：

| 误区 | 正确理解 |
|---|---|
| PowerShell 等于命令行 | PowerShell 是 .NET 自动化环境 |
| `-ExecutionPolicy Bypass` 能解决一切 | 它不等于绕过 AMSI、CLM、AppLocker |
| 能下载脚本就能执行 payload | 还要看 AMSI、语言模式、网络和位数 |

---

## 6.1.1 PowerShell and .NET

PowerShell 可以直接使用 .NET 类型，这就是它能做复杂内存操作的根。

你要读懂：

| 概念 | 人话解释 |
|---|---|
| Assembly | .NET 程序集，像一组已经加载的代码库 |
| Type | 类型，比如类、结构体、枚举 |
| Method | 方法，类型里的可调用函数 |
| Reflection | 运行时查找和调用这些类型、方法、字段 |
| Marshal | 托管和非托管内存之间的数据搬运工具 |

把它翻成一句话：

```text
PowerShell 能问 .NET：“你当前加载了哪些代码？里面有哪些类型？这些类型有哪些方法？我能不能现在调用它？”
```

---

## 6.2 Keep That PowerShell in Memory

为什么原文强调“Keep in Memory”？

因为许多检测会盯住磁盘文件、编译临时文件、命令行明文、脚本内容和已知工具特征。

| 方式 | 检测面 |
|---|---|
| 落地 EXE/DLL | 文件扫描、签名、哈希 |
| `Add-Type` 编译 C# | 临时文件、编译行为、代码内容 |
| 明文脚本 | AMSI、脚本块日志 |
| 纯反射 | 仍有行为检测，但减少部分静态落地痕迹 |

注意：内存执行不是隐身斗篷。它只是减少某些检测面，不等于不会被 EDR 发现。

---

## 6.2.1 Leveraging UnsafeNativeMethods

这一节常让初学者懵。你可以这样理解：

`.NET` 自己已经加载了一些能调用 Windows API 的内部类型。反射可以去找这些类型，然后借它们解析函数地址。

关键对象：

| 对象 | 作用 |
|---|---|
| `System.dll` | 常见 .NET 程序集 |
| `Microsoft.Win32.UnsafeNativeMethods` | 内部类型，包含一些原生 API 辅助方法 |
| `GetModuleHandle` | 获取已加载 DLL 的模块句柄 |
| `GetProcAddress` | 根据函数名获取函数地址 |

链路：

```text
找已加载程序集
  -> 找 `UnsafeNativeMethods`
  -> 调 `GetModuleHandle("kernel32.dll")`
  -> 调 `GetProcAddress(..., "VirtualAlloc")`
  -> 得到 API 函数地址
```

读懂标准：

```
我知道这一步不是执行 shellcode，而是在为后面“动态调用 Win32 API”找函数地址。
```

---

## 6.2.2 DelegateType Reflection

拿到函数地址后，还不能直接像普通 PowerShell 函数那样调用它。你需要一个“函数指针的包装”，也就是 Delegate。

| 概念 | 人话解释 |
|---|---|
| 函数地址 | API 在内存中的位置 |
| Delegate | .NET 里可调用的函数签名包装 |
| Dynamic Type | 运行时创建的类型 |
| 参数签名 | 告诉 .NET 这个函数需要什么参数、返回什么 |

为什么需要 Delegate：

```text
GetProcAddress 只给你一个地址。
Delegate 告诉 .NET：这个地址代表一个能按某种参数格式调用的函数。
```

常见失败：

| 失败 | 原因 |
|---|---|
| 调用崩溃 | Delegate 参数类型和真实 API 不匹配 |
| 返回值异常 | 返回类型错，指针被截断 |
| x86/x64 表现不同 | 指针宽度不同，`IntPtr` 使用不当 |

---

## 6.2.3 Reflection Shellcode Runner in PowerShell

完整反射 Shellcode Runner 就是把前面的步骤接起来。

| 阶段 | 动作 | 成功信号 |
|---|---|---|
| 解析 API | 找 `VirtualAlloc`、`CreateThread` 等地址 | 得到非零函数地址 |
| 构造 Delegate | 为 API 创建可调用签名 | 可以调用并返回合理值 |
| 分配内存 | 调 `VirtualAlloc` | 返回非零内存地址 |
| 复制 shellcode | `Marshal.Copy` | shellcode 长度正确 |
| 创建线程 | `CreateThread` | 返回线程句柄 |
| 等待/观察 | `WaitForSingleObject` 或会话保持 | 回连或效果出现 |

失败排查不要乱：

```text
先查 API 地址 -> 再查 Delegate 签名 -> 再查内存地址 -> 再查复制长度 -> 再查线程 -> 最后查网络
```

---

## 7.1 Including Reflective Code

客户端反射代码章节把反射能力放回初始访问场景。

你要抓住三层：

| 层 | 例子 | 作用 |
|---|---|---|
| 入口层 | Office 宏、JScript、HTA | 让第一段代码被用户触发 |
| 加载层 | PowerShell、C#、反射 | 把能力放进内存 |
| 能力层 | Shellcode Runner、枚举、横向模块 | 实际执行动作 |

这个分层非常重要。考试里你可以替换其中一层：

| 失败层 | 替换思路 |
|---|---|
| Office 宏被拦 | 换 JScript/HTA/HTML Smuggling |
| PowerShell 被 AMSI 拦 | 换 C#、DotNetToJScript、AppLocker 绕过 |
| 回连失败 | 换网络通道、代理感知、DNS/HTTP |
| shellcode 被杀 | 换编码、加载器、行为链 |

---

## 7.1.1 Reflective PowerShell in Client-Side Attacks

这一节的意思是：客户端入口不一定直接跑 payload，可以触发一段反射 PowerShell。

链路：

```text
用户打开文档或脚本
  -> 入口层执行最小命令
  -> 下载/拼接/解码反射 PowerShell
  -> 在内存中解析 API 和创建 Delegate
  -> 执行 shellcode 或加载工具
```

常见失败：

| 现象 | 优先排查 |
|---|---|
| 入口没触发 | 宏/WSH/AppLocker/用户交互 |
| PowerShell 被拦 | AMSI、CLM、脚本块日志、AV |
| 反射代码报错 | 类型名、方法签名、.NET 版本 |
| 线程创建但无回连 | payload、网络、代理、监听器 |

---

## 7.1.2 Reflective C# in Client-Side Attacks

反射 C# 的思路类似，但能力层换成 C#。

| PowerShell 反射 | C# 反射/加载 |
|---|---|
| 灵活、易拼接、适合脚本入口 | 类型清晰、适合复杂 loader |
| 容易碰 AMSI/CLM | 需要考虑编译、.NET 版本、加载方式 |
| 适合快速验证 | 适合封装能力模块 |

考试理解：

```text
不要纠结“PowerShell 更好还是 C# 更好”。
先看当前环境允许哪种入口、哪种加载方式、哪种网络出站。
```

---

## 与 JScript / Office 的关系

| 入口 | 反射怎么接上 |
|---|---|
| Office VBA | VBA 启动或下载 PowerShell/C# 反射代码 |
| JScript | WSH 执行 JScript，再触发 DotNetToJScript 或下载反射代码 |
| HTML Smuggling | 投递脚本或文档，再进入反射加载 |
| HTA/MSHTA | 用可信宿主执行脚本逻辑 |

你要学透的是“组合能力”：

```text
入口可以换，加载可以换，payload 可以换，但前提、成功信号和失败排查必须说清。
```

---

## 报告证据清单

| 阶段 | 证据 |
|---|---|
| 入口触发 | 文档/脚本、当前用户、主机名 |
| 反射加载 | PowerShell 版本、语言模式、关键输出 |
| API 解析 | 函数地址或执行阶段说明 |
| 内存执行 | 回连、命令执行、权限上下文 |
| 失败排查 | AMSI/CLM/AppLocker/网络检查结果 |

---

## 闭卷自测

1. PowerShell 为什么能调用 .NET？
2. `Add-Type` 和纯反射的区别是什么？
3. `UnsafeNativeMethods` 在反射链路里解决什么问题？
4. `GetProcAddress` 返回的地址为什么还需要 Delegate？
5. 反射式 Shellcode Runner 的阶段有哪些？
6. 客户端反射代码为什么要分入口层、加载层、能力层？
7. Office/JScript 能触发反射 PowerShell，但无回连时先查什么？
8. PowerShell 被 CLM 限制时，你会切到哪些路径？

---

## 下一步阅读

| 如果你想继续 | 阅读 |
|---|---|
| PowerShell 与 Win32 API | `01-PowerShell与Win32API.md` |
| 下载摇篮 | `02-下载摇篮技术.md` |
| 反射技术进阶 | `03-反射技术进阶.md` |
| 完整反射实现 | `04-完整反射实现.md` |
| 客户端反射联动 | `06-客户端反射代码攻击联动.md` |
| 新手详解 | `07-反射式PowerShell新手详解.md` |
| JScript 桥接 | `../04-JScript攻击/11-JScript与DotNetToJScript原文考点精读.md` |
