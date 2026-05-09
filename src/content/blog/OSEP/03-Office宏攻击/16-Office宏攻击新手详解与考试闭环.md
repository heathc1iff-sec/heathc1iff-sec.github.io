---
title: OSEP-03-Office宏攻击新手详解与考试闭环
description: '03-Office宏攻击 | 16-Office宏攻击新手详解与考试闭环'
pubDate: 2026-01-30T00:00:25+08:00
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

# Office 宏攻击新手详解与考试闭环

## 对应课程范围

本文件对应 `1：office钓鱼.html`，用于把 Office 宏攻击从“能跑代码”整理成初学者可以复习的完整链路。

学习本章时，不要只背 VBA 语法。OSEP 更看重你能不能解释：为什么 Office 文档能触发代码、代码如何进入内存、为什么会失败、失败后该切换到哪条路径。

---

## 一句话理解

Office 宏攻击的本质是：

```
用户打开文档
  -> Office 触发宏入口
  -> 宏调用系统能力或下载能力
  -> 载荷在当前用户上下文中执行
  -> 建立 foothold 或完成下一步枚举
```

宏只是入口，不是最终目标。考试里真正要拿到的是稳定执行能力、网络连通能力和后续枚举能力。

---

## 核心概念

| 概念 | 说明 | 复习重点 |
|---|---|---|
| VBA | Office 内置脚本语言 | 能写入口函数、变量、数组、函数调用 |
| 宏入口 | `AutoOpen`、`Document_Open` 等自动触发点 | 能判断宏为什么没有运行 |
| Win32 API | Windows 提供的系统函数 | 能理解 `VirtualAlloc`、`CreateThread` 等调用目的 |
| Shellcode Runner | 分配内存并执行 shellcode 的加载器 | 能区分 x86/x64、内存保护、退出方式 |
| Dropper | 下载或释放下一阶段载荷的程序 | 能先做最小下载测试，再上完整载荷 |
| 代理感知 | 使用目标系统代理访问外网 | 能区分用户代理和 SYSTEM 代理 |
| HTML Smuggling | 通过浏览器端构造下载文件 | 能理解它解决的是投递问题，不是执行问题 |

---

## 正序学习路线

| 顺序 | 文件 | 学习目标 |
|---|---|---|
| 1 | `01-VBA基础.md` | 先能写最小宏，确认触发条件 |
| 2 | `02-VBA调用Win32API.md` | 理解 32/64 位声明、`Declare`、`PtrSafe`、`LongPtr`、`ByVal/ByRef` 和 Windows API 参数 |
| 3 | `03-VBA-Shellcode执行器.md` | 学会内存执行的基本流程 |
| 4 | `04-Dropper基础.md`、`05-HTML-Smuggling.md` | 区分执行入口和投递入口 |
| 5 | `06-PowerShell-Shellcode.md`、`07-反射技术.md` | 连接 Office、PowerShell、P/Invoke、下载摇篮、`Add-Type` 风险和反射加载 |
| 6 | `08-代理感知通信.md`、`09-代理感知通信高级.md` | 解决出网和代理问题 |
| 7 | `15-客户端初始访问考试速查.md` | 用考试视角选择入口 |

---

## 最小实验闭环

每次做宏攻击实验，都按下面顺序推进：

1. 用 `MsgBox` 或写文件确认宏是否触发。
2. 用 `whoami`、`hostname` 这类最小命令确认能执行系统命令。
3. 用访问测试 URL 或下载小文本确认出网。
4. 再切换到下载器、PowerShell、shellcode runner 或反射加载。
5. 最后记录证据：触发方式、当前用户、主机名、回连、失败原因。

不要一开始就放完整 payload。初学者最容易把“宏没触发、网络不通、payload 架构错误、AV 拦截”混成一个问题。

---

## 常用检查命令

### Windows 侧验证

```powershell
whoami
hostname
$env:PROCESSOR_ARCHITECTURE
[Environment]::Is64BitProcess
[Environment]::Is64BitOperatingSystem
```

### PowerShell 基础状态

```powershell
$PSVersionTable
$ExecutionContext.SessionState.LanguageMode
Get-ExecutionPolicy -List
```

### 代理与出网

```powershell
netsh winhttp show proxy
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
```

这些命令不是攻击本身，而是为了判断环境。OSEP 考试里，判断环境往往比换 payload 更重要。

---

## 常见失败与排错

| 现象 | 优先排查 | 相关章节 |
|---|---|---|
| 文档打开后无反应 | 宏是否启用、Protected View、Mark-of-the-Web、入口函数名 | `11-Office安全机制.md` |
| 本地可以，目标不行 | Office 位数、系统位数、语言环境、权限、AV | `15-客户端初始访问考试速查.md` |
| Office 崩溃 | Shellcode 架构、API 声明、内存保护、线程退出方式 | `03-VBA-Shellcode执行器.md` |
| 有命令执行但无回连 | 监听器、代理、TLS、DNS、出站端口 | `10-网络过滤绕过/08-出网受限决策树.md` |
| PowerShell 报恶意内容 | AMSI | `08-AMSI绕过/11-AMSI-CLM联动排错.md` |
| 文件落地被删 | AV 静态签名 | `07-杀软绕过/11-AV绕过决策树.md` |

---

## OSEP 考试重点

| 重点 | 你要能做到 |
|---|---|
| 入口判断 | 判断目标更适合 Office、JScript、HTA、HTML Smuggling 还是凭证诱导 |
| 位数判断 | 能解释 Office 位数、PowerShell 位数、shellcode 位数为什么必须匹配 |
| 分层设计 | 把载体层、加载层、能力层分开，便于替换 |
| 出网排错 | 会先验证网络再换 payload |
| 证据记录 | 记录当前用户、主机、执行结果、回连、后续影响 |

---

## 复习自测

1. 宏为什么能自动运行？有哪些入口函数？
2. `PtrSafe` 和 `LongPtr` 解决什么问题？
3. 为什么 x64 系统上仍可能需要 x86 payload？
4. Office 直接启动 PowerShell 为什么容易被检测？
5. HTML Smuggling 解决的是投递、执行还是免杀？
6. 宏能执行但没有回连，最先查哪三件事？
7. 如果 PowerShell 被 AMSI 拦，你会切到哪条路径？

---

## 交叉引用

| 主题 | 文件 |
|---|---|
| 初始访问总表 | `15-客户端初始访问考试速查.md` |
| 客户端反射联动 | `05-反射式PowerShell/06-客户端反射代码攻击联动.md` |
| AV 绕过 | `07-杀软绕过/11-AV绕过决策树.md` |
| AMSI/CLM | `08-AMSI绕过/11-AMSI-CLM联动排错.md` |
| 出网排错 | `10-网络过滤绕过/08-出网受限决策树.md` |
