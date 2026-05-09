---
title: OSEP-03-Office与日历钓鱼原文考点精读
description: '03-Office宏攻击 | 17-Office与日历钓鱼原文考点精读'
pubDate: 2026-01-30T00:00:26+08:00
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

# Office 与日历钓鱼原文考点精读

## 这篇文章解决什么问题

本文件对照参考资料目录中的两篇原文：

| 原文 HTML | 原文主题 | 本文处理方式 |
|---|---|---|
| `C:\Users\Administrator\Desktop\办公\OSEP\web\1：office钓鱼.html` | `3. Phishing with Microsoft Office` | 把 VBA、Win32 API、VBA Shellcode Runner、PowerShell Shellcode Runner 拆成初学者能读懂的链路 |
| `C:\Users\Administrator\Desktop\办公\OSEP\web\2：日历钓鱼.html` | `4. Phishing with Calendars` | 把 ICS、自定义会议邀请、自动化、Responder 凭证捕获拆成凭证入口链路 |

你读本章时最容易卡在两件事：

1. Office 宏到底为什么能从“文档”变成“代码执行”。
2. 日历邀请到底为什么能从“会议提醒”变成“凭证捕获”。

本文不替代原文，也不替代已有详细章节。它的作用是把原文小节背后的逻辑讲清楚，让你读原文时不会只看到一串代码和命令。

---

## 原文小节地图

### Office 钓鱼原文结构

| 原文小节 | 你应该读懂什么 | 知识库对应 |
|---|---|---|
| `3.1 Microsoft Office Macros` | Office 宏为什么是客户端执行入口 | `01-VBA基础.md`、`04-Dropper基础.md` |
| `3.1.2 Understanding the Basics of VBA` | VBA 语法、入口函数、变量和字符串拼接 | `01-VBA基础.md` |
| `3.1.3 Integrating PowerShell` | VBA 如何把能力交给 PowerShell | `06-PowerShell-Shellcode.md` |
| `3.2 Executing Shellcode in Word Memory` | 为什么要在 Word 进程内存中执行 shellcode | `03-VBA-Shellcode执行器.md` |
| `3.2.1 Calling Win32 APIs from VBA` | VBA 如何声明并调用 Windows API | `02-VBA调用Win32API.md` |
| `3.2.2 VBA Shellcode Runner` | 分配内存、复制 shellcode、创建线程的完整链路 | `03-VBA-Shellcode执行器.md` |
| `3.3 PowerShell Shellcode Runner` | 同一套内存执行思路如何迁移到 PowerShell | `06-PowerShell-Shellcode.md` |
| `3.3.1 Calling Win32 APIs from PowerShell` | PowerShell 如何通过 .NET/PInvoke 调 API | `05-反射式PowerShell` |
| `3.3.2 Porting Shellcode Runner to PowerShell` | 为什么同一技术可换载体实现 | `06-PowerShell-Shellcode.md`、`07-反射技术.md` |

### 日历钓鱼原文结构

| 原文小节 | 你应该读懂什么 | 知识库对应 |
|---|---|---|
| `4.1 Calendar as an Initial Access Vector` | 日历邀请为什么能成为初始访问载体 | `13-日历钓鱼攻击.md` |
| `4.1.1 The iCalendar (ICS) standard` | ICS 是什么，哪些字段会影响展示和触发 | `13-日历钓鱼攻击.md` |
| `4.1.2 Creating a Custom Calendar Invite` | 如何手工构造看起来合理的邀请 | `13-日历钓鱼攻击.md` |
| `4.2 Abusing Calendars` | 日历滥用不止是链接，还可诱导认证 | `15-客户端初始访问考试速查.md` |
| `4.2.1 Crafting The Full Calendar Phishing` | 完整邀请需要标题、时间、组织者、描述和触发点一致 | `13-日历钓鱼攻击.md` |
| `4.2.2 Automating the Attack` | 自动化生成是为了规模化和减少格式错误 | `13-日历钓鱼攻击.md` |
| `4.2.3 Credential Stealing with Responder` | UNC 触发 NTLM 认证，Responder 捕获 Net-NTLMv2 | `13-日历钓鱼攻击.md`、`13-Windows凭证/06-Windows凭证新手闭环与材料去向.md` |

---

## 一句话总模型

Office 宏和日历钓鱼都属于客户端初始访问，但它们的目标不同：

| 载体 | 更像什么 | 最终想得到什么 |
|---|---|---|
| Office 宏 | 代码执行入口 | 命令执行、内存执行、回连、主机枚举 |
| 日历邀请 | 用户交互和凭证诱导入口 | 链接点击、NTLM 认证、明文凭证或可中继认证 |

考试里不要把它们混成一个东西。Office 宏偏“让代码跑起来”，日历钓鱼偏“让用户或系统发起一次有价值的访问/认证”。

---

## Office 宏链路逐段拆解

### 1. Microsoft Office Macros

这一段原文想让你理解：Office 文档不是纯文本，它可以携带宏代码。

| 要点 | 人话解释 |
|---|---|
| 宏 | Office 里的自动化脚本 |
| VBA | 写宏用的语言 |
| 入口函数 | 文档打开时自动触发的函数，例如 `AutoOpen` 或 `Document_Open` |
| 用户上下文 | 宏以打开文档的用户身份执行 |

读懂标准：

```
我知道宏不是 payload 本身，而是让 payload 开始运行的入口。
```

常见误区：

| 误区 | 正确理解 |
|---|---|
| 宏一打开就一定执行 | 宏设置、Protected View、MOTW、用户交互都会影响 |
| 宏等于 shellcode | 宏只是载体，shellcode 是后续执行内容 |
| 只要能弹 MsgBox 就等于攻击成功 | MsgBox 只证明宏触发，不证明网络、权限、payload 可用 |

---

### 2. Understanding the Basics of VBA

原文这里不是为了把你培养成 VBA 程序员，而是让你能读懂后续 loader。

你至少要读懂：

| VBA 点 | 为什么重要 |
|---|---|
| `Sub` | 定义可执行过程 |
| 字符串拼接 | 用来拆分敏感命令、URL 或 payload |
| 数组 | 存放 shellcode 字节 |
| 条件判断 | 根据系统环境选择执行路径 |
| `CreateObject` | 调用 COM 对象，例如 `WScript.Shell` |

自测：

```
□ 我能解释 `AutoOpen` 和普通 `Sub` 的区别
□ 我能看出一段 VBA 是在弹窗、执行命令、下载文件，还是调用 API
□ 我能解释为什么字符串会被拆开再拼回去
```

---

### 3. Integrating PowerShell

这一段原文的重点是：VBA 不一定自己完成所有事情，它可以把执行交给 PowerShell。

链路是：

```text
Word 打开文档
  -> VBA 宏触发
  -> VBA 启动 PowerShell
  -> PowerShell 下载/加载/执行下一阶段
```

为什么这样做：

| 原因 | 解释 |
|---|---|
| VBA 写复杂逻辑不方便 | PowerShell 更适合下载、字符串处理、调用 .NET |
| 分层更灵活 | 宏只做入口，PowerShell 做能力层 |
| 便于替换 | PowerShell 被拦时可以换 JScript、C#、HTA 或其他路径 |

失败排查：

| 现象 | 先查 |
|---|---|
| 宏触发但 PowerShell 不启动 | 命令拼接、路径、引号、执行策略、AppLocker |
| PowerShell 启动但报恶意内容 | AMSI |
| PowerShell 能执行但功能受限 | CLM |
| PowerShell 能跑但无回连 | 代理、DNS、TLS、监听器 |

读不懂时回退：

| 卡点 | 回退 |
|---|---|
| 不懂 PowerShell 基础 | `01-前置知识/03-PowerShell基础.md` |
| 不懂 AMSI/CLM | `08-AMSI绕过/12-AMSI与CLM新手详解.md` |
| 不懂出网问题 | `10-网络过滤绕过/09-网络过滤新手详解与出网排错.md` |

---

## Word 内存执行链路逐段拆解

### 4. Executing Shellcode in Word Memory

原文这里开始进入 OSEP 的关键能力：不只是启动命令，而是在当前进程内存里执行机器码。

核心流程：

```text
准备 shellcode 字节
  -> 在 Word 进程中申请内存
  -> 把 shellcode 复制进去
  -> 让这块内存具备执行权限
  -> 创建线程从这块内存开始执行
```

你要真正理解的是：shellcode 不是“脚本”，它是 CPU 能执行的机器指令。机器指令要执行，必须在内存里，并且有可执行权限，还要有线程跳过去跑。

---

### 5. Calling Win32 APIs from VBA

VBA 本身没有 `VirtualAlloc` 这种底层能力，所以要声明 Win32 API。

| 术语 | 人话解释 |
|---|---|
| Win32 API | Windows 提供给程序使用系统能力的函数 |
| `Declare` | 告诉 VBA：我要调用某个 DLL 里的函数 |
| `PtrSafe` | 告诉 Office 64 位环境：这个声明考虑了指针大小 |
| `LongPtr` | 能在 32/64 位 Office 中表示指针或句柄 |
| `ByVal` | 把值传进去，而不是传变量地址 |

为什么这块容易错：

| 错误 | 结果 |
|---|---|
| Office 位数和声明不匹配 | 编译错误或崩溃 |
| 指针类型写错 | 地址截断，内存访问异常 |
| 参数顺序写错 | API 返回失败 |
| payload 位数不匹配 | Word 崩溃或无回连 |

读懂标准：

```
我不一定背得出每个 API 声明，但我知道每个参数在传什么，以及为什么 x86/x64 会影响它。
```

---

### 6. VBA Shellcode Runner

Shellcode Runner 不要当成“神秘代码”，它只有几个动作。

| 动作 | 常见 API/方法 | 作用 |
|---|---|---|
| 申请内存 | `VirtualAlloc` | 给 shellcode 找一块能放进去的地方 |
| 复制字节 | `RtlMoveMemory` / `CopyMemory` | 把字节数组写到内存 |
| 执行 | `CreateThread` | 新建线程，从 shellcode 地址开始跑 |
| 等待 | `WaitForSingleObject` | 防止线程太快退出或进程提前结束 |

实验时不要一上来放完整 payload。最小验证顺序是：

1. `MsgBox` 确认宏入口。
2. 简单命令确认系统命令执行。
3. 小网络请求确认出网。
4. 再跑 shellcode runner。
5. 最后处理 AV/AMSI/代理/位数问题。

---

## PowerShell Shellcode Runner 逐段拆解

### 7. Calling Win32 APIs from PowerShell

原文从 VBA 转到 PowerShell，是为了让你看到同一个底层动作可以用不同载体完成。

| VBA 方式 | PowerShell 方式 | 本质 |
|---|---|---|
| `Declare PtrSafe` 调 API | `Add-Type` 或反射/PInvoke 调 API | 都是在调用 Win32 API |
| VBA 字节数组 | PowerShell byte array | 都是在保存 shellcode |
| `RtlMoveMemory` | `Marshal.Copy` | 都是在把字节复制进内存 |
| `CreateThread` | P/Invoke `CreateThread` | 都是在启动执行 |

关键理解：

```
载体变了，底层内存执行模型没变。
```

所以学透本章后，你看 JScript、C#、反射 DLL、进程注入时会发现：它们都在围绕“数据进入内存并被执行”这个核心变化。

---

### 8. Porting Shellcode Runner to PowerShell

Porting 的意思不是复制粘贴语法，而是把同一个逻辑换一种语言实现。

迁移时要逐项对应：

| 要迁移的东西 | 检查点 |
|---|---|
| API 声明 | 参数类型、返回值、调用约定 |
| shellcode 数组 | byte 类型、长度、架构 |
| 内存分配 | 权限、大小、返回地址 |
| 字节复制 | 是否写入完整 |
| 线程执行 | 入口地址是否正确 |
| 出网 | payload 是否能连到监听器 |

常见失败：

| 失败 | 可能原因 |
|---|---|
| PowerShell 报恶意内容 | AMSI 扫描 |
| `Add-Type` 失败 | CLM、编译限制、语法错误 |
| 进程崩溃 | API 签名或 payload 架构错误 |
| 执行成功但无回连 | 网络、代理、证书、监听器 |

---

## 日历钓鱼链路逐段拆解

### 9. Calendar as an Initial Access Vector

日历钓鱼不是“宏攻击的替代品”，它更像另一种入口：让用户或系统处理一个看起来正常的会议对象。

| 对比 | Office 宏 | 日历邀请 |
|---|---|---|
| 用户动作 | 打开文档、启用宏 | 接受/查看/点击会议邀请 |
| 主要目标 | 执行代码 | 诱导访问、认证或下载 |
| 关键材料 | 宏、payload、loader | ICS 字段、URL、UNC、组织者 |
| 成功信号 | 命令执行或回连 | 点击、认证、hash、凭证验证 |

读懂标准：

```
我知道日历钓鱼的价值不在 ICS 文件本身，而在 ICS 让客户端展示、点击或访问某个资源。
```

---

### 10. The iCalendar (ICS) Standard

ICS 是纯文本日历格式。你要读懂的不是所有 RFC 细节，而是哪些字段影响攻击链。

| 字段 | 人话解释 | 为什么重要 |
|---|---|---|
| `BEGIN:VCALENDAR` / `END:VCALENDAR` | 日历文件边界 | 格式不完整会被客户端忽略 |
| `BEGIN:VEVENT` / `END:VEVENT` | 单个会议事件 | 主要内容都在事件里 |
| `SUMMARY` | 会议标题 | 决定用户第一眼看到什么 |
| `DESCRIPTION` | 会议描述 | 常放链接、说明、诱导文本 |
| `LOCATION` | 会议地点 | 可能显示 URL、会议链接或路径 |
| `ORGANIZER` | 组织者 | 影响可信度 |
| `DTSTART` / `DTEND` | 时间 | 影响是否显得真实 |
| `UID` | 唯一标识 | 避免重复或异常 |

常见误区：

| 误区 | 正确理解 |
|---|---|
| ICS 里有链接就一定触发 | 不同客户端对 DESCRIPTION/LOCATION/ATTACH 处理不同 |
| ORGANIZER 写谁都行 | 发件人、组织者、域名不一致会降低可信度 |
| 时间不重要 | 异常时间会让邀请显得很假 |

---

### 11. Creating a Custom Calendar Invite

原文让你手工构造邀请，是为了理解每个字段的展示效果。

逐段检查：

| 检查项 | 问题 |
|---|---|
| 标题 | 用户是否能理解这是一个正常业务会议 |
| 组织者 | 是否和场景一致 |
| 描述 | 链接或路径是否自然 |
| 时间 | 是否符合工作时间和时区 |
| 地点 | 是否像真实会议链接 |
| UID | 是否唯一 |

学习建议：

```
先做一个完全无害的 ICS，在 Outlook 或目标客户端里打开，
观察 SUMMARY、DESCRIPTION、LOCATION、ORGANIZER 分别显示在哪里。
看懂展示效果后，再理解为什么某些字段适合放链接或 UNC 路径。
```

---

### 12. Crafting The Full Calendar Phishing

完整日历钓鱼不是只写一个 ICS 文件，而是让邮件、邀请、链接、主题、组织者、业务语境一致。

| 层 | 要一致 |
|---|---|
| 邮件层 | 发件人、主题、正文、附件名 |
| 日历层 | ORGANIZER、SUMMARY、LOCATION、DESCRIPTION |
| 业务层 | 为什么这个用户会收到这个会议 |
| 技术层 | 链接/UNC 是否能被目标访问 |
| 证据层 | 是否能记录访问、认证或后续凭证验证 |

考试理解：

```
日历钓鱼成功不是“文件能打开”，而是它让目标产生了可利用的访问、认证或下载行为。
```

---

### 13. Automating the Attack

自动化的目的不是炫技，而是减少手工错误。

| 自动化内容 | 为什么重要 |
|---|---|
| 生成唯一 UID | 避免重复会议异常 |
| 自动设置时间 | 避免过期或时区错误 |
| 批量替换组织者/标题 | 适配不同目标 |
| 统一模板 | 减少格式错误 |
| 记录目标和时间 | 方便报告和复盘 |

初学者要警惕：自动化会放大错误。如果模板字段错了，批量生成的都错。

---

### 14. Credential Stealing with Responder

Responder 这一节的关键是理解“强制认证”。

链路是：

```text
ICS 中出现 UNC 路径
  -> Windows 尝试访问远程 SMB 资源
  -> 系统发起 NTLM 认证
  -> Responder 捕获 Net-NTLMv2
  -> 后续尝试破解或中继
```

最容易混淆的点：

| 材料 | 能不能直接登录 | 正确去向 |
|---|---|---|
| 明文密码 | 通常可以 | SMB/WinRM/RDP/MSSQL/LDAP 验证 |
| NTLM hash | 可用于部分 Pass-the-Hash 场景 | SMB/WinRM/远程执行条件判断 |
| Net-NTLMv2 | 不能直接 Pass-the-Hash | 破解或中继 |

所以 Responder 捕获成功只是开始，不是结束。下一步看：

1. 捕获到的是谁。
2. 来源主机是谁。
3. 能否破解。
4. 不能破解时是否能中继。
5. 拿到可用凭证后能访问哪里。

对应回退：`13-Windows凭证/06-Windows凭证新手闭环与材料去向.md`。

---

## 两条路线的考试决策

| 你看到的机会 | 优先路线 | 成功后进入 |
|---|---|---|
| 用户可能打开 Office 文档 | Office 宏 / HTML Smuggling | 命令执行、回连、主机枚举 |
| 宏被限制但可诱导点击 | JScript / HTA / 链接下载 | 客户端执行链 |
| 用户常处理会议邀请 | ICS 日历钓鱼 | 凭证捕获、链接点击 |
| 内网允许 SMB 出站 | ICS + UNC + Responder | Net-NTLMv2 破解/中继 |
| 出网走代理 | 代理感知下载/回连 | 网络过滤排错 |
| PowerShell 被拦 | JScript/C#/反射/白名单绕过 | 执行能力恢复 |

---

## 每段原文精读问题

读原文时每遇到一个小节，就问：

```text
这一节的对象是什么？Office 文档、宏、内存、PowerShell、ICS、UNC，还是凭证？
它解决什么问题？触发、执行、下载、内存运行、凭证捕获，还是自动化？
它需要什么前提？用户交互、宏启用、位数匹配、网络、代理、SMB 出站？
成功信号是什么？弹窗、命令输出、回连、HTTP 访问、Responder hash？
失败先查什么？格式、入口、策略、位数、网络、认证、工具参数？
```

---

## 报告证据清单

| 技术 | 至少保留 |
|---|---|
| VBA 宏触发 | 文档、宏入口、当前用户、主机名 |
| Win32 API/Shellcode Runner | 位数判断、执行结果、回连证明 |
| PowerShell Runner | PowerShell 版本、语言模式、执行结果 |
| 日历邀请 | ICS 内容、组织者、标题、触发字段 |
| Responder 捕获 | 原始 hash、来源 IP、用户名、时间 |
| 凭证后续 | 破解/中继/登录验证结果 |

---

## 闭卷自测

1. Office 宏为什么能成为初始访问入口？
2. `AutoOpen` 和 `Document_Open` 的价值是什么？
3. VBA 调 Win32 API 时，`PtrSafe` 和 `LongPtr` 解决什么问题？
4. Shellcode Runner 的四个核心动作是什么？
5. 为什么 PowerShell Shellcode Runner 和 VBA Shellcode Runner 本质相同？
6. ICS 中哪些字段影响用户看到的内容？
7. 日历钓鱼为什么更像凭证入口，而不是稳定代码执行入口？
8. Responder 捕获到 Net-NTLMv2 后，为什么不能直接当 NTLM hash 用？
9. 宏能运行但无回连，先查哪三类问题？
10. 日历邀请打开了但没有 hash，先查哪些字段和网络条件？

---

## 下一步阅读

| 如果你想继续 | 阅读 |
|---|---|
| 深入 VBA 基础 | `01-VBA基础.md` |
| 深入 Win32 API | `02-VBA调用Win32API.md` |
| 深入 VBA 内存执行 | `03-VBA-Shellcode执行器.md` |
| 深入 PowerShell 执行链 | `06-PowerShell-Shellcode.md` |
| 深入日历钓鱼 | `13-日历钓鱼攻击.md` |
| 做考前压缩 | `15-客户端初始访问考试速查.md` |
| 看新手闭环 | `16-Office宏攻击新手详解与考试闭环.md` |
