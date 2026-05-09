---
title: OSEP-00-OSEP术语速查与概念对照
description: '00-学习计划 | 03-OSEP术语速查与概念对照'
pubDate: 2026-01-27T08:00:03+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Life
---

# OSEP 术语速查与概念对照

这份表不是字典式百科，而是给初学者看的“看到这个词时，我应该怎么理解它”。如果你有 Web 安全背景，可以把很多系统和域内概念类比成 Web 里的会话、鉴权、上传、执行、代理和权限模型。

## 怎么使用

1. 第一次遇到陌生词，先看“人话解释”。
2. 再看“为什么重要”，确认它在攻击链里的位置。
3. 最后看“关联章节”，回到对应文档深入学习。

## Windows 与编程基础

| 术语 | 人话解释 | 为什么重要 | 关联章节 |
|---|---|---|---|
| Win32 API | Windows 暴露给程序调用系统能力的一组函数 | Shellcode Runner、进程注入、文件操作、线程创建都会用到 | `02-操作系统与编程理论` |
| 托管代码 | 运行在 .NET CLR 等运行时里的代码 | PowerShell、C#、反射都和 .NET 运行时有关 | `02-操作系统与编程理论` |
| 非托管代码 | 直接由操作系统执行的原生代码 | Win32 API、Shellcode、DLL 注入常属于这个层面 | `02-操作系统与编程理论` |
| P/Invoke | .NET 调用原生 DLL 函数的机制 | PowerShell/C# 调用 `VirtualAlloc`、`CreateThread` 时常用 | `03-Office宏攻击`、`05-反射式PowerShell` |
| WOW64 | 64 位 Windows 上运行 32 位程序的兼容层 | 位数不匹配会导致注入、DLL 加载和 API 调用失败 | `02-操作系统与编程理论` |
| Registry | Windows 注册表，存储系统和应用配置 | 持久化、策略、组件注册、环境判断都会碰到 | `02-操作系统与编程理论` |

## 客户端执行

| 术语 | 人话解释 | 为什么重要 | 关联章节 |
|---|---|---|---|
| Macro | Office 文档里的自动化脚本 | 初始访问常见入口之一 | `03-Office宏攻击` |
| VBA | Office 宏常用语言 | 可调用 Win32 API，也可启动 PowerShell | `03-Office宏攻击` |
| HTML Smuggling | 用 HTML/JS 在浏览器端拼装或投递文件 | 用于绕过某些下载检查或投递限制 | `03-Office宏攻击` |
| WSH | Windows Script Host，执行 JScript/VBScript 的宿主 | JScript 投递、DotNetToJScript 会用到 | `04-JScript攻击` |
| DotNetToJScript | 把 .NET 程序封装到 JScript 里执行的技术 | 连接 JScript 初始执行和 C# 能力 | `04-JScript攻击` |

## 内存执行与注入

| 术语 | 人话解释 | 为什么重要 | 关联章节 |
|---|---|---|---|
| Shellcode | 一段可以直接在内存里执行的机器码 | 很多客户端执行、注入和后渗透载荷都围绕它展开 | `03-Office宏攻击`、`06-进程注入` |
| VirtualAlloc | 在进程内分配内存的 Win32 API | Shellcode Runner 常用的第一步 | `03-Office宏攻击` |
| CreateThread | 创建线程执行代码的 Win32 API | 常用于让 shellcode 开始运行 | `03-Office宏攻击` |
| Process Injection | 把代码放进另一个进程里执行 | 用来迁移、隐藏或借用目标进程上下文 | `06-进程注入` |
| DLL Injection | 把 DLL 加载到目标进程 | 进程注入的一类常见形式 | `06-进程注入` |
| Reflective DLL | 不依赖正常 LoadLibrary 路径的 DLL 加载方式 | 减少落地和传统加载痕迹 | `06-进程注入` |
| Process Hollowing | 创建合法进程后掏空并替换其内存 | 伪装进程映像和执行上下文 | `06-进程注入` |

## 防护绕过

| 术语 | 人话解释 | 为什么重要 | 关联章节 |
|---|---|---|---|
| AV | 杀毒软件，检查文件、内存或行为 | 文件落地和执行时经常被拦 | `07-杀软绕过` |
| Signature | 特征码或检测规则 | 修改特征可以解释为什么同一 payload 有时被拦 | `07-杀软绕过` |
| AMSI | Windows 反恶意软件扫描接口 | PowerShell、JScript 等脚本内容常会经过它 | `08-AMSI绕过` |
| CLM | PowerShell 受限语言模式 | 会限制 Add-Type、反射、COM 等高级能力 | `08-AMSI绕过`、`09-应用白名单绕过` |
| AppLocker | Windows 应用白名单 | 决定哪些程序、脚本、安装包能运行 | `09-应用白名单绕过` |
| LOLBAS | 利用系统自带或可信程序完成执行/加载 | 白名单环境中的重要思路 | `09-应用白名单绕过` |
| WDAC | 更强的 Windows 应用控制机制 | 理解它有助于区分 AppLocker 与更现代的控制策略 | `09-应用白名单绕过` |

## 网络与出网

| 术语 | 人话解释 | 为什么重要 | 关联章节 |
|---|---|---|---|
| Egress Filtering | 出站过滤 | 决定目标能否连到外部监听器或 C2 | `10-网络过滤绕过` |
| Proxy | 代理服务器 | 企业常要求 HTTP/HTTPS 出网经过代理 | `10-网络过滤绕过` |
| IDS/IPS | 入侵检测/防御系统 | 会根据流量特征报警或阻断 | `10-网络过滤绕过` |
| HTTPS Inspection | HTTPS 解密检查 | 可能导致证书异常、连接失败或内容被审查 | `10-网络过滤绕过` |
| Domain Fronting | 利用 CDN/云平台隐藏真实目的地 | 用于理解 HTTPS 层面的流量伪装 | `10-网络过滤绕过` |
| DNS Tunneling | 通过 DNS 查询和响应传输数据 | 受限出网环境中的低带宽备选通道 | `10-网络过滤绕过` |

## 凭证与横向移动

| 术语 | 人话解释 | 为什么重要 | 关联章节 |
|---|---|---|---|
| SAM | 本地 Windows 账户哈希数据库 | 本地凭证获取会遇到 | `13-Windows凭证` |
| LSASS | 存放认证材料的关键进程 | Mimikatz、MiniDump、凭证提取常围绕它 | `13-Windows凭证` |
| Token | Windows 访问令牌 | 表示某个进程/线程当前拥有什么身份和权限 | `13-Windows凭证` |
| Impersonation | 模拟另一个用户的 Token | 横向和提权场景常见 | `13-Windows凭证` |
| RDP | 远程桌面协议 | 交互式横向移动和凭证暴露都可能涉及 | `14-横向移动` |
| Fileless | 尽量不落地文件的执行方式 | 横向移动和防护绕过经常结合 | `14-横向移动` |
| Keytab | Linux 上保存 Kerberos 密钥的文件 | Linux 加入域后可能成为横向移动材料 | `11-Linux后渗透` |
| ccache | Kerberos 票据缓存 | Linux 域内认证和横向移动会用到 | `11-Linux后渗透` |

## Active Directory

| 术语 | 人话解释 | 为什么重要 | 关联章节 |
|---|---|---|---|
| AD | Active Directory，Windows 域身份和权限系统 | OSEP 后半段多数攻击链围绕它 | `16-AD权限滥用` |
| ACL | 对象访问控制列表 | 决定谁能改用户、组、计算机、GPO 等对象 | `16-AD权限滥用` |
| GenericAll | 对某个 AD 对象几乎完全控制 | 常可转化为重置密码、加组或配置委派 | `16-AD权限滥用` |
| WriteDACL | 修改对象权限列表的权限 | 可以给自己加更多权限 | `16-AD权限滥用` |
| Kerberos | 域内常用认证协议 | 委派、票据、跨域信任都和它有关 | `17-Kerberos委派` |
| Delegation | 服务代表用户访问资源的机制 | 配置不当时可被滥用横向移动 | `17-Kerberos委派` |
| RBCD | 基于资源的约束委派 | 常见的计算机对象滥用路径 | `17-Kerberos委派` |
| Forest Trust | 域森林间信任 | 跨域、跨森林攻击的基础 | `18-域森林攻击` |
| Extra SID | 在票据中加入额外 SID 的攻击思路 | 跨域/森林攻击链中的关键概念 | `18-域森林攻击` |
| ADCS | Active Directory Certificate Services | 证书模板误配置可能换来认证能力 | `21-ADCS证书攻击` |
| ESC | ADCS 常见误配置类别 | 用于快速判断证书攻击路径 | `21-ADCS证书攻击` |
| JEA | Just Enough Administration | 限制管理员能做什么，配置不当可突破 | `19-JEA与JIT` |
| JIT | Just-In-Time Administration | 临时提权机制，可能存在利用窗口 | `19-JEA与JIT` |

## Web 安全类比

| Web 安全里的概念 | OSEP 里相似的概念 | 类比方式 |
|---|---|---|
| XSS | 客户端代码执行 | 都是让代码在别人上下文里运行 |
| 文件上传绕过 | AppLocker/AV 绕过 | 都是在限制条件下找到可执行路径 |
| SSRF 出网限制 | 网络过滤绕过 | 都需要判断目标能访问哪里 |
| Cookie / Session | Token / Kerberos Ticket | 都表示身份状态 |
| 后台权限 | AD 对象权限 | 权限决定你能操作哪些资源 |
| 供应链密钥泄露 | Ansible / Artifactory 凭证泄露 | 自动化系统常带高价值凭证 |

## 背不住怎么办

术语不用一次背完。你只需要把每个词放进一个问题里：

```text
它属于执行、绕过、通信、凭证、横向、AD 哪一类？
它解决什么限制？
它需要什么前提？
它失败时通常卡在哪里？
```

能回答这四个问题，就已经比单纯背命令更接近真正理解。
