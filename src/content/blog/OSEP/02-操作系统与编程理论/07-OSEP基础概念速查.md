---
title: OSEP-02-OSEP基础概念速查
description: '02-操作系统与编程理论 | 07-OSEP基础概念速查'
pubDate: 2026-01-30T00:00:07+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
---

# OSEP 基础概念速查

## 定位

这不是替代前面理论章节的长文，而是考前把 Windows、.NET、Win32 API、WOW64、注册表这些基础概念快速串起来的“判断卡”。当你遇到代码跑不起来、Payload 位数不对、API 调用失败、脚本被限制时，先用这张表找方向。

---

## 一张总图

```
执行载体
├── Office / JScript / PowerShell / C# / 原生 EXE
│
运行时
├── VBA Runtime / WSH / PowerShell Host / .NET CLR / Win32
│
系统边界
├── 用户权限 / 完整性级别 / 会话 / 位数 / 策略
│
能力落点
├── 内存执行 / 进程注入 / 凭证读取 / 横向移动 / 域枚举
│
拦截点
└── AV / AMSI / CLM / AppLocker / EDR / 代理 / 防火墙
```

考试里不要只问“这个命令怎么写”，要先问“我当前在哪一层被卡住”。

---

## 核心概念地图

| 概念 | 你要会判断什么 | 常见失败信号 |
|---|---|---|
| 进程 | 代码在哪个程序上下文里跑 | 目标进程退出、权限不够、会话不对 |
| 线程 | 代码由哪个执行单元启动 | 线程创建成功但无回连、目标崩溃 |
| 虚拟内存 | 数据是否可写、可执行、可读 | Access violation、写入失败、执行失败 |
| 句柄 | 是否拿到了访问对象的“门票” | OpenProcess 失败、Access denied |
| 完整性级别 | Medium/High/System 的权限差异 | 管理员组用户仍不能做高权限操作 |
| WOW64 | 32 位进程跑在 64 位系统上 | API 结构体、Shellcode、路径重定向异常 |
| P/Invoke | C# 调 Win32 API 的桥 | DllImport 签名错误、参数类型不匹配 |
| 反射 | 运行时查找类型、方法、字段 | 类型名变化、策略限制、AMSI 拦截 |
| 注册表 | 系统和程序配置数据库 | 读得到但写不了、HKLM/HKCU 混淆 |

---

## 进程、线程、内存速查

| 问题 | 优先检查 |
|---|---|
| 我能不能注入某个进程 | 位数一致、权限足够、目标稳定、不是受保护进程 |
| Shellcode 执行后没反应 | 回连网络、内存权限、线程入口、payload 架构 |
| 目标程序崩溃 | Shellcode 位数错、调用约定错、入口点错、内存保护错 |
| 远程线程创建失败 | 句柄权限不足、EDR 拦截、进程保护、跨会话限制 |
| 本地 runner 能跑，注入不行 | 远程内存写入、目标架构、目标权限、会话上下文 |

记忆方式：

```
能不能跑 = 位数 + 权限 + 内存 + 线程 + 网络
```

---

## x86 / x64 / WOW64 判断卡

| 现象 | 可能原因 | 处理思路 |
|---|---|---|
| 32 位 payload 在 64 位进程中失败 | 架构不匹配 | 保持 runner、shellcode、目标进程同架构 |
| `System32` 路径行为异常 | WOW64 文件系统重定向 | 区分 32 位进程看到的 `SysWOW64` |
| 结构体字段错位 | 指针长度不一致 | `IntPtr` 优先于固定 `int` |
| C# P/Invoke 在一台机器成功另一台失败 | 系统位数或权限不同 | 先输出当前进程位数、OS 位数、完整性级别 |

考场建议：每个自定义工具都保留一个“环境自检输出”，至少打印：

```
当前用户、进程位数、OS 位数、完整性级别、当前目录、网络目标
```

---

## .NET、P/Invoke 与反射

| 技术 | 适合场景 | 风险点 |
|---|---|---|
| Add-Type | 快速编译 C# 调 Win32 API | 可能落编译痕迹、容易被 AMSI 扫 |
| P/Invoke | C# 直接调用 Win32 API | 签名、结构体、权限要准确 |
| 反射 | 不落地调用 .NET 类型和方法 | 代码复杂、容易被策略/签名拦 |
| DelegateType | 动态构造函数指针调用 | 调试难度高、参数错就崩 |
| DotNetToJScript | JScript 承载 .NET 能力 | WSH、COM、AMSI/AV 都可能影响 |

判断顺序：

```
脚本能否执行
├── 不能：先看 AppLocker/CLM/AMSI
└── 能：再看 .NET 类型加载、API 签名、位数、网络
```

---

## 常用 Win32 API 分类

| 类型 | 常见 API | 用途 |
|---|---|---|
| 内存 | `VirtualAlloc`, `VirtualProtect`, `VirtualAllocEx` | 分配或修改内存权限 |
| 写入 | `Marshal.Copy`, `WriteProcessMemory` | 把代码或数据写入内存 |
| 线程 | `CreateThread`, `CreateRemoteThread` | 启动本地或远程执行 |
| 进程 | `OpenProcess`, `CreateProcess` | 获取目标进程或创建新进程 |
| 模块 | `LoadLibrary`, `GetProcAddress` | 加载 DLL、解析函数地址 |
| 权限 | `OpenProcessToken`, `DuplicateToken` | Token 操作和模拟 |

最小理解：这些 API 不是孤立命令，而是一条链。

```
分配内存 -> 写入数据 -> 修改权限 -> 创建线程 -> 等待/观察结果
```

---

## 注册表与系统配置

| 位置 | 你要关注什么 |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | 当前用户登录启动项 |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | 全局登录启动项，通常需要高权限 |
| `HKLM\System\CurrentControlSet\Services` | 服务路径、权限、启动方式 |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` | 已安装软件和版本 |
| AppLocker/SRP 相关策略路径 | 判断脚本、EXE、DLL 是否被限制 |

考试中读注册表的主要目的不是“持久化”，而是确认环境、软件、策略和潜在提权点。

---

## 基础排错顺序

1. 确认当前身份：`whoami`、组、完整性级别。
2. 确认进程位数：runner、payload、目标进程是否一致。
3. 确认策略限制：AMSI、CLM、AppLocker、Defender。
4. 确认网络：DNS、代理、端口、TLS、回连监听。
5. 确认 API 返回值：不要只看“程序没报错”。
6. 确认证据：保留错误、环境、命令和关键输出。

---

## 闭卷自测

```
□ 能解释进程和线程的区别吗？
□ 能解释为什么 x86 payload 不能随便注入 x64 进程吗？
□ 能说出 P/Invoke 的作用和常见坑吗？
□ 能把 VirtualAlloc、WriteProcessMemory、CreateThread 串成执行链吗？
□ 能区分 AMSI、CLM、AppLocker 分别卡在哪一层吗？
```
