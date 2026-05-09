---
title: OSEP-14-RDP与Fileless横向移动补充
description: '14-横向移动 | 06-RDP与Fileless横向移动补充'
pubDate: 2026-01-30T00:02:21+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Active Directory
  - Lateral Movement
---

# RDP 与 Fileless 横向移动补充

## 对应课程小节

`14：windows横向利用（rdp+psexec）.html` 重点包含 RDP、Reverse RDP Proxying、RDP as a Console、Stealing Clear Text Credentials from RDP，以及 Fileless Lateral Movement 的认证与执行理论、C# 实现。

现有横向移动章节已经覆盖 PsExec/WMI/WinRM/DCOM，这份补充专门整理 RDP 和 Fileless 的考试判断。

---

## 横向移动不是只有执行命令

横向移动有三类目标：

| 目标 | 例子 |
|---|---|
| 交互访问 | RDP、反向 RDP、跳板代理 |
| 远程执行 | PsExec、WMI、WinRM、SCM、计划任务 |
| 凭证与会话利用 | RDP 明文、Token、票据、机器账户 |

RDP 的价值在于交互和凭证暴露；Fileless 的价值在于减少落地和服务创建痕迹。

---

## RDP 判断链

```
目标是否开放 RDP
  -> 当前凭证是否允许登录
  -> 是否需要穿透网络边界
  -> 是否启用 NLA / Restricted Admin / CredSSP
  -> 登录是否会暴露凭证
  -> 会不会影响目标用户会话
```

---

## Reverse RDP Proxy 场景

当攻击机无法直接访问目标 RDP，但已有中间主机执行能力时，反向 RDP 代理可以把目标的 RDP 暴露回攻击端。

| 条件 | 说明 |
|---|---|
| 中间主机能访问目标 RDP | 内网连通性成立 |
| 中间主机能出站到攻击机 | 反向通道成立 |
| 攻击机本地能接收代理端口 | 本地客户端连接代理端 |
| 凭证可用 | 代理只解决网络，不解决认证 |

常见卡点：

| 现象 | 排查 |
|---|---|
| 代理连上但 RDP 黑屏 | NLA、CredSSP、网络延迟、图形会话限制 |
| 端口转发成功但认证失败 | 凭证、域名格式、本地/域账户混淆 |
| 登录踢掉用户 | 目标系统会话策略和用户会话状态 |
| 连接被断 | 防火墙、代理进程退出、出站过滤 |

---

## RDP as a Console

RDP 不只是 GUI 登录，也可以作为“远程控制台”来完成工具触发、凭证观察和管理动作。

| 场景 | 适合用 RDP | 更适合换路 |
|---|---|---|
| 需要点击管理控制台或浏览器 | 是，GUI 价值高 | 无 |
| 只需要执行单条命令 | 不优先 | WinRM/WMI/SCM 更轻 |
| 需要观察用户会话或复制交互结果 | 是 | Token/凭证已足够时可转命令执行 |
| 网络只能通过跳板访问 3389 | 是，配合反向 RDP 代理 | 若 NLA/策略阻断，转 SMB/WinRM |
| 防护盯服务创建/PsExec | 可以尝试 | 也可尝试 WMI/DCOM/Fileless |

证据记录：RDP 入口、目标主机、登录身份、是否创建新会话、是否影响已有用户会话、完成的关键操作。

---

## RDP 明文凭证风险

RDP 登录可能让凭证进入目标的认证缓存，后续可被高权限上下文读取。考试里这通常和 Windows Credentials、Token 模拟、LSASS Dump 联动。

判断问题：

1. 是否真的需要 RDP 登录，还是可以用 WinRM/WMI 完成目标。
2. RDP 登录是否会改变目标状态或影响用户。
3. 登录后能否获得更高价值 Token 或凭证。
4. 目标是否启用 Credential Guard 或 Restricted Admin。
5. 是否有报告证据证明凭证暴露路径。

---

## Fileless 横向移动理论

Fileless 横向移动的核心不是“不产生任何痕迹”，而是尽量避免上传大二进制或创建明显服务。

典型流程：

```
认证到远程主机
  -> 使用远程管理接口创建进程或执行命令
  -> 命令从内存/网络加载载荷
  -> 载荷在目标内存中执行
  -> 回连或执行指定动作
```

常用接口对比：

| 接口 | 优点 | 痕迹 |
|---|---|---|
| WMI | 不一定需要上传文件，适合命令执行 | WMI 事件、进程创建 |
| WinRM | PowerShell 原生，交互性好 | PowerShell 日志、WinRM 日志 |
| SCM/PsExec | 稳定，权限明确 | 服务创建、文件上传 |
| DCOM | 依赖组件，可绕开部分习惯检测 | DCOM 事件、组件调用 |
| 计划任务 | 稳定，可延迟执行 | 任务创建记录 |

---

## C# 实现时关注的 API/组件

| 功能 | 关注点 |
|---|---|
| 远程认证 | 域、用户、Hash/票据、当前 Token |
| 服务控制 | SCM、服务创建、启动、删除 |
| 远程写入 | ADMIN$、IPC$、命名管道 |
| 进程创建 | WMI、WinRM、服务二进制路径 |
| 内存执行 | 反射加载、Shellcode Runner、进程注入 |
| 输出回收 | SMB 临时文件、管道、HTTP 回连 |

---

## Fileless C# API 调用链

| 阶段 | 关注 API/组件 | 排错点 |
|---|---|---|
| 认证 | `LogonUser`、当前 Token、Kerberos/NTLM | 域名格式、时间同步、凭证类型 |
| 连接远程管理面 | SCM、WMI、WinRM、DCOM、ADMIN$ | 端口、防火墙、本地管理员权限 |
| 投递能力 | 反射加载、内存加载、命名管道、临时服务参数 | 架构、路径、AV/AMSI、命令长度 |
| 执行与回连 | 服务启动、远程进程创建、HTTP/SMB 回连 | 出网、代理、监听器、父进程 |
| 清理与证据 | 服务删除、临时文件、日志时间线 | 不要丢失截图和命令输出 |

考试可用总结：Fileless 的优势是少落地，但失败排查更依赖每一层状态。记录认证、远程管理面、执行和回连四个检查点，比只记录最终 Shell 更有用。

---

## 方法选择表

| 当前条件 | 首选 |
|---|---|
| 有本地管理员密码/Hash，SMB 开放 | PsExec/SCM 或 WMI |
| 有 Kerberos 票据，目标域名可解析 | Kerberos 方式的 WMI/SMB |
| WinRM 开放且凭证有效 | WinRM |
| 只能访问 RDP | RDP 或 RDP 代理 |
| 不想上传文件 | WMI/WinRM + 内存加载 |
| 需要 GUI 操作 | RDP |
| 防护盯服务创建 | WMI/WinRM/DCOM |

---

## 失败排查

| 问题 | 排查 |
|---|---|
| `Access denied` | 是否本地管理员、UAC 远程限制、域/本地账户格式 |
| `STATUS_LOGON_FAILURE` | 密码/Hash 格式、域名、时间同步、账户锁定 |
| Kerberos 失败 | SPN、DNS、时间、票据格式、`KRB5CCNAME` |
| 命令执行无输出 | 输出重定向、临时文件权限、命令解释器路径 |
| 回连失败 | 出网、代理、防火墙、监听器、Payload 架构 |
| RDP 不通 | NLA、端口、策略、代理链、证书/CredSSP |

---

## 相关文件

| 主题 | 文件 |
|---|---|
| Windows 凭证 | `13-Windows凭证/05-Token与MiniDump离线处理.md` |
| 横向移动基础 | `14-横向移动/01-横向移动技术.md` |
| Windows 横向 | `14-横向移动/03-Windows横向移动.md` |
| 攻击链 | `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` |
