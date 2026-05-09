---
title: OSEP-13-Token与MiniDump离线处理
description: '13-Windows凭证 | 05-Token与MiniDump离线处理'
pubDate: 2026-01-30T00:02:13+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Credential Dumping
---

# Token、RDP 凭证与 MiniDump 离线处理

## 对应课程小节

`13：windows凭证.html` 中除了 SAM 和 Mimikatz，还覆盖 Access Token、Impersonation、Incognito、Kerberos/域凭证、Memory Dump、MiniDumpWriteDump。现有章节已经有凭证提取基础，这份补充重点整理考试里的判断顺序和离线处理思路。

---

## 凭证材料分类

| 类型 | 例子 | 价值 |
|---|---|---|
| 明文凭证 | 密码、配置文件、RDP 明文 | 可直接登录和复用 |
| Hash | NTLM、DCC2、NetNTLMv2 | PTH、破解、离线分析 |
| Token | Primary/Impersonation Token | 本地权限切换、访问远程资源 |
| Kerberos 票据 | TGT、TGS、kirbi、ccache | PTT、委派、服务访问 |
| Dump | LSASS Dump、MiniDump | 离线提取，降低在线工具被杀风险 |
| 证书 | PFX、PEM、私钥 | PKINIT、Schannel、WinRM 证书认证 |

---

## Access Token 复习重点

Access Token 代表“当前线程或进程以谁的身份访问资源”。考试里最重要的是区分：

| Token 类型 | 含义 | 常见利用 |
|---|---|---|
| Primary Token | 进程主令牌 | 创建新进程 |
| Impersonation Token | 线程模拟令牌 | 临时模拟用户访问资源 |
| Delegation Token | 可用于远程访问的委派令牌 | 横向移动价值更高 |
| Identification Token | 只能识别身份 | 通常不能直接访问远程资源 |

判断问题：

1. 当前进程是否有高价值用户的 Token。
2. Token 是 Delegation 还是 Impersonation。
3. 当前权限是否允许模拟或复制 Token。
4. 模拟后能访问的是本地资源还是远程资源。
5. 是否能把 Token 转成新进程或远程访问能力。

---

## Incognito/Token 路线

Token 利用经常出现在“本机有管理员或 SYSTEM，但没有明文域凭证”的阶段。

```
获得本地高权限
  -> 枚举 Token
  -> 找高价值域用户 Token
  -> 模拟 Token
  -> 访问远程资源或执行横向移动
```

常见卡点：

| 现象 | 排查 |
|---|---|
| 看不到高价值 Token | 目标用户没有登录、会话隔离、权限不足 |
| 模拟成功但远程失败 | Token 不是 Delegation、目标服务不接受、网络/防火墙 |
| 模拟后命令仍是原用户 | 只模拟线程，创建新进程方式不对 |
| 工具被杀 | 换离线 Dump、系统 API、已有工具或手工验证访问 |

---

## RDP 明文凭证风险

`windows横向利用` 课程里提到 RDP 明文凭证窃取，和 Windows Credentials 章节是联动关系。复习时要理解：RDP 不是只用于登录，也可能制造凭证暴露面。

| 场景 | 关注点 |
|---|---|
| 用户通过 RDP 登录受控主机 | LSASS 中可能出现可复用凭证 |
| RDP 反代或跳板 | 凭证输入路径和代理端控制点 |
| Restricted Admin | 减少明文暴露，但可能允许 Hash/票据登录 |
| Credential Guard | 影响 LSASS 中可提取材料 |

考试判断：

1. 是否能诱导或等待高价值用户登录。
2. 是否能观察到 RDP 会话进程。
3. 目标是否启用 Credential Guard、Restricted Admin、Remote Credential Guard。
4. 是提取明文、Hash、票据，还是只拿 Token。

---

## MiniDump 离线处理

离线处理的价值是：在线阶段只做最少动作，把 LSASS 内存转成文件，后续在自己机器上慢慢分析。

优点：

| 优点 | 说明 |
|---|---|
| 降低在线暴露 | 目标上不一定要直接运行完整 Mimikatz |
| 便于反复分析 | Dump 可多工具、多版本解析 |
| 便于绕过工具拦截 | 只要能创建 Dump，就能把分析转移出去 |

风险：

| 风险 | 说明 |
|---|---|
| 文件很大 | 传输慢，容易被监控 |
| Dump 行为敏感 | EDR 常监控 LSASS 句柄和转储行为 |
| PPL/Credential Guard | 可能阻止读取有效内容 |
| 权限要求高 | 通常需要管理员/SYSTEM 和调试权限 |

---

## MiniDump 判断链

```
我是否有足够权限？
  -> LSASS 是否受 PPL/Credential Guard 保护？
  -> 能否安全创建 Dump？
  -> Dump 能否传出？
  -> 离线工具能否解析？
  -> 解析结果能否转成横向移动材料？
```

---

## 凭证材料到下一步动作映射表

| 材料 | 先验证 | 常见下一步 | 卡住时 |
|---|---|---|---|
| 本地 SAM Hash | 是否本地管理员复用 | SMB/WMI/PsExec/WinRM 的 PTH | 查目标本地管理员、UAC、SMB 签名 |
| 明文密码 | 域/本地身份、是否过期 | RDP、WinRM、SMB、MSSQL、VPN/应用 | 查账户锁定、域名格式、登录限制 |
| Kerberos 票据 | 票据服务、有效期、目标 SPN | PTT 访问 CIFS/LDAP/HTTP/WinRM | 查 DNS、时间同步、SPN、票据格式 |
| Delegation Token | 是否可委派到远程主机 | 模拟后访问 SMB/服务或触发横向 | 若只能本地用，转本机文件/配置/LSASS |
| RDP 明文/缓存凭证 | 是否能登录目标或跳板 | GUI 操作、RDP as Console、凭证复用 | 查 NLA、组策略、跳板网络 |
| LSASS MiniDump | 能否离线解析出 Hash/明文/票据 | 转 Hash、票据、机器账户攻击 | 查 PPL/Credential Guard、架构和工具版本 |
| 机器账户 Hash | SPN/委派/LDAP 权限 | S4U、RBCD、机器证书、资源访问 | 查目标服务名、票据可转发、机器权限 |

考试可用总结：凭证不是终点。每拿到一种材料，都要立刻问“它能登录哪里、能代表谁、能否转成委派/证书/横向移动能力”。

---

## 优先级建议

| 当前权限 | 优先凭证动作 |
|---|---|
| 普通用户 | 浏览器、配置文件、历史命令、DPAPI 用户上下文 |
| 本地管理员 | SAM、LSASS Dump、服务凭证、计划任务 |
| SYSTEM | Token、LSASS、机器账户、DPAPI System MasterKey |
| 域用户 | Kerberoast、AS-REP、ADCS、BloodHound、MSSQL |
| 域管理员 | DCSync、NTDS、域控证据、报告固化 |

---

## 报告证据

| 证据 | 说明 |
|---|---|
| 当前身份和权限 | 证明为什么能访问凭证材料 |
| 保护状态 | PPL、Credential Guard、Defender 状态 |
| Dump 或 Token 枚举结果 | 证明凭证来源 |
| 后续登录或访问结果 | 证明凭证影响 |
| 清晰时间线 | 说明凭证从哪里来、用到了哪里 |
