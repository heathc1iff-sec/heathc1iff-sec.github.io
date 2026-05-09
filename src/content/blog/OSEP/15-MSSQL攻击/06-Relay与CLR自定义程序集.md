---
title: OSEP-15-Relay与CLR自定义程序集
description: '15-MSSQL攻击 | 06-Relay与CLR自定义程序集'
pubDate: 2026-01-30T00:02:29+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Exploit Development
  - SQL Injection
---

# Relay My Hash 与 CLR 自定义程序集

## 对应课程小节

`15：mssql数据库攻击向量.html` 中除了枚举、认证、UNC Path Injection、xp_cmdshell、链接服务器，还包含 `Relay My Hash` 和 `Custom Assemblies`。这份补充把 MSSQL 从“能执行命令”扩展成“能中继、能跨边界、能加载代码”的思路。

---

## MSSQL 的三种价值

| 价值 | 说明 |
|---|---|
| 凭证入口 | UNC Path Injection 可触发 SQL Server 机器账户或服务账户认证 |
| 执行入口 | `xp_cmdshell`、Agent Job、OLE、CLR Assembly 等 |
| 横向入口 | Linked Server、跨域信任、数据库权限链 |

---

## UNC Path Injection 到 Relay

UNC Path Injection 的核心是让 SQL Server 去访问攻击者控制的 UNC 路径，从而触发 NTLM 认证。捕获 Hash 只是第一层；如果环境允许，中继可能更有价值。

判断链：

```
能执行 SQL 查询
  -> 能触发 SQL Server 访问 UNC
  -> 捕获到的是用户、服务账户还是机器账户
  -> 目标是否可被 NTLM Relay
  -> 中继后能访问 SMB/LDAP/ADCS/MSSQL 哪个服务
```

---

## Relay 价值判断

| 捕获身份 | 可能价值 |
|---|---|
| SQL 服务域账户 | 可能访问其他 SQL、文件共享或被委派 |
| SQL 机器账户 | 可能用于机器权限、RBCD、ADCS ESC8 |
| 高权限用户 | 可能直接横向或 LDAP 修改 |
| 低权限用户 | 可用于基础枚举、Kerberoast、ADCS 枚举 |

中继前要问：

1. 目标服务是否允许 NTLM。
2. SMB 签名或 LDAP 签名是否阻断。
3. 是否能中继到 ADCS HTTP 端点。
4. 是否能中继到另一台 MSSQL 或 SMB 服务。
5. 捕获身份是否对中继目标有权限。

---

## CLR 自定义程序集

CLR Assembly 路线适用于 `xp_cmdshell` 不可用或需要更灵活代码执行的场景。它利用 SQL Server 托管 .NET 集成能力，把自定义程序集加载进 SQL Server 上下文执行。

关键条件：

| 条件 | 说明 |
|---|---|
| `clr enabled` | SQL Server 允许 CLR |
| 足够数据库权限 | 创建程序集、函数或存储过程 |
| TRUSTWORTHY 或签名配置 | 影响高权限程序集执行 |
| 文件/字节载入方式 | 程序集从路径或十六进制内容导入 |
| SQL Server 进程权限 | 最终代码运行在 SQL Server 服务上下文 |

---

## CLR 与 xp_cmdshell 对比

| 项目 | xp_cmdshell | CLR Assembly |
|---|---|---|
| 开启难度 | 需要启用配置 | 需要启用 CLR 和创建程序集权限 |
| 灵活度 | 命令级 | .NET 代码级 |
| 检测点 | 命令执行明显 | 程序集创建和 CLR 执行明显 |
| 适用场景 | 快速命令执行 | 自定义逻辑、网络、文件、内存加载 |
| 常见卡点 | 被禁用、权限不足 | TRUSTWORTHY、权限集、程序集签名 |

---

## 权限提升思路

| 发现 | 方向 |
|---|---|
| 可模拟登录 | `EXECUTE AS` 后检查权限变化 |
| 数据库 TRUSTWORTHY 开启 | 结合 db_owner 到 sysadmin 的路径 |
| 可创建 CLR 程序集 | 尝试自定义代码执行或权限提升 |
| 链接服务器 | 递归枚举链接和远程权限 |
| SQL Agent 可用 | 通过 Job 执行命令或代理上下文 |

---

## 链接服务器与 Relay 联动

MSSQL 经常成为跨边界路径。复习时把它想成图：

```
当前 SQL 实例
  -> 链接服务器 A
  -> 链接服务器 B
  -> 另一个域/森林的 SQL
  -> 触发 UNC / 执行命令 / 读取凭证
```

每跳都要记录：

| 记录项 | 说明 |
|---|---|
| 当前 SQL 身份 | `SYSTEM_USER`、`ORIGINAL_LOGIN()` |
| 当前权限 | 是否 sysadmin、是否可模拟 |
| 链接方向 | 从哪里到哪里 |
| 远端身份 | 链接过去后变成谁 |
| 可执行能力 | 查询、文件、命令、CLR、Agent |

---

## Come Home To Me：链接服务器回连与身份判断

`15：mssql数据库攻击向量.html` 中的 Come Home To Me 可以理解为：利用 SQL 链接服务器的执行上下文，让远端 SQL 或服务账户主动访问你控制的 UNC/HTTP 资源，从而确认身份、触发认证或建立下一跳。

| 步骤 | 目标 | 关键记录 |
|---|---|---|
| 1. 找链路 | 枚举 linked servers 和 RPC Out | 本地实例、远端实例、链接方向 |
| 2. 确认上下文 | 查询 `SYSTEM_USER`、`ORIGINAL_LOGIN()` | 每一跳变成哪个 SQL/Windows 身份 |
| 3. 触发回连 | 用远端上下文访问 UNC/HTTP | 监听器看到的来源主机和账户 |
| 4. 判断价值 | Hash 能否破解/中继，身份能访问哪里 | 是否能转 SMB/LDAP/ADCS/MSSQL |
| 5. 落点选择 | 决定命令执行、Relay、读取数据还是继续跳 | 当前权限和失败原因 |

考试可用总结：链接服务器不要只看“能不能执行命令”，还要看“跨过去后是谁在替你访问资源”。这个身份变化经常比单次 SQL 查询更值钱。

---

## 失败排查

| 现象 | 排查 |
|---|---|
| UNC 不触发认证 | SQL Server 出网、服务账户权限、路径格式、SMB 被阻断 |
| 捕获 Hash 不能破解 | 转向 Relay，不要只耗字典 |
| Relay 失败 | 签名、EPA、目标服务不支持、身份权限不足 |
| CLR 创建失败 | 权限、CLR 配置、TRUSTWORTHY、程序集权限集 |
| Linked Server 无法执行 | RPC Out、远端权限、查询语法、链接上下文 |
| xp_cmdshell 启用失败 | 当前不是 sysadmin 或配置权限不足 |

---

## 证据记录

| 阶段 | 证据 |
|---|---|
| 枚举 | 实例、数据库、权限、链接服务器 |
| UNC | 触发查询和捕获到的认证身份 |
| Relay | 中继目标、认证身份、成功后的访问能力 |
| CLR | 配置状态、程序集创建、执行结果 |
| 横向 | 从 SQL 到主机或域权限变化 |
