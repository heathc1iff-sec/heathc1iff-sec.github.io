---
title: OSEP-03-Office安全机制
description: '03-Office宏攻击 | 11-Office安全机制'
pubDate: 2026-01-30T00:00:20+08:00
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

# Office 2021 安全机制详解

## 概述

Microsoft Office 2021 和 Office 365 引入了更严格的宏安全机制，默认阻止从互联网下载的文档中的宏执行。本文详细介绍这些安全机制及其影响。

## 宏安全演变

### 版本对比

| Office 版本 | 宏默认行为 | 绕过难度 |
|-------------|-----------|----------|
| Office 2016 | 提示启用 | 低 |
| Office 2019 | 提示启用 | 低 |
| Office 2021 | 默认阻止 | 高 |
| Office 365 | 默认阻止 | 高 |

### Office 2016/2019 行为

```
用户打开文档
    ↓
显示安全警告
    ↓
用户点击"启用内容"
    ↓
宏执行
```

### Office 2021/365 行为

```
用户打开文档（来自互联网）
    ↓
宏被完全阻止
    ↓
无法通过点击启用
    ↓
需要手动解除 MoTW
```

## Mark of the Web (MoTW)

### 什么是 MoTW

Mark of the Web 是 Windows 用于标记从互联网下载文件的属性。当文件从互联网下载时，Windows 会自动添加此标记。

### 查看 MoTW

1. 右键点击文件
2. 选择"属性"
3. 查看"安全"部分

```
┌─────────────────────────────────────────┐
│ 属性                                     │
├─────────────────────────────────────────┤
│ 安全: 此文件来自其他计算机，可能被阻止   │
│       以帮助保护此计算机。               │
│                                         │
│ [√] 解除锁定                            │
└─────────────────────────────────────────┘
```

### MoTW 存储位置

MoTW 存储在 NTFS 备用数据流 (ADS) 中：

```
文件名:Zone.Identifier
```

### 查看 ADS

```powershell
# 使用 PowerShell 查看
Get-Content -Path "document.doc" -Stream Zone.Identifier

# 输出示例
[ZoneTransfer]
ZoneId=3
```

Zone ID 含义：
- 0 = 本地计算机
- 1 = 本地 Intranet
- 2 = 受信任的站点
- 3 = Internet
- 4 = 受限制的站点

## 绕过 MoTW

### 方法 1：手动解除

1. 右键点击文件 → 属性
2. 勾选"解除锁定"
3. 点击"应用"

### 方法 2：PowerShell 解除

```powershell
# 解除单个文件
Unblock-File -Path "C:\path\to\document.doc"

# 解除目录下所有文件
Get-ChildItem -Path "C:\path\to\folder" -Recurse | Unblock-File
```

### 方法 3：删除 ADS

```powershell
# 删除 Zone.Identifier 流
Remove-Item -Path "document.doc" -Stream Zone.Identifier
```

### 方法 4：使用不支持 ADS 的文件系统

将文件复制到 FAT32 或 exFAT 格式的驱动器，然后复制回来：

```
NTFS (有 MoTW) → FAT32 (无 ADS) → NTFS (无 MoTW)
```

## 攻击者视角

### 社会工程绕过

攻击者需要说服用户手动解除 MoTW：

**示例预文本**：

```
重要：安全文档查看说明

由于安全原因，此文档已加密。
要查看内容，请按以下步骤操作：

1. 右键点击文档 → 属性
2. 勾选"解除锁定"
3. 点击"应用"
4. 打开文档并启用内容

如有问题，请联系 IT 支持。
```

### 替代攻击向量

由于 Office 2021 的限制，攻击者转向其他方法：

1. **ISO/IMG 文件** - 挂载后的文件没有 MoTW
2. **ZIP 文件** - 某些解压工具不保留 MoTW
3. **LNK 文件** - 快捷方式攻击
4. **OneNote** - 嵌入恶意对象
5. **HTML Smuggling** - 在浏览器中生成文件

## Trust Center 设置

### 访问 Trust Center

```
文件 → 选项 → 信任中心 → 信任中心设置
```

### 宏设置选项

| 设置 | 说明 |
|------|------|
| 禁用所有宏，无通知 | 最安全，完全阻止 |
| 禁用所有宏，并发出通知 | 默认设置 |
| 禁用无数字签名的宏 | 只允许签名宏 |
| 启用所有宏 | 最不安全 |

### Protected View 设置

Protected View 是 Office 2010 引入的沙箱功能：

```
┌─────────────────────────────────────────┐
│ Protected View 设置                      │
├─────────────────────────────────────────┤
│ [√] 为来自 Internet 的文件启用          │
│ [√] 为位于可能不安全位置的文件启用      │
│ [√] 为 Outlook 附件启用                 │
└─────────────────────────────────────────┘
```

## 32 位 vs 64 位 Office

### 版本差异

| Office 版本 | 默认架构 |
|-------------|----------|
| Office 2016 | 32 位 |
| Office 2019 | 32 位 |
| Office 2021 | 64 位 |
| Office 365 | 64 位 |

### 对 Shellcode 的影响

```bash
# 32 位 Office
msfvenom -p windows/meterpreter/reverse_https ...

# 64 位 Office
msfvenom -p windows/x64/meterpreter/reverse_https ...
```

### 检测 Office 架构

```vba
#If Win64 Then
    ' 64 位代码
#Else
    ' 32 位代码
#End If
```

## 企业环境考虑

### 组策略设置

管理员可以通过组策略控制宏行为：

```
计算机配置 → 管理模板 → Microsoft Office → 安全设置
```

### 常见企业配置

1. **完全禁用宏** - 最安全但限制功能
2. **只允许签名宏** - 平衡安全和功能
3. **受信任位置** - 允许特定位置的宏

## 渗透测试建议

### 1. 侦察阶段

- 确定目标 Office 版本
- 了解企业安全策略
- 识别可能的绕过方法

### 2. 选择攻击向量

| 目标环境 | 推荐方法 |
|----------|----------|
| Office 2016/2019 | 传统宏攻击 |
| Office 2021/365 | ISO/LNK/OneNote |
| 严格策略 | 非 Office 攻击 |

### 3. 测试和验证

- 在类似环境测试
- 验证 payload 执行
- 准备备用方案

## 总结

Office 2021 的安全改进显著提高了宏攻击的难度，但并非不可绕过。攻击者需要：

1. 了解目标环境的具体配置
2. 使用社会工程说服用户解除 MoTW
3. 考虑替代攻击向量
4. 保持对新绕过技术的关注
