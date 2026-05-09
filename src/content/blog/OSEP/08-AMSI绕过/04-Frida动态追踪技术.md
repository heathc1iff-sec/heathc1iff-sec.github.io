---
title: OSEP-08-Frida动态追踪技术
description: '08-AMSI绕过 | 04-Frida动态追踪技术'
pubDate: 2026-01-30T00:01:17+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# Frida 动态追踪技术

## 什么是 Frida

Frida 是一个动态代码插桩框架，允许我们在运行时 Hook Win32 API，追踪函数调用、参数和返回值。

### Frida vs WinDbg

| 特性 | Frida | WinDbg |
|------|-------|--------|
| 学习曲线 | 较低 | 较高 |
| 脚本语言 | JavaScript | 专用命令 |
| 灵活性 | 高 | 中 |
| 性能影响 | 较小 | 较大 |
| 适用场景 | API 追踪 | 深度调试 |

## 安装 Frida

### 使用 pip 安装

```cmd
pip install frida-tools
```

### 验证安装

```cmd
frida --version
```

## 基本使用

### frida-trace 命令

```cmd
frida-trace -p <PID> -x <DLL> -i <函数模式>
```

**参数说明**：

| 参数 | 说明 |
|------|------|
| -p | 目标进程 ID |
| -x | 要追踪的 DLL |
| -i | 函数名模式（支持通配符） |
| -n | 进程名（替代 -p） |

### 追踪 AMSI 示例

```cmd
C:\> frida-trace -p 1584 -x amsi.dll -i Amsi*
```

**输出**：

```
Instrumenting functions...
AmsiOpenSession: Auto-generated handler at "C:\Users\Offsec\__handlers__\amsi.dll\AmsiOpenSession.js"
AmsiScanBuffer: Auto-generated handler at "C:\Users\Offsec\__handlers__\amsi.dll\AmsiScanBuffer.js"
AmsiCloseSession: Auto-generated handler at "C:\Users\Offsec\__handlers__\amsi.dll\AmsiCloseSession.js"
...
Started tracing 9 functions. Press Ctrl+C to stop.
```

## Handler 文件

### 默认 Handler 结构

当 Frida 开始追踪时，会为每个函数创建 Handler 文件：

```
C:\Users\<用户>\__handlers__\<DLL>\<函数名>.js
```

### Handler 文件内容

```javascript
{
  onEnter: function (log, args, state) {
    // 函数调用时执行
    log('AmsiScanBuffer()');
  },

  onLeave: function (log, retval, state) {
    // 函数返回时执行
  }
}
```

### 参数说明

| 参数 | 说明 |
|------|------|
| log | 输出函数 |
| args | 函数参数数组 |
| retval | 返回值 |
| state | 状态对象（跨调用保持） |

## 自定义 Handler

### 追踪 AmsiScanBuffer 参数

修改 `AmsiScanBuffer.js`：

```javascript
{
  onEnter: function (log, args, state) {
    log('[*] AmsiScanBuffer()');
    log('|- amsiContext: ' + args[0]);
    log('|- buffer: ' + Memory.readUtf16String(args[1], args[2].toInt32() / 2));
    log('|- length: ' + args[2]);
    log('|- contentName: ' + Memory.readUtf16String(args[3]));
    log('|- amsiSession: ' + args[4]);
    log('|- result ptr: ' + args[5]);
  },

  onLeave: function (log, retval, state) {
    log('[*] AmsiScanBuffer returned: ' + retval);
  }
}
```

### 输出示例

在 PowerShell 中输入 "test" 后：

```
[*] AmsiScanBuffer()
|- amsiContext: 0x1a2b3c4d
|- buffer: test
|- length: 0x8
|- contentName: PowerShell_ISE.exe
|- amsiSession: 0x5e6f7a8b
|- result ptr: 0x9c0d1e2f
[*] AmsiScanBuffer returned: 0x0
```

## Frida API 参考

### 内存读取

```javascript
// 读取 UTF-16 字符串
Memory.readUtf16String(ptr)

// 读取 UTF-8 字符串
Memory.readUtf8String(ptr)

// 读取字节
Memory.readByteArray(ptr, length)

// 读取指针
Memory.readPointer(ptr)

// 读取整数
Memory.readInt(ptr)
Memory.readUInt(ptr)
```

### 内存写入

```javascript
// 写入字节
Memory.writeByteArray(ptr, bytes)

// 写入整数
Memory.writeInt(ptr, value)

// 写入指针
Memory.writePointer(ptr, value)
```

### 指针操作

```javascript
// 创建指针
ptr('0x12345678')

// 指针运算
ptr.add(offset)
ptr.sub(offset)

// 空指针
NULL
```

### 模块操作

```javascript
// 获取模块基址
Module.findBaseAddress('amsi.dll')

// 获取导出函数地址
Module.findExportByName('amsi.dll', 'AmsiScanBuffer')

// 枚举导出
Module.enumerateExports('amsi.dll')
```

## 高级追踪技术

### 追踪返回值

```javascript
{
  onEnter: function (log, args, state) {
    // 保存 result 指针供 onLeave 使用
    this.resultPtr = args[5];
  },

  onLeave: function (log, retval, state) {
    // 读取扫描结果
    var result = Memory.readInt(this.resultPtr);
    log('Scan result: ' + result);

    if (result == 32768) {
      log('[!] MALWARE DETECTED!');
    } else {
      log('[+] Clean');
    }
  }
}
```

### 修改返回值

```javascript
{
  onLeave: function (log, retval, state) {
    // 强制返回成功
    retval.replace(0);
    log('[*] Return value modified to 0');
  }
}
```

### 修改参数

```javascript
{
  onEnter: function (log, args, state) {
    // Frida 中直接给 args[n] 赋值不一定能稳定改写真实调用参数。
    // 稳定绕过建议使用 Interceptor.replace 或在 onLeave 中改写 result 指针。
    log('[*] 参数改写请使用 Interceptor.replace/onLeave 方案，不建议直接 args[2] = ptr(0)');
  }
}
```

## 实战：分析 AMSI 检测

### 步骤 1：启动 PowerShell

```cmd
powershell.exe
```

记录进程 ID（例如：1584）

### 步骤 2：启动 Frida 追踪

```cmd
frida-trace -p 1584 -x amsi.dll -i Amsi*
```

### 步骤 3：修改 Handler

编辑 `AmsiScanBuffer.js`：

```javascript
{
  onEnter: function (log, args, state) {
    log('='.repeat(50));
    log('[*] AmsiScanBuffer called');

    var length = args[2].toInt32();
    var buffer = Memory.readUtf16String(args[1], length / 2);

    log('|- Buffer (' + length + ' bytes):');
    log(buffer);

    this.resultPtr = args[5];
  },

  onLeave: function (log, retval, state) {
    var result = Memory.readInt(this.resultPtr);

    if (result == 32768) {
      log('[!] DETECTED AS MALWARE');
    } else if (result == 1) {
      log('[+] Clean');
    } else {
      log('[?] Result: ' + result);
    }
    log('='.repeat(50));
  }
}
```

### 步骤 4：测试检测

在 PowerShell 中输入：

```powershell
# 正常命令
Get-Process

# 可能被检测的命令
"amsiutils"
```

### 步骤 5：分析输出

```
==================================================
[*] AmsiScanBuffer called
|- Buffer (18 bytes):
amsiutils
[!] DETECTED AS MALWARE
==================================================
```

## 追踪多个函数

### 追踪完整 AMSI 流程

```javascript
// AmsiOpenSession.js
{
  onEnter: function (log, args, state) {
    log('[SESSION] Opening AMSI session');
  }
}

// AmsiScanBuffer.js
{
  onEnter: function (log, args, state) {
    log('[SCAN] Scanning: ' + Memory.readUtf16String(args[1]));
  }
}

// AmsiCloseSession.js
{
  onEnter: function (log, args, state) {
    log('[SESSION] Closing AMSI session');
  }
}
```

## 常见问题

### 1. 找不到进程

```
Error: unable to find process with pid 1234
```

**解决**：确认进程 ID 正确，使用管理员权限运行。

### 2. 无法附加

```
Error: access denied
```

**解决**：以管理员身份运行命令提示符。

### 3. Handler 不生效

**解决**：
1. 确认 Handler 文件路径正确
2. 检查 JavaScript 语法
3. 重新启动 frida-trace

## 下一步

掌握 Frida 追踪后，继续学习 [05-AMSI绕过技术.md](/blog/osep/08-amsi绕过/05-amsi绕过技术/)，利用分析结果实现绕过。
