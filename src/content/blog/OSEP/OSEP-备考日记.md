---
title: OSEP-备考日记
description: 'PEN-300 OSEP 日记'
pubDate: 2026-05-07T08:00:00+08:00
image: /ACGN/JSS.jpg
categories:
  - OffSec
  - Experiences
tags:
  - PEN-300-OSEP
  - Life
---

# 2026年5月7日（星期四）
## 母上的转账
今天下午上完课跟家里提出准备走谷安报名，税后价10900元，家母微信转了我12000元

![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-1.jpeg)

三个月学习时长+一次考试机会，感觉容错率很低啊......如果再给我一次机会我会选择大二考证而不是大三

祝我好运吧....

![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-2.png)

## HTB-Prolabs
在报名之前我已经完成了HTB-Prolabs的部分靶场

![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-3.png)

![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-4.png)

# 2026年5月8日（星期五-第一天）
## Outlook-邮件
中午上完课回来发现邀请邮件已经发送过来了，效率好高啊

![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-5.png)

## OffSec-Dashboard
![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-6.png)

## OffSec-Course
![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-7.png)

## VPN代理
> 适用场景：人在国内，直接连接 OffSec/OSEP VPN 延迟高、丢包明显，或者 UDP 到境外 VPN 服务器不稳定。  
核心目标：让 Kali 最终仍然像“正常直连 OffSec VPN”一样工作，`tun0`、靶场动态路由、`nmap`、`smbclient`、`xfreerdp` 都在 Kali 本机使用；VPS 只负责把 OpenVPN 的 UDP 流量从更稳定的境外出口转发出去。

### 1. 网络架构
原始连接方式是：

```text
Kali OpenVPN  ->  OffSec VPN
```

优化后的连接方式是：

```text
Kali OpenVPN
    |
    | UDP 127.0.0.1:1195
    v
Kali 本地 Xray 客户端
    |
    | VLESS + REALITY over TCP 443
    v
海外 VPS Xray 服务端
    |
    | UDP 到 OffSec VPN
    v
vpn-pool2.offseclabs.com:1194
```

关键点：

+ OpenVPN 仍然运行在 Kali 上。
+ Kali 仍然拿到 OffSec 推送的 `tun0` 和真实靶场路由。
+ VPS 不长期连接 OffSec VPN，避免同一份 VPN 证书多点登录。
+ 不写死靶场网段，例如不依赖 `192.168.0.0/16`。
+ 不使用 `/etc/hosts` 劫持 OffSec 域名。
+ 如果考试时 OffSec 发了新的 VPN 配置，只需要按新 `.ovpn` 的远端地址同步调整 Kali 侧配置。

### 2. 为什么不直接在 VPS 上挂 OpenVPN
把 OffSec VPN 直接挂在 VPS 上，再从 Kali 走 SSH 隧道或路由转发，看起来能临时访问靶机，但问题很多：

+ OffSec VPN 的路由是动态推送的，考试或靶场重置后网段可能变化。
+ `xfreerdp`、`nmap`、`smbclient` 等工具最好直接走 Kali 的 `tun0`。
+ 同一份 `.ovpn` 同时在 VPS 和 Kali 上连接，可能出现会话冲突。
+ 后续排障会变复杂，很难判断是 OpenVPN、转发、NAT 还是路由的问题。

所以更稳定的思路是：Kali 本机挂 VPN，VPS 只当网络前置代理。

### 3. VPS 侧配置：Xray 服务端
VPS 使用 Debian，公网 IP 用 `<VPS_IP>` 代替。SSH 端口建议不要用默认的 `22`，例如改成 `22222`。

#### 3.1 安装 Xray
```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

检查版本：

```bash
xray version
```

#### 3.2 生成 UUID 和 REALITY 密钥
```bash
xray uuid
xray x25519
openssl rand -hex 8
```

分别记录：

+ `uuid`
+ REALITY `Private key`
+ REALITY `Public key`
+ `shortId`

博客里不要公开真实值，可以写成：

```text
UUID: <UUID>
Private key: <REALITY_PRIVATE_KEY>
Public key: <REALITY_PUBLIC_KEY>
shortId: <SHORT_ID>
```

#### 3.3 配置服务端
编辑：

```bash
nano /usr/local/etc/xray/config.json
```

示例配置：

```json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "<UUID>",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "xver": 0,
          "serverNames": [
            "www.microsoft.com"
          ],
          "privateKey": "<REALITY_PRIVATE_KEY>",
          "shortIds": [
            "<SHORT_ID>"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
```

启动并设置开机自启：

```bash
systemctl enable --now xray
systemctl restart xray
```

检查：

```bash
systemctl status xray --no-pager -l
ss -tlnp | grep ':443'
```

正常应该看到 Xray 正在运行，并监听 `0.0.0.0:443`。

#### 3.4 VPS 安全组
在云厂商控制台放行：

```text
TCP 443 入站
TCP 22222 入站，或你自己的 SSH 端口
```

不需要长期放行 `UDP 1194`，因为最终不是让 VPS 当 OpenVPN relay。

### 4. Kali 侧配置：Xray 客户端
#### 4.1 安装 Xray
```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

检查：

```bash
xray version
```

#### 4.2 配置 Kali 本地 UDP 入口
创建配置文件：

```bash
nano /usr/local/etc/xray/offsec-client.json
```

示例配置：

```json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 1195,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "vpn-pool2.offseclabs.com",
        "port": 1194,
        "network": "udp"
      },
      "tag": "offsec-udp-in"
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "<VPS_IP>",
            "port": 443,
            "users": [
              {
                "id": "<UUID>",
                "encryption": "none",
                "flow": ""
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "www.microsoft.com",
          "fingerprint": "chrome",
          "publicKey": "<REALITY_PUBLIC_KEY>",
          "shortId": "<SHORT_ID>",
          "spiderX": "/"
        }
      },
      "tag": "vps"
    }
  ]
}
```

这里最重要的是 inbound：

```json
"listen": "127.0.0.1",
"port": 1195,
"address": "vpn-pool2.offseclabs.com",
"port": 1194,
"network": "udp"
```

含义是：Kali 本地开放 `127.0.0.1:1195/udp`，收到 OpenVPN 流量后，由 Xray 通过 VPS 发往 OffSec 官方 VPN 地址。

#### 4.3 创建 systemd 服务
创建：

```bash
nano /etc/systemd/system/xray-offsec-client.service
```

内容：

```properties
[Unit]
Description=Xray client for OffSec OpenVPN UDP proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/offsec-client.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

启动并设置开机自启：

```bash
systemctl daemon-reload
systemctl enable --now xray-offsec-client
systemctl restart xray-offsec-client
```

检查：

```bash
systemctl status xray-offsec-client --no-pager -l
ss -ulnp | grep 1195
```

正常应该看到：

```text
127.0.0.1:1195
```

### 5. OpenVPN 配置
不要直接改原始 `.ovpn`，先复制一份：

```bash
cd /home/kali/Desktop/OSEP/VPN
cp "universal.ovpn" universal-vpsproxy.ovpn
```

编辑副本：

```bash
nano universal-vpsproxy.ovpn
```

找到原来的 `remote` 行，例如：

```nginx
remote vpn-pool2.offseclabs.com 1194 udp
```

改成：

```nginx
remote 127.0.0.1 1195 udp
```

保留证书校验配置，例如：

```nginx
verify-x509-name "offensive-security.com" name
```

然后连接：

```bash
openvpn --config "/home/kali/Desktop/OSEP/VPN/universal-vpsproxy.ovpn"
```

正常日志应包含：

```text
UDPv4 link remote: [AF_INET]127.0.0.1:1195
Initialization Sequence Completed
```

这说明 OpenVPN 已经从 Kali 本机连上，只是底层 UDP 流量经由 VPS 出口转发到了 OffSec VPN。

### 6. 验证靶场路由
VPN 连上后检查：

```bash
ip addr show tun0
ip route
```

应该能看到 `tun0`，以及 OffSec 推送下来的真实靶场路由，例如：

```text
192.168.106.0/24 via 192.168.45.254 dev tun0
```

注意：这个网段只是示例。考试或不同 lab 里可能不是这个，所以不要在配置里写死它。

### 7. 每次开机后怎么连
如果已经把 `xray-offsec-client` 设置为开机自启，通常只需要：

```bash
systemctl status xray-offsec-client --no-pager -l
openvpn --config "/home/kali/Desktop/OSEP/VPN/universal-vpsproxy.ovpn"
```

如果 Xray 没启动：

```bash
systemctl restart xray-offsec-client
```

如果 OpenVPN 没连上，先看三件事：

```bash
ss -ulnp | grep 1195
systemctl status xray-offsec-client --no-pager -l
ping -c 4 <VPS_IP>
```

### 8. 如果考试发了新的 VPN 文件，应该改哪里
大多数情况下，VPS 不用动，只改 Kali。

#### 8.1 新 VPN 仍然是同一个官方域名
如果新 `.ovpn` 里还是：

```nginx
remote vpn-pool2.offseclabs.com 1194 udp
```

只需要复制新文件，然后把副本的 remote 改成本地 Xray：

```bash
cp new-exam.ovpn new-exam-vpsproxy.ovpn
sed -i -E 's/^remote .+ 1194 udp$/remote 127.0.0.1 1195 udp/' new-exam-vpsproxy.ovpn
openvpn --config ./new-exam-vpsproxy.ovpn
```

#### 8.2 新 VPN 换了官方域名
先查看新文件里的 remote：

```bash
grep '^remote ' new-exam.ovpn
```

假设看到：

```nginx
remote vpn-pool3.offseclabs.com 1194 udp
```

那 Kali 需要改两处：

第一处，改 Xray 客户端目标：

```bash
nano /usr/local/etc/xray/offsec-client.json
```

把：

```json
"address": "vpn-pool2.offseclabs.com"
```

改成：

```json
"address": "vpn-pool3.offseclabs.com"
```

然后重启：

```bash
systemctl restart xray-offsec-client
```

第二处，复制新的 `.ovpn`，把 remote 改成本地：

```bash
cp new-exam.ovpn new-exam-vpsproxy.ovpn
sed -i -E 's/^remote .+ 1194 udp$/remote 127.0.0.1 1195 udp/' new-exam-vpsproxy.ovpn
openvpn --config ./new-exam-vpsproxy.ovpn
```

#### 8.3 新 VPN 端口也变了
如果新 `.ovpn` 里是：

```nginx
remote <NEW_VPN_HOST> <NEW_PORT> udp
```

则 Kali 的 `/usr/local/etc/xray/offsec-client.json` 也要同步改：

```json
"address": "<NEW_VPN_HOST>",
"port": <NEW_PORT>,
"network": "udp"
```

然后：

```bash
systemctl restart xray-offsec-client
```

`.ovpn` 副本仍然改成：

```nginx
remote 127.0.0.1 1195 udp
```

也就是说：

+ Xray 客户端负责记住真实 OffSec VPN 地址。
+ OpenVPN 永远只连 `127.0.0.1 1195 udp`。

## 课程进度
![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-8.png)

# 2026年5月9日（星期六-第二天）
## 课程进度
白天美美的休息了，下午学了一阵然后打瓦去了

![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-9.png)

## 个人感受
感觉购买前准备的还是太充分了，又臭又长的pdf文档在购买前我已经啃完了一半，ai搭建的知识库我也都过了一遍，这导致我处于速通状态，后悔没早点买了

## 笔记整理
主要分为俩个部分，一个是course笔记：用于汇总章节内容和处理章节习题等

另一个是code笔记，提取章节内有用的代码进行汇总整理，方便二次查阅使用代码

格式大概就是这样：章节标题写成英文确实看着挺高级，但也是真的容易让我发晕

![](/image/osep-%E5%89%8D%E8%A8%80/OSEP-%E5%A4%87%E8%80%83%E6%97%A5%E8%AE%B0-10.png)
