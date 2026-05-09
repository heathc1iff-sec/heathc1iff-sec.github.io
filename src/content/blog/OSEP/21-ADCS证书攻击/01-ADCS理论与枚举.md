---
title: OSEP-21-ADCS理论与枚举
description: '21-ADCS证书攻击 | 01-ADCS理论与枚举'
pubDate: 2026-01-30T00:03:00+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Exploit Development
  - Active Directory
  - ADCS
---

# ADCS 理论与枚举

## 核心概念

| 概念 | 你要记住的点 |
|---|---|
| CA | 证书颁发机构，决定证书由谁签发以及信任链从哪里来 |
| Certificate Template | 证书模板，决定谁能申请、申请什么用途、主题名能否自定义 |
| EKU | Extended Key Usage，决定证书能用于客户端认证、服务器认证、代码签名等场景 |
| Enrollment Rights | 谁能基于模板申请证书 |
| Subject / SAN / UPN | 证书里代表身份的字段，很多冒充路径都围绕它们展开 |
| Manager Approval | 是否需要审批；需要审批通常会阻断直接利用 |
| Authorized Signatures | 是否需要额外签名；需要签名通常会提高利用门槛 |
| PKINIT | 用证书向 Kerberos 申请 TGT 的认证方式 |
| Schannel | TLS 客户端证书认证到 LDAP 等服务的路径 |

---

## 枚举优先级

考试里看到域凭证后，ADCS 不应该放到最后才看。推荐顺序：

1. 先确认是否存在 CA。
2. 再确认是否存在 Web Enrollment、CEP、CES 等 HTTP 端点。
3. 再看模板是否允许低权限主体注册。
4. 再看模板是否允许申请者提供 Subject 或 SAN。
5. 再看模板 EKU 是否包含 Client Authentication、Smart Card Logon、PKINIT Client Authentication，或者是否存在 Any Purpose。
6. 最后判断证书拿到后能不能直接变成 TGT，不能则考虑 Schannel/LDAP 路线。

---

## 高价值字段速查

| 字段或现象 | 为什么重要 |
|---|---|
| `Client Authentication` | 证书可能可用于用户或机器身份认证 |
| `ENROLLEE_SUPPLIES_SUBJECT` | 申请者可能能指定要冒充的身份 |
| `Subject Alternative Name` 可控 | 常见高危模板路径的关键条件 |
| `Domain Users` 可注册 | 低权限用户可能直接触发攻击链 |
| `Manager approval disabled` | 不需要人工审批，攻击链更直接 |
| `Authorized signatures: 0` | 不需要额外签名，攻击链更直接 |
| `Web Enrollment` | NTLM Relay 到 ADCS 的常见入口 |
| `msPKI-Certificate-Name-Flag` | 判断主题名是否可由申请者控制 |
| `pKIExtendedKeyUsage` | 判断证书能否用于认证 |
| `altSecurityIdentities` | 显式证书映射和影子凭证相关判断点 |

---

## 枚举记录模板

| 项目 | 记录 |
|---|---|
| 域名 |  |
| DC |  |
| CA 主机 |  |
| CA 名称 |  |
| Web Enrollment URL |  |
| 可疑模板 |  |
| 可注册主体 |  |
| 可控字段 |  |
| EKU |  |
| 是否需要审批 |  |
| 是否需要签名 |  |
| 可冒充目标 |  |
| 后续认证方式 |  |

---

## 和其他 AD 攻击的区别

| 攻击类型 | 依赖点 | 成功后得到什么 |
|---|---|---|
| Kerberoasting | SPN 与可破解服务票据 | 明文密码或服务账户控制 |
| 委派攻击 | 委派配置和可用票据/账户 | 目标服务票据或服务访问 |
| ACL 滥用 | 对 AD 对象的写权限 | 改密码、加组、写 RBCD、写影子凭证 |
| ADCS | 证书模板、CA、映射和注册权限 | 可认证的证书、TGT、LDAP 修改能力 |

ADCS 的特别之处是：它经常绕过“没有密码/Hash”的限制，把证书变成新的认证材料。因此复习时要把它放在凭证攻击和 AD 权限滥用之间理解。
