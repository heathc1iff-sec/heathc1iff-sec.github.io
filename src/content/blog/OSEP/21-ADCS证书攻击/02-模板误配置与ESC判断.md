---
title: OSEP-21-模板误配置与ESC判断
description: '21-ADCS证书攻击 | 02-模板误配置与ESC判断'
pubDate: 2026-01-30T00:03:01+08:00
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

# 模板误配置与 ESC 判断

## 先记住考试优先级

课程 HTML 重点覆盖“误配置模板”和“NTLM Relay 到 ADCS HTTP 端点”。备考时优先把下面几类练熟：

| 优先级 | 类型 | 判断重点 |
|---|---|---|
| A | ESC1 类模板误配置 | 低权限可注册、可提供 Subject/SAN、证书可用于客户端认证 |
| A | ESC8 类 HTTP 端点中继 | 存在 ADCS HTTP 端点，能把 NTLM 认证中继给 CA |
| B | ESC4 类模板可写 | 你能修改模板，把它变成更容易利用的形态 |
| B | ESC9/ESC16 类映射问题 | 证书映射策略导致身份绑定可被绕过或操纵 |
| B | ESC14/ESC15 类新型映射/应用策略问题 | 需要看证书映射、邮箱/UPN、应用策略注入等细节 |
| B | Shadow Credentials | 对目标对象可写 `msDS-KeyCredentialLink`，能添加公钥凭据 |

---

## 判断树

```
发现可疑模板
    |
    v
低权限用户能否注册？
    |-- 否 --> 是否能修改模板 ACL？如果能，考虑 ESC4
    |
    v
申请者能否控制 Subject / SAN / UPN？
    |-- 否 --> 看映射问题、代理注册、其他模板或转向 ACL/委派
    |
    v
证书用途是否支持认证？
    |-- 否 --> 看 Any Purpose、应用策略、Schannel 或 PassTheCert
    |
    v
是否无需审批、无需授权签名？
    |-- 否 --> 直接利用可能受阻，记录为风险但转向其他路径
    |
    v
优先按 ESC1 思路验证
```

---

## 常见 ESC 类型复习表

| 类型 | 入口条件 | 关键字段 | 成功后的能力 | 常见卡点 |
|---|---|---|---|---|
| ESC1 | 低权限可注册模板，申请者能提供身份字段 | `ENROLLEE_SUPPLIES_SUBJECT`、Client Auth EKU | 申请可冒充高权限用户的证书 | 模板需要审批、EKU 不对、目标身份格式不对 |
| ESC4 | 对模板有写权限 | 模板 DACL、Owner、WriteDACL | 修改模板后转成 ESC1 类路径 | 没有模板写权限、修改后未生效 |
| ESC8 | ADCS HTTP 端点可被 NTLM 中继 | Web Enrollment、NTLM、机器模板 | 申请机器证书并转换为机器身份能力 | EPA/HTTPS 配置、模板不可用、无法触发认证 |
| ESC9 | 弱证书映射相关 | UPN、`altSecurityIdentities`、映射策略 | 利用映射差异完成身份绑定 | 新补丁策略、字段不匹配 |
| ESC14 | 显式证书映射可操纵 | `altSecurityIdentities` | 把证书显式映射到目标身份 | 目标对象不可写、证书引用不匹配 |
| ESC15 | 应用策略或 EKU 注入 | Application Policies | 构造可用于认证或代理的证书 | 模板版本、工具版本、策略 OID 不符合 |
| ESC16 | 强映射/弱映射策略组合 | 账户属性、证书映射 | 类似映射绕过路径 | 域控补丁和注册表策略影响很大 |

OSEP 课程优先级：ESC1、ESC8 是主线；ESC4 是常见补充；ESC9/14/15/16 和 Shadow Credentials 作为扩展了解，避免考前复习跑偏。

---

## 证书到权限的转换

拿到证书不等于立刻拿到 Shell。考试里要明确下一跳：

| 证书状态 | 下一步 |
|---|---|
| 可用于 PKINIT | 申请 TGT，再访问 SMB/LDAP/WinRM 等服务 |
| PKINIT 不可用但 LDAP 支持 Schannel | 用证书认证 LDAP，执行可用的目录修改 |
| 证书属于机器账户 | 优先考虑机器权限、RBCD、资源访问、DCSync 前置条件 |
| 证书属于高权限用户 | 优先验证域内访问、DCSync、远程执行或敏感资源读取 |
| 证书无法直接认证 | 检查 EKU、映射、域控补丁、CA 链和时间同步 |

---

## 失败排查顺序

1. 模板是不是启用状态。
2. 当前用户或组是否真的有注册权限。
3. 模板是否需要 Manager Approval。
4. 模板是否需要 Authorized Signatures。
5. EKU 是否支持目标认证方式。
6. 申请的身份字段是否符合 UPN、DNS、SAMAccountName 的格式。
7. 域控是否支持 PKINIT，时间是否同步。
8. 证书链是否被目标信任。
9. 新版强映射策略是否影响证书身份绑定。
10. 工具版本是否与 ESC 类型匹配。
