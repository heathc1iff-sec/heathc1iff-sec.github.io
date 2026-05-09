---
title: OSEP-21-ADCS-ESC攻击决策树详解
description: '21-ADCS证书攻击 | 05-ADCS-ESC攻击决策树详解'
pubDate: 2026-01-30T00:03:04+08:00
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

# ADCS ESC 攻击决策树详解

## ADCS 为什么重要

ADCS 是 Active Directory 里的证书服务。配置错误时，普通域用户可能通过申请证书获得更高权限身份的认证能力。

对初学者来说，ADCS 难点不是命令，而是判断模板配置到底危险在哪里。

---

## 基础概念

| 概念 | 说明 |
|---|---|
| CA | Certificate Authority，证书颁发机构 |
| 证书模板 | 定义谁能申请、证书用途、申请字段 |
| EKU | Extended Key Usage，证书用途 |
| SAN | Subject Alternative Name，证书可声明的身份 |
| Enrollment 权限 | 谁能申请该模板 |
| Manager Approval | 是否需要人工审批 |
| Client Authentication | 是否可用于客户端认证 |

---

## ADCS 枚举顺序

1. 找 CA。
2. 找可用模板。
3. 看谁能注册模板。
4. 看模板是否允许认证用途。
5. 看是否能自定义主体或 SAN。
6. 看是否需要审批。
7. 看模板 ACL 是否可修改。
8. 看是否存在 Web Enrollment/HTTP endpoint。

---

## ESC 判断树

| 条件 | 可能 ESC | 说明 |
|---|---|---|
| 低权限用户可注册 | ESC 判断前提之一 | 需要继续看用途和 SAN |
| Client Authentication | ESC1/ESC2 相关 | 可用于认证 |
| Enrollee supplies subject | ESC1 | 可申请成其他身份 |
| 模板 ACL 可写 | ESC4 | 可把模板改危险 |
| CA 配置允许 SAN | ESC6 | CA 层面危险 |
| Web Enrollment + NTLM Relay | ESC8 | 中继到 ADCS |

---

## 场景化攻击链

### 普通域用户到高权限证书

```
普通域用户可注册模板
  -> 模板允许 Client Authentication
  -> 可提供 SAN/UPN
  -> 申请高权限用户证书
  -> 使用证书请求 TGT
```

### NTLM Relay 到 ADCS

```
触发目标认证
  -> 中继到 ADCS HTTP endpoint
  -> 申请机器或用户证书
  -> 证书换取认证能力
```

### 模板写权限到证书滥用

```
发现模板 ACL 可写
  -> 修改模板用途或注册条件
  -> 申请证书
  -> 恢复或记录修改
```

---

## 命令应该怎么学

命令不要死背，按动作分类：

| 动作 | 工具方向 |
|---|---|
| 枚举 CA/模板 | Certipy、Certify |
| 判断 ESC | Certipy find、手动读模板字段 |
| 申请证书 | Certipy req、Certify request |
| 证书换 TGT | Certipy auth、Rubeus/PKINIT |
| 中继到 ADCS | ntlmrelayx |
| 格式转换 | PFX/PEM/ccache/kirbi 转换 |

---

## 常见失败与排错

| 现象 | 排查 |
|---|---|
| 找不到 CA | DNS、LDAP、权限、域信息 |
| 模板不可注册 | Enrollment 权限不足 |
| 申请需要审批 | Manager Approval |
| 证书不能认证 | EKU 不对、UPN/SAN 不对 |
| PKINIT 失败 | KDC、证书链、时间同步 |
| Relay 失败 | SMB signing、EPA、HTTP endpoint 不可用 |

---

## OSEP 重点

1. 看到模板不要急着申请，先判断权限、用途、SAN、审批。
2. ESC1/ESC4/ESC8 是考试复习优先级较高的方向。
3. 证书是凭证材料，拿到后要知道如何换 TGT 或访问 LDAP。
4. ADCS 常与 NTLM Relay、机器账户、LDAP 修改联动。
