---
title: OSEP-21-ADCS考试速查
description: '21-ADCS证书攻击 | 04-ADCS考试速查'
pubDate: 2026-01-30T00:03:03+08:00
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

# ADCS 考试速查

## 看到什么就想 ADCS

| 信号 | 下一步 |
|---|---|
| 域里出现 CA 主机或证书服务 | 枚举 CA、模板、HTTP 端点 |
| `certsrv`、CEP、CES、证书注册页面 | 判断 NTLM Relay 到 ADCS |
| BloodHound 或 LDAP 显示模板 ACL 异常 | 判断 ESC4 或模板改写 |
| 模板允许 `Domain Users` 注册 | 检查是否可提供 Subject/SAN |
| 模板包含 Client Authentication | 判断能否转成认证材料 |
| 拿到 PFX/PEM/KEY/CERT | 判断 PKINIT、Schannel、WinRM 证书认证 |
| 对目标对象有写权限 | 考虑 Shadow Credentials 或显式映射 |

---

## 最小问题集

考试卡住时，按顺序问自己：

1. 我是否已经用当前凭证枚举过 ADCS。
2. 是否有低权限可注册且可认证的模板。
3. 是否能控制证书里的身份字段。
4. 是否存在 HTTP 注册端点。
5. 是否能触发机器或用户的 NTLM 认证。
6. 拿到证书后是走 PKINIT 还是 Schannel。
7. 证书身份能访问什么资源。
8. 这条路径能否和 RBCD、DCSync、MSSQL、委派结合。

---

## OSEP 课程最小闭环

`17：ad基于证书攻击（adcs）.html` 的考试优先级可以压缩成下面这条链。先把链跑通，再考虑扩展 ESC 类型。

| 阶段 | 目标 | 关键判断 | 失败转向 |
|---|---|---|---|
| 1. 枚举 CA | 确认域内是否部署 ADCS | CA 主机、CA 名称、Web Enrollment/HTTP 端点 | 回到 ACL、Kerberoasting、MSSQL |
| 2. 枚举模板 | 找低权限可利用模板 | 注册权限、EKU、Subject/SAN 是否可控、审批要求 | 看 ESC4 模板写权限或其他模板 |
| 3. 申请证书 | 把普通身份变成证书材料 | 目标 UPN/DNS 是否正确，PFX 是否生成 | 查模板权限、CA 名称、时间同步 |
| 4. HTTP Relay | 把 NTLM 认证转成证书 | 端点是否支持 NTLM，是否能触发高价值主体认证 | 查 EPA/HTTPS、coercion、机器模板 |
| 5. 证书认证 | 用证书换可用访问能力 | PKINIT、Schannel、PassTheCert 哪个成立 | 查 EKU、证书链、强映射策略 |
| 6. 权限验证 | 证明证书带来的实际影响 | SMB/LDAP/WinRM/DCSync/对象修改是否可用 | 转委派、ACL、MSSQL 或凭证复用 |

考试可用总结：ADCS 不要只记工具命令，要能说明“谁能申请什么证书、证书代表谁、证书能访问哪里”。新版 ESC9/14/15/16 可以作为扩展了解，但 OSEP 复习优先先稳住模板误配置和 NTLM Relay 到 HTTP 端点。

---

## ADCS 与其他路径的切换

| 当前发现 | 优先路径 |
|---|---|
| 有普通域用户凭证，但没有本地管理员 | ADCS、Kerberoasting、BloodHound、MSSQL |
| 有目标机器账户能力 | RBCD、机器证书、LDAP 写权限、敏感共享 |
| 有模板写权限 | 先把模板变成可利用形态，再申请证书 |
| 有 Web Enrollment 和 coercion 机会 | 优先评估 ESC8 |
| PKINIT 不通 | 不要立刻放弃，检查 Schannel/PassTheCert |
| ADCS 全部不成立 | 回到 ACL、委派、MSSQL、凭证复用 |

---

## 命令去哪里查

| 需求 | 位置 |
|---|---|
| ADCS 枚举命令 | `14-横向移动/00-章节指南.md` 的“ADCS证书攻击” |
| 原始命令合集 | `21-ADCS证书攻击/06-ADCS命令索引与附录映射.md` 的“ADCS证书相关” |
| 信息收集命令 | `16-AD权限滥用/00-章节指南.md` |
| 横向移动命令 | `14-横向移动` 与 `14-横向移动/00-章节指南.md` |

---

## 报告模板

```
发现：
- 域内存在 ADCS：<CA 主机>/<CA 名称>
- 可疑模板：<模板名>
- 风险条件：<谁可注册>、<可控字段>、<EKU>、<审批/签名状态>

影响：
- 可为 <目标身份> 申请可认证证书
- 可进一步获得 <TGT/LDAP 修改/远程访问> 能力

证据：
- 枚举输出截图
- 证书申请结果
- 使用证书认证后的身份验证截图
- 后续访问或权限提升证据

修复建议：
- 收紧模板注册权限
- 禁止申请者提供高风险身份字段
- 启用审批或授权签名
- 禁用不必要的 ADCS HTTP 端点
- 启用 EPA/通道绑定并审计证书申请
```
