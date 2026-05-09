---
title: OSEP-21-ADCS命令索引与附录映射
description: '21-ADCS证书攻击 | 06-ADCS命令索引与附录映射'
pubDate: 2026-01-30T00:03:05+08:00
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

# ADCS 命令索引与附录映射

## 这篇文档解决什么问题

ADCS 的难点不是“命令少”，而是命令太容易散落在枚举、证书申请、票据转换、NTLM 中继、LDAP 操作、横向移动等多个章节里。初学者常见问题是：

- 知道 `certipy find`，但不知道输出里哪些字段代表风险。
- 拿到 `.pfx` 后不知道下一步该换 TGT、走 LDAP，还是转格式。
- ESC1、ESC4、ESC8 之间命令相似，但入口条件完全不同。
- 附录里有命令，ADCS 章节里有原理，考试时不知道从哪里开始。

这篇文档把 ADCS 常用命令按“阶段”和“材料去向”重新索引，并标出应该回看哪些附录。

---

## ADCS 正序攻击链

```text
有域身份或可中继身份
  -> 枚举 CA / 模板 / HTTP 端点
  -> 判断 ESC 或中继路径
  -> 申请或获取证书
  -> 使用证书认证
  -> 转成 TGT / LDAP 权限 / 横向移动
  -> 记录证据并继续域提权
```

每一步都要问：

1. 我现在有什么身份。
2. 这个身份能枚举什么。
3. 哪个模板或端点危险。
4. 我拿到的证书代表谁。
5. 这个证书能换成什么访问能力。

---

## 命令索引总表

| 阶段 | 目标 | 常用工具/命令 | 回看文件 |
|---|---|---|---|
| 发现 CA | 确认域内是否有 ADCS | Certipy、Certify、LDAP 枚举 | `01-ADCS理论与枚举.md` |
| 枚举模板 | 找危险模板和注册权限 | `certipy find`、Certify | `02-模板误配置与ESC判断.md` |
| 判断 ESC | 把配置转成攻击路径 | ESC 判断树 | `05-ADCS-ESC攻击决策树详解.md` |
| 申请证书 | 获取 PFX/证书材料 | `certipy req`、Certify request | `04-ADCS考试速查.md` |
| 证书认证 | 用证书换身份 | `certipy auth`、PKINIT 工具 | 本篇与 `20-综合渗透案例` |
| NTLM 中继 | Relay 到 ADCS HTTP 端点 | `ntlmrelayx` | `03-NTLM中继到ADCS.md` |
| LDAP 操作 | 使用证书做后续修改 | PassTheCert、LDAP 工具 | `16-AD权限滥用` |
| 横向移动 | 用得到的身份访问主机 | SMB/WinRM/RDP/MSSQL | `14-横向移动`、`15-MSSQL攻击` |

---

## 阶段一：发现 CA 和模板

### 概念说明

ADCS 枚举不是只看“有没有 CA”。你要同时看：

- CA 名称。
- 证书模板。
- 模板注册权限。
- 模板是否允许客户端认证。
- 是否允许申请者指定 SAN/UPN。
- 是否需要 Manager Approval。
- 是否有 HTTP Web Enrollment/CES/CEP 端点。

### 使用场景

拿到任意域用户凭证、Hash、TGT 或可运行域枚举的上下文后，都应该考虑 ADCS 枚举。

### 常用命令

```bash
certipy find -u user@domain.local -p 'Password123!' -dc-ip 10.10.10.10 -vulnerable -enabled
certipy find -u user@domain.local -p 'Password123!' -dc-ip 10.10.10.10 -json -output adcs_find
```

Windows 侧常见思路：

```powershell
Certify.exe find /vulnerable
Certify.exe cas
```

### 注意事项

| 点 | 说明 |
|---|---|
| 没有 `-vulnerable` 不代表没风险 | 初学时先看完整输出，再看过滤结果 |
| 模板名和显示名可能不同 | 命令里经常需要模板名 |
| CA 名称格式要准确 | 申请证书时常用 `CAHOST\CA-NAME` |
| 注册权限不等于可提权 | 还要看 EKU、SAN、审批、映射 |

### 排错思路

| 现象 | 排查 |
|---|---|
| 找不到 CA | DNS、LDAP、DC IP、域名、权限 |
| 工具认证失败 | 凭证格式、Kerberos/NTLM、时间同步 |
| 输出为空 | 可能没有 ADCS，也可能权限不足或参数错 |
| 模板看不懂 | 回到 `01-ADCS理论与枚举.md` 看 CA/EKU/SAN |

---

## 阶段二：从输出判断 ESC

### ESC1 重点

常见危险组合：

- 普通用户可注册。
- 允许申请者提供 subject/SAN。
- EKU 包含 Client Authentication 或可用于认证。
- 不需要 Manager Approval。

判断问题：

```text
我能不能申请一个证书，让它代表另一个高价值用户？
```

### ESC4 重点

ESC4 关注模板对象权限。你不是直接申请危险证书，而是先修改模板，让它变危险。

判断问题：

```text
我是否能修改模板配置，让普通用户可注册、可指定 SAN、可用于客户端认证？
```

### ESC8 重点

ESC8 是 NTLM Relay 到 ADCS HTTP 端点。关键不在模板本身，而在：

- 是否有可中继的 NTLM 身份。
- ADCS HTTP 端点是否可访问。
- EPA/HTTPS/签名等限制是否影响中继。
- 中继后申请的证书代表谁。

判断问题：

```text
我能否诱导或捕获一个身份的 NTLM，并把它中继到 ADCS 申请证书？
```

---

## 阶段三：申请证书

### 常用命令模板

```bash
certipy req -u user@domain.local -p 'Password123!' \
  -ca 'CA-NAME' -target ca.domain.local \
  -template 'TemplateName' \
  -upn administrator@domain.local \
  -dc-ip 10.10.10.10
```

常见输出材料：

| 文件 | 说明 |
|---|---|
| `.pfx` | 证书和私钥打包，最常见 |
| `.crt`/`.cer` | 证书 |
| `.key` | 私钥 |
| `.pem` | PEM 格式，某些工具使用 |

### 注意事项

1. `-ca`、`-target`、`-template` 写错会导致申请失败。
2. `-upn` 或 SAN 是否可控取决于模板配置。
3. 申请成功不等于能认证成功，还要看映射和 PKINIT/Schannel。
4. 证书代表的身份必须在报告中写清楚。

### 排错表

| 现象 | 排查 |
|---|---|
| `CERTSRV_E_TEMPLATE_DENIED` | 当前用户无注册权限或模板限制 |
| `CERTSRV_E_SUBJECT_DNS_REQUIRED` | 模板要求 DNS/SAN 字段 |
| `Access denied` | CA 权限、模板权限、认证问题 |
| 申请成功但没有 PFX | 输出路径、工具版本、私钥导出 |
| 申请的是自己不是目标用户 | SAN/UPN 参数未生效或模板不允许 |

---

## 阶段四：用证书认证

### 常用命令

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

成功后你可能得到：

- TGT/ccache。
- NT hash。
- 可用于后续工具的认证上下文。

### 证书材料去向

| 材料 | 下一步 |
|---|---|
| PFX 代表高权限用户 | 尝试 PKINIT 换 TGT |
| PFX 代表机器账户 | 评估 RBCD、LDAP、主机访问 |
| PEM/KEY | 转换成工具可用格式 |
| TGT/ccache | 使用 Kerberos 访问 SMB/LDAP/MSSQL |
| NT hash | Pass-the-Hash 或离线记录 |

回看：

- `13-Windows凭证/06-Windows凭证新手闭环与材料去向.md`
- `17-Kerberos委派/04-三类委派攻击学习闭环.md`
- `14-横向移动/06-RDP与Fileless横向移动补充.md`

### 排错表

| 现象 | 排查 |
|---|---|
| PKINIT 失败 | DC 证书、KDC 支持、时间、域名、映射 |
| 证书无法映射用户 | UPN/SAN、强证书绑定、账户映射规则 |
| ccache 不能用 | `KRB5CCNAME`、Realm、时间、SPN |
| 有 TGT 但访问失败 | 目标服务权限不足或需要 TGS |

---

## 阶段五：NTLM Relay 到 ADCS

### 概念说明

NTLM Relay 到 ADCS 的核心是：把一个被诱导认证的 NTLM 身份转发给 ADCS HTTP 端点，申请代表该身份的证书。

### 使用场景

- 存在 ADCS Web Enrollment 或相关 HTTP 端点。
- 能诱导目标机器或用户发起 NTLM 认证。
- 目标环境未阻止这类中继。

### 常用命令方向

```bash
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp --adcs --template Machine
```

后续根据拿到的证书继续认证。

### 注意事项

| 点 | 说明 |
|---|---|
| 目标身份决定证书价值 | 机器账户和用户账户后续路径不同 |
| HTTP 端点很关键 | 没有可用端点，中继路径不成立 |
| EPA/HTTPS/签名可能影响 | 失败时不要只看模板 |
| 证书拿到后要立刻分类 | 放到凭证材料去向总表 |

---

## 附录映射

| 你想查 | 推荐入口 |
|---|---|
| ADCS 原理 | `21-ADCS证书攻击/01-ADCS理论与枚举.md` |
| ESC 判断 | `21-ADCS证书攻击/05-ADCS-ESC攻击决策树详解.md` |
| ADCS 考前速查 | `21-ADCS证书攻击/04-ADCS考试速查.md` |
| 横向移动命令 | `14-横向移动/00-章节指南.md` |
| 凭证材料下一步 | `13-Windows凭证/06-Windows凭证新手闭环与材料去向.md` |
| 总攻击链决策 | `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` |

---

## OSEP 考试相关重点

1. ADCS 不是背 ESC 编号，而是从模板字段和权限推导攻击路径。
2. 申请证书前先确认：谁能申请、申请什么模板、证书代表谁。
3. 拿到 PFX 后立刻判断它能换 TGT、LDAP 操作、机器账户能力还是横向访问。
4. NTLM Relay 到 ADCS 要分清“可中继身份”和“ADCS HTTP 端点”两个条件。
5. 报告里必须能解释“为什么这个模板/端点危险”，不能只贴命令截图。

---

## 自检清单

- [ ] 我能从 Certipy/Certify 输出里找 CA、模板、注册权限、EKU、SAN。
- [ ] 我能解释 ESC1、ESC4、ESC8 的入口条件差异。
- [ ] 我知道 `.pfx`、`.pem`、`ccache`、NT hash 分别下一步怎么用。
- [ ] 我能判断申请失败是权限、模板、CA 名称、SAN 还是认证问题。
- [ ] 我知道 ADCS 命令散落在哪些附录，并能从本篇快速跳转。
