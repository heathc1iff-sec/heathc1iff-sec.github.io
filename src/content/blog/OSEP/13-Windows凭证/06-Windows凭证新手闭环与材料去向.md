---
title: OSEP-13-Windows凭证新手闭环与材料去向
description: '13-Windows凭证 | 06-Windows凭证新手闭环与材料去向'
pubDate: 2026-01-30T00:02:14+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Credential Dumping
---

# Windows 凭证新手闭环与材料去向

## 这篇文档解决什么问题

Windows 凭证章节最容易学成“背 Mimikatz 命令”。但 OSEP 真正考的是：你拿到一台 Windows 主机后，能不能判断这台机器上有什么身份材料、这些材料能不能横向移动、能不能进入域攻击链。

这篇文档把 Windows 凭证学习拆成一条闭环：

```text
拿到 Windows foothold
  -> 判断当前权限和登录会话
  -> 找凭证材料
  -> 判断材料类型
  -> 验证材料是否有效
  -> 选择横向移动或域提权路线
  -> 记录证据和排错结论
```

只用于 OSEP 授权实验环境和考试备考，不用于未授权目标。

---

## 先建立核心观念：凭证不是只有密码

初学者常把“凭证”理解成明文密码，其实 Windows 里常见的身份材料很多：

| 材料 | 人话解释 | 常见去向 |
|---|---|---|
| 明文密码 | 用户输入过的真实密码 | SMB、WinRM、RDP、MSSQL、LDAP |
| NTLM Hash | 密码的 NTLM 哈希 | Pass-the-Hash、离线破解 |
| Net-NTLMv2 | 网络认证挑战响应 | 离线破解、中继 |
| Kerberos TGT/TGS | 域内票据 | Pass-the-Ticket、服务访问 |
| Token | 已登录会话的访问令牌 | Impersonation、访问资源 |
| SAM Hash | 本地账户 Hash | 本地管理员复用 |
| LSA Secrets | 服务账户、自动登录、缓存秘密 | 服务账户登录、横向 |
| DPAPI Masterkey | 解密用户加密数据的关键材料 | 浏览器、Vault、WiFi、RDP 凭证 |
| MiniDump | 进程内存转储 | 离线提取 LSASS 凭证 |
| 证书/PFX | 证书身份材料 | ADCS、PKINIT、Schannel |

所以每次拿到材料，都要问：

1. 它代表哪个用户或机器。
2. 它能不能直接认证。
3. 它能不能离线破解。
4. 它能不能中继。
5. 它能不能转成票据、Token 或证书认证。
6. 它能访问哪些主机、服务或 AD 对象。

---

## 拿到 Windows Shell 后的 10 分钟流程

### 0-2 分钟：确认当前身份和权限

```cmd
whoami
whoami /user
whoami /groups
whoami /priv
hostname
ipconfig /all
net config workstation
```

重点判断：

| 输出 | 说明 |
|---|---|
| 当前用户是本地用户还是域用户 | 决定后续认证范围 |
| 是否在 Administrators | 决定是否能读 LSASS/SAM |
| 是否有 `SeDebugPrivilege` | 影响进程内存读取 |
| 是否有域名、DNS 后缀、DC | 决定能否做域枚举 |
| 当前机器是否多人登录 | 可能有 Token 和 LSASS 凭证价值 |

### 2-4 分钟：看登录会话和票据

```cmd
query user
klist
cmdkey /list
net use
```

PowerShell：

```powershell
Get-Process -IncludeUserName 2>$null
Get-ChildItem Env:
```

重点判断：

| 发现 | 下一步 |
|---|---|
| 有域用户交互式登录 | 优先考虑 LSASS、Token、Kerberos |
| 有 RDP 会话 | 看 Token、凭证管理器、剪贴板/映射盘风险 |
| `klist` 有 TGT/TGS | 判断是否能 Pass-the-Ticket |
| `cmdkey /list` 有保存凭证 | 测试能否访问目标资源 |
| `net use` 有共享连接 | 记录目标和使用身份 |

### 4-6 分钟：判断能否直接提取高价值材料

```cmd
reg save HKLM\SAM C:\Windows\Temp\SAM.save
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.save
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY.save
```

如果能读取 LSASS 或做 MiniDump：

```powershell
tasklist /fi "imagename eq lsass.exe"
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Windows\Temp\lsass.dmp full
```

注意：是否能这么做取决于权限、防护和考试环境规则。学习时重点理解“为什么需要管理员/Debug 权限”，不要把命令当万能钥匙。

### 6-8 分钟：找文件型凭证

```powershell
Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue -Include *.kdbx,*.rdp,*.config,*.xml,*.txt,*.ps1,*.bat,*.cmd | Select-Object FullName
Select-String -Path C:\Users\*\Documents\* -Pattern "password|passwd|pwd|credential|token|secret" -ErrorAction SilentlyContinue
```

常见位置：

| 位置 | 可能材料 |
|---|---|
| `C:\Users\*\Documents` | 密码文档、RDP 文件 |
| `C:\Users\*\AppData` | 应用配置、Token、浏览器数据 |
| `C:\ProgramData` | 服务配置、部署脚本 |
| Web 应用目录 | 数据库连接串 |
| 计划任务 | 服务账号、脚本参数 |
| 服务配置 | 启动账号、明文参数 |

### 8-10 分钟：把材料放进“去向表”

不要把凭证截图丢到笔记里就结束。按下面方式分类：

| 材料 | 代表身份 | 验证命令 | 下一步 |
|---|---|---|---|
| 明文密码 |  | `net use`、SMB/WinRM/RDP 测试 | 横向移动 |
| NTLM Hash |  | SMB PtH 测试 | CrackMapExec/Impacket |
| TGT/TGS |  | `klist`、服务访问 | Pass-the-Ticket |
| Token |  | `whoami`、资源访问 | Impersonation |
| PFX/证书 |  | 证书认证 | ADCS/PKINIT |
| SSH Key |  | SSH 登录 | Linux/DevOps 横向 |

同时回看：`13-Windows凭证/06-Windows凭证新手闭环与材料去向.md`。

---

## 凭证来源详解

### LSASS

LSASS 是 Windows 身份认证核心进程，登录会话中的凭证材料可能在它的内存里。

常见材料：

- NTLM Hash。
- Kerberos 票据。
- 某些场景下的明文密码。
- 会话信息。

常用思路：

```text
有本地管理员或高权限
  -> 读取 LSASS 或生成 MiniDump
  -> 离线解析
  -> 分类得到的 Hash/票据/明文
```

注意事项：

| 点 | 说明 |
|---|---|
| 防护会重点监控 LSASS | 直接读取可能触发拦截 |
| MiniDump 适合离线处理 | 降低在目标上运行敏感工具的时间 |
| 不是每次都有明文 | 现代 Windows 默认更少暴露明文 |
| 位数和权限会影响工具 | x86/x64、管理员、PPL 都可能影响 |

排错：

| 现象 | 排查 |
|---|---|
| Access denied | 权限不足、没有 Debug 权限、PPL |
| Dump 文件为空或损坏 | PID 错、权限不足、工具被拦 |
| 解析不出密码 | 本来没有明文、系统版本、防护配置 |
| 工具被杀 | 回到 AV/AMSI/AppLocker 章节 |

### SAM、SYSTEM、SECURITY

SAM 保存本地账户 Hash，SYSTEM 用于解密，SECURITY 可能包含 LSA Secrets。

适合场景：

- 你有本地管理员。
- 想拿本地管理员 Hash。
- 想看本地账户是否在多台机器复用。
- 想离线分析，减少目标上执行工具。

常见命令：

```cmd
reg save HKLM\SAM C:\Windows\Temp\SAM.save
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.save
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY.save
```

离线处理可回到命令附录或工具文档。

注意：本地管理员 Hash 的价值取决于是否复用。如果只在本机有效，它更多用于本机控制；如果在多台机器复用，就能横向移动。

### Kerberos 票据

Kerberos 票据适用于域环境。

查看：

```cmd
klist
```

判断：

| 票据 | 说明 |
|---|---|
| TGT | 能向 KDC 请求服务票据 |
| CIFS TGS | 可能访问 SMB |
| HTTP TGS | 可能访问 Web/WinRM/应用 |
| MSSQLSvc TGS | 可能访问 SQL Server |

注意：

1. 票据有过期时间。
2. 票据绑定用户、域和服务。
3. 导出/注入票据时要关注当前登录会话。
4. DNS、时间偏差、SPN 会影响 Kerberos。

### Token

Token 是已登录身份的访问令牌。它不一定包含密码，但可能让你“借用”某个身份访问资源。

使用场景：

- 高权限用户正在目标机器上登录。
- 服务进程以高权限身份运行。
- 你能模拟或窃取 Token。

判断链：

```text
发现高价值登录会话或进程
  -> 判断当前权限能否查看/模拟 Token
  -> 模拟身份
  -> 验证能访问哪些本地或远程资源
```

注意：Token 常受会话、完整性级别、权限和网络认证限制影响。能本地 impersonate 不一定能远程访问。

### Credential Manager 和 DPAPI

Windows Credential Manager、浏览器、RDP、WiFi、应用密码经常依赖 DPAPI 保护。

常用检查：

```cmd
cmdkey /list
```

PowerShell 或工具可以进一步枚举 Vault、浏览器数据、Masterkey。学习重点是理解：

- DPAPI 通常绑定用户或机器。
- 解密经常需要用户上下文、密码、Masterkey 或备份密钥。
- 拿到文件不等于能解密。

---

## 材料到横向移动的选择表

| 你有的材料 | 优先验证 | 可能路线 |
|---|---|---|
| 明文域用户密码 | SMB/WinRM/RDP/MSSQL/LDAP | 横向、域枚举、ADCS |
| 明文本地管理员密码 | 多主机复用 | SMB/PsExec/WMI |
| NTLM Hash | SMB 是否允许 NTLM | Pass-the-Hash |
| TGT/ccache/kirbi | Kerberos 服务访问 | Pass-the-Ticket |
| CIFS TGS | 对应主机 SMB | 文件访问、远程执行前置 |
| MSSQL 凭证 | SQL 登录权限 | xp_cmdshell、Linked Server |
| Token | 本地资源、网络资源 | Impersonation、凭证读取 |
| PFX/证书 | PKINIT/Schannel | ADCS、LDAP 修改 |
| SSH Key | Linux 主机 | DevOps/加域 Linux |

---

## 常用验证命令

### Windows 内置验证

```cmd
net use \\TARGET\C$ /user:DOMAIN\user Password123!
dir \\TARGET\C$
wmic /node:TARGET /user:DOMAIN\user /password:Password123! process call create "cmd.exe /c whoami"
```

### Kerberos 检查

```cmd
klist
klist purge
```

### PowerShell Remoting

```powershell
$cred = Get-Credential
Test-WSMan TARGET
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }
```

### RDP 方向

```cmd
cmdkey /generic:TERMSRV/TARGET /user:DOMAIN\user /pass:Password123!
mstsc /v:TARGET
```

记录每次验证：

| 目标 | 协议 | 身份 | 结果 | 失败原因 |
|---|---|---|---|---|
|  | SMB |  |  |  |
|  | WinRM |  |  |  |
|  | RDP |  |  |  |
|  | MSSQL |  |  |  |

---

## 初学者排错总表

| 现象 | 先不要做什么 | 优先排查 |
|---|---|---|
| Hash 不能登录 | 不要立刻说 Hash 错 | 目标是否允许 NTLM、是否本地/域账号、管理员权限 |
| 密码 SMB 成功但 WinRM 失败 | 不要换密码 | WinRM 是否开启、用户是否允许远程管理 |
| RDP 密码正确但登录失败 | 不要只看密码 | RDP 权限、NLA、登录限制、组策略 |
| `klist` 有票据但访问失败 | 不要删除票据 | 票据服务类型、SPN、过期时间、DNS |
| Token 模拟成功但远程失败 | 不要以为 Token 无效 | 是否是 delegation token、网络认证限制 |
| Dump 成功但没明文 | 不要重复 Dump | 系统版本、登录类型、Credential Guard、WDigest |
| 凭证很多不知道先用哪个 | 不要平均测试 | 先测高权限、域身份、服务账户、管理员复用 |

---

## OSEP 考试相关重点

1. 凭证章节是横向移动和 AD 攻击的桥，不是独立章节。
2. 每拿到一个材料，都要马上写清楚“代表谁、能去哪、怎么验证”。
3. Hash、票据、Token、证书的使用方式不同，不要混成“都能登录”。
4. MiniDump 离线处理适合降低目标机上工具运行压力，但仍要考虑权限和防护。
5. 报告要保留发现位置、提取方式、验证命令、访问结果，不要只放工具输出。

---

## 自检清单

- [ ] 我能解释 LSASS、SAM、LSA Secrets、DPAPI 的区别。
- [ ] 我知道明文、Hash、票据、Token、证书分别下一步怎么用。
- [ ] 我能判断本地管理员 Hash 是否可能复用。
- [ ] 我知道为什么 Token 本地有效但远程可能失败。
- [ ] 我能把凭证材料写入去向表，而不是只截图保存。
- [ ] 我能把 Windows 凭证章节接到 `14-横向移动`、`15-MSSQL攻击`、`21-ADCS证书攻击`。
