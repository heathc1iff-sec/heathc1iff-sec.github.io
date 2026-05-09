---
title: OSEP-19-JEA-JIT初学者决策树
description: '19-JEA与JIT | 03-JEA-JIT初学者决策树'
pubDate: 2026-01-30T00:02:54+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
---

# JEA/JIT 初学者决策树

## 这篇文档解决什么问题

JEA 和 JIT 很容易被初学者误认为是“又一种提权漏洞”。更准确地说，它们是企业为了减少长期高权限账户而设计的管理机制：

- JEA 解决“你进入一个管理 PowerShell 会话后，只允许你执行哪些命令”。
- JIT 解决“你是否能在一个很短的时间窗口内临时获得某个权限”。

对 OSEP 来说，重点不是背定义，而是看到线索后能判断：

1. 这是不是一个受限管理入口。
2. 当前身份能不能连接、申请或影响它。
3. 它给出的命令、路径、参数、临时组成员关系能不能变成真实访问能力。
4. 失败时该检查端点、权限、Kerberos 票据、GPO，还是命令限制。

只在授权实验环境和考试备考中练习，不对未授权目标使用。

---

## 一句话区分 JEA 和 JIT

| 机制 | 你可以怎么理解 | 攻击者关注点 |
|---|---|---|
| JEA | 给你一个受限制的管理员控制台 | 限制是否配置过宽，能否通过允许命令绕出受限环境 |
| JIT | 临时把你加入某个权限组 | 能否申请、审批、刷新票据，并在时间窗口内访问目标 |

如果你看到的是 PowerShell 端点、`ConfigurationName`、`VisibleCmdlets`、`RoleCapabilities`，优先想 JEA。

如果你看到的是临时组成员、审批流程、PAM、TTL group membership、请求/批准/激活权限，优先想 JIT。

---

## 初学者必须先理解的概念

### PowerShell Remoting

JEA 通常建立在 PowerShell Remoting 上。你不是打开一个完整的 PowerShell，而是连接到某个预配置端点。

常见命令：

```powershell
Get-PSSessionConfiguration
Enter-PSSession -ComputerName TARGET -ConfigurationName EndpointName
Invoke-Command -ComputerName TARGET -ConfigurationName EndpointName -ScriptBlock { whoami }
```

排错重点：

| 现象 | 更可能的问题 |
|---|---|
| WinRM 端口不通 | 网络、防火墙、服务未启动 |
| 端点不存在 | 名字错、端点只在另一台机器上 |
| 认证失败 | 凭证无效、域/本地身份混淆、SPN/Kerberos 问题 |
| 连接成功但命令很少 | JEA 正常限制，不是失败 |

### Session Configuration

Session Configuration 是 PowerShell Remoting 的端点配置。JEA 会把端点配置成只暴露少量命令。

你要关心：

- 端点名字是什么。
- 哪些用户或组可以连接。
- 进入后语言模式是什么。
- 可见命令和参数范围是什么。
- 是否使用 `RunAsVirtualAccount` 或固定 RunAs 身份。

### Role Capability

Role Capability 决定某类用户进入 JEA 会话后能看到什么命令。

常见字段：

| 字段 | 初学者解释 |
|---|---|
| `VisibleCmdlets` | 允许你用哪些 cmdlet |
| `VisibleFunctions` | 允许你用哪些函数 |
| `VisibleExternalCommands` | 允许你调用哪些外部程序 |
| `FunctionDefinitions` | 端点自定义函数，可能封装危险操作 |
| `ModulesToImport` | 自动加载的模块，可能扩大攻击面 |

### Constrained Language Mode

JEA 会话里经常是 Constrained Language Mode。它限制 .NET 类型、反射、任意对象创建等能力。

快速检查：

```powershell
$ExecutionContext.SessionState.LanguageMode
Get-Command
```

注意：CLM 限制的是 PowerShell 语言能力，不等于网络不通，也不等于文件系统不可写。

### RunAsVirtualAccount

如果 JEA 端点使用虚拟账户运行命令，你在会话里的某些命令可能以目标机本地管理员能力执行。

关注点：

| 检查点 | 说明 |
|---|---|
| 当前会话内 `whoami /groups` | 看实际执行身份和组 |
| 可执行命令是否能读写敏感路径 | 虚拟账户可能有本地管理员能力 |
| 可否访问远程资源 | 虚拟账户通常不一定能跨机器使用 |

### JIT/PAM

JIT 常见于特权访问管理。你可能通过一个入口申请临时加入某个组，审批通过后获得时间有限的权限。

关键点：

- 请求者：谁能申请。
- 审批者：谁能批准。
- 目标组：最终获得什么权限。
- 时间窗口：权限何时生效，何时过期。
- 票据刷新：Kerberos 票据里需要带上新的组成员关系。

---

## 正序学习路线

| 阶段 | 学什么 | 推荐文件 |
|---|---|---|
| 1 | JEA/JIT 基础定义和课程流程 | `01-JEA-JIT利用.md` |
| 2 | 考场快速判断和失败现象 | `02-考试速查与排错.md` |
| 3 | 用本篇把 JEA/JIT 转成决策树 | `03-JEA-JIT初学者决策树.md` |
| 4 | 联动凭证、横向移动、AD 权限 | `13-Windows凭证`、`14-横向移动`、`16-AD权限滥用` |

学习时不要一开始就问“怎么打”。先问：

1. 我看到的是端点还是临时权限。
2. 我现在是什么身份。
3. 我能连接、申请、审批、写文件、读配置中的哪一种。
4. 这个能力能不能转成凭证、执行、组成员或横向移动。

---

## 总决策树

```text
发现疑似 JEA/JIT 线索
  |
  +-- 线索是 PowerShell 端点、ConfigurationName、受限命令？
  |     |
  |     +-- 是：走 JEA 判断链
  |     |     |
  |     |     +-- 当前身份能连接端点吗？
  |     |     |     |
  |     |     |     +-- 不能：查 WinRM、端点 ACL、凭证、Kerberos
  |     |     |     +-- 能：枚举 Get-Command、LanguageMode、可读写路径
  |     |     |
  |     |     +-- 允许命令能直接执行程序吗？
  |     |     |     |
  |     |     |     +-- 能：尝试受限范围内的合法执行
  |     |     |     +-- 不能：看是否能读配置、复制文件、触发脚本/服务
  |     |     |
  |     |     +-- 是否能拿到凭证、写入加载点或扩大权限？
  |     |
  |     +-- 否：继续看 JIT 或其他 AD 路径
  |
  +-- 线索是临时组、审批、PAM、TTL membership？
        |
        +-- 是：走 JIT 判断链
        |     |
        |     +-- 当前身份能申请或影响审批吗？
        |     |     |
        |     |     +-- 不能：枚举请求组、审批组、目标组和 Web/API 权限
        |     |     +-- 能：申请临时权限
        |     |
        |     +-- 权限是否生效？
        |     |     |
        |     |     +-- 否：查审批状态、同步、GPO、票据刷新
        |     |     +-- 是：在时间窗口内横向或提取凭证
        |
        +-- 否：回到 ACL、ADCS、委派、MSSQL 等路径
```

---

## JEA 枚举步骤清单

### 1. 找端点

```powershell
Get-PSSessionConfiguration
Get-PSSessionConfiguration | Select-Object Name,Permission
```

从历史记录里找：

```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Pattern "ConfigurationName|Enter-PSSession|Invoke-Command"
```

你要记录：

| 项目 | 为什么重要 |
|---|---|
| 端点名 | 后续连接必须准确 |
| 目标主机 | JEA 是主机级端点，不一定每台都有 |
| 可连接用户/组 | 判断当前凭证是否有价值 |
| 历史命令 | 可能暴露真实管理员使用方式 |

### 2. 连接端点

```powershell
Enter-PSSession -ComputerName TARGET -ConfigurationName EndpointName
```

如果需要凭证：

```powershell
$cred = Get-Credential
Enter-PSSession -ComputerName TARGET -ConfigurationName EndpointName -Credential $cred
```

常见失败：

| 报错方向 | 排查 |
|---|---|
| Access denied | 当前用户不在端点允许组 |
| Cannot find configuration | 端点名或目标机器错 |
| WinRM cannot process request | WinRM 服务、SPN、认证方式、防火墙 |
| Kerberos auth failed | 时间偏差、DNS、域名、SPN、跨域认证 |

### 3. 进入后先不要乱跑，先看限制

```powershell
whoami
whoami /groups
$ExecutionContext.SessionState.LanguageMode
Get-Command
Get-Command | Select-Object Name,CommandType,Source
```

如果 `Get-Command` 很少，这是 JEA 的设计。你要把每个命令当作“可能的突破面”分析。

### 4. 看命令参数是否被限制

```powershell
Get-Command Copy-Item -Syntax
Get-Help Copy-Item -Full
```

初学者容易忽略参数限制。JEA 可能允许 `Copy-Item`，但只允许固定路径；也可能允许 `Restart-Service`，但只允许固定服务名。

记录模板：

| 命令 | 是否可用 | 参数限制 | 潜在用途 | 下一步 |
|---|---|---|---|---|
| `Copy-Item` |  |  | 读写文件、投递文件 |  |
| `Start-Process` |  |  | 启动程序 |  |
| `Get-Content` |  |  | 读取配置和凭证 |  |
| `Restart-Service` |  |  | 触发 DLL/配置加载 |  |

---

## JEA 高风险能力详解

### 文件读取

如果你能读文件，优先找：

```powershell
Get-Content C:\Path\To\config.xml
Get-Content C:\Windows\Panther\Unattend.xml
Get-Content C:\ProgramData\*\*.config
```

可读文件的价值：

| 文件类型 | 可能发现 |
|---|---|
| Web/App 配置 | 数据库连接串、服务账户 |
| 部署脚本 | 明文密码、共享路径、管理员操作习惯 |
| 备份文件 | 旧凭证、证书、配置 |
| Transcript | 管理员曾经执行过的命令 |

### 文件写入

如果你能写文件，先判断写入点是否会被执行或加载：

| 写入位置 | 可能用途 |
|---|---|
| 服务目录 | DLL 劫持、配置替换 |
| 脚本目录 | 等待计划任务或管理员调用 |
| Web 根目录 | Web shell 或配置修改 |
| 用户启动目录 | 下次登录触发 |
| 可信执行路径 | 配合 AppLocker 默认规则 |

不要只证明“能写文件”。要证明这个写入能否变成执行、凭证读取或权限变化。

### 启动进程

如果 `Start-Process`、`Invoke-Item`、外部命令可用，就要检查：

1. 是否能指定任意路径。
2. 是否能传入参数。
3. 执行身份是谁。
4. 输出能不能回显。
5. 进程是否被 AppLocker/AMSI/AV 拦截。

最小验证：

```powershell
Start-Process -FilePath "C:\Windows\System32\cmd.exe" -ArgumentList "/c whoami > C:\Windows\Temp\jea.txt"
Get-Content C:\Windows\Temp\jea.txt
```

### 服务控制

如果能重启服务或修改配置，要联想到：

- 服务二进制路径。
- DLL 加载路径。
- 配置文件读取路径。
- 服务账户权限。

配合学习：

- `06-进程注入/09-进程注入新手详解与排错.md`
- `09-应用白名单绕过/08-AppLocker新手详解与绕过地图.md`
- `13-Windows凭证/05-Token与MiniDump离线处理.md`

---

## JIT 枚举步骤清单

### 1. 找 JIT 线索

常见线索：

| 线索 | 说明 |
|---|---|
| 管理 Web 入口 | 申请临时权限 |
| 组名包含 `JIT`、`PAM`、`Request`、`Approve` | 角色分工 |
| GPO 把某个域组加入本地 Administrators | 权限落点 |
| 组成员带 TTL | 临时成员关系 |
| 文档或脚本提到审批流程 | 业务流程入口 |

PowerShell 枚举：

```powershell
net group /domain
net group "Some JIT Group" /domain
whoami /groups
gpresult /r
```

如果有 AD PowerShell 模块：

```powershell
Get-ADGroup -Filter 'Name -like "*JIT*" -or Name -like "*PAM*"'
Get-ADGroupMember "GroupName"
```

### 2. 分清三类角色

| 角色 | 你要问的问题 | 成功标志 |
|---|---|---|
| 请求者 | 当前用户能不能发起申请 | 申请记录创建成功 |
| 审批者 | 谁能批准，能否影响审批 | 状态从 pending 到 approved |
| 目标权限组 | 最终获得什么访问能力 | 组成员、GPO、本地管理员变化 |

JIT 不是“申请成功就等于能打”。必须验证权限真的落到目标资源上。

### 3. 权限生效后刷新票据

Kerberos 票据在登录时包含组成员关系。JIT 加组后，如果你还拿着旧票据，`whoami /groups` 可能看不到新组。

常见动作：

```cmd
klist
klist purge
```

然后重新建立会话或重新认证，再检查：

```cmd
whoami /groups
net localgroup administrators
```

### 4. 时间窗口内做什么

JIT 权限可能只有几分钟到几十分钟。不要拿到权限后才开始想路线。

优先动作：

| 动作 | 目标 |
|---|---|
| 访问目标主机 | 证明权限生效 |
| 抓取必要证据 | 截图、命令、时间、身份 |
| 枚举凭证材料 | Token、配置、服务账户 |
| 横向移动 | 使用临时权限打开下一跳 |
| 记录过期时间 | 报告和排错都需要 |

---

## 从现象反推问题

| 现象 | 更可能原因 | 下一步 |
|---|---|---|
| 端点连接不上 | 端点 ACL、WinRM、认证、端点名 | 回到 JEA 枚举 |
| 进入端点后什么都不能做 | Role Capability 很窄 | 查命令参数、Transcript、可读路径 |
| 允许 `Copy-Item` 但不能写目标 | 路径或权限限制 | 换可写目录、看参数约束 |
| 写入成功但没有触发 | 加载点错误或需重启 | 查服务、计划任务、应用加载逻辑 |
| `Start-Process` 失败 | 命令被限制、AppLocker、AV | 查事件日志和应用白名单章节 |
| JIT 申请成功但权限没变 | 审批未完成、同步延迟、旧票据 | 查状态、GPO、`klist purge` |
| `whoami /groups` 没有新组 | 旧登录会话 | 清票据或新建会话 |
| 目标机器仍拒绝访问 | GPO 未应用、目标组不对应 | 查本地组、`gpresult`、策略作用域 |

---

## 常用命令索引

### JEA 端点与会话

```powershell
Get-PSSessionConfiguration
Get-PSSessionConfiguration | Format-List *
Enter-PSSession -ComputerName TARGET -ConfigurationName EndpointName
Invoke-Command -ComputerName TARGET -ConfigurationName EndpointName -ScriptBlock { whoami }
```

### 会话限制

```powershell
$ExecutionContext.SessionState.LanguageMode
Get-Command
Get-Command CommandName -Syntax
whoami /groups
```

### 端点线索

```powershell
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Pattern "ConfigurationName|Enter-PSSession|Invoke-Command"
Get-ChildItem -Path "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Filter "*.psrc" -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Filter "*.pssc" -ErrorAction SilentlyContinue
```

### JIT/组成员

```cmd
whoami /groups
net group /domain
net group "GroupName" /domain
gpresult /r
klist
klist purge
```

---

## 注意事项

1. JEA 的突破点通常来自配置过宽，不是所有 JEA 都能突破。
2. 允许一个命令不代表允许这个命令的所有参数。
3. JEA 会话里的执行身份可能和你登录身份不同，要反复验证 `whoami`。
4. JIT 申请成功后要看权限是否真的落到目标，不要只看审批页面。
5. Kerberos 组成员变化经常需要刷新票据或新建登录会话。
6. 如果 JEA/JIT 路径太窄，不要死磕，及时切回 ACL、ADCS、MSSQL、委派等主线。

---

## OSEP 考试相关重点

| 考点 | 你要能做到 |
|---|---|
| 识别 JEA | 从 PowerShell 历史、端点、受限命令看出 JEA |
| 识别 JIT | 从临时组、申请入口、GPO、本地管理员变化看出 JIT |
| 解释风险 | 说明为什么某个允许命令或临时权限能扩大影响 |
| 快速验证 | 用最小命令证明连接、限制、权限生效 |
| 排错 | 区分端点、权限、票据、GPO、AppLocker、网络问题 |
| 报告 | 保留端点名、命令限制、申请记录、权限窗口、访问结果 |

---

## 自检清单

- [ ] 我能用自己的话解释 JEA 和 JIT 的区别。
- [ ] 我知道 `Get-PSSessionConfiguration` 查什么。
- [ ] 我进入 JEA 会话后会先查 `Get-Command` 和 LanguageMode。
- [ ] 我能判断 `Copy-Item`、`Start-Process`、`Get-Content` 的风险。
- [ ] 我知道 JIT 加组后为什么要刷新 Kerberos 票据。
- [ ] 我能把 JIT 临时权限转成横向移动或凭证获取动作。
- [ ] 我知道什么时候该放弃 JEA/JIT，切换到 ADCS、ACL、委派或 MSSQL。
