---
title: OSEP-00-web课程映射与复习优先级
description: '00-学习计划 | 02-web课程映射与复习优先级'
pubDate: 2026-01-27T08:00:02+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Life
---

# OSEP Web 课程映射与复习优先级

## 使用方式

这份表把 `C:\Users\Administrator\Desktop\办公\OSEP\web` 下的 HTML 资料，映射到当前知识库目录。复习时建议以知识库为主线，HTML 作为官方课程结构和实验细节的校验源。

推荐节奏：

1. 先读本表确认主题、优先级和对应知识库位置。
2. 进入知识库章节学习原理、判断条件和命令速查。
3. 回到 HTML 只核对课程小节、实验语境和你没有理解的原始表述。
4. 每个主题结束后，用“能否解释触发条件、能否判断失败原因、能否写出报告证据”三件事验收。

---

## 总体结论

`web` 目录覆盖了 PEN-300 的核心链路：客户端攻击、执行绕过、网络过滤绕过、后渗透、横向移动、AD/MSSQL/ADCS/JEA/JIT 以及最终组合攻击链。当前知识库整体覆盖较完整，近期重点把“课程主题映射、考场决策树、组合复盘、报告证据与时间管理”补成可快速发现的入口：

| 优化点 | 现状 | 本次处理 |
|---|---|---|
| ADCS | 命令散落在综合笔记中，缺少独立学习章节 | 已整理为 `21-ADCS证书攻击` |
| 课程映射 | HTML 与知识库目录没有一张总对照表 | 新增本文件 |
| 考试链路 | 有综合案例，但考场决策入口需要更集中 | 统一从 `20-综合渗透案例/00-章节指南.md` 进入 |
| 偏薄专题 | 部分 HTML 小节分散在多个章节，不适合考前快速查 | 新增客户端反射、MSHTA/XSL、Token/MiniDump、RDP/Fileless、MSSQL Relay/CLR、Linux 横向、Kiosk、JEA/JIT 速查 |
| 高频决策树 | 多数主题已有知识点，但考场选择和排错入口不够集中 | 新增 AV、AMSI/CLM、出网受限、进程注入、AD 对象权限、委派、跨域跨森林等速查与决策树 |
| 考前闭环 | 攻击链之外，证据、枚举、时间、失败排错容易分散 | 新增报告证据清单、枚举优先级总表、48 小时时间管理模板、失败排错总表 |
| 初学者精讲 | 原章节偏速查和专项，初学者不容易把 20 个 HTML 串起来 | 用各章节的“新手详解 / 决策树 / 学习闭环”文章串联 |

---

## Web HTML 到知识库映射

| HTML 文件 | 课程主题 | 核心小节 | 知识库位置 | 复习优先级 |
|---|---|---|---|---|
| `1：office钓鱼.html` | Phishing with Microsoft Office | VBA、Win32 API、VBA/PowerShell Shellcode Runner | `03-Office宏攻击` | A |
| `2：日历钓鱼.html` | Phishing with Calendars | ICS、自定义日历邀请、Responder 凭证捕获 | `03-Office宏攻击/13-日历钓鱼攻击.md` | B |
| `3：wsh钓鱼.html` | Phishing with JScript | JScript Dropper、DotNetToJScript、C# Shellcode Runner、SharpShooter | `04-JScript攻击` | A |
| `4：反射式powershell.html` | Reflective PowerShell | UnsafeNativeMethods、DelegateType、内存执行 | `05-反射式PowerShell` | A |
| `5：客户端反射代码攻击.html` | Reflective Code Execution in Client Side Attacks | 客户端场景中的反射式 PowerShell/C# | `03-Office宏攻击`、`04-JScript攻击`、`05-反射式PowerShell` | A |
| `6：进程注入迁移挖空.html` | Process Injection and Migration | 进程注入、DLL 注入、反射 DLL、进程镂空 | `06-进程注入` | A |
| `7：基于编码加密或者修改特征值针对静态杀软绕过.html` | Introduction to Antivirus Evasion | 签名定位、编码/加密、行为绕过、VBA Stomping、WMI 解链 | `07-杀软绕过` | A |
| `8：windows防御机制绕过（amsi+clm）.html` | 源文件需核对 | 文件名标注 AMSI/CLM，但当前导出标题结构与第 7 章 AV 绕过高度重复；不要直接当作 AMSI 主资料 | `07-杀软绕过`、`08-AMSI绕过/11-AMSI-CLM联动排错.md` | A |
| `9：windows防御机制绕过（应用程序白名单：applocker).html` | Application Whitelisting | AppLocker、Trusted Folders、DLL、ADS、CLM、Custom Runspaces、MSHTA/XSL | `09-应用白名单绕过` | A |
| `10：绕过网络过滤器.html` | Bypassing Network Filters | DNS Filter、Web Proxy、IDS/IPS、自定义证书、HTTPS Inspection、Domain Fronting、DNS Tunneling | `10-网络过滤绕过` | B |
| `11：linux维持权限（绕杀软以及简易后门部署）.html` | Linux Post-Exploitation | 用户配置文件、VIM 后门、Linux AV、共享库劫持、LD_PRELOAD | `11-Linux后渗透` | B |
| `12：自助信息亭渗透.html` | Kiosk Breakouts | Kiosk 枚举、命令执行、Firefox Profile、模拟交互 Shell、提权 | `12-Kiosk突破` | C |
| `13：windows凭证.html` | Windows Credentials | SAM、Access Token、Impersonation、Mimikatz、Memory Dump、MiniDumpWriteDump | `13-Windows凭证` | A |
| `14：windows横向利用（rdp+psexec）.html` | Windows Lateral Movement | RDP、Reverse RDP Proxy、明文凭证、Fileless Lateral Movement、C# 实现 | `14-横向移动` | A |
| `19：linux域内横向移动（ssh后门部署+ad中的linux）.html` | Linux Lateral Movement | SSH Keys、SSH Persistence、ControlMaster、SSH-Agent、Ansible、Artifactory、Linux Kerberos、Keytab、ccache | `11-Linux后渗透`、`14-横向移动` | B |
| `15：mssql数据库攻击向量.html` | Microsoft SQL Attacks | SQL 枚举、认证、UNC Path Injection、Relay、xp_cmdshell、CLR Assembly、Linked SQL Servers | `15-MSSQL攻击` | A |
| `16：ad间攻击向量.html` | Active Directory Exploitation | ACL、GenericAll、WriteDACL、委派、森林信任、Extra SID、打印机、跨森林、SQL Link | `16-AD权限滥用`、`17-Kerberos委派`、`18-域森林攻击` | A |
| `17：ad基于证书攻击（adcs）.html` | Attacking ADCS | ADCS Theory、Misconfigured Templates、NTLM Relay to ADCS HTTP Endpoints | `21-ADCS证书攻击` | A |
| `18：ad内部攻击向量（JEA以及JIT策略）.html` | Attacking Active Directory | Kerberos Delegation、JEA、JIT | `17-Kerberos委派`、`19-JEA与JIT` | B |
| `组合起来的渗透流程.html` | Combining the Pieces | Initial Enumeration、Foothold、Post-Exploitation、Delegation、Lateral Movement、Domain Admin | `20-综合渗透案例` | A |

---

## 源资料核对备注

本轮按正序核对前 10 个 HTML 时发现一个需要特别标记的点：`8：windows防御机制绕过（amsi+clm）.html` 的文件名像是 AMSI/CLM，但页面标题结构与 `7：基于编码加密或者修改特征值针对静态杀软绕过.html` 高度一致，疑似重复导出或源文件命名错误。

复习时按下面的规则处理：

| 情况 | 处理方式 |
|---|---|
| 复习 AV 静态/行为绕过 | 以 `07-杀软绕过` 为主，参考第 7/8 个 HTML 的重复内容 |
| 复习 AMSI 原理和补丁 | 以 `08-AMSI绕过` 为主，不依赖第 8 个 HTML |
| 复习 CLM/AppLocker 联动 | 以 `08-AMSI绕过/11-AMSI-CLM联动排错.md` 和 `09-应用白名单绕过` 为主 |
| 后续重新导出课程资料 | 优先确认是否缺失真正的 AMSI/CLM 原始 HTML |

---

## 初学者串联阅读索引

如果你是初学者，建议先读各章节里的“新手详解 / 决策树 / 学习闭环”文章。这个索引不会替代原章节，而是把原章节讲成能理解、能练习、能排错的教程。

| 精讲文件 | 覆盖 HTML | 适合解决的问题 |
|---|---|---|
| `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` | `组合起来的渗透流程`、`19`、`18`、`17`、`16` | 不知道 ADCS、委派、JEA/JIT、森林信任、Linux 横向怎么放进完整攻击链 |
| `15-MSSQL攻击/07-MSSQL从凭证到代码执行学习闭环.md` | `15`、`14`、`13`、`12` | 不知道 MSSQL、RDP/Fileless、Windows 凭证、Kiosk 之间如何互相转化 |
| `11-Linux后渗透/11-Linux到AD与DevOps横向学习闭环.md` | `11`、`10` | 不知道 Linux 后渗透和出网受限怎么从基础条件开始判断 |
| `07-杀软绕过/12-AV绕过新手详解与实验闭环.md` | `9`、`8`、`7`、`6` | 不知道 AV、AMSI、CLM、AppLocker、进程注入卡在哪一层 |
| `03-Office宏攻击/16-Office宏攻击新手详解与考试闭环.md` | `5`、`4`、`3`、`2`、`1` | 不知道 Office、JScript、反射 PowerShell、ICS 和客户端反射链路的关系 |

---

## 复习优先级定义

| 优先级 | 含义 | 复习目标 |
|---|---|---|
| A | 考试链路核心，必须能独立判断和复现 | 能从枚举结果推导下一步，并能解释失败原因 |
| B | 常见辅助链路，能扩大可选路径 | 能识别机会点，知道何时切换工具或攻击面 |
| C | 场景型主题，出现时很关键但概率较低 | 能快速定位对应笔记，不在考试里长时间卡住 |

---

## 查漏补缺清单

| 主题 | 当前复习动作 |
|---|---|
| ADCS | 先读 `21-ADCS证书攻击/00-章节指南.md`，再用 `21-ADCS证书攻击/04-ADCS考试速查.md` 做闭卷回忆 |
| Combining the Pieces | 用 `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` 训练 30 分钟循环枚举 |
| Linux Lateral Movement | 把 `11-Linux后渗透` 的 Ansible、Artifactory、Kerberos 与 `14-横向移动` 交叉复习 |
| AppLocker + CLM | 把 `08-AMSI绕过` 和 `09-应用白名单绕过` 连成一条“执行受限时如何恢复能力”的链 |
| MSSQL + Forest | 重点理解 SQL Link 如何变成跨边界移动，而不只是记 `xp_cmdshell` |
| AMSI/CLM 源资料核对 | 第 8 个 HTML 疑似 AV 重复导出，后续如重新导出课程资料，应优先补齐真正 AMSI/CLM 页面 |
| DNS 隧道与域前置 | 先读 `10-网络过滤绕过/11-DNS隧道去重与学习路线.md`，再用 `10-网络过滤绕过/12-域前置现实限制说明.md` 分清课程模型和现实限制 |
| JEA/JIT | 先读 `19-JEA与JIT/03-JEA-JIT初学者决策树.md`，再回到 `19-JEA与JIT/02-考试速查与排错.md` 做考场压缩 |
| Linux 到 AD/DevOps | 用 `11-Linux后渗透/11-Linux到AD与DevOps横向学习闭环.md` 把 SSH、ccache、keytab、Ansible、Artifactory 统一成横向路线 |
| ADCS 命令去向 | 用 `21-ADCS证书攻击/06-ADCS命令索引与附录映射.md` 把 Certipy/Certify、PFX、ccache、NTLM Relay 和附录命令串起来 |

---

## 新增专题索引

| 新增文件 | 用途 |
|---|---|
| `02-操作系统与编程理论/07-OSEP基础概念速查.md` | 把托管/非托管、WOW64、Win32 API、注册表等基础概念压缩成考前速查 |
| `03-Office宏攻击/15-客户端初始访问考试速查.md` | 汇总 Office、HTML Smuggling、日历钓鱼等初始访问入口与证据点 |
| `03-Office宏攻击/17-Office与日历钓鱼原文考点精读.md` | 对照 `1：office钓鱼.html` 和 `2：日历钓鱼.html`，逐节解释 VBA、Win32 API、Shellcode Runner、ICS、Responder 的原文考点 |
| `04-JScript攻击/09-JScript投递与DotNetToJScript考试速查.md` | 聚焦 JScript Dropper、DotNetToJScript、SharpShooter 的选择与排错 |
| `04-JScript攻击/11-JScript与DotNetToJScript原文考点精读.md` | 对照 `3：wsh钓鱼.html`，逐节解释 WSH、JScript Dropper、C#、DotNetToJScript、Shellcode Runner、SharpShooter |
| `05-反射式PowerShell/06-客户端反射代码攻击联动.md` | 把 Office/JScript/PowerShell/C# 反射加载连成可替换的执行链 |
| `05-反射式PowerShell/08-反射PowerShell与客户端反射原文考点精读.md` | 对照 `4：反射式powershell.html` 和 `5：客户端反射代码攻击.html`，拆解 .NET 反射、UnsafeNativeMethods、DelegateType、客户端反射组合 |
| `06-进程注入/08-注入技术选择与排错.md` | 对比进程注入、DLL 注入、反射 DLL、进程镂空的选择条件和失败检查 |
| `07-杀软绕过/11-AV绕过决策树.md` | 按签名、启发式、行为拦截拆解 AV 绕过路线 |
| `08-AMSI绕过/11-AMSI-CLM联动排错.md` | 把 AMSI、CLM、PowerShell 受限执行串成联动排错流程 |
| `09-应用白名单绕过/07-MSHTA-XSL与第三方执行.md` | 补齐 MSHTA、XSL Transform、第三方可信程序加载点 |
| `10-网络过滤绕过/08-出网受限决策树.md` | 面向 DNS、代理、HTTPS Inspection、IDS/IPS 的出网受限判断入口 |
| `11-Linux后渗透/10-Linux域内横向移动考试速查.md` | 串联 SSH Agent、ControlMaster、Keytab、ccache、Ansible、Artifactory |
| `12-Kiosk突破/04-Kiosk突破考试速查.md` | 把 Kiosk UI 突破整理成考场判断链 |
| `12-Kiosk突破/05-Kiosk从受限UI到命令执行闭环.md` | 从受限 UI、文件读写、URI Scheme、Profile 到命令执行和提权形成闭环 |
| `13-Windows凭证/05-Token与MiniDump离线处理.md` | 补齐 Token、RDP 凭证暴露、MiniDump 离线处理 |
| `13-Windows凭证/06-Windows凭证新手闭环与材料去向.md` | 把 LSASS、SAM、Token、DPAPI、Hash、票据、证书和横向去向串成闭环 |
| `14-横向移动/06-RDP与Fileless横向移动补充.md` | 补齐 Reverse RDP Proxy、RDP 明文风险、Fileless 横向 |
| `14-横向移动/07-横向移动新手决策树与排错.md` | 从身份材料、开放端口、认证方式和权限选择 SMB/WMI/WinRM/RDP/MSSQL/SSH |
| `15-MSSQL攻击/06-Relay与CLR自定义程序集.md` | 补齐 Relay My Hash、CLR Assembly、MSSQL 跨边界链路 |
| `15-MSSQL攻击/07-MSSQL从凭证到代码执行学习闭环.md` | 串联 SQL 连接、权限判断、UNC 捕获、xp_cmdshell、CLR、Linked Server 和 AD 联动 |
| `16-AD权限滥用/06-AD对象权限攻击决策树.md` | 把 GenericAll、WriteDACL、RBCD、DCSync 等 AD 对象权限转换成攻击选择 |
| `17-Kerberos委派/03-委派攻击考试速查.md` | 汇总无约束、约束委派、RBCD 的发现、利用与证据保留 |
| `18-域森林攻击/05-跨域跨森林考试速查.md` | 聚焦信任、Extra SID、跨域/跨森林路径判断 |
| `18-域森林攻击/06-跨域跨森林决策树.md` | 从当前域、信任方向、SID Filtering、SQL Link、ADCS 和可用凭证判断跨边界路线 |
| `19-JEA与JIT/02-考试速查与排错.md` | 补齐 JEA/JIT 的考场发现、利用和排错清单 |
| `19-JEA与JIT/03-JEA-JIT初学者决策树.md` | 用初学者视角拆清 JEA 端点、Role Capability、RunAs、JIT 临时组和票据刷新 |
| `20-综合渗透案例/02-Combining-the-Pieces复盘模板.md` | 用复盘模板把入口、枚举、利用、横向、提权、证据闭环串起来 |
| `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` | 把 foothold、提权、凭证、横向、AD 提权和报告证据连成完整复盘线 |
| `21-ADCS证书攻击/05-ADCS-ESC攻击决策树详解.md` | 用 ESC 判断树解释模板、权限、SAN、EKU、HTTP 端点和证书认证 |
| `21-ADCS证书攻击/06-ADCS命令索引与附录映射.md` | 按阶段索引 ADCS 命令，并说明 PFX、ccache、LDAP、Relay 的后续去向 |
| `00-学习计划/02-web课程映射与复习优先级.md` | 初学者按 web 资料倒序学习的总入口 |
| `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` | 精讲综合攻击链、Linux 域内、委派/JEA/JIT、ADCS、域森林 |
| `15-MSSQL攻击/07-MSSQL从凭证到代码执行学习闭环.md` | 精讲 MSSQL、Windows 横向、凭证材料、Kiosk |
| `11-Linux后渗透/11-Linux到AD与DevOps横向学习闭环.md` | 精讲 Linux 维持权限、共享库、Linux AV、代理和网络过滤 |
| `07-杀软绕过/12-AV绕过新手详解与实验闭环.md` | 精讲 AppLocker、AMSI/CLM、AV 绕过、进程注入 |
| `03-Office宏攻击/16-Office宏攻击新手详解与考试闭环.md` | 精讲 Office、日历、JScript、反射 PowerShell、客户端反射链 |
| `00-学习计划/03-OSEP术语速查与概念对照.md` | 提供术语翻译、分层判断、凭证材料去向、学习卡、实验记录和报告证据模板 |
| `20-综合渗透案例/02-Combining-the-Pieces复盘模板.md` | 考试报告截图、命令、身份、影响范围和时间线证据入口 |
| `20-综合渗透案例/00-章节指南.md` | 从主机、凭证、网络、AD、MSSQL、ADCS 到横向移动的枚举顺序总表 |
| `20-综合渗透案例/02-Combining-the-Pieces复盘模板.md` | 把 48 小时拆成枚举、攻击、复盘、报告的时间盒 |
| `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` | 按权限、网络、认证、架构、策略、工具和证据缺口定位失败原因 |
| `13-Windows凭证/06-Windows凭证新手闭环与材料去向.md` | 把明文、Hash、票据、证书、Token、SSH Key、API Key 分类到下一步攻击路线 |
| `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` | 用总决策树串联入口、提权、凭证、横向、ADCS、委派和域控目标 |
| `10-网络过滤绕过/11-DNS隧道去重与学习路线.md` | 说明 DNS 隧道各文件定位、学习顺序、失败排错和何时不该优先使用 DNS 隧道 |
| `10-网络过滤绕过/12-域前置现实限制说明.md` | 分清 SNI、Host、证书、CDN 回源和现代云厂商限制 |
| `11-Linux后渗透/11-Linux到AD与DevOps横向学习闭环.md` | 把 Linux Shell 后枚举、SSH、Kerberos、Ansible、Artifactory 与 AD 横向联动 |

---

## 考前最小闭环

每个 A 类主题至少完成一次下面的闭环：

1. 写出入口条件：我需要什么权限、凭证、端口、服务或配置。
2. 写出枚举信号：我看到什么字段或输出，才说明这个方向成立。
3. 写出执行路径：我选择哪类工具，为什么不用另一个工具。
4. 写出失败排查：权限、网络、认证、时间、位数、架构、策略限制分别怎么检查。
5. 写出报告证据：截图、命令、时间点、目标、获得的身份和影响范围。

考前建议把闭环落到四张总表：

| 闭环动作 | 推荐入口 |
|---|---|
| 证据是否足够写报告 | `20-综合渗透案例/02-Combining-the-Pieces复盘模板.md` |
| 下一步先枚举什么 | `20-综合渗透案例/00-章节指南.md` |
| 48 小时如何分配 | `20-综合渗透案例/02-Combining-the-Pieces复盘模板.md` |
| 卡住时怎么排错 | `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` |
| 拿到凭证材料后走哪条路 | `13-Windows凭证/06-Windows凭证新手闭环与材料去向.md` |
| 从入口到域控如何决策 | `20-综合渗透案例/03-从单点突破到域控的复盘式攻击链.md` |
## 进程注入、迁移、镂空

- 原文对应：`6：进程注入迁移挖空.html`
- 优先级：高
- 推荐先读：`06-进程注入/10-进程注入迁移镂空原文考点精读.md`
- 关键问题：为什么要把 payload 放进别的进程、如何选择目标进程、为什么迁移不等于提权、Process Hollowing 与普通注入有什么区别
- 复习方式：先记攻击链位置，再记 API 顺序，最后看失败排错
