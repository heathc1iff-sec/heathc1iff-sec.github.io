---
title: OSEP-09-MSHTA-XSL与第三方执行
description: '09-应用白名单绕过 | 07-MSHTA-XSL与第三方执行'
pubDate: 2026-01-30T00:01:34+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# MSHTA、XSL 与第三方执行绕过

## 对应课程小节

`9：windows防御机制绕过（应用程序白名单：applocker).html` 中除了 Trusted Folders、DLL、PowerShell CLM，还包含 `Third Party Execution`、`JScript and MSHTA`、`XSL Transform`、`Bypassing AppLocker with C#` 等小节。

这份补充把这些内容整理成考试时的判断模型。

---

## 核心思路

AppLocker 绕过不是“找一个神奇 LOLBin”，而是回答：

```
什么文件类型被限制？
哪些可信程序仍可运行？
可信程序是否能加载我可控的脚本、DLL、配置、XSL、插件或程序集？
加载行为是否被当前规则覆盖？
```

---

## 按课程正序定位

本页承接 `9：windows防御机制绕过（应用程序白名单：applocker).html` 的后半段内容。建议先看 AppLocker 基础和规则枚举，再看本页的 MSHTA、XSL、第三方执行和 C# 可信加载点。

| 学习顺序 | 先解决的问题 | 推荐文件 |
|---|---|---|
| 1 | 哪类文件被限制，规则按路径、哈希还是签名匹配 | `01-AppLocker基础与绕过完整指南.md` |
| 2 | Trusted Folder、DLL、ADS、基础绕过是否成立 | `01-AppLocker基础与绕过完整指南.md`、`02-基础绕过技术.md` |
| 3 | PowerShell 是否进入 CLM，能否用 Runspace 或脚本宿主替代 | `04-PowerShell绕过.md`、`08-AMSI绕过/11-AMSI-CLM联动排错.md` |
| 4 | MSHTA、XSL、第三方程序、C# 加载点是否可用 | 本文件 |
| 5 | 执行后是否被 AV/AMSI/网络继续拦截 | `07-杀软绕过/11-AV绕过决策树.md`、`10-网络过滤绕过/08-出网受限决策树.md` |

---

## 常见可利用面

| 类型 | 判断问题 | 典型风险 |
|---|---|---|
| MSHTA/JScript | `mshta.exe` 或脚本宿主是否允许运行 | 通过 HTML Application 执行脚本逻辑 |
| XSL Transform | 是否允许 `wmic`、`msxsl` 或相关组件处理远程/本地 XSL | XSL 中嵌入脚本执行 |
| 第三方签名程序 | 是否存在白名单允许的厂商程序 | 利用程序的插件、配置或 DLL 加载点 |
| DLL 搜索顺序 | 可信程序是否从可写目录加载 DLL | 放置同名 DLL 获取执行 |
| C# 加载目标 | 是否存在可控参数或加载路径 | 反编译找加载点，喂入恶意程序集或配置 |
| Alternate Data Streams | 路径/脚本规则是否忽略 ADS | 把脚本放入 ADS 规避简单路径规则 |

---

## 枚举优先级

| 优先级 | 枚举项 | 判断价值 |
|---|---|---|
| 1 | 当前用户能运行哪些 EXE、脚本、MSI、DLL | 决定可选绕过大类 |
| 2 | 可写目录是否位于允许路径内 | 决定能否利用 Trusted Folder 或 DLL 加载 |
| 3 | PowerShell 语言模式和脚本规则 | 决定是否走 CLM/Runspace/JScript/MSHTA |
| 4 | 已安装第三方程序和签名厂商 | 决定是否找配置、插件、DLL、程序集加载点 |
| 5 | 出网、代理、TLS 检查 | 决定使用远程脚本还是本地内嵌内容 |

---

## MSHTA 路线

MSHTA 的价值在于它是受信任的 Windows 组件，并且能解释 HTA/JScript/VBScript。复习时不要只记命令，要理解三件事：

1. AppLocker 是否限制脚本规则和 `mshta.exe` 本身。
2. HTA 内容来自本地、远程还是内嵌。
3. 脚本执行后是否会触发 AMSI、代理、父子进程告警。

判断表：

| 现象 | 说明 |
|---|---|
| EXE 被禁但 `mshta.exe` 可运行 | 可以测试脚本型执行器 |
| 脚本规则启用且严格 | MSHTA 可能仍被阻断 |
| AMSI 拦截脚本内容 | 需要先换载体或做内容层处理 |
| 目标不能出网 | 使用本地 HTA 或内嵌内容 |

---

## XSL Transform 路线

XSL 绕过的关键是：某些受信任工具会加载 XSL 并执行其中的脚本扩展。考试里它常作为“脚本受限但系统工具还能解释输入文件”的备选路径。

判断链：

```
能运行可信转换器
  -> 能控制 XSL 内容
  -> XSL 内脚本没有被策略阻断
  -> 脚本能启动后续加载器
```

排查点：

| 卡点 | 排查 |
|---|---|
| 转换器无法运行 | EXE 规则或路径规则 |
| XSL 被读取但不执行 | 脚本扩展被禁用、版本差异 |
| 执行后无回连 | AMSI、代理、出网、payload 位数 |
| 远程 XSL 不加载 | Web 代理、认证、TLS、URL 分类 |

---

## 第三方执行与 C# 加载点

课程里的 C# 绕过重点是：不要只找 Windows 自带 LOLBin，也要找被白名单允许的第三方程序。很多企业规则会信任某个安装目录、签名厂商或管理工具，而这些程序可能存在可控加载点。

枚举方向：

| 方向 | 要找什么 |
|---|---|
| 安装目录 | 普通用户是否可写 |
| DLL 加载 | 缺失 DLL、相对路径 DLL、插件目录 |
| 配置文件 | XML/JSON/YAML/INI 是否能指定程序集或命令 |
| 日志/模板 | 是否能影响脚本解释或模板渲染 |
| 命令行参数 | 是否能传入路径、URL、脚本、插件 |
| .NET 程序 | 是否能反编译找到 `Assembly.Load`、`LoadFrom`、反射调用 |

---

## 第三方程序验证闭环

| 步骤 | 目标 |
|---|---|
| 确认程序可运行 | 证明它在白名单里 |
| 确认输入点可控 | 参数、配置、插件目录、DLL 搜索路径、模板文件 |
| 用无害动作验证执行 | 先弹出、写文件或运行最小命令 |
| 再替换加载层 | 放入 JScript、DLL、程序集或 XSL |
| 记录证据 | 保存规则、可控路径、执行结果、当前身份 |

---

## 第三方执行目标定位

| 目标类型 | 重点看 | 触发入口记录 |
|---|---|---|
| .NET 管理工具 | `Assembly.Load`、`LoadFrom`、插件目录、配置文件 | 参数、配置路径、加载的程序集名 |
| Electron/Node 工具 | 可写资源目录、插件、启动参数 | 用户可写目录、启动命令 |
| Java 工具 | classpath、插件 JAR、配置中的类名 | JAR 路径、类加载错误 |
| 备份/同步/监控代理 | 脚本钩子、外部工具路径、模板 | 任务名、配置字段、执行身份 |
| 签名第三方 EXE | DLL 搜索顺序、缺失 DLL、相对路径 | ProcMon/日志中缺失的 DLL 名 |

定位时保留一张候选表：程序路径、签名/白名单原因、可控输入、验证命令、当前失败点。这样反编译和测试不会散。

---

## 反编译时关注的关键字

| 关键字 | 含义 |
|---|---|
| `Assembly.Load` | 可能存在内存加载程序集 |
| `Assembly.LoadFrom` | 可能从路径加载程序集 |
| `Process.Start` | 可能能影响启动命令 |
| `LoadLibrary` | DLL 加载点 |
| `GetProcAddress` | 动态 API 调用 |
| `ConfigurationManager` | 配置文件可能影响逻辑 |
| `XmlDocument` / `XslCompiledTransform` | XML/XSL 处理链 |
| `ScriptControl` | 脚本执行面 |

---

## 考试决策表

| 当前限制 | 优先测试 |
|---|---|
| 只能运行 Windows 目录里的 EXE | MSHTA、WMIC/XSL、InstallUtil、Workflow Compiler |
| PowerShell 是 CLM | Custom Runspace、JScript/MSHTA、C# 可信加载点 |
| EXE 路径规则严格但 DLL 规则宽松 | DLL 搜索顺序、可信程序 DLL 劫持 |
| 只有某个第三方目录可运行 | 反编译第三方程序，找配置/插件/DLL 加载点 |
| 脚本规则也严格 | 转向 DLL、MSI、签名二进制、服务配置或凭证路线 |

---

## 常见失败与切换

| 失败现象 | 先判断 | 切换方向 |
|---|---|---|
| `mshta.exe` 能启动但脚本不跑 | 脚本规则、AMSI、HTA 内容格式 | XSL、InstallUtil、Workflow、JScript |
| XSL 被加载但无执行 | 脚本扩展、工具版本、路径/URL 访问 | 本地 XSL、MSHTA、第三方加载点 |
| 第三方程序可运行但 DLL 不加载 | 搜索顺序、位数、导出函数、权限 | 插件/配置/程序集加载点 |
| 加载成功但被杀 | AV/AMSI/行为检测 | AV 决策树或换能力层 |
| 执行成功但无回连 | 代理/TLS/出网策略 | 网络过滤绕过 |

---

## 和其他章节联动

| 如果发现 | 跳转 |
|---|---|
| 脚本可执行但被 AMSI 拦 | `08-AMSI绕过` |
| 可以运行 C# 程序但被 AV 杀 | `07-杀软绕过` |
| 找到 DLL 加载点 | `06-进程注入/03-DLL注入技术.md` |
| 只能通过 Office/JScript 触发 | `05-反射式PowerShell/06-客户端反射代码攻击联动.md` |
| 出网失败 | `10-网络过滤绕过` |

---

## 证据记录

| 证据 | 说明 |
|---|---|
| AppLocker 规则截图或导出 | 证明限制条件 |
| 可运行的可信程序 | 证明白名单允许面 |
| 可控输入点 | 证明为什么能影响执行 |
| 执行结果 | 证明绕过效果 |
| 当前身份 | 证明影响范围 |
