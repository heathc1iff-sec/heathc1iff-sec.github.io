---
title: OSEP-09-AppLocker基础与绕过完整指南
description: '09-应用白名单绕过 | 01-AppLocker基础与绕过完整指南'
pubDate: 2026-01-30T00:01:28+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Exploit Development
---

# AppLocker 基础与绕过完整指南

本文件是 `09-应用白名单绕过` 的 AppLocker 主文档。原来的 AppLocker 基础概述、基础、从零开始和完整指南内容已经合并和重写，旧文件已归档到 `_archive\2026-05-07-深度优化`。

## 这一章到底在学什么

AppLocker 是 Windows 的应用程序白名单机制。它的思路不是“发现坏程序就拦”，而是“只有符合规则的程序才允许运行”。

对渗透测试学习来说，AppLocker 的核心意义是：

```text
你已经拿到执行机会，但目标机器不允许你的程序或脚本运行。
你必须先判断限制来自哪里，再选择合适的受信任执行路径。
```

这章不是让你死记一堆 LOLBAS 名字，而是训练你判断：

1. 哪些文件类型被限制。
2. 哪些路径、签名、哈希规则允许执行。
3. 当前用户能写入哪里。
4. 系统上有哪些受信任程序可以帮你加载代码。
5. PowerShell 是否被 CLM 限制。

## 黑名单和白名单的区别

| 模型 | 默认行为 | 类比 | 绕过思路 |
|---|---|---|---|
| 黑名单，常见于传统杀软 | 默认允许，命中特征才拦截 | 通缉名单 | 修改特征、加密、混淆、改变行为 |
| 白名单，常见于 AppLocker | 默认阻止，符合规则才允许 | 门禁名单 | 找到被允许的路径、签名程序或加载方式 |

简单讲：

```text
杀软问：你是不是坏东西？
AppLocker 问：你是不是被批准运行的东西？
```

所以 AppLocker 绕过不一定靠“免杀”，更多是靠“借路”：借受信任目录、受信任程序、受信任脚本宿主或默认规则。

## AppLocker 能限制什么

| 类型 | 常见扩展名 | 初学者理解 |
|---|---|---|
| 可执行文件 | `.exe`、`.com` | 普通程序 |
| Windows Installer | `.msi`、`.msp`、`.mst` | 安装包 |
| 脚本 | `.ps1`、`.bat`、`.cmd`、`.vbs`、`.js` | PowerShell、批处理、VBScript、JScript |
| 打包应用 | `.appx` 等 | UWP 应用 |
| DLL | `.dll`、`.ocx` | 可选规则，默认不一定启用 |

学习重点：DLL 规则常常没有启用，这会影响你是否可以考虑 DLL 加载路径。

## AppLocker 三种规则

### 路径规则

路径规则允许某些路径下的文件运行，例如：

```text
C:\Windows\*
C:\Program Files\*
```

优点：简单。

风险：如果允许路径里存在普通用户可写目录，就可能被绕过。

### 发布者规则

发布者规则基于数字签名，例如允许 Microsoft 签名程序。

优点：维护方便，程序更新后仍可能允许。

风险：某些被信任的程序本身具备加载脚本、编译代码、加载 DLL 或执行外部内容的能力。

### 哈希规则

哈希规则只允许某个具体文件。

优点：精确。

缺点：文件一更新哈希就变了，维护成本高。

## 默认规则为什么危险

常见默认规则大致是：

```text
允许 Everyone 执行 C:\Windows\* 下的程序
允许 Everyone 执行 C:\Program Files\* 下的程序
允许 Administrators 执行任意程序
```

这些规则的假设是：

```text
普通用户不能往 C:\Windows 或 C:\Program Files 里写文件。
```

问题是，现实中某些子目录可能允许普通用户写入。如果一个目录同时满足：

```text
在允许执行的路径下面
当前用户可写
文件写进去后能执行
```

就可能形成路径规则绕过。

## 绕过路径总览

| 路径 | 需要的前提 | 适合场景 |
|---|---|---|
| 可写可信目录 | 允许路径下存在当前用户可写目录 | `.exe` 被路径规则限制 |
| DLL 加载 | DLL 规则未启用或受信任程序可加载 DLL | 可执行文件受限但 DLL 可被加载 |
| ADS 备用数据流 | 可写入 NTFS ADS，脚本宿主允许执行 | 脚本路径检查不严或存在历史环境 |
| 第三方解释器 | Python、Java、Office 等未被规则覆盖 | AppLocker 规则只覆盖 Windows 脚本 |
| LOLBAS | 受信任程序具备执行/加载外部内容能力 | 白名单允许系统工具或微软签名程序 |
| PowerShell 绕过 | PowerShell 可运行但受策略限制 | CLM、脚本策略、执行策略限制 |

## 绕过方法一：可写可信目录

### 判断逻辑

```text
1. AppLocker 允许 C:\Windows\* 或 C:\Program Files\*
2. 当前用户能写入其中某个子目录
3. 写入后的文件可以从该路径执行
4. 于是你的文件继承了“路径被允许”的优势
```

### 查找可写目录

使用 Sysinternals 的 accesschk：

```cmd
accesschk.exe -w -s -q -u Users C:\Windows
```

或使用当前用户：

```cmd
accesschk.exe "%USERNAME%" C:\Windows -wus
```

常见候选目录：

```text
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\Tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\drivers\color
```

注意：不同 Windows 版本、补丁、域策略会影响权限，不能死记路径。

### 验证权限

```cmd
icacls C:\Windows\Tasks
```

你关注：

| 权限 | 含义 |
|---|---|
| `RX` | 读取和执行 |
| `W` / `WD` | 写入 |
| `M` | 修改 |
| `F` | 完全控制 |

### 执行思路

```cmd
copy payload.exe C:\Windows\Tasks\payload.exe
C:\Windows\Tasks\payload.exe
```

如果失败，先别换 payload，先排查：

```text
文件是否真的写进去了
当前路径是否被 AppLocker 允许
文件类型是否被规则覆盖
是否被 AV/AMSI 另一个防护拦截
执行位数是否正确
```

## 绕过方法二：DLL 加载

很多环境默认不启用 DLL 规则，因为 DLL 规则可能明显影响性能和兼容性。

如果 DLL 规则未启用，你可以思考：

```text
我不能直接运行 exe，能不能让一个受信任程序加载 DLL？
```

### rundll32 基本概念

`rundll32.exe` 是 Windows 自带程序，可以调用 DLL 中的导出函数：

```cmd
rundll32.exe C:\Path\payload.dll,ExportedFunction
```

关键点：

| 点 | 说明 |
|---|---|
| DLL 必须导出函数 | 否则 rundll32 不知道调用哪个入口 |
| 位数要匹配 | x86 / x64 不匹配会失败 |
| 可能被其他防护拦截 | AppLocker 不是唯一限制 |

### 简单 DLL 结构

```cpp
#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    return TRUE;
}

extern "C" __declspec(dllexport) void run()
{
    MessageBoxA(NULL, "Execution happened", "Bypass", MB_OK);
}
```

编译和执行时要特别注意导出函数名、架构和路径。

## 绕过方法三：备用数据流 ADS

NTFS 支持 Alternate Data Streams，格式类似：

```text
normal.txt:hidden.js
```

示例：

```cmd
echo var shell = new ActiveXObject("WScript.Shell"); shell.Run("cmd.exe"); > test.js
type test.js > "C:\Program Files\App\log.txt:test.js"
dir /r "C:\Program Files\App\log.txt"
wscript "C:\Program Files\App\log.txt:test.js"
```

学习时理解概念即可：ADS 是把数据藏在某个文件的额外数据流里。是否能执行，取决于系统版本、脚本宿主、规则和补丁情况。

## 绕过方法四：第三方解释器

AppLocker 的脚本规则常覆盖：

```text
.ps1 .bat .cmd .vbs .js
```

但不一定覆盖：

```text
Python
Java
Ruby
Perl
Office VBA
某些第三方程序的脚本功能
```

所以你要枚举系统上是否存在解释器：

```cmd
where python
where java
where perl
where msbuild
where installutil
where mshta
```

判断逻辑：

```text
不是“有 Python 就一定能绕过”
而是“AppLocker 规则有没有限制这个解释器，以及解释器本身是否允许执行我的代码”
```

## 绕过方法五：LOLBAS

LOLBAS 是 Living Off The Land Binaries And Scripts，指利用系统自带或可信程序完成攻击动作。

学习时不要把 LOLBAS 当成清单背，要按能力分类：

| 能力 | 例子 | 你要问的问题 |
|---|---|---|
| 执行脚本 | `mshta.exe`、`wscript.exe`、`cscript.exe` | 脚本规则是否允许 |
| 编译或加载 .NET | `MSBuild.exe`、`InstallUtil.exe` | 是否能执行内嵌代码 |
| 注册或加载组件 | `regsvr32.exe`、`rundll32.exe` | 能否加载远程或本地组件 |
| XSL 转换执行 | `wmic.exe` 等历史路径 | 系统版本是否仍支持 |
| 下载或代理 | `certutil.exe`、`bitsadmin.exe` | 网络和策略是否允许 |

资源入口：`https://lolbas-project.github.io/`

## PowerShell、CLM 和 AppLocker

PowerShell 可能处于 Constrained Language Mode：

```powershell
$ExecutionContext.SessionState.LanguageMode
```

常见返回：

| 模式 | 含义 |
|---|---|
| `FullLanguage` | 完整语言能力 |
| `ConstrainedLanguage` | 受限语言模式 |

CLM 会限制很多对 OSEP 很关键的能力：

```text
Add-Type
.NET 反射
COM 对象
任意类型调用
复杂脚本能力
```

所以如果 PowerShell 代码失败，不要只看报错，要先判断：

```text
是执行策略问题？
是 AppLocker 脚本规则问题？
是 CLM 限制？
是 AMSI 扫描？
是杀软拦截？
```

这几个限制经常叠在一起。

## AppLocker 枚举流程

### 1. 看策略是否存在

```powershell
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

如果没有 PowerShell 权限，可以看事件和现象：

```text
程序运行时被提示策略阻止
事件日志出现 AppLocker 拦截记录
脚本运行被禁止
PowerShell 进入 CLM
```

### 2. 看当前用户

```cmd
whoami
whoami /groups
```

管理员组通常有更宽松规则，普通用户限制更明显。

### 3. 找允许路径

重点关注：

```text
C:\Windows
C:\Program Files
C:\Program Files (x86)
软件安装目录
企业自定义工具目录
```

### 4. 找可写路径

```cmd
icacls <目录>
accesschk.exe -w -s -q -u Users <目录>
```

### 5. 找可信程序

```cmd
where msbuild
where installutil
where regsvr32
where rundll32
where mshta
where wscript
where cscript
```

### 6. 做最小验证

先用安全的最小测试验证路径，例如弹计算器或输出文本。不要一上来就把复杂 payload 塞进去，否则失败时你不知道是策略、payload、架构还是网络问题。

## 常见失败排查

| 现象 | 可能原因 | 排查 |
|---|---|---|
| 文件无法运行，提示被策略阻止 | AppLocker 可执行规则命中 | 换允许路径或受信任程序 |
| 文件复制成功但无法执行 | 路径可写但不在允许执行规则内 | 检查规则和事件日志 |
| DLL 无法加载 | DLL 规则启用、导出函数错误或架构不匹配 | 查规则、导出表、x86/x64 |
| PowerShell 报类型/方法不可用 | CLM 限制 | 检查 `LanguageMode` |
| 脚本被扫描阻断 | AMSI 或 AV | 转到 `08-AMSI绕过`、`07-杀软绕过` |
| LOLBAS 不存在 | 系统版本或组件缺失 | `where` 搜索，换路径 |
| 执行成功但无回连 | 网络出站限制 | 转到 `10-网络过滤绕过` |

## AppLocker 和其他防护的关系

```text
AppLocker：你能不能启动这个文件或脚本
CLM：PowerShell 启动后能不能使用完整语言能力
AMSI：脚本内容是否被扫描并阻止
AV/EDR：文件、内存、行为是否被检测
网络过滤：执行后能不能连出去
```

所以真实排错顺序通常是：

```text
先确认能不能执行
再确认脚本能力是否受限
再确认内容是否被扫描
再确认网络是否能出
```

## 学习检查清单

读完本文后，你应该能回答：

| 问题 | 自测 |
|---|---|
| AppLocker 和杀软有什么区别 | 能说出白名单和黑名单的区别 |
| 路径规则为什么可能被绕过 | 能说出允许路径里存在可写目录 |
| DLL 规则为什么重要 | 能说出默认可能不限制 DLL 加载 |
| CLM 和 AppLocker 是什么关系 | 能说出 AppLocker 可能触发或伴随 CLM，CLM 限制 PowerShell 能力 |
| LOLBAS 的本质是什么 | 能说出借受信任程序执行或加载代码 |
| 执行失败时怎么排查 | 能按策略、权限、架构、AMSI/AV、网络拆分 |

## 练习题

1. 如果 `payload.exe` 在桌面无法运行，你会先查 AppLocker 规则，还是先换 payload？为什么？
2. `C:\Windows\Temp` 可写是否一定能绕过 AppLocker？还需要验证什么？
3. DLL 规则未启用时，为什么 `rundll32` 仍可能失败？
4. PowerShell 返回 `ConstrainedLanguage` 时，哪些 OSEP 常用能力会受影响？
5. 为什么说 LOLBAS 是“能力分类”，不是“命令清单”？

## 关联文档

| 文档 | 作用 |
|---|---|
| `02-基础绕过技术.md` | 补充基础白名单绕过方式 |
| `03-InstallUtil绕过详解.md` | 深入 InstallUtil 这类 .NET 执行路径 |
| `04-PowerShell绕过.md` | PowerShell 和 CLM 相关绕过 |
| `05-Workflow-Compiler绕过详解.md` | 另一个受信任编译/执行路径 |
| `07-MSHTA-XSL与第三方执行.md` | MSHTA、XSL、第三方解释器等补充 |
| `08-AMSI绕过/11-AMSI-CLM联动排错.md` | AppLocker、CLM、AMSI 叠加时的排错入口 |
