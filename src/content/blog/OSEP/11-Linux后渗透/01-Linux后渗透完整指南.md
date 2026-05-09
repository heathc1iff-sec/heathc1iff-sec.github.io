---
title: OSEP-11-Linux后渗透完整指南
description: '11-Linux后渗透 | 01-Linux后渗透完整指南'
pubDate: 2026-01-30T00:01:51+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Linux Machine
---

# Linux 后渗透完整指南

本章是 `11-Linux后渗透` 的主入口。原来散落在配置文件利用、Linux 杀软绕过、共享库劫持、Ansible、Artifactory、Kerberos、SSH 横向移动等多篇文章里的内容，已经在这里重新组织成一条适合初学者的学习主线。

## 这章要解决什么问题

Linux 主机在 OSEP 里不是“顺便看一眼”的背景板。它经常是：

```text
Web 服务器
CI/CD 节点
Ansible 控制机
Artifactory 仓库
跳板机
加域 Linux 主机
```

你拿到 Linux shell 后，真正要问的不是“我能不能 `id`”，而是：

```text
这台 Linux 能给我什么身份材料？
它能连到哪些内网系统？
它保存了哪些自动化、配置或缓存凭证？
它是否能作为横向移动和域内扩展的跳板？
```

## Linux 后渗透的四个核心方向

| 方向 | 你在找什么 | 典型收益 |
|---|---|---|
| 配置文件利用 | dotfiles、历史命令、应用配置、SSH 配置 | 明文密码、SSH 密钥、脚本、API Token |
| 权限维持与提权 | `.bashrc`、`.vimrc`、`sudo vim`、`authorized_keys` | 重新进入、root 级执行 |
| 安全机制绕过 | Linux 杀软、签名检测、共享库劫持 | 让载荷更容易落地或运行 |
| 横向与控制面 | SSH、Kerberos、Ansible、Artifactory、DevOps 工具 | 批量执行、跨主机移动、拿到更多凭证 |

## 先学会枚举

拿到 Linux shell 的前 10 分钟，优先做这些事：

```bash
id
whoami
hostname -f
uname -a
pwd
ip addr
ip route
ss -tunlp 2>/dev/null
```

然后按下面顺序找材料：

1. SSH 材料。
2. Kerberos 材料。
3. DevOps 材料。
4. 配置文件和历史记录。
5. 本地提权和持久化路径。

## 1. 配置文件利用

配置文件是 Linux 后渗透最容易上手的入口，因为很多系统会把敏感内容直接写在明文文件里。

### 你要找什么

| 材料 | 位置 | 价值 |
|---|---|---|
| `.bashrc` / `.bash_profile` | 用户主目录 | 登录时执行命令，适合持久化 |
| `.vimrc` / `.vim/plugin/` | 用户主目录 | VIM 自动加载，适合后门和提权 |
| `.ssh/config` | 用户主目录 | 可能暴露跳板、代理、密钥和 Host 配置 |
| `.ssh/authorized_keys` | 用户主目录 | 可以直接写入公钥实现持久化 |
| `.bash_history` | 用户主目录 | 暴露历史命令、地址、用户名、密码 |
| 应用配置文件 | `/opt`、`/var`、`/etc`、项目目录 | 数据库密码、API Token、服务凭据 |

### 最常见的三条线

#### `.bashrc`

适合做“用户每次打开 shell 都执行”的动作。

```bash
echo 'touch /tmp/backdoor.txt' >> ~/.bashrc
```

如果要做持久访问，可以考虑在实验环境里记录一个反向连接或脚本拉取逻辑。

#### `.vimrc`

VIM 在管理员环境里很常见，尤其是 `sudo vim`。

```vim
:silent !touch /tmp/vimbackdoor.txt
```

你真正要理解的是：

```text
用户打开 VIM -> 读取配置 -> 自动执行命令
```

如果管理员用 `sudo vim`，后果会更大。

#### SSH 配置

```bash
cat ~/.ssh/config
cat ~/.ssh/known_hosts
cat ~/.ssh/authorized_keys
```

这里常常能找到：

```text
下一跳主机
跳板配置
IdentityFile
Agent 转发痕迹
历史登录目标
```

### 这一节的判断标准

你看完配置文件利用后，应该能回答：

| 问题 | 你要能说出来 |
|---|---|
| 什么配置会在登录时自动运行 | `.bash_profile`、`.bashrc`、`.vimrc` 等 |
| 为什么 `sudo vim` 可能危险 | root 级编辑器会读取配置并执行命令 |
| SSH 横向最常见的材料是什么 | 私钥、agent、authorized_keys、config、known_hosts |

## 2. Linux 杀软绕过

Linux 杀软比 Windows 少见，但在服务器上更值得重视。它一旦拦截，往往说明你面对的是更有价值的资产。

### 你要理解的几个点

| 概念 | 解释 |
|---|---|
| EICAR | 标准测试文件，用来确认杀软是否检测正常 |
| 签名检测 | 通过特征匹配发现已知载荷 |
| 编码 / 混淆 | 改变静态特征，避开简单规则 |
| shellcode 包装器 | 把 shellcode 嵌进 C 程序后再编译 |

### 学习顺序

1. 先看基础检测。
2. 再看编码器测试。
3. 再看 shellcode 包装器。
4. 最后理解运行时解码和静态检测的区别。

### 你要记住

```text
杀软绕过不是“永远不被发现”
而是“在当前检测规则下，换一种更容易通过的表达方式”
```

## 3. 共享库劫持

共享库是 Linux 版的 DLL。程序启动时会按一定顺序找库，顺序理解错了就看不懂劫持。

### 核心搜索顺序

```text
RPATH
LD_LIBRARY_PATH
RUNPATH
/etc/ld.so.conf
系统目录
```

### 两种最重要的思路

| 思路 | 解释 |
|---|---|
| `LD_PRELOAD` | 在目标程序启动前预加载你的库 |
| 库名劫持 | 在优先搜索路径放入同名恶意库 |

### 初学者要想清楚

```text
程序为什么会加载我的库？
我放库的位置是不是它先找的地方？
目标程序是否真的会用到这个库？
```

### 常见前提

- 你能控制环境变量。
- 你能影响程序启动方式。
- 程序不是静态编译。
- 库搜索路径是可利用的。

## 4. Ansible 利用

Ansible 是 Linux 后渗透里最值得认真学的一章之一。它不是单台机器的工具，而是批量管理控制面。

### 为什么它危险

如果你拿到 Ansible 控制节点或配置目录，往往意味着：

```text
你不是在拿一台机器，而是在拿一批机器的执行权。
```

### 你要找什么

| 材料 | 价值 |
|---|---|
| `/etc/ansible/hosts` | 主机清单 |
| `ansible.cfg` | 控制配置、路径和行为 |
| Playbook | 自动化执行逻辑 |
| Vault | 加密敏感配置 |
| SSH Key | 批量登录材料 |

### Ad-hoc 和 Playbook 的区别

| 方式 | 特点 |
|---|---|
| Ad-hoc | 临时命令，方便快速验证 |
| Playbook | YAML 自动化脚本，适合复杂流程 |

### 你需要形成的判断

```text
这台机器是普通目标，还是 Ansible 控制节点？
它有没有 inventory、playbook、vault、ssh key？
它是否能批量影响其他主机？
```

## 5. Artifactory 利用

Artifactory 常出现在 DevOps 管道中，里面可能有构建产物、备份、数据库和用户信息。

### 为什么要学

它经常比你想的更有价值，因为里面可能不只是二进制包，而是：

```text
仓库配置
备份文件
用户数据库
LDAP 绑定信息
管理员账号
CI/CD 产物
```

### 枚举重点

| 检查项 | 你在找什么 |
|---|---|
| 端口 | 是否暴露 8081 / 8082 |
| API | 是否允许匿名访问 |
| 备份 | 是否能拿到 access / 配置备份 |
| 数据库 | 是否有明文或 bcrypt 哈希 |

### 初学者视角

Artifactory 不只是“仓库网站”，它可能是：

```text
一个泄露凭证的入口
一个批量部署链上的控制面
一个把你带进更深内网的跳板
```

## 6. Linux Kerberos

Linux 一旦加入域，Kerberos 就会变成非常重要的凭证链。

### 关键材料

| 材料 | 人话解释 |
|---|---|
| `krb5.conf` | 说明 Realm 和 KDC 在哪里 |
| `ccache` | 已经拿到的票据缓存 |
| `keytab` | 长期密钥文件 |
| `principal` | Kerberos 身份名 |

### 你要学会的检查

```bash
klist
realm list
cat /etc/krb5.conf
find / -name "*.keytab" 2>/dev/null
find /tmp -name "krb5cc_*" 2>/dev/null
```

### 重要判断

```text
有票据不等于有高权限
keytab 不一定能拿到管理员权限
时间偏差、DNS、Realm 配置都会让 Kerberos 失败
```

## 7. Linux 横向移动

Linux 横向移动主要围绕 SSH、Agent、ControlMaster、Keytab、ccache、Ansible、Artifactory。

### 你要形成的路线感

```text
我是不是能直接 SSH？
我能不能复用 Agent？
我能不能用现有 socket？
我有没有 Kerberos 票据？
我是不是已经站在控制面上了？
```

### 常见横向材料

| 材料 | 作用 |
|---|---|
| 私钥 | 直接登录 |
| Agent | 代签名 |
| ControlMaster socket | 复用现有连接 |
| `known_hosts` | 暴露历史和目标 |
| `ccache` / `keytab` | 加域资源访问 |
| Ansible / Artifactory | 批量控制面 |

## 8. 学习顺序建议

如果你想按最顺的路线读，建议这样：

1. 配置文件利用。
2. Linux 杀软绕过。
3. 共享库劫持。
4. Ansible 利用。
5. Artifactory 利用。
6. Linux Kerberos。
7. SSH 横向移动。
8. 看 `11-Linux到AD与DevOps横向学习闭环.md` 做总复盘。

## 9. 你应该掌握的排错思路

| 现象 | 先查什么 |
|---|---|
| 配置文件改了没反应 | 触发时机、文件路径、权限 |
| 杀软样本被拦 | 特征、编码器、架构、运行方式 |
| 共享库没被加载 | 搜索路径、库名、程序是否真正依赖 |
| Ansible 命令不执行 | inventory、权限、become、主机组 |
| Artifactory 找不到数据 | 备份路径、API 权限、版本差异 |
| Kerberos 失败 | 时间、Realm、KDC、票据路径 |
| SSH 登录失败 | 私钥权限、用户名、授权、公钥匹配 |

## 10. 学完后你该能说什么

学完本章，你应该能把一个 Linux 主机从“普通 shell”看成这样：

```text
它可能是一个配置泄露点
它可能是一个持久化点
它可能是一个控制面
它可能是一个横向跳板
它可能保存了通向 AD 的票据
```

这才是 Linux 后渗透在 OSEP 里的真正价值。
