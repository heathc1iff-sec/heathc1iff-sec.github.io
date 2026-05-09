---
title: OSEP-11-Linux域内横向移动考试速查
description: '11-Linux后渗透 | 10-Linux域内横向移动考试速查'
pubDate: 2026-01-30T00:02:00+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Linux Machine
  - Active Directory
  - Lateral Movement
---

# Linux 域内横向移动考试速查

## 对应课程小节

`19：linux域内横向移动（ssh后门部署+ad中的linux）.html` 覆盖 SSH Keys、SSH Persistence、ControlMaster、SSH-Agent Forwarding、Ansible、Artifactory、Linux Kerberos、Keytab、ccache、Impacket Kerberos 使用。

现有目录已经有 Ansible、Artifactory、Linux Kerberos 和 SSH/DevOps 文件，这份补充用于考试时快速串联。

---

## Linux 横向移动优先级

| 优先级 | 方向 | 为什么 |
|---|---|---|
| A | SSH 私钥和 `authorized_keys` | 最直接的横向材料 |
| A | SSH Agent / ControlMaster | 不需要知道私钥密码也可能复用会话 |
| A | Keytab / ccache | Linux 加域环境里的 Kerberos 入口 |
| B | Ansible Inventory / Playbook / Vault | DevOps 凭证和批量执行入口 |
| B | Artifactory 备份/数据库 | 常泄漏管理员凭证、API Key、仓库凭证 |
| C | 用户配置文件后门 | 维持权限或等待用户触发 |

---

## Linux 加域主机枚举顺序

拿到 Linux Shell 后，先判断它是不是 AD 生态的一部分，再决定走 SSH、Kerberos 还是 DevOps。

| 顺序 | 检查点 | 重点看什么 | 下一步 |
|---|---|---|---|
| 1 | 主机身份 | `hostname -f`、DNS 后缀、`/etc/hosts` | 判断域名和关键服务器命名 |
| 2 | 加域痕迹 | `/etc/krb5.conf`、`/etc/sssd/sssd.conf`、`realm list` | 找 realm、KDC、LDAP、允许登录的域组 |
| 3 | 票据缓存 | `klist`、`KRB5CCNAME`、`/tmp/krb5cc_*` | 复用 ccache 访问 SMB/LDAP/HTTP |
| 4 | Keytab | `/etc/krb5.keytab`、应用目录中的 `.keytab` | 用服务身份 `kinit -k`，再评估权限 |
| 5 | 用户痕迹 | `/home/*/.ssh`、shell history、sudoers、cron | 找 SSH 目标、域用户、管理脚本 |
| 6 | DevOps 配置 | Ansible inventory、Vault、Artifactory 备份 | 判断是否能批量执行或拿凭据 |

考试可用总结：Linux 加域主机的价值经常不在本机 root，而在它保存的 `ccache`、`keytab`、SSH agent、Ansible inventory 和服务配置。

---

## 拿到 Linux Shell 后 10 分钟判断链

| 时间 | 动作 | 目标 |
|---|---|---|
| 0-2 分钟 | `id`、`sudo -l`、主机名、网络、进程 | 确认身份和边界 |
| 2-4 分钟 | 查 SSH key、agent、ControlMaster socket | 找最快横向路径 |
| 4-6 分钟 | 查 `krb5.conf`、`sssd.conf`、ccache、keytab | 判断域内 Kerberos 价值 |
| 6-8 分钟 | 查 Ansible、Artifactory、备份、配置文件 | 找 DevOps 批量控制点 |
| 8-10 分钟 | 查 AV、VIM/配置后门、共享库劫持机会 | 决定维持、提权还是横向 |

---

## SSH 检查清单

| 检查项 | 价值 |
|---|---|
| `~/.ssh/id_*` | 私钥 |
| `~/.ssh/authorized_keys` | 可写则可持久化 |
| `~/.ssh/config` | Host 别名、ControlMaster、代理跳板 |
| `known_hosts` | 历史连接目标 |
| Shell 历史 | 主机名、用户名、命令习惯 |
| 运行中的 `ssh` 进程 | Agent/ControlMaster 线索 |
| `SSH_AUTH_SOCK` | Agent socket 位置 |

---

## ControlMaster 判断

ControlMaster 允许 SSH 连接复用同一个控制 socket。考试里重点是：如果你能访问同一用户的 socket，就可能复用已有连接。

判断链：

```
发现 SSH 配置启用 ControlMaster
  -> 找 ControlPath
  -> 当前用户或 root 能否访问 socket
  -> socket 是否仍然活跃
  -> 复用连接访问目标
```

常见卡点：

| 现象 | 排查 |
|---|---|
| socket 不存在 | 会话已断、ControlPath 不同 |
| 权限不足 | 是否能切到同一用户或 root |
| 复用失败 | 目标别名不一致、Host 配置不匹配 |
| 连接成功但权限低 | 复用的是普通用户会话，继续找 sudo/凭证 |

---

## SSH-Agent Forwarding 判断

SSH Agent Forwarding 的价值是：私钥不在目标上，但目标上可能有可用的 agent socket。

判断链：

```
发现 SSH_AUTH_SOCK
  -> 确认 socket 属主和权限
  -> 使用该 socket 列出可用身份
  -> 根据 known_hosts/config/history 找目标
  -> 复用 agent 横向
```

注意点：

| 点 | 说明 |
|---|---|
| 不等于拿到私钥 | 只是借用 agent 做签名 |
| 需要目标接受对应公钥 | 不是所有主机都能用 |
| root 通常能访问用户环境 | 但环境变量可能需要从进程环境中找 |
| 适合快速扩展 | 成功后立刻枚举新主机上的 SSH/Keytab/配置 |

---

## Linux Kerberos 判断

| 材料 | 用途 |
|---|---|
| `/etc/krb5.conf` | Realm、KDC、域配置 |
| Keytab | 服务或主机的长期密钥材料 |
| ccache | 已获取的 Kerberos 凭证缓存 |
| `klist` 输出 | 当前票据、过期时间、服务范围 |
| 加域配置 | SSSD、realmd、krb5、ldap 配置 |

判断链：

```
发现 keytab 或 ccache
  -> 确认对应 principal
  -> 确认票据是否有效或能否重新申请
  -> 转成工具可用格式
  -> 用 Kerberos 访问 SMB/LDAP/MSSQL/WinRM
```

---

## Ansible 与 Artifactory

| 发现 | 下一步 |
|---|---|
| Inventory | 找主机分组、用户名、连接方式 |
| Playbook | 找命令执行、文件分发、凭证引用 |
| Vault | 尝试找到 vault password 或离线破解 |
| Ansible 配置 | 找私钥路径、remote_user、become 配置 |
| Artifactory 备份 | 解包找数据库、配置、管理员账号 |
| Artifactory DB | 找用户、Hash、API Key、仓库凭证 |

---

## 和 Windows/AD 的联动

| Linux 发现 | AD 方向 |
|---|---|
| 域用户密码 | SMB/LDAP/WinRM/MSSQL 枚举 |
| Keytab | Kerberos 认证、服务账户权限 |
| ccache | Pass-the-Cache 到 Impacket |
| SSH 到 Windows 管理机 | 找 RDP/WinRM/凭证 |
| Ansible 管理 Windows | 可能有 WinRM 凭证或本地管理员 |
| Artifactory 域集成 | LDAP 绑定账号、管理员凭证 |

---

## 证据记录

| 阶段 | 证据 |
|---|---|
| 发现材料 | 文件路径、权限、属主 |
| 证明有效 | 成功认证、`klist`、SSH 登录 |
| 横向结果 | 新主机身份、权限、可访问资源 |
| AD 联动 | 使用凭证或票据访问域服务的结果 |
