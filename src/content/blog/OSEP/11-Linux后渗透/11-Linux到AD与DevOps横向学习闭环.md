---
title: OSEP-11-Linux到AD与DevOps横向学习闭环
description: '11-Linux后渗透 | 11-Linux到AD与DevOps横向学习闭环'
pubDate: 2026-01-30T00:02:01+08:00
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

# Linux 到 AD 与 DevOps 横向学习闭环

## 这篇文档解决什么问题

很多初学者拿到 Linux Shell 后会只做三件事：`id`、`sudo -l`、找 `id_rsa`。这些当然重要，但 OSEP 里的 Linux 主机经常不是孤立资产，它可能是：

- 加入 AD 的 Linux 服务器。
- Ansible 控制节点。
- Artifactory、Jenkins、Git、部署机等 DevOps 节点。
- 可以访问 Windows 管理网段的跳板机。
- 保存 Kerberos `ccache`、`keytab`、SSH Agent、Vault 密码、API Token 的中转点。

这篇文档的目标是把 Linux 后渗透从“搜文件”升级成“判断它能通向哪条横向移动链”。

只在 OSEP 授权实验环境和考试备考中使用。

---

## Linux 主机在攻击链里的位置

| Linux 资产类型 | 常见价值 | 可能通向 |
|---|---|---|
| 普通 Web 服务器 | 配置文件、数据库凭证、部署脚本 | 数据库、内网服务、管理员凭证 |
| 加域 Linux | Kerberos 配置、ccache、keytab、SSSD | SMB、LDAP、MSSQL、域枚举 |
| Ansible 控制机 | Inventory、Playbook、Vault、SSH Key | 批量执行、横向到多台主机 |
| Artifactory | 仓库凭证、LDAP 绑定账号、备份数据库 | DevOps 权限、域账号、构建链 |
| 跳板机 | SSH Agent、ControlMaster、known_hosts | 下一跳 Linux 或管理网段 |
| 构建/部署节点 | CI/CD Token、云密钥、制品签名材料 | 应用服务器、源码、凭证复用 |

考试里不要把 Linux 当成“和 AD 无关”。先判断它是否能提供身份材料、网络位置或自动化控制能力。

---

## 10 分钟正序枚举流程

### 0-2 分钟：确认自己是谁、在哪

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

判断：

| 输出 | 说明 |
|---|---|
| 域风格主机名 | 可能在 AD 命名体系中 |
| 多网卡/特殊路由 | 可能是跳板机 |
| 当前用户是部署/运维账号 | 重点找自动化配置 |
| 当前用户在 `sudo`、`docker`、`adm` 等组 | 有本地提权或读日志机会 |

### 2-4 分钟：找 SSH 横向材料

```bash
ls -la ~/.ssh
find /home -maxdepth 3 -name "id_*" -o -name "*.pem" 2>/dev/null
find /tmp -type s -name "agent.*" 2>/dev/null
env | grep -E "SSH|KRB5|ANSIBLE"
ps aux | grep -i ssh
```

重点看：

- 私钥是否存在。
- 私钥是否需要口令。
- `known_hosts` 里有哪些主机。
- `~/.ssh/config` 是否配置了跳板、ControlMaster、IdentityFile。
- `SSH_AUTH_SOCK` 是否指向可访问的 agent socket。

### 4-6 分钟：判断是否加域或使用 Kerberos

```bash
cat /etc/krb5.conf 2>/dev/null
cat /etc/sssd/sssd.conf 2>/dev/null
realm list 2>/dev/null
klist 2>/dev/null
find /tmp -maxdepth 1 -name "krb5cc_*" -ls 2>/dev/null
find / -name "*.keytab" -o -name "krb5.keytab" 2>/dev/null
```

重点看：

| 材料 | 价值 |
|---|---|
| `/etc/krb5.conf` | Realm、KDC、域名 |
| `/etc/sssd/sssd.conf` | 加域方式、允许登录的域组、缓存设置 |
| `ccache` | 已经拿到的 Kerberos 票据 |
| `keytab` | 服务或机器长期密钥，可重新申请票据 |
| `KRB5CCNAME` | 当前进程使用的票据路径 |

### 6-8 分钟：找 DevOps 控制面

```bash
find / -name "ansible.cfg" -o -name "inventory" -o -name "hosts" 2>/dev/null | head -50
find / -name "*.yml" -o -name "*.yaml" 2>/dev/null | grep -Ei "ansible|playbook|deploy|inventory" | head -50
find / -iname "*vault*" 2>/dev/null | head -50
find /opt /var /home -maxdepth 4 -iname "*artifactory*" 2>/dev/null
```

DevOps 节点里常见的“下一步材料”：

| 材料 | 下一步 |
|---|---|
| Inventory | 找主机分组、用户名、连接方式 |
| Playbook | 找命令执行、文件分发、凭证引用 |
| Vault 密码文件 | 解密敏感变量 |
| 私钥路径 | SSH 横向 |
| Artifactory 配置 | 找数据库、LDAP、管理员凭证 |
| 构建脚本 | 找发布目标、token、环境变量 |

### 8-10 分钟：决定路线

| 发现 | 优先路线 |
|---|---|
| 有 SSH 私钥 | 先验证 SSH 横向 |
| 有 `SSH_AUTH_SOCK` | 先复用 agent |
| 有 ControlMaster socket | 先复用现有连接 |
| 有 ccache | 尝试 Kerberos 访问域服务 |
| 有 keytab | `kinit -k` 后评估 principal 权限 |
| 有 Ansible | 看能否批量执行或拿凭证 |
| 有 Artifactory | 查备份、数据库、LDAP 绑定账号 |
| 只有本地弱权限 | 回到 Linux 本地提权、配置文件、共享库劫持 |

---

## SSH 横向移动闭环

### 概念说明

SSH 横向移动依赖三类材料：

1. 私钥文件：例如 `id_rsa`、`.pem`。
2. Agent socket：私钥不在目标上，但可借 agent 签名。
3. ControlMaster socket：已有 SSH 连接的复用通道。

### 使用场景

- Web 服务器上有部署账号私钥。
- 运维人员通过跳板机开启了 SSH Agent Forwarding。
- `~/.ssh/config` 中启用了 ControlMaster。
- `known_hosts` 暴露了下一跳主机。

### 常用命令

```bash
# 查看 SSH 配置和历史目标
cat ~/.ssh/config 2>/dev/null
cat ~/.ssh/known_hosts 2>/dev/null
history | grep -i ssh

# 私钥权限修正后测试
chmod 600 id_rsa
ssh -i id_rsa user@target

# 查看 agent 可用身份
ssh-add -l

# 指定 agent socket
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNN ssh-add -l
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNN ssh user@target
```

### 注意事项

| 点 | 说明 |
|---|---|
| 私钥权限太宽会被拒绝 | `chmod 600` |
| `known_hosts` 只是历史，不代表当前可登录 | 需要验证 |
| Agent 不是私钥文件 | 它只能帮你签名，不能直接导出私钥 |
| ControlMaster 依赖 socket 活跃 | 断开的会话无法复用 |
| 横向成功后立即再枚举 | 新主机可能有新的 Keytab、Ansible、凭证 |

### 排错思路

| 现象 | 排查 |
|---|---|
| `Permission denied (publickey)` | 用户名错、公钥未授权、私钥不匹配 |
| `Bad permissions` | 私钥权限太宽 |
| Agent 有 key 但不能登录 | 目标未信任该公钥 |
| ControlMaster socket 不存在 | 会话已断或路径不同 |
| 登录后权限很低 | 查 sudo、组、配置文件、横向下一跳 |

### OSEP 重点

SSH 横向的价值不只是“登录另一台 Linux”。它可能把你带到管理网段、Ansible 控制机、Artifactory 主机或加域 Linux 节点。每次 SSH 成功都要重新走 10 分钟枚举流程。

---

## Linux Kerberos 闭环

### 概念说明

Linux 也可以使用 Kerberos 访问 AD 资源。常见材料：

| 材料 | 人话解释 |
|---|---|
| `krb5.conf` | 告诉 Linux 你的 Realm/KDC 在哪里 |
| `ccache` | 已经获得的票据缓存 |
| `keytab` | 保存某个 principal 的长期密钥 |
| `principal` | Kerberos 身份，例如 `user@REALM` 或 `host/server@REALM` |

### 使用场景

- Linux 加入 AD，使用 SSSD/realmd。
- Web 服务或自动化任务使用域服务账户。
- 目标上存在 `/tmp/krb5cc_*`。
- 应用目录里有 `.keytab`。

### 常用命令

```bash
# 查看当前票据
klist

# 指定 ccache
export KRB5CCNAME=/tmp/krb5cc_1000
klist

# 使用 keytab 申请票据
kinit -k -t /path/to/file.keytab principal@REALM
klist

# 查看 realm 与 KDC
cat /etc/krb5.conf
realm list 2>/dev/null
```

Impacket 使用 Kerberos 时常见环境变量：

```bash
export KRB5CCNAME=/path/to/cache.ccache
```

然后在支持 Kerberos 的工具里使用 `-k` 或对应参数。

### 注意事项

1. ccache 有过期时间，先看 `klist`。
2. keytab 对应的是某个 principal，不一定是高权限。
3. Linux 和 Windows 时间偏差会导致 Kerberos 失败。
4. DNS/Realm 大小写、KDC 名称会影响工具使用。
5. 机器账户或服务账户也可能有对象权限、SPN 或委派价值。

### 排错思路

| 现象 | 排查 |
|---|---|
| `klist` 没票据 | ccache 路径错或票据不存在 |
| `kinit -k` 失败 | principal 不匹配、keytab 不含该身份、时间偏差 |
| 工具不认票据 | `KRB5CCNAME` 路径错、格式不兼容 |
| Kerberos 认证失败 | DNS、Realm、KDC、SPN、时间 |
| 票据有效但权限不足 | principal 本身权限低，继续枚举 ACL/组/SPN |

### OSEP 重点

Linux Kerberos 的核心是“把 Linux 上的票据或 keytab 转成 AD 访问能力”。不要只截图 `klist`，还要验证它能访问什么，例如 SMB、LDAP、MSSQL 或 HTTP 服务。

---

## Ansible 横向闭环

### 概念说明

Ansible 是自动化运维工具，通常通过 SSH 批量管理机器。它的高价值信息集中在：

- Inventory：管哪些主机。
- Playbook：执行什么动作。
- Variables：使用什么账户、密码、路径。
- Vault：加密敏感变量。
- SSH Key：连接目标的身份材料。

### 使用场景

- 当前主机是部署机或控制机。
- 用户家目录里有 `ansible.cfg`。
- `/etc/ansible/hosts` 存在大量主机。
- Playbook 中有 `become: yes`、`remote_user`、`ansible_password`。
- Vault 密码文件可读。

### 常用命令

```bash
# 找配置
find / -name "ansible.cfg" 2>/dev/null
find / -path "*ansible*" -type f 2>/dev/null | head -100

# 查看默认 inventory
cat /etc/ansible/hosts 2>/dev/null

# 查看配置
ansible --version 2>/dev/null
ansible-inventory --list -y 2>/dev/null

# 如果有 Vault 密码
ansible-vault view secrets.yml --vault-password-file .vault_pass
```

如果已经确认是授权实验环境并且当前身份本来有执行权限，可以用小命令验证控制能力：

```bash
ansible all -m ping
ansible target_group -m command -a "id"
```

### 注意事项

| 点 | 说明 |
|---|---|
| Inventory 可能含 Windows 主机 | 查 WinRM 变量和域账号 |
| Vault 密码可能在脚本或环境变量中 | 查 history、cron、service 文件 |
| `become` 不等于已经能 root | 可能需要 sudo 密码 |
| 批量执行风险大 | 考试里先验证单台、保留证据 |

### 排错思路

| 现象 | 排查 |
|---|---|
| `ansible` 命令不存在 | 查项目虚拟环境、脚本、配置文件 |
| inventory 为空 | 查 `ansible.cfg` 指定路径 |
| ping 失败 | SSH key、用户、网络、host key |
| Vault 解不开 | 密码文件错、Vault ID 不匹配 |
| 命令执行失败 | become 权限、目标 Python、连接方式 |

### OSEP 重点

Ansible 的价值在“批量控制”和“凭证聚合”。拿到 Ansible 配置后，不要只看一个主机，优先画出主机组、用户名、私钥、Vault、Windows/AD 联动关系。

---

## Artifactory 与制品库闭环

### 概念说明

Artifactory 是制品仓库，可能保存构建产物、依赖包、API Key、LDAP 配置、管理员账号、数据库备份。

### 使用场景

- 主机路径中出现 `artifactory`。
- Web 端口开放制品库。
- 配置文件里有数据库连接。
- 备份目录可读。
- LDAP/AD 集成配置可读。

### 常用检查位置

```bash
find /opt /var /etc /home -maxdepth 5 -iname "*artifactory*" 2>/dev/null
find / -iname "system.yaml" -o -iname "db.properties" -o -iname "binarystore.xml" 2>/dev/null
```

常见敏感点：

| 文件/位置 | 可能内容 |
|---|---|
| `system.yaml` | 数据库、LDAP、服务配置 |
| 备份目录 | 数据库、用户、token |
| 环境变量 | 管理员密码、数据库密码 |
| 日志 | 登录用户、内部主机、错误中的路径 |

### 注意事项

Artifactory 的数据结构和版本差异较大。初学者不要急着套命令，先确认：

1. 版本。
2. 数据库类型。
3. 配置路径。
4. 是否启用 LDAP/AD。
5. 是否有可读备份。

### 排错思路

| 现象 | 排查 |
|---|---|
| 找不到配置 | 可能是容器部署，查 Docker volume |
| 数据库连不上 | 凭证过期、网络限制、服务只监听本地 |
| Hash 不能直接用 | 判断算法和是否需要离线破解 |
| API Key 无效 | 版本变更、权限低、Token 过期 |

### OSEP 重点

Artifactory 通常是“凭证中转站”。重点是把发现的账号、API Key、LDAP 绑定用户、数据库凭证放入 `13-Windows凭证/06-Windows凭证新手闭环与材料去向.md` 的分类里，判断下一步能否进入 AD、MSSQL、SSH 或 Web 管理入口。

---

## 凭证材料去向表

| 你拿到的材料 | 先验证什么 | 可能下一步 |
|---|---|---|
| SSH 私钥 | 能否登录 known_hosts 中的主机 | 横向到 DevOps/跳板机 |
| SSH Agent | `ssh-add -l` 是否有身份 | 复用 agent 横向 |
| ControlMaster socket | socket 是否活跃 | 复用已有连接 |
| ccache | `klist` 是否有效 | Kerberos 访问 SMB/LDAP/MSSQL |
| keytab | principal 是谁 | `kinit -k` 后查权限 |
| sudo 密码 | `sudo -l` | 本地提权、读 keytab/配置 |
| Ansible Vault | 能否解密变量 | 批量 SSH/WinRM |
| Artifactory DB 凭证 | 能否读用户/token | DevOps 到 AD |
| LDAP 绑定账号 | 能否域枚举 | ACL、ADCS、委派路径 |
| 数据库连接串 | 能否访问 DB | 账号复用、MSSQL 横向 |

---

## Linux 到 Windows/AD 的联动

| Linux 发现 | 对应知识库 |
|---|---|
| 域用户密码或 LDAP 绑定账号 | `16-AD权限滥用`、`21-ADCS证书攻击` |
| Kerberos ccache/keytab | `17-Kerberos委派`、`13-Windows凭证/06-Windows凭证新手闭环与材料去向.md` |
| MSSQL 连接串 | `15-MSSQL攻击` |
| WinRM/Windows Ansible 变量 | `14-横向移动` |
| 代理或出网限制 | `10-网络过滤绕过` |
| AV/EDR 拦截 Linux payload | `11-Linux后渗透/03-Linux杀软绕过.md` |

---

## 初学者排错总表

| 问题 | 不要急着做什么 | 应该先查什么 |
|---|---|---|
| SSH 登录失败 | 不要立刻换 payload | 用户名、公钥授权、私钥权限、目标端口 |
| Agent 不能用 | 不要以为私钥无效 | `SSH_AUTH_SOCK`、socket 权限、目标是否接受该 key |
| ccache 不工作 | 不要删除票据 | `KRB5CCNAME`、过期时间、Realm、时间同步 |
| keytab 没权限 | 不要假设它无价值 | principal、SPN、组、对象权限 |
| Ansible 执行失败 | 不要直接全网重试 | inventory、SSH key、become、目标 Python |
| Artifactory 没找到密码 | 不要只 grep password | 查数据库、备份、system.yaml、环境变量 |
| Linux root 后没有方向 | 不要停在本机 | 查网络位置、DevOps、AD 配置、SSH 历史 |

---

## OSEP 考试相关重点

1. Linux 后渗透的考试价值常来自“凭证和网络位置”，不是本机本身。
2. SSH、Kerberos、Ansible、Artifactory 要放在一张图里看。
3. 每拿到一种材料，都要问它能否登录、能否认证、能否中继、能否横向、能否域枚举。
4. Linux 到 AD 的桥梁通常是 `ccache`、`keytab`、LDAP 绑定账号、MSSQL/WinRM 凭证。
5. 报告里要保留材料路径、权限、验证命令、访问结果，避免只写“发现了 key”。

---

## 自检清单

- [ ] 我拿到 Linux Shell 后能在 10 分钟内判断 SSH、Kerberos、DevOps 三条路线。
- [ ] 我知道 `ccache` 和 `keytab` 的区别。
- [ ] 我知道 `SSH_AUTH_SOCK` 和私钥文件不是一回事。
- [ ] 我能从 Ansible Inventory 判断主机组、用户和连接方式。
- [ ] 我能解释 Artifactory 为什么可能通向 AD。
- [ ] 我能把每种凭证材料写入“去向总表”，而不是孤立保存。
