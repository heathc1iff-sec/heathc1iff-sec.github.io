---
title: OSEP-11-Ansible利用
description: '11-Linux后渗透 | 05-Ansible利用'
pubDate: 2026-01-30T00:01:55+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Linux Machine
---

# Ansible 利用完整指南

本文件合并了原来的 Ansible 利用和 Ansible 利用详细指南内容。旧详细指南已归档到 `_archive\2026-05-07-深度优化`。

## 这篇文档解决什么问题

Ansible 是自动化运维工具。它的价值不在于“这台机器装了一个命令”，而在于：

```text
控制节点可以通过 SSH 批量管理很多服务器。
如果你控制了控制节点或它的凭证，就可能影响一批主机。
```

所以 Ansible 是 Linux 后渗透里从单机进入横向移动的重要跳板。

## Ansible 架构

```text
控制节点
├─ ansible 命令
├─ inventory 主机清单
├─ ansible.cfg 配置
├─ playbook 自动化任务
├─ vault 加密变量
└─ SSH key / 凭证
      │
      └── SSH 管理多台被控节点
```

## 你要先判断目标是不是控制节点

```bash
which ansible
ansible --version
ls -la /etc/ansible
cat /etc/ansible/hosts 2>/dev/null
cat /etc/ansible/ansible.cfg 2>/dev/null
find /home /opt /etc -name "ansible.cfg" -o -name "*.yml" -o -name "*.yaml" 2>/dev/null | head -100
```

危险信号：

```text
存在 ansible 命令
存在 /etc/ansible/hosts
存在 ansibleadm 之类用户
存在 playbook 目录
存在 vault 文件或 vault password 文件
存在大量 SSH 私钥
```

## Inventory 主机清单

Inventory 告诉你 Ansible 管哪些主机。

示例：

```ini
[webservers]
web01
web02

[databases]
db01 ansible_user=dbadmin ansible_host=192.168.1.100
```

你要提取：

| 字段 | 价值 |
|---|---|
| 主机名 / IP | 横向目标 |
| 分组 | 资产角色 |
| `ansible_user` | 登录用户 |
| `ansible_host` | 真实连接地址 |
| `ansible_ssh_private_key_file` | 私钥路径 |
| `ansible_become_pass` | 提权密码 |

## ansible.cfg

配置文件可能告诉你：

```text
默认 inventory 路径
remote_user
private_key_file
vault_password_file
roles_path
log_path
host_key_checking
```

命令：

```bash
ansible-config dump
cat ansible.cfg
```

## Ad-hoc 命令

Ad-hoc 是临时命令模式。

```bash
ansible <目标组> -a "<命令>"
```

示例：

```bash
ansible all -a "whoami"
ansible webservers -a "id"
ansible databases -a "hostname"
```

如果支持提权：

```bash
ansible all -a "whoami" --become
ansible all -a "cat /etc/shadow" --become
```

判断重点：

```text
当前用户能否运行 ansible
能否连接目标
连接到目标时是什么用户
是否可以 --become 到 root
```

## Playbook

Playbook 是 YAML 自动化任务。

最小结构：

```yaml
---
- name: demo
  hosts: webservers
  become: yes
  tasks:
    - name: run id
      shell: id
```

运行：

```bash
ansible-playbook demo.yml
```

### 从 Playbook 找敏感信息

```bash
grep -RniE "password|passwd|secret|token|become|private_key|vault|mysql|postgres" . 2>/dev/null
```

重点看：

```text
vars
group_vars
host_vars
roles/*/defaults
roles/*/vars
任务里的 shell 命令
模板文件
```

## Ansible Vault

Vault 用来加密敏感变量。

识别：

```bash
head -1 secrets.yml
# $ANSIBLE_VAULT;1.1;AES256
```

找 vault 密码文件：

```bash
find / -iname "*vault*" 2>/dev/null | head -100
find / -name ".vault_pass*" -o -name "vault_password*" 2>/dev/null
```

如果有密码文件：

```bash
ansible-vault view secrets.yml --vault-password-file .vault_pass
```

如果需要破解：

```bash
python3 /usr/share/john/ansible2john.py secrets.yml > vault.hash
john --wordlist=/usr/share/wordlists/rockyou.txt vault.hash
```

或 hashcat 模式：

```bash
hashcat -m 16900 vault.hash /usr/share/wordlists/rockyou.txt
```

## SSH Key 与 Ansible

Ansible 通常依赖 SSH。

```bash
ls -la ~/.ssh
find /home -maxdepth 3 -name "id_*" -o -name "*.pem" 2>/dev/null
grep -Rni "private_key_file" /etc/ansible /home /opt 2>/dev/null
```

你要把 inventory 和 key 对上：

```text
哪个 key
哪个 user
连到哪个 host
是否能 become
```

## 日志中的泄露

Ansible 命令可能把敏感参数写进日志。

```bash
grep -i ansible /var/log/syslog 2>/dev/null
grep -RiE "password|passwd|token|secret" /var/log 2>/dev/null | head -100
```

常见泄露：

```text
数据库命令里的密码
playbook 执行参数
远程 shell 命令
错误输出里的 token
```

## 攻击链思路

不要把 Ansible 当“命令执行工具”就结束了。你要形成链路：

```text
发现 Ansible -> 读 inventory -> 找目标分组 -> 找连接身份 -> 找 key/vault -> 验证 ad-hoc -> 判断 become -> 横向到被管理节点 -> 重新枚举
```

## 排错表

| 现象 | 可能原因 | 排查 |
|---|---|---|
| `ansible` 不存在 | 不是控制节点 | 查 playbook、ssh key、历史命令 |
| inventory 为空 | 使用自定义路径 | 查 `ansible.cfg`、命令历史 |
| 主机 unreachable | DNS、网络、SSH key、用户名问题 | `ssh -v`、inventory 参数 |
| permission denied | key 不匹配或用户错 | 查 `ansible_user`、key 文件 |
| `--become` 失败 | 无 sudo 或需要密码 | 查 `become_pass`、sudoers |
| vault 不能解 | 缺密码文件或密码错误 | 找 vault 文件、历史命令、配置 |

## 学习检查清单

| 问题 | 自测 |
|---|---|
| Ansible 控制节点为什么危险 | 能批量管理很多主机 |
| Inventory 里最重要的信息是什么 | 主机、用户、key、分组 |
| Ad-hoc 和 Playbook 区别是什么 | 临时命令 vs 自动化任务 |
| Vault 是什么 | 加密敏感变量 |
| 控制节点拿下后下一步是什么 | 验证横向能力并重新枚举 |
