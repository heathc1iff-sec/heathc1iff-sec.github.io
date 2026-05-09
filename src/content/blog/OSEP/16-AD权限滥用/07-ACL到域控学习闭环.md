---
title: OSEP-16-ACL到域控学习闭环
description: '16-AD权限滥用 | 07-ACL到域控学习闭环'
pubDate: 2026-01-30T00:02:38+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Active Directory
---

# ACL 到域控学习闭环

## ACL 攻击的本质

AD 里的对象都有权限控制。ACL 攻击不是“看到 BloodHound 边就点命令”，而是理解：

```
我是谁
  -> 我对哪个对象有什么权限
  -> 这个权限能转成什么动作
  -> 这个动作能不能继续扩大权限
```

---

## 初学者先分清对象

| 对象 | 攻击价值 |
|---|---|
| 用户对象 | 改密码、写 SPN、Shadow Credentials |
| 组对象 | 添加成员，获得组权限 |
| 计算机对象 | RBCD、Shadow Credentials、委派 |
| OU | 影响下级对象，可能联动 GPO |
| GPO | 影响多台主机配置 |
| 域对象 | DCSync、域级权限 |

---

## 权限翻译成人话

| 权限 | 人话解释 | 常见动作 |
|---|---|---|
| GenericAll | 几乎全控 | 改密码、加组、写属性 |
| GenericWrite | 可写部分属性 | 写 SPN、Shadow Credentials |
| WriteDACL | 可改权限 | 给自己加更高权限 |
| WriteOwner | 可改 owner | 变 owner 后改 DACL |
| AllExtendedRights | 扩展权限 | ForceChangePassword、DCSync 相关 |
| ForceChangePassword | 强制改密码 | 重置目标用户密码 |
| AddMember | 可加组成员 | 把自己加进高权限组 |
| WriteProperty | 写指定属性 | 取决于能写哪个属性 |

---

## 枚举结果怎么读

| 问题 | 解释 |
|---|---|
| 当前主体是谁 | 是你当前用户、组、机器账户还是 token |
| 目标对象是谁 | 用户、组、机器、OU、域 |
| 权限是什么 | 能不能变成实际动作 |
| 动作后得到什么 | 凭证、组权限、机器控制、DCSync |
| 是否需要等待 | 组成员、票据刷新、复制延迟 |

---

## 攻击决策树

| 能力 | 下一步 |
|---|---|
| 能改用户密码 | 改密码后登录或请求票据 |
| 能改组成员 | 加入高权限组，刷新票据 |
| 能改机器对象 | RBCD 或 Shadow Credentials |
| 能改 DACL | 给自己加 GenericAll/DCSync |
| 能写 SPN | Kerberoasting 或后续链 |
| 能改 GPO | 推送脚本或权限配置 |
| 能 DCSync | 导出域凭证 |

---

## 常见失败与排错

| 现象 | 排查 |
|---|---|
| BloodHound 有边但命令失败 | 当前 token/组是否刷新，权限是否继承 |
| 加组后没权限 | 需要重新登录或刷新 Kerberos 票据 |
| 写 DACL 失败 | 缺 WriteDACL/WriteOwner，目标错误 |
| RBCD 不成功 | SPN、机器账户、时间同步、票据服务名 |
| DCSync 失败 | 权限不完整、目标 DC、网络/防火墙 |

---

## OSEP 重点

1. 能把 BloodHound 边翻译成“我能做什么动作”。
2. 能解释 GenericAll、WriteDACL、WriteOwner 的差别。
3. 能处理“加组后为什么还没生效”。
4. 能把 ACL 攻击和 RBCD、Shadow Credentials、DCSync 串起来。
