---
title: OSEP-12-Kiosk突破技术
description: '12-Kiosk突破 | 01-Kiosk突破技术'
pubDate: 2026-01-30T00:02:03+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
---

# Module 12: Kiosk 突破

## 第一节：Kiosk 环境概述

### 什么是 Kiosk？

Kiosk（信息亭/自助终端）是一种限制用户只能访问特定应用程序的计算机配置，常见于公共场所如机场、酒店、图书馆等。

---

## 一、Kiosk 基础

### 1.1 Kiosk 类型

```
常见 Kiosk 类型:
├── 浏览器 Kiosk (只能访问特定网站)
├── 应用程序 Kiosk (只能运行特定应用)
├── 信息查询终端 (只读信息展示)
├── 自助服务终端 (银行、票务等)
└── 数字标牌 (广告展示)
```

### 1.2 常见限制

| 限制类型 | 描述 |
|----------|------|
| Shell 限制 | 无法访问命令行 |
| 文件系统限制 | 无法浏览文件 |
| 应用程序限制 | 只能运行指定程序 |
| 网络限制 | 只能访问特定网站 |
| 外设限制 | 禁用 USB、打印等 |

### 1.3 Kiosk 实现方式

```
Windows Kiosk 实现:
├── Assigned Access (Windows 10/11)
├── Shell Launcher
├── AppLocker
├── 组策略限制
└── 第三方 Kiosk 软件

Linux Kiosk 实现:
├── 自定义 Shell
├── X11 限制
├── 浏览器全屏模式
└── 权限限制
```

---

## 二、浏览器 Kiosk 突破

### 2.1 常见突破点

```
浏览器突破向量:
├── 文件对话框
├── 打印对话框
├── 帮助菜单
├── 右键菜单
├── 键盘快捷键
├── 地址栏
└── 开发者工具
```

### 2.2 文件对话框利用

```
步骤:
1. 触发文件上传/下载对话框
2. 在地址栏输入路径
3. 导航到系统目录
4. 右键 -> 打开方式
5. 选择 cmd.exe 或 powershell.exe
```

### 2.3 打印对话框利用

```
步骤:
1. Ctrl+P 打开打印对话框
2. 选择 "打印到文件" 或 "Microsoft Print to PDF"
3. 在文件名中输入: C:\Windows\System32\cmd.exe
4. 或者浏览到系统目录
5. 利用文件浏览器访问系统
```

### 2.4 键盘快捷键

| 快捷键 | 功能 |
|--------|------|
| F1 | 帮助 (可能打开 CHM 文件) |
| F11 | 退出全屏 |
| Ctrl+O | 打开文件 |
| Ctrl+S | 保存文件 |
| Ctrl+P | 打印 |
| Ctrl+Shift+Esc | 任务管理器 |
| Win+R | 运行对话框 |
| Win+E | 文件资源管理器 |
| Alt+Tab | 切换窗口 |

---

## 三、Windows Kiosk 突破

### 3.1 Sticky Keys 后门

```
步骤:
1. 连续按 Shift 键 5 次
2. 如果弹出 Sticky Keys 对话框
3. 点击 "转到轻松访问中心"
4. 可能获得控制面板访问
5. 从控制面板启动 cmd
```

### 3.2 利用帮助文件

```
步骤:
1. 在任何应用中按 F1
2. 如果打开 Windows 帮助
3. 右键点击帮助内容
4. 选择 "查看源代码" 或 "属性"
5. 可能获得文件系统访问
```

### 3.3 利用 CHM 文件

```
CHM 文件利用:
├── CHM 文件可以包含 HTML 和脚本
├── 可以执行 ActiveX 控件
├── 可以调用本地程序
└── 可以访问文件系统
```

### 3.4 任务管理器

```bash
# 如果可以访问任务管理器
Ctrl+Shift+Esc

# 在任务管理器中
文件 -> 运行新任务 -> cmd.exe
```

---

## 四、利用 Explorer 功能

### 4.1 地址栏命令执行

```
在文件资源管理器地址栏输入:
├── cmd
├── powershell
├── notepad
├── control (控制面板)
└── C:\Windows\System32\cmd.exe
```

### 4.2 右键菜单利用

```
右键菜单选项:
├── 打开方式 -> 选择程序
├── 发送到 -> 压缩文件夹
├── 属性 -> 可能有链接
└── 新建 -> 快捷方式
```

### 4.3 创建快捷方式

```
步骤:
1. 右键 -> 新建 -> 快捷方式
2. 输入: cmd.exe
3. 完成创建
4. 双击运行
```

---

## 五、网络突破

### 5.1 利用浏览器访问本地资源

```
在浏览器地址栏输入:
├── file:///C:/
├── file:///C:/Windows/System32/
├── \\127.0.0.1\C$
└── \\localhost\admin$
```

### 5.2 利用 URI 协议

```
常见 URI 协议:
├── file:// - 本地文件
├── ms-settings: - Windows 设置
├── control: - 控制面板
├── shell: - Shell 文件夹
└── calculator: - 计算器
```

### 5.3 利用 JavaScript

```javascript
// 在浏览器控制台执行
// 尝试访问本地文件
window.location = "file:///C:/Windows/System32/";

// 尝试执行命令 (某些旧版浏览器)
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd.exe");
```

---

## 六、物理攻击

### 6.1 USB 攻击

```
USB 攻击向量:
├── Rubber Ducky (键盘模拟)
├── USB Armory (网络攻击)
├── BadUSB (固件攻击)
├── 启动盘 (绕过系统)
└── 自动运行 (如果启用)
```

### 6.2 Rubber Ducky 脚本

```
REM 打开运行对话框
DELAY 1000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 500
STRING whoami
ENTER
```

### 6.3 启动盘攻击

```
步骤:
1. 准备 Linux 启动盘
2. 重启 Kiosk 机器
3. 从 USB 启动
4. 挂载 Windows 分区
5. 修改系统文件或提取数据
```

---

## 七、实践示例

### 7.1 浏览器 Kiosk 突破流程

```
1. 尝试键盘快捷键
   - F11 退出全屏
   - Ctrl+O 打开文件
   - Ctrl+P 打印

2. 利用对话框
   - 文件上传/下载
   - 打印对话框
   - 另存为对话框

3. 导航到系统目录
   - C:\Windows\System32
   - 找到 cmd.exe

4. 执行命令
   - 右键 -> 打开
   - 或创建快捷方式
```

### 7.2 获取 Shell 后的操作

```powershell
# 检查当前权限
whoami /all

# 检查网络
ipconfig /all

# 检查系统信息
systeminfo

# 尝试提权
# 检查未打补丁的漏洞
# 检查服务配置
# 检查计划任务
```

---

## 八、防御建议

### 8.1 Kiosk 加固

```
加固措施:
├── 禁用所有不必要的快捷键
├── 禁用右键菜单
├── 禁用文件对话框
├── 使用 AppLocker 限制程序
├── 禁用 USB 端口
├── 设置 BIOS 密码
├── 禁用网络启动
└── 定期审计配置
```

### 8.2 监控

```
监控建议:
├── 监控异常进程
├── 监控文件系统访问
├── 监控网络连接
├── 监控 USB 设备
└── 设置告警
```

---

## 九、章节测试

### 选择题

1. Kiosk 最常见的突破点是？
   - A) 网络攻击
   - B) 文件对话框
   - C) 密码破解
   - D) 物理破坏

2. 哪个快捷键可以打开任务管理器？
   - A) Ctrl+Alt+Del
   - B) Ctrl+Shift+Esc
   - C) Win+R
   - D) Alt+F4

3. Sticky Keys 后门利用的是？
   - A) 连续按 Shift 5 次
   - B) 连续按 Ctrl 5 次
   - C) 连续按 Alt 5 次
   - D) 连续按 Win 5 次

4. 浏览器中访问本地文件的协议是？
   - A) http://
   - B) https://
   - C) file://
   - D) local://

5. Rubber Ducky 是什么类型的攻击工具？
   - A) 网络攻击
   - B) 键盘模拟
   - C) 密码破解
   - D) 漏洞利用

### 答案

1-B, 2-B, 3-A, 4-C, 5-B

---

**返回**：知识库目录
