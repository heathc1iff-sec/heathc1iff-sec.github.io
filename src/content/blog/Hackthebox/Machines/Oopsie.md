---
title: HTB-Oopsie
description: 'Hack the box'
pubDate: 2024-03-02 
image: /hackthebox/Oopsie.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Linux Machine
---

## TASK 1 
![](/image/hackthebox/Oopsie-1.png)

## TASK 2
![](/image/hackthebox/Oopsie-2.png)

先用nmap扫描下ip

 ![](/image/hackthebox/Oopsie-3.png)

可以看到80端口开放，尝试访问

使用dirsearch进行扫描

![](/image/hackthebox/Oopsie-4.png)

没扫出什么有用的消息

uploads网页又不给访问

审查一下主站的源码

发现了这个![](/image/hackthebox/Oopsie-5.png)

尝试了下没什么用

再去瞅瞅![](/image/hackthebox/Oopsie-6.png)

发现了登录接口，去掉script.js即可

## TASK 3
![](/image/hackthebox/Oopsie-7.png)

答案是cookie

## TASK 4
![](/image/hackthebox/Oopsie-8.png)这里尝试了下admin/admin弱口令失败

直接使用guest账户进行登录

在点击上面栏目表时发现url框里id为2

![](/image/hackthebox/Oopsie-9.png)

尝试修改为1

成功得到adminID ![](/image/hackthebox/Oopsie-10.png)

这里我们尝试吧cookie值修改为admin账户

第一遍没有成功，第二遍成功了![](/image/hackthebox/Oopsie-11.png)

## TASK 5
![](/image/hackthebox/Oopsie-12.png)

看到尾部有个s直接使用/uploads秒了

## TASK 6
![](/image/hackthebox/Oopsie-13.png)

这里我们随便上传个文件，怀疑没什么过滤

上传个webshell

> kali本身自带了一些webshell，位于/usr/share/webshells目录，php目录下有个php-reverse-shell.php，可以利用它来进行[反弹shell](https://so.csdn.net/so/search?q=%E5%8F%8D%E5%BC%B9shell&spm=1001.2101.3001.7020)
>

![](/image/hackthebox/Oopsie-14.png)

这里我们需要把ip修改为自身ip

之后上传的时候不要填写产品产品名称

访问url+uploads/php-reverse-shell.php同时监听4444端口

成功get shell

![](/image/hackthebox/Oopsie-15.png)

根据题目得知还有一个**robert 用户**

**cat /etc/passwd 在靶机中发现robert用户**

![](/image/hackthebox/Oopsie-16.png)

信息收集时我们知道靶机用的是apache的服务，那就再去/var/www/html下看看有什么文件

读取web应用下的db.php文件获取到数据库连接信息

![](/image/hackthebox/Oopsie-17.png)

$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');

然后切换robert用户

![](/image/hackthebox/Oopsie-18.png)

由于不是交互式shell 使用SHELL=/bin/bash script -q /dev/null :  来调整到交互式shell

这里使用python的pty模块也可以

![](/image/hackthebox/Oopsie-19.png)

 成功登录后先查看下ID

现robert属于bugtracker这个组

![](/image/hackthebox/Oopsie-20.png)

用find看下bugtracker这个组的用户能执行哪些文件

find / -group bugtracker 2>/dev/null

> （查找属于 "bugtracker" 用户组的文件，并输出它们的路径其中**2>/dev/null**: 这部分是将标准错误重定向到 **/dev/null**。**2>**表示将标准错误（stderr）重定向，**/dev/null** 是一个特殊的设备文件，它会丢弃所有写入其中的数据。因此，此部分的作用是将错误信息静默化，这样在执行命令时不会显示错误信息。）
>

![](/image/hackthebox/Oopsie-21.png)

发现存在一个/usr/bin/bugtracker文件，再看下这个文件有哪些权限

ls -al /usr/bin/bugtracker

![](/image/hackthebox/Oopsie-22.png)发现这个文件有s权限即suid权限，所有者为root，suid简单来说就是任何用户执行具有suid权限的文件时都会以它拥有者的权限执行

![](/image/hackthebox/Oopsie-23.png)

"Set Owner User ID"（设置所有者用户标识）是一种文件系统权限设置，通常简写为SUID。当文件的SUID位被设置时，它会允许执行该文件的用户在执行过程中临时拥有文件所有者的权限。

![](/image/hackthebox/Oopsie-24.png)

我们先执行一下这个文件bugtracke

![](/image/hackthebox/Oopsie-25.png)



这时候就发现这个文件实际上是用cat命令抓取/root/reports/目录下的指定文件

我们需要注意的是，它这里是直接调用的cat，所以很依赖环境变量，直接调用cat只会抓取环境变量中的路径下的文件

所以我们可以在环境变量中注入一个自定义的路径，替代掉这个文件真正想要调用的cat

进入tmp目录下，创建一个会调用bash的cat文件，然后给文件一个执行权限

使用export PATH=/tmp:$PATH命令把/tmp加入到环境变量中，再查看一下，发现/tmp已经添加到环境变量中了

![](/image/hackthebox/Oopsie-26.png)

这时候我们再执行bugtracker文件时，系统就会先去/tmp目录下找到我们写的cat并以root权限执行我们写的/bin/bash

![](/image/hackthebox/Oopsie-27.png)

在/root文档中打开root.txt 得到根flag

af13b0bee69f8a877c3faf667f7beacf

用robert账户在home/robert/user.txt中找到用户flag



