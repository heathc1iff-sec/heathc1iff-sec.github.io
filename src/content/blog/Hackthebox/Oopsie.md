---
title: HTB-Oopsie
description: 'Hack the box'
pubDate: 2024-03-02 
image: /public/hackthebox/Oopsie.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Linux Machine
---

## TASK 1 
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709202635540-de73d4a7-e42c-4ab8-a45e-abbf0ae4f6f7.png)

## TASK 2
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709202676870-f5c9577c-c08c-402c-8d2b-3953f4b9fb02.png)

先用nmap扫描下ip

 ![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709202754817-540370cd-9340-4ec4-99f1-6244816722d2.png)

可以看到80端口开放，尝试访问

使用dirsearch进行扫描

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709253067627-03ceee5b-24dc-4d8d-832c-0ee017d05029.png)

没扫出什么有用的消息

uploads网页又不给访问

审查一下主站的源码

发现了这个![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709253416518-ff25259b-0469-44e6-ad0f-0b341f742e3d.png)

尝试了下没什么用

再去瞅瞅![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709253539066-8c0dc297-8a20-4ae1-9d39-8d075b7227e3.png)

发现了登录接口，去掉script.js即可

## TASK 3
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709253619674-cdbc7f72-5b5a-4e8e-b93f-bce25d0f718f.png)

答案是cookie

## TASK 4
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709253827186-623d0786-f3d4-4686-9f97-65abd9096467.png)这里尝试了下admin/admin弱口令失败

直接使用guest账户进行登录

在点击上面栏目表时发现url框里id为2

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709253927939-358a6d46-274b-4362-9c9a-d565fc10d784.png)

尝试修改为1

成功得到adminID ![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709253960011-7cafde46-b51d-402f-916a-fe7fcbcb6099.png)

这里我们尝试吧cookie值修改为admin账户

第一遍没有成功，第二遍成功了![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709254255228-2622b452-efcd-423b-90db-506fac2a2e09.png)

## TASK 5
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709254364141-151f3908-74e7-4def-92f2-596e80e9c3d2.png)

看到尾部有个s直接使用/uploads秒了

## TASK 6
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709254428353-bfcbb949-599c-4e3f-91eb-5c04f1b08233.png)

这里我们随便上传个文件，怀疑没什么过滤

上传个webshell

> <font style="color:rgb(77, 77, 77);">kali本身自带了一些webshell，位于</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">/usr/share/webshells</font><font style="color:rgb(77, 77, 77);">目录，php目录下有个php-reverse-shell.php，可以利用它来进行</font>[反弹shell](https://so.csdn.net/so/search?q=%E5%8F%8D%E5%BC%B9shell&spm=1001.2101.3001.7020)
>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709256064242-92d53150-ba15-483e-b68e-0b316f11e347.png)

这里我们需要把ip修改为自身ip

之后上传的时候不要填写产品产品名称

访问url+uploads/<font style="color:rgb(77, 77, 77);">php-reverse-shell.php同时监听4444端口</font>

<font style="color:rgb(77, 77, 77);">成功get shell</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709256174063-4118ef7e-7f2b-493f-9fe2-04099ec7fe91.png)

根据题目得知还有一个**<font style="color:rgb(255, 255, 255);background-color:rgb(20, 29, 43);">robert 用户</font>**

**cat /etc/passwd 在靶机中发现robert用户**

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709256308708-b68ab809-113e-4d17-b4d8-2f24318f9dda.png)

<font style="color:rgb(77, 77, 77);">信息收集时我们知道靶机用的是apache的服务，那就再去/var/www/html下看看有什么文件</font>

<font style="color:rgb(25, 27, 31);">读取web应用下的db.php文件获取到数据库连接信息</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709256659434-c0835521-0a8d-41c3-8aac-3004a3be3211.png)

$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');

然后切换robert用户

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709256719663-eb3a2484-ca49-4b36-8e50-ef0cfae230d2.png)

由于不是交互式shell 使用<font style="color:rgb(25, 27, 31);background-color:rgb(248, 248, 250);">SHELL=/bin/bash script -q /dev/null</font><font style="color:rgb(25, 27, 31);"> :  来调整到交互式shell</font>

<font style="color:rgb(25, 27, 31);">这里使用python的pty模块也可以</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709257275627-64623046-6e66-4317-a1a4-203b7dd5f366.png)

 成功登录后先查看下ID

<font style="color:rgb(77, 77, 77);">现robert属于bugtracker这个组</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709261600181-0dc8ed0c-b932-4ab5-9e53-9aa04c10e44c.png)

<font style="color:rgb(77, 77, 77);">用find看下bugtracker这个组的用户能执行哪些文件</font>

<font style="color:rgb(25, 27, 31);">find / -group bugtracker 2>/dev/null</font>

> <font style="color:rgb(77, 77, 77);">（</font><font style="color:rgb(13, 13, 13);">查找属于 "bugtracker" 用户组的文件，并输出它们的路径其中</font>**<font style="color:rgb(13, 13, 13);">2>/dev/null</font>**<font style="color:rgb(13, 13, 13);">: 这部分是将标准错误重定向到 </font>**<font style="color:rgb(13, 13, 13);">/dev/null</font>**<font style="color:rgb(13, 13, 13);">。</font>**<font style="color:rgb(13, 13, 13);">2></font>**<font style="color:rgb(13, 13, 13);">表示将标准错误（stderr）重定向，</font>**<font style="color:rgb(13, 13, 13);">/dev/null</font>**<font style="color:rgb(13, 13, 13);"> 是一个特殊的设备文件，它会丢弃所有写入其中的数据。因此，此部分的作用是将错误信息静默化，这样在执行命令时不会显示错误信息。</font><font style="color:rgb(77, 77, 77);">）</font>
>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709261781089-aba2f0a4-375a-4854-a4da-2cb4e8cfc937.png)

<font style="color:rgb(77, 77, 77);">发现存在一个/usr/bin/bugtracker文件，再看下这个文件有哪些权限</font>

<font style="color:rgb(25, 27, 31);">ls -al /usr/bin/bugtracker</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709261810927-8b898f47-6214-4e31-8290-c2c4677f4806.png)<font style="color:rgb(77, 77, 77);">发现这个文件有s权限即suid权限，所有者为root，suid简单来说就是任何用户执行具有suid权限的文件时都会以它拥有者的权限执行</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709262897594-4d427da8-c89c-49a7-8ec5-92e1b5a95af9.png)

<font style="color:rgb(13, 13, 13);">"Set Owner User ID"（设置所有者用户标识）是一种文件系统权限设置，通常简写为SUID。当文件的SUID位被设置时，它会允许执行该文件的用户在执行过程中临时拥有文件所有者的权限。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709358191728-eb6bd21e-80b8-4e11-8778-c18e31e34847.png)

<font style="color:rgb(77, 77, 77);">我们先执行一下这个文件bugtracke</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709358249319-27f145b3-fa51-4ffd-aae7-7668319a3df5.png)

<font style="color:rgb(13, 13, 13);"></font>

<font style="color:rgb(13, 13, 13);">这时候就发现这个文件实际上是用cat命令抓取/root/reports/目录下的指定文件</font>

<font style="color:rgb(13, 13, 13);">我们需要注意的是，它这里是直接调用的cat，所以很依赖环境变量，直接调用cat只会抓取环境变量中的路径下的文件</font>

<font style="color:rgb(13, 13, 13);">所以我们可以在环境变量中注入一个自定义的路径，替代掉这个文件真正想要调用的cat</font>

<font style="color:rgb(13, 13, 13);">进入tmp目录下，创建一个会调用bash的cat文件，然后给文件一个执行权限</font>

<font style="color:rgb(77, 77, 77);">使用</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">export PATH=/tmp:$PATH</font><font style="color:rgb(77, 77, 77);">命令把/tmp加入到环境变量中，再查看一下，发现/tmp已经添加到环境变量中了</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709358285178-e8efb58f-3480-4f1b-8d77-71d76a6a313b.png)

<font style="color:rgb(77, 77, 77);">这时候我们再执行bugtracker文件时，系统就会先去/tmp目录下找到我们写的cat并以root权限执行我们写的/bin/bash</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709358376510-1f716978-bc2c-4339-82fd-98bde6558930.png)

在/root文档中打开root.txt 得到根flag

af13b0bee69f8a877c3faf667f7beacf

用robert账户在home/robert/user.txt中找到用户flag



