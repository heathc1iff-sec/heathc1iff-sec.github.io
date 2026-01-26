---
title: TryHackMe-Active Directory Basics
description: 'Red Teaming'
pubDate: 2025-12-13
image: /image/tryhackme.jpg
categories:
  - Documentation
tags:
  - Tryhackme
---

<font style="color:rgb(21, 28, 43);">命令与控制 （C2） 框架是 Red Teamers 和 Advanced Adversaries 剧本的重要组成部分。它们使在交战期间管理受感染的设备变得容易，并且通常有助于横向移动。</font>

<font style="color:rgb(21, 28, 43);">几乎所有的 C2 框架都需要一个特殊的有效载荷生成器。这通常是框架本身内置的功能。例如，Metasploit 是一个 C2 框架，它有自己的有效负载生成器 MSFVenom。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1711934710691-934335a7-bb5f-4018-ae39-44f567b7ae5b.png)

<font style="color:rgb(21, 28, 43);">让我们从最重要的组件开始 - C2 服务器本身。C2 服务器充当代理回调的中心。代理将定期联系 C2 服务器并等待操作员的命令。</font>

## <font style="color:rgb(21, 28, 43);">混淆代理回调</font>
### <font style="color:rgb(21, 28, 43);">Sleep Timers 睡眠定时器</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 3s, 55 packets sent, 10:00:05.000  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：05.000</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 2s, 33 packets sent, 10:00:10.000</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 2 秒，发送 33 个数据包，10：00：10.000</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 3s, 55 packets sent, 10:00:15.000</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：15.000</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 1s, 33 packets sent, 10:00:20.000</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 1 秒，发送 33 个数据包，10：00：20.000</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 3s, 55 packets sent, 10:00:25.000  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：25.000</font>
>

<font style="color:rgb(21, 28, 43);">一种模式开始形成。代理每 5 秒发出一次信标;这意味着它有一个 5 秒的睡眠定时器。</font>

<font style="color:rgb(21, 28, 43);"></font>

### <font style="color:rgb(21, 28, 43);">Jitter 抖动</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 3s, 55 packets sent, 10:00:03.580  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：03.580</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 2s, 33 packets sent, 10:00:13.213</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 2 秒，发送 33 个数据包，10：00：13.213</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 3s, 55 packets sent, 10:00:14.912</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：14.912</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 1s, 33 packets sent, 10:00:23.444</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 1 秒，发送 33 个数据包，10：00：23.444</font>
> + <u><font style="color:rgb(21, 28, 43);">TCP</font></u><font style="color:rgb(21, 28, 43);">/443 - Session Duration 3s, 55 packets sent, 10:00:27.182  
</font><font style="color:rgb(21, 28, 43);">TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：27.182</font>
>

<font style="color:rgb(21, 28, 43);">信标现在设置为半不规则模式，这使得在常规用户流量中识别的难度略有增加。在更高级的 C2 框架中，可以更改各种其他参数，例如“文件”抖动或将垃圾数据添加到有效负载或正在传输的文件以使其看起来比实际更大。</font>

<font style="color:rgb(21, 28, 43);">Jitter 的示例 Python3 代码可能如下所示：</font>

> **<font style="color:rgb(255, 255, 255);background-color:rgb(33, 44, 66);">import random</font>**
>
> **<font style="color:rgb(255, 255, 255);background-color:rgb(33, 44, 66);">sleep = 60</font>**
>
> **<font style="color:rgb(255, 255, 255);background-color:rgb(33, 44, 66);">jitter = random.randint(-30,30)</font>**
>
> **<font style="color:rgb(255, 255, 255);background-color:rgb(33, 44, 66);">sleep = sleep + jitter</font>**
>

**<font style="color:rgb(255, 255, 255);background-color:rgb(33, 44, 66);"></font>**

## <font style="color:rgb(21, 28, 43);">Payload Types 有效负载类型</font>
> <font style="color:rgb(21, 28, 43);">Much like a regular Reverse Shell, there are two primary types of payloads that you may be able to use in your C2 Framework; Staged and Stageless payloads.  
</font><font style="color:rgb(21, 28, 43);">与常规的反向 Shell 非常相似，您可以在 C2 框架中使用两种主要类型的有效负载;暂存和无暂存有效负载。</font>
>
> ### <font style="color:rgb(21, 28, 43);">Stageless Payloads 无级有效载荷</font>
> <font style="color:rgb(21, 28, 43);">Stageless Payloads are the simplest of the two; they contain the full </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> agent and will call back to the </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> server and begin beaconing immediately. You can refer to the diagram below to gain a better understanding of how Stageless payloads operate.  
</font><font style="color:rgb(21, 28, 43);">无级有效载荷是两者中最简单的;它们包含完整的 C2 代理，并将回调到 C2 服务器并立即开始信标。您可以参考下图，以更好地了解无级有效负载的运行方式。</font>
>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1711935043374-9ff8c53e-39bf-4822-afbe-9b3185779b8b.png)

> <font style="color:rgb(21, 28, 43);">The steps for establishing </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> beaconing with a Stageless payload are as follows:  
</font><font style="color:rgb(21, 28, 43);">使用无阶段有效负载建立 C2 信标的步骤如下：</font>
>
> **<font style="color:rgb(21, 28, 43);">1.</font>**<font style="color:rgb(21, 28, 43);"> The Victim downloads and executes the Dropper</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">1. 受害人下载并执行滴管</font>
>
> **<font style="color:rgb(21, 28, 43);">2.</font>**<font style="color:rgb(21, 28, 43);"> The beaconing to the</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">Server begins</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">2. 开始向 C2 服务器发送信标</font>
>
> <font style="color:rgb(21, 28, 43);"></font>
>
> ### <font style="color:rgb(21, 28, 43);">Staged Payloads 暂存有效载荷</font>
> <font style="color:rgb(21, 28, 43);">Staged payloads require a callback to the </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> server to download additional parts of the </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> agent. This is commonly referred to as a “Dropper” because it is “Dropped” onto the victim machine to download the second stage of our staged payload. This is a preferred method over stageless payloads because a small amount of code needs to be written to retrieve the additional parts of the </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> agent from the </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> server. It also makes it easier to obfuscate code to bypass Anti-Virus programs.  
</font><font style="color:rgb(21, 28, 43);">暂存有效负载需要回调到 C2 服务器才能下载 C2 代理的其他部分。这通常被称为“滴管”，因为它被“滴落”到受害机器上，以下载我们暂存有效载荷的第二阶段。这是优于无阶段有效负载的首选方法，因为需要编写少量代码才能从 C2 服务器检索 C2 代理的附加部分。它还使混淆代码以绕过防病毒程序变得更加容易。</font>
>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1711935077355-632fb3b2-4a05-4562-9c7f-101683b6bfa9.png)

> <font style="color:rgb(21, 28, 43);">The steps for establishing </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> beaconing with a Staged payload are as follows:  
</font><font style="color:rgb(21, 28, 43);">使用暂存有效负载建立 C2 信标的步骤如下：</font>
>
> <font style="color:rgb(21, 28, 43);"></font>
>
> **<font style="color:rgb(21, 28, 43);">1.</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">The Victim downloads and executes the Dropper</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">1. 受害人下载并执行滴管</font>
>
> **<font style="color:rgb(21, 28, 43);">2.</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">The Dropper calls back to the</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">Server for Stage 2</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">2. Dropper 回调 C2 服务器进行第 2 阶段</font>
>
> **<font style="color:rgb(21, 28, 43);">3.</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">The</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">Server sends Stage 2 back to the Victim Workstation</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">3. C2 服务器将阶段 2 发送回受害者工作站</font>
>
> **<font style="color:rgb(21, 28, 43);">4.</font>****<font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Stage 2 is loaded into memory on the Victim Workstation </font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">4. 第 2 阶段加载到受害者工作站的内存中</font>
>
> **<font style="color:rgb(21, 28, 43);">5.</font>**<font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> Beaconing Initializes, and the Red Teamer/Threat Actors can engage with the Victim on the </font><u><font style="color:rgb(21, 28, 43);">C2</font></u><font style="color:rgb(21, 28, 43);"> Server.  
</font><font style="color:rgb(21, 28, 43);">5. C2 信标初始化，红队成员/威胁参与者可以在 C2 服务器上与受害者互动。</font>
>

简单解释下

### <font style="color:rgb(13, 13, 13);">暂存有效负载</font>
+ <font style="color:rgb(13, 13, 13);">暂存有效负载指的是恶意代码或攻击负载在目标系统上不会直接写入磁盘，而是在内存中运行。</font>
+ <font style="color:rgb(13, 13, 13);">这意味着一旦目标系统重启或关机，恶意代码就会被清除，不会在系统上留下明显的痕迹。</font>
+ <font style="color:rgb(13, 13, 13);">由于不涉及文件写入，暂存有效负载通常更难被杀毒软件或安全工具检测到，因为它们不会触发传统的病毒扫描或文件监视机制。</font>

### 无暂存有效负载<font style="color:rgb(13, 13, 13);">：</font>
+ <font style="color:rgb(13, 13, 13);">与暂存有效负载相反，无暂存有效负载是将恶意代码或攻击负载写入目标系统的磁盘中，通常作为文件保存。</font>
+ <font style="color:rgb(13, 13, 13);">这种方式使得恶意代码在目标系统上持久存在，即使系统重启或关机，也会在启动后重新执行。</font>
+ <font style="color:rgb(13, 13, 13);">由于涉及文件写入，无暂存有效负载可能更容易被杀毒软件或安全工具检测到，因为它们可以触发文件监视和病毒扫描。</font>



