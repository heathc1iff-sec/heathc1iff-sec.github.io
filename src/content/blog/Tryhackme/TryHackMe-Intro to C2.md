---
title: TryHackMe-Intro to C2
description: 'Red Teaming'
pubDate: 2024-04-01
image: /image/fengmian/tryhackme.jpg
categories:
  - Documentation
tags:
  - Tryhackme
---

命令与控制 （C2） 框架是 Red Teamers 和 Advanced Adversaries 剧本的重要组成部分。它们使在交战期间管理受感染的设备变得容易，并且通常有助于横向移动。

几乎所有的 C2 框架都需要一个特殊的有效载荷生成器。这通常是框架本身内置的功能。例如，Metasploit 是一个 C2 框架，它有自己的有效负载生成器 MSFVenom。

![](/image/tryhackme/TryHackMe-Intro%20to%20C2-1.png)

让我们从最重要的组件开始 - C2 服务器本身。C2 服务器充当代理回调的中心。代理将定期联系 C2 服务器并等待操作员的命令。

## 混淆代理回调
### Sleep Timers 睡眠定时器
> + <u>TCP</u>/443 - Session Duration 3s, 55 packets sent, 10:00:05.000  
TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：05.000
> + <u>TCP</u>/443 - Session Duration 2s, 33 packets sent, 10:00:10.000  
TCP/443 - 会话持续时间 2 秒，发送 33 个数据包，10：00：10.000
> + <u>TCP</u>/443 - Session Duration 3s, 55 packets sent, 10:00:15.000  
TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：15.000
> + <u>TCP</u>/443 - Session Duration 1s, 33 packets sent, 10:00:20.000  
TCP/443 - 会话持续时间 1 秒，发送 33 个数据包，10：00：20.000
> + <u>TCP</u>/443 - Session Duration 3s, 55 packets sent, 10:00:25.000  
TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：25.000
>

一种模式开始形成。代理每 5 秒发出一次信标;这意味着它有一个 5 秒的睡眠定时器。



### Jitter 抖动
> + <u>TCP</u>/443 - Session Duration 3s, 55 packets sent, 10:00:03.580  
TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：03.580
> + <u>TCP</u>/443 - Session Duration 2s, 33 packets sent, 10:00:13.213  
TCP/443 - 会话持续时间 2 秒，发送 33 个数据包，10：00：13.213
> + <u>TCP</u>/443 - Session Duration 3s, 55 packets sent, 10:00:14.912  
TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：14.912
> + <u>TCP</u>/443 - Session Duration 1s, 33 packets sent, 10:00:23.444  
TCP/443 - 会话持续时间 1 秒，发送 33 个数据包，10：00：23.444
> + <u>TCP</u>/443 - Session Duration 3s, 55 packets sent, 10:00:27.182  
TCP/443 - 会话持续时间 3 秒，发送 55 个数据包，10：00：27.182
>

信标现在设置为半不规则模式，这使得在常规用户流量中识别的难度略有增加。在更高级的 C2 框架中，可以更改各种其他参数，例如“文件”抖动或将垃圾数据添加到有效负载或正在传输的文件以使其看起来比实际更大。

Jitter 的示例 Python3 代码可能如下所示：

> **import random**
>
> **sleep = 60**
>
> **jitter = random.randint(-30,30)**
>
> **sleep = sleep + jitter**
>

****

## Payload Types 有效负载类型
> Much like a regular Reverse Shell, there are two primary types of payloads that you may be able to use in your C2 Framework; Staged and Stageless payloads.  
与常规的反向 Shell 非常相似，您可以在 C2 框架中使用两种主要类型的有效负载;暂存和无暂存有效负载。
>
> ### Stageless Payloads 无级有效载荷
> Stageless Payloads are the simplest of the two; they contain the full <u>C2</u> agent and will call back to the <u>C2</u> server and begin beaconing immediately. You can refer to the diagram below to gain a better understanding of how Stageless payloads operate.  
无级有效载荷是两者中最简单的;它们包含完整的 C2 代理，并将回调到 C2 服务器并立即开始信标。您可以参考下图，以更好地了解无级有效负载的运行方式。
>

![](/image/tryhackme/TryHackMe-Intro%20to%20C2-2.png)

> The steps for establishing <u>C2</u> beaconing with a Stageless payload are as follows:  
使用无阶段有效负载建立 C2 信标的步骤如下：
>
> **1.** The Victim downloads and executes the Dropper  
1. 受害人下载并执行滴管
>
> **2.** The beaconing to the <u>C2</u> Server begins  
2. 开始向 C2 服务器发送信标
>
> 
>
> ### Staged Payloads 暂存有效载荷
> Staged payloads require a callback to the <u>C2</u> server to download additional parts of the <u>C2</u> agent. This is commonly referred to as a “Dropper” because it is “Dropped” onto the victim machine to download the second stage of our staged payload. This is a preferred method over stageless payloads because a small amount of code needs to be written to retrieve the additional parts of the <u>C2</u> agent from the <u>C2</u> server. It also makes it easier to obfuscate code to bypass Anti-Virus programs.  
暂存有效负载需要回调到 C2 服务器才能下载 C2 代理的其他部分。这通常被称为“滴管”，因为它被“滴落”到受害机器上，以下载我们暂存有效载荷的第二阶段。这是优于无阶段有效负载的首选方法，因为需要编写少量代码才能从 C2 服务器检索 C2 代理的附加部分。它还使混淆代码以绕过防病毒程序变得更加容易。
>

![](/image/tryhackme/TryHackMe-Intro%20to%20C2-3.png)

> The steps for establishing <u>C2</u> beaconing with a Staged payload are as follows:  
使用暂存有效负载建立 C2 信标的步骤如下：
>
> 
>
> **1.** The Victim downloads and executes the Dropper  
1. 受害人下载并执行滴管
>
> **2.** The Dropper calls back to the <u>C2</u> Server for Stage 2  
2. Dropper 回调 C2 服务器进行第 2 阶段
>
> **3.** The <u>C2</u> Server sends Stage 2 back to the Victim Workstation  
3. C2 服务器将阶段 2 发送回受害者工作站
>
> **4.**** **Stage 2 is loaded into memory on the Victim Workstation   
4. 第 2 阶段加载到受害者工作站的内存中
>
> **5.** <u>C2</u> Beaconing Initializes, and the Red Teamer/Threat Actors can engage with the Victim on the <u>C2</u> Server.  
5. C2 信标初始化，红队成员/威胁参与者可以在 C2 服务器上与受害者互动。
>

简单解释下

### 暂存有效负载
+ 暂存有效负载指的是恶意代码或攻击负载在目标系统上不会直接写入磁盘，而是在内存中运行。
+ 这意味着一旦目标系统重启或关机，恶意代码就会被清除，不会在系统上留下明显的痕迹。
+ 由于不涉及文件写入，暂存有效负载通常更难被杀毒软件或安全工具检测到，因为它们不会触发传统的病毒扫描或文件监视机制。

### 无暂存有效负载：
+ 与暂存有效负载相反，无暂存有效负载是将恶意代码或攻击负载写入目标系统的磁盘中，通常作为文件保存。
+ 这种方式使得恶意代码在目标系统上持久存在，即使系统重启或关机，也会在启动后重新执行。
+ 由于涉及文件写入，无暂存有效负载可能更容易被杀毒软件或安全工具检测到，因为它们可以触发文件监视和病毒扫描。



