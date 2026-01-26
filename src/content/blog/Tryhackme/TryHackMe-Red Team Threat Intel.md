---
title: TryHackMe-Red Team Threat Intel
description: 'Red Teaming'
pubDate: 2024-04-01
image: /image/tryhackme.jpg
categories:
  - Documentation
tags:
  - Tryhackme
---

> ATT&CK战术知识库：[https://attack.mitre.org/](https://attack.mitre.org/)
>
> OST Map 跟踪威胁参与者使用具有攻击性功能的库的地图：[https://intezer.com/ost-map/#Carbanak](https://intezer.com/ost-map/#Carbanak)
>





> Rundll32.exe 是 Windows 的标准部分，用于运行动态链接库 （DLL） 文件。DLL 包含程序各种函数的代码，通常由 Windows 进程和第三方应用使用。Rundll32.exe 通常不是恶意软件，但它可用于执行恶意代码。
>



> LOLBAS （Living Off the Land Binaries And Scripts） 是一种攻击方法，它使用已经是系统一部分的二进制文件和脚本进行恶意目的。这使得安全团队很难区分合法和恶意活动，因为它们都是由受信任的系统实用程序执行的。
>





> Bootkit 是一种现代恶意软件，威胁参与者使用它将恶意软件附加到计算机系统。Bootkit 可能对您的业务构成严重的安全威胁，并且通常涉及用于逃避检测的 rootkit 工具。这些攻击以统一可扩展固件接口 （UEFI） 为目标，该接口是将 PC 的操作系统与其设备固件连接起来的软件。
>
> rootkit 是软件工具的集合，或旨在让威胁参与者远程控制计算机系统的程序。通过停用端点防病毒和反恶意软件，Rootkit 可以在不被检测到的情况下运行。这使得恶意软件可以引入系统，以攻击网络或应用程序安全。
>
> Bootkit 将此过程更进一步，旨在感染卷引导记录或主引导记录。通过这样做，引导工具包可以在计算机的操作系统加载之前运行。这样，bootkit 安装的恶意代码在计算机操作系统启动之前启动并运行。
>
> Bootkit感染未被检测到，因为所有组件都在Microsoft Windows文件系统之外，使它们对标准操作系统进程不可见。计算机可能感染 bootkit 的一些警告包括系统不稳定，导致蓝屏警告和无法启动操作系统。
>
> UEFI 安全启动是一种安全标准，可确保设备仅使用受信任的软件启动。固件检查每个启动软件（包括 UEFI 固件）的签名，如果所有签名都有效，则 PC 启动。这种安全启动可以防止 bootkit 感染造成伤害，因为如果发现它，PC 将无法启动。
>



>   
Certutil是Windows操作系统中的一个命令行工具，主要用于证书服务和证书管理。但在渗透测试中，攻击者有时会利用Certutil工具来执行一些恶意操作
>
> **1.下载文件	**
>
> **2.上传文件**	
>
> 3.**绕过安全软件检测**： 有些安全软件会监视和拦截常见的攻击工具或恶意文件下载行为，但是Certutil是Windows系统的正规工具，因此它的使用可能会绕过一些安全软件的检测。
>
> **4.执行Base64编码解码**： Certutil还可以用于Base64编码和解码。攻击者可能会将恶意文件编码为Base64格式，然后在目标系统上使用Certutil解码并执行。
>



> MESSAGETAP（留言点击）
>
> MESSAGETAP 是 APT41 部署到电信网络中的数据挖掘恶意软件系列，用于监控和保存来自特定电话号码、IMSI 号码或包含特定关键字的 SMS 流量
>
> 存档收集的数据：通过自定义方法存档，自动收集，数据暂存：本地数据暂存，对文件或信息进行反混淆/解码，文件和目录发现，指示器删除：文件删除，网络嗅探，系统网络连接发现
>
> SMB（Server Message Block）是一种在局域网中共享文件、打印机以及其他资源的网络协议。
>

