---
title: HMV-Venus
description: 'For people who starts playing CTF and wants to practice Linux skills.'
pubDate: 2026-01-14
image: /machine/Venus.jpg
categories:
  - Documentation
tags:
  - Hackmyvm
  - HMVLabs
  - Linux Machine
---

#### 一键获取flag
```plain
sophia/Y1o645M3mR84ejc
angela/oh5p9gAABugHBje
emma/fIvltaGaq0OUH8O
mia/iKXIYg0pyEH2Hos
camila/F67aDmCAAgOOaOc
luna/j3vkuoKQwvbhkMc
eleanor/UNDchvln6Bmtu7b
victoria/pz8OqvJBFxH0cSj
isla/D3XTob0FUImsoBb
violet/WKINVzNQLKLDVAc
lucy/OCmMUjebG53giud
elena/4xZ5lIKYmfPLg9t
alice/Cgecy2MY2MWbaqt
anna/w8NvY27qkpdePox
natalia/NMuc4DkYKDsmZ5z
eva/upsCA3UFu10fDAO
clara/39YziWp5gSvgQN9
frida/Ed4ErEUJEaMcXli
eliza/Fg6b6aoksceQqB9
iris/kYjyoLcnBZ9EJdz
eloise/yOUJlV0SHOnbSPm
lucia/uvMwFDQrQWPMeGP
isabel/H5ol8Z2mrRsorC0
freya/EEDyYFDwYsmYawj
alexa/mxq9O3MSxxX9Q3S
ariel/33EtHoz9a0w2Yqo
lola/d3LieOzRGX5wud6
celeste/VLSNMTKwSV2o8Tn
nina/ixpeqdWuvC5N9kG
kira/tPlqxSKuT4eP3yr
veronica/QTOel6BodTx2cwX
lana/UWbc0zNEVVops1v
noa/9WWOPoeJrq6ncvJ
maia/h1hnDPHpydEjoEN
gloria/v7xUVE2e5bjUcxw
alora/mhrTFCoxGoqUxtw
julie/sjDf4i2MSNgSvOv
irene/8VeRLEFkBpe2DSD
adela/nbhlQyKuaXGojHx
sky/papaparadise
sarah/LWOHeRgmIxg7fuS
mercy/ym5yyXZ163uIS8L
paula/dlHZ6cvX6cLuL8p
karla/gYAmvWY3I7yDKRf
denise/pFg92DpGucMWccA
zora/BWm1R3jCcb53riO
belen/2jA0E8bQ4WrGwWZ
leona/freedom
ava/oCXBeeEeYFX34NU
maria/.--. .- .--. .- .--. .- .-. .- -.. .. ... .
```

```plain
#!/usr/bin/expect -f
set timeout 10

set host "venus.hackmyvm.eu"
set port 5000
set ssh_user "hacker"
set ssh_pass "havefun!"
set prompt {[$#] $}

# 读取用户
set f [open "users.txt" r]
set users [split [read $f] "\n"]
close $f

# SSH 登录一次
spawn ssh -o StrictHostKeyChecking=no -p $port $ssh_user@$host
expect "*assword:"
send "$ssh_pass\r"
expect -re $prompt

foreach line $users {
    if {[string trim $line] == ""} {
        continue
    }

    set user [lindex $line 0]
    set pass [lindex $line 1]

    puts "\n===== $user ====="

    send "su $user\r"
    expect {
        "*assword:" {
            send "$pass\r"
        }
        "*Authentication failure*" {
            puts "FAIL $user su failed"
            expect -re $prompt
            continue
        }
    }

    expect {
        "*Authentication failure*" {
            puts "FAIL $user su failed"
            expect -re $prompt
            continue
        }
        -re $prompt {
            send "cd /pwned/$user; cat flagz.txt 2>/dev/null || echo 'no flag'\r"
            expect -re $prompt
            send "exit\r"
            expect -re $prompt
        }
    }
}

send "exit\r"
expect eof
```

****

****

****

**Instruction**

```plain
Do you love Linux and CTFs? WTF, so you are like us!
Enjoy practicing your Linux skills to get the flags and to find the password to log in as other users.
This is a beginner level so enjoy and be patient!
```

**Start**

```plain
$ ssh hacker@venus.hackmyvm.eu -p 5000
password :havefun!
```

【成功连接，游戏开始】

每个用户的主目录下都会有一个 `mission.txt`

#### Mission 0x01
```plain
$ ls
mission.txt  readme.txt
// mission.txt 是任务，readme.txt 是游戏介绍
$ cat mission.txt
################
# MISSION 0x01 #
################

## EN ##
User sophia has saved her password in a hidden file in this folder. Find it and log in as sophia.
## ES ##
La usuaria sophia ha guardado su contraseña en un fichero oculto en esta carpeta.Encuentralo y logueate como sophia.
```

任务 0x01是获取用户 `sophia`的密码并登录，任务提示是当前目录的隐藏文件，使用`ls -a`查看隐藏文件，得到密码 `Y1o645M3mR84ejc`

```shell
// 切换用户
$ su sophia
// 到用户的主目录
$ cd ../sophia       在目录下的到第一个flag和下一个任务
```

#### Mission 0x02
```plain
$ cat mission.txt
################
# MISSION 0x02 #
################

## EN ##
The user angela has saved her password in a file but she does not remember where ... she only remembers that the file was called whereismypazz.txt 

## ES ##
La usuaria angela ha guardado su password en un fichero pero no recuerda donde... solo recuerda que el fichero se llamaba whereismypazz.txt
```

任务 0x02是获取 `angela`的密码并登录，任务提示了存放密码的文件名，但没有提供目录，所以我们需要使用`find`命令来查找文件

```shell
$ find / -name whereismypazz.txt 2>/dev/null
/usr/share/whereismypazz.txt
// 直接查看
$ cat /usr/share/whereismypazz.txt
```

得到密码`oh5p9gAABugHBje`,切换用户到 `angela`, 到该用户的主目录下获取到第二个flag 和 任务 0x03

#### Mission 0x03
```shell
$ cat mission.txt
################
# MISSION 0x03 #
################
## EN ##
The password of the user emma is in line 4069 of the file findme.txt
## ES ##
La password de la usuaria emma esta en la linea 4069 del fichero findme.txt
```

任务提示密码在 findme.txt文件的第 4096 行，获取到改行的数据就是密码

```shell
$ head -n 4096 findme.txt | tail -n 1
fIvltaGaq0OUH8O
切换到 emma ，在主目录下发现flag和下一个任务
```

这里列出几个获取第 50 行数据的指令

+ `head -n 50 filename | tail -n 1`
+ `cat -n filename | grep "50"`
+ `awk "NR==50" filename`
+ `sed -n '50p' filename`
+ `grep -n "" filename | grep "^50:" | cut -d: -f2-`

#### Mission 0x04
```shell
################
# MISSION 0x04 #
################

## EN ##
User mia has left her password in the file -.
## ES ##
La usuaria mia ha dejado su password en el fichero -.
```

用户`mia`的密码在文件 `-`中，这里有一个坑，不能直接使用`cat -`读取名为 `-`的文件

```shell
$ cat ./-         #读取当前目录下的名为 - 的文件
iKXIYg0pyEH2Hos
在mia的家目录下获取到flag和下一个任务
```

#### Mission 0x05
```shell
################
# MISSION 0x05 #
################
## EN ##
It seems that the user camila has left her password inside a folder called hereiam 
## ES ##
Parece que la usuaria camila ha dejado su password dentro de una carpeta llamada hereiam
```

任务提示密码在文件夹`hereiam`下，我们需要查找该文件夹的位置

```shell
$ find / -type d -name hereiam 2>/dev/null
/opt/hereiam    # 密码在该目录下的隐藏文件 .here里
```

获取用户`camila`的密码`F67aDmCAAgOOaOc`，切换用户，转到其主目录下获取flag和下一个任务。

#### Mission 0x06
```shell
################
# MISSION 0x06 #
################
## EN ##
The user luna has left her password in a file inside the muack folder. 
## ES ##
La usuaria luna ha dejado su password en algun fichero dentro de la carpeta muack.
```

查看`muack/`下的文件夹

蛙趣，层层嵌套，手动查找肯定是不可能的了，使用 `find`命令可以达到想要的效果

```shell
$ find muack/ -type f -exec cat {} \;
j3vkuoKQwvbhkMc
```

得到用户`luna`的密码`j3vkuoKQwvbhkMc`,切换用户，在其主目录下发现flag和下一个Mission

#### Mission 0x07
```shell
################
# MISSION 0x07 #
################
## EN ##
The user eleanor has left her password in a file that occupies 6969 bytes. 
## ES ##
La usuaria eleanor ha dejado su password en un fichero que ocupa 6969 bytes.
```

任务提示文件密码在大小为 6969 bytes的文件内，继续使用 `find`命令查找符合条件的文件

```shell
$ find / -size 6969c -type f 2>/dev/null
/usr/share/moon.txt   # 查看moon.txt内的内容
```

获取到用户`eleanor`的密码`UNDchvln6Bmtu7b`，登录并到主目录下获取flag 和下一个任务指示

#### Misssion 0x08
```plain
################
# MISSION 0x08 #
################

## EN ##
The user victoria has left her password in a file in which the owner is the user violin. 

## ES ##
La usuaria victoria ha dejado su password en un fichero en el cual el propietario es el usuario violin.
```

任务提示，victoria的密码存在的文件的主人是 violin，`find`命令也可以查找所有者的文件

```shell
$ find / -type f -name "*" -user violin -exec cat {} \; 2>/dev/null
pz8OqvJBFxH0cSj
```

获取到用户`victoria`的密码，登录并到其主目录下获得flag和下一个任务指示。

#### Mission 0x09
```plain
################
# MISSION 0x09 #
################

## EN ##
The user isla has left her password in a zip file.

## ES ##
La usuaria isla ha dejado su password en un fichero zip.
```

任务提示 isla的密码在压缩包里，但在当前主目录下是没有写入权限的，所以不能直接解压到当前目录，但 `/tmp`有写入权限

预期解应该是解压到`/tmp目录下`，然后读取

```plain
$ unzip passw0rd.zip -d /tmp
/tmp/pwned/victoria/passw0rd.txt   #读取获得密码
非预期：直接cat passw0rd.zip
PK
�.�T��B�wned/victoria/passw0rd.txtUT    �|Nb�|Nbux
                                                  D3XTob0FUImsoBb
PK
�.�T��B���pwned/victoria/passw0rd.txtUT�|Nbux
                                             PKae
同样可以得到密码
```

得到用户 `isla`的密码`D3XTob0FUImsoBb`，登陆在主目录下发下flag和下一个任务提示

#### Mission 0x10
```plain
################
# MISSION 0x10 #
################
## EN ##
The password of the user violet is in the line that begins with a9HFX (these 5 characters are not part of her password.). 
## ES ##
El password de la usuaria violet esta en la linea que empieza por a9HFX (sin ser estos 5 caracteres parte de su password.).
```

任务提示密码是 以`a9HFX`开头，所以可以读取

```plain
$ grep ^a9HFX passy    或者     cat passy | grep "^a9HFX"
a9HFXWKINVzNQLKLDVAc
```

得到 用户`violet`的密码`WKINVzNQLKLDVAc`，登录并转到主目录下发现flag 和 下一个任务提示。

#### Mission 0x11
```plain
################
# MISSION 0x11 #
################

## EN ##
The password of the user lucy is in the line that ends with 0JuAZ (these last 5 characters are not part of her password) 

## ES ##
El password de la usuaria lucy se encuentra en la linea que acaba por 0JuAZ (sin ser estos ultimos 5 caracteres parte de su password)
```

任务提示密码是以`0JuAZ`结尾的，可以

```plain
$ cat end | grep "0JuAZ$"   或grep "0JuAZ$" end
```

得到用户`lucy`的密码`OCmMUjebG53giud`，登录转到主目录下获取flag和下一个任务提示。

#### Mission 0x12
```plain
################
# MISSION 0x12 #
################
## EN ##
The password of the user elena is between the characters fu and ck 
## ES ##
El password de la usuaria elena esta entre los caracteres fu y ck
```

任务提示，密码在 fu 和 ck 之间

```plain
$ cat file.yo | grep -E "^fu.*ck$"
fu4xZ5lIKYmfPLg9tck
```

`elena`的密码是`4xZ5lIKYmfPLg9t`

#### Misson 0x13
```shell
################
# MISSION 0x13 #
################

## EN ##
The user alice has her password is in an environment variable. 

## ES ##
La password de alice esta en una variable de entorno.
```

密码在环境变量里面，

```shell
$ env    或 printenv
...
USER=elena
PASS=Cgecy2MY2MWbaqt
SHLVL=3
...
```

得到用户 `alice`的密码`Cgecy2MY2MWbaqt`

#### Mission 0x14
```plain
################
# MISSION 0x14 #
################

## EN ##
The admin has left the password of the user anna as a comment in the file passwd. 

## ES ##
El admin ha dejado la password de anna como comentario en el fichero passwd.
```

用户`anna`的密码在`/etc/passwd`的注释里面

```shell
$ cat /etc/passwd | grep alice
alice:x:1014:1014:w8NvY27qkpdePox:/pwned/alice:/bin/bash
```

这是 Linux 系统中 `/etc/passwd` 文件中的一行记录，用于存储系统用户的基本信息。该记录的字段由冒号 `:` 分隔，各字段的含义如下：

+ `alice`：用户名，表示该用户的登录名。
+ `x`：加密密码，通常会在 `/etc/shadow` 文件中存储加密后的密码信息，因为密码需要保密，所以 `/etc/passwd` 文件中会使用一个占位符（通常是 `x`）来代替真正的密码。
+ `1014`：用户 ID（UID），表示该用户在系统中的唯一标识符。每个用户都有一个 UID，可以用于区分不同的用户。
+ `1014`：组 ID（GID），表示该用户所属的用户组在系统中的唯一标识符。每个用户都属于一个或多个用户组，可以用于实现文件、目录等资源的访问控制。
+ `w8NvY27qkpdePox`：用户信息，通常包括用户的全名、电话号码、地址等信息。
+ `/pwned/alice`：用户主目录，表示该用户的默认工作目录。在登录时，系统会自动切换到该目录。
+ `/bin/bash`：shell 程序路径，表示该用户默认的 shell 程序。在登录时，系统会启动该程序，为该用户提供基于命令行的交互式界面。

需要注意的是，上述记录中的各字段并没有固定的位置和数量，而是由各个 Linux 发行版和系统版本决定。但是，它们的含义通常是相同的，可以根据需要进行解析。

德奥用户 `anna`的密码是`w8NvY27qkpdePox`

#### Mission 0x15
```plain
################
# MISSION 0x15 #
################
## EN ##
Maybe sudo can help you to be natalia.
## ES ##
Puede que sudo te ayude para ser natalia.
```

任务提示 `sudo`

```shell
$ sudo -l
Matching Defaults entries for anna on venus:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User anna may run the following commands on venus:
    (natalia) NOPASSWD: /bin/bash
```

+ `User anna may run the following commands on venus`说明用户`anna`可以执行`bash`命令
+ ` (natalia) NOPASSWD: /bin/bash`：用户natalia 在执行bash命令时无需密码

```shell
$ sudo -u natalia bash  跳转到natalia的bash,得到natalia的密码 NMuc4DkYKDsmZ5z
```

Tips：`-u <用户>`:以指定的用户作为新的身份。若不加上此参数，则预设以root作为新的身份；

#### Mission 0x16
```plain
################
# MISSION 0x16 #
################
## EN ##
The password of user eva is encoded in the base64.txt file
## ES ##
El password de eva esta encodeado en el fichero base64.txt
```

密码被base64加密了

```plain
$ cat base64.txt | base64 -d
upsCA3UFu10fDAO
```

得到 `eva`的密码 `upsCA3UFu10fDAO`

#### Mission 0x17
```shell
################
# MISSION 0x17 #
################

## EN ##
The password of the clara user is found in a file modified on May 1, 1968. 

## ES ##
La password de la usuaria clara se encuentra en un fichero modificado el 01 de Mayo de 1968.
```

任务提示最后被修改的时间，`find`命令有选项可以查看文件的相关时间，比如访问、修改等

```plain
$ $ find / -type f -mtime +19345 2>/dev/null   （2023-1970）*365=19345，时间戳最开始的时间是1970
/usr/lib/cmdo   # 查看即可得到 clara的密码  39YziWp5gSvgQN9
```

**根据文件时间戳进行搜索**

```shell
find . -type f 时间戳
```

Linux 每个文件都有三种时间戳

+ **访问时间** （-atime/天，-amin/分钟）：用户最近一次访问时间。
+ **修改时间** （-mtime/天，-mmin/分钟）：文件最后一次修改时间。
+ **变化时间** （-ctime/天，-cmin/分钟）：文件数据元（例如权限等）最后一次修改时间。

举个栗子：

```bash
##搜索最近七天内被访问过的所有文件
$ find . -type f -atime -7
## 恰好七天
$ find . -type f -atime 7
##超过七天
$ find . -type f -atime +7
```

切换得到flag和下一个Mission

#### Mission 0x18
```shell
################
# MISSION 0x18 #
################

## EN ##
The password of user frida is in the password-protected zip (rockyou.txt can help you) 

## ES ##
La password de frida esta en el zip protegido con password.(rockyou.txt puede ayudarte)
```

任务提示 frida的密码在被加密的压缩包里面，需要爆破

```shell
$ scp -P 5000 clara@venus.hackmyvm.eu:~/protected.zip .   // 把压缩包down到本地
$ zip2john protected.zip > Hash
$ john --wordlist=/home/kali/rockyou.txt Hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass123          (protected.zip/pwned/clara/protected.txt)     
1g 0:00:00:00 DONE (2023-06-02 21:17) 100.0g/s 819200p/s 819200c/s 819200C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
#得到密码解压得到 frida的密码 Ed4ErEUJEaMcXli
```

#### Mission 0x19
```shell
################
# MISSION 0x19 #
################

## EN ##
The password of eliza is the only string that is repeated (unsorted) in repeated.txt. 

## ES ##
La password de eliza es el unico string que se repite (sin estar ordenado) en repeated.txt.
```

任务提示 eliza的密码是唯一重复的字符串

```bash
$ uniq -d repeated.txt
Fg6b6aoksceQqB9
```

得到 eliza的密码 `Fg6b6aoksceQqB9`

#### Mission 0x20
```shell
################
# MISSION 0x20 #
################

## EN ##
The user iris has left me her key.

## ES ##
La usuaria iris me ha dejado su key.
```

任务提示 iris的key被 当前用户知道了。

```plain
$ find / -name "*iris*" -exec ls -l {} \; 2>/dev/null    #查看与iris相关的问价，发现了 .iris_key,很显然是ssh私钥
直接连接
$ ssh -i  .iris_key iris@localhost
连接成功，并且得到 iris 的密码 kYjyoLcnBZ9EJdz
```

#### Mission 0x21
```plain
################
# MISSION 0x21 #
################
## EN ##
User eloise has saved her password in a particular way. 
## ES ##
La usuaria eloise ha guardado su password de una forma particular.
```

一眼 Base64转图片（可以搜在线工具，也有很多离线工具）

```plain
$ scp -P 5000 iris@venus.hackmyvm.eu:~/eloise ./
```

base64解码保存为 .jpg ,得到 `eloise`的密码 `yOUJlV0SHOnbSPm`

#### Mission 0x22
```shell
################
# MISSION 0x22 #
################

## EN ##
User lucia has been creative in saving her password.

## ES ##
La usuaria lucia ha sido creativa en la forma de guardar su password.
```

根据提示可以得到，密码被某种方式编码了，CyberChef 一把嗦，可知是 hexdump

```plain
$ xxd -r hi
uvMwFDQrQWPMeGP   # 得到lucia的密码
```

#### Mission 0x23
```shell
################
# MISSION 0x23 #
################

## EN ##
The user isabel has left her password in a file in the /etc/xdg folder but she does not remember the name, however she has dict.txt that can help her to remember.

## ES ##
La usuaria isabel ha dejado su password en un fichero en la carpeta /etc/xdg pero no recuerda el nombre, sin embargo tiene dict.txt que puede ayudarle a recordar.
```

任务提示，密码文件在`/etc/xdg`文件夹下，但是我们没有权限全列出（ls）其下的文件列表，但提供了一个文件dict.txt，所以就只能爆破了。

```shell
$ stat /etc/xdg       // 查看一下文件夹权限
  File: /etc/xdg
  Size: 4096            Blocks: 8          IO Block: 4096   directory
Device: 28h/40d Inode: 272791      Links: 3
Access: (0661/drw-rw---x)  Uid: (    0/    root)   Gid: (    0/    root)

$ while IFS= read -r line; do readlink -e /etc/xdg/$line ; done < dict.txt
/etc/xdg
/etc/xdg/readme
$ cat /etc/xdg/readme
H5ol8Z2mrRsorC0     // 得到isabel的密码 H5ol8Z2mrRsorC0
```

dict.txt中有一个隐藏的的Flag

标准格式

```bash
IFS=
while read -r line
do
 readlink -e "/etc/xdg/$line"
done < dict.txt
```

+ 脚本细究
    - `IFS=` 是 Shell 脚本中的一种特殊变量，表示输入字段分隔符。当 `IFS` 变量为空时，Shell 将默认使用空格、制表符和换行符作为输入字段分隔符。也就是说，设置 `IFS=` 后，Shell 会将需要读取的内容以整行为单位读入。（目的是为了处理文件中包含特殊字符或空格的情况，但我测试的短文本加不加好像都一样）
    - 该脚本首先将 `dict.txt` 文件通过输入重定向 `<` 输入到循环中，然后逐行读取 `dict.txt` 中的记录，并将每一行的内容赋值给循环变量 `$line`。

然后，脚本使用 `readlink` 命令来输出指定文件的符号链接或子目录内容。其中 `-e` 选项表示展开符号链接，并将链接转换为其所指向的真实文件路径。命令中的 `/etc/xdg/$line` 表示由 `/etc/xdg/` 目录和当前循环变量 `$line` 组成的文件路径，用于确定需要获取符号链接的目标文件。

因此，整个脚本的作用是：逐行读取 `dict.txt` 文件中的内容，将每一行内容作为文件名参数传递给 `readlink` 命令，并输出符号链接对应的真实文件路径或子目录内容。该脚本可以用于查找指定目录下的文件或目录的符号链接，并输出它们所指向的真实路径或内容。

#### Mission 0x24
```shell
################
# MISSION 0x24 #
################

## EN ##
The password of the user freya is the only string that is not repeated in different.txt 

## ES ##
La password de la usuaria freya es el unico string que no se repite en different.txt
```

任务提示：freya的密码是唯一一个没有重复的字符串（和Mission 0x19 恰恰相反）

```shell
$ uniq -u differnt.txt
EEDyYFDwYsmYawj   //得到freya的密码 EEDyYFDwYsmYawj
```

#### Mission 0x25
```shell
################
# MISSION 0x25 #
################
## EN ##
User alexa puts her password in a .txt file in /free every minute and then deletes it. 
## ES ##
La usuaria alexa pone su password en un fichero .txt en la carpeta /free cada minuto y luego lo borra.
```

任务提示密码在 /free文件夹下，但每分钟都会被删除，想要手动打开的可能性应该不大，所以可以用脚本来实现

```plain
$ false; while [ $? -ne 0 ]; do cat /free/* ; done 2>/dev/null
mxq9O3MSxxX9Q3S   # 得到alexa的密码 mxq9O3MSxxX9Q3S
```

等价于：

```plain
while true; do
cat /free/* 2>/dev/null
if [ $? -eq 0 ]; then
  break
fi
done
```

Tips: Linux系统中 True 是 0；false 是 1；如果上一条命令执行失败，`$?`就等于 1（false）

#### Mission 0x26
```plain
################
# MISSION 0x26 #
################

## EN ##
The password of the user ariel is online! (HTTP)

## ES ##
El password de la usuaria ariel esta online! (HTTP)
```

密码是在线的

```plain
$ curl http://localhost
33EtHoz9a0w2Yqo   #得到ariel的密码 33EtHoz9a0w2Yqo
```

#### Mission 0x27
```plain
################
# MISSION 0x27 #
################

## EN ##
Seems that ariel don't save the password for lola, but there is a temporal file.

## ES ##
Parece ser que a ariel no le dio tiempo a guardar la password de lola... menosmal que hay un temporal!
```

任务提示没保存 lola 的密码。

```plain
$ ls -a
.  ..  .bash_logout  .bashrc  .goas.swp  .profile  flagz.txt  mission.txt
$ vim -r .goas.swp
   ...  删除掉 -->
:w /tmp/jzcheng.txt
:q!           # 将文件另存到 /tmp/jzcheng.txt 并退出
$ while IFS= read -r passwd;do echo $passwd | timeout 2 su lola 2>/dev/null;if [ $? -eq 0 ];then echo $passwd;break;fi;done < /tmp/jzcheng.txt
d3LieOzRGX5wud6
// 得到 lola 的密码 d3LieOzRGX5wud6
或者使用 hydra
$ hydra -l lola -P /tmp/jzcheng.txt ssh://venus.hackmyvm.eu:5000
```

#### Mission 0x28
```shell
################
# MISSION 0x28 #
################
## EN ##
The user celeste has left a list of names of possible .html pages where to find her password. 
## ES ##
La usuaria celeste ha dejado un listado de nombres de posibles paginas .html donde encontrar su password.
```

任务提示，密码藏在 html 的网页里面

```plain
创建一个 SSH 隧道（tunnel），将远程服务器 venus.hackmyvm.eu 上的 80 端口转发到本地计算机的 9001 端口。
$ ssh -L 9001:127.0.0.1:80 lola@venus.hackmyvm.eu -p 5000
然后再扫描目录
$ dirb http://127.0.0.1:9001/ ./pages.txt -X .html
或者 gobuster dir -w pages.txt -u http://127.0.0.1:9001 -x html
可以得到一个网页
http://127.0.0.1:9001/cebolla.html
$ curl http://127.0.0.1:9001/cebolla.html
VLSNMTKwSV2o8Tn   //得到了 celeste 的密码 VLSNMTKwSV2o8Tn
```

非预期 `find / -name "*.html" -path '/var/www*' 2>/dev/null`

#### Mission 0x29
```plain
################
# MISSION 0x29 #
################

## EN ##
The user celeste has access to mysql but for what?

## ES ##
La usuaria celeste tiene acceso al mysql, pero para que?
```

任务提示，数据库中存在着些什么

```plain
$ mysql -uceleste -pVLSNMTKwSV2o8Tn   //登录Mysql数据库
> show databases;
> use venus;
> show tables;
> select * from people where length(pazz)=15;        //根据之前的密码长度来做个过滤
+-----------+----------+-----------------+
| id_people | uzer     | pazz            |
+-----------+----------+-----------------+
|        16 | sfdfdsml | ixpeqdsfsdfdsfW |
|        44 | yuio     | ixpgbvcbvcbeqdW |
|        54 | crom     | ixpefdbvvcbrqdW |
|        58 | bael     | ixpesdvsdvsdqdW |
|        74 | nina     | ixpeqdWuvC5N9kG |
|        77 | dsar     | ixpeF43F3F34qdW |
|        78 | yop      | ixpeqdWCSDFDSFD |
|        79 | loco     | ixpeF43F34F3qdW |
+-----------+----------+-----------------+
```

发现在 `pwned`目录下发现 用户名 nina，因此可以得到 `nina`的密码 `ixpeqdWuvC5N9kG`

在数据库中还存在一个Hidden Flag； select * from people;

#### Mission 0x30
```plain
################
# MISSION 0x30 #
################

## EN ##
The user kira is hidding something in http://localhost/method.php

## ES ##
La usuaria kira esconde algo en http://localhost/method.php
```

任务提示，通过某种请求方法

```plain
$ curl -XGET http://localhost/method.php
I dont like this method!
$ curl -XPUT http://localhost/method.php
tPlqxSKuT4eP3yr   //得到 kira的密码 tPlqxSKuT4eP3yr
```

#### Mission 0x31
```plain
################
# MISSION 31 #
################

## EN ##
The user veronica visits a lot http://localhost/waiting.php

## ES ##
La usuaria veronica visita mucho http://localhost/waiting.php
```

任务提示

```plain
$ curl http://localhost/waiting.php
Im waiting for the user-agent PARADISE.   
使用 -A 选项来修改 user-agent 的值
$ curl -A PARADISE http://localhost/waiting.php
QTOel6BodTx2cwX   // 获得到 veronica的密码 QTOel6BodTx2cwX
```

#### Mission 0x32
```plain
################
# MISSION 0x32 #
################

## EN ##
The user veronica uses a lot the password from lana, so she created an alias.

## ES ##
La usuaria veronica usa mucho la password de lana, asi que ha creado un alias.
```

任务提示，lana的密码被设置成了别名

```plain
$ alias   
alias lanapass='UWbc0zNEVVops1v'   // 得到lana的密码 UWbc0zNEVVops1v
```

#### Mission 0x33
```plain
################
# MISSION 0x33 #
################

## EN ##
The user noa loves to compress her things.

## ES ##
A la usuaria noa le gusta comprimir sus cosas.
```

密码在压缩包里面

```plain
$ mkdir /tmp/jzcheng;
$ tar -xvf zip.gz -C /tmp/jzcheng 
$ cat ...           // 得到 noa 的密码 9WWOPoeJrq6ncvJ
> 非预期
$ cat zip.gz 
pwned/lana/zip0000644000000000000000000000002014223477016012327 0ustar  rootroot9WWOPoeJrq6ncvJ
```

#### Mission 0x34
```plain
################
# MISSION 0x34 #
################

## EN ##
The password of maia is surrounded by trash 

## ES ##
La password de maia esta rodeada de basura
```

任务提示密码在 trash 中

```plain
$ string trash
h1hnDPHpydEjoEN  //得到maia 的密码 h1hnDPHpydEjoEN
```

#### Mission 0x35
```plain
################
# MISSION 0x35 #
################

## EN ##
The user gloria has forgotten the last 2 characters of her password ... They only remember that they were 2 lowercase letters. 

## ES ##
La usuaria gloria ha olvidado los 2 ultimos caracteres de su password... Solo recuerdan que eran 2 letras minusculas.
```

任务提示密码的后两位是小写字母，

```python
from string import ascii_lowercase
f = open('pazz.txt', 'w+')
for i in ascii_lowercase:
    for j in ascii_lowercase:
        print(f"v7xUVE2e5bjUc{i}{j}", file=f)
```

hydra 超慢

```plain
$hydra -l gloria -P pazz.txt ssh://venus.hackmyvm.eu:5000
$ hydra -l gloria -P pazz.txt  -f venus.hackmyvm.eu -s 5000 ssh
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-10 00:36:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 676 login tries (l:1/p:676), ~43 tries per task
[DATA] attacking ssh://venus.hackmyvm.eu:5000/
[STATUS] 101.00 tries/min, 101 tries in 00:01h, 580 to do in 00:06h, 16 active
[STATUS] 89.00 tries/min, 267 tries in 00:03h, 414 to do in 00:05h, 16 active
[STATUS] 83.71 tries/min, 586 tries in 00:07h, 99 to do in 00:02h, 16 active
[5000][ssh] host: venus.hackmyvm.eu   login: gloria   password: v7xUVE2e5bjUcxw
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 14 final worker threads did not complete until end.
[ERROR] 14 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-10 00:43:55
```

获得 `gloria`的密码 `v7xUVE2e5bjUcxw`

#### Mission 0x36
```plain
################
# MISSION 0x36 #
################

## EN ##
User alora likes drawings, that's why she saved her password as ... 

## ES ##
A la usuaria alora le gustan los dibujos, por eso ha guardado su password como...
```

任务提示在密码在image文件中，cat查看一下像二维码，缩小，扫码得到alora的密码`mhrTFCoxGoqUxtw`

[image-20230614104921199](http://jzcheng.cn/archives/venus1.html)

#### Mission 0x37
```plain
################
# MISSION 0x37 #
################

## EN ##
User Julie has created an iso with her password.

## ES ##
La usuaria julie ha creado una iso con su password.
```

密码在 iso 镜像文件里

非预期直接 cat 查看

```plain
$ mkdir /tmp/music
$ sudo mount -o loop music.iso /tmp/music   //挂载到本地虚拟机
$ unzip /tmp/music/music.zip -d tmp
$ cat /tmp/pwned/a;ora/music.txt
sjDf4i2MSNgSvOv            -- 得到julie的密码 sjDf4i2MSNgSvOv
```

这个命令的作用是将 `music.iso` 挂载到 `/tmp/music/` 目录下。具体来说，`mount` 命令是用于挂载文件系统， `-o loop` 参数告诉它把文件作为循环设备（loop device）挂载，`music.iso` 则是要挂载的 ISO 镜像文件，最后的 `/tmp/music/` 是指挂载点（mount point），即将镜像文件挂载到哪个目录下面。执行这条命令后，在 `/tmp/music/` 目录下就可以访问 `music.iso` 镜像中的文件了。

#### Mission 0x38
```plain
################
# MISSION 0x38 #
################

## EN ##
The user irene believes that the beauty is in the difference.

## ES ##
La usuaria irene cree que en la diferencia esta lo bonito.
```

根据任务提示可以知道，密码应该是两个文件的差异部分

```plain
$ diff 1.txt 2.txt
174c174
< 8VeRLEFkBpe2DSD
---
> aNHRdohjOiNizlU
```

经过尝试得到 `irene`的密码`8VeRLEFkBpe2DSD`

#### Mission 0x39
```plain
################
# MISSION 0x39 #
################

## EN ##
The user adela has lent her password to irene.

## ES ##
La usuaria adela le ha dejado prestada su password a irene.
```

查看有三个文件 `id_rsa.pem、id_rsa.pub、pass.enc`

1. `id_rsa.pem`：一个私钥文件，可能用于 SSH 认证等操作。通常情况下，私钥文件需要严格保密。
2. `id_rsa.pub`：与 `id_rsa.pem` 配对的公钥文件，可用于验证使用相应私钥签名的数据或者对数据进行加密。
3. `pass.enc`：一个加密文件，可能包含密码、私钥或其他敏感信息。该文件使用某种加密算法进行了加密处理，需要使用正确的秘钥或密码进行解密才能读取其中的内容。

```plain
$ openssl rsautl -decrypt -inkey id_rsa.pem -in pass.enc
nbhlQyKuaXGojHx    --得到 adela的密码 nbhlQyKuaXGojHx
```

`openssl rsautl` 是 OpenSSL 命令行工具中使用 RSA 算法进行加解密操作的命令

`-decrypt`选项 是解密

`-inkey id_rsa.pem` 表示指定使用 `id_rsa.pem` 文件中的私钥进行解密操作

`-in pass.enc` 表示要解密的输入文件是 `pass.enc`.

#### Mission 0x40
```plain
################
# MISSION 0x40 #
################

## EN ##
User sky has saved her password to something that can be listened to.

## ES ##
La usuaria sky ha guardado su password en algo que puede ser escuchado.
```

文件`wtf`的内容被莫斯电码加密了

```plain
.--. .- .--. .- .--. .- .-. .- -.. .. ... .
解密 PAPAPARADISE （要转换成小写papaparadise就是sky的密码）
```

#### Mission 0x41
```plain
################
# MISSION 0x41 #
################

## EN ##
User sarah uses header in http://localhost/key.php

## ES ##
La usuaria sarah utiliza header para http://localhost/key.php
```

密码在网页 key.php里面

```plain
$ curl http://localhost/key.php
Key header is true?
$ curl -H "key:true" http://localhost/key.php
LWOHeRgmIxg7fuS       -- 得到 sarah的密码 LWOHeRgmIxg7fuS
```

#### Mission 0x42
```plain
################
# MISSION 0x42 #
################

## EN ##
The password of mercy is hidden in this directory.

## ES ##
La password de mercy esta oculta en este directorio.
```

密码文件隐藏在当前目录下

```plain
$ ls -a  发现可疑文件 ...
$ cat ./...
ym5yyXZ163uIS8L       --得到mercy的密码 ym5yyXZ163uIS8L
```

#### Mission 0x43
```plain
################
# MISSION 0x43 #
################

## EN ##
User mercy is always wrong with the password of paula. 

## ES ##
La usuaria mercy siempre se equivoca con la password de paula.
```

查看 mercy 的历史指令

```plain
$ cat .bash_history
得到 paula的密码 dlHZ6cvX6cLuL8p
```

#### Mission 0x44
```plain
################
# MISSION 0x44 #
################

## EN ##
The user karla trusts me, she is part of my group of friends. 

## ES ##
La usuaria karla confia en mi, es parte de mi grupo de amigos.
```

查看 karla的组

```plain
$ id
uid=1044(paula) gid=1044(paula) groups=1044(paula),1053(hidden)   --hidden组
$ find / -group hidden -type f -exec cat {} \; 2>/dev/null
gYAmvWY3I7yDKRf     -- 得到karla的密码
```

#### Mission 0x45
```plain
################
# MISSION 0x45 #
################

## EN ##
User denise has saved her password in the image.

## ES ##
La usuaria denise ha guardado su password en la imagen.
```

密码隐藏在 图片里

```plain
$ exiftool yuju.jpg
About  : pFg92DpGucMWccA  -- 得到denise的密码 pFg92DpGucMWccA
```

#### Mission 0x46
```plain
################
# MISSION 0x46 #
################

## EN ##
The user zora is screaming doas!

## ES ##
La usuaria zora no deja de gritar doas!
```

通过搜索可以知道 **Doas是一个开源软件，简化的Unix命令授权系统**

```plain
$ find / -name doas 2>/dev/null
/usr/share/lintian/overrides/doas
/usr/share/doc/doas
/usr/bin/doas
/etc/pam.d/doas
```

有一个可执行的二进制文件 `doas -u zora bash`后输入denise的密码 `pFg92DpGucMWccA`

成功登录到 zora的 shell，得到其密码 `BWm1R3jCcb53riO`

#### Mission 0x47
```plain
################
# MISSION 0x47 #
################

## EN ##
The user belen has left her password in venus.hmv

## ES ##
La usuaria belen ha dejado su password en venus.hmv
```

密码在 网页`venus.hmv`

```plain
$ curl venus.hmv
得到用户belen的密码2jA0E8bQ4WrGwWZ
```

#### Misson 0x48
```plain
################
# MISSION 0x48 #
################

## EN ##
It seems that belen has stolen the password of the user leona...

## ES ##
Parece que belen ha robado el password de la usuaria leona..
```

密码在 stolen.txt

```plain
$ cat stolen.txt
$1$leona$lhWp56YnWAMz6z32Bw53L0
$ hashid '$1$leona$lhWp56YnWAMz6z32Bw53L0'
Analyzing '$1$leona$lhWp56YnWAMz6z32Bw53L0'
[+] MD5 Crypt 
[+] Cisco-IOS(MD5) 
[+] FreeBSD MD5   //是哈希MD5
使用john爆破
$ echo '$1$leona$lhWp56YnWAMz6z32Bw53L0'>hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
得到 leona的密码 freedom
```

#### Mission 0x49
```plain
################
# MISSION 0x49 #
################

## EN ##
User ava plays a lot with the DNS of venus.hmv lately... 

## ES ##
La usuaria ava juega mucho con el DNS de venus.hmv ultimamente...
```

与DNS记录有关

```plain
nslook和dig都没发现有用的详细
$ ls /etc/bind
$ cat /etc/bind/db.venus.hmv 
在TXT记录里面发现 ava的密码 oCXBeeEeYFX34NU
```

#### Mission 0x50
```plain
################
# MISSION 0x50 #
################

## EN ##
The password of maria is somewhere...

## ES ##
El password de maria esta en algun lugar...
```

试了好半天，万万没想到maria的密码是 `.--. .- .--. .- .--. .- .-. .- -.. .. ... .`

#### Last Mission
```plain
################
# MISSION 0x51 #
################

## EN ##
Congrats!

## ES ##
Felicidades :)
```

