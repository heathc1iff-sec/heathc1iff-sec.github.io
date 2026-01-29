---
title: OSEP-前置知识-Windows架构概述
description: '00-前置知识 | 03-Windows架构概述'
pubDate: 2026-01-29
image: /image/fengmian/OSEP.png
categories:
  - Documentation
  - OffSec
tags:
  - PEN-300-OSEP
  - Windows Learning
---
# Windows 架构概述 - 写给 Web 安全人员
## 为什么需要了解 Windows 架构？
作为 Web 安全人员，你可能习惯了：

+ 浏览器 → Web 服务器 → 数据库 这样的架构
+ HTTP 请求/响应模型
+ 应用层的漏洞利用

但在 OSEP 中，你需要理解：

+ 进程如何运行
+ 内存如何管理
+ 权限如何控制
+ 系统调用如何工作

---

## 一、Windows 架构总览
### 1.1 用户模式 vs 内核模式
```plain
+------------------------------------------------------------------+
|                        用户模式 (User Mode)                        |
|  +------------+  +------------+  +------------+  +------------+   |
|  | 应用程序1  |  | 应用程序2  |  | 服务程序   |  | 子系统DLL  |   |
|  +------------+  +------------+  +------------+  +------------+   |
|                              ↓                                    |
|  +----------------------------------------------------------+    |
|  |                    NTDLL.DLL (系统调用接口)                |    |
|  +----------------------------------------------------------+    |
+------------------------------------------------------------------+
                               ↓ 系统调用 (syscall)
+------------------------------------------------------------------+
|                        内核模式 (Kernel Mode)                      |
|  +----------------------------------------------------------+    |
|  |                    NTOSKRNL.EXE (内核)                    |    |
|  |  +----------+  +----------+  +----------+  +----------+  |    |
|  |  | 进程管理 |  | 内存管理 |  | I/O管理  |  | 安全管理 |  |    |
|  |  +----------+  +----------+  +----------+  +----------+  |    |
|  +----------------------------------------------------------+    |
|  +----------------------------------------------------------+    |
|  |                    HAL (硬件抽象层)                        |    |
|  +----------------------------------------------------------+    |
+------------------------------------------------------------------+
                               ↓
+------------------------------------------------------------------+
|                           硬件                                    |
+------------------------------------------------------------------+
```

### 1.2 关键概念
| 概念 | 说明 | 类比 Web |
| --- | --- | --- |
| 用户模式 | 应用程序运行的环境，权限受限 | 前端 JavaScript |
| 内核模式 | 操作系统核心，完全权限 | 后端服务器 |
| 系统调用 | 用户模式请求内核服务 | API 请求 |
| Ring 0 | 内核模式的特权级别 | root 权限 |
| Ring 3 | 用户模式的特权级别 | 普通用户权限 |


---

## 二、进程与线程
### 2.1 什么是进程？
**进程**是程序的运行实例，包含：

+ 私有的虚拟地址空间
+ 可执行代码
+ 打开的句柄
+ 安全上下文
+ 至少一个执行线程

```plain
进程结构：
+----------------------------------+
|           进程 (Process)          |
|  +----------------------------+  |
|  |     虚拟地址空间            |  |
|  |  +--------+  +--------+   |  |
|  |  | 代码段 |  | 数据段 |   |  |
|  |  +--------+  +--------+   |  |
|  |  +--------+  +--------+   |  |
|  |  |   堆   |  |   栈   |   |  |
|  |  +--------+  +--------+   |  |
|  +----------------------------+  |
|  +----------------------------+  |
|  |     线程1    |    线程2    |  |
|  +----------------------------+  |
|  +----------------------------+  |
|  |     句柄表 (Handle Table)  |  |
|  +----------------------------+  |
|  +----------------------------+  |
|  |     安全令牌 (Token)       |  |
|  +----------------------------+  |
+----------------------------------+
```

### 2.2 什么是线程？
**线程**是进程中的执行单元，包含：

+ 自己的栈
+ CPU 寄存器状态
+ 线程本地存储 (TLS)

```c
// 创建新线程
HANDLE hThread = CreateThread(
    NULL,                   // 安全属性
    0,                      // 栈大小 (0 = 默认)
    ThreadFunction,         // 线程函数
    lpParameter,            // 传递给线程的参数
    0,                      // 创建标志
    &dwThreadId             // 接收线程 ID
);
```

### 2.3 进程与线程的关系
| 特性 | 进程 | 线程 |
| --- | --- | --- |
| 地址空间 | 独立 | 共享所属进程的地址空间 |
| 资源 | 独立 | 共享进程资源 |
| 创建开销 | 大 | 小 |
| 通信 | 需要 IPC | 直接共享内存 |
| 崩溃影响 | 只影响自己 | 可能影响整个进程 |


#### IPC 一般指 Inter-Process Communication（进程间通信）。  
##### 常见 IPC 方式（偏系统 / 开发方向）
在操作系统、C/C++、Linux、Windows 里最常见：

1. **管道（Pipe）**
    - 匿名管道 / 命名管道（FIFO）
    - 父子进程通信很常见
    - `|`、`mkfifo`
2. **共享内存（Shared Memory）**
    - 多个进程直接访问同一块内存
    - 速度最快，但需要 **同步机制**
    - 常配合 **信号量 / Mutex**
3. **消息队列（Message Queue）**
    - 内核维护队列，进程发消息、收消息
    - 解耦好，但比共享内存慢
4. **信号（Signal）**
    - 用来通知事件（如 `SIGKILL`、`SIGSEGV`）
    - 不能传复杂数据
5. **Socket（本地 / 网络）**
    - 不只网络，**本地进程也能用**
    - Docker、微服务常用

---

##### Windows 里的 IPC
如果你在看 Windows 内核 / 漏洞 / 提权，常见的 IPC：

+ **Named Pipe（命名管道）**
+ **ALPC / LPC（高级本地过程调用）**
+ **共享内存 + Mutex**
+ **COM / RPC**

很多 **Windows 提权漏洞**、**服务通信** 都是 IPC 设计不当造成的 👀

---

## 三、Windows 内存管理
### 3.1 虚拟内存
每个进程都有自己的**虚拟地址空间**：

```plain
32位进程虚拟地址空间 (4GB):
+------------------+ 0xFFFFFFFF
|   内核空间 (2GB) |  <- 用户模式不可访问
+------------------+ 0x80000000
|                  |
|   用户空间 (2GB) |  <- 应用程序使用
|                  |
+------------------+ 0x00000000

64位进程虚拟地址空间:
用户空间: 0x0000000000000000 - 0x00007FFFFFFFFFFF (128TB)
内核空间: 0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF (128TB)
```

#### 在 32 位架构下，单个进程“可寻址的虚拟地址空间”上限是 4GB
##### 1️⃣ 为什么是 4GB？
**32 位地址 ⇒ 2³² 个地址：**

```plain
2^32 = 4,294,967,296 ≈ 4GB
```

**所以：**

**32 位进程，理论上的虚拟地址空间上限 = 4GB**

**注意关键词：****虚拟地址空间****，不是物理内存。**

---

##### 2️⃣ 但进程 ≠ 能用满 4GB
**操作系统会把这 4GB ****切成两半****（或不等分）：**

###### 🔹 常见划分（默认）
| **区域** | **大小** | **用途** |
| --- | --- | --- |
| **用户空间** | **2GB** | **进程自己的代码/堆/栈** |
| **内核空间** | **2GB** | **OS 内核、驱动** |


👉** ****普通 32 位进程：最多只能用 2GB**

---

##### 3️⃣ 能不能用到 3GB / 4GB？
**可以，但有条件。**

###### ✅ Windows（32 位）
+ **默认：**`**2GB 用户 + 2GB 内核**`
+ **可选：**
    - **/3GB 启动参数**
    - **程序 ****必须**** 标记为 **`**LARGEADDRESSAWARE**`

**结果：**

```plain
用户空间最多 = 3GB
```

⚠️** 内核只剩 1GB，驱动兼容性可能炸**

---

###### ✅ Linux（32 位）
**常见配置：**

+ `**3GB 用户 + 1GB 内核**`
+ **或 **`**2G/2G**`
+ **或 **`**1G/3G**`

**由内核编译选项决定（**`**CONFIG_VMSPLIT_***`**）**

#### 0xFFFFFFFF
##### 1️⃣ 作为 32 位无符号整数
```plain
0xFFFFFFFF = 4294967295
```

+ 32 位能表示的 **最大值**
+ 常见于：
    - 长度 / 大小错误
    - 溢出边界
    - 返回值表示失败

---

##### 2️⃣ 作为 32 位有符号整数
```plain
0xFFFFFFFF = -1
```

因为二进制补码表示法：

```plain
11111111 11111111 11111111 11111111
```

👉 **这是最常见用法**

常见含义：

+ **失败**
+ **错误**
+ **无效值**

例如：

```plain
return -1;
```

---

##### 3️⃣ 在 Windows / C / 系统编程中
非常高频 👇

###### ❌ 失败返回值
```plain
INVALID_HANDLE_VALUE == (HANDLE)0xFFFFFFFF
```

###### ❌ API 调用失败
```plain
if (ret == 0xFFFFFFFF) {
    // error
}
```

###### ❌ 未初始化 / 非法状态
```plain
DWORD pid = 0xFFFFFFFF;
```

---

##### 4️⃣ 在内存 / 漏洞 / 利用里
如果你在 **调试 / 漏洞利用 / OSEP / CTF** 里看到它，常见含义：

+ **填充数据（filler）**
+ **非法索引**
+ **数组越界触发**
+ **sign conversion bug**
+ **长度计算溢出**

例如：

```plain
size = user_input;   // -1
malloc(size);        // 实际变成 0xFFFFFFFF
```

👉 经典漏洞触发点 💥

### 3.2 内存页面保护
| 保护属性 | 值 | 说明 |
| --- | --- | --- |
| PAGE_NOACCESS | 0x01 | 不可访问 |
| PAGE_READONLY | 0x02 | 只读 |
| PAGE_READWRITE | 0x04 | 可读写 |
| PAGE_EXECUTE | 0x10 | 可执行 |
| PAGE_EXECUTE_READ | 0x20 | 可执行可读 |
| PAGE_EXECUTE_READWRITE | 0x40 | 可执行可读写 |


**OSEP 重点**：执行 shellcode 需要 `PAGE_EXECUTE_READWRITE` 权限！

### 3.3 内存分配 API
```c
// VirtualAlloc - 分配虚拟内存
LPVOID VirtualAlloc(
    LPVOID lpAddress,        // 起始地址 (NULL = 系统决定)
    SIZE_T dwSize,           // 大小
    DWORD  flAllocationType, // MEM_COMMIT, MEM_RESERVE
    DWORD  flProtect         // 保护属性 （对应3.2内存页面保护值）
);

// VirtualAllocEx - 在其他进程分配内存 (进程注入用)
LPVOID VirtualAllocEx(
    HANDLE hProcess,         // 目标进程句柄
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

// VirtualProtect - 修改内存保护属性
BOOL VirtualProtect(
    LPVOID lpAddress,        // 内存地址
    SIZE_T dwSize,           // 大小
    DWORD  flNewProtect,     // 新保护属性
    PDWORD lpflOldProtect    // 接收旧保护属性
);
```

---

## 四、Windows 安全模型
### 4.1 安全标识符 (SID)
**SID** 是用户、组、计算机的唯一标识符。

```plain
SID 格式: S-R-I-S-S-S...
S: 字面量 "S"
R: 修订级别 (通常为 1)
I: 标识符颁发机构
S: 子颁发机构值

常见 SID:
S-1-5-18          SYSTEM (最高权限)
S-1-5-19          LOCAL SERVICE
S-1-5-20          NETWORK SERVICE
S-1-5-32-544      Administrators 组
S-1-5-32-545      Users 组
S-1-5-21-xxx-500  域管理员
S-1-5-21-xxx-501  域来宾
```

### 4.2 访问令牌 (Access Token)
每个进程都有一个**访问令牌**，包含：

+ 用户 SID
+ 组 SID 列表
+ 特权列表
+ 完整性级别

```c
// 获取当前进程令牌
HANDLE hToken;  //声明令牌句柄  内核对象句柄将指向 当前进程的 Access Token
OpenProcessToken(
    GetCurrentProcess(),  //返回当前进程的伪句柄,不是真实内核句柄，但 API 能识别
    TOKEN_ALL_ACCESS,
/*表示你要对 Token 做什么操作：
包括：
TOKEN_QUERY（查询信息）
TOKEN_ADJUST_PRIVILEGES（启用/禁用权限）
TOKEN_DUPLICATE（复制令牌）
TOKEN_ASSIGN_PRIMARY（给新进程用）
如果进程权限不够（比如普通用户），这里可能失败。*/
    &hToken
//输出参数  成功后，hToken 就是 Token 句柄
);

// 查看令牌信息
GetTokenInformation(
    hToken,  //上一步拿到的 Token
    TokenUser,     //这里是你想查的“信息类型(当前用户 SID)  
// 或 TokenGroups(所属用户组), TokenPrivileges(拥有哪些权限)等等
    pTokenInfo, //输出缓冲区,类型取决于 TokenInformationClass
    dwSize,//pTokenInfo 的大小 如果太小 → API 失败
    &dwReturnLength  // 实际需要/返回的数据大小 常见用法是 先调用一次拿大小，再分配内存
);
```

 Windows API 全靠：文档 + 头文件 + 搜索路径。  

**代码用于获取当前进程的访问令牌（Access Token），并查询这个令牌里包含的安全信息（用户、组、权限等）。**

这里咱们先去搜OpenProcessToken这个api接口

[OpenProcessToken 函数 (processthreadsapi.h) - Win32 apps](https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)

![](/image/00-%E5%89%8D%E7%BD%AE%E7%9F%A5%E8%AF%86/03-Windows%E6%9E%B6%E6%9E%84%E6%A6%82%E8%BF%B0-1.png)

养成查官方api接口的好习惯

也可以通过看头文件

```c
// winbase.h / securitybaseapi.h
BOOL WINAPI OpenProcessToken(...);
```

```c
typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    ...
} TOKEN_INFORMATION_CLASS;
```

在 **VS / CLion / IDA** 里：

+ `Ctrl + 左键` 跳定义
+ `Go to Definition`

### 4.3 完整性级别 (Integrity Level)
Windows Vista 引入的强制访问控制：

| 级别 | 值 | 说明 |
| --- | --- | --- |
| Untrusted | 0x0000 | 最低，几乎无权限 |
| Low | 0x1000 | 沙箱进程 (如浏览器标签) |
| Medium | 0x2000 | 普通用户进程 |
| High | 0x3000 | 管理员进程 |
| System | 0x4000 | 系统服务 |


**规则**：低完整性进程不能写入高完整性对象。

### 4.4 用户账户控制 (UAC)
```plain
UAC 工作流程:

用户双击程序 → 需要管理员权限?
                    ↓
              +-----+-----+
              |           |
              否          是
              ↓           ↓
         正常启动    弹出 UAC 提示
         (Medium)        ↓
                   +-----+-----+
                   |           |
                  允许        拒绝
                   ↓           ↓
              以 High 启动  启动失败
```

---

#### 一、UAC 到底解决什么问题？
在 **Vista 之前**：

+ 只要你是管理员登录
+ 程序一启动就是 **管理员权限**
+ 病毒 = 爽到飞起 🦠

👉 **UAC 的目标**：  
**“管理员用户 ≠ 管理员权限进程”**

---

#### 二、UAC 的核心机制（非常重要）
当你用**管理员账号**登录时，Windows **不会只给你一个 Token**，而是：

##### 🔑 给你两个 Token
| Token 类型 | 权限 |
| --- | --- |
| **Filtered Token（受限）** | 普通用户权限 |
| **Elevated Token（提升）** | 完整管理员权限 |


默认情况下：

**所有程序都用「受限 Token」运行**

---

#### 三、点“是”的瞬间发生了什么？
当你看到这个弹窗 👇

“你要允许此应用对你的设备进行更改吗？”

实际上是：

1. 当前进程：**Filtered Token**
2. UAC 弹窗出现
3. 你点「是」
4. 系统用 **Elevated Token** 重新创建进程

⚠️ **不是“权限升级”，而是“换了一个 Token”**

---

#### 四、为什么这对安全 / 提权特别重要？
因为这就直接引出了几个**关键概念**：

##### 1️⃣ 管理员 ≠ 高权限
```plain
用户是 Administrators
≠
进程是 High Integrity
```

---

##### 2️⃣ 完整性级别（Integrity Level）
Token 里还有一个东西叫 **Integrity Level**：

| 级别 | 含义 |
| --- | --- |
| Low | 沙箱 / IE |
| Medium | 普通程序 |
| High | 管理员提升后 |
| System | SYSTEM |


👉 **UAC 控制的就是 Medium → High**

---

##### 3️⃣ UAC Bypass 为什么存在？
因为：

+ 有些系统组件 **被信任**
+ 它们可以 **自动拿 Elevated Token**
+ 不弹窗 ❌

这就成了：

**UAC Bypass ≠ 提权到管理员  
****而是“无弹窗拿管理员 Token”**

## 五、Windows API 层次
### 5.1 API 调用链
```plain
应用程序代码
      ↓
+------------------+
| Windows API      |  <- kernel32.dll, user32.dll, advapi32.dll
| (文档化的 API)   |     CreateFile, MessageBox, RegOpenKey
+------------------+
      ↓
+------------------+
| Native API       |  <- ntdll.dll
| (部分文档化)     |     NtCreateFile, NtOpenKey
+------------------+
      ↓
+------------------+
| System Call      |  <- syscall 指令
| (内核入口)       |
+------------------+
      ↓
+------------------+
| Kernel           |  <- ntoskrnl.exe
| (内核实现)       |
+------------------+
```

### 5.2 常用 Windows API
#### 进程操作
```c
// 创建进程
BOOL CreateProcessA(
    LPCSTR lpApplicationName,      // 程序路径
    LPSTR lpCommandLine,           // 命令行
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,          // 是否继承句柄
    DWORD dwCreationFlags,         // 创建标志
    LPVOID lpEnvironment,          // 环境变量
    LPCSTR lpCurrentDirectory,     // 工作目录
    LPSTARTUPINFOA lpStartupInfo,  // 启动信息
    LPPROCESS_INFORMATION lpProcessInformation  // 进程信息
);

// 打开进程
HANDLE OpenProcess(
    DWORD dwDesiredAccess,         // 访问权限
    BOOL bInheritHandle,           // 是否可继承
    DWORD dwProcessId              // 进程 ID
);

// 终止进程
BOOL TerminateProcess(
    HANDLE hProcess,               // 进程句柄
    UINT uExitCode                 // 退出码
);
```

#### 内存操作
```c
// 读取进程内存
BOOL ReadProcessMemory(
    HANDLE hProcess,               // 进程句柄
    LPCVOID lpBaseAddress,         // 源地址
    LPVOID lpBuffer,               // 目标缓冲区
    SIZE_T nSize,                  // 大小
    SIZE_T *lpNumberOfBytesRead    // 实际读取字节数
);

// 写入进程内存
BOOL WriteProcessMemory(
    HANDLE hProcess,               // 进程句柄
    LPVOID lpBaseAddress,          // 目标地址
    LPCVOID lpBuffer,              // 源缓冲区
    SIZE_T nSize,                  // 大小
    SIZE_T *lpNumberOfBytesWritten // 实际写入字节数
);
```

#### 线程操作
```c
// 创建远程线程 (进程注入核心 API)
HANDLE CreateRemoteThread(
    HANDLE hProcess,               // 目标进程句柄
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,            // 栈大小
    LPTHREAD_START_ROUTINE lpStartAddress,  // 线程函数地址
    LPVOID lpParameter,            // 参数
    DWORD dwCreationFlags,         // 创建标志
    LPDWORD lpThreadId             // 线程 ID
);
```

`CreateRemoteThread` 是一个允许在指定进程中创建并启动线程的内核接口，其安全边界完全由进程权限、令牌和完整性级别决定。  

#### 动态链接库
```c
// 加载 DLL
HMODULE LoadLibraryA(
    LPCSTR lpLibFileName           // DLL 路径
);

// 获取函数地址
FARPROC GetProcAddress(
    HMODULE hModule,               // 模块句柄
    LPCSTR lpProcName              // 函数名
);

// 释放 DLL
BOOL FreeLibrary(
    HMODULE hLibModule             // 模块句柄
);
```

---

## 六、PEB 和 TEB
### 6.1 TEB (Thread Environment Block)
每个线程都有一个 TEB，存储线程相关信息。

```c
// 通过 FS/GS 段寄存器访问
// x86: FS:[0x00] 指向 TEB
// x64: GS:[0x00] 指向 TEB

// TEB 重要字段
typedef struct _TEB {
    NT_TIB NtTib;                  // 0x00: 线程信息块
    PVOID EnvironmentPointer;      // 0x1C/0x38
    CLIENT_ID ClientId;            // 0x20/0x40: 进程ID和线程ID
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;  // 0x30/0x60: 指向 PEB !!!
    // ...
} TEB, *PTEB;
```

#### 一、TEB 是什么？一句话
**TEB（Thread Environment Block）是“每个线程私有的用户态结构体”，保存线程自身的关键信息。**

**关键词：**

+ **每线程一份**
+ **用户态可访问**
+ **由内核创建，用户态读取**

---

#### 二、为什么要用 FS / GS 段寄存器？
**这是****历史 + 性能 + ABI 设计****的结果。**

##### x86（32 位）
```plain
FS:[0x00] → TEB
```

##### x64（64 位）
```plain
GS:[0x00] → TEB
```

**原因核心就三点：**

1. **访问极快**
    - **一条指令就能拿到当前线程上下文**
2. **不需要全局变量**
    - **多线程安全，天然 TLS**
3. **ABI 固定**
    - **编译器 / 系统组件都约定俗成**

👉** 所以你会看到：**

+ **编译器**
+ **ntdll**
+ **loader**
+ **CRT  
****全都默认：****“FS/GS 里一定能拿到 TEB”**

---

#### 三、TEB 和 NT_TIB 的关系
```plain
// NT Thread Information Block (NT_TIB)
// 位于 TEB 的起始位置（TEB == NT_TIB 起始）
// x86: FS:[0x00]  -> NT_TIB / TEB
// x64: GS:[0x00]  -> NT_TIB / TEB
// 保存每个线程最底层、最关键的运行时信息
typedef struct _NT_TIB {
    PVOID ExceptionList;
    // 指向当前线程的 SEH（结构化异常处理）链表头
    // x86 下为异常处理记录链
    // 用于异常分发、栈展开、调试与反调试
    // 早期 SEH 覆盖漏洞与该字段直接相关

    PVOID StackBase;
    // 线程栈的高地址（栈顶）
    // Windows 栈从高地址向低地址增长
    // 用于栈溢出检测、异常处理和调试器栈回溯

    PVOID StackLimit;
    // 线程栈的低地址（栈底）
    // 低于该地址会触发栈溢出异常
    // 通常与 Guard Page 机制配合使用

    PVOID SubSystemTib;
    // 子系统相关的 TIB 指针
    // 早期为 POSIX / OS2 子系统预留
    // 现代 Windows 中基本未使用，通常为 NULL

    PVOID FiberData;
    // Fiber（纤程）相关数据指针
    // 当线程被转换为 Fiber 时，指向当前 Fiber 的上下文
    // 普通线程下通常为 NULL

    PVOID ArbitraryUserPointer;
    // 用户自定义指针槽
    // 系统不解析该字段，完全由用户态程序使用
    // 可通过 NtSetInformationThread 设置
    // 常用于线程上下文绑定或调试标记

    struct _NT_TIB *Self;
    // 指向自身的 NT_TIB 结构
    // Self == NT_TIB 的起始地址
    // 用于快速校验结构完整性或反向确认 TEB 基址

} NT_TIB;

```

 NT_TIB（NT Thread Information Block）是 TEB 的开头部分，保存“线程最底层、最关键”的运行信息。  

📌** ****NT_TIB 是 TEB 的第一个成员**

+ **所以：**

```plain
TEB 地址 == NT_TIB 地址
```

**这也是为什么：**

```plain
FS:[0x00] / GS:[0x00]
```

**能直接当作 ****TIB / TEB**** 用。**

---

#### 四、你标出来的这些字段在干嘛（重点）
##### 1️⃣ `NtTib`（0x00）
+ **线程异常链**
+ **栈基址 / 栈限制**
+ **SEH（结构化异常）核心**

👉** 异常、调试、反调试全靠它**

---

##### 2️⃣ `CLIENT_ID ClientId`
```plain
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;  // 实际上就是 PID
    HANDLE UniqueThread;   // 实际上就是 TID
} CLIENT_ID;
```

+ **当前线程的 PID / TID**
+ **不用 API，直接读内存就能拿**

👉** 很多 shellcode / loader 就靠这个（ 无 API / 稳定 / 隐蔽 / 直接能拿当前进程 ID 和线程 ID   ）**

---

##### 3️⃣ `ThreadLocalStoragePointer`
+ **TLS（线程本地存储）**
+ `**__declspec(thread)**`** 背后的东西**

👉** 编译器级别支持**

---

##### 4️⃣ ⭐ `PPEB ProcessEnvironmentBlock`
```plain
x86: offset 0x30
x64: offset 0x60
```

`0x30`（x86）和 `0x60`（x64）是 `TEB` 中 `ProcessEnvironmentBlock (PEB)` 字段的偏移，差异完全来自 32 位 vs 64 位指针大小和结构体对齐。  

🔥** 这是重中之重**

** 它们都指向同一件事：  **

`**TEB->ProcessEnvironmentBlock**`

**TEB → PEB → 模块 / 参数 / 加载器 / 堆**

**也就是说：**

```plain
FS/GS → TEB → PEB
```

👉** 不用任何 WinAPI，就能拿到：**

+ **模块基址**
+ **命令行**
+ **当前路径**
+ **Loader 数据**

---

#### 五、为什么偏偏 x86 和 x64 偏移不一样？
**因为：**

+ **指针大小不同**
+ **结构体自然对齐**
+ **Microsoft ****保证语义，不保证偏移一致**

**但有一点是****铁律****：**

**TEB → PEB 的“相对位置是固定的”**

**所以你看到大量代码写成：**

```plain
x86: fs:[0x30]
x64: gs:[0x60]
```

---

#### 六、这玩意为什么在逆向 / 安全里这么重要？
**因为它意味着：**

##### ❌ 不需要 API
+ **不触发 Hook**
+ **不进内核**
+ **不走 IAT**

##### ✅ 直接从 CPU 级别拿上下文
+ **Loader**
+ **Malware**
+ **Shellcode**
+ **反调试**

👉** 所以你会在 IDA / Ghidra 里经常看到：**

```plain
mov eax, fs:[0x30]
mov rax, gs:[0x60]
```

**那不是“魔法”，那是 ****PEB 链****。**

---

#### 七、一个“层级关系图”（非常关键）
```plain
CPU
 └─ FS / GS
     └─ TEB（线程）
         ├─ TIB / 栈 / SEH
         ├─ ClientId
         └─ PEB（进程）
             ├─ Ldr
             ├─ ProcessParameters
             └─ Heap
```

---

### 6.2 PEB (Process Environment Block)
每个进程都有一个 PEB，存储进程相关信息。

```c
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;      // 0x00
    BOOLEAN ReadImageFileExecOptions;   // 0x01
    BOOLEAN BeingDebugged;              // 0x02: 调试标志 !!!
    BOOLEAN SpareBool;                  // 0x03
    HANDLE Mutant;                      // 0x04
    PVOID ImageBaseAddress;             // 0x08: 进程基址 !!!
    PPEB_LDR_DATA Ldr;                  // 0x0C/0x18: 加载的模块列表 !!!
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;  // 0x10/0x20
    // ...
} PEB, *PPEB;
```

#### 一、PEB 是什么
**PEB（Process Environment Block）**  
👉 每个进程在用户态都有的一块“核心结构”，**描述整个进程的运行环境**  
👉 不用 API，直接从 TEB → PEB，就能拿到很多关键信息

这也是 **shellcode / loader / anti-debug** 的核心目标之一。

---

#### 二、你的 PEB 结构 + 注释
```plain
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;      
    // 是否继承父进程地址空间（一般为 FALSE）

    BOOLEAN ReadImageFileExecOptions;   
    // 是否从注册表读取 Image File Execution Options

    BOOLEAN BeingDebugged;              
    // ★★★ 是否正在被调试（反调试常用）★★★

    BOOLEAN SpareBool;                  
    // 填充字段，对齐用

    HANDLE Mutant;                      
    // 进程互斥体（早期 Windows 使用，现在基本不用）

    PVOID ImageBaseAddress;             
    // ★★★ 当前进程 EXE 的基址（非常重要）★★★

    PPEB_LDR_DATA Ldr;                  
    // ★★★ 模块加载器数据（DLL 链表）★★★

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;  
    // ★ 命令行、环境变量、当前目录等

    // ...
} PEB, *PPEB;
```

---

#### 三、x86: 0x30 / x64: 0x60 是什么意思？
这指的是：

**TEB 中 **`**ProcessEnvironmentBlock**`** 字段的偏移**

##### 在 TEB 里：
| 架构 | PEB 指针偏移 |
| --- | --- |
| x86 | `FS:[0x30]` |
| x64 | `GS:[0x60]` |


##### 汇编层面常见写法
###### x86
```plain
mov eax, fs:[0x30]   ; eax = PEB*
```

###### x64
```plain
mov rax, gs:[0x60]   ; rax = PEB*
```

👉 **这就是为什么你会看到大量 shellcode 里硬编码 0x30 / 0x60**

---

#### 四、为什么 PEB 这么重要？（实战角度）
##### 1️⃣ 不用任何 API（绕过监控）
```plain
TEB → PEB → Ldr → 模块链表 → kernel32.dll → GetProcAddress
```

✔ 无需 `LoadLibrary`  
✔ 无需 `GetModuleHandle`  
✔ 绕过 EDR / API Hook

---

##### 2️⃣ 反调试第一招
```plain
if (Peb->BeingDebugged) {
    ExitProcess(0);
}
```

✔ 极其经典  
✔ 很多壳 / 恶意样本第一行就干这个

---

##### 3️⃣ 拿进程基址（PIE / ASLR 下仍然可靠）
```plain
PVOID base = Peb->ImageBaseAddress;
```

✔ 手写 PE 解析  
✔ 自实现 Import Resolver  
✔ shellcode 标配

---

#### 五、PEB / TEB / CLIENT_ID 三件套关系图
```plain
FS/GS
  ↓
 TEB
  ├─ NtTib
  ├─ ClientId        → PID / TID
  └─ ProcessEnvironmentBlock
           ↓
          PEB
           ├─ ImageBaseAddress
           ├─ Ldr (DLL 链表)
           └─ ProcessParameters
```

👉 你前面问的 **CLIENT_ID、NT_TIB、TEB、PEB**  
现在已经完整闭环了 🔥

---

#### 六、一句话总结（面试 / OSEP / 实战用）
**PEB 是用户态进程的“控制中枢”，  
****shellcode 通过 FS/GS 固定偏移拿到 PEB，  
****从而绕过 API，完成模块定位、反调试和加载逻辑。**

### 6.3 Shellcode 中的应用
```c
// 获取 kernel32.dll 基址的经典方法
// x86 汇编:
mov eax, fs:[0x30]      // 获取 PEB
mov eax, [eax + 0x0C]   // PEB->Ldr
mov eax, [eax + 0x14]   // Ldr->InMemoryOrderModuleList ; eax = &InMemoryOrderModuleList
mov eax, [eax]          // 第一个模块 (ntdll.dll)
/*
eax 当前保存的是“链表节点地址”
[eax] 读的是这个节点里的 Flink（下一个节点指针）
*/
mov eax, [eax]          // 第二个模块 (kernel32.dll)  沿着一个双向链表的 Flink 指针不断往下走
mov eax, [eax + 0x10]   // DllBase (kernel32.dll 基址)
```

```c
1. PEB → Ldr → 模块链表
PEB
 └─ Ldr        ← Loader 的“管理器”
      └─ InMemoryOrderModuleList  ← 模块清单

2.InMemoryOrderModuleList结构（循环双向链表）
LIST_ENTRY {
    LIST_ENTRY* Flink;  // 下一个
    LIST_ENTRY* Blink;  // 上一个
}

3. 俩次mov 内存关系
PEB_LDR_DATA
└─ InMemoryOrderModuleList (链表头，不是模块)

InMemoryOrderModuleList.Flink
        ↓
  ntdll.dll 的 InMemoryOrderLinks
        ↓
  kernel32.dll 的 InMemoryOrderLinks
        ↓
  user32.dll ...

4.PEB->Ldr 指向
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;

    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

它的职责是：
记录所有已加载模块
维护多个视角的顺序
保证加载 / 卸载 / 初始化安全
```

---

## 七、Windows 服务
### 7.1 服务概述
Windows 服务是在后台运行的程序，通常以 SYSTEM 权限运行。

```plain
服务状态:
- Stopped (已停止)
- Start Pending (正在启动)
- Running (正在运行)
- Stop Pending (正在停止)
- Paused (已暂停)
```

### 7.2 服务相关 API
```c
// 打开服务控制管理器
SC_HANDLE OpenSCManagerA(
    LPCSTR lpMachineName,          // 计算机名 (NULL = 本地)
    LPCSTR lpDatabaseName,         // 数据库名 (NULL = 默认)
    DWORD dwDesiredAccess          // 访问权限
);

// 打开服务
SC_HANDLE OpenServiceA(
    SC_HANDLE hSCManager,          // SCM 句柄
    LPCSTR lpServiceName,          // 服务名
    DWORD dwDesiredAccess          // 访问权限
);

// 创建服务
//在系统中注册一个新服务（写注册表 + SCM 记录）
SC_HANDLE CreateServiceA(
    SC_HANDLE hSCManager,
    LPCSTR lpServiceName,          // 服务名
    LPCSTR lpDisplayName,          // 显示名
    DWORD dwDesiredAccess,
    DWORD dwServiceType,           // 服务类型
    DWORD dwStartType,             // 启动类型
    DWORD dwErrorControl,
    LPCSTR lpBinaryPathName,       // 可执行文件路径
    // ...
);

// 启动服务
BOOL StartServiceA(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPCSTR *lpServiceArgVectors
);
```

 SCM 就是“管理 Windows 服务的总管进程”，你所有服务操作都要先跟它打交道。  

#### 一、整体流程（先有地图）
典型顺序一定是：

```plain
OpenSCManager
    ↓
OpenService / CreateService
    ↓
StartService
```

**没有 SCM 句柄，后面一步都干不了。**

---

#### 二、OpenSCManagerA —— 打开“服务管理中心”
```plain
SC_HANDLE OpenSCManagerA(
    LPCSTR lpMachineName,   // NULL = 本机
    LPCSTR lpDatabaseName,  // NULL = SERVICES_ACTIVE_DATABASE
    DWORD  dwDesiredAccess  // 你想要的权限
);
```

**这是在干嘛？**

👉 **连接到 SCM（services.exe）并返回一个句柄**

可以理解为：

“我想和 Windows 的服务管理系统建立一个会话”

 ⚠️ **需要管理员权限（通常还受 UAC 影响）**

#### 三、OpenServiceA —— 打开“已有服务”
```plain
SC_HANDLE OpenServiceA(
    SC_HANDLE hSCManager,
    LPCSTR lpServiceName,
    DWORD dwDesiredAccess
);
```

**这是在干嘛？**

👉** ****拿到“某一个具体服务”的操作句柄**

**SCM 句柄 ≠ 服务句柄  
****SCM 是“管理局”，Service 是“具体对象”**

#### 四、CreateServiceA —— 创建一个新服务（重点）
```plain
SC_HANDLE CreateServiceA(
    SC_HANDLE hSCManager,
    LPCSTR lpServiceName,
    LPCSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPCSTR lpBinaryPathName,
    ...
);
```

**这是在干嘛？**

👉** ****在系统中注册一个新服务（写注册表 + SCM 记录）**

📌** 本质上：**

```plain
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```

---

##### 最小可用示例（理解版）
```plain
SC_HANDLE hService = CreateServiceA(
    hSCM,
    "MyTestService",              // 服务名（唯一）
    "My Test Service",            // 显示名
    SERVICE_ALL_ACCESS,
    SERVICE_WIN32_OWN_PROCESS,    // 普通用户态服务
    SERVICE_DEMAND_START,         // 手动启动
    SERVICE_ERROR_IGNORE,
    "C:\\test\\service.exe",      // 可执行文件路径
    NULL, NULL, NULL, NULL, NULL
);
```

---

##### 关键参数你必须懂的
###### 1️⃣ dwServiceType
```plain
SERVICE_WIN32_OWN_PROCESS
```

+ **一个服务 = 一个进程（最常见）**

---

###### 2️⃣ dwStartType
| **值** | **含义** |
| --- | --- |
| `**SERVICE_AUTO_START**` | **开机自启** |
| `**SERVICE_DEMAND_START**` | **手动** |
| `**SERVICE_DISABLED**` | **禁用** |


---

###### 3️⃣ lpBinaryPathName
⚠️** ****这是服务真正执行的程序**

+ **可以是 EXE**
+ **可以带参数**
+ **路径错误 = 服务启动失败**

---

#### 五、StartServiceA —— 启动服务
```plain
BOOL StartServiceA(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPCSTR *lpServiceArgVectors
);
```

##### 这是在干嘛？
👉** ****告诉 SCM：“启动这个服务”**

**SCM 会：**

1. **创建进程**
2. **调用服务入口**
3. **等待 **`**SERVICE_RUNNING**`

---

##### 常见用法
```plain
StartServiceA(
    hService,
    0,
    NULL
);
```

**服务参数很少用，除非你写的是自定义服务程序。**

---

## 八、Windows 注册表
Win + R 键打开“运行”对话框，输入 `regedit`（或 `regedit.exe`）然后按回车

### 8.1 注册表结构
```plain
注册表根键:
HKEY_CLASSES_ROOT (HKCR)    - 文件关联和 COM 对象
HKEY_CURRENT_USER (HKCU)    - 当前用户设置
HKEY_LOCAL_MACHINE (HKLM)   - 系统范围设置
HKEY_USERS (HKU)            - 所有用户配置
HKEY_CURRENT_CONFIG (HKCC)  - 当前硬件配置
```

![](/image/00-%E5%89%8D%E7%BD%AE%E7%9F%A5%E8%AF%86/03-Windows%E6%9E%B6%E6%9E%84%E6%A6%82%E8%BF%B0-2.png)

### 8.2 OSEP 中重要的注册表位置
```plain
自启动位置:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
/*
HKCU = HKEY_CURRENT_USER
→ 当前登录用户的配置，只对这个用户有效
HKLM = HKEY_LOCAL_MACHINE
→ 机器级配置，对所有用户都有效

HKCU：当前用户有写权限  不需要管理员  受 UAC 影响小
HKLM：普通用户 默认不可写  写入通常需要 UAC 提升权限（管理员 token） 服务安装、系统级持久化都在这里
*/
服务配置:
HKLM\SYSTEM\CurrentControlSet\Services\<服务名>

UAC 设置:
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

AppLocker 策略:
HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2

AMSI 提供程序:
HKLM\SOFTWARE\Microsoft\AMSI\Providers
```

#### AppLocker
**AppLocker 是 Windows 的“应用白名单机制”**  
👉 决定 **谁能运行、谁不能运行**

它本质上是：  
**“不是我不让你做坏事，而是我只允许我信任的程序运行。”**

---

##### 一、AppLocker 是干嘛的？
AppLocker 用来 **限制可执行内容**，包括：

+ `.exe`
+ `.dll`
+ `.msi`
+ `.ps1`（PowerShell）
+ `.vbs / .js`
+ `.bat / .cmd`
+ UWP 应用

👉 **核心目标：阻止未知程序执行（恶意软件、横向工具等）**

---

##### 二、AppLocker 工作在什么层？
这是重点。

###### 它不是：
+ ❌ 普通用户态程序
+ ❌ 防病毒
+ ❌ 文件权限（ACL）

###### 它是：
**基于 SRP / CI 的执行控制机制  
****由系统在“进程创建阶段”强制检查**

执行链大概是：

```plain
CreateProcess
   ↓
Win32 / NtCreateUserProcess
   ↓
Code Integrity / AppLocker
   ↓
允许 or 拒绝
```

👉 **程序甚至来不及运行 main()**

---

##### 三、AppLocker 的规则类型（核心）
###### 1️⃣ Publisher（发布者规则）✅ 最常用
```plain
签名是谁？
公司是谁？
版本范围？
```

例子：

允许 Microsoft 签名的所有 EXE

✔ 安全  
✔ 易维护  
✔ 企业最爱

---

###### 2️⃣ Path（路径规则）
```plain
C:\Windows\*
C:\Program Files\*
```

⚠️ 风险大：

+ 目录可写 = 可被利用
+ 企业仍在用，但不安全

---

###### 3️⃣ Hash（哈希规则）
```plain
文件 SHA256 = xxx
```

✔ 最精确  
❌ 文件更新就失效  
❌ 运维成本高

---

##### 四、AppLocker 不是“默认开启”的
📌 关键事实：

+ **家庭版 Windows 没有 AppLocker**
+ 专业版 / 企业版才有
+ **默认是关闭的**
+ 必须通过：
    - 本地安全策略
    - 组策略（GPO）

---

##### 五、强制模式 vs 审计模式（很重要）
###### 🔴 Enforce（强制）
+ 不符合规则 → **直接阻止**
+ 用户看到错误提示

###### 🟡 Audit（审计）
+ 不阻止
+ **只记录日志**

👉 企业通常：

```plain
Audit → 观察 → Enforce
```

---

##### 六、日志在哪？（防守视角）
事件查看器：

```plain
Applications and Services Logs
 └─ Microsoft
    └─ Windows
       └─ AppLocker
```

常见事件 ID：

| ID | 含义 |
| --- | --- |
| 8003 | EXE 被阻止 |
| 8004 | EXE 被允许 |
| 8006 | Script 被阻止 |


### 8.3 注册表 API
####  UI 里的“值类型” ↔ WinAPI 的 dwType  
![](/image/00-%E5%89%8D%E7%BD%AE%E7%9F%A5%E8%AF%86/03-Windows%E6%9E%B6%E6%9E%84%E6%A6%82%E8%BF%B0-3.png)

```plain
字符串值
二进制值
DWORD (32 位) 值
QWORD (64 位) 值
多字符串值
可扩充字符串值
```

**本质上只有两样东西：**[值类型 dwType] + [一段原始字节数据 lpData]

 注册表**不关心语义，只关心类型和字节长度**。  

##### 1️⃣ 字符串值（String）
**UI：**

```plain
字符串值
```

**API：**

```plain
dwType = REG_SZ
```

**内存：**

```plain
ASCII / UTF-16 字符串 + '\0'
```

**示例：**

```plain
const char path[] = "C:\\test\\a.exe";
RegSetValueExA(
    hKey,
    "Path",
    0,
    REG_SZ,
    (BYTE*)path,
    sizeof(path)
);
```

📌 常用于：

+ 程序路径
+ 配置字符串
+ Run 启动项

---

##### 2️⃣ 可扩充字符串值（Expandable String）
**UI：**

```plain
可扩充字符串值
```

**API：**

```plain
dwType = REG_EXPAND_SZ
```

**区别点（非常重要）：**

```plain
字符串里可以包含环境变量
如：%SystemRoot%\System32
```

系统在**读取时会展开**。

---

##### 3️⃣ DWORD (32 位) 值
**UI：**

```plain
DWORD (32 位) 值
```

**API：**

```plain
dwType = REG_DWORD
```

**内存：**

```plain
4 字节（小端序）
```

**示例：**

```plain
DWORD value = 1;
RegSetValueExA(
    hKey,
    "Enable",
    0,
    REG_DWORD,
    (BYTE*)&value,
    sizeof(DWORD)
);
```

📌 超常见：

+ 开关
+ 标志位
+ 配置项（0 / 1 / 2）

---

##### 4️⃣ QWORD (64 位) 值
**UI：**

```plain
QWORD (64 位) 值
```

**API：**

```plain
dwType = REG_QWORD
```

**内存：**

```plain
8 字节
```

📌 用得少，但存在：

+ 时间戳
+ 大计数器
+ 64 位状态值

---

##### 5️⃣ 二进制值（Binary）
**UI：**

```plain
二进制值
```

**API：**

```plain
dwType = REG_BINARY
```

**内存：**

```plain
原始字节数组（不解释）
```

**示例：**

```plain
BYTE buf[] = { 0x90, 0x90, 0xCC };
RegSetValueExA(
    hKey,
    "Blob",
    0,
    REG_BINARY,
    buf,
    sizeof(buf)
);
```

📌 常用于：

+ Hash
+ 加密数据
+ 自定义结构体
+ 驱动 / 安全产品

---

##### 6️⃣ 多字符串值（Multi-String）
**UI：**

```plain
多字符串值
```

**API：**

```plain
dwType = REG_MULTI_SZ
```

**内存结构（非常关键）：**

```plain
"str1\0str2\0str3\0\0"
```

📌 两个 `\0` 结尾  
📌 SCM / 服务 / 驱动里很常见

####  注册表API  
```c
// 打开注册表键
//只负责定位，不读不写
LSTATUS RegOpenKeyExA(
    HKEY hKey,                     // 根键
    LPCSTR lpSubKey,               // 子键路径
    DWORD ulOptions,               // 选项
    REGSAM samDesired,             // 访问权限
    PHKEY phkResult                // 返回的键句柄
);

// 读取值
//lpType 告诉你 值的真实类型  lpData 是原始字节  你要根据 type 自己解释

LSTATUS RegQueryValueExA(
    HKEY hKey,                     // 键句柄
    LPCSTR lpValueName,            // 值名
    LPDWORD lpReserved,            // 保留
    LPDWORD lpType,                // 值类型
    LPBYTE lpData,                 // 数据缓冲区
    LPDWORD lpcbData               // 数据大小
);

// 设置值
//注册表 不校验你给的数据是否“合理”     它只管：类型 + 长度
LSTATUS RegSetValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,                  // REG_SZ, REG_DWORD, REG_BINARY
    const BYTE *lpData,
    DWORD cbData
);
```

---

## 九、章节测试
### 选择题
1. Windows 中哪个权限级别最高？
    - A) Ring 3
    - <font style="color:#DF2A3F;">B) Ring 0</font>
    - C) Medium Integrity
    - D) High Integrity
2. 执行 shellcode 需要的内存保护属性是？
    - A) PAGE_READONLY
    - B) PAGE_READWRITE
    - C) PAGE_EXECUTE_READWRITE
    - D) PAGE_NOACCESS
3. PEB 可以通过哪个段寄存器访问？
    - A) CS
    - B) DS
    - C) FS/GS
    - D) SS
4. 哪个 API 用于在其他进程中分配内存？
    - A) VirtualAlloc
    - B) VirtualAllocEx
    - C) malloc
    - D) HeapAlloc
5. SYSTEM 账户的 SID 是？
    - A) S-1-5-32-544
    - <font style="color:#DF2A3F;">B) S-1-5-18</font>
    - C) S-1-5-21-xxx-500
    - D) S-1-5-32-545

### 简答题
1. 解释用户模式和内核模式的区别。
2. 什么是访问令牌？它包含哪些信息？
3. 描述 UAC 的工作原理。
4. 为什么 shellcode 需要 PAGE_EXECUTE_READWRITE 权限？

### 答案
**选择题**：1-B, 2-C, 3-C, 4-B, 5-B

**简答题**：

1. 用户模式权限受限，不能直接访问硬件；内核模式拥有完全权限，可以执行任何操作。
2. 访问令牌是进程的安全上下文，包含用户 SID、组 SID、特权列表、完整性级别等。
3. UAC 在需要管理员权限时弹出提示，用户确认后以高完整性级别运行程序。
4. shellcode 是代码，需要执行权限；同时可能需要自修改，需要写权限。

---

**下一章**：[04-PowerShell基础](./04-PowerShell基础.md)

