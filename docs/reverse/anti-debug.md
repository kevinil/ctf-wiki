# 反调试与反虚拟机

关键词：反调试 anti-debug 反虚拟机 anti-VM 反沙箱 ptrace TracerPid IsDebuggerPresent NtQueryInformationProcess rdtsc 时间差 int3 0xCC ScyllaHide frida LD_PRELOAD 壳检测

## ① 识别指纹

- 正常双击运行有输出；在 gdb / x64dbg / IDA 里一启动就退出、输出 `Debugger detected!` 或无输出
- `strings` 命中 `/proc/self/status`、`TracerPid`、`ptrace`、`BeingDebugged`、`IsDebuggerPresent`、`NtQueryInformationProcess`
- 导入表有 `IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess`、`ptrace`
- 断点打不上 / 不命中；单步执行程序跑飞；下断点后程序行为改变
- 程序里有 `rdtsc`、`GetTickCount`、`QueryPerformanceCounter` 成对出现
- 代码里出现 `0xCC` 扫描自身、`int 3` + 异常处理、`SIGTRAP`
- 在虚拟机里跑不出 flag，换真机可以；`strings` 有 `VMware`、`VirtualBox`、`QEMU`、`VBOX`
- 壳的特征（UPX / Themida / VMProtect）—— 强壳通常自带反调试，先判壳
- 题目名带 `anti`、`debug`、`vm`、`sandbox`、`hide`

## ② 考什么

- Linux 反调试：`ptrace(PTRACE_TRACEME)`（两次调用）、`/proc/self/status` 的 `TracerPid`、`getppid`、`/proc/self/maps`
- Windows 反调试：PEB->`BeingDebugged`、`IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess`（`ProcessDebugPort=7`、`ProcessDebugFlags=0x1F`、`ProcessDebugObjectHandle=0x1E`）
- 时间差：`rdtsc`、`GetTickCount`、`QueryPerformanceCounter`、`clock_gettime`
- 异常：`int 3` / `0xCC`、SEH / VEH、`SIGTRAP`、`0xCC` 自扫描
- 线程隐藏：`NtSetInformationThread(ThreadHideFromDebugger)`
- 反虚拟机：CPUID hypervisor 位（leaf 1，ECX bit 31）、vendor leaf `0x40000000` 字符串、VMware 后门端口 `0x5658`、注册表（`HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum`）、MAC OUI（VMware `00:0C:29` / `00:50:56`，VirtualBox `08:00:27`，QEMU `52:54:00`，Hyper-V `00:15:5D`）、磁盘 / BIOS 型号
- 反沙箱（宏特征）：用户名、计算机名、进程列表、文件、开机时长、鼠标移动
- 绕过：patch 分支、`LD_PRELOAD` hook、frida hook、ScyllaHide、硬件断点、内存 dump

## ③ 判断流程

### ③-1 子类型分流

1. 正常跑有输出，调试器下退出 / 无输出 → 反调试，跳 ③-2 第 1 条
2. 真机跑出 flag，虚拟机里失败 → 反虚拟机，跳 ③-2 第 7 条
3. 只在特定用户名 / 主机名 / 进程环境下失败 → 反沙箱，跳 ③-2 第 8 条
4. `DIE` 显示 UPX / Themida / VMProtect 等壳 → 先按 [加壳与脱壳](/reverse/unpacking) 处理
5. 断点不命中、单步跑飞，但正常运行无异常 → 异常 / 线程隐藏类反调试，跳 ③-2 第 9 条
6. 以上都不成立 → 回 [常规静态分析](/reverse/static-analysis)

### ③-2 成本排序链

1. 先对比运行环境：正常命令行跑一次、gdb / x64dbg 跑一次，记录输出差异 → 有差异进第 2 条；无差异进第 6 条
2. `strings` + 导入表搜检测 API：`ptrace`、`TracerPid`、`IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess`、`rdtsc` → 命中 → 第 3 条；无命中 → 第 6 条
3. 在 IDA/Ghidra 里对检测 API 按 `X` 看交叉引用，定位调用点后的条件跳转（`test eax,eax; jne` / `cmp; jne`）→ 第 4 条
4. patch 分支：把 `jne` 改成 `je` 或 NOP，或把函数返回值改成 0 / 1；先备份原文件 → 运行验证，结束；不能改文件 → 第 5 条
5. 动态绕过：Linux `LD_PRELOAD` hook `ptrace` 返回 0；Windows 用 ScyllaHide 隐藏调试器；frida hook `IsDebuggerPresent` / `ptrace` → 运行验证，结束；hook 失败 → 第 6 条
6. 时间差检测：`rdtsc` / `GetTickCount` 成对出现且差值参与比较 → patch 比较阈值或 hook 时间函数，结束；没有时间差检测 → 第 7 条
7. 反虚拟机：搜 CPUID hypervisor 位、vendor 串（`VMwareVMware` / `VBoxVBoxVBox` / `KVMKVMKVM`）、注册表、MAC 前缀 → patch 检测分支，或改 VM 配置 → 结束；无 VM 特征 → 第 8 条
8. 反沙箱：搜用户名 / 主机名 / 进程名 / 文件路径 / uptime → 改环境或 patch 判断 → 结束；无沙箱特征 → 第 9 条
9. 异常 / `0xCC` 检测：程序用 `int 3` + 异常处理或扫描自身代码 → 用硬件断点 / 内存断点代替 `0xCC`，patch 扫描循环 → 结束；无异常检测 → 第 10 条
10. 强壳反调试（Themida / VMProtect）→ 先脱壳 / 内存 dump；关键代码在 VM 里则转动态分析 / 侧信道 → 结束；不是强壳 → 第 11 条
11. 以上都不成立 → 回 ③-1 第 1 条，换调试器（gdb → x64dbg → frida）重试

## ④ 工具与命令

```bash
# Linux：先看程序调用了什么
strace -f -e trace=ptrace,openat,read ./prog
ltrace ./prog
# 程序运行时另开终端
cat /proc/$(pgrep -n prog)/status | grep TracerPid
```

```c
/* 让 ptrace 永远返回 0；只对动态链接且直接调 ptrace 的程序有效 */
#define _GNU_SOURCE
long ptrace(int request, ...) { return 0; }
```

```bash
gcc -shared -fPIC -o noptrace.so noptrace.c
LD_PRELOAD=./noptrace.so ./prog
```

```js
// Linux：hook ptrace，打印请求号并强制返回 0
Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
    onEnter: function (args) { console.log('ptrace(' + args[0].toInt32() + ')'); },
    onLeave: function (retval) { retval.replace(0); }
});
```

```js
// Windows：hook IsDebuggerPresent，强制返回 0
var p = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
Interceptor.attach(p, {
    onLeave: function (retval) { retval.replace(0); }
});
```

```bash
frida -f prog.exe -l hook.js        # Windows 本地 spawn；若停在入口，REPL 里输入 %resume
frida -U -f 包名 -l hook.js         # Android
```

```text
Windows 工具链
x64dbg + ScyllaHide 插件     隐藏调试器，过 PEB / API 检测
Process Hacker / PE-sieve    看内存、dump
IDA                          定位检测点与交叉引用
CPUID 检测
  leaf 1, ECX bit 31 = 1              hypervisor present
  leaf 0x40000000                     返回 12 字节 vendor 串
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 改了 `IsDebuggerPresent` 返回 0 还是退出 | 还有第二处检测（`CheckRemoteDebuggerPresent` / `NtQueryInformationProcess` / 时间差） | 搜全部检测点，逐个 patch |
| `ptrace` hook 返回 0 还是失败 | 第二次 `ptrace`，或程序读 `/proc/self/status` | 同时 hook `open` / `read`，或 patch 读取逻辑 |
| gdb 下正常，x64dbg 下退出 | 检测方式不同（PEB / API / 时间） | 换工具并 patch 对应检测 |
| 断点不命中 | 程序扫描 `0xCC` 或使用异常 | 用硬件断点 / 内存断点，先 patch 扫描 |
| 单步就退出 | 时间差或 `int 3` 检测 | patch 时间比较或异常处理 |
| `LD_PRELOAD` 不生效 | 程序静态链接，或直接 `syscall` | patch 二进制，或 hook syscall |
| 虚拟机检测绕不过 | 同时检查 CPUID + 注册表 + MAC | 全部 patch，或改 VM 配置 |
| 把反调试当壳 | 有反调试不等于有壳 | 先 `DIE` 判壳，再处理反调试 |
| 强壳里 patch 无效 | 代码被 VM / 加密，patch 的是解密前 | 先脱壳 / 内存 dump |
| `IsDebuggerPresent` 在 gdb 下也返回 1 | gdb 也是调试器 | 正常，按调试器环境处理 |

## ⑥ 例题

**题目**：`IsDebuggerPresent` 反调试（本页配套可复现样例）
**来源**：本页自建，等价于 Windows crackme 入门题里的第一类反调试

**题干**：给一个 PE，正常运行时输出 `Correct!`，在调试器里运行时输出 `Debugger detected!`；要求在不触发检测的情况下拿到 flag。

**附件**：`anti.exe`（MinGW gcc 14.2 编译，`-O2`，未加壳）

**关键观察**：
- 正常命令行运行：`Correct! flag{byp4ss_1s_d3bugg3r}`
- `gdb -batch -ex run`：`Debugger detected!`，退出码 1
- `objdump -d` 在 `main` 里看到 `call *__imp_IsDebuggerPresent`、`test eax,eax`、`jne`
- 分支字节是 `75 14`（`jne`），文件偏移 `0x1fa4`

**走了哪条链**：③-1 第 1 条（调试器下行为不同）→ ③-2 第 2 条（导入表命中 `IsDebuggerPresent`）→ 第 3 条（定位 `test/jne`）→ 第 4 条（NOP 分支）→ 结束。

**命令与输出**：

```text
$ ./anti.exe
Correct! flag{byp4ss_1s_d3bugg3r}

$ gdb -batch -ex run --args ./anti.exe
Debugger detected!
```

关键反汇编：

```text
14000299a: call *0x5920(%rip)        # 1400082c0 <__imp_IsDebuggerPresent>
1400029a0: test %eax,%eax
1400029a2: mov  %eax,%ebx
1400029a4: jne  1400029ba <main+0x2a>
```

文件偏移换算：

- `.text` 的 VMA 是 `0x140001000`，File off 是 `0x600`
- `jne` 的 VA 是 `0x1400029a4`，RVA 是 `0x29a4`
- 文件偏移 = `0x600 + (0x29a4 - 0x1000)` = `0x1fa4`
- `xxd -s 0x1fa0 -l 16` 显示 `... 85c0 89c3 7514 ...`

patch：

```python
p = 'anti.exe'
b = bytearray(open(p, 'rb').read())
off = 0x1FA4
assert b[off:off+2] == b'\x75\x14'
b[off:off+2] = b'\x90\x90'      # NOP 掉 jne
open(p, 'wb').write(b)
```

改完再跑：

```text
$ gdb -batch -ex run --args ./anti.exe
Correct! flag{byp4ss_1s_d3bugg3r}
```

**结果**：NOP 掉 `jne` 后，即使 `IsDebuggerPresent` 返回 1，程序也会继续走正确分支。退出码仍是 1，因为 `ebx` 已经保存了检测结果，不影响拿 flag。本页样例为自建，实际比赛 flag 以平台为准。

::: tip 同类公开练习
- 看雪论坛 crackme 区的反调试入门题（大量 `IsDebuggerPresent` / `ptrace` 结构）
- Crackmes.one 上带反调试的 crackme
- 用 `picoCTF` 的 reversing 入门题练"正常跑 vs gdb 跑"的对比方法
:::
