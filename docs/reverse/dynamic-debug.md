# 动态调试

关键词：动态调试 gdb pwndbg gef x64dbg Frida hook 断点 breakpoint 条件断点 catch syscall 单步 ni si finish 内存 dump vmmap telescope patch x/20gx 反调试 attach spawn Interceptor Java.perform 寄存器 栈

## ① 识别指纹

- 静态分析读不懂：控制流混淆、字符串运行时才解密、算法逻辑被拆得很散
- 程序要求输入 `flag` / `serial`，正确与否只在运行时才能看到
- `strings` 里没有明文 flag，但代码里有 XOR / 加减解密循环，解完再 `strcmp` / `memcmp`
- 校验依赖文件内容、网络响应、时间或环境变量，静态看不出数据来源
- 程序检测调试器（`ptrace`、`IsDebuggerPresent`、`/proc/self/status`），一附加就退出
- 附件是 ELF、PE 或 APK；Android 题需要 hook Java 层或 so 层
- 只有远程 `nc` 能跑、本地没有二进制 —— 这种题无法 attach，只能做输入输出观察
- 题目给的是"跑起来才能拿到 flag"，或 hint 明说 "动态调试"

## ② 考什么

- 断点：软件断点（`int3`）、硬件断点、内存断点、条件断点、日志断点
- 单步控制：`si`（进入）、`ni`（越过）、`finish`（执行到返回）、`until`（执行到指定地址）
- 寄存器与栈：`info registers`、`x/20gx $rsp`、按调用约定找参数
- 内存查看与 dump：`x/s`、`x/16bx`、`dump memory`、`vmmap`、`telescope`
- 系统调用跟踪：`catch syscall`、`strace`、`ltrace`
- 运行时修改：改寄存器、改内存、NOP 掉校验、把 `ok` 变量置 1
- x64dbg：断点、单步、内存窗口、调用栈、条件断点与日志
- Frida：spawn/attach、`Interceptor.attach`、`Java.perform`、读写参数与返回值
- **动态调试的判断价值**：
  - 断在 `strcmp`/`memcmp` 时，比较双方已经在内存里 —— 直接读，不要回去逆算法
  - 解密/解压循环刚结束时 dump 内存 —— 比逆变换便宜
  - 只缺密钥/常量时，断在调用点读参数 —— 不必还原整个函数
  - 输入逐字符校验时，用条件断点把命中次数缩到 1 次
  - 控制流被混淆时，跑一遍看真实执行路径 —— 静态图会骗人
  - 出现 `strchr`、`atoi`、CRC 查表等已知库行为时，断库函数，不要读内联展开

## ③ 判断流程

### ③-1 子类型分流

1. `file` 报 ELF → gdb 链，走 ③-2 第 1 条
2. `file` 报 PE，且 `gdb --version` 可用（MinGW / MSYS2） → gdb 链，走 ③-2 第 1 条，寄存器按 Win64 读
3. `file` 报 PE，且只有 x64dbg 的 Windows 图形环境 → x64dbg 链，走 ③-2 第 12 条
4. 目标是 APK / Android 进程，或题目提供 `hook.js`、frida-server 环境 → Frida 链，走 ③-2 第 13 条
5. 远程 `nc` 且本地没有二进制 → 动态调试不可用，本链结束，转 [常规静态分析](/reverse/static-analysis) 做纯静态
6. 一附加就退出或 `ptrace` 报错 → 先转 [反调试](/reverse/anti-debug) 绕过检测，处理后回第 1 条
7. 以上都不成立 → 回第 1 条，用 `file`、`uname -m`、`cat /proc/sys/kernel/yama/ptrace_scope` 重新确认平台与权限

### ③-2 成本排序链

1. 直接运行程序拿基线 → 记录提示语、正确/错误输出、退出码 → 继续
2. `strings -n 6 程序` 找 `strcmp`/`memcmp`/`Correct`/`Wrong`；无符号时用 `ltrace -e strcmp ./prog` 看实际调用 → 继续
3. `gdb -q ./prog`，`b strcmp`（或 `b memcmp`），`run`，输入任意串 → 断下后读参数：SysV 用 `x/s $rdi`、`x/s $rsi`；Win64 用 `x/s $rcx`、`x/s $rdx` → 若一侧是刚才输入的原串、另一侧是可读常量 → 常量那侧就是输入，跳到第 14 条
4. 两侧都不是明文（被变换/加密） → `finish` 回到调用者，`info registers rax` 看返回值，再在调用者的比较分支 `b *地址` → 继续
5. 校验按字符循环、断点命中次数太多 → 条件断点 `b *地址 if $ecx == 8`，或 `ignore 1 8`；用 `commands` 自动打印寄存器 → 继续
6. 输入先经过解密/解压循环 → 在循环出口地址 `b *地址`，`dump memory out.bin $rsi $rsi+0x100`，再 `strings out.bin` → 跳到第 14 条
7. 程序读文件/网络/时间才决定分支 → `catch syscall openat`（Linux）或 `strace -f -e trace=openat,read ./prog` → 继续
8. 校验结果只控制一个 `ok` 变量 → 在返回前 `set $eax=1`，让程序走正确分支 → 跳到第 14 条
9. 断点不命中或附加即退出 → 反调试；先处理检测点，转 [反调试](/reverse/anti-debug) → 处理后回第 3 条
10. gdb 链全部不成立且目标是 PE → 跳到第 12 条
11. gdb 链全部不成立且目标是 Android / JS → 跳到第 13 条
12. x64dbg：`File → Open` 打开程序，`Ctrl+G` 跳到入口或函数地址，`F2` 下断，`F9` 运行，`F7`/`F8` 单步，`Ctrl+F9` 执行到返回；断下后读 `rcx`/`rdx`，内存窗口 `Ctrl+G` 跟随地址 → 读到明文 → 跳到第 14 条
13. Frida：`frida-ps -U` 确认进程名，`frida -U -f 包名 -l hook.js` 启动并注入（CLI 若提示 `%resume`，输入 `%resume` 继续），hook 里用 `Interceptor.attach` 读 `args[0]`/`args[1]`，或 `Java.perform` + `Java.use(...).verify.implementation` 打印参数与返回值 → 读到明文 → 跳到第 14 条
14. 把读到的明文/常量写进脚本还原输入 → 回原程序验证输出正确 → 结束
15. 以上都不成立 → 回第 1 条，改在"输入被读取之后、校验之前"下硬件断点或 watchpoint 重看

## ④ 工具与命令

gdb + pwndbg/gef：

```bash
gdb -q ./chall
```

```text
(gdb) b main                          # 在 main 下断
(gdb) b *0x4011a0                     # 在绝对地址下断
(gdb) b strcmp                        # 断已知库函数
(gdb) b *0x401234 if $eax == 5        # 条件断点
(gdb) ignore 1 8                      # 前 8 次命中忽略
(gdb) run                             # 运行；run < in.txt 可喂输入
(gdb) ni                              # 单步步过
(gdb) si                              # 单步进入
(gdb) finish                          # 执行到当前函数返回
(gdb) until *0x401250                 # 执行到指定地址
(gdb) x/20gx $rsp                     # 看栈
(gdb) x/s $rdi                        # SysV 第 1 个参数
(gdb) x/16bx $rsi                     # 按字节看第 2 个参数
(gdb) info registers                  # 全部寄存器
(gdb) p/x $rax                        # 返回值
(gdb) set $eax=1                      # 运行时改返回值
(gdb) catch syscall openat            # 只断 openat（Linux）
(gdb) dump memory out.bin $rsi $rsi+0x100
(gdb) disassemble /r                  # 带机器码反汇编当前函数
```

自动打印的条件断点：

```text
(gdb) b *0x401234 if $eax == 5
(gdb) commands
> silent
> printf "i=%d, ptr=%p\n", $eax, $rdx
> continue
> end
```

pwndbg / gef 的增强命令：

| 命令 | 提供者 | 作用 |
|---|---|---|
| `vmmap` | pwndbg / gef | 内存映射，找可写段、模块基址 |
| `telescope $rsp 20` | pwndbg | 按栈布局逐层展开指针 |
| `context` | pwndbg / gef | 一次显示寄存器、栈、代码 |
| `heap` / `bin` | pwndbg | 堆块与 bin 状态（Pwn 常用） |
| `xinfo $rdi` | gef | 查看地址属于哪个映射 |
| `patch byte 0x4011a0 0x90` | gef | 运行时改内存；gdb 内置等价 `set {unsigned char}0x4011a0 = 0x90` |

x64dbg：

| 操作 | 快捷键 / 位置 |
|---|---|
| 打开程序 | `File → Open` |
| 跳到地址 | `Ctrl+G`（Go to expression） |
| 下 / 取消断点 | `F2` |
| 运行 / 暂停 | `F9` |
| 单步进入 | `F7` |
| 单步越过 | `F8` |
| 执行到返回 | `Ctrl+F9` |
| 内存窗口跟随地址 | 内存窗口 `Ctrl+G`，或右键 "Follow in Dump" |
| 条件断点 / 日志断点 | 断点窗口右键 → Edit，填 Condition 与 Log Text |
| 硬件断点 | `bph` 命令，或断点窗口添加 |

Frida：

```bash
frida-ps -U                                  # 列出 USB 设备上的进程
frida -U -f com.example.app -l hook.js       # spawn 并注入
frida -U -n com.example.app -l hook.js       # attach 到已运行进程
frida -U -p 1234 -l hook.js                  # 按 PID attach
```

`hook.js`（原生层读 `strcmp` 参数）：

```js
// Frida 17+；旧版等价写法：Module.findExportByName(null, "strcmp")
const p = Module.getGlobalExportByName("strcmp");
Interceptor.attach(p, {
  onEnter(args) {
    console.log("[strcmp] a =", Memory.readUtf8String(args[0]));
    console.log("[strcmp] b =", Memory.readUtf8String(args[1]));
  },
  onLeave(retval) {
    console.log("[strcmp] ret =", retval.toInt32());
  }
});
```

`hook.js`（Java 层替换方法实现）：

```js
Java.perform(function () {
  const Check = Java.use("com.example.app.Check");
  Check.verify.implementation = function (s) {
    console.log("[verify] arg =", s);
    const r = this.verify(s);
    console.log("[verify] ret =", r);
    return r;
  };
});
```

::: tip 什么时候该停下来，别再读汇编了
- 断点处比较双方已经是明文 → 直接抄，结束
- 解密循环已经跑完、明文就在内存里 → dump，结束
- 只缺一个常量/密钥 → 断在调用点把参数读出来，结束
- 输入格式与长度已经确定、只差逐字符校验 → 条件断点逐字符取，结束
- 混淆代码已经跑出真实路径 → 记录路径与常量，结束
- 命中的是 `strcmp`/`memcmp`/`atoi`/CRC 查表等已知函数 → 读调用点参数，不要逆内联
:::

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 按静态地址下断，断点永远不命中 | PIE / ASLR 让基址每次不同 | 用符号名（`b main`）或"模块基址 + 偏移"，PIE 下用 `b *main+0x10` |
| `vmmap` / `telescope` 提示找不到命令 | 装的是裸 gdb | 装 pwndbg 或 gef；没有就用内置 `x/`、`info proc mappings` |
| 断在函数入口读 `$rdi` 是垃圾 | 断点落在序言之前，或平台不是 SysV | 断在序言之后；PE 用 `rcx/rdx/r8/r9`，先 `file` 确认平台 |
| `finish` 之后看不到返回值 | 函数是 `void`，或返回值已被下一条指令覆盖 | 在 `ret` 前下断，读 `rax`/`eax` |
| 下断后程序直接退出或崩溃 | 反调试检测到 `int3` / 调试器 | 用硬件断点，或先 patch 掉检测；见 [反调试](/reverse/anti-debug) |
| `catch syscall` 太慢，几乎无法运行 | 对所有系统调用都断 | 指定调用名：`catch syscall openat`，或改用 `strace -e` |
| dump 出来的内存是乱码 | dump 时机早于解密完成 | 断在解密循环出口，再 `dump memory` |
| 远程 `nc` 的题目无法 attach | 二进制在远端，本地只有服务地址 | 找附件本地复现；没有附件就纯静态 + 观察输入输出 |
| Frida attach 失败 | 包名/进程名不对，frida-server 未启动或版本不匹配 | `frida-ps -U` 确认名字；设备上以 root 启动同版本 frida-server |
| `Java.perform` 没有任何输出 | hook 时机早于类加载，或目标不是 ART 运行时 | 用 `-f` spawn 模式；必要时把 hook 延迟到类加载后执行 |
| 改了内存但程序行为没变 | 改的是栈上的副本，或程序已把值缓存到寄存器 | 改寄存器，或在真正使用该值的指令前下断 |

## ⑥ 例题

**题目**：运行时解密 + `strcmp`（自建样例）
**来源**：本页配套样例。等价于常见"字符串加密后比较"的 crackme：静态看不到明文，比较发生在运行时。

**题干**：给一个 64 位 PE，运行后提示 `flag: `，输入正确输出 `Correct!`，否则 `Wrong!`。附件没有源码。

**附件**：`dyn.exe`，MinGW GCC 编译，未加壳。样例的校验串被写成 `flag{...}` 这 9 个字符；真实比赛题以原题平台为准。

**关键观察**：
- `strings -n 6 dyn.exe | grep -iE 'flag|Correct|Wrong'` 只有提示语，没有明文
- 导入表里有 `strcmp`，最终比较一定走它
- 程序里有一段 `enc[i] ^ 0x55` 的循环，明文只在运行时出现在栈上

**走了哪条链**：① 看到 `strings` 无明文 + 有 `strcmp` → ③-1 第 2 条（PE + MinGW gdb）→ ③-2 第 1 条（跑基线）→ 第 2 条（`strings` 定位 `strcmp`）→ 第 3 条（断 `strcmp` 直接读参数）；第 3 条命中"另一侧是可读常量"，跳到第 14 条验证。

**命令与输出**（本机 MinGW gdb 实测，地址随 ASLR 变化）：

```text
$ strings -n 6 dyn.exe | grep -iE 'flag|Correct|Wrong'
flag:
Correct!
Wrong!

$ printf 'flag{...}\n' > in.txt
$ gdb -q ./dyn.exe
(gdb) b strcmp
Breakpoint 1 at 0x140002960
(gdb) run < in.txt
Thread 1 hit Breakpoint 1.1, 0x00007ff98a4cd290 in ucrtbase!strcmp () from C:\Windows\System32\ucrtbase.dll
(gdb) x/s $rcx
0x5ffe80:	"flag{...}"
(gdb) x/s $rdx
0x5ffe6d:	"flag{...}"
(gdb) x/16bx $rdx
0x5ffe6d:	0x66	0x6c	0x61	0x67	0x7b	0x2e	0x2e	0x2e
0x5ffe75:	0x7d	0x00	0x33	0x39	0x34	0x32	0x2e	0x7b
```

`rcx` 是用户输入缓冲区，`rdx` 是解密后的期望串。`rdx+9` 的 NUL 之后还能看到原始密文 `33 39 34 32 2e 7b ...`——它就是明文再异或 `0x55` 的结果（`0x33 ^ 0x55 = 0x66`，即 `f`）。

**结果**：不需要逆那个 XOR 循环。断在 `strcmp` 时比较双方都已是明文，直接得到输入 `flag{...}`。

**验证方法**：

```text
$ printf 'flag{...}\n' | ./dyn.exe
flag: Correct!
```

**命中条目复述**：③-1 第 2 条 → ③-2 第 1、2、3 条 → 跳到第 14 条。

::: tip 同类公开练习
- `BUUCTF` 的 `[BJDCTF2020] JustRE`：可以在 `strcmp` 前断下直接看两侧
- `picoCTF` 的 `GDB Test Drive` / `babygame` 系列：练 `b`、`x`、`set`
- `Crackmes.one` 上带 "anti-debug" 标签的题：练硬件断点与检测点 patch
:::
