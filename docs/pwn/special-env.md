# 特殊环境（musl / ARM / QEMU / 多线程与竞态）

关键词：特殊环境 musl ARM AArch64 aarch64 arm64 qemu qemu-arm qemu-system 用户态 系统态 交叉编译 ropper pthread 多线程 竞态 race 条件竞争 TOCTOU LD_PRELOAD double free UAF 原子性 pwn

## ① 识别指纹

- `file ./pwn` 显示非 x86 架构：`ARM aarch64`、`ARM, EABI5`、`MIPS`；或者显示 `statically linked`
- `ldd ./pwn` 报 `not a dynamic executable`，或 `readelf -l ./pwn | grep interpreter` 显示 `ld-musl-x86_64.so.1`
- `strings -a ./pwn | grep -i musl` 有输出；`readelf -s` 里找不到 `__free_hook` / `__malloc_hook`
- 附件带 `run.sh`，内容是 `qemu-arm ./pwn`、`qemu-aarch64 -L ./lib ./pwn`，或 `qemu-system-*`
- 直接 `./pwn` 报 `Exec format error`，必须用 QEMU 运行
- 程序里有 `pthread_create`、`pthread_mutex_lock`、`sleep` / `usleep`、`alarm`，同一块内存或同一个 fd 被多个线程操作
- 题干出现 `race`、`并发`、`同时`、`多线程`、`musl`、`arm`、`qemu`
- 题目名带 `baby_arm` / `race` / `musl` / `qemu` / `thread`

## ② 考什么

- musl：没有 `__free_hook` / `__malloc_hook`，没有 tcache / safe-linking；1.2+ 的 mallocng 用 `meta` / `group`，1.1.x 用旧 bin 链表
- musl 的 `_IO_FILE` 把 `read` / `write` / `seek` / `close` 函数指针直接放在结构体里，`exit_handlers` / `atexit` 也是常见目标
- musl 的 `printf` 对 `%n` / 位置参数的支持与 glibc 不同，利用前先本地验证
- ARM / AArch64 调用约定：AArch64 用 `x0–x7` 传参、`x8` 放 syscall 号、`svc #0`；ARM 32 位用 `r0–r3`、`r7` 放号
- ARM 返回地址在 `x30` / `LR`；Thumb 指令地址的 bit0 为 1
- 架构 syscall 号不同：AArch64 用 `openat = 56`、`read = 63`、`write = 64`、`execve = 221`、`mprotect = 226`；ARM 32 位用 `open = 5`、`read = 3`、`write = 4`、`openat = 322`、`mprotect = 125`
- QEMU 用户态：`qemu-<arch>` 跑单个 Linux 进程；系统态：`qemu-system-<arch>` 跑整机、内核与设备
- QEMU 调试：`-g <port>` 起 gdbserver，`-L <sysroot>` 指定动态库根，`-strace` 看 syscall
- 交叉编译与 gadget：`aarch64-linux-gnu-gcc`、`gdb-multiarch`、`ropper --arch arm64`、ARM 32 位用 `--arch arm`
- 多线程与竞态：TOCTOU、double free、UAF、共享 fd、检查与使用之间的窗口
- 用 `LD_PRELOAD` 覆盖 `sleep` / `usleep` / `strcmp` / `malloc`，卡住一个线程，让另一个线程先完成操作
- `pthread_barrier` / 管道 / 信号量把竞态变成可重复的顺序
- `fork` 的子进程继承地址，可用于爆破；线程共享地址空间，没有这个便利

## ③ 判断流程

### ③-1 子类型分流

1. **`file ./pwn` 看架构** → x86_64 / i386，跳到第 2 条；ARM / AArch64 / MIPS，转 ③-2 B 组第 1 条
2. **看 libc 类型** → `ldd` 或 `readelf -l | grep interpreter` 显示 `ld-musl-*`，或 `strings` 有 `musl` → **musl**，转 A 组第 1 条；glibc / 动态链接，跳到第 3 条；静态且无 musl 字样，跳到第 3 条
3. **看是否多线程** → `readelf -s ./pwn | grep pthread_create`，或 `strings` 有 `pthread`，或源码里 `pthread_create` → **多线程 / 竞态**，转 D 组第 1 条；没有，跳到第 4 条
4. **看 `run.sh` 用哪种 QEMU** → `qemu-system-*`，转 [内核 Pwn 入门](/pwn/kernel)；`qemu-<arch>` 或直接运行报 `Exec format error`，转 B 组第 1 条；没有 QEMU 且能直接运行，跳到第 5 条
5. **以上都不成立** → 回第 1 条，用 `readelf -h` / `readelf -A` 再确认架构与 ABI；仍无 → 回 [题型总表](/map)

### ③-2 成本排序链

**A. musl**

1. **确认 musl 版本** → `strings -a ./pwn | grep -i musl`、`readelf -n ./pwn`；动态 musl 会显示 `ld-musl-x86_64.so.1` → 进入第 2 条；版本未知，用题目给的 `libc.so` 运行或看 `--version`，仍未知就按 1.2+ 的 mallocng 处理，回到第 1 条
2. **确认没有 glibc hooks** → `readelf -s ./pwn | grep -E '__free_hook|__malloc_hook'` 无结果 → 进入第 3 条；有结果，说明不是 musl，回 ③-1 第 2 条
3. **判断堆实现** → 1.1.x 用旧 bin 链表，重点看 `mal.bins` / `unbin`；1.2.x 用 mallocng，重点看 `meta` / `group` → 进入第 4 条
4. **找利用原语** → 有 UAF / OOB / 任意写，优先改 `_IO_FILE` 的函数指针或 `exit_handlers` / `atexit`；有栈溢出，直接 ROP / ORW → 进入第 5 条
5. **先泄露** → 动态 musl 泄露 libc 基址，静态 / PIE 泄露代码基址；用 GOT、栈、格式化字符串 → 转 [地址泄露与 PIE 绕过](/pwn/leak-pie)
6. **收尾** → 控制流劫持到 `system` / `execve`，或按 sandbox 要求走 ORW；有 seccomp → 转 [沙箱绕过](/pwn/sandbox-seccomp) → 结束
7. **以上都不成立** → 回第 1 条，换题目给的 musl 版本与运行方式；仍无 → 回 ③-1 第 2 条

**B. ARM / AArch64**

1. **选对 QEMU** → `file` 显示 `ARM aarch64` 用 `qemu-aarch64`；`ARM, EABI5` 用 `qemu-arm`；`MIPS` 用 `qemu-mips` → 进入第 2 条；架构不匹配报 `Exec format error`，回到第 1 条换 QEMU
2. **补 sysroot** → 动态链接时加 `-L`，指向包含 `lib/ld-linux-*.so.*` 的目录；报 `could not open /lib/ld-linux-...`，调整 `-L` 到正确根目录，回到第 2 条；静态链接不用 `-L`，进入第 3 条
3. **起调试** → `qemu-aarch64 -g 1234 -L ./lib ./pwn` 配 `gdb-multiarch ./pwn -ex 'target remote :1234'`；能断到 `main`，进入第 4 条；连不上，检查 `-g` 的位置与端口，回到第 3 条
4. **找 gadget** → `ropper --file ./pwn --arch arm64 --search 'ldr x0'`、`'pop {x0, pc}'`；ARM 32 位用 `--arch arm`；`ROPgadget` 对 ARM 支持有限 → 找到 gadget，进入第 5 条；找不到，换 libc 或直接写 shellcode，跳到第 6 条
5. **确认调用约定** → AArch64：`x0–x7` 传参、`x8` 放 syscall 号、`svc #0`、返回地址在 `x30`；ARM 32 位：`r0–r3`、`r7`、`svc #0` → 按约定构造 ROP / ORW，进入第 6 条
6. **选代码执行方式** → 缓冲区可执行或能 `mprotect`，写对应架构的 ORW shellcode；不能执行，用 ROP 调 `openat` / `read` / `write` → 进入第 7 条
7. **收尾** → 拿到 flag 或 shell；如果 `run.sh` 是 `qemu-system-*`，转 [内核 Pwn 入门](/pwn/kernel) → 结束
8. **以上都不成立** → 回第 1 条，用 `readelf -h` 再确认架构与端序；仍无 → 换 QEMU 版本或题目提供的运行脚本

**C. QEMU 用户态与系统态**

1. **看命令名** → `qemu-system-*` 是系统态，转 [内核 Pwn 入门](/pwn/kernel)；`qemu-<arch>`（没有 `-system`）是用户态，进入第 2 条
2. **用户态补库** → `qemu-aarch64 -L <sysroot> ./pwn`；缺 `ld-linux` / `libc.so` 就从附件或同版本镜像取，放到 sysroot 对应路径，回到第 2 条；库齐了，进入第 3 条
3. **用户态调试** → `-g <port>` 配 `gdb-multiarch`；`-strace` 看 syscall 序列 → 能定位输入点，进入第 4 条；不能，检查 QEMU 版本与参数顺序，回到第 3 条
4. **系统态调试** → `-s -S` 配 `gdb vmlinux`，串口用 `-nographic`，文件传输用 `-virtfs` / 9p 或 base64 → 转 [内核 Pwn 入门](/pwn/kernel)
5. **用户态不支持某 syscall / 设备** → QEMU 用户态只翻译进程 syscall，不模拟硬件 → 改用 `qemu-system-*`，回到第 1 条
6. **以上都不成立** → 回第 1 条，确认拼写是 `qemu-*` 还是 `qemu-system-*`

**D. 多线程与竞态**

1. **定位共享对象与窗口** → 源码 / 反编译里 `if (check(x)) { ... use(x) ... }`，中间有 `sleep` / `usleep` / IO / 解锁 → 进入第 2 条；没有窗口，找 `free` 后另一个线程仍使用（UAF）→ 进入第 2 条
2. **本地放大窗口** → 动态 glibc 二进制用 `LD_PRELOAD` 覆盖 `sleep` / `usleep` / `strcmp` / `malloc`，在目标点阻塞；静态 musl 无法 `LD_PRELOAD`，改用源码重编译或大量重试 → 进入第 3 条
3. **同步两个线程** → hook 里用 `pthread_barrier` / 管道 / 信号量，让线程 A 停在检查后，线程 B 完成使用后再放行 → 进入第 4 条；不能用 hook，用多线程 + 循环重试，进入第 4 条
4. **利用竞态** → 双花 / 双 free / UAF / TOCTOU 改 fd 或长度；目标是堆，转 [堆利用](/pwn/heap)；是栈溢出，转 [栈溢出基础](/pwn/stack-basic)；是内核对象，转 [内核 Pwn 入门](/pwn/kernel) → 结束
5. **远程稳定化** → 把同步逻辑写进 exploit，按服务端交互顺序卡点；仍不稳，增加线程或重试次数，回到第 3 条
6. **以上都不成立** → 回第 1 条，用 `strace -f` 确认竞态窗口真实存在；仍无 → 回 ③-1 第 3 条

## ④ 工具与命令

```bash
file ./pwn
readelf -h ./pwn | grep -E 'Class|Machine|Type'
readelf -l ./pwn | grep -E 'interpreter|LOAD'
readelf -s ./pwn | grep -E '__free_hook|__malloc_hook|pthread_create'
strings -a ./pwn | grep -iE 'musl|pthread|race'
checksec --file=./pwn
```

```bash
# QEMU 用户态
qemu-aarch64 -L ./lib ./pwn
qemu-aarch64 -g 1234 -L ./lib ./pwn
qemu-arm -L ./lib ./pwn
qemu-aarch64 -strace ./pwn

# gdb 多架构
gdb-multiarch ./pwn -ex 'set architecture aarch64' -ex 'target remote :1234'
```

```bash
# gadget 搜索
ropper --file ./pwn --arch arm64 --search "ldr x0"
ropper --file ./pwn --arch arm64 --search "pop {x0, pc}"
ropper --file ./pwn --arch arm --search "pop {r0, pc}"
ROPgadget --binary ./pwn --only "pop|ret"
```

```bash
# 交叉编译（按题目架构选）
aarch64-linux-gnu-gcc -static -O2 pwn.c -o pwn
arm-linux-gnueabi-gcc -static -O2 pwn.c -o pwn
musl-gcc -static -O2 pwn.c -o pwn
```

```bash
# 竞态：编译目标与 LD_PRELOAD hook
gcc -O0 -pthread race.c -o race
gcc -O0 -shared -fPIC -pthread slow.c -o slow.so
LD_PRELOAD=./slow.so ./race
strace -f ./race
gdb ./race -ex 'set scheduler-locking on'
```

```bash
# 动态 musl 二进制换解释器（本地调试时）
patchelf --set-interpreter ./ld-musl-x86_64.so.1 --set-rpath . ./pwn
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 直接运行报 `Exec format error` | 架构不是本机 x86 | 用对应的 `qemu-<arch>` |
| 用 `qemu-arm` 跑 AArch64 程序 | QEMU 名字选错 | AArch64 用 `qemu-aarch64`，ARM 32 位用 `qemu-arm` |
| 动态 ARM 程序提示找不到 `ld-linux` | 没有指定 sysroot | 加 `-L`，指向包含 `lib/ld-linux-*.so.*` 的根目录 |
| musl 题套 `__free_hook` 模板 | musl 从来没有这个符号 | 改 `_IO_FILE` 函数指针、`exit_handlers` / `atexit` |
| musl 堆布局与 glibc 对不上 | 1.2+ 是 mallocng，1.1.x 是旧 bin | 先确认版本，再选对应原语 |
| 静态 musl 加 `LD_PRELOAD` 没反应 | 静态链接不加载动态库 | 改源码重编译，或走重试 / 其他原语 |
| `LD_PRELOAD` 对 setuid 程序无效 | 动态加载器忽略不可信预加载 | 不用这条路，换源码级或竞态重试 |
| ARM gadget 地址是奇数 | Thumb 模式地址 bit0 为 1 | ARM 32 位确认 Thumb / ARM 模式，别把 bit0 当偏移 |
| AArch64 调用函数后崩溃 | 栈没按 16 字节对齐 | 调整填充，保持 SP 16 字节对齐 |
| QEMU 用户态找不到某设备 / syscall | 用户态只翻译进程 syscall，不模拟硬件 | 改用 `qemu-system-*` |
| 竞态本地通、远程不通 | 调度、CPU 数、环境不同 | 用 `LD_PRELOAD` / barrier 同步，或多线程重试 |
| 多线程 payload 顺序错乱 | `sendline` 与线程调度竞争 | 用 `send`，按服务端交互顺序精确卡点 |
| 线程栈地址与主线程不同 | 每个线程有独立栈，canary 按线程独立 | 用主线程泄露，或单独泄露目标线程 |
| musl 的 `printf` 格式化行为不同 | `%n` / 位置参数支持与 glibc 不同 | 先本地验证，再决定是否用格式化字符串 |
| 交叉编译工具链缺失 | 没装 `aarch64-linux-gnu-gcc` | 安装对应工具链，或直接用题目提供的 libc / qemu |

## ⑥ 例题

**题目**：自建最小样例：双线程取款竞态（`race.c` + `slow.c`）
**来源**：本页附带源码，Linux 下 `gcc -pthread` 可复现；对应真实题目里的 TOCTOU / 双花 / UAF 竞态

**题干**：账户余额 100，两个线程同时购买价格为 100 的商品；正常只应成功一次，竞态成功时余额变成负数。

**关键观察**：
- `buy()` 先判断 `balance >= 100`，再 `usleep`，最后 `balance -= 100`；检查与使用之间有窗口
- 没有加锁，两个线程共享 `balance`
- 直接运行时结果取决于调度；用 `LD_PRELOAD` 卡住 `usleep`，可以让两个线程都停在扣款之前

**走了哪条链**：③-1 第 3 条（发现 pthread 与共享状态）→ ③-2 D 组第 1 条（定位检查-使用窗口）→ 第 2 条（`LD_PRELOAD` 卡住 `usleep`）→ 第 3 条（barrier 同步两个线程）→ 第 4 条（竞态成立）。

**命令与输出**：

```c
// race.c
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static volatile int balance = 100;
static volatile int won = 0;

static void *buy(void *arg) {
    (void)arg;
    if (balance >= 100) {
        usleep(1);              // 检查与扣款之间的窗口
        balance -= 100;
        if (balance < 0) won = 1;
    }
    return NULL;
}

int main(void) {
    pthread_t a, b;
    pthread_create(&a, NULL, buy, NULL);
    pthread_create(&b, NULL, buy, NULL);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    puts(won ? "race won: balance < 0" : "no race");
    return 0;
}
```

```c
// slow.c：覆盖 usleep，让两个线程都到达同一点后再继续
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static pthread_barrier_t bar;

__attribute__((constructor))
static void init_bar(void) {
    pthread_barrier_init(&bar, NULL, 2);
}

int usleep(useconds_t usec) {
    (void)usec;
    pthread_barrier_wait(&bar);
    return 0;
}
```

```bash
$ gcc -O0 -pthread race.c -o race
$ gcc -O0 -shared -fPIC -pthread slow.c -o slow.so
$ ./race
no race                       # 或 race won，取决于调度
$ LD_PRELOAD=./slow.so ./race
race won: balance < 0
```

**结果**：带 hook 时稳定输出 `race won: balance < 0`，说明两个线程都通过了 `balance >= 100` 的检查。真实题目把“余额为负”换成 double free / UAF / 双花读 flag 时，利用方法相同：**先找到检查与使用之间的函数，再用 `LD_PRELOAD` 或 barrier 把这个窗口变成确定顺序**；真实题目在该分支读到 `flag{...}`，以原题平台为准。

::: tip 从样例到真题
把 `balance` 换成堆指针，就是“一个线程 free、另一个线程继续写”的 UAF；把 `usleep` 换成 `close` / `read`，就是 fd 竞态。ARM 题则把同一套判断换成 `qemu-aarch64` + `ropper --arch arm64`。flag 以原题平台为准，本页不固定具体字符串。
:::
