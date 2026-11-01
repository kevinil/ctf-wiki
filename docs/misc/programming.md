# 编程题与交互题

关键词：编程题 交互题 自动交互 pwntools remote recvuntil sendlineafter nc 算法题 输入格式 约束求解 z3 sympy 超时 限速 PoW 哈希现金 脚本编程 programming

## ① 识别指纹

- 题干只给 `nc host port`，或者"连接服务器"，附件为空 / 只有一段说明
- 附件是 `.py` / `.sage` / `.txt`，里面是算法描述或服务端源码
- 题目要求"连续答对 N 题"、"在限制时间内完成"、"自动交互"
- 分类在 Misc / Programming，不是 Pwn：没有二进制、没有溢出、没有内存破坏
- 连上去先出现数学题、菜单、编码题、棋盘或 Proof-of-Work
- 题干有"输入格式 / 输出格式 / 多组数据 / 样例"
- 题目给了服务端脚本，或明确说"你可以本地起服务测试"
- 通过率不低但耗时长，很多人卡在"手点太慢"

## ② 考什么

- **协议读写**：提示符、行尾、菜单、JSON / base64 字段
- **自动化**：`pwntools` 的 `remote` / `recvuntil` / `sendlineafter`，或标准库 `socket`
- **算法实现**：严格按题目的输入格式读、按输出格式写，处理多组数据与边界
- **约束求解**：`z3` 解整数 / 位向量 / 布尔约束，`sympy` 解方程与数论
- **Proof-of-Work**：按题目要求找满足哈希前缀的 nonce
- **超时与限速**：测量单轮耗时，减少往返，预计算查表
- **状态保持**：一局游戏或一次挑战必须复用同一条连接
- **本地复现**：先把服务端跑起来，把交互逻辑跑通，再换远程地址
- **异常处理**：连接重置、EOF、编码错误、字段顺序变化

## ③ 判断流程

### ③-1 子类型分流

1. 题干给 `nc host port`，附件为空或只是说明 → 交互题，跳到 ③-2 第 1 条。
2. 连接后首屏要求提交一个满足哈希条件的字符串 → PoW，跳到 ③-2 第 2 条。
3. 附件是源码 / 脚本，含算法与输入输出格式 → 算法题，跳到 ③-2 第 3 条。
4. 题目给方程、约束、密码学参数，要求求未知量 → 约束题，跳到 ③-2 第 4 条。
5. 交互中连续出现同构小题（算术、编码、判断）→ 自动化循环，跳到 ③-2 第 5 条。
6. 以上都不匹配 → 跳到 ③-2 第 1 条，先手工连一次看协议。

### ③-2 成本排序链

1. 手工 `nc host port` 连一次，完整记录首屏到第一次作答的收发 → 确定提示符、行尾是 `\n` 还是 `\r\n`、题目字段、是否需要立刻回答；首屏是 PoW → 跳第 2 条；首屏没有 PoW 且协议能复述清楚 → 跳第 5 条；协议复述不清 → 跳第 7 条。
2. 首屏是 PoW → 从题目里抄出哈希算法、前缀和难度，枚举 nonce 计算哈希直到满足条件；通过后回到第 1 条重新看协议；首屏不是 PoW → 跳第 7 条。
3. 附件是算法题 → 按题目的输入格式写 `solve.py`，先用样例自测，输出格式逐字符对齐（空格、换行、大小写）；样例通过 → 提交，结束；不通过 → 检查输入格式并重写，仍不通过 → 跳第 8 条。
4. 题目可以写成约束 → 用 `z3` 建变量和约束，或 `sympy` 列方程；先在小样例上验证解，再代入原题；有解 → 输出，结束；无解 → 检查变量范围、整数性、边界条件后重试，仍无解 → 跳第 8 条。
5. 自动化交互：用 `pwntools` 或 `socket` 写循环，`recvuntil(提示符)` → 解析 → 计算 → `sendline`；先在本地复现服务上跑通完整一局，再替换成远程地址；本地通过、远程失败 → 跳第 6 条。
6. 超时、限速或断线：测量单轮往返耗时，减少 I/O（一次读多行、批量计算），把重复计算改成预计算查表；仍然超时 → 跳第 8 条。
7. 协议异常（乱码、字段变长、二进制）：打印原始字节（`print(repr(data))` 或 `hexdump`），按字段偏移重新解析；仍解析不了 → 回到第 1 条，用 `socat -v` 抓一次完整会话；换粒度后仍解析不了 → 跳第 8 条。
8. 兜底：以上全不成立 → 回到第 1 条，换粒度重看：按行 → 按字节、单题 → 整局、远程 → 本地；把服务端源码或附件当协议文档逐行读。

## ④ 工具与命令

```bash
nc host port                       # 手工看协议
nc -v host port
socat -v TCP:host:port - 2>session.log   # 带十六进制转储的会话记录
timeout 60 python3 solve.py        # 本地给脚本加超时，防止卡死
```

```python
# pwntools：先本地，再远程
from pwn import remote, process, context

context.log_level = 'info'

# io = process(['python3', 'server.py'])      # 本地复现
io = remote('host', 1337)

while True:
    line = io.recvline().decode().strip()
    if not line:
        break
    print('S:', line)
    if line.endswith('= ?'):
        a, op, b = line.split(' = ?')[0].split()   # 解析 "12 + 30 = ?"
        ans = ...                             # 按 op 计算
        io.sendline(str(ans).encode())
    if line.startswith('flag{'):
        break
```

```python
# 标准库 socket：不依赖 pwntools 的最小循环
import socket

s = socket.create_connection(('host', 1337))
f = s.makefile('rwb', buffering=0)
buf = b''
while True:
    ch = f.read(1)
    if not ch:
        break
    buf += ch
    if buf.endswith(b'\n'):
        line = buf.decode().strip()
        buf = b''
        print('S:', line)
        # 解析 line，算出答案，然后：
        # f.write(b'answer\n')
```

```python
# 本地复现服务：和上面的客户端放进同一个脚本，先起线程再连
import socket, threading

def handle(conn):
    conn.sendall(b'welcome to quickmath\n')
    for q, ans in [('12 + 30', 42), ('7 * 8', 56), ('100 - 37', 63)]:
        conn.sendall(f'{q} = ?\n'.encode())
        if conn.recv(1024).strip() != str(ans).encode():
            conn.sendall(b'wrong\n'); conn.close(); return
    conn.sendall(b'flag{quick_math_demo}\n'); conn.close()

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 40007))
srv.listen(1)
threading.Thread(target=lambda: handle(srv.accept()[0]), daemon=True).start()
```

```python
# 约束：z3
from z3 import Int, Solver, sat

x, y = Int('x'), Int('y')
s = Solver()
s.add(x + y == 10, x - y == 4, x > 0, y > 0)
if s.check() == sat:
    m = s.model()
    print(m[x], m[y])
```

```python
# 约束：sympy
from sympy import symbols, solve

a, b = symbols('a b')
print(solve([a + b - 10, a - b - 4], [a, b]))
```

实测输出：

```text
{a: 7, b: 3}
```

```python
# Proof-of-Work
import hashlib

prefix = b'...'                     # 服务端给的前缀
for n in range(10 ** 9):
    if hashlib.sha256(prefix + str(n).encode()).hexdigest().startswith('0000'):
        print(n)
        break
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `recvuntil` 一直卡住 | 提示符不一致，或服务端没有换行 | 先 `recvline` 循环打印原始行，确认实际提示符 |
| 本地脚本正常，远程失败 | 行尾、编码或缓冲方式不同 | 统一用 `sendline`，按字节处理，检查 `\r\n` |
| 每答一题就断线 | 脚本每题重连，状态被重置 | 整局复用同一条连接，只在开局连一次 |
| 答案正确却判错 | 输出格式多了空格、少了换行、大小写不同 | 严格按样例输出，逐字符比对 |
| 跑着跑着超时 | 单轮往返太多或搜索太慢 | 批量读取、预计算查表、降低每轮 I/O |
| 浮点答案被判错 | 题目要整数或固定小数位 | 读清楚输出格式，必要时用分数 / 整数运算 |
| `z3` 返回 unsat | 变量范围没写，或用了错误的类型 | 补边界，区分 `Int` / `BitVec`，检查 `Distinct` |
| PoW 一直算不出来 | 哈希算法、前缀或难度抄错 | 从服务端原文复制参数，确认大小写和编码 |
| 多组数据只读了第一组 | 没按题目给的组数循环 | 先读组数 `T`，再循环 `T` 次 |
| 大整数结果溢出 | 用了 C++ / 固定宽度整数 | 用 Python 原生大整数，或改 `gmpy2` |

## ⑥ 例题

**题目**：连续答题的交互服务
**来源**：自建样例（"nc 连上去连续算题"是交互题最常见的形态；实际比赛按原题平台为准）

**题干**：连接服务后连续回答算术题，每题一行答案，全部答对后返回 flag。

**附件**：无附件，只有一个 `nc 127.0.0.1 40007`（本地复现端口；远程题以题干给的地址为准）。

**关键观察**：
- 首屏是 `welcome to quickmath`，随后每行形如 `12 + 30 = ?`
- 题目行以换行结尾，服务端在等一行输入，不是在等单字节
- 三题结构完全相同，可以写一个"读到 `= ?` → 解析 → 计算 → 发送"的循环
- 本地服务端和客户端可以放在同一个脚本里，先把解析逻辑跑通

**走了哪条链**：③-1 第 1 条（只有 `nc`）→ ③-2 第 1 条（手工看协议）→ 第 5 条（自动化循环）。

**命令与输出**：

```text
$ python -I prog_server.py
S: welcome to quickmath
S: 12 + 30 = ?
C: 42
S: 7 * 8 = ?
C: 56
S: 100 - 37 = ?
C: 63
S: flag{quick_math_demo}
```

对应的客户端核心逻辑：

```python
import socket, operator

OPS = {'+': operator.add, '-': operator.sub, '*': operator.mul}
s = socket.create_connection(('127.0.0.1', 40007))
f = s.makefile('rwb', buffering=0)

buf = b''
while True:
    ch = f.read(1)
    if not ch:
        break
    buf += ch
    if buf.endswith(b'\n'):
        line = buf.decode().strip()
        buf = b''
        print('S:', line)
        if '= ?' in line:
            a, op, b = line.split(' = ?')[0].split()
            ans = OPS[op](int(a), int(b))
            print('C:', ans)
            f.write(f'{ans}\n'.encode())
        if line.startswith('flag{'):
            break
```

**结果**：三题全部答对，服务端返回 `flag{...}`；上例中的 `flag{quick_math_demo}` 是本地样例值，真实题目以原题平台为准。

**为什么先本地跑通**：本地能同时看到服务端和客户端，协议字段、行尾、提示符都可以直接对照；把这套解析逻辑搬到远程时，只需要把 `socket.create_connection` 换成 `remote(host, port)`，其余代码不动。反过来先连远程调试，每次出错都分不清是协议理解错还是网络问题。

::: tip 交互题的第一原则
**不要手点。** 只要出现第二道同构小题，就停下来写循环；手点不仅慢，还会在超时前答不完。
:::
