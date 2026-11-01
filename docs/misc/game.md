# 游戏题

关键词：游戏题 AI 博弈 minimax 极小化极大 alpha-beta 剪枝 记忆化 置换表 井字棋 五子棋 Connect Four 四子棋 Nim 取石子 Sprague-Grundy SG 函数 协议逆向 自动对弈 pwntools game

## ① 识别指纹

- 题干说"和 AI 下棋"、"赢过服务器"、"连续获胜"、"拿到最高分"
- 附件是棋盘截图、规则说明，或者什么都没有、只给 `nc host port`
- 出现井字棋 3×3、五子棋、Connect Four、Nim 石子、猜数字、24 点、石头剪刀布
- 服务端每回合发一个棋盘 / 状态，等你发坐标或取法
- 有步数限制、时间限制，或要求连胜若干局
- 分值中高、通过率偏低，因为必须写 bot
- 题干或附件给了服务端源码、协议样例、棋盘编码说明

## ② 考什么

- **完全信息博弈**：minimax、negamax、alpha-beta 剪枝、记忆化、置换表
- **状态表示**：棋盘用数组 / 位棋盘 / 字符串，状态去重与对称性
- **组合博弈**：Nim 的 XOR 策略、Sprague-Grundy 函数
- **大空间搜索**：五子棋、Connect Four 的限深搜索与启发式评估
- **协议逆向**：棋盘行列数、空位符号、坐标基准、先后手、回合提示
- **自动对弈**：`recvline` / `recvuntil` → 解析 → 求解 → `sendline`
- **随机性**：固定种子、可预测序列、重复开局
- **规则漏洞**：非法坐标、负数、超量取子、重复落子、越界
- **超时与性能**：预计算开局库、缓存、降低搜索深度

## ③ 判断流程

### ③-1 子类型分流

1. 出现 3×3 棋盘、轮流落子、连成一线获胜 → 井字棋，跳到 ③-2 第 2 条。
2. 出现 15×15 或 19×19 棋盘、五连获胜 → 五子棋，跳到 ③-2 第 3 条。
3. 出现 7 列 × 6 行、四连获胜 → Connect Four，跳到 ③-2 第 3 条。
4. 出现石子堆、每次从一堆取走若干个、取走最后一个者获胜 → Nim，跳到 ③-2 第 4 条。
5. 没有规则说明，只有 `nc` 和未知报文 → 协议未知，跳到 ③-2 第 5 条先逆向协议。
6. 服务器给了源码或二进制 → 本地复现，跳到 ③-2 第 1 条。
7. 以上都不匹配 → 跳到 ③-2 第 1 条。

### ③-2 成本排序链

1. 按规则估算状态空间：规则未知 → 跳第 5 条；能全部枚举（井字棋、Nim、小棋盘）→ 跳第 2 条；不能全部枚举（五子棋、Connect Four）→ 跳第 3 条。
2. 完全求解：写 minimax / negamax + 记忆化，终局判胜、平局判 0，递归取最大值；本地自测先手不输 → 跳第 5 条；出现败局 → 检查终局判定和轮到谁，修正后回到本条重测；修正后仍败 → 跳第 9 条。
3. 大空间搜索：alpha-beta + 限深 + 启发式评估（连子数、中心权重、活三活四），本地对随机 AI 连续对局；能稳定取胜 → 跳第 5 条；出现败局 → 加深一层或改评估函数，仍败 → 跳第 6 条。
4. Nim / SG：算所有堆的 XOR；非 0 → 把某一堆减到 `pile ^ xor`；为 0 → 走最小合法步。先确认规则是"取走最后一个赢"还是"取走最后一个输"；标准规则直接执行，misère 规则在全为 1 的堆上特判。本地模拟连续对局全胜 → 跳第 5 条；有败局 → 跳第 1 条重新确认规则。
5. 协议逆向：手工 `nc` 记录开局到第一次落子后的完整收发，确定棋盘行列数、空位符号、坐标从 0 还是 1 开始、谁先手、每行是否带提示符；解析成功且求解器已就绪 → 跳第 7 条；解析成功但还没写求解器 → 跳第 1 条；解析不了 → 回到第 1 条，改用 `socat -v` 记录完整会话后重新解析。
6. 规则漏洞与随机性：依次试非法坐标、负数、超量取子、重复落子、越界下标；再收集多局开局，找固定种子或重复序列。服务端接受非法输入 → 直接利用，结束；找不到漏洞 → 回到第 1 条换假设。
7. 自动对弈：用 `pwntools` 循环 `recvline` / `recvuntil` → 解析局面 → 本地求解 → `sendline`；先对本地复现服务跑完整一局，再换远程地址；每一步核对服务端回显与本地模型，不一致 → 回第 5 条重解析协议；每一步一致且整局跑完 → 结束；单步超时 → 跳第 8 条。
8. 超时与限速：测单步耗时，预计算开局库、加置换表、降低搜索深度；仍然超时 → 回第 3 条换更轻的评估函数。
9. 兜底：以上全不成立 → 回到第 1 条，把多局完整流量存盘逐字节 diff，换粒度重看：整局 → 单步、文本协议 → 二进制协议。

## ④ 工具与命令

```bash
nc host port
socat -v TCP:host:port - 2>game.log    # 记录完整会话和十六进制转储
python3 -c "print(3 ^ 4 ^ 5)"          # Nim 起手：算出 2，说明先手必胜
```

```python
# 井字棋：negamax + 记忆化，3×3 只有 5478 个可达局面
from functools import lru_cache

LINES = [(0, 1, 2), (3, 4, 5), (6, 7, 8),
         (0, 3, 6), (1, 4, 7), (2, 5, 8),
         (0, 4, 8), (2, 4, 6)]

def winner(b):
    for a, c, d in LINES:
        if b[a] and b[a] == b[c] == b[d]:
            return b[a]
    return 0

@lru_cache(None)
def negamax(b, player):
    w = winner(b)
    if w:
        return (10 if w == player else -10), None
    if 0 not in b:
        return 0, None
    best = (-99, None)
    for i, v in enumerate(b):
        if v == 0:
            nb = b[:i] + (player,) + b[i + 1:]
            score, _ = negamax(nb, 3 - player)
            score = -score
            if score > best[0]:
                best = (score, i)
    return best

board = (0,) * 9
score, move = negamax(board, 1)
print(score, move)
```

```python
# 自动对弈骨架：局面解析和求解换成具体游戏
from pwn import remote, context

context.log_level = 'info'
io = remote('host', 1337)

while True:
    line = io.recvline().decode().strip()
    if not line:
        break
    if line.startswith('piles'):
        piles = list(map(int, line.split()[1:]))
        i, k = nim_move(piles)            # 见 ⑥ 的求解函数
        io.sendline(f'take {i} {k}'.encode())
    elif line in ('you win', 'you lose'):
        break
```

```python
# Nim 必胜手：把 XOR 打成 0
import functools

def nim_move(piles):
    x = functools.reduce(lambda a, b: a ^ b, piles)
    if x == 0:
        i = next(i for i, p in enumerate(piles) if p > 0)
        return i, 1
    for i, p in enumerate(piles):
        t = p ^ x
        if t < p:
            return i, p - t
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 棋盘解析出来是转置的 | 报文按列存，代码按行读 | 用服务端回显对照，打印 `board[i][j]` 和原始行 |
| 坐标总是差一格 | 服务端从 0 开始，脚本从 1 开始 | 先看角落落子后的回显，确认基准 |
| 第一步就报非法 | 服务端期望先手 / 后手不同 | 读清提示符，必要时先发一个探测坐标 |
| 每步都重连、局面重置 | 连接没有复用 | 整局只建一次连接 |
| 搜索超时 | 没有记忆化 / 深度太大 | 加 `lru_cache` / 置换表，或 alpha-beta 限深 |
| 明明能赢却判平局 | 题目要求必须赢，平局不算过 | 读胜负条件，平局分支要主动变招 |
| Nim 策略失效 | 规则是"取走最后一个输"的 misère 版 | 全为 1 的堆要特判，不能直接套普通 XOR |
| AI 有随机性，偶尔输 | 对手不是确定性策略 | 重开或针对种子预测；先确认能否接受重试 |
| 服务端回显和本地模型不一致 | 协议字段解析错，或走了非法步 | 每步比对回显，不一致立刻回第 5 条重解析 |
| 脚本速度够快但仍超时 | 网络往返次数太多 | 批量读、减少 debug 输出、预计算 |

## ⑥ 例题

**题目**：Nim 取石子
**来源**：自建样例（Nim 是组合博弈的经典入门题；真实比赛常以"取石子 / 取硬币"形式出现，按原题平台为准）

**题干**：三堆石子，数量分别为 3、4、5；双方轮流从任意一堆取走任意正数颗，取走最后一颗者获胜。赢过服务端即可拿 flag。

**附件**：无附件，只有一个本地复现服务（远程题以题干地址为准）。

**关键观察**：
- 初始三堆是 `3 4 5`，异或为 `3 ^ 4 ^ 5 = 2`，不为 0 —— 先手存在必胜策略
- 每步的目标是把对手回合开始时的 XOR 变成 0
- 服务端报文只有 `piles a b c` 和结果行，协议极简，适合先写求解器再接协议

**走了哪条链**：③-1 第 4 条（Nim）→ ③-2 第 4 条（XOR 策略）→ 第 7 条（自动对弈）。

**命令与输出**：

```text
$ python -I nim.py
wins 200 / 200
--- sample game ---
S: piles 3 4 5
C: take 0 2
S: piles 0 4 5
C: take 2 1
S: piles 0 0 4
C: take 2 4
S: you win
```

求解核心：

```python
import functools

def nim_move(piles):
    x = functools.reduce(lambda a, b: a ^ b, piles)
    if x == 0:
        i = next(i for i, p in enumerate(piles) if p > 0)
        return i, 1
    for i, p in enumerate(piles):
        t = p ^ x
        if t < p:
            return i, p - t
```

**结果**：对随机走法的服务端连打 200 局全胜；样例服务端只返回 `you win`，真实题目在获胜后返回 `flag{...}`，具体 flag 以原题平台为准。

**每一步在算什么**：
- 初始 `3 4 5`，XOR = `2`，找到第一堆满足 `3 ^ 2 = 1 < 3`，所以从第 0 堆取 `3 - 1 = 2` 颗
- 服务端随机走完后变成 `0 4 5`，XOR = `1`，第 2 堆 `5 ^ 1 = 4 < 5`，取 1 颗
- 服务端再走成 `0 0 4`，XOR = `4`，第 2 堆 `4 ^ 4 = 0`，取 4 颗，清空
- 对手无子可取，本局结束

**为什么 XOR 为 0 是必败态**：无论对手从哪一堆取多少，取完后 XOR 一定不再是 0；你总能再把 XOR 打回 0。如此反复，最后一次把石子取完的一定是你。前提是规则为"取走最后一个赢"；如果是"取走最后一个输"，全为 1 的堆要单独处理。

::: tip 先算胜负，再写协议
游戏题先判断"这局在数学上是否可解"，再花时间逆向协议。Nim 的 XOR、井字棋的 minimax 都是几十行代码；协议解析反而常常是更耗时的部分。
:::
