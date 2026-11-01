# 随机数预测

关键词：随机数预测 PRNG MT19937 randcrack LCG 线性同余 Java Random 48-bit php_mt_seed mt_rand 种子 seed getrandbits 伪随机

## ① 识别指纹

- 附件/远程服务连续吐出**一长串整数**，或者每轮给一个"随机"数，要求预测下一个
- 脚本出现 `import random`、`random.getrandbits`、`random.randint`、`random.randrange`、`random.seed`
- 脚本出现递推式 `s = (a*s + c) % m`，或 `state = (state * A + B) % M`
- 语言线索：`java.util.Random` / `nextInt()` / `nextLong()`；PHP 的 `mt_rand` / `mt_srand`
- 题干出现 `predict` / `random` / `seed` / `LCG` / `MT` / `猜数字`
- 题目给"时间种子"、`time()`、`os.urandom` 的替代品，或要求"预测下一轮抽奖结果"
- 输出数量很大（成百上千个），或要求提交下一个输出

## ② 考什么

- **Python `random` 是 MT19937**：内部状态 624 个 32-bit 字，连续 624 个 32-bit 输出可还原状态
- **`randcrack`**：喂满 624 个 32-bit 输出后克隆，预测后续
- **LCG 参数恢复**：`s_{n+1} = a·s_n + c mod m`；`m` 已知时 3 个连续输出解 `a, c`；`m` 未知时用二阶差分 + `gcd` 求 `m`
- **Java `Random`**：48-bit 内部状态，`nextInt()` 给高 32 位；2 个 `nextInt()` 或 1 个 `nextLong()` 可恢复
- **PHP `mt_rand`**：31-bit 输出，`php_mt_seed` 爆破种子，或按 MT19937 恢复状态
- **输出格式还原**：十进制/hex/base64/取模/浮点 → 怎么变回 32-bit 整数
- 种子：时间戳、PID、`time()` 低位；`php_mt_seed`、Java 时间种子爆破

## ③ 判断流程

### ③-1 子类型分流

1. 脚本 `import random`，或输出是 Python 的 `getrandbits` / `randint` → **Python MT19937 路径**，跳 ③-2 第 1 条
2. 脚本出现 `(a*s + c) % m` 或明显的线性递推 → **LCG 路径**，跳 ③-2 第 5 条
3. 脚本/题干是 Java，出现 `java.util.Random`、`nextInt`、`nextLong` → **Java Random 路径**，跳 ③-2 第 8 条
4. 脚本/题干是 PHP，出现 `mt_rand` / `mt_srand` → **PHP MT 路径**，跳 ③-2 第 9 条
5. 算法未知，但输出可复现/与时间相关 → **种子爆破路径**，跳 ③-2 第 10 条
6. 以上都不是 → 回第 1 条，确认输出是否被哈希/加密/编码过，先还原成原始整数

### ③-2 成本排序链

1. 先把每个输出还原成整数：十进制直接 `int`，hex 用 `int(s,16)`，base64 先 `b64decode` 再 `int.from_bytes`，继续第 2 条
2. 确认位宽：`getrandbits(32)` / `randint(0, 2^32-1)` 是完整 32 bit → 第 3 条；只有 31 bit、被取模、或浮点 → 视为截断，跳第 4 条
3. 收集到 **624 个连续 32-bit 输出**：全部 `rc.submit(x)` 后 `rc.predict_getrandbits(32)`，预测成功 → 结束；不足 624 个 → 第 4 条
4. 输出被截断（只给高位/低位/浮点）→ 用位重建或格恢复 MT 状态，结束本页流程，转 [格密码](/crypto/lattice)；无法重建 → 第 11 条
5. LCG 且 `m` 已知：取 3 个连续输出 `s0,s1,s2`，`a = (s2-s1)/(s1-s0) mod m`，`c = s1-a·s0 mod m`，预测下一个 → 结束
6. LCG 且 `m` 未知：取 ≥5–6 个连续输出，令 `t_i = s_{i+1}-s_i`，`m = gcd(t_{i+1}·t_{i-1} - t_i²)`；用候选值按第 5 条解 `a,c` 并回代验证，通过 → 结束；不通过 → 去掉候选值的小因子后重试第 5 条
7. LCG 输出被截断（只给高位）→ 用 Coppersmith/格恢复 `a,c,m` 或状态，结束本页流程，转 [格密码](/crypto/lattice)
8. Java `Random`：拿 2 个连续 `nextInt()`（或 1 个 `nextLong()`），爆破低 16 位（`2^16`）恢复 48-bit 状态，预测下一个 → 结束
9. PHP `mt_rand`：收集若干输出，用 `php_mt_seed` 爆破种子；或按 MT19937 的 624 个状态恢复 → 结束
10. 题干给了 `time()`、毫秒时间戳或 PID 作为种子 → 枚举 `time()` 前后若干秒、PID、常见种子格式，逐个 `seed` 后比对第一个输出；命中 → 结束；不中 → 第 11 条
11. 以上都不成立 → 回第 1 条，确认题目是否对输出做了 `% 1000`、异或、加密；先逆掉这一层再判断算法

## ④ 工具与命令

```bash
pip install randcrack
```

```python
# Python MT19937：624 个 32-bit 输出克隆
from randcrack import RandCrack

rc = RandCrack()
for x in outputs[:624]:        # 每个都必须是 32-bit 整数
    rc.submit(x)
print(rc.predict_getrandbits(32))
```

```python
# LCG：m 已知，3 个输出解 a、c
a = (s2 - s1) * pow(s1 - s0, -1, m) % m
c = (s1 - a * s0) % m
next_s = (a * s2 + c) % m

# LCG：m 未知，6 个输出用二阶差分 + gcd
from math import gcd
t = [s[i+1] - s[i] for i in range(len(s) - 1)]
m = 0
for i in range(1, len(t) - 1):
    m = gcd(m, t[i+1]*t[i-1] - t[i]*t[i])
# m 可能是真实模数的小倍数：去掉小因子后逐个验证
```

```python
# 把题目输出还原成 32-bit 整数
import base64
x1 = int(s, 10)
x2 = int(s, 16)
x3 = int.from_bytes(base64.b64decode(s), 'big')
# 若服务端打印 random.random()：
f = float(s)
n53 = int(f * (2**53))          # 53 bit，来自两次 getrandbits
hi27, lo26 = n53 >> 26, n53 & ((1 << 26) - 1)
```

```bash
# PHP mt_rand 种子
php_mt_seed <output1> <output2> <output3> <output4>
# Java 时间种子：枚举 millis 附近的种子，比对 nextInt()
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `randcrack` 喂了 624 个还是预测错 | 输出不是 32-bit（是 31-bit、取模、或浮点） | 先还原成完整的 32-bit 整数；截断输出不能用 randcrack 直接喂 |
| 624 个输出对不上 | 中间隔了别的 `random` 调用（如 `randint` 的拒绝采样） | 找只走 `getrandbits(32)` 的连续输出，或把中间调用算进去 |
| LCG 用 3 个输出解不出 `m` | 3 个输出只有两个方程，`m` 是第三个未知量 | `m` 未知时用 5–6 个输出做二阶差分 gcd |
| gcd 求出的 `m` 比真实模数大 | 只用了两个差分项，gcd 含小因子 | 多用几项，或去掉小因子后逐个验证输出 |
| `pow(s1-s0, -1, m)` 报错 | `gcd(s1-s0, m) != 1`，逆元不存在 | 解线性同余 `(s1-s0)·a ≡ s2-s1 mod m`，用扩欧或枚举 |
| Java 用 `nextInt(bound)` 当 `nextInt()` | `nextInt(bound)` 有拒绝采样，位数不固定 | 用无参 `nextInt()` 或 `nextLong()` |
| PHP 输出只有 31 bit | `mt_rand()` 返回 0..2^31-1 | 用 `php_mt_seed`，不要直接按 32-bit 喂 randcrack |
| 时间种子爆破不中 | 种子是 `time()*1000+pid` 之类的组合 | 枚举时间窗口 + PID/计数器，或看脚本的 seed 生成 |
| 预测下一个总差一位 | 输出被 `% 2^k` 截断 | 用多个截断输出联立，或上格 |

## ⑥ 例题

**题目**：LCG 参数恢复与预测
**来源**：自建样例，参数由 Python 现场生成并验证；对应 CTF 中"给一串随机数，预测下一个"的经典题型

**题干**：服务端连续输出 8 个整数，内部使用 `s = (a*s + c) mod m`：

```text
outputs = [20261101, 185053411, 40413531, 46720856,
           763745958, 1798022867, 1068414455, 1838698001]
```

不给 `a, c, m`，求下一个输出。

**关键观察**：
- 输出是线性递推，`t_i = s_{i+1} - s_i` 满足 `t_{i+1} = a·t_i mod m`
- 因此 `m` 整除 `t_{i+1}·t_{i-1} - t_i²`；用多个这样的项取 `gcd` 就能得到 `m`
- 这里给了 8 个输出，足够算多个差分项；`gcd` 恰好就是 `m`

**走了哪条链**：③-1 第 2 条（LCG）→ ③-2 第 6 条（`m` 未知）→ 第 5 条（`m` 已知后解 `a,c`）。

**命令与输出**：

```python
from math import gcd

outs = [20261101, 185053411, 40413531, 46720856,
        763745958, 1798022867, 1068414455, 1838698001]
t = [outs[i+1] - outs[i] for i in range(len(outs) - 1)]

m = 0
for i in range(1, len(t) - 1):
    m = gcd(m, t[i+1]*t[i-1] - t[i]*t[i])
print('gcd =', m)

a = (outs[2] - outs[1]) * pow(outs[1] - outs[0], -1, m) % m
c = (outs[1] - a * outs[0]) % m
print('a =', a, 'c =', c)
print('predict =', (a * outs[-1] + c) % m)
```

输出：

```text
gcd = 2147483647
a = 1103515245 c = 12345
predict = 2082061785
```

代回验证：`(a * 1838698001 + c) % 2147483647 == 2082061785`，与真实的下一个输出一致。

**结果**：`m = 2147483647`，`a = 1103515245`，`c = 12345`，下一个输出是 `2082061785`。真实题目的"下一个输出"通常就是验证码/flag 的一部分；样例数字不是任何真实题目的参数，提交以原题平台为准。

::: tip 迁移
如果题目只给 3 个输出且没给 `m`，不要硬解：先看题目有没有给 `m`（常见 `2^31-1`、`2^32`、`2^48`），有就直接用第 5 条。如果没有，继续多要几个输出，或者看脚本里有没有 `m` 的生成逻辑。MT19937 题则完全换一套：凑够 624 个 32-bit 输出，直接 `randcrack`。
:::
