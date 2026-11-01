# 离散对数与 DH

关键词：离散对数 DLP BSGS baby-step giant-step Pohlig-Hellman 光滑阶 小群攻击 small subgroup DH Diffie-Hellman discrete_log sage 整数群

## ① 识别指纹

- 题干给三个大整数 `p`、`g`、`y`，问满足 `y = g^x mod p` 的 `x`
- 脚本里出现 `pow(g, x, p)`，或者 `g^x % p`
- 题目是一个 **DH 密钥交换服务**：服务端发 `A = g^a mod p`，收你的 `B`，回一个用共享密钥加密的 token
- 附件里有 `p-1` 的分解、`smooth`、`order`、`subgroup` 这类词
- 题目名带 `dlog` / `dh` / `discrete` / `baby` / `pohlig` / `离散对数`
- `p` 通常几百 bit；`p-1` 可能被故意构造成光滑数

> 本页只处理**整数乘法群** `(Z/pZ)*`。椭圆曲线上的 DLP 在 [椭圆曲线 ECC](/crypto/ecc)。

## ② 考什么

- 整数群 DLP：`y = g^x mod p`，已知 `p, g, y` 求 `x`
- **BSGS**（baby-step giant-step）：`O(√n)` 时间和空间
- **Pohlig-Hellman**：`p-1` 光滑时，把 DLP 拆到每个素因子幂再 CRT
- 阶与生成元：`ord(g)` 可能远小于 `p-1`，解只在模 `ord(g)` 意义下唯一
- **DH 参数过小**：`p` 位数不够，直接 `discrete_log`
- **`g` 不是生成元**：子群太小，或私钥信息泄露
- **小群攻击**：服务端不校验公钥，攻击者发送小阶元素，逐个小模数恢复私钥再 CRT
- 大素数域 DLP：`p-1` 有大素因子时只能上 NFS（`cado-nfs`），成本高

## ③ 判断流程

### ③-1 子类型分流

1. 题目给 `p, g, y` 三个整数，求 `x` → **整数群 DLP 路径**，跳 ③-2 第 1 条
2. 题目是 DH 交互（发公钥、收公钥、回共享密钥加密的数据）→ **DH 协议路径**，跳 ③-2 第 8 条
3. 未知量是椭圆曲线上的点倍关系 → **不是本页**，结束，转 [椭圆曲线 ECC](/crypto/ecc)
4. 题目是 `m = c^d mod n` 的 RSA 结构 → **不是本页**，结束，转 [RSA 攻击](/crypto/rsa)
5. 以上都不成立 → 回第 1 条确认未知量在指数上、模数是整数而不是曲线

### ③-2 成本排序链

1. 看 `p` 的位数：`p < 2^48` → 直接 Sage `discrete_log` 或 BSGS，结束；`p ≥ 2^48` → 第 2 条
2. `isprime(p)`：不是素数 → 跳第 7 条；是素数 → 第 3 条
3. 用 `p-1` 的小素因子逐个除，求最小的 `M` 使 `pow(g, M, p) == 1`：若 `M < 2^48` → 对 `ord(g)` 做 BSGS，结束；否则第 4 条
4. 完全分解 `p-1`（`factorint` / Sage `factor`）：最大素因子 `< 2^40` → Pohlig-Hellman，跳第 5 条；分解不动或最大因子很大 → 第 6 条
5. Pohlig-Hellman：对每个 `q^e || p-1` 在子群 `g^((p-1)/q^e)` 上做 BSGS，得到 `x mod q^e`，再用 CRT 合并，结束
6. 已定位 `p-1` 的最大素因子 `q`（题目给了分解或部分分解）：`q < 2^40` → 对 `q` 做 BSGS，与其余因子 CRT 合并，结束；`2^40 ≤ q < 2^256` → 用 `cado-nfs` 的 NFS 模式（位数越高越慢），结束；`q ≥ 2^256` → 跳第 10 条
7. `p` 非素数：分解 `p = ∏ q_i^{e_i}`，对每个素数幂做 DLP（`q_i^e` 用逐位提升），CRT 合并，结束
8. DH 参数审计：`p` 位数 `< 256` → 用 `cado-nfs` 的 NFS 模式解离散对数，结束；`g == 1` → 共享密钥恒为 1，结束；`g == p-1` → 密钥只有 ±1，结束；否则第 9 条
9. DH 小群攻击：服务端接受任意公钥且不回验 → 发送阶为小 `q` 的元素，观察共享密钥得到私钥 `mod q`，换多个 `q` 后 CRT 恢复完整私钥，结束；服务端验证公钥在 `⟨g⟩` 内 → 跳第 10 条
10. 以上都不成立 → 回第 1 条，确认题目是否给了 `x` 的部分信息（高位/低位）或 `p-1` 的分解；都没有则用 `cado-nfs` 算大素数域 DLP（成本高），或回读题找额外泄露

## ④ 工具与命令

```python
# BSGS：y = g^x mod p，n 是 g 的阶
import math
def bsgs(g, y, p, n):
    m = math.isqrt(n) + 1
    table = {}
    e = 1
    for j in range(m):                 # baby steps: g^j
        table.setdefault(e, j)
        e = e * g % p
    factor = pow(g, -m, p)             # giant steps: y * g^(-im)
    gamma = y
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None
```

```python
# Pohlig-Hellman：p-1 光滑时逐因子求解再 CRT
from math import prod
from sympy import factorint

def crt(rs, ms):
    M = prod(ms)
    return sum(r * (M // m) * pow(M // m, -1, m) for r, m in zip(rs, ms)) % M

def pohlig_hellman(g, y, p):
    residues, moduli = [], []
    for q, e in factorint(p - 1).items():
        qe = q ** e
        gamma = pow(g, (p - 1) // qe, p)   # 阶为 q^e 的子群生成元
        h = pow(y, (p - 1) // qe, p)
        xq = bsgs(gamma, h, p, qe)
        residues.append(xq); moduli.append(qe)
    return crt(residues, moduli)
```

```python
# Sage：一行梭，适合 p 不大或阶光滑
p = ...
F = GF(p)
x = discrete_log(F(y), F(g))          # 解 g^x = y
factor(p - 1)                          # 先看光滑性，决定能否走 Pohlig-Hellman
```

```bash
# 大素数域 DLP：cado-nfs 的 DLP 模式（参数以官方 README 的 -dlp 小节为准）
# 小 p 直接本地跑
sage -c "print(discrete_log(Mod(35652265716,603844273183), Mod(10,603844273183)))"
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| BSGS 建表把内存打满 | `n = p-1` 而不是 `ord(g)`，或 `p` 有几百 bit | 先算 `ord(g)`；不光滑就别硬上 BSGS |
| `discrete_log` 解出来不是题目要的那个 `x` | 解只在模 `ord(g)` 意义下唯一，可能有多个 | 用 `pow(g, x, p) == y` 验证；按题目范围取 `x + k·ord(g)` |
| `g` 不是生成元但没发现 | `pow(g, (p-1)//q, p) == 1` 对某个 `q` 成立 | 用实际阶 `ord(g)` 做 DLP，不要用 `p-1` |
| `p-1` 分解不动 | 含大素因子，Pohlig-Hellman 失效 | 对最大因子单独 BSGS，或 NFS |
| `p` 不是素数 | 模数不是域，逆元/阶的性质都变了 | 分解 `p`，按素数幂分别做再 CRT |
| DH 算出的共享密钥对不上 | 对方公钥不在 `⟨g⟩` 里 | 检查 `pow(y, ord(g), p) == 1` |
| 小群攻击收不到有效余数 | 服务端校验了公钥或点 | 换攻击面：参数太小、`g=1`、私钥泄露 |
| 题目给的 `g` 很大但阶很小 | 出题人故意选了小阶元素 | 先算阶，阶小直接 BSGS，成本按阶算 |

## ⑥ 例题

**题目**：光滑阶上的离散对数（Pohlig-Hellman）
**来源**：自建样例，参数由 Python 现场生成；对应 CTF 中 `p-1` 光滑的经典 DLP 题型

**题干**：

```text
p = 603844273183
g = 10
y = 35652265716
求 x，使 g^x ≡ y (mod p)
```

**关键观察**：
- `p` 只有 40 bit，但直接 BSGS 也要 `√p ≈ 2^20` 的表
- `p-1 = 2 · 3 · 23² · 31 · 41 · 43 · 59²`，最大素因子只有 59 —— **完全光滑**
- 因此可以对每个 `q^e` 单独求 `x mod q^e`，再 CRT

**走了哪条链**：③-1 第 1 条（整数群 DLP）→ ③-2 第 1 条（`p < 2^48`，本来可以直接 BSGS）→ 第 2 条（素数）→ 第 4 条（`p-1` 光滑）→ 第 5 条（Pohlig-Hellman）。

**命令与输出**：

```python
from sympy import factorint
from sympy.ntheory.residue_ntheory import discrete_log
# bsgs、crt、pohlig_hellman 见 ④

p = 603844273183
g = 10
y = 35652265716

print('p-1 =', factorint(p - 1))
print('sympy =', discrete_log(p, y, g))     # sympy 的签名是 discrete_log(n, a, b)，解 b^x = a
print('PH    =', pohlig_hellman(g, y, p))
print('verify =', pow(g, pohlig_hellman(g, y, p), p) == y)
```

输出：

```text
p-1 = {2: 1, 3: 1, 23: 2, 31: 1, 41: 1, 43: 1, 59: 2}
sympy = 184838556118
PH    = 184838556118
verify = True
```

逐因子余数（Pohlig-Hellman 的中间结果）：

```text
q^e = 2     residue = 0
q^e = 3     residue = 1
q^e = 529   residue = 107
q^e = 31    residue = 10
q^e = 41    residue = 12
q^e = 43    residue = 22
q^e = 3481  residue = 729
```

**结果**：`x = 184838556118`。代回 `pow(10, 184838556118, 603844273183)` 得到 `35652265716`，与 `y` 一致。真实题目的 `x` 通常就是私钥或 flag 的种子，提交以原题平台为准。

::: tip 迁移
比赛里 `p` 往往是 512～2048 bit，但 `p-1` 被故意做成光滑数。拿到题先 `factor(p-1)` 或看题干给的分解：只要最大素因子够小，Pohlig-Hellman 就能把 `O(√p)` 降成 `O(√q_max)`。如果 `p-1` 含一个大素因子，剩下的那部分只能 BSGS 或 NFS。
:::
