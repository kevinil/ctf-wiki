# 哈希攻击与数论杂项

关键词：哈希攻击 CRT 中国剩余定理 二次剩余 Legendre 符号 Tonelli-Shanks 模开方 Pollard rho 欧拉函数 阶 gcd 攻击 模方程 数论

## ① 识别指纹

- 题目给多组同余式 `x ≡ a_i mod m_i`，或给多组余数要求合并
- RSA 变体里出现 `e = 2`、`m^2 mod n`、`pow(m, 2, n)`、"平方剩余"、"开方"
- 题目给了 `n` 但没有 `p、q`，要求先分解；`n` 有中小因子、`p-1` 光滑、或两个 `n` 共享因子
- 题干出现 `CRT` / `remainder` / `mod` / `sqrt` / `Legendre` / `residue` / `phi` / `order` / `gcd`
- 脚本里出现 `pow(a, (p-1)//2, p)`、`inverse`、`gcd(...)`、`factorint`
- 题目名带 `crt` / `math` / `number` / `sqrt` / `residue` / `pollard` / `gcd`
- 分数不高，但需要自己写几行数论代码，工具脚本往往不能直接一把梭

> 哈希长度扩展攻击与 MD5/SHA1 碰撞已经写在 [编码与哈希基础](/crypto/encoding-hash)，本页不重复；本页只处理 CRT、二次剩余、分解、gcd 与模方程。

## ② 考什么

- **CRT（中国剩余定理）**：互素模数直接合并；不互素时先检查 `gcd(m_i,m_j)` 是否整除差
- **哈希题的数论侧**：CRT、模开方、gcd；长度扩展与碰撞见 [编码与哈希基础](/crypto/encoding-hash)
- **二次剩余**：`x² ≡ a mod p` 的可解性（Legendre 符号）、`Tonelli-Shanks` 开方
- **合数模开方**：`n = p·q` 时有 4 个根，需要 CRT 组合并挑可打印的那个
- **Euler 函数与阶**：`φ(n)`、`ord_n(a)`、`a^x ≡ 1 mod n` 的最小指数
- **Pollard rho / Pollard p-1**：中小因子的分解；`p-1` 光滑时优先 p-1
- **gcd 相关攻击**：共因子、`gcd(c1-c2, n)`、`gcd(a-b, n)`、两个模数共享因子
- **模方程**：线性同余、指数同余、二次同余的统一处理
- 工具：`sympy`、`gmpy2`、`yafu`、`factordb`、Sage

## ③ 判断流程

### ③-1 子类型分流

1. 题目给多个同余式 `x ≡ a_i mod m_i` → **CRT 路径**，跳 ③-2 第 1 条
2. 题目出现 `e = 2`、平方、开方、Legendre/二次剩余 → **二次剩余路径**，跳 ③-2 第 4 条
3. 题目给 `n` 要求先分解（RSA 变体、大整数分解）→ **分解路径**，跳 ③-2 第 7 条
4. 题目出现 `gcd`、共因子、模数不互素、两个 `n` 共享因子 → **gcd 攻击路径**，跳 ③-2 第 9 条
5. 题目是哈希长度扩展/碰撞 → **不是本页**，结束，转 [编码与哈希基础](/crypto/encoding-hash)
6. 以上都不是 → 回第 1 条，把方程写成标准形式（未知量、模数、次数），确认是否其实归到 RSA/ECC/格

### ③-2 成本排序链

1. CRT：检查所有模数两两互素；互素 → 直接合并出唯一解 `mod ∏m_i`，结束；不互素 → 第 2 条
2. 非互素 CRT：对每对 `(m_i, a_i)`、`(m_j, a_j)` 检查 `gcd(m_i,m_j)` 是否整除 `a_i - a_j`；不整除 → 该方程组无解，回读题；整除 → 合并成 `lcm` 模数，重复到只剩一个，结束
3. CRT 合并后是"`m^e < ∏n_i` 的广播" → 先 CRT 再对结果开 `e` 次方，结束；开方不整 → 第 4 条
4. 二次剩余：对每个奇素数 `p` 算 Legendre `pow(a,(p-1)//2,p)`；结果 `1` → 有解，跳第 5 条；结果 `p-1`（即 -1）→ 无解，结束；结果 `0` → `p | a`，根是 `0`，结束
5. 开方：`p % 4 == 3` 时 `x = pow(a,(p+1)//4,p)`；否则 Tonelli-Shanks；合数模 `n = p·q` 对 `p、q` 分别开方后 CRT 组合出 4 个根，挑可打印的，结束
6. 模数是合数且未分解 → 先跳第 7 条分解，再回第 5 条对每个素因子开方 + CRT
7. 分解：先试小因子/查 `factordb`；`n` 有 ≤ 2^60 的因子 → Pollard rho；`p-1` 光滑 → Pollard p-1；仍不行 → ECM / `yafu` / `cado-nfs`；分解成功 → 结束
8. 分解成功后：算 `φ(n) = ∏(p_i-1)p_i^{e_i-1}`、`d = e^{-1} mod φ(n)`、`m = c^d mod n`；RSA 结构结束本页流程，转 [RSA 攻击](/crypto/rsa)，结束
9. gcd 攻击：算 `gcd(c1-c2, n)`、`gcd(a-b, n)`、两个 `n` 的 `gcd(n1,n2)`、`gcd(pow(a,k,n)-1, n)`；得到非平凡因子 → 跳第 8 条；全是 1 或 `n` → 第 10 条
10. 模方程 `a^x ≡ b mod n`：先分解 `n`，按 CRT 拆到素数幂，用阶/离散对数求解；整数群 DLP 结束本页流程，转 [离散对数与 DH](/crypto/discrete-log)
11. 以上都不成立 → 回第 1 条，把方程写成标准形式（未知量、模数、次数、是否有不等式），确认是否其实归到 RSA/ECC/格；仍不行 → 回读脚本找自定义模运算

## ④ 工具与命令

```python
# CRT：互素模数
from math import prod
def crt(rs, ms):
    M = prod(ms)
    return sum(r * (M // m) * pow(M // m, -1, m) for r, m in zip(rs, ms)) % M

# 非互素 CRT：逐个合并
from math import gcd
def crt2(a1, m1, a2, m2):
    g = gcd(m1, m2)
    if (a2 - a1) % g:
        return None                      # 无解
    l = m1 // g * m2
    t = ((a2 - a1) // g * pow(m1 // g, -1, m2 // g)) % (m2 // g)
    return (a1 + m1 * t) % l, l
```

```python
# Legendre 符号与 Tonelli-Shanks
def legendre(a, p):
    return pow(a, (p - 1) // 2, p)       # 1 / p-1 / 0

def tonelli(n, p):
    assert legendre(n, p) == 1
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2; s += 1
    z = 2
    while legendre(z, p) != p - 1:
        z += 1
    M, c, t, R = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p; i += 1
        b = pow(c, 1 << (M - i - 1), p)
        M, c = i, b * b % p
        t, R = t * c % p, R * b % p
    return R
```

```python
# Pollard rho（中小因子）
from math import gcd
def pollard(n):
    if n % 2 == 0: return 2
    for c in (1, 2, 3):
        x = y = 2; d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
        if d != n:
            return d
    return None
```

```python
# 工具函数
from sympy import factorint, totient, n_order
from sympy.ntheory.residue_ntheory import sqrt_mod
factorint(n)                 # 分解
totient(n)                   # φ(n)，需要先分解
n_order(a, n)                # ord_n(a)
sqrt_mod(c, p, all_roots=True)   # 模素数开方，所有根
```

```bash
yafu "factor(<n>)"           # 中小 n 的强力分解
# factordb.com 直接查 n
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| CRT 合并结果不对 | 模数不互素，用了互素公式 | 先 `gcd(m1,m2)`；不互素要检查整除条件，用广义 CRT |
| Legendre 返回 `p-1` 还硬开方 | `p-1` 表示 -1，即无解 | 先判 `1` / `p-1` / `0`，再决定是否开方 |
| `Tonelli-Shanks` 断言失败 | `a` 不是二次剩余，或 `p` 不是奇素数 | 检查 `p` 的素性；`p=2` 单独处理 |
| 合数开方只得到一个根 | `n = p·q` 有 4 个根，只取了 `p` 上的正根 | 对 `p、q` 各取 ± 根，CRT 组合 4 个，挑可打印 |
| Pollard rho 返回 `n` | 迭代进入 `gcd = n` 的退化 | 换随机常数 `c` 重跑，或先试小因子 |
| 分解卡住 | `n` 的两个因子都很大，或方法选错 | 先查 `factordb`；`p-1` 光滑用 p-1；否则 ECM/NFS |
| `pow(a, -1, m)` 报错 | `gcd(a,m) != 1` | 先 `gcd`；不互素就把这个 gcd 直接当因子，可能直接分解 |
| `inverse(e, φ)` 报错 | `gcd(e, φ(n)) != 1` | 不能直接求 `d`；转 [RSA 攻击](/crypto/rsa) 的有限域开方/多因子处理 |
| 题目 `m^2 < n` 却先去分解 `n` | 没有发生取模，直接整数开方即可 | 先看 `c` 是否是完全平方；是就 `iroot`，不是再走 CRT |

## ⑥ 例题

**题目**：RSA 变体 `e=2`，二次剩余 + CRT 开方
**来源**：自建样例，参数由 Python 现场生成并验证；对应 CTF 中 `e=2` / Rabin 类加密的经典形态

**题干**：

```text
p = 327625899393920320859117916876619940977
q = 14769054140391480316955554838403521401
n = 4838724645943261496552064476035734374383800622924954127862102019453576348777
c = 608583161118478880585782386002542907144177367141289285226241269531126222672
已知 c = m^2 mod n，求 m
```

**关键观察**：
- `e = 2`，密文是明文的平方模 `n`
- `c` 在 `p`、`q` 下都是二次剩余（Legendre 都为 1）
- `n = p·q` 有 4 个平方根，必须 CRT 组合后逐个看哪一个可打印

**走了哪条链**：③-1 第 2 条（二次剩余）→ ③-2 第 4 条（Legendre 判定）→ 第 5 条（Tonelli-Shanks + CRT 四根）。题目已经给了 `p、q`；真实题目若只给 `n`，先走第 7 条分解。

**命令与输出**：

```python
from Crypto.Util.number import long_to_bytes

p = 327625899393920320859117916876619940977
q = 14769054140391480316955554838403521401
n = p * q
c = 608583161118478880585782386002542907144177367141289285226241269531126222672

print('legendre(c,p) =', legendre(c % p, p))
print('legendre(c,q) =', legendre(c % q, q))

rp = tonelli(c % p, p)
rq = tonelli(c % q, q)
print('sqrt mod p =', rp)
print('sqrt mod q =', rq)

cands = set()
for s1 in (rp, p - rp):
    for s2 in (rq, q - rq):
        cands.add(crt([s1, s2], [p, q]))

for x in cands:
    b = long_to_bytes(x)
    if b.startswith(b'flag'):
        print('found =', b)
```

输出：

```text
legendre(c,p) = 1
legendre(c,q) = 1
sqrt mod p = 273414897906612672914315232667921149811
sqrt mod q = 5413436619507093772049525288073517046
found = b'flag{quadratic_residue_and_crt}'
```

**结果**：4 个候选根里只有一个是可打印明文，`m = 180966415225622923925574974682281976514777677075164539900273931376967971965`，对应 `flag{...}`。输出里的明文是本页自建样例数据，不是任何真实比赛的 flag；真实题目提交以原题平台为准。

::: tip 迁移
真实比赛里 `e=2` 的题通常只给 `n、c`，并且 `n` 可能有小因子或 `p-1` 光滑。先走 ③-2 第 7 条分解，再回到本例题的开方 + CRT。若 `m^2 < n`（没有发生取模），根本不用分解，直接 `gmpy2.iroot(c, 2)` 即可，见 [RSA 攻击](/crypto/rsa)。
:::
