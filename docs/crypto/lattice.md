# 格密码与 Coppersmith

关键词：格 lattice LLL BKZ Coppersmith small_roots 小根 已知高位 背包 knapsack 子集和 HNP 隐数问题 正交格 fpylll sage beta

## ① 识别指纹

- 附件是 Sage 脚本，出现 `small_roots`、`Matrix(ZZ, ...).LLL()`、`BKZ`、`fpylll`
- 题目给了 `N` 和"`p` 的高位" / "明文的高位" / "部分字节"，要求补全
- 题目给一组数和一个目标和，问选哪些数（子集和/背包）
- 题目给很多组"近似相等"的方程，每组带一个小误差（HNP、biased nonce、截断 LCG）
- 题干出现 `coppersmith` / `lattice` / `LLL` / `knapsack` / `subset` / `partial` / `hnp` / `hidden number`
- 题目名带 `copper` / `small_root` / `lattice` / `backpack` / `knapsack` / `hnp`
- 通常需要 Sage 或 fpylll，纯 Python 只能跑很小的维度

## ② 考什么

- **LLL/BKZ 什么时候该想到**：题目里有"小"未知量、"近似"等式、或要找一组短整数关系
- **Coppersmith 小根定理**：`f(x) ≡ 0 mod N` 且 `|x0| < N^(1/δ)` 时可在多项式时间求小根
- **未知因子版本**：`f(x0) ≡ 0 mod p`，`p | N`，`p ≥ N^β` 时界变成 `N^(β²/δ)`
- **`beta` 与 `X` 的选择**：`beta` 是未知因子在模数中的比例下界，平衡 RSA（`p`、`q` 同量级）取 `0.5`；`X` 是根的上界，按未知位数取 `2^k`
- 已知 `p` 高位、已知明文高位（RSA 部分信息）
- **RSA 的 HNP / 部分密钥泄露**：已知 `d` 的高位时把 `d = d_high·2^k + x` 代入密钥方程，用格/HNP；已知 `p` 的高位用 Coppersmith
- **背包/子集和**：低密度（`d < 0.94`）时 LLL 直接恢复 0/1 向量
- **正交格**：找与已知向量近似正交的短向量，用于近似 GCD、隐藏子集和
- 工具：Sage `small_roots`、fpylll、`flatter`（快速 LLL）

## ③ 判断流程

### ③-1 子类型分流

1. 题目是多项式同余 `f(x) ≡ 0 mod N`，未知量是"小根"或"部分位" → **Coppersmith 路径**，跳 ③-2 第 1 条
2. 题目是一组数和目标和的子集和/背包 → **背包路径**，跳 ③-2 第 8 条
3. 题目给多组带小误差的近似等式（nonce 高位、截断输出、部分密钥）→ **HNP 路径**，跳 ③-2 第 10 条
4. 题目给一堆大整数，要求短向量/近似公因子/隐藏关系 → **正交格路径**，跳 ③-2 第 11 条
5. 以上都不成立 → 回第 1 条，确认题目里是否存在"小"未知量；没有小量就不是格题

### ③-2 成本排序链

1. 把题目写成 `f(x) ≡ 0 mod M`，标出三件事：`deg f = δ`、未知量上界 `X`、模数 `M` 是 `N` 还是 `N` 的因子 `p`；`M = N` → `beta = 1.0`，`M = p | N` → `beta = 0.5`（`p` 明显小于 `N` 时按 `p` 的位数比例取更小的 `beta`），继续第 2 条
2. 用位数检查可行性：设 `bitlen(N) = L`、未知量 `X = 2^k`，要求 `k < β²·L/δ`；满足 → 第 3 条；不满足 → 跳第 7 条（根太大，Coppersmith 不保证）
3. 单变量且 `f` 首一：直接 `f.monic().small_roots(X=X, beta=beta)`；返回非空 → 结束；返回空 → 第 4 条
4. 调参：`epsilon` 调小（默认 `beta/8`）以增加格维数，重跑；仍为空 → 第 5 条
5. 已知 `p` 高位：令 `p = p_high·2^k + x`，`f(x) = p_high·2^k + x`，`beta=0.5`，`X=2^k`；`k ≥ L/4` → 跳第 6 条；`k < L/4` → 跑 `small_roots`，返回非空 → 结束，返回空 → 第 6 条
6. 多变量或非首一：先用结式消元降到单变量，或两边乘首项系数的逆元变首一；降不下来 → 第 7 条
7. Coppersmith 失败：检查 `X` 是不是把十进制位数当成了 bit 数、`beta` 是否用反、`f` 是否 monic；修正后回第 3 条；仍失败 → 跳第 12 条
8. 背包：密度 `d = n / log2(max(a_i))`；`d < 0.94` → 构造 `n+1` 维格，LLL，取末位为 0、前 `n` 位为 ±1 的短向量，恢复 0/1，结束
9. 背包密度高或 `n` 大：`n ≤ 40` 用 meet-in-the-middle；否则先 BKZ 降维/约减；仍不行 → 第 12 条
10. HNP：把每个方程写成 `k_i = known_i + e_i`、`|e_i| < B`，消去 `k_i` 得到 `t_i·d + c_i ≡ e_i mod n`；构造格（见 ④），LLL/BKZ 恢复 `d`，结束
11. 正交格/近似 GCD：把已知向量按行放入矩阵，LLL 求短的正交组合；用短关系恢复秘密或公因子，结束
12. 以上都不成立 → 回第 1 条，重算 `L`、`δ`、`β`、`X` 四个量；四个量里只要有一个估错，格就出不来。仍失败就用 fpylll 的 BKZ（block size 20–40）替代 LLL 再试

## ④ 工具与命令

```python
# Sage：已知 p 高位（beta=0.5，因为 p 是 N 的未知因子）
N = ...
p_high = ...
k = 64
PR.<x> = PolynomialRing(Zmod(N))
f = p_high * 2^k + x
f = f.monic()
roots = f.small_roots(X=2^k, beta=0.5)     # X 必须 >= 真实根
p = p_high * 2^k + int(roots[0])
assert N % p == 0
```

```python
# Sage：已知明文高位（beta=1.0，模数是完整的 N）
# m = m_high * 2^k + x, c = m^e mod N
PR.<x> = PolynomialRing(Zmod(N))
f = (m_high * 2^k + x)^e - c
roots = f.monic().small_roots(X=2^k, beta=1.0)   # 要求 k < L/e（L = bitlen(N)）
```

```python
# 没有 Sage 时的等价实现（sympy 的 LLL，仅适合低维小例子）
from sympy import Poly, Matrix, symbols, expand, ground_roots, ZZ
x = symbols('x')

def coppersmith(f, N, X, m, t):
    f = Poly(f, x, domain=ZZ)
    d = f.degree()
    dim = d * m + t
    polys = []
    for i in range(m):
        for j in range(d):
            polys.append(expand(x**j * N**(m-i) * f.as_expr()**i))
    for i in range(t):
        polys.append(expand(x**i * f.as_expr()**m))
    B = Matrix.zeros(dim, dim)
    for i, g in enumerate(polys):
        for j, c in enumerate(Poly(g, x).all_coeffs()[::-1]):
            B[i, j] = c * X**j
    v = B.lll().tolist()[0]
    P = sum((v[j] // X**j) * x**j for j in range(dim))
    return [r for r in ground_roots(Poly(P, x), x) if r.is_Integer]

# beta=0.5, delta=1 时：epsilon=beta/8, m=ceil(beta^2/(delta*epsilon)), t=floor(delta*m*(1/beta-1))
```

```python
# 背包（低密度子集和）
from sympy import Matrix
n = len(a)
B = Matrix.zeros(n + 1, n + 1)
for i in range(n):
    B[i, i] = 2
    B[i, n] = a[i]
for i in range(n):
    B[n, i] = 1
B[n, n] = s
for v in B.lll().tolist():
    if v[n] == 0 and all(abs(t) == 1 for t in v[:n]):
        for e in ([(1 - t)//2 for t in v[:n]], [(t + 1)//2 for t in v[:n]]):
            if sum(ei*ai for ei, ai in zip(e, a)) == s:
                print(e)          # 0/1 解
```

```python
# HNP：t_i*d + c_i ≡ e_i (mod n)，|e_i| < B
from sympy import Matrix
def hnp(n, t, c, B):
    m = len(t)
    M = Matrix.zeros(m + 2, m + 2)
    for i in range(m):
        M[i, i] = n * n          # 模数行，消去 n 的倍数
        M[m, i] = t[i] * n
        M[m+1, i] = c[i] * n
    M[m, m] = B                  # 给 d 一列权重
    M[m+1, m+1] = B * n
    for v in M.lll().tolist():
        if all(x % n == 0 for x in v[:m]) and v[m] % B == 0:
            d = (v[m] // B) % n
            for dd in (d, (-d) % n):
                es = [(t[i] * dd + c[i]) % n for i in range(m)]
                if all(min(e, n - e) < B for e in es):
                    return dd
    return None
```

```python
# fpylll 的 LLL/BKZ（比 sympy 快很多）；先 pip install fpylll cysignals
from fpylll import IntegerMatrix, LLL
rows = B.tolist() if hasattr(B, 'tolist') else B
A = IntegerMatrix.from_matrix([[int(x) for x in row] for row in rows])
LLL.reduction(A)
# BKZ：from fpylll import BKZ; BKZ.reduction(A, BKZ.Param(block_size=30))
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `small_roots` 返回 `[]` | `X` 大于理论界，或 `beta` 用错 | 先算 `k < β²·L/δ`，再确认 `M=N` 还是 `p` 整除 `N` |
| 已知 `p` 高位却用 `beta=1.0` | `beta` 描述的是未知因子占模数的比例，不是明文比例 | `p` 整除 `N` 时用 `beta=0.5`；模数是完整 `N` 才用 `1.0` |
| `small_roots` 报 not monic | 首项系数在 `Zmod(N)` 下不可逆 | 先 `f.monic()`；不可逆说明首项系数和 `N` 不互素，先处理这个因子 |
| 把十进制位数当 bit 数 | `X=10^18` 和 `2^18` 差很多 | 统一用 `X=2^k`，`k` 是未知的二进制位数 |
| LLL 出来的向量不短 | 维度太高或格基没约减好 | 降维、调 `X`/`m`，或用 BKZ（block size 20–40） |
| 背包 LLL 解不出 | 密度 `d ≥ 0.94`，或权重没放大 2 倍 | 检查密度；格的对角线用 2，末列放 `a_i`，最后一行全 1 |
| HNP 解出的 `d` 不对 | 已知高位 `K_i` 的偏移算错，或 `B` 估小 | 用 `k_i - K_i` 的 centered 表示，`B` 取真实误差上界 |
| 维度一高 Python 就卡死 | sympy 的 LLL 是纯 Python | 用 fpylll/Sage，或用 `flatter` 先约减 |

## ⑥ 例题

**题目**：已知 RSA 的 `p` 高位，Coppersmith 补全
**来源**：自建样例，参数由 Python 现场生成并验证；对应 CTF 常见的 `partial_p` / `p 高位泄露` 题型

**题干**：

```text
N = 331945126438068748700421139389019569369499705022136715039995544982656639420063750156463274092965071477703393563510347954210072024698046038400380073939383
p_high = 740187689803930149002615647713327487112458822167347423967
已知 p = p_high * 2^64 + x，其中 0 <= x < 2^64
求 p、q
```

**关键观察**：
- `N` 是 507 bit，`p` 是 253 bit，`p_high` 是 189 bit → 未知的低位只有 64 bit
- `p | N` 且 `p` 是未知因子 → `beta = 0.5`
- `X = 2^64`，理论上界 `N^0.25` 约 `2^127`，`64 < 127`，Coppersmith 可行
- 多项式 `f(x) = p_high·2^64 + x` 在模 `p` 下以真实的低位为根

**走了哪条链**：③-1 第 1 条（Coppersmith）→ ③-2 第 1 条（`M = p | N`，`beta=0.5`）→ 第 2 条（位数检查通过）→ 第 5 条（已知 `p` 高位）→ 跑出根。

**命令与输出**：

```python
# 复用 ④ 的 coppersmith 函数；m=4, t=4 由 beta=0.5, delta=1, epsilon=beta/8 推出
roots = coppersmith((p_high << 64) + x, N, X=1 << 64, m=4, t=4)
low = roots[0]
p = (p_high << 64) + low
q = N // p
print('roots =', roots)
print('p =', p)
print('q =', q)
print('N % p == 0:', N % p == 0)
```

输出：

```text
roots = [10499958131665515005]
p = 13654052880323412379663692421328806547061611885489941438207873342831887495677
q = 24311105965938388548830698200525867024144360738597094831162501213063826691779
N % p == 0: True
```

**结果**：补全出的低位是 `10499958131665515005`，拼回去得到 `p`，`N % p == 0` 成立，`q = N // p`。真实题目到这里就可以走 [RSA 攻击](/crypto/rsa) 解明文；样例中的数字不是任何真实题目的参数，提交以原题平台为准。

::: tip 迁移
Sage 里同样的输入只需一行：

```python
PR.<x> = PolynomialRing(Zmod(N))
roots = ((p_high << 64) + x).monic().small_roots(X=2^64, beta=0.5)
```

`small_roots` 会自动选 `m`、`t` 和 `epsilon`；失败时先调小 `epsilon`（如 `epsilon=0.02`），再检查 `X` 是否大于真实根。已知明文高位时把 `beta` 改成 `1.0`，`X` 的界换成 `N^(1/e)`。
:::
