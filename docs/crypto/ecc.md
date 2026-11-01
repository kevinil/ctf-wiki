# 椭圆曲线 ECC

关键词：椭圆曲线 ECC ECDLP ECDSA Smart 攻击 MOV 攻击 Pohlig-Hellman 无效曲线 invalid curve 小阶点 扭曲 Edwards secp256k1 非奇异 奇异曲线

## ① 识别指纹

- 参数是一组 `(p, a, b, Gx, Gy, n)`，或者脚本里出现 `EllipticCurve(GF(p), [a, b])`
- 题目问"已知 `Q = dG`，求 `d`"，或给两个点问倍点关系
- 签名题给 `(r, s)`、消息 `m`、公钥点 `Q`，脚本里出现 `inverse(k, n) * (z + r*d) % n`
- 曲线方程写成 `y² = x³ + ax + b`，或 `a·x² + y² = 1 + d·x²·y²`（Twisted Edwards）
- 题干出现 `smart` / `mov` / `anomalous` / `invalid curve` / `small order` / `smooth order`
- 题目名带 `ecc` / `ecdlp` / `ecdsa` / `curve` / `smart` / `babyecc`
- `p` 和 `n` 位数接近，或 `n` 的分解里有大量小素数

## ② 考什么

- 曲线参数：缺 `a` 或 `b` 时，用曲线上的点反解参数
- **奇异曲线**：`4a³ + 27b² ≡ 0 mod p`，曲线退化成加法群或乘法群，DLP 变简单
- 点阶与曲线阶：`n = ord(G)` 不一定是 `#E(F_p)`，Pohlig-Hellman 要分解的是 `n`
- **Pohlig-Hellman**：`n` 光滑时按素因子拆 DLP 再 CRT
- **Smart 攻击**：`#E(F_p) == p`（anomalous curve），用 `p`-adic 椭圆对数
- **MOV 攻击**：embedding degree `k` 很小，把曲线 DLP 转到 `GF(p^k)` 的有限域 DLP
- **小阶点 / 无效曲线攻击**：服务端不验证点是否在曲线上，构造同 `a` 不同 `b` 的小阶曲线
- **ECDSA**：nonce `k` 重用、`k` 有偏置（HNP）→ [格密码](/crypto/lattice)
- **Twisted Edwards**：方程与点加公式和 Weierstrass 不同，先识别再转换

> 整数群上的 `y = g^x mod p` 在 [离散对数与 DH](/crypto/discrete-log)。本页只处理曲线群。

## ③ 判断流程

### ③-1 子类型分流

1. 给曲线参数和点，求 `Q = dG` 的 `d` → **曲线 DLP 路径**，跳 ③-2 第 1 条
2. 给 ECDSA 签名 `(r, s)`、消息哈希、公钥 → **ECDSA 路径**，跳 ③-2 第 10 条
3. 曲线方程是 `a·x² + y² = 1 + d·x²·y²` → **Twisted Edwards 路径**，跳 ③-2 第 9 条
4. 只给一堆点、没给 `a` 或 `b` → **参数缺失路径**，跳 ③-2 第 2 条
5. 以上都不成立 → 回第 1 条，确认未知量是曲线上的标量而不是 RSA 指数/整数群指数

### ③-2 成本排序链

1. 先算判别式 `4a³ + 27b² mod p`：等于 0 → **奇异曲线**，跳第 6 条；不等于 0 → 第 2 条
2. `a` 或 `b` 缺失：把两个已知点代入 `y² = x³ + ax + b`，解二元一次方程；解出后回第 1 条
3. 验证 `G` 在曲线上、`n*G == O`：不成立 → 参数抄错或曲线被魔改，回第 2 条重新解参数
4. 先分解 `n = ord(G)`，同时算 `#E(F_p)`：`n` 的最大素因子 `< 2^40` → Pohlig-Hellman，结束；否则第 5 条
5. 检查 `#E(F_p) == p`：成立 → **Smart 攻击**（`p`-adic 椭圆对数），结束；不成立 → 第 6 条
6. **奇异曲线**：`a = b = 0`（cusp）→ 映射到加法群 `F_p`；`a ≠ 0`（node）→ 映射到乘法群 `F_p^*` 或 `F_{p²}^*`；在退化群上解 DLP，结束
7. 算 embedding degree `k = ord_n(p)`：`k ≤ 6` → **MOV 攻击**，把点映射到 `GF(p^k)` 做有限域 DLP，结束；`k` 大 → 第 8 条
8. 服务端接受任意点且不验证在曲线上 → **无效曲线/小阶点攻击**：构造同 `a`、不同 `b`、有小阶点 `P` 的曲线，收集 `d mod ord(P)`，换多个阶后 CRT 恢复 `d`，结束；服务端验证点 → 跳第 12 条
9. Twisted Edwards：按 Edwards 点加公式手写运算，或做双有理变换转成 Montgomery/Weierstrass 后用 Sage；转换后回第 4 条判断阶是否光滑
10. ECDSA：两条签名的 `r` 相同 → **nonce 重用**，`k = (z1-z2)/(s1-s2) mod n`，`d = (s1·k-z1)/r mod n`，结束；`r` 不同 → 第 11 条
11. ECDSA 签名很多且 `k` 高位泄露/偏小 → **HNP**，构造格恢复 `d`，结束本页流程，转 [格密码](/crypto/lattice) 的 HNP 部分；没有偏置 → 回第 1 条检查曲线阶、公钥、私钥泄露
12. 以上都不成立 → 回第 1 条，用 Sage 的 `E.order()` / `E.abelian_group()` 重算曲线阶，确认题目给的 `n` 是曲线阶还是 `G` 的阶

## ④ 工具与命令

```python
# Sage 基础：建曲线、算阶、解 DLP
p = ...
a, b = ..., ...
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
Q = E(Qx, Qy)
n = G.order()
print(E.order(), n, factor(n))
d = discrete_log(Q, G, ord=n, operation='+')
```

```python
# 参数缺失：用两个点反解 a、b
# y1^2 = x1^3 + a*x1 + b
# y2^2 = x2^3 + a*x2 + b
a = (y1^2 - y2^2 - (x1^3 - x2^3)) * inverse(x1 - x2, p) % p
b = (y1^2 - x1^3 - a*x1) % p
```

```python
# Smart 攻击（#E == p），Sage 标准写法
def smart_attack(P, Q, p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2),
                        [ZZ(t) + randint(0, p) * p for t in E.a_invariants()])
    P_Qp = [R for R in Eqp.lift_x(ZZ(P.xy()[0]), all=True)
            if GF(p)(R.xy()[1]) == P.xy()[1]][0]
    Q_Qp = [R for R in Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
            if GF(p)(R.xy()[1]) == Q.xy()[1]][0]
    xP, yP = (p * P_Qp).xy()
    xQ, yQ = (p * Q_Qp).xy()
    return ZZ((-(xQ/yQ)) / (-(xP/yP)))
```

```python
# MOV 攻击：embedding degree 小
k = Mod(p, n).multiplicative_order()
K = GF(p ** k)
Ee = E.change_ring(K)
R = Ee.random_point()
g1 = Ee(P).weil_pairing(R, n)
g2 = Ee(Q).weil_pairing(R, n)
d = discrete_log(g2, g1)
```

```python
# ECDSA nonce 重用
k = (z1 - z2) * inverse(s1 - s2, n) % n
d = (s1 * k - z1) * inverse(r, n) % n
# 验证：r == (k*G).x % n，且 Q == d*G
```

```bash
pip install pycryptodome
# 常见曲线直接取参数
python -c "from Crypto.PublicKey import ECC; print(ECC.generate(curve='secp256k1').pointQ)"
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| Sage 建曲线报 "singular curve" | `4a³ + 27b² ≡ 0 mod p` | 这是考点，按奇异曲线退化到加法/乘法群 |
| `G` 算阶时报点不在曲线上 | 题目给的 `a` 或 `b` 抄错/缺失 | 用两个点代入方程反解 `a`、`b`，再验证 |
| `discrete_log` 跑不动 | `n` 含大素因子，不是光滑阶 | 先 `factor(n)`；不光滑转 Smart/MOV/无效曲线 |
| `n*G != O` | 题目给的 `n` 是曲线阶 `#E`，不是 `G` 的阶 | 用 `G.order()` 重算，Pohlig-Hellman 用 `ord(G)` |
| `#E == p` 但没意识到 | anomalous curve，普通 DLP 很难 | 直接上 Smart 攻击 |
| ECDSA 用 `(z1-z2)/(s1-s2)` 解出的 `d` 不对 | 两条签名 `r` 相同但 `k` 可能是 `n-k`（`r` 只取 x 坐标） | 对 `k` 和 `n-k` 各验证一次，或用公钥验证 `d` |
| ECDSA 的 `z` 算错 | 实现不是简单 `hash % n`，而是截取哈希最左 `n.bit_length()` 位 | 回读签名脚本，照抄它的 `z` 计算方式 |
| 无效曲线攻击发的点被拒绝 | 服务端验证了点在原曲线上 | 换攻击面：参数缺失、奇异、Smart、ECDSA |

## ⑥ 例题

**题目**：ECDSA nonce 重用
**来源**：对应 2010 年 Sony PS3 ECDSA nonce 重用事件与 CTF 常见 ECDSA 题；本页为自建小曲线样例，数字由脚本现场生成并验证

**题干**：同一条曲线、同一个私钥 `d`，用**相同 nonce `k`** 签了两条不同消息：

```text
curve: y^2 = x^3 + 3x + 6 mod 10007,  #E = 10039 (prime)
G = (0, 1973)
r = 5061
(z1, s1) = (7386, 3078)
(z2, s2) = (800, 9519)
求私钥 d
```

**关键观察**：
- 两条签名的 `r` 完全相同 → 它们对应的点有相同的 x 坐标，通常意味着同一个 `k`（也可能是 `k` 与 `n-k`）
- ECDSA 里 `s = k^{-1}(z + r·d) mod n`，两条式子相减可以把 `d` 消掉，先解 `k`
- 常见真实曲线 secp256k1 的 `n` 是 256 bit，公式和这里完全一样，只是数字更长

**走了哪条链**：③-1 第 2 条（ECDSA）→ ③-2 第 10 条（`r` 相同，nonce 重用）。

**命令与输出**：

```python
n = 10039
r, z1, s1, z2, s2 = 5061, 7386, 3078, 800, 9519

k = (z1 - z2) * pow(s1 - s2, -1, n) % n
d = (s1 * k - z1) * pow(r, -1, n) % n
print('k =', k)
print('d =', d)
```

输出：

```text
k = 4321
d = 1234
```

验证：用 `k = 4321` 重新签名两条消息，`r` 都应等于 `5061`；用 `d = 1234` 算公钥 `dG` 应等于 `(5099, 1878)`。脚本里这两项都返回 `True`。

**结果**：私钥 `d = 1234`。真实题目里 `d` 通常直接决定 flag 或能解出服务端会话；提交以原题平台为准。真实曲线换成 secp256k1 时，只需把 `n`、`r`、`s`、`z` 换成 256 bit 的值，公式不变。

::: tip 迁移
`r` 相同只是"nonce 重用"的一种表现。更常见的是 `k` 由弱随机数生成，导致**高位泄露或偏小**：这时把 `s_i k_i - z_i - r_i d ≡ 0 mod n` 写成 HNP，构造格求解，方法见 [格密码与 Coppersmith](/crypto/lattice)。另外，`r` 相同也可能是 `k` 与 `n-k`，代入公式前先用公钥验证。
:::
