# RSA 攻击

关键词：RSA 共模攻击 低指数攻击 广播攻击 Wiener 攻击 分解 factordb 小指数 私钥泄露 dp dq

## ① 识别指纹

- 附件是 `.py` 脚本，里面出现 `pow(m, e, n)` 或 `pow(m, d, n)`
- 题干直接给三个大整数：`n = ...` `e = ...` `c = ...`
- `n` 有几百到几千位，`e` 常常是 `65537`，偶尔是很小的 `3` / `5` / `17`
- 题目名带 `rsa` / `easyrsa` / `babyrsa` / `RSA` / `crypto` / `签到`
- 附件给的是一个**远程服务**，只让你提交密文/明文 —— 这是 RSA 预言机题，不是常规攻击

## ② 考什么

- 基础：`φ(n) = (p-1)(q-1)`、`d = e⁻¹ mod φ(n)`、`m = c^d mod n`
- 分解类：factordb / yafu / Fermat（p、q 接近）/ Pollard rho / 小因子
- 小公钥指数：`e=3` 且 `m^e < n` 时直接整数开方
- 广播攻击（Håstad）：同一明文用**不同 n**、相同小 e 加密多份 → CRT
- 共模攻击：**同一 n**、不同 e、同一明文
- 已知泄露：`dp` / `dq` / `d` / `p` 的高位 / `phi`
- `e` 与 `φ(n)` 不互素 → 有限域开方
- Wiener 攻击：`d` 过小（`d < n^0.25/3`）
- 多因子 RSA（`n` 由 3 个以上素数构成）
- 相关消息攻击（Franklin-Reiter）、已知明文前缀
- Coppersmith / 格：已知明文高位、`p` 高位 → 见 [格密码](/crypto/lattice)

## ③ 判断流程

1. **把 `n` 原样粘进 [factordb.com](https://factordb.com)** —— 30 秒，命中率比你想的高；分解出来 → 跳 11
2. **看 `n` 的位数**：
   - `< 256 bit` → 本地直接试除 + `yafu`；能分解 → 跳 11
   - `>` 1024 bit → 基本排除暴力分解，往下走
3. **看 `e`**：
   - `e` 很小（3 / 5 / 17）→ 跳 4
   - `e = 65537` 或更大 → 跳 5
4. **小指数攻击**：
   - 试 `m = iroot(c, e)`，如果 `m^e == c`（说明没取模）→ 直接得到明文，结束
   - 不成立 → 看题目是否给了**多组 n**；有 → 广播攻击（跳 6）
   - 都不行 → 可能是明文过小但经过填充，回读脚本
5. **看是否给你"额外信息"**：题目里有没有 `dp`、`dq`、`d`、`p 的高位`、`phi`、`leak` 这类变量？
   - 有 → 对应攻击，**这是出题人给你的捷径，优先走**
   - 没有 → 跳 6
6. **有多组 `(n_i, e, c_i)`？**
   - 多个 `n` + 相同 `e` + 相同明文 → **广播攻击**
   - 同一个 `n` + 多个 `e` + 相同明文 → **共模攻击**（要求 `gcd(e1,e2)=1`）
   - → 算出明文后结束
7. **`d` 可能很小？** 用 Wiener 攻击试一次（成本很低）
8. **`p` 和 `q` 可能很接近？** 用 Fermat 分解试一次（成本很低）
9. **`e` 与 `φ(n)` 不互素？** 脚本里若出现 `inverse(e, phi)` 报错或 `gcd(e,phi)!=1` → 有限域开方
10. **以上全不成立** → 跑 `RsaCtfTool --publickey pub.pem --uncipherfile c.txt` 一把梭；仍不行 → 回读脚本，找**非标准 RSA**（逐字节加密、明文是字符拼接、自写模运算、多因子、先做哈希）
11. **拿到 p、q 后**：`d = inverse(e, (p-1)*(q-1))`，`m = pow(c, d, n)`，`long_to_bytes(m)`

## ④ 工具与命令

```bash
pip install gmpy2 pycryptodome
pip install RsaCtfTool            # 一把梭，覆盖几十种攻击
```

```python
from Crypto.Util.number import long_to_bytes, inverse
import gmpy2

# —— 基础：已知 p、q ——
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)

# —— 小指数直接开方 ——
m, exact = gmpy2.iroot(c, e)      # exact 为 True 说明没有取模
print(long_to_bytes(int(m)))

# —— 共模攻击 ——
_, a, b = gmpy2.gcdext(e1, e2)    # a*e1 + b*e2 = 1
if a < 0: a, c1 = -a, inverse(c1, n)
if b < 0: b, c2 = -b, inverse(c2, n)
m = pow(c1, int(a), n) * pow(c2, int(b), n) % n

# —— 广播攻击（CRT）——
from functools import reduce
def crt(rs, ms):
    M = reduce(lambda a, b: a*b, ms)
    x = 0
    for r, m in zip(rs, ms):
        Mi = M // m
        x += r * Mi * pow(Mi, -1, m)
    return x % M
m = gmpy2.iroot(crt(cs, ns), e)[0]
```

```bash
# 命令行一把梭
RsaCtfTool --publickey key.pub --uncipherfile cipher.bin
RsaCtfTool --n <n> --e <e> --uncipher <c>
yafu "factor(<n>)"                 # 中小 n 的强力分解
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `iroot` 用浮点算，结果差 1 | 浮点精度不够 | 一律用 `gmpy2.iroot`，不要 `c**(1/3)` |
| factordb 查不到 | `n` 是新生成的 | 转 Fermat / Wiener / 泄露类攻击 |
| 共模攻击解出来是乱码 | 两个 `e` 不互素 | 先 `gcd(e1,e2)`，不为 1 就得另想办法 |
| 还原出的 `m` 转字节后前面有 `\x00` 或长度不对 | `long_to_bytes` 不补前导零 | 手动 `zfill` 到预期长度 |
| `c` 是字符串不是整数 | 题目为了好看做了 `bytes_to_long` 之外的编码 | 回读脚本，照抄它生成 `c` 的方式反过来做 |
| 分解出来了但还是没 flag | 明文被逐字符加密 / 每字节单独 RSA | 回脚本看循环结构，往往是列表 `c` |
| `e = 1` 或 `e = 3` 且 `d` 也小 | 参数生成有 bug，这本身就是考点 | 直接看 `c` 与 `n` 的关系 |

## ⑥ 例题

**题目**：低加密指数攻击（`e=3`，明文立方后未溢出模数）
**来源**：RSA 小指数攻击的标准形态，CTF Wiki《RSA》章节与各大入门赛通用题型

**题干**：

```text
n = 1181640291642918365944871538900041798133700243321
e = 3
c = 5074073570688783701917376375
```

**关键观察**：
- `n` 只有 **160 bit**，但 `c` 只有 **93 bit** —— `c` 比 `n` 小得多，这是最大的破绽
- `e = 3` 很小

`c = m^e mod n`，如果 `m^e < n`，那么取模根本没发生，`c` 就等于 `m^3`。此时不需要分解 `n`，直接开三次方即可。

**走了哪条链**：第 2 条（`n` 位数偏小，排除暴力）→ 第 3 条（`e=3` 很小）→ 第 4 条（小指数攻击），命中后直接结束，`factordb` 都没用上。

**命令与输出**：

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

n = 1181640291642918365944871538900041798133700243321
e = 3
c = 5074073570688783701917376375

m, exact = gmpy2.iroot(c, e)
print(exact)              # True —— 说明 c 确实是完全立方数
print(hex(int(m)))        # 0x666c6167
print(long_to_bytes(int(m)))
```

输出：

```text
True
0x666c6167
b'flag'
```

**结果**：`c` 的整数三次方根 `1718378855`，十六进制 `0x666c6167` 正好是 ASCII 的 `flag`。真实题目里这段就是 `flag{...}` 的前缀，后面还会接着更多字节。

**验证**：`pow(int(m), 3, n) == c` 应当成立 —— 这一步能确认你的开方没算错。

::: tip 迁移
真实比赛里 `m` 通常很长，`m^3 > n`，开方就失效了。此时往下走：
- 题目给了 3 组不同 `n` 加密同一 `m` → **广播攻击**（CRT 拼起来再开方）
- 题目给了同一 `n` 的两个 `e` → **共模攻击**
:::
