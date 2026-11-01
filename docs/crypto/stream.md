# 流密码与异或

关键词：流密码 异或 XOR RC4 two-time pad 密钥流复用 已知明文 LFSR Berlekamp-Massey 线性反馈移位寄存器 重复密钥 repeating key

## ① 识别指纹

- 密文是 hex/base64，**长度和明文相同**，没有 16 字节分组
- 脚本里出现逐字节 `^`、`xor(...)`、`bytes(a ^ b for a, b in zip(...))`
- 脚本出现 RC4 的 KSA/PRGA 两层循环：`S = list(range(256))` + `S[i], S[j] = S[j], S[i]`
- 脚本出现 LFSR：移位、`& 1`、反馈多项式、`state = (state >> 1) | (bit << n)`
- 题目给两段等长密文，或给"加密服务"让你提交明文、返回密文
- 题干出现 `xor` / `stream` / `rc4` / `otp` / `one-time pad` / `known plaintext` / `reuse`
- 题目名带 `xor` / `stream` / `rc4` / `lfsr` / `pad` / `异或`

## ② 考什么

- **已知明文攻击**：`keystream = c ⊕ p`，再用同一密钥流解其他密文
- **密钥流复用（two-time pad）**：`c1 ⊕ c2 = p1 ⊕ p2`，用空格/常见词做 crib dragging
- **重复密钥 XOR**：key 比明文短，按 Hamming 距离估 key 长度，再逐列破解
- **RC4**：KSA/PRGA 实现、key/nonce 复用、WEP 式 IV||key 的弱密钥偏置
- **LFSR**：线性反馈移位寄存器，Berlekamp-Massey 用 `2L` 位输出恢复反馈多项式
- **LCG 生成密钥流**：相邻输出线性相关；`m` 为 2 的幂时低 `k` 位周期最多 `2^k`；用已知明文恢复若干输出后转 [随机数预测](/crypto/prng)
- 常见编码：密文 hex、明文是 ASCII/HTTP/JSON；先把两边统一成 bytes

## ③ 判断流程

### ③-1 子类型分流

1. 密文是 hex/base64，长度与明文一致，脚本里逐字节异或 → **XOR/流密码路径**，跳 ③-2 第 1 条
2. 脚本出现 RC4 的 KSA（`range(256)` 两层循环）→ **RC4 路径**，跳 ③-2 第 5 条
3. 脚本出现移位寄存器/反馈多项式/`& 1` → **LFSR 路径**，跳 ③-2 第 7 条
4. 密钥流由 LCG/PRNG 生成 → **PRNG 路径**，跳 ③-2 第 9 条
5. 以上都不是 → 回第 1 条，确认密文是否按 16 字节分组（是则去 [对称加密](/crypto/symmetric)）

### ③-2 成本排序链

1. 有一段密文和**已知明文格式**（`flag{`、HTTP 头、JSON 键名）→ `keystream = c ⊕ known`；用该密钥流解同密钥流的其他密文，结束
2. 有两段等长密文且同一密钥流 → 算 `c1 ⊕ c2 = p1 ⊕ p2`，跳第 3 条
3. Two-time pad：用 crib dragging；英文里空格 XOR 字母仍是字母，先定位空格，再逐词恢复两段明文，结束；恢复不出 → 第 4 条
4. 密钥流是**重复短 key** → 用 Hamming 距离估 key 长度，按列做单字节频率破解，拼出 key，结束
5. RC4：先实现 KSA/PRGA 复现密钥流；若 key/nonce 固定或复用 → 有已知明文走第 1 条，没有则走第 2/3 条，结束；key 短且已知明文够 → 字典/已知明文恢复，结束
6. RC4 弱密钥：key 是 `IV || key`（WEP 式）→ 用 FMS 统计前几字节偏置；数据量不足 → 回第 5 条按复用处理
7. LFSR：把输出按位拆开，收集 `2L` 位（`L` 是寄存器长度）→ Berlekamp-Massey 求反馈多项式，递推后续位，结束
8. LFSR 输出不足 `2L` 位 → 用已知明文补出密钥流位，或按线性方程组解初始状态，结束；两条都不行 → 第 11 条
9. 密钥流来自 LCG/PRNG → 结束本页流程，转 [随机数预测](/crypto/prng) 恢复参数/状态，再生成密钥流，结束
10. 只有一段密文、key 未知、无已知明文 → 先按单字节 XOR 爆破（key 长度 1），再试 key 长度 2–4 的频率分析；出可读文本 → 结束；全不可读 → 第 11 条
11. 以上都不成立 → 回第 1 条，用 `xxd` / `file` 检查密文是否先压缩/编码，或 XOR 的对象是 hex 字符串而不是原始 bytes

## ④ 工具与命令

```python
# 通用异或
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# 已知明文恢复密钥流
keystream = xor(c1, known_plain)
p2 = xor(c2, keystream)

# two-time pad
p1_xor_p2 = xor(c1, c2)
```

```python
# RC4：KSA + PRGA（标准实现）
def rc4(key: bytes, n: int) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) % 256])
    return bytes(out)
```

```python
# 重复密钥 XOR：用 Hamming 距离估 key 长度
def hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def guess_keylen(ct: bytes, maxlen=40):
    scores = []
    for k in range(1, maxlen + 1):
        blocks = [ct[i:i+k] for i in range(0, min(len(ct), k*8), k)]
        if len(blocks) < 2: continue
        d = sum(hamming(blocks[i], blocks[i+1]) for i in range(len(blocks)-1))
        scores.append((d / k, k))
    return sorted(scores)[:5]
```

```python
# LFSR / Berlekamp-Massey（GF(2) 位序列，长度至少 2L）
def berlekamp_massey(bits):
    n = len(bits)
    C, B, L, m = [1], [1], 0, 1
    for N in range(n):
        d = bits[N]
        for i in range(1, L + 1):
            d ^= C[i] & bits[N - i]
        if d == 0:
            m += 1
            continue
        T = C[:]
        if len(C) < len(B) + m:
            C += [0] * (len(B) + m - len(C))
        for j in range(len(B)):
            C[j + m] ^= B[j]
        if 2 * L <= N:
            L, B, m = N + 1 - L, T, 1
        else:
            m += 1
    return C, L        # C 的系数就是反馈多项式，L 是线性复杂度
```

```bash
pip install pycryptodome
# 快速看密文结构
xxd cipher.bin | head
python -c "print(bytes.fromhex('...').hex())"
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 两段密文异或后还是乱码 | 密文是 hex/base64 字符串，直接按字符异或了 | 先解码成 bytes 再逐字节 XOR |
| two-time pad 找不到空格 | 明文不是英文，或其中一段是二进制 | 换已知明文格式（`flag{`、HTTP 头）或先猜一段 |
| 空格 XOR 字母得到奇怪字符 | 空格 `0x20` 只对字母保持字母形态，对数字/标点不成立 | 只用它做候选，不要当硬规则 |
| 重复密钥 XOR 的 key 长度估错 | 密文太短，Hamming 距离不显著 | 多试几个长度，按解密可读性排序 |
| RC4 换了 nonce 还是同密钥流 | nonce 没有真正参与 key，或 PRGA 状态被复用 | 回读脚本，确认 key = f(nonce) 且状态重置 |
| RC4 "弱密钥"攻击跑不出来 | CTF 里多数不是 WEP 场景，而是 key 复用 | 先按 two-time pad/已知明文处理 |
| LFSR 用 `L` 位就解 | BM 需要 `2L` 位才能唯一确定反馈多项式 | 至少收集 `2L` 位；不够就用已知明文补 |
| LFSR 解出的多项式代回去不对 | 输出是字节/十六进制，没拆成 bit | 先按 bit 展开，再跑 BM |

## ⑥ 例题

**题目**：RC4 密钥流复用（已知明文攻击）
**来源**：自建样例，密钥流与密文由 Python 现场生成并验证；对应固定 nonce 复用/流密码 two-time pad 的经典题型

**题干**：服务端用同一个 RC4 key 分别加密了你的请求和 flag，返回两段密文：

```text
p1 = b'GET /admin HTTP/1.1\r\nHost: a\r\n\r\n'     # 你知道自己发的内容
c1 = aa73863cadc5b2cb5ba59b94a7b2a5189c1943ef89bbab2f04465486d7605815
c2 = 8b5ab37bf9d6b5926da5d4b29083aa45c8420187dc9ab703161d0086b64b7462
求 p2
```

**关键观察**：
- 两段密文长度相同，且服务端对两次请求使用了同一个 key
- 你知道 `p1`，所以能直接恢复前 32 字节密钥流：`ks = c1 ⊕ p1`
- 把同一段 `ks` 和 `c2` 异或就得到 `p2`；等价地 `p2 = c1 ⊕ c2 ⊕ p1`

**走了哪条链**：③-1 第 2 条（RC4）→ ③-2 第 5 条（key 复用，有已知明文）→ 第 1 条（已知明文恢复密钥流）。

**命令与输出**：

```python
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

c1 = bytes.fromhex('aa73863cadc5b2cb5ba59b94a7b2a5189c1943ef89bbab2f04465486d7605815')
c2 = bytes.fromhex('8b5ab37bf9d6b5926da5d4b29083aa45c8420187dc9ab703161d0086b64b7462')
p1 = b'GET /admin HTTP/1.1\r\nHost: a\r\n\r\n'

ks = xor(c1, p1)              # 恢复密钥流
p2 = xor(c2, ks)              # 解第二段
print('keystream[:8] =', ks[:8].hex())
print('p2 =', p2)
```

输出：

```text
keystream[:8] = ed36d21c82a4d6a6
p2 = b'flag{rc4_nonce_reuse_is_fatal!!}'
```

**结果**：`p2 = b'flag{...}'`。输出里的明文是本页自建样例数据，不是任何真实比赛的 flag；真实题目提交以原题平台为准。

::: tip 迁移
如果不知道 `p1`，就走 two-time pad：先算 `c1 ⊕ c2 = p1 ⊕ p2`，利用英文空格（`0x20`）XOR 字母仍是字母的性质定位空格，逐步 crib dragging 出两段明文。CTF 里还常见"服务端把用户输入和 flag 用同一密钥流加密"，这时你的输入就是已知明文，直接套本例即可。
:::
