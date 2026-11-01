# 对称加密

关键词：对称加密 AES DES 分组密码 ECB CBC CTR CFB OFB padding oracle 填充 oracle 位翻转 CBC flip padbuster 块频次

## ① 识别指纹

- 附件是 `.py`，出现 `AES.new(...)`、`MODE_ECB`、`MODE_CBC`、`MODE_CTR`、`pad(...)`、`unpad(...)`
- 密文是 base64 或 hex 字符串，**解码后长度是 16 的倍数**（AES 块长）
- 题干出现 "ECB" / "CBC" / "IV" / "padding" / "oracle" / "翻转" / "cut and paste"
- 题目给了一个**远程加密/解密接口**，输入任意明文返回密文，或输入密文返回"解密成功/失败"
- 题目名常是 `aes` / `aes-ecb` / `cbc` / `padding` / `signin` / `easycrypto`
- 密文里肉眼能看到重复的 16 字节块（复制到编辑器按 32 个 hex 字符换行即可看出）

## ② 考什么

- 分组密码模式：ECB / CBC / CTR / CFB / OFB，以及它们各自的可乘之机
- **ECB 的确定性**：相同明文块加密成相同密文块 → 块频次、块重排、cut-and-paste、byte-at-a-time
- **CBC 的链式结构**：`P_i = D(C_i) ⊕ C_{i-1}`，IV 公开，改 IV 控 `P_0`，改 `C_{i-1}` 控 `P_i`
- **CTR 的计数器结构**：`keystream_i = E(nonce || counter)`，nonce 复用等价于 two-time pad → [流密码](/crypto/stream)
- PKCS#7 填充与 **padding oracle**（把"填充对不对"变成解密预言机）
- 加密脚本和解密脚本的对应关系：**攻击改的是密文块或 IV，不是 key**
- 常见实现：pycryptodome、OpenSSL CLI、padbuster、CyberChef

## ③ 判断流程

### ③-1 子类型分流

1. 脚本或题干出现 `MODE_ECB`，或密文按 16 字节分组后存在重复块 → **ECB 路径**，跳 ③-2 第 5 条
2. 脚本出现 `MODE_CBC` 且给了 IV，或题干出现 "IV" → **CBC 路径**，跳 ③-2 第 8 条
3. 脚本出现 `MODE_CTR` / `nonce` / `counter`，或两段密文长度相同且 nonce 相同 → **CTR 路径**，跳 ③-2 第 10 条
4. 远程服务对篡改后的密文返回两种不同响应（如 "padding error" 与 "decrypt error"）→ **padding oracle 路径**，跳 ③-2 第 11 条
5. 以上都不成立，只有密文和 key/模式未知 → **模式枚举路径**，跳 ③-2 第 1 条从头判断

### ③-2 成本排序链

1. 密文是 base64/hex 字符串 → 先解码成 raw bytes；长度是 16 的倍数 → 按 AES 处理，继续第 2 条；长度不是 16 的倍数 → 结束本页流程，转 [流密码](/crypto/stream)
2. 按 16 字节切块，统计块频次 `Counter(blocks)`：最大频次 ≥ 2 → **ECB**，跳第 5 条；全部频次为 1 → 继续第 3 条
3. 脚本/服务给了 IV 或写了 `MODE_CBC` → 按 CBC 处理，跳第 8 条；给了 nonce 且没有 IV → 跳第 10 条；两者都没有 → 继续第 4 条
4. 只有密文和 key、模式未知 → 依次用 ECB、CBC(zero IV)、CTR(zero nonce) 解密并打印明文；出现可读明文 → 结束；三种都不可读 → 跳第 13 条
5. ECB 且题目提供加密 oracle（任意明文 → 密文）→ 走 byte-at-a-time，跳第 6 条；没有 oracle → 跳第 7 条
6. 先测 block size（长度跳变的差值），再逐字节建字典：固定前缀把目标字节推到块末，比对密文块，恢复全部明文 → 结束
7. ECB 无 oracle：尝试把密文块重排、删除、复制（cut-and-paste）；服务端解密后接受篡改结果 → 构造目标明文，结束；不接受 → 跳第 13 条
8. CBC 且能控制 IV 或前一块密文 → 位翻转，跳第 9 条；只有固定 IV 无法修改 → 检查服务端是否把 IV 拼在密文最前面（前 16 字节），是则把那 16 字节当 IV 改并跳第 9 条，不是则跳第 13 条
9. 位翻转：改 IV 的第 k 字节 → 只改 `P_0` 第 k 字节；改 `C_{i-1}` 的第 k 字节 → 改 `P_i` 第 k 字节，同时 `P_{i-1}` 整块损坏；按目标明文计算异或差，结束
10. CTR/流模式：两段密文 nonce 相同 → `c1 ⊕ c2 = p1 ⊕ p2`，结束本页流程，转 [流密码](/crypto/stream) 的 two-time pad；只有一段且有已知明文前缀 → 恢复密钥流前缀并解出其余部分，结束
11. Padding oracle：确认服务端对"填充错误"和"其他错误"的响应可区分 → 用 padbuster 逐字节解出明文，跳第 12 条
12. padbuster 跑出完整明文 → 按题目要求重新加密目标块（若需要伪造）→ 结束；padbuster 报长度/编码错误 → 回第 1 条确认密文编码和 block size
13. 以上都不成立 → 回第 1 条，用 `xxd` / CyberChef 重新确认密文是否先压缩、先 base64、或每块单独加密

## ④ 工具与命令

```bash
pip install pycryptodome
# 命令行快速试模式（key/iv 用 hex）
openssl enc -aes-128-ecb -d -K <hexkey> -in ct.bin
openssl enc -aes-128-cbc -d -K <hexkey> -iv <hexiv> -in ct.bin
```

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from collections import Counter

key = b'0123456789abcdef'
iv  = bytes(16)

# —— 加密：cipher.encrypt ——
ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(b'admin=0;uid=1;&role=guest;', 16))

# —— 正常解密：cipher.decrypt + unpad ——
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)

# —— ECB 块频次判定 ——
ecb_ct = AES.new(key, AES.MODE_ECB).encrypt(pad(b'A' * 48, 16))
blocks = [ecb_ct[i:i+16] for i in range(0, len(ecb_ct), 16)]
print(Counter(blocks).most_common(3))       # 频次 >1 就说明是 ECB

# —— CBC 位翻转：把 P0 里的 '0' 改成 '1' ——
iv2 = bytearray(iv)
iv2[6] ^= ord('0') ^ ord('1')               # 明文下标 6 处是 '0'
pt2 = AES.new(key, AES.MODE_CBC, bytes(iv2)).decrypt(ct)
print(pt2[:16])                             # b'admin=1;uid=1;&r'
```

```python
# CBC 位翻转的通用写法：改 P_i（i>=1）就改 C_{i-1}；改 P_0 就改 IV
def flip_block(ct, iv, i, pos, old, new):
    if i == 0:
        iv = bytearray(iv); iv[pos] ^= old ^ new; return ct, bytes(iv)
    ct = bytearray(ct)
    ct[(i-1)*16 + pos] ^= old ^ new
    return bytes(ct), iv
```

```bash
# padding oracle 一把梭
padbuster http://target/decrypt.php <base64密文> 16 \
  -cookies "auth=<base64密文>" -encoding 0
# -encoding 0 = base64，1 = hex；block size 一般是 16
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 块频次全是 1，但题目说是 ECB | 密文是 base64/hex，没先解码，按字符分组了 | 先 base64/hex 解码，再按 16 字节切块 |
| ECB 检测不到重复块 | 明文每块都不同（比如前面带了随机 nonce） | 找 oracle 题，用固定前缀把相同内容推到同一块 |
| CBC 改了一个字节，明文整块乱码 | 改的是 `C_i`，它同时是 `P_i` 的输入和 `P_{i+1}` 的前一块 | 要改 `P_i` 就改 `C_{i-1}`；接受 `P_{i-1}` 损坏 |
| CBC 改 IV 后第一块对了，后续没变 | IV 只影响 `P_0`，不影响后面的链 | 后续块要逐块改对应的前一块密文 |
| `unpad` 报 `PKCS#7 padding is incorrect` | 解出来的是攻击后的中间值，不是合法密文 | 攻击阶段不要 `unpad`，直接看 raw bytes |
| padding oracle 每个字节都试不出来 | 服务端对所有错误返回同一页面/同一状态码 | 看响应长度、耗时、cookie 差异；仍一样就换题 |
| CTR 两段密文异或后仍是乱码 | nonce 不同，或 counter 起始值不同 | 回脚本确认 nonce/counter 的生成方式 |
| 自己加密验证对不上 | 加密用 `encrypt`，解密攻击改的是密文块 | 加密/解密各写一遍，确认 IV、padding、字节序一致 |

## ⑥ 例题

**题目**：ECB byte-at-a-time 解密（AES-ECB 加密预言机）
**来源**：Cryptopals Set 2 Challenge 12 "Byte-at-a-time ECB decryption (Simple)" 的经典形态；本页数字为自建样例，脚本现场生成并验证

**题干**：服务端把攻击者输入拼在秘密后面，用固定 key 做 AES-ECB：

```python
def oracle(inp):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(inp + secret, 16))
```

不给 key，只给 oracle 的访问权限，求 `secret`。

**关键观察**：
- 输入长度每增加 1，密文长度在若干点跳变 16 字节 → block size = 16
- 输入 48 个 `A` 时，密文前 3 个块完全相同 → 相同明文块产生相同密文块，确认 ECB
- ECB 没有链式扩散，可以逐字节把目标推到块末，用字典比对

**走了哪条链**：③-1 第 1 条（ECB）→ ③-2 第 2 条（块频次 >1）→ 第 5 条（有 oracle）→ 第 6 条（byte-at-a-time）。

**命令与输出**：

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from collections import Counter

key = b'0123456789abcdef'
secret = b'flag{ecb_byte_at_a_time_is_classic}'

def oracle(inp):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(inp + secret, 16))

# 1) block size：找长度跳变，第二个跳变减第一个 = 16
lengths = [len(oracle(b'A'*i)) for i in range(64)]
jumps = [i for i in range(1, 64) if lengths[i] != lengths[i-1]]
bs = jumps[1] - jumps[0]
print('block size =', bs)

# 2) ECB 判定：喂 3 个相同块
ct = oracle(b'A' * 48)
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
print('freq of first 3 blocks =', [Counter(blocks)[blocks[i]] for i in range(3)])

# 3) 逐字节恢复
rec = b''
for i in range(len(secret)):
    prefix = b'A' * (bs - 1 - i % bs)
    tb = i // bs
    table = {}
    for b in range(256):
        c = oracle(prefix + rec + bytes([b]))
        table[c[tb*bs:(tb+1)*bs]] = b
    c = oracle(prefix)                       # 注意：目标只用 prefix
    rec += bytes([table[c[tb*bs:(tb+1)*bs]]])

print('recovered =', rec)
print('match =', rec == secret)
```

输出：

```text
block size = 16
freq of first 3 blocks = [3, 3, 3]
recovered = b'flag{ecb_byte_at_a_time_is_classic}'
match = True
```

**结果**：`flag{...}`。输出里的明文是本页自建样例数据，不是任何真实比赛的 flag；真实题目提交以原题平台为准。

同一套脚本里验证 CBC 位翻转：明文 `admin=0;uid=1;&role=guest;`，把 IV 第 6 字节按 `'0' ^ '1'` 翻转，解密后第一块变成 `b'admin=1;uid=1;&r'`，其余块不变。

::: tip 迁移
真实题目里 `secret` 往往就是 flag，且 oracle 还会在密文前加随机前缀。此时第 6 条要改成"先确定随机前缀长度，再按块对齐"。如果题目给的是远程服务，把 `bytes` 和 base64 的转换写在收发函数里，攻击逻辑不变。
:::
