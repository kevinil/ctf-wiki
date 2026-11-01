# 算法识别

关键词：算法识别 algorithm identification 加密算法 TEA XTEA RC4 MD5 SHA1 AES SM4 base64 findcrypt signsrch 常量 指纹 S-box 魔改 逆向

## ① 识别指纹

- 校验函数里有大段循环、移位、异或、32/64 位回绕，输入长度固定（8 / 16 / 32 字节）
- 二进制里出现大块 256 字节表、64 字符表、16 字节 IV / key
- `strings` 命中 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`、`expand 32-byte k`、`0123456789abcdef`
- 常量密集：`0x9E3779B9`（TEA/XTEA）、`0x67452301`（MD5/SHA1）、`0xEDB88320`（CRC32）、`0x6A09E667`（SHA256）
- 输出是 hex / base64；输入长度固定；错误提示只有 `Wrong`
- 题目名带 `crypto`、`tea`、`rc4`、`aes`、`encode`、`easyre`
- `DIE` 显示无壳、正常编译器，但校验函数体很大、常量密集
- `findcrypt` / `signsrch` 扫出算法名 —— 最直接的信号

## ② 考什么

- 常量指纹：TEA delta、MD5/SHA IV、AES/SM4 S-box、CRC32 多项式、base64 字母表
- 表驱动识别：256 字节 S 盒、64 字符表、T-table、Rcon
- 算法结构：Feistel（TEA/XTEA/DES）、SPN（AES/SM4）、流密码（RC4）、哈希（MD5/SHA）、编码（base64/hex）
- 区分 MD5 / SHA1 / SHA256：IV 常量、输出长度、第五个常量
- 模式与参数：ECB / CBC、IV、padding、轮数、delta、key schedule
- 识别后直接调库（`hashlib`、`base64`、`pycryptodome`）或写逆运算
- 魔改算法：改 delta / 轮数 / S-box / 字母表，按伪代码重写参考实现
- 工具：IDA `findcrypt` 插件、`signsrch`、YARA 规则、自己写常量扫描脚本

| 算法 | 关键常量 / 表 | 识别要点 |
|---|---|---|
| TEA / XTEA | delta `0x9E3779B9`；TEA 32 轮 / XTEA 32 组双轮；sum 终值 `0xC6EF3720` | delta 常以补码 `0x61C88647` 出现 |
| MD5 | IV `0x67452301` `0xefcdab89` `0x98badcfe` `0x10325476`；T 表首项 `0xd76aa478` | x86 立即数字节序为 `01 23 45 67 ...` |
| SHA1 | 前四个 IV 同 MD5，加 `0xC3D2E1F0` | 五个 IV；输出 20 字节 |
| SHA256 | IV 首项 `0x6A09E667` | 输出 32 字节 |
| RC4 | 256 字节 S 盒初始化为 `0..255`，再做 KSA / PRGA | 没有固定 magic，看 256 次循环 + 交换 |
| base64 | 64 字符表 `A-Za-z0-9+/`，`=` padding | 自定义表就是换这 64 个字符 |
| AES | S-box 首字节 `0x63`，前 16 字节 `63 7c 77 7b ...`；T-table 首项 `0xC66363A5` | 256 字节 S 盒；T-table 是 4 个 1 KB 表 |
| SM4 | S-box 前 16 字节 `d6 90 e9 fe cc e1 3d b7 ...` | 国密题常见 |
| CRC32 | 多项式 `0xEDB88320`；表首项 `0x00000000` `0x77073096` ... | 校验不是加密 |
| ChaCha / Salsa20 | 字符串 `expand 32-byte k` | `strings` 直接命中 |

## ③ 判断流程

### ③-1 子类型分流

1. 程序输出固定长度 hex / base64，输入长度固定 → 分组 / 流密码或哈希，进第 2 条
2. `strings` / `xxd` 命中 64 字符表、`=` padding → base64 变种，跳 ③-2 第 5 条
3. 命中 256 字节表（S 盒）且伴随密钥调度循环 → RC4 或 AES/SM4，跳 ③-2 第 4 条
4. 命中 32 位常量 `0x67452301` / `0x6A09E667` / `0xEDB88320` → 哈希 / CRC，跳 ③-2 第 7 条
5. 命中 `0x9E3779B9` 或 32 轮 Feistel → TEA/XTEA，跳 ③-2 第 3 条
6. 没有明显常量，只有逐字节 XOR / 移位 / 加法 → 自定义编码，跳 ③-2 第 6 条
7. 以上都不成立 → 跳 ③-2 第 1 条，用 `findcrypt` / `signsrch` 扫一遍；工具也无命中则回 [常规静态分析](/reverse/static-analysis)

### ③-2 成本排序链

1. `findcrypt` / `signsrch` 扫二进制 → 命中算法名 → 记下候选，进第 2 条；无命中 → 第 3 条
2. 打开命中常量的交叉引用，确认轮数、密钥长度、块大小 → 与标准实现一致 → 调库计算或解密，结束；不一致 → 第 8 条
3. TEA/XTEA：搜 `0x9E3779B9` 及其补码 `0x61C88647`，确认 32 轮和 sum 终值 `0xC6EF3720` → 提取 key / ciphertext → 解密，结束；delta 或轮数被改 → 第 8 条；不是 TEA → 第 4 条
4. RC4 / AES / SM4：从 S 盒与密钥调度确认算法 → RC4 提取 key 解密；AES/SM4 提取 key / IV / mode → 调库解密，结束；S 盒被改 → 第 8 条；不是 RC4 / AES / SM4 → 第 5 条
5. base64：从二进制抄 64 字符表 → 用自定义表解码 → 解码成功则结束；解码后还有 XOR / 换位则按第 6 条处理，结束；解码失败 → 第 6 条
6. 自定义逐字节变换：把循环抄成 Python，按位反推（XOR 自逆、加法取补、查表逆表）→ 输出原文，结束；反推失败 → 第 7 条
7. 哈希 / CRC：若是"输入哈希 == 常量"，输入空间小则爆破 / 字典，命中则结束；CRC 只是校验则找被校验的原始数据，结束；哈希不可逆且空间大 → 第 9 条
8. 魔改算法：按伪代码重写 Python 参考实现，用一组已知明文 / 密文对验证 → 验证通过后解密，结束；对不上 → 第 9 条
9. 算法不可逆或密钥未知 → 转 [动态调试](/reverse/dynamic-debug) 抓中间值，或侧信道爆破；仍不行 → 第 10 条
10. 以上都不成立 → 回 ③-1 第 1 条，用 `strings`、熵、表长重新分类

## ④ 工具与命令

```bash
# 常量扫描：先让工具报算法名
signsrch target.exe
# IDA: Edit -> Plugins -> FindCrypt（findcrypt-yara 插件）

# 自己扫：可控、可加自定义签名
python scan_const.py target.exe
```

```python
# scan_const.py
import sys
sigs = {
    'TEA delta 0x9E3779B9': bytes.fromhex('b979379e'),
    'TEA -delta 0x61C88647': bytes.fromhex('4786c861'),
    'TEA sum 0xC6EF3720': bytes.fromhex('2037efc6'),
    'MD5/SHA1 IV head': bytes.fromhex('0123456789abcdef'),
    'AES S-box head': bytes.fromhex('637c777bf26b6fc5'),
    'SM4 S-box head': bytes.fromhex('d690e9fecce13db7'),
    'CRC32 table': bytes.fromhex('0000000096300777'),
}
data = open(sys.argv[1], 'rb').read()
for name, sig in sigs.items():
    off = data.find(sig)
    print(f'{name:28s} {hex(off) if off >= 0 else "not found"}')
```

```python
# 自定义 base64：把自定义表映射回标准表
import base64
std = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
custom = b'...'                                        # 从二进制里抄
trans = bytes.maketrans(custom, std)
print(base64.b64decode(s.encode().translate(trans)))
```

```python
# 识别出 AES/RC4 后直接调库
from Crypto.Cipher import AES, ARC4
from hashlib import md5, sha1
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 搜 `0x9E3779B9` 没有，就以为不是 TEA | 编译器把 `sum += delta` 优化成 `sub 0x61C88647` | 同时搜补码；看 32 轮 Feistel 与 sum 终值 `0xC6EF3720` |
| 把 MD5 当 SHA1 | 前四个 IV 相同，x86 立即数都按小端存放 | 看第五个常量 `0xC3D2E1F0` 和输出长度；SHA256 首常量 `0x6A09E667` |
| base64 解出乱码 | 自定义字母表，或先做了 XOR | 从二进制抄 64 字符表，替换标准表后再解 |
| RC4 解不对 | KSA / PRGA 被改，或 key 长度不对 | 对照 `S[i]=i` 初始化与 `j=(j+S[i]+key[i%len])&0xff` |
| 找不到 AES S-box | 用了 T-table，或 S-box 被加密 / 压缩 | 搜 T-table 首项 `0xC66363A5` 等，或运行时 dump |
| 识别出算法但结果不对 | mode / IV / padding 错 | 从代码里找 IV、padding 与分组模式 |
| 常量只在代码里，不在 `.rdata` | 编译器把常量内联成立即数 | 用反汇编交叉引用，不要只扫数据段 |
| 魔改 TEA 直接套库失败 | delta / 轮数 / key schedule 被改 | 按伪代码重写参考实现 |
| 把 CRC32 当加密 | CRC 只是校验 | 看多项式 `0xEDB88320`，找被校验的原始数据 |
| 把哈希当加密想解密 | 哈希不可逆 | 爆破 / 字典 / 侧信道，或找哈希前的输入 |

## ⑥ 例题

**题目**：TEA 常量识别与解密（本页配套可复现样例）
**来源**：本页自建，等价于 CTF 里"识别 TEA → 提取 key → 解密"的算法识别题

**题干**：给一个 PE，输入 16 字节，正确输出 `Correct!`；要求逆出正确输入。

**附件**：`tea.exe`（MinGW gcc 14.2 编译，`-O2`，未加壳）

**关键观察**：
- `strings` 没有明文 flag，只有 `Correct!` / `Wrong!`
- 常量扫描：`0x9E3779B9` 搜不到，但补码 `0x61C88647` 在文件偏移 `0xa68` 命中；`0xC6EF3720` 在 `0xab2` 命中
- 反汇编里是 32 轮 Feistel：`sub $0x61c88647`、`cmp $0xc6ef3720`、`jne` 回循环
- `.rdata` 文件偏移 `0x2410` 有 16 字节密文 `f7517c04...`

**走了哪条链**：③-1 第 5 条（TEA 常量 / Feistel）→ ③-2 第 3 条（确认 TEA、提取 key / 密文、解密）→ 结束。

**命令与输出**：

```text
$ python scan_const.py tea.exe
TEA delta 0x9E3779B9         not found
TEA -delta 0x61C88647        0xa68
TEA sum 0xC6EF3720           0xab2
MD5/SHA1 IV head             not found
AES S-box head               not found
SM4 S-box head               not found
CRC32 table                  not found
```

反汇编关键片段：

```text
140001465: sub  $0x61c88647,%r8d       ; sum += delta（delta 写成补码）
140001473: sub  $0x76543211,%r9d       ; +0x89abcdef
14000147a: add  $0x1234567,%eax        ; +0x01234567
140001497: add  $0x76543210,%r9d
14000149e: sub  $0x1234568,%eax        ; +0xfedcba98
1400014af: cmp  $0xc6ef3720,%r8d       ; 32 轮后的 sum
1400014b6: jne  140001460
```

- `0x61C88647` = `-0x9E3779B9`，`0xC6EF3720` = `0x9E3779B9 * 32 mod 2^32` —— 两个特征同时出现，可以确定 TEA
- key 被内联成四个立即数：`0x01234567`、`0x89abcdef`、`0xfedcba98`、`0x76543210`
- `sub $0x76543211` 等价于 `+0x89abcdef`，`sub $0x1234568` 等价于 `+0xfedcba98`

解密脚本：

```python
import struct

key = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210]
ct = bytes.fromhex('f7517c0413f2ab8ac050cf093228a48d')

def tea_dec(block):
    v0, v1 = struct.unpack('<2I', block)
    s = 0xC6EF3720
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + s) ^ ((v0 >> 5) + key[3]))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + s) ^ ((v1 >> 5) + key[1]))) & 0xffffffff
        s = (s - 0x9E3779B9) & 0xffffffff
    return struct.pack('<2I', v0, v1)

print((tea_dec(ct[:8]) + tea_dec(ct[8:])).decode())
```

输出：

```text
flag{tea_demo!!}
```

回程序验证：

```text
$ ./tea.exe 'flag{tea_demo!!}'
Correct!
```

**结果**：补码形式的 delta 和 32 轮后的 sum 是 TEA 的稳定指纹；识别出算法后不必逐轮逆，直接用标准 TEA 解密即可。本页样例为自建，实际比赛 flag 以平台为准。

::: tip 同类公开练习
- CryptoHack 的 `Symmetric Cryptography` 章节（AES / RC4 / TEA 结构）
- Crackmes.one 上标注 `crypto` 的 crackme（用常量扫描找算法）
:::
