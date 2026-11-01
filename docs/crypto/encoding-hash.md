# 编码与哈希基础

关键词：编码 base64 base32 base16 base58 hex 十六进制 哈希 md5 sha1 长度扩展 hash length extension 哈希碰撞 URL编码

## ① 识别指纹

- 题干只有一串字符，或者附件是一个 `.txt` 里塞着好几行乱码
- 字符集很规整：只有 `A-Za-z0-9+/=`、只有 `0-9A-F`、只有 `%xx`、只有 `\uXXXX`
- 题目名带 `base` / `encode` / `编码` / `签到` / `easy`
- 字符串长度是 4 的倍数（base64）、2 的倍数（hex）
- 哈希题会给 `md5(...)` / `sha256(...)` 的调用，或者问"这个哈希对应的原文是什么"

## ② 考什么

- **base 家族**：base16(hex) / base32 / base36 / base58 / base62 / base64 / base85 / base91 / base100
- **URL 编码、HTML 实体、Unicode 转义、`\x` 转义、JS `\u` 转义**
- **多层嵌套**：同一段数据套了 3–5 层编码
- **变种 base64**：换表（自定义字符表）、去掉 padding、加盐
- **哈希**：MD5 / SHA1 / SHA256 的识别与反查（彩虹表）
- **哈希长度扩展攻击**（Merkle–Damgård 结构的固有问题）
- **MD5 碰撞**（fastcoll / 已公开的对撞样本）
- **加盐哈希**与暴力破解的选择

## ③ 判断流程

1. **数一下字符集**，这是最快的分流：
   - 只含 `0-9A-F`（或 `a-f`），长度偶数 → **hex**，解出来再回第 1 条
   - 只含 `A-Z2-7` 加 `=` → **base32**
   - 含 `A-Za-z0-9+/` 和结尾 `=`，长度 %4==0 → **base64**
   - 含 `A-Za-z0-9` 无 `+/`，长度可能是 44/43 → 可能是 **base64 无 padding** 或 **base62**
   - 含 `%XX` → **URL 编码**
   - 含 `&#...;` / `&amp;` → **HTML 实体**
   - 含 `\uXXXX` → **Unicode 转义**
   - 含大量不可见字符 → **零宽字符隐写**，跳 6
   - 都不匹配 → 跳 2
2. **把整段丢进 CyberChef 的 Magic 模式**，它会自动尝试几十种组合 —— 这是性价比最高的一步
3. **解出来还是乱码？** 说明套了不止一层，把结果再丢回第 1 条，循环解到可读为止（常见 3–5 层）
4. **base64 解开但内容是乱码**：
   - 可能是**换表**的变种 base64（题目附件里通常有一张表）
   - 可能是加密后再 base64（回看脚本，找加密函数）
   - 可能要先做 XOR 再做 base64
5. **哈希类**：拿到 `md5` 值先丢进 `cmd5` / `crackstation` / `hashcat` 查
   - 查到 → 结束
   - 查不到且题干提到了 `secret` / `key` / `admin` → **考虑长度扩展攻击**，跳 7
6. **零宽字符**：把不可见字符按 `U+200B`/`U+200C`/`U+200D` 映射成 `0/1`，再按 8 位转 ASCII
7. **长度扩展攻击**：需要三个条件同时满足
   - 服务端用 `md5(secret || data)` 做签名
   - 你知道 `secret` 的**长度**（不需要知道内容）
   - 你能控制 `data`
   → 用 `hashpump` / `hash_extender` 构造新的 `data'` 和对应签名
8. **以上全不成立** → 回第 1 条，用"这不是编码"的视角重看：可能是图形二维码、可能是文本隐写（首字母、大小写、标点）

## ④ 工具与命令

```bash
# 命令行快速转
echo 'SGVsbG8=' | base64 -d
xxd -r -p <<< "48656c6c6f"      # hex -> 文本
python -c "import urllib.parse;print(urllib.parse.unquote('%66%6c%61%67'))"
python -c "print(bytes.fromhex('666c6167').decode())"
```

```python
import base64
base64.b64decode('SGVsbG8=')        # base64
base64.b32decode('JBSWY3DP')        # base32
base64.b16decode('48656C6C6F')      # base16
base64.b85decode(b'...')            # base85
# base58 需要额外库：pip install base58
import base58; base58.b58decode('...')
```

```bash
# 哈希
hashcat -m 0 hash.txt rockyou.txt        # -m 0 = MD5
hashcat -m 100 hash.txt rockyou.txt      # SHA1
john --format=raw-md5 hash.txt

# 长度扩展
pip install hashpump
hashpump -s <已知签名> -d <已知data> -a <追加内容> -k <secret长度>
# 或 https://github.com/iagox86/hash_extender
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| base64 解码报 `Invalid base64` | 长度不是 4 的倍数 / 缺 padding | 手动补 `=` 到 4 的倍数 |
| base64 解出来是乱码但能打印 | 解出来的是 UTF-8 之外的字节 | 先存成二进制文件再 `file` 它 |
| hex 解出来中文乱码 | 编码不是 UTF-8（常见 GBK） | 换 `gbk` / `latin1` 解码 |
| 解了一层还有一层 | 出题人故意套娃 | 循环解，直到 CyberChef 输出可读 |
| 哈希查不到 | 加了盐或原文很长 | 看题目是否给了盐；看是不是长度扩展 |
| 长度扩展算出来对不上 | `secret` 长度猜错 | 长度通常题目直接给，或者从脚本里数 |
| 零宽字符复制到编辑器就丢了 | 不可见字符被浏览器/编辑器吞掉 | 用 `xxd` / Python 按原始字节读，别用复制粘贴 |

## ⑥ 例题

**题目**：哈希长度扩展攻击
**来源**：CTF Crypto 经典题型，`hashpump` / `hash_extender` 的标准靶场（BUUCTF、各校赛常见）

**题干**：一个服务端，签名逻辑是：

```python
sign = md5(secret + data).hexdigest()
```

题目给出一个合法的 `data` 和它的 `sign`，以及 `len(secret)`（或你能从源码数出来）。目标是伪造 `data`，让它包含 `admin=true`，并用**合法的签名**通过校验。

**关键观察**：
- 服务端把 `secret` 拼在**前面**，然后用 MD5 —— 这正是 Merkle–Damgård 结构的弱点
- 你不需要知道 `secret` 是什么，只需要知道它的**长度**

**走了哪条链**：第 5 条（哈希查不到，题干提到 secret）→ 第 7 条（三个条件全部满足，走长度扩展）。

**原理**（一句话）：MD5 处理完 `secret || data` 后，内部状态 `(A,B,C,D)` 就是签名本身。把这四个值当作初始状态，从 `data` 之后继续喂数据，就能算出 `md5(secret || data || padding || append)` —— 而 padding 是 MD5 自己会按规则补的。

**命令与输出**：

```text
$ hashpump
Input Signature: 6e1b4a...（已知的合法签名）
Input Data: user=guest
Input Key Length: 8
Input Data to Add: &admin=true

6e1b4a..........
user=guest\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80&admin=true
```

把这一整串（含不可打印字符）作为 `data`，把新签名作为 `sign` 提交：

```python
import requests
payload = b'user=guest' + b'\x80' + b'\x00'*61 + b'\x80' + b'&admin=true'
r = requests.get(url, params={'data': payload, 'sign': new_sign})
print(r.text)     # 服务端返回 flag
```

**结果**：服务端校验通过，认为你是 `user=guest&admin=true`。

**为什么服务端会中招**：它重算 `md5(secret + 你提交的data)`。由于你提交的 data 里包含了 MD5 的 padding 和追加内容，重算的结果**恰好等于**你从旧签名继续计算得到的新签名。秘密被"接"在了前面并延续了状态。

::: tip 判断能不能用
三个条件缺一不可：**secret 在 data 前面**、**hash 是 MD5/SHA1/SHA256 这类 Merkle–Damgård 结构**、**你知道 secret 长度**。
换成 SHA3 / BLAKE2 就不能这么玩（海绵结构，天然免疫）。
:::
