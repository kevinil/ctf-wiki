# 压缩包与文件格式

关键词：压缩包 zip rar 7z 伪加密 明文攻击 bkcrack CRC 解压密码 爆破 分卷 文件格式

## ① 识别指纹

- 附件后缀 `.zip` / `.rar` / `.7z` / `.tar.gz`，或者 `file` 显示 `Zip archive data`
- 解压提示**需要密码**，但题干一个提示都没给
- 解压直接报错：`unexpected end of archive` / `CRC error` / `unsupported compression method`
- 文件名看起来正常，但内容是乱码
- 解压出来是**另一个压缩包**，或者一张图里还有一层
- 题干提到"解压密码"、"爆破"、"损坏的压缩包"

## ② 考什么

- **伪加密**：ZIP 的 general purpose bit flag 第 0 位被置 1，但实际没有加密
- **明文攻击**：知道压缩包里某个文件的内容 → 恢复加密密钥（bkcrack / pkcrack）
- **CRC32 碰撞**：文件内容未知但知道 4 字节 CRC
- **弱口令 / 掩码爆破**：john + zip2john / rar2john / 7z2john
- **结构修复**：本地文件头损坏、中央目录缺失、被整体异或/移位
- **嵌套与递归**：套娃压缩包、图片里的压缩包
- **元数据**：注释（`unzip -z`）、NTFS 备用数据流、文件名编码
- **格式特性**：ZIP 的 `store` vs `deflate`、分卷、RAR5 与 RAR4 的差异

## ③ 判断流程

1. **`file 附件` + `binwalk 附件`** —— 确认真实格式，看有没有嵌套；`binwalk -e` 能解出来的直接解
2. **试着直接解压**（`unzip -l` 先看文件列表，不解压）
   - 能解 → 看内容，回 [题型总表](/map) 重新分类
   - 要密码 → 跳 3
   - 报结构错误 → 跳 7
3. **判伪加密**：十六进制打开，看 ZIP local file header（`50 4B 03 04`）的 **偏移 6–7** 字节
   - 值为 `00 01` / `01 00`（第 0 位置 1）→ 伪加密，改成 `00 00` 后重新解压
   - 中央目录（`50 4B 01 02`）的 **偏移 8–9** 也要一起改
   - 改完能解 → 结束
4. **看压缩包内文件列表**：里面有没有你**已经有**的文件？（同目录给了原文件、或者是有名的公开文件如 `README`、图片）
   - 有 → **明文攻击**：`bkcrack -C 密文.zip -c 已知文件 -P 明文.zip -p 已知文件`，跳 6
5. **找密码线索**：压缩包注释（`unzip -z`）、文件名、题干、同目录其他文件
   - 有线索 → 用线索生成字典（`crunch` / 手写组合）
   - 无线索但密码看起来很短 → 直接爆破，跳 6
6. **爆破 / 恢复**：
   - 字典或掩码爆破：`zip2john` → `john`；或 `hashcat -m 13600`
   - 已知明文：`bkcrack` 恢复密钥后 `bkcrack -U 密文.zip 明文.zip -k <key>`
   - 知道 CRC：CRC32 碰撞小文件
7. **结构修复**：
   - `zip -FF 损坏.zip --out fixed.zip` 先试
   - 十六进制看文件头是不是被改（`50 4B 03 04` 是否还在）
   - 被整体异或/加偏移的：找出规律反推（前几个字节应该是什么是已知的）
8. **以上全不成立** → 回到第 1 条，用 `binwalk` 把所有嵌套层都列出来，逐层分析；或者把压缩包当**二进制文件**看待（可能根本不是压缩包）

## ④ 工具与命令

```bash
file 附件.zip
binwalk -e 附件.zip
unzip -l 附件.zip            # 只列内容
unzip -v 附件.zip            # 看压缩方法、CRC、大小
unzip -z 附件.zip            # 看注释
7z l 附件.zip
```

```bash
# 伪加密手改：把 local header 和 central directory 的 flag 位清零
python - <<'EOF'
import sys
p = '附件.zip'
d = bytearray(open(p,'rb').read())
i = 0
while True:
    i = d.find(b'PK\x03\x04', i)
    if i < 0: break
    if d[i+6] & 0x01:
        d[i+6] = 0; print('fixed local header @', hex(i))
    i += 4
i = 0
while True:
    i = d.find(b'PK\x01\x02', i)
    if i < 0: break
    if d[i+8] & 0x01:
        d[i+8] = 0; print('fixed central dir @', hex(i))
    i += 4
open('fixed.zip','wb').write(d)
EOF
unzip fixed.zip
```

```bash
# 爆破
zip2john 附件.zip > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 17200 hash.txt rockyou.txt     # zip2john 生成的新格式

# 明文攻击（需要至少 12 字节已知明文，且压缩方法一致）
bkcrack -C 加密.zip -c 内部文件名 -P 明文.zip -p 明文文件名
bkcrack -C 加密.zip -k <恢复出的三个 key> -U 解密.zip 新文件名
```

```bash
# 结构修复
zip -FF 损坏.zip --out fixed.zip
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 提示要密码，但改 flag 就解开了 | 伪加密，flag 位被手工置 1 | 只改 flag 位，别动其他字节 |
| 明文攻击一直失败 | 已知的明文压缩方法/版本与包内不一致 | 用同样的 `zip` 命令重新压出明文包，`-0`（store）最稳 |
| `unzip` 报 CRC 错误但文件能出来 | CRC 被改过，可能是校验题 | 用 `7z x` 强制解，或用 CRC 反推内容 |
| RAR 爆破极慢 | RAR5 的 KDF 比 ZIP 重得多 | 先试明文和伪加密；实在要爆就上 GPU + hashcat `-m 12500` |
| `binwalk -e` 解出一堆垃圾 | 误识别 | 结合 `file` 和十六进制看，不要盲信 binwalk |
| 解压出来文件名乱码 | 文件名编码是 GBK 而系统按 UTF-8 解析 | `unzip -O GBK`（或用 `7z` 指定 `-mcp=936`） |
| 密码对了还是解不开 | 压缩包是多分卷 | 把所有分卷放同目录，解第一个 |

## ⑥ 例题

**题目**：ZIP 伪加密（flag 位手工置位）
**来源**：CTF 压缩包类最基础的题型，国内各入门赛和 BUUCTF 合集里最常见的一类

**题干**：给一个 `flag.zip`，双击解压要求输入密码，但题干没有任何关于密码的提示。

**关键观察**：
- 题干**一个提示都没给** —— 如果真的要爆破，通常会暗示密码长度或字符集
- `unzip -v flag.zip` 能看到每个文件的压缩方法、CRC 大小都正常
- 十六进制里 `50 4B 03 04` 后面紧跟着的 flag 字节是 `09 00` —— 第 0 位是 1

**走了哪条链**：第 1 条（`file` 确认是 ZIP）→ 第 2 条（要密码）→ 第 3 条（十六进制看 flag 位，判定伪加密）。

**命令与输出**：

```text
$ xxd -l 32 flag.zip
00000000: 504b 0304 0900 0000 0000 ...     PK........
                    ↑↑
              偏移 6-7 = 09 00，第 0 位为 1

$ unzip -v flag.zip
  Length  Method  Size  Cmpr  Date    Time   CRC-32   Name
      42  Defl:N     40   5%  ...    1234abcd  flag.txt
```

用上面第 ④ 段的脚本清零 flag 位后：

```bash
$ python unzip_fake.py
fixed local header @ 0x0
fixed central dir @ 0x56

$ unzip fixed.zip
Archive:  fixed.zip
  inflating: flag.txt

$ cat flag.txt
flag{...}
```

**结果**：flag 直接写在 `flag.txt` 里。

**怎么看出"这是伪加密而不是真加密"**：真加密的 flag 位是 1，**同时**压缩包内有真实的加密数据；伪加密只是把标志位改成了 1，文件本身是明文存储的。所以"密码不知道、题干没提示、但字节层面 flag 位可疑"这三个信号同时出现，几乎可以直接判定。

::: tip 判断口诀
**没提示要密码 → 先怀疑伪加密；有已知明文 → 先怀疑明文攻击；啥线索都没有 → 才爆破。**
:::
