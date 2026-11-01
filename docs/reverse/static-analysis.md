# 常规静态分析

关键词：逆向 reverse IDA Ghidra 静态分析 注册码 crackme 反编译 汇编 校验函数 主函数

## ① 识别指纹

- 附件是 ELF / PE，题干说"逆向"、"找注册码"、"分析这个程序"
- 程序运行后要求输入一个 `flag` / `serial` / `password`，输错了就退出
- **没有网络交互**（不是 `nc` 到远程）—— 这是和 Pwn 最直接的分界
- 题目名带 `re` / `easyre` / `babyre` / `crackme` / `login`
- 分值中等，位置通常在 reverse 方向的前两三题
- `strings` 里能看到 `flag`、`correct`、`wrong`、`input:` 这类词

## ② 考什么

- 定位 `main`（Linux 有符号时直接找；无符号时从 `__libc_start_main` 的第一个参数找）
- 字符串交叉引用（XREF）：从 `"wrong"` 反推校验函数
- 函数重命名与数据结构识别
- 常见校验模式：`strcmp` 直接比较 / 逐字符变换后比较 / 查表 / 自定义编码
- 常见算法识别：base64、RC4、TEA/XTEA、简单异或、循环移位
- 编译期优化造成的"反直觉"代码：内联、循环展开、`-O2` 后的常量折叠
- IDA Hex-Rays 反编译与 Ghidra 的对比使用

## ③ 判断流程

1. **`file 程序`** 确认架构、位数、是否 `statically linked`
   - 有 `UPX` / `packed` 字样 → 先去 [加壳与脱壳](/reverse/unpacking)
   - 正常 → 继续
2. **`strings -n 6 程序 | grep -iE 'flag|correct|wrong|input|serial|key'`** —— 有命中的字符串，这题就有一半了
3. **直接运行一遍**（在隔离环境 / Windows 沙箱）：
   - 有交互 → 记下提示文字，回到 2 里找对应字符串
   - 无交互直接退出 → 输出可能被写死，跳 5
   - 崩溃 / 要求特殊环境 → 可能是驱动、需要特定文件，先看 `strace ./prog`
4. **IDA / Ghidra 打开**：
   - 有符号 → 直接在函数列表找 `main`
   - 无符号 → 找 `entry`，跟到 `__libc_start_main`，第一个参数就是 `main`
5. **从字符串反推**：在 IDA 里对 `"correct"` / `"wrong"` 按 `X` 看交叉引用，跳到校验函数
6. **读校验逻辑**：
   - 是 `strcmp(input, "明文")` → 直接抄，结束
   - 是逐字符 `input[i] ^ k == table[i]` → 把 table 和 k 抄出来写脚本
   - 是调用了某个已知算法 → 识别算法（见 [算法识别](/reverse/algorithm-id)）
7. **读不懂控制流**（花指令、扁平化、大 switch）→ 转 [动态调试](/reverse/dynamic-debug)，直接下断点看内存
8. **算法太复杂、来不及逆** → 考虑**侧信道**：把待比较的内存 dump 出来，或者直接爆破（输入空间小时）
9. **程序根本没交互**：flag 就藏在常量/资源段里 → `strings` 全量 + `objdump -s -j .rodata`
10. **以上都不成立** → 回第 1 条，重新按"这不是常规逆向题"分类（可能是 VM、壳、内核模块）

## ④ 工具与命令

```bash
file ./crackme
strings -n 6 ./crackme | less
objdump -d ./crackme | less
objdump -s -j .rodata ./crackme        # 直接看只读数据段
readelf -s ./crackme | grep -i main    # 有符号时的函数表
nm -C ./crackme | grep ' T '
```

```text
图形工具
IDA Pro / IDA Free        反编译首选，Hex-Rays 伪代码质量最高
Ghidra                    免费，反编译质量接近，支持脚本（Python/Java）
Binary Ninja              反编译体验好，付费
Cutter + radare2          开源，命令行友好
检测工具
Detect It Easy (DIE)      一键看壳、编译器、语言
```

```python
# 常见的"逐字符异或"校验，直接抄出 table 和 key 就能解
table = [0x12, 0x34, ...]
key = [0x0f, 0x1e, ...]
print(''.join(chr(t ^ k) for t, k in zip(table, key)))
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| IDA 找不到 `main` | 静态链接 / 被 strip | 从 `entry` 跟 `__libc_start_main` |
| 反编译出来是乱码或跳转错乱 | 花指令 / 反编译失败 | 先 `C` 强制转代码，再 `P` 定义函数；或换 Ghidra |
| 校验函数里看不到 `strcmp` | 编译器内联成了循环比较 | 看循环里的逐字节比较，或者直接动态跑 |
| 程序跑起来就崩 | 缺依赖库 / 检测到调试器 | `ldd` 看依赖；`strace` 看系统调用 |
| 逻辑看懂了但写不出解密脚本 | 算法有状态（如 RC4 的 S 盒） | 先识别算法名，再找现成实现 |
| 明明 `strcmp` 相等还判错 | 比较前对输入做了变换 | 往回找 `strcmp` 的第一个参数是怎么来的 |
| 32/64 位搞混 | 参数传递方式不同 | `file` 一眼确认，别猜 |

## ⑥ 例题

**题目**：逐字符异或校验（可本地复现的最小样例）
**来源**：本页配套样例，等价于 `picoCTF` 系列 crackme 与各校赛"s1mpl3rev"类题目的核心结构

**题干**：给一个 ELF 程序，运行后提示 `Input flag: `，输入正确则输出 `Correct!`，否则 `Wrong!`。

**关键观察**：
- `strings` 里同时出现 `Input flag: `、`Correct!`、`Wrong!` —— 校验逻辑一定紧挨着这三个字符串
- `file` 显示 64 位、未加壳、动态链接

**走了哪条链**：第 1 条（正常 ELF）→ 第 2 条（命中了字符串）→ 第 4 条（有符号，直接进 `main`）→ 第 5 条（从 `Correct!` 反查交叉引用）→ 第 6 条（识别出逐字符异或）。

**命令与输出**：

```text
$ strings -n 6 ./crackme
Input flag:
Correct!
Wrong!
```

伪代码（IDA Hex-Rays 还原后大致是这样）：

```c
int check(char *in) {
    if (strlen(in) != 8) return 0;
    unsigned char tbl[8] = {0x36,0x35,0x34,0x3e,0x2c,0x3d,0x28,0x38};
    for (int i = 0; i < 8; i++)
        if ((in[i] ^ 0x55) != tbl[i]) return 0;
    return 1;
}
```

写脚本反推：

```python
tbl = [0x36,0x35,0x34,0x3e,0x2c,0x3d,0x28,0x38]
print(''.join(chr(t ^ 0x55) for t in tbl))
```

输出：

```text
flag{hax}
```

**结果**：校验函数的语义是"输入每一位异或 `0x55` 后等于常量表"，因此把常量表再异或一次 `0x55` 就得到原文。异或运算是自逆的 —— 这是逆向题里最常利用的性质。

**验证方法**：把解出的字符串输回程序，应当输出 `Correct!`。**任何逆向题的答案都必须回程序验证一次**，不要只信脚本输出。

::: tip 同类公开练习
- `picoCTF` 的 `transformation`（简单的编码逆运算）
- `BUUCTF` 的 `[BJDCTF2020] JustRE`（从字符串反查校验）
- `Crackmes.one` 的入门级 crackme（大量同类结构）
:::
