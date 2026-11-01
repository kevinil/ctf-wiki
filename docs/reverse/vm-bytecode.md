# 虚拟机与自定义字节码

关键词：虚拟机 VM virtual machine 字节码 bytecode opcode 解释器 interpreter dispatch 分发器 switch jump table handler 自定义指令 逆向

## ① 识别指纹

- 一个巨大函数里是 `while(1)` + `switch`，或 `jmp *rax` 间接跳转，case 数量远多于正常业务
- 代码里有 `pc` / `ip` / `sp` 变量，循环里 `pc++` 或 `pc += n`
- `.rodata` / `.data` 里有一段高熵或规律性字节数组，长度与输入长度成倍数
- 函数被拆成很多小 handler，每个 handler 只做一件事（加减 / 异或 / load / store / jmp）
- 字符串出现 `opcode`、`invalid instruction`、`vm`、`bytecode`、`interpreter`
- 输入长度固定，错误提示统一；程序行为像"解释执行"而不是直接计算
- IDA 反编译出 `switch ( *(_BYTE *)(pc) )` 或跳转表；Ghidra 显示 `switchD`
- Android / Java 层有 `switch (byte)` + `byte[] code`；Python 层有 `dispatch = {...}` + `exec`
- 注意：OLLVM 控制流平坦化也有大 `switch`，但没有独立的字节码数组

## ② 考什么

- 定位 dispatch 循环：找 `switch` / 跳转表 / 间接跳转
- 恢复 `opcode -> handler` 映射：每个 handler 消耗几个字节、改哪个寄存器 / 栈
- 定位字节码数组：起始地址、长度、指令宽度、字节序
- 识别 VM 状态：`vm_ctx` 结构体里的寄存器组、栈、内存、输入缓冲区、`pc`
- 写 Python 解释器复现语义，而不是硬读每个 handler
- 在解释器上解约束 / 爆破输入，或反运算
- 区分 VM 与 OLLVM 扁平化、脚本解释器
- 运行时 dump 字节码（解密后）、用 Unicorn / angr 辅助

## ③ 判断流程

### ③-1 子类型分流

1. 有大 `switch` / 跳转表，且 `.rodata` 里有独立字节数组 → 自定义 VM，跳 ③-2 第 1 条
2. 有大 `switch` 但每个 case 是原程序的基本块，没有字节码数组 → OLLVM 控制流平坦化，转 [汇编阅读与手工还原](/reverse/asm-reading)
3. 看到 `eval` / `exec` / `Function` / `dispatch` 字典执行字符串或字节码 → 脚本 VM，转 [脚本类逆向](/reverse/script-reverse)
4. Java / Android 层 `switch` + `byte[]` → Java VM，先按 [Android 逆向](/reverse/android) 拿 dex，再回本页
5. 字节码在 `.rodata` 里是明文 → 跳 ③-2 第 2 条
6. 字节码在初始化时被 XOR / RC4 解密 → 跳 ③-2 第 5 条
7. 以上都不成立 → 回 [常规静态分析](/reverse/static-analysis)

### ③-2 成本排序链

1. 运行程序，记录输入长度与输出；用错误输入确认是逐字节校验还是整体变换 → 进第 2 条
2. IDA/Ghidra 找 dispatch：搜 `jmp rax` / `jmp *` 间接跳转、`switch`、循环里的 `pc++` → 定位 dispatch 循环 → 第 3 条
3. 从 jump table / switch cases 抽 `opcode -> handler`：记录每个 handler 读取的字节数、修改的寄存器 / 栈 → 得到指令表 → 第 4 条
4. 定位字节码数组：dispatch 初始化处的 `lea reg,[rip+...]`、`.rodata` 里的连续字节；确认起始、长度、指令宽度 → 明文则第 6 条，密文则第 5 条
5. 字节码被加密 → 找初始化前的解密循环（XOR / RC4 / 压缩），在内存中 dump 解密后的数组 → 回第 4 条
6. 用 Python 写解释器：按指令表实现 handler，跑字节码，先让错误输入得到与程序一致的 `Wrong` → 第 7 条
7. 校验型 VM（`CMP` 后置 `ok` 标志）→ 在解释器里逐位爆破 / 约束求解，得到输入 → 回程序验证，结束；结果不对 → 第 8 条；变换型 VM → 用解释器反运算，结束
8. 解释器结果与程序不一致 → 检查指令宽度、字节序、栈方向、寄存器初值、8/32 位截断 → 回第 3 条
9. 静态定位不到 dispatch（花指令 / 混淆）→ 动态调试在 `jmp *` / `switch` 处下断点，记录 opcode 序列 → 回第 3 条
10. 以上都不成立 → 回 ③-1 第 1 条，用 Unicorn 模拟整段 code 段，观察内存访问

## ④ 工具与命令

```bash
# 静态定位 dispatch 与字节码
objdump -d target.exe | grep -nE "jmp.*\*|switch"
objdump -s -j .rodata target.exe | head -40
readelf -x .rodata target.elf | head -40
xxd -s 0x2440 -l 160 target.exe
```

```text
IDA
  Options -> General -> Number of opcode bytes 设为 6，方便看指令字节
  在 jmp rax / switch 跳转处按 Enter 跟 jump table
Ghidra
  Decompiler 视图对照 case 与跳转表
Unicorn
  pip install unicorn：映射 code/data 段，跑字节码并 hook 内存访问
angr
  pip install angr：对输入符号化，适合校验型 VM
```

```python
# 解释器骨架：先对齐语义，再谈解题
pc = 0
acc = 0
ok = True
while True:
    op = code[pc]; pc += 1
    if op == 0x00:
        break
    elif op == 0x01:
        acc = inp[code[pc]]; pc += 1
    elif op == 0x02:
        acc ^= code[pc]; pc += 1
    elif op == 0x03:
        acc = (acc + code[pc]) & 0xFF; pc += 1
    elif op == 0x04:
        if acc != code[pc]:
            ok = False
        pc += 1
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 大 `switch` 就当成 VM | OLLVM 扁平化没有字节码数组 | 先找 `.rodata` 的字节码；没有就转 asm-reading |
| jump table 读出来是乱的 | 表项是相对偏移不是绝对地址 | 用 `jmp rax` 处的基址 + 表项偏移计算 |
| handler 里 `pc` 每次加 2 不是 1 | 指令是定长多字节或变长 | 按每个 handler 实际读取的字节数解析 |
| 多字节立即数读反 | 字节序搞错 | 看 handler 用 `movzx` 逐字节拼还是 `mov` 整字读 |
| 解释器跑出来全是错 | 栈方向 / 寄存器初值 / 截断位宽不对 | 用一组已知输入输出校准 |
| 硬读每个 handler 花太久 | 方法不对 | 先抽指令表，再写解释器 |
| 静态 dump 的字节码是密文 | 运行时才解密 | 在 dispatch 前 / 后下断点 dump |
| `switch` 的 default 也像 handler | default 是错误处理 / 反调试 | 只统计正常 opcode 范围 |
| 输入长度检查过不去 | VM 先检查长度 | 先满足长度，再解内容 |
| 字节码地址在 PIE 下变 | 基址随机化 | 用 `模块基址 + RVA`，或运行时 dump |

## ⑥ 例题

**题目**：自定义 5 opcode VM（本页配套可复现样例）
**来源**：本页自建，等价于 CTF 里"自定义字节码 + 逐字节校验"的 VM 题

**题干**：给一个 PE，输入 16 字节，正确输出 `Correct!`；程序用一个自定义 VM 解释字节码完成校验。

**附件**：`vm.exe`（MinGW gcc 14.2 编译，`-O2`，未加壳）

**关键观察**：
- `main` 里是 `while(1)` + `switch(op)`，`lea ... # 140004041 <code+0x1>` 指向字节码
- `.rdata` 文件偏移 `0x2440` 开始是 129 字节字节码，首字节 `01 00 02 11 03 03 04 7a`
- jump table 在 `.rdata+0x10`，5 个表项对应 opcode `0x00`–`0x04`
- handler 极短：`xor (%rax),%r8b`、`add (%rax),%r8b`、`cmp %r8b,(%rax)`

**走了哪条链**：③-1 第 1 条（switch + 字节码数组）→ ③-2 第 2–6 条（定位 dispatch、抽指令表、写解释器）→ 第 7 条（逐位爆破）→ 结束。

从 handler 读出的指令表：

| opcode | 语义 | 消耗字节 |
|---|---|---|
| `0x00` | HALT | 1 |
| `0x01` | `acc = input[imm]` | 2 |
| `0x02` | `acc ^= imm` | 2 |
| `0x03` | `acc = (acc + imm) & 0xff` | 2 |
| `0x04` | `if acc != imm: ok = 0` | 2 |

**命令与输出**：

反汇编关键片段（从 `objdump -d vm.exe` 的输出中摘出）：

```text
1400029b7: lea   0x1683(%rip),%rax   # 140004041 <code+0x1>
1400029cd: cmpb  $0x4,-0x1(%rax)
1400029d1: ja    140002980 <main.cold>
1400029db: movslq (%rcx,%rdx,4),%rdx
1400029e2: jmp   *%rdx
1400029fc: add   (%rax),%r8b
140002a05: xor   (%rax),%r8b
140002a0a: movzbl (%rsi,%rdx,1),%r8d
140002a32: cmp   %r8b,(%rax)
```

```text
$ objdump -s -j .rdata vm.exe | grep -A1 "140004040"
 140004040 01000211 0303047a 01010222 03070455  .......z..."...U
 140004050 01020233 030b045d 01030244 030d0430  ...3...]...D...0
```

Python 解释器 + 逐位爆破：

```python
code = bytes.fromhex(
 "010002110303047a010102220307045501020233030b045d01030244030d0430"
 "010402550311043f0105026603130423010602770317043101070288031d04f4"
 "01080299031f04c7010902aa032304fc010a02bb0329040d010b02cc032b04da"
 "010c02dd032f041c010d02ee0331040f010e020f0337049a010f02f0033b04c800")

def run(inp):
    acc = pc = idx = 0
    while True:
        op = code[pc]; pc += 1
        if op == 0x00:
            return None
        if op == 0x01:
            acc = inp[code[pc]]; pc += 1
        elif op == 0x02:
            acc ^= code[pc]; pc += 1
        elif op == 0x03:
            acc = (acc + code[pc]) & 0xFF; pc += 1
        elif op == 0x04:
            if acc != code[pc]:
                return idx          # 返回第一个失败的 CMP 序号
            pc += 1; idx += 1

inp = bytearray(b'A' * 16)
for i in range(16):
    for c in range(256):
        inp[i] = c
        r = run(inp)
        if r is None or r > i:      # 第 i 位之后不再失败，说明这一位对了
            break
print(inp.decode())
```

输出：

```text
flag{vm_1s_c00l}
```

回程序验证：

```text
$ ./vm.exe 'flag{vm_1s_c00l}'
Correct!
```

**结果**：VM 的语义只有 LOAD / XOR / ADD / CMP 四种运算；把字节码抽出来写解释器，再逐位爆破即可恢复输入，不需要逐行读 handler。本页样例为自建，实际比赛 flag 以平台为准。

::: tip 同类公开练习
- Crackmes.one 上标注 `vm` / `bytecode` 的 crackme
- `picoCTF` 的 `reverse_cipher`（先理解变换，再写逆变换）
- `angr` 官方文档里的 CTF 示例（符号执行解校验型程序）
:::
