# 汇编阅读与手工还原

关键词：汇编 asm assembly 反汇编 手工还原 花指令 junk code 垃圾字节 控制流平坦化 OLLVM 平坦化 去混淆 反平坦化 deflat D810 指令 mov lea cmp test jmp jcc call ret push pop 序言 尾声 调用约定 SysV Win64 跳表 数组 结构体 反编译失败

## ① 识别指纹

- 静态分析能打开，但 Hex-Rays / Ghidra 反编译失败，输出 `JUMPOUT`、红色地址，或整个函数变成 `undefined`
- 反汇编里出现 `call $+5` 紧跟 `pop`，或者 `jmp` 的落点不在任何一条指令的边界上
- 函数图形视图呈"星形"：一个块被十几个块跳入，所有块又跳回它，块内反复读写同一个栈变量
- 伪代码能出来，但形状是 `while (1) { switch (state) { ... } }`，每个 case 只做一两步就改写 `state`
- 大量 `jmp rax` / `jmp QWORD PTR [reg+idx*8]`，后面跟着一组结构完全相同的 handler
- 一条源码级操作对应十几条 `add/sub/xor/and` 组合，真实值被反复拆开重组（MBA）
- 题干写 "obfuscated"、"ollvm"、"junk code"、"花指令"、"去混淆"
- 程序功能很小，代码段却异常大；`strings` 很少、导入表很干净
- 这页是 [常规静态分析](/reverse/static-analysis) 判断流程第 7 条的下游：伪代码读不懂时进入

## ② 考什么

- 常见指令的语义与副作用：`mov`、`lea`、`cmp`、`test`、`jmp`、`jcc`、`call`、`ret`、`push`、`pop`、`xor reg,reg`
- 函数序言与尾声：`push rbp; mov rbp,rsp` 开头，`leave; ret` 结尾；`-O2` 常省略帧指针
- 调用约定：SysV x86-64 与 Windows x64 的参数寄存器、栈参数、shadow space、callee-saved 寄存器
- 循环与分支的汇编形态：顶条件 / 底条件循环、`cmp` + `jcc`、`cmovcc`、`setcc`
- 数组与结构体：`base + index * sizeof(T) + offsetof(field)`，由 `shl`/`imul` 的常数反推元素大小与字段偏移
- 花指令：垃圾字节、跳到指令中间、`call $+5; pop reg`、永假跳转、同一段逻辑的两份副本
- 控制流平坦化（OLLVM）：分发器 + 状态变量 + 真实块；真实块结尾写入下一个状态并跳回分发器
- 手工还原：NOP 垃圾字节、按状态链重排真实块、把伪代码抄成可执行脚本
- 自动去混淆：IDA 的 D810（unflattening + MBA + dead code）、Binary Ninja 的 deflat

## ③ 判断流程

### ③-1 子类型分流

1. `file` 是 ELF/PE，反汇编完整、伪代码可读 → 正常代码，走 ③-2 第 1 条
2. 反汇编里出现 `call $+5; pop`、`jmp` 落点不在指令边界、或反编译器报错/`JUMPOUT` → 花指令，走 ③-2 第 4 条
3. 伪代码是 `while (1) { switch (state) }`，所有真实块都跳回同一块并改写 `state` → OLLVM 平坦化，走 ③-2 第 5 条
4. 同一条真值被 3 条以上 `add/sub/xor/and` 反复计算，控制流仍只有直接的 `jmp`/`jcc`、没有分发器 → MBA/指令替换，走 ③-2 第 7 条
5. 大量 `jmp rax` + 一组重复结构的 handler + `strings` 里出现 opcode 名字 → 转 [虚拟机与自定义字节码](/reverse/vm-bytecode)，本页流程结束
6. 以上都不成立 → 回第 1 条，先核对入口点、节区权限与代码段校验和，确认代码是否被改过

### ③-2 成本排序链

1. 用 `objdump -d -M intel 程序` 或 IDA 打开，找 `push rbp; mov rbp,rsp`（或 `sub rsp, imm`）与 `ret` → 标出函数起止 → 继续
2. 在函数内找 `cmp`/`test` 后紧跟的 `jcc`，记录条件成立/不成立两条边的汇合点 → 标出校验分支 → 继续
3. `cmp`/`test` 的判定只依赖输入与已定位的常量（立即数或 `.rdata` 表） → 抄出常量与运算，写脚本 → 跳到第 9 条
4. 看到 `call` 后紧跟 `pop reg`，或 `jmp` 落点落在上一条指令的字节中间 → 花指令；从真实目标按 `C` 转代码，把垃圾字节 patch 成 `90` → 跳到第 2 条
5. 多个块跳回同一块，该块读取一个被反复赋值的变量，再按该变量的值分发（间接跳转或 `cmp`/`je` 链） → OLLVM；为每个 case 记录"写入的状态值"与"真实块入口地址" → 继续
6. 按状态值排序 case（`state=0 → 1 → 2 …`），把真实块串成线性序列，丢弃分发器 → 得到线性逻辑 → 跳到第 3 条
7. 看到 `(x ^ y) + 2*(x & y)` 这类等价长表达式 → 用 D810 的 MBA 化简或 z3 验证化简规则 → 继续
8. 间接跳转目标由表项决定（`jmp [table+idx*8]` / `jmp rax`）且静态表可读 → 读出全部表项、枚举目标块 → 回到第 5 条重排
9. 写脚本还原输入/解密 → 输回程序验证输出正确 → 结束
10. 以上都不成立 → 回第 1 条，改从字符串 XREF 重新定位函数；仍不成立 → 转 [动态调试](/reverse/dynamic-debug)

## ④ 工具与命令

```bash
objdump -d -M intel ./prog | less
objdump -d --start-address=0x401000 --stop-address=0x401200 ./prog
objdump -s -j .rodata ./prog         # ELF 的只读数据段（常量、提示字符串）
objdump -s -j .rdata  ./prog         # PE 的只读数据段
objdump -r ./prog.o                  # 重定位项，能看出跳表指向
ndisasm -b 64 -o 0x401000 code.bin   # 没有文件头时，按字节反汇编
```

IDA 里的手工操作（快捷键）：

| 操作 | 快捷键 / 菜单 | 用途 |
|---|---|---|
| 强制转代码 | `C` | 把被当成数据的字节重新按指令解码 |
| 取消定义 | `U` | 反编译器跟丢后，先撤销再重新定义 |
| 定义函数 | `P` | 花指令把函数尾切断时，手工圈出函数范围 |
| 定义数据 | `D` | 跳表、常量表被误判成代码时 |
| 交叉引用 | `X` | 从字符串/常量反查使用点 |
| 修改字节 | `Edit → Patch program → Change byte` | 把花指令字节改成 `90`（NOP） |
| 汇编指令 | `Edit → Patch program → Assemble` | 把跳转改回真实目标 |

常见指令语义速查：

| 指令 | 语义 | 阅读要点 |
|---|---|---|
| `mov dst, src` | 传送 | 看清 `[rbp-0x8]` 是局部变量还是参数槽 |
| `lea dst, [mem]` | 只计算有效地址，**不访问内存** | `lea rax,[rbp-0x10]` 是取局部变量地址；`lea eax,[rdx+rdx*4]` 是 `rdx*5` |
| `cmp a, b` | 计算 `a - b`，只改标志位 | 后面跟 `jcc`、`setcc` 或 `cmovcc` |
| `test a, b` | 按位与，只改标志位 | `test eax,eax` 判断是否为 0、符号位 |
| `jmp` | 无条件跳转 | 落点不是指令边界时，先怀疑花指令 |
| `jcc` | 条件跳转 | `je/jne` 相等、`jl/jle/jg/jge` 有符号、`ja/jae/jb/jbe` 无符号 |
| `call` / `ret` | 调用 / 返回 | `call $+5`（`e8 00 00 00 00`）把下一条地址压栈 |
| `push` / `pop` | 压栈 / 出栈 | 函数序言尾声、保存 callee-saved 寄存器 |
| `xor eax,eax` | 清零，并把 ZF 置 1 | 常见于 `return 0`，不是"没做事" |
| `cdqe` / `movsxd` | 32 位符号扩展到 64 位 | 数组下标从 `int` 扩到 64 位时出现 |
| `shl` / `sar` | 移位 | `shl rax,4` 等于乘 16，对应 stride 为 16 字节的元素 |
| `cmovcc` / `setcc` | 条件传送 / 条件置位 | `-O2` 把 `if/else` 变成无分支代码 |

函数序言与尾声（真实 `objdump -d -M intel` 节选，GCC 14.2）：

```text
; -O0：完整帧指针
55                    push   rbp
48 89 e5              mov    rbp,rsp
48 83 ec 10           sub    rsp,0x10
...
48 83 c4 10           add    rsp,0x10
5d                    pop    rbp
c3                    ret
```

```text
; -O2：省略帧指针，只保存用到的 callee-saved 寄存器
53                    push   rbx
48 83 ec 30           sub    rsp,0x30
...
48 83 c4 30           add    rsp,0x30
5b                    pop    rbx
c3                    ret
```

```text
; 另一种尾声（未省略帧指针时）
c9                    leave        ; 等价于 mov rsp,rbp; pop rbp
c3                    ret
```

`leave` 是 `c9`，等价于 `mov rsp,rbp; pop rbp`。开启帧指针省略（`-O2` 的默认行为）时，它和 `push rbp` 一起消失，**不能只靠序言认函数**。

调用约定对照：

| 项 | SysV x86-64（Linux） | Windows x64 |
|---|---|---|
| 整数参数 1–4 | `rdi`、`rsi`、`rdx`、`rcx` | `rcx`、`rdx`、`r8`、`r9` |
| 整数参数 5–6 | `r8`、`r9` | 栈传递，第 5 个参数在 `[rsp+0x28]`（有 `push rbp; mov rbp,rsp` 时是 `[rbp+0x30]`） |
| 第 7 个起 | 栈 | 栈 |
| 返回值 | `rax`（128 位返回值用 `rdx:rax`，`rdx` 存高 64 位） | `rax` |
| 调用者预留 | 无 | 0x20 字节 shadow space |
| callee-saved | `rbx`、`rbp`、`r12`–`r15` | `rbx`、`rbp`、`rdi`、`rsi`、`r12`–`r15` |
| 栈对齐 | 16 字节 | 16 字节 |

循环与分支的真实形态（`-O0` 与 `-O2` 对同一个 `for` 循环）：

```text
; -O0：先跳到条件判断，再执行循环体
140001469: eb 0d                 jmp    140001478
14000146b: 8b 45 f8              mov    eax,DWORD PTR [rbp-0x8]
14000146e: 0f af c0              imul   eax,eax
140001471: 01 45 fc              add    DWORD PTR [rbp-0x4],eax
140001474: 83 45 f8 01           add    DWORD PTR [rbp-0x8],0x1
140001478: 8b 45 f8              mov    eax,DWORD PTR [rbp-0x8]
14000147b: 3b 45 10              cmp    eax,DWORD PTR [rbp+0x10]
14000147e: 7c eb                 jl     14000146b
```

```text
; -O2：寄存器化 + 底条件循环，cmov 把 if/else 变成无分支
140001460: 85 c9                 test   ecx,ecx
140001462: 7e 34                 jle    140001498
140001464: 31 c0                 xor    eax,eax
140001466: 31 d2                 xor    edx,edx
140001480: 41 89 c0              mov    r8d,eax
140001483: 44 0f af c0           imul   r8d,eax
140001487: 83 c0 01              add    eax,0x1
14000148a: 44 01 c2              add    edx,r8d
14000148d: 39 c1                 cmp    ecx,eax
14000148f: 75 ef                 jne    140001480

; absdiff 的两分支被 cmovg 合并
1400014a0: 41 89 c8              mov    r8d,ecx
1400014a3: 89 d0                 mov    eax,edx
1400014a5: 41 29 d0              sub    r8d,edx
1400014a8: 29 c8                 sub    eax,ecx
1400014aa: 39 d1                 cmp    ecx,edx
1400014ac: 41 0f 4f c0           cmovg  eax,r8d
```

数组与结构体（`struct Point { int x; int y; long long z; }`，`-O0` 节选）：

```text
e:  48 98                 cdqe                 ; int 下标扩展到 64 位
10: 48 c1 e0 04           shl    rax,0x4       ; ×16 = sizeof(Point)
1b: 48 01 d0              add    rax,rdx       ; base + i*sizeof
1e: 8b 40 04              mov    eax,DWORD PTR [rax+0x4] ; p[i].y
37: 48 8b 52 08           mov    rdx,QWORD PTR [rdx+0x8] ; p[i].z
```

`shl` 的移位量就是元素大小的以 2 为底的对数。Windows x64 的 `long` 是 4 字节而不是 8 字节，所以**类型名不可信，移位量和 `imul` 常数才可信**。

花指令（真实汇编 + `objdump -D -b binary -m i386:x86-64 -M intel` 输出）：

```asm
jmp     target
.byte   0xeb, 0x05                    ; 被跳过时永远不执行，线性反汇编会当它是一条 jmp
.byte   0xe8, 0x00, 0x00, 0x00, 0x00  ; call $+5
target:
xor     eax, eax
call    after
after:
pop     rax
ret
```

```text
0: eb 07                 jmp    0x9
2: eb 05                 jmp    0x9
4: e8 00 00 00 00        call   0x9
9: 31 c0                 xor    eax,eax
b: e8 00 00 00 00        call   0x10
10: 58                   pop    rax
```

从偏移 5 开始反汇编，同一段字节会被解释成另一组指令 —— 这就是"指令边界由入口决定"：

```text
5: 00 00                 add    BYTE PTR [rax],al
7: 00 00                 add    BYTE PTR [rax],al
9: 31 c0                 xor    eax,eax
```

控制流平坦化（真实 `-O2` 输出整理后的节选，"写状态 → 跳回分发器"结构）：

```text
16: mov    eax,[rsp+0xc]        ; 读状态变量
1a: cmp    eax,0x4
1d: ja     16                   ; 越界就回到分发器
1f: movsxd rax,[rdx+rax*4]      ; 读跳表项
23: add    rax,rdx
26: jmp    rax                  ; 分发
...
34: mov    DWORD PTR [rsp+0xc],0x4   ; 写下一个状态
3c: jmp    16                        ; 跳回分发器
```

去混淆工具：

| 工具 | 宿主 | 用途 |
|---|---|---|
| D810 | IDA | 控制流平坦化还原、MBA 化简、死代码消除；解压到 IDA 的 `plugins/` 目录，从 `Edit → Plugins` 启动 |
| deflat | Binary Ninja | OLLVM 分发器还原，安装后从 `Plugins` 菜单运行 |
| angr / miasm | Python | 符号执行求真实块与状态转移，适合手工写脚本 |
| Capstone | Python / C | 自己写脚本处理花指令、跳表和字节 patch |

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| Hex-Rays 报 `Decompilation failure`，或伪代码里出现 `JUMPOUT` | 花指令让指令边界错位，反编译器跟丢 | 从真实入口或字符串 XREF 重建；`C` 转代码，`U` 撤销后再 `C`，垃圾字节 patch 成 `90` |
| 反汇编窗口出现 `call $+5` 后紧跟 `pop reg` | 位置无关取址：`call` 把下一条地址压栈，`pop` 取出 | 合并读作 `lea reg,[rip+0]`，再看后面的 `add reg, imm` |
| 图形视图里所有块都指向同一个块 | OLLVM 分发器 | 找状态变量与每个 case 写入的常量，按状态链重排；或 D810 / deflat |
| `-O2` 函数开头没有 `push rbp` | 帧指针被省略（frame pointer omission） | 用 `ret` 和调用点定边界，不要只认序言 |
| 把 `xor eax,eax` 当成空操作跳过 | 它清零并置 ZF，常见于 `return 0` | 看后续 `ret` 与调用者如何使用 `eax` |
| 把 `lea` 当成读内存 | `lea` 只计算地址，不访问内存 | `lea rax,[rbp-0x10]` 是取局部变量地址，不是取内容 |
| 结构体数组步长算错 | 数据模型不同：Windows x64 的 `long` 是 4 字节 | 用 `shl`/`imul` 的常数反推 stride，不按源码类型猜 |
| 从文件头线性反汇编得到的代码全是垃圾 | 代码段里混有数据或花指令字节 | 用 IDA 从入口/真实跳转目标跟；`ndisasm` 只用于裸字节块 |
| 在 PE 里用 SysV 的 `rdi/rsi` 读参数 | 两个平台调用约定不同 | 先 `file` 判平台；Win64 用 `rcx/rdx/r8/r9`，SysV 用 `rdi/rsi/rdx/rcx` |
| D810 跑完代码更乱 | 函数没被识别为函数，或插件与 IDA 版本不匹配 | 先 `P` 定义函数、`C` 转代码，再跑 D810 |

## ⑥ 例题

**题目**：控制流平坦化的逐字符校验（自建样例）
**来源**：本页配套样例。用 GCC 14.2 `-O2` + `volatile state` 构造出与 OLLVM 平坦化同形的"分发器 + 状态变量 + 真实块"结构；真实 OLLVM 还会把 `switch` 编译成跳表，读法相同。

**题干**：给一个 PE 程序，运行后提示 `flag: `，输入正确输出 `Correct!`，否则 `Wrong!`。反汇编里找不到线性循环，只有一个反复读 `[rsp+0x2c]` 的块。

**附件**：`flat-check.exe`（64 位 PE，未加壳）。样例的校验串被刻意写成 `flag{...}` 这 9 个字符；真实比赛题以原题平台为准。

**关键观察**：
- `strings -n 6` 只看到 `flag: `、`Correct!`、`Wrong!`，没有明文 flag
- `check` 函数没有线性循环：`[rsp+0x2c]` 被反复读写，三个分支都跳回 `0x14000147b`
- `.rdata` 的 `0x140004020` 处有一串 9 字节常量 `55 5f 52 54 48 1d 1d 1d 4e`

**走了哪条链**：① 认出 `while(1)/switch` 形状 → ③-1 第 3 条（OLLVM 形态）→ ③-2 第 1 条（定函数边界）→ 第 2 条（定位 `cmp`/`jcc`）→ 第 5 条（记录状态转移）→ 第 6 条（按状态链重排）→ 第 3 条（从 `.rdata` 抄出常量表）→ 第 9 条（写脚本还原并验证）。

**命令与输出**（节选；`objdump` 对超长指令的字节续行已合并）：

```text
$ objdump -d -M intel flat-check.exe | sed -n '/<check>:/,/^$/p'
0000000140001450 <check>:
  140001450: 53                    push   rbx
  140001451: 48 83 ec 30           sub    rsp,0x30
  140001455: 48 89 cb              mov    rbx,rcx
  140001458: e8 ab 14 00 00        call   140002908 <strlen>
  14000145d: 31 d2                 xor    edx,edx
  14000145f: 48 83 f8 09           cmp    rax,0x9
  140001463: 75 6b                 jne    1400014d0 <check+0x80>
  140001465: c7 44 24 2c 00 00 00 00  mov DWORD PTR [rsp+0x2c],0x0
  14000146d: ba 01 00 00 00        mov    edx,0x1
  140001472: 31 c9                 xor    ecx,ecx
  140001474: 4c 8d 0d 9e 2b 00 00  lea    r9,[rip+0x2b9e]   # 140004020 <tbl>
  14000147b: 8b 44 24 2c           mov    eax,DWORD PTR [rsp+0x2c]   ; 分发器：读状态
  14000147f: 83 f8 01              cmp    eax,0x1
  140001482: 74 21                 je     1400014a5 <check+0x55>      ; state=1 → 逐字符校验
  140001484: 83 f8 02              cmp    eax,0x2
  140001487: 74 47                 je     1400014d0 <check+0x80>      ; state=2 → 返回
  140001489: 85 c0                 test   eax,eax
  14000148b: 75 ee                 jne    14000147b <check+0x2b>
  14000148d: 31 c0                 xor    eax,eax
  14000148f: 83 f9 08              cmp    ecx,0x8
  140001492: 0f 9f c0              setg   al
  140001495: 83 c0 01              add    eax,0x1                      ; state = (i>8) + 1
  140001498: 89 44 24 2c           mov    DWORD PTR [rsp+0x2c],eax
  14000149c: 8b 44 24 2c           mov    eax,DWORD PTR [rsp+0x2c]
  1400014a0: 83 f8 01              cmp    eax,0x1
  1400014a3: 75 df                 jne    140001484 <check+0x34>
  1400014a5: 4c 63 c1              movsxd r8,ecx
  1400014a8: c7 44 24 2c 00 00 00 00  mov DWORD PTR [rsp+0x2c],0x0
  1400014b0: 42 0f b6 04 03        movzx  eax,BYTE PTR [rbx+r8*1]   ; input[i]
  1400014b5: 83 f0 33              xor    eax,0x33
  1400014b8: 43 3a 04 01           cmp    al,BYTE PTR [r9+r8*1]        ; 对比 tbl[i]
  1400014bc: 0f 94 c0              sete   al
  1400014bf: 83 c1 01              add    ecx,0x1
  1400014c2: 0f b6 c0              movzx  eax,al
  1400014c5: 21 c2                 and    edx,eax
  1400014c7: eb b2                 jmp    14000147b <check+0x2b>       ; 跳回分发器
  1400014d0: 89 d0                 mov    eax,edx
  1400014d2: 48 83 c4 30           add    rsp,0x30
  1400014d6: 5b                    pop    rbx
  1400014d7: c3                    ret
```

按状态链重排后只有三段：`state=0` 判断 `i > 8` 决定继续或退出；`state=1` 做 `(input[i] ^ 0x33) == tbl[i]`；`state=2` 返回累积结果 `edx`。等价伪代码：

```c
ok = 1;
for (i = 0; i <= 8; i++)
    ok &= ((input[i] ^ 0x33) == tbl[i]);
return ok;
```

常量表来自 `.rdata`：

```text
$ objdump -s -j .rdata flat-check.exe
 140004020 555f5254 481d1d1d 4e000000 00000000  U_RTH...N.......
```

```text
$ python -c "tbl=[0x55,0x5f,0x52,0x54,0x48,0x1d,0x1d,0x1d,0x4e]; print(''.join(chr(b^0x33) for b in tbl))"
flag{...}
```

**结果**：校验逻辑是"每一位异或 `0x33` 后等于 `.rdata` 里的常量表"，把常量表再异或一次 `0x33` 就得到输入。本例常量表解出的就是 `flag{...}` 这 9 个字符。

**验证方法**：

```text
$ printf 'flag{...}\n' | ./flat-check.exe
flag: Correct!
```

**命中条目复述**：③-1 第 3 条 → ③-2 第 1、2、5、6、3、9 条。

::: tip 同类公开练习
- `OLLVM` 保护的 Android so / ARM 程序：先用 D810 或 deflat 去掉平坦化，再按 [算法识别](/reverse/algorithm-id)
- `Crackmes.one` 上标 `obfuscated` 的 crackme：大量 `call $+5` + 跳转错位，适合练 NOP 与手工重建
- `picoCTF` 的 `asm` 系列：只给汇编片段，练指令语义与 `xor eax,eax` 的识别
:::
