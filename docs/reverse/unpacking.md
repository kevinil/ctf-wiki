# 加壳与脱壳

关键词：加壳 脱壳 unpacking packer UPX ASPack Themida VMProtect ESP 定律 OEP IAT Scylla dump 壳 逆向 压缩壳

## ① 识别指纹

- `file` 对加壳程序常常仍显示 `PE32+ executable` / `ELF ... executable`，不能只靠 `file` 判壳
- `strings -n 4 程序 | grep -i upx` 命中 `UPX!`、`UPX0`、`UPX1`、`$Info: This file is packed with the UPX`
- `objdump -h` 的节区名是 `UPX0` / `UPX1` / `UPX2`，或节区极少、`.text` 很小
- `DIE`（Detect It Easy）显示 `Packer: UPX` / `ASPack` / `Themida` / `VMProtect`
- 导入表很小：只有 `LoadLibraryA`、`GetProcAddress`、`VirtualProtect` 等壳常用 API
- 入口点落在最后一个节区，或入口处是一段与程序功能无关的 stub
- 文件体积明显小于同类程序；节区熵接近 8（压缩/加密）
- 运行后在内存里才出现真实代码；x64dbg 的入口不是 `main`
- OLLVM 二进制没有 `UPX!`、没有壳 stub，只有控制流平坦化 —— 它不是壳

## ② 考什么

- 判壳：DIE、节区名、magic、导入表、熵、入口点位置
- UPX：`upx -d` 直接脱；改版 UPX 需要手工
- ESP 定律：入口 `pushad` 后对栈下硬件断点，跑到 `popad` 附近就是 OEP
- OEP 识别：`popad` 后的 `jmp` / `call` 目标、代码段特征、`main` 的 `__libc_start_main` 调用
- dump：Scylla / OllyDump / x64dbg 插件 / PE-sieve 从内存抓映像
- IAT 修复：Scylla `IAT Autosearch` → `Get Imports` → `Fix Dump`
- 强壳（Themida / VMProtect）：不追求完整脱壳，内存 dump + 动态分析
- 反调试 / 反 dump：壳常带检测，先过 anti-debug
- 压缩壳 vs 加密壳 vs 混淆：UPX / ASPack 是压缩壳；Themida / VMProtect 是加密 + VM；OLLVM 是混淆

## ③ 判断流程

### ③-1 子类型分流

1. `DIE` 显示 `Packer: UPX`，或 `objdump -h` 有 `UPX0` / `UPX1`，或 `strings` 有 `UPX!` → UPX 壳，跳 ③-2 第 1 条
2. `DIE` 显示 `ASPack` / `FSG` / `PECompact` 等老式压缩壳 → 先试专用 unpacker，失败走 ESP，跳 ③-2 第 3 条
3. `DIE` 显示 `Themida` / `VMProtect` / `Enigma` / `Obsidium` → 强壳，跳 ③-2 第 7 条
4. 没有壳名，但入口在最后一个节区、导入表只有十几个 API、节区熵 > 7.5 → 未知壳 / 自写壳，跳 ③-2 第 3 条
5. `DIE` 显示 `OLLVM` 或只有控制流平坦化，没有壳 stub → 不是壳，转 [汇编阅读与手工还原](/reverse/asm-reading)
6. 输入是 `.zip` / `.gz` / `.tar` 等普通压缩包 → 不是壳，回 [Misc · 压缩包](/misc/archive)
7. 以上都不成立 → 回 [常规静态分析](/reverse/static-analysis)

### ③-2 成本排序链

1. `upx -d 程序 -o 脱壳后` → 输出 `Unpacked 1 file.` → `file` 确认节区恢复、运行验证，结束；报 `CantUnpackException` / `not packed` → 第 2 条
2. 检查 UPX 头是否被改：`grep -abo "UPX!" 程序` → 有 `UPX!` 但 `upx -d` 失败 → 手工脱壳，第 3 条；完全无 UPX 特征 → 回 ③-1 第 4 条
3. 用 x64dbg / IDA 载入，在入口处找 `pushad`（x86）或连续 `push`（x64）→ 在 `pushad` 执行后对 `[esp]` / `[rsp]` 下硬件访问断点 → 运行，第 4 条
4. 断点命中在 `popad` / `pop` 序列附近 → 单步到其后的 `jmp` / `call`，目标地址就是 OEP → 第 5 条；断点没命中 → 回第 3 条换 `rsp` / 栈范围断点
5. 在 OEP 处 dump：Scylla `Dump` 保存映像 → `IAT Autosearch` → `Get Imports` → 删除无效项 → `Fix Dump` → 运行验证，结束；dump 后崩溃 → 第 6 条
6. dump 崩溃排查：确认 OEP 正确、节区对齐与大小、IAT 是否完整 → 用 PE-sieve 重新抓取或 Scylla 重建 → 回第 5 条；仍崩溃 → 第 9 条
7. 强壳（Themida / VMProtect）→ 不硬脱；运行到程序解密完成后用 PE-sieve / Process Hacker dump 内存，Scylla 修 IAT；关键代码在 VM 里则转动态调试 / 侧信道，结束
8. 壳带反调试 / 反 dump（检测调试器、`rdtsc`、`0xCC` 扫描）→ 先按 [反调试与反虚拟机](/reverse/anti-debug) 过检测 → 回第 3 条
9. 以上都不成立 → 回 ③-1 第 1 条，用 DIE 重新识别（换签名库、看入口 stub）

## ④ 工具与命令

```bash
# 判壳
file target.exe
diec target.exe                      # DIE 命令行；GUI 版直接拖入
strings -n 4 target.exe | grep -iE 'upx|aspack|themida|vmprotect'
objdump -h target.exe | head -40
readelf -S target.elf | head -40

# UPX
upx -l target.exe                    # 列出是否 UPX 打包
upx -d target.exe -o unpacked.exe
upx -d target.elf -o unpacked.elf

# 节区熵：接近 8 说明压缩/加密
python -c "import math,sys; d=open(sys.argv[1],'rb').read(); p=[d.count(bytes([i]))/len(d) for i in range(256)]; print(-sum(x*math.log2(x) for x in p if x))" target.exe
```

```text
图形 / 动态工具
x64dbg + Scylla 插件      Windows 脱壳主力
OllyDbg + OllyDump        老壳 / 32 位
IDA Pro                   看 stub、找 OEP
PE-sieve                  从内存抓取解密后的映像
Process Hacker            查看内存节区
DIE (Detect It Easy)      判壳、看编译器 / 熵
Scylla                    IAT 修复
```

```bash
# Linux ELF 同样先用 upx，失败再上 gdb
gdb -q ./packed
readelf -S ./packed
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `upx -d` 报 `CantUnpackException` | UPX 头被改、版本不匹配或不是标准 UPX | 不要反复加 `-f`；走 ESP 手工脱壳 |
| `file` 没显示 packed 就以为无壳 | `file` 对多数壳没有识别能力 | 用 DIE + 节区名 + 导入表 + 熵 |
| `strings` 看不到明文就以为加密 | 压缩不保证抹掉所有明文片段，不能作为判据 | 看节区名、熵、入口 stub |
| 在入口点直接 dump | 入口是壳 stub，不是 OEP | 必须跑到 `popad` 后的 OEP |
| 脱壳后程序一运行就崩 | OEP 错、IAT 未修复、节区大小不对 | 重新确认 OEP，Scylla 修 IAT |
| 把 OLLVM 当壳 | OLLVM 是编译期混淆，没有壳 stub | 转 asm-reading，按混淆处理 |
| 强壳硬脱失败 | Themida / VMProtect 有 VM + 反 dump | 内存 dump + 动态分析，不追求完整脱壳 |
| x64 程序用 ESP 定律 | x64 没有 `pushad`，栈指针是 RSP | 对 RSP 下断点，找连续 `push` / `pop` |
| `upx -d` 后杀软报毒 | 壳 stub 被移除但程序行为仍可疑 | 隔离环境分析，不要在生产机运行 |
| 脱壳后导入表全是无效指针 | dump 时 IAT 还没解析完 | 运行到 OEP 后再 dump，或 Scylla 手动填 |

## ⑥ 例题

**题目**：UPX 单层壳 + XOR 校验（本页配套可复现样例）
**来源**：本页自建，等价于 CTF 里"UPX 壳 + 简单校验"的签到题

**题干**：给一个 PE，要求输入 flag，正确输出 `Correct!`；flag 被 XOR 编码后放在程序里，外层用 UPX 打包；要求脱壳后拿到正确输入。

**附件**：`demo.exe`（MinGW gcc 14.2 编译，`-O2 -s`，UPX 5.0.0 打包）

**关键观察**：
- `DIE` 输出 `Packer: UPX(3.91+)[modified]`
- `objdump -h` 脱壳前只有 `UPX0` / `UPX1` / `UPX2` 三个节区
- `strings -n 4` 有 `UPX!`、`UPX0`、`UPX1`，没有明文 flag
- 文件从 15872 字节压到 8704 字节（54.84%）

**走了哪条链**：③-1 第 1 条（UPX 特征）→ ③-2 第 1 条（`upx -d` 一把梭）→ 脱壳完成；随后按 [算法识别](/reverse/algorithm-id) 解 XOR。

**命令与输出**：

先复现打包，再执行脱壳：

```text
$ upx demo.exe
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     15872 ->      8704   54.84%    win64/pe     demo.exe
Packed 1 file.

$ objdump -h demo.exe | grep -E 'Idx|UPX|\.text'
Idx Name          Size      VMA               LMA               File off  Algn
  0 UPX0          0000a000  0000000140001000  0000000140001000  00000200  2**2
  1 UPX1          00001c00  000000014000b000  000000014000b000  00000200  2**2
  2 UPX2          00000400  000000014000d000  000000014000d000  00001e00  2**2
```

```text
$ upx -d demo.exe
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     15872 <-      8704   54.84%    win64/pe     demo.exe
Unpacked 1 file.

$ strings -n 4 demo.exe | grep 'flag{'
# 无输出：flag 是 XOR 编码的，strings 找不到

$ ./demo.exe
Wrong!
```

反汇编里能看到初始化与 XOR 循环（编译器把编码数组拆成 `movabs` 立即数）：

```text
1400029a5: movabs $0x4b43464854525f55,%rax
1400029b9: movabs $0x6c47035d6c40026c,%rax
1400029c8: movabs $0x4100585007436c07,%rax
1400029d7: mov    $0x334e,%eax
1400029f0: xorb   $0x33,(%rax)
1400029f3: xorb   $0x33,0x1(%rax)
1400029f7: add    $0x2,%rax
1400029fb: cmp    %rdx,%rax
1400029fe: jne    1400029f0
```

把四个立即数按小端拼起来，得到 26 字节编码数组：

```python
raw = bytes.fromhex('555f52544846434b6c02406c5d03476c076c4307505800414e33')
print(bytes(x ^ 0x33 for x in raw).rstrip(b'\x00').decode())
```

输出：

```text
flag{upx_1s_n0t_4_p4ck3r}
```

回程序验证：

```text
$ ./demo.exe 'flag{upx_1s_n0t_4_p4ck3r}'
Correct!
```

**结果**：`upx -d` 恢复原节区后，才能看到 `main` 里的 XOR 循环与编码数组；把数组按 `0x33` 解回来就是正确输入。本页样例为自建，实际比赛 flag 以平台为准。

::: tip 同类公开练习
- 攻防世界 reverse 新手区 `simple-unpack`（UPX 单层壳）
- Crackmes.one 上的 UPX-packed crackme（大量同结构）
:::
