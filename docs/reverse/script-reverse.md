# 脚本类逆向

关键词：脚本逆向 pyc python 字节码 bytecode PyInstaller pyinstxtractor uncompyle6 decompyle3 pycdc dis marshal magic JavaScript JS 混淆 javascript-obfuscator obfuscator.io deobfuscator deobfuscator.io webcrack de4js eval 解包 npm 反混淆 node 单文件 exe 自解压

## ① 识别指纹

- 附件是 `.pyc`；或给了 `__pycache__/xxx.cpython-312.pyc`
- `file` 报 `Byte-compiled Python module for CPython 3.12 (magic: 3531)`
- `xxd -l 4` 看到 `cb 0d 0d 0a`、`55 0d 0d 0a`、`a7 0d 0d 0a` 这类以 `0d 0a` 结尾的文件头
- 附件是单个 `.exe`，体积几 MB 到几十 MB，`strings` 出现 `PYINSTALLER_`、`PYZ`、`MEI`
- 用 `binwalk` 能看到 `MEI`、`PYZ` 结构，或用 `pyinstxtractor` 解出 `python3xx.dll`、`PYZ-00.pyz`、`base_library.zip`
- 附件是 `.js`，打开是一行超长代码，变量名是 `_0x1a2b3c`，开头是 `(function(_0x...){...})(...)`
- 看到 `while (!![])` + `parseInt(...)` + `_0x` 函数调用，或 `eval(function(p,a,c,k,e,d){...})`
- HTML 里只有一个 `<script src="app.js">`，`app.js` 几万行且没有可读字符串
- 题干写 "python"、"js"、"node"、"混淆"、"pyc"、"打包的 exe"

## ② 考什么

- `.pyc` 结构：magic(4) + flags/时间戳/源大小(12) + marshal 序列化的 code object
- magic 与 Python 版本的对应关系；版本不匹配时反编译器直接拒绝
- 反编译工具链：`uncompyle6`、`decompyle3`、`pycdc`，全失败时用 `dis` 读字节码
- `marshal.load` 与 code object 的递归：函数定义在 `co_consts` 里，要逐层 `dis`
- PyInstaller：CArchive / PKG 结构、`pyinstxtractor`、`PYZ` 归档、提取后 pyc 的头部修复
- 单文件 exe 的自解压流程（运行时解包到临时目录）
- JS 混淆器：`javascript-obfuscator` / `obfuscator.io` 的字符串数组、控制流平坦化、死代码、self-defending
- JS 反混淆：`webcrack`、`deobfuscator.io`、`de4js`，以及手动还原字符串数组
- `eval` 链式解包：一层 `eval` 套一层，逐层替换成 `console.log`
- Node 动态执行观察：hook `console.log` / `Function`，直接看运行时参数

## ③ 判断流程

### ③-1 子类型分流

1. 文件头是 pyc magic，或 `file` 报 `Byte-compiled Python module` → pyc，走 ③-2 第 1 条
2. `file` 是 PE，且 `strings -n 8 | grep -i pyinstaller` 命中 `PYINSTALLER_` → PyInstaller，走 ③-2 第 4 条
3. `.exe` 的 `strings` 命中 `PYZ-00.pyz`/`MEI`，或 `binwalk` 显示追加归档 → PyInstaller（同上），走 ③-2 第 4 条
4. 文本内容是 JS/HTML（`function`、`var _0x`、`<script>`） → JS，走 ③-2 第 7 条
5. `file` 报 `Zip archive` 且含 `.py`/`.pyc`/`.class` → 先解包，再回到第 1 条
6. 是 `.py` 源码但用 `exec`/`eval`/`marshal.loads` 动态加载 → 从动态加载点 dump 出 code object，回到第 1 条
7. 以上都不成立 → `file` + `xxd -l 64` 重新确认格式；ELF 里内嵌 Python 解释器 → 转 [常规静态分析](/reverse/static-analysis)，本页流程结束

### ③-2 成本排序链

1. `xxd -l 16 文件.pyc` 读 magic，按下方版本表确定 Python 版本 → 继续
2. 按版本选工具：≤3.8 用 `uncompyle6`；3.7–3.8 可用 `decompyle3`；3.9–3.13 试 `pycdc`，`pycdc` 不可用 → 跳到第 12 条
3. 反编译成功 → 得到源码 → 跳到第 14 条；报"不支持的版本" → 跳到第 12 条
4. PyInstaller：`pyinstxtractor-ng app.exe`（或 `python pyinstxtractor.py app.exe`）→ 得到 `app.exe_extracted/` → 继续
5. 找入口 pyc：`app.pyc`（与 exe 同名），或 `PYZ.pyz_extracted/` 下的模块 → 检查 `xxd -l 16 app.pyc`：前 4 字节是 magic → 跳到第 1 条；以 `e3` 开头（缺头） → 跳到第 6 条
6. 缺 16 字节头 → 用 `magic + b'\x00'*12 + 原字节` 重拼后再 `marshal.loads` → 跳到第 12 条
7. JS：先 `node obf.js 输入` 跑一遍记录行为，再 `head -c 500 obf.js` 看结构 → 继续
8. 结构是 `eval(function(p,a,c,k,e,d){...})`（Packer） → 用 `de4js` / `webcrack`，或把首层 `eval` 换成 `console.log` 逐层解 → 跳到第 11 条
9. 结构是 `_0x` 字符串数组 + 分发函数（`javascript-obfuscator`） → `webcrack obf.js -o out`，或 `deobfuscator.io` 网页版 → 继续
10. 输出仍是 `_0x` 变量或 switch 状态机 → 按状态常量手工还原；字符串数组写脚本全部 decode 后全局替换 → 继续
11. 反混淆后读到校验逻辑 → 得到输入/常量 → 跳到第 14 条
12. 反编译/反混淆无法直接得到可读源码 → pyc 用 `marshal` + `dis` 逐层读 code object；JS 用 Node hook `console.log`/`Function` 打印运行时参数 → 继续
13. 从 `dis` 输出或运行时输出里还原常量与算法 → 跳到第 14 条
14. 写脚本解出输入 → 回原程序验证输出正确 → 结束
15. 以上都不成立 → 回第 1 条，换粒度：`strings` / 资源段 / `binwalk -e` 直接找 flag；仍不成立 → 转 [常规静态分析](/reverse/static-analysis)

## ④ 工具与命令

pyc 的 magic 与版本（十进制 magic 与小端前两字节）：

| Python | magic | pyc 前两字节 | 完整文件头前缀 |
|---|---|---|---|
| 3.6 | 3379 | `33 0d` | `33 0d 0d 0a` |
| 3.7 | 3394 | `42 0d` | `42 0d 0d 0a` |
| 3.8 | 3413 | `55 0d` | `55 0d 0d 0a` |
| 3.9 | 3425 | `61 0d` | `61 0d 0d 0a` |
| 3.10 | 3439 | `6f 0d` | `6f 0d 0d 0a` |
| 3.11 | 3495 | `a7 0d` | `a7 0d 0d 0a` |
| 3.12 | 3531 | `cb 0d` | `cb 0d 0d 0a` |
| 3.13 | 3571 | `f3 0d` | `f3 0d 0d 0a` |

反编译器覆盖范围：

| 工具 | 覆盖版本 | 说明 |
|---|---|---|
| `uncompyle6` | 2.7–3.8（官方 README） | 3.12 的 pyc 实测报 `Unsupported Python version, 3.12.0` |
| `decompyle3` | 3.7–3.8 | uncompyle6 的后继分支，覆盖更窄 |
| `pycdc` | 较新字节码（以 README 为准） | C++ 实现，编译后命令行使用；新版本支持快于 Python 系工具 |
| `dis` | 与当前解释器同版本 | 不需要"反编译"，直接读字节码，任何版本都有 |
| `file` | 所有 | 直接报 `magic: 3531` 与 CPython 版本，最省事 |

pyc 读取：

```bash
xxd -l 16 challenge.pyc
file challenge.pyc

uncompyle6 challenge.pyc
decompyle3 challenge.pyc
pycdc challenge.pyc

# 反编译全失败时：直接读 code object
python -c "import marshal,dis; f=open('challenge.pyc','rb'); f.read(16); dis.dis(marshal.load(f))"

# 递归看嵌套函数（函数体在 co_consts 里）
python -c "import marshal,dis; f=open('challenge.pyc','rb'); f.read(16); co=marshal.load(f); [dis.dis(c) for c in co.co_consts if hasattr(c,'co_code')]"
```

缺头修复：

```python
import marshal, dis

MAGIC = b'\xcb\x0d\x0d\x0a'                 # 3.12；换版本查上表
raw = open('app.pyc', 'rb').read()

if raw[:4] == MAGIC:
    code = marshal.loads(raw[16:])          # 标准 16 字节头
else:
    code = marshal.loads(MAGIC + b'\x00'*12 + raw)  # 缺 magic 与头
dis.dis(code)
```

若 `raw[:4]` 是 magic，但 `marshal.loads` 仍报 `bad marshal data`，说明头的长度不足 16 字节。此时从 code object 的起始字节 `e3` 处截断，再按 `magic + 12 字节 0 + 截断后的字节` 重拼。

PyInstaller：

```bash
pyinstaller --onefile app.py            # 生成 dist/app.exe
pyinstxtractor-ng app.exe               # 经典版脚本：python pyinstxtractor.py app.exe
ls app.exe_extracted/                   # app.pyc、PYZ.pyz、PYZ.pyz_extracted/、*.pyd、*.dll
```

`pyinstxtractor-ng` 的真实输出节选（PyInstaller 6.22.3 / Python 3.12.7 构建的样例）：

```text
[+] Processing app.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.12
[+] Found 66 files in CArchive
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: app.pyc
[+] Found 102 files in PYZ archive
[+] Successfully extracted pyinstaller archive: app.exe
```

JS 混淆与反混淆：

```bash
npm install -g javascript-obfuscator webcrack

javascript-obfuscator input.js \
  --output obf.js \
  --control-flow-flattening true \
  --string-array true \
  --string-array-encoding base64

webcrack obf.js -o out          # 输出 out/deobfuscated.js
node obf.js 'flag{...}'         # 先确认混淆后行为不变
```

`eval` 链解包（不执行，只打印下一层源码）：

```js
const s = require('fs').readFileSync('packed.js', 'utf8');
console.log(s.replace(/^eval\(/, 'console.log('));
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `uncompyle6` 报 `Unsupported Python version, 3.12.0` | 工具只覆盖到 3.8，文件没坏 | 换 `pycdc`，或直接用 `dis` |
| 对 PyInstaller 提取的 pyc 报 `too many values to unpack (expected 7)` | uncompyle6 不支持 3.12；提取出的 pyc 头与标准 pyc 不同，报错信息因此不是版本提示 | 用 `dis`；先 `xxd -l 16` 确认头，再按需补 `magic + 12 字节 0` |
| `python challenge.pyc` 报 `bad magic number` | 运行程序的 Python 版本与 pyc 的 magic 不一致 | 按 magic 表换对应版本的解释器，不要用当前 python 硬跑 |
| `marshal.loads` 报 `bad marshal data` / `EOF` | pyc 缺 16 字节头，或提取时被截断 | 用 `magic + b'\x00'*12 + raw` 重拼；确认文件大小非 0 |
| `pyinstxtractor` 报找不到 cookie | 不是 PyInstaller，或版本太新 | 换 `pyinstxtractor-ng`；或 `binwalk -e` 看有没有 `MEI` |
| 提取目录里找不到入口脚本 | 入口 pyc 与 exe 同名，其余模块在 PYZ 里 | 看 `app.exe_extracted/app.pyc` 与 `PYZ.pyz_extracted/` |
| `decompyle3` 也失败 | 它和 uncompyle6 覆盖的版本区间差不多 | 不要连续试同族工具，直接 `dis` |
| JS 反混淆后变量名还是 `_0x` | 只还原了字符串数组，没有重命名 | 用 webcrack 的 unminify，或手工按用途改名 |
| webcrack 输出的逻辑与实际运行不一致 | 混淆器带 self-defending / 反调试，静态变换不完整 | 以 `node` 实际执行结果为准，必要时 hook `console.log` |
| `eval` 套 `eval`，解一层还是混淆代码 | 多层 Packer | 每层都把 `eval` 换成打印，直到看到明文逻辑 |
| 7z 打不开单文件 exe | PyInstaller 的 CArchive 不是标准 zip | 用 pyinstxtractor，不要用解压软件硬拆 |
| 提取出的 pyc 是 3.12，本机只有 3.8 | 打包机与做题机 Python 版本不同 | 用 `file` 读 magic 确认版本；`dis` 需要同版本解释器，没有就换 pycdc |

## ⑥ 例题

**题目**：PyInstaller 单文件 exe 逆向（自建样例）
**来源**：本页配套样例，用 PyInstaller 6.22.3 + Python 3.12.7 实际打包并提取。等价于常见"给一个打包好的 exe，还原文末校验逻辑"的题。

**题干**：给一个单文件 `app.exe`，运行后提示 `flag: `，输入正确输出 `Correct!`，否则 `Wrong!`。没有源码，只有一个几 MB 的 exe。

**附件**：`app.exe`（64 位 PE，8784847 字节，PyInstaller onefile）。样例的校验串被写成 `flag{...}` 这 9 个字符；真实比赛题以原题平台为准。

**关键观察**：
- `file` 是普通 PE，但 `strings -n 8` 命中 `PYINSTALLER_` 前缀，说明是 PyInstaller 打包
- 提取后入口是 `app.pyc`，文件头 `cb 0d 0d 0a` —— magic 3531，对应 Python 3.12
- `uncompyle6` 不支持 3.12，只能读字节码；`dis` 里直接出现 9 个整数常量

**走了哪条链**：① `strings` 命中 `PYINSTALLER_` → ③-1 第 2 条 → ③-2 第 4 条（提取）→ 第 5 条（定位 `app.pyc`，头完整）→ 第 1 条（magic 3531 = 3.12）→ 第 2 条（`pycdc` 未安装，跳到第 12 条）→ 第 12 条（`dis`）→ 第 13 条（还原常量）→ 第 14 条（验证）。

**命令与输出**：

```text
$ file dist/app.exe
dist/app.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 7 sections

$ strings -n 8 dist/app.exe | grep -m3 -iE 'pyinstaller|PYZ'
PYINSTALLER_SUPPRESS_SPLASH_SCREEN
PYINSTALLER_RESET_ENVIRONMENT
PYINSTALLER_STRICT_UNPACK_MODE

$ pyinstxtractor-ng app.exe
[+] Processing app.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.12
[+] Found 66 files in CArchive
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: app.pyc
[+] Found 102 files in PYZ archive
[+] Successfully extracted pyinstaller archive: app.exe

$ file app.exe_extracted/app.pyc
app.exe_extracted/app.pyc: Byte-compiled Python module for CPython 3.12 (magic: 3531), timestamp-based, .py timestamp: Thu Jan  1 00:00:00 1970 UTC, .py size: 0 bytes

$ xxd -l 16 app.exe_extracted/app.pyc
00000000: cb0d 0d0a 0000 0000 0000 0000 0000 0000  ................
```

顺手用 `uncompyle6` 试一次，确认版本上限：

```text
$ uncompyle6 app.exe_extracted/app.pyc
# file app.exe_extracted\app.pyc
# too many values to unpack (expected 7)
```

换 `dis` 直接读入口 code object：

```text
$ python -c "import marshal,dis; f=open('app.exe_extracted/app.pyc','rb'); f.read(16); co=marshal.load(f); [dis.dis(c) for c in co.co_consts if hasattr(c,'co_code')]"

  2           2 LOAD_GLOBAL              1 (NULL + len)
             12 LOAD_FAST                0 (s)
             14 CALL                     1
             22 LOAD_CONST               1 (9)
             24 COMPARE_OP              55 (!=)
             28 POP_JUMP_IF_FALSE        1 (to 32)

  3          30 RETURN_CONST             2 (False)

  4     >>   32 BUILD_LIST               0
             34 LOAD_CONST               3 ((102, 108, 97, 103, 123, 46, 46, 46, 125))
             36 LIST_EXTEND              1
             38 STORE_FAST               1 (t)

  5          40 LOAD_GLOBAL              3 (NULL + enumerate)
             50 LOAD_FAST                0 (s)
             52 CALL                     1
             60 GET_ITER
        >>   62 FOR_ITER                24 (to 114)
             66 UNPACK_SEQUENCE          2
             70 STORE_FAST               2 (i)
             72 STORE_FAST               3 (c)
```

`LOAD_CONST` 里的元组 `(102, 108, 97, 103, 123, 46, 46, 46, 125)` 就是目标字符码：

```text
$ python -c "print(''.join(chr(x) for x in [102,108,97,103,123,46,46,46,125]))"
flag{...}
```

**结果**：`verify` 先检查长度 9，再逐字符比较 `ord(c) == t[i]`；`t` 就是 `flag{...}` 的 9 个字符码。反编译工具不支持 3.12，但 `dis` 足以还原全部逻辑。

**验证方法**：

```text
$ printf 'flag{...}\n' | ./dist/app.exe
flag: Correct!

$ printf 'abc\n' | ./dist/app.exe
flag: Wrong!
```

**命中条目复述**：③-1 第 2 条 → ③-2 第 4、5、1、2、12、13、14 条。

::: tip JS 同构题的实测片段
用 `javascript-obfuscator` 对同一个 9 字符校验脚本开启 `--control-flow-flattening --string-array --string-array-encoding base64` 后，文件从 263 字节涨到 2609 字节，`file` 报 `JavaScript source, ASCII text, with very long lines (2609), with no line terminators`。`webcrack obf.js -o out` 跑完后，`out/deobfuscated.js` 里直接恢复出：

```js
function verify(_0x3820d9) {
  var _0x4905a1 = [102, 108, 97, 103, 123, 46, 46, 46, 125];
  if (_0x3820d9.length !== _0x4905a1.length) {
    return false;
  }
  ...
}
```

变量名仍是 `_0x`，但数组与分支条件已经可读——这就是"字符串数组 + 控制流平坦化"最典型的反混淆结果。
:::
