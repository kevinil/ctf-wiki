# .NET 与 Java 反编译

关键词：.NET dotnet C# dnSpy ILSpy dotPeek Mono assembly mscoree BSJB IL Java jar class jadx cfr procyon jd-cli javap 反编译 ProGuard 混淆 字符串加密 META-INF MANIFEST 字节码 常量池 Unity Assembly-CSharp IL2CPP ConfuserEx de4dot mapping

## ① 识别指纹

- `file` 输出含 `Mono/.Net assembly` —— 这是 .NET 程序集，不是原生 PE
- PE 的导入表只有 `mscoree.dll` / `_CorExeMain`，IDA 里没有多少正常导入函数
- 文件里能搜到 `BSJB` 元数据签名，或字符串里有 `mscoree.dll`、`.NET Framework`、`System.`
- `file` 输出 `compiled Java class data, version XX.0` —— 单个 `.class`
- 后缀 `.jar`，或 `file` 报 `Java archive data (JAR)`；解包后能看到 `META-INF/MANIFEST.MF` 与 `.class`
- Java 程序里能看到 `java/lang/`、`Ljava/lang/String;`、`Code:` 属性、常量池
- 后缀 `.apk` / 含 `classes.dex` —— dex 不是本页主角，转 [Android 逆向](/reverse/android)
- Unity 游戏目录里有 `Assembly-CSharp.dll`（Mono）或 `GameAssembly.dll` + `global-metadata.dat`（IL2CPP）
- 题干写 "C#"、".NET"、"unity"、"jar"、"class"、"java"、"反编译"
- 同一道题在 IDA 里打开是一堆看不懂的数据，在 dnSpy / jadx 里却能直接看到接近源码的结构

## ② 考什么

- .NET 程序集结构：CLI header、metadata、IL 指令、`<Module>`、类型与方法表
- dnSpy：反编译、调试、资源编辑器、IL 编辑与重编译
- ILSpy / dotPeek：反编译导出工程，阅读大项目
- Java class 结构：magic `CAFEBABE`、常量池、方法表、`Code` 属性、字节码指令
- jar 解包：`META-INF/`、资源文件、`mapping.txt`
- 反编译工具：`jadx`、`cfr`、`procyon`、`jd-cli`、`javap`
- 字符串加密：.NET 的 `ldstr` 前调用解密函数；Java 的 `String decrypt(...)` / 异或常量
- 混淆：ConfuserEx、de4dot；ProGuard/R8 改类名与方法名，但字符串常量仍在
- 资源里的 flag：jar 的 `assets/`、`res/raw/`；.NET 的 `.resources`、嵌入资源
- Unity：Mono 的 `Assembly-CSharp.dll` 可直接反编译；IL2CPP 是原生代码 + 元数据，工具不同

## ③ 判断流程

### ③-1 子类型分流

1. `file` 含 `Mono/.Net assembly`，或 PE 导入表只有 `mscoree.dll`/`_CorExeMain` → .NET，走 ③-2 第 1 条
2. `file` 报 `compiled Java class data` 或后缀是 `.class` → Java class，走 ③-2 第 5 条
3. 后缀 `.jar` 或 `file` 报 `Java archive data` → `jar tf` 看内容：有 `.class` → 走 ③-2 第 5 条；有 `classes.dex` → 转 [Android 逆向](/reverse/android)，本页流程结束
4. 后缀 `.apk` 或包含 `classes.dex` → 转 [Android 逆向](/reverse/android)，本页流程结束
5. 目录里有 `Assembly-CSharp.dll` → .NET，走 ③-2 第 1 条；只有 `GameAssembly.dll` + `global-metadata.dat` → IL2CPP（原生），转 [常规静态分析](/reverse/static-analysis)，本页流程结束
6. 以上都不成立 → `strings -n 6 文件 | grep -E 'System\\.|mscorlib|java/lang|Ljava/'`：命中 .NET → 第 1 条；命中 Java → 第 2 条；都不命中 → 本页不适用，转 [常规静态分析](/reverse/static-analysis)，本页流程结束

### ③-2 成本排序链

1. .NET：用 dnSpy 打开程序集，左侧展开 `<Module>`、`Program` 等类型，从入口点或 `Main` 开始 → 继续
2. 用 dnSpy 的 `Search Assemblies` 全局搜 `flag`/`Correct`/`Wrong`/`Error` → 双击搜索结果跟到引用方法 → 继续
3. 方法体是明文比较或简单运算 → 抄常量与算法，写脚本 → 跳到第 12 条
4. 方法体里 `ldstr` 前调用了字符串解密函数，或常量是乱码 → 在解密函数处 `F9` 下断，再 `Debug → Start` 运行，触发后读返回值；或把 IL 里的 `ldstr` 换成解密结果重编译 → 回到第 3 条
5. Java：`jadx-gui check.jar` 打开（jar / class / apk 都可），搜索 `main`、`verify`、`check`，再用字符串搜索定位校验 → 继续
6. jadx 不可用或反编译报错 → 换 `cfr` / `procyon`；两者都不可用或仍失败 → `javap -c -p -classpath . 类名` 直接读字节码 → 继续
7. 类名/方法名是 `a`/`b`/`c`（ProGuard / R8）→ 按字符串引用、调用关系和 AndroidManifest 定位逻辑，忽略名字 → 继续
8. `jar xf check.jar` 解包 → 检查 `META-INF/`、`assets/`、`res/raw/`、图片和文本资源；资源里直接有 flag → 结束
9. 需要动态验证 Java → `java -cp check.jar Main` 跑；要断点则用 `jdb` 或 IDE 远程调试 → 继续
10. .NET 程序集被 ConfuserEx 等混淆 → 先 `de4dot` 去混淆，再回 dnSpy；字符串仍加密 → 回到第 4 条
11. .NET 资源 `.resources` 打不开 → 用 dnSpy 的资源编辑器导出，或用 `System.Resources.ResourceReader` 读取 → 继续
12. 还原出算法/常量后写脚本 → 回原程序验证输出正确 → 结束
13. 以上都不成立 → 回第 1 条，改用 `strings` + 资源文件粒度；仍不成立 → 转 [常规静态分析](/reverse/static-analysis)

## ④ 工具与命令

识别与 .NET：

```bash
file Assembly-CSharp.dll
# PE32+ executable for MS Windows ... Mono/.Net assembly

strings -n 6 Assembly-CSharp.dll | grep -m3 -iE 'mscoree|\.NET Framework|System\.'
grep -abo 'BSJB' Assembly-CSharp.dll | head    # 元数据签名，出现即 .NET
```

```text
图形工具
dnSpy            反编译 + 调试 + 资源编辑器，.NET 首选
ILSpy            反编译质量好，可导出 C# 工程
dotPeek          JetBrains 免费 .NET 反编译器
de4dot           ConfuserEx 等混淆的去混淆工具
Il2CppDumper     IL2CPP：从 GameAssembly.dll + global-metadata.dat 导出结构
```

Java 识别与解包：

```bash
file Check.class check.jar
# Check.class: compiled Java class data, version 68.0 (Java SE 24)
# check.jar:   Java archive data (JAR)

jar tf check.jar             # 看 META-INF、class、资源
jar xf check.jar             # 解包到当前目录
unzip -l check.jar           # 与 jar tf 等价，额外看压缩后大小
strings -n 6 Check.class | head
```

Java 反编译：

```bash
jadx-gui check.jar                  # 图形界面，jar/class/apk 都支持
jadx -d jadx-out check.jar          # 命令行导出
java -jar cfr.jar check.jar --outputdir cfr-out
java -jar procyon-decompiler.jar check.jar -o procyon-out
jd-cli check.jar -od jd-out
javap -c -p -classpath . Check       # 字节码，工具全挂时的兜底
javap -v -classpath . Check          # 常量池、方法表、class 版本
```

`javap` 读字节码的关键对照：

| 字节码 | 含义 |
|---|---|
| `aload_0` / `iload_1` | 加载局部变量 0 / 1（实例方法的 0 是 `this`） |
| `ldc` / `bipush` / `sipush` | 加载常量（字符串、整数） |
| `invokevirtual` / `invokestatic` / `invokespecial` | 调实例方法 / 静态方法 / 构造器或父类方法 |
| `if_icmpeq` / `if_icmpne` | 两个 int 比较后跳转 |
| `iastore` / `iaload` | 写 / 读 int 数组 |
| `newarray` / `anewarray` | 新建基本类型数组 / 对象数组 |
| `ireturn` / `areturn` / `return` | 返回 int / 对象 / void |
| `tableswitch` / `lookupswitch` | switch 跳表 |

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `file` 说是 PE，IDA 里只有 `_CorExeMain`，反汇编没内容 | 这是 .NET 程序集，IL 不是原生机器码 | 用 dnSpy / ILSpy / dotPeek，不要用 IDA 反汇编 |
| dnSpy 打开后类型全是乱码、方法体为空 | 被 ConfuserEx 等混淆，或 IL2CPP | 先 `de4dot`；有 `GameAssembly.dll` 就用 Il2CppDumper |
| Unity 目录里没有 `Assembly-CSharp.dll` | 打包成了 IL2CPP | 找 `GameAssembly.dll` + `global-metadata.dat`，转静态分析 |
| jadx 打开大 apk 卡死 | 资源和 dex 太多 | 用命令行 `jadx -d out --no-res app.apk`，或先脱壳 |
| jadx 反编译某些方法失败 | 混淆过的字节码或 class 版本高于工具支持 | 换 cfr / procyon 最新版；仍失败用 `javap -c` 读字节码 |
| 类名全是 `a`、`b`、`c`，找不到入口 | ProGuard / R8 混淆 | 从 AndroidManifest、字符串常量、调用图定位，不要看类名 |
| jar 的 `META-INF/` 里没有 flag | `META-INF` 只是 manifest 与签名元数据 | 查 `assets/`、`res/raw/`、图片和二进制资源 |
| Java 源码里看不到拼接后的字符串 | 编译期常量折叠进常量池 | `javap -v` 看 Constant pool，或在 jadx 里全局搜字符串 |
| .NET 的 `.resources` 双击打不开 | 它是二进制资源格式，不是文本 | 用 dnSpy 资源编辑器导出，或 `ResourceReader` 读取 |
| 改了 apk 里的 dex/资源后重打包安装失败 | APK 签名校验 | 用 `apksigner` 重新签名；纯 jar 不需要 |
| `javap` 报 `class not found` | `-classpath` 指向的目录/ jar 不对 | 用 `-classpath out` 指到 class 根目录，包名用全限定名 |

## ⑥ 例题

**题目**：Java class 逐字符校验（自建样例）
**来源**：本页配套样例，用 JDK 24 编译并打包为 jar。等价于常见"给一个 jar，反编译看校验逻辑"的题。

**题干**：给 `check.jar`，运行后提示 `flag: `，输入正确输出 `Correct!`，否则 `Wrong!`。

**附件**：`Check.class` 与 `check.jar`。样例的校验串被写成 `flag{...}` 这 9 个字符；真实比赛题以原题平台为准。

**关键观察**：
- `file Check.class` 直接给出 `compiled Java class data, version 68.0`
- `jar tf check.jar` 只有 `META-INF/`、`META-INF/MANIFEST.MF`、`Check.class`，没有额外资源
- `javap -c` 里 `verify` 方法把 9 个 `bipush` 常量写进 int 数组，再逐字符比较

**走了哪条链**：① `file`/`jar tf` 认出 Java class → ③-1 第 2 条 → ③-2 第 6 条（本机没有 jadx/cfr/procyon，直接用 `javap` 读字节码）→ 第 3 条（常量与输入直接比较，抄常量）→ 第 12 条（验证）。

**命令与输出**：

```text
$ file out/Check.class
out/Check.class: compiled Java class data, version 68.0 (Java SE 24)

$ jar tf check.jar
META-INF/
META-INF/MANIFEST.MF
Check.class

$ javap -c -p -classpath out Check
  static boolean verify(java.lang.String);
    Code:
         0: aload_0
         1: invokevirtual #7                  // Method java/lang/String.length:()I
         4: bipush        9
         6: if_icmpeq     11
         9: iconst_0
        10: ireturn
        11: bipush        9
        13: newarray       int
        15: dup
        16: iconst_0
        17: bipush        102
        19: iastore
        20: dup
        21: iconst_1
        22: bipush        108
        24: iastore
        25: dup
        26: iconst_2
        27: bipush        97
        29: iastore
        30: dup
        31: iconst_3
        32: bipush        103
        34: iastore
        35: dup
        36: iconst_4
        37: bipush        123
        39: iastore
        40: dup
        41: iconst_5
        42: bipush        46
        44: iastore
        45: dup
        46: bipush        6
        48: bipush        46
        50: iastore
        51: dup
        52: bipush        7
        54: bipush        46
        56: iastore
        57: dup
        58: bipush        8
        60: bipush        125
        62: iastore
        63: astore_1
        64: iconst_0
        65: istore_2
        66: iload_2
        67: bipush        9
        69: if_icmpge     91
        72: aload_0
        73: iload_2
        74: invokevirtual #13                 // Method java/lang/String.charAt:(I)C
        77: aload_1
        78: iload_2
        79: iaload
        80: if_icmpeq     85
        83: iconst_0
        84: ireturn
        85: iinc          2, 1
```

常量 `102, 108, 97, 103, 123, 46, 46, 46, 125` 逐个转成 ASCII：

```text
$ python -c "print(''.join(chr(x) for x in [102,108,97,103,123,46,46,46,125]))"
flag{...}
```

**结果**：`verify` 的语义是"输入长度 9，且第 i 个字符等于常量数组第 i 项"，数组就是 `flag{...}` 的字符编码。不需要运行程序也能得到输入。

**验证方法**：

```text
$ printf 'flag{...}\n' | java -cp check.jar Check
flag: Correct!

$ printf 'abc\n' | java -cp check.jar Check
flag: Wrong!
```

**命中条目复述**：③-1 第 2 条 → ③-2 第 6、3、12 条。

::: tip .NET 同构题的观察点
同样的逐字符比较如果出现在 .NET 里，`javap` 的角色由 dnSpy 承担：方法体里会是一串 `ldstr`/`ldc.i4` + `bne.un`，`Search Assemblies` 搜提示字符串即可落到校验方法。若常量看不到，在 `ldstr` 前的方法调用上下断，运行时读返回值。
:::
