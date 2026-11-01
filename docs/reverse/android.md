# Android APK 逆向

关键词：Android APK 安卓 逆向 jadx apktool smali dex Dalvik frida hook native so JNI AndroidManifest assets adb 模拟器 移动安全

## ① 识别指纹

- 附件后缀 `.apk`，`file` 显示 `Android package` 或 `Zip archive`；`unzip -l` 里能看到 `AndroidManifest.xml` —— APK 本质是 zip
- 附件是单个 `.dex`，`file` 显示 `Dalvik dex file version 035`
- 题干出现"安装这个 app"、"登录成功给 flag"、"安卓"、"mobile"、"APK"
- 题目位于 reverse 或移动安全方向，附件从几十 KB 到几十 MB
- `unzip -l app.apk` 能看到 `classes.dex`、`lib/<abi>/*.so`、`assets/`、`res/`
- 装到模拟器上要求输入 key / 密码，输错提示"错误" / `failed`
- APK 里有 `libjiagu.so`、`libshella-*.so`、`StubApp` 等 —— 加固壳
- `strings app.apk | grep -i flag` 有时直接命中 `assets` 里的明文

## ② 考什么

- APK 结构：`AndroidManifest.xml`（包名、主 Activity、权限）、`classes.dex`（Java/Kotlin 字节码）、`lib/`（native so）、`assets/`（原始资源）
- `jadx` 反编译 Java 层；`apktool` 反编译出 smali 与可读的 `AndroidManifest.xml`
- `AndroidManifest.xml` 是二进制 XML，`apktool` / `aapt2` 才能正确解码
- Java 层常见校验：`String.equals`、`Objects.equals`、`TextUtils.equals`、`MessageDigest`、`Base64`、`Cipher`
- native 层校验：`System.loadLibrary` + `native` 方法；JNI 函数名 `Java_包名_类名_方法名`，或 `RegisterNatives` 动态注册
- `assets` 藏文件：明文、base64、单字节 XOR、AES 加密后放资源里
- 动态分析：`frida` hook Java / native，`adb` 安装运行，`logcat` 看输出
- 加固与多 dex：壳只留 `StubApp`，真实 dex 在内存里；`frida-dexdump` 从内存 dump
- 重打包：改 smali 后 `apktool b`，必须重新签名才能安装

## ③ 判断流程

### ③-1 子类型分流

1. `file` 输出含 `Android package`，或后缀 `.apk` 且 `unzip -l` 能看到 `AndroidManifest.xml` → 是 APK，进第 2 条；否则跳第 6 条
2. `unzip -l` 里有 `libjiagu.so` / `libshella` / `libDexHelper`，或 jadx 里只有 `StubApp` / `StubShell` 壳类 → 加固壳，跳 ③-2 第 8 条
3. `assets/` 下有 `file` 识别为 `data` 的二进制文件，且不是图片、音频、字体 → 资源隐藏，跳 ③-2 第 4 条
4. `unzip -l` 有 `lib/<abi>/*.so`，且 jadx 里业务类只声明 `native` 方法 → native 校验，跳 ③-2 第 6 条
5. `unzip -l` 有 `classes.dex`，且 jadx 能显示业务类与校验函数 → Java 层校验，跳 ③-2 第 1 条
6. 附件是单个 `.dex`（`file` 显示 `Dalvik dex file`）→ 跳过 `unzip`，直接跳 ③-2 第 2 条
7. 以上都不成立 → 回 [常规静态分析](/reverse/static-analysis)

### ③-2 成本排序链

1. `unzip -l app.apk` 列出 `classes.dex` 数量、`lib/` 的 ABI、`assets/` 的文件名与大小 → 记录布局，进第 2 条
2. `jadx-gui app.apk` 全局搜索（`Ctrl+Shift+F`）题干里的原词：`flag`、`correct`、`wrong`、`请输入` → 命中明文比较常量 → 直接抄常量，结束；无命中 → 第 3 条
3. jadx 全局搜索 `equals|compareTo|MessageDigest|getInstance|Base64|Cipher` → 找到校验函数且能直接读出变换 → 逆运算，结束；找不到或读不出 → 第 4 条
4. `unzip -o app.apk 'assets/*' -d ext`，对每个文件跑 `file` 和 `xxd | head` → 是 base64、单字节 XOR 或已知文件头 → 解码，结束；不是 → 第 5 条
5. jadx 里 Java 校验存在但静态读不出（字符串加密、动态加载、混淆）→ frida hook 该 Java 方法，打印入参与返回值 → 能绕过则 `return true`，结束；hook 失败 → 第 6 条
6. jadx 里看到 `System.loadLibrary("xxx")` 或 `public native boolean check(...)` → 抽出 `lib/<abi>/libxxx.so`，用 IDA/Ghidra 找 `JNI_OnLoad` 与 `Java_*` 导出符号 → 读到校验逻辑，结束；读不出 → 第 7 条
7. native 逻辑读不出 → frida hook 该导出函数，打印入参与返回值 → 按返回值确定正确输入，或直接把返回值改成 1，结束；hook 失败 → 第 9 条
8. jadx 只看到壳类 → 设备上启动 app，`frida-dexdump -U -f 包名` 从内存 dump dex → 用 jadx 打开 dump 出的 dex → 回第 2 条
9. 前 8 条都没有结果 → `adb install -r app.apk` 安装，`adb shell am start -n 包名/.主Activity` 启动，`adb logcat | grep 包名` 看校验成功后的输出 → 拿到 flag 则结束；没拿到 → 第 10 条
10. 以上都不成立 → 回 ③-1 第 1 条，改用 `apktool d app.apk -o out` 看 `smali/`，jadx 反编译失败时 smali 更可靠

## ④ 工具与命令

```bash
# 结构：APK 是 zip，先把布局看清楚
file app.apk
unzip -l app.apk
unzip -o app.apk 'assets/*' -d ext
unzip -o app.apk 'lib/*' -d ext

# Java 层
jadx-gui app.apk
jadx -d out app.apk                      # 命令行版，输出到 out/
apktool d app.apk -o apktool_out
aapt2 dump badging app.apk               # 包名、主 Activity、权限
aapt2 dump xmltree --file AndroidManifest.xml app.apk

# 运行时
adb install -r app.apk
adb shell pm list packages | grep 关键词
adb shell am start -n com.example.app/.MainActivity
adb logcat | grep com.example.app
adb shell pm path com.example.app
adb pull /data/app/.../base.apk          # 应用私有目录需要 root

# 重打包与签名
apktool b apktool_out -o patched.apk
apksigner sign --ks my.keystore patched.apk
adb install -r patched.apk
```

```js
// hook Java 方法：打印入参/返回值，并强制返回 true
Java.perform(function () {
    var M = Java.use('com.example.app.MainActivity');
    M.check.overload('java.lang.String').implementation = function (s) {
        console.log('[in ] ' + s);
        var r = this.check(s);          // 调用原方法
        console.log('[out] ' + r);
        return true;                    // 绕过校验
    };
});
```

```js
// hook native 导出函数：JNI 的 jstring 参数要经 JNIEnv 转成 C 字符串
Java.perform(function () {
    var f = Module.findExportByName('libnative.so',
        'Java_com_example_app_MainActivity_check');
    Interceptor.attach(f, {
        onEnter: function (args) {
            var env = Java.vm.getEnv();
            this.arg = env.getStringUtf8Chars(args[2]).readUtf8String();
        },
        onLeave: function (retval) {
            console.log('[in ] ' + this.arg + ' [out] ' + retval);
        }
    });
});
```

```bash
frida -U -f com.example.app -l hook.js
frida-ps -Uai
frida-trace -U -f com.example.app -i "Java_*"
frida-dexdump -U -f com.example.app
objection -g com.example.app explore
# android hooking watch class_method com.example.app.MainActivity.check --dump-args --dump-return
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `jadx-gui` 大量 `// Decompilation failed` | 混淆、异常控制流或壳 | 改用 `apktool d` 读 smali；是壳则先 dump dex |
| 搜 `equals` 没有结果 | 字符串被拆开/加密，或用了 `TextUtils.equals` / native | 搜 `Objects.equals`、`TextUtils.equals`，再 hook 通用比较方法 |
| 改 smali 后 `adb install` 报签名错误 | 重打包后签名与安装包不一致 | 用 `apksigner` / `uber-apk-signer` 重新签名 |
| 模拟器安装成功但 so 加载失败 | 模拟器是 x86_64，APK 只带 arm64 so | 换 arm64 模拟器或真机；只分析 Java 层时先注释加载 |
| frida 连接不上 | 设备没有 `frida-server` 或未 root | 推对应架构的 `frida-server`，用 root 启动 |
| hook 返回值改了但界面还是错 | 校验在 native，或被调用两次 | 同时 hook native；在 `onLeave` 打印真实返回值 |
| `classes.dex` 里找不到业务类 | 多 dex 或加固壳 | 看 `smali_classes2/`；加固则 dump 内存 dex |
| `assets` 文件 `file` 显示 `data` | 被 XOR、压缩或加密 | `xxd` 看头，试单字节 XOR、base64、zlib |
| `AndroidManifest.xml` 打开是乱码 | 它是二进制 XML | 用 `apktool` / `aapt2` 解码，不要直接 `cat` |
| 真机 `adb pull` 失败 | 应用私有目录无权限 | `run-as 包名`（debuggable）或 root |

## ⑥ 例题

**题目**：assets 层单字节 XOR（本页配套最小样例）
**来源**：本页自建，等价于移动安全入门题里"flag 藏在 assets"的结构

**题干**：APK 的 Java 层只做一件事：读 `assets/secret.bin`，逐字节 XOR `0x5A`，再与输入比较；输入正确显示 `Correct!`。

**附件**：从 APK 的 `assets/` 抽出的 `secret.bin`（20 字节）

**关键观察**：
- jadx 里 `MainActivity.check` 调 `getAssets().open("secret.bin")`，循环里 `b[i] ^= 0x5A`
- `unzip -l` 中 `assets/secret.bin` 只有 20 字节，`file` 识别为 `data`
- smali 里常量是 `const/16 v0, 0x5a`

对应的 Java 逻辑：

```java
InputStream is = getAssets().open("secret.bin");
byte[] b = new byte[is.available()];
is.read(b);
for (int i = 0; i < b.length; i++) b[i] ^= 0x5A;
return s.equals(new String(b));
```

**走了哪条链**：③-1 第 3 条（assets 里有 `data` 文件）→ ③-2 第 4 条（解 assets）→ 结束。

**命令与输出**：

```text
$ xxd assets/secret.bin
00000000: 3c36 3b3d 213b 343e 6d35 333e 056e 2929  <6;=!;4>m53>.n))
00000010: 692e 2927                                i.)'
```

```python
b = open('assets/secret.bin', 'rb').read()
print(bytes(x ^ 0x5A for x in b).decode())
```

输出：

```text
flag{and7oid_4ss3ts}
```

**结果**：`assets/secret.bin` 是明文 flag 逐字节 XOR `0x5A` 的结果；把文件再 XOR 一次即可还原。自建样例的输出由本地脚本实跑得到，实际比赛 flag 以平台为准。

::: tip 同类公开练习
- 攻防世界 mobile 新手区 `app1`、`easy-apk`、`easy-so`
- `picoCTF` 的 `droids` 系列（Android 动态分析入门）
:::
