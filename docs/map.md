# 题型总表 —— 全局判断流程

关键词：题型总表 全局判断 识别 看到什么 去哪一页 分类 一眼认出 索引

> 这是第 0 层判断流程。任何一道题，从这里开始。命中即停，进对应题型页。

## 0. 先做这三件事（30 秒，零成本）

1. **把题干读两遍**，第二遍只看名词：有没有你认识的工具名、协议名、产品名
2. **`file` 一遍所有附件**，记录真实类型（后缀骗人的情况极多）
3. **记下三个数字**：分值、通过率、（如果有）提示条数 —— 它们决定这题大概是什么档位

```bash
file *                          # 真实类型
ls -la                          # 大小、时间戳
strings -n 8 附件 | head -50    # 有没有现成的 flag 线索
binwalk 附件                    # 有没有嵌套
```

::: warning 后缀不等于类型
`.png` 实际上是 zip、`.jpg` 实际上是流量包、`.docx` 实际上是 PE —— 这在 CTF 里是常态，不是例外。
**永远先 `file`，再决定方向。** 一个附件"看起来不像它自己"，本身就是最大的线索。
:::

## 1. 按附件类型分流

| `file` 显示 / 后缀 | 大概率方向 | 去哪一页 |
|---|---|---|
| `pcap capture file` / `.pcap` `.pcapng` `.cap` | 流量分析 | [取证 · 流量分析](/forensics/pcap) |
| `Zip archive` / `.zip` `.rar` `.7z` `.tar` `.gz` | 压缩包 | [Misc · 压缩包](/misc/archive) |
| `PNG image` / `JPEG image` / `GIF` / `.bmp` `.webp` | 图片隐写 | [Misc · 图片隐写](/misc/image-stego) |
| `RIFF ... WAVE` / `.wav` `.mp3` `.ogg` `.flac` | 音频隐写 | [Misc · 音频视频](/misc/audio-video) |
| `.mp4` `.avi` `.mkv` | 视频帧 / 字幕 | [Misc · 音频视频](/misc/audio-video) |
| `PDF document` / `.pdf` | 文档隐写 | [Misc · 文档隐写](/misc/document-macro) |
| `.docx` `.xlsx` `.pptx` `.doc` `.xls` | Office / 宏 | [Misc · 文档隐写](/misc/document-macro) |
| `ELF ... executable`（无后缀 / `.bin` / `.elf`） | Pwn 或 Reverse | [Pwn](/pwn/stack-basic) / [Reverse](/reverse/static-analysis) |
| `PE32` / `.exe` `.dll` `.sys` | Reverse（或 Windows Pwn） | [Reverse](/reverse/static-analysis) |
| `ELF ... relocatable` / `.ko` | 内核 Pwn | [Pwn · 内核](/pwn/kernel) |
| `Dalvik` / `.apk` `.dex` `.smali` `.so`（安卓） | Android 逆向 | [Reverse · Android](/reverse/android) |
| `python ... byte-compiled` / `.pyc` | 脚本类逆向 | [Reverse · 脚本逆向](/reverse/script-reverse) |
| `Java class` / `.jar` `.class` | Java 反编译 | [Reverse · .NET/Java](/reverse/dotnet-java) |
| `Mono/.Net assembly` / `.dll`（.NET） | .NET 反编译 | [Reverse · .NET/Java](/reverse/dotnet-java) |
| `.js` + 一大坨 `_0x` 变量 | JS 混淆 | [Reverse · 脚本逆向](/reverse/script-reverse) |
| `.img` `.dd` `.raw` `.E01` `.vhd` `.qcow2` `.vmdk` | 磁盘镜像取证 | [取证 · 磁盘](/forensics/disk) |
| `.vmem` `.mem` `.dmp` `.core` `.lime` | 内存取证 | [取证 · 内存](/forensics/memory) |
| `.evtx` 一堆日志 | Windows 取证 | [取证 · Windows](/forensics/windows) |
| `auth.log` `.log` 一堆文本日志 | 日志与时间线 | [取证 · 日志](/forensics/logs-timeline) |
| `.hive` / `SYSTEM` `SAM` `NTUSER.DAT` | Windows 注册表 | [取证 · Windows](/forensics/windows) |
| `.sqlite` / `History` / `Cookies` | 浏览器取证 | [取证 · 移动浏览器](/forensics/mobile-cloud) |
| **没有附件，只有一个 `nc host port`** | 交互式 Pwn / 编程题 | [Pwn](/pwn/stack-basic) / [Misc · 编程题](/misc/programming) |
| **没有附件，只有一个 URL** | Web | [Web](/web/sql-injection) |
| **只有一段文本 / 一串密文** | Crypto 或编码链 | [Crypto · 古典](/crypto/classical) / [Misc · 编码链](/misc/encoding-mix) |

## 2. 按题干关键词分流

| 题干里出现 | 先想 | 去哪一页 |
|---|---|---|
| 登录 / admin / 用户名密码 / 后台 | 注入、弱口令、认证绕过 | [SQL 注入](/web/sql-injection)、[认证与权限](/web/auth) |
| 上传 / 头像 / 附件 | 文件上传 | [文件上传](/web/file-upload) |
| include / 文件包含 / 模板 | 文件包含 / SSTI | [文件包含](/web/file-inclusion)、[SSTI](/web/ssti) |
| 内网 / 127.0.0.1 / 帮我访问 / `url=` | SSRF | [SSRF](/web/ssrf) |
| flag 在 `/flag`、读文件、源码泄露 | 任意文件读取 / RCE | [任意文件读取](/web/path-traversal)、[RCE](/web/rce) |
| token / JWT / 签名 / 伪造 | 认证与权限 | [认证与权限](/web/auth) |
| 命令 / 执行 / `system` / 反弹 | 命令执行 | [RCE](/web/rce) |
| XML / 实体 / DOCTYPE | XXE | [XXE](/web/xxe) |
| 反序列化 / `unserialize` / `readObject` | 反序列化 | [反序列化](/web/deserialization) |
| 注册码 / license / serial / 验证 / 输入 flag | Reverse | [常规静态分析](/reverse/static-analysis) |
| 壳 / 加壳 / UPX / 保护 | 脱壳 | [加壳与脱壳](/reverse/unpacking) |
| `n = ...` `e = ...` `c = ...` | RSA | [RSA 攻击](/crypto/rsa) |
| 曲线 / ECC / 点 / 椭圆 | ECC | [椭圆曲线](/crypto/ecc) |
| 随机数 / seed / 连续输出 | PRNG 预测 | [随机数预测](/crypto/prng) |
| 异或 / xor / 密钥流 | 流密码 | [流密码与异或](/crypto/stream) |
| 密文 / 密钥 / 加密算法 | 对称加密 | [对称加密](/crypto/symmetric) |
| 格 / LLL / 小根 | 格密码 | [格密码](/crypto/lattice) |
| 解压密码 / 加密的压缩包 | 压缩包攻击 | [压缩包](/misc/archive) |
| 听 / 频谱 / 声音 / 音频 | 音频隐写 | [音频视频](/misc/audio-video) |
| 内存 / 进程 / 转储 | 内存取证 | [内存取证](/forensics/memory) |
| 时间线 / 什么时候 / 谁登录过 | 日志与时间线 | [日志与时间线](/forensics/logs-timeline) |
| 样本 / 病毒 / 恶意 / 行为 | 样本分析 | [恶意样本分析](/forensics/malware) |
| 磁盘 / 分区 / 恢复 / 删除的文件 | 磁盘取证 | [磁盘镜像](/forensics/disk) |
| 下棋 / 对弈 / 游戏 / 过关 | 游戏题 | [游戏题](/misc/game) |
| 照片在哪 / 这是哪里 / 找人 | OSINT | [OSINT](/misc/osint) |

## 3. 按题目名字分流（出题人最爱在标题里藏提示）

| 名字里的词 | 大概率是 |
|---|---|
| `baby` / `easy` / `签到` / `warmup` | 该方向最基础的题型，先别想复杂 |
| `base` / `encode` / `编码` | [编码链](/misc/encoding-mix) |
| `rsa` / `crypto` | [RSA](/crypto/rsa) 或古典 |
| `sql` / `inject` | [SQL 注入](/web/sql-injection) |
| `upload` | [文件上传](/web/file-upload) |
| `unserialize` / `phar` | [反序列化](/web/deserialization) |
| `ssti` / `template` | [SSTI](/web/ssti) |
| `xxe` | [XXE](/web/xxe) |
| `jwt` / `token` | [认证与权限](/web/auth) |
| `re` / `rev` / `crackme` | [常规静态分析](/reverse/static-analysis) |
| `vm` / `bytecode` | [虚拟机与自定义字节码](/reverse/vm-bytecode) |
| `pwn` / `stack` / `ret2` | [栈溢出基础](/pwn/stack-basic) / [ROP](/pwn/rop-ret2libc) |
| `heap` / `malloc` | [堆利用](/pwn/heap) |
| `stego` / `misc` | [图片隐写](/misc/image-stego) / [编码链](/misc/encoding-mix) |
| `pcap` / `traffic` | [流量分析](/forensics/pcap) |
| `memory` / `mem` | [内存取证](/forensics/memory) |
| 一个协议名（`redis`、`gopher`、`mysql`） | 大概率要打该协议 |

## 4. 按"这题的位置"辅助判断

| 位置 | 常见是什么 |
|---|---|
| 签到题 / 1 分题 | 编码链、古典密码、`strings` 直接出 flag |
| 某个方向的第一题 | 该方向最基础的题型：crypto→古典，pwn→ret2text，re→无壳直接看 main |
| 通过率很低但分值不高 | 大概率是"知识点冷门"而非"工程量巨大" —— 查资料比硬刚划算 |
| 通过率很高但分值很高 | 工具链能用，但需要批量/自动化 |
| 题干异常简短 | 题干省掉的每个字都要你自己 `file`/`strings` 找回来 |

## 5. 以上都不命中

1. 回到第 1 条，把**每一个附件**的 `file` 输出重新看一遍，包括那些你跳过的
2. 对每个附件跑 `binwalk 附件`，看嵌套了什么
3. 把所有附件的 `strings` 全量导出到文件里，搜索 `flag`、`ctf`、`{`
4. 看**题目名字本身**：出题人极爱在标题里藏提示（谐音、协议名、工具名）
5. 还是没有 → 进 [卡住怎么办](/meta/stuck)

## 6. 方向内部索引

- [Web 12 类](/web/sql-injection)
- [Pwn 10 类](/pwn/stack-basic)
- [Reverse 10 类](/reverse/static-analysis)
- [Crypto 10 类](/crypto/classical)
- [Misc 8 类](/misc/encoding-mix)
- [取证 8 类](/forensics/pcap)
