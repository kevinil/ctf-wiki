# 内存取证

关键词：内存取证 volatility vol3 vmem mem dump pslist cmdline filescan dumpfiles netscan hashdump malfind 内存镜像 进程 取证

## ① 识别指纹

- 附件是 `.vmem` / `.mem` / `.dmp` / `.raw` / `.lime` / `.core`，或者 `file` 显示 `Windows crash dump` / `ELF core file`
- 文件很大（几百 MB 到几 GB），但**打开看不出任何结构**
- 题干说"内存"、"进程"、"找找他做了什么"、"这个人的电脑"
- 题目名带 `memory` / `mem` / `dump` / `取证`
- 常和"日志分析"、"磁盘镜像"一起出现，构成一个多附件的故事线

## ② 考什么

- 内存镜像的 OS 与版本识别（profile / symbol）
- 进程树与命令行（谁启动了什么）
- 网络连接（有没有回连、连了哪里）
- 文件对象扫描与导出（从内存里把文件抠出来）
- 注册表、剪贴板、浏览器历史
- 密码散列提取（`hashdump` / `lsadump`）
- 恶意进程识别（`malfind`，找 RWX 内存页）
- Linux 内存取证的差异（没有注册表，看 `bash` 历史、`ps`、`/proc` 残留）

## ③ 判断流程

1. **`file 镜像`** 确认是不是内存镜像（不是的话回 [题型总表](/map)）
2. **识别系统**：
   - Volatility 3：`vol -f 镜像 windows.info` / `linux.pslist`
   - Volatility 2：`volatility -f 镜像 imageinfo`，从输出里挑 profile
   - 这一步失败 → 大概率是加密/压缩的内存，或者根本不是内存镜像
3. **`pslist` + `pstree`** —— 先看进程树，重点是：名字奇怪的、父进程不对的（比如 `cmd.exe` 的父进程是 `explorer.exe` 而不是 `services.exe`）、SVCHOST 数量异常
4. **`cmdline`** —— 把可疑进程的命令行拉出来，**flag 经常直接写在命令行参数里**
5. **`netscan`** —— 看有没有外连，尤其是出站到公网 IP 的连接
6. **`filescan` 全量导出 + `grep -i flag`** —— 内存里所有文件对象的名字，搜 flag 命中率很高
   - 命中 → `dumpfiles -Q <物理地址> -D ./out` 导出
7. **`hashdump`** —— 拿到 NTLM 散列，可能题目的答案就是散列或者密码
8. **`malfind`** —— 找被注入的进程，看有没有可执行内存页
9. **注册表 + 剪贴板**：`printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"`、`clipboard`（Vol2）
10. **以上都没找到** → `strings -n 8 镜像 | grep -iE 'flag|ctf\{'` —— 粗暴但有效；或者 `binwalk` 拆镜像
11. **还是不行** → 回第 3 条，重新审视"哪一个进程才是故事的主角"

## ④ 工具与命令

```bash
pip install volatility3
vol -f 镜像.vmem windows.info
vol -f 镜像.vmem windows.pslist
vol -f 镜像.vmem windows.pstree
vol -f 镜像.vmem windows.cmdline
vol -f 镜像.vmem windows.netscan
vol -f 镜像.vmem windows.filescan > filescan.txt
grep -i flag filescan.txt
vol -f 镜像.vmem windows.dumpfiles --physaddr 0x1f2a3b40 --dump-dir ./out
vol -f 镜像.vmem windows.hashdump
vol -f 镜像.vmem windows.malfind
```

```bash
# Volatility 2（老教程、老题目大量使用）
volatility -f 镜像.vmem imageinfo
volatility -f 镜像.vmem --profile=Win7SP1x64 pslist
volatility -f 镜像.vmem --profile=Win7SP1x64 cmdline
volatility -f 镜像.vmem --profile=Win7SP1x64 filescan | grep -i flag
volatility -f 镜像.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000001f2a3b40 -D ./out
```

```bash
# Linux 内存
vol -f 镜像.lime linux.pslist
vol -f 镜像.lime linux.bash          # bash 命令历史
vol -f 镜像.lime linux.lsof
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `imageinfo` 认不出系统 | 用了 Volatility 2 但镜像是新版 Windows / Volatility 3 缺 symbol | 换 Volatility 3；Vol3 会自动下载 symbol（**需要联网**，离线要先准备好） |
| `filescan` 找不到 flag 文件 | 文件已被删除但内容还在内存里 | 用 `malfind` / `strings`；或搜 `dumpfiles` 之后的内容 |
| `dumpfiles -Q` 导出的文件打不开 | 地址填的是虚拟地址不是物理地址 | 用 filescan 输出里的 `Physical Address` 那一列 |
| Vol3 联网下载 symbol 卡住 | 国内网络访问符号服务器慢 | 手动下载 symbol 包放到本地，或改用 Vol2 + profile |
| `pslist` 里有很多 `svchost.exe` | 正常现象 | 看**父进程**和**路径**，不是看名字 |
| 时间对不上 | 镜像时区不是 UTC | 所有时间戳先确认时区，再回答"几点" |

## ⑥ 例题

**题目**：从内存镜像中定位被删除的 flag 文件
**来源**：CTF 取证方向最经典的内存题结构，`Volatility` 官方文档与各大靶场（如 `MemLabs` 系列）反复使用

**题干**：给一个 `memory.vmem`，题干只有一句"他下载了一个文件，然后删掉了。"

**关键观察**：
- 题干点明了"下载 → 删除"：**文件系统层面已经没了，但内存里还有**
- 所以不需要重建磁盘，直接用 `filescan` 扫内存中的文件对象

**走了哪条链**：第 1 条（确认镜像是内存）→ 第 2 条（识别 Windows 版本）→ 第 6 条（`filescan` 搜索 → `dumpfiles` 导出）。

**命令与输出**：

```text
$ vol -f memory.vmem windows.info
Image: memory.vmem
OS: Windows 10 19041
...

$ vol -f memory.vmem windows.filescan > filescan.txt
$ grep -i flag filescan.txt
0x1f2a3b40  \Users\bob\Downloads\flag.txt
0x1f2a3c10  \Users\bob\Downloads\flag.txt
```

同一个文件出现两次是正常的（文件对象和缓存对象各一份）。

```text
$ vol -f memory.vmem windows.dumpfiles --physaddr 0x1f2a3b40 --dump-dir ./out
$ ls out
file.0x1f2a3b40.0xffff...dat
$ cat out/*.dat
flag{...}
```

**结果**：从内存里还原出已被删除的 `flag.txt`。

**为什么删了还在**：删除文件只是把文件系统索引里的条目去掉，**文件内容在内存页缓存里往往还活着**，直到那块内存被重新分配。所以"刚删不久"的文件，内存镜像里经常能完整捞出来。

::: tip 找不到文件时
`filescan` 只扫文件对象。如果文件被剪切走、或者是在浏览器里看的，去搜：
- 浏览器缓存：`chrome` / `firefox` 进程的 `filescan` 结果
- 剪贴板：Vol2 的 `clipboard` 插件
- 直接 `strings` 整块镜像搜 `flag{`
:::
