# Windows 系统取证

关键词：Windows 取证 windows forensics 注册表 registry hive SYSTEM SOFTWARE SAM SECURITY NTUSER.DAT regripper hivexsh evtx EvtxECmd python-evtx 4624 4625 4688 7045 $MFT Prefetch PECmd Amcache ShimCache 回收站 Recycle.Bin LNK JumpList USN Journal 用户痕迹

## ① 识别指纹

- 附件是 `C:\` 目录打包，能看到 `Windows/System32/config/`、`Windows/System32/winevt/Logs/`、`Users/<name>/`
- 单个文件形态：`SAM` / `SYSTEM` / `SOFTWARE` / `SECURITY` / `NTUSER.DAT`（注册表 hive）、`*.evtx`、`$MFT`、`$UsnJrnl:$J`、`*.pf`（Prefetch）、`*.lnk`、`$Recycle.Bin`
- `file` 对 hive 显示 `MS Windows registry file`；对 evtx 显示 `MS Windows Vista Event Log`（文件头是 `ElfFile`）
- 题干出现"某员工的电脑"、"谁登录过"、"他运行了什么"、"U 盘插过什么"、"Windows 服务器被入侵"
- 常与磁盘镜像一起给：镜像里 `C:\` 分区就是这一页的输入

## ② 考什么

- **注册表 hive 与路径**：`SYSTEM`（服务、启动项、USB、计算机名、时区）、`SOFTWARE`（安装程序、Run、网络配置）、`SAM`（本地用户、RID、最后登录）、`SECURITY`（缓存凭据、LSA secrets）、每个用户的 `NTUSER.DAT`
- **用户行为键**：`UserAssist`（GUI 程序执行次数与时间）、`RecentDocs`、`TypedPaths`、`RunMRU`、`ShellBags`（访问过的文件夹）
- **事件日志**：4624 登录成功（LogonType 2 交互 / 3 网络 / 10 RDP）、4625 登录失败、4648 显式凭据、4672 特殊权限、4688 进程创建（含命令行需审核策略）、4720 建用户、7045 服务安装、1102 日志被清
- **执行痕迹**：Prefetch（运行次数、最后运行时间、加载的 DLL）、Amcache（程序路径 + SHA1）、ShimCache（AppCompatCache，文件存在痕迹）
- **文件系统**：`$MFT`（创建/修改时间、路径、删除标记）、`$UsnJrnl:$J`（创建/删除/重命名流水）、ADS
- **删除文件**：回收站 `$Recycle.Bin/<SID>/$I*`（原始路径、删除时间）与 `$R*`（真实内容）
- **外围痕迹**：LNK、JumpList、USBSTOR、`setupapi.dev.log`、MountedDevices、计划任务、WMI 持久化
- **时间戳分析**：`$STANDARD_INFORMATION` 与 `$FILE_NAME` 两套时间，用于发现 timestomping

## ③ 判断流程

1. **先清点交付形态**：`find . -maxdepth 4 \( -iname 'SAM' -o -iname 'SYSTEM' -o -iname '*.evtx' -o -iname '$MFT' -o -iname '*.pf' -o -iname 'NTUSER.DAT' \)`。整盘镜像 → 先去 [磁盘镜像](/forensics/disk) 定位分区；是目录 → 跳第 2 条；只有单个文件 → 注册表跳第 2 或第 9 条、evtx 跳第 3 条、`$MFT` 跳第 6 条、`$J` 跳第 7 条、回收站跳第 8 条。
2. **用户与登录**：`regripper -r SAM -p sam` 列本地用户、RID、最后登录；`SOFTWARE` 的 `ProfileList` 把 SID 映射到用户目录。题目只问"有哪些用户 / 谁登录过" → 结束；要继续查"他做了什么" → 跳第 3 条。
3. **事件日志**：`EvtxECmd` 全量导出 CSV，先筛 `4625`、`4624`、`4688`、`7045`、`1102`。找到可疑进程或服务 → 记下时间与路径，跳第 4 条；直接拿到答案（登录 IP、时间、用户名）→ 结束；没有 evtx 或日志为空 → 跳第 4 条。
4. **Prefetch**：`PECmd` 导出，按 `LastRun` 排序。可疑程序命中 → 记下可执行文件名与路径，跳第 5 条；没有命中 → 跳第 5 条（用 Amcache 补）。
5. **Amcache + ShimCache**：`AmcacheParser` 拿程序路径、SHA1、首次出现时间；`AppCompatCacheParser` 解析 SYSTEM 里的 ShimCache，补文件存在过的痕迹（ShimCache 不能单独证明执行）。Prefetch 与 Amcache 指向同一程序 → 跳第 6 条定位文件；两者都没有记录 → 跳第 6 条。
6. **`$MFT`**：`MFTECmd` 导出，按文件名、`ParentPath`、`InUse`、时间筛。找到落地文件（尤其是 `Temp`、`Downloads`、`Public` 下的可执行文件）→ 读内容或按 inode 导出，结束；没找到 → 跳第 7 条。
7. **`$UsnJrnl:$J`**：`MFTECmd -f '$J'` 导出，看 create / delete / rename 流水，把已删除的文件名和路径补回来 → 带着名字回到第 6 条在 `$MFT` 里定位；没有 `$J` → 跳第 8 条。
8. **回收站**：读 `$Recycle.Bin/<SID>/$I*` 拿原始路径与删除时间，读同名 `$R*` 拿内容。flag 在删除文件里 → 结束；不是 → 跳第 9 条。
9. **用户活动**：`NTUSER.DAT` 用 RegRipper 跑 `userassist`、`recentdocs`、`typedurls`、`runmru`；`LECmd` 解 `.lnk`，`JLECmd` 解 JumpList。拿到新路径或文件名 → 回第 6 条找内容；题目问"用户打开过什么" → 直接结束。
10. **USB 设备**：SYSTEM 里 `USBSTOR` 拿设备名与序列号，`MountedDevices` 拿盘符，`setupapi.dev.log` 拿首次接入时间。题目问"插过什么 U 盘 / 什么时候插的" → 结束；还要找 U 盘里的文件 → 把设备序列号带回第 6 条按路径筛。
11. **持久化**：查 Run/RunOnce、`Services`、计划任务（`SOFTWARE` 的 `TaskCache` + `System32\Tasks` 文件）、启动目录、WMI repository。找到恶意项 → 提取命令行与落地路径，回第 6 条定位文件；没有 → 跳第 12 条。
12. **日志被清空或断档**：查 `1102`（日志清除）、`104`（日志文件删除）、evtx 文件大小与 `$MFT` 里的修改时间。确定断档时间点 → 用 Prefetch / Amcache / `$MFT` 在该时间窗重建，重建出事件就回第 3 条按该时间窗复查；完全没有线索 → 跳第 13 条。
13. **兜底**：`grep -rail 'flag' .`；注册表和 evtx 里大量字符串是 UTF-16LE，必须 `strings -el`；对 hive 用 `hivexsh` 全量 `lsval`。命中 → 读值，结束；没命中 → 跳第 14 条。
14. **全部走空** → 回到第 2 条，换一个 artifact 当主角（上一轮查登录，这一轮查 USB / 持久化 / 浏览器）；仍然没有 → 回 [题型总表](/map)。

## ④ 工具与命令

```bash
# 注册表：先列插件，再按 hive 跑
regripper -l | grep -iE 'userassist|usb|run|recent'
regripper -r SAM -p sam
regripper -r SYSTEM -p services
regripper -r SYSTEM -p usb
regripper -r NTUSER.DAT -p userassist
regripper -r NTUSER.DAT -p recentdocs
# hive 被改过名时，加 -f 指定类型：-f sam / system / software / ntuser
```

```bash
# hivexsh：交互式浏览任意 hive，路径用反斜杠
hivexsh NTUSER.DAT
><fs> cd Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
><fs> lsval
><fs> cat url1
```

```python
# python-registry：脚本化查询
from Registry import Registry

reg = Registry.Registry("SYSTEM")
key = reg.open(r"ControlSet001\Services\USBSTOR")
for v in key.values():
    print(v.name(), v.value())
```

```bash
# 事件日志
EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv out --csvf evtx.csv
# CSV 里按 EventId 过滤；4688 的命令行在 Payload 的 CommandLine 字段
```

```python
# python-evtx：不想用 EvtxECmd 时直接出 XML
from Evtx.Evtx import Evtx

with Evtx("Security.evtx") as log:
    for record in log.records():
        print(record.xml())
```

```bash
# 执行痕迹
PECmd.exe -d C:\Windows\Prefetch --csv out --csvf prefetch.csv
AmcacheParser.exe -f Amcache.hve --csv out --csvf amcache.csv
AppCompatCacheParser.exe -f SYSTEM --csv out --csvf shimcache.csv

# 文件系统与删除（$MFT 在卷根；$J 需先从 \$Extend\$UsnJrnl 导出）
MFTECmd.exe -f '$MFT' --csv out --csvf mft.csv
MFTECmd.exe -f '$J'   --csv out --csvf usn.csv
RBCmd.exe -f '$Recycle.Bin' --csv out --csvf recycle.csv

# 快捷方式
LECmd.exe -d . --csv out --csvf lnk.csv
JLECmd.exe -d . --csv out --csvf jumplist.csv
```

```bash
# 命令行快速过滤（CSV 已导出后）
grep ',4688,' evtx.csv | grep -i 'powershell'
grep -i 'Temp' mft.csv | grep -i '\.exe'
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| SAM 里看不到明文密码 | SAM 只存 NT hash | 用 `secretsdump` / `hashcat` 处理 hash，或去 SECURITY 找缓存凭据 |
| 4624 一大堆，看不出谁是真登录 | 服务、系统账户、网络登录都会产生 4624 | 先按 `LogonType` 筛（2 交互 / 10 RDP / 3 网络），再看 `TargetUserName` 与源 IP |
| 4688 有事件但没有命令行 | 未开启 `ProcessCreationIncludeCmdLine_Enabled` 审核策略 | 改用 Prefetch / Amcache / ShimCache 补执行痕迹 |
| Prefetch 里只有最近几条 | Prefetch 数量有限且会被系统清理 | 用 Amcache + `$MFT` + `$UsnJrnl` 交叉补时间线 |
| Prefetch 文件打不开 | Win10/11 用 MAM 压缩 | 用 PECmd 解析，不要手工解压 |
| `$MFT` 时间明显被改过 | timestomping 只改 `$STANDARD_INFORMATION` | 对比 `$FILE_NAME` 时间与 `$UsnJrnl`，两套时间不一致就是线索 |
| 回收站只有 `$I` 没有 `$R` | 文件已被还原或彻底删除，`$I` 只是元数据 | 用 `$I` 拿原始路径和删除时间，再回 `$MFT` / carving 找内容 |
| 用户名和 `NTUSER.DAT` 对不上 | 目录名不等于账户名 | 用 `SOFTWARE\ProfileList` 的 SID → ProfileImagePath 映射 |
| Amcache 有记录但不确定执行过 | 新版 Windows 的 Amcache 可能记录"存在"而非"执行" | 必须与 Prefetch / ShimCache / 4688 交叉验证 |
| evtx 时间比本地时间早 8 小时 | evtx 内部按 UTC 存储 | 统一换算成 UTC 再回答，展示时注明时区 |
| `strings` 搜不到注册表里的 flag | hive 里的字符串是 UTF-16LE | `strings -el`，或用 `hivexsh` / python-registry 按值读 |
| 日志被清空就放弃 | 1102 本身就是证据 | 记下清除时间，用 Prefetch / `$MFT` 重建该时间窗 |

## ⑥ 例题

**题目**：Windows 主机入侵排查 —— 从进程创建到落地文件
**来源**：Windows 取证方向的经典题结构，各校赛 "forensic / windows" 与公开 DFIR 靶场反复使用

**题干**：给一台 Windows 主机的目录打包，描述："服务器被入侵了。找出攻击者执行了什么，以及他留下的文件。"

**附件**：`C:\` 目录，含 `Windows/System32/config`、`Windows/System32/winevt/Logs`、`Windows/Prefetch`、`Users/bob/`。

**关键观察**：
- 事件日志里有 4688，且 `CommandLine` 是 `powershell -enc <base64>` —— 编码命令是典型的落地执行手法
- 同一时间点 Prefetch 里 `POWERSHELL.EXE` 的 `LastRun` 对得上，确认不是日志噪声
- `$MFT` 在 `\Users\bob\AppData\Local\Temp\` 下找到同一时间创建的可执行文件

**走了哪条链**：第 1 条（清点目录）→ 第 3 条（evtx 筛 4688）→ 第 4 条（Prefetch 交叉确认）→ 第 6 条（`$MFT` 定位落地文件）→ 第 8 条（文件被删时从回收站取内容）。

**命令与输出**：

```bash
$ EvtxECmd.exe -d Logs --csv out --csvf evtx.csv
# 在 evtx.csv 里筛 EventId=4688，关键字段形如：
# TimeCreated(UTC)        EventId  Payload
# <时间>                  4688     ... NewProcessName=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
#                                  ... CommandLine=powershell -enc <base64>
```

把 `<base64>` 解码后通常是下载命令或一段反射加载脚本。接着用 Prefetch 确认执行时间：

```bash
$ PECmd.exe -d Prefetch --csv out --csvf prefetch.csv
# 在 prefetch.csv 中找 POWERSHELL.EXE 的 LastRun 与 RunCount
```

再用 `$MFT` 找落地文件（列名以 MFTECmd 版本为准）：

```bash
$ MFTECmd.exe -f '$MFT' --csv out --csvf mft.csv
# 筛 ParentPath 含 \AppData\Local\Temp\ 且 InUse=True 的行
# FileName=<落地文件名>  Created0x10=<与 4688 同一时间窗>
```

文件若已被删除，回收站里取内容：

```bash
$ RBCmd.exe -f '$Recycle.Bin' --csv out --csvf recycle.csv
# OriginalPath 指向 Temp 下的落地文件；对应的 $R 文件就是内容
```

**结果**：还原出攻击者的执行链（编码 PowerShell → 下载/落地 → 执行），落地文件内容或其中的 C2 配置形如 `flag{...}`（精确值以原题平台为准）。

**交叉验证**：如果 4688 被关闭，链路改成 第 3 条（4625/4624 找入口）→ 第 4 条（Prefetch）→ 第 5 条（Amcache 拿 SHA1）→ 第 6 条（`$MFT`）。**任何单一日志都不足以下结论，至少两个 artifact 时间对得上才算确认。**
