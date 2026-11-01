# 磁盘镜像与文件系统

关键词：磁盘镜像 disk image disk forensics E01 EWF dd raw img vmdk vhd qcow2 mmls fls icat tsk_recover photorec testdisk sleuthkit NTFS MFT 分区表 删除恢复 隐藏分区 LVM RAID ext4 文件系统取证

## ① 识别指纹

- 后缀 `.img` / `.dd` / `.raw` / `.001` / `.E01` / `.Ex01` / `.vhd` / `.vhdx` / `.vmdk` / `.qcow2` / `.ad1` / `.iso`
- `file` 显示 `DOS/MBR boot sector` —— 这是**整盘**或带引导扇区的分区，后面通常跟 `partition 1 : ID=0x7 ...`
- `file` 显示 `Linux rev 1.0 ext4 filesystem data` / `NTFS` / `ISO 9660 CD-ROM filesystem` —— 这是**单个文件系统**，没有分区表
- 取证容器：`EWF`（Expert Witness Compression，`.E01`）、`VMware4 disk image`（`.vmdk`）、`QEMU QCOW Image`（`.qcow2`）、`Microsoft Virtual Hard Disk`（`.vhd`）
- 文件从几 MB（软盘 / 单分区）到几十 GB；经常先套一层 zip / 7z，解压后才见镜像
- 题干出现"磁盘"、"镜像"、"挂载"、"分区"、"服务器被入侵"、"找被删除的文件"
- 附件里同时有 `memory`、`pcap`、日志目录 —— 磁盘只是故事线的一块

## ② 考什么

- **分区表**：MBR（4 个主分区 + 扩展分区链）、GPT（主备两份分区表）、分区类型 ID 与 GUID
- **偏移**：所有文件系统工具都要 `-o <Start 扇区>`，漏掉这个参数是本类题第一大死因
- **Sleuth Kit 三层**：卷（`mmls`）→ 文件系统（`fsstat`）→ inode 与文件（`fls` / `istat` / `icat`）
- **删除恢复**：inode 未复用、数据块未被覆盖时，按 inode 直接取回
- **文件系统内部结构**：NTFS 的 `$MFT`、`$UsnJrnl`、`$DATA` 与 ADS；ext4 的 superblock、inode table、journal
- **签名雕刻（carving）**：文件系统结构坏掉时，按文件头尾特征从裸数据里抠
- **容器解码**：EWF 压缩、VMDK 描述符与快照链、qcow2 backing file
- **卷管理层**：LVM2、软 RAID（mdadm）、LUKS 加密卷
- **隐藏分区与嵌套镜像**：分区表里没登记的区域、镜像里再套一个镜像
- **时间线**：`fls -m` 生成 bodyfile，`mactime` 汇总

## ③ 判断流程

1. **`file 附件` + `ls -la`**，按真实容器分流：`EWF` → 第 2 条；`VMware4` / `QEMU QCOW` / `Virtual Hard Disk` → 第 3 条；`DOS/MBR boot sector` / `GPT` / `ext4` / `NTFS` / `ISO 9660` → 第 4 条；是 zip / 7z / gz → 解压后回到第 1 条；全都不匹配 → 第 11 条。
2. **E01/EWF**：`ewfinfo 附件` 记下分段数与压缩方式，`ewfmount 附件 /mnt/ewf`，把 `/mnt/ewf/ewf1` 当作 raw 镜像 → 第 4 条；`ewfmount` 报缺分段 → `ewfexport 附件 -t 镜像.raw` 合并成一个文件 → 第 4 条。
3. **虚拟磁盘**：`qemu-img info 附件` 看 `backing file` 与 `Snapshot list`，`qemu-img convert -O raw 附件 镜像.raw`（有快照加 `-l snapshot.name=<快照名>`）→ 第 4 条；转换报格式错误 → 第 11 条。
4. **`mmls 镜像`**：输出里有 `Start` 非 0 的实际分区 → 记下目标分区 `Start`，跳第 5 条；只有 `Meta` / `Unallocated`，或直接报 `Cannot determine partition type` → 先 `fsstat -o 0 镜像`，能解析 → 说明整盘就是单个文件系统，令 `Start=0` 后跳第 5 条；解析失败 → 跳第 9 条。
5. **`fsstat -o <Start> 镜像`**：能打印文件系统类型、块大小、inode 范围 → 跳第 6 条；报 `Cannot determine file system type` 或 `not a valid` → 跳第 9 条。
6. **`fls -r -p -o <Start> 镜像`**：列表里有目标文件且**不带** `*` → `icat -o <Start> 镜像 <inode>` 取出内容，结束；目标只以 `*`（已删除）出现 → 跳第 7 条；列表整体为空 → 跳第 10 条。
7. **删除文件恢复**：`icat -r -o <Start> 镜像 <inode>`；输出非空 → 结束；报 `Cannot determine file size` 或输出为空 → `tsk_recover -o <Start> 镜像 ./out` 全量恢复；恢复出目标 → 结束；仍没有 → 跳第 8 条。
8. **签名雕刻**：交互式 `photorec 镜像` 选分区、选输出目录；或 `foremost -t all -i 镜像 -o ./out`；已知目标格式直接 `binwalk -e`。抠出目标 → 结束；一个都没抠出 → 跳第 10 条。
9. **分区 / 文件系统识别失败**：`blkid 镜像` 看有没有 `LVM2_member` / `linux_raid_member` / `crypto_LUKS`；LVM → `losetup -fP` 后 `pvscan` / `vgscan` / `lvscan` / `vgchange -ay`；软 RAID → `mdadm --assemble --scan`；LUKS → `cryptsetup luksDump`，有密码就 `cryptsetup luksOpen`。解锁出新的块设备 → 回到第 4 条对它重跑 `mmls`；三者都不是 → 跳第 10 条。
10. **隐藏分区 / 嵌套镜像**：`testdisk 镜像` 选 `Analyse`，把分区表与文件系统签名对照；同时在整盘上按 magic 搜偏移：`grep -abo 'NTFS    '`、`grep -abo 'EFI PART'`、`grep -abo 'KDMV'`（VMDK）、`grep -aboP '\x51\x46\x49\xfb'`（qcow2）、`grep -abo 'conectix'`（VHD）、`grep -abo 'EVF'`（E01）。找到内层字节偏移 → `dd if=镜像 of=内层.img bs=1 skip=<字节偏移>` → 回到第 1 条；找不到 → 跳第 11 条。
11. **兜底**：`strings -n 6 镜像 | grep -iE 'flag|ctf'`，以及 `grep -aob 'flag{' 镜像`；`binwalk 镜像` 看还有没有没拆的层。命中 → 按偏移取出，结束；没命中 → 跳第 12 条。
12. **全部走空** → 回到第 4 条，把粒度从"整盘"换成"每个分区 + 未分配区"重扫一遍；仍然没有 → 回 [题型总表](/map)，用附带的 memory / logs 重建故事线。

## ④ 工具与命令

```bash
# 先算 hash，再对所有操作使用副本；取证镜像永远只读
sha256sum 镜像
file 镜像
ls -la 镜像
```

```bash
# 取证容器 → raw
ewfinfo 镜像.E01
ewfmount 镜像.E01 /mnt/ewf
ls /mnt/ewf                  # 通常是 ewf1
ewfexport 镜像.E01 -t 镜像.raw

qemu-img info 镜像.vmdk
qemu-img convert -O raw 镜像.vmdk 镜像.raw
qemu-img convert -l snapshot.name=<快照名> -O raw 镜像.vmdk 镜像.raw
```

```bash
# Sleuth Kit：卷 → 文件系统 → 文件
mmls 镜像
fsstat -o <Start> 镜像
fls -r -p -o <Start> 镜像            # -r 递归，-p 带完整路径
fls -r -p -o <Start> 镜像 | grep -E '\* [0-9]+:'   # 只看已删除项
istat -o <Start> 镜像 <inode>        # inode 元数据：时间、块列表、ADS
icat -o <Start> 镜像 <inode>         # 按 inode 取内容
icat -r -o <Start> 镜像 <inode>      # 删除文件的恢复模式
tsk_recover -o <Start> 镜像 ./out    # 批量恢复；-e 连未分配区一起
```

```bash
# 时间线
fls -m / -r -p -o <Start> 镜像 > body.txt
mactime -b body.txt -d -z UTC > timeline.csv
```

```bash
# 挂载（只读、带偏移；START 换成 mmls 输出的 Start，单位是扇区）
START=<Start>
mount -o ro,loop,offset=$((START*512)) 镜像 /mnt/disk
ntfs-3g -o ro,loop,offset=$((START*512)) 镜像 /mnt/disk
```

```bash
# 雕刻
testdisk 镜像
photorec 镜像
foremost -t all -i 镜像 -o ./out
binwalk -e 镜像
```

```bash
# LVM / RAID / LUKS
losetup -fP --show 镜像
pvscan; vgscan; lvscan; vgchange -ay
mdadm --assemble --scan
cryptsetup luksDump 镜像
cryptsetup luksOpen 镜像 明文卷
```

```bash
# NTFS 专用（Windows 侧）
MFTECmd.exe -f '$MFT' --csv out --csvf mft.csv
MFTECmd.exe -f '$J'   --csv out --csvf usn.csv
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `mmls` 只显示 `Unallocated` | 分区表被清、或是 LVM / RAID / LUKS 成员盘 | `blkid` 看类型；`pvscan` / `mdadm` / `cryptsetup` 解锁后重跑 `mmls` |
| `fsstat` 报 `Cannot determine file system type` | 偏移没加，或加的是字节数不是扇区数 | `-o` 用 `mmls` 的 `Start`（扇区），必要时加 `-b 512` |
| `fls` 能列出删除文件，`icat` 却是空的 | 数据块已被覆盖，只剩 MFT 残留 | `icat -r`、`tsk_recover`，最后用 `photorec` 按签名抠 |
| 挂载后中文文件名全是乱码 | 挂载没指定字符集 | `mount -o iocharset=utf8`；或干脆不挂载，用 TSK 读 |
| 时间整体差 8 小时 | 镜像按本地时区记录，工具按 UTC 解释 | 全链统一 `TZ=UTC`，`mactime -z UTC`，回答"几点"前先标明时区 |
| `qemu-img convert` 后容量不对 | VMDK 是拆分文件或有快照链 | 保留描述符和所有 `-sNNN.vmdk`，用 `-l` 指定快照 |
| `mount` 一个 qcow2 直接失败 | 它不是 raw 镜像 | 先 `qemu-img convert -O raw`，再 `mount -o loop` |
| 对 E01 直接 `strings` 搜不到 | EWF 是压缩 + 分段的 | `ewfmount` / `ewfexport` 转 raw 后再搜 |
| 挂载后不小心改了镜像 | 没加 `-o ro`，或工具写回了原文件 | 先复制并记 hash；所有挂载一律 `-o ro` |
| `fls` 看不到文件但 `fsstat` 正常 | 目标在 NTFS 备用数据流（ADS）里 | `fls -r` 看 `:stream` 后缀；用 `icat` 指定流名 |
| 镜像里好像还有一层 | 嵌套镜像 / 压缩包内嵌 | `binwalk`、`grep -abo` 找 magic，切出来重新走第 1 条 |
| flag 文件内容只是一个路径 | 拿到的是 `.lnk` 或符号链接 | 读链接目标，再去目标路径取文件 |

## ⑥ 例题

**题目**：磁盘镜像中恢复被删除的 flag 文件
**来源**：CTF 取证方向的经典题结构，BUUCTF 取证题与各校赛 "disk / forensic" 系列反复出现

**题干**：给一个 `disk.img`，描述只有一句："攻击者下载了一个文件，然后把它删掉了。"

**附件**：一个带 MBR 分区表的整盘镜像，分区内是 NTFS。

**关键观察**：
- `file disk.img` 是 `DOS/MBR boot sector`，说明拿到的是**整盘**，必须先看分区
- `mmls` 里有实际分区，`Start` 非 0，后面所有命令都要带 `-o`
- `fls -r -p` 里目标文件带 `*`，这是 TSK 标记的**已删除**条目

**走了哪条链**：第 1 条（识别为 MBR 整盘）→ 第 4 条（`mmls` 拿 `Start`）→ 第 5 条（`fsstat` 确认 NTFS）→ 第 6 条（`fls` 看到带 `*` 的目标）→ 第 7 条（`icat -r` 恢复）。

**命令与输出**：

```bash
$ file disk.img
disk.img: DOS/MBR boot sector; partition <N> : ID=0x7, ...

`ID=0x7` 是 NTFS。接着看分区表（扇区号以附件为准，只记 `Start` 列）：

```bash
$ mmls disk.img
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors
      Slot      Start        End          Length       Description
      <Slot>    <Start>      <End>        <Length>     NTFS / exFAT (0x07)
```

```bash
$ fls -r -p -o <Start> disk.img
r/r * <inode>:	flag.txt
```

`r/r *` 表示普通文件、已删除。直接用恢复模式按 inode 取内容：

```bash
$ icat -r -o <Start> disk.img <inode>
flag{...}
```

**结果**：还原出已删除的 `flag.txt`，内容形如 `flag{...}`（精确值以原题平台为准）。

**如果 `icat -r` 出来是空的**：说明 inode 指向的数据块已经被覆盖。这时按第 7 条继续：

```bash
$ tsk_recover -o <Start> disk.img ./out
$ grep -r 'flag{' ./out
```

还没有就按第 8 条用 `photorec` 按文件签名抠。**删除恢复的成功率取决于删除后有没有新数据写入** —— 这是本类题的核心变量，也是题干常常强调"刚删不久"的原因。
