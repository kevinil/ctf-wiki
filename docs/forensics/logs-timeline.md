# 日志与时间线

关键词：日志分析 时间线 timeline plaso log2timeline psort Timesketch mactime grep awk Apache Nginx access log auth.log secure syslog 爆破 时区 UTC 日志合并 evtx 取证

## ① 识别指纹

- 一堆文本日志：`access.log` / `access_log` / `error.log` / `auth.log` / `secure` / `syslog` / `messages` / `*.log.gz`
- 单个或多个 `.evtx`（Windows 事件日志）
- 题干出现"什么时候"、"谁先谁后"、"找出攻击时间"、"合并日志"、"时间线"
- 附件是一个 web 根目录、一台服务器的 `/var/log`、或从多个主机导出的日志包
- 日志量从几 MB 到几 GB；同一事件在不同来源里时间戳格式完全不同
- 常和磁盘镜像、pcap 一起给：日志负责"何时"，镜像负责"何物"

## ② 考什么

- **日志格式识别**：Apache/Nginx combined、syslog（RFC3164/5424）、journald、Windows evtx、JSON/CSV 自定义格式
- **时区统一**：UTC、带偏移的 `+0800`、epoch 秒/毫秒、Windows FILETIME、WebKit 时间
- **单源统计**：`grep` / `awk` / `sort` / `uniq` 做 IP、状态码、URI、UA 的频次
- **Web 异常**：目录扫描（大量 404）、注入/包含特征、异常 UA、上传与 webshell 访问、时间密集请求
- **认证异常**：`Failed password` 爆破、爆破后 `Accepted`、`sudo` / `su` / 新建用户
- **Windows 事件**：4624/4625/4688/7045/1102（细节见 [Windows 取证](/forensics/windows)）
- **多源合并**：plaso（`log2timeline.py` + `psort.py`）、TSK bodyfile + `mactime`、Timesketch
- **关联分析**：同一 IP / 同一用户在 web、auth、文件系统三处的行为对齐
- **日志篡改**：断档、轮转缺失、1102、文件 mtime 与内容矛盾

## ③ 判断流程

### ③-1 子类型分流

1. 有 `access.log` / `access_log` / `nginx` / `apache` 目录 → 走 **A. Web 访问日志**。
2. 有 `auth.log` / `secure` / `syslog` / `messages` / `wtmp` / `btmp` → 走 **B. 认证与系统日志**。
3. 有 `.evtx` → 走 **C. Windows 事件日志**。
4. 题干直接问"时间线 / 先后顺序 / 什么时候"，或给了 3 个以上来源 → 走 **D. 多源时间线**（D 会回头调用 A/B/C 的统计结果）。
5. 是 JSON / CSV / 自定义应用日志 → 先 `head -n 3` 定字段，再按内容跳 A / B / D。
6. 全都不匹配 → 走 D 的第 8 条兜底。

### ③-2 成本排序链

**A. Web 访问日志**

1. **看头 3 行**：`head -n 3 access.log`。是 combined 格式（`IP - - [time] "METHOD URI PROTO" status size "referer" "UA"`）→ 第 2 条；字段顺序不同 → 先记下 `时间 / IP / 请求 / 状态码` 各在第几列，再跳第 2 条。
2. **圈时间范围**：`head -1` 与 `tail -1` 取首末时间，`wc -l` 记总行数；有 `.gz` 轮转 → 用 `zcat` / `zgrep` 把所有轮转一起算，跳第 3 条。
3. **按 IP 计数**：`awk '{print $1}' | sort | uniq -c | sort -rn | head -20`。某个 IP 明显高于其余 → 记下它，跳第 4 条；分布平均 → 跳第 6 条。
4. **该 IP 的状态码与 URI**：`grep '^<IP> ' | awk '{print $9}' | sort | uniq -c`；大量 404/403 → 扫描行为，跳第 5 条；出现 200 且 URI 可疑 → 跳第 5 条。
5. **可疑 URI 解码后匹配**：`union.*select`、`\.\./`、`/etc/passwd`、`cmd=`、`base64`、`<script`、`eval`、`php://`。命中 → 记录时间、URI、状态码、UA、源 IP，跳第 7 条；没命中 → 跳第 6 条。
6. **换维度**：按 URI 计数（哪个路径被打得最多）、按 UA 计数（`sqlmap` / `nikto` / `curl` / 空 UA）、按状态码计数。出现异常 → 跳第 5 条；没有 → 跳第 8 条。
7. **确认成功**：同一 IP 在可疑请求之后有没有 200 响应、有没有访问上传目录或新出现的 `.php` / `.jsp`。确认成功 → 把时间窗交给 D 合并，并去 [Linux](/forensics/linux) / [Windows](/forensics/windows) 页找落地文件；未成功 → 跳第 8 条。
8. **兜底**：看 `error.log`、`access.log.1`、应用日志（`debug.log` / `app.log`）；仍然没有 → 回到第 1 条，按字段重新映射后再统计。

**B. 认证与系统日志**

1. **看格式与时间范围**：`head -n 5 auth.log`，确认是 syslog 格式（无年份，年份要从文件 mtime 或相邻日志推）；`auth.log` 不存在 → 换 `secure` / `messages` / journald，跳第 2 条。
2. **统计失败登录**：`grep 'Failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn`。某 IP 次数明显偏高 → 跳第 3 条；没有 → 跳第 5 条。
3. **查爆破是否成功**：`grep 'Accepted' auth.log | grep '<IP>'`。有 → 记下用户、时间、源端口，跳第 4 条；没有 → 结束（爆破未遂，答案就是失败次数/来源）。
4. **成功后做了什么**：同一时间窗内 `grep -E 'sudo|su:|useradd|usermod|passwd|session opened'`；有提权或新建用户 → 记录并结束；没有 → 跳第 5 条。
5. **看非常规入口**：`Accepted publickey`、`Invalid user`、`Connection closed by authenticating user`；出现陌生公钥登录 → 去 [Linux 取证](/forensics/linux) 查 `authorized_keys`；没有 → 跳第 6 条。
6. **兜底**：`last -f wtmp`、`lastb -f btmp`、所有 `.gz` 用 `zgrep`；仍无 → 回到第 1 条换日志源。

**C. Windows 事件日志**

1. **全量导出**：`EvtxECmd` 把目录下所有 evtx 转 CSV，跳第 2 条。
2. **先筛 4625**：按用户与源 IP 计数，找爆破；有 → 跳第 3 条；没有 → 跳第 3 条（换 4624）。
3. **筛 4624**：看 `LogonType`（2 交互 / 3 网络 / 10 RDP）与异常源 IP；找到可疑登录 → 记下时间，跳第 4 条。
4. **筛 4688**：找可疑进程与命令行；命中 → 记录进程名/路径/时间，跳第 5 条；没有 4688 → 跳第 5 条（用 Prefetch 补）。
5. **筛 7045**：看新安装的服务与 `ImagePath`；命中 → 记录服务名与二进制路径，跳第 6 条。
6. **关联文件**：把进程/服务路径交给 [Windows 取证](/forensics/windows) 第 6 条（`$MFT`）和第 8 条（回收站）定位；找到内容 → 结束；没有 → 跳 D 做全局时间线。

**D. 多源时间线**

1. **列来源 + 定基准时区**：每个来源记下格式、时区、时间精度；全部换算成 UTC（带偏移的直接减偏移，epoch 直接转，无年份的 syslog 用文件 mtime 补年份），跳第 2 条。
2. **先做单源速查**：对 web 与 auth 各跑一遍 A / B 的关键统计，拿到"第一个异常"的候选时间与主体（IP/用户），跳第 3 条。
3. **生成统一 CSV**：每条事件写成 `ISO8601_UTC,source,主体,事件`；多源用 `sort -k1,1` 合并（ISO8601 字符串可直接字典序排序），跳第 4 条。
4. **文件系统时间线**：有磁盘镜像就 `fls -m / -r -p -o <Start> 镜像 > body.txt`，再 `mactime -b body.txt -d -z UTC > fs.csv`，跳第 5 条。
5. **大而全用 plaso**：`log2timeline.py --storage-file case.plaso <证据目录>`，再 `psort.py -o l2tcsv -w timeline.csv case.plaso`；只分析特定时间窗时在 `psort` 后加过滤表达式，跳第 6 条。
6. **锁定窗口**：以第一个异常（首次失败登录 / 首次可疑 URI / 新服务安装）为中心取前后 10 分钟，把窗口内事件按时间顺序读一遍，跳第 7 条。
7. **串因果**：扫描 → 登录成功 → 落地文件 → 持久化 → 外连，每一步都要在至少两个来源里找到对应；串通 → 结束；串不通 → 跳第 8 条。
8. **兜底**：时间线出现空档时，查日志轮转（`.1` / `.gz`）、日志删除（1102）、主机重启（`last reboot`）、时钟跳变；仍无 → 回到第 1 条换时间粒度（小时 → 分钟）。

## ④ 工具与命令

```bash
# Web 日志：格式与范围
head -n 3 access.log
head -1 access.log; tail -1 access.log
wc -l access.log

# 频次统计
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20
awk '{print $9}' access.log | sort | uniq -c | sort -rn
awk '{print $7}' access.log | sort | uniq -c | sort -rn | head -20
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn | head -20

# 异常特征
grep -Ei 'union.*select|\.\./|/etc/passwd|cmd=|base64|<script|php://' access.log
awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head
zgrep -h 'GET /' access.log.*.gz
```

```bash
# 认证日志
grep 'Failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
grep -E 'Accepted|session opened|sudo|useradd|passwd' auth.log
last -f wtmp
lastb -f btmp
zgrep -hE 'Failed password|Accepted' auth.log.*.gz
journalctl -D /var/log/journal --since '2024-05-01 00:00:00'
```

```bash
# Windows evtx → CSV
EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv out --csvf evtx.csv
grep ',4625,' evtx.csv | head
grep ',4688,' evtx.csv | grep -i powershell
```

```bash
# 文件系统时间线
fls -m / -r -p -o <Start> 镜像 > body.txt
mactime -b body.txt -d -z UTC > fs.csv
```

```bash
# plaso：全量时间线（先在小样本上试，确认解析器）
log2timeline.py --storage-file case.plaso ./evidence
psort.py -o l2tcsv -w timeline.csv case.plaso
psort.py -o l2tcsv -w window.csv case.plaso \
  "date > '2024-05-01 00:00:00' AND date < '2024-05-02 00:00:00'"
```

```bash
# 合并与查看
sort -t, -k1,1 timeline.csv | less
column -s, -t timeline.csv | less
```

```text
# Timesketch：在 Web UI 上传 timeline.csv 建 sketch；
# 或用 timesketch_import_client 导入后做时间线可视化与协作标注。
```

```bash
# JSON 日志
jq -c 'select(.eventTime != null) | [.eventTime, .eventName, .sourceIPAddress]' cloudtrail.json
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 合并后事件顺序乱 | 各来源时区不同，或按本地时间字符串排序 | 先全部转 UTC、统一 ISO8601，再按第一列排序 |
| 时间整体差 8 小时 | 服务器本地时区是 +0800，工具按 UTC 解释 | 读 `[.. +0800]` 偏移或 `/etc/timezone`，显式换算 |
| `auth.log` 的时间没有年份 | syslog 默认不写年份 | 用文件 mtime、轮转文件名、相邻日志推年份 |
| 日志里时间缩写 `CST` | CST 可指中国标准时间，也可指美国中部时间 | 一律以偏移（`+0800`）或服务器配置为准，不靠缩写 |
| 只查当前日志，漏掉攻击时段 | logrotate 把旧日志转成 `.1` / `.gz` | `zgrep` / `zcat` 所有轮转，按文件名排序后一起统计 |
| `grep` 大文件卡住 | 单线程逐行扫几 GB | 先 `awk` 一次抽取需要的列，或 `LC_ALL=C grep`、`ripgrep` |
| 可疑 URI 搜不到 | 攻击者用了 URL 编码 / 双重编码 | 先 `python3 -c 'import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))'` 解码再匹配 |
| 404 很多就断定被扫描 | 爬虫、坏链、静态资源缺失也会产生 404 | 看 UA、请求路径是否成字典序、是否集中在同一时间段 |
| 日志里 IP 是内网或 CDN | 前面有反向代理 / NAT | 查 `X-Forwarded-For`、代理日志、`last -i` |
| evtx 在工具里显示的时间和题干差 8 小时 | evtx 内部是 UTC，查看器按本地时区显示 | 统一按 UTC 输出，展示时注明 |
| 时间线出现大段空白就认为"没发生" | 日志被轮转、删除或主机重启 | 查 `.gz`、1102、`last reboot`、文件 mtime，空档本身也是证据 |
| `log2timeline` 跑几个小时 | 解析器全开、证据目录太大 | 先限定证据目录，必要时用 `--parsers` 只开相关解析器 |

## ⑥ 例题

**题目**：Web 日志与认证日志的联合时间线
**来源**：CTF 日志分析方向的经典题结构，各校赛 "log / forensic / timeline" 系列反复使用

**题干**：给一台 Web 服务器的 `access.log` 与 `auth.log`，描述："网站被打了。找出攻击者什么时候进来的、做了什么。"

**附件**：`access.log`、`auth.log` 及对应的 `.1` / `.gz` 轮转文件。

**关键观察**：
- `access.log` 是 combined 格式，时间字段带时区偏移（例如 `+0800`）
- 某个 IP 在短时间内出现大量 404，随后出现一条对 `upload.php` 的 200 POST
- 同一 IP 在 `auth.log` 里紧接着出现 `Accepted password`
- 登录后 `auth.log` 有 `sudo` 记录，时间与 web 的 POST 在时间线上相邻

**走了哪条链**：③-1 第 4 条（多源，进 D）→ D 第 1 条（统一时区）→ A 第 3 条（按 IP 计数）→ A 第 5 条（可疑 URI 命中）→ A 第 7 条（确认 200 成功）→ B 第 3 条（同 IP 登录成功）→ D 第 6 条（窗口内串因果）。

**命令与输出**：

```bash
$ head -n 1 access.log
<IP> - - [<时间> +0800] "GET /<路径> HTTP/1.1" <状态码> <大小> "<referer>" "<UA>"
```

先按 IP 统计（输出按次数降序，第一行就是主要来源，具体次数以附件为准）：

```bash
$ awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
#  <次数> <IP>
```

```bash
$ grep -Ei 'union.*select|\.\./|/etc/passwd|cmd=|base64' access.log
# <时间> ... "GET /<路径>?<参数> HTTP/1.1" 404 ...
# <时间> ... "POST /upload.php HTTP/1.1" 200 ...
```

确认同一 IP 的登录：

```bash
$ grep 'Accepted' auth.log | grep '<IP>'
# <时间> ... Accepted password for <用户> from <IP> port <端口> ssh2
```

登录后的提权：

```bash
$ grep -E 'sudo|session opened' auth.log | grep '<用户>'
# <时间> ... session opened for user <用户>
# <时间> ... <用户> : TTY=pts/0 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash
```

**结果**：把 `access.log` 的 `+0800` 时间换算成 UTC，再与 `auth.log` 对齐，得到完整链路：扫描 → 上传 webshell（200）→ 同 IP SSH 登录 → sudo 提权。落地 webshell 的路径与内容去服务器目录里取，flag 形如 `flag{...}`（精确值以原题平台为准）。

**为什么必须合并**：单看 `access.log` 只能证明"有人上传成功"；单看 `auth.log` 只能证明"有人登录"。**两个来源的时间对得上，才能证明是同一个人、同一场攻击** —— 这就是时间线题的核心判据。
