# 移动 / 浏览器 / 容器与云取证

关键词：移动取证 mobile forensics iOS iTunes 备份 Manifest.db Manifest.plist brute force 解密 Android ADB backup .ab 浏览器 History Cookies Login Data SQLite SQLCipher 云同步 云取证 Docker 容器 overlay2 docker export docker save 取证

## ① 识别指纹

- **iOS 备份**（iTunes / Finder 备份）：目录里有 `Manifest.db`、`Manifest.plist`、`Info.plist`、`Status.plist`，以及 `00/` 到 `ff/` 的两位十六进制子目录
- **Android**：`.ab` 文件、`apps/<包名>/`、`/data/data/<包名>/`、`sdcard/`、`Android/data/`、`adb` 导出的目录
- **浏览器**：`History`、`Cookies`、`Login Data`、`Web Data`、`Bookmarks`、`Local State`，所在目录是 `Default/`、`Profile 1/` 或 Firefox 的随机名 profile
- **容器**：`/var/lib/docker/overlay2/`、`containers/<id>/config.v2.json`、`*-json.log`、`diff/`、`merged/`、`image.tar` 里的 `manifest.json` + `layer.tar`
- **云**：CloudTrail / S3 access log / Azure Activity / GCP Audit 的 JSON，或云盘同步目录、同步数据库
- 题干出现"手机"、"微信"、"聊天记录"、"浏览器访问了什么"、"密码"、"Docker"、"容器逃逸"、"云服务器"

## ② 考什么

- **iOS 备份结构**（iTunes / Finder）：`Manifest.db` 的 `Files` 表把 `fileID` 映射到 `domain + relativePath`；实际文件按 `fileID` 前两位分目录存放
- **iOS 加密备份**：`Manifest.plist` 的 `IsEncrypted`；keybag 用 PBKDF2 派生密钥、AES 加密，弱口令可以做字典验证
- **iOS 数据**：`sms.db`、Safari `History.db`、通讯录、照片、App 数据库；Apple/Core Data 时间戳从 2001 起算
- **Android 备份**：`.ab` = 头部 + zlib 压缩的 tar；`abe` 解包；App 的 `databases/`、`shared_prefs/`、`files/`、`cache/`
- **Android 加密库**：微信 `EnMicroMsg.db`、WhatsApp 等的 SQLCipher；文件头不是 `SQLite format 3` 就是加密
- **浏览器历史**：Chrome/Edge 的 `urls`、`visits`、`downloads`；时间戳是 WebKit 时间（1601 起算、微秒）
- **浏览器凭据**：`Cookies.encrypted_value`、`Login Data.password_value`；Windows 用 DPAPI，macOS 用 Keychain，Linux 旧版用固定 key
- **Firefox**：`places.sqlite`、`logins.json` + `key4.db`
- **本地存储**：`Local Storage` / `Session Storage` / `IndexedDB` 里的 token、草稿、离线数据
- **Docker**：镜像层与容器层、overlay2 的 `diff` / `lower` / `merged`、whiteout、`docker export` vs `docker save`
- **容器配置与日志**：`config.v2.json` 的环境变量、`*-json.log` 的 stdout、Mounts 指向的宿主机路径
- **云日志**：CloudTrail 等 JSON 的 `eventTime` / `eventName` / `sourceIPAddress` / `userIdentity`
- **云同步残留**：云盘缓存、浏览器同步数据、云主机磁盘镜像

## ③ 判断流程

### ③-1 子类型分流

1. 有 `Manifest.db` + `Manifest.plist` + 两位十六进制目录 → 走 **A. iOS 备份**。
2. 有 `.ab`、`apps/<包名>/`、`/data/data/`、`sdcard/` → 走 **B. Android**。
3. 有 `History` / `Cookies` / `Login Data` / `places.sqlite` / `logins.json` / `Default/` / `Profile *` → 走 **C. 浏览器**。
4. 有 `overlay2/`、`containers/<id>/`、`merged/`、`diff/`、`image.tar`、`manifest.json` + `layer.tar` → 走 **D. 容器**。
5. 有 CloudTrail / S3 access log / Azure / GCP 审计 JSON、云盘同步目录 → 走 **E. 云**。
6. 多种混在一起 → 按目录体积最大的那一类先走，其余记下来，处理完主类型后回到第 1 条。
7. 全都不匹配 → 对每个文件 `file` 一遍，按上面的特征重新对照；仍不匹配 → 第 8 条兜底。
8. **兜底**：`grep -rail 'flag' .`、`strings -el`、`file` 全目录；命中 → 处理对应文件，结束；仍无 → 回 [题型总表](/map)，按最大目录重新分类。

### ③-2 成本排序链

**A. iOS 备份**

1. **判是否加密**：`plutil -p Manifest.plist`（Linux 用 `plistutil -p`），看 `IsEncrypted`。`true` → 第 2 条；`false` → 第 3 条。
2. **解密备份**：用题干给的密码或字典，通过 `iosbackup` / `iphone-dataprotection` 对 keybag 密码做校验/字典爆破；成功 → 第 3 条；没有密码且字典跑不出 → 结束（无密码不可解，向出题人确认是否有 hint）。
3. **看索引**：`sqlite3 Manifest.db '.schema Files'`，按 `domain` 与 `relativePath` 找目标，例如 `Library/SMS/sms.db`、`Library/Safari/History.db`、聊天 App 的域 → 第 4 条。
4. **按 fileID 取文件**：备份里的路径是 `<fileID 前 2 位>/<fileID>`，不是 `relativePath`；`cp <fileID[:2]>/<fileID> ./out`，`file ./out` 确认类型。文件不存在 → 第 8 条。
5. **查内容**：SQLite 先 `.tables` 再查消息/历史/联系人表；plist 直接 `plutil -p`；图片按魔数改名 → 第 6 条。
6. **换算时间**：Apple/Core Data 时间戳从 2001-01-01 起算，Unix = 值 + 978307200；统一转 UTC → 第 7 条。
7. **加密 App 库**：文件头不是 `SQLite format 3` → SQLCipher，需要 key（keychain 导出或已知派生）；解出 → 回到第 5 条；解不出 → 第 8 条。
8. **兜底**：`grep -rail 'flag' .`、`strings -el`、对所有 plist 跑 `plutil -p`；仍无 → 回到第 3 条换一个 `domain` 重查。

**B. Android**

1. **判形态**：`.ab` → 第 2 条；`/data/data/<包名>` 或 `apps/<包名>` → 第 3 条；只有 `sdcard/` → 第 5 条。
2. **解 `.ab`**：`file backup.ab` 看头，`java -jar abe.jar unpack backup.ab backup.tar`（有密码就把密码作为第三个参数），再 `tar xf`。成功 → 第 3 条；报加密/头错误 → 第 8 条。
3. **定位 App 数据**：`find . -path '*databases*' -o -path '*shared_prefs*'`；`file` 确认哪些是 SQLite、哪些是 XML → 第 4 条。
4. **查数据库**：SQLite 用 `.tables` 找消息/账号表；文件头不是 `SQLite format 3` → SQLCipher（微信 `EnMicroMsg.db` 的 key 与 IMEI/uin 相关，版本不同算法不同），解出 → 第 5 条；解不出 → 第 8 条。
5. **查外部存储**：`sdcard/DCIM`、`Download`、`Pictures`、`Tencent`、`Android/data/<包名>`；找到下载文件或聊天附件 → 读内容，结束；没有 → 第 6 条。
6. **查配置**：`shared_prefs/*.xml` 搜 `token` / `password` / `server` / `url`；命中 → 结束；没有 → 第 7 条。
7. **有设备时的 live 取证**：`adb shell pm list packages`、`adb shell dumpsys`、`adb backup`；拿到新线索 → 回到第 3 条；没有设备 → 第 8 条。
8. **兜底**：`grep -rail 'flag' .`、`strings`、`binwalk` 拆 APK/资源；仍无 → 回到第 1 条换形态。

**C. 浏览器**

1. **认浏览器与 profile**：Chrome/Edge 看 `Default/`、`Profile 1/`；Firefox 看随机名目录里的 `places.sqlite`；Safari 看 `History.db`。记下 profile 路径 → 第 2 条。
2. **先复制再查**：浏览器运行时会锁库，`cp History /tmp/History` 后再 `sqlite3`；打不开 → 连 `-wal` / `-shm` 一起复制。成功 → 第 3 条。
3. **历史记录**：查 `urls` 的 `url` / `title` / `visit_count` / `last_visit_time`，按时间倒序；时间按 WebKit epoch（1601 起算、微秒）换算。命中目标站点 → 记下时间，跳第 4 条；没有 → 跳第 4 条（看下载）。
4. **下载记录**：查 `downloads` 的 `target_path` / `tab_url` / `total_bytes` / `start_time`。找到落地路径 → 去文件系统读该文件，结束；没有 → 第 5 条。
5. **Cookie**：查 `cookies` 的 `host_key` / `name` / `value` / `encrypted_value`；`value` 有明文 → 结束；只有 `encrypted_value` → 第 6 条。
6. **解密凭据**：Windows 用 `Local State` 的 `os_crypt.encrypted_key` + DPAPI（必须同一用户上下文）；Linux 旧版 `v10` 用固定 key（PBKDF2 `peanuts` / `saltysalt`）；macOS 用 Keychain。解出 → 结束；没有同用户环境 → 第 7 条。
7. **保存的密码**：`Login Data` 查 `origin_url` / `username_value` / `password_value`，按第 6 条同样方式解密；拿到 → 结束；为空 → 第 8 条（先检查 profile 是否完整）。
8. **Firefox**：`places.sqlite` 的 `moz_places` / `moz_historyvisits`（Unix 微秒），`logins.json` + `key4.db` 用 `firefox_decrypt`；拿到 → 结束；没有 → 第 9 条。
9. **本地存储**：`Local Storage/leveldb`、`Session Storage`、`IndexedDB` 用 `strings` 搜 token / flag；找到 → 结束；没有 → 第 10 条。
10. **兜底**：`grep -rail 'flag'` 整个 profile、看缓存目录里的落地文件；仍无 → 回到第 1 条换 profile 或换浏览器。

**D. 容器**

1. **有 Docker daemon**：`docker ps -a --no-trunc` 找容器 ID，`docker inspect` 看 `Config.Env`、`Config.Cmd`、`Mounts`；拿到 ID 与关键配置 → 第 2 条；没有 daemon → 第 2 条直接在文件系统里找。
2. **读容器配置与日志**：`/var/lib/docker/containers/<id>/config.v2.json` 看 Env / Cmd / Image；同目录 `<id>-json.log` 是 stdout 日志；从 `GraphDriver.Data.UpperDir` / `LowerDir` 拿实际的 overlay2 层目录，看容器的 `diff` 与 `lower`。找到线索 → 第 6 条；没有 → 第 3 条。
3. **导出完整文件系统**：`docker export <id> -o fs.tar`；没有 daemon 就按 `lowerdir` 顺序叠加 `diff`，或解 `docker save` 出来的 `layer.tar`。成功 → 第 7 条。
4. **看镜像历史**：`docker save <image> -o image.tar`，解包看 `manifest.json`、各层 `layer.tar`、镜像 config 里的 `history`（`RUN` 命令是明文）。命中构建阶段的敏感命令 → 结束；没有 → 第 5 条。
5. **看日志时间线**：json-file 每行是 `{"log":"...","stream":"stdout","time":"..."}`，`jq -r '.log'` 取内容，`time` 是 UTC；按时间排序。找到 → 结束；没有 → 第 6 条。
6. **看挂载与卷**：`Mounts` 里的 `Source` 是宿主机路径，去那里找容器写入/读取的文件；命中 → 结束；没有 → 第 8 条。
7. **分清层**：`diff` 只有容器写入的改动，`lower` / `layer.tar` 是镜像原始内容，`merged` 是运行时合并视图；删除的文件在 `diff` 里是 `.wh.<文件名>` whiteout。按目标时间点选层，跳第 8 条。
8. **查环境变量与密钥**：`config.v2.json` 的 `Env`、镜像 config 的 `Env`，搜 token / password / flag；命中 → 结束；没有 → 第 9 条。
9. **兜底**：`grep -rail 'flag'` 容器的 `diff` / `merged` / 各层；仍无 → 回到第 2 条换容器或换镜像。

**E. 云**

1. **认来源与字段**：CloudTrail 是 JSON（`eventTime` / `eventName` / `sourceIPAddress` / `userIdentity` / `requestParameters`）；S3 access log 是空格分隔文本；Azure/GCP 是各自 JSON。确认字段 → 第 2 条。
2. **解析并统一时间**：`jq` 抽字段，`eventTime` 是 ISO8601 UTC；生成 `时间,事件,来源IP,身份` 四列，跳第 3 条。
3. **统计异常**：按 `sourceIPAddress` 与 `userIdentity` 计数；出现陌生 IP 或异常身份 → 跳第 4 条；没有 → 第 5 条。
4. **筛敏感调用**：`CreateAccessKey`、`CreateUser`、`AttachUserPolicy`、`RunInstances`、`GetSecretValue`、`PutBucketPolicy`、`DeleteTrail`、`StopLogging`；命中 → 记录时间与参数，跳第 5 条。
5. **回到实例侧**：用云日志里的实例 ID / 时间找对应磁盘镜像或系统日志，去 [磁盘](/forensics/disk) / [Linux](/forensics/linux) / [Windows](/forensics/windows) 页取证；找到 → 结束；没有 → 第 6 条。
6. **兜底**：云盘同步目录、浏览器同步数据、缓存里的 token；`grep -rail 'flag'`；仍无 → 回到第 1 条换日志源。

## ④ 工具与命令

```bash
# ---------- iOS ----------
plutil -p Manifest.plist
plistutil -p Manifest.plist              # Linux
sqlite3 Manifest.db ".schema Files"
sqlite3 Manifest.db "select fileID, domain, relativePath from Files where relativePath like '%History%' limit 20;"

# 备份里的真实路径 = 前两位/fileID
cp <fileID前两位>/<fileID> ./out
file ./out
sqlite3 ./out ".tables"
```

```bash
# ---------- Android ----------
file backup.ab
java -jar abe.jar unpack backup.ab backup.tar
tar tf backup.tar | head
tar xf backup.tar

find . -path '*databases*' -name '*.db'
sqlite3 msgstore.db ".tables"

adb shell pm list packages
adb shell dumpsys
```

```bash
# ---------- 浏览器 ----------
cp ~/.config/google-chrome/Default/History /tmp/History

sqlite3 /tmp/History \
  "select datetime(last_visit_time/1000000-11644473600,'unixepoch') as t, url, title
   from urls order by last_visit_time desc limit 20;"

sqlite3 /tmp/History \
  "select target_path, tab_url, total_bytes,
          datetime(start_time/1000000-11644473600,'unixepoch')
   from downloads order by start_time desc;"

sqlite3 Cookies "select host_key,name,value,length(encrypted_value) from cookies;"
sqlite3 "Login Data" "select origin_url,username_value,length(password_value) from logins;"
```

```python
# WebKit / Apple 时间戳换算（已本地验证）
from datetime import datetime, timezone

def webkit(t: int) -> datetime:          # 1601 起算，微秒
    return datetime.fromtimestamp(t / 1_000_000 - 11644473600, tz=timezone.utc)

def apple(t: int) -> datetime:           # 2001 起算，秒
    return datetime.fromtimestamp(t + 978307200, tz=timezone.utc)

print(webkit(13359038400000000))         # 2024-05-01 12:00:00+00:00
```

```bash
# ---------- 容器 ----------
docker ps -a --no-trunc
docker inspect <id>
docker export <id> -o fs.tar
docker save <image> -o image.tar
tar xf image.tar

# 没有 daemon 时直接读文件系统
jq -r '.GraphDriver.Data.UpperDir' /var/lib/docker/containers/<id>/config.v2.json
jq '.Config.Env' /var/lib/docker/containers/<id>/config.v2.json
jq -r '.log' /var/lib/docker/containers/<id>/<id>-json.log
```

```bash
# ---------- 云 ----------
jq -r '[.eventTime, .eventName, .sourceIPAddress, (.userIdentity.arn // "")] | @tsv' \
  cloudtrail.json | sort | head
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| iOS 备份里找不到 `relativePath` 对应的文件 | 真实路径是 `fileID` 前两位做目录、`fileID` 做文件名 | 用 `Files.fileID` 拼路径，不要用 `relativePath` |
| 备份一打开就是一堆哈希名文件 | 备份不做明文目录结构，全靠 `Manifest.db` 索引 | 先查索引，再按 `fileID` 取文件 |
| 加密备份提示密码错误 | 密码用于校验 keybag，不是解压密码 | 用 keybag 校验工具验证；字典爆破只对弱口令有效 |
| `.ab` 解包失败 | 不是 tar，或文件头声明的加密标志为 1 | 先 `file` 看头；加密备份需要密码，别当损坏 |
| ADB 备份里没有目标 App | `allowBackup=false`，或新版 Android 限制 `adb backup` | 改用已 root 的 `/data/data` 导出，或找应用自身的备份文件 |
| SQLite 打开报 `file is encrypted` | SQLCipher（微信/WhatsApp 常见） | 先看文件头；需要 key，不是换工具能解决 |
| 微信数据库解不开 | key 与 IMEI / uin 派生，版本不同算法不同 | 先确认版本，再按对应派生方式算 key；不要套旧教程 |
| `History` 打不开或数据为空 | 浏览器正在运行，库被锁或有 WAL 未合并 | 复制 `History` + `History-wal` + `History-shm` 后再查 |
| 浏览器时间算成 1970 年附近 | 把 WebKit 时间当 Unix 秒用了 | WebKit 是 1601 起算的**微秒**，除以 1e6 再减 11644473600 |
| Chrome 密码全是空 | profile 不完整，或没有同一用户的 DPAPI 上下文 | 连同 `Local State` 一起取；Windows 必须同一用户解密 |
| Cookie 里只有 `encrypted_value` | 新版浏览器不再存明文 | 按 OS 走 DPAPI / Keychain / 固定 key 解密；没有环境就只能拿长度 |
| Firefox 的 `logins.json` 是密文 | 密码用 `key4.db` 里的主密钥加密 | 用 `firefox_decrypt` 配合整个 profile，不要只拿 `logins.json` |
| `docker export` 出来的文件系统"少了东西" | export 是容器当前视图，不是镜像层 | 要镜像原始内容用 `docker save`；要改动看 `diff` |
| 在容器 `diff` 里找不到被删的文件 | 删除在 overlay 里是 whiteout（`.wh.`） | 去 `lower` / `layer.tar` 找原始文件，`diff` 只记录删除标记 |
| 云日志时间和服务器对不上 | 云日志是 UTC，服务器可能是本地时区 | 全链统一 UTC 再对齐 |

## ⑥ 例题

**题目**：Chrome 浏览器取证 —— 访问、下载与保存的密码
**来源**：CTF 浏览器取证方向的经典题结构，各校赛 "browser / forensic" 系列反复使用

**题干**：给一个 Chrome 用户配置目录，描述："他访问了一个内部系统，下载了东西，还保存了密码。找出他做了什么。"

**附件**：`Default/` 目录，含 `History`、`Cookies`、`Login Data`、`Local State`、`Bookmarks`。

**关键观察**：
- `History` 的 `urls` 表里有目标内部系统的地址，`visit_count` 大于 1
- `downloads` 表的 `target_path` 指向 `Downloads` 下的一个文件，`tab_url` 与访问记录对得上
- `Login Data` 的 `username_value` 是明文，`password_value` 非空 → 需要解密
- `Local State` 存在 → Windows 下可以用同一用户的 DPAPI 解 `os_crypt.encrypted_key`

**走了哪条链**：③-1 第 3 条（浏览器）→ C 第 1 条（认 profile）→ C 第 2 条（复制数据库）→ C 第 3 条（History）→ C 第 4 条（Downloads）→ C 第 7 条（Login Data）。

**命令与输出**：

```bash
$ cp Default/History /tmp/History
$ sqlite3 /tmp/History \
  "select datetime(last_visit_time/1000000-11644473600,'unixepoch') as t, url, title
   from urls order by last_visit_time desc limit 20;"
<UTC时间>|https://<内部系统>/<路径>|<标题>
...
```

```bash
$ sqlite3 /tmp/History \
  "select target_path, tab_url, total_bytes,
          datetime(start_time/1000000-11644473600,'unixepoch')
   from downloads order by start_time desc;"
<下载路径>|https://<内部系统>/<文件>|<字节数>|<UTC时间>
```

按 `target_path` 去文件系统取下载文件，`file` + `strings` 看内容。再查保存的密码：

```bash
$ sqlite3 "Login Data" "select origin_url,username_value,length(password_value) from logins;"
https://<内部系统>|<用户名>|<密文长度>
```

`password_value` 是 DPAPI 加密的，必须在同一 Windows 用户上下文里解；解出后得到登录密码。

**时间换算校验**：如果某条 `last_visit_time` 是 `13359038400000000`，它对应 `2024-05-01 12:00:00 UTC`（上面的 Python 换算已本地验证）。用这个值可以确认你的公式没有把微秒当秒。

**结果**：还原出"访问内部系统 → 下载文件 → 保存凭据"的完整链路。flag 常在被下载文件的内容、URL 的路径参数、或保存的密码里，形如 `flag{...}`（精确值以原题平台为准）。

**如果没有 `Local State` 或解密环境**：不要卡在密码上。按 C 第 4 条先把下载文件拿到，按 C 第 5 条看 Cookie 明文，按 C 第 9 条搜 `Local Storage` 里的 token —— 浏览器题往往有多条路径通向同一个 flag。
