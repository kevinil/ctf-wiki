# 流量分析

关键词：流量分析 pcap pcapng wireshark tshark USB HID 隧道 DNS隧道 ICMP隧道 抓包 协议还原 取证

## ① 识别指纹

- 附件是 `.pcap` / `.pcapng` / `.cap`，`file` 显示 `tcpdump capture file` 或 `pcapng capture file`
- 题干出现"流量"、"抓包"、"数据包"、"分析这个 pcap"、"他在干什么"
- 文件大小从几十 KB 到几百 MB 都有
- 题目名带 `traffic` / `pcap` / `forensic` / `流量分析`
- 有时附件没有后缀，但 `file` 一看就是 pcap

## ② 考什么

- Wireshark 显示过滤器：`http`、`tcp.port==80`、`ip.addr==x`、`frame contains "flag"`
- 协议分层统计：`Statistics → Protocol Hierarchy`
- Follow TCP/UDP Stream 看完整会话
- **导出对象**（`File → Export Objects → HTTP/SMB/FTP`）
- 明文协议还原：HTTP / FTP / Telnet / SMTP / POP3 / IRC
- 隧道：DNS 隧道、ICMP 隧道、HTTP 隐蔽信道
- USB 流量（HID 键盘 / 鼠标 / 存储）
- TLS 解密：`SSLKEYLOGFILE`、服务器私钥、预主密钥
- 提取文件：导出对象、`binwalk`、`foremost`
- 统计与时间线：`Statistics → Conversations` / `Endpoints`

## ③ 判断流程

1. **`capinfos 附件.pcap`** 看包数、时间跨度、平均速率 —— 十几万的包说明是流量噪声型，几百个包说明是**关键会话型**
2. **Wireshark 打开 → `Statistics → Protocol Hierarchy`** —— 哪个协议占主导，方向就定了：
   - HTTP 占比高 → 跳 3
   - FTP / Telnet / SMTP / POP3 → 跳 4
   - DNS 查询量异常多且字符串可疑 → 跳 5
   - ICMP 包大且多 → 跳 6
   - USB（`usb.capdata` / `usb.src`）→ 跳 7
   - TLS / SSH 占主导 → 跳 8
   - 协议高度混杂、看不出重点 → 跳 9
3. **HTTP**：`File → Export Objects → HTTP` 先把所有对象导出；再 `过滤 http.request` 看 URL 和 POST body；flag 常见于上传的表单、Cookie、响应体
   - 导出后没找到 → 用 `frame contains "flag"` 全文搜
4. **明文协议**：右键 → `Follow → TCP Stream`，从第一条按顺序读；FTP 的 `USER/PASS`、Telnet 的键盘输入往往是直接答案
5. **DNS 隧道**：过滤 `dns`，看查询的子域名 —— 把 `qname` 逐个拼起来、或者把子域名前缀按顺序解 base32/base64
6. **ICMP 隧道**：过滤 `icmp`，看 `data` 长度是否恒定且偏大；把 payload 按顺序抽出拼成文件（先看前几个包判断是 base64 还是 raw）
7. **USB**：`usb.capdata` 是 HID 报文的通用字段
   - 键盘：每包 8 字节，第 3 字节（索引 2）是键码，键码 4–29 对应 a–z
   - 鼠标：看 `usb.capdata` 的高低字节，横纵坐标变化量能还原出"画出"的轨迹
   - 存储：按 URB 的原始数据重组
8. **TLS / SSH**：
   - 找有没有随附的 `keylog` 文件或服务器私钥，配进 `Preferences → Protocols → TLS` 解密
   - 没有 → 基本只能靠 `strings` / `binwalk` 从原始流里捞，或者题目另有入口
9. **兜底**：`strings -n 6 附件.pcap | grep -i flag`；`binwalk -e 附件.pcap`；用 `foremost` 拆文件
10. **以上都不成立** → 回到第 2 条，用 `Statistics → Conversations` 按流量排序，最大的那条流一定有问题

## ④ 工具与命令

```bash
capinfos 附件.pcap                      # 概览
tshark -r 附件.pcap -q -z io,phs        # 协议层次统计
tshark -r 附件.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
tshark -r 附件.pcap -Y 'frame contains "flag"' -T fields -e frame.number -e data.text

# 导出 HTTP 对象
tshark -r 附件.pcap --export-objects http,./out

# 提取 TCP 流
tshark -r 附件.pcap -q -z follow,tcp,ascii,0
```

```python
# USB 键盘流量解码（pcapng 用 pyshark / scapy 读 usb.capdata）
# 键码表：4-29 -> a-z，30-39 -> 1-0，40 -> 回车
keymap = {
    4:'a',5:'b',6:'c',7:'d',8:'e',9:'f',10:'g',11:'h',12:'i',13:'j',
    14:'k',15:'l',16:'m',17:'n',18:'o',19:'p',20:'q',21:'r',22:'s',
    23:'t',24:'u',25:'v',26:'w',27:'x',28:'y',29:'z',
    30:'1',31:'2',32:'3',33:'4',34:'5',35:'6',36:'7',37:'8',38:'9',39:'0',
    40:'\n',44:' ',45:'-',46:'=',47:'[',48:']',49:'\\',52:"'",54:',',55:'.',56:'/'
}
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 抓到的都是 TLS，看不到明文 | 加密流量 | 找 keylog / 私钥；没有就换方向（可能是 USB/DNS 隐藏信道） |
| Follow TCP Stream 是乱码 | 端口不是 80 但内容是 HTTP，或被 gzip 了 | `Decode As → HTTP`；或导出后用 `zcat` 解压 |
| 导出对象里什么都没有 | 数据不在 HTTP 层 | 试 SMB / FTP / TFTP 的导出对象 |
| USB 包有但不是键盘 | 可能是鼠标/存储 | 看 `usb.bInterfaceClass` / 报告描述符 |
| DNS 子域名拼出来是乱码 | 顺序错了或需要 base32 | 按时间排序；试 base32 / base64 / hex |
| 包太多，Wireshark 卡死 | 大文件 | 用 `editcap -c 50000` 分片，或直接用 tshark 命令行过滤 |
| flag 搜不到但明显有 | 被分段在多个包里 | 先 `Follow Stream` 拼完整，再在流里搜 |

## ⑥ 例题

**题目**：USB 键盘流量还原
**来源**：CTF 取证类最常见的题型之一，BUUCTF / 各大校赛的"USB 流量"系列

**题干**：给一个 `usb.pcapng`，题干说"他在电脑上敲了什么"。

**关键观察**：
- `Statistics → Protocol Hierarchy` 里几乎全是 USB，没有任何网络协议 —— 说明这题考的不是网络协议
- `usb.capdata` 字段存在，且每包长度固定 8 字节
- 8 字节 + 固定长度 = 标准 HID 键盘报告

**走了哪条链**：第 1 条（`capinfos` 看包数）→ 第 2 条（协议层次全是 USB）→ 第 7 条（USB HID 键盘解码）。

**命令与输出**：

```bash
tshark -r usb.pcapng -T fields -e usb.capdata | head
# 00:00:04:00:00:00:00:00
# 00:00:00:00:00:00:00:00
# 00:00:05:00:00:00:00:00
# ...
```

第 3 个字节（索引 2）是键码：`04` → `a`，`05` → `b`。

```python
from scapy.all import rdpcap, Raw

data = rdpcap('usb.pcapng')
out = []
for pkt in data:
    try:
        payload = bytes(pkt[Raw].load)
    except Exception:
        continue
    if len(payload) == 8 and payload[2] != 0:
        out.append(keymap.get(payload[2], '?'))
print(''.join(out))
```

**结果**：拼出来是一段可读字符串，通常就是 `flag{...}`。

**验证方法**：如果解出来有大量 `?` 和回车，说明键码表不完整 —— 补上 `44`（空格）、`40`（回车）、`45`（减号）之后通常就通了。

::: tip 迁移
USB 流量还有两个常见变体：
- **鼠标**：`usb.capdata` 里是 x/y 位移量，把点连起来画图，flag 是画出来的字
- **存储**：不是 HID，而是 `USB Mass Storage` 的 bulk transfer，需要按 SCSI 命令重组数据块，工具用 `usbrubberducky` 或手工索引 URB
:::
