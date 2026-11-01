---
layout: home

hero:
  name: CTF 知识字典
  text: 看到题，先认出它
  tagline: 六大方向 · 58 个题型 · 每个题型一张"判断 → 动作 → 命中即停"的优先级链
  actions:
    - theme: brand
      text: 题型总表（从这里开始）
      link: /map
    - theme: alt
      text: 开场起手
      link: /meta/opening
    - theme: alt
      text: 卡住了怎么办
      link: /meta/stuck

features:
  - title: Web
    details: 注入、上传、包含、反序列化、SSTI、XXE 等 12 类服务端与前端漏洞
    link: /web/sql-injection
  - title: Pwn
    details: 栈溢出、ROP、格式化字符串、堆利用、沙箱绕过等 10 类二进制利用
    link: /pwn/stack-basic
  - title: Reverse
    details: 静态分析、动态调试、脱壳、算法识别、虚拟机逆向等 10 类
    link: /reverse/static-analysis
  - title: Crypto
    details: 古典密码、RSA、格、PRNG、流密码等 10 类密码学攻击
    link: /crypto/classical
  - title: Misc
    details: 隐写、压缩包、编码链、交互题等 8 类杂项
    link: /misc/encoding-mix
  - title: 取证
    details: 流量、内存、磁盘、系统、日志、样本分析等 8 类数字取证
    link: /forensics/pcap
---

## 怎么用这个站

这不是教程合集，是**识别层**。

拿到一道题，先别急着打开工具：

```text
① 看附件 / 题干 → 走 /map 的全局判断流程
② 命中某个方向 → 进该方向页的「判断流程」
③ 判断流程是优先级列表：从最便宜的检查开始，命中就停
④ 执行完再回到该方向页顶部重扫一遍
```

这套东西的结构，和游戏里的输出循环是一个思路：**不是记住所有技能，而是记住先放哪个**。

## 每条判断流程长什么样

```markdown
1. `file` 看到 ELF 且是 `executable` → 进二进制方向，跳第 4 条
2. 运行后直接要求输入一行 → 大概率栈溢出或格式化字符串
3. 有 `nc` 连接地址 → 交互式 pwn，先看保护开了什么（checksec）
4. 以上都不成立 → 回到第 1 条，用 `binwalk` 换个颗粒度重看
```

三条硬规矩：

- **按成本排序**：零成本的检查永远排前面
- **命中即停**：条件成立就执行，执行完回顶部重扫
- **禁止模糊词**："可能需要"不许写；必须是可判定的条件

## 每个题型页的固定六段

| 段 | 回答的问题 |
|---|---|
| 识别指纹 | 这题长什么样，我怎么知道它是这一类 |
| 考什么 | 背后靠哪些知识点撑着 |
| 判断流程 | 先做什么、后做什么、什么条件下转火 |
| 工具与命令 | 直接复制就能跑 |
| 常见坑 | 哪些看起来是 A 其实是 B |
| 一道例题 | 公开原题，走到哪一条链，flag 在哪 |
