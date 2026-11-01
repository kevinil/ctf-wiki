# CTF 知识字典

按题型识别的 CTF 知识体系与解题优先级。

不是教程合集，是**识别层**：看到一道题，先认出它属于哪一类、考什么、按什么顺序试。

## 快速开始

```bash
npm install       # 首次
npm run dev       # 开发预览 http://localhost:5173
npm run build     # 构建到 docs/.vitepress/dist
npm run preview   # 本地预览构建产物 http://localhost:4173
```

Windows 上直接双击 `serve.bat`：自动构建并打开浏览器。

## 内容

- `docs/map.md` —— 题型总表（全局判断流程），**从这里开始**
- `docs/web|pwn|reverse|crypto|misc|forensics/` —— 六大方向，共 58 个题型页
- `docs/meta/` —— 开场起手 / 卡住怎么办
- `docs/superpowers/specs/` —— 设计文档

## 每个题型页的固定七行

标题 → `关键词：` → ① 识别指纹 → ② 考什么 → ③ 判断流程 → ④ 工具与命令 → ⑤ 常见坑 → ⑥ 例题

其中**判断流程**是核心：一份按成本排序的优先级列表，命中即停，执行完回到顶部重扫。

## 校验脚本

```bash
python scripts/lint_docs.py      # 六段结构、关键词行、判断流程是否有序列表、跳转目标是否越界
python scripts/lint_vue.py       # VitePress 会把 {{ }} 当 Vue 表达式求值，这个脚本找出会被求值的位置
node   scripts/search_probe.mjs  # 用构建产物验证 15 条中文查询是否都能命中
```

改完内容后按顺序跑一遍，再 `npm run build`。

## 编辑约定

- 判断流程里的每一条必须是「条件 → 动作 → 命中后去哪」，禁止"可能需要""或许可以"这类模糊措辞。
- 模板里的 `{{ ... }}`（SSTI payload）必须放进围栏代码块或写成 `<code v-pre>{{...}}</code>`，否则会被 Vue 求值。
- 页面上出现的数字和命令输出，要么真实跑过，要么不写。
- 详见 `docs/superpowers/specs/2026-11-01-ctf-wiki-design.md` 第 6 节与 §9.1。
