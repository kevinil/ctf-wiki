#!/usr/bin/env python3
"""检查 VitePress 会把哪些 {{ }} 当成 Vue 表达式求值。

VitePress 渲染 markdown 时：
- 围栏代码块 (```)      -> 自动 v-pre，安全
- 行内代码 (`...`)       -> **不安全**，{{ }} 会被求值
- 正文                    -> **不安全**

用法: python scripts/lint_vue.py
退出码 1 表示有问题。
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'docs')
SKIP_DIRS = {'.vitepress', 'superpowers', 'public'}

problems = []

for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for name in filenames:
        if not name.endswith('.md'):
            continue
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, ROOT).replace('\\', '/')
        in_fence = False
        fence_marker = None
        with open(path, encoding='utf-8') as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.lstrip()
                m = re.match(r'^(```+|~~~+)', stripped)
                if m:
                    if not in_fence:
                        in_fence = True
                        fence_marker = m.group(1)[0]
                    elif stripped.startswith(fence_marker * 3):
                        in_fence = False
                    continue
                if in_fence:
                    continue
                # 去掉行内代码，单独标记
                if '{{' in line:
                    # <code v-pre> 是显式豁免；行内代码与正文都不安全
                    safe = re.sub(r'<code v-pre>.*?</code>', '', line)
                    if '{{' in safe:
                        inline = re.sub(r'`[^`]*`', '', safe)
                        if '{{' in inline:
                            problems.append(f'{rel}:{lineno}: 正文中的 {{{{ ... }}}} -> {line.strip()[:80]}')
                        else:
                            problems.append(f'{rel}:{lineno}: 行内代码中的 {{{{ ... }}}}（不安全） -> {line.strip()[:80]}')

if problems:
    print('发现 VitePress 会求值的 {{ }}：\n')
    for p in problems:
        print('  ' + p)
    print(f'\n共 {len(problems)} 处。改写方式：放进 ``` 围栏代码块，或写成 <code v-pre>{{7*7}}</code>')
    sys.exit(1)

print('OK: 没有会被 Vue 求值的 {{ }}。')
