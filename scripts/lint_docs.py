#!/usr/bin/env python3
"""检查题型页是否满足设计文档第 6 节的六段结构。

用法: python scripts/lint_docs.py
退出码 1 表示有页面不合规。
"""
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'docs')
SKIP_DIRS = {'.vitepress', 'superpowers', 'public', 'meta'}
SKIP_FILES = {'index.md', 'map.md', 'README.md'}
SECTIONS = ['## ① 识别指纹', '## ② 考什么', '## ③ 判断流程', '## ④ 工具与命令', '## ⑤ 常见坑', '## ⑥ 例题']
VAGUE = ['可能需要', '或许可以', '也许可以', '大概可以', '可能是%']


def strip_fences(text):
    out, in_fence, fence = [], False, None
    for line in text.split('\n'):
        s = line.lstrip()
        m = re.match(r'^(```+|~~~+)', s)
        if m:
            if not in_fence:
                in_fence, fence = True, m.group(1)[0]
            elif s.startswith(fence * 3):
                in_fence = False
            out.append('')
            continue
        out.append('' if in_fence else line)
    return '\n'.join(out)


def check(path):
    rel = os.path.relpath(path, ROOT).replace('\\', '/')
    text = open(path, encoding='utf-8').read()
    problems = []

    for sec in SECTIONS:
        if sec not in text:
            problems.append(f'缺少段落: {sec}')

    if not re.search(r'^关键词：', text, re.M):
        problems.append('缺少 关键词： 行')

    # 判断流程里必须是有序列表
    m = re.search(r'## ③ 判断流程(.*?)(?=\n## |\Z)', text, re.S)
    if m:
        body = strip_fences(m.group(1))
        if not re.search(r'^\s*\d+\.\s', body, re.M):
            problems.append('③ 判断流程 里没有有序列表')
        for w in VAGUE:
            if w in body:
                problems.append(f'③ 里出现模糊措辞: {w}')
        # 跳转目标必须在条目数范围内
        items = re.findall(r'^\s*(\d+)\.\s', body, re.M)
        if items:
            top = max(int(i) for i in items)
            for target in re.findall(r'(?:进|跳|回|转到|回到)\s*第?\s*(\d+)\s*条', body):
                if int(target) > top:
                    problems.append(f'③ 跳转目标越界: 第 {target} 条，但本页只有 {top} 条')

    # ⑤ 常见坑 必须是表格
    m5 = re.search(r'## ⑤ 常见坑(.*?)(?=\n## |\Z)', text, re.S)
    if m5 and '|' not in m5.group(1):
        problems.append('⑤ 常见坑 不是表格')

    return rel, problems


def main():
    bad = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if not name.endswith('.md') or name in SKIP_FILES:
                continue
            rel, problems = check(os.path.join(dirpath, name))
            if problems:
                bad += 1
                print(f'✗ {rel}')
                for p in problems:
                    print(f'    - {p}')
    if bad:
        print(f'\n{bad} 个页面不合规')
        sys.exit(1)
    print('OK: 所有页面结构合规')


if __name__ == '__main__':
    main()
