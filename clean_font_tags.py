#!/usr/bin/env python3
"""
批量清理markdown文件中的font标签
用于清理从语雀复制过来的带颜色样式的文字
"""
import re
from pathlib import Path

# 配置 - 修改为你的博客内容目录
CONTENT_DIR = Path(r"D:\Blog\heathc1iff-sec.github.io\src\content\blog")

# 匹配 font 标签的正则
FONT_OPEN = re.compile(r'<font[^>]*>')
FONT_CLOSE = re.compile(r'</font>')

def clean_font_tags():
    count = 0
    files_changed = 0

    for md_path in CONTENT_DIR.rglob('*.md'):
        with open(md_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 统计匹配数
        matches = len(FONT_OPEN.findall(content))
        if matches == 0:
            continue

        count += matches
        files_changed += 1

        # 移除 font 标签，保留标签内的文字
        new_content = FONT_OPEN.sub('', content)
        new_content = FONT_CLOSE.sub('', new_content)

        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print(f'清理: {md_path.name} ({matches}处)')

    print(f'\n完成! 处理了 {files_changed} 个文件, 共清理 {count} 处font标签')

if __name__ == "__main__":
    clean_font_tags()
