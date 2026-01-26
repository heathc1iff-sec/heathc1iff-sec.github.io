#!/usr/bin/env python3
"""
批量下载语雀图片并替换markdown中的链接
"""
import os
import re
import urllib.request
import urllib.parse
import hashlib
from pathlib import Path

# 配置
BLOG_DIR = Path(r"D:\Blog\heathc1iff-sec.github.io")
CONTENT_DIR = BLOG_DIR / "src" / "content" / "blog"
IMAGE_DIR = BLOG_DIR / "public" / "image"

# 语雀CDN正则
YUQUE_PATTERN = r'https://cdn\.nlark\.com/yuque/\d+/\d+/(?:jpeg|jpg|png|gif|webp)/\d+/[\w-]+\.(?:jpeg|jpg|png|gif|webp)'

def get_image_ext(url):
    """从URL获取图片扩展名"""
    match = re.search(r'\.(jpeg|jpg|png|gif|webp)$', url, re.IGNORECASE)
    return match.group(1).lower() if match else 'jpg'

def download_image(url, save_path):
    """下载图片"""
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': 'https://www.yuque.com/'
        })
        with urllib.request.urlopen(req, timeout=30) as response:
            with open(save_path, 'wb') as f:
                f.write(response.read())
        return True
    except Exception as e:
        print(f"  [错误] 下载失败: {url}")
        print(f"         原因: {e}")
        return False

def sanitize_filename(name):
    """清理文件名，移除特殊字符"""
    # 移除或替换不适合做文件名的字符
    name = re.sub(r'[<>:"/\\|?*]', '', name)
    name = re.sub(r'[""]', '', name)  # 移除中文引号
    name = name.strip()
    # 如果文件名太长，截断
    if len(name) > 50:
        name = name[:50]
    return name

def process_markdown_file(md_path):
    """处理单个markdown文件"""
    with open(md_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 查找所有语雀图片链接
    urls = re.findall(YUQUE_PATTERN, content)
    if not urls:
        return 0

    # 去重但保持顺序
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    # 获取文章分类目录名（如 HmvMachines, Tryhackme 等）
    category = md_path.parent.name.lower()

    # 获取文章名（不含扩展名）
    article_name = sanitize_filename(md_path.stem)

    # 创建图片保存目录
    img_save_dir = IMAGE_DIR / category
    img_save_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n处理: {md_path.name}")
    print(f"  分类: {category}, 图片数: {len(unique_urls)}")

    # 下载图片并替换链接
    for idx, url in enumerate(unique_urls, 1):
        ext = get_image_ext(url)
        # 使用 文章名-序号.扩展名 格式
        img_filename = f"{article_name}-{idx}.{ext}"
        img_save_path = img_save_dir / img_filename

        # 新的引用路径（对空格进行URL编码）
        encoded_category = urllib.parse.quote(category)
        encoded_filename = urllib.parse.quote(img_filename)
        new_url = f"/image/{encoded_category}/{encoded_filename}"

        # 下载图片
        if img_save_path.exists():
            print(f"  [{idx}/{len(unique_urls)}] 已存在: {img_filename}")
        else:
            print(f"  [{idx}/{len(unique_urls)}] 下载: {img_filename}")
            if not download_image(url, img_save_path):
                continue

        # 替换内容中的链接
        content = content.replace(url, new_url)

    # 写回文件
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(content)

    return len(unique_urls)

def main():
    print("=" * 60)
    print("语雀图片迁移工具")
    print("=" * 60)

    # 查找所有markdown文件
    md_files = list(CONTENT_DIR.rglob("*.md"))
    print(f"找到 {len(md_files)} 个markdown文件")

    total_images = 0
    processed_files = 0

    for md_path in md_files:
        count = process_markdown_file(md_path)
        if count > 0:
            total_images += count
            processed_files += 1

    print("\n" + "=" * 60)
    print(f"完成! 处理了 {processed_files} 个文件, 共 {total_images} 张图片")
    print("=" * 60)

if __name__ == "__main__":
    main()
