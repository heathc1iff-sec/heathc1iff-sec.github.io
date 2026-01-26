import sharp from 'sharp';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const publicDir = path.join(__dirname, 'public');

// 图片扩展名
const imageExtensions = ['.png', '.jpg', '.jpeg'];

// 递归获取所有图片文件
function getImageFiles(dir) {
  let results = [];
  const items = fs.readdirSync(dir);

  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      results = results.concat(getImageFiles(fullPath));
    } else {
      const ext = path.extname(item).toLowerCase();
      if (imageExtensions.includes(ext)) {
        results.push(fullPath);
      }
    }
  }

  return results;
}

// 压缩单个图片
async function compressImage(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const originalSize = fs.statSync(filePath).size;

  // 跳过小于 50KB 的图片
  if (originalSize < 50 * 1024) {
    return { skipped: true, reason: 'too small' };
  }

  try {
    const image = sharp(filePath);
    const metadata = await image.metadata();

    let outputBuffer;

    if (ext === '.png') {
      // PNG 压缩 - 保持尺寸，降低质量
      outputBuffer = await image
        .png({
          quality: 80,
          compressionLevel: 9,
          palette: true
        })
        .toBuffer();
    } else {
      // JPEG 压缩
      outputBuffer = await image
        .jpeg({
          quality: 80,
          mozjpeg: true
        })
        .toBuffer();
    }

    const newSize = outputBuffer.length;

    // 只有压缩后变小才保存
    if (newSize < originalSize) {
      fs.writeFileSync(filePath, outputBuffer);
      return {
        success: true,
        originalSize,
        newSize,
        saved: originalSize - newSize,
        percent: ((1 - newSize / originalSize) * 100).toFixed(1)
      };
    } else {
      return { skipped: true, reason: 'no improvement' };
    }
  } catch (error) {
    return { error: error.message };
  }
}

// 格式化文件大小
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

// 主函数
async function main() {
  console.log('正在扫描图片文件...\n');

  const images = getImageFiles(publicDir);
  console.log(`找到 ${images.length} 个图片文件\n`);

  let totalOriginal = 0;
  let totalSaved = 0;
  let compressed = 0;
  let skipped = 0;
  let errors = 0;

  for (const filePath of images) {
    const relativePath = path.relative(__dirname, filePath);
    const result = await compressImage(filePath);

    if (result.success) {
      totalOriginal += result.originalSize;
      totalSaved += result.saved;
      compressed++;
      console.log(`✓ ${relativePath}`);
      console.log(`  ${formatSize(result.originalSize)} -> ${formatSize(result.newSize)} (节省 ${result.percent}%)\n`);
    } else if (result.skipped) {
      skipped++;
    } else if (result.error) {
      errors++;
      console.log(`✗ ${relativePath}: ${result.error}\n`);
    }
  }

  console.log('='.repeat(50));
  console.log(`\n压缩完成!`);
  console.log(`压缩: ${compressed} 个文件`);
  console.log(`跳过: ${skipped} 个文件 (太小或无法优化)`);
  console.log(`错误: ${errors} 个文件`);
  console.log(`总共节省: ${formatSize(totalSaved)}`);
}

main().catch(console.error);
