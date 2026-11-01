# 图片隐写

关键词：图片隐写 LSB zsteg steghide 盲水印 EXIF PNG IHDR 隐写术 stego 位平面 调色板 GIF

## ① 识别指纹

- 附件是 `.png` / `.jpg` / `.bmp` / `.gif` / `.webp`
- 题干说"看图"、"图片里有东西"、"找不同"、"这张照片"
- 图片打开看起来完全正常，甚至很无聊
- 分值通常很低（签到题级别）
- 题目名带 `misc` / `stego` / `图片` / `藏在图片里`
- 给了**两张**几乎一样的图 —— 直接跳到盲水印对比

## ② 考什么

- **文件尾部附加**：PNG 的 `IEND` 之后、JPEG 的 `FFD9` 之后追加数据
- **LSB 隐写**：最低有效位藏信息（`zsteg` / `stegsolve`）
- **EXIF 与元数据**：注释、GPS、软件名
- **嵌套文件**：`binwalk` 分离出 zip / 另一张图 / PE
- **尺寸篡改**：PNG 的 `IHDR` 高度被改小，画出半张图
- **调色板 / GIF 帧**：多帧动画逐帧藏信息
- **盲水印**：两张图频域/空域做差
- **JPEG 特有**：`steghide`、DCT 系数、量化表
- **二维码 / 条形码**：图里有个识别不出来的码
- **像素重排**：宽高乘积不变的重排、按 RGB 通道拆分

## ③ 判断流程

1. **`file 图片`** —— 确认真实格式（`.png` 实际是 zip 的情况非常多）
2. **`exiftool 图片`** —— 看 Comment / Image Description / GPS / Artist / Software
3. **`binwalk 图片`** —— 有嵌套就 `binwalk -e`，命中直接结束；没嵌套继续
4. **`strings -n 6 图片 | grep -i flag`** —— 30 秒，命中最快
5. **看文件尾**：十六进制跳到文件末尾，找 `IEND`（PNG）或 `FFD9`（JPEG）之后的字节
   - 有可疑数据 → 按对应格式切开翻译（可能是 base64、可能是另一个文件），跳 11
6. **`zsteg 图片`**（PNG/BMP 专用）—— 一把梭扫 LSB 的各种组合，输出里出现可读 ASCII 或 `flag` 就结束
7. **JPEG 用 `steghide`**：先试空密码和常见弱密码
   ```bash
   steghide extract -sf 图.jpg -p ''
   ```
8. **两张图？** 做差：`stegsolve` 的 Image Combiner，或用 Python 逐像素相减/异或 —— 隐藏内容会浮出来
9. **检查尺寸**：用 `stegsolve` 或 `pngcheck -v 图.png` 看 `IHDR` 声明的宽高，和肉眼看到的是否一致
   - 高度明显偏小、下方有"被切断"的痕迹 → **改高度**，跳 10
10. **改 PNG 高度**：算出正确的 height，重建 `IHDR` 的 CRC —— 详见下面的脚本
11. **数据拿到后**：判断编码（base64 / hex / 二进制直接 `file`），再回 [Misc 编码链](/misc/encoding-mix)
12. **以上全不成立** → 试 RGB 通道分离、`stegsolve` 的 Alpha/位平面视图、把图放大 3 倍看噪点；仍不行回第 1 条

## ④ 工具与命令

```bash
file 图.png
exiftool 图.png
binwalk -e 图.png
strings -n 6 图.png | grep -iE 'flag|ctf'
pngcheck -v 图.png                 # 检查 chunk 结构
zsteg -a 图.png                    # LSB 全扫
steghide extract -sf 图.jpg -p ''  # JPEG
foremost 图.png                    # 通用文件雕刻
```

```python
# 修改 PNG 高度并重建 IHDR 的 CRC32
import struct, zlib

path = '图.png'
data = bytearray(open(path, 'rb').read())

# PNG: 0-7 签名, 8-11 chunk length, 12-15 "IHDR", 16-19 width, 20-23 height
old_h = struct.unpack('>I', data[20:24])[0]
new_h = old_h * 2                        # 常见做法：按需尝试不同高度

data[20:24] = struct.pack('>I', new_h)

# CRC 覆盖 "IHDR" + 13 字节数据，即字节 12..28
crc = zlib.crc32(bytes(data[12:29])) & 0xffffffff
data[29:33] = struct.pack('>I', crc)

open('fixed.png', 'wb').write(data)
print('height', old_h, '->', new_h)
```

```python
# 两张图做差（盲水印的最简形式）
from PIL import Image, ImageChops
a = Image.open('1.png').convert('RGB')
b = Image.open('2.png').convert('RGB')
diff = ImageChops.difference(a, b)
diff.save('diff.png')
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `zsteg` 输出一堆乱码 | 它把噪声也当成候选 | 只关注 `text:` / 含 `flag` / 可打印 ASCII 的行 |
| 改高度后图还是打不开 | CRC 没重建 | `IHDR` 的 CRC 必须重算，否则解码器直接拒绝 |
| 改高度后 CRC 对但显示异常 | 高度改得太大，超出了实际 IDAT 数据量 | 从小的值开始试，或者用 `pngcheck` 看 IDAT 解压后长度反推 |
| `steghide` 说密码错 | 没有密码或密码在别处 | 试空密码；看题干/文件名有没有暗示 |
| `binwalk` 没扫出东西 | 数据被加密或压缩过 | 换 `foremost`，或直接看文件尾十六进制 |
| JPEG 里什么 LSB 都没有 | JPEG 是有损压缩，LSB 不可靠 | JPEG 走 `steghide` / DCT / 量化表，不要用 LSB 思路 |
| 图看起来正常但统计异常 | 噪声被替换过 | 用 `stegsolve` 的位平面视图，低位平面会显出图案 |

## ⑥ 例题

**题目**：PNG 高度篡改
**来源**：CTF 图片隐写最经典的题型之一，`pngcheck` / `IHDR` 手工修复是所有入门课的必修

**题干**：给一张 `flag.png`，打开就是一张纯色的图，什么都没有。

**关键观察**：
- 图是纯色，但文件大小明显大于一张纯色图应有的大小（几 KB 以上）
- `pngcheck -v flag.png` 通过，说明结构没坏
- `binwalk` 没有嵌套，`strings` 没有内容
- 这说明**数据还在文件里，只是没被画出来** —— 高度被改小了

**走了哪条链**：第 1–4 条（`file` / `exiftool` / `binwalk` / `strings` 全部无收获）→ 第 9 条（尺寸检查，发现高度可疑）→ 第 10 条（改高度并重建 CRC）。

**命令与输出**：

```text
$ pngcheck -v flag.png
File: flag.png (1234 bytes)
  chunk IHDR at offset 0x0000c, length 13
    800 x 80 image, 32-bit RGB+alpha, non-interlaced
```

文件 1234 字节，但 `800 x 80` 的 RGBA 图像按未压缩算应该有 800×80×4 = 256 KB。**文件比应有的小得多**是正常的（PNG 压缩），但一张**纯色**图不该有 1 KB 以上。可疑。

```python
# 用第 ④ 段的脚本把高度改成 400
$ python fix_height.py
height 80 -> 400

$ pngcheck -v fixed.png
File: fixed.png (1234 bytes)
  chunk IHDR at offset 0x0000c, length 13
    800 x 400 image, 32-bit RGB+alpha, non-interlaced
```

打开 `fixed.png`，下半部分显示出 `flag{...}`。

**结果**：图片下方被"裁掉"的部分重新出现，flag 就画在那里。

**为什么能判断出高度被改**：PNG 的 `IHDR` 声明 `height=80`，解码器只渲染前 80 行；但 `IDAT` 里存放的是按**原始高度**压缩的全部像素数据。所以图像数据和声明对不上时，解码器要么报错、要么只画出前一部分。**纯色图 + 文件偏大 + 结构正常**，就是这个矛盾的典型表现。

::: tip 高度试不出来怎么办
盲猜高度很烦，可以用 `pngcheck` 输出的 IDAT 解压后字节数反推：
`IDAT 解压总长度 / (宽度 × 每像素字节数) = 真实高度`。
写脚本把 `zlib.decompress` 后的长度除以 `width * 4` 即可。
:::
