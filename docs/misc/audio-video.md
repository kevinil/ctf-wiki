# 音频与视频隐写

关键词：音频隐写 视频隐写 频谱图 声谱图 spectrogram Audacity Sonic Visualiser sox ffmpeg ffprobe LSB 音频 DTMF 双音多频 SSTV 慢扫描电视 摩斯 Morse 倒放 变速 声道分离 remix 逐帧 帧间差异 字幕轨

## ① 识别指纹

- 附件后缀是 `.wav` / `.mp3` / `.flac` / `.ogg` / `.m4a`，或 `.mp4` / `.mkv` / `.avi` / `.mov` / `.webm`
- `file` 显示 `RIFF ... WAVE` / `MPEG ADTS` / `FLAC` / `Ogg` / `ISO Media` / `Matroska`
- 题干出现"听"、"录音"、"电话"、"电台"、"频谱"、"视频"、"帧"、"字幕"
- 音频播放起来是噪声、蜂鸣、按键音、传真式扫频音，或者倒放才像人声
- 双声道文件里一边有声、另一边近乎无声
- 视频能正常播放，但某几帧一闪而过，或者播放器能选出字幕轨
- 附件的时长、采样率、声道数与题干描述对不上
- 同一段素材给了两个版本（原版 / 处理版）

## ② 考什么

- **容器与流**：`ffprobe` 看音轨、视频轨、字幕轨、附件轨各有几条
- **频谱图**：用 STFT 把声音画成时频图，横向条纹、文字、二维码就是信息
- **波形与节奏**：DTMF 双音、摩斯短长音、SSTV 扫频音
- **采样 LSB**：PCM 每个采样值的最低位拼成字节
- **声道**：左右声道各藏一路，或反相相减抵消人声
- **时间轴**：倒放、变速、变调、片段拼接
- **视频**：逐帧导出、帧间差、帧顺序、单帧闪烁
- **字幕与附件**：软字幕、封面图、章节、附加文件
- **元数据与文件尾**：comment、title、`binwalk` 分离出的嵌套文件
- **编码参数异常**：采样率、位深、声道数被改过

## ③ 判断流程

### ③-1 子类型分流

1. `ffprobe` 只有 audio stream → 纯音频，跳到 ③-2 第 1 条。
2. `ffprobe` 同时有 audio 和 video stream → 音视频混合，跳到 ③-2 第 1 条，视频专项在 ③-2 第 10 条。
3. `ffprobe` 只有 video stream → 纯视频，直接跳到 ③-2 第 10 条。
4. 播放时是成组的短促双音按键声 → DTMF，跳到 ③-2 第 9 条。
5. 播放时是连续扫频的"啾"声 → SSTV，跳到 ③-2 第 9 条。
6. 播放时是长短不一的"滴"声、间隔成组 → 摩斯，跳到 ③-2 第 9 条。
7. 以上都不符合 → 跳到 ③-2 第 1 条。

### ③-2 成本排序链

1. `file 附件` + `ffprobe -v error -show_format -show_streams 附件`（纯音频再加 `soxi 附件`）→ 记下容器、编码、采样率、位深、声道数、流数量；有额外音轨或附件轨 → 跳第 11 条；有字幕轨 → 跳第 10 条；只有一条流 → 跳第 2 条。
2. `strings -n 6 附件 | grep -iE 'flag|ctf'` + `exiftool 附件`（或 `mediainfo 附件`）→ 出现 flag，或 comment/title/artist 里有可疑文本 → 提取并结束；没有 → 跳第 3 条。
3. `binwalk 附件` → 有嵌套或文件尾附加数据 → `binwalk -e` 分离，命中结束；没有 → 跳第 4 条。
4. 用播放器按正常速度完整听一遍（视频按正常速度看一遍）→ 听到成组按键声、扫频声、长短滴声 → 跳第 9 条；听到倒放才像人声 → 跳第 8 条；没有异常 → 跳第 5 条。
5. 画频谱图：`sox 附件 -n spectrogram -o spec.png`，或用 Audacity 的 Spectrogram 视图、Sonic Visualiser 打开 → 图上出现横向条纹、字母、数字、二维码 → 读出来，结束；把 FFT 窗口从 2048 换成 4096 仍无图案 → 跳第 6 条。
6. 仅当文件是 WAV/PCM：读每个采样的最低位拼字节 → 出现可打印 ASCII 或 `flag` → 结束；没有，或文件不是 WAV/PCM → 跳第 7 条。
7. 双声道：`sox in.wav left.wav remix 1`、`sox in.wav right.wav remix 2`，再对两声道做相减 → 某一路有人声、摩斯或数据 → 结束；两路相同 → 跳第 8 条。
8. 时间轴处理：`sox in.wav rev.wav reverse`、`sox in.wav fast.wav speed 2`、`sox in.wav slow.wav speed 0.5`、`sox in.wav tempo.wav tempo 1.5` → 处理后出现可辨识语音、摩斯或频谱文字 → 按对应方法提取，结束；仍无 → 跳第 9 条。
9. 按 ③-1 识别出的信号做专用解码：DTMF 取每段的行/列两个频率查表；SSTV 用 `sstv -d` 或 `qsstv` 解出图片；摩斯按短/长分段映射点划 → 得到文本或图片 → 结束；解码失败 → 跳第 12 条。
10. 视频：先看字幕流，有字幕 → `ffmpeg -map 0:s:0` 导出后读；无字幕 → `ffmpeg -i in.mp4 -vsync 0 frames/%04d.png` 逐帧导出，检查闪烁帧和异常帧；再用 `tblend=all_mode=difference` 或逐帧相减找帧间差异 → 命中结束；无 → 跳第 11 条。
11. 额外流与附件：把 `ffprobe` 列出的第二条音轨、字幕轨、附件轨逐条导出（`-map 0:a:1`、`-map 0:s:0`、`-map 0:t:0`），检查封面图、章节、附加文件 → 命中结束；无 → 跳第 12 条。
12. 兜底：以上全不成立 → 回到第 1 条，换粒度重看：整段 → 分段、单声道 → 逐采样、正常速度 → 半速；仍无 → 按题干提示改走 [图片隐写](/misc/image-stego) 或 [压缩包](/misc/archive)。

## ④ 工具与命令

```bash
file 附件
ffprobe -v error -show_format -show_streams 附件.mp4
soxi 附件.wav                      # 采样率、声道、时长
sox --i 附件.wav                   # 与 soxi 同源
exiftool 附件.wav
mediainfo 附件.mp4
binwalk -e 附件
```

```bash
# 频谱图：横轴时间，纵轴频率，亮度是能量
sox audio.wav -n spectrogram -o spec.png
```

Audacity：轨道左侧下拉菜单选 `Spectrogram`；`Analyze → Plot Spectrum` 看整体频率分布。
Sonic Visualiser：直接拖入音频，加 `Spectrogram` 图层，可调 window size 和 color map。

```python
# WAV/PCM 采样 LSB 提取（16-bit 单声道）
import wave, struct

w = wave.open('lsb.wav', 'rb')
raw = w.readframes(w.getnframes())
vals = struct.unpack('<%dh' % (len(raw) // 2), raw)
bits = ''.join(str(v & 1) for v in vals)

out = bytearray()
for i in range(0, len(bits) - 7, 8):
    b = int(bits[i:i + 8], 2)
    if b == 0:          # 常见的字符串结束标记
        break
    out.append(b)
print(out.decode())
```

实测输出：

```text
flag{lsb_audio_demo}
```

```text
DTMF 频率表（行频 × 列频）

        1209   1336   1477   1633
697      1      2      3      A
770      4      5      6      B
852      7      8      9      C
941      *      0      #      D
```

```bash
# 专用解码
sstv -d recording.wav -o image.png     # SSTV（Martin / Scottie / Robot36 等模式）
qsstv                                  # SSTV 图形界面，手动选模式
dtmf2num dtmf.wav                      # DTMF；没有就按上表自己算 FFT 峰值
```

摩斯音频没有固定工具也能做：在 Audacity 里看波形，按"响/静"切段，统计每段响声的持续时长，短为点、长为划，静音长的段落之间分词、更长的分段之间分字。

```bash
# 时间轴与声道
sox in.wav rev.wav reverse
sox in.wav fast.wav speed 2
sox in.wav slow.wav speed 0.5
sox in.wav tempo.wav tempo 1.5        # 改速度但保持音高
sox stereo.wav left.wav remix 1
sox stereo.wav right.wav remix 2
```

```bash
# 视频
ffmpeg -i in.mp4 -vn -acodec pcm_s16le audio.wav
ffprobe -v error -select_streams s -show_entries stream=index,codec_name -of csv in.mkv
ffmpeg -i in.mkv -map 0:s:0 subs.srt              # 文本字幕
ffmpeg -i in.mkv -map 0:s:0 -c:s copy subs.sup    # 位图字幕，导出后 OCR
ffmpeg -i in.mp4 -vsync 0 frames/%04d.png         # 逐帧，保持原始帧
ffmpeg -i in.mp4 -vf "tblend=all_mode=difference" diff/%04d.png
ffmpeg -i in.mp4 -map 0:a:1 second_audio.wav
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| 频谱图一片黑 | 动态范围和增益不合适 | 调 `sox spectrogram` 的 `-z` dB 范围，或在 Audacity 里拉对比度 |
| 频谱里只有一条亮线 | 单频正弦，不是隐藏信息 | 找频率随时间变化的横条纹或多条平行线 |
| 改后缀为 `.wav` 后打不开 | 容器并不是 WAV，只是后缀被改 | 先 `file` / `ffprobe`，用对应的解码器 |
| LSB 提取全是乱码 | 有损格式重编码过，采样值已变 | LSB 只对 PCM WAV / 无损 FLAC 做 |
| 左右声道相减后什么都没有 | 两声道内容相同或同相 | 先分别听两条声道，再做反相或差分 |
| `speed` 后声音变调、听不懂 | `speed` 同时改变时长和音高 | 试 `tempo`（保持音高），或两个都试 |
| 抽帧数量和视频帧数对不上 | 默认按恒定帧率重采样了 | 加 `-vsync 0`，保留原始帧 |
| 字幕导不出来 | 字幕是位图（PGS / VobSub） | 导出 `.sup` 后 OCR，不能当文本直接读 |
| 只听到一条音轨 | 播放器默认只播第一条 | `ffprobe` 看全部流，用 `-map 0:a:1` 导出 |

## ⑥ 例题

**题目**：DTMF 按键音
**来源**：自建样例（"电话录音 / 按键音"是 CTF 音频入门最常见的题型之一；实际比赛按原题平台为准）

**题干**：给一段电话录音 `dtmf.wav`，提示"密码是 8 位数字"，flag 格式以平台为准。

**附件**：单声道、16 bit、8000 Hz 的 WAV。

**关键观察**：
- `file` 直接给出 `WAVE audio, Microsoft PCM, 16 bit, mono 8000 Hz`，是无损 PCM，不存在有损重编码干扰
- 播放时是 8 组短促的双音"嘟"声，每组由两个频率叠加而成 —— DTMF 的典型听感
- 8000 Hz 采样率的上限是 4000 Hz，而 DTMF 最高列频是 1633 Hz，采样率足够

**走了哪条链**：③-1 第 4 条（成组双音 → DTMF）→ ③-2 第 9 条（专用解码）。

**命令与输出**：

```text
$ file dtmf.wav
dtmf.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 8000 Hz
```

```python
import wave
import numpy as np

w = wave.open('dtmf.wav', 'rb')
fs = w.getframerate()
x = np.frombuffer(w.readframes(w.getnframes()), dtype='<i2').astype(float)

rows = [697, 770, 852, 941]
cols = [1209, 1336, 1477, 1633]
keys = [['1', '2', '3', 'A'], ['4', '5', '6', 'B'],
        ['7', '8', '9', 'C'], ['*', '0', '#', 'D']]

win, step = int(0.05 * fs), int(0.12 * fs)
out = []
for start in range(0, len(x) - win, step):
    seg = x[start:start + win]
    if np.sqrt(np.mean(seg ** 2)) < 500:      # 跳过静音段
        continue
    spec = np.abs(np.fft.rfft(seg * np.hanning(len(seg))))
    freqs = np.fft.rfftfreq(len(seg), 1 / fs)

    def peak(lo, hi):
        idx = [i for i, f in enumerate(freqs) if lo <= f <= hi]
        return freqs[max(idx, key=lambda i: spec[i])]

    r = min(rows, key=lambda f: abs(f - peak(600, 1000)))
    c = min(cols, key=lambda f: abs(f - peak(1100, 1700)))
    out.append(keys[rows.index(r)][cols.index(c)])

print(''.join(out))
```

```text
13370880
```

**结果**：解出 8 位数字 `13370880`；按题目要求包成 `flag{...}` 提交，具体 flag 以原题平台为准。

**为什么代码要分两个频段找峰值**：DTMF 的每一段是"行频 + 列频"两个正弦叠加，全局最大值只会取到其中一个。必须在 600–1000 Hz 里找行频、在 1100–1700 Hz 里找列频，再各自取最近的标准频率。只取全局峰值会把列频误判成行频，解出来的第一位就会错。

::: tip 频谱图优先
音频题里频谱图的命中率高于 LSB。先 `sox ... spectrogram` 出一张图，看完再去做 LSB 和声道。
:::
