# 文档隐写与宏

关键词：文档隐写 PDF Office OOXML docx xlsx pptx doc xls vba 宏 macro vbaProject.bin AutoOpen olevba oletools oledump pdfinfo pdftotext pdfimages qpdf PDF JavaScript 隐藏文字 白字 极小字号 嵌入式对象

## ① 识别指纹

- 附件是 `.pdf` / `.docx` / `.xlsx` / `.pptx` / `.doc` / `.xls` / `.ppt` / `.rtf`
- `file` 显示 `PDF document`、`Microsoft Word 2007+`、`Composite Document File V2 Document`、`Rich Text Format`
- 题干出现"简历"、"合同"、"发票"、"工资表"、"打开文档"、"启用宏"、"宏病毒"
- 文档打开后内容很少、有大片空白，或者文字颜色与背景相同
- Word / Excel 打开时提示"启用宏"，或文件后缀是 `.docm` / `.xlsm` / `.pptm`
- 文档体积明显大于可见内容应有的大小
- PDF 打开时弹窗、跳转、要求点击，或元数据里有奇怪的 Producer
- 表格里有隐藏工作表，或文档里有批注、修订记录

## ② 考什么

- **OOXML 本质是 ZIP**：`word/document.xml`、`xl/sharedStrings.xml`、`word/vbaProject.bin`
- **PDF 对象与流**：对象流、增量更新、`FlateDecode` 压缩流
- **PDF 主动内容**：`/JS`、`/JavaScript`、`/OpenAction`、`/AA`、`/Launch`、`/EmbeddedFile`
- **VBA 宏行为**：`AutoOpen` / `Workbook_Open` / `Document_Open` 在打开文档时自动触发；`Shell` 调用外部程序；`CreateObject("WScript.Shell")` 提供执行环境；`Documents.Open` 打开载荷文件
- **隐藏文字**：白色字、极小字号、`w:vanish`、隐藏工作表、批注、页眉页脚
- **老式 OLE 复合文档**：`.doc` / `.xls` 的流结构，宏存放在独立的流里
- **嵌入对象**：`word/embeddings/`、`xl/embeddings/`、OLE 对象、外部关系 `.rels`
- **元数据与修订**：作者、公司、创建时间、最后保存者、删除的文本
- **加密文档**：有密码的 Office 文档、PDF 的加密字典

## ③ 判断流程

### ③-1 子类型分流

1. `file` 显示 `PDF document` → PDF 分支，跳到 ③-2 第 1 条。
2. `file` 显示 `Microsoft Word 2007+` / `Microsoft Excel 2007+` / `Microsoft PowerPoint 2007+`，或后缀是 `.docx` / `.xlsx` / `.pptx` 且 `file` 显示 `Zip archive` → OOXML 分支，跳到 ③-2 第 5 条。
3. `file` 显示 `Composite Document File V2 Document` / `CDFV2` → 老式 OLE 分支，跳到 ③-2 第 7 条先跑 `olevba`；没有宏再跳第 8 条看流。
4. `file` 显示 `Rich Text Format` → RTF 分支，跳到 ③-2 第 8 条。
5. 后缀是 `.docm` / `.xlsm` / `.pptm` → 一定按 OOXML 处理，跳到 ③-2 第 5 条，并优先看第 7 条的宏。
6. 以上都不匹配 → 跳到 ③-2 第 1 条。

### ③-2 成本排序链

1. `file 附件` + `exiftool 附件`（PDF 再加 `pdfinfo 附件`）→ 读 Author、Title、Subject、Keywords、Producer、Creator、CreationDate；`pdfinfo` 报 `Encrypted` 或元数据标了加密 → 跳第 10 条；出现 flag 或明确提示 → 提取并结束；没有 → 跳第 2 条。
2. `strings -n 6 附件 | grep -iE 'flag|ctf|http|powershell|cmd'` → 命中 → 按上下文提取字符串，结束；没有 → 跳第 3 条。
3. PDF 文本与附件：`pdftotext -layout in.pdf -`、`pdfimages -list in.pdf`、`pdfdetach -list in.pdf`、`pdfinfo -js in.pdf` → 文本里有 flag、存在附件、存在 JavaScript → 提取并阅读，命中结束；都没有 → 跳第 4 条。
4. PDF 对象流：`qpdf --qdf --object-streams=disable in.pdf out.qdf`，在 `out.qdf` 里查 `/JS`、`/JavaScript`、`/OpenAction`、`/AA`、`/Launch`、`/EmbeddedFile`、`/URI`；同时确认 `pdftotext` 是否提出了白色或极小字号文本 → 命中结束；没有 → 跳第 11 条。
5. OOXML 解包：`unzip -o in.docx -d out/`，再 `grep -rInaE 'flag|ctf' out/`；逐个读 `word/document.xml`、`xl/sharedStrings.xml`、`word/comments.xml`、`word/header*.xml`、`word/footer*.xml`、`docProps/core.xml`、`customXml/` → 命中结束；`unzip` 报密码或加密 → 跳第 10 条；没有 → 跳第 6 条。
6. 隐藏内容：在 `word/document.xml` 里找 `<w:color w:val="FFFFFF"/>`、`<w:sz w:val="2"/>`、`<w:vanish/>`；在 `xl/workbook.xml` 里找 `state="hidden"` / `state="veryHidden"`；在 `xl/styles.xml` 里找白色字体 → 命中结束；没有 → 跳第 7 条。
7. 宏：`olevba in.docm`（`.doc` / `.xls` 同样适用）→ 看 `AutoOpen` / `Workbook_Open` / `Document_Open` / `Shell` / `CreateObject` / `Documents.Open`；字符串被混淆 → `olevba --decode`；`olevba` 报加密/密码 → 跳第 10 条；命中结束；没有宏 → OOXML 跳第 9 条，老式 OLE / RTF 跳第 8 条。
8. 老格式与 RTF：`oledump.py in.doc` 列出流，`oledump.py -s N -v` 解压指定流，`oledump.py -s N -d` 导出；`rtfobj in.rtf` 提取嵌入对象；`strings -el in.doc` 找 UTF-16 字符串 → 命中结束；没有 → 跳第 9 条。
9. 嵌入对象与媒体：`binwalk -e 附件`、`foremost 附件`，检查 `word/media/`、`word/embeddings/`、`xl/embeddings/`，以及 `.rels` 里的外部 URL → 提取后按 [图片隐写](/misc/image-stego) 或 [压缩包](/misc/archive) 处理；命中结束；没有 → 跳第 11 条。
10. 加密或只读（只从第 1 / 5 / 7 条进入）：Office 用 `msoffcrypto-tool -p '密码' in.docx out.docx`，PDF 用 `qpdf --password= --decrypt in.pdf out.pdf`（先试空密码）→ 解密成功 → 跳第 2 条重新扫；解不开 → 跳第 11 条。
11. 兜底：以上全不成立 → 回到第 1 条，换粒度重看：用 LibreOffice 打开并另存为 `.txt` / `.xml`，或把文档当普通 ZIP / 二进制重新 `binwalk`；仍无 → 按题干中的密码、作者、日期线索改走其他方向。

## ④ 工具与命令

```bash
file 附件
exiftool 附件
pdfinfo 附件.pdf
pdftotext -layout 附件.pdf -          # 文本（包括白色/极小字）
pdfimages -list 附件.pdf              # 图片列表
pdfimages -all 附件.pdf images/       # 导出全部图片
pdfdetach -list 附件.pdf              # 附件列表
pdfdetach -saveall 附件.pdf           # 导出全部附件
pdfinfo -js 附件.pdf                  # 打印 PDF 内的 JavaScript
```

```bash
# PDF 对象流：把压缩的对象流展开成可读的 QDF
qpdf --qdf --object-streams=disable 附件.pdf out.qdf
qpdf --stream-data=uncompress 附件.pdf uncompressed.pdf
grep -aE '/JS|/JavaScript|/OpenAction|/AA|/Launch|/EmbeddedFile|/URI' out.qdf
```

```bash
# OOXML：docx / xlsx / pptx 都是 zip
unzip -l 附件.docx
unzip -o 附件.docx -d out/
grep -rInaE 'flag|ctf' out/
```

```bash
# 宏与老式 OLE
olevba 附件.docm
olevba --decode 附件.docm          # 解字符串混淆
oleid 附件.docm                    # 先看有没有宏/加密/外部关系
oledump.py 附件.doc                # 列出 OLE 流
oledump.py -s 8 -v 附件.doc        # 解压第 8 个流
oledump.py -s 8 -d 附件.doc        # 导出第 8 个流
rtfobj 附件.rtf
strings -el 附件.doc | grep -iE 'flag|http'
```

```bash
# 加密文档
msoffcrypto-tool -p '密码' 附件.docx 解密.docx
qpdf --password= --decrypt 附件.pdf 解密.pdf
```

白色字和极小字号在 `pdftotext` 里是能提出来的，实测：

```text
$ pdftotext -layout hidden.pdf -
Read the agreement carefully.

flag{pdf_hidden_text_demo}
```

PDF 里视觉上完全看不到第二行，但文本层仍然存在 —— 所以 PDF 先跑 `pdftotext`，不要只靠截图看。

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `unzip` 打不开 `.docx` | 文件其实是老式 `.doc`，只是后缀改了 | 看 `file` 是不是 `Composite Document File V2`，改用 `olevba` / `oledump` |
| 解包后没有 `vbaProject.bin` | 宏在嵌入的 OLE 对象里，或文档根本没宏 | `binwalk` / `foremost` 分离 `embeddings/`，再对分离物跑 `olevba` |
| 宏代码看不到明文 | VBA 字符串做了 `Chr()` / `StrReverse` 混淆 | `olevba --decode`，或把宏导出后手工还原 |
| 打开文档提示启用宏但没有 flag | flag 在宏的字符串里，不在执行结果里 | 静态提取宏代码和字符串，不要真的运行宏 |
| `pdftotext` 提取不到文字 | 页面是扫描图，文字是像素 | 先 `pdfimages` 导出再 OCR，或对整页渲染后 OCR |
| `qpdf` 生成的 QDF 里搜不到 JS | 对象在压缩流或增量更新里 | 同时试 `--stream-data=uncompress`，并在原始 PDF 上 `grep -a` |
| Word 里看不到白字或隐藏文字 | 白色字与背景同色，或 `w:vanish` 的显示选项没开 | 直接解包看 XML，或 `pdftotext` 同理处理 PDF |
| `.xlsx` 里找不到数据 | 数据在隐藏工作表或 `sharedStrings.xml` | 查 `workbook.xml` 的 `state`，再读 `sharedStrings.xml` |
| 文档要密码但题干没给 | 可能是空密码或只读 / 权限保护 | 先试空密码；Office 用 `msoffcrypto-tool`，PDF 用 `qpdf --password=` |

## ⑥ 例题

**题目**：OOXML 白字与极小字号
**来源**：自建样例（Office 文档隐写的入门题型；实际比赛按原题平台为准）

**题干**：给一个 `hidden.docx`，打开只看到一句"Read the agreement carefully."，要求找出文档里的 flag。

**附件**：一个标准 OOXML `.docx`，正文只有一行可见文字和一行白色 2 pt 文字。

**关键观察**：
- `file` 显示 `Microsoft Word 2007+`，说明是 OOXML，本质是 ZIP
- 文档体积正常，`unzip -l` 里没有 `vbaProject.bin`，排除宏
- 可见文字只有一句，但 `word/document.xml` 的大小明显不止这一句
- XML 里出现 `<w:color w:val="FFFFFF"/>`（白色）和 `<w:sz w:val="4"/>`（4 个半磅 = 2 pt，极小）

**走了哪条链**：③-1 第 2 条（OOXML）→ ③-2 第 5 条（解包看 XML）→ 第 6 条（识别白色 / 极小字号）。

**命令与输出**：

```text
$ file hidden.docx
hidden.docx: Microsoft Word 2007+

$ unzip -l hidden.docx | grep 'word/document.xml$'
     1711  2026-11-01 17:40   word/document.xml

$ unzip -p hidden.docx word/document.xml | grep -o 'flag{[^<]*}'
flag{hidden_text_demo}
```

`word/document.xml` 中对应的片段：

```xml
<w:r><w:rPr><w:color w:val="FFFFFF"/><w:sz w:val="4"/></w:rPr>
<w:t>flag{hidden_text_demo}</w:t></w:r>
```

**结果**：flag 写在白色、2 pt 的 run 里，肉眼几乎不可见；解包或全选复制即可拿到。提交时按平台要求写成 `flag{...}`，具体值以原题平台为准。

**为什么白色字仍然能被提取**：文字颜色和字号只是渲染属性，字符本身完整地存在 `document.xml` 里。Word 的"全选 → 复制"、`unzip -p`、`grep` 都不关心颜色；只有截图和肉眼会漏掉它。PDF 同理，`pdftotext` 提取的是文本层，不是渲染后的像素。

::: tip 先解包再打开
拿到 Office 文档，第一动作是 `file` + `unzip -l`，不是双击打开。双击可能触发宏，也可能因为渲染而漏掉隐藏内容；解包永远是无损的。
:::
