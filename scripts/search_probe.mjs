// 用构建产物里的搜索索引，验证中文查询能否命中。
// 用法: node scripts/search_probe.mjs [查询词...]
import fs from 'node:fs'
import path from 'node:path'
import MiniSearch from 'minisearch'

const DIST = 'docs/.vitepress/dist'
const chunksDir = path.join(DIST, 'assets/chunks')
const indexFile = fs
  .readdirSync(chunksDir)
  .find((f) => f.startsWith('@localSearchIndexroot.'))

if (!indexFile) {
  console.error('找不到搜索索引，先 npm run build')
  process.exit(1)
}

let src = fs.readFileSync(path.join(chunksDir, indexFile), 'utf-8')
src = src.slice(src.indexOf('`') + 1, src.lastIndexOf('`'))
const json = JSON.parse(src)

const tokenize = (text) =>
  Array.from(new Intl.Segmenter('zh', { granularity: 'word' }).segment(text))
    .filter((s) => s.isWordLike)
    .map((s) => String(s.segment).toLowerCase())

const ms = MiniSearch.loadJSON(JSON.stringify(json), {
  fields: ['title', 'titles', 'text'],
  storeFields: ['title', 'titles'],
  searchOptions: {
    fuzzy: 0.2,
    prefix: true,
    boost: { title: 4, text: 2, titles: 1 }
  },
  tokenize
})

const defaults = [
  '注入', '盲注', 'sqli', 'sql 注入', '反序列化', '伪加密', 'pcap',
  'ret2libc', '堆', '格式化字符串', 'RSA', '盲水印', 'volatility',
  'JWT', 'SSTI'
]

const queries = process.argv.slice(2).length ? process.argv.slice(2) : defaults
let failed = 0

for (const q of queries) {
  const results = ms.search(q).slice(0, 3)
  if (results.length === 0) {
    failed++
    console.log(`✗ ${q}  ->  (无结果)`)
  } else {
    console.log(`✓ ${q}`)
    for (const r of results) console.log(`     ${r.id}`)
  }
}

console.log(`\n${queries.length - failed}/${queries.length} 条查询有结果`)
process.exit(failed ? 1 : 0)
