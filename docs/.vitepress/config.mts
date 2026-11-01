import { defineConfig } from 'vitepress'

const DIRS = [
  {
    text: 'Web',
    items: [
      { text: 'SQL 注入', link: '/web/sql-injection' },
      { text: 'XSS 跨站脚本', link: '/web/xss' },
      { text: 'SSRF 服务端请求伪造', link: '/web/ssrf' },
      { text: '文件上传', link: '/web/file-upload' },
      { text: '文件包含 LFI / RFI', link: '/web/file-inclusion' },
      { text: '命令执行与代码执行', link: '/web/rce' },
      { text: '反序列化', link: '/web/deserialization' },
      { text: '目录穿越与任意文件读取', link: '/web/path-traversal' },
      { text: '认证与权限', link: '/web/auth' },
      { text: '模板注入 SSTI', link: '/web/ssti' },
      { text: 'XXE', link: '/web/xxe' },
      { text: 'HTTP 层杂项', link: '/web/http-misc' }
    ]
  },
  {
    text: 'Pwn',
    items: [
      { text: '栈溢出基础', link: '/pwn/stack-basic' },
      { text: 'ROP 与 ret2libc', link: '/pwn/rop-ret2libc' },
      { text: '栈保护绕过', link: '/pwn/stack-protection' },
      { text: '格式化字符串', link: '/pwn/format-string' },
      { text: '堆利用', link: '/pwn/heap' },
      { text: '越界与整数问题', link: '/pwn/oob-integer' },
      { text: '地址泄露与 PIE/ASLR 绕过', link: '/pwn/leak-pie' },
      { text: '沙箱绕过', link: '/pwn/sandbox-seccomp' },
      { text: '内核 Pwn 入门', link: '/pwn/kernel' },
      { text: '特殊环境', link: '/pwn/special-env' }
    ]
  },
  {
    text: 'Reverse',
    items: [
      { text: '常规静态分析', link: '/reverse/static-analysis' },
      { text: '汇编阅读与手工还原', link: '/reverse/asm-reading' },
      { text: '动态调试', link: '/reverse/dynamic-debug' },
      { text: '.NET 与 Java 反编译', link: '/reverse/dotnet-java' },
      { text: '脚本类逆向', link: '/reverse/script-reverse' },
      { text: 'Android 逆向', link: '/reverse/android' },
      { text: '加壳与脱壳', link: '/reverse/unpacking' },
      { text: '算法识别', link: '/reverse/algorithm-id' },
      { text: '虚拟机与自定义字节码', link: '/reverse/vm-bytecode' },
      { text: '反调试与反虚拟机', link: '/reverse/anti-debug' }
    ]
  },
  {
    text: 'Crypto',
    items: [
      { text: '古典密码', link: '/crypto/classical' },
      { text: '编码与哈希基础', link: '/crypto/encoding-hash' },
      { text: '对称加密', link: '/crypto/symmetric' },
      { text: 'RSA 攻击', link: '/crypto/rsa' },
      { text: '离散对数与 DH', link: '/crypto/discrete-log' },
      { text: '椭圆曲线 ECC', link: '/crypto/ecc' },
      { text: '格密码与 Coppersmith', link: '/crypto/lattice' },
      { text: '随机数预测', link: '/crypto/prng' },
      { text: '流密码与异或', link: '/crypto/stream' },
      { text: '哈希攻击与数论杂项', link: '/crypto/hash-numbertheory' }
    ]
  },
  {
    text: 'Misc',
    items: [
      { text: '编码与古典杂烩', link: '/misc/encoding-mix' },
      { text: '图片隐写', link: '/misc/image-stego' },
      { text: '音频与视频隐写', link: '/misc/audio-video' },
      { text: '文档隐写与宏', link: '/misc/document-macro' },
      { text: '压缩包与文件格式', link: '/misc/archive' },
      { text: '编程题与交互题', link: '/misc/programming' },
      { text: '游戏题', link: '/misc/game' },
      { text: 'OSINT、二维码与杂项', link: '/misc/osint' }
    ]
  },
  {
    text: '取证',
    items: [
      { text: '流量分析', link: '/forensics/pcap' },
      { text: '内存取证', link: '/forensics/memory' },
      { text: '磁盘镜像与文件系统', link: '/forensics/disk' },
      { text: 'Windows 系统取证', link: '/forensics/windows' },
      { text: 'Linux 系统取证', link: '/forensics/linux' },
      { text: '恶意样本基础分析', link: '/forensics/malware' },
      { text: '日志与时间线', link: '/forensics/logs-timeline' },
      { text: '移动 / 浏览器 / 云取证', link: '/forensics/mobile-cloud' }
    ]
  },
  {
    text: '元流程',
    items: [
      { text: '开场起手', link: '/meta/opening' },
      { text: '卡住怎么办', link: '/meta/stuck' }
    ]
  }
]

export default defineConfig({
  lang: 'zh-CN',
  title: 'CTF 知识字典',
  description: '按题型识别的 CTF 知识体系与解题优先级',
  // GitHub Pages 的项目站点部署在 /<repo>/ 下，构建时由 CI 传入；
  // 本地 dev / build 不设该变量，默认根路径。
  base: process.env.CTF_WIKI_BASE || '/',
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: ['**/superpowers/**', '**/README.md'],

  markdown: {
    lineNumbers: true
  },

  themeConfig: {
    nav: [
      { text: '首页', link: '/' },
      { text: '题型总表', link: '/map' },
      { text: 'Web', link: '/web/sql-injection' },
      { text: 'Pwn', link: '/pwn/stack-basic' },
      { text: 'Reverse', link: '/reverse/static-analysis' },
      { text: 'Crypto', link: '/crypto/classical' },
      { text: 'Misc', link: '/misc/encoding-mix' },
      { text: '取证', link: '/forensics/pcap' }
    ],

    sidebar: DIRS,

    outline: { level: [2, 3], label: '本页导航' },

    search: {
      provider: 'local',
      options: {
        detailedView: true,
        miniSearch: {
          options: {
            tokenize: (text: string) =>
              Array.from(
                new Intl.Segmenter('zh', { granularity: 'word' }).segment(text)
              )
                .filter((s: any) => s.isWordLike)
                .map((s: any) => String(s.segment).toLowerCase())
          },
          searchOptions: {
            fuzzy: 0.2,
            prefix: true,
            boost: { title: 4, text: 2 }
          }
        },
        translations: {
          button: { buttonText: '搜索知识库', buttonAriaLabel: '搜索知识库' },
          modal: {
            displayDetails: '显示详细列表',
            resetButtonTitle: '重置搜索',
            backButtonTitle: '关闭搜索',
            noResultsText: '没有结果',
            footer: {
              selectText: '选择',
              selectKeyAriaLabel: '回车',
              navigateText: '切换',
              navigateUpKeyAriaLabel: '上箭头',
              navigateDownKeyAriaLabel: '下箭头',
              closeText: '关闭',
              closeKeyAriaLabel: 'Esc'
            }
          }
        }
      }
    },

    docFooter: { prev: '上一篇', next: '下一篇' },
    returnToTopLabel: '回到顶部',
    sidebarMenuLabel: '目录',
    darkModeSwitchLabel: '主题',
    lightModeSwitchTitle: '切换到浅色模式',
    darkModeSwitchTitle: '切换到深色模式',
    lastUpdatedText: '最后更新',
    outlineTitle: '本页导航'
  }
})
