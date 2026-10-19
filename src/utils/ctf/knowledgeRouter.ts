// CTF 知识 AI 检索路由（批次 B）：四元组路由注册表 + 纯函数查询。
// 目标是让 AI/检索层一次定位「知识条目 + 速查卡 + 工具卡」：payload 库（server 种子库 payloads 表）、
// 工具库（tools 表）、ctfCheatSheets 速查条目、文件取证工作台渲染工具卡（ff-card-*）。
// 零依赖纯函数，不引分词库；全部 id 由 tests/knowledge-router.test.mjs 构建时校验存在性，id 悬挂即测试红。

export interface KnowledgeRoute {
  /** 技术域唯一标识 */
  domain: string;
  /** 双语域名 */
  label: { zh: string; en: string };
  /**
   * 该域知识的主导载体提示：payload = 载荷知识条目为主，tool = 工具命令集为主。
   * ids 允许混挂 payload/tool 两类库条目（取证类域常以工具命令集为主体），校验只查存在性。
   */
  knowledge: { kind: 'payload' | 'tool'; ids: string[] };
  /** ctfCheatSheets 四域速查条目 id */
  cheatEntryIds: string[];
  /** 文件取证工作台渲染工具卡 id（src/components/ctf 下 id="ff-card-*"） */
  toolCardIds: string[];
  /** 中文检索关键词（含同义词），宁准勿滥——这是给 AI 的路由表，噪声即事故 */
  keywords: string[];
}

// 14 技术域注册表。id 全部对照 server/default-seed.sqlite 与 src/components/ctf 渲染卡源码。
export const knowledgeRoutes: KnowledgeRoute[] = [
  {
    domain: 'sqli',
    label: { zh: 'SQL 注入', en: 'SQL Injection' },
    knowledge: {
      kind: 'payload',
      ids: ['sqli-union-query', 'sqli-error-based', 'sqli2-time-based-blind-sqli', 'sqli-boolean-blind', 'sqli-stacked-mysql', 'sqlmap'],
    },
    cheatEntryIds: ['web-sqli-union', 'web-sqli-time-based'],
    toolCardIds: [],
    keywords: ['sql 注入', 'union select', '联合注入', '报错注入', '盲注', '堆叠注入', '宽字节', 'order by', 'information_schema'],
  },
  {
    domain: 'rce',
    label: { zh: '命令执行与 RCE', en: 'Command Injection & RCE' },
    knowledge: {
      kind: 'payload',
      ids: ['rce-command-injection', 'cmdi2-command-separators', 'cmdi2-base64', 'cmdi2-hex', 'rce-htaccess', 'bizlogic-rce'],
    },
    cheatEntryIds: ['web-command-injection'],
    toolCardIds: [],
    keywords: ['命令注入', '命令执行', 'rce', '管道符', '分号绕过', '反引号', '无回显', '命令拼接'],
  },
  {
    domain: 'upload',
    label: { zh: '文件上传', en: 'File Upload' },
    knowledge: {
      kind: 'payload',
      ids: ['file-upload-declared-type-mismatch', 'file-upload-double-write-extension', 'file-upload-null-byte-filename', 'file-upload-signature-content-mismatch', 'file-upload-ntfs-ads-name', 'rce-file-upload'],
    },
    cheatEntryIds: [],
    toolCardIds: [],
    keywords: ['文件上传', '一句话木马', 'content-type', '双写扩展名', '空字节', '魔数', '解析漏洞', 'htaccess', '上传绕过'],
  },
  {
    domain: 'lfi',
    label: { zh: '文件包含与路径穿越', en: 'LFI & Path Traversal' },
    knowledge: {
      kind: 'payload',
      ids: ['lfi-traversal-marker-read-boundary', 'lfi-filter-source-read-boundary', 'lfi-log-marker-read-boundary', 'fileup-lfi-filter-transform-boundary', 'file-traversal-posix-normalization'],
    },
    cheatEntryIds: ['web-lfi-traversal'],
    toolCardIds: [],
    keywords: ['文件包含', '目录穿越', '路径遍历', 'lfi', 'php://filter', '伪协议', '日志注入', 'php://input'],
  },
  {
    domain: 'ssrf',
    label: { zh: 'SSRF', en: 'SSRF' },
    knowledge: {
      kind: 'payload',
      ids: ['ssrf-basic', 'ssrf-bypass', 'ssrf-gopher', 'ssrf-cloud-aws', 'ssrf-dns-rebinding', 'ssrf-redis'],
    },
    cheatEntryIds: ['web-ssrf-basic'],
    toolCardIds: [],
      keywords: ['ssrf', '内网探测', '169.254.169.254', '云元数据', 'gopher', 'dns 重绑定', 'dns rebinding', 'redis 未授权'],
  },
  {
    domain: 'ssti',
    label: { zh: 'SSTI', en: 'SSTI' },
    knowledge: {
      kind: 'payload',
      ids: ['ssti-jinja2', 'ssti-tornado', 'ssti-erb', 'ssti2-twig-php', 'flask-jinja-evaluation-boundary'],
    },
    cheatEntryIds: ['web-ssti-jinja2'],
    toolCardIds: [],
    keywords: ['ssti', '模板注入', 'jinja2', 'twig', 'smarty', '{{7*7}}', '__mro__', '沙箱逃逸', 'freemarker'],
  },
  {
    domain: 'deserialization',
    label: { zh: '反序列化', en: 'Deserialization' },
    knowledge: {
      kind: 'payload',
      ids: ['rce-deserialize', 'rce-deserialize-php', 'rce-deserialize-java', 'nosql2-python-pickle', 'auth-shiro-rememberme-deserialization', 'nosql2-jndi-log4shell'],
    },
    cheatEntryIds: [],
    toolCardIds: [],
    keywords: ['反序列化', 'pop 链', 'gadget', 'pickle', 'shiro', 'log4j', 'jndi', 'ysoserial', 'commons collections'],
  },
  {
    domain: 'xss-frontend',
    label: { zh: 'XSS 与前端', en: 'XSS & Frontend' },
    knowledge: {
      kind: 'payload',
      ids: ['xss-reflected', 'xss-stored', 'xss-dom', 'xss-csp-bypass', 'xss2-dom-clobbering', 'csrf-basic'],
    },
    cheatEntryIds: ['web-xss-reflected'],
    toolCardIds: [],
    keywords: ['xss', '反射型', '存储型', 'dom clobbering', 'csp 绕过', 'cookie 外带', 'csrf', '点击劫持'],
  },
  {
    domain: 'archive-forensics',
    label: { zh: '压缩包取证', en: 'Archive Forensics' },
    knowledge: {
      kind: 'tool',
      ids: ['ctf-forensics-tools', 'ctf-forensics-advanced'],
    },
    cheatEntryIds: [],
    toolCardIds: ['ff-card-zipbrute', 'ff-card-rar', 'ff-card-embedded', 'ff-card-chunks', 'ff-card-repair'],
    keywords: ['压缩包', '伪加密', 'zip 爆破', 'rar', '明文攻击', 'crc32', 'zip slip', '加密标志位', '归档'],
  },
  {
    domain: 'image-stego',
    label: { zh: '图片隐写', en: 'Image Steganography' },
    knowledge: {
      kind: 'tool',
      ids: ['steganography-tools', 'ctf-forensics-advanced'],
    },
    cheatEntryIds: [],
    toolCardIds: ['ff-card-preview', 'ff-card-bitplanes', 'ff-card-channels', 'ff-card-imageops', 'ff-card-imagestego', 'ff-card-jpegstego', 'ff-card-steghide'],
    keywords: ['图片隐写', 'lsb', '位平面', 'steghide', 'outguess', '盲水印', 'exif', 'dct', 'jpeg 隐写'],
  },
  {
    domain: 'audio-stego',
    label: { zh: '音频隐写', en: 'Audio Steganography' },
    knowledge: {
      kind: 'tool',
      ids: ['steganography-tools', 'ctf-forensics-tools'],
    },
    cheatEntryIds: [],
    toolCardIds: ['ff-card-audio'],
    keywords: ['音频隐写', '频谱图', 'morse', '摩斯电码', 'sstv', 'deepsound', 'wav 隐写', '音频倒放'],
  },
  {
    domain: 'traffic-analysis',
    label: { zh: '流量分析', en: 'Traffic Analysis' },
    knowledge: {
      kind: 'tool',
      ids: ['wireshark-tshark', 'ctf-network-tools', 'network-forensics-advanced'],
    },
    cheatEntryIds: [],
    toolCardIds: [],
    keywords: ['流量分析', 'pcap', 'wireshark', 'tshark', 'usb 流量', 'icmp', 'http 导出', '数据流还原'],
  },
  {
    domain: 'codec-classical',
    label: { zh: '编码与古典密码', en: 'Encoding & Classical Ciphers' },
    knowledge: {
      kind: 'tool',
      ids: ['ctf-crypto-tools', 'ctf-misc-tools'],
    },
    cheatEntryIds: [],
    toolCardIds: [],
    keywords: ['base64', 'base32', '古典密码', '凯撒', '维吉尼亚', 'vigenere', '摩斯密码', '栅栏', '零宽字符', '佛曰'],
  },
  {
    domain: 'rsa-number-theory',
    label: { zh: 'RSA 与数论', en: 'RSA & Number Theory' },
    knowledge: {
      kind: 'tool',
      ids: ['rsactftool', 'ctf-crypto-tools'],
    },
    cheatEntryIds: [],
    toolCardIds: [],
    keywords: ['rsa', '共模攻击', '维纳', 'wiener', '费马分解', 'dp 泄露', '因数分解', 'factordb', '格密码'],
  },
];

/**
 * 按关键词命中为查询打分并返回前 topN 个技术域。
 * 匹配语义分两路：纯 ASCII 关键词按词边界命中（防「rce」子串误配 source/read 等噪声，宁准勿滥）；
 * 含中文的关键词保持子串包含（中文无词边界可依）。query 与关键词先 trim + lowercase 归一。
 * 排序：命中关键词数降序 → 命中关键词总字符长度降序 → 注册顺序稳定。
 */
const PURE_ASCII_KEYWORD = /^[\x20-\x7e]+$/;

const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const matchesKeyword = (query: string, keyword: string): boolean => {
  if (!PURE_ASCII_KEYWORD.test(keyword)) return query.includes(keyword);
  return new RegExp(`(?<![a-z0-9])${escapeRegExp(keyword)}(?![a-z0-9])`).test(query);
};

export function routeKnowledgeQuery(query: string, topN = 3): KnowledgeRoute[] {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return [];
  const scored: { route: KnowledgeRoute; score: number; weight: number }[] = [];
  for (const route of knowledgeRoutes) {
    let score = 0;
    let weight = 0;
    for (const keyword of route.keywords) {
      if (matchesKeyword(normalized, keyword)) {
        score += 1;
        weight += keyword.length;
      }
    }
    if (score > 0) scored.push({ route, score, weight });
  }
  scored.sort((a, b) => b.score - a.score || b.weight - a.weight);
  return scored.slice(0, Math.max(0, topN)).map(item => item.route);
}
