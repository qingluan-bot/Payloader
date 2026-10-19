// Exploit-DB 主源模块：RFC4180 CSV 解析、六年窗口过滤、CVE 提取、EXP 数据模型映射。
// 纯函数（网络下载在 CLI 编排层），便于 fixture 单测。
// v2.0.2 治理：克隆去重（title+date+platform+type 同键保留最小 EDB-ID）、描述真实化
// （NVD 英文描述 > CSV description 原文）、CWE/分档映射提公共模块、products[] 归一、canonicalKey。

import { truncateAtSentence, primaryCveKey, resolveVulnType, severityFromScore, vulnTypeFromCwe } from './classify.mjs';
import { deriveProducts } from './products.mjs';
import { EDB_CSV_COLUMNS, EDB_FILE_URL, EDB_PAGE_URL, GHSA_URL, MAX_CODE_BYTES, NVD_CVE_URL } from './sources.mjs';

const CVE_PATTERN = /\bCVE-\d{4}-\d{4,7}\b/gi;

// EDB 正文文件扩展名 → 语言标注（脚本类优先，文本类按内容形态在调用方细分）
const EDB_LANGUAGE_BY_EXT = {
  py: 'python', rb: 'ruby', php: 'php', jsp: 'java', java: 'java', pl: 'perl',
  cs: 'csharp', c: 'c', cpp: 'cpp', sh: 'bash', ps1: 'powershell', asp: 'asp',
  aspx: 'aspx', go: 'go', lua: 'lua', war: 'binary', txt: 'text',
};

// 正文 → { segments, format }（format 供调用方打形态 tag；用户优先级：可执行脚本 > HTTP POC > curl > 说明文本）
export const codeSegmentsFromContent = (content, fileName, sourcePageUrl) => {
  if (!content || !content.trim()) return { segments: [], format: '' };
  const ext = String(fileName || '').split('.').pop()?.toLowerCase() || 'txt';
  const language = EDB_LANGUAGE_BY_EXT[ext] || 'text';
  const truncated = content.length > MAX_CODE_BYTES;
  const body = truncated ? `${content.slice(0, MAX_CODE_BYTES)}\n\n... [正文超 ${Math.round(MAX_CODE_BYTES / 1024)}KB 已截断，完整内容见原始来源]` : content;
  const isScript = language !== 'text';
  const looksHttp = /^(GET|POST|PUT|HEAD|OPTIONS|PATCH) \/|HTTP\/\d/i.test(content.trimStart());
  const looksCurl = /^\s*curl\s/m.test(content);
  const format = isScript ? 'script' : looksHttp ? 'http-poc' : looksCurl ? 'curl' : 'text';
  const title = isScript
    ? `完整利用脚本（${language}，可直接执行）`
    : looksHttp ? 'HTTP POC（请求报文可直接粘贴 Burp Repeater）'
      : looksCurl ? '利用命令（curl 形态）' : '利用说明 / POC 正文';
  const segment = { title, language, code: body };
  if (sourcePageUrl && truncated) segment.description = `原文：${sourcePageUrl}`;
  return { segments: [segment], format };
};

// ---- RFC4180 CSV 解析（引号字段、双引号转义、引号内换行/逗号）----
export const parseCsv = text => {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (inQuotes) {
      if (char === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
      continue;
    }
    if (char === '"') {
      inQuotes = true;
      continue;
    }
    if (char === ',') {
      row.push(field);
      field = '';
      continue;
    }
    if (char === '\n') {
      row.push(field);
      field = '';
      rows.push(row);
      row = [];
      continue;
    }
    if (char === '\r') continue;
    field += char;
  }
  if (field !== '' || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter(r => r.length > 1 || (r[0] ?? '').trim() !== '');
};

// CSV 文本 → 记录数组（表头逐列名映射 + 列契约校验，上游结构变化显式报错而非静默错映射）
export const parseEdbCsv = text => {
  const rows = parseCsv(text);
  if (!rows.length) throw new Error('Exploit-DB CSV 为空');
  const header = rows[0];
  const mismatch = EDB_CSV_COLUMNS.find((column, index) => header[index] !== column);
  if (mismatch) {
    throw new Error(`Exploit-DB CSV 表头变化（第 ${EDB_CSV_COLUMNS.indexOf(mismatch) + 1} 列期望 "${mismatch}"，实得 "${header[EDB_CSV_COLUMNS.indexOf(mismatch)]}"），请核对 sources.mjs 列契约`);
  }
  return rows.slice(1).map(cells => {
    const record = {};
    EDB_CSV_COLUMNS.forEach((column, index) => {
      record[column] = (cells[index] ?? '').trim();
    });
    return record;
  });
};

export { resolveVulnType, severityFromScore, vulnTypeFromCwe };

const extractCves = record => {
  const found = new Set();
  String(record.codes || '').split(';').forEach(code => {
    const value = code.trim().toUpperCase();
    if (/^CVE-\d{4}-\d{4,7}$/.test(value)) found.add(value);
  });
  for (const match of String(record.description || '').matchAll(CVE_PATTERN)) {
    found.add(match[0].toUpperCase());
  }
  return [...found];
};

export { extractCves };

const truncateName = value => (value.length > 200 ? `${value.slice(0, 197)}...` : value);

// ---- 克隆去重（治理 A3）：(title, date_published, platform, type) 完全相同视为克隆，
// 组内保留最小 EDB-ID。date_published 在键内 ⇒ 组成员窗口判定一致，不存在跨窗口误删。----
export const dedupeCloneRecords = records => {
  const groups = new Map();
  for (const record of records) {
    // 畸形行（缺日期/缺 id）不参与克隆判定，交由 buildExploitModels 既有 skip 口径处理
    if (!record.id || !/^\d{4}-\d{2}-\d{2}$/.test(record.date_published)) continue;
    const key = [record.description, record.date_published, record.platform, record.type].join('\u0000');
    const group = groups.get(key);
    if (!group) groups.set(key, [record]);
    else group.push(record);
  }
  let dropped = 0;
  const kept = new Set();
  for (const group of groups.values()) {
    if (group.length === 1) continue;
    const sorted = [...group].sort((a, b) => Number(a.id) - Number(b.id));
    sorted.slice(1).forEach(record => kept.add(record));
    dropped += sorted.length - 1;
  }
  return { records: records.filter(record => !kept.has(record)), dropped };
};

// ---- prerequisites 变量化（治理 A4）：按 EDB type/platform 生成真实利用条件，禁免责话术 ----
const EDB_PREREQUISITES_BY_TYPE = [
  ['local', record => `利用条件：需已获得目标主机（平台 ${record.platform || 'unspecified'}）的本地访问与代码执行入口，条目为本地漏洞利用。`],
  ['remote', record => `利用条件：需网络可达目标服务（平台 ${record.platform || 'unspecified'}）并按正文指定目标主机与端口；目标版本须在受影响区间。`],
  ['webapps', record => `利用条件：需能访问目标 Web 应用（平台 ${record.platform || 'unspecified'}），请求路径与参数点以正文为准。`],
  ['dos', record => `利用条件：需能将构造的输入送达目标服务（平台 ${record.platform || 'unspecified'}），触发拒绝服务后目标功能不可用。`],
  ['shellcodes', record => `利用条件：需嵌入既有利用链在目标架构（平台 ${record.platform || 'unspecified'}）执行，地址与偏移须按目标版本重算。`],
  ['papers', () => '利用条件：本条目为技术分析文献，无直接可执行利用，需按文中步骤复现。'],
  ['hardware', record => `利用条件：需物理接触或网络可达目标硬件设备（平台 ${record.platform || 'unspecified'}）。`],
];

const edbPrerequisites = record => {
  const hit = EDB_PREREQUISITES_BY_TYPE.find(([type]) => type === record.type);
  return (hit ? hit[1](record) : `利用条件：需按正文复现（类型 ${record.type || 'unclassified'}，平台 ${record.platform || 'unspecified'}）。`)
    + `${record.verified === '1' ? '条目经 Exploit-DB 校验标记 verified。' : '条目未经 Exploit-DB 校验标记，适用性需自行核对。'}`;
};

// NVD 映射条目：{ score, severity, cwe, products, description }
// contents：正文 Map（file 列路径 → 正文文本）；命中时注入 exploitCode（真实脚本/POC 正文）
// 记录 → EXP 模型候选（bizKey + sanitizeExploit 入参形状）。
// sinceISO：date_published 窗口下界（含）；返回 { pairs, skipped: {outOfWindow, malformed, clones} }
export const buildExploitModels = (records, { cveMap = new Map(), ghsaMap = new Map(), contents = new Map(), sinceISO = '2020-09-01' } = {}) => {
  const { records: dedupedRecords, dropped } = dedupeCloneRecords(records);
  const pairs = [];
  const skipped = { outOfWindow: 0, malformed: 0, clones: dropped };
  dedupedRecords.forEach(record => {
    const edbId = record.id;
    const publishedAt = record.date_published;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(publishedAt) || !edbId) {
      skipped.malformed += 1;
      return;
    }
    if (publishedAt < sinceISO) {
      skipped.outOfWindow += 1;
      return;
    }
    const cves = extractCves(record);
    const primaryCve = cves[0] || '';
    const nvd = primaryCve ? cveMap.get(primaryCve) : undefined;
    const cwe = nvd?.cwe || '';
    const ghsa = primaryCve ? ghsaMap.get(primaryCve) || '' : '';
    // 描述真实化（A4）：NVD 英文描述优先，否则 CSV description 列原文（完整句截断）
    const description = (nvd?.description && truncateAtSentence(nvd.description))
      || truncateAtSentence(record.description || `EDB-${edbId}`);
    const vulnType = resolveVulnType({ cwe, description: `${record.description}\n${description}` });
    const cpeProducts = nvd?.products?.length ? nvd.products : [record.platform].filter(Boolean);
    const products = deriveProducts({ cpeProducts, name: record.description, description, affected: cpeProducts.join('; ') });
    const severity = nvd ? severityFromScore(nvd.score) : 'unknown';
    const tags = [record.type, record.platform, cwe ? `cwe-${cwe.replace(/^CWE-/, '')}` : '', record.verified === '1' ? 'verified' : '']
      .map(tag => tag.toLowerCase())
      .filter(Boolean);
    const references = [
      EDB_PAGE_URL(edbId),
      record.file ? EDB_FILE_URL(record.file) : '',
      primaryCve ? NVD_CVE_URL(primaryCve) : '',
      ghsa ? GHSA_URL(ghsa) : '',
      record.source_url || '',
    ].filter(Boolean);
    // 正文注入：有真实脚本/POC 正文时替换"见原始来源"式空代码段，并打形态 tag（script/http-poc/curl/text）
    const content = contents.get(record.file);
    const contentResult = content
      ? codeSegmentsFromContent(content, record.file, EDB_PAGE_URL(edbId))
      : { segments: [], format: '' };
    const exploitCode = contentResult.segments.length
      ? contentResult.segments
      : [];
    const contentTags = contentResult.format ? [`format:${contentResult.format}`] : [];
    const vulnerabilityIds = [
      { type: 'EDB-ID', value: edbId },
      ...cves.map(value => ({ type: 'CVE', value })),
      ...(ghsa ? [{ type: 'GHSA', value: ghsa }] : []),
    ];
    pairs.push({
      bizKey: `edb:${edbId}`,
      exploit: {
        name: truncateName(record.description || `EDB-${edbId}`),
        description,
        vulnType,
        affected: cpeProducts.join('; '),
        severity,
        publishedAt,
        vulnerabilityIds,
        exploitCode,
        prerequisites: edbPrerequisites(record),
        references,
        tags: [...tags, ...contentTags],
        attribution: { source: 'Exploit-DB', author: record.author || '', license: 'GPL-2.0' },
        source: 'exploit-db',
        sourceRef: `edb-${edbId}`,
        products,
        canonicalKey: primaryCveKey(vulnerabilityIds),
      },
    });
  });
  return { pairs, skipped };
};
