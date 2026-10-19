// Nuclei Templates 补源模块（v2.0.3 第二聚合源）：projectdiscovery/nuclei-templates 的
// http/cves + http/vulnerabilities 检测模板 → EXP 模型候选。
// 覆盖近六年热门 CVE 的 N-day PoC 与大量护网季披露的国内厂商漏洞（用友/泛微/致远/海康等）。
// YAML 用正则字段抽取（模板 schema 高度一致：id/info.severity/info.classification.cve-id/tags），
// 只做索引层映射，每条带 raw 链接指回模板原文。

import { truncateAtSentence, vulnTypeFromCwe } from './classify.mjs';
import { MAX_CODE_BYTES, NVD_CVE_URL, NUCLEI_RAW_URL } from './sources.mjs';

const CVE_IN_TEXT = /\bCVE-\d{4}-\d{4,7}\b/gi;

// CVE 升序比较（年份, 序号），与 classify.mjs primaryCveKey 同口径
const cveAscCompare = (a, b) => {
  const [yearA, seqA] = a.slice(4).split('-').map(Number);
  const [yearB, seqB] = b.slice(4).split('-').map(Number);
  return yearA - yearB || seqA - seqB;
};

const yamlBlock = (text, key) => {
  // 取顶层或 info:/classification: 缩进块内的 key 值（单行字符串或行内数组）
  const lines = text.split(/\r?\n/);
  let baseIndent = null;
  for (let i = 0; i < lines.length; i += 1) {
    const match = lines[i].match(/^(\s*)-? ?([a-z-]+):\s*(.*)$/);
    if (!match) continue;
    const indent = match[1].length;
    if (match[2] === key && (baseIndent === null || indent === baseIndent)) {
      baseIndent = indent;
      const value = match[3].trim();
      if (value && value !== '|' && value !== '>') return value.replace(/^["']|["']$/g, '');
      // 块标量（| / >）→ 取后续更深缩进的行拼接首行
      for (let j = i + 1; j < lines.length; j += 1) {
        const blockMatch = lines[j].match(/^\s{2,}(\S.*)$/);
        if (!blockMatch) break;
        return blockMatch[1].trim();
      }
      return '';
    }
  }
  return '';
};

const extractTemplateFields = (text, path) => {
  const id = yamlBlock(text, 'id');
  if (!id) return null;
  const name = yamlBlock(text, 'name') || id;
  // 治理 A4：模板 description 原文（折叠标量/|- 块两种形态），作 EXP 描述主体
  const description = (yamlBlock(text, 'description') || '').replace(/\s*\n\s*/g, ' ').trim();
  const severityRaw = (yamlBlock(text, 'severity') || 'info').toLowerCase();
  const severity = ['critical', 'high', 'medium', 'low'].includes(severityRaw) ? severityRaw : 'low';
  const tags = (yamlBlock(text, 'tags') || '')
    .split(',')
    .map(tag => tag.trim().toLowerCase())
    .filter(Boolean);
  const cweMatch = text.match(/cwe-id[s]?:\s*\n?(?:\s*-\s*)?(CWE-\d+)/i);
  const cwe = cweMatch ? cweMatch[1].toUpperCase() : '';
  // 治理 A8：CVE 提取分两路记账——cve-id 字段（info.classification 结构化权威）与全文扫描
  // （正文/reference 链接，会把别家 CVE 也扫进来）
  const cveIdFieldValues = (yamlBlock(text, 'cve-id') || '')
    .split(/[\s,]+/)
    .map(value => value.replace(/[[\]]/g, '').trim().toUpperCase())
    .filter(value => /^CVE-\d{4}-\d{4,7}$/.test(value));
  const textMatches = [...new Set(
    [...text.matchAll(CVE_IN_TEXT)]
      .map(match => match[0].replace(/[[\]]/g, '').trim().toUpperCase())
      .filter(value => /^CVE-\d{4}-\d{4,7}$/.test(value)),
  )];
  let cves = [...new Set([...cveIdFieldValues, ...textMatches])];
  // 治理 A8 多 CVE 跨产品污染防护：权威集 = cve-id 字段 ∪ name 字符串中的 CVE。
  // 提取列表超出权威集时只保留交集（CrushFTP CVE-2025-31161 模板 reference 里的
  // Rapid7 博文 URL 带出 Next.js CVE-2025-29927 的根因）；cve-id 字段缺失且 name 无 CVE
  // 时保留全部，但主键仍取与模板 id 同源的 CVE（下方排序）。
  const nameCves = [...new Set([...(name.match(CVE_IN_TEXT) || [])].map(match => match[0].toUpperCase()))];
  const authoritativeCves = new Set([...cveIdFieldValues, ...nameCves]);
  if (authoritativeCves.size && cves.some(cve => !authoritativeCves.has(cve))) {
    cves = cves.filter(cve => authoritativeCves.has(cve));
  }
  // 主键排序：与模板 id 同源的 CVE 排 vulnerabilityIds[0]，其余按（年份, 序号）升序保证可复现
  const idCve = (id.match(CVE_IN_TEXT)?.[0] || '').toUpperCase();
  cves.sort((a, b) => {
    if (a === idCve && b !== idCve) return -1;
    if (b === idCve && a !== idCve) return 1;
    return cveAscCompare(a, b);
  });
  // 分类路径段：http/cves/<year>/... 或 http/vulnerabilities/<vendor>/...
  const segments = path.split('/');
  const category = segments.includes('cves') ? 'cves' : segments.includes('vulnerabilities') ? 'vulnerabilities' : 'other';
  const vendor = category === 'vulnerabilities' ? segments[segments.indexOf('vulnerabilities') + 1] || '' : '';
  return { id, path, name, description, severity, tags, cwe, cves, category, vendor, rawYaml: text };
};

// 记录 → EXP 模型候选（bizKey + sanitizeExploit 入参形状）
export const buildNucleiModels = (templates, { cveMap = new Map() } = {}) => {
  const pairs = [];
  const skipped = { noId: 0 };
  templates.forEach(template => {
    if (!template.id) {
      skipped.noId += 1;
      return;
    }
    const primaryCve = template.cves[0] || '';
    const nvd = primaryCve ? cveMap.get(primaryCve) : undefined;
    const tagTypeRules = [
      // 治理 A8：lfi/fileread 比含认证语义的规则更特异——phpMyAdmin CVE-2018-12613 这类
      // "认证后 LFI"模板同时命中 unauth 与 lfi，须按特异面归类为 path-traversal 而非 auth-bypass
      [/fileread|path-?traversal|\blfi\b/, 'path-traversal'],
      [/rce|exec|code-?injection|command-?injection/, 'rce'],
      [/sqli|sql-?injection/, 'sqli'],
      [/deserial/, 'deserialization'],
      [/lpe|priv-?esc/, 'lpe'],
      [/upload/, 'file-upload'],
      [/xss/, 'xss'],
      [/xxe/, 'xxe'],
      [/ssrf/, 'ssrf'],
      [/ssti/, 'ssti'],
      [/unauth|auth-?bypass/, 'auth-bypass'],
    ];
    const tagHit = tagTypeRules.find(([pattern]) => pattern.test(template.tags.join(' ')));
    const vulnType = vulnTypeFromCwe(template.cwe) || (tagHit ? tagHit[1] : 'uncategorized');
    const products = nvd?.products?.length ? nvd.products : (template.vendor ? [template.vendor] : []);
    const severity = template.severity;
    const publishedAt = primaryCve ? primaryCve.slice(4, 8) : String(new Date().getFullYear());
    const references = [
      NUCLEI_RAW_URL(template.path),
      primaryCve ? NVD_CVE_URL(primaryCve) : '',
    ].filter(Boolean);
    // 模板 YAML 原文即 POC：nuclei 直接跑；raw 里的 HTTP 请求可复用到 Burp Repeater
    const yamlBody = template.rawYaml.length > MAX_CODE_BYTES
      ? `${template.rawYaml.slice(0, MAX_CODE_BYTES)}\n\n... [模板已截断，完整内容见原始链接]`
      : template.rawYaml;
    pairs.push({
      bizKey: `nuclei:${template.id}`,
      exploit: {
        name: template.name.slice(0, 200),
        description: truncateAtSentence(template.description || template.name, 300),
        vulnType,
        affected: products.join('; '),
        severity,
        publishedAt,
        vulnerabilityIds: [
          ...template.cves.map(value => ({ type: 'CVE', value })),
        ],
        exploitCode: [{
          title: 'Nuclei 检测模板（nuclei -t 直接运行；HTTP 请求可复用于 Burp）',
          language: 'yaml',
          code: yamlBody,
        }],
        prerequisites: `本条目来自 Nuclei 公开模板聚合索引，未经平台人工验证；模板为检测/验证向量，武器化利用需结合目标环境评估。`,
        references,
        tags: [...new Set(['nuclei', 'format:poc', ...template.tags, template.vendor].filter(Boolean))].slice(0, 8),
        attribution: { source: 'Nuclei Templates', author: 'ProjectDiscovery', license: 'MIT' },
        source: 'nuclei',
        sourceRef: `nuclei-${template.id}`,
      },
    });
  });
  return { pairs, skipped };
};

export { extractTemplateFields };
