// 存储条目清洗（纯函数，自 data-store.mjs 机械迁移）：settings/payload/tool/nav 四域 sanitize 族
// 与 makeId/cloneValue 工具。文本归一依赖 text-quality，零 db 与 IO 依赖，独立可测。

import { publicProjectRoute } from './project-attribution.mjs';
import { createUlid } from './ulid.mjs';
import {
  dedupeCommandEntries,
  ensureDisplayTextObject,
  isObject,
  isPlatform,
  localizeKnownToolEnglish,
  normalizeList,
  normalizeText,
  scrubLowQualityEnglishContent,
  scrubRetiredEdrContent,
  textValue,
  toText,
} from './text-quality.mjs';

const projectUrl = publicProjectRoute;

const defaultSettings = {
  siteTitle: { zh: 'PAYLOADER', en: 'PAYLOADER' },
  siteSubtitle: { zh: '渗透测试辅助平台', en: 'Pentest Assistance Platform' },
  browserTitle: { zh: 'Payloader - 渗透测试辅助平台', en: 'Payloader - Pentest Assistance Platform' },
  logoIcon: '⚡',
  logoUrl: '',
  projectUrl,
  // CTF 解题模块默认关闭：公开发布场景下含 proxy/portscan 端点，需管理员在后台显式开启。
  ctfEnabled: false,
};
const json = value => JSON.stringify(value ?? null);
const parseJson = value => {
  if (typeof value !== 'string' || value.length === 0) return null;
  return JSON.parse(value);
};

const protectedExternalUrl = 'https://xss.icu/';
const protectedXssToolId = 'xss-platform';
const systemToolIds = new Set([protectedXssToolId]);

const sanitizeLogoUrl = value => {
  const logoUrl = String(value ?? '').trim();
  return /^\/uploads\/logo\/logo-[a-zA-Z0-9.-]+\.(png|jpe?g|webp)$/.test(logoUrl) ? logoUrl : '';
};

const makeId = (prefix, fallback = 'item') => {
  const source = String(fallback || 'item')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  const suffix = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${source || 'item'}-${suffix}`;
};

export const sanitizeSettings = value => {
  const candidate = isObject(value) ? value : {};
  const merged = { ...defaultSettings, ...candidate };
  return {
    siteTitle: normalizeText(merged.siteTitle),
    siteSubtitle: normalizeText(merged.siteSubtitle),
    browserTitle: normalizeText(merged.browserTitle),
    logoIcon: String(merged.logoIcon ?? defaultSettings.logoIcon).trim() || defaultSettings.logoIcon,
    logoUrl: sanitizeLogoUrl(merged.logoUrl),
    projectUrl,
    ctfEnabled: merged.ctfEnabled === true,
  };
};

const executionKindValues = new Set(['bypass', 'control']);
const executionEffectivenessLevels = new Set(['A', 'B', 'C']);

const sanitizePayloadExecution = value => {
  const candidate = isObject(value) ? value : {};
  const sanitized = {
    title: ensureDisplayTextObject(candidate.title),
    command: String(candidate.command ?? '').trim(),
    description: candidate.description == null ? undefined : ensureDisplayTextObject(candidate.description),
    syntaxBreakdown: normalizeList(candidate.syntaxBreakdown).map(sanitizeSyntaxPart).filter(Boolean),
    platform: isPlatform(candidate.platform) ? candidate.platform : 'all',
    requiresAdmin: Boolean(candidate.requiresAdmin),
  };
  // 变体分类字段（2026-10 WAF 审查批次）：kind 区分真绕过与受控样例，effectiveness 标注
  // 现代 WAF 有效性档位。仅合法值输出，存量条目 JSON 形态保持不变。
  if (executionKindValues.has(candidate.kind)) sanitized.kind = candidate.kind;
  if (executionEffectivenessLevels.has(candidate.effectiveness)) sanitized.effectiveness = candidate.effectiveness;
  return sanitized;
};

const sanitizeSyntaxPart = value => {
  if (!isObject(value)) return null;
  const part = String(value.part ?? '').trim();
  if (!part) return null;
  return {
    part,
    explanation: ensureDisplayTextObject(value.explanation),
    type: typeof value.type === 'string' ? value.type : undefined,
  };
};

const sanitizeAttackChainStep = value => {
  if (!isObject(value)) return null;
  const payload = String(value.payload ?? '').trim();
  const step = {
    title: ensureDisplayTextObject(value.title),
    description: ensureDisplayTextObject(value.description),
  };
  if (payload) step.payload = payload;
  return step;
};

const sanitizeStoredPublicPayload = value => {
  const candidate = isObject(value) ? value : {};
  const name = ensureDisplayTextObject(candidate.name);
  const id = typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('payload', name.zh || name.en || 'payload');
  return {
    id,
    name,
    description: ensureDisplayTextObject(candidate.description),
    category: ensureDisplayTextObject(candidate.category),
    subCategory: candidate.subCategory == null ? undefined : ensureDisplayTextObject(candidate.subCategory),
    tags: normalizeList(candidate.tags).map(String).map(item => item.trim()).filter(Boolean),
    prerequisites: normalizeList(candidate.prerequisites).map(ensureDisplayTextObject),
    execution: dedupeCommandEntries(normalizeList(candidate.execution).map(sanitizePayloadExecution).filter(item => item.command)),
    analysis: candidate.analysis == null ? undefined : ensureDisplayTextObject(candidate.analysis),
    opsecTips: normalizeList(candidate.opsecTips).map(ensureDisplayTextObject),
    wafBypass: dedupeCommandEntries(normalizeList(candidate.wafBypass).map(sanitizePayloadExecution).filter(item => item.command)),
    attackChain: normalizeList(candidate.attackChain).map(sanitizeAttackChainStep).filter(Boolean),
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(Boolean),
    // 治理 M5：CVE/产品双通道预关联的公开 EXP（仅 id/name/source 三个安全字段透传）
    relatedExploits: normalizeList(candidate.relatedExploits)
      .map(item => isObject(item) && typeof item.id === 'string' && /^EXP-[0-9A-HJKMNP-TV-Z]{26}$/.test(item.id)
        ? { id: item.id, name: (typeof item.name === 'string' ? item.name : item.name == null ? '' : JSON.stringify(item.name)).slice(0, 200), source: String(item.source ?? 'curated') }
        : null)
      .filter(Boolean)
      .slice(0, 3),
    tutorial: isObject(candidate.tutorial) ? {
      overview: ensureDisplayTextObject(candidate.tutorial.overview),
      vulnerability: ensureDisplayTextObject(candidate.tutorial.vulnerability),
      exploitation: ensureDisplayTextObject(candidate.tutorial.exploitation),
      mitigation: ensureDisplayTextObject(candidate.tutorial.mitigation),
      difficulty: ['beginner', 'intermediate', 'advanced', 'expert'].includes(candidate.tutorial.difficulty) ? candidate.tutorial.difficulty : 'beginner',
    } : undefined,
  };
};

export const sanitizePayload = value => {
  const scrubbed = scrubLowQualityEnglishContent(scrubRetiredEdrContent(value).value).value;
  const candidate = isObject(scrubbed) ? scrubbed : {};
  const name = ensureDisplayTextObject(candidate.name);
  const execution = normalizeList(candidate.execution).map(sanitizePayloadExecution).filter(item => item.command);
  return {
    id: typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('payload', name.zh || name.en || 'payload'),
    name,
    description: ensureDisplayTextObject(candidate.description),
    category: ensureDisplayTextObject(candidate.category),
    subCategory: candidate.subCategory == null ? undefined : ensureDisplayTextObject(candidate.subCategory),
    tags: normalizeList(candidate.tags).map(String).map(item => item.trim()).filter(Boolean),
    prerequisites: normalizeList(candidate.prerequisites).map(ensureDisplayTextObject),
    execution: execution.length ? execution : [{ title: toText('Command'), command: String(candidate.command ?? 'echo TODO').trim() || 'echo TODO', platform: 'all' }],
    analysis: candidate.analysis == null ? undefined : ensureDisplayTextObject(candidate.analysis),
    opsecTips: normalizeList(candidate.opsecTips).map(ensureDisplayTextObject),
    wafBypass: normalizeList(candidate.wafBypass).map(sanitizePayloadExecution).filter(item => item.command),
    attackChain: normalizeList(candidate.attackChain).map(sanitizeAttackChainStep).filter(Boolean),
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(Boolean),
    relatedExploits: normalizeList(candidate.relatedExploits)
      .map(item => isObject(item) && typeof item.id === 'string' && /^EXP-[0-9A-HJKMNP-TV-Z]{26}$/.test(item.id)
        ? { id: item.id, name: (typeof item.name === 'string' ? item.name : item.name == null ? '' : JSON.stringify(item.name)).slice(0, 200), source: String(item.source ?? 'curated') }
        : null)
      .filter(Boolean)
      .slice(0, 3),
    tutorial: isObject(candidate.tutorial) ? {
      overview: ensureDisplayTextObject(candidate.tutorial.overview),
      vulnerability: ensureDisplayTextObject(candidate.tutorial.vulnerability),
      exploitation: ensureDisplayTextObject(candidate.tutorial.exploitation),
      mitigation: ensureDisplayTextObject(candidate.tutorial.mitigation),
      difficulty: ['beginner', 'intermediate', 'advanced', 'expert'].includes(candidate.tutorial.difficulty) ? candidate.tutorial.difficulty : 'beginner',
    } : undefined,
  };
};

const sanitizeToolCommandItem = value => {
  const candidate = isObject(value) ? value : {};
  const command = String(candidate.command ?? '').trim();
  if (!command) return null;
  let name = localizeKnownToolEnglish(candidate.name);
  const description = localizeKnownToolEnglish(candidate.description);
  if (isObject(name) && !name.zh.trim() && !name.en.trim()) {
    const fallbackLabel = textValue(description).trim() || command.split(/\r?\n/, 1)[0].trim() || 'Command';
    name = localizeKnownToolEnglish(toText(fallbackLabel));
  }
  return {
    name,
    command,
    description,
    syntaxBreakdown: normalizeList(candidate.syntaxBreakdown).map(sanitizeSyntaxPart).filter(Boolean),
    examples: normalizeList(candidate.examples).map(localizeKnownToolEnglish),
    platform: isPlatform(candidate.platform) ? candidate.platform : 'all',
  };
};

export const sanitizeTool = value => {
  const candidate = isObject(value) ? value : {};
  const name = localizeKnownToolEnglish(candidate.name);
  const commands = normalizeList(candidate.commands).map(sanitizeToolCommandItem).filter(Boolean);
  const id = typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('tool', name.zh || name.en || 'tool');
  const externalUrl = candidate.externalUrl === protectedExternalUrl && systemToolIds.has(id) ? protectedExternalUrl : '';
  const description = localizeKnownToolEnglish(candidate.description);
  const category = localizeKnownToolEnglish(candidate.category);
  const installation = candidate.installation == null ? undefined : localizeKnownToolEnglish(candidate.installation);
  const item = {
    id,
    name,
    description,
    category,
    commands: commands.length ? commands : (externalUrl ? [] : [{ name: toText('Command'), command: 'echo TODO', description: toText('TODO'), platform: 'all' }]),
    installation,
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(Boolean),
  };
  if (externalUrl) {
    item.externalUrl = externalUrl;
    item.systemLocked = true;
  }
  // 治理 D 时效标注：active（现役，缺省）| archived（已归档/改名，配 replacedBy 指向等价替代）
  const status = String(candidate.status ?? '').trim().toLowerCase();
  if (['active', 'archived'].includes(status)) item.status = status;
  const replacedBy = String(candidate.replacedBy ?? '').trim();
  if (replacedBy) item.replacedBy = replacedBy;
  return item;
};

export const sanitizeNavItem = value => {
  const candidate = isObject(value) ? value : {};
  const name = normalizeText(candidate.name);
  const item = {
    id: typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('nav', name.zh || name.en || 'node'),
    name,
  };
  if (typeof candidate.icon === 'string' && candidate.icon.trim()) item.icon = candidate.icon.trim();
  if (typeof candidate.payloadId === 'string' && candidate.payloadId.trim()) item.payloadId = candidate.payloadId.trim();
  if (typeof candidate.toolId === 'string' && candidate.toolId.trim()) item.toolId = candidate.toolId.trim();
  const children = normalizeList(candidate.children).map(sanitizeNavItem);
  if (children.length) item.children = children;
  return item;
};

// ---- EXP 漏洞利用库（v2.0.2）：结构化字段机器可读优先，供 AI 检索与公开 API 消费 ----

export const exploitSeverities = ['critical', 'high', 'medium', 'low', 'unknown'];

const sanitizeVulnerabilityId = value => {
  if (!isObject(value)) return null;
  const type = String(value.type ?? '').trim().toUpperCase();
  const idValue = String(value.value ?? '').trim();
  if (!type || !idValue) return null;
  return { type, value: idValue };
};

const sanitizeExploitCodeSegment = value => {
  if (!isObject(value)) return null;
  const code = String(value.code ?? '').trim();
  if (!code) return null;
  const segment = {
    title: String(value.title ?? '').trim() || '利用代码',
    language: String(value.language ?? '').trim().toLowerCase() || 'text',
    code,
  };
  const description = String(value.description ?? '').trim();
  if (description) segment.description = description;
  return segment;
};

const sanitizeAttribution = value => {
  const candidate = isObject(value) ? value : {};
  const source = String(candidate.source ?? '').trim();
  const author = String(candidate.author ?? '').trim();
  const license = String(candidate.license ?? '').trim();
  const attribution = {};
  if (source) attribution.source = source;
  if (author) attribution.author = author;
  if (license) attribution.license = license;
  return Object.keys(attribution).length ? attribution : undefined;
};

export const sanitizeExploit = value => {
  const candidate = isObject(value) ? value : {};
  const name = String(candidate.name ?? '').trim();
  // 稳定 ID：缺省生成 EXP-<ULID>（时间有序可排序）；已有条目保留原 id（导入/自定义兼容）
  const item = {
    id: typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : `EXP-${createUlid()}`,
    name: name || '未命名漏洞利用',
    description: String(candidate.description ?? '').trim(),
    vulnType: String(candidate.vulnType ?? '').trim().toLowerCase() || 'uncategorized',
    affected: String(candidate.affected ?? '').trim(),
    severity: exploitSeverities.includes(candidate.severity) ? candidate.severity : 'unknown',
    publishedAt: String(candidate.publishedAt ?? '').trim(),
    vulnerabilityIds: normalizeList(candidate.vulnerabilityIds).map(sanitizeVulnerabilityId).filter(Boolean),
    exploitCode: normalizeList(candidate.exploitCode).map(sanitizeExploitCodeSegment).filter(Boolean),
    prerequisites: String(candidate.prerequisites ?? '').trim(),
    // 参考链接协议白名单：上游聚合数据是"非管理员录入"入口，仅收 http(s)，阻断 javascript: 等注入面
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(item => /^https?:\/\//i.test(item)),
    tags: normalizeList(candidate.tags).map(String).map(item => item.trim()).filter(Boolean),
  };
  // 分层来源字段（v2.0.3 聚合管线）：source 标上游来源（如 exploit-db），无 source 即精选/手工层；
  // sourceRef 存上游主键（如 edb-12345）供聚合管线幂等复用；treePath 为分类挂载位置（大类/类型/叶子 id）。
  const source = String(candidate.source ?? '').trim();
  const sourceRef = String(candidate.sourceRef ?? '').trim();
  const treePath = String(candidate.treePath ?? '').trim();
  if (source) item.source = source;
  if (sourceRef) item.sourceRef = sourceRef;
  if (treePath) item.treePath = treePath;
  // 治理 A5/A6 归一字段：products 为机器可读产品数组（API product 过滤主通道），
  // canonicalKey 为主 CVE 编号（跨源同漏洞分组）。非空才写，精选层可缺省。
  const products = normalizeList(candidate.products).map(value => String(value ?? '').trim()).filter(Boolean).slice(0, 12);
  if (products.length) item.products = products;
  const canonicalKey = String(candidate.canonicalKey ?? '').trim();
  if (canonicalKey) item.canonicalKey = canonicalKey;
  const attribution = sanitizeAttribution(candidate.attribution);
  if (attribution) item.attribution = attribution;
  return item;
};

export const sanitizeExploitNode = value => {
  const candidate = isObject(value) ? value : {};
  const name = normalizeText(candidate.name);
  const item = {
    id: typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('expnode', name.zh || name.en || 'node'),
    name,
  };
  if (typeof candidate.icon === 'string' && candidate.icon.trim()) item.icon = candidate.icon.trim();
  if (typeof candidate.exploitId === 'string' && candidate.exploitId.trim()) item.exploitId = candidate.exploitId.trim();
  // 治理 B：叶子多值挂载（多条同叶 EXP 全量引用，树点击直达取 exploitIds[0]）
  const exploitIds = normalizeList(candidate.exploitIds).map(value => String(value ?? '').trim()).filter(value => /^EXP-[0-9A-HJKMNP-TV-Z]{26}$/.test(value));
  if (exploitIds.length) item.exploitIds = exploitIds;
  const children = normalizeList(candidate.children).map(sanitizeExploitNode);
  if (children.length) item.children = children;
  return item;
};

const cloneValue = value => parseJson(json(value));


// ---- canonical 分组键（与 scripts/exp-corpus/classify.mjs 同语义，server 侧权威）：
// CVE 编号按（年份, 序号）数值升序取首个；无合法 CVE 返回空串 ----
export const primaryCveKey = vulnerabilityIds => {
  const cves = (Array.isArray(vulnerabilityIds) ? vulnerabilityIds : [])
    .map(item => (item && item.type === 'CVE' ? String(item.value ?? '').trim().toUpperCase() : ''))
    .filter(value => /^CVE-\d{4}-\d{4,7}$/.test(value));
  if (!cves.length) return '';
  cves.sort((a, b) => {
    const [yearA, seqA] = a.slice(4).split('-').map(Number);
    const [yearB, seqB] = b.slice(4).split('-').map(Number);
    return yearA - yearB || seqA - seqB;
  });
  return cves[0];
};

export {
  cloneValue,
  defaultSettings,
  makeId,
  projectUrl,
  protectedExternalUrl,
  protectedXssToolId,
  sanitizeAttackChainStep,
  sanitizeLogoUrl,
  sanitizePayloadExecution,
  sanitizeStoredPublicPayload,
  sanitizeSyntaxPart,
  sanitizeToolCommandItem,
  systemToolIds,
};
