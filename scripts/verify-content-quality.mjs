import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const defaultSeedFile = resolve(projectRoot, 'server', 'default-seed.sqlite');
const defaultRuntimeFile = resolve(projectRoot, 'data', 'payloader.sqlite');
const maxSamples = 50;
const validPlatforms = new Set(['all', 'windows', 'linux']);
const genericTutorialText = new Set([
  '\u9009\u62e9\u5bf9\u5e94payload\u6d4b\u8bd5',
  '\u9009\u62e9\u7ed5\u8fc7\u6280\u672f',
]);
const intentionalOrphanIds = new Set([
  'sqli-waf-bypass',
  'xss-filter-bypass',
  'xss-csp-bypass',
  'ssrf-bypass',
  'csrf-bypass',
  'csrf-token-bypass',
  'csrf-referer-bypass',
  'redirect-bypass',
  'jwt-none-alg',
  'jwt-none-algo',
  'jwt-weak-secret',
  'jwt-kid-injection',
  'jwt-jku-spoofing',
]);
const payloadRefAliases = new Map([
  ['sqli2-', 'sqli2-quick-reference'],
  ['sqli2--ext', 'sqli2-error-based-ext'],
  ['xss2-', 'xss2-basic-script-element'],
  ['xss2--ext', 'xss2-event-handler-ext'],
  ['cmdi2--ext', 'cmdi2-quote-tokenization-ext'],
  ['auth2-', 'auth2-username-enumeration'],
  ['auth2--ext', 'auth2-cors-subdomain-ext'],
  ['nosql2-', 'nosql2-type-confusion'],
  ['nosql2--ext', 'nosql2-ldap-filter-ext'],
  ['inject2-', 'inject2-graphql-introspection'],
  ['inject2--ext', 'inject2-parser-differential-ext'],
  ['bizlogic-', 'bizlogic-coupon-enumeration'],
  ['httpbypass-', 'httpbypass-admin-path-normalization'],
  ['api2-', 'api2-inline-fragment-authz'],
  ['ssrf2-', 'ssrf2-build-file-exposure'],
  ['biz-price-tamper', 'biz-payment-tamper'],
  ['jwt-none-alg', 'jwt-none-attack'],
  ['jwt-none-algo', 'jwt-none-attack'],
  ['jwt-weak-secret', 'jwt-secret-bruteforce'],
  ['jwt-kid-injection', 'jwt-key-confusion'],
  ['jwt-jku-spoofing', 'jwt-jku-x5u-injection'],
]);
export const categoryBranchExceptions = new Map([
  // rce-file-upload 历史纠偏已由 subCategory 声明组机制接管（挂"上传解析绕过"），例外表清空
]);

export const PAYLOAD_BRANCH_RULES = Object.freeze([
  { payloadId: 'ai2-mixed-case-bypass', branchId: 'ai-security' },
  { payloadId: 'ai2-virtual-scenario-bypass', branchId: 'ai-security' },
  { payloadId: 'nosql2-ognl-struts2', branchId: 'framework-vulns' },
  { payloadId: 'nosql2-python-pickle', branchId: 'rce' },
  { payloadId: 'nosql2-ruby-marshal', branchId: 'rce' },
  { payloadId: 'inject2-clickjacking-163-lines', branchId: 'clickjacking' },
  { payloadId: 'inject2-open-redirect-184-lines', branchId: 'web-redirect' },
  { payloadId: 'inject2-http-request-smuggling-request', branchId: 'web-smuggling' },
  { payloadId: 'inject2-prototype-pollution-prototype', branchId: 'prototype-pollution' },
  { payloadId: 'inject2-web-cache-deception-211-lines', branchId: 'web-cache' },
  { payloadId: 'inject2-wkhtmltopdf-ssrf', branchId: 'ssrf' },
  { payloadId: 'inject2-wkhtmltopdf-gopher-ssrf', branchId: 'ssrf' },
  { payloadId: 'inject2-puppeteer-headless-chrome-ssrf', branchId: 'ssrf' },
  { payloadId: 'inject2-weasyprint-ssrf', branchId: 'ssrf' },
  { payloadId: 'inject2-prince-xml-ssrf', branchId: 'ssrf' },
]);

export const categoryBranches = new Map([
  ['SQL/NoSQL\u6ce8\u5165', 'sqli'],
  ['SQL/NoSQL Injection', 'sqli'],
  ['XSS\u8de8\u7ad9\u811a\u672c', 'xss'],
  ['XSS Cross-Site Scripting', 'xss'],
  ['SSRF\u670d\u52a1\u7aef\u8bf7\u6c42\u4f2a\u9020', 'ssrf'],
  ['Server-side request forgery (SSRF)', 'ssrf'],
  ['RCE\u8fdc\u7a0b\u4ee3\u7801\u6267\u884c', 'rce'],
  ['RCE Remote Code Execution', 'rce'],
  ['\u70b9\u51fb\u52ab\u6301', 'clickjacking'],
  ['Clickjacking', 'clickjacking'],
  ['\u5f00\u653e\u91cd\u5b9a\u5411', 'web-redirect'],
  ['Open Redirect', 'web-redirect'],
  ['\u8bf7\u6c42\u8d70\u79c1', 'web-smuggling'],
  ['Request Smuggling', 'web-smuggling'],
  ['\u539f\u578b\u94fe\u6c61\u67d3', 'prototype-pollution'],
  ['Prototype Pollution', 'prototype-pollution'],
  ['\u7f13\u5b58\u4e0eCDN\u5b89\u5168', 'web-cache'],
  ['Cache & CDN Security', 'web-cache'],
  ['\u6846\u67b6\u6f0f\u6d1e', 'framework-vulns'],
  ['Framework Vulnerabilities', 'framework-vulns'],
  ['AI\u5b89\u5168', 'ai-security'],
  ['AI Security', 'ai-security'],
  // 全量归类批（2026-09）：补齐拆分/遗留 payload 分类到 web 树分支
  ['XXE\u5b9e\u4f53\u6ce8\u5165', 'xxe'],
  ['XXE Injection', 'xxe'],
  ['SSTI\u6a21\u677f\u6ce8\u5165', 'ssti'],
  ['SSTI Injection', 'ssti'],
  ['LFI/RFI\u6587\u4ef6\u5305\u542b', 'lfi-rfi'],
  ['LFI/RFI File Inclusion', 'lfi-rfi'],
  ['CSRF\u8de8\u7ad9\u8bf7\u6c42\u4f2a\u9020', 'csrf'],
  ['CSRF', 'csrf'],
  ['API\u5b89\u5168', 'api-security'],
  ['API Security', 'api-security'],
  ['\u8ba4\u8bc1\u6f0f\u6d1e', 'auth-vulns'],
  ['Authentication Vulnerabilities', 'auth-vulns'],
  ['\u6587\u4ef6\u6f0f\u6d1e', 'file-vulns'],
  ['File Vulnerabilities', 'file-vulns'],
  ['\u4e1a\u52a1\u903b\u8f91\u6f0f\u6d1e', 'biz-logic'],
  ['Business Logic Vulnerabilities', 'biz-logic'],
  ['JWT\u5b89\u5168', 'jwt-security'],
  ['JWT Security', 'jwt-security'],
  ['WebSocket \u5b89\u5168', 'websocket-security'],
  ['WebSocket Security', 'websocket-security'],
  ['Web \u7f13\u5b58\u5b89\u5168', 'web-cache'],
  ['Web Cache Security', 'web-cache'],
  ['CORS \u5b89\u5168', 'cors-security'],
  ['CORS Security', 'cors-security'],
  ['HTTP\u54cd\u5e94\u5206\u5272', 'http-response-splitting'],
  ['HTTP Response Splitting', 'http-response-splitting'],
  ['Host Header\u5b89\u5168', 'host-header-security'],
  ['Host Header Security', 'host-header-security'],
  ['\u62d2\u7edd\u670d\u52a1', 'denial-of-service'],
  ['Denial of Service', 'denial-of-service'],
  ['\u6587\u4ef6\u4e0e\u6e90\u7801\u6cc4\u9732', 'file-vulns'],
  ['File and Source Disclosure', 'file-vulns'],
  ['Web \u6e17\u900f\u5de5\u5177', 'sqli'],
  ['Web Pentest Tools', 'sqli'],
  // 内网树分支
  ['\u6743\u9650\u63d0\u5347\u5de5\u5177', 'privilege-escalation'],
  ['Privilege Escalation Tools', 'privilege-escalation'],
  ['Active Directory \u5b89\u5168\u8fb9\u754c', 'ad-attack'],
  ['Active Directory Security Boundary', 'ad-attack'],
  ['Exchange \u5de5\u5177', 'exchange-attack'],
  ['Exchange Tools', 'exchange-attack'],
  ['\u51ed\u8bc1\u5ba1\u8ba1\u5de5\u5177', 'credential-theft'],
  ['Credential Audit Tools', 'credential-theft'],
  ['\u6301\u4e45\u5316\u63a7\u5236\u4e0e\u68c0\u6d4b', 'persistence'],
  ['Persistence Control and Detection', 'persistence'],
  ['\u6301\u4e45\u5316\u5de5\u5177', 'persistence'],
  ['Persistence Tools', 'persistence'],
  ['\u51ed\u8bc1\u4fdd\u62a4\u4e0e\u5ba1\u8ba1', 'credential-theft'],
  ['Credential Protection and Auditing', 'credential-theft'],
  ['\u8fdc\u7a0b\u7ba1\u7406\u4e0e\u6a2a\u5411\u8fb9\u754c', 'lateral-movement'],
  ['Remote Management and Lateral Boundary', 'lateral-movement'],
  ['\u7ec8\u7aef\u9632\u62a4\u4e0e\u9065\u6d4b\u5b8c\u6574\u6027', 'nav-cat-evasion-powershell'],
  ['Endpoint Defense and Telemetry Integrity', 'nav-cat-evasion-powershell'],
  ['\u7ec8\u7aef\u5b89\u5168\u5de5\u5177', 'nav-cat-evasion-powershell'],
  ['Endpoint Security Tools', 'nav-cat-evasion-powershell'],
]);

const isObject = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const asList = value => Array.isArray(value) ? value : [];
const displayText = value => {
  if (typeof value === 'string') return value;
  if (isObject(value)) return value.zh || value.en || '';
  return '';
};
const hasHan = value => /\p{Script=Han}/u.test(String(value || ''));
const normalizedName = value => displayText(value).trim().toLocaleLowerCase('en-US');
const stableIssueKey = item => JSON.stringify(item);
const sorted = items => [...items].sort((left, right) => stableIssueKey(left).localeCompare(stableIssueKey(right), 'en'));
const issueGroup = (items, extra = {}) => ({
  count: items.length,
  items: sorted(items).slice(0, maxSamples),
  ...extra,
});

const walkStrings = (value, visit, path = []) => {
  if (typeof value === 'string') {
    visit(value, path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkStrings(item, visit, [...path, String(index)]));
    return;
  }
  if (isObject(value)) {
    Object.entries(value).forEach(([key, item]) => walkStrings(item, visit, [...path, key]));
  }
};

const walkI18n = (value, visit, path = []) => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkI18n(item, visit, [...path, String(index)]));
    return;
  }
  if (!isObject(value)) return;
  if (typeof value.en === 'string') visit(value, path);
  Object.entries(value).forEach(([key, item]) => walkI18n(item, visit, [...path, key]));
};

const sourceFragmentMatch = command => {
  const match = String(command || '').match(/\r?\n\s*syntaxBreakdown\s*:\s*\[/);
  return match ? 'internal-syntax-breakdown-property' : '';
};

const collectCommandIssues = (snapshot, replacementCharacter, sourceFragment, emptyCommand, invalidPlatform) => {
  for (const payload of asList(snapshot.payloads)) {
    const entries = asList(payload.execution);
    if (!entries.length) {
      emptyCommand.push({ resource: 'payload', id: payload.id, path: 'execution' });
    }
    for (const area of ['execution', 'wafBypass']) {
      asList(payload[area]).forEach((entry, index) => {
        const path = `${area}.${index}`;
        const command = typeof entry?.command === 'string' ? entry.command : '';
        if (!command.trim()) emptyCommand.push({ resource: 'payload', id: payload.id, path: `${path}.command` });
        const fragment = sourceFragmentMatch(command);
        if (fragment) sourceFragment.push({ resource: 'payload', id: payload.id, path: `${path}.command`, signature: fragment });
        if (entry?.platform != null && !validPlatforms.has(entry.platform)) {
          invalidPlatform.push({ resource: 'payload', id: payload.id, path: `${path}.platform`, value: entry.platform });
        }
      });
    }
  }
  for (const tool of asList(snapshot.tools)) {
    const entries = asList(tool.commands);
    if (!entries.length && !tool.externalUrl) emptyCommand.push({ resource: 'tool', id: tool.id, path: 'commands' });
    entries.forEach((entry, index) => {
      const path = `commands.${index}`;
      const command = typeof entry?.command === 'string' ? entry.command : '';
      if (!command.trim()) emptyCommand.push({ resource: 'tool', id: tool.id, path: `${path}.command` });
      const fragment = sourceFragmentMatch(command);
      if (fragment) sourceFragment.push({ resource: 'tool', id: tool.id, path: `${path}.command`, signature: fragment });
      if (entry?.platform != null && !validPlatforms.has(entry.platform)) {
        invalidPlatform.push({ resource: 'tool', id: tool.id, path: `${path}.platform`, value: entry.platform });
      }
    });
  }
  for (const [resource, items] of [
    ['payload', snapshot.payloads],
    ['tool', snapshot.tools],
    ['payload-navigation', snapshot.navigation],
    ['tool-navigation', snapshot.toolNavigation],
  ]) {
    for (const item of asList(items)) {
      walkStrings(item, (value, path) => {
        if (value.includes('\uFFFD')) replacementCharacter.push({
          resource,
          id: item.id,
          path: path.join('.'),
          value: value.slice(0, 180),
        });
      });
    }
  }
  if (snapshot.settings) {
    walkStrings(snapshot.settings, (value, path) => {
      if (value.includes('\uFFFD')) replacementCharacter.push({
        resource: 'metadata',
        id: 'settings',
        path: path.join('.'),
        value: value.slice(0, 180),
      });
    });
  }
};

const collectNavigation = (nodes, placements, references, path = []) => {
  for (const node of asList(nodes)) {
    const nextPath = [...path, node.id || '<missing-id>'];
    if (node.payloadId) {
      references.push({ kind: 'payload', id: node.payloadId, nodeId: node.id, path: nextPath.join('/') });
      placements.set(payloadRefAliases.get(node.payloadId) || node.payloadId, nextPath);
    }
    if (node.toolId) references.push({ kind: 'tool', id: node.toolId, nodeId: node.id, path: nextPath.join('/') });
    collectNavigation(node.children, placements, references, nextPath);
  }
};

const expectedBranch = payload => {
  if (categoryBranchExceptions.has(payload.id)) return categoryBranchExceptions.get(payload.id);
  const explicit = PAYLOAD_BRANCH_RULES.find(rule => rule.payloadId === payload.id);
  if (explicit) return explicit.branchId;
  const category = displayText(payload.category).trim();
  return categoryBranches.get(category) || '';
};

const branchFromPath = path => (path[0] === 'web' || path[0] === 'intranet') && path.length > 1 ? path[1] : (path[0] || '');

// ---- 治理 M3 防复发规则（2026-09-28 三库审计落位）----

// payload 英文描述三族模板句（迁移流水账），回归即阻断
const EN_TEMPLATE_PATTERNS = [
  /preserves the original reproducible technique commands while restricting execution to a written, reversible, isolated lab authorization/,
  /^Routes every source line belonging to .* into one focused card with explicit/,
  /^Isolates commands from the mixed source into a .* validation card using synthetic principals, a read-only marker, and server-side evidence\.$/,
];

// payload id 主键形态：小写字母数字连字符，禁尾部/双连字符（sqli2-、cmdi2--ext 类残缺 id 曾直通）
const VALID_PAYLOAD_ID = /^[a-z0-9]+(-[a-z0-9]+)*$/;

// installation 损坏四正则 + 已知坏串黑名单（驼峰断裂/flag 拆散/排版残留/pip 模块拆散）
const INSTALLATION_BAD_PATTERNS = [
  /github\.com\/[A-Za-z0-9._~:/?#%@$&*+=-]* [A-Za-z]/,           // URL 内空格（驼峰断裂主形态：Ghost Pack/Sec Lists…）
  /(?:^|\s)(?:curl|wget)\s+-[a-z]\s+[A-Z][a-z]?[A-Z]/, // flag 拆散（curl -s SfL…）
  /(?:^|\s)#\s/,                                // markdown 注释残留
  /pip3?\s+install\s+[A-Z][a-z]+\s+[A-Z][a-z]+/,   // pip 模块名拆散（pip install Git Hacker）
];
const INSTALLATION_BAD_EXACT = ['Downloadbinary', 'Built-in on mac OS', 'ROA Dtools', 'Graph Q Lmap', 'the Harvester'];

// 已知非法命令参数（照抄即错黑名单，按工具 id 前缀匹配）
const ILLEGAL_FLAG_RULES = [
  { match: toolId => toolId.startsWith('gobuster'), pattern: /(^|\s)-do\s/ },
];

const collectGovernanceIssues = snapshot => {
  const enTemplateDescription = [];
  const malformedPayloadId = [];
  const suspiciousInstallation = [];
  const illegalCommandFlag = [];
  for (const item of asList(snapshot?.payloads)) {
    const en = String(item?.description?.en ?? '');
    if (EN_TEMPLATE_PATTERNS.some(pattern => pattern.test(en))) {
      enTemplateDescription.push({ id: item.id, sample: en.slice(0, 80) });
    }
    if (typeof item?.id === 'string' && !VALID_PAYLOAD_ID.test(item.id)) {
      malformedPayloadId.push({ id: item.id });
    }
  }
  for (const item of asList(snapshot?.tools)) {
    for (const lang of ['en', 'zh']) {
      const text = String(item?.installation?.[lang] ?? '');
      if (!text) continue;
      const bad = INSTALLATION_BAD_PATTERNS.some(pattern => pattern.test(text)) || INSTALLATION_BAD_EXACT.some(marker => text.includes(marker));
      if (bad) {
        suspiciousInstallation.push({ id: item.id, lang, sample: text.slice(0, 80) });
        break;
      }
    }
    for (const command of asList(item?.commands)) {
      const text = String(command?.command ?? '');
      const rule = ILLEGAL_FLAG_RULES.find(candidate => candidate.match(item.id));
      if (rule && rule.pattern.test(text)) {
        illegalCommandFlag.push({ id: item.id, sample: text.slice(0, 80) });
      }
    }
  }
  return { enTemplateDescription, malformedPayloadId, suspiciousInstallation, illegalCommandFlag };
};

export const auditSnapshot = (input, options = {}) => {
  const snapshot = {
    payloads: asList(input?.payloads),
    tools: asList(input?.tools),
    navigation: asList(input?.navigation),
    toolNavigation: asList(input?.toolNavigation),
    settings: isObject(input?.settings) ? input.settings : null,
  };
  const replacementCharacter = [];
  const sourceFragment = [];
  const emptyCommand = [];
  const invalidPlatform = [];
  collectCommandIssues(snapshot, replacementCharacter, sourceFragment, emptyCommand, invalidPlatform);
  const governance = collectGovernanceIssues(snapshot);

  const payloadIds = new Set(snapshot.payloads.map(item => item?.id).filter(Boolean));
  const toolIds = new Set(snapshot.tools.map(item => item?.id).filter(Boolean));
  const placements = new Map();
  const references = [];
  collectNavigation(snapshot.navigation, placements, references);
  collectNavigation(snapshot.toolNavigation, placements, references);
  const danglingNavigation = references.flatMap(reference => {
    if (reference.kind === 'payload') {
      const resolved = payloadRefAliases.get(reference.id) || reference.id;
      return payloadIds.has(reference.id) || payloadIds.has(resolved) ? [] : [reference];
    }
    return toolIds.has(reference.id) ? [] : [reference];
  });

  const referencedPayloadIds = new Set(
    references
      .filter(reference => reference.kind === 'payload')
      .map(reference => payloadRefAliases.get(reference.id) || reference.id),
  );
  const orphanPayloads = snapshot.payloads
    .filter(payload => payload?.id && !referencedPayloadIds.has(payload.id))
    .map(payload => ({
      id: payload.id,
      name: displayText(payload.name),
      category: displayText(payload.category),
      intentional: intentionalOrphanIds.has(payload.id),
      custom: payload.id.startsWith('custom-'),
    }));

  const englishContainsHan = [];
  for (const [resource, items] of [
    ['payload', snapshot.payloads],
    ['tool', snapshot.tools],
    ['payload-navigation', snapshot.navigation],
    ['tool-navigation', snapshot.toolNavigation],
  ]) {
    for (const item of items) {
      walkI18n(item, (value, path) => {
        if (hasHan(value.en)) englishContainsHan.push({ resource, id: item.id, path: [...path, 'en'].join('.') });
      });
    }
  }
  if (snapshot.settings) {
    walkI18n(snapshot.settings, (value, path) => {
      if (hasHan(value.en)) englishContainsHan.push({ resource: 'metadata', id: 'settings', path: [...path, 'en'].join('.') });
    });
  }
  const englishAffectedResources = new Set(englishContainsHan.map(item => `${item.resource}:${item.id}`)).size;

  const duplicateNames = [];
  for (const [resource, items] of [['payload', snapshot.payloads], ['tool', snapshot.tools]]) {
    const groups = new Map();
    for (const item of items) {
      const name = normalizedName(item.name);
      if (!name) continue;
      if (!groups.has(name)) groups.set(name, []);
      groups.get(name).push(item.id);
    }
    for (const [name, ids] of groups) {
      if (ids.length > 1) duplicateNames.push({ resource, name, ids: [...ids].sort() });
    }
  }

  const genericTutorials = snapshot.payloads.flatMap(payload => {
    const exploitation = displayText(payload?.tutorial?.exploitation).trim();
    return genericTutorialText.has(exploitation) ? [{ id: payload.id, exploitation }] : [];
  });

  const categoryTreeMismatch = snapshot.payloads.flatMap(payload => {
    const expected = expectedBranch(payload);
    const path = placements.get(payload.id);
    if (!expected || !path) return [];
    const actual = branchFromPath(path);
    return actual === expected ? [] : [{ id: payload.id, expectedBranch: expected, actualBranch: actual, path: path.join('/') }];
  });

  const withWafVariants = snapshot.payloads.filter(payload => asList(payload.wafBypass).some(entry => String(entry?.command || '').trim())).length;
  const totalPayloads = snapshot.payloads.length;
  const blocking = {
    databaseIntegrity: issueGroup([]),
    invalidJson: issueGroup([]),
    replacementCharacter: issueGroup(replacementCharacter),
    sourceFragment: issueGroup(sourceFragment),
    emptyCommand: issueGroup(emptyCommand),
    invalidPlatform: issueGroup(invalidPlatform),
    danglingNavigation: issueGroup(danglingNavigation),
    enTemplateDescription: issueGroup(governance.enTemplateDescription),
    malformedPayloadId: issueGroup(governance.malformedPayloadId),
    suspiciousInstallation: issueGroup(governance.suspiciousInstallation),
    illegalCommandFlag: issueGroup(governance.illegalCommandFlag),
  };
  const reporting = {
    englishContainsHan: issueGroup(englishContainsHan, { affectedResources: englishAffectedResources }),
    orphanPayloads: issueGroup(orphanPayloads, {
      intentional: orphanPayloads.filter(item => item.intentional).length,
      custom: orphanPayloads.filter(item => item.custom).length,
      actionable: orphanPayloads.filter(item => !item.intentional && !item.custom).length,
    }),
    duplicateNames: issueGroup(duplicateNames),
    genericTutorials: issueGroup(genericTutorials),
    categoryTreeMismatch: issueGroup(categoryTreeMismatch),
    wafCoverage: {
      total: totalPayloads,
      withVariants: withWafVariants,
      withoutVariants: totalPayloads - withWafVariants,
      percent: totalPayloads ? Number(((withWafVariants / totalPayloads) * 100).toFixed(2)) : 100,
    },
  };
  const blockingErrors = Object.values(blocking).reduce((sum, group) => sum + group.count, 0);
  return {
    version: 1,
    source: options.source || 'snapshot',
    ok: blockingErrors === 0,
    summary: {
      blockingErrors,
      payloads: snapshot.payloads.length,
      tools: snapshot.tools.length,
      payloadNavigationRoots: snapshot.navigation.length,
      toolNavigationRoots: snapshot.toolNavigation.length,
    },
    blocking,
    reporting,
  };
};

const tableExists = (database, table) => Boolean(
  database.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(table),
);

const readRows = (database, table, column, invalidJson, kind) => {
  if (!tableExists(database, table)) {
    invalidJson.push({ resource: kind, id: '<table>', path: column, error: `Missing table: ${table}` });
    return [];
  }
  const rows = database.prepare(`SELECT id, ${column} AS json FROM ${table} ORDER BY sort_order, id`).all();
  return rows.flatMap(row => {
    try {
      const value = JSON.parse(row.json);
      return isObject(value) ? [value] : (() => {
        invalidJson.push({ resource: kind, id: row.id, path: column, error: 'JSON root must be an object' });
        return [];
      })();
    } catch (error) {
      invalidJson.push({ resource: kind, id: row.id, path: column, error: error.message });
      return [];
    }
  });
};

export const auditDatabase = file => {
  const absoluteFile = resolve(file);
  const database = new DatabaseSync(absoluteFile, { readOnly: true });
  try {
    const integrityRows = database.prepare('PRAGMA integrity_check').all();
    const integrityIssues = integrityRows
      .map(row => Object.values(row)[0])
      .filter(value => value !== 'ok')
      .map(value => ({ resource: 'database', id: '<database>', path: '', error: String(value) }));
    const invalidJson = [];
    const payloads = readRows(database, 'payloads', 'data', invalidJson, 'payload');
    const tools = readRows(database, 'tools', 'data', invalidJson, 'tool');
    const navigationRows = tableExists(database, 'navigation_nodes')
      ? database.prepare('SELECT id, tree AS json, kind FROM navigation_nodes ORDER BY kind, sort_order, id').all()
      : [];
    if (!tableExists(database, 'navigation_nodes')) {
      invalidJson.push({ resource: 'navigation', id: '<table>', path: 'tree', error: 'Missing table: navigation_nodes' });
    }
    const navigation = [];
    const toolNavigation = [];
    for (const row of navigationRows) {
      try {
        const value = JSON.parse(row.json);
        if (!isObject(value)) throw new Error('JSON root must be an object');
        (row.kind === 'tools' ? toolNavigation : navigation).push(value);
      } catch (error) {
        invalidJson.push({ resource: `${row.kind || 'unknown'}-navigation`, id: row.id, path: 'tree', error: error.message });
      }
    }
    let settings = null;
    if (tableExists(database, 'metadata')) {
      const settingsValue = database.prepare("SELECT value FROM metadata WHERE key = 'settings'").get()?.value;
      if (settingsValue) {
        try {
          settings = JSON.parse(settingsValue);
        } catch (error) {
          invalidJson.push({ resource: 'metadata', id: 'settings', path: 'value', error: error.message });
        }
      }
    }
    const report = auditSnapshot({ payloads, tools, navigation, toolNavigation, settings }, { source: absoluteFile });
    report.blocking.databaseIntegrity = issueGroup(integrityIssues);
    report.blocking.invalidJson = issueGroup(invalidJson);
    report.summary.blockingErrors = Object.values(report.blocking).reduce((sum, group) => sum + group.count, 0);
    report.ok = report.summary.blockingErrors === 0;
    return report;
  } finally {
    database.close();
  }
};

export const hasBlockingErrors = report => Number(report?.summary?.blockingErrors || 0) > 0;

export const formatHumanSummary = report => {
  const lines = [
    `Content quality: ${report.ok ? 'PASS' : 'FAIL'}`,
    `Database: ${report.source}`,
    `Resources: ${report.summary.payloads} payloads, ${report.summary.tools} tools, ${report.summary.payloadNavigationRoots} payload nav roots, ${report.summary.toolNavigationRoots} tool nav roots`,
    `Blocking errors: ${report.summary.blockingErrors}`,
  ];
  for (const [name, group] of Object.entries(report.blocking)) {
    if (group.count) lines.push(`  - ${name}: ${group.count}`);
  }
  lines.push(
    `Reporting: English-with-Han ${report.reporting.englishContainsHan.count}, orphans ${report.reporting.orphanPayloads.count} (${report.reporting.orphanPayloads.actionable} actionable), duplicate names ${report.reporting.duplicateNames.count}, generic tutorials ${report.reporting.genericTutorials.count}, category mismatches ${report.reporting.categoryTreeMismatch.count}`,
    `WAF coverage: ${report.reporting.wafCoverage.withVariants}/${report.reporting.wafCoverage.total} (${report.reporting.wafCoverage.percent}%)`,
  );
  return lines.join('\n');
};

const parseCli = argv => {
  const files = [];
  let json = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--json') json = true;
    else if (argument === '--database') {
      const file = argv[index + 1];
      if (!file) throw new Error('--database requires a path');
      files.push(resolve(file));
      index += 1;
    } else if (argument === '--seed-only') {
      files.push(defaultSeedFile);
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  if (!files.length) {
    files.push(defaultSeedFile);
    if (existsSync(defaultRuntimeFile)) files.push(defaultRuntimeFile);
  }
  return { files: [...new Set(files)], json };
};

const runCli = argv => {
  const { files, json } = parseCli(argv);
  const missing = files.filter(file => !existsSync(file));
  if (missing.length) throw new Error(`Content database not found: ${missing.join(', ')}`);
  const reports = files.map(auditDatabase);
  const result = {
    version: 1,
    ok: reports.every(report => report.ok),
    databases: reports,
  };
  if (json) console.log(JSON.stringify(result, null, 2));
  else console.log(reports.map(formatHumanSummary).join('\n\n'));
  if (!result.ok) process.exitCode = 1;
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    console.error(`Content quality verifier failed: ${error.message}`);
    process.exitCode = 2;
  }
}
