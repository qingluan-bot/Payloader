// 漏洞分类公共模块（v2.0.2 治理 A2）：CWE → 漏洞类型映射、CVSS 分档、描述关键词兜底、
// MSF 模块路径兜底映射，供 edb / msf / nuclei 三源共用（原先 cweTypeMap 私有在 edb.mjs，
// msf 硬编码 vulnType='rce' 的根因就是没有公共层）。

// ---- CWE → 漏洞类型（词表对齐策展层与前端 18 值枚举，无匹配返回空串由调用方兜底）----
export const cweTypeMap = new Map([
  ['CWE-22', 'path-traversal'], ['CWE-23', 'path-traversal'], ['CWE-36', 'path-traversal'],
  ['CWE-77', 'rce'], ['CWE-78', 'rce'], ['CWE-94', 'rce'], ['CWE-95', 'rce'], ['CWE-96', 'rce'],
  ['CWE-79', 'xss'], ['CWE-80', 'xss'],
  ['CWE-89', 'sqli'],
  ['CWE-119', 'memory-corruption'], ['CWE-120', 'memory-corruption'], ['CWE-121', 'memory-corruption'],
  ['CWE-122', 'memory-corruption'], ['CWE-125', 'memory-corruption'], ['CWE-416', 'memory-corruption'],
  ['CWE-787', 'memory-corruption'], ['CWE-824', 'memory-corruption'],
  ['CWE-200', 'info-disclosure'], ['CWE-209', 'info-disclosure'], ['CWE-532', 'info-disclosure'],
  ['CWE-250', 'lpe'], ['CWE-269', 'lpe'], ['CWE-272', 'lpe'], ['CWE-282', 'lpe'],
  ['CWE-284', 'access-control'], ['CWE-285', 'access-control'], ['CWE-639', 'access-control'],
  ['CWE-862', 'access-control'], ['CWE-863', 'access-control'],
  ['CWE-287', 'auth-bypass'], ['CWE-288', 'auth-bypass'], ['CWE-305', 'auth-bypass'],
  ['CWE-306', 'auth-bypass'], ['CWE-384', 'auth-bypass'],
  ['CWE-352', 'csrf'],
  ['CWE-400', 'dos'],
  ['CWE-434', 'file-upload'],
  ['CWE-502', 'deserialization'],
  ['CWE-611', 'xxe'],
  ['CWE-798', 'default-credentials'], ['CWE-1392', 'default-credentials'],
  ['CWE-918', 'ssrf'],
]);

export const descriptionTypeRules = [
  [/remote code execution|\brce\b/i, 'rce'],
  [/sql injection/i, 'sqli'],
  [/deserializ/i, 'deserialization'],
  [/file upload/i, 'file-upload'],
  [/(path|directory) traversal/i, 'path-traversal'],
  [/authentication bypass|auth(entication)? bypass|unauthorized (access|command)/i, 'auth-bypass'],
  [/privilege escalation/i, 'lpe'],
  [/information disclosure/i, 'info-disclosure'],
  [/(buffer|heap|stack)[- ]?(overflow|corruption)|use-after-free|memory corruption|out-of-bounds/i, 'memory-corruption'],
  [/xml external entity|\bxxe\b/i, 'xxe'],
  [/\bssrf\b|server-side request forgery/i, 'ssrf'],
  [/cross-?site scripting|\bxss\b/i, 'xss'],
  [/cross-?site request forgery|\bcsrf\b/i, 'csrf'],
  [/default (credentials|password)|hard-?coded credential/i, 'default-credentials'],
  [/denial of service/i, 'dos'],
];

export const resolveVulnType = ({ cwe, description }) => {
  if (cwe && cweTypeMap.has(cwe)) return cweTypeMap.get(cwe);
  for (const [pattern, type] of descriptionTypeRules) {
    if (pattern.test(description)) return type;
  }
  return 'uncategorized';
};

// CWE → 漏洞类型（无匹配返回空串，调用方自行兜底）——nuclei/msf 补源共用
export const vulnTypeFromCwe = cwe => (cwe && cweTypeMap.get(cwe)) || '';

// CVSS baseScore → 严重等级（策展词表 critical/high/medium/low）
// 治理 F-sev：无 NVD 评分（score 缺失/<=0）返回 'unknown'（官方未评级），不再编造 medium——
// 用户原则：不评高不评低，按官方评级；官方没评就是未评级。
export const severityFromScore = score => {
  if (!Number.isFinite(score) || score <= 0) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
};

// ---- MSF 模块路径 → 漏洞类型兜底（无 NVD CWE 命中时用）----
// 依据（rapid7/metasploit-framework 仓库结构实证）：modules/exploits/<platform>/<service>/name.rb。
// - exploits/*/local/（与 */privilege/）目录专收本地提权模块 → lpe；
// - 其余远端利用面（http/smb/ssh/fileformat/browser 等）MSF exploit 模块的成功路径
//   均以取得代码执行为目标（Metasploit 官方定位），统一归 rce；细分类型交给 NVD CWE 主映射。
const MSF_PATH_TYPE_RULES = [
  [/\/local\//, 'lpe'],       // MSF local 目录 = 本地提权模块（windows/local、linux/local…）
  [/\/privilege\//, 'lpe'],   // 历史目录别名，语义同 local
];

// 治理 A8 补：模块名直判兜底——模块文件名带 exec/rce/debug_rce/code_injection 等
// 执行语义标记时优先 rce。审计实证 Werkzeug debug_rce 标了 csrf（NVD CWE 映射被
// 泛化 CWE 带偏）、Total.js widget_exec 标了 access-control，这条规则在 CWE 映射
// 之后、路径兜底之前生效，修正此类个案。
const MSF_NAME_EXEC_RE = /(debug_?rce|_rce|rce_|_exec\b|exec_|code_?injection|cmd_?inject)/;

export const msfPathVulnType = (modulePath, moduleName = '') => {
  const normalized = `/${String(modulePath || '')}/`;
  for (const [pattern, type] of MSF_PATH_TYPE_RULES) {
    if (pattern.test(normalized)) return type;
  }
  const nameHint = String(moduleName || modulePath.split('/').pop() || '');
  if (MSF_NAME_EXEC_RE.test(nameHint)) return 'rce';
  return 'rce';
};

// ---- 描述截断：≥300 字符处落到完整句边界（治理 A4：不硬切半句）----
export const truncateAtSentence = (text, limit = 300) => {
  const clean = String(text ?? '').trim();
  if (clean.length <= limit) return clean;
  const rest = clean.slice(limit);
  const sentenceEnd = rest.match(/^[^.!?。;；]*[.!?。;；]/);
  if (sentenceEnd) return clean.slice(0, limit + sentenceEnd[0].length).trim();
  return `${clean.slice(0, limit)}...`;
};

// ---- canonical 分组键（治理 A6）：CVE 编号升序第一个；无 CVE 返回空串 ----
// 排序按（年份, 序号）数值比较，避免纯字典序把 CVE-2021-9 排到 CVE-2021-44228 之后
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
