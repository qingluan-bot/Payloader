// Metasploit 官方 exploit 模块源（v2.0.3 第四聚合源）：rapid7/metasploit-framework
// exploits/**/*.rb → EXP 模型候选（bizKey msf:<模块路径>）。模块即完整利用脚本，
// msfconsole use 直接可用；refs 里的 CVE 映射编号，Name/Description 抽标题与描述。
// v2.0.2 治理 A2：废除硬编码（vulnType='rce'/affected=''/severity='critical'）——
// vulnType = NVD CWE → cweTypeMap（公共模块 classify.mjs），无 NVD 命中按模块路径兜底；
// severity = NVD CVSS 分档（severityFromScore），无命中回退 high；
// affected = NVD CPE products；description/prerequisites 用真实文本按 rank/path 变量化。

import { msfPathVulnType, primaryCveKey, severityFromScore, truncateAtSentence, vulnTypeFromCwe } from './classify.mjs';
import { deriveProducts } from './products.mjs';
import { MAX_CODE_BYTES, MSF_MODULE_URL } from './sources.mjs';

// rank 官方语义（Metasploit 文档 Ranking：excellent 稳定可靠不致崩溃 → manual 需手动且不稳定）
const MSF_RANK_NOTES = {
  excellent: '稳定可靠，默认配置即可成功且不留痕迹',
  great: '可靠，可能需要微调目标选项',
  good: '可用，需正确配置目标环境',
  normal: '常规可靠性，成功率视环境而定',
  average: '可靠性一般，可能不稳定',
  low: '预期成功率低，多数环境不适用',
  manual: '需手动交互，稳定性差',
};

// 模块路径 exploit/<platform>/<service>/name → 服务段标签（prerequisites 变量化用）
const MSF_SERVICE_LABELS = {
  http: 'HTTP 服务', https: 'HTTPS 服务', smb: 'SMB 服务', ssh: 'SSH 服务', ftp: 'FTP 服务',
  smtp: 'SMTP 服务', telnet: 'Telnet 服务', rdp: 'RDP 服务', dns: 'DNS 服务', mysql: 'MySQL 服务',
  mssql: 'MSSQL 服务', postgres: 'PostgreSQL 服务', redis: 'Redis 服务', ftpserver: 'FTP 服务',
  browser: '目标浏览器', fileformat: '目标文件解析器', client: '目标客户端', local: '本地会话',
};

const serviceLabelOf = modulePath => {
  const segments = String(modulePath || '').split('/');
  // exploit/<platform>/<service...>/name：服务段取倒数第二层
  const service = segments.length >= 3 ? segments[segments.length - 2] : segments[1] || '';
  return MSF_SERVICE_LABELS[service] || (service === 'local' ? '本地会话' : `${service || '目标'} 服务`);
};

// 模块路径 exploit/<platform>/... → 平台标签（affected 兜底）
const MSF_PLATFORM_LABELS = {
  windows: 'Windows', linux: 'Linux', unix: 'Unix', multi: 'Multiple', osx: 'macOS',
  solaris: 'Solaris', aix: 'AIX', mainframe: 'Mainframe', netware: 'NetWare', irix: 'Irix',
  bsdi: 'BSD/OS', freebsd: 'FreeBSD', firefox: 'Firefox', browsers: 'Browser', android: 'Android',
  apple_ios: 'iOS', hpux: 'HP-UX', juniper: 'Juniper', mandrake: 'Mandrake', mips: 'MIPS',
  nginx: 'Nginx', openbsd: 'OpenBSD', php: 'PHP', plan9: 'Plan 9', python: 'Python',
  qnx: 'QNX', riscos: 'RISC OS', ruby: 'Ruby', snmp: 'SNMP', socialengineering: 'Social Engineering',
  solaris_2: 'Solaris', ssl: 'SSL/TLS', ttyn: 'TTY', unixothers: 'Unix', wifi: 'Wi-Fi',
};
const modulePathPlatformLabel = modulePath => {
  const segments = String(modulePath || '').split('/');
  const platform = segments.length >= 2 ? segments[1] : '';
  return MSF_PLATFORM_LABELS[platform] || '';
};

const rubyStringOf = (text, key) => {
  // 'Name' => 'xxx' / "Name" => "xxx"（含单引号转义的保守抽取，取首个匹配行）
  const match = text.match(new RegExp(`['"]${key}['"]\\s*=>\\s*['"]([^'"\\\\\\r\\n]*(?:\\\\.[^'"\\\\\\r\\n]*)*)['"]`));
  if (!match) return '';
  return match[1].replace(/\\'/g, "'").replace(/\\"/g, '"').replace(/\\n/g, ' ').trim();
};

// 单模块 rb 正文 → { modulePath, name, description, cves[], rank, content }；非 exploit/无 CVE 返回 null
export const parseMsfModule = (content, path) => {
  // MSF 仓库模块目录为 modules/exploits/**（归一化掉 modules/ 前缀），仅收 exploit 类模块
  const normalized = path.replace(/^modules\//, '');
  if (!normalized.startsWith('exploits/') || !normalized.endsWith('.rb')) return null;
  const segments = normalized.split('/');
  if (segments.length < 3) return null;
  const modulePath = `exploit/${segments.slice(1, -1).join('/')}/${segments.at(-1).replace(/\.rb$/, '')}`;
  const name = rubyStringOf(content, 'Name');
  const description = rubyStringOf(content, 'Description').slice(0, 500);
  const rankMatch = content.match(/^\s*Rank\s*=\s*(\w+)/m);
  // MSF refs 形态：['CVE', '2021-44228']（第二元素通常无 CVE- 前缀，规范如此）；兼容带前缀写法
  const cves = [...new Set(
    [...content.matchAll(/\[\s*['"]CVE['"]\s*,\s*['"]([^'"]+)['"]\s*\]/g)]
      .map(match => match[1].toUpperCase())
      .map(value => (value.startsWith('CVE-') ? value : `CVE-${value}`))
      .filter(value => /^CVE-\d{4}-\d{4,7}$/.test(value)),
  )];
  if (!cves.length) return null; // 无 CVE 的模块（auxiliary 类/无编号）不入库，保持信噪比
  return {
    modulePath,
    name: name || modulePath,
    description,
    rank: rankMatch?.[1] || '',
    cves,
    content,
  };
};

// 模块 → EXP 模型候选（正文即完整 exploit 脚本）
export const buildMsfModels = (modules, { cveMap = new Map() } = {}) => {
  const pairs = [];
  const skipped = { noCve: 0 };
  modules.forEach(module => {
    if (!module) {
      skipped.noCve += 1;
      return;
    }
    const truncated = module.content.length > MAX_CODE_BYTES;
    const body = truncated
      ? `${module.content.slice(0, MAX_CODE_BYTES)}\n\n... [模块超 ${Math.round(MAX_CODE_BYTES / 1024)}KB 已截断，完整模块见原始仓库]`
      : module.content;
    const primaryCve = module.cves[0];
    const nvd = cveMap.get(primaryCve);
    const cwe = nvd?.cwe || '';
    // vulnType：模块路径 local/privilege → lpe；模块名带明确 exec/rce 语义 → rce
    // （覆盖 NVD 泛化 CWE 的错映射——审计实证 Werkzeug debug_rce 被带偏）；否则 CWE 映射 → 路径兜底
    const cweType = vulnTypeFromCwe(cwe);
    const pathType = msfPathVulnType(module.modulePath);
    // exec 语义标记常在模块路径（werkzeug_debug_rce）而非显示名（Werkzeug Debugger Command Execution）——两者联合测试
    const vulnType = pathType === 'lpe'
      ? 'lpe'
      : /debug_?rce|_rce|rce_|_exec\b|exec_|code_?injection/.test(`${module.name}/${module.modulePath}`) ? 'rce'
        : cweType || pathType;
    // severity：NVD CVSS 分档；无 NVD 命中回退 high（不再恒 critical）
    const severity = nvd && Number.isFinite(nvd.score) ? severityFromScore(nvd.score) : 'unknown';
    const cpeProducts = nvd?.products || [];
    const rankText = module.rank
      ? `模块 rank=${module.rank}（${MSF_RANK_NOTES[module.rank.toLowerCase()] || '可靠性视目标环境而定'}）。`
      : '模块未标注 rank。';
    const baseDescription = truncateAtSentence(module.description || module.name, 500);
    const description = `${baseDescription} ${rankText}msfconsole 中 use ${module.modulePath} 加载。`.replace(/\s+/g, ' ').trim();
    const isLocal = module.modulePath.includes('/local/');
    const prerequisites = isLocal
      ? `利用条件：需已在目标主机（${module.modulePath.split('/')[1] || '目标'} 平台）获得本地执行入口；msfconsole 中 use ${module.modulePath} 后按 show options 配置 SESSION 等参数。${rankText}`
      : `利用条件：目标 ${serviceLabelOf(module.modulePath)} 需网络可达且版本在受影响区间；msfconsole 中 use ${module.modulePath} 后按 show options 配置 RHOSTS/RPORT 等参数。${rankText}`;
    const vulnerabilityIds = module.cves.slice(0, 30).map(value => ({ type: 'CVE', value }));
    pairs.push({
      bizKey: `msf:${module.modulePath}`,
      exploit: {
        name: module.name.slice(0, 200),
        description,
        vulnType,
        // affected：NVD CPE 优先；无命中时按模块路径平台段兜底（模块本身编码了目标平台，
        // 治理 A2 指标 affected 非空率的要求来源）
        affected: cpeProducts.length
          ? cpeProducts.join('; ')
          : (modulePathPlatformLabel(module.modulePath) || ''),
        severity,
        publishedAt: module.cves[0].slice(4, 8),
        vulnerabilityIds,
        exploitCode: [{
          title: '完整 Metasploit 利用模块（Ruby，msfconsole 直接 use）',
          language: 'ruby',
          code: body,
          ...(truncated ? { description: `完整模块：${MSF_MODULE_URL(module.modulePath)}` } : {}),
        }],
        prerequisites,
        references: [MSF_MODULE_URL(module.modulePath)],
        tags: ['metasploit', 'msf', 'format:script', 'ruby', ...(module.rank ? [`rank-${module.rank.toLowerCase()}`] : [])],
        attribution: { source: 'Metasploit Framework', author: 'Rapid7', license: 'BSD-3-Clause' },
        source: 'metasploit',
        sourceRef: `msf-${module.modulePath}`,
        products: deriveProducts({ cpeProducts, name: module.name, description: baseDescription }),
        canonicalKey: primaryCveKey(vulnerabilityIds),
      },
    });
  });
  return { pairs, skipped };
};
