// Lane B 工具库治理产物生成器（v2.0.2 治理 D）：
// B1 照抄即错修复（gobuster/amass/nuclei/installation 23 处）+
// B2 占位符统一（example.com/裸词/attacker-ip → {VAR} 风格，71 条）。
// 产物 content-review/tool-overrides-governance-2026-09.json 走 manifest.toolOverrideFiles
// 现成 path-patch 通道。幂等可重放：从运行库快照 + 规则表生成。
// amass v4 语法依据（2026-09-28 网搜核对）：enum/intel/graph/db 保留、viz 废弃、
// -brute 移除（-active + -w 即暴力解析）、-max-dns-queries 移除。
import { readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const rows = new DatabaseSync('data/payloader.sqlite', { readOnly: true })
  .prepare('SELECT id, data FROM tools').all()
  .map(row => ({ id: row.id, ...JSON.parse(row.data) }));
const byId = new Map(rows.map(row => [row.id, row]));

const entriesById = new Map();
const addPatch = (id, path, value) => {
  if (!entriesById.has(id)) entriesById.set(id, { id, patches: [] });
  entriesById.get(id).patches.push({ path, value });
};

// ---- B1a：命令修复（精确旧串 → 新串；description 同步可选）----
const commandFixes = [
  {
    tool: 'gobuster', index: 2,
    expect: 'gobuster dns -do {TARGET} -w subdomains.txt',
    command: 'gobuster dns -d {DOMAIN} -w subdomains.txt',
    description: {
      zh: '用 dns 模式枚举目标域子域；-d 接根域名（不带协议与路径），字典每行一个候选子域前缀。',
      en: 'Enumerate subdomains with dns mode; -d takes the root domain (no scheme or path), and the wordlist lists one candidate label per line.',
    },
  },
  {
    tool: 'gobuster-advanced', index: 1,
    expect: 'gobuster dns -do {TARGET} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --resolver 8.8.8.8:53',
    command: 'gobuster dns -d {DOMAIN} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --resolver 8.8.8.8:53',
  },
  {
    tool: 'gobuster-advanced', index: 3,
    expectPrefix: '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
    command: 'gobuster dir -u http://{TARGET} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt -t 50',
    description: {
      zh: '用 SecLists raft-medium 词表做目录枚举，按技术栈追加扩展名并限并发 50；词表清单只是资源，真正下发的是这条 dir 命令。',
      en: 'Run directory enumeration against the SecLists raft-medium wordlist, appending stack-appropriate extensions with 50 threads; the wordlist paths are just resources, this dir command is what actually runs.',
    },
  },
  {
    tool: 'amass', index: 1,
    expect: 'amass enum -active -d {TARGET} -brute -w /usr/share/amass/wordlists/subdomains-top1mil-110000.txt',
    command: 'amass enum -active -d {DOMAIN} -w /usr/share/amass/wordlists/subdomains-top1mil-110000.txt',
    description: {
      zh: '主动枚举并暴力解析候选子域；v4 起不再有 -brute 开关，配合 -active 与词表 -w 即启用暴破解析。',
      en: 'Active enumeration with brute resolution; amass v4 removed -brute, pairing -active with a -w wordlist enables brute forcing.',
    },
  },
  {
    tool: 'amass', index: 2,
    expect: 'amass intel -d {TARGET} -whois\namass intel -org "Target Corp" -max-dns-queries 2500',
    command: 'amass intel -whois -d {DOMAIN}\namass intel -d {DOMAIN} -org "Target Corp"',
    description: {
      zh: '反向 WHOIS 与组织名关联发现；v4 移除了 -max-dns-queries 限速开关，翻找范围由组织名与域名控制。',
      en: 'Reverse WHOIS and organization-based discovery; v4 removed -max-dns-queries, scope is controlled by the org and domain flags.',
    },
  },
  {
    tool: 'amass', index: 3,
    expect: 'amass viz -d3 -d {TARGET}\namass db -show -d {TARGET}',
    command: 'amass db -list\namass graph -d {DOMAIN}',
    description: {
      zh: '查看枚举会话与资产关系图；v4 移除了 viz 子命令，会话列表用 db -list，关系图用 graph。',
      en: 'Inspect enumeration sessions and the asset graph; v4 removed viz, use db -list for sessions and graph for visualization.',
    },
  },
  {
    tool: 'nuclei-advanced', index: 3,
    expectPrefix: '# 简单模板示例',
    command: 'nuclei -u http://{TARGET} -t ~/nuclei-templates/custom-check.yaml -severity medium',
    description: {
      zh: '加载自建模板对单目标校验；模板 YAML 写在本地文件（id/info/requests 结构见 nuclei 官方模板规范），用 -t 引用而不是把 YAML 当命令粘贴。',
      en: 'Validate one target with a local custom template; author the YAML (id/info/requests per the nuclei template spec) in a file and reference it with -t instead of pasting YAML as a command.',
    },
  },
];

for (const fix of commandFixes) {
  const tool = byId.get(fix.tool);
  if (!tool) throw new Error(`工具不存在: ${fix.tool}`);
  const entry = tool.commands?.[fix.index];
  if (!entry) throw new Error(`${fix.tool}[${fix.index}] 不存在`);
  const actual = entry.command || '';
  if (fix.expect && actual !== fix.expect) throw new Error(`${fix.tool}[${fix.index}] 原文漂移:\n  期望 ${fix.expect}\n  实际 ${actual}`);
  if (fix.expectPrefix && !actual.startsWith(fix.expectPrefix)) throw new Error(`${fix.tool}[${fix.index}] 原文前缀漂移: ${actual.slice(0, 60)}`);
  addPatch(fix.tool, `commands.${fix.index}.command`, fix.command);
  if (fix.description) addPatch(fix.tool, `commands.${fix.index}.description`, fix.description);
}

// ---- B1b：nuclei 安装路径 v2 → v3 ----
{
  const nuclei = byId.get('nuclei');
  const inst = nuclei.installation || {};
  if (inst.en?.includes('/v2/')) addPatch('nuclei', 'installation.en', inst.en.replaceAll('/v2/', '/v3/'));
  if (inst.zh?.includes('/v2/')) addPatch('nuclei', 'installation.zh', inst.zh.replaceAll('/v2/', '/v3/'));
}

// ---- B1c：installation 23 处损坏（字符串替换表，双侧应用、无变化不产 patch）----
const installationReplacements = [
  ['graphqlmap', [['Graph Q Lmap', 'GraphQLmap']]],
  ['subdomainizer', [['Sub Domainizer', 'SubDomainizer']]],
  ['web-fuzzing-wordlists', [['Sec Lists', 'SecLists']]],
  ['seclists', [['Sec Lists', 'SecLists']]],
  ['pacu', [['Rhino Security Labs/pacu', 'RhinoSecurityLabs/pacu']]],
  ['rsactftool', [['Rsa Ctf Tool/Rsa Ctf Tool', 'RsaCtfTool/RsaCtfTool'], ['Rsa Ctf Tool', 'RsaCtfTool']]],
  ['regeorg', [['Neo-re Georg', 'Neo-reGeorg']]],
  ['rubeus', [['Ghost Pack', 'GhostPack']]],
  ['seatbelt', [['Ghost Pack', 'GhostPack']]],
  ['sharphound', [['BloodHound AD/Sharp Hound', 'BloodHoundAD/SharpHound']]],
  ['pspy', [['Dominic Breuker', 'DominicBreuker']]],
  ['powerview-adrecon', [['PowerShell Mafia/Power Sploit', 'PowerShellMafia/PowerSploit']]],
  ['lazagne-tool', [['Alessandro Z/LaZagne', 'AlessandroZ/LaZagne']]],
  ['sliver', [['Bishop Fox/sliver', 'BishopFox/sliver']]],
  ['grype', [['curl -s Sf L', 'curl -sSfL']]],
  ['syft', [['curl -s Sf L', 'curl -sSfL']]],
  ['rockyou', [['# Kali built-in: ', 'Kali 自带：'], ['# Kali built-in:', 'Kali built-in:']]],
  ['feroxbuster', [['Downloadbinary', 'Download binary']]],
  ['macos-commands', [['Built-in on mac OS', 'Built-in on macOS'], ['mac OS', 'macOS']]],
  ['azure-ad-attacks', [['ROA Dtools', 'ROADtools'], ['Install-Module Azure AD', 'Install-Module AzureAD']]],
  ['exchange-m365-attacks', [['Mail Sniper', 'MailSniper'], ['AAD Internals', 'AADInternals']]],
  ['git-pentest', [['Git Hacker', 'GitHacker']]],
  ['theharvester', [['the Harvester', 'theHarvester']]],
];
let installationFixed = 0;
for (const [toolId, pairs] of installationReplacements) {
  const tool = byId.get(toolId);
  if (!tool?.installation) throw new Error(`${toolId} 无 installation`);
  for (const lang of ['en', 'zh']) {
    let text = tool.installation[lang] || '';
    const original = text;
    for (const [from, to] of pairs) text = text.split(from).join(to);
    if (text !== original) {
      addPatch(toolId, `installation.${lang}`, text);
      installationFixed += 1;
    }
  }
}

// ---- B2：占位符统一（71 条，{VAR} 风格与库内词表先例一致）----
const normalizePlaceholder = command => command
  .replace(/(?<=\/\/)example\.com/g, '{TARGET}')
  .replace(/example\.com/g, '{DOMAIN}')
  .replace(/(?<![{}A-Za-z])TARGET(?![}A-Za-z])/g, '{TARGET}')
  .replace(/(?<![{}A-Za-z])DOMAIN(?![}A-Za-z])/g, '{DOMAIN}')
  .replace(/\[?(?:attacker|ATTACKER)[_ ]?(?:ip|IP|host|HOST)\b\]?/g, '{ATTACKER_IP}')
  .replace(/<TARGET>/g, '{TARGET}')
  .replace(/<DOMAIN>/g, '{DOMAIN}')
  .replace(/<ATTACKER_IP>/g, '{ATTACKER_IP}');
let placeholderFixed = 0;
const truePlaceholder = JSON.parse(readFileSync('output/v202-governance/lane-b-true-placeholders.json', 'utf8'));
for (const issue of truePlaceholder) {
  const tool = byId.get(issue.tool);
  const entry = tool?.commands?.[issue.idx];
  if (!entry) throw new Error(`占位符条目缺失: ${issue.tool}[${issue.idx}]`);
  const normalized = normalizePlaceholder(entry.command);
  if (normalized !== entry.command) {
    addPatch(issue.tool, `commands.${issue.idx}.command`, normalized);
    placeholderFixed += 1;
  }
}

const document = {
  schemaVersion: 1,
  entries: [...entriesById.values()],
};
writeFileSync('content-review/tool-overrides-governance-2026-09.json', JSON.stringify(document, null, 1) + '\n');

const manifest = JSON.parse(readFileSync('content-review/manifest.json', 'utf8'));
if (!manifest.toolOverrideFiles.includes('tool-overrides-governance-2026-09.json')) {
  manifest.toolOverrideFiles.push('tool-overrides-governance-2026-09.json'); // 置末：同 id 级联后声明胜出
  writeFileSync('content-review/manifest.json', JSON.stringify(manifest, null, 2));
}

console.log(`tool-overrides-governance-2026-09.json: ${document.entries.length} 个工具 / ${document.entries.reduce((n, e) => n + e.patches.length, 0)} 个 patch（命令修复 ${commandFixes.length}、installation ${installationFixed} 侧、占位符 ${placeholderFixed}）`);
