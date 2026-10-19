// 内容修复批次机械验收门禁（需求文档第七节.3）
// 从项目根运行：node scripts/review-content-gates.mjs [--db data/payloader.sqlite]
// 六项：⏎ 污染 / 命令边界字面 \n / 全角分号 / （删除 编辑残留 / SB part∉command / N-0003 requiresAdmin
import { DatabaseSync } from 'node:sqlite';

const dbFile = process.argv.includes('--db') ? process.argv[process.argv.indexOf('--db') + 1] : 'data/payloader.sqlite';
const db = new DatabaseSync(dbFile, { readOnly: true });
const payloads = db.prepare('SELECT id, data FROM payloads ORDER BY id').all().map(r => ({ id: r.id, ...JSON.parse(r.data) }));
const tools = db.prepare('SELECT id, data FROM tools ORDER BY id').all().map(r => ({ id: r.id, ...JSON.parse(r.data) }));

const findings = { mark: [], boundaryNL: [], fullwidthSemi: [], editResidue: [], sbMismatch: [], requiresAdmin: [] };
const N0003_IDS = ['lsa-secrets', 'persistence-wmi', 'persistence-dll-injection', 'golden-ticket', 'dsrm-backdoor', 'dcshadow-attack'];

// 格式串内 \n 白名单：printf/echo -e/tr/--write-out(-w) 等语境，或行尾续行符
const formatContextRe = /(?:printf\b|echo\s+(-e|-E)\b|tr\b|--write-out|-w\s)(?:(?!\\n).)*$/;
const continuationEnd = /(?:\\|\||&&|\|\||;\s*)$/;
const commandWords = new Set(['sudo', 'apt', 'apt-get', 'git', 'curl', 'wget', 'nc', 'ncat', 'netcat', 'bash', 'sh', 'zsh', 'python', 'python2', 'python3', 'pip', 'pip3', 'powershell', 'pwsh', 'cmd', 'certutil', 'bitsadmin', 'msfvenom', 'msfconsole', 'nmap', 'masscan', 'rustscan', 'gobuster', 'feroxbuster', 'ffuf', 'dirb', 'nikto', 'sqlmap', 'hydra', 'john', 'hashcat', 'openssl', 'ssh', 'scp', 'socat', 'tcpdump', 'tshark', 'tcpdump', 'dig', 'whois', 'echo', 'cat', 'ls', 'cd', 'mkdir', 'rm', 'cp', 'mv', 'chmod', 'chown', 'tar', 'unzip', '7z', 'gzip', 'find', 'grep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'head', 'tail', 'xargs', 'tee', 'make', 'cmake', 'gcc', 'g++', 'clang', 'node', 'npm', 'npx', 'deno', 'bun', 'go', 'rustc', 'cargo', 'java', 'javac', 'mvn', 'gradle', 'ruby', 'gem', 'perl', 'php', 'lua', 'powershell.exe', 'wevtutil', 'reg', 'sc', 'net', 'netsh', 'wmic', 'dsquery', 'dsmod', 'klist', 'kinit', 'rubeus', 'mimikatz', 'secretsdump.py', 'wmiexec.py', 'psexec.py', 'smbexec.py', 'atexec.py', 'dcomexec.py', 'impacket-smbexec', 'amass', 'subfinder', 'httpx', 'nuclei', 'naabu', 'subzy', 'dnsrecon', 'dnsenum', 'theHarvester', 'maltego', 'spiderfoot', 'recon-ng', 'wafw00f', 'whatweb', 'wappalyzer', 'burpsuite', ' Comm', 'kubectl', 'docker', 'helm', 'aws', 'az', 'gcloud', 'gsutil', 'terraform', 'ansible', 'sshpass', 'ssh2git', 'iex', 'Invoke-', 'Set-', 'Get-', 'New-', 'Start-', 'Stop-', 'Copy-', 'Remove-', 'Add-', 'Import-', 'Export-']);

const scanCommandText = (ownerId, where, cmd) => {
  if (typeof cmd !== 'string') return;
  if (cmd.includes('\u23CE') || cmd.includes('⏎ CMD: ')) findings.mark.push(`${ownerId} ${where}`);
  if (cmd.includes('；')) findings.fullwidthSemi.push(`${ownerId} ${where}`);
  if (/^（删除|^（保留/.test(cmd)) findings.editResidue.push(`${ownerId} ${where}`);
  // 命令边界字面 \n：反斜杠+n 两字符序列
  let idx = 0;
  while ((idx = cmd.indexOf('\\n', idx)) !== -1) {
    const before = cmd.slice(Math.max(0, idx - 200), idx);
    const after = cmd.slice(idx + 2, idx + 2 + 60).trimStart();
    const lineStart = before.lastIndexOf('\n') + 1;
    const line = before.slice(lineStart);
    const inFormat = formatContextRe.test(line) || /(?:printf|echo -e|tr\b|--write-out|-w\s)[^"']*["'][^"']*$/.test(line);
    if (!inFormat) {
      const firstToken = (after.split(/[\s"'`]/)[0] || '');
      const prevLineEnds = continuationEnd.test(line);
      if (commandWords.has(firstToken) && !prevLineEnds && line.trim().length > 0) {
        findings.boundaryNL.push(`${ownerId} ${where} @${idx}: …${line.slice(-40)}\\n${after.slice(0, 40)}…`);
      }
    }
    idx += 2;
  }
};

const scanSyntaxBreakdown = (ownerId, where, entry) => {
  const sb = entry?.syntaxBreakdown;
  const cmd = typeof entry?.command === 'string' ? entry.command : '';
  if (!Array.isArray(sb) || !cmd) return;
  for (const item of sb) {
    const part = typeof item?.part === 'string' ? item.part : '';
    if (!part) continue;
    if (!cmd.includes(part)) findings.sbMismatch.push(`${ownerId} ${where} part="${part.slice(0, 50)}"`);
  }
};

for (const p of payloads) {
  (p.execution || []).forEach((s, i) => { scanCommandText(p.id, `execution[${i}]`, s?.command); });
  (p.wafBypass || []).forEach((s, i) => { scanCommandText(p.id, `wafBypass[${i}]`, s?.command); });
  (p.attackChain || []).forEach((s, i) => { scanCommandText(p.id, `attackChain[${i}].payload`, s?.payload); scanCommandText(p.id, `attackChain[${i}].command`, s?.command); });
  if (N0003_IDS.includes(p.id)) {
    // N 报告逐步骤核定终态（true=必须 true；false=必须 false；省略=不约束）
    const N0003_EXPECT = {
      'lsa-secrets': { execution: [true, true, false] },
      'golden-ticket': { execution: [true, false, false, false] },
      'dsrm-backdoor': { execution: [true, true, true, false] },
      'persistence-wmi': { execution: [true, true, true] },
      'persistence-dll-injection': { execution: [false, false, true] },
      'dcshadow-attack': { execution: [true, true, true] },
    };
    const rows = [];
    let mismatch = 0;
    (p.execution || []).forEach((s, i) => {
      rows.push(`execution[${i}]=${s?.requiresAdmin}`);
      const exp = N0003_EXPECT[p.id]?.execution?.[i];
      if (exp !== undefined && s?.requiresAdmin !== exp) mismatch++;
    });
    (p.wafBypass || []).forEach((s, i) => {
      rows.push(`wafBypass[${i}]=${s?.requiresAdmin}`);
      const exp = N0003_EXPECT[p.id]?.wafBypass?.[i];
      if (exp !== undefined && s?.requiresAdmin !== exp) mismatch++;
    });
    if (mismatch) findings.requiresAdmin.push(`${p.id}: ${rows.join(' ')} （${mismatch} 步不符）`);
  }
}
for (const t of tools) {
  (t.commands || []).forEach((s, i) => { scanCommandText(t.id, `commands[${i}]`, s?.command); scanSyntaxBreakdown(t.id, `commands[${i}]`, s); });
}
let fail = false;
const report = (label, list) => {
  const hit = list.length;
  if (hit) fail = true;
  console.log(`\n[${hit ? 'FAIL' : 'PASS'}] ${label}: ${hit}`);
  for (const item of list.slice(0, 40)) console.log(`  - ${item}`);
  if (hit > 40) console.log(`  …共 ${hit} 条`);
};
report('⏎ 污染（U+23CE / ⏎ CMD:）', findings.mark);
report('命令边界字面 \\n', findings.boundaryNL);
report('全角分号 ； 于命令字段', findings.fullwidthSemi);
report('（删除/（保留 编辑残留', findings.editResidue);
report('syntaxBreakdown.part ∉ command', findings.sbMismatch);
report('N-0003 六载荷 requiresAdmin 现值（对照 N 报告逐步骤核定）', findings.requiresAdmin);
console.log(`\n数据库: ${dbFile}`);
console.log(fail ? '机械门禁: FAIL' : '机械门禁: PASS（requiresAdmin 项以人工核定为准）');
process.exit(fail ? 1 : 0);
