// 第二批集成：review.decision 补齐、tutorial 修正折入、ntlm-relay 接管、service-exploit 迁移、manifest 注册。
// 从项目根运行：node scripts/review-fix-b2-integrate.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const rtPayload = id => JSON.parse(db.prepare('SELECT data FROM payloads WHERE id = ?').get(id).data);
const loadDoc = f => JSON.parse(readFileSync(`content-review/${f}`, 'utf8'));
const writeDoc = (f, doc, indent = 1) => {
  const raw = readFileSync(`content-review/${f}`, 'utf8');
  const eol = raw.includes('\r\n') ? '\r\n' : '\n';
  const trailing = /\n$/.test(raw) ? eol : '';
  writeFileSync(`content-review/${f}`, JSON.stringify(doc, null, indent).replace(/\n/g, eol) + trailing, 'utf8');
};

// ---------- 1. b2-n：persistence-scheduled 补 review；追加 ntlm-relay 与 zerologon ----------
const b2nFile = 'overrides-contentfix-2026-10-b2-n.json';
const b2n = loadDoc(b2nFile);
for (const e of b2n.entries) {
  if (e.id === 'persistence-scheduled' && !e.review) {
    e.review = { decision: 'payload', rationale: 'N-0018：C4 标题从序列化 JSON 还原；C3/C1 置空与标题不符的错位挂载（C1 系同类矛盾外推，已报备）。' };
  }
}
const ids = new Set(b2n.entries.map(e => e.id));
if (!ids.has('ntlm-relay')) {
  const entry = rtPayload('ntlm-relay');
  // N-0013：删除错挂的 RDP 残留 B6-B9（运行库下标 5-8；0-4 保持，交由既有 patch 通道继续生效）
  entry.wafBypass = (entry.wafBypass || []).slice(0, 5);
  entry.review = { decision: 'payload', rationale: 'N-0013：wafBypass 删除错挂的 rdp-relay 残留四条（原 5-8 下标），保留 0-4 规避变体。' };
  b2n.entries.push(entry);
}
if (!ids.has('zerologon')) {
  const entry = rtPayload('zerologon');
  const mit = entry.tutorial?.mitigation?.zh || '';
  if (!mit.includes('FullSecureChannelSupport')) throw new Error('zerologon tutorial.mitigation 现文与 N-0019 描述不符');
  entry.tutorial.mitigation = {
    ...entry.tutorial.mitigation,
    zh: mit
      .replace('FullSecureChannelSupport', 'FullSecureChannelProtection')
      .replace('并开启 Netlogon 强制模式拒绝脆弱连接，', '并开启 Netlogon 强制模式拒绝脆弱连接（2021-02 后补丁默认强制，手动写值仅用于旧补丁窗口期），'),
  };
  entry.review = { decision: 'payload', rationale: 'N-0019：修复注册表值名 FullSecureChannelSupport→FullSecureChannelProtection，并补注补丁窗口期说明。' };
  b2n.entries.push(entry);
}
b2n.entries.sort((a, b) => a.id.localeCompare(b.id, 'en'));
b2n.sourceIds = b2n.entries.map(e => e.id);
writeDoc(b2nFile, b2n);
console.log(`b2-n: ${b2n.entries.length} entries（persistence-scheduled review、ntlm-relay、zerologon）`);

// ---------- 2. b2-wt4：laravel-rce / django-vuln tutorial 修正 ----------
const b2wt4File = 'overrides-contentfix-2026-10-b2-wt4.json';
const b2wt4 = loadDoc(b2wt4File);
for (const e of b2wt4.entries) {
  if (e.id === 'laravel-rce') {
    const zh = e.tutorial?.exploitation?.zh || '';
    if (zh.includes('/_ignition/health-check')) {
      e.tutorial.exploitation = { ...e.tutorial.exploitation, zh: zh.split('/_ignition/health-check').join('/_ignition/execute-solution') };
      console.log('b2-wt4: laravel-rce tutorial.exploitation 端点更正');
    }
  }
  if (e.id === 'django-vuln') {
    const zh = e.tutorial?.mitigation?.zh || '';
    const anchor = '与 CVE-2021-28658（3.1.9+）的版本；';
    if (zh.includes(anchor)) {
      e.tutorial.mitigation = {
        ...e.tutorial.mitigation,
        zh: zh.replace(anchor, '的版本；CVE-2021-28658（3.1.9+）仅适用于 collectstatic/findstatic 对符号链接目录的处理，与运行期 /static URL 穿越无关；'),
      };
      console.log('b2-wt4: django-vuln tutorial.mitigation CVE 归因限定');
    }
  }
}
writeDoc(b2wt4File, b2wt4);

// ---------- 3. sb 文档：摘除 ntlm-relay waf[5-8] 被接管 patch；收编 service-exploit ----------
const sbFile = 'payload-command-overrides-sb-2026-09.json';
const sb = loadDoc(sbFile);
for (const e of sb.entries) {
  if (e.id === 'ntlm-relay') {
    const before = e.patches.length;
    e.patches = e.patches.filter(p => !(p.area === 'wafBypass' && [5, 6, 7, 8].includes(p.index)));
    console.log(`sb: ntlm-relay 摘除 ${before - e.patches.length} 条被接管 waf patch`);
  }
}
const deadFile = 'payload-command-overrides-qa-final-2026-09.json';
const dead = loadDoc(deadFile);
const seEntry = (dead.entries || []).find(e => e.id === 'service-exploit');
if (seEntry && !sb.entries.some(e => e.id === 'service-exploit')) {
  sb.entries.push(JSON.parse(JSON.stringify(seEntry)));
  console.log('sb: 收编 service-exploit（自未注册的 qa-final 文档迁入）');
}
writeDoc(sbFile, sb);

// ---------- 4. 死文档移除 service-exploit（防将来复注册时复活） ----------
if (seEntry) {
  dead.entries = dead.entries.filter(e => e.id !== 'service-exploit');
  writeDoc(deadFile, dead);
  console.log('qa-final(command-overrides,未注册): 移除 service-exploit');
}

// ---------- 5. manifest 注册 ----------
const mFile = 'manifest.json';
const m = loadDoc(mFile);
for (const [key, f] of [
  ['payloadCommandOverrideFiles', 'payload-command-overrides-contentfix-2026-10-b2-wt4.json'],
  ['overrideFiles', 'overrides-contentfix-2026-10-b2-wt4.json'],
  ['overrideFiles', 'overrides-contentfix-2026-10-b2-n.json'],
]) {
  if (!m[key].includes(f)) { m[key].push(f); console.log(`registered ${key} → ${f}`); }
}
writeDoc(mFile, m, 2);
console.log('done');
