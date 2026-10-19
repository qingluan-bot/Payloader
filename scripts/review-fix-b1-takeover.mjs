// 第一批集成第二步：从旧 tool 文档删除被批次文档接管的 path 声明（存活冲突唯一解）。
// 批次文档（contentfix-2026-10-b1*）持有最终值；旧文档继续声明同路径会在 apply 时撞
// Duplicate tool override path（applyToolOverrides 不豁免同值重复）。
// 从项目根运行：node scripts/review-fix-b1-takeover.mjs
import { readFileSync, writeFileSync } from 'node:fs';

const batchDocs = [
  'content-review/tool-overrides-contentfix-2026-10-b1.json',
  'content-review/tool-overrides-contentfix-2026-10-b1-modea.json',
];
const finalByPath = new Map();
for (const f of batchDocs) {
  const doc = JSON.parse(readFileSync(f, 'utf8'));
  for (const e of doc.entries || []) {
    for (const p of e.patches || []) finalByPath.set(`${e.id}|${p.path}`, true);
  }
}
const oldDocs = [
  'tool-overrides.json', 'tool-overrides-qa-final-2026-09.json', 'tool-overrides-governance-2026-09.json',
  'tool-overrides-ux-2026-09.json', 'tool-overrides-cloud.json', 'tool-overrides-container.json',
  'tool-overrides-credentials.json', 'tool-overrides-ctf.json', 'tool-overrides-quality-adcs.json',
  'tool-overrides-quality-completion.json', 'tool-overrides-quality-credentials.json',
  'tool-overrides-quality-info-gathering.json', 'tool-overrides-quality-kubernetes.json',
  'tool-overrides-quality-operations.json', 'tool-overrides-reverse.json', 'tool-overrides-specialized.json',
  'tool-overrides-tunneling.json', 'tool-overrides-web.json',
];
let removed = 0;
for (const f of oldDocs) {
  if (batchDocs.some(b => b.endsWith(f))) continue;
  const path = `content-review/${f}`;
  let raw;
  try { raw = readFileSync(path, 'utf8'); } catch { continue; }
  const doc = JSON.parse(raw);
  let dirty = 0;
  const keptEntries = [];
  for (const e of doc.entries || []) {
    const kept = (e.patches || []).filter(p => {
      if (finalByPath.has(`${e.id}|${p.path}`)) { removed++; dirty++; return false; }
      return true;
    });
    if (kept.length) keptEntries.push({ ...e, patches: kept });
    else if (!(e.patches || []).length) keptEntries.push(e); // 本来就空（不应存在），保留原样
    else console.log(`drop empty entry: ${f} ${e.id}`);
  }
  if (dirty) {
    doc.entries = keptEntries;
    const eol = raw.includes('\r\n') ? '\r\n' : '\n';
    const trailing = /\n$/.test(raw) ? eol : '';
    writeFileSync(path, JSON.stringify(doc, null, 1).replace(/\n/g, eol) + trailing, 'utf8');
    console.log(`${f}: 删除 ${dirty} 条被接管声明`);
  }
}
console.log(`\n共删除 ${removed} 条被批次接管的旧声明`);
