// 第二批集成补丁：overrides-campaign / overrides-payload-gov 中 5 个模式A载荷的全条目声明
// 对齐运行库终态（批次一已修复；条目级联会在每次 apply 重污染 wafBypass+attackChain，
// patches 修不回链（键不匹配）→ 计划态 dangling）。整条对齐后条目进入"已应用"被过滤。
// 从项目根运行：node scripts/review-fix-b2-align-modea-entries.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const IDS = new Set(['sqli-carrier-multipart', 'sqli-http-chunked-carrier', 'sqli-time-mysql', 'sqli-time-postgresql', 'sqli-union-query']);
const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const rtById = new Map(db.prepare('SELECT id, data FROM payloads').all().map(r => [r.id, JSON.parse(r.data)]));

for (const f of ['overrides-campaign-2026-09.json', 'overrides-payload-gov-2026-09.json']) {
  const path = `content-review/${f}`;
  const raw = readFileSync(path, 'utf8');
  const doc = JSON.parse(raw);
  let aligned = 0;
  for (const e of doc.entries || []) {
    if (!IDS.has(e.id)) continue;
    const rt = rtById.get(e.id);
    const before = JSON.stringify(e);
    Object.assign(e, JSON.parse(JSON.stringify(rt)));
    if (JSON.stringify(e) !== before) {
      aligned++;
      console.log(`${f}: ${e.id} 整条对齐运行库终态`);
    }
  }
  if (aligned) {
    const eol = raw.includes('\r\n') ? '\r\n' : '\n';
    const trailing = /\n$/.test(raw) ? eol : '';
    writeFileSync(path, JSON.stringify(doc, null, 1).replace(/\n/g, eol) + trailing, 'utf8');
  }
}
console.log('done');
