// 第一批产物结构核验（合并 review 用）
import { readFileSync, existsSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const files = [
  'content-review/tool-overrides-contentfix-2026-10-b1.json',
  'content-review/payload-command-overrides-contentfix-2026-10-b1.json',
  'content-review/payload-command-overrides-contentfix-2026-10-b1-modea.json',
  'content-review/tool-overrides-contentfix-2026-10-b1-modea.json',
];
const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const payloadsById = new Map(db.prepare('SELECT id, data FROM payloads').all().map(r => [r.id, JSON.parse(r.data)]));
const toolsById = new Map(db.prepare('SELECT id, data FROM tools').all().map(r => [r.id, JSON.parse(r.data)]));
const readPath = (t, p) => {
  let cur = t;
  for (const seg of String(p || '').split('.').filter(Boolean)) {
    if (cur == null || !Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
    cur = cur[seg];
  }
  return cur;
};

let total = 0;
const seenToolPath = new Map();
const seenPayloadId = new Map();
for (const f of files) {
  if (!existsSync(f)) { console.log(`(未产出) ${f}`); continue; }
  const doc = JSON.parse(readFileSync(f, 'utf8'));
  if (doc.schemaVersion !== 1) console.log(`!! ${f}: schemaVersion=${doc.schemaVersion}`);
  const isTool = f.includes('tool-overrides');
  for (const e of doc.entries || []) {
    if (isTool) {
      const tool = toolsById.get(e.id);
      if (!tool) { console.log(`!! ${f}: 未知工具 id ${e.id}`); continue; }
      for (const p of e.patches || []) {
        total++;
        if (p.value === undefined) console.log(`!! ${f} ${e.id} ${p.path}: 缺 value`);
        if (readPath(tool, p.path) === undefined) console.log(`!! ${f} ${e.id} ${p.path}: 库内无此路径`);
        if (String(p.path).endsWith('.description') || String(p.path).includes('.description.')) {
          const v = p.value;
          if (v && typeof v === 'object' && (!v.zh || !v.en || v.zh.length < 12 || v.en.length < 30)) {
            console.log(`!! ${f} ${e.id} ${p.path}: description 双语长度不足`);
          }
        }
        const key = `${e.id}|${p.path}`;
        if (seenToolPath.has(key)) console.log(`!! 跨文档重复 tool path: ${key} (${seenToolPath.get(key)} vs ${f})`);
        seenToolPath.set(key, f);
      }
    } else {
      const payload = payloadsById.get(e.id);
      if (!payload) { console.log(`!! ${f}: 未知载荷 id ${e.id}`); continue; }
      if (seenPayloadId.has(e.id)) console.log(`!! 跨文档重复 payload id: ${e.id} (${seenPayloadId.get(e.id)} vs ${f})`);
      seenPayloadId.set(e.id, f);
      for (const p of e.patches || []) {
        total++;
        const step = payload?.[p.area]?.[p.index];
        if (!step) { console.log(`!! ${f} ${e.id} ${p.area}[${p.index}]: 越界`); continue; }
        const expected = String(p.expectedCommand ?? '');
        const live = String(step.command || '');
        if (expected !== live) console.log(`!! STALE ${f} ${e.id} ${p.area}[${p.index}]: expectedCommand 与库内不一致`);
        if (p.command !== undefined && String(p.command).trim() === '') console.log(`!! ${f} ${e.id}: 空 command`);
        if (p.command !== undefined && p.command === live) console.log(`?? NOOP ${f} ${e.id} ${p.area}[${p.index}]: command 与库内相同（需有元数据修正否则校验拒绝）`);
        if (p.requiresAdmin !== undefined && typeof p.requiresAdmin !== 'boolean') console.log(`!! ${f} ${e.id}: requiresAdmin 非布尔`);
      }
    }
  }
  console.log(`OK ${f}: ${(doc.entries || []).length} entries`);
}
console.log(`\n合计 patches: ${total}，结构核验完成（!! 为必须修，?? 为需人工确认）`);
