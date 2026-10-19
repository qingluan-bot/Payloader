// 第一批集成：旧工具文档防复活对齐——凡批次新文档（contentfix-2026-10-b1*）声明了最终值的
// toolId|path，其他已注册 tool 文档的同路径存活声明一律对齐该最终值（apply 后变成"已应用"被过滤，
// 不再复活回滚、不再互相撞 Duplicate tool override path）。
// 从项目根运行：node scripts/review-fix-b1-finalize.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const toolsById = new Map(db.prepare('SELECT id, data FROM tools').all().map(r => [r.id, JSON.parse(r.data)]));
const readPath = (t, p) => {
  let cur = t;
  for (const seg of String(p || '').split('.').filter(Boolean)) {
    if (cur == null || !Object.prototype.hasOwnProperty.call(cur, seg)) return { exists: false, value: undefined };
    cur = cur[seg];
  }
  return { exists: true, value: cur };
};
const isApplied = (cur, patch) => {
  if (!cur.exists) return false;
  if (JSON.stringify(cur.value) === JSON.stringify(patch.value)) return true;
  return ['commands', 'references'].includes(String(patch.path || '')) && Array.isArray(cur.value) && Array.isArray(patch.value)
    && patch.value.every(item => cur.value.some(c => JSON.stringify(c) === JSON.stringify(item)));
};

const batchDocs = [
  'content-review/tool-overrides-contentfix-2026-10-b1.json',
  'content-review/tool-overrides-contentfix-2026-10-b1-modea.json',
];
const finalByPath = new Map(); // `${id}|${path}` → value
for (const f of batchDocs) {
  const doc = JSON.parse(readFileSync(f, 'utf8'));
  for (const e of doc.entries || []) {
    for (const p of e.patches || []) {
      const key = `${e.id}|${p.path}`;
      if (finalByPath.has(key)) throw new Error(`批次文档内同路径冲突: ${key}`);
      finalByPath.set(key, p.value);
    }
  }
}
console.log(`批次最终值: ${finalByPath.size} 条路径`);

const oldDocs = [
  'tool-overrides.json', 'tool-overrides-qa-final-2026-09.json', 'tool-overrides-governance-2026-09.json',
  'tool-overrides-ux-2026-09.json', 'tool-overrides-cloud.json', 'tool-overrides-container.json',
  'tool-overrides-credentials.json', 'tool-overrides-ctf.json', 'tool-overrides-quality-adcs.json',
  'tool-overrides-quality-completion.json', 'tool-overrides-quality-credentials.json',
  'tool-overrides-quality-info-gathering.json', 'tool-overrides-quality-kubernetes.json',
  'tool-overrides-quality-operations.json', 'tool-overrides-reverse.json', 'tool-overrides-specialized.json',
  'tool-overrides-tunneling.json', 'tool-overrides-web.json',
];
let aligned = 0;
for (const f of oldDocs) {
  if (batchDocs.some(b => b.endsWith(f))) continue;
  const path = `content-review/${f}`;
  if (!existsSyncAll(path)) continue;
  const raw = readFileSync(path, 'utf8');
  const doc = JSON.parse(raw);
  let dirty = 0;
  for (const e of doc.entries || []) {
    for (const p of e.patches || []) {
      const key = `${e.id}|${p.path}`;
      if (!finalByPath.has(key)) continue;
      if (JSON.stringify(p.value) === JSON.stringify(finalByPath.get(key))) continue;
      p.value = finalByPath.get(key);
      dirty++;
      aligned++;
      console.log(`aligned: ${f} ${key}`);
    }
  }
  if (dirty) {
    const eol = raw.includes('\r\n') ? '\r\n' : '\n';
    const trailing = /\n$/.test(raw) ? eol : '';
    writeFileSync(path, JSON.stringify(doc, null, 1).replace(/\n/g, eol) + trailing, 'utf8');
  }
}
function existsSyncAll(p) { try { readFileSync(p); return true; } catch { return false; } }
console.log(`\n共对齐 ${aligned} 条旧文档声明到批次最终值`);

// 复核：全部已注册 tool 文档两两无同路径存活冲突
const manifest = JSON.parse(readFileSync('content-review/manifest.json', 'utf8'));
const alive = new Map();
let conflicts = 0;
for (const f of manifest.toolOverrideFiles) {
  const doc = JSON.parse(readFileSync(`content-review/${f}`, 'utf8'));
  for (const e of doc.entries || []) {
    const tool = toolsById.get(e.id);
    for (const p of e.patches || []) {
      if (isApplied(readPath(tool, p.path), p)) continue;
      const key = `${e.id}|${p.path}`;
      if (alive.has(key)) { conflicts++; console.log(`冲突残留: ${key} @ ${alive.get(key)} + ${f}`); }
      alive.set(key, f);
    }
  }
}
console.log(conflicts ? `存活冲突 ${conflicts} 处——需继续处理` : '存活冲突 0 处 ✓');
