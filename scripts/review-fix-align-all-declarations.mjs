// 通用清底：所有已注册 overrides 全条目 / tool-overrides patch 声明对齐运行库终态。
// 背景：patch 应用后即被"已应用"过滤，旧文档里仍声明旧值的条目会在下一次 apply 级联回灌（无补丁拦截）。
// 对齐后所有声明进入"已应用"过滤，文档 = 运行库终态的持久镜像，apply 恒为幂等零变更。
// 注意：对齐 overrides 条目时保留原 entry.review（管线要求 review.decision 存在）。
// 从项目根运行：node scripts/review-fix-align-all-declarations.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const rtPayloadById = new Map(db.prepare('SELECT id, data FROM payloads').all().map(r => [r.id, JSON.parse(r.data)]));
const rtToolById = new Map(db.prepare('SELECT id, data FROM tools').all().map(r => [r.id, JSON.parse(r.data)]));
const manifest = JSON.parse(readFileSync('content-review/manifest.json', 'utf8'));
const readPath = (t, p) => {
  let cur = t;
  for (const seg of String(p || '').split('.').filter(Boolean)) {
    if (cur == null || !Object.prototype.hasOwnProperty.call(cur, seg)) return { exists: false, value: undefined };
    cur = cur[seg];
  }
  return { exists: true, value: cur };
};
const rootCol = new Set(['commands', 'references']);
const isAppliedPatch = (tool, patch) => {
  const cur = readPath(tool, patch.path);
  if (!cur.exists) return true; // 路径不存在的不动（apply 会报错，另有专门处理）
  if (JSON.stringify(cur.value) === JSON.stringify(patch.value)) return true;
  return rootCol.has(String(patch.path || '')) && Array.isArray(cur.value) && Array.isArray(patch.value)
    && patch.value.every(item => cur.value.some(c => JSON.stringify(c) === JSON.stringify(item)));
};

const writeBack = (f, doc) => {
  const raw = readFileSync(`content-review/${f}`, 'utf8');
  const eol = raw.includes('\r\n') ? '\r\n' : '\n';
  const trailing = /\n$/.test(raw) ? eol : '';
  writeFileSync(`content-review/${f}`, JSON.stringify(doc, null, 1).replace(/\n/g, eol) + trailing, 'utf8');
};

let entryAligned = 0, entryMissing = 0, patchAligned = 0;
for (const f of manifest.overrideFiles) {
  const path = `content-review/${f}`;
  const raw = readFileSync(path, 'utf8');
  const doc = JSON.parse(raw);
  let dirty = 0;
  for (const e of doc.entries || []) {
    const rt = rtPayloadById.get(e.id);
    if (!rt) { entryMissing++; continue; }
    const review = e.review;
    const aligned = JSON.parse(JSON.stringify(rt));
    if (review !== undefined) aligned.review = review;
    if (JSON.stringify(e) !== JSON.stringify(aligned)) {
      Object.assign(e, aligned);
      entryAligned++;
      dirty++;
    }
  }
  if (dirty) { writeBack(f, doc); console.log(`${f}: ${dirty} 条目对齐`); }
}
console.log(`overrides 条目对齐 ${entryAligned} 条（未知 id ${entryMissing} 条跳过）`);

for (const f of manifest.toolOverrideFiles) {
  const path = `content-review/${f}`;
  const raw = readFileSync(path, 'utf8');
  const doc = JSON.parse(raw);
  let dirty = 0;
  for (const e of doc.entries || []) {
    const rt = rtToolById.get(e.id);
    if (!rt) continue;
    for (const p of e.patches || []) {
      if (isAppliedPatch(rt, p)) continue;
      const cur = readPath(rt, p.path);
      p.value = JSON.parse(JSON.stringify(cur.value));
      patchAligned++;
      dirty++;
    }
  }
  if (dirty) { writeBack(f, doc); console.log(`${f}: ${dirty} patch 对齐`); }
}
console.log(`tool patch 对齐 ${patchAligned} 条`);
