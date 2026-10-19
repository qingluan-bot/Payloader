// 修复批次前置：扫描策展文档间"同路径重复声明"碰撞（复刻 prepareCurationOptions 的已应用过滤）
// 从项目根运行：node scripts/review-fix-collisions.mjs
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const manifest = JSON.parse(readFileSync('content-review/manifest.json', 'utf8'));
const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const toolsById = new Map(db.prepare('SELECT id, data FROM tools').all().map(r => [r.id, JSON.parse(r.data)]));
const payloadsById = new Map(db.prepare('SELECT id, data FROM payloads').all().map(r => [r.id, JSON.parse(r.data)]));

const readPath = (target, path) => {
  let cur = target;
  for (const seg of String(path || '').split('.').filter(Boolean)) {
    if (cur == null || !Object.prototype.hasOwnProperty.call(cur, seg)) return { exists: false, value: undefined };
    cur = cur[seg];
  }
  return { exists: true, value: cur };
};

// —— tool overrides：复刻过滤（value 与 live 全等或 root 集合包含 → 已应用，剔除）——
const toolSeen = new Map(); // `${id}|${path}` → [{file, value}]
for (const file of manifest.toolOverrideFiles || []) {
  const doc = JSON.parse(readFileSync(`content-review/${file}`, 'utf8'));
  for (const entry of doc.entries || []) {
    const tool = toolsById.get(entry.id);
    for (const patch of entry.patches || []) {
      const cur = readPath(tool, patch.path);
      const rootCollection = ['commands', 'references'].includes(String(patch.path || ''));
      const applied = cur.exists && (
        JSON.stringify(cur.value) === JSON.stringify(patch.value)
        || (rootCollection && Array.isArray(cur.value) && Array.isArray(patch.value)
          && patch.value.every(item => cur.value.some(c => JSON.stringify(c) === JSON.stringify(item))))
      );
      if (applied) continue;
      const key = `${entry.id}|${patch.path}`;
      if (!toolSeen.has(key)) toolSeen.set(key, []);
      toolSeen.get(key).push({ file, value: JSON.stringify(patch.value).slice(0, 160) });
    }
  }
}
console.log('=== tool overrides 重复路径（未应用态） ===');
let dupTools = 0;
for (const [key, hits] of toolSeen) {
  if (hits.length > 1) {
    dupTools += 1;
    console.log(`\n${key}`);
    for (const h of hits) console.log(`  ${h.file} → ${h.value}`);
  }
}
console.log(`tool 重复路径数: ${dupTools}`);

// —— payload command overrides：STALE/重复目标（补丁未应用且 expectedCommand 与 live 不一致）——
const poSeen = new Map(); // id → [{file, area, index, stale, expected, cmd}]
const idDocs = new Map();
for (const file of manifest.payloadCommandOverrideFiles || []) {
  const doc = JSON.parse(readFileSync(`content-review/${file}`, 'utf8'));
  for (const entry of doc.entries || []) {
    if (!idDocs.has(entry.id)) idDocs.set(entry.id, []);
    idDocs.get(entry.id).push(file);
    const p = payloadsById.get(entry.id);
    for (const patch of entry.patches || []) {
      const step = p?.[patch.area]?.[patch.index];
      const live = String(step?.command ?? '');
      const expected = String(patch.expectedCommand ?? '');
      const cmdChanged = patch.command !== undefined && String(patch.command) !== live;
      const metaOnly = patch.command === undefined;
      const metaDirty = ['title', 'description', 'syntaxBreakdown', 'platform', 'requiresAdmin', 'kind', 'effectiveness']
        .some(f => patch[f] !== undefined && JSON.stringify(step?.[f]) !== JSON.stringify(patch[f]));
      const applied = step && !cmdChanged && (metaOnly ? !metaDirty : (!metaDirty || !metaDirty));
      const pending = step && (cmdChanged || (metaOnly && metaDirty) || (!metaOnly && metaDirty));
      if (pending) {
        const key = entry.id;
        if (!poSeen.has(key)) poSeen.set(key, []);
        poSeen.get(key).push({ file, target: `${patch.area}.${patch.index}`, stale: expected !== live, expected: JSON.stringify(expected).slice(0, 100), live: JSON.stringify(live).slice(0, 100) });
      }
    }
  }
}
console.log('\n=== payload command overrides：同 id 多文档仍含未应用补丁 ===');
let dupIds = 0;
for (const [id, hits] of poSeen) {
  if (hits.length > 1) {
    dupIds += 1;
    console.log(`${id}:`);
    for (const h of hits) console.log(`  ${h.file} ${h.target} stale=${h.stale}`);
  }
}
console.log(`payload 同 id 多文档未应用: ${dupIds}`);
console.log('\n=== payload command overrides：STALE（expectedCommand 与 live 不一致但补丁未应用） ===');
let staleCount = 0;
for (const [id, hits] of poSeen) {
  for (const h of hits) {
    if (h.stale) {
      staleCount += 1;
      if (staleCount <= 30) console.log(`${id} ${h.target} (${h.file})\n  expected=${h.expected}\n  live     =${h.live}`);
    }
  }
}
console.log(`STALE 总数: ${staleCount}`);
