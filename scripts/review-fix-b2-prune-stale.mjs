// 第二批集成收尾：清理 payload-command-overrides 文档中被后续修订取代的旧 patch。
// 判定：同 (id, area, index) 存在多个 patch 时，保留 command===库内现值 的那条（或唯一 expected===现值 的），
// 其余（command!==现值 的旧修订）删除——它们在 apply 后会浮出为 STALE_COMMAND/NOOP_COMMAND 阻断下一次 dry-run。
// 从项目根运行：node scripts/review-fix-b2-prune-stale.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const rtById = new Map(db.prepare('SELECT id, data FROM payloads').all().map(r => [r.id, JSON.parse(r.data)]));
const manifest = JSON.parse(readFileSync('content-review/manifest.json', 'utf8'));

// 先收集全部 (id, area, index) → 各文档各 patch 的快照
const registry = new Map(); // `${id}|${area}|${index}` → [{file, entryIdx, patchIdx, patch, live}]
for (const f of manifest.payloadCommandOverrideFiles) {
  const doc = JSON.parse(readFileSync(`content-review/${f}`, 'utf8'));
  (doc.entries || []).forEach((e, entryIdx) => {
    const rt = rtById.get(e.id);
    (e.patches || []).forEach((p, patchIdx) => {
      const live = String(rt?.[p.area]?.[p.index]?.command ?? '');
      const key = `${e.id}|${p.area}|${p.index}`;
      if (!registry.has(key)) registry.set(key, []);
      registry.get(key).push({ file: f, entryIdx, patchIdx, patch: p, live });
    });
  });
}

const toDelete = new Set(); // `${file}|${entryIdx}|${patchIdx}`
let reviewed = 0;
for (const [key, items] of registry) {
  if (items.length < 2) {
    // 单 patch：若 command!==live 且 expected!==live → 真滞留（不属于被取代，报出来人工看）
    const { file, patch, live } = items[0];
    if (patch.command !== undefined && String(patch.command) !== live && String(patch.expectedCommand ?? '') !== live) {
      console.log(`单 patch 滞留（人工核）：${file} ${key}`);
    }
    continue;
  }
  reviewed++;
  const matching = items.filter(it => String(it.patch.command ?? '') === it.live);
  const expectedMatching = items.filter(it => String(it.patch.expectedCommand ?? '') === it.live);
  // 保留：command===live 的全部（已应用终值）；否则保留 expected===live 的全部（待应用）；再否则保留最后一条
  const keep = new Set(matching.length ? matching.map(it => it) : (expectedMatching.length ? expectedMatching : [items[items.length - 1]]));
  for (const it of items) {
    if (!keep.has(it)) {
      toDelete.add(`${it.file}|${it.entryIdx}|${it.patchIdx}`);
      console.log(`prune: ${it.file} ${key} patch#${it.patchIdx}（被取代的旧修订）`);
    }
  }
}

// 执行删除（按文档分组，倒序删 patch）
const byFile = new Map();
for (const key of toDelete) {
  const [f, entryIdx, patchIdx] = key.split('|');
  if (!byFile.has(f)) byFile.set(f, []);
  byFile.get(f).push([Number(entryIdx), Number(patchIdx)]);
}
for (const [f, list] of byFile) {
  const path = `content-review/${f}`;
  const raw = readFileSync(path, 'utf8');
  const doc = JSON.parse(raw);
  for (const [entryIdx, patchIdx] of list.sort((a, b) => b[1] - a[1])) {
    doc.entries[entryIdx].patches.splice(patchIdx, 1);
  }
  doc.entries = doc.entries.filter(e => (e.patches || []).length > 0);
  const eol = raw.includes('\r\n') ? '\r\n' : '\n';
  const trailing = /\n$/.test(raw) ? eol : '';
  writeFileSync(path, JSON.stringify(doc, null, 1).replace(/\n/g, eol) + trailing, 'utf8');
  console.log(`${f}: 删除 ${list.length} 条被取代 patch`);
}
console.log(`\n多 patch 目标 ${reviewed} 组复核完成，共删除 ${toDelete.size} 条`);
