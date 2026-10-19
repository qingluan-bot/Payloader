// 修复批次前置：把 35 处滞后策展声明对齐到运行库现值（防 apply 时回滚既成事实/下次 apply 复活）。
// 载荷侧：只改级联胜出（manifest 顺序最后声明该 id）文档 entry 的差异字段；
// 工具侧：受影响工具的全部存活 patch value 对齐运行库对应路径现值（变成"已应用"被过滤）。
// 写盘自检：JSON.parse(新原文) 必须 deep-equal（clone(原 doc) + 同样变更），证明除目标值外零语义变化。
// 从项目根运行：node scripts/review-fix-align-stale.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const load = f => JSON.parse(readFileSync(`content-review/${f}`, 'utf8'));
const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const rtPayloadById = new Map(db.prepare('SELECT id, data FROM payloads').all().map(r => [r.id, JSON.parse(r.data)]));
const rtToolById = new Map(db.prepare('SELECT id, data FROM tools').all().map(r => [r.id, JSON.parse(r.data)]));
const manifest = JSON.parse(readFileSync('content-review/manifest.json', 'utf8'));

const readPath = (target, p) => {
  let cur = target;
  for (const seg of String(p || '').split('.').filter(Boolean)) {
    if (cur == null || !Object.prototype.hasOwnProperty.call(cur, seg)) return { exists: false, value: undefined };
    cur = cur[seg];
  }
  return { exists: true, value: cur };
};
const rootCol = new Set(['commands', 'references']);
const isApplied = (cur, patch) => {
  if (!cur.exists) return false;
  if (JSON.stringify(cur.value) === JSON.stringify(patch.value)) return true;
  return rootCol.has(String(patch.path || '')) && Array.isArray(cur.value) && Array.isArray(patch.value)
    && patch.value.every(item => cur.value.some(c => JSON.stringify(c) === JSON.stringify(item)));
};

const pendingChanges = []; // {file, kind:'payload'|'tool', id, fieldOrPath, oldValue, newValue}

// ---------- 载荷：找每个差异 id 的级联胜出文档，把差异字段对齐 runtime ----------
const payloadDiffTargets = {
  'ssrf-gopher': ['opsecTips'], 'rce-deserialize': ['opsecTips'], 'rce-file-upload': ['opsecTips'],
  'websocket-cross-origin-boundary': ['category'], 'websocket-channel-authorization-boundary': ['category'],
  'lateral-winrm': ['category'], 'lateral-ssh': ['category'], 'lateral-winrs': ['category'],
  'windows-privesc': ['category'], 'linux-privesc': ['category'], 'kernel-exploit': ['category'],
  'process-injection': ['category'], 'applocker-bypass': ['category'], 'exchange-mailbox-access': ['category'],
  'unattended-creds': ['category'], 'potato-attack': ['category'], 'bizlogic-coupon-enumeration': ['category'],
  'ssrf2-git': ['category'], 'ssrf2-svn': ['category'], 'ssrf2-build-file-exposure': ['category'],
};
const winnerDocOf = new Map(); // id → file（manifest 顺序最后声明者）
for (const f of manifest.overrideFiles) {
  const doc = load(f);
  for (const entry of doc.entries || []) {
    if (payloadDiffTargets[entry.id]) winnerDocOf.set(entry.id, f);
  }
}
const editsByFile = new Map(); // file → Map(id → {field: newValue})
for (const [id, fields] of Object.entries(payloadDiffTargets)) {
  const winnerFile = winnerDocOf.get(id);
  if (!winnerFile) throw new Error(`无文档声明 ${id}，但 dry-run 存在差异——中止`);
  const doc = load(winnerFile);
  const entry = (doc.entries || []).find(e => e.id === id);
  const rt = rtPayloadById.get(id);
  for (const field of fields) {
    const rtValue = rt[field];
    if (JSON.stringify(entry[field]) === JSON.stringify(rtValue)) continue; // 胜出文档已是终值（差异来自更早文档被覆盖前的暂态——不应发生，防御性跳过）
    if (!editsByFile.has(winnerFile)) editsByFile.set(winnerFile, new Map());
    if (!editsByFile.get(winnerFile).has(id)) editsByFile.get(winnerFile).set(id, {});
    editsByFile.get(winnerFile).get(id)[field] = rtValue;
    pendingChanges.push({ file: winnerFile, kind: 'payload', id, fieldOrPath: field, oldValue: entry[field], newValue: rtValue });
    entry[field] = rtValue;
  }
}

// ---------- 工具：受影响 id 的全部存活 patch 对齐 runtime ----------
const affectedTools = new Set(['gobuster', 'bash-reverse', 'python-reverse', 'powershell-reverse', 'nc-reverse', 'amass',
  'php-reverse', 'perl-reverse', 'ruby-reverse', 'lua-reverse', 'awk-reverse', 'powerview-adrecon',
  'post-exploitation-linux', 'evasion-techniques', 'network-diagnostics-toolkit']);
for (const f of manifest.toolOverrideFiles) {
  const doc = load(f);
  let docDirty = false;
  for (const entry of doc.entries || []) {
    if (!affectedTools.has(entry.id)) continue;
    const rt = rtToolById.get(entry.id);
    for (const patch of entry.patches || []) {
      const cur = readPath(rt, patch.path);
      if (!cur.exists) throw new Error(`${f} ${entry.id} ${patch.path}: 运行库无此路径`);
      if (isApplied(cur, patch)) continue;
      if (patch.op && patch.op !== 'replace') throw new Error(`${f} ${entry.id} ${patch.path}: op=${patch.op} 不支持自动对齐，人工处理`);
      pendingChanges.push({ file: f, kind: 'tool', id: entry.id, fieldOrPath: patch.path, oldValue: patch.value, newValue: cur.value });
      patch.value = cur.value;
      docDirty = true;
    }
  }
  if (docDirty) {
    if (!editsByFile.has(f)) editsByFile.set(f, new Map());
    editsByFile.get(f).set(`__toolDoc__${f}`, { __raw: doc });
  }
}

// ---------- 写盘（格式：indent 1 + 原 EOL + 原尾行；语义自检） ----------
const serialize = (doc, raw) => {
  const eol = raw.includes('\r\n') ? '\r\n' : '\n';
  const trailing = /\n$/.test(raw) ? eol : '';
  return JSON.stringify(doc, null, 1).replace(/\n/g, eol) + trailing;
};
const filesToWrite = new Set();
for (const [f, idMap] of editsByFile) filesToWrite.add(f);
for (const c of pendingChanges) filesToWrite.add(c.file);
for (const f of filesToWrite) {
  const raw = readFileSync(`content-review/${f}`, 'utf8');
  const original = JSON.parse(raw);
  // 重建期望语义：对 original 应用与本脚本相同的变更
  const expected = structuredClone(original);
  for (const c of pendingChanges.filter(c => c.file === f)) {
    if (c.kind === 'payload') {
      const entry = (expected.entries || []).find(e => e.id === c.id);
      entry[c.fieldOrPath] = c.newValue;
    } else {
      const entry = (expected.entries || []).find(e => e.id === c.id);
      const patch = entry.patches.find(p => p.path === c.fieldOrPath);
      patch.value = c.newValue;
    }
  }
  const doc = load(f);
  for (const c of pendingChanges.filter(c => c.file === f)) {
    if (c.kind === 'payload') {
      const entry = (doc.entries || []).find(e => e.id === c.id);
      entry[c.fieldOrPath] = c.newValue;
    } else {
      const entry = (doc.entries || []).find(e => e.id === c.id);
      const patch = entry.patches.find(p => p.path === c.fieldOrPath);
      patch.value = c.newValue;
    }
  }
  const out = serialize(doc, raw);
  const afterParse = JSON.parse(out);
  const deepEq = JSON.stringify(afterParse) === JSON.stringify(expected);
  if (!deepEq) throw new Error(`${f}: 写盘语义自检失败（变更集与预期不一致），未写盘`);
  const semanticUnchanged = JSON.stringify(afterParse) === JSON.stringify(original);
  writeFileSync(`content-review/${f}`, out, 'utf8');
  console.log(`${f}: 已写盘（${semanticUnchanged ? '纯格式' : '含值变更'}，EOL=${raw.includes('\r\n') ? 'CRLF' : 'LF'}）`);
}
console.log(`\n共 ${pendingChanges.length} 处声明已对齐运行库现值`);
for (const c of pendingChanges) console.log(`  [${c.kind}] ${c.file} ${c.id} ${c.fieldOrPath}`);
