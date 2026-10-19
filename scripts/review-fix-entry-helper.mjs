// 第二批模式 B（attackChain 错位修正）辅助器：从库 dump 全条目基底 + 组装校验 overrides 文档。
// 用法一（dump 基底）：  node scripts/review-fix-entry-helper.mjs dump id1 id2 ... > 基底文件.json
// 用法二（组装+校验）：  node scripts/review-fix-entry-helper.mjs build 基底文件.json 产物文档.json
//   基底文件格式：{"<id>": {entry对象改好 attackChain 后的原样}, ...}
//   产物格式：{schemaVersion:1, contentStandard:3, sourceIds:[...], entries:[...]}
import { readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const mode = process.argv[2];
const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });

if (mode === 'dump') {
  const ids = process.argv.slice(3);
  const out = {};
  for (const id of ids) {
    const row = db.prepare('SELECT data FROM payloads WHERE id = ?').get(id);
    if (!row) throw new Error(`库内无此载荷 id: ${id}`);
    out[id] = JSON.parse(row.data);
  }
  process.stdout.write(JSON.stringify(out, null, 1));
  } else if (mode === 'build') {
    const [baseFile, outFile, allowArg] = process.argv.slice(3);
    // --allow tutorial,wafBypass,…：显式豁免的字段不参与"逐字节一致"守卫（有意修正场景，如 N-0019 tutorial 文本）
    const allowed = new Set((allowArg || '').startsWith('--allow=') ? allowArg.slice(8).split(',').filter(Boolean) : []);
    const base = JSON.parse(readFileSync(baseFile, 'utf8'));
    const ids = Object.keys(base);
    if (!ids.length) throw new Error('基底为空');
    const entries = ids.map(id => {
      const entry = base[id];
      const row = db.prepare('SELECT data FROM payloads WHERE id = ?').get(id);
      if (!row) throw new Error(`库内无此载荷 id: ${id}`);
      const current = JSON.parse(row.data);
      // 安全校验：未被 --allow 豁免的 strict 字段必须与库内现值逐字节一致
      const strict = ['name', 'description', 'category', 'subCategory', 'prerequisites', 'tutorial', 'analysis', 'opsecTips', 'references', 'wafBypass', 'tags', 'id'];
      for (const f of strict) {
        if (allowed.has(f)) continue;
        if (JSON.stringify(entry[f]) !== JSON.stringify(current[f])) {
          throw new Error(`${id}: 字段 ${f} 与库内不一致——如需有意修正，用 --allow=${f} 显式豁免`);
        }
      }
      if (!allowed.has('execution') && JSON.stringify(entry.execution) !== JSON.stringify(current.execution)) {
        console.warn(`WARN ${id}: execution 与库内有差异——允许（补缺失命令场景），但该 id 不得再出现在任何 payload-command-overrides 文档（后者会覆盖 execution）`);
      }
      return entry;
    }).sort((a, b) => a.id.localeCompare(b.id, 'en'));
  const doc = { schemaVersion: 1, contentStandard: 3, sourceIds: entries.map(e => e.id), entries };
  writeFileSync(outFile, JSON.stringify(doc, null, 1) + '\n', 'utf8');
  console.log(`built ${outFile}: ${entries.length} entries`);
  console.log('请再跑: node -e "JSON.parse(require(\'fs\').readFileSync(\'' + outFile + '\',\'utf8\'))" 并确认 sourceIds 与 entries 一一对应');
} else {
  throw new Error('用法: dump <id...> | build <基底.json> <产物.json>');
}
