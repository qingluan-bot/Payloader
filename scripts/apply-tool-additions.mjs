// Lane B4 工具补缺落库（v2.0.2 治理 D）：content-review/tool-additions-governance-2026-09.json
// → 运行库 + 种子库。幂等：id 已存在即跳过（不覆盖管理员编辑），新增操作天然可重放。
// 用法：node scripts/apply-tool-additions.mjs [--verify]
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const rootDir = join(scriptDir, '..');
const verifyOnly = process.argv.includes('--verify');
const sourceFile = join(rootDir, 'content-review', 'tool-additions-governance-2026-09.json');
const additions = JSON.parse(readFileSync(sourceFile, 'utf8'));
if (!Array.isArray(additions) || !additions.length) throw new Error('补缺产物为空或形状非法');

const { getRuntimeDbFile, getDefaultSeedDbFile, writeDefaultSeedDatabase, loadContentDataFromDatabase } = await import('../server/data-store.mjs');
const { DatabaseSync } = await import('node:sqlite');
const { sanitizeTool } = await import('../server/sanitize.mjs');

// JSON.parse 门禁（AGENTS.md 红线：策展产物落库前必过）
for (const item of additions) JSON.parse(JSON.stringify(item));

const runtimeDbFile = getRuntimeDbFile();
if (!existsSync(runtimeDbFile)) {
  console.error(`运行库不存在：${runtimeDbFile}`);
  process.exit(1);
}
const database = new DatabaseSync(runtimeDbFile);
const existing = new Set(database.prepare('SELECT id FROM tools').all().map(row => row.id));
const newTools = additions.filter(item => !existing.has(item.id));
console.log(`补缺工具：产物 ${additions.length} 条，库内缺失 ${newTools.length} 条（已存在跳过 ${additions.length - newTools.length}）`);
if (verifyOnly) {
  newTools.forEach(item => console.log(`  + ${item.id}（${item.category?.zh || '?'} / ${(item.commands || []).length} 条命令）`));
  process.exit(0);
}

const timestamp = new Date().toISOString();
const upsert = database.prepare(`
  INSERT INTO tools (id, data, sort_order, enabled, created_at, updated_at)
  VALUES (?, ?, ?, 1, ?, ?)
`);
database.exec('BEGIN');
try {
  let nextSort = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM tools').get().next;
  for (const item of newTools) {
    const normalized = sanitizeTool(item);
    upsert.run(normalized.id, JSON.stringify(normalized), nextSort, timestamp, timestamp);
    nextSort += 1;
    console.log(`  + 落库 ${normalized.id}`);
  }
  database.exec('COMMIT');
} catch (error) {
  database.exec('ROLLBACK');
  throw error;
} finally {
  database.close();
}

// 种子库同步：运行库工具全量重刷（种子含新增工具，硬编码红线只约束 EXP 聚合层，工具是策展内容可入库）
const runtimeContent = await loadContentDataFromDatabase(runtimeDbFile);
await writeDefaultSeedDatabase(runtimeContent, getDefaultSeedDbFile(), `tool additions ${timestamp.slice(0, 10)}`);
console.log('种子库已同步。');
