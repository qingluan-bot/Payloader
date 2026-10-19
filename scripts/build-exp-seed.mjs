// EXP 策展管线（v2.0.2）：content-review/exp-*.json → 运行库 + 种子库。
// 基线快照保护管理员编辑：metadata curation_baseline_exploits 存每条 EXP 的 sha256；
// apply 时 runtime 哈希 ≠ 基线视为管理员手工编辑，保留 runtime 值并跳过策展覆盖；
// --force 跳过保护。--verify 只做内容质量校验不写库。

import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';
import { deriveProducts } from './exp-corpus/products.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const rootDir = join(scriptDir, '..');
const contentReviewDir = join(rootDir, process.env.PAYLOADER_CONTENT_REVIEW_DIR || 'content-review');
const args = new Set(process.argv.slice(2));
const force = args.has('--force');
const verifyOnly = args.has('--verify');

// ---- 载入策展源 ----
const treeSource = JSON.parse(readFileSync(join(contentReviewDir, 'exp-tree-v1.json'), 'utf8'));
const collectionSourceFiles = [
  'exp-collection-v1a.json',
  'exp-collection-v1b.json',
  'exp-collection-handwritten-2026-09.json',
];
const collection = collectionSourceFiles.flatMap(file => (
  JSON.parse(readFileSync(join(contentReviewDir, file), 'utf8'))
));

const EXPLOIT_SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const PLACEHOLDER_MARKERS = ['TODO', '待补充', '自行替换', 'FIXME', '待完善'];
const VULN_TYPE_PATTERN = /^[a-z][a-z0-9-]*$/;

const sha256 = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

// ---- 内容质量校验（verify 门禁）----
const leafIds = new Set();
(function walk(nodes) {
  nodes.forEach(node => {
    if (Array.isArray(node.children) && node.children.length) walk(node.children);
    else leafIds.add(node.id);
  });
})(treeSource.roots);

const errors = [];
const warnings = [];
const seenIds = new Set();

const assertText = (value, label) => {
  if (typeof value !== 'string' || !value.trim()) errors.push(`${label}: 缺失或为空`);
  else if (PLACEHOLDER_MARKERS.some(marker => value.includes(marker))) errors.push(`${label}: 含占位标记`);
};

collection.forEach((item, index) => {
  const label = `#${index + 1} ${item.name || '(未命名)'}`;
  if (item.id) {
    if (!/^EXP-[0-9A-HJKMNP-TV-Z]{26}$/.test(item.id)) errors.push(`${label}: id 非 EXP-<ULID> 形状`);
    if (seenIds.has(item.id)) errors.push(`${label}: id 重复`);
    seenIds.add(item.id);
  }
  assertText(item.name, `${label}.name`);
  assertText(item.description, `${label}.description`);
  assertText(item.affected, `${label}.affected`);
  assertText(item.prerequisites, `${label}.prerequisites`);
  if (!EXPLOIT_SEVERITIES.has(item.severity)) errors.push(`${label}.severity 非法: ${item.severity}`);
  if (!VULN_TYPE_PATTERN.test(item.vulnType || '')) errors.push(`${label}.vulnType 非法: ${item.vulnType}`);
  if (!/^\d{4}(-\d{2})?(-\d{2})?$/.test(item.publishedAt || '')) errors.push(`${label}.publishedAt 格式非法: ${item.publishedAt}`);
  if (!Array.isArray(item.vulnerabilityIds) || item.vulnerabilityIds.length === 0) {
    // 无编号是合法状态（默认凭据/未授权/特性滥用类知识条目无 CVE），降级为警告：
    // 前提是参考链接 ≥2 与 prerequisites 非空（独立硬校验），保证"宁缺毋错"不滑向内容空心
    warnings.push(`${label}: 无漏洞编号（知识型条目，确认无对应 CVE/CNVD 后可接受）`);
  }
  if (!Array.isArray(item.references) || item.references.length < 2) errors.push(`${label}: 参考链接至少 2 条`);
  if (!Array.isArray(item.exploitCode) || !item.exploitCode.some(seg => seg.code && seg.code.trim())) errors.push(`${label}: 至少一段利用代码`);
  const leafId = String(item.treePath || '').split('/').pop();
  if (!leafIds.has(leafId)) errors.push(`${label}.treePath 叶子不存在: ${item.treePath}`);
});

if (errors.length) {
  console.error(`EXP 内容校验失败（${errors.length} 处）：`);
  errors.forEach(error => console.error(`  ✖ ${error}`));
  process.exit(1);
}
if (warnings.length) {
  warnings.forEach(warning => console.warn(`  ⚠ ${warning}`));
}
console.log(`EXP 内容校验通过：${collection.length} 条 / ${leafIds.size} 个分类叶子（警告 ${warnings.length} 条）`);

if (verifyOnly) {
  console.log('--verify 模式：不写库，结束。');
  process.exit(0);
}

// ---- 落库（运行库 + 种子库）----
const { getRuntimeDbFile, getDefaultSeedDbFile, writeDefaultSeedDatabase, loadContentDataFromDatabase, closeStore } = await import('../server/data-store.mjs');
const { DatabaseSync } = await import('node:sqlite');
const { readMetadata, writeMetadata } = await import('../server/migrations.mjs');
const { sanitizeExploit, sanitizeExploitNode } = await import('../server/sanitize.mjs');
const json = value => JSON.stringify(value ?? null);
const { createUlid } = await import('../server/ulid.mjs');

const runtimeDbFile = getRuntimeDbFile();
if (!existsSync(runtimeDbFile)) {
  console.error(`运行库不存在：${runtimeDbFile}（先启动一次服务完成初始化）`);
  process.exit(1);
}

// 策展条目稳定 ID：以 treePath+主编号为业务键，复用已有 ULID（可重复执行）
const existingDatabase = new DatabaseSync(runtimeDbFile, { readOnly: true });
const existingByBizKey = new Map();
const existingRows = existingDatabase.prepare('SELECT id, data FROM exploits').all();
const previousBaseline = (() => {
  const raw = readMetadata(existingDatabase, 'curation_baseline_exploits');
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
})();
// 业务键 → id：优先上轮基线的 id 映射（独立于 data，导出导入回程不失明），
// 兼容旧格式的 data.curatedKey 字段
const previousIdMap = (previousBaseline && previousBaseline['@ids']) || {};
existingRows.forEach(row => {
  try {
    const data = JSON.parse(row.data);
    const key = previousIdMap[row.id] || String(data.curatedKey || '');
    if (key) existingByBizKey.set(key, row.id);
  } catch { /* 忽略坏行 */ }
});
existingDatabase.close();

// 管理员编辑保护：业务键的 runtime 哈希与上次基线不同 → 保留 runtime，跳过策展覆盖。
// baseline 结构 { bizKey: sha } + { "@ids": { id: bizKey } }——id 映射独立于条目 data，
// 导出→导入回程丢 curatedKey 字段也不会让保护失明。
const database = new DatabaseSync(runtimeDbFile);
const adminEdited = new Set();
if (previousBaseline && !force) {
  for (const row of existingRows) {
    try {
      const data = JSON.parse(row.data);
      const key = previousIdMap[row.id] || String(data.curatedKey || '');
      const expected = key ? previousBaseline[key] : null;
      if (key && expected && expected !== sha256(data)) {
        adminEdited.add(key);
      }
    } catch { /* 忽略坏行 */ }
  }
}

const timestamp = new Date().toISOString();
// 冲突更新不触 enabled：管理员隐藏（enabled=0）的策展条目重跑管线后保持隐藏
const upsertExploit = database.prepare(`
  INSERT INTO exploits (id, data, sort_order, enabled, created_at, updated_at)
  VALUES (?, ?, ?, 1, ?, ?)
  ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
`);
const nextSort = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM exploits');
const baseline = { '@ids': {} };

let applied = 0;
let kept = 0;
database.exec('BEGIN');
try {
  collection.forEach(item => {
    const bizKey = `${item.treePath}|${item.vulnerabilityIds[0]?.value ?? item.name}`;
    if (adminEdited.has(bizKey)) {
      kept += 1;
      const existingId = existingByBizKey.get(bizKey);
      const row = existingId ? database.prepare('SELECT data FROM exploits WHERE id = ?').get(existingId) : null;
      if (row) {
        baseline[bizKey] = sha256(JSON.parse(row.data));
        baseline['@ids'][existingId] = bizKey;
      }
      return;
    }
    const existingId = existingByBizKey.get(bizKey);
    const id = existingId || `EXP-${createUlid()}`;
    // 治理 B：精选层统一打 source:'curated'（此前靠缺 source 键识别精选，聚合层分层后必须显式化）
    // 治理 A5：精选层同样派生 products[]（affected 中文产品名走词典别名命中，AI 检索与
    // API product 过滤主通道）
    const normalizedName = typeof item.name === 'string' ? item.name : (item.name?.zh || item.name?.en || '');
    const normalizedDescription = typeof item.description === 'string' ? item.description : (item.description?.zh || '') + ' ' + (item.description?.en || '');
    const normalized = sanitizeExploit({
      ...item,
      id,
      source: 'curated',
      products: deriveProducts({ cpeProducts: [], name: normalizedName, description: normalizedDescription, affected: item.affected || '' }),
    });
    upsertExploit.run(id, JSON.stringify(normalized), nextSort.get().next, timestamp, timestamp);
    baseline[bizKey] = sha256(normalized);
    baseline['@ids'][id] = bizKey;
    applied += 1;
  });

  // 分类树：策展树为 EXP 域权威（管理员树编辑保护与条目同策略，v1 先全量重建树）
  const exploitIdByBizKey = new Map();
  for (const [id, key] of Object.entries(baseline['@ids'])) {
    exploitIdByBizKey.set(key, id);
  }

  const buildNode = node => {
    const clean = { id: node.id, name: node.name };
    if (Array.isArray(node.children) && node.children.length) {
      clean.children = node.children.map(buildNode);
    } else {
      // 叶子：挂载该叶子下全部策展条目（多条同叶支持）——树叶子语义为“分类位置”，
      // 实际条目枚举由前端按 treePath 聚合，这里为后台可视化写首个 exploitId 引用链
      const linked = collection
        .filter(item => item.treePath.split('/').pop() === node.id)
        .map(item => exploitIdByBizKey.get(`${item.treePath}|${item.vulnerabilityIds[0]?.value ?? item.name}`))
        .filter(Boolean);
      if (linked.length) clean.exploitIds = linked;
    }
    return clean;
  };

  // exploitId 单值字段：叶子取首个条目（前端树点击直达）；多叶条目由详情页 treePath 聚合展示
  database.prepare('DELETE FROM exploit_nodes').run();
  const insertNode = database.prepare(`
    INSERT INTO exploit_nodes (id, tree, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  const written = new Set();
  treeSource.roots.forEach((root, index) => {
    const node = buildNode(root);
    // 叶子扩展单值 exploitId（首个），供树点击直达详情
    const assignFirstExploitId = n => {
      if (n.children?.length) n.children.forEach(assignFirstExploitId);
      else if (Array.isArray(n.exploitIds) && n.exploitIds.length) n.exploitId = n.exploitIds[0];
    };
    assignFirstExploitId(node);
    let nodeId = node.id;
    if (written.has(nodeId)) nodeId = `${nodeId}-${index}`;
    written.add(nodeId);
    insertNode.run(nodeId, JSON.stringify(sanitizeExploitNode(node)), index, timestamp, timestamp);
  });
  // 基线快照写回（幂等与管理员编辑保护都依赖它，缺失会导致每轮全量新建）
  writeMetadata(database, 'curation_baseline_exploits', json(baseline));
  writeMetadata(database, 'curation_baseline_exploits_at', timestamp);
  database.exec('COMMIT');
} catch (error) {
  database.exec('ROLLBACK');
  throw error;
} finally {
  database.close();
}

console.log(`EXP 条目落库：新增/更新 ${applied} 条，管理员编辑保留 ${kept} 条`);

// ---- 重建种子库（payloads/tools/navigation 沿用运行库现状 + EXP 域替换为策展态）----
const runtimeContent = await loadContentDataFromDatabase(runtimeDbFile);
// 从运行库读回刚写入的 EXP：种子只带精选层（source='curated' 或无 source 的手工层），
// 万级聚合条目必须留在部署实例本地——种子进仓库，带聚合数据就破了硬编码红线。
const seedDatabase = new DatabaseSync(runtimeDbFile, { readOnly: true });
const exploits = seedDatabase.prepare('SELECT data FROM exploits WHERE enabled = 1 ORDER BY sort_order, id').all()
  .map(row => JSON.parse(row.data))
  .filter(data => !data.source || data.source === 'curated');
const exploitNodes = seedDatabase.prepare('SELECT tree FROM exploit_nodes WHERE enabled = 1 ORDER BY sort_order, id').all()
  .map(row => JSON.parse(row.tree));
seedDatabase.close();

await writeDefaultSeedDatabase({
  ...runtimeContent,
  exploits,
  exploitNavigation: exploitNodes,
}, getDefaultSeedDbFile(), `exp curation ${new Date().toISOString().slice(0, 10)}`);

console.log(`种子库已重建：exploits=${exploits.length} exploit_nodes=${exploitNodes.length}`);
console.log(`种子库路径：${getDefaultSeedDbFile()}`);
