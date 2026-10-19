// EXP 批量导入 CLI（v2.0.3）：固定格式 JSON 文件 → 运行库。
// 通道定位：人工/第三方按公开格式手写 EXP 文件批量入库（数据文件不进仓库，仓库只带格式与工具）；
// 全网聚合走 aggregate:exp 管线，两者幂等共存（业务键互不冲突）。
//
// 用法：npm run import:exp -- <file.json> [--preview]
//   文件格式：payloader.import.v1 兼容（顶层对象含 exploits 数组），或纯 EXP 数组；
//   字段说明见 examples/exp-import-format.json 或后台"导入数据"下载的模板。
//   幂等键：条目 id > sourceRef > 名称+首个漏洞编号（重复导入不产生重复数据）；
//   条目不带 source 字段即精选层（进 public-data 与前台分类树检索面）。

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import process from 'node:process';

const args = process.argv.slice(2);
const previewOnly = args.includes('--preview');
const fileArg = args.find(item => !item.startsWith('--'));
if (!fileArg) {
  console.error('用法：npm run import:exp -- <file.json> [--preview]');
  process.exit(1);
}
const filePath = resolve(fileArg);
if (!existsSync(filePath)) {
  console.error(`文件不存在：${filePath}`);
  process.exit(1);
}

let raw;
try {
  raw = JSON.parse(readFileSync(filePath, 'utf8'));
} catch (error) {
  console.error(`JSON 解析失败：${error.message}（注意 JSON 内代码换行写 \\n，不支持注释与尾逗号）`);
  process.exit(1);
}
const entries = Array.isArray(raw) ? raw : Array.isArray(raw?.exploits) ? raw.exploits : null;
if (!entries) {
  console.error('文件形状非法：期望顶层 exploits 数组，或文件本身是 EXP 数组（见 examples/exp-import-format.json）');
  process.exit(1);
}
if (raw?.format && raw.format !== 'payloader.import.v1') {
  console.warn(`模板标识为「${raw.format}」，按 payloader.import.v1 兼容导入。`);
}

const { sanitizeExploit } = await import('../server/sanitize.mjs');
const { createUlid } = await import('../server/ulid.mjs');

// ---- 逐条校验（错误阻断 / 警告放行）----
const warnings = [];
const valid = [];
entries.forEach((entry, index) => {
  const label = `#${index + 1} ${entry?.name || '(未命名)'}`;
  if (!entry || typeof entry !== 'object') {
    console.error(`✖ ${label}：不是对象`);
    process.exit(1);
  }
  for (const field of ['name', 'description', 'vulnType', 'severity', 'publishedAt', 'prerequisites']) {
    if (!String(entry[field] ?? '').trim()) {
      console.error(`✖ ${label}：缺 ${field}`);
      process.exit(1);
    }
  }
  if (!['critical', 'high', 'medium', 'low'].includes(entry.severity)) {
    console.error(`✖ ${label}：severity 非法（${entry.severity}）`);
    process.exit(1);
  }
  if (!/^\d{4}(-\d{2})?(-\d{2})?$/.test(entry.publishedAt)) {
    console.error(`✖ ${label}：publishedAt 格式应为 YYYY / YYYY-MM / YYYY-MM-DD`);
    process.exit(1);
  }
  if (!Array.isArray(entry.exploitCode) || !entry.exploitCode.some(seg => seg?.code?.trim())) {
    console.error(`✖ ${label}：至少需要一段利用代码（exploitCode[{title,language,code}]）`);
    process.exit(1);
  }
  if (!Array.isArray(entry.references) || entry.references.length < 1) {
    console.error(`✖ ${label}：至少一条参考链接`);
    process.exit(1);
  }
  if (!Array.isArray(entry.vulnerabilityIds) || !entry.vulnerabilityIds.length) {
    warnings.push(`${label}：无漏洞编号（知识型条目，确认无 CVE/CNVD 后可接受）`);
  }
  const badRefs = (entry.references || []).filter(url => !/^https?:\/\//i.test(String(url)));
  if (badRefs.length) warnings.push(`${label}：${badRefs.length} 条非 http(s) 参考链接将被过滤`);
  valid.push(entry);
});

const { getRuntimeDbFile } = await import('../server/data-store.mjs');
const { DatabaseSync } = await import('node:sqlite');
const runtimeDbFile = getRuntimeDbFile();
if (!existsSync(runtimeDbFile)) {
  console.error(`运行库不存在：${runtimeDbFile}（先启动一次服务完成初始化）`);
  process.exit(1);
}

const database = new DatabaseSync(runtimeDbFile);

// ---- 分类树叶子集合（treePath 校验：无效警告并剔除，不阻断）----
const leafIds = new Set();
for (const row of database.prepare('SELECT tree FROM exploit_nodes').all()) {
  let tree;
  try {
    tree = JSON.parse(row.tree);
  } catch {
    continue;
  }
  const walk = nodes => (nodes || []).forEach(node => (
    Array.isArray(node.children) && node.children.length ? walk(node.children) : leafIds.add(node.id)
  ));
  walk(Array.isArray(tree) ? tree : [tree]);
}

// ---- 幂等键解析：id > sourceRef > name|首个编号 ----
const existingRows = database.prepare('SELECT id, data FROM exploits').all();
const byId = new Map();
const byKey = new Map();
existingRows.forEach(row => {
  byId.set(row.id, row);
  try {
    const data = JSON.parse(row.data);
    if (data.sourceRef) byKey.set(`ref:${data.sourceRef}`, row);
    // 名称+首个编号做业务键；无编号条目也要注册（键尾部为空），否则知识型条目幂等失效重复入库
    byKey.set(`np:${data.name}|${data.vulnerabilityIds?.[0]?.value ?? ''}`, row);
  } catch { /* 忽略坏行 */ }
});

const timestamp = new Date().toISOString();
const upsert = database.prepare(`
  INSERT INTO exploits (id, data, sort_order, enabled, created_at, updated_at)
  VALUES (?, ?, ?, 1, ?, ?)
  ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
`);
const nextSort = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM exploits');

let imported = 0;
let updated = 0;
const seenKeys = new Set();

if (previewOnly) {
  console.log(`[preview] 共 ${valid.length} 条（错误 0，警告 ${warnings.length} 条）：`);
  warnings.forEach(warning => console.warn(`  ⚠ ${warning}`));
  valid.forEach(entry => {
    const key = entry.sourceRef ? `ref:${entry.sourceRef}` : `np:${entry.name}|${entry.vulnerabilityIds?.[0]?.value ?? ''}`;
    const existing = (entry.id && byId.get(entry.id)) || byKey.get(key);
    console.log(`  - ${entry.name} [${entry.vulnType}/${entry.severity}] → ${existing ? '更新' : '新增'}`);
  });
  database.close();
  process.exit(0);
}

database.exec('BEGIN');
try {
  valid.forEach(entry => {
    const key = entry.sourceRef ? `ref:${entry.sourceRef}` : `np:${entry.name}|${entry.vulnerabilityIds?.[0]?.value ?? ''}`;
    if (seenKeys.has(key)) {
      warnings.push(`${entry.name}：文件内重复（同幂等键），后一条跳过`);
      return;
    }
    seenKeys.add(key);

    let treePath = String(entry.treePath ?? '').trim();
    if (treePath && !leafIds.has(treePath.split('/').pop())) {
      warnings.push(`${entry.name}：treePath 叶子不存在，已剔除该挂载（可在后台编辑器重新挂载）`);
      treePath = '';
    }

    const existing = (entry.id && byId.get(entry.id)) || byKey.get(key);
    const id = existing ? existing.id : `EXP-${createUlid()}`;
    const entryWithoutTreePath = { ...entry };
    delete entryWithoutTreePath.treePath;
    const normalized = sanitizeExploit({ ...entryWithoutTreePath, id, ...(treePath ? { treePath } : {}) });
    const normalizedJson = JSON.stringify(normalized);
    const existingJson = existing ? JSON.stringify(JSON.parse(existing.data)) : null;
    if (existingJson === normalizedJson) return; // 内容未变，不写
    // 更新路径：sort_order 由 ON CONFLICT 保留原值，插入占位 0 即可
    upsert.run(id, normalizedJson, existing ? 0 : nextSort.get().next, timestamp, timestamp);
    if (existing) updated += 1;
    else imported += 1;
  });
  database.exec('COMMIT');
} catch (error) {
  database.exec('ROLLBACK');
  database.close();
  throw error;
}
database.close();

console.log(`EXP 批量导入完成：新增 ${imported} 条，更新 ${updated} 条（警告 ${warnings.length} 条）`);
warnings.forEach(warning => console.warn(`  ⚠ ${warning}`));
console.log('运行库已更新。重启 Payloader 服务后生效（运行中的服务持有内存缓存）。');
