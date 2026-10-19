// 修复批次前置：列出 dry-run 计划变更的逐条字段差异（防不明变更裹挟落库）
// 从项目根运行：node scripts/review-fix-planned-diff.mjs
import { loadCurationSnapshot, loadReviewConfiguration, prepareCurationOptions, curateDatabase } from './apply-payload-curation.mjs';

const source = loadCurationSnapshot('data/payloader.sqlite');
const configuration = await loadReviewConfiguration('content-review');
const curationOptions = prepareCurationOptions(configuration, source.payloads, source.tools);
const dryRun = await curateDatabase('data/payloader.sqlite', { ...configuration, backupDir: 'data/backups' });

const beforeById = new Map(source.payloads.map(p => [p.id, p]));
const fields = ['name', 'description', 'category', 'subCategory', 'prerequisites', 'tutorial', 'attackChain', 'analysis', 'opsecTips', 'references', 'wafBypass', 'tags', 'execution', 'platform', 'requiresAdmin'];

console.log(`=== payloads 计划变更 ${dryRun.snapshot.payloads.length - source.payloads.length + countChanged()} 条中实际内容有差异的 ===`);
function countChanged() { return 0; }
for (const after of dryRun.snapshot.payloads) {
  const before = beforeById.get(after.id);
  if (!before) { console.log(`[新增] ${after.id}`); continue; }
  const diffs = fields.filter(f => JSON.stringify(before[f]) !== JSON.stringify(after[f]));
  if (diffs.length) console.log(`${after.id}: ${diffs.join(', ')}`);
}
const beforeAfterIds = new Set(source.payloads.map(p => p.id));
for (const before of source.payloads) {
  if (!dryRun.snapshot.payloads.some(p => p.id === before.id)) console.log(`[移除] ${before.id}`);
}

const beforeTools = new Map(source.tools.map(t => [t.id, t]));
console.log('\n=== tools 计划变更 ===');
for (const after of dryRun.snapshot.tools) {
  const before = beforeTools.get(after.id);
  if (!before) { console.log(`[新增] ${after.id}`); continue; }
  const diffs = ['description', 'installation', 'commands', 'references', 'platform'].filter(f => JSON.stringify(before[f]) !== JSON.stringify(after[f]));
  if (diffs.length) console.log(`${after.id}: ${diffs.join(', ')}`);
}
