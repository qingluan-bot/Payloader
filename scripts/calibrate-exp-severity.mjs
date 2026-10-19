// severity 官方档校准 CLI（可独立于 aggregate 重跑）：NVD 全量窗口缓存 → 运行库全表对齐。
// 用法：npm run calibrate:exp
import { DatabaseSync } from 'node:sqlite';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { calibrateSeverity } from './exp-corpus/calibrate.mjs';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(rootDir, 'data', 'exp-corpus', 'cache');
const runtimeDbFile = process.env.PAYLOADER_DB || join(rootDir, 'data', 'payloader.sqlite');
if (!existsSync(runtimeDbFile)) {
  console.error();
  process.exit(1);
}

console.log('[calibrate] 载入 NVD 全量窗口缓存…');
const cveMap = new Map();
for (const f of readdirSync(cacheDir).filter(f => /^nvd-/.test(f))) {
  try {
    const data = JSON.parse(readFileSync(join(cacheDir, f), 'utf8'));
    for (const e of (data.entries || [])) {
      if (e.cve && Number.isFinite(e.score)) cveMap.set(e.cve, { score: e.score, cwe: e.cwe || '', products: e.products || [], description: e.description || '' });
    }
  } catch {}
}
console.log();

const database = new DatabaseSync(runtimeDbFile);
const stats = calibrateSeverity(database, cveMap, { log: msg => console.log(msg) });
database.close();
console.log();
