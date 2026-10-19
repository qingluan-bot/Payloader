import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
// severity 全量校准（治理 F-sev）：全表逐条按 NVD 官方 CVSS 分档对齐。
// 用户原则：不评高不评低，按官方评级——多 CVE 取最严重官方档；NVD 无分的条目
// 保持现值（nuclei 官方模板档 / curated 策展档 / unknown），不编造。
// 在 aggregate-exp-corpus 落库之后调用（精选 + 聚合全表生效），幂等可重跑。

export const calibrateSeverity = (database, cveMap, { log = () => {} } = {}) => {
  const sevOf = score => (score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'unknown');
  const rows = database.prepare('SELECT id, data FROM exploits').all();
  const update = database.prepare('UPDATE exploits SET data = ? WHERE id = ?');
  let fixed = 0;
  const checkedRows = [];
  for (const row of rows) {
    let data;
    try { data = JSON.parse(row.data); } catch { continue; }
    const cves = (Array.isArray(data.vulnerabilityIds) ? data.vulnerabilityIds : [])
      .map(item => (item && item.type === 'CVE' ? String(item.value ?? '').trim().toUpperCase() : ''))
      .filter(value => /^CVE-\d{4}-\d{4,7}$/.test(value));
    if (!cves.length) continue;
    const scores = cves.map(c => cveMap.get(c)?.score).filter(s => Number.isFinite(s));
    if (!scores.length) continue;
    const official = sevOf(Math.max(...scores));
    if (data.severity === official) continue;
    checkedRows.push({ id: row.id, data: { ...data, severity: official }, before: data.severity, official });
  }
  database.exec('BEGIN');
  try {
    for (const item of checkedRows) {
      update.run(JSON.stringify(item.data), item.id);
      fixed += 1;
    }
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
  log(`[calibrate] severity 官方档对齐：核对 ${rows.length} 条，修正 ${fixed} 条`);
  return { checked: rows.length, fixed };
};

// 全量 NVD 窗口缓存 → { cve → { score } }（不经 cveSet 过滤——
// 过滤版 cveMap 会随单轮跳过的源缩水，导致大量条目漏配官方分）
export const loadNvdScoreMap = cacheDir => {
  const scoreMap = new Map();
  for (const f of readdirSync(cacheDir).filter(f => /^nvd-/.test(f))) {
    try {
      const data = JSON.parse(readFileSync(join(cacheDir, f), 'utf8'));
      for (const e of (data.entries || [])) if (e.cve && Number.isFinite(e.score)) scoreMap.set(e.cve, e.score);
    } catch {
      // 单窗口缓存损坏时跳过该文件，其余窗口继续
    }
  }
  return scoreMap;
};
