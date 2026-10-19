// 聚合条目幂等落库：业务键 edb:<EDB-ID>，基线 metadata aggregation_baseline_exploits
// 复用策展管线模式（sha256 保护管理员编辑；--force 覆盖；upsert 不触碰 enabled——
// 管理员隐藏的聚合条目重跑后保持隐藏）。

import { createHash } from 'node:crypto';
import { readMetadata, writeMetadata } from '../../server/migrations.mjs';
import { sanitizeExploit } from '../../server/sanitize.mjs';
import { createUlid } from '../../server/ulid.mjs';

export const AGGREGATION_BASELINE_KEY = 'aggregation_baseline_exploits';

const sha256 = value => createHash('sha256').update(value).digest('hex');

const readBaseline = database => {
  const raw = readMetadata(database, AGGREGATION_BASELINE_KEY);
  if (!raw) return { hashes: {}, ids: {} };
  try {
    const parsed = JSON.parse(raw);
    return { hashes: parsed.hashes || {}, ids: parsed['@ids'] || {} };
  } catch {
    return { hashes: {}, ids: {} };
  }
};

// database: 已建表（exploits + metadata）的 node:sqlite DatabaseSync
// pairs: [{ bizKey, exploit }]（buildExploitModels 产物，exploit 为 sanitizeExploit 入参形状）
// options.reconcile（默认 true，治理 A7）：按本轮覆盖的 sourceRef 前缀做全量对账——
//   库中该前缀下、不属于本轮 id 集合的行删除（含 enabled=0）。业务键规则收紧后
//   旧行无兜底会残留（gh-poc 准入收紧后 6979 条噪音的清理就靠这一步），未跑的源不受影响。
// 返回统计 { imported, updated, unchanged, keptAdmin, deletedBySource }
export const applyExploitModels = (database, pairs, { force = false, reconcile = true } = {}) => {
  const previous = readBaseline(database);
  const idToKey = new Map(Object.entries(previous.ids).map(([id, key]) => [id, key]));
  const keyToId = new Map();
  const baselineKeyByRowId = new Map(); // rowId → bizKey（A7 对账删除时回滚基线的反查表）
  const runtimeJson = new Map();
  database.prepare('SELECT id, data FROM exploits').all().forEach(row => {
    runtimeJson.set(row.id, row.data);
    const key = idToKey.get(row.id) || (() => {
      try {
        const data = JSON.parse(row.data);
        return typeof data.sourceRef === 'string' && data.sourceRef.startsWith('edb-')
          ? `edb:${data.sourceRef.slice(4)}`
          : '';
      } catch {
        return '';
      }
    })();
    if (key) {
      keyToId.set(key, row.id);
      idToKey.set(row.id, key);
      baselineKeyByRowId.set(row.id, key);
    }
  });

  const adminEdited = new Set();
  if (!force) {
    for (const [key, id] of keyToId) {
      const expected = previous.hashes[key];
      const data = runtimeJson.get(id);
      if (expected && data && expected !== sha256(data)) adminEdited.add(key);
    }
  }

  const upsert = database.prepare(`
    INSERT INTO exploits (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
  `);
  const maxRow = database.prepare('SELECT COALESCE(MAX(sort_order), -1) AS next FROM exploits').get();
  let nextSort = maxRow.next;
  const timestamp = new Date().toISOString();
  const nextBaseline = { hashes: { ...previous.hashes }, ids: { ...previous.ids } };

  const stats = { imported: 0, updated: 0, unchanged: 0, keptAdmin: 0, skippedHidden: 0, skippedAdmin: 0, deletedBySource: {} };
  // 治理 A7 对账索引：本轮管理的行 id → sourceRef 前缀（edb/ghpoc/msf/nuclei）
  const pairByBizKey = new Map(pairs.map(pair => [pair.bizKey, pair]));
  const prefixOfRef = ref => {
    const value = typeof ref === 'string' ? ref.trim() : '';
    return value ? value.split('-')[0] : '';
  };
  const managedPrefixByRowId = new Map();
  for (const [bizKey, rowId] of keyToId) {
    const prefix = prefixOfRef(pairByBizKey.get(bizKey)?.exploit?.sourceRef);
    if (prefix) managedPrefixByRowId.set(rowId, prefix);
  }
  database.exec('BEGIN');
  try {
    pairs.forEach(({ bizKey, exploit }) => {
      const existingId = keyToId.get(bizKey);
      const existingData = existingId ? runtimeJson.get(existingId) : null;
      // 基线记录永远延续（含本轮未覆盖的历史业务键），防止下轮管理员保护失明
      if (existingId) nextBaseline.ids[existingId] = bizKey;
      if (existingId && adminEdited.has(bizKey)) {
        stats.keptAdmin += 1;
        nextBaseline.hashes[bizKey] = sha256(existingData);
        return;
      }
      const id = existingId || `EXP-${createUlid()}`;
      const normalized = sanitizeExploit({ ...exploit, id });
      const normalizedJson = JSON.stringify(normalized);
      if (existingData === normalizedJson) {
        stats.unchanged += 1;
        nextBaseline.hashes[bizKey] = sha256(existingData);
        return;
      }
      nextSort += 1;
      upsert.run(id, normalizedJson, nextSort, timestamp, timestamp);
      nextBaseline.hashes[bizKey] = sha256(normalizedJson);
      nextBaseline.ids[id] = bizKey;
      const prefix = prefixOfRef(normalized.sourceRef);
      if (prefix) managedPrefixByRowId.set(id, prefix);
      if (existingId) stats.updated += 1;
      else stats.imported += 1;
    });
    // 治理 A7：按本轮覆盖的 sourceRef 前缀全量对账——库中该前缀下、不归本轮管理的行删除。
    // 隐藏（enabled=0）与管理员编辑行是墓碑：跳过删除且不复活——否则对账删行后源重收录会以
    // enabled=1 INSERT，静默撤销管理员的隐藏/编辑（安全动作）。精选/手工层无聚合前缀 sourceRef，
    // 任何前缀都匹配不到，天然不受影响。
    if (reconcile && managedPrefixByRowId.size) {
      const prefixes = new Set(managedPrefixByRowId.values());
      const stale = [];
      for (const row of database.prepare('SELECT id, data, enabled FROM exploits').all()) {
        if (managedPrefixByRowId.has(row.id)) continue;
        if (row.enabled === 0) {
          stats.skippedHidden += 1;
          continue;
        }
        const tombstoneKey = baselineKeyByRowId.get(row.id);
        if (tombstoneKey && adminEdited.has(tombstoneKey)) {
          stats.skippedAdmin += 1;
          continue;
        }
        let prefix = '';
        try {
          prefix = prefixOfRef(JSON.parse(row.data)?.sourceRef);
        } catch {
          prefix = '';
        }
        if (prefix && prefixes.has(prefix)) stale.push({ id: row.id, prefix });
      }
      const deleteRow = database.prepare('DELETE FROM exploits WHERE id = ?');
      for (const { id, prefix } of stale) {
        deleteRow.run(id);
        const hashKey = baselineKeyByRowId.get(id);
        if (hashKey) {
          delete nextBaseline.hashes[hashKey];
          delete nextBaseline.ids[id];
          keyToId.delete(hashKey);
          baselineKeyByRowId.delete(id);
        }
        stats.deletedBySource[prefix] = (stats.deletedBySource[prefix] || 0) + 1;
      }
    }
    writeMetadata(database, AGGREGATION_BASELINE_KEY, JSON.stringify({ hashes: nextBaseline.hashes, '@ids': nextBaseline.ids }));
    writeMetadata(database, 'aggregation_baseline_exploits_at', timestamp);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
  return stats;
};
