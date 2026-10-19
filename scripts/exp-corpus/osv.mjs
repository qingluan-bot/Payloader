// OSV.dev 补源模块：CVE→GHSA 互查（GET /v1/vulns/{id}，aliases 互认）。
// 2026-09-27 实测：querybatch 不接受 CVE 主键（400），逐条 GET 可行且官方无速率限制；
// 管线限并发 8、失败超阈值即中止（GHSA 是补源，失败降级不影响入库）。
// 结果落 JSON 缓存（cve→ghsa 全量），重跑只查增量。

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { OSV_CONCURRENCY, OSV_VULN_URL } from './sources.mjs';

const sleep = ms => new Promise(resolve => { setTimeout(resolve, ms); });

export const fetchGhsaMap = async (cveList, {
  fetchImpl = fetch,
  concurrency = OSV_CONCURRENCY,
  maxFailures = 20,
  cacheFile = '',
  log = () => {},
} = {}) => {
  const map = new Map();
  if (cacheFile && existsSync(cacheFile)) {
    try {
      Object.entries(JSON.parse(readFileSync(cacheFile, 'utf8'))).forEach(([cve, ghsa]) => map.set(cve, ghsa));
    } catch {
      log('  OSV 缓存损坏，重建索引');
    }
  }
  const pending = cveList.filter(cve => !map.has(cve));
  if (!pending.length) return map;

  let cursor = 0;
  let failures = 0;
  let loggedOnce = false;
  const worker = async () => {
    while (cursor < pending.length && failures < maxFailures) {
      const cve = pending[cursor];
      cursor += 1;
      try {
        // 30s 超时：fetch 默认无超时，死连接会挂住整个 worker 池（实测咬过）
        const response = await fetchImpl(`${OSV_VULN_URL}/${cve}`, { signal: AbortSignal.timeout(30_000) });
        if (response.status === 404) {
          // OSV 无该 CVE 记录是正常状态（老编号/未收录），不算失败
          continue;
        }
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (typeof data.id === 'string' && data.id.startsWith('GHSA-')) {
          map.set(cve, data.id);
        } else {
          const alias = (data.aliases || []).find(item => typeof item === 'string' && item.startsWith('GHSA-'));
          if (alias) map.set(cve, alias);
        }
      } catch (error) {
        failures += 1;
        if (!loggedOnce) {
          log(`  OSV 查询失败（${cve}：${error.message}），失败超 ${maxFailures} 条将中止 GHSA 补充`);
          loggedOnce = true;
        }
        await sleep(500);
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));

  if (cacheFile && map.size) {
    try {
      writeFileSync(cacheFile, JSON.stringify(Object.fromEntries(map)));
    } catch (error) {
      log(`  OSV 缓存写入失败：${error.message}`);
    }
  }
  return map;
};
