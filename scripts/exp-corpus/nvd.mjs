// NVD API 2.0 补源模块：按 120 天窗口全量拉取 CVE → { CVSS, CWE, CPE 产品 } 映射。
// 速率与窗口约束为 2026-09-27 行为实证（121 天/2001 条均 404；限速超限 403）。
// 每窗口落 JSONL 缓存，重跑只补缺失窗口（增量续传）。

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { NVD_API_URL, NVD_MAX_WINDOW_DAYS, NVD_PAGE_SIZE } from './sources.mjs';

const DAY_MS = 24 * 60 * 60 * 1000;

const isoOf = ms => new Date(ms).toISOString().replace('Z', '');

const sleep = ms => new Promise(resolve => { setTimeout(resolve, ms); });

// 六年 → ≤120 天窗口序列（[startMs, endMs]，闭区间）
export const buildWindows = (sinceMs, untilMs) => {
  const windows = [];
  let start = sinceMs;
  while (start <= untilMs) {
    const end = Math.min(start + NVD_MAX_WINDOW_DAYS * DAY_MS - 1, untilMs);
    windows.push([start, end]);
    start = end + 1;
  }
  return windows;
};

// 单条 CVE 记录 → 映射条目；CVSS 优先级 V4.0 > V3.1 > V3.0 > V2（Primary 优先）
export const extractCveEntry = cveRecord => {
  const metrics = cveRecord.metrics || {};
  const metricGroups = [
    metrics.cvssMetricV40 || [],
    metrics.cvssMetricV31 || [],
    metrics.cvssMetricV30 || [],
    metrics.cvssMetricV2 || [],
  ];
  let score;
  for (const group of metricGroups) {
    if (!group.length) continue;
    const primary = group.find(item => item.type === 'Primary') || group[0];
    const value = primary?.cvssData?.baseScore;
    if (Number.isFinite(value)) {
      score = value;
      break;
    }
  }
  const weaknesses = cveRecord.weaknesses || [];
  let cwe = '';
  for (const weakness of weaknesses) {
    const value = (weakness.description || []).find(item => item.value && !item.value.startsWith('NVD-CWE'))?.value;
    if (value) {
      cwe = value;
      break;
    }
  }
  const products = new Set();
  for (const configuration of cveRecord.configurations || []) {
    for (const node of configuration.nodes || []) {
      for (const match of node.cpeMatch || []) {
        if (match.vulnerable !== true) continue;
        const parts = String(match.criteria || '').split(':');
        if (parts.length > 4 && parts[3] && parts[4]) products.add(`${parts[3]}:${parts[4]}`);
      }
    }
  }
  return {
    score: score ?? null,
    cwe,
    products: [...products].slice(0, 20),
    // 治理 A1：CVE 官方公开日期（YYYY-MM-DD），gh-poc 无仓库时间戳时的真实时间锚点
    published: String(cveRecord.published ?? '').slice(0, 10),
  };
};

const fetchJsonWithRetry = async (url, { headers = {}, fetchImpl, retryDelayMs, attempts = 3, log }) => {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const response = await fetchImpl(url, { headers });
    if (response.ok) return response.json();
    if (response.status === 403 || response.status === 429 || response.status >= 500) {
      if (attempt === attempts) throw new Error(`NVD HTTP ${response.status}（重试 ${attempts} 次后放弃）`);
      log(`  NVD HTTP ${response.status}，${Math.round(retryDelayMs / 1000)}s 后重试（${attempt}/${attempts - 1}）`);
      await sleep(retryDelayMs);
      continue;
    }
    throw new Error(`NVD HTTP ${response.status}：${url}`);
  }
  throw new Error('unreachable');
};

// 主入口：返回 { cveMap, windowsFetched, windowsCached, entries }
// cveSet：EDB 侧 CVE 集合（小写），命中才入库映射，控制缓存体积
export const buildNvdCveMap = async ({
  sinceMs,
  untilMs = Date.now(),
  cveSet,
  cacheDir,
  apiKey = process.env.PAYLOADER_NVD_API_KEY || '',
  fetchImpl = fetch,
  log = () => {},
}) => {
  const headers = apiKey ? { apiKey } : {};
  const paceMs = apiKey ? 700 : 6200;
  const cveMap = new Map();
  const windows = buildWindows(sinceMs, untilMs);
  let windowsFetched = 0;
  let windowsCached = 0;
  let windowsFailed = 0;
  for (const [startMs, endMs] of windows) {
    const cacheFile = join(cacheDir, `nvd-${isoOf(startMs).slice(0, 10)}_${isoOf(endMs).slice(0, 10)}.json`);
    if (existsSync(cacheFile)) {
      const cached = JSON.parse(readFileSync(cacheFile, 'utf8'));
      cached.entries.forEach(entry => cveMap.set(entry.cve, entry));
      windowsCached += 1;
      continue;
    }
    const entries = [];
    let startIndex = 0;
    let totalResults = Infinity;
    try {
      while (startIndex < totalResults) {
        const url = `${NVD_API_URL}?pubStartDate=${encodeURIComponent(isoOf(startMs))}&pubEndDate=${encodeURIComponent(isoOf(endMs))}&resultsPerPage=${NVD_PAGE_SIZE}&startIndex=${startIndex}`;
        const data = await fetchJsonWithRetry(url, { headers, fetchImpl, retryDelayMs: 31_000, log });
        totalResults = data.totalResults ?? 0;
        for (const item of data.vulnerabilities || []) {
          const cve = item.cve?.id || '';
          if (!cve || (cveSet && !cveSet.has(cve.toLowerCase()))) continue;
          const entry = extractCveEntry(item.cve);
          entries.push({ cve, ...entry });
          cveMap.set(cve, entry);
        }
        startIndex += NVD_PAGE_SIZE;
        if (startIndex < totalResults) await sleep(paceMs);
      }
    } catch (error) {
      // 按窗口降级：失败窗口跳过（磁盘无缓存），已命中窗口的结果保留，不拖垮整轮
      windowsFailed += 1;
      log(`  NVD 窗口 ${isoOf(startMs).slice(0, 10)} ~ ${isoOf(endMs).slice(0, 10)} 失败跳过：${error.message}`);
      await sleep(paceMs);
      continue;
    }
    writeFileSync(cacheFile, JSON.stringify({ startMs, endMs, entries }));
    windowsFetched += 1;
    log(`  NVD 窗口 ${isoOf(startMs).slice(0, 10)} ~ ${isoOf(endMs).slice(0, 10)}：${entries.length} 条命中（累计 ${cveMap.size}）`);
    await sleep(paceMs);
  }
  return { cveMap, windowsFetched, windowsCached, windowsFailed, entries: cveMap.size };
};
