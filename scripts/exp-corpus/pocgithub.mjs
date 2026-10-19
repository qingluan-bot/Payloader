// GitHub PoC 聚合源（v2.0.3 第三聚合源）：trickest/cve 数据集（MIT，每日更新）。
// 该仓库按 YYYY/CVE-YYYY-XXXXX.md 组织"全网 GitHub PoC"：md 自带 Product/Version/CWE
// badge、CVE 官方描述与 #### Github PoC 仓库链接列表。
//
// v2.0.2 治理 A1：准入粒度从"repo 级无条件采信"改为 **repo×CVE 对级**——
// ①仓库名含该 CVE 编号（CVE-2019-11358 / cve-2019-11358 / 2019-11358 变体）→ 直接准入；
// ②否则并发（≤16）拉 raw.githubusercontent.com/<owner>/<repo>/HEAD/README.md
//   （超时 8s、失败重试 1 次），README 文本实质包含该 CVE 编号才准入；
//   HTTP 404 或重试后仍失败 → 不准入（fail-closed）。
// publishedAt = README Last-Modified（YYYY-MM-DD），缺失回退最早关联 CVE 年份；
// 可选 env PAYLOADER_GITHUB_TOKEN 时改走 GitHub /repos API 取 created_at 优先
// （created_at 不可变，磁盘缓存永久复用，应对 60/h 匿名限流）。
// README 拉取结果（状态/Last-Modified/CVE 引用集）磁盘缓存 7 天，断点续跑。
// 治理 A8 语义修正：①CVE 主键防串扰（仓库名直标 CVE > md 标题 > 正文出现次数评分排序，
// 旧 CVE 借 README 引用准入不再抢主键）②CVE List 镜像/聚合仓库静态黑名单 + awesome- 清单仓
// 排除 ③tags 剥 owner 名。

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { vulnTypeFromCwe } from './edb.mjs';

const CVE_IN_TEXT = /\bCVE-\d{4}-\d{4,7}\b/gi;
const GITHUB_REPO_IN_TEXT = /https?:\/\/(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/g;
const README_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
// 治理 A1 强化：安全工具/漏洞索引仓库的 README 常列成百上千 CVE 编号（jQuery 噪音
// CVE-2019-11358 重导后仍余 5525 条的根因），"实质引用"以 25 个为界——超出视为索引仓库，
// README 通道全部拒绝（仓库名准入不受影响）。
const MAX_README_CVES = 25;
// 治理 A1 强化 2：README 长度阈值——审计归档/项目文档仓库（npm audit 报告全文贴入，
// 75-110KB）不是 PoC 说明；真 PoC 仓库 README 实测全部 <8KB（ysoserial 7.4KB、
// JNDI-Injection 3.6KB），40KB 中间带充足。超长 README 文档型仓库 README 通道拒绝。
const MAX_README_BYTES = 40_000;
const README_CACHE_VERSION = 2;
const README_CONCURRENCY = 16;
const README_TIMEOUT_MS = 8_000;

const decodeBadgeMessage = value => {
  try {
    return decodeURIComponent(value).trim();
  } catch {
    return value.trim();
  }
};

// 单个 CVE md → { cveId, titleCve, cveHits, product, version, cwes[], description, repos[] }；
// 无 GitHub 仓库时 repos 为空。
// 治理 A8 CVE 提取防串扰：优先级 = 文件名 > md 首个标题行 > 正文；文件名缺编号时正文兜底
// 按"标题命中 + 出现次数"评分取最高，不再"取第一个提取到的"（正文引用的别家旧 CVE 会串扰主键）
export const parseCveMd = (text, path) => {
  const fileName = path.split('/').pop() || '';
  const cveIdFromName = fileName.match(/^(CVE-\d{4}-\d{4,7})\.md$/i)?.[1]?.toUpperCase() || '';
  // 首个标题行中的 CVE（trickest md 顶部 ### [CVE-...] 即本篇主 CVE）
  let titleCve = '';
  for (const line of text.split(/\r?\n/)) {
    if (!/^\s*#{1,6}\s/.test(line)) continue;
    titleCve = (line.match(CVE_IN_TEXT)?.[0] || '').toUpperCase();
    break;
  }
  let cveId = cveIdFromName;
  if (!cveId) {
    const counts = new Map();
    for (const match of text.matchAll(CVE_IN_TEXT)) {
      const value = match[0].toUpperCase();
      counts.set(value, (counts.get(value) || 0) + 1);
    }
    if (!counts.size) return null;
    cveId = [...counts.entries()]
      .sort((a, b) => (b[1] + (b[0] === titleCve ? 1e6 : 0)) - (a[1] + (a[0] === titleCve ? 1e6 : 0)))[0][0];
  }
  const cveHits = [...text.matchAll(new RegExp(cveId, 'gi'))].length;

  let product = '';
  let version = '';
  const cwes = new Set();
  for (const badge of text.matchAll(/label=(Product|Version|Vulnerability)&message=([^&)\s]+)/g)) {
    const value = decodeBadgeMessage(badge[2]);
    if (badge[1] === 'Product' && !product) product = value;
    else if (badge[1] === 'Version' && !version) version = value;
    else if (badge[1] === 'Vulnerability') {
      for (const cwe of value.matchAll(/CWE-\d+/g)) cwes.add(cwe[0]);
    }
  }

  let description = '';
  const descSection = text.match(/###\s*Description\s*\n+([\s\S]*?)(?=\n###|\n####|$)/);
  if (descSection) description = descSection[1].trim().replace(/\s+/g, ' ').slice(0, 500);

  // #### Github 段的仓库链接（只取该段，Reference 段是第三方公告不算 GitHub EXP）
  const repos = new Set();
  const ghSection = text.match(/####\s*Github\s*([\s\S]*?)(?=\n####|$)/i);
  if (ghSection) {
    for (const match of ghSection[1].matchAll(GITHUB_REPO_IN_TEXT)) {
      const owner = match[1];
      const repo = match[2].replace(/\.git$/i, '');
      if (!owner || !repo) continue;
      repos.add(`${owner}/${repo}`.toLowerCase());
    }
  }
  return { cveId, titleCve, cveHits, path, product, version, cwes: [...cwes], description, repos: [...repos] };
};

// 治理 A8 静态黑名单：CVE List 全量镜像/聚合仓库不是 PoC——其 README 列成千上万 CVE 编号，
// 会借"README 实证引用"通道混进语料。条目形态对齐 isBlacklisted（owner 段即组织级通配）。
export const STATIC_BLACKLIST_REPOS = new Set([
  'dims/cvelist-public', // CVE List 官方数据全量镜像（cvelist 项目镜像仓）
  'cveproject/cvelist', // CVE List 官方仓库本体（全量编号索引，非 PoC）
  'live-hack-cve', // 组织级通配：自动生成的 CVE 详述镜像仓库群（live-hack-cve/CVE-*）
]);

// blacklist：trickest 自带 blacklist.txt（条目为 owner 或 owner/repo）+ 上面的静态黑名单
export const isBlacklisted = (repoKey, blacklistSet) => {
  const key = String(repoKey || '').toLowerCase();
  const owner = key.split('/')[0];
  if (blacklistSet && (blacklistSet.has(key) || blacklistSet.has(owner))) return true;
  return STATIC_BLACKLIST_REPOS.has(key) || STATIC_BLACKLIST_REPOS.has(owner);
};

// 治理 A8：awesome- 前缀仓库是"漏洞资源导航清单"不是 PoC——README 准入判定一并排除
export const isCuratedListRepo = repoKey => {
  const repoName = String(repoKey || '').split('/')[1] || '';
  return repoName.toLowerCase().startsWith('awesome-');
};

// 仓库名（owner/repo 的 repo 段 + owner 段）是否标注了该 CVE 编号的变体：
// 全称 CVE-YYYY-NNNNN（大小写不敏感）或裸 YYYY-NNNNN（前后不接数字，防撞版本号/日期）
export const repoNameAdmitsCve = (repoName, cveId) => {
  const match = String(cveId || '').match(/^CVE-(\d{4})-(\d{4,7})$/);
  if (!match) return false;
  const [, year, seq] = match;
  const lower = String(repoName || '').toLowerCase();
  if (lower.includes(`cve-${year}-${seq}`)) return true;
  return new RegExp(`(?<![0-9])${year}-${seq}(?![0-9])`).test(lower);
};

const httpDateToISODate = value => {
  if (!value) return '';
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : '';
};

const loadJsonCache = (file, log) => {
  if (!file || !existsSync(file)) return {};
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    log(`  ghpoc 缓存损坏重建（${file}）：${error.message}`);
    return {};
  }
};

const saveJsonCache = (file, data) => {
  if (!file) return;
  try {
    mkdirSync(join(file, '..'), { recursive: true });
    writeFileSync(file, JSON.stringify(data));
  } catch { /* 缓存写入失败不阻断管线 */ }
};

// 单仓库 README 拉取（带缓存与重试）：{ status: 200|404|0, lastModified, cves, fetchedAt }
// status 0 = 网络/非 404 失败（不落缓存，重跑自动重试）
export const fetchRepoReadmeEntry = async (repoKey, { fetchImpl = fetch, timeoutMs = README_TIMEOUT_MS } = {}) => {
  const url = `https://raw.githubusercontent.com/${repoKey}/HEAD/README.md`;
  let lastError = '';
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      const response = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
      if (response.status === 404) {
        return { status: 404, lastModified: '', cves: [], length: 0, fetchedAt: new Date().toISOString(), v: README_CACHE_VERSION };
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const text = await response.text();
      const cves = [...new Set([...text.matchAll(CVE_IN_TEXT)].map(item => item[0].toUpperCase()))];
      return {
        status: 200,
        lastModified: response.headers?.get?.('last-modified') || '',
        cves,
        length: text.length,
        fetchedAt: new Date().toISOString(),
        v: README_CACHE_VERSION,
      };
    } catch (error) {
      lastError = error.message;
      if (error.name === 'TimeoutError') lastError = `timeout ${timeoutMs}ms`;
    }
  }
  return { status: 0, error: lastError, cves: [], fetchedAt: new Date().toISOString() };
};

// GitHub /repos API created_at（可选 token 路径；created_at 不可变，缓存永久复用）
const fetchRepoCreatedAt = async (repoKey, { token, fetchImpl }) => {
  try {
    const response = await fetchImpl(`https://api.github.com/repos/${repoKey}`, {
      headers: { authorization: `Bearer ${token}`, 'user-agent': 'payloader-curation', accept: 'application/vnd.github+json' },
      signal: AbortSignal.timeout(README_TIMEOUT_MS),
    });
    if (!response.ok) return { ok: false, status: response.status };
    const data = await response.json();
    const isoDate = httpDateToISODate(data?.created_at);
    return isoDate ? { ok: true, createdAt: isoDate } : { ok: false, status: response.status };
  } catch {
    return { ok: false, status: 0 };
  }
};

// repo×CVE 对级准入（治理 A1 主入口）：
// 返回 { admission: Map<repoKey, { cves:Set, via, lastModified, createdAt }>, skipped }
// skipped: { blacklisted, nameAdmitted 对计数在 admission 内体现, readmeRejected, readmeFailed, readmeLimitReached }
export const admitRepoCves = async (mdRecords, {
  blacklistSet = new Set(),
  skipReadme = false,
  readmeLimit = Infinity,
  cacheDir = '',
  token = process.env.PAYLOADER_GITHUB_TOKEN || '',
  fetchImpl = fetch,
  concurrency = README_CONCURRENCY,
  log = () => {},
} = {}) => {
  // 第一遍：按 repo 聚合待判定的 CVE 集合，仓库名命中直接准入
  const candidates = new Map(); // repoKey → { nameAdmitted:Set, needsReadme:Set, firstCveAt }
  const skipped = { blacklisted: 0, awesomeList: 0, nameAdmitted: 0, readmeRejected: 0, readmeFailed: 0, readmeLimitReached: 0, readmesFetched: 0, reposMetaFetched: 0, readmeIndexRepo: 0, readmeDocumentRepo: 0 };
  const pushPair = (repoKey, cveId, admitted) => {
    let entry = candidates.get(repoKey);
    if (!entry) {
      entry = { nameAdmitted: new Set(), needsReadme: new Set() };
      candidates.set(repoKey, entry);
    }
    if (admitted) {
      entry.nameAdmitted.add(cveId);
      skipped.nameAdmitted += 1;
    } else {
      entry.needsReadme.add(cveId);
    }
    return entry;
  };
  for (const record of mdRecords) {
    if (!record) continue;
    for (const repoKey of record.repos || []) {
      if (isBlacklisted(repoKey, blacklistSet)) {
        skipped.blacklisted += 1;
        continue;
      }
      // 治理 A8：awesome- 清单仓库名不参与任何准入（README 通道与仓库名通道一并排除）
      if (isCuratedListRepo(repoKey)) {
        skipped.awesomeList += 1;
        continue;
      }
      pushPair(repoKey, record.cveId, repoNameAdmitsCve(repoKey, record.cveId));
    }
  }

  const admission = new Map();
  for (const [repoKey, entry] of candidates) {
    if (entry.nameAdmitted.size) {
      admission.set(repoKey, { cves: new Set(entry.nameAdmitted), via: 'name', lastModified: '', createdAt: '' });
    }
  }

  // 第二遍：README 实证准入（并发 ≤16，磁盘缓存 7 天，readmeLimit 限制实际网络拉取数）
  const reposNeedingReadme = skipReadme ? [] : [...candidates.entries()]
    .filter(([repoKey, entry]) => entry.needsReadme.size && !admission.has(repoKey))
    .map(([repoKey]) => repoKey);
  const readmeIndexFile = cacheDir ? join(cacheDir, 'ghpoc-readme-index.json') : '';
  const readmeIndex = loadJsonCache(readmeIndexFile, log);
  const nowMs = Date.now();
  const pending = [];
  for (const repoKey of reposNeedingReadme) {
    const cached = readmeIndex[repoKey];
    if (cached && cached.v === README_CACHE_VERSION && cached.fetchedAt && nowMs - Date.parse(cached.fetchedAt) < README_CACHE_TTL_MS) {
      pending.push({ repoKey, entry: null, cached });
      continue;
    }
    pending.push({ repoKey, entry: candidates.get(repoKey), cached: null });
  }

  let fetchedCount = 0;
  let networkLimited = false;
  let cursor = 0;
  const worker = async () => {
    while (cursor < pending.length) {
      const item = pending[cursor];
      cursor += 1;
      let result = item.cached;
      if (!result) {
        if (fetchedCount >= readmeLimit) {
          networkLimited = true;
          continue;
        }
        fetchedCount += 1;
        skipped.readmesFetched += 1;
        result = await fetchRepoReadmeEntry(item.repoKey, { fetchImpl });
        if (result.status !== 0) {
          readmeIndex[item.repoKey] = result;
          saveJsonCache(readmeIndexFile, readmeIndex);
        } else {
          skipped.readmeFailed += 1;
        }
      }
      const repoKey = item.repoKey;
      const entry = candidates.get(repoKey);
      if (result.status === 200 && result.lastModified) {
        const meta = admission.get(repoKey);
        if (meta) meta.lastModified = result.lastModified;
      }
      if (!entry) continue; // 命中缓存的仓库名准入仓（仅回填 lastModified）
      const indexRepo = result.status === 200 && result.cves.length > MAX_README_CVES;
      if (indexRepo) skipped.readmeIndexRepo += 1;
      const documentRepo = result.status === 200 && (result.length ?? 0) > MAX_README_BYTES;
      if (documentRepo) skipped.readmeDocumentRepo += 1;
      for (const cveId of entry.needsReadme) {
        if (!indexRepo && !documentRepo && result.status === 200 && result.cves.includes(cveId)) {
          let meta = admission.get(repoKey);
          if (!meta) {
            meta = { cves: new Set(), via: 'readme', lastModified: result.lastModified, createdAt: '' };
            admission.set(repoKey, meta);
          }
          meta.cves.add(cveId);
        } else if (result.status === 200 || result.status === 404) {
          skipped.readmeRejected += 1;
        }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(pending.length, 1)) }, worker));
  if (networkLimited) {
    log(`  ghpoc README 拉取达到上限 ${readmeLimit}（--ghpoc-readme-limit），其余仓库本轮不准入`);
    skipped.readmeLimitReached = pending.filter(item => !item.cached).length - fetchedCount;
  }

  // 第三遍（可选 token 路径）：/repos API created_at 优先做 publishedAt
  if (token && admission.size) {
    const reposIndexFile = cacheDir ? join(cacheDir, 'ghpoc-repos-index.json') : '';
    const reposIndex = loadJsonCache(reposIndexFile, log);
    const needMeta = [...admission.keys()].filter(repoKey => !reposIndex[repoKey]?.createdAt);
    let metaCursor = 0;
    let rateLimited = false;
    const metaWorker = async () => {
      while (metaCursor < needMeta.length && !rateLimited) {
        const repoKey = needMeta[metaCursor];
        metaCursor += 1;
        const result = await fetchRepoCreatedAt(repoKey, { token, fetchImpl });
        if (result.ok) {
          reposIndex[repoKey] = { createdAt: result.createdAt, fetchedAt: new Date().toISOString() };
          admission.get(repoKey).createdAt = result.createdAt;
          skipped.reposMetaFetched += 1;
          saveJsonCache(reposIndexFile, reposIndex);
        } else if (result.status === 403 || result.status === 429) {
          rateLimited = true;
          log(`  ghpoc /repos API 限流（HTTP ${result.status}），其余仓库 created_at 回退 README Last-Modified/年份口径`);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(4, Math.max(needMeta.length, 1)) }, metaWorker));
    for (const [repoKey, meta] of admission) {
      const cached = reposIndex[repoKey];
      if (cached?.createdAt) meta.createdAt = cached.createdAt;
    }
  }

  return { admission, skipped };
};

const lastModifiedFallbackYear = cveIds => {
  let earliest = '9999';
  for (const cveId of cveIds) {
    const year = String(cveId).slice(4, 8);
    if (year < earliest) earliest = year;
  }
  return earliest === '9999' ? String(new Date().getFullYear()) : earliest;
};

// md 解析流 + 准入结果 → repo 聚合模型（bizKey ghpoc:owner/repo）。
// 只有 repo×CVE 对通过准入的 CVE 才进入 vulnerabilityIds；全部被拒的 repo 不入库。
// severity 取关联 CVE 的 NVD 映射最严重档；vulnType 用 md 自带 CWE（回落 NVD CWE）。
export const buildGithubPocModels = (mdRecords, { cveMap = new Map(), blacklistSet = new Set(), admission = new Map() } = {}) => {
  const byRepo = new Map();
  const skipped = { noRepos: 0, blacklisted: 0, awesomeList: 0, notAdmitted: 0 };

  mdRecords.forEach(record => {
    if (!record || !record.repos.length) {
      skipped.noRepos += 1;
      return;
    }
    for (const repoKey of record.repos) {
      if (isBlacklisted(repoKey, blacklistSet)) {
        skipped.blacklisted += 1;
        continue;
      }
      if (isCuratedListRepo(repoKey)) {
        skipped.awesomeList += 1;
        continue;
      }
      const admitted = admission.get(repoKey);
      if (!admitted || !admitted.cves.has(record.cveId)) {
        skipped.notAdmitted += 1;
        continue;
      }
      let agg = byRepo.get(repoKey);
      if (!agg) {
        const [owner, repoName] = repoKey.split('/');
        agg = {
          repoKey,
          owner,
          repoName,
          cves: [],
          cveTitleHits: new Map(), // cve → 该 CVE 出现在某 md 标题行的记录数
          cveOccurrences: new Map(), // cve → md 正文出现次数合计
          products: new Set(),
          cwes: new Set(),
          descriptions: [],
          earliestYear: '9999',
        };
        byRepo.set(repoKey, agg);
      }
      if (!agg.cves.includes(record.cveId)) agg.cves.push(record.cveId);
      agg.cveTitleHits.set(record.cveId, (agg.cveTitleHits.get(record.cveId) || 0) + (record.titleCve === record.cveId ? 1 : 0));
      agg.cveOccurrences.set(record.cveId, (agg.cveOccurrences.get(record.cveId) || 0) + Math.max(Number(record.cveHits) || 0, 1));
      if (record.product) agg.products.add(record.product);
      record.cwes.forEach(cwe => agg.cwes.add(cwe));
      if (record.description && agg.descriptions.length < 3) agg.descriptions.push(record.description);
      const year = record.cveId.slice(4, 8);
      if (year < agg.earliestYear) agg.earliestYear = year;
    }
  });

  const pairs = [];
  for (const agg of byRepo.values()) {
    // 治理 A8 CVE 主键防串扰：旧 CVE 借 README 引用准入后不得抢主键
    // （muhammad1596/cve-2022-0847-dirty-pipe-checker 被挂到 CVE-2016-5195 的根因：md 迭代顺序
    // 让先到的旧 CVE 排在 vulnerabilityIds[0]）。评分排序取代"第一个提取到的"：
    // 仓库名直标 CVE（主键候选首位）> md 标题 CVE > 正文出现次数；Array#sort 稳定保序。
    const cveScore = cve => (repoNameAdmitsCve(agg.repoKey, cve) ? 1_000_000 : 0)
      + (agg.cveTitleHits.get(cve) ? 10_000 : 0)
      + Math.min(agg.cveOccurrences.get(cve) || 0, 9_999);
    agg.cves.sort((a, b) => cveScore(b) - cveScore(a));
    const meta = admission.get(agg.repoKey);
    const scores = agg.cves.map(cve => cveMap.get(cve)?.score).filter(score => Number.isFinite(score));
    // severity：NVD 最高分优先；无任何 NVD 命中回落 medium（聚合索引缺省，prerequisites 注明）
    let severity = 'unknown';
    if (scores.length) {
      const best = Math.max(...scores);
      severity = best >= 9 ? 'critical' : best >= 7 ? 'high' : best >= 4 ? 'medium' : 'low';
    }
    const cwes = [...agg.cwes];
    const tagHit = [[/rce|exec|code-?injection|command-?injection/, 'rce'], [/sqli|sql/, 'sqli'], [/deserial/, 'deserialization'],
      [/unauth|auth-?bypass/, 'auth-bypass'], [/priv-?esc|lpe/, 'lpe'], [/fileread|traversal|lfi/, 'path-traversal'],
      [/upload/, 'file-upload'], [/xss/, 'xss'], [/xxe/, 'xxe'], [/ssrf/, 'ssrf']]
      .find(([pattern]) => pattern.test(agg.repoName));
    const vulnType = cwes.map(cwe => vulnTypeFromCwe(cwe)).find(Boolean) || (tagHit ? tagHit[1] : 'uncategorized');
    const affected = [...agg.products].slice(0, 20).join('; ');
    const primaryCve = agg.cves[0];
    // publishedAt 口径：token 路径 /repos created_at → README Last-Modified →
    // NVD CVE 官方公开日期（raw 响应无 Last-Modified 头，实证 2026-09-28）→ 最早 CVE 年份
    const publishedAt = meta?.createdAt
      || httpDateToISODate(meta?.lastModified)
      || cveMap.get(primaryCve)?.published
      || lastModifiedFallbackYear(agg.cves);
    const viaText = meta?.via === 'name' ? '仓库名直接标注该 CVE' : 'README 实证引用该 CVE';
    pairs.push({
      bizKey: `ghpoc:${agg.repoKey}`,
      exploit: {
        name: agg.repoName.slice(0, 200),
        description: agg.descriptions[0]
          || `${agg.repoKey} 收录 ${agg.cves.slice(0, 5).join(', ')} 的公开 PoC/EXP 实现。`,
        vulnType,
        affected,
        severity,
        publishedAt,
        vulnerabilityIds: agg.cves.slice(0, 30).map(value => ({ type: 'CVE', value })),
        exploitCode: [],
        prerequisites: `利用条件：按仓库源码自行构建运行（语言与依赖见仓库 README），目标需版本受 ${primaryCve} 影响且服务可达（${viaText}）；社区 PoC 有效性随版本变化，运行前需在隔离环境核对代码。`,
        references: [
          `https://github.com/${agg.repoKey}`,
          `https://github.com/trickest/cve/blob/main/${primaryCve.slice(4, 8)}/${primaryCve}.md`,
        ],
        // 治理 A8：tags 剥离仓库 owner 名（99.97% 条目混 owner 名如 hybridious 的根因），
        // 只留 github/poc/cwe-* 语义标签
        tags: [...new Set(['github', 'poc', ...cwes.map(cwe => `cwe-${cwe.replace(/^CWE-/, '')}`)])]
          .filter(tag => tag !== agg.owner.toLowerCase())
          .slice(0, 8),
        products: deriveProducts({
          cpeProducts: cveMap.get(primaryCve)?.products || [],
          name: agg.repoName,
          description: agg.descriptions.join(' ').slice(0, 600),
          affected,
        }),
        attribution: { source: 'GitHub PoC', author: agg.owner, license: '' },
        source: 'gh-poc',
        sourceRef: `ghpoc-${agg.repoKey}`,
        // 主键防串扰：直接取评分排序首位，不走 primaryCveKey 的纯升序——升序会让旧 CVE
        // （年份小排前）把仓库名自证的新 CVE 抢回主键，串扰复发
        canonicalKey: primaryCve,
      },
    });
  }
  return { pairs, skipped };
};

import { deriveProducts } from './products.mjs';
