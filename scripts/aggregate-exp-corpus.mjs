// EXP 全网聚合管线 CLI（v2.0.3）：Exploit-DB 主源 + NVD 补 CVSS/CWE/CPE + OSV 补 GHSA
// → 结构化映射 → 运行库幂等落库。数据文件全部落在 data/exp-corpus/（.gitignore /data/），
// 仓库只带管线代码不带聚合数据。种子库与分类树不受影响。
//
// 用法：npm run aggregate:exp [-- --verify | --no-nvd | --no-ghsa | --no-nuclei | --no-ghpoc | --no-msf | --no-contents | --force | --since=YYYY-MM-DD]
//   --verify      只拉取与构建模型并打印报告，不写库
//   --no-nvd      跳过 NVD（无 CVSS/产品映射，severity 缺省 medium）
//   --no-ghsa     跳过 OSV GHSA 编号补充
//   --no-nuclei   跳过 Nuclei Templates 源（检测 POC 模板，YAML 原文入库）
//   --no-ghpoc    跳过 GitHub PoC 源（trickest/cve 十年窗口）
//   --no-msf      跳过 Metasploit 官方模块源（完整利用脚本）
//   --no-contents 跳过 EDB 正文仓注入（条目退化为索引形态）
//   默认 --since=2016-09-01（十年窗口，EDB 条目与 NVD 富化起点）
//   --force      覆盖管理员手工编辑过的聚合条目
//   PAYLOADER_NVD_API_KEY      NVD 免费 key（5→50 req/30s）
//   PAYLOADER_AGGREGATE_PROXY  HTTP 代理（如 http://127.0.0.1:7897，经 --use-env-proxy 重启生效）

import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const rootDir = join(scriptDir, '..');
const args = process.argv.slice(2);
const argSet = new Set(args);
const sinceArg = args.find(item => item.startsWith('--since='));
// 默认十年窗口（2016-09-01 起）：EDB 条目与 NVD 富化起点；nuclei/ghpoc/msf 源不受此过滤
const sinceISO = sinceArg ? sinceArg.split('=')[1] : '2016-09-01';
const options = {
  verify: argSet.has('--verify'),
  force: argSet.has('--force'),
  nvd: !argSet.has('--no-nvd'),
  ghsa: !argSet.has('--no-ghsa'),
  nuclei: !argSet.has('--no-nuclei'),
  ghpoc: !argSet.has('--no-ghpoc'),
  msf: !argSet.has('--no-msf'),
  contents: !argSet.has('--no-contents'),
  ghpocNoReadme: argSet.has('--no-ghpoc-readme'),
  ghpocReadmeLimit: Number.parseInt((args.find(item => item.startsWith('--ghpoc-readme-limit=')) || '').split('=')[1] ?? '', 10) || Infinity,
  reconcile: !argSet.has('--no-reconcile'),
  sinceISO,
};
const cacheDir = join(rootDir, 'data', 'exp-corpus', 'cache');
const csvCacheFile = join(cacheDir, 'files_exploits.csv');
const etagFile = `${csvCacheFile}.etag`;
const nucleiZipCacheFile = join(cacheDir, 'nuclei-templates.zip');
const pocghZipCacheFile = join(cacheDir, 'trickest-cve.zip');
const edbZipCacheFile = join(cacheDir, 'exploitdb-main.zip');
const msfZipCacheFile = join(cacheDir, 'metasploit-framework.zip');

const log = message => console.log(message);
const sleep = ms => new Promise(resolve => { setTimeout(resolve, ms); });

// 代理：Node 24 fetch 代理支持是启动级开关，需 --use-env-proxy 重启进程生效
const respawnWithProxy = async () => {
  const proxy = process.env.PAYLOADER_AGGREGATE_PROXY;
  if (!proxy || process.env.PAYLOADER_AGGREGATE_PROXY_RESPAWNED === '1') return;
  log(`[proxy] 经 ${proxy} 转发外部请求（--use-env-proxy 重启进程）`);
  const code = await new Promise(resolve => {
    const child = spawn(process.execPath, ['--use-env-proxy', ...process.execArgv, fileURLToPath(import.meta.url), ...args], {
      env: {
        ...process.env,
        HTTP_PROXY: proxy,
        HTTPS_PROXY: proxy,
        PAYLOADER_AGGREGATE_PROXY_RESPAWNED: '1',
      },
      stdio: 'inherit',
    });
    child.on('exit', exitCode => resolve(exitCode ?? 1));
    child.on('error', error => {
      console.error(`[proxy] 重启失败（Node ≥24 才支持 --use-env-proxy）：${error.message}`);
      resolve(1);
    });
  });
  process.exit(code);
};

await respawnWithProxy();

const { EDB_CSV_URL, EDB_ZIP_URL, MSF_ZIP_URL, NUCLEI_ZIP_URL, NUCLEI_INCLUDE_PREFIXES, POCGH_ZIP_URL, POCGH_BLACKLIST_URL, POCGH_MIN_YEAR, POCGH_MD_PATTERN } = await import('./exp-corpus/sources.mjs');
const { parseEdbCsv, buildExploitModels } = await import('./exp-corpus/edb.mjs');
const { buildNvdCveMap } = await import('./exp-corpus/nvd.mjs');
const { fetchGhsaMap } = await import('./exp-corpus/osv.mjs');
const { extractCves } = await import('./exp-corpus/edb.mjs');
const { readZipEntries } = await import('./exp-corpus/zip.mjs');
const { extractTemplateFields, buildNucleiModels } = await import('./exp-corpus/nuclei.mjs');
const { parseCveMd, buildGithubPocModels } = await import('./exp-corpus/pocgithub.mjs');
const { parseMsfModule, buildMsfModels } = await import('./exp-corpus/msf.mjs');

const fetchWithRetry = async (url, init = {}, attempts = 3) => {
  // 统一 UA：GitLab archive 等端点对无 UA 请求返回 406
  const initWithAgent = {
    ...init,
    headers: { 'user-agent': 'Mozilla/5.0 (payloader-curation)', ...(init.headers || {}) },
  };
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fetch(url, initWithAgent);
    } catch (error) {
      if (attempt === attempts) throw error;
      log(`  请求失败（${error.message}），重试 ${attempt}/${attempts - 1}`);
      await sleep(2000 * attempt);
    }
  }
  throw new Error('unreachable');
};

// EDB CSV 下载：ETag 条件请求缓存（304 复用本地副本）
const downloadEdbCsv = async () => {
  const headers = {};
  if (existsSync(etagFile)) headers['if-none-match'] = readFileSync(etagFile, 'utf8').trim();
  const response = await fetchWithRetry(EDB_CSV_URL, { headers });
  if (response.status === 304 && existsSync(csvCacheFile)) {
    log(`[edb] CSV 未变化（ETag 命中），复用本地缓存`);
    return readFileSync(csvCacheFile, 'utf8');
  }
  if (!response.ok) throw new Error(`Exploit-DB CSV 下载失败：HTTP ${response.status}`);
  const text = await response.text();
  mkdirSync(cacheDir, { recursive: true });
  writeFileSync(csvCacheFile, text);
  const etag = response.headers.get('etag');
  if (etag) writeFileSync(etagFile, etag);
  log(`[edb] CSV 已下载：${(text.length / 1024 / 1024).toFixed(1)} MB`);
  return text;
};

// Nuclei Templates zip 下载：存在即复用缓存（删除缓存文件可强制刷新）
const downloadNucleiZip = async () => {
  if (existsSync(nucleiZipCacheFile)) {
    const ageDays = (Date.now() - statSync(nucleiZipCacheFile).mtimeMs) / 86_400_000;
    if (ageDays < 7) {
      log(`[nuclei] 复用本地 zip 缓存（${(statSync(nucleiZipCacheFile).size / 1024 / 1024).toFixed(1)} MB，${ageDays.toFixed(1)} 天前拉取；删除缓存可强制刷新）`);
      return readFileSync(nucleiZipCacheFile);
    }
  }
  const response = await fetchWithRetry(NUCLEI_ZIP_URL);
  if (!response.ok) throw new Error(`Nuclei Templates 下载失败：HTTP ${response.status}`);
  const buffer = Buffer.from(await response.arrayBuffer());
  mkdirSync(cacheDir, { recursive: true });
  writeFileSync(nucleiZipCacheFile, buffer);
  log(`[nuclei] zip 已下载：${(buffer.length / 1024 / 1024).toFixed(1)} MB`);
  return buffer;
};

// trickest/cve zip 下载（数万 CVE md，体积数百 MB）：7 天缓存复用
const downloadPocghZip = async () => {
  if (existsSync(pocghZipCacheFile)) {
    const ageDays = (Date.now() - statSync(pocghZipCacheFile).mtimeMs) / 86_400_000;
    if (ageDays < 7) {
      log(`[ghpoc] 复用本地 zip 缓存（${(statSync(pocghZipCacheFile).size / 1024 / 1024).toFixed(1)} MB，${ageDays.toFixed(1)} 天前拉取）`);
      return readFileSync(pocghZipCacheFile);
    }
  }
  const response = await fetchWithRetry(POCGH_ZIP_URL, {}, 2);
  if (!response.ok) throw new Error(`trickest/cve zip 下载失败：HTTP ${response.status}`);
  const buffer = Buffer.from(await response.arrayBuffer());
  mkdirSync(cacheDir, { recursive: true });
  writeFileSync(pocghZipCacheFile, buffer);
  log(`[ghpoc] zip 已下载：${(buffer.length / 1024 / 1024).toFixed(1)} MB`);
  return buffer;
};

// EDB 正文仓 zip（真实脚本/POC 正文）：下载后流式提取 file 列路径 → 正文 Map
const downloadAndExtractEdbContents = async () => {
  if (existsSync(edbZipCacheFile)) {
    const ageDays = (Date.now() - statSync(edbZipCacheFile).mtimeMs) / 86_400_000;
    if (ageDays < 7) {
      log(`[edb-content] 复用本地 zip 缓存（${(statSync(edbZipCacheFile).size / 1024 / 1024).toFixed(1)} MB）`);
      return readFileSync(edbZipCacheFile);
    }
  }
  const response = await fetchWithRetry(EDB_ZIP_URL, {}, 2);
  if (!response.ok) throw new Error(`Exploit-DB 正文仓下载失败：HTTP ${response.status}`);
  const buffer = Buffer.from(await response.arrayBuffer());
  mkdirSync(cacheDir, { recursive: true });
  writeFileSync(edbZipCacheFile, buffer);
  log(`[edb-content] 正文仓已下载：${(buffer.length / 1024 / 1024).toFixed(1)} MB`);
  return buffer;
};

// MSF zip：exploits/**/*.rb 模块
const downloadMsfZip = async () => {
  if (existsSync(msfZipCacheFile)) {
    const ageDays = (Date.now() - statSync(msfZipCacheFile).mtimeMs) / 86_400_000;
    if (ageDays < 7) {
      log(`[msf] 复用本地 zip 缓存（${(statSync(msfZipCacheFile).size / 1024 / 1024).toFixed(1)} MB，${ageDays.toFixed(1)} 天前拉取）`);
      return readFileSync(msfZipCacheFile);
    }
  }
  const response = await fetchWithRetry(MSF_ZIP_URL, {}, 2);
  if (!response.ok) throw new Error(`Metasploit 仓库下载失败：HTTP ${response.status}`);
  const buffer = Buffer.from(await response.arrayBuffer());
  mkdirSync(cacheDir, { recursive: true });
  writeFileSync(msfZipCacheFile, buffer);
  log(`[msf] zip 已下载：${(buffer.length / 1024 / 1024).toFixed(1)} MB`);
  return buffer;
};

const sinceMs = Date.parse(`${options.sinceISO}T00:00:00.000Z`);
if (!Number.isFinite(sinceMs)) {
  console.error(`--since 非法：${options.sinceISO}（期望 YYYY-MM-DD）`);
  process.exit(1);
}

log(`EXP 全网聚合管线（since=${options.sinceISO}${options.verify ? '，verify 模式' : ''}${options.force ? '，force 覆盖' : ''}）`);
const csvText = await downloadEdbCsv();
const records = parseEdbCsv(csvText);
log(`[edb] 解析 ${records.length} 条记录`);

// EDB 正文仓：真实脚本/POC 正文（用户优先级：脚本 > HTTP POC > curl），file 列路径 → 正文
let edbContents = new Map();
if (options.contents) {
  try {
    const edbZipBuffer = await downloadAndExtractEdbContents();
    let contentCount = 0;
    readZipEntries(
      edbZipBuffer,
      path => path.includes('/exploits/') && !path.endsWith('/'),
      ({ path, data }) => {
        // zip 内路径带 exploitdb-main/ 前缀，剥离后与 CSV file 列对齐
        const relative = path.replace(/^[^/]+\//, '');
        edbContents.set(relative, data.toString('latin1'));
        contentCount += 1;
        if (contentCount % 10_000 === 0) log(`[edb-content] 已提取 ${contentCount} 个正文文件…`);
      },
    );
    log(`[edb-content] 正文提取完成：${contentCount} 个文件（命中窗口内条目将在落库时注入）`);
  } catch (error) {
    console.warn(`[edb-content] 正文仓拉取降级（条目退化为索引形态）：${error.message}`);
    edbContents = new Map();
  }
} else {
  log('[edb-content] 已按 --no-contents 跳过正文注入');
}

// Metasploit 官方模块：完整利用脚本（msfconsole use 直接可用）
let msfModules = [];
if (options.msf) {
  try {
    const msfZipBuffer = await downloadMsfZip();
    readZipEntries(
      msfZipBuffer,
      path => path.includes('/exploits/') && path.endsWith('.rb') && !path.endsWith('_spec.rb'),
      ({ path, data }) => {
        const relative = path.replace(/^[^/]+\//, '');
        const module = parseMsfModule(data.toString('utf8'), relative);
        if (module) msfModules.push(module);
      },
    );
    log(`[msf] 解析 ${msfModules.length} 个带 CVE 的 exploit 模块`);
  } catch (error) {
    console.warn(`[msf] 拉取/解析降级跳过：${error.message}`);
    msfModules = [];
  }
} else {
  log('[msf] 已按 --no-msf 跳过');
}

// Nuclei Templates：zip → 模板字段抽取（在 NVD 前进行，CVE 并入统一映射集合）
let nucleiTemplates = [];
if (options.nuclei) {
  try {
    const zipBuffer = await downloadNucleiZip();
    nucleiTemplates = readZipEntries(zipBuffer, path => (
      path.endsWith('.yaml') && NUCLEI_INCLUDE_PREFIXES.some(prefix => path.includes(prefix))
    )).map(entry => extractTemplateFields(entry.data.toString('utf8'), entry.path)).filter(Boolean);
    log(`[nuclei] 解析 ${nucleiTemplates.length} 个检测模板（http/cves + http/vulnerabilities）`);
  } catch (error) {
    console.warn(`[nuclei] 拉取/解析降级跳过：${error.message}`);
    nucleiTemplates = [];
  }
} else {
  log('[nuclei] 已按 --no-nuclei 跳过');
}

// GitHub PoC 聚合源：trickest/cve zip → 流式解析十年窗口 CVE md（数万条，回调模式防内存膨胀）
let pocghMdRecords = [];
let pocghBlacklistSet = new Set();
if (options.ghpoc) {
  try {
    const blacklistResponse = await fetchWithRetry(POCGH_BLACKLIST_URL, {}, 2);
    pocghBlacklistSet = new Set(
      blacklistResponse.ok
        ? (await blacklistResponse.text()).split(/\r?\n/).map(line => line.trim().toLowerCase()).filter(Boolean)
        : [],
    );
    log(`[ghpoc] blacklist ${pocghBlacklistSet.size} 条`);
    const zipBuffer = await downloadPocghZip();
    let mdScanned = 0;
    readZipEntries(
      zipBuffer,
      path => {
        const match = path.match(POCGH_MD_PATTERN);
        return Boolean(match && Number(match[1]) >= POCGH_MIN_YEAR);
      },
      ({ path, data }) => {
        const record = parseCveMd(data.toString('utf8'), path);
        if (record) {
          pocghMdRecords.push(record);
          mdScanned += 1;
          if (mdScanned % 10_000 === 0) log(`[ghpoc] 已解析 ${mdScanned} 个 CVE md…`);
        }
      },
    );
    log(`[ghpoc] 解析 ${pocghMdRecords.length} 个 CVE md（十年窗口 ${POCGH_MIN_YEAR}+）`);
  } catch (error) {
    console.warn(`[ghpoc] 拉取/解析降级跳过：${error.message}`);
    pocghMdRecords = [];
  }
} else {
  log('[ghpoc] 已按 --no-ghpoc 跳过');
}

const cveSet = new Set();
records.forEach(record => {
  // 与 edb.mjs extractCves 同源（codes 列 + description 兜底），description-only CVE 也能富化
  extractCves(record).forEach(value => cveSet.add(value.toLowerCase()));
});
nucleiTemplates.forEach(template => {
  template.cves.forEach(value => cveSet.add(value.toLowerCase()));
});
pocghMdRecords.forEach(record => cveSet.add(record.cveId.toLowerCase()));
msfModules.forEach(module => module.cves.forEach(value => cveSet.add(value.toLowerCase())));
log(`[cve] 统一关联 CVE 集合：${cveSet.size} 个（EDB + Nuclei + GitHub PoC + MSF 去重）`);

let cveMap = new Map();
if (options.nvd) {
  // ghpoc 开启时 CVE 集合横跨十年，NVD 起点自动扩到 2016-01-01（窗口有缓存，只补缺）
  // 治理 F-sev：severity 全量对齐 NVD 官方档——精选层含 2015 前老 CVE（Heartbleed 2014 等），
  // NVD 起点扩到 2000-01-01 补齐历史窗口（窗口缓存复用，只补缺）
  const nvdSinceMs = Math.min(sinceMs, options.ghpoc ? Date.parse('2016-01-01T00:00:00.000Z') : sinceMs, Date.parse('2000-01-01T00:00:00.000Z'));
  log(`[nvd] 窗口拉取 CVE 映射（${cveSet.size} 个关联 CVE，起点 ${new Date(nvdSinceMs).toISOString().slice(0, 10)}，key=${process.env.PAYLOADER_NVD_API_KEY ? '有' : '无'}，无 key 约 6s/请求）`);
  const nvdResult = await buildNvdCveMap({
    sinceMs: nvdSinceMs,
    cveSet,
    cacheDir,
    log,
  });
  cveMap = nvdResult.cveMap;
  log(`[nvd] 映射 ${cveMap.size} 个 CVE（拉取窗口 ${nvdResult.windowsFetched}，缓存复用 ${nvdResult.windowsCached}，失败跳过 ${nvdResult.windowsFailed}）`);
} else {
  log('[nvd] 已按 --no-nvd 跳过');
}

let ghsaMap = new Map();
if (options.ghsa && cveSet.size) {
  log('[osv] 逐条互查补充 GHSA 编号（GET /v1/vulns，并发 8，缓存增量）');
  ghsaMap = await fetchGhsaMap(
    [...cveSet].map(value => value.toUpperCase()).sort(),
    { log, cacheFile: join(cacheDir, 'ghsa-index.json') },
  );
  log(`[osv] GHSA 命中 ${ghsaMap.size} 个 CVE`);
} else {
  log('[osv] 已跳过（--no-ghsa 或无 CVE）');
}

const { pairs, skipped } = buildExploitModels(records, { cveMap, ghsaMap, contents: edbContents, sinceISO: options.sinceISO });
const nucleiResult = buildNucleiModels(nucleiTemplates, { cveMap });
// 治理 A1：repo×CVE 对级准入（仓库名/README 实证），fail-closed；结果磁盘缓存断点续跑
const { admitRepoCves } = await import('./exp-corpus/pocgithub.mjs');
const ghpocAdmission = await admitRepoCves(pocghMdRecords, {
  blacklistSet: pocghBlacklistSet,
  skipReadme: options.ghpocNoReadme,
  readmeLimit: options.ghpocReadmeLimit,
  cacheDir: join(rootDir, 'data', 'exp-corpus', 'cache', 'ghpoc-readme'),
  log,
});
  log(`[ghpoc] 准入：名字准入 ${ghpocAdmission.skipped.nameAdmitted} 对 / README 拒绝 ${ghpocAdmission.skipped.readmeRejected} / 失败 ${ghpocAdmission.skipped.readmeFailed} / 拉取 ${ghpocAdmission.skipped.readmesFetched}，准入仓库 ${ghpocAdmission.admission.size}`);
const ghpocResult = buildGithubPocModels(pocghMdRecords, { cveMap, blacklistSet: pocghBlacklistSet, admission: ghpocAdmission.admission });
const msfResult = buildMsfModels(msfModules, { cveMap });
const allPairs = [...pairs, ...nucleiResult.pairs, ...ghpocResult.pairs, ...msfResult.pairs];
log(`[map] 模型合计 ${allPairs.length} 条 = EDB ${pairs.length}（窗口外 ${skipped.outOfWindow}，畸形 ${skipped.malformed}）+ Nuclei 模板 ${nucleiResult.pairs.length} + GitHub PoC 仓库 ${ghpocResult.pairs.length}（无仓库 md ${ghpocResult.skipped.noRepos}，黑名单 ${ghpocResult.skipped.blacklisted}）+ Metasploit 模块 ${msfResult.pairs.length}（无 CVE 跳过 ${msfResult.skipped.noCve}）；NVD 映射 ${cveMap.size} 个 CVE，GHSA 命中 ${ghsaMap.size}`);

if (options.verify) {
  const { sanitizeExploit } = await import('../server/sanitize.mjs');
  const severities = new Set(['critical', 'high', 'medium', 'low']);
  let invalid = 0;
  const firstInvalid = [];
  allPairs.forEach(({ bizKey, exploit }) => {
    const normalized = sanitizeExploit({ ...exploit, id: `EXP-${'0'.repeat(26)}` });
    // 无编号是合法状态（nuclei 厂商漏洞模板/知识型条目无 CVE，与策展层口径一致）；
    // 硬校验只卡：severity 合法、参考链接非空、vulnType 已归类、标题非空
    if (!severities.has(normalized.severity) || !normalized.references.length || !normalized.vulnType || !normalized.name) {
      invalid += 1;
      if (firstInvalid.length < 5) firstInvalid.push(`${bizKey}: severity=${normalized.severity} refs=${normalized.references.length} type=${normalized.vulnType}`);
    }
  });
  if (invalid) {
    console.error(`[verify] ${invalid} 条模型未通过校验，样例：`);
    firstInvalid.forEach(item => console.error(`  ✖ ${item}`));
    process.exit(1);
  }
  log(`[verify] ${allPairs.length} 条模型全部通过校验；未写库（verify 模式）`);
  process.exit(0);
}

const { getRuntimeDbFile } = await import('../server/data-store.mjs');
const runtimeDbFile = getRuntimeDbFile();
if (!existsSync(runtimeDbFile)) {
  console.error(`运行库不存在：${runtimeDbFile}（先启动一次服务完成初始化）`);
  process.exit(1);
}
const { DatabaseSync } = await import('node:sqlite');
const { applyExploitModels } = await import('./exp-corpus/apply.mjs');
const database = new DatabaseSync(runtimeDbFile);
const stats = applyExploitModels(database, allPairs, { force: options.force, reconcile: options.reconcile });
// 治理 F-sev：severity 全表按 NVD 官方档对齐（精选+聚合统一口径，幂等）
const { calibrateSeverity, loadNvdScoreMap } = await import('./exp-corpus/calibrate.mjs');
const calibrateStats = calibrateSeverity(database, loadNvdScoreMap(cacheDir), { log });
database.close();

const deletedText = Object.entries(stats.deletedBySource || {}).map(([prefix, count]) => `${prefix}:${count}`).join(' ') || '无';
log(`[apply] 新增 ${stats.imported} / 更新 ${stats.updated} / 内容未变 ${stats.unchanged} / 管理员编辑保留 ${stats.keptAdmin} / 对账清理${options.reconcile ? '' : '（--no-reconcile 关闭）'} ${deletedText}`);
log(`[apply] severity 官方档校准：修正 ${calibrateStats.fixed} 条`);
log('运行库已更新。重启 Payloader 服务后生效（运行中的服务持有内存缓存）。');
