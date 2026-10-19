// EXP 聚合管线测试（v2.0.3）：EDB 解析映射 / NVD 提取 / OSV 批查 / 幂等落库。
// 全部 fixture 驱动，不打真实网络；落库用临时内存库（镜像表结构）。

import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { parseEdbCsv, buildExploitModels, severityFromScore } from '../scripts/exp-corpus/edb.mjs';
import { buildWindows, extractCveEntry } from '../scripts/exp-corpus/nvd.mjs';
import { fetchGhsaMap } from '../scripts/exp-corpus/osv.mjs';
import { applyExploitModels } from '../scripts/exp-corpus/apply.mjs';

const CSV_HEADER = 'id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url';

// ---- CSV 解析 ----

test('parseEdbCsv：RFC4180 引号字段（逗号/双引号转义）、列契约校验', () => {
  const csv = [
    CSV_HEADER,
    '51190,exploits/linux/webapps/51190.py,"Appsmith 1.10.4 - NoSQL Injection",2023-04-10,Some Author,webapps,linux,443,2023-04-10,2023-04-11,1,"CVE-2023-2879;OSVDB-123",,,,,',
    '50592,exploits/multiple/webapps/50592.txt,"Spring ""Cloud"" Gateway - RCE (CVE-2022-22947)",2022-01-25,"Author, Jr",remote,multiple,,2022-01-25,2022-02-01,0,,,,,,,,',
  ].join('\n');
  const records = parseEdbCsv(csv);
  assert.equal(records.length, 2);
  assert.equal(records[0].codes, 'CVE-2023-2879;OSVDB-123');
  assert.equal(records[1].author, 'Author, Jr');
  assert.equal(records[1].description, 'Spring "Cloud" Gateway - RCE (CVE-2022-22947)');
  assert.equal(records[1].verified, '0');

  const broken = csv.replace(',verified,codes', ',verified,extra_col');
  assert.throws(() => parseEdbCsv(broken), /表头变化/);
});

// ---- 模型映射 ----

const fixtureRecords = [
  // 有 codes CVE + NVD 映射命中：sqli / critical / CPE 产品
  {
    id: '51190',
    file: 'exploits/linux/webapps/51190.py',
    description: 'Appsmith 1.10.4 - NoSQL Injection',
    date_published: '2023-04-10',
    author: 'Some Author',
    type: 'webapps',
    platform: 'linux',
    port: '443',
    date_added: '2023-04-10',
    date_updated: '2023-04-11',
    verified: '1',
    codes: 'CVE-2023-2879;OSVDB-123',
    tags: '',
    aliases: '',
    screenshot_url: '',
    application_url: '',
    source_url: '',
  },
  // 无 codes：description 兜底提 CVE + 关键词类型映射；无 NVD 命中（medium + 未校准说明）
  {
    id: '50592',
    file: 'exploits/multiple/webapps/50592.txt',
    description: 'Spring Cloud Gateway - Remote Code Execution (CVE-2022-22947)',
    date_published: '2022-01-25',
    author: 'Author, Jr',
    type: 'remote',
    platform: 'multiple',
    port: '',
    date_added: '2022-01-25',
    date_updated: '2022-02-01',
    verified: '0',
    codes: '',
    tags: '',
    aliases: '',
    screenshot_url: '',
    application_url: '',
    source_url: 'https://example.com/advisory',
  },
  // 窗口外（2010）与畸形（缺日期）在下方用例追加
];

const cveMapFixture = new Map([
  ['CVE-2023-2879', { score: 9.8, cwe: 'CWE-89', products: ['appsmith:appsmith'] }],
]);

const ghsaMapFixture = new Map([
  ['CVE-2023-2879', 'GHSA-test-aaaa-bbbb'],
]);

test('buildExploitModels：CVE 提取、类型映射、severity、产品、编号与来源署名', () => {
  const { pairs, skipped } = buildExploitModels(fixtureRecords, {
    cveMap: cveMapFixture,
    ghsaMap: ghsaMapFixture,
    sinceISO: '2020-09-01',
  });
  assert.equal(pairs.length, 2);
  assert.deepEqual(skipped, { outOfWindow: 0, malformed: 0, clones: 0 });

  const [first, second] = pairs;
  assert.equal(first.bizKey, 'edb:51190');
  assert.equal(first.exploit.vulnType, 'sqli');
  assert.equal(first.exploit.severity, 'critical');
  assert.equal(first.exploit.affected, 'appsmith:appsmith');
  assert.equal(first.exploit.source, 'exploit-db');
  assert.equal(first.exploit.sourceRef, 'edb-51190');
  assert.deepEqual(first.exploit.vulnerabilityIds, [
    { type: 'EDB-ID', value: '51190' },
    { type: 'CVE', value: 'CVE-2023-2879' },
    { type: 'GHSA', value: 'GHSA-test-aaaa-bbbb' },
  ]);
  assert.ok(first.exploit.tags.includes('cwe-89'));
  assert.ok(first.exploit.tags.includes('verified'));
  assert.ok(first.exploit.references.includes('https://www.exploit-db.com/exploits/51190'));
  assert.ok(first.exploit.references.includes('https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/webapps/51190.py'));
  assert.ok(first.exploit.references.includes('https://nvd.nist.gov/vuln/detail/CVE-2023-2879'));
  assert.equal(first.exploit.attribution.source, 'Exploit-DB');
  assert.equal(first.exploit.attribution.license, 'GPL-2.0');
  assert.ok(first.exploit.prerequisites.includes('利用条件：'));

  assert.equal(second.exploit.vulnType, 'rce');
  assert.equal(second.exploit.severity, 'unknown');
  assert.equal(second.exploit.affected, 'multiple');
  assert.deepEqual(second.exploit.vulnerabilityIds, [
    { type: 'EDB-ID', value: '50592' },
    { type: 'CVE', value: 'CVE-2022-22947' },
  ]);
  assert.ok(second.exploit.prerequisites.includes('未经 Exploit-DB 校验标记'));
  assert.ok(second.exploit.references.includes('https://example.com/advisory'));
});

test('buildExploitModels：窗口过滤（2020-09-01 含边界）与畸形行跳过', () => {
  const records = [
    ...fixtureRecords,
    { ...fixtureRecords[0], id: '10000', date_published: '2020-09-01', codes: 'CVE-2020-01001' },
    { ...fixtureRecords[0], id: '10001', date_published: '2020-08-31' },
    { ...fixtureRecords[0], id: '10002', date_published: '' },
  ];
  const { pairs, skipped } = buildExploitModels(records, { sinceISO: '2020-09-01' });
  assert.equal(pairs.length, 3);
  assert.ok(pairs.some(pair => pair.bizKey === 'edb:10000'));
  assert.equal(skipped.outOfWindow, 1);
  assert.equal(skipped.malformed, 1);
});

test('severityFromScore：CVSS 分段边界', () => {
  assert.equal(severityFromScore(10), 'critical');
  assert.equal(severityFromScore(9), 'critical');
  assert.equal(severityFromScore(8.9), 'high');
  assert.equal(severityFromScore(7), 'high');
  assert.equal(severityFromScore(6.9), 'medium');
  assert.equal(severityFromScore(4), 'medium');
  assert.equal(severityFromScore(3.9), 'low');
  assert.equal(severityFromScore(0.1), 'low');
  assert.equal(severityFromScore(0), 'unknown');
  assert.equal(severityFromScore(undefined), 'unknown');
});

// ---- NVD 提取 ----

test('buildWindows：六年切 ≤120 天窗口且无缝覆盖', () => {
  const sinceMs = Date.parse('2020-09-01T00:00:00.000Z');
  const untilMs = Date.parse('2026-09-27T00:00:00.000Z');
  const windows = buildWindows(sinceMs, untilMs);
  assert.ok(windows.length >= 18 && windows.length <= 20, `窗口数异常：${windows.length}`);
  let previousEnd = sinceMs - 1;
  for (const [start, end] of windows) {
    assert.equal(start, previousEnd + 1);
    assert.ok(end - start + 1 <= 120 * 24 * 60 * 60 * 1000);
    previousEnd = end;
  }
  assert.equal(previousEnd, untilMs);
});

test('extractCveEntry：CVSS 优先级（V4>V3.1>V2、Primary 优先）、CWE 过滤 NVD 占位、CPE 产品', () => {
  const entry = extractCveEntry({
    metrics: {
      cvssMetricV31: [
        { type: 'Secondary', cvssData: { baseScore: 5.0 } },
        { type: 'Primary', cvssData: { baseScore: 9.8 } },
      ],
      cvssMetricV2: [{ type: 'Primary', cvssData: { baseScore: 4.1 } }],
    },
    weaknesses: [
      { description: [{ value: 'NVD-CWE-noinfo' }] },
      { description: [{ value: 'CWE-89' }] },
    ],
    configurations: [
      { nodes: [{ cpeMatch: [
        { vulnerable: true, criteria: 'cpe:2.3:a:appsmith:appsmith:1.10.4:*:*:*:*:*:*:*:*' },
        { vulnerable: false, criteria: 'cpe:2.3:a:other:other:*:*:*:*:*:*:*:*:*' },
        { vulnerable: true, criteria: 'cpe:2.3:o:siemens:6bk1602_firmware:*:*:*:*:*:*:*:*:*' },
      ] }] },
    ],
  });
  assert.equal(entry.score, 9.8);
  assert.equal(entry.cwe, 'CWE-89');
  assert.deepEqual(entry.products, ['appsmith:appsmith', 'siemens:6bk1602_firmware']);
});

// ---- OSV 逐条互查 ----

test('fetchGhsaMap：逐条 GET 互查、GHSA id 优先 aliases 兜底、缓存增量', async () => {
  const requested = [];
  const fakeFetch = async url => {
    requested.push(url);
    const cve = String(url).split('/').pop();
    if (cve === 'CVE-2023-2879') {
      return { ok: true, json: async () => ({ id: 'CVE-2023-2879', aliases: ['GHSA-alias-1111'] }) };
    }
    return { ok: true, json: async () => ({ id: 'GHSA-direct-2222', aliases: ['CVE-2022-22947'] }) };
  };
  const map = await fetchGhsaMap(['CVE-2023-2879', 'CVE-2022-22947'], { fetchImpl: fakeFetch, concurrency: 2 });
  assert.ok(requested.includes('https://api.osv.dev/v1/vulns/CVE-2023-2879'));
  assert.equal(map.get('CVE-2023-2879'), 'GHSA-alias-1111');
  assert.equal(map.get('CVE-2022-22947'), 'GHSA-direct-2222');
});

test('fetchGhsaMap：持续失败降级返回空映射（不阻塞入库）', async () => {
  const attempts = { count: 0 };
  const failingFetch = async () => {
    attempts.count += 1;
    throw new Error('network down');
  };
  const map = await fetchGhsaMap(['CVE-2023-2879', 'CVE-2022-22947', 'CVE-2021-44228'], {
    fetchImpl: failingFetch,
    concurrency: 1,
    maxFailures: 1,
  });
  assert.equal(map.size, 0);
  // 失败达阈值即中止剩余查询
  assert.ok(attempts.count >= 1 && attempts.count <= 2, `失败计数异常：${attempts.count}`);
});

// ---- 幂等落库 ----

const setupDb = () => {
  const database = new DatabaseSync(':memory:');
  database.exec(`
    CREATE TABLE metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE exploits (
      id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  return database;
};

test('applyExploitModels：导入幂等、更新检测、管理员保护与 --force', () => {
  const database = setupDb();
  const basePairs = buildExploitModels(fixtureRecords, {
    cveMap: cveMapFixture,
    ghsaMap: ghsaMapFixture,
    sinceISO: '2020-09-01',
  }).pairs;

  const firstRun = applyExploitModels(database, basePairs);
  assert.equal(firstRun.imported, 2);
  const idsAfterFirst = database.prepare('SELECT id FROM exploits ORDER BY id').all().map(row => row.id);
  assert.equal(idsAfterFirst.length, 2);

  const rerun = applyExploitModels(database, basePairs);
  assert.deepEqual(rerun, { imported: 0, updated: 0, unchanged: 2, keptAdmin: 0, skippedHidden: 0, skippedAdmin: 0, deletedBySource: {} });
  assert.deepEqual(
    database.prepare('SELECT id FROM exploits ORDER BY id').all().map(row => row.id),
    idsAfterFirst,
  );

  // 上游内容变化 → 更新（复用同一 EXP-ULID）
  const changedPairs = buildExploitModels([
    fixtureRecords[0],
    { ...fixtureRecords[1], description: 'Spring Cloud Gateway - Remote Code Execution (CVE-2022-22947) updated' },
  ], { cveMap: cveMapFixture, ghsaMap: ghsaMapFixture, sinceISO: '2020-09-01' }).pairs;
  const changeRun = applyExploitModels(database, changedPairs);
  assert.deepEqual(changeRun, { imported: 0, updated: 1, unchanged: 1, keptAdmin: 0, skippedHidden: 0, skippedAdmin: 0, deletedBySource: {} });
  const keptIds = database.prepare('SELECT id FROM exploits ORDER BY id').all().map(row => row.id);
  assert.deepEqual(keptIds, idsAfterFirst);

  // 管理员编辑保护：runtime 哈希 ≠ 基线 → 保留管理员版本
  const editedId = database.prepare('SELECT id FROM exploits ORDER BY id').all()[0].id;
  const edited = JSON.parse(database.prepare('SELECT data FROM exploits WHERE id = ?').get(editedId).data);
  edited.tags.push('admin-note');
  database.prepare('UPDATE exploits SET data = ? WHERE id = ?').run(JSON.stringify(edited), editedId);
  const keptRun = applyExploitModels(database, changedPairs);
  assert.equal(keptRun.keptAdmin, 1);
  assert.ok(JSON.parse(database.prepare('SELECT data FROM exploits WHERE id = ?').get(editedId).data).tags.includes('admin-note'));

  // --force 覆盖管理员编辑
  const forceRun = applyExploitModels(database, changedPairs, { force: true });
  assert.equal(forceRun.keptAdmin, 0);
  assert.ok(!JSON.parse(database.prepare('SELECT data FROM exploits WHERE id = ?').get(editedId).data).tags.includes('admin-note'));
  database.close();
});

test('applyExploitModels：管理员隐藏状态在重跑后保持（enabled 不被触碰）', () => {
  const database = setupDb();
  const pairs = buildExploitModels(fixtureRecords, { sinceISO: '2020-09-01' }).pairs;
  applyExploitModels(database, pairs);
  database.prepare('UPDATE exploits SET enabled = 0').run();
  applyExploitModels(database, pairs);
  const states = database.prepare('SELECT enabled FROM exploits').all();
  assert.ok(states.every(row => row.enabled === 0));
  database.close();
});

test('applyExploitModels：对账清理只作用于本轮跑过的源（治理 A7）', () => {
  const database = setupDb();
  const pairs = buildExploitModels(fixtureRecords, { sinceISO: '2020-09-01' }).pairs;
  applyExploitModels(database, pairs);
  // 上游只剩一条时重跑：同源（edb-）多余行被对账清理
  const rerun = applyExploitModels(database, pairs.slice(0, 1));
  assert.equal(rerun.deletedBySource.edb, 1);
  assert.equal(database.prepare('SELECT COUNT(*) AS n FROM exploits').get().n, 1);
  // 未跑的源不受影响：加入 ghpoc 行后只重跑 edb，ghpoc 行保留
  const ghPair = { bizKey: 'ghpoc:x/y', exploit: { name: 'gh', vulnType: 'rce', severity: 'high', publishedAt: '2024-01-01', affected: '', vulnerabilityIds: [], exploitCode: [], prerequisites: '', references: [], tags: [], sourceRef: 'ghpoc-x/y', source: 'gh-poc' } };
  applyExploitModels(database, [pairs[0], ghPair]);
  applyExploitModels(database, [pairs[0]]);
  assert.equal(database.prepare('SELECT COUNT(*) AS n FROM exploits').get().n, 2);
  database.close();
});

test('applyExploitModels reconcile：隐藏行与管理员编辑行是墓碑——不删除、不复活（P1-1 回归）', () => {
  const database = setupDb();
  const mkPair = (sourceRef, name) => ({
    bizKey: sourceRef,
    exploit: { name, vulnType: 'rce', severity: 'high', publishedAt: '2024-01-01', affected: '', vulnerabilityIds: [], exploitCode: [], prerequisites: '', references: [], tags: [], sourceRef, source: sourceRef.startsWith('edb') ? 'exploit-db' : 'gh-poc' },
  });
  const pairs = [mkPair('edb-a', '原始条目 A'), mkPair('edb-b', '原始条目 B'), mkPair('edb-c', '原始条目 C')];
  applyExploitModels(database, pairs);
  assert.equal(database.prepare('SELECT COUNT(*) AS n FROM exploits').get().n, 3);

  // 管理员隐藏 A、编辑 B；C 不动
  const idOf = name => database.prepare('SELECT id, data FROM exploits').all()
    .map(row => ({ ...row, name: JSON.parse(row.data).name }))
    .find(row => row.name === name)?.id;
  const aId = idOf('原始条目 A');
  const bId = idOf('原始条目 B');
  database.prepare('UPDATE exploits SET enabled = 0 WHERE id = ?').run(aId);
  database.prepare("UPDATE exploits SET data = json_set(data, '$.name', '管理员改过 B') WHERE id = ?").run(bId);

  // 第二轮源里 A、B 消失（对账应删它们），C 名字变了（upsert 更新）
  const round2 = [mkPair('edb-c', '上游改了 C')];
  const run = applyExploitModels(database, round2);
  assert.equal(run.skippedHidden, 1, '隐藏行不计入对账删除');
  assert.equal(run.skippedAdmin, 1, '管理员编辑行不计入对账删除');
  const after = database.prepare('SELECT id, enabled, data FROM exploits ORDER BY id').all();
  assert.equal(after.length, 3, '隐藏行与编辑行都还在库中');

  // 关键回归：第三轮源又收录了 A（原 bizKey）——必须仍以 UPDATE 命中存活行而不是 INSERT 复活
  const round3 = [mkPair('edb-c', '上游改了 C'), mkPair('edb-a', '原始条目 A（源重收录）')];
  applyExploitModels(database, round3);
  const aRow = database.prepare('SELECT enabled FROM exploits WHERE id = ?').get(aId);
  assert.equal(aRow.enabled, 0, '管理员隐藏在对账删行→源重收录后不得复活为公开');
  // 隐藏行仍被本轮 upsert 命中（data 更新但 enabled 不动），而不是新行
  assert.equal(database.prepare('SELECT COUNT(*) AS n FROM exploits WHERE data LIKE \'%源重收录%\'').get().n, 1);
  const bRow = JSON.parse(database.prepare('SELECT data FROM exploits WHERE id = ?').get(bId).data);
  assert.equal(bRow.name, '管理员改过 B', '编辑行对账轮后内容仍保留');
  database.close();
});

test('applyExploitModels：窄窗口跑一轮后，宽窗口轮次之外的历史键仍受管理员保护', () => {
  const database = setupDb();
  const wide = buildExploitModels(fixtureRecords, { sinceISO: '2020-09-01' }).pairs;
  applyExploitModels(database, wide);
  // 管理员编辑第一条
  const editedId = database.prepare('SELECT id FROM exploits ORDER BY id').all()[0].id;
  const edited = JSON.parse(database.prepare('SELECT data FROM exploits WHERE id = ?').get(editedId).data);
  edited.tags.push('admin-note');
  database.prepare('UPDATE exploits SET data = ? WHERE id = ?').run(JSON.stringify(edited), editedId);
  // 窄窗口重跑（pairs 为空，基线 hashes 仍须延续上一轮全量）
  applyExploitModels(database, []);
  // 再全量重跑：管理员编辑必须保留（基线哈希未丢）
  const rerun = applyExploitModels(database, wide);
  assert.ok(rerun.keptAdmin >= 1, `期望管理员编辑被保留：${JSON.stringify(rerun)}`);
  assert.ok(JSON.parse(database.prepare('SELECT data FROM exploits WHERE id = ?').get(editedId).data).tags.includes('admin-note'));
  database.close();
});

// ---- Nuclei 补源（zip 读取 + 模板映射）----

import { readZipEntries } from '../scripts/exp-corpus/zip.mjs';
import { buildNucleiModels, extractTemplateFields } from '../scripts/exp-corpus/nuclei.mjs';
import { deflateRawSync } from 'node:zlib';

test('readZipEntries：手工构造 zip（store + deflate 双条目）可完整还原', () => {
  const fileA = Buffer.from('hello nuclei template', 'utf8');
  const fileB = deflateRawSync(Buffer.from('deflated content '.repeat(20), 'utf8'));
  const nameA = Buffer.from('nuclei-templates-main/http/cves/2021/CVE-2021-44228.yaml');
  const nameB = Buffer.from('nuclei-templates-main/http/vulnerabilities/yonyou/test.yaml');

  const localHeader = (name, data, method, crc, compressedSize, size) => {
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(method, 8);
    head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(compressedSize, 18);
    head.writeUInt32LE(size, 22);
    head.writeUInt16LE(name.length, 26);
    return Buffer.concat([head, name]);
  };
  const centralHeader = (name, data, method, crc, compressedSize, size, localOffset) => {
    const head = Buffer.alloc(46);
    head.writeUInt32LE(0x02014b50, 0);
    head.writeUInt16LE(method, 10);
    head.writeUInt32LE(crc, 16);
    head.writeUInt32LE(compressedSize, 20);
    head.writeUInt32LE(size, 24);
    head.writeUInt16LE(name.length, 28);
    head.writeUInt32LE(localOffset, 42);
    return Buffer.concat([head, name]);
  };
  const crc32 = buffer => {
    let table = crc32.table;
    if (!table) {
      table = crc32.table = new Int32Array(256);
      for (let n = 0; n < 256; n += 1) {
        let c = n;
        for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        table[n] = c;
      }
    }
    let crc = -1;
    for (const byte of buffer) crc = (crc >>> 8) ^ table[(crc ^ byte) & 0xff];
    return (crc ^ -1) >>> 0;
  };

  const localA = localHeader(nameA, fileA, 0, crc32(fileA), fileA.length, fileA.length);
  const localB = localHeader(nameB, fileB, 8, crc32(fileB), fileB.length, fileB.length);
  const sectionA = localA.length + fileA.length;
  const sectionB = localB.length + fileB.length;
  const cdA = centralHeader(nameA, fileA, 0, crc32(fileA), fileA.length, fileA.length, 0);
  const cdB = centralHeader(nameB, fileB, 8, crc32(fileB), fileB.length, fileB.length, sectionA);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(2, 10);
  eocd.writeUInt32LE(cdA.length + cdB.length, 12);
  eocd.writeUInt32LE(sectionA + sectionB, 16);
  const zip = Buffer.concat([localA, fileA, localB, fileB, cdA, cdB, eocd]);

  const all = readZipEntries(zip);
  assert.equal(all.length, 2);
  assert.equal(all[0].data.toString(), 'hello nuclei template');
  assert.equal(all[1].data.toString().startsWith('deflated content'), true);

  const filtered = readZipEntries(zip, path => path.includes('/cves/'));
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].path, 'nuclei-templates-main/http/cves/2021/CVE-2021-44228.yaml');
});

const NUCLEI_FIXTURE = `id: CVE-2023-37580

info:
  name: Apache Jackrabbit - Text Extraction Query Language Injection
  author: DhiyaneshDK
  severity: critical
  description: |
    Apache Jackrabbit vulnerable to text extraction query language injection.
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2023-37580
    cwe-id: CWE-74
  tags: jackrabbit,apache,cve2023,rce
http:
  - method: GET
`;

test('extractTemplateFields + buildNucleiModels：nuclei YAML → EXP 模型', () => {
  const template = extractTemplateFields(NUCLEI_FIXTURE, 'nuclei-templates-main/http/cves/2023/CVE-2023-37580.yaml');
  assert.equal(template.id, 'CVE-2023-37580');
  assert.equal(template.severity, 'critical');
  assert.equal(template.cwe, 'CWE-74');
  assert.deepEqual(template.cves, ['CVE-2023-37580']);
  assert.ok(template.tags.includes('rce'));

  const { pairs } = buildNucleiModels([template], {
    cveMap: new Map([['CVE-2023-37580', { score: 9.8, cwe: 'CWE-74', products: ['apache:jackrabbit'] }]]),
  });
  assert.equal(pairs.length, 1);
  const exploit = pairs[0].exploit;
  assert.equal(pairs[0].bizKey, 'nuclei:CVE-2023-37580');
  assert.equal(exploit.source, 'nuclei');
  assert.equal(exploit.sourceRef, 'nuclei-CVE-2023-37580');
  assert.equal(exploit.severity, 'critical');
  assert.equal(exploit.vulnType, 'rce');
  assert.equal(exploit.affected, 'apache:jackrabbit');
  assert.equal(exploit.publishedAt, '2023');
  assert.deepEqual(exploit.vulnerabilityIds, [{ type: 'CVE', value: 'CVE-2023-37580' }]);
  assert.ok(exploit.references.includes('https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/nuclei-templates-main/http/cves/2023/CVE-2023-37580.yaml'));
  assert.equal(exploit.attribution.license, 'MIT');
});

test('buildNucleiModels：无 NVD 命中回落厂商目录段 + tags 兜底类型', () => {
  const template = extractTemplateFields(`id: yonyou-nc-upload
info:
  name: Yonyou NC - Arbitrary File Upload
  severity: high
  tags: yonyou,upload,intrusive
`, 'nuclei-templates-main/http/vulnerabilities/yonyou/yonyou-nc-upload.yaml');
  const { pairs } = buildNucleiModels([template]);
  assert.equal(pairs[0].exploit.vulnType, 'file-upload');
  assert.equal(pairs[0].exploit.affected, 'yonyou');
  assert.equal(pairs[0].exploit.publishedAt, String(new Date().getFullYear()));
});

// ---- GitHub PoC 聚合源（trickest/cve md 解析 + repo 聚合）----

import { admitRepoCves, parseCveMd, buildGithubPocModels } from '../scripts/exp-corpus/pocgithub.mjs';

const GHPpoc_MD_FIXTURE = `### [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)
![](https://img.shields.io/static/v1?label=Product&message=Apache%20Log4j2&color=blue)
![](https://img.shields.io/static/v1?label=Version&message=2.0-beta9%20&color=brightgreen)
![](https://img.shields.io/static/v1?label=Vulnerability&message=CWE-20%20Improper%20Input%20Validation&color=brightgreen)
![](https://img.shields.io/static/v1?label=Vulnerability&message=CWE-502%20Deserialization%20of%20Untrusted%20Data&color=brightgreen)

### Description

Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration do not protect against attacker controlled LDAP endpoints.

#### Reference
- http://packetstormsecurity.com/files/165225/Apache-Log4j2.html
- https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228

#### Github
- https://github.com/0x3SC4L4T3/Apache-Log4j-POC
- https://github.com/0x49b/jndisearch
- https://github.com/blacklisted-owner/evil-repo
`;

test('parseCveMd：badge 提取 Product/CWE、Description、Github 段仓库（Reference 段不算）', () => {
  const record = parseCveMd(GHPpoc_MD_FIXTURE, 'cve-main/2021/CVE-2021-44228.md');
  assert.equal(record.cveId, 'CVE-2021-44228');
  assert.equal(record.product, 'Apache Log4j2');
  assert.deepEqual(record.cwes, ['CWE-20', 'CWE-502']);
  assert.ok(record.description.startsWith('Apache Log4j2 2.0-beta9'));
  // Reference 段的 github.com/nu11secur1ty 不入 repos；Github 段两个仓库规范化小写
  assert.deepEqual(record.repos, ['0x3sc4l4t3/apache-log4j-poc', '0x49b/jndisearch', 'blacklisted-owner/evil-repo']);
});

test('buildGithubPocModels：repo 聚合多 CVE、黑名单过滤、CWE 类型映射、严重度取 NVD 最高', async () => {
  const secondMd = parseCveMd(GHPpoc_MD_FIXTURE.replace(/44228/g, '45046'), 'cve-main/2021/CVE-2021-45046.md');
  const records = [parseCveMd(GHPpoc_MD_FIXTURE, 'cve-main/2021/CVE-2021-44228.md'), secondMd];
  const cveMap = new Map([
    ['CVE-2021-44228', { score: 10, cwe: 'CWE-502', products: ['apache:log4j2'] }],
    ['CVE-2021-45046', { score: 9, cwe: 'CWE-502', products: ['apache:log4j2'] }],
  ]);
  const blacklistSet = new Set(['blacklisted-owner']);
  // 治理 A1：repo×CVE 对级准入——README mock 实质引用两个 CVE（Last-Modified 缺省回退年份口径）
  const { admission } = await admitRepoCves(records, {
    blacklistSet,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      headers: { get: () => '' },
      text: async () => 'Log4Shell PoC. Affects CVE-2021-44228 and CVE-2021-45046.',
    }),
  });
  const { pairs, skipped } = buildGithubPocModels(records, { cveMap, blacklistSet, admission });

  // jndisearch 只关联 1 个 CVE（45046 的 md 里 repo 是 44228 的名字改写后还是同两个仓库——两 md 的 Github 段相同）
  const jndi = pairs.find(pair => pair.bizKey === 'ghpoc:0x49b/jndisearch');
  assert.ok(jndi, 'jndisearch 应存在');
  assert.equal(jndi.exploit.severity, 'critical');
  assert.equal(jndi.exploit.vulnType, 'deserialization');
  assert.equal(jndi.exploit.publishedAt, '2021');
  assert.ok(jndi.exploit.affected.includes('Apache Log4j2'));
  assert.ok(jndi.exploit.vulnerabilityIds.some(vid => vid.value === 'CVE-2021-44228'));
  assert.equal(jndi.exploit.source, 'gh-poc');
  assert.equal(jndi.exploit.sourceRef, 'ghpoc-0x49b/jndisearch');
  assert.equal(jndi.exploit.attribution.author, '0x49b');
  assert.ok(jndi.exploit.prerequisites.includes('隔离环境'));

  // 黑名单仓库被过滤
  assert.ok(!pairs.some(pair => pair.bizKey.includes('blacklisted-owner')));
  assert.ok(skipped.blacklisted >= 2);
});

test('buildGithubPocModels：无 NVD 命中回落 unknown 与 uncategorized（repo 名关键词兜底）', async () => {
  const md = parseCveMd(`### [CVE-2016-1111](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1111)

### Description

Some old vuln.

#### Github
- https://github.com/someone/CVE-2016-1111-rce-exploit
`, 'cve-main/2016/CVE-2016-1111.md');
  // 仓库名含 CVE 编号 → 名字准入，无需 README 实证
  const { admission } = await admitRepoCves([md], { blacklistSet: new Set(), skipReadme: true });
  const { pairs } = buildGithubPocModels([md], { cveMap: new Map(), blacklistSet: new Set(), admission });
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0].exploit.severity, 'unknown');
  assert.equal(pairs[0].exploit.vulnType, 'rce');
  assert.equal(pairs[0].exploit.publishedAt, '2016');
});

test('admitRepoCves：README 不引用该 CVE 的 repo 不准入（fail-closed）', async () => {
  const md = parseCveMd(GHPpoc_MD_FIXTURE, 'cve-main/2021/CVE-2021-44228.md');
  const { admission } = await admitRepoCves([md], {
    blacklistSet: new Set(),
    fetchImpl: async url => {
      if (String(url).includes('jndisearch')) {
        return { ok: true, status: 200, headers: { get: () => '' }, text: async () => 'Unrelated README without any CVE id.' };
      }
      return { status: 404, ok: false, headers: { get: () => '' }, text: async () => '' };
    },
  });
  // Apache-Log4j-POC 返回 404 → 不准入；jndisearch README 无 CVE → 不准入
  assert.equal(admission.size, 0);
  const { pairs } = buildGithubPocModels([md], { cveMap: new Map(), blacklistSet: new Set(), admission });
  assert.equal(pairs.length, 0);
});

// ---- 正文注入与 MSF 源 ----

import { codeSegmentsFromContent } from '../scripts/exp-corpus/edb.mjs';
import { parseMsfModule, buildMsfModels } from '../scripts/exp-corpus/msf.mjs';

test('codeSegmentsFromContent：脚本/HTTP/curl 三形态识别与语言映射', () => {
  const py = codeSegmentsFromContent('#!/usr/bin/env python3\nimport os\nos.system("id")', 'exploits/x/51190.py', 'https://www.exploit-db.com/exploits/51190');
  assert.equal(py.format, 'script');
  assert.equal(py.segments[0].language, 'python');
  assert.match(py.segments[0].title, /完整利用脚本/);

  const http = codeSegmentsFromContent('GET / HTTP/1.1\nHost: t', 'exploits/x/123.txt', '');
  assert.equal(http.format, 'http-poc');
  assert.match(http.segments[0].title, /Burp/);

  const curl = codeSegmentsFromContent('# usage\ncurl -s http://t/', 'exploits/x/124.txt', '');
  assert.equal(curl.format, 'curl');
});

test('buildExploitModels：正文注入后 exploitCode 非空且带形态 tag', () => {
  const record = { ...fixtureRecords[0] };
  const contents = new Map([[record.file, '#!/usr/bin/env python3\nprint("pwn")']]);
  const { pairs } = buildExploitModels([record], { contents, sinceISO: '2020-09-01' });
  assert.equal(pairs[0].exploit.exploitCode.length, 1);
  assert.equal(pairs[0].exploit.exploitCode[0].language, 'python');
  assert.ok(pairs[0].exploit.tags.includes('format:script'));
});

const MSF_FIXTURE = `##
require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Test Module RCE',
      'Description'    => %q{ Test description for module. },
      'References'     =>
        [
          ['CVE', '2021-44228'],
          ['URL', 'https://example.com']
        ],
      'DisclosureDate' => '2021-12-10'))
  end
end
`;

test('parseMsfModule + buildMsfModels：模块解析（Name/refs CVE/rank）与完整脚本入库', () => {
  const module = parseMsfModule(MSF_FIXTURE, 'exploits/multi/http/test_mod.rb');
  assert.equal(module.name, 'Test Module RCE');
  assert.equal(module.rank, 'ExcellentRanking');
  assert.deepEqual(module.cves, ['CVE-2021-44228']);

  const { pairs } = buildMsfModels([module]);
  assert.equal(pairs.length, 1);
  const exploit = pairs[0].exploit;
  assert.equal(pairs[0].bizKey, 'msf:exploit/multi/http/test_mod');
  assert.equal(exploit.source, 'metasploit');
  assert.equal(exploit.exploitCode[0].language, 'ruby');
  assert.match(exploit.exploitCode[0].title, /msfconsole/);
  assert.ok(exploit.tags.includes('format:script'));
  assert.ok(exploit.references[0].includes('rapid7/metasploit-framework'));

  // 无 CVE 的模块不入库（保持信噪比）
  assert.equal(parseMsfModule('x'.repeat(10), 'exploits/a/b/no_cve.rb'), null);
});

// ---- 治理 A6/A7：canonical 分组 API 与对账清理 ----

test('dedupeByCanonical 与 product 过滤：源优先级取代表 + products[] 主通道', async () => {
  const { createExploitRoutes } = await import('../server/routes-exploits.mjs');
  const all = [
    { id: 'EXP-GH', name: 'gh 实现', source: 'gh-poc', sourceRef: 'ghpoc-a/b', canonicalKey: 'CVE-2021-44228', vulnType: 'rce', severity: 'critical', publishedAt: '2021-12-10', affected: '', products: ['Apache Log4j2'], vulnerabilityIds: [{ type: 'CVE', value: 'CVE-2021-44228' }], tags: [] },
    { id: 'EXP-EDB', name: 'edb 实现', source: 'exploit-db', sourceRef: 'edb-123', canonicalKey: 'CVE-2021-44228', vulnType: 'rce', severity: 'critical', publishedAt: '2021-12-13', affected: 'log4j', products: ['Apache Log4j2'], vulnerabilityIds: [{ type: 'CVE', value: 'CVE-2021-44228' }], tags: [] },
    { id: 'EXP-MSF', name: 'msf 实现', source: 'metasploit', sourceRef: 'msf-exploit/x', canonicalKey: 'CVE-2021-44228', vulnType: 'rce', severity: 'critical', publishedAt: '2021-12-12', affected: '', products: [], vulnerabilityIds: [{ type: 'CVE', value: 'CVE-2021-44228' }], tags: [] },
    { id: 'EXP-CUR', name: '精选', source: 'curated', sourceRef: '', canonicalKey: 'CVE-2021-44228', vulnType: 'rce', severity: 'critical', publishedAt: '2021-12-01', affected: 'log4j2', products: ['Apache Log4j2'], vulnerabilityIds: [{ type: 'CVE', value: 'CVE-2021-44228' }], tags: [] },
  ];
  const captured = [];
  const { registerExploitRoutes } = createExploitRoutes({ listExploits: async () => { captured.push(1); return all; } });
  const router = { route: (methods, path, handler) => { router[path] = handler; } };
  registerExploitRoutes(router);

  const urlOf = query => new URL(`http://localhost/api/exploits${query}`);
  const responseShim = () => ({
    statusCode: 0,
    setHeader: () => {},
    writeHead(code) { this.statusCode = code; },
    end(body) { this.body = body; },
  });

  // dedupe=canonical：精选层优先级最高，代表=精选，sourceCount=4
  const res1 = responseShim();
  await router['/api/exploits']({}, res1, { url: urlOf('?dedupe=canonical') });
  const body1 = JSON.parse(res1.body);
  assert.equal(body1.total, 1);
  assert.equal(body1.items[0].id, 'EXP-CUR');
  assert.equal(body1.items[0].sourceCount, 4);

  // product 过滤走 products[]（affected 为空也能命中）
  const res2 = responseShim();
  await router['/api/exploits']({}, res2, { url: urlOf('?product=log4j&source=gh-poc') });
  const body2 = JSON.parse(res2.body);
  assert.equal(body2.total, 1);
  assert.equal(body2.items[0].id, 'EXP-GH');

  // 详情：relatedSources 按源优先级排列（精选排首）
  const res3 = responseShim();
  await router['/api/exploits/:id']({}, res3, { params: { id: 'EXP-GH' } });
  const body3 = JSON.parse(res3.body);
  assert.deepEqual(body3.relatedSources.map(item => item.id), ['EXP-CUR', 'EXP-EDB', 'EXP-MSF']);
});

test('dedupeByCanonical 动态 key：无存储 canonicalKey 的条目按主 CVE 聚合（F3）', async () => {
  const { createExploitRoutes } = await import('../server/routes-exploits.mjs');
  // 关键差异：全部条目不带 canonicalKey 字段（EDB/nuclei/MSF 的真实形态），动态算 primaryCveKey
  const all = [
    { id: 'EXP-EDB2', name: 'edb 实现（无存储 key）', source: 'exploit-db', sourceRef: 'edb-999', vulnType: 'rce', severity: 'critical', publishedAt: '2021-12-13', affected: '', products: [], vulnerabilityIds: [{ type: 'CVE', value: 'CVE-2016-4437' }], tags: [] },
    { id: 'EXP-NUC2', name: 'nuclei 实现（无存储 key）', source: 'nuclei', sourceRef: 'nuclei-CVE-2016-4437', vulnType: 'auth-bypass', severity: 'high', publishedAt: '2021-11-01', affected: '', products: [], vulnerabilityIds: [{ type: 'CVE', value: 'CVE-2016-4437' }], tags: [] },
    { id: 'EXP-MSF2', name: 'msf 实现（无存储 key）', source: 'metasploit', sourceRef: 'msf-exploit/y', vulnType: 'rce', severity: 'critical', publishedAt: '2021-12-05', affected: '', products: [], vulnerabilityIds: [{ type: 'CVE', value: 'CVE-2016-4437' }], tags: [] },
    { id: 'EXP-OTHER', name: '不同漏洞不参与聚合', source: 'exploit-db', sourceRef: 'edb-998', vulnType: 'xss', severity: 'medium', publishedAt: '2020-01-01', affected: '', products: [], vulnerabilityIds: [{ type: 'CVE', value: 'CVE-2020-9999' }], tags: [] },
  ];
  const { registerExploitRoutes } = createExploitRoutes({ listExploits: async () => all });
  const router = { route: (methods, path, handler) => { router[path] = handler; } };
  registerExploitRoutes(router);
  const urlOf = query => new URL(`http://localhost/api/exploits${query}`);
  const responseShim = () => ({
    statusCode: 0,
    setHeader: () => {},
    writeHead(code) { this.statusCode = code; },
    end(body) { this.body = body; },
  });
  const res = responseShim();
  await router['/api/exploits']({}, res, { url: urlOf('?dedupe=canonical&vid=CVE-2016-4437') });
  const body = JSON.parse(res.body);
  assert.equal(body.total, 1, '同 CVE 三源聚合成一个代表');
  assert.equal(body.items[0].id, 'EXP-EDB2', '代表按源优先级取 exploit-db');
  assert.equal(body.items[0].sourceCount, 3);
  const resNoDedupe = responseShim();
  await router['/api/exploits']({}, resNoDedupe, { url: urlOf('?vid=CVE-2016-4437') });
  assert.equal(JSON.parse(resNoDedupe.body).total, 3, '不加 dedupe 时保持原行为');
});

test('applyExploitModels reconcile：业务键收紧后旧行对账清理、精选层不受影响、幂等', () => {
  const database = setupDb();
  const mkPair = (bizKey, sourceRef, name) => ({
    bizKey,
    exploit: { name, vulnType: 'rce', severity: 'high', publishedAt: '2024-01-01', affected: '', vulnerabilityIds: [], exploitCode: [], prerequisites: '', references: [], tags: [], sourceRef, source: sourceRef.split('-')[0] === 'edb' ? 'exploit-db' : 'gh-poc' },
  });
  // 第一轮：ghpoc 旧规则入库 2 条（a、b）+ 精选 1 条（无 sourceRef）
  const round1 = [
    mkPair('ghpoc:a', 'ghpoc-a', 'repo a'),
    mkPair('ghpoc:b', 'ghpoc-b', 'repo b'),
    { bizKey: 'curated:log4shell', exploit: { name: '精选 Log4Shell', vulnType: 'rce', severity: 'critical', publishedAt: '2021-12-10', affected: '', vulnerabilityIds: [], exploitCode: [], prerequisites: '', references: [], tags: [] } },
  ];
  const firstRun = applyExploitModels(database, round1);
  assert.equal(firstRun.imported, 3);

  // 第二轮：准入收紧，ghpoc 只剩 a → b 被对账清理；精选层不动
  const round2 = [mkPair('ghpoc:a', 'ghpoc-a', 'repo a（准入规则收紧后重新生成）')];
  const secondRun = applyExploitModels(database, round2);
  assert.equal(secondRun.updated, 1);
  assert.equal(secondRun.deletedBySource.ghpoc, 1);
  const remaining = database.prepare('SELECT id, data FROM exploits ORDER BY id').all().map(row => JSON.parse(row.data).name);
  assert.equal(remaining.length, 2);
  assert.ok(remaining.includes('精选 Log4Shell'));
  assert.ok(remaining.includes('repo a（准入规则收紧后重新生成）'));

  // 第三轮重跑同样集合：幂等，无新增删除
  const thirdRun = applyExploitModels(database, round2);
  assert.equal(thirdRun.updated, 0);
  assert.equal(thirdRun.imported, 0);
  assert.deepEqual(thirdRun.deletedBySource, {});
});

test('sanitizeExploit：products/canonicalKey 白名单落库', async () => {
  const { sanitizeExploit } = await import('../server/sanitize.mjs');
  const sanitized = sanitizeExploit({
    name: 'x', products: ['Nginx', 'nginx', '', 'OpenSSH'], canonicalKey: 'CVE-2021-44228',
  });
  assert.deepEqual(sanitized.products, ['Nginx', 'nginx', 'OpenSSH']);
  assert.equal(sanitized.canonicalKey, 'CVE-2021-44228');
  const minimal = sanitizeExploit({ name: 'y' });
  assert.equal(minimal.products, undefined);
  assert.equal(minimal.canonicalKey, undefined);
});

// ---- products 词边界（误关联修复回归）----

test('deriveProducts 词边界含下划线：cpe 复合键不再误派生裸产品词', async () => {
  const { deriveProducts, productStandsAlone } = await import('../scripts/exp-corpus/products.mjs');
  // oracle:mysql_enterprise_monitor 中的 mysql 曾派生裸 'MySQL'，把 MySQL UDF 载荷误挂到 Struts 条目
  const products = deriveProducts({ name: 'Apache Struts 2.5.20 - Double OGNL evaluation', description: '', affected: 'apache:struts; oracle:mysql_enterprise_monitor' });
  assert.ok(!products.includes('MySQL'), `复合键不得派生裸 MySQL: ${products.join(',')}`);
  assert.ok(products.includes('Apache Struts'), `正文别名照常命中: ${products.join(',')}`);
  // 独立出现照常命中（Debian 包名等连字符场景不受影响）
  assert.ok(deriveProducts({ name: '', description: '', affected: 'mysql-server package' }).includes('MySQL'));
  // 复核函数与文本通道同语义
  assert.equal(productStandsAlone('mysql', 'oracle:mysql_enterprise_monitor'), false);
  assert.equal(productStandsAlone('mysql', 'requires mysql 8.0 or later'), true);
});
