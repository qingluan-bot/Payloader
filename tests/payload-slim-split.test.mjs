import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import test from 'node:test';

// P1-2 首屏载荷瘦身契约：public-data 只发列表投影，详情/搜索语料走独立端点。
// 字段白名单是主防线（确定性），gzip 绊线是次防线（拦"详情字段回流首屏"的回归）。

const DETAIL_ONLY_FIELDS = [
  'wafBypass',
  'tutorial',
  'execution',
  'attackChain',
  'analysis',
  'prerequisites',
  'opsecTips',
  'edrBypass',
  'references',
];

// undici fetch 会在应用层自动解压 gzip 响应（且保留 content-encoding 头），测不了压缩字节；
// 压缩口径断言一律走 node:http 裸请求
const rawGet = (baseUrl, pathname, headers = {}) => new Promise((resolve, reject) => {
  http.get(`${baseUrl}${pathname}`, { headers }, response => {
    const chunks = [];
    response.on('data', chunk => chunks.push(chunk));
    response.on('end', () => resolve({ headers: response.headers, body: Buffer.concat(chunks), status: response.statusCode }));
  }).on('error', reject);
});

test('public-data 列表投影不含详情级字段；详情/语料端点按需可取且口径一致', async t => {
  const tempRoot = await mkdtemp(join(tmpdir(), 'payloader-payload-slim-'));
  process.env.PAYLOADER_DATA_DIR = join(tempRoot, 'data');
  process.env.PAYLOADER_CLIENT_BUILD_ROOT = join(tempRoot, 'client-builds');
  process.env.PAYLOADER_CLIENT_TMP_ROOT = join(tempRoot, 'client-tmp');
  process.env.PAYLOADER_ADMIN_USER = 'slim-admin';
  process.env.PAYLOADER_ADMIN_PASSWORD = 'Slim-Test-Password-123!';
  process.env.PAYLOADER_TRUSTED_PROXIES = 'loopback';
  process.env.PAYLOADER_UPDATE_CHECK_DISABLED = 'true';
  process.env.PAYLOADER_CLIENT_SHELLS_REMOTE_DISABLED = 'true';

  const [{ createAdminServer }, { closeStore }] = await Promise.all([
    import(`../server/admin-server.mjs?payload-slim=${Date.now()}`),
    import('../server/data-store.mjs'),
  ]);

  const fakeVersionChecker = {
    getStatus: async () => null,
    checkNow: async () => null,
    start: async () => null,
    stop() {},
  };
  const server = createAdminServer({ versionChecker: fakeVersionChecker });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  t.after(async () => {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await closeStore();
    await rm(tempRoot, { recursive: true, force: true });
  });

  // ① 列表投影字段白名单：详情级字段一个都不许出现
  const listResponse = await fetch(`${baseUrl}/api/public-data`, {
    headers: { 'accept-encoding': 'identity' },
  });
  assert.equal(listResponse.status, 200);
  const listData = await listResponse.json();
  assert.ok(Array.isArray(listData.payloads) && listData.payloads.length > 0, '种子库应含 payload');
  for (const payload of listData.payloads) {
    for (const field of DETAIL_ONLY_FIELDS) {
      assert.equal(payload[field], undefined, `列表条目 ${payload.id} 不应携带详情级字段 ${field}`);
    }
    assert.equal(typeof payload.commandCount, 'number', `列表条目 ${payload.id} 缺 commandCount 派生计数`);
    assert.equal(typeof payload.bypassCount, 'number', `列表条目 ${payload.id} 缺 bypassCount 派生计数`);
  }

  // ② gzip 绊线（正式 700KB 硬闸由验收 curl 承担；此处拦详情字段回流导致的体积回归）
  const gzipProbe = await rawGet(baseUrl, '/api/public-data', { 'accept-encoding': 'gzip' });
  assert.equal(gzipProbe.status, 200);
  assert.equal(gzipProbe.headers['content-encoding'], 'gzip');
  assert.equal(gzipProbe.body.subarray(0, 2).toString('hex'), '1f8b', '响应体应为 gzip 原始字节');
  assert.ok(gzipProbe.body.length <= 900 * 1024, `首屏 gzip ${gzipProbe.body.length}B 超出 900KB 回归绊线`);

  // ③ 详情端点：完整条目与列表计数一致，ETag/304/404 口径正确
  const withCommands = listData.payloads.find(payload => payload.commandCount > 0);
  assert.ok(withCommands, '种子库应含带执行命令的 payload');
  const detailUrl = `${baseUrl}/api/payloads/${encodeURIComponent(withCommands.id)}/detail`;
  const detailResponse = await fetch(detailUrl);
  assert.equal(detailResponse.status, 200);
  assert.equal(detailResponse.headers.get('cache-control'), 'public, max-age=0, must-revalidate');
  const detail = await detailResponse.json();
  assert.equal(detail.id, withCommands.id);
  assert.ok(Array.isArray(detail.execution), '详情应含 execution 全量字段');
  assert.equal(detail.execution.length, withCommands.commandCount, '详情 execution 数应与列表 commandCount 一致');
  const etag = detailResponse.headers.get('etag');
  assert.ok(etag && etag.startsWith('W/'), '详情响应应带弱 ETag');
  const notModified = await fetch(detailUrl, { headers: { 'if-none-match': etag } });
  assert.equal(notModified.status, 304);
  const missing = await fetch(`${baseUrl}/api/payloads/definitely-not-a-payload/detail`);
  assert.equal(missing.status, 404);

  // ④ 语料端点：条目与列表 id 对齐，文本覆盖该条目的命令原文/命令描述/前置条件
  const corpusResponse = await fetch(`${baseUrl}/api/payload-search-corpus`, {
    headers: { 'accept-encoding': 'identity' },
  });
  assert.equal(corpusResponse.status, 200);
  const corpus = await corpusResponse.json();
  assert.equal(corpus.version, 1);
  const listIds = new Set(listData.payloads.map(payload => payload.id));
  for (const entry of corpus.entries) {
    assert.ok(listIds.has(entry.id), `语料条目 ${entry.id} 不在列表投影中`);
    assert.ok(typeof entry.text === 'string' && entry.text.length > 0, `语料条目 ${entry.id} 文本为空`);
  }
  const corpusById = new Map(corpus.entries.map(entry => [entry.id, entry.text]));
  const commandsToMatch = [
    ...detail.execution.map(command => command.command),
    ...(detail.wafBypass || []).map(command => command.command),
  ];
  const corpusText = corpusById.get(detail.id) || '';
  for (const command of commandsToMatch) {
    assert.ok(corpusText.includes(command), `语料文本应包含 ${detail.id} 的命令原文`);
  }
  // 命令描述与前置条件文本也在语料覆盖面内（对齐旧搜索索引，防覆盖面回归）
  const commandDescriptions = detail.execution
    .flatMap(command => {
      const description = command.description;
      if (!description) return [];
      return typeof description === 'string' ? [description] : [description.zh, description.en];
    })
    .filter(Boolean);
  for (const description of commandDescriptions) {
    assert.ok(corpusText.includes(description), `语料文本应包含 ${detail.id} 的命令描述`);
  }
  const prerequisitesTexts = (detail.prerequisites || []).flatMap(item =>
    typeof item === 'string' ? [item] : [item.zh, item.en]).filter(Boolean);
  for (const text of prerequisitesTexts) {
    assert.ok(corpusText.includes(text), `语料文本应包含 ${detail.id} 的前置条件文本`);
  }

  // ⑤ 详情内存缓存与列表同源：改写路径失效后详情反映新数据（与 public-data 同一失效链）
  const { getPayloadDetail } = await import('../server/data-store.mjs');
  const viaStore = await getPayloadDetail(withCommands.id);
  assert.ok(viaStore, 'data-store.getPayloadDetail 应命中全量索引');
  assert.deepEqual(Object.keys(viaStore).sort(), Object.keys(detail).sort());
});
