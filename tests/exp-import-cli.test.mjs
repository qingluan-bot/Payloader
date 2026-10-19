// EXP 批量导入 CLI 集成测试（v2.0.3）：子进程真跑 scripts/import-exp.mjs，
// 验证固定格式文件 → 运行库的导入闭环：无编号知识条目幂等、treePath 无效剔除、坏文件退出码。

import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

const run = promisify(execFile);

const setupDb = async dataDir => {
  await mkdir(dataDir, { recursive: true });
  const database = new DatabaseSync(join(dataDir, 'payloader.sqlite'));
  database.exec(`
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE exploits (
      id TEXT PRIMARY KEY, data TEXT NOT NULL, sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE exploit_nodes (
      id TEXT PRIMARY KEY, tree TEXT NOT NULL, sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
  `);
  database.prepare('INSERT INTO exploit_nodes (id, tree, sort_order, created_at, updated_at) VALUES (?, ?, 0, ?, ?)')
    .run('root-x', JSON.stringify({ id: 'root-x', name: { zh: '测试树', en: 'Test' }, children: [{ id: 'leaf-x', name: { zh: '叶子', en: 'Leaf' } }] }), new Date().toISOString(), new Date().toISOString());
  database.close();
};

const importFile = async (dataDir, file) => run(process.execPath, [
  join(process.cwd(), 'scripts', 'import-exp.mjs'), file,
], {
  cwd: process.cwd(),
  env: { ...process.env, PAYLOADER_DATA_DIR: dataDir, PAYLOADER_UPDATE_CHECK_DISABLED: 'true' },
});

test('import:exp：格式文件导入闭环 + 无编号条目幂等 + treePath 无效剔除', async t => {
  const tempRoot = await mkdtemp(join(tmpdir(), 'payloader-exp-import-'));
  const dataDir = join(tempRoot, 'data');
  await setupDb(dataDir);
  t.after(async () => { await rm(tempRoot, { recursive: true, force: true }); });

  const payload = {
    format: 'payloader.import.v1',
    exploits: [
      {
        name: '带编号测试条目', description: '机理描述。', vulnType: 'rce', severity: 'high',
        publishedAt: '2023-01', affected: 'Test 1.0',
        vulnerabilityIds: [{ type: 'CVE', value: 'CVE-2099-00001' }],
        exploitCode: [{ title: '验证', language: 'http', code: 'GET / HTTP/1.1' }],
        prerequisites: '条件。', references: ['https://example.com/a', 'https://example.com/b'],
        tags: ['test'],
      },
      {
        name: '无编号知识条目', description: '知识型描述。', vulnType: 'auth-bypass', severity: 'medium',
        publishedAt: '2022',
        vulnerabilityIds: [],
        exploitCode: [{ title: '验证', language: 'bash', code: 'curl -s http://t/' }],
        prerequisites: '条件。', references: ['https://example.com/c'],
        tags: ['test'],
        treePath: 'root-x/leaf-not-exist',
      },
      {
        name: '挂载叶子条目', description: '挂载描述。', vulnType: 'file-upload', severity: 'high',
        publishedAt: '2021-06',
        vulnerabilityIds: [{ type: 'CNVD', value: 'CNVD-2099-0002' }],
        exploitCode: [{ title: '验证', language: 'http', code: 'POST / HTTP/1.1' }],
        prerequisites: '条件。', references: ['https://example.com/d'],
        tags: ['test'], treePath: 'root-x/leaf-x',
      },
    ],
  };
  const file = join(tempRoot, 'batch.json');
  await writeFile(file, JSON.stringify(payload, null, 2), 'utf8');

  const first = await importFile(dataDir, file);
  assert.match(first.stdout, /新增 3 条/);
  assert.match(first.stderr, /treePath 叶子不存在/);

  const database = new DatabaseSync(join(dataDir, 'payloader.sqlite'), { readOnly: true });
  const rows = database.prepare('SELECT data FROM exploits').all().map(row => JSON.parse(row.data));
  assert.equal(rows.length, 3);
  const mounted = rows.find(item => item.name === '挂载叶子条目');
  assert.equal(mounted.treePath, 'root-x/leaf-x');
  const dropped = rows.find(item => item.name === '无编号知识条目');
  assert.equal(dropped.treePath, undefined, '无效 treePath 应被剔除');
  const firstIds = new Set(rows.map(item => item.id));
  database.close();

  // 幂等重跑：三条全部零新增（含无编号知识条目）
  const rerun = await importFile(dataDir, file);
  assert.match(rerun.stdout, /新增 0 条，更新 0 条/);
  const database2 = new DatabaseSync(join(dataDir, 'payloader.sqlite'), { readOnly: true });
  const rerunRows = database2.prepare('SELECT id FROM exploits').all();
  assert.equal(rerunRows.length, 3);
  rerunRows.forEach(row => assert.ok(firstIds.has(row.id), '重跑不得产生新 id'));
  database2.close();

  // 坏 JSON：退出码 1
  const badFile = join(tempRoot, 'bad.json');
  await writeFile(badFile, '{"exploits": [}', 'utf8');
  await assert.rejects(importFile(dataDir, badFile), error => {
    assert.ok(error.code !== 0 || error.stderr.length > 0);
    return true;
  });
});
