// CTF 知识 AI 检索路由契约测试（批次 B）：注册表结构、四类 id 悬挂校验（防路由表腐烂）、
// 速查动线字段（steps/variants）形状、路由行为断言。
// 加载与种子库读取方式对齐 tests/ctf-cheatsheets.test.mjs（T4 测试基建收敛）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();

const router = loadModule(path.join(srcDir, 'utils', 'ctf', 'knowledgeRouter.ts'));
const cheatsheets = loadModule(path.join(srcDir, 'utils', 'ctf', 'cheatsheets', 'index.ts'));

// 跳转目标的真源是种子库（server/default-seed.sqlite），与全新部署的服务内容一致。
const { DatabaseSync } = await import('node:sqlite');
const seedFile = path.resolve('server', 'default-seed.sqlite');
const database = new DatabaseSync(seedFile, { readOnly: true });
const payloadIds = new Set(database.prepare('SELECT id FROM payloads').all().map(row => row.id));
const toolIds = new Set(database.prepare('SELECT id FROM tools').all().map(row => row.id));
database.close();
assert.ok(payloadIds.size > 100, `种子载荷库应非空，实际 ${payloadIds.size}`);
assert.ok(toolIds.size > 50, `种子工具库应非空，实际 ${toolIds.size}`);

// 从 src/components/ctf/*.tsx 源码真实提取渲染工具卡 id（对齐 tests/challenge-catalog.test.mjs 的提取方式）。
const componentDir = path.join(srcDir, 'components', 'ctf');
const renderedCardIds = new Set();
for (const file of readdirSync(componentDir)) {
  if (!file.endsWith('.tsx')) continue;
  const source = readFileSync(path.join(componentDir, file), 'utf8');
  for (const match of source.matchAll(/id=["'](ff-card-[a-z0-9-]+)["']/g)) renderedCardIds.add(match[1]);
}

// 速查条目 id 全集（web/reverse/pwn/ai 四域）。
const cheatEntryIds = new Set();
for (const sheet of Object.values(cheatsheets.ctfCheatSheets)) {
  for (const entry of sheet.entries) cheatEntryIds.add(entry.id);
}

test('注册表结构：14 域、domain 唯一、ids/keywords 数量达标、label 双语非空', () => {
  const { knowledgeRoutes } = router;
  assert.equal(knowledgeRoutes.length, 14, `应为 14 个技术域，实际 ${knowledgeRoutes.length}`);
  const seen = new Set();
  for (const route of knowledgeRoutes) {
    const label = `${route.domain}`;
    assert.ok(!seen.has(route.domain), `domain 重复：${route.domain}`);
    seen.add(route.domain);
    assert.ok(route.label.zh && route.label.en, `${label} label 双语缺失`);
    assert.ok(
      route.knowledge.ids.length >= 2 && route.knowledge.ids.length <= 6,
      `${label} knowledge.ids 应 2-6 条，实际 ${route.knowledge.ids.length}`,
    );
    assert.ok(route.knowledge.kind === 'payload' || route.knowledge.kind === 'tool', `${label} kind 非法`);
    assert.ok(
      route.keywords.length >= 3 && route.keywords.length <= 10,
      `${label} keywords 应 3-10 条，实际 ${route.keywords.length}`,
    );
    for (const keyword of route.keywords) {
      assert.ok(typeof keyword === 'string' && keyword.trim().length > 0, `${label} 存在空关键词`);
    }
  }
});

test('id 悬挂校验：knowledge/cheatEntry/toolCard 三类 id 必须真实存在（防路由表腐烂）', () => {
  for (const route of router.knowledgeRoutes) {
    for (const id of route.knowledge.ids) {
      assert.ok(
        payloadIds.has(id) || toolIds.has(id),
        `${route.domain} 挂载的库条目不存在：${id}`,
      );
    }
    for (const id of route.cheatEntryIds) {
      assert.ok(cheatEntryIds.has(id), `${route.domain} 挂载的速查条目不存在：${id}`);
    }
    for (const id of route.toolCardIds) {
      assert.ok(renderedCardIds.has(id), `${route.domain} 挂载的工具卡无渲染组件：${id}`);
    }
  }
});

test('steps/variants 形状：web 域带 steps 条目 ≥4、带 variants 条目 ≥3，内容非空', () => {
  const entries = cheatsheets.ctfCheatSheets.web.entries;
  const withSteps = entries.filter(entry => entry.steps !== undefined);
  const withVariants = entries.filter(entry => entry.variants !== undefined);
  assert.ok(withSteps.length >= 4, `web 域带 steps 条目应 ≥4，实际 ${withSteps.length}`);
  assert.ok(withVariants.length >= 3, `web 域带 variants 条目应 ≥3，实际 ${withVariants.length}`);
  for (const entry of withSteps) {
    assert.ok(entry.steps.length > 0, `${entry.id} steps 为空数组`);
    entry.steps.forEach((step, index) => {
      assert.ok(step.title.zh && step.title.en, `${entry.id} 第 ${index + 1} 步标题双语缺失`);
      assert.ok(typeof step.snippet === 'string' && step.snippet.trim().length > 0, `${entry.id} 第 ${index + 1} 步 snippet 为空`);
    });
  }
  for (const entry of withVariants) {
    assert.ok(entry.variants.length > 0, `${entry.id} variants 为空数组`);
    for (const variant of entry.variants) {
      assert.ok(typeof variant === 'string' && variant.trim().length > 0, `${entry.id} 存在空变体行`);
    }
  }
});

test('路由行为：查询命中预期第一名域', () => {
  const cases = [
    ['宽字节 注入', 'sqli'],
    ['union select 报错', 'sqli'],
    ['伪加密 爆破', 'archive-forensics'],
    ['LSB 位平面', 'image-stego'],
    ['频谱图', 'audio-stego'],
    ['pcap usb 流量', 'traffic-analysis'],
    ['共模攻击 维纳', 'rsa-number-theory'],
    ['{{7*7}} jinja2', 'ssti'],
    ['gopher 169.254.169.254', 'ssrf'],
    ['pickle gadget ysoserial', 'deserialization'],
  ];
  for (const [query, expected] of cases) {
    const result = router.routeKnowledgeQuery(query);
    assert.ok(result.length > 0, `查询「${query}」应至少命中一个域`);
    const actual = result.map(route => route.domain).join(',');
    assert.equal(result[0].domain, expected, `查询「${query}」第一名应为 ${expected}，实际 [${actual}]`);
  }
});

test('路由噪声负向：ASCII 关键词必须词边界命中，子串误配不得篡夺第一名', () => {
  // source 含子串 rce、read 含子串 ea——词边界匹配下不得触发 rce 域（宁准勿滥）。
  assert.deepEqual(Array.from(router.routeKnowledgeQuery('php source read')), [], 'source 的 rce 子串不得触发 rce 域');
  const lfiResult = router.routeKnowledgeQuery('read source via lfi');
  assert.ok(lfiResult.length > 0 && lfiResult[0].domain === 'lfi', 'lfi 查询不得被 rce 子串噪声压过');
  // handler 词归属 XSS 事件语境，sqli 域不得凭它抢第一名。
  assert.equal(router.routeKnowledgeQuery('xss event handler')[0].domain, 'xss-frontend', 'handler 不应把 XSS 查询错排到 sqli');
});

test('路由行为：无命中返回空数组、topN 生效', () => {
  // 沙箱跨 realm 数组 deepStrictEqual 必失败（见 AGENTS.md 踩坑记录），先转主 realm 再断言。
  assert.deepEqual(Array.from(router.routeKnowledgeQuery('完全无关词qqqzzz')), []);
  assert.deepEqual(Array.from(router.routeKnowledgeQuery('   ')), [], '纯空白查询应返回空');
  const limited = router.routeKnowledgeQuery('宽字节 注入', 1);
  assert.equal(limited.length, 1, `topN=1 应只返回 1 条，实际 ${limited.length}`);
});
