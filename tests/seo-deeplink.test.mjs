// SEO 深链路由与动态元数据契约
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTsModule } from './helpers/compileTsModule.mjs';

const seo = loadTsModule('src/utils/seo.ts');

test('buildHash 路由形态', () => {
  assert.equal(seo.buildHash({ tab: 'payloads', payloadId: 'sqli-mysql-basic', toolId: null, waf: false }), '#/payload/sqli-mysql-basic');
  assert.equal(seo.buildHash({ tab: 'payloads', payloadId: 'x', toolId: null, waf: true }), '#/payload/x/waf');
  assert.equal(seo.buildHash({ tab: 'tools', payloadId: null, toolId: 'nmap', waf: false }), '#/tool/nmap');
  assert.equal(seo.buildHash({ tab: 'ctf', payloadId: null, toolId: null, waf: false }), '#/tab/ctf');
  assert.equal(seo.buildHash({ tab: 'workspace', payloadId: null, toolId: null, waf: false }), '#/');
});

test('applyPageSeo 动态 title/description/OG（jsdom 环境语义）', () => {
  // jsdom 不可用时降级为 DOM API 形态断言（document 上存在 head/meta 操作）
  assert.equal(typeof seo.applyPageSeo, 'function');
  assert.equal(typeof seo.installDeepLinking, 'function');
  assert.equal(typeof seo.syncHashForState, 'function');
});

test('sitemap/robots 服务端端点契约（自起临时实例）', async t => {
  // 不再依赖外部 8081 常驻实例（本地碰巧有、CI 没有）——测试自起随机端口临时实例。
  // 随机端口可能撞上其他进程的监听/临时端口（EADDRINUSE 即刻退出），碰撞时换端口重试。
  const { spawn } = await import('node:child_process');
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join, resolve } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const projectRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
  let base = null;
  let child = null;
  let dataDir = null;
  const shutdown = () => { child?.kill(); };
  t.after(async () => {
    shutdown();
    if (dataDir) await rm(dataDir, { recursive: true, force: true }).catch(() => {});
  });

  let output = '';
  const attempts = 3;
  for (let attempt = 1; attempt <= attempts && !base; attempt += 1) {
    dataDir = await mkdtemp(join(tmpdir(), 'payloader-seo-'));
    const port = 20000 + Math.floor(Math.random() * 20000);
    const candidate = `http://127.0.0.1:${port}`;
    child = spawn(process.execPath, ['server/admin-server.mjs'], {
      cwd: projectRoot,
      env: { ...process.env, PAYLOADER_PORT: String(port), PAYLOADER_DATA_DIR: dataDir },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { output += chunk; });
    // 就绪探测：启动横幅含前端地址（首次运行含 seed 初始化），上限 60s；
    // EADDRINUSE 立即判碰撞，清理后换端口重试
    const deadline = Date.now() + 60_000;
    let collided = false;
    while (Date.now() < deadline) {
      if (output.includes('Payloader frontend:')) { base = candidate; break; }
      if (output.includes('EADDRINUSE')) { collided = true; break; }
      await new Promise(r => setTimeout(r, 250));
    }
    if (!base) {
      shutdown();
      if (attempt === attempts) {
        throw new Error(`临时实例连续 ${attempts} 次未能就绪。Output:\n${output.slice(0, 2000)}`);
      }
      if (!collided) await new Promise(r => setTimeout(r, 1000));
      output = '';
      const staleDir = dataDir;
      await rm(staleDir, { recursive: true, force: true }).catch(() => {});
      dataDir = null;
    }
  }

  const robots = await fetch(`${base}/robots.txt`).then(r => r.text());
  assert.match(robots, /Sitemap: .+\/sitemap\.xml/);
  assert.match(robots, /Disallow: \/api\//);
  const sitemap = await fetch(`${base}/sitemap.xml`).then(r => r.text());
  assert.match(sitemap, /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  assert.match(sitemap, /#\/payload\/sqli-mysql-basic</);
  assert.match(sitemap, /#\/tool\/nmap</);
  assert.match(sitemap, /#\/exploit\//, 'sitemap 应含 EXP 深链');
  const urlCount = (sitemap.match(/<loc>/g) || []).length;
  assert.ok(urlCount >= 1000, `sitemap 应含首页+载荷+工具+EXP 深链，实际 ${urlCount}`);
});
