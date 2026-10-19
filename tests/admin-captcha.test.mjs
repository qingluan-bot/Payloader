// 管理后台登录图形验证码测试：
// ① 服务单元：签发/校验语义（大小写不敏感、验证即焚、垃圾输入）
// ② 集成全链路：GET 签发 → 缺码/错码 400（不烧凭据）→ 对码错密 401 → 对码对密 200
// ③ 签发限流：超频 GET 得 429
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const projectRoot = resolve(import.meta.dirname, '..');
const serverEntrypoint = join(projectRoot, 'server', 'admin-server.mjs');
const seedDatabase = join(projectRoot, 'server', 'default-seed.sqlite');

test('captcha service unit: issue/verify semantics with burn-on-read', async () => {
  const { createCaptchaService } = await import('../server/admin-captcha.mjs');
  const previousEcho = process.env.PAYLOADER_CAPTCHA_ECHO_ANSWER;
  process.env.PAYLOADER_CAPTCHA_ECHO_ANSWER = '1';
  try {
    const service = createCaptchaService();
    const issued = service.issue();
    assert.equal(typeof issued.token, 'string');
    assert.ok(issued.token.length >= 32);
    assert.ok(issued.svg.startsWith('<svg'));
    assert.equal(issued.expiresInSeconds, 300);
    assert.equal(typeof issued.answer, 'string');
    assert.equal(issued.answer.length, 4);

    // 大小写不敏感 + 首尾空白容忍
    assert.equal(service.verify(issued.token, ` ${issued.answer.toUpperCase()} `), true);
    // 验证即焚：同一个 token 第二次必失败（无论答案对错）
    assert.equal(service.verify(issued.token, issued.answer), false);

    const second = service.issue();
    assert.equal(service.verify(second.token, 'wrong'), false);
    assert.equal(service.verify(second.token, second.answer), false, '错答案也要烧掉 token');

    assert.equal(service.verify('', 'abcd'), false);
    assert.equal(service.verify(second.token, ''), false);
    assert.equal(service.verify(null, 'abcd'), false);
  } finally {
    if (previousEcho === undefined) delete process.env.PAYLOADER_CAPTCHA_ECHO_ANSWER;
    else process.env.PAYLOADER_CAPTCHA_ECHO_ANSWER = previousEcho;
  }
});

test('captcha service never echoes answer without explicit test flag', async () => {
  const { createCaptchaService } = await import('../server/admin-captcha.mjs');
  const previousEcho = process.env.PAYLOADER_CAPTCHA_ECHO_ANSWER;
  delete process.env.PAYLOADER_CAPTCHA_ECHO_ANSWER;
  try {
    const issued = createCaptchaService().issue();
    assert.equal('answer' in issued, false);
  } finally {
    if (previousEcho !== undefined) process.env.PAYLOADER_CAPTCHA_ECHO_ANSWER = previousEcho;
  }
});

const startServer = dataDir => new Promise((resolveStart, rejectStart) => {
  const child = spawn(process.execPath, [serverEntrypoint], {
    cwd: projectRoot,
    env: {
      ...process.env,
      NODE_ENV: 'development',
      PAYLOADER_HOST: '127.0.0.1',
      PAYLOADER_PORT: '0',
      PAYLOADER_DATA_DIR: dataDir,
      PAYLOADER_SEED_DB: seedDatabase,
      PAYLOADER_ADMIN_USER: 'admin',
      PAYLOADER_ADMIN_PASSWORD: 'Captcha-Strong-2026#Pwd',
      PAYLOADER_CAPTCHA_ECHO_ANSWER: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let output = '';
  let settled = false;
  const settle = fn => {
    if (settled) return;
    settled = true;
    fn();
  };
  const inspect = chunk => {
    output += chunk.toString('utf8');
    const match = output.match(/Payloader frontend: http:\/\/127\.0\.0\.1:(\d+)\//);
    if (match) settle(() => resolveStart({ child, port: Number(match[1]) }));
  };
  child.stdout.on('data', inspect);
  child.stderr.on('data', inspect);
  child.once('error', error => settle(() => rejectStart(error)));
  setTimeout(() => settle(() => rejectStart(new Error(`startup timeout:\n${output}`))), 20_000);
});

const request = async (port, path, { method = 'GET', body = null } = {}) => {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === null ? undefined : JSON.stringify(body),
  });
  const parsed = await response.json().catch(() => ({}));
  return { status: response.status, body: parsed };
};

test('login captcha integration: missing/wrong captcha rejected before credentials, correct flow succeeds', async t => {
  const dataDir = await mkdtemp(join(tmpdir(), 'payloader-captcha-'));
  const server = await startServer(dataDir);
  t.after(async () => {
    server.child.kill();
    await rm(dataDir, { recursive: true, force: true }).catch(() => {});
  });

  // ① 签发：SVG + token（echo 仅供测试断言，生产不回 answer）
  const issued = await request(server.port, '/api/admin/captcha');
  assert.equal(issued.status, 200);
  assert.ok(issued.body.svg.startsWith('<svg'));
  assert.equal(typeof issued.body.answer, 'string');

  // ② 缺验证码：400 + captchaInvalid，凭据不被消耗
  const missing = await request(server.port, '/api/admin/login', {
    method: 'POST',
    body: { username: 'admin', password: 'Captcha-Strong-2026#Pwd' },
  });
  assert.equal(missing.status, 400);
  assert.equal(missing.body.captchaInvalid, true);

  // ③ 错验证码：400
  const wrong = await request(server.port, '/api/admin/login', {
    method: 'POST',
    body: {
      username: 'admin',
      password: 'Captcha-Strong-2026#Pwd',
      captchaToken: issued.body.token,
      captchaAnswer: 'zzzz',
    },
  });
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.captchaInvalid, true);

  // ④ 对验证码 + 错密码：401（说明验证码通过后进入凭据校验）
  const fresh = await request(server.port, '/api/admin/captcha');
  const wrongPassword = await request(server.port, '/api/admin/login', {
    method: 'POST',
    body: {
      username: 'admin',
      password: 'wrong-password',
      captchaToken: fresh.body.token,
      captchaAnswer: fresh.body.answer,
    },
  });
  assert.equal(wrongPassword.status, 401);
  assert.equal(wrongPassword.body.error, '账号或密码不正确');

  // ⑤ 全对：200 + Bearer 令牌
  const final = await request(server.port, '/api/admin/captcha');
  const success = await request(server.port, '/api/admin/login', {
    method: 'POST',
    body: {
      username: 'admin',
      password: 'Captcha-Strong-2026#Pwd',
      captchaToken: final.body.token,
      captchaAnswer: final.body.answer,
    },
  });
  assert.equal(success.status, 200);
  assert.equal(success.body.tokenType, 'Bearer');
  assert.ok(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(success.body.accessToken));
});

test('captcha issuance is rate limited', async t => {
  const dataDir = await mkdtemp(join(tmpdir(), 'payloader-captcha-rl-'));
  const server = await startServer(dataDir);
  t.after(async () => {
    server.child.kill();
    await rm(dataDir, { recursive: true, force: true }).catch(() => {});
  });

  let sawLimit = false;
  for (let i = 0; i < 34; i += 1) {
    const response = await request(server.port, '/api/admin/captcha');
    if (response.status === 429) {
      sawLimit = true;
      break;
    }
    assert.equal(response.status, 200, `request ${i} should be 200 or the loop should have stopped`);
  }
  assert.equal(sawLimit, true, '31+ captcha requests per minute must trigger 429');
});
