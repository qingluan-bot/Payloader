// 默认凭据强制改密测试（服务端 403 闸门全链路）：
// ① 默认凭据登录 → 响应 mustChangePassword=true
// ② 强制状态下其它管理端点 403+mustChangePassword、凭据读取/修改豁免
// ③ 新密码禁止使用公开示例口令（Change-Me-2026! → 400）
// ④ 改密成功后重新登录 mustChangePassword=false、其余端点恢复可用
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const projectRoot = resolve(import.meta.dirname, '..');
const serverEntrypoint = join(projectRoot, 'server', 'admin-server.mjs');
const seedDatabase = join(projectRoot, 'server', 'default-seed.sqlite');

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
    if (match) {
      const port = Number(match[1]);
      settle(() => resolveStart({ child, port, output }));
    }
  };
  child.stdout.on('data', inspect);
  child.stderr.on('data', inspect);
  child.once('error', error => settle(() => rejectStart(error)));
  setTimeout(() => settle(() => rejectStart(new Error(`startup timeout:\n${output}`))), 20_000);
});

const request = async (port, path, { method = 'GET', token = null, body = null } = {}) => {
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers,
    body: body === null ? undefined : JSON.stringify(body),
  });
  const parsed = await response.json().catch(() => ({}));
  return { status: response.status, body: parsed };
};

const login = async (port, username, password) => {
  const captcha = await request(port, '/api/admin/captcha');
  if (!captcha.body.token || !captcha.body.answer) {
    throw new Error(`captcha echo unavailable: ${JSON.stringify(captcha.body).slice(0, 120)}`);
  }
  return request(port, '/api/admin/login', {
    method: 'POST',
    body: { username, password, captchaToken: captcha.body.token, captchaAnswer: captcha.body.answer },
  });
};

test('默认凭据登录后强制改密：403 闸门 → 豁免改密 → 新凭据全恢复', async t => {
  const dataDir = await mkdtemp(join(tmpdir(), 'payloader-force-pwd-'));
  const instance = await startServer(dataDir);
  const { child, port } = instance;
  t.after(async () => {
    // Windows：先等子进程退出再删临时目录，否则 SQLite 文件仍被持有（EBUSY）
    if (child.exitCode === null) {
      child.kill();
      await new Promise(resolveExit => {
        child.once('exit', resolveExit);
        setTimeout(resolveExit, 3000);
      });
    }
    await rm(dataDir, { recursive: true, force: true });
  });

  // ① 默认凭据登录成功且带强制改密标记
  const firstLogin = await login(port, 'admin', 'payloader-admin!');
  assert.equal(firstLogin.status, 200);
  assert.equal(firstLogin.body.authenticated, true);
  assert.equal(firstLogin.body.mustChangePassword, true);
  const token = firstLogin.body.accessToken;

  // ② 其它管理端点被 403 拦截；session 端点（auth-entry）仍带标记
  const blocked = await request(port, '/api/admin/payloads', { token });
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.mustChangePassword, true);
  assert.match(blocked.body.error, /默认管理员密码/);

  const session = await request(port, '/api/admin/session', { token });
  assert.equal(session.status, 200);
  assert.equal(session.body.mustChangePassword, true);

  // 凭据读取豁免（前端账号安全表单依赖）
  const credentialsInfo = await request(port, '/api/admin/credentials', { token });
  assert.equal(credentialsInfo.status, 200);
  assert.equal(credentialsInfo.body.username, 'admin');

  // ③ 新密码禁止使用公开示例口令
  const examplePassword = await request(port, '/api/admin/credentials', {
    method: 'PUT',
    token,
    body: { username: 'admin', currentPassword: 'payloader-admin!', newPassword: 'Change-Me-2026!', confirmPassword: 'Change-Me-2026!' },
  });
  assert.equal(examplePassword.status, 400);
  assert.match(examplePassword.body.error, /示例密码/);

  const defaultAgain = await request(port, '/api/admin/credentials', {
    method: 'PUT',
    token,
    body: { username: 'admin', currentPassword: 'payloader-admin!', newPassword: 'payloader-admin!', confirmPassword: 'payloader-admin!' },
  });
  assert.equal(defaultAgain.status, 400);

  // ④ 正常改密成功（改密端点豁免 403 闸门）
  const strongPassword = 'N0t-Default-2026#Pass';
  const change = await request(port, '/api/admin/credentials', {
    method: 'PUT',
    token,
    body: { username: 'admin', currentPassword: 'payloader-admin!', newPassword: strongPassword, confirmPassword: strongPassword },
  });
  assert.equal(change.status, 200);

  // 改密后旧 token 失效（会话全清 + 凭据版本轮换），新凭据登录无强制标记、端点恢复
  const oldTokenBlocked = await request(port, '/api/admin/payloads', { token });
  assert.equal(oldTokenBlocked.status, 401);

  const secondLogin = await login(port, 'admin', strongPassword);
  assert.equal(secondLogin.status, 200);
  assert.equal(secondLogin.body.mustChangePassword, false);
  const newToken = secondLogin.body.accessToken;

  const restored = await request(port, '/api/admin/payloads', { token: newToken });
  assert.equal(restored.status, 200);
  const restoredSession = await request(port, '/api/admin/session', { token: newToken });
  assert.equal(restoredSession.body.mustChangePassword, false);
});

test('环境变量提供的非默认初始密码不触发强制改密', async t => {
  const dataDir = await mkdtemp(join(tmpdir(), 'payloader-custom-pwd-'));
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
      PAYLOADER_ADMIN_PASSWORD: 'Custom-Strong-2026#Pwd',
      PAYLOADER_CAPTCHA_ECHO_ANSWER: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  t.after(async () => {
    if (child.exitCode === null) {
      child.kill();
      await new Promise(resolveExit => {
        child.once('exit', resolveExit);
        setTimeout(resolveExit, 3000);
      });
    }
    await rm(dataDir, { recursive: true, force: true });
  });
  const port = await new Promise((resolvePort, rejectPort) => {
    let output = '';
    const inspect = chunk => {
      output += chunk.toString('utf8');
      const match = output.match(/Payloader frontend: http:\/\/127\.0\.0\.1:(\d+)\//);
      if (match) resolvePort(Number(match[1]));
    };
    child.stdout.on('data', inspect);
    child.stderr.on('data', inspect);
    child.once('error', rejectPort);
    setTimeout(() => rejectPort(new Error(`startup timeout:\n${output}`)), 20_000);
  });

  const loginResponse = await login(port, 'admin', 'Custom-Strong-2026#Pwd');
  assert.equal(loginResponse.status, 200);
  assert.equal(loginResponse.body.mustChangePassword, false);
  const listPayloads = await request(port, '/api/admin/payloads', {
    token: loginResponse.body.accessToken,
  });
  assert.equal(listPayloads.status, 200);
});
