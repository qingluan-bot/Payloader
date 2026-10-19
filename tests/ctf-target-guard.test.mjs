// CTF 目标防护（SSRF 缓解）测试：
// ① IP 解析与阻断段矩阵（v4/v6/压缩写法/v4 映射地址）
// ② 环境感知策略判定（loopback 放行、非回环拦截、PAYLOADER_CTF_TARGET_POLICY 覆盖）
// ③ guard.checkTarget（open 全放行；protected 拦回环/内网/link-local/解析到内网的域名）
// ④ proxy/portscan 路由集成（protected 下 127.0.0.1 与 localhost 均被 403，open 放行）
import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { Router } from '../server/router.mjs';
import {
  createCtfTargetGuard,
  isBlockedAddress,
  parseIpv4,
  parseIpv6,
  resolveCtfTargetPolicy,
} from '../server/ctf-target-guard.mjs';
import { createCtfProxyRoutes } from '../server/routes-ctf-proxy.mjs';
import { createCtfPortscanRoutes } from '../server/routes-ctf-portscan.mjs';

test('parseIpv4/parseIpv6：合法输入、非法输入与压缩写法展开', () => {
  assert.deepEqual(parseIpv4('192.168.1.1'), [192, 168, 1, 1]);
  assert.equal(parseIpv4('256.1.1.1'), null);
  assert.equal(parseIpv4('1.1.1'), null);
  assert.equal(parseIpv4('abc'), null);

  // 压缩写法 0:0:0:0:0:0:0:1 必须展开为 ::1（防字符串前缀绕过）
  assert.deepEqual(parseIpv6('::1'), parseIpv6('0:0:0:0:0:0:0:1'));
  assert.equal(parseIpv6('::1')[15], 1);
  assert.equal(parseIpv6('::').every(byte => byte === 0), true);
  assert.deepEqual(parseIpv6('::ffff:192.168.0.1').slice(12), [192, 168, 0, 1]);
  assert.deepEqual(parseIpv6('2606:4700:4700::1111').slice(0, 4), [0x26, 0x06, 0x47, 0x00]);
  assert.equal(parseIpv6('1.2.3.4'), null);
  assert.equal(parseIpv6('::1::'), null);
  assert.equal(parseIpv6('12345::'), null);
});

test('isBlockedAddress：阻断段矩阵与公网地址放行', () => {
  const blocked = [
    '127.0.0.1', '127.1.2.3',            // v4 回环
    '0.0.0.0', '0.1.2.3',                // 本网络段
    '10.0.0.1', '10.255.255.255',        // RFC1918
    '172.16.0.1', '172.31.255.255',      // RFC1918（172.16/12 边界）
    '192.168.0.1', '192.168.255.254',    // RFC1918
    '169.254.169.254',                   // 云 metadata
    '100.64.0.1',                        // CGNAT
    '::1', '0:0:0:0:0:0:0:1',            // v6 回环（含压缩写法变体）
    '::',                                // 未指定
    '::ffff:127.0.0.1', '::ffff:10.0.0.5', // v4 映射地址按 v4 规则拦
    'fc00::1', 'fd12:3456::1',           // ULA 内网
    'fe80::1', 'febf::1',                // 链路本地（fe80::/10 边界）
    '64:ff9b::a00:1',                    // NAT64 嵌入 10.0.0.1
    '2002:0a00:0001::',                  // 6to4 嵌入 10.0.0.1（须按嵌入段 10/8 拦，非 0/8 巧合）
    '2002:c0a8:0101::',                  // 6to4 嵌入 192.168.1.1（P1 回归：嵌入段取下标 2-5）
    '2002:ac10:0a01::',                  // 6to4 嵌入 172.16.10.1（172.16/12）
    '198.18.0.1', '198.19.255.254',      // 基准测试段（198.18/15）
    '240.0.0.1', '255.255.255.255',      // 保留段 240/4
  ];
  for (const value of blocked) {
    assert.equal(isBlockedAddress(value), true, `${value} 应被阻断`);
  }

  const allowed = [
    '8.8.8.8', '1.1.1.1', '172.32.0.1', '172.15.255.255', '100.128.0.1',
    '198.17.255.255', '239.255.255.1',
    '2606:4700:4700::1111', '2001:4860:4860::8888', '::ffff:8.8.8.8', 'fec0::1',
    '64:ff9b::808:808',                    // NAT64 嵌入公网 8.8.8.8
    '2002:0808:0808::',                    // 6to4 嵌入公网 8.8.8.8
  ];
  for (const value of allowed) {
    assert.equal(isBlockedAddress(value), false, `${value} 应放行`);
  }

  // 无法解析的地址 fail closed
  assert.equal(isBlockedAddress('not-an-ip'), true);
});

test('resolveCtfTargetPolicy：监听地址自动判定 + 环境变量覆盖', () => {
  const savedPolicy = process.env.PAYLOADER_CTF_TARGET_POLICY;
  try {
    delete process.env.PAYLOADER_CTF_TARGET_POLICY;
    assert.equal(resolveCtfTargetPolicy({ serverHost: '127.0.0.1' }), 'open');
    assert.equal(resolveCtfTargetPolicy({ serverHost: 'localhost' }), 'open');
    assert.equal(resolveCtfTargetPolicy({ serverHost: '::1' }), 'open');
    assert.equal(resolveCtfTargetPolicy({ serverHost: '0.0.0.0' }), 'protected');
    assert.equal(resolveCtfTargetPolicy({ serverHost: '192.168.10.20' }), 'protected');

    process.env.PAYLOADER_CTF_TARGET_POLICY = 'off';
    assert.equal(resolveCtfTargetPolicy({ serverHost: '0.0.0.0' }), 'open');
    process.env.PAYLOADER_CTF_TARGET_POLICY = 'OPEN';
    assert.equal(resolveCtfTargetPolicy({ serverHost: '0.0.0.0' }), 'open');
    process.env.PAYLOADER_CTF_TARGET_POLICY = 'protected';
    assert.equal(resolveCtfTargetPolicy({ serverHost: '127.0.0.1' }), 'protected');
    process.env.PAYLOADER_CTF_TARGET_POLICY = 'strict';
    assert.equal(resolveCtfTargetPolicy({ serverHost: 'localhost' }), 'protected');
  } finally {
    if (savedPolicy === undefined) delete process.env.PAYLOADER_CTF_TARGET_POLICY;
    else process.env.PAYLOADER_CTF_TARGET_POLICY = savedPolicy;
  }
});

test('guard.checkTarget：open 全放行；protected 拦危险目标、放公网 IP、拦解析到回环的域名', async () => {
  const open = createCtfTargetGuard({ policy: 'open' });
  assert.equal((await open.checkTarget('http://127.0.0.1:8080/')).allowed, true);
  assert.equal((await open.checkTarget('http://169.254.169.254/latest/meta-data/')).allowed, true);

  const protectedGuard = createCtfTargetGuard({ policy: 'protected' });
  const denied = [
    'http://127.0.0.1:8123/',
    'http://127.0.0.1:8123/api/admin/login',
    'http://[::1]:8123/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://10.1.2.3:6379/',
    'http://192.168.1.1/',
    'http://172.20.10.1/',
    'https://127.0.0.1/',
  ];
  for (const target of denied) {
    const verdict = await protectedGuard.checkTarget(target);
    assert.equal(verdict.allowed, false, `${target} 应被拦截`);
    assert.match(verdict.message, /SSRF 防护拦截/);
  }

  // 域名目标经 DNS 预解析判定：localhost → 127.0.0.1 被拦
  const localhostVerdict = await protectedGuard.checkTarget('http://localhost:8080/');
  assert.equal(localhostVerdict.allowed, false);
  const localhostHostVerdict = await protectedGuard.checkTarget('localhost');
  assert.equal(localhostHostVerdict.allowed, false);

  // 公网 IP 直连放行；残缺目标拒绝
  assert.equal((await protectedGuard.checkTarget('http://8.8.8.8/dns-query')).allowed, true);
  assert.equal((await protectedGuard.checkTarget('')).allowed, false);
  assert.equal((await protectedGuard.checkTarget('http:///no-host')).allowed, false);
});

const startServer = handler => new Promise(resolve => {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
});

const proxyOf = async ({ targetGuard }) => {
  const router = new Router();
  const isCtfEnabled = async () => true;
  createCtfProxyRoutes({ isCtfEnabled, targetGuard }).registerCtfProxyRoutes(router);
  createCtfPortscanRoutes({ isCtfEnabled, targetGuard }).registerCtfPortscanRoutes(router);
  return startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    void router.dispatch(req, res, url, 'public', {}).then(dispatched => {
      if (!dispatched) { res.writeHead(404); res.end(); }
    });
  });
};

const post = async (port, pathname, payload) => fetch(`http://127.0.0.1:${port}${pathname}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(payload),
});

test('路由集成：protected 策略下 proxy/portscan 对 127.0.0.1 与 localhost 返回 403，open 放行', async () => {
  const target = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('target-ok');
  });
  const protectedInstance = await proxyOf({ targetGuard: createCtfTargetGuard({ policy: 'protected' }) });
  const openInstance = await proxyOf({ targetGuard: createCtfTargetGuard({ policy: 'open' }) });
  try {
    const deniedProxy = await post(protectedInstance.port, '/api/ctf/proxy', {
      url: `http://127.0.0.1:${target.port}/`, method: 'GET', headers: {}, body: null,
    });
    assert.equal(deniedProxy.status, 403);
    assert.match((await deniedProxy.json()).error, /SSRF 防护拦截/);

    const deniedDomain = await post(protectedInstance.port, '/api/ctf/proxy', {
      url: 'http://localhost/x', method: 'GET', headers: {}, body: null,
    });
    assert.equal(deniedDomain.status, 403);

    const deniedScan = await post(protectedInstance.port, '/api/ctf/portscan', {
      host: '127.0.0.1', ports: [target.port],
    });
    assert.equal(deniedScan.status, 403);

    const deniedScanDomain = await post(protectedInstance.port, '/api/ctf/portscan', {
      host: 'localhost', ports: [80],
    });
    assert.equal(deniedScanDomain.status, 403);

    // open 策略功能不受影响：本机靶机目标正常转发/扫描
    const allowedProxy = await post(openInstance.port, '/api/ctf/proxy', {
      url: `http://127.0.0.1:${target.port}/`, method: 'GET', headers: {}, body: null,
    });
    assert.equal(allowedProxy.status, 200);
    const allowedBody = await allowedProxy.json();
    assert.equal(allowedBody.bodyText, 'target-ok');

    const allowedScan = await post(openInstance.port, '/api/ctf/portscan', {
      host: '127.0.0.1', ports: [target.port, 1],
    });
    assert.equal(allowedScan.status, 200);
    const scanBody = await allowedScan.json();
    assert.equal(scanBody.results.find(item => item.port === target.port)?.state, 'open');
    assert.equal(scanBody.results.find(item => item.port === 1)?.state, 'closed');
  } finally {
    target.server.close();
    protectedInstance.server.close();
    openInstance.server.close();
  }
});
